"""Check real Android Keystore attestation evidence with the registry's own parser.

    python scripts/check_attestation.py logcat.txt [--expect-package in.guardianregistry.app]
        [--roots google-roots.pem]

logcat.txt is `adb logcat -d -s GRATTEST:I -v raw` from the emulator test (SignInTest),
which prints {"challenge", "device_key", "attestation"} in numbered chunks.

Without --roots the chain's own top certificate is pinned for the check. An emulator's
Keystore is software, signed by a software attestation root, so this proves the parsing,
the challenge and key binding and the app identity, not the hardware; on a real phone,
pass Google's roots and expect hardware_backed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography import x509  # noqa: E402

from guardian_registry import attestation as A  # noqa: E402


def reassemble(text: str) -> dict:
    parts: dict[int, str] = {}
    total = None
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)/(\d+):(.*)$", line)
        if m:
            parts[int(m.group(1))] = m.group(3)
            total = int(m.group(2))
    if not total or len(parts) != total:
        raise SystemExit(f"incomplete evidence in logcat: got chunks {sorted(parts)} of {total}")
    return json.loads("".join(parts[i] for i in range(1, total + 1)))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logcat")
    ap.add_argument("--expect-package", default="in.guardianregistry.app")
    ap.add_argument("--roots")
    a = ap.parse_args(argv)
    doc = reassemble(open(a.logcat, encoding="utf-8", errors="replace").read())
    evidence = json.loads(doc["attestation"])
    chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in evidence["chain"]]
    roots = A.load_pem_roots(a.roots) if a.roots else [chain[-1]]
    ext = chain[0].extensions.get_extension_for_oid(A.ANDROID_KEY_DESCRIPTION_OID).value.value
    kd = A.parse_key_description(ext)
    levels = {0: "software", 1: "TEE", 2: "StrongBox"}
    print(f"chain: {len(chain)} certificates; top: {chain[-1].subject.rfc4514_string()}")
    print(f"attestation version {kd['attestation_version']}, security level "
          f"{levels.get(kd['attestation_security_level'])}, keymaster level {levels.get(kd['keymaster_security_level'])}")
    print(f"packages {sorted(kd['packages'])}, signing digests {sorted(kd['signature_digests'])}")
    print(f"device locked {kd.get('device_locked')}, verified boot state {kd.get('verified_boot_state')}")

    verifier = A.AndroidKeyAttestation(roots, {a.expect_package}, kd["signature_digests"] or {"none"})
    verdict = A.LocalKeyAttestor(android=verifier).verify(doc["device_key"], doc["attestation"], "android",
                                                          doc["challenge"])
    print(f"verdict: {verdict}")
    problems = []
    if not verdict["app_genuine"]:
        problems.append(f"package {a.expect_package!r} and its signing digest were not found in the evidence")
    try:  # replay with another challenge must fail
        A.LocalKeyAttestor(android=verifier).verify(doc["device_key"], doc["attestation"], "android", "other")
        problems.append("the evidence also verified for a different challenge")
    except A.AttestationError:
        pass
    if problems:
        print("FAIL: " + "; ".join(problems))
        return 1
    print("ok: the real Keystore chain verifies, is bound to this key and challenge, and names this app")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
