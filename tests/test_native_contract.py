"""The native apps and the server must agree on bytes: signing prefix, key encoding, App
Attest binding and attestation JSON. These read the Kotlin / Swift sources (and, in CI,
the output of the Swift self-check) so a change on one side fails here."""

import base64
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guardian_registry import attestation as A
from guardian_registry.devicekeys import SIGNING_PREFIX

ROOT = Path(__file__).resolve().parent.parent
KOTLIN = (ROOT / "android/app/src/main/java/in/guardianregistry/app/Wire.kt").read_text(encoding="utf-8")
SWIFT = (ROOT / "ios/GuardianRegistry/Wire.swift").read_text(encoding="utf-8")


def test_signing_prefix_is_the_same_everywhere():
    assert SIGNING_PREFIX == A.SIGNING_PREFIX == b"guardian-registry/v1:"
    assert f'SIGNING_PREFIX = "{SIGNING_PREFIX.decode()}"' in KOTLIN
    assert f'signingPrefix = "{SIGNING_PREFIX.decode()}"' in SWIFT


def test_swift_spki_header_matches_real_p256_keys():
    block = SWIFT.split("p256SpkiHeader = Data([", 1)[1].split("])", 1)[0]
    header = bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", block))
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert der == header + point


def test_attestation_formats_are_the_ones_the_server_parses():
    assert '"format", "android-key"' in KOTLIN and '"chain"' in KOTLIN
    assert '"format": "apple-appattest"' in SWIFT and '"key_id"' in SWIFT and '"object"' in SWIFT


def test_swift_self_check_output():
    """CI runs ios/WireCheck on macOS and passes its output in WIRECHECK_OUTPUT."""
    path = os.environ.get("WIRECHECK_OUTPUT")
    if not path:
        import pytest
        pytest.skip("set WIRECHECK_OUTPUT to the Swift self-check's output (macOS CI)")
    out = dict(line.split("=", 1) for line in Path(path).read_text().splitlines() if "=" in line)
    spki = base64.b64decode(out["spki"])
    assert len(spki) == 91 and spki[-65:] == bytes([0x04]) + bytes([0x11]) * 32 + bytes([0x22]) * 32
    assert base64.b64decode(out["cdh"]) == A.apple_client_data_hash("chl_x", spki)
