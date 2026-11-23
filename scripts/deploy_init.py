"""Create what deploy/docker-compose.yml needs: secrets, TLS certificates and deploy/.env.

    python scripts/deploy_init.py            production settings (fill in providers in deploy/.env)
    python scripts/deploy_init.py --dev      a local trial: development mode, OTP codes echoed

Writes (never overwrites without --force):
  deploy/secrets/   db_password, db_url, pepper, data_key, operators, metrics_token
  deploy/certs/     ca.pem (+ key) and server.pem for nginx; bank-cas.pem, and bank.pem + key
                    as an example bank client certificate (in production, bank-cas.pem holds the
                    CAs your banks' certificates chain to, and you don't hold their keys)
  deploy/.env       non-secret settings

The self-signed CA is for trials. In production use a certificate from a public CA (or your
organisation's) for the server, and keep the secrets in a secret manager that writes these
files (Vault Agent, a CSI driver); the containers only read files.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def _write(path: Path, data: bytes | str, force: bool, private: bool = True) -> None:
    if path.exists() and not force:
        raise SystemExit(f"{path} exists; re-run with --force to replace it (this rotates it!)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert(subject_cn, key, issuer_cert, issuer_key, *, ca=False, server_names=(), client=False, days=825):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    b = (x509.CertificateBuilder().subject_name(name)
         .issuer_name(issuer_cert.subject if issuer_cert else name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
         .not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, encipher_only=False,
                                          decipher_only=False), critical=True)
    if server_names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in server_names]), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if client:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dev", action="store_true", help="development mode with OTP echo, for a local trial")
    ap.add_argument("--hostname", default="localhost", help="name the server certificate is for")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    s, c = DEPLOY / "secrets", DEPLOY / "certs"

    # Compose bind-mounts each secret file into the containers, which run as their own users,
    # so the files are world-readable and the DIRECTORY is what keeps other host users out.
    s.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(s, 0o700)
    except OSError:
        pass
    db_password = secrets.token_urlsafe(24)
    for name, value in (("db_password", db_password),
                        ("db_url", f"postgresql://guardian:{db_password}@db:5432/guardian"),
                        ("pepper", secrets.token_urlsafe(32)),
                        ("data_key", Fernet.generate_key().decode()),
                        ("operators", f"alice:{secrets.token_urlsafe(24)},bob:{secrets.token_urlsafe(24)}"),
                        ("metrics_token", secrets.token_urlsafe(24))):
        _write(s / name, value, a.force, private=False)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Guardian Registry trial CA", ca_key, None, None, ca=True, days=3650)
    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv = _cert(a.hostname, srv_key, ca, ca_key, server_names=sorted({a.hostname, "localhost"}))
    bank_ca_key = ec.generate_private_key(ec.SECP256R1())
    bank_ca = _cert("Example Bank CA", bank_ca_key, None, None, ca=True, days=3650)
    bank_key = ec.generate_private_key(ec.SECP256R1())
    bank = _cert("api.examplebank.in", bank_key, bank_ca, bank_ca_key, client=True)
    _write(c / "ca.pem", _pem(ca), a.force, private=False)
    _write(c / "ca-key.pem", _key_pem(ca_key), a.force)
    _write(c / "server.pem", _pem(srv) + _pem(ca), a.force, private=False)
    _write(c / "server-key.pem", _key_pem(srv_key), a.force, private=False)  # nginx reads it as another user
    _write(c / "bank-cas.pem", _pem(bank_ca), a.force, private=False)
    _write(c / "bank.pem", _pem(bank), a.force, private=False)
    _write(c / "bank-key.pem", _key_pem(bank_key), a.force)

    env = ["# Non-secret settings for deploy/docker-compose.yml. Secrets live in deploy/secrets/.",
           f"GR_ENV={'development' if a.dev else 'production'}",
           "GR_WORKER_INTERVAL=5"]
    if a.dev:
        env += ["GR_OTP_DEV_ECHO=1", "GR_REQUIRE_MTLS=1", "GR_REQUIRE_ENTITY_REGISTER=1"]
    else:
        env += ["# Providers (production refuses to start without SMS). See README: Configuration.",
                "GR_SMS_PROVIDER=", "# GR_TWILIO_ACCOUNT_SID=, GR_TWILIO_AUTH_TOKEN_FILE=, GR_TWILIO_FROM=",
                "# GR_PUSH_PROVIDER=direct, GR_FCM_SERVICE_ACCOUNT_FILE=, GR_APNS_KEY_FILE=, ...",
                "# Operator SSO instead of tokens: GR_OPERATOR_OIDC_ISSUER=, GR_OPERATOR_OIDC_AUDIENCE=, "
                "GR_OPERATOR_OIDC_ALLOWED="]
    _write(DEPLOY / ".env", "\n".join(env) + "\n", a.force)
    print(f"wrote deploy/secrets, deploy/certs and deploy/.env ({'development' if a.dev else 'production'})")
    print("next: docker compose -f deploy/docker-compose.yml up -d --build")
    return 0


if __name__ == "__main__":
    sys.exit(main())
