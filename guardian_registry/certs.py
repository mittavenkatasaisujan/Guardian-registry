"""Mutual TLS for banks and apps: an API key alone is not enough.

A leaked API key would let anyone act as that bank: run checks, vouch for identities,
open SIM-swap windows. With mutual TLS the caller must also hold the bank's private
certificate key, which normally lives in an HSM and never travels.

How it is deployed: TLS ends at the reverse proxy in front of the registry (nginx, Envoy,
a cloud load balancer). The proxy verifies the bank's certificate chain and forwards the
certificate in a header (nginx: `proxy_set_header X-Client-Cert $ssl_client_escaped_cert`).
The registry trusts that header ONLY from GR_TRUSTED_PROXIES, then checks:
  * the certificate's SHA-256 fingerprint is PINNED for this participant (so a certificate
    from the same CA issued to someone else doesn't work), and
  * it is within its validity dates.

When it applies: as soon as a participant has an active pin, every one of its calls needs
the certificate. GR_REQUIRE_MTLS=1 (default in production) requires it for every
participant, so one without a pin can't call at all.

Managing pins:
  * An operator pins a certificate as PENDING; a different operator approves (four-eyes),
    because a new pin widens who can act as the bank.
  * A bank rotates its own certificate with a call that already presents a pinned one
    (plus its API key): the new one is active at once and both work until the old is removed.
  * Removing a pin is instant (operator or bank). A bank can't remove the certificate it is
    calling with unless another active one remains.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .clock import iso
from .errors import Conflict, Forbidden, Invalid, NotFound, Unauthorized
from .security import is_production


class CertError(Exception):
    pass


def parse_certificate(pem: str) -> dict:
    """PEM (or the proxy's URL-escaped PEM) -> {fingerprint, subject, not_before, not_after}."""
    text = unquote(pem or "").strip()
    if "BEGIN CERTIFICATE" not in text:
        raise CertError("not a PEM certificate")
    try:
        cert = x509.load_pem_x509_certificate(text.encode())
    except ValueError as e:
        raise CertError(f"unreadable certificate: {e}") from None
    der = cert.public_bytes(Encoding.DER)
    return {"fingerprint": hashlib.sha256(der).hexdigest(), "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before_utc, "not_after": cert.not_valid_after_utc}


def mtls_required_everywhere() -> bool:
    return os.environ.get("GR_REQUIRE_MTLS", "1" if is_production() else "0") == "1"


class ProxyTrust:
    """Who may hand us a client certificate in a header."""

    def __init__(self, spec: str | None = None, header: str | None = None):
        self.header = (header or os.environ.get("GR_CLIENT_CERT_HEADER") or "x-client-cert").lower()
        self.nets, self.names = [], set()
        for part in (spec if spec is not None else os.environ.get("GR_TRUSTED_PROXIES", "127.0.0.1,::1")).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                self.nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                self.names.add(part)  # e.g. a hostname in tests

    def trusted(self, host: str | None) -> bool:
        if not host:
            return False
        if host in self.names:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in n for n in self.nets)

    def client_ip(self, peer: str | None, headers) -> str:
        """The real client address for rate limits. Behind a trusted proxy, walk
        X-Forwarded-For from the right, skipping our own proxies; the first address that
        isn't one of ours is the client. A client can prepend anything it likes to the
        header, but it can't change what our proxy appended, so this can't be spoofed."""
        if not peer:
            return "unknown"
        if not self.trusted(peer):
            return peer
        hops = [h.strip() for h in (headers.get("x-forwarded-for") or "").split(",") if h.strip()]
        for hop in reversed(hops):
            if not self.trusted(hop):
                return hop
        return peer

    def certificate(self, host: str | None, headers) -> str | None:
        """The forwarded certificate, or None if absent or from an untrusted hop."""
        value = headers.get(self.header)
        if not value or not self.trusted(host):
            return None
        return value


class CertMixin:
    """Mixed into Registry."""

    def _cert_rows(self, pid: str, status: str | None = None):
        sql = "SELECT * FROM participant_certs WHERE participant_id=?" + (" AND status=?" if status else "")
        return self.db.all(sql + " ORDER BY added_at", (pid, status) if status else (pid,))

    def participant_certs(self, pid: str) -> list[dict]:
        self._participant_row(pid)
        return [{"fingerprint": r["fingerprint"], "subject": r["subject"], "not_after": r["not_after"],
                 "status": r["status"], "added_by": r["added_by"], "added_at": r["added_at"]}
                for r in self._cert_rows(pid)]

    def _insert_cert(self, c, pid: str, info: dict, status: str, by: str) -> None:
        if info["not_after"] <= self.clock.now():
            raise Invalid("certificate has expired")
        existing = c.execute("SELECT status FROM participant_certs WHERE participant_id=? AND fingerprint=?",
                             (pid, info["fingerprint"])).fetchone()
        if existing and existing["status"] in ("pending", "active"):
            raise Conflict(f"certificate is already {existing['status']}")
        other = c.execute("SELECT participant_id FROM participant_certs WHERE fingerprint=? AND status='active' "
                          "AND participant_id<>?", (info["fingerprint"], pid)).fetchone()
        if other:
            raise Conflict("this certificate is pinned to another participant")
        c.execute("DELETE FROM participant_certs WHERE participant_id=? AND fingerprint=?", (pid, info["fingerprint"]))
        c.execute("INSERT INTO participant_certs (participant_id, fingerprint, subject, not_after, status, added_by, "
                  "added_at) VALUES (?,?,?,?,?,?,?)",
                  (pid, info["fingerprint"], info["subject"], iso(info["not_after"]), status, by, self._now()))

    @staticmethod
    def _parse(pem: str) -> dict:
        try:
            return parse_certificate(pem)
        except CertError as e:
            raise Invalid(str(e)) from None

    # ------------------------------------------------------------- operators
    def request_cert_pin(self, operator: str, pid: str, pem: str) -> dict:
        r = self._participant_row(pid)
        if r["status"] == "offboarded":
            raise Conflict("participant is offboarded")
        info = self._parse(pem)
        with self.db.tx() as c:
            self._insert_cert(c, pid, info, "pending", f"operator:{operator}")
            self._audit(c, f"operator:{operator}", "cert.pin_requested", None, participant_id=pid,
                        fingerprint=info["fingerprint"], subject=info["subject"])
        return {"fingerprint": info["fingerprint"], "status": "pending"}

    def approve_cert_pin(self, operator: str, pid: str, fingerprint: str, *, allow_self: bool = False) -> dict:
        row = self.db.one("SELECT * FROM participant_certs WHERE participant_id=? AND fingerprint=?", (pid, fingerprint))
        if not row:
            raise NotFound("certificate not found")
        if row["status"] != "pending":
            raise Conflict(f"certificate is {row['status']}")
        if row["added_by"] == f"operator:{operator}" and not allow_self:
            raise Forbidden("a different operator must approve this (four-eyes rule)")
        with self.db.tx() as c:
            if not c.execute("UPDATE participant_certs SET status='active', decided_by=?, decided_at=? "
                             "WHERE participant_id=? AND fingerprint=? AND status='pending'",
                             (f"operator:{operator}", self._now(), pid, fingerprint)).rowcount:
                raise Conflict("certificate was decided meanwhile")
            self._audit(c, f"operator:{operator}", "cert.pinned", None, participant_id=pid, fingerprint=fingerprint)
            self._participant_event(c, pid)
        return {"fingerprint": fingerprint, "status": "active"}

    def remove_cert_pin(self, actor: str, pid: str, fingerprint: str, presented: str | None = None) -> dict:
        """Operator or the participant itself. Instant (it only narrows access)."""
        row = self.db.one("SELECT * FROM participant_certs WHERE participant_id=? AND fingerprint=? "
                          "AND status IN ('pending','active')", (pid, fingerprint))
        if not row:
            raise NotFound("certificate not found")
        if presented == fingerprint and len(self._cert_rows(pid, "active")) <= 1:
            raise Conflict("you are calling with this certificate and it is your only one; pin a new one first")
        with self.db.tx() as c:
            c.execute("UPDATE participant_certs SET status='removed', decided_by=?, decided_at=? "
                      "WHERE participant_id=? AND fingerprint=?", (actor, self._now(), pid, fingerprint))
            self._audit(c, actor, "cert.removed", None, participant_id=pid, fingerprint=fingerprint)
            self._participant_event(c, pid)
        return {"fingerprint": fingerprint, "status": "removed"}

    # ------------------------------------------------------------- participant self-service
    def rotate_cert(self, pid: str, presented: str | None, new_pem: str) -> dict:
        """Add a new certificate from a call that already presents a pinned one."""
        if not presented or not self.db.one("SELECT 1 FROM participant_certs WHERE participant_id=? AND fingerprint=? "
                                            "AND status='active'", (pid, presented)):
            raise Forbidden("rotation must be made over mutual TLS with a currently pinned certificate")
        info = self._parse(new_pem)
        with self.db.tx() as c:
            self._insert_cert(c, pid, info, "active", pid)
            self._audit(c, pid, "cert.rotated", None, participant_id=pid, fingerprint=info["fingerprint"],
                        via=presented)
            self._participant_event(c, pid)
        return {"fingerprint": info["fingerprint"], "status": "active",
                "note": "both certificates work now; remove the old one when you have switched"}

    # ------------------------------------------------------------- enforcement
    def check_client_cert(self, pid: str, forwarded_pem: str | None) -> str | None:
        """Called on every participant request. Returns the presented fingerprint (or None
        when mTLS doesn't apply to this participant); raises Unauthorized otherwise."""
        active = self._cert_rows(pid, "active")
        if not active and not mtls_required_everywhere():
            if forwarded_pem:  # not required, but tell the caller which pin it used if any
                try:
                    return parse_certificate(forwarded_pem)["fingerprint"]
                except CertError:
                    return None
            return None
        if not forwarded_pem:
            raise Unauthorized("client certificate required (mutual TLS)")
        try:
            info = parse_certificate(forwarded_pem)
        except CertError:
            raise Unauthorized("client certificate unreadable") from None
        now = self.clock.now()
        if not info["not_before"] <= now <= info["not_after"]:
            raise Unauthorized("client certificate is not valid now")
        if info["fingerprint"] not in {r["fingerprint"] for r in active}:
            raise Unauthorized("client certificate is not pinned for this participant")
        return info["fingerprint"]
