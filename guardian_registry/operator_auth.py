"""Operator sign-in through the organisation's identity provider (OpenID Connect).

Shared operator tokens (GR_OPERATORS) are long-lived secrets: anyone who copies one is that
operator until someone notices. With SSO the operator signs in to the company's identity
provider (Azure AD / Entra, Okta, Google Workspace, Keycloak...) and calls /v1/admin/* with
`Authorization: Bearer <ID token>`. The registry checks:

  * the signature against the provider's published keys (JWKS), the issuer and audience,
    and that the token hasn't expired (short-lived by design);
  * the operator's email is on the allow-list GR_OPERATOR_OIDC_ALLOWED and is verified;
  * optionally that they signed in with a hardware key: the `amr` claim must contain
    "hwk" (RFC 8176). On by default in production (GR_OPERATOR_REQUIRE_HWK).

The operator's email becomes their name for four-eyes checks and the audit log.
"""

from __future__ import annotations

import os
from typing import Callable

import jwt

from .security import is_production

ALGORITHMS = ["RS256", "ES256", "PS256"]


class OperatorAuthError(Exception):
    pass


class OidcVerifier:
    def __init__(self, issuer: str, audience: str, allowed: set[str], *, require_hwk: bool = False,
                 jwks_url: str | None = None, key_resolver: Callable[[str], object] | None = None,
                 leeway: int = 30):
        if not issuer or not audience:
            raise RuntimeError("operator SSO needs an issuer and an audience")
        self.issuer, self.audience, self.leeway = issuer, audience, leeway
        self.allowed = {a.strip().lower() for a in allowed if a.strip()}
        self.require_hwk = require_hwk
        if key_resolver is None:
            client = jwt.PyJWKClient(jwks_url or issuer.rstrip("/") + "/.well-known/jwks.json", cache_keys=True)
            key_resolver = lambda token: client.get_signing_key_from_jwt(token).key  # noqa: E731
        self._key = key_resolver

    def verify(self, token: str) -> str:
        """Return the operator's name (email) or raise OperatorAuthError."""
        try:
            claims = jwt.decode(token, self._key(token), algorithms=ALGORITHMS, audience=self.audience,
                                issuer=self.issuer, leeway=self.leeway,
                                options={"require": ["exp", "iat", "iss", "aud"]})
        except Exception as e:  # noqa: BLE001 - every failure is the same 401 to the caller
            raise OperatorAuthError(f"invalid operator token: {type(e).__name__}") from None
        email = str(claims.get("email") or "").lower()
        if not email or claims.get("email_verified") is False:
            raise OperatorAuthError("operator token has no verified email")
        if email not in self.allowed:
            raise OperatorAuthError("not an allowed operator")
        if self.require_hwk and "hwk" not in (claims.get("amr") or []):
            raise OperatorAuthError("operators must sign in with a hardware security key")
        return email


def oidc_from_env() -> OidcVerifier | None:
    issuer = os.environ.get("GR_OPERATOR_OIDC_ISSUER")
    if not issuer:
        return None
    allowed = set((os.environ.get("GR_OPERATOR_OIDC_ALLOWED") or "").split(","))
    hwk_default = "1" if is_production() else "0"
    return OidcVerifier(issuer, os.environ.get("GR_OPERATOR_OIDC_AUDIENCE", ""), allowed,
                        require_hwk=os.environ.get("GR_OPERATOR_REQUIRE_HWK", hwk_default) == "1",
                        jwks_url=os.environ.get("GR_OPERATOR_OIDC_JWKS_URL"))
