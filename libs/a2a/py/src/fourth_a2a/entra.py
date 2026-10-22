"""Validation of Microsoft Entra access tokens presented to an A2A server."""

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

import jwt


class EntraTokenError(ValueError):
    """The Entra access token is not acceptable."""


@dataclass(frozen=True)
class EntraClaims:
    oid: str
    appid: str
    roles: tuple[str, ...]


def validate_entra_token(
    token: str,
    *,
    tenant_id: str,
    audience: str,
    jwks: Mapping[str, Any],
    now: float | None = None,
) -> EntraClaims:
    """Validate an RS256 Entra access token against a tenant's JWKS.

    Accepts the v1 and v2 issuer formats of `tenant_id`. `exp` and `nbf` are compared with
    `now` (default: current time) so the clock is injectable. The JWKS is supplied by the
    caller from the tenant's `discovery/v2.0/keys` document; nothing is fetched here.
    """
    issuers = (
        f"https://sts.windows.net/{tenant_id}/",
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
    )
    try:
        kid = str(jwt.get_unverified_header(token).get("kid"))
        key = jwt.PyJWKSet.from_dict(dict(jwks))[kid]
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            options={
                "require": ["exp", "nbf", "iss", "aud"],
                "verify_exp": False,
                "verify_nbf": False,
            },
        )
    except KeyError as error:
        raise EntraTokenError(f"unknown kid: {error}") from error
    except jwt.PyJWTError as error:
        raise EntraTokenError(f"invalid token: {error}") from error

    if claims["iss"] not in issuers:
        raise EntraTokenError("unexpected issuer")
    if claims["aud"] != audience:
        raise EntraTokenError("unexpected audience")
    if claims.get("tid") != tenant_id:
        raise EntraTokenError("unexpected tenant")
    current = time.time() if now is None else now
    if not _is_number(claims["exp"]) or claims["exp"] <= current:
        raise EntraTokenError("token is expired")
    if not _is_number(claims["nbf"]) or claims["nbf"] > current:
        raise EntraTokenError("token is not yet valid")

    oid = claims.get("oid")
    appid = claims.get("appid") or claims.get("azp")
    roles: object = claims.get("roles") or []
    if not isinstance(oid, str) or not oid or not isinstance(appid, str):
        raise EntraTokenError("token carries no caller identity")
    if not isinstance(roles, list) or not all(
        isinstance(r, str) for r in cast(list[object], roles)
    ):
        raise EntraTokenError("roles claim is malformed")
    return EntraClaims(oid=oid, appid=appid, roles=tuple(cast(list[str], roles)))


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)
