"""Strict encodings, digests and signature formats."""

import base64
import hashlib
import re

DIGEST_PREFIX = "sha256:"
SIGNATURE_PREFIX = "ed25519:"
DIGEST_SIZE = 32
SIGNATURE_SIZE = 64

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


class EncodingError(ValueError):
    """Input is not in the exact canonical encoding."""


def b64url_encode(data: bytes) -> str:
    """Encode as base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Decode canonical unpadded base64url; padding, other alphabets and stray bits are errors."""
    if not text.isascii():
        raise EncodingError("base64url text must be ASCII")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise EncodingError("invalid base64url") from exc
    if b64url_encode(data) != text:
        raise EncodingError("non-canonical base64url")
    return data


def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of `data`."""
    return hashlib.sha256(data).digest()


def format_digest(raw: bytes) -> str:
    """Format a 32-byte digest as `sha256:` plus lowercase hex."""
    if len(raw) != DIGEST_SIZE:
        raise EncodingError(f"digest must be {DIGEST_SIZE} bytes")
    return DIGEST_PREFIX + raw.hex()


def parse_digest(text: str) -> bytes:
    """Parse `sha256:` plus 64 lowercase hex digits into the 32 raw bytes."""
    if not text.startswith(DIGEST_PREFIX) or not _HEX_DIGEST.fullmatch(text[len(DIGEST_PREFIX) :]):
        raise EncodingError("digest must be 'sha256:' followed by 64 lowercase hex digits")
    return bytes.fromhex(text[len(DIGEST_PREFIX) :])


def format_signature(raw: bytes) -> str:
    """Format a 64-byte signature as `ed25519:` plus base64url."""
    if len(raw) != SIGNATURE_SIZE:
        raise EncodingError(f"signature must be {SIGNATURE_SIZE} bytes")
    return SIGNATURE_PREFIX + b64url_encode(raw)


def parse_signature(text: str) -> bytes:
    """Parse `ed25519:` plus base64url into the 64 raw signature bytes."""
    if not text.startswith(SIGNATURE_PREFIX):
        raise EncodingError("signature must start with 'ed25519:'")
    raw = b64url_decode(text[len(SIGNATURE_PREFIX) :])
    if len(raw) != SIGNATURE_SIZE:
        raise EncodingError(f"signature must be {SIGNATURE_SIZE} bytes")
    return raw
