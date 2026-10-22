from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .encoding import EncodingError, format_signature, parse_signature
from .jcs import JsonValue, canonicalize


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return a new `(seed, public_key)` pair, both 32 bytes."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return seed, _public_bytes(key)


def public_key(seed: bytes) -> bytes:
    """Derive the public key from a 32-byte seed; a wrong-length seed raises `ValueError`."""
    return _public_bytes(Ed25519PrivateKey.from_private_bytes(seed))


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature of `message`."""
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Check a signature. Malformed keys or signatures return `False`; this never raises."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_json(seed: bytes, value: JsonValue) -> str:
    """Sign the RFC 8785 canonical bytes of `value`; returns `ed25519:` plus base64url.

    Integer fields must stay at or below 2^53-1 so that both languages
    canonicalize them identically.
    """
    return format_signature(sign(seed, canonicalize(value)))


def verify_json(public: bytes, value: JsonValue, signature: str) -> bool:
    """Verify a `sign_json` signature; a malformed signature string returns `False`."""
    try:
        raw = parse_signature(signature)
    except EncodingError:
        return False
    return verify(public, canonicalize(value), raw)
