import re

from .encoding import sha256

_CHAIN_PREFIX = b"fourth/chain/v1\x00"
_MAX_PART = 0xFFFFFFFF
_HASH_SIZE = 32
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def commitment(domain: str, *parts: bytes) -> bytes:
    """Domain-separated SHA-256 commitment over length-prefixed parts.

    `sha256(utf8(domain) || 0x00 || for each part: uint32_be(len(part)) || part)`.
    The length prefix makes the part boundaries unambiguous.

    Raises:
        ValueError: `domain` contains a NUL byte or a lone surrogate, or a part
            exceeds 2^32-1 bytes.
    """
    if "\x00" in domain:
        raise ValueError("domain must not contain a NUL byte")
    if _LONE_SURROGATE.search(domain):
        raise ValueError("domain must not contain a lone surrogate")
    if any(len(part) > _MAX_PART for part in parts):
        raise ValueError("part exceeds 2^32-1 bytes")
    buf = bytearray(domain.encode("utf-8") + b"\x00")
    for part in parts:
        buf += len(part).to_bytes(4, "big")
        buf += part
    return sha256(bytes(buf))


def chain_hash(prev_hash: bytes, data: bytes) -> bytes:
    """Next link of a hash chain: `sha256(b"fourth/chain/v1\\x00" || prev_hash || data)`.

    Raises:
        ValueError: `prev_hash` is not exactly 32 bytes.
    """
    if len(prev_hash) != _HASH_SIZE:
        raise ValueError("prev_hash must be 32 bytes")
    return sha256(_CHAIN_PREFIX + prev_hash + data)
