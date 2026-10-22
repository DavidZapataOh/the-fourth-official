"""COSE_Sign1 (RFC 9052 section 4.2) with EdDSA.

Messages are built directly with `cbor2` canonical encoding and Ed25519, so
production code needs no COSE library; `pycose` stays a test-only cross-check.
Verification reads the message with a small strict CBOR reader instead of a
library decoder: `cbor2` and `cborg` disagree on tags, simple values, floats,
UTF-8 validity and duplicate keys, and the Python and TypeScript verifiers must
accept exactly the same inputs. The accepted subset is integers, byte and text
strings, arrays, maps with integer or text keys (no duplicates) and null; tags
other than a leading tag 18, floats, other simple values, indefinite lengths,
invalid UTF-8 and trailing bytes are rejected.
"""

from typing import Any, cast

import cbor2

from .ed25519 import sign, verify

_TAG_SIGN1 = 0xD2
_ALG_LABEL = 1
_CRIT_LABEL = 2
_KID_LABEL = 4
_ALG_EDDSA = -8
_SIGNATURE_SIZE = 64
_FIELD_COUNT = 4
_MAX_DEPTH = 32
_NULL_BYTE = 0xF6
_MIN_EXTENDED = 24
_ARG_SIZES = {24: 1, 25: 2, 26: 4, 27: 8}

_MAJOR_UINT, _MAJOR_NINT, _MAJOR_BYTES, _MAJOR_TEXT = 0, 1, 2, 3
_MAJOR_ARRAY, _MAJOR_MAP, _MAJOR_TAG, _MAJOR_SIMPLE = 4, 5, 6, 7


class CoseError(ValueError):
    """A COSE_Sign1 message is malformed, uses another profile or fails verification."""


def _to_be_signed(protected: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def cose_sign1(seed: bytes, payload: bytes, kid: bytes) -> bytes:
    """Return a tag-18 COSE_Sign1 message signed with EdDSA over Ed25519.

    The protected header is `{1: -8, 4: kid}` under CBOR core deterministic encoding.
    """
    protected = cbor2.dumps({_ALG_LABEL: _ALG_EDDSA, _KID_LABEL: kid}, canonical=True)
    signature = sign(seed, _to_be_signed(protected, payload))
    unprotected: dict[int, bytes] = {}
    body = cbor2.dumps([protected, unprotected, payload, signature], canonical=True)
    return bytes([_TAG_SIGN1]) + body


def _head(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return `(major type, argument, next position)` of the item head at `pos`."""
    if pos >= len(data):
        raise CoseError("malformed CBOR")
    major, info = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if info < _MIN_EXTENDED:
        return major, info, pos
    size = _ARG_SIZES.get(info)
    if size is None:
        raise CoseError("indefinite or reserved length")
    if pos + size > len(data):
        raise CoseError("malformed CBOR")
    return major, int.from_bytes(data[pos : pos + size], "big"), pos + size


def _read_string(data: bytes, major: int, length: int, pos: int) -> tuple[bytes | str, int]:
    if length > len(data) - pos:
        raise CoseError("malformed CBOR")
    chunk = data[pos : pos + length]
    if major == _MAJOR_BYTES:
        return chunk, pos + length
    try:
        return chunk.decode("utf-8"), pos + length
    except UnicodeDecodeError as error:
        raise CoseError("invalid UTF-8") from error


def _read(data: bytes, pos: int, depth: int) -> tuple[Any, int]:
    if depth > _MAX_DEPTH:
        raise CoseError("nesting too deep")
    start = pos
    major, arg, pos = _head(data, pos)
    if major == _MAJOR_TAG:
        raise CoseError("CBOR tags are not allowed")
    if major == _MAJOR_SIMPLE:
        if data[start] != _NULL_BYTE:
            raise CoseError("only null is allowed among simple values and floats")
        return None, pos
    if major == _MAJOR_UINT:
        return arg, pos
    if major == _MAJOR_NINT:
        return -1 - arg, pos
    if major in (_MAJOR_BYTES, _MAJOR_TEXT):
        return _read_string(data, major, arg, pos)
    return _read_container(data, major, arg, pos, depth)


def _read_container(data: bytes, major: int, count: int, pos: int, depth: int) -> tuple[Any, int]:
    if count > len(data) - pos:
        raise CoseError("malformed CBOR")
    if major == _MAJOR_ARRAY:
        items: list[Any] = []
        for _ in range(count):
            item, pos = _read(data, pos, depth + 1)
            items.append(item)
        return items, pos
    entries: dict[int | str, Any] = {}
    for _ in range(count):
        key, pos = _read(data, pos, depth + 1)
        if not isinstance(key, int | str):
            raise CoseError("map keys must be integers or text")
        if key in entries:
            raise CoseError("duplicate map key")
        entries[key], pos = _read(data, pos, depth + 1)
    return entries, pos


def _decode(data: bytes) -> Any:
    value, end = _read(data, 0, 0)
    if end != len(data):
        raise CoseError("trailing bytes after CBOR item")
    return value


def _as_bytes(message: object) -> bytes:
    if not isinstance(message, bytes | bytearray | memoryview):
        raise CoseError("message must be bytes")
    return bytes(cast("bytes | bytearray | memoryview[int]", message))


def _parse(message: bytes) -> tuple[bytes, bytes | None, bytes]:
    body = message[1:] if message[:1] == bytes([_TAG_SIGN1]) else message
    fields = _decode(body)
    if not isinstance(fields, list) or len(cast(list[Any], fields)) != _FIELD_COUNT:
        raise CoseError("COSE_Sign1 must be an array of four items")
    protected, unprotected, payload, signature = cast(list[Any], fields)
    if not isinstance(protected, bytes) or not isinstance(unprotected, dict):
        raise CoseError("malformed headers")
    if payload is not None and not isinstance(payload, bytes):
        raise CoseError("payload must be a byte string")
    if not isinstance(signature, bytes):
        raise CoseError("signature must be a byte string")
    return protected, payload, signature


def _protected_header(protected: bytes) -> dict[int | str, Any]:
    if not protected:
        return {}
    header = _decode(protected)
    if not isinstance(header, dict):
        raise CoseError("protected header must be a map")
    return cast(dict[int | str, Any], header)


def cose_verify1(public: bytes, message: bytes | bytearray | memoryview) -> bytes:
    """Verify a COSE_Sign1 message and return its payload.

    Accepts tag 18 or an untagged array. Requires `alg` to be EdDSA (-8) in the
    protected header, an attached payload and a 64-byte signature. Every failure
    raises `CoseError`. Select the public key by `cose_kid` first, then verify.
    Messages are malleable outside the protected header: deduplicate on payload
    plus kid, never on raw message bytes.
    """
    protected, payload, signature = _parse(_as_bytes(message))
    header = _protected_header(protected)
    if header.get(_ALG_LABEL) != _ALG_EDDSA:
        raise CoseError("protected header must carry alg EdDSA (-8)")
    if _CRIT_LABEL in header:
        raise CoseError("critical headers are not supported")
    if payload is None:
        raise CoseError("detached payloads are not supported")
    if len(signature) != _SIGNATURE_SIZE:
        raise CoseError("signature must be 64 bytes")
    if not verify(public, _to_be_signed(protected, payload), signature):
        raise CoseError("signature verification failed")
    return payload


def cose_kid(message: bytes | bytearray | memoryview) -> bytes:
    """Return the `kid` from the protected header; the signature is not checked."""
    protected, _, _ = _parse(_as_bytes(message))
    kid = _protected_header(protected).get(_KID_LABEL)
    if not isinstance(kid, bytes):
        raise CoseError("protected header has no kid")
    return kid
