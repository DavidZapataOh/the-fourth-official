"""OpenTimestamps proof status, read from the detached timestamp file format."""

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from .ledger import ProofError

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
MAX_PROOF = 65536
MAX_DEPTH = 255
MAX_MESSAGE = 4096
MAX_PAYLOAD = 8192
MAX_URI = 1000
MAX_VARUINT = 2**53 - 1
MAX_VARUINT_BYTES = 8
URI_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")

_SHA256, _APPEND, _PREPEND, _REVERSE, _HEXLIFY, _FORK = 0x08, 0xF0, 0xF1, 0xF2, 0xF3, 0xFF
_HASHES: dict[int, Callable[[bytes], bytes]] = {
    0x02: lambda m: hashlib.sha1(m).digest(),
    0x03: lambda m: hashlib.new("ripemd160", m).digest(),
    _SHA256: lambda m: hashlib.sha256(m).digest(),
}
_UNSUPPORTED = {0x67: "keccak256"}


@dataclass(frozen=True)
class OtsStatus:
    """What an OpenTimestamps proof shows for a digest.

    `anchored` means a Bitcoin attestation in the proof commits to the Merkle root supplied for
    its block, and `block_height` is the lowest such block. Otherwise the proof is `pending`;
    `unverified_anchor_height` is the lowest block a Bitcoin attestation claims when no root was
    supplied to check it against. `calendars` lists the pending calendar URLs in proof order.
    """

    kind: Literal["pending", "anchored"]
    block_height: int | None
    calendars: list[str]
    unverified_anchor_height: int | None


def ots_status(
    proof: bytes, data_sha256: bytes, *, block_merkle_roots: Mapping[int, bytes] | None = None
) -> OtsStatus:
    """Read a detached OpenTimestamps proof (`.ots` file) for a SHA-256 digest.

    `block_merkle_roots` maps block heights to Merkle roots in block header byte order (the
    reverse of the hex block explorers show). A Bitcoin attestation whose computed root differs
    from the supplied one is rejected; without a supplied root it never counts as anchored.
    Raises `ProofError` for another digest or a malformed, truncated or unsupported proof.
    """
    if len(proof) > MAX_PROOF:
        raise ProofError("proof is too large")
    reader = _Reader(proof)
    if reader.take(len(MAGIC)) != MAGIC:
        raise ProofError("not an OpenTimestamps proof")
    if reader.varuint() != 1:
        raise ProofError("unsupported proof version")
    if reader.byte() != _SHA256:
        raise ProofError("proof is not for a SHA-256 file hash")
    if len(data_sha256) != 32 or reader.take(32) != data_sha256:  # noqa: PLR2004
        raise ProofError("proof is for another digest")
    found = _Found()
    _timestamp(reader, data_sha256, 0, found)
    reader.end()
    if not found.calendars and not found.anchors:
        raise ProofError("proof has no pending or Bitcoin attestation")

    roots = block_merkle_roots or {}
    verified: list[int] = []
    for height, root in found.anchors:
        if height in roots:
            if roots[height] != root:
                raise ProofError(f"proof does not match the Merkle root of block {height}")
            verified.append(height)
    calendars = list(dict.fromkeys(found.calendars))
    if verified:
        return OtsStatus("anchored", min(verified), calendars, None)
    claimed = min((height for height, _ in found.anchors), default=None)
    return OtsStatus("pending", None, calendars, claimed)


@dataclass
class _Found:
    calendars: list[str] = field(default_factory=list[str])
    anchors: list[tuple[int, bytes]] = field(default_factory=list[tuple[int, bytes]])


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ProofError("proof is truncated")
        self.pos += n
        return self.data[self.pos - n : self.pos]

    def byte(self) -> int:
        return self.take(1)[0]

    def varuint(self) -> int:
        value = 0
        for i in range(MAX_VARUINT_BYTES):
            b = self.byte()
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                if value > MAX_VARUINT:
                    break
                return value
        raise ProofError("integer is too large")

    def varbytes(self, max_len: int, min_len: int = 0) -> bytes:
        n = self.varuint()
        if not min_len <= n <= max_len:
            raise ProofError(f"field length {n} is out of range")
        return self.take(n)

    def end(self) -> None:
        if self.pos != len(self.data):
            raise ProofError("unexpected trailing data")


def _timestamp(reader: _Reader, msg: bytes, depth: int, found: _Found) -> None:
    tag = reader.byte()
    while tag == _FORK:
        _branch(reader, reader.byte(), msg, depth, found)
        tag = reader.byte()
    _branch(reader, tag, msg, depth, found)


def _branch(reader: _Reader, tag: int, msg: bytes, depth: int, found: _Found) -> None:
    if tag == 0:
        _attestation(reader, msg, found)
        return
    if depth == MAX_DEPTH:
        raise ProofError("proof is too deep")
    _timestamp(reader, _apply(reader, tag, msg), depth + 1, found)


def _apply(reader: _Reader, tag: int, msg: bytes) -> bytes:
    if tag in _HASHES:
        result = _HASHES[tag](msg)
    elif tag in (_APPEND, _PREPEND):
        arg = reader.varbytes(MAX_MESSAGE, 1)
        result = msg + arg if tag == _APPEND else arg + msg
    elif tag == _REVERSE:
        result = msg[::-1]
    elif tag == _HEXLIFY:
        result = msg.hex().encode()
    elif tag in _UNSUPPORTED:
        raise ProofError(f"unsupported operation: {_UNSUPPORTED[tag]}")
    else:
        raise ProofError(f"unknown operation 0x{tag:02x}")
    if len(result) > MAX_MESSAGE:
        raise ProofError("operation result is too long")
    return result


def _attestation(reader: _Reader, msg: bytes, found: _Found) -> None:
    tag = reader.take(8)
    payload = _Reader(reader.varbytes(MAX_PAYLOAD))
    if tag == PENDING:
        uri = payload.varbytes(MAX_URI)
        payload.end()
        if not set(uri) <= URI_CHARS:
            raise ProofError("calendar URL has a forbidden character")
        found.calendars.append(uri.decode())
    elif tag == BITCOIN:
        height = payload.varuint()
        payload.end()
        if len(msg) != 32:  # noqa: PLR2004
            raise ProofError("Bitcoin attestation is not on a 32-byte Merkle root")
        found.anchors.append((height, msg))
