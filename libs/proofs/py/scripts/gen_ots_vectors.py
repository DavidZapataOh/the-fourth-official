"""Regenerate `vectors/ots.json`. Deterministic apart from the stamped proof, which is kept.

The pending proof comes from the reference client (`stamp_test_hash.sh` passes it in with the
calendar URLs `ots info` printed). The Bitcoin-attested proof and the invalid proofs are built
here from the OpenTimestamps serialization format; their block root is synthetic.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[2] / "vectors" / "ots.json"
DATA = "The Fourth Official RFC 3161 test vector"
MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
SHA1, RIPEMD160, SHA256, KECCAK256 = b"\x02", b"\x03", b"\x08", b"\x67"
APPEND, PREPEND, REVERSE, HEXLIFY = b"\xf0", b"\xf1", b"\xf2", b"\xf3"
FORK, ATTESTATION = b"\xff", b"\x00"
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
UNKNOWN = bytes.fromhex("f0f1f2f3f4f5f6f7")
CALENDAR = "https://calendar.example.org"
BLOCK_HEIGHT = 900000
MAX_DEPTH = 255
LOW_7 = 0x7F


def varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        out.append((n & LOW_7) | (0x80 if n > LOW_7 else 0))
        n >>= 7
        if not n:
            return bytes(out)


def varbytes(b: bytes) -> bytes:
    return varuint(len(b)) + b


def label(text: str, size: int) -> bytes:
    return hashlib.sha256(f"fourth-proofs/ots/{text}".encode()).digest()[:size]


def attestation(tag: bytes, payload: bytes) -> bytes:
    return ATTESTATION + tag + varbytes(payload)


def pending(uri: str) -> bytes:
    return attestation(PENDING, varbytes(uri.encode()))


def bitcoin(height: int) -> bytes:
    return attestation(BITCOIN, varuint(height))


def header(digest: bytes, version: int = 1, file_op: bytes = SHA256) -> bytes:
    return MAGIC + varuint(version) + file_op + digest


def bitcoin_branch() -> tuple[bytes, bytes]:
    """An operation path through every supported operation, ending in a Bitcoin attestation."""
    msg = hashlib.sha256(DATA.encode()).digest()
    ops = bytearray()

    def binary(tag: bytes, arg: bytes) -> None:
        nonlocal msg
        ops.extend(tag + varbytes(arg))
        msg = msg + arg if tag == APPEND else arg + msg

    def unary(tag: bytes) -> None:
        nonlocal msg
        ops.extend(tag)
        match tag:
            case b"\x08":
                msg = hashlib.sha256(msg).digest()
            case b"\x02":
                msg = hashlib.sha1(msg).digest()
            case b"\x03":
                msg = hashlib.new("ripemd160", msg).digest()
            case b"\xf2":
                msg = msg[::-1]
            case _:
                msg = msg.hex().encode()

    binary(APPEND, label("nonce", 16))
    unary(SHA256)
    unary(HEXLIFY)
    unary(SHA1)
    binary(PREPEND, label("left", 32))
    unary(RIPEMD160)
    unary(REVERSE)
    unary(SHA256)
    binary(APPEND, label("right", 32))
    unary(SHA256)
    unary(SHA256)
    return bytes(ops) + bitcoin(BLOCK_HEIGHT), msg


def calendar_branch() -> bytes:
    return APPEND + varbytes(label("calendar", 16)) + SHA256 + pending(CALENDAR)


def build(stamp: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(DATA.encode()).digest()
    branch, root = bitcoin_branch()
    tree = FORK + calendar_branch() + FORK + attestation(UNKNOWN, b"\x01") + branch
    bitcoin_proof = header(digest) + tree

    def deep(depth: int) -> bytes:
        return header(digest) + SHA256 * depth + pending(CALENDAR)

    invalid = {
        "bad_magic": b"\x01" + bitcoin_proof[1:],
        "unsupported_version": header(digest, version=2) + tree,
        "sha1_file_hash": header(hashlib.sha1(DATA.encode()).digest(), file_op=SHA1) + tree,
        "unknown_opcode": header(digest) + b"\x42" + pending(CALENDAR),
        "keccak256_unsupported": header(digest) + KECCAK256 + pending(CALENDAR),
        "too_deep": deep(MAX_DEPTH + 1),
        "empty_append": header(digest) + APPEND + varbytes(b"") + pending(CALENDAR),
        "argument_too_long": header(digest) + APPEND + varbytes(bytes(4097)) + pending(CALENDAR),
        "message_too_long": header(digest)
        + (APPEND + varbytes(bytes(2100))) * 2
        + SHA256
        + pending(CALENDAR),
        "absurd_length": header(digest) + APPEND + varuint(2**60) + b"\x00",
        "absurd_varuint": header(digest) + SHA256 + bitcoin(2**64),
        "height_above_safe_integer": header(digest) + SHA256 + bitcoin(2**53),
        "overlong_varuint": header(digest)
        + SHA256
        + attestation(BITCOIN, b"\x81" + b"\x80" * 7 + b"\x00"),
        "bitcoin_message_not_32_bytes": header(digest) + APPEND + b"\x01\x00" + bitcoin(1),
        "bitcoin_payload_trailing_bytes": header(digest)
        + SHA256
        + attestation(BITCOIN, varuint(BLOCK_HEIGHT) + b"\x00"),
        "calendar_uri_bad_character": header(digest) + pending("https://calendar.example.org/?a"),
        "calendar_uri_too_long": header(digest) + pending("https://" + "a" * 1000),
        "only_unknown_attestations": header(digest) + attestation(UNKNOWN, b"\x01"),
        "trailing_garbage": bitcoin_proof + b"\x00",
    }
    return {
        "data": DATA,
        "data_sha256": digest.hex(),
        "pending": stamp,
        "bitcoin": {
            "source": "built from the serialization format; the block root is synthetic",
            "proof": base64.b64encode(bitcoin_proof).decode(),
            "block_height": BLOCK_HEIGHT,
            "block_merkle_root": root.hex(),
            "calendars": [CALENDAR],
        },
        "deepest": {
            "source": "built from the serialization format",
            "proof": base64.b64encode(deep(MAX_DEPTH)).decode(),
            "calendars": [CALENDAR],
        },
        "invalid": [
            {"name": name, "proof": base64.b64encode(proof).decode()}
            for name, proof in invalid.items()
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pending", type=Path, help="proof written by `ots stamp`")
    parser.add_argument("--source", help="how the pending proof was made")
    parser.add_argument("--calendar", action="append", default=[], help="URL from `ots info`")
    args = parser.parse_args()
    if args.pending:
        stamp = {
            "source": args.source,
            "proof": base64.b64encode(args.pending.read_bytes()).decode(),
            "calendars": args.calendar,
        }
    else:
        stamp = json.loads(OUT.read_text(encoding="utf-8"))["pending"]
    OUT.write_text(json.dumps(build(stamp), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
