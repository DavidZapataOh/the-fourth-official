"""Generate `vectors/cose_sign1_ours.json`. Deterministic; the output is committed."""

import json
from pathlib import Path

import cbor2
from fourth_crypto import cose_sign1, public_key, sign

SEED = bytes(range(1, 33))
OTHER_SEED = bytes(range(101, 133))
KID = b"fourth-test-key-1"
PAYLOAD = b'{"match":"m1","outcome":"goal"}'
OUT = Path(__file__).resolve().parents[2] / "vectors" / "cose_sign1_ours.json"


def _protected(header: dict[int, object]) -> bytes:
    return cbor2.dumps(header, canonical=True)


def _build(
    protected: bytes,
    unprotected: dict[int, object],
    payload: bytes | None,
    *,
    signed_payload: bytes = PAYLOAD,
    tag: int | None = 18,
) -> bytes:
    sig_structure = cbor2.dumps(["Signature1", protected, b"", signed_payload], canonical=True)
    body = [protected, unprotected, payload, sign(SEED, sig_structure)]
    return cbor2.dumps(cbor2.CBORTag(tag, body) if tag is not None else body, canonical=True)


def _bstr(data: bytes) -> bytes:
    return cbor2.dumps(data)


def _raw(
    unprotected: bytes,
    *,
    protected: bytes | None = None,
    payload: bytes | None = None,
    prefix: bytes = b"\xd2",
) -> bytes:
    """Assemble a correctly signed message from raw CBOR pieces, however hostile."""
    protected = protected if protected is not None else _protected({1: -8, 4: KID})
    signed = cbor2.dumps(["Signature1", protected, b"", PAYLOAD], canonical=True)
    shown = payload if payload is not None else _bstr(PAYLOAD)
    return prefix + b"\x84" + _bstr(protected) + unprotected + shown + _bstr(sign(SEED, signed))


def _unprotected(entry: str) -> bytes:
    """A one-entry unprotected map `{5: <entry>}` with the value given as hex."""
    return bytes.fromhex("a105" + entry)


def _flip(message: bytes, index: int) -> bytes:
    return message[:index] + bytes([message[index] ^ 0x01]) + message[index + 1 :]


def main() -> None:
    message = cose_sign1(SEED, PAYLOAD, KID)
    # Offsets into the fixed layout: d2 84 | 56 a2 01 27 04 51 kid... | a0 | payload | signature
    protected_at = 9  # a kid byte inside the protected header
    payload_at = message.index(PAYLOAD) + 5
    signature_at = len(message) - 10
    good = _protected({1: -8, 4: KID})

    tampered = {
        "payload bit flip": _flip(message, payload_at),
        "signature bit flip": _flip(message, signature_at),
        "protected header bit flip": _flip(message, protected_at),
        "protected header alg bit flip": _flip(message, 5),
        "truncated by one byte": message[:-1],
        "truncated in the middle": message[: len(message) // 2],
        "truncated to the tag": message[:2],
        "trailing byte": message + b"\x00",
    }
    rejected = {
        "alg ES256 in protected header": _build(_protected({1: -7, 4: KID}), {}, PAYLOAD),
        "alg only in unprotected header": _build(_protected({4: KID}), {1: -8}, PAYLOAD),
        "alg missing": _build(_protected({4: KID}), {}, PAYLOAD),
        "empty protected header": _build(b"", {}, PAYLOAD),
        "detached payload": _build(good, {}, None),
        "unknown tag 19": _build(good, {}, PAYLOAD, tag=19),
        "double tag 18": b"\xd2" + message,
        "critical header present": _build(_protected({1: -8, 2: [4], 4: KID}), {}, PAYLOAD),
        "duplicate alg in protected header": _build(
            bytes.fromhex("a3012701270442") + KID[:2], {}, PAYLOAD
        ),
        "signature of 63 bytes": cbor2.dumps(
            cbor2.CBORTag(18, [good, {}, PAYLOAD, message[-64:-1]]), canonical=True
        ),
    }
    kid_item = b"\x04" + _bstr(KID)
    raw = {
        "tag 28 around the array": _raw(b"\xa0", prefix=b"\xd8\x1c"),
        "tag 18 then tag 28": _raw(b"\xa0", prefix=b"\xd2\xd8\x1c"),
        "tag 55799 around the array": _raw(b"\xa0", prefix=b"\xd9\xd9\xf7"),
        "alg as tag 3 bignum": _raw(b"\xa0", protected=b"\xa2\x01\xc3\x41\x07" + kid_item),
        "alg as float -8.0": _raw(b"\xa0", protected=b"\xa2\x01\xf9\xc8\x00" + kid_item),
        "alg label as float 1.0": _raw(b"\xa0", protected=b"\xa2\xf9\x3c\x00\x27" + kid_item),
        "tag 1 in unprotected header": _raw(_unprotected("c100")),
        "tag 2 in unprotected header": _raw(_unprotected("c24101")),
        "tag 24 in unprotected header": _raw(_unprotected("d81840")),
        "tag 258 in unprotected header": _raw(_unprotected("d9010280")),
        "tag in protected header": _raw(b"\xa0", protected=b"\xa3\x01\x27\x05\xc1\x00" + kid_item),
        "tag around the payload": _raw(b"\xa0", payload=b"\xd8\x18" + _bstr(PAYLOAD)),
        "tag as map key": _raw(bytes.fromhex("a1c24101") + b"\x00"),
        "unassigned simple value": _raw(_unprotected("f0")),
        "simple value 255": _raw(_unprotected("f8ff")),
        "undefined": _raw(_unprotected("f7")),
        "true": _raw(_unprotected("f5")),
        "float 1.0": _raw(_unprotected("f93c00")),
        "half float ending in the null byte": _raw(_unprotected("f900f6")),
        "two-byte simple value ending in the null byte": _raw(_unprotected("f8f6")),
        "float 64": _raw(_unprotected("fb3ff0000000000000")),
        "invalid UTF-8 text": _raw(_unprotected("62fffe")),
        "overlong UTF-8 text": _raw(_unprotected("62c080")),
        "duplicate byte-string keys": _raw(bytes.fromhex("a2410101410102")),
        "byte-string key": _raw(bytes.fromhex("a1410101")),
        "duplicate integer keys": _raw(bytes.fromhex("a2050005" + "01")),
        "duplicate text keys": _raw(bytes.fromhex("a2617800617801")),
        "indefinite-length array": b"\xd2\x9f"
        + _bstr(good)
        + b"\xa0"
        + _bstr(PAYLOAD)
        + _bstr(message[-64:])
        + b"\xff",
        "indefinite-length payload": _raw(b"\xa0", payload=b"\x5f" + _bstr(PAYLOAD) + b"\xff"),
        "indefinite-length unprotected map": _raw(b"\xbf\xff"),
        "nesting too deep": _raw(_unprotected("81" * 100 + "00")),
    }
    rejected.update(raw)
    accepted = {
        "extra integer and text labels": _raw(bytes.fromhex("a20500617882f66161")),
        "non-minimal alg": _raw(b"\xa0", protected=b"\xa2\x01\x38\x07" + kid_item),
        "extra protected label": _raw(b"\xa0", protected=b"\xa3\x01\x27\x03\x00" + kid_item),
    }
    document = {
        "seed": SEED.hex(),
        "public": public_key(SEED).hex(),
        "other_public": public_key(OTHER_SEED).hex(),
        "kid": KID.hex(),
        "payload": PAYLOAD.hex(),
        "message": message.hex(),
        "untagged": message[1:].hex(),
        "tampered": [{"name": n, "message": m.hex()} for n, m in tampered.items()],
        "rejected": [{"name": n, "message": m.hex()} for n, m in rejected.items()],
        "accepted": [{"name": n, "message": m.hex()} for n, m in accepted.items()],
        "kid_missing": [
            {
                "name": "kid only in unprotected header",
                "message": _build(_protected({1: -8}), {4: KID}, PAYLOAD).hex(),
            },
            {"name": "no kid", "message": _build(_protected({1: -8}), {}, PAYLOAD).hex()},
        ],
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
