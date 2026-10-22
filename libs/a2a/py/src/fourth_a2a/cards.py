"""Signed A2A Agent Cards (protocol v1.0, section 8.4: JWS over the RFC 8785 canonical card)."""

import json
from collections.abc import Mapping
from typing import Any, cast

import jwt
from a2a.types import AgentCard
from a2a.utils.signing import SignatureVerificationError, create_signature_verifier
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fourth_crypto import EncodingError, JsonValue, b64url_decode, b64url_encode, canonicalize
from google.api import field_behavior_pb2  # pyright: ignore[reportMissingTypeStubs]
from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf.json_format import MessageToDict

ALGORITHM = "ES256"
_SIGNATURE_SIZE = 64
_REQUIRED = field_behavior_pb2.FieldBehavior.REQUIRED


class CardVerificationError(ValueError):
    """The Agent Card carries no signature that verifies against the trusted keys."""


def card_to_json(card: AgentCard) -> dict[str, Any]:
    """Return the card as v1.0 JSON; REQUIRED fields keep default values, other defaults go."""
    return _prune(
        MessageToDict(card, always_print_fields_with_no_presence=True),
        cast(Descriptor, card.DESCRIPTOR),
    )


def sign_card(card: AgentCard, private_jwk: Mapping[str, Any], kid: str) -> AgentCard:
    """Return a copy of `card` carrying an additional ES256 signature made with `private_jwk`."""
    signed = AgentCard()
    signed.CopyFrom(card)
    token = jwt.api_jws.encode(
        _canonical_payload(card_to_json(card)),
        jwt.PyJWK.from_dict(dict(private_jwk), ALGORITHM),
        algorithm=ALGORITHM,
        headers={"kid": kid, "typ": "JOSE"},
    )
    protected, _, signature = token.split(".")
    signed.signatures.add(protected=protected, signature=signature)
    return signed


def verify_card(card: AgentCard, keys: Mapping[str, Mapping[str, Any]]) -> None:
    """Verify with the SDK helper; `keys` maps `kid` to a public JWK. Never fetches `jku`."""

    def key_provider(kid: str | None, jku: str | None) -> jwt.PyJWK:
        if kid is None or kid not in keys:
            raise jwt.InvalidKeyError(f"unknown kid: {kid}")
        return jwt.PyJWK.from_dict(dict(keys[kid]), ALGORITHM)

    try:
        create_signature_verifier(key_provider, [ALGORITHM])(card)
    except (SignatureVerificationError, ValueError) as error:
        raise CardVerificationError(str(error)) from error


def independent_verify_card(
    card_json: Mapping[str, Any], keys: Mapping[str, Mapping[str, Any]]
) -> None:
    """Verify a served card without SDK code: JCS of the card minus `signatures`, then ES256."""
    signatures = card_json.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise CardVerificationError("card has no signatures")
    payload = b64url_encode(_canonical_payload(card_json))
    for entry in cast(list[object], signatures):
        try:
            _verify_signature(entry, payload, keys)
        except (EncodingError, InvalidSignature, KeyError, TypeError, ValueError):
            continue
        return
    raise CardVerificationError("no valid signature")


def _verify_signature(entry: object, payload: str, keys: Mapping[str, Mapping[str, Any]]) -> None:
    if not isinstance(entry, Mapping):
        raise TypeError("signature entry is not an object")
    protected = str(cast(Mapping[str, Any], entry)["protected"])
    signature = b64url_decode(str(cast(Mapping[str, Any], entry)["signature"]))
    header = json.loads(b64url_decode(protected))
    if header.get("alg") != ALGORITHM:
        raise ValueError("algorithm is not ES256")
    public_key = jwt.PyJWK.from_dict(dict(keys[header["kid"]]), ALGORITHM).key
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or public_key.curve.name != "secp256r1"
    ):
        raise ValueError("key is not a P-256 public key")
    if len(signature) != _SIGNATURE_SIZE:
        raise ValueError("ES256 signature must be 64 bytes")
    half = _SIGNATURE_SIZE // 2
    der = encode_dss_signature(int.from_bytes(signature[:half]), int.from_bytes(signature[half:]))
    public_key.verify(der, f"{protected}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))


def _canonical_payload(card_json: Mapping[str, Any]) -> bytes:
    return canonicalize(cast(JsonValue, {k: v for k, v in card_json.items() if k != "signatures"}))


def _prune(data: dict[str, Any], descriptor: Descriptor) -> dict[str, Any]:
    for field in descriptor.fields:
        name = field.json_name
        if name not in data:
            continue
        data[name] = _prune_value(data[name], field)
        if not _keeps_default(field) and data[name] in ("", [], {}, False):
            del data[name]
    return data


def _prune_value(value: Any, field: FieldDescriptor) -> Any:
    message = field.message_type
    if message is None:
        return value
    if message.GetOptions().map_entry:
        value_type = message.fields_by_name["value"].message_type
        return {k: _prune(v, value_type) for k, v in value.items()} if value_type else value
    if field.is_repeated:
        return [_prune(item, message) for item in value]
    return _prune(value, message) if not message.full_name.startswith("google.protobuf.") else value


def _keeps_default(field: FieldDescriptor) -> bool:
    extensions = cast(Any, field.GetOptions().Extensions)
    behaviors = cast(list[int], extensions[field_behavior_pb2.field_behavior])  # pyright: ignore[reportUnknownMemberType]
    return _REQUIRED in behaviors or field.has_presence
