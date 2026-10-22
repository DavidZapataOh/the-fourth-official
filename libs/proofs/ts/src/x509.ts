/**
 * The X.509 fields an ECDSA endorsement check needs, read with a strict DER subset.
 * Names, validity and extensions are covered by the signature but not interpreted.
 */

export type Curve = "P-256" | "P-384";
export type SignatureHash = "SHA-256" | "SHA-384" | "SHA-512";

export type Certificate = {
  tbs: Uint8Array;
  spki: Uint8Array;
  curve: Curve;
  publicKey: Uint8Array;
  signatureHash: SignatureHash;
  signature: Uint8Array;
};

export class X509Error extends Error {
  override name = "X509Error";
}

type Tlv = { tag: number; bytes: Uint8Array; value: Uint8Array };

const SEQUENCE = 0x30;
const BIT_STRING = 0x03;
const OID = 0x06;
const EXPLICIT_0 = 0xa0;

const EC_PUBLIC_KEY = "2a8648ce3d0201";
const CURVES: Record<string, Curve> = { "2a8648ce3d030107": "P-256", "2b81040022": "P-384" };
const SIGNATURE_HASHES: Record<string, SignatureHash> = {
  "2a8648ce3d040302": "SHA-256",
  "2a8648ce3d040303": "SHA-384",
  "2a8648ce3d040304": "SHA-512",
};

const PEM = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Decode padded standard base64; any other alphabet or padding is an error. */
export function decodeBase64(text: string): Uint8Array {
  if (!BASE64.test(text)) throw new X509Error("invalid base64");
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

function readTlv(data: Uint8Array, offset: number): Tlv {
  const tag = data[offset];
  let length = data[offset + 1];
  if (tag === undefined || length === undefined || (tag & 0x1f) === 0x1f) {
    throw new X509Error("invalid DER header");
  }
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3 || data[offset + 2] === 0) throw new X509Error("invalid length");
    length = 0;
    for (let i = 0; i < count; i++) length = (length << 8) | (data[offset + 2 + i] ?? 0);
    if (length < 0x80) throw new X509Error("non-minimal length");
    header += count;
  }
  const end = offset + header + length;
  if (end > data.length) throw new X509Error("truncated DER");
  return { tag, bytes: data.subarray(offset, end), value: data.subarray(offset + header, end) };
}

function children(tlv: Tlv | undefined): Tlv[] {
  if (tlv?.tag !== SEQUENCE) throw new X509Error("expected a sequence");
  const out: Tlv[] = [];
  let offset = 0;
  while (offset < tlv.value.length) {
    const child = readTlv(tlv.value, offset);
    out.push(child);
    offset += child.bytes.length;
  }
  return out;
}

function oid(tlv: Tlv | undefined): string {
  if (tlv?.tag !== OID) throw new X509Error("expected an object identifier");
  return Array.from(tlv.value, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bitString(tlv: Tlv | undefined): Uint8Array {
  if (tlv?.tag !== BIT_STRING || tlv.value[0] !== 0) {
    throw new X509Error("expected a bit string of whole bytes");
  }
  return tlv.value.subarray(1);
}

function lookup<T>(table: Record<string, T>, key: string, what: string): T {
  const value = table[key];
  if (value === undefined) throw new X509Error(`unsupported ${what}`);
  return value;
}

/** Parse the first PEM certificate in `pem`; only ECDSA P-256 and P-384 keys are accepted. */
export function parseCertificate(pem: string): Certificate {
  const body = PEM.exec(pem)?.[1];
  if (body === undefined) throw new X509Error("no PEM certificate");
  const der = decodeBase64(body.replace(/\s/g, ""));
  const outer = readTlv(der, 0);
  if (outer.bytes.length !== der.length) throw new X509Error("trailing data");
  const [tbs, algorithm, signature, extra] = children(outer);
  if (!tbs || extra) throw new X509Error("invalid certificate");
  const fields = children(tbs);
  const spki = fields[fields[0]?.tag === EXPLICIT_0 ? 6 : 5];
  if (!spki) throw new X509Error("missing subject public key");
  const [keyAlgorithm, publicKey, keyExtra] = children(spki);
  if (keyExtra) throw new X509Error("invalid subject public key");
  const [keyType, curve, curveExtra] = children(keyAlgorithm);
  if (oid(keyType) !== EC_PUBLIC_KEY || curveExtra) throw new X509Error("not an EC public key");
  const [signatureOid, parameters] = children(algorithm);
  if (parameters) throw new X509Error("unexpected signature parameters");
  return {
    tbs: tbs.bytes,
    spki: spki.bytes,
    curve: lookup(CURVES, oid(curve), "curve"),
    publicKey: bitString(publicKey),
    signatureHash: lookup(SIGNATURE_HASHES, oid(signatureOid), "signature algorithm"),
    signature: bitString(signature),
  };
}
