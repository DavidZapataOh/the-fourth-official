import { sha256 } from "@fourth/crypto";
import { p256, p384 } from "@noble/curves/nist.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 as sha256Hash } from "@noble/hashes/sha2.js";
import { type Certificate, decodeBase64, parseCertificate } from "./x509.ts";

/** Raised when a proof does not verify or is malformed. */
export class ProofError extends Error {
  override name = "ProofError";
}

export type LeafComponents = {
  claimsDigest: string;
  commitEvidence: string;
  writeSetDigest: string;
};

export type ProofElement = { left: string } | { right: string };

/** The `receipt` object of an Azure Confidential Ledger get-receipt response. */
export type LedgerReceipt = {
  cert: string;
  leafComponents: LeafComponents;
  nodeId?: string;
  proof: ProofElement[];
  serviceEndorsements?: string[];
  signature: string;
};

export type ApplicationClaim =
  | {
      kind: "LedgerEntry";
      ledgerEntry: { collectionId: string; contents: string; protocol: string; secretKey: string };
    }
  | { kind: "ClaimDigest"; digest: { protocol: string; value: string } };

export type VerifyLedgerReceiptOptions = { applicationClaims?: readonly ApplicationClaim[] };

const LEDGER_ENTRY_V1 = "LedgerEntryV1";
const LEAF_KEYS = new Set(["claimsDigest", "commitEvidence", "writeSetDigest"]);
const SIDES = new Set(["left", "right"]);
const HEX = /^(?:[0-9a-fA-F]{2})*$/;
const CURVES = { "P-256": p256, "P-384": p384 };
const utf8 = new TextEncoder();

function fail(message: string): never {
  throw new ProofError(message);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, what: string): string {
  return typeof value === "string" ? value : fail(`${what} must be a string`);
}

function hexBytes(value: string): Uint8Array {
  if (!HEX.test(value)) fail("invalid hex digest");
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function toHex(data: Uint8Array): string {
  return Array.from(data, (b) => b.toString(16).padStart(2, "0")).join("");
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function base64Bytes(value: string, what: string): Uint8Array {
  try {
    return decodeBase64(value);
  } catch {
    fail(`${what} is not base64`);
  }
}

function certificate(pem: unknown): Certificate {
  try {
    return parseCertificate(text(pem, "certificate"));
  } catch (error) {
    throw new ProofError(`invalid certificate: ${(error as Error).message}`);
  }
}

/** ECDSA over a digest the ledger signed directly, which WebCrypto cannot verify. */
function verifyPrehashed(key: Certificate, digest: Uint8Array, derSignature: Uint8Array): boolean {
  return CURVES[key.curve].verify(derSignature, digest, key.publicKey, {
    prehash: false,
    lowS: false,
    format: "der",
  });
}

async function endorses(endorser: Certificate, endorsee: Certificate): Promise<boolean> {
  try {
    const signature = CURVES[endorser.curve].Signature.fromBytes(endorsee.signature, "der");
    const key = await crypto.subtle.importKey(
      "spki",
      new Uint8Array(endorser.spki),
      { name: "ECDSA", namedCurve: endorser.curve },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: endorsee.signatureHash },
      key,
      new Uint8Array(signature.toBytes("compact")),
      new Uint8Array(endorsee.tbs),
    );
  } catch {
    return false;
  }
}

function parseReceipt(value: unknown): LedgerReceipt {
  if (!isObject(value) || !isObject(value.leafComponents) || !Array.isArray(value.proof)) {
    fail("invalid receipt structure");
  }
  const leaf = value.leafComponents;
  if (!Object.keys(leaf).every((key) => LEAF_KEYS.has(key))) fail("unexpected leaf component");
  const proof = value.proof.map((element: unknown) => {
    const entries = isObject(element) ? Object.entries(element) : [];
    const [entry] = entries;
    if (entries.length !== 1 || !entry || !SIDES.has(entry[0])) fail("invalid proof element");
    return { [entry[0]]: text(entry[1], "proof node") } as ProofElement;
  });
  const endorsements = "serviceEndorsements" in value ? value.serviceEndorsements : [];
  if (!Array.isArray(endorsements)) fail("serviceEndorsements must be a list");
  return {
    cert: text(value.cert, "cert"),
    leafComponents: {
      claimsDigest: text(leaf.claimsDigest, "claimsDigest"),
      commitEvidence: text(leaf.commitEvidence, "commitEvidence"),
      writeSetDigest: text(leaf.writeSetDigest, "writeSetDigest"),
    },
    ...("nodeId" in value ? { nodeId: text(value.nodeId, "nodeId") } : {}),
    proof,
    serviceEndorsements: endorsements.map((pem: unknown) => text(pem, "endorsement")),
    signature: text(value.signature, "signature"),
  };
}

function claimDigest(claim: unknown): Uint8Array {
  if (!isObject(claim)) fail("malformed application claim");
  let protocol: string;
  let data: Uint8Array;
  if (claim.kind === "LedgerEntry" && isObject(claim.ledgerEntry)) {
    const entry = claim.ledgerEntry;
    protocol = text(entry.protocol, "protocol");
    if (protocol !== LEDGER_ENTRY_V1) fail(`unsupported claim protocol: ${protocol}`);
    const key = base64Bytes(text(entry.secretKey, "secretKey"), "secretKey");
    const mac = (field: unknown, what: string) =>
      hmac(sha256Hash, key, utf8.encode(text(field, what)));
    data = sha256(concat(mac(entry.collectionId, "collectionId"), mac(entry.contents, "contents")));
  } else if (claim.kind === "ClaimDigest" && isObject(claim.digest)) {
    protocol = text(claim.digest.protocol, "protocol");
    data = hexBytes(text(claim.digest.value, "value"));
  } else {
    fail("unsupported application claim");
  }
  return sha256(concat(utf8.encode(protocol), data));
}

/** The claims digest the ledger records for `claims`, in hexadecimal. */
function claimsDigest(claims: readonly unknown[]): string {
  const count = new Uint8Array(4);
  new DataView(count.buffer).setUint32(0, claims.length, true);
  return toHex(sha256(concat(count, ...claims.map(claimDigest))));
}

/**
 * Verify a write transaction receipt against the ledger service identity certificate.
 *
 * When `applicationClaims` is non-empty, the claims must hash to the receipt's claims digest.
 * The node certificate must be endorsed by `serviceCertPem`, through `serviceEndorsements` when
 * the identity was renewed. Certificate validity periods are not checked, so historical receipts
 * keep verifying. Certificate signatures must be whole bytes, which the Azure SDK does not require.
 */
export async function verifyLedgerReceipt(
  receipt: LedgerReceipt,
  serviceCertPem: string,
  options: VerifyLedgerReceiptOptions = {},
): Promise<void> {
  const claims = options.applicationClaims ?? [];
  if (claims.length > 0) {
    const leaf: unknown = isObject(receipt) ? receipt.leafComponents : undefined;
    if (!isObject(leaf) || claimsDigest(claims) !== leaf.claimsDigest) {
      fail("application claims do not match the receipt claims digest");
    }
  }
  const parsed = parseReceipt(receipt);
  const node = certificate(parsed.cert);

  let endorsee = node;
  for (const pem of [...(parsed.serviceEndorsements ?? []), serviceCertPem]) {
    const endorser = certificate(pem);
    if (!(await endorses(endorser, endorsee))) fail("certificate is not endorsed");
    endorsee = endorser;
  }

  const leaf = parsed.leafComponents;
  let root = sha256(
    concat(
      hexBytes(leaf.writeSetDigest),
      sha256(utf8.encode(leaf.commitEvidence)),
      hexBytes(leaf.claimsDigest),
    ),
  );
  for (const element of parsed.proof) {
    root = sha256(
      "left" in element
        ? concat(hexBytes(element.left), root)
        : concat(root, hexBytes(element.right)),
    );
  }

  if (parsed.nodeId !== undefined && !equal(sha256(node.spki), hexBytes(parsed.nodeId))) {
    fail("nodeId does not match the node certificate");
  }
  if (!verifyPrehashed(node, root, base64Bytes(parsed.signature, "signature"))) {
    fail("invalid signature over the root");
  }
}
