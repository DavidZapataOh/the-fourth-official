import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { type OtsStatus, otsStatus, ProofError } from "../src/index.ts";

type Proof = { proof: string; calendars: string[] };
type Vectors = {
  data_sha256: string;
  pending: Proof;
  deepest: Proof;
  bitcoin: Proof & { block_height: number; block_merkle_root: string };
  invalid: { name: string; proof: string }[];
};

const VECTORS = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../vectors/ots.json", import.meta.url)), "utf8"),
) as Vectors;

const bytes = (text: string, encoding: "hex" | "base64") =>
  new Uint8Array(Buffer.from(text, encoding));
const DIGEST = bytes(VECTORS.data_sha256, "hex");
const PENDING = bytes(VECTORS.pending.proof, "base64");
const BITCOIN = bytes(VECTORS.bitcoin.proof, "base64");
const HEIGHT = VECTORS.bitcoin.block_height;
const ROOT = bytes(VECTORS.bitcoin.block_merkle_root, "hex");
const PROOFS = [
  ["pending", PENDING],
  ["bitcoin", BITCOIN],
] as const;

function rejected(proof: Uint8Array, roots?: ReadonlyMap<number, Uint8Array>): boolean {
  try {
    otsStatus(proof, DIGEST, roots ? { blockMerkleRoots: roots } : {});
    return false;
  } catch (error) {
    if (error instanceof ProofError) return true;
    throw error;
  }
}

describe("otsStatus", () => {
  test("pending proof is reported pending with calendar urls", () => {
    expect(otsStatus(PENDING, DIGEST)).toEqual<OtsStatus>({
      kind: "pending",
      blockHeight: null,
      calendars: VECTORS.pending.calendars,
      unverifiedAnchorHeight: null,
    });
  });

  test("deepest allowed proof is read", () => {
    const proof = bytes(VECTORS.deepest.proof, "base64");
    expect(otsStatus(proof, DIGEST).calendars).toEqual(VECTORS.deepest.calendars);
  });

  test.each(PROOFS)("%s proof for another hash is rejected", (_, proof) => {
    expect(() => otsStatus(proof, new Uint8Array(32))).toThrow(ProofError);
  });

  test("bitcoin attestation is anchored only when the computed root matches the supplied block root", () => {
    expect(
      otsStatus(BITCOIN, DIGEST, { blockMerkleRoots: new Map([[HEIGHT, ROOT]]) }),
    ).toEqual<OtsStatus>({
      kind: "anchored",
      blockHeight: HEIGHT,
      calendars: VECTORS.bitcoin.calendars,
      unverifiedAnchorHeight: null,
    });
    const wrong = ROOT.slice();
    wrong[0] = (wrong[0] as number) ^ 1;
    expect(rejected(BITCOIN, new Map([[HEIGHT, wrong]]))).toBe(true);
    expect(rejected(BITCOIN, new Map([[HEIGHT, ROOT.slice().reverse()]]))).toBe(true);
  });

  test.each([
    ["no roots", undefined],
    ["empty roots", new Map<number, Uint8Array>()],
    ["root for another block", new Map([[HEIGHT + 1, ROOT]])],
  ])("reader never reports anchored without a block root: %s", (_, roots) => {
    expect(otsStatus(BITCOIN, DIGEST, roots ? { blockMerkleRoots: roots } : {})).toEqual<OtsStatus>(
      {
        kind: "pending",
        blockHeight: null,
        calendars: VECTORS.bitcoin.calendars,
        unverifiedAnchorHeight: HEIGHT,
      },
    );
  });

  test.each(VECTORS.invalid.map((c) => [c.name, c.proof]))("%s is rejected", (_, proof) => {
    expect(rejected(bytes(proof, "base64"))).toBe(true);
  });

  test.each(PROOFS)("truncated or extended %s proofs are rejected", (_, proof) => {
    for (let end = 0; end < proof.length; end++) {
      expect(rejected(proof.subarray(0, end)), `${end}`).toBe(true);
    }
    expect(rejected(Uint8Array.of(...proof, 0x08))).toBe(true);
  });

  test("altered bitcoin path bytes never anchor", () => {
    const marker = Buffer.from(BITCOIN).indexOf(Buffer.from("f0f1f2f3f4f5f6f70101", "hex"));
    const indices = [
      ...Array.from({ length: 33 }, (_, i) => 32 + i),
      ...Array.from({ length: BITCOIN.length - marker - 10 }, (_, i) => marker + 10 + i),
    ];
    const roots = new Map([[HEIGHT, ROOT]]);
    for (const index of indices) {
      const altered = BITCOIN.slice();
      altered[index] = (altered[index] as number) ^ 0x01;
      try {
        expect(otsStatus(altered, DIGEST, { blockMerkleRoots: roots }).kind, `${index}`).toBe(
          "pending",
        );
      } catch (error) {
        if (!(error instanceof ProofError)) throw error;
      }
    }
  });
});

type Live = {
  data_sha256: string;
  pending: Proof;
  anchored?: Proof & { block_height: number; block_merkle_root: string };
};
const LIVE_PATH = fileURLToPath(new URL("../../vectors/ots_live.json", import.meta.url));
const LIVE = existsSync(LIVE_PATH) ? (JSON.parse(readFileSync(LIVE_PATH, "utf8")) as Live) : null;

describe.skipIf(LIVE === null)("otsStatus on the live calendar stamp", () => {
  const live = LIVE as Live;

  test("stamp is pending on the recorded calendars", () => {
    const status = otsStatus(bytes(live.pending.proof, "base64"), bytes(live.data_sha256, "hex"));
    expect(status.kind).toBe("pending");
    expect(status.calendars).toEqual(live.pending.calendars);
  });

  test.skipIf(!live?.anchored)("upgraded stamp is anchored in the recorded block", () => {
    const anchored = live.anchored as NonNullable<Live["anchored"]>;
    const roots = new Map([[anchored.block_height, bytes(anchored.block_merkle_root, "hex")]]);
    const status = otsStatus(bytes(anchored.proof, "base64"), bytes(live.data_sha256, "hex"), {
      blockMerkleRoots: roots,
    });
    expect([status.kind, status.blockHeight]).toEqual(["anchored", anchored.block_height]);
  });
});
