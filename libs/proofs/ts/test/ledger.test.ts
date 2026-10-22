import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  type ApplicationClaim,
  type LedgerReceipt,
  ProofError,
  verifyLedgerReceipt,
} from "../src/index.ts";

type Case = {
  name: string;
  receipt: LedgerReceipt;
  service_certificate: string;
  application_claims: ApplicationClaim[] | null;
  valid: boolean;
};
type Vectors = { bases: Record<string, Omit<Case, "name" | "valid">>; cases: Case[] };

const vectorPath = (name: string) =>
  fileURLToPath(new URL(`../../vectors/${name}`, import.meta.url));
const VECTORS = JSON.parse(readFileSync(vectorPath("ledger_receipt.json"), "utf8")) as Vectors;
const LIVE_PATH = vectorPath("ledger_receipt_live.json");
const LIVE = existsSync(LIVE_PATH)
  ? (JSON.parse(readFileSync(LIVE_PATH, "utf8")) as Vectors)
  : null;

async function outcome(
  receipt: LedgerReceipt,
  serviceCert: string,
  claims: ApplicationClaim[] | null = null,
): Promise<boolean> {
  try {
    await verifyLedgerReceipt(receipt, serviceCert, claims ? { applicationClaims: claims } : {});
    return true;
  } catch (error) {
    if (error instanceof ProofError) return false;
    throw error;
  }
}

const caseOutcome = (c: Case) => outcome(c.receipt, c.service_certificate, c.application_claims);

function casesNamed(fragment: string): Case[] {
  const selected = VECTORS.cases.filter((c) => c.name.includes(fragment));
  expect(selected.length, fragment).toBeGreaterThan(0);
  return selected;
}

function flip(data: Uint8Array, index: number): Uint8Array {
  const out = data.slice();
  out[index] = (out[index] as number) ^ 0x01;
  return out;
}

const hex = (data: Uint8Array) => Buffer.from(data).toString("hex");
const b64 = (data: Uint8Array) => Buffer.from(data).toString("base64");

function pemToDer(pem: string): Uint8Array {
  return Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");
}

function derToPem(der: Uint8Array): string {
  const lines = b64(der).match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function* singleByteChanges(receipt: LedgerReceipt): Generator<[string, LedgerReceipt]> {
  const leaf = receipt.leafComponents;
  for (const field of ["writeSetDigest", "claimsDigest"] as const) {
    const raw = Buffer.from(leaf[field], "hex");
    for (let i = 0; i < raw.length; i++) {
      const changed = { ...leaf, [field]: hex(flip(raw, i)) };
      yield [`${field}[${i}]`, { ...receipt, leafComponents: changed }];
    }
  }
  const evidence = new TextEncoder().encode(leaf.commitEvidence);
  for (let i = 0; i < evidence.length; i++) {
    const commitEvidence = new TextDecoder().decode(flip(evidence, i));
    yield [`commitEvidence[${i}]`, { ...receipt, leafComponents: { ...leaf, commitEvidence } }];
  }
  const nodeId = Buffer.from(receipt.nodeId ?? "", "hex");
  for (let i = 0; i < nodeId.length; i++) {
    yield [`nodeId[${i}]`, { ...receipt, nodeId: hex(flip(nodeId, i)) }];
  }
  for (const [index, element] of receipt.proof.entries()) {
    const [side, value] = Object.entries(element)[0] as [string, string];
    const raw = Buffer.from(value, "hex");
    for (let i = 0; i < raw.length; i++) {
      const proof = receipt.proof.map((e, j) => (j === index ? { [side]: hex(flip(raw, i)) } : e));
      yield [`proof[${index}][${i}]`, { ...receipt, proof } as LedgerReceipt];
    }
  }
  const signature = Buffer.from(receipt.signature, "base64");
  for (let i = 0; i < signature.length; i++) {
    yield [`signature[${i}]`, { ...receipt, signature: b64(flip(signature, i)) }];
  }
  const der = pemToDer(receipt.cert);
  for (let i = 0; i < der.length; i++) {
    yield [`cert[${i}]`, { ...receipt, cert: derToPem(flip(der, i)) }];
  }
}

describe("verifyLedgerReceipt", () => {
  test("valid receipt verifies", async () => {
    for (const base of Object.values(VECTORS.bases)) {
      expect(await outcome(base.receipt, base.service_certificate, base.application_claims)).toBe(
        true,
      );
    }
  });

  test.each(VECTORS.cases.map((c) => [c.name, c] as const))("vector %s", async (_, c) => {
    expect(await caseOutcome(c)).toBe(c.valid);
  });

  test.each(["azure_sdk_receipt_1", "synthetic_receipt_with_endorsement"])(
    "every single byte change is rejected: %s",
    async (name) => {
      const base = VECTORS.bases[name] as Vectors["bases"][string];
      const accepted: string[] = [];
      for (const [label, receipt] of singleByteChanges(base.receipt)) {
        if (await outcome(receipt, base.service_certificate)) accepted.push(label);
      }
      expect(accepted).toEqual([]);
    },
  );

  test("every mutated vector is rejected", async () => {
    const families = ["leaf_", "proof_", "signature_", "node_cert_", "node_id_byte"];
    const mutated = VECTORS.cases.filter((c) => families.some((f) => c.name.includes(`/${f}`)));
    expect(mutated.length).toBeGreaterThanOrEqual(4 * 16);
    for (const c of mutated) expect(await caseOutcome(c), c.name).toBe(false);
  });

  test("wrong service certificate is rejected", async () => {
    for (const c of [...casesNamed("wrong_service_certificate"), ...casesNamed("as_service")]) {
      expect(await caseOutcome(c), c.name).toBe(false);
    }
  });

  test("broken endorsement chain is rejected", async () => {
    for (const c of casesNamed("/endorsement")) expect(await caseOutcome(c), c.name).toBe(false);
  });

  test("application claims must hash to the claims digest", async () => {
    const cases = casesNamed("/claims_");
    expect(new Set(cases.map((c) => c.valid))).toEqual(new Set([true, false]));
    for (const c of cases) expect(await caseOutcome(c), c.name).toBe(c.valid);
  });

  test("malformed receipts raise ProofError", async () => {
    const base = VECTORS.bases.azure_sdk_receipt_1 as Vectors["bases"][string];
    const receipt = base.receipt;
    const first = receipt.proof[0] as { left: string };
    for (const broken of [
      {},
      { ...receipt, proof: [{ left: first.left, extra: "x" }] },
      { ...receipt, leafComponents: { ...receipt.leafComponents, extra: "x" } },
      { ...receipt, signature: "not base64!" },
      { ...receipt, nodeId: null },
    ]) {
      await expect(
        verifyLedgerReceipt(broken as unknown as LedgerReceipt, base.service_certificate),
      ).rejects.toBeInstanceOf(ProofError);
    }
  });
});

describe.skipIf(LIVE === null)("verifyLedgerReceipt on the live ledger vector", () => {
  const cases = LIVE?.cases ?? [];

  test("both outcomes are recorded", () => {
    expect(new Set(cases.map((c) => c.valid))).toEqual(new Set([true, false]));
  });

  test.each(cases.map((c) => [c.name, c] as const))("live vector %s", async (_, c) => {
    expect(await caseOutcome(c)).toBe(c.valid);
  });
});
