import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { type ApplicationClaim, type LedgerReceipt, verifyLedgerReceipt } from "../src/index.ts";

type Base = {
  receipt: LedgerReceipt;
  service_certificate: string;
  application_claims: ApplicationClaim[];
};

const { bases } = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../vectors/ledger_receipt.json", import.meta.url)),
    "utf8",
  ),
) as { bases: Record<string, Base> };

// Generous regression tripwire; measured about 350 ms for 100 P-384 receipts with one endorsement.
const HUNDRED_RECEIPTS_MS = 2000;

test("100 receipt verifications are under budget", async () => {
  const base = bases.synthetic_receipt_with_endorsement as Base;
  const start = performance.now();
  for (let i = 0; i < 100; i++) {
    await verifyLedgerReceipt(base.receipt, base.service_certificate, {
      applicationClaims: base.application_claims,
    });
  }
  const elapsed = performance.now() - start;
  console.log(`perf 100 ledger receipts ${elapsed.toFixed(0)} ms`);
  expect(elapsed).toBeLessThan(HUNDRED_RECEIPTS_MS);
});
