import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  canonicalize,
  coseSign1,
  coseVerify1,
  inclusionProof,
  type JsonValue,
  keypairFromSeed,
  leafHash,
  merkleRoot,
  sign,
  verify,
} from "../src/index.ts";

const path = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));
const BATCH = path("../../../contracts/fixtures/signed-batch/valid/three-events.json");

// Generous regression tripwires; measured medians are about 92 ms, 91 ms and 0.1 ms.
const MERKLE_ROOT_100K_MS = 500;
const INCLUSION_100K_MS = 500;
const CANONICALIZE_37_MS = 1;

function medianMs(fn: () => unknown, runs: number): number {
  const samples: number[] = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    fn();
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(runs / 2)] as number;
}

async function medianMsAsync(fn: () => Promise<unknown>, runs: number): Promise<number> {
  const samples: number[] = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    await fn();
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(runs / 2)] as number;
}

const leaves = Array.from({ length: 100_000 }, (_, i) => {
  const data = new Uint8Array(4);
  new DataView(data.buffer).setUint32(0, i);
  return leafHash(data);
});

describe("performance baselines", () => {
  test("merkleRoot of 100k leaves is under budget", () => {
    expect(medianMs(() => merkleRoot(leaves), 5)).toBeLessThan(MERKLE_ROOT_100K_MS);
  });

  test("inclusionProof for 100k leaves is under budget", () => {
    expect(medianMs(() => inclusionProof(leaves, 77_777), 5)).toBeLessThan(INCLUSION_100K_MS);
  });

  test("canonicalize of a 37 event batch is under budget", () => {
    const { events } = JSON.parse(readFileSync(BATCH, "utf8")) as {
      events: { seq: number }[];
    };
    const first = events[0] as { seq: number };
    const batch = Array.from({ length: 37 }, (_, i) => ({ ...first, seq: first.seq + i }));
    expect(medianMs(() => canonicalize(batch as JsonValue), 101)).toBeLessThan(CANONICALIZE_37_MS);
  });

  test("reports signature timings", async () => {
    const { privateKey, publicKey } = await keypairFromSeed(new Uint8Array(32).fill(7));
    const message = new Uint8Array(256).fill(120);
    const kid = new TextEncoder().encode("kid");
    const ed = await medianMsAsync(
      async () => verify(publicKey, message, await sign(privateKey, message)),
      101,
    );
    const cose = await medianMsAsync(
      async () => coseVerify1(publicKey, await coseSign1(privateKey, message, kid)),
      101,
    );
    console.log(
      `perf ed25519 sign+verify ${(ed * 1000).toFixed(0)} us, cose sign+verify ${(cose * 1000).toFixed(0)} us`,
    );
  });
});
