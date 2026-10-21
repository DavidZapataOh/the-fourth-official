import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { validate } from "../src/index.ts";

const RUNS = 200;

function batchOf37() {
  const path = fileURLToPath(
    new URL("../../fixtures/signed-batch/valid/three-events.json", import.meta.url),
  );
  const batch = JSON.parse(readFileSync(path, "utf8"));
  batch.events = Array.from({ length: 37 }, (_, seq) => ({ ...batch.events[0], seq }));
  batch.header.count = 37;
  return batch;
}

test("validate a signed batch of 37 events under 2 ms median", () => {
  const batch = batchOf37();
  validate("signed-batch", batch);
  const samples: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const start = performance.now();
    validate("signed-batch", batch);
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  expect(samples[RUNS / 2] as number).toBeLessThan(2);
});
