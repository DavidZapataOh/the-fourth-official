import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { CONTRACT_NAMES, ContractError, validate } from "../src/index.ts";

const fixtures = fileURLToPath(new URL("../../fixtures/", import.meta.url));

function cases(kind: "valid" | "invalid") {
  return CONTRACT_NAMES.flatMap((contract) => {
    const dir = join(fixtures, contract, kind);
    let names: string[] = [];
    try {
      names = readdirSync(dir)
        .filter((n) => n.endsWith(".json"))
        .sort();
    } catch {
      names = [];
    }
    return names.map((name) => ({
      contract,
      name,
      data: JSON.parse(readFileSync(join(dir, name), "utf8")) as unknown,
    }));
  });
}

describe("valid fixtures", () => {
  test.each(cases("valid"))("$contract/$name passes", ({ contract, data }) => {
    expect(() => validate(contract, data)).not.toThrow();
  });
});

describe("invalid fixtures", () => {
  test.each(cases("invalid"))("$contract/$name is rejected", ({ contract, data }) => {
    expect(() => validate(contract, data)).toThrow(ContractError);
  });
});

describe("coverage", () => {
  test.each(CONTRACT_NAMES)("%s has at least 1 valid and 3 invalid fixtures", (contract) => {
    const files = (kind: string) => {
      try {
        return readdirSync(join(fixtures, contract, kind)).filter((n) => n.endsWith(".json"));
      } catch {
        return [];
      }
    };
    expect(files("valid").length).toBeGreaterThanOrEqual(1);
    expect(files("invalid").length).toBeGreaterThanOrEqual(3);
  });

  test("signed-batch count is not enforced by the schema", () => {
    const batch = JSON.parse(
      readFileSync(join(fixtures, "signed-batch/valid/count-not-enforced.json"), "utf8"),
    );
    expect(batch.header.count).not.toBe(batch.events.length);
    expect(() => validate("signed-batch", batch)).not.toThrow();
  });

  test.each([
    ["signed-batch", "digest-uppercase"],
    ["signed-batch", "digest-no-prefix"],
    ["signed-batch", "signature-short"],
    ["verdict", "timestamp-with-offset"],
    ["sealed-call", "nonce-wrong-length"],
    ["overlay-cue", "credential-status-disputed"],
  ] as const)("%s/%s is rejected", (contract, name) => {
    const data = JSON.parse(
      readFileSync(join(fixtures, contract, "invalid", `${name}.json`), "utf8"),
    );
    expect(() => validate(contract, data)).toThrow(ContractError);
  });
});
