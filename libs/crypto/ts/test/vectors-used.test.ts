import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

const CRYPTO = fileURLToPath(new URL("../../", import.meta.url));

// The checks themselves are excluded from the scan: they quote the pattern.
const loads = (name: string, text: string) => new RegExp(`\\bvectors\\("${name}"\\)`).test(text);

test("matcher requires the load call", () => {
  expect(loads("jcs", 'const V = vectors("jcs")')).toBe(true);
  expect(loads("jcs", 'describe("jcs")')).toBe(false);
  expect(loads("jcs", 'vectors("jcs2")')).toBe(false);
});

test("every vector file is loaded by both suites", () => {
  const names = readdirSync(`${CRYPTO}vectors`)
    .filter((file) => file.endsWith(".json"))
    .map((file) => file.slice(0, -".json".length));
  expect(names.length).toBeGreaterThan(0);
  for (const [dir, suffix] of [
    ["py/tests", ".py"],
    ["ts/test", ".ts"],
  ] as const) {
    const text = readdirSync(`${CRYPTO}${dir}`)
      .filter((file) => file.endsWith(suffix) && !/vectors[-_]used/.test(file))
      .map((file) => readFileSync(`${CRYPTO}${dir}/${file}`, "utf8"))
      .join("\n");
    const missing = names.filter((name) => !loads(name, text));
    expect(missing, `${dir} does not load ${missing}`).toEqual([]);
  }
});
