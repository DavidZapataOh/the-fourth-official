import { expectTypeOf, test } from "vitest";
import type { Contracts } from "../src/index.ts";

test("event version is the literal 1", () => {
  expectTypeOf<Contracts["event"]["v"]>().toEqualTypeOf<1>();
});

test("verdict status union", () => {
  expectTypeOf<Contracts["verdict"]["status"]>().toEqualTypeOf<
    "confirmed" | "disputed" | "blocked"
  >();
});
