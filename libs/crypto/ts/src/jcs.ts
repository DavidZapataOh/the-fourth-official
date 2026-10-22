import canonicalizeJson from "canonicalize";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export class CanonicalizationError extends Error {
  override name = "CanonicalizationError";
}

// With the u flag a valid pair is one code point, so only unpaired surrogates match.
const LONE_SURROGATE = /\p{Surrogate}/u;
const encoder = new TextEncoder();

/** Serialize a JSON value to its RFC 8785 canonical UTF-8 form. */
export function canonicalize(value: JsonValue): Uint8Array {
  let text: string | undefined;
  try {
    check(value, new Set());
    text = canonicalizeJson(value);
  } catch (error) {
    if (error instanceof RangeError) throw new CanonicalizationError("nesting too deep");
    throw error;
  }
  if (text === undefined) throw new CanonicalizationError("value has no JSON form");
  return encoder.encode(text);
}

// The canonicalize package already rejects non-finite numbers, lone surrogates and cycles; this
// pass makes every rejection a CanonicalizationError and refuses types JSON.stringify would drop.
function check(value: unknown, ancestors: Set<object>): void {
  switch (typeof value) {
    case "boolean":
      return;
    case "number":
      if (!Number.isFinite(value)) throw new CanonicalizationError("NaN and Infinity are not JSON");
      return;
    case "string":
      if (LONE_SURROGATE.test(value)) throw new CanonicalizationError("lone surrogate");
      return;
    case "object":
      if (value === null) return;
      checkContainer(value, ancestors);
      return;
    default:
      throw new CanonicalizationError(`unsupported type ${typeof value}`);
  }
}

function checkContainer(value: object, ancestors: Set<object>): void {
  if (ancestors.has(value)) throw new CanonicalizationError("circular reference");
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (const item of value) check(item, ancestors);
  } else if (
    Object.getPrototypeOf(value) === Object.prototype ||
    Object.getPrototypeOf(value) === null
  ) {
    for (const [key, item] of Object.entries(value)) {
      check(key, ancestors);
      check(item, ancestors);
    }
  } else {
    throw new CanonicalizationError("only plain objects and arrays are supported");
  }
  ancestors.delete(value);
}
