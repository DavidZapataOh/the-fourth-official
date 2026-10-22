import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function vectors(name: string): unknown {
  const path = fileURLToPath(new URL(`../../vectors/${name}.json`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8"));
}
