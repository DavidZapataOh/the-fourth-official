import Ajv2020 from "ajv/dist/2020.js";
import { schemas } from "./schemas.ts";
import type { Contracts } from "./types.ts";

export const CONTRACT_NAMES = [
  "event",
  "signed-batch",
  "claim",
  "verdict",
  "overlay-cue",
  "scene-package",
  "sealed-call",
  "certificate",
] as const;

export type ContractName = (typeof CONTRACT_NAMES)[number];

export class ContractError extends Error {
  readonly contract: string;
  readonly errors: string[];

  constructor(contract: string, errors: string[]) {
    super(`${contract}: ${errors.join("; ")}`);
    this.name = "ContractError";
    this.contract = contract;
    this.errors = errors;
  }
}

const ajv = new Ajv2020({ strict: true, allErrors: true });
for (const schema of Object.values(schemas)) ajv.addSchema(schema);

const ids = Object.fromEntries(Object.entries(schemas).map(([name, schema]) => [name, schema.$id]));

export function validate<K extends ContractName>(
  contract: K,
  instance: unknown,
): asserts instance is Contracts[K] {
  const id = ids[contract];
  const check = id === undefined ? undefined : ajv.getSchema(id);
  if (check === undefined) throw new ContractError(contract, ["schema not found"]);
  if (!check(instance)) {
    const errors = (check.errors ?? []).map(
      (e) => `${e.instancePath || "<root>"}: ${e.message ?? "invalid"}`,
    );
    throw new ContractError(contract, errors);
  }
}
