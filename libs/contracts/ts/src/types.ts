import type { Certificate } from "./generated/certificate.schema.js";
import type { Claim } from "./generated/claim.schema.js";
import type { Event } from "./generated/event.schema.js";
import type { OverlayCue } from "./generated/overlay-cue.schema.js";
import type { ScenePackage } from "./generated/scene-package.schema.js";
import type { SealedCall } from "./generated/sealed-call.schema.js";
import type { SignedBatch } from "./generated/signed-batch.schema.js";
import type { Verdict } from "./generated/verdict.schema.js";

export type Contracts = {
  event: Event;
  "signed-batch": SignedBatch;
  claim: Claim;
  verdict: Verdict;
  "overlay-cue": OverlayCue;
  "scene-package": ScenePackage;
  "sealed-call": SealedCall;
  certificate: Certificate;
};

export type {
  Certificate,
  Claim,
  Event,
  OverlayCue,
  ScenePackage,
  SealedCall,
  SignedBatch,
  Verdict,
};
