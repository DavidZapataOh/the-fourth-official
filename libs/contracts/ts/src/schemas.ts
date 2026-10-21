import certificate from "../../schemas/certificate.schema.json" with { type: "json" };
import claim from "../../schemas/claim.schema.json" with { type: "json" };
import common from "../../schemas/common.schema.json" with { type: "json" };
import event from "../../schemas/event.schema.json" with { type: "json" };
import overlayCue from "../../schemas/overlay-cue.schema.json" with { type: "json" };
import scenePackage from "../../schemas/scene-package.schema.json" with { type: "json" };
import sealedCall from "../../schemas/sealed-call.schema.json" with { type: "json" };
import signedBatch from "../../schemas/signed-batch.schema.json" with { type: "json" };
import verdict from "../../schemas/verdict.schema.json" with { type: "json" };

export const schemas = {
  common,
  event,
  "signed-batch": signedBatch,
  claim,
  verdict,
  "overlay-cue": overlayCue,
  "scene-package": scenePackage,
  "sealed-call": sealedCall,
  certificate,
} as const;
