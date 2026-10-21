from pydantic import BaseModel

from fourth_contracts.models.certificate_schema import Certificate
from fourth_contracts.models.claim_schema import Claim
from fourth_contracts.models.event_schema import Event
from fourth_contracts.models.overlay_cue_schema import OverlayCue
from fourth_contracts.models.scene_package_schema import ScenePackage
from fourth_contracts.models.sealed_call_schema import SealedCall
from fourth_contracts.models.signed_batch_schema import SignedBatch
from fourth_contracts.models.verdict_schema import Verdict
from fourth_contracts.validate import CONTRACT_NAMES, ContractError, ContractName, validate

MODELS: dict[ContractName, type[BaseModel]] = {
    "event": Event,
    "signed-batch": SignedBatch,
    "claim": Claim,
    "verdict": Verdict,
    "overlay-cue": OverlayCue,
    "scene-package": ScenePackage,
    "sealed-call": SealedCall,
    "certificate": Certificate,
}

__all__ = [
    "CONTRACT_NAMES",
    "MODELS",
    "ContractError",
    "ContractName",
    "validate",
]
