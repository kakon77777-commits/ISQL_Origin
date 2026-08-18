from __future__ import annotations

import hashlib

from .p4_bridge import (
    BridgeCandidate, BridgeInvariantResult, BridgeObservation, BridgeObservationBundle,
    BridgePlan, BridgeReceipt, bridge_candidate_to_dict, bridge_receipt_to_dict,
    evaluate_bridge_observations, finalize_bridge_receipt, parse_bridge_plan,
    parse_bridge_receipt, parse_observation_bundle,
)
from .p5_mlf import detect_endpoint


def build_bridge_candidate(source_bytes: bytes, target_bytes: bytes, plan: BridgePlan) -> BridgeCandidate:
    sraw, traw = bytes(source_bytes), bytes(target_bytes)
    s, t = detect_endpoint(sraw), detect_endpoint(traw)
    if s.profile_name != plan.source_profile:
        raise ValueError("P4_BRIDGE_SOURCE_PROFILE_MISMATCH")
    if t.profile_name != plan.target_profile:
        raise ValueError("P4_BRIDGE_TARGET_PROFILE_MISMATCH")
    if plan.source_artifact_kind is not None and s.artifact_kind != plan.source_artifact_kind:
        raise ValueError("P4_BRIDGE_SOURCE_ARTIFACT_MISMATCH")
    if plan.target_artifact_kind is not None and t.artifact_kind != plan.target_artifact_kind:
        raise ValueError("P4_BRIDGE_TARGET_ARTIFACT_MISMATCH")
    if s.profile_name == t.profile_name:
        raise ValueError("P4_BRIDGE_SAME_PROFILE_FORBIDDEN")
    return BridgeCandidate(
        "CANDIDATE", False, False,
        s.profile_name, s.artifact_kind, s.native_version, hashlib.sha256(sraw).hexdigest(), len(sraw),
        t.profile_name, t.artifact_kind, t.native_version, hashlib.sha256(traw).hexdigest(), len(traw),
        plan.transition_ref, plan.fidelity_class, plan.preserved_invariants, plan.lost_invariants,
        plan.validator_ref, plan.authority_ref, plan.provenance_ref, plan.temporal_ref,
    )


def verify_bridge_receipt_binding(receipt: BridgeReceipt, source_bytes: bytes, target_bytes: bytes) -> tuple[str, ...]:
    source_raw, target_raw = bytes(source_bytes), bytes(target_bytes)
    errors: list[str] = []
    source_sha, target_sha = hashlib.sha256(source_raw).hexdigest(), hashlib.sha256(target_raw).hexdigest()
    if source_sha != receipt.source_native_sha256:
        errors.append("P4_RECEIPT_SOURCE_DIGEST_MISMATCH")
    if target_sha != receipt.target_native_sha256:
        errors.append("P4_RECEIPT_TARGET_DIGEST_MISMATCH")
    if len(source_raw) != receipt.source_native_bytes:
        errors.append("P4_RECEIPT_SOURCE_LENGTH_MISMATCH")
    if len(target_raw) != receipt.target_native_bytes:
        errors.append("P4_RECEIPT_TARGET_LENGTH_MISMATCH")
    if receipt.output_digest != receipt.target_native_sha256:
        errors.append("P4_RECEIPT_OUTPUT_DIGEST_MISMATCH")
    try:
        source, target = detect_endpoint(source_raw), detect_endpoint(target_raw)
    except Exception:
        errors.append("P4_RECEIPT_NATIVE_DETECTION_FAILED")
        return tuple(errors)
    if source.profile_name != receipt.source_profile or source.artifact_kind != receipt.source_artifact_kind or source.native_version != receipt.source_native_version:
        errors.append("P4_RECEIPT_SOURCE_IDENTITY_MISMATCH")
    if target.profile_name != receipt.target_profile or target.artifact_kind != receipt.target_artifact_kind or target.native_version != receipt.target_native_version:
        errors.append("P4_RECEIPT_TARGET_IDENTITY_MISMATCH")
    return tuple(errors)


__all__ = [
    "BridgePlan", "BridgeCandidate", "BridgeObservation", "BridgeObservationBundle",
    "BridgeInvariantResult", "BridgeReceipt", "parse_bridge_plan", "build_bridge_candidate",
    "parse_observation_bundle", "evaluate_bridge_observations", "finalize_bridge_receipt",
    "parse_bridge_receipt", "verify_bridge_receipt_binding", "bridge_candidate_to_dict",
    "bridge_receipt_to_dict",
]
