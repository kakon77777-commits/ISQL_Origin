from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .binary import Ref
from .omir import OMIRObject, encode_omir
from .p3_sections import AuthorityRecord, OperatorDescriptor, decode_authorities, decode_operators

ZERO_REF = Ref(0, 0)


def _ref_key(ref: Ref) -> tuple[int, int]:
    return ref.bundle_slot, ref.local_id


def _canonical_refs(refs) -> tuple[Ref, ...]:
    return tuple(sorted(set(refs), key=_ref_key))


def _ref_text(ref: Ref) -> str:
    return f"{ref.bundle_slot}:{ref.local_id}"


@dataclass(frozen=True, slots=True)
class ActionContext:
    subject_ref: Ref
    target_ref: Ref
    target_type_ref: Ref
    satisfied_guard_refs: tuple[Ref, ...]
    granted_capabilities: tuple[Ref, ...]
    denied_capabilities: tuple[Ref, ...]
    accepted_authority_refs: tuple[Ref, ...]


@dataclass(frozen=True, slots=True)
class ActionCertificate:
    origin_object_sha256: str
    operator_ref: Ref
    subject_ref: Ref
    target_ref: Ref
    ready: bool
    domain_check: bool
    type_check: bool
    guard_check: bool
    granted_capabilities: tuple[Ref, ...]
    denied_capabilities: tuple[Ref, ...]
    missing_capabilities: tuple[Ref, ...]
    authority_granted: tuple[Ref, ...]
    authority_denied: tuple[Ref, ...]
    authority_missing: tuple[Ref, ...]
    authority_evidence: tuple[Ref, ...]
    effects: tuple[Ref, ...]
    invariant_obligations: tuple[Ref, ...]
    executor_ref: Ref | None
    resource_bound_ref: Ref
    errors: tuple[str, ...]


def _decode_p3(obj: OMIRObject) -> tuple[tuple[OperatorDescriptor, ...], tuple[AuthorityRecord, ...]]:
    by_tag = {section.tag: section for section in obj.sections}
    operators = decode_operators(by_tag[4].payload) if 4 in by_tag else ()
    authorities = decode_authorities(by_tag[5].payload) if 5 in by_tag else ()
    return operators, authorities


def build_action_certificate(obj: OMIRObject, operator_ref: Ref, context: ActionContext) -> ActionCertificate:
    operators, authorities = _decode_p3(obj)
    operator = next((item for item in operators if item.operator_ref == operator_ref), None)
    if operator is None:
        raise ValueError(f"P3_OPERATOR_UNKNOWN:{_ref_text(operator_ref)}")

    satisfied_guards = set(context.satisfied_guard_refs)
    direct_grants = set(context.granted_capabilities)
    direct_denies = set(context.denied_capabilities)
    accepted = set(context.accepted_authority_refs)

    domain_check = context.target_ref != ZERO_REF
    type_check = context.target_type_ref == operator.domain_type_ref
    guard_check = operator.guard_ref == ZERO_REF or operator.guard_ref in satisfied_guards

    required_capabilities = set(operator.capabilities)
    denied_capabilities = _canonical_refs(required_capabilities & direct_denies)
    granted_capabilities = _canonical_refs((required_capabilities & direct_grants) - direct_denies)
    missing_capabilities = _canonical_refs(required_capabilities - direct_grants - direct_denies)

    records_by_ref = {record.authority_ref: record for record in authorities}
    unknown_accepted = _canonical_refs(ref for ref in accepted if ref not in records_by_ref)
    matching_records = [
        records_by_ref[ref]
        for ref in sorted(accepted, key=_ref_key)
        if ref in records_by_ref
        and records_by_ref[ref].subject_ref == context.subject_ref
        and records_by_ref[ref].scope_ref == operator.operator_ref
    ]

    authority_granted: list[Ref] = []
    authority_denied: list[Ref] = []
    authority_missing: list[Ref] = []
    evidence: set[Ref] = set()
    for requirement in operator.authority_requirements:
        deny_records = [record for record in matching_records if requirement in record.denies]
        grant_records = [record for record in matching_records if requirement in record.grants]
        if deny_records:
            authority_denied.append(requirement)
            evidence.update(record.authority_ref for record in deny_records + grant_records)
        elif grant_records:
            authority_granted.append(requirement)
            evidence.update(record.authority_ref for record in grant_records)
        else:
            authority_missing.append(requirement)

    errors: list[str] = []
    if not domain_check:
        errors.append("DOMAIN_TARGET_MISSING")
    if not type_check:
        errors.append("TYPE_MISMATCH")
    if not guard_check:
        errors.append("GUARD_UNSATISFIED")
    for ref in denied_capabilities:
        errors.append(f"CAPABILITY_DENIED:{_ref_text(ref)}")
    for ref in missing_capabilities:
        errors.append(f"CAPABILITY_MISSING:{_ref_text(ref)}")
    for ref in authority_denied:
        errors.append(f"AUTHORITY_DENIED:{_ref_text(ref)}")
    for ref in authority_missing:
        errors.append(f"AUTHORITY_MISSING:{_ref_text(ref)}")
    for ref in unknown_accepted:
        errors.append(f"AUTHORITY_RECORD_UNKNOWN:{_ref_text(ref)}")

    return ActionCertificate(
        origin_object_sha256=hashlib.sha256(encode_omir(obj)).hexdigest(),
        operator_ref=operator.operator_ref,
        subject_ref=context.subject_ref,
        target_ref=context.target_ref,
        ready=not errors,
        domain_check=domain_check,
        type_check=type_check,
        guard_check=guard_check,
        granted_capabilities=granted_capabilities,
        denied_capabilities=denied_capabilities,
        missing_capabilities=missing_capabilities,
        authority_granted=_canonical_refs(authority_granted),
        authority_denied=_canonical_refs(authority_denied),
        authority_missing=_canonical_refs(authority_missing),
        authority_evidence=_canonical_refs(evidence),
        effects=operator.effects,
        invariant_obligations=operator.invariant_obligations,
        executor_ref=operator.executor_ref,
        resource_bound_ref=operator.resource_bound_ref,
        errors=tuple(errors),
    )
