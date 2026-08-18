from __future__ import annotations

from dataclasses import dataclass

from .binary import Ref, decode_ref, decode_uvarint, encode_ref, encode_uvarint
from .errors import OriginDecodeError


@dataclass(frozen=True, slots=True)
class OperatorDescriptor:
    operator_ref: Ref
    domain_type_ref: Ref
    codomain_type_ref: Ref
    signature_ref: Ref
    guard_ref: Ref
    capabilities: tuple[Ref, ...]
    effects: tuple[Ref, ...]
    authority_requirements: tuple[Ref, ...]
    invariant_obligations: tuple[Ref, ...]
    executor_ref: Ref | None
    resource_bound_ref: Ref
    provenance_ref: Ref


@dataclass(frozen=True, slots=True)
class AuthorityRecord:
    authority_ref: Ref
    subject_ref: Ref
    issuer_ref: Ref
    grants: tuple[Ref, ...]
    denies: tuple[Ref, ...]
    scope_ref: Ref
    validity_ref: Ref | None
    evidence_ref: Ref | None
    signature_ref: Ref | None


def _ref_key(ref: Ref) -> tuple[int, int]:
    return ref.bundle_slot, ref.local_id


def _require_increasing_refs(refs: tuple[Ref, ...], code: str) -> None:
    previous: tuple[int, int] | None = None
    for ref in refs:
        key = _ref_key(ref)
        if previous is not None and key <= previous:
            raise ValueError(code)
        previous = key


def _decode_ref_list(data: bytes, offset: int, code: str) -> tuple[tuple[Ref, ...], int]:
    count, offset = decode_uvarint(data, offset)
    refs: list[Ref] = []
    previous: tuple[int, int] | None = None
    for _ in range(count):
        ref, offset = decode_ref(data, offset)
        key = _ref_key(ref)
        if previous is not None and key <= previous:
            raise OriginDecodeError(code)
        previous = key
        refs.append(ref)
    return tuple(refs), offset


def _decode_all(data: bytes, decoder):
    value, offset = decoder(data, 0)
    if offset != len(data):
        raise OriginDecodeError("OMIR_SECTION_TRAILING_BYTES")
    return value


def encode_operators(entries: tuple[OperatorDescriptor, ...]) -> bytes:
    _require_increasing_refs(tuple(e.operator_ref for e in entries), "OPERATOR_ENTRY_ORDER")
    out = bytearray(encode_uvarint(len(entries)))
    for entry in entries:
        _require_increasing_refs(entry.capabilities, "OPERATOR_CAPABILITY_ORDER")
        _require_increasing_refs(entry.effects, "OPERATOR_EFFECT_ORDER")
        _require_increasing_refs(entry.authority_requirements, "OPERATOR_AUTHORITY_REQUIREMENT_ORDER")
        _require_increasing_refs(entry.invariant_obligations, "OPERATOR_INVARIANT_OBLIGATION_ORDER")
        out += encode_ref(entry.operator_ref)
        out += encode_ref(entry.domain_type_ref)
        out += encode_ref(entry.codomain_type_ref)
        out += encode_ref(entry.signature_ref)
        out += encode_ref(entry.guard_ref)
        out += encode_uvarint(len(entry.capabilities))
        for ref in entry.capabilities:
            out += encode_ref(ref)
        out += encode_uvarint(len(entry.effects))
        for ref in entry.effects:
            out += encode_ref(ref)
        out += encode_uvarint(len(entry.authority_requirements))
        for ref in entry.authority_requirements:
            out += encode_ref(ref)
        out += encode_uvarint(len(entry.invariant_obligations))
        for ref in entry.invariant_obligations:
            out += encode_ref(ref)
        out += encode_uvarint(1 if entry.executor_ref is not None else 0)
        if entry.executor_ref is not None:
            out += encode_ref(entry.executor_ref)
        out += encode_ref(entry.resource_bound_ref)
        out += encode_ref(entry.provenance_ref)
    return bytes(out)


def _decode_operators(data: bytes, offset: int) -> tuple[tuple[OperatorDescriptor, ...], int]:
    count, offset = decode_uvarint(data, offset)
    entries: list[OperatorDescriptor] = []
    previous: tuple[int, int] | None = None
    for _ in range(count):
        operator_ref, offset = decode_ref(data, offset)
        key = _ref_key(operator_ref)
        if previous is not None and key <= previous:
            raise OriginDecodeError("OPERATOR_ENTRY_ORDER")
        previous = key
        domain_type_ref, offset = decode_ref(data, offset)
        codomain_type_ref, offset = decode_ref(data, offset)
        signature_ref, offset = decode_ref(data, offset)
        guard_ref, offset = decode_ref(data, offset)
        capabilities, offset = _decode_ref_list(data, offset, "OPERATOR_CAPABILITY_ORDER")
        effects, offset = _decode_ref_list(data, offset, "OPERATOR_EFFECT_ORDER")
        authority_requirements, offset = _decode_ref_list(data, offset, "OPERATOR_AUTHORITY_REQUIREMENT_ORDER")
        invariant_obligations, offset = _decode_ref_list(data, offset, "OPERATOR_INVARIANT_OBLIGATION_ORDER")
        executor_present, offset = decode_uvarint(data, offset)
        if executor_present not in (0, 1):
            raise OriginDecodeError("OPERATOR_EXECUTOR_FLAG_INVALID")
        executor_ref = None
        if executor_present:
            executor_ref, offset = decode_ref(data, offset)
        resource_bound_ref, offset = decode_ref(data, offset)
        provenance_ref, offset = decode_ref(data, offset)
        entries.append(OperatorDescriptor(operator_ref, domain_type_ref, codomain_type_ref, signature_ref, guard_ref, capabilities, effects, authority_requirements, invariant_obligations, executor_ref, resource_bound_ref, provenance_ref))
    return tuple(entries), offset


def decode_operators(data: bytes) -> tuple[OperatorDescriptor, ...]:
    return _decode_all(data, _decode_operators)


def encode_authorities(entries: tuple[AuthorityRecord, ...]) -> bytes:
    _require_increasing_refs(tuple(e.authority_ref for e in entries), "AUTHORITY_ENTRY_ORDER")
    out = bytearray(encode_uvarint(len(entries)))
    for entry in entries:
        _require_increasing_refs(entry.grants, "AUTHORITY_GRANT_ORDER")
        _require_increasing_refs(entry.denies, "AUTHORITY_DENY_ORDER")
        out += encode_ref(entry.authority_ref)
        out += encode_ref(entry.subject_ref)
        out += encode_ref(entry.issuer_ref)
        out += encode_uvarint(len(entry.grants))
        for ref in entry.grants:
            out += encode_ref(ref)
        out += encode_uvarint(len(entry.denies))
        for ref in entry.denies:
            out += encode_ref(ref)
        out += encode_ref(entry.scope_ref)
        presence = (1 if entry.validity_ref is not None else 0) | (2 if entry.evidence_ref is not None else 0) | (4 if entry.signature_ref is not None else 0)
        out += encode_uvarint(presence)
        if entry.validity_ref is not None:
            out += encode_ref(entry.validity_ref)
        if entry.evidence_ref is not None:
            out += encode_ref(entry.evidence_ref)
        if entry.signature_ref is not None:
            out += encode_ref(entry.signature_ref)
    return bytes(out)


def _decode_authorities(data: bytes, offset: int) -> tuple[tuple[AuthorityRecord, ...], int]:
    count, offset = decode_uvarint(data, offset)
    entries: list[AuthorityRecord] = []
    previous: tuple[int, int] | None = None
    for _ in range(count):
        authority_ref, offset = decode_ref(data, offset)
        key = _ref_key(authority_ref)
        if previous is not None and key <= previous:
            raise OriginDecodeError("AUTHORITY_ENTRY_ORDER")
        previous = key
        subject_ref, offset = decode_ref(data, offset)
        issuer_ref, offset = decode_ref(data, offset)
        grants, offset = _decode_ref_list(data, offset, "AUTHORITY_GRANT_ORDER")
        denies, offset = _decode_ref_list(data, offset, "AUTHORITY_DENY_ORDER")
        scope_ref, offset = decode_ref(data, offset)
        presence, offset = decode_uvarint(data, offset)
        if presence & ~0x07:
            raise OriginDecodeError("AUTHORITY_PRESENCE_FLAGS_INVALID")
        validity_ref = evidence_ref = signature_ref = None
        if presence & 1:
            validity_ref, offset = decode_ref(data, offset)
        if presence & 2:
            evidence_ref, offset = decode_ref(data, offset)
        if presence & 4:
            signature_ref, offset = decode_ref(data, offset)
        entries.append(AuthorityRecord(authority_ref, subject_ref, issuer_ref, grants, denies, scope_ref, validity_ref, evidence_ref, signature_ref))
    return tuple(entries), offset


def decode_authorities(data: bytes) -> tuple[AuthorityRecord, ...]:
    return _decode_all(data, _decode_authorities)
