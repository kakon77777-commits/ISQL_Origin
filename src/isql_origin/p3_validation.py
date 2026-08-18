from __future__ import annotations

from .omir import OMIRObject
from .sections import decode_invariants
from .p3_sections import decode_authorities, decode_operators


def _ref_text(ref) -> str:
    return f"{ref.bundle_slot}:{ref.local_id}"


def validate_p3_sections(obj: OMIRObject) -> list[str]:
    by_tag = {section.tag: section for section in obj.sections}
    if 4 not in by_tag and 5 not in by_tag:
        return []

    errors: list[str] = []
    operators = None
    invariants = None

    if 4 in by_tag:
        try:
            operators = decode_operators(by_tag[4].payload)
        except Exception as exc:
            errors.append(f"P3_SECTION_DECODE_FAILED:4:{exc}")
    if 5 in by_tag:
        try:
            decode_authorities(by_tag[5].payload)
        except Exception as exc:
            errors.append(f"P3_SECTION_DECODE_FAILED:5:{exc}")
    if 8 in by_tag:
        try:
            invariants = decode_invariants(by_tag[8].payload)
        except Exception:
            invariants = None

    if operators is not None:
        invariant_refs = {contract.invariant_ref for contract in invariants or ()}
        for operator in operators:
            for ref in operator.invariant_obligations:
                if ref not in invariant_refs:
                    errors.append(
                        f"P3_OPERATOR_INVARIANT_REF_UNKNOWN:{_ref_text(operator.operator_ref)}:{_ref_text(ref)}"
                    )
    return errors
