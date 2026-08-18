from __future__ import annotations

from .binary import Ref
from .omir import OMIRObject
from .orb import RegistryBundle, orb_digest
from .sections import decode_identity_family, decode_invariants, decode_payload_table, decode_profile_binding, decode_semantic_charts, decode_transitions

SHA256_ALGORITHM_REF = Ref(0, 1)
P0_REQUIRED_SECTIONS = frozenset({1, 8, 10})

def validate_registry_pins(obj: OMIRObject, registries: dict[int, RegistryBundle]) -> list[str]:
    errors=[]
    for pin in obj.registry_pins:
        bundle=registries.get(pin.slot)
        if bundle is None:
            errors.append(f"REGISTRY_SLOT_MISSING:{pin.slot}"); continue
        if pin.registry_kind_ref != bundle.bundle_kind_ref: errors.append(f"REGISTRY_KIND_MISMATCH:{pin.slot}")
        if pin.revision != bundle.revision: errors.append(f"REGISTRY_REVISION_MISMATCH:{pin.slot}:expected={pin.revision}:actual={bundle.revision}")
        if pin.digest.algorithm_ref != SHA256_ALGORITHM_REF: errors.append(f"REGISTRY_DIGEST_ALGORITHM_UNSUPPORTED:{pin.slot}")
        elif pin.digest.digest != orb_digest(bundle): errors.append(f"REGISTRY_DIGEST_MISMATCH:{pin.slot}")
    for slot in sorted(set(registries)-{p.slot for p in obj.registry_pins}): errors.append(f"REGISTRY_SLOT_UNPINNED:{slot}")
    return errors

def validate_p0_sections(obj):
    errors=[]; present={s.tag for s in obj.sections}
    for tag in sorted(P0_REQUIRED_SECTIONS-present): errors.append(f"P0_REQUIRED_SECTION_MISSING:{tag}")
    profile=None; decoders={1:decode_identity_family,8:decode_invariants,9:decode_payload_table,10:decode_profile_binding}
    for section in obj.sections:
        decoder=decoders.get(section.tag)
        if decoder is None: continue
        try: decoded=decoder(section.payload)
        except Exception as exc:
            errors.append(f"P0_SECTION_DECODE_FAILED:{section.tag}:{exc}"); continue
        if section.tag==10: profile=decoded
    if profile is not None:
        if profile.profile_ref != obj.profile_ref: errors.append("PROFILE_HEADER_REF_MISMATCH")
        for tag in profile.required_sections:
            if tag not in present: errors.append(f"PROFILE_REQUIRED_SECTION_MISSING:{tag}")
    return errors

def _ref_text(ref): return f"{ref.bundle_slot}:{ref.local_id}"

def validate_p2_sections(obj):
    by_tag={s.tag:s for s in obj.sections}
    if 2 not in by_tag and 3 not in by_tag: return []
    errors=[]; charts=transitions=invariants=None
    if 2 in by_tag:
        try: charts=decode_semantic_charts(by_tag[2].payload)
        except Exception as exc: errors.append(f"P2_SECTION_DECODE_FAILED:2:{exc}")
    if 3 in by_tag:
        try: transitions=decode_transitions(by_tag[3].payload)
        except Exception as exc: errors.append(f"P2_SECTION_DECODE_FAILED:3:{exc}")
    if 8 in by_tag:
        try: invariants=decode_invariants(by_tag[8].payload)
        except Exception: invariants=None
    if transitions is None: return errors
    chart_refs={c.chart_ref for c in charts or ()}; invariant_refs={i.invariant_ref for i in invariants or ()}
    for transition in transitions:
        if transition.source_chart_ref not in chart_refs: errors.append(f"P2_TRANSITION_CHART_REF_UNKNOWN:{_ref_text(transition.transition_ref)}:source={_ref_text(transition.source_chart_ref)}")
        if transition.target_chart_ref not in chart_refs: errors.append(f"P2_TRANSITION_CHART_REF_UNKNOWN:{_ref_text(transition.transition_ref)}:target={_ref_text(transition.target_chart_ref)}")
        for ref in transition.preserved_invariants+transition.lost_invariants:
            if ref not in invariant_refs: errors.append(f"P2_TRANSITION_INVARIANT_REF_UNKNOWN:{_ref_text(transition.transition_ref)}:{_ref_text(ref)}")
    return errors

def validate_object(obj, registries): return validate_p0_sections(obj)+validate_p2_sections(obj)+validate_registry_pins(obj,registries)
