from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .binary import Ref
from .errors import OriginError
from .omir import decode_omir, encode_omir
from .orb import decode_orb, encode_orb, orb_digest
from .profiles import detect_native_artifact, list_artifacts, list_profiles, profile_registry
from .validation import validate_object, validate_p2_sections
from .wrapping import inspect_native_wrapper, unwrap_native_artifact, validate_native_wrapper, wrap_native_artifact
from .holonomy import ReferenceHarness, run_holonomy
from .sections import decode_semantic_charts, decode_transitions


def _ref_json(ref: Ref) -> dict[str, int]:
    return {"bundle_slot": ref.bundle_slot, "local_id": ref.local_id}


def _load_registries(specs: list[str]) -> dict[int, object]:
    result = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError("--registry must be SLOT=PATH")
        slot_text, path_text = spec.split("=", 1)
        slot = int(slot_text)
        if slot in result:
            raise ValueError(f"duplicate registry slot {slot}")
        result[slot] = decode_orb(Path(path_text).read_bytes())
    return result


def inspect_object(path: Path) -> dict:
    obj = decode_omir(path.read_bytes())
    return {
        "schema": "isql-origin-omir-inspection/v0.1",
        "canonical": False,
        "format_version": obj.format_version,
        "critical_flags": obj.critical_flags,
        "object_kind_ref": _ref_json(obj.object_kind_ref),
        "profile_ref": _ref_json(obj.profile_ref),
        "hash_policy_ref": _ref_json(obj.hash_policy_ref),
        "registry_pins": [
            {
                "slot": pin.slot,
                "registry_kind_ref": _ref_json(pin.registry_kind_ref),
                "revision": pin.revision,
                "digest_algorithm_ref": _ref_json(pin.digest.algorithm_ref),
                "digest_hex": pin.digest.digest.hex(),
                "flags": pin.flags,
            }
            for pin in obj.registry_pins
        ],
        "sections": [
            {"tag": section.tag, "flags": section.flags, "payload_length": len(section.payload)}
            for section in obj.sections
        ],
    }


def cmd_inspect(args: argparse.Namespace) -> int:
    print(json.dumps(inspect_object(Path(args.file)), ensure_ascii=False, indent=2))
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    print(hashlib.sha256(Path(args.file).read_bytes()).hexdigest())
    return 0


def cmd_registry_info(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    bundle = decode_orb(raw)
    print(json.dumps({
        "schema": "isql-origin-orb-inspection/v0.1",
        "canonical": False,
        "format_version": bundle.format_version,
        "bundle_kind_ref": _ref_json(bundle.bundle_kind_ref),
        "namespace_ref": _ref_json(bundle.namespace_ref),
        "revision": bundle.revision,
        "parent_digest_hex": bundle.parent_digest.hex() if bundle.parent_digest else None,
        "entry_count": len(bundle.entries),
        "sha256": orb_digest(raw).hex(),
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes())
    registries = _load_registries(args.registry or [])
    errors = validate_object(obj, registries)
    print(json.dumps({
        "schema": "isql-origin-validation/v0.1",
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "registry_pin_count": len(obj.registry_pins),
        "section_count": len(obj.sections),
    }, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def cmd_profile_list(args: argparse.Namespace) -> int:
    print(json.dumps({
        "schema": "isql-origin-profile-list/v0.2",
        "canonical": False,
        "profiles": [{"name": p.name, "profile_ref": _ref_json(p.profile_ref), "profile_version": p.profile_version} for p in list_profiles()],
        "artifacts": [{"key": a.key, "profile": a.profile.name, "object_kind_ref": _ref_json(a.object_kind_ref), "codec_ref": _ref_json(a.codec_ref), "supported_versions": list(a.supported_versions), "extensions": list(a.extensions)} for a in list_artifacts()],
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_profile_detect(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes(); detected = detect_native_artifact(raw)
    print(json.dumps({
        "schema": "isql-origin-profile-detect/v0.2", "canonical": False,
        "profile": detected.profile.name, "profile_ref": _ref_json(detected.profile.profile_ref),
        "artifact_kind": detected.artifact.key, "object_kind_ref": _ref_json(detected.artifact.object_kind_ref),
        "codec_ref": _ref_json(detected.artifact.codec_ref), "native_version": detected.native_version,
        "native_bytes": len(raw), "native_sha256": hashlib.sha256(raw).hexdigest(),
    }, ensure_ascii=False, indent=2)); return 0


def cmd_profile_registry_write(args: argparse.Namespace) -> int:
    raw = encode_orb(profile_registry()); out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(raw)
    print(json.dumps({"schema":"isql-origin-profile-registry-write/v0.2","canonical":False,"out":str(out),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}, ensure_ascii=False, indent=2)); return 0


def cmd_wrap_native(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes(); obj = wrap_native_artifact(raw); canonical = encode_omir(obj); out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(canonical)
    data = inspect_native_wrapper(obj); data.update({"out": str(out), "wrapper_bytes": len(canonical)}); print(json.dumps(data, ensure_ascii=False, indent=2)); return 0


def cmd_wrapper_info(args: argparse.Namespace) -> int:
    print(json.dumps(inspect_native_wrapper(decode_omir(Path(args.file).read_bytes())), ensure_ascii=False, indent=2)); return 0


def cmd_validate_wrapper(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes()); errors = validate_native_wrapper(obj)
    data = {"schema":"isql-origin-native-wrapper-validation/v0.2","status":"PASS" if not errors else "FAIL","errors":errors}
    if not errors: data["binding"] = inspect_native_wrapper(obj)
    print(json.dumps(data, ensure_ascii=False, indent=2)); return 0 if not errors else 1


def cmd_unwrap_native(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes()); raw = unwrap_native_artifact(obj); out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(raw); detected = detect_native_artifact(raw)
    print(json.dumps({"schema":"isql-origin-native-unwrap/v0.2","canonical":False,"out":str(out),"profile":detected.profile.name,"artifact_kind":detected.artifact.key,"native_bytes":len(raw),"native_sha256":hashlib.sha256(raw).hexdigest()}, ensure_ascii=False, indent=2)); return 0


def _parse_ref_text(text: str) -> Ref:
    return ReferenceHarness.parse_ref(text)


def _p2_semantic_data(obj) -> dict:
    errors = validate_p2_sections(obj); by_tag = {s.tag:s for s in obj.sections}
    charts = decode_semantic_charts(by_tag[2].payload) if 2 in by_tag and not any(e.startswith("P2_SECTION_DECODE_FAILED:2:") for e in errors) else ()
    transitions = decode_transitions(by_tag[3].payload) if 3 in by_tag and not any(e.startswith("P2_SECTION_DECODE_FAILED:3:") for e in errors) else ()
    return {
        "schema":"isql-origin-semantic-info/v0.3","canonical":False,"status":"PASS" if not errors else "FAIL","errors":errors,
        "chart_count":len(charts),"transition_count":len(transitions),
        "charts":[{"chart_ref":_ref_json(c.chart_ref),"chart_type_ref":_ref_json(c.chart_type_ref),"chart_version":c.chart_version,"domain_ref":_ref_json(c.domain_ref),"coordinate_schema_ref":_ref_json(c.coordinate_schema_ref),"payload_ref":_ref_json(c.payload_ref),"flags":c.flags} for c in charts],
        "transitions":[{"transition_ref":_ref_json(t.transition_ref),"source_chart_ref":_ref_json(t.source_chart_ref),"target_chart_ref":_ref_json(t.target_chart_ref),"transformer_ref":_ref_json(t.transformer_ref),"fidelity_class":t.fidelity_class,"fidelity":f"F{t.fidelity_class}","deterministic":t.deterministic,"reversible":t.reversible,"preserved_invariants":[_ref_json(r) for r in t.preserved_invariants],"lost_invariants":[_ref_json(r) for r in t.lost_invariants]} for t in transitions],
    }


def cmd_semantic_info(args: argparse.Namespace) -> int:
    data = _p2_semantic_data(decode_omir(Path(args.file).read_bytes())); print(json.dumps(data, ensure_ascii=False, indent=2)); return 0 if data["status"] == "PASS" else 1


def _holonomy_report_json(report) -> dict:
    return {
        "schema":"isql-origin-holonomy-report/v0.3","canonical":False,"status":report.status,
        "source_chart_ref":_ref_json(report.source_chart_ref),"final_chart_ref":_ref_json(report.final_chart_ref),
        "source_sha256":report.source_sha256,"final_sha256":report.final_sha256,"step_count":report.step_count,"final_payload_hex":report.final_payload.hex(),
        "steps":[{"transition_ref":_ref_json(s.transition_ref),"source_chart_ref":_ref_json(s.source_chart_ref),"target_chart_ref":_ref_json(s.target_chart_ref),"input_sha256":s.input_sha256,"output_sha256":s.output_sha256} for s in report.steps],
        "invariants":[{"invariant_ref":_ref_json(i.invariant_ref),"passed":i.passed,"distance":i.distance,"tolerance":i.tolerance,"observable_count":i.observable_count} for i in report.invariants],
    }


def cmd_holonomy_check(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes()); harness = ReferenceHarness.from_dict(json.loads(Path(args.harness).read_text(encoding="utf-8")))
    path = tuple(_parse_ref_text(t) for t in args.path.split(",") if t); invariants = tuple(_parse_ref_text(t) for t in (args.invariant or [])) or None
    report = run_holonomy(obj, path, Path(args.payload_file).read_bytes(), harness, invariant_refs=invariants)
    print(json.dumps(_holonomy_report_json(report), ensure_ascii=False, indent=2)); return 0


def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="isql-origin", description="ISQL Origin OMIR/ORB P0+P1+P2 read-only tools"); sub=p.add_subparsers(dest="command", required=True)
    q=sub.add_parser("inspect"); q.add_argument("file"); q.set_defaults(func=cmd_inspect)
    q=sub.add_parser("hash"); q.add_argument("file"); q.set_defaults(func=cmd_hash)
    q=sub.add_parser("registry-info"); q.add_argument("file"); q.set_defaults(func=cmd_registry_info)
    q=sub.add_parser("validate"); q.add_argument("file"); q.add_argument("--registry",action="append",default=[],metavar="SLOT=PATH"); q.set_defaults(func=cmd_validate)
    q=sub.add_parser("profile-list"); q.set_defaults(func=cmd_profile_list)
    q=sub.add_parser("profile-detect"); q.add_argument("file"); q.set_defaults(func=cmd_profile_detect)
    q=sub.add_parser("profile-registry-write"); q.add_argument("--out",required=True); q.set_defaults(func=cmd_profile_registry_write)
    q=sub.add_parser("wrap-native"); q.add_argument("file"); q.add_argument("--out",required=True); q.set_defaults(func=cmd_wrap_native)
    q=sub.add_parser("wrapper-info"); q.add_argument("file"); q.set_defaults(func=cmd_wrapper_info)
    q=sub.add_parser("validate-wrapper"); q.add_argument("file"); q.set_defaults(func=cmd_validate_wrapper)
    q=sub.add_parser("unwrap-native"); q.add_argument("file"); q.add_argument("--out",required=True); q.set_defaults(func=cmd_unwrap_native)
    q=sub.add_parser("semantic-info"); q.add_argument("file"); q.set_defaults(func=cmd_semantic_info)
    q=sub.add_parser("holonomy-check"); q.add_argument("file"); q.add_argument("--harness",required=True); q.add_argument("--payload-file",required=True); q.add_argument("--path",required=True); q.add_argument("--invariant",action="append",default=[]); q.set_defaults(func=cmd_holonomy_check)
    return p


def main(argv: list[str] | None = None) -> int:
    args=build_parser().parse_args(argv)
    try: return int(args.func(args))
    except (OSError, ValueError, OriginError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
