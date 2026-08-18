from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import cli as legacy_cli
from .action import ActionContext, build_action_certificate
from .binary import Ref
from .errors import OriginError
from .handoff import prepare_dsr_handoff
from .omir import decode_omir
from .p3_sections import decode_authorities, decode_operators
from .p3_validation import validate_p3_sections

P3_COMMANDS = frozenset({"operator-info", "action-certificate", "dsr-handoff"})


def _parse_ref(text: str) -> Ref:
    parts = text.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"P3_REF_INVALID:{text}")
    return Ref(int(parts[0]), int(parts[1]))


def _ref_json(ref: Ref) -> dict[str, int]:
    return {"bundle_slot": ref.bundle_slot, "local_id": ref.local_id}


def _ref_list_json(refs) -> list[dict[str, int]]:
    return [_ref_json(ref) for ref in refs]


def _load_context(path: str) -> ActionContext:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("P3_CONTEXT_OBJECT_REQUIRED")

    def one(key: str) -> Ref:
        if key not in data:
            raise ValueError(f"P3_CONTEXT_FIELD_MISSING:{key}")
        return _parse_ref(str(data[key]))

    def many(key: str) -> tuple[Ref, ...]:
        value = data.get(key, [])
        if not isinstance(value, list):
            raise ValueError(f"P3_CONTEXT_LIST_INVALID:{key}")
        return tuple(_parse_ref(str(item)) for item in value)

    return ActionContext(
        subject_ref=one("subject_ref"),
        target_ref=one("target_ref"),
        target_type_ref=one("target_type_ref"),
        satisfied_guard_refs=many("satisfied_guard_refs"),
        granted_capabilities=many("granted_capabilities"),
        denied_capabilities=many("denied_capabilities"),
        accepted_authority_refs=many("accepted_authority_refs"),
    )


def _certificate_json(cert) -> dict:
    return {
        "schema": "isql-origin-action-certificate/v0.4",
        "canonical": False,
        "execute": False,
        "origin_object_sha256": cert.origin_object_sha256,
        "operator_ref": _ref_json(cert.operator_ref),
        "subject_ref": _ref_json(cert.subject_ref),
        "target_ref": _ref_json(cert.target_ref),
        "ready": cert.ready,
        "domain_check": cert.domain_check,
        "type_check": cert.type_check,
        "guard_check": cert.guard_check,
        "granted_capabilities": _ref_list_json(cert.granted_capabilities),
        "denied_capabilities": _ref_list_json(cert.denied_capabilities),
        "missing_capabilities": _ref_list_json(cert.missing_capabilities),
        "authority_granted": _ref_list_json(cert.authority_granted),
        "authority_denied": _ref_list_json(cert.authority_denied),
        "authority_missing": _ref_list_json(cert.authority_missing),
        "authority_evidence": _ref_list_json(cert.authority_evidence),
        "effects": _ref_list_json(cert.effects),
        "invariant_obligations": _ref_list_json(cert.invariant_obligations),
        "executor_ref": _ref_json(cert.executor_ref) if cert.executor_ref is not None else None,
        "resource_bound_ref": _ref_json(cert.resource_bound_ref),
        "errors": list(cert.errors),
    }


def cmd_operator_info(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes())
    errors = validate_p3_sections(obj)
    by_tag = {section.tag: section for section in obj.sections}
    operators = decode_operators(by_tag[4].payload) if 4 in by_tag and not any(e.startswith("P3_SECTION_DECODE_FAILED:4:") for e in errors) else ()
    authorities = decode_authorities(by_tag[5].payload) if 5 in by_tag and not any(e.startswith("P3_SECTION_DECODE_FAILED:5:") for e in errors) else ()
    data = {
        "schema": "isql-origin-operator-info/v0.4",
        "canonical": False,
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "operator_count": len(operators),
        "authority_count": len(authorities),
        "operators": [{
            "operator_ref": _ref_json(op.operator_ref),
            "domain_type_ref": _ref_json(op.domain_type_ref),
            "codomain_type_ref": _ref_json(op.codomain_type_ref),
            "signature_ref": _ref_json(op.signature_ref),
            "guard_ref": _ref_json(op.guard_ref),
            "capabilities": _ref_list_json(op.capabilities),
            "effects": _ref_list_json(op.effects),
            "authority_requirements": _ref_list_json(op.authority_requirements),
            "invariant_obligations": _ref_list_json(op.invariant_obligations),
            "executor_ref": _ref_json(op.executor_ref) if op.executor_ref is not None else None,
            "resource_bound_ref": _ref_json(op.resource_bound_ref),
            "provenance_ref": _ref_json(op.provenance_ref),
        } for op in operators],
        "authorities": [{
            "authority_ref": _ref_json(a.authority_ref),
            "subject_ref": _ref_json(a.subject_ref),
            "issuer_ref": _ref_json(a.issuer_ref),
            "grants": _ref_list_json(a.grants),
            "denies": _ref_list_json(a.denies),
            "scope_ref": _ref_json(a.scope_ref),
            "validity_ref": _ref_json(a.validity_ref) if a.validity_ref is not None else None,
            "evidence_ref": _ref_json(a.evidence_ref) if a.evidence_ref is not None else None,
            "signature_ref": _ref_json(a.signature_ref) if a.signature_ref is not None else None,
        } for a in authorities],
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def cmd_action_certificate(args: argparse.Namespace) -> int:
    obj = decode_omir(Path(args.file).read_bytes())
    errors = validate_p3_sections(obj)
    if errors:
        print(json.dumps({"schema":"isql-origin-action-certificate/v0.4","canonical":False,"execute":False,"ready":False,"errors":errors}, ensure_ascii=False, indent=2))
        return 1
    cert = build_action_certificate(obj, _parse_ref(args.operator), _load_context(args.context))
    print(json.dumps(_certificate_json(cert), ensure_ascii=False, indent=2))
    return 0 if cert.ready else 1


def cmd_dsr_handoff(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    obj = decode_omir(raw)
    errors = validate_p3_sections(obj)
    if errors:
        raise ValueError("P3_HANDOFF_OBJECT_INVALID:" + "|".join(errors))
    cert = build_action_certificate(obj, _parse_ref(args.operator), _load_context(args.context))
    handoff = prepare_dsr_handoff(raw, cert, Path(args.executor_file).read_bytes())
    print(json.dumps({
        "schema": "isql-origin-dsr-handoff/v0.4",
        "canonical": False,
        "status": handoff.status,
        "execute": handoff.execute,
        "operator_ref": _ref_json(handoff.operator_ref),
        "executor_ref": _ref_json(handoff.executor_ref),
        "origin_object_sha256": handoff.origin_object_sha256,
        "dsr_artifact_kind": handoff.dsr_artifact_kind,
        "dsr_native_version": handoff.dsr_native_version,
        "dsr_native_sha256": handoff.dsr_native_sha256,
        "dsr_native_bytes": handoff.dsr_native_bytes,
    }, ensure_ascii=False, indent=2))
    return 0


def _p3_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="isql-origin", description="ISQL Origin P3 compatibility CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("operator-info")
    p.add_argument("file")
    p.set_defaults(func=cmd_operator_info)
    p = sub.add_parser("action-certificate")
    p.add_argument("file")
    p.add_argument("--operator", required=True)
    p.add_argument("--context", required=True)
    p.set_defaults(func=cmd_action_certificate)
    p = sub.add_parser("dsr-handoff")
    p.add_argument("file")
    p.add_argument("--operator", required=True)
    p.add_argument("--context", required=True)
    p.add_argument("--executor-file", required=True)
    p.set_defaults(func=cmd_dsr_handoff)
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or args_list[0] not in P3_COMMANDS:
        return legacy_cli.main(args_list)
    try:
        args = _p3_parser().parse_args(args_list)
        return int(args.func(args))
    except (OSError, ValueError, OriginError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
