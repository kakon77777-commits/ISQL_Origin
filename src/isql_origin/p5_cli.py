from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import p4_cli as legacy_cli
from .errors import OriginError
from .omir import decode_omir, encode_omir
from .p4_bridge import bridge_candidate_to_dict, bridge_receipt_to_dict
from .p5_bridge import (
    build_bridge_candidate, evaluate_bridge_observations, finalize_bridge_receipt,
    parse_bridge_plan, parse_bridge_receipt, parse_observation_bundle,
    verify_bridge_receipt_binding,
)
from .p5_mlf import (
    MLF_PROFILE_REF, inspect_mlf_native, unwrap_mlf_native,
    validate_mlf_wrapper, wrap_mlf_native,
)

P5_COMMANDS = frozenset({
    "mlf-info", "wrap-native", "validate-wrapper", "wrapper-info", "unwrap-native",
    "bridge-candidate", "bridge-verify", "bridge-receipt-verify",
})


def _json_object(path: str, code: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(code)
    return data


def _is_mlf_bytes(raw: bytes) -> bool:
    return raw.startswith(b"PK")


def _is_mlf_wrapper(path: str) -> bool:
    try:
        return decode_omir(Path(path).read_bytes()).profile_ref == MLF_PROFILE_REF
    except Exception:
        return False


def _mlf_info_dict(raw: bytes) -> dict:
    x = inspect_mlf_native(raw)
    return {
        "schema": "isql-origin-mlf-info/v0.6",
        "canonical": False,
        "profile": "mlf-1.0",
        "mlf_version": x.mlf_version,
        "document_id": x.document_id,
        "title": x.title,
        "compiler": {"name": x.compiler_name, "version": x.compiler_version},
        "conformance": list(x.conformance),
        "fingerprint_algorithm": x.fingerprint_algorithm,
        "fingerprints": x.fingerprints,
        "native_sha256": x.native_sha256,
        "native_bytes": x.native_bytes,
        "package_entry_count": x.package_entry_count,
    }


def cmd_mlf_info(args: argparse.Namespace) -> int:
    print(json.dumps(_mlf_info_dict(Path(args.file).read_bytes()), ensure_ascii=False, indent=2))
    return 0


def cmd_wrap_native(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    if not _is_mlf_bytes(raw):
        return legacy_cli.main(["wrap-native", args.file, "--out", args.out])
    obj = wrap_mlf_native(raw)
    canonical = encode_omir(obj)
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(canonical)
    info = _mlf_info_dict(raw)
    info.update({"schema": "isql-origin-native-wrapper-inspection/v0.6", "out": str(out), "wrapper_bytes": len(canonical), "registry_pin_count": 2})
    print(json.dumps(info, ensure_ascii=False, indent=2)); return 0


def cmd_validate_wrapper(args: argparse.Namespace) -> int:
    if not _is_mlf_wrapper(args.file):
        return legacy_cli.main(["validate-wrapper", args.file])
    obj = decode_omir(Path(args.file).read_bytes()); errors = validate_mlf_wrapper(obj)
    print(json.dumps({"schema": "isql-origin-native-wrapper-validation/v0.6", "status": "PASS" if not errors else "FAIL", "errors": errors}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def cmd_wrapper_info(args: argparse.Namespace) -> int:
    if not _is_mlf_wrapper(args.file):
        return legacy_cli.main(["wrapper-info", args.file])
    obj = decode_omir(Path(args.file).read_bytes()); errors = validate_mlf_wrapper(obj)
    if errors: raise ValueError("P5_MLF_WRAPPER_INVALID:" + "|".join(errors))
    raw = unwrap_mlf_native(obj); data = _mlf_info_dict(raw)
    data.update({"schema": "isql-origin-native-wrapper-inspection/v0.6", "registry_pin_count": 2, "section_tags": [s.tag for s in obj.sections]})
    print(json.dumps(data, ensure_ascii=False, indent=2)); return 0


def cmd_unwrap_native(args: argparse.Namespace) -> int:
    if not _is_mlf_wrapper(args.file):
        return legacy_cli.main(["unwrap-native", args.file, "--out", args.out])
    raw = unwrap_mlf_native(decode_omir(Path(args.file).read_bytes()))
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(raw)
    data = _mlf_info_dict(raw); data.update({"schema": "isql-origin-native-unwrap/v0.6", "out": str(out)})
    print(json.dumps(data, ensure_ascii=False, indent=2)); return 0


def cmd_bridge_candidate(args: argparse.Namespace) -> int:
    plan = parse_bridge_plan(_json_object(args.plan, "P4_BRIDGE_PLAN_OBJECT_REQUIRED"))
    candidate = build_bridge_candidate(Path(args.source).read_bytes(), Path(args.target).read_bytes(), plan)
    print(json.dumps(bridge_candidate_to_dict(candidate), ensure_ascii=False, indent=2)); return 0


def cmd_bridge_verify(args: argparse.Namespace) -> int:
    source, target = Path(args.source).read_bytes(), Path(args.target).read_bytes()
    plan = parse_bridge_plan(_json_object(args.plan, "P4_BRIDGE_PLAN_OBJECT_REQUIRED"))
    candidate = build_bridge_candidate(source, target, plan)
    bundle = parse_observation_bundle(_json_object(args.observations, "P4_OBSERVATION_OBJECT_REQUIRED"))
    receipt = finalize_bridge_receipt(candidate, evaluate_bridge_observations(candidate, bundle))
    rendered = json.dumps(bridge_receipt_to_dict(receipt), ensure_ascii=False, indent=2) + "\n"
    if args.out: Path(args.out).write_text(rendered, encoding="utf-8")
    print(rendered, end=""); return 0 if receipt.status == "VERIFIED" else 1


def cmd_bridge_receipt_verify(args: argparse.Namespace) -> int:
    receipt = parse_bridge_receipt(_json_object(args.receipt, "P4_RECEIPT_OBJECT_REQUIRED"))
    errors = verify_bridge_receipt_binding(receipt, Path(args.source).read_bytes(), Path(args.target).read_bytes())
    print(json.dumps({"schema": "isql-origin-bridge-receipt-binding/v0.6", "status": "PASS" if not errors else "FAIL", "errors": list(errors)}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="isql-origin", description="ISQL Origin P5 source-focused compatibility CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("mlf-info"); p.add_argument("file"); p.set_defaults(func=cmd_mlf_info)
    p = sub.add_parser("wrap-native"); p.add_argument("file"); p.add_argument("--out", required=True); p.set_defaults(func=cmd_wrap_native)
    p = sub.add_parser("validate-wrapper"); p.add_argument("file"); p.set_defaults(func=cmd_validate_wrapper)
    p = sub.add_parser("wrapper-info"); p.add_argument("file"); p.set_defaults(func=cmd_wrapper_info)
    p = sub.add_parser("unwrap-native"); p.add_argument("file"); p.add_argument("--out", required=True); p.set_defaults(func=cmd_unwrap_native)
    p = sub.add_parser("bridge-candidate"); p.add_argument("source"); p.add_argument("target"); p.add_argument("--plan", required=True); p.set_defaults(func=cmd_bridge_candidate)
    p = sub.add_parser("bridge-verify"); p.add_argument("source"); p.add_argument("target"); p.add_argument("--plan", required=True); p.add_argument("--observations", required=True); p.add_argument("--out"); p.set_defaults(func=cmd_bridge_verify)
    p = sub.add_parser("bridge-receipt-verify"); p.add_argument("receipt"); p.add_argument("--source", required=True); p.add_argument("--target", required=True); p.set_defaults(func=cmd_bridge_receipt_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or args_list[0] not in P5_COMMANDS:
        return legacy_cli.main(args_list)
    if args_list[0] in {"wrap-native", "validate-wrapper", "wrapper-info", "unwrap-native"}:
        path = args_list[1] if len(args_list) > 1 else ""
        if args_list[0] == "wrap-native":
            try:
                if not _is_mlf_bytes(Path(path).read_bytes()): return legacy_cli.main(args_list)
            except OSError:
                return legacy_cli.main(args_list)
        elif not _is_mlf_wrapper(path):
            return legacy_cli.main(args_list)
    try:
        args = _parser().parse_args(args_list); return int(args.func(args))
    except (OSError, ValueError, OriginError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
