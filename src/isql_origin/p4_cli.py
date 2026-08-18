from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .errors import OriginError
from . import p3_cli
from .p4_bridge import (
    bridge_candidate_to_dict, bridge_receipt_to_dict, build_bridge_candidate,
    evaluate_bridge_observations, finalize_bridge_receipt, parse_bridge_plan,
    parse_bridge_receipt, parse_observation_bundle, verify_bridge_receipt_binding,
)

P4_COMMANDS=frozenset({'bridge-candidate','bridge-verify','bridge-receipt-verify'})

def _load(path: str, code: str):
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data,dict): raise ValueError(code)
    return data

def cmd_candidate(args):
    plan=parse_bridge_plan(_load(args.plan,'P4_BRIDGE_PLAN_OBJECT_REQUIRED'))
    c=build_bridge_candidate(Path(args.source).read_bytes(),Path(args.target).read_bytes(),plan)
    print(json.dumps(bridge_candidate_to_dict(c),ensure_ascii=False,indent=2)); return 0

def cmd_verify(args):
    plan=parse_bridge_plan(_load(args.plan,'P4_BRIDGE_PLAN_OBJECT_REQUIRED'))
    c=build_bridge_candidate(Path(args.source).read_bytes(),Path(args.target).read_bytes(),plan)
    obs=parse_observation_bundle(_load(args.observations,'P4_OBSERVATION_OBJECT_REQUIRED'))
    receipt=finalize_bridge_receipt(c,evaluate_bridge_observations(c,obs))
    data=bridge_receipt_to_dict(receipt); rendered=json.dumps(data,ensure_ascii=False,indent=2)+'\n'
    if args.out:
        out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(rendered,encoding='utf-8')
    print(rendered,end=''); return 0 if receipt.status=='VERIFIED' else 1

def cmd_receipt_verify(args):
    r=parse_bridge_receipt(_load(args.receipt,'P4_RECEIPT_OBJECT_REQUIRED'))
    errors=verify_bridge_receipt_binding(r,Path(args.source).read_bytes(),Path(args.target).read_bytes())
    print(json.dumps({'schema':'isql-origin-bridge-receipt-validation/v0.5','canonical':False,'status':'PASS' if not errors else 'FAIL','receipt_status':r.status,'errors':list(errors)},ensure_ascii=False,indent=2))
    return 0 if not errors else 1

def _parser():
    p=argparse.ArgumentParser(prog='isql-origin',description='ISQL Origin P4 compatibility CLI')
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('bridge-candidate'); q.add_argument('source'); q.add_argument('target'); q.add_argument('--plan',required=True); q.set_defaults(func=cmd_candidate)
    q=sub.add_parser('bridge-verify'); q.add_argument('source'); q.add_argument('target'); q.add_argument('--plan',required=True); q.add_argument('--observations',required=True); q.add_argument('--out'); q.set_defaults(func=cmd_verify)
    q=sub.add_parser('bridge-receipt-verify'); q.add_argument('receipt'); q.add_argument('--source',required=True); q.add_argument('--target',required=True); q.set_defaults(func=cmd_receipt_verify)
    return p

def main(argv=None):
    args_list=list(sys.argv[1:] if argv is None else argv)
    if not args_list or args_list[0] not in P4_COMMANDS: return p3_cli.main(args_list)
    try:
        args=_parser().parse_args(args_list); return int(args.func(args))
    except (OSError,ValueError,OriginError,json.JSONDecodeError) as exc:
        print(f'error: {exc}',file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
