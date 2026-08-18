from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from .binary import Ref
from .profiles import detect_native_artifact


def _key(ref: Ref) -> tuple[int, int]: return ref.bundle_slot, ref.local_id

def _ref(value: Any, optional: bool = False) -> Ref | None:
    if value is None and optional: return None
    if isinstance(value, Ref): return value
    try:
        if isinstance(value, str):
            a, b = value.split(':', 1); ref = Ref(int(a), int(b))
        elif isinstance(value, dict): ref = Ref(int(value['bundle_slot']), int(value['local_id']))
        else: raise ValueError
        if ref.bundle_slot < 0 or ref.local_id < 0: raise ValueError
        return ref
    except Exception as exc: raise ValueError('P4_BRIDGE_REF_INVALID') from exc

def _refs(values: Any) -> tuple[Ref, ...]:
    if not isinstance(values, list): raise ValueError('P4_BRIDGE_REFS_INVALID')
    out = tuple(_ref(v) for v in values)
    if any(not isinstance(v, Ref) for v in out): raise ValueError('P4_BRIDGE_REFS_INVALID')
    typed = tuple(v for v in out if isinstance(v, Ref))
    if typed != tuple(sorted(set(typed), key=_key)): raise ValueError('P4_BRIDGE_REFS_NOT_CANONICAL')
    return typed

def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64: raise ValueError(code)
    try: bytes.fromhex(value)
    except ValueError as exc: raise ValueError(code) from exc
    return value.lower()

def _rtext(ref: Ref | None) -> str | None: return None if ref is None else f'{ref.bundle_slot}:{ref.local_id}'

@dataclass(frozen=True, slots=True)
class BridgePlan:
    source_profile: str; target_profile: str
    source_artifact_kind: str | None; target_artifact_kind: str | None
    transition_ref: Ref; fidelity_class: int
    preserved_invariants: tuple[Ref, ...]; lost_invariants: tuple[Ref, ...]
    validator_ref: Ref; authority_ref: Ref; provenance_ref: Ref; temporal_ref: Ref | None

@dataclass(frozen=True, slots=True)
class BridgeCandidate:
    status: str; execute: bool; conversion_performed: bool
    source_profile: str; source_artifact_kind: str; source_native_version: int; source_native_sha256: str; source_native_bytes: int
    target_profile: str; target_artifact_kind: str; target_native_version: int; target_native_sha256: str; target_native_bytes: int
    transition_ref: Ref; fidelity_class: int; preserved_invariants: tuple[Ref, ...]; lost_invariants: tuple[Ref, ...]
    validator_ref: Ref; authority_ref: Ref; provenance_ref: Ref; temporal_ref: Ref | None

@dataclass(frozen=True, slots=True)
class BridgeObservation:
    invariant_ref: Ref; comparator: str; source_value: bytes; target_value: bytes; tolerance: int | None

@dataclass(frozen=True, slots=True)
class BridgeObservationBundle:
    source_native_sha256: str; target_native_sha256: str; observations: tuple[BridgeObservation, ...]

@dataclass(frozen=True, slots=True)
class BridgeInvariantResult:
    invariant_ref: Ref; comparator: str; passed: bool
    source_observable_sha256: str; target_observable_sha256: str
    source_observable_bytes: int; target_observable_bytes: int
    distance: int | None; tolerance: int | None

@dataclass(frozen=True, slots=True)
class BridgeReceipt:
    status: str; execute: bool; conversion_performed: bool
    source_profile: str; source_artifact_kind: str; source_native_version: int; source_native_sha256: str; source_native_bytes: int
    target_profile: str; target_artifact_kind: str; target_native_version: int; target_native_sha256: str; target_native_bytes: int
    transition_ref: Ref; fidelity_class: int; preserved_invariants: tuple[Ref, ...]; lost_invariants: tuple[Ref, ...]
    validation_results: tuple[BridgeInvariantResult, ...]
    validator_ref: Ref; authority_ref: Ref; provenance_ref: Ref; temporal_ref: Ref | None
    output_digest: str; errors: tuple[str, ...]


def parse_bridge_plan(data: dict[str, Any]) -> BridgePlan:
    if not isinstance(data, dict) or data.get('schema') != 'isql-origin-bridge-plan/v0.5': raise ValueError('P4_BRIDGE_PLAN_SCHEMA_INVALID')
    sp, tp = data.get('source_profile'), data.get('target_profile')
    if not isinstance(sp, str) or not sp: raise ValueError('P4_BRIDGE_SOURCE_PROFILE_INVALID')
    if not isinstance(tp, str) or not tp: raise ValueError('P4_BRIDGE_TARGET_PROFILE_INVALID')
    sk, tk = data.get('source_artifact_kind'), data.get('target_artifact_kind')
    if sk is not None and not isinstance(sk, str): raise ValueError('P4_BRIDGE_SOURCE_ARTIFACT_INVALID')
    if tk is not None and not isinstance(tk, str): raise ValueError('P4_BRIDGE_TARGET_ARTIFACT_INVALID')
    try: fidelity = int(data['fidelity_class'])
    except Exception as exc: raise ValueError('P4_BRIDGE_FIDELITY_INVALID') from exc
    if not 0 <= fidelity <= 4: raise ValueError('P4_BRIDGE_FIDELITY_INVALID')
    preserved, lost = _refs(data.get('preserved_invariants', [])), _refs(data.get('lost_invariants', []))
    if set(preserved) & set(lost): raise ValueError('P4_BRIDGE_INVARIANT_OVERLAP')
    return BridgePlan(sp, tp, sk, tk, _ref(data.get('transition_ref')), fidelity, preserved, lost,
                      _ref(data.get('validator_ref')), _ref(data.get('authority_ref')), _ref(data.get('provenance_ref')), _ref(data.get('temporal_ref'), True))


def build_bridge_candidate(source_bytes: bytes, target_bytes: bytes, plan: BridgePlan) -> BridgeCandidate:
    sraw, traw = bytes(source_bytes), bytes(target_bytes)
    s, t = detect_native_artifact(sraw), detect_native_artifact(traw)
    if s.profile.name != plan.source_profile: raise ValueError('P4_BRIDGE_SOURCE_PROFILE_MISMATCH')
    if t.profile.name != plan.target_profile: raise ValueError('P4_BRIDGE_TARGET_PROFILE_MISMATCH')
    if plan.source_artifact_kind is not None and s.artifact.key != plan.source_artifact_kind: raise ValueError('P4_BRIDGE_SOURCE_ARTIFACT_MISMATCH')
    if plan.target_artifact_kind is not None and t.artifact.key != plan.target_artifact_kind: raise ValueError('P4_BRIDGE_TARGET_ARTIFACT_MISMATCH')
    if s.profile.name == t.profile.name: raise ValueError('P4_BRIDGE_SAME_PROFILE_FORBIDDEN')
    return BridgeCandidate('CANDIDATE', False, False, s.profile.name, s.artifact.key, s.native_version, hashlib.sha256(sraw).hexdigest(), len(sraw),
                           t.profile.name, t.artifact.key, t.native_version, hashlib.sha256(traw).hexdigest(), len(traw),
                           plan.transition_ref, plan.fidelity_class, plan.preserved_invariants, plan.lost_invariants,
                           plan.validator_ref, plan.authority_ref, plan.provenance_ref, plan.temporal_ref)


def parse_observation_bundle(data: dict[str, Any]) -> BridgeObservationBundle:
    if not isinstance(data, dict) or data.get('schema') != 'isql-origin-bridge-observations/v0.5': raise ValueError('P4_OBSERVATION_SCHEMA_INVALID')
    rows = data.get('observations')
    if not isinstance(rows, list): raise ValueError('P4_OBSERVATION_LIST_INVALID')
    out=[]; seen=set(); last=None
    for row in rows:
        if not isinstance(row, dict): raise ValueError('P4_OBSERVATION_ROW_INVALID')
        inv = _ref(row.get('invariant_ref'))
        if not isinstance(inv, Ref): raise ValueError('P4_OBSERVATION_REF_INVALID')
        if inv in seen: raise ValueError(f'P4_OBSERVATION_DUPLICATE:{inv.bundle_slot}:{inv.local_id}')
        if last is not None and _key(inv) <= last: raise ValueError('P4_OBSERVATION_REFS_NOT_CANONICAL')
        seen.add(inv); last=_key(inv)
        comparator=row.get('comparator')
        if not isinstance(comparator,str) or not comparator: raise ValueError('P4_OBSERVATION_COMPARATOR_INVALID')
        try: sv=bytes.fromhex(row.get('source_value_hex')); tv=bytes.fromhex(row.get('target_value_hex'))
        except Exception as exc: raise ValueError('P4_OBSERVATION_VALUE_INVALID') from exc
        tol=row.get('tolerance')
        if tol is not None:
            try: tol=int(tol)
            except Exception as exc: raise ValueError('P4_OBSERVATION_TOLERANCE_INVALID') from exc
            if tol < 0: raise ValueError('P4_OBSERVATION_TOLERANCE_INVALID')
        out.append(BridgeObservation(inv,comparator,sv,tv,tol))
    return BridgeObservationBundle(_sha(data.get('source_native_sha256'),'P4_OBSERVATION_SOURCE_DIGEST_INVALID'),
                                   _sha(data.get('target_native_sha256'),'P4_OBSERVATION_TARGET_DIGEST_INVALID'), tuple(out))


def _evaluate(obs: BridgeObservation) -> BridgeInvariantResult:
    ss, ts = hashlib.sha256(obs.source_value).hexdigest(), hashlib.sha256(obs.target_value).hexdigest()
    if obs.comparator == 'bytes-eq':
        if obs.tolerance is not None: raise ValueError('P4_OBSERVATION_TOLERANCE_NOT_ALLOWED')
        passed, distance, tolerance = obs.source_value == obs.target_value, None, None
    elif obs.comparator == 'utf8-int-distance':
        if obs.tolerance is None: raise ValueError('P4_OBSERVATION_TOLERANCE_REQUIRED')
        try: distance=abs(int(obs.source_value.decode())-int(obs.target_value.decode()))
        except Exception as exc: raise ValueError('P4_OBSERVATION_INTEGER_INVALID') from exc
        tolerance=obs.tolerance; passed=distance <= tolerance
    else: raise ValueError('P4_OBSERVATION_COMPARATOR_UNKNOWN')
    return BridgeInvariantResult(obs.invariant_ref, obs.comparator, passed, ss, ts, len(obs.source_value), len(obs.target_value), distance, tolerance)


def evaluate_bridge_observations(candidate: BridgeCandidate, bundle: BridgeObservationBundle) -> tuple[BridgeInvariantResult, ...]:
    if bundle.source_native_sha256 != candidate.source_native_sha256: raise ValueError('P4_OBSERVATION_SOURCE_DIGEST_MISMATCH')
    if bundle.target_native_sha256 != candidate.target_native_sha256: raise ValueError('P4_OBSERVATION_TARGET_DIGEST_MISMATCH')
    by={o.invariant_ref:o for o in bundle.observations}; preserved=set(candidate.preserved_invariants)
    for r in candidate.preserved_invariants:
        if r not in by: raise ValueError(f'P4_OBSERVATION_PRESERVED_MISSING:{r.bundle_slot}:{r.local_id}')
    for r in by:
        if r not in preserved: raise ValueError(f'P4_OBSERVATION_UNDECLARED:{r.bundle_slot}:{r.local_id}')
    return tuple(_evaluate(by[r]) for r in candidate.preserved_invariants)


def finalize_bridge_receipt(candidate: BridgeCandidate, results) -> BridgeReceipt:
    results=tuple(results)
    if tuple(r.invariant_ref for r in results) != candidate.preserved_invariants: raise ValueError('P4_RECEIPT_VALIDATION_RESULT_SET_MISMATCH')
    errors=tuple(f'P4_PRESERVED_INVARIANT_FAILED:{r.invariant_ref.bundle_slot}:{r.invariant_ref.local_id}' for r in results if not r.passed)
    return BridgeReceipt('VERIFIED' if not errors else 'REJECTED', False, False,
        candidate.source_profile,candidate.source_artifact_kind,candidate.source_native_version,candidate.source_native_sha256,candidate.source_native_bytes,
        candidate.target_profile,candidate.target_artifact_kind,candidate.target_native_version,candidate.target_native_sha256,candidate.target_native_bytes,
        candidate.transition_ref,candidate.fidelity_class,candidate.preserved_invariants,candidate.lost_invariants,results,
        candidate.validator_ref,candidate.authority_ref,candidate.provenance_ref,candidate.temporal_ref,candidate.target_native_sha256,errors)


def _result_dict(r):
    return {'invariant_ref':_rtext(r.invariant_ref),'comparator':r.comparator,'passed':r.passed,
            'source_observable_sha256':r.source_observable_sha256,'target_observable_sha256':r.target_observable_sha256,
            'source_observable_bytes':r.source_observable_bytes,'target_observable_bytes':r.target_observable_bytes,
            'distance':r.distance,'tolerance':r.tolerance}

def bridge_candidate_to_dict(c):
    return {'schema':'isql-origin-bridge-candidate/v0.5','canonical':False,'status':c.status,'execute':False,'conversion_performed':False,
            'source':{'profile':c.source_profile,'artifact_kind':c.source_artifact_kind,'native_version':c.source_native_version,'native_sha256':c.source_native_sha256,'native_bytes':c.source_native_bytes},
            'target':{'profile':c.target_profile,'artifact_kind':c.target_artifact_kind,'native_version':c.target_native_version,'native_sha256':c.target_native_sha256,'native_bytes':c.target_native_bytes},
            'transition_ref':_rtext(c.transition_ref),'fidelity_class':c.fidelity_class,'preserved_invariants':[_rtext(r) for r in c.preserved_invariants],
            'lost_invariants':[_rtext(r) for r in c.lost_invariants],'validator_ref':_rtext(c.validator_ref),'authority_ref':_rtext(c.authority_ref),
            'provenance_ref':_rtext(c.provenance_ref),'temporal_ref':_rtext(c.temporal_ref)}

def bridge_receipt_to_dict(r):
    d=bridge_candidate_to_dict(BridgeCandidate('CANDIDATE',False,False,r.source_profile,r.source_artifact_kind,r.source_native_version,r.source_native_sha256,r.source_native_bytes,r.target_profile,r.target_artifact_kind,r.target_native_version,r.target_native_sha256,r.target_native_bytes,r.transition_ref,r.fidelity_class,r.preserved_invariants,r.lost_invariants,r.validator_ref,r.authority_ref,r.provenance_ref,r.temporal_ref))
    d.update({'schema':'isql-origin-bridge-receipt/v0.5','status':r.status,'validation_results':[_result_dict(x) for x in r.validation_results],'output_digest':r.output_digest,'errors':list(r.errors)})
    return d


def _parse_result(d):
    try:
        inv=_ref(d.get('invariant_ref')); comp=d['comparator']; passed=d['passed']; sb=int(d['source_observable_bytes']); tb=int(d['target_observable_bytes'])
        distance=None if d.get('distance') is None else int(d['distance']); tolerance=None if d.get('tolerance') is None else int(d['tolerance'])
    except Exception as exc: raise ValueError('P4_RECEIPT_RESULT_INVALID') from exc
    if not isinstance(inv,Ref) or not isinstance(comp,str) or not isinstance(passed,bool) or min(sb,tb)<0: raise ValueError('P4_RECEIPT_RESULT_INVALID')
    return BridgeInvariantResult(inv,comp,passed,_sha(d.get('source_observable_sha256'),'P4_RECEIPT_RESULT_INVALID'),_sha(d.get('target_observable_sha256'),'P4_RECEIPT_RESULT_INVALID'),sb,tb,distance,tolerance)


def parse_bridge_receipt(data: dict[str, Any]) -> BridgeReceipt:
    if not isinstance(data,dict) or data.get('schema')!='isql-origin-bridge-receipt/v0.5': raise ValueError('P4_RECEIPT_SCHEMA_INVALID')
    if data.get('execute') is not False or data.get('conversion_performed') is not False: raise ValueError('P4_RECEIPT_BOUNDARY_INVALID')
    status=data.get('status')
    if status not in {'VERIFIED','REJECTED'}: raise ValueError('P4_RECEIPT_STATUS_INVALID')
    s,t=data.get('source'),data.get('target')
    if not isinstance(s,dict) or not isinstance(t,dict): raise ValueError('P4_RECEIPT_NATIVE_IDENTITY_INVALID')
    preserved,lost=_refs(data.get('preserved_invariants',[])),_refs(data.get('lost_invariants',[]))
    if set(preserved)&set(lost): raise ValueError('P4_BRIDGE_INVARIANT_OVERLAP')
    raw=data.get('validation_results')
    if not isinstance(raw,list): raise ValueError('P4_RECEIPT_RESULTS_INVALID')
    results=tuple(_parse_result(x) for x in raw)
    if tuple(x.invariant_ref for x in results)!=preserved: raise ValueError('P4_RECEIPT_VALIDATION_RESULT_SET_MISMATCH')
    errors=data.get('errors')
    if not isinstance(errors,list) or not all(isinstance(x,str) for x in errors): raise ValueError('P4_RECEIPT_ERRORS_INVALID')
    errors=tuple(errors); rejected=any(not x.passed for x in results) or bool(errors)
    if (status=='REJECTED') != rejected: raise ValueError('P4_RECEIPT_STATUS_INCONSISTENT')
    try: sv=int(s['native_version']); sl=int(s['native_bytes']); tv=int(t['native_version']); tl=int(t['native_bytes']); fidelity=int(data['fidelity_class'])
    except Exception as exc: raise ValueError('P4_RECEIPT_NATIVE_IDENTITY_INVALID') from exc
    if min(sv,sl,tv,tl,fidelity)<0 or fidelity>4: raise ValueError('P4_RECEIPT_NATIVE_IDENTITY_INVALID')
    return BridgeReceipt(status,False,False,s['profile'],s['artifact_kind'],sv,_sha(s.get('native_sha256'),'P4_RECEIPT_NATIVE_IDENTITY_INVALID'),sl,
        t['profile'],t['artifact_kind'],tv,_sha(t.get('native_sha256'),'P4_RECEIPT_NATIVE_IDENTITY_INVALID'),tl,
        _ref(data.get('transition_ref')),fidelity,preserved,lost,results,_ref(data.get('validator_ref')),_ref(data.get('authority_ref')),
        _ref(data.get('provenance_ref')),_ref(data.get('temporal_ref'),True),_sha(data.get('output_digest'),'P4_RECEIPT_OUTPUT_DIGEST_INVALID'),errors)


def verify_bridge_receipt_binding(receipt: BridgeReceipt, source_bytes: bytes, target_bytes: bytes) -> tuple[str, ...]:
    sraw,traw=bytes(source_bytes),bytes(target_bytes); errors=[]
    ss,ts=hashlib.sha256(sraw).hexdigest(),hashlib.sha256(traw).hexdigest()
    if ss!=receipt.source_native_sha256: errors.append('P4_RECEIPT_SOURCE_DIGEST_MISMATCH')
    if ts!=receipt.target_native_sha256: errors.append('P4_RECEIPT_TARGET_DIGEST_MISMATCH')
    if len(sraw)!=receipt.source_native_bytes: errors.append('P4_RECEIPT_SOURCE_LENGTH_MISMATCH')
    if len(traw)!=receipt.target_native_bytes: errors.append('P4_RECEIPT_TARGET_LENGTH_MISMATCH')
    if receipt.output_digest!=receipt.target_native_sha256: errors.append('P4_RECEIPT_OUTPUT_DIGEST_MISMATCH')
    try: s,t=detect_native_artifact(sraw),detect_native_artifact(traw)
    except Exception:
        errors.append('P4_RECEIPT_NATIVE_DETECTION_FAILED'); return tuple(errors)
    if (s.profile.name,s.artifact.key,s.native_version)!=(receipt.source_profile,receipt.source_artifact_kind,receipt.source_native_version): errors.append('P4_RECEIPT_SOURCE_IDENTITY_MISMATCH')
    if (t.profile.name,t.artifact.key,t.native_version)!=(receipt.target_profile,receipt.target_artifact_kind,receipt.target_native_version): errors.append('P4_RECEIPT_TARGET_IDENTITY_MISMATCH')
    return tuple(errors)
