from __future__ import annotations

from dataclasses import dataclass

from .binary import Digest, Ref, decode_bytestring, decode_digest, decode_ref, decode_uvarint, encode_bytestring, encode_digest, encode_ref, encode_uvarint
from .errors import OriginDecodeError

@dataclass(frozen=True, slots=True)
class IdentityEntry:
    identity_kind_ref: Ref; algorithm_ref: Ref; digest: bytes; scope_flags: int; authority_ref: Ref|None=None; provenance_ref: Ref|None=None
@dataclass(frozen=True, slots=True)
class InvariantContract:
    invariant_ref: Ref; observable_refs: tuple[Ref,...]; comparator_ref: Ref; tolerance_ref: Ref|None; scope_ref: Ref; validator_ref: Ref; severity: int
@dataclass(frozen=True, slots=True)
class PayloadEntry:
    payload_ref: Ref; storage_class: int; media_type_ref: Ref; codec_ref: Ref; logical_length: int; digest: Digest; body_or_locator: bytes
@dataclass(frozen=True, slots=True)
class SemanticChart:
    chart_ref: Ref; chart_type_ref: Ref; chart_version: int; domain_ref: Ref; coordinate_schema_ref: Ref; payload_ref: Ref; authority_ref: Ref; provenance_ref: Ref; flags: int
@dataclass(frozen=True, slots=True)
class TransitionContract:
    transition_ref: Ref; source_chart_ref: Ref; target_chart_ref: Ref; transformer_ref: Ref; fidelity_class: int; deterministic: bool; reversible: bool; bound_ref: Ref; preserved_invariants: tuple[Ref,...]; lost_invariants: tuple[Ref,...]; validator_ref: Ref; authority_ref: Ref; provenance_ref: Ref
@dataclass(frozen=True, slots=True)
class ProfileBinding:
    profile_ref: Ref; profile_version: int; object_kind_refs: tuple[Ref,...]; required_sections: tuple[int,...]; optional_sections: tuple[int,...]; identity_policy_ref: Ref; canonicalization_ref: Ref; decoder_contract_ref: Ref; bridge_contract_refs: tuple[Ref,...]; conformance_class_ref: Ref

def _ref_key(r): return (r.bundle_slot,r.local_id)
def _inc_refs(refs,code):
    prev=None
    for r in refs:
        k=_ref_key(r)
        if prev is not None and k<=prev: raise ValueError(code)
        prev=k
def _inc_ints(vals,code):
    prev=-1
    for v in vals:
        if v<=prev: raise ValueError(code)
        prev=v
def _all(data,decoder):
    v,o=decoder(data,0)
    if o!=len(data): raise OriginDecodeError("OMIR_SECTION_TRAILING_BYTES")
    return v

def encode_identity_family(entries):
    _inc_refs(tuple(e.identity_kind_ref for e in entries),"IDENTITY_ENTRY_ORDER"); out=bytearray(encode_uvarint(len(entries)))
    for e in entries:
        out+=encode_ref(e.identity_kind_ref)+encode_ref(e.algorithm_ref)+encode_bytestring(e.digest)+encode_uvarint(e.scope_flags)
        p=(1 if e.authority_ref else 0)|(2 if e.provenance_ref else 0); out+=encode_uvarint(p)
        if e.authority_ref: out+=encode_ref(e.authority_ref)
        if e.provenance_ref: out+=encode_ref(e.provenance_ref)
    return bytes(out)
def _dec_identity(data,o):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        k,o=decode_ref(data,o); key=_ref_key(k)
        if prev is not None and key<=prev: raise OriginDecodeError("IDENTITY_ENTRY_ORDER")
        prev=key; a,o=decode_ref(data,o); d,o=decode_bytestring(data,o,max_length=4096); s,o=decode_uvarint(data,o); p,o=decode_uvarint(data,o)
        if p&~3: raise OriginDecodeError("IDENTITY_PRESENCE_FLAGS_INVALID")
        ar=pr=None
        if p&1: ar,o=decode_ref(data,o)
        if p&2: pr,o=decode_ref(data,o)
        rows.append(IdentityEntry(k,a,d,s,ar,pr))
    return tuple(rows),o
def decode_identity_family(data): return _all(data,_dec_identity)

def encode_invariants(entries):
    _inc_refs(tuple(e.invariant_ref for e in entries),"INVARIANT_ENTRY_ORDER"); out=bytearray(encode_uvarint(len(entries)))
    for e in entries:
        _inc_refs(e.observable_refs,"INVARIANT_OBSERVABLE_ORDER"); out+=encode_ref(e.invariant_ref)+encode_uvarint(len(e.observable_refs))
        for r in e.observable_refs: out+=encode_ref(r)
        out+=encode_ref(e.comparator_ref)+encode_uvarint(1 if e.tolerance_ref else 0)
        if e.tolerance_ref: out+=encode_ref(e.tolerance_ref)
        out+=encode_ref(e.scope_ref)+encode_ref(e.validator_ref)+encode_uvarint(e.severity)
    return bytes(out)
def _dec_invariants(data,o):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        ir,o=decode_ref(data,o); key=_ref_key(ir)
        if prev is not None and key<=prev: raise OriginDecodeError("INVARIANT_ENTRY_ORDER")
        prev=key; c,o=decode_uvarint(data,o); obs=[]; op=None
        for _ in range(c):
            r,o=decode_ref(data,o); k=_ref_key(r)
            if op is not None and k<=op: raise OriginDecodeError("INVARIANT_OBSERVABLE_ORDER")
            op=k; obs.append(r)
        comp,o=decode_ref(data,o); tp,o=decode_uvarint(data,o)
        if tp not in (0,1): raise OriginDecodeError("INVARIANT_TOLERANCE_FLAG_INVALID")
        tol=None
        if tp: tol,o=decode_ref(data,o)
        scope,o=decode_ref(data,o); val,o=decode_ref(data,o); sev,o=decode_uvarint(data,o); rows.append(InvariantContract(ir,tuple(obs),comp,tol,scope,val,sev))
    return tuple(rows),o
def decode_invariants(data): return _all(data,_dec_invariants)

def encode_payload_table(entries):
    _inc_refs(tuple(e.payload_ref for e in entries),"PAYLOAD_ENTRY_ORDER"); out=bytearray(encode_uvarint(len(entries)))
    for e in entries:
        if e.storage_class not in (0,1,2): raise ValueError("PAYLOAD_STORAGE_CLASS_INVALID")
        if e.storage_class==0 and e.logical_length!=len(e.body_or_locator): raise ValueError("PAYLOAD_INLINE_LENGTH_MISMATCH")
        out+=encode_ref(e.payload_ref)+encode_uvarint(e.storage_class)+encode_ref(e.media_type_ref)+encode_ref(e.codec_ref)+encode_uvarint(e.logical_length)+encode_digest(e.digest)+encode_bytestring(e.body_or_locator)
    return bytes(out)
def _dec_payload(data,o):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        pr,o=decode_ref(data,o); key=_ref_key(pr)
        if prev is not None and key<=prev: raise OriginDecodeError("PAYLOAD_ENTRY_ORDER")
        prev=key; sc,o=decode_uvarint(data,o)
        if sc not in (0,1,2): raise OriginDecodeError("PAYLOAD_STORAGE_CLASS_INVALID")
        mt,o=decode_ref(data,o); co,o=decode_ref(data,o); ll,o=decode_uvarint(data,o); dg,o=decode_digest(data,o); body,o=decode_bytestring(data,o,max_length=64*1024*1024)
        if sc==0 and ll!=len(body): raise OriginDecodeError("PAYLOAD_INLINE_LENGTH_MISMATCH")
        rows.append(PayloadEntry(pr,sc,mt,co,ll,dg,body))
    return tuple(rows),o
def decode_payload_table(data): return _all(data,_dec_payload)

def _enc_refs(refs):
    out=bytearray(encode_uvarint(len(refs)))
    for r in refs: out+=encode_ref(r)
    return out
def _enc_ints(vals):
    out=bytearray(encode_uvarint(len(vals)))
    for v in vals: out+=encode_uvarint(v)
    return out
def _dec_refs(data,o,code):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        r,o=decode_ref(data,o); k=_ref_key(r)
        if prev is not None and k<=prev: raise OriginDecodeError(code)
        prev=k; rows.append(r)
    return tuple(rows),o
def _dec_ints(data,o,code):
    n,o=decode_uvarint(data,o); rows=[]; prev=-1
    for _ in range(n):
        v,o=decode_uvarint(data,o)
        if v<=prev: raise OriginDecodeError(code)
        prev=v; rows.append(v)
    return tuple(rows),o

def encode_profile_binding(p):
    _inc_refs(p.object_kind_refs,"PROFILE_OBJECT_KIND_ORDER"); _inc_ints(p.required_sections,"PROFILE_REQUIRED_SECTION_ORDER"); _inc_ints(p.optional_sections,"PROFILE_OPTIONAL_SECTION_ORDER"); _inc_refs(p.bridge_contract_refs,"PROFILE_BRIDGE_CONTRACT_ORDER")
    if set(p.required_sections)&set(p.optional_sections): raise ValueError("PROFILE_SECTION_OVERLAP")
    return bytes(encode_ref(p.profile_ref)+encode_uvarint(p.profile_version)+_enc_refs(p.object_kind_refs)+_enc_ints(p.required_sections)+_enc_ints(p.optional_sections)+encode_ref(p.identity_policy_ref)+encode_ref(p.canonicalization_ref)+encode_ref(p.decoder_contract_ref)+_enc_refs(p.bridge_contract_refs)+encode_ref(p.conformance_class_ref))
def _dec_profile(data,o):
    pr,o=decode_ref(data,o); pv,o=decode_uvarint(data,o); ok,o=_dec_refs(data,o,"PROFILE_OBJECT_KIND_ORDER"); req,o=_dec_ints(data,o,"PROFILE_REQUIRED_SECTION_ORDER"); opt,o=_dec_ints(data,o,"PROFILE_OPTIONAL_SECTION_ORDER")
    if set(req)&set(opt): raise OriginDecodeError("PROFILE_SECTION_OVERLAP")
    ip,o=decode_ref(data,o); ca,o=decode_ref(data,o); dc,o=decode_ref(data,o); br,o=_dec_refs(data,o,"PROFILE_BRIDGE_CONTRACT_ORDER"); cc,o=decode_ref(data,o)
    return ProfileBinding(pr,pv,ok,req,opt,ip,ca,dc,br,cc),o
def decode_profile_binding(data): return _all(data,_dec_profile)

def encode_semantic_charts(entries):
    _inc_refs(tuple(e.chart_ref for e in entries),"CHART_ENTRY_ORDER"); out=bytearray(encode_uvarint(len(entries)))
    for e in entries: out+=encode_ref(e.chart_ref)+encode_ref(e.chart_type_ref)+encode_uvarint(e.chart_version)+encode_ref(e.domain_ref)+encode_ref(e.coordinate_schema_ref)+encode_ref(e.payload_ref)+encode_ref(e.authority_ref)+encode_ref(e.provenance_ref)+encode_uvarint(e.flags)
    return bytes(out)
def _dec_charts(data,o):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        cr,o=decode_ref(data,o); key=_ref_key(cr)
        if prev is not None and key<=prev: raise OriginDecodeError("CHART_ENTRY_ORDER")
        prev=key; ct,o=decode_ref(data,o); cv,o=decode_uvarint(data,o); d,o=decode_ref(data,o); cs,o=decode_ref(data,o); p,o=decode_ref(data,o); a,o=decode_ref(data,o); pr,o=decode_ref(data,o); fl,o=decode_uvarint(data,o); rows.append(SemanticChart(cr,ct,cv,d,cs,p,a,pr,fl))
    return tuple(rows),o
def decode_semantic_charts(data): return _all(data,_dec_charts)

def encode_transitions(entries):
    _inc_refs(tuple(e.transition_ref for e in entries),"TRANSITION_ENTRY_ORDER"); out=bytearray(encode_uvarint(len(entries)))
    for e in entries:
        if e.fidelity_class not in range(5): raise ValueError("TRANSITION_FIDELITY_INVALID")
        if not isinstance(e.deterministic,bool) or not isinstance(e.reversible,bool): raise ValueError("TRANSITION_FLAG_INVALID")
        _inc_refs(e.preserved_invariants,"TRANSITION_PRESERVED_INVARIANT_ORDER"); _inc_refs(e.lost_invariants,"TRANSITION_LOST_INVARIANT_ORDER")
        if set(e.preserved_invariants)&set(e.lost_invariants): raise ValueError("TRANSITION_INVARIANT_OVERLAP")
        out+=encode_ref(e.transition_ref)+encode_ref(e.source_chart_ref)+encode_ref(e.target_chart_ref)+encode_ref(e.transformer_ref)+encode_uvarint(e.fidelity_class)+encode_uvarint(int(e.deterministic))+encode_uvarint(int(e.reversible))+encode_ref(e.bound_ref)+_enc_refs(e.preserved_invariants)+_enc_refs(e.lost_invariants)+encode_ref(e.validator_ref)+encode_ref(e.authority_ref)+encode_ref(e.provenance_ref)
    return bytes(out)
def _dec_trans(data,o):
    n,o=decode_uvarint(data,o); rows=[]; prev=None
    for _ in range(n):
        tr,o=decode_ref(data,o); key=_ref_key(tr)
        if prev is not None and key<=prev: raise OriginDecodeError("TRANSITION_ENTRY_ORDER")
        prev=key; s,o=decode_ref(data,o); t,o=decode_ref(data,o); tf,o=decode_ref(data,o); f,o=decode_uvarint(data,o)
        if f not in range(5): raise OriginDecodeError("TRANSITION_FIDELITY_INVALID")
        dr,o=decode_uvarint(data,o); rr,o=decode_uvarint(data,o)
        if dr not in (0,1) or rr not in (0,1): raise OriginDecodeError("TRANSITION_FLAG_INVALID")
        b,o=decode_ref(data,o); pi,o=_dec_refs(data,o,"TRANSITION_PRESERVED_INVARIANT_ORDER"); li,o=_dec_refs(data,o,"TRANSITION_LOST_INVARIANT_ORDER")
        if set(pi)&set(li): raise OriginDecodeError("TRANSITION_INVARIANT_OVERLAP")
        v,o=decode_ref(data,o); a,o=decode_ref(data,o); p,o=decode_ref(data,o); rows.append(TransitionContract(tr,s,t,tf,f,bool(dr),bool(rr),b,pi,li,v,a,p))
    return tuple(rows),o
def decode_transitions(data): return _all(data,_dec_trans)
