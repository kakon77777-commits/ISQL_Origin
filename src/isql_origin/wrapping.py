from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .binary import Digest
from .errors import OriginDecodeError
from .omir import OMIR_FORMAT_VERSION, OMIRObject, RegistryPin, Section, encode_omir
from .profiles import (
    ARTIFACT_SCOPE_REF, BYTE_EXACT_INVARIANT_REF, BYTES_EQUAL_COMPARATOR_REF,
    NATIVE_BYTES_IDENTITY_REF, NATIVE_BYTES_OBSERVABLE_REF, NATIVE_PAYLOAD_REF,
    OCTET_STREAM_REF, P1_CONFORMANCE_CLASS_REF, P1_IDENTITY_POLICY_REF,
    PASS_THROUGH_CANONICALIZATION_REF, PROFILE_REGISTRY_BUNDLE_KIND_REF,
    READ_ONLY_DECODER_CONTRACT_REF, SHA256_REF, SHA256_VALIDATOR_REF,
    detect_native_artifact, profile_registry, profile_registry_digest,
)
from .sections import (
    IdentityEntry, InvariantContract, PayloadEntry, ProfileBinding,
    decode_identity_family, decode_invariants, decode_payload_table, decode_profile_binding,
    encode_identity_family, encode_invariants, encode_payload_table, encode_profile_binding,
)
from .validation import validate_object

P1_SECTION_SET=(1,8,9,10)

@dataclass(frozen=True, slots=True)
class NativeBinding:
    profile:str; artifact_kind:str; native_version:int; native_sha256:str; omir_sha256:str; native_bytes:int

def _sha256(data:bytes)->bytes: return hashlib.sha256(data).digest()

def wrap_native_artifact(data):
    raw=bytes(data); detected=detect_native_artifact(raw); native_digest=_sha256(raw)
    identity=IdentityEntry(NATIVE_BYTES_IDENTITY_REF,SHA256_REF,native_digest,0)
    invariant=InvariantContract(BYTE_EXACT_INVARIANT_REF,(NATIVE_BYTES_OBSERVABLE_REF,),BYTES_EQUAL_COMPARATOR_REF,None,ARTIFACT_SCOPE_REF,SHA256_VALIDATOR_REF,1)
    payload=PayloadEntry(NATIVE_PAYLOAD_REF,0,OCTET_STREAM_REF,detected.artifact.codec_ref,len(raw),Digest(SHA256_REF,native_digest),raw)
    profile=ProfileBinding(detected.profile.profile_ref,detected.profile.profile_version,(detected.artifact.object_kind_ref,),P1_SECTION_SET,(),P1_IDENTITY_POLICY_REF,PASS_THROUGH_CANONICALIZATION_REF,READ_ONLY_DECODER_CONTRACT_REF,(),P1_CONFORMANCE_CLASS_REF)
    pin=RegistryPin(0,PROFILE_REGISTRY_BUNDLE_KIND_REF,profile_registry().revision,Digest(SHA256_REF,profile_registry_digest()),0)
    return OMIRObject(OMIR_FORMAT_VERSION,0,detected.artifact.object_kind_ref,detected.profile.profile_ref,SHA256_REF,(pin,),(
        Section(1,0,encode_identity_family((identity,))),Section(8,0,encode_invariants((invariant,))),Section(9,0,encode_payload_table((payload,))),Section(10,0,encode_profile_binding(profile))))

def _decoded_sections(obj):
    by_tag={s.tag:s for s in obj.sections}
    return decode_identity_family(by_tag[1].payload),decode_invariants(by_tag[8].payload),decode_payload_table(by_tag[9].payload),decode_profile_binding(by_tag[10].payload)

def validate_native_wrapper(obj):
    errors=validate_object(obj,{0:profile_registry()}); tags=tuple(s.tag for s in obj.sections)
    if tags!=P1_SECTION_SET: return errors+["P1_SECTION_SET_INVALID"]
    try: identities,invariants,payloads,profile=_decoded_sections(obj)
    except Exception as exc: return errors+[f"P1_SECTION_DECODE_FAILED:{exc}"]
    if len(payloads)!=1 or payloads[0].payload_ref!=NATIVE_PAYLOAD_REF: return errors+["P1_NATIVE_PAYLOAD_CARDINALITY_INVALID"]
    payload=payloads[0]; native=payload.body_or_locator; digest=_sha256(native)
    if payload.digest.digest!=digest: errors.append("P1_NATIVE_PAYLOAD_DIGEST_MISMATCH")
    if len(identities)!=1 or identities[0].digest!=digest: errors.append("P1_NATIVE_IDENTITY_MISMATCH")
    expected=InvariantContract(BYTE_EXACT_INVARIANT_REF,(NATIVE_BYTES_OBSERVABLE_REF,),BYTES_EQUAL_COMPARATOR_REF,None,ARTIFACT_SCOPE_REF,SHA256_VALIDATOR_REF,1)
    if invariants!=(expected,): errors.append("P1_BYTE_EXACT_INVARIANT_MISSING")
    try: detected=detect_native_artifact(native)
    except OriginDecodeError as exc: return errors+[f"P1_NATIVE_DETECTION_FAILED:{exc.code}"]
    if obj.profile_ref!=detected.profile.profile_ref: errors.append("P1_NATIVE_PROFILE_MISMATCH")
    if obj.object_kind_ref!=detected.artifact.object_kind_ref: errors.append("P1_NATIVE_OBJECT_KIND_MISMATCH")
    if payload.codec_ref!=detected.artifact.codec_ref: errors.append("P1_NATIVE_CODEC_MISMATCH")
    if profile.profile_ref!=detected.profile.profile_ref or profile.object_kind_refs!=(detected.artifact.object_kind_ref,): errors.append("P1_PROFILE_BINDING_MISMATCH")
    return errors

def unwrap_native_artifact(obj):
    errors=validate_native_wrapper(obj)
    if errors: raise OriginDecodeError("P1_WRAPPER_INVALID",";".join(errors))
    return _decoded_sections(obj)[2][0].body_or_locator

def native_binding(obj):
    errors=validate_native_wrapper(obj)
    if errors: raise OriginDecodeError("P1_WRAPPER_INVALID",";".join(errors))
    native=_decoded_sections(obj)[2][0].body_or_locator; detected=detect_native_artifact(native)
    return NativeBinding(detected.profile.name,detected.artifact.key,detected.native_version,hashlib.sha256(native).hexdigest(),hashlib.sha256(encode_omir(obj)).hexdigest(),len(native))

def inspect_native_wrapper(obj):
    b=native_binding(obj)
    return {"schema":"isql-origin-native-wrapper-inspection/v0.2","canonical":False,"profile":b.profile,"artifact_kind":b.artifact_kind,"native_version":b.native_version,"native_sha256":b.native_sha256,"omir_sha256":b.omir_sha256,"native_bytes":b.native_bytes,"section_tags":[s.tag for s in obj.sections],"registry_pin_count":len(obj.registry_pins)}
