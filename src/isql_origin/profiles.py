from __future__ import annotations

from dataclasses import dataclass

from .binary import Ref, decode_uvarint
from .errors import OriginDecodeError
from .orb import RegistryBundle, RegistryEntry, orb_digest

SHA256_REF = Ref(0, 1)
PROFILE_REGISTRY_BUNDLE_KIND_REF = Ref(0, 2)
PROFILE_REGISTRY_NAMESPACE_REF = Ref(0, 3)
PROFILE_MEM_REF = Ref(0, 10)
PROFILE_DSR_REF = Ref(0, 11)
MEM_ISN7_KIND_REF = Ref(0, 20)
MEM_ISD8_KIND_REF = Ref(0, 21)
MEM_ILI1_KIND_REF = Ref(0, 22)
DSR_REGISTRY_KIND_REF = Ref(0, 30)
DSR_STATE_KIND_REF = Ref(0, 31)
DSR_EVENT_STREAM_KIND_REF = Ref(0, 32)
DSR_BRANCH_KIND_REF = Ref(0, 33)
DSR_CAUSAL_PROGRAM_KIND_REF = Ref(0, 34)
DSR_VM_PROGRAM_KIND_REF = Ref(0, 35)
MEM_ISN7_CODEC_REF = Ref(0, 50)
MEM_ISD8_CODEC_REF = Ref(0, 51)
MEM_ILI1_CODEC_REF = Ref(0, 52)
DSR_REGISTRY_CODEC_REF = Ref(0, 53)
DSR_STATE_CODEC_REF = Ref(0, 54)
DSR_EVENT_STREAM_CODEC_REF = Ref(0, 55)
DSR_BRANCH_CODEC_REF = Ref(0, 56)
DSR_CAUSAL_PROGRAM_CODEC_REF = Ref(0, 57)
DSR_VM_PROGRAM_CODEC_REF = Ref(0, 58)
NATIVE_BYTES_IDENTITY_REF = Ref(0, 60)
BYTE_EXACT_INVARIANT_REF = Ref(0, 61)
NATIVE_BYTES_OBSERVABLE_REF = Ref(0, 62)
BYTES_EQUAL_COMPARATOR_REF = Ref(0, 63)
ARTIFACT_SCOPE_REF = Ref(0, 64)
SHA256_VALIDATOR_REF = Ref(0, 65)
NATIVE_PAYLOAD_REF = Ref(0, 66)
OCTET_STREAM_REF = Ref(0, 67)
P1_IDENTITY_POLICY_REF = Ref(0, 68)
PASS_THROUGH_CANONICALIZATION_REF = Ref(0, 69)
READ_ONLY_DECODER_CONTRACT_REF = Ref(0, 70)
P1_CONFORMANCE_CLASS_REF = Ref(0, 71)
REGISTRY_ENTRY_KIND_REF = Ref(0, 200)
REGISTRY_UTF8_PAYLOAD_KIND_REF = Ref(0, 201)

@dataclass(frozen=True, slots=True)
class ProfileDescriptor:
    name: str
    profile_ref: Ref
    profile_version: int

@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    key: str
    profile: ProfileDescriptor
    object_kind_ref: Ref
    codec_ref: Ref
    magic: bytes
    supported_versions: tuple[int, ...]
    version_encoding: str
    extensions: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class DetectedArtifact:
    profile: ProfileDescriptor
    artifact: ArtifactDescriptor
    native_version: int

MEM_PROFILE = ProfileDescriptor("isql-mem", PROFILE_MEM_REF, 1)
DSR_PROFILE = ProfileDescriptor("isql-dsr", PROFILE_DSR_REF, 1)
_ARTIFACTS = (
    ArtifactDescriptor("mem.isn7", MEM_PROFILE, MEM_ISN7_KIND_REF, MEM_ISN7_CODEC_REF, b"ISN7", (7,), "byte", (".isql7",)),
    ArtifactDescriptor("mem.isd8", MEM_PROFILE, MEM_ISD8_KIND_REF, MEM_ISD8_CODEC_REF, b"ISD8", (8,), "byte", (".isqld8",)),
    ArtifactDescriptor("mem.ili1", MEM_PROFILE, MEM_ILI1_KIND_REF, MEM_ILI1_CODEC_REF, b"ILI1", (1,), "byte", (".ili1",)),
    ArtifactDescriptor("dsr.registry", DSR_PROFILE, DSR_REGISTRY_KIND_REF, DSR_REGISTRY_CODEC_REF, bytes.fromhex("d551b104"), (4,), "uvarint", (".isqlr",)),
    ArtifactDescriptor("dsr.state", DSR_PROFILE, DSR_STATE_KIND_REF, DSR_STATE_CODEC_REF, bytes.fromhex("d551c105"), (5,), "uvarint", (".isqln",)),
    ArtifactDescriptor("dsr.event-stream", DSR_PROFILE, DSR_EVENT_STREAM_KIND_REF, DSR_EVENT_STREAM_CODEC_REF, bytes.fromhex("d551e105"), (5,), "uvarint", (".isqle",)),
    ArtifactDescriptor("dsr.branch", DSR_PROFILE, DSR_BRANCH_KIND_REF, DSR_BRANCH_CODEC_REF, bytes.fromhex("d551b706"), (6,), "uvarint", (".isqlb",)),
    ArtifactDescriptor("dsr.causal-program", DSR_PROFILE, DSR_CAUSAL_PROGRAM_KIND_REF, DSR_CAUSAL_PROGRAM_CODEC_REF, bytes.fromhex("d551e106"), (6,), "uvarint", (".isqlp",)),
    ArtifactDescriptor("dsr.vm-program", DSR_PROFILE, DSR_VM_PROGRAM_KIND_REF, DSR_VM_PROGRAM_CODEC_REF, bytes.fromhex("d551e207"), (7, 8, 9, 10), "uvarint", (".isqlp",)),
)
_PROFILES = (MEM_PROFILE, DSR_PROFILE)

def list_profiles(): return _PROFILES
def list_artifacts(): return _ARTIFACTS

def artifact_by_kind_ref(ref):
    return next((a for a in _ARTIFACTS if a.object_kind_ref == ref), None)

def profile_by_ref(ref):
    return next((p for p in _PROFILES if p.profile_ref == ref), None)

def _registry_labels():
    rows={1:"sha256",2:"origin-profile-registry",3:"isql-origin-p1",10:"profile:isql-mem",11:"profile:isql-dsr",20:"object:mem.isn7",21:"object:mem.isd8",22:"object:mem.ili1",30:"object:dsr.registry",31:"object:dsr.state",32:"object:dsr.event-stream",33:"object:dsr.branch",34:"object:dsr.causal-program",35:"object:dsr.vm-program",50:"codec:mem.isn7",51:"codec:mem.isd8",52:"codec:mem.ili1",53:"codec:dsr.registry",54:"codec:dsr.state",55:"codec:dsr.event-stream",56:"codec:dsr.branch",57:"codec:dsr.causal-program",58:"codec:dsr.vm-program",60:"identity:native-bytes-sha256",61:"invariant:byte-exact",62:"observable:native-bytes",63:"comparator:bytes-equal",64:"scope:native-artifact",65:"validator:sha256",66:"payload:native-artifact",67:"media:application-octet-stream",68:"identity-policy:native-byte-exact",69:"canonicalization:native-pass-through",70:"decoder-contract:read-only-detect",71:"conformance:origin-p1",200:"registry-entry-kind:label",201:"registry-payload-kind:utf8"}
    return tuple(sorted(rows.items()))

def profile_registry():
    return RegistryBundle(1,PROFILE_REGISTRY_BUNDLE_KIND_REF,PROFILE_REGISTRY_NAMESPACE_REF,None,1,tuple(RegistryEntry(i,REGISTRY_ENTRY_KIND_REF,REGISTRY_UTF8_PAYLOAD_KIND_REF,label.encode()) for i,label in _registry_labels()))

def profile_registry_digest(): return orb_digest(profile_registry())

def _read_version(data, artifact):
    offset=len(artifact.magic)
    if len(data)<=offset: raise OriginDecodeError("PROFILE_NATIVE_TRUNCATED")
    if artifact.version_encoding=="byte": return data[offset]
    try: version,_=decode_uvarint(data,offset)
    except OriginDecodeError as exc: raise OriginDecodeError("PROFILE_NATIVE_TRUNCATED",str(exc)) from exc
    return version

def detect_native_artifact(data):
    raw=bytes(data)
    for artifact in _ARTIFACTS:
        if raw.startswith(artifact.magic):
            version=_read_version(raw,artifact)
            if version not in artifact.supported_versions: raise OriginDecodeError("PROFILE_NATIVE_VERSION_UNSUPPORTED",f"{artifact.key}:{version}")
            return DetectedArtifact(artifact.profile,artifact,version)
    if any(magic.startswith(raw) for magic in (a.magic for a in _ARTIFACTS)) and len(raw)<5: raise OriginDecodeError("PROFILE_NATIVE_TRUNCATED")
    raise OriginDecodeError("PROFILE_NATIVE_MAGIC_UNKNOWN")
