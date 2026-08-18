from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import zipfile

from .binary import Digest, Ref
from .errors import OriginDecodeError
from .omir import OMIR_FORMAT_VERSION, OMIRObject, RegistryPin, Section
from .orb import RegistryBundle, RegistryEntry, orb_digest
from .profiles import (
    ARTIFACT_SCOPE_REF, BYTE_EXACT_INVARIANT_REF, BYTES_EQUAL_COMPARATOR_REF,
    NATIVE_BYTES_IDENTITY_REF, NATIVE_BYTES_OBSERVABLE_REF, NATIVE_PAYLOAD_REF,
    OCTET_STREAM_REF, P1_CONFORMANCE_CLASS_REF, P1_IDENTITY_POLICY_REF,
    PASS_THROUGH_CANONICALIZATION_REF, PROFILE_REGISTRY_BUNDLE_KIND_REF,
    READ_ONLY_DECODER_CONTRACT_REF, SHA256_REF, SHA256_VALIDATOR_REF,
    detect_native_artifact as detect_legacy_native, profile_registry, profile_registry_digest,
)
from .sections import (
    IdentityEntry, InvariantContract, PayloadEntry, ProfileBinding,
    decode_identity_family, decode_invariants, decode_payload_table, decode_profile_binding,
    encode_identity_family, encode_invariants, encode_payload_table, encode_profile_binding,
)
from .validation import validate_object

MLF_PROFILE_REF = Ref(1, 10)
MLF_PACKAGE_KIND_REF = Ref(1, 20)
MLF_PACKAGE_CODEC_REF = Ref(1, 50)
MLF_STRUCTURAL_IDENTITY_REF = Ref(1, 60)
MLF_CONTENT_IDENTITY_REF = Ref(1, 61)
MLF_SEMANTIC_IDENTITY_REF = Ref(1, 62)
MLF_PRESENTATION_IDENTITY_REF = Ref(1, 63)
MLF_REGISTRY_BUNDLE_KIND_REF = Ref(1, 2)
MLF_REGISTRY_NAMESPACE_REF = Ref(1, 3)
MLF_REGISTRY_ENTRY_KIND_REF = Ref(1, 200)
MLF_REGISTRY_UTF8_PAYLOAD_KIND_REF = Ref(1, 201)
P1_SECTION_SET = (1, 8, 9, 10)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Endpoint:
    profile_name: str
    artifact_kind: str
    native_version: int


@dataclass(frozen=True, slots=True)
class MLFInspection:
    mlf_version: str
    document_id: str
    title: str | None
    compiler_name: str
    compiler_version: str
    conformance: tuple[str, ...]
    fingerprint_algorithm: str
    fingerprints: dict[str, str]
    native_sha256: str
    native_bytes: int
    package_entry_count: int


def _safe(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and name not in {".", ".."}


def _obj(raw: bytes, code: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OriginDecodeError(code, str(exc)) from exc
    if not isinstance(value, dict):
        raise OriginDecodeError(code, "object-required")
    return value


def _manifest(raw: bytes) -> tuple[dict, tuple[str, ...]]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = tuple(info.filename for info in zf.infolist())
            if len(names) != len(set(names)):
                raise OriginDecodeError("P5_MLF_DUPLICATE_ENTRY")
            if any(not _safe(name) for name in names):
                raise OriginDecodeError("P5_MLF_UNSAFE_PATH")
            if "manifest.json" not in names:
                raise OriginDecodeError("PROFILE_MLF_MANIFEST_MISSING")
            manifest = _obj(zf.read("manifest.json"), "PROFILE_MLF_MANIFEST_INVALID")
    except OriginDecodeError:
        raise
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise OriginDecodeError("PROFILE_MLF_INVALID_ZIP", str(exc)) from exc
    if manifest.get("mlf_version") != "1.0":
        raise OriginDecodeError("PROFILE_NATIVE_VERSION_UNSUPPORTED", f"mlf.package:{manifest.get('mlf_version')}")
    return manifest, names


def detect_endpoint(data: bytes | bytearray | memoryview) -> Endpoint:
    raw = bytes(data)
    if raw.startswith(b"PK"):
        _manifest(raw)
        return Endpoint("mlf-1.0", "mlf.package", 1)
    detected = detect_legacy_native(raw)
    return Endpoint(detected.profile.name, detected.artifact.key, detected.native_version)


def inspect_mlf_native(data: bytes | bytearray | memoryview) -> MLFInspection:
    raw = bytes(data)
    manifest, names = _manifest(raw)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            fp_path = manifest.get("fingerprints", "reports/fingerprints.json")
            if not isinstance(fp_path, str) or not _safe(fp_path) or fp_path not in names:
                raise OriginDecodeError("P5_MLF_FINGERPRINT_FILE_MISSING")
            fp = _obj(zf.read(fp_path), "P5_MLF_FINGERPRINT_INVALID")
            mapping = {
                "structural": fp.get("structural_hash"),
                "content": fp.get("content_hash"),
                "semantic": fp.get("semantic_hash"),
                "presentation": fp.get("presentation_hash"),
            }
            if not isinstance(fp.get("algorithm"), str) or any(not isinstance(v, str) or not _HEX64.fullmatch(v) for v in mapping.values()):
                raise OriginDecodeError("P5_MLF_FINGERPRINT_INVALID")
            if "checksums.json" not in names:
                raise OriginDecodeError("P5_MLF_CHECKSUM_FILE_MISSING")
            checks = _obj(zf.read("checksums.json"), "P5_MLF_CHECKSUM_INVALID")
            if checks.get("algorithm") != "sha256" or not isinstance(checks.get("files"), list):
                raise OriginDecodeError("P5_MLF_CHECKSUM_INVALID")
            seen: set[str] = set()
            for row in checks["files"]:
                if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                    raise OriginDecodeError("P5_MLF_CHECKSUM_INVALID")
                path = row["path"]
                if not _safe(path) or path in seen or path not in names:
                    raise OriginDecodeError("P5_MLF_CHECKSUM_INVALID", path)
                seen.add(path)
                payload = zf.read(path)
                if hashlib.sha256(payload).hexdigest() != row.get("sha256") or ("bytes" in row and row.get("bytes") != len(payload)):
                    raise OriginDecodeError("P5_MLF_CHECKSUM_MISMATCH", path)
    except OriginDecodeError:
        raise
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise OriginDecodeError("P5_MLF_CONTAINER_INVALID", str(exc)) from exc
    compiler = manifest.get("compiler")
    if not isinstance(compiler, dict) or not isinstance(compiler.get("name"), str) or not isinstance(compiler.get("version"), str):
        raise OriginDecodeError("P5_MLF_MANIFEST_INVALID", "compiler")
    conformance = manifest.get("conformance")
    if not isinstance(conformance, list) or not conformance or not all(isinstance(x, str) for x in conformance):
        raise OriginDecodeError("P5_MLF_MANIFEST_INVALID", "conformance")
    document_id = manifest.get("document_id")
    if not isinstance(document_id, str) or not document_id:
        raise OriginDecodeError("P5_MLF_MANIFEST_INVALID", "document_id")
    return MLFInspection(
        "1.0", document_id, manifest.get("title") if isinstance(manifest.get("title"), str) else None,
        compiler["name"], compiler["version"], tuple(conformance), fp["algorithm"], dict(mapping),
        hashlib.sha256(raw).hexdigest(), len(raw), len(names),
    )


def mlf_registry() -> RegistryBundle:
    rows = (
        (2, "mlf-profile-registry"), (3, "isql-origin-p5-mlf"), (10, "profile:mlf-1.0"),
        (20, "object:mlf.package"), (50, "codec:mlf.package-zip-1.0"),
        (60, "identity:mlf.structural-fingerprint"), (61, "identity:mlf.content-fingerprint"),
        (62, "identity:mlf.semantic-fingerprint"), (63, "identity:mlf.presentation-fingerprint"),
        (200, "registry-entry-kind:label"), (201, "registry-payload-kind:utf8"),
    )
    entries = tuple(RegistryEntry(i, MLF_REGISTRY_ENTRY_KIND_REF, MLF_REGISTRY_UTF8_PAYLOAD_KIND_REF, label.encode()) for i, label in rows)
    return RegistryBundle(1, MLF_REGISTRY_BUNDLE_KIND_REF, MLF_REGISTRY_NAMESPACE_REF, None, 1, entries)


def wrap_mlf_native(data: bytes | bytearray | memoryview) -> OMIRObject:
    raw = bytes(data)
    info = inspect_mlf_native(raw)
    digest = hashlib.sha256(raw).digest()
    identities = (
        IdentityEntry(NATIVE_BYTES_IDENTITY_REF, SHA256_REF, digest, 0),
        IdentityEntry(MLF_STRUCTURAL_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["structural"]), 0),
        IdentityEntry(MLF_CONTENT_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["content"]), 0),
        IdentityEntry(MLF_SEMANTIC_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["semantic"]), 0),
        IdentityEntry(MLF_PRESENTATION_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["presentation"]), 0),
    )
    invariant = InvariantContract(BYTE_EXACT_INVARIANT_REF, (NATIVE_BYTES_OBSERVABLE_REF,), BYTES_EQUAL_COMPARATOR_REF, None, ARTIFACT_SCOPE_REF, SHA256_VALIDATOR_REF, 1)
    payload = PayloadEntry(NATIVE_PAYLOAD_REF, 0, OCTET_STREAM_REF, MLF_PACKAGE_CODEC_REF, len(raw), Digest(SHA256_REF, digest), raw)
    profile = ProfileBinding(MLF_PROFILE_REF, 1, (MLF_PACKAGE_KIND_REF,), P1_SECTION_SET, (), P1_IDENTITY_POLICY_REF, PASS_THROUGH_CANONICALIZATION_REF, READ_ONLY_DECODER_CONTRACT_REF, (), P1_CONFORMANCE_CLASS_REF)
    ext = mlf_registry()
    pins = (
        RegistryPin(0, PROFILE_REGISTRY_BUNDLE_KIND_REF, profile_registry().revision, Digest(SHA256_REF, profile_registry_digest()), 0),
        RegistryPin(1, MLF_REGISTRY_BUNDLE_KIND_REF, ext.revision, Digest(SHA256_REF, orb_digest(ext)), 0),
    )
    return OMIRObject(OMIR_FORMAT_VERSION, 0, MLF_PACKAGE_KIND_REF, MLF_PROFILE_REF, SHA256_REF, pins, (
        Section(1, 0, encode_identity_family(identities)),
        Section(8, 0, encode_invariants((invariant,))),
        Section(9, 0, encode_payload_table((payload,))),
        Section(10, 0, encode_profile_binding(profile)),
    ))


def validate_mlf_wrapper(obj: OMIRObject) -> list[str]:
    errors = validate_object(obj, {0: profile_registry(), 1: mlf_registry()})
    if tuple(section.tag for section in obj.sections) != P1_SECTION_SET:
        return errors + ["P1_SECTION_SET_INVALID"]
    try:
        by = {section.tag: section for section in obj.sections}
        identities = decode_identity_family(by[1].payload)
        invariants = decode_invariants(by[8].payload)
        payloads = decode_payload_table(by[9].payload)
        profile = decode_profile_binding(by[10].payload)
    except Exception as exc:
        return errors + [f"P5_MLF_SECTION_DECODE_FAILED:{exc}"]
    if len(payloads) != 1:
        return errors + ["P1_NATIVE_PAYLOAD_CARDINALITY_INVALID"]
    native = payloads[0].body_or_locator
    try:
        info = inspect_mlf_native(native)
    except OriginDecodeError as exc:
        return errors + [f"P5_MLF_INSPECTION_FAILED:{exc.code}"]
    digest = hashlib.sha256(native).digest()
    expected = (
        IdentityEntry(NATIVE_BYTES_IDENTITY_REF, SHA256_REF, digest, 0),
        IdentityEntry(MLF_STRUCTURAL_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["structural"]), 0),
        IdentityEntry(MLF_CONTENT_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["content"]), 0),
        IdentityEntry(MLF_SEMANTIC_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["semantic"]), 0),
        IdentityEntry(MLF_PRESENTATION_IDENTITY_REF, SHA256_REF, bytes.fromhex(info.fingerprints["presentation"]), 0),
    )
    if identities != expected:
        errors.append("P5_MLF_IDENTITY_FAMILY_MISMATCH")
    if payloads[0].digest.digest != digest or payloads[0].codec_ref != MLF_PACKAGE_CODEC_REF:
        errors.append("P5_MLF_PAYLOAD_BINDING_MISMATCH")
    expected_inv = InvariantContract(BYTE_EXACT_INVARIANT_REF, (NATIVE_BYTES_OBSERVABLE_REF,), BYTES_EQUAL_COMPARATOR_REF, None, ARTIFACT_SCOPE_REF, SHA256_VALIDATOR_REF, 1)
    if invariants != (expected_inv,):
        errors.append("P1_BYTE_EXACT_INVARIANT_MISSING")
    if obj.profile_ref != MLF_PROFILE_REF or obj.object_kind_ref != MLF_PACKAGE_KIND_REF:
        errors.append("P5_MLF_HEADER_BINDING_MISMATCH")
    if profile.profile_ref != MLF_PROFILE_REF or profile.object_kind_refs != (MLF_PACKAGE_KIND_REF,):
        errors.append("P5_MLF_PROFILE_BINDING_MISMATCH")
    return errors


def unwrap_mlf_native(obj: OMIRObject) -> bytes:
    errors = validate_mlf_wrapper(obj)
    if errors:
        raise OriginDecodeError("P5_MLF_WRAPPER_INVALID", ";".join(errors))
    by = {section.tag: section for section in obj.sections}
    return decode_payload_table(by[9].payload)[0].body_or_locator
