from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .action import ActionCertificate
from .binary import Ref
from .profiles import detect_native_artifact

_ALLOWED_DSR_PROGRAMS = frozenset({'dsr.causal-program', 'dsr.vm-program'})


@dataclass(frozen=True, slots=True)
class DSRHandoff:
    status: str
    execute: bool
    operator_ref: Ref
    executor_ref: Ref
    origin_object_sha256: str
    dsr_artifact_kind: str
    dsr_native_version: int
    dsr_native_sha256: str
    dsr_native_bytes: int


def prepare_dsr_handoff(origin_bytes: bytes | bytearray | memoryview, certificate: ActionCertificate, executor_bytes: bytes | bytearray | memoryview) -> DSRHandoff:
    if not certificate.ready:
        raise ValueError('P3_HANDOFF_CERTIFICATE_NOT_READY')
    if certificate.executor_ref is None:
        raise ValueError('P3_HANDOFF_EXECUTOR_REF_MISSING')

    origin_raw = bytes(origin_bytes)
    origin_sha = hashlib.sha256(origin_raw).hexdigest()
    if origin_sha != certificate.origin_object_sha256:
        raise ValueError('P3_HANDOFF_ORIGIN_DIGEST_MISMATCH')

    executor_raw = bytes(executor_bytes)
    try:
        detected = detect_native_artifact(executor_raw)
    except Exception as exc:
        raise ValueError('P3_DSR_EXECUTOR_NOT_PROGRAM') from exc
    if detected.profile.name != 'isql-dsr' or detected.artifact.key not in _ALLOWED_DSR_PROGRAMS:
        raise ValueError('P3_DSR_EXECUTOR_NOT_PROGRAM')

    return DSRHandoff(
        status='READY',
        execute=False,
        operator_ref=certificate.operator_ref,
        executor_ref=certificate.executor_ref,
        origin_object_sha256=origin_sha,
        dsr_artifact_kind=detected.artifact.key,
        dsr_native_version=detected.native_version,
        dsr_native_sha256=hashlib.sha256(executor_raw).hexdigest(),
        dsr_native_bytes=len(executor_raw),
    )
