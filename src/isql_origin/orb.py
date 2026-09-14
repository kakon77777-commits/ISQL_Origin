from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .binary import (
    Ref,
    decode_bytestring,
    decode_ref,
    decode_uvarint,
    encode_bytestring,
    encode_ref,
    encode_uvarint,
)
from .errors import OriginDecodeError

ORB_MAGIC = bytes((0xD5, 0x52, 0x42, 0x01))
ORB_FORMAT_VERSION = 1


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    local_id: int
    entry_kind_ref: Ref
    payload_kind_ref: Ref
    payload: bytes


@dataclass(frozen=True, slots=True)
class RegistryBundle:
    format_version: int
    bundle_kind_ref: Ref
    namespace_ref: Ref
    parent_digest: bytes | None
    revision: int
    entries: tuple[RegistryEntry, ...]


def _check_entry_order(entries: tuple[RegistryEntry, ...]) -> None:
    previous = -1
    for entry in entries:
        if entry.local_id <= previous:
            raise ValueError("REGISTRY_ENTRY_ORDER: local_id values must be strictly increasing")
        previous = entry.local_id


def encode_orb(bundle: RegistryBundle) -> bytes:
    if bundle.format_version != ORB_FORMAT_VERSION:
        raise ValueError("REGISTRY_UNSUPPORTED_VERSION")
    _check_entry_order(bundle.entries)
    if bundle.parent_digest is not None and len(bundle.parent_digest) != 32:
        raise ValueError("REGISTRY_PARENT_DIGEST_LENGTH")
    out = bytearray(ORB_MAGIC)
    out += encode_uvarint(bundle.format_version)
    out += encode_ref(bundle.bundle_kind_ref)
    out += encode_ref(bundle.namespace_ref)
    out += encode_uvarint(1 if bundle.parent_digest is not None else 0)
    if bundle.parent_digest is not None:
        out += encode_bytestring(bundle.parent_digest)
    out += encode_uvarint(bundle.revision)
    out += encode_uvarint(len(bundle.entries))
    for entry in bundle.entries:
        out += encode_uvarint(entry.local_id)
        out += encode_ref(entry.entry_kind_ref)
        out += encode_ref(entry.payload_kind_ref)
        out += encode_bytestring(entry.payload)
    return bytes(out)


def decode_orb(data: bytes, *, max_entries: int = 100_000, max_payload_bytes: int = 16 * 1024 * 1024) -> RegistryBundle:
    if len(data) < len(ORB_MAGIC) or data[:4] != ORB_MAGIC:
        raise OriginDecodeError("ORB_BAD_MAGIC")
    offset = 4
    format_version, offset = decode_uvarint(data, offset)
    if format_version != ORB_FORMAT_VERSION:
        raise OriginDecodeError("ORB_UNSUPPORTED_VERSION", str(format_version))
    bundle_kind_ref, offset = decode_ref(data, offset)
    namespace_ref, offset = decode_ref(data, offset)
    parent_present, offset = decode_uvarint(data, offset)
    if parent_present not in (0, 1):
        raise OriginDecodeError("ORB_PARENT_FLAG_INVALID")
    parent_digest = None
    if parent_present:
        parent_digest, offset = decode_bytestring(data, offset, max_length=128)
        if len(parent_digest) != 32:
            raise OriginDecodeError("ORB_PARENT_DIGEST_LENGTH")
    revision, offset = decode_uvarint(data, offset)
    entry_count, offset = decode_uvarint(data, offset)
    if entry_count > max_entries:
        raise OriginDecodeError("ORB_BOUND_EXCEEDED", f"entry_count {entry_count} > {max_entries}")
    entries: list[RegistryEntry] = []
    previous = -1
    for _ in range(entry_count):
        local_id, offset = decode_uvarint(data, offset)
        if local_id <= previous:
            raise OriginDecodeError("ORB_ENTRY_ORDER")
        previous = local_id
        entry_kind_ref, offset = decode_ref(data, offset)
        payload_kind_ref, offset = decode_ref(data, offset)
        payload, offset = decode_bytestring(data, offset, max_length=max_payload_bytes)
        entries.append(RegistryEntry(local_id, entry_kind_ref, payload_kind_ref, payload))
    if offset != len(data):
        raise OriginDecodeError("ORB_TRAILING_BYTES")
    return RegistryBundle(format_version, bundle_kind_ref, namespace_ref, parent_digest, revision, tuple(entries))


def orb_digest(bundle: RegistryBundle | bytes) -> bytes:
    raw = bundle if isinstance(bundle, bytes) else encode_orb(bundle)
    return hashlib.sha256(raw).digest()


def validate_append_only(parent: RegistryBundle, child: RegistryBundle) -> None:
    if child.bundle_kind_ref != parent.bundle_kind_ref or child.namespace_ref != parent.namespace_ref:
        raise ValueError("REGISTRY_LINEAGE_MISMATCH")
    if child.parent_digest != orb_digest(parent):
        raise ValueError("REGISTRY_PARENT_DIGEST_MISMATCH")
    if child.revision <= parent.revision:
        raise ValueError("REGISTRY_REVISION_NOT_ADVANCED")
    parent_by_id = {entry.local_id: entry for entry in parent.entries}
    child_by_id = {entry.local_id: entry for entry in child.entries}
    for local_id, entry in parent_by_id.items():
        if local_id not in child_by_id:
            raise ValueError(f"REGISTRY_ENTRY_REMOVED:{local_id}")
        if child_by_id[local_id] != entry:
            raise ValueError(f"REGISTRY_REBIND:{local_id}")
    if parent.entries:
        max_parent = parent.entries[-1].local_id
        for entry in child.entries:
            if entry.local_id not in parent_by_id and entry.local_id <= max_parent:
                raise ValueError(f"REGISTRY_NON_APPEND_ID:{entry.local_id}")
