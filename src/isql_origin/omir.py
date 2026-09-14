from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .binary import Digest, Ref, decode_digest, decode_ref, decode_uvarint, encode_digest, encode_ref, encode_uvarint
from .errors import OriginDecodeError

OMIR_MAGIC = bytes((0xD5, 0x49, 0x4F, 0x01))
OMIR_FORMAT_VERSION = 1
SECTION_FLAG_CRITICAL = 0x01
KNOWN_CORE_TAGS = frozenset(range(1, 13))


@dataclass(frozen=True, slots=True)
class DecodeLimits:
    max_object_bytes: int = 64 * 1024 * 1024
    max_registry_slots: int = 256
    max_sections: int = 4096
    max_section_bytes: int = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RegistryPin:
    slot: int
    registry_kind_ref: Ref
    revision: int
    digest: Digest
    flags: int


@dataclass(frozen=True, slots=True)
class Section:
    tag: int
    flags: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class OMIRObject:
    format_version: int
    critical_flags: int
    object_kind_ref: Ref
    profile_ref: Ref
    hash_policy_ref: Ref
    registry_pins: tuple[RegistryPin, ...]
    sections: tuple[Section, ...]


def _check_pin_order(pins: tuple[RegistryPin, ...]) -> None:
    previous = -1
    for pin in pins:
        if pin.slot <= previous:
            raise ValueError("REGISTRY_SLOT_ORDER")
        previous = pin.slot


def _check_section_order(sections: tuple[Section, ...]) -> None:
    previous = -1
    for section in sections:
        if section.tag <= previous:
            raise ValueError("OMIR_SECTION_ORDER")
        previous = section.tag


def encode_omir(obj: OMIRObject, *, limits: DecodeLimits | None = None) -> bytes:
    limits = limits or DecodeLimits()
    if obj.format_version != OMIR_FORMAT_VERSION:
        raise ValueError("OMIR_UNSUPPORTED_VERSION")
    _check_pin_order(obj.registry_pins)
    _check_section_order(obj.sections)
    if len(obj.registry_pins) > limits.max_registry_slots:
        raise ValueError("OMIR_REGISTRY_SLOT_BOUND_EXCEEDED")
    if len(obj.sections) > limits.max_sections:
        raise ValueError("OMIR_SECTION_COUNT_BOUND_EXCEEDED")
    out = bytearray(OMIR_MAGIC)
    out += encode_uvarint(obj.format_version)
    out += encode_uvarint(obj.critical_flags)
    out += encode_ref(obj.object_kind_ref)
    out += encode_ref(obj.profile_ref)
    out += encode_ref(obj.hash_policy_ref)
    out += encode_uvarint(len(obj.registry_pins))
    for pin in obj.registry_pins:
        out += encode_uvarint(pin.slot)
        out += encode_ref(pin.registry_kind_ref)
        out += encode_uvarint(pin.revision)
        out += encode_digest(pin.digest)
        out += encode_uvarint(pin.flags)
    out += encode_uvarint(len(obj.sections))
    for section in obj.sections:
        if section.tag not in KNOWN_CORE_TAGS and (section.flags & SECTION_FLAG_CRITICAL):
            raise ValueError(f"OMIR_UNKNOWN_CRITICAL_SECTION:{section.tag}")
        if len(section.payload) > limits.max_section_bytes:
            raise ValueError("OMIR_SECTION_BOUND_EXCEEDED")
        out += encode_uvarint(section.tag)
        out += encode_uvarint(section.flags)
        out += encode_uvarint(len(section.payload))
        out += section.payload
    raw = bytes(out)
    if len(raw) > limits.max_object_bytes:
        raise ValueError("OMIR_OBJECT_BOUND_EXCEEDED")
    return raw


def decode_omir(data: bytes, *, limits: DecodeLimits | None = None) -> OMIRObject:
    limits = limits or DecodeLimits()
    if len(data) > limits.max_object_bytes:
        raise OriginDecodeError("OMIR_OBJECT_BOUND_EXCEEDED")
    if len(data) < 4 or data[:4] != OMIR_MAGIC:
        raise OriginDecodeError("OMIR_BAD_MAGIC")
    offset = 4
    format_version, offset = decode_uvarint(data, offset)
    if format_version != OMIR_FORMAT_VERSION:
        raise OriginDecodeError("OMIR_UNSUPPORTED_VERSION", str(format_version))
    critical_flags, offset = decode_uvarint(data, offset)
    object_kind_ref, offset = decode_ref(data, offset)
    profile_ref, offset = decode_ref(data, offset)
    hash_policy_ref, offset = decode_ref(data, offset)
    pin_count, offset = decode_uvarint(data, offset)
    if pin_count > limits.max_registry_slots:
        raise OriginDecodeError("OMIR_REGISTRY_SLOT_BOUND_EXCEEDED")
    pins: list[RegistryPin] = []
    previous_slot = -1
    for _ in range(pin_count):
        slot, offset = decode_uvarint(data, offset)
        if slot <= previous_slot:
            raise OriginDecodeError("REGISTRY_SLOT_ORDER")
        previous_slot = slot
        registry_kind_ref, offset = decode_ref(data, offset)
        revision, offset = decode_uvarint(data, offset)
        digest, offset = decode_digest(data, offset)
        flags, offset = decode_uvarint(data, offset)
        pins.append(RegistryPin(slot, registry_kind_ref, revision, digest, flags))
    section_count, offset = decode_uvarint(data, offset)
    if section_count > limits.max_sections:
        raise OriginDecodeError("OMIR_SECTION_COUNT_BOUND_EXCEEDED")
    sections: list[Section] = []
    previous_tag = -1
    for _ in range(section_count):
        tag, offset = decode_uvarint(data, offset)
        if tag <= previous_tag:
            raise OriginDecodeError("OMIR_SECTION_ORDER")
        previous_tag = tag
        flags, offset = decode_uvarint(data, offset)
        length, offset = decode_uvarint(data, offset)
        if length > limits.max_section_bytes:
            raise OriginDecodeError("OMIR_SECTION_BOUND_EXCEEDED")
        end = offset + length
        if end > len(data):
            raise OriginDecodeError("OMIR_TRUNCATED", "truncated section payload")
        payload = bytes(data[offset:end])
        offset = end
        if tag not in KNOWN_CORE_TAGS and (flags & SECTION_FLAG_CRITICAL):
            raise OriginDecodeError("OMIR_UNKNOWN_CRITICAL_SECTION", str(tag))
        sections.append(Section(tag, flags, payload))
    if offset != len(data):
        raise OriginDecodeError("OMIR_TRAILING_BYTES")
    return OMIRObject(format_version, critical_flags, object_kind_ref, profile_ref, hash_policy_ref, tuple(pins), tuple(sections))


def omir_digest(obj: OMIRObject | bytes) -> bytes:
    raw = obj if isinstance(obj, bytes) else encode_omir(obj)
    return hashlib.sha256(raw).digest()
