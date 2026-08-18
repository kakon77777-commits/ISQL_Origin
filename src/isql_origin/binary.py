from __future__ import annotations

from dataclasses import dataclass

from .errors import OriginDecodeError

MAX_UVARINT_BYTES = 10
MAX_UVARINT = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class Ref:
    bundle_slot: int
    local_id: int


@dataclass(frozen=True, slots=True)
class Digest:
    algorithm_ref: Ref
    digest: bytes


def encode_uvarint(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("UVarInt value must be an integer")
    if value < 0 or value > MAX_UVARINT:
        raise ValueError("UVarInt value out of supported uint64 range")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_uvarint(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int]:
    if offset < 0 or offset > len(data):
        raise OriginDecodeError("OMIR_OFFSET_INVALID")
    value = 0
    start = offset
    shift = 0
    for _ in range(MAX_UVARINT_BYTES):
        if offset >= len(data):
            raise OriginDecodeError("OMIR_TRUNCATED", "truncated UVarInt")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            if value > MAX_UVARINT:
                raise OriginDecodeError("OMIR_VARINT_OVERFLOW")
            encoded = encode_uvarint(value)
            if len(encoded) != offset - start:
                raise OriginDecodeError("OMIR_NON_CANONICAL_VARINT", "overlong UVarInt")
            return value, offset
        shift += 7
    raise OriginDecodeError("OMIR_VARINT_OVERFLOW", "UVarInt exceeds 10 bytes")


def zigzag_encode(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("SVarInt value must be an integer")
    return value * 2 if value >= 0 else (-value * 2) - 1


def zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def encode_svarint(value: int) -> bytes:
    return encode_uvarint(zigzag_encode(value))


def decode_svarint(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int]:
    raw, offset = decode_uvarint(data, offset)
    return zigzag_decode(raw), offset


def encode_bytestring(value: bytes | bytearray | memoryview) -> bytes:
    raw = bytes(value)
    return encode_uvarint(len(raw)) + raw


def decode_bytestring(
    data: bytes | bytearray | memoryview,
    offset: int = 0,
    *,
    max_length: int | None = None,
) -> tuple[bytes, int]:
    length, offset = decode_uvarint(data, offset)
    if max_length is not None and length > max_length:
        raise OriginDecodeError("OMIR_BOUND_EXCEEDED", f"bytestring length {length} > {max_length}")
    end = offset + length
    if end > len(data):
        raise OriginDecodeError("OMIR_TRUNCATED", "truncated byte string")
    return bytes(data[offset:end]), end


def encode_ref(ref: Ref) -> bytes:
    if not isinstance(ref, Ref):
        raise TypeError("ref must be Ref")
    return encode_uvarint(ref.bundle_slot) + encode_uvarint(ref.local_id)


def decode_ref(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[Ref, int]:
    bundle_slot, offset = decode_uvarint(data, offset)
    local_id, offset = decode_uvarint(data, offset)
    return Ref(bundle_slot, local_id), offset


def encode_digest(value: Digest) -> bytes:
    if not isinstance(value, Digest):
        raise TypeError("value must be Digest")
    return encode_ref(value.algorithm_ref) + encode_bytestring(value.digest)


def decode_digest(
    data: bytes | bytearray | memoryview,
    offset: int = 0,
    *,
    max_length: int = 128,
) -> tuple[Digest, int]:
    algorithm_ref, offset = decode_ref(data, offset)
    digest, offset = decode_bytestring(data, offset, max_length=max_length)
    return Digest(algorithm_ref, digest), offset
