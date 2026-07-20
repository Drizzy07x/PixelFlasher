"""Bounded Android binary XML decoding without legacy UI or subprocesses."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Protocol
from xml.sax.saxutils import escape, quoteattr


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class BinaryXmlStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class BinaryXmlCode(StrEnum):
    DECODED = "binary_xml_decoded"
    CANCELLED = "binary_xml_cancelled"
    INPUT_TOO_LARGE = "binary_xml_input_too_large"
    INVALID = "binary_xml_invalid"
    LIMIT_EXCEEDED = "binary_xml_limit_exceeded"
    OUTPUT_TOO_LARGE = "binary_xml_output_too_large"


@dataclass(frozen=True, slots=True)
class BinaryXmlLimits:
    maximum_input_bytes: int = 8 * 1024 * 1024
    maximum_output_bytes: int = 4 * 1024 * 1024
    maximum_strings: int = 100_000
    maximum_string_bytes: int = 1024 * 1024
    maximum_elements: int = 100_000
    maximum_attributes: int = 200_000
    maximum_attributes_per_element: int = 10_000
    maximum_depth: int = 256
    io_chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.maximum_input_bytes,
                self.maximum_output_bytes,
                self.maximum_strings,
                self.maximum_string_bytes,
                self.maximum_elements,
                self.maximum_attributes,
                self.maximum_attributes_per_element,
                self.maximum_depth,
                self.io_chunk_size,
            )
        ):
            raise ValueError("binary XML limits must be positive")


@dataclass(frozen=True, slots=True)
class BinaryXmlResult:
    status: BinaryXmlStatus
    code: BinaryXmlCode
    message: str
    xml: str = ""
    sha256: str = ""
    size_bytes: int = 0
    element_count: int = 0
    attribute_count: int = 0

    @property
    def ok(self) -> bool:
        return self.status is BinaryXmlStatus.SUCCESS


class _DecodeFailure(Exception):
    def __init__(self, code: BinaryXmlCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DecodeCancelled(Exception):
    pass


@dataclass(slots=True)
class _DecodedDocument:
    xml: str
    element_count: int
    attribute_count: int


class BinaryXmlService:
    def __init__(self, limits: BinaryXmlLimits | None = None) -> None:
        self.limits = limits or BinaryXmlLimits()

    def decode(
        self,
        source: BinaryIO,
        *,
        cancellation: CancellationProbe | None = None,
    ) -> BinaryXmlResult:
        digest = hashlib.sha256()
        data = bytearray()
        try:
            while True:
                _check_cancelled(cancellation)
                chunk = source.read(self.limits.io_chunk_size)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise _DecodeFailure(
                        BinaryXmlCode.INVALID,
                        "binary XML source returned non-byte content",
                    )
                data.extend(chunk)
                if len(data) > self.limits.maximum_input_bytes:
                    raise _DecodeFailure(
                        BinaryXmlCode.INPUT_TOO_LARGE,
                        "binary XML exceeds the configured input limit",
                    )
                digest.update(chunk)
            _check_cancelled(cancellation)
            document = _decode_document(bytes(data), self.limits, cancellation)
            return BinaryXmlResult(
                BinaryXmlStatus.SUCCESS,
                BinaryXmlCode.DECODED,
                "Android binary XML decoded successfully",
                document.xml,
                digest.hexdigest(),
                len(data),
                document.element_count,
                document.attribute_count,
            )
        except _DecodeCancelled:
            return BinaryXmlResult(
                BinaryXmlStatus.CANCELLED,
                BinaryXmlCode.CANCELLED,
                "binary XML decoding was cancelled",
            )
        except _DecodeFailure as error:
            return BinaryXmlResult(BinaryXmlStatus.FAILED, error.code, str(error))
        except Exception:
            return BinaryXmlResult(
                BinaryXmlStatus.FAILED,
                BinaryXmlCode.INVALID,
                "Android binary XML decoding failed",
            )


def _check_cancelled(cancellation: CancellationProbe | None) -> None:
    if cancellation is not None and cancellation.cancelled:
        raise _DecodeCancelled


def _failure(message: str, *, limit: bool = False) -> _DecodeFailure:
    return _DecodeFailure(
        BinaryXmlCode.LIMIT_EXCEEDED if limit else BinaryXmlCode.INVALID,
        message,
    )


def _chunk_header(data: bytes, offset: int, boundary: int) -> tuple[int, int, int]:
    if offset < 0 or offset + 8 > boundary:
        raise _failure("binary XML chunk is truncated")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if header_size < 8 or chunk_size < header_size or offset + chunk_size > boundary:
        raise _failure("binary XML chunk size is invalid")
    return chunk_type, header_size, chunk_size


def _decode_document(
    data: bytes,
    limits: BinaryXmlLimits,
    cancellation: CancellationProbe | None,
) -> _DecodedDocument:
    if len(data) < 8:
        raise _failure("binary XML header is truncated")
    chunk_type, header_size, total_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003 or header_size != 8 or total_size != len(data):
        raise _failure("binary XML header is invalid")

    strings: tuple[str, ...] | None = None
    offset = header_size
    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    output_bytes = len(lines[0].encode("utf-8")) + 1
    elements: list[str] = []
    namespace_events: list[tuple[str, str]] = []
    active_prefixes: dict[str, str] = {}
    active_uris: dict[str, str] = {}
    pending_namespaces: list[tuple[str, str]] = []
    root_started = False
    root_finished = False
    element_count = 0
    attribute_count = 0

    def append_line(line: str) -> None:
        nonlocal output_bytes
        line_bytes = len(line.encode("utf-8")) + 1
        if output_bytes + line_bytes > limits.maximum_output_bytes:
            raise _DecodeFailure(
                BinaryXmlCode.OUTPUT_TOO_LARGE,
                "decoded XML exceeds the configured output limit",
            )
        output_bytes += line_bytes
        lines.append(line)

    def string_at(index: int, *, optional: bool = False) -> str:
        if strings is None:
            raise _failure("binary XML node precedes its string pool")
        if index == 0xFFFFFFFF and optional:
            return ""
        if index >= len(strings):
            raise _failure("binary XML string index is invalid")
        return strings[index]

    def prefix_for(uri: str, *, attribute: bool = False) -> str:
        if not uri:
            return ""
        prefix = active_uris.get(uri)
        if prefix is not None and (prefix or not attribute):
            return prefix
        raise _failure("binary XML namespace is not declared in scope")

    while offset < total_size:
        _check_cancelled(cancellation)
        node_type, node_header, node_size = _chunk_header(data, offset, total_size)
        chunk = data[offset : offset + node_size]
        if node_type == 0x0001:
            if strings is not None or root_started:
                raise _failure("binary XML string pool is duplicated or out of order")
            strings = _parse_string_pool(chunk, limits)
        elif node_type == 0x0180:
            if strings is None or root_started or node_header != 8 or (node_size - 8) % 4:
                raise _failure("binary XML resource map is invalid")
        elif node_type in {0x0100, 0x0101}:
            if strings is None or node_header < 16 or node_size < node_header + 8:
                raise _failure("binary XML namespace node is invalid")
            prefix = string_at(struct.unpack_from("<I", chunk, node_header)[0], optional=True)
            uri = string_at(struct.unpack_from("<I", chunk, node_header + 4)[0])
            _validate_namespace(prefix, uri)
            if node_type == 0x0100:
                if prefix in active_prefixes and active_prefixes[prefix] != uri:
                    raise _failure("binary XML namespace prefix is ambiguous")
                active_prefixes[prefix] = uri
                active_uris[uri] = prefix
                namespace_events.append((prefix, uri))
                pending_namespaces.append((prefix, uri))
            else:
                if not namespace_events or namespace_events[-1] != (prefix, uri):
                    raise _failure("binary XML namespace closure is unbalanced")
                if (prefix, uri) in pending_namespaces:
                    raise _failure("binary XML namespace was closed before an element used it")
                namespace_events.pop()
                active_prefixes.pop(prefix, None)
                if active_uris.get(uri) == prefix:
                    active_uris.pop(uri, None)
                for previous_prefix, previous_uri in reversed(namespace_events):
                    if previous_prefix == prefix and prefix not in active_prefixes:
                        active_prefixes[prefix] = previous_uri
                    if previous_uri == uri and uri not in active_uris:
                        active_uris[uri] = previous_prefix
                    if prefix in active_prefixes and uri in active_uris:
                        break
        elif node_type == 0x0102:
            if root_finished or strings is None or node_header < 16 or node_size < node_header + 20:
                raise _failure("binary XML start element is invalid")
            if len(elements) >= limits.maximum_depth:
                raise _failure("binary XML nesting exceeds its limit", limit=True)
            element_count += 1
            if element_count > limits.maximum_elements:
                raise _failure("binary XML element count exceeds its limit", limit=True)
            namespace_index, name_index, attribute_start, attribute_size, count = struct.unpack_from(
                "<IIHHH", chunk, node_header
            )
            if attribute_size < 20 or count > limits.maximum_attributes_per_element:
                raise _failure("binary XML element attributes are invalid", limit=count > limits.maximum_attributes_per_element)
            attributes_offset = node_header + attribute_start
            if attributes_offset < node_header + 20 or attributes_offset + count * attribute_size > node_size:
                raise _failure("binary XML element attributes are truncated")
            attribute_count += count
            if attribute_count > limits.maximum_attributes:
                raise _failure("binary XML attribute count exceeds its limit", limit=True)
            local_name = string_at(name_index)
            _validate_name(local_name)
            namespace_uri = string_at(namespace_index, optional=True)
            prefix = prefix_for(namespace_uri)
            qualified_name = f"{prefix}:{local_name}" if prefix else local_name
            rendered_attributes: list[str] = []
            rendered_attribute_bytes = 0
            for index in range(count):
                item = attributes_offset + index * attribute_size
                attr_namespace, attr_name_index, raw_value = struct.unpack_from("<III", chunk, item)
                value_size, value_zero, value_type, typed_data = struct.unpack_from("<HBBI", chunk, item + 12)
                if value_size != 8 or value_zero != 0:
                    raise _failure("binary XML typed value is invalid")
                attr_name = string_at(attr_name_index)
                _validate_name(attr_name)
                attr_uri = string_at(attr_namespace, optional=True)
                attr_prefix = prefix_for(attr_uri, attribute=True)
                attr_qualified = f"{attr_prefix}:{attr_name}" if attr_prefix else attr_name
                value = (
                    string_at(raw_value)
                    if raw_value != 0xFFFFFFFF
                    else _typed_value(value_type, typed_data, string_at)
                )
                rendered = f"{attr_qualified}={quoteattr(value)}"
                rendered_attribute_bytes += len(rendered.encode("utf-8")) + 1
                if rendered_attribute_bytes > limits.maximum_output_bytes:
                    raise _DecodeFailure(
                        BinaryXmlCode.OUTPUT_TOO_LARGE,
                        "decoded XML exceeds the configured output limit",
                    )
                rendered_attributes.append(rendered)
            declarations: list[str] = []
            declaration_bytes = 0
            for namespace_prefix, namespace_uri_value in pending_namespaces:
                name = f"xmlns:{namespace_prefix}" if namespace_prefix else "xmlns"
                declaration = f"{name}={quoteattr(namespace_uri_value)}"
                declaration_bytes += len(declaration.encode("utf-8")) + 1
                if declaration_bytes > limits.maximum_output_bytes:
                    raise _DecodeFailure(
                        BinaryXmlCode.OUTPUT_TOO_LARGE,
                        "decoded XML exceeds the configured output limit",
                    )
                declarations.append(declaration)
            pending_namespaces.clear()
            joined = " ".join((*declarations, *rendered_attributes))
            append_line(f"{'  ' * len(elements)}<{qualified_name}{' ' if joined else ''}{joined}>")
            elements.append(qualified_name)
            if not root_started:
                root_started = True
        elif node_type == 0x0103:
            if strings is None or node_header < 16 or node_size < node_header + 8 or not elements:
                raise _failure("binary XML end element is invalid")
            namespace_index, name_index = struct.unpack_from("<II", chunk, node_header)
            local_name = string_at(name_index)
            namespace_uri = string_at(namespace_index, optional=True)
            prefix = active_uris.get(namespace_uri, "") if namespace_uri else ""
            qualified_name = f"{prefix}:{local_name}" if prefix else local_name
            if elements[-1] != qualified_name:
                raise _failure("binary XML element closure is unbalanced")
            elements.pop()
            append_line(f"{'  ' * len(elements)}</{qualified_name}>")
            if not elements:
                root_finished = True
        elif node_type == 0x0104:
            if strings is None or node_header < 16 or node_size < node_header + 12 or not elements:
                raise _failure("binary XML text node is invalid")
            text_index = struct.unpack_from("<I", chunk, node_header)[0]
            text = string_at(text_index)
            append_line(f"{'  ' * len(elements)}{escape(text)}")
        else:
            raise _failure(f"binary XML contains unsupported chunk type 0x{node_type:04x}")
        offset += node_size

    if offset != total_size or strings is None or not root_started or not root_finished or elements or namespace_events:
        raise _failure("binary XML document is incomplete")
    xml = "\n".join(lines) + "\n"
    if len(xml.encode("utf-8")) != output_bytes:
        raise _failure("decoded XML output accounting mismatch")
    return _DecodedDocument(xml, element_count, attribute_count)


def _parse_string_pool(data: bytes, limits: BinaryXmlLimits) -> tuple[str, ...]:
    if len(data) < 28:
        raise _failure("binary XML string pool is truncated")
    (
        chunk_type,
        header_size,
        chunk_size,
        string_count,
        style_count,
        flags,
        strings_start,
        styles_start,
    ) = struct.unpack_from("<HHIIIIII", data, 0)
    offsets_end = header_size + 4 * (string_count + style_count)
    if (
        chunk_type != 0x0001
        or header_size < 28
        or chunk_size != len(data)
        or string_count > limits.maximum_strings
        or offsets_end > len(data)
        or strings_start < offsets_end
        or strings_start > len(data)
        or (styles_start and (styles_start < strings_start or styles_start > len(data)))
    ):
        raise _failure("binary XML string pool is invalid", limit=string_count > limits.maximum_strings)
    boundary = styles_start or len(data)
    utf8 = bool(flags & 0x100)
    values: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", data, header_size + index * 4)[0]
        start = strings_start + relative
        if start < strings_start or start >= boundary:
            raise _failure("binary XML string offset is invalid")
        value = (
            _decode_utf8(data, start, boundary, limits.maximum_string_bytes)
            if utf8
            else _decode_utf16(data, start, boundary, limits.maximum_string_bytes)
        )
        _validate_xml_text(value)
        values.append(value)
    return tuple(values)


def _length8(data: bytes, offset: int, boundary: int) -> tuple[int, int]:
    if offset >= boundary:
        raise _failure("binary XML string length is truncated")
    first = data[offset]
    if first & 0x80:
        if offset + 2 > boundary:
            raise _failure("binary XML string length is truncated")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _length16(data: bytes, offset: int, boundary: int) -> tuple[int, int]:
    if offset + 2 > boundary:
        raise _failure("binary XML string length is truncated")
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        if offset + 4 > boundary:
            raise _failure("binary XML string length is truncated")
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


def _decode_utf8(data: bytes, start: int, boundary: int, limit: int) -> str:
    utf16_length, offset = _length8(data, start, boundary)
    byte_length, offset = _length8(data, offset, boundary)
    if byte_length > limit or offset + byte_length + 1 > boundary or data[offset + byte_length] != 0:
        raise _failure("binary XML UTF-8 string is invalid", limit=byte_length > limit)
    try:
        value = data[offset : offset + byte_length].decode("utf-8")
    except UnicodeError as error:
        raise _failure("binary XML UTF-8 string is invalid") from error
    if len(value.encode("utf-16le")) // 2 != utf16_length:
        raise _failure("binary XML UTF-8 string length is invalid")
    return value


def _decode_utf16(data: bytes, start: int, boundary: int, limit: int) -> str:
    code_units, offset = _length16(data, start, boundary)
    byte_length = code_units * 2
    if byte_length > limit or offset + byte_length + 2 > boundary or data[offset + byte_length : offset + byte_length + 2] != b"\0\0":
        raise _failure("binary XML UTF-16 string is invalid", limit=byte_length > limit)
    try:
        return data[offset : offset + byte_length].decode("utf-16le")
    except UnicodeError as error:
        raise _failure("binary XML UTF-16 string is invalid") from error


def _typed_value(value_type: int, data: int, string_at: Callable[[int], str]) -> str:
    resolver = string_at
    if value_type == 0x03:
        return resolver(data)
    if value_type == 0x01:
        return f"@0x{data:08x}"
    if value_type == 0x02:
        return f"?0x{data:08x}"
    if value_type == 0x04:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    if value_type == 0x10:
        return str(struct.unpack("<i", struct.pack("<I", data))[0])
    if value_type == 0x11:
        return f"0x{data:08x}"
    if value_type == 0x12:
        return "true" if data else "false"
    if value_type in {0x1C, 0x1D, 0x1E, 0x1F}:
        return f"#{data:08x}"
    if value_type == 0x00 and data == 0:
        return ""
    return f"0x{data:08x}"


def _validate_xml_text(value: str) -> None:
    if any(
        not (
            character in "\t\n\r"
            or "\u0020" <= character <= "\ud7ff"
            or "\ue000" <= character <= "\ufffd"
            or "\U00010000" <= character <= "\U0010ffff"
        )
        for character in value
    ):
        raise _failure("binary XML contains invalid XML characters")


def _validate_name(value: str) -> None:
    if (
        not value
        or len(value) > 1024
        or not (value[0].isalpha() or value[0] == "_")
        or any(not (character.isalnum() or character in "_.-") for character in value[1:])
    ):
        raise _failure("binary XML name is invalid")


def _validate_namespace(prefix: str, uri: str) -> None:
    if prefix:
        _validate_name(prefix)
    if not uri or len(uri.encode("utf-8")) > 4096:
        raise _failure("binary XML namespace URI is invalid")


__all__ = [
    "BinaryXmlCode",
    "BinaryXmlLimits",
    "BinaryXmlResult",
    "BinaryXmlService",
    "BinaryXmlStatus",
]
