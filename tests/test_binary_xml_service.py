from __future__ import annotations

import random
import struct
import tempfile
from io import BytesIO
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pixelflasher_core.binary_xml import (
    BinaryXmlCode,
    BinaryXmlLimits,
    BinaryXmlService,
    BinaryXmlStatus,
)
from pixelflasher_core.contracts import AppCommand, AppSnapshot
from pixelflasher_core.grants import PathGrantStore
from pixelflasher_core.store import AppStateStore
from tests.command_engine_factory import make_test_command_engine


def _utf8_pool_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    assert len(value) < 128 and len(encoded) < 128
    return bytes((len(value), len(encoded))) + encoded + b"\0"


def _string_pool(strings: tuple[str, ...]) -> bytes:
    encoded = tuple(_utf8_pool_string(value) for value in strings)
    offsets: list[int] = []
    cursor = 0
    for value in encoded:
        offsets.append(cursor)
        cursor += len(value)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    body = b"".join(encoded)
    size = strings_start + len(body)
    return (
        struct.pack(
            "<HHIIIIII",
            0x0001,
            header_size,
            size,
            len(strings),
            0,
            0x100,
            strings_start,
            0,
        )
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + body
    )


def _start_element(name: int, attributes: tuple[bytes, ...] = ()) -> bytes:
    size = 16 + 20 + 20 * len(attributes)
    return (
        struct.pack("<HHI", 0x0102, 16, size)
        + struct.pack("<II", 1, 0xFFFFFFFF)
        + struct.pack(
            "<IIHHHHHH",
            0xFFFFFFFF,
            name,
            20,
            20,
            len(attributes),
            0,
            0,
            0,
        )
        + b"".join(attributes)
    )


def _end_element(name: int) -> bytes:
    return (
        struct.pack("<HHI", 0x0103, 16, 24)
        + struct.pack("<II", 1, 0xFFFFFFFF)
        + struct.pack("<II", 0xFFFFFFFF, name)
    )


def _namespace(chunk_type: int, prefix: int, uri: int) -> bytes:
    return (
        struct.pack("<HHI", chunk_type, 16, 24)
        + struct.pack("<II", 1, 0xFFFFFFFF)
        + struct.pack("<II", prefix, uri)
    )


def _binary_xml() -> bytes:
    strings = ("manifest", "package", "org.example.binary")
    attribute = struct.pack(
        "<IIIHBBI",
        0xFFFFFFFF,
        1,
        2,
        8,
        0,
        0x03,
        2,
    )
    chunks = (_string_pool(strings), _start_element(0, (attribute,)), _end_element(0))
    size = 8 + sum(len(chunk) for chunk in chunks)
    return struct.pack("<HHI", 0x0003, 8, size) + b"".join(chunks)


def _namespaced_binary_xml() -> bytes:
    strings = (
        "manifest",
        "android",
        "http://schemas.android.com/apk/res/android",
        "versionCode",
    )
    attribute = struct.pack(
        "<IIIHBBI",
        2,
        3,
        0xFFFFFFFF,
        8,
        0,
        0x10,
        42,
    )
    chunks = (
        _string_pool(strings),
        _namespace(0x0100, 1, 2),
        _start_element(0, (attribute,)),
        _end_element(0),
        _namespace(0x0101, 1, 2),
    )
    size = 8 + sum(len(chunk) for chunk in chunks)
    return struct.pack("<HHI", 0x0003, 8, size) + b"".join(chunks)


class _Cancellation:
    def __init__(self, cancelled: bool) -> None:
        self.cancelled = cancelled


def test_decodes_bounded_android_binary_xml_without_external_tools() -> None:
    payload = _binary_xml()
    result = BinaryXmlService().decode(BytesIO(payload))

    assert result.status is BinaryXmlStatus.SUCCESS
    assert result.code is BinaryXmlCode.DECODED
    assert result.size_bytes == len(payload)
    assert result.element_count == 1
    assert result.attribute_count == 1
    assert result.sha256
    assert result.xml == (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="org.example.binary">\n'
        '</manifest>\n'
    )


def test_preserves_declared_namespaces_and_typed_integer_attributes() -> None:
    result = BinaryXmlService().decode(BytesIO(_namespaced_binary_xml()))

    assert result.ok
    assert result.xml == (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42">\n'
        '</manifest>\n'
    )


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"<manifest />", BinaryXmlCode.INVALID),
        (_binary_xml()[:-1], BinaryXmlCode.INVALID),
        (b"x" * 17, BinaryXmlCode.INPUT_TOO_LARGE),
    ],
)
def test_malformed_truncated_and_oversized_inputs_fail_closed(
    payload: bytes,
    code: BinaryXmlCode,
) -> None:
    limits = (
        BinaryXmlLimits(maximum_input_bytes=16)
        if code is BinaryXmlCode.INPUT_TOO_LARGE
        else BinaryXmlLimits()
    )
    result = BinaryXmlService(limits).decode(BytesIO(payload))

    assert result.status is BinaryXmlStatus.FAILED
    assert result.code is code
    assert not result.xml
    assert not result.sha256


def test_cancellation_is_never_reported_as_success() -> None:
    result = BinaryXmlService().decode(
        BytesIO(_binary_xml()),
        cancellation=_Cancellation(True),
    )

    assert result.status is BinaryXmlStatus.CANCELLED
    assert result.code is BinaryXmlCode.CANCELLED


def test_output_expansion_is_stopped_at_the_configured_byte_boundary() -> None:
    result = BinaryXmlService(
        BinaryXmlLimits(maximum_output_bytes=64)
    ).decode(BytesIO(_binary_xml()))

    assert result.status is BinaryXmlStatus.FAILED
    assert result.code is BinaryXmlCode.OUTPUT_TOO_LARGE
    assert not result.xml


def test_random_bytes_never_escape_as_raw_parser_exceptions() -> None:
    service = BinaryXmlService(BinaryXmlLimits(maximum_input_bytes=2048))
    generator = random.Random(0xA11CE)
    for size in range(0, 257, 7):
        result = service.decode(BytesIO(generator.randbytes(size)))
        assert result.status is BinaryXmlStatus.FAILED
        assert result.code in {
            BinaryXmlCode.INVALID,
            BinaryXmlCode.LIMIT_EXCEEDED,
            BinaryXmlCode.OUTPUT_TOO_LARGE,
        }


@given(st.binary(max_size=2048))
@settings(max_examples=200, deadline=None)
def test_arbitrary_bytes_always_yield_a_typed_result(data: bytes) -> None:
    result = BinaryXmlService(BinaryXmlLimits(maximum_input_bytes=2048)).decode(
        BytesIO(data)
    )

    assert result.status in {BinaryXmlStatus.SUCCESS, BinaryXmlStatus.FAILED}
    if result.status is BinaryXmlStatus.FAILED:
        assert result.code in {
            BinaryXmlCode.INVALID,
            BinaryXmlCode.LIMIT_EXCEEDED,
            BinaryXmlCode.OUTPUT_TOO_LARGE,
        }
    else:
        assert result.code is BinaryXmlCode.DECODED


@given(data=st.data())
@settings(max_examples=200, deadline=None)
def test_corrupted_documents_never_escape_the_typed_result(
    data: st.DataObject,
) -> None:
    document = bytearray(_binary_xml())
    index = data.draw(st.integers(min_value=0, max_value=len(document) - 1))
    document[index] ^= data.draw(st.integers(min_value=1, max_value=255))

    result = BinaryXmlService().decode(BytesIO(bytes(document)))

    assert result.status in {BinaryXmlStatus.SUCCESS, BinaryXmlStatus.FAILED}
    if result.status is BinaryXmlStatus.FAILED:
        assert result.code in {
            BinaryXmlCode.INVALID,
            BinaryXmlCode.LIMIT_EXCEEDED,
            BinaryXmlCode.OUTPUT_TOO_LARGE,
        }
    else:
        assert result.code is BinaryXmlCode.DECODED


@pytest.mark.parametrize(
    "kwargs",
    [
        {"maximum_input_bytes": 0},
        {"maximum_output_bytes": 0},
        {"maximum_strings": 0},
        {"maximum_elements": 0},
        {"maximum_depth": 0},
    ],
)
def test_invalid_limits_are_rejected(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        BinaryXmlLimits(**kwargs)


def test_command_engine_decodes_a_bound_file_and_registers_only_public_data() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "manifest.axml"
        source.write_bytes(_binary_xml())
        grants = PathGrantStore()
        issued = grants.issue_file(source, purpose="tools.xml.source")
        bound = grants.resolve_bound_file(issued.token, purpose="tools.xml.source")
        store = AppStateStore(AppSnapshot(revision=0))
        engine = make_test_command_engine(store=store)

        result = engine.execute(
            AppCommand(
                "tools.xml",
                expected_revision=0,
                operation_id="xml-command",
                payload={"action": "decodeBinary", "source": bound},
            )
        )

        assert result.ok
        assert result.code == "binary_xml_decoded"
        assert result.value is not None
        assert result.value["format"] == "android-binary-xml"
        assert result.value["bounded"] is True
        assert str(source) not in repr(result.to_dict())
        completed = store.snapshot()
        assert completed.revision == 2
        assert completed.active_operation is None
        assert completed.last_result == result


def test_command_engine_rejects_raw_paths_and_target_serials() -> None:
    engine = make_test_command_engine()
    raw = engine.execute(
        AppCommand(
            "tools.xml",
            expected_revision=0,
            payload={"action": "decodeBinary", "source": "C:/private/manifest.axml"},
        )
    )
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "manifest.axml"
        source.write_bytes(_binary_xml())
        grants = PathGrantStore()
        issued = grants.issue_file(source, purpose="tools.xml.source")
        targeted = engine.execute(
            AppCommand(
                "tools.xml",
                expected_revision=0,
                target_serial="SERIAL",
                payload={
                    "action": "decodeBinary",
                    "source": grants.resolve_bound_file(
                        issued.token, purpose="tools.xml.source"
                    ),
                },
            )
        )

    assert raw.code == "binary_xml_payload_invalid"
    assert targeted.code == "xml_target_not_allowed"
