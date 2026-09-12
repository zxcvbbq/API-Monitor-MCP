"""MCP bridge for the real Rohitab API Monitor application."""

from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import io
import math
import json
import mmap
import os
import re
import subprocess
import struct
import sys
import time
import uuid
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from xml.etree import ElementTree

from mcp.server.fastmcp import FastMCP


DEFAULT_APP_ROOT = Path(r"C:\Program Files\rohitab.com\API Monitor")
CAPTURE_SUFFIXES = {".apmx64", ".apmx86"}
COMMAND_OPEN_CAPTURE = 32852
COMMAND_SAVE_CAPTURE = 32854
COMMAND_SAVE_CAPTURE_AS = 32954
COMMAND_MONITOR_NEW_PROCESS = 32884
COMMAND_START_MONITORING = 32882
COMMAND_STOP_MONITORING = 32929
COMMAND_REMOVE_PROCESS = 32919
COMMAND_TERMINATE_PROCESS = 32924
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
API_NAME = re.compile(r'<Api\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)
MODULE_NAME = re.compile(r'<Module\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)
PROCESS_INFO = re.compile(r"process/(\d+)/info$", re.I)
SUMMARY_TEXT = re.compile(
    r"Summary\s*\|\s*([\d,]+)\s*calls\s*\|\s*([^|]+?)\s*\|\s*(.*)", re.I
)
MODULE_EVENT = re.compile(
    r"^(?P<process>[^:]+): Monitoring Module (?P<address>0x[0-9a-f]+) -> (?P<module>.+)$",
    re.I,
)
CHILD_EVENT = re.compile(
    r"^(?P<process>[^:]+): Monitoring Child Process - PID: (?P<pid>\d+) \| Attach: (?P<attach>.+)$",
    re.I,
)

mcp = FastMCP(
    "rohitab-api-monitor",
    instructions=(
        "Read Rohitab API Monitor .apmx captures, search their raw contents, "
        "launch the installed API Monitor application, and automate its GUI "
        "without bringing it to the foreground, including native API/filter trees. Decode saved call streams "
        "when their process call/data entries are present."
    ),
)


def _capture_path(file_path: str) -> Path:
    path = Path(file_path).expanduser()
    if path.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("file_path must end in .apmx64 or .apmx86")
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")
    return path.resolve()


def _capture_directory(directory: str) -> Path:
    path = Path(directory).expanduser()
    if not path.is_dir():
        raise NotADirectoryError(f"Capture directory not found: {path}")
    return path.resolve()


def _capture_output_path(output_path: str, architecture: str) -> Path:
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    path = Path(output_path).expanduser()
    expected_suffix = f".apm{architecture}"
    if path.suffix.lower() != expected_suffix:
        raise ValueError(f"output_path must end in {expected_suffix}")
    if not path.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {path.parent}")
    return path.resolve()


def _limit(value: int, name: str, maximum: int) -> int:
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _zip_offset(data: bytes) -> int | None:
    offsets = [data.find(signature) for signature in ZIP_SIGNATURES]
    offsets = [offset for offset in offsets if offset >= 0]
    return min(offsets) if offsets else None


def _capture_zip_offset(path: Path) -> int | None:
    tail = b""
    consumed = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            window = tail + chunk
            offset = _zip_offset(window)
            if offset is not None:
                return consumed - len(tail) + offset
            consumed += len(chunk)
            tail = window[-3:]
    return None


class _CaptureZipReader(io.RawIOBase):
    def __init__(self, path: Path, offset: int):
        self._handle = path.open("rb")
        self._offset = offset
        self._size = path.stat().st_size - offset
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self._position
        elif whence == io.SEEK_END:
            offset += self._size
        elif whence != io.SEEK_SET:
            raise ValueError(f"unsupported seek mode: {whence}")
        if offset < 0:
            raise ValueError("negative seek position")
        self._position = offset
        return offset

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._size - self._position
        size = min(size, max(0, self._size - self._position))
        if not size:
            return b""
        self._handle.seek(self._offset + self._position)
        data = self._handle.read(size)
        self._position += len(data)
        return data

    def close(self) -> None:
        if not self.closed:
            self._handle.close()
        super().close()


class _CaptureZipFile(zipfile.ZipFile):
    def __init__(self, path: Path, offset: int):
        self._capture_reader = _CaptureZipReader(path, offset)
        try:
            super().__init__(self._capture_reader)
        except Exception:
            self._capture_reader.close()
            raise

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._capture_reader.close()


def _open_capture_zip(path: Path) -> tuple[zipfile.ZipFile, bytes, int]:
    offset = _capture_zip_offset(path)
    if offset is None:
        raise ValueError("Capture does not contain a ZIP container")
    with path.open("rb") as handle:
        prefix = handle.read(offset)
    return _CaptureZipFile(path, offset), prefix, offset


def _zip_entries(path: Path) -> list[dict[str, Any]]:
    with_zip, _, _ = _open_capture_zip(path)
    with with_zip as archive:
        return [
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "crc32": f"0x{info.CRC:08x}",
                "is_dir": info.is_dir(),
            }
            for info in archive.infolist()
        ]


def _file_time(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()


def _capture_info(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    offset = _zip_offset(data)
    result: dict[str, Any] = {
        "file": str(path),
        "extension": path.suffix.lower(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "modified_utc": _file_time(path),
        "zip_offset": offset,
        "container": "zip-with-prefix" if offset is not None and offset else "zip",
    }
    if offset is None:
        result["zip_error"] = "No ZIP signature found"
        result["entries"] = []
        return result
    prefix = data[:offset]
    result["prefix_size"] = offset
    result["format_marker"] = "RBAPM" if prefix.endswith(b"RBAPM") else None
    result["format_header"] = prefix.decode("ascii", errors="replace").rstrip("\x00")
    result["architecture"] = (
        "x64"
        if b"64-bit Capture" in prefix
        else "x86"
        if b"32-bit Capture" in prefix
        else "x64"
        if path.suffix.lower() == ".apmx64"
        else "x86"
    )
    try:
        result["entries"] = _zip_entries(path)
        archive, _, _ = _open_capture_zip(path)
        with archive:
            if "info" in archive.namelist():
                result["metadata"] = _parse_capture_info(archive.read("info"))
    except zipfile.BadZipFile as exc:
        result["zip_error"] = str(exc)
        result["entries"] = []
    return result


def _parse_capture_info(data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        raise ValueError("Capture info entry is too small")
    version, title_length = struct.unpack_from("<II", data)
    title_end = 8 + title_length * 2
    if title_end + 28 > len(data):
        raise ValueError("Capture info entry has an invalid title length")
    title = data[8:title_end].decode("utf-16-le", errors="replace").rstrip("\x00")
    values = struct.unpack_from("<7I", data, title_end)
    checksum = struct.unpack_from("<I", data, len(data) - 4)[0] if len(data) >= 4 else None
    return {
        "version": version,
        "title_length": title_length,
        "application": title,
        "bitness": values[0],
        "fields": list(values[1:6]),
        "locale_id": values[6],
        "crc32": f"0x{checksum:08x}" if checksum is not None else None,
        "crc32_valid": checksum == zlib.crc32(data[:-4]) & 0xFFFFFFFF if checksum is not None else False,
    }


def _windows_filetime(value: int) -> str | None:
    if not value:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        return None


def _parse_capture_process_info(data: bytes, pointer_size: int = 8) -> dict[str, Any]:
    if pointer_size == 4:
        if len(data) < 16:
            raise ValueError("32-bit process info entry is too small")
        version, capture_index, pid, image_base = struct.unpack_from("<IIII", data)
        payload_end = len(data) - 4 if len(data) >= 20 else len(data)
        result: dict[str, Any] = {
            "architecture": "x86",
            "format_version": version,
            "capture_index": capture_index,
            "pid": pid,
            "image_base": f"0x{image_base:x}",
        }
        if payload_end < len(data):
            checksum = struct.unpack_from("<I", data, payload_end)[0]
            result["crc32"] = f"0x{checksum:08x}"
            result["crc32_valid"] = checksum == zlib.crc32(data[:payload_end]) & 0xFFFFFFFF
        if payload_end <= 16:
            result["format_note"] = "32-bit process metadata contains only its header"
            return result
        position = 16

        def read_dword(name: str) -> int:
            nonlocal position
            if position + 4 > payload_end:
                raise ValueError(f"32-bit process info is missing {name}")
            value = struct.unpack_from("<I", data, position)[0]
            position += 4
            return value

        def read_utf16(name: str) -> str:
            nonlocal position
            char_count = read_dword(f"{name} length")
            byte_count = char_count * 2
            if byte_count > payload_end - position:
                raise ValueError(f"32-bit process info {name} exceeds entry bounds")
            value = data[position : position + byte_count].decode(
                "utf-16-le", errors="replace"
            )
            position += byte_count
            return value

        def read_bytes(name: str) -> bytes:
            nonlocal position
            length = read_dword(f"{name} length")
            if length > payload_end - position:
                raise ValueError(f"32-bit process info {name} exceeds entry bounds")
            value = data[position : position + length]
            position += length
            return value

        result["image_path"] = read_utf16("image_path")
        result["command_line"] = read_utf16("command_line")
        result["description"] = read_utf16("description")
        result["call_start_index"] = read_dword("call start index")
        start_time = read_dword("start time low") | read_dword("start time high") << 32
        end_time = read_dword("end time low") | read_dword("end time high") << 32
        result.update(
            {
                "start_time_filetime": start_time,
                "end_time_filetime": end_time,
                "start_time_utc": _windows_filetime(start_time),
                "end_time_utc": _windows_filetime(end_time),
                "module_record_count": read_dword("module record count"),
            }
        )
        module_records = []
        for index in range(result["module_record_count"]):
            field0 = read_dword(f"module record {index} field0")
            ansi = read_bytes(f"module record {index} ANSI text")
            field1 = read_dword(f"module record {index} field1")
            field2 = read_dword(f"module record {index} field2")
            path = read_utf16(f"module record {index} path")
            pair = read_dword(f"module record {index} pair low") | read_dword(
                f"module record {index} pair high"
            ) << 32
            module_records.append(
                {
                    "index": index,
                    "fields": [field0, field1, field2],
                    "ansi_text": ansi.decode("cp1252", errors="replace"),
                    "ansi_bytes": _read_payload(ansi),
                    "path": path,
                    "qwords": [pair],
                }
            )
        result["module_records"] = module_records
        result["loaded_module_count"] = read_dword("loaded module count")
        result["loaded_modules"] = [
            {
                "index": index,
                "field": read_dword(f"loaded module {index} field"),
                "path": read_utf16(f"loaded module {index} path"),
            }
            for index in range(result["loaded_module_count"])
        ]
        return result
    if len(data) < 24:
        raise ValueError("Process info entry is too small")
    payload_end = len(data) - 4
    checksum = struct.unpack_from("<I", data, payload_end)[0]
    result: dict[str, Any] = {
        "format_version": struct.unpack_from("<I", data)[0],
        "capture_index": struct.unpack_from("<I", data, 4)[0],
        "pid": struct.unpack_from("<I", data, 8)[0],
        "image_base": f"0x{struct.unpack_from('<Q', data, 12)[0]:x}",
        "crc32": f"0x{checksum:08x}",
        "crc32_valid": checksum == zlib.crc32(data[:payload_end]) & 0xFFFFFFFF,
    }
    position = 20

    def read_utf16(name: str) -> str:
        nonlocal position
        if position + 4 > payload_end:
            raise ValueError(f"Process info is missing {name} length")
        char_count = struct.unpack_from("<I", data, position)[0]
        position += 4
        byte_count = char_count * 2
        if byte_count > payload_end - position:
            raise ValueError(f"Process info {name} exceeds entry bounds")
        value = data[position : position + byte_count].decode("utf-16-le", errors="replace")
        position += byte_count
        return value

    for name in ("image_path", "command_line", "description"):
        result[name] = read_utf16(name)
    if position + 24 > payload_end:
        return result
    result["call_start_index"], start_time, end_time = struct.unpack_from("<IQQ", data, position)
    position += 20
    result["start_time_filetime"] = start_time
    result["end_time_filetime"] = end_time
    result["start_time_utc"] = _windows_filetime(start_time)
    result["end_time_utc"] = _windows_filetime(end_time)
    result["module_record_count"] = struct.unpack_from("<I", data, position)[0]
    position += 4
    module_records = []
    for index in range(result["module_record_count"]):
        if position + 24 > payload_end:
            raise ValueError(f"Process info module record {index} exceeds entry bounds")
        field0, field1, field2 = struct.unpack_from("<III", data, position)
        position += 12
        qword0 = struct.unpack_from("<Q", data, position)[0]
        position += 8
        raw_length = struct.unpack_from("<I", data, position)[0]
        position += 4
        if raw_length > payload_end - position:
            raise ValueError(f"Process info module record {index} has invalid raw length")
        position += raw_length
        if position + 16 > payload_end:
            raise ValueError(f"Process info module record {index} is truncated")
        qword1, qword2 = struct.unpack_from("<QQ", data, position)
        position += 16
        path = read_utf16(f"module record {index} path")
        if position + 8 > payload_end:
            raise ValueError(f"Process info module record {index} is missing its final field")
        qword3 = struct.unpack_from("<Q", data, position)[0]
        position += 8
        module_records.append(
            {
                "index": index,
                "fields": [field0, field1, field2],
                "qwords": [qword0, qword1, qword2, qword3],
                "raw_bytes": raw_length,
                "path": path,
            }
        )
    result["module_records"] = module_records
    if position + 4 > payload_end:
        return result
    loaded_module_count = struct.unpack_from("<I", data, position)[0]
    position += 4
    result["loaded_module_count"] = loaded_module_count
    loaded_modules = []
    for index in range(loaded_module_count):
        if position + 16 > payload_end:
            raise ValueError(f"Process info loaded module {index} exceeds entry bounds")
        field0 = struct.unpack_from("<I", data, position)[0]
        position += 4
        base = struct.unpack_from("<Q", data, position)[0]
        position += 8
        path = read_utf16(f"loaded module {index} path")
        loaded_modules.append(
            {"index": index, "field": field0, "base": f"0x{base:x}", "path": path}
        )
    result["loaded_modules"] = loaded_modules
    return result


def _capture_layout(pointer_size: int) -> dict[str, Any]:
    if pointer_size == 4:
        return {
            "minimum_record_size": 112,
            "full_record_size": 120,
            "offset_format": "<I",
            "pointer_refs": (
                (0, 96, 32),
                (1, 100, 72),
                (2, 104, 76),
                (3, 108, 92),
                (4, 116, 112),
            ),
        }
    if pointer_size == 8:
        return {
            "minimum_record_size": 144,
            "full_record_size": 160,
            "offset_format": "<Q",
            "pointer_refs": (
                (0, 112, 32),
                (1, 120, 88),
                (2, 128, 92),
                (3, 136, 108),
                (4, 152, 144),
            ),
        }
    raise ValueError("pointer_size must be 4 or 8")


def _capture_record_size(
    offsets: list[int], index: int, data: bytes, pointer_size: int = 8
) -> int:
    layout = _capture_layout(pointer_size)
    offset = offsets[index]
    next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
    minimum = layout["minimum_record_size"]
    full = layout["full_record_size"]
    return next_offset - offset if minimum <= next_offset - offset <= full else full if data[offset + 2] else minimum


def _capture_call_context(data: bytes, offset: int, pointer_size: int = 8) -> dict[str, Any]:
    if pointer_size == 8:
        module_base_offset, timestamp_offset, duration_offset, error_offset = 48, 72, 96, 84
    else:
        module_base_offset, timestamp_offset, duration_offset, error_offset = 40, 56, 80, 68
    context: dict[str, Any] = {
        "thread_id": struct.unpack_from("<I", data, offset + 16)[0],
        "thread_number": struct.unpack_from("<I", data, offset + 20)[0],
        "module_base": f"0x{int.from_bytes(data[offset + module_base_offset : offset + module_base_offset + pointer_size], 'little'):0{pointer_size * 2}x}",
        "error_code": struct.unpack_from("<I", data, offset + error_offset)[0],
    }
    timestamp = int.from_bytes(
        data[offset + timestamp_offset : offset + timestamp_offset + 8], "little"
    )
    context["timestamp_filetime"] = timestamp
    context["timestamp_utc"] = _windows_filetime(timestamp)
    duration_valid = bool(data[offset])
    context["duration_valid"] = duration_valid
    if duration_valid:
        context["duration_seconds"] = struct.unpack_from(
            "<d", data, offset + duration_offset
        )[0]
    return context


def _capture_relative_text(data: bytes, relative: int) -> str | None:
    if relative <= 0 or relative >= len(data):
        return None
    end = data.find(b"\x00", relative)
    if end < 0:
        return None
    text = data[relative:end].decode("ascii", errors="replace")
    return text if text and all(char.isprintable() for char in text) else None


def _capture_type_info(
    definitions: bytes,
    relative: int,
    pointer_size: int = 8,
    _depth: int = 0,
) -> dict[str, Any] | None:
    type_size = 24 if pointer_size == 4 else 48
    if relative <= 0 or relative > len(definitions) - type_size:
        return None
    pointer_format = "<I" if pointer_size == 4 else "<Q"
    name_offset = struct.unpack_from(pointer_format, definitions, relative)[0]
    alias_offset = struct.unpack_from(pointer_format, definitions, relative + pointer_size * 2)[0]
    type_info: dict[str, Any] = {
        "offset": relative,
        "kind": struct.unpack_from("<I", definitions, relative + pointer_size)[0],
        "size": definitions[relative + pointer_size * 4],
        "flags": definitions[relative + pointer_size * 4 + 1],
        "pointer_size": pointer_size,
    }
    for key, offset in (
        ("name_offset", name_offset),
        ("alias_offset", alias_offset),
    ):
        text = _capture_relative_text(definitions, offset)
        if text:
            type_info[key] = offset
            type_info[key[:-7]] = text
    if type_info["kind"] == 11:
        size_field = relative + (40 if pointer_size == 8 else 20)
        if size_field + 2 <= len(definitions):
            structure_size = struct.unpack_from("<H", definitions, size_field)[0]
            if structure_size:
                type_info["structure_size"] = structure_size
            if pointer_size == 8 and size_field + 4 <= len(definitions):
                alternate_size = struct.unpack_from("<H", definitions, size_field + 2)[0]
                if alternate_size:
                    type_info["structure_size_flagged"] = alternate_size
        alignment_field = relative + (45 if pointer_size == 8 else 25)
        flags_field = relative + (46 if pointer_size == 8 else 26)
        if flags_field < len(definitions):
            type_info["alignment"] = definitions[alignment_field]
            type_info["struct_flags"] = definitions[flags_field]
    if type_info["kind"] == 14:
        element_field = relative + (32 if pointer_size == 8 else 16)
        count_field = relative + (40 if pointer_size == 8 else 20)
        flags_field = relative + (42 if pointer_size == 8 else 22)
        if flags_field < len(definitions):
            element_offset = struct.unpack_from(pointer_format, definitions, element_field)[0]
            array_count = struct.unpack_from("<H", definitions, count_field)[0]
            type_info.update(
                {
                    "element_type_offset": element_offset,
                    "array_count": array_count,
                    "array_flags": definitions[flags_field],
                }
            )
            if _depth < 4:
                element_type = _capture_type_info(
                    definitions, element_offset, pointer_size, _depth + 1
                )
                if element_type:
                    type_info["element_type"] = element_type
    if type_info["kind"] == 2:
        enum_field = relative + pointer_size * 3
        if enum_field + pointer_size <= len(definitions):
            enum_offset = struct.unpack_from(pointer_format, definitions, enum_field)[0]
            enum_header_size = pointer_size + 3
            if enum_offset > 0 and enum_offset + enum_header_size <= len(definitions):
                table_offset = struct.unpack_from(pointer_format, definitions, enum_offset)[0]
                enum_count = struct.unpack_from("<H", definitions, enum_offset + pointer_size)[0]
                enum_flags = definitions[enum_offset + pointer_size + 2]
                entry_size = 16
                table_end = table_offset + enum_count * entry_size
                if enum_count <= 4096 and table_offset > 0 and table_end <= len(definitions):
                    entries = []
                    for index in range(enum_count):
                        entry = table_offset + index * entry_size
                        name_offset = struct.unpack_from(pointer_format, definitions, entry)[0]
                        value = struct.unpack_from("<Q", definitions, entry + 8)[0]
                        item: dict[str, Any] = {
                            "index": index,
                            "offset": entry,
                            "name_offset": name_offset,
                            "value": value,
                        }
                        name = _capture_relative_text(definitions, name_offset)
                        if name:
                            item["name"] = name
                        entries.append(item)
                    type_info.update(
                        {
                            "enum_offset": enum_offset,
                            "enum_table_offset": table_offset,
                            "enum_count": enum_count,
                            "enum_flags": enum_flags,
                            "enum_entries": entries,
                        }
                    )
    if type_info["kind"] == 11 and _depth < 4:
        table_field = relative + pointer_size * 4
        count_field = relative + (44 if pointer_size == 8 else 24)
        if count_field < len(definitions) and table_field + pointer_size <= len(definitions):
            field_table = struct.unpack_from(pointer_format, definitions, table_field)[0]
            field_count = definitions[count_field]
            descriptor_size = 12 if pointer_size == 4 else 24
            table_end = field_table + field_count * descriptor_size
            if field_count <= 256 and field_table > 0 and table_end <= len(definitions):
                fields = []
                for index in range(field_count):
                    descriptor = field_table + index * descriptor_size
                    field_name_offset = struct.unpack_from(
                        pointer_format, definitions, descriptor
                    )[0]
                    field_type_offset = struct.unpack_from(
                        pointer_format, definitions, descriptor + pointer_size
                    )[0]
                    field: dict[str, Any] = {
                        "index": index,
                        "offset": descriptor,
                        "name_offset": field_name_offset,
                        "type_offset": field_type_offset,
                        "flags": struct.unpack_from(
                            "<H", definitions, descriptor + pointer_size * 2
                        )[0],
                    }
                    field_name = _capture_relative_text(definitions, field_name_offset)
                    if field_name:
                        field["name"] = field_name
                    field_type = _capture_type_info(
                        definitions, field_type_offset, pointer_size, _depth + 1
                    )
                    if field_type:
                        field["type"] = field_type
                    fields.append(field)
                type_info.update(
                    {
                        "field_table_offset": field_table,
                        "field_count": field_count,
                        "fields": fields,
                    }
                )
    return type_info


def _capture_definition_info(
    definitions: bytes, relative: int, pointer_size: int = 8
) -> dict[str, Any]:
    pointer_format = "<I" if pointer_size == 4 else "<Q"
    node_size = 44 if pointer_size == 4 else 64
    parameter_table_field = 28 if pointer_size == 4 else 32
    module_field = 32 if pointer_size == 4 else 40
    return_field = 40 if pointer_size == 4 else 56
    result: dict[str, Any] = {"offset": relative, "valid": False}
    if relative < 0 or relative > len(definitions) - node_size:
        result["error"] = "definition offset is outside definitions entry"
        return result
    flags = definitions[relative]
    ordinal = struct.unpack_from("<I", definitions, relative + 8)[0]
    name_relative = struct.unpack_from("<Q" if pointer_size == 8 else "<I", definitions, relative + 24)[0]
    module_relative = struct.unpack_from(pointer_format, definitions, relative + module_field)[0]
    parameter_count = definitions[relative + 2]
    parameter_table_relative = struct.unpack_from(
        pointer_format, definitions, relative + parameter_table_field
    )[0]
    return_descriptor_relative = struct.unpack_from(
        pointer_format, definitions, relative + return_field
    )[0]
    result.update(
        {
            "flags": f"0x{flags:02x}",
            "ordinal": ordinal,
            "name_offset": name_relative,
            "module_offset": module_relative,
            "parameter_count": parameter_count,
            "parameter_table_offset": parameter_table_relative,
            "return_descriptor_offset": return_descriptor_relative,
            "pointer_size": pointer_size,
        }
    )
    name = _capture_relative_text(definitions, name_relative)
    if name is None:
        result["error"] = "definition name offset is outside definitions entry"
        return result
    result["name"] = name
    if module_relative:
        if module_relative > len(definitions) - 16 - pointer_size:
            result["error"] = "definition module offset is outside definitions entry"
            return result
        module_name_relative = struct.unpack_from(
            pointer_format, definitions, module_relative + 16
        )[0]
        module = _capture_relative_text(definitions, module_name_relative)
        if module is None:
            result["error"] = "definition module name is not printable"
            return result
        result["module"] = module
        result["module_name_offset"] = module_name_relative
    if parameter_count and parameter_table_relative < len(definitions):
        descriptor_size = 12 if pointer_size == 4 else 24
        table_end = parameter_table_relative + parameter_count * descriptor_size
        if table_end <= len(definitions):
            parameters = []
            for index in range(parameter_count):
                descriptor = parameter_table_relative + index * descriptor_size
                name_offset = struct.unpack_from(pointer_format, definitions, descriptor)[0]
                type_offset = struct.unpack_from(
                    pointer_format, definitions, descriptor + pointer_size
                )[0]
                parameter: dict[str, Any] = {
                    "index": index,
                    "offset": descriptor,
                    "name_offset": name_offset,
                    "type_offset": type_offset,
                    "flags": struct.unpack_from(
                        "<H", definitions, descriptor + pointer_size * 2
                    )[0],
                }
                name = _capture_relative_text(definitions, name_offset)
                if name:
                    parameter["name"] = name
                type_info = _capture_type_info(definitions, type_offset, pointer_size)
                if type_info:
                    parameter["type"] = type_info
                parameters.append(parameter)
            result["parameters"] = parameters
        else:
            result["parameter_error"] = "parameter table exceeds definitions entry"
    if return_descriptor_relative and return_descriptor_relative <= len(definitions) - pointer_size:
        return_type_relative = struct.unpack_from(
            pointer_format, definitions, return_descriptor_relative
        )[0]
        result["return_type_offset"] = return_type_relative
        return_type = _capture_type_info(definitions, return_type_relative, pointer_size)
        if return_type:
            result["return_type"] = return_type
    result["valid"] = True
    return result


def _capture_call_records(
    calls: bytes,
    data: bytes,
    limit: int,
    include_data: bool,
    max_data_bytes: int,
    start_index: int = 0,
    definitions: bytes | None = None,
    pointer_size: int = 8,
) -> list[dict[str, Any]]:
    layout = _capture_layout(pointer_size)
    if len(calls) % pointer_size:
        raise ValueError(f"process calls entry is not an array of {pointer_size * 8}-bit offsets")
    offset_format = layout["offset_format"]
    offsets = [
        struct.unpack_from(offset_format, calls, index)[0]
        for index in range(0, len(calls), pointer_size)
    ]
    minimum = layout["minimum_record_size"]
    records: list[dict[str, Any]] = []
    for index, offset in enumerate(offsets[start_index : start_index + limit], start=start_index):
        if offset > len(data) - minimum:
            records.append({"index": index, "offset": offset, "valid": False, "error": "record offset is outside process data"})
            continue
        record_size = _capture_record_size(offsets, index, data, pointer_size)
        record = {
            "index": index,
            "offset": offset,
            "size": record_size,
            "valid": offset + record_size <= len(data),
            "flags": data[offset + 2],
            "header_hex": data[offset : offset + min(record_size, 112)].hex(" "),
            "data_refs": [],
        }
        definition_offset = struct.unpack_from(
            offset_format, data, offset + (40 if pointer_size == 8 else 36)
        )[0]
        record["definition_offset"] = definition_offset
        if definitions is not None:
            record["definition"] = _capture_definition_info(
                definitions, definition_offset, pointer_size
            )
        if not record["valid"]:
            record["error"] = "record extends beyond process data"
            records.append(record)
            continue
        record["context"] = _capture_call_context(data, offset, pointer_size)
        for slot, pointer_offset, length_offset in layout["pointer_refs"]:
            if pointer_offset + pointer_size > record_size or length_offset + 4 > record_size:
                continue
            relative = struct.unpack_from(
                offset_format, data, offset + pointer_offset
            )[0]
            length = struct.unpack_from("<I", data, offset + length_offset)[0]
            reference: dict[str, Any] = {"slot": slot, "offset": relative, "length": length}
            end = relative + length
            if end > len(data):
                reference["valid"] = False
                reference["error"] = "data reference is outside process data"
            else:
                reference["valid"] = True
                if include_data and length <= max_data_bytes:
                    reference["payload"] = _read_payload(data[relative:end])
                elif include_data:
                    reference["truncated"] = True
            record["data_refs"].append(reference)
        records.append(record)
    return records


def _capture_call_stats(
    calls: bytes, data: bytes, max_records: int, pointer_size: int = 8
) -> dict[str, Any]:
    layout = _capture_layout(pointer_size)
    if len(calls) % pointer_size:
        raise ValueError(f"process calls entry is not an array of {pointer_size * 8}-bit offsets")
    offset_format = layout["offset_format"]
    offsets = [
        struct.unpack_from(offset_format, calls, index)[0]
        for index in range(0, len(calls), pointer_size)
    ]
    scanned = min(len(offsets), max_records)
    stats: dict[str, Any] = {
        "count": len(offsets),
        "scanned_records": scanned,
        "truncated": scanned < len(offsets),
        "valid_records": 0,
        "invalid_records": 0,
        "record_sizes": {
            str(layout["minimum_record_size"]): 0,
            str(layout["full_record_size"]): 0,
            "other": 0,
        },
        "flags": {},
        "payload_slots": {
            str(slot): {"references": 0, "bytes": 0, "invalid_references": 0}
            for slot in range(5)
        },
        "data_bytes": len(data),
        "referenced_data_bytes": 0,
    }
    thread_ids: set[int] = set()
    timestamps: list[int] = []
    durations: list[float] = []
    error_codes: dict[str, int] = {}
    error_codes_truncated = False
    error_count = 0
    for index, offset in enumerate(offsets[:scanned]):
        if offset > len(data) - layout["minimum_record_size"]:
            stats["invalid_records"] += 1
            continue
        stats["valid_records"] += 1
        record_size = _capture_record_size(offsets, index, data, pointer_size)
        if offset + record_size > len(data):
            stats["valid_records"] -= 1
            stats["invalid_records"] += 1
            continue
        size_key = (
            str(record_size)
            if record_size in (layout["minimum_record_size"], layout["full_record_size"])
            else "other"
        )
        stats["record_sizes"][size_key] += 1
        flags = data[offset + 2]
        flag_key = f"0x{flags:02x}"
        stats["flags"][flag_key] = stats["flags"].get(flag_key, 0) + 1
        context = _capture_call_context(data, offset, pointer_size)
        thread_ids.add(context["thread_id"])
        error_code = context["error_code"]
        if error_code:
            error_count += 1
            error_key = f"0x{error_code:08x}"
            if error_key in error_codes or len(error_codes) < 256:
                error_codes[error_key] = error_codes.get(error_key, 0) + 1
            else:
                error_codes_truncated = True
        if context["timestamp_filetime"]:
            timestamps.append(context["timestamp_filetime"])
        if context.get("duration_valid"):
            durations.append(context["duration_seconds"])
        for slot, pointer_offset, length_offset in layout["pointer_refs"]:
            if pointer_offset + pointer_size > record_size or length_offset + 4 > record_size:
                continue
            relative = struct.unpack_from(
                offset_format, data, offset + pointer_offset
            )[0]
            length = struct.unpack_from("<I", data, offset + length_offset)[0]
            reference_stats = stats["payload_slots"][str(slot)]
            if not relative and not length:
                continue
            if relative + length > len(data):
                reference_stats["invalid_references"] += 1
                continue
            reference_stats["references"] += 1
            reference_stats["bytes"] += length
            stats["referenced_data_bytes"] += length
    context_stats: dict[str, Any] = {
        "thread_count": len(thread_ids),
        "duration_count": len(durations),
        "error_count": error_count,
        "error_codes": error_codes,
        "error_codes_truncated": error_codes_truncated,
        "first_timestamp_utc": _windows_filetime(min(timestamps)) if timestamps else None,
        "last_timestamp_utc": _windows_filetime(max(timestamps)) if timestamps else None,
    }
    if durations:
        context_stats["duration_seconds"] = {
            "minimum": min(durations),
            "maximum": max(durations),
            "average": sum(durations) / len(durations),
        }
    stats["context"] = context_stats
    stats["unreferenced_data_bytes"] = max(0, len(data) - stats["referenced_data_bytes"])
    return stats


def _scan_strings(data: bytes | mmap.mmap, query: str, limit: int, minimum: int) -> list[dict[str, Any]]:
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}")
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(minimum).encode() + rb",}")
    needle = query.casefold()
    matches: list[dict[str, Any]] = []

    for pattern, encoding in ((ascii_pattern, "ascii"), (utf16_pattern, "utf-16-le")):
        for match in pattern.finditer(data):
            text = match.group().decode(encoding, errors="replace").rstrip("\x00")
            if needle and needle not in text.casefold():
                continue
            matches.append({"offset": match.start(), "encoding": encoding, "text": text})

    matches.sort(key=lambda item: (item["offset"], item["encoding"]))
    unique: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for item in matches:
        key = (item["offset"], item["text"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
        if len(unique) >= limit:
            break
    return unique


def _monitoring_event(line: str) -> dict[str, Any]:
    if match := MODULE_EVENT.fullmatch(line):
        event = {"type": "module", **match.groupdict()}
        event["module"] = event["module"].rstrip(".")
        return event
    if match := CHILD_EVENT.fullmatch(line):
        event = {"type": "child_process", **match.groupdict()}
        event["pid"] = int(event["pid"])
        return event
    return {"type": "unknown"}


def _capture_strings(path: Path, query: str, limit: int, minimum: int) -> list[dict[str, Any]]:
    with path.open("rb") as handle:
        if path.stat().st_size == 0:
            return []
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return _scan_strings(data, query, limit, minimum)


def _app_root(root: str | None = None) -> Path:
    candidates = [Path(root).expanduser()] if root else []
    env_root = os.environ.get("APIMONITOR_HOME")
    if env_root:
        candidates.append(Path(env_root).expanduser())
    candidates.append(DEFAULT_APP_ROOT)

    if sys.platform == "win32":
        try:
            import winreg

            keys = (
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            )
            for hive, key_path in keys:
                with winreg.OpenKey(hive, key_path) as uninstall:
                    for index in range(winreg.QueryInfoKey(uninstall)[0]):
                        with winreg.OpenKey(uninstall, winreg.EnumKey(uninstall, index)) as key:
                            name = winreg.QueryValueEx(key, "DisplayName")[0]
                            if "api monitor" not in str(name).casefold():
                                continue
                            location = winreg.QueryValueEx(key, "InstallLocation")[0]
                            if location:
                                candidates.append(Path(location))
        except (FileNotFoundError, OSError):
            pass

    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise FileNotFoundError("Rohitab API Monitor installation was not found")


def _app_executable(root: Path, architecture: str) -> Path:
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    executable = root / f"apimonitor-{architecture}.exe"
    if not executable.is_file():
        raise FileNotFoundError(f"API Monitor executable not found: {executable}")
    return executable


def _window_text(user32: Any, handle: Any) -> str:
    length = user32.GetWindowTextLengthW(handle)
    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(handle, buffer, length + 1)
    return buffer.value


def _window_class(user32: Any, handle: Any) -> str:
    buffer = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(handle, buffer, len(buffer))
    return buffer.value


def _window_rectangle(user32: Any, handle: Any) -> dict[str, int]:
    from ctypes import wintypes

    rect = wintypes.RECT()
    if not user32.GetWindowRect(handle, ctypes.byref(rect)):
        return {}
    return {"left": rect.left, "top": rect.top, "right": rect.right, "bottom": rect.bottom}


def _ui_window(handle: Any, user32: Any) -> dict[str, Any]:
    return {
        "handle": int(handle),
        "class": _window_class(user32, handle),
        "title": _window_text(user32, handle),
        "control_id": int(user32.GetDlgCtrlID(handle)),
        "rectangle": _window_rectangle(user32, handle),
        "visible": bool(user32.IsWindowVisible(handle)),
        "enabled": bool(user32.IsWindowEnabled(handle)),
    }


def _find_api_monitor_windows() -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return []
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_windows = user32.EnumWindows
    enum_windows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM), wintypes.LPARAM]
    enum_windows.restype = ctypes.c_bool
    get_pid = user32.GetWindowThreadProcessId
    get_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    get_pid.restype = wintypes.DWORD
    enum_children = user32.EnumChildWindows
    enum_children.argtypes = [
        wintypes.HWND,
        ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM),
        wintypes.LPARAM,
    ]
    enum_children.restype = ctypes.c_bool

    api_monitor_pids = {
        int(process["pid"])
        for process in api_monitor_status().get("processes", [])
        if isinstance(process.get("pid"), int)
    }
    windows: list[dict[str, Any]] = []
    child_callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    window_callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def add_children(window: dict[str, Any]) -> None:
        children: list[dict[str, Any]] = []

        @child_callback_type
        def child_callback(handle: Any, _param: Any) -> bool:
            child = _ui_window(handle, user32)
            if child["title"] or child["class"]:
                children.append(child)
            return True

        enum_children(window["handle"], child_callback, 0)
        window["children"] = children

    @window_callback_type
    def window_callback(handle: Any, _param: Any) -> bool:
        title = _window_text(user32, handle)
        process_id = wintypes.DWORD()
        get_pid(handle, ctypes.byref(process_id))
        if process_id.value not in api_monitor_pids:
            return True
        window = _ui_window(handle, user32)
        window["pid"] = int(process_id.value)
        add_children(window)
        windows.append(window)
        return True

    enum_windows(window_callback, 0)
    return windows


def _find_control(windows: list[dict[str, Any]], control_id: int) -> dict[str, Any] | None:
    for window in windows:
        for child in window.get("children", []):
            if child.get("control_id") == control_id:
                return child
    return None


def _find_ui_control(
    windows: list[dict[str, Any]],
    control_id: int | None,
    title: str,
    class_name: str,
    window_title: str,
    handle: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for window in windows:
        if window_title and window.get("title") != window_title:
            continue
        for child in window.get("children", []):
            if handle is not None and child.get("handle") != handle:
                continue
            if control_id is not None and child.get("control_id") != control_id:
                continue
            if title and child.get("title") != title:
                continue
            if class_name and child.get("class") != class_name:
                continue
            matches.append((window, child))
    if len(matches) > 1:
        raise ValueError("GUI target is ambiguous; add window_title, title, or class_name")
    return matches[0] if matches else None


def _post_mouse_click_at(handle: int, x: int, y: int, button: str = "left") -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    from ctypes import wintypes

    rect = wintypes.RECT()
    if not user32.GetClientRect(handle, ctypes.byref(rect)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor control")
    if button not in {"left", "right"}:
        raise ValueError("button must be left or right")
    if not 0 <= x < rect.right or not 0 <= y < rect.bottom:
        raise ValueError("click coordinates are outside the control")
    lparam = (y << 16) | (x & 0xFFFF)
    down, up, key = (0x0201, 0x0202, 1) if button == "left" else (0x0204, 0x0205, 2)
    user32.PostMessageW(handle, down, key, lparam)
    user32.PostMessageW(handle, up, 0, lparam)


def _post_mouse_click(handle: int) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    from ctypes import wintypes

    rect = wintypes.RECT()
    if not user32.GetClientRect(handle, ctypes.byref(rect)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor control")
    _post_mouse_click_at(handle, max(0, rect.right // 2), max(0, rect.bottom // 2))


def _post_scroll(handle: int, direction: str, amount: int) -> None:
    messages = {
        "up": (0x0115, 0),
        "down": (0x0115, 1),
        "page_up": (0x0115, 2),
        "page_down": (0x0115, 3),
        "left": (0x0114, 0),
        "right": (0x0114, 1),
    }
    if direction not in messages:
        raise ValueError("direction must be up, down, page_up, page_down, left, or right")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    message, code = messages[direction]
    for _ in range(amount):
        if not user32.PostMessageW(handle, message, code, 0):
            raise OSError(ctypes.get_last_error(), "Could not scroll API Monitor control")


def _post_key(handle: int, key: str, modifiers: list[str] | None = None) -> None:
    keys = {
        "backspace": 0x08,
        "tab": 0x09,
        "enter": 0x0D,
        "escape": 0x1B,
        "space": 0x20,
        "page_up": 0x21,
        "page_down": 0x22,
        "end": 0x23,
        "home": 0x24,
        "left": 0x25,
        "up": 0x26,
        "right": 0x27,
        "down": 0x28,
        "insert": 0x2D,
        "delete": 0x2E,
    }
    modifier_keys = {"ctrl": 0x11, "shift": 0x10, "alt": 0x12}
    modifiers = modifiers or []
    if any(modifier.casefold() not in modifier_keys for modifier in modifiers):
        raise ValueError("modifiers must contain only ctrl, shift, or alt")
    if len(key) == 1:
        value = ord(key.upper())
        if not 0x20 <= value <= 0x7E:
            raise ValueError("key must be one supported named key or one ASCII character")
    else:
        value = keys.get(key.casefold())
        if value is None:
            raise ValueError("key must be one supported named key or one ASCII character")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    pressed = []
    try:
        for modifier in modifiers:
            modifier_value = modifier_keys[modifier.casefold()]
            if not user32.PostMessageW(handle, 0x0100, modifier_value, 0):  # WM_KEYDOWN
                raise OSError(ctypes.get_last_error(), "Could not send API Monitor modifier")
            pressed.append(modifier_value)
        if not user32.PostMessageW(handle, 0x0100, value, 0):  # WM_KEYDOWN
            raise OSError(ctypes.get_last_error(), "Could not send API Monitor key")
        if not user32.PostMessageW(handle, 0x0101, value, 0):  # WM_KEYUP
            raise OSError(ctypes.get_last_error(), "Could not release API Monitor key")
    finally:
        for modifier_value in reversed(pressed):
            user32.PostMessageW(handle, 0x0101, modifier_value, 0)  # WM_KEYUP


def _uia_text(control: Any) -> str:
    try:
        return control.window_text() or control.element_info.name or ""
    except (OSError, RuntimeError):
        return ""


def _uia_rect(control: Any) -> dict[str, int]:
    rect = control.rectangle()
    return {"left": rect.left, "top": rect.top, "right": rect.right, "bottom": rect.bottom}


def _post_button_click(handle: int) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    if not user32.PostMessageW(handle, 0x00F5, 0, 0):  # BM_CLICK
        raise OSError(ctypes.get_last_error(), "Could not click API Monitor control")


def _set_control_text(handle: int, text: str) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    if user32.SendMessageW(handle, 0x000C, 0, ctypes.c_wchar_p(text)) == 0:  # WM_SETTEXT
        raise OSError(ctypes.get_last_error(), "Could not set API Monitor control text")


def _set_combo_selection(handle: int, value: str) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    index = user32.SendMessageW(handle, 0x0158, -1, ctypes.c_wchar_p(value))  # CB_FINDSTRINGEXACT
    if index < 0:
        raise ValueError(f"API Monitor combo option not found: {value}")
    user32.SendMessageW(handle, 0x014E, index, 0)  # CB_SETCURSEL
    parent = user32.GetParent(handle)
    if parent:
        notification = (1 << 16) | (user32.GetDlgCtrlID(handle) & 0xFFFF)  # CBN_SELCHANGE
        user32.PostMessageW(parent, 0x0111, notification, handle)  # WM_COMMAND


def _tree_items(handle: int, limit: int, max_depth: int) -> list[dict[str, Any]]:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process_id = wintypes.DWORD()
    if not user32.GetWindowThreadProcessId(handle, ctypes.byref(process_id)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor tree")
    process = kernel32.OpenProcess(0x438, False, process_id.value)  # query/read/write/allocate
    if not process:
        error = ctypes.get_last_error()
        if error == 5:
            raise PermissionError(
                error,
                "API Monitor tree requires the MCP client to run at the same elevation level",
            )
        raise OSError(error, "Could not open API Monitor tree process")

    class TreeItem(ctypes.Structure):
        _fields_ = [
            ("mask", wintypes.UINT),
            ("hItem", wintypes.HANDLE),
            ("state", wintypes.UINT),
            ("stateMask", wintypes.UINT),
            ("pszText", wintypes.LPWSTR),
            ("cchTextMax", ctypes.c_int),
            ("iImage", ctypes.c_int),
            ("iSelectedImage", ctypes.c_int),
            ("cChildren", ctypes.c_int),
            ("lParam", wintypes.LPARAM),
        ]

    size = ctypes.sizeof(TreeItem)
    remote_item = kernel32.VirtualAllocEx(process, None, size, 0x3000, 4)
    remote_text = kernel32.VirtualAllocEx(process, None, 2048, 0x3000, 4)
    if not remote_item or not remote_text:
        if remote_item:
            kernel32.VirtualFreeEx(process, remote_item, 0, 0x8000)
        if remote_text:
            kernel32.VirtualFreeEx(process, remote_text, 0, 0x8000)
        kernel32.CloseHandle(process)
        raise OSError(ctypes.get_last_error(), "Could not allocate API Monitor tree buffer")

    def read_item(item_handle: int) -> dict[str, Any]:
        item = TreeItem(
            0x0001 | 0x0004 | 0x0008,
            item_handle,
            0,
            0xF000,
            remote_text,
            1024,
            0,
            0,
            0,
            0,
        )
        written = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            process, remote_item, ctypes.byref(item), size, ctypes.byref(written)
        ):
            raise OSError(ctypes.get_last_error(), "Could not write API Monitor tree buffer")
        if not user32.SendMessageW(handle, 0x113E, 0, remote_item):  # TVM_GETITEMW
            raise OSError(ctypes.get_last_error(), "Could not read API Monitor tree item")
        text_buffer = ctypes.create_unicode_buffer(1024)
        if not kernel32.ReadProcessMemory(
            process, text_buffer, remote_text, 2048, ctypes.byref(written)
        ):
            raise OSError(ctypes.get_last_error(), "Could not read API Monitor tree text")
        if not kernel32.ReadProcessMemory(
            process, ctypes.byref(item), remote_item, size, ctypes.byref(written)
        ):
            raise OSError(ctypes.get_last_error(), "Could not read API Monitor tree state")
        image_state = (item.state & 0xF000) >> 12
        return {
            "native_handle": int(item_handle),
            "text": text_buffer.value,
            "checked": image_state == 2,
            "state_image": image_state,
            "has_children": item.cChildren != 0,
        }

    items: list[dict[str, Any]] = []

    def visit(item_handle: int, parent_index: int, depth: int) -> None:
        if not item_handle or len(items) >= limit or depth > max_depth:
            return
        current = item_handle
        while current and len(items) < limit:
            index = len(items)
            item = read_item(current)
            item.update({"index": index, "parent_index": parent_index, "depth": depth})
            items.append(item)
            if item["has_children"] and depth < max_depth:
                child = user32.SendMessageW(handle, 0x1104, 4, current)  # TVM_GETNEXTITEM/TVGN_CHILD
                visit(int(child), index, depth + 1)
            current = user32.SendMessageW(handle, 0x1104, 1, current)  # TVGN_NEXT

    try:
        root = user32.SendMessageW(handle, 0x1104, 0, 0)  # TVGN_ROOT
        visit(int(root), -1, 0)
        return items
    finally:
        kernel32.VirtualFreeEx(process, remote_item, 0, 0x8000)
        kernel32.VirtualFreeEx(process, remote_text, 0, 0x8000)
        kernel32.CloseHandle(process)


def _set_tree_item_check(tree_handle: int, item_handle: int, checked: bool) -> None:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = wintypes.LRESULT
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process_id = wintypes.DWORD()
    if not user32.GetWindowThreadProcessId(tree_handle, ctypes.byref(process_id)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor tree")
    process = kernel32.OpenProcess(0x438, False, process_id.value)
    if not process:
        raise OSError(ctypes.get_last_error(), "Could not open API Monitor tree process")

    class TreeItem(ctypes.Structure):
        _fields_ = [
            ("mask", wintypes.UINT),
            ("hItem", wintypes.HANDLE),
            ("state", wintypes.UINT),
            ("stateMask", wintypes.UINT),
            ("pszText", wintypes.LPWSTR),
            ("cchTextMax", ctypes.c_int),
            ("iImage", ctypes.c_int),
            ("iSelectedImage", ctypes.c_int),
            ("cChildren", ctypes.c_int),
            ("lParam", wintypes.LPARAM),
        ]

    item = TreeItem(0x0008, item_handle, 2 << 12 if checked else 1 << 12, 0xF000, None, 0, 0, 0, 0, 0)
    size = ctypes.sizeof(item)
    remote_item = kernel32.VirtualAllocEx(process, None, size, 0x3000, 4)
    if not remote_item:
        kernel32.CloseHandle(process)
        raise OSError(ctypes.get_last_error(), "Could not allocate API Monitor tree buffer")
    try:
        written = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            process, remote_item, ctypes.byref(item), size, ctypes.byref(written)
        ):
            raise OSError(ctypes.get_last_error(), "Could not write API Monitor tree buffer")
        if not user32.SendMessageW(tree_handle, 0x113D, 0, remote_item):  # TVM_SETITEMW
            raise OSError(ctypes.get_last_error(), "Could not update API Monitor tree item")
    finally:
        kernel32.VirtualFreeEx(process, remote_item, 0, 0x8000)
        kernel32.CloseHandle(process)


def _wait_for_api_monitor_window(predicate: Any, timeout_seconds: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for window in _find_api_monitor_windows():
            if predicate(window):
                return window
        time.sleep(0.1)
    return None


def _post_window_command(handle: int, command_id: int) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    if not user32.PostMessageW(handle, 0x0111, command_id, 0):  # WM_COMMAND
        raise OSError(ctypes.get_last_error(), "Could not invoke API Monitor command")


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def _capture_window_png(handle: int, max_width: int, max_height: int) -> tuple[bytes, int, int]:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    rect = wintypes.RECT()
    if not user32.GetClientRect(handle, ctypes.byref(rect)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor window")
    width, height = rect.right - rect.left, rect.bottom - rect.top
    if width < 1 or height < 1:
        raise ValueError("API Monitor window has no drawable client area")
    if width > max_width or height > max_height:
        raise ValueError(f"window screenshot exceeds {max_width}x{max_height}")

    source = user32.GetDC(handle)
    memory = gdi32.CreateCompatibleDC(source)
    bitmap = gdi32.CreateCompatibleBitmap(source, width, height)
    if not source or not memory or not bitmap:
        raise OSError(ctypes.get_last_error(), "Could not allocate API Monitor screenshot")
    previous = gdi32.SelectObject(memory, bitmap)
    try:
        if not user32.PrintWindow(handle, memory, 2):  # PW_RENDERFULLCONTENT
            raise OSError(ctypes.get_last_error(), "API Monitor did not render its window")
        class BitmapInfoHeader(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD),
                ("width", wintypes.LONG),
                ("height", wintypes.LONG),
                ("planes", wintypes.WORD),
                ("bits", wintypes.WORD),
                ("compression", wintypes.DWORD),
                ("size_image", wintypes.DWORD),
                ("x_pixels_per_meter", wintypes.LONG),
                ("y_pixels_per_meter", wintypes.LONG),
                ("colors_used", wintypes.DWORD),
                ("colors_important", wintypes.DWORD),
            ]

        header = BitmapInfoHeader(ctypes.sizeof(BitmapInfoHeader), width, height, 1, 32, 0, 0, 0, 0, 0, 0)
        pixels = (ctypes.c_ubyte * (width * height * 4))()
        if not gdi32.GetDIBits(memory, bitmap, 0, height, pixels, ctypes.byref(header), 0):
            raise OSError(ctypes.get_last_error(), "Could not read API Monitor screenshot")
        raw = bytes(pixels)
    finally:
        gdi32.SelectObject(memory, previous)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory)
        user32.ReleaseDC(handle, source)

    rows = []
    for row in range(height - 1, -1, -1):
        start = row * width * 4
        pixels = raw[start : start + width * 4]
        rows.append(
            b"\x00"
            + b"".join(
                pixels[index + 2 : index + 3]
                + pixels[index + 1 : index + 2]
                + pixels[index : index + 1]
                + pixels[index + 3 : index + 4]
                for index in range(0, len(pixels), 4)
            )
        )
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += _png_chunk(b"IDAT", zlib.compress(b"".join(rows), 6))
    return png + _png_chunk(b"IEND", b""), width, height


def _api_monitor_main_window(architecture: str, timeout_seconds: float) -> dict[str, Any] | None:
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    bitness = "32-bit" if architecture == "x86" else "64-bit"
    candidates = [
        window
        for window in _find_api_monitor_windows()
        if "api monitor v2" in window["title"].casefold() and bitness in window["title"]
    ]
    main = next(
        (window for window in candidates if window["title"].casefold().startswith("monitoring")),
        candidates[0] if candidates else None,
    )
    if main is not None:
        return main
    api_monitor_launch(architecture)
    return _wait_for_api_monitor_window(
        lambda window: "api monitor v2" in window["title"].casefold()
        and bitness in window["title"],
        timeout_seconds,
    )


def _api_monitor_window_by_handle(handle: int, architecture: str) -> dict[str, Any] | None:
    if handle < 1:
        raise ValueError("window_handle must be positive")
    bitness = "32-bit" if architecture == "x86" else "64-bit"
    return next(
        (
            window
            for window in _find_api_monitor_windows()
            if window["handle"] == handle
            and "api monitor v2" in window["title"].casefold()
            and bitness in window["title"]
        ),
        None,
    )


def _run_file_dialog(
    main_window: dict[str, Any],
    command_id: int,
    dialog_title: str,
    button_titles: tuple[str, ...],
    filename_control_id: int,
    file_path: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    _post_window_command(main_window["handle"], command_id)
    dialog = _wait_for_api_monitor_window(
        lambda window: window["title"] == dialog_title, timeout_seconds
    )
    if dialog is None:
        raise TimeoutError(f"API Monitor {dialog_title} dialog did not appear")
    target = next(
        (
            child
            for child in dialog.get("children", [])
            if child.get("control_id") == filename_control_id and child.get("class") == "Edit"
        ),
        None,
    )
    if target is None:
        raise RuntimeError(f"API Monitor {dialog_title} filename field was not found")
    _set_control_text(target["handle"], str(file_path))
    button = None
    for title in button_titles:
        button = next(
            (
                child
                for child in dialog.get("children", [])
                if child.get("title") == title and child.get("class") == "Button"
            ),
            None,
        )
        if button is not None:
            break
    if button is None:
        raise RuntimeError(f"API Monitor {dialog_title} action button was not found")
    _post_button_click(button["handle"])
    return dialog


def _read_payload(data: bytes) -> dict[str, Any]:
    metadata = {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_preview": data[:256].hex(" "),
        "hex_truncated": len(data) > 256,
    }
    try:
        text = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16-le")
            encoding = "utf-16-le"
        except UnicodeDecodeError:
            text = ""
            encoding = None

    if text and "\x00" not in text and sum(
        char.isprintable() or char in "\r\n\t" for char in text
    ) / len(text) >= 0.9:
        return {**metadata, "encoding": encoding, "text": text}
    return {
        **metadata,
        "encoding": "base64",
        "base64": base64.b64encode(data).decode("ascii"),
    }


def _capture_payload_candidates(data: bytes, max_items: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "heuristic": True,
        "size": len(data),
        "strings": [],
        "integer_arrays": [],
    }
    for encoding in ("utf-8", "utf-16-le"):
        if encoding == "utf-16-le" and len(data) % 2:
            continue
        try:
            text = data.decode(encoding).rstrip("\x00")
        except UnicodeDecodeError:
            continue
        if text and "\x00" not in text and sum(
            char.isprintable() or char in "\r\n\t" for char in text
        ) / len(text) >= 0.9:
            result["strings"].append({"encoding": encoding, "text": text})
    for width, code in ((1, "B"), (2, "H"), (4, "I"), (8, "Q")):
        count = len(data) // width
        if not count or len(data) % width or count > max_items:
            continue
        values = list(struct.unpack(f"<{count}{code}", data))
        result["integer_arrays"].append(
            {
                "width": width,
                "signed": False,
                "values": values,
                "hex_values": [f"0x{value:0{width * 2}x}" for value in values],
            }
        )
        if width > 1:
            signed = list(struct.unpack(f"<{count}{code.lower()}", data))
            result["integer_arrays"].append(
                {"width": width, "signed": True, "values": signed}
            )
    return result


def _payload_bytes(payload: dict[str, Any]) -> bytes:
    if payload.get("encoding") == "base64":
        return base64.b64decode(payload["base64"])
    encoding = payload.get("encoding") or "utf-8"
    return str(payload.get("text", "")).encode(encoding)


def _capture_encoded_argument_stream(
    data: bytes,
    parameter_count: int | None = None,
    max_items: int = 256,
    max_data_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Parse API Monitor's proven slot-0 encoded-parameter table."""
    result: dict[str, Any] = {
        "format": "APMX encoded parameter stream",
        "valid": False,
        "size": len(data),
    }
    if not data:
        result["error"] = "encoded parameter stream is empty"
        return result
    captured_count = data[0]
    table_count = parameter_count if parameter_count is not None else captured_count
    result.update(
        {
            "captured_count": captured_count,
            "table_count": table_count,
            "parameter_count_source": "definition"
            if parameter_count is not None
            else "stream_header",
        }
    )
    if not 0 <= table_count <= 255:
        result["error"] = "encoded parameter table count is invalid"
        return result
    table_end = 1 + table_count * 4
    if table_end > len(data):
        result["error"] = "encoded parameter table exceeds payload"
        return result
    result["table_bytes"] = table_end
    count_mismatch = captured_count > table_count
    if count_mismatch:
        result["warning"] = "stream reports more parameters than the API definition"
    arguments = []
    available_count = min(captured_count, table_count, max_items)
    for index in range(available_count):
        offset, packed_length = struct.unpack_from("<HH", data, 1 + index * 4)
        length = packed_length >> 1
        argument: dict[str, Any] = {
            "index": index,
            "offset": offset,
            "length": length,
            "flags": packed_length & 1,
            "valid": not (packed_length & 1),
        }
        start = table_end + offset
        end = start + length
        if packed_length & 1:
            argument["valid"] = False
            argument["error"] = "API Monitor marked this parameter unavailable"
        elif end > len(data):
            argument["valid"] = False
            argument["error"] = "parameter bytes exceed payload"
        elif length <= max_data_bytes:
            raw = data[start:end]
            argument["payload"] = _read_payload(raw)
            argument["_raw"] = raw
        else:
            argument["truncated"] = True
        arguments.append(argument)
    result["arguments"] = arguments
    result["available_count"] = len(arguments)
    result["truncated"] = captured_count > available_count
    result["valid"] = not count_mismatch
    return result


def _capture_enum_annotation(value: int, type_info: dict[str, Any]) -> dict[str, Any] | None:
    entries = [entry for entry in type_info.get("enum_entries", []) if entry.get("name")]
    if not entries:
        return None
    size = type_info.get("size")
    mask = (1 << (int(size) * 8)) - 1 if isinstance(size, int) and 0 < size <= 8 else None
    value &= mask if mask is not None else (1 << 64) - 1
    names: list[str] = []
    if type_info.get("enum_flags", 0) & 2:
        if value == 0:
            names = [entry["name"] for entry in entries if entry["value"] == 0]
        else:
            remaining = value
            for entry in entries:
                entry_value = entry["value"] & (mask if mask is not None else (1 << 64) - 1)
                if entry_value and remaining & entry_value == entry_value:
                    names.append(entry["name"])
                    remaining &= ~entry_value
            return {"names": names, "remaining": remaining}
    else:
        names = [entry["name"] for entry in entries if entry["value"] == value]
    return {"names": names, "remaining": 0 if names else value}


def _capture_array_element_size(
    type_info: dict[str, Any], depth: int = 0, machine_flag: bool = False
) -> int | None:
    if depth >= 4:
        return None
    kind = type_info.get("kind")
    pointer_size = int(type_info.get("pointer_size", 8))
    if kind in (2, 3):
        size = type_info.get("size")
        return size if isinstance(size, int) and 0 < size <= 16 else None
    if kind in (4, 6):
        return pointer_size
    if kind == 7 or kind == 9:
        return 2 if kind == 9 and machine_flag else 1
    if kind == 8:
        return 2
    if kind == 11:
        size = type_info.get("structure_size")
        if machine_flag:
            size = type_info.get("structure_size_flagged", size)
        return size if isinstance(size, int) and size > 0 else None
    if kind == 13:
        return 16
    if kind == 14:
        element_type = type_info.get("element_type")
        count = type_info.get("array_count")
        if not isinstance(element_type, dict) or not isinstance(count, int):
            return None
        element_size = _capture_array_element_size(element_type, depth + 1, machine_flag)
        return element_size * count if element_size is not None else None
    return pointer_size


def _capture_type_alignment(
    type_info: dict[str, Any], depth: int = 0, machine_flag: bool = False
) -> int | None:
    if depth >= 4:
        return None
    kind = type_info.get("kind")
    if kind == 14:
        element_type = type_info.get("element_type")
        return (
            _capture_type_alignment(element_type, depth + 1, machine_flag)
            if isinstance(element_type, dict)
            else None
        )
    if kind == 11:
        alignment = type_info.get("alignment")
        if isinstance(alignment, int) and alignment > 0:
            return alignment
        alignments = [
            _capture_type_alignment(field["type"], depth + 1, machine_flag)
            for field in type_info.get("fields", [])
            if isinstance(field.get("type"), dict)
        ]
        return max(alignments, default=None)
    return _capture_array_element_size(type_info, depth, machine_flag)


def _capture_exact_fixed_structure(
    data: bytes,
    type_info: dict[str, Any],
    depth: int,
    machine_flag: bool,
) -> dict[str, Any] | None:
    if depth >= 4:
        return None
    fields = type_info.get("fields", [])
    offset = 0
    extent = 0
    union = bool(int(type_info.get("struct_flags", 0)) & 1)
    decoded_fields = []
    for index, field in enumerate(fields):
        field_type = field.get("type")
        if not isinstance(field_type, dict):
            return None
        size = _capture_array_element_size(field_type, depth + 1, machine_flag)
        alignment = _capture_type_alignment(field_type, depth + 1, machine_flag) or 1
        if not union and offset % alignment:
            offset += alignment - offset % alignment
        field_offset = 0 if union else offset
        item: dict[str, Any] = {
            "index": index,
            "offset": field_offset,
            "length": size,
            "valid": size is not None and field_offset + size <= len(data),
        }
        if field.get("name"):
            item["name"] = field["name"]
        if not item["valid"]:
            item["error"] = "fixed structure field exceeds payload"
        else:
            raw = data[field_offset : field_offset + size]
            item["payload"] = _read_payload(raw)
            typed = _capture_exact_value(
                raw, field_type, depth + 1, machine_flag, inline_pointer=True
            )
            if typed:
                item["typed"] = typed
        decoded_fields.append(item)
        extent = max(extent, field_offset + (size or 0))
        if not union:
            offset += size or 0
    return {
        "exact": True,
        "kind": "structure",
        "valid": all(field["valid"] for field in decoded_fields),
        "field_count": len(decoded_fields),
        "representation": "fixed_union" if union else "fixed",
        "serialized_table_bytes": 0,
        "size": extent,
        "fields": decoded_fields,
    }


def _capture_exact_array(
    data: bytes,
    type_info: dict[str, Any],
    depth: int,
    machine_flag: bool,
    inline_pointer: bool,
) -> dict[str, Any] | None:
    element_type = type_info.get("element_type")
    if not isinstance(element_type, dict) or depth >= 4:
        return None
    element_size = _capture_array_element_size(element_type, machine_flag=machine_flag)
    if element_size is None or element_size <= 0:
        return None
    declared_count = type_info.get("array_count")
    array_flags = int(type_info.get("array_flags", 0))
    elements: list[dict[str, Any]] = []
    data_start = 0
    if array_flags & 1:
        if not isinstance(declared_count, int):
            return None
        count = declared_count
        if count > 4096:
            return None
        if count and len(data) == count * element_size:
            pass
        elif len(data) >= 2:
            prefixed_count = struct.unpack_from("<H", data)[0]
            if prefixed_count > 4096 or len(data) != 2 + prefixed_count * element_size:
                return None
            count = prefixed_count
            data_start = 2
        elif count or data:
            return None
        representation = "contiguous"
        table_bytes = data_start
        if count > 4096 or data_start + count * element_size != len(data):
            return None
        for index in range(count):
            offset = data_start + index * element_size
            raw = data[offset : offset + element_size]
            item: dict[str, Any] = {
                "index": index,
                "offset": offset,
                "length": element_size,
                "valid": True,
                "payload": _read_payload(raw),
            }
            typed = _capture_exact_value(
                raw, element_type, depth + 1, machine_flag, inline_pointer=True
            )
            if typed:
                item["typed"] = typed
            elements.append(item)
    else:
        if len(data) < 2:
            return None
        count = struct.unpack_from("<H", data)[0]
        table_bytes = 2 + count * 4
        if count > 4096 or table_bytes > len(data):
            return None
        representation = "offset_table"
        for index in range(count):
            offset, packed_length = struct.unpack_from("<HH", data, 2 + index * 4)
            length = packed_length >> 1
            item = {
                "index": index,
                "offset": offset,
                "length": length,
                "valid": not (packed_length & 1),
            }
            if not item["valid"]:
                item["error"] = "API Monitor marked this array element unavailable"
            elif table_bytes + offset + length > len(data):
                item["valid"] = False
                item["error"] = "array element exceeds payload"
            else:
                raw = data[table_bytes + offset : table_bytes + offset + length]
                item["payload"] = _read_payload(raw)
                typed = _capture_exact_value(
                    raw, element_type, depth + 1, machine_flag, inline_pointer=False
                )
                if typed:
                    item["typed"] = typed
            elements.append(item)
    result = {
        "exact": True,
        "kind": "array",
        "valid": all(item["valid"] for item in elements),
        "count": len(elements),
        "element_size": element_size,
        "representation": representation,
        "serialized_table_bytes": table_bytes,
        "elements": elements,
    }
    if representation == "contiguous" and element_type.get("kind") in (7, 8, 9):
        raw = data[data_start : data_start + count * element_size]
        kind = element_type["kind"]
        encoding = (
            "utf-16-le"
            if kind == 8 or (kind == 9 and machine_flag)
            else "ascii"
            if kind == 7
            else "utf-8"
        )
        try:
            result["value"] = raw.decode(encoding).rstrip("\x00")
            result["encoding"] = encoding
        except UnicodeDecodeError:
            pass
    return result


def _capture_exact_scalar(
    data: bytes,
    type_info: dict[str, Any],
    machine_flag: bool = False,
    inline_pointer: bool = False,
) -> dict[str, Any] | None:
    kind = type_info.get("kind")
    size = type_info.get("size")
    if kind == 13:
        if len(data) < 16:
            return None
        guid = uuid.UUID(bytes_le=data[:16])
        formatted = f"{{{guid}}}"
        result = {
            "exact": True,
            "kind": "guid",
            "size": 16,
            "value": "IID_NULL" if guid.int == 0 else formatted,
            "guid": formatted,
            "hex": data[:16].hex(" "),
        }
        if guid.int == 0:
            result["name"] = "IID_NULL"
        return result
    if kind == 4:
        pointer_size = int(type_info.get("pointer_size", 8))
        pointer_offset = 0 if inline_pointer or int(type_info.get("flags", 0)) & 8 else 8
        serialized_size = pointer_offset + pointer_size
        if len(data) < serialized_size or pointer_size not in (4, 8):
            return None
        return {
            "exact": True,
            "kind": "pointer",
            "size": pointer_size,
            "serialized_size": serialized_size,
            "payload_offset": pointer_offset,
            "value": f"0x{int.from_bytes(data[pointer_offset:serialized_size], 'little'):0{pointer_size * 2}x}",
        }
    if kind in (7, 8, 9):
        if len(data) < 4:
            return None
        present, length = struct.unpack_from("<HH", data)
        if not present:
            return {
                "exact": True,
                "kind": "string",
                "present": False,
                "size": 0,
                "serialized_size": 4,
                "value": None,
            }
        if length > len(data) - 4:
            return None
        raw = data[4 : 4 + length]
        encodings = {
            7: ("ascii", "utf-8"),
            8: ("utf-16-le",),
            9: ("utf-8", "utf-16-le"),
        }[kind]
        if kind == 9:
            encodings = ("utf-16-le",) if machine_flag else ("utf-8",)
        for encoding in encodings:
            try:
                value = raw.decode(encoding).rstrip("\x00")
            except UnicodeDecodeError:
                continue
            return {
                "exact": True,
                "kind": "string",
                "present": True,
                "size": length,
                "serialized_size": 4 + length,
                "encoding": encoding,
                "value": value,
            }
        return {
            "exact": True,
            "kind": "string",
            "present": True,
            "size": length,
            "serialized_size": 4 + length,
            "encoding": "bytes",
            "value": _read_payload(raw),
        }
    if not isinstance(size, int) or size <= 0 or size > 16 or len(data) < size:
        return None
    raw = data[:size]
    if kind == 2:
        unsigned = int.from_bytes(raw, "little")
        signed = not (int(type_info.get("flags", 0)) & 1)
        result = {
            "exact": True,
            "kind": "integer",
            "size": size,
            "signed": signed,
            "value": int.from_bytes(raw, "little", signed=signed),
            "unsigned_value": unsigned,
        }
        enum = _capture_enum_annotation(unsigned, type_info)
        if enum:
            result["enum"] = enum
        return result
    if kind == 3 and size in (4, 8):
        return {
            "exact": True,
            "kind": "float",
            "size": size,
            "value": struct.unpack("<f" if size == 4 else "<d", raw)[0],
        }
    if kind == 6 and size in (4, 8):
        return {
            "exact": True,
            "kind": "handle",
            "size": size,
            "value": f"0x{int.from_bytes(raw, 'little'):0{size * 2}x}",
        }
    return None


def _capture_exact_value(
    data: bytes,
    type_info: dict[str, Any],
    depth: int = 0,
    machine_flag: bool = False,
    inline_pointer: bool = False,
) -> dict[str, Any] | None:
    scalar = _capture_exact_scalar(data, type_info, machine_flag, inline_pointer)
    if scalar or type_info.get("kind") == 14:
        return (
            _capture_exact_array(data, type_info, depth, machine_flag, inline_pointer)
            if not scalar
            else scalar
        )
    if type_info.get("kind") != 11 or depth >= 4:
        return scalar
    if int(type_info.get("struct_flags", 0)) & 2:
        return _capture_exact_fixed_structure(
            data, type_info, depth, machine_flag
        )
    fields = type_info.get("fields", [])
    if not fields:
        return None
    table_bytes = 4 * len(fields)
    if len(data) < table_bytes:
        return None
    decoded_fields = []
    for index, field in enumerate(fields):
        offset, packed_length = struct.unpack_from("<HH", data, index * 4)
        length = packed_length >> 1
        item: dict[str, Any] = {
            "index": index,
            "offset": offset,
            "length": length,
            "valid": not (packed_length & 1),
        }
        if field.get("name"):
            item["name"] = field["name"]
        if not item["valid"]:
            item["error"] = "API Monitor marked this field unavailable"
        elif offset + length > len(data) - table_bytes:
            item["valid"] = False
            item["error"] = "structure field exceeds payload"
        else:
            raw = data[table_bytes + offset : table_bytes + offset + length]
            item["payload"] = _read_payload(raw)
            field_type = field.get("type")
            if field_type:
                typed = _capture_exact_value(
                    raw, field_type, depth + 1, machine_flag, inline_pointer=False
                )
                if typed:
                    item["typed"] = typed
        decoded_fields.append(item)
    return {
        "exact": True,
        "kind": "structure",
        "valid": all(field["valid"] for field in decoded_fields),
        "field_count": len(decoded_fields),
        "serialized_table_bytes": table_bytes,
        "fields": decoded_fields,
    }


def _capture_decoded_argument_stream(
    data: bytes,
    definition: dict[str, Any],
    max_items: int,
    max_data_bytes: int,
) -> dict[str, Any]:
    parameter_count = (
        definition.get("parameter_count") if definition.get("valid") else None
    )
    stream = _capture_encoded_argument_stream(
        data,
        parameter_count=parameter_count,
        max_items=max_items,
        max_data_bytes=max_data_bytes,
    )
    parameters = definition.get("parameters", [])
    try:
        definition_flags = int(definition.get("flags", "0"), 0)
    except (TypeError, ValueError):
        definition_flags = 0
    machine_flag = bool(definition_flags & 8)
    for argument in stream.get("arguments", []):
        raw = argument.pop("_raw", None)
        if raw is None or argument["index"] >= len(parameters):
            continue
        parameter = parameters[argument["index"]]
        type_info = parameter.get("type")
        if type_info:
            exact = _capture_exact_value(raw, type_info, machine_flag=machine_flag)
            if exact:
                argument["typed"] = exact
        if parameter.get("name"):
            argument["name"] = parameter["name"]
    return stream


def _xml_entry_nodes(
    root: ElementTree.Element, query: str, limit: int
) -> tuple[list[dict[str, Any]], int]:
    needle = query.casefold()
    nodes: list[dict[str, Any]] = []
    matched = 0
    seen = 0
    stack: list[tuple[ElementTree.Element, int, int]] = [(root, -1, 0)]
    while stack:
        element, parent_index, depth = stack.pop()
        index = seen
        seen += 1
        tag = (
            element.tag.rsplit("}", 1)[-1]
            if isinstance(element.tag, str)
            else str(element.tag)
        )
        text = " ".join((element.text or "").split())
        searchable = " ".join((tag, text, *element.attrib.values())).casefold()
        if not needle or needle in searchable:
            matched += 1
            if len(nodes) < limit:
                nodes.append(
                    {
                        "index": index,
                        "parent_index": parent_index,
                        "depth": depth,
                        "tag": tag,
                        "attributes": dict(element.attrib),
                        "text": text[:4096],
                        "truncated_text": len(text) > 4096,
                    }
                )
        for child in reversed(list(element)):
            stack.append((child, index, depth + 1))
    return nodes, matched


def _tasklist_rows() -> tuple[list[list[str]], str | None]:
    try:
        completed = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        return [], str(exc)
    return list(csv.reader(io.StringIO(completed.stdout))), None


@mcp.tool()
def api_monitor_status() -> dict[str, Any]:
    """List running Rohitab API Monitor x86/x64 processes."""
    if sys.platform != "win32":
        return {"supported": False, "processes": []}
    rows, error = _tasklist_rows()
    if error:
        return {"supported": True, "error": error, "processes": []}

    processes = []
    for row in rows:
        if len(row) < 5 or row[0].casefold() not in {"apimonitor-x86.exe", "apimonitor-x64.exe"}:
            continue
        try:
            pid: int | str = int(row[1])
        except ValueError:
            pid = row[1]
        processes.append({"image": row[0], "pid": pid, "session": row[2], "memory": row[4]})
    return {"supported": True, "processes": processes}


@mcp.tool()
def api_monitor_target_processes(query: str = "", limit: int = 500) -> dict[str, Any]:
    """List current Windows processes that can be selected for API Monitor attach."""
    if sys.platform != "win32":
        return {"supported": False, "processes": []}
    limit = _limit(limit, "limit", 5000)
    rows, error = _tasklist_rows()
    if error:
        return {"supported": True, "error": error, "processes": []}

    needle = query.casefold()
    processes = []
    for row in rows:
        if len(row) < 5 or (needle and needle not in row[0].casefold()):
            continue
        try:
            pid: int | str = int(row[1])
        except ValueError:
            pid = row[1]
        processes.append({"image": row[0], "pid": pid, "session": row[2], "memory": row[4]})
    return {
        "supported": True,
        "query": query,
        "processes": processes[:limit],
        "count": len(processes),
        "truncated": len(processes) > limit,
    }


@mcp.tool()
def api_monitor_ui_tree() -> dict[str, Any]:
    """Inspect Rohitab API Monitor top-level windows and immediate controls."""
    if sys.platform != "win32":
        return {"supported": False, "windows": []}
    return {"supported": True, "windows": _find_api_monitor_windows()}


@mcp.tool()
def api_monitor_gui_screenshot(
    window_title: str = "",
    window_handle: int | None = None,
    max_width: int = 2400,
    max_height: int = 1600,
) -> dict[str, Any]:
    """Capture an API Monitor window in the background as a PNG data URL."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI screenshots require Windows")
    max_width = _limit(max_width, "max_width", 10_000)
    max_height = _limit(max_height, "max_height", 10_000)
    windows = _find_api_monitor_windows()
    if window_handle is not None:
        candidates = [window for window in windows if window["handle"] == window_handle]
    elif window_title:
        candidates = [window for window in windows if window["title"] == window_title]
    else:
        candidates = [
            window
            for window in windows
            if "api monitor v2" in window["title"].casefold()
            and window["title"].casefold().startswith("monitoring")
        ]
    if len(candidates) != 1:
        raise ValueError("screenshot requires one matching window_handle or window_title")
    png, width, height = _capture_window_png(candidates[0]["handle"], max_width, max_height)
    return {
        "window": candidates[0],
        "width": width,
        "height": height,
        "mime_type": "image/png",
        "image_data_url": "data:image/png;base64," + base64.b64encode(png).decode("ascii"),
    }


@mcp.tool()
def api_monitor_summary(window_title: str = "", window_handle: int | None = None) -> dict[str, Any]:
    """Read Rohitab Summary panes without foregrounding the application."""
    if sys.platform != "win32":
        return {"supported": False, "summaries": []}
    summaries: list[dict[str, Any]] = []
    for window in _find_api_monitor_windows():
        if "api monitor v2" not in window["title"].casefold():
            continue
        if window_title and window["title"] != window_title:
            continue
        if window_handle is not None and window["handle"] != window_handle:
            continue
        for control in window.get("children", []):
            match = SUMMARY_TEXT.fullmatch(control.get("title", "").strip())
            if not match:
                continue
            summaries.append(
                {
                    "window": {"handle": window["handle"], "title": window["title"]},
                    "control": control,
                    "text": control["title"],
                    "calls": int(match.group(1).replace(",", "")),
                    "usage": match.group(2).strip(),
                    "process": match.group(3).strip(),
                }
            )
    return {"supported": True, "summaries": summaries}


@mcp.tool()
def api_monitor_gui_action(
    action: str,
    control_id: int | None = None,
    title: str = "",
    class_name: str = "",
    window_title: str = "",
    text: str = "",
    handle: int | None = None,
) -> dict[str, Any]:
    """Act on a Rohitab GUI control using background Win32 messages."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI actions require Windows")
    if action not in {"click", "set_text", "close"}:
        raise ValueError("action must be click, set_text, or close")
    if action == "close":
        windows = _find_api_monitor_windows()
        candidates = [
            window
            for window in windows
            if (handle is None or window.get("handle") == handle)
            and (not window_title or window.get("title") == window_title)
        ]
        if len(candidates) != 1:
            raise ValueError("close requires one matching window handle or window_title")
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.PostMessageW(candidates[0]["handle"], 0x0010, 0, 0)  # WM_CLOSE
        return {"action": action, "window": candidates[0]}

    if control_id is None and handle is None and not title and not class_name:
        raise ValueError("click and set_text require handle, control_id, title, or class_name")
    target = _find_ui_control(
        _find_api_monitor_windows(), control_id, title, class_name, window_title, handle
    )
    if target is None:
        raise LookupError("Rohitab GUI control not found")
    parent, control = target
    if action == "click":
        if control["class"].casefold() == "button":
            _post_button_click(control["handle"])
        else:
            _post_mouse_click(control["handle"])
    else:
        _set_control_text(control["handle"], text)
    return {"action": action, "window": parent, "control": control, "text": text}


@mcp.tool()
def api_monitor_gui_click_point(
    control_handle: int,
    x: int,
    y: int,
    button: str = "left",
    window_title: str = "",
) -> dict[str, Any]:
    """Click a point inside an exact Rohitab control without foregrounding it."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI clicks require Windows")
    if control_handle < 1:
        raise ValueError("control_handle must be positive")
    target = _find_ui_control(
        _find_api_monitor_windows(), None, "", "", window_title, control_handle
    )
    if target is None:
        raise LookupError(f"Rohitab GUI control {control_handle} was not found")
    parent, control = target
    _post_mouse_click_at(control_handle, x, y, button)
    return {
        "clicked": True,
        "method": "background-win32",
        "button": button,
        "x": x,
        "y": y,
        "window": parent,
        "control": control,
    }


@mcp.tool()
def api_monitor_gui_scroll(
    control_handle: int,
    direction: str,
    amount: int = 1,
    window_title: str = "",
) -> dict[str, Any]:
    """Scroll an exact Rohitab control in the background."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI scrolling requires Windows")
    if control_handle < 1:
        raise ValueError("control_handle must be positive")
    amount = _limit(amount, "amount", 100)
    target = _find_ui_control(
        _find_api_monitor_windows(), None, "", "", window_title, control_handle
    )
    if target is None:
        raise LookupError(f"Rohitab GUI control {control_handle} was not found")
    _post_scroll(control_handle, direction, amount)
    return {
        "scrolled": True,
        "method": "background-win32",
        "direction": direction,
        "amount": amount,
        "window": target[0],
        "control": target[1],
    }


@mcp.tool()
def api_monitor_gui_key(
    control_handle: int,
    key: str,
    window_title: str = "",
    modifiers: list[str] | None = None,
) -> dict[str, Any]:
    """Send one navigation key to an exact Rohitab control in the background."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI key input requires Windows")
    if control_handle < 1 or not key:
        raise ValueError("control_handle and key are required")
    target = _find_ui_control(
        _find_api_monitor_windows(), None, "", "", window_title, control_handle
    )
    if target is None:
        raise LookupError(f"Rohitab GUI control {control_handle} was not found")
    _post_key(control_handle, key, modifiers)
    return {
        "sent": True,
        "method": "background-win32",
        "key": key,
        "window": target[0],
        "control": target[1],
        "modifiers": modifiers or [],
    }


@mcp.tool()
def api_monitor_gui_tree(
    tree_handle: int | None = None,
    window_title: str = "",
    limit: int = 2000,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Read Rohitab's native API/filter tree, including checkbox states, in the background."""
    if sys.platform != "win32":
        return {"supported": False, "items": []}
    limit = _limit(limit, "limit", 20_000)
    if not 0 <= max_depth <= 128:
        raise ValueError("max_depth must be between 0 and 128")
    windows = _find_api_monitor_windows()
    if tree_handle is not None:
        candidates = [
            (window, child)
            for window in windows
            for child in window.get("children", [])
            if child.get("handle") == tree_handle
            and (not window_title or window.get("title") == window_title)
            and child.get("class") == "SysTreeView32"
        ]
    else:
        candidates = [
            (window, child)
            for window in windows
            for child in window.get("children", [])
            if child.get("class") == "SysTreeView32"
            and child.get("control_id") == 32804
            and child.get("visible")
            and (not window_title or window.get("title") == window_title)
        ]
    if len(candidates) != 1:
        raise ValueError("tree_handle or window_title must identify one native API Monitor tree")
    window, tree = candidates[0]
    items = _tree_items(tree["handle"], limit + 1, max_depth)
    return {
        "supported": True,
        "method": "background-win32",
        "window": {"handle": window["handle"], "title": window["title"]},
        "tree": tree,
        "items": items[:limit],
        "truncated": len(items) > limit,
    }


@mcp.tool()
def api_monitor_gui_tree_check(
    item_handle: int,
    checked: bool,
    tree_handle: int | None = None,
    window_title: str = "",
) -> dict[str, Any]:
    """Set one Rohitab native API/filter tree checkbox without foregrounding the app."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab tree controls require Windows")
    if item_handle < 1:
        raise ValueError("item_handle must be positive")
    tree = api_monitor_gui_tree(tree_handle, window_title, 1, 0)["tree"]
    _set_tree_item_check(tree["handle"], item_handle, checked)
    return {
        "updated": True,
        "method": "background-win32",
        "tree": tree,
        "item_handle": item_handle,
        "checked": checked,
    }


@mcp.tool()
def api_monitor_window_control(
    action: str,
    window_title: str = "",
    window_handle: int | None = None,
    left: int | None = None,
    top: int | None = None,
    width: int | None = None,
    height: int | None = None,
) -> dict[str, Any]:
    """Move or change API Monitor window state without activating it."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab window controls require Windows")
    if action not in {"show", "hide", "minimize", "restore", "move", "resize"}:
        raise ValueError("action must be show, hide, minimize, restore, move, or resize")
    windows = _find_api_monitor_windows()
    if window_handle is not None:
        candidates = [window for window in windows if window["handle"] == window_handle]
    elif window_title:
        candidates = [window for window in windows if window["title"] == window_title]
    else:
        candidates = [
            window
            for window in windows
            if "api monitor v2" in window["title"].casefold()
            and window["title"].casefold().startswith("monitoring")
        ]
    if len(candidates) != 1:
        raise ValueError("window control requires one matching window_handle or window_title")
    target = candidates[0]
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    if action in {"show", "hide", "minimize", "restore"}:
        command = {"show": 4, "hide": 0, "minimize": 6, "restore": 4}[action]
        if not user32.ShowWindow(target["handle"], command):
            error = ctypes.get_last_error()
            if action != "hide" and error:
                raise OSError(error, "Could not change API Monitor window state")
    else:
        rectangle = target["rectangle"]
        current_width = rectangle.get("right", 0) - rectangle.get("left", 0)
        current_height = rectangle.get("bottom", 0) - rectangle.get("top", 0)
        if action == "move" and (left is None or top is None):
            raise ValueError("move requires left and top")
        if action == "resize" and (width is None or height is None):
            raise ValueError("resize requires width and height")
        left = rectangle.get("left", 0) if left is None else left
        top = rectangle.get("top", 0) if top is None else top
        width = current_width if width is None else width
        height = current_height if height is None else height
        if width < 1 or height < 1 or width > 10_000 or height > 10_000:
            raise ValueError("width and height must be between 1 and 10000")
        if not user32.SetWindowPos(target["handle"], 0, left, top, width, height, 0x0014):
            raise OSError(ctypes.get_last_error(), "Could not position API Monitor window")
    return {
        "changed": True,
        "method": "background-win32",
        "action": action,
        "window": target,
    }


@mcp.tool()
def api_monitor_gui_read(
    control_id: int | None = None,
    title: str = "",
    class_name: str = "",
    window_title: str = "",
    max_chars: int = 20_000,
    handle: int | None = None,
) -> dict[str, Any]:
    """Read one Rohitab GUI control without focusing or raising the window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI reads require Windows")
    if control_id is None and handle is None and not title and not class_name:
        raise ValueError("handle, control_id, title, or class_name is required")
    max_chars = _limit(max_chars, "max_chars", 1_000_000)
    target = _find_ui_control(
        _find_api_monitor_windows(), control_id, title, class_name, window_title, handle
    )
    if target is None:
        raise LookupError("Rohitab GUI control not found")
    parent, control = target
    text = _window_text(ctypes.WinDLL("user32", use_last_error=True), control["handle"])
    return {
        "window": parent,
        "control": control,
        "text": text[:max_chars],
        "truncated": len(text) > max_chars,
    }


@mcp.tool()
def api_monitor_gui_select_option(
    control_id: int,
    option: str,
    window_title: str = "",
) -> dict[str, Any]:
    """Select a native Rohitab combo-box option without focusing the window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI selection requires Windows")
    if not option:
        raise ValueError("option must not be empty")
    target = _find_ui_control(
        _find_api_monitor_windows(), control_id, "", "ComboBox", window_title
    )
    if target is None:
        raise LookupError("Rohitab combo box not found")
    parent, control = target
    _set_combo_selection(control["handle"], option)
    return {
        "selected": True,
        "method": "background-win32",
        "window": parent,
        "control": control,
        "option": option,
    }


@mcp.tool()
def api_monitor_gui_lists(
    window_title: str = "",
    limit: int = 200,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Read Rohitab list views through background Windows UI Automation."""
    if sys.platform != "win32":
        return {"supported": False, "windows": []}
    limit = _limit(limit, "limit", 2000)
    try:
        from pywinauto import Desktop
    except ImportError as exc:
        raise RuntimeError("Install pywinauto to read Rohitab GUI lists") from exc

    pids = {
        int(process["pid"])
        for process in api_monitor_status().get("processes", [])
        if isinstance(process.get("pid"), int)
    }
    result: list[dict[str, Any]] = []
    for window in Desktop(backend="uia").windows():
        if window.process_id() not in pids:
            continue
        if window_title and window.window_text() != window_title:
            continue
        if window_handle is not None and window.handle != window_handle:
            continue
        lists: list[dict[str, Any]] = []
        for control in window.descendants():
            if control.element_info.control_type != "List":
                continue
            headers = [
                _uia_text(item)
                for item in control.descendants()
                if item.element_info.control_type == "HeaderItem"
            ]
            rows: list[list[str]] = []
            for item in control.children():
                if item.element_info.control_type != "ListItem":
                    continue
                cells = [
                    _uia_text(cell)
                    for cell in item.descendants()
                    if cell.element_info.control_type == "Text"
                ]
                rows.append(cells or [_uia_text(item)])
                if len(rows) > limit:
                    break
            truncated = len(rows) > limit
            lists.append(
                {
                    "handle": control.handle,
                    "rectangle": _uia_rect(control),
                    "headers": headers,
                    "rows": rows[:limit],
                    "truncated": truncated,
                }
            )
        result.append({"handle": window.handle, "title": window.window_text(), "lists": lists})
    return {"supported": True, "windows": result}


@mcp.tool()
def api_monitor_gui_select(
    list_handle: int,
    row_index: int | None = None,
    query: str = "",
) -> dict[str, Any]:
    """Select a Rohitab list row by index or text without foregrounding the app."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI selection requires Windows")
    if list_handle < 1:
        raise ValueError("list_handle must be positive")
    if row_index is None and not query:
        raise ValueError("row_index or query is required")
    if row_index is not None and row_index < 0:
        raise ValueError("row_index must be non-negative")
    try:
        from pywinauto import Desktop
    except ImportError as exc:
        raise RuntimeError("Install pywinauto to select a GUI row") from exc

    wanted = query.casefold()
    api_monitor_pids = {
        int(process["pid"])
        for process in api_monitor_status().get("processes", [])
        if isinstance(process.get("pid"), int)
    }
    for window in Desktop(backend="uia").windows():
        if window.process_id() not in api_monitor_pids:
            continue
        for control in window.descendants():
            if control.element_info.control_type != "List" or control.handle != list_handle:
                continue
            rows = [
                item
                for item in control.children()
                if item.element_info.control_type == "ListItem"
            ]
            if row_index is not None:
                if row_index >= len(rows):
                    raise IndexError(f"row_index {row_index} is outside the list")
                matches = [(row_index, rows[row_index])]
            else:
                matches = [
                    (index, item)
                    for index, item in enumerate(rows)
                    if wanted in _uia_text(item).casefold()
                    or wanted in " ".join(
                        _uia_text(cell)
                        for cell in item.descendants()
                        if cell.element_info.control_type == "Text"
                    ).casefold()
                ]
                if len(matches) != 1:
                    raise ValueError("query must match exactly one GUI row")
            index, item = matches[0]
            item.select()
            cells = [
                _uia_text(cell)
                for cell in item.descendants()
                if cell.element_info.control_type == "Text"
            ]
            return {
                "selected": True,
                "method": "background-ui-automation",
                "window": {"handle": window.handle, "title": window.window_text()},
                "list_handle": list_handle,
                "row_index": index,
                "cells": cells or [_uia_text(item)],
                "rectangle": _uia_rect(item),
            }
    raise LookupError(f"Rohitab GUI list {list_handle} was not found")


@mcp.tool()
def api_monitor_traffic(
    window_title: str = "",
    limit: int = 500,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Read captured API-call rows from Rohitab's background traffic panes."""
    limit = _limit(limit, "limit", 2000)
    lists = api_monitor_gui_lists(window_title, limit, window_handle)
    traffic: list[dict[str, Any]] = []
    for window in lists.get("windows", []):
        for pane in window.get("lists", []):
            headers = pane.get("headers", [])
            if "API" not in headers or "Module" not in headers:
                continue
            traffic.append(
                {
                    "window": {"handle": window["handle"], "title": window["title"]},
                    "list_handle": pane["handle"],
                    "headers": headers,
                    "rows": pane["rows"],
                    "truncated": pane["truncated"],
                }
            )
    return {"supported": lists.get("supported", False), "panes": traffic}


@mcp.tool()
def api_monitor_traffic_details(
    window_title: str = "",
    row_index: int | None = None,
    query: str = "",
    limit: int = 500,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Select one captured API call and return its related GUI detail panes."""
    if row_index is None and not query:
        raise ValueError("row_index or query is required")
    limit = _limit(limit, "limit", 2000)
    traffic = api_monitor_traffic(window_title, limit, window_handle)
    if len(traffic["panes"]) != 1:
        raise ValueError("window_title must identify one window with one traffic pane")
    call_pane = traffic["panes"][0]
    selected = api_monitor_gui_select(call_pane["list_handle"], row_index, query)
    time.sleep(0.2)
    refreshed = api_monitor_gui_lists(window_title, limit, window_handle)
    details = [
        {
            "handle": pane["handle"],
            "headers": pane["headers"],
            "rows": pane["rows"],
            "truncated": pane["truncated"],
        }
        for window in refreshed.get("windows", [])
        for pane in window.get("lists", [])
        if pane["handle"] != call_pane["list_handle"]
    ]
    return {
        "selected_call": selected,
        "details": details,
        "summaries": api_monitor_summary(window_title, window_handle)["summaries"],
    }


@mcp.tool()
def api_monitor_wait_for_traffic(
    minimum_calls: int = 1,
    timeout_seconds: int = 30,
    window_title: str = "",
    window_handle: int | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Wait for a Rohitab Summary call count, then return the current traffic panes."""
    if minimum_calls < 0:
        raise ValueError("minimum_calls must be non-negative")
    if timeout_seconds < 1 or timeout_seconds > 300:
        raise ValueError("timeout_seconds must be between 1 and 300")
    limit = _limit(limit, "limit", 2000)
    deadline = time.monotonic() + timeout_seconds
    summaries: list[dict[str, Any]] = []
    while True:
        summaries = api_monitor_summary(window_title, window_handle)["summaries"]
        if any(summary["calls"] >= minimum_calls for summary in summaries):
            return {
                "ready": True,
                "summaries": summaries,
                "traffic": api_monitor_traffic(window_title, limit, window_handle),
            }
        if time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    return {
        "ready": False,
        "minimum_calls": minimum_calls,
        "summaries": summaries,
        "traffic": api_monitor_traffic(window_title, limit, window_handle),
    }


@mcp.tool()
def api_monitor_add_display_filter(
    field: str,
    operator: str,
    value: str,
    action: str = "Show",
    ignore_case: bool = True,
    architecture: str = "x64",
    timeout_seconds: int = 10,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Add a Rohitab Display Filter through its background GUI dialog."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab display filters require Windows")
    if not field or not operator or not value:
        raise ValueError("field, operator, and value are required")
    if action not in {"Show", "Hide"}:
        raise ValueError("action must be Show or Hide")
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")

    main_window = (
        _api_monitor_window_by_handle(window_handle, architecture)
        if window_handle is not None
        else _api_monitor_main_window(architecture, timeout_seconds)
    )
    if main_window is None:
        if window_handle is not None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
        raise TimeoutError("API Monitor main window did not appear")
    dialog = next(
        (window for window in _find_api_monitor_windows() if window["title"] == "Display Filter"),
        None,
    )
    if dialog is None:
        button = next(
            (
                child
                for child in main_window.get("children", [])
                if child.get("title") == "Add Filter (Insert)"
            ),
            None,
        )
        if button is None:
            raise RuntimeError("API Monitor Add Filter button was not found")
        _post_button_click(button["handle"])
        dialog = _wait_for_api_monitor_window(
            lambda window: window["title"] == "Display Filter", timeout_seconds
        )
    if dialog is None:
        raise TimeoutError("API Monitor Display Filter dialog did not appear")

    controls = {child.get("control_id"): child for child in dialog.get("children", [])}
    for control_id, option in ((2041, field), (2098, operator), (2001, action)):
        control = controls.get(control_id)
        if control is None:
            raise RuntimeError(f"API Monitor Display Filter control {control_id} was not found")
        _set_combo_selection(control["handle"], option)
    value_control = controls.get(2110)
    add_button = controls.get(2002)
    close_button = controls.get(2)
    case_button = controls.get(2051)
    if not value_control or not add_button or not close_button or not case_button:
        raise RuntimeError("API Monitor Display Filter controls were incomplete")
    _set_control_text(value_control["handle"], value)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    checked = user32.SendMessageW(case_button["handle"], 0x00F0, 0, 0) == 1  # BM_GETCHECK
    if checked != ignore_case:
        _post_button_click(case_button["handle"])
    _post_button_click(add_button["handle"])
    _post_button_click(close_button["handle"])
    return {
        "added": True,
        "method": "background-gui",
        "field": field,
        "operator": operator,
        "value": value,
        "action": action,
        "ignore_case": ignore_case,
    }


@mcp.tool()
def api_monitor_monitor_process(
    process_path: str,
    architecture: str = "x64",
    arguments: str = "",
    start_in: str = "",
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Start monitoring an executable through Rohitab's native Monitor Process dialog."""
    if sys.platform != "win32":
        raise RuntimeError("Starting API Monitor sessions requires Windows")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    target = Path(process_path).expanduser()
    if not target.is_file():
        raise FileNotFoundError(f"Target process not found: {target}")
    target = target.resolve()
    if start_in:
        start_directory = Path(start_in).expanduser()
        if not start_directory.is_dir():
            raise NotADirectoryError(f"Start directory not found: {start_directory}")
        start_in = str(start_directory.resolve())

    main_window = _api_monitor_main_window(architecture, timeout_seconds)
    if main_window is None:
        raise TimeoutError("API Monitor main window did not appear")

    dialog = next(
        (window for window in _find_api_monitor_windows() if window["title"] == "Monitor Process"),
        None,
    )
    if dialog is None:
        _post_window_command(main_window["handle"], COMMAND_MONITOR_NEW_PROCESS)
        dialog = _wait_for_api_monitor_window(
            lambda window: window["title"] == "Monitor Process", timeout_seconds
        )
    if dialog is None:
        raise TimeoutError("Monitor Process dialog did not appear")

    controls = {child.get("control_id"): child for child in dialog.get("children", [])}
    process_edit = controls.get(2081)
    arguments_edit = controls.get(2007)
    start_edit = controls.get(2022)
    ok_button = controls.get(1)
    if not process_edit or not ok_button:
        raise RuntimeError("Monitor Process dialog controls were not found")
    _set_control_text(process_edit["handle"], str(target))
    if arguments and arguments_edit:
        _set_control_text(arguments_edit["handle"], arguments)
    if start_in and start_edit:
        _set_control_text(start_edit["handle"], start_in)
    _post_button_click(ok_button["handle"])
    return {
        "submitted": True,
        "process": str(target),
        "architecture": architecture,
        "arguments": arguments,
        "start_in": start_in,
        "window": {"handle": main_window["handle"], "title": main_window["title"]},
    }


@mcp.tool()
def api_monitor_capture_process(
    process_path: str,
    output_path: str,
    architecture: str = "x64",
    arguments: str = "",
    start_in: str = "",
    duration_seconds: int = 10,
    minimum_calls: int = 0,
    timeout_seconds: int = 10,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Capture one executable in the background and save the resulting APMX file."""
    if sys.platform != "win32":
        raise RuntimeError("Live API Monitor captures require Windows")
    if duration_seconds < 1 or duration_seconds > 300:
        raise ValueError("duration_seconds must be between 1 and 300")
    if minimum_calls < 0:
        raise ValueError("minimum_calls must be non-negative")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    path = _capture_output_path(output_path, architecture)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Capture already exists: {path}")

    started = api_monitor_monitor_process(
        process_path,
        architecture=architecture,
        arguments=arguments,
        start_in=start_in,
        timeout_seconds=timeout_seconds,
    )
    started_at = time.monotonic()
    summaries: list[dict[str, Any]] = []
    ready = minimum_calls == 0
    wait_error = None
    try:
        deadline = started_at + duration_seconds
        while True:
            summaries = api_monitor_summary(window_handle=started["window"]["handle"])["summaries"]
            if minimum_calls and any(item["calls"] >= minimum_calls for item in summaries):
                ready = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.25, remaining))
    except Exception as exc:
        wait_error = str(exc)
    waited_seconds = round(time.monotonic() - started_at, 3)
    stopped = api_monitor_monitoring_control(
        "stop",
        architecture=architecture,
        timeout_seconds=timeout_seconds,
        window_handle=started["window"]["handle"],
    )
    saved = api_monitor_save_capture(
        str(path),
        overwrite=overwrite,
        timeout_seconds=timeout_seconds,
        window_handle=started["window"]["handle"],
    )
    validation = capture_validate(str(path))
    result: dict[str, Any] = {
        "captured": True,
        "ready": ready,
        "minimum_calls": minimum_calls,
        "waited_seconds": waited_seconds,
        "summaries": summaries,
        "started": started,
        "stopped": stopped,
        "saved": saved,
        "validation": validation,
    }
    if validation["valid"]:
        result["capture"] = capture_info(str(path))
    if wait_error:
        result["wait_error"] = wait_error
    return result


@mcp.tool()
def api_monitor_capture_session(
    output_path: str,
    architecture: str = "x64",
    duration_seconds: int = 10,
    minimum_calls: int = 0,
    timeout_seconds: int = 15,
    window_handle: int | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Stop and save an already-attached Rohitab monitoring session."""
    if sys.platform != "win32":
        raise RuntimeError("Live API Monitor captures require Windows")
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    if duration_seconds < 1 or duration_seconds > 300:
        raise ValueError("duration_seconds must be between 1 and 300")
    if minimum_calls < 0:
        raise ValueError("minimum_calls must be non-negative")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    path = _capture_output_path(output_path, architecture)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Capture already exists: {path}")

    waited = api_monitor_wait_for_traffic(
        minimum_calls=minimum_calls,
        timeout_seconds=duration_seconds,
        window_handle=window_handle,
    )
    stopped = api_monitor_monitoring_control(
        "stop",
        architecture=architecture,
        timeout_seconds=timeout_seconds,
        window_handle=window_handle,
    )
    saved = api_monitor_save_capture(
        str(path),
        overwrite=overwrite,
        timeout_seconds=timeout_seconds,
        window_handle=window_handle,
    )
    validation = capture_validate(str(path))
    result = {
        "captured": validation["valid"],
        "ready": waited.get("ready", False),
        "minimum_calls": minimum_calls,
        "waited": waited,
        "stopped": stopped,
        "saved": saved,
        "validation": validation,
    }
    if validation["valid"]:
        result["capture"] = capture_info(str(path))
    return result


@mcp.tool()
def api_monitor_attach_process(
    pid: int,
    process_name: str = "",
    architecture: str = "x64",
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Select a running process and start monitoring it in Rohitab's background GUI."""
    if sys.platform != "win32":
        raise RuntimeError("Attaching API Monitor sessions requires Windows")
    if pid < 1:
        raise ValueError("pid must be positive")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")

    main_windows = [
        window
        for window in _find_api_monitor_windows()
        if "api monitor v2" in window["title"].casefold()
        and ((architecture == "x86" and "32-bit" in window["title"]) or
             (architecture == "x64" and "64-bit" in window["title"]))
    ]
    if not main_windows:
        api_monitor_launch(architecture)
        window = _wait_for_api_monitor_window(
            lambda candidate: "api monitor v2" in candidate["title"].casefold()
            and ((architecture == "x86" and "32-bit" in candidate["title"]) or
                 (architecture == "x64" and "64-bit" in candidate["title"])),
            timeout_seconds,
        )
        main_windows = [window] if window else []
    if not main_windows:
        raise TimeoutError("API Monitor main window did not appear")

    try:
        from pywinauto import Desktop
    except ImportError as exc:
        raise RuntimeError("Install pywinauto to attach a running process") from exc

    wanted_name = process_name.casefold()
    for window in Desktop(backend="uia").windows():
        if window.handle not in {item["handle"] for item in main_windows}:
            continue
        for control in window.descendants():
            if control.element_info.control_type != "List":
                continue
            for item in control.children():
                if item.element_info.control_type != "ListItem":
                    continue
                cells = [
                    _uia_text(cell)
                    for cell in item.descendants()
                    if cell.element_info.control_type == "Text"
                ]
                if len(cells) < 2 or cells[1] != str(pid):
                    continue
                if wanted_name and cells[0].casefold() != wanted_name:
                    continue
                item.select()
                _post_window_command(window.handle, COMMAND_START_MONITORING)
                return {
                    "submitted": True,
                    "method": "background-gui",
                    "process": cells[0],
                    "pid": pid,
                    "architecture": architecture,
                    "window": {"handle": window.handle, "title": window.window_text()},
                }
    suffix = f" named {process_name!r}" if process_name else ""
    raise LookupError(f"Process PID {pid}{suffix} was not found in API Monitor's process list")


@mcp.tool()
def api_monitor_monitoring_control(
    action: str,
    architecture: str = "x64",
    timeout_seconds: int = 10,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Start or stop the selected Rohitab monitoring session in the background."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab monitoring control requires Windows")
    if action not in {"start", "stop"}:
        raise ValueError("action must be start or stop")
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    main_window = (
        _api_monitor_window_by_handle(window_handle, architecture)
        if window_handle is not None
        else _api_monitor_main_window(architecture, timeout_seconds)
    )
    if main_window is None:
        if window_handle is not None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
        raise TimeoutError("API Monitor main window did not appear")
    command = COMMAND_START_MONITORING if action == "start" else COMMAND_STOP_MONITORING
    _post_window_command(main_window["handle"], command)
    return {
        "submitted": True,
        "method": "background-gui",
        "action": action,
        "architecture": architecture,
        "window": {"handle": main_window["handle"], "title": main_window["title"]},
    }


@mcp.tool()
def api_monitor_process_control(
    action: str,
    architecture: str = "x64",
    timeout_seconds: int = 10,
    window_handle: int | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Remove or terminate the selected process in Rohitab's monitor window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab process controls require Windows")
    if action not in {"remove", "terminate"}:
        raise ValueError("action must be remove or terminate")
    if action == "terminate" and not confirm:
        raise ValueError("terminate requires confirm=true")
    if architecture not in {"x86", "x64"}:
        raise ValueError("architecture must be x86 or x64")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    main_window = (
        _api_monitor_window_by_handle(window_handle, architecture)
        if window_handle is not None
        else _api_monitor_main_window(architecture, timeout_seconds)
    )
    if main_window is None:
        if window_handle is not None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
        raise TimeoutError("API Monitor main window did not appear")
    command = COMMAND_REMOVE_PROCESS if action == "remove" else COMMAND_TERMINATE_PROCESS
    _post_window_command(main_window["handle"], command)
    return {
        "submitted": True,
        "method": "background-gui",
        "action": action,
        "architecture": architecture,
        "window": {"handle": main_window["handle"], "title": main_window["title"]},
    }


@mcp.tool()
def api_monitor_detach_all(timeout_seconds: int = 30) -> dict[str, Any]:
    """Detach pending Rohitab API Monitor hooks through its background safeguard dialog."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab detach control requires Windows")
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    dialog = next(
        (
            window
            for window in _find_api_monitor_windows()
            if window["title"] == "Action Required: Detach or Close Processes"
        ),
        None,
    )
    if dialog is None:
        return {"detached": False, "method": "background-gui", "reason": "no-pending-dialog"}
    button = next((child for child in dialog.get("children", []) if child["control_id"] == 32929), None)
    if button is None:
        raise RuntimeError("API Monitor Detach All button was not found")
    _post_button_click(button["handle"])
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not any(
            window["title"] == "Action Required: Detach or Close Processes"
            for window in _find_api_monitor_windows()
        ):
            return {"detached": True, "method": "background-gui"}
        time.sleep(0.1)
    raise TimeoutError("API Monitor did not finish detaching processes")


@mcp.tool()
def api_monitor_launch(architecture: str = "x64", install_root: str | None = None) -> dict[str, Any]:
    """Launch the installed Rohitab API Monitor x86 or x64 executable."""
    root = _app_root(install_root)
    executable = _app_executable(root, architecture)
    process = subprocess.Popen(
        [str(executable)],
        cwd=str(root),
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    return {"pid": process.pid, "architecture": architecture, "executable": str(executable)}


@mcp.tool()
def api_monitor_open_capture(
    file_path: str,
    install_root: str | None = None,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Open an APMX capture with the real Rohitab API Monitor application."""
    path = _capture_path(file_path)
    if sys.platform != "win32" or not hasattr(os, "startfile"):
        raise RuntimeError("Opening API Monitor captures requires Windows")

    architecture = "x86" if path.suffix.lower() == ".apmx86" else "x64"
    bitness = "32-bit" if architecture == "x86" else "64-bit"
    if window_handle is not None:
        main_window = _api_monitor_window_by_handle(window_handle, architecture)
        if main_window is None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
    else:
        candidates = [
            window
            for window in _find_api_monitor_windows()
            if "api monitor v2" in window["title"].casefold() and bitness in window["title"]
        ]
        capture_candidates = [
            window
            for window in candidates
            if not window["title"].casefold().startswith("monitoring")
        ]
        main_window = capture_candidates[0] if capture_candidates else None
    if main_window is None:
        if window_handle is not None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
        existing_handles = {window["handle"] for window in candidates}
        launch = api_monitor_launch(architecture, install_root)
        main_window = _wait_for_api_monitor_window(
            lambda window: window["handle"] not in existing_handles
            and "api monitor v2" in window["title"].casefold()
            and bitness in window["title"]
            and not window["title"].casefold().startswith("monitoring"),
            15,
        )
        if main_window is None:
            return {
                "opened": True,
                "method": "direct-launch-fallback",
                "pid": launch["pid"],
                "file": str(path),
            }

    try:
        _run_file_dialog(
            main_window,
            COMMAND_OPEN_CAPTURE,
            "Open",
            ("&Open", "Open"),
            1148,
            path,
            15,
        )
        return {
            "opened": True,
            "method": "background-gui",
            "file": str(path),
        }
    except (LookupError, OSError, RuntimeError, TimeoutError):
        try:
            os.startfile(str(path))
            return {"opened": True, "method": "file-association-fallback", "file": str(path)}
        except OSError:
            raise


@mcp.tool()
def api_monitor_save_capture(
    output_path: str,
    overwrite: bool = False,
    timeout_seconds: int = 15,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Save the current Rohitab capture through its background GUI."""
    if sys.platform != "win32":
        raise RuntimeError("Saving API Monitor captures requires Windows")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    suffix = Path(output_path).expanduser().suffix.lower()
    if suffix not in CAPTURE_SUFFIXES:
        raise ValueError("output_path must end in .apmx64 or .apmx86")
    architecture = "x86" if suffix == ".apmx86" else "x64"
    path = _capture_output_path(output_path, architecture)
    existed = path.exists()
    if existed and not overwrite:
        raise FileExistsError(f"Capture already exists: {path}")

    main_window = (
        _api_monitor_window_by_handle(window_handle, architecture)
        if window_handle is not None
        else _api_monitor_main_window(architecture, timeout_seconds)
    )
    if main_window is None:
        if window_handle is not None:
            raise LookupError(f"API Monitor window not found: {window_handle}")
        raise TimeoutError("API Monitor main window did not appear")
    if window_handle is None and main_window["title"].casefold().startswith("monitoring"):
        bitness = "32-bit" if architecture == "x86" else "64-bit"
        capture_window = next(
            (
                window
                for window in _find_api_monitor_windows()
                if "api monitor v2" in window["title"].casefold()
                and bitness in window["title"]
                and not window["title"].casefold().startswith("monitoring")
            ),
            None,
        )
        if capture_window is not None:
            main_window = capture_window
    _run_file_dialog(
        main_window,
        COMMAND_SAVE_CAPTURE_AS,
        "Save As",
        ("&Save", "Save"),
        1001,
        path,
        timeout_seconds,
    )
    if existed:
        confirmation = _wait_for_api_monitor_window(
            lambda window: window["title"] == "Confirm Save As", timeout_seconds
        )
        if confirmation is not None:
            button = None
            for title in ("&Yes", "Yes"):
                button = _find_ui_control(
                    _find_api_monitor_windows(), None, title, "Button", "Confirm Save As"
                )
                if button is not None:
                    break
            if button is None:
                raise RuntimeError("API Monitor overwrite confirmation button was not found")
            _post_button_click(button[1]["handle"])

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        dialogs = [
            window for window in _find_api_monitor_windows() if window["title"] == "Save As"
        ]
        if not dialogs and path.is_file():
            stat = path.stat()
            return {
                "saved": True,
                "method": "background-gui",
                "file": str(path),
                "size": stat.st_size,
                "modified_utc": _file_time(path),
            }
        time.sleep(0.1)
    raise TimeoutError("API Monitor did not finish saving the capture")


@mcp.tool()
def capture_info(file_path: str) -> dict[str, Any]:
    """Inspect an APMX file header and list its ZIP container entries."""
    return _capture_info(_capture_path(file_path))


@mcp.tool()
def capture_validate(
    file_path: str, deep: bool = False, max_records: int = 1_000_000
) -> dict[str, Any]:
    """Validate an APMX prefix, ZIP entries, process metadata, and call streams."""
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    try:
        archive, data, offset = _open_capture_zip(path)
    except (ValueError, zipfile.BadZipFile) as exc:
        return {
            "file": str(path),
            "valid": False,
            "prefix_valid": False,
            "zip_offset": None,
            "entries": 0,
            "first_bad_entry": None,
            "error": str(exc),
            "deep": deep,
        }
    bad_entry = None
    error = None
    with archive:
        try:
            bad_entry = archive.testzip()
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            error = str(exc)
        entry_count = len(archive.infolist())
    prefix = data[:offset]
    prefix_valid = prefix.endswith(b"RBAPM")
    result: dict[str, Any] = {
        "file": str(path),
        "valid": prefix_valid and error is None and bad_entry is None,
        "prefix_valid": prefix_valid,
        "zip_offset": offset,
        "entries": entry_count,
        "first_bad_entry": bad_entry,
        "error": error,
        "deep": deep,
    }
    if not deep or not result["valid"]:
        return result
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    streams = []
    archive, _, _ = _open_capture_zip(path)
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        definitions = archive.read("definitions") if "definitions" in entries else None
        process_infos = []
        for name in sorted(entries):
            match = PROCESS_INFO.fullmatch(name)
            if not match:
                continue
            process_index = int(match.group(1))
            process_data = archive.read(name)
            try:
                metadata = _parse_capture_process_info(process_data, pointer_size)
                valid = metadata.get("crc32_valid", True)
            except ValueError as exc:
                metadata = {"parse_error": str(exc)}
                valid = False
            process_infos.append(
                {
                    "process_index": process_index,
                    "entry": name,
                    "size": len(process_data),
                    "valid": valid,
                    "metadata": metadata,
                }
            )
        for name in sorted(entries):
            match = re.fullmatch(r"process/(\d+)/calls", name, re.I)
            if not match:
                continue
            index = int(match.group(1))
            calls = archive.read(name)
            data_name = f"process/{index}/data"
            data = archive.read(data_name) if data_name in entries else b""
            stream: dict[str, Any] = {
                "process_index": index,
                "architecture": "x86" if pointer_size == 4 else "x64",
                "calls_entry": name,
                "data_entry": data_name if data else None,
                "valid": False,
            }
            try:
                stats = _capture_call_stats(calls, data, max_records, pointer_size)
                stream["stats"] = stats
                stream["valid"] = stats["invalid_records"] == 0
                if definitions is not None:
                    records = _capture_call_records(
                        calls,
                        data,
                        min(len(calls) // pointer_size, max_records),
                        False,
                        0,
                        definitions=definitions,
                        pointer_size=pointer_size,
                    )
                    definition_checks = {
                        "available": True,
                        "resolved": 0,
                        "unknown": 0,
                        "invalid": 0,
                        "truncated": len(calls) // pointer_size > max_records,
                    }
                    for record in records:
                        definition_offset = record.get("definition_offset", 0)
                        if not definition_offset:
                            definition_checks["unknown"] += 1
                        elif record.get("definition", {}).get("valid"):
                            definition_checks["resolved"] += 1
                        else:
                            definition_checks["invalid"] += 1
                    stream["definitions"] = definition_checks
                    stream["valid"] = stream["valid"] and not definition_checks["invalid"]
                else:
                    stream["definitions"] = {"available": False}
            except (ValueError, struct.error) as exc:
                stream["error"] = str(exc)
            streams.append(stream)
    result["streams"] = streams
    result["process_infos"] = process_infos
    result["structural_valid"] = all(stream["valid"] for stream in streams) and all(
        process["valid"] for process in process_infos
    )
    result["valid"] = result["valid"] and result["structural_valid"]
    return result


@mcp.tool()
def capture_compare(
    first_file: str,
    second_file: str,
    limit: int = 2000,
) -> dict[str, Any]:
    """Compare two APMX captures by their stored entry sizes and CRCs."""
    limit = _limit(limit, "limit", 10_000)
    first = _capture_path(first_file)
    second = _capture_path(second_file)
    first_entries = {entry["name"]: entry for entry in _zip_entries(first)}
    second_entries = {entry["name"]: entry for entry in _zip_entries(second)}
    added_names = sorted(set(second_entries) - set(first_entries))
    removed_names = sorted(set(first_entries) - set(second_entries))
    changed_names = sorted(
        name
        for name in set(first_entries) & set(second_entries)
        if (
            first_entries[name]["size"],
            first_entries[name]["crc32"],
        )
        != (
            second_entries[name]["size"],
            second_entries[name]["crc32"],
        )
    )
    added = [{"entry": name, "second": second_entries[name]} for name in added_names]
    removed = [{"entry": name, "first": first_entries[name]} for name in removed_names]
    changed = [
        {"entry": name, "first": first_entries[name], "second": second_entries[name]}
        for name in changed_names
    ]
    return {
        "first": str(first),
        "second": str(second),
        "same": not added_names and not removed_names and not changed_names,
        "counts": {
            "added": len(added_names),
            "removed": len(removed_names),
            "changed": len(changed_names),
        },
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "truncated": any(
            len(items) > limit for items in (added_names, removed_names, changed_names)
        ),
    }


@mcp.tool()
def capture_compare_calls(
    first_file: str,
    second_file: str,
    process_index: int = 0,
    limit: int = 200,
    max_records: int = 10_000,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Compare saved call traffic by index and bounded payload fingerprints."""
    if process_index < 0:
        raise ValueError("process_index must be non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)

    def load(file_path: str) -> dict[str, Any]:
        try:
            return capture_call_records(
                file_path,
                process_index=process_index,
                limit=max_records,
                include_data=True,
                max_data_bytes=max_data_bytes,
                resolve_definitions=resolve_definitions,
            )
        except FileNotFoundError:
            path = _capture_path(file_path)
            return {
                "file": str(path),
                "architecture": "x86" if path.suffix.lower() == ".apmx86" else "x64",
                "count": 0,
                "records": [],
                "truncated": False,
            }

    def signature(record: dict[str, Any]) -> tuple[Any, ...]:
        definition = record.get("definition", {})
        refs = []
        for reference in record.get("data_refs", []):
            payload = reference.get("payload", {})
            refs.append(
                (
                    reference.get("slot"),
                    reference.get("length"),
                    payload.get("sha256"),
                    reference.get("valid"),
                )
            )
        return (
            record.get("flags"),
            definition.get("offset"),
            definition.get("name"),
            definition.get("module"),
            tuple(refs),
        )

    def summary(record: dict[str, Any]) -> dict[str, Any]:
        definition = record.get("definition", {})
        return {
            "index": record.get("index"),
            "flags": record.get("flags"),
            "definition": {
                key: definition.get(key)
                for key in ("offset", "name", "module", "ordinal")
                if key in definition
            },
            "data_refs": [
                {
                    key: reference.get(key)
                    for key in ("slot", "offset", "length", "valid", "error")
                    if key in reference
                }
                | ({"sha256": reference["payload"]["sha256"]} if reference.get("payload") else {})
                for reference in record.get("data_refs", [])
            ],
        }

    first = load(first_file)
    second = load(second_file)
    first_records = first.get("records", [])
    second_records = second.get("records", [])
    added = []
    removed = []
    changed = []
    for index in range(min(len(first_records), len(second_records))):
        if signature(first_records[index]) != signature(second_records[index]):
            changed.append(
                {
                    "index": index,
                    "first": summary(first_records[index]),
                    "second": summary(second_records[index]),
                }
            )
    for index in range(len(first_records), len(second_records)):
        added.append(summary(second_records[index]))
    for index in range(len(second_records), len(first_records)):
        removed.append(summary(first_records[index]))
    return {
        "first": first.get("file"),
        "second": second.get("file"),
        "process_index": process_index,
        "architectures": {
            "first": first.get("architecture"),
            "second": second.get("architecture"),
        },
        "counts": {
            "first": first.get("count", len(first_records)),
            "second": second.get("count", len(second_records)),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "truncated": any(
            len(items) > limit for items in (added, removed, changed)
        ) or first.get("truncated", False) or second.get("truncated", False),
        "payload_fingerprint": "sha256 when payload is within max_data_bytes",
    }


@mcp.tool()
def capture_list_entries(file_path: str, limit: int = 200) -> dict[str, Any]:
    """List files stored inside an APMX capture container."""
    limit = _limit(limit, "limit", 2000)
    entries = _zip_entries(_capture_path(file_path))
    return {"entries": entries[:limit], "count": len(entries), "truncated": len(entries) > limit}


@mcp.tool()
def capture_strings(
    file_path: str,
    query: str = "",
    limit: int = 100,
    minimum_length: int = 4,
) -> dict[str, Any]:
    """Extract/search printable ANSI and UTF-16LE strings from an APMX capture."""
    limit = _limit(limit, "limit", 2000)
    minimum_length = _limit(minimum_length, "minimum_length", 256)
    strings = _capture_strings(_capture_path(file_path), query, limit, minimum_length)
    return {"query": query, "strings": strings, "count": len(strings), "limit": limit}


@mcp.tool()
def capture_search_entries(
    file_path: str,
    query: str,
    limit: int = 100,
    max_entry_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Search printable strings inside each APMX ZIP entry."""
    if not query:
        raise ValueError("query must not be empty")
    limit = _limit(limit, "limit", 2000)
    max_entry_bytes = _limit(max_entry_bytes, "max_entry_bytes", 64 * 1024 * 1024)
    path = _capture_path(file_path)
    archive, _, _ = _open_capture_zip(path)
    matches: list[dict[str, Any]] = []
    truncated = False
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            with archive.open(info) as member:
                data = member.read(max_entry_bytes + 1)
            entry_matches = _scan_strings(data[:max_entry_bytes], query, min(20, limit), 4)
            if entry_matches:
                matches.append(
                    {
                        "entry": info.filename,
                        "matches": entry_matches,
                        "entry_truncated": len(data) > max_entry_bytes,
                    }
                )
                if len(matches) > limit:
                    truncated = True
                    break
    returned = matches[:limit]
    return {
        "file": str(path),
        "query": query,
        "entries": returned,
        "count": len(returned),
        "truncated": truncated,
    }


@mcp.tool()
def capture_read_entry(file_path: str, entry_name: str, max_bytes: int = 1_048_576) -> dict[str, Any]:
    """Read one APMX ZIP entry, returning text when printable or base64 otherwise."""
    max_bytes = _limit(max_bytes, "max_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
        with archive.open(info) as member:
            data = member.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    payload = _read_payload(data[:max_bytes])
    return {
        "entry": entry_name,
        "size": info.file_size,
        "returned_bytes": min(len(data), max_bytes),
        "truncated": truncated or info.file_size > max_bytes,
        **payload,
    }


@mcp.tool()
def capture_xml_entry(
    file_path: str,
    entry_name: str = "filter/display.xml",
    query: str = "",
    limit: int = 1000,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Parse one bounded XML entry, such as an APMX display/filter tree."""
    if not entry_name:
        raise ValueError("entry_name must not be empty")
    limit = _limit(limit, "limit", 20_000)
    max_bytes = _limit(max_bytes, "max_bytes", 64 * 1024 * 1024)
    path = _capture_path(file_path)
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
        if info.is_dir():
            raise IsADirectoryError(f"ZIP entry is a directory: {entry_name}")
        with archive.open(info) as member:
            data = member.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"XML entry exceeds max_bytes: {info.file_size}")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid XML entry: {entry_name}") from exc
    nodes, matched = _xml_entry_nodes(root, query, limit)
    root_tag = root.tag.rsplit("}", 1)[-1] if isinstance(root.tag, str) else str(root.tag)
    return {
        "file": str(path),
        "entry": entry_name,
        "size": info.file_size,
        "root": root_tag,
        "query": query,
        "nodes": nodes,
        "count": matched,
        "truncated": matched > limit,
        "format": "XML element stream; node indexes preserve document order",
    }


@mcp.tool()
def capture_call_records(
    file_path: str,
    process_index: int = 0,
    start_index: int = 0,
    limit: int = 500,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Decode saved process call offsets and their raw data references."""
    if process_index < 0 or start_index < 0:
        raise ValueError("process_index and start_index must be non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    calls_name = f"process/{process_index}/calls"
    data_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            calls = archive.read(calls_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {calls_name}") from exc
        try:
            data = archive.read(data_name)
        except KeyError:
            data = b""
        definitions = archive.read("definitions") if resolve_definitions and "definitions" in archive.namelist() else None
    if len(calls) % pointer_size:
        raise ValueError(
            f"process calls entry is not an array of {pointer_size * 8}-bit offsets"
        )
    count = len(calls) // pointer_size
    if start_index > count:
        raise IndexError(f"start_index {start_index} is outside {count} saved calls")
    records = _capture_call_records(
        calls,
        data,
        limit,
        include_data,
        max_data_bytes,
        start_index=start_index,
        definitions=definitions,
        pointer_size=pointer_size,
    )
    return {
        "file": str(path),
        "process_index": process_index,
        "calls_entry": calls_name,
        "data_entry": data_name if data else None,
        "call_entry_bytes": len(calls),
        "data_entry_bytes": len(data),
        "definitions_available": definitions is not None,
        "architecture": "x86" if pointer_size == 4 else "x64",
        "count": count,
        "start_index": start_index,
        "end_index": records[-1]["index"] if records else None,
        "records": records,
        "truncated": start_index + len(records) < count,
        "format": (
            "APMX process call offset stream with definition resolution"
            if definitions is not None
            else "APMX process call offset stream; enable resolve_definitions when the definitions entry is present"
        ),
    }


@mcp.tool()
def capture_read_definition(file_path: str, definition_offset: int) -> dict[str, Any]:
    """Resolve one API definition node from an APMX definitions entry."""
    if definition_offset < 0:
        raise ValueError("definition_offset must be non-negative")
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            definitions = archive.read("definitions")
        except KeyError as exc:
            raise FileNotFoundError("Capture definitions entry not found") from exc
    definition = _capture_definition_info(definitions, definition_offset, pointer_size)
    return {
        "file": str(path),
        "architecture": "x86" if pointer_size == 4 else "x64",
        "definitions_bytes": len(definitions),
        "definition": definition,
    }


@mcp.tool()
def capture_read_type(file_path: str, type_offset: int) -> dict[str, Any]:
    """Resolve one type descriptor from an APMX definitions entry."""
    if type_offset < 0:
        raise ValueError("type_offset must be non-negative")
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            definitions = archive.read("definitions")
        except KeyError as exc:
            raise FileNotFoundError("Capture definitions entry not found") from exc
    type_info = _capture_type_info(definitions, type_offset, pointer_size)
    return {
        "file": str(path),
        "architecture": "x86" if pointer_size == 4 else "x64",
        "definitions_bytes": len(definitions),
        "type": type_info,
        "valid": type_info is not None,
    }


@mcp.tool()
def capture_export_calls(
    file_path: str,
    output_path: str,
    process_index: int = 0,
    start_index: int = 0,
    limit: int = 500,
    output_format: str = "json",
    include_data: bool = True,
    max_data_bytes: int = 4096,
    overwrite: bool = False,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Export a bounded saved call-record page as JSON or CSV."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")
    result = capture_call_records(
        file_path,
        process_index=process_index,
        start_index=start_index,
        limit=limit,
        include_data=include_data,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
    )
    if output_format == "json":
        content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    else:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(
            [
                "process_index",
                "record_index",
                "offset",
                "size",
                "valid",
                "flags",
                "definition_offset",
                "api_name",
                "api_module",
                "thread_id",
                "thread_number",
                "timestamp_utc",
                "duration_seconds",
                "error_code",
                "slot",
                "data_offset",
                "length",
                "encoding",
                "payload",
            ]
        )
        for record in result["records"]:
            references = record.get("data_refs", []) or [{}]
            definition = record.get("definition", {})
            context = record.get("context", {})
            for reference in references:
                payload = reference.get("payload", {})
                writer.writerow(
                    [
                        process_index,
                        record["index"],
                        record["offset"],
                        record["size"],
                        record["valid"],
                        record["flags"],
                        record.get("definition_offset", ""),
                        definition.get("name", ""),
                        definition.get("module", ""),
                        context.get("thread_id", ""),
                        context.get("thread_number", ""),
                        context.get("timestamp_utc", ""),
                        context.get("duration_seconds", ""),
                        context.get("error_code", ""),
                        reference.get("slot", ""),
                        reference.get("offset", ""),
                        reference.get("length", ""),
                        payload.get("encoding", ""),
                        payload.get("text", payload.get("base64", "")),
                    ]
                )
        content = stream.getvalue()
    encoded = content.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    try:
        mode = "wb" if overwrite else "xb"
        with output.open(mode) as handle:
            handle.write(encoded)
    except Exception:
        if output.exists() and not overwrite:
            output.unlink()
        raise
    return {
        "exported": True,
        "file": result["file"],
        "output": str(output),
        "format": output_format,
        "process_index": process_index,
        "start_index": result["start_index"],
        "end_index": result["end_index"],
        "count": len(result["records"]),
        "truncated": result["truncated"],
        "size": len(encoded),
        "sha256": digest,
    }


@mcp.tool()
def capture_extract_call_payload(
    file_path: str,
    process_index: int,
    record_index: int,
    slot: int,
    output_path: str,
    overwrite: bool = False,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Extract one bounded raw payload referenced by a saved call record."""
    if process_index < 0 or record_index < 0:
        raise ValueError("process_index and record_index must be non-negative")
    if slot not in range(5):
        raise ValueError("slot must be between 0 and 4")
    max_bytes = _limit(max_bytes, "max_bytes", 256 * 1024 * 1024)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")

    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    calls_name = f"process/{process_index}/calls"
    data_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            calls = archive.read(calls_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {calls_name}") from exc
        try:
            data = archive.read(data_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {data_name}") from exc
    if len(calls) % pointer_size:
        raise ValueError(
            f"process calls entry is not an array of {pointer_size * 8}-bit offsets"
        )
    count = len(calls) // pointer_size
    if record_index >= count:
        raise IndexError(f"record_index {record_index} is outside {count} saved calls")
    record = _capture_call_records(
        calls,
        data,
        1,
        False,
        max_bytes,
        start_index=record_index,
        pointer_size=pointer_size,
    )[0]
    if not record["valid"]:
        raise ValueError(record.get("error", "saved call record is invalid"))
    reference = next(
        (item for item in record["data_refs"] if item["slot"] == slot), None
    )
    if not reference or not reference["length"]:
        raise ValueError(f"call record {record_index} has no payload in slot {slot}")
    if not reference["valid"]:
        raise ValueError(reference.get("error", "saved call payload is invalid"))
    if reference["length"] > max_bytes:
        raise ValueError(f"call payload exceeds max_bytes: {reference['length']}")
    payload = data[reference["offset"] : reference["offset"] + reference["length"]]
    digest = hashlib.sha256(payload).hexdigest()
    try:
        mode = "wb" if overwrite else "xb"
        with output.open(mode) as handle:
            handle.write(payload)
    except Exception:
        if output.exists() and not overwrite:
            output.unlink()
        raise
    return {
        "extracted": True,
        "file": str(path),
        "process_index": process_index,
        "record_index": record_index,
        "slot": slot,
        "data_offset": reference["offset"],
        "size": len(payload),
        "output": str(output),
        "sha256": digest,
    }


@mcp.tool()
def capture_read_process_data(
    file_path: str,
    process_index: int,
    offset: int = 0,
    length: int = 4096,
) -> dict[str, Any]:
    """Read a bounded logical slice from a saved process data entry."""
    if process_index < 0 or offset < 0:
        raise ValueError("process_index and offset must be non-negative")
    length = _limit(length, "length", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    entry_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture data entry not found: {entry_name}") from exc
        if offset > info.file_size:
            raise ValueError(f"offset {offset} is outside {info.file_size}-byte data entry")
        with archive.open(info) as member:
            member.seek(offset)
            data = member.read(length + 1)
    returned = data[:length]
    payload = _read_payload(returned)
    return {
        "file": str(path),
        "process_index": process_index,
        "entry": entry_name,
        "entry_size": info.file_size,
        "offset": offset,
        "returned_bytes": len(returned),
        "truncated": len(data) > length,
        **payload,
    }


@mcp.tool()
def capture_decode_call(
    file_path: str,
    process_index: int,
    record_index: int,
    max_data_bytes: int = 4096,
    max_items: int = 64,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Return one saved call with exact encoded args plus bounded candidates."""
    if process_index < 0 or record_index < 0:
        raise ValueError("process_index and record_index must be non-negative")
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    max_items = _limit(max_items, "max_items", 256)
    result = capture_call_records(
        file_path,
        process_index=process_index,
        start_index=record_index,
        limit=1,
        include_data=True,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
    )
    if not result["records"]:
        raise IndexError(f"record_index {record_index} is outside saved calls")
    record = result["records"][0]
    for reference in record.get("data_refs", []):
        payload = reference.get("payload")
        if payload is None:
            reference["decoding"] = {
                "heuristic": True,
                "skipped": "payload exceeds max_data_bytes",
            }
            continue
        raw = _payload_bytes(payload)
        reference["decoding"] = _capture_payload_candidates(raw, max_items)
    slot0 = next(
        (
            reference.get("payload")
            for reference in record.get("data_refs", [])
            if reference.get("slot") == 0
        ),
        None,
    )
    definition = record.get("definition", {})
    if slot0 is None:
        argument_stream = {
            "format": "APMX encoded parameter stream",
            "valid": False,
            "error": "call has no bounded slot-0 payload",
        }
    else:
        argument_stream = _capture_decoded_argument_stream(
            _payload_bytes(slot0), definition, max_items, max_data_bytes
        )
    return_reference = next(
        (
            reference
            for reference in record.get("data_refs", [])
            if reference.get("slot") == 2
        ),
        None,
    )
    return_value: dict[str, Any]
    if not return_reference or return_reference.get("payload") is None:
        return_value = {
            "available": False,
            "reason": "call has no bounded slot-2 return payload",
        }
    else:
        return_payload = return_reference["payload"]
        return_value = {"available": True, "payload": return_payload}
        return_raw = _payload_bytes(return_payload)
        return_type = definition.get("return_type")
        if return_type:
            try:
                definition_flags = int(definition.get("flags", "0"), 0)
            except (TypeError, ValueError):
                definition_flags = 0
            exact = _capture_exact_value(
                return_raw, return_type, machine_flag=bool(definition_flags & 8)
            )
            if exact:
                return_value["typed"] = exact
            return_value["type"] = return_type
    return {
        "file": result["file"],
        "process_index": process_index,
        "record_index": record_index,
        "record": record,
        "argument_stream": argument_stream,
        "return_value": return_value,
        "definitions_available": result["definitions_available"],
        "format": "APMX encoded parameter table; recognized scalar, string, structure, array, and enum values are exact, other values remain heuristic",
    }


@mcp.tool()
def capture_call_stats(
    file_path: str,
    process_index: int | None = None,
    max_records: int = 1_000_000,
) -> dict[str, Any]:
    """Summarize saved raw call streams without returning every record."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    with archive:
        entries = {info.filename for info in archive.infolist()}
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.I))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        processes = []
        for index in process_indices:
            calls_name = f"process/{index}/calls"
            data_name = f"process/{index}/data"
            calls = archive.read(calls_name)
            data = archive.read(data_name) if data_name in entries else b""
            stats = _capture_call_stats(calls, data, max_records, pointer_size)
            processes.append(
                {
                    "process_index": index,
                    "calls_entry": calls_name,
                    "data_entry": data_name if data else None,
                    **stats,
                }
            )
    totals = {
        "count": sum(process["count"] for process in processes),
        "scanned_records": sum(process["scanned_records"] for process in processes),
        "valid_records": sum(process["valid_records"] for process in processes),
        "invalid_records": sum(process["invalid_records"] for process in processes),
        "data_bytes": sum(process["data_bytes"] for process in processes),
        "referenced_data_bytes": sum(process["referenced_data_bytes"] for process in processes),
    }
    totals["unreferenced_data_bytes"] = max(0, totals["data_bytes"] - totals["referenced_data_bytes"])
    return {
        "file": str(path),
        "process_index": process_index,
        "max_records": max_records,
        "processes": processes,
        "totals": totals,
        "count": len(processes),
    }


@mcp.tool()
def capture_list_apis(
    file_path: str,
    process_index: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
) -> dict[str, Any]:
    """List resolved API definitions ordered by saved call frequency."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    apis: dict[int, dict[str, Any]] = {}
    scanned = 0
    truncated = False
    with archive:
        entries = {info.filename for info in archive.infolist()}
        if "definitions" not in entries:
            return {
                "file": str(path),
                "process_index": process_index,
                "definitions_available": False,
                "apis": [],
                "count": 0,
                "scanned_records": 0,
                "truncated": False,
            }
        definitions = archive.read("definitions")
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.I))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            calls = archive.read(f"process/{index}/calls")
            data_name = f"process/{index}/data"
            data = archive.read(data_name) if data_name in entries else b""
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count
            records = _capture_call_records(
                calls,
                data,
                page_count,
                False,
                0,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            for record in records:
                scanned += 1
                definition = record.get("definition", {})
                if not definition.get("valid"):
                    continue
                offset = definition["offset"]
                item = apis.setdefault(
                    offset,
                    {
                        "offset": offset,
                        "name": definition.get("name"),
                        "module": definition.get("module"),
                        "ordinal": definition.get("ordinal"),
                        "count": 0,
                        "process_indices": [],
                        "first_record": record["index"],
                        "last_record": record["index"],
                        "_thread_ids": set(),
                        "_timestamps": [],
                        "_durations": [],
                        "_error_count": 0,
                    },
                )
                item["count"] += 1
                if index not in item["process_indices"]:
                    item["process_indices"].append(index)
                item["first_record"] = min(item["first_record"], record["index"])
                item["last_record"] = max(item["last_record"], record["index"])
                context = record.get("context", {})
                item["_thread_ids"].add(context.get("thread_id", 0))
                if context.get("timestamp_filetime"):
                    item["_timestamps"].append(context["timestamp_filetime"])
                if context.get("duration_valid"):
                    item["_durations"].append(context["duration_seconds"])
                if context.get("error_code"):
                    item["_error_count"] += 1
            if scanned >= max_records:
                break
    for item in apis.values():
        timestamps = item.pop("_timestamps")
        durations = item.pop("_durations")
        item["context"] = {
            "thread_count": len(item.pop("_thread_ids")),
            "duration_count": len(durations),
            "error_count": item.pop("_error_count"),
            "first_timestamp_utc": _windows_filetime(min(timestamps)) if timestamps else None,
            "last_timestamp_utc": _windows_filetime(max(timestamps)) if timestamps else None,
        }
        if durations:
            item["context"]["duration_seconds"] = {
                "minimum": min(durations),
                "maximum": max(durations),
                "average": sum(durations) / len(durations),
            }
    returned = sorted(apis.values(), key=lambda item: (-item["count"], item["name"] or ""))
    return {
        "file": str(path),
        "process_index": process_index,
        "definitions_available": True,
        "apis": returned[:limit],
        "count": len(returned),
        "scanned_records": scanned,
        "truncated": truncated or len(returned) > limit,
    }


@mcp.tool()
def capture_search_calls(
    file_path: str,
    query: str,
    process_index: int | None = None,
    limit: int = 100,
    max_records: int = 100_000,
    max_data_bytes: int = 16_384,
    resolve_definitions: bool = False,
    decode_arguments: bool = False,
) -> dict[str, Any]:
    """Search saved call payloads, API definitions, and decoded arguments."""
    if not query:
        raise ValueError("query must not be empty")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    wanted = query.casefold()
    matches: list[dict[str, Any]] = []
    scanned = 0
    scan_truncated = False
    process_indices: set[int] = set()
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        for name in entries:
            match = re.fullmatch(r"process/(\d+)/calls", name, re.I)
            if match and (process_index is None or int(match.group(1)) == process_index):
                process_indices.add(int(match.group(1)))
        for index in sorted(process_indices):
            calls = archive.read(f"process/{index}/calls")
            data = archive.read(f"process/{index}/data") if f"process/{index}/data" in entries else b""
            definitions = archive.read("definitions") if resolve_definitions and "definitions" in entries else None
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            if scanned + record_count > max_records:
                scan_truncated = True
            records = _capture_call_records(
                calls,
                data,
                min(record_count, max_records - scanned),
                True,
                max_data_bytes,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            for record in records:
                scanned += 1
                payload_matches = []
                for reference in record.get("data_refs", []):
                    text = reference.get("payload", {}).get("text")
                    if text is None or wanted not in text.casefold():
                        continue
                    position = text.casefold().find(wanted)
                    start = max(0, position - 120)
                    end = min(len(text), position + len(query) + 120)
                    payload_matches.append(
                        {
                            "slot": reference["slot"],
                            "offset": reference["offset"],
                            "length": reference["length"],
                            "snippet": text[start:end],
                        }
                    )
                definition = record.get("definition", {})
                api_matches = []
                api_text = f"{definition.get('name', '')} {definition.get('module', '')}"
                if definition.get("valid") and wanted in api_text.casefold():
                    api_matches.append(
                        {
                            "name": definition.get("name"),
                            "module": definition.get("module"),
                            "ordinal": definition.get("ordinal"),
                            "offset": definition.get("offset"),
                        }
                    )
                argument_matches = []
                if decode_arguments:
                    slot0 = next(
                        (
                            reference.get("payload")
                            for reference in record.get("data_refs", [])
                            if reference.get("slot") == 0
                        ),
                        None,
                    )
                    if slot0 is not None:
                        argument_stream = _capture_decoded_argument_stream(
                            _payload_bytes(slot0), definition, 256, max_data_bytes
                        )
                        for argument in argument_stream.get("arguments", []):
                            payload = argument.get("payload", {})
                            typed = argument.get("typed", {})
                            searchable = " ".join(
                                str(value)
                                for value in (
                                    argument.get("name", ""),
                                    payload.get("text", ""),
                                    payload.get("hex_preview", ""),
                                    typed.get("value", ""),
                                    json.dumps(typed, ensure_ascii=False),
                                )
                                if value != ""
                            )
                            if wanted in searchable.casefold():
                                argument_matches.append(argument)
                if payload_matches or api_matches or argument_matches:
                    match = {
                        "process_index": index,
                        "record": record,
                        "payload_matches": payload_matches,
                    }
                    if api_matches:
                        match["api_matches"] = api_matches
                    if argument_matches:
                        match["argument_matches"] = argument_matches
                    matches.append(
                        match
                    )
                    if len(matches) >= limit:
                        return {
                            "file": str(path),
                            "query": query,
                            "process_index": process_index,
                            "matches": matches,
                            "count": len(matches),
                            "scanned_records": scanned,
                            "truncated": True,
                            "arguments_decoded": decode_arguments,
                        }
            if scanned >= max_records:
                break
    return {
        "file": str(path),
        "query": query,
        "process_index": process_index,
        "matches": matches,
        "count": len(matches),
        "scanned_records": scanned,
        "truncated": scan_truncated,
        "definitions_resolved": resolve_definitions,
        "arguments_decoded": decode_arguments,
    }


@mcp.tool()
def capture_filter_calls(
    file_path: str,
    process_index: int | None = None,
    thread_id: int | None = None,
    error_code: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    limit: int = 500,
    max_records: int = 100_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Filter saved calls by verified thread, error, and duration context."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if thread_id is not None and not 0 <= thread_id <= 0xFFFFFFFF:
        raise ValueError("thread_id must be between 0 and 4294967295")
    if error_code is not None and not 0 <= error_code <= 0xFFFFFFFF:
        raise ValueError("error_code must be between 0 and 4294967295")
    if min_duration_seconds is not None and (
        not math.isfinite(min_duration_seconds) or min_duration_seconds < 0
    ):
        raise ValueError("min_duration_seconds must be finite and non-negative")
    if max_duration_seconds is not None and (
        not math.isfinite(max_duration_seconds) or max_duration_seconds < 0
    ):
        raise ValueError("max_duration_seconds must be finite and non-negative")
    if (
        min_duration_seconds is not None
        and max_duration_seconds is not None
        and min_duration_seconds > max_duration_seconds
    ):
        raise ValueError("min_duration_seconds must not exceed max_duration_seconds")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    matches: list[dict[str, Any]] = []
    scanned = 0
    scan_truncated = False
    with archive:
        entries = {info.filename for info in archive.infolist()}
        definitions = archive.read("definitions") if resolve_definitions and "definitions" in entries else None
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.I))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            calls = archive.read(f"process/{index}/calls")
            data_name = f"process/{index}/data"
            data = archive.read(data_name) if data_name in entries else b""
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            scan_truncated |= page_count < record_count
            records = _capture_call_records(
                calls,
                data,
                page_count,
                include_data,
                max_data_bytes,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            scanned += len(records)
            for record in records:
                context = record.get("context")
                if context is None:
                    continue
                duration = context.get("duration_seconds") if context.get("duration_valid") else None
                if duration is not None and not math.isfinite(duration):
                    duration = None
                if thread_id is not None and context.get("thread_id") != thread_id:
                    continue
                if error_code is not None and context.get("error_code") != error_code:
                    continue
                if min_duration_seconds is not None and (
                    duration is None or duration < min_duration_seconds
                ):
                    continue
                if max_duration_seconds is not None and (
                    duration is None or duration > max_duration_seconds
                ):
                    continue
                matches.append({"process_index": index, "record": record})
                if len(matches) >= limit:
                    return {
                        "file": str(path),
                        "process_index": process_index,
                        "filters": {
                            "thread_id": thread_id,
                            "error_code": error_code,
                            "min_duration_seconds": min_duration_seconds,
                            "max_duration_seconds": max_duration_seconds,
                        },
                        "matches": matches,
                        "count": len(matches),
                        "scanned_records": scanned,
                        "truncated": True,
                        "definitions_resolved": resolve_definitions,
                    }
            if scanned >= max_records:
                break
    return {
        "file": str(path),
        "process_index": process_index,
        "filters": {
            "thread_id": thread_id,
            "error_code": error_code,
            "min_duration_seconds": min_duration_seconds,
            "max_duration_seconds": max_duration_seconds,
        },
        "matches": matches,
        "count": len(matches),
        "scanned_records": scanned,
        "truncated": scan_truncated,
        "definitions_resolved": resolve_definitions,
    }


@mcp.tool()
def capture_calls_around(
    file_path: str,
    process_index: int,
    record_index: int,
    before: int = 5,
    after: int = 5,
    include_data: bool = True,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Return a bounded raw call-record window around one saved call."""
    if process_index < 0 or record_index < 0:
        raise ValueError("process_index and record_index must be non-negative")
    if not 0 <= before <= 1000 or not 0 <= after <= 1000:
        raise ValueError("before and after must be between 0 and 1000")
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    calls_name = f"process/{process_index}/calls"
    data_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        entries = {info.filename for info in archive.infolist()}
        try:
            calls = archive.read(calls_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {calls_name}") from exc
        data = archive.read(data_name) if data_name in entries else b""
        definitions = archive.read("definitions") if resolve_definitions and "definitions" in entries else None
    if len(calls) % pointer_size:
        raise ValueError(
            f"process calls entry is not an array of {pointer_size * 8}-bit offsets"
        )
    count = len(calls) // pointer_size
    if record_index >= count:
        raise IndexError(f"record_index {record_index} is outside {count} saved calls")
    start = max(0, record_index - before)
    end = min(count, record_index + after + 1)
    records = _capture_call_records(
        calls,
        data,
        end - start,
        include_data,
        max_data_bytes,
        start_index=start,
        definitions=definitions,
        pointer_size=pointer_size,
    )
    for record in records:
        record["is_target"] = record["index"] == record_index
    return {
        "file": str(path),
        "process_index": process_index,
        "record_index": record_index,
        "before": before,
        "after": after,
        "calls_entry": calls_name,
        "data_entry": data_name if data else None,
        "count": count,
        "window_start": start,
        "window_end": end - 1,
        "records": records,
        "format": (
            "APMX process call offset stream with definition resolution"
            if resolve_definitions and definitions is not None
            else "APMX process call offset stream; enable resolve_definitions when the definitions entry is present"
        ),
    }


@mcp.tool()
def capture_extract_entry(
    file_path: str,
    entry_name: str,
    output_path: str,
    overwrite: bool = False,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Extract one bounded APMX ZIP entry to a caller-selected file."""
    if not entry_name:
        raise ValueError("entry_name must not be empty")
    max_bytes = _limit(max_bytes, "max_bytes", 256 * 1024 * 1024)
    path = _capture_path(file_path)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
        if info.is_dir():
            raise IsADirectoryError(f"ZIP entry is a directory: {entry_name}")
        if info.file_size > max_bytes:
            raise ValueError(f"ZIP entry exceeds max_bytes: {info.file_size}")
        if output.exists() and not overwrite:
            raise FileExistsError(f"Output already exists: {output}")
        digest = hashlib.sha256()
        written = 0
        try:
            mode = "wb" if overwrite else "xb"
            with archive.open(info) as member, output.open(mode) as handle:
                while chunk := member.read(1024 * 1024):
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError("ZIP entry exceeded max_bytes while extracting")
                    digest.update(chunk)
                    handle.write(chunk)
        except Exception:
            if output.exists() and not overwrite:
                output.unlink()
            raise
    return {
        "extracted": True,
        "file": str(path),
        "entry": entry_name,
        "output": str(output),
        "size": written,
        "sha256": digest.hexdigest(),
    }


@mcp.tool()
def capture_monitoring_log(
    file_path: str,
    query: str = "",
    limit: int = 1000,
) -> dict[str, Any]:
    """Read and search the monitoring log stored in an APMX capture."""
    limit = _limit(limit, "limit", 10_000)
    result = capture_read_entry(file_path, "log/monitoring.txt", 16 * 1024 * 1024)
    text = result.get("text")
    if text is None:
        raise ValueError("Capture monitoring log is not text")
    text = text.lstrip("\ufeff")
    needle = query.casefold()
    lines = [
        line.rstrip("\r")
        for line in text.splitlines()
        if not needle or needle in line.casefold()
    ]
    returned = lines[:limit]
    return {
        "file": str(_capture_path(file_path)),
        "query": query,
        "lines": returned,
        "events": [
            {"line": line, **_monitoring_event(line)}
            for line in returned
        ],
        "count": len(lines),
        "truncated": len(lines) > limit,
    }


@mcp.tool()
def capture_list_processes(file_path: str, limit: int = 200) -> dict[str, Any]:
    """List process records and executable paths recoverable from an APMX capture."""
    limit = _limit(limit, "limit", 2000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    processes: list[dict[str, Any]] = []
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        for info in entries.values():
            match = PROCESS_INFO.fullmatch(info.filename)
            if not match:
                continue
            index = int(match.group(1))
            data = archive.read(info)
            strings = _scan_strings(data, "", 2000, 4)
            modules = []
            executables = []
            for item in strings:
                value = item["text"].strip("\x00")
                if not value.casefold().endswith((".dll", ".exe")):
                    continue
                if value not in modules:
                    modules.append(value)
                if value.casefold().endswith(".exe") and value not in executables:
                    executables.append(value)
            try:
                metadata = _parse_capture_process_info(data, pointer_size)
            except ValueError as exc:
                metadata = {"parse_error": str(exc)}
            processes.append(
                {
                    "index": index,
                    "entry": info.filename,
                    "size": info.file_size,
                    "modules": modules,
                    "executables": executables,
                    "calls_entry": f"process/{index}/calls" if f"process/{index}/calls" in entries else None,
                    "data_entry": f"process/{index}/data" if f"process/{index}/data" in entries else None,
                    "call_count": entries[f"process/{index}/calls"].file_size // pointer_size
                    if f"process/{index}/calls" in entries
                    and entries[f"process/{index}/calls"].file_size % pointer_size == 0
                    else None,
                    "data_size": entries[f"process/{index}/data"].file_size
                    if f"process/{index}/data" in entries
                    else 0,
                    "metadata": metadata,
                }
            )
    processes.sort(key=lambda item: item["index"])
    return {
        "file": str(path),
        "processes": processes[:limit],
        "count": len(processes),
        "truncated": len(processes) > limit,
    }


@mcp.tool()
def capture_hex(file_path: str, offset: int = 0, length: int = 256) -> dict[str, Any]:
    """Return a bounded hex/ASCII view of raw bytes from an APMX capture."""
    if offset < 0:
        raise ValueError("offset must be non-negative")
    length = _limit(length, "length", 4096)
    path = _capture_path(file_path)
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    return {
        "offset": offset,
        "length": len(data),
        "hex": data.hex(" "),
        "ascii": "".join(chr(value) if 32 <= value < 127 else "." for value in data),
    }


@mcp.tool()
def capture_find_bytes(
    file_path: str,
    pattern_hex: str,
    limit: int = 1000,
    start_offset: int = 0,
) -> dict[str, Any]:
    """Find a hexadecimal byte pattern in an APMX file and return raw offsets."""
    if not pattern_hex.strip():
        raise ValueError("pattern_hex must not be empty")
    limit = _limit(limit, "limit", 10_000)
    if start_offset < 0:
        raise ValueError("start_offset must be non-negative")
    try:
        pattern = bytes.fromhex(pattern_hex)
    except ValueError as exc:
        raise ValueError("pattern_hex must contain hexadecimal bytes") from exc
    if not pattern or len(pattern) > 256:
        raise ValueError("pattern_hex must contain between 1 and 256 bytes")
    path = _capture_path(file_path)
    offsets: list[int] = []
    truncated = False
    with path.open("rb") as handle:
        if start_offset >= path.stat().st_size:
            return {"file": str(path), "pattern_hex": pattern.hex(" "), "offsets": [], "count": 0}
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            offset = data.find(pattern, start_offset)
            while offset >= 0:
                if len(offsets) >= limit:
                    truncated = True
                    break
                offsets.append(offset)
                offset = data.find(pattern, offset + 1)
    return {
        "file": str(path),
        "pattern_hex": pattern.hex(" "),
        "start_offset": start_offset,
        "offsets": offsets,
        "count": len(offsets),
        "truncated": truncated,
    }


@mcp.tool()
def capture_list_directory(
    directory: str,
    recursive: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    """List Rohitab APMX captures in a directory."""
    limit = _limit(limit, "limit", 5000)
    root = _capture_directory(directory)
    paths = root.rglob("*") if recursive else root.glob("*")
    captures = []
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in CAPTURE_SUFFIXES:
            continue
        stat = path.stat()
        captures.append(
            {
                "file": str(path.resolve()),
                "architecture": "x86" if path.suffix.lower() == ".apmx86" else "x64",
                "size": stat.st_size,
                "modified_utc": _file_time(path),
            }
        )
    captures.sort(key=lambda item: item["modified_utc"], reverse=True)
    return {
        "directory": str(root),
        "recursive": recursive,
        "captures": captures[:limit],
        "count": len(captures),
        "truncated": len(captures) > limit,
    }


@mcp.tool()
def capture_search_directory(
    directory: str,
    query: str,
    recursive: bool = True,
    limit: int = 100,
) -> dict[str, Any]:
    """Search printable strings across all APMX captures in a directory."""
    if not query:
        raise ValueError("query must not be empty")
    limit = _limit(limit, "limit", 1000)
    root = _capture_directory(directory)
    listed = capture_list_directory(str(root), recursive, 5000)["captures"]
    matches: list[dict[str, Any]] = []
    for capture in listed:
        path = Path(capture["file"])
        strings = _capture_strings(path, query, min(20, limit), 4)
        entries = capture_search_entries(str(path), query, min(20, limit), 4 * 1024 * 1024)["entries"]
        if strings or entries:
            matches.append({"file": str(path), "matches": strings, "entries": entries})
            if len(matches) >= limit:
                break
    return {"directory": str(root), "query": query, "captures": matches, "count": len(matches)}


@mcp.tool()
def api_monitor_search_apis(
    query: str,
    limit: int = 100,
    install_root: str | None = None,
) -> dict[str, Any]:
    """Search Rohitab API Monitor's installed XML API definitions."""
    if not query.strip():
        raise ValueError("query must not be empty")
    limit = _limit(limit, "limit", 2000)
    api_root = _app_root(install_root) / "API"
    if not api_root.is_dir():
        raise FileNotFoundError(f"API definition directory not found: {api_root}")

    needle = query.casefold()
    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for xml_path in sorted(api_root.rglob("*.xml")):
        try:
            text = xml_path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        module_match = MODULE_NAME.search(text)
        module = module_match.group(1) if module_match else xml_path.stem
        for match in API_NAME.finditer(text):
            name = match.group(1)
            if needle not in name.casefold() and needle not in module.casefold():
                continue
            key = (module, name)
            if key in seen:
                continue
            seen.add(key)
            results.append({"name": name, "module": module, "definition": str(xml_path)})
            if len(results) >= limit:
                return {"query": query, "results": results, "count": len(results), "truncated": True}
    return {"query": query, "results": results, "count": len(results), "truncated": False}


def _api_definition_path(definition_path: str, install_root: str | None = None) -> Path:
    api_root = (_app_root(install_root) / "API").resolve()
    path = Path(definition_path).expanduser().resolve()
    try:
        path.relative_to(api_root)
    except ValueError as exc:
        raise ValueError("definition_path must be inside Rohitab's API directory") from exc
    if path.suffix.lower() != ".xml" or not path.is_file():
        raise FileNotFoundError(f"API definition not found: {path}")
    return path


@mcp.tool()
def api_monitor_parse_api_definition(
    definition_path: str,
    api_name: str = "",
    limit: int = 200,
    install_root: str | None = None,
) -> dict[str, Any]:
    """Return structured Rohitab API signatures from one XML definition."""
    limit = _limit(limit, "limit", 5000)
    path = _api_definition_path(definition_path, install_root)
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid API definition XML: {path}") from exc

    parents = {child: parent for parent in root.iter() for child in parent}
    needle = api_name.casefold()
    results: list[dict[str, Any]] = []
    for api in root.iter("Api"):
        name = api.get("Name", "")
        if needle and needle not in name.casefold():
            continue
        ancestor = parents.get(api)
        module = None
        interface = None
        module_attributes: dict[str, str] = {}
        interface_attributes: dict[str, str] = {}
        while ancestor is not None:
            if ancestor.tag == "Module" and module is None:
                module = ancestor.get("Name")
                module_attributes = dict(ancestor.attrib)
            if ancestor.tag == "Interface" and interface is None:
                interface = ancestor.get("Name")
                interface_attributes = dict(ancestor.attrib)
            ancestor = parents.get(ancestor)
        results.append(
            {
                "name": name,
                "api_attributes": dict(api.attrib),
                "module": module,
                "module_attributes": module_attributes,
                "interface": interface,
                "interface_attributes": interface_attributes,
                "params": [dict(param.attrib) for param in api.findall("Param")],
                "returns": [dict(return_value.attrib) for return_value in api.findall("Return")],
                "definition": str(path),
            }
        )
    returned = results[:limit]
    return {
        "definition": str(path),
        "api_name": api_name,
        "apis": returned,
        "count": len(returned),
        "truncated": len(results) > limit,
    }


@mcp.tool()
def api_monitor_read_api_definition(
    definition_path: str,
    max_chars: int = 100_000,
    install_root: str | None = None,
) -> dict[str, Any]:
    """Read a bounded Rohitab XML API definition returned by the API search tool."""
    max_chars = _limit(max_chars, "max_chars", 2_000_000)
    path = _api_definition_path(definition_path, install_root)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    return {
        "definition": str(path),
        "text": text[:max_chars],
        "size_chars": len(text),
        "truncated": len(text) > max_chars,
    }


def _self_test() -> None:
    with TemporaryDirectory() as directory:
        assert _capture_output_path(str(Path(directory) / "out.apmx64"), "x64").suffix == ".apmx64"
        path = Path(directory) / "sample.apmx64"
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("metadata.txt", "process=sample.exe\n")
            archive.writestr("calls.bin", b"CreateFileW\x00https://example.test\x00")
            archive.writestr(
                "filter/display.xml",
                '<DisplayFilters><Filter Field="API" Operator="contains">CreateFile</Filter></DisplayFilters>',
            )
            record = bytearray(160)
            record[0] = 1
            record[2] = 1
            struct.pack_into("<I", record, 16, 0x1234)
            struct.pack_into("<I", record, 20, 7)
            struct.pack_into("<Q", record, 48, 0x7FF600001000)
            struct.pack_into("<Q", record, 72, 132223104000000000)
            struct.pack_into("<I", record, 84, 5)
            struct.pack_into("<d", record, 96, 0.125)
            struct.pack_into("<Q", record, 40, 16)
            struct.pack_into("<I", record, 32, 5)
            struct.pack_into("<Q", record, 112, 160)
            struct.pack_into("<I", record, 92, 4)
            struct.pack_into("<Q", record, 128, 165)
            archive.writestr("process/0/calls", struct.pack("<Q", 0))
            archive.writestr("process/0/data", bytes(record) + b"hello" + struct.pack("<I", 7))
            definitions = bytearray(768)
            struct.pack_into("<I", definitions, 16 + 8, 123)
            struct.pack_into("<Q", definitions, 16 + 24, 80)
            struct.pack_into("<Q", definitions, 16 + 40, 96)
            struct.pack_into("<Q", definitions, 16 + 56, 208)
            definitions[80 : 80 + len(b"CreateFileW\x00")] = b"CreateFileW\x00"
            struct.pack_into("<Q", definitions, 96 + 16, 128)
            definitions[128 : 128 + len(b"kernel32.dll\x00")] = b"kernel32.dll\x00"
            struct.pack_into("<Q", definitions, 208, 160)
            struct.pack_into("<I", definitions, 160 + 8, 2)
            definitions[160 + 32] = 4
            definitions[240 : 240 + len(b"DWORD\x00")] = b"DWORD\x00"
            struct_type_offset = 272
            struct.pack_into("<I", definitions, struct_type_offset + 8, 11)
            struct.pack_into("<Q", definitions, struct_type_offset + 32, 320)
            definitions[struct_type_offset + 44] = 1
            struct.pack_into("<Q", definitions, 320, 400)
            struct.pack_into("<Q", definitions, 328, 160)
            definitions[400 : 400 + len(b"dwValue\x00")] = b"dwValue\x00"
            array_type_offset = 448
            struct.pack_into("<I", definitions, array_type_offset + 8, 14)
            struct.pack_into("<Q", definitions, array_type_offset + 32, 160)
            struct.pack_into("<H", definitions, array_type_offset + 40, 3)
            definitions[array_type_offset + 42] = 1
            variable_array_type_offset = 512
            struct.pack_into("<I", definitions, variable_array_type_offset + 8, 14)
            struct.pack_into("<Q", definitions, variable_array_type_offset + 32, 160)
            struct.pack_into("<H", definitions, variable_array_type_offset + 40, 2)
            enum_type_offset = 576
            struct.pack_into("<I", definitions, enum_type_offset + 8, 2)
            struct.pack_into("<Q", definitions, enum_type_offset + 24, 640)
            definitions[enum_type_offset + 32] = 4
            struct.pack_into("<Q", definitions, 640, 672)
            struct.pack_into("<H", definitions, 648, 2)
            struct.pack_into("<Q", definitions, 672, 704)
            struct.pack_into("<Q", definitions, 672 + 8, 1)
            struct.pack_into("<Q", definitions, 688, 720)
            struct.pack_into("<Q", definitions, 688 + 8, 2)
            definitions[704 : 704 + len(b"Red\x00")] = b"Red\x00"
            definitions[720 : 720 + len(b"Green\x00")] = b"Green\x00"
            fixed_struct_type_offset = 384
            struct.pack_into("<I", definitions, fixed_struct_type_offset + 8, 11)
            struct.pack_into("<Q", definitions, fixed_struct_type_offset + 32, 320)
            struct.pack_into("<H", definitions, fixed_struct_type_offset + 40, 4)
            struct.pack_into("<H", definitions, fixed_struct_type_offset + 42, 8)
            definitions[fixed_struct_type_offset + 44] = 1
            definitions[fixed_struct_type_offset + 45] = 4
            definitions[fixed_struct_type_offset + 46] = 2
            archive.writestr("definitions", bytes(definitions))
            archive.writestr(
                "log/monitoring.txt",
                "sample.exe: Monitoring Module 0x1234 -> C:\\sample.dll\n",
            )
            process_info = struct.pack("<IIIQ", 1, 0, 1234, 0x7FF600000000)
            for value in ("C:\\sample.exe", '"C:\\sample.exe" /test', "Sample Process"):
                process_info += struct.pack("<I", len(value)) + value.encode("utf-16-le")
            process_info += struct.pack("<IQQI", 0, 0, 0, 0)
            archive.writestr(
                "process/0/info",
                process_info + struct.pack("<I", zlib.crc32(process_info) & 0xFFFFFFFF),
            )
            title = "API Monitor v2 Alpha-r13 64-bit"
            info = struct.pack("<II", 2, len(title)) + title.encode("utf-16-le")
            info += struct.pack("<7I", 64, 0, 6, 2, 1, 1, 0x409)
            archive.writestr("info", info + struct.pack("<I", zlib.crc32(info) & 0xFFFFFFFF))
        path.write_bytes(b"\r\nAPI Monitor 64-bit Capture\r\nRBAPM" + payload.getvalue())
        second_path = Path(directory) / "variants" / "second.apmx64"
        second_path.parent.mkdir()
        second_payload = io.BytesIO()
        with zipfile.ZipFile(second_payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("metadata.txt", "process=changed.exe\n")
            archive.writestr("extra.bin", b"new")
        second_path.write_bytes(b"\r\nAPI Monitor 64-bit Capture\r\nRBAPM" + second_payload.getvalue())

        info = _capture_info(path)
        assert _capture_zip_offset(path) == info["zip_offset"]
        assert info["extension"] == ".apmx64"
        assert info["format_marker"] == "RBAPM"
        assert info["architecture"] == "x64"
        assert info["metadata"]["application"] == "API Monitor v2 Alpha-r13 64-bit"
        assert info["metadata"]["crc32_valid"]
        assert capture_validate(str(path))["valid"]
        deep_validation = capture_validate(str(path), deep=True)
        assert deep_validation["structural_valid"]
        assert deep_validation["process_infos"][0]["valid"]
        assert deep_validation["streams"][0]["definitions"]["resolved"] == 1
        assert capture_read_type(str(path), 160)["type"]["kind"] == 2
        invalid_prefix = Path(directory) / "invalid-prefix.apmx64"
        invalid_prefix.write_bytes(b"not-an-apmx" + path.read_bytes()[info["zip_offset"] :])
        assert not capture_validate(str(invalid_prefix))["valid"]
        invalid_prefix.unlink()
        assert info["entries"][0]["name"] == "metadata.txt"
        strings = _capture_strings(path, "CreateFile", 10, 4)
        assert strings and "CreateFileW" in strings[0]["text"]
        log = capture_monitoring_log(str(path), "module", 10)
        assert log["lines"] == ["sample.exe: Monitoring Module 0x1234 -> C:\\sample.dll"]
        assert log["events"][0]["type"] == "module"
        searched = capture_search_entries(str(path), "CreateFile", 10)
        assert searched["entries"][0]["entry"] == "calls.bin"
        assert not searched["truncated"]
        xml = capture_xml_entry(str(path), query="CreateFile")
        assert xml["root"] == "DisplayFilters"
        assert xml["nodes"][0]["attributes"]["Field"] == "API"
        call_records = capture_call_records(str(path), include_data=True)
        assert call_records["count"] == 1
        assert call_records["start_index"] == 0
        assert call_records["records"][0]["data_refs"][0]["payload"]["text"] == "hello"
        call_context = call_records["records"][0]["context"]
        assert call_context["thread_id"] == 0x1234
        assert call_context["thread_number"] == 7
        assert call_context["module_base"] == "0x00007ff600001000"
        assert call_context["error_code"] == 5
        assert call_context["timestamp_utc"] == "2020-01-01T00:00:00+00:00"
        assert call_context["duration_seconds"] == 0.125
        stats = capture_call_stats(str(path))
        assert stats["processes"][0]["context"]["error_count"] == 1
        assert stats["processes"][0]["context"]["error_codes"] == {"0x00000005": 1}
        bounded_records = bytearray(257 * 160)
        bounded_calls = b"".join(struct.pack("<Q", index * 160) for index in range(257))
        for index in range(257):
            bounded_records[index * 160 + 2] = 1
            struct.pack_into("<I", bounded_records, index * 160 + 84, index + 1)
        bounded_stats = _capture_call_stats(bounded_calls, bytes(bounded_records), 1000)
        assert bounded_stats["context"]["error_count"] == 257
        assert bounded_stats["context"]["error_codes_truncated"]
        filtered = capture_filter_calls(
            str(path),
            thread_id=0x1234,
            error_code=5,
            min_duration_seconds=0.1,
            max_duration_seconds=0.2,
        )
        assert filtered["count"] == 1
        assert filtered["matches"][0]["record"]["index"] == 0
        resolved_records = capture_call_records(str(path), resolve_definitions=True)
        assert resolved_records["definitions_available"]
        assert resolved_records["records"][0]["definition"]["name"] == "CreateFileW"
        assert resolved_records["records"][0]["definition"]["module"] == "kernel32.dll"
        assert resolved_records["records"][0]["definition"]["ordinal"] == 123
        assert capture_read_definition(str(path), 16)["definition"]["name"] == "CreateFileW"
        decoded_call = capture_decode_call(str(path), 0, 0, resolve_definitions=True)
        assert decoded_call["record"]["data_refs"][0]["decoding"]["strings"][0]["text"] == "hello"
        assert decoded_call["record"]["definition"]["name"] == "CreateFileW"
        assert decoded_call["return_value"]["typed"]["value"] == 7
        extracted_payload = Path(directory) / "payload.bin"
        payload_export = capture_extract_call_payload(str(path), 0, 0, 0, str(extracted_payload))
        assert payload_export["size"] == 5
        assert extracted_payload.read_bytes() == b"hello"
        process_slice = capture_read_process_data(str(path), 0, 160, 5)
        assert process_slice["text"] == "hello"
        json_export = capture_export_calls(
            str(path), str(Path(directory) / "calls.json"), resolve_definitions=True
        )
        assert json_export["count"] == 1
        exported_json = json.loads((Path(directory) / "calls.json").read_text())
        assert exported_json["records"][0]["index"] == 0
        assert exported_json["records"][0]["definition"]["name"] == "CreateFileW"
        csv_export = capture_export_calls(
            str(path),
            str(Path(directory) / "calls.csv"),
            output_format="csv",
            resolve_definitions=True,
        )
        assert csv_export["format"] == "csv"
        csv_text = (Path(directory) / "calls.csv").read_text()
        assert csv_text.startswith("process_index,record_index")
        assert "thread_id" in csv_text.splitlines()[0]
        assert "CreateFileW" in csv_text and "kernel32.dll" in csv_text
        call_search = capture_search_calls(str(path), "ell")
        assert call_search["count"] == 1
        assert call_search["matches"][0]["payload_matches"][0]["snippet"] == "hello"
        api_search = capture_search_calls(str(path), "CreateFileW", resolve_definitions=True)
        assert api_search["count"] == 1
        assert api_search["matches"][0]["api_matches"][0]["module"] == "kernel32.dll"
        argument_path = Path(directory) / "variants" / "arguments.apmx64"
        argument_record = bytearray(160)
        argument_record[2] = 1
        struct.pack_into("<Q", argument_record, 40, 16)
        struct_argument = struct.pack("<HH", 0, 8) + struct.pack("<I", 99)
        encoded_argument = b"\x01" + struct.pack(
            "<HH", 0, len(struct_argument) << 1
        ) + struct_argument
        struct.pack_into("<Q", argument_record, 112, 160)
        struct.pack_into("<I", argument_record, 32, len(encoded_argument))
        argument_definitions = bytearray(definitions)
        argument_definitions[16 + 2] = 1
        struct.pack_into("<Q", argument_definitions, 16 + 32, 224)
        struct.pack_into("<Q", argument_definitions, 224, 240)
        struct.pack_into("<Q", argument_definitions, 232, struct_type_offset)
        argument_payload = io.BytesIO()
        with zipfile.ZipFile(argument_payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("process/0/calls", struct.pack("<Q", 0))
            archive.writestr(
                "process/0/data", bytes(argument_record) + encoded_argument
            )
            archive.writestr("definitions", bytes(argument_definitions))
        argument_path.write_bytes(
            b"\r\nAPI Monitor 64-bit Capture\r\nRBAPM" + argument_payload.getvalue()
        )
        argument_search = capture_search_calls(
            str(argument_path),
            "99",
            resolve_definitions=True,
            decode_arguments=True,
        )
        assert argument_search["count"] == 1
        assert argument_search["arguments_decoded"]
        typed_structure = argument_search["matches"][0]["argument_matches"][0]["typed"]
        assert typed_structure["kind"] == "structure"
        assert typed_structure["fields"][0]["typed"]["value"] == 99
        call_window = capture_calls_around(str(path), 0, 0, before=2, after=2)
        assert call_window["window_start"] == 0
        assert call_window["records"][0]["is_target"]
        resolved_window = capture_calls_around(str(path), 0, 0, resolve_definitions=True)
        assert resolved_window["records"][0]["definition"]["name"] == "CreateFileW"
        binary_payload = _read_payload(b"\x01\x00\xff\x00")
        assert binary_payload["encoding"] == "base64"
        assert binary_payload["size"] == 4
        assert binary_payload["hex_preview"] == "01 00 ff 00"
        encoded = _capture_encoded_argument_stream(
            b"\x01" + struct.pack("<HH", 0, 8) + struct.pack("<I", 42),
            parameter_count=1,
        )
        assert encoded["valid"] and encoded["arguments"][0]["length"] == 4
        assert _capture_exact_scalar(
            struct.pack("<I", 42), {"kind": 2, "size": 4, "flags": 0}
        )["value"] == 42
        assert _capture_exact_scalar(
            b"\x00" * 8 + struct.pack("<Q", 0x1234),
            {"kind": 4, "flags": 0, "pointer_size": 8},
        )["value"] == "0x0000000000001234"
        assert _capture_exact_scalar(
            struct.pack("<HH", 1, 5) + b"hello", {"kind": 7, "flags": 0}
        )["value"] == "hello"
        assert _capture_exact_scalar(
            struct.pack("<HH", 1, 8) + "wide".encode("utf-16-le"),
            {"kind": 9, "flags": 0},
            machine_flag=True,
        )["value"] == "wide"
        assert _capture_exact_scalar(
            bytes(range(16)), {"kind": 13, "flags": 0}
        )["value"] == "{03020100-0504-0706-0809-0a0b0c0d0e0f}"
        assert _capture_exact_scalar(
            bytes(16), {"kind": 13, "flags": 0}
        )["value"] == "IID_NULL"
        array_type = _capture_type_info(bytes(definitions), array_type_offset)
        assert array_type and array_type["array_flags"] == 1
        array_value = _capture_exact_value(struct.pack("<III", 1, 2, 3), array_type)
        assert array_value and array_value["elements"][1]["typed"]["value"] == 2
        string_array_value = _capture_exact_value(
            b"hello", {"kind": 14, "array_count": 5, "array_flags": 1, "element_type": {"kind": 7}}
        )
        assert string_array_value and string_array_value["value"] == "hello"
        wide_array_value = _capture_exact_value(
            "wide".encode("utf-16-le"),
            {"kind": 14, "array_count": 4, "array_flags": 1, "element_type": {"kind": 8}},
        )
        assert wide_array_value and wide_array_value["value"] == "wide"
        pointer_type = {"kind": 4, "pointer_size": 8, "flags": 0}
        direct_pointer_array = _capture_exact_value(
            struct.pack("<Q", 0x1234),
            {"kind": 14, "array_count": 1, "array_flags": 1, "element_type": pointer_type},
        )
        assert direct_pointer_array and direct_pointer_array["elements"][0]["typed"]["value"] == "0x0000000000001234"
        variable_pointer_array = _capture_exact_value(
            struct.pack("<H", 1) + struct.pack("<HH", 0, 32) + b"\0" * 8 + struct.pack("<Q", 0x5678),
            {"kind": 14, "array_count": 1, "array_flags": 0, "element_type": pointer_type},
        )
        assert variable_pointer_array and variable_pointer_array["elements"][0]["typed"]["value"] == "0x0000000000005678"
        prefixed_array_value = _capture_exact_value(
            struct.pack("<HIII", 3, 1, 2, 3), array_type
        )
        assert prefixed_array_value and prefixed_array_value["count"] == 3
        fixed_struct_type = _capture_type_info(bytes(definitions), fixed_struct_type_offset)
        assert fixed_struct_type and fixed_struct_type["struct_flags"] == 2
        assert fixed_struct_type["structure_size_flagged"] == 8
        assert _capture_array_element_size(fixed_struct_type, machine_flag=True) == 8
        fixed_struct_value = _capture_exact_value(struct.pack("<I", 99), fixed_struct_type)
        assert fixed_struct_value and fixed_struct_value["representation"] == "fixed"
        assert fixed_struct_value["fields"][0]["typed"]["value"] == 99
        union_value = _capture_exact_value(
            struct.pack("<I", 0x12345678),
            {
                "kind": 11,
                "struct_flags": 3,
                "fields": [
                    {"type": {"kind": 2, "size": 4}},
                    {"type": {"kind": 2, "size": 2}},
                ],
            },
        )
        assert union_value and union_value["representation"] == "fixed_union"
        assert union_value["fields"][1]["offset"] == 0
        variable_array_type = _capture_type_info(
            bytes(definitions), variable_array_type_offset
        )
        assert variable_array_type
        variable_array_value = _capture_exact_value(
            struct.pack("<H", 2)
            + struct.pack("<HHHH", 0, 8, 4, 8)
            + struct.pack("<II", 4, 5),
            variable_array_type,
        )
        assert variable_array_value and variable_array_value["elements"][1]["typed"]["value"] == 5
        enum_type = _capture_type_info(bytes(definitions), enum_type_offset)
        assert enum_type and enum_type["enum_entries"][1]["name"] == "Green"
        enum_value = _capture_exact_value(struct.pack("<I", 2), enum_type)
        assert enum_value and enum_value["enum"]["names"] == ["Green"]
        bitmask_definitions = bytearray(definitions)
        bitmask_definitions[650] = 2
        bitmask_type = _capture_type_info(bytes(bitmask_definitions), enum_type_offset)
        bitmask_value = _capture_exact_value(struct.pack("<I", 3), bitmask_type)
        assert bitmask_value and bitmask_value["enum"]["names"] == ["Red", "Green"]
        extracted = Path(directory) / "calls.bin"
        exported = capture_extract_entry(str(path), "calls.bin", str(extracted))
        assert exported["size"] == len(b"CreateFileW\x00https://example.test\x00")
        assert extracted.read_bytes().startswith(b"CreateFileW")
        found = capture_find_bytes(str(path), "43 72 65 61 74 65", 10)
        assert found["offsets"]
        assert not found["truncated"]
        processes = capture_list_processes(str(path), 10)
        assert processes["processes"][0]["executables"] == ["C:\\sample.exe"]
        assert processes["processes"][0]["metadata"]["pid"] == 1234
        assert processes["processes"][0]["metadata"]["crc32_valid"]
        assert processes["processes"][0]["metadata"]["module_records"] == []
        assert processes["processes"][0]["call_count"] == 1
        call_stats = capture_call_stats(str(path), process_index=0)
        assert call_stats["processes"][0]["record_sizes"]["160"] == 1
        assert call_stats["totals"]["referenced_data_bytes"] == 9
        call_context_stats = call_stats["processes"][0]["context"]
        assert call_context_stats["thread_count"] == 1
        assert call_context_stats["duration_seconds"]["average"] == 0.125
        assert call_context_stats["first_timestamp_utc"] == "2020-01-01T00:00:00+00:00"
        api_list = capture_list_apis(str(path))
        assert api_list["count"] == 1
        assert api_list["apis"][0]["name"] == "CreateFileW"
        assert api_list["apis"][0]["count"] == 1
        assert api_list["apis"][0]["context"]["error_count"] == 1
        assert api_list["apis"][0]["context"]["duration_seconds"]["average"] == 0.125
        entries = _zip_entries(path)
        assert {entry["name"] for entry in entries} == {
            "metadata.txt",
            "calls.bin",
            "filter/display.xml",
            "process/0/calls",
            "process/0/data",
            "definitions",
            "log/monitoring.txt",
            "process/0/info",
            "info",
        }
        listed = capture_list_directory(directory, recursive=False, limit=10)
        assert listed["count"] == 1
        directory_search = capture_search_directory(directory, "CreateFile", recursive=False, limit=10)
        assert directory_search["captures"][0]["entries"][0]["entry"] == "calls.bin"
        comparison = capture_compare(str(path), str(second_path))
        assert comparison["counts"] == {"added": 1, "removed": 8, "changed": 1}
        assert not comparison["same"]
        call_comparison = capture_compare_calls(
            str(path), str(second_path), resolve_definitions=True
        )
        assert call_comparison["counts"]["removed"] == 1
        assert call_comparison["counts"]["changed"] == 0

        x86_path = Path(directory) / "sample.apmx86"
        x86_record = bytearray(120)
        x86_record[0] = 1
        x86_record[2] = 1
        struct.pack_into("<I", x86_record, 16, 0x2345)
        struct.pack_into("<I", x86_record, 20, 8)
        struct.pack_into("<I", x86_record, 40, 0x00401000)
        struct.pack_into("<Q", x86_record, 56, 132223104000000000)
        struct.pack_into("<I", x86_record, 68, 6)
        struct.pack_into("<d", x86_record, 80, 0.25)
        struct.pack_into("<I", x86_record, 36, 16)
        struct.pack_into("<I", x86_record, 32, 5)
        struct.pack_into("<I", x86_record, 96, 120)
        x86_definitions = bytearray(768)
        struct.pack_into("<I", x86_definitions, 16 + 8, 321)
        struct.pack_into("<I", x86_definitions, 16 + 24, 80)
        struct.pack_into("<I", x86_definitions, 16 + 32, 96)
        x86_definitions[16 + 2] = 1
        struct.pack_into("<I", x86_definitions, 16 + 28, 440)
        x86_definitions[80 : 80 + len(b"CreateFileA\x00")] = b"CreateFileA\x00"
        struct.pack_into("<I", x86_definitions, 96 + 16, 128)
        x86_definitions[128 : 128 + len(b"kernel32.dll\x00")] = b"kernel32.dll\x00"
        struct.pack_into("<I", x86_definitions, 160 + 4, 2)
        x86_definitions[160 + 16] = 4
        x86_struct_type_offset = 272
        struct.pack_into("<I", x86_definitions, x86_struct_type_offset + 4, 11)
        struct.pack_into("<I", x86_definitions, x86_struct_type_offset + 16, 320)
        x86_definitions[x86_struct_type_offset + 24] = 1
        struct.pack_into("<I", x86_definitions, 320, 480)
        struct.pack_into("<I", x86_definitions, 324, 160)
        x86_definitions[480 : 480 + len(b"dwValue\x00")] = b"dwValue\x00"
        struct.pack_into("<I", x86_definitions, 440, 480)
        struct.pack_into("<I", x86_definitions, 444, x86_struct_type_offset)
        x86_array_type_offset = 512
        struct.pack_into("<I", x86_definitions, x86_array_type_offset + 4, 14)
        struct.pack_into("<I", x86_definitions, x86_array_type_offset + 16, 160)
        struct.pack_into("<H", x86_definitions, x86_array_type_offset + 20, 3)
        x86_definitions[x86_array_type_offset + 22] = 1
        x86_enum_type_offset = 568
        struct.pack_into("<I", x86_definitions, x86_enum_type_offset + 4, 2)
        struct.pack_into("<I", x86_definitions, x86_enum_type_offset + 12, 600)
        x86_definitions[x86_enum_type_offset + 16] = 4
        struct.pack_into("<I", x86_definitions, 600, 624)
        struct.pack_into("<H", x86_definitions, 604, 2)
        struct.pack_into("<I", x86_definitions, 624, 656)
        struct.pack_into("<Q", x86_definitions, 624 + 8, 1)
        struct.pack_into("<I", x86_definitions, 640, 664)
        struct.pack_into("<Q", x86_definitions, 640 + 8, 2)
        x86_definitions[656 : 656 + len(b"Red\x00")] = b"Red\x00"
        x86_definitions[664 : 664 + len(b"Green\x00")] = b"Green\x00"
        x86_fixed_struct_type_offset = 536
        struct.pack_into("<I", x86_definitions, x86_fixed_struct_type_offset + 4, 11)
        struct.pack_into("<I", x86_definitions, x86_fixed_struct_type_offset + 16, 320)
        struct.pack_into("<H", x86_definitions, x86_fixed_struct_type_offset + 20, 4)
        x86_definitions[x86_fixed_struct_type_offset + 24] = 1
        x86_definitions[x86_fixed_struct_type_offset + 25] = 4
        x86_definitions[x86_fixed_struct_type_offset + 26] = 2
        x86_struct_argument = struct.pack("<HH", 0, 8) + struct.pack("<I", 77)
        x86_encoded_argument = b"\x01" + struct.pack(
            "<HH", 0, len(x86_struct_argument) << 1
        ) + x86_struct_argument
        struct.pack_into("<I", x86_record, 32, len(x86_encoded_argument))
        x86_process_info = struct.pack("<IIII", 1, 0, 4321, 0x400000)
        for value in ("C:\\sample32.exe", '"C:\\sample32.exe" /test', "Sample 32-bit Process"):
            x86_process_info += struct.pack("<I", len(value)) + value.encode("utf-16-le")
        x86_process_info += struct.pack(
            "<IQQI", 0, 132223104000000000, 132223104010000000, 1
        )
        x86_module_path = "C:\\Windows\\System32\\kernel32.dll"
        x86_module_name = b"kernel32.dll"
        x86_process_info += struct.pack("<I", 0x400000)
        x86_process_info += struct.pack("<I", len(x86_module_name)) + x86_module_name
        x86_process_info += struct.pack("<II", 1, 2)
        x86_process_info += struct.pack("<I", len(x86_module_path)) + x86_module_path.encode("utf-16-le")
        x86_process_info += struct.pack("<II", 3, 4)
        x86_process_info += struct.pack("<I", 1)
        x86_process_info += struct.pack("<I", 0x400000)
        x86_process_info += struct.pack("<I", len(x86_module_path)) + x86_module_path.encode("utf-16-le")
        x86_process_info += struct.pack("<I", zlib.crc32(x86_process_info) & 0xFFFFFFFF)
        x86_payload = io.BytesIO()
        with zipfile.ZipFile(x86_payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("process/0/calls", struct.pack("<I", 0))
            archive.writestr("process/0/data", bytes(x86_record) + x86_encoded_argument)
            archive.writestr("definitions", bytes(x86_definitions))
            archive.writestr("process/0/info", x86_process_info)
        x86_path.write_bytes(b"\r\nAPI Monitor 32-bit Capture\r\nRBAPM" + x86_payload.getvalue())
        x86_records = capture_call_records(
            str(x86_path), include_data=True, resolve_definitions=True
        )
        assert x86_records["architecture"] == "x86"
        assert x86_records["records"][0]["definition"]["name"] == "CreateFileA"
        assert x86_records["records"][0]["data_refs"][0]["payload"]["size"] == len(x86_encoded_argument)
        x86_context = x86_records["records"][0]["context"]
        assert x86_context["thread_id"] == 0x2345
        assert x86_context["thread_number"] == 8
        assert x86_context["module_base"] == "0x00401000"
        assert x86_context["error_code"] == 6
        assert x86_context["duration_seconds"] == 0.25
        assert capture_read_definition(str(x86_path), 16)["architecture"] == "x86"
        assert capture_list_apis(str(x86_path))["apis"][0]["module"] == "kernel32.dll"
        x86_deep_validation = capture_validate(str(x86_path), deep=True)
        assert x86_deep_validation["structural_valid"]
        assert x86_deep_validation["process_infos"][0]["valid"]
        assert x86_deep_validation["streams"][0]["definitions"]["resolved"] == 1
        x86_call_stats = capture_call_stats(str(x86_path))
        assert x86_call_stats["processes"][0]["record_sizes"]["120"] == 1
        assert x86_call_stats["processes"][0]["context"]["duration_seconds"]["maximum"] == 0.25
        x86_processes = capture_list_processes(str(x86_path))
        assert x86_processes["processes"][0]["call_count"] == 1
        x86_metadata = x86_processes["processes"][0]["metadata"]
        assert x86_metadata["pid"] == 4321
        assert x86_metadata["crc32_valid"]
        assert x86_metadata["image_path"] == "C:\\sample32.exe"
        assert x86_metadata["module_records"][0]["ansi_text"] == "kernel32.dll"
        assert x86_metadata["module_records"][0]["path"] == x86_module_path
        assert x86_metadata["loaded_modules"][0]["path"] == x86_module_path
        x86_decoded = capture_decode_call(str(x86_path), 0, 0, resolve_definitions=True)
        assert x86_decoded["argument_stream"]["arguments"][0]["typed"]["fields"][0]["typed"]["value"] == 77
        x86_array_type = _capture_type_info(bytes(x86_definitions), x86_array_type_offset, 4)
        assert x86_array_type and x86_array_type["array_flags"] == 1
        x86_array_value = _capture_exact_value(
            struct.pack("<III", 1, 2, 3), x86_array_type
        )
        assert x86_array_value and x86_array_value["elements"][1]["typed"]["value"] == 2
        x86_enum_type = _capture_type_info(bytes(x86_definitions), x86_enum_type_offset, 4)
        assert x86_enum_type and x86_enum_type["enum_entries"][1]["name"] == "Green"
        x86_enum_value = _capture_exact_value(struct.pack("<I", 2), x86_enum_type)
        assert x86_enum_value and x86_enum_value["enum"]["names"] == ["Green"]
        x86_fixed_struct_type = _capture_type_info(
            bytes(x86_definitions), x86_fixed_struct_type_offset, 4
        )
        assert x86_fixed_struct_type and x86_fixed_struct_type["struct_flags"] == 2
        x86_fixed_struct_value = _capture_exact_value(
            struct.pack("<I", 88), x86_fixed_struct_type
        )
        assert x86_fixed_struct_value and x86_fixed_struct_value["fields"][0]["typed"]["value"] == 88

        app_root = Path(directory) / "app"
        definition_root = app_root / "API"
        definition_root.mkdir(parents=True)
        definition = definition_root / "sample.xml"
        definition.write_text(
            '<ApiMonitor><Module Name="sample.dll" CallingConvention="STDCALL">'
            '<Api Name="OpenThing"><Param Type="HANDLE" Name="hThing" />'
            '<Return Type="BOOL" /></Api></Module></ApiMonitor>',
            encoding="utf-8",
        )
        parsed = api_monitor_parse_api_definition(str(definition), install_root=str(app_root))
        assert parsed["apis"][0]["module"] == "sample.dll"
        assert parsed["apis"][0]["params"] == [{"Type": "HANDLE", "Name": "hThing"}]


def main() -> None:
    if "--self-test" in sys.argv:
        _self_test()
        print("ok")
        return
    mcp.run("stdio")


if __name__ == "__main__":
    main()
