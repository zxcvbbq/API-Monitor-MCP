"""APMX container, process, definition, and call-stream parsing."""

from __future__ import annotations

import hashlib
import io
import math
import mmap
import re
import struct
import sys
import zipfile
import zlib
from array import array
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from .capture_values import _read_payload
from .runtime import CAPTURE_SUFFIXES, CHILD_EVENT, MODULE_EVENT, ZIP_SIGNATURES


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


def _scan_capture_zip_offset(path: Path) -> int | None:
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


@lru_cache(maxsize=128)
def _cached_capture_zip_offset(
    path_name: str, size: int, modified_ns: int, changed_ns: int
) -> int | None:
    return _scan_capture_zip_offset(Path(path_name))


def _capture_zip_offset(path: Path) -> int | None:
    stat = path.stat()
    return _cached_capture_zip_offset(
        str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns
    )


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _capture_info(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    offset = _capture_zip_offset(path)
    result: dict[str, Any] = {
        "file": str(path),
        "extension": path.suffix.lower(),
        "size": size,
        "sha256": _file_sha256(path),
        "modified_utc": _file_time(path),
        "zip_offset": offset,
        "container": "zip-with-prefix" if offset is not None and offset else "zip",
    }
    if offset is None:
        result["zip_error"] = "No ZIP signature found"
        result["entries"] = []
        return result
    with path.open("rb") as handle:
        prefix = handle.read(offset)
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


def _parse_utc_timestamp(value: str | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("UTC timestamps must be non-empty ISO-8601 strings")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid UTC timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = parsed.astimezone(timezone.utc) - epoch
    if delta.days < 0:
        raise ValueError("UTC timestamp must not be before 1601-01-01")
    return delta.days * 864_000_000_000 + delta.seconds * 10_000_000 + delta.microseconds * 10


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
        raw_data = data[position : position + raw_length]
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
                "raw_payload": _read_payload(raw_data, 1024 * 1024),
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


def _capture_process_pid(
    archive: Any, entries: Any, process_index: int, pointer_size: int
) -> int | None:
    entry_name = f"process/{process_index}/info"
    if entry_name not in entries:
        return None
    try:
        return _parse_capture_process_info(archive.read(entry_name), pointer_size).get("pid")
    except (ValueError, struct.error):
        return None


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
    offsets: Sequence[int], index: int, data: bytes, pointer_size: int = 8
) -> int:
    layout = _capture_layout(pointer_size)
    offset = offsets[index]
    next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
    minimum = layout["minimum_record_size"]
    full = layout["full_record_size"]
    return next_offset - offset if minimum <= next_offset - offset <= full else full if data[offset + 2] else minimum


def _capture_offsets(calls: bytes, pointer_size: int) -> array:
    if len(calls) % pointer_size:
        raise ValueError(f"process calls entry is not an array of {pointer_size * 8}-bit offsets")
    offsets = array("I" if pointer_size == 4 else "Q")
    if offsets.itemsize != pointer_size:
        raise ValueError(f"unsupported native offset size for {pointer_size * 8}-bit captures")
    offsets.frombytes(calls)
    if sys.byteorder != "little":
        offsets.byteswap()
    return offsets


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
    minimum = layout["minimum_record_size"]
    records: list[dict[str, Any]] = []
    count = len(calls) // pointer_size
    end_index = min(count, start_index + limit)
    window = _capture_offsets(
        calls[start_index * pointer_size : (end_index + 1) * pointer_size], pointer_size
    )
    for local_index, offset in enumerate(window[: end_index - start_index]):
        index = start_index + local_index
        if offset > len(data) - minimum:
            records.append({"index": index, "offset": offset, "valid": False, "error": "record offset is outside process data"})
            continue
        record_size = _capture_record_size(window, local_index, data, pointer_size)
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
    calls: bytes,
    data: bytes,
    max_records: int,
    pointer_size: int = 8,
    data_size: int | None = None,
    data_reader: Any = None,
) -> dict[str, Any]:
    layout = _capture_layout(pointer_size)
    if len(calls) % pointer_size:
        raise ValueError(f"process calls entry is not an array of {pointer_size * 8}-bit offsets")
    offset_format = layout["offset_format"]
    count = len(calls) // pointer_size
    scanned = min(count, max_records)
    offsets = _capture_offsets(calls[: (scanned + 1) * pointer_size], pointer_size)
    data_length = len(data) if data_size is None else data_size

    def read_data(offset: int, size: int) -> bytes:
        return data_reader(offset, size) if data_reader is not None else data[offset : offset + size]

    stats: dict[str, Any] = {
        "count": count,
        "scanned_records": scanned,
        "truncated": scanned < count,
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
        "data_bytes": data_length,
        "referenced_data_bytes": 0,
    }
    thread_ids: set[int] = set()
    timestamps: list[int] = []
    durations: list[float] = []
    error_codes: dict[str, int] = {}
    error_codes_truncated = False
    error_count = 0
    for index, offset in enumerate(offsets[:scanned]):
        if offset > data_length - layout["minimum_record_size"]:
            stats["invalid_records"] += 1
            continue
        next_offset = offsets[index + 1] if index + 1 < len(offsets) else data_length
        size_from_offsets = next_offset - offset
        if layout["minimum_record_size"] <= size_from_offsets <= layout["full_record_size"]:
            record_size = size_from_offsets
        else:
            header = read_data(offset + 2, 1)
            if not header:
                stats["invalid_records"] += 1
                continue
            record_size = layout["full_record_size"] if header[0] else layout["minimum_record_size"]
        record = read_data(offset, record_size)
        if len(record) < record_size:
            stats["invalid_records"] += 1
            continue
        stats["valid_records"] += 1
        size_key = (
            str(record_size)
            if record_size in (layout["minimum_record_size"], layout["full_record_size"])
            else "other"
        )
        stats["record_sizes"][size_key] += 1
        flags = record[2]
        flag_key = f"0x{flags:02x}"
        stats["flags"][flag_key] = stats["flags"].get(flag_key, 0) + 1
        context = _capture_call_context(record, 0, pointer_size)
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
        if context.get("duration_valid") and math.isfinite(context["duration_seconds"]):
            durations.append(context["duration_seconds"])
        for slot, pointer_offset, length_offset in layout["pointer_refs"]:
            if pointer_offset + pointer_size > record_size or length_offset + 4 > record_size:
                continue
            relative = struct.unpack_from(
                offset_format, record, pointer_offset
            )[0]
            length = struct.unpack_from("<I", record, length_offset)[0]
            reference_stats = stats["payload_slots"][str(slot)]
            if not relative and not length:
                continue
            if relative + length > data_length:
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
    stats["unreferenced_data_bytes"] = max(0, data_length - stats["referenced_data_bytes"])
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
