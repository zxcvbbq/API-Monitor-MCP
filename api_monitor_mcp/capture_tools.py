"""Headless APMX inspection, decoding, search, comparison, and export tools."""

from __future__ import annotations

import base64
import csv
import difflib
import hashlib
import io
import json
import math
import mmap
import re
import struct
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .capture_format import (
    _capture_call_records,
    _capture_call_stats,
    _capture_definition_info,
    _capture_directory,
    _capture_info,
    _capture_path,
    _capture_process_pid,
    _capture_strings,
    _capture_type_info,
    _file_time,
    _limit,
    _monitoring_event,
    _open_capture_zip,
    _parse_capture_info,
    _parse_capture_process_info,
    _parse_utc_timestamp,
    _scan_strings,
    _windows_filetime,
    _zip_entries,
)
from .capture_values import (
    _capture_decoded_argument_stream,
    _capture_exact_value,
    _capture_payload_candidates,
    _payload_bytes,
    _read_payload,
    _xml_entry_nodes,
)
from .runtime import CAPTURE_SUFFIXES, PROCESS_INFO, mcp


def _capture_records_without_data(
    archive: zipfile.ZipFile,
    data_info: zipfile.ZipInfo | None,
    calls: bytes,
    limit: int,
    *,
    start_index: int = 0,
    definitions: bytes | None = None,
    pointer_size: int = 8,
) -> list[dict[str, Any]]:
    if data_info is None:
        return _capture_call_records(
            calls,
            b"",
            limit,
            False,
            0,
            start_index=start_index,
            definitions=definitions,
            pointer_size=pointer_size,
        )
    with archive.open(data_info) as data_stream:
        def read_data(offset: int, size: int) -> bytes:
            data_stream.seek(offset)
            return data_stream.read(size)

        return _capture_call_records(
            calls,
            b"",
            limit,
            False,
            0,
            start_index=start_index,
            definitions=definitions,
            pointer_size=pointer_size,
            data_size=data_info.file_size,
            data_reader=read_data,
        )


def _capture_validate_stream(
    calls: bytes,
    data_size: int,
    definitions: bytes | None,
    max_records: int,
    pointer_size: int,
    data_reader: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    stats = _capture_call_stats(
        calls,
        b"",
        max_records,
        pointer_size,
        data_size=data_size,
        data_reader=data_reader,
    )
    if definitions is None:
        return stats, {"available": False}
    records = _capture_call_records(
        calls,
        b"",
        min(len(calls) // pointer_size, max_records),
        False,
        0,
        definitions=definitions,
        pointer_size=pointer_size,
        data_size=data_size,
        data_reader=data_reader,
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
    return stats, definition_checks


def _copy_capture_slice(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    offset: int,
    length: int,
    output: Path,
    overwrite: bool,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    written = 0
    created = False
    try:
        with archive.open(info) as data_stream:
            data_stream.seek(offset)
            with output.open("wb" if overwrite else "xb") as handle:
                created = True
                while written < length:
                    chunk = data_stream.read(min(1024 * 1024, length - written))
                    if not chunk:
                        raise ValueError("capture entry ended before its declared length")
                    handle.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
    except Exception:
        if created and output.exists():
            output.unlink()
        raise
    return written, digest.hexdigest()


@mcp.tool()
def capture_info(file_path: str) -> dict[str, Any]:
    """Inspect an APMX file header and list its ZIP container entries."""
    return _capture_info(_capture_path(file_path))


@mcp.tool()
def capture_overview(
    file_path: str,
    process_limit: int = 200,
    api_limit: int = 1000,
    max_records: int = 100_000,
    include_log: bool = False,
    log_limit: int = 1000,
) -> dict[str, Any]:
    """Return one bounded triage report for an APMX capture."""
    process_limit = _limit(process_limit, "process_limit", 2000)
    api_limit = _limit(api_limit, "api_limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    log_limit = _limit(log_limit, "log_limit", 10_000)
    path = _capture_path(file_path)
    result: dict[str, Any] = {
        "file": str(path),
        "info": capture_info(str(path)),
        "validation": capture_validate(str(path)),
        "processes": capture_list_processes(str(path), process_limit),
        "stats": capture_call_stats(str(path), max_records=max_records),
        "apis": capture_list_apis(
            str(path), limit=api_limit, max_records=max_records
        ),
    }
    if include_log:
        result["log"] = capture_monitoring_log(str(path), limit=log_limit)
    return result


@mcp.tool()
def capture_process_overview(
    file_path: str,
    process_index: int,
    pid: int | None = None,
    max_records: int = 100_000,
    include_calls: bool = False,
    call_limit: int = 100,
    include_data: bool = False,
    max_data_bytes: int = 4096,
) -> dict[str, Any]:
    """Return one bounded investigation report for a captured process."""
    if process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    max_records = _limit(max_records, "max_records", 1_000_000)
    call_limit = _limit(call_limit, "call_limit", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    processes = capture_list_processes(file_path, limit=2000)["processes"]
    process = next((item for item in processes if item["index"] == process_index), None)
    if process is None:
        raise LookupError(f"Captured process index {process_index} was not found")
    process_pid = process.get("metadata", {}).get("pid")
    if pid is not None and process_pid != pid:
        raise LookupError(f"Captured process index {process_index} does not contain PID {pid}")
    stats = capture_call_stats(file_path, process_index=process_index, max_records=max_records)
    process_stats = next(
        (item for item in stats["processes"] if item["process_index"] == process_index),
        None,
    )
    result: dict[str, Any] = {
        "file": str(_capture_path(file_path)),
        "process_index": process_index,
        "pid": process_pid,
        "process": process,
        "stats": process_stats,
        "modules": capture_list_modules(file_path, process_index=process_index, pid=pid),
        "threads": capture_list_threads(
            file_path,
            process_index=process_index,
            pid=pid,
            max_records=max_records,
        ),
        "apis": capture_list_apis(
            file_path,
            process_index=process_index,
            pid=pid,
            max_records=max_records,
        ),
        "errors": capture_error_summary(
            file_path,
            process_index=process_index,
            pid=pid,
            max_records=max_records,
        ),
    }
    if include_calls:
        result["calls"] = capture_call_records(
            file_path,
            process_index=process_index,
            limit=call_limit,
            include_data=include_data,
            max_data_bytes=max_data_bytes,
            resolve_definitions=True,
        )
    return result


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
    suffix_architecture = "x86" if path.suffix.lower() == ".apmx86" else "x64"
    header_architecture = (
        "x64"
        if b"64-bit Capture" in prefix
        else "x86"
        if b"32-bit Capture" in prefix
        else None
    )
    architecture_match = (
        header_architecture is None or header_architecture == suffix_architecture
    )
    result: dict[str, Any] = {
        "file": str(path),
        "valid": prefix_valid and architecture_match and error is None and bad_entry is None,
        "prefix_valid": prefix_valid,
        "architecture": suffix_architecture,
        "header_architecture": header_architecture,
        "architecture_match": architecture_match,
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
        info_validation: dict[str, Any] = {"available": False}
        if "info" in entries:
            try:
                info_metadata = _parse_capture_info(archive.read("info"))
                info_validation = {
                    "available": True,
                    "valid": info_metadata["crc32_valid"],
                    "metadata": info_metadata,
                }
            except ValueError as exc:
                info_validation = {"available": True, "valid": False, "error": str(exc)}
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
            match = re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE)
            if not match:
                continue
            index = int(match.group(1))
            calls = archive.read(name)
            data_name = f"process/{index}/data"
            data_info = entries.get(data_name)
            data_size = data_info.file_size if data_info is not None else 0
            stream: dict[str, Any] = {
                "process_index": index,
                "architecture": "x86" if pointer_size == 4 else "x64",
                "calls_entry": name,
                "data_entry": data_name if data_size else None,
                "valid": False,
            }

            try:
                if data_info is None:
                    stats, definition_checks = _capture_validate_stream(
                        calls,
                        data_size,
                        definitions,
                        max_records,
                        pointer_size,
                    )
                else:
                    with archive.open(data_info) as data_stream:
                        def read_data(
                            offset: int, size: int, data_stream: Any = data_stream
                        ) -> bytes:
                            data_stream.seek(offset)
                            return data_stream.read(size)

                        stats, definition_checks = _capture_validate_stream(
                            calls,
                            data_size,
                            definitions,
                            max_records,
                            pointer_size,
                            read_data,
                        )
                stream["stats"] = stats
                stream["valid"] = stats["invalid_records"] == 0
                stream["definitions"] = definition_checks
                if definitions is not None:
                    stream["valid"] = stream["valid"] and not definition_checks["invalid"]
            except (ValueError, struct.error) as exc:
                stream["error"] = str(exc)
            streams.append(stream)
    result["streams"] = streams
    result["info"] = info_validation
    result["process_infos"] = process_infos
    result["structural_valid"] = (
        all(stream["valid"] for stream in streams)
        and all(process["valid"] for process in process_infos)
        and (not info_validation["available"] or info_validation["valid"])
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
def capture_compare_entry(
    first_file: str,
    second_file: str,
    entry_name: str,
    context_bytes: int = 32,
    max_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Find the first bounded byte difference between two APMX ZIP entries."""
    if not entry_name:
        raise ValueError("entry_name must not be empty")
    if not 0 <= context_bytes <= 4096:
        raise ValueError("context_bytes must be between 0 and 4096")
    max_bytes = _limit(max_bytes, "max_bytes", 256 * 1024 * 1024)

    def open_entry(file_path: str) -> tuple[Path, zipfile.ZipFile, zipfile.ZipInfo]:
        path = _capture_path(file_path)
        archive, _, _ = _open_capture_zip(path)
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            archive.close()
            raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
        if info.is_dir():
            archive.close()
            raise IsADirectoryError(f"ZIP entry is a directory: {entry_name}")
        return path, archive, info

    def find_difference(
        first_archive: zipfile.ZipFile,
        first_info: zipfile.ZipInfo,
        second_archive: zipfile.ZipFile,
        second_info: zipfile.ZipInfo,
        compare_bytes: int,
    ) -> int | None:
        compared = 0
        chunk_size = 1024 * 1024
        with first_archive.open(first_info) as first_stream, second_archive.open(
            second_info
        ) as second_stream:
            while compared < compare_bytes:
                size = min(chunk_size, compare_bytes - compared)
                first_chunk = first_stream.read(size)
                second_chunk = second_stream.read(size)
                for offset, (left, right) in enumerate(zip(first_chunk, second_chunk)):
                    if left != right:
                        return compared + offset
                compared += min(len(first_chunk), len(second_chunk))
                if len(first_chunk) != len(second_chunk):
                    return compared
                if not first_chunk:
                    break
        return None

    def read_context(
        archive: zipfile.ZipFile, info: zipfile.ZipInfo, start: int, length: int
    ) -> bytes:
        with archive.open(info) as member:
            member.seek(start)
            return member.read(length)

    first, first_archive, first_info = open_entry(first_file)
    try:
        second, second_archive, second_info = open_entry(second_file)
    except Exception:
        first_archive.close()
        raise
    try:
        first_visible = min(first_info.file_size, max_bytes)
        second_visible = min(second_info.file_size, max_bytes)
        compared = min(first_visible, second_visible)
        difference = find_difference(
            first_archive, first_info, second_archive, second_info, compared
        )
        if difference is None and first_visible != second_visible:
            difference = compared
        truncated = first_info.file_size > max_bytes or second_info.file_size > max_bytes
        same = difference is None and first_info.file_size == second_info.file_size and not truncated
        result: dict[str, Any] = {
            "first": str(first),
            "second": str(second),
            "entry": entry_name,
            "first_size": first_info.file_size,
            "second_size": second_info.file_size,
            "compared_bytes": compared,
            "max_bytes": max_bytes,
            "same": same,
            "truncated": truncated,
            "first_difference": difference,
        }
        if difference is not None:
            start = max(0, difference - context_bytes)
            end = min(max(first_visible, second_visible), difference + context_bytes + 1)
            first_context = read_context(first_archive, first_info, start, end - start)
            second_context = read_context(second_archive, second_info, start, end - start)
            result["context"] = {
                "offset": start,
                "length": end - start,
                "first_hex": first_context.hex(" "),
                "second_hex": second_context.hex(" "),
            }
        return result
    finally:
        first_archive.close()
        second_archive.close()


@mcp.tool()
def capture_compare_calls(
    first_file: str,
    second_file: str,
    process_index: int = 0,
    limit: int = 200,
    max_records: int = 10_000,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
    match_mode: str = "index",
    compare_context: bool = False,
) -> dict[str, Any]:
    """Compare saved calls by alignment and bounded fingerprints, optionally including context."""
    if match_mode not in {"index", "sequence"}:
        raise ValueError("match_mode must be index or sequence")
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
        result = (
            record.get("flags"),
            definition.get("offset"),
            definition.get("name"),
            definition.get("module"),
            tuple(refs),
        )
        if compare_context:
            context = record.get("context", {})
            duration = (
                context.get("duration_seconds")
                if context.get("duration_valid")
                else None
            )
            result += (
                (
                    context.get("thread_id"),
                    context.get("thread_number"),
                    context.get("module_base"),
                    context.get("error_code"),
                    duration,
                ),
            )
        return result

    def summary(record: dict[str, Any]) -> dict[str, Any]:
        definition = record.get("definition", {})
        result = {
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
        if compare_context:
            context = record.get("context", {})
            result["context"] = {
                key: context.get(key)
                for key in (
                    "thread_id",
                    "thread_number",
                    "module_base",
                    "error_code",
                    "duration_valid",
                    "duration_seconds",
                )
                if key in context
            }
        return result

    first = load(first_file)
    second = load(second_file)
    first_records = first.get("records", [])
    second_records = second.get("records", [])
    added = []
    removed = []
    changed = []
    if match_mode == "index":
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
    else:
        first_signatures = [signature(record) for record in first_records]
        second_signatures = [signature(record) for record in second_records]
        matcher = difflib.SequenceMatcher(
            None, first_signatures, second_signatures, autojunk=False
        )
        for tag, first_start, first_end, second_start, second_end in matcher.get_opcodes():
            if tag == "equal":
                continue
            pair_count = min(first_end - first_start, second_end - second_start)
            for offset in range(pair_count):
                first_record = first_records[first_start + offset]
                second_record = second_records[second_start + offset]
                changed.append(
                    {
                        "first_index": first_record.get("index"),
                        "second_index": second_record.get("index"),
                        "first": summary(first_record),
                        "second": summary(second_record),
                    }
                )
            for index in range(first_start + pair_count, first_end):
                removed.append(summary(first_records[index]))
            for index in range(second_start + pair_count, second_end):
                added.append(summary(second_records[index]))
    truncated = any(
        len(items) > limit for items in (added, removed, changed)
    ) or first.get("truncated", False) or second.get("truncated", False)
    return {
        "first": first.get("file"),
        "second": second.get("file"),
        "process_index": process_index,
        "process_pids": {
            "first": first.get("process_pid"),
            "second": second.get("process_pid"),
        },
        "match_mode": match_mode,
        "compare_context": compare_context,
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
        "truncated": truncated,
        "same": not added and not removed and not changed and not truncated,
        "payload_fingerprint": "sha256 when payload is within max_data_bytes",
    }


@mcp.tool()
def capture_compare_all_calls(
    first_file: str,
    second_file: str,
    limit: int = 200,
    max_records: int = 10_000,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
    match_mode: str = "index",
    compare_context: bool = False,
) -> dict[str, Any]:
    """Compare saved call streams for every process in two APMX captures."""
    if match_mode not in {"index", "sequence"}:
        raise ValueError("match_mode must be index or sequence")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    first = _capture_path(first_file)
    second = _capture_path(second_file)

    def process_indices(path: Path) -> set[int]:
        return {
            int(match.group(1))
            for entry in _zip_entries(path)
            if (match := re.fullmatch(r"process/(\d+)/calls", entry["name"], re.IGNORECASE))
        }

    indices = sorted(process_indices(first) | process_indices(second))
    comparisons = [
        capture_compare_calls(
            str(first),
            str(second),
            process_index=index,
            limit=limit,
            max_records=max_records,
            max_data_bytes=max_data_bytes,
            resolve_definitions=resolve_definitions,
            match_mode=match_mode,
            compare_context=compare_context,
        )
        for index in indices
    ]
    totals = {
        key: sum(comparison["counts"][key] for comparison in comparisons)
        for key in ("added", "removed", "changed")
    }
    truncated = any(comparison["truncated"] for comparison in comparisons)
    return {
        "first": str(first),
        "second": str(second),
        "match_mode": match_mode,
        "compare_context": compare_context,
        "process_indices": indices,
        "process_pids": {
            str(index): comparison.get("process_pids", {})
            for index, comparison in zip(indices, comparisons)
        },
        "comparisons": comparisons,
        "counts": totals,
        "same": not any(totals.values()) and not truncated,
        "truncated": truncated,
        "payload_fingerprint": "sha256 when payload is within max_data_bytes",
    }


@mcp.tool()
def capture_compare_apis(
    first_file: str,
    second_file: str,
    limit: int = 500,
    max_records: int = 1_000_000,
) -> dict[str, Any]:
    """Compare resolved API call frequencies across two APMX captures."""
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    first = capture_list_apis(first_file, limit=10_000, max_records=max_records)
    second = capture_list_apis(second_file, limit=10_000, max_records=max_records)

    def key(item: dict[str, Any]) -> tuple[str, str, Any]:
        return (
            str(item.get("name") or "").casefold(),
            str(item.get("module") or "").casefold(),
            item.get("ordinal"),
        )

    first_apis = {key(item): item for item in first["apis"]}
    second_apis = {key(item): item for item in second["apis"]}
    sort_key = lambda api_key: (api_key[0], api_key[1], str(api_key[2]))
    added_keys = sorted(set(second_apis) - set(first_apis), key=sort_key)
    removed_keys = sorted(set(first_apis) - set(second_apis), key=sort_key)
    changed_keys = sorted(
        (
            api_key
            for api_key in set(first_apis) & set(second_apis)
            if (
                first_apis[api_key].get("count"),
                first_apis[api_key].get("process_indices"),
            )
            != (
                second_apis[api_key].get("count"),
                second_apis[api_key].get("process_indices"),
            )
        ),
        key=sort_key,
    )
    added = [second_apis[api_key] for api_key in added_keys]
    removed = [first_apis[api_key] for api_key in removed_keys]
    changed = [
        {
            "api": {
                "name": api_key[0],
                "module": api_key[1],
                "ordinal": api_key[2],
            },
            "first": first_apis[api_key],
            "second": second_apis[api_key],
        }
        for api_key in changed_keys
    ]
    return {
        "first": first["file"],
        "second": second["file"],
        "definitions_available": {
            "first": first["definitions_available"],
            "second": second["definitions_available"],
        },
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
        "added": added[:limit],
        "removed": removed[:limit],
        "changed": changed[:limit],
        "same": not added_keys and not removed_keys and not changed_keys and not (
            first["truncated"] or second["truncated"]
        ),
        "truncated": any(
            len(items) > limit for items in (added, removed, changed)
        ) or first["truncated"] or second["truncated"],
    }


@mcp.tool()
def capture_export_all_calls(
    file_path: str,
    output_path: str,
    limit: int = 10_000,
    output_format: str = "json",
    include_data: bool = True,
    max_data_bytes: int = 4096,
    overwrite: bool = False,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Export bounded call records for every process in an APMX capture."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    limit = _limit(limit, "limit", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")
    path = _capture_path(file_path)
    indices = sorted(
        {
            int(match.group(1))
            for entry in _zip_entries(path)
            if (match := re.fullmatch(r"process/(\d+)/calls", entry["name"], re.IGNORECASE))
        }
    )
    processes = []
    for index in indices:
        page = capture_call_records(
            str(path),
            process_index=index,
            limit=min(limit, 10_000),
            include_data=include_data,
            max_data_bytes=max_data_bytes,
            resolve_definitions=resolve_definitions,
        )
        records = page["records"]
        next_index = page["start_index"] + len(records)
        while page["truncated"] and len(records) < limit:
            page = capture_call_records(
                str(path),
                process_index=index,
                start_index=next_index,
                limit=min(limit - len(records), 10_000),
                include_data=include_data,
                max_data_bytes=max_data_bytes,
                resolve_definitions=resolve_definitions,
            )
            records.extend(page["records"])
            next_index = page["start_index"] + len(page["records"])
            if not page["records"]:
                break
        page["records"] = records
        page["start_index"] = 0
        page["end_index"] = records[-1]["index"] if records else None
        page["truncated"] = next_index < page["count"]
        processes.append(page)

    if output_format == "json":
        content = json.dumps(
            {
                "file": str(path),
                "architecture": "x86" if path.suffix.lower() == ".apmx86" else "x64",
                "process_indices": indices,
                "processes": processes,
                "count": sum(len(process["records"]) for process in processes),
                "truncated": any(process["truncated"] for process in processes),
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    else:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(
            [
                "process_index",
                "pid",
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
        for process in processes:
            process_index = process["process_index"]
            for record in process["records"]:
                references = record.get("data_refs", []) or [{}]
                definition = record.get("definition", {})
                context = record.get("context", {})
                for reference in references:
                    payload = reference.get("payload", {})
                    writer.writerow(
                        [
                            process_index,
                            process.get("process_pid", ""),
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
        "file": str(path),
        "output": str(output),
        "format": output_format,
        "process_indices": indices,
        "count": sum(len(process["records"]) for process in processes),
        "process_count": len(processes),
        "truncated": any(process["truncated"] for process in processes),
        "size": len(encoded),
        "sha256": digest,
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
def capture_read_entry(
    file_path: str,
    entry_name: str,
    max_bytes: int = 1_048_576,
    offset: int = 0,
) -> dict[str, Any]:
    """Read one APMX ZIP entry, returning text when printable or base64 otherwise."""
    if offset < 0:
        raise ValueError("offset must be non-negative")
    max_bytes = _limit(max_bytes, "max_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
        if info.is_dir():
            raise IsADirectoryError(f"ZIP entry is a directory: {entry_name}")
        if offset > info.file_size:
            raise ValueError(f"offset {offset} is outside {info.file_size}-byte entry")
        with archive.open(info) as member:
            member.seek(offset)
            data = member.read(max_bytes + 1)
    returned_bytes = min(len(data), max_bytes)
    truncated = len(data) > max_bytes or offset + returned_bytes < info.file_size
    payload = _read_payload(data[:max_bytes])
    return {
        "entry": entry_name,
        "offset": offset,
        "size": info.file_size,
        "returned_bytes": returned_bytes,
        "truncated": truncated,
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
def capture_list_filters(
    file_path: str,
    filter_type: str = "all",
    query: str = "",
    limit: int = 1000,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """List structured display/monitor filters stored in an APMX capture."""
    if filter_type not in {"all", "display", "monitor"}:
        raise ValueError("filter_type must be all, display, or monitor")
    if len(query) > 4096:
        raise ValueError("query must not exceed 4096 characters")
    limit = _limit(limit, "limit", 20_000)
    max_bytes = _limit(max_bytes, "max_bytes", 64 * 1024 * 1024)
    path = _capture_path(file_path)
    wanted = query.casefold()
    entries: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    returned = 0
    matched = 0
    truncated = False
    archive, _, _ = _open_capture_zip(path)
    with archive:
        for info in archive.infolist():
            name = info.filename
            lowered = name.casefold()
            if info.is_dir() or not lowered.startswith("filter/") or not lowered.endswith(".xml"):
                continue
            if filter_type != "all" and filter_type not in lowered:
                continue
            try:
                if info.file_size > max_bytes:
                    raise ValueError(f"XML entry exceeds max_bytes: {info.file_size}")
                root = ElementTree.fromstring(archive.read(info))
            except (OSError, ElementTree.ParseError, ValueError) as exc:
                errors.append({"entry": name, "error": str(exc)})
                continue
            root_tag = root.tag.rsplit("}", 1)[-1] if isinstance(root.tag, str) else str(root.tag)
            filters: list[dict[str, Any]] = []
            for node_index, node in enumerate(root.iter()):
                tag = node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else str(node.tag)
                if "filter" != tag.casefold():
                    continue
                text = " ".join((node.text or "").split())
                searchable = " ".join((tag, text, *node.attrib.values())).casefold()
                if wanted and wanted not in searchable:
                    continue
                matched += 1
                if returned >= limit:
                    truncated = True
                    continue
                filters.append(
                    {
                        "index": node_index,
                        "tag": tag,
                        "attributes": dict(node.attrib),
                        "text": text[:4096],
                        "truncated_text": len(text) > 4096,
                    }
                )
                returned += 1
            if filters:
                entries.append(
                    {
                        "entry": name,
                        "root": root_tag,
                        "filters": filters,
                        "count": len(filters),
                    }
                )
    return {
        "file": str(path),
        "filter_type": filter_type,
        "query": query,
        "entries": entries,
        "filters": [item for entry in entries for item in entry["filters"]],
        "count": returned,
        "matched": matched,
        "truncated": truncated or matched > returned,
        "errors": errors,
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
        entries = {info.filename for info in archive.infolist()}
        try:
            calls = archive.read(calls_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {calls_name}") from exc
        data_info = archive.getinfo(data_name) if data_name in entries else None
        data_entry_bytes = data_info.file_size if data_info is not None else 0
        definitions = archive.read("definitions") if resolve_definitions and "definitions" in entries else None
        process_pid = _capture_process_pid(archive, entries, process_index, pointer_size)
        if len(calls) % pointer_size:
            raise ValueError(
                f"process calls entry is not an array of {pointer_size * 8}-bit offsets"
            )
        count = len(calls) // pointer_size
        if start_index > count:
            raise IndexError(f"start_index {start_index} is outside {count} saved calls")
        if data_info is not None and include_data:
            with archive.open(data_info) as data_stream:
                def read_data(offset: int, size: int) -> bytes:
                    data_stream.seek(offset)
                    return data_stream.read(size)

                records = _capture_call_records(
                    calls,
                    b"",
                    limit,
                    True,
                    max_data_bytes,
                    start_index=start_index,
                    definitions=definitions,
                    pointer_size=pointer_size,
                    data_size=data_entry_bytes,
                    data_reader=read_data,
                )
        elif data_info is not None:
            records = _capture_records_without_data(
                archive,
                data_info,
                calls,
                limit,
                start_index=start_index,
                definitions=definitions,
                pointer_size=pointer_size,
            )
        else:
            records = _capture_call_records(
                calls,
                b"",
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
        "process_pid": process_pid,
        "calls_entry": calls_name,
        "data_entry": data_name if data_entry_bytes else None,
        "call_entry_bytes": len(calls),
        "data_entry_bytes": data_entry_bytes,
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
def capture_payload_summary(
    file_path: str,
    process_index: int | None = None,
    pid: int | None = None,
    api_name: str | None = None,
    api_module: str | None = None,
    limit: int = 1000,
    max_records: int = 100_000,
    max_data_bytes: int = 16_384,
) -> dict[str, Any]:
    """Summarize saved payload references by API and APMX data slot."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    if api_name is not None and not api_name.strip():
        raise ValueError("api_name must be non-empty when provided")
    if api_module is not None and not api_module.strip():
        raise ValueError("api_module must be non-empty when provided")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    groups: dict[tuple[int, int], dict[str, Any]] = {}
    scanned = 0
    total_references = 0
    truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        definitions = archive.read("definitions") if "definitions" in entries else None
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            if scanned >= max_records:
                truncated = True
                break
            calls = archive.read(f"process/{index}/calls")
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            data_info = entries.get(f"process/{index}/data")
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count

            def collect(
                records: list[dict[str, Any]],
                current_index: int = index,
                current_pid: int | None = process_pid,
            ) -> None:
                nonlocal scanned, total_references
                scanned += len(records)
                for record in records:
                    definition = record.get("definition", {})
                    name = definition.get("name")
                    module = definition.get("module")
                    if api_name and api_name.casefold() not in str(name or "").casefold():
                        continue
                    if api_module and api_module.casefold() not in str(module or "").casefold():
                        continue
                    definition_offset = int(
                        definition.get("offset", record.get("definition_offset", 0)) or 0
                    )
                    for reference in record.get("data_refs", []):
                        total_references += 1
                        slot = int(reference.get("slot", 0))
                        key = (definition_offset, slot)
                        item = groups.setdefault(
                            key,
                            {
                                "slot": slot,
                                "definition_offset": definition_offset,
                                "api": {
                                    "name": name,
                                    "module": module,
                                    "ordinal": definition.get("ordinal"),
                                },
                                "references": 0,
                                "bytes": 0,
                                "valid_references": 0,
                                "invalid_references": 0,
                                "oversize_references": 0,
                                "max_length": 0,
                                "process_indices": [],
                                "pids": set(),
                                "samples": [],
                                "_sample_hashes": set(),
                            },
                        )
                        item["references"] += 1
                        length = int(reference.get("length", 0) or 0)
                        item["bytes"] += length
                        item["max_length"] = max(item["max_length"], length)
                        if current_index not in item["process_indices"]:
                            item["process_indices"].append(current_index)
                        if current_pid is not None:
                            item["pids"].add(current_pid)
                        if not reference.get("valid", False):
                            item["invalid_references"] += 1
                            continue
                        item["valid_references"] += 1
                        payload = reference.get("payload")
                        if payload is None:
                            if reference.get("truncated"):
                                item["oversize_references"] += 1
                            continue
                        digest = payload.get("sha256")
                        if digest in item["_sample_hashes"] or len(item["samples"]) >= 3:
                            continue
                        item["_sample_hashes"].add(digest)
                        sample = {
                            key: payload[key]
                            for key in ("size", "sha256", "encoding", "hex_preview")
                            if key in payload
                        }
                        if "text" in payload:
                            sample["text"] = payload["text"][:1024]
                            sample["text_truncated"] = len(payload["text"]) > 1024
                        if "base64" in payload:
                            sample["base64_preview"] = payload["base64"][:1024]
                            sample["base64_truncated"] = len(payload["base64"]) > 1024
                        item["samples"].append(sample)

            if data_info is None:
                collect(
                    _capture_call_records(
                        calls,
                        b"",
                        page_count,
                        True,
                        max_data_bytes,
                        definitions=definitions,
                        pointer_size=pointer_size,
                    )
                )
            else:
                with archive.open(data_info) as data_stream:

                    def read_data(offset: int, size: int) -> bytes:
                        data_stream.seek(offset)
                        return data_stream.read(size)

                    collect(
                        _capture_call_records(
                            calls,
                            b"",
                            page_count,
                            True,
                            max_data_bytes,
                            definitions=definitions,
                            pointer_size=pointer_size,
                            data_size=data_info.file_size,
                            data_reader=read_data,
                        )
                    )
            if scanned >= max_records:
                break

    returned: list[dict[str, Any]] = []
    for item in groups.values():
        item["pids"] = sorted(item["pids"])
        item.pop("_sample_hashes")
        returned.append(item)
    returned.sort(key=lambda item: (-item["bytes"], -item["references"], item["slot"]))
    return {
        "file": str(path),
        "process_index": process_index,
        "pid": pid,
        "api_name": api_name,
        "api_module": api_module,
        "definitions_available": definitions is not None,
        "payloads": returned[:limit],
        "count": len(returned),
        "total_references": total_references,
        "scanned_records": scanned,
        "truncated": truncated or len(returned) > limit,
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
def capture_list_types(
    file_path: str,
    process_index: int | None = None,
    query: str = "",
    kind: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
    include_details: bool = False,
    pid: int | None = None,
) -> dict[str, Any]:
    """List type descriptors reachable from API definitions used by saved calls."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if kind is not None and not 0 <= kind <= 0xFFFFFFFF:
        raise ValueError("kind must be between 0 and 4294967295")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    types: dict[int, dict[str, Any]] = {}
    scanned = 0
    resolved_definitions: set[int] = set()
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        if "definitions" not in entries:
            return {
                "file": str(path),
                "process_index": process_index,
                "pid": pid,
                "definitions_available": False,
                "types": [],
                "count": 0,
                "scanned_records": 0,
                "truncated": False,
            }
        definitions = archive.read("definitions")
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )

        def add_type(
            type_info: Any,
            usage: dict[str, Any],
            path_name: str,
            visited: set[int],
        ) -> None:
            if not isinstance(type_info, dict):
                return
            offset = type_info.get("offset")
            if not isinstance(offset, int) or offset <= 0:
                return
            item = types.setdefault(
                offset,
                {
                    "offset": offset,
                    "kind": type_info.get("kind"),
                    "size": type_info.get("size"),
                    "flags": type_info.get("flags"),
                    "pointer_size": type_info.get("pointer_size"),
                    "_details": type_info,
                    "_uses": [],
                    "_use_keys": set(),
                    "_usage_truncated": False,
                },
            )
            use = {**usage, "path": path_name}
            use_key = tuple(sorted((key, str(value)) for key, value in use.items()))
            if use_key not in item["_use_keys"]:
                if len(item["_uses"]) < 256:
                    item["_uses"].append(use)
                else:
                    item["_usage_truncated"] = True
                item["_use_keys"].add(use_key)
            if offset in visited:
                return
            visited.add(offset)
            for index, field in enumerate(type_info.get("fields", [])):
                add_type(
                    field.get("type"),
                    usage,
                    f"{path_name}.field[{index}]",
                    visited,
                )
            add_type(
                type_info.get("element_type"),
                usage,
                f"{path_name}.element",
                visited,
            )

        for index in process_indices:
            if scanned >= max_records:
                break
            calls = archive.read(f"process/{index}/calls")
            data_name = f"process/{index}/data"
            data_info = entries.get(data_name)
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            records = _capture_records_without_data(
                archive,
                data_info,
                calls,
                page_count,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            scanned += len(records)
            for record in records:
                definition = record.get("definition", {})
                if not definition.get("valid"):
                    continue
                definition_offset = definition.get("offset")
                if isinstance(definition_offset, int):
                    resolved_definitions.add(definition_offset)
                usage = {
                    "process_index": index,
                    "pid": process_pid,
                    "definition_offset": definition.get("offset"),
                    "api_name": definition.get("name"),
                    "api_module": definition.get("module"),
                }
                for parameter_index, parameter in enumerate(definition.get("parameters", [])):
                    add_type(
                        parameter.get("type"),
                        usage,
                        f"parameter[{parameter_index}]",
                        set(),
                    )
                add_type(definition.get("return_type"), usage, "return", set())

    wanted = query.casefold()
    returned: list[dict[str, Any]] = []
    for item in types.values():
        details = item["_details"]
        if kind is not None and details.get("kind") != kind:
            continue
        if wanted and wanted not in json.dumps(details, ensure_ascii=False).casefold():
            continue
        result = {
            key: details[key]
            for key in (
                "offset",
                "kind",
                "size",
                "flags",
                "pointer_size",
                "name",
                "alias",
                "structure_size",
                "structure_size_flagged",
                "alignment",
                "struct_flags",
                "element_type_offset",
                "array_count",
                "array_flags",
                "enum_count",
                "enum_flags",
                "field_count",
            )
            if key in details
        }
        result["usage_count"] = len(item["_uses"])
        result["usage_truncated"] = item["_usage_truncated"]
        result["uses"] = item["_uses"]
        if include_details:
            result["type"] = details
        returned.append(result)
    returned.sort(key=lambda value: (str(value.get("name") or "").casefold(), value["offset"]))
    return {
        "file": str(path),
        "process_index": process_index,
        "pid": pid,
        "definitions_available": True,
        "types": returned[:limit],
        "count": len(returned),
        "scanned_records": scanned,
        "resolved_definitions": len(resolved_definitions),
        "truncated": len(returned) > limit or scanned >= max_records,
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
                "pid",
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
                        result.get("process_pid", ""),
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
        "process_pid": result.get("process_pid"),
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
    if output == path:
        raise ValueError("output_path must differ from the capture file")
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    calls_name = f"process/{process_index}/calls"
    data_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        try:
            calls = archive.read(calls_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture call entry not found: {calls_name}") from exc
        data_info = entries.get(data_name)
        if data_info is None:
            raise FileNotFoundError(f"Capture data entry not found: {data_name}")
        if len(calls) % pointer_size:
            raise ValueError(
                f"process calls entry is not an array of {pointer_size * 8}-bit offsets"
            )
        count = len(calls) // pointer_size
        if record_index >= count:
            raise IndexError(f"record_index {record_index} is outside {count} saved calls")
        record = _capture_records_without_data(
            archive,
            data_info,
            calls,
            1,
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

        written, digest = _copy_capture_slice(
            archive,
            data_info,
            reference["offset"],
            reference["length"],
            output,
            overwrite,
        )
    return {
        "extracted": True,
        "file": str(path),
        "process_index": process_index,
        "record_index": record_index,
        "slot": slot,
        "data_offset": reference["offset"],
        "size": written,
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
def capture_extract_process_data(
    file_path: str,
    process_index: int,
    output_path: str,
    offset: int = 0,
    length: int = 4096,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Extract a bounded arbitrary process-data range to a file."""
    if process_index < 0 or offset < 0:
        raise ValueError("process_index and offset must be non-negative")
    length = _limit(length, "length", 256 * 1024 * 1024)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")
    path = _capture_path(file_path)
    if output == path:
        raise ValueError("output_path must differ from the capture file")
    entry_name = f"process/{process_index}/data"
    archive, _, _ = _open_capture_zip(path)
    with archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise FileNotFoundError(f"Capture data entry not found: {entry_name}") from exc
        if info.is_dir():
            raise IsADirectoryError(f"Capture data entry is a directory: {entry_name}")
        if offset > info.file_size:
            raise ValueError(f"offset {offset} is outside {info.file_size}-byte data entry")
        requested = min(length, info.file_size - offset)
        written, digest = _copy_capture_slice(
            archive,
            info,
            offset,
            requested,
            output,
            overwrite,
        )
    return {
        "extracted": True,
        "file": str(path),
        "process_index": process_index,
        "entry": entry_name,
        "entry_size": info.file_size,
        "offset": offset,
        "requested_bytes": length,
        "size": written,
        "truncated": written < length,
        "output": str(output),
        "sha256": digest,
    }


@mcp.tool()
def capture_decode_process_data(
    file_path: str,
    process_index: int,
    offset: int = 0,
    length: int = 4096,
    max_items: int = 64,
) -> dict[str, Any]:
    """Decode a bounded arbitrary process-data slice with heuristic candidates."""
    if max_items < 1 or max_items > 4096:
        raise ValueError("max_items must be between 1 and 4096")
    result = capture_read_process_data(
        file_path,
        process_index=process_index,
        offset=offset,
        length=length,
    )
    raw = _payload_bytes(result)
    return {
        **result,
        "decoding": _capture_payload_candidates(raw, max_items),
    }


def _capture_decode_record(
    record: dict[str, Any], max_data_bytes: int, max_items: int
) -> tuple[dict[str, Any], dict[str, Any]]:
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
    return argument_stream, return_value


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
    argument_stream, return_value = _capture_decode_record(
        record, max_data_bytes, max_items
    )
    return {
        "file": result["file"],
        "process_index": process_index,
        "process_pid": result["process_pid"],
        "record_index": record_index,
        "record": record,
        "argument_stream": argument_stream,
        "return_value": return_value,
        "definitions_available": result["definitions_available"],
        "format": "APMX encoded parameter table; recognized scalar, string, structure, array, and enum values are exact, other values remain heuristic",
    }


@mcp.tool()
def capture_decode_calls(
    file_path: str,
    process_index: int = 0,
    start_index: int = 0,
    limit: int = 100,
    max_data_bytes: int = 4096,
    max_items: int = 64,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Decode a bounded page of saved calls with arguments and return values."""
    if process_index < 0 or start_index < 0:
        raise ValueError("process_index and start_index must be non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    max_items = _limit(max_items, "max_items", 256)
    result = capture_call_records(
        file_path,
        process_index=process_index,
        start_index=start_index,
        limit=limit,
        include_data=True,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
    )
    decoded = []
    for record in result["records"]:
        argument_stream, return_value = _capture_decode_record(
            record, max_data_bytes, max_items
        )
        decoded.append(
            {
                "index": record["index"],
                "record": record,
                "argument_stream": argument_stream,
                "return_value": return_value,
            }
        )
    return {
        "file": result["file"],
        "process_index": process_index,
        "process_pid": result["process_pid"],
        "architecture": result["architecture"],
        "count": result["count"],
        "start_index": result["start_index"],
        "end_index": decoded[-1]["index"] if decoded else None,
        "definitions_available": result["definitions_available"],
        "records": decoded,
        "truncated": result["truncated"],
    }


@mcp.tool()
def capture_decode_all_calls(
    file_path: str,
    limit: int = 10_000,
    max_data_bytes: int = 4096,
    max_items: int = 64,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Decode a bounded page of saved calls across every captured process."""
    limit = _limit(limit, "limit", 10_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    max_items = _limit(max_items, "max_items", 256)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    call_entries = [
        (int(match.group(1)), entry["size"])
        for entry in _zip_entries(path)
        if (match := re.fullmatch(r"process/(\d+)/calls", entry["name"], re.IGNORECASE))
    ]
    if any(size % pointer_size for _, size in call_entries):
        raise ValueError("process calls entry is not an array of saved offsets")
    indices = sorted(index for index, _ in call_entries)
    total_count = sum(size // pointer_size for _, size in call_entries)
    processes = []
    remaining = limit
    truncated = False
    for index in indices:
        if remaining <= 0:
            truncated = True
            break
        page = capture_decode_calls(
            str(path),
            process_index=index,
            limit=remaining,
            max_data_bytes=max_data_bytes,
            max_items=max_items,
            resolve_definitions=resolve_definitions,
        )
        processes.append(page)
        remaining -= len(page["records"])
        if page["truncated"]:
            truncated = True
            break
    return {
        "file": str(path),
        "architecture": "x86" if path.suffix.lower() == ".apmx86" else "x64",
        "process_indices": indices,
        "processes": processes,
        "count": sum(len(process["records"]) for process in processes),
        "total_count": total_count,
        "definitions_available": {
            str(process["process_index"]): process["definitions_available"]
            for process in processes
        },
        "truncated": truncated,
    }


@mcp.tool()
def capture_export_decoded_calls(
    file_path: str,
    output_path: str,
    limit: int = 10_000,
    output_format: str = "json",
    max_data_bytes: int = 4096,
    max_items: int = 64,
    resolve_definitions: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export bounded decoded calls across every captured process as JSON or CSV."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    limit = _limit(limit, "limit", 10_000)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")

    result = capture_decode_all_calls(
        file_path,
        limit=limit,
        max_data_bytes=max_data_bytes,
        max_items=max_items,
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
                "pid",
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
                "argument_index",
                "argument_name",
                "argument_type",
                "argument_value",
                "argument_payload",
                "return_available",
                "return_type",
                "return_value",
                "return_payload",
            ]
        )
        for process in result["processes"]:
            process_index = process["process_index"]
            for decoded in process["records"]:
                record = decoded["record"]
                definition = record.get("definition", {})
                context = record.get("context", {})
                arguments = decoded.get("argument_stream", {}).get("arguments", []) or [None]
                return_value = decoded.get("return_value", {})
                return_payload = return_value.get("payload", {})
                for argument in arguments:
                    argument = argument or {}
                    argument_payload = argument.get("payload", {})
                    writer.writerow(
                        [
                            process_index,
                            process.get("process_pid", ""),
                            record.get("index", ""),
                            record.get("offset", ""),
                            record.get("size", ""),
                            record.get("valid", ""),
                            record.get("flags", ""),
                            record.get("definition_offset", ""),
                            definition.get("name", ""),
                            definition.get("module", ""),
                            context.get("thread_id", ""),
                            context.get("thread_number", ""),
                            context.get("timestamp_utc", ""),
                            context.get("duration_seconds", ""),
                            context.get("error_code", ""),
                            argument.get("index", ""),
                            argument.get("name", ""),
                            json.dumps(argument.get("type", {}), ensure_ascii=False)
                            if argument.get("type")
                            else "",
                            json.dumps(argument.get("typed", {}), ensure_ascii=False)
                            if argument.get("typed")
                            else "",
                            argument_payload.get("text", argument_payload.get("base64", "")),
                            return_value.get("available", ""),
                            json.dumps(return_value.get("type", {}), ensure_ascii=False)
                            if return_value.get("type")
                            else "",
                            json.dumps(return_value.get("typed", {}), ensure_ascii=False)
                            if return_value.get("typed")
                            else "",
                            return_payload.get("text", return_payload.get("base64", "")),
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
        "count": result["count"],
        "total_count": result["total_count"],
        "truncated": result["truncated"],
        "size": len(encoded),
        "sha256": digest,
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
        entries = {info.filename: info for info in archive.infolist()}
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        processes = []
        for index in process_indices:
            calls_name = f"process/{index}/calls"
            data_name = f"process/{index}/data"
            calls = archive.read(calls_name)
            data_size = entries[data_name].file_size if data_name in entries else 0
            if data_size:
                with archive.open(data_name) as data_stream:
                    def read_data(offset: int, size: int) -> bytes:
                        data_stream.seek(offset)
                        return data_stream.read(size)

                    stats = _capture_call_stats(
                        calls,
                        b"",
                        max_records,
                        pointer_size,
                        data_size=data_size,
                        data_reader=read_data,
                    )
            else:
                stats = _capture_call_stats(calls, b"", max_records, pointer_size)
            processes.append(
                {
                    "process_index": index,
                    "process_pid": _capture_process_pid(archive, entries, index, pointer_size),
                    "calls_entry": calls_name,
                    "data_entry": data_name if data_size else None,
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
def capture_wait_for_calls(
    file_path: str,
    minimum_calls: int = 1,
    process_index: int | None = None,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.5,
    max_records: int = 1_000_000,
) -> dict[str, Any]:
    """Wait for a saved capture to become readable and reach a call count."""
    if minimum_calls < 0:
        raise ValueError("minimum_calls must be non-negative")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be finite and between 0 and 300")
    if not math.isfinite(poll_interval_seconds) or not 0.01 <= poll_interval_seconds <= 5:
        raise ValueError("poll_interval_seconds must be finite and between 0.01 and 5")
    max_records = _limit(max_records, "max_records", 1_000_000)
    candidate = Path(file_path).expanduser()
    if candidate.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("file_path must end in .apmx64 or .apmx86")
    path = candidate.resolve()
    started = time.monotonic()
    deadline = started + timeout_seconds
    attempts = 0
    last_stats: dict[str, Any] | None = None
    last_error: str | None = None
    while True:
        attempts += 1
        if path.is_file():
            try:
                stats = capture_call_stats(
                    str(path), process_index=process_index, max_records=max_records
                )
                last_stats = stats
                last_error = None
                calls = sum(item["count"] for item in stats["processes"])
                if calls >= minimum_calls:
                    return {
                        "ready": True,
                        "file": str(path),
                        "minimum_calls": minimum_calls,
                        "calls": calls,
                        "process_index": process_index,
                        "attempts": attempts,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "stats": stats,
                    }
            except (KeyError, OSError, ValueError, zipfile.BadZipFile) as exc:
                last_error = str(exc)
        else:
            last_error = f"Capture file not found: {path}"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval_seconds, remaining))
    calls = (
        sum(item["count"] for item in last_stats["processes"])
        if last_stats is not None
        else 0
    )
    return {
        "ready": False,
        "file": str(path),
        "minimum_calls": minimum_calls,
        "calls": calls,
        "process_index": process_index,
        "attempts": attempts,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stats": last_stats,
        "error": last_error,
    }


@mcp.tool()
def capture_wait_for_new_calls(
    file_path: str,
    minimum_new_calls: int = 1,
    process_index: int | None = None,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.5,
    max_records: int = 1_000_000,
    max_returned_calls: int = 10_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
) -> dict[str, Any]:
    """Wait for calls added after this tool starts and return their records."""
    if minimum_new_calls < 0:
        raise ValueError("minimum_new_calls must be non-negative")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be finite and between 0 and 300")
    if not math.isfinite(poll_interval_seconds) or not 0.01 <= poll_interval_seconds <= 5:
        raise ValueError("poll_interval_seconds must be finite and between 0.01 and 5")
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_returned_calls = _limit(max_returned_calls, "max_returned_calls", 50_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    candidate = Path(file_path).expanduser()
    if candidate.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("file_path must end in .apmx64 or .apmx86")
    path = candidate.resolve()
    started = time.monotonic()
    deadline = started + timeout_seconds
    attempts = 0
    baseline: dict[int, int] | None = None
    last_stats: dict[str, Any] | None = None
    last_error: str | None = None

    while True:
        attempts += 1
        try:
            stats = capture_call_stats(
                str(path), process_index=process_index, max_records=max_records
            )
            last_stats = stats
            last_error = None
            counts = {
                int(item["process_index"]): int(item["count"])
                for item in stats["processes"]
            }
            if baseline is None:
                baseline = counts.copy()
            else:
                for index, count in counts.items():
                    if count < baseline.get(index, 0):
                        baseline[index] = count
            new_counts = {
                index: max(0, count - baseline.get(index, 0))
                for index, count in counts.items()
            }
            new_total = sum(new_counts.values())
            if new_total >= minimum_new_calls:
                records: list[dict[str, Any]] = []
                remaining = max_returned_calls
                if new_total and remaining:
                    for index in sorted(new_counts):
                        count = new_counts[index]
                        if not count:
                            continue
                        result = capture_call_records(
                            str(path),
                            process_index=index,
                            start_index=baseline.get(index, 0),
                            limit=min(count, remaining),
                            include_data=include_data,
                            max_data_bytes=max_data_bytes,
                            resolve_definitions=resolve_definitions,
                        )
                        records.extend(result["records"])
                        remaining = max_returned_calls - len(records)
                        if not remaining:
                            break
                return {
                    "ready": True,
                    "file": str(path),
                    "minimum_new_calls": minimum_new_calls,
                    "baseline_calls": sum(baseline.values()),
                    "current_calls": sum(counts.values()),
                    "new_calls": new_total,
                    "new_process_counts": {
                        str(index): count for index, count in sorted(new_counts.items()) if count
                    },
                    "records": records,
                    "records_truncated": new_total > len(records),
                    "process_index": process_index,
                    "attempts": attempts,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "stats": stats,
                }
        except (KeyError, OSError, ValueError, zipfile.BadZipFile) as exc:
            last_error = str(exc)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval_seconds, remaining))

    current_counts = {
        int(item["process_index"]): int(item["count"])
        for item in (last_stats or {}).get("processes", [])
    }
    baseline = baseline or {}
    new_counts = {
        index: max(0, count - baseline.get(index, 0))
        for index, count in current_counts.items()
    }
    return {
        "ready": False,
        "file": str(path),
        "minimum_new_calls": minimum_new_calls,
        "baseline_calls": sum(baseline.values()),
        "current_calls": sum(current_counts.values()),
        "new_calls": sum(new_counts.values()),
        "new_process_counts": {
            str(index): count for index, count in sorted(new_counts.items()) if count
        },
        "records": [],
        "records_truncated": False,
        "process_index": process_index,
        "attempts": attempts,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stats": last_stats,
        "error": last_error,
    }


@mcp.tool()
def capture_list_apis(
    file_path: str,
    process_index: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
    pid: int | None = None,
) -> dict[str, Any]:
    """List resolved API definitions ordered by saved call frequency."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    apis: dict[int, dict[str, Any]] = {}
    scanned = 0
    truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        if "definitions" not in entries:
            return {
                "file": str(path),
                "process_index": process_index,
                "pid": pid,
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
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            calls = archive.read(f"process/{index}/calls")
            data_name = f"process/{index}/data"
            data_info = entries.get(data_name)
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count
            records = _capture_records_without_data(
                archive,
                data_info,
                calls,
                page_count,
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
                        "_pids": set(),
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
                if process_pid is not None:
                    item["_pids"].add(process_pid)
                item["first_record"] = min(item["first_record"], record["index"])
                item["last_record"] = max(item["last_record"], record["index"])
                context = record.get("context", {})
                item["_thread_ids"].add(context.get("thread_id", 0))
                if context.get("timestamp_filetime"):
                    item["_timestamps"].append(context["timestamp_filetime"])
                if context.get("duration_valid") and math.isfinite(context["duration_seconds"]):
                    item["_durations"].append(context["duration_seconds"])
                if context.get("error_code"):
                    item["_error_count"] += 1
            if scanned >= max_records:
                break
    for item in apis.values():
        item["pids"] = sorted(item.pop("_pids"))
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
        "pid": pid,
        "definitions_available": True,
        "apis": returned[:limit],
        "count": len(returned),
        "scanned_records": scanned,
        "truncated": truncated or len(returned) > limit,
    }


@mcp.tool()
def capture_error_summary(
    file_path: str,
    process_index: int | None = None,
    pid: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
) -> dict[str, Any]:
    """Aggregate nonzero saved call error codes and their affected APIs."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    errors: dict[int, dict[str, Any]] = {}
    scanned = 0
    truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        definitions = archive.read("definitions") if "definitions" in entries else None
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            if scanned >= max_records:
                truncated = True
                break
            calls = archive.read(f"process/{index}/calls")
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count
            records = _capture_records_without_data(
                archive,
                entries.get(f"process/{index}/data"),
                calls,
                page_count,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            scanned += len(records)
            for record in records:
                context = record.get("context")
                if not context:
                    continue
                error_code = int(context.get("error_code", 0))
                if not error_code:
                    continue
                item = errors.setdefault(
                    error_code,
                    {
                        "error_code": error_code,
                        "hex": f"0x{error_code:08x}",
                        "count": 0,
                        "process_indices": [],
                        "pids": set(),
                        "thread_ids": set(),
                        "apis": {},
                        "first_record": {"process_index": index, "index": record["index"]},
                        "last_record": {"process_index": index, "index": record["index"]},
                        "_timestamps": [],
                        "_durations": [],
                    },
                )
                item["count"] += 1
                if index not in item["process_indices"]:
                    item["process_indices"].append(index)
                if process_pid is not None:
                    item["pids"].add(process_pid)
                item["thread_ids"].add(int(context.get("thread_id", 0)))
                definition = record.get("definition", {})
                api_key = int(definition.get("offset", 0)) if definition else 0
                api = item["apis"].setdefault(
                    api_key,
                    {
                        "offset": api_key,
                        "name": definition.get("name"),
                        "module": definition.get("module"),
                        "count": 0,
                    },
                )
                api["count"] += 1
                location = (index, record["index"])
                if location < (
                    item["first_record"]["process_index"],
                    item["first_record"]["index"],
                ):
                    item["first_record"] = {"process_index": index, "index": record["index"]}
                if location > (
                    item["last_record"]["process_index"],
                    item["last_record"]["index"],
                ):
                    item["last_record"] = {"process_index": index, "index": record["index"]}
                timestamp = context.get("timestamp_filetime")
                if timestamp:
                    item["_timestamps"].append(timestamp)
                duration = context.get("duration_seconds")
                if context.get("duration_valid") and isinstance(duration, (int, float)) and math.isfinite(duration):
                    item["_durations"].append(duration)
            if scanned >= max_records:
                break

    returned: list[dict[str, Any]] = []
    for item in errors.values():
        timestamps = item.pop("_timestamps")
        durations = item.pop("_durations")
        item["pids"] = sorted(item["pids"])
        item["thread_ids"] = sorted(item["thread_ids"])
        item["apis"] = sorted(item["apis"].values(), key=lambda api: (-api["count"], api["name"] or ""))
        item["context"] = {
            "api_count": len(item["apis"]),
            "thread_count": len(item["thread_ids"]),
            "first_timestamp_utc": _windows_filetime(min(timestamps)) if timestamps else None,
            "last_timestamp_utc": _windows_filetime(max(timestamps)) if timestamps else None,
        }
        if durations:
            item["context"]["duration_seconds"] = {
                "minimum": min(durations),
                "maximum": max(durations),
                "average": sum(durations) / len(durations),
            }
        returned.append(item)
    returned.sort(key=lambda item: (-item["count"], item["error_code"]))
    return {
        "file": str(path),
        "process_index": process_index,
        "pid": pid,
        "errors": returned[:limit],
        "count": len(returned),
        "error_count": sum(item["count"] for item in returned),
        "scanned_records": scanned,
        "truncated": truncated or len(returned) > limit,
    }


@mcp.tool()
def capture_list_definitions(
    file_path: str,
    process_index: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
    include_details: bool = False,
    pid: int | None = None,
) -> dict[str, Any]:
    """List API definitions referenced by saved calls, including unresolved offsets."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    definitions_by_offset: dict[int, dict[str, Any]] = {}
    scanned = 0
    unknown_records = 0
    invalid_records = 0
    truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        if "definitions" not in entries:
            return {
                "file": str(path),
                "process_index": process_index,
                "pid": pid,
                "definitions_available": False,
                "definitions": [],
                "count": 0,
                "scanned_records": 0,
                "resolved_records": 0,
                "unknown_records": 0,
                "invalid_records": 0,
                "truncated": False,
            }
        definitions = archive.read("definitions")
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            calls_name = f"process/{index}/calls"
            data_name = f"process/{index}/data"
            calls = archive.read(calls_name)
            data_info = entries.get(data_name)
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count
            records = _capture_records_without_data(
                archive,
                data_info,
                calls,
                page_count,
                definitions=definitions,
                pointer_size=pointer_size,
            )
            for record in records:
                scanned += 1
                definition_offset = record.get("definition_offset", 0)
                if not definition_offset:
                    unknown_records += 1
                    continue
                definition = record.get("definition", {})
                if not definition.get("valid"):
                    invalid_records += 1
                item = definitions_by_offset.setdefault(
                    definition_offset,
                    {
                        "offset": definition_offset,
                        "count": 0,
                        "process_indices": [],
                        "_pids": set(),
                        "first_record": {
                            "process_index": index,
                            "index": record["index"],
                        },
                        "last_record": {
                            "process_index": index,
                            "index": record["index"],
                        },
                        "definition": definition,
                    },
                )
                item["count"] += 1
                if index not in item["process_indices"]:
                    item["process_indices"].append(index)
                if process_pid is not None:
                    item["_pids"].add(process_pid)
                first = item["first_record"]
                last = item["last_record"]
                if (index, record["index"]) < (first["process_index"], first["index"]):
                    item["first_record"] = {"process_index": index, "index": record["index"]}
                if (index, record["index"]) > (last["process_index"], last["index"]):
                    item["last_record"] = {"process_index": index, "index": record["index"]}
            if scanned >= max_records:
                break
    returned = sorted(
        definitions_by_offset.values(),
        key=lambda item: (-item["count"], item["offset"]),
    )
    for item in returned:
        definition = item.pop("definition")
        item["pids"] = sorted(item.pop("_pids"))
        item.update(
            {
                key: definition[key]
                for key in ("valid", "error", "name", "module", "ordinal", "flags", "parameter_count")
                if key in definition
            }
        )
        if include_details:
            item["details"] = definition
    return {
        "file": str(path),
        "process_index": process_index,
        "pid": pid,
        "definitions_available": True,
        "definitions": returned[:limit],
        "count": len(returned),
        "scanned_records": scanned,
        "resolved_records": scanned - unknown_records - invalid_records,
        "unknown_records": unknown_records,
        "invalid_records": invalid_records,
        "truncated": truncated or len(returned) > limit,
    }


@mcp.tool()
def capture_search_definitions(
    file_path: str,
    query: str,
    process_index: int | None = None,
    limit: int = 100,
    max_records: int = 1_000_000,
    include_details: bool = False,
    pid: int | None = None,
) -> dict[str, Any]:
    """Search referenced API definitions, parameters, and nested types in a saved capture."""
    if not query:
        raise ValueError("query must not be empty")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    source = capture_list_definitions(
        file_path,
        process_index=process_index,
        limit=10_000,
        max_records=max_records,
        include_details=True,
        pid=pid,
    )
    wanted = query.casefold()

    def matching_paths(value: Any, path: str = "$") -> list[dict[str, str]]:
        matches: list[dict[str, str]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                matches.extend(matching_paths(child, f"{path}.{key}"))
                if len(matches) >= 32:
                    break
        elif isinstance(value, list):
            for index, child in enumerate(value):
                matches.extend(matching_paths(child, f"{path}[{index}]"))
                if len(matches) >= 32:
                    break
        elif isinstance(value, str) and wanted in value.casefold():
            matches.append({"path": path, "value": value})
        return matches[:32]

    matches = []
    for item in source["definitions"]:
        paths = matching_paths(item.get("details", {}))
        if not paths:
            continue
        result = {key: value for key, value in item.items() if key != "details"}
        result["matches"] = paths
        if include_details:
            result["details"] = item["details"]
        matches.append(result)
    return {
        "file": source["file"],
        "process_index": process_index,
        "pid": pid,
        "query": query,
        "definitions_available": source["definitions_available"],
        "matches": matches[:limit],
        "count": len(matches),
        "scanned_records": source["scanned_records"],
        "unknown_records": source["unknown_records"],
        "invalid_records": source["invalid_records"],
        "truncated": source["truncated"] or len(matches) > limit,
    }


@mcp.tool()
def capture_export_definitions(
    file_path: str,
    output_path: str,
    process_index: int | None = None,
    limit: int = 10_000,
    max_records: int = 1_000_000,
    output_format: str = "json",
    include_details: bool = True,
    overwrite: bool = False,
    pid: int | None = None,
) -> dict[str, Any]:
    """Export referenced API definitions as bounded JSON or CSV."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")

    result = capture_list_definitions(
        file_path,
        process_index=process_index,
        limit=limit,
        max_records=max_records,
        include_details=include_details,
        pid=pid,
    )
    if output_format == "json":
        content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    else:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(
            [
                "offset",
                "count",
                "process_indices",
                "pids",
                "first_record",
                "last_record",
                "valid",
                "name",
                "module",
                "ordinal",
                "flags",
                "parameter_count",
                "error",
                "details_json",
            ]
        )
        for definition in result["definitions"]:
            writer.writerow(
                [
                    definition.get("offset", ""),
                    definition.get("count", ""),
                    json.dumps(definition.get("process_indices", [])),
                    json.dumps(definition.get("pids", [])),
                    json.dumps(definition.get("first_record", {})),
                    json.dumps(definition.get("last_record", {})),
                    definition.get("valid", ""),
                    definition.get("name", ""),
                    definition.get("module", ""),
                    definition.get("ordinal", ""),
                    definition.get("flags", ""),
                    definition.get("parameter_count", ""),
                    definition.get("error", ""),
                    json.dumps(definition.get("details", {}), ensure_ascii=False)
                    if include_details
                    else "",
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
        "count": len(result["definitions"]),
        "scanned_records": result["scanned_records"],
        "truncated": result["truncated"],
        "size": len(encoded),
        "sha256": digest,
    }


@mcp.tool()
def capture_search_calls(
    file_path: str,
    query: str = "",
    process_index: int | None = None,
    limit: int = 100,
    max_records: int = 100_000,
    max_data_bytes: int = 16_384,
    resolve_definitions: bool = False,
    decode_arguments: bool = False,
    pattern_hex: str | None = None,
    include_record_bytes: bool = False,
    pid: int | None = None,
    query_regex: bool = False,
    thread_id: int | None = None,
    error_code: int | None = None,
    flags: int | None = None,
    api_name: str | None = None,
    api_module: str | None = None,
    definition_offset: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    start_time_utc: str | None = None,
    end_time_utc: str | None = None,
) -> dict[str, Any]:
    """Search saved call payloads, API definitions, and decoded arguments."""
    if not query and pattern_hex is None:
        raise ValueError("query or pattern_hex is required")
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    if thread_id is not None and not 0 <= thread_id <= 0xFFFFFFFF:
        raise ValueError("thread_id must be between 0 and 4294967295")
    if error_code is not None and not 0 <= error_code <= 0xFFFFFFFF:
        raise ValueError("error_code must be between 0 and 4294967295")
    if flags is not None and not 0 <= flags <= 0xFF:
        raise ValueError("flags must be between 0 and 255")
    if api_name is not None and not api_name.strip():
        raise ValueError("api_name must be non-empty when provided")
    if api_module is not None and not api_module.strip():
        raise ValueError("api_module must be non-empty when provided")
    if definition_offset is not None and definition_offset < 0:
        raise ValueError("definition_offset must be non-negative")
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
    start_filetime = _parse_utc_timestamp(start_time_utc)
    end_filetime = _parse_utc_timestamp(end_time_utc)
    if start_filetime is not None and end_filetime is not None and start_filetime > end_filetime:
        raise ValueError("start_time_utc must not be after end_time_utc")
    if len(query) > 4096:
        raise ValueError("query must not exceed 4096 characters")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    pattern = None
    if pattern_hex is not None:
        if not pattern_hex.strip():
            raise ValueError("pattern_hex must not be empty when provided")
        try:
            pattern = bytes.fromhex(pattern_hex)
        except ValueError as exc:
            raise ValueError("pattern_hex must contain hexadecimal bytes") from exc
        if not pattern or len(pattern) > 256:
            raise ValueError("pattern_hex must contain between 1 and 256 bytes")
    query_expression = None
    if query_regex and query:
        try:
            query_expression = re.compile(query, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid query regular expression: {exc}") from exc
    resolve_definitions = resolve_definitions or any(
        value is not None for value in (api_name, api_module, definition_offset)
    )
    filters = {
        "pid": pid,
        "thread_id": thread_id,
        "error_code": error_code,
        "flags": flags,
        "api_name": api_name,
        "api_module": api_module,
        "definition_offset": definition_offset,
        "min_duration_seconds": min_duration_seconds,
        "max_duration_seconds": max_duration_seconds,
        "start_time_utc": start_time_utc,
        "end_time_utc": end_time_utc,
    }

    def collect_byte_matches(
        payload: bytes,
        needle: bytes,
        results: list[dict[str, Any]],
        scope: str,
        data_offset: int,
        slot: int | None = None,
    ) -> None:
        position = payload.find(needle)
        while position >= 0 and len(results) < 32:
            context_start = max(0, position - 16)
            context_end = min(len(payload), position + len(needle) + 16)
            results.append(
                {
                    "scope": scope,
                    "slot": slot,
                    "data_offset": data_offset,
                    "match_offset": position,
                    "absolute_offset": data_offset + position,
                    "length": len(needle),
                    "context_hex": payload[context_start:context_end].hex(" "),
                }
            )
            position = payload.find(needle, position + 1)

    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    wanted = query.casefold()
    matches: list[dict[str, Any]] = []
    scanned = 0
    scan_truncated = False
    process_indices: set[int] = set()
    with archive, ExitStack() as streams:
        entries = {info.filename: info for info in archive.infolist()}
        for name in entries:
            match = re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE)
            if match and (process_index is None or int(match.group(1)) == process_index):
                process_indices.add(int(match.group(1)))
        for index in sorted(process_indices):
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            calls = archive.read(f"process/{index}/calls")
            data_info = entries.get(f"process/{index}/data")
            data_size = data_info.file_size if data_info is not None else 0
            data_stream = (
                streams.enter_context(archive.open(data_info))
                if data_info is not None
                else None
            )

            def read_data(offset: int, size: int, stream: Any = data_stream) -> bytes:
                if stream is None:
                    return b""
                stream.seek(offset)
                return stream.read(size)

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
                b"",
                min(record_count, max_records - scanned),
                True,
                max_data_bytes,
                definitions=definitions,
                pointer_size=pointer_size,
                data_size=data_size,
                data_reader=read_data if data_stream is not None else None,
            )
            for record in records:
                scanned += 1
                context = record.get("context", {})
                duration = context.get("duration_seconds") if context.get("duration_valid") else None
                if duration is not None and not math.isfinite(duration):
                    duration = None
                if thread_id is not None and context.get("thread_id") != thread_id:
                    continue
                if error_code is not None and context.get("error_code") != error_code:
                    continue
                if flags is not None and record.get("flags") != flags:
                    continue
                definition = record.get("definition", {})
                if definition_offset is not None and definition.get("offset") != definition_offset:
                    continue
                if api_name is not None and api_name.casefold() not in str(
                    definition.get("name", "")
                ).casefold():
                    continue
                if api_module is not None and api_module.casefold() not in str(
                    definition.get("module", "")
                ).casefold():
                    continue
                timestamp = context.get("timestamp_filetime", 0)
                if start_filetime is not None and (not timestamp or timestamp < start_filetime):
                    continue
                if end_filetime is not None and (not timestamp or timestamp > end_filetime):
                    continue
                if min_duration_seconds is not None and (
                    duration is None or duration < min_duration_seconds
                ):
                    continue
                if max_duration_seconds is not None and (
                    duration is None or duration > max_duration_seconds
                ):
                    continue
                payload_matches = []
                for reference in record.get("data_refs", []):
                    text = reference.get("payload", {}).get("text")
                    if not wanted or text is None:
                        continue
                    if query_expression is not None:
                        found = query_expression.search(text)
                        if found is None:
                            continue
                        position = found.start()
                        match_end = found.end()
                    else:
                        if wanted not in text.casefold():
                            continue
                        position = text.casefold().find(wanted)
                        match_end = position + len(query)
                    start = max(0, position - 120)
                    end = min(len(text), match_end + 120)
                    payload_matches.append(
                        {
                            "slot": reference["slot"],
                            "offset": reference["offset"],
                            "length": reference["length"],
                            "snippet": text[start:end],
                        }
                    )
                api_matches = []
                api_text = f"{definition.get('name', '')} {definition.get('module', '')}"
                api_matches_query = (
                    query_expression.search(api_text)
                    if query_expression is not None and wanted
                    else None
                )
                if wanted and definition.get("valid") and (
                    api_matches_query is not None
                    if query_expression is not None
                    else wanted in api_text.casefold()
                ):
                    api_matches.append(
                        {
                            "name": definition.get("name"),
                            "module": definition.get("module"),
                            "ordinal": definition.get("ordinal"),
                            "offset": definition.get("offset"),
                        }
                    )
                argument_matches = []
                if decode_arguments and wanted:
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
                            if (
                                query_expression.search(searchable)
                                if query_expression is not None
                                else wanted in searchable.casefold()
                            ):
                                argument_matches.append(argument)
                byte_matches = []
                if pattern is not None:
                    for reference in record.get("data_refs", []):
                        if not reference.get("valid"):
                            continue
                        relative = reference["offset"]
                        end = relative + reference["length"]
                        if end > data_size:
                            continue
                        payload = read_data(relative, reference["length"])
                        if len(payload) < reference["length"]:
                            continue
                        collect_byte_matches(
                            payload, pattern, byte_matches, "payload", relative, reference["slot"]
                        )
                    if include_record_bytes and record.get("valid") and len(byte_matches) < 32:
                        record_offset = int(record["offset"])
                        record_size = int(record["size"])
                        collect_byte_matches(
                            read_data(record_offset, record_size),
                            pattern,
                            byte_matches,
                            "record",
                            record_offset,
                        )
                if payload_matches or api_matches or argument_matches or byte_matches:
                    match = {
                        "process_index": index,
                        "pid": process_pid,
                        "record": record,
                        "payload_matches": payload_matches,
                    }
                    if api_matches:
                        match["api_matches"] = api_matches
                    if argument_matches:
                        match["argument_matches"] = argument_matches
                    if byte_matches:
                        match["byte_matches"] = byte_matches
                    matches.append(
                        match
                    )
                    if len(matches) >= limit:
                        return {
                            "file": str(path),
                            "query": query,
                            "query_regex": query_regex,
                            "process_index": process_index,
                            "pid": pid,
                            "filters": filters,
                            "matches": matches,
                            "count": len(matches),
                            "scanned_records": scanned,
                            "pattern_hex": pattern.hex(" ") if pattern is not None else None,
                            "truncated": True,
                            "definitions_resolved": resolve_definitions,
                            "arguments_decoded": decode_arguments,
                        }
            if scanned >= max_records:
                break
    return {
        "file": str(path),
        "query": query,
        "query_regex": query_regex,
        "process_index": process_index,
        "pid": pid,
        "filters": filters,
        "matches": matches,
        "count": len(matches),
        "scanned_records": scanned,
        "pattern_hex": pattern.hex(" ") if pattern is not None else None,
        "truncated": scan_truncated,
        "definitions_resolved": resolve_definitions,
        "arguments_decoded": decode_arguments,
        "record_bytes_searched": include_record_bytes,
    }


@mcp.tool()
def capture_filter_calls(
    file_path: str,
    process_index: int | None = None,
    thread_id: int | None = None,
    error_code: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    start_time_utc: str | None = None,
    end_time_utc: str | None = None,
    limit: int = 500,
    max_records: int = 100_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
    api_name: str | None = None,
    api_module: str | None = None,
    definition_offset: int | None = None,
    flags: int | None = None,
    pid: int | None = None,
    thread_number: int | None = None,
    module_base: int | None = None,
) -> dict[str, Any]:
    """Filter saved calls by API definition, thread, error, and duration context."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if thread_id is not None and not 0 <= thread_id <= 0xFFFFFFFF:
        raise ValueError("thread_id must be between 0 and 4294967295")
    if thread_number is not None and not 0 <= thread_number <= 0xFFFFFFFF:
        raise ValueError("thread_number must be between 0 and 4294967295")
    if module_base is not None and not 0 <= module_base <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("module_base must be between 0 and 18446744073709551615")
    if error_code is not None and not 0 <= error_code <= 0xFFFFFFFF:
        raise ValueError("error_code must be between 0 and 4294967295")
    if flags is not None and not 0 <= flags <= 0xFF:
        raise ValueError("flags must be between 0 and 255")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    if api_name is not None and not api_name.strip():
        raise ValueError("api_name must be non-empty when provided")
    if api_module is not None and not api_module.strip():
        raise ValueError("api_module must be non-empty when provided")
    if definition_offset is not None and definition_offset < 0:
        raise ValueError("definition_offset must be non-negative")
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
    start_filetime = _parse_utc_timestamp(start_time_utc)
    end_filetime = _parse_utc_timestamp(end_time_utc)
    if start_filetime is not None and end_filetime is not None and start_filetime > end_filetime:
        raise ValueError("start_time_utc must not be after end_time_utc")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    resolve_definitions = resolve_definitions or any(
        value is not None for value in (api_name, api_module, definition_offset)
    )
    filters = {
        "thread_id": thread_id,
        "thread_number": thread_number,
        "module_base": module_base,
        "error_code": error_code,
        "flags": flags,
        "api_name": api_name,
        "api_module": api_module,
        "definition_offset": definition_offset,
        "pid": pid,
        "min_duration_seconds": min_duration_seconds,
        "max_duration_seconds": max_duration_seconds,
        "start_time_utc": start_time_utc,
        "end_time_utc": end_time_utc,
    }
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    matches: list[dict[str, Any]] = []
    scanned = 0
    scan_truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        definitions = archive.read("definitions") if resolve_definitions and "definitions" in entries else None
        process_entries = []
        for name in entries:
            match = re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE)
            if not match:
                continue
            index = int(match.group(1))
            if process_index is not None and index != process_index:
                continue
            process_pid = None
            info_name = f"process/{index}/info"
            if info_name in entries:
                try:
                    process_pid = _parse_capture_process_info(
                        archive.read(info_name), pointer_size
                    ).get("pid")
                except ValueError:
                    if pid is not None:
                        continue
            if pid is not None and process_pid != pid:
                continue
            process_entries.append((index, process_pid))
        process_entries.sort()
        for index, process_pid in process_entries:
            calls = archive.read(f"process/{index}/calls")
            data_name = f"process/{index}/data"
            data_info = entries.get(data_name)
            data = archive.read(data_info) if include_data and data_info is not None else b""
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            scan_truncated |= page_count < record_count
            if data_info is not None and not include_data:
                records = _capture_records_without_data(
                    archive,
                    data_info,
                    calls,
                    page_count,
                    definitions=definitions,
                    pointer_size=pointer_size,
                )
            else:
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
                if thread_number is not None and context.get("thread_number") != thread_number:
                    continue
                if module_base is not None and int(context.get("module_base", "0"), 16) != module_base:
                    continue
                if error_code is not None and context.get("error_code") != error_code:
                    continue
                if flags is not None and record.get("flags") != flags:
                    continue
                definition = record.get("definition", {})
                if definition_offset is not None and definition.get("offset") != definition_offset:
                    continue
                if api_name is not None and api_name.casefold() not in str(
                    definition.get("name", "")
                ).casefold():
                    continue
                if api_module is not None and api_module.casefold() not in str(
                    definition.get("module", "")
                ).casefold():
                    continue
                timestamp = context.get("timestamp_filetime", 0)
                if start_filetime is not None and (
                    not timestamp or timestamp < start_filetime
                ):
                    continue
                if end_filetime is not None and (
                    not timestamp or timestamp > end_filetime
                ):
                    continue
                if min_duration_seconds is not None and (
                    duration is None or duration < min_duration_seconds
                ):
                    continue
                if max_duration_seconds is not None and (
                    duration is None or duration > max_duration_seconds
                ):
                    continue
                matches.append(
                    {"process_index": index, "pid": process_pid, "record": record}
                )
                if len(matches) >= limit:
                    return {
                        "file": str(path),
                        "process_index": process_index,
                        "filters": filters,
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
        "filters": filters,
        "matches": matches,
        "count": len(matches),
        "scanned_records": scanned,
        "truncated": scan_truncated,
        "definitions_resolved": resolve_definitions,
    }


@mcp.tool()
def capture_slowest_calls(
    file_path: str,
    process_index: int | None = None,
    pid: int | None = None,
    thread_id: int | None = None,
    api_name: str | None = None,
    api_module: str | None = None,
    min_duration_seconds: float = 0.0,
    limit: int = 100,
    max_records: int = 100_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = True,
) -> dict[str, Any]:
    """Return the slowest measured saved calls in descending duration order."""
    if not math.isfinite(min_duration_seconds) or min_duration_seconds < 0:
        raise ValueError("min_duration_seconds must be finite and non-negative")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    max_data_bytes = _limit(max_data_bytes, "max_data_bytes", 16 * 1024 * 1024)
    filtered = capture_filter_calls(
        file_path,
        process_index=process_index,
        pid=pid,
        thread_id=thread_id,
        api_name=api_name,
        api_module=api_module,
        min_duration_seconds=min_duration_seconds,
        limit=10_000,
        max_records=max_records,
        include_data=include_data,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
    )
    measured = [
        item
        for item in filtered["matches"]
        if item["record"].get("context", {}).get("duration_valid")
        and isinstance(item["record"].get("context", {}).get("duration_seconds"), (int, float))
        and math.isfinite(item["record"]["context"]["duration_seconds"])
    ]
    measured.sort(
        key=lambda item: (
            -item["record"]["context"]["duration_seconds"],
            item["process_index"],
            item["record"].get("index", 0),
        )
    )
    return {
        "file": filtered["file"],
        "process_index": process_index,
        "pid": pid,
        "thread_id": thread_id,
        "api_name": api_name,
        "api_module": api_module,
        "min_duration_seconds": min_duration_seconds,
        "calls": measured[:limit],
        "count": len(measured),
        "measured_count": len(measured),
        "scanned_records": filtered["scanned_records"],
        "truncated": filtered["truncated"] or len(measured) > limit,
        "definitions_resolved": resolve_definitions,
    }


@mcp.tool()
def capture_call_timeline(
    file_path: str,
    process_index: int | None = None,
    start_time_utc: str | None = None,
    end_time_utc: str | None = None,
    order_by: str = "timestamp",
    descending: bool = False,
    limit: int = 500,
    max_records: int = 100_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
    api_name: str | None = None,
    api_module: str | None = None,
    definition_offset: int | None = None,
    flags: int | None = None,
    pid: int | None = None,
    thread_number: int | None = None,
    module_base: int | None = None,
    thread_id: int | None = None,
    error_code: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
) -> dict[str, Any]:
    """Return saved calls as one bounded cross-process timeline."""
    if order_by not in {"timestamp", "capture"}:
        raise ValueError("order_by must be timestamp or capture")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    filtered = capture_filter_calls(
        file_path,
        process_index=process_index,
        thread_id=thread_id,
        error_code=error_code,
        min_duration_seconds=min_duration_seconds,
        max_duration_seconds=max_duration_seconds,
        flags=flags,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        limit=10_000,
        max_records=max_records,
        include_data=include_data,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
        api_name=api_name,
        api_module=api_module,
        definition_offset=definition_offset,
        pid=pid,
        thread_number=thread_number,
        module_base=module_base,
    )
    events = list(filtered["matches"])
    if order_by == "capture":
        events.sort(
            key=lambda item: (item["process_index"], item["record"].get("index", 0)),
            reverse=descending,
        )
    else:
        with_timestamps = [
            item
            for item in events
            if item["record"].get("context", {}).get("timestamp_filetime")
        ]
        without_timestamps = [
            item
            for item in events
            if not item["record"].get("context", {}).get("timestamp_filetime")
        ]
        with_timestamps.sort(
            key=lambda item: (
                item["record"]["context"]["timestamp_filetime"],
                item["process_index"],
                item["record"].get("index", 0),
            ),
            reverse=descending,
        )
        events = with_timestamps + without_timestamps
    return {
        "file": filtered["file"],
        "process_index": process_index,
        "thread_id": thread_id,
        "error_code": error_code,
        "min_duration_seconds": min_duration_seconds,
        "max_duration_seconds": max_duration_seconds,
        "thread_number": thread_number,
        "module_base": module_base,
        "flags": flags,
        "order_by": order_by,
        "descending": descending,
        "start_time_utc": start_time_utc,
        "end_time_utc": end_time_utc,
        "api_name": api_name,
        "api_module": api_module,
        "definition_offset": definition_offset,
        "pid": pid,
        "timeline": events[:limit],
        "count": min(len(events), limit),
        "scanned_records": filtered["scanned_records"],
        "truncated": filtered["truncated"] or len(events) > limit,
        "definitions_resolved": resolve_definitions,
    }


@mcp.tool()
def capture_api_transitions(
    file_path: str,
    process_index: int | None = None,
    pid: int | None = None,
    thread_id: int | None = None,
    api_module: str | None = None,
    limit: int = 1000,
    max_records: int = 100_000,
) -> dict[str, Any]:
    """Count adjacent resolved API transitions for each captured thread."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    if thread_id is not None and not 0 <= thread_id <= 0xFFFFFFFF:
        raise ValueError("thread_id must be between 0 and 4294967295")
    if api_module is not None and not api_module.strip():
        raise ValueError("api_module must be non-empty when provided")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    timeline = capture_call_timeline(
        file_path,
        process_index=process_index,
        order_by="capture",
        limit=10_000,
        max_records=max_records,
        include_data=False,
        resolve_definitions=True,
        api_module=api_module,
        pid=pid,
        thread_id=thread_id,
    )
    previous: dict[tuple[int, int], dict[str, Any]] = {}
    transitions: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    for event in timeline["timeline"]:
        record = event.get("record", {})
        definition = record.get("definition", {})
        if not definition.get("valid") or not definition.get("name"):
            continue
        context = record.get("context", {})
        current_thread = int(context.get("thread_id", 0))
        current_process = int(event.get("process_index", 0))
        stream_key = (current_process, current_thread)
        current = {
            "process_index": current_process,
            "pid": event.get("pid"),
            "thread_id": current_thread,
            "index": record.get("index"),
            "api": {
                key: definition.get(key)
                for key in ("offset", "name", "module", "ordinal")
                if key in definition
            },
        }
        prior = previous.get(stream_key)
        if prior is not None:
            prior_api = prior["api"]
            current_api = current["api"]
            key = (
                current_process,
                current_thread,
                int(prior_api.get("offset", 0) or 0),
                int(current_api.get("offset", 0) or 0),
            )
            item = transitions.setdefault(
                key,
                {
                    "process_index": current_process,
                    "pid": current.get("pid"),
                    "thread_id": current_thread,
                    "from": prior_api,
                    "to": current_api,
                    "count": 0,
                    "first_transition": {
                        "from_record": prior.get("index"),
                        "to_record": current.get("index"),
                    },
                    "last_transition": {
                        "from_record": prior.get("index"),
                        "to_record": current.get("index"),
                    },
                },
            )
            item["count"] += 1
            item["last_transition"] = {
                "from_record": prior.get("index"),
                "to_record": current.get("index"),
            }
        previous[stream_key] = current
    returned = sorted(
        transitions.values(),
        key=lambda item: (-item["count"], item["process_index"], item["thread_id"]),
    )
    return {
        "file": timeline["file"],
        "process_index": process_index,
        "pid": pid,
        "thread_id": thread_id,
        "api_module": api_module,
        "transitions": returned[:limit],
        "count": len(returned),
        "scanned_records": timeline["scanned_records"],
        "truncated": timeline["truncated"] or len(returned) > limit,
        "definitions_resolved": timeline["definitions_resolved"],
    }


@mcp.tool()
def capture_export_timeline(
    file_path: str,
    output_path: str,
    process_index: int | None = None,
    start_time_utc: str | None = None,
    end_time_utc: str | None = None,
    order_by: str = "timestamp",
    descending: bool = False,
    limit: int = 500,
    max_records: int = 100_000,
    include_data: bool = False,
    max_data_bytes: int = 4096,
    resolve_definitions: bool = False,
    api_name: str | None = None,
    api_module: str | None = None,
    definition_offset: int | None = None,
    flags: int | None = None,
    pid: int | None = None,
    thread_number: int | None = None,
    module_base: int | None = None,
    thread_id: int | None = None,
    error_code: int | None = None,
    min_duration_seconds: float | None = None,
    max_duration_seconds: float | None = None,
    output_format: str = "json",
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export a filtered cross-process call timeline as bounded JSON or CSV."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")

    result = capture_call_timeline(
        file_path,
        process_index=process_index,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        order_by=order_by,
        descending=descending,
        limit=limit,
        max_records=max_records,
        include_data=include_data,
        max_data_bytes=max_data_bytes,
        resolve_definitions=resolve_definitions,
        api_name=api_name,
        api_module=api_module,
        definition_offset=definition_offset,
        flags=flags,
        pid=pid,
        thread_number=thread_number,
        module_base=module_base,
        thread_id=thread_id,
        error_code=error_code,
        min_duration_seconds=min_duration_seconds,
        max_duration_seconds=max_duration_seconds,
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
                "pid",
                "thread_id",
                "thread_number",
                "module_base",
                "timestamp_utc",
                "duration_seconds",
                "error_code",
                "data_refs_json",
            ]
        )
        for item in result["timeline"]:
            record = item["record"]
            definition = record.get("definition", {})
            context = record.get("context", {})
            writer.writerow(
                [
                    item["process_index"],
                    record.get("index", ""),
                    record.get("offset", ""),
                    record.get("size", ""),
                    record.get("valid", ""),
                    record.get("flags", ""),
                    record.get("definition_offset", ""),
                    definition.get("name", ""),
                    definition.get("module", ""),
                    item.get("pid", ""),
                    context.get("thread_id", ""),
                    context.get("thread_number", ""),
                    context.get("module_base", ""),
                    context.get("timestamp_utc", ""),
                    context.get("duration_seconds", ""),
                    context.get("error_code", ""),
                    json.dumps(record.get("data_refs", []), ensure_ascii=False),
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
        "count": result["count"],
        "truncated": result["truncated"],
        "order_by": order_by,
        "descending": descending,
        "size": len(encoded),
        "sha256": digest,
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
        process_pid = _capture_process_pid(archive, entries, process_index, pointer_size)
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
        "process_pid": process_pid,
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
def capture_read_call_bytes(
    file_path: str,
    process_index: int,
    record_index: int,
    max_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Read one complete saved call record as bounded raw bytes."""
    if process_index < 0 or record_index < 0:
        raise ValueError("process_index and record_index must be non-negative")
    max_bytes = _limit(max_bytes, "max_bytes", 16 * 1024 * 1024)
    context = capture_calls_around(
        file_path,
        process_index=process_index,
        record_index=record_index,
        before=0,
        after=0,
        include_data=False,
    )
    record = context["records"][0]
    if not record.get("valid"):
        raise ValueError(record.get("error", "saved call record is invalid"))
    size = int(record["size"])
    if size > max_bytes:
        raise ValueError(f"call record exceeds max_bytes: {size}")
    data = capture_read_process_data(
        file_path,
        process_index=process_index,
        offset=int(record["offset"]),
        length=size,
    )
    raw = _payload_bytes(data)
    if len(raw) != size:
        raise ValueError("call record bytes could not be read completely")
    return {
        "file": context["file"],
        "process_index": process_index,
        "process_pid": context.get("process_pid"),
        "record_index": record_index,
        "offset": record["offset"],
        "size": size,
        "record": record,
        "record_bytes": {
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "hex_preview": raw[:256].hex(" "),
            "hex_truncated": len(raw) > 256,
            "base64": base64.b64encode(raw).decode("ascii"),
        },
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
def capture_monitoring_events(
    file_path: str,
    event_type: str = "all",
    process_query: str = "",
    limit: int = 1000,
) -> dict[str, Any]:
    """Return structured module, child-process, and summary events from a capture log."""
    if event_type not in {"all", "module", "child_process", "summary", "unknown"}:
        raise ValueError("event_type must be all, module, child_process, summary, or unknown")
    if len(process_query) > 4096:
        raise ValueError("process_query must not exceed 4096 characters")
    limit = _limit(limit, "limit", 10_000)
    source = capture_monitoring_log(file_path, limit=10_000)
    wanted_process = process_query.casefold()
    events = [
        event
        for event in source["events"]
        if (event_type == "all" or event.get("type") == event_type)
        and (
            not wanted_process
            or wanted_process in str(event.get("process", "")).casefold()
        )
    ]
    by_type: dict[str, int] = {}
    processes: dict[str, dict[str, Any]] = {}
    for event in events:
        kind = str(event.get("type", "unknown"))
        by_type[kind] = by_type.get(kind, 0) + 1
        process = str(event.get("process", ""))
        if not process:
            continue
        item = processes.setdefault(
            process,
            {"process": process, "modules": [], "children": [], "summaries": []},
        )
        if kind == "module" and event.get("module") not in item["modules"]:
            item["modules"].append(event.get("module"))
        elif kind == "child_process":
            item["children"].append(
                {key: event.get(key) for key in ("pid", "attach") if key in event}
            )
        elif kind == "summary":
            item["summaries"].append(
                {key: event.get(key) for key in ("calls", "usage") if key in event}
            )
    return {
        "file": source["file"],
        "event_type": event_type,
        "process_query": process_query,
        "events": events[:limit],
        "count": len(events),
        "by_type": by_type,
        "processes": list(processes.values()),
        "truncated": source["truncated"] or len(events) > limit,
    }


@mcp.tool()
def capture_export_monitoring_log(
    file_path: str,
    output_path: str,
    query: str = "",
    limit: int = 10_000,
    output_format: str = "json",
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export parsed monitoring-log events as bounded JSON or CSV."""
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    limit = _limit(limit, "limit", 100_000)
    output = Path(output_path).expanduser()
    if not output.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {output.parent}")
    output = output.resolve()
    if output.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output}")

    result = capture_monitoring_log(file_path, query=query, limit=limit)
    if output_format == "json":
        content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    else:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(
            ["line", "type", "process", "address", "module", "pid", "attach", "calls", "usage"]
        )
        for event in result["events"]:
            writer.writerow(
                [
                    event.get("line", ""),
                    event.get("type", ""),
                    event.get("process", ""),
                    event.get("address", ""),
                    event.get("module", ""),
                    event.get("pid", ""),
                    event.get("attach", ""),
                    event.get("calls", ""),
                    event.get("usage", ""),
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
        "query": query,
        "count": len(result["events"]),
        "matched_count": result["count"],
        "truncated": result["truncated"],
        "size": len(encoded),
        "sha256": digest,
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
def capture_list_modules(
    file_path: str,
    process_index: int | None = None,
    query: str = "",
    limit: int = 1000,
    pid: int | None = None,
) -> dict[str, Any]:
    """List loaded modules across captured processes with their occurrences and bases."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    source = capture_list_processes(file_path, limit=2000)
    wanted = query.casefold()
    modules: dict[str, dict[str, Any]] = {}
    for process in source["processes"]:
        index = process["index"]
        if process_index is not None and index != process_index:
            continue
        metadata = process.get("metadata", {})
        process_pid = metadata.get("pid") if isinstance(metadata, dict) else None
        if pid is not None and process_pid != pid:
            continue
        loaded = metadata.get("loaded_modules", []) if isinstance(metadata, dict) else []
        seen_in_process: set[str] = set()
        for item in loaded:
            path = str(item.get("path") or "")
            if not path or wanted not in path.casefold():
                continue
            key = path.casefold()
            module = modules.setdefault(
                key,
                {
                    "name": path.replace("/", "\\").rsplit("\\", 1)[-1],
                    "path": path,
                    "process_indices": [],
                    "pids": [],
                    "occurrences": [],
                },
            )
            if key not in seen_in_process:
                module["process_indices"].append(index)
                if process_pid is not None:
                    module["pids"].append(process_pid)
                seen_in_process.add(key)
            module["occurrences"].append(
                {
                    "process_index": index,
                    "pid": process_pid,
                    "index": item.get("index"),
                    "base": item.get("base"),
                    "field": item.get("field"),
                    "source": "loaded_modules",
                }
            )
        if loaded:
            continue
        for path in process.get("modules", []):
            if not path or wanted not in path.casefold():
                continue
            key = path.casefold()
            module = modules.setdefault(
                key,
                {
                    "name": path.replace("/", "\\").rsplit("\\", 1)[-1],
                    "path": path,
                    "process_indices": [],
                    "pids": [],
                    "occurrences": [],
                },
            )
            if index not in module["process_indices"]:
                module["process_indices"].append(index)
                if process_pid is not None:
                    module["pids"].append(process_pid)
            module["occurrences"].append(
                {"process_index": index, "pid": process_pid, "source": "process_strings"}
            )
    returned = sorted(modules.values(), key=lambda item: (item["name"].casefold(), item["path"].casefold()))
    return {
        "file": source["file"],
        "process_index": process_index,
        "pid": pid,
        "query": query,
        "modules": returned[:limit],
        "count": len(returned),
        "truncated": len(returned) > limit or source["truncated"],
    }


@mcp.tool()
def capture_list_threads(
    file_path: str,
    process_index: int | None = None,
    limit: int = 1000,
    max_records: int = 1_000_000,
    pid: int | None = None,
) -> dict[str, Any]:
    """List per-thread activity, errors, timings, and record ranges in a capture."""
    if process_index is not None and process_index < 0:
        raise ValueError("process_index must be non-negative")
    if pid is not None and not 1 <= pid <= 0xFFFFFFFF:
        raise ValueError("pid must be between 1 and 4294967295")
    limit = _limit(limit, "limit", 10_000)
    max_records = _limit(max_records, "max_records", 1_000_000)
    path = _capture_path(file_path)
    pointer_size = 4 if path.suffix.lower() == ".apmx86" else 8
    archive, _, _ = _open_capture_zip(path)
    threads: dict[tuple[int, int, int], dict[str, Any]] = {}
    scanned = 0
    truncated = False
    with archive:
        entries = {info.filename: info for info in archive.infolist()}
        process_indices = sorted(
            int(match.group(1))
            for name in entries
            if (match := re.fullmatch(r"process/(\d+)/calls", name, re.IGNORECASE))
            and (process_index is None or int(match.group(1)) == process_index)
        )
        for index in process_indices:
            if scanned >= max_records:
                truncated = True
                break
            calls = archive.read(f"process/{index}/calls")
            if len(calls) % pointer_size:
                raise ValueError(
                    f"process/{index}/calls is not an array of {pointer_size * 8}-bit offsets"
                )
            process_pid = _capture_process_pid(archive, entries, index, pointer_size)
            if pid is not None and process_pid != pid:
                continue
            record_count = len(calls) // pointer_size
            page_count = min(record_count, max_records - scanned)
            truncated |= page_count < record_count
            records = _capture_records_without_data(
                archive,
                entries.get(f"process/{index}/data"),
                calls,
                page_count,
                pointer_size=pointer_size,
            )
            scanned += len(records)
            for record in records:
                context = record.get("context")
                if not context:
                    continue
                thread_id = int(context.get("thread_id", 0))
                thread_number = int(context.get("thread_number", 0))
                key = (index, thread_id, thread_number)
                item = threads.setdefault(
                    key,
                    {
                        "process_index": index,
                        "pid": process_pid,
                        "thread_id": thread_id,
                        "thread_number": thread_number,
                        "count": 0,
                        "first_record": record["index"],
                        "last_record": record["index"],
                        "error_count": 0,
                        "flags": {},
                        "error_codes": {},
                        "_timestamps": [],
                        "_durations": [],
                    },
                )
                item["count"] += 1
                item["first_record"] = min(item["first_record"], record["index"])
                item["last_record"] = max(item["last_record"], record["index"])
                flag_key = f"0x{int(record.get('flags', 0)):02x}"
                item["flags"][flag_key] = item["flags"].get(flag_key, 0) + 1
                error_code = int(context.get("error_code", 0))
                if error_code:
                    item["error_count"] += 1
                    error_key = f"0x{error_code:08x}"
                    item["error_codes"][error_key] = item["error_codes"].get(error_key, 0) + 1
                timestamp = context.get("timestamp_filetime")
                if timestamp:
                    item["_timestamps"].append(timestamp)
                duration = context.get("duration_seconds")
                if context.get("duration_valid") and isinstance(duration, (int, float)) and math.isfinite(duration):
                    item["_durations"].append(duration)
            if scanned >= max_records:
                break
    for item in threads.values():
        timestamps = item.pop("_timestamps")
        durations = item.pop("_durations")
        item["context"] = {
            "duration_count": len(durations),
            "first_timestamp_utc": _windows_filetime(min(timestamps)) if timestamps else None,
            "last_timestamp_utc": _windows_filetime(max(timestamps)) if timestamps else None,
        }
        if durations:
            item["context"]["duration_seconds"] = {
                "minimum": min(durations),
                "maximum": max(durations),
                "average": sum(durations) / len(durations),
            }
    returned = sorted(
        threads.values(),
        key=lambda item: (-item["count"], item["process_index"], item["thread_id"]),
    )
    return {
        "file": str(path),
        "process_index": process_index,
        "pid": pid,
        "threads": returned[:limit],
        "count": len(returned),
        "scanned_records": scanned,
        "truncated": truncated or len(returned) > limit,
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
    entry_name: str | None = None,
    max_bytes: int = 256 * 1024 * 1024,
) -> dict[str, Any]:
    """Find a hexadecimal byte pattern in the raw file or a decompressed entry."""
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
    if entry_name is not None:
        if not entry_name:
            raise ValueError("entry_name must not be empty")
        max_bytes = _limit(max_bytes, "max_bytes", 256 * 1024 * 1024)
        archive, _, _ = _open_capture_zip(path)
        with archive:
            try:
                info = archive.getinfo(entry_name)
            except KeyError as exc:
                raise FileNotFoundError(f"ZIP entry not found: {entry_name}") from exc
            if info.is_dir():
                raise IsADirectoryError(f"ZIP entry is a directory: {entry_name}")
            if start_offset >= info.file_size:
                return {
                    "file": str(path),
                    "entry": entry_name,
                    "pattern_hex": pattern.hex(" "),
                    "start_offset": start_offset,
                    "offsets": [],
                    "count": 0,
                    "truncated": False,
                }
            search_end = min(info.file_size, start_offset + max_bytes)
            truncated = search_end < info.file_size
            overlap = b""
            consumed = start_offset
            with archive.open(info) as member:
                member.seek(start_offset)
                while consumed < search_end:
                    chunk = member.read(min(1024 * 1024, search_end - consumed))
                    if not chunk:
                        break
                    window = overlap + chunk
                    base_offset = consumed - len(overlap)
                    position = window.find(pattern)
                    while position >= 0:
                        absolute = base_offset + position
                        if (
                            absolute >= start_offset
                            and absolute + len(pattern) > consumed
                            and absolute + len(pattern) <= search_end
                        ):
                            offsets.append(absolute)
                            if len(offsets) >= limit:
                                truncated = True
                                break
                        position = window.find(pattern, position + 1)
                    if len(offsets) >= limit:
                        break
                    overlap = window[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
                    consumed += len(chunk)
        return {
            "file": str(path),
            "entry": entry_name,
            "pattern_hex": pattern.hex(" "),
            "start_offset": start_offset,
            "offsets": offsets,
            "count": len(offsets),
            "truncated": truncated,
        }
    with path.open("rb") as handle:
        if start_offset >= path.stat().st_size:
            return {
                "file": str(path),
                "entry": None,
                "pattern_hex": pattern.hex(" "),
                "offsets": [],
                "count": 0,
            }
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
        "entry": None,
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

