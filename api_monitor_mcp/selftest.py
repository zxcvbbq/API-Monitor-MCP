"""Runnable end-to-end self-test for the parser and tool surface."""

from __future__ import annotations

import base64
import io
import json
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from tempfile import TemporaryDirectory

from . import capture_tools, gui_tools
from .capture_format import (
    _capture_call_records,
    _capture_call_stats,
    _capture_info,
    _capture_output_path,
    _capture_strings,
    _capture_type_info,
    _capture_zip_offset,
    _parse_capture_process_info,
    _zip_entries,
)
from .capture_tools import (
    capture_api_transitions,
    capture_call_graph,
    capture_call_records,
    capture_call_stats,
    capture_call_timeline,
    capture_calls_around,
    capture_compare,
    capture_compare_all_calls,
    capture_compare_apis,
    capture_compare_calls,
    capture_compare_entry,
    capture_decode_all_calls,
    capture_decode_call,
    capture_decode_calls,
    capture_decode_process_data,
    capture_error_summary,
    capture_export_all_calls,
    capture_export_api_summary,
    capture_export_call_graph,
    capture_export_calls,
    capture_export_decoded_calls,
    capture_export_definitions,
    capture_export_error_summary,
    capture_export_monitoring_events,
    capture_export_monitoring_log,
    capture_export_search_calls,
    capture_export_slowest_calls,
    capture_export_timeline,
    capture_extract_call_payload,
    capture_extract_entry,
    capture_extract_process_data,
    capture_filter_calls,
    capture_find_bytes,
    capture_find_call_sequence,
    capture_info,
    capture_list_apis,
    capture_list_definitions,
    capture_list_directory,
    capture_list_filters,
    capture_list_modules,
    capture_list_processes,
    capture_list_threads,
    capture_list_types,
    capture_monitoring_events,
    capture_monitoring_log,
    capture_overview,
    capture_payload_summary,
    capture_process_overview,
    capture_read_call_bytes,
    capture_read_definition,
    capture_read_entry,
    capture_read_process_data,
    capture_read_type,
    capture_search_calls,
    capture_search_definitions,
    capture_search_directory,
    capture_search_entries,
    capture_slowest_calls,
    capture_validate,
    capture_wait_for_calls,
    capture_wait_for_new_calls,
    capture_wait_for_new_events,
    capture_xml_entry,
)
from .capture_values import (
    _capture_array_element_size,
    _capture_encoded_argument_stream,
    _capture_exact_scalar,
    _capture_exact_value,
    _read_payload,
)
from .definition_tools import (
    api_monitor_list_api_files,
    api_monitor_parse_api_definition,
    api_monitor_search_api_details,
    api_monitor_search_apis,
    api_monitor_search_variables,
)
from .gui_runtime import (
    _detect_executable_architecture,
    _gui_pane_title,
    _gui_traffic_delta,
    _named_gui_rows,
)
from .gui_tools import (
    api_monitor_call_stack,
    api_monitor_environment,
    api_monitor_export_traffic,
    api_monitor_gui_tree_check_query,
    api_monitor_process_architecture,
    api_monitor_process_details,
    api_monitor_search_traffic,
    api_monitor_wait_for_new_traffic,
)


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
                "sample.exe: Monitoring Module 0x1234 -> C:\\sample.dll\n"
                "Summary | 1 calls | 5% | sample.exe\n",
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
        executable = Path(directory) / "sample.exe"
        pe = bytearray(0x4A)
        pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x40)
        pe[0x40:0x44] = b"PE\0\0"
        struct.pack_into("<H", pe, 0x44, 0x014C)
        executable.write_bytes(pe)
        assert _detect_executable_architecture(executable)["architecture"] == "x86"
        second_path = Path(directory) / "variants" / "second.apmx64"
        second_path.parent.mkdir()
        second_payload = io.BytesIO()
        with zipfile.ZipFile(second_payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("metadata.txt", "process=changed.exe\n")
            archive.writestr("extra.bin", b"new")
        second_path.write_bytes(b"\r\nAPI Monitor 64-bit Capture\r\nRBAPM" + second_payload.getvalue())

        info = _capture_info(path)
        assert capture_info(str(path))["architecture"] == "x64"
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
        assert deep_validation["info"]["valid"]
        assert deep_validation["architecture_match"]
        assert deep_validation["streams"][0]["definitions"]["resolved"] == 1
        overview = capture_overview(str(path), include_log=True, log_limit=10)
        assert overview["validation"]["valid"]
        assert overview["stats"]["totals"]["count"] == 1
        assert overview["apis"]["apis"][0]["name"] == "CreateFileW"
        assert overview["log"]["events"][0]["type"] == "module"
        process_overview = capture_process_overview(str(path), 0, include_calls=True)
        assert process_overview["pid"] == 1234
        assert process_overview["threads"]["count"] == 1
        assert process_overview["errors"]["error_count"] == 1
        assert process_overview["calls"]["records"][0]["definition"]["name"] == "CreateFileW"
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
        regex_log = capture_monitoring_log(
            str(path), r"sample\.exe:.*Module", 10, query_regex=True
        )
        assert regex_log["count"] == 1 and regex_log["query_regex"]
        summary_log = capture_monitoring_log(str(path), "summary", 10)
        assert summary_log["events"][0]["calls"] == 1
        assert summary_log["events"][0]["process"] == "sample.exe"
        events = capture_monitoring_events(str(path), event_type="summary")
        assert events["count"] == 1
        assert events["by_type"]["summary"] == 1
        assert events["processes"][0]["summaries"][0]["calls"] == 1
        regex_events = capture_monitoring_events(
            str(path), process_query=r"sample\.exe", process_query_regex=True
        )
        assert regex_events["count"] == 2 and regex_events["process_query_regex"]
        events_json_path = Path(directory) / "events.json"
        events_export = capture_export_monitoring_events(
            str(path), str(events_json_path), event_type="summary"
        )
        assert events_export["count"] == 1
        assert json.loads(events_json_path.read_text())["events"][0]["calls"] == 1
        events_csv_path = Path(directory) / "events.csv"
        events_csv_export = capture_export_monitoring_events(
            str(path), str(events_csv_path), event_type="summary", output_format="csv"
        )
        assert events_csv_export["format"] == "csv"
        assert "calls" in events_csv_path.read_text().splitlines()[0]
        assert ",1,5%" in events_csv_path.read_text()
        full_log_entry = capture_read_entry(str(path), "log/monitoring.txt", max_bytes=1024)
        log_slice = capture_read_entry(str(path), "log/monitoring.txt", max_bytes=4, offset=7)
        assert log_slice["text"] == full_log_entry["text"][7:11]
        assert log_slice["truncated"]
        log_json = Path(directory) / "monitoring.json"
        log_export = capture_export_monitoring_log(str(path), str(log_json), query="module")
        assert log_export["count"] == 1
        assert json.loads(log_json.read_text())["events"][0]["module"] == r"C:\sample.dll"
        regex_log_json = Path(directory) / "monitoring-regex.json"
        regex_export = capture_export_monitoring_log(
            str(path),
            str(regex_log_json),
            query=r"sample\.exe:.*Module",
            query_regex=True,
        )
        assert regex_export["count"] == 1
        log_csv = Path(directory) / "monitoring.csv"
        log_csv_export = capture_export_monitoring_log(
            str(path), str(log_csv), query="module", output_format="csv"
        )
        assert log_csv_export["count"] == 1
        assert "C:\\sample.dll" in log_csv.read_text()
        summary_csv = Path(directory) / "summary.csv"
        summary_csv_export = capture_export_monitoring_log(
            str(path), str(summary_csv), query="summary", output_format="csv"
        )
        assert summary_csv_export["count"] == 1
        assert "calls" in summary_csv.read_text().splitlines()[0]
        assert ",1,5%" in summary_csv.read_text()
        searched = capture_search_entries(str(path), "CreateFile", 10)
        assert searched["entries"][0]["entry"] == "calls.bin"
        assert not searched["truncated"]
        xml = capture_xml_entry(str(path), query="CreateFile")
        assert xml["root"] == "DisplayFilters"
        assert xml["nodes"][0]["attributes"]["Field"] == "API"
        filters = capture_list_filters(str(path), filter_type="display")
        assert filters["count"] == 1
        assert filters["filters"][0]["attributes"]["Operator"] == "contains"
        call_records = capture_call_records(str(path), include_data=True)
        assert call_records["count"] == 1
        assert call_records["process_pid"] == 1234
        assert call_records["start_index"] == 0
        assert call_records["records"][0]["data_refs"][0]["payload"]["text"] == "hello"
        payload_summary = capture_payload_summary(str(path), api_name="CreateFile")
        slot_zero = next(item for item in payload_summary["payloads"] if item["slot"] == 0)
        assert slot_zero["bytes"] == 5
        assert slot_zero["samples"][0]["text"] == "hello"
        original_timeline = capture_tools.capture_call_timeline
        capture_tools.capture_call_timeline = lambda *_args, **_kwargs: {
            "file": "sample.apmx64",
            "timeline": [
                {
                    "process_index": 0,
                    "pid": 1234,
                    "record": {
                        "index": 0,
                        "definition": {"valid": True, "offset": 16, "name": "CreateFileW", "module": "kernel32.dll"},
                        "context": {"thread_id": 0x1234},
                    },
                },
                {
                    "process_index": 0,
                    "pid": 1234,
                    "record": {
                        "index": 1,
                        "definition": {"valid": True, "offset": 32, "name": "ReadFile", "module": "kernel32.dll"},
                        "context": {"thread_id": 0x1234},
                    },
                },
            ],
            "scanned_records": 2,
            "truncated": False,
            "definitions_resolved": True,
        }
        try:
            transitions = capture_api_transitions(str(path))
            sequence = capture_find_call_sequence(
                str(path), ["CreateFileW", "ReadFile"], max_gap=0
            )
            graph = capture_call_graph(str(path))
            graph_json = Path(directory) / "graph.json"
            graph_export = capture_export_call_graph(str(path), str(graph_json))
            graph_csv = Path(directory) / "graph.csv"
            graph_csv_export = capture_export_call_graph(
                str(path), str(graph_csv), output_format="csv"
            )
        finally:
            capture_tools.capture_call_timeline = original_timeline
        assert transitions["count"] == 1
        assert transitions["transitions"][0]["from"]["name"] == "CreateFileW"
        assert transitions["transitions"][0]["to"]["name"] == "ReadFile"
        assert sequence["count"] == 1
        assert sequence["matches"][0]["start_record"] == 0
        assert graph["node_count"] == 2
        assert graph["edge_count"] == 1
        assert graph["edges"][0]["from"]["id"] == graph["nodes"][0]["id"]
        assert graph_export["edge_count"] == 1
        assert json.loads(graph_json.read_text())["node_count"] == 2
        assert graph_csv_export["format"] == "csv"
        assert "kind,id,process_index" in graph_csv.read_text().splitlines()[0]
        lazy_call_records = capture_call_records(str(path), include_data=False)
        assert lazy_call_records["data_entry_bytes"] == len(record) + 9
        assert lazy_call_records["records"][0]["valid"]
        assert "payload" not in lazy_call_records["records"][0]["data_refs"][0]
        raw_call = capture_read_call_bytes(str(path), 0, 0)
        assert raw_call["size"] == 160
        assert raw_call["process_pid"] == 1234
        assert base64.b64decode(raw_call["record_bytes"]["base64"]) == bytes(record)
        decoded_data = capture_decode_process_data(str(path), 0, offset=160, length=5)
        assert decoded_data["decoding"]["strings"][0]["text"] == "hello"
        call_context = call_records["records"][0]["context"]
        assert call_context["thread_id"] == 0x1234
        assert call_context["thread_number"] == 7
        assert call_context["module_base"] == "0x00007ff600001000"
        assert call_context["error_code"] == 5
        assert call_context["timestamp_utc"] == "2020-01-01T00:00:00+00:00"
        assert call_context["duration_seconds"] == 0.125
        stats = capture_call_stats(str(path))
        assert stats["processes"][0]["process_pid"] == 1234
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
        limited_stats = _capture_call_stats(bounded_calls, bytes(bounded_records), 1)
        assert limited_stats["count"] == 257
        assert limited_stats["scanned_records"] == 1 and limited_stats["truncated"]
        sized_stats = _capture_call_stats(
            struct.pack("<Q", 0), b"", 1, data_size=len(record),
            data_reader=lambda offset, size: record[offset : offset + size],
        )
        assert sized_stats["data_bytes"] == len(record)
        assert sized_stats["valid_records"] == 1
        partial_records = _capture_call_records(
            bounded_calls,
            bytes(bounded_records),
            1,
            False,
            0,
            start_index=256,
        )
        assert partial_records[0]["index"] == 256 and partial_records[0]["size"] == 160
        filtered = capture_filter_calls(
            str(path),
            thread_id=0x1234,
            error_code=5,
            min_duration_seconds=0.1,
            max_duration_seconds=0.2,
            start_time_utc="2020-01-01T00:00:00Z",
            end_time_utc="2020-01-01T00:00:01+00:00",
        )
        assert filtered["count"] == 1
        assert filtered["matches"][0]["record"]["index"] == 0
        assert filtered["matches"][0]["pid"] == 1234
        slowest = capture_slowest_calls(str(path))
        assert slowest["count"] == 1
        assert slowest["calls"][0]["record"]["context"]["duration_seconds"] == 0.125
        slowest_json_path = Path(directory) / "slowest.json"
        slowest_export = capture_export_slowest_calls(str(path), str(slowest_json_path))
        assert slowest_export["count"] == 1
        assert json.loads(slowest_json_path.read_text())["calls"][0]["record"]["index"] == 0
        slowest_csv_path = Path(directory) / "slowest.csv"
        slowest_csv_export = capture_export_slowest_calls(
            str(path), str(slowest_csv_path), output_format="csv"
        )
        assert slowest_csv_export["format"] == "csv"
        assert "duration_seconds" in slowest_csv_path.read_text().splitlines()[0]
        assert "CreateFileW" in slowest_csv_path.read_text()
        api_filtered = capture_filter_calls(
            str(path),
            api_name="CreateFileW",
            api_module="kernel32",
            definition_offset=16,
            flags=1,
            pid=1234,
            thread_number=7,
            module_base=0x7FF600001000,
            include_data=True,
        )
        assert api_filtered["count"] == 1
        assert api_filtered["definitions_resolved"]
        assert api_filtered["matches"][0]["record"]["data_refs"][0]["payload"]["text"] == "hello"
        timeline = capture_call_timeline(str(path), order_by="timestamp")
        assert timeline["count"] == 1
        assert timeline["timeline"][0]["record"]["context"]["timestamp_utc"] == "2020-01-01T00:00:00+00:00"
        api_timeline = capture_call_timeline(
            str(path),
            api_name="CreateFileW",
            api_module="kernel32",
            flags=1,
            pid=1234,
            thread_number=7,
            module_base=0x7FF600001000,
            thread_id=0x1234,
            error_code=5,
            min_duration_seconds=0.1,
            max_duration_seconds=0.2,
        )
        assert api_timeline["count"] == 1
        assert api_timeline["timeline"][0]["record"]["definition"]["name"] == "CreateFileW"
        timeline_json = Path(directory) / "timeline.json"
        timeline_export = capture_export_timeline(
            str(path),
            str(timeline_json),
            thread_id=0x1234,
            error_code=5,
            min_duration_seconds=0.1,
            max_duration_seconds=0.2,
            resolve_definitions=True,
        )
        assert timeline_export["count"] == 1
        assert json.loads(timeline_json.read_text())["timeline"][0]["process_index"] == 0
        assert json.loads(timeline_json.read_text())["timeline"][0]["pid"] == 1234
        timeline_csv = Path(directory) / "timeline.csv"
        timeline_csv_export = capture_export_timeline(
            str(path), str(timeline_csv), output_format="csv", resolve_definitions=True
        )
        assert timeline_csv_export["count"] == 1
        assert "CreateFileW" in timeline_csv.read_text()
        assert ",1234," in timeline_csv.read_text()
        resolved_records = capture_call_records(str(path), resolve_definitions=True)
        assert resolved_records["definitions_available"]
        assert resolved_records["records"][0]["definition"]["name"] == "CreateFileW"
        assert resolved_records["records"][0]["definition"]["module"] == "kernel32.dll"
        assert resolved_records["records"][0]["definition"]["ordinal"] == 123
        assert capture_read_definition(str(path), 16)["definition"]["name"] == "CreateFileW"
        decoded_call = capture_decode_call(str(path), 0, 0, resolve_definitions=True)
        assert decoded_call["process_pid"] == 1234
        assert decoded_call["record"]["data_refs"][0]["decoding"]["strings"][0]["text"] == "hello"
        assert decoded_call["record"]["definition"]["name"] == "CreateFileW"
        assert decoded_call["return_value"]["typed"]["value"] == 7
        decoded_calls = capture_decode_calls(str(path), resolve_definitions=True)
        assert decoded_calls["count"] == 1
        assert decoded_calls["records"][0]["return_value"]["typed"]["value"] == 7
        extracted_payload = Path(directory) / "payload.bin"
        payload_export = capture_extract_call_payload(str(path), 0, 0, 0, str(extracted_payload))
        assert payload_export["size"] == 5
        assert extracted_payload.read_bytes() == b"hello"
        protected_output = Path(directory) / "existing-payload.bin"
        protected_output.write_bytes(b"keep")
        try:
            capture_extract_call_payload(str(path), 0, 0, 0, str(protected_output))
        except FileExistsError:
            pass
        else:
            raise AssertionError("exclusive payload extraction unexpectedly overwrote output")
        assert protected_output.read_bytes() == b"keep"
        process_slice = capture_read_process_data(str(path), 0, 160, 5)
        assert process_slice["text"] == "hello"
        process_extract = Path(directory) / "process-slice.bin"
        process_extract_result = capture_extract_process_data(
            str(path), 0, str(process_extract), offset=160, length=5
        )
        assert process_extract_result["size"] == 5
        assert process_extract.read_bytes() == b"hello"
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
        assert csv_text.startswith("process_index,pid,record_index")
        assert "thread_id" in csv_text.splitlines()[0]
        assert "CreateFileW" in csv_text and "kernel32.dll" in csv_text and ",1234," in csv_text
        call_search = capture_search_calls(str(path), "ell")
        assert call_search["count"] == 1
        assert call_search["matches"][0]["pid"] == 1234
        assert call_search["matches"][0]["payload_matches"][0]["snippet"] == "hello"
        assert capture_search_calls(str(path), "ell", pid=1234)["count"] == 1
        regex_search = capture_search_calls(str(path), r"he..o", query_regex=True)
        assert regex_search["query_regex"] and regex_search["count"] == 1
        binary_call_search = capture_search_calls(
            str(path), pattern_hex="68 65 6c 6c 6f"
        )
        assert binary_call_search["count"] == 1
        assert binary_call_search["matches"][0]["byte_matches"][0]["absolute_offset"] == 160
        record_call_search = capture_search_calls(
            str(path), pattern_hex="34 12 00 00", include_record_bytes=True
        )
        assert record_call_search["count"] == 1
        assert record_call_search["record_bytes_searched"]
        assert record_call_search["matches"][0]["byte_matches"][0]["scope"] == "record"
        api_search = capture_search_calls(str(path), "CreateFileW", resolve_definitions=True)
        assert api_search["count"] == 1
        assert api_search["matches"][0]["api_matches"][0]["module"] == "kernel32.dll"
        filtered_search = capture_search_calls(
            str(path),
            "ell",
            thread_id=0x1234,
            error_code=5,
            api_name="CreateFile",
            min_duration_seconds=0.1,
        )
        assert filtered_search["count"] == 1
        assert filtered_search["filters"]["api_name"] == "CreateFile"
        limited_api_search = capture_search_calls(
            str(path), "CreateFileW", limit=1, resolve_definitions=True
        )
        assert limited_api_search["definitions_resolved"]
        filter_only_search = capture_search_calls(str(path), api_name="CreateFileW")
        assert filter_only_search["count"] == 1 and filter_only_search["filter_only"]
        filter_only_path = Path(directory) / "search-filter.json"
        filter_only_export = capture_export_search_calls(
            str(path), str(filter_only_path), api_name="CreateFileW"
        )
        assert filter_only_export["count"] == 1
        assert json.loads(filter_only_path.read_text())["filter_only"]
        search_json_path = Path(directory) / "search.json"
        search_export = capture_export_search_calls(
            str(path), str(search_json_path), query="ell"
        )
        assert search_export["count"] == 1
        assert json.loads(search_json_path.read_text())["matches"][0]["pid"] == 1234
        search_csv_path = Path(directory) / "search.csv"
        search_csv_export = capture_export_search_calls(
            str(path),
            str(search_csv_path),
            query=r"he..o",
            query_regex=True,
            output_format="csv",
        )
        assert search_csv_export["format"] == "csv"
        assert "payload_matches" in search_csv_path.read_text().splitlines()[0]
        assert "hello" in search_csv_path.read_text()
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
        definition_search = capture_search_definitions(
            str(argument_path), "dwValue", include_details=True
        )
        assert definition_search["count"] == 1
        assert any(
            match["path"].endswith(".name")
            for match in definition_search["matches"][0]["matches"]
        )
        definitions_json = Path(directory) / "definitions.json"
        definition_export = capture_export_definitions(
            str(argument_path), str(definitions_json), include_details=True
        )
        assert definition_export["count"] == 1
        assert json.loads(definitions_json.read_text())["definitions"][0]["details"]["name"] == "CreateFileW"
        definitions_csv = Path(directory) / "definitions.csv"
        csv_definition_export = capture_export_definitions(
            str(path), str(definitions_csv), output_format="csv", include_details=False
        )
        assert csv_definition_export["count"] == 1
        assert "CreateFileW" in definitions_csv.read_text()
        call_window = capture_calls_around(str(path), 0, 0, before=2, after=2)
        assert call_window["process_pid"] == 1234
        assert call_window["window_start"] == 0
        assert call_window["records"][0]["is_target"]
        resolved_window = capture_calls_around(str(path), 0, 0, resolve_definitions=True)
        assert resolved_window["records"][0]["definition"]["name"] == "CreateFileW"
        binary_payload = _read_payload(b"\x01\x00\xff\x00")
        assert binary_payload["encoding"] == "base64"
        assert binary_payload["size"] == 4
        assert binary_payload["hex_preview"] == "01 00 ff 00"
        bounded_payload = _read_payload(b"abcdef", max_bytes=3)
        assert bounded_payload["size"] == 6
        assert bounded_payload["returned_bytes"] == 3
        assert bounded_payload["text"] == "abc"
        assert bounded_payload["truncated"]
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
        entry_found = capture_find_bytes(
            str(path), "43 72 65 61 74 65", entry_name="calls.bin"
        )
        assert entry_found["offsets"] == [0]
        processes = capture_list_processes(str(path), 10)
        assert processes["processes"][0]["executables"] == ["C:\\sample.exe"]
        assert processes["processes"][0]["metadata"]["pid"] == 1234
        assert processes["processes"][0]["metadata"]["crc32_valid"]
        assert processes["processes"][0]["metadata"]["module_records"] == []
        assert processes["processes"][0]["call_count"] == 1
        modules = capture_list_modules(str(path))
        assert modules["count"] == 1
        assert modules["modules"][0]["name"] == "sample.exe"
        assert modules["modules"][0]["pids"] == [1234]
        assert capture_list_modules(str(path), pid=1234)["count"] == 1
        threads = capture_list_threads(str(path))
        assert threads["count"] == 1
        assert threads["threads"][0]["thread_id"] == 0x1234
        assert threads["threads"][0]["error_count"] == 1
        call_stats = capture_call_stats(str(path), process_index=0)
        assert call_stats["processes"][0]["record_sizes"]["160"] == 1
        assert call_stats["totals"]["referenced_data_bytes"] == 9
        call_context_stats = call_stats["processes"][0]["context"]
        assert call_context_stats["thread_count"] == 1
        assert call_context_stats["duration_seconds"]["average"] == 0.125
        assert call_context_stats["first_timestamp_utc"] == "2020-01-01T00:00:00+00:00"
        waited_capture = capture_wait_for_calls(
            str(path), minimum_calls=1, timeout_seconds=1, poll_interval_seconds=0.01
        )
        assert waited_capture["ready"] and waited_capture["calls"] == 1
        new_wait = capture_wait_for_new_calls(
            str(path), minimum_new_calls=0, timeout_seconds=1, poll_interval_seconds=0.01
        )
        assert new_wait["ready"] and new_wait["new_calls"] == 0
        api_list = capture_list_apis(str(path))
        assert api_list["count"] == 1
        assert api_list["apis"][0]["name"] == "CreateFileW"
        assert api_list["apis"][0]["pids"] == [1234]
        assert capture_list_apis(str(path), pid=1234)["count"] == 1
        assert api_list["apis"][0]["count"] == 1
        assert api_list["apis"][0]["context"]["error_count"] == 1
        assert api_list["apis"][0]["context"]["duration_seconds"]["average"] == 0.125
        api_json_path = Path(directory) / "apis.json"
        api_export = capture_export_api_summary(str(path), str(api_json_path))
        assert api_export["count"] == 1
        assert json.loads(api_json_path.read_text())["apis"][0]["name"] == "CreateFileW"
        api_csv_path = Path(directory) / "apis.csv"
        api_csv_export = capture_export_api_summary(
            str(path), str(api_csv_path), output_format="csv"
        )
        assert api_csv_export["format"] == "csv"
        assert "process_indices" in api_csv_path.read_text().splitlines()[0]
        assert "CreateFileW" in api_csv_path.read_text()
        error_summary = capture_error_summary(str(path))
        assert error_summary["error_count"] == 1
        assert error_summary["errors"][0]["hex"] == "0x00000005"
        assert error_summary["errors"][0]["apis"][0]["name"] == "CreateFileW"
        assert capture_error_summary(str(path), pid=1234)["count"] == 1
        error_json_path = Path(directory) / "errors.json"
        error_export = capture_export_error_summary(str(path), str(error_json_path))
        assert error_export["error_count"] == 1
        assert json.loads(error_json_path.read_text())["errors"][0]["error_code"] == 5
        error_csv_path = Path(directory) / "errors.csv"
        error_csv_export = capture_export_error_summary(
            str(path), str(error_csv_path), output_format="csv"
        )
        assert error_csv_export["format"] == "csv"
        assert "error_code" in error_csv_path.read_text().splitlines()[0]
        assert "0x00000005" in error_csv_path.read_text()
        definitions_list = capture_list_definitions(str(path), include_details=True)
        assert definitions_list["count"] == 1
        assert definitions_list["definitions"][0]["name"] == "CreateFileW"
        assert definitions_list["definitions"][0]["pids"] == [1234]
        assert definitions_list["definitions"][0]["details"]["module"] == "kernel32.dll"
        assert capture_list_definitions(str(path), pid=1234)["count"] == 1
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
        same_entry = capture_compare_entry(str(path), str(path), "calls.bin")
        assert same_entry["same"]
        entry_diff = capture_compare_entry(str(path), str(second_path), "metadata.txt")
        assert not entry_diff["same"]
        assert entry_diff["first_difference"] is not None
        assert entry_diff["context"]["first_hex"] != entry_diff["context"]["second_hex"]
        capped_entry_diff = capture_compare_entry(
            str(path), str(second_path), "metadata.txt", max_bytes=2
        )
        assert capped_entry_diff["compared_bytes"] == 2
        assert capped_entry_diff["truncated"] and not capped_entry_diff["same"]
        call_comparison = capture_compare_calls(
            str(path), str(second_path), resolve_definitions=True
        )
        assert call_comparison["process_pids"] == {"first": 1234, "second": None}
        assert call_comparison["counts"]["removed"] == 1
        assert call_comparison["counts"]["changed"] == 0
        context_comparison = capture_compare_calls(
            str(path), str(path), compare_context=True, resolve_definitions=True
        )
        assert context_comparison["compare_context"]
        assert context_comparison["same"]
        sequence_comparison = capture_compare_calls(
            str(path), str(second_path), match_mode="sequence", resolve_definitions=True
        )
        assert sequence_comparison["match_mode"] == "sequence"
        assert sequence_comparison["counts"]["removed"] == 1
        api_comparison = capture_compare_apis(str(path), str(path))
        assert api_comparison["same"]
        assert api_comparison["counts"] == {"added": 0, "removed": 0, "changed": 0}
        all_call_comparison = capture_compare_all_calls(str(path), str(path))
        assert all_call_comparison["process_indices"] == [0]
        assert all_call_comparison["process_pids"]["0"] == {"first": 1234, "second": 1234}
        assert all_call_comparison["same"]
        all_json_path = Path(directory) / "all-calls.json"
        all_json_export = capture_export_all_calls(str(path), str(all_json_path))
        assert all_json_export["count"] == 1
        assert json.loads(all_json_path.read_text())["processes"][0]["process_index"] == 0
        assert json.loads(all_json_path.read_text())["processes"][0]["process_pid"] == 1234
        all_csv_path = Path(directory) / "all-calls.csv"
        all_csv_export = capture_export_all_calls(
            str(path), str(all_csv_path), output_format="csv", resolve_definitions=True
        )
        assert all_csv_export["count"] == 1
        assert "CreateFileW" in all_csv_path.read_text() and ",1234," in all_csv_path.read_text()
        multi_path = Path(directory) / "multi.apmx64"
        multi_payload = io.BytesIO()
        with zipfile.ZipFile(multi_payload, "w", zipfile.ZIP_STORED) as archive:
            for process_index in range(2):
                archive.writestr(
                    f"process/{process_index}/calls", struct.pack("<Q", 0)
                )
                archive.writestr(
                    f"process/{process_index}/data",
                    bytes(record) + b"hello" + struct.pack("<I", 7),
                )
        multi_path.write_bytes(
            b"\r\nAPI Monitor 64-bit Capture\r\nRBAPM" + multi_payload.getvalue()
        )
        multi_export = capture_export_all_calls(
            str(multi_path), str(Path(directory) / "multi.json"), include_data=False, limit=1
        )
        assert multi_export["process_indices"] == [0, 1]
        assert multi_export["count"] == 2
        decoded_all = capture_decode_all_calls(str(multi_path), limit=2)
        assert decoded_all["process_indices"] == [0, 1]
        assert decoded_all["count"] == 2
        assert decoded_all["total_count"] == 2
        assert len(decoded_all["processes"]) == 2
        decoded_json = Path(directory) / "decoded.json"
        decoded_export = capture_export_decoded_calls(
            str(path), str(decoded_json), resolve_definitions=True
        )
        assert decoded_export["count"] == 1
        assert json.loads(decoded_json.read_text())["processes"][0]["records"][0]["return_value"]["typed"]["value"] == 7
        decoded_csv = Path(directory) / "decoded.csv"
        decoded_csv_export = capture_export_decoded_calls(
            str(path), str(decoded_csv), output_format="csv", resolve_definitions=True
        )
        assert decoded_csv_export["count"] == 1
        assert "CreateFileW" in decoded_csv.read_text() and ",1234," in decoded_csv.read_text()

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
        assert x86_records["process_pid"] == 4321
        assert x86_records["records"][0]["definition"]["name"] == "CreateFileA"
        assert x86_records["records"][0]["data_refs"][0]["payload"]["size"] == len(x86_encoded_argument)
        x86_context = x86_records["records"][0]["context"]
        assert x86_context["thread_id"] == 0x2345
        assert x86_context["thread_number"] == 8
        assert x86_context["module_base"] == "0x00401000"
        assert x86_context["error_code"] == 6
        assert x86_context["duration_seconds"] == 0.25
        assert capture_read_definition(str(x86_path), 16)["architecture"] == "x86"
        x86_types = capture_list_types(
            str(x86_path), include_details=True, pid=4321
        )
        assert x86_types["count"] == 2
        assert {item["offset"] for item in x86_types["types"]} == {
            x86_struct_type_offset,
            160,
        }
        assert capture_list_types(str(x86_path), kind=11)["count"] == 1
        assert capture_list_types(str(x86_path), query="dwValue")["count"] == 1
        assert capture_list_apis(str(x86_path))["apis"][0]["module"] == "kernel32.dll"
        assert capture_list_apis(str(x86_path))["apis"][0]["pids"] == [4321]
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
        x86_modules = capture_list_modules(str(x86_path), query="kernel32")
        assert x86_modules["count"] == 1
        assert x86_modules["modules"][0]["pids"] == [4321]
        assert capture_list_modules(str(x86_path), query="kernel32", pid=4321)["count"] == 1
        assert x86_modules["modules"][0]["occurrences"][0]["base"] is None
        assert x86_modules["modules"][0]["occurrences"][0]["pid"] == 4321
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
        included_definition = definition_root / "included.xml"
        included_definition.write_text(
            '<ApiMonitor><Module Name="included.dll"><Api Name="IncludedThing">'
            '<Return Type="BOOL" /></Api></Module>'
            '<Variable Name="IncludedStruct" Type="Struct">'
            '<Field Type="DWORD" Name="value" />'
            '<Enum><Set Name="One" Value="1" /></Enum></Variable></ApiMonitor>',
            encoding="utf-8",
        )
        definition = definition_root / "sample.xml"
        definition.write_text(
            '<ApiMonitor><Include Filename="included.xml" />'
            '<Module Name="sample.dll" CallingConvention="STDCALL">'
            '<Api Name="OpenThing"><Param Type="HANDLE" Name="hThing" />'
            '<Return Type="BOOL" /></Api></Module></ApiMonitor>',
            encoding="utf-8",
        )
        environment = api_monitor_environment(install_root=str(app_root))
        assert environment["installed"]
        assert environment["api_directory"]["xml_count"] == 2
        exact_limit = api_monitor_list_api_files(install_root=str(app_root), limit=2)
        assert exact_limit["count"] == 2 and not exact_limit["truncated"]
        lazy_limit = api_monitor_list_api_files(
            install_root=str(app_root), limit=1, include_counts=False
        )
        assert lazy_limit["count"] == 1 and lazy_limit["truncated"]
        listed_api_files = api_monitor_list_api_files(
            query="sample.xml", install_root=str(app_root)
        )
        assert listed_api_files["count"] == 1
        assert listed_api_files["files"][0]["api_count"] == 1
        assert api_monitor_list_api_files(
            query="OpenThing", install_root=str(app_root)
        )["count"] == 1
        searched_apis = api_monitor_search_apis("OpenThing", install_root=str(app_root))
        assert searched_apis["count"] == 1
        assert searched_apis["results"][0]["module"] == "sample.dll"
        detailed_apis = api_monitor_search_api_details(
            "OpenThing", install_root=str(app_root)
        )
        assert detailed_apis["count"] == 1
        assert detailed_apis["results"][0]["params"] == [
            {"Type": "HANDLE", "Name": "hThing"}
        ]
        assert detailed_apis["results"][0]["returns"] == [{"Type": "BOOL"}]
        cache_probe = definition_root / "cache_probe.xml"
        cache_probe.write_text(
            '<ApiMonitor><Module Name="probe.dll"><Api Name="SecondThing" /></Module></ApiMonitor>',
            encoding="utf-8",
        )
        assert api_monitor_search_apis("SecondThing", install_root=str(app_root))["count"] == 1
        parsed = api_monitor_parse_api_definition(str(definition), install_root=str(app_root))
        assert parsed["apis"][0]["module"] == "sample.dll"
        assert parsed["apis"][0]["params"] == [{"Type": "HANDLE", "Name": "hThing"}]
        parsed_includes = api_monitor_parse_api_definition(
            str(definition),
            resolve_includes=True,
            install_root=str(app_root),
            include_variables=True,
        )
        assert len(parsed_includes["documents"]) == 2
        assert {api["name"] for api in parsed_includes["apis"]} == {
            "OpenThing",
            "IncludedThing",
        }
        assert parsed_includes["variables"][0]["fields"] == [
            {"Type": "DWORD", "Name": "value"}
        ]
        assert parsed_includes["variables"][0]["enums"][0]["sets"] == [
            {"Name": "One", "Value": "1"}
        ]
        variable_search = api_monitor_search_variables(
            "IncludedStruct", install_root=str(app_root)
        )
        assert variable_search["count"] == 1
        assert variable_search["variables"][0]["name"] == "IncludedStruct"
        assert _named_gui_rows(["API", "Error"], [["OpenThing", "5"]])[0]["values"] == {
            "API": "OpenThing",
            "Error": "5",
        }
        assert _gui_pane_title(
            {
                "children": [
                    {
                        "handle": 10,
                        "class": "Afx:ControlBar:test",
                        "title": "Call Stack",
                        "rectangle": {"left": 0, "top": 0, "right": 100, "bottom": 100},
                    },
                    {
                        "handle": 11,
                        "class": "SysListView32",
                        "title": "",
                        "rectangle": {"left": 1, "top": 1, "right": 99, "bottom": 99},
                    },
                ]
            },
            11,
        ) == "Call Stack"
        raw_module = b"raw-module"
        raw_process_info = struct.pack("<IIIQ", 1, 0, 77, 0x140000000)
        for value in ("C:\\sample.exe", "sample.exe", "Sample"):
            raw_process_info += struct.pack("<I", len(value)) + value.encode("utf-16-le")
        raw_process_info += struct.pack("<IQQI", 0, 0, 0, 1)
        raw_process_info += struct.pack("<IIIQI", 1, 2, 3, 0x140001000, len(raw_module))
        raw_process_info += raw_module
        raw_process_info += struct.pack("<QQ", 0x1234, 0x5678)
        raw_module_path = "C:\\sample.dll"
        raw_process_info += struct.pack("<I", len(raw_module_path))
        raw_process_info += raw_module_path.encode("utf-16-le")
        raw_process_info += struct.pack("<Q", 0xABCDEF)
        raw_process_info += struct.pack("<I", 0)
        raw_process_info += struct.pack("<I", zlib.crc32(raw_process_info) & 0xFFFFFFFF)
        raw_process = _parse_capture_process_info(raw_process_info, 8)
        assert raw_process["module_records"][0]["raw_payload"]["text"] == "raw-module"
        original_summary = gui_tools.api_monitor_summary
        original_traffic = gui_tools.api_monitor_traffic
        summary_calls = iter((3, 4))
        gui_tools.api_monitor_summary = lambda *_args, **_kwargs: {
            "summaries": [{"calls": next(summary_calls)}]
        }
        gui_tools.api_monitor_traffic = lambda *_args, **_kwargs: {"panes": []}
        try:
            waited_new = api_monitor_wait_for_new_traffic(
                minimum_new_calls=2, timeout_seconds=1, baseline_calls=2
            )
        finally:
            gui_tools.api_monitor_summary = original_summary
            gui_tools.api_monitor_traffic = original_traffic
        assert waited_new["ready"]
        assert waited_new["current_calls"] == 4
        assert waited_new["new_calls"] == 2
        original_events = capture_tools.capture_monitoring_events
        event_snapshots = iter(
            (
                {"count": 1, "events": [{"line": "old"}], "truncated": False},
                {
                    "count": 3,
                    "events": [
                        {"line": "old"},
                        {"line": "new-1"},
                        {"line": "new-2"},
                    ],
                    "truncated": False,
                },
            )
        )
        capture_tools.capture_monitoring_events = lambda *_args, **_kwargs: next(event_snapshots)
        try:
            waited_events = capture_wait_for_new_events(
                str(path),
                minimum_new_events=2,
                process_query_regex=True,
                timeout_seconds=1,
                poll_interval_seconds=0.01,
            )
        finally:
            capture_tools.capture_monitoring_events = original_events
        assert waited_events["ready"]
        assert waited_events["new_events_count"] == 2
        assert waited_events["process_query_regex"]
        assert [event["line"] for event in waited_events["events"]] == ["new-1", "new-2"]
        original_traffic = gui_tools.api_monitor_traffic
        gui_tools.api_monitor_traffic = lambda *_args, **_kwargs: {
            "supported": True,
            "panes": [
                {
                    "list_handle": 7,
                    "pane_title": "API Calls",
                    "headers": ["API", "Module"],
                    "rows": [["CreateFileW", "kernel32.dll"]],
                    "records": [{"API": "CreateFileW", "Arguments": {"path": "x"}}],
                    "row_details": [{"selected": True}],
                    "truncated": False,
                }
            ],
        }
        try:
            live_json = Path(directory) / "live-traffic.json"
            live_csv = Path(directory) / "live-traffic.csv"
            live_json_export = api_monitor_export_traffic(str(live_json))
            live_csv_export = api_monitor_export_traffic(
                str(live_csv), output_format="csv"
            )
            live_search = api_monitor_search_traffic(r"CreateFile(W|A)", query_regex=True)
        finally:
            gui_tools.api_monitor_traffic = original_traffic
        assert live_json_export["rows"] == 1
        assert json.loads(live_json.read_text())["panes"][0]["records"][0]["API"] == "CreateFileW"
        assert live_csv_export["format"] == "csv"
        assert "pane_title,list_handle,row_index" in live_csv.read_text().splitlines()[0]
        assert "CreateFileW" in live_csv.read_text()
        assert live_search["count"] == 1
        assert live_search["panes"][0]["rows"] == [["CreateFileW", "kernel32.dll"]]
        original_tree = gui_tools.api_monitor_gui_tree
        original_check = gui_tools._set_tree_item_check
        checked_items = []
        gui_tools.api_monitor_gui_tree = lambda **_kwargs: {
            "tree": {"handle": 99},
            "items": [
                {"native_handle": 101, "text": "CreateFileW"},
                {"native_handle": 102, "text": "ReadFile"},
            ],
            "truncated": False,
        }
        gui_tools._set_tree_item_check = lambda tree, item, checked: checked_items.append(
            (tree, item, checked)
        )
        try:
            tree_query = api_monitor_gui_tree_check_query("create", True)
        finally:
            gui_tools.api_monitor_gui_tree = original_tree
            gui_tools._set_tree_item_check = original_check
        assert tree_query["updated_count"] == 1
        assert checked_items == [(99, 101, True)]
        original_details = gui_tools.api_monitor_traffic_details
        gui_tools.api_monitor_traffic_details = lambda **_kwargs: {
            "selected_call": {"row_index": 0},
            "details": [
                {
                    "pane_title": "Call Stack",
                    "rows": [["kernel32.dll", "CreateFileW"]],
                }
            ],
            "summaries": [],
        }
        try:
            stack = api_monitor_call_stack(row_index=0)
        finally:
            gui_tools.api_monitor_traffic_details = original_details
        assert stack["supported"] and stack["stacks"][0]["pane_title"] == "Call Stack"
        delta = _gui_traffic_delta(
            {"panes": [{"list_handle": 1, "headers": ["API"], "rows": [["old"]]}]},
            {
                "supported": True,
                "panes": [
                    {
                        "list_handle": 1,
                        "headers": ["API"],
                        "rows": [["old"], ["new"]],
                        "truncated": False,
                    }
                ],
            },
        )
        assert delta["complete"] and delta["panes"][0]["rows"] == [["new"]]
        if sys.platform == "win32":
            process_architecture = api_monitor_process_architecture(os.getpid())
            assert process_architecture["architecture"] in {"x86", "x64", "arm64"}
            process_details = api_monitor_process_details(os.getpid())
            assert process_details["path"]
            assert process_details["architecture"]["architecture"] in {"x86", "x64", "arm64"}
