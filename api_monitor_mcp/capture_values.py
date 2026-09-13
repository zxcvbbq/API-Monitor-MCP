"""Payload, argument, value, and XML decoding helpers."""

from __future__ import annotations

import base64
import hashlib
import struct
import uuid
from typing import Any
from xml.etree import ElementTree


def _read_payload(data: bytes, max_bytes: int | None = None) -> dict[str, Any]:
    if max_bytes is not None and max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    view = data if max_bytes is None else data[:max_bytes]
    truncated = len(view) < len(data)
    metadata = {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_preview": data[:256].hex(" "),
        "hex_truncated": len(data) > 256,
    }
    if truncated:
        metadata.update({"returned_bytes": len(view), "truncated": True})
    try:
        text = view.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        try:
            text = view.decode("utf-16-le")
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
        "base64": base64.b64encode(view).decode("ascii"),
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
