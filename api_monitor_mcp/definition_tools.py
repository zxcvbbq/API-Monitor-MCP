"""Installed Rohitab XML API-definition search and parsing tools."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .capture_format import _file_time, _limit
from .gui_runtime import _app_root
from .runtime import API_NAME, MODULE_NAME, mcp


def _api_definition_signature(api_root: Path) -> tuple[tuple[str, int, int], ...]:
    signature: list[tuple[str, int, int]] = []
    for path in sorted(api_root.rglob("*.xml")):
        try:
            stat = path.stat()
        except OSError:
            continue
        signature.append((str(path), stat.st_size, stat.st_mtime_ns))
    return tuple(signature)


@lru_cache(maxsize=2)
def _cached_api_definition_index(
    api_root_name: str, signature: tuple[tuple[str, int, int], ...]
) -> tuple[dict[str, Any], ...]:
    api_root = Path(api_root_name)
    index: list[dict[str, Any]] = []
    for path_name, size, _modified_ns in signature:
        path = Path(path_name)
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            relative = str(path.relative_to(api_root))
            module_match = MODULE_NAME.search(text)
            module = module_match.group(1) if module_match else path.stem
        except (OSError, ValueError):
            continue
        api_names = tuple(match.group(1) for match in API_NAME.finditer(text))
        item: dict[str, Any] = {
            "definition": str(path),
            "relative_path": relative,
            "module": module,
            "size": size,
            "modified_utc": _file_time(path),
            "api_names": api_names,
        }
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError as exc:
            item.update({"valid": False, "error": str(exc), "api_count": 0, "variable_count": 0})
        else:
            item.update(
                {
                    "valid": True,
                    "api_count": sum(
                        1
                        for node in root.iter()
                        if isinstance(node.tag, str)
                        and node.tag.rsplit("}", 1)[-1].casefold() == "api"
                    ),
                    "variable_count": sum(
                        1
                        for node in root.iter()
                        if isinstance(node.tag, str)
                        and node.tag.rsplit("}", 1)[-1].casefold() == "variable"
                    ),
                }
            )
        index.append(item)
    return tuple(index)


def _api_definition_index(api_root: Path) -> tuple[dict[str, Any], ...]:
    return _cached_api_definition_index(str(api_root), _api_definition_signature(api_root))


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
    for item in _api_definition_index(api_root):
        module = str(item["module"])
        for name in item["api_names"]:
            if needle not in name.casefold() and needle not in module.casefold():
                continue
            key = (module, name)
            if key in seen:
                continue
            seen.add(key)
            results.append({"name": name, "module": module, "definition": item["definition"]})
            if len(results) >= limit:
                return {"query": query, "results": results, "count": len(results), "truncated": True}
    return {"query": query, "results": results, "count": len(results), "truncated": False}


@mcp.tool()
def api_monitor_list_api_files(
    query: str = "",
    limit: int = 500,
    install_root: str | None = None,
    include_counts: bool = True,
) -> dict[str, Any]:
    """List installed Rohitab XML API definitions and their bounded contents."""
    if len(query) > 4096:
        raise ValueError("query must not exceed 4096 characters")
    limit = _limit(limit, "limit", 5000)
    api_root = _app_root(install_root) / "API"
    if not api_root.is_dir():
        raise FileNotFoundError(f"API definition directory not found: {api_root}")

    wanted = query.casefold()
    results: list[dict[str, Any]] = []
    for indexed in _api_definition_index(api_root):
        if wanted and wanted not in indexed["relative_path"].casefold() and wanted not in indexed["module"].casefold():
            continue
        item = {
            key: value
            for key, value in indexed.items()
            if key != "api_names" and (include_counts or key not in {"valid", "error", "api_count", "variable_count"})
        }
        results.append(item)
        if len(results) >= limit:
            return {
                "query": query,
                "api_directory": str(api_root),
                "files": results,
                "count": len(results),
                "truncated": True,
                "counts_included": include_counts,
            }
    return {
        "query": query,
        "api_directory": str(api_root),
        "files": results,
        "count": len(results),
        "truncated": False,
        "counts_included": include_counts,
    }


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


def _api_definition_documents(
    path: Path, api_root: Path, resolve_includes: bool
) -> list[tuple[Path, Any]]:
    documents: list[tuple[Path, Any]] = []
    pending = [path]
    seen: set[Path] = set()
    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            root = ElementTree.parse(current).getroot()
        except ElementTree.ParseError as exc:
            raise ValueError(f"Invalid API definition XML: {current}") from exc
        documents.append((current, root))
        if not resolve_includes:
            break
        for include in root.iter("Include"):
            filename = (include.get("Filename") or "").strip()
            if not filename:
                continue
            included = (api_root / filename.replace("\\", "/")).resolve()
            try:
                included.relative_to(api_root)
            except ValueError as exc:
                raise ValueError(f"Included API definition escapes API directory: {filename}") from exc
            if included.suffix.lower() != ".xml" or not included.is_file():
                raise FileNotFoundError(f"Included API definition not found: {included}")
            pending.append(included)
    return documents


def _api_variable_info(variable: Any, document: Path) -> dict[str, Any]:
    return {
        "name": variable.get("Name", ""),
        "attributes": dict(variable.attrib),
        "fields": [dict(field.attrib) for field in variable.findall("Field")],
        "displays": [dict(display.attrib) for display in variable.findall("Display")],
        "enums": [
            {
                "attributes": dict(enum.attrib),
                "sets": [dict(item.attrib) for item in enum.findall("Set")],
            }
            for enum in variable.findall("Enum")
        ],
        "definition": str(document),
    }


@mcp.tool()
def api_monitor_search_variables(
    query: str,
    limit: int = 100,
    install_root: str | None = None,
) -> dict[str, Any]:
    """Search Rohitab XML variables, structures, unions, aliases, and enums."""
    if not query.strip():
        raise ValueError("query must not be empty")
    limit = _limit(limit, "limit", 5000)
    api_root = _app_root(install_root) / "API"
    if not api_root.is_dir():
        raise FileNotFoundError(f"API definition directory not found: {api_root}")
    needle = query.casefold()
    results: list[dict[str, Any]] = []
    for xml_path in sorted(api_root.rglob("*.xml")):
        try:
            root = ElementTree.parse(xml_path).getroot()
        except ElementTree.ParseError:
            continue
        for variable in root.iter("Variable"):
            item = _api_variable_info(variable, xml_path)
            searchable = json.dumps(item, ensure_ascii=False).casefold()
            if needle not in searchable:
                continue
            results.append(item)
            if len(results) >= limit:
                return {
                    "query": query,
                    "variables": results,
                    "count": len(results),
                    "truncated": True,
                }
    return {
        "query": query,
        "variables": results,
        "count": len(results),
        "truncated": False,
    }


@mcp.tool()
def api_monitor_parse_api_definition(
    definition_path: str,
    api_name: str = "",
    limit: int = 200,
    resolve_includes: bool = False,
    install_root: str | None = None,
    include_variables: bool = False,
) -> dict[str, Any]:
    """Return structured Rohitab API signatures and optional XML variables."""
    limit = _limit(limit, "limit", 5000)
    path = _api_definition_path(definition_path, install_root)
    api_root = (_app_root(install_root) / "API").resolve()
    documents = _api_definition_documents(path, api_root, resolve_includes)
    needle = api_name.casefold()
    results: list[dict[str, Any]] = []
    variables: list[dict[str, Any]] = []
    for document, root in documents:
        parents = {child: parent for parent in root.iter() for child in parent}
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
                    "definition": str(document),
                }
            )
        if include_variables:
            for variable in root.iter("Variable"):
                variables.append(_api_variable_info(variable, document))
    returned = results[:limit]
    returned_variables = variables[:limit]
    return {
        "definition": str(path),
        "api_name": api_name,
        "includes_resolved": resolve_includes,
        "variables_included": include_variables,
        "documents": [str(document) for document, _ in documents],
        "apis": returned,
        "count": len(returned),
        "truncated": len(results) > limit,
        "variables": returned_variables,
        "variable_count": len(returned_variables),
        "variables_truncated": len(variables) > limit,
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
