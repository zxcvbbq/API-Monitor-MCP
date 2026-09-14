"""Background GUI and live-capture MCP tools."""

from __future__ import annotations

import base64
import csv
import ctypes
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .capture_format import (
    _capture_output_path,
    _capture_path,
    _file_time,
    _limit,
)
from .capture_tools import capture_info, capture_validate
from .gui_runtime import (
    _api_monitor_main_window,
    _api_monitor_window_by_handle,
    _app_executable,
    _app_root,
    _background_startupinfo,
    _capture_window_png,
    _detect_executable_architecture,
    _detect_process_architecture,
    _detect_process_path,
    _find_api_monitor_windows,
    _find_native_menu_item,
    _find_ui_control,
    _gui_pane_title,
    _gui_traffic_delta,
    _named_gui_rows,
    _post_button_click,
    _post_key,
    _post_mouse_click,
    _post_mouse_click_at,
    _post_scroll,
    _post_window_command,
    _read_native_menu,
    _read_native_toolbar,
    _run_file_dialog,
    _set_combo_selection,
    _set_control_text,
    _set_tree_item_check,
    _tasklist_rows,
    _tree_item_action,
    _tree_items,
    _uia_rect,
    _uia_text,
    _wait_for_api_monitor_window,
    _window_text,
)
from .runtime import (
    CAPTURE_SUFFIXES,
    COMMAND_MONITOR_NEW_PROCESS,
    COMMAND_OPEN_CAPTURE,
    COMMAND_REMOVE_PROCESS,
    COMMAND_SAVE_CAPTURE_AS,
    COMMAND_START_MONITORING,
    COMMAND_STOP_MONITORING,
    COMMAND_TERMINATE_PROCESS,
    SUMMARY_TEXT,
    mcp,
)


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
def api_monitor_environment(install_root: str | None = None) -> dict[str, Any]:
    """Report the installed Rohitab API Monitor paths without starting the GUI."""
    supported = sys.platform == "win32"
    try:
        root = _app_root(install_root)
    except FileNotFoundError as exc:
        return {
            "supported": supported,
            "installed": False,
            "root": None,
            "error": str(exc),
            "executables": {},
            "api_directory": {"path": None, "exists": False, "xml_count": 0},
        }

    executables: dict[str, dict[str, Any]] = {}
    for architecture in ("x86", "x64"):
        path = root / f"apimonitor-{architecture}.exe"
        item: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
        if item["exists"]:
            try:
                item["size"] = path.stat().st_size
            except OSError as exc:
                item["error"] = str(exc)
        executables[architecture] = item

    api_directory = root / "API"
    try:
        xml_count = sum(1 for path in api_directory.rglob("*.xml")) if api_directory.is_dir() else 0
    except OSError:
        xml_count = 0
    return {
        "supported": supported,
        "installed": True,
        "root": str(root),
        "executables": executables,
        "api_directory": {
            "path": str(api_directory),
            "exists": api_directory.is_dir(),
            "xml_count": xml_count,
        },
    }


@mcp.tool()
def api_monitor_overview(
    window_title: str = "",
    window_handle: int | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Return one read-only snapshot of a background Rohitab monitoring session."""
    if sys.platform != "win32":
        return {
            "supported": False,
            "status": {"supported": False, "processes": []},
            "windows": [],
            "summaries": [],
            "traffic": {"supported": False, "panes": []},
            "lists": {"supported": False, "windows": []},
        }
    limit = _limit(limit, "limit", 2000)
    ui = api_monitor_ui_tree()
    windows = []
    for window in ui["windows"]:
        if window_title and window["title"] != window_title:
            continue
        if window_handle is not None and window["handle"] != window_handle:
            continue
        if not window_title and window_handle is None and "api monitor v2" not in window["title"].casefold():
            continue
        windows.append(window)
    summaries = api_monitor_summary(window_title, window_handle)
    traffic = api_monitor_traffic(window_title, limit, window_handle)
    lists = api_monitor_gui_lists(window_title, limit, window_handle)
    return {
        "supported": True,
        "status": api_monitor_status(),
        "windows": windows,
        "summaries": summaries.get("summaries", []),
        "traffic": traffic,
        "lists": lists,
    }


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
def api_monitor_process_architecture(pid: int) -> dict[str, Any]:
    """Report a running Windows process architecture for API Monitor attach selection."""
    if sys.platform != "win32":
        return {"supported": False, "pid": pid, "architecture": None}
    if pid < 1:
        raise ValueError("pid must be positive")
    result = _detect_process_architecture(pid)
    return {"supported": True, **result}


@mcp.tool()
def api_monitor_process_details(pid: int) -> dict[str, Any]:
    """Return attach-ready details for one running Windows process."""
    if sys.platform != "win32":
        return {"supported": False, "pid": pid, "path": None, "architecture": None}
    if pid < 1:
        raise ValueError("pid must be positive")
    rows, error = _tasklist_rows()
    process_row = None
    if not error:
        for row in rows:
            if len(row) >= 2 and row[1].isdigit() and int(row[1]) == pid:
                process_row = {
                    "image": row[0],
                    "pid": pid,
                    "session": row[2] if len(row) > 2 else None,
                    "memory": row[4] if len(row) > 4 else None,
                }
                break
    result: dict[str, Any] = {
        "supported": True,
        "pid": pid,
        "tasklist": process_row,
        "tasklist_error": error,
    }
    try:
        result["path"] = _detect_process_path(pid)
    except OSError as exc:
        result["path"] = None
        result["path_error"] = str(exc)
    try:
        result["architecture"] = _detect_process_architecture(pid)
    except OSError as exc:
        result["architecture"] = None
        result["architecture_error"] = str(exc)
    return result


@mcp.tool()
def api_monitor_executable_architecture(process_path: str) -> dict[str, Any]:
    """Report a Windows executable architecture for API Monitor launch selection."""
    if sys.platform != "win32":
        return {"supported": False, "file": process_path, "architecture": None}
    path = Path(process_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Target process not found: {path}")
    return {"supported": True, **_detect_executable_architecture(path.resolve())}


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
def api_monitor_gui_tree_check_query(
    query: str,
    checked: bool,
    match_mode: str = "contains",
    tree_handle: int | None = None,
    window_title: str = "",
    limit: int = 500,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Check matching API/filter tree items without foregrounding the window."""
    if not query.strip():
        raise ValueError("query must not be empty")
    if match_mode not in {"contains", "exact", "regex"}:
        raise ValueError("match_mode must be contains, exact, or regex")
    limit = _limit(limit, "limit", 20_000)
    if not 0 <= max_depth <= 128:
        raise ValueError("max_depth must be between 0 and 128")
    if sys.platform != "win32":
        return {
            "supported": False,
            "query": query,
            "match_mode": match_mode,
            "checked": checked,
            "matches": [],
            "count": 0,
            "updated_count": 0,
            "truncated": False,
        }
    expression = re.compile(query, re.IGNORECASE) if match_mode == "regex" else None
    tree_result = api_monitor_gui_tree(
        tree_handle=tree_handle,
        window_title=window_title,
        limit=20_000,
        max_depth=max_depth,
    )
    wanted = query.casefold()

    def matches(text: str) -> bool:
        if match_mode == "exact":
            return text.casefold() == wanted
        if expression is not None:
            return expression.search(text) is not None
        return wanted in text.casefold()

    selected = [item for item in tree_result.get("items", []) if matches(item.get("text", ""))]
    changed = selected[:limit]
    tree = tree_result["tree"]
    for item in changed:
        _set_tree_item_check(tree["handle"], item["native_handle"], checked)
    return {
        "updated": True,
        "method": "background-win32",
        "query": query,
        "match_mode": match_mode,
        "checked": checked,
        "tree": tree,
        "matches": changed,
        "count": len(selected),
        "updated_count": len(changed),
        "truncated": tree_result.get("truncated", False) or len(selected) > limit,
    }


@mcp.tool()
def api_monitor_gui_tree_action(
    action: str,
    item_handle: int,
    tree_handle: int | None = None,
    window_title: str = "",
) -> dict[str, Any]:
    """Expand, select, or scroll a Rohitab API/filter tree item in the background."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab tree controls require Windows")
    if action not in {"expand", "collapse", "toggle", "select", "ensure_visible"}:
        raise ValueError("action must be expand, collapse, toggle, select, or ensure_visible")
    if item_handle < 1:
        raise ValueError("item_handle must be positive")
    windows = _find_api_monitor_windows()
    if tree_handle is not None:
        candidates = [
            (window, child)
            for window in windows
            for child in window.get("children", [])
            if child.get("handle") == tree_handle
            and child.get("class") == "SysTreeView32"
            and (not window_title or window.get("title") == window_title)
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
        raise ValueError("tree_handle or window_title must identify one API Monitor tree")
    window, tree = candidates[0]
    _tree_item_action(tree["handle"], item_handle, action)
    return {
        "updated": True,
        "method": "background-win32",
        "action": action,
        "window": {"handle": window["handle"], "title": window["title"]},
        "tree": tree,
        "item_handle": item_handle,
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
def api_monitor_gui_menu(
    action: str = "read",
    window_title: str = "",
    window_handle: int | None = None,
    item_path: list[str] | None = None,
    command_id: int | None = None,
    max_items: int = 1000,
    max_depth: int = 16,
) -> dict[str, Any]:
    """Read or invoke a Rohitab API Monitor menu without activating its window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab menus require Windows")
    if action not in {"read", "click"}:
        raise ValueError("action must be read or click")
    if window_handle is not None:
        candidates = [window for window in _find_api_monitor_windows() if window["handle"] == window_handle]
    elif window_title:
        candidates = [window for window in _find_api_monitor_windows() if window["title"] == window_title]
    else:
        candidates = [
            window
            for window in _find_api_monitor_windows()
            if window["title"].casefold().startswith("monitoring")
        ]
    if len(candidates) != 1:
        raise ValueError("menu requires one matching window_handle or window_title")
    max_items = _limit(max_items, "max_items", 20_000)
    if not 0 <= max_depth <= 128:
        raise ValueError("max_depth must be between 0 and 128")
    target = candidates[0]
    try:
        items, truncated = _read_native_menu(target["handle"], max_items, max_depth)
    except LookupError:
        if action == "read":
            return {
                "supported": False,
                "method": "background-win32",
                "window": target,
                "items": [],
                "truncated": False,
                "reason": "window has no native menu",
            }
        raise
    if action == "read":
        return {
            "supported": True,
            "method": "background-win32",
            "window": target,
            "items": items,
            "truncated": truncated,
        }
    if command_id is not None and not 0 <= command_id <= 0xFFFF:
        raise ValueError("command_id must be between 0 and 65535")
    if command_id is None:
        if not item_path or any(not part.strip() for part in item_path):
            raise ValueError("click requires item_path or command_id")
        selected = _find_native_menu_item(items, item_path)
        if selected is None:
            raise LookupError("Rohitab menu item was not found")
        command_id = selected.get("command_id")
        if command_id is None:
            raise ValueError("selected menu item is not an actionable command")
    else:
        selected = None
    if selected is not None and not selected["enabled"]:
        raise PermissionError("selected Rohitab menu item is disabled")
    _post_window_command(target["handle"], command_id)
    return {
        "clicked": True,
        "method": "background-win32",
        "window": target,
        "item_path": item_path,
        "command_id": command_id,
        "item": selected,
    }


@mcp.tool()
def api_monitor_gui_toolbars(
    action: str = "read",
    window_title: str = "",
    window_handle: int | None = None,
    toolbar_handle: int | None = None,
    toolbar_title: str = "",
    command_id: int | None = None,
    limit: int = 500,
    include_hidden: bool = False,
) -> dict[str, Any]:
    """Read or invoke Rohitab MFC toolbar commands without activating the window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab toolbars require Windows")
    if action not in {"read", "click"}:
        raise ValueError("action must be read or click")
    if command_id is not None and not 0 <= command_id <= 0xFFFF:
        raise ValueError("command_id must be between 0 and 65535")
    limit = _limit(limit, "limit", 20_000)
    if window_handle is not None:
        candidates = [window for window in _find_api_monitor_windows() if window["handle"] == window_handle]
    elif window_title:
        candidates = [window for window in _find_api_monitor_windows() if window["title"] == window_title]
    else:
        candidates = [
            window
            for window in _find_api_monitor_windows()
            if window["title"].casefold().startswith("monitoring")
        ]
    if len(candidates) != 1:
        raise ValueError("toolbar requires one matching window_handle or window_title")
    target = candidates[0]
    toolbars = [
        child
        for child in target.get("children", [])
        if child.get("class", "").startswith("Afx:ToolBar")
        and (include_hidden or child.get("visible"))
        and (toolbar_handle is None or child.get("handle") == toolbar_handle)
        and (not toolbar_title or child.get("title") == toolbar_title)
    ]
    if toolbar_handle is not None and len(toolbars) != 1:
        raise ValueError("toolbar_handle must identify one toolbar")
    if toolbar_title and not toolbars:
        raise LookupError("Rohitab toolbar was not found")
    if action == "click":
        if command_id is None:
            raise ValueError("click requires command_id")
        if len(toolbars) != 1:
            raise ValueError("click requires one toolbar_handle or toolbar_title")
        items, _ = _read_native_toolbar(toolbars[0]["handle"], 20_000)
        selected = next((item for item in items if item["command_id"] == command_id), None)
        if selected is None:
            raise LookupError(f"Toolbar command {command_id} was not found")
        if not selected["enabled"]:
            raise PermissionError(f"Toolbar command {command_id} is disabled")
        _post_window_command(target["handle"], command_id)
        return {
            "clicked": True,
            "method": "background-win32",
            "window": target,
            "toolbar": toolbars[0],
            "command_id": command_id,
            "item": selected,
        }

    returned: list[dict[str, Any]] = []
    remaining = limit
    truncated = False
    try:
        for toolbar in toolbars:
            items, item_truncated = _read_native_toolbar(toolbar["handle"], remaining)
            returned.append({**toolbar, "items": items, "truncated": item_truncated})
            remaining -= len(items)
            truncated |= item_truncated
            if remaining <= 0:
                truncated = True
                break
    except PermissionError as exc:
        return {
            "supported": False,
            "method": "background-win32",
            "window": target,
            "toolbars": [],
            "count": 0,
            "truncated": False,
            "reason": str(exc),
        }
    return {
        "supported": True,
        "method": "background-win32",
        "window": target,
        "toolbars": returned,
        "count": len(returned),
        "truncated": truncated,
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
def api_monitor_gui_uia(
    action: str = "read",
    window_title: str = "",
    window_handle: int | None = None,
    control_name: str = "",
    control_type: str = "",
    control_handle: int | None = None,
    text: str = "",
    limit: int = 2000,
    max_depth: int = 8,
    automation_id: str = "",
    class_name: str = "",
) -> dict[str, Any]:
    """Read or invoke Rohitab controls through background Windows UI Automation."""
    if sys.platform != "win32":
        return {"supported": False, "windows": []}
    if action not in {"read", "click", "set_text", "select"}:
        raise ValueError("action must be read, click, set_text, or select")
    if (
        action != "read"
        and not control_name
        and control_handle is None
        and not automation_id
        and not class_name
    ):
        raise ValueError(
            "an action requires control_name, control_handle, automation_id, or class_name"
        )
    if control_handle is not None and control_handle < 1:
        raise ValueError("control_handle must be positive")
    limit = _limit(limit, "limit", 20_000)
    if not 0 <= max_depth <= 32:
        raise ValueError("max_depth must be between 0 and 32")
    try:
        from pywinauto import Desktop
    except ImportError as exc:
        raise RuntimeError("Install pywinauto for Rohitab UI Automation") from exc

    pids = {
        int(process["pid"])
        for process in api_monitor_status().get("processes", [])
        if isinstance(process.get("pid"), int)
    }
    windows = []
    for window in Desktop(backend="uia").windows():
        try:
            if window.process_id() not in pids:
                continue
            if window_title and window.window_text() != window_title:
                continue
            if window_handle is not None and window.handle != window_handle:
                continue
            windows.append(window)
        except (OSError, RuntimeError):
            continue
    if not windows:
        raise LookupError("Rohitab UI Automation window was not found")

    def control_info(control: Any, depth: int) -> dict[str, Any]:
        try:
            kind = control.element_info.control_type or ""
        except (AttributeError, OSError, RuntimeError):
            kind = ""
        try:
            name = _uia_text(control)
        except (AttributeError, OSError, RuntimeError):
            name = ""
        try:
            handle = int(control.handle) if control.handle is not None else None
        except (AttributeError, TypeError, ValueError):
            handle = None
        try:
            automation = control.element_info.automation_id or ""
        except (AttributeError, OSError, RuntimeError):
            automation = ""
        try:
            native_class = control.element_info.class_name or ""
        except (AttributeError, OSError, RuntimeError):
            native_class = ""
        try:
            rectangle = _uia_rect(control)
        except (OSError, RuntimeError):
            rectangle = {}
        try:
            visible = bool(control.is_visible())
        except (AttributeError, OSError, RuntimeError):
            visible = None
        try:
            enabled = bool(control.is_enabled())
        except (AttributeError, OSError, RuntimeError):
            enabled = None
        return {
            "handle": handle,
            "control_type": kind,
            "name": name,
            "automation_id": automation,
            "class_name": native_class,
            "rectangle": rectangle,
            "visible": visible,
            "enabled": enabled,
            "depth": depth,
        }

    selector_requested = bool(
        control_name
        or control_type
        or control_handle is not None
        or automation_id
        or class_name
    )

    def selected(info: dict[str, Any]) -> bool:
        return not (
            (control_handle is not None and info["handle"] != control_handle)
            or (control_name and info["name"] != control_name)
            or (control_type and info["control_type"] != control_type)
            or (automation_id and info["automation_id"] != automation_id)
            or (class_name and info["class_name"] != class_name)
        )

    def all_controls(window: Any) -> list[Any]:
        try:
            return [window, *window.descendants()]
        except (OSError, RuntimeError):
            return []

    if action == "read":
        if selector_requested:
            matches = []
            for window in windows:
                for control in all_controls(window):
                    info = control_info(control, 0)
                    if selected(info):
                        matches.append(
                            {
                                "window": {"handle": window.handle, "title": window.window_text()},
                                "control": info,
                            }
                        )
            return {
                "supported": True,
                "method": "background-ui-automation",
                "controls": matches[:limit],
                "count": len(matches),
                "truncated": len(matches) > limit,
            }
        returned_windows = []
        item_count = 0
        truncated = False

        def walk(control: Any, depth: int, items: list[dict[str, Any]]) -> None:
            nonlocal item_count, truncated
            if item_count >= limit:
                truncated = True
                return
            items.append(control_info(control, depth))
            item_count += 1
            if depth >= max_depth or item_count >= limit:
                return
            try:
                children = control.children()
            except (OSError, RuntimeError):
                return
            for child in children:
                walk(child, depth + 1, items)
                if item_count >= limit:
                    truncated = True
                    return

        for window in windows:
            items: list[dict[str, Any]] = []
            walk(window, 0, items)
            returned_windows.append(
                {
                    "handle": window.handle,
                    "title": window.window_text(),
                    "items": items,
                }
            )
            if item_count >= limit:
                break
        return {
            "supported": True,
            "method": "background-ui-automation",
            "windows": returned_windows,
            "count": item_count,
            "truncated": truncated,
        }

    matches = []
    for window in windows:
        for control in all_controls(window):
            info = control_info(control, 0)
            if not selected(info):
                continue
            matches.append((window, control, info))
    if len(matches) != 1:
        raise ValueError("UIA action must identify exactly one control")
    window, control, info = matches[0]
    try:
        if action == "click":
            control.invoke()
        elif action == "set_text":
            control.set_edit_text(text)
        else:
            control.select()
    except Exception as exc:
        raise RuntimeError(f"Could not {action} Rohitab UIA control: {exc}") from exc
    return {
        "updated": True,
        "method": "background-ui-automation",
        "action": action,
        "window": {"handle": window.handle, "title": window.window_text()},
        "control": info,
        "text": text if action == "set_text" else None,
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
    native_windows = {window["handle"]: window for window in _find_api_monitor_windows(pids)}
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
            row_details: list[dict[str, Any]] = []
            for item in control.children():
                if item.element_info.control_type != "ListItem":
                    continue
                cells = [
                    _uia_text(cell)
                    for cell in item.descendants()
                    if cell.element_info.control_type == "Text"
                ]
                row_index = len(rows)
                rows.append(cells or [_uia_text(item)])
                try:
                    row_handle = int(item.handle) if item.handle is not None else None
                except (AttributeError, TypeError, ValueError):
                    row_handle = None
                try:
                    row_selected = bool(item.is_selected())
                except (AttributeError, OSError, RuntimeError):
                    row_selected = None
                try:
                    row_enabled = bool(item.is_enabled())
                except (AttributeError, OSError, RuntimeError):
                    row_enabled = None
                try:
                    row_rectangle = _uia_rect(item)
                except (AttributeError, OSError, RuntimeError):
                    row_rectangle = {}
                row_details.append(
                    {
                        "row_index": row_index,
                        "handle": row_handle,
                        "cells": rows[-1],
                        "selected": row_selected,
                        "enabled": row_enabled,
                        "rectangle": row_rectangle,
                    }
                )
                if len(rows) > limit:
                    break
            truncated = len(rows) > limit
            lists.append(
                {
                    "handle": control.handle,
                    "pane_title": _gui_pane_title(
                        native_windows.get(window.handle, {}), int(control.handle)
                    ),
                    "rectangle": _uia_rect(control),
                    "headers": headers,
                    "rows": rows[:limit],
                    "records": _named_gui_rows(headers, rows[:limit]),
                    "row_details": row_details[:limit],
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
                    "pane_title": pane.get("pane_title"),
                    "headers": headers,
                    "rows": pane["rows"],
                    "records": _named_gui_rows(headers, pane["rows"]),
                    "row_details": pane.get("row_details", []),
                    "truncated": pane["truncated"],
                }
            )
    return {"supported": lists.get("supported", False), "panes": traffic}


@mcp.tool()
def api_monitor_search_traffic(
    query: str,
    window_title: str = "",
    limit: int = 500,
    query_regex: bool = False,
    max_matches: int = 2000,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Search the current background API Monitor traffic snapshot."""
    if not query.strip():
        raise ValueError("query must not be empty")
    if len(query) > 4096:
        raise ValueError("query must not exceed 4096 characters")
    expression = None
    if query_regex:
        try:
            expression = re.compile(query, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"query is not a valid regex: {exc}") from exc
    limit = _limit(limit, "limit", 2000)
    max_matches = _limit(max_matches, "max_matches", 20_000)
    traffic = api_monitor_traffic(window_title, limit, window_handle)
    matched_panes: list[dict[str, Any]] = []
    match_count = 0
    returned_count = 0
    source_truncated = False
    for pane in traffic.get("panes", []):
        rows = pane.get("rows", [])
        details = pane.get("row_details", [])
        matching_indices = []
        for index, record in enumerate(pane.get("records", [])):
            text = json.dumps(record, ensure_ascii=False, default=str)
            if expression.search(text) if expression else query.casefold() in text.casefold():
                matching_indices.append(index)
        match_count += len(matching_indices)
        source_truncated |= pane.get("truncated", False)
        selected = matching_indices[: max(0, max_matches - returned_count)]
        if not selected:
            continue
        matched = dict(pane)
        matched["rows"] = [rows[index] for index in selected if index < len(rows)]
        matched["records"] = [pane["records"][index] for index in selected]
        matched["row_details"] = [details[index] for index in selected if index < len(details)]
        matched["match_count"] = len(matching_indices)
        matched["truncated"] = pane.get("truncated", False) or len(selected) < len(matching_indices)
        matched_panes.append(matched)
        returned_count += len(selected)
    return {
        "supported": traffic.get("supported", False),
        "query": query,
        "query_regex": query_regex,
        "panes": matched_panes,
        "count": match_count,
        "returned_count": returned_count,
        "truncated": source_truncated or match_count > returned_count,
    }


@mcp.tool()
def api_monitor_export_traffic(
    output_path: str,
    window_title: str = "",
    limit: int = 500,
    output_format: str = "json",
    window_handle: int | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export a bounded live API Monitor traffic snapshot as JSON or CSV."""
    output_format = output_format.casefold()
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be json or csv")
    path = Path(output_path).expanduser()
    if not path.parent.is_dir():
        raise FileNotFoundError(f"Output directory not found: {path.parent}")
    existed = path.exists()
    if existed and not overwrite:
        raise FileExistsError(f"Output already exists: {path}")

    traffic = api_monitor_traffic(window_title, limit, window_handle)
    panes = traffic.get("panes", [])
    records = [
        {
            **(record if isinstance(record, dict) else {"value": record}),
            "pane_title": pane.get("pane_title"),
            "list_handle": pane.get("list_handle"),
            "row_index": row_index,
        }
        for pane in panes
        for row_index, record in enumerate(pane.get("records", []))
    ]
    if output_format == "json":
        payload = (json.dumps(traffic, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    else:
        base_fields = ["pane_title", "list_handle", "row_index"]
        fields = set().union(*(record.keys() for record in records)) if records else set()
        fieldnames = base_fields + sorted(fields.difference(base_fields))
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    key: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                    if isinstance(value, (dict, list))
                    else value
                    for key, value in record.items()
                }
            )
        payload = stream.getvalue().encode("utf-8")
    try:
        if overwrite:
            path.write_bytes(payload)
        else:
            with path.open("xb") as stream:
                stream.write(payload)
    except Exception:
        if not existed and path.is_file():
            path.unlink()
        raise
    return {
        "exported": True,
        "output": str(path),
        "format": output_format,
        "supported": traffic.get("supported", False),
        "panes": len(panes),
        "rows": len(records),
        "truncated": any(pane.get("truncated", False) for pane in panes),
        "size": len(payload),
    }


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
            "pane_title": pane.get("pane_title"),
            "headers": pane["headers"],
            "rows": pane["rows"],
            "records": _named_gui_rows(pane["headers"], pane["rows"]),
            "row_details": pane.get("row_details", []),
            "truncated": pane["truncated"],
        }
        for window in refreshed.get("windows", [])
        for pane in window.get("lists", [])
        if pane["handle"] != call_pane["list_handle"]
    ]
    details_by_pane: dict[str, dict[str, Any]] = {}
    for pane in details:
        key = pane.get("pane_title") or f"list:{pane['handle']}"
        if key in details_by_pane:
            key = f"{key}#{pane['handle']}"
        details_by_pane[key] = pane
    return {
        "selected_call": selected,
        "details": details,
        "details_by_pane": details_by_pane,
        "summaries": api_monitor_summary(window_title, window_handle)["summaries"],
    }


@mcp.tool()
def api_monitor_call_stack(
    row_index: int | None = None,
    query: str = "",
    window_title: str = "",
    limit: int = 500,
    window_handle: int | None = None,
) -> dict[str, Any]:
    """Select a live API call and return its background Call Stack pane."""
    if row_index is None and not query:
        raise ValueError("row_index or query is required")
    limit = _limit(limit, "limit", 2000)
    details = api_monitor_traffic_details(
        window_title=window_title,
        row_index=row_index,
        query=query,
        limit=limit,
        window_handle=window_handle,
    )
    stacks = [
        pane
        for pane in details.get("details", [])
        if "call stack" in str(pane.get("pane_title") or "").casefold()
    ]
    return {
        "supported": bool(stacks),
        "method": "background-ui-automation",
        "selected_call": details.get("selected_call"),
        "stacks": stacks,
        "count": len(stacks),
        "summaries": details.get("summaries", []),
        "reason": None if stacks else "Call Stack pane was not found",
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
def api_monitor_wait_for_new_traffic(
    minimum_new_calls: int = 1,
    timeout_seconds: int = 30,
    window_title: str = "",
    window_handle: int | None = None,
    baseline_calls: int | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Wait for new Rohitab traffic relative to an optional call-count baseline."""
    if minimum_new_calls < 0:
        raise ValueError("minimum_new_calls must be non-negative")
    if timeout_seconds < 1 or timeout_seconds > 300:
        raise ValueError("timeout_seconds must be between 1 and 300")
    if baseline_calls is not None and baseline_calls < 0:
        raise ValueError("baseline_calls must be non-negative")
    limit = _limit(limit, "limit", 2000)
    summaries = api_monitor_summary(window_title, window_handle)["summaries"]
    baseline_traffic = api_monitor_traffic(window_title, limit, window_handle)
    if baseline_calls is None:
        baseline_calls = sum(summary["calls"] for summary in summaries)
    target_calls = baseline_calls + minimum_new_calls
    deadline = time.monotonic() + timeout_seconds

    def result(ready: bool, current_calls: int) -> dict[str, Any]:
        traffic = api_monitor_traffic(window_title, limit, window_handle)
        return {
            "ready": ready,
            "baseline_calls": baseline_calls,
            "current_calls": current_calls,
            "new_calls": current_calls - baseline_calls,
            "minimum_new_calls": minimum_new_calls,
            "summaries": summaries,
            "traffic": traffic,
            "new_traffic": _gui_traffic_delta(baseline_traffic, traffic),
        }

    while True:
        summaries = api_monitor_summary(window_title, window_handle)["summaries"]
        current_calls = sum(summary["calls"] for summary in summaries)
        if current_calls >= target_calls:
            return result(True, current_calls)
        if time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    current_calls = sum(summary["calls"] for summary in summaries)
    return result(False, current_calls)


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
    if architecture not in {"auto", "x86", "x64"}:
        raise ValueError("architecture must be auto, x86, or x64")
    target = Path(process_path).expanduser()
    if not target.is_file():
        raise FileNotFoundError(f"Target process not found: {target}")
    target = target.resolve()
    requested_architecture = architecture
    if architecture == "auto":
        detected = api_monitor_executable_architecture(str(target))
        architecture = detected.get("architecture")
        if architecture not in {"x86", "x64"}:
            raise RuntimeError(
                f"Could not determine an API Monitor-compatible architecture for {target}"
            )
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
        "requested_architecture": requested_architecture,
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
    if architecture not in {"auto", "x86", "x64"}:
        raise ValueError("architecture must be auto, x86, or x64")
    requested_architecture = architecture
    if architecture == "auto":
        target = Path(process_path).expanduser()
        if not target.is_file():
            raise FileNotFoundError(f"Target process not found: {target}")
        detected = api_monitor_executable_architecture(str(target.resolve()))
        architecture = detected.get("architecture")
        if architecture not in {"x86", "x64"}:
            raise RuntimeError(
                f"Could not determine an API Monitor-compatible architecture for {target}"
            )
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
    except (LookupError, OSError, RuntimeError, TimeoutError) as exc:
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
    validation = saved.get("validation")
    if validation is None:
        validation = capture_validate(str(path))
    result: dict[str, Any] = {
        "captured": True,
        "ready": ready,
        "minimum_calls": minimum_calls,
        "requested_architecture": requested_architecture,
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
    validation = saved.get("validation")
    if validation is None:
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
    if architecture not in {"auto", "x86", "x64"}:
        raise ValueError("architecture must be auto, x86, or x64")
    requested_architecture = architecture
    if architecture == "auto":
        detected = api_monitor_process_architecture(pid)
        architecture = detected.get("architecture")
        if architecture not in {"x86", "x64"}:
            raise RuntimeError(f"Could not determine an API Monitor-compatible architecture for PID {pid}")

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
                    "requested_architecture": requested_architecture,
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
def api_monitor_launch(
    architecture: str = "x64",
    install_root: str | None = None,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Launch the installed Rohitab API Monitor x86 or x64 executable."""
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    root = _app_root(install_root)
    executable = _app_executable(root, architecture)
    existing_handles = {window["handle"] for window in _find_api_monitor_windows()}
    process = subprocess.Popen(
        [str(executable)],
        cwd=str(root),
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        startupinfo=_background_startupinfo(),
    )
    bitness = "32-bit" if architecture == "x86" else "64-bit"
    window = _wait_for_api_monitor_window(
        lambda candidate: candidate["handle"] not in existing_handles
        and "api monitor v2" in candidate["title"].casefold()
        and bitness in candidate["title"],
        timeout_seconds,
    )
    return {
        "pid": process.pid,
        "architecture": architecture,
        "executable": str(executable),
        "ready": window is not None,
        "window": window,
    }


@mcp.tool()
def api_monitor_open_capture(
    file_path: str,
    install_root: str | None = None,
    window_handle: int | None = None,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Open an APMX capture with the real Rohitab API Monitor application."""
    path = _capture_path(file_path)
    if sys.platform != "win32" or not hasattr(os, "startfile"):
        raise RuntimeError("Opening API Monitor captures requires Windows")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")

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
            timeout_seconds,
        )
        opened_window = _wait_for_api_monitor_window(
            lambda window: path.name.casefold() in window["title"].casefold()
            or path.stem.casefold() in window["title"].casefold(),
            timeout_seconds,
        )
        return {
            "opened": True,
            "method": "background-gui",
            "file": str(path),
            "verified": opened_window is not None,
            "window": opened_window,
        }
    except (LookupError, OSError, RuntimeError, TimeoutError):
        os.startfile(str(path), "open", None, None, 4)  # SW_SHOWNOACTIVATE
        opened_window = _wait_for_api_monitor_window(
            lambda window: path.name.casefold() in window["title"].casefold()
            or path.stem.casefold() in window["title"].casefold(),
            timeout_seconds,
        )
        return {
            "opened": True,
            "method": "file-association-fallback",
            "file": str(path),
            "verified": opened_window is not None,
            "window": opened_window,
        }


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
            result = {
                "saved": True,
                "method": "background-gui",
                "file": str(path),
                "size": stat.st_size,
                "modified_utc": _file_time(path),
            }
            result["validation"] = capture_validate(str(path))
            return result
        time.sleep(0.1)
    raise TimeoutError("API Monitor did not finish saving the capture")
