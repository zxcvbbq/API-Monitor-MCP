"""MCP bridge for the real Rohitab API Monitor application.

This version intentionally does not reverse engineer live IPC or the APMX call
record format. It exposes capture triage plus background GUI operations.
"""

from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import io
import mmap
import os
import re
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from mcp.server.fastmcp import FastMCP


DEFAULT_APP_ROOT = Path(r"C:\Program Files\rohitab.com\API Monitor")
CAPTURE_SUFFIXES = {".apmx64", ".apmx86"}
COMMAND_OPEN_CAPTURE = 32852
COMMAND_SAVE_CAPTURE = 32854
COMMAND_SAVE_CAPTURE_AS = 32954
COMMAND_START_MONITORING = 32882
COMMAND_STOP_MONITORING = 32929
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
API_NAME = re.compile(r'<Api\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)
MODULE_NAME = re.compile(r'<Module\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)
PROCESS_INFO = re.compile(r"process/(\d+)/info$", re.I)

mcp = FastMCP(
    "rohitab-api-monitor",
    instructions=(
        "Read Rohitab API Monitor .apmx captures, search their raw contents, "
        "launch the installed API Monitor application, and automate its GUI "
        "without bringing it to the foreground. This server does not decode "
        "live API calls yet."
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


def _limit(value: int, name: str, maximum: int) -> int:
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _zip_offset(data: bytes) -> int | None:
    offsets = [data.find(signature) for signature in ZIP_SIGNATURES]
    offsets = [offset for offset in offsets if offset >= 0]
    return min(offsets) if offsets else None


def _open_capture_zip(path: Path) -> tuple[zipfile.ZipFile, bytes, int]:
    # ponytail: copies the capture for ZIP access; use a streaming offset reader if multi-GB captures matter.
    data = path.read_bytes()
    offset = _zip_offset(data)
    if offset is None:
        raise ValueError("Capture does not contain a ZIP container")
    return zipfile.ZipFile(io.BytesIO(data[offset:])), data, offset


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
    try:
        result["entries"] = _zip_entries(path)
    except zipfile.BadZipFile as exc:
        result["zip_error"] = str(exc)
        result["entries"] = []
    return result


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


def _ui_window(handle: Any, user32: Any) -> dict[str, Any]:
    return {
        "handle": int(handle),
        "class": _window_class(user32, handle),
        "title": _window_text(user32, handle),
        "control_id": int(user32.GetDlgCtrlID(handle)),
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
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for window in windows:
        if window_title and window.get("title") != window_title:
            continue
        for child in window.get("children", []):
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


def _post_mouse_click(handle: int) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    from ctypes import wintypes

    rect = wintypes.RECT()
    if not user32.GetClientRect(handle, ctypes.byref(rect)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor control")
    x = max(0, (rect.right - rect.left) // 2)
    y = max(0, (rect.bottom - rect.top) // 2)
    lparam = (y << 16) | (x & 0xFFFF)
    user32.PostMessageW(handle, 0x0201, 1, lparam)  # WM_LBUTTONDOWN
    user32.PostMessageW(handle, 0x0202, 0, lparam)  # WM_LBUTTONUP


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
        lambda window: "api monitor v2" in window["title"].casefold(), timeout_seconds
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

    if text and sum(char.isprintable() or char in "\r\n\t" for char in text) / len(text) >= 0.85:
        return {"encoding": encoding, "text": text}
    return {"encoding": "base64", "base64": base64.b64encode(data).decode("ascii")}


@mcp.tool()
def api_monitor_status() -> dict[str, Any]:
    """List running Rohitab API Monitor x86/x64 processes."""
    if sys.platform != "win32":
        return {"supported": False, "processes": []}
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
        return {"supported": True, "error": str(exc), "processes": []}

    processes = []
    for row in csv.reader(io.StringIO(completed.stdout)):
        if len(row) < 5 or row[0].casefold() not in {"apimonitor-x86.exe", "apimonitor-x64.exe"}:
            continue
        try:
            pid: int | str = int(row[1])
        except ValueError:
            pid = row[1]
        processes.append({"image": row[0], "pid": pid, "session": row[2], "memory": row[4]})
    return {"supported": True, "processes": processes}


@mcp.tool()
def api_monitor_ui_tree() -> dict[str, Any]:
    """Inspect Rohitab API Monitor top-level windows and immediate controls."""
    if sys.platform != "win32":
        return {"supported": False, "windows": []}
    return {"supported": True, "windows": _find_api_monitor_windows()}


@mcp.tool()
def api_monitor_gui_action(
    action: str,
    control_id: int | None = None,
    title: str = "",
    class_name: str = "",
    window_title: str = "",
    text: str = "",
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
            if not window_title or window.get("title") == window_title
        ]
        if len(candidates) != 1:
            raise ValueError("close requires one matching window_title")
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.PostMessageW(candidates[0]["handle"], 0x0010, 0, 0)  # WM_CLOSE
        return {"action": action, "window": candidates[0]}

    if control_id is None and not title and not class_name:
        raise ValueError("click and set_text require control_id, title, or class_name")
    target = _find_ui_control(
        _find_api_monitor_windows(), control_id, title, class_name, window_title
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
def api_monitor_gui_read(
    control_id: int | None = None,
    title: str = "",
    class_name: str = "",
    window_title: str = "",
    max_chars: int = 20_000,
) -> dict[str, Any]:
    """Read one Rohitab GUI control without focusing or raising the window."""
    if sys.platform != "win32":
        raise RuntimeError("Rohitab GUI reads require Windows")
    if control_id is None and not title and not class_name:
        raise ValueError("control_id, title, or class_name is required")
    max_chars = _limit(max_chars, "max_chars", 1_000_000)
    target = _find_ui_control(
        _find_api_monitor_windows(), control_id, title, class_name, window_title
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
def api_monitor_gui_lists(window_title: str = "", limit: int = 200) -> dict[str, Any]:
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
        if window.process_id() not in pids or (window_title and window.window_text() != window_title):
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
def api_monitor_traffic(window_title: str = "", limit: int = 500) -> dict[str, Any]:
    """Read captured API-call rows from Rohitab's background traffic panes."""
    limit = _limit(limit, "limit", 2000)
    lists = api_monitor_gui_lists(window_title, limit)
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
def api_monitor_add_display_filter(
    field: str,
    operator: str,
    value: str,
    action: str = "Show",
    ignore_case: bool = True,
    architecture: str = "x64",
    timeout_seconds: int = 10,
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

    main_window = _api_monitor_main_window(architecture, timeout_seconds)
    if main_window is None:
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

    windows = _find_api_monitor_windows()
    main_window = next(
        (window for window in windows if "api monitor v2" in window["title"].casefold()),
        None,
    )
    if main_window is None:
        api_monitor_launch(architecture)
        main_window = _wait_for_api_monitor_window(
            lambda window: "api monitor v2" in window["title"].casefold(), timeout_seconds
        )
    if main_window is None:
        raise TimeoutError("API Monitor main window did not appear")

    dialog = next((window for window in windows if window["title"] == "Monitor Process"), None)
    if dialog is None:
        button = next(
            (
                child
                for child in main_window.get("children", [])
                if child.get("title") == "Monitor New Process"
            ),
            None,
        )
        if button is None:
            raise RuntimeError("Monitor New Process button not found")
        _post_button_click(button["handle"])
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
    }


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
    main_window = _api_monitor_main_window(architecture, timeout_seconds)
    if main_window is None:
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
def api_monitor_open_capture(file_path: str, install_root: str | None = None) -> dict[str, Any]:
    """Open an APMX capture with the real Rohitab API Monitor application."""
    path = _capture_path(file_path)
    if sys.platform != "win32" or not hasattr(os, "startfile"):
        raise RuntimeError("Opening API Monitor captures requires Windows")

    architecture = "x86" if path.suffix.lower() == ".apmx86" else "x64"
    bitness = "32-bit" if architecture == "x86" else "64-bit"
    candidates = [
        window
        for window in _find_api_monitor_windows()
        if "api monitor v2" in window["title"].casefold() and bitness in window["title"]
    ]
    main_window = next(
        (
            window
            for window in candidates
            if not window["title"].casefold().startswith("monitoring")
        ),
        candidates[0] if candidates else None,
    )
    if main_window is None:
        root = _app_root(install_root)
        executable = _app_executable(root, architecture)
        process = subprocess.Popen([str(executable)], cwd=str(root))
        main_window = _wait_for_api_monitor_window(
            lambda window: "api monitor v2" in window["title"].casefold(), 15
        )
        if main_window is None:
            return {
                "opened": True,
                "method": "direct-launch-fallback",
                "pid": process.pid,
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
) -> dict[str, Any]:
    """Save the current Rohitab capture through its background GUI."""
    if sys.platform != "win32":
        raise RuntimeError("Saving API Monitor captures requires Windows")
    if timeout_seconds < 1 or timeout_seconds > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    path = Path(output_path).expanduser()
    if path.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("output_path must end in .apmx64 or .apmx86")
    if not path.parent.is_dir():
        raise NotADirectoryError(f"Output directory not found: {path.parent}")
    path = path.resolve()
    existed = path.exists()
    if existed and not overwrite:
        raise FileExistsError(f"Capture already exists: {path}")

    main_window = _api_monitor_main_window(
        "x86" if path.suffix.lower() == ".apmx86" else "x64", timeout_seconds
    )
    if main_window is None:
        raise TimeoutError("API Monitor main window did not appear")
    if main_window["title"].casefold().startswith("monitoring"):
        bitness = "32-bit" if path.suffix.lower() == ".apmx86" else "64-bit"
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
                if len(matches) >= limit:
                    truncated = True
                    break
    return {
        "file": str(path),
        "query": query,
        "entries": matches,
        "count": len(matches),
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
    return {
        "file": str(_capture_path(file_path)),
        "query": query,
        "lines": lines[:limit],
        "count": len(lines),
        "truncated": len(lines) > limit,
    }


@mcp.tool()
def capture_list_processes(file_path: str, limit: int = 200) -> dict[str, Any]:
    """List process records and executable paths recoverable from an APMX capture."""
    limit = _limit(limit, "limit", 2000)
    path = _capture_path(file_path)
    archive, _, _ = _open_capture_zip(path)
    processes: list[dict[str, Any]] = []
    with archive:
        for info in archive.infolist():
            match = PROCESS_INFO.fullmatch(info.filename)
            if not match:
                continue
            data = archive.read(info)
            strings = _scan_strings(data, ".exe", 200, 4)
            executables = []
            for item in strings:
                value = item["text"].strip("\x00")
                if value.casefold().endswith(".exe") and value not in executables:
                    executables.append(value)
            processes.append(
                {
                    "index": int(match.group(1)),
                    "entry": info.filename,
                    "size": info.file_size,
                    "executables": executables,
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
        if strings:
            matches.append({"file": str(path), "matches": strings})
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


def _self_test() -> None:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "sample.apmx64"
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("metadata.txt", "process=sample.exe\n")
            archive.writestr("calls.bin", b"CreateFileW\x00https://example.test\x00")
            archive.writestr("log/monitoring.txt", "sample.exe: Monitoring Module\n")
            archive.writestr("process/0/info", "C:\\sample.exe".encode("utf-16-le"))
        path.write_bytes(b"APMX-BARE-BONES\x00" + payload.getvalue())

        info = _capture_info(path)
        assert info["extension"] == ".apmx64"
        assert info["entries"][0]["name"] == "metadata.txt"
        strings = _capture_strings(path, "CreateFile", 10, 4)
        assert strings and "CreateFileW" in strings[0]["text"]
        log = capture_monitoring_log(str(path), "module", 10)
        assert log["lines"] == ["sample.exe: Monitoring Module"]
        searched = capture_search_entries(str(path), "CreateFile", 10)
        assert searched["entries"][0]["entry"] == "calls.bin"
        processes = capture_list_processes(str(path), 10)
        assert processes["processes"][0]["executables"] == ["C:\\sample.exe"]
        entries = _zip_entries(path)
        assert {entry["name"] for entry in entries} == {
            "metadata.txt",
            "calls.bin",
            "log/monitoring.txt",
            "process/0/info",
        }
        listed = capture_list_directory(directory, recursive=False, limit=10)
        assert listed["count"] == 1


def main() -> None:
    if "--self-test" in sys.argv:
        _self_test()
        print("ok")
        return
    mcp.run("stdio")


if __name__ == "__main__":
    main()
