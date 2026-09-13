"""Windows API Monitor discovery and background GUI helpers."""

from __future__ import annotations

import csv
import ctypes
import io
import os
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path
from typing import Any

from .runtime import DEFAULT_APP_ROOT


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


def _background_startupinfo() -> subprocess.STARTUPINFO | None:
    if sys.platform != "win32":
        return None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 4  # SW_SHOWNOACTIVATE
    return startupinfo


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

    from . import gui_tools

    api_monitor_pids = {
        int(process["pid"])
        for process in gui_tools.api_monitor_status().get("processes", [])
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
    user32.SendMessageW.restype = ctypes.c_ssize_t
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


def _tree_item_action(tree_handle: int, item_handle: int, action: str) -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendMessageW.restype = ctypes.c_ssize_t
    messages = {
        "expand": (0x1102, 2),  # TVM_EXPAND / TVE_EXPAND
        "collapse": (0x1102, 1),  # TVM_EXPAND / TVE_COLLAPSE
        "toggle": (0x1102, 3),  # TVM_EXPAND / TVE_TOGGLE
        "select": (0x110B, 9),  # TVM_SELECTITEM / TVGN_CARET
        "ensure_visible": (0x1114, 0),  # TVM_ENSUREVISIBLE
    }
    message, command = messages[action]
    result = user32.SendMessageW(tree_handle, message, command, item_handle)
    if action != "collapse" and not result:
        error = ctypes.get_last_error()
        if error:
            raise OSError(error, f"Could not {action.replace('_', ' ')} API Monitor tree item")


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


def _read_native_menu(handle: int, max_items: int, max_depth: int) -> tuple[list[dict[str, Any]], bool]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    menu = user32.GetMenu(handle)
    if not menu:
        raise LookupError("API Monitor window has no menu")
    seen = 0
    truncated = False

    def visit(menu_handle: int, depth: int) -> list[dict[str, Any]]:
        nonlocal seen, truncated
        items: list[dict[str, Any]] = []
        count = user32.GetMenuItemCount(menu_handle)
        for position in range(max(0, count)):
            if seen >= max_items:
                truncated = True
                break
            seen += 1
            state = user32.GetMenuState(menu_handle, position, 0x0400)  # MF_BYPOSITION
            command_id = user32.GetMenuItemID(menu_handle, position)
            text_buffer = ctypes.create_unicode_buffer(512)
            text_length = user32.GetMenuStringW(
                menu_handle, position, text_buffer, len(text_buffer), 0x0400
            )
            item: dict[str, Any] = {
                "position": position,
                "command_id": None if command_id == -1 else int(command_id),
                "text": text_buffer.value[:text_length],
                "separator": bool(state & 0x0800),
                "enabled": not bool(state & 0x0003),
                "checked": bool(state & 0x0008),
                "state": int(state),
            }
            submenu = user32.GetSubMenu(menu_handle, position)
            if submenu:
                if depth < max_depth:
                    item["items"] = visit(submenu, depth + 1)
                else:
                    item["items"] = []
                    item["children_truncated"] = True
            items.append(item)
        return items

    return visit(menu, 0), truncated


def _menu_label(text: str) -> str:
    return text.replace("&", "").replace("...", "").strip().casefold()


def _find_native_menu_item(items: list[dict[str, Any]], path: list[str]) -> dict[str, Any] | None:
    if not path:
        return None
    wanted = _menu_label(path[0])
    for item in items:
        if _menu_label(item.get("text", "")) != wanted:
            continue
        if len(path) == 1:
            return item
        return _find_native_menu_item(item.get("items", []), path[1:])
    return None


def _read_native_toolbar(handle: int, max_items: int) -> tuple[list[dict[str, Any]], bool]:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPCVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    class ToolbarButton(ctypes.Structure):
        _fields_ = [
            ("bitmap", ctypes.c_int),
            ("command_id", ctypes.c_int),
            ("state", ctypes.c_ubyte),
            ("style", ctypes.c_ubyte),
            ("reserved", ctypes.c_ubyte * 2),
            ("data", ctypes.c_void_p),
            ("string", ctypes.c_void_p),
        ]

    process_id = wintypes.DWORD()
    if not user32.GetWindowThreadProcessId(handle, ctypes.byref(process_id)):
        raise OSError(ctypes.get_last_error(), "Could not inspect API Monitor toolbar")
    process = kernel32.OpenProcess(0x438, False, process_id.value)
    if not process:
        error = ctypes.get_last_error()
        if error == 5:
            raise PermissionError(
                error,
                "API Monitor toolbar requires the MCP client to run at the same elevation level",
            )
        raise OSError(error, "Could not open API Monitor toolbar process")
    button_size = ctypes.sizeof(ToolbarButton)
    remote_button = kernel32.VirtualAllocEx(process, None, button_size, 0x3000, 4)
    remote_text = kernel32.VirtualAllocEx(process, None, 2048, 0x3000, 4)
    if not remote_button or not remote_text:
        if remote_button:
            kernel32.VirtualFreeEx(process, remote_button, 0, 0x8000)
        if remote_text:
            kernel32.VirtualFreeEx(process, remote_text, 0, 0x8000)
        kernel32.CloseHandle(process)
        raise OSError(ctypes.get_last_error(), "Could not allocate API Monitor toolbar buffer")

    try:
        count = int(user32.SendMessageW(handle, 0x0418, 0, 0))  # TB_BUTTONCOUNT
        if count < 0:
            raise OSError(ctypes.get_last_error(), "Could not count API Monitor toolbar buttons")
        truncated = count > max_items
        items: list[dict[str, Any]] = []
        written = ctypes.c_size_t()
        for index in range(min(count, max_items)):
            if not user32.SendMessageW(handle, 0x0417, index, remote_button):  # TB_GETBUTTON
                raise OSError(ctypes.get_last_error(), f"Could not read toolbar button {index}")
            button = ToolbarButton()
            if not kernel32.ReadProcessMemory(
                process, remote_button, ctypes.byref(button), button_size, ctypes.byref(written)
            ):
                raise OSError(ctypes.get_last_error(), f"Could not copy toolbar button {index}")
            text = ""
            if button.command_id >= 0:
                text_length = int(
                    user32.SendMessageW(handle, 0x044B, button.command_id, remote_text)
                )  # TB_GETBUTTONTEXTW
                if text_length >= 0:
                    text_buffer = ctypes.create_unicode_buffer(1024)
                    if kernel32.ReadProcessMemory(
                        process, remote_text, text_buffer, 2048, ctypes.byref(written)
                    ):
                        text = text_buffer.value[: min(text_length, 1023)]
            items.append(
                {
                    "index": index,
                    "command_id": button.command_id,
                    "bitmap": button.bitmap,
                    "state": int(button.state),
                    "style": int(button.style),
                    "text": text,
                    "separator": bool(button.style & 0x01),
                    "enabled": bool(button.state & 0x04),
                    "checked": bool(button.state & 0x01),
                    "hidden": bool(button.state & 0x08),
                }
            )
        return items, truncated
    finally:
        kernel32.VirtualFreeEx(process, remote_button, 0, 0x8000)
        kernel32.VirtualFreeEx(process, remote_text, 0, 0x8000)
        kernel32.CloseHandle(process)


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
    from . import gui_tools

    gui_tools.api_monitor_launch(architecture)
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


def _detect_process_architecture(pid: int) -> dict[str, Any]:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    process = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not process:
        raise OSError(ctypes.get_last_error(), f"Could not query process {pid}")
    try:
        machine_names = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
        is_wow64_process2 = getattr(kernel32, "IsWow64Process2", None)
        if is_wow64_process2 is not None:
            is_wow64_process2.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ctypes.c_ushort),
                ctypes.POINTER(ctypes.c_ushort),
            ]
            is_wow64_process2.restype = wintypes.BOOL
            process_machine = ctypes.c_ushort()
            native_machine = ctypes.c_ushort()
            if not is_wow64_process2(
                process,
                ctypes.byref(process_machine),
                ctypes.byref(native_machine),
            ):
                raise OSError(ctypes.get_last_error(), f"Could not query process {pid} architecture")
            machine = process_machine.value or native_machine.value
            return {
                "pid": pid,
                "architecture": machine_names.get(machine),
                "machine": f"0x{machine:04x}",
                "method": "IsWow64Process2",
            }
        is_wow64_process = kernel32.IsWow64Process
        is_wow64_process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        is_wow64_process.restype = wintypes.BOOL
        wow64 = wintypes.BOOL()
        if not is_wow64_process(process, ctypes.byref(wow64)):
            raise OSError(ctypes.get_last_error(), f"Could not query process {pid} architecture")
        return {
            "pid": pid,
            "architecture": "x86" if wow64.value else "x64",
            "machine": None,
            "method": "IsWow64Process",
        }
    finally:
        close_handle(process)


def _detect_executable_architecture(path: Path) -> dict[str, Any]:
    machine_names = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
    with path.open("rb") as handle:
        dos_header = handle.read(64)
        if len(dos_header) < 64 or dos_header[:2] != b"MZ":
            raise ValueError(f"Not a Windows PE executable: {path}")
        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
        handle.seek(pe_offset)
        pe_header = handle.read(6)
    if len(pe_header) < 6 or pe_header[:4] != b"PE\0\0":
        raise ValueError(f"Not a Windows PE executable: {path}")
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    return {
        "file": str(path),
        "architecture": machine_names.get(machine),
        "machine": f"0x{machine:04x}",
        "method": "PE machine header",
    }


def _named_gui_rows(headers: list[str], rows: list[list[str]]) -> list[dict[str, Any]]:
    return [
        {
            "row_index": row_index,
            "values": {
                header or f"column_{column_index}": value
                for column_index, value in enumerate(row)
                if column_index < len(headers)
                for header in [headers[column_index]]
            },
        }
        for row_index, row in enumerate(rows)
    ]


def _gui_pane_title(window: dict[str, Any], list_handle: int) -> str | None:
    list_child = next(
        (child for child in window.get("children", []) if child.get("handle") == list_handle),
        None,
    )
    list_rect = (list_child or {}).get("rectangle", {})
    if not list_rect:
        return None

    def contains(outer: dict[str, Any], inner: dict[str, Any]) -> bool:
        return (
            outer.get("left", 0) <= inner.get("left", 0)
            and outer.get("top", 0) <= inner.get("top", 0)
            and outer.get("right", 0) >= inner.get("right", 0)
            and outer.get("bottom", 0) >= inner.get("bottom", 0)
        )

    candidates = [
        child
        for child in window.get("children", [])
        if child.get("class", "").startswith("Afx:ControlBar")
        and child.get("title")
        and contains(child.get("rectangle", {}), list_rect)
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda child: (
            (child["rectangle"].get("right", 0) - child["rectangle"].get("left", 0))
            * (child["rectangle"].get("bottom", 0) - child["rectangle"].get("top", 0)),
            child["handle"],
        )
    )
    return candidates[0]["title"]


def _gui_traffic_delta(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_rows = {
        pane.get("list_handle"): pane.get("rows", [])
        for pane in baseline.get("panes", [])
    }
    panes = []
    complete = True
    for pane in current.get("panes", []):
        rows = pane.get("rows", [])
        previous = baseline_rows.get(pane.get("list_handle"), [])
        prefix_matches = rows[: len(previous)] == previous
        pane_complete = prefix_matches and not pane.get("truncated", False)
        new_rows = rows[len(previous) :] if prefix_matches else []
        complete = complete and pane_complete
        if new_rows or not pane_complete:
            panes.append(
                {
                    **pane,
                    "rows": new_rows,
                    "records": _named_gui_rows(pane.get("headers", []), new_rows),
                    "baseline_rows": len(previous),
                    "delta_complete": pane_complete,
                }
            )
    return {
        "supported": current.get("supported", False),
        "panes": panes,
        "complete": complete,
    }
