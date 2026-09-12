"""Bare-bones MCP bridge for the real Rohitab API Monitor application.

This version intentionally does not reverse engineer live IPC or the APMX call
record format. It exposes safe capture triage plus launch/open operations.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import mmap
import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from mcp.server.fastmcp import FastMCP


DEFAULT_APP_ROOT = Path(r"C:\Program Files\rohitab.com\API Monitor")
CAPTURE_SUFFIXES = {".apmx64", ".apmx86"}
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
API_NAME = re.compile(r'<Api\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)
MODULE_NAME = re.compile(r'<Module\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.I)

mcp = FastMCP(
    "rohitab-api-monitor",
    instructions=(
        "Read Rohitab API Monitor .apmx captures, search their raw contents, "
        "and launch the installed API Monitor application. This server does not "
        "decode live API calls yet."
    ),
)


def _capture_path(file_path: str) -> Path:
    path = Path(file_path).expanduser()
    if path.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("file_path must end in .apmx64 or .apmx86")
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")
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

    try:
        os.startfile(str(path))
        return {"opened": True, "method": "file-association", "file": str(path)}
    except OSError:
        architecture = "x86" if path.suffix.lower() == ".apmx86" else "x64"
        root = _app_root(install_root)
        executable = _app_executable(root, architecture)
        process = subprocess.Popen([str(executable), str(path)], cwd=str(root))
        return {
            "opened": True,
            "method": "direct-launch-fallback",
            "pid": process.pid,
            "file": str(path),
            "executable": str(executable),
        }


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
        path.write_bytes(b"APMX-BARE-BONES\x00" + payload.getvalue())

        info = _capture_info(path)
        assert info["extension"] == ".apmx64"
        assert info["entries"][0]["name"] == "metadata.txt"
        strings = _capture_strings(path, "CreateFile", 10, 4)
        assert strings and "CreateFileW" in strings[0]["text"]
        entries = _zip_entries(path)
        assert {entry["name"] for entry in entries} == {"metadata.txt", "calls.bin"}


def main() -> None:
    if "--self-test" in sys.argv:
        _self_test()
        print("ok")
        return
    mcp.run("stdio")


if __name__ == "__main__":
    main()
