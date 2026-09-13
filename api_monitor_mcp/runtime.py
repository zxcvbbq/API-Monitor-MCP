"""Shared MCP instance and constants."""

from __future__ import annotations

import re
from pathlib import Path

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
API_NAME = re.compile(r'<Api\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.IGNORECASE)
MODULE_NAME = re.compile(r'<Module\b[^>]*\bName\s*=\s*["\']([^"\']+)', re.IGNORECASE)
PROCESS_INFO = re.compile(r"process/(\d+)/info$", re.IGNORECASE)
SUMMARY_TEXT = re.compile(
    r"Summary\s*\|\s*([\d,]+)\s*calls\s*\|\s*([^|]+?)\s*\|\s*(.*)",
    re.IGNORECASE,
)
MODULE_EVENT = re.compile(
    r"^(?P<process>[^:]+): Monitoring Module (?P<address>0x[0-9a-f]+) -> (?P<module>.+)$",
    re.IGNORECASE,
)
CHILD_EVENT = re.compile(
    r"^(?P<process>[^:]+): Monitoring Child Process - PID: (?P<pid>\d+) \| Attach: (?P<attach>.+)$",
    re.IGNORECASE,
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
