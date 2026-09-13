"""MCP entry point for the real Rohitab API Monitor application."""

from __future__ import annotations

import argparse

from api_monitor_mcp import capture_tools, definition_tools, gui_tools  # noqa: F401
from api_monitor_mcp.runtime import mcp
from api_monitor_mcp.selftest import _self_test


def main() -> None:
    parser = argparse.ArgumentParser(description="Rohitab API Monitor MCP server")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=mcp.settings.port,
        help="HTTP/SSE port (default: 8000)",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535")
    if args.self_test:
        _self_test()
        print("ok")
        return
    mcp.settings.port = args.port
    mcp.run(args.transport)


if __name__ == "__main__":
    main()
