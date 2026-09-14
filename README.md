# Rohitab API Monitor MCP

MCP server for the installed Rohitab API Monitor on Windows. Supports APMX capture inspection, live capture, GUI control, traffic search, decoding, and blue-team/CTF triage.

## Requirements

- Windows 10+
- Rohitab API Monitor installed
- [`uv`](https://docs.astral.sh/uv/)

## Installation

### Claude Code

```powershell
claude plugin marketplace add https://github.com/zxcvbbq/API-Monitor-MCP.git
claude plugin install api-monitor-mcp@api-monitor-mcp
```

### Codex

```powershell
codex plugin marketplace add zxcvbbq/API-Monitor-MCP
codex plugin add api-monitor-mcp@api-monitor-mcp
```

## Local

```powershell
uv run python .\server.py --self-test
uv run python .\server.py --transport streamable-http --port 8745
```

## Tools

Headless: `capture_overview`, `capture_security_report`, `capture_search_calls`, `capture_decode_call`, `capture_compare_calls`, `capture_extract_entry`, and evidence exports for `.apmx86`/`.apmx64`.

GUI/live: `api_monitor_capture_process`, `api_monitor_attach_process`, `api_monitor_traffic`, `api_monitor_add_display_filter`, and `api_monitor_gui_screenshot`.

Set `APIMONITOR_HOME` if API Monitor is installed outside the default path.
