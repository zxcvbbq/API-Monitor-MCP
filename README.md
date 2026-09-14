# Rohitab API Monitor MCP

Windows MCP server for Rohitab API Monitor. It analyzes `.apmx86`/`.apmx64` captures headlessly and can also control the installed API Monitor GUI for live traffic collection.

## Requirements

- Windows 10 or later
- [Rohitab API Monitor](http://www.rohitab.com/apimonitor) for live capture and GUI tools
- [`uv`](https://docs.astral.sh/uv/) for local use

Capture analysis works without opening the GUI. Set `APIMONITOR_HOME` when API Monitor is installed outside its default location.

## Install

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

Restart the client after installation or an update.

## Main capabilities

- Inspect capture metadata, processes, modules, API definitions, call records, arguments, return values, and payloads.
- Search calls by API, module, thread, error code, timestamp, duration, text, or bytes.
- Decode strings and typed values, compare calls, build call sequences/graphs, and extract ZIP entries.
- Run bounded blue-team/CTF triage: validation, errors, indicators, entropy, behavior, and security reports.
- Export evidence as JSON, CSV, or raw files.
- Start/attach to processes, collect live traffic, apply display filters, and take GUI screenshots.

## Local development

```powershell
uv run python .\server.py --self-test
uv run python .\server.py --transport streamable-http --port 8745
```

Typical headless workflow: start with `capture_overview` or `capture_security_report`, narrow results with `capture_search_calls`, then inspect matching records with `capture_decode_call` or an export tool.

## Useful tools

Headless: `capture_overview`, `capture_security_report`, `capture_search_calls`, `capture_decode_call`, `capture_compare_calls`, `capture_extract_entry`.

Live/GUI: `api_monitor_capture_process`, `api_monitor_attach_process`, `api_monitor_traffic`, `api_monitor_add_display_filter`, `api_monitor_gui_screenshot`.
