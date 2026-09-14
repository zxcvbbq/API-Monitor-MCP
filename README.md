# Rohitab API Monitor MCP

MCP bridge for the installed Rohitab API Monitor on Windows.

## Install

### Codex

```powershell
codex plugin marketplace add zxcvbbq/API-Monitor-MCP
codex plugin add api-monitor-mcp@api-monitor-mcp
```

### Claude Code

```powershell
claude plugin marketplace add https://github.com/zxcvbbq/API-Monitor-MCP.git
claude plugin install api-monitor-mcp@api-monitor-mcp
```

## Features

- Background GUI control, process attach, live capture/export, filters, screenshots, and capture tailing
- Read, validate, search, compare, decode, filter, IOC and behavior triage, and export `.apmx86`/`.apmx64`
- Inspect calls, statistics, API definitions and types, parameters, returns, payloads, sequences, graphs, errors, processes, modules, logs, and raw bytes

## Local

```powershell
uv run python .\server.py --self-test
uv run python .\server.py --transport streamable-http --port 8745
```

Set `APIMONITOR_HOME` if the app is installed elsewhere.
