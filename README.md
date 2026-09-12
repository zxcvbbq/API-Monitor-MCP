# Rohitab API Monitor MCP

MCP bridge for the installed Rohitab API Monitor app.

Features:

- Launch/status, process attach, native filter-tree inspection, and background GUI actions
- Open, validate, decode, search, inspect, and export `.apmx86`/`.apmx64` captures
- Inspect/search capture ZIPs, XML filters, logs, process metadata/modules, strings, and raw hex
- Search Rohitab XML API definitions

Install:

```powershell
claude plugin marketplace add zxcvbbq/API-Monitor-MCP
claude plugin install api-monitor-mcp@api-monitor-mcp
codex plugin marketplace add zxcvbbq/API-Monitor-MCP
codex plugin add api-monitor-mcp@api-monitor-mcp
```

Run locally:

```powershell
uv run python .\server.py
uv run python .\server.py --self-test
```

Set `APIMONITOR_HOME` if the app is installed elsewhere.
