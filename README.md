# Rohitab API Monitor MCP

MCP bridge for the installed Rohitab API Monitor app.

Features:

- Launch/status, process monitoring, and background GUI inspection/actions
- Open and inspect `.apmx86`/`.apmx64` captures
- List/search captures, strings, ZIP entries, and raw hex
- Search Rohitab XML API definitions

Run:

```powershell
uv run --with mcp python .\server.py
uv run --with mcp python .\server.py --self-test
```

Set `APIMONITOR_HOME` if the app is installed elsewhere.
