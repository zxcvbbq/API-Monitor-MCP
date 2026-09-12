# Rohitab API Monitor MCP

Bare-bones, read-only MCP bridge for the real Rohitab API Monitor installation.

Current scope:

- launch and inspect the installed x86/x64 API Monitor processes;
- open `.apmx86`/`.apmx64` captures in the real application;
- inspect the capture container and ZIP entries;
- list and search capture files across a directory;
- extract/search printable ANSI and UTF-16LE strings;
- read bounded ZIP entries and raw hex ranges;
- search the installed Rohitab XML API definitions.

This version intentionally does not reverse engineer live IPC or decode APMX API-call records. Those are the next layer.

## Run

```powershell
uv run --with mcp python .\server.py
```

Self-check:

```powershell
uv run --with mcp python .\server.py --self-test
```

Optional installation override:

```powershell
$env:APIMONITOR_HOME = 'C:\Program Files\rohitab.com\API Monitor'
```

Example MCP configuration:

```json
{
  "mcpServers": {
    "rohitab-api-monitor": {
      "command": "uv",
      "args": ["run", "--directory", "E:\\Work\\api", "python", "server.py"]
    }
  }
}
```
