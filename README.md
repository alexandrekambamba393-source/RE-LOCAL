# REA (local)

A local reverse-engineering helper with a terminal CLI and an MCP server for agents. You ask a question
about an app or binary, and REA returns a cited report: the evidence it found, where it found it, and
what it could not check. Everything runs on your machine. REA makes no network calls and never runs the
target.

REA gathers evidence. The explanation of how a feature works is written by the agent (or you) after
reading that evidence. REA does not run a language model.

## What works today

| Target | Capabilities |
|---|---|
| ELF, PE, Mach-O binaries | file type, embedded strings search, symbol search, section list, .NET marker detection |
| JavaScript folders | term search with line numbers, route-literal candidates, network and IPC call-site counts |
| Electron folders | same as JavaScript, plus `ipcMain.handle` / `ipcRenderer.invoke` detection. Packed `app.asar` is reported, not extracted |
| Android APKs | archive layout, dex file list, entry-name search |

**Not built yet** (the diagram's other branches): disassembly and decompilation, Ghidra/IDA/Hopper/Cutter
bridges, GDB debug sessions, Frida instrumentation, browser capture and scenarios, screenshots, asar
extraction, APK dex decompilation, and computer control. Where a capability is missing, the report says so
in its Limitations section instead of guessing.

## Install

Requirements: Python 3.10 or newer. Optional binutils (`file`, `strings`, `nm`, `objdump`) add capabilities.
Nothing is downloaded.

```bash
cd rea-local
python3 -m rea --help            # runs straight from the folder, no install needed
# or, if pip is allowed on your machine:
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

## Guided setup

```bash
rea setup --dry-run                     # show what would change; changes nothing
rea setup --allow ~/work/app-under-test # the folder(s) REA may investigate
rea setup                               # shows the plan and asks "Apply this plan? [y/N]"
rea setup --yes                         # apply without asking (scripts)
```

Setup checks which optional tools exist, writes `config.json` under REA home, writes an example MCP client
entry, and logs the run. It never edits your agent client's configuration. Rerun it any time; it keeps
your existing allowed folders and limits. REA home defaults to `~/.rea` and can be moved with `REA_HOME`.

To see what happened:

```bash
rea doctor          # tools, allowed folders, history count
rea logs            # list setup logs
rea logs --last     # print the latest setup log
```

## Investigate

```bash
rea investigate ./Some.app/Contents/MacOS/Some -q "How does search work?"
rea investigate ~/work/electron-app -q "where is the export button handled?"
rea history
rea show inv-20261114-205100-a3f1
rea delete inv-20261114-205100-a3f1 --yes
```

Each investigation gets its own folder with `report.md` and `evidence.json`, and a row in
`history.sqlite3`. Evidence refs (E1, E2, ...) are stable inside a report, so you can cite them.

## Use from an agent (MCP)

Run `rea mcp` as a stdio server. The example entry in `~/.rea/mcp-client-config.json` shows the command
and working directory. Copy its `mcpServers.rea` block into your client's MCP settings.

Tools: `rea_doctor`, `rea_investigate`, `rea_list_investigations`, `rea_get_report`.

`rea_investigate` is refused until you have allowed at least one folder with `rea setup --allow`, so an
agent cannot point REA at arbitrary files on your machine.

## Safety model

- **Local only.** REA opens no sockets. Its external tools run locally.
- **No execution of targets.** Binaries are parsed by `file`, `strings`, `nm`, and `objdump`. Scripts
  are read as text and never run.
- **No shell.** Tools run from fixed argument lists with absolute paths, so a file name cannot inject
  flags or commands.
- **Bounded work.** Each tool call has a timeout, output is capped, and oversized source files are skipped
  and counted.
- **Allowlist.** Investigations are confined to allowed folders when any are configured. MCP requires them.
- **Safe deletes.** `rea delete` only removes folders directly inside `investigations/` with a valid ID.

## Layout

```
rea/
  cli.py              terminal commands
  mcp_server.py       MCP stdio server (rea_* tools)
  setup_flow.py       guided setup, doctor
  investigate.py      routing, cited reports, history helpers
  static_analysis.py  identify targets; binary, JS/Electron, APK capabilities
  evidence.py         evidence records and limitations
  store.py            SQLite history
  tools_probe.py      optional tool detection
  subproc.py          safe external command runner
  config.py, paths.py configuration and state locations
tests/test_rea.py     standard-library tests
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
