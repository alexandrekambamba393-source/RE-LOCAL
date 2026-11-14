# RE LOCAL (local)

A local reverse-engineering helper with a terminal CLI and an MCP server for agents. You ask a question about
an app or binary, or ask for a security audit or a comparison of two versions, and RE LOCAL returns a cited report:
the evidence it found, where it came from, and what it could not check. Everything runs on your machine.
RE LOCAL makes no network calls and never runs the target.

RE LOCAL gathers evidence. The explanation of how a feature works is written by the agent (or you) after reading
that evidence. RE LOCAL does not run a language model.

## Commands

| Command | What it does |
|---|---|
| `relocal setup` | Detect optional tools, show a plan, ask before changing anything. Safe to rerun. |
| `relocal doctor` | Show tools, sandbox status, allowed folders, and history count. |
| `relocal investigate <target> -q "..."` | Answer a question about a file or folder, with cited evidence. |
| `relocal audit <target>` | Flag common security risks, each with a severity and evidence refs. |
| `relocal diff <old> <new>` | Compare two versions and report only what changed. |
| `relocal history` / `relocal show <id>` / `relocal delete <id>` | Browse, print, or remove past runs. |
| `relocal logs [--last]` | List setup logs, or print the latest. |
| `relocal mcp` | Run the MCP server on stdio for agent clients. |

Common flags on `investigate`, `audit`, and `diff`: `--export-graph` and `--sandbox`. `audit` also takes
`--min-severity` (CRITICAL, HIGH, MEDIUM, INFO), and every run command takes `--json`.

## Install

Requirements: Python 3.10 or newer. Optional tools add capabilities (see below). Nothing is downloaded.

```bash
cd "RE LOCAL"
python3 -m relocal --help            # runs straight from the folder, no install needed
# or, if pip is allowed on your machine:
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

## Guided setup

```bash
relocal setup --dry-run                      # show the plan; changes nothing
relocal setup --allow ~/work/app-under-test  # folder(s) RE LOCAL may investigate
relocal setup                                # shows the plan and asks "Apply this plan? [y/N]"
relocal setup --yes                          # apply without asking (scripts)
relocal doctor
```

Setup records which optional tools it found, writes `config.json` under RE LOCAL home (`~/.relocal` by default,
or `RELOCAL_HOME`), writes an example MCP client entry, and logs the run. It never edits your agent client's
configuration. Rerunning keeps your allowed folders and limits.

## Optional tools

RE LOCAL uses whatever is installed and says in each report what it could not run.

| Tool | Used for | Status |
|---|---|---|
| `file`, `strings`, `nm`, `objdump` | file type, embedded text, symbols, sections | used |
| `readelf` | ELF protections: PIE, NX, RELRO, stack canary | used by `audit` |
| `rabin2` (radare2) or `rz-bin` (rizin) | imports, exports, sections in JSON; enriches `investigate` and `audit` | used when present |
| `analyzeHeadless` (Ghidra) | detected only | not run; it needs a project and script |
| `bwrap` (Bubblewrap) or `firejail` | sandbox for `--sandbox` | used when present and working |
| `jadx`, `gdb`, `node` | reserved for future capabilities | detected only |

## Investigate

```bash
relocal investigate ./Some.app/Contents/MacOS/Some -q "How does search work?"
relocal investigate ~/work/electron-app -q "where is the export button handled?" --export-graph
```

Searches for the words in your question across embedded strings, symbol names, JS source, and APK entries.
Each hit is a lead, not an explanation.

## Audit

```bash
relocal audit ~/work/electron-app
relocal audit ./server-binary --min-severity HIGH
relocal audit ./app-release.apk --export-graph --json
```

Rules and what they check:

**JavaScript and Electron** (JS-001 to JS-009):
- `nodeIntegration: true` (CRITICAL)
- `contextIsolation: false` (HIGH)
- raw `ipcRenderer` exposed through `contextBridge` in a preload file (HIGH)
- IPC channel name that is not a fixed string, in preload files (HIGH)
- embedded private keys (CRITICAL), AWS key IDs (HIGH), and generic hard-coded secrets (MEDIUM)
- `eval()` on a non-literal value (HIGH)
- `exec()` on a non-literal value in files that use `child_process` (HIGH)

**Native ELF and PE** (NAT-001 to NAT-005):
- stack not non-executable, from NX / `GNU_STACK` (HIGH). PE: `NX_COMPAT` missing
- not built as PIE (MEDIUM). PE: ASLR (`DYNAMIC_BASE`) disabled
- no stack canary, a heuristic based on the `__stack_chk_fail` import (MEDIUM)
- RELRO: none (MEDIUM), partial (INFO)
- imported unsafe functions: `gets` (HIGH); `strcpy`, `strcat`, `sprintf`, `vsprintf` (MEDIUM)

**Android APK** (APK-001 to APK-005):
- `android:debuggable="true"` (HIGH)
- `android:usesCleartextTraffic="true"` (HIGH)
- `android:allowBackup="true"` (MEDIUM)
- sensitive permissions such as `CAMERA` or `READ_SMS` (INFO)
- cleartext `http://` URLs in dex string constants (MEDIUM). Localhost and schema URLs are ignored.

Secrets are masked in every excerpt and in the report. Findings do not prove exploitability. Confirm each one in code.

## Diff (patch comparison)

```bash
relocal diff ./app-1.4 ./app-1.5
relocal diff ./weak-v1 ./weak-v2 --export-graph
```

Compares two versions of the same kind of target:
- **Folders:** added, removed, and changed files (SHA-256), plus route literals and IPC/network call-site counts for JS and Electron.
- **Binaries:** SHA-256, plus strings, symbol names, and section names.
- **APKs:** archive entries (CRC), dex string constants, and manifest flags and permissions.

Mixing kinds, such as a folder against an APK, is refused. Diffs of compiled binaries are noisy: linker
strings change between builds, so read them as leads.

## Evidence graph (`--export-graph`)

Writes two files into the run folder:
- `graph.mmd`: a Mermaid `flowchart TD` from the target to the modules it touched, to evidence refs (E1, E2...), to findings.
- `graph.html`: a standalone page. It always includes a pure-SVG view that works offline. If Mermaid.js loads from its CDN, the page switches to the Mermaid rendering.

Every string from the target is HTML-escaped, so a file name or string cannot inject markup or script.
Existing runs can be exported later: `relocal show <id> --export-graph`.

## Sandbox (`--sandbox`)

```bash
relocal investigate ./unknown-tool -q "what does it read?" --sandbox
```

When `bwrap` or `firejail` is installed and actually runs a trivial command, RE LOCAL wraps its external tools:
- read-only filesystem (`--ro-bind /` for Bubblewrap)
- no network (`--unshare-net`, or `--net=none` for firejail)
- one private scratch folder, removed after the run

If neither works, RE LOCAL still runs its static tools (the target is never executed either way). The report
states in Limitations that the sandbox was unavailable. `relocal doctor` shows which sandbox is active.

## Use from an agent (MCP)

Run `relocal mcp` as a stdio server. Copy the `mcpServers.relocal` block from `~/.relocal/mcp-client-config.json`
into your client's MCP settings.

| Tool | Purpose |
|---|---|
| `relocal_doctor` | tools, sandbox, allowed folders |
| `relocal_investigate` | question about a target (`export_graph`, `sandbox` optional) |
| `relocal_audit` | security rules (`min_severity`, `export_graph`, `sandbox` optional) |
| `relocal_diff` | compare two versions (`export_graph`, `sandbox` optional) |
| `relocal_list_investigations` | recent runs |
| `relocal_get_report` | full report for a run |

Every tool that reads a target is refused until you allow a folder with `relocal setup --allow`.

## Safety model

- **Local only.** RE LOCAL opens no network sockets. Its external tools run locally.
- **No execution of targets.** Binaries are parsed by read-only tools. Scripts are read as text and never run.
- **No shell.** Tools run from fixed argument lists with absolute paths, so file names cannot inject flags or commands.
- **Bounded work.** Each tool call has a timeout, output is capped, and oversized files are skipped and counted.
- **Allowlist.** Investigations are confined to allowed folders when any are configured. MCP requires them.
- **Sandbox, opt-in.** `--sandbox` adds a read-only, no-network wrapper when a working sandbox tool exists.
- **Secret masking.** Hard-coded secrets are redacted in excerpts, the report, and the graph.
- **Safe deletes.** `relocal delete` only removes folders directly inside `investigations/` with a valid ID.

## Layout

```
relocal/
  cli.py              terminal commands
  mcp_server.py       MCP stdio server
  setup_flow.py       guided setup, doctor
  investigate.py      pipelines for investigate, audit, diff; reports; history
  static_analysis.py  identify targets; binary, JS/Electron, APK capabilities
  audit.py            security rules (JS, native, APK) with severities
  diffing.py          version comparison
  graph.py            Mermaid, SVG, and HTML evidence graphs
  native_tools.py     readelf/objdump/nm checks; rabin2/rizin JSON extraction
  apk_format.py       dex string table and Android binary XML parsers
  sandbox.py          bubblewrap/firejail detection and command wrapping
  runner.py           single gateway for external tools
  evidence.py         evidence records and limitations
  store.py            SQLite history with migration
  tools_probe.py      optional tool detection
  subproc.py          safe subprocess wrapper
  config.py, paths.py configuration and state locations
tests/
  helpers.py          synthetic APK/dex/AXML builders, fake runner
  test_relocal.py         original v0.1 tests
  test_audit.py       audit rules (JS, native, APK)
  test_diff_and_graph.py
  test_sandbox_store_cli.py
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite uses only the standard library. It builds synthetic APKs, dex files, and manifests, and uses a fake
tool runner for readelf output. Tests that need a real tool (`strings`) run when it is installed.

**Not exercised on the machine where v0.2 was built:** `bwrap`, `firejail`, `rabin2`, `rz-bin`, and a live
Mermaid CDN load. Their command construction and output parsing are unit-tested, but the real tools were not run.
Protection checks, string and symbol diffs, and the offline SVG were verified against real binaries built with GCC.
