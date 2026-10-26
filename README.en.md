# RXEngine

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-FastMCP-6f42c1.svg)](https://modelcontextprotocol.io)

English | [简体中文](README.md)

RXEngine is an MCP server for automated reverse engineering. It combines a
JavaScript sandbox with headless IDA, angr, qiling/unicorn, and Z3, so an agent
can drive the whole analysis loop from a single script: inspect, emulate,
symbolically explore, deobfuscate, and stage IDA writes.

## Why it exists

Most reverse-engineering MCP servers expose dozens of one-shot tools. That
forces an agent to glue several stateless calls together and carry intermediate
results in the conversation. RXEngine takes the opposite approach:

- **One execution entry point.** `run_js` runs a script in an isolated worker
  with `require('ida' | 'lab' | 'qiling' | 'angr' | 'z3' | ...)`.
- **Cross-run memory.** An analysis blackboard (targets, findings, traces,
  paths, hypotheses) lives in the server process and survives across `run_js`
  calls.
- **Engine composition.** `require('lab')` resolves addresses across IDA, angr,
  and qiling coordinate spaces and provides four closed loops: trace, emulate,
  deobfuscate, and path-follow.
- **Staged writes.** IDA mutations are staged, previewed, and explicitly
  committed. Nothing touches the database until you say so.

## Architecture

```text
MCP client
   │  run_js / set_binary_path / engine_status / read-only IDA tools
   ▼
FastMCP parent process
   ├─ SessionManager        per-connection EngineSession (binary, IDA, board)
   ├─ IDAFacade             staged writes, preview/commit/undo
   ├─ AnalysisBoard         cross-run analysis memory
   └─ SandboxSupervisor     worker lifecycle, Pipe RPC, timeout/orphan handling
          │
          ▼
   worker process (kept warm, recycled on timeout/crash/session switch)
   ├─ STPyV8                JavaScript runtime
   ├─ require('lab')        address anchoring + four scenario loops
   └─ qiling / angr / z3    local engines, proxied IDA calls over RPC
```

The worker is reused between calls so heavy imports (`angr`, `qiling`, `z3`)
happen once. It is destroyed and rebuilt after a timeout, a native crash, or a
binary/session switch. Analysis sessions are isolated per MCP connection; a
single fallback session serves stdio and internal calls.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Requirements

- Python `>=3.10,<3.14`
- IDA Pro / IDA Home with a working headless executable (`idat.exe` or the
  platform equivalent)
- Windows is verified; Linux/macOS should work if IDA, STPyV8, and the analysis
  dependencies are available

## Install

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # then set IDA_PATH
python main.py
```

Or install as a package:

```bash
pip install -e .
rxengine --transport sse
```

## MCP tools

The tool surface is intentionally small: 9 tools and 2 prompts.

| Tool | Purpose |
| --- | --- |
| `run_js` | Execute JavaScript in the sandbox; the main entry point for all analysis |
| `set_binary_path` | Load a binary or IDA database and start a session |
| `open_ida_database` | Open an existing `.idb` / `.ida` / `.i64` |
| `engine_status` | Session, modules, dependencies, blackboard, sandbox and limits |
| `engine_diagnostics` | Health and readiness report |
| `decompile_function` / `decompile_checked` | Fast read-only decompilation |
| `disassemble_function` | Fast read-only disassembly |
| `get_entry_points` | Entry point list |

`run_js` accepts `structured=True` to return a machine-readable result:
`{ok, text, result, error, traceback, run_id, generation, session_id, phase,
timeout_s}`. The default remains the historical text form.

## Example

```js
var lab = require('lab');

// Resolve an IDA address and trace it with unicorn
var t = lab.target('pre_c_init');
var tr = lab.trace(t.ea, {max_steps: 2000});

// Rule out an opaque predicate with Z3, optionally confirmed concretely
var verdict = lab.solve_branch(0x140001026, {concrete: true});

// Concrete prefix -> symbolic exploration -> model -> concrete verification
var seed = lab.concrete_prefix(t.ea, {stop_at: 0x140001100});
var path = lab.follow(t.ea, {
  goal: [0x1400012a0],
  seed_regs: seed.regs,
  verify_concrete: true
});

// Stage a comment, review, then commit
lab.annotate(t.ea, 'entry: checked by RXEngine');
log(JSON.stringify(lab.preview()));
lab.commit();
```

## Testing

```bash
# Offline unit tests (IDA tests deselected by default)
python -m pytest -q

# Real IDA integration tests
python -m pytest -o addopts="" -m requires_ida -q

# SSE end-to-end (start the server first)
python main.py --transport sse
python -m pytest -o addopts="" test_sse_client.py -q
```

Real-IDA tests need a local sample binary. Place it at `sample.exe` in the repo
root or point `RXENGINE_SAMPLE` at another path; the tests are skipped when it
is absent.

## Production notes

RXEngine is designed as a local, controlled analysis tool. Before exposing it
to a network or a multi-user environment, add authentication, resource quotas,
audit logging, task isolation, and broader automated tests.

Do not commit analysis artifacts: `.env`, `.venv/`, `*.log`, IDA databases
(`*.idb`, `*.i64`, ...), `artifacts/`, and sample binaries.

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Report security issues privately as described in [SECURITY.md](SECURITY.md).
- Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Copyright 2026 liankong <xhsw.new@qq.com>.

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party
dependencies remain under their respective licenses; see [NOTICE](NOTICE).
IDA Pro is a commercial product of Hex-Rays SA. RXEngine only invokes a locally
installed headless IDA; you are responsible for holding a valid IDA license.
