# RXEngine Lab 编排层 + MCP 收敛 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 `require('lab')` 组合原语层（跨引擎锚点 + 父进程分析黑板 + 四场景闭环），并把 MCP 面从 53 个工具收敛到 9 个。

**Architecture:** worker 侧 `LabFacade` 组合本地 qiling/angr/z3ida/deobfuscation 门面、经 RPC 操作父进程 `IDAFacade`；分析记忆存父进程 `AnalysisBoard`（新 RPC root `board`，挂 `EngineSession`，跨 `run_js` 存活、随二进制切换重建）。不新增 RPC 操作类型，不引入双向 RPC。

**Tech Stack:** Python 3.10–3.13、FastMCP、STPyV8、qiling/unicorn、angr、z3、headless-ida（rpyc）、pytest。

**Spec:** `docs/superpowers/specs/2026-09-11-rxengine-lab-orchestration-design.md`

## Global Constraints

- 工作分支：`feature/lab-orchestration`（已存在，含此前沙箱 RPC 修复）。
- 测试命令：`.venv/Scripts/python.exe -m pytest`（默认 addopts 已排除 `requires_ida/sse/slow`）；真实 IDA 用 `.venv/Scripts/python.exe -m pytest <file> -o addopts=""`。
- 写回一律 staged-only；`commit` 仅显式调用。
- 不修改 `sandbox/supervisor.py` 的 RPC 协议；不新增 RPC 操作类型。
- 沙箱内 `require(...)` 的下划线私有属性屏蔽、远程集合分页、引用可调用提示保持不变。
- 每个任务以独立可测的交付物结束并提交；提交信息用中文。
- `run_js` 单轮超时默认 30s/上限 300s，Lab recipe 必须自带 `timeout`/`max_steps` 预算。

## File Structure

| 文件 | 动作 | 职责 |
| --- | --- | --- |
| `extensions/lab_board.py` | 新增 | `AnalysisBoard` 父进程黑板（纯数据、RPC 友好） |
| `extensions/lab_ext.py` | 新增 | `LabFacade`、`LabEmulator`、锚点数学、trace 归约、rxstubs 辅助 |
| `headless_ida_mcp_server/ida_facade.py` | 修改 | parity：`function_info`/`decompile`/`disassemble`/`get_entry_points`/`prepare_decompile`/`arch_info` |
| `extensions/qiling_ext.py` | 修改 | 公开 `map_idb_segments(ql, opts)` |
| `extensions/__init__.py` | 修改 | `register(registry, ida=None, board=None)`，注册 `lab`/`board` |
| `sandbox/worker.py` | 修改 | 读取 `board_bound`，注入 `board` root |
| `headless_ida_mcp_server/server.py` | 修改 | session.board、roots、engine_* 合并、删 44 工具、4 只读工具改 facade |
| `test_lab_board.py`、`test_lab_anchor.py`、`test_lab_ext.py`、`test_lab_wiring.py`、`test_mcp_surface.py` | 新增 | 离线测试 |
| `test_real_ida.py` | 修改 | parity + Lab 工作流 + 跨轮黑板 |
| `test_sse_client.py`、`test_merge.py`、`test_rxstubs_server.py` | 修改 | 适配收敛后的工具面 |
| `docs/prompt.md`、`README.md` | 修改 | 沙箱闭环优先的 agent 指引 |

---

### Task 1: AnalysisBoard 黑板

**Files:**
- Create: `extensions/lab_board.py`
- Test: `test_lab_board.py`

**Interfaces:**
- Produces: `AnalysisBoard(session_id=None, limits=None, artifact_dir="artifacts")`，方法 `add_target(**fields)`、`add_finding(kind, ea, text, evidence=None, severity="info", action=None, target_id=None)`、`add_trace(**fields)`、`add_path(**fields)`、`add_hypothesis(**fields)`、`add_patch(**fields)`、`get(kind, item_id)`、`list(kind, where=None, limit=200)`、`attach(kind, item_id, **fields)`、`delete(kind, item_id)`、`clear(kind=None)`、`counts()`、`summary()`、`save_snapshot(path)`、`load_snapshot(path)`、`artifact(name, content)`；异常 `LabBoardError`/`LabBoardOverflow`；`cap_list(seq, limit)`。

- [ ] **Step 1: 写失败测试**

```python
# test_lab_board.py
# -*- coding: utf-8 -*-
import pytest

from extensions.lab_board import AnalysisBoard, LabBoardOverflow


@pytest.mark.unit
def test_board_roundtrip_and_attach():
    board = AnalysisBoard(session_id="s1")
    t = board.add_target(kind="func", ea=0x1000, name="main",
                         start_ea=0x1000, end_ea=0x1100, size=0x100)
    f = board.add_finding("opaque_predicate", 0x1010, "always true",
                          evidence={"x": 1}, target_id=t["id"])
    assert f["id"].startswith("finding-")
    assert board.get("finding", f["id"])["kind"] == "opaque_predicate"
    assert board.list("finding", target_id=t["id"])[0]["id"] == f["id"]
    board.attach("finding", f["id"], evidence_id="trace-00001")
    assert board.get("finding", f["id"])["evidence_id"] == "trace-00001"
    assert board.summary()["counts"]["finding"] == 1


@pytest.mark.unit
def test_board_where_filter_and_missing():
    board = AnalysisBoard(session_id="s1")
    board.add_finding("opaque_predicate", 0x1, "a")
    board.add_finding("constant_fold", 0x2, "b")
    only = board.list("finding", where={"kind": "constant_fold"})
    assert [i["ea"] for i in only] == [0x2]
    with pytest.raises(Exception):
        board.get("finding", "finding-99999")


@pytest.mark.unit
def test_board_entity_limit_overflow():
    board = AnalysisBoard(session_id="s2", limits={"entities": 3})
    for i in range(3):
        board.add_finding("k", i, "x")
    with pytest.raises(LabBoardOverflow):
        board.add_finding("k", 9, "y")
    assert board.summary()["overflow"] is True
    board.clear("finding")
    assert board.counts()["finding"] == 0


@pytest.mark.unit
def test_board_snapshot_roundtrip(tmp_path):
    board = AnalysisBoard(session_id="s3")
    board.add_finding("k", 0x10, "hello")
    path = tmp_path / "snap.json"
    board.save_snapshot(str(path))
    other = AnalysisBoard(session_id="s4")
    other.load_snapshot(str(path))
    assert other.counts()["finding"] == 1
    assert other.list("finding")[0]["text"] == "hello"


@pytest.mark.unit
def test_board_artifact_writes_file(tmp_path):
    board = AnalysisBoard(session_id="s5", artifact_dir=str(tmp_path))
    out = board.artifact("strings main", "a,b,c")
    assert out["ok"] is True
    assert (tmp_path / out["path"].replace("\\", "/").split("/")[-1]).read_text() == "a,b,c"
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_lab_board.py -q`
Expected: FAIL（`ModuleNotFoundError: extensions.lab_board`）

- [ ] **Step 3: 实现 `extensions/lab_board.py`**

```python
# -*- coding: utf-8 -*-
"""分析黑板：跨 run_js 持久化的分析记忆。

父进程对象，只保存可序列化数据；方法只收发原始类型/dict，便于经 RPC 暴露。
随 EngineSession 创建/重建：换二进制即换黑板。
"""
import json
import os
import time
from uuid import uuid4

DEFAULT_LIMITS = {
    "entities": 5000,
    "artifact_max_chars": 2_000_000,
}

_KINDS = ("target", "finding", "trace", "path", "hypothesis", "patch")


class LabBoardError(RuntimeError):
    pass


class LabBoardOverflow(LabBoardError):
    pass


def cap_list(seq, limit):
    seq = list(seq or [])
    return seq[: int(limit)], len(seq) > int(limit)


class AnalysisBoard:
    def __init__(self, session_id=None, limits=None, artifact_dir="artifacts"):
        self.session_id = session_id or uuid4().hex
        self.limits = dict(DEFAULT_LIMITS)
        if limits:
            self.limits.update({k: int(v) for k, v in limits.items()})
        self.artifact_dir = artifact_dir
        self._seq = 0
        self._items = {kind: {} for kind in _KINDS}
        self.overflow = False

    def _next_id(self, kind):
        self._seq += 1
        return f"{kind}-{self._seq:05d}"

    def _put(self, kind, item):
        if len(self._items[kind]) >= self.limits["entities"]:
            self.overflow = True
            raise LabBoardOverflow(
                f"blackboard entity limit reached: {self.limits['entities']}")
        record = dict(item or {})
        record["id"] = record.get("id") or self._next_id(kind)
        record["kind"] = kind
        record["created_at"] = time.time()
        record["session_id"] = self.session_id
        self._items[kind][record["id"]] = record
        return dict(record)

    def add_target(self, **fields):
        return self._put("target", fields)

    def add_finding(self, kind, ea, text, evidence=None, severity="info",
                    action=None, target_id=None):
        return self._put("finding", {"kind": str(kind), "ea": int(ea), "text": str(text),
                                     "evidence": dict(evidence or {}),
                                     "severity": str(severity), "action": action,
                                     "target_id": target_id})

    def add_trace(self, **fields):
        return self._put("trace", fields)

    def add_path(self, **fields):
        return self._put("path", fields)

    def add_hypothesis(self, **fields):
        return self._put("hypothesis", fields)

    def add_patch(self, **fields):
        return self._put("patch", fields)

    def get(self, kind, item_id):
        item = self._items.get(kind, {}).get(str(item_id))
        if item is None:
            raise LabBoardError(f"not found: {kind}/{item_id}")
        return dict(item)

    def list(self, kind, where=None, limit=200):
        where = dict(where or {})
        out = []
        for item in self._items.get(kind, {}).values():
            if all(item.get(k) == v for k, v in where.items()):
                out.append(dict(item))
        return out[: int(limit)]

    def attach(self, kind, item_id, **fields):
        item = self._items.get(kind, {}).get(str(item_id))
        if item is None:
            raise LabBoardError(f"not found: {kind}/{item_id}")
        item.update(fields)
        return dict(item)

    def delete(self, kind, item_id):
        return self._items.get(kind, {}).pop(str(item_id), None) is not None

    def clear(self, kind=None):
        for k in ([kind] if kind else list(_KINDS)):
            self._items[k] = {}

    def counts(self):
        return {k: len(v) for k, v in self._items.items()}

    def summary(self):
        return {"session_id": self.session_id, "counts": self.counts(),
                "overflow": self.overflow, "limits": dict(self.limits)}

    def save_snapshot(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = {"session_id": self.session_id, "saved_at": time.time(),
                   "items": {k: list(v.values()) for k, v in self._items.items()}}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        return {"ok": True, "path": path, "counts": self.counts()}

    def load_snapshot(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        self.clear()
        for kind, items in (payload.get("items") or {}).items():
            if kind not in self._items:
                continue
            for item in items:
                record = dict(item)
                record.setdefault("id", self._next_id(kind))
                self._items[kind][record["id"]] = record
        return {"ok": True, "path": path, "counts": self.counts()}

    def artifact(self, name, content):
        content = str(content)
        if len(content) > self.limits["artifact_max_chars"]:
            raise LabBoardError("artifact too large")
        os.makedirs(self.artifact_dir, exist_ok=True)
        safe = "".join(c for c in str(name) if c.isalnum() or c in "._-") or "artifact"
        path = os.path.join(self.artifact_dir, f"{int(time.time())}-{safe}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return {"ok": True, "path": path, "chars": len(content)}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_lab_board.py -q`
Expected: 5 passed

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_board.py test_lab_board.py
git commit -m "feat: 新增父进程分析黑板 AnalysisBoard"
```

---

### Task 2: 黑板接线（session/roots/worker/register）

**Files:**
- Modify: `headless_ida_mcp_server/server.py:22-48`（EngineSession、_sandbox_roots）
- Modify: `sandbox/worker.py:9-30`
- Modify: `extensions/__init__.py:24-48`
- Create: `test_lab_wiring.py`

**Interfaces:**
- Consumes: Task 1 的 `AnalysisBoard`
- Produces: `EngineSession.board: AnalysisBoard`；`_sandbox_roots()` 返回含 `"board"`；`extensions.register(registry, ida=None, board=None)` 注册 `require('board')`/`require('lab')`（本任务 LabFacade 先用最小骨架，Task 4 补全）；worker 请求字段 `board_bound: bool`。

- [ ] **Step 1: 写失败测试**

```python
# test_lab_wiring.py
# -*- coding: utf-8 -*-
import pytest

from extensions.lab_board import AnalysisBoard
from sandbox.supervisor import SandboxSupervisor
from test_lab_ext import FakeIDAFacade


@pytest.mark.sandbox
def test_board_and_lab_roots_reachable_in_worker():
    roots = {"ida": FakeIDAFacade(), "raw_ida": object(),
             "board": AnalysisBoard(session_id="w1")}
    sup = SandboxSupervisor(lambda: roots)
    out = sup.run("require.list().indexOf('lab') >= 0 && require.list().indexOf('board') >= 0",
                  timeout=120)
    assert out.rstrip().endswith("=> true")
    out = sup.run("'' + require('board').summary().session_id", timeout=60)
    assert "w1" in out


@pytest.mark.sandbox
def test_board_absent_without_root():
    sup = SandboxSupervisor(lambda: {"ida": FakeIDAFacade(), "raw_ida": object()})
    out = sup.run("require.list().indexOf('board') < 0", timeout=120)
    assert out.rstrip().endswith("=> true")
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_lab_wiring.py -q`
Expected: FAIL（`test_lab_ext` 不存在 / `board` 未注册）

- [ ] **Step 3: 先落最小 `extensions/lab_ext.py` 骨架（Task 4 会补全）**

```python
# extensions/lab_ext.py（本任务的最小骨架）
# -*- coding: utf-8 -*-
"""Lab 组合原语层：跨引擎锚点 + 分析黑板 + IDA/Angr/Unicorn 组合。

worker 本地对象：构造时不做 RPC；引擎活对象仅在一轮 run_js 内有效。
"""


class LabError(Exception):
    pass


class LabFacade:
    def __init__(self, ida=None, board=None):
        self._ida = ida
        self._board = board
```

- [ ] **Step 4: 接线**

`headless_ida_mcp_server/server.py`：

```python
# EngineSession（约 22-31 行）
from extensions.lab_board import AnalysisBoard


@dataclass
class EngineSession:
    session_id: str = field(default_factory=lambda: uuid4().hex)
    binary_path: Optional[str] = None
    ida: Optional[IDA] = None
    ida_facade: Optional[IDAFacade] = None
    registry: Registry = field(default_factory=Registry)
    board: AnalysisBoard = field(default_factory=AnalysisBoard)
```

```python
# _sandbox_roots()（约 41-46 行）
def _sandbox_roots():
    session = _session()
    if session.ida is None or session.ida_facade is None:
        return {}
    return {"ida": session.ida_facade, "raw_ida": session.ida, "board": session.board}
```

```python
# register() 里（约 271 行）
    extensions.register(_session().registry, board=_session().board)
```

```python
# _new_ida_session() 里（约 100 行）
            extensions.register(session.registry, ida=ida, board=session.board)
```

`sandbox/worker.py` 的 `run_worker`：

```python
        client = WorkerRPCClient(connection, request["run_id"], request["generation"])
        registry = Registry()
        raw_ida = client.root("raw_ida") if request["ida_bound"] else None
        board = client.root("board") if request.get("board_bound") else None
        register(registry, ida=raw_ida, board=board)
```

`sandbox/supervisor.py` 的 `run()` 请求 dict 增加一行：

```python
                "ida_bound": "ida" in roots and "raw_ida" in roots,
                "board_bound": "board" in roots,
```

`extensions/__init__.py`：

```python
from extensions.lab_ext import LabFacade


def register(registry, ida=None, board=None):
    """把分析扩展注册进给定沙箱注册表（可重复调用，后注册覆盖）。"""
    registry.register("rxstubs", _js_module("rxstubs.js"))
    if board is not None:
        registry.register("board", board)
    registry.register("lab", LabFacade(ida=ida, board=board))
    # ……其余注册保持不变（qiling/angr/deobfuscation/elf/...）……
```

- [ ] **Step 5: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_lab_wiring.py -q`
Expected: FAIL 仍缺 `test_lab_ext.FakeIDAFacade` → 与 Task 4 的 Step 1 一起补；本任务至少保证 import 无错。

- [ ] **Step 6: 提交（与 Task 4 的 Step 1 同分支推进时再跑绿）**

```bash
git add extensions/lab_ext.py extensions/__init__.py sandbox/worker.py sandbox/supervisor.py headless_ida_mcp_server/server.py test_lab_wiring.py
git commit -m "feat: 黑板作为 RPC root 接入 session/worker/注册表"
```

> 注：本任务与 Task 4 的 `FakeIDAFacade` 有依赖，实施时可先做 Task 4 Step 1（FakeIDAFacade），再回头跑绿本任务。

---

### Task 3: IDAFacade parity + QilingFacade 公开段映射

**Files:**
- Modify: `headless_ida_mcp_server/ida_facade.py`（文件末尾追加）
- Modify: `extensions/qiling_ext.py`（`_map_idb_segments` 旁新增公开方法）
- Modify: `test_real_ida.py`（追加测试）

**Interfaces:**
- Produces（后续 LabFacade 依赖的精确签名）:
  - `IDAFacade.function_info(ea) -> dict|None`：`{ea, start_ea, end_ea, size, name}`
  - `IDAFacade.decompile_checked(ea) -> object`（cfunc，异常抛 `IDAError`）
  - `IDAFacade.decompile(ea) -> str`
  - `IDAFacade.disassemble(ea, count=None) -> str`
  - `IDAFacade.get_entry_points() -> list[dict]`
  - `IDAFacade.prepare_decompile(**opts) -> dict`、`IDAFacade.prepare_decompile_status() -> dict`
  - `IDAFacade.arch_info() -> {proc: str, bits: int}`
  - `QilingFacade.map_idb_segments(ql, opts=None) -> list`

- [ ] **Step 1: 写失败测试（真实 IDA，追加到 `test_real_ida.py`）**

```python
def test_ida_facade_parity():
    from headless_ida_mcp_server.helper import IDAError
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    try:
        first = next(iter(ida.idautils.Functions()))
        info = facade.function_info(first)
        assert info and info["start_ea"] == int(first) and info["size"] > 0 and info["name"]
        arch = facade.arch_info()
        assert arch["bits"] in (16, 32, 64) and isinstance(arch["proc"], str)
        try:
            code = facade.decompile(info["start_ea"])
            assert isinstance(code, str) and code
        except IDAError:
            pass  # headless 无 hexrays 时跳过反编译断言
        assert facade.disassemble(info["start_ea"])
        assert isinstance(facade.get_entry_points(), list)
        assert "queue_size" in facade.prepare_decompile_status()
    finally:
        ida.close()
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_ida_facade_parity -o addopts="" -q`
Expected: FAIL（`function_info` 不存在）

- [ ] **Step 3: 实现 facade 方法（追加到 `ida_facade.py` 末尾）**

```python
    # ---- Lab parity：结构化函数信息 / 反编译 / 反汇编 / 入口点 / 预热 ----
    def function_info(self, ea):
        func = self._ida.idaapi.get_func(int(ea))
        if func is None:
            return None
        start, end = int(func.start_ea), int(func.end_ea)
        return {"ea": start, "start_ea": start, "end_ea": end,
                "size": end - start,
                "name": self._ida.ida_funcs.get_func_name(start) or ""}

    def decompile_checked(self, ea):
        return self._ida.decompile_checked(int(ea))

    def decompile(self, ea):
        return self._ida.decompile_function(int(ea))

    def disassemble(self, ea, count=None):
        text = self._ida.disassemble_function(int(ea))
        if count:
            return "\n".join(text.splitlines()[: int(count)])
        return text

    def get_entry_points(self):
        return self._ida.get_entry_points()

    def prepare_decompile(self, **opts):
        return self._ida.prepare_decompile(**opts)

    def prepare_decompile_status(self):
        return self._ida.get_prepare_decompile_status()

    def arch_info(self):
        info = self._ida.idaapi.get_inf_structure()
        bits = 64 if info.is_64bit() else (32 if info.is_32bit() else 16)
        return {"proc": str(getattr(info, "procname", "") or "").lower(), "bits": bits}
```

`extensions/qiling_ext.py`（放在 `emulate_function` 之后）：

```python
    def map_idb_segments(self, ql, opts=None):
        """按原地址把 IDB 段映射进模拟空间（公开封装，供 Lab 的交互模拟使用）。"""
        return self._map_idb_segments(ql, opts or {})
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_ida_facade_parity -o addopts="" -q`
Expected: 1 passed

- [ ] **Step 5: 提交**

```bash
git add headless_ida_mcp_server/ida_facade.py extensions/qiling_ext.py test_real_ida.py
git commit -m "feat: IDAFacade 补齐 decompile/disassemble/entry_points/prepare/arch parity"
```

---

### Task 4: LabFacade 核心（锚点/目标/写回/黑板）

**Files:**
- Modify: `extensions/lab_ext.py`（补全）
- Create: `test_lab_ext.py`

**Interfaces:**
- Consumes: Task 1 `AnalysisBoard`、Task 2 接线、Task 3 facade 方法
- Produces（后续 recipe 依赖）:
  - `LabError`、`to_angr_addr/from_angr_addr/to_ql_addr/from_ql_addr`、`parse_hex_operand`、`summarize_trace(events, limits)`
  - `LabFacade`：`_ea(x)`、`basis()`、`anchor(x)`、`target(x, opts=None)`、`_qiling_arch(opts=None)`、`_get_project(opts=None)`、`to_angr(ea, project=None)`、`from_angr(addr, project=None)`、`decompile(x)`、`disasm(x, opts=None)`、`xrefs(x)`、`bytes(x, size=None)`、`plan_emulation(x, opts=None)`、`annotate(ea, text, opts=None)`、`preview()/commit(backup=None)/discard()/undo()/save_idb(path)`、`note(kind, ea, text, opts=None)`、`findings(kind=None, target_id=None)`、`targets()/traces()/paths()/hypotheses()`、`hypothesis(ea, claim)`、`clear(kind=None)`、`save_snapshot(path)`、`load_snapshot(path)`、`artifact(name, content)`、`board_summary()`、`stage_rxstub_comments(results, opts=None)`

- [ ] **Step 1: 写失败测试（含 `FakeIDAFacade`，供多个测试文件复用）**

```python
# test_lab_ext.py
# -*- coding: utf-8 -*-
import pytest

from extensions.lab_board import AnalysisBoard
from extensions.lab_ext import (LabError, LabFacade, from_angr_addr, from_ql_addr,
                                parse_hex_operand, summarize_trace, to_angr_addr,
                                to_ql_addr)


class _NS:
    """模块命名空间替身：ida_bytes.get_bytes 这类属性链。"""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeIDAFacade:
    """离线替身：实现 LabFacade 会用到的 IDAFacade 方法子集。"""

    def __init__(self, functions=None, code=b"", image_base=0x140000000):
        self.functions = functions or {}   # start_ea -> {"start_ea","end_ea","name","size"}
        self.code = code
        self.image_base = image_base
        self.input_path = "sample.exe"
        self.comments = []
        self.renames = []
        self.staged = []
        self.ida_bytes = _NS(get_bytes=lambda ea, size: self.code[:size])
        self.idaapi = _NS(get_func=lambda ea: None)

    # 读
    def get_name_ea(self, name):
        for start, info in self.functions.items():
            if info["name"] == name:
                return start
        return (1 << 64) - 1

    def get_function_name(self, ea):
        info = self.functions.get(ea)
        return info["name"] if info else ""

    def function_info(self, ea):
        return self.functions.get(ea)

    def get_instruction_size(self, ea):
        return len(self.code)

    def get_bytes(self, ea, size):
        return self.code[:size]

    def get_imagebase(self):
        return self.image_base

    def get_input_file_path(self):
        return self.input_path

    def get_segment_name(self, ea):
        return ".text"

    def get_segments(self):
        return [0x140001000]

    def get_segment_start(self, ea):
        return 0x140001000

    def get_segment_end(self, ea):
        return 0x140001000 + len(self.code)

    def get_segment_perm(self, ea):
        return 0b101

    def get_xrefs_to(self, ea):
        return [0x140002000]

    def get_xrefs_from(self, ea):
        return []

    def arch_info(self):
        return {"proc": "metapc", "bits": 64}

    # 写（staged）
    def set_comment(self, ea, text, repeatable=False):
        self.comments.append((ea, text))
        return {"op": "set_comment", "ea": ea}

    def set_decompiler_comment(self, ea, text):
        self.comments.append((ea, text))
        return {"op": "set_decompiler_comment", "ea": ea}

    def rename(self, ea, name):
        self.renames.append((ea, name))
        return {"op": "rename", "ea": ea}

    def rename_local_variable(self, function_address, old_name, new_name):
        return {"op": "rename_local_variable"}

    def set_function_prototype(self, ea, prototype):
        return {"op": "set_function_prototype"}

    def preview(self):
        return list(self.staged)

    def commit(self, backup=None):
        return {"applied": len(self.staged)}

    def discard(self):
        return 0

    def undo(self):
        return 0

    def save_idb(self, path):
        return True

    def decompile(self, ea):
        return "int main(void) { return 0; }"

    def disassemble(self, ea, count=None):
        return f"{ea}: ret"

    def get_entry_points(self):
        return []

    def prepare_decompile(self, **opts):
        return {"ok": True}

    def prepare_decompile_status(self):
        return {"queue_size": 0}


@pytest.mark.unit
def test_anchor_math():
    assert to_angr_addr(0x14001000, 0x140000000, 0x400000) == 0x400000 + 0x1000
    assert from_angr_addr(0x401000, 0x140000000, 0x400000) == 0x14001000
    assert to_ql_addr(0x14001005, 0x14001000, 0x1000) == 0x1005
    assert from_ql_addr(0x1005, 0x14001000, 0x1000) == 0x14001005
    assert parse_hex_operand("0x140001234") == 0x140001234
    assert parse_hex_operand("rax") is None


@pytest.mark.unit
def test_summarize_trace_edges_and_hot():
    events = [
        {"ida_ea": 0x1000, "mnemonic": "mov", "op_str": "eax, 1"},
        {"ida_ea": 0x1005, "mnemonic": "call", "op_str": "0x900"},
        {"ida_ea": 0x100a, "mnemonic": "jz", "op_str": "0x1020"},
        {"ida_ea": 0x1020, "mnemonic": "ret", "op_str": ""},
    ]
    out = summarize_trace(events, {"call_edges": 10, "branch_edges": 10,
                                   "hot_eas": 2, "mem_writes": 10})
    assert out["call_edges"] == [{"ea": 0x1005, "to_ea": 0x900}]
    assert out["branch_edges"][0]["ea"] == 0x100a
    assert out["branch_edges"][0]["taken"] is True
    assert out["hot_eas"][0]["count"] == 1


def _lab(functions=None, code=b""):
    ida = FakeIDAFacade(functions=functions, code=code)
    board = AnalysisBoard(session_id="lab")
    return LabFacade(ida=ida, board=board), ida, board


@pytest.mark.sandbox
def test_anchor_target_annotate_roundtrip():
    lab, ida, board = _lab(
        functions={0x14001000: {"start_ea": 0x14001000, "end_ea": 0x14001100,
                                "name": "main", "size": 0x100}},
        code=bytes(range(0x100)))
    assert lab.anchor("main")["ea"] == 0x14001000
    t = lab.target("main", {"with_bytes": True})
    assert t["kind"] == "func" and t["bytes_hex"]
    assert board.counts()["target"] == 1
    assert lab.basis()["image_base"] == 0x140000000
    assert "main" in lab.decompile("main")
    patch = lab.annotate(0x14001000, "hello", {"kind": "disasm"})
    assert patch["op"] == "disasm" and board.counts()["patch"] == 1
    assert ida.comments == [(0x14001000, "hello")]
    assert len(lab.preview()) == 0 or isinstance(lab.preview(), list)


@pytest.mark.sandbox
def test_unknown_symbol_raises_laberror():
    lab, _, _ = _lab()
    with pytest.raises(LabError):
        lab.anchor("nope")


@pytest.mark.sandbox
def test_board_passthroughs():
    lab, _, board = _lab()
    lab.note("hypothesis", 0x10, "maybe obfuscated", {"severity": "low"})
    assert lab.findings("hypothesis")[0]["text"] == "maybe obfuscated"
    h = lab.hypothesis(0x10, "is obfuscated")
    assert h["status"] == "open"
    assert lab.artifact("demo", "x")["ok"] is True
    assert "session_id" in lab.board_summary()


@pytest.mark.sandbox
def test_stage_rxstub_comments():
    lab, ida, _ = _lab()
    out = lab.stage_rxstub_comments([{"callsiteEa": 0x14001000,
                                      "name": "java/lang/String"}], {})
    assert out["ok"] is True and len(out["staged"]) == 1
    assert ida.comments[0][1].startswith("rxstub:")
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py -q`
Expected: FAIL（`LabFacade` 缺方法）

- [ ] **Step 3: 补全 `extensions/lab_ext.py`**

在 Task 2 骨架之上补全（完整文件内容如下，`trace/emulate/deob/solve_branch/concrete_prefix/follow` 由 Task 5-8 追加）：

```python
# -*- coding: utf-8 -*-
"""Lab 组合原语层：跨引擎地址锚点 + 分析黑板 + IDA/Angr/Unicorn 组合。

worker 本地对象：构造时不做 RPC；引擎活对象仅在一轮 run_js 内有效，
跨轮记忆放父进程 AnalysisBoard（require('board')）。
"""
from extensions.angr_ext import AngrFacade
from extensions.deobfuscation_ext import DeobfuscationFacade
from extensions.qiling_ext import QilingFacade
from extensions.z3ida_ext import Z3IDAFacade

_BADADDR = (1 << 64) - 1
_QL_ARCH = {
    ("metapc", 64): "x8664", ("metapc", 32): "x86",
    ("arm", 64): "arm64", ("arm", 32): "arm",
    ("mips", 64): "mips", ("mips", 32): "mips", ("mipsb", 32): "mips",
}
_TRACE_LIMITS = {"call_edges": 2000, "branch_edges": 2000,
                 "hot_eas": 50, "mem_writes": 500}


class LabError(Exception):
    pass


def to_angr_addr(ea, image_base, mapped_base):
    return int(ea) - int(image_base) + int(mapped_base)


def from_angr_addr(addr, image_base, mapped_base):
    return int(addr) - int(mapped_base) + int(image_base)


def to_ql_addr(ea, orig_ea, entry_point):
    return int(ea) - int(orig_ea) + int(entry_point)


def from_ql_addr(ql_ea, orig_ea, entry_point):
    return int(ql_ea) - int(entry_point) + int(orig_ea)


def parse_hex_operand(op_str):
    text = str(op_str or "").strip()
    try:
        return int(text, 16)
    except ValueError:
        return None


def cap_list(seq, limit):
    seq = list(seq or [])
    return seq[: int(limit)], len(seq) > int(limit)


def summarize_trace(events, limits):
    """把逐指令事件归约为 Trace 摘要（调用/分支边、热点、内存写）。"""
    call_edges, branch_edges, hot, mem_writes = [], [], {}, []
    for idx, ev in enumerate(events):
        ea = int(ev.get("ida_ea", ev.get("address", 0)))
        mnem = (ev.get("mnemonic") or "").lower()
        hot[ea] = hot.get(ea, 0) + 1
        target = parse_hex_operand(ev.get("op_str"))
        if mnem.startswith("call") and target is not None:
            call_edges.append({"ea": ea, "to_ea": target})
        elif mnem.startswith("j") or mnem.startswith("loop"):
            nxt = None
            if idx + 1 < len(events):
                nxt = int(events[idx + 1].get("ida_ea", events[idx + 1].get("address", 0)))
            branch_edges.append({"ea": ea, "to_ea": target,
                                 "taken": None if target is None else (nxt == target)})
        for write in ev.get("mem_writes") or []:
            mem_writes.append({"ea": int(write.get("ida_ea", write.get("address", 0))),
                               "size": int(write.get("size", 0)),
                               "value": int(write.get("value", 0))})
    hot_pairs, _ = cap_list(sorted(hot.items(), key=lambda kv: -kv[1]), limits["hot_eas"])
    call_edges, call_trunc = cap_list(call_edges, limits["call_edges"])
    branch_edges, branch_trunc = cap_list(branch_edges, limits["branch_edges"])
    mem_writes, mem_trunc = cap_list(mem_writes, limits["mem_writes"])
    return {"call_edges": call_edges, "branch_edges": branch_edges,
            "hot_eas": [{"ea": ea, "count": n} for ea, n in hot_pairs],
            "mem_writes": mem_writes,
            "edges_truncated": bool(call_trunc or branch_trunc or mem_trunc)}


def _rxstub_comment_ea(item):
    for key in ("callsiteEa", "callsite_ea", "callsite", "ea", "addr"):
        value = item.get(key)
        if value is not None:
            return value
    return None


def _format_rxstub_value(value):
    if value is None:
        return "null"
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict) and value.get("name") is not None:
        return str(value["name"])
    return repr(value)


class LabFacade:
    def __init__(self, ida=None, board=None):
        self._ida = ida
        self._board = board
        self._qiling = QilingFacade(ida)
        self._angr = AngrFacade(ida)
        self._z3ida = Z3IDAFacade(ida)
        self._deob = DeobfuscationFacade(ida)
        self._project_cache = None
        self._emulators = []

    # ---- 基础 ----
    def _require_ida(self):
        if self._ida is None:
            raise LabError("lab requires an IDA session (set_binary_path first)")

    def _require_board(self):
        if self._board is None:
            raise LabError("analysis board unavailable in this session")

    def _ea(self, x):
        if isinstance(x, int):
            return int(x)
        text = str(x).strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
        self._require_ida()
        ea = self._ida.get_name_ea(text)
        if ea is None or int(ea) >= _BADADDR:
            raise LabError(f"cannot resolve address/symbol: {x!r}")
        return int(ea)

    def _board_add(self, kind, **fields):
        if self._board is None:
            fields.setdefault("id", None)
            return fields
        return getattr(self._board, f"add_{kind}")(**fields)

    def _qiling_arch(self, opts=None):
        arch = (opts or {}).get("arch")
        if arch:
            return str(arch)
        info = self._ida.arch_info()
        return _QL_ARCH.get((info.get("proc"), info.get("bits")), "x8664")

    # ---- 会话与坐标 ----
    def basis(self):
        self._require_ida()
        return {"image_base": int(self._ida.get_imagebase()),
                "input_path": self._ida.get_input_file_path(),
                "arch": self._ida.arch_info()}

    def anchor(self, x):
        self._require_ida()
        ea = self._ea(x)
        return {"ea": ea,
                "name": self._ida.get_function_name(ea) or "",
                "func": self._ida.function_info(ea),
                "segment": self._ida.get_segment_name(ea)}

    def target(self, x, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        base = self.anchor(x)
        info = base.get("func")
        if info and opts.get("force_kind") != "region":
            record = {"kind": "func", "ea": info["start_ea"], "name": info["name"],
                      "start_ea": info["start_ea"], "end_ea": info["end_ea"],
                      "size": info["size"]}
        else:
            size = int(opts.get("size") or self._ida.get_instruction_size(base["ea"]) or 1)
            record = {"kind": "region", "ea": base["ea"],
                      "name": base["name"] or f"region_{base['ea']:x}",
                      "start_ea": base["ea"], "end_ea": base["ea"] + size, "size": size}
        record["segment"] = base.get("segment")
        if opts.get("with_bytes"):
            raw = self._ida.get_bytes(record["start_ea"],
                                      min(record["size"], int(opts.get("max_bytes", 1 << 16))))
            record["bytes_hex"] = bytes(raw or b"").hex()
        return self._board_add("target", **record)

    def _get_project(self, opts=None):
        if self._project_cache is None:
            self._require_ida()
            self._project_cache = self._angr.project((opts or {}).get("path"))
        return self._project_cache

    def to_angr(self, ea, project=None):
        project = project or self._get_project()
        base = project.loader.main_object.mapped_base
        return to_angr_addr(self._ea(ea), int(self._ida.get_imagebase()), int(base))

    def from_angr(self, addr, project=None):
        project = project or self._get_project()
        base = project.loader.main_object.mapped_base
        return from_angr_addr(int(addr), int(self._ida.get_imagebase()), int(base))

    # ---- 读原语 ----
    def decompile(self, x):
        self._require_ida()
        return self._ida.decompile(self._ea(x))

    def disasm(self, x, opts=None):
        self._require_ida()
        return self._ida.disassemble(self._ea(x), (opts or {}).get("count"))

    def xrefs(self, x):
        self._require_ida()
        ea = self._ea(x)
        return {"to": self._ida.get_xrefs_to(ea), "from": self._ida.get_xrefs_from(ea)}

    def bytes(self, x, size=None):
        self._require_ida()
        ea = self._ea(x)
        n = int(size or self._ida.get_instruction_size(ea) or 1)
        return {"ea": ea, "size": n, "hex": bytes(self._ida.get_bytes(ea, n) or b"").hex()}

    def plan_emulation(self, x, opts=None):
        self._require_ida()
        t = self.target(x)
        return self._qiling.plan(t["start_ea"], t["size"], opts)

    def detect_arch(self):
        return self._ida.arch_info()

    # ---- 写回（staged-only）----
    def annotate(self, ea, text, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        addr = self._ea(ea)
        kind = opts.get("kind", "disasm")
        if kind == "decompiler":
            change = self._ida.set_decompiler_comment(addr, str(text))
        elif kind == "rename":
            change = self._ida.rename(addr, str(text))
        elif kind == "prototype":
            change = self._ida.set_function_prototype(addr, str(text))
        elif kind == "local":
            change = self._ida.rename_local_variable(
                int(opts["function_address"]), str(opts["old_name"]), str(text))
        else:
            change = self._ida.set_comment(addr, str(text),
                                           bool(opts.get("repeatable", False)))
        return self._board_add("patch", op=kind, ea=addr, new=str(text), change=change)

    def preview(self):
        self._require_ida()
        return self._ida.preview()

    def commit(self, backup=None):
        self._require_ida()
        return self._ida.commit(backup)

    def discard(self):
        self._require_ida()
        return self._ida.discard()

    def undo(self):
        self._require_ida()
        return self._ida.undo()

    def save_idb(self, path):
        self._require_ida()
        return self._ida.save_idb(path)

    # ---- 黑板 ----
    def note(self, kind, ea, text, opts=None):
        self._require_board()
        opts = dict(opts or {})
        return self._board.add_finding(
            kind, self._ea(ea) if ea is not None else 0, text,
            evidence=opts.get("evidence"), severity=opts.get("severity", "info"),
            action=opts.get("action"), target_id=opts.get("target_id"))

    def findings(self, kind=None, target_id=None):
        self._require_board()
        where = {}
        if kind is not None:
            where["kind"] = kind
        if target_id is not None:
            where["target_id"] = target_id
        return self._board.list("finding", where=where)

    def targets(self):
        self._require_board()
        return self._board.list("target", limit=1000)

    def traces(self):
        self._require_board()
        return self._board.list("trace", limit=200)

    def paths(self):
        self._require_board()
        return self._board.list("path", limit=200)

    def hypotheses(self):
        self._require_board()
        return self._board.list("hypothesis", limit=200)

    def hypothesis(self, ea, claim):
        self._require_board()
        return self._board.add_hypothesis(ea=self._ea(ea), claim=str(claim), status="open")

    def clear(self, kind=None):
        self._require_board()
        self._board.clear(kind)
        return {"ok": True}

    def save_snapshot(self, path):
        self._require_board()
        return self._board.save_snapshot(path)

    def load_snapshot(self, path):
        self._require_board()
        return self._board.load_snapshot(path)

    def artifact(self, name, content):
        self._require_board()
        return self._board.artifact(name, content)

    def board_summary(self):
        self._require_board()
        return self._board.summary()

    # ---- rxstubs（承接原 MCP 工具）----
    def stage_rxstub_comments(self, results, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        prefix = str(opts.get("prefix", "rxstub"))
        staged = []
        for item in list(results or []):
            ea = _rxstub_comment_ea(item)
            if ea is None:
                continue
            text = f"{prefix}: {_format_rxstub_value(item)}"
            staged.append(self.annotate(int(ea), text,
                                        {"kind": opts.get("comment_kind", "disasm")}))
        return {"ok": True, "staged": staged}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py test_lab_board.py -q`
Expected: all passed（`test_lab_wiring.py` 中的 board 用例此时也应通过；若仍缺 FakeIDAFacade 依赖确认已从 `test_lab_ext` 导入）

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_ext.py test_lab_ext.py test_lab_wiring.py
git commit -m "feat: LabFacade 核心原语（锚点/目标/写回/黑板）"
```

---

### Task 5: `lab.trace`（跟踪闭环）

**Files:**
- Modify: `extensions/lab_ext.py`（LabFacade 追加方法）
- Modify: `test_lab_ext.py`（追加测试）

**Interfaces:**
- Consumes: Task 4 全部；`QilingFacade.trace_at(start_ea, size, count, arch, os, regs, trace_regs, trace_mem, timeout, max_trace, max_mem_events)`、`QilingFacade.plan(start_ea, size, opts)`
- Produces: `LabFacade.trace(x, opts=None) -> dict`（信封；`{ok, trace_id, target, steps, truncated, plan, call_edges, branch_edges, hot_eas, mem_writes, edges_truncated, strings?, events?}`）

- [ ] **Step 1: 写失败测试（追加到 `test_lab_ext.py`）**

```python
@pytest.mark.sandbox
def test_lab_trace_runs_shellcode_and_records():
    code = bytes.fromhex("b801000000c3")  # mov eax,1 ; ret
    lab, _, board = _lab(code=code)
    out = lab.trace(0x14001000, {"size": len(code), "plan": False, "store_events": True})
    assert out["ok"] is True, out
    assert out["steps"] >= 1
    assert out["trace_id"]
    assert board.counts()["trace"] == 1
    assert any(ev["mnemonic"] in ("mov", "ret") for ev in out["events"])


@pytest.mark.sandbox
def test_lab_trace_returns_error_envelope_on_bad_input():
    lab, _, _ = _lab(code=b"")
    out = lab.trace(0x14001000, {"plan": False})
    assert out["ok"] is False and "error_type" in out
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py -k trace -q`
Expected: FAIL（`LabFacade` 无 `trace`）

- [ ] **Step 3: 实现（追加到 LabFacade）**

```python
    # ---- 场景：跟踪 ----
    def trace(self, x, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target = self.target(x, opts)
            arch = self._qiling_arch(opts)
            max_trace = int(opts.get("max_steps") or 2000)
            plan = {"ok": False, "skipped": True}
            if opts.get("plan", True):
                try:
                    plan = self._qiling.plan(target["start_ea"], target["size"],
                                             {"limit": int(opts.get("plan_limit", 500))})
                except Exception as exc:  # noqa: BLE001 — plan 只是提示，不阻断
                    plan = {"ok": False, "skipped": True, "error": str(exc)}
            raw = self._qiling.trace_at(
                target["start_ea"], target["size"],
                count=int(opts.get("count") or 0), arch=arch,
                os=opts.get("os", "linux"), regs=opts.get("regs"),
                trace_regs=bool(opts.get("trace_regs", True)),
                trace_mem=bool(opts.get("trace_mem", True)),
                timeout=float(opts.get("timeout", 0) or 0),
                max_trace=max_trace,
                max_mem_events=int(opts.get("max_mem_events", 5000)))
            events = raw.get("trace") if isinstance(raw, dict) else raw
            truncated = bool(raw.get("truncated")) if isinstance(raw, dict) else False
            strings = raw.get("strings") if isinstance(raw, dict) else None
            summary = summarize_trace(events, _TRACE_LIMITS)
            record = self._board_add(
                "trace", target_id=target.get("id"), entry_ea=target["start_ea"],
                steps=len(events), truncated=truncated, **summary)
            out = {"ok": True, "trace_id": record["id"],
                   "target": {"id": target.get("id"), "kind": target["kind"],
                              "start_ea": target["start_ea"], "size": target["size"]},
                   "steps": len(events), "truncated": truncated,
                   "plan": plan, "arch": arch, **summary}
            if strings is not None:
                out["strings"] = strings
            if opts.get("store_events"):
                out["events"] = events
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py -q`
Expected: all passed

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_ext.py test_lab_ext.py
git commit -m "feat: lab.trace 跟踪闭环（锚定 trace + 黑板记录）"
```

---

### Task 6: `lab.emulate` + `LabEmulator`（调试闭环）

**Files:**
- Modify: `extensions/lab_ext.py`
- Modify: `test_lab_ext.py`

**Interfaces:**
- Consumes: `QilingFacade.create/create_from/set_regs/regs/hook_address/mem_read/mem_write/trace/map_idb_segments`
- Produces: `LabFacade.emulate(x, opts=None) -> LabEmulator`；`LabEmulator`：`to_ql(ea)`、`to_ida(q)`、`rip()`、`step(n=1)`、`run(opts=None)`、`regs(names=None)`、`set_regs(mapping)`、`mem_read(ea, size)`、`mem_write(ea, data)`、`bp(ea, cb=None)`、`save_state(ranges=None)`、`restore_state(sid)`、`trace(opts=None)`、`record(name=None)`

- [ ] **Step 1: 写失败测试（追加到 `test_lab_ext.py`）**

```python
@pytest.mark.sandbox
def test_lab_emulator_step_regs_snapshot():
    code = bytes.fromhex("b801000000c3")  # mov eax,1 ; ret
    lab, _, _ = _lab(code=code)
    emu = lab.emulate(0x14001000, {"size": len(code)})
    assert emu.rip() == 0x14001000
    emu.step(1)
    assert emu.regs(["rax"])["rax"] == 1
    emu.mem_write(0x14001000, "90")
    assert emu.mem_read(0x14001000, 1) == "90"
    snap = emu.save_state([(0x14001000, 4)])
    emu.mem_write(0x14001000, "cc")
    emu.restore_state(snap)
    assert emu.mem_read(0x14001000, 1) == "90"


@pytest.mark.sandbox
def test_lab_emulator_trace_records_to_board():
    code = bytes.fromhex("b801000000c3")
    lab, _, board = _lab(code=code)
    emu = lab.emulate(0x14001000, {"size": len(code)})
    out = emu.trace({"max_trace": 16})
    events = out["trace"] if isinstance(out, dict) else out
    assert len(events) >= 1
    emu.record("after mov")
    assert board.counts()["finding"] == 1
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py -k emulator -q`
Expected: FAIL

- [ ] **Step 3: 实现（追加到 `lab_ext.py`）**

```python
class LabEmulator:
    """活模拟句柄：以 IDA 地址为入参，内部换算；仅在一轮 run_js 内有效。"""

    def __init__(self, lab, ql, orig_ea, entry, size, arch, mapped, mapped_segments=None):
        self._lab = lab
        self._q = lab._qiling
        self._ql = ql
        self.orig_ea = int(orig_ea)
        self.entry = int(entry)
        self.size = int(size)
        self.arch = arch
        self.mapped = bool(mapped)
        self.mapped_segments = mapped_segments or []
        self._snapshots = {}
        self._snap_seq = 0

    def to_ql(self, ea):
        if self.mapped:
            return int(ea)
        return to_ql_addr(ea, self.orig_ea, self.entry)

    def to_ida(self, ql_ea):
        if self.mapped:
            return int(ql_ea)
        return from_ql_addr(ql_ea, self.orig_ea, self.entry)

    def _pc(self):
        return int(self._ql.arch.regs.arch_pc)

    def rip(self):
        return self.to_ida(self._pc())

    def _emu_start(self, count=None, until_ql=None, timeout_us=None):
        kwargs = {}
        if count:
            kwargs["count"] = int(count)
        if until_ql is not None:
            kwargs["until"] = int(until_ql)
        if timeout_us:
            kwargs["timeout"] = int(timeout_us)
        try:
            self._ql.arch.uc.emu_start(self._pc(), **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise LabError(f"emulation stopped at {self.rip():#x}: {exc}") from exc

    def step(self, n=1):
        self._emu_start(count=int(n))
        return {"rip_ida": self.rip(), "regs": self.regs()}

    def run(self, opts=None):
        opts = dict(opts or {})
        self._emu_start(
            count=int(opts["count"]) if opts.get("count") else None,
            until_ql=self.to_ql(opts["until_ida"]) if opts.get("until_ida") is not None else None,
            timeout_us=int(float(opts["timeout"]) * 1_000_000) if opts.get("timeout") else None)
        return {"ok": True, "rip_ida": self.rip(), "regs": self.regs()}

    def regs(self, names=None):
        if names:
            return {str(n): int(self._ql.arch.regs.read(str(n))) for n in names}
        return {k: int(v) for k, v in self._q.regs(self._ql).items()}

    def set_regs(self, mapping):
        self._q.set_regs(self._ql, {str(k): int(v) for k, v in dict(mapping).items()})
        return {"ok": True}

    def mem_read(self, ea, size):
        return bytes(self._q.mem_read(self._ql, self.to_ql(ea), int(size))).hex()

    def mem_write(self, ea, data):
        payload = bytes.fromhex(data) if isinstance(data, str) else bytes(data)
        self._q.mem_write(self._ql, self.to_ql(ea), payload)
        return {"ok": True, "ea": int(ea), "size": len(payload)}

    def bp(self, ea, cb=None):
        return self._q.hook_address(self._ql, self.to_ql(ea), cb)

    def save_state(self, ranges=None):
        ranges = list(ranges) if ranges else [(self.orig_ea, self.size)]
        snapshot = {"regs": self.regs(),
                    "mem": [{"ea": int(ea), "size": int(sz), "hex": self.mem_read(ea, sz)}
                            for ea, sz in ranges]}
        self._snap_seq += 1
        sid = f"snap-{self._snap_seq}"
        self._snapshots[sid] = snapshot
        return sid

    def restore_state(self, snapshot_id):
        snapshot = self._snapshots.get(str(snapshot_id))
        if snapshot is None:
            raise LabError(f"unknown snapshot: {snapshot_id}")
        self.set_regs(snapshot["regs"])
        for block in snapshot["mem"]:
            self.mem_write(block["ea"], block["hex"])
        return {"ok": True, "restored": str(snapshot_id)}

    def trace(self, opts=None):
        opts = dict(opts or {})
        opts.setdefault("orig_ea", None if self.mapped else self.orig_ea)
        return self._q.trace(self._ql, opts)

    def record(self, name=None):
        return self._lab._board_add("finding", kind="emulator_state", ea=self.rip(),
                                    text=str(name or "emulator state"),
                                    evidence={"regs": self.regs()})
```

LabFacade 追加：

```python
    # ---- 场景：调试 ----
    def emulate(self, x, opts=None):
        opts = dict(opts or {})
        self._require_ida()
        target = self.target(x, opts)
        arch = self._qiling_arch(opts)
        os_name = opts.get("os", "linux")
        mapped = bool(opts.get("map_segments"))
        if mapped:
            ql = self._qiling.create(b"\x90\x90\x90\x90", {"arch": arch, "os": os_name})
            segments = self._qiling.map_idb_segments(ql, opts)
            entry = orig = target["start_ea"]
        else:
            ql = self._qiling.create_from(target["start_ea"], target["size"],
                                          {"arch": arch, "os": os_name})
            segments = []
            entry = int(ql.os.entry_point)
            orig = target["start_ea"]
        if opts.get("regs"):
            self._qiling.set_regs(ql, {str(k): int(v) for k, v in dict(opts["regs"]).items()})
        emu = LabEmulator(self, ql, orig_ea=orig, entry=entry, size=target["size"],
                          arch=arch, mapped=mapped, mapped_segments=segments)
        self._emulators.append(emu)
        return emu
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_lab_ext.py -q`
Expected: all passed

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_ext.py test_lab_ext.py
git commit -m "feat: lab.emulate 交互模拟（step/regs/mem/bp/快照）"
```

---

### Task 7: `lab.deob` + `lab.solve_branch`（反混淆闭环）

**Files:**
- Modify: `extensions/lab_ext.py`
- Modify: `test_real_ida.py`（追加真实 IDA 测试）

**Interfaces:**
- Consumes: `DeobfuscationFacade.scan(opts)`、`Z3IDAFacade.checkBranch(ea, opts)`、Task 6 `emulate`
- Produces: `LabFacade.deob(x=None, opts=None) -> dict`、`LabFacade.solve_branch(ea, opts=None) -> dict`

- [ ] **Step 1: 写失败测试（真实 IDA，追加到 `test_real_ida.py`）**

```python
def test_lab_deob_and_solve_branch_real_ida():
    from extensions.lab_board import AnalysisBoard
    from sandbox.supervisor import SandboxSupervisor
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida, "board": AnalysisBoard(session_id="lab-deob")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "var lab = require('lab');"
            "var r = lab.deob('pre_c_init', {limit: 5});"
            "'' + r.ok + '/' + r.scanned", timeout=240)
        assert result_of(out).startswith("true/"), out

        out = sup.run(
            "var lab = require('lab');"
            "var r = lab.deob('pre_c_init', {limit: 20});"
            "var b = null;"
            "for (var i = 0; i < r.results.length; i++) {"
            "  if (r.results[i].kind === 'opaque_predicate') { b = r.results[i].ea; break; } }"
            "b === null ? 'nobranch' : (function () {"
            "  var s = lab.solve_branch(b, {});"
            "  return '' + s.ok + '/' + s.classification; })()", timeout=240)
        assert result_of(out) == "nobranch" or result_of(out).startswith("true/"), out
    finally:
        facade.discard()
        ida.close()
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_lab_deob_and_solve_branch_real_ida -o addopts="" -q`
Expected: FAIL（`deob` 不存在）

- [ ] **Step 3: 实现（追加到 LabFacade）**

```python
    # ---- 场景：反混淆 ----
    def deob(self, x=None, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target_id = None
            if x is not None:
                target = self.target(x, opts)
                target_id = target.get("id")
                opts["functions"] = [target["start_ea"]]
            res = self._deob.scan(opts)
            findings = []
            for item in list(res.get("results", [])):
                enriched = dict(item)
                ea = item.get("ea") or item.get("addr")
                if ea is not None and (item.get("kind") or "") == "opaque_predicate":
                    enriched["branch"] = self.solve_branch(ea, {"stage": False})
                findings.append(self._board_add(
                    "finding", kind=item.get("kind") or "deob", ea=int(ea or 0),
                    text=str(item), evidence=enriched, target_id=target_id))
            return {"ok": True, "results": findings, "scanned": res.get("scanned"),
                    "matched": res.get("matched"),
                    "failures": list(res.get("failures", []))[:20]}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def solve_branch(self, ea, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            addr = self._ea(ea)
            res = self._z3ida.checkBranch(addr, opts.get("slice_opts"))
            keys = ("classification", "result", "simplified", "taken_ea",
                    "not_taken_ea", "confidence", "reason", "comment", "unsupported")
            out = {"ok": True, "ea": addr}
            out.update({k: res.get(k) for k in keys})
            if opts.get("concrete") and out.get("classification") in ("symbolic", "unknown"):
                out["concrete"] = self._concrete_confirm(addr, opts)
            if opts.get("stage") and out.get("comment"):
                out["patch"] = self.annotate(addr, out["comment"], {"kind": "disasm"})
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def _concrete_confirm(self, branch_ea, opts):
        info = self._ida.function_info(branch_ea)
        if not info:
            return {"ok": False, "reason": "branch not inside a function"}
        emu = self.emulate(info["start_ea"],
                           {"map_segments": bool(opts.get("map_segments", False))})
        taken = self._ea(opts["taken_ea"]) if opts.get("taken_ea") else None
        visited = set()
        for _ in range(int(opts.get("max_steps", 2000))):
            emu.step(1)
            visited.add(emu.rip())
            if emu.rip() == branch_ea:
                emu.step(1)
                visited.add(emu.rip())
                break
        return {"ok": True, "taken_ea": taken,
                "taken_hit": None if taken is None else (taken in visited),
                "visited": len(visited)}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_lab_deob_and_solve_branch_real_ida -o addopts="" -q`
Expected: 1 passed

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_ext.py test_real_ida.py
git commit -m "feat: lab.deob/solve_branch 反混淆闭环（z3ida + 具体确认）"
```

---

### Task 8: `lab.concrete_prefix` + `lab.follow`（路径跟随闭环）

**Files:**
- Modify: `extensions/lab_ext.py`
- Modify: `test_real_ida.py`

**Interfaces:**
- Consumes: `AngrFacade.project/blank_state/call_state/reg_write/explore_paths/first/eval`、Task 6 `emulate`
- Produces: `LabFacade.concrete_prefix(x, opts=None) -> dict`、`LabFacade.follow(x, opts=None) -> dict`

- [ ] **Step 1: 写失败测试（真实 IDA）**

```python
def test_lab_concrete_prefix_and_follow_real_ida():
    from extensions.lab_board import AnalysisBoard
    from sandbox.supervisor import SandboxSupervisor
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida, "board": AnalysisBoard(session_id="lab-path")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "var lab = require('lab');"
            "var t = lab.target('pre_c_init');"
            "var c = lab.concrete_prefix(t.start_ea, {max_steps: 500});"
            "'' + c.ok + '/' + (typeof c.regs === 'object')", timeout=240)
        assert result_of(out) == "true/true", out

        out = sup.run(
            "var lab = require('lab');"
            "var t = lab.target('pre_c_init');"
            "var p = lab.follow(t.start_ea, {max_steps: 300, timeout: 20, regs: ['rax']});"
            "'' + p.ok + '/' + (p.found === true || p.found === false)", timeout=300)
        assert result_of(out) == "true/true", out
    finally:
        facade.discard()
        ida.close()
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_lab_concrete_prefix_and_follow_real_ida -o addopts="" -q`
Expected: FAIL（方法不存在）

- [ ] **Step 3: 实现（追加到 LabFacade）**

```python
    # ---- 场景：路径跟随 ----
    def concrete_prefix(self, x, opts=None):
        opts = dict(opts or {})
        try:
            emu = self.emulate(x, {"map_segments": bool(opts.get("map_segments", False)),
                                   "arch": opts.get("arch"), "os": opts.get("os")})
            until = emu.to_ql(self._ea(opts["stop_at"])) if opts.get("stop_at") is not None else None
            steps = int(opts.get("max_steps", 2000))
            emu._emu_start(count=steps or None, until_ql=until,
                           timeout_us=int(float(opts.get("timeout", 0) or 0) * 1_000_000) or None)
            out = {"ok": True, "rip_ida": emu.rip(), "regs": emu.regs(), "steps": steps}
            if opts.get("record"):
                emu.record("concrete_prefix")
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def follow(self, x, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target = self.target(x, opts)
            project = self._get_project(opts)
            start_angr = self.to_angr(target["start_ea"], project)
            if opts.get("args") is not None:
                state = self._angr.call_state(project, start_angr, args=opts["args"])
            else:
                state = self._angr.blank_state(project, start_angr, opts.get("state_opts"))
            for name, value in dict(opts.get("seed_regs") or {}).items():
                self._angr.reg_write(state, name, int(value))
            find = ([self.to_angr(self._ea(g), project) for g in opts["goal"]]
                    if opts.get("goal") else None)
            avoid = ([self.to_angr(self._ea(g), project) for g in opts.get("avoid", [])]
                     or None)
            res = self._angr.explore_paths(project, state, {
                "find": find, "avoid": avoid,
                "max_steps": int(opts.get("max_steps", 0) or 0),
                "timeout": float(opts.get("timeout", 0) or 0),
                "n": opts.get("n"), "max_active": opts.get("max_active"),
                "veritesting": opts.get("veritesting"), "dfs": opts.get("dfs"),
                "loop_bound": opts.get("loop_bound")})
            simgr = res["simgr"]
            found = self._angr.first(simgr, "found" if find else "active")
            reg_names = opts.get("regs") or list(project.arch.default_symbolic_registers)[:6]
            blocks, regs, constraints = [], {}, []
            if found is not None:
                blocks = [self.from_angr(a, project)
                          for a in found.history.bbl_addrs][: int(opts.get("max_blocks", 5000))]
                regs = {r: self._angr.eval(found, getattr(found.regs, r)) for r in reg_names}
                constraints = [str(c) for c in list(found.solver.constraints)[:100]]
            record = self._board_add(
                "path", target_id=target.get("id"), found=found is not None,
                goal_ea=self._ea(opts["goal"][0]) if opts.get("goal") else None,
                blocks_ida=blocks, regs=regs, constraints=constraints,
                stash_counts=res.get("counts"))
            out = {"ok": True, "path_id": record["id"], "found": record["found"],
                   "blocks_ida": blocks[:200], "regs": regs,
                   "constraints": constraints[:20], "stash_counts": res.get("counts")}
            if opts.get("verify_concrete") and found is not None:
                out["verify"] = self._verify_concrete(target, opts, regs)
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def _verify_concrete(self, target, opts, regs):
        try:
            emu = self.emulate(target["start_ea"], {"map_segments": True})
            goal = opts.get("goal")
            until = emu.to_ql(self._ea(goal[0])) if goal else None
            emu.set_regs({k: int(v) for k, v in dict(regs).items()
                          if isinstance(v, int)})
            emu._emu_start(count=int(opts.get("verify_steps", 10000)) or None,
                           until_ql=until)
            reached = goal is not None and emu.rip() == self._ea(goal[0])
            return {"ok": True, "reached": reached, "rip_ida": emu.rip()}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_lab_concrete_prefix_and_follow_real_ida -o addopts="" -q`
Expected: 1 passed

- [ ] **Step 5: 提交**

```bash
git add extensions/lab_ext.py test_real_ida.py
git commit -m "feat: lab.concrete_prefix/follow 路径跟随闭环（具体->符号->验证）"
```

---

### Task 9: `engine_status` / `engine_diagnostics` 合并

**Files:**
- Modify: `headless_ida_mcp_server/server.py:111-135`（_engine_status）、`597-649`（readiness 抽取）
- Create: `test_mcp_surface.py`

**Interfaces:**
- Produces: `_engine_status()` 返回额外含 `"modules"`（原 engine_capabilities 的依赖 dict）与 `"board"`（`session.board.summary()`）；`_engine_diagnostics()` 返回额外含 `"readiness"`（原 `reverse_readiness_check` 的 report，`check_angr=False`）；内部函数 `_readiness_report(check_angr=False)`。

- [ ] **Step 1: 写失败测试**

```python
# test_mcp_surface.py
# -*- coding: utf-8 -*-
import pytest

from headless_ida_mcp_server import server


@pytest.mark.unit
def test_engine_status_includes_modules_and_board():
    status = server._engine_status()
    assert isinstance(status["modules"], dict) and "angr" in status["modules"]
    assert status["board"]["session_id"]
    assert "sandbox" in status


@pytest.mark.unit
def test_engine_diagnostics_includes_readiness():
    report = server._engine_diagnostics()
    assert "readiness" in report
    assert "ok" in report["readiness"]
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_mcp_surface.py -q`
Expected: FAIL（`modules`/`board`/`readiness` 键不存在）

- [ ] **Step 3: 实现**

`_engine_status()`（返回 dict 中追加两键）：

```python
        "modules": _dependency_status(),
        "board": session.board.summary(),
```

把 `reverse_readiness_check`（server.py:597-649）的函数体改名为 `_readiness_report(check_angr=False)`（去掉 `@mcp.tool()`，`check_angr` 默认 False），原工具删除（Task 10 一并删，本任务先保留工具并让 diagnostics 复用）：

```python
def _readiness_report(check_angr: bool = False) -> dict:
    # ……原 reverse_readiness_check 的函数体，保留逐项 try/except……
```

`_engine_diagnostics()` 返回 dict 追加：

```python
        "readiness": _readiness_report(check_angr=False),
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_mcp_surface.py -q`
Expected: 2 passed

- [ ] **Step 5: 提交**

```bash
git add headless_ida_mcp_server/server.py test_mcp_surface.py
git commit -m "feat: engine_status/diagnostics 合并 capabilities 与 readiness"
```

---

### Task 10: MCP 收敛（删 44 工具，4 只读工具改走 facade）

**Files:**
- Modify: `headless_ida_mcp_server/server.py`
- Modify: `test_mcp_surface.py`

**Interfaces:**
- Consumes: Task 3 的 `IDAFacade.decompile/disassemble/get_entry_points`
- Produces: 工具面恰为 `{run_js, set_binary_path, open_ida_database, engine_status, engine_diagnostics, decompile_function, decompile_checked, disassemble_function, get_entry_points}`；只读工具经由 `IDAFacade`。

**移除清单（44 个，逐个删除整个 `@mcp.tool()` 函数）：**
`engine_capabilities`、`emulate_code`、`trace_code`、`strings_code`、`scan_string_decryptors`、`scan_string_call_sites`、`emulate_function`、`scan_string_decrypt_chains`、`qiling_capabilities`、`qiling_plan`、`batch_strings_at`、`write_strings_results`、`rxstubs_stage_log_comments`、`deobfuscation_scan`、`deobfuscation_patch_preview`、`stage_deobfuscation_patch`、`ida_preview`、`ida_commit`、`ida_discard`、`ida_undo`、`ida_save_idb`、`reverse_readiness_check`、`angr_project_info`、`angr_function_range`、`angr_stage_result_comments`、`get_function`、`get_function_by_name`、`get_function_by_address`、`get_current_address`、`get_current_function`、`convert_number`、`list_functions`、`prepare_decompile`、`get_prepare_decompile_status`、`get_xrefs_to`、`set_decompiler_comment`、`set_disassembly_comment`、`refresh_decompiler_widget`、`refresh_decompiler_ctext`、`rename_local_variable`、`rename_function`、`set_function_prototype`、`save_idb_file`、`save_ida_database`。

连带清理（确认无引用后删除）：`_qiling_guard`、`_format_rxstub_value`、`_rxstub_comment_ea`（已移入 lab_ext）、以及 server.py 顶部不再使用的 `AngrFacade`/`DeobfuscationFacade`/`QilingFacade`/`QilingError`/`QilingEmulationError` 导入（`import extensions` 与 `IDAFacade`/`IDA` 保留）。

- [ ] **Step 1: 写失败测试（追加到 `test_mcp_surface.py`）**

```python
KEEP_TOOLS = {"run_js", "set_binary_path", "open_ida_database", "engine_status",
              "engine_diagnostics", "decompile_function", "decompile_checked",
              "disassemble_function", "get_entry_points"}

DROP_TOOLS = {
    "engine_capabilities", "emulate_code", "trace_code", "strings_code",
    "scan_string_decryptors", "scan_string_call_sites", "emulate_function",
    "scan_string_decrypt_chains", "qiling_capabilities", "qiling_plan",
    "batch_strings_at", "write_strings_results", "rxstubs_stage_log_comments",
    "deobfuscation_scan", "deobfuscation_patch_preview", "stage_deobfuscation_patch",
    "ida_preview", "ida_commit", "ida_discard", "ida_undo", "ida_save_idb",
    "reverse_readiness_check", "angr_project_info", "angr_function_range",
    "angr_stage_result_comments", "get_function", "get_function_by_name",
    "get_function_by_address", "get_current_address", "get_current_function",
    "convert_number", "list_functions", "prepare_decompile",
    "get_prepare_decompile_status", "get_xrefs_to", "set_decompiler_comment",
    "set_disassembly_comment", "refresh_decompiler_widget", "refresh_decompiler_ctext",
    "rename_local_variable", "rename_function", "set_function_prototype",
    "save_idb_file", "save_ida_database",
}


@pytest.mark.unit
def test_mcp_surface_is_sandbox_first():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("surface")
    server.register(mcp)
    names = set(mcp._tool_manager._tools.keys())
    assert names == KEEP_TOOLS
    assert not (DROP_TOOLS & names)
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest test_mcp_surface.py -q`
Expected: FAIL（仍有被移除工具）

- [ ] **Step 3: 执行删除与改写**

删除上表 44 个工具函数及连带辅助后，4 个只读工具改写为 facade 薄封装：

```python
    @mcp.tool()
    def decompile_function(address: Annotated[int, "Address of the function to decompile"]) -> str:
        """反编译指定地址的函数，返回伪代码文本。"""
        return _require_ida_facade().decompile(address)

    @mcp.tool()
    def decompile_checked(address: Annotated[int, "Address of the function to decompile"]) -> dict:
        """反编译并返回结构化结果；失败返回 {ok:false, message} 而非抛错。"""
        try:
            return {"ok": True, "pseudocode": _require_ida_facade().decompile(address)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    @mcp.tool()
    def disassemble_function(address: Annotated[int, "Address of the function to disassemble"]) -> str:
        """返回函数的逐指令汇编文本。"""
        return _require_ida_facade().disassemble(address)

    @mcp.tool()
    def get_entry_points() -> list:
        """返回数据库全部入口点。"""
        return _require_ida_facade().get_entry_points()
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest test_mcp_surface.py test_server_fallback.py -q`
Expected: all passed

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 无失败（`test_sse_client.py`/`test_merge.py` 默认被排除，Task 11 处理）

- [ ] **Step 5: 提交**

```bash
git add headless_ida_mcp_server/server.py test_mcp_surface.py
git commit -m "feat: MCP 收敛到 9 工具，只读工具改走 IDAFacade"
```

---

### Task 11: 适配既有测试（sse/merge/rxstubs）

**Files:**
- Modify: `test_sse_client.py`、`test_merge.py`、`test_rxstubs_server.py`

**Interfaces:**
- Consumes: Task 4 的 `lab.stage_rxstub_comments`；保留工具 `decompile_function`

- [ ] **Step 1: 更新 `test_merge.py`（`get_function_by_name` → `run_js`）**

```python
            r = await session.call_tool("set_binary_path", {"path": BINARY})
            print("set_binary_path ->", _text(r))
            r = await session.call_tool(
                "run_js",
                {"code": "'' + require('ida').get_name_ea('pre_c_init')"})
            print("pre_c_init via run_js ->", _text(r))
```

- [ ] **Step 2: 更新 `test_sse_client.py`（同上替换 `get_function_by_name` 调用；`decompile_function` 保留不动）**

将 41-44 行的调用替换为：

```python
            r = await session.call_tool(
                "run_js",
                {"code": "'' + require('ida').get_name_ea('pre_c_init')"})
            print("pre_c_init via run_js ->", _text(r))
```

- [ ] **Step 3: 更新 `test_rxstubs_server.py`（辅助函数已移至 lab_ext）**

```python
# -*- coding: utf-8 -*-
"""rxstubs 暂存辅助逻辑验证（已并入 LabFacade 所在模块）。"""

import pytest

from extensions.lab_ext import _format_rxstub_value, _rxstub_comment_ea


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        ("abcd", "'abcd'"),
        (True, "true"),
        (False, "false"),
        (4, "4"),
        ({"name": "java/lang/String", "type": "jclass"}, "java/lang/String"),
    ],
)
def test_format_rxstub_value(value, expected):
    assert _format_rxstub_value(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"callsiteEa": 0x1000, "ea": 0x2000, "addr": 0x3000}, 0x1000),
        ({"callsite_ea": 0x1100, "callsite": 0x1200, "ea": 0x2000}, 0x1100),
        ({"callsite": 0x1200, "ea": 0x2000}, 0x1200),
        ({"ea": 0x2000, "addr": 0x3000}, 0x2000),
        ({"addr": 0x3000}, 0x3000),
    ],
)
def test_rxstub_comment_ea(item, expected):
    assert _rxstub_comment_ea(item) == expected
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest test_rxstubs_server.py test_server_fallback.py test_mcp_surface.py -q`
Expected: all passed（sse 两个文件保持被默认排除，语法正确即可：`python -m py_compile test_sse_client.py test_merge.py`）

- [ ] **Step 5: 提交**

```bash
git add test_sse_client.py test_merge.py test_rxstubs_server.py
git commit -m "test: 适配收敛后的 MCP 工具面"
```

---

### Task 12: 文档重写（prompt/README）

**Files:**
- Modify: `docs/prompt.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: 最终工具面与 `require('lab')` 原语集

- [ ] **Step 1: 重写 `docs/prompt.md` 的工具指引段**

`docs/prompt.md` 中原「engine_status / engine_capabilities / engine_diagnostics 可在分析前查看…」段落替换为：

```markdown
engine_status / engine_diagnostics 可在分析前查看 session、依赖、黑板与沙箱状态。
所有分析优先在 run_js 沙箱内用 require('lab') 完成闭环：
- lab.target(x)/lab.anchor(x)：把名字或地址解析成统一 Target/锚点（IDA ea 为规范坐标）。
- lab.trace(x, {max_steps, timeout})：IDA 函数 -> unicorn 跟踪 -> 调用/分支边/内存写，写入黑板。
- lab.emulate(x, {map_segments}) -> emu：交互调试；emu.step(n)/regs()/mem_read/mem_write/bp(ea)/save_state()/restore_state()。
- lab.deob(x)/lab.solve_branch(ea)：混淆扫描 + z3 谓词判定 +（可选）具体执行确认。
- lab.concrete_prefix(x, {stop_at}) + lab.follow(x, {goal, avoid, seed_regs, verify_concrete})：具体前缀 -> 符号探索 -> 约束模型 -> 具体验证。
- lab.annotate(ea, text)/lab.preview()/lab.commit()：结论一律先暂存，preview 核对后显式提交。
- lab.note/lab.findings/lab.paths/lab.artifact：结论与证据写黑板，跨 run_js 可读。
MCP 只保留：run_js、set_binary_path/open_ida_database、engine_status/engine_diagnostics、
decompile_function/decompile_checked/disassemble_function/get_entry_points。
反编译优先 require('ida').decompile(ea)（在沙箱内），只有独立快速查看才用 MCP 的 decompile_function。
```

- [ ] **Step 2: 更新 `README.md`**

- 「功能概览」增加一条：`require('lab')` 组合原语层（锚点/黑板/跟踪/调试/反混淆/路径跟随）。
- 「配置项」之后的工具清单段落（若有）改为 9 个保留工具表。
- 「测试脚本」段落补：`test_lab_board.py`、`test_lab_anchor.py`、`test_lab_ext.py`、`test_lab_wiring.py`、`test_mcp_surface.py`。
- 新增小节「## Lab 沙箱编排」，内容取 spec 第 6、7 节的原语表与四场景签名。

- [ ] **Step 3: 校对文档与实现一致（人工核对原语名）**

Run: `grep -o "lab\.[a-z_]*" docs/prompt.md | sort -u`
Expected: 列表中的每个名字都能在 `extensions/lab_ext.py` 中找到同名方法

- [ ] **Step 4: 提交**

```bash
git add docs/prompt.md README.md
git commit -m "docs: agent 指引改为沙箱闭环优先，列出 Lab 原语"
```

---

### Task 13: 全量验证与收尾

**Files:**
- 无新文件

- [ ] **Step 1: 离线全量**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: 全部通过，0 failed（新增 lab 测试全绿）

- [ ] **Step 2: 真实 IDA 全量**

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py -o addopts="" -q`
Expected: 全部通过（含 parity、deob、follow、跨轮黑板）

- [ ] **Step 3: 跨轮黑板持久化确认（真实 IDA，追加到 `test_real_ida.py` 若 Task 8 未覆盖）**

```python
def test_lab_board_survives_across_runs_real_ida():
    from extensions.lab_board import AnalysisBoard
    from sandbox.supervisor import SandboxSupervisor
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida, "board": AnalysisBoard(session_id="persist")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        first = sup.run("require('lab').note('hypothesis', 'pre_c_init', 'demo claim')", timeout=120)
        assert "ok" in first or "=> " in first
        second = sup.run(
            "var f = require('lab').findings('hypothesis');"
            "'' + f.length + '/' + f[0].text", timeout=120)
        assert result_of(second) == "1/demo claim", second
    finally:
        facade.discard()
        ida.close()
```

Run: `.venv/Scripts/python.exe -m pytest test_real_ida.py::test_lab_board_survives_across_runs_real_ida -o addopts="" -q`
Expected: 1 passed

- [ ] **Step 4: 提交**

```bash
git add -A
git commit -m "test: Lab 全量验证（离线 + 真实 IDA + 跨轮黑板）"
```

---

## Self-Review 记录

- **Spec 覆盖**：spec §5 黑板 → Task 1；§4 接线 → Task 2；§8.3 parity → Task 3；§6 原语 → Task 4；§7.1-7.4 → Task 5-8；§8.1/8.2 与 engine 合并 → Task 9-10；§10 测试 → 各任务 + Task 13；§11 文档 → Task 12。spec 的 `lab.link` 以 `board.attach`（Task 1）+ `lab.note(evidence)` 承接，未单列方法（YAGNI，已在测试中覆盖 attach）。
- **占位符**：无 TBD/TODO；所有代码步骤给出完整代码。
- **类型一致性**：`LabFacade._get_project`（非 `_project`）避免与属性同名；`summarize_trace` 返回键为 `edges_truncated`（避免与 trace 记录的 `truncated` 布尔冲突）；`board.list(kind, where=…)` 与 `lab.findings(kind=…)` 的 where 映射一致。
