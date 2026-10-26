# RXEngine

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-FastMCP-6f42c1.svg)](https://modelcontextprotocol.io)

[English](README.en.md) | 简体中文

RXEngine 是一个面向逆向分析自动化的 MCP 服务，融合 JavaScript 沙箱、Headless IDA、angr、qiling 和反混淆辅助能力。它适合作为本地分析工具或受控环境内的自动化逆向后端。

## 功能概览

- 通过 FastMCP 暴露统一工具入口。
- 使用 `run_js` 在受控 JavaScript 上下文中调用已注册的 Python/IDA 能力。
- 通过 Headless IDA 加载二进制并提供函数、反汇编、反编译、xref、patch 暂存等能力。
- 通过 qiling/unicorn 执行 shellcode 模拟、trace、字符串解密候选分析。
- 通过 angr/claripy 提供符号执行辅助能力。
- 通过 z3/z3ida 提供约束求解、bit-vector 表达式和轻量分支谓词分析能力。
- 通过 `require('lab')` 组合原语层提供沙箱闭环编排：锚点解析、分析黑板、unicorn 跟踪、交互调试、反混淆判定与 angr 路径跟随。

## 环境要求

- Python `>=3.10,<3.14`
- IDA Pro / IDA Home，且可执行 `idat.exe` 或对应平台的 headless IDA 可执行文件
- Windows 环境已验证；其他平台需要确认 IDA 路径、STPyV8 和二进制分析依赖是否可用

## 快速启动

```bash
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
python main.py
```

Windows PowerShell 可使用：

```powershell
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python main.py
```

启动后默认使用 `.env` 中的 `HOST`、`PORT` 和 `TRANSPORT`。也可以通过命令行覆盖：

```bash
python main.py --host 127.0.0.1 --port 8888 --transport sse --ida-path "D:\IDA Professional 9.2\idat.exe"
```

## 配置项

| 变量 | 默认示例 | 说明 |
| --- | --- | --- |
| `IDA_PATH` | `D:\IDA Professional 9.2\idat.exe` | Headless IDA 可执行文件路径，必填 |
| `HOST` | `127.0.0.1` | MCP SSE 监听地址 |
| `PORT` | `8888` | MCP SSE 监听端口 |
| `TRANSPORT` | `sse` | MCP 传输方式，支持 `sse` 或 `stdio` |

真实 `.env` 不应提交到仓库；请从 `.env.example` 复制后在本机修改。

## 基本使用

启动服务后，MCP 客户端可以连接到：

```text
http://127.0.0.1:8888/sse
```

### MCP 工具面

工具面收敛为 9 个工具 + 2 个 prompt，分析闭环一律优先在 `run_js` 沙箱内完成：

| 工具 | 用途 |
| --- | --- |
| `run_js` | 沙箱闭环唯一入口，编排 `require('ida'/'lab'/'qiling'/'angr'/'z3'/...)` 全部能力 |
| `set_binary_path` | 加载待分析二进制或已有 IDA 数据库，建立 session |
| `open_ida_database` | 专门打开已有 `.idb`/`.ida`/`.i64` |
| `engine_status` | 查看 session、模块、依赖、黑板（`board`）、沙箱（`sandbox`）与 `limits` |
| `engine_diagnostics` | 健康检查与就绪报告 |
| `decompile_function` / `decompile_checked` | 独立快速反编译（只读，与沙箱同一实现） |
| `disassemble_function` | 独立快速反汇编（只读） |
| `get_entry_points` | 入口点列表 |

MCP prompt（非工具）：`exploit_prompt`、`deobfuscation_prompt`，用于引导对应场景的分析模板。

常见流程：

1. 调用 `set_binary_path` 加载待分析二进制，或用 `open_ida_database` 打开已有 `.idb`/`.ida`/`.i64`。
2. 用 `engine_status` / `engine_diagnostics` 确认 session、依赖、黑板与沙箱状态。
3. 用 `get_entry_points`、`disassemble_function`、`decompile_function` 做独立快速只读查询。
4. 用 `run_js` 在沙箱内以 `require('lab')` 完成分析闭环；写回一律 staged：`lab.annotate` -> `lab.preview()` -> `lab.commit()`，改错用 `lab.undo()` 回退，持久化用 `lab.save_idb(path)`。

### 会话隔离

分析会话按 MCP 连接隔离：每个 SSE 连接拥有独立的 `EngineSession`（各自的 binary/IDA/黑板/保活 worker），互不污染；同一连接内的所有工具调用命中同一会话。默认最多 4 个并发会话（`SessionManager(max_sessions=4)`），空闲 30 分钟后回收；连接断开时对应会话（含 IDA 与 worker）立即释放。`engine_status.sessions` 返回 `active`/`max`/`idle_ttl`/`fallback`。

两点边界需要知道：

- **重连即新会话**：身份绑定在传输连接上，而不是可配置的 token。客户端重连后需重新 `set_binary_path`，旧的 IDA 会话不会被继承。
- **无连接身份的调用共享 fallback 会话**：stdio 传输、内部直接调用与测试都落到同一个 fallback 会话，行为与单会话模式一致。

`set_binary_path` / `open_ida_database` 会重置当前会话的 `session_id` 与黑板（换样本即换分析上下文），并回收其保活 worker，避免引擎缓存仍绑定旧样本。

## MCP 工具异常兜底

RXEngine 在 FastMCP 工具分发边界统一捕获 Python 工具异常。单次工具失败不会继续向上传播为未处理异常，而是返回可恢复的结构化结果：

```json
{
  "ok": false,
  "error_type": "RuntimeError",
  "message": "detector exited",
  "tool": "tool_name",
  "arguments": {"address": 4198400},
  "recoverable": true
}
```

字段含义：

- `ok`：`false` 表示本次调用失败，调用方不得把其余字段当作正常业务结果。
- `error_type`：原始 Python 异常类型，用于区分参数、状态、依赖和后端执行错误。
- `message`：可读错误信息。
- `tool`：失败的 MCP 工具名称。
- `arguments`：调用方提交的原始参数；非字典参数时为 `null`。
- `recoverable`：表示 MCP 会话仍可继续调用，不代表原调用适合原样重试。

Qiling 等工具可能额外返回嵌套的 `error.type`、`error.message` 和 `error.details`，其中包含模拟地址、寄存器或其他复现上下文。调用方应同时兼容顶层错误信封和工具专用错误字段。

`run_js` 支持 `structured=True`，返回机器可读结果而不是历史文本：`{ok, text, result, error, traceback, run_id, generation, session_id, phase, timeout_s}`。其中 `error` 是结构化信封；`phase` 标明失败阶段（`session_busy` / `host_call_pending` / `executing` / `awaiting_host_call` / `worker_error` / `worker_exit`）；`host_call_abandoned` 表示超时时宿主调用仍在执行；`traceback` 保留 worker 侧异常（此前被丢弃）。默认 `structured=False` 仍返回历史文本，两条路径的结果一致。

推荐的恢复顺序：

1. 每次调用先判断 `ok === false`，不要只依赖捕获 MCP 传输异常。
2. 参数错误先修正参数；未加载 IDA 时调用 `set_binary_path` 或 `open_ida_database`。
3. 状态或依赖异常先调用 `engine_status` 和 `engine_diagnostics`，再决定降级到静态分析、缩小范围或跳过当前步骤。
4. 仅对超时、暂态后端错误执行有限次数重试；参数错误、依赖缺失和确定性模拟 fault 不应原样循环重试。
5. 记录 `tool`、`error_type`、`message` 和必要的 `error.details`；持久化日志前对 `arguments` 中的敏感路径或数据脱敏。

`run_js` 在 `spawn` worker 进程中执行脚本，worker 默认**跨调用保活**（warm）：首次调用承担一次 `extensions`（angr/qiling/z3）重导入，后续调用复用同一进程，避免每轮重复支付冷启动。`timeout` 默认 30 秒、最大 300 秒；超时会销毁 worker 并返回 `RunTimeout`，STPyV8、Qiling/Unicorn、angr/Z3 等 worker 内原生扩展崩溃会返回 `WorkerCrashed`，两种情况下一轮都会重建 worker。切换 binary/IDB（`set_binary_path` / `open_ida_database`）也会先回收 worker，避免它的引擎缓存（如 angr project）仍绑定旧样本；单个 worker 默认服务 200 轮后主动回收。下一次调用使用新的 generation，FastMCP 主进程和当前 IDA facade 的 staged/history 保持可用。`engine_status.sandbox` 提供 generation、活动 run、`host_calls_inflight`、最近退出原因，以及 `worker`（`warm` / `alive` / `pid` / `runs`）。

如需每次调用都新建进程（例如定位跨轮状态污染），可在创建 `SandboxSupervisor` 时传 `warm=False`。

`timeout` 同样约束宿主调用（`require(...)` 触发的 IDA/扩展方法）。若超时发生时宿主调用仍在主进程执行，返回的 `RunTimeout` 会带 `host_call_abandoned: true`；在该调用真正结束前，新的 `run_js` 会返回 `HostCallPending`，`set_binary_path` / `open_ida_database` 也会拒绝切换 session，其他依赖 `_require_ida` 的工具同样会拒绝并提示重试，避免与未完成的 IDA 操作并发访问同一会话。

单个 session 同时只允许一个 `run_js`。脚本运行期间再次调用会返回 `SessionBusy`。结果仍保持若干 `[log] ...` 行加最终 `=> ...` 行；脚本及 bridge 异常写入最终错误对象。可通过 `max_log_lines`、`max_log_line_chars`、`max_log_chars` 和 `max_result_chars` 限制返回文本，日志被截断时会注明实际命中的边界（行数/单行字符数/总字符数）。

沙箱内的 `require(...)` 结果屏蔽了以下划线开头的属性，避免脚本绕过 IDA staged 写策略直接访问底层对象。`require.describe(name)` 会返回宿主对象的真实公开属性清单，不因远程引用而变空。宿主返回的集合支持 `for` / `list()` / `sum()` 等迭代：可迭代对象经分页拉取（每页 512 项），不会再因一次性物化超过传输上限而失败；远程对象还会区分方法（可调用）与数据属性，属性链上的对象用路径引用回传，不会随访问次数膨胀（按名字解析结果缓存，跨轮仍指向当前会话）。分页在父进程侧的物化受 100000 项上限约束，超出返回结构化错误而不是静默截断。

当前进程隔离覆盖 `run_js` 路径。直接调用独立的 Qiling/angr MCP 工具仍在 FastMCP 进程内执行，其原生访问冲突不属于该 worker 边界；MCP 传输断开也仍需客户端重连。

## JavaScript 沙箱中的 Z3

`run_js` 会在沙箱中提供 `require(name)`，用于获取已注册的分析能力。Z3 相关能力分为两个入口：

- `require('z3')`：纯 Z3 求解门面，适合构造约束、求解模型、简化表达式。
- `require('z3ida')`：面向 IDA 场景的 helper 层，复用 Z3 bit-vector 能力，并提供轻量指令/分支谓词分析入口。

### `require('z3')`

```js
var z3 = require('z3');

var x = z3.Int('x');
var y = z3.Int('y');
var s = z3.Solver();

s.add(z3.Gt(x, 0));
s.add(z3.Gt(y, 0));
s.add(z3.Eq(z3.Add(x, y), 10));

var result = s.check();
var model = s.model();
log(result + ': x=' + model.eval(x, true) + ', y=' + model.eval(y, true));
```

常用 API：

- 变量和值：`Int(name)`、`Bool(name)`、`Real(name)`、`BitVec(name, bits)`、`bitvec(name, bits)`、`IntVal(value)`、`BoolVal(value)`、`BitVecVal(value, bits)`、`bvv(value, bits)`
- 比较：`Eq(a, b)`、`Ne(a, b)`、`Lt(a, b)`、`Le(a, b)`、`Gt(a, b)`、`Ge(a, b)`、`ULT(a, b)`、`ULE(a, b)`、`UGT(a, b)`、`UGE(a, b)`
- 运算：`Add(a, b)`、`Sub(a, b)`、`Mul(a, b)`、`BVAnd(a, b)`、`BVOr(a, b)`、`BVXor(a, b)`、`BVNot(a)`、`Shl(a, b)`、`LShR(a, b)`、`Extract(high, low, value)`、`Concat(...values)`
- 逻辑：`And(...args)`、`Or(...args)`、`Not(arg)`、`Implies(a, b)`
- 求解：`Solver()`、`solve(constraints)`、`isAlwaysTrue(expr)`、`isAlwaysFalse(expr)`、`simplify(expr)`、`exprToString(expr)`、`toString(obj)`

`solve(constraints)` 返回普通 JS 友好的结构：

```js
var x = z3.bitvec('x', 8);
var solved = z3.solve([z3.Eq(x, z3.bvv(1, 8))]);
log(solved.result + '/' + solved.model.x); // sat/0x01
```

bit-vector 模型值会以十六进制字符串返回，避免跨 JS/Python 边界时丢失大整数精度。

### `require('z3ida')`

`z3ida` 提供与 `z3` 一致的常用 helper，并增加 IDA 相关入口：

```js
var z3 = require('z3');
var z3ida = require('z3ida');

var x = z3ida.bitvec('x', 8);
var solved = z3ida.solve([z3.Eq(x, z3ida.bvv(1, 8))]);
log(z3ida.isAlwaysTrue(z3.Eq(x, x)) + '/' + solved.model.x);
```

可用 helper：

- `bitvec(name, bits)`
- `bvv(value, bits)`
- `solve(constraints)`
- `isAlwaysTrue(expr)`
- `isAlwaysFalse(expr)`
- `simplify(expr)`
- `exprToString(expr)`

IDA 相关入口：

- `liftInstruction(ea, state)`：读取并尝试提升单条指令。
- `liftBlock(block_ea, state)`：从基本块起点线性提升有限条指令。
- `slicePredicate(branch_ea, opts)`：从条件跳转向前回溯最近的 `cmp` / `test` 谓词。
- `checkBranch(branch_ea, opts)`：用 Z3 判断分支条件是否恒真、恒假或未知。

示例：

```js
var ida = require('ida');
var z3ida = require('z3ida');

var r = z3ida.checkBranch(0x24F30, { window: 16, arch: 'x64' });
log(JSON.stringify(r, null, 2));

if (r.result === 'always_false') {
  ida.set_comment(0x24F30, '[z3] opaque predicate: always false\n' + r.simplified);
}
```

当前 `z3ida` 的指令语义是轻量实现，主要覆盖 x86/x64 常见 `cmp` / `test` 与部分条件跳转。完整 ISA 语义、内存别名、循环、跨函数数据流、ARM64 语义和复杂 flags 建模仍需要后续扩展。无 IDA 实例时，IDA 相关 API 会返回结构化错误，例如 `error.type === 'ida_required'`。

## Lab 沙箱编排

`run_js` 内的 `require('lab')` 提供面向逆向闭环的组合原语层：以 IDA `ea` 为规范坐标，分析结论与证据写入分析黑板（跨 `run_js` 可读），所有写回走 staged 通道——先暂存、`preview()` 核对、显式 `commit()`。`require('board')` 直接暴露底层 `AnalysisBoard`（`summary` / `counts` / `list` / `get` / `attach` / `save_snapshot` / `load_snapshot` / `artifact`），供脚本直接查询。

### 会话与坐标

| 原语 | 说明 |
| --- | --- |
| `lab.basis()` | 基本信息 `{image_base, input_path, arch}` |
| `lab.anchor(x)` | 把名字或地址（`int` / `"0x..."` / 符号）解析为 `{ea, name, func?, segment?}` |
| `lab.target(x, opts?)` | 解析为统一 Target 写入黑板；`opts: {force_kind, size, with_bytes, max_bytes}` |
| `lab.to_angr(ea[, project])` / `lab.from_angr(addr[, project])` | IDA `ea` 与 angr 重基址互换（project 缺省内部加载并缓存） |
| `lab.detect_arch()` | 架构信息（`arch_info()`） |

### 读与黑板

| 原语 | 说明 |
| --- | --- |
| `lab.decompile(x)` | 反编译伪代码（与 MCP `decompile_function` 同一实现） |
| `lab.disasm(x, {count})` / `lab.xrefs(x)` / `lab.bytes(x, size?)` | 反汇编 / `{to, from}` 交叉引用 / `{ea, size, hex}` |
| `lab.plan_emulation(x, opts?)` | qiling 可模拟性风险提示 |
| `lab.note(kind, ea, text, opts?)` / `lab.findings(kind?, target_id?)` | Finding 写入 / 查询 |
| `lab.hypothesis(ea, claim)` / `lab.hypotheses()` | 假设记录 / 列出 |
| `lab.targets()` / `lab.traces()` / `lab.paths()` | 黑板 Target / Trace / Path 列表 |
| `lab.board_summary()` | 黑板摘要（各类实体计数） |
| `lab.clear(kind?)` | 清空黑板（可按 kind） |
| `lab.save_snapshot(path)` / `lab.load_snapshot(path)` | 黑板快照落盘 / 恢复 |
| `lab.artifact(name, content)` | 产物写入 `artifacts/` 目录 |

### 写回（staged-only）

| 原语 | 说明 |
| --- | --- |
| `lab.annotate(ea, text, opts?)` | 暂存注释/改名/原型；`opts.kind: "disasm"|"decompiler"|"rename"|"prototype"|"local"` |
| `lab.preview()` | 待应用 diff 列表 |
| `lab.commit(backup?)` | 显式落地到临时 IDB 并入 history（给 backup 先存快照） |
| `lab.discard()` / `lab.undo()` | 丢弃暂存 / 回退最近一次 commit |
| `lab.save_idb(path)` | 把当前含改动的 IDB 持久化到 `.idb`/`.ida`/`.i64` |
| `lab.stage_rxstub_comments(results, opts?)` | rxstubs 日志暂存为注释（地址优先真实 callsite） |

所有 lab 暂存写共享 session 门面：跨 `run_js` 调用保持，`require('ida').preview()` 亦可见；`commit` 只改临时 IDB，落盘需 `save_idb`。

### 四个场景闭环

跟踪——IDA 函数 -> unicorn 跟踪 -> 调用/分支边、内存写、字符串候选归约后写入黑板。模拟 fault 容错：保留最大干净前缀，结果标 `truncated` 并附 `fault`：

```js
var lab = require('lab');
var t = lab.trace('decrypt', {max_steps: 2000, timeout: 30, trace_mem: true});
log(t.trace_id + ' steps=' + t.steps + ' truncated=' + t.truncated);
```

调试——`lab.emulate` 返回活的 `LabEmulator`（仅本轮 `run_js` 内有效；参数用 IDA 地址，内部换算；`map_segments: true` 把 IDB 各段映射到原地址使全局数据引用可用，缺省 shellcode 模式只映射目标字节）：

```js
var emu = lab.emulate(0x401000, {map_segments: true});
emu.step(16);                                   // -> {rip_ida, regs}
emu.regs(['rax']); emu.mem_read(0x405000, 32); emu.mem_write(0x405000, '00ff');
var sid = emu.save_state(); emu.restore_state(sid);
emu.bp(0x401200);                               // 观测断点（可带回调）
emu.run({until_ida: 0x401200, timeout: 10});
log(emu.to_ql(0x401200) + ' <-> ' + emu.to_ida(emu.rip()));
emu.trace({count: 200}); emu.record('mid-state');
```

反混淆——混淆扫描（opaque predicate / 常量折叠 / 间接跳转）+ z3 分支谓词判定 +（可选）具体执行确认：

```js
var d = lab.deob(null, {limit: 1000});      // x 省略则全库扫描；opaque predicate 逐条附 z3 分支判定
var b = lab.solve_branch(0x401234, {concrete: true});  // always_taken / never_taken / symbolic，可加具体执行确认
lab.annotate(0x401234, b.comment);          // 结论先暂存，preview 核对后 commit
```

路径跟随——具体前缀 -> 符号探索 -> 约束模型 -> 具体验证：

```js
var seed = lab.concrete_prefix(0x401000, {stop_at: 0x401100});
var p = lab.follow(0x401000, {goal: [0x4012a0], seed_regs: seed.regs, verify_concrete: true});
```

注意：`follow` 的 `goal` / `avoid` 必须是数组（元素为地址/符号名，可多个），实现按列表逐个换算 angr 地址，传标量会返回 `ok:false`。

语义说明：

- `lab.follow` 的 `found` 只在设置了 `goal` 时表示"到达 goal"；无 `goal` 时恒为 `false`，探索存活情况以 `active_count` 报告。
- `verify_concrete` 用 qiling 重放模型寄存器时自动忽略栈/IP 类寄存器（`rsp/esp/rbp/ebp/rip/eip`），只播撒标量寄存器；`reached` 以 `rip === goal` 判定。
- `lab.concrete_prefix` 容忍故障：已执行至少一条指令后 fault 时返回 `ok:true` 加 `faulted:true, fault:...` 的部分快照；零指令故障仍返回 `ok:false` 信封。
- `emu.trace()` 与 `lab.trace` 同样按 clean-prefix 容错：故障时二分搜索最大干净指令数重放，句柄停在干净终态。

## 项目结构

```text
main.py                     # 入口：加载配置并启动 FastMCP（sse / stdio）
headless_ida_mcp_server/
  server.py                 # 9 个 MCP 工具、SessionManager、引擎状态与诊断
  helper.py                 # Headless IDA 助手（ida_* 模块、反编译/反汇编）
  ida_facade.py             # 语义化 IDA 门面 + staged 写回 / preview / commit / undo
sandbox/
  vm.py                     # STPyV8 执行环境与 log/require 注入
  bridge.py                 # JS <-> Python 编组与属性屏蔽
  registry.py               # require(name) 对象注册表
  supervisor.py             # worker 生命周期、Pipe RPC、超时/崩溃/孤儿处理
  worker.py                 # worker 进程入口、远程引用、分页迭代、批量 RPC
  rpc.py                    # 门面侧批量调用助手
extensions/
  lab_ext.py                # require('lab')：地址锚点、四场景闭环
  lab_board.py              # 跨 run_js 的分析黑板（Target/Finding/Trace/Path/...）
  qiling_ext.py             # qiling / unicorn 模拟与 trace
  angr_ext.py               # 符号执行门面
  z3_ext.py / z3ida_ext.py  # 约束求解与分支谓词判定
  deobfuscation_ext.py      # 混淆扫描与 patch 计划
  rxstubs.js               # JS 侧 stub 语义层
docs/                       # 设计文档、Agent 指引、架构说明
test_*.py                   # 离线单测 + requires_ida / sse / slow 集成测试
```

## 测试脚本

当前仓库使用 pytest markers 区分离线、真实 IDA、SSE 和慢速测试：

- `test_sandbox.py`：不依赖 IDA 的 JS 沙箱、bridge 与输出边界测试。
- `test_sandbox_supervisor.py`：worker 成功、超时、崩溃、恢复、状态查询和 session 互斥测试。
- `test_sandbox_rpc.py`：宿主 RPC 编组、私有属性屏蔽、阻塞宿主调用的超时中断与恢复测试。
- `test_z3_bridge.py`：不依赖 IDA 的 Z3 沙箱桥接测试。
- `test_z3ida_bridge.py`：不依赖 IDA 的 z3ida helper 与错误返回测试。
- `test_qiling_bridge.py`：不依赖 IDA 的 qiling/unicorn bridge 测试。
- `test_angr_bridge.py`：不依赖 IDA 的 angr/claripy bridge 测试。
- `test_lab_board.py`：分析黑板 AnalysisBoard 的实体增删、attach、快照与 artifact 测试。
- `test_lab_ext.py`：LabFacade 原语与坐标换算的离线替身测试（FakeIDAFacade）。
- `test_lab_wiring.py`：`require('lab')`/`require('board')` 的 worker 根绑定与 staged 写回持久性测试。
- `test_mcp_surface.py`：收敛后 MCP 工具面（9 工具 + 2 prompt）与 `engine_status` 字段回归测试。
- `test_real_ida.py`：依赖真实 IDA 和样本二进制的端到端测试。
- `test_sse_client.py`、`test_merge.py`：依赖已启动 SSE 服务的客户端验证脚本。

示例：

```bash
python test_sandbox.py
python test_z3_bridge.py
python test_z3ida_bridge.py
python test_qiling_bridge.py
python test_angr_bridge.py
python test_lab_board.py
python test_lab_ext.py
python test_lab_wiring.py
python test_mcp_surface.py
```

真实 IDA 测试需要先准备本地样本文件，并确认脚本中的样本路径可用。

## 发布边界

仓库应只包含源码、配置模板、依赖声明、文档，以及用于测试的最小样本。以下内容属于本地运行产物或分析数据，不应进入正式发布：

- `.env`、`.env.*` 中的真实环境配置
- `.venv/` 虚拟环境
- `*.log` 日志文件
- `*.idb`、`*.i64`、`*.id0`、`*.id1`、`*.id2`、`*.nam`、`*.til`、`*.bak` IDA 产物
- `samples/`、`artifacts/` 下的分析样本或输出产物
- `sample.exe` 等本地测试二进制
- `.claude/`、`.superpowers/` 等本地 agent 工具与工作流状态

真实 IDA 测试使用本地测试样本：默认查找仓库根目录的 `sample.exe`，也可通过环境变量
`RXENGINE_SAMPLE` 指定其他路径；样本不存在时 `test_real_ida.py` 会整体跳过。新增分析
样本前请确认其来源、哈希与再分发授权。

## 生产化注意事项

当前项目默认更适合作为本地受控工具使用。暴露到网络或多人环境前，至少需要补齐认证/鉴权、资源限制、审计日志、任务隔离和自动化测试。

## 贡献

欢迎提交 Issue 和 Pull Request。开发环境、测试约定与提交规范见 [CONTRIBUTING.md](CONTRIBUTING.md)。参与本项目即表示同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

如果你发现了安全问题，请不要在公开 Issue 中披露，按 [SECURITY.md](SECURITY.md) 的方式私下报告。

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源，版权归 liankong <xhsw.new@qq.com> 所有。

第三方依赖（IDA Pro / headless-ida、angr、claripy、qiling、unicorn、z3、capstone、keystone、STPyV8、pyelftools 等）仍遵循各自许可证，详见 [NOTICE](NOTICE)。IDA Pro 是 Hex-Rays SA 的商业产品，本项目只调用本机已安装的 headless IDA，使用者需自行持有有效授权。