# RXEngine Lab 编排层设计

日期：2026-09-11
状态：待用户评审
范围：Lab 组合原语层 + MCP 面收敛

## 1. 背景

RXEngine 目前把逆向能力拆成一组互相独立、各管一段的门面：

| 门面 | 位置 | 能力 |
| --- | --- | --- |
| `ida` (`IDAFacade`) | 父进程，经 RPC 暴露 | IDA 只读 + staged 写回 |
| `raw_ida` (`IDA` 助手) | 父进程，经 RPC 暴露 | 17 个 IDA 模块（`idaapi`/`ida_hexrays`/…） |
| `qiling` (`QilingFacade`) | worker 本地 | unicorn/qiling 模拟、trace、字符串解密 |
| `angr` (`AngrFacade`) | worker 本地 | 符号执行、hook、约束 |
| `z3` / `z3ida` | worker 本地 | 求解、指令/分支谓词 |
| `deobfuscation` | worker 本地 + 远程 `ida` | 混淆扫描、patch 计划 |
| `binary`/`capstone`/`keystone`/pyelftools | worker 本地 | 解析、反汇编、汇编 |

能力齐全，但 **Agent 必须自己在一次 `run_js` 里把多者粘起来**：从 IDA 取函数范围与字节 → 判断能否模拟 → 换算地址 → 跑 emulator → 把结果映射回 IDA → 暂存注释。当前痛点：

1. **三套地址空间**：IDA `ea`、angr `rebased_addr`/`linked_addr`（依赖 `mapped_base`）、qiling 模拟地址（依赖每实例 `entry_point` 与 `orig_ea`）。换算散落在各门面。
2. **跨 `run_js` 无记忆**：`run_js` 每次 spawn 新 worker，活对象一律消失；分析结论没有落脚点，Agent 只能把中间结果塞进对话。
3. **写回流程分散**：暂存、preview、commit 需要 Agent 自己记得走 `ida` 门面。

同时 MCP 侧有 53 个工具，其中绝大多数（qiling/angr/deobfuscation/细粒度 IDA 读写）与沙箱能力重复，反而诱导 Agent 绕开沙箱、把一次闭环拆成多次无状态调用。

## 2. 目标与非目标

**目标**

- 提供 `require('lab')`：一个会话对象，暴露跨引擎地址锚点、分析黑板、引擎组合原语，让 Agent 用少量原语流畅拼出「跟踪 / 调试 / 反混淆 / 路径跟随」。
- 分析记忆（Target/Finding/Trace/Path/Hypothesis）常驻父进程，跨 `run_js` 存活、随二进制切换重置。
- 收敛 MCP 面：只保留引导、状态与少量 IDA 只读工具；其余能力由沙箱闭环承接。
- 写回一律 staged，`commit` 显式触发。

**非目标**

- 不做父→worker 双向 RPC。所有编排发生在 worker 脚本内，父进程只提供 IDA 与黑板。
- 不跨 `run_js` 保活活引擎对象（`angr.Project`、`Qiling` 实例仅在一轮内有效）。跨轮记忆是**数据**，不是活对象。
- 不自动 commit、不自动改字节。

## 3. 关键约束

1. **worker 每次新建**：任何需要跨轮的东西必须在父进程。这是黑板存在的根本原因。
2. **RPC 已有语义**：支持 `getattr`/`call`/`getitem`/`iter_page`/`describe`/`len`/`bool`；标量与容器按值传，非容器对象以「引用」（handle 或路径）回传，引用带 `__callable__` 提示；集合分页（每页 512）。Lab 的返回值必须落在这些语义内。
3. **地址空间**：
   - 规范坐标 = IDA `ea`。
   - angr：`rebased = mapped_base + (ea - ida_image_base)`（`mapped_base` 需已加载 project）。
   - qiling：`ql = entry_point + (ea - orig_ea)`，`orig_ea` 是构造该实例时的 IDB 起点（`to_ql`/`to_ida` 已有实现）。

## 4. 架构

```
┌──────────────────────── MCP 侧（薄） ────────────────────────┐
│ run_js · set_binary_path · open_ida_database                 │
│ engine_status · engine_diagnostics                           │
│ decompile_function · decompile_checked ·                     │
│ disassemble_function · get_entry_points                      │
└───────────────────────────┬──────────────────────────────────┘
                            │ run_js 启动
┌───────────────────────────▼──────────────────────────────────┐
│ worker 进程（每轮新建）                                       │
│   require('lab')  = LabFacade                                │
│     ├─ qiling / angr / z3 / z3ida / deobfuscation（本地）     │
│     └─ ida / raw_ida / board（RPC 回父进程）                  │
└───────────────────────────┬──────────────────────────────────┘
                            │ RPC (Pipe)
┌───────────────────────────▼──────────────────────────────────┐
│ FastMCP 主进程（跨 run_js 存活）                              │
│   EngineSession                                              │
│     ├─ ida (IDA) · ida_facade (IDAFacade)                    │
│     └─ board (AnalysisBoard)  ← 分析记忆，随 session 重建     │
└──────────────────────────────────────────────────────────────┘
```

要点：`board` 与 `ida` 一样作为 RPC root 注册（`_sandbox_roots()` 增加 `"board"`）；`request` 增加 `board_bound`；worker 在 `extensions.register(registry, ida=raw_ida, board=client.root("board"))` 时注入。

## 5. 黑板实体模型

黑板（`extensions/lab_board.py`，父进程）只保存可序列化数据，方法只收发原始类型/dict。所有实体有 `id`（`f"{kind}-{seq}"`）、`created_at`、`session_id`。

| 实体 | 字段 |
| --- | --- |
| `Target` | `id, kind: "func"|"region", ea, name, start_ea, end_ea, size, arch, bits, bytes_hex?, segment?` |
| `Finding` | `id, kind, ea, text, evidence: dict, severity, action?: PatchIntent, target_id?` |
| `Trace` | `id, target_id, entry_ea, steps, truncated, call_edges: [{ea, to_ea, to_name?}], branch_edges, hot_blocks: [{ea, count}], mem_writes: [{ea, size, value}], strings?: [...]` |
| `Path` | `id, target_id, found, goal_ea, blocks_ida: [ea], regs: {name: int}, constraints: [str], model: dict?, verified?: bool` |
| `Hypothesis` | `id, ea, claim, status: "open"|"confirmed"|"refuted", evidence_id?` |
| `PatchIntent` | `{op, ea, old?, new?, note?}`（与 `IDAFacade._stage` 语义一致） |

**上限**（防止父进程内存与 RPC 体积失控）：`Trace` 事件默认只存摘要，`call_edges`/`branch_edges` 上限 2000、`hot_blocks` 200、`mem_writes` 500、`strings` 200，超限置 `truncated`；`Path.blocks_ida` 上限 5000。黑板总量上限（如 5000 实体），超限时 `lab.board` 返回 `overflow` 标记而非静默丢弃。

## 6. 核心原语（`require('lab')`）

### 6.1 会话与坐标

```
lab.basis()                      -> {image_base, arch, bits, input_path, session_id}
lab.anchor(x)                    -> {ea, name, func?: {start_ea, end_ea, name}, segment?}
                                    # x: int | "0x..." | 符号名
lab.target(x, opts?)             -> Target            # opts: {force_kind, name_hint}
lab.to_angr(ea, project)         -> int               # angr rebased
lab.from_angr(addr, project)     -> int               # -> IDA ea
lab.to_ql(ea, emu)               -> int               # 需要 LabEmulator / qiling 实例
lab.from_ql(ql_ea, emu)          -> int
```

`basis()` 与 `anchor()` 只读 IDA，廉价。`to_angr` 需要已加载 project（`lab.follow` 内部缓存 project）。`to_ql` 需要活实例，固以实例方法形式挂在 `LabEmulator`/`QLHandle` 上（见 6.3）。

### 6.2 黑板

```
lab.note(kind, data)                      -> Finding
lab.findings(kind?, target_id?)           -> [Finding]
lab.targets()                             -> [Target]
lab.traces() / lab.paths()                -> [Trace] / [Path]
lab.hypothesis(ea, claim)                 -> Hypothesis
lab.link(finding_id, evidence_id)
lab.snapshot()                            -> {counts, session_id, sandbox}
lab.clear(kind?)
lab.save_snapshot(path) / lab.load_snapshot(path)  -> {ok, path, counts}
lab.artifact(name, content)               -> {ok, path}    # 写 artifacts/，承接 write_strings_results
```

`lab.board` 同时暴露底层 `board` 引用，供直接查询；MCP 侧不再提供黑板工具（除状态摘要）。

### 6.3 写回（staged-only）

```
lab.annotate(ea, text, opts?)   -> PatchIntent
        # opts.kind: "disasm"|"decompiler"|"rename"|"prototype"|"local"
lab.propose(patch_intent)       -> PatchIntent
lab.preview()                   -> [PatchIntent]     # 转发 IDAFacade.preview
lab.commit(backup?)             -> dict              # 显式；记录到黑板
lab.discard() / lab.undo()      -> int
lab.save_idb(path)              -> bool
```

### 6.4 组合原语

```
lab.decompile(x, opts?)         -> str               # 走 IDAFacade.decompile
lab.disasm(x, opts?)            -> [insn]            # 走 IDAFacade.disassemble
lab.xrefs(x, opts?)             -> {to: [...], from: [...]}
lab.bytes(x, size?)             -> hex str
lab.plan_emulation(x, opts?)    -> qiling.plan 结果（可模拟性风险）
lab.detect_arch()               -> {arch, bits, os_hint}
```

## 7. 四个场景闭环

### 7.1 跟踪 `lab.trace`

```
lab.trace(x, opts?) -> Trace 摘要 + 黑板记录
opts: {arch?, os?, regs?, max_steps?, timeout?, trace_mem?, trace_regs?,
       store_events?, strings?}
```

步骤：`lab.target(x)` → 若绑定 IDA，先 `qiling.plan(start, size)` 取可模拟性风险 → `qiling.trace_at(start, size, count=max_steps, orig_ea=start, …)`（trace_at 已把 `ida_ea` 归一化）→ 归约成 `Trace`（调用/分支边、热点块、内存写、字符串）→ `board.add_trace`。
返回摘要；`store_events=true` 时才把逐指令事件返回 JS（受 `max_steps` 限制）。若 `plan` 报 high 风险，返回 `{ok:true, warnings:[…], emulatable:false}` 让 Agent 决定先 hook 还是改走 `lab.emulate`。

### 7.2 调试 `lab.emulate` → `LabEmulator`

```
lab.emulate(x, opts?) -> LabEmulator          # 活句柄，仅本轮有效
opts: {arch?, os?, regs?, map_segments?=true, trace?}
```

`LabEmulator` 方法（全部以 IDA 地址为参数，内部换算；`map_segments=true` 时用 `qiling` 的 emulate_function 式段映射，使全局数据引用可用）：

```
emu.step(n=1)                 -> {rip_ida, steps, stopped?}
emu.run(until_ida?, max_steps?) -> {rip_ida, regs}
emu.regs(names?)              -> {name: int}
emu.set_regs({name: int})
emu.mem_read(ea, size)        -> hex str
emu.mem_write(ea, hex|bytes)
emu.bp(ea, cb?)               -> handle          # 内部 hook_address(ql_addr)
emu.code_base() / emu.to_ida(q) / emu.to_ql(ea)
emu.save_state(ranges?)       -> snapshot_id     # 寄存器 + 指定内存区间（默认 code+stack）
emu.restore_state(snapshot_id)
emu.trace_on() / emu.trace()  -> Trace
emu.record(name?)             -> 把当前状态写入黑板
```

错误（未映射内存、外部调用 fault）按现有 `QilingError`/信封返回，不抛穿轮次。

### 7.3 反混淆 `lab.deob` + `lab.solve_branch`

```
lab.deob(x?, opts?) -> {results: [Finding], scanned, matched, ...}  # x 省略则全库
opts: {limit?, max_func_size?, timeout?, concrete?}
```

`deobfuscation.scan` 定位 opaque predicate / 常量折叠 / 间接跳转；分支类逐条 `z3ida.checkBranch(branch_ea)` 得 `always_taken|never_taken|symbolic`；`concrete=true` 时用 `lab.emulate` 走具体前缀确认，冲突则标 `Hypothesis.status="refuted"`。Finding 写入黑板。

```
lab.solve_branch(ea, opts?) -> {classification, taken_ea, not_taken_ea,
                                confidence, comment, concrete_verified?}
```

结果经 `lab.annotate(ea, comment)` 暂存（`opts.stage=true`，默认 false，保持「先看后写」）。

### 7.4 路径跟随 `lab.concrete_prefix` + `lab.follow`

```
lab.concrete_prefix(x, opts?) -> {regs, mem_writes_summary, reached_ea?, steps, truncated}
opts: {arch?, os?, regs?, stop_at?, max_steps?, timeout?}
```

用 qiling 跑到 `stop_at`（锚点），把结束寄存器作为具体种子。

```
lab.follow(x, opts?) -> Path
opts: {goal?, avoid?, seed_regs?, seed_from_concrete?, args?, max_steps?, timeout?,
       max_active?, n?, veritesting?, dfs?, loop_bound?, symbolics?: [...], verify_concrete?}
```

步骤：加载/缓存 `angr.Project`（path 缺省取 `ida.get_input_file_path()`）→ `call_state(start)` 或 `blank_state`，`seed_regs`/`seed_from_concrete` 注入具体寄存器 → `goal`/`avoid` 经 `lab.to_angr` 换算 → `angr.explore_paths` → 命中后取首个 found state：`history.bbl_addrs` 换算成 IDA 基本块序列、读 `regs`/`mem`、收集约束；`symbolics` 交给 `angr.eval` 求具体值；`verify_concrete=true` 时用 qiling 按解出的具体输入重跑，确认能到达 goal。返回 `Path` 并写黑板。

闭环：具体前缀 → 符号探索 → 模型 → 具体验证。

## 8. MCP 面收敛

### 8.1 保留（9 tools + 2 prompts）

| 工具 | 理由 |
| --- | --- |
| `run_js` | 沙箱闭环唯一入口 |
| `set_binary_path` / `open_ida_database` | session 引导，沙箱无法自建 IDA session |
| `engine_status` | session/依赖/黑板/沙箱摘要（并入原 `engine_capabilities` 的模块与依赖信息） |
| `engine_diagnostics` | 健康检查（并入原 `reverse_readiness_check`） |
| `decompile_function` / `decompile_checked` | 高频只读，用户要求保留 |
| `disassemble_function` | 高频只读，用户要求保留 |
| `get_entry_points` | 入口点，启动分析常用 |
| `exploit_prompt` / `deobfuscation_prompt` | MCP prompt，非工具，用于引导 |

### 8.2 移除（44 tools）

- qiling/unicorn（11）：`emulate_code`、`trace_code`、`strings_code`、`scan_string_decryptors`、`scan_string_call_sites`、`emulate_function`、`scan_string_decrypt_chains`、`qiling_capabilities`、`qiling_plan`、`batch_strings_at`、`write_strings_results`
- deobfuscation（3）：`deobfuscation_scan`、`deobfuscation_patch_preview`、`stage_deobfuscation_patch`
- angr（3）：`angr_project_info`、`angr_function_range`、`angr_stage_result_comments`
- IDA 细粒度读（8）：`get_function`、`get_function_by_name`、`get_function_by_address`、`get_current_address`、`get_current_function`、`convert_number`、`list_functions`、`get_xrefs_to`
- IDA 预热（2）：`prepare_decompile`、`get_prepare_decompile_status`
- IDA 写/暂存（14）：`ida_preview`、`ida_commit`、`ida_discard`、`ida_undo`、`ida_save_idb`、`set_decompiler_comment`、`set_disassembly_comment`、`refresh_decompiler_widget`、`refresh_decompiler_ctext`、`rename_local_variable`、`rename_function`、`set_function_prototype`、`save_idb_file`、`save_ida_database`
- 其他（3）：`engine_capabilities`（并入 `engine_status`）、`reverse_readiness_check`（并入 `engine_diagnostics`）、`rxstubs_stage_log_comments`

合计 44 个，保留 9 个（53 − 9 = 44）。能力承接见 8.3。

> 说明：`convert_number` 直接丢弃（JS 一行可做）；`get_current_address`/`get_current_function` 在 headless 无「当前」语义；`refresh_decompiler_widget`/`refresh_decompiler_ctext` 是 UI 刷新，headless 无意义；`engine_capabilities`/`reverse_readiness_check` 合并进 `engine_status`/`engine_diagnostics`。

### 8.3 必须先补的 parity（否则属能力丢失）

| 目标 | 承接方式 |
| --- | --- |
| `decompile_function` / `decompile_checked` 的沙箱等价 | `IDAFacade.decompile(ea)` / `decompile_checked(ea)`，内部复用 `IDA.decompile_*` |
| `disassemble_function` 的沙箱等价 | `IDAFacade.disassemble(ea, count?)` |
| `get_entry_points` 的沙箱等价 | `IDAFacade.get_entry_points()` |
| `prepare_decompile` / 状态 | `IDAFacade.prepare_decompile(opts)` / `prepare_decompile_status()` |
| `write_strings_results` | `lab.artifact(name, content)`（父进程黑板落盘） |
| `rxstubs_stage_log_comments` | `lab.stage_rxstub_comments(log)` |
| `get_function*` / `list_functions` / `get_xrefs_to` | `require('ida')`：`get_function`、`get_name_ea`、`get_functions`、`get_xrefs_to/from` 已具备 |

保留的 4 个 IDA 只读 MCP 工具改为 **`IDAFacade` 的薄封装**，与沙箱走同一实现，避免两套逻辑。

## 9. 错误处理、边界与安全

- recipe 返回 `{ok:false, error_type, message, ...}` 信封而非抛异常；原语直接返回数据（异常由 `run_js` 边界转成 `=> {ok:false}`）。
- 所有 recipe 支持 `timeout`/`max_steps`，沿用 qiling/angr 现有预算机制与 `run_js` 外层超时。
- 黑板实体与事件有上限（第 5 节），超限显式标记。
- 写回 staged-only，`commit` 显式；`lab.annotate` 默认只暂存。
- 沿用既有：`require(...)` 屏蔽下划线私有属性；远程集合分页；引用带可调用性提示。
- `lab` 门面在 worker 本地构造，不新增 RPC 操作类型（只用现有 `getattr`/`call`/`getitem`/`iter_page`/`describe`）。

## 10. 测试

**离线**

- `test_lab_board.py`：实体增删查、上限与 `truncated`/`overflow`、`export`/`import` 往返、随 session 重置。
- `test_lab_anchor.py`：用假 IDA（FakeModule 风格）验证 `anchor`/`target`/`basis` 与 angr/qiling 换算数学。
- `test_lab_ext.py`：用 shellcode + 假 IDA 验证 `lab.trace`/`lab.emulate` 的基本闭环与信封；`lab.deob` 用构造的 opaque predicate 样本。

**真实 IDA**

- `test_real_ida.py` 增加 Lab 工作流：`lab.target('pre_c_init')` → `lab.trace` → `lab.deob` → `lab.follow`（goal 用函数内已知分支）。
- **跨 `run_js` 黑板持久化**：两次 `supervisor.run`，第一次 `lab.note`/`lab.target`，第二次读回，验证父进程存储。

**MCP 收敛回归**

- `test_sse_client.py` / `test_merge.py`：把 `get_function_by_name`/`decompile_function` 调用改为保留的 `decompile_function` + `run_js`，或直接改走 `run_js`。
- 新增断言：移除的工具名不再出现在 `mcp._tool_manager` 中；保留的 9 个仍在。

## 11. 文件布局与改动清单

新增：

- `extensions/lab_board.py` — `AnalysisBoard`（父进程，纯数据）
- `extensions/lab_ext.py` — `LabFacade`、`LabEmulator`、锚点数学
- `test_lab_board.py`、`test_lab_anchor.py`、`test_lab_ext.py`

修改：

- `extensions/__init__.py` — `register(registry, ida=None, board=None)`，注册 `lab`
- `sandbox/worker.py` — 读取 `request["board_bound"]`，注入 `board` root
- `headless_ida_mcp_server/server.py` — `EngineSession.board`；`_sandbox_roots()` 加 `board`；`_new_ida_session` 重建 board；移除 44 个工具；4 个只读工具改走 facade；`engine_status`/`engine_diagnostics` 合并
- `headless_ida_mcp_server/ida_facade.py` — 新增 `decompile`/`disassemble`/`get_entry_points`/`prepare_decompile`(+status)
- `docs/prompt.md`、`README.md` — agent 指引改为「沙箱闭环优先」，列出 `require('lab')` 原语
- `test_sse_client.py`、`test_merge.py`、`test_rxstubs_server.py` — 适配移除的工具

不改：`sandbox/supervisor.py` 的 RPC 协议与超时/黑板无关部分。

## 12. 交付顺序

1. **M1 底层**：`AnalysisBoard` + `EngineSession.board` + `board` RPC root + 锚点数学 + `IDAFacade` parity（decompile/disassemble/entry_points/prepare）。
2. **M2 Lab 核心**：`LabFacade` 会话/锚点/黑板/写回原语，注册 `require('lab')`/`require('board')`。
3. **M3 四场景**：trace / emulate / deob+solve_branch / concrete_prefix+follow。
4. **M4 MCP 收敛**：删 44 工具、4 只读工具改 facade、`engine_*` 合并。
5. **M5 文档与测试**：prompt/README 重写，测试补齐。

每步独立可测；M1 完成即可验证跨轮黑板，M2 完成即可验证锚点与写回，M3 起逐场景验证。

## 13. 已确认决策

- 形态：**组合原语 Lab 对象**（用户选择 A）。
- 首版范围：**核心 + 四场景各一条闭环**（用户选择）。
- MCP 收敛：**多保留 IDA 只读工具**（`decompile_function`/`decompile_checked`/`disassemble_function`/`get_entry_points`），其余 44 个移除。
- 黑板挂在 `EngineSession`，随二进制切换重建。
- `lab.follow` 的路径跟随为「具体前缀 → 符号探索 → 模型 → 具体验证」。
