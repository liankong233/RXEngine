# RXEngine 架构说明

本文面向希望修改或扩展 RXEngine 的开发者，说明进程模型、状态归属、RPC 协议、
Lab 编排层与错误/资源边界。用户文档见 [README.md](../README.md)。

## 1. 进程模型

```text
MCP client
   │  SSE / stdio
   ▼
FastMCP 主进程（长期存活）
   ├─ SessionManager          按连接隔离 EngineSession
   ├─ EngineSession
   │    ├─ IDA / IDAFacade    二进制、反编译、staged 写回
   │    ├─ AnalysisBoard      跨 run_js 的分析记忆
   │    └─ SandboxSupervisor  单飞 run_js、worker 生命周期、Pipe RPC
   ▼
worker 进程（保活，可替换）
   ├─ STPyV8                  JavaScript 运行时
   ├─ Registry               require(name) 的对象表
   ├─ LabFacade              组合原语（worker 本地）
   └─ qiling / angr / z3     本地引擎；IDA 调用经 RPC 回父进程
```

两条关键约束决定了上面所有设计：

1. **worker 会被随时杀死。** 超时、原生扩展崩溃、切换 binary 都会销毁进程。
   因此任何需要跨轮存活的东西都必须放在父进程（黑板、staged 写回、IDA 会话）。
2. **IDA 只在父进程。** worker 通过路径引用调用父进程的门面，不能直接持有 IDA 对象。

## 2. 会话生命周期

`SessionManager`（`headless_ida_mcp_server/server.py`）以 MCP 连接的
`ServerSession` 对象为键，每个键对应一个 `EngineSession`：

- `set_binary_path` / `open_ida_database` 在当前会话内切换样本：重置
  `session_id` 与黑板、回收 worker、关闭旧 IDA。
- 没有连接身份的调用（stdio、内部函数、测试）落到唯一 fallback 会话。
- 回收路径：连接对象被 GC 时 `weakref.finalize` 立即释放；空闲 30 分钟后按 TTL
  回收；超过 `max_sessions`（默认 4）时淘汰最久未使用的**空闲**会话。有活动 run
  的会话不会被抢占。

注意：身份绑定在传输连接上，重连会得到新会话，客户端需要重新加载样本。

## 3. worker 生命周期

`SandboxSupervisor`（`sandbox/supervisor.py`）每次 `run` 只允许一个脚本（单飞），
并维护一个可复用的 worker：

| 事件 | 处理 |
| --- | --- |
| 首次 / worker 已退出 | 新建 Pipe + Process，把首个请求作为进程参数传入 |
| 后续 run | 通过 Pipe 发送 `{"kind": "run", ...}` 复用进程 |
| 超时 | 终止进程、丢弃句柄，下一轮重建 |
| worker 异常退出 | 返回 `WorkerCrashed`，丢弃句柄 |
| `session_mutation()` | 发 `shutdown` 优雅退出后再切换会话 |
| 达到 `max_worker_runs`（默认 200） | 本轮结束后主动回收 |

worker 内 `extensions`、registry、各门面只构建一次。`WorkerRPCClient.begin_run()`
在每轮开始时更新 `run_id` / `generation`，因此跨轮复用的 `RemoteObject` 发出的帧
始终属于当前轮。

worker 设为 daemon：父进程退出时自动回收，避免残留持有 angr 的孤儿进程；代价是
脚本不能在 worker 内再派生孙进程。

## 4. RPC 协议

worker 与父进程之间是一条 `multiprocessing.Pipe`，帧都带
`version / run_id / generation / seq`。版本匹配使用区间
`[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`，避免升级版本号时静默丢帧。

操作集合：

| 操作 | 说明 |
| --- | --- |
| `getattr` | 读取属性；不可按值编组的对象回传路径引用 |
| `call` | 调用方法；参数/返回值经编组 |
| `getitem` | 下标访问 |
| `iter_page` | 分页迭代，每页 512 项 |
| `describe` | 宿主侧内省公开属性，供 `require.describe()` |
| `len` / `bool` | 长度/真值 |
| `batch` | 一次执行多个子操作，顺序保持、错误隔离 |

编组规则（`_encode_value` / `_encode_call_result`）：

- 标量与容器按值传输；非容器对象回传
  `{"__remote_ref__": target, "__callable__": bool}`。
- `target` 是路径（`root` + `attr`/`item` 步骤），父进程每次调用时重新解析。因此
  引用不会因属性链访问次数增长，也能跨轮指向当前会话。
- worker 侧按名字缓存路径引用（`RemoteObject._attrs`），属性链访问从 3 次 RPC
  降为 1 次；按值返回的数据属性不缓存。

超时语义：host call 在 daemon 线程执行，supervisor 用独立 deadline 等待其响应。
若超时时宿主调用仍在执行，返回的 `RunTimeout` 带 `host_call_abandoned: true`；在
它结束前，新的 run 返回 `HostCallPending`，会话切换也会被拒绝（`has_orphan_host_call`）。

分页在父进程侧物化，受 `_MAX_ITER_ITEMS`（100000）约束，超限返回结构化错误。当前
没有做游标保活：已注册 API 不向 JS 返回生成器，而持有 IDA 游标跨页叠加写回有崩溃
风险。新增返回生成器的 API 时应重新评估。

## 5. Lab 编排层

`require('lab')` 由 `extensions/lab_ext.py` 实现，是 worker 本地对象，构造时不发
RPC。它把三套地址空间统一到 IDA 的 `ea`：

| 引擎 | 换算 |
| --- | --- |
| angr | `rebased = mapped_base + (ea - ida_image_base)` |
| qiling | `ql = entry_point + (ea - orig_ea)` |

黑板 `AnalysisBoard`（`extensions/lab_board.py`）在父进程，只存可序列化数据：
`Target` / `Finding` / `Trace` / `Path` / `Hypothesis` / `Patch`。总量上限 5000
实体，超限置 `overflow` 并拒绝继续写入；支持快照与 artifact。

写回一律 staged：`annotate` 只进 `IDAFacade._staged`，`preview()` 查看 diff，
`commit()` 才应用并进入 history，`undo()` 逆序回退。Lab 的门面级调用路由到
worker 经 RPC 访问的**父进程 session 门面**，所以暂存区跨 `run_js` 存活，不会出现
worker 内自包门面的 split-brain。

四个场景闭环：

- `lab.trace`：IDA 函数 → qiling trace → 归约为调用/分支边、热点块、内存写。
- `lab.emulate`：返回 `LabEmulator`，支持 step/regs/mem_read/mem_write/bp/
  save_state/restore_state。
- `lab.deob` + `lab.solve_branch`：扫描 + Z3 谓词判定，可选具体执行确认。
- `lab.concrete_prefix` + `lab.follow`：具体前缀 → angr 符号探索 → 约束模型 →
  qiling 具体回放验证。

## 6. 错误模型

- MCP 工具边界统一兜底：任何 Python 异常变成 `{ok:false, error_type, message,
  tool, arguments, recoverable:true}`。
- `run_js` 默认返回历史文本；`structured=True` 返回结构化结果，错误信封包含
  `phase`（`session_busy` / `host_call_pending` / `executing` /
  `awaiting_host_call` / `worker_error` / `worker_exit`）、`session_id`、
  `timeout_s`、`host_call_abandoned`、`exit_code`，worker 侧 traceback 单独放在
  `traceback` 字段（不撑大默认文本）。

## 7. 资源边界

| 边界 | 默认值 |
| --- | --- |
| `run_js` 超时 | 30s（最大 300s） |
| 日志行/单行/总字符/结果字符 | 1000 / 4000 / 100000 / 20000 |
| 黑板实体 | 5000 |
| trace 摘要 | 调用边 2000、分支边 2000、热点 50、内存写 500 |
| 批量 RPC | 256 子操作/帧 |
| 分页物化 | 100000 项 |
| worker 轮次 | 200 轮/进程 |
| 并发会话 | 4 |

## 8. 扩展点

**新增 `require(name)` 能力**：在 `extensions/__init__.py:register()` 里
`registry.register(name, facade)`。门面方法参数/返回值保持 int/str/bytes/dict/list，
远程引用会自动处理；需要批量调用时用 `sandbox.rpc.call_many`。

**新增 MCP 工具**：在 `headless_ida_mcp_server/server.py:register()` 中注册，并把
该工具加入 `test_mcp_surface.py` 的期望集合。工具需要会话时加
`ctx: Optional[Context] = None` 并用 `_session(ctx)` 解析。

**新增 Lab 原语**：在 `LabFacade` 上加方法，遵守「IDA ea 为规范坐标」「活对象只在
一轮内有效」「写回走 staged」三条约束。

## 9. 测试策略

- 默认 `pytest` 只跑离线用例（`requires_ida` / `sse` / `slow` 被 deselect）。
- `test_sandbox_*` 用自定义 worker target 验证 RPC/超时/崩溃/批量/分页边界。
- `test_lab_*` 用 `FakeIDAFacade` 验证原语与黑板，不需要 IDA。
- `test_real_ida.py` 覆盖真实 IDA 的 parity、staged 跨轮、反混淆与路径跟随。
- `test_sse_client.py` 需要先启动服务，验证单连接跨工具复用同一会话。
