# Changelog

本文件记录 RXEngine 的主要变更。格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-10-26

首个开源版本。

### Added

- FastMCP 服务：9 个工具 + 2 个 prompt，分析闭环统一走 `run_js` 沙箱。
- `require('lab')` 组合原语：IDA/angr/qiling 地址锚定、分析黑板，以及四条闭环：
  `trace`、`emulate`、`deob` + `solve_branch`、`concrete_prefix` + `follow`。
- `AnalysisBoard` 跨 `run_js` 分析记忆：Target/Finding/Trace/Path/Hypothesis/Patch、
  实体上限、快照、artifact。
- staged IDA 写回：`annotate` → `preview` → `commit` / `undo` / `save_idb`。
- `run_js(structured=True)` 结构化结果；错误信封包含 `phase`、`session_id`、
  `timeout_s`、`host_call_abandoned`、`traceback`。
- 按 MCP 连接隔离的分析会话（`SessionManager`），空闲 TTL、容量上限与断连回收。
- warm worker 跨调用保活，超时/崩溃/切换样本时自动重建。
- batch RPC 与属性链记忆化，降低 worker ↔ 父进程往返。
- 离线单测，以及 `requires_ida` / `sse` / `slow` 标记的集成测试。

### Security

- `run_js` 在独立 worker 进程执行，原生扩展崩溃不影响主进程与 IDA 会话。
- 沙箱屏蔽下划线开头的私有属性，阻止绕过 staged 写策略。
- IDA 写回默认只暂存，显式 `commit` 才落地。
