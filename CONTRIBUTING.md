# 贡献指南

感谢你愿意改进 RXEngine。本文说明开发环境、测试约定和提交规范。

## 开发环境

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env               # 设置 IDA_PATH
```

需要本机可执行的 headless IDA。没有 IDA 时，离线单测仍可运行（依赖 IDA 的用例
默认被 deselect）。

## 运行测试

```bash
# 离线用例（默认）
python -m pytest -q

# 单个模块
python -m pytest test_sandbox_rpc.py -q

# 真实 IDA 集成测试
python -m pytest -o addopts="" -m requires_ida -q

# SSE 端到端（先启动服务）
python main.py --transport sse
python -m pytest -o addopts="" test_sse_client.py -q
```

真实 IDA 测试需要一个本地样本：默认使用仓库根目录的 `sample.exe`，也可用
`RXENGINE_SAMPLE` 指定路径；样本不存在时该文件会自动跳过。样本不应提交到仓库。

提交前请至少保证离线套件全绿，并保持测试输出干净（不要新增 warning/noise）。

## 代码约定

- Python `>=3.10`，4 空格缩进，行宽与现有代码一致。
- 注释用中文，解释**约束和原因**，不要复述代码在做什么。
- 新逻辑优先补测试；涉及跨进程/超时/崩溃的改动请覆盖失败路径。
- 门面方法（`extensions/*.py`）的参数和返回值保持 int/str/bytes/dict/list，
  这样能直接跨 RPC 编组。
- 不要在仓库中提交真实路径、凭据、分析样本、IDA 数据库或日志。

## 新增能力的位置

| 目标 | 位置 |
| --- | --- |
| 新的 `require(name)` 门面 | `extensions/__init__.py:register()` + 新模块 |
| 新的 Lab 原语 | `extensions/lab_ext.py`（遵守 ea 坐标、staged 写回） |
| 新的 MCP 工具 | `headless_ida_mcp_server/server.py:register()`，并更新 `test_mcp_surface.py` |
| 新的 RPC 操作 | `sandbox/supervisor.py` + `sandbox/worker.py`，同时加协议测试 |

修改 RPC 帧格式或新增字段时，请保持向后兼容：新字段用 `.get()` 读取，必要时
提升 `PROTOCOL_VERSION`（supervisor 接受 `[MIN, CURRENT]` 区间）。

## 提交规范

提交信息使用 `<type>: <摘要>`，type 取 `feat` / `fix` / `perf` / `test` /
`docs` / `refactor` / `chore`。摘要用一句话说明结果；细节放正文。

示例：

```text
fix: 分页物化加上限，超大迭代器返回结构化错误
perf: RPC 属性链记忆化，属性访问从 3 次往返降到 1 次
```

## Pull Request 清单

- [ ] 说明动机与行为变化（含不兼容点）
- [ ] 新增/修改的测试通过，离线套件全绿
- [ ] 文档同步更新（README / docs/ARCHITECTURE.md / docs/prompt.md）
- [ ] 没有提交 `.env`、日志、样本或 IDA 产物
- [ ] 确认可以对本次贡献按 Apache-2.0 授权

提交 PR 即表示你同意以 [Apache License 2.0](LICENSE) 授权你的贡献（inbound =
outbound），并遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。

## 报告问题

- 功能缺陷与建议：使用 GitHub Issue 模板，附最小复现脚本和 `engine_status` /
  `engine_diagnostics` 输出。
- 安全相关问题：不要开公开 Issue，按 [SECURITY.md](SECURITY.md) 私下报告。
