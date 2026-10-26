# -*- coding: utf-8 -*-
import threading
import time
import weakref
from dataclasses import dataclass, field
from importlib.util import find_spec
from pathlib import Path
from typing import Annotated, Optional
from uuid import uuid4

from mcp.server.fastmcp import Context
from mcp.server.fastmcp.prompts import base

import extensions
from extensions.angr_ext import AngrFacade
from extensions.lab_board import AnalysisBoard
from extensions.qiling_ext import QilingFacade
from headless_ida_mcp_server.helper import IDA
from headless_ida_mcp_server.ida_facade import IDAFacade
from sandbox.registry import Registry
from sandbox.supervisor import SandboxSupervisor


@dataclass
class EngineSession:
    session_id: str = field(default_factory=lambda: uuid4().hex)
    binary_path: Optional[str] = None
    ida: Optional[IDA] = None
    ida_facade: Optional[IDAFacade] = None
    registry: Registry = field(default_factory=Registry)
    board: AnalysisBoard = field(default_factory=AnalysisBoard)
    supervisor: Optional[SandboxSupervisor] = None

    def info(self) -> dict:
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "ida_bound": self.ida is not None,
            "facade_ready": self.ida_facade is not None,
            "modules": self.registry.names(),
        }


def _sandbox_roots_for(session: EngineSession) -> dict:
    if session.ida is None or session.ida_facade is None:
        return {}
    return {"ida": session.ida_facade, "raw_ida": session.ida, "board": session.board}


def _new_session() -> EngineSession:
    """构建一个分析会话：登记扩展，并挂一个独立的（保活）沙箱 supervisor。"""
    session = EngineSession()
    session.supervisor = SandboxSupervisor(
        lambda s=session: _sandbox_roots_for(s),
        session_id_provider=lambda s=session: s.session_id,
        warm=True)
    extensions.register(session.registry, board=session.board)
    return session


class SessionManager:
    """按 MCP 连接隔离分析会话。

    - 每个 SSE 连接对应一个 EngineSession（各自的 binary/IDA/黑板/worker）；
    - 无法归属到连接的调用（stdio、内部调用、测试）落到单一 fallback 会话，
      保持单会话语义不变；
    - 连接断开时经 weakref finalizer 回收，空闲 TTL 与容量上限另作兜底。
    """

    def __init__(self, max_sessions=4, idle_ttl=1800.0):
        self._lock = threading.RLock()
        self._sessions = {}
        self._last_seen = {}
        # LRU 顺序用递增序号而非墙钟：time.monotonic() 在 Windows 上分辨率约 15.6ms，
        # 同批创建的会话时间戳会并列，淘汰将变成任意选择。
        self._order = {}
        self._tick = 0
        self._keys = weakref.WeakKeyDictionary()
        self._max_sessions = max(1, int(max_sessions))
        self._idle_ttl = float(idle_ttl)
        self._fallback = None

    def for_request(self, ctx=None) -> EngineSession:
        key = self._key_for(ctx)
        if key is None:
            return self._fallback_session()
        with self._lock:
            self._evict_idle_locked()
            session = self._sessions.get(key)
            if session is None:
                self._enforce_capacity_locked()
                session = _new_session()
                self._sessions[key] = session
            self._touch_locked(key)
            return session

    def _touch_locked(self, key):
        self._tick += 1
        self._order[key] = self._tick
        self._last_seen[key] = time.monotonic()

    def counts(self) -> dict:
        with self._lock:
            return {"active": len(self._sessions), "max": self._max_sessions,
                    "idle_ttl": self._idle_ttl, "fallback": self._fallback is not None}

    def close_all(self):
        """回收全部会话（服务关闭/测试清理用）。"""
        with self._lock:
            sessions = list(self._sessions.values())
            fallback = self._fallback
            self._sessions.clear()
            self._last_seen.clear()
            self._order.clear()
            self._fallback = None
        for session in sessions:
            self._close_session(session)
        if fallback is not None:
            self._close_session(fallback)

    # ---- internals ----
    def _fallback_session(self) -> EngineSession:
        with self._lock:
            if self._fallback is None:
                self._fallback = _new_session()
            return self._fallback

    def _key_for(self, ctx):
        if ctx is None:
            return None
        try:
            server_session = ctx.request_context.session
        except Exception:  # noqa: BLE001 — 取不到连接身份则退化为单会话
            return None
        if server_session is None:
            return None
        with self._lock:
            key = self._keys.get(server_session)
            if key is None:
                key = uuid4().hex
                try:
                    self._keys[server_session] = key
                    weakref.finalize(server_session, self._drop_key, key)
                except TypeError:  # 不可弱引用/不可哈希：退化为单会话
                    return None
            return key

    def _drop_key(self, key):
        """连接断开（ServerSession 被回收）时释放对应会话。"""
        with self._lock:
            session = self._sessions.get(key)
        if session is None:
            return
        if self._close_session(session):
            with self._lock:
                self._forget_locked(key)

    def _forget_locked(self, key):
        self._sessions.pop(key, None)
        self._last_seen.pop(key, None)
        self._order.pop(key, None)

    def _evict_idle_locked(self):
        if self._idle_ttl <= 0:
            return
        now = time.monotonic()
        stale = [key for key, seen in self._last_seen.items()
                 if key in self._sessions and now - seen > self._idle_ttl]
        for key in stale:
            session = self._sessions.get(key)
            if session is None:
                self._forget_locked(key)
                continue
            if self._close_session(session):
                self._forget_locked(key)

    def _enforce_capacity_locked(self):
        while len(self._sessions) >= self._max_sessions:
            key = self._oldest_idle_key_locked()
            if key is None:
                # 全部忙时不抢占：宁可临时超出上限，也不打断活动分析。
                return
            session = self._sessions.get(key)
            if session is None or not self._close_session(session):
                self._last_seen.pop(key, None)
                return
            self._forget_locked(key)

    def _oldest_idle_key_locked(self):
        candidates = [key for key in self._order
                      if key in self._sessions and self._is_idle(self._sessions[key])]
        return min(candidates, key=lambda k: self._order[k]) if candidates else None

    @staticmethod
    def _is_idle(session) -> bool:
        supervisor = session.supervisor
        if supervisor is None:
            return True
        status = supervisor.status()
        return (status.get("active_run") is None
                and not status.get("host_calls_inflight"))

    @staticmethod
    def _close_session(session) -> bool:
        """关闭会话；有活动 run 时放弃并返回 False（留待后续回收）。"""
        supervisor = session.supervisor
        if supervisor is not None:
            if supervisor.status().get("active_run") is not None:
                return False
            try:
                supervisor.close()
            except Exception:  # noqa: BLE001
                pass
        if session.ida is not None:
            try:
                session.ida.close()
            except Exception:  # noqa: BLE001 — 清理失败不应阻塞其它会话回收
                pass
            session.ida = None
        return True


_manager = SessionManager()


def _session(ctx=None) -> EngineSession:
    """解析当前请求所属的分析会话；ctx 缺失时落到 fallback（单会话）会话。"""
    return _manager.for_request(ctx)


def _require_ida(session: Optional[EngineSession] = None) -> IDA:
    """返回已加载的 IDA 实例；未先 set_binary_path 则报错。"""
    session = session or _session()
    if session.ida is None:
        raise ValueError("Binary path not set")
    if session.supervisor is not None and session.supervisor.has_orphan_host_call():
        raise RuntimeError(
            "a previous run_js host call is still running; retry after it finishes")
    return session.ida


def _require_ida_facade(session: Optional[EngineSession] = None) -> IDAFacade:
    """返回当前 IDB 绑定的 IDA 门面。"""
    session = session or _session()
    if session.ida_facade is None:
        _require_ida(session)
        raise ValueError("IDA facade not initialized")
    if session.supervisor is not None and session.supervisor.has_orphan_host_call():
        raise RuntimeError(
            "a previous run_js host call is still running; retry after it finishes")
    return session.ida_facade


_IDB_EXTENSIONS = {".idb", ".ida", ".i64"}


def _is_idb_path(path: str) -> bool:
    return Path(str(path)).suffix.lower() in _IDB_EXTENSIONS


def _dependency_status() -> dict:
    modules = {
        "STPyV8": "STPyV8",
        "angr": "angr",
        "claripy": "claripy",
        "z3": "z3",
        "qiling": "qiling",
        "unicorn": "unicorn",
        "capstone": "capstone",
        "keystone": "keystone",
        "pyelftools": "elftools",
    }
    return {name: find_spec(module) is not None for name, module in modules.items()}


def _new_ida_session(session: EngineSession, path: str) -> dict:
    """在当前会话内切换到新的 binary/IDB。

    换样本即换分析上下文：session_id 与黑板一并重置；worker 由 session_mutation
    回收，避免其引擎缓存（如 angr project）仍绑定旧样本。
    """
    supervisor = session.supervisor
    with supervisor.session_mutation():
        ida = IDA(path)
        try:
            ida_facade = IDAFacade(ida)
            board = AnalysisBoard()
            registry = Registry()
            registry.register("ida", ida_facade)
            # lab_ida：把会话门面交给 lab，使其 staged 写回与沙箱 require('ida')
            # 的预览/提交共用同一份暂存区，跨 run_js 存活。
            extensions.register(registry, ida=ida, board=board, lab_ida=ida_facade)
        except Exception:
            ida.close()
            raise
        previous_ida = session.ida
        session.session_id = uuid4().hex
        session.binary_path = path
        session.ida = ida
        session.ida_facade = ida_facade
        session.registry = registry
        session.board = board
        if previous_ida is not None:
            try:
                previous_ida.close()
            except Exception:  # noqa: BLE001 — 旧 session 清理失败不应影响已切换的新 session
                pass
        return session.info()


def _engine_status(session: Optional[EngineSession] = None) -> dict:
    session = session or _session()
    facade_status = session.ida_facade.status() if session.ida_facade is not None else {"staged": 0, "committed_batches": 0}
    return {
        **session.info(),
        "database_type": "idb" if session.binary_path and _is_idb_path(session.binary_path) else "binary",
        "policy": "staged_ida_writes",
        "facade_status": facade_status,
        "board": session.board.summary(),
        "dependencies": _dependency_status(),
        "sandbox": session.supervisor.status() if session.supervisor is not None else {},
        "sessions": _manager.counts(),
        "limits": {
            "run_js": {
                "timeout_default": 30.0,
                "timeout_max": 300.0,
                "max_log_lines": 1000,
                "max_log_line_chars": 4000,
                "max_log_chars": 100000,
                "max_result_chars": 20000,
            },
            "qiling": {"count_default": 1000000},
            "angr": {"timeout_supported": True, "step_budget_supported": True},
            "z3": {"timeout_supported": True, "rlimit_supported": True},
        },
    }


def _readiness_report(session: Optional[EngineSession] = None,
                      check_angr: bool = False, check_qiling: bool = False) -> dict:
    """逆向流程健康检查报告体（原 reverse_readiness_check 的函数体）。

    逐项 try/except 降级：任何子检查失败都进 warnings/errors，不中断整体返回。
    check_angr/check_qiling 默认 False，供 engine_diagnostics 复用时不隐式加载
    angr 工程 / qiling 实例。
    """
    session = session or _session()
    report = {
        "ok": True,
        "binary_loaded": session.ida is not None,
        "facade_ready": session.ida_facade is not None,
        "warnings": [],
        "errors": [],
    }
    if session.ida is None:
        report["warnings"].append("尚未 set_binary_path，多数逆向工具不可用")
        return report

    try:
        facade = _require_ida_facade(session)
        report["input_file"] = facade.get_input_file_path()
        report["imagebase"] = facade.get_imagebase()
        report["function_count"] = len(facade.get_functions())
        report["staging"] = facade.status()
    except Exception as exc:  # noqa: BLE001 — 健康检查须容错，逐项降级
        report["errors"].append(f"IDA 门面读取失败: {exc}")

    if check_angr:
        try:
            angr_facade = AngrFacade(session.ida)
            info = angr_facade.loader_object(angr_facade.project())
            report["angr"] = {
                "arch": info["arch"],
                "entry": info["entry"],
                "mapped_base": info["mapped_base"],
            }
            imagebase = report.get("imagebase")
            if imagebase is not None and info["mapped_base"] != imagebase:
                report["warnings"].append(
                    "angr mapped_base 与 IDA imagebase 不一致，find/avoid 地址需换算基址")
        except Exception as exc:  # noqa: BLE001
            report["warnings"].append(f"angr 加载当前样本失败: {exc}")

    if check_qiling:
        try:
            QilingFacade().create("90")
            report["qiling"] = "ok"
        except Exception as exc:  # noqa: BLE001
            report["warnings"].append(f"qiling shellcode 模式不可用: {exc}")

    staging = report.get("staging") or {}
    if staging.get("staged"):
        report["warnings"].append(
            f"暂存区有 {staging['staged']} 条未提交改动，preview 确认后需 commit")

    report["ok"] = not report["errors"]
    return report


def _engine_diagnostics(session: Optional[EngineSession] = None) -> dict:
    session = session or _session()
    report = {"ok": True, "status": _engine_status(session),
              "dependencies": _dependency_status(),
              "readiness": _readiness_report(session, check_angr=False),
              "warnings": [], "errors": []}
    if session.ida is None:
        report["warnings"].append("尚未加载 binary 或 IDB，IDA 相关工具不可用")
    if not report["dependencies"].get("STPyV8"):
        report["warnings"].append("STPyV8 不可用，run_js 无法执行")
    for name in ("angr", "claripy", "z3", "qiling", "unicorn"):
        if not report["dependencies"].get(name):
            report["warnings"].append(f"{name} 不可用，相关能力降级")
    report["ok"] = not report["errors"]
    return report


def _tool_fallback_error(tool_name, exc, arguments=None) -> dict:
    return {
        "ok": False,
        "error_type": type(exc).__name__,
        "message": str(exc),
        "tool": str(tool_name),
        "arguments": arguments if isinstance(arguments, dict) else None,
        "recoverable": True,
    }


def _norm_key(s):
    """把参数名归一化：小写并去掉下划线/连字符，用于大小写与分隔符不敏感匹配。"""
    return str(s).lower().replace("_", "").replace("-", "")


def _install_arg_key_normalizer(mcp):
    """让 MCP 工具参数名对大小写/分隔符(_/-)不敏感(#4)：调用前把传入 key 归一到工具已
    声明的参数名（如 Address/min-score -> address/min_score），避免仅因字段名写法不同就
    报泛化校验错误。归一失败或无匹配的 key 原样保留，交由框架照常校验。"""
    tm = mcp._tool_manager
    original = tm.call_tool

    async def call_tool(name, arguments, *args, **kwargs):
        original_arguments = arguments
        try:
            if isinstance(arguments, dict):
                tool = tm.get_tool(name)
                try:
                    fields = list(tool.fn_metadata.arg_model.model_fields.keys())
                except Exception:  # noqa: BLE001 — 取不到参数模型就不改写
                    fields = []
                if fields:
                    canonical = {_norm_key(f): f for f in fields}
                    valid = set(fields)
                    fixed = {}
                    for key, value in arguments.items():
                        target = key if key in valid else canonical.get(_norm_key(key), key)
                        fixed[target] = value
                    arguments = fixed
            return await original(name, arguments, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return _tool_fallback_error(name, exc, original_arguments)

    tm.call_tool = call_tool


def register(mcp):
    """把 JS 沙箱工具与 IDA 逆向工具注册到给定的 FastMCP 实例。

    工具按 MCP 连接解析会话：每个连接有独立的 EngineSession（binary/IDA/黑板/
    worker）；无连接身份的调用（stdio、内部调用、测试）落到 fallback 单会话。
    """

    # 参数名大小写/分隔符不敏感（#4）：拦截工具分发，把传入 key 归一到已声明参数名。
    _install_arg_key_normalizer(mcp)

    @mcp.tool()
    def engine_status(ctx: Optional[Context] = None) -> dict:
        """返回当前连接的 engine session、IDA 绑定、registry 模块、staged 写回状态与默认资源边界。"""
        return _engine_status(_session(ctx))

    @mcp.tool()
    def engine_diagnostics(ctx: Optional[Context] = None) -> dict:
        """返回降级友好的运行环境诊断；未加载 binary/IDB 时也可调用。"""
        return _engine_diagnostics(_session(ctx))

    @mcp.tool()
    def run_js(
        code: Annotated[str, "JavaScript source to execute"],
        timeout: Annotated[float, "Seconds before the worker is terminated"] = 30.0,
        max_log_lines: Annotated[int, "Maximum log lines to return"] = 1000,
        max_result_chars: Annotated[int, "Maximum result characters to return"] = 20000,
        max_log_line_chars: Annotated[int, "Maximum characters per log line"] = 4000,
        max_log_chars: Annotated[int, "Maximum total log characters"] = 100000,
        structured: Annotated[
            bool, "Return a structured result dict instead of the legacy text"] = False,
        ctx: Optional[Context] = None,
    ):
        """在 worker 进程中执行 JavaScript；超时或崩溃不影响 MCP 主进程。

        默认返回历史文本（`[log] ...` 行 + `=> 结果/错误信封`）。`structured=True`
        时返回 dict：ok、text、result、error（结构化错误信封，含 error_type/status/
        phase/session_id/timeout_s/host_call_abandoned/exit_code）、traceback、
        run_id、generation、session_id、phase、timeout_s。
        默认路径与历史行为逐字节一致。
        """
        kwargs = dict(timeout=timeout, max_log_lines=max_log_lines,
                      max_result_chars=max_result_chars,
                      max_log_line_chars=max_log_line_chars, max_log_chars=max_log_chars)
        supervisor = _session(ctx).supervisor
        if structured:
            return supervisor.run_ex(code, **kwargs)
        return supervisor.run(code, **kwargs)

    @mcp.tool()
    def set_binary_path(path: Annotated[str, "Path to the binary file or IDA database"],
                        ctx: Optional[Context] = None):
        """加载二进制或 IDA 数据库，重置当前连接的 engine session。"""
        return _new_ida_session(_session(ctx), path)

    @mcp.tool()
    def open_ida_database(path: Annotated[str, "Path to an .idb/.ida/.i64 database"],
                          ctx: Optional[Context] = None):
        """打开已有 IDA 数据库，重置当前连接的 engine session。"""
        if not _is_idb_path(path):
            raise ValueError("IDA database path must end with .idb, .ida, or .i64")
        return _new_ida_session(_session(ctx), path)

    @mcp.tool()
    def decompile_function(address: Annotated[int, "Address of the function to decompile"],
                           ctx: Optional[Context] = None) -> str:
        """反编译指定地址的函数，返回伪代码文本。"""
        return _require_ida_facade(_session(ctx)).decompile(address)

    @mcp.tool()
    def decompile_checked(address: Annotated[int, "Address of the function to decompile"],
                          ctx: Optional[Context] = None) -> dict:
        """反编译并返回结构化结果；失败返回 {ok:false, message} 而非抛错。"""
        try:
            return {"ok": True, "pseudocode": _require_ida_facade(_session(ctx)).decompile(address)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    @mcp.tool()
    def disassemble_function(address: Annotated[int, "Address of the function to disassemble"],
                             ctx: Optional[Context] = None) -> str:
        """返回函数的逐指令汇编文本。"""
        return _require_ida_facade(_session(ctx)).disassemble(address)

    @mcp.tool()
    def get_entry_points(ctx: Optional[Context] = None) -> list:
        """返回数据库全部入口点。"""
        return _require_ida_facade(_session(ctx)).get_entry_points()

    @mcp.prompt()
    def exploit_prompt():
        """Exploit prompt"""
        messages = [
            base.UserMessage(
                "You are a helpful assistant that can help me with my exploit."
            ),
            base.UserMessage(
                """
    You need to follow these steps to complete the exploit:
    1. Reverse analyze the binary file to locate vulnerabilities and analyze vulnerability types
    - Locate vulnerabilities: Use IDA Pro's analysis features to find vulnerability locations
    - Need to first gather binary file information, such as using checksec tool to check binary protection mechanisms
    - If you find NX protection is disabled, you can use ret2shellcode method to get a shell
    2. Choose appropriate exploitation method based on vulnerability type
    - For stack overflow vulnerabilities, analyze the overflow pattern and check if there are backdoor functions in the binary. If there are backdoor functions, modify the return address to point to the backdoor function address
    - If there are no backdoor functions, need to use ret2libc method. Don't assume the binary contains the gadgets you want - you need to use ROPgadget to find gadgets and combine them to construct the pop chain.
    """
            ),
        ]
        return messages

    @mcp.prompt()
    def deobfuscation_prompt():
        """反混淆闭环使用说明：用 run_js 打通反编译 + 模拟执行 + 写回 IDA。"""
        messages = [
            base.UserMessage(
                "优先用 run_js 沙箱的 require('lab') 完成闭环：lab.deob(x) 扫描并富化 z3 判定、"
                "lab.solve_branch(ea, {concrete:true}) 判定分支恒真/恒假、"
                "lab.emulate(x, {map_segments:true}) 交互模拟（活句柄 step/regs/mem_read）、"
                "lab.annotate(ea, text) 暂存结论、lab.findings() 读回黑板。"
                "以下门面细节仅在需要更细粒度时使用。\n"
                "你是一个逆向工程助手。所有分析都在 run_js 这个 JavaScript 沙箱里完成：\n"
                "每次脚本在一次性 worker 进程中运行；使用 timeout 控制执行时间，超时或 worker 崩溃后检查 engine_status.sandbox 再继续。\n"
                "沙箱全局提供 log(...)（打印，收进返回串）和 require(name)（取宿主模块）。\n"
                "编组规则：整数 <=2^53 到 JS 变成 number、更大变成十进制字符串；bytes 变成 hex 串；\n"
                "JS 对象/数组/函数都能传回 Python（对象->dict、数组->list、函数->可回调 hook）。\n"
                "由于 JS number 是 float64，处理地址时优先用字符串拼接（'' + ea）避免精度丢失。"
            ),
            base.UserMessage(
                """可用的 require() 接口：

【require('ida')】高层 IDA 门面（读 + 写回）。
读：get_function(ea) / get_function_start|end|name(ea) / get_functions()；
    get_bytes(ea,size)->hex / get_byte|word|dword|qword(ea)；
    get_name(ea) / get_name_ea(name) / get_imagebase() / get_input_file_path()；
    get_instruction(ea)->助记符 / get_instruction_size(ea) / print_operand(ea,n) / get_operand(ea,n)->[type,value]；
    get_segments() / get_segment_name|start|end|perm(ea)；
    get_xrefs_to(ea) / get_xrefs_from(ea)。
写回（默认 dry-run，只暂存不落地）：
    patch_bytes(ea, hex或字节数组) / nop(ea,size) / set_comment(ea,text[,repeatable])；
    rename(ea,name) / set_decompiler_comment(ea,text)（函数级，显示在伪代码顶部）；
    make_code(ea) / make_function(ea)。
暂存区控制：preview()->待应用 diff 列表；commit([backup路径])->落地到临时 IDB 并入 history（给 backup 会先存快照）；
    discard()->丢弃暂存；undo()->回退最近一次 commit；save_idb(path)->把当前含改动的 IDB 持久化到 .idb/.ida/.i64。
MCP 层可用 open_ida_database 打开已有 .idb/.ida/.i64；要持久化到磁盘用 require('ida').save_idb(path)。
注意：commit 只改临时 IDB，不 save_idb 就不会写盘。暂存/history 挂在门面实例上，跨多次 run_js 调用保持。

【require('qiling')】qiling code 模式模拟（shellcode，无需 rootfs）。
一次性：emulate_code(hex, count=0, arch='x8664', os='linux', regs) -> 结束寄存器 dict；
        emulate_at(start_ea, size, count, ...) -> 从 IDB 取字节再模拟（shellcode，只映射这段字节）。
面向函数：emulate_function(address, args, {arch,os,count,timeout,segments,strings}) -> 自动映射 IDB 各段到
        原地址、按调用约定设参数寄存器与返回哨兵、整段跑到返回，回收 {return,regs,strings,mem_writes}。
        args 每项：int / {value|ptr:int} / {bytes:'hex'|str:'文本'}（后者自动分配缓冲区并传指针）。
        依赖栈上密文/全局 key table/内部 call 的解密链优先用它；外部/PLT 调用仍会 fault（返回结构化错误）。
活实例：create(hex, {arch,os,verbose}) / create_from(start_ea, size, opts) -> 活的 Qiling，JS 自行驱动。
    活实例上：ql.arch.regs.read/write(name)、ql.mem.read(addr,size)/write、ql.hook_code(fn(ql,addr,size))、
             ql.arch.uc（底层 unicorn 引擎）、ql.run({begin,end,timeout,count})。
门面便捷方法（补 JS 无 bytes/kwargs 的适配）：run(ql,{count})、regs(ql)、get_reg/set_reg/set_regs、
    mem_read(ql,addr,size)->hex、mem_write(ql,addr, hex或字节数组)、map_mem(默认 RW，可传 'rx'/'rwx')、
    alloc(ql,size,perms)->addr、stack_push/stack_pop、disasm(ql,addr,size)->[{address,mnemonic,op_str,size,bytes}]。
Trace：trace_code(hex,count,arch,os,regs,orig_ea,trace_regs,trace_mem,timeout,max_trace,max_mem_events) / trace_at(start_ea,size,...)；
    活实例 trace(ql,{count,timeout,orig_ea,trace_regs,trace_mem,max_trace,max_mem_events,strings:{min_len}}) -> trace 或 {trace,strings,truncated}。
字符串：strings_code(hex,count,arch,os,regs,orig_ea,{min_len,max_trace_items,max_writes,max_candidates}) / strings_at(start_ea,size,...)；
    strings_from_trace(trace,{min_len,max_trace_items,max_writes,max_candidates,return_meta}) 可从连续内存写入中提取 ASCII 字符串候选。
批量：batch_strings_at(jobs,{total_timeout,per_item_timeout,max_errors}) 返回 {results,timed_out,errors,truncated}。
地址换算：code_base(ql)=shellcode 加载基址；to_ida(ql,ql_ea,orig_ea) / to_ql(ql,ida_ea,orig_ea)
    （用 create_from(orig_ea,...) 时把模拟地址换算回真实 IDA 地址：ida_ea = ql_ea - code_base + orig_ea）。

【require('angr')】angr 符号执行门面。
项目：project(path,{auto_load_libs:false}) / project()（加载当前 IDA 输入文件） / loader_object(project) / entry(project) / image_base(project) / find_symbol(project,name)。
状态：blank_state(project,addr) / entry_state(project,args) / call_state(project,addr,args) / simgr(project,state)。
执行：explore(simgr,find,avoid,n) / run(simgr,n) / step(simgr,n) / stash_counts(simgr) / stash(simgr,name) / first(simgr,name)。
求解：bvs(name,bits) / bvv(value,bits) / concat(values) / and_(values) / or_(values) / not_(value)；
    add(state,constraint) / eval(state,expr,'int'|'bytes') / eval_upto(state,expr,n,'int'|'bytes') / satisfiable(state)。
访问：reg_read/reg_write、mem_read/mem_write、posix_dump(state,fd)->hex。
【require('angr_module') / require('claripy')】底层 angr/claripy 模块，需要门面没覆盖的能力时直接用。

【require('unicorn')】底层 unicorn 模块本体（UC_* 常量、Uc 类）。
【require('unicorn_x86' | 'unicorn_arm' | 'unicorn_arm64' | 'unicorn_mips')】各架构寄存器/常量子模块（如 UC_X86_REG_RAX）。
默认不向 JS 暴露裸 IDA 模块；写回必须通过 require('ida') 门面并走 preview -> commit -> save_idb。"""
            ),
            base.UserMessage(
                """推荐的反混淆闭环工作流（读 -> 模拟求解 -> 写回，全在 run_js 里）：

0. 状态检查：先调用 engine_status / engine_diagnostics 确认 binary/IDB、依赖、registry 模块和 staged 状态；已有数据库用 open_ida_database('xxx.i64') 打开。
1. 读：用 require('ida') 定位目标函数/指令，get_bytes / get_instruction / decompile 观察混淆形态
   （典型：不透明谓词、间接跳转 jmp reg、运行时算出的常量/字符串解密）。
2. Trace/模拟求解：先用 require('qiling').trace_at(ea, size, ...) 观察真实执行路径、寄存器和内存读写，
   再用 emulate_at/emulate_code 求结束值（如间接跳转目标、解出的常量、解密后的字符串）。
   需要单步/下 hook/读中间态时用 create/create_from 拿活实例，配合 trace、hook_code、mem_read、disasm。
   若代码来自 create_from(orig_ea,...)，用 to_ida() 把模拟地址换算回 IDA 地址。
3. 写回：把求解结果写回 IDA——
   - set_comment(ea, 'jmp target = 0x...') 或 set_decompiler_comment 标注结论；
   - patch_bytes / nop 消除死代码或修正间接跳转；
   - rename / make_code / make_function 恢复结构。
   所有写操作默认只进暂存区。
4. 预览与提交：先 preview() 核对 diff，确认无误再 commit()；
   高风险改动 commit(backup路径) 先落快照；发现改错用 undo() 回退；要持久化到磁盘再 save_idb(path)。

原则：先读懂再模拟，模拟结果务必以 preview 核对后再 commit；能用注释表达结论时优先注释，
不到必要不 patch 字节；每一步用 log() 记录中间值方便回溯。"""
            ),
        ]
        return messages
