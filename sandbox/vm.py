# -*- coding: utf-8 -*-
"""JS 沙箱：基于 STPyV8 执行 JavaScript，向 JS 全局注入 log/require。

由 MCP server 统一注册为工具。本模块只提供纯函数，不带 MCP 装饰器。
"""
import STPyV8

from sandbox import bridge
from sandbox.jsmodule import JSModule
from sandbox.registry import registry as default_registry


_MAX_LOG_LINES = 10000
_MAX_LOG_LINE_CHARS = 20000
_MAX_LOG_CHARS = 200000
_MAX_RESULT_CHARS = 1000000


class _RequireInfo:
    def __init__(self, registry):
        self._registry = registry

    def list(self):
        return self._registry.names()

    def describe(self, name):
        return self._registry.describe(str(name))


class _Global(STPyV8.JSClass):
    """注入到 JS 全局作用域的宿主对象（log/require）。"""

    def __init__(self, logs: list[str], registry, max_log_lines=1000,
                 max_log_line_chars=4000, max_log_chars=100000):
        self._logs = logs
        self._registry = registry
        self._max_log_lines = int(max_log_lines)
        self._max_log_line_chars = int(max_log_line_chars)
        self._max_log_chars = int(max_log_chars)
        self._log_chars = 0
        self._log_truncated = False
        self._truncation_reasons = set()
        self._require_info = _RequireInfo(registry)

    @property
    def log_truncated(self):
        return self._log_truncated

    @property
    def log_truncation_reason(self):
        """返回最贴近触发原因的边界名：lines > chars > line_chars。"""
        for reason in ("lines", "chars", "line_chars"):
            if reason in self._truncation_reasons:
                return reason
        return None

    def log(self, *args):
        if len(self._logs) >= self._max_log_lines:
            self._log_truncated = True
            self._truncation_reasons.add("lines")
            return
        line = " ".join(str(a) for a in args)
        remaining = self._max_log_chars - self._log_chars
        if remaining <= 0:
            self._log_truncated = True
            self._truncation_reasons.add("chars")
            return
        limit = min(self._max_log_line_chars, remaining)
        if len(line) > limit:
            line = line[:limit] + "... [truncated]"
            self._log_truncated = True
            self._truncation_reasons.add(
                "chars" if limit == remaining else "line_chars")
        self._logs.append(line)
        self._log_chars += min(len(line), limit)

    def require(self, name):
        if name == "__require__":
            return bridge.wrap(self._require_info)
        obj = self._registry.get(name)
        if isinstance(obj, JSModule):
            return STPyV8.JSContext.current.eval(obj.source)
        # 从注册表按名获取对象（由各模块主动注册，如 idaapi、idautils），
        # 经 bridge 包裹后返回，自动处理 JS<->netref 的参数/返回值编组。
        return bridge.wrap(obj)


def _bounded_int(name, value, default, maximum):
    value = default if value is None else int(value)
    if value < 0 or value > maximum:
        raise ValueError(f"{name} must be between 0 and {maximum}")
    return value


def run_js(code: str, registry=None, max_log_lines=1000, max_result_chars=20000,
           max_log_line_chars=4000, max_log_chars=100000) -> str:
    """执行一段 JavaScript 代码。

    JS 全局作用域可用：
      - log(...args)   打印日志，随执行结果一并返回
      - require(name)  获取已注册对象，如 require('ida')、require('qiling')
    """
    max_log_lines = _bounded_int("max_log_lines", max_log_lines, 1000, _MAX_LOG_LINES)
    max_result_chars = _bounded_int("max_result_chars", max_result_chars, 20000, _MAX_RESULT_CHARS)
    max_log_line_chars = _bounded_int(
        "max_log_line_chars", max_log_line_chars, 4000, _MAX_LOG_LINE_CHARS)
    max_log_chars = _bounded_int("max_log_chars", max_log_chars, 100000, _MAX_LOG_CHARS)
    active_registry = registry or default_registry
    logs: list[str] = []
    host = _Global(
        logs,
        active_registry,
        max_log_lines=max_log_lines,
        max_log_line_chars=max_log_line_chars,
        max_log_chars=max_log_chars,
    )
    try:
        with STPyV8.JSContext(host) as ctx:
            ctx.eval("var __host_require = require;"
                     "require = function(name){ return __host_require(name); };"
                     "require.list = function(){ return __host_require('__require__').list(); };"
                     "require.describe = function(name){ return __host_require('__require__').describe(name); };")
            result = ctx.eval(code)
            result_text = str(result)
            result = None
    except Exception as exc:  # noqa: BLE001
        result_text = str({"ok": False, "error_type": type(exc).__name__, "message": str(exc)})

    out = []
    for line in logs:
        out.append(f"[log] {line}")
    reason = host.log_truncation_reason
    if reason == "lines":
        out.append(f"[log] ... truncated after {int(max_log_lines)} log lines")
    elif reason == "chars":
        out.append(f"[log] ... log output truncated after {int(max_log_chars)} total characters")
    elif reason == "line_chars":
        out.append(f"[log] ... log lines truncated to {int(max_log_line_chars)} characters")
    if max_result_chars and len(result_text) > int(max_result_chars):
        result_text = result_text[:int(max_result_chars)] + "... [truncated]"
    out.append(f"=> {result_text}")
    return "\n".join(out)
