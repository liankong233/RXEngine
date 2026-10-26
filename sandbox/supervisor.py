# -*- coding: utf-8 -*-
import multiprocessing
import queue
import threading
import time
from contextlib import contextmanager
from uuid import uuid4

from sandbox.worker import (
    MAX_BATCH_OPS, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, run_worker)

_HOST_RESULT_SLICE = 0.05
_MAX_ITEMS = 10000
_MAX_DEPTH = 64
_SUPPORTED_VERSIONS = frozenset(SUPPORTED_PROTOCOL_VERSIONS)
_TRACEBACK_CHARS = 4000
_MAX_BATCH_OPS = MAX_BATCH_OPS
# 分页物化上限：防止超大/无限迭代器把父进程内存吃光。真实 API 目前不返回生成器，
# 这里只作安全边界，超限给出结构化错误而非静默截断。
_MAX_ITER_ITEMS = 100000


class SandboxSupervisor:
    def __init__(self, roots_provider=None, context_name="spawn", worker_target=run_worker,
                 session_id_provider=None, warm=False, max_worker_runs=200):
        self._roots_provider = roots_provider or (lambda: {})
        self._context = multiprocessing.get_context(context_name)
        self._worker_target = worker_target
        # 可选：向结构化结果注入当前 session id。缺省 None 时信封不含该字段，
        # 离线/测试路径不受影响。
        self._session_id_provider = session_id_provider
        # warm=True 时 worker 进程跨 run_js 保活，省掉 extensions（angr/qiling/z3）
        # 的重复导入；离线默认 False 保持每次新建进程的确定性，MCP 服务端显式开启。
        self._warm = bool(warm)
        self._max_worker_runs = int(max_worker_runs or 0)
        self._worker = None
        self._worker_runs = 0
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._generation = 0
        self._active_run = None
        self._last_exit = None
        self._host_results = queue.Queue()
        self._host_inflight = set()
        self._handle_seq = 0

    def status(self):
        with self._state_lock:
            status = {
                "generation": self._generation,
                "active_run": self._active_run,
                "last_exit": self._last_exit,
                "host_calls_inflight": len(self._host_inflight),
            }
        slot = self._worker
        status["worker"] = {
            "warm": self._warm,
            "alive": bool(slot is not None and slot["process"].is_alive()),
            "pid": slot["process"].pid if slot is not None else None,
            "runs": self._worker_runs,
        }
        return status

    def close(self):
        """回收保活的 worker 进程（服务关闭/测试清理用）；有活动 run 时不打断。"""
        if not self._run_lock.acquire(blocking=False):
            return
        try:
            self._retire_worker()
        finally:
            self._run_lock.release()

    def has_orphan_host_call(self):
        """是否有上一轮 run_js 超时弃置、但仍在执行的宿主调用。

        这类调用还在使用 IDA 的底层连接，此时其他 IDA 工具应先等待/重试，
        避免与其并发访问同一份会话状态。
        """
        return self._has_orphan_host_call()

    @contextmanager
    def session_mutation(self):
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("cannot replace IDA session while run_js is active")
        try:
            if self._has_orphan_host_call():
                raise RuntimeError(
                    "cannot replace IDA session while a host call is still running")
            # 保活 worker 内缓存的引擎状态（angr project 等）与旧 binary 绑定，
            # 换 session 后必须销毁重建，避免后续轮次在旧项目上分析。
            self._retire_worker()
            yield
        finally:
            self._run_lock.release()

    def run(self, code, timeout=30.0, max_log_lines=1000, max_result_chars=20000,
            max_log_line_chars=4000, max_log_chars=100000):
        """执行脚本，返回历史文本契约（日志行 + `=> 结果`/`=> 错误信封`）。"""
        return self.run_ex(
            code, timeout=timeout, max_log_lines=max_log_lines,
            max_result_chars=max_result_chars, max_log_line_chars=max_log_line_chars,
            max_log_chars=max_log_chars)["text"]

    def run_ex(self, code, timeout=30.0, max_log_lines=1000, max_result_chars=20000,
               max_log_line_chars=4000, max_log_chars=100000):
        """执行脚本并返回结构化结果。

        返回 dict：ok、text（legacy 文本，与 run() 逐字节一致）、result（成功时 worker
        原始结果串）、error（失败时的结构化错误信封）、run_id、generation、session_id、
        phase、timeout_s。默认行为与历史一致，结构化字段为增量，不改变文本契约。
        """
        timeout = float(timeout)
        if timeout <= 0 or timeout > 300:
            raise ValueError("timeout must be greater than 0 and at most 300 seconds")
        session_id = self._session_id_provider() if self._session_id_provider else None
        if not self._run_lock.acquire(blocking=False):
            return self._failed("SessionBusy", "another run_js call is active",
                                "session_busy", session_id=session_id, timeout=timeout,
                                generation=self._current_generation(), phase="session_busy")
        if self._has_orphan_host_call():
            self._run_lock.release()
            return self._failed(
                "HostCallPending",
                "a previous host call is still running; retry after it finishes",
                "host_call_pending", session_id=session_id, timeout=timeout,
                generation=self._current_generation(), phase="host_call_pending")
        run_id = uuid4().hex
        generation = None
        iter_cache = {}
        try:
            with self._state_lock:
                self._generation += 1
                generation = self._generation
                self._active_run = run_id
            roots = self._roots_provider() or {}
            request = {
                "version": PROTOCOL_VERSION,
                "run_id": run_id,
                "generation": generation,
                "code": str(code),
                "timeout": timeout,
                "max_log_lines": int(max_log_lines),
                "max_result_chars": int(max_result_chars),
                "max_log_line_chars": int(max_log_line_chars),
                "max_log_chars": int(max_log_chars),
                "ida_bound": "ida" in roots and "raw_ida" in roots,
                "board_bound": "board" in roots,
                "warm": self._warm,
            }
            slot = self._acquire_slot(request)
            return self._pump(slot, roots, iter_cache, timeout,
                              session_id, run_id, generation)
        finally:
            with self._state_lock:
                self._active_run = None
            self._run_lock.release()

    def _acquire_slot(self, request):
        """取得可用 worker：优先复用保活的进程，失效则回收后重建。"""
        slot = self._worker
        if slot is not None:
            if slot["process"].is_alive():
                try:
                    slot["parent"].send({"kind": "run", **request})
                    return slot
                except Exception:  # noqa: BLE001 — 管道失效，走重建
                    pass
            self._retire_worker()
        return self._spawn_worker(request)

    def _spawn_worker(self, request):
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(target=self._worker_target, args=(child, request))
        # 保活的 worker 设为守护进程：随父进程退出自动回收，避免残留持有 angr 的
        # 孤儿进程；同时禁止 worker 内再派生孙进程。
        process.daemon = True
        process.start()
        child.close()
        self._worker = {"parent": parent, "process": process}
        self._worker_runs = 0
        return self._worker

    def _pump(self, slot, roots, iter_cache, timeout, session_id, run_id, generation):
        """驱动一轮 run 的消息循环，并在结束时决定 worker 的去留。"""
        parent, process = slot["parent"], slot["process"]
        phase = "executing"
        deadline = time.monotonic() + timeout
        pending = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._discard_worker(slot)
                self._set_last_exit("timed_out")
                abandoned = pending is not None
                return self._timeout_outcome(
                    timeout, session_id, run_id, generation,
                    "awaiting_host_call" if abandoned else phase, abandoned)
            if pending is not None:
                phase = "awaiting_host_call"
                response = self._await_host_response(pending, remaining)
                if response is None:
                    self._discard_worker(slot)
                    self._set_last_exit("timed_out")
                    return self._timeout_outcome(
                        timeout, session_id, run_id, generation,
                        "awaiting_host_call", True)
                try:
                    parent.send(response)
                except Exception:  # noqa: BLE001 — worker 已死，等同崩溃
                    self._discard_worker(slot)
                    self._set_last_exit("worker_crashed")
                    return self._failed(
                        "WorkerCrashed", "worker exited while handling a host call",
                        "worker_crashed", session_id=session_id, timeout=timeout,
                        run_id=run_id, generation=generation, phase="worker_exit",
                        exit_code=process.exitcode)
                pending = None
                phase = "executing"
                continue
            if parent.poll(min(remaining, _HOST_RESULT_SLICE)):
                try:
                    message = parent.recv()
                except EOFError:
                    message = None
                if message is None:
                    break
                if not self._message_matches(message, run_id, generation):
                    continue
                kind = message.get("kind")
                if kind == "host_call":
                    pending = message
                    self._start_host_call(message, roots, iter_cache)
                    continue
                if kind == "result":
                    if message.get("ok"):
                        self._set_last_exit("completed")
                        self._keep_or_retire(slot)
                        return self._succeeded(message["result"], run_id, generation,
                                               session_id, timeout)
                    self._set_last_exit("worker_error")
                    self._keep_or_retire(slot)
                    return self._failed(
                        message.get("error_type", "WorkerError"),
                        message.get("message", "worker failed"),
                        "worker_error", session_id=session_id, timeout=timeout,
                        run_id=run_id, generation=generation, phase="worker_error",
                        traceback=self._truncate_traceback(message.get("traceback")))
                continue
            if not process.is_alive():
                break
        process.join(timeout=1)
        self._discard_worker(slot)
        self._set_last_exit("worker_crashed")
        return self._failed(
            "WorkerCrashed", f"run_js worker exited with code {process.exitcode}",
            "worker_crashed", session_id=session_id, timeout=timeout,
            run_id=run_id, generation=generation, phase="worker_exit",
            exit_code=process.exitcode)

    def _keep_or_retire(self, slot):
        """一轮成功后：保活可复用的 worker，否则回收（一次性/已退出/超轮次上限）。"""
        if not self._warm or not slot["process"].is_alive():
            self._discard_worker(slot)
            return
        self._worker_runs += 1
        if self._max_worker_runs and self._worker_runs >= self._max_worker_runs:
            self._retire_worker()

    def _retire_worker(self):
        """优雅回收当前 worker：发 shutdown，超时未退再强杀。"""
        slot = self._worker
        self._worker = None
        if slot is None:
            return
        process, parent = slot["process"], slot["parent"]
        try:
            if process.is_alive():
                try:
                    parent.send({"kind": "shutdown"})
                except Exception:  # noqa: BLE001 — 管道已断
                    pass
                process.join(timeout=1)
            if process.is_alive():
                self._terminate(process)
        finally:
            try:
                parent.close()
            except Exception:  # noqa: BLE001
                pass

    def _discard_worker(self, slot=None):
        """丢弃 worker（超时/崩溃/一次性路径）：终止进程并关闭管道。"""
        if slot is None or slot is self._worker:
            self._worker = None
        if slot is None:
            return
        process, parent = slot["process"], slot["parent"]
        if process.is_alive():
            self._terminate(process)
        try:
            parent.close()
        except Exception:  # noqa: BLE001
            pass

    def _current_generation(self):
        with self._state_lock:
            return self._generation

    def _succeeded(self, result, run_id, generation, session_id, timeout):
        return {
            "ok": True,
            "text": result,
            "result": result,
            "error": None,
            "traceback": None,
            "run_id": run_id,
            "generation": generation,
            "session_id": session_id,
            "phase": "completed",
            "timeout_s": float(timeout),
        }

    def _failed(self, error_type, message, status, session_id=None, timeout=None,
                run_id=None, generation=None, phase=None, traceback=None, **extra):
        # traceback 只进结构化结果，不进 legacy 文本：它可能很大，而历史文本契约
        # 保持精简（错误信封本身仍是完整的机器可读 dict）。
        payload = self._error_payload(error_type, message, status, phase=phase,
                                      session_id=session_id, **extra)
        return {
            "ok": False,
            "text": self._render(payload),
            "result": None,
            "error": payload,
            "traceback": traceback,
            "run_id": run_id,
            "generation": generation,
            "session_id": session_id,
            "phase": phase or status,
            "timeout_s": None if timeout is None else float(timeout),
        }

    def _timeout_outcome(self, timeout, session_id, run_id, generation, phase, abandoned):
        extra = {"host_call_abandoned": True} if abandoned else {}
        return self._failed(
            "RunTimeout", f"run_js exceeded {timeout:g} seconds", "timed_out",
            session_id=session_id, timeout=timeout, run_id=run_id,
            generation=generation, phase=phase, **extra)

    @staticmethod
    def _truncate_traceback(text, limit=_TRACEBACK_CHARS):
        """保留 worker 侧异常的 traceback 尾部（结构化信封用，避免文本无界膨胀）。"""
        if not text:
            return None
        text = str(text)
        return text if len(text) <= limit else text[-limit:]

    @staticmethod
    def _message_matches(message, run_id, generation):
        return (message.get("run_id") == run_id
                and message.get("generation") == generation
                and message.get("version") in _SUPPORTED_VERSIONS)

    def _await_host_response(self, message, remaining):
        """等待宿主调用结果；结果在新线程里执行，因此这里的 deadline 始终有效。"""
        key = (message["run_id"], message["generation"], message["seq"])
        host_deadline = time.monotonic() + remaining
        while True:
            left = host_deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                response = self._host_results.get(timeout=min(left, _HOST_RESULT_SLICE))
            except queue.Empty:
                continue
            response_key = (
                response.get("run_id"), response.get("generation"), response.get("seq"))
            if response_key == key:
                return response

    def _start_host_call(self, message, roots, iter_cache):
        key = (message["run_id"], message["generation"], message["seq"])
        with self._state_lock:
            self._host_inflight.add(key)

        def work():
            response = self._dispatch_host_call(message, roots, iter_cache)
            self._host_results.put(response)
            with self._state_lock:
                self._host_inflight.discard(key)

        threading.Thread(target=work, daemon=True, name=f"rx-host-{key[2]}").start()

    def _has_orphan_host_call(self):
        with self._state_lock:
            active = self._active_run
            return any(run_id != active for run_id, _gen, _seq in self._host_inflight)

    def _set_last_exit(self, value):
        with self._state_lock:
            self._last_exit = value

    def _dispatch_host_call(self, message, roots, iter_cache):
        response = {
            "version": PROTOCOL_VERSION,
            "kind": "host_response",
            "run_id": message["run_id"],
            "generation": message["generation"],
            "seq": message["seq"],
        }
        try:
            operation = message["operation"]
            if operation == "iter_page":
                encoded = self._iter_page(message, roots, iter_cache)
            elif operation == "batch":
                encoded = self._dispatch_batch(message, roots, iter_cache)
            else:
                encoded = self._dispatch_one(message, roots, iter_cache)
            response.update(ok=True, result=encoded)
        except BaseException as exc:  # noqa: BLE001
            response.update(ok=False, error_type=type(exc).__name__, message=str(exc))
        return response

    def _dispatch_one(self, op, roots, iter_cache):
        """执行单个 RPC 操作并返回编组后的结果；batch 复用同一实现，不新增语义。"""
        operation = op.get("op") or op.get("operation")
        target = self._resolve_target(op["target"], roots)
        if operation == "getattr":
            name = op["name"]
            result = getattr(target, name)
            return self._encode_value(
                result, roots, self._child_target(op["target"], "attr", name))
        if operation == "call":
            args = self._decode(op.get("args", []), roots)
            kwargs = self._decode(op.get("kwargs", {}), roots)
            return self._encode_call_result(target(*args, **kwargs), roots)
        if operation == "getitem":
            key = self._decode(op["key"], roots)
            result = target[key]
            return self._encode_value(
                result, roots, self._child_target(op["target"], "item", key))
        if operation == "describe":
            return self._describe_attributes(target)
        if operation == "len":
            return len(target)
        if operation == "bool":
            return bool(target)
        if operation in ("iter_page", "batch"):
            raise ValueError(f"operation cannot be nested in a batch: {operation}")
        raise ValueError(f"unsupported host RPC operation: {operation}")

    def _dispatch_batch(self, message, roots, iter_cache):
        """一次 RPC 执行多个操作；子调用顺序保持、错误隔离，不因单个失败中断整批。"""
        ops = message.get("ops") or []
        if len(ops) > _MAX_BATCH_OPS:
            raise ValueError(f"batch too large: {len(ops)} > {_MAX_BATCH_OPS}")
        results, errors = [], 0
        for op in ops:
            try:
                results.append({"ok": True,
                                "result": self._dispatch_one(op, roots, iter_cache)})
            except BaseException as exc:  # noqa: BLE001 — 子调用错误隔离
                errors += 1
                results.append({"ok": False, "error_type": type(exc).__name__,
                                "message": str(exc)})
        return {"results": results, "errors": errors}

    @staticmethod
    def _describe_attributes(target):
        """在宿主侧内省真实对象，供远程 require.describe() 使用。"""
        try:
            names = dir(target)
        except Exception:  # noqa: BLE001
            names = []
        attributes = []
        for attr in names:
            if attr.startswith("_"):
                continue
            try:
                value = getattr(target, attr)
            except Exception:  # noqa: BLE001
                attributes.append({"name": attr, "kind": "unreadable"})
                continue
            attributes.append({"name": attr, "kind": "method" if callable(value) else "value"})
        return {"type": type(target).__name__, "attributes": attributes}

    def _iter_page(self, message, roots, iter_cache):
        """把远程可迭代对象分页返回，避免一次性物化超过传输上限。

        父进程侧物化受 _MAX_ITER_ITEMS 约束：超大/无限迭代器给出结构化错误，
        不会无声吃光内存。
        """
        key = self._freeze(message["target"])
        seq = iter_cache.get(key)
        if seq is None:
            seq = []
            for item in self._resolve_target(message["target"], roots):
                seq.append(item)
                if len(seq) > _MAX_ITER_ITEMS:
                    raise ValueError(
                        f"iterable too large to page: more than {_MAX_ITER_ITEMS} items")
            iter_cache[key] = seq
        total = len(seq)
        offset = max(0, int(message.get("offset", 0)))
        limit = int(message.get("limit", 512))
        if limit <= 0 or limit > _MAX_ITEMS:
            limit = _MAX_ITEMS
        page = seq[offset:offset + limit]
        if page:
            handle = self._new_handle(page, roots)
            items = self._encode_value(page, roots, {"root": handle})
        else:
            items = []
        nxt = offset + len(page)
        return {"items": items, "next": nxt, "done": nxt >= total, "size": total}

    @staticmethod
    def _child_target(target, kind, value):
        return {**target, "path": list(target.get("path", [])) + [[kind, value]]}

    @staticmethod
    def _resolve_target(target, roots):
        root_name = target.get("root")
        if root_name not in roots:
            raise KeyError(f"unknown RPC root: {root_name}")
        obj = roots[root_name]
        for step in target.get("path", []):
            kind, value = step
            obj = getattr(obj, value) if kind == "attr" else obj[value]
        return obj

    def _encode_call_result(self, result, roots):
        """调用结果：可复用的容器/对象落到 handle 上，内部叶子走路径引用。"""
        if self._needs_handle(result):
            handle = self._new_handle(result, roots)
            return self._encode_value(result, roots, {"root": handle})
        return self._encode_value(result, roots, {"root": "__value__"})

    def _encode_value(self, value, roots, target, depth=0):
        """按值编组；不可按值编组的对象返回指向 target 路径的引用。

        target 必须能被 _resolve_target 重新解析，这样属性/下标链上的对象不需要
        各自新建 handle，迭代同一容器时也不会让 handle 表随元素数增长。
        """
        if depth > _MAX_DEPTH:
            raise ValueError("host RPC result is too deep")
        if value is None or isinstance(value, (bool, int, float, str, bytes)):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, (list, tuple)):
            if len(value) > _MAX_ITEMS:
                raise ValueError("host RPC result has too many items")
            return [
                self._encode_value(item, roots, self._child_target(target, "item", i), depth + 1)
                for i, item in enumerate(value)
            ]
        if isinstance(value, dict):
            if len(value) > _MAX_ITEMS:
                raise ValueError("host RPC result has too many items")
            return {
                str(key): self._encode_value(
                    item, roots, self._child_target(target, "item", key), depth + 1)
                for key, item in value.items()
            }
        return {"__remote_ref__": target, "__callable__": bool(callable(value))}

    @staticmethod
    def _is_by_value(value):
        return value is None or isinstance(
            value, (bool, int, float, str, bytes, bytearray, list, tuple, dict))

    def _needs_handle(self, value, depth=0):
        """判断某个调用结果是否需要落到 handle（含不可按值编组的叶子）。"""
        if depth > _MAX_DEPTH:
            return True
        if not self._is_by_value(value):
            return True
        if isinstance(value, (list, tuple)):
            return any(self._needs_handle(item, depth + 1) for item in value)
        if isinstance(value, dict):
            return any(self._needs_handle(item, depth + 1) for item in value.values())
        return False

    def _new_handle(self, value, roots):
        while True:
            name = f"__handle_{self._handle_seq}"
            self._handle_seq += 1
            if name not in roots:
                break
        roots[name] = value
        return name

    @staticmethod
    def _freeze(value):
        if isinstance(value, (list, tuple)):
            return tuple(SandboxSupervisor._freeze(item) for item in value)
        if isinstance(value, dict):
            return tuple(sorted(
                (str(key), SandboxSupervisor._freeze(item)) for key, item in value.items()))
        try:
            hash(value)
        except TypeError:
            return ("id", id(value))
        return value

    def _decode(self, value, roots):
        if isinstance(value, dict) and "__remote_ref__" in value:
            return self._resolve_target(value["__remote_ref__"], roots)
        if isinstance(value, list):
            return [self._decode(item, roots) for item in value]
        if isinstance(value, dict):
            return {key: self._decode(item, roots) for key, item in value.items()}
        return value

    @staticmethod
    def _terminate(process):
        process.terminate()
        process.join(timeout=2)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=2)

    @staticmethod
    def _error_payload(error_type, message, status, phase=None, session_id=None, **extra):
        """结构化错误信封。phase/session_id 与值为 None 的可选字段按需省略。"""
        payload = {
            "ok": False,
            "error_type": error_type,
            "message": message,
            "status": status,
            "recoverable": True,
            "state_consistency": "known",
        }
        if phase is not None:
            payload["phase"] = phase
        if session_id is not None:
            payload["session_id"] = session_id
        payload.update({k: v for k, v in extra.items() if v is not None})
        return payload

    @staticmethod
    def _render(payload):
        return f"=> {payload}"
