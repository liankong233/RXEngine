# -*- coding: utf-8 -*-
import os
import traceback


PROTOCOL_VERSION = 1
# supervisor 接受的最低协议版本：帧版本落在 [MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]
# 区间内即视为匹配。新增 operation/字段（batch、cursor 等）时 bump PROTOCOL_VERSION
# 即可，只要旧帧仍在区间内就不会因版本号不等而被静默丢弃。
MIN_PROTOCOL_VERSION = 1
SUPPORTED_PROTOCOL_VERSIONS = tuple(range(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION + 1))

# 单次 batch 的子操作上限：超出的批量调用在 worker 侧分片。
MAX_BATCH_OPS = 256


def _send_result(connection, request, result):
    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request["run_id"],
        "generation": request["generation"],
        "ok": True,
        "result": result,
    })


def _send_error(connection, request, exc):
    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request.get("run_id"),
        "generation": request.get("generation"),
        "ok": False,
        "error_type": type(exc).__name__,
        "message": str(exc),
        "traceback": traceback.format_exc(limit=20),
    })


def _next_request(connection):
    """等待下一条 run 请求；shutdown 或管道断开返回 None。"""
    while True:
        try:
            message = connection.recv()
        except EOFError:
            return None
        if message is None:
            return None
        kind = message.get("kind")
        if kind == "shutdown":
            return None
        if kind == "run":
            return message
        # 不认识的帧忽略，保持前向兼容（新字段/新 kind 不应打断旧 worker）。


def run_worker(connection, request):
    """worker 入口。

    首个请求经进程参数传入；`request["warm"]` 为真时在同一进程内继续服务后续 run
    请求，使 extensions（angr/qiling/z3）的重导入只发生一次。RPC client 的
    run_id/generation 在每轮开始时更新，跨轮复用的门面引用因此始终指向当前轮。
    """
    try:
        from extensions import register
        from sandbox.registry import Registry
        from sandbox.vm import run_js

        client = WorkerRPCClient(connection, request["run_id"], request["generation"])
        registry = Registry()
        raw_ida = client.root("raw_ida") if request["ida_bound"] else None
        board = client.root("board") if request.get("board_bound") else None
        # "ida" 根即父进程 session 门面（EngineSession.ida_facade）：把它作为 lab 的
        # facade 传入，lab 的 staged 写回（annotate/preview/commit）落在跨 worker
        # 存活的门面上；否则暂存进 worker 内自包的门面、随 worker 退出丢失
        # （stage -> 下一轮 preview/commit 断链的 split-brain）。
        facade = client.root("ida") if request["ida_bound"] else None
        register(registry, ida=raw_ida, board=board, lab_ida=facade)
        if request["ida_bound"]:
            registry.register("ida", facade)
    except BaseException as exc:  # noqa: BLE001 — 初始化失败则本进程无法服务任何请求
        try:
            _send_error(connection, request, exc)
        except BaseException:  # noqa: BLE001
            pass
        finally:
            connection.close()
        return

    warm = bool(request.get("warm"))
    try:
        while request is not None:
            client.begin_run(request["run_id"], request["generation"])
            try:
                result = run_js(
                    request["code"],
                    registry=registry,
                    max_log_lines=request["max_log_lines"],
                    max_result_chars=request["max_result_chars"],
                    max_log_line_chars=request["max_log_line_chars"],
                    max_log_chars=request["max_log_chars"],
                )
                _send_result(connection, request, result)
            except BaseException as exc:  # noqa: BLE001
                try:
                    _send_error(connection, request, exc)
                except BaseException:  # noqa: BLE001 — 管道已断，退出
                    break
            if not warm:
                break
            request = _next_request(connection)
    finally:
        connection.close()


class WorkerRPCClient:
    def __init__(self, connection, run_id, generation):
        self._connection = connection
        self._run_id = run_id
        self._generation = generation
        self._seq = 0

    def begin_run(self, run_id, generation):
        """切换到新一轮：远程引用共用同一 client，调用时自然带上当前轮标识。"""
        self._run_id = run_id
        self._generation = generation
        self._seq = 0

    def root(self, name):
        return RemoteObject(self, {"root": str(name)})

    def call(self, operation, target, **payload):
        self._seq += 1
        message = {
            "version": PROTOCOL_VERSION,
            "kind": "host_call",
            "run_id": self._run_id,
            "generation": self._generation,
            "seq": self._seq,
            "operation": operation,
            "target": target,
            **payload,
        }
        self._connection.send(message)
        response = self._connection.recv()
        if (response.get("kind") != "host_response"
                or response.get("run_id") != self._run_id
                or response.get("generation") != self._generation
                or response.get("seq") != self._seq):
            raise RuntimeError("invalid host RPC response")
        if not response.get("ok"):
            raise RemoteCallError(response.get("error_type"), response.get("message"))
        return self.decode(response.get("result"))

    def batch(self, ops):
        """一次 RPC 提交多个操作，返回 {"results": [...], "errors": n}。

        子调用顺序与 ops 一致，各自独立成败（一个失败不影响同批其它项）。传输层
        仍是一个 seq，因此超时/孤儿语义与单次调用完全相同。
        """
        self._seq += 1
        message = {
            "version": PROTOCOL_VERSION,
            "kind": "host_call",
            "run_id": self._run_id,
            "generation": self._generation,
            "seq": self._seq,
            "operation": "batch",
            "ops": [self._encode_op(op) for op in ops],
        }
        self._connection.send(message)
        response = self._connection.recv()
        if (response.get("kind") != "host_response"
                or response.get("run_id") != self._run_id
                or response.get("generation") != self._generation
                or response.get("seq") != self._seq):
            raise RuntimeError("invalid host RPC response")
        if not response.get("ok"):
            raise RemoteCallError(response.get("error_type"), response.get("message"))
        outcome = dict(response.get("result") or {})
        for item in outcome.get("results", []):
            if item.get("ok") and "result" in item:
                item["result"] = self.decode(item["result"])
        return outcome

    def _encode_op(self, op):
        encoded = {"op": op["op"], "target": op["target"]}
        if "name" in op:
            encoded["name"] = op["name"]
        if "args" in op:
            encoded["args"] = self.encode(list(op["args"]))
        if "kwargs" in op:
            encoded["kwargs"] = self.encode(dict(op["kwargs"]))
        if "key" in op:
            encoded["key"] = self.encode(op["key"])
        return encoded

    def encode(self, value):
        if isinstance(value, RemoteObject):
            return {"__remote_ref__": value._target}
        if value is None or isinstance(value, (bool, int, float, str, bytes)):
            return value
        if isinstance(value, (list, tuple)):
            return [self.encode(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.encode(item) for key, item in value.items()}
        raise TypeError(f"worker RPC argument is not serializable: {type(value).__name__}")

    def decode(self, value):
        if isinstance(value, dict) and "__remote_ref__" in value:
            return RemoteObject(self, value["__remote_ref__"], value.get("__callable__"))
        if isinstance(value, list):
            return [self.decode(item) for item in value]
        if isinstance(value, dict):
            return {key: self.decode(item) for key, item in value.items()}
        return value


class RemoteCallError(RuntimeError):
    def __init__(self, error_type, message):
        super().__init__(f"{error_type}: {message}")
        self.error_type = error_type


class RemoteObject:
    _ITER_PAGE = 512

    def __init__(self, client, target, callable_hint=None):
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_target", target)
        # 由宿主侧编码时带上的可调用性提示：远程对象也能正确区分方法与数据属性。
        object.__setattr__(self, "remote_callable", callable_hint)
        # 属性链记忆化：同名属性只解析一次。缓存的是"路径引用"（按名字解析，跨轮/
        # 状态变化仍然正确），按值返回的数据属性不缓存，避免读到陈旧值。
        object.__setattr__(self, "_attrs", {})

    def __getattr__(self, name):
        # 屏蔽 dunder 探测，也屏蔽单下划线私有属性（如门面的 _ida），
        # 避免 JS 绕过 IDA staged 写策略直接触达底层对象。
        if name.startswith("_"):
            raise AttributeError(name)
        cache = self._attrs
        if name in cache:
            return cache[name]
        value = self._client.call("getattr", self._target, name=str(name))
        if isinstance(value, RemoteObject):
            cache[name] = value
        return value

    def call_many(self, args_list, chunk=None):
        """对同一方法批量调用，args_list 为每次的位置参数序列。

        一次批量 RPC 完成整批调用并保持顺序；跨越 MAX_BATCH_OPS 时自动分片。任一
        子调用失败按普通循环语义抛出（RemoteCallError），不返回部分结果。
        """
        chunk = int(chunk or MAX_BATCH_OPS)
        args_list = list(args_list)
        results = []
        for start in range(0, len(args_list), chunk):
            window = args_list[start:start + chunk]
            ops = [{"op": "call", "target": self._target, "args": list(args), "kwargs": {}}
                   for args in window]
            outcome = self._client.batch(ops)
            for item in outcome.get("results", []):
                if item.get("ok"):
                    results.append(item.get("result"))
                else:
                    raise RemoteCallError(item.get("error_type"), item.get("message"))
        return results

    def __call__(self, *args, **kwargs):
        return self._client.call(
            "call",
            self._target,
            args=self._client.encode(list(args)),
            kwargs=self._client.encode(kwargs),
        )

    def __getitem__(self, key):
        return self._client.call("getitem", self._target, key=self._client.encode(key))

    def __iter__(self):
        # 分页拉取，避免一次性物化大集合；每次只解码一页（<= _ITER_PAGE 项）。
        offset = 0
        while True:
            page = self._client.call(
                "iter_page", self._target, offset=offset, limit=self._ITER_PAGE)
            for item in page["items"]:
                yield item
            if page["done"]:
                return
            offset = page["next"]

    def __length_hint__(self):
        # 只能迭代、没有 __len__ 的远程对象（如 IDA 的生成器）不应让 list()/tuple()
        # 因为 len() 报错而失败；返回 0 让 CPython 回退到 __iter__。
        return 0

    def __len__(self):
        try:
            return int(self._client.call("len", self._target))
        except RemoteCallError as exc:
            # list()/tuple()/sorted() 的长度提示只吞 TypeError；把远程的
            # “没有 len()”翻译成真正的 TypeError，迭代才会回退到 __iter__。
            if exc.error_type == "TypeError":
                raise TypeError(str(exc)) from None
            raise

    def __bool__(self):
        return bool(self._client.call("bool", self._target))

    def __describe__(self):
        """由注册表调用：把真实宿主对象的可读属性内省结果拉回 worker。"""
        return self._client.call("describe", self._target)

    def __repr__(self):
        return f"<RemoteObject pid={os.getpid()} target={self._target!r}>"
