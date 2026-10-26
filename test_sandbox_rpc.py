# -*- coding: utf-8 -*-
"""离线验证 SandboxSupervisor 的宿主 RPC 编组、超时中断与恢复（不依赖 IDA）。"""
import threading
import time

import pytest

from sandbox.supervisor import SandboxSupervisor
from sandbox.worker import RemoteObject


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


class _Inner:
    value = 7


class _Obj:
    n = 11

    def __init__(self):
        self.inner = _Inner()


class FakeFacade:
    def add(self, a, b):
        return a + b

    def info(self):
        return {"name": "fake", "n": 3}

    def pair(self):
        return [_Inner(), 2]

    def obj(self):
        return _Obj()

    def count(self, items):
        return len(items)

    def _secret(self):
        return "RAW"


@pytest.mark.unit
@pytest.mark.sandbox
def test_host_rpc_roundtrip_and_private_attr_blocked():
    facade = FakeFacade()
    sup = SandboxSupervisor(lambda: {"ida": facade, "raw_ida": object()})
    out = sup.run(
        "var ida = require('ida');"
        "log('' + ida.add(2, 3));"
        "log(ida.info().name);"
        "var p = ida.pair();"
        "log('' + p.length + '/' + p[0].value);"
        "log('' + ida.obj().n);"
        "log('' + ida.count([10, 20, 30]));"
        "var priv; try { priv = '' + ida._secret; } catch (e) { priv = 'BLOCKED'; }"
        "log(priv);"
        "'done'",
        timeout=180,
    )
    assert result_of(out) == "done"
    assert "[log] 5" in out
    assert "[log] fake" in out
    assert "[log] 2/7" in out
    assert "[log] 11" in out
    assert "[log] 3" in out
    assert "RAW" not in out
    assert "[log] BLOCKED" in out or "[log] undefined" in out


class BlockingFacade:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def block(self):
        self.entered.set()
        self.release.wait(120)
        return "released"


@pytest.mark.unit
@pytest.mark.sandbox
def test_blocking_host_call_honors_timeout_and_recovers():
    facade = BlockingFacade()
    sup = SandboxSupervisor(lambda: {"ida": facade, "raw_ida": object()},
                            session_id_provider=lambda: "sess-host")
    try:
        started = time.monotonic()
        outcome = sup.run_ex("require('ida').block()", timeout=45.0)
        out = outcome["text"]
        elapsed = time.monotonic() - started
        assert "RunTimeout" in out
        assert "'host_call_abandoned': True" in out
        # 结构化信封必须把“超时发生在宿主调用等待阶段”如实标出
        assert outcome["ok"] is False
        assert outcome["error"]["error_type"] == "RunTimeout"
        assert outcome["error"]["host_call_abandoned"] is True
        assert outcome["error"]["phase"] == "awaiting_host_call"
        assert outcome["error"]["session_id"] == "sess-host"
        # 上界必须大于 worker 导入重依赖（angr 等）的耗时，
        # 否则测的是导入速度而非超时中断对宿主调用的有效性
        assert elapsed < 60.0
        assert facade.entered.wait(60.0)
        assert sup.has_orphan_host_call()

        with pytest.raises(RuntimeError, match="host call is still running"):
            with sup.session_mutation():
                pass
        pending = sup.run_ex("1", timeout=10)
        assert "HostCallPending" in pending["text"]
        assert pending["error"]["error_type"] == "HostCallPending"
        assert pending["error"]["phase"] == "host_call_pending"
    finally:
        facade.release.set()

    deadline = time.monotonic() + 5
    while sup.status()["host_calls_inflight"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert sup.status()["host_calls_inflight"] == 0
    assert not sup.has_orphan_host_call()
    assert sup.run("1 + 1", timeout=60).endswith("=> 2")


class IterFacade:
    def small_iter(self):
        return iter(range(5))

    def big_iter(self, n):
        return iter(range(n))

    def obj_iter(self, n):
        return (_Inner() for _ in range(n))


def _iter_worker(connection, request):
    from sandbox.worker import PROTOCOL_VERSION, WorkerRPCClient

    client = WorkerRPCClient(connection, request["run_id"], request["generation"])
    root = client.root("ida")
    out = {}
    for name, fn in (
        ("small_list", lambda: len(list(root.small_iter()))),
        ("big_list", lambda: len(list(root.big_iter(20000)))),
        ("big_for", lambda: sum(1 for _ in root.big_iter(20000))),
        ("big_sum", lambda: sum(root.big_iter(20000))),
        ("obj_values", lambda: sorted(o.value for o in root.obj_iter(50))[-1]),
    ):
        try:
            out[name] = repr(fn())
        except BaseException as exc:  # noqa: BLE001
            out[name] = f"{type(exc).__name__}: {exc}"
    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request["run_id"],
        "generation": request["generation"],
        "ok": True,
        "result": str(out),
    })
    connection.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_host_rpc_paged_iteration():
    """远程生成器可用 list()/tuple()/sum()，且大集合经分页迭代不触发传输上限。"""
    sup = SandboxSupervisor(
        lambda: {"ida": IterFacade(), "raw_ida": object()}, worker_target=_iter_worker)
    out = sup.run("unused", timeout=300)
    assert "'small_list': '5'" in out
    assert "'big_list': '20000'" in out
    assert "'big_for': '20000'" in out
    assert "'big_sum': '199990000'" in out
    assert "'obj_values': '7'" in out
    assert "Error" not in out


class DescFacade:
    version = "x"

    def method_a(self):
        return 1


@pytest.mark.unit
@pytest.mark.sandbox
def test_remote_describe_reports_real_attributes():
    """require.describe() 对远程引用应返回宿主对象的真实属性，而非空列表。"""
    sup = SandboxSupervisor(lambda: {"ida": DescFacade(), "raw_ida": object()})
    out = sup.run(
        "var d = require.describe('ida');"
        "var names = [];"
        "for (var i = 0; i < d.attributes.length; i++) names.push(d.attributes[i].name);"
        "'' + d.type + '/' + names.sort().join(',');",
        timeout=180,
    )
    assert result_of(out) == "DescFacade/method_a,version"


# ---- 属性链记忆化 / 批量 RPC / 分页上限 ----

class _AttrClient:
    """记录 getattr 次数的最小 RPC 客户端（不经过真实管道）。"""

    def __init__(self):
        self.ops = []

    def call(self, operation, target, **payload):
        self.ops.append((operation, payload.get("name")))
        name = payload.get("name")
        if name == "value":
            return 7  # 按值返回，不应被缓存
        path = list(target.get("path", [])) + [["attr", name]]
        return RemoteObject(self, {**target, "path": path}, True)


@pytest.mark.unit
@pytest.mark.sandbox
def test_remote_object_memoizes_path_refs_but_not_values():
    from sandbox.worker import RemoteObject

    client = _AttrClient()
    obj = RemoteObject(client, {"root": "ida"})

    assert obj.mod is obj.mod                       # 路径引用只解析一次
    assert client.ops == [("getattr", "mod")]
    assert obj.value == 7 and obj.value == 7        # 按值属性每次都取最新
    assert client.ops.count(("getattr", "value")) == 2


class _BatchClient:
    def __init__(self):
        self.batches = []

    def batch(self, ops):
        self.batches.append(ops)
        return {"results": [{"ok": True, "result": sum(op["args"])} for op in ops],
                "errors": 0}


@pytest.mark.unit
@pytest.mark.sandbox
def test_call_many_uses_one_batch_for_remote_and_loops_locally():
    from sandbox.rpc import call_many
    from sandbox.worker import RemoteObject

    client = _BatchClient()
    remote = RemoteObject(client, {"root": "ida"})
    assert remote.call_many([[1, 2], [3, 4], [5, 6]]) == [3, 7, 11]
    assert len(client.batches) == 1                 # N 次调用压成一次 RPC

    assert call_many(remote, [[1, 2], [3, 4]]) == [3, 7]
    assert len(client.batches) == 2

    # 本地对象（离线替身/进程内直连）退回普通循环，行为一致
    assert call_many(lambda a, b: a + b, [[1, 2], [3, 4]]) == [3, 7]


def _batch_worker(connection, request):
    from sandbox.worker import PROTOCOL_VERSION, WorkerRPCClient

    client = WorkerRPCClient(connection, request["run_id"], request["generation"])
    root = client.root("ida")
    out = {}
    try:
        out["values"] = root.add.call_many([[1, 2], [10, 20], [100, 200]])
        out["empty"] = root.add.call_many([])
        outcome = client.batch([
            {"op": "call", "target": {"root": "ida", "path": [["attr", "add"]]},
             "args": [1, 2], "kwargs": {}},
            {"op": "call", "target": {"root": "ida", "path": [["attr", "add"]]},
             "args": [1], "kwargs": {}},
        ])
        out["errors"] = outcome["errors"]
        out["first"] = outcome["results"][0]["result"]
        out["second_ok"] = outcome["results"][1]["ok"]
        out["second_type"] = outcome["results"][1]["error_type"]
    except BaseException as exc:  # noqa: BLE001
        out["exception"] = f"{type(exc).__name__}: {exc}"
    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request["run_id"],
        "generation": request["generation"],
        "ok": True,
        "result": str(out),
    })
    connection.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_host_rpc_batch_operation_and_error_isolation():
    facade = FakeFacade()
    sup = SandboxSupervisor(
        lambda: {"ida": facade, "raw_ida": object()}, worker_target=_batch_worker)
    out = sup.run("unused", timeout=300)

    assert "'values': [3, 30, 300]" in out
    assert "'empty': []" in out
    assert "'errors': 1" in out                     # 第二个子调用失败，整批仍返回
    assert "'first': 3" in out                      # 失败不影响同批其它项
    assert "'second_ok': False" in out
    assert "'second_type': 'TypeError'" in out
    assert "exception" not in out


@pytest.mark.unit
@pytest.mark.sandbox
def test_iter_page_bounds_parent_materialization(monkeypatch):
    import sandbox.supervisor as supervisor_module

    monkeypatch.setattr(supervisor_module, "_MAX_ITER_ITEMS", 10)
    sup = SandboxSupervisor(
        lambda: {"ida": IterFacade(), "raw_ida": object()}, worker_target=_iter_worker)
    out = sup.run("unused", timeout=300)

    assert "'small_list': '5'" in out               # 小集合不受影响
    assert "too large to page" in out               # 超限给出结构化错误
    assert "'big_list': '20000'" not in out
