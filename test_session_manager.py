# -*- coding: utf-8 -*-
"""SessionManager：按 MCP 连接隔离分析会话（binary/IDA/黑板/worker）。"""
import asyncio
import gc
import time

import pytest

from headless_ida_mcp_server import server


class FakeServerSession:
    """可弱引用的连接身份替身，对应 FastMCP 每个传输连接一个的 ServerSession。"""


class FakeRequestContext:
    def __init__(self, session):
        self.session = session


class FakeContext:
    def __init__(self, session):
        self.request_context = FakeRequestContext(session)


@pytest.fixture(autouse=True)
def _clean_manager():
    yield
    server._manager.close_all()


@pytest.mark.unit
def test_for_request_without_context_uses_single_fallback():
    assert server._session(None) is server._session()
    assert server._manager.counts()["fallback"] is True


@pytest.mark.unit
def test_distinct_connections_get_isolated_sessions():
    first, second = FakeServerSession(), FakeServerSession()

    a = server._session(FakeContext(first))
    b = server._session(FakeContext(second))

    assert a is not b
    assert a.session_id != b.session_id
    assert a.board is not b.board
    assert a.supervisor is not b.supervisor
    # 同一连接稳定映射到同一会话
    assert server._session(FakeContext(first)) is a
    assert server._manager.counts()["active"] == 2


@pytest.mark.unit
def test_connection_gc_releases_session():
    connection = FakeServerSession()
    server._session(FakeContext(connection))
    assert server._manager.counts()["active"] == 1

    del connection
    gc.collect()

    assert server._manager.counts()["active"] == 0


@pytest.mark.unit
def test_idle_ttl_evicts_and_recreates_session():
    manager = server.SessionManager(max_sessions=2, idle_ttl=0.01)
    try:
        connection = FakeServerSession()
        ctx = FakeContext(connection)
        session = manager.for_request(ctx)
        assert manager.counts()["active"] == 1

        time.sleep(0.05)
        # 下一次请求先触发空闲回收，再为同一连接重建会话
        assert manager.for_request(ctx) is not session
    finally:
        manager.close_all()


@pytest.mark.unit
def test_capacity_evicts_oldest_idle_session():
    manager = server.SessionManager(max_sessions=2, idle_ttl=0)
    try:
        c1, c2, c3 = FakeServerSession(), FakeServerSession(), FakeServerSession()
        manager.for_request(FakeContext(c1))   # 最久未使用
        second = manager.for_request(FakeContext(c2))
        third = manager.for_request(FakeContext(c3))

        assert manager.counts()["active"] == 2
        # c1 被淘汰，c2/c3 的会话保持不变
        assert manager.for_request(FakeContext(c2)) is second
        assert manager.for_request(FakeContext(c3)) is third
    finally:
        manager.close_all()


@pytest.mark.unit
def test_unknown_context_falls_back_instead_of_failing():
    class BrokenContext:
        @property
        def request_context(self):
            raise RuntimeError("no request context")

    fallback = server._session()
    assert server._session(BrokenContext()) is fallback


@pytest.mark.unit
def test_tools_resolve_session_from_mcp_context():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("session-probe")
    server.register(mcp)
    tools = mcp._tool_manager

    first, second = FakeServerSession(), FakeServerSession()
    a1 = asyncio.run(tools.call_tool("engine_status", {}, context=FakeContext(first)))
    a2 = asyncio.run(tools.call_tool("engine_status", {}, context=FakeContext(first)))
    b1 = asyncio.run(tools.call_tool("engine_status", {}, context=FakeContext(second)))

    assert a1["session_id"] == a2["session_id"]
    assert a1["session_id"] != b1["session_id"]
    assert a1["sessions"]["active"] == 1   # a1 在第二个连接出现前产生
    assert b1["sessions"]["active"] == 2
