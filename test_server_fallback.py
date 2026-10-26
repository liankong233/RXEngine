# -*- coding: utf-8 -*-
import asyncio

import pytest

from headless_ida_mcp_server import server


class FakeArgModel:
    model_fields = {"min_score": object(), "address": object()}


class FakeFnMetadata:
    arg_model = FakeArgModel()


class FakeTool:
    fn_metadata = FakeFnMetadata()


class FakeToolManager:
    def __init__(self):
        self.seen_arguments = None

    def get_tool(self, name):
        return FakeTool()

    async def call_tool(self, name, arguments, *args, **kwargs):
        self.seen_arguments = arguments
        if name == "boom":
            raise RuntimeError("detector exited")
        return {"ok": True, "arguments": arguments}


class FakeMCP:
    def __init__(self):
        self._tool_manager = FakeToolManager()


@pytest.mark.unit
def test_tool_dispatch_normalizes_argument_keys():
    mcp = FakeMCP()
    server._install_arg_key_normalizer(mcp)

    result = asyncio.run(mcp._tool_manager.call_tool("scan", {"Min-Score": 7, "Address": 0x401000}))

    assert result == {"ok": True, "arguments": {"min_score": 7, "address": 0x401000}}


@pytest.mark.unit
def test_tool_dispatch_returns_recoverable_fallback_on_exception():
    mcp = FakeMCP()
    server._install_arg_key_normalizer(mcp)

    result = asyncio.run(mcp._tool_manager.call_tool("boom", {"Min-Score": 7}))

    assert result["ok"] is False
    assert result["recoverable"] is True
    assert result["error_type"] == "RuntimeError"
    assert result["message"] == "detector exited"
    assert result["tool"] == "boom"
    assert result["arguments"] == {"Min-Score": 7}
