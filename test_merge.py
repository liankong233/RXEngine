# -*- coding: utf-8 -*-
"""验证 JS 容器与 IDA 工具融合到同一 MCP 实例。"""
import asyncio
import os

import pytest

pytestmark = [pytest.mark.sse, pytest.mark.requires_ida, pytest.mark.ida, pytest.mark.slow]

from mcp import ClientSession
from mcp.client.sse import sse_client

URL = "http://127.0.0.1:8888/sse"
BINARY = os.environ.get("RXENGINE_SAMPLE") or os.path.join(
    os.path.dirname(__file__), "sample.exe")


def _text(result):
    return "\n".join(getattr(c, "text", str(c)) for c in result.content)


@pytest.mark.asyncio
async def test_merge_sse():
    async with sse_client(URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print(f"工具数={len(names)}")
            print("run_js 在工具集中:", "run_js" in names)

            r = await session.call_tool("run_js", {"code": "log('hi'); 1+2"})
            print("run_js ->", repr(_text(r)))

            # IDA 工具回归
            r = await session.call_tool("set_binary_path", {"path": BINARY})
            print("set_binary_path ->", _text(r))
            r = await session.call_tool(
                "run_js",
                {"code": "'' + require('ida').get_name_ea('pre_c_init')"})
            print("pre_c_init via run_js ->", _text(r))

            print("=== 融合验证完成 ===")


if __name__ == "__main__":
    asyncio.run(test_merge_sse())
