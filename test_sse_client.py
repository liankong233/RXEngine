# -*- coding: utf-8 -*-
"""SSE 客户端：验证 headless_ida_mcp_server 的各 IDA 工具。"""
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
    """从 CallToolResult 中取出文本内容。"""
    parts = []
    for c in result.content:
        parts.append(getattr(c, "text", str(c)))
    return "\n".join(parts)


@pytest.mark.asyncio
async def test_sse_client():
    async with sse_client(URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print(f"工具数={len(tools.tools)}")

            r = await session.call_tool("set_binary_path", {"path": BINARY})
            print("set_binary_path ->", _text(r))

            r = await session.call_tool("get_entry_points", {})
            print("get_entry_points ->", _text(r)[:400])

            r = await session.call_tool(
                "run_js",
                {"code": "'' + require('ida').get_name_ea('pre_c_init')"})
            fn_text = _text(r)
            print("pre_c_init via run_js ->", fn_text)

            addr = None
            # run_js 输出形如 "[log]...\n=> '<value>'"，取最后一段 => 后的值再转地址
            raw = fn_text.rsplit("=> ", 1)[-1].strip().strip("'")
            try:
                addr = int(raw, 0)
            except (ValueError, IndexError):
                addr = None
                print("解析地址失败:", raw)

            if addr is not None:
                r = await session.call_tool(
                    "disassemble_function", {"address": addr}
                )
                print("disassemble_function ->\n", _text(r)[:600])

                r = await session.call_tool(
                    "decompile_function", {"address": addr}
                )
                print("decompile_function ->\n", _text(r)[:600])

                r = await session.call_tool(
                    "run_js",
                    {"code": f"'' + JSON.stringify(require('ida').get_xrefs_to({addr}))"})
                print("get_xrefs_to ->", _text(r)[:400])

            print("=== 全部测试完成 ===")


if __name__ == "__main__":
    asyncio.run(test_sse_client())
