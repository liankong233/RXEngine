# -*- coding: utf-8 -*-
"""RXEngine 融合入口。

JS 沙箱（run_js）与 IDA 逆向工具合并到同一个 FastMCP 实例，
配置来源：.env 提供默认值，命令行参数可覆盖。
"""
import argparse
import os

from mcp.server import FastMCP

from headless_ida_mcp_server import HOST, IDA_PATH, PORT, TRANSPORT
from headless_ida_mcp_server import server as _server

# 唯一的 MCP 实例，工具在此注册
mcp = FastMCP("IDA MCP Server", host=HOST, port=PORT)
_server.register(mcp)


def parse_args(argv=None) -> argparse.Namespace:
    """解析命令行配置，未提供的项回退到 .env 默认值。"""
    parser = argparse.ArgumentParser(
        prog="rxengine",
        description="RXEngine MCP：JS 沙箱 + IDA 逆向工具",
    )
    parser.add_argument(
        "--host", default=HOST, help="SSE 监听地址（默认取 .env HOST）"
    )
    parser.add_argument(
        "--port", type=int, default=PORT, help="SSE 监听端口（默认取 .env PORT）"
    )
    parser.add_argument(
        "--transport",
        default=TRANSPORT,
        choices=["sse", "stdio"],
        help="传输方式（默认取 .env TRANSPORT）",
    )
    parser.add_argument(
        "--ida-path",
        default=IDA_PATH,
        help="IDA idat 可执行文件路径（默认取 .env IDA_PATH）",
    )
    return parser.parse_args(argv)


def apply_config(args: argparse.Namespace) -> None:
    """把解析出的配置应用到 MCP 实例与 IDA 后端。"""
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    # helper 在导入时已按值绑定 IDA_PATH，这里同步更新其模块属性与环境变量，
    # 使 --ida-path 对后续 set_binary_path 创建的 IDA 实例生效。
    from headless_ida_mcp_server import helper as _helper

    _helper.IDA_PATH = args.ida_path
    os.environ["IDA_PATH"] = args.ida_path


def main(argv=None) -> None:
    args = parse_args(argv)
    apply_config(args)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
