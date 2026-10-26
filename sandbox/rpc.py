# -*- coding: utf-8 -*-
"""跨进程 RPC 调用助手（无重依赖，供 extensions/ 门面复用）。

worker 里经 RPC 暴露的宿主方法，每次属性链访问（模块 -> 方法 -> 调用）都要多次
往返。`call_many` 让"同一个方法批量调用"走一次批量 RPC；对本地对象（离线替身、
进程内直连）自动退回普通循环，行为不变。
"""


def call_many(func, args_list):
    """调用已解析出的宿主方法 N 次，args_list 为每次的位置参数序列。

    远程引用（sandbox.worker.RemoteObject）走单次批量 RPC 并保持顺序；本地对象
    退回普通循环。任一子调用失败按普通循环语义抛出（不返回部分结果）。
    """
    # 用 type(func) 判断而不触碰 func 自身：对 RemoteObject 触发 __getattr__ 会发 RPC。
    if hasattr(type(func), "call_many"):
        return func.call_many(args_list)
    return [func(*args) for args in args_list]
