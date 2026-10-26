# -*- coding: utf-8 -*-
"""对象注册表：各模块把可供 JS require() 获取的对象主动注册进来。

与旧的 importlib 方案相反——sandbox 不再主动 import 任意模块，只暴露
已被显式注册的对象（例如 IDA 集成会注册 idaapi、idautils 等）。
"""


class Registry:
    def __init__(self):
        self._objects: dict = {}

    def register(self, name: str, obj) -> None:
        """注册一个可被 require(name) 获取的对象（重名覆盖）。"""
        self._objects[name] = obj

    def register_many(self, mapping: dict) -> None:
        """批量注册 {name: obj}。"""
        self._objects.update(mapping)

    def unregister(self, name: str) -> None:
        self._objects.pop(name, None)

    def get(self, name: str):
        if name not in self._objects:
            raise KeyError(f"require: '{name}' 未注册")
        return self._objects[name]

    def names(self) -> list:
        return list(self._objects)

    def describe(self, name: str) -> dict:
        obj = self.get(name)
        # 远程引用（worker 里的 RPC 代理）自身没有可读属性，改由宿主侧内省后回传，
        # 使 require.describe() 在进程内与沙箱两条路径下给出同样的结果。
        remote_describe = getattr(obj, "__describe__", None)
        if callable(remote_describe):
            result = dict(remote_describe())
            result["name"] = name
            return result
        attrs = []
        for attr in dir(obj):
            if attr.startswith("_"):
                continue
            try:
                value = getattr(obj, attr)
            except Exception:  # noqa: BLE001
                attrs.append({"name": attr, "kind": "unreadable"})
                continue
            attrs.append({"name": attr, "kind": "method" if callable(value) else "value"})
        return {"name": name, "type": type(obj).__name__, "attributes": attrs}


# 全局单例：模块注册与 require 查找共用同一个实例
registry = Registry()
