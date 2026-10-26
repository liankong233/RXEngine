# -*- coding: utf-8 -*-
"""JS <-> Python(含 rpyc netref) 边界编组。

针对 STPyV8 在 Windows 上的两个约束设计：
  1. JS 的数字都是 float64；传入 Python 时大整数会变成 float，而 IDA 的 ea_t 等
     参数要求 int。故入参方向把"整数值的 float"还原为 int。
  2. STPyV8 用 32 位 C long 把 Python int 转成 JS number，超过 2^31 会溢出/截断。
     故返回方向把 int 转成 float（<=2^53 精确，覆盖真实地址），超大值转字符串。

rpyc 会把标量（int/str/bool 等）按值返回为真正的 Python 原生类型，isinstance 判断
可靠；只有复杂对象（如 func_t）是 netref 代理，用 Proxy 包裹以便 JS 继续访问其字段。

list/tuple 需转成真正的 JS 数组（否则 JS 侧拿到的对象只能下标索引、无 .length /
Array 方法）；而 STPyV8.JSArray 只能在活动 JSContext 内构造（context 外构造会段错误），
故按 JSContext.current 判断：有上下文才转 JSArray，纯 Python 环境退回普通 list。
"""
import STPyV8

from sandbox.worker import RemoteObject

_SAFE_INT = 2 ** 53
_MAX_DEPTH = 64
_MAX_ITEMS = 10000


def _check_depth(depth):
    if depth > _MAX_DEPTH:
        raise ValueError("JS bridge object is too deep")


def _check_items(count):
    if count > _MAX_ITEMS:
        raise ValueError("JS bridge object has too many items")


def _unwrap(p):
    """取出 Proxy 内部包裹的原始对象。"""
    return object.__getattribute__(p, "_obj")


def _to_js(v, depth=0):
    """把 Python 返回值转成 STPyV8 能安全传给 JS 的形式。"""
    _check_depth(depth)
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        # 绕开 Windows 上 STPyV8 的 32 位 long：小整数用 float（<=2^53 精确），
        # 超大整数（如 BADADDR=2^64-1）用字符串，避免溢出与精度丢失。
        if -_SAFE_INT <= v <= _SAFE_INT:
            return float(v)
        return str(v)
    if v is None or isinstance(v, (str, float)):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, dict):
        _check_items(len(v))
        return {k: _to_js(val, depth + 1) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        _check_items(len(v))
        items = [_to_js(x, depth + 1) for x in v]
        if STPyV8.JSContext.current is not None:
            return STPyV8.JSArray(items)
        return items
    # 其他（rpyc netref 对象、SWIG 代理等）：包成 Proxy 供 JS 继续访问/调用
    return Proxy(v)


def _wrap_js_callback(fn):
    """把 JS 函数包成 Python 可调用对象，供 qiling/unicorn 等回 JS 的 hook 使用。

    Python 侧（如 unicorn 引擎）以原生 int/对象回调，这里把每个实参经 _to_js 编组
    后再交给 JS 函数（地址等大整数才不会撞上 STPyV8 的 32 位溢出），JS 的返回值再
    经 _from_js 还原。hook 触发发生在 ql.run() 期间，此时仍在活动 JSContext 内。
    """
    def cb(*args):
        return _from_js(fn(*[_to_js(a) for a in args]))

    return cb


def _from_js(a, depth=0):
    """把 JS 传入的实参转成 Python 侧可用的值。"""
    _check_depth(depth)
    if isinstance(a, Proxy):
        return _unwrap(a)
    if isinstance(a, bool):
        return a
    if isinstance(a, float) and a.is_integer():
        # JS number 一律是 double，整数值还原为 int（ea_t 等参数需要）
        return int(a)
    # JSFunction / JSArray 都是 JSObject 子类，故先判具体类型再退到通用对象。
    if isinstance(a, STPyV8.JSFunction):
        return _wrap_js_callback(a)
    if isinstance(a, STPyV8.JSArray):
        _check_items(len(a))
        return [_from_js(a[i], depth + 1) for i in range(len(a))]
    if isinstance(a, STPyV8.JSObject):
        # 普通 JS 对象（如 create 的 opts、regs 初值）转成 Python dict
        keys = list(a.keys())
        _check_items(len(keys))
        return {k: _from_js(a[k], depth + 1) for k in keys}
    return a


class Proxy:
    """包裹 Python/netref 对象，在 JS<->Python 边界自动做参数与返回值编组。"""

    def __init__(self, obj):
        object.__setattr__(self, "_obj", obj)

    def __getattr__(self, name):
        # 屏蔽 JS 引擎对 dunder 的内部探测，避免无谓的 rpyc 往返；
        # 同时屏蔽单下划线私有属性，避免 JS 触达宿主对象的内部实现。
        if name.startswith("_"):
            raise AttributeError(name)
        attr = getattr(_unwrap(self), name)
        if self._is_callable(attr):
            def method(*args):
                return _to_js(attr(*[_from_js(a) for a in args]))

            return method
        return _to_js(attr)

    @staticmethod
    def _is_callable(attr):
        # 远程引用本身都带 __call__，用宿主侧编码时记录的提示区分方法与数据属性。
        if isinstance(attr, RemoteObject) and attr.remote_callable is not None:
            return attr.remote_callable
        return callable(attr)

    def __call__(self, *args):
        obj = _unwrap(self)
        return _to_js(obj(*[_from_js(a) for a in args]))

    def __getitem__(self, key):
        obj = _unwrap(self)
        return _to_js(obj[_from_js(key)])


def wrap(obj):
    """把已注册对象包成 JS 友好的代理，供 require() 返回。"""
    return _to_js(obj)
