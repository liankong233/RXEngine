# -*- coding: utf-8 -*-
"""沙箱测试：registry / bridge 编组 / vm.run_js。"""

import pytest

from sandbox import bridge, vm
from sandbox.registry import Registry, registry


class FakeFunc:
    def __init__(self, ea):
        self.start_ea = ea
        self.end_ea = ea + 211

    def size(self):
        return self.end_ea - self.start_ea

    def contains(self, ea):
        return self.start_ea <= ea < self.end_ea


class FakeModule:
    BADADDR = 2 ** 64 - 1

    def get_func(self, ea):
        assert isinstance(ea, int), f"ea 必须是 int，实际 {type(ea).__name__}"
        return FakeFunc(ea)

    def get_name(self, ea):
        assert isinstance(ea, int)
        return "sub_%X" % ea

    def get_bytes(self, ea, n):
        assert isinstance(ea, int) and isinstance(n, int)
        return bytes(range(n))

    def iterable(self):
        return iter([1, 2, 3])


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


@pytest.mark.unit
def test_registry():
    r = Registry()
    obj = object()
    r.register("a", obj)
    assert r.get("a") is obj
    r.register_many({"b": 1, "c": 2})
    assert r.get("b") == 1
    assert r.get("c") == 2
    assert set(r.names()) == {"a", "b", "c"}
    desc = r.describe("b")
    assert desc["name"] == "b"
    assert desc["type"] == "int"
    r.unregister("a")
    assert "a" not in r.names()
    with pytest.raises(KeyError):
        r.get("missing")


@pytest.mark.unit
def test_bridge_marshal():
    assert bridge._from_js(5368713232.0) == 5368713232
    assert isinstance(bridge._from_js(5368713232.0), int)
    assert bridge._from_js(3.5) == 3.5
    assert bridge._from_js(True) is True
    assert bridge._to_js(0x140001000) == float(0x140001000)
    assert isinstance(bridge._to_js(0x140001000), float)
    assert bridge._to_js(2 ** 64 - 1) == "18446744073709551615"
    assert bridge._to_js(b"\x48\x83\xec\x28") == "4883ec28"
    assert bridge._to_js(True) is True
    assert bridge._to_js(None) is None
    assert bridge._to_js("x") == "x"
    assert bridge._to_js({"ea": 5368713232, "name": "f"}) == {"ea": 5368713232.0, "name": "f"}
    assert bridge._to_js([1, 2 ** 64 - 1]) == [1.0, "18446744073709551615"]


@pytest.mark.unit
def test_bridge_proxy():
    p = bridge.Proxy(FakeModule())
    f = p.get_func(5368713232.0)
    assert isinstance(f, bridge.Proxy)
    assert f.start_ea == 5368713232.0
    assert f.end_ea == 5368713232.0 + 211
    assert f.size() == 211.0
    assert f.contains(5368713232.0) is True
    assert p.BADADDR == "18446744073709551615"
    assert p.get_bytes(0x1000, 4) == "00010203"
    assert bridge._from_js(f) is object.__getattribute__(f, "_obj")


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_basic():
    out = vm.run_js("log('a'); log('b'); 1 + 2")
    assert result_of(out) == "3"
    assert "[log] a" in out
    assert "[log] b" in out


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_output_limits():
    out = vm.run_js(
        "log('abcdef'); log('ghijkl'); '123456789'",
        max_log_lines=10,
        max_log_line_chars=3,
        max_log_chars=5,
        max_result_chars=4,
    )
    assert "[log] abc... [truncated]" in out
    assert "[log] ... log output truncated after 5 total characters" in out
    assert "truncated after 10 log lines" not in out
    assert result_of(out) == "1234... [truncated]"


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_reports_truncation_reason():
    by_lines = vm.run_js("log('a'); log('b'); log('c'); 'ok'", max_log_lines=2)
    assert "[log] ... truncated after 2 log lines" in by_lines

    by_line_chars = vm.run_js("log('abcdefgh'); 'ok'", max_log_line_chars=3)
    assert "[log] ... log lines truncated to 3 characters" in by_line_chars


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_rejects_invalid_limits():
    with pytest.raises(ValueError, match="max_log_lines"):
        vm.run_js("1", max_log_lines=-1)
    with pytest.raises(ValueError, match="max_result_chars"):
        vm.run_js("1", max_result_chars=1000001)


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_complex_result_stays_inside_context():
    assert result_of(vm.run_js("({answer: 42})")) == "[object Object]"
    assert result_of(vm.run_js("[1, 2, 3]")) == "1,2,3"


@pytest.mark.unit
@pytest.mark.sandbox
def test_vm_require_bridge():
    registry.register("fake", FakeModule())
    try:
        out = vm.run_js("var xs = require.list(); '' + (xs.indexOf('fake') >= 0);")
        assert result_of(out) == "true"
        out = vm.run_js("var d = require.describe('fake'); '' + d.name + '/' + d.attributes.length;")
        parts = result_of(out).split("/")
        assert parts[0] == "fake"
        assert int(parts[1]) > 0
        out = vm.run_js(
            "var m = require('fake');"
            "var f = m.get_func(5368713232);"
            "'' + f.start_ea + '/' + f.size() + '/' + m.get_name(5368713232);"
        )
        assert result_of(out) == "5368713232/211/sub_140001010"
        out = vm.run_js("'' + require('fake').BADADDR")
        assert result_of(out) == "18446744073709551615"
        out = vm.run_js("require('fake').get_bytes(4096, 4)")
        assert result_of(out) == "00010203"
        out = vm.run_js("require('nope')")
        assert "'ok': False" in out
        assert "KeyError" in out
        assert "nope" in out
    finally:
        registry.unregister("fake")
