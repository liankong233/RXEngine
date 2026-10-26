# -*- coding: utf-8 -*-
"""离线测试（无需 IDA）：验证 angr/claripy 到 JS 的基础桥接。"""

import pytest

pytestmark = [pytest.mark.angr, pytest.mark.slow, pytest.mark.sandbox]

from extensions.angr_ext import AngrFacade
from extensions import register
from sandbox import vm
from sandbox.registry import registry

_PASS = 0
_FAIL = 0


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  [PASS] {name}")
    else:
        _FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


def run(name, code, cond_fn, expect_desc=""):
    out = vm.run_js(code)
    res = result_of(out)
    print(f"[{name}]")
    print("   ", out.replace("\n", " | "))
    check(name, cond_fn(res), f"got {res} (want {expect_desc})")
    return res


def main():
    register(registry)
    registry.register("angr", AngrFacade())

    run(
        "symbolic equality solve",
        "var a = require('angr');"
        "var x = a.bvs('x', 8);"
        "var s = a.blank_state(a.project('.venv/Scripts/python.exe', {auto_load_libs:false}));"
        "a.add(s, a.eq(x, a.bvv(0x41, 8)));"
        "'' + a.eval(s, x);",
        lambda r: r == "65",
        "65",
    )

    run(
        "eval_upto returns JS array",
        "var a = require('angr');"
        "var x = a.bvs('x', 8);"
        "var s = a.blank_state(a.project('.venv/Scripts/python.exe', {auto_load_libs:false}));"
        "a.add(s, a.uge(x, a.bvv(1, 8)));"
        "a.add(s, a.ule(x, a.bvv(3, 8)));"
        "var xs = a.eval_upto(s, x, 3);"
        "'' + xs.length + '/' + xs.sort().join(',');",
        lambda r: r == "3/1,2,3",
        "3/1,2,3",
    )

    run(
        "loader info",
        "var a = require('angr');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var info = a.loader_object(p);"
        "'' + (info.entry > 0) + '/' + info.arch;",
        lambda r: r.startswith("true/"),
        "true/<arch>",
    )

    run(
        "declarative return const",
        "var a = require('angr');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var summary = a.hook_declarative(p, 0x401000, {behavior:'return_const', value:7, argc:0});"
        "'' + summary.hook + '/' + summary.behavior + '/' + summary.argc;",
        lambda r: r == "declarative/return_const/0",
        "declarative/return_const/0",
    )

    run(
        "declarative memory ops",
        "var a = require('angr');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var s = a.blank_state(p);"
        "a.mem_write(s, 0x5000, '41424344');"
        "var memcpy = a.hook_declarative(p, 0x401010, {behavior:'memcpy'});"
        "a.hook_declarative(p, 0x401020, {behavior:'memset'});"
        "a.apply_declarative(s, {behavior:'memcpy'}, [0x6000, 0x5000, 4]);"
        "a.apply_declarative(s, {behavior:'memset'}, [0x7000, 0x58, 3]);"
        "'' + memcpy.behavior + '/' + a.mem_read(s, 0x6000, 4) + '/' + a.mem_read(s, 0x7000, 3);",
        lambda r: r == "memcpy/44434241/585858",
        "memcpy/44434241/585858",
    )

    run(
        "declarative libc strings",
        "var a = require('angr');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var s = a.blank_state(p);"
        "a.mem_write(s, 0x5000, '61626300');"
        "a.mem_write(s, 0x5100, '61626400');"
        "a.mem_write(s, 0x5200, '626300');"
        "var len = a.apply_declarative(s, {behavior:'strlen'}, [0x5000]);"
        "var cmp = a.apply_declarative(s, {behavior:'strcmp'}, [0x5000, 0x5100]);"
        "var ncmp = a.apply_declarative(s, {behavior:'strncmp'}, [0x5000, 0x5100, 2]);"
        "var found = a.apply_declarative(s, {behavior:'strstr'}, [0x5000, 0x5200]);"
        "a.apply_declarative(s, {behavior:'strcpy'}, [0x6000, 0x5000]);"
        "a.apply_declarative(s, {behavior:'strncpy'}, [0x6100, 0x5000, 5]);"
        "'' + len + '/' + cmp + '/' + ncmp + '/' + (found - 0x5000) + '/' + a.mem_read(s, 0x6000, 4) + '/' + a.mem_read(s, 0x6100, 5);",
        lambda r: r == "3/-1/0/1/00636261/0000636261",
        "3/-1/0/1/00636261/0000636261",
    )

    run(
        "declarative libc allocation",
        "var a = require('angr');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var s = a.blank_state(p);"
        "var one = a.apply_declarative(s, {behavior:'malloc', base:0x70000000, step:0x1000}, [0x20]);"
        "var two = a.apply_declarative(s, {behavior:'malloc', base:0x70000000, step:0x1000}, [0x20]);"
        "var freed = a.apply_declarative(s, {behavior:'free'}, [one]);"
        "'' + one + '/' + two + '/' + freed;",
        lambda r: r == "1879048192/1879052288/0",
        "1879048192/1879052288/0",
    )

    run(
        "rxstubs libc profile installs into angr",
        "var a = require('angr'); var r = require('rxstubs');"
        "var p = a.project('.venv/Scripts/python.exe', {auto_load_libs:false});"
        "var reg = new r.StubRegistry(); r.installLibcDeclarativeProfile(reg);"
        "var specs = reg.exportDeclarative({names:['strlen', 'memcpy', 'free']});"
        "var installs = []; for (var i = 0; i < specs.length; i++) installs.push({addr:0x402000 + i * 0x10, spec:specs[i]});"
        "var out = a.hook_declarative_many(p, installs);"
        "'' + out.length + '/' + out[0].behavior + '/' + out[1].behavior + '/' + out[2].behavior;",
        lambda r: r == "3/strlen/memcpy/return_const",
        "3/strlen/memcpy/return_const",
    )

    assert _FAIL == 0


@pytest.mark.angr
@pytest.mark.slow
@pytest.mark.sandbox
def test_angr_bridge():
    global _PASS, _FAIL
    _PASS = 0
    _FAIL = 0
    main()


if __name__ == "__main__":
    main()
