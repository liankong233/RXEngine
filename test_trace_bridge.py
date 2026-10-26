# -*- coding: utf-8 -*-
"""离线测试（无需 IDA）：验证 qiling trace API。"""

import pytest

pytestmark = [pytest.mark.qiling, pytest.mark.slow, pytest.mark.sandbox]

from extensions.qiling_ext import QilingFacade
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
    registry.register("qiling", QilingFacade())

    run(
        "trace_code records instructions",
        "var q = require('qiling');"
        "var t = q.trace_code('48c7c00100000048c7c3020000004801d8');"
        "'' + t.length + '/' + t[0].mnemonic + '/' + t[2].regs.rax;",
        lambda r: r == "3/mov/1",
        "3/mov/1",
    )

    run(
        "trace_code count limits execution",
        "var q = require('qiling');"
        "var t = q.trace_code('48c7c00100000048c7c3020000004801d8', 2);"
        "'' + t.length + '/' + t[1].mnemonic;",
        lambda r: r == "2/mov",
        "2/mov",
    )

    run(
        "trace_code maps ida address",
        "var q = require('qiling');"
        "var t = q.trace_code('9090', 0, 'x8664', 'linux', null, 0x140001000);"
        "'' + t[0].ida_ea + '/' + t[1].ida_ea;",
        lambda r: r == "5368713216/5368713217",
        "0x140001000/0x140001001",
    )

    run(
        "trace captures memory write",
        "var q = require('qiling');"
        "var ql = q.create('c70078563412', {arch:'x86', os:'linux'});"
        "q.map_mem(ql, 0x2000000, 0x1000);"
        "q.set_reg(ql, 'eax', 0x2000000);"
        "var t = q.trace(ql);"
        "'' + t.length + '/' + t[0].mem_writes.length + '/' + t[0].mem_writes[0].value;",
        lambda r: r == "1/1/305419896",
        "1/1/305419896",
    )

    run(
        "trace captures memory read",
        "var q = require('qiling');"
        "var ql = q.create('8b00', {arch:'x86', os:'linux'});"
        "q.map_mem(ql, 0x2000000, 0x1000);"
        "q.mem_write(ql, 0x2000000, '78563412');"
        "q.set_reg(ql, 'eax', 0x2000000);"
        "var t = q.trace(ql);"
        "'' + t[0].mem_reads.length + '/' + t[0].mem_reads[0].value;",
        lambda r: r == "1/305419896",
        "1/305419896",
    )

    run(
        "strings_from_trace extracts writes",
        "var q = require('qiling');"
        "var ql = q.create('c60048c6400169c6400221', {arch:'x86', os:'linux'});"
        "q.map_mem(ql, 0x2000000, 0x1000);"
        "q.set_reg(ql, 'eax', 0x2000000);"
        "var r = q.trace(ql, {strings:{min_len:3}});"
        "'' + r.strings.length + '/' + r.strings[0].text + '/' + r.strings[0].length;",
        lambda r: r == "1/Hi!/3",
        "1/Hi!/3",
    )

    run(
        "strings option accepts boolean",
        "var q = require('qiling');"
        "var ql = q.create('c60048c6400169c6400221c640033f', {arch:'x86', os:'linux'});"
        "q.map_mem(ql, 0x2000000, 0x1000);"
        "q.set_reg(ql, 'eax', 0x2000000);"
        "var r = q.trace(ql, {strings:true});"
        "'' + r.strings.length + '/' + r.strings[0].text;",
        lambda r: r == "1/Hi!?",
        "1/Hi!?",
    )

    assert _FAIL == 0


@pytest.mark.qiling
@pytest.mark.slow
@pytest.mark.sandbox
def test_trace_bridge():
    global _PASS, _FAIL
    _PASS = 0
    _FAIL = 0
    main()


if __name__ == "__main__":
    main()
