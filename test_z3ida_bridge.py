# -*- coding: utf-8 -*-
"""Z3IDA 沙箱桥接测试。"""

import pytest

import extensions
from sandbox import vm
from sandbox.registry import registry


@pytest.fixture(scope="module", autouse=True)
def register_extensions():
    extensions.register(registry)


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_require_z3ida():
    out = vm.run_js("var xs = require.list(); '' + (xs.indexOf('z3ida') >= 0);")
    assert result_of(out) == "true"
    out = vm.run_js("var d = require.describe('z3ida'); d.name + '/' + d.type;")
    assert result_of(out) == "z3ida/Z3IDAFacade"


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_z3ida_helpers():
    out = vm.run_js(
        "var z3 = require('z3');"
        "var z3ida = require('z3ida');"
        "var x = z3ida.bitvec('x', 8);"
        "var solved = z3ida.solve([z3.Eq(x, z3ida.bvv(1, 8))]);"
        "z3ida.isAlwaysTrue(z3.Eq(x, x)) + '/' + z3ida.isAlwaysFalse(z3.Ne(x, x)) + '/' + solved.result + '/' + solved.model.x;"
    )
    assert result_of(out) == "true/true/sat/0x01"


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_z3ida_no_ida_error():
    out = vm.run_js(
        "var z3ida = require('z3ida');"
        "var r = z3ida.checkBranch(0x401000);"
        "r.ok + '/' + r.error.type;"
    )
    assert result_of(out) == "false/ida_required"
