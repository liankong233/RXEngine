# -*- coding: utf-8 -*-
"""Z3 沙箱桥接测试。"""

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
def test_require_z3():
    out = vm.run_js("var xs = require.list(); '' + (xs.indexOf('z3') >= 0);")
    assert result_of(out) == "true"
    out = vm.run_js("var d = require.describe('z3'); d.name + '/' + d.type;")
    assert result_of(out) == "z3/Z3Facade"


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_int_sat_model():
    out = vm.run_js(
        "var z3 = require('z3');"
        "var x = z3.Int('x');"
        "var y = z3.Int('y');"
        "var s = z3.Solver();"
        "s.add(z3.Gt(x, 0));"
        "s.add(z3.Gt(y, 0));"
        "s.add(z3.Eq(z3.Add(x, y), 10));"
        "var r = s.check();"
        "var m = s.model();"
        "r + '/' + m.eval(x, true) + '/' + m.eval(y, true);"
    )
    parts = result_of(out).split("/")
    assert parts[0] == "sat"
    assert int(parts[1]) + int(parts[2]) == 10


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_unsat():
    out = vm.run_js(
        "var z3 = require('z3');"
        "var x = z3.Int('x');"
        "var s = z3.Solver();"
        "s.add(z3.Gt(x, 5));"
        "s.add(z3.Lt(x, 3));"
        "s.check();"
    )
    assert result_of(out) == "unsat"


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_bool_model():
    out = vm.run_js(
        "var z3 = require('z3');"
        "var a = z3.Bool('a');"
        "var b = z3.Bool('b');"
        "var s = z3.Solver();"
        "s.add(z3.And(a, z3.Not(b)));"
        "var r = s.check();"
        "var m = s.model();"
        "r + '/' + m.eval(a, true) + '/' + m.eval(b, true);"
    )
    assert result_of(out) == "sat/true/false"


@pytest.mark.unit
@pytest.mark.z3
@pytest.mark.sandbox
def test_bitvec_helpers():
    out = vm.run_js(
        "var z3 = require('z3');"
        "var x = z3.bitvec('x', 8);"
        "var one = z3.bvv(1, 8);"
        "var solved = z3.solve([z3.Eq(x, one)]);"
        "solved.result + '/' + solved.model.x + '/' + z3.isAlwaysTrue(z3.Eq(x, x)) + '/' + z3.isAlwaysFalse(z3.Ne(x, x));"
    )
    assert result_of(out) == "sat/0x01/true/true"
