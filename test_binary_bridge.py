# -*- coding: utf-8 -*-
"""pyelftools / capstone / keystone 沙箱桥接测试。"""

import pytest

import extensions
from sandbox import vm
from sandbox.registry import registry


ELF32_MINIMAL = (
    "7f454c46010101000000000000000000"
    "020003000100000000804804340000000000000000000000340020000100280000000000"
    "0100000000000000008048040080048000000000000000000500000000100000"
)


@pytest.fixture(scope="module", autouse=True)
def register_extensions():
    extensions.register(registry)


def result_of(out: str):
    return out.rsplit("=> ", 1)[-1]


@pytest.mark.unit
@pytest.mark.sandbox
def test_require_modules():
    out = vm.run_js(
        "var xs = require.list();"
        "['elf','pyelftools','capstone','keystone','binary'].map(function(x){ return xs.indexOf(x) >= 0; }).join('/');"
    )
    assert result_of(out) == "true/true/true/true/true"


@pytest.mark.unit
@pytest.mark.sandbox
def test_capstone_disasm():
    out = vm.run_js(
        "var cs = require('capstone');"
        "var ins = cs.disasm('554889e5', 'x64', 0x1000);"
        "ins.length + '/' + ins[0].mnemonic + '/' + ins[0].opStr + '/' + ins[1].text;"
    )
    assert result_of(out) == "2/push/rbp/mov rbp, rsp"


@pytest.mark.unit
@pytest.mark.sandbox
def test_keystone_asm():
    out = vm.run_js(
        "var ks = require('keystone');"
        "var r = ks.asm('push rbp; mov rbp, rsp', 'x64', 0x1000);"
        "r.ok + '/' + r.count + '/' + r.bytes;"
    )
    assert result_of(out) == "true/2/554889e5"


@pytest.mark.unit
@pytest.mark.sandbox
def test_binary_roundtrip():
    out = vm.run_js(
        "var bin = require('binary');"
        "var asm = bin.keystone.asm('nop', 'x64');"
        "var ins = bin.capstone.disasm(asm.bytes, 'x64', 0);"
        "asm.bytes + '/' + ins[0].mnemonic + '/' + bin.bytesToHex([0x41, 0x42]);"
    )
    assert result_of(out) == "90/nop/4142"


@pytest.mark.unit
@pytest.mark.sandbox
def test_pyelftools_parse():
    out = vm.run_js(
        "var elf = require('elf');"
        f"var e = elf.parse('{ELF32_MINIMAL}');"
        "e.ok + '/' + e.class + '/' + e.machine + '/' + e.entry + '/' + e.segments.length;"
    )
    assert result_of(out) == "true/32/EM_386/71860224/1"
