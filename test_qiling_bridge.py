# -*- coding: utf-8 -*-
"""离线测试（无需 IDA）：验证 qiling/unicorn 到 JS 的完整桥接。

覆盖 create() 活实例、寄存器读写、内存读写、JS 回调 hook、底层 unicorn 引擎访问。
用 shellcode 模式，rootfs 用当前目录占位，不依赖任何目标系统运行库，跑得快。
"""

import pytest

pytestmark = [pytest.mark.qiling, pytest.mark.slow, pytest.mark.sandbox]

import unicorn as _unicorn
from unicorn import x86_const

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
    registry.register("unicorn", _unicorn)
    registry.register("unicorn_x86", x86_const)

    # 1) create + run + 读寄存器：mov rax,1; mov rbx,2; add rax,rbx => rax=3
    run("create/run/read reg",
        "var ql = require('qiling').create('48c7c00100000048c7c3020000004801d8');"
        "ql.run(); '' + ql.arch.regs.read('rax');",
        lambda r: r == "3", "3")

    # 2) 运行前写寄存器：add rax,rbx，预置 rax=10 rbx=20 => 30
    run("write reg before run",
        "var ql = require('qiling').create('4801d8');"
        "ql.arch.regs.write('rax', 10); ql.arch.regs.write('rbx', 20);"
        "ql.run(); '' + ql.arch.regs.read('rax');",
        lambda r: r == "30", "30")

    # 3) create 带 opts（对象 -> dict）：x86 32 位，mov eax,5 (b805000000) => eax=5
    run("create with opts object",
        "var ql = require('qiling').create('b805000000', {arch:'x86', os:'linux'});"
        "ql.run(); '' + ql.arch.regs.read('eax');",
        lambda r: r == "5", "5")

    # 4) 内存写(hex) + 读(直接 ql.mem.read -> hex)
    run("mem_write hex + ql.mem.read -> hex",
        "var q = require('qiling'); var ql = q.create('90');"
        "q.mem_write(ql, 0x1100000, 'deadbeef');"
        "ql.mem.read(0x1100000, 4);",
        lambda r: r == "deadbeef", "deadbeef")

    # 5) 内存写(字节数组 -> list -> bytes)
    run("mem_write byte array",
        "var q = require('qiling'); var ql = q.create('90');"
        "q.mem_write(ql, 0x1100000, [1,2,3,4]);"
        "ql.mem.read(0x1100000, 4);",
        lambda r: r == "01020304", "01020304")

    # 6) JS 回调 hook：统计执行指令数（3 条指令的 shellcode）
    run("JS callback hook_code fires",
        "var ql = require('qiling').create('48c7c00100000048c7c3020000004801d8');"
        "var n = 0; ql.hook_code(function(q, addr, size){ n++; });"
        "ql.run(); '' + n;",
        lambda r: r == "3", "3")

    # 7) hook 回调里拿到的地址是精确大整数（经 bridge 编组，无 32 位溢出）
    run("hook addr marshaled correctly",
        "var ql = require('qiling').create('90');"
        "var first = -1; ql.hook_code(function(q, addr, size){ if(first<0) first=addr; });"
        "ql.run(); '' + first;",
        lambda r: r == "18870272", "0x11ff000=18870272")

    # 8) 直接驱动底层 unicorn 引擎：ql.arch.uc.reg_read(UC_X86_REG_RAX)
    run("raw unicorn engine access",
        "var uc_x86 = require('unicorn_x86');"
        "var ql = require('qiling').create('48c7c0630000004801d8');"  # mov rax,0x63; add rax,rbx
        "ql.arch.regs.write('rbx', 1); ql.run();"
        "'' + ql.arch.uc.reg_read(uc_x86.UC_X86_REG_RAX);",
        lambda r: r == "100", "0x63+1=100")

    # 9) unicorn 常量可读（UC_HOOK_CODE 是整数）
    run("unicorn constant readable",
        "'' + (require('unicorn').UC_HOOK_CODE > 0);",
        lambda r: r == "true", "true")

    # 10) run(ql, {count}) 便捷执行 + 返回寄存器 dump
    run("run() with count returns reg dump",
        "var q = require('qiling');"
        "var ql = q.create('48c7c00100000048c7c3020000004801d8');"
        "var r = q.run(ql, {count: 2});"  # 只跑前两条：mov rax,1; mov rbx,2
        "'' + r.rax + '/' + r.rbx;",
        lambda r: r == "1/2", "1/2")

    # 11) regs(ql) 批量 dump 全部通用寄存器
    run("regs() dumps all GP regs",
        "var q = require('qiling'); var ql = q.create('90'); ql.run();"
        "var r = q.regs(ql); '' + ('rax' in r) + ',' + ('r15' in r) + ',' + (Object.keys(r).length);",
        lambda r: r == "true,true,17", "true,true,17")

    # 12) set_regs(ql, {..}) 批量写
    run("set_regs writes many",
        "var q = require('qiling'); var ql = q.create('4801d8');"  # add rax,rbx
        "q.set_regs(ql, {rax: 7, rbx: 8}); q.run(ql);"
        "'' + q.get_reg(ql, 'rax');",
        lambda r: r == "15", "15")

    # 13) alloc + mem_write + mem_read 往返
    run("alloc/mem_write/mem_read roundtrip",
        "var q = require('qiling'); var ql = q.create('90');"
        "var addr = q.alloc(ql, 0x1000);"
        "q.mem_write(ql, addr, 'cafebabe');"
        "q.mem_read(ql, addr, 4);",
        lambda r: r == "cafebabe", "cafebabe")

    # 14) map_mem 固定地址映射后可读写
    run("map_mem fixed address",
        "var q = require('qiling'); var ql = q.create('90');"
        "q.map_mem(ql, 0x2000000, 0x1000); q.mem_write(ql, 0x2000000, '11223344');"
        "ql.mem.read(0x2000000, 4);",
        lambda r: r == "11223344", "11223344")

    # 15) disasm 反汇编，返回指令列表
    run("disasm returns instruction list",
        "var q = require('qiling'); var ql = q.create('90');"
        "var addr = q.alloc(ql, 0x1000);"
        "q.mem_write(ql, addr, '48c7c0010000004801d8');"  # mov rax,1; add rax,rbx
        "var d = q.disasm(ql, addr, 10);"
        "'' + d.length + ',' + d[0].mnemonic + ',' + d[1].mnemonic;",
        lambda r: r == "2,mov,add", "2,mov,add")

    # 16) stack_push / stack_pop 往返
    run("stack push/pop roundtrip",
        "var q = require('qiling'); var ql = q.create('90');"
        "q.stack_push(ql, 0x12345678); '' + q.stack_pop(ql);",
        lambda r: r == "305419896", "0x12345678=305419896")

    # 17) code_base 返回 shellcode 加载基址
    run("code_base is shellcode base",
        "var q = require('qiling'); var ql = q.create('90');"
        "'' + q.code_base(ql);",
        lambda r: r == "18870272", "0x11ff000")

    # 18) to_ida / to_ql 地址映射往返（模拟 create_from(orig_ea) 场景）
    run("to_ida/to_ql roundtrip",
        "var q = require('qiling'); var ql = q.create('90');"
        "var orig = 5368713232;"  # 0x140001010
        "var qea = q.code_base(ql) + 0x20;"  # 模拟地址空间里偏移 0x20 处
        "var ida = q.to_ida(ql, qea, orig);"  # 应 = orig + 0x20
        "'' + ida + '/' + (q.to_ql(ql, ida, orig) == qea);",
        lambda r: r == "5368713264/true", "orig+0x20 且往返一致")

    # 19) 间接跳转求解：模拟算术得出真实跳转目标
    run("resolve indirect jump target",
        "var q = require('qiling');"
        # mov rax,0x400000 ; add rax,0x1234 => 目标 0x401234
        "var r = q.emulate_code('48c7c000004000480534120000');"
        "'0x' + r.rax.toString(16);",
        lambda r: r == "0x401234", "0x401234")

    assert _FAIL == 0


@pytest.mark.qiling
@pytest.mark.slow
@pytest.mark.sandbox
def test_qiling_bridge():
    global _PASS, _FAIL
    _PASS = 0
    _FAIL = 0
    main()


if __name__ == "__main__":
    main()
