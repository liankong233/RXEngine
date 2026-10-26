# -*- coding: utf-8 -*-
"""分析扩展的注册入口。

把动态分析相关能力（qiling 模拟门面 + 底层 unicorn 引擎/常量）统一注册进沙箱
注册表，供 JS 侧 require() 使用。server 在启动时与加载二进制后各调用一次
register()：前者 ida=None（qiling shellcode 模拟不依赖 IDA），后者带 ida 以启用
create_from/emulate_at 等按 IDB 取字节的能力。
"""
from pathlib import Path

from extensions.angr_ext import AngrFacade
from extensions.binary_ext import BinaryFacade, CapstoneFacade, KeystoneFacade, PyElfToolsFacade
from extensions.deobfuscation_ext import DeobfuscationFacade
from extensions.lab_ext import LabFacade
from extensions.qiling_ext import QilingFacade
from extensions.z3_ext import Z3Facade
from extensions.z3ida_ext import Z3IDAFacade
from sandbox.jsmodule import JSModule


def _js_module(name):
    return JSModule((Path(__file__).resolve().parent / name).read_text(encoding="utf-8"))


def register(registry, ida=None, board=None, lab_ida=None):
    """把分析扩展注册进给定的沙箱注册表（可重复调用，后注册覆盖）。

    lab_ida：lab 门面级调用（annotate/preview/commit 等 staged 写回）使用的门面根
    （如 worker 里经 RPC 指向父进程 session 门面的 "ida" 根），使 staged 状态跨
    worker 存活；子门面仍用裸 ida 助手取 IDA SDK 子模块。缺省回落到 ida 的
    门面视图（_facade_view），离线/直连行为不变。
    """
    registry.register("rxstubs", _js_module("rxstubs.js"))
    if board is not None:
        registry.register("board", board)
    registry.register("lab", LabFacade(ida=ida, board=board, facade=lab_ida))
    registry.register("qiling", QilingFacade(ida))
    registry.register("angr", AngrFacade(ida))
    try:
        import angr as _angr
        import claripy as _claripy
        registry.register("angr_module", _angr)
        registry.register("claripy", _claripy)
    except ModuleNotFoundError:
        pass
    registry.register("deobfuscation", DeobfuscationFacade(ida))
    registry.register("elf", PyElfToolsFacade())
    registry.register("pyelftools", PyElfToolsFacade())
    registry.register("capstone", CapstoneFacade())
    registry.register("keystone", KeystoneFacade())
    registry.register("binary", BinaryFacade())
    registry.register("z3", Z3Facade())
    registry.register("z3ida", Z3IDAFacade(ida))
    try:
        import unicorn as _unicorn
        from unicorn import arm_const, arm64_const, mips_const, x86_const
    except ModuleNotFoundError:
        return
    # 底层 unicorn：常量（UC_HOOK_*/UC_PROT_*/UC_ARCH_*）+ Uc 类，以及各架构寄存器
    # 常量子模块（require('unicorn_x86').UC_X86_REG_RAX 等），供 JS 直接驱动引擎。
    registry.register("unicorn", _unicorn)
    registry.register("unicorn_x86", x86_const)
    registry.register("unicorn_arm", arm_const)
    registry.register("unicorn_arm64", arm64_const)
    registry.register("unicorn_mips", mips_const)
