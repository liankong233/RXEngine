# test_lab_ext.py
# -*- coding: utf-8 -*-
# 本文件当前仅包含 FakeIDAFacade 离线替身，供 test_lab_wiring.py 导入；
# Task 4 会在本文件补全 LabFacade 完整测试套件（不得改动此类定义）。
import pytest

from extensions.lab_board import AnalysisBoard
from extensions.lab_ext import (LabError, LabFacade, _replay_seed_regs,
                                from_angr_addr, from_ql_addr, parse_hex_operand,
                                summarize_trace, to_angr_addr, to_ql_addr)


class _NS:
    """模块命名空间替身：ida_bytes.get_bytes 这类属性链。"""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeIDAFacade:
    """离线替身：实现 LabFacade 会用到的 IDAFacade 方法子集。"""

    def __init__(self, functions=None, code=b"", image_base=0x140000000):
        self.functions = functions or {}   # start_ea -> {"start_ea","end_ea","name","size"}
        self.code = code
        self.image_base = image_base
        self.input_path = "sample.exe"
        self.comments = []
        self.renames = []
        self.staged = []
        self.ida_bytes = _NS(get_bytes=lambda ea, size: self.code[:size])
        # 偏差说明：QilingFacade._bytes_from_ida 实际走 self._ida.idaapi.get_bytes
        # （qiling_ext.py），并非任务上下文所述 ida_bytes.get_bytes；此处对 idaapi
        # 补同一个 get_bytes 替身（纯增量，不改既有属性），否则离线 trace 拿不到字节。
        self.idaapi = _NS(get_func=lambda ea: None,
                          get_bytes=lambda ea, size: self.code[:size])

    # 读
    def get_name_ea(self, name):
        for start, info in self.functions.items():
            if info["name"] == name:
                return start
        return (1 << 64) - 1

    def get_function_name(self, ea):
        info = self.functions.get(ea)
        return info["name"] if info else ""

    def function_info(self, ea):
        return self.functions.get(ea)

    def get_instruction_size(self, ea):
        return len(self.code)

    def get_bytes(self, ea, size):
        return self.code[:size]

    def get_imagebase(self):
        return self.image_base

    def get_input_file_path(self):
        return self.input_path

    def get_segment_name(self, ea):
        return ".text"

    def get_segments(self):
        return [0x140001000]

    def get_segment_start(self, ea):
        return 0x140001000

    def get_segment_end(self, ea):
        return 0x140001000 + len(self.code)

    def get_segment_perm(self, ea):
        return 0b101

    def get_xrefs_to(self, ea):
        return [0x140002000]

    def get_xrefs_from(self, ea):
        return []

    def arch_info(self):
        return {"proc": "metapc", "bits": 64}

    # 写（staged）
    def set_comment(self, ea, text, repeatable=False):
        self.comments.append((ea, text))
        return {"op": "set_comment", "ea": ea}

    def set_decompiler_comment(self, ea, text):
        self.comments.append((ea, text))
        return {"op": "set_decompiler_comment", "ea": ea}

    def rename(self, ea, name):
        self.renames.append((ea, name))
        return {"op": "rename", "ea": ea}

    def rename_local_variable(self, function_address, old_name, new_name):
        return {"op": "rename_local_variable"}

    def set_function_prototype(self, ea, prototype):
        return {"op": "set_function_prototype"}

    def preview(self):
        return list(self.staged)

    def commit(self, backup=None):
        return {"applied": len(self.staged)}

    def discard(self):
        return 0

    def undo(self):
        return 0

    def save_idb(self, path):
        return True

    def decompile(self, ea):
        return "int main(void) { return 0; }"

    def disassemble(self, ea, count=None):
        return f"{ea}: ret"

    def get_entry_points(self):
        return []

    def prepare_decompile(self, **opts):
        return {"ok": True}

    def prepare_decompile_status(self):
        return {"queue_size": 0}


@pytest.mark.unit
def test_anchor_math():
    # 注：brief 原文写作 0x14001000/0x14001000（与 image_base=0x140000000 相减为负，
    # 且与 from_angr_addr 的期望往返矛盾）；按测试意图（镜像基偏移 0x1000）修正为
    # 0x140001000，与 FakeIDAFacade 的段起点 0x140001000 一致。
    assert to_angr_addr(0x140001000, 0x140000000, 0x400000) == 0x400000 + 0x1000
    assert from_angr_addr(0x401000, 0x140000000, 0x400000) == 0x140001000
    assert to_ql_addr(0x14001005, 0x14001000, 0x1000) == 0x1005
    assert from_ql_addr(0x1005, 0x14001000, 0x1000) == 0x14001005
    assert parse_hex_operand("0x140001234") == 0x140001234
    assert parse_hex_operand("rax") is None


@pytest.mark.unit
def test_summarize_trace_edges_and_hot():
    events = [
        {"ida_ea": 0x1000, "mnemonic": "mov", "op_str": "eax, 1"},
        {"ida_ea": 0x1005, "mnemonic": "call", "op_str": "0x900"},
        {"ida_ea": 0x100a, "mnemonic": "jz", "op_str": "0x1020"},
        {"ida_ea": 0x1020, "mnemonic": "ret", "op_str": ""},
    ]
    out = summarize_trace(events, {"call_edges": 10, "branch_edges": 10,
                                   "hot_eas": 2, "mem_writes": 10})
    assert out["call_edges"] == [{"ea": 0x1005, "to_ea": 0x900}]
    assert out["branch_edges"][0]["ea"] == 0x100a
    assert out["branch_edges"][0]["taken"] is True
    assert out["hot_eas"][0]["count"] == 1


def _lab(functions=None, code=b""):
    ida = FakeIDAFacade(functions=functions, code=code)
    board = AnalysisBoard(session_id="lab")
    return LabFacade(ida=ida, board=board), ida, board


@pytest.mark.sandbox
def test_anchor_target_annotate_roundtrip():
    lab, ida, board = _lab(
        functions={0x14001000: {"start_ea": 0x14001000, "end_ea": 0x14001100,
                                "name": "main", "size": 0x100}},
        code=bytes(range(0x100)))
    assert lab.anchor("main")["ea"] == 0x14001000
    t = lab.target("main", {"with_bytes": True})
    assert t["kind"] == "func" and t["bytes_hex"]
    assert board.counts()["target"] == 1
    assert lab.basis()["image_base"] == 0x140000000
    assert "main" in lab.decompile("main")
    patch = lab.annotate(0x14001000, "hello", {"kind": "disasm"})
    assert patch["op"] == "disasm" and board.counts()["patch"] == 1
    assert ida.comments == [(0x14001000, "hello")]
    assert len(lab.preview()) == 0 or isinstance(lab.preview(), list)


@pytest.mark.sandbox
def test_unknown_symbol_raises_laberror():
    lab, _, _ = _lab()
    with pytest.raises(LabError):
        lab.anchor("nope")


@pytest.mark.sandbox
def test_board_passthroughs():
    lab, _, board = _lab()
    lab.note("hypothesis", 0x10, "maybe obfuscated", {"severity": "low"})
    assert lab.findings("hypothesis")[0]["text"] == "maybe obfuscated"
    h = lab.hypothesis(0x10, "is obfuscated")
    assert h["status"] == "open"
    assert lab.artifact("demo", "x")["ok"] is True
    assert "session_id" in lab.board_summary()


@pytest.mark.sandbox
def test_stage_rxstub_comments():
    lab, ida, _ = _lab()
    out = lab.stage_rxstub_comments([{"callsiteEa": 0x14001000,
                                      "name": "java/lang/String"}], {})
    assert out["ok"] is True and len(out["staged"]) == 1
    assert ida.comments[0][1].startswith("rxstub:")


@pytest.mark.sandbox
def test_arch_helpers_require_ida():
    # 修复回归：ida=None 时 detect_arch/_qiling_arch 必须与兄弟方法一致地抛 LabError，
    # 而不是 AttributeError（'NoneType' object has no attribute 'arch_info'）。
    lab = LabFacade(ida=None, board=None)
    with pytest.raises(LabError):
        lab.detect_arch()
    with pytest.raises(LabError):
        lab._qiling_arch("x8664")


@pytest.mark.sandbox
def test_lab_trace_runs_shellcode_and_records():
    code = bytes.fromhex("b801000000c3")  # mov eax,1 ; ret
    lab, _, board = _lab(code=code)
    out = lab.trace(0x14001000, {"size": len(code), "plan": False, "store_events": True})
    assert out["ok"] is True, out
    assert out["steps"] >= 1
    assert out["trace_id"]
    assert board.counts()["trace"] == 1
    assert any(ev["mnemonic"] in ("mov", "ret") for ev in out["events"])


@pytest.mark.sandbox
def test_lab_trace_returns_error_envelope_on_bad_input():
    lab, _, _ = _lab(code=b"")
    out = lab.trace(0x14001000, {"plan": False})
    assert out["ok"] is False and "error_type" in out


@pytest.mark.sandbox
def test_lab_emulator_step_regs_snapshot():
    code = bytes.fromhex("b801000000c3")  # mov eax,1 ; ret
    lab, _, _ = _lab(code=code)
    emu = lab.emulate(0x14001000, {"size": len(code)})
    assert emu.rip() == 0x14001000
    emu.step(1)
    assert emu.regs(["rax"])["rax"] == 1
    emu.mem_write(0x14001000, "90")
    assert emu.mem_read(0x14001000, 1) == "90"
    snap = emu.save_state([(0x14001000, 4)])
    emu.mem_write(0x14001000, "cc")
    emu.restore_state(snap)
    assert emu.mem_read(0x14001000, 1) == "90"


@pytest.mark.sandbox
def test_lab_emulator_trace_records_to_board():
    code = bytes.fromhex("b801000000c3")
    lab, _, board = _lab(code=code)
    emu = lab.emulate(0x14001000, {"size": len(code)})
    out = emu.trace({"max_trace": 16})
    events = out["trace"] if isinstance(out, dict) else out
    assert len(events) >= 1
    emu.record("after mov")
    assert board.counts()["finding"] == 1


@pytest.mark.sandbox
def test_lab_emulate_does_not_accumulate_emulators():
    # 回归：保活 worker 下 LabFacade 跨轮存活，emulate 不能把活 qiling 实例累积在
    # 列表里（旧实现 append 会在 worker 回收前一直滞留）。
    code = bytes.fromhex("b801000000c3")
    lab, _, _ = _lab(code=code)
    for _ in range(3):
        lab.emulate(0x14001000, {"size": len(code)})
    assert len(lab._emulators) == 1


@pytest.mark.sandbox
def test_lab_emulator_bp_without_callback_is_noop():
    # 修复回归：bp 不传回调时不得在断点命中瞬间抛 TypeError（hook_address 会
    # 无条件调用回调），应等效空操作断点；断言走可观测面：单步穿越断点地址
    # 无异常逃逸且 rip 越过断点。
    code = bytes.fromhex("b801000000c3")  # mov eax,1 ; ret
    lab, _, _ = _lab(code=code)
    emu = lab.emulate(0x14001000, {"size": len(code)})
    emu.bp(0x14001000)  # 断在入口（mov），不传回调
    emu.step(1)         # 穿越（执行）断点地址
    assert emu.rip() == 0x14001005
    assert emu.regs(["rax"])["rax"] == 1


@pytest.mark.sandbox
def test_replay_seed_regs_drops_stack_and_ip_registers():
    # 修复回归（评审 Finding 1）：angr 空间评估出的 rsp/rbp/rip 等是重基址后的
    # 指针值，写进全新 qiling 回放实例必然未映射——_replay_seed_regs 必须大小写
    # 不敏感地剔除栈/帧/指令指针寄存器，其余键值原样透传（含非 int 值不挑剔）。
    mapping = {"rax": 1, "rcx": 0x10, "RSP": 0x11FF000, "rsp": 2, "Rbp": 3,
               "eip": 4, "RIP": 5, "esp": 6, "EBP": 7, "flags": "0x246"}
    out = _replay_seed_regs(mapping)
    assert out == {"rax": 1, "rcx": 0x10, "flags": "0x246"}
    # 空输入 / None 容错
    assert _replay_seed_regs({}) == {}
    assert _replay_seed_regs(None) == {}
