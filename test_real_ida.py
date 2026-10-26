# -*- coding: utf-8 -*-
"""真实环境测试：加载 sample.exe 到 headless-ida，经 registry + bridge + vm.run_js
验证 JS<->IDA(rpyc netref) 桥接在真实 IDA 上的端到端行为。

与 test_sandbox.py（用 FakeModule 自包含）不同，本脚本依赖真实 IDA，跑得慢。
"""
import os
import traceback

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.ida, pytest.mark.qiling, pytest.mark.slow]

from headless_ida_mcp_server.helper import IDA, IDA_MODULE_NAMES
from headless_ida_mcp_server.ida_facade import IDAFacade
from extensions.qiling_ext import QilingFacade
from sandbox import vm
from sandbox.registry import registry
from sandbox.supervisor import SandboxSupervisor
from sandbox.worker import run_worker

_PASS = 0
_FAIL = 0

BINARY = os.environ.get("RXENGINE_SAMPLE") or os.path.join(
    os.path.dirname(__file__), "sample.exe")

if not os.path.isfile(BINARY):
    pytest.skip(
        "real-IDA tests need a sample binary; set RXENGINE_SAMPLE=/path/to/binary",
        allow_module_level=True)


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  [PASS] {name}")
    else:
        _FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def result_of(out: str):
    """取 run_js 返回串里 '=> ' 之后的最终结果行。"""
    return out.rsplit("=> ", 1)[-1]


def main():
    print(f"[load] {BINARY}")
    ida = IDA(BINARY)
    registry.register_many({name: getattr(ida, name) for name in IDA_MODULE_NAMES})
    registry.register("ida", IDAFacade(ida))
    registry.register("qiling", QilingFacade(ida))

    # Python 侧先定位一个真实函数地址（int），作为 JS 测试的输入
    ea = ida.idc.get_name_ea_simple("pre_c_init")
    if ea == ida.idaapi.BADADDR:
        ea = next(iter(ida.idautils.Functions()))
    name = ida.ida_funcs.get_func_name(ea)
    print(f"[locate] ea={ea} (0x{ea:X}) name={name!r}")

    print("[JS -> IDA netref field access]")
    out = vm.run_js(
        f"var m = require('idaapi');"
        f"var f = m.get_func({ea});"
        f"'' + f.start_ea + '/' + f.end_ea + '/' + f.size();"
    )
    print("   ", out.replace("\n", " | "))
    parts = result_of(out).split("/")
    check("start_ea exact roundtrip", parts[0] == str(ea), f"got {parts[0]}")
    check("end_ea > start_ea", float(parts[1]) > float(parts[0]))
    check("size() > 0", float(parts[2]) > 0)

    print("[JS -> IDA method returns str]")
    out = vm.run_js(f"require('ida_funcs').get_func_name({ea})")
    print("   ", out.replace("\n", " | "))
    check("get_func_name matches python", result_of(out) == name, f"got {result_of(out)}")

    print("[JS-side huge const BADADDR]")
    out = vm.run_js("'' + require('idaapi').BADADDR")
    print("   ", out.replace("\n", " | "))
    check("BADADDR -> string", result_of(out) == "18446744073709551615",
          f"got {result_of(out)}")

    print("[JS-side get_bytes -> hex]")
    out = vm.run_js(f"require('idaapi').get_bytes({ea}, 4)")
    print("   ", out.replace("\n", " | "))
    hexstr = result_of(out)
    check("get_bytes -> 8-char hex",
          len(hexstr) == 8 and all(c in "0123456789abcdef" for c in hexstr),
          f"got {hexstr}")

    print("[JS number arg -> ea_t (float coerced to int)]")
    # 在 JS 侧做字符串拼接，验证 JS 收到的是真正的 boolean（真 -> "true"）
    out = vm.run_js(
        f"var f = require('idaapi').get_func({ea});"
        f"'' + f.contains({ea});"
    )
    print("   ", out.replace("\n", " | "))
    check("contains(ea) is true", result_of(out) == "true", f"got {result_of(out)}")

    print("[require('ida') facade]")
    out = vm.run_js("var xs = require.list(); '' + (xs.indexOf('ida') >= 0) + '/' + (xs.indexOf('qiling') >= 0);")
    print("   ", out.replace("\n", " | "))
    check("require.list 包含高层模块", result_of(out) == "true/true", f"got {result_of(out)}")

    out = vm.run_js("var d = require.describe('ida'); '' + d.name + '/' + (d.attributes.length > 0);")
    print("   ", out.replace("\n", " | "))
    check("require.describe 描述 ida 门面", result_of(out) == "ida/true", f"got {result_of(out)}")

    out = vm.run_js(
        f"var ida = require('ida');"
        f"'' + ida.get_function_start({ea}) + '/' + ida.get_function_end({ea})"
        f" + '/' + ida.get_function_name({ea});"
    )
    print("   ", out.replace("\n", " | "))
    check("facade get_function_* 与底层一致",
          result_of(out) == f"{ea}/{ea + 211}/{name}", f"got {result_of(out)}")

    out = vm.run_js(f"require('ida').get_instruction({ea})")
    print("   ", out.replace("\n", " | "))
    check("facade get_instruction 返回助记符",
          result_of(out) not in ("", "undefined", "null"), f"got {result_of(out)}")

    out = vm.run_js(f"require('ida').get_bytes({ea}, 4)")
    print("   ", out.replace("\n", " | "))
    check("facade get_bytes -> hex", result_of(out) == "4883ec28", f"got {result_of(out)}")

    out = vm.run_js(f"'' + require('ida').get_name_ea('{name}')")
    print("   ", out.replace("\n", " | "))
    check("facade get_name_ea 反查地址", result_of(out) == str(ea), f"got {result_of(out)}")

    out = vm.run_js("var s = require('ida').get_segments(); '' + (s.length > 0)")
    print("   ", out.replace("\n", " | "))
    check("facade get_segments 非空", result_of(out) == "true", f"got {result_of(out)}")

    out = vm.run_js(f"'' + require('ida').get_imagebase()")
    print("   ", out.replace("\n", " | "))
    check("facade get_imagebase 为整数地址",
          result_of(out).isdigit(), f"got {result_of(out)}")

    print("[require('qiling') shellcode 模拟]")
    # mov rax,1 ; mov rbx,2 ; add rax,rbx  =>  rax = 3
    out = vm.run_js(
        "var q = require('qiling');"
        "var r = q.emulate_code('48c7c00100000048c7c3020000004801d8');"
        "'' + r.rax;"
    )
    print("   ", out.replace("\n", " | "))
    check("emulate_code rax=3", result_of(out) == "3", f"got {result_of(out)}")

    print("[require('qiling') 从 IDB 取字节模拟 emulate_at]")
    # pre_c_init 首指令 sub rsp,0x28（4883ec28），单步后 rsp 应减少 0x28
    out = vm.run_js(
        f"var r = require('qiling').emulate_at({ea}, 4, 1);"
        f"'' + r.rsp;"
    )
    print("   ", out.replace("\n", " | "))
    check("emulate_at rsp 减少 0x28",
          result_of(out) == str(0x11ff000 - 0x28), f"got {result_of(out)}")

    print("[写回 set_comment：dry-run -> preview -> commit -> undo]")
    # 暂存注释：dry-run 阶段不落地，get_cmt 仍为空
    out = vm.run_js(
        f"var ida = require('ida');"
        f"ida.set_comment({ea}, 'resolved by emu');"
        f"var applied = require('idaapi').get_cmt({ea}, false);"
        f"'' + applied;"  # dry-run 下应为 null/None
    )
    print("   ", out.replace("\n", " | "))
    check("dry-run 未落地", result_of(out) in ("null", "None", "undefined", ""),
          f"got {result_of(out)}")

    out = vm.run_js(
        f"var ida = require('ida');"
        f"var p = ida.preview();"
        f"'' + p.length + '/' + p[0].op + '/' + p[0].new + '/' + p[0].repeatable + '/' + p[0].comment_type;"
    )
    print("   ", out.replace("\n", " | "))
    check("preview 显示结构化 diff",
          result_of(out) == "1/set_comment/resolved by emu/false/disassembly", f"got {result_of(out)}")

    out = vm.run_js(
        f"var ida = require('ida');"
        f"var r = ida.commit();"
        f"'' + r.ok + '/' + r.applied + '/' + require('idaapi').get_cmt({ea}, false);"
    )
    print("   ", out.replace("\n", " | "))
    check("commit 落地注释",
          result_of(out) == "true/1/resolved by emu", f"got {result_of(out)}")

    out = vm.run_js(
        f"var ida = require('ida');"
        f"var n = ida.undo();"
        f"var c = require('idaapi').get_cmt({ea}, false);"
        f"'' + n + '/' + c;"
    )
    print("   ", out.replace("\n", " | "))
    check("undo 还原注释", result_of(out) in ("1/null", "1/None", "1/", "1/undefined"),
          f"got {result_of(out)}")

    print("[写回 patch_bytes：commit 改字节再 undo 还原]")
    # pre_c_init 原始首 4 字节 4883ec28；patch 成 deadbeef，commit 后应变，undo 后还原
    out = vm.run_js(
        f"var ida = require('ida');"
        f"ida.patch_bytes({ea}, 'deadbeef'); ida.commit();"
        f"var after = require('idaapi').get_bytes({ea}, 4);"
        f"ida.undo();"
        f"var back = require('idaapi').get_bytes({ea}, 4);"
        f"after + '/' + back;"
    )
    print("   ", out.replace("\n", " | "))
    check("patch commit/undo 往返",
          result_of(out) == "deadbeef/4883ec28", f"got {result_of(out)}")

    print("[写回 set_decompiler_comment：函数级注释 commit/undo]")
    out = vm.run_js(
        f"var ida = require('ida');"
        f"ida.set_decompiler_comment({ea}, 'decrypts strings'); ida.commit();"
        f"var c = require('idc').get_func_cmt({ea}, true);"
        f"ida.undo();"
        f"var back = require('idc').get_func_cmt({ea}, true);"
        f"'' + c + '/' + back;"
    )
    print("   ", out.replace("\n", " | "))
    check("decompiler comment commit/undo",
          result_of(out) in ("decrypts strings/null", "decrypts strings/None",
                              "decrypts strings/", "decrypts strings/undefined"),
          f"got {result_of(out)}")

    print("[写回 commit(backup)：提交前快照落盘]")
    snap = os.path.join(os.path.dirname(BINARY), "_snap_test.i64")
    if os.path.exists(snap):
        os.remove(snap)
    out = vm.run_js(
        f"var ida = require('ida');"
        f"ida.set_comment({ea}, 'x'); var r = ida.commit('{snap.replace(chr(92), '/') }');"
        f"ida.undo(); '' + r.ok + '/' + r.applied;"
    )
    print("   ", out.replace("\n", " | "))
    check("commit backup 生成快照文件", os.path.exists(snap) and result_of(out) == "true/1",
          f"snapshot not found or bad result: {snap} {result_of(out)}")
    if os.path.exists(snap):
        os.remove(snap)

    print("[保存/打开 IDB 数据库：save_idb -> IDA(saved)]")
    saved = os.path.join(os.path.dirname(BINARY), "_saved_test.i64")
    if os.path.exists(saved):
        os.remove(saved)
    out = vm.run_js(
        f"var ok = require('ida').save_idb('{saved.replace(chr(92), '/') }');"
        f"'' + ok;"
    )
    print("   ", out.replace("\n", " | "))
    check("save_idb 保存 .i64", os.path.exists(saved), f"saved not found: {saved}, result={result_of(out)}")
    if os.path.exists(saved):
        with open(saved, "rb") as f:
            sig = f.read(4)
        check("save_idb 生成 IDA 数据库文件", sig in (b"IDA2", b"IDA1"), f"signature={sig!r}")
        os.remove(saved)

    print("[闭环：qiling 求解常量 -> 写回 IDA 注释]")
    # 模拟算出真实跳转目标 0x401234，作为注释写回 ea，commit 后验证，再 undo 复原
    out = vm.run_js(
        f"var q = require('qiling'); var ida = require('ida');"
        f"var r = q.emulate_code('48c7c000004000480534120000');"
        f"var target = '0x' + r.rax.toString(16);"
        f"ida.set_comment({ea}, 'jmp target = ' + target); ida.commit();"
        f"var c = require('idaapi').get_cmt({ea}, false);"
        f"ida.undo();"
        f"'' + c;"
    )
    print("   ", out.replace("\n", " | "))
    check("闭环写回注释含求解目标",
          result_of(out) == "jmp target = 0x401234", f"got {result_of(out)}")

    print(f"\nresult: {_PASS} passed / {_FAIL} failed")
    assert _FAIL == 0


@pytest.mark.requires_ida
@pytest.mark.ida
@pytest.mark.qiling
@pytest.mark.slow
def test_real_ida_workflow():
    global _PASS, _FAIL
    _PASS = 0
    _FAIL = 0
    main()


def test_real_ida_supervisor_preserves_staged_state_after_worker_failure():
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida}
    supervisor = SandboxSupervisor(lambda: roots)
    ea = None
    try:
        ea = ida.idc.get_name_ea_simple("pre_c_init")
        if ea == ida.idaapi.BADADDR:
            ea = next(iter(ida.idautils.Functions()))

        read = supervisor.run(
            f"require('ida').get_function_name({ea})",
            timeout=30,
        )
        assert result_of(read) == ida.ida_funcs.get_func_name(ea)

        staged = supervisor.run(
            f"var ida = require('ida');"
            f"ida.set_comment({ea}, 'supervisor staged');"
            f"var p = ida.preview();"
            f"'' + p.length + '/' + p[0].new;",
            timeout=30,
        )
        assert result_of(staged) == "1/supervisor staged"

        timed_out = supervisor.run("while (true) {}", timeout=0.2)
        assert "RunTimeout" in timed_out

        preview = supervisor.run(
            "var p = require('ida').preview(); '' + p.length + '/' + p[0].new;",
            timeout=30,
        )
        assert result_of(preview) == "1/supervisor staged"

        crash_supervisor = SandboxSupervisor(lambda: roots, worker_target=_crash_worker)
        crashed = crash_supervisor.run("unused", timeout=5)
        assert "WorkerCrashed" in crashed

        recovered = supervisor.run(
            f"'' + require('ida').get_instruction({ea}) + '/' + require('ida').preview().length;",
            timeout=30,
        )
        mnemonic, staged_count = result_of(recovered).split("/")
        assert mnemonic
        assert staged_count == "1"
    finally:
        facade.discard()
        ida.close()


def _crash_worker(connection, request):
    os._exit(23)


def _iter_probe_worker(connection, request):
    """在 worker 里经 RPC 迭代 IDA 的生成器 API，验证 list()/for 都能工作。"""
    from sandbox.worker import PROTOCOL_VERSION, WorkerRPCClient

    client = WorkerRPCClient(connection, request["run_id"], request["generation"])
    raw = client.root("raw_ida")
    detail = {}
    for name, fn in (
        ("functions_list", lambda: len(list(raw.idautils.Functions()))),
        ("functions_for", lambda: sum(1 for _ in raw.idautils.Functions())),
    ):
        try:
            detail[name] = fn()
        except BaseException as exc:  # noqa: BLE001
            detail[name] = f"{type(exc).__name__}: {exc}"
    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request["run_id"],
        "generation": request["generation"],
        "ok": True,
        "result": str(detail),
    })
    connection.close()


def test_real_ida_supervisor_iterates_generator_over_rpc():
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida}
    supervisor = SandboxSupervisor(lambda: roots, worker_target=_iter_probe_worker)
    try:
        expected = len(list(ida.idautils.Functions()))
        out = supervisor.run("unused", timeout=60)
        assert f"'functions_list': {expected}" in out, out
        assert f"'functions_for': {expected}" in out, out
    finally:
        facade.discard()
        ida.close()


def test_ida_facade_parity():
    from headless_ida_mcp_server.helper import IDAError
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    try:
        first = next(iter(ida.idautils.Functions()))
        info = facade.function_info(first)
        assert info and info["start_ea"] == int(first) and info["size"] > 0 and info["name"]
        arch = facade.arch_info()
        assert arch["bits"] in (16, 32, 64) and isinstance(arch["proc"], str)
        try:
            code = facade.decompile(info["start_ea"])
            assert isinstance(code, str) and code
        except IDAError:
            pass  # headless 无 hexrays 时跳过反编译断言
        assert facade.disassemble(info["start_ea"])
        assert isinstance(facade.get_entry_points(), list)
        assert "queue_size" in facade.prepare_decompile_status()
    finally:
        ida.close()


def test_lab_staged_state_survives_across_runs_real_ida():
    """回归：lab 的 staged 写回必须落在父进程 session 门面上，跨 worker 存活。

    修复前：worker 内 LabFacade 经 _facade_view 自包的 IDAFacade 随 worker 退出
    销毁，lab.annotate 的暂存对 require('ida')（session 门面）不可见，
    stage -> 下一轮 preview/commit 断链（split-brain）。
    """
    from extensions.lab_board import AnalysisBoard
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida,
             "board": AnalysisBoard(session_id="lab-split")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        # run #1：经 lab 暂存一条注释，同一轮里经 session 门面读回 staged 数
        out = sup.run(
            "var lab = require('lab');"
            "lab.annotate('pre_c_init', 'split-brain check', {});"
            "'' + require('ida').preview().length;", timeout=120)
        assert int(result_of(out)) >= 1, out

        # run #2（全新 worker）：staged 状态必须仍然可见（修复前这里看到 0）
        out = sup.run("'' + require('ida').preview().length;", timeout=120)
        assert int(result_of(out)) >= 1, out

        # run #3：清理暂存区
        sup.run("require('ida').discard();", timeout=120)
    finally:
        facade.discard()
        ida.close()


def test_lab_board_findings_survive_across_runs_real_ida():
    """回归：lab.note 写入的黑板 findings 必须经共享 AnalysisBoard 跨 worker 存活。

    与 test_lab_staged_state_survives_across_runs_real_ida（门面暂存态）互补，
    覆盖 spec §5 黑板 findings 的跨轮持久化（note 在 run #1，findings 在全新 run #2 读回）。
    """
    from extensions.lab_board import AnalysisBoard
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida,
             "board": AnalysisBoard(session_id="lab-findings")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "require('lab').note('hypothesis', 'pre_c_init', 'cross-run claim', {});"
            "'noted'", timeout=120)
        assert result_of(out) == "noted", out

        # run #2（全新 worker）：黑板 findings 必须仍然可见
        out = sup.run(
            "var f = require('lab').findings('hypothesis');"
            "'' + f.length + '/' + f[0].text", timeout=120)
        assert result_of(out) == "1/cross-run claim", out
    finally:
        facade.discard()
        ida.close()


def test_lab_deob_and_solve_branch_real_ida():
    from extensions.lab_board import AnalysisBoard
    from sandbox.supervisor import SandboxSupervisor
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida, "board": AnalysisBoard(session_id="lab-deob")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "var lab = require('lab');"
            "var r = lab.deob('pre_c_init', {limit: 5});"
            "'' + r.ok + '/' + r.scanned", timeout=240)
        assert result_of(out).startswith("true/"), out

        out = sup.run(
            "var lab = require('lab');"
            "var r = lab.deob('pre_c_init', {limit: 20});"
            "var b = null;"
            "for (var i = 0; i < r.results.length; i++) {"
            "  if (r.results[i].kind === 'opaque_predicate') { b = r.results[i].ea; break; } }"
            "b === null ? 'nobranch' : (function () {"
            "  var s = lab.solve_branch(b, {});"
            "  return '' + s.ok + '/' + s.classification; })()", timeout=240)
        assert result_of(out) == "nobranch" or result_of(out).startswith("true/"), out
    finally:
        facade.discard()
        ida.close()


def test_lab_emulate_mapped_mode_real_ida():
    """mapped 模式（map_segments:true）的 lab.emulate 活句柄在真实 IDA 上闭环：
    单步推进后 rip 非零（有进展）、寄存器可读、能按 IDA 原地址读回映射内存。
    mapped 模式跑真实函数几乎必然在推进后某处 fault（导入调用等）——fault 只要
    发生在有进展之后即属预期，断言只针对已产生的状态，不要求跑到函数末尾。"""
    from extensions.lab_board import AnalysisBoard
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida,
             "board": AnalysisBoard(session_id="lab-mapped")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "var lab = require('lab');"
            "var t = lab.target('pre_c_init');"
            "var emu = lab.emulate(t.start_ea, {map_segments: true, max_steps: 50});"
            "var fault = '';"
            "try { emu.step(1); } catch (e) { fault = '' + e; }"
            "var regs = emu.regs(['rax']);"
            "var regNames = Object.keys(emu.regs());"
            "var hex = emu.mem_read(t.start_ea, 4);"
            "'' + (emu.rip() !== 0)"
            " + '/' + (regs.rax !== undefined || regNames.length > 0)"
            " + '/' + (hex.length === 8) + '/' + (fault === '')", timeout=240)
        # 前三段是硬断言（推进/寄存器/内存读回）；第 4 段仅报告单步是否 fault，
        # 位置随二进制与后端而变，只作诊断不作为失败条件
        assert result_of(out).startswith("true/true/true"), out
    finally:
        facade.discard()
        ida.close()


def test_lab_concrete_prefix_and_follow_real_ida():
    from extensions.lab_board import AnalysisBoard
    from sandbox.supervisor import SandboxSupervisor
    ida = IDA(BINARY)
    facade = IDAFacade(ida)
    roots = {"ida": facade, "raw_ida": ida, "board": AnalysisBoard(session_id="lab-path")}
    sup = SandboxSupervisor(lambda: roots)
    try:
        out = sup.run(
            "var lab = require('lab');"
            "var t = lab.target('pre_c_init');"
            "var c = lab.concrete_prefix(t.start_ea, {max_steps: 500});"
            # STPyV8 桥接现实：嵌套在返回值里的 Python dict 在 JS 侧是宿主对象，
            # typeof 为 'function'（顶层 list 才转真 JSArray），属性访问/Object.keys
            # 均正常。故 typeof 探针接受 'object' 或 'function'，未定义/标量仍判失败。
            "'' + c.ok + '/' + (typeof c.regs === 'object' || typeof c.regs === 'function')",
            timeout=240)
        assert result_of(out) == "true/true", out

        out = sup.run(
            "var lab = require('lab');"
            "var t = lab.target('pre_c_init');"
            "var p = lab.follow(t.start_ea, {max_steps: 300, timeout: 20, regs: ['rax']});"
            # verify_concrete 接线：goal 取 angr 单步后的真实落点（基本块边界），
            # angr 一步即 found=true，_verify_concrete 的 qiling 映射段回放被真正
            # 触发；不要求回放 reached（导入调用等会让回放 fault，_verify_concrete
            # 兜成结构化结果，typeof 仍为宿主对象）。
            # typeof 现实（见 concrete_prefix 探针注释）：嵌套 dict 过桥后是宿主对象，
            # typeof 为 'function'，故探针接受 'object' 或 'function'。
            "var angr = require('angr');"
            "var pr = angr.project();"
            "var st = angr.blank_state(pr, t.start_ea);"
            "var sim = angr.simgr(pr, st);"
            "angr.step(sim, 1);"
            "var s0 = angr.first(sim, 'active');"
            "var goal = lab.from_angr(s0.addr, pr);"
            "var q = lab.follow(t.start_ea, {max_steps: 300, timeout: 20, regs: ['rax'],"
            " goal: [goal], verify_concrete: true});"
            "'' + p.ok + '/' + (p.found === true || p.found === false)"
            " + '/' + (typeof p.active_count === 'number')"
            " + '/' + (typeof q.verify === 'object' || typeof q.verify === 'function')",
            timeout=300)
        assert result_of(out) == "true/true/true/true", out
    finally:
        facade.discard()
        ida.close()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)
