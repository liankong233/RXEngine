# test_lab_wiring.py
# -*- coding: utf-8 -*-
import pytest

from extensions.lab_board import AnalysisBoard
from sandbox.supervisor import SandboxSupervisor
from test_lab_ext import FakeIDAFacade


@pytest.mark.sandbox
def test_board_and_lab_roots_reachable_in_worker():
    roots = {"ida": FakeIDAFacade(), "raw_ida": object(),
             "board": AnalysisBoard(session_id="w1")}
    sup = SandboxSupervisor(lambda: roots)
    # 注：沙箱把顶层 JS 布尔按 Python bool 输出（"=> True"），与代码库既有约定一致，
    # 这里用 '' + (...) 强制 JS 字符串化后再断言 "=> true"。
    out = sup.run("'' + (require.list().indexOf('lab') >= 0 && require.list().indexOf('board') >= 0)",
                  timeout=120)
    assert out.rstrip().endswith("=> true")
    out = sup.run("'' + require('board').summary().session_id", timeout=60)
    assert "w1" in out


@pytest.mark.sandbox
def test_board_absent_without_root():
    sup = SandboxSupervisor(lambda: {"ida": FakeIDAFacade(), "raw_ida": object()})
    out = sup.run("'' + (require.list().indexOf('board') < 0)", timeout=120)
    assert out.rstrip().endswith("=> true")
