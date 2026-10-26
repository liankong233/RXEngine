# -*- coding: utf-8 -*-
"""rxstubs 暂存辅助逻辑验证（已并入 LabFacade 所在模块）。"""

import pytest

from extensions.lab_ext import _format_rxstub_value, _rxstub_comment_ea


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        ("abcd", "'abcd'"),
        (True, "true"),
        (False, "false"),
        (4, "4"),
        ({"name": "java/lang/String", "type": "jclass"}, "java/lang/String"),
    ],
)
def test_format_rxstub_value(value, expected):
    assert _format_rxstub_value(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"callsiteEa": 0x1000, "ea": 0x2000, "addr": 0x3000}, 0x1000),
        ({"callsite_ea": 0x1100, "callsite": 0x1200, "ea": 0x2000}, 0x1100),
        ({"callsite": 0x1200, "ea": 0x2000}, 0x1200),
        ({"ea": 0x2000, "addr": 0x3000}, 0x2000),
        ({"addr": 0x3000}, 0x3000),
    ],
)
def test_rxstub_comment_ea(item, expected):
    assert _rxstub_comment_ea(item) == expected
