# -*- coding: utf-8 -*-
"""可由 JS 沙箱原生 eval 的 JavaScript 模块。"""


class JSModule:
    def __init__(self, source: str):
        self.source = source
