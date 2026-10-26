# -*- coding: utf-8 -*-
"""暴露给 JS 沙箱的高层 IDA 门面（require('ida')）。

参考 qiling idaplugin 的 `class IDA` 静态门面，把散落的 ida_* 调用收敛成语义化
方法。差异在于：qiling 运行在 IDA 进程内、直接 import ida_*；这里各 ida_* 是
headless-ida 经 rpyc 暴露的 netref，门面持有 helper.IDA 实例按需调用，返回值再由
sandbox.bridge 统一编组给 JS（int->float/str、bytes->hex 等）。
"""


class IDAFacade:
    """语义化 IDA 接口；方法参数/返回值均为 int/bytes/str 标量，天然可编组。"""

    def __init__(self, ida):
        # ida: headless_ida_mcp_server.helper.IDA 实例，持有各 ida_* netref 模块
        self._ida = ida
        # 写回采用 dry-run：写方法只把改动记入 _staged（含 before 状态），preview()
        # 看 diff，commit() 才落地并压入 _history 供 undo() 逐条回退。随 IDB 重载重建。
        self._staged = []
        self._history = []

    # ---- functions ----
    def get_function(self, ea):
        """返回 ea 所属函数的 func_t（无则 None）。"""
        return self._ida.idaapi.get_func(ea)

    def get_function_start(self, ea):
        f = self._ida.idaapi.get_func(ea)
        return None if f is None else f.start_ea

    def get_function_end(self, ea):
        f = self._ida.idaapi.get_func(ea)
        return None if f is None else f.end_ea

    def get_function_name(self, ea):
        return self._ida.ida_funcs.get_func_name(ea)

    def get_functions(self):
        """所有函数的起始地址列表。"""
        return list(self._ida.idautils.Functions())

    # ---- bytes / memory ----
    def get_bytes(self, ea, size):
        return self._ida.idaapi.get_bytes(ea, size)

    def get_byte(self, ea):
        return self._ida.ida_bytes.get_byte(ea)

    def get_word(self, ea):
        return self._ida.ida_bytes.get_word(ea)

    def get_dword(self, ea):
        return self._ida.ida_bytes.get_dword(ea)

    def get_qword(self, ea):
        return self._ida.ida_bytes.get_qword(ea)

    # ---- names / addresses ----
    def get_name(self, ea):
        return self._ida.ida_name.get_name(ea)

    def get_name_ea(self, name):
        """按名字取地址（无则 BADADDR）。"""
        return self._ida.idaapi.get_name_ea(self._ida.idaapi.BADADDR, name)

    def get_imagebase(self):
        return self._ida.idaapi.get_imagebase()

    def get_input_file_path(self):
        return self._ida.ida_nalt.get_input_file_path()

    # ---- instructions ----
    def get_instruction(self, ea):
        """指令助记符，如 'mov'（无指令则空串）。"""
        return self._ida.ida_ua.print_insn_mnem(ea)

    def get_instruction_size(self, ea):
        return self._ida.ida_bytes.get_item_size(ea)

    def disasm_line(self, ea):
        return self._ida.idaapi.generate_disasm_line(int(ea), self._ida.idaapi.GENDSM_REMOVE_TAGS)

    def prev_head(self, ea, min_ea=0):
        return self._ida.ida_bytes.prev_head(int(ea), int(min_ea))

    def next_head(self, ea, max_ea=None):
        if max_ea is None:
            max_ea = self._ida.idaapi.BADADDR
        return self._ida.ida_bytes.next_head(int(ea), int(max_ea))

    def function_items(self, ea):
        f = self._ida.idaapi.get_func(int(ea))
        if f is None:
            return []
        return [int(x) for x in self._ida.ida_funcs.func_item_iterator_t(f)]

    def print_operand(self, ea, n):
        return self._ida.idc.print_operand(ea, n)

    def get_operand(self, ea, n):
        """返回 [type, value] 二元组。"""
        return [self._ida.idc.get_operand_type(ea, n),
                self._ida.idc.get_operand_value(ea, n)]

    # ---- segments ----
    def get_segments(self):
        """所有段的起始地址列表。"""
        seg = self._ida.ida_segment.get_first_seg()
        out = []
        while seg is not None:
            out.append(seg.start_ea)
            seg = self._ida.ida_segment.get_next_seg(seg.start_ea)
        return out

    def get_segment_name(self, ea):
        seg = self._ida.ida_segment.getseg(ea)
        return None if seg is None else self._ida.ida_segment.get_segm_name(seg)

    def get_segment_start(self, ea):
        seg = self._ida.ida_segment.getseg(ea)
        return None if seg is None else seg.start_ea

    def get_segment_end(self, ea):
        seg = self._ida.ida_segment.getseg(ea)
        return None if seg is None else seg.end_ea

    def get_segment_perm(self, ea):
        """段权限位，RWX，如 0b101 = R|X。"""
        seg = self._ida.ida_segment.getseg(ea)
        return None if seg is None else seg.perm

    # ---- xrefs ----
    def get_xrefs_to(self, ea):
        """引用到 ea 的来源地址列表。"""
        return [x.frm for x in self._ida.idautils.XrefsTo(ea)]

    def get_xrefs_from(self, ea):
        """从 ea 引出的目标地址列表。"""
        return [x.to for x in self._ida.idautils.XrefsFrom(ea)]

    # ==== 写回（dry-run + 预览 + 可撤销）====
    # 所有写方法默认不落地：只把改动连同 before 状态记入暂存区，返回该条 diff。
    # 需显式 commit() 才应用到（临时）IDB；save_idb() 才持久化到磁盘。

    def _stage(self, op, ea, old, new, apply_fn, revert_fn, **meta):
        entry = {"op": op, "kind": op, "ea": int(ea), "address": int(ea),
                 "old": old, "new": new, **meta,
                 "_apply": apply_fn, "_revert": revert_fn}
        self._staged.append(entry)
        return {k: v for k, v in entry.items() if not k.startswith("_")}

    def patch_bytes(self, ea, data):
        """暂存字节 patch。data 为 hex 字符串（'deadbeef'）或字节整数数组。"""
        ea = int(ea)
        if isinstance(data, str):
            new = bytes.fromhex(data)
        else:
            new = bytes(bytearray(int(x) & 0xFF for x in data))
        old_raw = self._ida.idaapi.get_bytes(ea, len(new))
        old = bytes(old_raw).hex() if old_raw else ""
        return self._stage(
            "patch_bytes", ea, old, new.hex(),
            lambda: self._ida.idaapi.patch_bytes(ea, new),
            (lambda: self._ida.idaapi.patch_bytes(ea, bytes.fromhex(old)))
            if old else (lambda: None))

    def nop(self, ea, size):
        """暂存把 [ea, ea+size) 填成 x86 NOP(0x90)。"""
        return self.patch_bytes(ea, "90" * int(size))

    def set_comment(self, ea, text, repeatable=False):
        """暂存反汇编注释。"""
        ea, rpt = int(ea), bool(repeatable)
        old = self._ida.idaapi.get_cmt(ea, rpt) or ""
        return self._stage(
            "set_comment", ea, old, str(text),
            lambda: self._ida.idaapi.set_cmt(ea, str(text), rpt),
            lambda: self._ida.idaapi.set_cmt(ea, old, rpt),
            repeatable=rpt, comment_type="disassembly")

    def rename(self, ea, name):
        """暂存重命名 ea 处符号。"""
        ea = int(ea)
        name = self.sanitize_name(name)
        old = self._ida.ida_name.get_name(ea) or ""
        return self._stage(
            "rename", ea, old, name,
            lambda: self._ida.idaapi.set_name(ea, name),
            lambda: self._ida.idaapi.set_name(ea, old))

    def sanitize_name(self, name, prefix="sym"):
        text = str(name).strip()
        out = []
        for idx, ch in enumerate(text):
            if ch == "_" or ch.isalnum():
                out.append(ch)
            elif idx > 0:
                out.append("_")
        cleaned = "".join(out).strip("_")[:255]
        if not cleaned or cleaned[0].isdigit():
            cleaned = f"{prefix}_{cleaned}" if cleaned else str(prefix)
        return cleaned

    def set_decompiler_comment(self, ea, text, repeatable=True):
        """暂存函数级注释（显示在伪代码/反汇编顶部）。ea 需落在某函数内。"""
        ea, rpt = int(ea), bool(repeatable)
        old = self._ida.idc.get_func_cmt(ea, rpt) or ""
        return self._stage(
            "set_decompiler_comment", ea, old, str(text),
            lambda: self._ida.idc.set_func_cmt(ea, str(text), rpt),
            lambda: self._ida.idc.set_func_cmt(ea, old, rpt),
            repeatable=rpt, comment_type="function")

    def set_function_prototype(self, ea, prototype):
        ea = int(ea)
        func = self._ida.idaapi.get_func(ea)
        if func is None:
            raise ValueError(f"No function found at address {ea}")
        start = int(func.start_ea)
        old = self._ida.get_prototype(start) or ""
        new = str(prototype)
        return self._stage(
            "set_function_prototype", start, old, new,
            lambda: self._ida.set_function_prototype(start, new),
            (lambda: self._ida.set_function_prototype(start, old))
            if old else (lambda: self._ida.ida_typeinf.del_tinfo(start)))

    def rename_local_variable(self, function_address, old_name, new_name):
        ea = int(function_address)
        old = str(old_name)
        new = str(new_name)
        return self._stage(
            "rename_local_variable", ea, old, new,
            lambda: self._ida.rename_local_variable(ea, old, new),
            lambda: self._ida.rename_local_variable(ea, new, old),
            function_address=ea)

    def make_code(self, ea):
        """暂存把 ea 处转成指令（撤销为 del_items，尽力而为）。"""
        ea = int(ea)
        return self._stage(
            "make_code", ea, "", "code",
            lambda: self._ida.ida_ua.create_insn(ea),
            lambda: self._ida.ida_bytes.del_items(ea, 0, 1))

    def make_function(self, ea):
        """暂存在 ea 处定义函数（撤销为 del_func）。"""
        ea = int(ea)
        return self._stage(
            "make_function", ea, "", "func",
            lambda: self._ida.ida_funcs.add_func(ea),
            lambda: self._ida.ida_funcs.del_func(ea))

    def preview(self):
        """返回暂存区里将要应用的改动列表（不含内部回调）。"""
        return [{k: v for k, v in c.items() if not k.startswith("_")}
                for c in self._staged]

    def status(self):
        """返回暂存区与提交历史的计数，供逆向流程健康检查读取。"""
        return {"staged": len(self._staged), "committed_batches": len(self._history)}

    def commit(self, backup=None):
        """应用暂存区全部改动到（临时）IDB，压入 history 供 undo，返回结构化结果。

        backup: 可选路径。给了则在应用改动**之前**先把当前 IDB 存到该路径，作为
        提交前快照（真正不可逆时的兜底）。
        """
        if backup:
            self._ida.ida_loader.save_database(str(backup), 0)
        batch = list(self._staged)
        applied = []
        for idx, change in enumerate(batch):
            try:
                change["_apply"]()
                applied.append(change)
            except Exception as exc:  # noqa: BLE001
                rollback_errors = []
                rolled_back = []
                for applied_change in reversed(applied):
                    public_change = {k: v for k, v in applied_change.items() if not k.startswith("_")}
                    try:
                        applied_change["_revert"]()
                        rolled_back.append(public_change)
                    except Exception as rollback_exc:  # noqa: BLE001
                        rollback_errors.append({
                            "change": public_change,
                            "error": str(rollback_exc),
                            "error_type": type(rollback_exc).__name__,
                        })
                return {
                    "ok": False,
                    "applied": len(applied),
                    "failed_index": idx,
                    "failed_change": {k: v for k, v in change.items() if not k.startswith("_")},
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "rolled_back": rolled_back,
                    "rollback_errors": rollback_errors,
                }
        if batch:
            self._history.append(batch)
        self._staged = []
        return {"ok": True, "applied": len(batch)}

    def discard(self):
        """清空暂存区（不应用），返回被丢弃的条数。"""
        n = len(self._staged)
        self._staged = []
        return n

    def undo(self):
        """回退最近一次 commit：按逆序还原 before 状态，返回回退条数。"""
        if not self._history:
            return 0
        batch = self._history.pop()
        for c in reversed(batch):
            c["_revert"]()
        return len(batch)

    def save_idb(self, path):
        """把当前（含已 commit 改动的）IDB 持久化到磁盘。"""
        return self._ida.ida_loader.save_database(str(path), 0)

    # ---- Lab parity：结构化函数信息 / 反编译 / 反汇编 / 入口点 / 预热 ----
    def function_info(self, ea):
        func = self._ida.idaapi.get_func(int(ea))
        if func is None:
            return None
        start, end = int(func.start_ea), int(func.end_ea)
        return {"ea": start, "start_ea": start, "end_ea": end,
                "size": end - start,
                "name": self._ida.ida_funcs.get_func_name(start) or ""}

    def decompile_checked(self, ea):
        return self._ida.decompile_checked(int(ea))

    def decompile(self, ea):
        return self._ida.decompile_function(int(ea))

    def disassemble(self, ea, count=None):
        text = self._ida.disassemble_function(int(ea))
        if count:
            return "\n".join(text.splitlines()[: int(count)])
        return text

    def get_entry_points(self):
        return self._ida.get_entry_points()

    def prepare_decompile(self, **opts):
        return self._ida.prepare_decompile(**opts)

    def prepare_decompile_status(self):
        return self._ida.get_prepare_decompile_status()

    def arch_info(self):
        # IDA 7.6+/9：get_inf_structure 已移除，优先走 ida_ida 取值函数；旧版回退。
        # 与 QilingFacade._infer_arch 相同的两代 API 兼容写法。
        try:
            proc = str(self._ida.ida_ida.inf_get_procname() or "").lower()
            is64 = bool(self._ida.ida_ida.inf_is_64bit())
            is32 = bool(self._ida.ida_ida.inf_is_32bit_exactly())
        except AttributeError:
            info = self._ida.idaapi.get_inf_structure()
            proc = str(getattr(info, "procname", "") or "").lower()
            is64 = bool(info.is_64bit())
            is32 = bool(info.is_32bit())
        bits = 64 if is64 else (32 if is32 else 16)
        return {"proc": proc, "bits": bits}
