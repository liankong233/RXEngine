# -*- coding: utf-8 -*-
"""静态反混淆辅助：识别常见模式并生成 IDA 门面可预览 patch。"""
import time

from sandbox.rpc import call_many


class DeobfuscationError(Exception):
    pass


class DeobfuscationFacade:
    def __init__(self, ida=None):
        self._ida = ida

    def scan(self, opts=None):
        self._require_ida()
        opts = opts or {}
        functions = opts.get("functions")
        max_items = int(opts.get("limit", 1000))
        start_ea = opts.get("start_ea")
        end_ea = opts.get("end_ea")
        timeout = float(opts.get("timeout", 0) or 0)
        max_func_size = int(opts.get("max_func_size", 0) or 0)
        failure_limit = int(opts.get("failure_limit", 20) or 20)
        started = time.monotonic()
        findings = []
        scanned = 0
        skipped = []
        failures = []
        timed_out = False
        last_ea = None
        for start in self._function_starts(functions):
            start = int(start)
            if start_ea is not None and start < int(start_ea):
                continue
            if end_ea is not None and start >= int(end_ea):
                continue
            if timeout and time.monotonic() - started >= timeout:
                timed_out = True
                break
            last_ea = start
            func = self._ida.idaapi.get_func(start)
            if func is None:
                continue
            size = int(func.end_ea) - int(func.start_ea)
            if max_func_size and size > max_func_size:
                if len(skipped) < failure_limit:
                    skipped.append({"ea": start, "reason": "max_func_size", "size": size})
                continue
            try:
                findings.extend(self.scan_function(func, opts))
                scanned += 1
            except Exception as exc:  # noqa: BLE001
                if len(failures) < failure_limit:
                    failures.append({"ea": start, "error_type": type(exc).__name__, "message": str(exc)})
            if len(findings) >= max_items:
                findings = findings[:max_items]
                break
        return {
            "results": findings,
            "scanned": scanned,
            "matched": len(findings),
            "timed_out": timed_out,
            "last_ea": last_ea,
            "skipped": skipped,
            "failures": failures,
        }

    def scan_function(self, func, opts=None):
        opts = opts or {}
        findings = []
        # 先物化指令列表，再批量取助记符：把逐指令的属性链 RPC 压成一次批量调用，
        # 也避免在迭代 IDA 游标的过程中做嵌套 IDA 调用。
        items = [int(ea) for ea in self._ida.ida_funcs.func_item_iterator_t(func)]
        mnemonics = call_many(self._ida.ida_ua.print_insn_mnem, [[ea] for ea in items])
        for ea, mnem in zip(items, mnemonics):
            mnem = (mnem or "").lower()
            if mnem in {"jz", "jnz", "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle"}:
                opaque = self._opaque_predicate(ea)
                if opaque:
                    findings.append(opaque)
            folded = self._constant_fold(ea)
            if folded:
                findings.append(folded)
            indirect = self._indirect_jump(ea)
            if indirect:
                findings.append(indirect)
        return findings

    def patch_plan(self, findings, opts=None):
        self._require_ida()
        opts = opts or {}
        nop_false_branch = bool(opts.get("nop_false_branch", True))
        plan = []
        for finding in list(findings or []):
            kind = finding.get("kind")
            ea = int(finding.get("ea"))
            confidence = str(finding.get("confidence", "medium"))
            confirmed = bool(finding.get("confirmed", False))
            classification = str(finding.get("classification", ""))
            destructive_allowed = confirmed or confidence == "high"
            if kind == "opaque_predicate" and nop_false_branch and destructive_allowed and classification != "unknown":
                size = self._ida.ida_bytes.get_item_size(ea)
                plan.append({
                    "kind": "nop",
                    "ea": ea,
                    "size": int(size),
                    "reason": finding.get("reason", kind),
                    "confidence": confidence,
                    "confirmed": confirmed,
                    "finding": finding,
                })
            elif kind == "opaque_predicate":
                plan.append({
                    "kind": "comment",
                    "ea": ea,
                    "text": finding.get("comment", f"opaque predicate candidate: {finding.get('reason', 'unknown')}"),
                    "reason": "opaque_predicate_unconfirmed",
                    "confidence": confidence,
                    "confirmed": confirmed,
                    "finding": finding,
                })
            elif kind == "constant_fold":
                plan.append({
                    "kind": "comment",
                    "ea": ea,
                    "text": f"constant-fold: {finding.get('expression')} = {finding.get('value')}",
                    "reason": kind,
                    "confidence": confidence,
                    "confirmed": confirmed,
                    "finding": finding,
                })
            elif kind == "indirect_jump":
                target = finding.get("target")
                if target is not None:
                    text = f"indirect-jump target candidate: {hex(int(target))}"
                else:
                    itype = finding.get("indirect_type", "indirect")
                    text = f"unresolved indirect jump ({itype}); needs dynamic analysis"
                plan.append({
                    "kind": "comment",
                    "ea": ea,
                    "text": text,
                    "reason": kind,
                    "confidence": confidence,
                    "confirmed": confirmed,
                    "finding": finding,
                })
        return plan

    def stage_patch_plan(self, plan, ida_facade):
        changes = []
        for item in list(plan or []):
            kind = item.get("kind")
            ea = int(item.get("ea"))
            if kind == "nop":
                changes.append(ida_facade.nop(ea, int(item.get("size", 1))))
            elif kind == "comment":
                changes.append(ida_facade.set_comment(ea, str(item.get("text", ""))))
            elif kind == "patch_bytes":
                if not (bool(item.get("confirmed", False)) or str(item.get("confidence", "")) == "high"):
                    changes.append(ida_facade.set_comment(ea, str(item.get("text", "unconfirmed patch_bytes skipped"))))
                    continue
                changes.append(ida_facade.patch_bytes(ea, item.get("bytes", "")))
        return changes

    def _opaque_predicate(self, ea):
        prev = int(self._ida.ida_bytes.prev_head(ea, 0))
        if prev == self._ida.idaapi.BADADDR:
            return None
        pm = (self._ida.ida_ua.print_insn_mnem(prev) or "").lower()
        op0 = self._ida.idc.print_operand(prev, 0) or ""
        op1 = self._ida.idc.print_operand(prev, 1) or ""
        if pm in {"test", "cmp"} and op0 and op0 == op1:
            return {
                "kind": "opaque_predicate",
                "ea": int(ea),
                "predicate_ea": prev,
                "target": int(self._ida.idc.get_operand_value(ea, 0)),
                "reason": f"{pm} same operand before conditional jump",
            }
        return None

    def _constant_fold(self, ea):
        mnem = (self._ida.ida_ua.print_insn_mnem(ea) or "").lower()
        if mnem not in {"add", "sub", "xor", "or", "and", "shl", "shr"}:
            return None
        if self._ida.idc.get_operand_type(ea, 0) != 5 or self._ida.idc.get_operand_type(ea, 1) != 5:
            return None
        left = int(self._ida.idc.get_operand_value(ea, 0))
        right = int(self._ida.idc.get_operand_value(ea, 1))
        ops = {
            "add": left + right,
            "sub": left - right,
            "xor": left ^ right,
            "or": left | right,
            "and": left & right,
            "shl": left << right,
            "shr": left >> right,
        }
        return {
            "kind": "constant_fold",
            "ea": int(ea),
            "expression": f"{left:#x} {mnem} {right:#x}",
            "value": int(ops[mnem]),
        }

    def _indirect_jump(self, ea):
        mnem = (self._ida.ida_ua.print_insn_mnem(ea) or "").lower()
        if mnem not in {"jmp", "call"}:
            return None
        op_type = self._ida.idc.get_operand_type(ea, 0)
        # o_mem=2：直接内存操作数，目标可静态解析。
        if op_type == 2:
            target = int(self._ida.idc.get_operand_value(ea, 0))
            seg = self._ida.ida_segment.getseg(target)
            if seg is None:
                return None
            return {"kind": "indirect_jump", "ea": int(ea), "target": target,
                    "indirect_type": "memory",
                    "segment": self._ida.ida_segment.get_segm_name(seg)}
        # o_reg=1 / o_phrase=3 / o_displ=4：目标依赖运行时寄存器或跳表，静态不可解
        # （混淆最常用的间接跳转形式），标注为待动态分析，可配合 qiling trace 求真实目标。
        type_name = {1: "register", 3: "phrase", 4: "displacement"}.get(op_type)
        if type_name is not None:
            return {"kind": "indirect_jump", "ea": int(ea), "target": None,
                    "indirect_type": type_name,
                    "operand": self._ida.idc.print_operand(ea, 0) or ""}
        return None

    def _function_starts(self, functions):
        if functions:
            return [int(x) for x in list(functions)]
        return list(self._ida.idautils.Functions())

    def _require_ida(self):
        if self._ida is None:
            raise DeobfuscationError("this operation requires an IDA instance")
