# -*- coding: utf-8 -*-
"""IDA + Z3 辅助扩展：暴露给 JS 沙箱的 require('z3ida') 门面。"""
from extensions.z3_ext import Z3Facade, z3


_CONDITIONAL_JUMPS = {
    "jz", "je", "jnz", "jne", "ja", "jae", "jb", "jbe",
    "jg", "jge", "jl", "jle", "js", "jns",
}


class Z3IDAFacade:
    def __init__(self, ida=None):
        self._ida = ida
        self._z3 = Z3Facade()

    def bitvec(self, name, bits):
        return self._z3.bitvec(name, bits)

    def bvv(self, value, bits):
        return self._z3.bvv(value, bits)

    def solve(self, constraints):
        return self._z3.solve(constraints)

    def isAlwaysTrue(self, expr):
        return self._z3.isAlwaysTrue(expr)

    def isAlwaysFalse(self, expr):
        return self._z3.isAlwaysFalse(expr)

    def simplify(self, expr):
        return self._z3.simplify(expr)

    def exprToString(self, expr):
        return str(expr)

    def liftInstruction(self, ea, state=None):
        if self._ida is None:
            return _error("ida_required", "this operation requires an IDA instance", ea)
        try:
            insn = self._instruction(int(ea))
            effects, warnings = self._effects(insn, state or {})
            return {**insn, "ok": True, "supported": not warnings, "effects": effects, "warnings": warnings}
        except Exception as exc:
            return _error(type(exc).__name__, str(exc), ea)

    def liftBlock(self, block_ea, state=None):
        if self._ida is None:
            return _error("ida_required", "this operation requires an IDA instance", block_ea)
        try:
            opts = state or {}
            max_instructions = int(opts.get("maxInstructions", opts.get("window", 16)))
            ea = int(block_ea)
            func = self._ida.idaapi.get_func(ea)
            max_ea = int(func.end_ea) if func is not None else self._ida.idaapi.BADADDR
            instructions = []
            branch = None
            for _ in range(max_instructions):
                insn = self._instruction(ea)
                lifted = self.liftInstruction(ea, opts)
                instructions.append(lifted)
                if insn["mnemonic"] in _CONDITIONAL_JUMPS or insn["mnemonic"] in {"jmp", "ret", "retn"}:
                    branch = self._branch_info(insn)
                    break
                next_ea = int(self._ida.ida_bytes.next_head(ea, max_ea))
                if next_ea == self._ida.idaapi.BADADDR or next_ea <= ea:
                    break
                ea = next_ea
            return {
                "ok": True,
                "start_ea": int(block_ea),
                "end_ea": instructions[-1]["ea"] if instructions else int(block_ea),
                "instructions": instructions,
                "branch": branch,
                "warnings": [],
            }
        except Exception as exc:
            return _error(type(exc).__name__, str(exc), block_ea)

    def slicePredicate(self, branch_ea, opts=None):
        if self._ida is None:
            return _error("ida_required", "this operation requires an IDA instance", branch_ea)
        try:
            opts = opts or {}
            branch = self._instruction(int(branch_ea))
            if branch["mnemonic"] not in _CONDITIONAL_JUMPS:
                return {**branch, "ok": True, "condition": None, "slice": [branch],
                        "unsupported": [{"ea": int(branch_ea), "reason": "not a conditional jump"}], "warnings": []}
            max_backtrack = int(opts.get("maxBacktrack", opts.get("window", 16)))
            func = self._ida.idaapi.get_func(int(branch_ea))
            min_ea = int(func.start_ea) if func is not None else 0
            items = [branch]
            predicate = None
            ea = int(branch_ea)
            for _ in range(max_backtrack):
                prev = int(self._ida.ida_bytes.prev_head(ea, min_ea))
                if prev == self._ida.idaapi.BADADDR or prev >= ea:
                    break
                insn = self._instruction(prev)
                items.insert(0, insn)
                if insn["mnemonic"] in {"cmp", "test"}:
                    predicate = insn
                    break
                ea = prev
            condition, unsupported = self._predicate_condition(branch, predicate, opts)
            return {
                "ok": True,
                "branch_ea": int(branch_ea),
                "branch_mnemonic": branch["mnemonic"],
                "target": branch["target"],
                "fallthrough": branch["fallthrough"],
                "predicate_ea": None if predicate is None else predicate["ea"],
                "condition": None if condition is None else str(condition),
                "expr": condition,
                "slice": items,
                "unsupported": unsupported,
                "warnings": [] if condition is not None else ["predicate condition is incomplete"],
            }
        except Exception as exc:
            return _error(type(exc).__name__, str(exc), branch_ea)

    def checkBranch(self, branch_ea, opts=None):
        sliced = self.slicePredicate(branch_ea, opts or {})
        if not sliced.get("ok"):
            return sliced
        expr = sliced.get("expr")
        unsupported = sliced.get("unsupported", [])
        if expr is None:
            return {**_without_expr(sliced), "classification": "unsupported", "result": "unsupported",
                    "isAlwaysTrue": False, "isAlwaysFalse": False,
                    "confidence": "low", "reason": "predicate is unsupported",
                    "unsupported": unsupported,
                    "comment": "[z3ida] unsupported branch predicate"}
        if unsupported:
            return {**_without_expr(sliced), "classification": "unknown", "result": "unknown",
                    "isAlwaysTrue": False, "isAlwaysFalse": False,
                    "confidence": "low", "reason": "predicate has unsupported instructions",
                    "unsupported": unsupported,
                    "comment": "[z3ida] unknown branch predicate"}
        always_true = self.isAlwaysTrue(expr)
        always_false = self.isAlwaysFalse(expr)
        if always_true:
            classification = "always_taken"
            result = "always_true"
            reason = "branch condition is provably true by Z3"
        elif always_false:
            classification = "never_taken"
            result = "always_false"
            reason = "branch condition is provably false by Z3"
        else:
            classification = "unknown"
            result = "symbolic"
            reason = "both branch outcomes may be feasible"
        simplified = z3.simplify(expr)
        comment = f"[z3ida] {classification}: {simplified}"
        return {
            **_without_expr(sliced),
            "ok": True,
            "result": result,
            "classification": classification,
            "simplified": str(simplified),
            "isAlwaysTrue": bool(always_true),
            "isAlwaysFalse": bool(always_false),
            "taken_ea": sliced.get("target"),
            "not_taken_ea": sliced.get("fallthrough"),
            "confidence": "high" if classification != "unknown" else "medium",
            "reason": reason,
            "comment": comment,
        }

    def _instruction(self, ea):
        size = int(self._ida.ida_bytes.get_item_size(ea))
        raw = self._ida.idaapi.get_bytes(ea, size) or b""
        mnemonic = (self._ida.ida_ua.print_insn_mnem(ea) or "").lower()
        operands = []
        for idx in range(4):
            text = self._ida.idc.print_operand(ea, idx) or ""
            if not text:
                continue
            operands.append({
                "text": text,
                "type": int(self._ida.idc.get_operand_type(ea, idx)),
                "value": int(self._ida.idc.get_operand_value(ea, idx)),
            })
        return {
            "ea": int(ea),
            "size": size,
            "bytes": bytes(raw).hex(),
            "mnemonic": mnemonic,
            "operands": operands,
            "text": self._ida.idaapi.generate_disasm_line(ea, self._ida.idaapi.GENDSM_REMOVE_TAGS) or "",
            "target": int(self._ida.idc.get_operand_value(ea, 0)) if mnemonic in _CONDITIONAL_JUMPS else None,
            "fallthrough": int(ea + size),
        }

    def _effects(self, insn, state):
        mnem = insn["mnemonic"]
        ops = insn["operands"]
        bits = int(state.get("bits", 64)) if isinstance(state, dict) else 64
        if mnem in {"mov", "lea"} and len(ops) >= 2:
            dst = _operand_register(ops[0])
            src = _operand_expr(ops[1], bits, state)
            if dst is not None and src is not None:
                return [{"kind": "assign", "name": dst, "expr": str(src)}], []
            return [], [f"unsupported operands for {mnem}"]
        if mnem in {"add", "sub", "xor", "or", "and", "shl", "shr", "sar"} and len(ops) >= 2:
            dst = _operand_register(ops[0])
            left = _operand_expr(ops[0], bits, state)
            right = _operand_expr(ops[1], bits, state)
            if dst is not None and left is not None and right is not None:
                return [{"kind": "assign", "name": dst, "expr": str(_binary_expr(mnem, left, right))}], []
            return [], [f"unsupported operands for {mnem}"]
        if mnem in {"cmp", "test"} and len(ops) >= 2:
            condition, unsupported = self._predicate_condition({"mnemonic": "jz", "ea": insn["ea"]}, insn, state)
            if condition is not None:
                return [{"kind": "flag", "name": "ZF", "expr": str(condition)}], []
            return [], [x["reason"] for x in unsupported]
        if mnem in _CONDITIONAL_JUMPS:
            return [{"kind": "branch", "target": insn["target"], "fallthrough": insn["fallthrough"]}], []
        return [], [f"unsupported instruction: {mnem}"]

    def _branch_info(self, insn):
        return {"ea": insn["ea"], "mnemonic": insn["mnemonic"], "target": insn["target"], "fallthrough": insn["fallthrough"]}

    def _predicate_condition(self, branch, predicate, state=None):
        state = state or {}
        if predicate is None:
            return None, [{"ea": branch["ea"], "reason": "no cmp/test predicate found"}]
        mnem = predicate["mnemonic"]
        ops = predicate["operands"]
        if len(ops) < 2:
            return None, [{"ea": predicate["ea"], "reason": "predicate has fewer than two operands"}]
        bits = int(state.get("bits", 64)) if isinstance(state, dict) else 64
        left = _operand_expr(ops[0], bits, state)
        right = _operand_expr(ops[1], bits, state)
        if left is None or right is None:
            return None, [{"ea": predicate["ea"], "reason": "unsupported operand in predicate"}]
        if mnem == "cmp":
            diff = left - right
            zf = left == right
            cf = z3.ULT(left, right)
            sf = z3.Extract(bits - 1, bits - 1, diff) == z3.BitVecVal(1, 1)
            of = z3.Extract(bits - 1, bits - 1, (left ^ right) & (left ^ diff)) == z3.BitVecVal(1, 1)
        elif mnem == "test":
            tested = left & right
            zf = tested == z3.BitVecVal(0, bits)
            cf = z3.BoolVal(False)
            sf = z3.Extract(bits - 1, bits - 1, tested) == z3.BitVecVal(1, 1)
            of = z3.BoolVal(False)
        else:
            return None, [{"ea": predicate["ea"], "reason": f"unsupported predicate instruction: {mnem}"}]
        cond = _jump_condition(branch["mnemonic"], zf, cf, sf, of)
        if cond is None:
            return None, [{"ea": branch["ea"], "reason": f"unsupported conditional jump: {branch['mnemonic']}"}]
        return cond, []


def _operand_expr(op, bits, state=None):
    state = state or {}
    text = str(op.get("text", "")).strip()
    typ = int(op.get("type", 0))
    if typ == 5:
        return z3.BitVecVal(int(op.get("value", 0)), bits)
    if typ == 1 and _is_simple_register(text):
        name = _canonical_register(text)
        if isinstance(state, dict) and name in state:
            return _coerce_bitvec(state[name], bits)
        return z3.BitVec(name, bits)
    if text and text.lower() in {"0", "1"}:
        return z3.BitVecVal(int(text, 0), bits)
    return None


def _operand_register(op):
    text = str(op.get("text", "")).strip()
    if int(op.get("type", 0)) == 1 and _is_simple_register(text):
        return _canonical_register(text)
    return None


def _coerce_bitvec(value, bits):
    if isinstance(value, str):
        if value.startswith(("0x", "0X")) or value.lstrip("-").isdigit():
            return z3.BitVecVal(int(value, 0), bits)
        return z3.BitVec(value, bits)
    if isinstance(value, int):
        return z3.BitVecVal(value, bits)
    return value


def _binary_expr(mnem, left, right):
    if mnem == "add":
        return left + right
    if mnem == "sub":
        return left - right
    if mnem == "xor":
        return left ^ right
    if mnem == "or":
        return left | right
    if mnem == "and":
        return left & right
    if mnem == "shl":
        return left << right
    if mnem == "shr":
        return z3.LShR(left, right)
    if mnem == "sar":
        return left >> right
    return left


def _is_simple_register(text):
    t = text.lower()
    regs = {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"}
    regs.update({f"r{i}" for i in range(8, 16)})
    regs.update({f"r{i}d" for i in range(8, 16)})
    return t in regs


def _canonical_register(text):
    t = text.lower()
    if t.endswith("d") and len(t) > 2 and t[1:-1].isdigit():
        return t[:-1]
    return t


def _jump_condition(mnem, zf, cf, sf=None, of=None):
    if mnem in {"jz", "je"}:
        return zf
    if mnem in {"jnz", "jne"}:
        return z3.Not(zf)
    if mnem == "jb":
        return cf
    if mnem == "jae":
        return z3.Not(cf)
    if mnem == "jbe":
        return z3.Or(cf, zf)
    if mnem == "ja":
        return z3.And(z3.Not(cf), z3.Not(zf))
    if mnem == "jg":
        return z3.And(z3.Not(zf), sf == of)
    if mnem == "jge":
        return sf == of
    if mnem == "jl":
        return sf != of
    if mnem == "jle":
        return z3.Or(zf, sf != of)
    if mnem == "js":
        return sf
    if mnem == "jns":
        return z3.Not(sf)
    return None


def _error(error_type, message, ea=None):
    out = {"ok": False, "error": {"type": str(error_type), "message": str(message)}}
    if ea is not None:
        out["ea"] = int(ea)
    return out


def _without_expr(value):
    return {k: v for k, v in value.items() if k != "expr"}
