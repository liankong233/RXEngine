# -*- coding: utf-8 -*-
"""Lab 组合原语层：跨引擎地址锚点 + 分析黑板 + IDA/Angr/Unicorn 组合。

worker 本地对象：构造时不做 RPC；引擎活对象仅在一轮 run_js 内有效，
跨轮记忆放父进程 AnalysisBoard（require('board')）。
"""
from extensions.angr_ext import AngrFacade
from extensions.deobfuscation_ext import DeobfuscationFacade
from extensions.qiling_ext import QilingEmulationError, QilingFacade
from extensions.z3ida_ext import Z3IDAFacade

_BADADDR = (1 << 64) - 1
_QL_ARCH = {
    ("metapc", 64): "x8664", ("metapc", 32): "x86",
    ("arm", 64): "arm64", ("arm", 32): "arm",
    ("mips", 64): "mips", ("mips", 32): "mips", ("mipsb", 32): "mips",
}
_TRACE_LIMITS = {"call_edges": 2000, "branch_edges": 2000,
                 "hot_eas": 50, "mem_writes": 500}
# LabFacade 与各子门面经 self._ida.<mod> 访问的 IDA SDK 子模块全集
_IDA_SDK_MODULES = ("idaapi", "idautils", "idc", "ida_funcs", "ida_bytes",
                    "ida_ua", "ida_segment", "ida_name", "ida_ida")


def _facade_view(ida):
    """把传入的 ida 归一成 LabFacade/子门面期望的完整界面（FakeIDAFacade 的形状）。

    偏差说明（相对 brief 逐字实现，必要修复）：沙箱与生产的实际接线
    （sandbox.worker.run_worker -> extensions.register(ida=raw_ida)）把裸
    headless-ida 助手（只有 idaapi/idc/... SDK 子模块，没有 get_name_ea 等
    门面方法）交给 LabFacade；而 LabFacade 自己只调门面方法、四个子门面只调
    SDK 属性链——用裸对象两者皆缺门面方法，lab.deob/target/anchor 等在真实
    沙箱里必然 AttributeError。这里在探测到缺门面 API 时包一层 IDAFacade
    （其方法经 self._ida.<sdk> 落到裸对象），并把裸对象上的 SDK 子模块透传到
    包装层，使子门面的属性链不受影响；已是门面形状（FakeIDAFacade/IDAFacade）
    的对象原样返回，离线路径零影响。探测/透传对 RemoteObject 需捕 Exception
    （宿主 AttributeError 会被包成 RemoteCallError(RuntimeError)）。
    """
    if ida is None:
        return None
    try:
        ida.get_name_ea
    except Exception:  # noqa: BLE001
        pass
    else:
        return ida
    try:
        from headless_ida_mcp_server.ida_facade import IDAFacade  # 延迟导入：仅包装裸助手时需要
    except Exception:  # noqa: BLE001 — 环境缺 IDA_PATH 等导致不可导入时保持原对象，
        return ida  # 维持既有"调用期报错"契约，不让构造 LabFacade 本身失败
    wrapped = IDAFacade(ida)
    for name in _IDA_SDK_MODULES:
        try:
            setattr(wrapped, name, getattr(ida, name))
        except Exception:  # noqa: BLE001 — 缺哪个 SDK 子模块跳哪个（离线替身/精简后端）
            continue
    return wrapped


class LabError(Exception):
    pass


def to_angr_addr(ea, image_base, mapped_base):
    return int(ea) - int(image_base) + int(mapped_base)


def from_angr_addr(addr, image_base, mapped_base):
    return int(addr) - int(mapped_base) + int(image_base)


def to_ql_addr(ea, orig_ea, entry_point):
    return int(ea) - int(orig_ea) + int(entry_point)


def from_ql_addr(ql_ea, orig_ea, entry_point):
    return int(ql_ea) - int(entry_point) + int(orig_ea)


def parse_hex_operand(op_str):
    text = str(op_str or "").strip()
    try:
        return int(text, 16)
    except ValueError:
        return None


def cap_list(seq, limit):
    seq = list(seq or [])
    return seq[: int(limit)], len(seq) > int(limit)


# angr 回放种子要剔除的栈/帧/指令指针寄存器（大小写不敏感）：angr 评估出的
# rsp/rbp 指向 angr 重基址(rebase)后的栈空间，写入全新的 qiling 实例必然指向
# 未映射内存，回放近乎必炸——回放实例保留自己的栈，只播撒可移植的标量/通用寄存器。
_REPLAY_DROP_REGS = frozenset({"rsp", "esp", "rbp", "ebp", "rip", "eip"})


def _replay_seed_regs(mapping):
    """剔除栈/帧/指令指针寄存器后的回放种子（键名大小写不敏感；值原样透传）。"""
    return {name: value for name, value in dict(mapping or {}).items()
            if str(name).lower() not in _REPLAY_DROP_REGS}


def summarize_trace(events, limits):
    """把逐指令事件归约为 Trace 摘要（调用/分支边、热点、内存写）。"""
    call_edges, branch_edges, hot, mem_writes = [], [], {}, []
    for idx, ev in enumerate(events):
        ea = int(ev.get("ida_ea", ev.get("address", 0)))
        mnem = (ev.get("mnemonic") or "").lower()
        hot[ea] = hot.get(ea, 0) + 1
        target = parse_hex_operand(ev.get("op_str"))
        if mnem.startswith("call") and target is not None:
            call_edges.append({"ea": ea, "to_ea": target})
        elif mnem.startswith("j") or mnem.startswith("loop"):
            nxt = None
            if idx + 1 < len(events):
                nxt = int(events[idx + 1].get("ida_ea", events[idx + 1].get("address", 0)))
            branch_edges.append({"ea": ea, "to_ea": target,
                                 "taken": None if target is None else (nxt == target)})
        for write in ev.get("mem_writes") or []:
            mem_writes.append({"ea": int(write.get("ida_ea", write.get("address", 0))),
                               "size": int(write.get("size", 0)),
                               "value": int(write.get("value", 0))})
    hot_pairs, _ = cap_list(sorted(hot.items(), key=lambda kv: -kv[1]), limits["hot_eas"])
    call_edges, call_trunc = cap_list(call_edges, limits["call_edges"])
    branch_edges, branch_trunc = cap_list(branch_edges, limits["branch_edges"])
    mem_writes, mem_trunc = cap_list(mem_writes, limits["mem_writes"])
    return {"call_edges": call_edges, "branch_edges": branch_edges,
            "hot_eas": [{"ea": ea, "count": n} for ea, n in hot_pairs],
            "mem_writes": mem_writes,
            "edges_truncated": bool(call_trunc or branch_trunc or mem_trunc)}


def _rxstub_comment_ea(item):
    for key in ("callsiteEa", "callsite_ea", "callsite", "ea", "addr"):
        value = item.get(key)
        if value is not None:
            return value
    return None


def _format_rxstub_value(value):
    if value is None:
        return "null"
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict) and value.get("name") is not None:
        return str(value["name"])
    return repr(value)


class LabFacade:
    def __init__(self, ida=None, board=None, facade=None):
        # 门面级调用（annotate/preview/commit/decompile/target/...）走 self._ida：
        # 调用方显式给了 facade（如 worker 经 RPC 指向父进程 session 门面的 "ida"
        # 根）就直接采用、不做能力探测——staged 状态必须落在跨 worker 存活的
        # session 门面上，而不是随 worker 退出销毁的进程内包装（split-brain）。
        self._ida = facade if facade is not None else _facade_view(ida)
        # 子门面（qiling/angr/z3ida/deobfuscation）只走 self._ida.<sdk> 属性链，
        # 需要裸助手上原始的 IDA SDK 子模块（门面根不透传它们），故传裸 ida。
        self._raw_ida = ida
        self._board = board
        self._qiling = QilingFacade(ida)
        self._angr = AngrFacade(ida)
        self._z3ida = Z3IDAFacade(ida)
        self._deob = DeobfuscationFacade(ida)
        self._project_cache = None
        self._project_cache_path = None
        # 只保留最近一次实例。保活 worker 下 LabFacade 跨轮存活，若按 append 累积，
        # 每轮 lab.emulate 的活 qiling 实例都会滞留到 worker 回收；JS 侧句柄本身持有
        # 引用，这里仅作最近一次实例的调试可见性。
        self._emulators = []

    # ---- 基础 ----
    def _require_ida(self):
        if self._ida is None:
            raise LabError("lab requires an IDA session (set_binary_path first)")

    def _require_board(self):
        if self._board is None:
            raise LabError("analysis board unavailable in this session")

    def _ea(self, x):
        if isinstance(x, int):
            return int(x)
        text = str(x).strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
        self._require_ida()
        ea = self._ida.get_name_ea(text)
        if ea is None or int(ea) >= _BADADDR:
            raise LabError(f"cannot resolve address/symbol: {x!r}")
        return int(ea)

    def _board_add(self, entity_kind, **fields):
        # 注：参数名用 entity_kind，避免与 fields 里的语义 kind（如 target 的 "func"）
        # 冲突；board._put 侧 setdefault 会保留语义 kind，仅缺省时回落到实体 kind。
        if self._board is None:
            fields.setdefault("id", None)
            return fields
        return getattr(self._board, f"add_{entity_kind}")(**fields)

    def _qiling_arch(self, opts=None):
        self._require_ida()
        arch = (opts or {}).get("arch")
        if arch:
            return str(arch)
        info = self._ida.arch_info()
        return _QL_ARCH.get((info.get("proc"), info.get("bits")), "x8664")

    # ---- 会话与坐标 ----
    def basis(self):
        self._require_ida()
        return {"image_base": int(self._ida.get_imagebase()),
                "input_path": self._ida.get_input_file_path(),
                "arch": self._ida.arch_info()}

    def anchor(self, x):
        self._require_ida()
        ea = self._ea(x)
        return {"ea": ea,
                "name": self._ida.get_function_name(ea) or "",
                "func": self._ida.function_info(ea),
                "segment": self._ida.get_segment_name(ea)}

    def target(self, x, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        base = self.anchor(x)
        info = base.get("func")
        if info and opts.get("force_kind") != "region":
            record = {"kind": "func", "ea": info["start_ea"], "name": info["name"],
                      "start_ea": info["start_ea"], "end_ea": info["end_ea"],
                      "size": info["size"]}
        else:
            size = int(opts.get("size") or self._ida.get_instruction_size(base["ea"]) or 1)
            record = {"kind": "region", "ea": base["ea"],
                      "name": base["name"] or f"region_{base['ea']:x}",
                      "start_ea": base["ea"], "end_ea": base["ea"] + size, "size": size}
        record["segment"] = base.get("segment")
        if opts.get("with_bytes"):
            raw = self._ida.get_bytes(record["start_ea"],
                                      min(record["size"], int(opts.get("max_bytes", 1 << 16))))
            record["bytes_hex"] = bytes(raw or b"").hex()
        return self._board_add("target", **record)

    def _get_project(self, opts=None):
        # 按 path 作缓存键：保活 worker 下缓存跨轮存活，显式换 path 时必须重新加载，
        # 否则会在旧项目上做地址换算/路径跟随。path=None 表示当前输入文件，换 binary
        # 会经 session_mutation 回收 worker，因此无需额外的失效条件。
        path = (opts or {}).get("path")
        if self._project_cache is None or self._project_cache_path != path:
            self._require_ida()
            self._project_cache = self._angr.project(path)
            self._project_cache_path = path
        return self._project_cache

    def to_angr(self, ea, project=None):
        project = project or self._get_project()
        base = project.loader.main_object.mapped_base
        return to_angr_addr(self._ea(ea), int(self._ida.get_imagebase()), int(base))

    def from_angr(self, addr, project=None):
        project = project or self._get_project()
        base = project.loader.main_object.mapped_base
        return from_angr_addr(int(addr), int(self._ida.get_imagebase()), int(base))

    # ---- 读原语 ----
    def decompile(self, x):
        self._require_ida()
        return self._ida.decompile(self._ea(x))

    def disasm(self, x, opts=None):
        self._require_ida()
        return self._ida.disassemble(self._ea(x), (opts or {}).get("count"))

    def xrefs(self, x):
        self._require_ida()
        ea = self._ea(x)
        return {"to": self._ida.get_xrefs_to(ea), "from": self._ida.get_xrefs_from(ea)}

    def bytes(self, x, size=None):
        self._require_ida()
        ea = self._ea(x)
        n = int(size or self._ida.get_instruction_size(ea) or 1)
        return {"ea": ea, "size": n, "hex": bytes(self._ida.get_bytes(ea, n) or b"").hex()}

    def plan_emulation(self, x, opts=None):
        self._require_ida()
        t = self.target(x)
        return self._qiling.plan(t["start_ea"], t["size"], opts)

    def detect_arch(self):
        self._require_ida()
        return self._ida.arch_info()

    # ---- 写回（staged-only）----
    def annotate(self, ea, text, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        addr = self._ea(ea)
        kind = opts.get("kind", "disasm")
        if kind == "decompiler":
            change = self._ida.set_decompiler_comment(addr, str(text))
        elif kind == "rename":
            change = self._ida.rename(addr, str(text))
        elif kind == "prototype":
            change = self._ida.set_function_prototype(addr, str(text))
        elif kind == "local":
            change = self._ida.rename_local_variable(
                int(opts["function_address"]), str(opts["old_name"]), str(text))
        else:
            change = self._ida.set_comment(addr, str(text),
                                           bool(opts.get("repeatable", False)))
        return self._board_add("patch", op=kind, ea=addr, new=str(text), change=change)

    def preview(self):
        self._require_ida()
        return self._ida.preview()

    def commit(self, backup=None):
        self._require_ida()
        return self._ida.commit(backup)

    def discard(self):
        self._require_ida()
        return self._ida.discard()

    def undo(self):
        self._require_ida()
        return self._ida.undo()

    def save_idb(self, path):
        self._require_ida()
        return self._ida.save_idb(path)

    # ---- 黑板 ----
    def note(self, kind, ea, text, opts=None):
        self._require_board()
        opts = dict(opts or {})
        return self._board.add_finding(
            kind, self._ea(ea) if ea is not None else 0, text,
            evidence=opts.get("evidence"), severity=opts.get("severity", "info"),
            action=opts.get("action"), target_id=opts.get("target_id"))

    def findings(self, kind=None, target_id=None):
        self._require_board()
        where = {}
        if kind is not None:
            where["kind"] = kind
        if target_id is not None:
            where["target_id"] = target_id
        return self._board.list("finding", where=where)

    def targets(self):
        self._require_board()
        return self._board.list("target", limit=1000)

    def traces(self):
        self._require_board()
        return self._board.list("trace", limit=200)

    def paths(self):
        self._require_board()
        return self._board.list("path", limit=200)

    def hypotheses(self):
        self._require_board()
        return self._board.list("hypothesis", limit=200)

    def hypothesis(self, ea, claim):
        self._require_board()
        return self._board.add_hypothesis(ea=self._ea(ea), claim=str(claim), status="open")

    def clear(self, kind=None):
        self._require_board()
        self._board.clear(kind)
        return {"ok": True}

    def save_snapshot(self, path):
        self._require_board()
        return self._board.save_snapshot(path)

    def load_snapshot(self, path):
        self._require_board()
        return self._board.load_snapshot(path)

    def artifact(self, name, content):
        self._require_board()
        return self._board.artifact(name, content)

    def board_summary(self):
        self._require_board()
        return self._board.summary()

    # ---- rxstubs（承接原 MCP 工具）----
    def stage_rxstub_comments(self, results, opts=None):
        self._require_ida()
        opts = dict(opts or {})
        prefix = str(opts.get("prefix", "rxstub"))
        staged = []
        for item in list(results or []):
            ea = _rxstub_comment_ea(item)
            if ea is None:
                continue
            text = f"{prefix}: {_format_rxstub_value(item)}"
            staged.append(self.annotate(int(ea), text,
                                        {"kind": opts.get("comment_kind", "disasm")}))
        return {"ok": True, "staged": staged}

    # ---- 场景：跟踪 ----
    def trace(self, x, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target = self.target(x, opts)
            arch = self._qiling_arch(opts)
            max_trace = int(opts.get("max_steps") or 2000)
            plan = {"ok": False, "skipped": True}
            if opts.get("plan", True):
                try:
                    plan = self._qiling.plan(target["start_ea"], target["size"],
                                             {"limit": int(opts.get("plan_limit", 500))})
                except Exception as exc:  # noqa: BLE001 — plan 只是提示，不阻断
                    plan = {"ok": False, "skipped": True, "error": str(exc)}
            raw, fault = self._trace_at(target, arch, opts, max_trace)
            events = raw.get("trace") if isinstance(raw, dict) else raw
            truncated = bool((raw.get("truncated") if isinstance(raw, dict) else False)
                             or fault)
            strings = raw.get("strings") if isinstance(raw, dict) else None
            summary = summarize_trace(events, _TRACE_LIMITS)
            fields = {}
            if fault is not None:
                fields["fault"] = fault
            record = self._board_add(
                "trace", target_id=target.get("id"), entry_ea=target["start_ea"],
                steps=len(events), truncated=truncated, **summary, **fields)
            out = {"ok": True, "trace_id": record["id"],
                   "target": {"id": target.get("id"), "kind": target["kind"],
                              "start_ea": target["start_ea"], "size": target["size"]},
                   "steps": len(events), "truncated": truncated,
                   "plan": plan, "arch": arch, **summary}
            if fault is not None:
                out["fault"] = fault
            if strings is not None:
                out["strings"] = strings
            if opts.get("store_events"):
                out["events"] = events
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def _trace_at(self, target, arch, opts, max_trace):
        """跑 trace_at 并容忍模拟故障，返回 (raw, fault)。

        偏差说明（相对 brief 逐字实现）：shellcode 模式下 qiling 把 sp 指到代码
        起始处，函数末尾的 ret 会把代码前 8 字节当返回地址弹出并取指失败
        （UC_ERR_FETCH_UNMAPPED），count=0 的"跑到自然结束"必炸且已采集的事件
        随异常丢弃；trace_at 也未暴露 end/stop。故这里按 max_steps 封顶执行，
        若中途故障则二分搜索能干净跑完的最大指令数，保住故障前的完整前缀
        （clean 随 count 单调），并把 truncated=1、故障信息附到结果里；
        同时消除了 count=0+timeout=0 在自循环代码上无限挂起的风险。
        """
        count = int(opts.get("count") or 0)

        def run(n):
            return self._qiling.trace_at(
                target["start_ea"], target["size"],
                count=n, arch=arch,
                os=opts.get("os", "linux"), regs=opts.get("regs"),
                trace_regs=bool(opts.get("trace_regs", True)),
                trace_mem=bool(opts.get("trace_mem", True)),
                timeout=float(opts.get("timeout", 0) or 0),
                max_trace=max_trace,
                max_mem_events=int(opts.get("max_mem_events", 5000)))

        cap = count or max_trace
        try:
            return run(cap), None
        except QilingEmulationError as exc:
            first = exc
        best_raw, best = None, 0
        lo, hi = 1, cap - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            try:
                best_raw, best, lo = run(mid), mid, mid + 1
            except QilingEmulationError:
                hi = mid - 1
        if best == 0:
            raise first
        return best_raw, f"emulation faulted; kept clean prefix of {best} instructions"

    # ---- 场景：调试 ----
    def emulate(self, x, opts=None):
        opts = dict(opts or {})
        self._require_ida()
        target = self.target(x, opts)
        arch = self._qiling_arch(opts)
        os_name = opts.get("os", "linux")
        mapped = bool(opts.get("map_segments"))
        if mapped:
            ql = self._qiling.create(b"\x90\x90\x90\x90", {"arch": arch, "os": os_name})
            segments = self._qiling.map_idb_segments(ql, opts)
            entry = orig = target["start_ea"]
        else:
            ql = self._qiling.create_from(target["start_ea"], target["size"],
                                          {"arch": arch, "os": os_name})
            segments = []
            entry = int(ql.os.entry_point)
            orig = target["start_ea"]
        if opts.get("regs"):
            self._qiling.set_regs(ql, {str(k): int(v) for k, v in dict(opts["regs"]).items()})
        emu = LabEmulator(self, ql, orig_ea=orig, entry=entry, size=target["size"],
                          arch=arch, mapped=mapped, mapped_segments=segments)
        self._emulators = [emu]
        return emu

    # ---- 场景：反混淆 ----
    def deob(self, x=None, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target_id = None
            if x is not None:
                target = self.target(x, opts)
                target_id = target.get("id")
                opts["functions"] = [target["start_ea"]]
            res = self._deob.scan(opts)
            findings = []
            for item in list(res.get("results", [])):
                enriched = dict(item)
                ea = item.get("ea") or item.get("addr")
                if ea is not None and (item.get("kind") or "") == "opaque_predicate":
                    enriched["branch"] = self.solve_branch(ea, {"stage": False})
                findings.append(self._board_add(
                    "finding", kind=item.get("kind") or "deob", ea=int(ea or 0),
                    text=str(item), evidence=enriched, target_id=target_id))
            return {"ok": True, "results": findings, "scanned": res.get("scanned"),
                    "matched": res.get("matched"),
                    "failures": list(res.get("failures", []))[:20]}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def solve_branch(self, ea, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            addr = self._ea(ea)
            res = self._z3ida.checkBranch(addr, opts.get("slice_opts"))
            # 偏差说明（相对 brief 逐字实现）：checkBranch/slicePredicate 内部异常会
            # 返回 {"ok": False, "error": {...}}；若仍按 brief 继续构造
            # {"ok": True, classification: None, ...} 会把失败伪装成成功判定并落进
            # 黑板 evidence。这里把失败原样上抛（附 ea），成功路径与 brief 完全一致。
            if not res.get("ok", True):
                return {**res, "ea": addr}
            keys = ("classification", "result", "simplified", "taken_ea",
                    "not_taken_ea", "confidence", "reason", "comment", "unsupported")
            out = {"ok": True, "ea": addr}
            out.update({k: res.get(k) for k in keys})
            if opts.get("concrete") and out.get("classification") in ("symbolic", "unknown"):
                out["concrete"] = self._concrete_confirm(addr, opts)
            if opts.get("stage") and out.get("comment"):
                out["patch"] = self.annotate(addr, out["comment"], {"kind": "disasm"})
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def _concrete_confirm(self, branch_ea, opts):
        info = self._ida.function_info(branch_ea)
        if not info:
            return {"ok": False, "reason": "branch not inside a function"}
        emu = self.emulate(info["start_ea"],
                           {"map_segments": bool(opts.get("map_segments", False))})
        taken = self._ea(opts["taken_ea"]) if opts.get("taken_ea") else None
        visited = set()
        for _ in range(int(opts.get("max_steps", 2000))):
            emu.step(1)
            visited.add(emu.rip())
            if emu.rip() == branch_ea:
                emu.step(1)
                visited.add(emu.rip())
                break
        return {"ok": True, "taken_ea": taken,
                "taken_hit": None if taken is None else (taken in visited),
                "visited": len(visited)}

    # ---- 场景：路径跟随 ----
    def concrete_prefix(self, x, opts=None):
        opts = dict(opts or {})
        try:
            # 偏差说明（相对 brief 逐字实现，必要修复）：brief 原样把
            # {"arch": opts.get("arch"), "os": opts.get("os")} 传给 emulate，键恒存在、
            # 值为 None，而 emulate 侧 opts.get("os", "linux") 只在键缺席时取默认——
            # 结果 os=None 直接 QilingError: unsupported os: none。故仅显式提供时才
            # 透传 arch/os，缺省回落 emulate 自身的探测/默认逻辑。
            emu_opts = {"map_segments": bool(opts.get("map_segments", False))}
            if opts.get("arch") is not None:
                emu_opts["arch"] = opts["arch"]
            if opts.get("os") is not None:
                emu_opts["os"] = opts["os"]
            emu = self.emulate(x, emu_opts)
            until = emu.to_ql(self._ea(opts["stop_at"])) if opts.get("stop_at") is not None else None
            steps = int(opts.get("max_steps", 2000))
            timeout_us = int(float(opts.get("timeout", 0) or 0) * 1_000_000) or None
            # 偏差说明（相对 brief 逐字实现，承接控制器备忘）：qiling shellcode 模式下
            # 执行越过映射代码末端（末尾 ret、未映射 call 目标）会抛，被
            # LabEmulator._emu_start 包成 LabError；在真实函数上按 max_steps 预算跑
            # 几乎必然命中，若照 brief 原样返回 {ok:false}，方法就失去意义（本意是
            # 快照具体寄存器状态）。故：故障前已执行至少一条指令（PC 离开入口或
            # 寄存器有变化）时仍返回 {ok:true, ..., faulted:true, fault:...} 的
            # 部分状态快照；零指令故障（或非模拟错误）维持 {ok:false} 信封。
            # 仅 concrete_prefix 容忍故障，emu.step()/run() 的抛错契约不变。
            start_pc = emu._pc()
            regs_before = emu.regs()
            fault = None
            try:
                emu._emu_start(count=steps or None, until_ql=until, timeout_us=timeout_us)
            except Exception as exc:  # noqa: BLE001 — 按执行进度决定容忍或上抛
                if emu._pc() == start_pc and emu.regs() == regs_before:
                    raise
                fault = str(exc)
            out = {"ok": True, "rip_ida": emu.rip(), "regs": emu.regs(), "steps": steps}
            if fault is not None:
                out["faulted"] = True
                out["fault"] = fault
            if opts.get("record"):
                emu.record("concrete_prefix")
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def follow(self, x, opts=None):
        opts = dict(opts or {})
        try:
            self._require_ida()
            target = self.target(x, opts)
            project = self._get_project(opts)
            start_angr = self.to_angr(target["start_ea"], project)
            if opts.get("args") is not None:
                state = self._angr.call_state(project, start_angr, args=opts["args"])
            else:
                state = self._angr.blank_state(project, start_angr, opts.get("state_opts"))
            for name, value in dict(opts.get("seed_regs") or {}).items():
                self._angr.reg_write(state, name, int(value))
            find = ([self.to_angr(self._ea(g), project) for g in opts["goal"]]
                    if opts.get("goal") else None)
            avoid = ([self.to_angr(self._ea(g), project) for g in opts.get("avoid", [])]
                     or None)
            res = self._angr.explore_paths(project, state, {
                "find": find, "avoid": avoid,
                "max_steps": int(opts.get("max_steps", 0) or 0),
                "timeout": float(opts.get("timeout", 0) or 0),
                "n": opts.get("n"), "max_active": opts.get("max_active"),
                "veritesting": opts.get("veritesting"), "dfs": opts.get("dfs"),
                "loop_bound": opts.get("loop_bound")})
            simgr = res["simgr"]
            # 修复（评审 Finding 2）：无 goal 时 simgr 里没有 "found" stash，原先
            # first(simgr, "active") 会把"预算末端仍有活状态"伪装成 found=True。
            # found 语义统一为"找到 goal 路径"：无 goal 一律 False，探索存活情况改以
            # active_count 报告（黑板记录与信封都带；有 goal 的路径也带，保持对称）。
            # 无 goal 时仍采样首个活状态的 blocks/regs/constraints 作为探索快照。
            pick = self._angr.first(simgr, "found" if find else "active")
            found = pick if find is not None else None
            active_count = len(simgr.active)
            reg_names = opts.get("regs") or list(project.arch.default_symbolic_registers)[:6]
            blocks, regs, constraints = [], {}, []
            if pick is not None:
                blocks = [self.from_angr(a, project)
                          for a in pick.history.bbl_addrs][: int(opts.get("max_blocks", 5000))]
                regs = {r: self._angr.eval(pick, getattr(pick.regs, r)) for r in reg_names}
                constraints = [str(c) for c in list(pick.solver.constraints)[:100]]
            record = self._board_add(
                "path", target_id=target.get("id"), found=found is not None,
                active_count=active_count,
                goal_ea=self._ea(opts["goal"][0]) if opts.get("goal") else None,
                blocks_ida=blocks, regs=regs, constraints=constraints,
                stash_counts=res.get("counts"))
            out = {"ok": True, "path_id": record["id"], "found": record["found"],
                   "active_count": record["active_count"],
                   "blocks_ida": blocks[:200], "regs": regs,
                   "constraints": constraints[:20], "stash_counts": res.get("counts")}
            if opts.get("verify_concrete") and found is not None:
                out["verify"] = self._verify_concrete(target, opts, regs)
            return out
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error_type": type(exc).__name__, "message": str(exc)}

    def _verify_concrete(self, target, opts, regs):
        try:
            emu = self.emulate(target["start_ea"], {"map_segments": True})
            goal = opts.get("goal")
            until = emu.to_ql(self._ea(goal[0])) if goal else None
            # 修复（评审 Finding 1）：regs 由 angr 在重基址后的项目空间评估，其中
            # rsp/rbp 是 angr 栈空间的指针值，对全新 qiling 实例不可移植，直接写入
            # 会让回放近乎必然 UC_ERR_READ_UNMAPPED。故先经 _replay_seed_regs 剔除
            # 栈/帧/指令指针寄存器（angr 空间指针值不进回放实例，qiling 保留自己
            # 的栈），仅播撒标量/通用寄存器；reached 语义（rip == goal）不变。
            emu.set_regs({k: int(v) for k, v in _replay_seed_regs(regs).items()
                          if isinstance(v, int)})
            emu._emu_start(count=int(opts.get("verify_steps", 10000)) or None,
                           until_ql=until)
            reached = goal is not None and emu.rip() == self._ea(goal[0])
            return {"ok": True, "reached": reached, "rip_ida": emu.rip()}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}


class LabEmulator:
    """活模拟句柄：以 IDA 地址为入参，内部换算；仅在一轮 run_js 内有效。"""

    def __init__(self, lab, ql, orig_ea, entry, size, arch, mapped, mapped_segments=None):
        self._lab = lab
        self._q = lab._qiling
        self._ql = ql
        self.orig_ea = int(orig_ea)
        self.entry = int(entry)
        self.size = int(size)
        self.arch = arch
        self.mapped = bool(mapped)
        self.mapped_segments = mapped_segments or []
        self._snapshots = {}
        self._snap_seq = 0
        # 偏差说明（相对 brief 逐字实现）：qiling 在首次 emu_start 前 arch_pc 读出为
        # 0（并非 entry_point），会令 rip() 锚错位置、step() 从 0 取指直接炸。构造时
        # 把 PC 寄存器锚到入口（qiling 的 regs.arch_pc 有 setter），保证句柄一创建
        # 就处于"停在入口"的一致状态。
        self._ql.arch.regs.arch_pc = self.entry

    def to_ql(self, ea):
        if self.mapped:
            return int(ea)
        return to_ql_addr(ea, self.orig_ea, self.entry)

    def to_ida(self, ql_ea):
        if self.mapped:
            return int(ql_ea)
        return from_ql_addr(ql_ea, self.orig_ea, self.entry)

    def _pc(self):
        return int(self._ql.arch.regs.arch_pc)

    def rip(self):
        return self.to_ida(self._pc())

    def _emu_start(self, count=None, until_ql=None, timeout_us=None):
        kwargs = {}
        if count:
            kwargs["count"] = int(count)
        if timeout_us:
            kwargs["timeout"] = int(timeout_us)
        try:
            # 偏差说明（相对 brief 逐字实现）：本机 unicorn 绑定的 emu_start 签名是
            # emu_start(begin, until, timeout=0, count=0)，until 为必填位置参数，
            # 不传直接 TypeError。故 until 改为位置传参，未指定终点时以 0 占位
            # （等价于不设终点；正常执行不会恰好停在 0）。
            self._ql.arch.uc.emu_start(self._pc(),
                                       int(until_ql) if until_ql is not None else 0,
                                       **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise LabError(f"emulation stopped at {self.rip():#x}: {exc}") from exc

    def step(self, n=1):
        self._emu_start(count=int(n))
        return {"rip_ida": self.rip(), "regs": self.regs()}

    def run(self, opts=None):
        opts = dict(opts or {})
        self._emu_start(
            count=int(opts["count"]) if opts.get("count") else None,
            until_ql=self.to_ql(opts["until_ida"]) if opts.get("until_ida") is not None else None,
            timeout_us=int(float(opts["timeout"]) * 1_000_000) if opts.get("timeout") else None)
        return {"ok": True, "rip_ida": self.rip(), "regs": self.regs()}

    def regs(self, names=None):
        if names:
            return {str(n): int(self._ql.arch.regs.read(str(n))) for n in names}
        return {k: int(v) for k, v in self._q.regs(self._ql).items()}

    def set_regs(self, mapping):
        self._q.set_regs(self._ql, {str(k): int(v) for k, v in dict(mapping).items()})
        return {"ok": True}

    def mem_read(self, ea, size):
        return bytes(self._q.mem_read(self._ql, self.to_ql(ea), int(size))).hex()

    def mem_write(self, ea, data):
        payload = bytes.fromhex(data) if isinstance(data, str) else bytes(data)
        self._q.mem_write(self._ql, self.to_ql(ea), payload)
        return {"ok": True, "ea": int(ea), "size": len(payload)}

    def bp(self, ea, cb=None):
        # 修复回归：hook_address 会无条件调用回调（qiling_ext.py 的 on_code），
        # cb=None 的断点会在命中瞬间抛 'NoneType' object is not callable。
        # 缺省回落为接受 hook 签名的空操作回调，使无回调断点等效纯观测断点。
        return self._q.hook_address(self._ql, self.to_ql(ea),
                                    cb or (lambda *_args: None))

    def save_state(self, ranges=None):
        ranges = list(ranges) if ranges else [(self.orig_ea, self.size)]
        snapshot = {"regs": self.regs(),
                    "mem": [{"ea": int(ea), "size": int(sz), "hex": self.mem_read(ea, sz)}
                            for ea, sz in ranges]}
        self._snap_seq += 1
        sid = f"snap-{self._snap_seq}"
        self._snapshots[sid] = snapshot
        return sid

    def restore_state(self, snapshot_id):
        snapshot = self._snapshots.get(str(snapshot_id))
        if snapshot is None:
            raise LabError(f"unknown snapshot: {snapshot_id}")
        self.set_regs(snapshot["regs"])
        for block in snapshot["mem"]:
            self.mem_write(block["ea"], block["hex"])
        return {"ok": True, "restored": str(snapshot_id)}

    def trace(self, opts=None):
        opts = dict(opts or {})
        opts.setdefault("orig_ea", None if self.mapped else self.orig_ea)
        # 偏差说明（承接控制器备忘，相对 brief 逐字实现）：shellcode 模式下 qiling 把
        # sp 指到代码起始处，末尾 ret 会把代码字节当返回地址弹出并取指失败；实测
        # count=16 也在第 3 条指令就 UC_ERR_FETCH_UNMAPPED，且 QilingFacade.trace
        # 故障时会丢弃已采集事件。故除按预算封顶 count（无显式 count 时取 max_trace）
        # 外，故障时先存快照、二分搜索能干净跑完的最大指令数重放（每次重放前恢复
        # 快照），保住故障前完整前缀并把句柄停在干净终态——语义与 lab.trace 的
        # _trace_at clean-prefix 约定一致。代价：每次重放会叠加一组 hook（仅本句柄
        # 生命周期内，无正确性影响）；快照默认只覆盖代码区，故障重放不回收代码区外
        # 的内存写入。
        if not opts.get("count"):
            opts["count"] = int(opts.get("max_trace") or 0)
        sid = self.save_state()
        try:
            return self._q.trace(self._ql, opts)
        except QilingEmulationError as exc:
            first = exc
        cap = int(opts.get("count") or 0)
        best_raw, best = None, 0
        lo, hi = 1, cap - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            self.restore_state(sid)
            try:
                retry = dict(opts)
                retry["count"] = mid
                best_raw, best, lo = self._q.trace(self._ql, retry), mid, mid + 1
            except QilingEmulationError:
                hi = mid - 1
        if best == 0:
            self.restore_state(sid)
            raise first
        self.restore_state(sid)
        retry = dict(opts)
        retry["count"] = best
        return self._q.trace(self._ql, retry)

    def record(self, name=None):
        return self._lab._board_add("finding", kind="emulator_state", ea=self.rip(),
                                    text=str(name or "emulator state"),
                                    evidence={"regs": self.regs()})
