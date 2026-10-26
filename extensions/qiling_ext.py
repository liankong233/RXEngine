# -*- coding: utf-8 -*-
"""qiling 模拟扩展：暴露给 JS 沙箱的 require('qiling') 门面。

参考 qiling 的 IDA 插件（qilingida.py 的 QlEmuQiling），但做了关键简化：
qiling 插件运行在 IDA 进程内、从磁盘加载完整二进制并需要 rootfs（含目标系统 DLL/so）；
这里走 qiling 的 code 模式（shellcode 模拟），只喂原始机器码字节，rootfs 用当前目录占位，
不需要任何目标系统运行库，适合模拟一段指令并观察寄存器/内存变化。

两类用法：
  - 一次性：emulate_code / emulate_at，建实例->run->返回寄存器 dict。
  - 交互式：create / create_from 返回活的 Qiling 实例，JS 自行读写寄存器/内存、设
    hook、直接访问底层 unicorn 引擎 ql.arch.uc；本门面另提供 run/regs/set_regs/
    mem_read/mem_write/map_mem/alloc/disasm/stack_push/stack_pop 等便捷方法（因 JS
    无原生 bytes、也无法给 Python 传 kwargs，这些方法负责补上这层适配）。

参数/返回值都是 int/str/dict/list 标量，天然可经 sandbox.bridge 编组给 JS（int->
float(<=2^53)/str(更大)、bytes->hex、list->JSArray、JS 对象->dict、JS 函数->回调）。
"""
import time
import traceback

try:
    import unicorn
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
    from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UcError
    from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
except ModuleNotFoundError as exc:
    unicorn = None
    Qiling = None
    QL_ARCH = QL_OS = QL_VERBOSE = None
    UC_HOOK_MEM_READ = UC_HOOK_MEM_WRITE = UC_HOOK_CODE = 0
    UC_PROT_READ = 1
    UC_PROT_WRITE = 2
    UC_PROT_EXEC = 4

    class UcError(Exception):
        pass

    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

# arch 名 -> (QL_ARCH, 主要通用寄存器名列表)。寄存器名用于批量回读/dump。
if _IMPORT_ERROR is None:
    _ARCH = {
        "x86": (QL_ARCH.X86,
                ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]),
        "x8664": (QL_ARCH.X8664,
                  ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]),
        "arm": (QL_ARCH.ARM,
                ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                 "r10", "r11", "r12", "sp", "lr", "pc"]),
        "arm64": (QL_ARCH.ARM64,
                  ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                   "x10", "x11", "x12", "x13", "x14", "x15", "sp", "pc"]),
        "mips": (QL_ARCH.MIPS,
                 ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "sp", "ra", "pc"]),
    }
    _ARCH["x64"] = _ARCH["x8664"]
else:
    _ARCH = {}

# arch 名 -> 程序计数器寄存器名，用于模拟异常时定位出错指令地址。
_PC = {"x86": "eip", "x8664": "rip", "x64": "rip",
       "arm": "pc", "arm64": "pc", "mips": "pc"}

# arch 名 -> 按调用约定传参的寄存器顺序（x86 走栈，不在此表）。
_ARG_REGS = {
    "x8664": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],  # SysV AMD64
    "x64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],  # AAPCS64
    "arm": ["r0", "r1", "r2", "r3"],
    "mips": ["a0", "a1", "a2", "a3"],
}

# arch 名 -> 返回值寄存器；-> 返回地址（link register）寄存器（None=经栈）。
_RET_REG = {"x86": "eax", "x8664": "rax", "x64": "rax",
            "arm": "r0", "arm64": "x0", "mips": "v0"}
_LR_REG = {"arm": "lr", "arm64": "lr", "mips": "ra",
           "x86": None, "x8664": None, "x64": None}

# unicorn 错误码 -> 结构化 error_type，避免向上层暴露裸 UcError。
if _IMPORT_ERROR is None:
    _UC_ERROR = {
        unicorn.UC_ERR_READ_UNMAPPED: "unmapped_memory_read",
        unicorn.UC_ERR_WRITE_UNMAPPED: "unmapped_memory_write",
        unicorn.UC_ERR_FETCH_UNMAPPED: "unmapped_code_fetch",
        unicorn.UC_ERR_READ_PROT: "protected_memory_read",
        unicorn.UC_ERR_WRITE_PROT: "protected_memory_write",
        unicorn.UC_ERR_FETCH_PROT: "protected_code_fetch",
        unicorn.UC_ERR_READ_UNALIGNED: "unaligned_memory_read",
        unicorn.UC_ERR_WRITE_UNALIGNED: "unaligned_memory_write",
        unicorn.UC_ERR_INSN_INVALID: "invalid_instruction",
        unicorn.UC_ERR_EXCEPTION: "cpu_exception",
    }

    _OS = {
        "linux": QL_OS.LINUX,
        "windows": QL_OS.WINDOWS,
        "macos": QL_OS.MACOS,
        "freebsd": QL_OS.FREEBSD,
    }
else:
    _UC_ERROR = {}
    _OS = {}


class QilingError(Exception):
    pass


class QilingEmulationError(QilingError):
    """模拟失败时携带结构化上下文，便于上层给出 {ok:false,...} 与复现信息。"""

    def __init__(self, message, error_type="emulation_failed", details=None):
        super().__init__(message)
        self.error_type = error_type
        self.details = details or {}

    def to_dict(self):
        return {
            "ok": False,
            "error": {
                "type": self.error_type,
                "message": str(self),
                "details": self.details,
            },
            "error_type": self.error_type,
            "message": str(self),
            "details": self.details,
        }


class QilingFacade:
    """基于 qiling code 模式的轻量模拟；不依赖 rootfs（占位当前目录）。"""

    def __init__(self, ida=None):
        # ida 可选：给了就能按名/地址从 IDB 取字节做模拟（emulate_at/create_from）。
        self._ida = ida

    def _require_qiling(self):
        if _IMPORT_ERROR is not None:
            raise QilingError(f"qiling dependencies unavailable: {_IMPORT_ERROR}")

    # ---- 构造 ----
    def create(self, code, opts=None):
        """创建并返回一个活的 Qiling 实例，供 JS 交互式驱动。

        code: hex 字符串或字节数组。
        opts: 可选 dict，{arch, os, verbose}；arch/os 缺省 x8664/linux。
        与 emulate_code 不同，这里不自动 run()，由 JS 决定何时/如何跑。
        """
        self._require_qiling()
        opts = opts or {}
        arch = opts.get("arch", "x8664")
        os = opts.get("os", "linux")
        verbose = opts.get("verbose", False)
        ql_arch, _, ql_os = self._resolve(arch, os)
        code = self._as_bytes(code)
        if not code:
            raise QilingError("empty code")
        return Qiling(code=code, archtype=ql_arch, ostype=ql_os, rootfs=".",
                      verbose=QL_VERBOSE.DEFAULT if verbose else QL_VERBOSE.OFF)

    def create_from(self, start_ea, size, opts=None):
        """从 IDB 的 start_ea 取 size 字节创建活的 Qiling 实例（需构造时传入 ida）。"""
        code = self._bytes_from_ida(start_ea, size)
        return self.create(code, opts)

    # ---- 一次性模拟 ----
    def emulate_code(self, code, count=0, arch="x8664", os="linux", regs=None):
        """模拟一段原始机器码，返回结束时的寄存器 dict。

        code:  机器码，hex 字符串（如 '4883ec28'）或字节数组。
        count: 最多执行的指令数，0 表示执行到自然结束。
        regs:  可选，模拟前预置的寄存器初值 {name: int}。
        """
        code = self._as_bytes(code)
        if not code:
            raise QilingError("empty code")
        ql_arch, regnames, ql_os = self._resolve(arch, os)
        ql = Qiling(code=code, archtype=ql_arch, ostype=ql_os,
                    rootfs=".", verbose=QL_VERBOSE.OFF)
        if regs:
            self.set_regs(ql, regs)
        kwargs = {"count": int(count)} if count and int(count) > 0 else {}
        self._run_guarded(ql, kwargs, code_size=len(code))
        return {name: ql.arch.regs.read(name) for name in regnames}

    def emulate_at(self, start_ea, size, count=0, arch="x8664", os="linux",
                   regs=None):
        """从 IDB 的 start_ea 取 size 字节机器码并模拟（需构造时传入 ida）。"""
        code = self._bytes_from_ida(start_ea, size)
        return self.emulate_code(code, count=count, arch=arch, os=os, regs=regs)

    def trace_code(self, code, count=0, arch="x8664", os="linux", regs=None,
                   orig_ea=None, trace_regs=True, trace_mem=True, timeout=0,
                   max_trace=0, max_mem_events=0):
        """模拟一段机器码并返回指令 trace。"""
        code = self._as_bytes(code)
        if not code:
            raise QilingError("empty code")
        ql_arch, regnames, ql_os = self._resolve(arch, os)
        ql = Qiling(code=code, archtype=ql_arch, ostype=ql_os,
                    rootfs=".", verbose=QL_VERBOSE.OFF)
        if regs:
            self.set_regs(ql, regs)
        return self.trace(ql, {
            "count": count,
            "timeout": int(float(timeout or 0) * 1_000_000) if timeout else None,
            "orig_ea": orig_ea,
            "regnames": regnames,
            "trace_regs": trace_regs,
            "trace_mem": trace_mem,
            "max_trace": int(max_trace or (int(count) if count and int(count) > 0 else 0)),
            "max_mem_events": max_mem_events,
        })

    def trace_at(self, start_ea, size, count=0, arch="x8664", os="linux",
                 regs=None, trace_regs=True, trace_mem=True, timeout=0,
                 max_trace=0, max_mem_events=0):
        """从 IDB 取字节模拟并返回归一到 IDA 地址的 trace。"""
        code = self._bytes_from_ida(start_ea, size)
        return self.trace_code(code, count=count, arch=arch, os=os, regs=regs,
                               orig_ea=int(start_ea), trace_regs=trace_regs,
                               trace_mem=trace_mem, timeout=timeout,
                               max_trace=max_trace, max_mem_events=max_mem_events)

    def strings_code(self, code, count=0, arch="x8664", os="linux", regs=None,
                     orig_ea=None, opts=None, timeout=0):
        """模拟机器码并只返回由内存写入产生的字符串候选。"""
        opts = dict(opts or {})
        trace = self.trace_code(code, count=count, arch=arch, os=os, regs=regs,
                                orig_ea=orig_ea, trace_regs=False, trace_mem=True,
                                timeout=timeout,
                                max_trace=opts.get("max_trace", 0),
                                max_mem_events=opts.get("max_mem_events", 0))
        if isinstance(trace, dict):
            opts.setdefault("truncated", trace.get("truncated", False))
            trace = trace.get("trace", [])
        return self.strings_from_trace(trace, opts)

    def strings_at(self, start_ea, size, count=0, arch="x8664", os="linux",
                   regs=None, opts=None, timeout=0):
        """从 IDB 取字节模拟并只返回字符串候选。"""
        code = self._bytes_from_ida(start_ea, size)
        return self.strings_code(code, count=count, arch=arch, os=os, regs=regs,
                                 orig_ea=int(start_ea), opts=opts, timeout=timeout)

    def scan_string_decryptors(self, opts=None):
        """按静态特征扫描疑似字符串解密函数。

        大库（如控制流平坦化的 .so）易卡死，故支持：
          - start_ea/end_ea：限定扫描地址范围（缺省=全库）；
          - timeout：秒，超时立即返回已扫到的部分结果（partial=True）；
          - max_func_size：跳过超大函数（默认 0=不限），避免个别巨型函数拖垮扫描。
        返回 {results, scanned, matched, total, timed_out, last_ea, range}，
        results 为已按分数排序的候选（受 limit 限制）；即便超时也带上下文（#1/#6）。
        """
        self._require_ida()
        opts = opts or {}
        min_score = int(opts.get("min_score", 3))
        limit = int(opts.get("limit", 200))
        timeout = float(opts.get("timeout", 0) or 0)
        max_func_size = int(opts.get("max_func_size", 0) or 0)
        start_ea = opts.get("start_ea")
        end_ea = opts.get("end_ea")
        if start_ea is not None and end_ea is not None:
            func_iter = self._ida.idautils.Functions(int(start_ea), int(end_ea))
        elif start_ea is not None:
            func_iter = self._ida.idautils.Functions(int(start_ea))
        else:
            func_iter = self._ida.idautils.Functions()
        deadline = (time.monotonic() + timeout) if timeout > 0 else None
        out = []
        scanned = 0
        last_ea = None
        timed_out = False
        for start in func_iter:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            func = self._ida.idaapi.get_func(start)
            if func is None:
                continue
            scanned += 1
            last_ea = int(func.start_ea)
            if max_func_size and int(func.end_ea - func.start_ea) > max_func_size:
                continue
            stats = self._function_stats(func)
            score = 0
            reasons = []
            if stats["xor"] or stats["rol"] or stats["ror"]:
                score += stats["xor"] + stats["rol"] + stats["ror"]
                reasons.append("bitwise_transform")
            if stats["mem_write"]:
                score += min(stats["mem_write"], 4)
                reasons.append("memory_writes")
            if stats["loops"]:
                score += 2
                reasons.append("loop")
            if stats["small_immediates"] >= 2:
                score += 1
                reasons.append("byte_constants")
            if score >= min_score:
                out.append({
                    "ea": int(func.start_ea),
                    "end_ea": int(func.end_ea),
                    "name": self._ida.ida_funcs.get_func_name(func.start_ea),
                    "size": int(func.end_ea - func.start_ea),
                    "score": int(score),
                    "reasons": reasons,
                    "stats": stats,
                })
        out.sort(key=lambda x: (-x["score"], x["size"]))
        return {
            "results": out[:limit],
            "scanned": scanned,
            "matched": len(out),
            "total": int(self._ida.ida_funcs.get_func_qty()),
            "timed_out": timed_out,
            "last_ea": last_ea,
            "range": {"start_ea": None if start_ea is None else int(start_ea),
                      "end_ea": None if end_ea is None else int(end_ea)},
        }

    def scan_string_call_sites(self, decryptors, opts=None):
        """扫描候选解密函数的调用点，并提取附近立即数参数线索。"""
        self._require_ida()
        opts = opts or {}
        backtrack = int(opts.get("backtrack", 8))
        max_sites = int(opts.get("limit", 1000))
        targets = []
        for x in list(decryptors or []):
            if isinstance(x, dict):
                targets.append(int(x.get("ea")))
            else:
                targets.append(int(x))
        sites = []
        for target in targets:
            for xref in self._ida.idautils.XrefsTo(target):
                ea = int(xref.frm)
                func = self._ida.idaapi.get_func(ea)
                sites.append({
                    "call_ea": ea,
                    "target_ea": target,
                    "function_ea": None if func is None else int(func.start_ea),
                    "function_name": "" if func is None else self._ida.ida_funcs.get_func_name(func.start_ea),
                    "args": self._nearby_immediates(ea, backtrack),
                })
                if len(sites) >= max_sites:
                    return sites
        return sites

    def scan_string_decrypt_chains(self, opts=None):
        """识别 wrapper→(mode 分发)→算法 的字符串解密调用链。

        单函数打分（scan_string_decryptors）识别不出 wrapper 转发链，故这里：
          1. 先定位真正的算法函数：同时含 位运算(xor/rol/ror) + 循环 + 内存写入；
          2. 从算法函数沿调用者向上爬（只穿过“小函数”即 wrapper，遇到大函数即视为使用点/入口停止），
             还原 sub_B8E8→sub_B81C→sub_B9024→sub_B9374 这类转发链；
          3. 汇总每层调用点的立即数参数（mode/固定参数线索）与沿链引用的全局数据地址
             （key table / 密文来源候选，如 unk_194538）。
        输出仅是静态线索；解出明文请对入口函数用 emulate_function。
        opts: {min_score=4, max_depth=3, wrapper_max_size=0x80, limit=100,
               backtrack=8, data_ref_limit=32, timeout(秒), algos:[已知算法函数,跳过自动定位]}。
        """
        self._require_ida()
        opts = opts or {}
        min_score = int(opts.get("min_score", 4))
        max_depth = int(opts.get("max_depth", 3))
        wrapper_max_size = int(opts.get("wrapper_max_size", 0x80))
        limit = int(opts.get("limit", 100))
        backtrack = int(opts.get("backtrack", 8))
        data_ref_limit = int(opts.get("data_ref_limit", 32))
        timeout = float(opts.get("timeout", 0) or 0)
        deadline = (time.monotonic() + timeout) if timeout > 0 else None

        algos = []
        provided = opts.get("algos")
        if provided:
            for x in list(provided):
                algos.append(int(x.get("ea") if isinstance(x, dict) else x))
        else:
            for start in self._ida.idautils.Functions():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                func = self._ida.idaapi.get_func(start)
                if func is None:
                    continue
                stats = self._function_stats(func)
                bitwise = stats["xor"] + stats["rol"] + stats["ror"]
                if bitwise > 0 and stats["loops"] > 0 and stats["mem_write"] > 0:
                    score = bitwise + min(stats["mem_write"], 4) + 2
                    if score >= min_score:
                        algos.append(int(func.start_ea))

        chains = []
        timed_out = False
        for algo_ea in algos:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            chains.append(self._trace_wrapper_chain(
                algo_ea, max_depth, wrapper_max_size, backtrack, data_ref_limit))
            if len(chains) >= limit:
                break
        return {"chains": chains, "algo_count": len(algos), "timed_out": timed_out}

    def batch_strings_at(self, jobs, opts=None):
        """批量模拟多个函数/代码范围并聚合字符串候选。"""
        opts = opts or {}
        default_arch = opts.get("arch", "x8664")
        default_os = opts.get("os", "linux")
        default_count = int(opts.get("count", 0))
        default_size = opts.get("size")
        results = []
        errors = 0
        max_errors = int(opts.get("max_errors", 0) or 0)
        total_timeout = float(opts.get("total_timeout", 0) or 0)
        per_item_timeout = float(opts.get("per_item_timeout", 0) or 0)
        deadline = time.monotonic() + total_timeout if total_timeout > 0 else None
        timed_out = False
        for job in list(jobs or []):
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            start = int(job.get("start_ea", job.get("ea")))
            size = job.get("size", default_size)
            if size is None:
                func = self._ida.idaapi.get_func(start) if self._ida is not None else None
                if func is None:
                    raise QilingError(f"size is required for {start}")
                start = int(func.start_ea)
                size = int(func.end_ea - func.start_ea)
            try:
                item_opts = dict(opts.get("strings", {}))
                item_opts.update(job.get("strings", {}))
                item_count = int(job.get("count", default_count))
                if per_item_timeout > 0 and item_count <= 0:
                    item_count = 1_000_000
                strings = self.strings_at(
                    start,
                    int(size),
                    count=item_count,
                    arch=job.get("arch", default_arch),
                    os=job.get("os", default_os),
                    regs=job.get("regs"),
                    opts=item_opts,
                    timeout=per_item_timeout,
                )
                results.append({"start_ea": start, "size": int(size), "strings": strings, "error": None})
            except QilingEmulationError as exc:
                errors += 1
                results.append({"start_ea": start, "size": int(size), "strings": [], "error": exc.to_dict()})
            except Exception as exc:
                errors += 1
                results.append({"start_ea": start, "size": int(size), "strings": [],
                                "error": {"ok": False, "error_type": "error", "message": str(exc), "details": {}}})
            if max_errors and errors >= max_errors:
                break
        return {"results": results, "timed_out": timed_out, "errors": errors, "truncated": bool(timed_out or (max_errors and errors >= max_errors))}

    def emulate_function(self, address, args=None, opts=None):
        """面向 IDA 函数的模拟：自动映射当前 IDB 各段到真实地址，按调用约定设置
        参数寄存器/返回哨兵，从函数入口整段执行到返回，回收寄存器/内存写入/字符串。

        与 shellcode 模式（emulate_at）的区别：这里把 IDB 的 LOAD 段（代码+数据，如
        全局 key table）按原地址映射进内存，因此：
          - 全局数据引用（如 unk_194538）可直接读到；
          - 对已映射段内的内部 call（如 sub_B9024/sub_B9374）能自然续跑；
          - 模拟地址即 IDA 地址，无需换算。
        对导入/PLT 等映射范围外的外部调用仍会 fault，返回结构化 unmapped_* 错误。

        args: 参数列表。每项可为：
          - int：作为标量直接写入参数寄存器；
          - {"value": int} / {"ptr": int}：标量/已知指针；
          - {"bytes": "hex"} / {"str": "文本"}：自动分配缓冲区写入并把指针传入（指针参数）。
        opts: {arch(缺省从 IDB 推断), os='linux', count(指令上限,默认 1e6,0=不限),
               timeout(秒), segments(仅映射指定段名), max_writes(返回写入上限),
               strings(传给字符串提取的 {min_len,max_gap})}。
        """
        self._require_ida()
        opts = opts or {}
        arch = str(opts.get("arch") or self._infer_arch() or "").lower()
        arch = arch.replace("_", "").replace("-", "")
        if arch not in _ARG_REGS and arch != "x86":
            raise QilingError(
                f"无法确定 arch（推断失败），请在 opts.arch 指定 x86/x8664/arm/arm64/mips；得到 {arch!r}")
        os_ = opts.get("os", "linux")
        func = self._ida.idaapi.get_func(int(address))
        if func is None:
            raise QilingError(f"no function at {address}")
        start, end = int(func.start_ea), int(func.end_ea)
        name = self._ida.ida_funcs.get_func_name(start)

        ql_arch, regnames, ql_os = self._resolve(arch, os_)
        ql = Qiling(code=b"\x90\x90\x90\x90", archtype=ql_arch, ostype=ql_os,
                    rootfs=".", verbose=QL_VERBOSE.OFF)
        mapped = self._map_idb_segments(ql, opts)
        ret_addr = int(ql.mem.map_anywhere(0x1000, perms=self._perms("rwx")))
        prepared = self._set_args(ql, arch, args, ret_addr)

        writes = []
        state = {"insns": 0}

        def on_code(_ql, addr, size):
            state["insns"] += 1

        def on_mem_write(*a):
            addr, size, value = (a[2], a[3], a[4])
            writes.append({"address": int(addr), "ida_ea": int(addr),
                           "size": int(size), "value": int(value)})

        ql.hook_code(on_code)
        ql.arch.uc.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)

        count = int(opts.get("count", 1_000_000))
        timeout = float(opts.get("timeout", 0) or 0)
        emu_kwargs = {}
        if count > 0:
            emu_kwargs["count"] = count
        if timeout > 0:
            emu_kwargs["timeout"] = int(timeout * 1_000_000)
        stopped = "returned"
        try:
            ql.arch.uc.emu_start(start, ret_addr, **emu_kwargs)
        except Exception as exc:  # noqa: BLE001 — 归一为结构化模拟错误（带复现上下文）
            err = self._emu_error(ql, exc, None, end - start, emu_kwargs)
            err.details["function"] = {"start": start, "end": end, "name": name}
            err.details["mapped_segments"] = mapped
            err.details["insns"] = state["insns"]
            raise err from exc
        if count > 0 and state["insns"] >= count:
            stopped = "instruction_limit"

        ret_reg = _RET_REG.get(arch)
        max_writes = int(opts.get("max_writes", 2000))
        strings = self.strings_from_trace(
            [{"ida_ea": start, "address": start, "mem_writes": writes}],
            opts.get("strings"))
        return {
            "ok": True,
            "arch": arch,
            "function": {"start": start, "end": end, "name": name},
            "args": prepared,
            "return": {"reg": ret_reg,
                       "value": int(ql.arch.regs.read(ret_reg)) if ret_reg else None},
            "regs": {n: int(ql.arch.regs.read(n)) for n in regnames},
            "instructions": state["insns"],
            "stopped": stopped,
            "strings": strings,
            "mem_writes": writes[:max_writes],
            "mem_writes_truncated": len(writes) > max_writes,
            "mapped_segments": mapped,
        }

    def map_idb_segments(self, ql, opts=None):
        """按原地址把 IDB 段映射进模拟空间（公开封装，供 Lab 的交互模拟使用）。"""
        return self._map_idb_segments(ql, opts or {})

    # ---- 活实例：执行 ----
    def run(self, ql, opts=None):
        """驱动活实例执行，返回结束寄存器 dump。

        opts: 可选 dict，{begin, end, timeout, count}——因 JS 无法给 Python 传
        kwargs，这里把对象翻译成 ql.run(**kwargs)。
        """
        opts = opts or {}
        kwargs = {}
        for k in ("begin", "end", "timeout", "count"):
            v = opts.get(k)
            if v is not None:
                kwargs[k] = int(v)
        self._run_guarded(ql, kwargs)
        return self.regs(ql)

    def trace(self, ql, opts=None):
        """驱动活实例执行并返回指令/内存访问 trace。"""
        opts = opts or {}
        regnames = list(opts.get("regnames") or self._regnames(ql))
        orig_ea = opts.get("orig_ea")
        trace_regs = bool(opts.get("trace_regs", opts.get("include_regs", True)))
        trace_mem = bool(opts.get("trace_mem", opts.get("include_mem", True)))
        max_trace = int(opts.get("max_trace", 0) or 0)
        max_mem_events = int(opts.get("max_mem_events", 0) or 0)
        records = []
        current = {"idx": -1}
        limits = {"trace_truncated": False, "mem_truncated": False, "mem_events": 0}

        def norm(addr):
            addr = int(addr)
            if orig_ea is None:
                return addr
            return self.to_ida(ql, addr, int(orig_ea))

        def on_code(_ql, addr, size):
            if max_trace and len(records) >= max_trace:
                limits["trace_truncated"] = True
                return
            code = bytes(_ql.mem.read(int(addr), int(size)))
            insns = list(_ql.arch.disassembler.disasm(code, int(addr)))
            insn = insns[0] if insns else None
            item = {
                "index": len(records),
                "address": int(addr),
                "ida_ea": norm(addr),
                "size": int(size),
                "bytes": code.hex(),
                "mnemonic": "" if insn is None else insn.mnemonic,
                "op_str": "" if insn is None else insn.op_str,
            }
            if trace_regs:
                item["regs"] = {name: _ql.arch.regs.read(name) for name in regnames}
            if trace_mem:
                item["mem_reads"] = []
                item["mem_writes"] = []
            records.append(item)
            current["idx"] = len(records) - 1

        def on_mem_read(*args):
            if len(args) == 6:
                _uc, access, addr, size, value, _user_data = args
            else:
                _ql, access, addr, size, value = args
            if current["idx"] >= 0 and trace_mem:
                if max_mem_events and limits["mem_events"] >= max_mem_events:
                    limits["mem_truncated"] = True
                    return
                value = int.from_bytes(bytes(ql.mem.read(int(addr), int(size))), "little")
                records[current["idx"]]["mem_reads"].append({
                    "address": int(addr),
                    "ida_ea": norm(addr),
                    "size": int(size),
                    "value": int(value),
                })
                limits["mem_events"] += 1

        def on_mem_write(*args):
            if len(args) == 6:
                _uc, access, addr, size, value, _user_data = args
            else:
                _ql, access, addr, size, value = args
            if current["idx"] >= 0 and trace_mem:
                if max_mem_events and limits["mem_events"] >= max_mem_events:
                    limits["mem_truncated"] = True
                    return
                records[current["idx"]]["mem_writes"].append({
                    "address": int(addr),
                    "ida_ea": norm(addr),
                    "size": int(size),
                    "value": int(value),
                })
                limits["mem_events"] += 1

        ql.hook_code(on_code)
        if trace_mem:
            ql.arch.uc.hook_add(UC_HOOK_MEM_READ, on_mem_read)
            ql.arch.uc.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)
        run_opts = {k: opts[k] for k in ("begin", "end", "timeout", "count")
                    if opts.get(k) is not None}
        self.run(ql, run_opts)
        truncated = bool(limits["trace_truncated"] or limits["mem_truncated"])
        if opts.get("strings"):
            return {"trace": records, "strings": self.strings_from_trace(records, opts.get("strings")),
                    "truncated": truncated, "trace_truncated": limits["trace_truncated"],
                    "mem_truncated": limits["mem_truncated"]}
        if truncated:
            return {"trace": records, "truncated": True,
                    "trace_truncated": limits["trace_truncated"],
                    "mem_truncated": limits["mem_truncated"]}
        return records

    def _string_opts(self, opts):
        if opts is None:
            return {}
        if opts is True:
            return {"min_len": 4}
        if opts is False:
            return {}
        if not isinstance(opts, dict):
            raise QilingError(f"strings must be an object, got {type(opts).__name__}")
        return opts

    def strings_from_trace(self, trace, opts=None):
        """从 trace 的连续内存写入中提取可读 ASCII 字符串候选。"""
        opts = self._string_opts(opts)
        min_len = int(opts.get("min_len", 4))
        max_gap = int(opts.get("max_gap", 1))
        max_trace_items = int(opts.get("max_trace_items", 10000) or 0)
        max_writes = int(opts.get("max_writes", 20000) or 0)
        max_candidates = int(opts.get("max_candidates", 200) or 0)
        if isinstance(trace, dict):
            trace = trace.get("trace", [])
        writes = []
        truncated = bool(opts.get("truncated", False))
        for item_index, item in enumerate(trace):
            if max_trace_items and item_index >= max_trace_items:
                truncated = True
                break
            for mem in item.get("mem_writes", []):
                if max_writes and len(writes) >= max_writes:
                    truncated = True
                    break
                size = int(mem.get("size", 0))
                value = int(mem.get("value", 0))
                for offset, b in enumerate(value.to_bytes(max(size, 1), "little")[:size]):
                    writes.append({
                        "address": int(mem["address"]) + offset,
                        "ida_ea": int(mem["ida_ea"]) + offset,
                        "byte": b,
                        "writer_ea": int(item.get("ida_ea", item.get("address", 0))),
                    })
        writes.sort(key=lambda x: x["address"])
        runs = []
        current = []
        prev_addr = None
        for w in writes:
            if not self._is_printable(w["byte"]):
                if current:
                    runs.append(current)
                    current = []
                prev_addr = None
                continue
            if prev_addr is None or 0 < w["address"] - prev_addr <= max_gap:
                current.append(w)
            else:
                runs.append(current)
                current = [w]
            prev_addr = w["address"]
        if current:
            runs.append(current)
        out = []
        for run in runs:
            if len(run) >= min_len:
                text = bytes(x["byte"] for x in run).decode("ascii")
                out.append({
                    "address": run[0]["address"],
                    "ida_ea": run[0]["ida_ea"],
                    "length": len(run),
                    "text": text,
                    "hex": bytes(x["byte"] for x in run).hex(),
                    "writer_ea": run[0]["writer_ea"],
                })
                if max_candidates and len(out) >= max_candidates:
                    truncated = True
                    break
        if opts.get("return_meta"):
            return {"strings": out, "truncated": truncated, "write_count": len(writes)}
        return out

    # ---- 活实例：寄存器 ----
    def regs(self, ql):
        """dump 该实例架构下的主要通用寄存器为 dict。"""
        return {name: ql.arch.regs.read(name) for name in self._regnames(ql)}

    def get_reg(self, ql, name):
        return ql.arch.regs.read(str(name))

    def set_reg(self, ql, name, value):
        ql.arch.regs.write(str(name), int(value))

    def set_regs(self, ql, values):
        """按 {name: int} 批量写寄存器。"""
        for name, value in dict(values).items():
            ql.arch.regs.write(str(name), int(value))

    # ---- 活实例：内存 ----
    def mem_read(self, ql, addr, size):
        """读内存，返回 bytes（经 bridge 转 hex）。等价于 ql.mem.read。"""
        return bytes(ql.mem.read(int(addr), int(size)))

    def mem_write(self, ql, addr, data):
        """写内存。JS 无原生 bytes，故 data 收 hex 字符串（'deadbeef'）或字节整数
        数组（[0xde,0xad,...]）；ql 由 bridge 自动解包。
        """
        ql.mem.write(int(addr), self._as_bytes(data))

    def read_ptr(self, ql, addr, bits=64, endian="little"):
        """按指定位宽读取指针/整数。"""
        size = int(bits) // 8
        if size <= 0:
            raise QilingError(f"invalid pointer bits: {bits}")
        return int.from_bytes(bytes(ql.mem.read(int(addr), size)), str(endian))

    def write_ptr(self, ql, addr, value, bits=64, endian="little"):
        """按指定位宽写入指针/整数。"""
        size = int(bits) // 8
        if size <= 0:
            raise QilingError(f"invalid pointer bits: {bits}")
        ql.mem.write(int(addr), int(value).to_bytes(size, str(endian), signed=False))

    def read_cstring(self, ql, addr, max_len=4096):
        """读取以 NUL 结尾的字符串。"""
        addr = int(addr)
        out = bytearray()
        for i in range(int(max_len)):
            b = bytes(ql.mem.read(addr + i, 1))[0]
            if b == 0:
                break
            out.append(b)
        return out.decode("utf-8", errors="replace")

    def write_cstring(self, ql, addr, text):
        """写入 UTF-8 NUL 结尾字符串。"""
        ql.mem.write(int(addr), str(text).encode("utf-8") + b"\x00")

    def hook_address(self, ql, addr, callback):
        """在指定地址触发 JS/Python 回调，回调签名为 callback(ql, addr, size)。"""
        target = int(addr)

        def on_code(_uc, current, size, _user_data):
            if int(current) == target:
                callback(ql, int(current), int(size))

        return ql.arch.uc.hook_add(UC_HOOK_CODE, on_code, begin=target, end=target + 1)

    def map_stub_region(self, ql, base, size, arch="arm64"):
        """映射 fake stub 区域，并填充架构对应的返回/断点占位指令。"""
        base = int(base)
        size = int(size)
        self._map_missing(ql, base, size, perms="rwx")
        arch = str(arch).lower().replace("_", "").replace("-", "")
        pattern = b"\xc0\x03\x5f\xd6" if arch == "arm64" else b"\xcc"
        ql.mem.write(base, (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size])
        return {"base": base, "size": size, "arch": arch}

    def map_mem(self, ql, addr, size, perms=None):
        """在固定地址映射一段内存（perms 为 RWX 位，默认 RW）。"""
        ql.mem.map(int(addr), int(size), perms=self._perms(perms))

    def alloc(self, ql, size, perms=None):
        """任意位置分配一段内存，返回起始地址。"""
        return ql.mem.map_anywhere(int(size), perms=self._perms(perms))

    def _perms(self, perms=None):
        if perms is None:
            return UC_PROT_READ | UC_PROT_WRITE
        if isinstance(perms, int):
            return int(perms)
        if isinstance(perms, dict):
            value = 0
            if perms.get("read", perms.get("r", False)):
                value |= UC_PROT_READ
            if perms.get("write", perms.get("w", False)):
                value |= UC_PROT_WRITE
            if perms.get("execute", perms.get("exec", perms.get("x", False))):
                value |= UC_PROT_EXEC
            return value or (UC_PROT_READ | UC_PROT_WRITE)
        text = str(perms).lower()
        value = 0
        if "r" in text:
            value |= UC_PROT_READ
        if "w" in text:
            value |= UC_PROT_WRITE
        if "x" in text or "exec" in text:
            value |= UC_PROT_EXEC
        return value or (UC_PROT_READ | UC_PROT_WRITE)

    # ---- 活实例：栈 ----
    def stack_push(self, ql, value):
        """压栈并返回压入后的栈指针。"""
        return ql.arch.stack_push(int(value))

    def stack_pop(self, ql):
        """弹栈并返回弹出的值。"""
        return ql.arch.stack_pop()

    # ---- 活实例：IDA<->qiling 地址映射 ----
    # shellcode 模式下代码被 qiling 载到固定基址（code_base），而 IDA 里是真实地址。
    # 若用 create_from(orig_ea, ...) 从 IDB 取来的代码，模拟出的地址可经此换算回 IDA：
    #   ida_ea = ql_ea - code_base + orig_ea
    def code_base(self, ql):
        """该实例里 shellcode 的加载基址（模拟地址空间的入口）。"""
        return ql.os.entry_point

    def to_ida(self, ql, ql_ea, orig_ea):
        """把模拟地址 ql_ea 换算回 IDA 地址（orig_ea 为 create_from 时的原始地址）。"""
        return int(ql_ea) - int(ql.os.entry_point) + int(orig_ea)

    def to_ql(self, ql, ida_ea, orig_ea):
        """把 IDA 地址换算成模拟地址。"""
        return int(ida_ea) - int(orig_ea) + int(ql.os.entry_point)

    # ---- 活实例：反汇编 ----
    def disasm(self, ql, addr, size):
        """反汇编 [addr, addr+size) 的机器码，返回指令 dict 列表：
        {address, mnemonic, op_str, size, bytes(hex)}。
        """
        addr = int(addr)
        code = bytes(ql.mem.read(addr, int(size)))
        out = []
        for insn in ql.arch.disassembler.disasm(code, addr):
            out.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "bytes": bytes(insn.bytes).hex(),
            })
        return out

    # ---- 能力自检 / 可行性评估 ----
    def capabilities(self):
        """返回本门面的静态能力矩阵：模式、支持的 arch/os、限制、是否绑定 IDA。

        本门面是 qiling code(shellcode)模式：只喂原始机器码字节、rootfs 用当前目录
        占位，不加载可执行镜像/动态库、不解析导入、无 OS syscall 语义。据此可提前判断
        某段代码是否适合直接模拟，或需改走完整 rootfs 加载 / 先 hook 外部调用。
        """
        return {
            "mode": "code",
            "rootfs": ".",
            "arches": sorted(set(_ARCH.keys())),
            "oses": sorted(_OS.keys()),
            "ida_bound": self._ida is not None,
            "ida_methods": ["emulate_at", "trace_at", "strings_at", "create_from",
                            "batch_strings_at", "scan_string_decryptors",
                            "scan_string_call_sites", "scan_string_decrypt_chains",
                            "plan", "emulate_function"],
            "limitations": [
                "shellcode/code 模式：不加载镜像与动态库，无导入符号解析",
                "无 OS 运行库/syscall 语义：调用外部 API 或触发 syscall 会失败或返回垃圾值",
                "只映射喂入的机器码字节：对代码范围外的内存/数据访问未映射",
                "无重定位：绝对/rip 相对地址引用保持原值，可能落在未映射区",
                "emulate_function 例外：会按原地址映射 IDB 各段（代码+数据），"
                "支持全局数据引用与段内 call，但导入/PLT 等外部调用仍会 fault",
            ],
        }

    def plan(self, start_ea, size=None, opts=None):
        """静态评估把某函数/代码范围放进 shellcode 模拟的可行性与风险（需绑定 IDA）。

        逐指令扫描，标记会破坏 code 模式模拟的因素：外部调用（导入/范围外目标）、
        syscall/中断、间接调用/跳转、范围外内存引用。返回 {summary, risks}；
        summary.emulatable 为 True 表示无 high 级风险，可直接 emulate_at/trace_at；
        否则建议先 hook 外部调用/换完整 rootfs 加载。
        """
        self._require_ida()
        opts = opts or {}
        limit = int(opts.get("limit", 500))
        start = int(start_ea)
        if size is not None:
            end = start + int(size)
        else:
            func = self._ida.idaapi.get_func(start)
            if func is None:
                raise QilingError(f"size is required for {start} (no function there)")
            start, end = int(func.start_ea), int(func.end_ea)
        risks = []
        insns = 0
        for ea in self._iter_range(start, end):
            insns += 1
            mnem = (self._ida.ida_ua.print_insn_mnem(ea) or "").lower()
            if mnem in {"syscall", "sysenter", "svc"} or mnem == "int":
                risks.append({"ea": ea, "kind": "syscall", "level": "high",
                              "reason": f"{mnem} 需 OS syscall 语义（code 模式不支持）"})
                continue
            r = None
            if mnem == "call":
                r = self._call_risk(ea, start, end)
            elif mnem.startswith("j"):
                r = self._jmp_risk(ea, start, end)
            if r is None:
                r = self._data_risk(ea, start, end)
            if r is not None:
                risks.append(r)
        levels = [r["level"] for r in risks]
        high, medium = levels.count("high"), levels.count("medium")
        if high:
            rec = "含 high 风险，直接 shellcode 模拟会失败；先 hook 外部调用或改完整 rootfs 加载"
        elif medium:
            rec = "无 high 风险但有范围外引用；可模拟，注意未映射内存需预置或缩小 count"
        else:
            rec = "适合直接 emulate_at/trace_at 模拟"
        return {
            "summary": {
                "range": {"start_ea": start, "end_ea": end, "size": end - start},
                "insns": insns,
                "high": high,
                "medium": medium,
                "emulatable": high == 0,
                "recommendation": rec,
            },
            "risks": risks[:limit],
        }

    def _iter_range(self, start, end):
        ea = int(start)
        while ea < int(end) and ea != self._ida.idaapi.BADADDR:
            yield ea
            ea = int(self._ida.ida_bytes.next_head(ea, int(end)))

    def _branch_target(self, ea):
        # o_mem=2 / o_near=7：直接目标可静态解析；否则（寄存器/跳表）不可解析。
        t = self._ida.idc.get_operand_type(ea, 0)
        if t in (2, 7):
            return int(self._ida.idc.get_operand_value(ea, 0))
        return None

    def _call_risk(self, ea, start, end):
        tgt = self._branch_target(ea)
        if tgt is None:
            return {"ea": int(ea), "kind": "indirect_call", "level": "high",
                    "reason": "间接调用目标静态不可解析（导入/寄存器/跳表）"}
        if not (start <= tgt < end):
            return {"ea": int(ea), "kind": "external_call", "level": "high",
                    "target": tgt, "name": self._name_of(tgt),
                    "reason": "调用范围外目标（导入/库函数未映射）"}
        return None

    def _jmp_risk(self, ea, start, end):
        tgt = self._branch_target(ea)
        if tgt is None:
            return {"ea": int(ea), "kind": "indirect_jump", "level": "high",
                    "reason": "间接/跳表跳转目标静态不可解析"}
        if not (start <= tgt < end):
            return {"ea": int(ea), "kind": "external_jump", "level": "medium",
                    "target": tgt, "reason": "跳出模拟范围（尾调用/跨函数）"}
        return None

    def _data_risk(self, ea, start, end):
        for n in range(2):
            if self._ida.idc.get_operand_type(ea, n) == 2:
                addr = int(self._ida.idc.get_operand_value(ea, n))
                if not (start <= addr < end):
                    return {"ea": int(ea), "kind": "unmapped_data", "level": "medium",
                            "target": addr, "name": self._name_of(addr),
                            "reason": "绝对/rip 相对内存引用落在模拟范围外（未映射）"}
        return None

    def _name_of(self, ea):
        return self._ida.ida_name.get_name(int(ea)) or ""

    # ---- 内部工具 ----
    def _resolve(self, arch, os):
        arch = str(arch).lower().replace("_", "").replace("-", "")
        if arch not in _ARCH:
            raise QilingError(f"unsupported arch: {arch}")
        os = str(os).lower()
        if os not in _OS:
            raise QilingError(f"unsupported os: {os}")
        ql_arch, regnames = _ARCH[arch]
        return ql_arch, regnames, _OS[os]

    def _regnames(self, ql):
        name = ql.arch.type.name.lower()
        if name in _ARCH:
            return _ARCH[name][1]
        return list(ql.arch.regs.register_mapping.keys())

    @staticmethod
    def _is_printable(b):
        return b in (9, 10, 13) or 32 <= int(b) <= 126

    @staticmethod
    def _as_bytes(data):
        """把 hex 字符串或字节整数数组（JS 侧两种表示）统一转成 bytes。"""
        if isinstance(data, str):
            return bytes.fromhex(data)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        return bytes(bytearray(int(x) & 0xFF for x in data))

    def _bytes_from_ida(self, start_ea, size):
        self._require_ida()
        code = self._ida.idaapi.get_bytes(int(start_ea), int(size))
        if not code:
            raise QilingError(f"no bytes at {start_ea}")
        return code

    def _require_ida(self):
        if self._ida is None:
            raise QilingError("this operation requires an IDA instance")

    def _run_guarded(self, ql, kwargs, orig_ea=None, code_size=None):
        """驱动 ql.run，把底层 unicorn/qiling 异常转成带复现上下文的结构化错误。"""
        try:
            ql.run(**kwargs)
        except QilingEmulationError:
            raise
        except Exception as exc:  # noqa: BLE001 — 统一归一为结构化模拟错误
            raise self._emu_error(ql, exc, orig_ea, code_size, kwargs) from exc

    def _emu_error(self, ql, exc, orig_ea, code_size, kwargs):
        """构造 QilingEmulationError：分类错误并附上可复现上下文（#6）。"""
        error_type = "emulation_failed"
        if isinstance(exc, UcError):
            code = getattr(exc, "errno", None)
            error_type = _UC_ERROR.get(code, "emulation_failed")
        arch = self._ql_arch_name(ql)
        details = {
            "arch": arch,
            "os": self._ql_os_name(ql),
            "code_size": None if code_size is None else int(code_size),
            "run_kwargs": {k: int(v) for k, v in (kwargs or {}).items()},
            "exception": f"{type(exc).__name__}: {exc}",
            "traceback": self._short_tb(),
        }
        try:
            details["code_base"] = int(ql.os.entry_point)
        except Exception:  # noqa: BLE001
            pass
        pc = self._ql_pc(ql, arch)
        if pc is not None:
            details["pc"] = pc
            if orig_ea is not None:
                try:
                    details["ida_ea"] = self.to_ida(ql, pc, int(orig_ea))
                except Exception:  # noqa: BLE001
                    pass
            details["last_insn"] = self._disasm_one(ql, pc)
        if self._ida is not None:
            details["binary_path"] = self._ida_input_path()
            details["imagebase"] = self._ida_imagebase()
        msg = f"{error_type}: {type(exc).__name__}: {exc}"
        return QilingEmulationError(msg, error_type=error_type, details=details)

    @staticmethod
    def _ql_arch_name(ql):
        try:
            return ql.arch.type.name.lower()
        except Exception:  # noqa: BLE001
            return "unknown"

    @staticmethod
    def _ql_os_name(ql):
        try:
            return ql.os.type.name.lower()
        except Exception:  # noqa: BLE001
            return "unknown"

    @staticmethod
    def _ql_pc(ql, arch):
        name = _PC.get(arch)
        if name is None:
            return None
        try:
            return int(ql.arch.regs.read(name))
        except Exception:  # noqa: BLE001
            return None

    def _disasm_one(self, ql, addr):
        try:
            code = bytes(ql.mem.read(int(addr), 8))
            insns = list(ql.arch.disassembler.disasm(code, int(addr)))
            if insns:
                insn = insns[0]
                return {"address": int(insn.address), "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str, "bytes": bytes(insn.bytes).hex()}
        except Exception:  # noqa: BLE001 — 出错地址可能未映射，读不出属正常
            pass
        return None

    @staticmethod
    def _short_tb(limit=5):
        return "".join(traceback.format_exc().splitlines(keepends=True)[-limit:])

    def _ida_input_path(self):
        try:
            return self._ida.idc.get_input_file_path()
        except Exception:  # noqa: BLE001
            return None

    def _ida_imagebase(self):
        try:
            return int(self._ida.idaapi.get_imagebase())
        except Exception:  # noqa: BLE001
            return None

    def _infer_arch(self):
        """从 IDB 推断 arch 名（emulate_function 用）；失败返回 None，由调用方要求显式指定。"""
        proc = is64 = None
        try:  # IDA 7.6+/9：get_inf_structure 已移除，用 ida_ida 的取值函数
            proc = str(self._ida.ida_ida.inf_get_procname()).lower()
            is64 = bool(self._ida.ida_ida.inf_is_64bit())
        except Exception:  # noqa: BLE001 — 退回旧 API
            try:
                info = self._ida.idaapi.get_inf_structure()
                proc = str(info.procname).lower()
                is64 = bool(info.is_64bit())
            except Exception:  # noqa: BLE001
                return None
        if "arm" in proc or "aarch" in proc:
            return "arm64" if is64 else "arm"
        if "mips" in proc:
            return "mips"
        if "metapc" in proc or "x86" in proc or "pc" in proc:
            return "x8664" if is64 else "x86"
        return None

    def _map_idb_segments(self, ql, opts):
        """把当前 IDB 各段按原地址页对齐映射进 ql 内存并写入字节（跳过已映射页）。"""
        opts = opts or {}
        include = opts.get("segments")
        seg = self._ida.ida_segment
        mapped = []
        for i in range(int(seg.get_segm_qty())):
            s = seg.getnseg(i)
            if s is None:
                continue
            sname = seg.get_segm_name(s)
            if include and sname not in include:
                continue
            start, end = int(s.start_ea), int(s.end_ea)
            if end <= start:
                continue
            page_start = start & ~0xFFF
            page_end = (end + 0xFFF) & ~0xFFF
            self._map_missing(ql, page_start, page_end - page_start, perms=self._segment_perms(s))
            data = self._ida.idaapi.get_bytes(start, end - start)
            if data:
                try:
                    ql.mem.write(start, data)
                except Exception:  # noqa: BLE001 — 与 ql 内部区重叠时跳过写入
                    pass
            mapped.append({"name": sname, "start": start, "end": end,
                           "size": end - start})
        return mapped

    def _map_missing(self, ql, base, size, perms=None):
        """把 [base, base+size) 内尚未映射的页按最大连续段一次性映射。"""
        page = 0x1000
        run_start = None
        addr = int(base)
        stop = int(base) + int(size)
        flags = self._perms(perms)
        while addr <= stop:
            free = addr < stop and not ql.mem.is_mapped(addr, page)
            if free:
                if run_start is None:
                    run_start = addr
            elif run_start is not None:
                try:
                    ql.mem.map(run_start, addr - run_start, perms=flags)
                except Exception:  # noqa: BLE001
                    pass
                run_start = None
            addr += page

    def _segment_perms(self, segment):
        perm = int(getattr(segment, "perm", 0) or 0)
        flags = 0
        ida_segment = self._ida.ida_segment
        if perm & getattr(ida_segment, "SEGPERM_READ", 4):
            flags |= UC_PROT_READ
        if perm & getattr(ida_segment, "SEGPERM_WRITE", 2):
            flags |= UC_PROT_WRITE
        if perm & getattr(ida_segment, "SEGPERM_EXEC", 1):
            flags |= UC_PROT_EXEC
        return flags or (UC_PROT_READ | UC_PROT_WRITE)

    def _set_args(self, ql, arch, args, ret_addr):
        """按调用约定布置参数与返回哨兵；返回每个参数的 {kind,value} 元信息。"""
        prepared = [self._prepare_arg(ql, a) for a in list(args or [])]
        lr = _LR_REG.get(arch)
        if lr:  # arm/arm64/mips：返回地址放 link register
            for i, p in enumerate(prepared):
                regs = _ARG_REGS[arch]
                if i < len(regs):
                    ql.arch.regs.write(regs[i], int(p["value"]))
                else:
                    ql.arch.stack_push(int(p["value"]))
            ql.arch.regs.write(lr, int(ret_addr))
        elif arch in _ARG_REGS:  # x8664：寄存器传参，返回地址压栈
            regs = _ARG_REGS[arch]
            for i, p in enumerate(prepared):
                if i < len(regs):
                    ql.arch.regs.write(regs[i], int(p["value"]))
            for p in reversed(prepared[len(regs):]):
                ql.arch.stack_push(int(p["value"]))
            ql.arch.stack_push(int(ret_addr))
        else:  # x86：cdecl，全部经栈，右到左，最后压返回地址
            for p in reversed(prepared):
                ql.arch.stack_push(int(p["value"]))
            ql.arch.stack_push(int(ret_addr))
        return prepared

    def _prepare_arg(self, ql, a):
        """把单个参数解析为具体寄存器/栈值；缓冲区类参数自动分配并返回指针。"""
        if isinstance(a, dict):
            if "bytes" in a or "str" in a:
                data = (self._as_bytes(a["bytes"]) if "bytes" in a
                        else (str(a["str"]).encode("utf-8") + b"\x00"))
                buf = int(ql.mem.map_anywhere(max(len(data), 1)))
                ql.mem.write(buf, data)
                return {"kind": "buffer", "value": buf, "size": len(data)}
            if "ptr" in a:
                return {"kind": "ptr", "value": int(a["ptr"])}
            return {"kind": "scalar", "value": int(a.get("value", 0))}
        return {"kind": "scalar", "value": int(a)}

    def _function_stats(self, func):
        stats = {"insns": 0, "xor": 0, "rol": 0, "ror": 0, "mem_write": 0,
                 "loops": 0, "small_immediates": 0}
        for ea in self._ida.ida_funcs.func_item_iterator_t(func):
            ea = int(ea)
            stats["insns"] += 1
            mnem = (self._ida.ida_ua.print_insn_mnem(ea) or "").lower()
            if mnem in stats:
                stats[mnem] += 1
            if mnem.startswith("j") and self._ida.idc.get_operand_value(ea, 0) < ea:
                stats["loops"] += 1
            op0 = self._ida.idc.print_operand(ea, 0) or ""
            if "[" in op0 and mnem in {"mov", "stos", "xor", "add", "sub", "or", "and"}:
                stats["mem_write"] += 1
            for idx in range(2):
                if self._ida.idc.get_operand_type(ea, idx) == 5:
                    value = int(self._ida.idc.get_operand_value(ea, idx))
                    if 0 < value <= 0xff:
                        stats["small_immediates"] += 1
        return stats

    # 类调用助记符：识别调用点（x86/arm/mips）。
    _CALL_MNEMS = {"call", "callq", "bl", "blx", "blr", "jal", "jalr"}

    def _trace_wrapper_chain(self, algo_ea, max_depth, wrapper_max_size,
                             backtrack, data_ref_limit):
        """从算法函数沿调用者向上爬穿过 wrapper（小函数），还原转发链与数据线索。"""
        algo_ea = int(algo_ea)
        algo_func = self._ida.idaapi.get_func(algo_ea)
        levels = []
        entries = {}
        data_refs = {}
        self._collect_data_refs(algo_ea, data_refs, data_ref_limit)
        frontier = [algo_ea]
        visited = {algo_ea}
        for depth in range(1, int(max_depth) + 1):
            next_frontier = []
            for callee in frontier:
                had_caller = False
                for xref in self._ida.idautils.XrefsTo(callee):
                    if not getattr(xref, "iscode", True):
                        continue
                    frm = int(xref.frm)
                    mnem = (self._ida.ida_ua.print_insn_mnem(frm) or "").lower()
                    if mnem and mnem not in self._CALL_MNEMS and not mnem.startswith("call"):
                        continue
                    cf = self._ida.idaapi.get_func(frm)
                    caller_ea = None if cf is None else int(cf.start_ea)
                    size = 0 if cf is None else int(cf.end_ea - cf.start_ea)
                    is_wrapper = cf is not None and size <= int(wrapper_max_size)
                    had_caller = True
                    levels.append({
                        "depth": depth,
                        "call_ea": frm,
                        "callee_ea": int(callee),
                        "caller_ea": caller_ea,
                        "caller_name": "" if cf is None else self._ida.ida_funcs.get_func_name(caller_ea),
                        "caller_size": size,
                        "is_wrapper": is_wrapper,
                        "immediates": self._nearby_immediates(frm, backtrack),
                    })
                    if caller_ea is None:
                        continue
                    self._collect_data_refs(caller_ea, data_refs, data_ref_limit)
                    if is_wrapper and caller_ea not in visited:
                        visited.add(caller_ea)
                        next_frontier.append(caller_ea)
                    elif not is_wrapper:
                        entries[caller_ea] = self._ida.ida_funcs.get_func_name(caller_ea)
                if not had_caller:
                    entries.setdefault(int(callee), self._ida.ida_funcs.get_func_name(int(callee)))
            frontier = next_frontier
            if not frontier:
                break
        return {
            "algo": {
                "ea": algo_ea,
                "name": self._ida.ida_funcs.get_func_name(algo_ea),
                "size": 0 if algo_func is None else int(algo_func.end_ea - algo_func.start_ea),
            },
            "levels": levels,
            "entries": [{"ea": ea, "name": name} for ea, name in entries.items()],
            "data_refs": list(data_refs.values())[:data_ref_limit],
        }

    def _collect_data_refs(self, func_ea, acc, limit):
        """收集函数体内引用的全局数据地址（key table / 密文来源候选）。"""
        if len(acc) >= int(limit):
            return
        func = self._ida.idaapi.get_func(int(func_ea))
        if func is None:
            return
        for ea in self._ida.ida_funcs.func_item_iterator_t(func):
            ea = int(ea)
            for dr in self._ida.idautils.DataRefsFrom(ea):
                dr = int(dr)
                if dr not in acc:
                    acc[dr] = {"data_ea": dr, "name": self._name_of(dr),
                               "from_ea": ea, "from_func": int(func_ea)}
                    if len(acc) >= int(limit):
                        return

    def _nearby_immediates(self, ea, limit):
        out = []
        cur = int(ea)
        for _ in range(max(0, int(limit))):
            cur = int(self._ida.ida_bytes.prev_head(cur, 0))
            if cur == self._ida.idaapi.BADADDR:
                break
            for idx in range(2):
                if self._ida.idc.get_operand_type(cur, idx) == 5:
                    out.append({
                        "ea": cur,
                        "operand": idx,
                        "value": int(self._ida.idc.get_operand_value(cur, idx)),
                        "text": self._ida.idc.generate_disasm_line(cur, 0),
                    })
        return out
