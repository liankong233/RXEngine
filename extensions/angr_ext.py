# -*- coding: utf-8 -*-
"""angr 符号执行扩展：暴露给 JS 沙箱的 require('angr') 门面。"""
import time

try:
    import angr
    import claripy
except ModuleNotFoundError as exc:
    angr = None
    claripy = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class AngrError(Exception):
    pass


class AngrFacade:
    def __init__(self, ida=None):
        self._ida = ida

    def _require_angr(self):
        if _IMPORT_ERROR is not None:
            raise AngrError(f"angr dependencies unavailable: {_IMPORT_ERROR}")

    def project(self, path=None, opts=None):
        self._require_angr()
        opts = opts or {}
        if path is None:
            path = self.input_file_path()
        return angr.Project(str(path), **self._project_kwargs(opts))

    def input_file_path(self):
        if self._ida is None:
            raise AngrError("this operation requires an IDA instance")
        return self._ida.idc.get_input_file_path()

    def entry(self, project):
        return project.entry

    def image_base(self, project):
        return project.loader.main_object.mapped_base

    def find_symbol(self, project, name):
        sym = project.loader.find_symbol(str(name))
        if sym is None:
            return None
        return {"name": sym.name, "rebased_addr": sym.rebased_addr, "linked_addr": sym.linked_addr}

    def blank_state(self, project, addr=None, opts=None):
        kwargs = self._state_kwargs(opts)
        if addr is None:
            return project.factory.blank_state(**kwargs)
        return project.factory.blank_state(addr=int(addr), **kwargs)

    def entry_state(self, project, args=None, opts=None):
        kwargs = self._state_kwargs(opts)
        if args is not None:
            kwargs["args"] = [str(x) for x in args]
        return project.factory.entry_state(**kwargs)

    def call_state(self, project, addr, args=None, opts=None):
        kwargs = self._state_kwargs(opts)
        return project.factory.call_state(int(addr), *(args or []), **kwargs)

    def function_range(self, addr):
        if self._ida is None:
            raise AngrError("this operation requires an IDA instance")
        func = self._ida.idaapi.get_func(int(addr))
        if func is None:
            raise AngrError(f"no function at {addr}")
        return {"start_ea": int(func.start_ea), "end_ea": int(func.end_ea), "size": int(func.end_ea - func.start_ea)}

    def function_state(self, project, addr, opts=None):
        info = self.function_range(addr)
        state = self.blank_state(project, info["start_ea"], opts)
        return {"state": state, "range": info}

    def symbolic_args(self, state, specs):
        args = []
        for spec in list(specs or []):
            name = str(spec.get("name", f"arg{len(args)}"))
            bits = int(spec.get("bits", 64))
            value = claripy.BVS(name, bits)
            args.append(value)
            reg = spec.get("reg")
            addr = spec.get("addr")
            if reg is not None:
                setattr(state.regs, str(reg), value)
            if addr is not None:
                state.memory.store(int(addr), value, endness=state.arch.memory_endness)
            for item in list(spec.get("constraints", []) or []):
                self._apply_constraint(state, value, item)
        return args

    def hook_return(self, project, addr, value=0, length=0):
        """在 addr 处挂 SimProcedure，仅设返回值（返回寄存器由 cc 决定）。"""
        return self.hook_model(project, addr, {"return": value, "length": length})

    def hook_symbol_return(self, project, name, value=0):
        return self.hook_symbol_model(project, name, {"return": value})

    def hook_model(self, project, addr, model=None):
        """在 addr 处挂一个可配置的 SimProcedure，建模函数的调用约定与副作用。

        比 hook_return 更完整地替代一个函数：可指定返回值、覆写寄存器/内存副作用，
        并通过调用约定（cc）+ 参数个数（num_args）让 angr 正确取参与清理栈（stdcall
        callee 弹栈等），从而在符号执行里安全跳过无法/不必进入的函数体。

        model 可含：
          - return: 返回值（int，写入返回寄存器）；缺省不设返回值。
          - regs: {reg: int} 覆写寄存器，建模函数对寄存器的副作用。
          - mem: [{addr, value|hex, size}] 写内存副作用；给 value(int)+size 或 hex 串。
          - length: 被 hook 指令占用的字节数；内联 hook 需给，函数级 hook 传 0。
          - cc: 调用约定类名（如 'SimCCStdcall'/'SimCCCdecl'），据此取参/清栈。
          - num_args: 参数个数，配合 cc 做基于参数的栈清理。
          - returns: 是否正常返回（默认 True）；False 表示 noreturn。
        """
        model = model or {}
        hook_cls = self._build_model_procedure(model)
        kwargs = {}
        if model.get("num_args") is not None:
            kwargs["num_args"] = int(model["num_args"])
        cc = self._resolve_cc(project, model.get("cc"))
        if cc is not None:
            kwargs["cc"] = cc
        if model.get("returns") is not None:
            kwargs["returns"] = bool(model["returns"])
        project.hook(int(addr), hook_cls(**kwargs), length=int(model.get("length", 0)))
        return self._model_summary(int(addr), model)

    def hook_symbol_model(self, project, name, model=None):
        """按符号名解析地址后挂 hook_model；建模某个导入/命名函数的调用约定与副作用。"""
        sym = project.loader.find_symbol(str(name))
        if sym is None:
            raise AngrError(f"symbol not found: {name}")
        summary = self.hook_model(project, sym.rebased_addr, model)
        summary["symbol"] = str(name)
        return summary

    def hook_declarative(self, project, addr, spec=None):
        spec = self._validate_declarative_spec(spec)
        hook_cls = self._build_declarative_procedure(spec)
        kwargs = {}
        if spec.get("argc") is not None:
            kwargs["num_args"] = int(spec["argc"])
        cc = self._resolve_cc(project, spec.get("cc"))
        if cc is not None:
            kwargs["cc"] = cc
        if spec.get("returns") is not None:
            kwargs["returns"] = bool(spec["returns"])
        project.hook(int(addr), hook_cls(**kwargs), length=int(spec.get("length", 0)))
        return self._declarative_summary(int(addr), spec)

    def hook_symbol_declarative(self, project, name, spec=None):
        sym = project.loader.find_symbol(str(name))
        if sym is None:
            raise AngrError(f"symbol not found: {name}")
        summary = self.hook_declarative(project, sym.rebased_addr, spec)
        summary["symbol"] = str(name)
        return summary

    def hook_declarative_many(self, project, installs):
        out = []
        for item in list(installs or []):
            spec = item.get("spec", item)
            if item.get("addr") is not None:
                out.append(self.hook_declarative(project, item["addr"], spec))
            elif item.get("name") is not None:
                out.append(self.hook_symbol_declarative(project, item["name"], spec))
            else:
                raise AngrError("declarative install requires addr or name")
        return out

    def apply_declarative(self, state, spec, args=None):
        spec = self._validate_declarative_spec(spec)
        behavior = spec["behavior"]
        args = list(args or [])
        if behavior == "return_const":
            return int(spec.get("value", 0))
        if behavior == "return_arg":
            return args[int(spec.get("index", 0))]
        if behavior == "memcpy":
            return self._decl_memcpy(state, args)
        if behavior == "memset":
            return self._decl_memset(state, args)
        if behavior == "strlen":
            return self._decl_strlen(state, args)
        if behavior == "strcmp":
            return self._decl_strcmp(state, args)
        if behavior == "strncmp":
            return self._decl_strncmp(state, args)
        if behavior == "strstr":
            return self._decl_strstr(state, args)
        if behavior == "strcpy":
            return self._decl_strcpy(state, args)
        if behavior == "strncpy":
            return self._decl_strncpy(state, args)
        if behavior == "malloc":
            return self._decl_malloc(state, args, spec)
        if behavior == "free":
            return 0
        raise AngrError(f"unsupported declarative behavior: {behavior}")

    def _build_model_procedure(self, model):
        facade = self
        ret = model.get("return")
        regs = dict(model.get("regs") or {})
        mem = list(model.get("mem") or [])

        class ModelHook(angr.SimProcedure):
            def run(self, *args):
                for name, value in regs.items():
                    # 直接赋 int，angr 按目标寄存器宽度自动包装（含 edx 等子寄存器）
                    setattr(self.state.regs, str(name), int(value))
                for item in mem:
                    facade._store_mem(self.state, item)
                if ret is None:
                    return
                return int(ret)

        return ModelHook

    def _build_declarative_procedure(self, spec):
        facade = self
        behavior = str(spec.get("behavior"))
        value = spec.get("value")
        index = int(spec.get("index", 0))

        class DeclarativeHook(angr.SimProcedure):
            def run(self, *args):
                if behavior == "return_const":
                    return int(value or 0)
                if behavior == "return_arg":
                    return args[index]
                if behavior == "memcpy":
                    return facade._decl_memcpy(self.state, args)
                if behavior == "memset":
                    return facade._decl_memset(self.state, args)
                if behavior == "strlen":
                    return facade._decl_strlen(self.state, args)
                if behavior == "strcmp":
                    return facade._decl_strcmp(self.state, args)
                if behavior == "strncmp":
                    return facade._decl_strncmp(self.state, args)
                if behavior == "strstr":
                    return facade._decl_strstr(self.state, args)
                if behavior == "strcpy":
                    return facade._decl_strcpy(self.state, args)
                if behavior == "strncpy":
                    return facade._decl_strncpy(self.state, args)
                if behavior == "malloc":
                    return facade._decl_malloc(self.state, args, spec)
                if behavior == "free":
                    return 0
                raise AngrError(f"unsupported declarative behavior: {behavior}")

        return DeclarativeHook

    @staticmethod
    def _decl_memcpy(state, args):
        dst, src, size = args[:3]
        concrete_size = state.solver.eval(size)
        data = state.memory.load(src, concrete_size, endness="Iend_BE")
        state.memory.store(dst, data, endness="Iend_BE")
        return dst

    @staticmethod
    def _decl_memset(state, args):
        dst, value, size = args[:3]
        concrete_size = state.solver.eval(size)
        if isinstance(value, int):
            value = claripy.BVV(value, state.arch.bits)
        byte = claripy.Extract(7, 0, value)
        state.memory.store(dst, claripy.Concat(*([byte] * concrete_size)))
        return dst

    @classmethod
    def _decl_strlen(cls, state, args):
        return len(cls._read_cstring(state, args[0]))

    @classmethod
    def _decl_strcmp(cls, state, args):
        left = cls._read_cstring(state, args[0])
        right = cls._read_cstring(state, args[1])
        return cls._strcmp_bytes(left, right)

    @classmethod
    def _decl_strncmp(cls, state, args):
        size = state.solver.eval(args[2])
        left = cls._read_cstring(state, args[0], size)
        right = cls._read_cstring(state, args[1], size)
        return cls._strcmp_bytes(left[:size], right[:size])

    @classmethod
    def _decl_strstr(cls, state, args):
        haystack = cls._read_cstring(state, args[0])
        needle = cls._read_cstring(state, args[1])
        offset = haystack.find(needle)
        if offset < 0:
            return 0
        return args[0] + offset

    @classmethod
    def _decl_strcpy(cls, state, args):
        dst, src = args[:2]
        data = cls._read_cstring(state, src) + b"\x00"
        state.memory.store(dst, data)
        return dst

    @classmethod
    def _decl_strncpy(cls, state, args):
        dst, src, size = args[:3]
        concrete_size = state.solver.eval(size)
        data = cls._read_cstring(state, src, concrete_size)[:concrete_size]
        data = data + (b"\x00" * max(0, concrete_size - len(data)))
        state.memory.store(dst, data)
        return dst

    @staticmethod
    def _decl_malloc(state, args, spec):
        size = state.solver.eval(args[0])
        base = int(spec.get("base", 0x50000000))
        step = int(spec.get("step", 0x10000))
        next_addr = state.globals.get("rx_declarative_malloc_next", base)
        aligned_size = max(1, (int(size) + 0xF) & ~0xF)
        state.globals["rx_declarative_malloc_next"] = next_addr + max(step, aligned_size)
        return next_addr

    @staticmethod
    def _read_cstring(state, addr, max_len=4096):
        out = bytearray()
        for offset in range(int(max_len)):
            byte = state.memory.load(addr + offset, 1)
            if state.solver.symbolic(byte):
                raise AngrError("symbolic strings are unsupported for declarative libc hooks")
            value = state.solver.eval(byte)
            if value == 0:
                break
            out.append(value & 0xFF)
        return bytes(out)

    @staticmethod
    def _strcmp_bytes(left, right):
        limit = min(len(left), len(right))
        for idx in range(limit):
            if left[idx] != right[idx]:
                return left[idx] - right[idx]
        return len(left) - len(right)

    @staticmethod
    def _validate_declarative_spec(spec):
        spec = dict(spec or {})
        behavior = spec.get("behavior")
        if behavior is None:
            raise AngrError("declarative spec requires behavior")
        behavior = str(behavior)
        supported = {"return_const", "return_arg", "memcpy", "memset", "strlen", "strcmp",
                     "strncmp", "strstr", "strcpy", "strncpy", "malloc", "free"}
        if behavior not in supported:
            raise AngrError(f"unsupported declarative behavior: {behavior}")
        spec["behavior"] = behavior
        if behavior == "return_arg" and spec.get("index") is None:
            spec["index"] = 0
        argc_by_behavior = {
            "memcpy": 3,
            "memset": 3,
            "strlen": 1,
            "strcmp": 2,
            "strncmp": 3,
            "strstr": 2,
            "strcpy": 2,
            "strncpy": 3,
            "malloc": 1,
            "free": 1,
        }
        if behavior in argc_by_behavior and spec.get("argc") is None:
            spec["argc"] = argc_by_behavior[behavior]
        return spec

    @staticmethod
    def _declarative_summary(addr, spec):
        summary = {"addr": int(addr), "hook": "declarative", "behavior": str(spec.get("behavior"))}
        if spec.get("name") is not None:
            summary["name"] = str(spec["name"])
        if spec.get("argc") is not None:
            summary["argc"] = int(spec["argc"])
        return summary

    @staticmethod
    def _store_mem(state, item):
        addr = int(item.get("addr"))
        if item.get("hex") is not None:
            data = bytes.fromhex(str(item["hex"]))
            state.memory.store(addr, data)
            return
        size = int(item.get("size", state.arch.bytes))
        value = claripy.BVV(int(item.get("value", 0)), size * 8)
        state.memory.store(addr, value, endness=state.arch.memory_endness)

    def _resolve_cc(self, project, name):
        if name is None:
            return None
        import angr.calling_conventions as cc_mod
        cls = getattr(cc_mod, str(name), None)
        if cls is None:
            raise AngrError(f"unknown calling convention: {name}")
        return cls(project.arch)

    @staticmethod
    def _model_summary(addr, model):
        summary = {"addr": int(addr), "hook": "model"}
        if model.get("return") is not None:
            summary["return"] = int(model["return"])
        if model.get("regs"):
            summary["regs"] = {str(k): int(v) for k, v in model["regs"].items()}
        if model.get("mem"):
            summary["mem"] = len(list(model["mem"]))
        if model.get("cc") is not None:
            summary["cc"] = str(model["cc"])
        if model.get("num_args") is not None:
            summary["num_args"] = int(model["num_args"])
        return summary

    def explore_paths(self, project, state, opts=None):
        opts = opts or {}
        simgr = project.factory.simgr(state)
        if opts.get("veritesting"):
            simgr.use_technique(angr.exploration_techniques.Veritesting())
        if opts.get("dfs"):
            simgr.use_technique(angr.exploration_techniques.DFS())
        if opts.get("loop_bound") is not None:
            simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=int(opts["loop_bound"])))
        if opts.get("find") is not None or opts.get("avoid") is not None:
            self.explore(simgr, opts.get("find"), opts.get("avoid"), opts.get("n"), opts)
        else:
            self.run(simgr, opts.get("steps"), opts)
        return {"simgr": simgr, "counts": self.stash_counts(simgr)}

    def result_template(self, state, opts=None):
        opts = opts or {}
        out = {"addr": int(state.addr), "satisfiable": bool(state.solver.satisfiable())}
        regs = opts.get("regs") or []
        if regs:
            out["regs"] = {str(name): self.eval(state, getattr(state.regs, str(name))) for name in regs}
        mem = []
        for item in list(opts.get("mem", []) or []):
            addr = int(item.get("addr"))
            size = int(item.get("size", 1))
            mem.append({"addr": addr, "size": size, "hex": self.mem_read(state, addr, size)})
        if mem:
            out["mem"] = mem
        return out

    def simgr(self, project, state):
        return project.factory.simgr(state)

    def explore(self, simgr, find=None, avoid=None, n=None, opts=None):
        opts = opts or {}
        kwargs = {}
        if find is not None:
            kwargs["find"] = self._addr_or_addrs(find)
        if avoid is not None:
            kwargs["avoid"] = self._addr_or_addrs(avoid)
        target_found = int(n) if n is not None else 0
        timeout = float(opts.get("timeout", 0) or 0)
        max_steps = int(opts.get("max_steps", opts.get("steps", 0)) or 0)
        start = time.monotonic()
        steps = 0
        while True:
            before = self.stash_counts(simgr)
            simgr.explore(**kwargs, n=1)
            steps += 1
            if self._budget_exhausted(simgr, opts, start, steps, before):
                break
            if max_steps and steps >= max_steps:
                break
            if timeout and time.monotonic() - start >= timeout:
                break
            if not simgr.active:
                break
            if find is not None and target_found and len(simgr.found) >= target_found:
                break
        return simgr

    def run(self, simgr, n=None, opts=None):
        opts = opts or {}
        max_steps = int(opts.get("max_steps", n if n is not None else 0) or 0)
        timeout = float(opts.get("timeout", 0) or 0)
        start = time.monotonic()
        steps = 0
        while True:
            before = self.stash_counts(simgr)
            simgr.step()
            steps += 1
            if self._budget_exhausted(simgr, opts, start, steps, before):
                break
            if max_steps and steps >= max_steps:
                break
            if timeout and time.monotonic() - start >= timeout:
                break
            if not simgr.active:
                break
        return simgr

    def _budget_exhausted(self, simgr, opts, start, steps, before_counts):
        max_active = int(opts.get("max_active", 0) or 0)
        max_found = int(opts.get("max_found", 0) or 0)
        timeout = float(opts.get("timeout", 0) or 0)
        if max_active and len(simgr.active) > max_active:
            simgr.stashes["active"] = simgr.active[:max_active]
            return True
        if max_found and len(simgr.found) >= max_found:
            return True
        if timeout and time.monotonic() - start >= timeout:
            return True
        return before_counts == self.stash_counts(simgr) and not simgr.active

    def step(self, simgr, n=1):
        for _ in range(int(n)):
            simgr.step()
        return simgr

    def stash_counts(self, simgr):
        return {name: len(stash) for name, stash in simgr.stashes.items()}

    def stash(self, simgr, name="active"):
        return list(simgr.stashes.get(str(name), []))

    def first(self, simgr, name="active"):
        states = simgr.stashes.get(str(name), [])
        return states[0] if states else None

    def eval(self, state, expr, cast_to="int"):
        value = state.solver.eval(expr, cast_to=self._cast(cast_to))
        if isinstance(value, bytes):
            return value.hex()
        return value

    def eval_upto(self, state, expr, n, cast_to="int"):
        cast = self._cast(cast_to)
        values = state.solver.eval_upto(expr, int(n), cast_to=cast)
        return [v.hex() if isinstance(v, bytes) else v for v in values]

    def satisfiable(self, state):
        return state.solver.satisfiable()

    def add(self, state, constraint):
        state.solver.add(constraint)

    def bvs(self, name, bits):
        return claripy.BVS(str(name), int(bits))

    def bvv(self, value, bits):
        return claripy.BVV(int(value), int(bits))

    def concat(self, values):
        return claripy.Concat(*list(values))

    def eq(self, left, right):
        return left == right

    def ne(self, left, right):
        return left != right

    def ugt(self, left, right):
        return left.UGT(right)

    def uge(self, left, right):
        return left.UGE(right)

    def ult(self, left, right):
        return left.ULT(right)

    def ule(self, left, right):
        return left.ULE(right)

    def and_(self, values):
        return claripy.And(*list(values))

    def or_(self, values):
        return claripy.Or(*list(values))

    def not_(self, value):
        return claripy.Not(value)

    def mem_read(self, state, addr, size):
        data = state.memory.load(int(addr), int(size), endness=state.arch.memory_endness)
        return state.solver.eval(data, cast_to=bytes).hex()

    def mem_write(self, state, addr, data):
        state.memory.store(int(addr), self._as_bytes(data))

    def stage_result_comments(self, results, ida_facade, opts=None):
        if self._ida is None:
            raise AngrError("this operation requires an IDA instance")
        opts = opts or {}
        prefix = str(opts.get("prefix", "angr"))
        changes = []
        for item in list(results or []):
            ea = int(item.get("ea", item.get("addr")))
            text = item.get("text")
            if text is None:
                text = self._format_result(item)
            changes.append(ida_facade.set_comment(ea, f"{prefix}: {text}"))
        return changes

    def reg_read(self, state, name):
        return getattr(state.regs, str(name))

    def reg_write(self, state, name, value):
        setattr(state.regs, str(name), value)

    def posix_dump(self, state, fd):
        return state.posix.dumps(int(fd)).hex()

    def loader_object(self, project):
        obj = project.loader.main_object
        return {
            "binary": obj.binary,
            "arch": project.arch.name,
            "entry": project.entry,
            "mapped_base": obj.mapped_base,
            "min_addr": obj.min_addr,
            "max_addr": obj.max_addr,
        }

    @staticmethod
    def _project_kwargs(opts):
        kwargs = {}
        if "auto_load_libs" in opts:
            kwargs["auto_load_libs"] = bool(opts["auto_load_libs"])
        if "main_opts" in opts:
            kwargs["main_opts"] = dict(opts["main_opts"])
        return kwargs

    @staticmethod
    def _state_kwargs(opts):
        opts = opts or {}
        kwargs = {}
        if "add_options" in opts:
            kwargs["add_options"] = set(opts["add_options"])
        if "remove_options" in opts:
            kwargs["remove_options"] = set(opts["remove_options"])
        return kwargs

    @staticmethod
    def _addr_or_addrs(value):
        if isinstance(value, (list, tuple)):
            return [int(x) for x in value]
        return int(value)

    @staticmethod
    def _cast(name):
        if name in (bytes, int):
            return name
        if str(name).lower() == "bytes":
            return bytes
        return int

    def _apply_constraint(self, state, value, item):
        op = str(item.get("op", "=="))
        other = int(item.get("value"))
        if op == "==":
            state.solver.add(value == other)
        elif op == "!=":
            state.solver.add(value != other)
        elif op == "ugt":
            state.solver.add(value.UGT(other))
        elif op == "uge":
            state.solver.add(value.UGE(other))
        elif op == "ult":
            state.solver.add(value.ULT(other))
        elif op == "ule":
            state.solver.add(value.ULE(other))
        else:
            raise AngrError(f"unsupported constraint op: {op}")

    @staticmethod
    def _format_result(item):
        parts = []
        for key in ("addr", "value", "hex", "satisfiable"):
            if key in item:
                parts.append(f"{key}={item[key]}")
        return ", ".join(parts) if parts else str(item)

    @staticmethod
    def _as_bytes(data):
        if isinstance(data, str):
            return bytes.fromhex(data)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        return bytes(bytearray(int(x) & 0xFF for x in data))
