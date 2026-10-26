"""
Helper module for IDA Python integration.
Provides configuration and IDA interface initialization.
"""

import os
import struct
import tempfile
from typing import Annotated, Optional, TypedDict

from headless_ida import HeadlessIda

from headless_ida_mcp_server import IDA_PATH


class Function(TypedDict):
    start_address: int
    end_address: int
    name: str
    prototype: Optional[str]


class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class Xref(TypedDict):
    address: int
    type: str
    function: Optional[Function]


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


# headless-ida 通过 import_module 暴露的 IDA 模块；同一份清单既用于按属性挂载
# 到 IDA 实例，也用于注册进沙箱注册表（server.py 复用），避免两处各写一遍。
IDA_MODULE_NAMES = [
    "idaapi",
    "idautils",
    "ida_entry",
    "ida_funcs",
    "ida_hexrays",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_typeinf",
    "ida_xref",
    "idc",
    "ida_loader",
    "ida_bytes",
    "ida_ua",
    "ida_segment",
    "ida_ida",
]


class IDA:
    def __init__(self, binary_path: Annotated[str, "Path to the binary file"]):
        self.headlessida = HeadlessIda(IDA_PATH, binary_path)
        self._closed = False
        self._prepare_decompile_idle_queue = []
        self._prepare_decompile_idle_done = 0
        self._prepare_decompile_idle_failed = 0
        self._prepare_decompile_idle_failures = []
        self._prepare_decompile_idle_timer = None
        for name in IDA_MODULE_NAMES:
            setattr(self, name, self.headlessida.import_module(name))

    def close(self):
        if self._closed:
            return
        self._closed = True
        timer = self._prepare_decompile_idle_timer
        self._prepare_decompile_idle_timer = None
        if timer is not None and hasattr(self.ida_kernwin, "unregister_timer"):
            try:
                self.ida_kernwin.unregister_timer(timer)
            except Exception:  # noqa: BLE001
                pass
        self._prepare_decompile_idle_queue.clear()
        self.headlessida.clean_up()

    ######## COPY from https://github.com/mrexodia/ida-pro-mcp ########
    def get_image_size(self):
        try:
            info = self.idaapi.get_inf_structure()
            omin_ea = info.omin_ea
            omax_ea = info.omax_ea
        except AttributeError:
            import ida_ida

            omin_ea = ida_ida.inf_get_omin_ea()
            omax_ea = ida_ida.inf_get_omax_ea()
        # Bad heuristic for image size (bad if the relocations are the last section)
        image_size = omax_ea - omin_ea
        # Try to extract it from the PE header
        header = self.idautils.peutils_t().header()
        if header and header[:4] == b"PE\0\0":
            image_size = struct.unpack("<I", header[0x50:0x54])[0]
        return image_size

    def get_prototype(self, fn) -> Optional[str]:
        try:
            if isinstance(fn, self.ida_funcs.func_t):
                func = fn
            else:
                func = self.idaapi.get_func(fn)
                if func is None:
                    return None
            tif = self.ida_typeinf.tinfo_t()
            if self.ida_nalt.get_tinfo(tif, func.start_ea):
                return str(tif)
            return self.idc.get_type(func.start_ea)
        except Exception as e:
            print(f"Error getting function prototype: {e}")
            return None

    def get_function(self, address: int, *, raise_error=True) -> Optional[Function]:
        fn = self.idaapi.get_func(address)
        if fn is None:
            if raise_error:
                raise IDAError(f"No function found at address {address}")
            return None

        try:
            name = fn.get_name()
        except AttributeError:
            name = self.ida_funcs.get_func_name(fn.start_ea)
        return {
            "address": fn.start_ea,
            "end_address": fn.end_ea,
            "name": name,
            "prototype": self.get_prototype(fn),
        }

    def get_function_by_name(
        self, name: Annotated[str, "Name of the function to get"]
    ) -> Function:
        """Get a function by its name"""
        function_address = self.idaapi.get_name_ea(self.idaapi.BADADDR, name)
        if function_address == self.idaapi.BADADDR:
            raise IDAError(f"No function found with name {name}")
        return self.get_function(function_address)

    def get_function_by_address(
        self, address: Annotated[int, "Address of the function to get"]
    ) -> Function:
        """Get a function by its address"""
        return self.get_function(address)

    def get_current_address(self) -> int:
        """Get the address currently selected by the user"""
        return self.idaapi.get_screen_ea()

    def get_current_function(self) -> Optional[Function]:
        """Get the function currently selected by the user"""
        return self.get_function(self.idaapi.get_screen_ea())

    def convert_number(
        self,
        text: Annotated[str, "Textual representation of the number to convert"],
        size: Annotated[Optional[int], "Size of the variable in bytes"],
    ) -> ConvertedNumber:
        """Convert a number (decimal, hexadecimal) to different representations"""
        try:
            value = int(text, 0)
        except ValueError:
            raise IDAError(f"Invalid number: {text}")

        # Estimate the size of the number
        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        # Convert the number to bytes
        try:
            bytes = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            raise IDAError(f"Number {text} is too big for {size} bytes")

        # Convert the bytes to ASCII
        ascii = ""
        for byte in bytes.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii += chr(byte)
            else:
                ascii = None
                break

        return {
            "decimal": str(value),
            "hexadecimal": hex(value),
            "bytes": bytes.hex(" "),
            "ascii": ascii,
            "binary": bin(value),
        }

    def list_functions(self) -> list[Function]:
        """List all functions in the database"""
        return [self.get_function(address) for address in self.idautils.Functions()]

    def prepare_decompile(
        self,
        start_ea: Optional[int] = None,
        end_ea: Optional[int] = None,
        max_functions: int = 0,
        max_func_size: int = 0,
        failure_limit: int = 20,
        auto_wait: bool = True,
        refresh: bool = False,
        idle: bool = True,
        idle_batch_size: int = 3,
        idle_interval_ms: int = 250,
    ) -> dict:
        """批量预反编译函数，优先用 decompile_many，并可安排空闲时间逐个补热。"""
        if not self.ida_hexrays.init_hexrays_plugin():
            raise IDAError("Hex-Rays decompiler is not available")

        if auto_wait:
            try:
                self.idaapi.auto_wait()
            except Exception:
                pass

        starts = []
        skipped = 0
        skipped_functions = []
        for ea in self.idautils.Functions():
            ea = int(ea)
            if start_ea is not None and ea < int(start_ea):
                continue
            if end_ea is not None and ea >= int(end_ea):
                continue
            func = self.idaapi.get_func(ea)
            if func is None:
                skipped += 1
                if len(skipped_functions) < failure_limit:
                    skipped_functions.append({"address": ea, "reason": "not a function"})
                continue
            size = int(func.end_ea - func.start_ea)
            if max_func_size and size > int(max_func_size):
                skipped += 1
                if len(skipped_functions) < failure_limit:
                    skipped_functions.append({
                        "address": int(func.start_ea),
                        "name": self.ida_funcs.get_func_name(func.start_ea),
                        "size": size,
                        "reason": "function too large",
                    })
                continue
            starts.append(ea)

        total = len(starts)
        limit_reached = False
        if max_functions and len(starts) > int(max_functions):
            starts = starts[:int(max_functions)]
            limit_reached = True

        decompile_many = {
            "attempted": False,
            "ok": False,
            "output_path": None,
            "message": "ida_hexrays.decompile_many is unavailable",
        }
        if starts and hasattr(self.ida_hexrays, "decompile_many"):
            fd, output_path = tempfile.mkstemp(prefix="rxengine_decompile_", suffix=".c")
            os.close(fd)
            flags = getattr(self.ida_hexrays, "VDRUN_SILENT", 0)
            try:
                decompile_many["attempted"] = True
                result = self.ida_hexrays.decompile_many(output_path, starts, flags)
                decompile_many.update({
                    "ok": bool(result),
                    "output_path": output_path,
                    "message": "decompile_many completed" if result else "decompile_many returned false",
                })
            except Exception as exc:
                decompile_many.update({"output_path": output_path, "message": str(exc)})

        entries = []
        failures = []
        decompiled = 0
        failed = 0
        for ea in starts:
            func = self.idaapi.get_func(ea)
            if func is None:
                continue
            size = int(func.end_ea - func.start_ea)
            name = self.ida_funcs.get_func_name(func.start_ea)
            error = self.ida_hexrays.hexrays_failure_t()
            try:
                cfunc = self.ida_hexrays.decompile_func(
                    func.start_ea, error, self.ida_hexrays.DECOMP_WARNINGS
                )
                if not cfunc:
                    message = "decompile_func returned null"
                    if getattr(error, "str", None):
                        message = str(error.str)
                    errea = int(error.errea) if error.errea != self.idaapi.BADADDR else None
                    raise IDAError(message if errea is None else f"{message} (address: {errea})")
                if refresh:
                    try:
                        cfunc.refresh_func_ctext()
                    except Exception:
                        pass
                lines = cfunc.get_pseudocode()
                decompiled += 1
                entries.append({
                    "address": int(func.start_ea),
                    "end_address": int(func.end_ea),
                    "name": name,
                    "size": size,
                    "line_count": len(lines),
                })
            except Exception as exc:
                failed += 1
                if len(failures) < failure_limit:
                    failures.append({
                        "address": int(func.start_ea),
                        "end_address": int(func.end_ea),
                        "name": name,
                        "size": size,
                        "message": str(exc),
                    })

        idle_status = {"scheduled": False, "queue_size": 0, "message": "idle warming disabled"}
        if idle and starts:
            idle_status = self._schedule_idle_decompile(starts, idle_batch_size, idle_interval_ms, failure_limit)

        self._prepare_decompile_cache = {
            "entries": entries,
            "failures": failures,
            "skipped": skipped_functions,
            "decompile_many": decompile_many,
            "idle": idle_status,
        }
        processed = decompiled + failed + skipped
        return {
            "ok": failed == 0 and (decompile_many["ok"] or not decompile_many["attempted"]),
            "total": total,
            "processed": processed,
            "decompiled": decompiled,
            "failed": failed,
            "skipped": skipped,
            "limit_reached": limit_reached,
            "decompile_many": decompile_many,
            "idle": idle_status,
            "failures": failures,
            "skipped_functions": skipped_functions,
            "ai_hint": (
                "已优先调用 decompile_many 批量预热，并可在 IDA 空闲回调中继续逐个补热；"
                "后续优先直接调用 decompile_function 读取已预热函数；"
                "若 failed 非 0，先处理 failures 中的地址，必要时改用 disassemble_function；"
                "若 limit_reached 为 true，用 start_ea/end_ea 或调大 max_functions 分批继续。"
            ),
        }

    def _schedule_idle_decompile(self, starts, idle_batch_size, idle_interval_ms, failure_limit):
        self._prepare_decompile_idle_queue = list(starts)
        self._prepare_decompile_idle_done = 0
        self._prepare_decompile_idle_failed = 0
        self._prepare_decompile_idle_failures = []
        batch_size = max(1, int(idle_batch_size or 1))
        interval_ms = max(50, int(idle_interval_ms or 50))

        def tick():
            for _ in range(batch_size):
                if not self._prepare_decompile_idle_queue:
                    self._prepare_decompile_idle_timer = None
                    return -1
                ea = self._prepare_decompile_idle_queue.pop(0)
                func = self.idaapi.get_func(ea)
                if func is None:
                    continue
                try:
                    error = self.ida_hexrays.hexrays_failure_t()
                    cfunc = self.ida_hexrays.decompile_func(
                        func.start_ea, error, self.ida_hexrays.DECOMP_WARNINGS
                    )
                    if not cfunc:
                        message = str(error.str) if getattr(error, "str", None) else "decompile_func returned null"
                        raise IDAError(message)
                    self._prepare_decompile_idle_done += 1
                except Exception as exc:
                    self._prepare_decompile_idle_failed += 1
                    if len(self._prepare_decompile_idle_failures) < failure_limit:
                        self._prepare_decompile_idle_failures.append({
                            "address": int(func.start_ea),
                            "name": self.ida_funcs.get_func_name(func.start_ea),
                            "message": str(exc),
                        })
            return interval_ms

        if not hasattr(self.ida_kernwin, "register_timer"):
            return {
                "scheduled": False,
                "queue_size": len(self._prepare_decompile_idle_queue),
                "message": "ida_kernwin.register_timer is unavailable",
            }
        try:
            self._prepare_decompile_idle_timer = self.ida_kernwin.register_timer(interval_ms, tick)
            return {
                "scheduled": self._prepare_decompile_idle_timer is not None,
                "queue_size": len(self._prepare_decompile_idle_queue),
                "batch_size": batch_size,
                "interval_ms": interval_ms,
                "message": "idle decompile warming scheduled",
            }
        except Exception as exc:
            return {
                "scheduled": False,
                "queue_size": len(self._prepare_decompile_idle_queue),
                "message": str(exc),
            }

    def get_prepare_decompile_status(self) -> dict:
        return {
            "queue_size": len(self._prepare_decompile_idle_queue),
            "idle_done": self._prepare_decompile_idle_done,
            "idle_failed": self._prepare_decompile_idle_failed,
            "idle_failures": self._prepare_decompile_idle_failures,
            "idle_running": self._prepare_decompile_idle_timer is not None,
        }

    def decompile_checked(self, address: int):
        if not self.ida_hexrays.init_hexrays_plugin():
            raise IDAError("Hex-Rays decompiler is not available")
        error = self.ida_hexrays.hexrays_failure_t()
        cfunc = self.ida_hexrays.decompile_func(
            address, error, self.ida_hexrays.DECOMP_WARNINGS
        )
        if not cfunc:
            message = f"Decompilation failed at {address}"
            if error.str:
                message += f": {error.str}"
            if error.errea != self.idaapi.BADADDR:
                message += f" (address: {error.errea})"
            raise IDAError(message)
        return cfunc

    def decompile_function(
        self, address: Annotated[int, "Address of the function to decompile"]
    ) -> str:
        """Decompile a function at the given address"""
        cfunc = self.decompile_checked(address)
        sv = cfunc.get_pseudocode()
        pseudocode = ""
        for i, sl in enumerate(sv):
            item = self.ida_hexrays.ctree_item_t()
            addr = None if i > 0 else cfunc.entry_ea
            if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                ds = item.dstr().split(": ")
                if len(ds) == 2:
                    try:
                        addr = int(ds[0], 16)
                    except ValueError:
                        pass
            line = self.ida_lines.tag_remove(sl.line)
            if len(pseudocode) > 0:
                pseudocode += "\n"
            if addr is None:
                pseudocode += f"/* line: {i} */ {line}"
            else:
                pseudocode += f"/* line: {i}, address: {addr} */ {line}"

        return pseudocode

    def disassemble_function(
        self, address: Annotated[int, "Address of the function to disassemble"]
    ) -> str:
        """Get assembly code (address: instruction; comment) for a function"""
        func = self.idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at address {address}")

        # TODO: add labels
        disassembly = ""
        for address in self.ida_funcs.func_item_iterator_t(func):
            if len(disassembly) > 0:
                disassembly += "\n"
            disassembly += f"{address}: "
            disassembly += self.idaapi.generate_disasm_line(
                address, self.idaapi.GENDSM_REMOVE_TAGS
            )
            comment = self.idaapi.get_cmt(address, False)
            if not comment:
                comment = self.idaapi.get_cmt(address, True)
            if comment:
                disassembly += f"; {comment}"
        return disassembly

    def get_xrefs_to(
        self, address: Annotated[int, "Address to get cross references to"]
    ) -> list[Xref]:
        """Get all cross references to the given address"""
        xrefs = []
        for xref in self.idautils.XrefsTo(address):
            xrefs.append(
                {
                    "address": xref.frm,
                    "type": "code" if xref.iscode else "data",
                    "function": self.get_function(xref.frm, raise_error=False),
                }
            )
        return xrefs

    def get_entry_points(self) -> list[Function]:
        """Get all entry points in the database"""
        result = []
        for i in range(self.ida_entry.get_entry_qty()):
            ordinal = self.ida_entry.get_entry_ordinal(i)
            address = self.ida_entry.get_entry(ordinal)
            func = self.get_function(address, raise_error=False)
            if func is not None:
                result.append(func)
        return result

    def set_decompiler_comment(
        self,
        address: Annotated[int, "Address in the function to set the comment for"],
        comment: Annotated[str, "Comment text (not shown in the disassembly)"],
    ):
        """Set a comment for a given address in the function pseudocode"""
        # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
        # Check if the address corresponds to a line
        cfunc = self.decompile_checked(address)

        # Special case for function entry comments
        if address == cfunc.entry_ea:
            self.idc.set_func_cmt(address, comment, True)
            cfunc.refresh_func_ctext()
            return

        eamap = cfunc.get_eamap()
        if address not in eamap:
            raise IDAError(f"Failed to set comment at {address}")
        nearest_ea = eamap[address][0].ea

        # Remove existing orphan comments
        if cfunc.has_orphan_cmts():
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()

        # Set the comment by trying all possible item types
        tl = self.idaapi.treeloc_t()
        tl.ea = nearest_ea
        for itp in range(self.idaapi.ITP_SEMI, self.idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                return
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()
        raise IDAError(f"Failed to set comment at {address}")

    def set_disassembly_comment(
        self,
        address: Annotated[int, "Address in the function to set the comment for"],
        comment: Annotated[str, "Comment text (not shown in the pseudocode)"],
    ):
        """Set a comment for a given address in the function disassembly"""
        if not self.idaapi.set_cmt(address, comment, False):
            raise IDAError(f"Failed to set comment at {address}")

    def refresh_decompiler_widget(self):
        widget = self.ida_kernwin.get_current_widget()
        if widget is not None:
            vu = self.ida_hexrays.get_widget_vdui(widget)
            if vu is not None:
                vu.refresh_ctext()

    def refresh_decompiler_ctext(self, function_address: int):
        error = self.ida_hexrays.hexrays_failure_t()
        cfunc = self.ida_hexrays.decompile_func(
            function_address, error, self.ida_hexrays.DECOMP_WARNINGS
        )
        if cfunc:
            cfunc.refresh_func_ctext()

    def rename_local_variable(
        self,
        function_address: Annotated[
            int, "Address of the function containing the variable"
        ],
        old_name: Annotated[str, "Current name of the variable"],
        new_name: Annotated[str, "New name for the variable"],
    ):
        """Rename a local variable in a function"""
        func = self.idaapi.get_func(function_address)
        if not func:
            raise IDAError(f"No function found at address {function_address}")
        if not self.ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
            raise IDAError(
                f"Failed to rename local variable {old_name} in function {func.start_ea}"
            )
        self.refresh_decompiler_ctext(func.start_ea)

    def rename_function(
        self,
        function_address: Annotated[int, "Address of the function to rename"],
        new_name: Annotated[str, "New name for the function"],
    ):
        """Rename a function"""
        fn = self.idaapi.get_func(function_address)
        if not fn:
            raise IDAError(f"No function found at address {function_address}")
        if not self.idaapi.set_name(fn.start_ea, new_name):
            raise IDAError(f"Failed to rename function {fn.start_ea} to {new_name}")
        self.refresh_decompiler_ctext(fn.start_ea)

    def set_function_prototype(
        self,
        function_address: Annotated[int, "Address of the function"],
        prototype: Annotated[str, "New function prototype"],
    ) -> str:
        """Set a function's prototype"""
        fn = self.idaapi.get_func(function_address)
        if not fn:
            raise IDAError(f"No function found at address {function_address}")
        try:
            tif = self.ida_typeinf.tinfo_t(prototype, None, self.ida_typeinf.PT_SIL)
            if not tif.is_func():
                raise IDAError("Parsed declaration is not a function type")
            if not self.ida_typeinf.apply_tinfo(
                fn.start_ea, tif, self.ida_typeinf.PT_SIL
            ):
                raise IDAError("Failed to apply type")
            self.refresh_decompiler_ctext(fn.start_ea)
        except Exception:
            raise IDAError(f"Failed to parse prototype string: {prototype}")

    def save_idb_file(self, save_path: Annotated[str, "Path to save the IDB file"]):
        self.ida_loader.save_database(save_path, 0)
