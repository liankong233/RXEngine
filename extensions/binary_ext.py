# -*- coding: utf-8 -*-
"""二进制分析基础库扩展：ELF 解析、反汇编与汇编。"""
import io

try:
    from capstone import Cs
except ModuleNotFoundError as exc:
    Cs = None
    _CAPSTONE_IMPORT_ERROR = exc
else:
    _CAPSTONE_IMPORT_ERROR = None
try:
    from elftools.elf.elffile import ELFFile
except ModuleNotFoundError as exc:
    ELFFile = None
    _ELFTOOLS_IMPORT_ERROR = exc
else:
    _ELFTOOLS_IMPORT_ERROR = None
try:
    from keystone import Ks
except ModuleNotFoundError as exc:
    Ks = None
    _KEYSTONE_IMPORT_ERROR = exc
else:
    _KEYSTONE_IMPORT_ERROR = None


_CAPSTONE_ARCH = {
    "x86": ("CS_ARCH_X86", "CS_MODE_32"),
    "x64": ("CS_ARCH_X86", "CS_MODE_64"),
    "amd64": ("CS_ARCH_X86", "CS_MODE_64"),
    "arm": ("CS_ARCH_ARM", "CS_MODE_ARM"),
    "thumb": ("CS_ARCH_ARM", "CS_MODE_THUMB"),
    "arm64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "aarch64": ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips32": ("CS_ARCH_MIPS", "CS_MODE_MIPS32"),
    "mips64": ("CS_ARCH_MIPS", "CS_MODE_MIPS64"),
}

_KEYSTONE_ARCH = {
    "x86": ("KS_ARCH_X86", "KS_MODE_32"),
    "x64": ("KS_ARCH_X86", "KS_MODE_64"),
    "amd64": ("KS_ARCH_X86", "KS_MODE_64"),
    "arm": ("KS_ARCH_ARM", "KS_MODE_ARM"),
    "thumb": ("KS_ARCH_ARM", "KS_MODE_THUMB"),
    "arm64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
    "aarch64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN"),
    "mips32": ("KS_ARCH_MIPS", "KS_MODE_MIPS32"),
    "mips64": ("KS_ARCH_MIPS", "KS_MODE_MIPS64"),
}


class PyElfToolsFacade:
    def parse(self, data):
        elf = _elf(data)
        return {
            "ok": True,
            "class": elf.elfclass,
            "littleEndian": elf.little_endian,
            "machine": elf.header["e_machine"],
            "entry": int(elf.header["e_entry"]),
            "type": elf.header["e_type"],
            "sections": _sections(elf),
            "segments": _segments(elf),
        }

    def sections(self, data):
        return _sections(_elf(data))

    def segments(self, data):
        return _segments(_elf(data))

    def symbols(self, data):
        out = []
        for section in _elf(data).iter_sections():
            if not hasattr(section, "iter_symbols"):
                continue
            for sym in section.iter_symbols():
                out.append({
                    "name": sym.name,
                    "value": int(sym.entry["st_value"]),
                    "size": int(sym.entry["st_size"]),
                    "type": sym.entry["st_info"]["type"],
                    "bind": sym.entry["st_info"]["bind"],
                    "section": sym.entry["st_shndx"],
                })
        return out


class CapstoneFacade:
    def constants(self):
        import capstone
        return _constants(capstone, ("CS_ARCH_", "CS_MODE_", "CS_OPT_"))

    def disasm(self, code, arch="x64", address=0, opts=None):
        md = _capstone(arch, opts or {})
        return [_instruction(i) for i in md.disasm(_bytes(code), int(address))]

    def disasmOne(self, code, arch="x64", address=0, opts=None):
        items = self.disasm(code, arch, address, opts or {})
        return None if not items else items[0]


class KeystoneFacade:
    def constants(self):
        import keystone
        return _constants(keystone, ("KS_ARCH_", "KS_MODE_", "KS_OPT_"))

    def asm(self, assembly, arch="x64", address=0, opts=None):
        ks = _keystone(arch, opts or {})
        encoding, count = ks.asm(str(assembly), int(address))
        data = bytes(encoding or [])
        return {"ok": True, "count": int(count), "bytes": data.hex(), "encoding": list(data)}


class BinaryFacade:
    def __init__(self):
        self.elf = PyElfToolsFacade()
        self.capstone = CapstoneFacade()
        self.keystone = KeystoneFacade()

    def hexToBytes(self, value):
        return _bytes(value)

    def bytesToHex(self, value):
        return _bytes(value).hex()


def _require_dependency(error, name):
    if error is not None:
        raise RuntimeError(f"{name} dependency unavailable: {error}")


def _elf(data):
    _require_dependency(_ELFTOOLS_IMPORT_ERROR, "pyelftools")
    return ELFFile(io.BytesIO(_bytes(data)))


def _sections(elf):
    return [{
        "name": sec.name,
        "type": sec.header["sh_type"],
        "addr": int(sec.header["sh_addr"]),
        "offset": int(sec.header["sh_offset"]),
        "size": int(sec.header["sh_size"]),
        "flags": int(sec.header["sh_flags"]),
    } for sec in elf.iter_sections()]


def _segments(elf):
    return [{
        "type": seg.header["p_type"],
        "vaddr": int(seg.header["p_vaddr"]),
        "paddr": int(seg.header["p_paddr"]),
        "offset": int(seg.header["p_offset"]),
        "filesz": int(seg.header["p_filesz"]),
        "memsz": int(seg.header["p_memsz"]),
        "flags": int(seg.header["p_flags"]),
    } for seg in elf.iter_segments()]


def _capstone(arch, opts):
    _require_dependency(_CAPSTONE_IMPORT_ERROR, "capstone")
    import capstone
    arch_const, mode_const = _arch_mode(capstone, _CAPSTONE_ARCH, arch, opts)
    md = Cs(arch_const, mode_const)
    if opts.get("detail") is not None:
        md.detail = bool(opts["detail"])
    return md


def _keystone(arch, opts):
    _require_dependency(_KEYSTONE_IMPORT_ERROR, "keystone")
    import keystone
    arch_const, mode_const = _arch_mode(keystone, _KEYSTONE_ARCH, arch, opts)
    return Ks(arch_const, mode_const)


def _arch_mode(module, table, arch, opts):
    key = str(arch).lower()
    if key not in table:
        raise ValueError(f"unsupported architecture: {arch}")
    arch_name, mode_name = table[key]
    mode = getattr(module, mode_name)
    endian = str(opts.get("endian", "")).lower()
    if endian == "little" and hasattr(module, "CS_MODE_LITTLE_ENDIAN"):
        mode |= module.CS_MODE_LITTLE_ENDIAN
    elif endian == "big" and hasattr(module, "CS_MODE_BIG_ENDIAN"):
        mode |= module.CS_MODE_BIG_ENDIAN
    if endian == "little" and hasattr(module, "KS_MODE_LITTLE_ENDIAN"):
        mode |= module.KS_MODE_LITTLE_ENDIAN
    elif endian == "big" and hasattr(module, "KS_MODE_BIG_ENDIAN"):
        mode |= module.KS_MODE_BIG_ENDIAN
    return getattr(module, arch_name), mode


def _instruction(insn):
    return {
        "address": int(insn.address),
        "size": int(insn.size),
        "bytes": bytes(insn.bytes).hex(),
        "mnemonic": insn.mnemonic,
        "opStr": insn.op_str,
        "text": (insn.mnemonic + (" " + insn.op_str if insn.op_str else "")).strip(),
    }


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, list):
        return bytes(int(x) & 0xff for x in value)
    if isinstance(value, str):
        cleaned = value.strip().replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        return bytes.fromhex(cleaned)
    raise TypeError(f"unsupported bytes input: {type(value).__name__}")


def _constants(module, prefixes):
    return {name: int(getattr(module, name)) for name in dir(module)
            if name.startswith(prefixes) and isinstance(getattr(module, name), int)}
