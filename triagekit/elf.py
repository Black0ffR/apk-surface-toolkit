"""ELF-01: bounds-checked ELF address resolver + minimal ELF parsing.

Shared resolver for native triage (plan §14). Address concepts stay
explicit: file offset (bytes in the .so file), ELF virtual address
(p_vaddr from PT_LOAD), runtime virtual address (VA + load bias). File
offset != VA in general; BSS-only bytes are never mapped to a file
offset; overlapping mappings are reported as ambiguous and never
silently confirmed.

Everything here is stdlib (`struct`) and passes on untrusted bytes:
malformed input raises `ElfFormatError` instead of guessing.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

PT_LOAD = 1
SHT_DYNSYM = 11
SHT_STRTAB = 3
SHN_UNDEF = 0

STB_GLOBAL = 1
STB_WEAK = 2
STT_FUNC = 2

_MACHINE_NAMES = {3: "x86", 8: "mips", 20: "powerpc", 40: "arm",
                  62: "x86-64", 183: "aarch64"}


class ElfFormatError(ValueError):
    """Raised on malformed ELF input; never a silent guess."""


@dataclass(frozen=True)
class LoadSegment:
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int


class ElfImage:
    """Parsed ELF image facts needed for address mapping (read-only)."""

    __slots__ = ("elf_class", "byteorder", "machine", "entry", "loads")

    def __init__(self, elf_class: str, byteorder: str, machine: int,
                 entry: int, loads: list[LoadSegment]):
        self.elf_class = elf_class
        self.byteorder = byteorder
        self.machine = machine
        self.entry = entry
        self.loads = loads

    @property
    def machine_name(self) -> str:
        return machine_name(self.machine)


def machine_name(machine: int) -> str:
    return _MACHINE_NAMES.get(machine, f"machine-{machine}")


def _ident(data: bytes) -> tuple[int, bool]:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ElfFormatError("missing ELF magic")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ElfFormatError(f"unknown EI_CLASS {ei_class}")
    if ei_data not in (1, 2):
        raise ElfFormatError(f"unknown EI_DATA {ei_data}")
    return ei_class, ei_data == 1


def parse(data: bytes) -> ElfImage:
    """Parse header + PT_LOAD program headers. Malformed input raises."""
    ei_class, little = _ident(data)
    is64 = ei_class == 2
    end = "<" if little else ">"
    ehdr_extra = ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    ehdr_size = 16 + struct.calcsize(end + ehdr_extra)
    if len(data) < ehdr_size:
        raise ElfFormatError("truncated ELF header")
    (e_type, e_machine, _ver, e_entry, e_phoff, _shoff, _flags,
     _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = \
        struct.unpack_from(end + ehdr_extra, data, 16)
    phfmt = end + ("IIQQQQIQ" if is64 else "IIIIIIII")
    phentsize = struct.calcsize(phfmt)
    if e_phnum and e_phentsize < phentsize:
        raise ElfFormatError(
            f"e_phentsize {e_phentsize} smaller than PT_LOAD needs {phentsize}")
    if e_phnum:
        table = e_phoff + e_phnum * e_phentsize
        if table > len(data):
            raise ElfFormatError(
                f"program header table out of bounds ({table} > {len(data)})")
    loads: list[LoadSegment] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + phentsize > len(data):
            raise ElfFormatError("truncated program header")
        if is64:
            p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags, \
                p_align = struct.unpack_from(phfmt, data, off)
        else:
            (p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz,
             p_flags, p_align) = struct.unpack_from(phfmt, data, off)
        if p_type != PT_LOAD:
            continue
        if p_filesz > p_memsz:
            raise ElfFormatError(
                f"PT_LOAD {i}: p_filesz exceeds p_memsz")
        if p_align and p_align & (p_align - 1):
            raise ElfFormatError(
                f"PT_LOAD {i}: p_align {hex(p_align)} not a power of two")
        loads.append(LoadSegment(p_offset, p_vaddr, p_filesz, p_memsz,
                                 p_flags, p_align))
    return ElfImage("elf64" if is64 else "elf32",
                    "little" if little else "big",
                    e_machine, e_entry, loads)


# --------------------------------------------------------------- mapping


def find_file_backings(offset: int, segments: list[LoadSegment]) -> list[LoadSegment]:
    """All PT_LOAD segments whose file-backed range contains the offset."""
    return [s for s in segments
            if s.file_offset <= offset < s.file_offset + s.file_size]


def find_va_backings(va: int, segments: list[LoadSegment]) -> list[LoadSegment]:
    """All PT_LOAD segments whose memory range contains the VA."""
    return [s for s in segments
            if s.virtual_address <= va < s.virtual_address + s.memory_size]


def file_offset_to_va(offset: int, segments: list[LoadSegment]) -> int | None:
    """Map only when the offset lies in a segment's file-backed range.

    None when unmapped or ambiguous (more than one PT_LOAD backs the
    offset); ambiguity is never silently resolved to a single VA.
    """
    backs = find_file_backings(offset, segments)
    if len(backs) != 1:
        return None
    s = backs[0]
    return s.virtual_address + (offset - s.file_offset)


def va_to_file_offset(va: int, segments: list[LoadSegment]) -> int | None:
    """Best exact file-offset mapping or None.

    None for VAs without file backing (BSS-only page tail), unmapped VAs,
    and ambiguous multi-mapping.
    """
    backs = find_va_backings(va, segments)
    if len(backs) != 1:
        return None
    s = backs[0]
    delta = va - s.virtual_address
    if delta >= s.file_size:
        return None  # memory-only (BSS) page tail has no file bytes
    return s.file_offset + delta


def va_to_runtime(va: int, load_bias: int) -> int:
    return va + load_bias


def runtime_to_va(runtime_va: int, load_bias: int) -> int:
    return runtime_va - load_bias


MAPPING_STATUSES = ("static-file-mapping", "memory-only", "unmapped",
                    "ambiguous")


def describe_location(segments: list[LoadSegment], *, va: int | None = None,
                      file_offset: int | None = None,
                      library_sha256: str = "", abi: str = "",
                      load_bias: int | None = None,
                      runtime_address: int | None = None) -> dict:
    """Plan §14.4 location record: address kind + ELF identity together.

    `load_bias`/`runtime_address` are None from static analysis; callers
    with runtime knowledge fill them in explicitly.
    """
    backs_file = (find_file_backings(file_offset, segments)
                  if file_offset is not None else [])
    if va is None and file_offset is not None:
        va = file_offset_to_va(file_offset, segments)
    backs_va = find_va_backings(va, segments) if va is not None else []
    ambiguous = len(backs_file) > 1 or len(backs_va) > 1
    if ambiguous:
        status = "ambiguous"
    elif va is None or not backs_va:
        status = "unmapped"
        if file_offset is None:
            file_offset = None
    elif file_offset is None:
        file_offset = va_to_file_offset(va, segments)
        status = "static-file-mapping" if file_offset is not None \
            else "memory-only"
    else:
        status = "static-file-mapping"
    # A location record reports what the ELF resolves to. Unmapped or
    # ambiguous queries carry no confirmed VA — the status says why.
    if status in ("unmapped", "ambiguous"):
        va = None
    return {
        "library_sha256": library_sha256,
        "abi": abi,
        "file_offset": file_offset,
        "elf_virtual_address": va,
        "runtime_address": runtime_address,
        "load_bias": load_bias,
        "mapping_status": status,
    }


# ------------------------------------------------------- dynamic symbols


def parse_dynamic_symbols(data: bytes, image: ElfImage | None = None
                          ) -> tuple[list[dict], list[str]]:
    """Parse SHT_DYNSYM sections. Returns (symbols, errors).

    Symbol dicts carry {"name", "value", "size", "type", "bind", "shndx",
    "defined"}. Malformed tables are reported in `errors` and skipped —
    never a partial silent guess, never a crash.
    """
    img = image if image is not None else parse(data)
    is64 = img.elf_class == "elf64"
    end = "<" if img.byteorder == "little" else ">"
    ehdr_extra = ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    ehdr_size = 16 + struct.calcsize(end + ehdr_extra)
    sym_fmt = end + ("IBBHQQ" if is64 else "IIIBBH")
    syment = struct.calcsize(sym_fmt)
    shfmt = end + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    shentsize = struct.calcsize(shfmt)

    (e_type, e_machine, _ver, _entry, _phoff, e_shoff, _flags,
     _ehsize, _phentsize, _phnum, e_shentsize, e_shnum, _shstrndx) = \
        struct.unpack_from(end + ehdr_extra, data, 16)
    errors: list[str] = []
    if e_shnum == 0 or e_shoff == 0:
        return [], errors  # no section table -> no symbols (still honest)
    shentsize = e_shentsize if e_shentsize >= shentsize else shentsize
    if e_shoff + e_shnum * shentsize > len(data):
        errors.append(f"section header table out of bounds "
                      f"(e_shoff {e_shoff}, e_shnum {e_shnum})")
        return [], errors

    def _shdr(i: int):
        return struct.unpack_from(shfmt, data, e_shoff + i * shentsize)

    sym_secs, str_secs = [], []
    for i in range(e_shnum):
        (sh_name, sh_type, _flags, _addr, sh_off, sh_size,
         sh_link, _info, _align, _entsize) = _shdr(i)
        if sh_type == SHT_DYNSYM:
            sym_secs.append((i, sh_off, sh_size, sh_link))
        elif sh_type == SHT_STRTAB:
            str_secs.append((i, sh_off, sh_size))

    def _strsec_data(idx: int) -> bytes | None:
        for i, off, size in str_secs:
            if i == idx:
                if off + size > len(data):
                    errors.append(f"string table {idx} out of bounds")
                    return None
                return data[off:off + size]
        return None

    out: list[dict] = []
    for _, sym_off, sym_size, sh_link in sym_secs:
        if sym_off + sym_size > len(data):
            errors.append(f"dynamic symbol table at {sym_off} "
                          f"exceeds file bounds")
            continue
        tab = False
        tab = sh_link in range(e_shnum)
        if not tab:
            errors.append(f"dynsym sh_link {sh_link} outside section table")
            continue
        tabi, st_off, st_size = None, 0, 0
        for i, off, size in str_secs:
            if i == sh_link:
                tabi = i
                st_off, st_size = off, size
                break
        if tabi is None:
            errors.append(f"dynsym links section {sh_link} which is not "
                          f"SHT_STRTAB")
            continue
        if st_off + st_size > len(data):
            errors.append(f"linked strtab {sh_link} out of bounds")
            continue
        strsec = data[st_off:st_off + st_size]
        if sh_size == 0 or (syment and sym_size % syment):
            errors.append(f"dynsym at {sym_off}: invalid symtab size "
                          f"{sym_size} (ent {syment})")
            continue
        for o in range(0, sym_size, syment):
            if o + syment > sym_size:
                errors.append(f"dynsym at {sym_off}: truncated entry")
                break
            raw_off = sym_off + o
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(sym_fmt, data, raw_off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from(sym_fmt, data, raw_off)
            if st_name >= len(strsec):
                errors.append(f"dynsym entry: name offset {st_name} "
                              f"exceeds strtab {len(strsec)}")
                continue
            stz = strsec.find(b"\x00", st_name)
            if stz < 0:
                stz = len(strsec)
            name = strsec[st_name:stz].decode("utf-8", "replace")
            out.append({
                "name": name,
                "value": st_value,
                "size": st_size,
                "type": "func" if st_info & 0xF == STT_FUNC
                        else "unknown",
                "bind": {0: "local", STB_GLOBAL: "global",
                         STB_WEAK: "weak"}.get(st_info >> 4, "unknown"),
                "shndx": st_shndx,
                "defined": st_shndx != SHN_UNDEF and st_value != 0,
            })
    # deterministic order: symbol table order is already deterministic
    return out, errors


def parse_symbols(data: bytes) -> tuple[list[dict], list[str]]:
    """Back-compat alias of parse_dynamic_symbols."""
    return parse_dynamic_symbols(data)
