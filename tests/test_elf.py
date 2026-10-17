"""ELF-01 regression tests. Synthetic struct-built fixtures only.

Contracts under test:
- elf.parse(): explicit ELF32/ELF64 + both byte orders; malformed input
  raises ElfFormatError, never a silent guess.
- Bounds-checked file-offset/VA/runtime mappings (plan §14.3 API), with
  BSS-only VAs never mapped to file offsets and ambiguous mappings never
  silently confirmed.
- describe_location() output contract (plan §14.4).
- Dynamic symbol table parsing for JNI correlation (errors reported,
  never partial-guess crashes).
"""
from __future__ import annotations

import struct
import unittest

from triagekit import elf as ELF
from triagekit.elf import LoadSegment


def _seg(off, va, fsz, msz, flags=5, align=0x1000) -> LoadSegment:
    return LoadSegment(file_offset=off, virtual_address=va, file_size=fsz,
                       memory_size=msz, flags=flags, alignment=align)


_EHDR_FMT = {64: "HHIQQQIHHHHHH", 32: "HHIIIIIHHHHHH"}

# ELF64 program header order is type, flags, offset, vaddr, paddr,
# filesz, memsz, align (p_flags is the SECOND field, not the seventh).
_PHDR_FMT = {64: "IIQQQQQQ", 32: "IIIIIIII"}


def _build(loads: list[tuple], *, elf_class: int = 64, little: bool = True,
           phnum: int | None = None, shoff: int = 0, shnum: int = 0) -> bytes:
    """Minimal ELF image: identifier + program headers (+ section table
    pointer fields when asked)."""
    is64 = elf_class == 64
    end = "<" if little else ">"
    ident = (b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, 0])
             + b"\x00" * 8)
    fmt_hdr = end + _EHDR_FMT[elf_class]
    phfmt = end + _PHDR_FMT[elf_class]
    phentsize = struct.calcsize(phfmt)
    ehdr_size = 16 + struct.calcsize(fmt_hdr)
    phoff = ehdr_size
    fields = (3, 183 if is64 else 40, 1,
              0x1000, phoff, shoff, 0,
              ehdr_size, phentsize,
              len(loads) if phnum is None else phnum,
              64 if is64 else 40, shnum, 0)
    hdr = ident + struct.pack(fmt_hdr, *fields)
    def ph_row(t: tuple) -> bytes:
        off, va, fsz, msz = t[0], t[1], t[2], t[3]
        flags = t[4] if len(t) > 4 else 5
        align = t[5] if len(t) > 5 else 0x1000
        if is64:
            # ELF64: type, flags, offset, vaddr, paddr, filesz, memsz, align
            return struct.pack(phfmt, 1, flags, off, va, va, fsz, msz, align)
        # ELF32: type, offset, vaddr, paddr, filesz, memsz, flags, align
        return struct.pack(phfmt, 1, off, va, va, fsz, msz, flags, align)
    ph = b"".join(ph_row(t) for t in loads)
    return hdr + ph


_SYM_FMT = {64: "IBBHQQ", 32: "IIIBBH"}

_SHDR_FMT = {64: "IIQQQQIIQQ", 32: "IIIIIIIIII"}


def _build_symtab(symbols: list[dict], *, elf_class: int = 64,
                  little: bool = True, sym_size_extra: int = 0,
                  bad_sh_link: bool = False) -> bytes:
    """Minimal ELF with a .dynsym (SHT_DYNSYM) + linked .dynstr table."""
    is64 = elf_class == 64
    end = "<" if little else ">"
    shdr_fmt = end + _SHDR_FMT[elf_class]
    shentsize = struct.calcsize(shdr_fmt)

    strtab = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for s in symbols:
        nm = s.get("name", "")
        offsets[nm] = len(strtab)
        strtab += nm.encode() + b"\x00"
    symtab = bytearray()
    symfmt = end + _SYM_FMT[elf_class]
    for s in symbols:
        st_name = offsets.get(s.get("name", ""), 0)
        if is64:
            symtab += struct.pack(symfmt, st_name, s.get("info", 0x12),
                                  s.get("other", 0), s.get("shndx", 2),
                                  s.get("value", 0), s.get("size", 0))
        else:
            symtab += struct.pack(symfmt, st_name, s.get("value", 0),
                                  s.get("size", 0), s.get("info", 0x12),
                                  s.get("other", 0), s.get("shndx", 2))
    sym_size = len(symbols) * (24 if is64 else 16)

    loads = [(0x0, 0x10000, 0x800, 0x800, 5, 0x1000)]
    head = _build(loads, elf_class=elf_class, little=little,
                  shoff=0, shnum=3)
    shoff = len(head)
    strtab_off = shoff + 3 * shentsize
    symtab_off = strtab_off + len(strtab)

    shdrs = b""
    # null section
    shdrs += struct.pack(shdr_fmt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    # .dynstr (index 1), SHT_STRTAB
    shdrs += struct.pack(shdr_fmt, 0, 3, 0, 0x10000, strtab_off,
                         len(strtab), 0, 0, 1, 0)
    # .dynsym (index 2), SHT_DYNSYM, sh_link -> 1 (OOB when corrupt)
    shdrs += struct.pack(shdr_fmt, 0, 11, 0, 0x10000, symtab_off,
                         sym_size + sym_size_extra,
                         7 if bad_sh_link else 1, 1, 8,
                         24 if is64 else 16)
    # rebuild the header so e_shoff/e_shnum land inside the file
    head = _build(loads, elf_class=elf_class, little=little,
                  shoff=shoff, shnum=3)
    # layout: [head][shdrs][strtab][symtab] — all declared offsets exact
    return head + shdrs + bytes(strtab) + bytes(symtab)


class TestFileOffsetToVa(unittest.TestCase):
    def test_contains_and_bounds(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        self.assertEqual(ELF.file_offset_to_va(0x1000, segs), 0x20000)
        self.assertEqual(ELF.file_offset_to_va(0x1400, segs), 0x20400)
        self.assertEqual(ELF.file_offset_to_va(0x17FF, segs), 0x207FF)
        self.assertIsNone(ELF.file_offset_to_va(0x1800, segs))
        self.assertIsNone(ELF.file_offset_to_va(0, segs))

    def test_multi_load_nearest_segment(self):
        segs = [_seg(0x0, 0x0, 0x800, 0x800),
                _seg(0x1000, 0x20000, 0x800, 0x800)]
        self.assertEqual(ELF.file_offset_to_va(0x0, segs), 0x0)
        self.assertEqual(ELF.file_offset_to_va(0x1000, segs), 0x20000)

    def test_ambiguous_overlap_never_confirmed(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x800),
                _seg(0x1000, 0x30000, 0x800, 0x800)]
        self.assertIsNone(ELF.file_offset_to_va(0x1400, segs))
        backs = ELF.find_file_backings(0x1400, segs)
        self.assertEqual(len(backs), 2)


class TestVaToFileOffset(unittest.TestCase):
    def test_file_backed_range(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        self.assertEqual(ELF.va_to_file_offset(0x20000, segs), 0x1000)
        self.assertEqual(ELF.va_to_file_offset(0x207FF, segs), 0x17FF)

    def test_bss_only_va_returns_none(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        # 0x20800..0x21000 is within p_memsz but beyond p_filesz
        self.assertIsNone(ELF.va_to_file_offset(0x20800, segs))
        self.assertIsNone(ELF.va_to_file_offset(0x20900, segs))

    def test_unmapped_va_returns_none(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        self.assertIsNone(ELF.va_to_file_offset(0x21000, segs))

    def test_ambiguous_va_never_confirmed(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x800),
                _seg(0x2000, 0x20400, 0x800, 0x800)]
        self.assertIsNone(ELF.va_to_file_offset(0x20400, segs))
        self.assertEqual(len(ELF.find_va_backings(0x20400, segs)), 2)


class TestRuntimeMapping(unittest.TestCase):
    def test_round_trip_with_bias(self):
        self.assertEqual(ELF.va_to_runtime(0x1000, 0x500000), 0x501000)
        self.assertEqual(ELF.runtime_to_va(0x501000, 0x500000), 0x1000)
        self.assertEqual(ELF.va_to_runtime(0x1000, 0), 0x1000)


class TestParse(unittest.TestCase):
    def test_elf64_little(self):
        data = _build([(0x0, 0x10000, 0x800, 0x800),
                       (0x1000, 0x20000, 0x800, 0x1000)])
        img = ELF.parse(data)
        self.assertEqual(img.elf_class, "elf64")
        self.assertEqual(img.byteorder, "little")
        self.assertEqual(len(img.loads), 2)
        self.assertEqual(img.loads[0].virtual_address, 0x10000)
        self.assertEqual(img.loads[1].memory_size, 0x1000)
        self.assertEqual(img.machine_name, "aarch64")

    def test_elf64_phdr_field_order(self):
        # Regression: ELF64 p_flags is the second field. A parser that
        # assigns fields in ELF32 order misreads flags/offset/filesz and
        # can reject a valid segment. Distinct values catch the shift.
        data = _build([(0x1000, 0x20000, 0x800, 0x1000, 0x6, 0x1000)])
        img = ELF.parse(data)
        seg = img.loads[0]
        self.assertEqual(seg.file_offset, 0x1000)
        self.assertEqual(seg.virtual_address, 0x20000)
        self.assertEqual(seg.file_size, 0x800)
        self.assertEqual(seg.memory_size, 0x1000)
        self.assertEqual(seg.flags, 0x6)
        self.assertEqual(seg.alignment, 0x1000)

    def test_elf64_filesz_less_than_memsz_accepted(self):
        # Valid BSS tail: filesz < memsz must parse (the reported bug was a
        # valid segment being rejected as "filesz exceeds memsz").
        data = _build([(0x0, 0x0, 0xa70, 0xa80)])
        img = ELF.parse(data)
        self.assertEqual(img.loads[0].file_size, 0xa70)
        self.assertEqual(img.loads[0].memory_size, 0xa80)

    def test_elf32_little(self):
        data = _build([(0x0, 0x8000, 0x400, 0x400)], elf_class=32)
        img = ELF.parse(data)
        self.assertEqual(img.elf_class, "elf32")
        self.assertEqual(img.machine_name, "arm")

    def test_big_endian(self):
        data = _build([(0x1000, 0x20000, 0x800, 0x800)], little=False)
        img = ELF.parse(data)
        self.assertEqual(img.byteorder, "big")
        self.assertEqual(img.loads[0].virtual_address, 0x20000)

    def test_malformed_phnum_raises(self):
        data = _build([(0x0, 0x10000, 0x800, 0x800)], phnum=5)
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(data)

    def test_truncated_header_raises(self):
        data = _build([(0x0, 0x10000, 0x800, 0x800)])[:40]
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(data)

    def test_empty_and_garbage_raise(self):
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(b"")
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(b"not an elf file at all" * 4)
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(b"\x7fELF" + b"\x99" * 12)

    def test_filesz_exceeding_memsz_rejected(self):
        data = _build([(0x1000, 0x20000, 0x900, 0x800)])
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse(data)


class TestDescribeLocation(unittest.TestCase):
    def test_static_file_mapping_record(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        rec = ELF.describe_location(segs, file_offset=0x1400,
                                    library_sha256="abc", abi="arm64-v8a")
        self.assertEqual(rec["file_offset"], 0x1400)
        self.assertEqual(rec["elf_virtual_address"], 0x20400)
        self.assertIsNone(rec["runtime_address"])
        self.assertIsNone(rec["load_bias"])
        self.assertEqual(rec["mapping_status"], "static-file-mapping")
        self.assertEqual(rec["library_sha256"], "abc")
        self.assertEqual(rec["abi"], "arm64-v8a")

    def test_memory_only_record(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        rec = ELF.describe_location(segs, va=0x20900, library_sha256="abc")
        self.assertIsNone(rec["file_offset"])
        self.assertEqual(rec["elf_virtual_address"], 0x20900)
        self.assertEqual(rec["mapping_status"], "memory-only")

    def test_unmapped_record(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x1000)]
        rec = ELF.describe_location(segs, va=0x99999)
        self.assertIsNone(rec["elf_virtual_address"])
        self.assertEqual(rec["mapping_status"], "unmapped")

    def test_ambiguous_record_is_explicit(self):
        segs = [_seg(0x1000, 0x20000, 0x800, 0x800),
                _seg(0x1000, 0x30000, 0x800, 0x800)]
        rec = ELF.describe_location(segs, file_offset=0x1400)
        self.assertIsNone(rec["elf_virtual_address"])
        self.assertEqual(rec["mapping_status"], "ambiguous")


class TestSymbols(unittest.TestCase):
    def test_dynsym_symbols_parsed(self):
        symbols = [
            {"name": "Java_com_example_Foo_getData", "value": 0x1008,
             "size": 32, "info": 0x12, "shndx": 2},
            {"name": "", "value": 0, "size": 0, "info": 0,
             "shndx": 0},
        ]
        data = _build_symtab(symbols)
        syms, errors = ELF.parse_dynamic_symbols(data)
        self.assertEqual(errors, [])
        self.assertEqual(len(syms), 2)
        defined = {s["name"] for s in syms if s["defined"]}
        self.assertEqual(defined, {"Java_com_example_Foo_getData"})
        fn = [s for s in syms if s["name"] == "Java_com_example_Foo_getData"][0]
        self.assertEqual(fn["value"], 0x1008)
        self.assertEqual(fn["type"], "func")
        self.assertEqual(fn["bind"], "global")

    def test_elf32_symtab(self):
        symbols = [{"name": "JNI_OnLoad", "value": 0x4,
                    "info": 0x12, "shndx": 2, "size": 16}]
        data = _build_symtab(symbols, elf_class=32)
        syms, errors = ELF.parse_dynamic_symbols(data)
        self.assertEqual(errors, [])
        self.assertEqual(syms[0]["name"], "JNI_OnLoad")
        self.assertEqual(syms[0]["value"], 0x4)

    def test_truncated_dynsym_reports_error_not_crash(self):
        symbols = [{"name": "Java_com_example_Foo_getData",
                    "value": 0x1008, "shndx": 2}]
        data = _build_symtab(symbols, sym_size_extra=64)
        syms, errors = ELF.parse_dynamic_symbols(data)
        self.assertTrue(errors, "expected an error about truncated symtab")

    def test_bad_sh_link_reports_error_not_crash(self):
        symbols = [{"name": "JNI_OnLoad", "value": 0x4, "shndx": 2}]
        data = _build_symtab(symbols, bad_sh_link=True)
        syms, errors = ELF.parse_dynamic_symbols(data)
        self.assertTrue(any("link" in e.lower() for e in errors))

    def test_non_elf_input_raises(self):
        with self.assertRaises(ELF.ElfFormatError):
            ELF.parse_dynamic_symbols(b"this is not an elf" + b"\x00" * 64)
