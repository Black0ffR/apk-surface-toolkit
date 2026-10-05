"""Pure-Python binary AXML (AndroidManifest.xml) parser.

Why this exists: apktool is a JVM application. On a phone it is usually present,
but it is a single point of failure, and it can fail outright on protected or
heavily-modified packages. The manifest is the highest-value input this tool has
and it is not that hard to read directly.

The binary format is a chunk stream:
    ResChunk_header { u16 type, u16 headerSize, u32 size }
      0x0001 string pool
      0x0180 resource map
      0x0100/0x0101 start/end namespace
      0x0102/0x0103 start/end element
      0x0104 cdata

Standard library only. Parses to an ElementTree, which manifest.parse() then
consumes unchanged -- so there is exactly one manifest logic path in this tool.
"""
from __future__ import annotations

import struct
import zipfile
from xml.etree import ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)

RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 1 << 8


class AxmlError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _parse_string_pool(data: bytes, start: int) -> list[str]:
    """Decode a RES_STRING_POOL chunk. Handles both UTF-8 and UTF-16 pools."""
    count = _u32(data, start + 8)
    style_count = _u32(data, start + 12)
    flags = _u32(data, start + 16)
    strings_start = _u32(data, start + 20)
    utf8 = bool(flags & UTF8_FLAG)

    offsets = [_u32(data, start + 28 + 4 * i) for i in range(count)]
    base = start + strings_start
    out: list[str] = []
    for off in offsets:
        p = base + off
        if p >= len(data):
            out.append("")
            continue
        try:
            if utf8:
                # A UTF-8 pool stores TWO length fields per string: the UTF-16
                # code-unit count, then the UTF-8 byte count. Reading only the
                # first truncates every string and leaves the second length byte
                # at the front -- "TextView" decodes as "\x08TextVie". Each may
                # use the 1-or-2-byte form.
                n16 = data[p]
                p += 1
                if n16 & 0x80:
                    n16 = ((n16 & 0x7F) << 8) | data[p]
                    p += 1
                n8 = data[p]
                p += 1
                if n8 & 0x80:
                    n8 = ((n8 & 0x7F) << 8) | data[p]
                    p += 1
                out.append(data[p:p + n8].decode("utf-8", "replace"))
            else:
                n = _u16(data, p)
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | _u16(data, p)
                    p += 2
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def _attr_value(pool: list[str], raw: int, data_type: int, data: int) -> str:
    if data_type == TYPE_STRING:
        return pool[data] if 0 <= data < len(pool) else ""
    if data_type == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if data != 0 else "false"
    if data_type == TYPE_INT_HEX:
        return f"0x{data:x}"
    if data_type in (TYPE_INT_DEC,):
        return str(struct.unpack("<i", struct.pack("<I", data))[0])
    if data_type == 0x04:  # float
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    # Fall back to the raw string reference before giving up.
    if raw != 0xFFFFFFFF and 0 <= raw < len(pool):
        return pool[raw]
    return str(data)


def parse_bytes(data: bytes) -> ET.Element:
    """Parse a binary AXML blob into an ElementTree Element."""
    if len(data) < 8:
        raise AxmlError("not an AXML blob (too short)")
    magic_type, header_size, _size = struct.unpack_from("<HHI", data, 0)
    if magic_type != RES_XML_TYPE:
        raise AxmlError(f"not AXML: type=0x{magic_type:04x}")

    pool: list[str] = []
    root: ET.Element | None = None
    stack: list[ET.Element] = []
    ns_seen = False

    off = header_size
    total = len(data)
    while off + 8 <= total:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
        if csize == 0:
            break
        if ctype == RES_STRING_POOL_TYPE:
            pool = _parse_string_pool(data, off)
        elif ctype == RES_XML_START_NAMESPACE:
            if not ns_seen:
                prefix = pool[_u32(data, off + 16)] if _u32(data, off + 16) < len(pool) else ""
                uri = pool[_u32(data, off + 20)] if _u32(data, off + 20) < len(pool) else ""
                if uri == ANDROID_NS:
                    ns_seen = True
        elif ctype == RES_XML_START_ELEMENT:
            name_idx = _u32(data, off + 20)
            attr_start = _u16(data, off + 24)
            attr_size = _u16(data, off + 26)
            attr_count = _u16(data, off + 28)
            tag = pool[name_idx] if name_idx < len(pool) else "unknown"
            el = ET.Element(tag)
            a_base = off + 16 + attr_start
            for i in range(attr_count):
                ao = a_base + i * attr_size
                if ao + 20 > total:
                    break
                a_ns = _u32(data, ao)
                a_name = _u32(data, ao + 4)
                a_raw = _u32(data, ao + 8)
                a_dtype = data[ao + 15]
                a_data = _u32(data, ao + 16)
                name = pool[a_name] if a_name < len(pool) else f"a{a_name}"
                uri = pool[a_ns] if a_ns < len(pool) else ""
                val = _attr_value(pool, a_raw, a_dtype, a_data)
                el.set(f"{{{uri}}}{name}" if uri else name, val)
            if stack:
                stack[-1].append(el)
            else:
                root = el
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        elif ctype == RES_XML_CDATA:
            # Element text lives in CDATA chunks, not in the start element.
            # Dropping these is how <domain>www.example.com</domain> ends up
            # looking empty, which silently guts pin-set analysis.
            if stack:
                ci = _u32(data, off + 16)
                if ci < len(pool):
                    stack[-1].text = (stack[-1].text or "") + pool[ci]
        off += csize

    if root is None:
        raise AxmlError("no root element found")
    return root


def extract_manifest_xml(apk_path: str) -> bytes:
    """Read AndroidManifest.xml out of the APK as raw (binary) bytes."""
    with zipfile.ZipFile(apk_path) as z:
        return z.read("AndroidManifest.xml")


def _attr_name(key: str) -> str:
    if key.startswith("{"):
        uri, local = key[1:].split("}", 1)
        return f"android:{local}" if uri == ANDROID_NS else local
    return key


def to_xml_string(root: ET.Element) -> str:
    """Serialise to text XML.

    Written by hand rather than via ET.tostring(root): the root element carries
    the package/version attributes we care most about, and a blanket string
    slice to inject the xmlns declaration will happily eat the root's closing
    bracket and all of them with it.
    """
    attrs = "".join(
        f' {_attr_name(k)}="{_escape_attr(v)}"' for k, v in root.attrib.items()
    )
    children = "".join(ET.tostring(c, encoding="unicode") for c in root)
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            f'<manifest xmlns:android="{ANDROID_NS}"{attrs}>{children}</manifest>')


def _escape_attr(v: str) -> str:
    return (v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))
