"""Parser and safe repacker for SolidWorks 2015+ ROL-obfuscated ZIP containers."""

from __future__ import annotations

import logging
import re
import struct
import zlib

from lxml import etree

from ..config import SAFE_CAD_VENDORS, SAFE_DOMAINS
from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .image_handler import process_image_bytes

log = logging.getLogger(__name__)

MARKER = b"\x14\x00\x06\x00\x08\x00"
XML_STREAM_PREFIXES = ("docprops/", "swxmlcontents/")
TEXT_LIKE_STREAMS = {
    "docprops/core.xml",
    "docprops/app.xml",
    "docprops/custom.xml",
    "docprops/isolidworksinformation.xml",
}
BIN_META_STREAMS = ("header2", "biography", "swdoccontentmgrinfo", "definition", "cmgr")


def is_modern_solidworks(data: bytes) -> bool:
    """Detect SolidWorks 2015+ modern chunked format."""
    if len(data) < 32:
        return False
    if data[:4] == b"\xd0\xcf\x11\xe0" or data[:4] == b"PK\x03\x04":
        return False
    return MARKER in data[:64]


def _rol_decode(raw: bytes, key: int) -> str:
    k = key & 7
    if k == 0:
        return raw.decode("utf-8", errors="replace")
    dec = bytes(((b << k) | (b >> (8 - k))) & 0xFF for b in raw)
    return dec.decode("utf-8", errors="replace")


def _is_printable_stream_name(name: str) -> bool:
    return bool(name) and all(0x20 <= ord(c) < 0x7F for c in name)


def parse_modern_container(data: bytes) -> dict:
    """Parse active inline chunks and Central Directory entries from a SW2015+ file."""
    key = data[7] & 7
    cd_entries: list[dict] = []
    local_chunks: dict[int, dict] = {}

    pos = 0
    while True:
        idx = data.find(MARKER, pos)
        if idx == -1:
            break
        pos = idx + 1

        # Check if this is a Central Directory entry (marker at +6 from 4-byte CD sig)
        if idx >= 6 and idx + 40 <= len(data):
            two_l, half_l, usz_cd, nsz_cd = struct.unpack_from("<IIII", data, idx + 0x0A)
            # CD entries have 0 at +0x0A and +0x12 (whereas inline local headers have crc & csz)
            if two_l == 0 and usz_cd == 0 and 1 <= nsz_cd < 500 and idx + 40 + nsz_cd <= len(data):
                csz_cd = half_l
                # Re-read full CD layout starting at sig (idx - 6)
                cd_sig_off = idx - 6
                if cd_sig_off + 46 + nsz_cd <= len(data):
                    type_id, crc, csz, usz, nsz = struct.unpack_from("<IIIII", data, idx + 6)
                    # Wait: in CD, offset +0x10 from sig (idx+0x0A) is crc32! Let's check:
                    pass

        # Parse inline local header if valid
        if idx + 0x1A <= len(data):
            type_id, f1, f2, f3, nsz = struct.unpack_from("<IIIII", data, idx + 6)
            # 1) CacheCell check: f1 == 2*f3 and f2 == f3//2 -> placeholder slot, skip!
            if f3 > 0 and f1 == (f3 * 2) and f2 == (f3 // 2):
                continue
            # 2) Directory entry check (matches openswx TryDirectoryEntry: f1==0 and f3==0)
            if f1 == 0 and f3 == 0 and idx >= 6 and 1 <= nsz < 500 and idx + 40 + nsz <= len(data):
                # Note: in real SW files f1 IS crc32 for CD? No: look at Schiebestange tail:
                # 8a318fc7 0000 1400 0600 0800 739bfa1b 765ce7e7 65040000 bd0b0000 0d000000 ... 46020000
                # Here f1=0xe7e75c76 (crc32), f2=0x465 (csz), f3=0xbbd (usz)!
                pass

            # Let's distinguish Local Header vs Central Directory Entry cleanly!
            # In Central Directory Entry: bytes [idx-2:idx] == b'\x00\x00' AND bytes [idx+26:idx+36] are zeros/small
            # AND loff at idx+36 points to actual_local_off = loff + 8 where data[loff+12:loff+18] == MARKER!
            is_cd = False
            if idx >= 6 and idx + 40 + nsz <= len(data) and 1 <= nsz < 500:
                if data[idx - 2 : idx] == b"\x00\x00":
                    loff = struct.unpack_from("<I", data, idx + 36)[0]
                    cand_marker = loff + 12
                    if cand_marker + 0x1A <= len(data) and data[cand_marker : cand_marker + 6] == MARKER:
                        nm = _rol_decode(data[idx + 40 : idx + 40 + nsz], key)
                        if _is_printable_stream_name(nm):
                            is_cd = True
                            cd_entries.append(
                                {
                                    "cd_off": idx - 6,
                                    "marker_off": idx,
                                    "crc": f1,
                                    "csz": f2,
                                    "usz": f3,
                                    "nsz": nsz,
                                    "loff": loff,
                                    "local_marker_off": cand_marker,
                                    "name": nm,
                                }
                            )
            if is_cd:
                continue

            # Inline Local Header candidate
            crc, csz, usz = f1, f2, f3
            if 1 <= nsz < 500 and csz < 64 * 1024 * 1024 and idx + 0x1A + nsz + csz <= len(data):
                nm = _rol_decode(data[idx + 0x1A : idx + 0x1A + nsz], key)
                if _is_printable_stream_name(nm):
                    comp_bytes = data[idx + 0x1A + nsz : idx + 0x1A + nsz + csz]
                    try:
                        raw = zlib.decompress(comp_bytes, -15)
                        if len(raw) == usz and (usz == 0 or (zlib.crc32(raw) & 0xFFFFFFFF) == crc):
                            local_chunks[idx] = {
                                "marker_off": idx,
                                "payload_off": idx + 0x1A + nsz,
                                "crc": crc,
                                "csz": csz,
                                "usz": usz,
                                "nsz": nsz,
                                "name": nm,
                                "raw": raw,
                            }
                    except Exception:
                        pass

    return {
        "key": key,
        "cd_entries": cd_entries,
        "local_chunks": local_chunks,
    }


def inspect_modern_solidworks(data: bytes) -> list[tuple[str, str]]:
    """Extract identifying strings from SW2015+ streams for Phase 1 discovery."""
    found: list[tuple[str, str]] = []
    if not is_modern_solidworks(data):
        return found
    parsed = parse_modern_container(data)
    # Prefer active CD-referenced streams if CD was found, else all valid local chunks
    active_markers = {e["local_marker_off"] for e in parsed["cd_entries"]} if parsed["cd_entries"] else None
    for m_off, chunk in parsed["local_chunks"].items():
        if active_markers is not None and m_off not in active_markers:
            continue
        name_l = chunk["name"].lower()
        raw: bytes = chunk["raw"]
        if not raw:
            continue
        if name_l.startswith("docprops/") or name_l.startswith("swxmlcontents/"):
            txt = raw.decode("utf-8", errors="replace")
            for tag in ("creator", "lastModifiedBy", "title", "subject", "description", "keywords"):
                for m in re.finditer(rf"<(?:[a-z0-9]+:)?{tag}[^>]*>([^<]+)</", txt, re.I):
                    val = m.group(1).strip()
                    if val:
                        etype = "USERNAME" if tag in {"creator", "lastModifiedBy"} else "PART_ID"
                        found.append((etype, val))
            for m in re.finditer(r'name="SW-(?:Author|Last Saved By|Folder Name|Title|Comments|Keywords)"[^>]*><vt:lpw?str>([^<]+)</', txt, re.I):
                val = m.group(1).strip()
                if val:
                    found.append(("PATH" if "\\" in val else "USERNAME", val))
            for m in re.finditer(r'(?:swPath|swImportedPath|swFile)="([^"]+)"', txt):
                found.append(("PATH", m.group(1)))
        elif "header2" in name_l:
            # Extract usernames ONLY from su_CStringArray right after moHeader_c (skip feature tree logs)
            arr_pos = raw.find(b"su_CStringArray")
            log_pos = raw.find(b"moLogs_c")
            region = raw[arr_pos : (log_pos if log_pos > arr_pos else arr_pos + 512)] if arr_pos != -1 else b""
            for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", region):
                s = u16.decode("utf-16-le", errors="ignore").strip()
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{2,24}", s):
                    found.append(("USERNAME", s))
        elif "biography" in name_l:
            for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", raw):
                s = u16.decode("utf-16-le", errors="ignore").strip()
                if ("\\" in s or "/" in s) and not re.match(r"^[A-Za-z]:\\(?:Windows|Program Files|ProgramData)\\", s, re.I):
                    found.append(("PATH", s))
    return found


def _scrub_sw_xml(raw: bytes, stream_name: str, registry: IdentityRegistry, scope: str) -> bytes:
    """De-identify XML streams (docProps/* and swXmlContents/*) cleanly via lxml."""
    prefix = b""
    xml_bytes = raw
    # SolidWorks swXmlContents/KeyWords sometimes has a 1-byte non-XML prefix before <?xml
    xml_start = raw.find(b"<?xml")
    if xml_start > 0 and xml_start < 16:
        prefix = raw[:xml_start]
        xml_bytes = raw[xml_start:]
    try:
        parser = etree.XMLParser(recover=False, remove_blank_text=False)
        root = etree.fromstring(xml_bytes, parser=parser)
    except Exception:
        txt = raw.decode("utf-8", errors="replace")
        new_txt = registry.replace_text(txt, scope, context="xml")
        return new_txt.encode("utf-8", errors="replace")

    name_l = stream_name.lower()

    def scrub_val(v: str, etype_hint: str | None = None) -> str:
        if not v or not v.strip():
            return v
        rep = registry.replace_text(v, scope, context="xml")
        if rep == v and etype_hint:
            low = v.strip().lower()
            if etype_hint == "ORG" and any(cv in low for cv in SAFE_CAD_VENDORS):
                return v
            p = registry.register(v.strip(), etype_hint, scope, is_global=False)
            if p:
                return p
        return rep

    for elem in root.iter():
        tag_local = etree.QName(elem).localname if isinstance(elem.tag, str) else ""
        # Core/App XML properties
        if tag_local in {"creator", "lastModifiedBy"} and elem.text:
            elem.text = scrub_val(elem.text, "USERNAME")
        elif tag_local in {"title", "subject", "description", "keywords"} and elem.text:
            elem.text = scrub_val(elem.text)
        elif tag_local == "Company" and elem.text:
            elem.text = scrub_val(elem.text, "ORG")
        elif tag_local == "property":
            pname = (elem.get("name") or "").lower()
            hint = None
            if any(k in pname for k in ("author", "saved by", "autor", "speicherung durch")):
                hint = "USERNAME"
            elif "folder" in pname or "ordner" in pname:
                hint = "PATH"
            for child in elem:
                ctag = etree.QName(child).localname if isinstance(child.tag, str) else ""
                if ctag in {"lpstr", "lpwstr"} and child.text:
                    if hint == "PATH":
                        child.text = registry.register_path(child.text, scope)
                    else:
                        child.text = scrub_val(child.text, hint)
        # swXmlContents attributes (cover swPath, swImportedPath, swName, swReference, Name, etc.)
        skip_attrs = {
            "id",
            "swID",
            "swObjCount",
            "swVersion",
            "swDocType",
            "swCreationTime",
            "swLastModifiedStamp",
            "swConfigurationFlags",
            "swFileRef",
            "swModelRef",
            "swMostRecentConfiguration",
            "swConfigurationNeedsUpdate",
            "swTransform",
            "Type",
            "Material",
            "pid",
            "fmtid",
        }
        for attr, av in list(elem.attrib.items()):
            if attr == "Type" and tag_local == "Reference" and name_l == "swxmlcontents/keywords":
                # The reference type repeats the component label in this stream.
                elem.set(attr, scrub_val(av))
                continue
            if not av or attr in skip_attrs or attr.startswith("xmlns"):
                continue
            if ("\\" in av or "/" in av) and not av.startswith(("http://", "https://")) or re.match(r"^[A-Za-z]:\\", av):
                elem.set(attr, registry.register_path(av, scope))
            elif attr in {"swPath", "swImportedPath", "swName", "swReference", "Name"}:
                elem.set(attr, scrub_val(av))
            else:
                rep = registry.replace_text(av, scope, context="xml")
                if rep != av:
                    elem.set(attr, rep)

    serialized = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return prefix + serialized


def _scrub_utf16_and_ascii_inplace(raw: bytes, registry: IdentityRegistry, scope: str) -> bytes:
    """Length-preserving UTF-16LE and ASCII scrubbing for MFC binary streams (Header2, Biography, etc.)."""
    buf = bytearray(raw)
    # 1. Scrub UTF-16LE runs (length >= 4 chars) keeping exact byte length so MFC length headers stay valid!
    for m in re.finditer(rb"(?:[\x20-\x7e\x80-\xff]\x00){4,}", raw):
        s = m.group(0).decode("utf-16-le", errors="ignore")
        # Ignore internal MFC class names and system paths
        if s.startswith(("mo", "su", "dm", "visState")) or "C:\\Windows" in s:
            continue
        new_b = registry.replace_fixed_length(s, scope, encoding="utf-16-le")
        if len(new_b) == len(m.group(0)) and new_b != m.group(0):
            buf[m.start() : m.end()] = new_b

    # 2. Scrub any raw ASCII runs (length >= 4) that match registered tokens or UNC/email/paths
    cur = bytes(buf)
    for m in re.finditer(rb"[\x20-\x7e]{4,}", cur):
        s = m.group(0).decode("latin1")
        if s.startswith(("mo", "su", "dm", "SCH_", "PS\x00")):
            continue
        new_b = registry.replace_fixed_length(s, scope, encoding="latin1")
        if len(new_b) == len(m.group(0)) and new_b != m.group(0):
            buf[m.start() : m.end()] = new_b
    return bytes(buf)


def _deflate_exact_size(raw: bytes, target_csz: int) -> bytes | None:
    """Compress raw to exact target_csz using valid RFC-1951 raw DEFLATE if len <= target_csz."""
    # Try multiple compression levels and strategies to find one <= target_csz
    # and if possible with (target_csz - len) >= 5 or == 0
    best: bytes | None = None
    candidates: list[bytes] = []
    for level in (9, 6, 4, 1):
        comp = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=-15)
        c_full = comp.compress(raw) + comp.flush(zlib.Z_FINISH)
        candidates.append(c_full)
        if len(c_full) == target_csz:
            return c_full
        # Also try Z_SYNC_FLUSH open stream + final empty stored block (5B)
        comp_open = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=-15)
        c_open = comp_open.compress(raw) + comp_open.flush(zlib.Z_SYNC_FLUSH)
        diff = target_csz - len(c_open)
        if diff >= 5 and diff % 5 == 0:
            n_empty = (diff - 5) // 5
            padded = c_open + (b"\x00\x00\x00\xff\xff" * n_empty) + b"\x01\x00\x00\xff\xff"
            if len(padded) == target_csz:
                return padded

    # If raw is XML/text, try trimming whitespace or inserting spaces in an XML comment
    if raw.lstrip().startswith((b"<?xml", b"<")) and b"?>" in raw[:128]:
        for pad_len in range(0, 64):
            pad_raw = raw + (b" " * pad_len)
            comp_open = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
            c_open = comp_open.compress(pad_raw) + comp_open.flush(zlib.Z_SYNC_FLUSH)
            diff = target_csz - len(c_open)
            if diff >= 5 and diff % 5 == 0 and pad_len == 0:
                n_empty = (diff - 5) // 5
                return c_open + (b"\x00\x00\x00\xff\xff" * n_empty) + b"\x01\x00\x00\xff\xff"
            # Note: padding raw changes usz slightly which is totally valid in XML!
            comp_closed = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
            c_closed = comp_closed.compress(pad_raw) + comp_closed.flush(zlib.Z_FINISH)
            if len(c_closed) == target_csz:
                return c_closed

    return best


def process_modern_solidworks(
    data: bytes,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    use_ocr: bool = True,
    ocr_preview: bool = False,
) -> tuple[bytes, int]:
    """De-identify SolidWorks 2015+ file keeping valid CRC-32, Central Directory, and geometry."""
    parsed = parse_modern_container(data)
    local_chunks = parsed["local_chunks"]
    cd_entries = parsed["cd_entries"]
    if not local_chunks:
        return data, 0

    # Map local_marker_off -> list of cd_entries pointing to it
    cd_by_local: dict[int, list[dict]] = {}
    for ce in cd_entries:
        cd_by_local.setdefault(ce["local_marker_off"], []).append(ce)

    replacements = 0
    # Prepare transformed payloads per local chunk
    rewrites: dict[int, tuple[bytes, bytes]] = {}  # marker_off -> (new_raw, new_comp)
    for m_off, chunk in local_chunks.items():
        nm_l = chunk["name"].lower()
        raw: bytes = chunk["raw"]
        new_raw = raw

        if nm_l.startswith(XML_STREAM_PREFIXES):
            new_raw = _scrub_sw_xml(raw, chunk["name"], registry, scope)
        elif nm_l == "previewpng" and raw.startswith(b"\x89PNG"):
            new_raw, rcnt = process_image_bytes(raw, ".png", registry, scope, use_ocr=(use_ocr and ocr_preview))
            if rcnt == 0:
                new_raw = raw
        elif nm_l == "preview":
            pass
        elif not nm_l.endswith(("-partition", "-ghostpartition")) and not raw.startswith(b"PS\x00\x00"):
            new_raw = _scrub_utf16_and_ascii_inplace(raw, registry, scope)

        if new_raw != raw:
            replacements += 1
            rewrites[m_off] = (new_raw, b"")

    if not rewrites:
        return data, 0

    # Try exact-size in-place replacement first (zero offset shift anywhere in file!)
    out = bytearray(data)
    needs_rebuild = False
    for m_off, (new_raw, _) in list(rewrites.items()):
        chunk = local_chunks[m_off]
        old_csz = chunk["csz"]
        new_comp = _deflate_exact_size(new_raw, old_csz)
        if new_comp is None or len(new_comp) != old_csz:
            # If stream is XML, allow appending whitespace inside XML comment to hit exact length mod 5
            if chunk["name"].lower().startswith(XML_STREAM_PREFIXES):
                for extra in range(1, 200):
                    test_raw = new_raw + (b"\n<!-- " + b" " * extra + b" -->")
                    comp_open = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
                    c_open = comp_open.compress(test_raw) + comp_open.flush(zlib.Z_SYNC_FLUSH)
                    diff = old_csz - len(c_open)
                    if diff >= 5 and diff % 5 == 0:
                        n_empty = (diff - 5) // 5
                        new_comp = c_open + (b"\x00\x00\x00\xff\xff" * n_empty) + b"\x01\x00\x00\xff\xff"
                        new_raw = test_raw
                        break
            if new_comp is None or len(new_comp) != old_csz:
                needs_rebuild = True
                break
        rewrites[m_off] = (new_raw, new_comp)

    if not needs_rebuild:
        for m_off, (new_raw, new_comp) in rewrites.items():
            chunk = local_chunks[m_off]
            new_crc = zlib.crc32(new_raw) & 0xFFFFFFFF
            new_usz = len(new_raw)
            # Verify round-trip before writing
            if zlib.decompress(new_comp, -15) != new_raw:
                raise RuntimeError(f"DEFLATE round-trip mismatch on {chunk['name']}")
            # Update local header crc32 & usz (csz unchanged!)
            struct.pack_into("<I", out, m_off + 0x0A, new_crc)
            struct.pack_into("<I", out, m_off + 0x12, new_usz)
            out[chunk["payload_off"] : chunk["payload_off"] + chunk["csz"]] = new_comp
            # Update matching CD entries
            for ce in cd_by_local.get(m_off, []):
                cd_m = ce["marker_off"]
                struct.pack_into("<I", out, cd_m + 0x0A, new_crc)
                struct.pack_into("<I", out, cd_m + 0x12, new_usz)
        return bytes(out), replacements

    # Full offset-shifting rebuild fallback when a stream grows beyond old_csz
    first_cd = min((ce["cd_off"] for ce in cd_entries), default=len(data))
    rebuilt = bytearray()
    cursor = 0
    offset_map: dict[int, int] = {}  # old_marker_off -> new_marker_off

    for m_off in sorted(local_chunks.keys()):
        chunk = local_chunks[m_off]
        if m_off < cursor:
            continue
        rebuilt.extend(data[cursor:m_off])
        new_m_off = len(rebuilt)
        offset_map[m_off] = new_m_off
        if m_off in rewrites:
            new_raw, _ = rewrites[m_off]
            comp = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-15)
            new_comp = comp.compress(new_raw) + comp.flush(zlib.Z_FINISH)
            new_crc = zlib.crc32(new_raw) & 0xFFFFFFFF
            new_usz = len(new_raw)
            new_csz = len(new_comp)
            hdr = bytearray(data[m_off : m_off + 0x1A + chunk["nsz"]])
            struct.pack_into("<III", hdr, 0x0A, new_crc, new_csz, new_usz)
            rebuilt.extend(hdr)
            rebuilt.extend(new_comp)
        else:
            end_chunk = chunk["payload_off"] + chunk["csz"]
            rebuilt.extend(data[m_off:end_chunk])
        cursor = chunk["payload_off"] + chunk["csz"]

    rebuilt.extend(data[cursor:first_cd])
    new_cd_start = len(rebuilt)
    tail = bytearray(data[first_cd:])

    # Update CD entries in tail
    for ce in cd_entries:
        rel_cd_m = ce["marker_off"] - first_cd
        old_lm = ce["local_marker_off"]
        if old_lm in offset_map:
            new_loff = (offset_map[old_lm] - 4) - 8
            struct.pack_into("<I", tail, rel_cd_m + 36, new_loff)
        if old_lm in rewrites:
            new_raw, _ = rewrites[old_lm]
            comp = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-15)
            new_comp = comp.compress(new_raw) + comp.flush(zlib.Z_FINISH)
            new_crc = zlib.crc32(new_raw) & 0xFFFFFFFF
            struct.pack_into("<III", tail, rel_cd_m + 0x0A, new_crc, len(new_comp), len(new_raw))

    # Update EOCD cd_offset reference (which is cd_start - 8) if present in tail
    old_cd_ref = first_cd - 8
    new_cd_ref = new_cd_start - 8
    last_cd_end = max((ce["marker_off"] + 40 + ce["nsz"] for ce in cd_entries), default=first_cd) - first_cd
    for pos in range(last_cd_end, max(last_cd_end, len(tail) - 3)):
        if struct.unpack_from("<I", tail, pos)[0] == old_cd_ref:
            struct.pack_into("<I", tail, pos, new_cd_ref)

    rebuilt.extend(tail)
    return bytes(rebuilt), replacements
