"""OLE2 Compound File Binary Format (MS-CFBF) + [MS-OLEPS] PropertySet handler
for SolidWorks pre-2015 (.sldprt/.sldasm/.slddrw), Autodesk Inventor (.ipt/.iam/.idw/.ipn),
and Solid Edge (.par/.asm/.dft).
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import struct
from uuid import UUID

import olefile

from ..config import SAFE_CAD_VENDORS
from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .image_handler import generate_neutral_logo, process_image_bytes
from .text_cad import process_parasolid_bytes

log = logging.getLogger(__name__)

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# [MS-OLEPS] Property types
VT_I2 = 2
VT_I4 = 3
VT_LPSTR = 30
VT_LPWSTR = 31
VT_CF = 71

# The same property number has different meanings in different property sets.
SUMMARY_INFO = UUID("f29f85e0-4ff9-1068-ab91-08002b27b3d9").bytes_le
DOCUMENT_SUMMARY = UUID("d5cdd502-2e9c-101b-9397-08002b2cf9ae").bytes_le
INVENTOR_TRACKING = UUID("32853f0f-3444-11d1-9e93-0060b03c1ca6").bytes_le
INVENTOR_TRACKING_CONTROL = UUID("d861fb30-3136-11d1-9e92-0060b03c1ca6").bytes_le
SOLID_EDGE_PROJECT = UUID("cc024fa2-6eb5-11ce-8aa2-08003601e988").bytes_le
PROPERTY_ROLES = {
    SUMMARY_INFO: {4: "PERSON", 8: "PERSON"},
    DOCUMENT_SUMMARY: {14: "PERSON", 15: "ORG"},
    INVENTOR_TRACKING: {3: "PERSON", 41: "PERSON", 42: "PERSON"},
    INVENTOR_TRACKING_CONTROL: {16: "PERSON"},
    SOLID_EDGE_PROJECT: {8: "PERSON"},
}
RE_ABSOLUTE_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/(?:home|Users|Volumes)/)")
RE_HISTORY_USER = re.compile(r"(?:eng(?:ineer|r)?|dr|mr|ms)[._-]?([A-Za-z][A-Za-z0-9._-]{3,24})", re.I)


def is_ole2(data: bytes) -> bool:
    return len(data) >= 512 and data[:8] == OLE2_MAGIC


def _pad4(n: int) -> int:
    return (n + 3) & ~3


def parse_oleps_strings(raw: bytes) -> list[tuple[int, str, str]]:
    """Read VT_LPSTR / VT_LPWSTR values from an OLE PropertySet stream (UTF-16LE safe)."""
    return [(pid, kind, value) for _, pid, kind, value in _iter_oleps_strings(raw)]


def _iter_oleps_strings(raw: bytes):
    if len(raw) < 48 or struct.unpack_from("<H", raw, 0)[0] != 0xFFFE:
        return
    n_sec = struct.unpack_from("<I", raw, 24)[0]
    for s in range(min(n_sec, 8)):
        fmt_off = 28 + s * 20
        if fmt_off + 20 > len(raw):
            break
        fmtid = raw[fmt_off : fmt_off + 16]
        sec_off = struct.unpack_from("<I", raw, fmt_off + 16)[0]
        if sec_off + 8 > len(raw):
            continue
        section_size, n_props = struct.unpack_from("<II", raw, sec_off)
        limit = min(len(raw), sec_off + section_size)
        for p in range(n_props):
            ent_off = sec_off + 8 + p * 8
            if ent_off + 8 > limit:
                break
            pid, poff = struct.unpack_from("<II", raw, ent_off)
            if pid == 0:
                continue
            v_off = sec_off + poff
            if v_off + 8 > limit:
                continue
            vt, ln = struct.unpack_from("<II", raw, v_off)
            if vt == VT_LPSTR and v_off + 8 + ln <= limit:
                # Decode first, strip trailing NULs second
                val = raw[v_off + 8 : v_off + 8 + ln].decode("latin1", errors="replace").rstrip("\x00")
                if val:
                    yield fmtid, pid, "LPSTR", val
            elif vt == VT_LPWSTR and v_off + 8 + ln * 2 <= limit:
                # Decode UTF-16LE BEFORE stripping NULs so final ASCII char's high 0x00 isn't stripped!
                val = raw[v_off + 8 : v_off + 8 + ln * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
                if val:
                    yield fmtid, pid, "LPWSTR", val


def _rewrite_oleps_stream(
    raw: bytes, registry: IdentityRegistry, scope: str, *, max_len: int, compact: bool = False
) -> tuple[bytes, int]:
    """Rebuild an [MS-OLEPS] PropertySet stream with scrubbed string & VT_CF thumbnail values."""
    if len(raw) < 48 or struct.unpack_from("<H", raw, 0)[0] != 0xFFFE:
        return raw, 0
    n_sec = struct.unpack_from("<I", raw, 24)[0]
    if n_sec == 0 or n_sec > 8 or 28 + n_sec * 20 > len(raw):
        return raw, 0

    header_prefix = raw[:28]
    sec_entries: list[tuple[bytes, int]] = []
    for s in range(n_sec):
        off = 28 + s * 20
        sec_entries.append((raw[off : off + 16], struct.unpack_from("<I", raw, off + 16)[0]))

    # Determine section spans sorted by offset
    ordered = sorted(range(n_sec), key=lambda idx: sec_entries[idx][1])
    new_sections: dict[int, bytes] = {}
    total_rep = 0

    for pos_i, s_idx in enumerate(ordered):
        fmtid, sec_off = sec_entries[s_idx]
        sec_end = sec_entries[ordered[pos_i + 1]][1] if pos_i + 1 < len(ordered) else len(raw)
        sec_raw = raw[sec_off:sec_end]
        if len(sec_raw) < 8:
            new_sections[s_idx] = sec_raw
            continue

        _, n_props = struct.unpack_from("<II", sec_raw, 0)
        if n_props > (len(sec_raw) - 8) // 8:
            new_sections[s_idx] = sec_raw
            continue
        prop_meta: list[tuple[int, int]] = []
        for p in range(n_props):
            pid, poff = struct.unpack_from("<II", sec_raw, 8 + p * 8)
            prop_meta.append((pid, poff))

        # Sort properties by offset to know exact original byte slices
        prop_by_off = sorted(enumerate(prop_meta), key=lambda x: x[1][1])
        prop_blobs: dict[int, bytes] = {}
        for k_i, (orig_i, (pid, poff)) in enumerate(prop_by_off):
            next_poff = prop_by_off[k_i + 1][1][1] if k_i + 1 < len(prop_by_off) else len(sec_raw)
            blob = sec_raw[poff:next_poff]
            if pid == 0 or len(blob) < 8:
                prop_blobs[orig_i] = blob
                continue

            vt, ln = struct.unpack_from("<II", blob, 0)
            if vt == VT_LPSTR and 8 + ln <= len(blob):
                val = blob[8 : 8 + ln].decode("latin1", errors="replace").rstrip("\x00")
                new_val = _scrub_oleps_string(fmtid, pid, val, registry, scope)
                if new_val != val:
                    total_rep += 1
                    if compact:
                        new_val = _fit_property_string(new_val, len(blob) - 9, "latin1")
                    enc = new_val.encode("latin1", errors="replace") + b"\x00"
                    padded_len = _pad4(len(enc))
                    prop_blobs[orig_i] = struct.pack("<II", VT_LPSTR, len(enc)) + enc.ljust(padded_len, b"\x00")
                    continue
            elif vt == VT_LPWSTR and 8 + ln * 2 <= len(blob):
                val = blob[8 : 8 + ln * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
                new_val = _scrub_oleps_string(fmtid, pid, val, registry, scope)
                if new_val != val:
                    total_rep += 1
                    if compact:
                        new_val = _fit_property_string(new_val, len(blob) - 10, "utf-16-le")
                    enc = (new_val + "\x00").encode("utf-16-le")
                    wchar_cnt = len(enc) // 2
                    padded_len = _pad4(len(enc))
                    prop_blobs[orig_i] = struct.pack("<II", VT_LPWSTR, wchar_cnt) + enc.ljust(padded_len, b"\x00")
                    continue
            elif vt == VT_CF and fmtid == SUMMARY_INFO and pid == 17 and ln > 64:
                # Replace embedded thumbnail with compact neutral PNG/BMP stub or cleaned CF blob
                neutral_png = generate_neutral_logo(64, 64, "CAD")
                cf_payload = struct.pack("<II", 8, 0) + neutral_png  # compact CF placeholder <= original
                if len(cf_payload) <= ln:
                    total_rep += 1
                    padded = _pad4(len(cf_payload))
                    prop_blobs[orig_i] = struct.pack("<II", VT_CF, len(cf_payload)) + cf_payload.ljust(padded, b"\x00")
                    continue

            prop_blobs[orig_i] = blob

        # Reassemble section cleanly
        hdr_size = 8 + len(prop_meta) * 8
        cur_poff = _pad4(hdr_size)
        body = bytearray(b"\x00" * (cur_poff - hdr_size))
        new_table = bytearray()
        for orig_i, (pid, _) in enumerate(prop_meta):
            b = prop_blobs[orig_i]
            new_table.extend(struct.pack("<II", pid, cur_poff))
            body.extend(b)
            # Ensure 4-byte alignment between properties
            rem = len(body) % 4
            if rem:
                body.extend(b"\x00" * (4 - rem))
            cur_poff = hdr_size + len(body)
        sec_bytes = struct.pack("<II", hdr_size + len(body), len(prop_meta)) + bytes(new_table) + bytes(body)
        new_sections[s_idx] = sec_bytes

    # Assemble whole PropertySet stream
    out = bytearray(header_prefix)
    sec_body = bytearray()
    base_off = 28 + n_sec * 20
    new_sec_offsets: list[tuple[bytes, int]] = []
    for s_idx in range(n_sec):
        guid = sec_entries[s_idx][0]
        new_sec_offsets.append((guid, base_off + len(sec_body)))
        sec_body.extend(new_sections[s_idx])
    for guid, off in new_sec_offsets:
        out.extend(guid + struct.pack("<I", off))
    out.extend(sec_body)

    if len(out) > max_len and not compact:
        return _rewrite_oleps_stream(raw, registry, scope, max_len=max_len, compact=True)
    if len(out) > max_len or not total_rep:
        return raw, 0
    return bytes(out), total_rep


def _fit_property_string(value: str, max_bytes: int, encoding: str) -> str:
    if len(value.encode(encoding, errors="replace")) <= max_bytes:
        return value
    characters = max(0, max_bytes // (2 if encoding == "utf-16-le" else 1))
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest().upper()
    return digest[:characters]


def _scrub_oleps_string(
    fmtid: bytes, pid: int, val: str, registry: IdentityRegistry, scope: str
) -> str:
    if not val.strip():
        return val
    # Preserve PropertySet section name stored at pid=255 or internal Inventor/Solid Edge markers
    if pid == 255 or val.startswith("<PartActiveColorStyle>"):
        return val
    if "adsklib#" in val.lower() or "design data\\materials" in val.lower():
        return val
    rep = registry.replace_text(val, scope, context="metadata")
    if rep != val:
        return rep
    # Force-pseudonymize author/company fields in OLE2 PropertySets even if short
    role = PROPERTY_ROLES.get(fmtid, {}).get(pid)
    if role and not any(cv in val.lower() for cv in SAFE_CAD_VENDORS):
        return registry.register(val.strip(), role, scope, is_global=False) or val
    return val


def _is_oleps_stream(leaf: str, raw: bytes) -> bool:
    if leaf.startswith("\x05"):
        return True
    return len(raw) >= 48 and raw[:2] == b"\xfe\xff" and raw[2:4] in (b"\x00\x00", b"\x01\x00")


def inspect_ole2_metadata(data: bytes) -> list[tuple[str, str]]:
    """Extract metadata identifiers from OLE2 PropertySets and CAD streams for discovery."""
    found: list[tuple[str, str]] = []
    if not is_ole2(data):
        return found
    try:
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            for entry in ole.listdir(streams=True, storages=False):
                sname = "/".join(entry)
                raw = ole.openstream(entry).read()
                if _is_oleps_stream(entry[-1], raw):
                    for fmtid, pid, _, val in _iter_oleps_strings(raw):
                        if (
                            pid == 255
                            or val.startswith("<")
                            or "Inventor " in val
                            or "Design Tracking" in val
                            or "adsklib#" in val.lower()
                            or "solid edge" in val.lower()
                            or "kg/m^" in val.lower()
                        ):
                            continue
                        role = PROPERTY_ROLES.get(fmtid, {}).get(pid)
                        if role:
                            found.append((role, val))
                        elif RE_ABSOLUTE_PATH.search(val):
                            if not re.match(r"^[A-Za-z]:\\(?:Windows|Program Files|ProgramData)\\", val, re.I):
                                found.append(("PATH", val))
                        elif fmtid in {SUMMARY_INFO, INVENTOR_TRACKING} and pid in {2, 3, 5, 6} and len(val) >= 4:
                            if re.search(r"@|\.[a-z]{2,4}$|[A-Z]{2,}-\d{3,}", val, re.I):
                                found.append(("PART_ID", val))
                elif "isolidworksinformation" in sname.lower() or "swxmlcontents" in sname.lower():
                    txt = raw.decode("utf-8", errors="replace")
                    for m in re.finditer(r'(?:swPath|swImportedPath)="([^"]+)"', txt):
                        found.append(("PATH", m.group(1)))
                elif "header2" in sname.lower():
                    arr_pos = raw.find(b"su_CStringArray")
                    log_pos = raw.find(b"moLogs_c")
                    region = raw[arr_pos : (log_pos if log_pos > arr_pos else arr_pos + 512)] if arr_pos != -1 else b""
                    for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", region):
                        s = u16.decode("utf-16-le", errors="ignore").strip()
                        if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{2,24}", s):
                            found.append(("USERNAME", s))
                elif "biography" in sname.lower():
                    for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", raw):
                        s = u16.decode("utf-16-le", errors="ignore").strip()
                        if ("\\" in s or "/" in s) and not re.match(r"^[A-Za-z]:\\(?:Windows|Program Files|ProgramData)\\", s, re.I):
                            found.append(("PATH", s))
                elif entry[-1].lower() == "geometricversionhistory":
                    authors = {value.strip().lower() for role, value in found if role == "PERSON"}
                    for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", raw):
                        user = u16.decode("utf-16-le").strip()
                        alias = RE_HISTORY_USER.fullmatch(user)
                        if alias and alias[1].lower() in authors:
                            found.append(("USERNAME", user))
    except Exception as e:
        log.debug("OLE2 inspect error: %s", e)
    return found


def _patch_ole2_streams_inplace(data: bytes, replacements: dict[int, bytes]) -> bytes | None:
    """Safely patch OLE2 streams in-place when each new stream fits its existing sector allocation.
    Updates directory entry dwSize without disturbing any proprietary CAD storage trees.
    """
    sec_shift = struct.unpack_from("<H", data, 30)[0]
    mini_shift = struct.unpack_from("<H", data, 32)[0]
    sec_size = 1 << sec_shift
    mini_size = 1 << mini_shift
    first_dir = struct.unpack_from("<I", data, 48)[0]
    cutoff = struct.unpack_from("<I", data, 56)[0]
    first_minifat = struct.unpack_from("<I", data, 60)[0]
    num_fat_secs = struct.unpack_from("<I", data, 44)[0]
    first_difat = struct.unpack_from("<I", data, 68)[0]

    # Build FAT from header DIFAT + chained DIFAT sectors
    difat: list[int] = list(struct.unpack_from("<109I", data, 76))
    cur_difat = first_difat
    seen_d = set()
    while cur_difat < 0xFFFFFFFA and cur_difat not in seen_d:
        seen_d.add(cur_difat)
        off = (cur_difat + 1) * sec_size
        if off + sec_size > len(data):
            break
        n_ents = sec_size // 4 - 1
        difat.extend(struct.unpack_from(f"<{n_ents}I", data, off))
        cur_difat = struct.unpack_from("<I", data, off + n_ents * 4)[0]

    fat: list[int] = []
    for s in difat[:num_fat_secs]:
        if s >= 0xFFFFFFFA:
            break
        off = (s + 1) * sec_size
        if off + sec_size <= len(data):
            fat.extend(struct.unpack_from(f"<{sec_size // 4}I", data, off))

    def get_chain(start: int) -> list[int]:
        chain = []
        cur = start
        seen = set()
        while cur < 0xFFFFFFFA and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cur = fat[cur] if cur < len(fat) else 0xFFFFFFFF
        return chain

    # Build MiniFAT
    minifat: list[int] = []
    for s in get_chain(first_minifat):
        off = (s + 1) * sec_size
        if off + sec_size <= len(data):
            minifat.extend(struct.unpack_from(f"<{sec_size // 4}I", data, off))

    def get_mini_chain(start: int) -> list[int]:
        chain = []
        cur = start
        seen = set()
        while cur < 0xFFFFFFFA and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cur = minifat[cur] if cur < len(minifat) else 0xFFFFFFFF
        return chain

    # Read directory sectors & locate root ministream
    dir_secs = get_chain(first_dir)
    root_chain: list[int] = []
    dir_entries: list[tuple[int, int, int, int, int]] = []  # (SID, directory offset, type, start sector, size)
    for dir_index, ds in enumerate(dir_secs):
        d_base = (ds + 1) * sec_size
        for i in range(0, sec_size, 128):
            e_off = d_base + i
            e = data[e_off : e_off + 128]
            nl = struct.unpack_from("<H", e, 64)[0]
            et = e[66]
            if et == 0 or nl < 2 or nl > 64:
                continue
            sid = (dir_index * sec_size + i) // 128
            ssec = struct.unpack_from("<I", e, 116)[0]
            sz = struct.unpack_from("<I", e, 120)[0]
            if et == 5:
                root_chain = get_chain(ssec)
            dir_entries.append((sid, e_off, et, ssec, sz))

    buf = bytearray(data)
    for sid, e_off, et, ssec, old_sz in dir_entries:
        if et != 2 or sid not in replacements:
            continue
        new_bytes = replacements[sid]
        new_sz = len(new_bytes)
        in_mini = old_sz < cutoff and bool(root_chain)

        if in_mini:
            if new_sz >= cutoff:
                return None  # crossed mini-stream boundary
            mchain = get_mini_chain(ssec)
            if new_sz > len(mchain) * mini_size:
                return None  # needs more mini-sectors
            # Write into mini-stream sectors mapped via root_chain
            for m_idx, ms in enumerate(mchain):
                chunk = new_bytes[m_idx * mini_size : (m_idx + 1) * mini_size].ljust(mini_size, b"\x00")
                m_byte_off = ms * mini_size
                r_sec_idx = m_byte_off // sec_size
                r_sec_off = m_byte_off % sec_size
                if r_sec_idx >= len(root_chain):
                    return None
                abs_off = (root_chain[r_sec_idx] + 1) * sec_size + r_sec_off
                buf[abs_off : abs_off + mini_size] = chunk
        else:
            if new_sz < cutoff and old_sz >= cutoff:
                # Pad new_bytes up to cutoff with NULs so it stays in regular FAT chain safely!
                new_bytes = new_bytes.ljust(cutoff, b"\x00")
                new_sz = len(new_bytes)
            chain = get_chain(ssec)
            if new_sz > len(chain) * sec_size:
                return None  # needs more FAT sectors
            for s_idx, sec_id in enumerate(chain):
                chunk = new_bytes[s_idx * sec_size : (s_idx + 1) * sec_size].ljust(sec_size, b"\x00")
                abs_off = (sec_id + 1) * sec_size
                buf[abs_off : abs_off + sec_size] = chunk

        struct.pack_into("<I", buf, e_off + 120, new_sz)

    return bytes(buf)


def process_ole2_bytes(
    data: bytes, ext: str, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE, *, use_ocr: bool = True
) -> tuple[bytes, int]:
    """De-identify OLE2 CAD files (Inventor, Solid Edge, SolidWorks pre-2015)."""
    if not is_ole2(data):
        return data, 0

    stream_updates: dict[int, bytes] = {}
    total_rep = 0

    try:
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            for entry in ole.listdir(streams=True, storages=False):
                leaf = entry[-1]
                sid = ole._find(entry)
                raw = ole.openstream(entry).read()

                if _is_oleps_stream(leaf, raw):
                    if len(raw) < ole.minisectorcutoff:
                        sector_size = ole.minisectorsize
                        capacity = min(ole.minisectorcutoff - 1, -(-len(raw) // sector_size) * sector_size)
                    else:
                        sector_size = ole.sectorsize
                        capacity = -(-len(raw) // sector_size) * sector_size
                    new_raw, rep = _rewrite_oleps_stream(raw, registry, scope, max_len=capacity)
                    if rep and new_raw != raw:
                        stream_updates[sid] = new_raw
                        total_rep += rep
                elif leaf == "PreviewPNG" and raw.startswith(b"\x89PNG"):
                    ocr_prev = use_ocr and ext in {".slddrw", ".drwdot", ".slddrt", ".idw", ".dft"}
                    new_png, rep = process_image_bytes(raw, ".png", registry, scope, use_ocr=ocr_prev)
                    if rep and len(new_png) <= len(raw):
                        stream_updates[sid] = new_png
                        total_rep += rep
                elif leaf == "Preview":
                    pass
                elif leaf == "STREAM0.X_B" and b"**END_OF_HEADER" in raw[:1024]:
                    alloc_cap = ((len(raw) + 511) // 512) * 512 if len(raw) >= 4096 else ((len(raw) + 63) // 64) * 64
                    new_xb, rep = process_parasolid_bytes(
                        raw, is_binary=True, registry=registry, scope=scope, max_total_bytes=alloc_cap
                    )
                    if rep and len(new_xb) <= alloc_cap:
                        stream_updates[sid] = new_xb
                        total_rep += rep
                elif leaf.lower() in {"features", "keywords", "compinstancetree"}:
                    txt = raw.decode("utf-8", errors="replace")
                    new_txt = registry.replace_text(txt, scope, context="xml")
                    new_b = new_txt.encode("utf-8", errors="replace")
                    if new_b != raw and len(new_b) <= len(raw):
                        stream_updates[sid] = new_b
                        total_rep += 1
                elif not leaf.lower().endswith(("-partition", "-ghostpartition")) and not raw.startswith(b"PS\x00\x00"):
                    # Length-preserving UTF-16LE / ASCII scrub in-place across Header2, Biography, VBLists, SectionBodies, etc.
                    from .solidworks_modern import _scrub_utf16_and_ascii_inplace

                    new_raw = _scrub_utf16_and_ascii_inplace(raw, registry, scope)
                    if new_raw != raw:
                        stream_updates[sid] = new_raw
                        total_rep += 1
    except Exception as e:
        log.debug("OLE2 read failed: %s", e)
        return data, 0

    if not stream_updates:
        return data, 0

    patched = _patch_ole2_streams_inplace(data, stream_updates)
    if patched is not None:
        return patched, total_rep

    # Fallback: trim VT_CF / pad within existing capacity so in-place update always fits
    compact_updates: dict[int, bytes] = {}
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        for entry in ole.listdir(streams=True, storages=False):
            sid = ole._find(entry)
            if sid in stream_updates:
                orig_len = len(ole.openstream(entry).read())
                if len(stream_updates[sid]) <= orig_len:
                    compact_updates[sid] = stream_updates[sid]
    if compact_updates:
        patched = _patch_ole2_streams_inplace(data, compact_updates)
        if patched is not None:
            return patched, total_rep

    return data, 0
