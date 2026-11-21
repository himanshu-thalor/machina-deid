"""Handlers for text-based and structured neutral CAD formats:
STEP (.step/.stp), IGES (.igs/.iges), ACIS (.sat), Parasolid (.x_t/.x_b/.xmt_txt/.xmt_bin),
STL (.stl binary & ASCII), OBJ (.obj), VRML (.wrl), OFF, BREP, SCAD, JT, UNV, NEU, PS/EPS, IPJ.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
import struct

from ..registry import GLOBAL_SCOPE, IdentityRegistry

log = logging.getLogger(__name__)

# STEP entities whose string arguments frequently carry identifying metadata or part/product names.
STEP_IDENTIFYING_ENTITIES: frozenset[str] = frozenset(
    {
        "PERSON",
        "PERSON_AND_ORGANIZATION",
        "ORGANIZATION",
        "ADDRESS",
        "PERSONAL_ADDRESS",
        "ORGANIZATIONAL_ADDRESS",
        "TELECOM_ADDRESS",
        "APPROVAL",
        "APPROVAL_STATUS",
        "APPROVAL_ROLE",
        "APPROVAL_PERSON_ORGANIZATION",
        "SECURITY_CLASSIFICATION",
        "SECURITY_CLASSIFICATION_LEVEL",
        "PRODUCT",
        "PRODUCT_DEFINITION_FORMATION",
        "PRODUCT_DEFINITION_FORMATION_WITH_SPECIFIED_SOURCE",
        "PRODUCT_DEFINITION",
        "PRODUCT_CATEGORY",
        "PRODUCT_RELATED_PRODUCT_CATEGORY",
        "DRAUGHTING_TITLE",
        "TEXT_LITERAL",
        "TEXT_LITERAL_WITH_EXTENT",
        "ANNOTATION_TEXT",
        "NEXT_ASSEMBLY_USAGE_OCCURRENCE",
        "ASSEMBLY_COMPONENT_USAGE",
        "SPECIFIED_HIGHER_USAGE_OCCURRENCE",
        "DOCUMENT",
        "DOCUMENT_FILE",
        "DOCUMENT_TYPE",
        "EXTERNAL_SOURCE",
        "DESCRIPTIVE_REPRESENTATION_ITEM",
        "APPLIED_NAME_ASSIGNMENT",
        "MANIFOLD_SOLID_BREP",
        "BREP_WITH_VOIDS",
        "FACETED_BREP",
        "SHELL_BASED_SURFACE_MODEL",
        "SHAPE_REPRESENTATION",
        "ADVANCED_BREP_SHAPE_REPRESENTATION",
        "FACETED_BREP_SHAPE_REPRESENTATION",
        "PROPERTY_DEFINITION",
        "NAME_ATTRIBUTE",
        "APPLICATION_PROTOCOL_DEFINITION",
    }
)

# STEP string literal regex handling doubled-apostrophe escapes ('foo''bar')
RE_STEP_STR = re.compile(r"'((?:[^']|'')*)'")
RE_STEP_COMMENT = re.compile(r"/\*.*?\*/", re.S)
RE_STEP_ENTITY_HEAD = re.compile(r"^#\d+\s*=\s*(?:\(\s*)?([A-Z0-9_]+)\b")


def _step_unescape(s: str) -> str:
    return s.replace("''", "'")


def _step_escape(s: str) -> str:
    return s.replace("'", "''")


def inspect_step_metadata(path: Path, max_bytes: int = 2_000_000) -> list[tuple[str, str]]:
    """Extract structured (entity_type, raw_value) pairs from STEP HEADER and early DATA entities."""
    found: list[tuple[str, str]] = []
    try:
        with path.open("rb") as f:
            head = f.read(max_bytes).decode("latin1", errors="replace")
    except Exception:
        return found

    # Extract FILE_NAME fields
    m_fn = re.search(r"FILE_NAME\s*\((.*?)\)\s*;", head, re.S | re.I)
    if m_fn:
        strs = [_step_unescape(x) for x in RE_STEP_STR.findall(m_fn.group(1))]
        # FILE_NAME(name, time_stamp, (author), (org), preproc, orig_sys, auth)
        if len(strs) >= 1 and strs[0]:
            found.append(("PART_ID", strs[0]))
        if len(strs) >= 3 and strs[2]:
            found.append(("PERSON", strs[2]))
        if len(strs) >= 4 and strs[3]:
            found.append(("ORG", strs[3]))
        if len(strs) >= 7 and strs[6]:
            found.append(("PERSON", strs[6]))

    for m in re.finditer(
        r"#\d+\s*=\s*(PERSON|ORGANIZATION|ADDRESS|PRODUCT|DOCUMENT_FILE)\s*\(([^;]{1,600})\)\s*;",
        head,
    ):
        ent_name = m.group(1)
        strs = [_step_unescape(x) for x in RE_STEP_STR.findall(m.group(2))]
        etype = {"PERSON": "PERSON", "ORGANIZATION": "ORG", "ADDRESS": "ADDRESS", "PRODUCT": "PART_ID"}.get(
            ent_name, "PART_ID"
        )
        for s in strs:
            if s.strip() and not s.strip().lower() in {"unspecified", "none", "$"}:
                found.append((etype, s.strip()))
    return found


def _transform_step_statement(stmt: str, in_header: bool, registry: IdentityRegistry, scope: str) -> tuple[str, int]:
    """De-identify a single STEP HEADER or DATA statement while preserving geometry/numbers."""
    cnt = 0
    if "/*" in stmt:
        def _clean_cmt(mc: re.Match[str]) -> str:
            nonlocal cnt
            rep = registry.replace_text(mc.group(0), scope, context="step")
            if rep != mc.group(0):
                cnt += 1
            return rep

        stmt = RE_STEP_COMMENT.sub(_clean_cmt, stmt)

    if in_header:
        if stmt.lstrip().upper().startswith(("FILE_DESCRIPTION", "FILE_NAME")):
            def _sub_hdr_str(ms: re.Match[str]) -> str:
                nonlocal cnt
                raw = _step_unescape(ms.group(1))
                if not raw:
                    return ms.group(0)
                rep = registry.replace_text(raw, scope, context="step")
                if rep != raw:
                    cnt += 1
                return "'" + _step_escape(rep) + "'"

            stmt = RE_STEP_STR.sub(_sub_hdr_str, stmt)
        return stmt, cnt

    # DATA section: only inspect statements belonging to identifying entity types or containing strings
    if "'" not in stmt:
        return stmt, cnt

    m_ent = RE_STEP_ENTITY_HEAD.match(stmt.lstrip())
    ent_type = m_ent.group(1).upper() if m_ent else ""
    if ent_type and ent_type not in STEP_IDENTIFYING_ENTITIES and "(" not in stmt.lstrip()[m_ent.end() - 1 :]:
        return stmt, cnt

    # Skip pure geometric coordinate/curve entities even if compound
    if ent_type in {"CARTESIAN_POINT", "DIRECTION", "VECTOR", "B_SPLINE_CURVE_WITH_KNOTS", "B_SPLINE_SURFACE_WITH_KNOTS"}:
        return stmt, cnt

    def _sub_data_str(ms: re.Match[str]) -> str:
        nonlocal cnt
        raw = _step_unescape(ms.group(1))
        if not raw:
            return ms.group(0)
        rep = registry.replace_text(raw, scope, context="step")
        if rep != raw:
            cnt += 1
        return "'" + _step_escape(rep) + "'"

    stmt = RE_STEP_STR.sub(_sub_data_str, stmt)
    return stmt, cnt


def process_step_file(src_path: Path, dst_path: Path, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> int:
    """Stream-process an ISO-10303-21 STEP file in bounded memory (safe up to >1.4 GB)."""
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    replacements = 0
    in_header = False
    in_data = False
    buf = ""

    def flush_statement(st: str, fout) -> None:
        nonlocal replacements, in_header, in_data
        stripped = st.strip().upper()
        if stripped == "HEADER;":
            in_header = True
            fout.write(st)
            return
        if stripped == "DATA;":
            in_header = False
            in_data = True
            fout.write(st)
            return
        if stripped == "ENDSEC;":
            in_header = False
            in_data = False
            fout.write(st)
            return
        if in_header or in_data:
            new_st, c = _transform_step_statement(st, in_header, registry, scope)
            replacements += c
            fout.write(new_st)
        else:
            fout.write(st)

    # Preserve line endings and ISO-10303-21 framing using latin1 lossless 1-to-1 byte codec
    with src_path.open("r", encoding="latin1", newline="") as fin, dst_path.open(
        "w", encoding="latin1", newline=""
    ) as fout:
        for line in fin:
            buf += line
            # Fast path: single-line statement ending in ';' (with optional newline)
            ls = line.rstrip("\r\n")
            if ls.endswith(";") and not (buf.count("'") % 2 == 1):
                flush_statement(buf, fout)
                buf = ""
            elif len(buf) > 4_000_000:
                # Safety flush for malformed multi-MB non-terminated block
                fout.write(buf)
                buf = ""
        if buf:
            flush_statement(buf, fout)
    return replacements


# ---------------------------------------------------------------------------
# IGES (.igs / .iges) 80-column Hollerith parser & writer
# ---------------------------------------------------------------------------

RE_HOLLERITH = re.compile(r"^(\d+)H(.*)$", re.S)


def inspect_iges_metadata(data: bytes) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    txt = data[:65536].decode("latin1", errors="replace")
    g_buf = []
    for line in txt.splitlines():
        if len(line) >= 73 and line[72] == "G":
            g_buf.append(line[:72])
    g_raw = "".join(g_buf)
    for m in re.finditer(r"(\d+)H", g_raw):
        n = int(m.group(1))
        val = g_raw[m.end() : m.end() + n]
        if "\\" in val or "/" in val or "@" in val or "." in val:
            found.append(("PATH" if ("\\" in val or "/" in val) else "PART_ID", val))
    return found


def _rewrite_iges_global_stream(g_raw: str, registry: IdentityRegistry, scope: str) -> tuple[str, int]:
    """Parse IGES Global section, transform Hollerith strings, recompute nH byte counts."""
    if len(g_raw) < 4:
        return g_raw, 0
    # Parse parameter & record delimiters per IGES spec
    idx = 0
    if g_raw.startswith("1H"):
        p_delim = g_raw[2]
        idx = 3
        if idx < len(g_raw) and g_raw[idx] == p_delim:
            idx += 1
        if g_raw[idx : idx + 2] == "1H":
            r_delim = g_raw[idx + 2]
            idx += 3
        else:
            r_delim = ";"
    else:
        p_delim = ","
        r_delim = ";"

    # Reconstruct token by token respecting Hollerith nH...
    out = [g_raw[:idx]]
    replacements = 0
    n = len(g_raw)
    i = idx
    while i < n:
        ch = g_raw[i]
        if ch in (p_delim, r_delim, " "):
            out.append(ch)
            i += 1
            continue
        m = re.match(r"(\d+)H", g_raw[i:])
        if m:
            hlen = int(m.group(1))
            s_start = i + m.end()
            s_val = g_raw[s_start : s_start + hlen]
            new_s = registry.replace_text(s_val, scope, context="iges")
            if new_s != s_val:
                replacements += 1
            out.append(f"{len(new_s.encode('latin1', 'replace'))}H{new_s}")
            i = s_start + hlen
        else:
            j = i
            while j < n and g_raw[j] not in (p_delim, r_delim):
                j += 1
            out.append(g_raw[i:j])
            i = j
    return "".join(out), replacements


def _wrap_iges_section(stream: str, sec_char: str, eol: str) -> list[str]:
    lines: list[str] = []
    if not stream:
        return lines
    pos = 0
    seq = 1
    while pos < len(stream):
        chunk = stream[pos : pos + 72].ljust(72)
        lines.append(f"{chunk}{sec_char}{seq:7d}{eol}")
        pos += 72
        seq += 1
    return lines


def process_iges_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    """De-identify IGES Start/Global sections cleanly preserving 80-column Hollerith layout."""
    txt = data.decode("latin1", errors="replace")
    eol = "\r\n" if "\r\n" in txt[:400] else "\n"
    raw_lines = txt.splitlines()

    s_lines: list[str] = []
    g_raw_parts: list[str] = []
    d_lines: list[str] = []
    p_lines: list[str] = []
    other_lines: list[str] = []

    for ln in raw_lines:
        if len(ln) >= 73:
            code = ln[72]
            if code == "S":
                s_lines.append(ln[:72])
            elif code == "G":
                g_raw_parts.append(ln[:72])
            elif code == "D":
                d_lines.append(ln)
            elif code == "P":
                p_lines.append(ln)
            elif code == "T":
                continue
            else:
                other_lines.append(ln)
        elif ln.strip():
            other_lines.append(ln)

    if not g_raw_parts or not d_lines:
        # Malformed or non-standard IGES: safe text fallback
        rep = registry.replace_text(txt, scope, context="iges")
        return rep.encode("latin1", errors="replace"), (1 if rep != txt else 0)

    replacements = 0
    out_lines: list[str] = []

    # Start section
    for idx, sl in enumerate(s_lines, start=1):
        new_sl = registry.replace_text(sl.rstrip(), scope, context="iges")
        if new_sl != sl.rstrip():
            replacements += 1
        out_lines.append(f"{new_sl[:72].ljust(72)}S{idx:7d}{eol}")

    # Global section
    g_stream = "".join(g_raw_parts).rstrip()
    if ";" in g_stream:
        g_stream = g_stream[: g_stream.rfind(";") + 1]
    new_g_stream, g_rep = _rewrite_iges_global_stream(g_stream, registry, scope)
    replacements += g_rep
    g_wrapped = _wrap_iges_section(new_g_stream, "G", eol)
    out_lines.extend(g_wrapped)

    # D and P sections (preserve all geometry/pointers; check for 212/406 string Hollerith only if length-neutral or safe)
    for dl in d_lines:
        out_lines.append(dl[:80].ljust(80) + eol)
    for pl in p_lines:
        out_lines.append(pl[:80].ljust(80) + eol)

    # Terminate line with exact updated counts
    t_line = f"S{len(s_lines):7d}G{len(g_wrapped):7d}D{len(d_lines):7d}P{len(p_lines):7d}".ljust(72) + f"T{1:7d}{eol}"
    out_lines.append(t_line)

    return "".join(out_lines).encode("latin1", errors="replace"), replacements


# ---------------------------------------------------------------------------
# ACIS (.sat)
# ---------------------------------------------------------------------------

RE_ACIS_LEN_STR = re.compile(r"(@)(\d+)(\s+)([^\r\n#]+)")


def process_sat_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    """De-identify ACIS .sat header and length-prefixed string attributes."""
    txt = data.decode("latin1", errors="replace")
    lines = txt.splitlines(keepends=True)
    if len(lines) < 3:
        return data, 0

    replacements = 0
    # Line 2 in ACIS .sat contains `<num_app> <app_id> ... <date>`
    # Keep token count/structure intact while scrubbing any identifying tokens
    if len(lines) >= 2:
        new_l1 = registry.replace_text(lines[1], scope, context="metadata")
        if new_l1 != lines[1]:
            replacements += 1
            lines[1] = new_l1

    for idx in range(3, len(lines)):
        ln = lines[idx]
        if "@" not in ln:
            continue

        # ACIS strings use @<byte_len> <exact_bytes>
        def _sub_acis(m: re.Match[str]) -> str:
            nonlocal replacements
            prefix, slen_s, sp, rest = m.groups()
            slen = int(slen_s)
            val = rest[:slen]
            tail = rest[slen:]
            new_val = registry.replace_text(val, scope, context="metadata")
            if new_val != val:
                replacements += 1
                return f"{prefix}{len(new_val.encode('latin1', 'replace'))}{sp}{new_val}{tail}"
            return m.group(0)

        lines[idx] = RE_ACIS_LEN_STR.sub(_sub_acis, ln)

    return "".join(lines).encode("latin1", errors="replace"), replacements


# ---------------------------------------------------------------------------
# Parasolid (.x_t, .x_b, .xmt_txt, .xmt_bin)
# ---------------------------------------------------------------------------

def inspect_parasolid_metadata(data: bytes) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    end_hdr = data.find(b"**END_OF_HEADER")
    hdr = data[: end_hdr if end_hdr != -1 else min(len(data), 4096)].decode("latin1", errors="replace")
    for line in hdr.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().upper()
        v = v.strip().rstrip(";")
        if not v or v.lower() == "unknown":
            continue
        if k == "USER":
            found.append(("USERNAME", v))
        elif k == "MC":
            found.append(("HOST", v))
        elif k == "SITE":
            found.append(("ADDRESS", v))
        elif k in {"KEY", "FILE"}:
            found.append(("PATH", v))
    return found


def process_parasolid_bytes(
    data: bytes,
    is_binary: bool,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    max_total_bytes: int | None = None,
) -> tuple[bytes, int]:
    """Rewrite Parasolid **PART1; header fields while leaving binary body intact."""
    end_idx = data.find(b"**END_OF_HEADER")
    if end_idx == -1:
        if is_binary:
            return data, 0
        txt = data.decode("latin1", errors="replace")
        rep = registry.replace_text(txt, scope, context="metadata")
        return rep.encode("latin1", errors="replace"), (1 if rep != txt else 0)

    # Locate end of the **END_OF_HEADER***** line
    nl_after = data.find(b"\n", end_idx)
    split_pos = (nl_after + 1) if nl_after != -1 else (end_idx + len(b"**END_OF_HEADER"))
    hdr_bytes = data[:split_pos]
    body_bytes = data[split_pos:]

    def _rewrite_hdr(compact: bool) -> tuple[bytes, int]:
        hdr_txt = hdr_bytes.decode("latin1", errors="replace")
        lines = hdr_txt.splitlines(keepends=True)
        rep_cnt = 0
        for i, ln in enumerate(lines):
            if "=" not in ln:
                continue
            key_part, val_part = ln.split("=", 1)
            k = key_part.strip().upper()
            eol = "\r\n" if ln.endswith("\r\n") else ("\n" if ln.endswith("\n") else "")
            core = val_part[: len(val_part) - len(eol)]
            has_semi = core.endswith(";")
            val = core[:-1] if has_semi else core

            if k in {"MC", "SITE", "USER", "KEY", "FILE"} and val.strip() and val.strip().lower() != "unknown":
                if compact:
                    new_val = registry.replace_fixed_length(val, scope, encoding="latin1").decode("latin1", errors="replace").strip()
                    if new_val == val.strip():
                        # Short deterministic code guaranteed <= original length when len >= 4
                        new_val = (registry.register(val.strip(), "ADDRESS" if k == "SITE" else "USERNAME", scope, is_global=True) or "ID")[: max(1, len(val.strip()))]
                elif k in {"KEY", "FILE"}:
                    new_val = registry.register_path(val.strip(), scope)
                elif k == "USER":
                    new_val = registry.register(val.strip(), "USERNAME", scope, is_global=True) or "usr0001"
                elif k == "MC":
                    new_val = registry.register(val.strip(), "HOST", scope, is_global=True) or "host-0001"
                else:
                    new_val = registry.register(val.strip(), "ADDRESS", scope, is_global=True) or "City, Country"
                if new_val != val:
                    rep_cnt += 1
                lines[i] = f"{key_part}={new_val}{';' if has_semi else ''}{eol}"
        return "".join(lines).encode("latin1", errors="replace"), rep_cnt

    new_hdr, replacements = _rewrite_hdr(compact=False)
    if max_total_bytes is not None and len(new_hdr) + len(body_bytes) > max_total_bytes:
        new_hdr, replacements = _rewrite_hdr(compact=True)

    if not is_binary:
        body_txt = body_bytes.decode("latin1", errors="replace")
        new_body_txt = registry.replace_text(body_txt, scope, context="metadata")
        if new_body_txt != body_txt:
            replacements += 1
        body_bytes = new_body_txt.encode("latin1", errors="replace")

    return new_hdr + body_bytes, replacements


# ---------------------------------------------------------------------------
# STL (Strict Binary vs ASCII)
# ---------------------------------------------------------------------------

def is_binary_stl(data: bytes) -> bool:
    if len(data) < 84:
        return False
    tri_count = struct.unpack_from("<I", data, 80)[0]
    return 84 + tri_count * 50 == len(data)


def process_stl_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    """De-identify STL 80-byte binary header or ASCII solid/endsolid header lines."""
    if is_binary_stl(data):
        hdr = data[:80]
        hdr_txt = hdr.rstrip(b"\x00 ").decode("latin1", errors="replace")
        new_hdr_txt = registry.replace_text(hdr_txt, scope, context="filename")
        # If header starts with 'solid ' and has identifying name not yet in registry, neutralize safely
        if new_hdr_txt != hdr_txt:
            new_hdr = new_hdr_txt.encode("latin1", errors="replace")[:80].ljust(80, b"\x00")
            return new_hdr + data[80:], 1
        return data, 0

    txt = data.decode("utf-8", errors="replace")
    lines = txt.splitlines(keepends=True)
    replacements = 0
    for i, ln in enumerate(lines):
        low = ln.lstrip().lower()
        if low.startswith(("solid ", "endsolid ")):
            new_ln = registry.replace_text(ln, scope, context="filename")
            if new_ln != ln:
                replacements += 1
                lines[i] = new_ln
    if replacements:
        return "".join(lines).encode("utf-8", errors="replace"), replacements
    return data, 0


# ---------------------------------------------------------------------------
# OBJ, VRML (.wrl), Generic Text CAD (.off, .brep, .scad, .jt, .unv, .neu, .ps, .eps, .ipj)
# ---------------------------------------------------------------------------

def process_obj_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    txt = data.decode("utf-8", errors="replace")
    lines = txt.splitlines(keepends=True)
    replacements = 0
    for i, ln in enumerate(lines):
        s = ln.lstrip()
        if s.startswith(("#", "o ", "g ", "mtllib ", "usemtl ")):
            new_ln = registry.replace_text(ln, scope, context="metadata")
            if new_ln != ln:
                replacements += 1
                lines[i] = new_ln
    return ("".join(lines).encode("utf-8", errors="replace"), replacements) if replacements else (data, 0)


def process_generic_text_cad(
    data: bytes, ext: str, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE
) -> tuple[bytes, int]:
    """Process VRML, JT text placeholders, UNV, NEU, OFF, BREP, SCAD, PS/EPS, IPJ XML."""
    # Check if binary magic accidentally matched a text extension
    if b"\x00" in data[:1024]:
        return data, 0
    txt = data.decode("utf-8", errors="replace")
    new_txt = registry.replace_text(txt, scope, context="metadata" if ext in {".ipj", ".jt", ".wrl"} else "general")
    if new_txt != txt:
        return new_txt.encode("utf-8", errors="replace"), 1
    return data, 0
