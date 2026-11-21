"""Handlers for PTC Creo (#UGC:2), CATIA V5 (V5_CFV2), and other binary CAD containers."""

from __future__ import annotations

import logging
import re

from ..config import split_compound_extension
from ..registry import GLOBAL_SCOPE, IdentityRegistry

log = logging.getLogger(__name__)


def is_creo_ugc(data: bytes) -> bool:
    return data.startswith(b"#UGC:")


def is_catia_v5(data: bytes) -> bool:
    return data.startswith(b"V5_CFV2")


def inspect_creo_metadata(data: bytes) -> list[tuple[str, str]]:
    """Extract Creo header fields and @model_name for discovery."""
    found: list[tuple[str, str]] = []
    if not is_creo_ugc(data):
        return found
    head = data[:4096].decode("latin1", errors="replace")
    for k in ("HOST", "LINK", "DBID", "MACH"):
        m = re.search(rf"^#-\s*{k}\s+(.+?)\s*\\?$", head, re.M)
        if m and m.group(1).strip():
            val = m.group(1).strip()
            et = "HOST" if k == "HOST" else "PART_ID"
            found.append((et, val))
    m_mn = re.search(r"@model_name\s+\d+\s+\d+\r?\n\d+\s+\d+\s+([^\r\n]+)", head)
    if m_mn:
        val = m_mn.group(1).strip()
        if val and not re.fullmatch(r"\d+", val):
            found.append(("PART_ID", val))
    return found


def _rename_creo_model_slot(value: str, capacity: int, registry: IdentityRegistry, scope: str) -> str:
    """Rename a CMNM model reference with its three-digit hexadecimal byte count."""
    if not re.fullmatch(r"[0-9a-fA-F]{3}", value[:3]) or int(value[:3], 16) != len(value) - 3:
        return value
    raw_name = value[3:].encode("latin1")
    try:
        filename = raw_name.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        filename = raw_name.decode("latin1")
        encoding = "latin1"
    replacement = registry.resolve_filename(filename, scope).encode(encoding, errors="replace")
    if replacement == raw_name:
        return value
    if len(replacement) + 3 > capacity:
        stem, extension = split_compound_extension(filename)
        replacement = registry.replace_fixed_length(stem, scope, encoding) + extension.encode(encoding)
    return f"{len(replacement):03x}{replacement.decode('latin1')}"


def process_creo_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    """De-identify PTC Creo #UGC:2 files preserving exact byte offsets for #UGC_TOC."""
    if not is_creo_ugc(data):
        return data, 0

    end_hdr = data.find(b"#-END_OF_UGC_HEADER")
    buf = bytearray(data)
    replacements = 0

    # 1. These header lines are fixed-width and space-padded, with a trailing backslash.
    if end_hdr != -1:
        hdr_txt = data[:end_hdr].decode("latin1", errors="replace")
        out_lines: list[str] = []
        for ln in hdr_txt.splitlines(keepends=True):
            eol = "\r\n" if ln.endswith("\r\n") else ("\n" if ln.endswith("\n") else "")
            core = ln[: len(ln) - len(eol)]
            m = re.match(r"^(#-\s*(HOST|LINK|DBID|MACH|CMNM)\s+)(.+?)(\s*\\)$", core)
            if m:
                prefix, field, val, suffix = m.groups()
                total_val_slot = len(val) + len(suffix) - 1  # excluding trailing '\'
                if field == "CMNM":
                    new_val = _rename_creo_model_slot(val.strip(), total_val_slot, registry, scope)
                else:
                    new_b = registry.replace_fixed_length(val.strip(), scope, encoding="latin1")
                    new_val = new_b.decode("latin1")
                new_val = new_val[:total_val_slot].ljust(total_val_slot)
                if new_val.strip() != val.strip():
                    replacements += 1
                out_lines.append(f"{prefix}{new_val}\\{eol}")
            else:
                out_lines.append(ln)
        new_hdr_bytes = "".join(out_lines).encode("latin1", errors="replace")
        if len(new_hdr_bytes) == end_hdr:
            buf[:end_hdr] = new_hdr_bytes

    # 2. Length-preserving ASCII scrubbing inside sections after header (preserving #UGC_TOC offsets!)
    body_start = end_hdr if end_hdr != -1 else 0
    cur = bytes(buf)
    for m in re.finditer(rb"[\x20-\x7e]{4,}", cur[body_start:]):
        s = m.group(0).decode("latin1")
        if s.startswith(("#", "@", "UGC", "P_OBJECT", "END_OF")):
            continue
        new_b = registry.replace_fixed_length(s, scope, encoding="latin1")
        if len(new_b) == len(m.group(0)) and new_b != m.group(0):
            s_off = body_start + m.start()
            buf[s_off : s_off + len(new_b)] = new_b
            replacements += 1

    return bytes(buf), replacements


def process_catia_or_binary_cad(
    data: bytes, ext: str, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE
) -> tuple[bytes, int]:
    """Length-preserving ASCII & UTF-16LE scrubbing for CATIA V5 (V5_CFV2), U3D, 3DS, MF1."""
    buf = bytearray(data)
    replacements = 0
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        s = m.group(0).decode("latin1")
        if s.startswith(("V5_CFV2", "DASSAULT", "CAT", "NOTHING-", "StreamBlock")):
            continue
        new_b = registry.replace_fixed_length(s, scope, encoding="latin1")
        if len(new_b) == len(m.group(0)) and new_b != m.group(0):
            buf[m.start() : m.end()] = new_b
            replacements += 1
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", data):
        s = m.group(0).decode("utf-16-le", errors="ignore")
        if s.startswith(("CAT", "DASSAULT")):
            continue
        new_b = registry.replace_fixed_length(s, scope, encoding="utf-16-le")
        if len(new_b) == len(m.group(0)) and new_b != m.group(0):
            buf[m.start() : m.end()] = new_b
            replacements += 1
    return bytes(buf), replacements
