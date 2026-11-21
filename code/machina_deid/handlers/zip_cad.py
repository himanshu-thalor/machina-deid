"""ZIP-based native CAD handlers: FreeCAD (.fcstd), Fusion 360 (.f3d/.f3z), 3MF (.3mf), OpenDocument (.odg)."""

from __future__ import annotations

import io
import logging
import re
import struct
import zipfile

from lxml import etree

from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .image_handler import process_image_bytes

log = logging.getLogger(__name__)


def inspect_zip_cad_metadata(data: bytes, ext: str) -> list[tuple[str, str]]:
    """Extract metadata identifiers from FreeCAD, Fusion 360, 3MF, and ODG ZIP containers."""
    found: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for nm in zf.namelist():
                nl = nm.lower()
                if ext == ".fcstd" and nl in {"document.xml", "guidocument.xml"}:
                    txt = zf.read(nm).decode("utf-8", errors="replace")
                    for prop in ("CreatedBy", "LastModifiedBy", "Company", "License", "Comment", "FileName"):
                        for m in re.finditer(rf'name="{prop}"[^>]*>\s*<String\s+value="([^"]+)"', txt):
                            val = m.group(1).strip()
                            if val and "creativecommons" not in val.lower():
                                et = "PATH" if ("\\" in val or "/" in val) else ("ORG" if prop == "Company" else "PERSON")
                                found.append((et, val))
                elif ext == ".3mf" and nl.endswith((".model", ".xml", ".config")):
                    txt = zf.read(nm).decode("utf-8", errors="replace")
                    for m in re.finditer(r'<metadata\s+name="([^"]+)">([^<]+)</metadata>', txt, re.I):
                        k, v = m.group(1).lower(), m.group(2).strip()
                        if v and k in {"designer", "author", "copyright", "license", "title", "description", "company"}:
                            found.append(("PERSON" if k in {"designer", "author"} else "ORG", v))
                elif ext in {".f3d", ".f3z"} and nl.endswith((".dat", ".xml", ".json")):
                    raw = zf.read(nm)
                    for u16 in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", raw):
                        s = u16.decode("utf-16-le", errors="ignore").strip()
                        if "@" in s:
                            found.append(("EMAIL", s))
                        elif "\\" in s or "/" in s:
                            found.append(("PATH", s))
                elif ext == ".odg" and nl == "meta.xml":
                    txt = zf.read(nm).decode("utf-8", errors="replace")
                    for m in re.finditer(r"<(?:dc:creator|meta:initial-creator|dc:title)>([^<]+)</", txt):
                        found.append(("PERSON", m.group(1).strip()))
    except Exception:
        pass
    return found


def _scrub_fcstd_xml(raw: bytes, registry: IdentityRegistry, scope: str) -> tuple[bytes, int]:
    try:
        root = etree.fromstring(raw)
    except Exception:
        txt = raw.decode("utf-8", errors="replace")
        nt = registry.replace_text(txt, scope, context="xml")
        return nt.encode("utf-8"), (1 if nt != txt else 0)

    rep = 0
    for prop in root.xpath(".//Property"):
        pname = (prop.get("name") or "").lower()
        str_el = prop.find("String")
        if str_el is None:
            continue
        val = str_el.get("value") or ""
        if not val:
            continue
        if pname == "filename":
            new_v = registry.register_path(val, scope)
        elif pname in {"createdby", "lastmodifiedby"}:
            new_v = registry.replace_text(val, scope, context="metadata")
            if new_v == val and val.strip():
                new_v = registry.register(val.strip(), "PERSON", scope, is_global=False) or val
        elif pname == "company":
            new_v = registry.replace_text(val, scope, context="metadata")
            if new_v == val and val.strip():
                new_v = registry.register(val.strip(), "ORG", scope, is_global=False) or val
        elif pname in {"comment", "label", "licenseurl"}:
            new_v = registry.replace_text(val, scope, context="xml")
        else:
            new_v = registry.replace_text(val, scope, context="xml")
        if new_v != val:
            str_el.set("value", new_v)
            rep += 1

    return etree.tostring(root, xml_declaration=True, encoding="utf-8"), rep


def _scrub_3mf_xml(raw: bytes, registry: IdentityRegistry, scope: str) -> tuple[bytes, int]:
    """De-identify 3MF 3dmodel.model metadata & object names while preserving <mesh> geometry."""
    try:
        root = etree.fromstring(raw)
    except Exception:
        txt = raw.decode("utf-8", errors="replace")
        nt = registry.replace_text(txt, scope, context="xml")
        return nt.encode("utf-8"), (1 if nt != txt else 0)

    rep = 0
    for elem in root.iter():
        tag = etree.QName(elem).localname if isinstance(elem.tag, str) else ""
        if tag == "metadata":
            mname = (elem.get("name") or "").lower()
            if elem.text and elem.text.strip():
                nt = registry.replace_text(elem.text, scope, context="metadata")
                if nt == elem.text and mname in {"designer", "author", "company", "copyright"}:
                    et = "PERSON" if mname in {"designer", "author"} else "ORG"
                    nt = registry.register(elem.text.strip(), et, scope, is_global=False) or elem.text
                if nt != elem.text:
                    elem.text = nt
                    rep += 1
        elif tag in {"object", "component", "plate"}:
            nm = elem.get("name")
            if nm:
                nt = registry.replace_text(nm, scope, context="xml")
                if nt != nm:
                    elem.set("name", nt)
                    rep += 1

    return etree.tostring(root, xml_declaration=True, encoding="utf-8"), rep


def _scrub_f3d_binary_dat(raw: bytes, registry: IdentityRegistry, scope: str) -> tuple[bytes, int]:
    """Scrub Fusion 360 MetaStream.dat / Properties.dat / Manifest.dat safely."""
    from .solidworks_modern import _scrub_utf16_and_ascii_inplace

    # Check if XML
    if raw.lstrip().startswith((b"<?xml", b"<")):
        txt = raw.decode("utf-8", errors="replace")
        nt = registry.replace_text(txt, scope, context="xml")
        return nt.encode("utf-8"), (1 if nt != txt else 0)
    new_raw = _scrub_utf16_and_ascii_inplace(raw, registry, scope)
    return new_raw, (1 if new_raw != raw else 0)


def process_zip_cad_bytes(
    data: bytes, ext: str, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE, *, use_ocr: bool = True
) -> tuple[bytes, int]:
    """Process .fcstd, .f3d, .f3z, .3mf, .odg ZIP archives preserving geometry and structure."""
    try:
        in_bio = io.BytesIO(data)
        out_bio = io.BytesIO()
        rep_total = 0
        with zipfile.ZipFile(in_bio, "r") as zin, zipfile.ZipFile(out_bio, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                raw = zin.read(info.filename)
                nl = info.filename.lower()
                new_raw = raw

                if info.is_dir():
                    zout.writestr(info, b"")
                    continue

                if ext == ".fcstd":
                    if nl in {"document.xml", "guidocument.xml"}:
                        new_raw, r = _scrub_fcstd_xml(raw, registry, scope)
                        rep_total += r
                    elif nl == "stringhasher.table.txt":
                        txt = raw.decode("utf-8", errors="replace")
                        nt = registry.replace_text(txt, scope, context="metadata")
                        if nt != txt:
                            new_raw = nt.encode("utf-8")
                            rep_total += 1
                    elif nl.endswith(".svg"):
                        from .svg_dxf_dwg import process_svg_bytes

                        new_raw, r = process_svg_bytes(raw, registry, scope, use_ocr=use_ocr)
                        rep_total += r
                    elif nl.endswith((".png", ".jpg", ".jpeg")):
                        new_raw, r = process_image_bytes(raw, "." + nl.rsplit(".", 1)[-1], registry, scope, use_ocr=use_ocr)
                        rep_total += r

                elif ext == ".3mf":
                    if nl.endswith((".model", ".xml", ".config", ".rels")):
                        new_raw, r = _scrub_3mf_xml(raw, registry, scope)
                        rep_total += r
                    elif nl.endswith((".png", ".jpg", ".jpeg")):
                        new_raw, r = process_image_bytes(raw, "." + nl.rsplit(".", 1)[-1], registry, scope, use_ocr=use_ocr)
                        rep_total += r

                elif ext in {".f3d", ".f3z"}:
                    if nl.endswith((".dat", ".xml", ".json", ".txt")):
                        new_raw, r = _scrub_f3d_binary_dat(raw, registry, scope)
                        rep_total += r
                    elif nl.endswith((".png", ".jpg", ".jpeg")):
                        new_raw, r = process_image_bytes(raw, "." + nl.rsplit(".", 1)[-1], registry, scope, use_ocr=use_ocr)
                        rep_total += r
                    elif nl.endswith((".smt", ".smb")) and b"**END_OF_HEADER" in raw[:1024]:
                        from .text_cad import process_parasolid_bytes

                        new_raw, r = process_parasolid_bytes(raw, nl.endswith(".smb"), registry, scope)
                        rep_total += r

                elif ext == ".odg":
                    if nl.endswith(".xml"):
                        txt = raw.decode("utf-8", errors="replace")
                        nt = registry.replace_text(txt, scope, context="xml")
                        if nt != txt:
                            new_raw = nt.encode("utf-8")
                            rep_total += 1
                    elif nl.endswith((".png", ".jpg", ".jpeg")):
                        new_raw, r = process_image_bytes(raw, "." + nl.rsplit(".", 1)[-1], registry, scope, use_ocr=use_ocr)
                        rep_total += r

                # Preserve compression method and deterministic timestamp
                zi = zipfile.ZipInfo(info.filename, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = info.compress_type if info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) else zipfile.ZIP_DEFLATED
                zout.writestr(zi, new_raw)

        return out_bio.getvalue(), rep_total
    except Exception as e:
        log.debug("ZIP CAD failed (%s): %s", ext, e)
        return data, 0
