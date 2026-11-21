"""Handlers for SVG (.svg), DXF (.dxf), and DWG (.dwg) 2D CAD / vector drawing formats."""

from __future__ import annotations

import base64
import io
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import ezdxf
from ezdxf.document import Drawing
from ezdxf.filemanagement import dxf_stream_info
from ezdxf.lldxf.tagger import binary_tags_loader
from ezdxf.lldxf.validator import is_dxf_stream
from lxml import etree

from ..config import SAFE_CAD_VENDORS, is_safe_engineering_token
from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .image_handler import process_image_bytes

log = logging.getLogger(__name__)

RE_DATA_IMG = re.compile(r"^data:image/(png|jpeg|jpg|bmp|tiff);base64,(.+)$", re.I | re.S)


def inspect_svg_metadata(data: bytes) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    try:
        root = etree.fromstring(data)
    except Exception:
        return found

    for attr in ("{http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd}docname", "{http://www.inkscape.org/namespaces/inkscape}export-filename"):
        val = root.get(attr)
        if val:
            if "\\" in val or "/" in val:
                found.append(("PATH", val))
            elif re.search(r"@|[A-Z]{2,}[-_]\d{3,}", val):
                found.append(("PART_ID", val))

    for elem in root.iter():
        tag = etree.QName(elem).localname if isinstance(elem.tag, str) else ""
        if tag in {"creator", "title", "rights", "publisher", "subject"} and elem.text and elem.text.strip():
            et = "PERSON" if tag == "creator" else ("ORG" if tag == "publisher" else "PART_ID")
            found.append((et, elem.text.strip()))
    return found


def process_svg_bytes(
    data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE, *, use_ocr: bool = True
) -> tuple[bytes, int]:
    """De-identify SVG metadata, Inkscape path attributes, comments, text elements, and embedded logos."""
    try:
        parser = etree.XMLParser(recover=True, remove_blank_text=False)
        root = etree.fromstring(data, parser=parser)
        if root is None:
            return data, 0
    except Exception:
        txt = data.decode("utf-8", errors="replace")
        nt = registry.replace_text(txt, scope, context="xml")
        return nt.encode("utf-8"), (1 if nt != txt else 0)

    replacements = 0
    org_label = "ORG-0001"
    for ent in registry.entities.values():
        if ent.entity_type == "ORG" and (GLOBAL_SCOPE in ent.scopes or scope in ent.scopes):
            org_label = ent.pseudonym
            break

    # Scrub root Inkscape/Sodipodi file-path attributes
    for k, v in list(root.attrib.items()):
        kl = k.lower()
        if any(s in kl for s in ("docname", "export-filename", "source")):
            nv = registry.register_path(v, scope) if ("\\" in v or "/" in v) else registry.replace_text(v, scope, context="filename")
            if nv != v:
                root.set(k, nv)
                replacements += 1

    for elem in root.iter():
        if isinstance(elem, etree._Comment):
            if elem.text:
                nt = registry.replace_text(elem.text, scope, context="xml")
                if nt != elem.text:
                    elem.text = nt
                    replacements += 1
            continue
        if not isinstance(elem.tag, str):
            continue
        tag = etree.QName(elem).localname
        if tag in {"title", "desc", "text", "tspan", "creator", "publisher", "rights", "subject", "description"}:
            if elem.text and elem.text.strip():
                nt = registry.replace_text(elem.text, scope, context="xml")
                if nt == elem.text and tag in {"creator", "publisher"} and not any(cv in elem.text.lower() for cv in SAFE_CAD_VENDORS):
                    nt = registry.register(elem.text.strip(), "PERSON" if tag == "creator" else "ORG", scope, is_global=False) or elem.text
                if nt != elem.text:
                    elem.text = nt
                    replacements += 1
            if elem.tail and elem.tail.strip():
                nt2 = registry.replace_text(elem.tail, scope, context="xml")
                if nt2 != elem.tail:
                    elem.tail = nt2
                    replacements += 1
        elif tag == "image":
            for hk in ("{http://www.w3.org/1999/xlink}href", "href"):
                hv = elem.get(hk)
                if not hv:
                    continue
                m = RE_DATA_IMG.match(hv.strip())
                if m:
                    img_fmt, b64 = m.groups()
                    try:
                        raw_img = base64.b64decode(b64)
                        w_attr = float(re.sub(r"[^0-9.]", "", elem.get("width") or "0") or 0)
                        h_attr = float(re.sub(r"[^0-9.]", "", elem.get("height") or "0") or 0)
                        is_logo = (0 < w_attr <= 300 and 0 < h_attr <= 200)
                        clean_img, ir = process_image_bytes(
                            raw_img,
                            f".{img_fmt.lower()}",
                            registry,
                            scope,
                            use_ocr=use_ocr,
                            is_logo_candidate=is_logo,
                            org_label=org_label,
                        )
                        if ir > 0:
                            out_mime = "png" if is_logo else img_fmt.lower()
                            elem.set(hk, f"data:image/{out_mime};base64,{base64.b64encode(clean_img).decode('ascii')}")
                            replacements += ir
                    except Exception:
                        pass
                else:
                    nv = registry.register_path(hv, scope) if ("\\" in hv or "/" in hv) else registry.replace_text(hv, scope, context="filename")
                    if nv != hv:
                        elem.set(hk, nv)
                        replacements += 1
        # Check id/label attributes in Inkscape layers
        for ak in ("{http://www.inkscape.org/namespaces/inkscape}label", "id"):
            av = elem.get(ak)
            if av and not is_safe_engineering_token(av):
                nv = registry.replace_text(av, scope, context="xml")
                if nv != av:
                    elem.set(ak, nv)
                    replacements += 1

    out = etree.tostring(root, xml_declaration=True, encoding="utf-8")
    return out, replacements


# ---------------------------------------------------------------------------
# DXF (.dxf) via ezdxf
# ---------------------------------------------------------------------------

DXF_BINARY_SIGNATURE = b"AutoCAD Binary DXF\r\n\x1a\x00"


def read_dxf_document(data: bytes) -> Drawing:
    """Load binary or ASCII DXF with the source codepage and universal newlines."""
    if data.startswith(DXF_BINARY_SIGNATURE):
        return Drawing.load(binary_tags_loader(data))

    # HEADER codepage declarations are ASCII. Latin-1 also preserves all bytes
    # read ahead while probing the declared encoding.
    with io.TextIOWrapper(io.BytesIO(data), encoding="latin-1") as probe:
        if not is_dxf_stream(probe):
            raise ezdxf.DXFStructureError("Missing DXF section")
        probe.seek(0)
        encoding = dxf_stream_info(probe).encoding
    # TextIOWrapper translates CRLF so hex-valued tags reach the parser without CR.
    with io.TextIOWrapper(io.BytesIO(data), encoding=encoding, errors="surrogateescape") as source:
        return ezdxf.read(source)


def inspect_dxf_metadata(data: bytes) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    try:
        doc = read_dxf_document(data)
        for hv in ("$LASTSAVEDBY", "$PROJECTNAME", "$HYPERLINKBASE"):
            v = str(doc.header.get(hv, "") or "").strip()
            if v:
                found.append(("USERNAME" if hv == "$LASTSAVEDBY" else "PROJECT", v))
        try:
            meta = doc.ezdxf_metadata()
            for k in ("author", "title", "subject", "comments"):
                v = str(meta.get(k, "") or "").strip()
                if v:
                    found.append(("PERSON" if k == "author" else "PART_ID", v))
        except Exception:
            pass
    except Exception:
        pass
    return found


def _scrub_dxf_entity_text(ent, registry: IdentityRegistry, scope: str) -> int:
    rep = 0
    etype = ent.dxftype()
    if etype in {"TEXT", "ATTRIB", "ATTDEF"}:
        old = ent.dxf.get("text", "")
        if old:
            new = registry.replace_text(old, scope, context="title_block")
            if new != old:
                ent.dxf.text = new
                rep += 1
        if etype in {"ATTRIB", "ATTDEF"}:
            tag = ent.dxf.get("tag", "")
            if tag and tag.upper() in {"AUTHOR", "DRAWN", "DRAWN_BY", "COMPANY", "CLIENT", "ENGINEER", "DESIGNED_BY"} and old:
                new2 = registry.register(old.strip(), "PERSON" if "COMPANY" not in tag.upper() and "CLIENT" not in tag.upper() else "ORG", scope, is_global=False)
                if new2 and new2 != old:
                    ent.dxf.text = new2
                    rep += 1
    elif etype == "MTEXT":
        old = ent.text or ""
        if old:
            new = registry.replace_text(old, scope, context="title_block")
            if new != old:
                ent.text = new
                rep += 1
    elif etype == "INSERT":
        for attribute in ent.attribs:
            rep += _scrub_dxf_entity_text(attribute, registry, scope)
    return rep


def process_dxf_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int]:
    """De-identify DXF header vars, summary info, thumbnails, XREFs, and TEXT/MTEXT/ATTRIB entities."""
    doc = read_dxf_document(data)

    rep = 0
    # 1. Header vars
    for hv, etype in (("$LASTSAVEDBY", "USERNAME"), ("$PROJECTNAME", "PROJECT"), ("$HYPERLINKBASE", "PATH")):
        if hv in doc.header:
            val = str(doc.header[hv] or "").strip()
            if val:
                nv = registry.register_path(val, scope) if etype == "PATH" else (
                    registry.replace_text(val, scope, context="metadata")
                )
                if nv == val:
                    nv = registry.register(val, etype, scope, is_global=False) or val
                if nv != val:
                    doc.header[hv] = nv
                    rep += 1

    # Clear custom header properties if identifying
    try:
        cv = doc.header.custom_vars
        for k, v in list(cv.properties):
            nv = registry.replace_text(str(v), scope, context="metadata")
            if nv != str(v):
                cv.replace(k, nv)
                rep += 1
    except Exception:
        pass

    # 2. Blocks include modelspace and paperspace layouts.
    for blk in doc.blocks:
        blk_ent = getattr(blk, "block", None)
        if blk_ent is not None and getattr(blk_ent, "is_xref", False):
            xp = blk_ent.dxf.get("xref_path", "")
            if xp:
                nxp = registry.register_path(xp, scope) if ("\\" in xp or "/" in xp) else registry.resolve_filename(xp, scope)
                if nxp != xp:
                    blk_ent.dxf.xref_path = nxp
                    rep += 1
        for ent in blk:
            rep += _scrub_dxf_entity_text(ent, registry, scope)

    # 3. Scrub IMAGE / UNDERLAY paths
    for obj in doc.objects:
        if obj.dxftype() in {"IMAGEDEF", "PDFDEFINITION", "DWFDEFINITION", "DGNDEFINITION"}:
            fn = obj.dxf.get("filename", "")
            if fn:
                nfn = registry.register_path(fn, scope) if ("\\" in fn or "/" in fn) else registry.resolve_filename(fn, scope)
                if nfn != fn:
                    obj.dxf.filename = nfn
                    rep += 1

    # 4. Remove only the thumbnail section, preserving native binary records
    # elsewhere in the drawing, such as XRECORD data and ACIS geometry.
    retained_sections = [section for section in doc.stored_sections if section.entities[0][1] != (2, "THUMBNAILIMAGE")]
    rep += len(doc.stored_sections) - len(retained_sections)
    doc.stored_sections[:] = retained_sections

    if data.startswith(DXF_BINARY_SIGNATURE):
        binary_output = io.BytesIO()
        doc.write(binary_output, fmt="bin")
        return binary_output.getvalue(), rep
    text_output = io.StringIO()
    doc.write(text_output)
    return doc.encode(text_output.getvalue()), rep


# ---------------------------------------------------------------------------
# DWG (.dwg)
# ---------------------------------------------------------------------------

def process_dwg_bytes(data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE) -> tuple[bytes, int, list[str]]:
    """De-identify DWG via LibreDWG round-trip if installed, else length-preserving binary scrub."""
    warnings: list[str] = []
    dwg2dxf = shutil.which("dwg2dxf")
    dxf2dwg = shutil.which("dxf2dwg")
    if dwg2dxf and dxf2dwg:
        try:
            with tempfile.TemporaryDirectory() as td:
                td_p = Path(td)
                in_dwg = td_p / "in.dwg"
                mid_dxf = td_p / "mid.dxf"
                out_dxf = td_p / "out.dxf"
                out_dwg = td_p / "out.dwg"
                in_dwg.write_bytes(data)
                r1 = subprocess.run([dwg2dxf, str(in_dwg), "-o", str(mid_dxf)], capture_output=True, timeout=60)
                if r1.returncode == 0 and mid_dxf.exists() and mid_dxf.stat().st_size > 0:
                    clean_dxf, rep = process_dxf_bytes(mid_dxf.read_bytes(), registry, scope)
                    out_dxf.write_bytes(clean_dxf)
                    r2 = subprocess.run([dxf2dwg, str(out_dxf), "-o", str(out_dwg)], capture_output=True, timeout=60)
                    if r2.returncode == 0 and out_dwg.exists() and out_dwg.stat().st_size > 0:
                        return out_dwg.read_bytes(), rep, warnings
        except Exception as e:
            log.debug("LibreDWG round-trip failed, falling back to binary scrub: %s", e)

    # Length-preserving UTF-16LE & ASCII scrubbing of uncompressed DWG metadata strings
    from .solidworks_modern import _scrub_utf16_and_ascii_inplace

    scrubbed = _scrub_utf16_and_ascii_inplace(data, registry, scope)
    rep = 1 if scrubbed != data else 0
    if not (dwg2dxf and dxf2dwg):
        warnings.append("dwg_compressed_sections_need_oda_or_libredwg_for_internal_lz77_text")
    return scrubbed, rep, warnings
