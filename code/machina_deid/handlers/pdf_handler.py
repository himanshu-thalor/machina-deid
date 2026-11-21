"""PDF handler: metadata/XMP sanitization, vector text redaction, logo replacement, OCR, and attachments."""

from __future__ import annotations

import io
import logging
import re
from threading import Lock

import pymupdf as fitz
from lxml import etree
import numpy as np
import pikepdf
from PIL import Image

from ..config import (
    SAFE_CAD_VENDORS,
    SAFE_DOMAINS,
    TITLE_BLOCK_ORG_LABELS,
    TITLE_BLOCK_PERSON_LABELS,
    TITLE_BLOCK_PROJECT_LABELS,
    is_safe_engineering_token,
    split_compound_extension,
)
from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .archive_handler import MAX_ARCHIVE_DEPTH, archive_output_name
from .image_handler import generate_neutral_logo, process_image_bytes, run_ocr_on_array

log = logging.getLogger(__name__)
_PDF_INSPECTION_LOCK = Lock()

RE_INITIAL_NAME = re.compile(r"\b([A-Z]\.(?:\s*[A-Z]\.)?\s*[A-Z][a-zA-Z\u00c0-\u024f-]{2,})\b")
RE_TITLE_NAME = re.compile(r"\b((?:Hr|Herr|Frau|Mr|Ms|Mrs|Dr|Prof|Ing)\.?\s+[A-Z][a-zA-Z\u00c0-\u024f-]{2,})\b")
RE_PERSON_PAIR = re.compile(r"\b([A-Z][a-z]{2,18}\s+[A-Z][a-z]{2,20})\b")


def inspect_pdf_metadata(data: bytes) -> list[tuple[str, str]]:
    # MuPDF requires single-threaded access inside a process.
    with _PDF_INSPECTION_LOCK:
        return _inspect_pdf_metadata(data)


def _inspect_pdf_metadata(data: bytes) -> list[tuple[str, str]]:
    """Extract identifying Info dict, XMP, links, attachments, and title-block clues from a PDF."""
    found: list[tuple[str, str]] = []
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception:
        return found

    try:
        meta = doc.metadata or {}
        for field, etype in (
            ("author", "PERSON"),
            ("title", "PART_ID"),
            ("subject", "PART_ID"),
            ("keywords", "PART_ID"),
        ):
            val = (meta.get(field) or "").strip()
            if not val:
                continue
            if field in {"title", "subject", "keywords"} and not re.search(r"@|\\|/|\.[a-z]{2,4}$|[A-Z]{2,}-\d{3,}", val, re.I):
                continue
            # Handle patterns like 'DMAWI\jlemburg (BINF04P010)'
            m_paren = re.match(r"^(.+?)\s*\(([A-Za-z0-9_-]{4,24})\)\s*$", val)
            if m_paren:
                found.append((etype, m_paren.group(1).strip()))
                found.append(("HOST", m_paren.group(2).strip()))
            else:
                found.append((etype, val))

        for k in ("creator", "producer"):
            val = (meta.get(k) or "").strip()
            if val and not any(cv in val.lower() for cv in SAFE_CAD_VENDORS):
                found.append(("ORG", val))

        # Embedded attachment names
        for i in range(doc.embfile_count()):
            info = doc.embfile_info(i)
            fn = info.get("filename") or info.get("name") or ""
            if fn:
                found.append(("PART_ID", fn))

        # Page 1..3 text & links for title-block clues
        for pno in range(min(3, len(doc))):
            page = doc[pno]
            for lnk in page.get_links():
                uri = lnk.get("uri") or ""
                if uri.startswith(("http://", "https://", "mailto:")):
                    found.append(("EMAIL" if uri.startswith("mailto:") else "URL", uri.replace("mailto:", "")))
            txt = page.get_text("text") or ""
            for m in RE_INITIAL_NAME.finditer(txt):
                cand = m.group(1).strip()
                if not is_safe_engineering_token(cand):
                    found.append(("PERSON", cand))
            for m in RE_TITLE_NAME.finditer(txt):
                found.append(("PERSON", m.group(1).strip()))
            # Check explicit labeled lines like "Author: John Smith" or "Project no: 12345"
            for line in txt.splitlines():
                if ":" in line:
                    lbl, rhs = line.split(":", 1)
                    rhs = rhs.strip()
                    if rhs and len(rhs) >= 3 and not is_safe_engineering_token(rhs):
                        if TITLE_BLOCK_PERSON_LABELS.search(lbl):
                            found.append(("PERSON", rhs))
                        elif TITLE_BLOCK_ORG_LABELS.search(lbl):
                            found.append(("ORG", rhs))
                        elif TITLE_BLOCK_PROJECT_LABELS.search(lbl):
                            found.append(("PROJECT", rhs))
    finally:
        doc.close()
    return found


def _is_title_block_zone(bbox: tuple[float, float, float, float], page_w: float, page_h: float) -> bool:
    x0, y0, x1, y1 = bbox
    # Standard engineering drawing title block: bottom-right quadrant or bottom/top edge strip
    if x0 >= page_w * 0.42 and y0 >= page_h * 0.65:
        return True
    if y0 >= page_h * 0.80 or y1 <= page_h * 0.08:
        return True
    return False


def _scrub_title_block_text(txt: str, registry: IdentityRegistry, scope: str, in_tb: bool) -> str:
    new_txt = registry.replace_text(txt, scope, context="pdf_span")
    if new_txt != txt:
        return new_txt
    if not in_tb:
        return txt

    # In title block zones, catch unlabeled person names/initials like "Geo Hr Dallmayr M.Littmann"
    def _sub_title_name(m: re.Match[str]) -> str:
        raw = m.group(1)
        if is_safe_engineering_token(raw):
            return raw
        return registry.register(raw, "PERSON", scope, is_global=True) or raw

    def _sub_init_name(m: re.Match[str]) -> str:
        raw = m.group(1)
        if is_safe_engineering_token(raw):
            return raw
        return registry.register(raw, "PERSON", scope, is_global=True) or raw

    out = RE_TITLE_NAME.sub(_sub_title_name, txt)
    out = RE_INITIAL_NAME.sub(_sub_init_name, out)
    if ":" in out:
        lbl, rhs = out.split(":", 1)
        rhs_s = rhs.strip()
        if rhs_s and len(rhs_s) >= 2 and not is_safe_engineering_token(rhs_s):
            if TITLE_BLOCK_PERSON_LABELS.search(lbl):
                p = registry.register(rhs_s, "PERSON", scope, is_global=False)
                if p:
                    out = f"{lbl}: {p}"
            elif TITLE_BLOCK_ORG_LABELS.search(lbl):
                p = registry.register(rhs_s, "ORG", scope, is_global=False)
                if p:
                    out = f"{lbl}: {p}"
            elif TITLE_BLOCK_PROJECT_LABELS.search(lbl):
                p = registry.register(rhs_s, "PROJECT", scope, is_global=False)
                if p:
                    out = f"{lbl}: {p}"
    return out


def _int_color_to_rgb(c: int) -> tuple[float, float, float]:
    r = ((c >> 16) & 0xFF) / 255.0
    g = ((c >> 8) & 0xFF) / 255.0
    b = (c & 0xFF) / 255.0
    return (r, g, b)


def _clean_pdf_xmp_and_info(pdf_bytes: bytes, new_meta: dict[str, str]) -> bytes:
    """Use pikepdf to sanitize Info dictionary and strip/rebuild XMP metadata cleanly."""
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            for k, pdf_k in (
                ("author", "/Author"),
                ("title", "/Title"),
                ("subject", "/Subject"),
                ("keywords", "/Keywords"),
                ("creator", "/Creator"),
                ("producer", "/Producer"),
            ):
                val = new_meta.get(k, "")
                if val:
                    pdf.docinfo[pdf_k] = val
                elif pdf_k in pdf.docinfo:
                    del pdf.docinfo[pdf_k]

            with pdf.open_metadata(set_pikepdf_as_editor=False) as xmp:
                for key in list(xmp.keys()):
                    del xmp[key]
                if new_meta.get("author"):
                    xmp["dc:creator"] = [new_meta["author"]]
                if new_meta.get("title"):
                    xmp["dc:title"] = new_meta["title"]
                if new_meta.get("subject"):
                    xmp["dc:description"] = new_meta["subject"]
                if new_meta.get("keywords"):
                    xmp["pdf:Keywords"] = new_meta["keywords"]
                if new_meta.get("creator"):
                    xmp["xmp:CreatorTool"] = new_meta["creator"]
                if new_meta.get("producer"):
                    xmp["pdf:Producer"] = new_meta["producer"]

            out = io.BytesIO()
            pdf.save(out, linearize=False, compress_streams=True, object_stream_mode=pikepdf.ObjectStreamMode.generate)
            return out.getvalue()
    except Exception as e:
        log.debug("pikepdf XMP cleanup fallback: %s", e)
        return pdf_bytes


def process_pdf_bytes(
    data: bytes, registry: IdentityRegistry, scope: str = GLOBAL_SCOPE, *, use_ocr: bool = True,
    depth: int = 0, warnings: list[str] | None = None,
) -> tuple[bytes, int]:
    """De-identify PDF metadata, XMP, attachments, vector text, title-block logos, and raster pages."""
    doc = fitz.open(stream=data, filetype="pdf")

    replacements = 0
    try:
        if doc.needs_pass:
            raise ValueError("Password-protected PDF")
        # 1. Recursively process PDF attachments (/EmbeddedFiles)
        if doc.embfile_count() > 0:
            from . import dispatch_bytes_detailed

            if depth >= MAX_ARCHIVE_DEPTH:
                raise ValueError("Embedded file recursion limit exceeded")

            saved_embs: list[tuple[str, bytes, str]] = []
            used_names: set[str] = set()
            for i in range(doc.embfile_count()):
                info = doc.embfile_info(i)
                fn = info.get("filename") or info.get("name") or f"attachment_{i}"
                desc = info.get("description") or ""
                raw_emb = doc.embfile_get(i)
                new_fn = registry.resolve_filename(fn, scope)
                new_desc = registry.replace_text(desc, scope, context="metadata")
                new_emb, emb_reps, emb_warnings, extension = dispatch_bytes_detailed(
                    raw_emb, new_fn, registry, scope, use_ocr=use_ocr, depth=depth + 1
                )
                if warnings is not None:
                    warnings.extend(emb_warnings)
                new_fn = archive_output_name(new_fn, extension)
                if new_fn in used_names:
                    stem, ext = split_compound_extension(new_fn)
                    suffix = 2
                    while f"{stem}_{suffix}{ext}" in used_names:
                        suffix += 1
                    new_fn = f"{stem}_{suffix}{ext}"
                used_names.add(new_fn)
                if new_fn != fn or new_desc != desc or emb_reps > 0:
                    replacements += 1
                saved_embs.append((new_fn, new_emb, new_desc))
            # Delete old attachments backwards and re-add clean ones
            for i in range(doc.embfile_count() - 1, -1, -1):
                doc.embfile_del(i)
            for new_fn, new_emb, new_desc in saved_embs:
                doc.embfile_add(new_fn, new_emb, filename=new_fn, desc=new_desc)

        # Determine org label for neutral logo replacement
        org_label = "ORG-0001"
        for _, ent in registry.entities.items():
            if ent.entity_type == "ORG" and (GLOBAL_SCOPE in ent.scopes or scope in ent.scopes):
                org_label = ent.pseudonym
                break

        # 2. Per-page vector redaction, link/annotation scrub, logo & raster handling
        for page in doc:
            pw, ph = page.rect.width, page.rect.height
            page_dict = page.get_text("dict")
            pending_rotated: list[tuple[fitz.Rect, str, float, tuple[float, float, float], int]] = []
            page_redacted = False

            for blk in page_dict.get("blocks", []):
                if blk.get("type") != 0:
                    continue
                for line in blk.get("lines", []):
                    line_bbox = tuple(line.get("bbox", (0, 0, 0, 0)))
                    in_tb = _is_title_block_zone(line_bbox, pw, ph)
                    line_dir = line.get("dir", (1.0, 0.0))
                    is_rotated = abs(line_dir[0]) < 0.5
                    spans = line.get("spans", [])
                    if not spans:
                        continue

                    # Check both span-by-span and full line string
                    line_txt = "".join(sp.get("text", "") for sp in spans)
                    new_line_txt = _scrub_title_block_text(line_txt, registry, scope, in_tb)
                    if new_line_txt == line_txt:
                        continue

                    # Try per-span redaction first if individual spans carry the changes cleanly
                    span_changed = False
                    for sp in spans:
                        stxt = sp.get("text", "")
                        if not stxt.strip():
                            continue
                        new_stxt = _scrub_title_block_text(stxt, registry, scope, in_tb)
                        if new_stxt != stxt:
                            span_changed = True
                            srect = fitz.Rect(sp["bbox"])
                            fsize = max(5.0, float(sp.get("size", 8.0)))
                            col = _int_color_to_rgb(int(sp.get("color", 0)))
                            if is_rotated:
                                page.add_redact_annot(srect, fill=(1, 1, 1), cross_out=False)
                                rot = 90 if line_dir[1] < -0.5 else 270
                                pending_rotated.append((srect, new_stxt, fsize, col, rot))
                            else:
                                # Slightly widen rect horizontally if pseudonym is longer
                                if len(new_stxt) > len(stxt):
                                    extra = min(pw - srect.x1, (len(new_stxt) - len(stxt)) * fsize * 0.45)
                                    if extra > 0:
                                        srect = fitz.Rect(srect.x0, srect.y0, srect.x1 + extra, srect.y1)
                                page.add_redact_annot(
                                    srect,
                                    text=new_stxt,
                                    fontsize=min(fsize, max(5.0, srect.height * 0.85)),
                                    fill=(1, 1, 1),
                                    text_color=col,
                                    cross_out=False,
                                )
                            replacements += 1
                            page_redacted = True

                    if not span_changed:
                        # Identifier spanned multiple spans: redact whole line bbox
                        lrect = fitz.Rect(line_bbox)
                        sp0 = spans[0]
                        fsize = max(5.0, float(sp0.get("size", 8.0)))
                        col = _int_color_to_rgb(int(sp0.get("color", 0)))
                        if is_rotated:
                            page.add_redact_annot(lrect, fill=(1, 1, 1), cross_out=False)
                            rot = 90 if line_dir[1] < -0.5 else 270
                            pending_rotated.append((lrect, new_line_txt, fsize, col, rot))
                        else:
                            page.add_redact_annot(
                                lrect,
                                text=new_line_txt,
                                fontsize=min(fsize, max(5.0, lrect.height * 0.85)),
                                fill=(1, 1, 1),
                                text_color=col,
                                cross_out=False,
                            )
                        replacements += 1
                        page_redacted = True

            if page_redacted:
                # CRITICAL: Never strip line-art vector geometry or non-overlapping images!
                page.apply_redactions(
                    images=fitz.PDF_REDACT_IMAGE_NONE,
                    graphics=fitz.PDF_REDACT_LINE_ART_NONE,
                )
                for rrect, rtxt, rfsize, rcol, rrot in pending_rotated:
                    page.insert_textbox(rrect, rtxt, fontsize=rfsize * 0.85, color=rcol, rotate=rrot)

            # Update links
            for lnk in page.get_links():
                uri = lnk.get("uri") or ""
                if uri.startswith(("http://", "https://", "mailto:")):
                    new_uri = registry.replace_text(uri, scope, context="metadata")
                    if new_uri != uri:
                        lnk["uri"] = new_uri
                        page.update_link(lnk)
                        replacements += 1

            # Scrub annotations
            for annot in page.annots() or []:
                info = annot.info or {}
                changed_a = False
                for ak in ("content", "title", "subject"):
                    av = info.get(ak) or ""
                    if av:
                        nv = registry.replace_text(av, scope, context="metadata")
                        if nv != av:
                            info[ak] = nv
                            changed_a = True
                if changed_a:
                    annot.set_info(info)
                    annot.update()
                    replacements += 1

            # Inspect embedded images: replace title-block/header logos & OCR scanned sheets
            page_area = max(1.0, pw * ph)
            vec_text_len = len((page.get_text("text") or "").strip())
            replaced_xrefs: set[int] = set()
            for img_info in page.get_images(full=True):
                xref = img_info[0]
                if xref in replaced_xrefs:
                    continue
                rects = page.get_image_rects(xref)
                if not rects:
                    continue
                img_rect = rects[0]
                img_area = img_rect.width * img_rect.height
                is_small_corner = (img_area < page_area * 0.12) and (
                    _is_title_block_zone(tuple(img_rect), pw, ph)
                    or img_rect.y1 <= ph * 0.20
                    or img_rect.x0 <= pw * 0.18
                    or img_rect.x1 >= pw * 0.82
                )
                try:
                    extracted = doc.extract_image(xref)
                    img_b = extracted.get("image") or b""
                    iw = int(extracted.get("width", 120))
                    ih = int(extracted.get("height", 60))
                except Exception:
                    continue

                if is_small_corner and iw >= 16 and ih >= 16:
                    # Replace suspected logo/stamp in title block or corner with neutral emblem
                    neutral = generate_neutral_logo(iw, ih, org_label, transparent=False)
                    page.replace_image(xref, stream=neutral)
                    replaced_xrefs.add(xref)
                    replacements += 1
                elif use_ocr and img_area >= page_area * 0.25 and vec_text_len < 120 and img_b:
                    # Scanned / rasterized engineering drawing: run OCR + clean metadata
                    ext_i = "." + str(extracted.get("ext", "png"))
                    clean_img, ir = process_image_bytes(img_b, ext_i, registry, scope, use_ocr=True)
                    if ir > 0:
                        page.replace_image(xref, stream=clean_img)
                        replaced_xrefs.add(xref)
                        replacements += ir

        # 3. Bookmarks / TOC
        toc = doc.get_toc()
        if toc:
            new_toc = []
            toc_changed = False
            for lvl, ttitle, pg in toc:
                nt = registry.replace_text(ttitle, scope, context="metadata")
                if nt != ttitle:
                    toc_changed = True
                new_toc.append([lvl, nt, pg])
            if toc_changed:
                doc.set_toc(new_toc)
                replacements += 1

        # 4. PDF Info dictionary
        old_meta = doc.metadata or {}
        new_meta: dict[str, str] = {}
        for k in ("author", "title", "subject", "keywords", "creator", "producer"):
            val = (old_meta.get(k) or "").strip()
            if not val:
                new_meta[k] = ""
                continue
            if k in {"creator", "producer"} and any(cv in val.lower() for cv in SAFE_CAD_VENDORS):
                new_meta[k] = val
                continue
            rep = registry.replace_text(val, scope, context="metadata")
            if rep == val:
                if k == "author":
                    rep = registry.register(val, "PERSON", scope, is_global=False) or val
                elif k in {"creator", "producer"}:
                    rep = registry.register(val, "ORG", scope, is_global=False) or val
            if rep != val:
                replacements += 1
            new_meta[k] = rep
        doc.set_metadata(new_meta)

        raw_out = doc.tobytes(garbage=4, deflate=True, clean=True)
    finally:
        doc.close()

    # 5. Scrub XMP packet cleanly with pikepdf
    final_bytes = _clean_pdf_xmp_and_info(raw_out, new_meta)
    return final_bytes, replacements
