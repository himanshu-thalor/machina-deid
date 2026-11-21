"""Raster image metadata stripping, OCR text de-identification, and logo emblem synthesis."""

from __future__ import annotations

import io
import logging
import re
from typing import Any

import numpy as np
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

from ..config import TITLE_BLOCK_ORG_LABELS, TITLE_BLOCK_PERSON_LABELS, TITLE_BLOCK_PROJECT_LABELS
from ..registry import GLOBAL_SCOPE, IdentityRegistry

log = logging.getLogger(__name__)

_OCR_ENGINE: Any = None
_OCR_TRIED = False


def get_ocr_engine() -> Any:
    """Lazily initialize RapidOCR (or pytesseract fallback), returning None if unavailable."""
    global _OCR_ENGINE, _OCR_TRIED
    if _OCR_TRIED:
        return _OCR_ENGINE
    _OCR_TRIED = True
    try:
        from rapidocr import RapidOCR  # type: ignore

        _OCR_ENGINE = ("rapidocr", RapidOCR())
        return _OCR_ENGINE
    except Exception as e:
        log.debug("rapidocr unavailable: %s", e)
    try:
        from rapidocr_onnxruntime import RapidOCR as LegacyRapidOCR  # type: ignore

        _OCR_ENGINE = ("rapidocr_legacy", LegacyRapidOCR())
        return _OCR_ENGINE
    except Exception:
        pass
    try:
        import pytesseract  # type: ignore

        pytesseract.get_tesseract_version()
        _OCR_ENGINE = ("pytesseract", pytesseract)
        return _OCR_ENGINE
    except Exception:
        pass
    return None


def run_ocr_on_array(img_rgb: np.ndarray) -> list[tuple[list[tuple[float, float]], str, float]]:
    """Run OCR on an RGB numpy array and return [(quad_points, text, confidence), ...]."""
    eng = get_ocr_engine()
    if eng is None:
        return []
    kind, driver = eng
    results: list[tuple[list[tuple[float, float]], str, float]] = []
    try:
        if kind == "rapidocr":
            out = driver(img_rgb)
            boxes = getattr(out, "boxes", None)
            txts = getattr(out, "txts", None)
            scores = getattr(out, "scores", None)
            if boxes is not None and txts is not None:
                for i, txt in enumerate(txts):
                    if not txt:
                        continue
                    box = boxes[i]
                    sc = float(scores[i]) if scores is not None and i < len(scores) else 0.9
                    pts = [(float(p[0]), float(p[1])) for p in box]
                    results.append((pts, str(txt), sc))
        elif kind == "rapidocr_legacy":
            res, _ = driver(img_rgb)
            if res:
                for item in res:
                    box, txt, sc = item[0], item[1], float(item[2])
                    pts = [(float(p[0]), float(p[1])) for p in box]
                    results.append((pts, str(txt), sc))
        elif kind == "pytesseract":
            pil_img = Image.fromarray(img_rgb)
            data = driver.image_to_data(pil_img, output_type=driver.Output.DICT)
            n = len(data.get("text", []))
            for i in range(n):
                txt = (data["text"][i] or "").strip()
                conf = float(data["conf"][i]) if data["conf"][i] != "-1" else 0.0
                if not txt or conf < 30.0:
                    continue
                x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                pts = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
                results.append((pts, txt, conf / 100.0))
    except Exception as e:
        log.debug("OCR failed gracefully: %s", e)
    return results


def _fit_font(text: str, box_w: int, box_h: int) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    target_h = max(8, int(box_h * 0.72))
    try:
        font = ImageFont.load_default(size=target_h)
        if text:
            bbox = font.getbbox(text)
            tw = max(1, bbox[2] - bbox[0])
            if tw > box_w * 0.96:
                scaled = max(7, int(target_h * (box_w * 0.94) / tw))
                font = ImageFont.load_default(size=scaled)
        return font
    except TypeError:
        return ImageFont.load_default()


def generate_neutral_logo(width: int, height: int, label: str = "ORG", *, transparent: bool = False) -> bytes:
    """Create a clean neutral geometric emblem PNG of exact dimensions."""
    w = max(16, int(width))
    h = max(16, int(height))
    bg = (255, 255, 255, 0) if transparent else (246, 248, 250, 255)
    img = Image.new("RGBA", (w, h), bg)
    draw = ImageDraw.Draw(img)

    pad = max(2, min(w, h) // 12)
    accent = (52, 73, 94, 255)
    border = (140, 152, 164, 255)
    draw.rounded_rectangle(
        [pad, pad, max(pad + 4, w - 1 - pad), max(pad + 4, h - 1 - pad)],
        radius=max(2, min(w, h) // 10),
        outline=border,
        width=max(1, min(w, h) // 24),
        fill=(242, 245, 248, 255) if not transparent else None,
    )
    # Simple geometric hexagon/badge mark on left if wide enough, else centered text
    short = re.sub(r"[^A-Za-z0-9-]", "", label)[:10] or "ORG"
    font = _fit_font(short, max(8, w - 2 * pad), max(8, h - 2 * pad))
    bbox = draw.textbbox((0, 0), short, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (w - tw) // 2 - bbox[0]
    ty = (h - th) // 2 - bbox[1]
    draw.text((tx, ty), short, fill=accent, font=font)

    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


def _sample_bg_color(arr: np.ndarray, x0: int, y0: int, x1: int, y1: int) -> tuple[int, ...]:
    h, w = arr.shape[:2]
    x0c, x1c = max(0, x0), min(w - 1, x1)
    y0c, y1c = max(0, y0), min(h - 1, y1)
    border_pixels = []
    if y0c > 0:
        border_pixels.append(arr[y0c - 1, x0c : x1c + 1])
    if y1c + 1 < h:
        border_pixels.append(arr[y1c + 1, x0c : x1c + 1])
    if x0c > 0:
        border_pixels.append(arr[y0c : y1c + 1, x0c - 1])
    if x1c + 1 < w:
        border_pixels.append(arr[y0c : y1c + 1, x1c + 1])
    if not border_pixels:
        return (255, 255, 255) if arr.shape[2] == 3 else (255, 255, 255, 255)
    stacked = np.concatenate(border_pixels, axis=0)
    med = np.median(stacked, axis=0).astype(int)
    return tuple(int(v) for v in med)


def inspect_image_text(
    img_bytes: bytes,
    registry: IdentityRegistry,
    scope: str,
    *,
    use_ocr: bool = True,
) -> list[str]:
    """Extract metadata text (PNG chunks, EXIF, XMP) and optional OCR strings for discovery."""
    found: list[str] = []
    try:
        with Image.open(io.BytesIO(img_bytes)) as im:
            for k, v in (im.info or {}).items():
                if isinstance(v, (str, bytes)) and str(k).lower() not in {"icc_profile", "dpi", "gamma", "chromaticity"}:
                    s = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
                    if s.strip():
                        found.append(s)
            if use_ocr and im.width >= 32 and im.height >= 24:
                rgb = np.array(im.convert("RGB"))
                for _, txt, sc in run_ocr_on_array(rgb):
                    if sc >= 0.45 and txt.strip():
                        found.append(txt.strip())
    except Exception:
        pass
    return found


def process_image_bytes(
    img_bytes: bytes,
    ext: str,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    use_ocr: bool = True,
    is_logo_candidate: bool = False,
    org_label: str = "ORG-0001",
) -> tuple[bytes, int]:
    """Strip image metadata and scrub OCR-detected identifying text (or replace logo)."""
    replacements = 0
    try:
        with Image.open(io.BytesIO(img_bytes)) as src_im:
            orig_fmt = src_im.format or _fmt_from_ext(ext)
            orig_mode = src_im.mode
            w, h = src_im.size

            if is_logo_candidate and w <= 800 and h <= 400:
                logo_png = generate_neutral_logo(w, h, org_label, transparent=("A" in orig_mode))
                if orig_fmt.upper() == "PNG":
                    return logo_png, 1
                with Image.open(io.BytesIO(logo_png)) as lim:
                    buf = io.BytesIO()
                    save_im = lim.convert("RGB") if orig_fmt.upper() in {"JPEG", "JPG"} else lim
                    save_im.save(buf, format=orig_fmt)
                    return buf.getvalue(), 1

            # Strip all metadata by copying raw pixel data to a clean Image
            need_alpha = ("A" in orig_mode) or (orig_mode == "P" and "transparency" in (src_im.info or {}))
            work = src_im.convert("RGBA" if need_alpha else "RGB")
            if use_ocr and w >= 40 and h >= 20:
                rgb_arr = np.array(work.convert("RGB"))
                ocr_hits = run_ocr_on_array(rgb_arr)
                if ocr_hits:
                    draw = ImageDraw.Draw(work)
                    arr = np.array(work)
                    for pts, txt, sc in ocr_hits:
                        if sc < 0.45 or len(txt.strip()) < 3:
                            continue
                        new_txt = registry.replace_text(txt, scope, context="title_block")
                        # Also scrub obvious person/org lines immediately adjacent to labels
                        if new_txt == txt and (
                            TITLE_BLOCK_PERSON_LABELS.search(txt)
                            or TITLE_BLOCK_ORG_LABELS.search(txt)
                            or TITLE_BLOCK_PROJECT_LABELS.search(txt)
                        ):
                            new_txt = _scrub_labeled_line(txt, registry, scope)
                        if new_txt != txt:
                            xs = [p[0] for p in pts]
                            ys = [p[1] for p in pts]
                            x0, x1 = max(0, int(min(xs)) - 2), min(w - 1, int(max(xs)) + 2)
                            y0, y1 = max(0, int(min(ys)) - 2), min(h - 1, int(max(ys)) + 2)
                            bg = _sample_bg_color(arr, x0, y0, x1, y1)
                            fg = (20, 20, 20) if sum(bg[:3]) > 380 else (240, 240, 240)
                            if len(bg) == 4:
                                fg = fg + (255,)
                            draw.rectangle([x0, y0, x1, y1], fill=bg)
                            font = _fit_font(new_txt, max(10, x1 - x0), max(8, y1 - y0))
                            draw.text((x0 + 1, y0), new_txt, fill=fg, font=font)
                            replacements += 1

            # Metadata count check (EXIF / info text)
            if src_im.info:
                for k in src_im.info:
                    if str(k).lower() in {"exif", "xmp", "comment", "author", "title", "software", "xml:com.adobe.xmp"}:
                        replacements += 1

            # Re-encode cleanly with no EXIF/XMP/tEXt chunks
            out_buf = io.BytesIO()
            fmt_upper = orig_fmt.upper()
            if fmt_upper == "JPEG":
                work.convert("RGB").save(out_buf, format="JPEG", quality=92)
            elif fmt_upper == "PNG":
                info = PngImagePlugin.PngInfo()
                work.save(out_buf, format="PNG", pnginfo=info, optimize=True)
            elif fmt_upper == "TIFF":
                work.save(out_buf, format="TIFF")
            else:
                if orig_mode in {"1", "L", "P"} and "A" not in orig_mode:
                    work.convert(orig_mode).save(out_buf, format=orig_fmt)
                else:
                    work.save(out_buf, format=orig_fmt)
            return out_buf.getvalue(), replacements
    except Exception as e:
        log.debug("Image clean fallback (%s): %s", ext, e)
        return img_bytes, 0


def _scrub_labeled_line(line: str, registry: IdentityRegistry, scope: str) -> str:
    if ":" in line:
        lbl, val = line.split(":", 1)
        val_s = val.strip()
        if val_s:
            p = registry.register(val_s, "PERSON" if TITLE_BLOCK_PERSON_LABELS.search(lbl) else "ORG", scope, is_global=False)
            if p:
                return f"{lbl}: {p}"
    return registry.replace_text(line, scope, context="title_block")


def _fmt_from_ext(ext: str) -> str:
    e = ext.lower().lstrip(".")
    if e in {"jpg", "jpeg"}:
        return "JPEG"
    if e in {"tif", "tiff"}:
        return "TIFF"
    if e == "bmp":
        return "BMP"
    return "PNG"
