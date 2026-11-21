"""Unified format dispatcher routing files by magic bytes and compound extensions."""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import TransformResult, split_compound_extension
from ..registry import GLOBAL_SCOPE, IdentityRegistry
from .archive_handler import (
    archive_output_name,
    inspect_archive_bytes,
    inspect_archive_file,
    is_archive_extension,
    process_archive_bytes,
)
from .creo_catia import (
    inspect_creo_metadata,
    is_catia_v5,
    is_creo_ugc,
    process_catia_or_binary_cad,
    process_creo_bytes,
)
from .image_handler import inspect_image_text, process_image_bytes
from .ole2_cad import inspect_ole2_metadata, is_ole2, process_ole2_bytes
from .pdf_handler import inspect_pdf_metadata, process_pdf_bytes
from .solidworks_modern import inspect_modern_solidworks, is_modern_solidworks, process_modern_solidworks
from .svg_dxf_dwg import (
    inspect_dxf_metadata,
    inspect_svg_metadata,
    process_dwg_bytes,
    process_dxf_bytes,
    process_svg_bytes,
)
from .text_cad import (
    inspect_iges_metadata,
    inspect_parasolid_metadata,
    inspect_step_metadata,
    process_generic_text_cad,
    process_iges_bytes,
    process_obj_bytes,
    process_parasolid_bytes,
    process_sat_bytes,
    process_step_file,
    process_stl_bytes,
)
from .zip_cad import inspect_zip_cad_metadata, process_zip_cad_bytes

log = logging.getLogger(__name__)

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif"}
ZIP_CAD_EXTS = {".fcstd", ".f3d", ".f3z", ".3mf", ".odg"}
SOLIDWORKS_EXTS = {".sldprt", ".sldasm", ".slddrw", ".prtdot", ".asmdot", ".drwdot", ".sldlfp", ".slddrt"}
OLE2_CAD_EXTS = {".ipt", ".iam", ".idw", ".ipn", ".par", ".asm", ".dft"} | SOLIDWORKS_EXTS
CREO_EXTS = {".prt", ".asm", ".drw"}
GENERIC_TEXT_CAD_EXTS = {".wrl", ".jt", ".off", ".brep", ".brp", ".scad", ".unv", ".neu", ".ps", ".eps", ".ipj", ".txt", ".md", ".csv", ".json", ".xml"}


def _is_creo_ext(ext: str) -> bool:
    return ext in CREO_EXTS or any(ext.startswith(p + ".") and ext[len(p) + 1 :].isdigit() for p in CREO_EXTS)


def inspect_file_metadata(path: Path, rel_path: str, max_read: int = 8_000_000) -> list[tuple[str, str]]:
    """Phase 1 read-only metadata extractor across all corpus formats."""
    _, ext = split_compound_extension(path.name.lower())
    try:
        sz = path.stat().st_size
    except OSError:
        return []
    if sz == 0:
        return []

    if ext in {".step", ".stp"}:
        return inspect_step_metadata(path)

    try:
        if is_archive_extension(ext):
            return inspect_archive_file(path, ext)
        with path.open("rb") as f:
            data = f.read(min(sz, max_read))
    except OSError:
        return []

    return inspect_bytes_metadata(data, path.name)


def inspect_bytes_metadata(data: bytes, filename: str, depth: int = 0) -> list[tuple[str, str]]:
    """Inspect in-memory file bytes for metadata identifiers."""
    if not data:
        return []
    _, ext = split_compound_extension(filename.lower())

    if data[:4] == b"%PDF" or ext == ".pdf":
        return inspect_pdf_metadata(data)
    if ext in {".igs", ".iges"}:
        return inspect_iges_metadata(data)
    if ext in {".x_t", ".x_b", ".xmt_txt", ".xmt_bin"}:
        return inspect_parasolid_metadata(data)
    if is_modern_solidworks(data):
        return inspect_modern_solidworks(data)
    if is_ole2(data):
        return inspect_ole2_metadata(data)
    if ext in ZIP_CAD_EXTS and data[:4] == b"PK\x03\x04":
        return inspect_zip_cad_metadata(data, ext)
    if is_creo_ugc(data) or _is_creo_ext(ext):
        return inspect_creo_metadata(data)
    if ext == ".svg":
        return inspect_svg_metadata(data)
    if ext == ".dxf":
        return inspect_dxf_metadata(data)
    if is_archive_extension(ext):
        return inspect_archive_bytes(data, ext, depth=depth, filename=filename)
    return []


def dispatch_bytes(
    data: bytes,
    filename: str,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    use_ocr: bool = True,
    depth: int = 0,
) -> tuple[bytes, int]:
    """In-memory dispatcher used for PDF attachments and nested archive entries."""
    out_bytes, rep, _, _ = dispatch_bytes_detailed(
        data, filename, registry, scope, use_ocr=use_ocr, depth=depth
    )
    return out_bytes, rep


def dispatch_bytes_detailed(
    data: bytes,
    filename: str,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    use_ocr: bool = True,
    depth: int = 0,
) -> tuple[bytes, int, list[str], str]:
    """Transform bytes for any format and return (bytes, replacements, warnings, ext_override)."""
    if not data:
        return data, 0, [], ""

    _, ext = split_compound_extension(filename.lower())
    warnings: list[str] = []

    if data[:4] == b"%PDF" or ext == ".pdf":
        b, r = process_pdf_bytes(data, registry, scope, use_ocr=use_ocr, depth=depth, warnings=warnings)
        return b, r, warnings, ""

    if ext in {".igs", ".iges"}:
        b, r = process_iges_bytes(data, registry, scope)
        return b, r, warnings, ""

    if ext == ".sat":
        b, r = process_sat_bytes(data, registry, scope)
        return b, r, warnings, ""

    if ext in {".x_t", ".x_b", ".xmt_txt", ".xmt_bin"}:
        is_bin = ext in {".x_b", ".xmt_bin"} or b"BINARY" in data[:512]
        b, r = process_parasolid_bytes(data, is_bin, registry, scope)
        return b, r, warnings, ""

    if ext == ".stl":
        b, r = process_stl_bytes(data, registry, scope)
        return b, r, warnings, ""

    if ext == ".obj":
        b, r = process_obj_bytes(data, registry, scope)
        return b, r, warnings, ""

    if ext == ".svg":
        b, r = process_svg_bytes(data, registry, scope, use_ocr=use_ocr)
        return b, r, warnings, ""

    if ext == ".dxf":
        b, r = process_dxf_bytes(data, registry, scope)
        return b, r, warnings, ""

    if ext == ".dwg":
        b, r, dwg_w = process_dwg_bytes(data, registry, scope)
        return b, r, dwg_w, ""

    if is_modern_solidworks(data):
        ocr_prev = use_ocr and ext in {".slddrw", ".drwdot", ".slddrt"}
        b, r = process_modern_solidworks(data, registry, scope, use_ocr=use_ocr, ocr_preview=ocr_prev)
        return b, r, warnings, ""

    if is_ole2(data):
        b, r = process_ole2_bytes(data, ext, registry, scope, use_ocr=use_ocr)
        return b, r, warnings, ""

    if ext in ZIP_CAD_EXTS or (data[:4] == b"PK\x03\x04" and ext in ZIP_CAD_EXTS):
        b, r = process_zip_cad_bytes(data, ext, registry, scope, use_ocr=use_ocr)
        return b, r, warnings, ""

    if is_creo_ugc(data) or _is_creo_ext(ext):
        b, r = process_creo_bytes(data, registry, scope)
        return b, r, warnings, ""

    if is_catia_v5(data) or ext in {".catpart", ".catproduct", ".catdrawing", ".u3d", ".3ds", ".mf1"}:
        b, r = process_catia_or_binary_cad(data, ext, registry, scope)
        return b, r, warnings, ""

    if ext in IMAGE_EXTS:
        b, r = process_image_bytes(data, ext, registry, scope, use_ocr=use_ocr)
        return b, r, warnings, ""

    if is_archive_extension(ext):
        return process_archive_bytes(data, filename, registry, scope, use_ocr=use_ocr, depth=depth)

    if ext in {".step", ".stp"}:
        # Fallback for small in-memory STEP files inside archives
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "in.step"
            dp = Path(td) / "out.step"
            sp.write_bytes(data)
            r = process_step_file(sp, dp, registry, scope)
            return dp.read_bytes(), r, warnings, ""

    if ext in GENERIC_TEXT_CAD_EXTS:
        b, r = process_generic_text_cad(data, ext, registry, scope)
        return b, r, warnings, ""

    # Unknown binary/text fallback
    if b"\x00" not in data[:1024]:
        b, r = process_generic_text_cad(data, ext, registry, scope)
        return b, r, warnings, ""
    return data, 0, warnings, ""


def process_file(
    src_path: Path,
    dst_path: Path,
    input_rel_path: str,
    output_rel_path: str,
    registry: IdentityRegistry,
    *,
    use_ocr: bool = True,
) -> TransformResult:
    """Process a single corpus file from src_path to dst_path."""
    scope = registry.scope_for_rel_path(input_rel_path)
    _, ext = split_compound_extension(src_path.name.lower())

    if input_rel_path.lower().endswith(".resume-partial"):
        return TransformResult(
            status="omitted_defect",
            input_rel_path=input_rel_path,
            output_rel_path="",
            handler="defect_filter",
            defects=["truncated_resume_partial_archive_fragment_omitted"],
            bytes_in=src_path.stat().st_size if src_path.exists() else 0,
        )

    sz = src_path.stat().st_size
    if sz == 0:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_bytes(b"")
        return TransformResult(
            status="skipped_empty",
            input_rel_path=input_rel_path,
            output_rel_path=output_rel_path,
            handler="empty_passthrough",
            defects=["zero_byte_source_file_preserved"],
            bytes_in=0,
            bytes_out=0,
        )

    # Streaming fast path for STEP files (supports >1.4 GB without full RAM load)
    if ext in {".step", ".stp"}:
        rep = process_step_file(src_path, dst_path, registry, scope)
        return TransformResult(
            status="ok",
            input_rel_path=input_rel_path,
            output_rel_path=output_rel_path,
            handler="step_stream",
            replacements=rep,
            bytes_in=sz,
            bytes_out=dst_path.stat().st_size,
        )

    data = src_path.read_bytes()
    try:
        out_bytes, rep, warnings, ext_override = dispatch_bytes_detailed(
            data, src_path.name, registry, scope, use_ocr=use_ocr, depth=0
        )
    except Exception as e:
        return TransformResult(
            status="omitted_defect",
            input_rel_path=input_rel_path,
            output_rel_path="",
            handler=ext.lstrip(".") or "generic",
            defects=[f"unreadable_or_encrypted_source_omitted: {type(e).__name__}"],
            bytes_in=sz,
        )

    final_dst = dst_path
    final_rel = output_rel_path
    if ext_override:
        final_dst = dst_path.with_name(archive_output_name(dst_path.name, ext_override))
        rel_parent = output_rel_path.rsplit("/", 1)[0] if "/" in output_rel_path else ""
        final_rel = f"{rel_parent}/{final_dst.name}" if rel_parent else final_dst.name

    final_dst.parent.mkdir(parents=True, exist_ok=True)
    final_dst.write_bytes(out_bytes)
    return TransformResult(
        status="warning" if warnings else "ok",
        input_rel_path=input_rel_path,
        output_rel_path=final_rel,
        handler=ext.lstrip(".") or "generic",
        warnings=warnings,
        replacements=rep,
        bytes_in=sz,
        bytes_out=len(out_bytes),
    )
