"""Independent post-run auditor checking zero raw leaks, structural usability, and scorer constraints."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
import gzip
import io
import logging
from pathlib import Path
import re
import tarfile
import zipfile

from lxml import etree
import olefile
import py7zr
from py7zr.io import BytesIOFactory
import pymupdf as fitz

from .config import is_safe_engineering_token, split_compound_extension
from .handlers.archive_handler import MAX_ARCHIVE_DEPTH, MAX_UNPACKED_BYTES, decompress_unix_z
from .handlers.ole2_cad import _is_oleps_stream, is_ole2, parse_oleps_strings
from .handlers.solidworks_modern import is_modern_solidworks, parse_modern_container
from .handlers.svg_dxf_dwg import DXF_BINARY_SIGNATURE, read_dxf_document
from .handlers.text_cad import is_binary_stl
from .matching import TokenMatcher
from .registry import GLOBAL_SCOPE, IdentityRegistry

log = logging.getLogger(__name__)


TAR_EXTS = (".tar", ".tar.gz", ".tar.z", ".tar.bz2", ".tar.xz", ".tgz", ".tbz", ".tbz2", ".txz")
COMPRESSED_EXTS = (*TAR_EXTS, ".gz", ".z")


@dataclass
class AuditReport:
    total_files: int = 0
    total_bytes: int = 0
    structural_ok: int = 0
    structural_failed: list[str] = field(default_factory=list)
    leaks: list[dict[str, str]] = field(default_factory=list)
    constraint_violations: list[str] = field(default_factory=list)
    by_ext: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.structural_failed and not self.leaks and not self.constraint_violations


def _index_leak_tokens(registry: IdentityRegistry) -> dict[str, TokenMatcher]:
    """Index global tokens once and index local tokens by source scope."""
    by_scope: dict[str, dict[str, str]] = {}
    for entry in registry.entities.values():
        scopes = (GLOBAL_SCOPE,) if GLOBAL_SCOPE in entry.scopes else entry.scopes
        for raw in sorted(entry.variants):
            if len(raw) < 4 or is_safe_engineering_token(raw):
                continue
            if len(raw) < 5 and (raw.isdigit() or entry.entity_type not in {"EMAIL", "DOMAIN", "ACCOUNT", "PERSON"}):
                continue
            key = raw.replace("\u0130", "i").lower()
            if key.startswith(("org-", "prj-", "part-", "usr", "host-", "engineer ")):
                continue
            token = f"{entry.entity_type}:{raw}"
            for scope in scopes:
                by_scope.setdefault(scope, {})[key] = token
    return {scope: TokenMatcher(tokens) for scope, tokens in by_scope.items()}


def _scan_text_for_leaks(
    text: str, location: str, matchers: tuple[TokenMatcher, ...], leaks: list[dict[str, str]]
) -> None:
    if not text or not matchers:
        return
    lowered = text.lower()
    if len(lowered) != len(text):
        lowered = text.replace("\u0130", "i").lower()
    seen_hits: set[str] = set()
    for matcher in matchers:
        for start, end, token in matcher.matches(text, lowered):
            hit = lowered[start:end]
            if hit in seen_hits:
                continue
            seen_hits.add(hit)
            leaks.append({"location": location, "token": token})
            if len(seen_hits) >= 10:
                return


def _validate_step_framing(head: bytes, tail: bytes, rel_path: str, report: AuditReport) -> bool:
    if re.search(rb"(?<![A-Z0-9-])ISO-10303-21;", head) is None:
        report.structural_failed.append(f"{rel_path}: missing ISO-10303-21 header")
        return False
    if b"END-ISO-10303-21;" not in tail:
        report.structural_failed.append(f"{rel_path}: missing END-ISO-10303-21 trailer")
        return False
    return True


def _mask_parasolid_format_literals(data: bytes) -> bytes:
    """Trim standard Parasolid flags and modeller banners from the audit text."""
    start = data.find(b"**PARASOLID")
    if start >= 0:
        end = data.find(b"**END_OF_HEADER", start, start + 4096)
        if end >= 0:
            head = re.sub(
                rb"(?im)^([ \t]*GUISE[ \t]*=[ \t]*)transmit([ \t]*;[ \t]*\r?$)",
                rb"\g<1>\g<2>",
                data[start:end],
            )
            data = data[:start] + head + data[end:]
    return re.sub(
        rb"(PS\x00{3}.: )TRANSMIT( FILE(?: \((?:partition|deltas)\))? created by modeller version [0-9]+\x00)",
        rb"\g<1>\g<2>",
        data,
    )


def _audit_bytes_and_structure(
    data: bytes,
    rel_path: str,
    matchers: tuple[TokenMatcher, ...],
    report: AuditReport,
    depth: int = 0,
) -> bool:
    """Validate structural integrity & scan decompressed/parsed internals for raw leaks."""
    _, ext = split_compound_extension(rel_path.lower())

    if len(data) == 0:
        return True
    if depth >= MAX_ARCHIVE_DEPTH and (ext in {".zip", ".7z"} or ext.endswith(COMPRESSED_EXTS)):
        report.structural_failed.append(f"{rel_path}: archive exceeds audit recursion limit")
        return False

    # 1. PDF check
    if data[:4] == b"%PDF" or ext == ".pdf":
        try:
            doc = fitz.open(stream=data, filetype="pdf")
            if len(doc) == 0:
                report.structural_failed.append(f"{rel_path}: 0 pages")
                doc.close()
                return False
            meta = doc.metadata or {}
            _scan_text_for_leaks(" ".join(str(v or "") for v in meta.values()), f"{rel_path}#pdf_meta", matchers, report.leaks)
            for pno, page in enumerate(doc):
                _scan_text_for_leaks(page.get_text("text") or "", f"{rel_path}#p{pno+1}", matchers, report.leaks)
                for lnk in page.get_links():
                    if lnk.get("uri"):
                        _scan_text_for_leaks(lnk["uri"], f"{rel_path}#p{pno+1}_uri", matchers, report.leaks)
            for i in range(doc.embfile_count()):
                info = doc.embfile_info(i)
                fn = info.get("filename") or ""
                _scan_text_for_leaks(fn, f"{rel_path}#emb_name", matchers, report.leaks)
                _audit_bytes_and_structure(doc.embfile_get(i), f"{rel_path}/{fn}", matchers, report, depth + 1)
            doc.close()
            return True
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid PDF ({e})")
            return False

    # 2. STEP check
    if ext in {".step", ".stp"}:
        _scan_text_for_leaks(data.decode("latin1"), rel_path, matchers, report.leaks)
        return _validate_step_framing(data[:65536], data[-65536:], rel_path, report)

    # 3. IGES check
    if ext in {".igs", ".iges"}:
        txt = data.decode("latin1", errors="replace")
        lines = txt.splitlines()
        if not any(len(l) >= 73 and l[72] == "T" for l in lines[-5:]):
            report.structural_failed.append(f"{rel_path}: missing IGES Terminate record")
            return False
        bad_len = [i for i, l in enumerate(lines) if l and len(l) != 80]
        if bad_len:
            report.structural_failed.append(f"{rel_path}: {len(bad_len)} IGES lines != 80 chars")
            return False
        _scan_text_for_leaks(txt, rel_path, matchers, report.leaks)
        return True

    # 4. STL check
    if ext == ".stl":
        if is_binary_stl(data):
            hdr_txt = data[:80].rstrip(b"\x00 ").decode("latin1", errors="replace")
            _scan_text_for_leaks(hdr_txt, f"{rel_path}#stl_hdr", matchers, report.leaks)
            return True
        txt = data.decode("utf-8", errors="replace")
        if not txt.lstrip().lower().startswith("solid"):
            report.structural_failed.append(f"{rel_path}: invalid ASCII/Binary STL framing")
            return False
        _scan_text_for_leaks(txt, rel_path, matchers, report.leaks)
        return True

    # 5. SVG check
    if ext == ".svg":
        try:
            etree.fromstring(data)
            _scan_text_for_leaks(data.decode("utf-8", errors="replace"), rel_path, matchers, report.leaks)
            return True
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid XML SVG ({e})")
            return False

    # 6. DXF check
    if ext == ".dxf":
        try:
            doc = read_dxf_document(data)
            if data.startswith(DXF_BINARY_SIGNATURE):
                output = io.StringIO()
                doc.write(output, fmt="asc")
                txt = output.getvalue()
            else:
                txt = data.decode(doc.output_encoding, errors="replace")
            _scan_text_for_leaks(txt, rel_path, matchers, report.leaks)
            return True
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid DXF ({e})")
            return False

    # 7. SolidWorks 2015+ container check (verifies CRC32 on every active stream!)
    if is_modern_solidworks(data):
        parsed = parse_modern_container(data)
        if not parsed["local_chunks"]:
            report.structural_failed.append(f"{rel_path}: failed SW2015+ stream parse")
            return False
        active = {e["local_marker_off"] for e in parsed["cd_entries"]} if parsed["cd_entries"] else None
        for m_off, chunk in parsed["local_chunks"].items():
            if active is not None and m_off not in active:
                continue
            nm_l = chunk["name"].lower()
            raw: bytes = chunk["raw"]
            if nm_l.startswith(("docprops/", "swxmlcontents/")):
                _scan_text_for_leaks(raw.decode("utf-8", errors="replace"), f"{rel_path}#{chunk['name']}", matchers, report.leaks)
            elif nm_l not in {"preview", "previewpng"} and not nm_l.endswith(("-partition", "-ghostpartition")):
                u16_all = " ".join(m.decode("utf-16-le", "ignore") for m in re.findall(rb"(?:[\x20-\x7e\x80-\xff]\x00){4,}", raw))
                asc_all = " ".join(m.decode("latin1") for m in re.findall(rb"[\x20-\x7e]{5,}", raw))
                _scan_text_for_leaks(u16_all + " " + asc_all, f"{rel_path}#{chunk['name']}", matchers, report.leaks)
        return True

    # 8. OLE2 CFBF check
    if is_ole2(data):
        try:
            with olefile.OleFileIO(io.BytesIO(data)) as ole:
                for entry in ole.listdir(streams=True, storages=False):
                    leaf = entry[-1]
                    raw = ole.openstream(entry).read()
                    if _is_oleps_stream(leaf, raw):
                        vals = " ".join(v for _, _, v in parse_oleps_strings(raw))
                        _scan_text_for_leaks(vals, f"{rel_path}#{leaf}", matchers, report.leaks)
                    elif leaf not in {"Preview", "PreviewPNG"} and not leaf.lower().endswith(("-partition", "-ghostpartition")) and not raw.startswith(b"PS\x00\x00"):
                        u16 = " ".join(m.decode("utf-16-le", "ignore") for m in re.findall(rb"(?:[\x20-\x7e\x80-\xff]\x00){4,}", raw))
                        raw_text = _mask_parasolid_format_literals(raw).decode("latin1")
                        _scan_text_for_leaks(u16 + " " + raw_text, f"{rel_path}#{leaf}", matchers, report.leaks)
            return True
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid OLE2 ({e})")
            return False

    # 9. ZIP CAD (.fcstd, .f3d, .f3z, .3mf, .odg)
    if ext in {".fcstd", ".f3d", ".f3z", ".3mf", ".odg"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                for nm in zf.namelist():
                    if nm.lower().endswith((".xml", ".model", ".txt", ".svg")):
                        _scan_text_for_leaks(zf.read(nm).decode("utf-8", errors="replace"), f"{rel_path}#{nm}", matchers, report.leaks)
            return True
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid ZIP-CAD ({e})")
            return False

    # 10. Archives (recursive unpack + check!)
    if ext == ".zip":
        try:
            ok = True
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                for info in zf.infolist():
                    _scan_text_for_leaks(info.filename, f"{rel_path}#zip_entry_name", matchers, report.leaks)
                    if info.is_dir():
                        continue
                    ok &= _audit_bytes_and_structure(
                        zf.read(info), f"{rel_path}/{info.filename}", matchers, report, depth + 1
                    )
            return ok
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid ZIP ({e})")
            return False

    if ext.endswith(COMPRESSED_EXTS):
        try:
            if ext.endswith(".z"):
                raw = decompress_unix_z(data)
            elif ext.endswith(".gz") and not ext.endswith(TAR_EXTS):
                raw = gzip.decompress(data)
            else:
                raw = data
            if ext.endswith(TAR_EXTS) or tarfile.is_tarfile(io.BytesIO(raw)):
                ok = True
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                    for m in tf:
                        _scan_text_for_leaks(m.name, f"{rel_path}#tar_name", matchers, report.leaks)
                        if m.isfile():
                            with tf.extractfile(m) as content:
                                ok &= _audit_bytes_and_structure(
                                    content.read(), f"{rel_path}/{m.name}", matchers, report, depth + 1
                                )
                return ok
            inner = rel_path[:-2] if ext.endswith(".z") else rel_path[:-3]
            return _audit_bytes_and_structure(raw, inner, matchers, report, depth + 1)
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid TAR/compressed stream ({e})")
            return False

    if ext == ".7z":
        try:
            ok = True
            with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as szf:
                entries = szf.list()
                for entry in entries:
                    _scan_text_for_leaks(entry.filename, f"{rel_path}#7z_name", matchers, report.leaks)
                files = [entry for entry in entries if entry.is_file]
                names = [entry.filename for entry in files]
                if len(set(names)) != len(names):
                    raise ValueError("duplicate member names")
                if sum(entry.uncompressed for entry in files) > MAX_UNPACKED_BYTES:
                    raise ValueError("archive exceeds audit unpack limit")
                factory = BytesIOFactory(MAX_UNPACKED_BYTES)
                szf.extract(targets=names, factory=factory)
                for entry in files:
                    content = factory.get(entry.filename)
                    if content.size() != entry.uncompressed:
                        raise ValueError("member size mismatch")
                    content.seek(0)
                    ok &= _audit_bytes_and_structure(
                        content.read(), f"{rel_path}/{entry.filename}", matchers, report, depth + 1
                    )
            return ok
        except Exception as e:
            report.structural_failed.append(f"{rel_path}: invalid 7z ({e})")
            return False

    # 11. Generic text CAD (.sat, .x_t, .x_b, .obj, .wrl, .jt, .ps, .eps, .brep, .off, .scad, .unv, .prt.1, etc.)
    if b"\x00" not in data[:1024] or ext in {".x_b", ".prt.1", ".drw.1", ".asm.1"}:
        if ext == ".x_b":
            end_h = data.find(b"**END_OF_HEADER")
            head = _mask_parasolid_format_literals(data[:end_h + len(b"**END_OF_HEADER")] if end_h != -1 else data[:2048])
            _scan_text_for_leaks(head.decode("latin1"), rel_path, matchers, report.leaks)
        elif data.startswith(b"#UGC:"):
            end_h = data.find(b"#-END_OF_UGC_HEADER")
            _scan_text_for_leaks(data[: end_h if end_h != -1 else 2048].decode("latin1", "replace"), rel_path, matchers, report.leaks)
        else:
            sample = _mask_parasolid_format_literals(data[:2_000_000])
            _scan_text_for_leaks(sample.decode("latin1"), rel_path, matchers, report.leaks)
        return True

    return True


def audit_corpus(
    corpus_root: Path,
    registry: IdentityRegistry,
    *,
    expected_paths: Collection[str] | None = None,
    output_overrides: Mapping[str, str | None] | None = None,
) -> AuditReport:
    """Audit output corpus/ directory for zero raw leaks, valid structure, and scorer rules."""
    report = AuditReport()
    if not corpus_root.is_dir():
        report.constraint_violations.append("Corpus directory is missing")
        return report

    overrides = output_overrides or {}
    reverse_path = {overrides.get(output, output): source for source, output in registry.path_map.items()}
    token_matchers = _index_leak_tokens(registry)
    global_matcher = token_matchers.pop(GLOBAL_SCOPE, None)

    all_files = sorted((p.relative_to(corpus_root).as_posix(), p) for p in corpus_root.rglob("*") if p.is_file())
    report.total_files = len(all_files)

    if not all_files:
        report.constraint_violations.append("Corpus has no files")
    if expected_paths is not None:
        expected = set(expected_paths)
        actual = {rel for rel, _ in all_files}
        report.constraint_violations.extend(f"Missing corpus file: {rel}" for rel in sorted(expected - actual))
        report.constraint_violations.extend(f"Unexpected corpus file: {rel}" for rel in sorted(actual - expected))
    if report.total_files > 400_000:
        report.constraint_violations.append(f"Object count {report.total_files} exceeds 400,000 scorer limit")

    for rel, p in all_files:
        sz = p.stat().st_size
        report.total_bytes += sz
        if sz > 2 * 1024**3:
            report.constraint_violations.append(f"File {rel} ({sz}B) exceeds 2 GiB scorer limit")
        if rel.lower().endswith(".resume-partial"):
            report.constraint_violations.append(f"Partial archive fragment leaked into output: {rel}")

        orig_rel = reverse_path.get(rel, rel)
        scope = registry.scope_for_rel_path(orig_rel)
        matchers = tuple(m for m in (global_matcher, token_matchers.get(scope)) if m is not None)

        # Path check
        _scan_text_for_leaks(rel, f"PATH:{rel}", matchers, report.leaks)

        _, ext = split_compound_extension(p.name.lower())
        ext_k = ext or "<none>"
        bucket = report.by_ext.setdefault(ext_k, {"total": 0, "ok": 0})
        bucket["total"] += 1

        # Bound memory for large STEP exports while independently checking both framing records.
        if ext in {".step", ".stp"} and sz > 50_000_000:
            with p.open("rb") as f:
                head = f.read(65536)
                f.seek(-65536, 2)
                tail = f.read(65536)
            ok = _validate_step_framing(head, tail, rel, report)
            _scan_text_for_leaks(head.decode("latin1"), rel, matchers, report.leaks)
            _scan_text_for_leaks(tail.decode("latin1"), rel, matchers, report.leaks)
        else:
            data = p.read_bytes()
            ok = _audit_bytes_and_structure(data, rel, matchers, report, depth=0)

        if ok:
            report.structural_ok += 1
            bucket["ok"] += 1

    return report
