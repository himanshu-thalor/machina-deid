"""CLI entrypoint for Machina CAD De-ID: discover, transform, run, audit."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time

from .audit import audit_corpus
from .config import TransformResult, split_compound_extension
from .discovery import run_discovery
from .handlers import process_file
from .registry import IdentityRegistry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("ezdxf").setLevel(logging.WARNING)
logging.getLogger("RapidOCR").setLevel(logging.WARNING)
log = logging.getLogger("machina_deid")

_WORKER_REGISTRY: IdentityRegistry | None = None
_WORKER_USE_OCR: bool = True
_WORKER_OUTPUT_ROOT: Path | None = None
_WORKER_PLANNED_PATHS: set[str] = set()


def _init_worker(registry_path: str, use_ocr: bool, output_root: str) -> None:
    global _WORKER_REGISTRY, _WORKER_USE_OCR, _WORKER_OUTPUT_ROOT, _WORKER_PLANNED_PATHS
    _WORKER_REGISTRY = IdentityRegistry.load(Path(registry_path))
    _WORKER_REGISTRY.freeze()
    _WORKER_USE_OCR = use_ocr
    _WORKER_OUTPUT_ROOT = Path(output_root)
    _WORKER_PLANNED_PATHS = {path.casefold() for path in _WORKER_REGISTRY.path_map.values()}


def _transform_worker(task: tuple[str, str, str, str]) -> TransformResult:
    assert _WORKER_REGISTRY is not None
    assert _WORKER_OUTPUT_ROOT is not None
    src_s, dst_s, in_rel, out_rel = task
    dst = Path(dst_s)
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".machina-", dir=dst.parent) as tmp:
            result = process_file(Path(src_s), Path(tmp) / dst.name, in_rel, out_rel, _WORKER_REGISTRY,
                                  use_ocr=_WORKER_USE_OCR)
            if result.output_rel_path and result.status in {"ok", "warning", "skipped_empty"}:
                staged = Path(tmp) / Path(result.output_rel_path).name
                # An archive's fallback extension must never overwrite another mapped file.
                if result.output_rel_path != out_rel and result.output_rel_path.casefold() in _WORKER_PLANNED_PATHS:
                    parent = _WORKER_OUTPUT_ROOT / Path(result.output_rel_path).parent
                    name, ext = split_compound_extension(staged.name)
                    tag = hashlib.sha256(out_rel.encode()).hexdigest()[:12]
                    result.output_rel_path = (parent / f"{name}-{tag}{ext}").relative_to(_WORKER_OUTPUT_ROOT).as_posix()
                staged.replace(_WORKER_OUTPUT_ROOT / result.output_rel_path)
            return result
    except (OSError, ValueError) as exc:
        return TransformResult("error", in_rel, out_rel, "transform", defects=[type(exc).__name__])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _run_signature(registry_digest: str, use_ocr: bool) -> str:
    implementation = hashlib.sha256()
    for module in sorted(Path(__file__).parent.rglob("*.py")):
        implementation.update(module.read_bytes())
    lock = Path(__file__).parent.parent / "requirements.lock"
    if lock.is_file():
        implementation.update(lock.read_bytes())
    tools = tuple(shutil.which(tool) for tool in ("compress", "7z", "unar", "unrar", "dwg2dxf", "dxf2dwg"))
    return json.dumps([registry_digest, implementation.hexdigest(), use_ocr, sys.platform, tools])


def _validate_layout(input_root: Path, output_root: Path, state_dir: Path, readme_out: Path | None) -> None:
    roots = [path.resolve() for path in (input_root, output_root, state_dir)]
    for index, left in enumerate(roots):
        for right in roots[index + 1 :]:
            if left.is_relative_to(right) or right.is_relative_to(left):
                raise ValueError("Input, output and private state must be separate directories")
    if readme_out is not None and any(readme_out.resolve().is_relative_to(root) for root in roots):
        raise ValueError("README must be outside the input, output corpus and private state directories")


def run_transform(
    input_root: Path,
    output_root: Path,
    state_dir: Path,
    *,
    workers: int = 8,
    resume: bool = True,
    use_cache: bool = True,
    use_ocr: bool = True,
    readme_out: Path | None = None,
) -> dict:
    """Transform files and record completed writes in private state."""
    _validate_layout(input_root, output_root, state_dir, readme_out)
    registry_path = state_dir / "registry.json"
    registry = IdentityRegistry.load(registry_path)
    registry_digest = _sha256_file(registry_path)
    signature = _run_signature(registry_digest, use_ocr)
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    cache_dir = state_dir / "content_cache"
    if use_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "registry_sha256": registry_digest,
        "output_root": str(output_root),
        "total_mapped": len(registry.path_map),
        "processed": 0,
        "resumed_skipped": 0,
        "cache_hits": 0,
        "empty_preserved": 0,
        "omitted_defects": len(registry.omitted_defects),
        "omission_reasons": Counter(item["type"] for item in registry.omitted_defects),
        "omitted_items": [],
        "warnings": [],
        "errors": [],
        "output_overrides": {},
    }

    def record(result: TransformResult, planned: str) -> None:
        if result.status == "skipped_empty":
            summary["empty_preserved"] += 1
        if result.status == "omitted_defect":
            summary["omitted_defects"] += 1
            summary["omission_reasons"].update(result.defects)
            summary["omitted_items"].append({"path": planned, "format": result.handler, "defects": result.defects})
            summary["output_overrides"][planned] = None
        elif result.status == "error":
            summary["errors"].append({"path": planned, "defects": result.defects})
        elif result.output_rel_path != planned:
            summary["output_overrides"][planned] = result.output_rel_path
        if result.warnings:
            summary["warnings"].append({"path": result.output_rel_path, "warnings": result.warnings})

    with sqlite3.connect(state_dir / "transform_progress.sqlite3") as db:
        db.execute("""CREATE TABLE IF NOT EXISTS receipts (
            output_root TEXT, source_path TEXT, source_key TEXT, result TEXT, output_mtime INTEGER,
            PRIMARY KEY (output_root, source_path))""")

        def jobs():
            for in_rel, out_rel in sorted(registry.path_map.items()):
                src = input_root / in_rel
                dst = output_root / out_rel
                try:
                    stat = src.stat()
                except OSError as exc:
                    record(TransformResult("error", in_rel, out_rel, "input", defects=[type(exc).__name__]), out_rel)
                    continue
                source_key = hashlib.sha256(
                    json.dumps([signature, str(src.resolve()), stat.st_size, stat.st_mtime_ns]).encode()
                ).hexdigest()
                if resume:
                    row = db.execute(
                        "SELECT result, output_mtime FROM receipts WHERE output_root=? AND source_path=? AND source_key=?",
                        (str(output_root), in_rel, source_key),
                    ).fetchone()
                    if row:
                        prior = TransformResult(**json.loads(row[0]))
                        previous_output = output_root / prior.output_rel_path
                        try:
                            valid = not prior.output_rel_path or (
                                previous_output.stat().st_size == prior.bytes_out and
                                previous_output.stat().st_mtime_ns == row[1]
                            )
                        except FileNotFoundError:
                            valid = False
                        if valid:
                            summary["resumed_skipped"] += 1
                            record(prior, out_rel)
                            continue
                cache_path = None
                if use_cache and 0 < stat.st_size <= 100_000_000:
                    scope = registry.scope_for_rel_path(in_rel)
                    cache_key = hashlib.sha256(
                        json.dumps([signature, scope, src.name, _sha256_file(src)]).encode()
                    ).hexdigest()
                    cache_path = cache_dir / cache_key
                yield (str(src), str(dst), in_rel, out_rel), source_key, cache_path, stat.st_size

        def complete(job, result: TransformResult) -> None:
            task, source_key, cache_path, _ = job
            _, _, in_rel, out_rel = task
            summary["processed"] += 1
            record(result, out_rel)
            if result.status == "error":
                return
            actual = output_root / result.output_rel_path if result.output_rel_path else None
            if actual and cache_path and result.status == "ok" and not result.from_cache:
                _copy_atomic(actual, cache_path)
            db.execute("INSERT OR REPLACE INTO receipts VALUES (?, ?, ?, ?, ?)", (
                str(output_root), in_rel, source_key, json.dumps(asdict(result)),
                actual.stat().st_mtime_ns if actual else None,
            ))
            if summary["processed"] % 128 == 0:
                db.commit()
            if summary["processed"] % 500 == 0:
                log.info("Processed %d / %d files (%d reused)", summary["processed"],
                         summary["total_mapped"], summary["resumed_skipped"])

        def uncached_jobs():
            for job in jobs():
                task, _, cache_path, size = job
                if cache_path is None or not cache_path.is_file():
                    yield job
                    continue
                _, dst, in_rel, out_rel = task
                _copy_atomic(cache_path, Path(dst))
                summary["cache_hits"] += 1
                complete(job, TransformResult("ok", in_rel, out_rel, "content_cache",
                                               bytes_in=size, bytes_out=cache_path.stat().st_size,
                                               from_cache=True))

        log.info("Transform phase: %d mapped files", summary["total_mapped"])
        if workers <= 1 or len(registry.path_map) <= 4:
            _init_worker(str(registry_path), use_ocr, str(output_root))
            for job in uncached_jobs():
                complete(job, _transform_worker(job[0]))
        else:
            with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                     initargs=(str(registry_path), use_ocr, str(output_root))) as pool:
                pending = {}
                for job in uncached_jobs():
                    pending[pool.submit(_transform_worker, job[0])] = job
                    if len(pending) >= workers * 3:
                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for future in done:
                            complete(pending.pop(future), future.result())
                for future, job in pending.items():
                    complete(job, future.result())
        db.commit()

    for key in ("omitted_items", "warnings", "errors"):
        summary[key].sort(key=lambda entry: entry["path"])
    report = state_dir / "transform_summary.json"
    temporary_report = report.with_suffix(".tmp")
    temporary_report.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    temporary_report.replace(report)

    if readme_out is not None:
        _write_submission_readme(readme_out, summary)
    return summary


def _copy_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".machina-", dir=destination.parent) as tmp:
        staged = Path(tmp) / destination.name
        shutil.copyfile(source, staged)
        staged.replace(destination)


def _write_submission_readme(readme_path: Path, summary: dict) -> None:
    """Write reproducible instructions and neutral counts of defects and limitations."""
    lines = [
        "Machina CAD De-ID",
        "",
        "Run these commands from the project directory on a case-sensitive filesystem.",
        "  docker build -t machina-deid ./code",
        "  mkdir -p ./attempt-1 ./private_state",
        '  docker run --rm -v "$PWD/input:/input:ro" -v "$PWD/attempt-1:/attempt" -v "$PWD/private_state:/state" machina-deid run --input /input --output /attempt/corpus --state-dir /state --workers 4 --no-cache --readme-out /attempt/README.txt',
        '  docker run --rm -v "$PWD/attempt-1:/attempt:ro" -v "$PWD/private_state:/state:ro" machina-deid audit --corpus /attempt/corpus --state-dir /state',
        "",
        "Run from a fresh attempt directory when switching input datasets.",
        "The audit checks discovered identifiers, file coverage and supported format structures.",
        "Copy code/ into the attempt alongside corpus/ and README.txt.",
        "Keep input, private state and audit reports outside the attempt.",
        "",
        "Run summary",
        f"  {summary['total_mapped']:,} mapped source files",
        f"  {summary['empty_preserved']:,} empty source files preserved",
        f"  {summary['omitted_defects']:,} omitted source files",
        f"  {len(summary['errors']):,} transformation errors",
    ]
    partial = summary["omission_reasons"].get("omitted_partial_archive", 0)
    if partial:
        lines.append(f"  {partial:,} truncated .resume-partial source fragments omitted")
    omission_groups = Counter((item["format"], reason) for item in summary["omitted_items"] for reason in item["defects"])
    for (file_format, reason), count in sorted(omission_groups.items()):
        if reason.endswith("PasswordRequired"):
            lines.append(f"  {count:,} password-protected {file_format} archives omitted")
        else:
            code = reason.rsplit(": ", 1)[-1].replace("_", " ")
            lines.append(f"  {count:,} {file_format} inputs omitted after processing failed with {code}")
    warning_counts = Counter(warning for item in summary["warnings"] for warning in set(item["warnings"]))
    for warning, count in sorted(warning_counts.items()):
        lines.append(f"  {count:,} outputs with warning '{warning}'")
    lines.extend((
        "",
        "Format limits",
        "  DWG compressed object streams and opaque native CAD records have partial coverage.",
        "  Raster drawing redaction depends on OCR recall and title-block detection.",
        "  RAR is repacked as ZIP. Unix compress archives require ncompress to retain .Z.",
        "  The independent audit can inspect supported containers and known identifiers.",
    ))
    readme_path.parent.mkdir(parents=True, exist_ok=True)
    readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="machina_deid", description="Machina CAD De-ID pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser("discover", help="Phase 1 read-only identity discovery")
    p_disc.add_argument("--input", required=True, type=Path)
    p_disc.add_argument("--state-dir", required=True, type=Path)
    p_disc.add_argument("--workers", type=int, default=min(16, os.cpu_count() or 8))

    p_tr = sub.add_parser("transform", help="Phase 2 & 3 corpus transformation")
    p_tr.add_argument("--input", required=True, type=Path)
    p_tr.add_argument("--output", required=True, type=Path)
    p_tr.add_argument("--state-dir", required=True, type=Path)
    p_tr.add_argument("--workers", type=int, default=min(16, os.cpu_count() or 8))
    p_tr.add_argument("--no-resume", action="store_true")
    p_tr.add_argument("--no-cache", action="store_true")
    p_tr.add_argument("--no-ocr", action="store_true")
    p_tr.add_argument("--readme-out", type=Path, default=None)

    p_run = sub.add_parser("run", help="Run full discover + transform pipeline")
    p_run.add_argument("--input", required=True, type=Path)
    p_run.add_argument("--output", required=True, type=Path)
    p_run.add_argument("--state-dir", required=True, type=Path)
    p_run.add_argument("--workers", type=int, default=min(16, os.cpu_count() or 8))
    p_run.add_argument("--no-resume", action="store_true")
    p_run.add_argument("--no-cache", action="store_true")
    p_run.add_argument("--no-ocr", action="store_true")
    p_run.add_argument("--readme-out", type=Path, default=None)

    p_aud = sub.add_parser("audit", help="Check coverage, known identifiers and output structure")
    p_aud.add_argument("--corpus", required=True, type=Path)
    p_aud.add_argument("--state-dir", required=True, type=Path)
    p_aud.add_argument("--report-out", type=Path, default=None)

    args = parser.parse_args(argv)
    t0 = time.monotonic()

    if args.cmd == "discover":
        args.state_dir.mkdir(parents=True, exist_ok=True)
        reg = IdentityRegistry()
        run_discovery(args.input, reg, workers=args.workers)
        reg.save(args.state_dir / "registry.json")
        log.info("Saved registry to %s in %.2fs", args.state_dir / "registry.json", time.monotonic() - t0)
        return 0

    if args.cmd == "transform":
        summary = run_transform(
            args.input,
            args.output,
            args.state_dir,
            workers=args.workers,
            resume=not args.no_resume,
            use_cache=not args.no_cache,
            use_ocr=not args.no_ocr,
            readme_out=args.readme_out,
        )
        log.info("Transform done in %.2fs (%d errors)", time.monotonic() - t0, len(summary["errors"]))
        return int(bool(summary["errors"]))

    if args.cmd == "run":
        _validate_layout(args.input, args.output, args.state_dir, args.readme_out)
        args.state_dir.mkdir(parents=True, exist_ok=True)
        reg = IdentityRegistry()
        run_discovery(args.input, reg, workers=args.workers)
        reg.save(args.state_dir / "registry.json")
        summary = run_transform(
            args.input,
            args.output,
            args.state_dir,
            workers=args.workers,
            resume=not args.no_resume,
            use_cache=not args.no_cache,
            use_ocr=not args.no_ocr,
            readme_out=args.readme_out,
        )
        log.info("Full pipeline finished in %.2fs (%d errors)", time.monotonic() - t0, len(summary["errors"]))
        return int(bool(summary["errors"]))

    if args.cmd == "audit":
        registry_path = args.state_dir / "registry.json"
        reg = IdentityRegistry.load(registry_path)
        expected = set(reg.path_map.values())
        overrides = {}
        transform_errors = []
        summary_path = args.state_dir / "transform_summary.json"
        if summary_path.is_file():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary.get("registry_sha256") == _sha256_file(registry_path):
                overrides = summary["output_overrides"]
                expected.difference_update(overrides)
                expected.update(path for path in overrides.values() if path is not None)
                transform_errors = summary["errors"]
        rep = audit_corpus(args.corpus, reg, expected_paths=expected, output_overrides=overrides)
        if transform_errors:
            rep.constraint_violations.append(f"Transformation reported {len(transform_errors)} errors")
        out_dict = {
            "passed": rep.passed,
            "total_files": rep.total_files,
            "total_bytes": rep.total_bytes,
            "structural_ok": rep.structural_ok,
            "structural_failed": rep.structural_failed,
            "leak_count": len(rep.leaks),
            "leaks": rep.leaks[:50],
            "constraint_violations": rep.constraint_violations,
            "by_ext": rep.by_ext,
        }
        txt = json.dumps(out_dict, indent=2)
        print(txt)
        if args.report_out:
            args.report_out.write_text(txt, encoding="utf-8")
        return 0 if rep.passed else 1

    return 2
