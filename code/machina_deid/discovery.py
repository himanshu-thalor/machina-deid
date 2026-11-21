"""Phase 1 parallel read-only corpus discovery, entity extraction, and alias clustering."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import logging
from pathlib import Path
import re

from .config import PRESERVED_PATH_SEGMENTS, is_safe_engineering_token, split_compound_extension
from .handlers import inspect_file_metadata
from .registry import IdentityRegistry

log = logging.getLogger(__name__)

RE_EXPLICIT_PART_CODE = re.compile(r"\b([A-Z]{2,8}[-_]\d{3,}[A-Za-z0-9-]*|\d{5,}-\d{2,})\b")


def _extract_path_identities(rel_path: str, registry: IdentityRegistry, scope: str) -> None:
    """Register identifying owner, repo, domain, project, and part prefixes from corpus paths."""
    segs = rel_path.replace("\\", "/").strip("/").split("/")
    for idx, seg in enumerate(segs[:-1]):
        low = seg.lower()
        if low in PRESERVED_PATH_SEGMENTS or re.fullmatch(r"[0-9a-f]{8,16}", low):
            continue
        base = seg[:-len(".extracted")] if low.endswith(".extracted") else seg
        if idx == 2 and segs[0].lower() == "sources":
            kind = segs[1].lower()
            if kind == "web":
                registry.register(base, "DOMAIN", scope, is_global=True)
                continue
            if kind == "github" and "__" in base:
                parts = base.split("__")
                owner = parts[0]
                has_hash = len(parts) >= 3 and bool(re.fullmatch(r"[0-9a-f]{8,16}", parts[-1].lower()))
                repo = "__".join(parts[1:-1] if has_hash else parts[1:])
                registry.register(owner, "ORG", scope, is_global=(len(owner) >= 4))
                registry.register(repo, "PROJECT", scope, is_global=(len(repo) >= 6))
                # Also register sub-tokens of owner/repo if unambiguous
                for sub in re.split(r"[-_]", owner):
                    if len(sub) >= 5 and not is_safe_engineering_token(sub):
                        registry.register(sub, "ORG", scope, is_global=False)
                continue
            if kind == "gitlab" and base.lower().startswith("gitlab.com__"):
                parts = base.split("__")
                if len(parts) >= 3:
                    registry.register(parts[1], "ORG", scope, is_global=(len(parts[1]) >= 4))
                    registry.register("__".join(parts[2:]), "PROJECT", scope, is_global=False)
                continue
            if kind == "catalog":
                registry.register(base, "PROJECT", scope, is_global=(len(base) >= 8))
                # Extract capitalized acronyms (e.g. AWI, CNR-STIIMA, OST, NIST, BAM, LulzBot, Aleph Objects)
                for tok in re.findall(r"\b[A-Z][A-Za-z0-9-]{2,}\b", base):
                    if not is_safe_engineering_token(tok):
                        et = "ORG" if tok.isupper() or "-" in tok else "PROJECT"
                        registry.register(tok, et, scope, is_global=(len(tok) >= 6))
                continue

        if "__" in base:
            parts = base.split("__")
            registry.register(parts[0], "ORG", scope, is_global=(len(parts[0]) >= 4))
            registry.register(parts[1], "PROJECT", scope, is_global=False)

    # Filename part-number prefixes (e.g., 810032-11-..., TRL-0024-A, CRNHZMW_9442)
    fname = segs[-1]
    stem, _ = split_compound_extension(fname)
    if segs[0] == "archives" and "__" in stem:
        registry._transform_owner_repo_slug(stem, scope)
    for m in RE_EXPLICIT_PART_CODE.finditer(stem):
        tok = m.group(1)
        if not is_safe_engineering_token(tok):
            registry.register(tok, "PART_ID", scope, is_global=False)
            # Register numeric project code prefix like 810032 in 810032-11-...
            if "-" in tok:
                prefix = tok.split("-")[0]
                if len(prefix) >= 5 and prefix.isdigit():
                    registry.register(prefix, "PART_ID", scope, is_global=False)


def run_discovery(
    input_root: Path,
    registry: IdentityRegistry,
    *,
    workers: int = 8,
    max_inspect_bytes: int = 8_000_000,
) -> list[str]:
    """Scan input_root read-only, populate registry entities & path_map, return sorted rel_paths."""
    if not input_root.is_dir():
        raise ValueError(f"Input directory does not exist: {input_root}")
    all_files: list[tuple[Path, str]] = []
    for p in sorted(input_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(input_root).as_posix()
        # Ignore downloader bookkeeping folders
        if rel.startswith(".get-input/"):
            continue
        all_files.append((p, rel))

    if not all_files:
        raise ValueError(f"Input directory contains no corpus files: {input_root}")
    log.info("Discovery phase: %d files found in %s", len(all_files), input_root)

    # 1. Path-derived identities (fast, single-threaded)
    for _, rel in all_files:
        if rel.lower().endswith(".resume-partial"):
            registry.omitted_defects.append(
                {
                    "type": "omitted_partial_archive",
                    "description": "Truncated .resume-partial download fragment in source corpus omitted from output.",
                    "scope": registry.scope_for_rel_path(rel),
                    "input_rel_path": rel,
                }
            )
            continue
        scope = registry.scope_for_rel_path(rel)
        _extract_path_identities(rel, registry, scope)

    # 2. Content metadata inspection across files in parallel
    def _inspect_one(item: tuple[Path, str]) -> tuple[str, list[tuple[str, str]]]:
        p, rel = item
        if rel.lower().endswith(".resume-partial"):
            return rel, []
        return rel, inspect_file_metadata(p, rel, max_read=max_inspect_bytes)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        # Inspect concurrently, but allocate IDs in sorted source order.
        for offset in range(0, len(all_files), 256):
            for rel, items in pool.map(_inspect_one, all_files[offset : offset + 256]):
                scope = registry.scope_for_rel_path(rel)
                for etype, raw in items:
                    if not raw or not raw.strip():
                        continue
                    if etype == "PATH":
                        registry.register_path(raw, scope, discover=True)
                    else:
                        registry.register(raw, etype, scope)
                    for m in RE_EXPLICIT_PART_CODE.finditer(raw):
                        registry.register(m.group(1), "PART_ID", scope, is_global=False)

    # 3. Compute deterministic collision-free path map & cross-file reference map
    rel_paths = [rel for _, rel in all_files]
    registry.freeze()
    registry.compute_path_mapping(rel_paths)

    log.info(
        "Discovery complete: %d entities registered across %d path mappings",
        len(registry.entities),
        len(registry.path_map),
    )
    return rel_paths
