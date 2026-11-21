"""Inspect and transform nested ZIP, TAR, 7z, RAR and compressed streams."""

from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
import gzip
import io
import logging
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile

import py7zr
from py7zr.io import Py7zIO, WriterFactory
import rarfile

from ..config import split_compound_extension
from ..registry import GLOBAL_SCOPE, IdentityRegistry

log = logging.getLogger(__name__)

MAX_ARCHIVE_DEPTH = 5
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024  # Bound decompressed data in one archive.


def decompress_unix_z(data: bytes) -> bytes:
    """Pure-Python decompressor for Unix compress (.Z) 16-bit LZW format."""
    if len(data) < 3 or data[:2] != b"\x1f\x9d":
        raise ValueError("Not a valid Unix .Z stream")
    flags = data[2]
    block_mode = bool(flags & 0x80)
    maxbits = flags & 0x1F
    if maxbits < 9 or maxbits > 16:
        raise ValueError(f"Unsupported .Z maxbits={maxbits}")

    clear_code = 256 if block_mode else -1
    n_bits = 9
    maxcode = (1 << n_bits) - 1
    free_ent = 257 if block_mode else 256
    # Table maps code -> bytes
    table: dict[int, bytes] = {i: bytes([i]) for i in range(256)}

    bit_buf = 0
    bit_cnt = 0
    pos = 3

    def next_code() -> int | None:
        nonlocal bit_buf, bit_cnt, pos
        while bit_cnt < n_bits:
            if pos >= len(data):
                return None
            bit_buf |= data[pos] << bit_cnt
            bit_cnt += 8
            pos += 1
        code = bit_buf & ((1 << n_bits) - 1)
        bit_buf >>= n_bits
        bit_cnt -= n_bits
        return code

    out = bytearray()
    first = next_code()
    if first is None:
        return b""
    if first >= 256:
        raise ValueError("Corrupt .Z first code")
    old_entry = table[first]
    out.extend(old_entry)

    while True:
        code = next_code()
        if code is None:
            break
        if code == clear_code:
            # Align bit buffer to n_bits*8 boundary per ncompress spec
            table = {i: bytes([i]) for i in range(256)}
            n_bits = 9
            maxcode = (1 << n_bits) - 1
            free_ent = 257
            nxt = next_code()
            if nxt is None:
                break
            old_entry = table[nxt]
            if len(out) + len(old_entry) > MAX_UNPACKED_BYTES:
                raise ArchiveSizeError("Unix .Z stream exceeds uncompressed size limit")
            out.extend(old_entry)
            continue
        if code in table:
            entry = table[code]
        elif code == free_ent:
            entry = old_entry + old_entry[:1]
        else:
            raise ValueError(f"Invalid .Z LZW code {code}")
        if len(out) + len(entry) > MAX_UNPACKED_BYTES:
            raise ArchiveSizeError("Unix .Z stream exceeds uncompressed size limit")
        out.extend(entry)
        if free_ent < (1 << maxbits):
            table[free_ent] = old_entry + entry[:1]
            free_ent += 1
            if free_ent > maxcode and n_bits < maxbits:
                n_bits += 1
                maxcode = (1 << n_bits) - 1
        old_entry = entry
    return bytes(out)


class ArchiveDepthError(ValueError):
    """An archive exceeds the supported recursion depth."""


class ArchiveSizeError(ValueError):
    """An archive exceeds the supported uncompressed size."""


TAR_EXTS = {".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.z"}
ARCHIVE_EXTS = TAR_EXTS | {".zip", ".7z", ".rar", ".gz", ".z"}
MAX_INSPECT_MEMBER_BYTES = 2_000_000
MAX_INSPECT_ARCHIVE_BYTES = 32_000_000


def is_archive_extension(ext: str) -> bool:
    return _archive_kind(ext) in ARCHIVE_EXTS or ext.endswith((".gz", ".z"))


def _archive_kind(ext: str) -> str:
    # STEP archives can have compound extensions such as .stp.tar.gz.
    return next((kind for kind in TAR_EXTS if ext.endswith(kind)), ext)


def archive_output_name(filename: str, extension_override: str) -> str:
    if not extension_override:
        return filename
    stem, _ = split_compound_extension(filename)
    return stem + extension_override


def _is_safe_member_name(name: str) -> bool:
    norm = name.replace("\\", "/")
    parts = norm.split("/")
    return (
        any(p and p != "." for p in parts)
        and not norm.startswith("/")
        and not re.match(r"^[A-Za-z]:", norm)
        and ".." not in parts
        and "\x00" not in norm
    )


def _is_zip_regular(info: zipfile.ZipInfo) -> bool:
    mode = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
    return not info.is_dir() and mode in (0, stat.S_IFREG)


def _read_member(source, max_bytes: int) -> bytes:
    data = io.BytesIO()
    while chunk := source.read(min(1024 * 1024, max_bytes - data.tell() + 1)):
        data.write(chunk)
        if data.tell() > max_bytes:
            raise ArchiveSizeError("Archive member exceeds uncompressed size limit")
    return data.getvalue()


class _DiskMember(Py7zIO):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.file = path.open("w+b")

    def write(self, data: bytes | bytearray) -> int:
        return self.file.write(data)

    def read(self, size: int | None = None) -> bytes:
        return self.file.read(-1 if size is None else size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.file.seek(offset, whence)

    def flush(self) -> None:
        self.file.flush()

    def size(self) -> int:
        return self.path.stat().st_size

    def close(self) -> None:
        self.file.close()


class _SevenZipDiskSink(WriterFactory):
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.files: dict[str, _DiskMember] = {}

    def create(self, filename: str) -> _DiskMember:
        if filename in self.files:
            raise ValueError("Ambiguous 7z member name after normalization")
        member = _DiskMember(self.directory / str(len(self.files)))
        self.files[filename] = member
        return member

    def close(self) -> None:
        for member in self.files.values():
            member.close()


def _seven_zip_members(archive, directory: Path, warn, max_bytes: int, *, inspect: bool = False):
    members = archive.list()
    name_counts = Counter(info.filename for info in members)
    special_names = {info.filename for info in members if not info.is_file}
    targets: set[str] = set()
    names: dict[str, str] = {}
    copies: dict[str, int] = {}
    total = 0
    for info in members:
        if info.is_directory:
            continue
        name = info.filename
        if not info.is_file or not _is_safe_member_name(name):
            warn("archive_unsafe_or_special_member_skipped")
            continue
        if name in special_names:
            raise ValueError("7z file and special member have the same name")
        if inspect and (
            name_counts[name] > 1 or info.uncompressed >= MAX_INSPECT_MEMBER_BYTES or total + info.uncompressed > max_bytes
        ):
            continue
        total += info.uncompressed
        if total > max_bytes:
            raise ArchiveSizeError("7z archive exceeds uncompressed size limit")
        # py7zr appends _0, _1, ... to repeated source names when calling its writer.
        copies[name] = copies.get(name, -1) + 1
        extract_name = f"{name}_{copies[name] - 1}" if copies[name] else name
        key = Path(extract_name).as_posix()
        if key in names:
            raise ValueError("Ambiguous 7z member name after normalization")
        names[key] = name
        targets.add(name)

    if not targets:
        return

    sink = _SevenZipDiskSink(directory)
    try:
        archive.extract(targets=targets, factory=sink)
        for key, name in names.items():
            member = sink.files.get(key)
            if member is None:
                raise ValueError("7z library did not extract a selected member")
            yield name, member.path
    finally:
        sink.close()


def inspect_archive_file(path: Path, ext: str) -> list[tuple[str, str]]:
    """Read archive member metadata without loading the outer archive into RAM."""
    with path.open("rb") as source:
        return _inspect_archive(source, ext, 0, path.name)


def inspect_archive_bytes(data: bytes, ext: str, depth: int = 0, *, filename: str = "") -> list[tuple[str, str]]:
    """Read small supported members for identity discovery without unpacking archive paths."""
    return _inspect_archive(io.BytesIO(data), ext, depth, filename)


def _inspect_archive(source, ext: str, depth: int, filename: str) -> list[tuple[str, str]]:
    from . import inspect_bytes_metadata
    from .text_cad import inspect_step_metadata

    found: list[tuple[str, str]] = []
    if depth >= MAX_ARCHIVE_DEPTH:
        return found

    ext = _archive_kind(ext)
    budget = MAX_INSPECT_ARCHIVE_BYTES

    def inspect_member(name: str, size: int, open_member) -> None:
        nonlocal budget
        if size >= MAX_INSPECT_MEMBER_BYTES or size > budget:
            return
        with open_member() as member:
            raw = _read_member(member, MAX_INSPECT_MEMBER_BYTES)
        budget -= len(raw)
        _, member_ext = split_compound_extension(name.lower())
        if member_ext in {".step", ".stp"}:
            with tempfile.TemporaryDirectory() as directory:
                step = Path(directory) / "metadata.step"
                step.write_bytes(raw)
                found.extend(inspect_step_metadata(step))
        else:
            found.extend(inspect_bytes_metadata(raw, name, depth=depth + 1))

    try:
        if ext == ".zip":
            with zipfile.ZipFile(source) as archive:
                for info in archive.infolist():
                    if _is_zip_regular(info) and _is_safe_member_name(info.filename):
                        inspect_member(info.filename, info.file_size, lambda: archive.open(info))
        elif ext in TAR_EXTS:
            if ext == ".tar.z":
                source = io.BytesIO(decompress_unix_z(_read_member(source, MAX_INSPECT_ARCHIVE_BYTES)))
            with tarfile.open(fileobj=source, mode="r:*") as archive:
                for info in archive:
                    if info.isfile() and _is_safe_member_name(info.name):
                        inspect_member(info.name, info.size, lambda: archive.extractfile(info))
        elif ext == ".7z":
            with tempfile.TemporaryDirectory() as directory, py7zr.SevenZipFile(
                source, mode="r", max_extract_size=MAX_UNPACKED_BYTES
            ) as archive:
                for name, path in _seven_zip_members(archive, Path(directory), lambda _: None, budget, inspect=True):
                    inspect_member(name, path.stat().st_size, lambda: path.open("rb"))
        elif ext == ".rar":
            with rarfile.RarFile(source, errors="strict") as archive:
                for info in archive.infolist():
                    if info.is_file() and not info.file_redir and _is_safe_member_name(info.filename):
                        inspect_member(info.filename, info.file_size, lambda: archive.open(info))
        elif ext.endswith(".gz") and filename:
            with gzip.GzipFile(fileobj=source) as member:
                raw = _read_member(member, MAX_INSPECT_MEMBER_BYTES)
            inspect_member(filename[:-3], len(raw), lambda: io.BytesIO(raw))
        elif ext.endswith(".z") and filename:
            raw = decompress_unix_z(_read_member(source, MAX_INSPECT_ARCHIVE_BYTES))
            if tarfile.is_tarfile(io.BytesIO(raw)):
                found.extend(inspect_archive_bytes(raw, ".tar", depth))
            else:
                inspect_member(filename[:-2], len(raw), lambda: io.BytesIO(raw))
    except Exception as e:
        log.debug("Archive inspect (%s) failed: %s", ext, type(e).__name__)
    return found


def _rename_inner_path(inner_path: str, registry: IdentityRegistry, scope: str) -> str:
    parts = [p for p in inner_path.replace("\\", "/").split("/") if p not in {"", "."}]
    dirs = [
        registry._sanitize_path_component(registry.replace_text(p, scope, context="path_seg")) or p
        for p in parts[:-1]
    ]
    return "/".join([*dirs, registry.resolve_filename(parts[-1], scope)])


def _unique_member_name(name: str, used: set[str]) -> str:
    stem, ext = split_compound_extension(name)
    candidate = name
    number = 2
    while candidate.casefold() in used:
        candidate = f"{stem}_dup{number}{ext}"
        number += 1
    used.add(candidate.casefold())
    return candidate


def _write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data)


def _repack_tar(data: bytes, ext: str, clean_member, warn) -> bytes:
    out = io.BytesIO()
    consumed = 0
    with ExitStack() as stack:
        destination = out
        mode = {".tar.bz2": "w|bz2", ".tar.xz": "w|xz"}.get(ext, "w|")
        if ext in {".tar.gz", ".tgz"}:
            destination = stack.enter_context(gzip.GzipFile(fileobj=out, mode="wb", mtime=0))
        output = stack.enter_context(tarfile.open(fileobj=destination, mode=mode))
        source = stack.enter_context(tarfile.open(fileobj=io.BytesIO(data), mode="r|*"))
        for info in source:
            consumed += info.size
            if consumed > MAX_UNPACKED_BYTES:
                raise ArchiveSizeError("TAR archive exceeds uncompressed size limit")
            if info.isdir():
                continue
            if not info.isfile() or not _is_safe_member_name(info.name):
                warn("archive_unsafe_or_special_member_skipped")
                continue
            with source.extractfile(info) as file:
                new_name, clean = clean_member(info.name, file.read())
            item = tarfile.TarInfo(name=new_name)
            item.size = len(clean)
            item.mtime = 1767225600
            item.mode = 0o644
            output.addfile(item, io.BytesIO(clean))
    return out.getvalue()


def process_archive_bytes(
    data: bytes,
    filename: str,
    registry: IdentityRegistry,
    scope: str = GLOBAL_SCOPE,
    *,
    use_ocr: bool = True,
    depth: int = 0,
) -> tuple[bytes, int, list[str], str]:
    """Transform an archive and return its bytes, replacement count, warnings, and extension override."""
    from . import dispatch_bytes_detailed

    if depth >= MAX_ARCHIVE_DEPTH:
        raise ArchiveDepthError("Archive exceeds supported nesting depth")

    stem, ext = split_compound_extension(filename)
    ext = _archive_kind(ext.lower())
    replacements = 0
    used_names: set[str] = set()
    warnings: dict[str, None] = {}

    def warn(message: str) -> None:
        warnings[message] = None

    def clean_member(name: str, raw: bytes, *, embedded: bool = True) -> tuple[str, bytes]:
        nonlocal replacements
        clean_name = _rename_inner_path(name, registry, scope) if embedded else name
        clean, count, nested_warnings, new_ext = dispatch_bytes_detailed(
            raw, clean_name, registry, scope, use_ocr=use_ocr, depth=depth + 1
        )
        for warning in nested_warnings:
            warn(warning)
        clean_name = archive_output_name(clean_name, new_ext)
        if embedded:
            if not _is_safe_member_name(clean_name):
                raise ValueError("Transformed archive member name is unsafe")
            clean_name = _unique_member_name(clean_name, used_names)
        if clean_name != name or count:
            replacements += max(1, count)
        return clean_name, clean

    override = ""
    if ext == ".zip":
        out = io.BytesIO()
        consumed = 0
        with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, mode="w") as output:
            for info in source.infolist():
                if info.is_dir():
                    continue
                if not _is_zip_regular(info) or not _is_safe_member_name(info.filename):
                    warn("archive_unsafe_or_special_member_skipped")
                    continue
                consumed += info.file_size
                if consumed > MAX_UNPACKED_BYTES:
                    raise ArchiveSizeError("ZIP archive exceeds uncompressed size limit")
                name, clean = clean_member(info.filename, source.read(info))
                _write_zip_member(output, name, clean)
        result = out.getvalue()

    elif ext in TAR_EXTS - {".tar.z"}:
        result = _repack_tar(data, ext, clean_member, warn)

    elif ext == ".7z":
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean_path = root / "output.7z"
            with py7zr.SevenZipFile(
                io.BytesIO(data), mode="r", max_extract_size=MAX_UNPACKED_BYTES
            ) as source, py7zr.SevenZipFile(clean_path, mode="w") as output:
                for original, path in _seven_zip_members(source, root, warn, MAX_UNPACKED_BYTES):
                    name, clean = clean_member(original, path.read_bytes())
                    output.writestr(clean, name)
                    path.unlink()
            result = clean_path.read_bytes()

    elif ext == ".rar":
        out = io.BytesIO()
        consumed = 0
        with rarfile.RarFile(io.BytesIO(data), errors="strict") as source, zipfile.ZipFile(out, mode="w") as output:
            for info in source.infolist():
                if info.is_dir():
                    continue
                if not info.is_file() or info.file_redir or not _is_safe_member_name(info.filename):
                    warn("archive_unsafe_or_special_member_skipped")
                    continue
                if consumed + info.file_size > MAX_UNPACKED_BYTES:
                    raise ArchiveSizeError("RAR archive exceeds uncompressed size limit")
                with source.open(info) as member:
                    raw = _read_member(member, MAX_UNPACKED_BYTES - consumed)
                consumed += len(raw)
                name, clean = clean_member(info.filename, raw)
                _write_zip_member(output, name, clean)
        result = out.getvalue()
        warn("rar_repacked_as_zip_proprietary_rar_encoder_unavailable")
        override = ".zip"

    elif ext.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
            raw = _read_member(source, MAX_UNPACKED_BYTES)
        inner_name = filename[:-3]
        clean_name, payload = clean_member(inner_name, raw, embedded=False)
        result = gzip.compress(payload, mtime=0)
        if clean_name != inner_name:
            override = clean_name[len(stem):] + filename[-3:]

    elif ext.endswith(".z"):
        raw = decompress_unix_z(data)
        is_tar = ext == ".tar.z" or tarfile.is_tarfile(io.BytesIO(raw))
        inner_name = filename[:-2]
        clean_name = inner_name
        if is_tar:
            payload = _repack_tar(raw, ".tar", clean_member, warn)
        else:
            clean_name, payload = clean_member(inner_name, raw, embedded=False)
        encoder = shutil.which("compress")
        result = b""
        if encoder:
            packed = subprocess.run([encoder, "-c"], input=payload, capture_output=True)
            if packed.returncode == 0 and packed.stdout.startswith(b"\x1f\x9d"):
                result = packed.stdout
        if result:
            if clean_name != inner_name:
                override = clean_name[len(stem):] + filename[-2:]
        else:
            result = gzip.compress(payload, mtime=0)
            if is_tar:
                override = ".tar.gz"
                warn("tar.z_repacked_as_tar_gz_no_compress_binary")
            else:
                override = clean_name[len(stem):] + ".gz"
                warn("unix_z_repacked_as_gz_no_compress_binary")

    else:
        raise ValueError("Unsupported archive extension")

    return result, replacements, list(warnings), override
