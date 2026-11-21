import gzip
import io
import stat
import tarfile
import zipfile

import py7zr
import pytest

from machina_deid.handlers import dispatch_bytes_detailed
from machina_deid.handlers.archive_handler import ArchiveDepthError, MAX_ARCHIVE_DEPTH
from machina_deid.registry import IdentityRegistry


def _zip(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.parametrize(("mode", "suffix"), [("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz"), ("w:gz", ".stp.tar.gz")])
def test_repack_tar_preserves_compression_and_regular_members(mode: str, suffix: str) -> None:
    registry = IdentityRegistry()
    pseudonym = registry.register("Gondora Engineering", "ORG")
    payload = b"Gondora Engineering"
    source = io.BytesIO()
    with tarfile.open(fileobj=source, mode=mode) as archive:
        regular = tarfile.TarInfo("./notes.txt")
        regular.size = len(payload)
        archive.addfile(regular, io.BytesIO(payload))
        link = tarfile.TarInfo("link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "notes.txt"
        archive.addfile(link)

    output, _, warnings, override = dispatch_bytes_detailed(source.getvalue(), "drawing" + suffix, registry, use_ocr=False)
    assert not override
    assert warnings == ["archive_unsafe_or_special_member_skipped"]
    with tarfile.open(fileobj=io.BytesIO(output), mode=mode.replace("w:", "r:")) as archive:
        assert archive.getnames() == ["notes.txt"]
        assert archive.extractfile("notes.txt").read() == pseudonym.encode()


def test_zip_applies_nested_extension_override_and_preserves_duplicate_payloads(monkeypatch) -> None:
    # A valid short Unix compress stream can encode every byte as a literal 9-bit code.
    payload = b"drawing details"
    codes = sum(byte << (9 * index) for index, byte in enumerate(payload))
    compressed = b"\x1f\x9d\x89" + codes.to_bytes((len(payload) * 9 + 7) // 8, "little")
    monkeypatch.setattr("machina_deid.handlers.archive_handler.shutil.which", lambda _: None)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt.Z", compressed)
        archive.writestr("duplicate.txt", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("duplicate.txt", b"second")
        link = zipfile.ZipInfo("link.txt")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, b"duplicate.txt")

    output, _, warnings, override = dispatch_bytes_detailed(buffer.getvalue(), "drawings.zip", IdentityRegistry(), use_ocr=False)
    assert not override
    assert set(warnings) == {"unix_z_repacked_as_gz_no_compress_binary", "archive_unsafe_or_special_member_skipped"}
    with zipfile.ZipFile(io.BytesIO(output)) as archive:
        assert archive.namelist() == ["notes.txt.gz", "duplicate.txt", "duplicate_dup2.txt"]
        assert gzip.decompress(archive.read("notes.txt.gz")) == payload
        assert archive.read("duplicate.txt") == b"first"
        assert archive.read("duplicate_dup2.txt") == b"second"


def test_over_depth_archive_raises_without_returning_raw_content() -> None:
    data = _zip("notes.txt", b"drawing details")
    for _ in range(MAX_ARCHIVE_DEPTH):
        data = _zip("nested.zip", data)
    with pytest.raises(ArchiveDepthError):
        dispatch_bytes_detailed(data, "drawings.zip", IdentityRegistry(), use_ocr=False)


def test_seven_zip_preserves_distinct_regular_members() -> None:
    source = io.BytesIO()
    with py7zr.SevenZipFile(source, mode="w") as archive:
        archive.writestr(b"first", "folder/notes.txt")
        archive.writestr(b"second", "folder/notes.txt")
        archive.writestr(b"", "folder/empty.txt")

    output, _, warnings, override = dispatch_bytes_detailed(source.getvalue(), "drawings.7z", IdentityRegistry(), use_ocr=False)
    assert not warnings and not override
    with py7zr.SevenZipFile(io.BytesIO(output)) as archive:
        files = {info.filename: info.uncompressed for info in archive.list()}
    assert files == {"folder/notes.txt": 5, "folder/notes_dup2.txt": 6, "folder/empty.txt": 0}
