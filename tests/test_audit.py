"""Regression tests for corpus coverage, STEP framing, and archive payload auditing."""

import io
import gzip
from pathlib import Path
import tarfile

import py7zr
import pytest

from machina_deid.audit import audit_corpus
from machina_deid.registry import GLOBAL_SCOPE, IdentityRegistry


def test_audit_checks_corpus_paths(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    registry = IdentityRegistry()
    assert not audit_corpus(corpus, registry).passed
    corpus.mkdir()
    assert not audit_corpus(corpus, registry).passed

    (corpus / "clean.txt").write_text("clean", encoding="utf-8")
    report = audit_corpus(corpus, registry, expected_paths={"other.txt"})
    assert report.constraint_violations == [
        "Missing corpus file: other.txt",
        "Unexpected corpus file: clean.txt",
    ]
    assert audit_corpus(corpus, registry, expected_paths={"clean.txt"}).passed


def test_audit_matches_source_scope_after_archive_conversion(tmp_path: Path) -> None:
    registry = IdentityRegistry()
    registry.register("Local Draft", "PERSON", "sources/catalog/original", is_global=False)
    registry.path_map["sources/catalog/original/notes.Z"] = "sources/catalog/PRJ-0001/notes.Z"
    output = "sources/catalog/PRJ-0001/notes.gz"
    archive = tmp_path / output
    archive.parent.mkdir(parents=True)
    archive.write_bytes(gzip.compress(b"Created by Local Draft"))

    report = audit_corpus(
        tmp_path,
        registry,
        expected_paths={output},
        output_overrides={"sources/catalog/PRJ-0001/notes.Z": output},
    )
    assert report.leaks == [{"location": output[:-3], "token": "PERSON:Local Draft"}]


def test_audit_matches_tokens_beyond_previous_limit(tmp_path: Path) -> None:
    registry = IdentityRegistry()
    for i in range(650):
        registry.register(f"Confidential Organization Number {i:04}", "ORG", GLOBAL_SCOPE)
    registry.register("Leah Rose", "PERSON", GLOBAL_SCOPE)
    (tmp_path / "notes.txt").write_text("Created by Leah Rose", encoding="utf-8")
    report = audit_corpus(tmp_path, registry)
    assert report.leaks == [{"location": "notes.txt", "token": "PERSON:Leah Rose"}]


def test_audit_preserves_parasolid_transmit_flag_but_catches_author(tmp_path: Path) -> None:
    registry = IdentityRegistry()
    registry.register("transmit", "PERSON", GLOBAL_SCOPE)
    file = tmp_path / "assembly.x_b"
    header = b"**PARASOLID\nFORMAT=binary;\nGUISE=transmit;\n"
    tail = b"**END_OF_HEADER***\n\x00"
    file.write_bytes(header + b"USER=Engineer;\n" + tail)
    assert audit_corpus(tmp_path, registry).passed
    file.write_bytes(header + b"USER=transmit;\n" + tail)
    report = audit_corpus(tmp_path, registry)
    assert report.leaks == [{"location": file.name, "token": "PERSON:transmit"}]


@pytest.mark.parametrize("header", [b"", b"ISO-10303-21;\n"])
def test_audit_rejects_bad_large_step_framing(tmp_path: Path, header: bytes) -> None:
    with (tmp_path / "large.step").open("wb") as file:
        file.write(header)
        file.truncate(50_000_001)

    report = audit_corpus(tmp_path, IdentityRegistry())
    assert not report.passed
    assert report.structural_ok == 0
    marker = "END-ISO-10303-21 trailer" if header else "ISO-10303-21 header"
    assert report.structural_failed == [f"large.step: missing {marker}"]


@pytest.mark.parametrize("ext", [".7z", ".z", ".tar.bz2", ".tar.xz"])
def test_audit_checks_archive_payloads(tmp_path: Path, ext: str) -> None:
    raw = b"Created by Leah Engineer"
    output = tmp_path / ("export" + ext)
    registry = IdentityRegistry()
    registry.register("Leah Engineer", "PERSON", GLOBAL_SCOPE)

    if ext == ".7z":
        with py7zr.SevenZipFile(output, mode="w") as file:
            file.writestr(raw, "notes.txt")
    elif ext == ".z":
        # A small valid .Z stream can use all literal nine-bit LZW codes.
        codes = sum(value << (9 * i) for i, value in enumerate(raw))
        output.write_bytes(b"\x1f\x9d\x89" + codes.to_bytes((9 * len(raw) + 7) // 8, "little"))
    else:
        mode = "w:bz2" if ext.endswith("bz2") else "w:xz"
        with tarfile.open(output, mode) as file:
            info = tarfile.TarInfo("notes.txt")
            info.size = len(raw)
            file.addfile(info, io.BytesIO(raw))

    report = audit_corpus(tmp_path, registry)
    assert report.structural_ok == 1
    assert len(report.leaks) == 1
    assert report.leaks[0]["token"] == "PERSON:Leah Engineer"
