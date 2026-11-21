"""End-to-end integration test across discovery, transform, and audit phases."""

from __future__ import annotations

import io
from pathlib import Path
import zipfile

import pymupdf as fitz

from machina_deid.audit import audit_corpus
from machina_deid.cli import run_transform
from machina_deid.discovery import run_discovery
from machina_deid.registry import IdentityRegistry


def test_end_to_end_pipeline_and_consistency(tmp_path: Path) -> None:
    in_root = tmp_path / "input"
    out_root = tmp_path / "output" / "corpus"
    state_dir = tmp_path / "private_state"

    proj_dir = in_root / "sources" / "github" / "AcmeLabs__SuperWidget"
    proj_dir.mkdir(parents=True)

    # 1. STEP file citing Jane Doe & AcmeLabs
    (proj_dir / "AcmeWidget_Bracket.step").write_text(
        "ISO-10303-21;\nHEADER;\n"
        "FILE_NAME('AcmeWidget_Bracket','2025-02-01',('Jane Doe'),('AcmeLabs'),'','','');\n"
        "FILE_SCHEMA(('AP214'));\nENDSEC;\nDATA;\n"
        "#1=PRODUCT('AcmeWidget_Bracket','AcmeWidget_Bracket','',(#2));\n"
        "ENDSEC;\nEND-ISO-10303-21;\n",
        encoding="latin1",
    )

    # 2. PDF citing same author & org
    pdf = fitz.open()
    page = pdf.new_page(width=595, height=420)
    page.draw_rect(fitz.Rect(30, 30, 560, 390), color=(0, 0, 0), width=1.0)
    page.insert_text((360, 350), "Author: Jane Doe", fontsize=9)
    page.insert_text((360, 370), "Company: AcmeLabs", fontsize=9)
    page.insert_text((100, 100), "50.0 +/- 0.1 mm", fontsize=10)
    pdf.set_metadata({"author": "Jane Doe", "title": "AcmeWidget_Bracket"})
    pdf.save(proj_dir / "AcmeWidget_Bracket.pdf")
    pdf.close()

    # 3. ZIP archive containing an SVG with same identities
    z_bio = io.BytesIO()
    with zipfile.ZipFile(z_bio, "w") as zf:
        zf.writestr(
            "AcmeLabs/Jane_Doe_notes.svg",
            '<svg xmlns="http://www.w3.org/2000/svg"><text>Jane Doe - AcmeLabs</text></svg>',
        )
    (in_root / "archives").mkdir(parents=True)
    (in_root / "archives" / "AcmeLabs__SuperWidget.zip").write_bytes(z_bio.getvalue())

    # 4. Source defect files: 0-byte file + .resume-partial fragment
    (proj_dir / "empty_file.step").write_bytes(b"")
    (proj_dir / "broken.7z.resume-partial").write_bytes(b"AcmeLabs raw partial bytes")

    # Run Phase 1..3
    state_dir.mkdir(parents=True)
    reg = IdentityRegistry()
    run_discovery(in_root, reg, workers=2)
    reg.save(state_dir / "registry.json")

    readme = tmp_path / "README.txt"
    summary = run_transform(
        in_root, out_root, state_dir, workers=2, resume=False, use_cache=True, use_ocr=False, readme_out=readme
    )
    assert summary["empty_preserved"] == 1
    assert summary["omitted_defects"] == 1
    assert readme.exists()
    assert "AcmeLabs" not in readme.read_text(encoding="utf-8")
    assert "Jane Doe" not in readme.read_text(encoding="utf-8")

    # Independent audit must pass with 0 leaks & 0 structural failures
    rep = audit_corpus(out_root, IdentityRegistry.load(state_dir / "registry.json"))
    assert rep.passed, f"Audit failed: leaks={rep.leaks}, struct={rep.structural_failed}, cons={rep.constraint_violations}"
    assert not list(out_root.rglob("*.resume-partial"))

    # Verify cross-format pseudonym consistency between STEP and PDF
    step_out = list(out_root.rglob("*.step"))
    non_empty_step = [p for p in step_out if p.stat().st_size > 0][0]
    pdf_out = list(out_root.rglob("*.pdf"))[0]
    step_txt = non_empty_step.read_text(encoding="latin1")
    d = fitz.open(pdf_out)
    pdf_txt = d[0].get_text("text")
    d.close()

    jane_pseudo = reg.entities[reg.variant_to_id["jane doe"]].pseudonym
    acme_pseudo = reg.entities[reg.variant_to_id["acmelabs"]].pseudonym
    assert jane_pseudo in step_txt and jane_pseudo in pdf_txt
    assert acme_pseudo in step_txt and acme_pseudo in pdf_txt
    assert "50.0 +/- 0.1 mm" in pdf_txt


def test_worker_order_and_resume_receipts(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    state = tmp_path / "state"
    corpus = tmp_path / "corpus"
    for i in range(6):
        (source / f"part-{i}.txt").write_text(f"Contact: engineer{i}@private-company.test")

    sequential = IdentityRegistry()
    run_discovery(source, sequential, workers=1)
    sequential.save(state / "sequential.json")
    parallel = IdentityRegistry()
    run_discovery(source, parallel, workers=4)
    parallel.save(state / "registry.json")
    assert (state / "sequential.json").read_bytes() == (state / "registry.json").read_bytes()

    first = run_transform(source, corpus, state, workers=2, use_cache=False, use_ocr=False)
    assert first["processed"] == 6
    baseline = {path.name: path.read_bytes() for path in corpus.iterdir()}
    swapped = run_transform(source, corpus, state, workers=1, resume=False, use_cache=False, use_ocr=False)
    assert swapped["processed"] == 6
    assert {path.name: path.read_bytes() for path in corpus.iterdir()} == baseline

    resumed = run_transform(source, corpus, state, workers=2, use_cache=False, use_ocr=False)
    assert resumed["resumed_skipped"] == 6
    (corpus / "part-0.txt").write_text("bad output")
    (source / "part-1.txt").write_text("Contact: other-engineer@private-company.test")
    repaired = run_transform(source, corpus, state, workers=2, use_cache=False, use_ocr=False)
    assert repaired["resumed_skipped"] == 4
    assert (corpus / "part-0.txt").read_bytes() == baseline["part-0.txt"]
    assert (corpus / "part-1.txt").read_bytes() != baseline["part-1.txt"]
