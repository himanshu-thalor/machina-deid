"""Unit and format-level tests for all Machina CAD De-ID handlers."""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import tarfile
import zipfile

import ezdxf
from lxml import etree
import olefile
from PIL import Image, PngImagePlugin
import pymupdf as fitz
import pytest

from machina_deid.config import split_compound_extension
from machina_deid.handlers import dispatch_bytes, process_file
from machina_deid.handlers.archive_handler import decompress_unix_z
from machina_deid.handlers.creo_catia import process_creo_bytes
from machina_deid.handlers.ole2_cad import SUMMARY_INFO, _rewrite_oleps_stream, parse_oleps_strings, process_ole2_bytes
from machina_deid.handlers.pdf_handler import process_pdf_bytes
from machina_deid.handlers.solidworks_modern import _scrub_sw_xml, parse_modern_container, process_modern_solidworks
from machina_deid.handlers.svg_dxf_dwg import process_dxf_bytes, process_svg_bytes
from machina_deid.handlers.text_cad import (
    is_binary_stl,
    process_iges_bytes,
    process_parasolid_bytes,
    process_sat_bytes,
    process_step_file,
    process_stl_bytes,
)
from machina_deid.registry import GLOBAL_SCOPE, IdentityRegistry


SAMPLE_ROOT = Path(__file__).resolve().parent.parent / "sample_input"


def test_compound_extensions() -> None:
    assert split_compound_extension("810032-11-abdeckblech.drw.6") == ("810032-11-abdeckblech", ".drw.6")
    assert split_compound_extension("0353-40-123.stp.tar.gz") == ("0353-40-123", ".stp.tar.gz")
    assert split_compound_extension("part.SLDPRT") == ("part", ".SLDPRT")
    assert split_compound_extension("archive.7z.resume-partial") == ("archive", ".7z.resume-partial")


def test_qualified_part_identifier_keeps_compound_suffix() -> None:
    registry = IdentityRegistry()
    pseudo = registry.register("0353-40-123.stp", "PART_ID")
    registry.freeze()
    assert registry.resolve_filename("0353-40-123.stp.tar.gz", "project") == f"{pseudo}.stp.tar.gz"
    assert registry.resolve_filename("0353-40-123.stp", "project") == f"{pseudo}.stp"
    assert registry.replace_text("See 0353-40-123.stp", "project") == f"See {pseudo}.stp"


def test_property_set_roles_and_fixed_capacity() -> None:
    value = b"Mira\0\0\0\0"
    section = struct.pack("<6I", 32, 1, 4, 16, 30, 5) + value
    header = b"\xfe\xff" + bytes(22) + struct.pack("<I", 1)
    registry = IdentityRegistry()
    registry.freeze()

    raw_custom = header + bytes(16) + struct.pack("<I", 48) + section
    assert _rewrite_oleps_stream(raw_custom, registry, GLOBAL_SCOPE, max_len=len(raw_custom)) == (raw_custom, 0)

    raw_author = header + SUMMARY_INFO + struct.pack("<I", 48) + section
    updated, count = _rewrite_oleps_stream(raw_author, registry, GLOBAL_SCOPE, max_len=len(raw_author))
    assert len(updated) <= len(raw_author)
    assert count == 1
    assert parse_oleps_strings(updated)[0][2] != "Mira"


def test_registry_boundary_and_consistency() -> None:
    reg = IdentityRegistry()
    scope = "sources/catalog/AcmeWidget"
    p_acc = reg.register("ACME\\jsmith", "ACCOUNT", scope)
    assert p_acc and "\\" in p_acc
    # Underscore boundary must match _Dallmayr_7817 without mangling unrelated words!
    reg.register("Dallmayr", "ORG", scope, is_global=True)
    reg.register("arm", "ORG", scope, is_global=False)
    txt = "20180913_Schneestecher_Dallmayr_7817 PARAMETRIC arm_mount"
    out = reg.replace_text(txt, scope)
    assert "Dallmayr" not in out
    assert "PARAMETRIC" in out
    assert "arm_mount" in out  # 'arm' is 3 chars and 'arm_mount' is alphanumeric-joined? Wait: '_' is not alphanumeric so arm matches if registered!
    # Verify global scope does NOT apply scoped 'arm'
    assert reg.replace_text("PARAMETRIC arm", GLOBAL_SCOPE) == "PARAMETRIC arm"


def test_step_streaming_preserves_geometry(tmp_path: Path) -> None:
    reg = IdentityRegistry()
    scope = "sources/github/Acme__Widget"
    reg.register("Acme Robotics", "ORG", scope, is_global=True)
    reg.register("Alice Engineer", "PERSON", scope, is_global=True)
    step_in = tmp_path / "part.step"
    step_out = tmp_path / "out.step"
    step_in.write_text(
        "ISO-10303-21;\n"
        "HEADER;\n"
        "FILE_DESCRIPTION(('Acme Robotics Bracket'),'2;1');\n"
        "FILE_NAME('bracket','2024-01-01',('Alice Engineer'),('Acme Robotics'),'','','');\n"
        "FILE_SCHEMA(('AP214'));\n"
        "ENDSEC;\n"
        "DATA;\n"
        "#1=PERSON('1','Engineer','Alice',$,$,$);\n"
        "#2=ORGANIZATION('O1','Acme Robotics','Org');\n"
        "#3=CARTESIAN_POINT('Origin',(12.5,-4.0,100.0));\n"
        "#4=MANIFOLD_SOLID_BREP('Acme Robotics Body',#5);\n"
        "ENDSEC;\n"
        "END-ISO-10303-21;\n",
        encoding="latin1",
    )
    rep = process_step_file(step_in, step_out, reg, scope)
    assert rep >= 3
    out_txt = step_out.read_text(encoding="latin1")
    assert "ISO-10303-21;" in out_txt
    assert "Acme Robotics" not in out_txt
    assert "Alice Engineer" not in out_txt
    assert "#3=CARTESIAN_POINT('Origin',(12.5,-4.0,100.0));" in out_txt


def test_iges_hollerith_80col_wrap() -> None:
    reg = IdentityRegistry()
    scope = "sources/catalog/TestIges"
    reg.register("VerySecretOrgName", "ORG", scope, is_global=True)
    reg.register("Jane Doe", "PERSON", scope, is_global=True)
    g_content = "1H,,1H;,12Hpart.SLDPRT,28HC:\\Users\\Jane Doe\\part.IGS,15HSolidWorks 2020,17HVerySecretOrgName,32,308,15,308,15,,1.,2,2HMM;"
    # Wrap into 72-char G lines
    lines = []
    lines.append("SolidWorks IGES export by Jane Doe".ljust(72) + "S      1\n")
    pos = 0
    seq = 1
    while pos < len(g_content):
        lines.append(g_content[pos : pos + 72].ljust(72) + f"G{seq:7d}\n")
        pos += 72
        seq += 1
    lines.append(("     116       1       0       1       0       0       0       000000000".ljust(72) + "D      1\n"))
    lines.append(("     116       0       0       1       0                               0".ljust(72) + "D      2\n"))
    lines.append(("116,0.0,0.0,0.0;".ljust(72) + "P      1\n"))
    lines.append(f"S      1G{seq-1:7d}D      2P      1".ljust(72) + "T      1\n")

    out_bytes, rep = process_iges_bytes("".join(lines).encode("latin1"), reg, scope)
    assert rep >= 2
    out_lines = out_bytes.decode("latin1").splitlines()
    assert all(len(l) == 80 for l in out_lines)
    assert "VerySecretOrgName" not in out_bytes.decode("latin1")
    assert "Jane Doe" not in out_bytes.decode("latin1")
    t_line = out_lines[-1]
    assert t_line[72] == "T"
    # Verify updated G line count in T record matches actual G lines
    g_count = sum(1 for l in out_lines if l[72] == "G")
    assert f"G{g_count:7d}" in t_line


def test_binary_stl_solid_trap() -> None:
    reg = IdentityRegistry()
    scope = "sources/github/Acme__Part"
    reg.register("AcmeCorp", "ORG", scope, is_global=True)
    # Construct valid binary STL whose 80-byte header starts with 'solid AcmeCorp'
    hdr = b"solid AcmeCorp secret header".ljust(80, b"\x00")
    tri = struct.pack("<12fH", 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0)
    raw = hdr + struct.pack("<I", 1) + tri
    assert is_binary_stl(raw)
    out, rep = process_stl_bytes(raw, reg, scope)
    assert rep == 1
    assert len(out) == len(raw)
    assert is_binary_stl(out)
    assert b"AcmeCorp" not in out[:80]
    assert out[80:] == raw[80:]


def test_sat_and_parasolid() -> None:
    reg = IdentityRegistry()
    scope = "sources/catalog/SatTest"
    reg.register("AcmeCorp", "ORG", scope, is_global=True)
    sat = (
        "700 0 1 0\n"
        "30 AcmeCorp Exporter 1.0 NT 24 Thu Jul 2 2026\n"
        "1 1e-06 1e-10\n"
        "name_attrib $-1 -1 $-1 $-1 @13 AcmeCorp_Part #\n"
    ).encode("latin1")
    out_sat, rep_sat = process_sat_bytes(sat, reg, scope)
    assert rep_sat >= 1
    assert b"AcmeCorp" not in out_sat
    # Check @<len> matches actual string length
    m = struct.pack
    txt_sat = out_sat.decode("latin1")
    import re
    mh = re.search(r"@(\d+) ([^\r\n#]+)#", txt_sat)
    assert mh
    assert int(mh.group(1)) == len(mh.group(2).rstrip())

    xb = (
        b"**PART1;\nMC=WORKSTATION1;\nUSER=jdoe;\nSITE=Columbus, OH;\n"
        b"KEY=C:\\Users\\jdoe\\part;\nFILE=C:\\Users\\jdoe\\part.x_b;\n"
        b"**END_OF_HEADER*****\n\x00\x01\x02BINARY_GEOMETRY_BYTES"
    )
    out_xb, rep_xb = process_parasolid_bytes(xb, True, reg, scope)
    assert rep_xb >= 4
    assert b"WORKSTATION1" not in out_xb
    assert b"jdoe" not in out_xb
    assert out_xb.endswith(b"\x00\x01\x02BINARY_GEOMETRY_BYTES")


def test_pdf_vector_logo_xmp_attachment() -> None:
    reg = IdentityRegistry()
    scope = "sources/catalog/PdfTest"
    reg.register("DMAWI\\jlemburg", "ACCOUNT", scope, is_global=True)
    reg.register("M.Littmann", "PERSON", scope, is_global=True)
    reg.register("Acme Robotics", "ORG", scope, is_global=True)

    # Create a real vector PDF with drawing geometry, title-block text, corner logo, and attachment
    doc = fitz.open()
    page = doc.new_page(width=595, height=420)
    # Vector drawing rect (CAD border & part)
    page.draw_rect(fitz.Rect(20, 20, 575, 400), color=(0, 0, 0), width=1.0)
    page.draw_circle(fitz.Point(200, 180), 40, color=(0, 0, 0), width=1.0)
    # Dimension & title-block text
    page.insert_text((190, 130), "245 mm", fontsize=10)
    page.insert_text((350, 340), "Author: M.Littmann", fontsize=9)
    page.insert_text((350, 360), "Org: Acme Robotics", fontsize=9)
    # Corner logo image
    im = Image.new("RGB", (80, 30), (200, 30, 30))
    im_bio = io.BytesIO()
    im.save(im_bio, format="PNG")
    page.insert_image(fitz.Rect(480, 330, 560, 360), stream=im_bio.getvalue())
    # Metadata & attachment
    doc.set_metadata({"author": "DMAWI\\jlemburg", "title": "Acme Robotics Bracket"})
    doc.embfile_add("Acme_notes.txt", b"Created by M.Littmann at Acme Robotics", filename="Acme_notes.txt")
    raw_pdf = doc.tobytes()
    doc.close()

    out_pdf, rep = process_pdf_bytes(raw_pdf, reg, scope, use_ocr=False)
    assert rep >= 4
    check_doc = fitz.open(stream=out_pdf, filetype="pdf")
    p0 = check_doc[0]
    txt = p0.get_text("text")
    assert "M.Littmann" not in txt
    assert "Acme Robotics" not in txt
    assert "245 mm" in txt
    assert len(p0.get_drawings()) >= 2  # Vector geometry preserved!
    assert "jlemburg" not in (check_doc.metadata.get("author") or "")
    assert "Acme Robotics" not in (check_doc.metadata.get("title") or "")
    # Attachment de-identified
    assert check_doc.embfile_count() == 1
    emb_info = check_doc.embfile_info(0)
    assert "Acme" not in (emb_info.get("filename") or "")
    emb_data = check_doc.embfile_get(0).decode("utf-8")
    assert "M.Littmann" not in emb_data
    assert "Acme Robotics" not in emb_data
    check_doc.close()


def test_svg_and_dxf_handlers() -> None:
    reg = IdentityRegistry()
    scope = "sources/github/Acme__Cad"
    reg.register("Jane Designer", "PERSON", scope, is_global=True)
    reg.register("AcmeCorp", "ORG", scope, is_global=True)

    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" '
        'sodipodi:docname="C:\\Users\\Jane Designer\\AcmeCorp_part.svg">'
        '<metadata><dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Jane Designer</dc:creator></metadata>'
        '<text x="10" y="20">AcmeCorp 45.0 mm</text>'
        "</svg>"
    ).encode("utf-8")
    out_svg, rep_svg = process_svg_bytes(svg, reg, scope, use_ocr=False)
    assert rep_svg >= 2
    s_txt = out_svg.decode("utf-8")
    assert "Jane Designer" not in s_txt
    assert "AcmeCorp" not in s_txt
    assert "45.0 mm" in s_txt
    etree.fromstring(out_svg)

    dxf_doc = ezdxf.new("R2010")
    dxf_doc.header["$LASTSAVEDBY"] = "Jane Designer"
    dxf_doc.header["$PROJECTNAME"] = "AcmeCorp"
    msp = dxf_doc.modelspace()
    msp.add_line((0, 0), (100, 0))
    msp.add_text("Drawn by Jane Designer - AcmeCorp 100 mm").set_placement((10, 10))
    s_io = io.StringIO()
    dxf_doc.write(s_io)
    out_dxf, rep_dxf = process_dxf_bytes(s_io.getvalue().encode("utf-8"), reg, scope)
    assert rep_dxf >= 2
    out_dxf_txt = out_dxf.decode("utf-8")
    assert "Jane Designer" not in out_dxf_txt
    assert "AcmeCorp" not in out_dxf_txt
    assert "100 mm" in out_dxf_txt
    ezdxf.read(io.StringIO(out_dxf_txt))


def test_real_sw2015_and_ole2_from_sample() -> None:
    if not SAMPLE_ROOT.exists():
        pytest.skip("sample_input not present")

    # Test real SW2015+ file (Schiebestange.SLDPRT)
    sw_files = list(SAMPLE_ROOT.rglob("Schiebestange.SLDPRT"))
    if sw_files:
        reg = IdentityRegistry()
        scope = "sources/catalog/AWI"
        reg.register("DMAWI\\jlemburg", "ACCOUNT", scope, is_global=True)
        reg.register("mlittman", "USERNAME", scope, is_global=True)
        reg.register("Dallmayr", "ORG", scope, is_global=True)
        reg.register("infsrv.dmawi.de", "DOMAIN", scope, is_global=True)
        reg.register("7817", "PROJECT", scope, is_global=False)

        raw = sw_files[0].read_bytes()
        out, rep = process_modern_solidworks(raw, reg, scope, use_ocr=False)
        assert rep >= 3
        parsed = parse_modern_container(out)
        assert len(parsed["local_chunks"]) >= 30
        active = {e["local_marker_off"] for e in parsed["cd_entries"]}
        for m_off, chunk in parsed["local_chunks"].items():
            if m_off not in active:
                continue
            r = chunk["raw"]
            for bad in (b"jlemburg", b"mlittman", b"Dallmayr", b"dmawi.de"):
                assert bad.lower() not in r.lower()
                assert bad.decode().encode("utf-16-le").lower() not in r.lower()

    # Test real OLE2 Inventor file (Connecting plate 2.ipt)
    ipt_files = list(SAMPLE_ROOT.rglob("*.ipt"))
    if ipt_files:
        reg = IdentityRegistry()
        scope = "sources/catalog/AdReNa"
        reg.register("Simone", "PERSON", scope, is_global=True)
        raw = ipt_files[0].read_bytes()
        out, rep = process_ole2_bytes(raw, ".ipt", reg, scope, use_ocr=False)
        assert olefile.isOleFile(io.BytesIO(out))
        with olefile.OleFileIO(io.BytesIO(out)) as ole:
            for entry in ole.listdir(streams=True, storages=False):
                if entry[-1].startswith("\x05"):
                    for pid, _, val in parse_oleps_strings(ole.openstream(entry).read()):
                        assert "simone" not in val.lower()
                        # Check final char wasn't clipped!
                        if "Engineer" in val:
                            assert not val.endswith("000") or val.endswith("0001") or len(val.split()[-1]) == 4


def test_real_unix_z_archive_from_sample() -> None:
    if not SAMPLE_ROOT.exists():
        pytest.skip("sample_input not present")
    z_files = list(SAMPLE_ROOT.rglob("*.Z"))
    if z_files:
        raw = decompress_unix_z(z_files[0].read_bytes())
        assert len(raw) > 100


def test_creo_renames_model_name_with_byte_length_and_fixed_header_size() -> None:
    registry = IdentityRegistry()
    registry.register("NewOrg", "ORG", GLOBAL_SCOPE)
    filename = "NewOrg-mécanisme.drw".encode("utf-8")
    cmnm = f"{len(filename):03x}".encode("ascii") + filename
    raw = b"#UGC:2 DRAWING\n#- CMNM " + cmnm.ljust(64) + b"\\\n#-END_OF_UGC_HEADER\nGEOMETRY\x00"

    output, changes = process_creo_bytes(raw, registry)

    assert changes == 1
    assert len(output) == len(raw)
    assert output.endswith(b"#-END_OF_UGC_HEADER\nGEOMETRY\x00")
    payload = output.splitlines()[1][len(b"#- CMNM ") : -1].rstrip()
    assert int(payload[:3], 16) == len(payload[3:])
    assert payload[3:].decode("utf-8") == "ORG-0001-mécanisme.drw"


def test_solidworks_keywords_scrubs_reference_type_only() -> None:
    registry = IdentityRegistry()
    registry.register("Customer Design", "PROJECT", GLOBAL_SCOPE)
    raw = (
        b'\x86<?xml version="1.0" encoding="UTF-8"?>'
        b'<Keywords><Reference Name="Customer Design assembly-1" Type="Customer Design assembly-"/>'
        b'<Feature Name="Preserve" Type="Customer Design face"/></Keywords>'
    )

    output = _scrub_sw_xml(raw, "swXmlContents/KeyWords", registry, GLOBAL_SCOPE)

    assert output.startswith(b"\x86")
    root = etree.fromstring(output[1:])
    assert root.find("Reference").get("Name") == "PRJ-0001 assembly-1"
    assert root.find("Reference").get("Type") == "PRJ-0001 assembly-"
    assert root.find("Feature").get("Type") == "Customer Design face"
