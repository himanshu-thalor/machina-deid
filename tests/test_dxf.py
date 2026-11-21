import io

import ezdxf
import pytest
from ezdxf.lldxf.types import DXFBinaryTag

from machina_deid.handlers.svg_dxf_dwg import (
    DXF_BINARY_SIGNATURE,
    inspect_dxf_metadata,
    process_dxf_bytes,
    read_dxf_document,
)
from machina_deid.registry import IdentityRegistry


@pytest.mark.parametrize("binary", [False, True])
def test_dxf_round_trip_preserves_codepage_geometry_and_binary_records(binary: bool) -> None:
    doc = ezdxf.new("R2004")
    doc.header["$PROJECTNAME"] = "Jörg Design"
    model = doc.modelspace()
    model.add_line((2, 3), (5, 7))
    model.add_text("Jörg Design Ø 45.0 mm")
    doc.blocks.new("TitleBlock")
    model.add_blockref("TitleBlock", (2, 3)).add_attrib("AUTHOR", "Jörg Design")
    payload = b"\x01\x00\x12\x34\x80\xfe"
    record = doc.objects.add_xrecord()
    record.tags.append(DXFBinaryTag(310, payload))
    doc.rootdict["EngineeringRecord"] = record

    if binary:
        output = io.BytesIO()
        doc.write(output, fmt="bin")
        raw = output.getvalue()
    else:
        output = io.StringIO()
        doc.write(output)
        raw = doc.encode(output.getvalue().replace("\n", "\r\n"))

    assert ("PROJECT", "Jörg Design") in inspect_dxf_metadata(raw)
    registry = IdentityRegistry()
    pseudonym = registry.register("Jörg Design", "PROJECT")
    clean, count = process_dxf_bytes(raw, registry)

    assert count >= 2
    assert clean.startswith(DXF_BINARY_SIGNATURE) == binary
    result = read_dxf_document(clean)
    assert result.header["$PROJECTNAME"] == pseudonym
    line, text, blockref = result.modelspace()
    assert tuple(line.dxf.start) == (2, 3, 0)
    assert tuple(line.dxf.end) == (5, 7, 0)
    assert text.dxf.text == f"{pseudonym} Ø 45.0 mm"
    assert blockref.attribs[0].dxf.text == pseudonym
    assert result.rootdict["EngineeringRecord"].tags[0].value == payload


def test_unparseable_dxf_does_not_write_unvalidated_fallback() -> None:
    with pytest.raises(ezdxf.DXFStructureError):
        process_dxf_bytes(b"Not a DXF drawing\r\n", IdentityRegistry())
