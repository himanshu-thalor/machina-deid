#!/usr/bin/env python3
"""Download a stratified multi-format sample of real files from the Machina De-ID mirror."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import sys
import urllib.request

BASE = os.environ.get("MACHINA_INPUT_BASE", "https://machina-input.joinbuilders.org").rstrip("/")
MANIFEST_URL = f"{BASE}/manifest.tsv"
DEST = Path(__file__).resolve().parent.parent / "sample_input"


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "machina-deid-sampler/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def select_sample(rows: list[tuple[str, int, str, str]]) -> list[tuple[str, int, str, str]]:
    selected: dict[str, tuple[str, int, str, str]] = {}

    def add(row: tuple[str, int, str, str]) -> None:
        selected[row[0]] = row

    def pick_first(pred, limit: int = 1) -> int:
        cnt = 0
        for r in rows:
            if r[0] in selected:
                continue
            if pred(r[0], r[1]):
                add(r)
                cnt += 1
                if cnt >= limit:
                    break
        return cnt

    # 1. AWI snow-sampler paired SW2015+ .SLDPRT and .PDF drawings (4 pairs = 8 files)
    awi_parts = ["Schiebestange", "Oberplatte_2", "Halteplatte", "Deckel"]
    for part in awi_parts:
        pick_first(lambda p, s, pt=part: "AWI dual-tube" in p and p.lower().endswith(f"/{pt.lower()}.sldprt"), 1)
        pick_first(lambda p, s, pt=part: "AWI dual-tube" in p and p.lower().endswith(f"/{pt.lower()}.pdf"), 1)

    # 2. SolidWorks pre-2015 OLE2 .SLDPRT + .iges (LulzBot)
    pick_first(lambda p, s: "LulzBot _ Aleph Objects" in p and p.lower().endswith(".sldprt") and 20_000 < s < 450_000, 2)
    pick_first(lambda p, s: "LulzBot _ Aleph Objects" in p and p.lower().endswith((".iges", ".igs")) and 5_000 < s < 500_000, 1)

    # 3. SolidWorks assembly + drawing + part family (MultiArm-Pendulum or ASTM D638)
    pick_first(lambda p, s: "MultiArm-Pendulum" in p and p.lower().endswith(".sldasm") and s < 1_200_000, 1)
    pick_first(lambda p, s: "MultiArm-Pendulum" in p and p.lower().endswith(".slddrw") and s < 1_000_000, 2)
    pick_first(lambda p, s: "MultiArm-Pendulum" in p and p.lower().endswith(".sldprt") and s < 500_000, 2)
    pick_first(lambda p, s: "ASTM D638" in p and p.lower().endswith(".sldasm") and s < 2_500_000, 1)
    pick_first(lambda p, s: "ASTM D638" in p and p.lower().endswith(".sldprt") and s < 500_000, 2)

    # 4. Autodesk Inventor (.ipt, .iam, .idw, .ipj, .dwg) from CNR-STIIMA & AdReNa
    pick_first(lambda p, s: "CNR-STIIMA" in p and p.lower().endswith(".ipj"), 1)
    pick_first(lambda p, s: "CNR-STIIMA" in p and p.lower().endswith(".iam") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: "CNR-STIIMA" in p and p.lower().endswith(".idw") and 10_000 < s < 600_000, 1)
    pick_first(lambda p, s: "CNR-STIIMA" in p and p.lower().endswith(".ipt") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: "CNR-STIIMA" in p and p.lower().endswith(".dwg") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: "AdReNa" in p and p.lower().endswith(".ipt") and 10_000 < s < 600_000, 1)
    pick_first(lambda p, s: "AdReNa" in p and p.lower().endswith(".dwg") and 10_000 < s < 600_000, 1)

    # 5. Solid Edge (.par, .asm, .dft)
    pick_first(lambda p, s: p.lower().endswith(".par") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".asm") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".dft") and 10_000 < s < 500_000, 1)

    # 6. PTC Creo (.prt.1, .drw.1, .asm.1)
    pick_first(lambda p, s: "OST ThrowBot" in p and p.lower().endswith(".prt.1") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: "OST ThrowBot" in p and p.lower().endswith(".drw.1") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: "OST ThrowBot" in p and p.lower().endswith(".asm.1") and 10_000 < s < 500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".drw.1") and "icub-tech" in p and 10_000 < s < 500_000, 1)

    # 7. FreeCAD, Fusion 360, 3MF, CATIA
    pick_first(lambda p, s: p.lower().endswith(".fcstd") and 5_000 < s < 400_000, 2)
    pick_first(lambda p, s: p.lower().endswith(".f3d") and 5_000 < s < 400_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".3mf") and 5_000 < s < 400_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".catpart") and 5_000 < s < 500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".catproduct") and 5_000 < s < 500_000, 1)

    # 8. Neutral CAD & vector/mesh/drawing formats
    neutral_specs = [
        (".step", 2),
        (".stp", 2),
        (".sat", 2),
        (".igs", 2),
        (".x_b", 1),
        (".x_t", 1),
        (".stl", 2),
        (".obj", 1),
        (".wrl", 2),
        (".dxf", 2),
        (".svg", 2),
        (".jt", 1),
        (".ps", 1),
        (".eps", 1),
        (".unv", 1),
        (".brep", 1),
        (".off", 1),
        (".scad", 1),
        (".odg", 1),
    ]
    for ext, lim in neutral_specs:
        pick_first(lambda p, s, e=ext: p.lower().endswith(e) and 200 < s < 450_000, lim)

    # 9. Additional PDFs (web / github / catalog) + raster images
    pick_first(lambda p, s: p.startswith("sources/web/") and p.lower().endswith(".pdf") and 10_000 < s < 600_000, 2)
    pick_first(lambda p, s: p.startswith("sources/github/") and p.lower().endswith(".pdf") and 10_000 < s < 600_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".png") and 2_000 < s < 400_000, 2)
    pick_first(lambda p, s: p.lower().endswith(".jpg") and 2_000 < s < 400_000, 1)

    # 10. Archives (.zip, .tar.gz, .7z, .Z)
    pick_first(lambda p, s: p == "archives/2002Bishwajeet__stepmaker.zip", 1)
    pick_first(lambda p, s: p.lower().endswith(".zip") and 5_000 < s < 1_500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".tar.gz") and 1_000 < s < 500_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".7z") and 5_000 < s < 800_000, 1)
    pick_first(lambda p, s: p.lower().endswith(".z") and 5_000 < s < 400_000, 1)

    # 11. Empty (0-byte) source defect files
    pick_first(lambda p, s: s == 0, 2)

    return list(selected.values())


def main() -> int:
    print(f"Fetching manifest from {MANIFEST_URL}...")
    manifest_text = fetch_bytes(MANIFEST_URL).decode("utf-8", errors="replace")
    rows: list[tuple[str, int, str, str]] = []
    for line in manifest_text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append((parts[0], int(parts[1]), parts[2], parts[3]))

    sample = select_sample(rows)
    total_bytes = sum(r[1] for r in sample)
    print(f"Selected {len(sample)} files ({total_bytes / 1e6:.2f} MB) into {DEST}")
    DEST.mkdir(parents=True, exist_ok=True)

    def download_one(row: tuple[str, int, str, str]) -> tuple[str, int]:
        rel_path, size, _, url_path = row
        out_path = DEST / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists() and out_path.stat().st_size == size:
            return rel_path, size
        if size == 0:
            out_path.write_bytes(b"")
            return rel_path, 0
        data = fetch_bytes(f"{BASE}/{url_path.lstrip('/')}")
        out_path.write_bytes(data)
        return rel_path, len(data)

    done = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(download_one, row) for row in sample]
        for fut in as_completed(futs):
            rel, n = fut.result()
            done += 1
            if done % 15 == 0 or done == len(sample):
                print(f"  [{done}/{len(sample)}] latest: {rel} ({n} B)")

    print("Stratified sample ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
