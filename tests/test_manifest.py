import csv

from manifest import Manifest


def test_manifest_deduplicates_rows(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    m = Manifest(out)

    first = m.add(
        "group_abc",
        "report",
        ".pdf",
        "/enc/report.pdf.ABCDEFGHJ",
        "/out/report.pdf",
        "OK",
        "PDF document",
        100,
        120,
    )
    second = m.add(
        "group_abc",
        "report",
        ".pdf",
        "/enc/report.pdf.ABCDEFGHJ",
        "/out/report.pdf",
        "OK",
        "PDF document",
        100,
        120,
    )

    assert first is True
    assert second is False

    with (out / "manifest.csv").open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["group_kek"] == "group_abc"
