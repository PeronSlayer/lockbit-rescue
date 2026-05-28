import csv
import json

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
    assert rows[0]["confidence_score"] == "95"
    assert rows[0]["phase_attempted"] == ""


def test_manifest_exports_json_and_source_status(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    m = Manifest(out)

    m.add(
        "group_abc",
        "photo.jpg",
        "jpg",
        "/enc/photo.jpg.ABCDEFGHJ",
        "/out/photo.jpg",
        "OK",
        "JPEG image data",
        200,
        130,
    )

    assert m.has_source_status("/enc/photo.jpg.ABCDEFGHJ") is True
    exported = m.export_json()
    data = json.loads(exported.read_text(encoding="utf-8"))

    assert data["totals"]["OK"] == 1
    assert data["rows"][0]["encrypted_source_path"] == "/enc/photo.jpg.ABCDEFGHJ"
    assert data["metrics"]["files_ok"] == 1
    assert data["metrics"]["bytes_total"] == 200


def test_manifest_migrates_older_csv_header(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    legacy = out / "manifest.csv"
    legacy.write_text(
        "group_kek,original_basename,original_extension,encrypted_source_path,"
        "recovered_output_path,status,file_type_magic,file_size_bytes,fei_len,timestamp\n"
        "abc,report.pdf,pdf,/enc/report.pdf.ABCDEFGHJ,/out/report.pdf,OK,PDF document,100,120,now\n",
        encoding="utf-8",
    )

    Manifest(out)

    with legacy.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert "status_reason" in reader.fieldnames
    assert "recovery_rate_percent" in reader.fieldnames
    assert "confidence_score" in reader.fieldnames
    assert rows[0]["status_reason"] == ""
    assert rows[0]["recovered_bytes"] == ""


def test_manifest_records_recovery_metrics(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    recovered = out / "photo.jpg"
    recovered.write_bytes(b"x" * 75)
    m = Manifest(out, default_phase="phase1")

    m.add(
        "group_abc",
        "photo.jpg",
        "jpg",
        "/enc/photo.jpg.ABCDEFGHJ",
        str(recovered),
        "OK",
        "JPEG image data",
        100,
        130,
    )

    with (out / "manifest.csv").open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["recovered_bytes"] == "75"
    assert rows[0]["recovery_rate_percent"] == "75.00"
    assert rows[0]["phase_attempted"] == "phase1"
    assert rows[0]["is_truncated"] == "true"

    data = json.loads(m.export_json().read_text(encoding="utf-8"))
    assert data["metrics"]["bytes_recovered"] == 75
    assert data["metrics"]["recovery_rate_percent"] == 75.0
