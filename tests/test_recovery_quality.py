import csv
import json
import subprocess
import sys

from recovery_metrics import aggregate_manifest_rows, metric_fields


def test_metric_fields_compute_rate_and_confidence(tmp_path):
    recovered = tmp_path / "recovered.bin"
    recovered.write_bytes(b"x" * 50)

    fields = metric_fields(
        status="REVIEW",
        file_size_bytes=100,
        recovered_output_path=str(recovered),
        phase_attempted="phase2",
        magic_rule_id="pdf:%PDF",
    )

    assert fields["recovered_bytes"] == "50"
    assert fields["recovery_rate_percent"] == "50.00"
    assert fields["confidence_score"] == "50"
    assert fields["phase_attempted"] == "phase2"
    assert fields["magic_rule_id"] == "pdf:%PDF"
    assert fields["is_truncated"] == "true"


def test_aggregate_manifest_rows_by_phase():
    rows = [
        {
            "status": "OK",
            "file_size_bytes": "100",
            "recovered_bytes": "100",
            "phase_attempted": "phase1",
            "confidence_score": "95",
        },
        {
            "status": "REVIEW",
            "file_size_bytes": "100",
            "recovered_bytes": "40",
            "phase_attempted": "phase2",
            "confidence_score": "50",
        },
        {
            "status": "FAIL",
            "file_size_bytes": "100",
            "recovered_bytes": "0",
            "phase_attempted": "phase2",
            "confidence_score": "0",
        },
    ]

    metrics = aggregate_manifest_rows(rows)

    assert metrics["files_total"] == 3
    assert metrics["files_ok"] == 1
    assert metrics["files_review"] == 1
    assert metrics["files_fail"] == 1
    assert metrics["bytes_total"] == 300
    assert metrics["bytes_recovered"] == 140
    assert metrics["recovery_rate_percent"] == 46.67
    assert metrics["files_fully_recovered_percent"] == 33.33
    assert metrics["avg_confidence_score"] == 48.33
    assert metrics["by_phase"]["phase1"]["files_ok"] == 1
    assert metrics["by_phase"]["phase2"]["files_review"] == 1


def test_benchmark_recovery_reads_manifest(tmp_path):
    manifest = tmp_path / "manifest.csv"
    report = tmp_path / "benchmark.json"
    rows = [
        {
            "group_kek": "group_abc",
            "original_basename": "photo.jpg",
            "original_extension": "jpg",
            "encrypted_source_path": "/enc/photo.jpg.ABCDEFGHJ",
            "recovered_output_path": "/out/photo.jpg",
            "status": "OK",
            "file_type_magic": "JPEG image data",
            "status_reason": "",
            "file_size_bytes": "100",
            "fei_len": "130",
            "timestamp": "now",
            "recovered_bytes": "80",
            "recovery_rate_percent": "80.00",
            "phase_attempted": "phase1",
            "confidence_score": "95",
            "magic_rule_id": "",
            "keystream_offset_start": "",
            "keystream_offset_end": "",
            "is_truncated": "true",
        }
    ]
    with manifest.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    result = subprocess.run(
        [sys.executable, "scripts/benchmark_recovery.py", "--manifest", str(manifest), "--report-json", str(report)],
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "recovery_rate_percent: 80.0" in result.stdout
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["metrics"]["bytes_recovered"] == 80
