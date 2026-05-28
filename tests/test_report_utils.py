import json

from report_utils import write_html_report, write_json_report


def test_write_json_report_creates_file(tmp_path):
    out = tmp_path / "reports" / "run.json"
    payload = {"tool": "lockbit-rescue", "ok": 1}

    write_json_report(out, payload)

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "lockbit-rescue"
    assert data["ok"] == 1


def test_write_html_report_creates_summary(tmp_path):
    out = tmp_path / "reports" / "run.html"
    payload = {
        "generated_at": "2026-05-28T00:00:00+00:00",
        "scan": {"scanned": 10, "matched": 8, "groups": 2},
        "plan": {
            "targets_to_attempt": 3,
            "groups": [
                {
                    "kek": "abc123",
                    "files": 4,
                    "phase1_targets": 2,
                    "phase2_candidates": 1,
                    "oracle_fei_len": 140,
                    "coverage_bytes": 76,
                    "status": "phase1",
                }
            ],
        },
        "phase1": {"ok": 1, "review": 0},
        "phase2": {"totals": {"ok": 0, "review": 1}},
        "metrics": {
            "recovery_rate_percent": 75.0,
            "bytes_recovered": 750,
            "files_fully_recovered_percent": 50.0,
            "avg_confidence_score": 72.5,
        },
    }

    write_html_report(out, payload)

    html = out.read_text(encoding="utf-8")
    assert "LockBit Rescue Report" in html
    assert "abc123" in html
    assert "Recovery rate" in html
    assert "75.0%" in html
