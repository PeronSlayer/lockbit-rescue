import json

from report_utils import write_json_report


def test_write_json_report_creates_file(tmp_path):
    out = tmp_path / "reports" / "run.json"
    payload = {"tool": "lockbit-rescue", "ok": 1}

    write_json_report(out, payload)

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "lockbit-rescue"
    assert data["ok"] == 1
