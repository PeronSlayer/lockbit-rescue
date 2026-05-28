import json
import os
import subprocess
import sys


def test_cli_plan_only_report_generation(tmp_path):
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    out.mkdir()

    report_rescue = tmp_path / "rescue-report.json"
    report_extend = tmp_path / "extend-report.json"

    p1 = subprocess.run(
        [
            sys.executable,
            "lockbit-rescue.py",
            str(src),
            str(out),
            "--ext",
            ".ABCDEFGHJ",
            "--plan-only",
            "--report-json",
            str(report_rescue),
        ],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
        timeout=30,
    )
    assert p1.returncode == 0
    assert report_rescue.exists()
    rescue_json = json.loads(report_rescue.read_text(encoding="utf-8"))
    assert rescue_json["tool"] == "lockbit-rescue"
    assert rescue_json["phase1"]["status"] == "plan_only"

    p2 = subprocess.run(
        [
            sys.executable,
            "lockbit-extend.py",
            str(src),
            str(out),
            "--ext",
            ".ABCDEFGHJ",
            "--plan-only",
            "--report-json",
            str(report_extend),
        ],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
        timeout=30,
    )
    assert p2.returncode == 0
    assert report_extend.exists()
    extend_json = json.loads(report_extend.read_text(encoding="utf-8"))
    assert extend_json["tool"] == "lockbit-extend"
    assert extend_json["phase2"]["status"] == "plan_only"
