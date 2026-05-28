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
    report_rescue_html = tmp_path / "rescue-report.html"
    manifest_rescue_json = tmp_path / "manifest.json"
    report_extend = tmp_path / "extend-report.json"
    report_extend_html = tmp_path / "extend-report.html"
    manifest_extend_json = tmp_path / "extend-manifest.json"

    p1 = subprocess.run(
        [
            sys.executable,
            "lockbit-rescue.py",
            str(src),
            str(out),
            "--ext",
            ".ABCDEFGHJ",
            "--profile",
            "safe",
            "--plan-only",
            "--report-json",
            str(report_rescue),
            "--report-html",
            str(report_rescue_html),
            "--manifest-json",
            str(manifest_rescue_json),
        ],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
        timeout=30,
    )
    assert p1.returncode == 0
    assert report_rescue.exists()
    assert report_rescue_html.exists()
    assert manifest_rescue_json.exists()
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
            "--profile",
            "safe",
            "--plan-only",
            "--report-json",
            str(report_extend),
            "--report-html",
            str(report_extend_html),
            "--manifest-json",
            str(manifest_extend_json),
        ],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
        timeout=30,
    )
    assert p2.returncode == 0
    assert report_extend.exists()
    assert report_extend_html.exists()
    assert manifest_extend_json.exists()
    extend_json = json.loads(report_extend.read_text(encoding="utf-8"))
    assert extend_json["tool"] == "lockbit-extend"
    assert extend_json["phase2"]["status"] == "plan_only"
