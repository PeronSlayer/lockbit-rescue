from pathlib import Path

from output_layout import collision_safe_path, compute_output_relative, maybe_predict_name


def test_compute_output_relative_preserves_tree(tmp_path):
    source_root = tmp_path / "enc"
    target = source_root / "docs" / "nested" / "report.pdf.ABCDEFGHJ"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x")

    rel = compute_output_relative(str(target), source_root, ".ABCDEFGHJ", "fallback")
    assert rel == Path("docs") / "nested" / "report.pdf"


def test_compute_output_relative_fallback_when_outside_root(tmp_path):
    source_root = tmp_path / "enc"
    source_root.mkdir()
    outside = tmp_path / "outside.bin.ABCDEFGHJ"
    outside.write_bytes(b"x")

    rel = compute_output_relative(str(outside), source_root, ".ABCDEFGHJ", "fallback")
    assert rel == Path("fallback")


def test_maybe_predict_name_for_extensionless_file(tmp_path):
    base = tmp_path / "sample"
    predicted = maybe_predict_name(base, "PNG image data, 320 x 200", enabled=True)
    assert predicted.name == "sample.png"


def test_maybe_predict_name_keeps_existing_suffix(tmp_path):
    base = tmp_path / "sample.txt"
    predicted = maybe_predict_name(base, "PNG image data, 320 x 200", enabled=True)
    assert predicted == base


def test_collision_safe_path_adds_stable_source_hash(tmp_path):
    existing = tmp_path / "report.pdf"
    existing.write_text("old", encoding="utf-8")

    candidate = collision_safe_path(existing, "/encrypted/a/report.pdf.ABCDEFGHJ")

    assert candidate != existing
    assert candidate.suffix == ".pdf"
    assert candidate.name.startswith("report__")
