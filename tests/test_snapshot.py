from pathlib import Path

from backend.snapshot import create_snapshot, restore_snapshot


def test_snapshot_round_trip(tmp_path: Path):
    ufw = tmp_path / "ufw"
    data = tmp_path / "data"
    ufw.mkdir()
    (ufw / "user.rules").write_text("BEFORE\n", encoding="utf-8")
    (ufw / "subdir").mkdir()
    (ufw / "subdir" / "x").write_text("nested\n", encoding="utf-8")

    snap = create_snapshot(ufw, data)
    assert snap.is_dir()
    assert (snap / "user.rules").read_text(encoding="utf-8") == "BEFORE\n"

    (ufw / "user.rules").write_text("AFTER\n", encoding="utf-8")
    restore_snapshot(snap, ufw)
    assert (ufw / "user.rules").read_text(encoding="utf-8") == "BEFORE\n"
    assert (ufw / "subdir" / "x").read_text(encoding="utf-8") == "nested\n"
