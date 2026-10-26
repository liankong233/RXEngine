# test_lab_board.py
# -*- coding: utf-8 -*-
import pytest

from extensions.lab_board import AnalysisBoard, LabBoardOverflow


@pytest.mark.unit
def test_board_roundtrip_and_attach():
    board = AnalysisBoard(session_id="s1")
    t = board.add_target(kind="func", ea=0x1000, name="main",
                         start_ea=0x1000, end_ea=0x1100, size=0x100)
    f = board.add_finding("opaque_predicate", 0x1010, "always true",
                          evidence={"x": 1}, target_id=t["id"])
    assert f["id"].startswith("finding-")
    assert board.get("finding", f["id"])["kind"] == "opaque_predicate"
    assert board.list("finding", target_id=t["id"])[0]["id"] == f["id"]
    board.attach("finding", f["id"], evidence_id="trace-00001")
    assert board.get("finding", f["id"])["evidence_id"] == "trace-00001"
    assert board.summary()["counts"]["finding"] == 1


@pytest.mark.unit
def test_board_where_filter_and_missing():
    board = AnalysisBoard(session_id="s1")
    board.add_finding("opaque_predicate", 0x1, "a")
    board.add_finding("constant_fold", 0x2, "b")
    only = board.list("finding", where={"kind": "constant_fold"})
    assert [i["ea"] for i in only] == [0x2]
    with pytest.raises(Exception):
        board.get("finding", "finding-99999")


@pytest.mark.unit
def test_board_entity_limit_overflow():
    board = AnalysisBoard(session_id="s2", limits={"entities": 3})
    for i in range(3):
        board.add_finding("k", i, "x")
    with pytest.raises(LabBoardOverflow):
        board.add_finding("k", 9, "y")
    assert board.summary()["overflow"] is True
    board.clear("finding")
    assert board.counts()["finding"] == 0


@pytest.mark.unit
def test_board_total_cap_across_kinds():
    """SPEC 总量语义：1 target + limit-1 个 finding 恰好填满黑板总数，
    下一个 finding（第二个 kind）触发 overflow——旧的单 kind 上限在此不会触发
    （finding 数量 2 < limit 3），证明 cap 按"全部 kind 总数"生效。"""
    board = AnalysisBoard(session_id="s10", limits={"entities": 3})
    board.add_target(kind="func", ea=0x1000, name="main",
                     start_ea=0x1000, end_ea=0x1100, size=0x100)
    board.add_finding("k", 0x1, "a")
    board.add_finding("k", 0x2, "b")
    summary = board.summary()
    assert summary["overflow"] is False
    assert summary["counts"]["target"] == 1 and summary["counts"]["finding"] == 2
    with pytest.raises(LabBoardOverflow):
        board.add_finding("k", 0x3, "c")
    assert board.summary()["overflow"] is True
    # 全量 clear() 必须复位 overflow，黑板恢复可写
    board.clear()
    assert board.summary()["overflow"] is False
    board.add_finding("k", 0x4, "d")
    assert board.summary()["overflow"] is False


@pytest.mark.unit
def test_board_clear_single_kind_recomputes_overflow():
    board = AnalysisBoard(session_id="s13", limits={"entities": 3})
    for i in range(3):
        board.add_finding("k", i, "x")
    with pytest.raises(LabBoardOverflow):
        board.add_finding("k", 9, "y")
    assert board.summary()["overflow"] is True
    board.clear("finding")
    assert board.counts()["finding"] == 0
    # 只清一个 kind 后 overflow 按剩余总量重算
    assert board.summary()["overflow"] is False


@pytest.mark.unit
def test_board_snapshot_summary_reflects_loaded_count(tmp_path):
    board = AnalysisBoard(session_id="s14")
    board.add_target(kind="func", ea=0x1000, name="main",
                     start_ea=0x1000, end_ea=0x1100, size=0x100)
    board.add_finding("k", 0x10, "hello")
    path = tmp_path / "snap_counts.json"
    board.save_snapshot(str(path))
    other = AnalysisBoard(session_id="s15")
    other.load_snapshot(str(path))
    summary = other.summary()
    assert summary["counts"]["target"] == 1
    assert summary["counts"]["finding"] == 1
    assert summary["overflow"] is False


@pytest.mark.unit
def test_board_snapshot_roundtrip(tmp_path):
    board = AnalysisBoard(session_id="s3")
    board.add_finding("k", 0x10, "hello")
    path = tmp_path / "snap.json"
    board.save_snapshot(str(path))
    other = AnalysisBoard(session_id="s4")
    other.load_snapshot(str(path))
    assert other.counts()["finding"] == 1
    assert other.list("finding")[0]["text"] == "hello"


@pytest.mark.unit
def test_board_load_then_add_does_not_clobber(tmp_path):
    board = AnalysisBoard(session_id="s6")
    board.add_finding("k", 0x1, "first")
    path = tmp_path / "snap.json"
    board.save_snapshot(str(path))
    other = AnalysisBoard(session_id="s7")
    other.load_snapshot(str(path))
    second = other.add_finding("k", 0x2, "second")
    items = other.list("finding")
    assert len(items) == 2
    assert len({i["id"] for i in items}) == 2
    first = other.get("finding", "finding-00001")
    assert first["text"] == "first"
    assert second["id"] != first["id"]


@pytest.mark.unit
def test_board_load_snapshot_advances_seq_past_max_id(tmp_path):
    board = AnalysisBoard(session_id="s8")
    board.add_finding("k", 0x1, "a")
    keep = board.add_finding("k", 0x2, "b")
    board.delete("finding", "finding-00001")
    path = tmp_path / "gap.json"
    board.save_snapshot(str(path))
    assert keep["id"] == "finding-00002"
    other = AnalysisBoard(session_id="s9")
    other.load_snapshot(str(path))
    added = other.add_finding("k", 0x3, "c")
    assert added["id"] == "finding-00003"
    assert other.counts()["finding"] == 2
    assert other.get("finding", "finding-00002")["text"] == "b"


@pytest.mark.unit
def test_board_artifact_writes_file(tmp_path):
    board = AnalysisBoard(session_id="s5", artifact_dir=str(tmp_path))
    out = board.artifact("strings main", "a,b,c")
    assert out["ok"] is True
    assert (tmp_path / out["path"].replace("\\", "/").split("/")[-1]).read_text() == "a,b,c"
