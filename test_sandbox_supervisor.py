# -*- coding: utf-8 -*-
import os
import threading
import time

import pytest

from sandbox.supervisor import SandboxSupervisor


def _crash_worker(connection, request):
    os._exit(23)


@pytest.mark.unit
@pytest.mark.sandbox
def test_supervisor_times_out_and_recovers():
    supervisor = SandboxSupervisor()

    assert supervisor.run("1 + 2", timeout=60).endswith("=> 3")
    timed_out = supervisor.run("while (true) {}", timeout=0.2)
    assert "RunTimeout" in timed_out
    assert "'status': 'timed_out'" in timed_out
    assert supervisor.status()["last_exit"] == "timed_out"

    assert supervisor.run("6 * 7", timeout=60).endswith("=> 42")
    status = supervisor.status()
    assert status["generation"] == 3
    assert status["active_run"] is None
    assert status["last_exit"] == "completed"


@pytest.mark.unit
@pytest.mark.sandbox
def test_supervisor_reports_worker_crash():
    supervisor = SandboxSupervisor(worker_target=_crash_worker)

    result = supervisor.run("unused", timeout=60)

    assert "WorkerCrashed" in result
    assert "'exit_code': 23" in result
    assert supervisor.status()["last_exit"] == "worker_crashed"


@pytest.mark.unit
@pytest.mark.sandbox
def test_supervisor_rejects_session_mutation_during_run():
    supervisor = SandboxSupervisor()
    result = []
    thread = threading.Thread(
        target=lambda: result.append(supervisor.run("while (true) {}", timeout=0.5)),
    )
    thread.start()

    deadline = time.monotonic() + 5
    while supervisor.status()["active_run"] is None and time.monotonic() < deadline:
        time.sleep(0.01)

    with pytest.raises(RuntimeError, match="replace IDA session"):
        with supervisor.session_mutation():
            pass

    thread.join(timeout=5)
    assert result and "RunTimeout" in result[0]


@pytest.mark.unit
@pytest.mark.sandbox
def test_status_does_not_block_during_active_run():
    supervisor = SandboxSupervisor()
    result = []
    thread = threading.Thread(
        target=lambda: result.append(supervisor.run("while (true) {}", timeout=0.5)),
    )
    thread.start()

    deadline = time.monotonic() + 5
    while supervisor.status()["active_run"] is None and time.monotonic() < deadline:
        time.sleep(0.01)

    started = time.monotonic()
    status = supervisor.status()
    elapsed = time.monotonic() - started

    thread.join(timeout=5)
    assert status["active_run"] is not None
    assert elapsed < 0.1
    assert result and "RunTimeout" in result[0]


# ---- 结构化结果（run_ex）与协议版本容错 ----

def _error_worker(connection, request):
    from sandbox.worker import PROTOCOL_VERSION

    connection.send({
        "version": PROTOCOL_VERSION,
        "kind": "result",
        "run_id": request["run_id"],
        "generation": request["generation"],
        "ok": False,
        "error_type": "ValueError",
        "message": "boom",
        "traceback": "Traceback (most recent call last):\n  File \"x.py\", line 1\nValueError: boom",
    })
    connection.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_run_ex_success_is_structured():
    supervisor = SandboxSupervisor(session_id_provider=lambda: "sess-1")

    out = supervisor.run_ex("1 + 2", timeout=60)

    assert out["ok"] is True
    assert out["error"] is None
    assert out["result"].endswith("=> 3")
    assert out["text"] == out["result"]
    assert out["phase"] == "completed"
    assert out["session_id"] == "sess-1"
    assert out["generation"] == 1
    assert out["timeout_s"] == 60.0
    # 默认文本契约不变：run() 与 run_ex()["text"] 一致
    assert supervisor.run("1 + 2", timeout=60).endswith("=> 3")


@pytest.mark.unit
@pytest.mark.sandbox
def test_run_ex_timeout_is_structured_with_phase():
    supervisor = SandboxSupervisor(session_id_provider=lambda: "sess-2")

    out = supervisor.run_ex("while (true) {}", timeout=0.2)

    assert out["ok"] is False
    assert out["result"] is None
    assert out["error"]["error_type"] == "RunTimeout"
    assert out["error"]["status"] == "timed_out"
    assert out["error"]["recoverable"] is True
    assert out["error"]["phase"] == "executing"  # 无宿主调用挂起时停在 worker 执行阶段
    assert out["error"]["session_id"] == "sess-2"
    assert out["phase"] == "executing"
    assert "RunTimeout" in out["text"]


@pytest.mark.unit
@pytest.mark.sandbox
def test_run_ex_preserves_worker_traceback():
    supervisor = SandboxSupervisor(worker_target=_error_worker)

    out = supervisor.run_ex("unused", timeout=60)

    assert out["ok"] is False
    assert out["error"]["error_type"] == "ValueError"
    assert out["error"]["phase"] == "worker_error"
    assert "ValueError: boom" in out["traceback"]
    # traceback 只在结构化字段里，legacy 文本保持精简
    assert "Traceback" not in out["text"]
    assert supervisor.status()["last_exit"] == "worker_error"


@pytest.mark.unit
@pytest.mark.sandbox
def test_error_payload_omits_none_optional_fields():
    payload = SandboxSupervisor._error_payload(
        "RunTimeout", "m", "timed_out", phase="awaiting_host_call",
        host_call_abandoned=True, session_id=None)

    assert payload["phase"] == "awaiting_host_call"
    assert payload["host_call_abandoned"] is True
    assert "session_id" not in payload


@pytest.mark.unit
@pytest.mark.sandbox
def test_message_matches_accepts_supported_protocol_versions():
    from sandbox.worker import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS

    base = {"run_id": "r1", "generation": 7, "kind": "result"}
    assert PROTOCOL_VERSION in SUPPORTED_PROTOCOL_VERSIONS
    for version in SUPPORTED_PROTOCOL_VERSIONS:
        assert SandboxSupervisor._message_matches({**base, "version": version}, "r1", 7)
    assert not SandboxSupervisor._message_matches({**base, "version": 0}, "r1", 7)
    assert not SandboxSupervisor._message_matches({**base, "version": 9999}, "r1", 7)
    assert not SandboxSupervisor._message_matches({**base, "version": None}, "r1", 7)
    assert not SandboxSupervisor._message_matches(
        {**base, "version": PROTOCOL_VERSION}, "other", 7)
    assert not SandboxSupervisor._message_matches(
        {**base, "version": PROTOCOL_VERSION}, "r1", 8)


# ---- warm worker（跨 run_js 保活）----

def _stateful_warm_worker(connection, request):
    """最小 warm worker：用进程内 Python 计数器证明跨轮状态确实存活。"""
    from sandbox.worker import _next_request, _send_error, _send_result

    counter = {"n": 0}
    warm = bool(request.get("warm"))
    try:
        while request is not None:
            try:
                counter["n"] += 1
                _send_result(connection, request, f"=> {counter['n']}")
            except BaseException as exc:  # noqa: BLE001
                _send_error(connection, request, exc)
            if not warm:
                break
            request = _next_request(connection)
    finally:
        connection.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_warm_worker_preserves_process_state_across_runs():
    supervisor = SandboxSupervisor(warm=True, worker_target=_stateful_warm_worker)
    try:
        first = supervisor.run_ex("unused", timeout=60)
        second = supervisor.run_ex("unused", timeout=60)

        assert first["result"].endswith("=> 1")
        assert second["result"].endswith("=> 2")  # 同一进程内的计数器继续累加
        assert supervisor.status()["worker"]["runs"] == 2
    finally:
        supervisor.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_warm_worker_reuses_real_worker_process():
    supervisor = SandboxSupervisor(warm=True, session_id_provider=lambda: "s-warm")
    try:
        first = supervisor.run_ex("1 + 1", timeout=120)
        assert first["ok"] is True
        pid = supervisor.status()["worker"]["pid"]
        assert pid is not None

        second = supervisor.run_ex("2 + 2", timeout=120)
        assert second["ok"] is True
        assert second["generation"] == first["generation"] + 1
        assert supervisor.status()["worker"]["pid"] == pid  # 进程被复用
        assert supervisor.status()["worker"]["runs"] == 2
        assert supervisor.status()["worker"]["warm"] is True
    finally:
        supervisor.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_warm_worker_timeout_forces_respawn():
    supervisor = SandboxSupervisor(warm=True)
    try:
        supervisor.run_ex("1", timeout=120)
        pid = supervisor.status()["worker"]["pid"]

        timed_out = supervisor.run_ex("while (true) {}", timeout=0.3)

        assert timed_out["ok"] is False
        assert timed_out["error"]["error_type"] == "RunTimeout"
        assert supervisor.status()["worker"]["pid"] is None  # 超时后丢弃保活进程

        assert supervisor.run_ex("3", timeout=120)["ok"] is True
        assert supervisor.status()["worker"]["pid"] not in (None, pid)
    finally:
        supervisor.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_session_mutation_retires_warm_worker():
    supervisor = SandboxSupervisor(warm=True)
    try:
        supervisor.run_ex("1", timeout=120)
        assert supervisor.status()["worker"]["alive"] is True

        with supervisor.session_mutation():
            pass

        assert supervisor.status()["worker"]["alive"] is False
        assert supervisor.status()["worker"]["pid"] is None
    finally:
        supervisor.close()


@pytest.mark.unit
@pytest.mark.sandbox
def test_one_shot_mode_releases_worker_after_run():
    supervisor = SandboxSupervisor(warm=False)

    out = supervisor.run_ex("1", timeout=120)

    assert out["ok"] is True
    assert supervisor.status()["worker"]["warm"] is False
    assert supervisor.status()["worker"]["pid"] is None
