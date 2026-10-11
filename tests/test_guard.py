import asyncio
import threading
import time

import pytest

from permission_gate import (ApprovalRejected, ApprovalRequired, ApprovalTimeout, PermissionDenied,
                             PermissionGate, gated_tool)


@pytest.fixture
def gate():
    return PermissionGate()


def test_allow_block_and_args_captured(gate):
    @gated_tool(gate, agent="a1")
    def read_file(path):
        return f"contents of {path}"

    @gated_tool(gate, tool="delete_dir")
    def nuke(path):
        raise AssertionError("must not run")

    assert read_file("x.txt") == "contents of x.txt"
    with pytest.raises(PermissionDenied):
        nuke(path="prod/data")
    assert gate.audit[0].call.args == {"path": "x.txt"} and gate.audit[0].call.agent == "a1"


def test_approval_required_then_single_use_retry(gate):
    ran = []

    @gated_tool(gate)
    def edit_file(path, content="x"):
        ran.append(path)

    with pytest.raises(ApprovalRequired) as ei:
        edit_file("a.py")
    rid = ei.value.request.id
    assert not ran

    with pytest.raises(PermissionDenied):  # not approved yet
        edit_file("a.py", _approval_id=rid)
    gate.resolve(rid, True)
    with pytest.raises(PermissionDenied):  # approval is for a different call
        edit_file("other.py", _approval_id=rid)
    edit_file("a.py", _approval_id=rid)
    assert ran == ["a.py"]
    with pytest.raises(PermissionDenied):  # single use
        edit_file("a.py", _approval_id=rid)
    assert gate.audit[-1].final == "executed" or gate.audit[-2].final == "executed"


def test_wait_approved_rejected_timeout(gate):
    @gated_tool(gate, wait=2)
    def edit_file(path):
        return "done"

    def approve_soon(approve):
        for _ in range(100):
            if gate.pending():
                gate.resolve(gate.pending()[0].id, approve)
                return
            time.sleep(0.02)

    t = threading.Thread(target=approve_soon, args=(True,)); t.start()
    assert edit_file("a.py") == "done"
    t.join()

    t = threading.Thread(target=approve_soon, args=(False,)); t.start()
    with pytest.raises(ApprovalRejected):
        edit_file("b.py")
    t.join()

    @gated_tool(gate, tool="edit_file", wait=0.1)
    def slow(path):
        return "never"

    with pytest.raises(ApprovalTimeout):
        slow("c.py")


def test_async_function(gate):
    @gated_tool(gate)
    async def read_file(path):
        return path

    assert asyncio.run(read_file("a")) == "a"
