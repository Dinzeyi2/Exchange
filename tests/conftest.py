import pytest

from node.audit.store import Store
from node.signer.backends import SoftwareSigner
from prototype.legacy.seed import sample_terms, seed
from prototype.legacy.workflow import OFFICERS, Workflow


@pytest.fixture
def workflow(tmp_path):
    w = Workflow(
        Store("sqlite:///" + str(tmp_path / "test.db")),
        SoftwareSigner(),
        {id: SoftwareSigner() for id in OFFICERS},
    )
    seed(w)
    return w


@pytest.fixture
def trade_id():
    return sample_terms()["trade_id"]


def load(w, id):
    with w.store.transaction() as s:
        return w.load(s, id)


def advance(w, id, target="FUNDING_SENT"):
    for _ in range(40):
        t = load(w, id)
        if t["state"] == target:
            return t
        task = next(x for x in t["tasks"] if x["status"] == "pending")
        officer = next(id for id in OFFICERS if w.can_approve(task, id))
        w.decide(id, task["task_id"], officer, "approve")
    raise AssertionError("workflow stalled")
