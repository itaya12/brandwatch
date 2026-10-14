"""Job model + event feed: queued → running → done with a replayable, monotonic event stream."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from tests.conftest import make_job, make_workspace

from brandwatch.db.enums import JobState
from brandwatch.db.models import ScanEventRecord, ScanJob, ScanStage
from brandwatch.events.emitter import ScanEventEmitter, replay
from brandwatch.jobs.queue import ArqJobQueue, InMemoryJobQueue
from brandwatch.jobs.worker import DEFAULT_HANDLERS
from brandwatch.pipeline.stages import CONTRACTS, PIPELINE_ORDER, STAGES


def test_noop_job_runs_through_states(session):
    ws = make_workspace(session)
    queue = InMemoryJobQueue(session=session, handlers=DEFAULT_HANDLERS)
    job_id = queue.enqueue("noop", {"why": "dod"}, workspace_id=ws.id)

    job = session.get(ScanJob, job_id)
    assert job.state is JobState.DONE
    assert job.started_at is not None and job.finished_at is not None
    assert job.cost_usd == 0
    assert job.payload == {"why": "dod"}

    stages = session.scalars(sa.select(ScanStage).where(ScanStage.job_id == job_id)).all()
    assert [s.name for s in stages] == ["noop"] and stages[0].state is JobState.DONE

    events = replay(session, job_id)
    assert [e.seq for e in events] == list(range(1, len(events) + 1))
    assert len(events) >= 3
    assert events[0].status == "running" and events[-1].status == "done"
    summary = events[-1].data
    assert set(summary) >= {"duration_ms", "hits", "criticals", "api_calls", "cost_usd", "next_run"}
    assert summary["cost_usd"] == 0.0 and summary["api_calls"] == 0


def test_replay_from_seq_supports_reconnect(session):
    ws = make_workspace(session)
    queue = InMemoryJobQueue(session=session, handlers=DEFAULT_HANDLERS)
    job_id = queue.enqueue("noop", workspace_id=ws.id)
    all_events = replay(session, job_id)
    tail = replay(session, job_id, from_seq=all_events[0].seq)
    assert [e.seq for e in tail] == [e.seq for e in all_events[1:]]


def test_emitter_seq_resumes_from_database(session):
    job = make_job(session, make_workspace(session))
    first = ScanEventEmitter(session, job.id)
    first.running("s", "a", "one")
    first.done("s", "b", "two")
    second = ScanEventEmitter(session, job.id)  # e.g. a retried worker on the same job
    ev = second.running("s", "c", "three")
    assert ev.seq == 3
    seqs = session.scalars(
        sa.select(ScanEventRecord.seq).where(ScanEventRecord.job_id == job.id).order_by("seq")
    ).all()
    assert seqs == [1, 2, 3]


def test_emitter_redacts_secrets_and_publishes(session):
    job = make_job(session, make_workspace(session))
    published = []
    em = ScanEventEmitter(session, job.id, secrets=["sk-live-SECRET"], publish=published.append)
    ev = em.error(
        "enrichment",
        "virustotal",
        "call failed with key sk-live-SECRET",
        data={"headers": {"x-apikey": "sk-live-SECRET"}, "nested": ["sk-live-SECRET"]},
    )
    assert "SECRET" not in ev.message and ev.message.endswith("***")
    assert ev.data == {"headers": {"x-apikey": "***"}, "nested": ["***"]}
    assert ev.level == "error" and ev.status == "error"
    assert published == [ev]
    stored = session.scalars(
        sa.select(ScanEventRecord).where(ScanEventRecord.job_id == job.id)
    ).one()
    assert "SECRET" not in stored.message and "SECRET" not in str(stored.data)


def test_handler_exception_marks_job_failed(session):
    ws = make_workspace(session)

    def boom(_s, _job_id):
        raise RuntimeError("kaboom")

    queue = InMemoryJobQueue(session=session, handlers={"boom": boom})
    job_id = queue.enqueue("boom", workspace_id=ws.id)
    job = session.get(ScanJob, job_id)
    assert job.state is JobState.FAILED
    assert "RuntimeError: kaboom" in job.error
    assert job.finished_at is not None


def test_unknown_kind_is_rejected_before_creating_a_row(session):
    ws = make_workspace(session)
    queue = InMemoryJobQueue(session=session, handlers={})
    with pytest.raises(KeyError):
        queue.enqueue("nope", workspace_id=ws.id)
    assert (
        session.scalar(
            sa.select(sa.func.count()).select_from(ScanJob).where(ScanJob.workspace_id == ws.id)
        )
        == 0
    )


def test_queue_requires_exactly_one_session_source():
    with pytest.raises(ValueError):
        InMemoryJobQueue()


def test_arq_queue_requires_redis_url_and_session_factory():
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        ArqJobQueue(None)
    q = ArqJobQueue(
        "redis://localhost:6379/0"
    )  # no session factory → cannot create the durable row
    with pytest.raises(RuntimeError, match="session_factory"):
        q.enqueue("noop", workspace_id=None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------
# Pipeline contracts
# --------------------------------------------------------------------------------------------
def test_pipeline_contracts_follow_spec_order():
    assert PIPELINE_ORDER == (
        "discovery", "normalize", "deduplicate", "pre_filter", "enrichment",
        "analysis", "scoring", "finding", "investigation",
    )  # fmt: skip
    assert set(STAGES) == set(CONTRACTS)
    for name, contract in CONTRACTS.items():
        assert contract.name == name
        assert STAGES[name].contract is contract


def test_contract_io_types_chain():
    """Each stage's output type is the next stage's input type."""
    order = PIPELINE_ORDER
    for prev, nxt in zip(order, order[1:], strict=False):
        if nxt in ("pre_filter", "enrichment"):  # both consume the DedupResult
            continue
        assert CONTRACTS[prev].output_type is CONTRACTS[nxt].input_type, (prev, nxt)


async def test_stage_stubs_name_their_phase():
    for name, cls in STAGES.items():
        with pytest.raises(NotImplementedError, match="Phase"):
            await cls().run(None, None)  # type: ignore[arg-type]
        assert CONTRACTS[name].failure_behavior


def test_pure_stages_write_no_evidence_and_cost_nothing():
    for name in ("normalize", "scoring"):
        c = CONTRACTS[name]
        assert c.evidence_written == () or name == "scoring"
        assert c.cost.startswith("0")
    assert CONTRACTS["pre_filter"].failure_behavior.startswith("fail-open")
    assert "never clean" in CONTRACTS["enrichment"].failure_behavior
