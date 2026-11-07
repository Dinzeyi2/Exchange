import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from node.identity.crypto import digest


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "records"
    key = Column(String, primary_key=True)
    kind = Column(String, nullable=False, index=True)
    data = Column(JSON, nullable=False)


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    seq = Column(Integer, primary_key=True, autoincrement=False)
    ts = Column(String, nullable=False)
    direction = Column(String, nullable=False)
    peer = Column(String, nullable=False)
    type = Column(String, nullable=False)
    body = Column(JSON, nullable=False)
    prev_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)


class Store:
    def __init__(self, url):
        self.engine = create_engine(
            url,
            connect_args={"check_same_thread": False}
            if url.startswith("sqlite")
            else {},
        )
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        self.lock = threading.RLock()
        if self.engine.dialect.name == "sqlite":
            with self.engine.begin() as c:
                c.exec_driver_sql(
                    "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_entries BEGIN SELECT RAISE(ABORT, 'append only'); END"
                )
                c.exec_driver_sql(
                    "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_entries BEGIN SELECT RAISE(ABORT, 'append only'); END"
                )

    @contextmanager
    def transaction(self):
        with self.lock, self.sessions.begin() as s:
            if self.engine.dialect.name == "postgresql":
                # Serializes reference-node state transitions and the audit chain across workers.
                from sqlalchemy import text

                s.execute(text("SELECT pg_advisory_xact_lock(34017001)"))
            elif self.engine.dialect.name == "sqlite":
                s.connection().exec_driver_sql("BEGIN IMMEDIATE")
            yield s

    def get(self, s, key):
        record = s.get(Record, key)
        return record.data.copy() if record else None

    def put(self, s, key, kind, data):
        record = s.get(Record, key)
        if record:
            record.data = data.copy()
        else:
            s.add(Record(key=key, kind=kind, data=data.copy()))
        s.flush()

    def list(self, s, kind):
        return [
            r.data.copy()
            for r in s.scalars(
                select(Record).where(Record.kind == kind).order_by(Record.key)
            )
        ]

    def audit(self, s, type, body, direction="local", peer="local"):
        last = s.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
        entry = dict(
            seq=last.seq + 1 if last else 1,
            ts=now(),
            direction=direction,
            peer=peer,
            type=type,
            body=body,
            prev_hash=last.hash if last else "0" * 64,
        )
        entry["hash"] = digest(entry)
        s.add(AuditEntry(**entry))
        s.flush()
        return entry

    def audit_rows(self, s):
        return [
            {
                k: getattr(r, k)
                for k in [
                    "seq",
                    "ts",
                    "direction",
                    "peer",
                    "type",
                    "body",
                    "prev_hash",
                    "hash",
                ]
            }
            for r in s.scalars(select(AuditEntry).order_by(AuditEntry.seq))
        ]

    def verify_audit_chain(self):
        with self.transaction() as s:
            previous = "0" * 64
            for i, row in enumerate(self.audit_rows(s), 1):
                claimed = row.pop("hash")
                if (
                    row["seq"] != i
                    or row["prev_hash"] != previous
                    or digest(row) != claimed
                ):
                    return False
                previous = claimed
        return True
