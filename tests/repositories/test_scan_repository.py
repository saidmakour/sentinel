from datetime import UTC
from datetime import datetime

from sentinel.enums.scan_status import ScanStatus
from sentinel.models.scan import Scan
from sentinel.repositories.scan_repository import ScanRepository


def test_create_scan(db_session):
    scan = Scan(
        repository_id=1,
        started_at=datetime.now(UTC),
        status=ScanStatus.STARTED,
    )

    repo = ScanRepository(db_session)

    created = repo.create(scan)

    assert created.id is not None
    assert created.repository_id == 1
    assert created.status == ScanStatus.STARTED


def test_get_scan_by_id_returns_scan(db_session):
    scan = Scan(
        repository_id=1,
        started_at=datetime.now(UTC),
        status=ScanStatus.STARTED,
    )

    repo = ScanRepository(db_session)

    created = repo.create(scan)

    loaded = repo.get_by_id(created.id)

    assert loaded is not None
    assert loaded.id == created.id
    assert loaded.repository_id == 1


def test_get_scan_by_id_returns_none_when_not_found(db_session):
    repo = ScanRepository(db_session)

    result = repo.get_by_id(999999)

    assert result is None


def test_list_by_repository_returns_scans(db_session):
    repo = ScanRepository(db_session)

    repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.FAILED,
        )
    )

    scans = repo.list_by_repository(10)

    assert len(scans) == 2


def test_list_by_repository_does_not_return_other_repositories(
    db_session,
):
    repo = ScanRepository(db_session)

    repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    repo.create(
        Scan(
            repository_id=20,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    scans = repo.list_by_repository(10)

    assert len(scans) == 1
    assert scans[0].repository_id == 10


def test_list_by_repository_orders_latest_first(db_session):
    repo = ScanRepository(db_session)

    oldest = repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    newest = repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 3, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    middle = repo.create(
        Scan(
            repository_id=10,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    scans = repo.list_by_repository(10)

    assert [scan.id for scan in scans] == [
        newest.id,
        middle.id,
        oldest.id,
    ]


def test_latest_by_repository_returns_latest_scan(db_session):
    repo = ScanRepository(db_session)

    repo.create(
        Scan(
            repository_id=20,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    latest_scan = repo.create(
        Scan(
            repository_id=20,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.FAILED,
        )
    )

    latest = repo.latest_by_repository(20)

    assert latest is not None
    assert latest.id == latest_scan.id
    assert latest.status == ScanStatus.FAILED


def test_latest_by_repository_returns_none_when_no_scan(
    db_session,
):
    repo = ScanRepository(db_session)

    result = repo.latest_by_repository(999999)

    assert result is None


def test_get_all_returns_all_scans(db_session):
    repo = ScanRepository(db_session)

    repo.create(
        Scan(
            repository_id=1,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    repo.create(
        Scan(
            repository_id=2,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.FAILED,
        )
    )

    scans = repo.get_all()

    assert len(scans) == 2


def test_get_all_orders_latest_first(db_session):
    repo = ScanRepository(db_session)

    oldest = repo.create(
        Scan(
            repository_id=1,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    newest = repo.create(
        Scan(
            repository_id=2,
            started_at=datetime(2026, 1, 3, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    middle = repo.create(
        Scan(
            repository_id=3,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            status=ScanStatus.SUCCESS,
        )
    )

    scans = repo.get_all()

    assert [scan.id for scan in scans] == [
        newest.id,
        middle.id,
        oldest.id,
    ]


def test_get_previous_scan_returns_immediately_previous_scan(
    db_session,
):
    repository_id = 1

    old_scan = Scan(
        repository_id=repository_id,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=ScanStatus.SUCCESS,
    )

    previous_scan = Scan(
        repository_id=repository_id,
        started_at=datetime(2026, 2, 1, tzinfo=UTC),
        status=ScanStatus.SUCCESS,
    )

    current_scan = Scan(
        repository_id=repository_id,
        started_at=datetime(2026, 3, 1, tzinfo=UTC),
        status=ScanStatus.STARTED,
    )

    db_session.add_all(
        [
            old_scan,
            previous_scan,
            current_scan,
        ]
    )
    db_session.flush()

    result = ScanRepository(db_session).get_previous_scan(
        current_scan,
    )

    assert result is not None
    assert result.id == previous_scan.id


def test_get_previous_scan_returns_none_for_first_scan(
    db_session,
):
    first_scan = Scan(
        repository_id=1,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=ScanStatus.SUCCESS,
    )

    db_session.add(first_scan)
    db_session.flush()

    result = ScanRepository(db_session).get_previous_scan(
        first_scan,
    )

    assert result is None


def test_get_previous_scan_ignores_other_repositories(
    db_session,
):
    repository_id = 1

    previous_scan = Scan(
        repository_id=repository_id,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=ScanStatus.SUCCESS,
    )

    other_repository_scan = Scan(
        repository_id=2,
        started_at=datetime(2026, 2, 1, tzinfo=UTC),
        status=ScanStatus.SUCCESS,
    )

    current_scan = Scan(
        repository_id=repository_id,
        started_at=datetime(2026, 3, 1, tzinfo=UTC),
        status=ScanStatus.STARTED,
    )

    db_session.add_all(
        [
            previous_scan,
            other_repository_scan,
            current_scan,
        ]
    )
    db_session.flush()

    result = ScanRepository(db_session).get_previous_scan(
        current_scan,
    )

    assert result is not None
    assert result.id == previous_scan.id
