from sentinel.models.repository import Repository
from sentinel.repositories.repository_repository import RepositoryRepository


def test_get_all_repositories(
    db_session,
):

    repository1 = Repository(
        application_id=1,
        name="backend",
        local_path="/tmp/backend",
        language="python",
    )

    repository2 = Repository(
        application_id=1,
        name="frontend",
        local_path="/tmp/frontend",
        language="javascript",
    )

    db_session.add_all(
        [
            repository1,
            repository2,
        ],
    )

    db_session.commit()

    repository_repository = RepositoryRepository(
        db_session,
    )

    repositories = repository_repository.get_all()

    assert len(repositories) == 2
    assert repositories[0].name == "backend"
    assert repositories[1].name == "frontend"
