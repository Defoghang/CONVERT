import os
import tempfile
import pytest
from unittest.mock import patch


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.mark.asyncio
async def test_database_init_and_operations(temp_db):
    with patch("database.DATABASE_PATH", temp_db):
        import database
        database.DATABASE_PATH = temp_db
        database.init_db()
        database.upsert_user(1, "user1", "First")
        database.upsert_user(1, "user1_updated", "First")
        user = database.get_user(1)
        assert user is not None
        assert user["username"] == "user1_updated"
        database.increment_stat("messages_processed")
        assert database.get_stat("messages_processed") == 1
