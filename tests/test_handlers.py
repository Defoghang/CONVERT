import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from handlers import cmd_start, cmd_echo, cmd_help, cmd_stats, cmd_status


@pytest.fixture
def mock_update():
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = 12345
    update.effective_user.username = "testuser"
    update.effective_user.first_name = "Test"
    update.message = AsyncMock()
    update.message.reply_text = AsyncMock()
    return update


@pytest.fixture
def mock_context():
    context = MagicMock()
    context.args = []
    return context


@pytest.mark.asyncio
async def test_cmd_start(mock_update, mock_context):
    with patch("handlers.upsert_user"):
        await cmd_start(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_cmd_echo_no_args(mock_update, mock_context):
    mock_context.args = []
    await cmd_echo(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_with("Usage : /echo <texte>")


@pytest.mark.asyncio
async def test_cmd_echo_with_args(mock_update, mock_context):
    mock_context.args = ["hello", "world"]
    await cmd_echo(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_with("hello world")


@pytest.mark.asyncio
async def test_cmd_help(mock_update, mock_context):
    await cmd_help(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_cmd_stats(mock_update, mock_context):
    with patch("handlers.get_stat", return_value=42):
        await cmd_stats(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_once()


@pytest.mark.asyncio
async def test_cmd_status_non_admin(mock_update, mock_context):
    with patch("handlers.ADMIN_IDS", set()):
        await cmd_status(mock_update, mock_context)
    mock_update.message.reply_text.assert_awaited_with("Accès refusé.")
