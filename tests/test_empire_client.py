"""Tests for EmpireClient"""

from unittest.mock import patch, MagicMock


from raven.tools.empire_client import EmpireClient, EmpireResult


CONFIG = {"empire_url": "http://localhost:1337", "empire_ssl_verify": True}


def _make_client(**overrides) -> EmpireClient:
    return EmpireClient({**CONFIG, **overrides})


def _mock_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = str(body)
    return resp


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_authenticate_success():
    client = _make_client()
    token_resp = _mock_response(200, {"token": "abc123"})
    with patch.object(client._session, "post", return_value=token_resp):
        assert client.authenticate("admin", "password") is True
    assert client.token == "abc123"
    assert client._session.headers["Authorization"] == "Bearer abc123"


def test_authenticate_failure_bad_credentials():
    client = _make_client()
    with patch.object(client._session, "post", return_value=_mock_response(401, {})):
        assert client.authenticate("admin", "wrong") is False
    assert client.token is None


def test_authenticate_failure_connection_error():
    client = _make_client()
    with patch.object(client._session, "post", side_effect=ConnectionError("refused")):
        assert client.authenticate("admin", "pass") is False


# ---------------------------------------------------------------------------
# Agent listing
# ---------------------------------------------------------------------------


def test_list_agents_returns_records():
    client = _make_client()
    agents = [{"name": "AGENT1", "os": "linux"}]
    with patch.object(
        client._session, "get", return_value=_mock_response(200, {"records": agents})
    ):
        result = client.list_agents()
    assert result == agents


def test_list_agents_returns_empty_on_error():
    client = _make_client()
    with patch.object(client._session, "get", side_effect=ConnectionError()):
        result = client.list_agents()
    assert result == []


# ---------------------------------------------------------------------------
# execute_module
# ---------------------------------------------------------------------------


def test_execute_module_success():
    client = _make_client()
    resp = _mock_response(201, {"output": "Administrator"})
    with patch.object(client._session, "post", return_value=resp):
        result = client.execute_module(
            "AGENT1", "powershell/situational_awareness/host/winenum"
        )
    assert isinstance(result, EmpireResult)
    assert result.success is True
    assert result.output == "Administrator"
    assert result.operation == "execute_module"


def test_execute_module_failure_non_201():
    client = _make_client()
    resp = _mock_response(404, {})
    with patch.object(client._session, "post", return_value=resp):
        result = client.execute_module("AGENT1", "bad/module")
    assert result.success is False


def test_execute_module_connection_error():
    client = _make_client()
    with patch.object(client._session, "post", side_effect=ConnectionError("refused")):
        result = client.execute_module("AGENT1", "some/module")
    assert result.success is False
    assert "refused" in result.output


# ---------------------------------------------------------------------------
# run_shell
# ---------------------------------------------------------------------------


def test_run_shell_success():
    client = _make_client()
    resp = _mock_response(201, {"output": "root"})
    with patch.object(client._session, "post", return_value=resp):
        result = client.run_shell("AGENT1", "whoami")
    assert result.success is True
    assert result.operation == "shell"


# ---------------------------------------------------------------------------
# SSL verification config
# ---------------------------------------------------------------------------


def test_ssl_verify_default_true():
    client = _make_client()
    assert client._session.verify is True


def test_ssl_verify_can_be_disabled():
    client = _make_client(empire_ssl_verify=False)
    assert client._session.verify is False
