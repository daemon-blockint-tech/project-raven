"""Tests for WhoisClient adapter."""
import pytest
from unittest.mock import patch, MagicMock


def test_whois_query_cli_fallback(monkeypatch):
    """CLI fallback path returns parsed dict."""
    from raven.tools.adapter_base import ToolResult
    from raven.tools.whois_client import WhoisClient

    mock_result = ToolResult(
        tool="whois",
        success=True,
        target="example.com",
        stdout="domain name: example.com\nregistrar: ICANN\ncreation date: 1995-08-14\n",
        exit_code=0,
    )

    client = WhoisClient()

    # Force ImportError so python-whois module path is skipped
    with patch.dict("sys.modules", {"whois": None}):
        with patch.object(client, "_run", return_value=mock_result) as mock_run:
            result = client.lookup("example.com")

    mock_run.assert_called_once()
    assert result.success is True
    assert result.target == "example.com"
    assert "domain name" in result.parsed or result.parsed is not None


def test_whois_query_alias():
    """query() is an alias returning a dict."""
    from raven.tools.whois_client import WhoisClient
    from raven.tools.adapter_base import ToolResult

    client = WhoisClient()
    fake = ToolResult(tool="whois", success=True, target="x.com", parsed={"registrar": "test"})

    with patch.dict("sys.modules", {"whois": None}):
        with patch.object(client, "_run", return_value=fake):
            out = client.query("x.com")

    assert isinstance(out, dict)
    assert out["success"] is True


def test_whois_parse_raw():
    from raven.tools.whois_client import WhoisClient

    raw = "# comment\ndomain name: test.com\nregistrar: Example Registrar\n% skip\n"
    parsed = WhoisClient._parse_raw(raw)
    assert parsed.get("domain name") == "test.com"
    assert parsed.get("registrar") == "Example Registrar"
    assert "# comment" not in parsed


def test_whois_is_available_with_module():
    """is_available returns True when python-whois importable."""
    from raven.tools.whois_client import WhoisClient
    fake_whois = MagicMock()
    with patch.dict("sys.modules", {"whois": fake_whois}):
        assert WhoisClient().is_available() is True


def test_whois_is_available_cli_fallback():
    """is_available falls back to binary check."""
    from raven.tools.whois_client import WhoisClient
    with patch.dict("sys.modules", {"whois": None}):
        with patch("raven.tools.adapter_base.shutil.which", return_value="/usr/bin/whois"):
            assert WhoisClient().is_available() is True


def test_whois_is_not_available():
    from raven.tools.whois_client import WhoisClient
    with patch.dict("sys.modules", {"whois": None}):
        with patch("raven.tools.adapter_base.shutil.which", return_value=None):
            c = WhoisClient()
            with patch.object(c, "is_available", return_value=False):
                assert c.is_available() is False
