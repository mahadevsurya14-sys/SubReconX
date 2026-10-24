"""Tests for HTTP probing engine."""

from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from subreconx.core.http_prober import HTTPProber


def test_extract_title() -> None:
    html_sample = "<html><head><title>  Security Dashboard  </title></head></html>"
    assert HTTPProber._extract_title(html_sample) == "Security Dashboard"

    multiline = "<html><title>\nWelcome to\nSecure Portal\n</title></html>"
    assert HTTPProber._extract_title(multiline) == "Welcome to Secure Portal"

    no_title = "<html><body>No title here</body></html>"
    assert HTTPProber._extract_title(no_title) is None


@pytest.mark.asyncio
async def test_probe_url_success() -> None:
    prober = HTTPProber(timeout=5.0, rate_limit=50.0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://api.example.com/")
    mock_resp.headers = {"server": "nginx", "content-length": "128"}
    mock_resp.text = "<html><title>API</title></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp

        res = await prober.probe_url("https://api.example.com")
        assert res.hostname == "api.example.com"
        assert res.scheme == "https"
        assert res.status_code == 200
        assert res.page_title == "API"
        assert res.server == "nginx"
        assert res.is_live is True
        assert res.error is None

    await prober.close()


@pytest.mark.asyncio
async def test_probe_url_connection_error() -> None:
    prober = HTTPProber(timeout=2.0)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectError("Connection refused")

        res = await prober.probe_url("http://dead.example.com")
        assert res.hostname == "dead.example.com"
        assert res.status_code is None
        assert res.is_live is False
        assert "ConnectError" in (res.error or "")

    await prober.close()
