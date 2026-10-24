"""HTTP/HTTPS probing engine for SubReconX.

Uses httpx to perform GET requests against discovered subdomains,
recording status codes, response times, page titles, server headers,
and other metadata. Implements concurrency limiting via semaphores
and inter-request rate limiting to avoid overwhelming targets.
"""

import asyncio
import logging
import re
import time
from typing import Optional

import httpx

from subreconx.models import HTTPResult

logger = logging.getLogger(__name__)

# Regex to extract <title> content from HTML.  Handles multiline titles
# and common whitespace patterns.  Intentionally simple – no full parser.
_TITLE_RE = re.compile(
    r"<title[^>]*>\s*(.*?)\s*</title>",
    re.IGNORECASE | re.DOTALL,
)

# Maximum number of bytes to read from a response body for title extraction.
# This avoids downloading entire large files just to find a title tag.
_MAX_BODY_READ: int = 65_536

# Default User-Agent string.
_DEFAULT_UA: str = "SubReconX/0.1.0"


class HTTPProber:
    """Asynchronous HTTP/HTTPS prober with rate & concurrency limiting.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds (connect + read combined).
    concurrency:
        Maximum number of concurrent probes.
    rate_limit:
        Maximum requests per second across all concurrent tasks.
    user_agent:
        User-Agent header value sent with every request.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        concurrency: int = 10,
        rate_limit: float = 20.0,
        user_agent: str = _DEFAULT_UA,
    ) -> None:
        self._timeout = timeout
        self._concurrency = concurrency
        self._rate_limit = rate_limit
        self._user_agent = user_agent

        self._semaphore = asyncio.Semaphore(concurrency)
        self._min_interval: float = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self._last_request_time: float = 0.0
        self._rate_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _apply_rate_limit(self) -> None:
        """Enforce minimum gap between successive requests."""
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                wait = self._min_interval - elapsed
                logger.debug("Rate limiter: sleeping %.3f s", wait)
                await asyncio.sleep(wait)
            self._last_request_time = time.monotonic()

    # ------------------------------------------------------------------
    # Title extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_title(body: str) -> Optional[str]:
        """Extract page title from HTML body using regex.

        Returns
        -------
        str or None
            The title text with collapsed whitespace, or *None* if no
            ``<title>`` tag is found.
        """
        match = _TITLE_RE.search(body)
        if match:
            raw = match.group(1).strip()
            # Collapse internal whitespace / newlines into single spaces.
            return " ".join(raw.split()) or None
        return None

    # ------------------------------------------------------------------
    # Single URL probe
    # ------------------------------------------------------------------

    async def probe_url(self, url: str) -> HTTPResult:
        """Probe a single URL with a GET request.

        Parameters
        ----------
        url:
            Fully-qualified URL (e.g. ``https://example.com``).

        Returns
        -------
        HTTPResult
            Result object – always returned, even on error.
        """
        scheme = "https" if url.startswith("https://") else "http"
        # Derive hostname from the URL (strip scheme + trailing path).
        hostname = url.split("://", 1)[-1].rstrip("/").split("/", 1)[0]

        await self._apply_rate_limit()

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout, connect=self._timeout),
                follow_redirects=True,
                max_redirects=5,
                verify=False,  # Self-signed certs are common on internal hosts.
                headers={"User-Agent": self._user_agent},
            ) as client:
                start = time.monotonic()
                response = await client.get(url)
                elapsed_ms = round((time.monotonic() - start) * 1000, 2)

            status_code = response.status_code
            final_url = str(response.url)
            server = response.headers.get("server")
            content_length: Optional[int] = None

            cl_header = response.headers.get("content-length")
            if cl_header is not None:
                try:
                    content_length = int(cl_header)
                except ValueError:
                    content_length = None

            # Attempt title extraction on HTML or whenever <title> is in body.
            page_title: Optional[str] = None
            content_type = response.headers.get("content-type", "").lower()
            resp_text = response.text[:_MAX_BODY_READ] if hasattr(response, "text") else ""
            if not content_type or "text/html" in content_type or "<title" in resp_text.lower():
                page_title = self._extract_title(resp_text)

            logger.info(
                "Probed %s -> %d (%.0f ms)",
                url,
                status_code,
                elapsed_ms,
            )

            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                status_code=status_code,
                response_time_ms=elapsed_ms,
                final_url=final_url,
                page_title=page_title,
                content_length=content_length,
                server=server,
                error=None,
            )

        except httpx.TimeoutException as exc:
            logger.warning("Timeout probing %s: %s", url, exc)
            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                error=f"Timeout: {exc}",
            )
        except httpx.ConnectError as exc:
            logger.warning("Connection error probing %s: %s", url, exc)
            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                error=f"ConnectError: {exc}",
            )
        except httpx.TooManyRedirects as exc:
            logger.warning("Too many redirects probing %s: %s", url, exc)
            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                error=f"TooManyRedirects: {exc}",
            )
        except httpx.HTTPError as exc:
            logger.warning("HTTP error probing %s: %s", url, exc)
            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                error=f"HTTPError: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error probing %s", url)
            return HTTPResult(
                hostname=hostname,
                url=url,
                scheme=scheme,
                error=f"Unexpected: {type(exc).__name__}: {exc}",
            )

    # ------------------------------------------------------------------
    # Hostname probe (HTTP + HTTPS)
    # ------------------------------------------------------------------

    async def probe_hostname(self, hostname: str) -> list[HTTPResult]:
        """Probe both ``http://`` and ``https://`` for a hostname.

        Parameters
        ----------
        hostname:
            Bare hostname (e.g. ``sub.example.com``).

        Returns
        -------
        list[HTTPResult]
            Two results – one for each scheme.
        """
        http_url = f"http://{hostname}"
        https_url = f"https://{hostname}"
        results = await asyncio.gather(
            self.probe_url(http_url),
            self.probe_url(https_url),
        )
        return list(results)

    # ------------------------------------------------------------------
    # Batch probe
    # ------------------------------------------------------------------

    async def _probe_hostname_guarded(
        self, hostname: str
    ) -> list[HTTPResult]:
        """Probe a hostname while respecting the concurrency semaphore."""
        async with self._semaphore:
            return await self.probe_hostname(hostname)

    async def probe_batch(
        self, hostnames: list[str]
    ) -> list[HTTPResult]:
        """Probe a batch of hostnames concurrently.

        Concurrency is bounded by the semaphore configured at init time.

        Parameters
        ----------
        hostnames:
            List of bare hostnames to probe.

        Returns
        -------
        list[HTTPResult]
            Flat list of results for every hostname × scheme.
        """
        if not hostnames:
            return []

        logger.info(
            "Starting batch HTTP probe of %d hostname(s) "
            "(concurrency=%d, rate_limit=%.1f rps)",
            len(hostnames),
            self._concurrency,
            self._rate_limit,
        )

        nested: list[list[HTTPResult]] = await asyncio.gather(
            *(self._probe_hostname_guarded(h) for h in hostnames)
        )

        flat: list[HTTPResult] = []
        for group in nested:
            flat.extend(group)

        live_count = sum(1 for r in flat if r.is_live)
        logger.info(
            "Batch probe complete: %d result(s), %d live",
            len(flat),
            live_count,
        )
        return flat

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release resources held by the prober.

        Currently a no-op because we create a fresh ``httpx.AsyncClient``
        per request.  Provided for forward-compatibility and to satisfy
        the async context-manager pattern.
        """
        logger.debug("HTTPProber closed")
