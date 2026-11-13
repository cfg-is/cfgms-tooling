"""Minimal Prometheus HTTP API client (instant queries), stdlib only."""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.parse
import urllib.request


class PromError(Exception):
    """The query could not be run or did not return one value."""


class Prometheus:
    def __init__(self, base_url: str, timeout: float = 15.0):
        # The agent queries its own Prometheus, normally on loopback; the HTTPS
        # scrape of the controllers' private metrics listener is Prometheus's
        # job, not this client's.
        if urllib.parse.urlparse(base_url).scheme not in ("http", "https"):
            raise PromError(f"prometheus_url must be http or https, got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_value(self, promql: str, at: float | None = None) -> float | None:
        """Run an instant query that must reduce to at most one sample.

        Returns the value, or None when the query matched nothing. A query that
        returns several series is an error: catalog queries aggregate.
        """
        params = {"query": promql}
        if at is not None:
            params["time"] = f"{at:.3f}"
        url = f"{self.base_url}/api/v1/query?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 - operator-configured URL
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            e.close()
            raise PromError(f"query failed: {e}") from e
        except (OSError, ValueError) as e:  # URLError, RemoteDisconnected, timeouts, bad JSON
            raise PromError(f"query failed: {e}") from e
        try:
            if body.get("status") != "success":
                raise PromError(f"query error: {body.get('errorType')}: {body.get('error')}")
            data = body.get("data") or {}
            rtype, result = data.get("resultType"), data.get("result")
            if rtype == "scalar":
                return _num(result[1])
            if rtype == "vector":
                if not result:
                    return None
                if len(result) > 1:
                    raise PromError(f"query returned {len(result)} series; catalog queries must aggregate to one")
                return _num(result[0]["value"][1])
        except (AttributeError, KeyError, IndexError, TypeError, ValueError) as e:
            raise PromError(f"malformed query response: {e}") from e
        raise PromError(f"unsupported result type {rtype!r}")


def _num(s: str) -> float | None:
    v = float(s)
    return None if math.isnan(v) else v
