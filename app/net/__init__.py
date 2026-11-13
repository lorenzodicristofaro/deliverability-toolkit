"""Guarded outbound network access (M7-01, ARCHITECTURE section 9). Nothing else in ``app/``
imports an HTTP library."""

from app.net.guarded_http import FetchResult, Hop, fetch, limits_from_settings
from app.net.policy import FetchError, FetchErrorKind, FetchLimits

__all__ = [
    "FetchError",
    "FetchErrorKind",
    "FetchLimits",
    "FetchResult",
    "Hop",
    "fetch",
    "limits_from_settings",
]
