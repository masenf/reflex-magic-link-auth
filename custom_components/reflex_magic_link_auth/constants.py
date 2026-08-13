"""Tunable constants, each overridable by an environment variable.

| Constant | Environment variable | Default |
| --- | --- | --- |
| `AUTH_ROUTE` | `MAGIC_LINK_AUTH_ROUTE` | `/magic-link-auth` |
| `DEFAULT_OTP_EXPIRATION_DELTA` | `MAGIC_LINK_AUTH_OTP_EXPIRATION_SECONDS` | 1800 (30 minutes) |
| `DEFAULT_AUTH_SESSION_EXPIRATION_DELTA` | `MAGIC_LINK_AUTH_SESSION_EXPIRATION_SECONDS` | 604800 (7 days) |
| `DEFAULT_OTP_RATE_LIMIT` | `MAGIC_LINK_AUTH_OTP_RATE_LIMIT` | 5 |

The environment is read once, when this module is first imported. `AUTH_ROUTE`
is consumed at import time by the `@rx.page` decorator in `page.py`, so the
variables have to be set before the app imports this package.

A variable that is set but unusable raises `ValueError` at import rather than
falling back to the default: these values bound how long a credential lives and
how often one can be requested, so silently ignoring a typo would weaken the
app without saying so.
"""

from __future__ import annotations

import datetime
import os

DEFAULT_AUTH_ROUTE = "/magic-link-auth"


def _env(name: str) -> str | None:
    """Return an environment variable, treating blank as unset.

    Args:
        name: The variable to read.

    Returns:
        The stripped value, or None when it is unset or blank. Deployment
        tooling routinely passes a variable through with an empty value when it
        has none to give, which means "no opinion", not "set it to nothing".
    """
    return (os.environ.get(name) or "").strip() or None


def _route(name: str, default: str) -> str:
    """Read a URL path from the environment.

    Args:
        name: The variable to read.
        default: The value to use when it is unset.

    Returns:
        The configured path.

    Raises:
        ValueError: The value is not an absolute path. The same string is
            registered as a page route and joined onto the app's origin to
            build the emailed link, and a relative path would resolve
            differently in those two places.
    """
    value = _env(name)
    if value is None:
        return default
    if not value.startswith("/"):
        raise ValueError(
            f"{name} must be an absolute path starting with '/', got {value!r}"
        )
    return value


def _positive_int(name: str, default: int) -> int:
    """Read a positive integer from the environment.

    Args:
        name: The variable to read.
        default: The value to use when it is unset.

    Returns:
        The configured integer.

    Raises:
        ValueError: The value is not an integer, or is below 1. A rate limit of
            zero rejects every request, including the first.
    """
    value = _env(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {value!r}") from None
    if parsed < 1:
        raise ValueError(f"{name} must be at least 1, got {parsed}")
    return parsed


def _positive_seconds(name: str, default: datetime.timedelta) -> datetime.timedelta:
    """Read a positive duration in seconds from the environment.

    Args:
        name: The variable to read.
        default: The value to use when it is unset.

    Returns:
        The configured duration.

    Raises:
        ValueError: The value is not a number, or is not greater than zero. A
            non-positive lifetime would expire every credential the moment it
            was issued.
    """
    value = _env(name)
    if value is None:
        return default
    try:
        seconds = float(value)
    except ValueError:
        raise ValueError(f"{name} must be a number of seconds, got {value!r}") from None
    if seconds <= 0:
        raise ValueError(f"{name} must be greater than zero, got {value!r}")
    return datetime.timedelta(seconds=seconds)


AUTH_ROUTE = _route("MAGIC_LINK_AUTH_ROUTE", DEFAULT_AUTH_ROUTE)
DEFAULT_OTP_EXPIRATION_DELTA = _positive_seconds(
    "MAGIC_LINK_AUTH_OTP_EXPIRATION_SECONDS",
    datetime.timedelta(minutes=30),
)
DEFAULT_AUTH_SESSION_EXPIRATION_DELTA = _positive_seconds(
    "MAGIC_LINK_AUTH_SESSION_EXPIRATION_SECONDS",
    datetime.timedelta(days=7),
)
DEFAULT_OTP_RATE_LIMIT = _positive_int("MAGIC_LINK_AUTH_OTP_RATE_LIMIT", 5)
