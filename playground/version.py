"""Single source of truth for the running service's version string.

``SERVICE_VERSION`` is resolved from the *installed distribution's* metadata
via ``importlib.metadata`` rather than a literal (which would be a second copy
of ``pyproject.toml``'s ``version`` that nothing keeps in sync) or an
environment variable (a knob an operator could set to a value that
contradicts the code actually running). Reading ``pyproject.toml`` at runtime
was also considered and rejected: it is not present in a wheel-installed
layout, so it would work in dev and silently fall back in production — the
worst combination. ``importlib.metadata`` structurally cannot drift from what
was actually installed, including a stale editable install: it reports
whatever ``.dist-info`` was written at the last ``uv sync``, which is exactly
what is running, even if that lags a newer ``pyproject.toml`` on disk.

Renaming the project in ``pyproject.toml`` (``name = "acdp-playground"``)
would break this lookup into the fallback below, since the distribution name
is what ``importlib.metadata`` is keyed on.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

_DIST_NAME = "acdp-playground"

try:
    SERVICE_VERSION: str = _dist_version(_DIST_NAME)
except PackageNotFoundError:  # running from a source tree, not installed
    SERVICE_VERSION = "unknown"
