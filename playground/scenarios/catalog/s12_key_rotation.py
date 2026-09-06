"""S12 — pinned-key rotation with an admin reload.

Demonstrates the key-rotation overlap window: the demo
``rotating-publisher`` agent has an outgoing key (valid through
2026-06-02) and an incoming key (valid from 2026-06-01), so both verify
during the overlap. We evaluate the active set at a few instants to show
the rollover, then — when a control plane is configured — trigger a hot
``POST /admin/pinned-keys/reload`` to prove rotation without a restart.

The window evaluation is deterministic and always runs; the admin reload
is best-effort.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from acdp_client.models import StepEvent
from playground.config import get_settings
from playground.control_plane import get_control_plane
from playground.pinned_keys import PinnedKey, active_keys
from playground.scenarios.models import RunResult, RunSpec, ScenarioDef

log = logging.getLogger(__name__)

SCENARIO = ScenarioDef(
    id="s12_key_rotation",
    name="Key Rotation + Admin Reload",
    description="Overlapping pinned-key validity windows: outgoing and incoming "
    "keys both verify during the overlap; an admin reload rotates "
    "without a restart.",
    registry_mode="single",
    agent_count=1,
    framework="langchain",
    default_inputs={},
)

# The demo windows from config/registry-a.toml.
_DID = "did:web:registry-a.playground.local:agents:rotating-publisher"
_OLD = PinnedKey(
    _DID, "9tsbbuOon0zOWgZYlL3m+nQ0PTVS9/MWOmQ/EQXgpRk=", "ed25519", valid_until=1780358400
)  # → 2026-06-02
_NEW = PinnedKey(
    _DID, "V/U68CudHahBq0B1x0+vUM8XQ4ZkmpGwe8G4EScYagI=", "ed25519", valid_from=1780272000
)  # 2026-06-01 →

# Sample instants (unix seconds).
_BEFORE = 1780185600  # 2026-05-31 — only the old key valid
_OVERLAP = 1780300000  # 2026-06-01 — BOTH valid (rotation window)
_AFTER = 1780444800  # 2026-06-03 — only the new key valid


async def run(spec: RunSpec, events: asyncio.Queue[StepEvent]) -> RunResult:
    settings = get_settings()
    keys = [_OLD, _NEW]

    def count_at(now: int) -> int:
        return len(active_keys(keys, now))

    before = count_at(_BEFORE)
    overlap = count_at(_OVERLAP)
    after = count_at(_AFTER)

    # The rotation invariant: exactly one key outside the overlap, both
    # inside it (so a roll-forward never has a gap).
    window_ok = before == 1 and overlap == 2 and after == 1

    await events.put(
        StepEvent(
            type="scenario.note",
            run_id=spec.run_id,
            ts=datetime.now(UTC).isoformat(),
            title="pinned-key window evaluation",
            preview=f"before={before} overlap={overlap} after={after}",
        )
    )

    summary: dict[str, Any] = {
        "window_ok": window_ok,
        "active_before": before,
        "active_overlap": overlap,
        "active_after": after,
    }

    # Optional: hot reload at the control plane.
    cp = get_control_plane(settings)
    if cp.enabled and settings.control_plane_admin_token:
        result = await cp.reload_pinned_keys()
        summary["cp_reload"] = result if result is not None else "unavailable"
    else:
        summary["cp_reload"] = "skipped (no control plane / admin token)"

    return RunResult(
        run_id=spec.run_id,
        scenario_id=SCENARIO.id,
        status="complete" if window_ok else "failed",
        contexts=[],
        summary=summary,
        error=None if window_ok else "S12 rotation window evaluation failed",
    )
