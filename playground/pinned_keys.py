"""Pinned-key validity-window evaluation (RFC-ACDP-0008 §9.3).

The registry/CP accept multiple pinned keys per agent, each scoped by an
optional ``valid_from`` / ``valid_until`` window (unix seconds; inclusive
start, exclusive end). During a rotation, the outgoing and incoming keys
overlap so signatures verify against either while clients roll forward.

This module mirrors that evaluation on the playground side so a scenario
can show which key(s) are active at a given instant without standing up
the registry.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PinnedKey:
    agent_did: str
    public_key: str
    algorithm: str = "ed25519"
    valid_from: int | None = None
    valid_until: int | None = None

    def active_at(self, now: int) -> bool:
        """Whether this key is valid at unix time ``now``.

        ``valid_from`` is inclusive, ``valid_until`` is exclusive; an
        absent bound is open-ended.
        """
        if self.valid_from is not None and now < self.valid_from:
            return False
        return not (self.valid_until is not None and now >= self.valid_until)


def active_keys(keys: list[PinnedKey], now: int) -> list[PinnedKey]:
    """Return the subset of ``keys`` valid at ``now``.

    During a rotation overlap this returns more than one key for the
    same agent — exactly the window in which either signature verifies.
    """
    return [k for k in keys if k.active_at(now)]
