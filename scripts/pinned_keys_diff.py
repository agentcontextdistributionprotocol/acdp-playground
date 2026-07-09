#!/usr/bin/env python3
"""Translate a registry's `[playground] pinned_keys` TOML into the
control plane's `CONTROL_PLANE_PINNED_KEYS` env-var format.

The registry and the control plane both pin agent public keys, but
they read from different config surfaces:

  - Registry: `[[playground.pinned_keys]]` blocks in `registry-a.toml`
    (or whatever the registry config file is).
  - Control plane: `CONTROL_PLANE_PINNED_KEYS=did1=pub1,did2=pub2`
    environment variable consumed by `PinnedKeysService`.

Operators have been maintaining both by hand. This CLI reads one or
more registry TOML files and emits the matching env string (and,
optionally, a diff against an existing one) so the two stay in
lock-step.

Usage:

    # Emit env var for one registry
    python scripts/pinned_keys_diff.py config/registry-a.toml

    # Merge multiple registries (deduped by agent_did)
    python scripts/pinned_keys_diff.py config/registry-a.toml config/registry-b.toml

    # Compare against a current env value
    CONTROL_PLANE_PINNED_KEYS=did:web:a=AAA \\
        python scripts/pinned_keys_diff.py --diff config/registry-a.toml

    # Emit as `KEY=VALUE` shell-export line (default)
    python scripts/pinned_keys_diff.py --format export config/registry-a.toml

    # Emit as JSON (useful for ops scripting)
    python scripts/pinned_keys_diff.py --format json config/registry-a.toml

Exit status: 0 on success; 2 when --diff is set and the inputs differ
(so the CLI is usable in a CI guard).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PinnedEntry:
    agent_did: str
    public_key_b64: str
    algorithm: str = "ed25519"
    valid_from: int | None = None
    valid_until: int | None = None

    def to_env_token(self) -> str:
        """Render the CP ``CONTROL_PLANE_PINNED_KEYS`` wire token.

        Format: ``did=pubkey[:algorithm[:validFrom..validUntil]]``.

        A plain Ed25519 key with no validity window renders as the bare
        ``did=pubkey`` (backward-compatible). A non-default algorithm or
        a validity window appends the extra colon-delimited segments;
        the algorithm is always emitted alongside a window so the value
        is unambiguous (a window segment is the one containing ``..``).
        """
        token = f"{self.agent_did}={self.public_key_b64}"
        has_window = self.valid_from is not None or self.valid_until is not None
        if self.algorithm != "ed25519" or has_window:
            token += f":{self.algorithm}"
        if has_window:
            lo = str(self.valid_from) if self.valid_from is not None else ""
            hi = str(self.valid_until) if self.valid_until is not None else ""
            token += f":{lo}..{hi}"
        return token

    def identity(self) -> tuple:
        """Comparable tuple of everything that matters for a diff."""
        return (self.public_key_b64, self.algorithm, self.valid_from, self.valid_until)


def parse_registry_toml(path: Path) -> list[PinnedEntry]:
    """Extract [[playground.pinned_keys]] entries from a registry TOML."""
    raw = tomllib.loads(path.read_text())
    pg = raw.get("playground", {}) or {}
    out: list[PinnedEntry] = []
    for entry in pg.get("pinned_keys", []) or []:
        try:
            out.append(
                PinnedEntry(
                    agent_did=entry["agent_did"],
                    public_key_b64=entry["public_key_b64"],
                    algorithm=entry.get("algorithm", "ed25519"),
                    valid_from=entry.get("valid_from"),
                    valid_until=entry.get("valid_until"),
                )
            )
        except KeyError as e:
            raise SystemExit(f"{path}: pinned_keys entry missing required field {e}: {entry!r}")
    return out


def merge_dedup(entry_lists: list[list[PinnedEntry]]) -> list[PinnedEntry]:
    """Merge with dedup-by-agent_did. Later wins (= last registry on cmdline).

    Conflicts (same DID, different pub key) print a warning to stderr
    so the operator notices a real divergence; the later entry takes
    precedence so the command stays deterministic.
    """
    out: dict[str, PinnedEntry] = {}
    for entries in entry_lists:
        for e in entries:
            existing = out.get(e.agent_did)
            if existing is not None and existing.public_key_b64 != e.public_key_b64:
                print(
                    f"warning: conflicting pin for {e.agent_did}: "
                    f"{existing.public_key_b64[:12]}... vs {e.public_key_b64[:12]}... "
                    f"(later wins)",
                    file=sys.stderr,
                )
            out[e.agent_did] = e
    return sorted(out.values(), key=lambda x: x.agent_did)


def to_env_value(entries: list[PinnedEntry]) -> str:
    return ",".join(e.to_env_token() for e in entries)


def parse_env_value(raw: str) -> list[PinnedEntry]:
    """Parse the CONTROL_PLANE_PINNED_KEYS format back into entries.

    Tolerates the extended ``did=pub[:algorithm[:from..until]]`` form: a
    colon segment containing ``..`` is the validity window, otherwise it
    is the algorithm. Base64 keys never contain ``:`` so the split is
    unambiguous.
    """
    out: list[PinnedEntry] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "=" not in token:
            raise SystemExit(f"malformed env token (expected did=pubkey): {token!r}")
        did, _, value = token.partition("=")
        segs = value.strip().split(":")
        pub = segs[0]
        algorithm = "ed25519"
        valid_from: int | None = None
        valid_until: int | None = None
        for seg in segs[1:]:
            if ".." in seg:
                lo, _, hi = seg.partition("..")
                valid_from = int(lo) if lo else None
                valid_until = int(hi) if hi else None
            elif seg:
                algorithm = seg
        out.append(
            PinnedEntry(
                agent_did=did.strip(),
                public_key_b64=pub,
                algorithm=algorithm,
                valid_from=valid_from,
                valid_until=valid_until,
            )
        )
    return out


def diff_entries(
    desired: list[PinnedEntry],
    current: list[PinnedEntry],
) -> tuple[list[PinnedEntry], list[PinnedEntry], list[tuple[PinnedEntry, PinnedEntry]]]:
    """Return (only_in_desired, only_in_current, changed)."""
    cur_map = {e.agent_did: e for e in current}
    des_map = {e.agent_did: e for e in desired}
    only_desired = [e for e in desired if e.agent_did not in cur_map]
    only_current = [e for e in current if e.agent_did not in des_map]
    changed = [
        (cur_map[did], des_map[did])
        for did in cur_map.keys() & des_map.keys()
        if cur_map[did].identity() != des_map[did].identity()
    ]
    return only_desired, only_current, changed


def render(fmt: str, entries: list[PinnedEntry]) -> str:
    if fmt == "export":
        return f"CONTROL_PLANE_PINNED_KEYS={to_env_value(entries)}"
    if fmt == "raw":
        return to_env_value(entries)
    if fmt == "json":
        records = []
        for e in entries:
            rec = {
                "agent_did": e.agent_did,
                "public_key_b64": e.public_key_b64,
                "algorithm": e.algorithm,
            }
            # Only surface window bounds when present, so the common case
            # stays a clean 3-key record.
            if e.valid_from is not None:
                rec["valid_from"] = e.valid_from
            if e.valid_until is not None:
                rec["valid_until"] = e.valid_until
            records.append(rec)
        return json.dumps(records, indent=2)
    raise SystemExit(f"unknown --format: {fmt}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("toml", nargs="+", type=Path, help="registry TOML config file(s)")
    p.add_argument(
        "--format",
        choices=("export", "raw", "json"),
        default="export",
        help="output format (default: export, suitable for `eval $(...)` in shells)",
    )
    p.add_argument(
        "--diff",
        action="store_true",
        help=(
            "compare against $CONTROL_PLANE_PINNED_KEYS in the environment; "
            "exit 2 when desired != current"
        ),
    )
    args = p.parse_args(argv)

    entry_lists: list[list[PinnedEntry]] = []
    for path in args.toml:
        if not path.exists():
            raise SystemExit(f"no such file: {path}")
        entry_lists.append(parse_registry_toml(path))
    desired = merge_dedup(entry_lists)

    if args.diff:
        current_raw = os.environ.get("CONTROL_PLANE_PINNED_KEYS", "")
        current = parse_env_value(current_raw)
        only_desired, only_current, changed = diff_entries(desired, current)
        if not only_desired and not only_current and not changed:
            print("up to date")
            return 0
        if only_desired:
            print("+ would add:")
            for e in only_desired:
                print(f"    {e.agent_did}={e.public_key_b64}")
        if only_current:
            print("- would remove:")
            for e in only_current:
                print(f"    {e.agent_did}={e.public_key_b64}")
        if changed:
            print("~ would rotate:")
            for old, new in changed:
                print(
                    f"    {old.agent_did}: {old.public_key_b64[:12]}... -> {new.public_key_b64[:12]}..."
                )
        return 2

    print(render(args.format, desired))
    return 0


if __name__ == "__main__":
    sys.exit(main())
