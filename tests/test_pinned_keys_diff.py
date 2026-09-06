"""Tests for scripts/pinned_keys_diff.py — the registry-TOML → CP-env translator."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make the script importable without installing.
SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from pinned_keys_diff import (  # type: ignore[import-not-found]
    PinnedEntry,
    diff_entries,
    main,
    merge_dedup,
    parse_env_value,
    parse_registry_toml,
    to_env_value,
)


def _write_toml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "registry.toml"
    p.write_text(body)
    return p


def test_parse_registry_toml_extracts_pinned_keys(tmp_path: Path) -> None:
    p = _write_toml(
        tmp_path,
        """
[playground]
enabled = true

[[playground.pinned_keys]]
agent_did = "did:web:a:agents:alice"
public_key_b64 = "AAA"

[[playground.pinned_keys]]
agent_did = "did:web:a:agents:bob"
public_key_b64 = "BBB"
algorithm = "ed25519"
""",
    )
    out = parse_registry_toml(p)
    assert len(out) == 2
    assert out[0].agent_did == "did:web:a:agents:alice"
    assert out[0].public_key_b64 == "AAA"
    assert out[1].algorithm == "ed25519"


def test_parse_registry_toml_with_no_playground_section(tmp_path: Path) -> None:
    p = _write_toml(tmp_path, "[storage]\nurl='x'\n")
    assert parse_registry_toml(p) == []


def test_merge_dedup_later_wins_with_warning(tmp_path: Path, capsys) -> None:
    a = [PinnedEntry("did:x", "PUB_OLD")]
    b = [PinnedEntry("did:x", "PUB_NEW"), PinnedEntry("did:y", "PUB_Y")]
    merged = merge_dedup([a, b])
    pubs = {e.agent_did: e.public_key_b64 for e in merged}
    assert pubs == {"did:x": "PUB_NEW", "did:y": "PUB_Y"}
    err = capsys.readouterr().err
    assert "conflicting pin" in err


def test_to_env_value_format() -> None:
    entries = [PinnedEntry("did:a", "AAA"), PinnedEntry("did:b", "BBB")]
    assert to_env_value(entries) == "did:a=AAA,did:b=BBB"


def test_parse_env_value_round_trip() -> None:
    raw = "did:a=AAA,did:b=BBB"
    back = parse_env_value(raw)
    assert back == [PinnedEntry("did:a", "AAA"), PinnedEntry("did:b", "BBB")]


def test_parse_env_value_skips_empty_tokens() -> None:
    assert parse_env_value("  ,did:a=AAA,  ,did:b=BBB ,") == [
        PinnedEntry("did:a", "AAA"),
        PinnedEntry("did:b", "BBB"),
    ]


def test_parse_env_value_rejects_malformed() -> None:
    with pytest.raises(SystemExit):
        parse_env_value("not-a-token")


def test_diff_entries_adds_removes_changes() -> None:
    desired = [PinnedEntry("did:a", "AAA"), PinnedEntry("did:b", "B-NEW")]
    current = [PinnedEntry("did:b", "B-OLD"), PinnedEntry("did:c", "CCC")]
    add, rm, chg = diff_entries(desired, current)
    assert [e.agent_did for e in add] == ["did:a"]
    assert [e.agent_did for e in rm] == ["did:c"]
    assert len(chg) == 1
    assert chg[0][0].public_key_b64 == "B-OLD"
    assert chg[0][1].public_key_b64 == "B-NEW"


def test_main_emits_export_by_default(tmp_path: Path, capsys) -> None:
    p = _write_toml(
        tmp_path,
        """
[[playground.pinned_keys]]
agent_did = "did:a"
public_key_b64 = "AAA"
""",
    )
    rc = main([str(p)])
    assert rc == 0
    assert "CONTROL_PLANE_PINNED_KEYS=did:a=AAA" in capsys.readouterr().out


def test_main_emits_json_when_requested(tmp_path: Path, capsys) -> None:
    p = _write_toml(
        tmp_path,
        """
[[playground.pinned_keys]]
agent_did = "did:a"
public_key_b64 = "AAA"
""",
    )
    rc = main([str(p), "--format", "json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed == [{"agent_did": "did:a", "public_key_b64": "AAA", "algorithm": "ed25519"}]


def test_main_diff_exit_codes(tmp_path: Path, monkeypatch, capsys) -> None:
    p = _write_toml(
        tmp_path,
        """
[[playground.pinned_keys]]
agent_did = "did:a"
public_key_b64 = "AAA"
""",
    )

    monkeypatch.setenv("CONTROL_PLANE_PINNED_KEYS", "did:a=AAA")
    rc = main([str(p), "--diff"])
    assert rc == 0
    assert "up to date" in capsys.readouterr().out

    monkeypatch.setenv("CONTROL_PLANE_PINNED_KEYS", "did:a=DIFFERENT")
    rc = main([str(p), "--diff"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "would rotate" in out

    monkeypatch.setenv("CONTROL_PLANE_PINNED_KEYS", "")
    rc = main([str(p), "--diff"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "would add" in out


def test_main_merges_multiple_registries(tmp_path: Path, capsys) -> None:
    a = tmp_path / "a.toml"
    a.write_text("[[playground.pinned_keys]]\nagent_did='did:a'\npublic_key_b64='AAA'\n")
    b = tmp_path / "b.toml"
    b.write_text("[[playground.pinned_keys]]\nagent_did='did:b'\npublic_key_b64='BBB'\n")
    rc = main([str(a), str(b), "--format", "raw"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    # Sorted by agent_did.
    assert out == "did:a=AAA,did:b=BBB"
