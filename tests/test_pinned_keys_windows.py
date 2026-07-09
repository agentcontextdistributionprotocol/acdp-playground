"""Tests for playground.pinned_keys — validity-window evaluation."""

from __future__ import annotations

from playground.pinned_keys import PinnedKey, active_keys

OLD = PinnedKey("did:x", "k-old", "ed25519", valid_until=1780358400)  # → 2026-06-02
NEW = PinnedKey("did:x", "k-new", "ed25519", valid_from=1780272000)  # 2026-06-01 →

BEFORE = 1780185600  # 2026-05-31
OVERLAP = 1780300000  # 2026-06-01
AFTER = 1780444800  # 2026-06-03


def test_open_ended_key_always_active():
    k = PinnedKey("did:x", "k")
    assert k.active_at(0)
    assert k.active_at(9_999_999_999)


def test_valid_from_inclusive():
    k = PinnedKey("did:x", "k", valid_from=100)
    assert not k.active_at(99)
    assert k.active_at(100)
    assert k.active_at(101)


def test_valid_until_exclusive():
    k = PinnedKey("did:x", "k", valid_until=200)
    assert k.active_at(199)
    assert not k.active_at(200)


def test_rotation_overlap_window():
    assert [k.public_key for k in active_keys([OLD, NEW], BEFORE)] == ["k-old"]
    assert {k.public_key for k in active_keys([OLD, NEW], OVERLAP)} == {"k-old", "k-new"}
    assert [k.public_key for k in active_keys([OLD, NEW], AFTER)] == ["k-new"]
