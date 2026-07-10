"""Unit tests for playground.config.Settings derived helpers."""

from __future__ import annotations

from playground.config import Settings, get_settings


def _settings(**overrides) -> Settings:
    base = dict(
        registry_a_url="http://reg-a:8100",
        registry_b_url="http://reg-b:8200",
        registry_a_authority="registry-a.playground.local",
        registry_b_authority="registry-b.playground.local",
    )
    base.update(overrides)
    return Settings(**base)


def test_registry_url_for_maps_known_authorities():
    s = _settings()
    assert s.registry_url_for("registry-a.playground.local") == "http://reg-a:8100"
    assert s.registry_url_for("registry-b.playground.local") == "http://reg-b:8200"


def test_registry_url_for_unknown_authority_is_none():
    assert _settings().registry_url_for("registry-z.example") is None


def test_authority_url_map_round_trips_all():
    s = _settings()
    assert s.authority_url_map() == {
        "registry-a.playground.local": "http://reg-a:8100",
        "registry-b.playground.local": "http://reg-b:8200",
    }


def test_control_plane_enabled_reflects_url():
    assert _settings(control_plane_url="").control_plane_enabled is False
    assert _settings(control_plane_url="http://cp:3001").control_plane_enabled is True


def test_get_settings_is_cached():
    a = get_settings()
    b = get_settings()
    assert a is b  # lru_cache singleton
    get_settings.cache_clear()
    assert get_settings() is not a  # cleared → fresh instance
