"""Settings, brand config, secrets (spec §13)."""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from brandwatch.config.brand_config import (
    DEFAULT_GROUP_CAPS,
    DEFAULT_WEIGHTS,
    SIGNAL_GROUPS,
    BrandConfig,
    ScoringConfig,
    Thresholds,
)
from brandwatch.config.secrets import Envelope, EnvSecretStore, RedactingFilter, last4, mask
from brandwatch.config.settings import Settings
from brandwatch.db.enums import Severity

# --------------------------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------------------------


def test_settings_read_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db/bw")
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("ECONOMIC_LIMITS__MAX_DAILY_SPEND", "12.5")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret-key-1234")
    s = Settings(_env_file=None)
    assert s.database_url.startswith("postgresql+psycopg://")
    assert s.demo_mode is False
    assert s.economic_limits.max_daily_spend == 12.5
    assert s.has_key("virustotal") and not s.has_key("shodan")
    assert s.provider_key("virustotal") == "vt-secret-key-1234"
    assert "vt-secret-key-1234" not in repr(s)  # SecretStr never leaks via repr


def test_settings_defaults_are_safe(monkeypatch):
    for var in ("DATABASE_URL", "DEMO_MODE", "VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    s = Settings(_env_file=None)
    assert s.demo_mode is True
    assert s.database_url.startswith("sqlite:///")
    assert s.economic_limits.max_daily_spend == 0
    assert s.providers["reputation"].primary == "virustotal"
    assert s.providers["reputation"].fallback == ["urlhaus", "safebrowsing"]  # PhishTank dropped


def test_blank_key_counts_as_missing(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "   ")
    assert Settings(_env_file=None).has_key("shodan") is False


def test_economic_limits_reject_negative(monkeypatch):
    monkeypatch.setenv("ECONOMIC_LIMITS__MAX_API_CALLS", "-1")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


# --------------------------------------------------------------------------------------------
# Brand config / scoring
# --------------------------------------------------------------------------------------------


def test_default_brand_config_is_valid_and_consistent():
    cfg = BrandConfig()
    assert cfg.scoring.raw_max == 150  # Σ group caps (spec §5)
    assert set(cfg.scoring.weights) == set(DEFAULT_WEIGHTS) <= set(SIGNAL_GROUPS)
    assert set(cfg.scoring.group_caps) == set(DEFAULT_GROUP_CAPS)
    assert {g for g in SIGNAL_GROUPS.values()} == set(DEFAULT_GROUP_CAPS)


def test_thresholds_map_scores_to_severity():
    t = Thresholds()
    assert t.severity_for(0) is Severity.LOW
    assert t.severity_for(24) is Severity.LOW
    assert t.severity_for(25) is Severity.MEDIUM
    assert t.severity_for(50) is Severity.HIGH
    assert t.severity_for(75) is Severity.CRITICAL
    assert t.severity_for(100) is Severity.CRITICAL


def test_thresholds_must_be_monotonic():
    with pytest.raises(ValidationError, match="monotonic|medium < high"):
        Thresholds(medium=50, high=50, critical=75)


def test_scoring_rejects_unknown_signal_and_negative_weight():
    with pytest.raises(ValidationError, match="unknown signal"):
        ScoringConfig(weights={"made_up_signal": 5})
    with pytest.raises(ValidationError, match=">= 0"):
        ScoringConfig(weights={"favicon_exact": -1})


def test_scoring_rejects_rule_with_unknown_signal():
    with pytest.raises(ValidationError, match="unknown signals"):
        ScoringConfig(
            combination_rules=[
                {"name": "x", "signals_all": ["favicon_exact", "nope"], "min_severity": "high"}
            ]
        )


def test_brand_config_forbids_unknown_keys():
    with pytest.raises(ValidationError):
        BrandConfig.model_validate({"scoring": {"weights": {}, "FETCH_TIMEOUT": 1}})
    with pytest.raises(ValidationError):
        BrandConfig.model_validate({"preset": "ultra"})


def test_brand_config_round_trips_through_json():
    cfg = BrandConfig(preset="standard")
    again = BrandConfig.model_validate_json(cfg.model_dump_json())
    assert again == cfg


# --------------------------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------------------------


def test_mask_and_last4():
    assert mask("sk-live-abcdefghijkl-a4f2") == "sk-…a4f2"
    assert mask("0123456789abcdef") == "…cdef"
    assert mask("abc") == "…"
    assert last4("0123456789") == "6789"


def test_envelope_round_trip_and_tamper_detection():
    env = Envelope.from_b64(Envelope.generate_kek_b64())
    ct, wrapped = env.encrypt("vt-secret-key-1234", aad=b"virustotal")
    assert b"vt-secret-key-1234" not in ct
    assert env.decrypt(ct, wrapped, aad=b"virustotal") == "vt-secret-key-1234"
    with pytest.raises(Exception):  # noqa: B017 - cryptography.InvalidTag
        env.decrypt(ct, wrapped, aad=b"other-provider")
    other = Envelope.from_b64(Envelope.generate_kek_b64())
    with pytest.raises(Exception):  # noqa: B017
        other.decrypt(ct, wrapped, aad=b"virustotal")


def test_envelope_requires_32_byte_kek():
    with pytest.raises(ValueError):
        Envelope(b"short")


def test_env_secret_store(monkeypatch):
    monkeypatch.setenv("SOME_SECRET", " value ")
    monkeypatch.setenv("EMPTY_SECRET", "   ")
    store = EnvSecretStore()
    assert store.get("SOME_SECRET") == "value"
    assert store.get("EMPTY_SECRET") is None
    assert store.get("MISSING_SECRET") is None


def test_redacting_filter_blanks_secrets():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "key=%s used", ("vt-secret",), None)
    assert RedactingFilter(["vt-secret"]).filter(record) is True
    assert record.getMessage() == "key=*** used"


def test_secret_key_must_be_at_least_32_bytes(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "too-short")
    with pytest.raises(ValidationError, match="32 bytes"):
        Settings(_env_file=None)
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    assert Settings(_env_file=None).secret_key.get_secret_value() == "x" * 32
