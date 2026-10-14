"""Residential / mobile proxy: URL building, Webshare country encoding, per-brand country,
and the encrypted workspace settings round-trip. No network is touched."""

import uuid

import pytest

from brandwatch import proxy as proxy_mod
from brandwatch import tenancy


def test_country_for_brand_audience():
    assert proxy_mod.country_for("uk", "en") == "uk"  # explicit search country wins
    assert proxy_mod.country_for("", "en") == "us"  # English audience → US
    assert proxy_mod.country_for("", "pt") == "br"
    assert proxy_mod.country_for("worldwide", "de") == "de"  # not a 2-letter code → by language
    assert proxy_mod.country_for(None, None) == "us"


def test_manual_proxy_url_is_verbatim_and_encoded():
    cfg = proxy_mod.ProxyConfig(mode="manual", host="proxy.example", port=8080,
                                username="u ser", password="p@ss:word", rotating=False)  # fmt: skip
    assert cfg.enabled
    assert (
        cfg.url("us") == "http://u%20ser:p%40ss%3Aword@proxy.example:8080"
    )  # country ignored for manual
    assert cfg.username_for("us") == "u ser"


def test_webshare_username_encodes_rotation_and_country():
    cfg = proxy_mod.ProxyConfig(mode="webshare", host="p.webshare.io", port=80,
                                username="acct", password="pw", rotating=True)  # fmt: skip
    assert cfg.username_for("us") == "acct-rotate-country-us"
    assert cfg.username_for(None) == "acct-rotate"
    assert cfg.username_for("worldwide") == "acct-rotate"
    assert cfg.url("de") == "http://acct-rotate-country-de:pw@p.webshare.io:80"
    # a stored username that already has the suffixes is normalised, not doubled
    cfg2 = proxy_mod.ProxyConfig(mode="webshare", host="p.webshare.io", port=80,
                                 username="acct-rotate-country-de", password="pw", rotating=True)  # fmt: skip
    assert cfg2.username_for("us") == "acct-rotate-country-us"


def test_off_and_incomplete_are_not_enabled():
    assert not proxy_mod.ProxyConfig(mode="off").enabled
    assert not proxy_mod.ProxyConfig(mode="webshare").enabled  # no creds resolved yet
    assert not proxy_mod.ProxyConfig(mode="manual", host="", username="u").enabled


def test_from_stored_builds_each_mode():
    manual = proxy_mod.from_stored(
        {"mode": "manual", "host": "h", "port": "3128", "username": "u"}, "secret-pw", None
    )
    assert manual.mode == "manual" and manual.password == "secret-pw" and manual.port == 3128
    ws = proxy_mod.from_stored({"mode": "webshare"}, None, ("wsuser", "wspw"))
    assert ws.username == "wsuser" and ws.password == "wspw" and ws.host == "p.webshare.io"
    assert proxy_mod.from_stored({"mode": "webshare"}, None, None).enabled is False


def test_workspace_proxy_settings_round_trip_and_secrets(session):
    from brandwatch import keys as keystore
    from brandwatch.config.settings import Settings
    from brandwatch.db.models import Workspace

    settings = Settings(_env_file=None, secret_key="unit-test-secret-0123456789abcdef")
    ws = Workspace(name=f"px-{uuid.uuid4().hex[:6]}")
    session.add(ws)
    session.flush()
    assert tenancy.workspace_proxy_settings(session, ws.id)["mode"] == "off"
    tenancy.set_workspace_proxy(session, ws.id, {
        "mode": "manual", "host": "proxy.example", "port": "8080", "username": "u", "rotating": True,
    })  # fmt: skip
    got = tenancy.workspace_proxy_settings(session, ws.id)
    assert got == {
        "mode": "manual",
        "host": "proxy.example",
        "port": 8080,
        "username": "u",
        "rotating": True,
    }
    # the password is stored encrypted via the key store, never in workspace.settings
    keystore.store_key(session, ws.id, "residential_proxy_password", "hunter2pw", settings)
    assert "hunter2pw" not in str(ws.settings)
    assert keystore.load_keys(session, ws.id, settings)["residential_proxy_password"] == "hunter2pw"


async def test_resolve_proxy_manual(session):
    from brandwatch import keys as keystore
    from brandwatch.config.settings import Settings
    from brandwatch.db.models import Workspace

    settings = Settings(_env_file=None, secret_key="unit-test-secret-0123456789abcdef")
    ws = Workspace(name=f"rp-{uuid.uuid4().hex[:6]}")
    session.add(ws)
    session.flush()
    tenancy.set_workspace_proxy(session, ws.id, {
        "mode": "manual", "host": "proxy.example", "port": "8080", "username": "u", "rotating": False,
    })  # fmt: skip
    keystore.store_key(session, ws.id, "residential_proxy_password", "pw123456", settings)
    cfg = await tenancy.resolve_proxy(session, ws.id, settings)
    assert cfg.enabled and cfg.url("us") == "http://u:pw123456@proxy.example:8080"
    tenancy.set_workspace_proxy(session, ws.id, {"mode": "off"})
    assert (await tenancy.resolve_proxy(session, ws.id, settings)).mode == "off"


def test_reserved_secret_rejects_wrong_name(session):
    from brandwatch import keys as keystore
    from brandwatch.config.settings import Settings
    from brandwatch.db.models import Workspace

    settings = Settings(_env_file=None, secret_key="unit-test-secret-0123456789abcdef")
    ws = Workspace(name=f"x-{uuid.uuid4().hex[:6]}")
    session.add(ws)
    session.flush()
    with pytest.raises(ValueError, match="unknown provider"):
        keystore.store_key(session, ws.id, "not_a_real_secret", "value123", settings)
