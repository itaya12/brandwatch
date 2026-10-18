"""Workspace-level settings and the effective configuration a brand runs with (Phase 6).

Precedence for economic limits (spec §13 "Economic Limits per workspace/brand"):
    environment defaults  <  workspace settings  <  explicit brand override
Security limits are never part of this chain (``brandwatch.security.limits``).
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.brand_config import BrandConfig
from brandwatch.config.settings import EconomicLimits, Settings, get_settings
from brandwatch.db.models import Brand, Config, Workspace


def workspace_limits(
    session: Session, workspace_id: uuid.UUID, settings: Settings | None = None
) -> EconomicLimits:
    settings = settings or get_settings()
    base = settings.economic_limits.model_dump()
    ws = session.get(Workspace, workspace_id)
    override = ((ws.settings or {}).get("economic_limits") or {}) if ws else {}
    return EconomicLimits.model_validate({**base, **override})


def set_workspace_limits(
    session: Session, workspace_id: uuid.UUID, limits: dict[str, Any]
) -> EconomicLimits:
    validated = EconomicLimits.model_validate(
        {**workspace_limits(session, workspace_id).model_dump(), **limits}
    )
    ws = session.get(Workspace, workspace_id)
    ws.settings = {**(ws.settings or {}), "economic_limits": validated.model_dump()}
    session.flush()
    return validated


DEFAULT_LOOKUPS: dict[str, dict[str, Any]] = {
    "dns": {"mode": "python", "fallback": True},  # python = walk from the root servers
    "whois": {"mode": "python", "fallback": True},  # python = RDAP + port-43 WHOIS
}


def workspace_lookups(session: Session, workspace_id: uuid.UUID) -> dict[str, dict[str, Any]]:
    """How DNS and WHOIS look-ups are done in this workspace (Settings → Lookups)."""
    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("lookups") or {}) if ws else {}
    out: dict[str, dict[str, Any]] = {}
    for kind, default in DEFAULT_LOOKUPS.items():
        cur = {**default, **(stored.get(kind) or {})}
        if cur.get("mode") not in ("python", "service"):
            cur["mode"] = default["mode"]
        cur["fallback"] = bool(cur.get("fallback"))
        out[kind] = cur
    return out


def set_workspace_lookups(
    session: Session, workspace_id: uuid.UUID, lookups: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    merged = workspace_lookups(session, workspace_id)
    for kind in DEFAULT_LOOKUPS:
        if kind in lookups:
            merged[kind] = {**merged[kind], **lookups[kind]}
    ws = session.get(Workspace, workspace_id)
    ws.settings = {**(ws.settings or {}), "lookups": merged}
    session.flush()
    return workspace_lookups(session, workspace_id)


def whois_route(lookups: dict[str, dict[str, Any]]) -> list[str]:
    """Provider order for WHOIS: python = RDAP then port-43; service = WhoisXML API."""
    w = lookups["whois"]
    python, service = ["rdap", "local_whois"], ["whoisxml"]
    first, second = (python, service) if w["mode"] == "python" else (service, python)
    return first + (second if w["fallback"] else [])


def workspace_proxy_settings(session: Session, workspace_id: uuid.UUID) -> dict[str, Any]:
    """The non-secret proxy settings (mode, host, port, username, rotating) for the UI."""
    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("proxy") or {}) if ws else {}
    return {
        "mode": stored.get("mode", "off"),
        "host": stored.get("host", ""),
        "port": stored.get("port", 0),
        "username": stored.get("username", ""),
        "rotating": bool(stored.get("rotating", True)),
    }


def set_workspace_proxy(
    session: Session, workspace_id: uuid.UUID, cfg: dict[str, Any]
) -> dict[str, Any]:
    ws = session.get(Workspace, workspace_id)
    clean = {
        "mode": cfg.get("mode") if cfg.get("mode") in ("off", "manual", "webshare") else "off",
        "host": str(cfg.get("host") or "")[:200],
        "port": int(cfg.get("port") or 0),
        "username": str(cfg.get("username") or "")[:200],
        "rotating": bool(cfg.get("rotating")),
    }
    ws.settings = {**(ws.settings or {}), "proxy": clean}
    session.flush()
    return clean


PROXY_KINDS = ("residential", "mobile", "both")  # both: one visit through each proxy
DEVICES = ("desktop", "mobile", "both")


def workspace_mobile_proxy_settings(session: Session, workspace_id: uuid.UUID) -> dict[str, Any]:
    """The mobile proxy slot (non-secret part): any provider's 4G / 5G proxy, entered by hand."""
    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("proxy_mobile") or {}) if ws else {}
    return {"mode": "manual" if stored.get("mode") == "manual" else "off", "host": stored.get("host", ""),
            "port": stored.get("port", 0), "username": stored.get("username", "")}  # fmt: skip


def set_workspace_mobile_proxy(session: Session, workspace_id: uuid.UUID, cfg: dict[str, Any]) -> dict[str, Any]:
    ws = session.get(Workspace, workspace_id)
    clean = {"mode": "manual" if cfg.get("mode") == "manual" else "off", "host": str(cfg.get("host") or "")[:200],
             "port": int(cfg.get("port") or 0), "username": str(cfg.get("username") or "")[:200]}  # fmt: skip
    ws.settings = {**(ws.settings or {}), "proxy_mobile": clean}
    session.flush()
    return clean


SEVERITIES = ("low", "medium", "high", "critical")


def workspace_notify(session: Session, workspace_id: uuid.UUID, settings: Settings | None = None) -> dict[str, Any]:
    """Settings → Notifications: the alert threshold, which of the configured channels to use (None = all), the brands
    that are muted and whether the daily digest goes out. Stored in ``workspace.settings["notify"]``; the environment
    (NOTIFY_MIN_SEVERITY, NOTIFY_CHANNELS) is the default."""
    settings = settings or get_settings()
    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("notify") or {}) if ws else {}
    min_sev = stored.get("min_severity")
    channels = stored.get("channels")
    return {
        "min_severity": min_sev if min_sev in SEVERITIES else settings.notify_min_severity,
        "channels": [str(c) for c in channels] if isinstance(channels, list) else None,
        "brands_off": [str(b) for b in (stored.get("brands_off") or [])],
        "digest": bool(stored.get("digest", True)),
    }


def set_workspace_notify(session: Session, workspace_id: uuid.UUID, *, min_severity: str | None, channels: list[str] | None,
                         brands_off: list[str], digest: bool) -> dict[str, Any]:  # fmt: skip
    ws = session.get(Workspace, workspace_id)
    clean: dict[str, Any] = {"brands_off": [str(b) for b in brands_off], "digest": bool(digest)}
    if min_severity in SEVERITIES:
        clean["min_severity"] = min_severity
    if channels is not None:
        clean["channels"] = [str(c) for c in channels]
    ws.settings = {**(ws.settings or {}), "notify": clean}
    session.flush()
    return workspace_notify(session, workspace_id)


def workspace_probe_settings(session: Session, workspace_id: uuid.UUID) -> dict[str, str]:
    """Which proxy the Tier-4 probe goes through (residential, mobile or both) and which device it pretends to be (desktop, a phone, or both)."""
    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("probe") or {}) if ws else {}
    return {"proxy_kind": stored.get("proxy_kind") if stored.get("proxy_kind") in PROXY_KINDS else "residential",
            "devices": stored.get("devices") if stored.get("devices") in DEVICES else "desktop"}  # fmt: skip


def set_workspace_probe(session: Session, workspace_id: uuid.UUID, proxy_kind: str | None, devices: str | None) -> dict[str, str]:
    ws = session.get(Workspace, workspace_id)
    clean = {"proxy_kind": proxy_kind if proxy_kind in PROXY_KINDS else "residential", "devices": devices if devices in DEVICES else "desktop"}
    ws.settings = {**(ws.settings or {}), "probe": clean}
    session.flush()
    return clean


async def resolve_proxy(session: Session, workspace_id: uuid.UUID, settings: Settings, kind: str | None = None):
    """Build the live ProxyConfig: the stored settings + decrypted secrets, resolving the Webshare
    token to proxy credentials when in webshare mode. ``kind`` (residential or mobile) defaults to the
    workspace's choice ("both" → the residential one; the runner asks for the mobile one itself). Returns a ``proxy.ProxyConfig``."""
    from brandwatch import keys as keystore
    from brandwatch import proxy as proxy_mod

    if (kind or workspace_probe_settings(session, workspace_id)["proxy_kind"]) == "mobile":
        secrets = keystore.load_keys(session, workspace_id, settings)
        return proxy_mod.from_stored_mobile(workspace_mobile_proxy_settings(session, workspace_id), secrets.get("mobile_proxy_password"))
    cfg = workspace_proxy_settings(session, workspace_id)
    if cfg["mode"] == "off":
        return proxy_mod.ProxyConfig(mode="off")
    secrets = keystore.load_keys(session, workspace_id, settings)
    webshare_creds = None
    if cfg["mode"] == "webshare" and secrets.get("webshare_token"):
        try:
            webshare_creds = await proxy_mod.webshare_credentials(secrets["webshare_token"])
        except proxy_mod.ProxyError:
            webshare_creds = None
    return proxy_mod.from_stored(cfg, secrets.get("residential_proxy_password"), webshare_creds)


def effective_brand_config(
    session: Session, brand_id: uuid.UUID, settings: Settings | None = None
) -> BrandConfig:
    brand = session.get(Brand, brand_id)
    row = session.scalars(sa.select(Config).where(Config.brand_id == brand_id)).first()
    limits = workspace_limits(session, brand.workspace_id, settings).model_dump() if brand else {}
    if row is None:
        return BrandConfig.model_validate({"economic_limits": limits})
    return BrandConfig.model_validate(
        {
            "preset": row.preset,
            "detection": row.detection or {},
            "economic_limits": {**limits, **(row.economic_limits or {})},
            "scoring": row.scoring or {},
        }
    )


def platform_admin_workspace(session: Session) -> Workspace | None:
    """The bootstrap workspace: its admins may create further tenants."""
    return session.scalars(
        sa.select(Workspace).order_by(Workspace.created_at, Workspace.id)
    ).first()
