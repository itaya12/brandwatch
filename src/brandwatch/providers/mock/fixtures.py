"""Recorded scenarios that drive the mock providers (spec §4 "Demo mode", §18 golden dataset).

A *scenario* is one JSONL line describing everything the world would have answered for a host:
DNS, HTTP (status + HTML), which favicon/screenshot class it serves, WHOIS age, reputation
verdicts. Every mock consults the store first; hosts without a scenario get the deterministic
hash-based default (and, for DNS, NXDOMAIN — which keeps a demo scan bounded).

The shipped scenarios live in ``brandwatch/demo/golden/*.jsonl`` and double as the golden dataset.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

GOLDEN_DIR = Path(__file__).resolve().parents[2] / "demo" / "golden"
# extra demo worlds (an attack network that spans two brands …): answered by every mock provider like the golden scenarios, but never part of the
# golden dataset: they are not listed by ``all()`` / ``by_label()`` / ``len()``, so the metrics, the classifier and the label counts do not change
NETWORKS_DIR = Path(__file__).resolve().parents[2] / "demo" / "networks"
LABELS = (
    "phishing",
    "legit",
    "brand_related_legit",
    "suspicious_not_phishing",
    "other_brand_phishing",
    "scam_shop",  # a web shop advertising the brand's products and shipping replicas
)


@dataclass(frozen=True, slots=True)
class Scenario:
    url: str
    host: str
    brand: str
    label: str
    notes: str = ""
    dns: dict[str, list[str]] | None = None  # None → NXDOMAIN
    http: dict[str, Any] | None = None  # {"status", "html", "content_type", "location"}
    favicon: str | None = None  # "brand" | "other" | None (no favicon served)
    screenshot: str | None = None  # "brand" | "similar" | "other" | None
    whois: dict[str, Any] | None = None  # {"age_days", "registrar", "registrant"}
    reputation: dict[str, str] = field(default_factory=dict)  # provider → status
    infra: dict[str, Any] = field(default_factory=dict)  # ip, cert_fp, tracking_ids, registrant
    cloak: dict[str, Any] = field(
        default_factory=dict
    )  # {"mode": ip|ua|param|referer, "benign_html": ...}
    # suspicious shops: the Meta ads that point here, the company-registry answer for the number the
    # page prints, and what a Google search for reviews of the shop returns
    ads: list[dict[str, Any]] = field(
        default_factory=list
    )  # [{page_name, page_id, text, countries, start_date}]
    registry: dict[str, Any] = field(
        default_factory=dict
    )  # {"number", "status": found|not_found|dissolved, "name"}
    reviews: list[dict[str, Any]] = field(default_factory=list)  # [{title, url, snippet}]
    pages: dict[str, str] = field(default_factory=dict)  # other pages of the site: {"/terms/": html}
    behind_warning: str | None = None  # the site behind a Cloudflare "Suspected Phishing" interstitial

    @property
    def is_phishing(self) -> bool:
        return self.label == "phishing"

    @classmethod
    def from_json(cls, row: dict[str, Any]) -> Scenario:
        url = row["url"]
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        ev = row.get("evidence", {})
        return cls(
            url=url,
            host=host,
            brand=row["brand"],
            label=row["label"],
            notes=row.get("notes", ""),
            dns=ev.get("dns"),
            http=ev.get("http"),
            favicon=ev.get("favicon"),
            screenshot=ev.get("screenshot"),
            whois=ev.get("whois"),
            reputation=dict(ev.get("reputation", {})),
            infra=dict(ev.get("infra", {})),
            cloak=dict(ev.get("cloak", {})),
            ads=list(ev.get("ads", [])),
            registry=dict(ev.get("registry", {})),
            reviews=list(ev.get("reviews", [])),
            pages=dict(ev.get("pages", {})),
            behind_warning=ev.get("behind_warning"),
        )


class FixtureStore:
    def __init__(self, scenarios: list[Scenario]) -> None:
        self._by_host: dict[str, Scenario] = {}
        self._extra: dict[str, Scenario] = {}
        for s in scenarios:
            if s.host in self._by_host:
                raise ValueError(f"duplicate scenario host: {s.host}")
            self._by_host[s.host] = s

    @classmethod
    def from_paths(cls, paths: list[Path]) -> FixtureStore:
        scenarios: list[Scenario] = []
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    scenarios.append(Scenario.from_json(json.loads(line)))
        return cls(scenarios)

    @classmethod
    def from_dir(cls, directory: Path = GOLDEN_DIR) -> FixtureStore:
        return cls.from_paths(sorted(directory.glob("*.jsonl")))

    def add_extras(self, directory: Path = NETWORKS_DIR) -> None:
        for path in sorted(directory.glob("*.jsonl")) if directory.is_dir() else []:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    s = Scenario.from_json(json.loads(line))
                    if s.host in self._by_host or s.host in self._extra:
                        raise ValueError(f"duplicate scenario host: {s.host}")
                    self._extra[s.host] = s

    def get(self, host: str) -> Scenario | None:
        h = host.lower().rstrip(".")
        return self._by_host.get(h) or self._extra.get(h)

    def all(self) -> list[Scenario]:
        return list(self._by_host.values())

    def everything(self) -> list[Scenario]:
        """The golden scenarios and the extras (demo networks) — for searches that look across the recorded world,
        like the Ad Library; ``all()`` stays the golden set the metrics are measured on."""
        return [*self._by_host.values(), *self._extra.values()]

    def by_label(self, label: str) -> list[Scenario]:
        return [s for s in self._by_host.values() if s.label == label]

    def by_ip(self, ip: str) -> list[Scenario]:
        return [s for s in (*self._by_host.values(), *self._extra.values()) if s.infra.get("ip") == ip]

    def by_cert(self, fp: str) -> list[Scenario]:
        return [s for s in (*self._by_host.values(), *self._extra.values()) if s.infra.get("cert_fp") == fp]

    def for_brand(self, brand: str) -> list[Scenario]:
        return [s for s in self._by_host.values() if s.brand == brand]

    def __len__(self) -> int:
        return len(self._by_host)


@lru_cache(maxsize=1)
def default_store() -> FixtureStore:
    store = FixtureStore.from_dir()
    store.add_extras()
    return store
