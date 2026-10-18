"""System settings (environment / .env) — spec §13.

Two layers exist on purpose:

* **Security limits** live in :mod:`brandwatch.security.limits` and are NOT settable here.
* **Economic limits** and everything operational (URLs, DEMO_MODE, provider routing, keys) are
  settable per deployment through the environment.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EconomicLimits(BaseModel):
    """Per-workspace spend guardrails (spec §13). Zero means "do not spend"."""

    max_api_calls: int = Field(default=1000, ge=0)
    max_residential_gb: float = Field(default=0.0, ge=0)
    max_daily_spend: float = Field(default=0.0, ge=0)
    max_investigation_cost: float = Field(default=0.0, ge=0)
    max_candidate_count: int = Field(default=500, ge=0)


class ProviderRoute(BaseModel):
    primary: str
    fallback: list[str] = Field(default_factory=list)


# Spec §4 default routing table.
DEFAULT_PROVIDER_ROUTES: dict[str, ProviderRoute] = {
    "reputation": ProviderRoute(
        primary="virustotal",
        fallback=["urlhaus", "safebrowsing"],  # every member is asked, see enrichment
    ),
    "whois": ProviderRoute(primary="whoisxml", fallback=["rdap", "local_whois"]),
    "dns": ProviderRoute(primary="local_dns", fallback=[]),
    "passive_dns": ProviderRoute(primary="virustotal", fallback=["securitytrails"]),
    "cert": ProviderRoute(primary="crtsh", fallback=["certspotter", "censys"]),
    # ScraperAPI answers when SerpAPI has no key, no quota left, or is down (a provider without a key is skipped in live mode)
    "search": ProviderRoute(primary="serpapi", fallback=["scraperapi", "serper"]),
    "host": ProviderRoute(primary="shodan", fallback=["censys"]),
    "browser": ProviderRoute(primary="playwright", fallback=["httpx_datacenter"]),
    "urlscan": ProviderRoute(primary="urlscan", fallback=[]),
    "geo": ProviderRoute(primary="ipapi", fallback=[]),
    "llm": ProviderRoute(primary="openai", fallback=[]),
    # suspicious shops: ads that sell the brand's products, and company-number registries
    # (registries are picked per country by detection/merchant.py, not tried as a chain)
    "ads": ProviderRoute(primary="searchapi", fallback=[]),
    # fake social accounts: Facebook pages / Instagram profiles under the brand's name (same key)
    "social": ProviderRoute(primary="searchapi", fallback=[]),
    # what ChatGPT / Gemini / Google AI Mode tell users about the brand's contacts (same key)
    "ai_answers": ProviderRoute(primary="searchapi", fallback=[]),
    "registry": ProviderRoute(
        primary="il_companies", fallback=["companies_house", "vies", "gleif", "opencorporates"]
    ),
}

# provider name -> Settings attribute that holds its key
PROVIDER_KEY_FIELDS: dict[str, str] = {
    "virustotal": "virustotal_api_key",
    "urlscan": "urlscan_api_key",
    "shodan": "shodan_api_key",
    "censys": "censys_api_secret",
    "whoisxml": "whoisxml_api_key",
    "securitytrails": "securitytrails_api_key",
    "serpapi": "serpapi_api_key",
    "scraperapi": "scraperapi_api_key",
    "serper": "serper_api_key",
    "abuseipdb": "abuseipdb_api_key",
    "safebrowsing": "safebrowsing_api_key",
    "urlhaus": "urlhaus_api_key",
    "openai": "openai_api_key",
    "searchapi": "searchapi_api_key",
    "companies_house": "companies_house_api_key",
    "opencorporates": "opencorporates_api_key",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    # --- core -------------------------------------------------------------------------------
    database_url: str = "sqlite:///./brandwatch.db"
    redis_url: str | None = None
    demo_mode: bool = True
    environment: str = "development"
    evidence_dir: str = "./evidence_store"

    # --- continuous intelligence (Phase 3) ----------------------------------------------
    queue_backend: str = "thread"  # thread | arq
    scheduler_enabled: bool = False
    scheduler_interval_seconds: int = Field(default=60, ge=5)
    nrd_feed_path: str | None = None  # newline-delimited newly-registered domains (NRD) feed
    notify_channels: list[str] = Field(
        default_factory=lambda: ["log"]
    )  # log | slack | telegram | email
    notify_min_severity: str = "high"
    slack_webhook_url: SecretStr | None = None
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_to: list[str] = Field(default_factory=list)
    residential_proxy_url: SecretStr | None = None  # Phase 5 Tier-4 probe (never for attacks)
    # dashboard globe: where the monitored brand "lives" (arcs start here)
    openai_model: str = "gpt-4o-mini"
    # VirusTotal public API: 4 requests/minute. The intel page paces itself to this; raise
    # it for a premium key.
    virustotal_rate_per_minute: int = 4
    # demo only: make one provider fail once per process so the fallback chain and the alert panel
    # can be shown live (e.g. DEMO_FLAKY_PROVIDER=virustotal)
    demo_flaky_provider: str = ""
    # on shutdown, wait up to this long for in-process jobs before exiting
    shutdown_job_wait_seconds: float = 30.0
    # optional origin of the dashboard globe's arcs (e.g. your SOC or the brand's head office);
    # unset → the globe shows where the kits are hosted, without arcs (demo mode uses ShopNova HQ)
    home_label: str | None = None
    home_lat: float | None = None
    home_lon: float | None = None
    log_level: str = "INFO"
    # the "built by" card on How it works: a case-study video, shown only when set (the public demo
    # build sets it; a private deployment leaves it empty)
    case_study_url: str = ""

    # --- auth -------------------------------------------------------------------------------
    secret_key: SecretStr = SecretStr("change-me-in-real-deployments-please")
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = Field(default=12 * 60, ge=5)
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: SecretStr = SecretStr("change-me")

    # --- secrets at rest ----------------------------------------------------------------------
    local_kek_b64: SecretStr | None = None  # dev only; production: KMS-held KEK

    # --- economics / providers ----------------------------------------------------------------
    economic_limits: EconomicLimits = Field(default_factory=EconomicLimits)
    providers: dict[str, ProviderRoute] = Field(
        default_factory=lambda: dict(DEFAULT_PROVIDER_ROUTES)
    )

    virustotal_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    censys_api_id: SecretStr | None = None
    censys_api_secret: SecretStr | None = None
    whoisxml_api_key: SecretStr | None = None
    securitytrails_api_key: SecretStr | None = None
    serpapi_api_key: SecretStr | None = None
    serper_api_key: SecretStr | None = None
    scraperapi_api_key: SecretStr | None = None  # scraperapi.com: Google search when SerpAPI cannot answer
    abuseipdb_api_key: SecretStr | None = None
    safebrowsing_api_key: SecretStr | None = (
        None  # Google Cloud API key with the Safe Browsing API enabled
    )
    urlhaus_api_key: SecretStr | None = (
        None  # abuse.ch Auth-Key (free account, required since 2025)
    )
    openai_api_key: SecretStr | None = None
    searchapi_api_key: SecretStr | None = None  # SearchApi.io — Meta Ad Library, social accounts, AI answers
    companies_house_api_key: SecretStr | None = None  # UK Companies House (free)
    opencorporates_api_key: SecretStr | None = None  # OpenCorporates (paid, optional)

    @field_validator("secret_key")
    @classmethod
    def _secret_key_long_enough(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value().encode()) < 32:
            raise ValueError("SECRET_KEY must be at least 32 bytes (HS256 minimum)")
        return v

    @field_validator("database_url")
    @classmethod
    def _non_empty_url(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("DATABASE_URL must not be empty")
        return v

    # --- helpers --------------------------------------------------------------------------------
    def provider_key(self, provider: str) -> str | None:
        """Plaintext key for a provider or ``None``. Never log the return value."""
        attr = PROVIDER_KEY_FIELDS.get(provider)
        if attr is None:
            return None
        value: SecretStr | None = getattr(self, attr)
        if value is None:
            return None
        secret = value.get_secret_value().strip()
        return secret or None

    def has_key(self, provider: str) -> bool:
        return self.provider_key(provider) is not None

    def known_secret_values(self) -> list[str]:
        """All configured secrets, for log redaction."""
        values = [
            self.secret_key.get_secret_value(),
            self.bootstrap_admin_password.get_secret_value(),
        ]
        values += [k for p in PROVIDER_KEY_FIELDS if (k := self.provider_key(p))]
        if self.local_kek_b64:
            values.append(self.local_kek_b64.get_secret_value())
        return [v for v in values if v]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """For tests that mutate the environment."""
    get_settings.cache_clear()
