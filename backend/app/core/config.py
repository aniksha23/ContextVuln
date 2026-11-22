from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration. Every tunable number in the project lives here
    (override any of them via environment variables or a .env file).
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ---- App ----
    app_name: str = "ContextVuln API"
    app_env: str = "development"
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    # If set, every /api/* call (except /api/health) must send header  X-API-Key: <value>
    api_key: str = ""

    # ---- Threat-intel source ----
    # "mock": offline fixtures filtered by the repo's requirements.txt (demo / dev)
    # "live": Member 3's ThreatIntelAgent (OSV + EPSS + KEV)
    intel_mode: str = "mock"
    # Dependency-exposure analysis (is a pinned package pulled in by something the app imports?)
    # "auto" = online when intel_mode == "live", off otherwise; or force "online" / "off".
    dep_graph_mode: str = "auto"
    max_dep_lookups: int = 150

    # ---- LLM (Agent 3). Never used for math. ----
    llm_enabled: bool = True
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    llm_timeout_s: float = 20.0
    llm_max_retries: int = 2
    llm_max_concurrency: int = 3
    # Ask PyPI whether the suggested fixed version really exists (needs network).
    validate_versions_online: bool = False

    # ---- Scoring: Multi-Attribute Utility weights (must sum to 1.0) ----
    w_epss: float = 0.45
    w_cvss: float = 0.35
    w_kev: float = 0.20
    # EPSS is heavily skewed (most CVEs < 0.05). signal = epss ** epss_exponent
    # (0.5 = square root). Use 1.0 for the original linear behaviour.
    epss_exponent: float = 0.5

    # ---- Reachability confidence values ----
    conf_direct: float = 1.0
    conf_transitive: float = 0.7
    # Prior used when analysis is inconclusive (NEEDS_REVIEW findings)
    conf_needs_review: float = 0.5
    # Multiplier when the advisory names no function (symbol_source == "fallback"): package is used,
    # but we cannot show the vulnerable code path is.
    conf_package_level: float = 0.6

    # ---- Business criticality is clamped into this band so it cannot dominate ----
    criticality_min: float = 0.7
    criticality_max: float = 1.5

    # ---- Tier thresholds (score out of 100) ----
    tier_critical: float = 60.0
    tier_monitor: float = 30.0
    # Floors: reachable + CISA-KEV is always at least CRITICAL; reachable + CVSS>=9 at least MONITOR
    kev_floor_score: float = 60.0
    high_cvss_threshold: float = 9.0
    high_cvss_floor_score: float = 30.0
    # Cap for confirmed-unreachable findings
    suppressed_cap: float = 15.0

    # ---- Orchestration ----
    max_retries: int = 1
    max_concurrency: int = 6

    # ---- Input limits ----
    max_upload_mb: int = 50
    max_uncompressed_mb: int = 200
    max_zip_files: int = 20000
    max_compression_ratio: int = 200
    git_clone_timeout_s: int = 60
    max_jobs_kept: int = 100


    @property
    def dep_graph_enabled(self) -> bool:
        if self.dep_graph_mode == "online":
            return True
        if self.dep_graph_mode == "off":
            return False
        return self.intel_mode == "live"


settings = Settings()
