"""Configuration settings for BitGuard firewall service."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class BitGuardSettings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="BITGUARD_",
        env_file=".env",
        extra="ignore",
    )

    environment: str = "development"
    service_name: str = "bitguard"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    # Infrastructure endpoints
    database_url: str = "postgresql://postgres:postgres@postgres:5432/bitguard"
    redis_url: str = "redis://redis:6379/0"
    anvil_url: str = "http://anvil:8545"

    # Internal service endpoints
    signer_shim_url: str = "http://signer_shim:8001"
    signer_shim_internal_auth_token: str = "bitguard-shim-internal-lab-token-2026"
    ledger_mock_url: str = "http://ledger_mock:8002"

    # Gateway mTLS settings (S12)
    mtls_ca_cert_path: str = ""
    mtls_allowed_sans: list[str] = [
        "spiffe://exchange.internal/workload/custody",
        "custody.exchange.internal",
        "demo_custody",
    ]

    # Policy and evaluation defaults
    approval_token_ttl_seconds: int = 60
    single_tx_usd_default: float = 50_000.0
    wallet_limit_usd_default: float = 100_000.0
    global_limit_usd_default: float = 500_000.0
    new_recipient_usd_default: float = 10_000.0

    # Limit store defaults (F3 / S07)
    limit_reservation_ttl_seconds: int = 120
    limit_sliding_window_seconds: int = 3600
    local_caps_enabled: bool = True
    local_fallback_cap: int = 10_000  # Conservative local cap (smallest integer units)

    # Risk Profiler (S27)
    profiler_enabled: bool = False
    profiler_lists_dir: str = "lists"
    profiler_cache_ttl_seconds: int = 3600
    # Pre-sign Simulation (S28 / F5)
    simulation_enabled: bool = False
    simulation_timeout_ms: float = 300.0
    local_fallback_wallet_cap: int = 5_000

    # Pricing Sanity (S31 / F13)
    price_api_url: str = ""
    price_api_key: str = ""
    price_provider_name: str = "mock_aggregate"
    price_max_age_seconds: int = 300
    price_max_deviation_pct: float = 5.0

    # Shadow mode and promotion defaults (F7)
    shadow_min_days: int = 14
    shadow_max_false_positive_rate: float = 0.001

    # RBAC and JWT Authentication settings (F9 basic / S05)
    jwt_secret: str = "bitguard-dev-secret-key-32-chars-min-at-least-256-bits"
    jwt_algorithm: str = "HS256"
    jwt_expiration_seconds: int = 3600
    dev_auth_bypass: bool = True

    # OIDC Authentication settings (Milestone S15 / F9)
    oidc_enabled: bool = True
    oidc_issuer_url: str = "http://localhost:8080/realms/bitguard"
    oidc_client_id: str = "bitguard-api"
    oidc_client_secret: str = "bitguard-api-client-secret-2026"
    oidc_jwks_url: str = "http://localhost:8080/realms/bitguard/protocol/openid-connect/certs"

    # WebAuthn Hardware Authentication settings (Milestone S15 / F9)
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "BitGuard Defensive Firewall"
    webauthn_origin: str = "http://localhost:3000"
    webauthn_allowed_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://console.bitguard.exchange",
    ]
    step_up_token_ttl_seconds: int = 900  # 15 minutes
    enforce_step_up: bool = False

    # Circuit breaker trigger settings (Milestone S18 / F9, F14)
    breaker_auto_triggers_enabled: bool = False
    breaker_denials_threshold: int = 5
    breaker_unmatched_intents_threshold: int = 3
    breaker_velocity_spike_threshold_usd: float = 1_000_000.0

    # Incident Runbook Automation and Escalation settings (Milestone S19 / F14)
    runbooks_dir: str = "policy/runbooks"
    oncall_slack_webhook: str = ""
    oncall_pagerduty_routing_key: str = ""
    oncall_ack_timeout_seconds: int = 300
    incident_target_time_to_contain_ms: float = 100.0

    # Tamper-evident Audit Chain and Object-Lock Anchoring (Milestone S21 / F18)
    audit_anchor_enabled: bool = True
    audit_anchor_interval_seconds: int = 60
    audit_minio_endpoint: str = "http://minio:9000"
    audit_minio_access_key: str = "minioadmin"
    audit_minio_secret_key: str = "minioadmin"
    audit_minio_bucket: str = "bitguard-audit-anchors"
    audit_siem_enabled: bool = False
    audit_siem_format: str = "syslog"
    audit_siem_syslog_host: str = "localhost"
    audit_siem_syslog_port: int = 514
    audit_siem_otel_endpoint: str = "http://localhost:4318/v1/logs"

    # Versioned Policy Management settings (Milestone S20 / Section D)
    policy_cooldown_seconds: int = 60  # Default 60 seconds in lab/dev, 86400 (24h) in prod
    policy_rollback_window_seconds: int = 300  # 5 minutes auto-rollback observation window
    policy_signing_ed25519_privkey: str = ""  # Hex-encoded Ed25519 seed or privkey for release authority
    policy_signing_ed25519_pubkey: str = ""  # Hex-encoded Ed25519 pubkey for verifying activation

    # Self-protection and High Availability (Milestone S24 / F17)
    instance_id: str = "bitguard-1"
    heartbeat_interval_seconds: float = 5.0
    heartbeat_sender_enabled: bool = True
    config_integrity_check_interval_seconds: int = 60
    rate_limit_enabled: bool = True
    rate_limit_admin_per_minute: int = 10
    rate_limit_standard_per_minute: int = 120
    break_glass_max_duration_seconds: int = 14400  # 4 hours max


settings = BitGuardSettings()
