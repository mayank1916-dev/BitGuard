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
    local_fallback_wallet_cap: int = 5_000

    # Shadow mode and promotion defaults (F7)
    shadow_min_days: int = 14
    shadow_max_false_positive_rate: float = 0.001

    # RBAC and JWT Authentication settings (F9 basic / S05)
    jwt_secret: str = "bitguard-dev-secret-key-32-chars-min-at-least-256-bits"
    jwt_algorithm: str = "HS256"
    jwt_expiration_seconds: int = 3600
    dev_auth_bypass: bool = True


settings = BitGuardSettings()
