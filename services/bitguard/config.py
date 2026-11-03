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
    ledger_mock_url: str = "http://ledger_mock:8002"

    # Policy and evaluation defaults
    approval_token_ttl_seconds: int = 60
    single_tx_usd_default: float = 50_000.0
    wallet_limit_usd_default: float = 100_000.0
    global_limit_usd_default: float = 500_000.0
    new_recipient_usd_default: float = 10_000.0


settings = BitGuardSettings()
