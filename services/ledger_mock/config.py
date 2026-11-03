"""Configuration settings for Ledger Mock service."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class LedgerMockSettings(BaseSettings):
    """Ledger Mock configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="LEDGER_MOCK_",
        env_file=".env",
        extra="ignore",
    )

    environment: str = "development"
    service_name: str = "ledger_mock"
    host: str = "0.0.0.0"
    port: int = 8002
    log_level: str = "INFO"
    database_url: str = "postgresql://postgres:postgres@postgres:5432/bitguard"


settings = LedgerMockSettings()
