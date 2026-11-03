"""Configuration settings for Signer Shim service."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class SignerShimSettings(BaseSettings):
    """Signer Shim configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="SIGNER_SHIM_",
        env_file=".env",
        extra="ignore",
    )

    environment: str = "development"
    service_name: str = "signer_shim"
    host: str = "0.0.0.0"
    port: int = 8001
    log_level: str = "INFO"

    # Foundry Anvil local EVM endpoint
    anvil_url: str = "http://anvil:8545"

    # Disposable testnet private key (strictly isolated to signer shim)
    # Default is Anvil Account #0 standard disposable dev key
    testnet_private_key: str = (
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )


settings = SignerShimSettings()
