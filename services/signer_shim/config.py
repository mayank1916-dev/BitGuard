"""Configuration settings for Signer Shim service (Enforcement Point)."""

import json
from typing import Any

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

    # Redis endpoint for atomic nonce consumption (SET NX)
    redis_url: str = "redis://redis:6379/0"
    nonce_ttl_seconds: int = 120

    # Internal network ACL shared secret (mTLS simulation in lab)
    internal_auth_token: str = "bitguard-shim-internal-lab-token-2026"

    # Dead-man heartbeat timeout threshold in seconds (fail-closed if expired)
    heartbeat_timeout_seconds: float = 20.0

    # Disposable testnet private key (strictly isolated to signer shim)
    # Default is Anvil Account #0 standard disposable dev key
    testnet_private_key: str = (
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )

    # Optional pre-configured BitGuard public key set JSON string
    public_key_set_json: str = ""

    def get_public_key_dict(self) -> dict[str, Any]:
        """Parses public_key_set_json into a dictionary, or returns empty dict."""
        if not self.public_key_set_json.strip():
            return {}
        try:
            return json.loads(self.public_key_set_json)
        except Exception:
            return {}


settings = SignerShimSettings()
