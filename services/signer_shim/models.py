"""Data models for Signer Shim signing requests and responses (Milestone S11 / F1)."""

from pydantic import BaseModel, ConfigDict, Field


class SignRequest(BaseModel):
    """Payload submitted to the Signer Shim /sign endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    raw_tx_bytes: str = Field(description="Raw unsigned transaction payload hex string")
    token: str = Field(description="Compact Ed25519 BitGuard approval token")
    wallet: str | None = Field(default=None, description="Expected hot wallet address")
    chain: str | None = Field(default=None, description="Expected target blockchain")


class SignResponse(BaseModel):
    """Cryptographic signature response issued by the Signer Shim."""

    model_config = ConfigDict(populate_by_name=True)

    status: str = Field(default="SIGNED", description="Signing outcome (SIGNED)")
    signature: str = Field(description="Serialized hex signature or signed raw transaction")
    tx_hash: str = Field(description="Computed keccak256 transaction hash")
    digest: str = Field(description="Signing digest recomputed from raw bytes")
    chain: str = Field(description="Verified target blockchain")
    wallet: str = Field(description="Signer hot wallet address")
    r: str = Field(description="ECDSA r component hex")
    s: str = Field(description="ECDSA s component hex")
    v: int = Field(description="ECDSA recovery identifier v")


class RefusalResponse(BaseModel):
    """Structured refusal response returned on token verification or invariant failure."""

    model_config = ConfigDict(populate_by_name=True)

    status: str = Field(default="REFUSED", description="Signing refusal status (REFUSED)")
    reason_code: str = Field(description="Standardized error code explaining the refusal")
    detail: str = Field(description="Explanatory diagnostic detail")
