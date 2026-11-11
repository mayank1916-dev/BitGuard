"""Signer Backend abstraction package for Signer Shim (Milestone S36)."""

import os

from services.signer_shim.backends.aws_kms import AwsKmsBackend
from services.signer_shim.backends.base import SignerBackend
from services.signer_shim.backends.disposable import DisposableKeyBackend
from services.signer_shim.backends.mpc_hsm import MpcHsmStubBackend
from services.signer_shim.backends.vault_transit import VaultTransitBackend

__all__ = [
    "SignerBackend",
    "DisposableKeyBackend",
    "AwsKmsBackend",
    "VaultTransitBackend",
    "MpcHsmStubBackend",
    "get_signer_backend",
]


def get_signer_backend(backend_type: str | None = None) -> SignerBackend:
    """Factory creating the configured SignerBackend implementation.

    Default: DisposableKeyBackend (local ephemeral testnet key).
    Supported types: 'disposable', 'aws_kms', 'vault_transit', 'mpc_hsm'.
    """
    raw_type = backend_type if backend_type is not None else os.getenv("SIGNER_BACKEND", "disposable")
    b_type = (raw_type or "disposable").lower().strip()
    if b_type == "disposable":
        return DisposableKeyBackend()
    elif b_type in ("aws_kms", "kms"):
        key_id = os.getenv("AWS_KMS_KEY_ID", "alias/bitguard-hot-wallet")
        region = os.getenv("AWS_REGION", "us-east-1")
        return AwsKmsBackend(key_id=key_id, region_name=region)
    elif b_type in ("vault_transit", "vault"):
        vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        key_name = os.getenv("VAULT_TRANSIT_KEY", "bitguard-hot-wallet")
        token = os.getenv("VAULT_TOKEN", "")
        return VaultTransitBackend(vault_addr=vault_addr, key_name=key_name, token=token)
    elif b_type in ("mpc_hsm", "mpc", "hsm"):
        vendor = os.getenv("MPC_VENDOR", "generic_mpc")
        cluster_id = os.getenv("MPC_CLUSTER_ID", "cluster-alpha-01")
        return MpcHsmStubBackend(vendor=vendor, cluster_id=cluster_id)
    else:
        # Fail closed on unknown backend type
        raise ValueError(f"Unknown or unsupported SignerBackend type: '{b_type}'")
