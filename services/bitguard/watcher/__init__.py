"""Delegation and code watcher module for hot wallet addresses (Milestone S17 / F6)."""

from services.bitguard.watcher.inspector import (
    EIP7702_PREFIX,
    WatcherInspector,
    extract_eip7702_delegate,
    inspector,
    is_eip7702_delegation,
)
from services.bitguard.watcher.provider_pool import (
    ProviderDisagreementError,
    ProviderPool,
    provider_pool,
)
from services.bitguard.watcher.router import router
from services.bitguard.watcher.store import WatchedAddressStore, watched_address_store
from services.bitguard.watcher.worker import DelegationWatcher, delegation_watcher

__all__ = [
    "EIP7702_PREFIX",
    "DelegationWatcher",
    "ProviderDisagreementError",
    "ProviderPool",
    "WatchedAddressStore",
    "WatcherInspector",
    "delegation_watcher",
    "extract_eip7702_delegate",
    "inspector",
    "is_eip7702_delegation",
    "provider_pool",
    "router",
    "watched_address_store",
]
