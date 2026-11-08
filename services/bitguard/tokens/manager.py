"""Token Manager coordinating key sets and approval token issuance (Milestone S11)."""

import logging

from services.bitguard.models import DecodedTx
from services.bitguard.tokens.issuer import issue_token
from services.bitguard.tokens.keys import KeySet, TokenKey
from services.bitguard.tokens.models import TokenVerificationResult
from services.bitguard.tokens.verifier import verify_token

logger = logging.getLogger("bitguard.tokens.manager")


class TokenIssuanceBlockedError(Exception):
    """Raised when token issuance is blocked by circuit breaker operational state."""


class TokenManager:
    """Manages BitGuard Ed25519 approval token keys and issuance."""

    def __init__(self, key_set: KeySet | None = None) -> None:
        self.key_set = key_set or KeySet()
        # Initialize default active key if key set is empty
        if not self.key_set._keys:
            default_key = TokenKey.generate("bg-ed25519-v1")
            self.key_set.add_key(default_key, set_active=True)
            logger.info("Initialized default BitGuard Ed25519 signing key 'bg-ed25519-v1'")

    def issue(
        self,
        decoded_tx: DecodedTx,
        wallet: str,
        chain: str,
        ttl_seconds: int = 60,
        nonce: str | None = None,
        now: int | None = None,
        epoch: int | None = None,
    ) -> str:
        """Issues a signed approval token using the current active key."""
        from services.bitguard.engine.breaker_store import breaker_store
        from services.bitguard.models import BreakerStateEnum

        b_state = breaker_store.get_state()
        if b_state == BreakerStateEnum.LOCKDOWN:
            try:
                from services.bitguard.metrics import record_token_refusal

                record_token_refusal("breaker_lockdown")
            except Exception:
                pass
            raise TokenIssuanceBlockedError(
                "Approval token issuance rejected: circuit breaker is in LOCKDOWN mode"
            )

        active_epoch = epoch
        if active_epoch is None:
            try:
                from services.bitguard.breaker.epoch_store import token_epoch_store

                active_epoch = token_epoch_store.get_current_epoch()
            except Exception:
                active_epoch = 1

        token = issue_token(
            decoded_tx=decoded_tx,
            wallet=wallet,
            chain=chain,
            key_set=self.key_set,
            ttl_seconds=ttl_seconds,
            nonce=nonce,
            now=now,
            epoch=active_epoch,
        )
        try:
            from services.bitguard.metrics import record_token_issue

            active_key = self.key_set.get_active_key()
            record_token_issue(active_key.kid)
        except Exception:
            pass

        return token

    def verify(self, token: str, now: int | None = None) -> TokenVerificationResult:
        """Verifies an approval token using the configured key set."""
        return verify_token(token=token, key_set=self.key_set, now=now)

    def rotate_key(self, new_kid: str) -> TokenKey:
        """Generates and activates a new signing key while maintaining verification for older keys."""
        new_key = TokenKey.generate(kid=new_kid)
        self.key_set.add_key(new_key, set_active=True)
        logger.info("Rotated active BitGuard signing key to '%s'", new_kid)
        return new_key

    def retire_key(self, kid: str) -> None:
        """Retires a key ID from active use and verification."""
        self.key_set.retire_key(kid)
        logger.info("Retired BitGuard signing key '%s'", kid)


# Global singleton instance
token_manager = TokenManager()
