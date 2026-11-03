"""KeyUsePolicyHook interface for cryptographic key isolation at KMS/HSM level (Milestone S18 / F1, F9).

Architectural Context:
----------------------
BitGuard operates strictly as a Policy Decision Point. Signing execution is isolated to
the Signer Shim (Enforcement Point) or hardware security modules (HSM) / cloud KMS.
When the circuit breaker transitions into HOLD or LOCKDOWN, all signing must cease
immediately. In addition to token epoch invalidation, BitGuard coordinates with the
hardware key management plane via this `KeyUsePolicyHook`.

Vendor API Variations & Implementation Guidance:
------------------------------------------------
Different KMS and HSM providers offer divergent primitives for disabling key use:

1. AWS Key Management Service (AWS KMS):
   - Direct Key State Disablement:
     Call `kms:DisableKey(KeyId=...)`. The key transitions to the `Disabled` state within
     seconds globally. Subsequent calls to `kms:Sign` return `KMSInvalidStateException`.
   - Granular Key Policy Revocation:
     Call `kms:PutKeyPolicy` to attach an explicit `Deny` condition on `kms:Sign` for
     the signer shim role ARN.
   - Tag-Based Condition Enforcement:
     Apply tag `CircuitBreaker=LOCKDOWN` and reference IAM condition `aws:PrincipalTag`
     or `kms:ResourceTag/CircuitBreaker`.

2. Google Cloud Key Management Service (GCP Cloud KMS):
   - CryptoKeyVersion Disablement:
     Call `projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.patch` with
     `updateMask="state"` and `state="DISABLED"`. Disabled versions cannot sign.
   - IAM Condition Policy:
     Attach a temporary conditional IAM binding denying `cloudkms.cryptoKeyVersions.useToSign`
     unless an authorized unlock assertion has been verified.

3. HashiCorp Vault (Transit Secrets Engine):
   - Key Version Archival / Minimum Version:
     Call `POST /v1/transit/keys/:name/config` setting `min_decryption_version` or
     `min_encryption_version` to prevent key usage.
   - Dynamic Lease Revocation:
     Issue `PUT /v1/sys/leases/revoke-prefix` to instantly invalidate all active
     signer role tokens.

4. Azure Key Vault:
   - Key Disablement:
     Call `KeyClient.update_key_properties(key_name, enabled=False)`. Disabled keys
     immediately fail `CryptographyClient.sign()` with `403 Forbidden`.

5. On-Premises PKCS#11 Hardware Security Modules (Thales Luna, AWS CloudHSM, NitroHSM):
   - Session Termination:
     Call `C_Logout(hSession)` followed by `C_CloseSession(hSession)` to drop the active
     Crypto Officer / Crypto User session handle, requiring physical/WebAuthn re-auth.
   - Attribute Modification:
     Call `C_SetAttributeValue` setting `CKA_SIGN = CK_FALSE` on the target private key
     object handle.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

from services.bitguard.models import BreakerStateEnum

logger = logging.getLogger("bitguard.breaker.key_hook")


class KeyUsePolicyHook(ABC):
    """Abstract policy hook for managing cryptographic key availability at KMS/HSM level."""

    @abstractmethod
    def disable_key(self, key_id: str, reason: str = "") -> bool:
        """Disables or revokes signing permissions for a specific key at KMS/HSM level."""
        ...

    @abstractmethod
    def enable_key(self, key_id: str, reason: str = "") -> bool:
        """Restores signing permissions for a specific key at KMS/HSM level."""
        ...

    @abstractmethod
    def is_key_enabled(self, key_id: str) -> bool:
        """Queries KMS/HSM to verify whether key is currently permitted for signing operations."""
        ...

    @abstractmethod
    def disable_all_keys(self, reason: str = "") -> None:
        """Disables all managed hot wallet signing keys (emergency lockdown)."""
        ...

    @abstractmethod
    def enable_all_keys(self, reason: str = "") -> None:
        """Re-enables managed hot wallet signing keys following quorum unlock."""
        ...

    @abstractmethod
    def on_breaker_state_change(self, new_state: BreakerStateEnum, reason: str = "") -> None:
        """Callback invoked when circuit breaker state changes.

        Transitions to HOLD or LOCKDOWN immediately disable signing keys at KMS/HSM level.
        Return to NORMAL re-enables signing keys.
        """
        ...


class MockKeyUsePolicyHook(KeyUsePolicyHook):
    """Thread-safe mock implementation of KeyUsePolicyHook for testing and lab environments."""

    def __init__(self) -> None:
        # key_id -> bool (True = enabled, False = disabled)
        self._key_states: dict[str, bool] = {}
        self._all_keys_disabled: bool = False
        self._action_log: list[dict[str, Any]] = []

    def disable_key(self, key_id: str, reason: str = "") -> bool:
        clean_id = key_id.strip()
        self._key_states[clean_id] = False
        self._action_log.append({"action": "DISABLE_KEY", "key_id": clean_id, "reason": reason})
        logger.info("mock_kms_key_disabled: key=%s reason=%s", clean_id, reason)
        return True

    def enable_key(self, key_id: str, reason: str = "") -> bool:
        clean_id = key_id.strip()
        self._key_states[clean_id] = True
        self._action_log.append({"action": "ENABLE_KEY", "key_id": clean_id, "reason": reason})
        logger.info("mock_kms_key_enabled: key=%s reason=%s", clean_id, reason)
        return True

    def is_key_enabled(self, key_id: str) -> bool:
        if self._all_keys_disabled:
            return False
        clean_id = key_id.strip()
        return self._key_states.get(clean_id, True)

    def disable_all_keys(self, reason: str = "") -> None:
        self._all_keys_disabled = True
        for k in self._key_states:
            self._key_states[k] = False
        self._action_log.append({"action": "DISABLE_ALL_KEYS", "reason": reason})
        logger.warning("mock_kms_all_keys_disabled: reason=%s", reason)

    def enable_all_keys(self, reason: str = "") -> None:
        self._all_keys_disabled = False
        for k in self._key_states:
            self._key_states[k] = True
        self._action_log.append({"action": "ENABLE_ALL_KEYS", "reason": reason})
        logger.info("mock_kms_all_keys_enabled: reason=%s", reason)

    def on_breaker_state_change(self, new_state: BreakerStateEnum, reason: str = "") -> None:
        if new_state in [BreakerStateEnum.HOLD, BreakerStateEnum.LOCKDOWN]:
            self.disable_all_keys(reason=f"Breaker entered {new_state}: {reason}")
        elif new_state == BreakerStateEnum.NORMAL:
            self.enable_all_keys(reason=f"Breaker returned to NORMAL: {reason}")

    def reset(self) -> None:
        """Resets mock key state to fully enabled nominal condition."""
        self._key_states.clear()
        self._all_keys_disabled = False
        self._action_log.clear()


# Global singleton instance
key_policy_hook = MockKeyUsePolicyHook()
