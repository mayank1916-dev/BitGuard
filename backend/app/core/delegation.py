from typing import Any

from backend.app.models import SigningRequest


class DelegationGuard:
    """
    Guard for EIP-7702 delegation authorization requests and nonce protection.
    - Enforces deny-by-default for authorization_7702 requests unless the delegate
      address is explicitly in delegate_allowlist.
    - Detects batch nonce-spraying patterns: flags requests with consecutive nonces
      for the same hot wallet.
    """

    def __init__(
        self,
        delegate_allowlist: set[str] | list[str] | None = None,
        spray_threshold: int = 50,
    ):
        self.delegate_allowlist: set[str] = {
            d.lower() for d in (delegate_allowlist or [])
        }
        self.spray_threshold: int = spray_threshold
        # Maps wallet address (lowercased) -> {"last_nonce": int, "streak": int}
        self.wallet_streaks: dict[str, dict[str, Any]] = {}

    def add_delegate(self, address: str) -> None:
        self.delegate_allowlist.add(address.lower())

    def remove_delegate(self, address: str) -> None:
        self.delegate_allowlist.discard(address.lower())

    def is_delegate_allowed(self, address: str | None) -> bool:
        if not address:
            return False
        return address.lower() in self.delegate_allowlist

    def _extract_nonce(self, req: SigningRequest) -> int | None:
        if not req.meta:
            return None
        val = req.meta.get("nonce")
        if val is None:
            return None
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            val = val.strip()
            if val.startswith("0x") or val.startswith("0X"):
                return int(val, 16)
            return int(val)
        return None

    def check_nonce_spray(self, req: SigningRequest) -> dict[str, Any] | None:
        """
        Detects batch nonce-spraying patterns.
        Flags requests with consecutive nonces for the same hot wallet when the streak
        reaches or exceeds spray_threshold (default 50).
        """
        wallet_key = req.wallet.lower()

        # Check for batch of nonces in request meta (e.g., meta={'nonces': [...]})
        if req.meta:
            batch_nonces = req.meta.get("nonces") or req.meta.get("batch_nonces")
            if isinstance(batch_nonces, list) and len(batch_nonces) >= self.spray_threshold:
                try:
                    int_nonces = [int(n) for n in batch_nonces]
                    is_consecutive = all(
                        int_nonces[i] + 1 == int_nonces[i + 1]
                        for i in range(len(int_nonces) - 1)
                    )
                    if is_consecutive:
                        return {
                            "rule": "nonce_spray_detected",
                            "message": (
                                f"Batch nonce spray detected: {len(int_nonces)} consecutive nonces "
                                f"for wallet {req.wallet}"
                            ),
                            "critical": True,
                            "wallet": req.wallet,
                            "consecutive_count": len(int_nonces),
                        }
                except (ValueError, TypeError):
                    pass

        # Check sequential nonce tracking across individual requests
        current_nonce = self._extract_nonce(req)
        if current_nonce is not None:
            streak_info = self.wallet_streaks.get(
                wallet_key, {"last_nonce": None, "streak": 0}
            )
            last_nonce = streak_info["last_nonce"]
            streak = streak_info["streak"]

            if last_nonce is not None and current_nonce == last_nonce + 1:
                streak += 1
            else:
                streak = 1

            self.wallet_streaks[wallet_key] = {
                "last_nonce": current_nonce,
                "streak": streak,
            }

            if streak >= self.spray_threshold:
                return {
                    "rule": "nonce_spray_detected",
                    "message": (
                        f"Sequential nonce spray detected: {streak} consecutive nonces "
                        f"for wallet {req.wallet}"
                    ),
                    "critical": True,
                    "wallet": req.wallet,
                    "consecutive_count": streak,
                }

        return None

    def evaluate_request(self, req: SigningRequest) -> dict[str, Any] | None:
        """
        Evaluate delegation and nonce rules.
        Returns a violation dict if any rule is violated, or None if passed.
        """
        # Rule 1: EIP-7702 authorization check (deny-by-default unless allowlisted)
        if req.kind == "authorization_7702":
            if not req.delegate or not self.is_delegate_allowed(req.delegate):
                return {
                    "rule": "7702_unauthorized_delegate",
                    "message": (
                        f"Unauthorized EIP-7702 delegation request: delegate "
                        f"'{req.delegate}' is not in delegate_allowlist"
                    ),
                    "critical": True,
                    "delegate": req.delegate,
                }

        # Rule 2: Nonce spray detection
        spray_violation = self.check_nonce_spray(req)
        if spray_violation:
            return spray_violation

        return None

    def reset(self) -> None:
        self.wallet_streaks.clear()
