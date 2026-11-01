from typing import Optional, Any


class Breaker:
    """
    BitGuard Circuit Breaker State Machine.
    States: Normal -> Elevated -> Hold -> Lockdown.

    In Lockdown, all automated signing requests are paused (deny).
    Automatically elevates or locks down if anomalous/denied requests occur
    across multiple chains within a 5-minute rolling window or on any confirmed
    7702 unauthorized delegation.
    """

    STATES = ("Normal", "Elevated", "Hold", "Lockdown")

    def __init__(
        self,
        window_seconds: float = 300.0,  # 5-minute rolling window
        multi_chain_elevate_threshold: int = 2,
        multi_chain_lockdown_threshold: int = 3,
    ):
        self.state: str = "Normal"
        self.window_seconds: float = window_seconds
        self.multi_chain_elevate_threshold: int = multi_chain_elevate_threshold
        self.multi_chain_lockdown_threshold: int = multi_chain_lockdown_threshold
        self.anomalies: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []

    def is_locked_down(self) -> bool:
        return self.state == "Lockdown"

    def trip_lockdown(self, reason: str, details: Optional[dict[str, Any]] = None) -> None:
        """Force transition to Lockdown state."""
        prev = self.state
        self.state = "Lockdown"
        entry = {
            "from_state": prev,
            "to_state": "Lockdown",
            "reason": reason,
            "details": details or {},
        }
        self.history.append(entry)

    def trip_elevated(self, reason: str, details: Optional[dict[str, Any]] = None) -> None:
        """Elevate state if not currently in Hold or Lockdown."""
        if self.state not in ("Hold", "Lockdown"):
            prev = self.state
            self.state = "Elevated"
            entry = {
                "from_state": prev,
                "to_state": "Elevated",
                "reason": reason,
                "details": details or {},
            }
            self.history.append(entry)

    def trip_hold(self, reason: str, details: Optional[dict[str, Any]] = None) -> None:
        """Transition to Hold if not in Lockdown."""
        if self.state != "Lockdown":
            prev = self.state
            self.state = "Hold"
            entry = {
                "from_state": prev,
                "to_state": "Hold",
                "reason": reason,
                "details": details or {},
            }
            self.history.append(entry)

    def reset(self) -> None:
        """Reset breaker back to Normal."""
        self.state = "Normal"
        self.anomalies.clear()
        self.history.clear()

    def _prune_anomalies(self, current_ts: float) -> list[dict[str, Any]]:
        cutoff = current_ts - self.window_seconds
        self.anomalies = [a for a in self.anomalies if a["ts"] > cutoff]
        return self.anomalies

    def record_anomaly(
        self,
        chain: str,
        ts: float,
        reason: str = "",
        is_critical: bool = False,
    ) -> None:
        """
        Record an anomalous or denied request.
        If is_critical is True (e.g. 7702 unauthorized delegation or nonce spray),
        immediately forces Lockdown.
        If anomalies occur across multiple chains within the 5-minute rolling window,
        automatically elevates or locks down.
        """
        self._prune_anomalies(ts)
        self.anomalies.append({
            "chain": chain.lower(),
            "ts": ts,
            "reason": reason,
            "is_critical": is_critical,
        })

        if is_critical:
            self.trip_lockdown(
                reason=f"Critical exploit indicator triggered on chain '{chain}': {reason}",
                details={"chain": chain, "ts": ts},
            )
            return

        # Check multi-chain anomaly spread
        unique_chains = {a["chain"] for a in self.anomalies}
        if len(unique_chains) >= self.multi_chain_lockdown_threshold:
            self.trip_lockdown(
                reason=f"Multi-chain anomaly outbreak detected across {len(unique_chains)} chains ({sorted(unique_chains)}) within 5 minutes",
                details={"chains": list(unique_chains), "ts": ts},
            )
        elif len(unique_chains) >= self.multi_chain_elevate_threshold:
            self.trip_elevated(
                reason=f"Multi-chain anomalous activity detected across {len(unique_chains)} chains ({sorted(unique_chains)}) within 5 minutes",
                details={"chains": list(unique_chains), "ts": ts},
            )
