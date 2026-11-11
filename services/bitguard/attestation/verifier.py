"""Caller identity and build attestation verifier (Milestone S33 / F16).

Enforces:
- CALLER_UNKNOWN_DIGEST: Flagged as HOLD when caller runs an unauthorized container digest.
- CALLER_RECENT_DEPLOY: Configurable risk weight when caller was deployed within the freshness window.
- CALLER_UNUSUAL_SOURCE: Configurable risk weight when caller source IP is outside allowed networks.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import UTC, datetime
from typing import Any

from services.bitguard.attestation.models import AttestationCheckResult
from services.bitguard.attestation.store import AllowedImagesStore, allowed_images_store
from services.bitguard.models import DecisionReason

logger = logging.getLogger("bitguard.attestation.verifier")


class CallerAttestationVerifier:
    """Evaluates caller identity attributes against policy and allowed image catalogs."""

    def __init__(self, store: AllowedImagesStore | None = None) -> None:
        self.store = store or allowed_images_store

    def verify(
        self,
        caller_identity: str | None,
        image_digest: str | None,
        deploy_time: datetime | None,
        source_ip: str | None,
        policy: Any | None = None,
        now_ts: float | None = None,
    ) -> AttestationCheckResult:
        """Evaluates caller attestation attributes and returns diagnostic reasons."""
        eval_ts = now_ts if now_ts is not None else time.time()
        reasons: list[DecisionReason] = []
        hold_required = False
        details: dict[str, Any] = {}

        # Default policy settings if not provided
        enabled = getattr(policy, "enabled", True) if policy is not None else True
        if not enabled:
            return AttestationCheckResult(reasons=[], hold_required=False, details={"status": "disabled"})

        require_attestation = getattr(policy, "require_attestation", False) if policy is not None else False
        unknown_digest_weight = getattr(policy, "unknown_digest_weight", 60) if policy is not None else 60
        recent_deploy_window = getattr(policy, "recent_deploy_window_seconds", 3600) if policy is not None else 3600
        recent_deploy_weight = getattr(policy, "recent_deploy_weight", 25) if policy is not None else 25
        allowed_networks = getattr(
            policy,
            "allowed_source_networks",
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"],
        ) if policy is not None else ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]
        unusual_source_weight = getattr(policy, "unusual_source_weight", 40) if policy is not None else 40
        policy_digests = getattr(policy, "allowed_digests", []) if policy is not None else []

        # -----------------------------------------------------------------
        # 1. CALLER_UNKNOWN_DIGEST Check (triggers HOLD)
        # -----------------------------------------------------------------
        if image_digest:
            clean_digest = image_digest.strip().lower()
            allowed = self.store.is_digest_allowed(clean_digest)
            if not allowed and policy_digests:
                allowed = (
                    clean_digest in [d.lower() for d in policy_digests]
                    or clean_digest.removeprefix("sha256:") in [d.lower().removeprefix("sha256:") for d in policy_digests]
                )

            if not allowed:
                reasons.append(
                    DecisionReason(
                        code="CALLER_UNKNOWN_DIGEST",
                        weight=unknown_digest_weight,
                        detail=(
                            f"Caller container image digest '{image_digest}' is not recognized "
                            "in policy allowed_images catalog; quarantine HOLD required."
                        ),
                    )
                )
                hold_required = True
                details["digest_verified"] = False
            else:
                details["digest_verified"] = True
        elif require_attestation:
            reasons.append(
                DecisionReason(
                    code="CALLER_UNKNOWN_DIGEST",
                    weight=unknown_digest_weight,
                    detail="Caller image digest is missing; caller attestation is required by policy.",
                )
            )
            hold_required = True
            details["digest_verified"] = False

        # -----------------------------------------------------------------
        # 2. CALLER_RECENT_DEPLOY Check (freshness window)
        # -----------------------------------------------------------------
        if deploy_time:
            dt_utc = deploy_time if deploy_time.tzinfo is not None else deploy_time.replace(tzinfo=UTC)
            age_seconds = eval_ts - dt_utc.timestamp()
            details["deploy_age_seconds"] = age_seconds
            if 0 <= age_seconds < recent_deploy_window:
                reasons.append(
                    DecisionReason(
                        code="CALLER_RECENT_DEPLOY",
                        weight=recent_deploy_weight,
                        detail=(
                            f"Caller was recently deployed at {dt_utc.isoformat()} "
                            f"({age_seconds:.0f}s ago < {recent_deploy_window}s policy window); "
                            "elevated deployment risk applied."
                        ),
                    )
                )

        # -----------------------------------------------------------------
        # 3. CALLER_UNUSUAL_SOURCE Check (network CIDR allowlist)
        # -----------------------------------------------------------------
        if source_ip and allowed_networks:
            clean_ip = source_ip.strip()
            # Remove port if present
            if ":" in clean_ip and not clean_ip.count(":") > 1:
                clean_ip = clean_ip.split(":")[0]

            ip_allowed = False
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                for net_str in allowed_networks:
                    try:
                        net_obj = ipaddress.ip_network(net_str.strip(), strict=False)
                        if ip_obj in net_obj:
                            ip_allowed = True
                            break
                    except ValueError:
                        continue
            except ValueError:
                # If IP address string is unparseable, treat as unusual
                ip_allowed = False

            if not ip_allowed:
                reasons.append(
                    DecisionReason(
                        code="CALLER_UNUSUAL_SOURCE",
                        weight=unusual_source_weight,
                        detail=(
                            f"Caller source address {source_ip} does not originate from "
                            f"configured allowed networks {allowed_networks}."
                        ),
                    )
                )
                details["source_ip_allowed"] = False
            else:
                details["source_ip_allowed"] = True

        return AttestationCheckResult(
            reasons=reasons,
            hold_required=hold_required,
            details=details,
        )


# Global singleton verifier
caller_attestation_verifier = CallerAttestationVerifier()
