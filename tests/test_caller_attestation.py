"""Unit and integration tests for Caller Identity and Build Attestation (Milestone S33 / Feature F16).

Verifies:
- CALLER_UNKNOWN_DIGEST: Quarantines transfer into HOLD even if amount and ledger intent are valid.
- CALLER_RECENT_DEPLOY: Applies configurable risk weight when caller was deployed within freshness window.
- CALLER_UNUSUAL_SOURCE: Applies configurable risk weight when caller source IP is outside allowed CIDRs.
- mTLS SAN / SPIFFE ID parsing of query parameters and custom X.509 extensions.
- Storage of caller identity attributes on Decision objects and in hash-chained audit ledger.
- Dynamic publishing of container image digests via CI scripts.
- Asymmetric policy evolution (tighten vs loosen classification).
"""

import json
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rlp
from fastapi import Request

from lab.scripts.make_dev_ca import (
    DEFAULT_ATTESTED_IMAGE_DIGEST,
    generate_dev_pki,
)
from scripts.publish_image_digest import publish_image_digest
from services.bitguard.attestation.store import allowed_images_store
from services.bitguard.attestation.verifier import caller_attestation_verifier
from services.bitguard.audit_service import audit_service
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.engine.types import DecisionEngineConfig
from services.bitguard.gateway.mtls import (
    extract_workload_identity,
)
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, LedgerIntent
from services.bitguard.models import (
    SigningRequest,
    Verdict,
)
from services.bitguard.policy.classifier import ChangeClassification, classify_change
from services.bitguard.policy.models import (
    CallerAttestationPolicy,
    PolicyDocument,
)

BENIGN_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
BENIGN_DEST = "0x1111111111111111111111111111111111111111"
KNOWN_ALLOWED_DIGEST = "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
UNKNOWN_DIGEST = "sha256:9999999999999999999999999999999999999999999999999999999999999999"


def build_raw_tx(to_addr: str, value_wei: int = 10**18) -> str:
    """Builds valid RLP-encoded raw legacy EVM transaction hex."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [0, 20_000_000_000, 21000, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path):
    """Sets up fresh test state for attestation tests."""
    allowed_images_store.reset()
    audit_service.clear()
    mock_ledger_connector._ledger_url = ""
    yield
    allowed_images_store.reset()
    audit_service.clear()


# ==============================================================================
# 1. Unknown Digest Triggers HOLD (Even with Valid Intent and Amount)
# ==============================================================================


def test_unknown_digest_triggers_caller_unknown_digest_and_holds():
    """Requirement: CALLER_UNKNOWN_DIGEST (HOLD). A request from an unknown digest is HOLD

    even if amount and intent are fine.
    """
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
    )

    # Valid approved ledger intent
    intent_id = "intent-valid-001"
    mock_ledger_connector.register_intent(
        LedgerIntent(
            id=intent_id,
            chain="ethereum",
            destination=BENIGN_DEST,
            asset="ETH",
            amount="1000000000000000000",
            status=IntentStatus.APPROVED.value,
        )
    )

    req = SigningRequest(
        chain="ethereum",
        wallet=BENIGN_WALLET,
        raw_tx=build_raw_tx(BENIGN_DEST, value_wei=10**18),
        intent_id=intent_id,
        caller_identity="spiffe://exchange.internal/workload/custody",
        caller_image_digest=UNKNOWN_DIGEST,
        caller_source_ip="10.0.1.5",
        metadata={
            "amount_usd": 100.0,  # Small normal amount well below limits
        },
    )

    decision = engine.evaluate(req)

    # Must be quarantined into HOLD, not ALLOW and not DENY
    assert decision.verdict == Verdict.HOLD
    assert decision.verdict != Verdict.ALLOW
    assert decision.verdict != Verdict.DENY

    reason_codes = [r.code for r in decision.reasons]
    assert "CALLER_UNKNOWN_DIGEST" in reason_codes
    unknown_r = next(r for r in decision.reasons if r.code == "CALLER_UNKNOWN_DIGEST")
    assert "quarantine HOLD required" in unknown_r.detail
    assert unknown_r.weight == 60


def test_known_digest_allows_request():
    """Requirement: An authorized container image digest allows execution when other checks pass."""
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
    )

    intent_id = "intent-valid-002"
    mock_ledger_connector.register_intent(
        LedgerIntent(
            id=intent_id,
            chain="ethereum",
            destination=BENIGN_DEST,
            asset="ETH",
            amount="1000000000000000000",
            status=IntentStatus.APPROVED.value,
        )
    )

    req = SigningRequest(
        chain="ethereum",
        wallet=BENIGN_WALLET,
        raw_tx=build_raw_tx(BENIGN_DEST, value_wei=10**18),
        intent_id=intent_id,
        caller_identity="spiffe://exchange.internal/workload/custody",
        caller_image_digest=KNOWN_ALLOWED_DIGEST,
        caller_source_ip="10.0.1.5",
        metadata={
            "amount_usd": 100.0,
        },
    )

    decision = engine.evaluate(req)

    assert decision.verdict == Verdict.ALLOW
    reason_codes = [r.code for r in decision.reasons]
    assert "CALLER_UNKNOWN_DIGEST" not in reason_codes


# ==============================================================================
# 2. CALLER_RECENT_DEPLOY Freshness Window Check
# ==============================================================================


def test_recent_deploy_adds_risk_weight():
    """Requirement: CALLER_RECENT_DEPLOY adds risk weight when caller was deployed within window."""
    now_ts = time.time()
    # Deployed 5 minutes ago (300 s ago < 3600 s window)
    recent_deploy_time = datetime.fromtimestamp(now_ts - 300, tz=UTC)

    result = caller_attestation_verifier.verify(
        caller_identity="spiffe://exchange.internal/workload/custody",
        image_digest=KNOWN_ALLOWED_DIGEST,
        deploy_time=recent_deploy_time,
        source_ip="10.0.1.5",
        now_ts=now_ts,
    )

    reason_codes = [r.code for r in result.reasons]
    assert "CALLER_RECENT_DEPLOY" in reason_codes
    deploy_r = next(r for r in result.reasons if r.code == "CALLER_RECENT_DEPLOY")
    assert deploy_r.weight == 25
    assert "recently deployed" in deploy_r.detail


def test_mature_deploy_does_not_trigger_recent_deploy():
    """Requirement: Caller deployed outside freshness window (> 3600s) is not flagged."""
    now_ts = time.time()
    # Deployed 2 days ago (172,800 s ago > 3600 s window)
    mature_deploy_time = datetime.fromtimestamp(now_ts - 172800, tz=UTC)

    result = caller_attestation_verifier.verify(
        caller_identity="spiffe://exchange.internal/workload/custody",
        image_digest=KNOWN_ALLOWED_DIGEST,
        deploy_time=mature_deploy_time,
        source_ip="10.0.1.5",
        now_ts=now_ts,
    )

    reason_codes = [r.code for r in result.reasons]
    assert "CALLER_RECENT_DEPLOY" not in reason_codes


# ==============================================================================
# 3. CALLER_UNUSUAL_SOURCE Network Allowlist Check
# ==============================================================================


def test_unusual_source_network_adds_risk_weight():
    """Requirement: CALLER_UNUSUAL_SOURCE flagged when caller source IP is outside allowlist."""
    result = caller_attestation_verifier.verify(
        caller_identity="spiffe://exchange.internal/workload/custody",
        image_digest=KNOWN_ALLOWED_DIGEST,
        deploy_time=None,
        source_ip="198.51.100.77",  # Public / external IP not in private CIDR allowlist
    )

    reason_codes = [r.code for r in result.reasons]
    assert "CALLER_UNUSUAL_SOURCE" in reason_codes
    source_r = next(r for r in result.reasons if r.code == "CALLER_UNUSUAL_SOURCE")
    assert source_r.weight == 40
    assert "does not originate from configured allowed networks" in source_r.detail


def test_allowed_source_network_does_not_flag_unusual_source():
    """Requirement: Private VPC CIDRs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) are accepted."""
    for ip in ["10.244.0.12", "172.20.1.99", "192.168.1.10", "127.0.0.1"]:
        result = caller_attestation_verifier.verify(
            caller_identity="spiffe://exchange.internal/workload/custody",
            image_digest=KNOWN_ALLOWED_DIGEST,
            deploy_time=None,
            source_ip=ip,
        )
        reason_codes = [r.code for r in result.reasons]
        assert "CALLER_UNUSUAL_SOURCE" not in reason_codes


def test_combined_attestation_reasons_accumulate_to_hold():
    """Requirement: Multiple attestation risk weights accumulate and can trigger HOLD via risk score."""
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
    )

    intent_id = "intent-valid-003"
    mock_ledger_connector.register_intent(
        LedgerIntent(
            id=intent_id,
            chain="ethereum",
            destination=BENIGN_DEST,
            asset="ETH",
            amount="1000000000000000000",
            status=IntentStatus.APPROVED.value,
        )
    )

    now_ts = time.time()
    recent_deploy = datetime.fromtimestamp(now_ts - 120, tz=UTC)

    # CALLER_RECENT_DEPLOY (25) + CALLER_UNUSUAL_SOURCE (40) = 65 >= hold_risk_threshold (50)
    req = SigningRequest(
        chain="ethereum",
        wallet=BENIGN_WALLET,
        raw_tx=build_raw_tx(BENIGN_DEST, value_wei=10**18),
        intent_id=intent_id,
        caller_identity="spiffe://exchange.internal/workload/custody",
        caller_image_digest=KNOWN_ALLOWED_DIGEST,
        caller_deploy_time=recent_deploy,
        caller_source_ip="203.0.113.88",  # External untrusted IP
        metadata={"amount_usd": 100.0, "ts": now_ts},
    )

    decision = engine.evaluate(req)

    assert decision.verdict == Verdict.HOLD
    assert decision.risk_score >= 65
    reason_codes = [r.code for r in decision.reasons]
    assert "CALLER_RECENT_DEPLOY" in reason_codes
    assert "CALLER_UNUSUAL_SOURCE" in reason_codes


# ==============================================================================
# 4. Identity Fields Stored on Decision & Immutable Audit Ledger
# ==============================================================================


def test_identity_fields_stored_on_decision_and_audit_ledger():
    """Requirement: Store identity fields on every Decision for audit."""
    engine = DecisionEngine()

    now_ts = time.time()
    deploy_dt = datetime.fromtimestamp(now_ts - 5000, tz=UTC)

    req = SigningRequest(
        chain="ethereum",
        wallet=BENIGN_WALLET,
        raw_tx=build_raw_tx(BENIGN_DEST, value_wei=10**18),
        caller_identity="spiffe://exchange.internal/workload/custody",
        caller_image_digest=KNOWN_ALLOWED_DIGEST,
        caller_deploy_time=deploy_dt,
        caller_source_ip="10.0.5.21",
        metadata={"amount_usd": 200.0},
    )

    decision = engine.evaluate(req)

    # Check fields on Decision model
    assert decision.caller_identity == "spiffe://exchange.internal/workload/custody"
    assert decision.caller_image_digest == KNOWN_ALLOWED_DIGEST
    assert decision.caller_deploy_time == deploy_dt
    assert decision.caller_source_ip == "10.0.5.21"

    # Verify audit ledger persistence
    from services.bitguard.decision_store import decision_store

    decision_store.save_decision(decision)
    entries = audit_service.get_entries()
    assert len(entries) > 0

    dec_entry = next(e for e in entries if e.request_id == decision.request_id)
    payload = dec_entry.payload
    assert payload.get("caller_identity") == "spiffe://exchange.internal/workload/custody"
    assert payload.get("caller_image_digest") == KNOWN_ALLOWED_DIGEST
    assert payload.get("caller_source_ip") == "10.0.5.21"


# ==============================================================================
# 5. mTLS Workload Identity Extraction from Certificate SANs and Headers
# ==============================================================================


def test_mtls_san_with_query_attributes_extracted():
    """Requirement: Extend mTLS identity (S12) to include image_digest and deploy_time

    as certificate SAN or custom attributes.
    """
    certs_dir = Path("lab/certs")
    generate_dev_pki(certs_dir)

    client_crt_pem = (certs_dir / "client.crt").read_text(encoding="utf-8")

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/gateway",
        "headers": [
            (b"x-client-cert-pem", client_crt_pem.encode("utf-8")),
            (b"x-caller-source-ip", b"10.0.2.14"),
        ],
    }
    request = Request(scope)

    workload = extract_workload_identity(request)
    assert workload is not None
    assert workload.san == "spiffe://exchange.internal/workload/custody"
    assert workload.image_digest == DEFAULT_ATTESTED_IMAGE_DIGEST
    assert workload.source_ip == "10.0.2.14"
    assert workload.deploy_time is not None


def test_mtls_headers_fallback_extraction():
    """Requirement: Proxy-injected headers (Envoy/SPIFFE) provide image digest and deploy time."""
    deploy_iso = "2026-11-11T11:30:00Z"
    test_digest = "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/gateway",
        "headers": [
            (b"x-client-cert-san", b"spiffe://exchange.internal/workload/custody"),
            (b"x-caller-image-digest", test_digest.encode("utf-8")),
            (b"x-caller-deploy-time", deploy_iso.encode("utf-8")),
            (b"x-caller-source-ip", b"172.16.4.8"),
        ],
    }
    request = Request(scope)

    workload = extract_workload_identity(request)
    assert workload is not None
    assert workload.san == "spiffe://exchange.internal/workload/custody"
    assert workload.image_digest == test_digest
    assert workload.deploy_time == datetime.fromisoformat("2026-11-11T11:30:00+00:00")
    assert workload.source_ip == "172.16.4.8"


# ==============================================================================
# 6. CI Script Publishing and Dynamic Policy Reloading
# ==============================================================================


def test_publish_image_digest_script_updates_policy(tmp_path):
    """Requirement: policy/allowed_images.json published by the CI pipeline."""
    policy_file = tmp_path / "allowed_images.json"
    new_digest = "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

    published_digest = publish_image_digest(
        image="bitguard/custody-workload",
        digest=new_digest,
        tag="v2.5.0",
        output_path=str(policy_file),
    )
    assert published_digest == new_digest

    # Verify content on disk
    content = json.loads(policy_file.read_text(encoding="utf-8"))
    assert new_digest in content["allowed_digests"]
    assert any(img["digest"] == new_digest for img in content["allowed_images"])


# ==============================================================================
# 7. Asymmetric Policy Evolution (Classifier)
# ==============================================================================


def test_attestation_policy_asymmetric_classification():
    """Requirement: Tightening attestation = TIGHTEN (instant 1-person). Loosening = LOOSEN."""
    old_doc = PolicyDocument(
        attestation=CallerAttestationPolicy(
            require_attestation=False,
            recent_deploy_window_seconds=3600,
            allowed_source_networks=["10.0.0.0/8", "172.16.0.0/12"],
        )
    )

    # 1. Enforcing mandatory attestation (require_attestation=True) -> TIGHTEN
    tighten_req = old_doc.model_copy(deep=True)
    tighten_req.attestation.require_attestation = True
    assert classify_change(old_doc, tighten_req) == ChangeClassification.TIGHTEN

    # 2. Expanding freshness scrutiny window (7200s > 3600s) -> TIGHTEN
    tighten_win = old_doc.model_copy(deep=True)
    tighten_win.attestation.recent_deploy_window_seconds = 7200
    assert classify_change(old_doc, tighten_win) == ChangeClassification.TIGHTEN

    # 3. Adding extra allowed networks (e.g. 192.168.0.0/16) -> LOOSEN
    loosen_net = old_doc.model_copy(deep=True)
    loosen_net.attestation.allowed_source_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert classify_change(old_doc, loosen_net) == ChangeClassification.LOOSEN

    # 4. Disabling attestation checks -> LOOSEN
    loosen_disable = old_doc.model_copy(deep=True)
    loosen_disable.attestation.enabled = False
    assert classify_change(old_doc, loosen_disable) == ChangeClassification.LOOSEN
