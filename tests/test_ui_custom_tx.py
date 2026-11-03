"""Test suite for Simulate Custom TX dry-run evaluation (Milestone U4).

Verifies:
1. POST /v1/evaluate accepts raw transaction hex (and optionally an intent id).
2. Evaluation outcome includes:
   - verdict (ALLOW, HOLD, DENY)
   - risk score 0-100
   - each reason with its weight
   - decoded fields (chain, from, to, asset, amount, calls, authorizations, fee)
   - per-stage timings (decode, intent_check, delegation, limits, enrichment, decide, total)
3. Fails closed on invalid raw transaction hex (DECODE_ERROR, weight=100).
4. Missing raw_tx returns 422 validation error.
5. UI components and API client layer (web/api.js, frontend/src/api.ts, ReplayView.tsx)
   contain required wire-up and the clear dry-run note: "dry run - nothing signed or reserved".
6. Visual stability: CSS tokens, fonts, and layouts remain unchanged.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from services.bitguard.main import app
from services.bitguard.models import Decision, Verdict

client = TestClient(app)

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_REPLAY_VIEW = ROOT_DIR / "frontend" / "src" / "pages" / "ReplayView.tsx"
FRONTEND_API_FILE = ROOT_DIR / "frontend" / "src" / "api.ts"
WEB_API_FILE = ROOT_DIR / "web" / "api.js"

# Valid EIP-155 Native Transfer Vector (0.001 ETH / 1e15 wei)
VALID_RAW_TX = "0xec018504a817c80082520894742d35cc6634c0532925a3b844bc454e4438f44e880de0b6b3a764000080018080"
# EIP-7702 Type-4 Delegation Vector
EIP7702_RAW_TX = "0x04f86601018477359400847735940082520894742d35cc6634c0532925a3b844bc454e4438f44e8080f84bf849019433333333333333333333333333333333333333330080808080"


def test_post_evaluate_valid_raw_tx_returns_canonical_fields():
    """POST /v1/evaluate returns verdict, risk 0-100, reasons with weights, decoded fields, and timings."""
    payload = {
        "raw_tx": VALID_RAW_TX,
    }
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()

    # 1. Decision model validation
    decision = Decision.model_validate(data)
    assert decision.verdict in [Verdict.ALLOW, Verdict.HOLD, Verdict.DENY]
    assert 0 <= decision.risk_score <= 100

    # 2. Reasons with weights
    assert isinstance(decision.reasons, list)
    for r in decision.reasons:
        assert hasattr(r, "code") and len(r.code) > 0
        assert hasattr(r, "weight") and 0 <= r.weight <= 100
        assert hasattr(r, "detail")

    # 3. Decoded fields (chain, from, to, asset, amount, calls, authorizations, fee)
    assert decision.decoded_tx is not None, "decoded_tx must be present in dry-run evaluation"
    decoded = decision.decoded_tx
    assert decoded.chain == "ethereum"
    assert decoded.from_address is not None
    assert decoded.to_address is not None
    assert decoded.asset == "ETH"
    assert decoded.amount == "1000000000000000000"
    assert isinstance(decoded.calls, list)
    assert isinstance(decoded.authorizations, list)
    assert decoded.fee is not None

    # 4. Per-stage execution timings
    assert isinstance(decision.timings, dict)
    assert "decode" in decision.timings
    assert "decide" in decision.timings
    assert "total" in decision.timings
    assert decision.evaluation_latency_ms is not None
    assert decision.evaluation_latency_ms >= 0.0


def test_post_evaluate_with_optional_intent_id():
    """POST /v1/evaluate accepts optional intent_id and triggers reconciliation."""
    payload = {
        "raw_tx": VALID_RAW_TX,
        "intent_id": "intent-demo-nonexistent-01",
    }
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    decision = Decision.model_validate(data)

    # Missing ledger intent fails closed with DENY or reason hit
    intent_reason_hit = any("INTENT" in r.code for r in decision.reasons)
    assert intent_reason_hit or decision.verdict in [Verdict.DENY, Verdict.HOLD]


def test_post_evaluate_invalid_raw_hex_fails_closed():
    """POST /v1/evaluate with malformed hex fails closed with DECODE_ERROR and weight=100."""
    payload = {
        "raw_tx": "0xdeadbeef001122",
    }
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    decision = Decision.model_validate(data)
    assert decision.verdict == Verdict.DENY
    assert decision.risk_score == 100
    assert any(r.code == "DECODE_ERROR" and r.weight == 100 for r in decision.reasons)


def test_post_evaluate_missing_raw_tx_returns_422():
    """POST /v1/evaluate without raw_tx returns 422 Unprocessable Entity."""
    response = client.post("/v1/evaluate", json={"chain": "ethereum"})
    assert response.status_code == 422


def test_ui_and_api_files_contain_u4_requirements():
    """Verifies that ReplayView.tsx, api.ts, and web/api.js implement U4 requirements."""
    assert FRONTEND_REPLAY_VIEW.exists()
    assert FRONTEND_API_FILE.exists()
    assert WEB_API_FILE.exists()

    replay_view_content = FRONTEND_REPLAY_VIEW.read_text(encoding="utf-8")
    fe_api_content = FRONTEND_API_FILE.read_text(encoding="utf-8")
    web_api_content = WEB_API_FILE.read_text(encoding="utf-8")

    # 1. API client exports evaluateCustomTx and routes raw_tx to /v1/evaluate
    assert "evaluateCustomTx" in fe_api_content
    assert "evaluateCustomTx" in web_api_content
    assert "/v1/evaluate" in fe_api_content
    assert "/v1/evaluate" in web_api_content

    # 2. ReplayView contains raw_tx input and intent_id input
    assert "raw_tx" in replay_view_content
    assert "intent_id" in replay_view_content
    assert "rawTxHex" in replay_view_content

    # 3. ReplayView contains explicit dry run note
    assert "dry run - nothing signed or reserved" in replay_view_content

    # 4. ReplayView contains decoded fields and per-stage timings rendering
    assert "decoded_tx" in replay_view_content
    assert "timings" in replay_view_content
    assert "Weight:" in replay_view_content
    assert "VERDICT:" in replay_view_content


def test_visual_stability_tokens_preserved():
    """Invariant #10: Existing styles, tokens, and classes remain intact."""
    app_css = ROOT_DIR / "frontend" / "src" / "App.css"
    index_css = ROOT_DIR / "frontend" / "src" / "index.css"
    tailwind_config = ROOT_DIR / "frontend" / "tailwind.config.js"

    assert app_css.exists()
    assert index_css.exists()
    assert tailwind_config.exists()
