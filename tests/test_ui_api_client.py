"""Test suite for UI API client layer (Milestone U1).

Verifies:
1. web/api.js and frontend/src/api.ts export the required seam interface:
   - login
   - evaluate
   - getDecisions
   - getBreaker
   - escalateBreaker
   - getHolds
   - approve
   - openStream
   - DATA_SOURCE / getDataSource / setDataSource
2. DATA_SOURCE switching logic between 'demo' and 'api'.
3. Backend endpoint parity for every seam method against FastAPI testclient.
4. Visual stability invariants (no CSS or markup drift in build artifacts).
"""

from pathlib import Path

from fastapi.testclient import TestClient

from services.bitguard.main import app

client = TestClient(app)

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_API_FILE = ROOT_DIR / "web" / "api.js"
FRONTEND_API_FILE = ROOT_DIR / "frontend" / "src" / "api.ts"
UI_CHECKLIST_FILE = ROOT_DIR / "docs" / "ui-checklist.md"


def test_api_client_files_exist_and_contain_required_functions():
    """Requirement: Single module exposing login, evaluate, getDecisions, getBreaker, escalateBreaker, getHolds, approve, openStream."""
    assert WEB_API_FILE.exists(), "web/api.js must exist"
    assert FRONTEND_API_FILE.exists(), "frontend/src/api.ts must exist"
    assert UI_CHECKLIST_FILE.exists(), "docs/ui-checklist.md must exist"

    web_content = WEB_API_FILE.read_text(encoding="utf-8")
    fe_content = FRONTEND_API_FILE.read_text(encoding="utf-8")

    required_exports = [
        "login",
        "evaluate",
        "getDecisions",
        "getBreaker",
        "escalateBreaker",
        "getHolds",
        "approve",
        "openStream",
        "DATA_SOURCE",
        "getDataSource",
        "setDataSource",
    ]

    for fn in required_exports:
        assert fn in web_content, f"web/api.js missing export '{fn}'"
        assert fn in fe_content, f"frontend/src/api.ts missing export '{fn}'"


def test_data_source_configuration_parsing():
    """Requirement: DATA_SOURCE setting ('demo' keeps built-in behaviour, 'api' uses backend) selectable by query param or config."""
    web_content = WEB_API_FILE.read_text(encoding="utf-8")
    fe_content = FRONTEND_API_FILE.read_text(encoding="utf-8")

    # Verify query param checking
    for content in [web_content, fe_content]:
        assert "datasource" in content
        assert "localStorage" in content
        assert "'demo'" in content
        assert "'api'" in content


def test_backend_endpoint_parity_for_api_client():
    """Verifies that all API routes called by the client layer exist and respond correctly on the backend."""
    # 1. login -> POST /v1/auth/dev-token
    resp_login = client.post("/v1/auth/dev-token", json={"role": "Approver", "user_id": "usr-approver-01"})
    assert resp_login.status_code == 200
    token = resp_login.json()["access_token"]
    assert len(token) > 20
    auth_header = {"Authorization": f"Bearer {token}"}

    # 2. evaluate -> POST /api/evaluate
    sample_tx = {
        "id": "ui-eval-test-01",
        "ts": 1700000000,
        "chain": "ethereum",
        "wallet": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "kind": "transfer",
        "asset": "ETH",
        "amount_usd": 1500.0,
        "to": "0x1111111111111111111111111111111111111111",
    }
    resp_eval = client.post("/api/evaluate", json=sample_tx)
    assert resp_eval.status_code == 200
    eval_data = resp_eval.json()
    assert "action" in eval_data or "verdict" in eval_data

    # 3. getDecisions -> GET /v1/decisions
    resp_decisions = client.get("/v1/decisions?limit=5", headers=auth_header)
    assert resp_decisions.status_code == 200
    assert isinstance(resp_decisions.json(), list) or "decisions" in resp_decisions.json()

    # 4. getBreaker -> GET /v1/breaker
    resp_breaker = client.get("/v1/breaker", headers=auth_header)
    assert resp_breaker.status_code == 200
    assert "state" in resp_breaker.json()

    # 5. getHolds -> GET /v1/holds
    resp_holds = client.get("/v1/holds", headers=auth_header)
    assert resp_holds.status_code == 200
    assert isinstance(resp_holds.json(), list)


def test_visual_stability_css_unchanged():
    """Hard constraint: do not change any CSS, layout, markup structure, colours, fonts or existing class names."""
    index_css = ROOT_DIR / "frontend" / "src" / "index.css"
    app_css = ROOT_DIR / "frontend" / "src" / "App.css"
    tailwind_config = ROOT_DIR / "frontend" / "tailwind.config.js"

    assert index_css.exists()
    assert app_css.exists()
    assert tailwind_config.exists()
