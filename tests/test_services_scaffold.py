"""Unit tests for scaffolded service endpoints, health checks, and configuration."""

import json
import logging

from fastapi.testclient import TestClient

from services.bitguard.config import BitGuardSettings
from services.bitguard.logging import JSONFormatter
from services.bitguard.main import app as bitguard_app
from services.ledger_mock.config import LedgerMockSettings
from services.ledger_mock.main import app as ledger_mock_app
from services.signer_shim.config import SignerShimSettings
from services.signer_shim.main import app as signer_shim_app


def test_bitguard_healthz_endpoint():
    """Verify bitguard service responds on /healthz."""
    client = TestClient(bitguard_app)
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "bitguard"
    assert "environment" in data


def test_signer_shim_healthz_endpoint():
    """Verify signer_shim service responds on /healthz."""
    client = TestClient(signer_shim_app)
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "signer_shim"
    assert "environment" in data


def test_ledger_mock_healthz_endpoint():
    """Verify ledger_mock service responds on /healthz."""
    client = TestClient(ledger_mock_app)
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ledger_mock"
    assert "environment" in data


def test_bitguard_structured_json_logging():
    """Verify JSONFormatter outputs valid JSON with required structured metadata."""
    formatter = JSONFormatter(service_name="bitguard-test")
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test structured log message",
        args=(),
        exc_info=None,
    )
    record.__dict__["custom_field"] = "custom_value"

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "INFO"
    assert parsed["service"] == "bitguard-test"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "Test structured log message"
    assert "timestamp" in parsed
    assert parsed["extra"]["custom_field"] == "custom_value"


def test_service_settings_and_defaults():
    """Verify settings defaults are populated from pydantic-settings."""
    bg_settings = BitGuardSettings()
    assert bg_settings.service_name == "bitguard"
    assert bg_settings.port == 8000
    assert bg_settings.approval_token_ttl_seconds == 60

    shim_settings = SignerShimSettings()
    assert shim_settings.service_name == "signer_shim"
    assert shim_settings.port == 8001
    assert shim_settings.testnet_private_key.startswith("0x")

    ledger_settings = LedgerMockSettings()
    assert ledger_settings.service_name == "ledger_mock"
    assert ledger_settings.port == 8002
