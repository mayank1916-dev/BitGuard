"""Configuration and environment detection for BitGuard Integration Lab."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class LabSettings(BaseSettings):
    """Runtime settings for the integration lab runner."""

    chain_id: int = 31337
    chain_name: str = "anvil-local"
    bitguard_url: str = "http://localhost:8000"
    signer_shim_url: str = "http://localhost:8001"
    ledger_mock_url: str = "http://localhost:8002"
    anvil_url: str = "http://localhost:8545"
    demo_custody_url: str = "http://localhost:8003"

    # Execution mode: 'auto' probes services; 'in-process' uses FastAPI ASGI harness; 'live' requires running docker stack
    execution_mode: str = "auto"
    request_timeout: float = 10.0
    data_label: str = "SYNTHETIC"

    model_config = SettingsConfigDict(
        env_prefix="BITGUARD_LAB_",
        case_sensitive=False,
        extra="ignore",
    )


lab_settings = LabSettings()

LAB_DIR = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = LAB_DIR / "scenarios"
RESULTS_DIR = LAB_DIR / "results"
LATEST_JSON_FILE = RESULTS_DIR / "latest.json"
LATEST_SUMMARY_FILE = RESULTS_DIR / "latest_summary.txt"
