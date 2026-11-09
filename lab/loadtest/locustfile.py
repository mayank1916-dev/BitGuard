"""Locust load test suite for BitGuard Defensive Signing Firewall (Milestone S25).

Evaluates:
1. Local Fast Path: POST /v1/evaluate (decode + intent + limits + delegation + decision)
2. End-to-End Signing Path: POST /rpc (JSON-RPC bitguard_signTransaction calling Signer Shim)

Usage:
    locust -f lab/loadtest/locustfile.py --headless -u 50 -r 10 --run-time 5m --host http://localhost:8000
    locust -f lab/loadtest/locustfile.py --headless -u 200 -r 20 --run-time 5m --host http://localhost:8000
    locust -f lab/loadtest/locustfile.py --headless -u 500 -r 50 --run-time 5m --host http://localhost:8000
"""

import itertools

import rlp
from locust import HttpUser, between, task

BENIGN_DEST_RAW = "1111111111111111111111111111111111111111"
OWNED_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


def build_raw_legacy_tx(to_hex: str = BENIGN_DEST_RAW, value: int = 1000, nonce: int = 0) -> str:
    """Constructs a valid raw unsigned legacy EVM transaction hex."""
    clean_hex = to_hex[2:] if to_hex.startswith("0x") else to_hex
    payload = [nonce, 20_000_000_000, 21000, bytes.fromhex(clean_hex), value, b""]
    return "0x" + rlp.encode(payload).hex()


SAMPLE_RAW_TX = build_raw_legacy_tx(value=1000)


class FastPathUser(HttpUser):
    """Simulates high-throughput client sending dry-run evaluation requests to /v1/evaluate."""

    wait_time = between(0.001, 0.005)
    _counter = itertools.count()

    @task(10)
    def evaluate_transaction(self) -> None:
        """Sends POST /v1/evaluate measuring policy decision pipeline latency."""
        req_id = f"eval-load-{next(self._counter)}"
        payload = {
            "id": req_id,
            "chain": "ethereum",
            "raw_tx": SAMPLE_RAW_TX,
            "wallet": OWNED_WALLET,
            "wallet_group": "default",
            "mode": "SIMULATION",
            "metadata": {
                "amount_usd": 100.0,
                "is_loadtest": True,
            },
        }
        headers = {
            "Content-Type": "application/json",
            "X-Dev-Role": "operator",
            "X-Caller-ID": f"client-{self.environment.runner.user_count if self.environment and self.environment.runner else 1}",
        }

        with self.client.post(
            "/v1/evaluate",
            json=payload,
            headers=headers,
            catch_response=True,
            name="/v1/evaluate (Fast Path)",
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "verdict" in data and "timings" in data:
                    response.success()
                else:
                    response.failure(f"Malformed evaluate response: {data}")
            else:
                response.failure(f"HTTP {response.status_code}: {response.text}")


class SigningPathUser(HttpUser):
    """Simulates custodial signing client sending JSON-RPC bitguard_signTransaction requests."""

    wait_time = between(0.002, 0.010)
    _counter = itertools.count()

    @task(5)
    def sign_transaction(self) -> None:
        """Sends POST /rpc with bitguard_signTransaction measuring end-to-end signing latency."""
        req_id = f"rpc-load-{next(self._counter)}"
        rpc_payload = {
            "jsonrpc": "2.0",
            "method": "bitguard_signTransaction",
            "params": {
                "chain": "ethereum",
                "raw_tx": SAMPLE_RAW_TX,
                "amount_usd": 10.0,
                "metadata": {
                    "is_loadtest": True,
                },
            },
            "id": req_id,
        }
        worker_id = (self.environment.runner.user_count if self.environment and self.environment.runner else 1)
        headers = {
            "Content-Type": "application/json",
            "X-Client-Cert-SAN": f"spiffe://exchange.internal/workload/custody-{worker_id % 50}",
        }

        with self.client.post(
            "/rpc",
            json=rpc_payload,
            headers=headers,
            catch_response=True,
            name="/rpc (End-to-End Signing)",
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "result" in data or "error" in data:
                    response.success()
                else:
                    response.failure(f"Unexpected JSON-RPC response: {data}")
            else:
                response.failure(f"HTTP {response.status_code}: {response.text}")
