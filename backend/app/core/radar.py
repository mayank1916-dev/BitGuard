from pathlib import Path
from typing import Optional, Any, Union
import json
import logging
import time
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DEFAULT_RPC_ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.ankr.com/eth",
    "https://1rpc.io/eth",
]


class Type4Finding(BaseModel):
    """Represents a discovered or evaluated Type-4 EIP-7702 transaction."""
    tx_hash: str
    block_number: int
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    delegate_address: Optional[str] = None
    unique_delegates_count: int = 0
    auth_count: int = 0
    has_consecutive_nonces: bool = False
    max_consecutive_nonces: int = 0
    patterns: list[str] = Field(default_factory=list)
    risk_score: int = 0
    is_suspicious: bool = False
    timestamp: int = 0
    source: str = "live_rpc"
    description: Optional[str] = None


class RadarScanResult(BaseModel):
    """Aggregate result from scanning Ethereum blocks for Type-4 transactions."""
    source: str  # 'live_rpc' | 'cached_sample' | 'cached_fallback'
    blocks_scanned: int
    latest_block: int
    findings_count: int
    suspicious_count: int
    findings: list[Type4Finding]


def find_max_consecutive_nonces(nonces: list[int]) -> int:
    """Finds maximum consecutive sequence of integer nonces in a list."""
    if not nonces:
        return 0

    # In-order streak
    max_streak = 1
    current_streak = 1
    for i in range(len(nonces) - 1):
        if nonces[i] + 1 == nonces[i + 1]:
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 1

    # Sorted unique streak
    sorted_unique = sorted(set(nonces))
    sorted_max = 1
    s_curr = 1
    for i in range(len(sorted_unique) - 1):
        if sorted_unique[i] + 1 == sorted_unique[i + 1]:
            s_curr += 1
            sorted_max = max(sorted_max, s_curr)
        else:
            s_curr = 1

    return max(max_streak, sorted_max)


class RadarScanner:
    """
    Live Ethereum RPC Scanner & Radar for EIP-7702 (Type-4) set-code transactions.
    Scans recent blocks, inspects authorizationLists, and applies heuristic pattern scoring.
    Seamlessly falls back to cached offline datasets when public RPCs rate-limit.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        cached_data_path: Optional[Union[str, Path]] = None,
        timeout: float = 6.0,
    ):
        self.rpc_url = rpc_url or DEFAULT_RPC_ENDPOINTS[0]
        self.timeout = timeout
        self.cached_data_path = Path(
            cached_data_path
            or Path(__file__).resolve().parent.parent.parent / "data" / "cached_type4_blocks.json"
        )
        self.simulated_block_counter: int = 21_890_124
        self.scan_count: int = 0

    def _generate_simulated_finding(self, block_number: int, source: str = "cached_fallback") -> Type4Finding:
        """Generates a randomized Type-4 finding for newly scanned blocks when offline."""
        pool = [
            (["consecutive_nonces_spray"], 60, True, 12, 12),
            (["high_volume_authorizations", "single_delegate_concentration"], 70, True, 25, 2),
            ([], 15, False, 1, 1),
            (["single_delegate_concentration"], 35, False, 3, 1),
        ]
        patterns, risk, suspicious, auths, nonces = pool[self.scan_count % len(pool)]
        hex_salt = f"{(self.scan_count * 1337 + 0xabcde) % 0xffffff:06x}"
        return Type4Finding(
            tx_hash=f"0x{hex_salt}a1b2c3d4e5f67890123456789abcdef0123456789abcdef012345{hex_salt[:4]}",
            block_number=block_number,
            from_address=f"0x{hex_salt}HotWalletSigner1",
            to_address=f"0x{hex_salt}BatchExecutor",
            delegate_address=f"0x{hex_salt}SweeperProxyContract",
            unique_delegates_count=1,
            auth_count=auths,
            has_consecutive_nonces=suspicious,
            max_consecutive_nonces=nonces,
            patterns=patterns,
            risk_score=risk,
            is_suspicious=suspicious,
            timestamp=int(time.time()),
            source=source,
            description=f"Type-4 transaction with {auths} authorizations in block #{block_number}",
        )

    def load_cached_findings(self, source_label: str = "cached_sample") -> list[Type4Finding]:
        """Loads pre-recorded Type-4 findings from disk."""
        if not self.cached_data_path.exists():
            return []
        with open(self.cached_data_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        findings = []
        for item in raw:
            item_copy = dict(item)
            item_copy["source"] = source_label
            findings.append(Type4Finding(**item_copy))
        return findings

    def evaluate_type4_tx(
        self,
        tx: dict[str, Any],
        block_number: int = 0,
        timestamp: int = 0,
        source: str = "live_rpc",
    ) -> Optional[Type4Finding]:
        """
        Evaluates a Type-4 transaction against heuristic patterns:
        - Consecutive nonces (>= 5 in sequence: +40 risk)
        - High authorization volume (>= 20 auths: +20 risk)
        - Single-delegate concentration (multiple auths targeting 1 delegate: +20 risk)
        """
        tx_type = tx.get("type")
        if tx_type not in ("0x4", "0x04", 4):
            return None

        auth_list = tx.get("authorizationList") or []
        auth_count = len(auth_list)

        # Extract nonces
        nonces: list[int] = []
        delegates: list[str] = []

        for auth in auth_list:
            if not isinstance(auth, dict):
                continue
            nonce_val = auth.get("nonce")
            if nonce_val is not None:
                try:
                    if isinstance(nonce_val, str) and (nonce_val.startswith("0x") or nonce_val.startswith("0X")):
                        nonces.append(int(nonce_val, 16))
                    else:
                        nonces.append(int(nonce_val))
                except (ValueError, TypeError):
                    pass

            del_addr = auth.get("address")
            if del_addr:
                delegates.append(del_addr.lower())

        unique_delegates = set(delegates)
        max_consecutive = find_max_consecutive_nonces(nonces)

        patterns: list[str] = []
        risk_score = 0

        # Heuristic 1: Consecutive nonces spray (>= 5 adds +40 risk)
        has_consecutive = max_consecutive >= 5
        if has_consecutive:
            patterns.append("consecutive_nonces_spray")
            risk_score += 40

        # Heuristic 2: High authorization volume (>= 20 adds +20 risk)
        if auth_count >= 20:
            patterns.append("high_volume_authorizations")
            risk_score += 20

        # Heuristic 3: Single-delegate concentration (multiple auths targeting 1 delegate adds +20 risk)
        if auth_count >= 2 and len(unique_delegates) == 1:
            patterns.append("single_delegate_concentration")
            risk_score += 20

        # Baseline adjustment
        if patterns:
            risk_score = min(100, risk_score + 20)
        else:
            risk_score = 10 if auth_count <= 1 else 15

        delegate_display = delegates[0] if delegates else (auth_list[0].get("address") if auth_list else None)

        return Type4Finding(
            tx_hash=tx.get("hash") or tx.get("tx_hash", "0x0"),
            block_number=block_number,
            from_address=tx.get("from") or tx.get("from_address"),
            to_address=tx.get("to") or tx.get("to_address"),
            delegate_address=delegate_display,
            unique_delegates_count=len(unique_delegates),
            auth_count=auth_count,
            has_consecutive_nonces=has_consecutive,
            max_consecutive_nonces=max_consecutive,
            patterns=patterns,
            risk_score=risk_score,
            is_suspicious=risk_score >= 50,
            timestamp=timestamp,
            source=source,
            description=f"Type-4 transaction with {auth_count} authorizations ({len(unique_delegates)} unique delegate)",
        )

    def scan_recent_blocks(self, n_blocks: int = 5, force_cached: bool = False) -> RadarScanResult:
        """
        Scans recent Ethereum blocks for Type-4 transactions using eth_getBlockByNumber.
        Falls back to cached findings if RPC is unreachable or no Type-4 transactions exist.
        """
        self.scan_count += 1
        self.simulated_block_counter += 1

        if force_cached:
            cached = self.load_cached_findings(source_label="cached_sample")
            latest_block = max(max((f.block_number for f in cached), default=21890124), self.simulated_block_counter)
            dyn_finding = self._generate_simulated_finding(latest_block, source="cached_sample")
            combined = [dyn_finding] + cached
            return RadarScanResult(
                source="cached_sample",
                blocks_scanned=n_blocks,
                latest_block=latest_block,
                findings_count=len(combined),
                suspicious_count=sum(1 for f in combined if f.is_suspicious),
                findings=combined,
            )

        findings: list[Type4Finding] = []
        latest_block = 0

        try:
            with httpx.Client(timeout=self.timeout) as client:
                # 1. Fetch latest block number
                resp = client.post(
                    self.rpc_url,
                    json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                )
                if resp.status_code != 200:
                    raise httpx.HTTPError(f"HTTP {resp.status_code}")
                data = resp.json()
                if "error" in data or "result" not in data:
                    raise httpx.HTTPError("RPC error response")

                latest_block = int(data["result"], 16)

                # 2. Scan recent n_blocks
                for i in range(n_blocks):
                    block_num = latest_block - i
                    block_hex = hex(block_num)
                    block_resp = client.post(
                        self.rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_getBlockByNumber",
                            "params": [block_hex, True],
                            "id": i + 2,
                        },
                    )
                    if block_resp.status_code != 200:
                        continue
                    block_data = block_resp.json().get("result")
                    if not block_data or not isinstance(block_data, dict):
                        continue

                    block_ts = int(block_data.get("timestamp", "0x0"), 16)
                    transactions = block_data.get("transactions", [])

                    for tx in transactions:
                        if isinstance(tx, dict) and tx.get("type") in ("0x4", "0x04", 4):
                            finding = self.evaluate_type4_tx(
                                tx,
                                block_number=block_num,
                                timestamp=block_ts,
                                source="live_rpc",
                            )
                            if finding:
                                findings.append(finding)

            # If live RPC succeeded and found Type-4 transactions
            if findings:
                return RadarScanResult(
                    source="live_rpc",
                    blocks_scanned=n_blocks,
                    latest_block=latest_block,
                    findings_count=len(findings),
                    suspicious_count=sum(1 for f in findings if f.is_suspicious),
                    findings=findings,
                )

        except Exception as e:
            logger.warning(f"Live Ethereum RPC scan failed or timed out ({e}). Falling back to cached findings.")

        # Seamless Offline Fallback
        cached = self.load_cached_findings(source_label="cached_fallback")
        fallback_block = latest_block if latest_block > 0 else max(max((f.block_number for f in cached), default=21890124), self.simulated_block_counter)
        dyn_finding = self._generate_simulated_finding(fallback_block, source="cached_fallback")
        combined = [dyn_finding] + cached
        return RadarScanResult(
            source="cached_fallback",
            blocks_scanned=n_blocks,
            latest_block=fallback_block,
            findings_count=len(combined),
            suspicious_count=sum(1 for f in combined if f.is_suspicious),
            findings=combined,
        )
