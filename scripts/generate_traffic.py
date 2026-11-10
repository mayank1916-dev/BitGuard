#!/usr/bin/env python3
"""Realistic historical traffic and synthetic anomaly generator for BitGuard Shadow-Mode Pilot (Milestone S26).

Generates a realistic 14+ day transaction dataset with:
- Hourly/daily diurnal seasonality.
- Heavy tail of large transfers (Log-normal + Pareto distribution).
- Stable destination address set (~88%) plus occasional new destinations (~12%).
- Market volatility volume spike episodes (Days 4 and 11).
- Ground truth labelling ('BENIGN' vs 'ANOMALY'/'ATTACK') for rigorous false-positive measurement.
- Real RLP-encoded EVM transaction bytes for raw byte source-of-truth validation.
- Support for importing real historical logs (tagged REAL) from data/ or CLI arguments.
"""

import argparse
import hashlib
import json
import math
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import rlp

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Primary monitored hot wallet and chain
DEFAULT_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
DEFAULT_CHAIN = "ethereum"
DEFAULT_ASSET = "ETH"

# Predefined stable destination pool (exchanges, liquidity pools, OTC desks, verified users)
STABLE_DESTINATIONS = [
    f"0x{i:02x}{hashlib.sha256(f'stable-partner-{i}'.encode()).hexdigest()[:38]}"
    for i in range(1, 51)
]


def build_raw_legacy_tx(to_hex: str, value_wei: int, nonce: int = 0) -> str:
    """Builds valid raw unsigned EVM transaction bytes hex."""
    clean_hex = to_hex[2:] if to_hex.startswith("0x") else to_hex
    clean_hex = clean_hex.zfill(40)
    to_bytes = bytes.fromhex(clean_hex)
    gas_price = 25_000_000_000  # 25 gwei
    gas_limit = 21000
    payload = [nonce, gas_price, gas_limit, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


def build_raw_eip7702_tx(
    to_hex: str,
    delegate_hex: str,
    value_wei: int = 0,
    nonce: int = 0,
) -> str:
    """Builds valid Type-4 EIP-7702 transaction bytes hex with authorization list."""
    clean_to = (to_hex[2:] if to_hex.startswith("0x") else to_hex).zfill(40)
    clean_del = (delegate_hex[2:] if delegate_hex.startswith("0x") else delegate_hex).zfill(40)

    auth_item = [
        1,  # chain_id
        bytes.fromhex(clean_del),  # delegate address
        nonce,  # auth nonce
        27,  # y_parity
        b"\x01" * 32,  # r
        b"\x02" * 32,  # s
    ]
    tx_payload = [
        1,  # chain_id
        nonce,  # nonce
        30_000_000_000,  # max_priority_fee_per_gas
        50_000_000_000,  # max_fee_per_gas
        65000,  # gas_limit
        bytes.fromhex(clean_to),  # to
        value_wei,  # value
        b"",  # data
        [],  # access_list
        [auth_item],  # authorization_list
    ]
    encoded = b"\x04" + rlp.encode(tx_payload)
    return "0x" + encoded.hex()


def generate_synthetic_traffic(
    days: int = 14,
    base_events_per_day: int = 220,
    start_time_iso: str | None = None,
    seed: int = 42,
    wallet: str = DEFAULT_WALLET,
) -> list[dict[str, Any]]:
    """Generates a realistic multi-day transaction log with seasonality, spikes, and ground truth."""
    random.seed(seed)

    if start_time_iso:
        start_dt = datetime.fromisoformat(start_time_iso.replace("Z", "+00:00"))
    else:
        # Default start date 14 days ago rounded to hour 00:00 UTC
        now = datetime.now(UTC)
        start_dt = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)

    start_ts = start_dt.timestamp()
    events: list[dict[str, Any]] = []
    event_counter = 1
    nonce_counter = 100

    # Volume spike days: e.g. Day 4 and Day 11 (0-indexed: 3 and 10)
    spike_days = {3, 10}

    for day_idx in range(days):
        day_date = start_dt + timedelta(days=day_idx)
        is_spike_day = day_idx in spike_days
        is_weekend = day_date.weekday() >= 5

        # Base multiplier for volume
        day_multiplier = 1.0
        if is_spike_day:
            day_multiplier = 3.6  # 3.6x volume spike on volatility days
        elif is_weekend:
            day_multiplier = 0.75  # Weekend dip
        else:
            day_multiplier = 1.15  # Normal weekday

        day_total_events = int(base_events_per_day * day_multiplier)

        # Distribute events across 24 hours using diurnal seasonality
        for hour in range(24):
            # Diurnal curve: peak at ~14:00 UTC, trough at ~02:00 UTC
            diurnal_weight = 1.0 + 0.65 * math.sin(2.0 * math.pi * (hour - 8.0) / 24.0)
            hour_fraction = max(0.1, diurnal_weight) / 24.0
            hour_events_count = max(1, int(day_total_events * hour_fraction))

            for _ in range(hour_events_count):
                second_in_hour = random.uniform(0, 3590)
                event_ts = start_ts + (day_idx * 86400) + (hour * 3600) + second_in_hour

                # -----------------------------------------------------
                # Amount distribution: Heavy tail (Log-normal + Pareto)
                # -----------------------------------------------------
                roll = random.random()
                if roll < 0.74:
                    # Retail customer transfers ($25 to $3,000)
                    amount_usd = round(random.lognormvariate(5.5, 1.1), 2)
                    amount_usd = max(25.0, min(amount_usd, 3_000.0))
                    transfer_tier = "retail"
                elif roll < 0.94:
                    # Medium transfers ($3,000 to $25,000)
                    amount_usd = round(random.uniform(3_000.0, 25_000.0), 2)
                    transfer_tier = "medium"
                elif roll < 0.985:
                    # Large institutional transfers ($25,000 to $48,000)
                    amount_usd = round(random.uniform(25_000.0, 48_000.0), 2)
                    transfer_tier = "institutional"
                else:
                    # Whale sweep / high-value transfers (Pareto tail $50,000 - $250,000)
                    # Pareto with alpha=1.8 gives realistic heavy tail
                    raw_pareto = 50_000.0 * (random.paretovariate(1.8))
                    amount_usd = round(min(raw_pareto, 250_000.0), 2)
                    transfer_tier = "whale"

                # -----------------------------------------------------
                # Destination address selection (Stable vs New)
                # -----------------------------------------------------
                dest_roll = random.random()
                if dest_roll < 0.88:
                    destination = random.choice(STABLE_DESTINATIONS)
                    is_new_dest = False
                else:
                    destination = f"0x{random.randint(1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):040x}"
                    is_new_dest = True

                # -----------------------------------------------------
                # Ground truth labelling and anomaly injection
                # -----------------------------------------------------
                ground_truth_label = "BENIGN"
                ground_truth_reason = "normal_retail_or_treasury_traffic"
                scenario = "normal"
                intent_id = None
                delegate_addr = None
                delegate_code_hash = None
                simulate_intent_mismatch = False

                # Inject realistic anomaly scenarios on specific fractions
                anomaly_roll = random.random()
                if is_spike_day and anomaly_roll < 0.035:
                    # Volatility rapid burst anomaly
                    ground_truth_label = "ANOMALY"
                    ground_truth_reason = "velocity_spike_rapid_burst"
                    scenario = "velocity_burst"
                    amount_usd = round(random.uniform(60_000.0, 120_000.0), 2)
                elif anomaly_roll < 0.004:
                    # Unapproved EIP-7702 delegation attempt
                    ground_truth_label = "ANOMALY"
                    ground_truth_reason = "unapproved_eip7702_delegation"
                    scenario = "unapproved_delegation"
                    delegate_addr = "0xBadc0de999999999999999999999999999999999"
                    delegate_code_hash = "0x" + hashlib.sha256(b"exploit_bytecode").hexdigest()
                elif anomaly_roll < 0.009:
                    # Splitting just under single-tx limit ($49,500)
                    ground_truth_label = "ANOMALY"
                    ground_truth_reason = "split_under_single_tx_limit"
                    scenario = "split_under_limit"
                    amount_usd = 49_500.0
                elif anomaly_roll < 0.013:
                    # Ledger intent mismatch anomaly
                    ground_truth_label = "ANOMALY"
                    ground_truth_reason = "custody_ledger_intent_mismatch"
                    scenario = "intent_mismatch"
                    intent_id = f"intent-unregistered-{event_counter:06d}"
                    simulate_intent_mismatch = True

                # Convert amount_usd to approximate wei (assume $3,000/ETH for EVM bytecode)
                eth_price_usd = 3000.0
                value_wei = int((amount_usd / eth_price_usd) * 10**18)
                nonce_counter += 1

                # Generate raw EVM bytecode matching transaction type
                if delegate_addr:
                    raw_tx = build_raw_eip7702_tx(
                        to_hex=destination,
                        delegate_hex=delegate_addr,
                        value_wei=value_wei,
                        nonce=nonce_counter,
                    )
                else:
                    raw_tx = build_raw_legacy_tx(
                        to_hex=destination,
                        value_wei=value_wei,
                        nonce=nonce_counter,
                    )

                event_id = f"syn-tx-{event_counter:06d}"
                tx_digest = f"0x{hashlib.sha256(f'{DEFAULT_CHAIN}:{wallet}:{destination}:{amount_usd}:{event_ts}:{event_id}'.encode()).hexdigest()}"

                decoded_tx_meta: dict[str, Any] = {
                    "chain": DEFAULT_CHAIN,
                    "from_address": wallet,
                    "to_address": destination,
                    "amount": str(value_wei),
                    "asset": DEFAULT_ASSET,
                    "digest": tx_digest,
                }
                if delegate_addr:
                    decoded_tx_meta["delegate_address"] = delegate_addr
                    decoded_tx_meta["authorizations"] = [{
                        "chain_id": 1,
                        "address": delegate_addr,
                        "nonce": nonce_counter,
                        "authority": None,
                    }]

                event_record: dict[str, Any] = {
                    "id": event_id,
                    "ts": round(event_ts, 3),
                    "datetime_utc": datetime.fromtimestamp(event_ts, UTC).isoformat(),
                    "day_index": day_idx + 1,
                    "hour_utc": hour,
                    "chain": DEFAULT_CHAIN,
                    "wallet": wallet,
                    "asset": DEFAULT_ASSET,
                    "amount": amount_usd,
                    "amount_usd": amount_usd,
                    "destination": destination,
                    "is_new_destination": is_new_dest,
                    "transfer_tier": transfer_tier,
                    "raw_tx": raw_tx,
                    "intent_id": None if simulate_intent_mismatch else intent_id,
                    "data_label": "SYNTHETIC",
                    "ground_truth_label": ground_truth_label,
                    "ground_truth_reason": ground_truth_reason,
                    "scenario": scenario,
                    "metadata": {
                        "amount_usd": amount_usd,
                        "ts": round(event_ts, 3),
                        "chain": DEFAULT_CHAIN,
                        "asset": DEFAULT_ASSET,
                        "wallet": wallet,
                        "destination": destination,
                        "data_label": "SYNTHETIC",
                        "is_backtest": True,
                        "scenario": scenario,
                        "ground_truth_label": ground_truth_label,
                        "ground_truth_reason": ground_truth_reason,
                        "decoded_tx": decoded_tx_meta,
                    },
                }

                if delegate_addr:
                    event_record["delegate"] = delegate_addr
                    event_record["delegate_code_hash"] = delegate_code_hash
                    event_record["metadata"]["delegate"] = delegate_addr
                    event_record["metadata"]["delegate_code_hash"] = delegate_code_hash

                events.append(event_record)
                event_counter += 1

    # Sort deterministically by timestamp
    events.sort(key=lambda e: e["ts"])
    return events


def import_real_log(file_path: Path) -> list[dict[str, Any]]:
    """Imports historical transactions from real exported CSV or JSONL (labelled REAL)."""
    if not file_path.exists():
        raise FileNotFoundError(f"Exported log file '{file_path}' does not exist")

    imported_events: list[dict[str, Any]] = []
    raw_text = file_path.read_text(encoding="utf-8").strip()

    if file_path.suffix.lower() == ".csv":
        import csv
        import io
        reader = csv.DictReader(io.StringIO(raw_text))
        for idx, row in enumerate(reader):
            low = {k.strip().lower(): v for k, v in row.items() if k}
            ts_val = float(low.get("ts", datetime.now(UTC).timestamp()))
            amt = float(low.get("amount", low.get("amount_usd", 0.0)))
            wallet = str(low.get("wallet", DEFAULT_WALLET))
            dest = str(low.get("destination", low.get("to", STABLE_DESTINATIONS[0])))
            chain = str(low.get("chain", DEFAULT_CHAIN))
            asset = str(low.get("asset", DEFAULT_ASSET))
            raw_tx = str(low.get("raw_tx", build_raw_legacy_tx(to_hex=dest, value_wei=int(amt * 10**14))))
            rec: dict[str, Any] = {
                "id": str(low.get("id", f"real-csv-{idx+1:05d}")),
                "ts": ts_val,
                "chain": chain,
                "wallet": wallet,
                "asset": asset,
                "amount": amt,
                "amount_usd": amt,
                "destination": dest,
                "raw_tx": raw_tx,
                "intent_id": low.get("intent_id"),
                "data_label": "REAL",
                "ground_truth_label": "BENIGN",
                "ground_truth_reason": "imported_real_history",
                "scenario": "normal",
                "metadata": {
                    "amount_usd": amt,
                    "ts": ts_val,
                    "chain": chain,
                    "asset": asset,
                    "wallet": wallet,
                    "destination": dest,
                    "data_label": "REAL",
                    "is_backtest": True,
                    "scenario": "normal",
                    "ground_truth_label": "BENIGN",
                },
            }
            imported_events.append(rec)
    else:
        # JSONL format
        for _idx, line in enumerate(raw_text.splitlines()):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            amt = float(obj.get("amount", obj.get("amount_usd", 0.0)))
            dest = str(obj.get("destination", obj.get("to", STABLE_DESTINATIONS[0])))
            obj["data_label"] = "REAL"
            obj["ground_truth_label"] = obj.get("ground_truth_label", "BENIGN")
            if "raw_tx" not in obj:
                obj["raw_tx"] = build_raw_legacy_tx(to_hex=dest, value_wei=int(amt * 10**14))
            if "metadata" not in obj:
                obj["metadata"] = dict(obj)
            obj["metadata"]["data_label"] = "REAL"
            obj["metadata"]["is_backtest"] = True
            imported_events.append(obj)

    imported_events.sort(key=lambda e: float(e.get("ts", 0.0)))
    return imported_events


def save_traffic_jsonl(events: list[dict[str, Any]], output_path: Path) -> None:
    """Writes event sequence to JSONL file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="BitGuard Traffic Generator for Shadow-Mode Pilot (Milestone S26)")
    parser.add_argument("--days", type=int, default=14, help="Number of simulated days (default: 14)")
    parser.add_argument("--events-per-day", type=int, default=220, help="Base events per day (default: 220)")
    parser.add_argument("--output", type=str, default="data/synthetic_14d_traffic.jsonl", help="Output JSONL path")
    parser.add_argument("--import-file", type=str, default=None, help="Import real historical log file (labelled REAL)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    out_file = Path(args.output)

    if args.import_file:
        import_path = Path(args.import_file)
        print(f"[*] Importing real historical events from '{import_path}'...")
        events = import_real_log(import_path)
        print(f"[+] Imported {len(events)} events (Data Provenance: REAL)")
    else:
        # Check if real data log exists in data/ directory
        data_dir = Path("data")
        real_candidates = []
        if data_dir.exists():
            for f in data_dir.glob("*"):
                if f.is_file() and f.suffix in [".jsonl", ".csv"] and "synthetic" not in f.name:
                    real_candidates.append(f)

        if real_candidates:
            chosen = real_candidates[0]
            print(f"[*] Found real exported log in data/: '{chosen}'. Importing as REAL...")
            events = import_real_log(chosen)
            print(f"[+] Imported {len(events)} events (Data Provenance: REAL)")
        else:
            print(f"[*] Generating realistic SYNTHETIC traffic over {args.days} days...")
            events = generate_synthetic_traffic(
                days=args.days,
                base_events_per_day=args.events_per_day,
                seed=args.seed,
            )
            print(f"[+] Generated {len(events)} events (Data Provenance: SYNTHETIC)")

    save_traffic_jsonl(events, out_file)
    print(f"[+] Output written to {out_file.resolve()}")

    # Print summary statistics
    total_val = sum(float(e.get("amount_usd", 0.0)) for e in events)
    benign_count = sum(1 for e in events if e.get("ground_truth_label") == "BENIGN")
    anomaly_count = len(events) - benign_count
    whale_count = sum(1 for e in events if float(e.get("amount_usd", 0.0)) >= 50_000.0)

    print("\n--- Dataset Profile Summary ---")
    print(f"Total Events: {len(events):,} [{events[0]['data_label']}]")
    print(f"Total Value: ${total_val:,.2f} [{events[0]['data_label']}]")
    print(f"Benign Events: {benign_count:,} ({benign_count/len(events)*100:.1f}%) [{events[0]['data_label']}]")
    print(f"Anomalies / Attacks: {anomaly_count:,} ({anomaly_count/len(events)*100:.1f}%) [{events[0]['data_label']}]")
    print(f"Whale Transfers (>= $50k): {whale_count:,} [{events[0]['data_label']}]")


if __name__ == "__main__":
    main()
