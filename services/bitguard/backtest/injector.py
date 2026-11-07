"""Scenario injector for synthetic attack pattern simulation (Milestone S22 / F8).

Scenarios are DATA describing patterns (split_under_limit, rapid_velocity,
new_destination_burst, unapproved_delegation_flag, unmatched_intent_burst).
No exploit code or real blockchain interactions.
"""

import hashlib
import logging
from pathlib import Path
from typing import Any

import yaml

from services.bitguard.backtest.models import ScenarioPattern
from services.bitguard.models import DecodedTx, SigningRequest

logger = logging.getLogger("bitguard.backtest.injector")


class ScenarioInjector:
    """Loads YAML scenario definitions and overlays them on real traffic as SYNTHETIC events."""

    def __init__(self, scenarios_dir: Path | None = None) -> None:
        self.scenarios_dir = scenarios_dir or (Path(__file__).resolve().parent.parent.parent.parent / "scenarios")
        self._patterns_cache: dict[str, ScenarioPattern] = {}

    def get_scenario_paths(self) -> list[Path]:
        """Finds all YAML scenario files in the configured scenarios directory."""
        if not self.scenarios_dir.exists():
            return []
        return sorted(list(self.scenarios_dir.glob("*.yaml")) + list(self.scenarios_dir.glob("*.yml")))

    def load_scenario(self, scenario_id: str) -> ScenarioPattern | None:
        """Loads a specific scenario pattern by ID."""
        if scenario_id in self._patterns_cache:
            return self._patterns_cache[scenario_id]

        target_file = self.scenarios_dir / f"{scenario_id}.yaml"
        if not target_file.exists():
            target_file = self.scenarios_dir / f"{scenario_id}.yml"
        if not target_file.exists():
            # Search by ID inside all scenario files
            for p in self.get_scenario_paths():
                try:
                    data = yaml.safe_load(p.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("id") == scenario_id:
                        pattern = ScenarioPattern.model_validate(data)
                        self._patterns_cache[scenario_id] = pattern
                        return pattern
                except Exception as exc:
                    logger.warning("Error reading scenario %s: %s", p, exc)
            return None

        try:
            data = yaml.safe_load(target_file.read_text(encoding="utf-8"))
            pattern = ScenarioPattern.model_validate(data)
            self._patterns_cache[scenario_id] = pattern
            return pattern
        except Exception as exc:
            logger.warning("Error loading scenario %s: %s", target_file, exc)
            return None

    def list_available_scenarios(self) -> list[ScenarioPattern]:
        """Returns all available scenario patterns."""
        patterns: list[ScenarioPattern] = []
        for p in self.get_scenario_paths():
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "id" in data:
                    pattern = ScenarioPattern.model_validate(data)
                    self._patterns_cache[pattern.id] = pattern
                    patterns.append(pattern)
            except Exception as exc:
                logger.warning("Failed parsing scenario file %s: %s", p, exc)
        return patterns

    def generate_events(
        self,
        scenario: ScenarioPattern,
        start_ts: float,
        index_offset: int = 0,
    ) -> list[SigningRequest]:
        """Generates synthetic SigningRequest objects according to the scenario pattern."""
        events: list[SigningRequest] = []
        destinations = scenario.destinations or ["0xDefaultAttackerSink01"]

        for i in range(scenario.count):
            event_ts = start_ts + (i * scenario.interval_seconds)
            req_id = f"syn-{scenario.id}-{index_offset + i + 1:03d}"
            dest = destinations[i % len(destinations)]

            metadata: dict[str, Any] = {
                "amount_usd": float(scenario.amount_usd_per_event),
                "ts": float(event_ts),
                "chain": scenario.chain,
                "asset": scenario.asset,
                "wallet": scenario.target_wallet,
                "destination": dest,
                "scenario": scenario.pattern_type,
                "data_label": "SYNTHETIC",
                "is_backtest": True,
            }

            if scenario.delegate_address:
                metadata["delegate"] = scenario.delegate_address
            if scenario.delegate_code_hash:
                metadata["delegate_code_hash"] = scenario.delegate_code_hash
            if scenario.simulate_intent_mismatch:
                metadata["simulate_intent_mismatch"] = True
            if scenario.intent_id:
                metadata["intent_id"] = scenario.intent_id

            # Canonical decoded tx representation for EVM engine
            tx_digest = f"0x{hashlib.sha256(f'{scenario.chain}:{scenario.target_wallet}:{dest}:{event_ts}'.encode()).hexdigest()}"
            decoded = DecodedTx(
                chain=scenario.chain,
                from_address=scenario.target_wallet,
                to_address=dest,
                amount=str(int(scenario.amount_usd_per_event * 100)),
                asset=scenario.asset,
                digest=tx_digest,
            )
            metadata["decoded_tx"] = decoded.model_dump(mode="json")

            req = SigningRequest(
                id=req_id,
                raw_tx="0x02f87001synthetic",
                chain=scenario.chain,
                wallet=scenario.target_wallet,
                intent_id=scenario.intent_id,
                metadata=metadata,
            )
            events.append(req)

        return events

    def overlay(
        self,
        real_events: list[SigningRequest],
        scenario_ids: list[str],
    ) -> list[SigningRequest]:
        """Overlays requested scenarios as SYNTHETIC events on top of historical traffic."""
        if not scenario_ids:
            # Deterministically sort real events by timestamp
            return sorted(real_events, key=lambda e: float(e.metadata.get("ts", 0.0)))

        # Determine reference timestamp from real events
        if real_events:
            timestamps = [float(e.metadata.get("ts", 0.0)) for e in real_events]
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            # Position synthetic attacks towards the middle / active period
            anchor_ts = min_ts + ((max_ts - min_ts) * 0.4) if max_ts > min_ts else min_ts
        else:
            anchor_ts = 1730299400.0

        all_events: list[SigningRequest] = list(real_events)
        offset = 0

        for sc_id in scenario_ids:
            pattern = self.load_scenario(sc_id)
            if not pattern:
                logger.warning("Scenario pattern '%s' requested but not found", sc_id)
                continue

            syn_events = self.generate_events(
                scenario=pattern,
                start_ts=anchor_ts + (offset * 120.0),
                index_offset=offset,
            )
            all_events.extend(syn_events)
            offset += len(syn_events)

        # Deterministic sorting in timestamp order
        all_events.sort(key=lambda e: (float(e.metadata.get("ts", 0.0)), e.id))
        return all_events


scenario_injector = ScenarioInjector()
