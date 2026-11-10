"""Comprehensive test suite for Task S27 - Address & Contract Risk Profiler.

Invariants Verified:
- Invariant #1: Cached lookups on the fast path (never on hot path).
- Invariant #3: Fail-Closed Default. Poisoned feed rejected; cache miss adds ELEVATED_RISK_UNPROFILED, never safe.
- Invariant #9: Environment & Safety Boundary. FAKE fixture lists only; never fabricate real sanctioned addresses.
"""

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import rlp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.engine.types import DecisionEngineConfig
from services.bitguard.models import OperationMode, SigningRequest, Verdict
from services.bitguard.policy.models import PolicyDocument
from services.bitguard.profiler.enricher import CachedProfilerEnricher
from services.bitguard.profiler.lists import ListIntegrityError, SanctionListStore
from services.bitguard.profiler.models import AddressProfile, ListManifest, ListManifestFile
from services.bitguard.profiler.provider import MockTaintProvider
from services.bitguard.profiler.scorer import ProfileScorer
from services.bitguard.profiler.worker import ProfileWorker
from services.bitguard.rpc.client import MockRpcClient


def build_test_raw_tx(to_addr: str) -> str:
    """Constructs valid decodable EVM raw legacy transaction bytes."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [0, 20_000_000_000, 21000, to_bytes, 1_000_000_000_000_000, b""]
    return "0x" + rlp.encode(payload).hex()

# FAKE test fixture addresses (Invariant #9)
FAKE_SANCTIONED = "0xbad0000000000000000000000000000000000001"
FAKE_BLOCKED = "0xdead000000000000000000000000000000000001"
FAKE_BAD_HASH = "0xbadc0de000000000000000000000000000000000000000000000000000000001"
FAKE_CLEAN_DEST = "0x1111111111111111111111111111111111111111"
FAKE_WALLET = "0x9999999999999999999999999999999999999999"


@pytest.fixture
def clean_profiler_stores(tmp_path: Path):
    """Provides isolated list store and profiler worker with temporary directory."""
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir(parents=True, exist_ok=True)

    sanctions = [FAKE_SANCTIONED]
    blocklist = [FAKE_BLOCKED]
    bad_hashes = [FAKE_BAD_HASH]

    def _write_file(fname: str, items: list[str]) -> ListManifestFile:
        p = lists_dir / fname
        raw = json.dumps(items).encode("utf-8")
        p.write_bytes(raw)
        return ListManifestFile(
            filename=fname,
            sha256=hashlib.sha256(raw).hexdigest(),
            count=len(items),
        )

    files = [
        _write_file("sanctions.json", sanctions),
        _write_file("blocklist.json", blocklist),
        _write_file("known_bad_hashes.json", bad_hashes),
    ]
    manifest = ListManifest(
        version="1.0.0",
        created_at=datetime.now(UTC).isoformat(),
        files=files,
    )
    (lists_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    list_store = SanctionListStore(lists_dir=lists_dir)
    list_store.load_from_directory()

    mock_rpc = MockRpcClient()
    mock_taint = MockTaintProvider()
    worker = ProfileWorker(rpc_client=mock_rpc, taint_provider=mock_taint, list_store=list_store)
    enricher = CachedProfilerEnricher(worker=worker)

    return {
        "lists_dir": lists_dir,
        "list_store": list_store,
        "mock_rpc": mock_rpc,
        "mock_taint": mock_taint,
        "worker": worker,
        "enricher": enricher,
    }


def test_list_loading_and_matching(clean_profiler_stores):
    """Verifies that lists are loaded into memory and match addresses correctly."""
    store: SanctionListStore = clean_profiler_stores["list_store"]

    assert store.sanctions_count == 1
    assert store.blocklist_count == 1
    assert store.known_bad_hashes_count == 1

    # Exact matches
    assert store.is_sanctioned(FAKE_SANCTIONED) is True
    assert store.is_sanctioned(FAKE_SANCTIONED.upper()) is True
    assert store.is_blocked(FAKE_BLOCKED) is True
    assert store.is_known_bad_code(FAKE_BAD_HASH) is True

    # Negative matches
    assert store.is_sanctioned(FAKE_CLEAN_DEST) is False
    assert store.is_blocked(FAKE_CLEAN_DEST) is False
    assert store.is_known_bad_code("0x0000000000000000000000000000000000000000000000000000000000000000") is False

    # Match address helper
    assert store.match_address(FAKE_SANCTIONED) == "SANCTIONS"
    assert store.match_address(FAKE_BLOCKED) == "BLOCKLIST"
    assert store.match_address(FAKE_CLEAN_DEST) is None


def test_microsecond_level_lookup_benchmark(clean_profiler_stores):
    """Benchmarking test proving in-memory set lookups complete in microseconds."""
    store: SanctionListStore = clean_profiler_stores["list_store"]

    # Pre-populate store with 1,000 fake addresses to test realistic scale
    large_set = {f"0x{i:040x}" for i in range(1, 1001)}
    store.reset_for_test(sanctions=large_set)

    test_addr = "0x0000000000000000000000000000000000000500"
    iterations = 20_000

    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = store.is_sanctioned(test_addr)
    t1 = time.perf_counter()

    total_time_s = t1 - t0
    avg_latency_us = (total_time_s / iterations) * 1_000_000.0

    # Ensure average lookup is well under 5 microseconds
    assert avg_latency_us < 5.0, f"Expected < 5.0 us, measured {avg_latency_us:.3f} us"


def test_list_refresh_with_bad_checksum_rejected(tmp_path: Path):
    """Verifies that a tampered file or bad checksum causes refresh to reject and preserve state."""
    lists_dir = tmp_path / "active_lists"
    lists_dir.mkdir(parents=True, exist_ok=True)
    (lists_dir / "sanctions.json").write_text(json.dumps([FAKE_SANCTIONED]), encoding="utf-8")
    sanct_hash = hashlib.sha256(json.dumps([FAKE_SANCTIONED]).encode("utf-8")).hexdigest()
    manifest = ListManifest(
        created_at=datetime.now(UTC).isoformat(),
        files=[ListManifestFile(filename="sanctions.json", sha256=sanct_hash, count=1)],
    )
    (lists_dir / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")

    store = SanctionListStore(lists_dir=lists_dir)
    store.load_from_directory()
    assert store.sanctions_count == 1
    assert store.is_sanctioned(FAKE_SANCTIONED) is True

    # Create staging dir with a tampered file (checksum declared does not match actual bytes)
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    poisoned_payload = ["0xbadf00d000000000000000000000000000000001"]
    (staging_dir / "sanctions.json").write_text(json.dumps(poisoned_payload), encoding="utf-8")
    fake_manifest = ListManifest(
        created_at=datetime.now(UTC).isoformat(),
        files=[ListManifestFile(filename="sanctions.json", sha256="0000000000000000000000000000000000000000000000000000000000000000", count=1)],
    )
    (staging_dir / "manifest.json").write_text(fake_manifest.model_dump_json(), encoding="utf-8")

    # Refresh must fail and raise ListIntegrityError
    with pytest.raises(ListIntegrityError, match="Checksum mismatch"):
        store.refresh_from_staging(staging_dir)

    # Invariant #3: Fail-closed default - existing in-memory sets remain intact
    assert store.sanctions_count == 1
    assert store.is_sanctioned(FAKE_SANCTIONED) is True
    assert store.is_sanctioned("0xbadf00d000000000000000000000000000000001") is False


def test_list_refresh_atomic_swap_success(tmp_path: Path):
    """Verifies that a valid staging feed is swapped atomically into active memory and disk."""
    active_dir = tmp_path / "active"
    staging_dir = tmp_path / "staging"
    active_dir.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir(parents=True, exist_ok=True)

    store = SanctionListStore(lists_dir=active_dir)
    assert store.sanctions_count == 0

    # Write valid staging files
    new_sanct_addr = "0xbad0000000000000000000000000000000000099"
    new_sanctions = [new_sanct_addr]
    content_bytes = json.dumps(new_sanctions).encode("utf-8")
    (staging_dir / "sanctions.json").write_bytes(content_bytes)
    sha256 = hashlib.sha256(content_bytes).hexdigest()

    manifest = ListManifest(
        created_at=datetime.now(UTC).isoformat(),
        files=[ListManifestFile(filename="sanctions.json", sha256=sha256, count=1)],
    )
    (staging_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    store.refresh_from_staging(staging_dir)
    assert store.sanctions_count == 1
    assert store.is_sanctioned(new_sanct_addr) is True
    # Verify disk files were updated
    assert (active_dir / "sanctions.json").exists()


def test_manifest_ed25519_signature_verification(tmp_path: Path):
    """Verifies that an optional Ed25519 signature on the manifest is cryptographically enforced."""
    lists_dir = tmp_path / "signed_lists"
    lists_dir.mkdir(parents=True, exist_ok=True)

    priv_key = Ed25519PrivateKey.generate()
    pub_key_hex = priv_key.public_key().public_bytes_raw().hex()

    sanct_bytes = json.dumps([FAKE_SANCTIONED]).encode("utf-8")
    (lists_dir / "sanctions.json").write_bytes(sanct_bytes)
    sanct_sha = hashlib.sha256(sanct_bytes).hexdigest()

    manifest = ListManifest(
        created_at=datetime.now(UTC).isoformat(),
        files=[ListManifestFile(filename="sanctions.json", sha256=sanct_sha, count=1)],
        signer_public_key=pub_key_hex,
    )

    # Sign canonical manifest
    canonical_dict = manifest.model_dump(exclude={"signature"})
    canonical_bytes = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
    sig = priv_key.sign(canonical_bytes).hex()
    manifest.signature = sig

    (lists_dir / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")

    # Valid signature loads smoothly
    store = SanctionListStore(lists_dir=lists_dir)
    store.load_from_directory()
    assert store.sanctions_count == 1

    # Corrupt signature -> must fail closed
    manifest.signature = "ff" * 64
    (lists_dir / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")

    with pytest.raises(ListIntegrityError, match="signature is invalid"):
        store.load_from_directory()


def test_profile_worker_contract_age_bytecode_and_first_time(clean_profiler_stores):
    """Verifies that the background profile worker correctly computes contract metadata."""
    worker: ProfileWorker = clean_profiler_stores["worker"]
    mock_rpc: MockRpcClient = clean_profiler_stores["mock_rpc"]
    mock_taint: MockTaintProvider = clean_profiler_stores["mock_taint"]

    test_contract = "0x2222222222222222222222222222222222222222"
    bytecode = "0x608060405234801561001057600080fd5b50"
    mock_rpc.set_contract(test_contract, bytecode)

    # Set contract age to 3 days (young contract heuristic)
    worker.set_contract_age(test_contract, age_blocks=21600, age_days=3.0)
    mock_taint.set_address_taint(test_contract, 75.0)

    # First-time destination check
    assert worker.is_first_time_destination(FAKE_WALLET, test_contract) is True

    # Out-of-band profile generation
    profile = worker.profile_address("ethereum", test_contract, wallet=FAKE_WALLET)
    assert profile.address == test_contract.lower()
    assert profile.is_contract is True
    assert profile.contract_age_days == 3.0
    assert profile.contract_age_blocks == 21600
    assert profile.code_hash is not None
    assert profile.taint_exposure_score == 75.0

    # Record destination and verify first-time status clears
    worker.record_wallet_destination(FAKE_WALLET, test_contract)
    assert worker.is_first_time_destination(FAKE_WALLET, test_contract) is False


def test_profile_scorer_heuristic_reasons():
    """Verifies that individual heuristics add appropriate weights and reasons."""
    scorer = ProfileScorer()

    # 1. New contract (< 7 days)
    new_contract_profile = AddressProfile(
        address=FAKE_CLEAN_DEST,
        is_contract=True,
        contract_age_days=2.5,
        contract_age_blocks=18000,
        taint_exposure_score=5.0,
    )
    res = scorer.score_profile(new_contract_profile, is_first_time=False)
    assert res.risk_score == 30
    assert any(r["code"] == "NEW_CONTRACT" for r in res.reasons)
    assert res.is_hard_deny is False  # Heuristic never hard-denies

    # 2. Known-bad bytecode match
    bad_code_profile = AddressProfile(
        address=FAKE_CLEAN_DEST,
        is_contract=True,
        code_hash=FAKE_BAD_HASH,
        is_known_bad_code=True,
    )
    res_code = scorer.score_profile(bad_code_profile)
    assert any(r["code"] == "KNOWN_BAD_BYTECODE" for r in res_code.reasons)

    # 3. Direct sanctions match -> hard deny
    sanct_profile = AddressProfile(
        address=FAKE_SANCTIONED,
        is_sanctioned=True,
    )
    res_sanct = scorer.score_profile(sanct_profile)
    assert res_sanct.is_hard_deny is True
    assert any(r["code"] == "LIST_MATCH" for r in res_sanct.reasons)
    assert res_sanct.risk_score == 100

    # 4. Taint exposure heuristic
    taint_profile = AddressProfile(
        address=FAKE_CLEAN_DEST,
        taint_exposure_score=85.0,
    )
    res_taint = scorer.score_profile(taint_profile)
    assert res_taint.risk_score == 40
    assert any(r["code"] == "TAINT_EXPOSURE" for r in res_taint.reasons)


def test_cache_miss_adds_elevated_risk_unprofiled():
    """Invariant #3: Cache miss adds ELEVATED_RISK_UNPROFILED weight, never safe."""
    scorer = ProfileScorer()
    res = scorer.score_profile(None)  # Cache miss

    assert res.is_unprofiled is True
    assert res.risk_score == 25
    assert len(res.reasons) == 1
    assert res.reasons[0]["code"] == "ELEVATED_RISK_UNPROFILED"
    assert res.reasons[0]["weight"] == 25
    assert res.is_hard_deny is False


def test_decision_engine_fast_path_cache_miss_behavior(clean_profiler_stores):
    """Verifies that the fast path reads the cache and applies ELEVATED_RISK_UNPROFILED on a miss."""
    enricher: CachedProfilerEnricher = clean_profiler_stores["enricher"]
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
        profiler=enricher,
    )

    # Unprofiled destination
    req = SigningRequest(
        chain="ethereum",
        wallet=FAKE_WALLET,
        raw_tx=build_test_raw_tx(FAKE_CLEAN_DEST),
        metadata={"amount_usd": 100.0, "enable_profiler": True},
    )

    decision = engine.evaluate(req)

    # Cache miss adds ELEVATED_RISK_UNPROFILED (weight 25 < threshold 50 -> ALLOW with unprofiled notice)
    assert any(r.code == "ELEVATED_RISK_UNPROFILED" for r in decision.reasons)
    assert decision.risk_score >= 25
    assert decision.verdict == Verdict.ALLOW


def test_decision_engine_fast_path_list_match_hard_deny(clean_profiler_stores):
    """Verifies that a cached list match strictly returns hard DENY."""
    worker: ProfileWorker = clean_profiler_stores["worker"]
    enricher: CachedProfilerEnricher = clean_profiler_stores["enricher"]

    # Pre-seed cache with sanctioned profile
    worker.profile_address("ethereum", FAKE_SANCTIONED)

    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
        profiler=enricher,
    )

    req = SigningRequest(
        chain="ethereum",
        wallet=FAKE_WALLET,
        raw_tx=build_test_raw_tx(FAKE_SANCTIONED),
        mode=OperationMode.ENFORCE,
        metadata={"amount_usd": 100.0, "enable_profiler": True},
    )

    decision = engine.evaluate(req)
    assert decision.verdict == Verdict.DENY
    assert decision.risk_score == 100
    assert any(r.code == "LIST_MATCH" for r in decision.reasons)


def test_risk_weights_editable_in_policy(clean_profiler_stores):
    """Verifies that risk weights can be customized via PolicyDocument.risk_weights and hot-reloaded."""
    enricher: CachedProfilerEnricher = clean_profiler_stores["enricher"]
    engine = DecisionEngine(
        config=DecisionEngineConfig(hold_risk_threshold=50),
        profiler=enricher,
    )

    # 1. Standard unprofiled request -> weight 25
    req = SigningRequest(
        chain="ethereum",
        wallet=FAKE_WALLET,
        raw_tx=build_test_raw_tx(FAKE_CLEAN_DEST),
        metadata={"amount_usd": 100.0, "enable_profiler": True},
    )
    d1 = engine.evaluate(req)
    unprofiled_r1 = next(r for r in d1.reasons if r.code == "ELEVATED_RISK_UNPROFILED")
    assert unprofiled_r1.weight == 25

    # 2. Hot-reload policy with custom risk weight for ELEVATED_RISK_UNPROFILED = 55 (exceeds hold threshold 50)
    custom_policy = PolicyDocument(
        version="v1.1.0-risk-tune",
        risk_weights={
            "ELEVATED_RISK_UNPROFILED": 55,
            "NEW_CONTRACT": 15,
            "TAINT_EXPOSURE": 50,
        },
    )
    engine.reload_policy(custom_policy)

    d2 = engine.evaluate(req)
    unprofiled_r2 = next(r for r in d2.reasons if r.code == "ELEVATED_RISK_UNPROFILED")
    assert unprofiled_r2.weight == 55
    # Risk score 55 >= hold threshold 50 -> triggers HOLD
    assert d2.risk_score == 55
    assert d2.verdict == Verdict.HOLD
