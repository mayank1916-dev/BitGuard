"""Main entrypoint script for executing BitGuard Integration Lab scenarios."""

import argparse
import sys
from pathlib import Path

from lab.runner.config import LATEST_JSON_FILE, LATEST_SUMMARY_FILE, SCENARIOS_DIR, lab_settings
from lab.runner.executor import LabScenarioExecutor
from lab.runner.safety import MainnetForbiddenError, assert_non_mainnet


def main() -> int:
    """CLI entrypoint for running the integration lab."""
    parser = argparse.ArgumentParser(
        description="BitGuard Integration Lab Runner - Executes integration scenarios against stack."
    )
    parser.add_argument(
        "--scenarios-dir",
        type=Path,
        default=SCENARIOS_DIR,
        help="Directory containing YAML scenario files",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=LATEST_JSON_FILE,
        help="Path to write JSON benchmark report",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=LATEST_SUMMARY_FILE,
        help="Path to write readable text summary",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        default=lab_settings.chain_id,
        help="Target chain ID (Mainnet chain IDs strictly forbidden)",
    )

    args = parser.parse_args()

    # Pre-execution Safety Guard
    try:
        assert_non_mainnet(args.chain_id)
    except MainnetForbiddenError as exc:
        print(f"\n[FATAL SAFETY VIOLATION] {exc}", file=sys.stderr)
        return 2

    print(f"\n[INFO] Starting BitGuard Integration Lab on chain ID {args.chain_id}...")
    executor = LabScenarioExecutor()
    report = executor.execute_all(directory=args.scenarios_dir)

    # Print summary to stdout
    summary = executor.format_readable_summary(report)
    print(summary)
    print(f"\n[INFO] Latest JSON results written to: {args.output}")
    print(f"[INFO] Summary report written to: {args.summary}\n")

    if report.failed > 0:
        print(f"[FAIL] {report.failed} scenario(s) failed.")
        return 1

    print("[SUCCESS] All scenarios passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
