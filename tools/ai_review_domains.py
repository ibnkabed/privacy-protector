"""AI domain review from the command line.

Works directly on the classifications file, so running the app is not required. Useful for
the initial bulk scan of thousands of domains, and for re-evaluation after changing provider keys.

    python tools/ai_review_domains.py --calibrate
    python tools/ai_review_domains.py --scope weak --limit 300
    python tools/ai_review_domains.py --domain data.flurry.com
    python tools/ai_review_domains.py --report
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ai_calibration  # noqa: E402
from ai_reviewer import DomainAIReviewer  # noqa: E402
from domain_classifier import DomainClassificationEngine  # noqa: E402

DATA_ROOT = ROOT / "data"
CLASSIFICATIONS = DATA_ROOT / "domain-classifications.json"
COLOR_WORDS = {"green": "Green", "orange": "Orange", "red": "Red"}


def _engine() -> DomainClassificationEngine:
    return DomainClassificationEngine(CLASSIFICATIONS, active_analysis=False)


def _print_calibration(report: dict) -> None:
    for name, item in sorted(report.get("providers", {}).items(), key=lambda kv: -kv[1]["score"]):
        mark = "passed" if item["passed"] else "failed"
        print(
            f"  {name.ljust(12)} {mark}  score={item['score']:<6} "
            f"answered={item.get('answered', '?')}/{item.get('expected', '?')}  {item.get('model', '')}"
        )
    print("  Trusted:", ", ".join(report.get("trusted", [])) or "none")


def main() -> int:
    parser = argparse.ArgumentParser(description="Review DNS domains using AI models")
    parser.add_argument("--domain", default="", help="A specific single domain")
    parser.add_argument("--limit", type=int, default=120, help="Number of domains in this run")
    parser.add_argument(
        "--scope",
        default="weak",
        choices=("weak", "unreviewed", "red", "all"),
        help="weak: undecided by local engine, unreviewed: all unreviewed, red: current reds",
    )
    parser.add_argument("--calibrate", action="store_true", help="Re-test providers only")
    parser.add_argument("--report", action="store_true", help="Show saved review summary only")
    parser.add_argument("--no-consensus", action="store_true", help="No second opinion on reds")
    parser.add_argument("--dry-run", action="store_true", help="Show verdict without saving")
    parser.add_argument(
        "--no-paid", action="store_true",
        help="Exclude paid providers (anthropic and anthropic-sonnet) — they are default top priority and consume credits",
    )
    # Paid used to require explicit request, then became the default option on 2026-09-23; so
    # the old flag remains accepted for compatibility with no effect.
    parser.add_argument("--paid", "--allow-paid", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()

    if arguments.calibrate:
        print("Testing providers on known domains…")
        # Above the saved state there is no alternative: trusted fields remain, and those who
        # could not be tested today keep their previous verdict.
        report = ai_calibration.recalibrate(DATA_ROOT, allow_paid=not arguments.no_paid)
        _print_calibration(report)
        return 0

    engine = _engine()
    if arguments.report:
        summary = engine.ai_review_summary()
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    reviewer = DomainAIReviewer(DATA_ROOT, classifier=engine, allow_paid=not arguments.no_paid)
    reviewer.ensure_pool()
    if not reviewer.trusted:
        print("No provider passed the test. Run --calibrate or check the keys file.")
        return 1
    print("Trusted providers:", ", ".join(reviewer.trusted))

    targets = [arguments.domain] if arguments.domain else reviewer.candidates(
        arguments.limit, arguments.scope
    )
    if not targets:
        print("No domain matches this search scope.")
        return 0
    print(f"Reviewing {len(targets)} domains…")

    started = time.monotonic()
    result = reviewer.review_domains(
        targets,
        consensus=not arguments.no_consensus,
        apply_result=not arguments.dry_run,
    )
    if not result.get("ok"):
        print("Review failed:", result.get("error", ""))
        return 1

    for verdict in sorted(result["verdicts"], key=lambda item: item["domain"]):
        colour = COLOR_WORDS.get(verdict["color"], verdict["color"])
        block = "Blocked" if verdict.get("blockSafe") else "Not blocked"
        print(f"  {colour:<8}{verdict['confidence']:>4}%  {block:<9}{verdict['domain']}")
        print(f"          {verdict.get('reason', '')[:150]}")
    if not arguments.dry_run:
        engine.flush()
    elapsed = round(time.monotonic() - started, 1)
    print(
        f"\nReviewed {result['reviewed']} of {result['requested']} in {elapsed}s, "
        f"and {result['changed']} changed color."
    )
    print(json.dumps(engine.ai_review_summary(), ensure_ascii=False))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
