"""Scanner benchmark (Experiment B): TEST / BENCHMARK ONLY.

Runs the real active scanners against the controlled lab and scores each probe against a
fixed expected label. This measures the vulnerability scanner only; it is deliberately
separate from the ML classification metrics (Experiment A) in ml/reports/.

Usage: python -m labs.benchmark
"""

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from backend.scanner.active.reflected_xss import scan_reflected_xss_for_parameter
from backend.scanner.active.sqli import scan_sqli_for_parameter
from labs.vulnerable_app import app

REPORT_DIR = Path("reports/benchmark")
BASE_URL = "http://lab.test"


@dataclass(frozen=True)
class BenchmarkCase:
    endpoint: str
    parameter: str
    check: str  # "SQLI" or "XSS"
    expected_vulnerable: bool
    original_value: str = "1"


# Frozen target set: every endpoint is probed by both checks, so cross-class false positives count.
CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase("/vulnerable/products", "id", "SQLI", True),
    BenchmarkCase("/vulnerable/products", "id", "XSS", False),
    BenchmarkCase("/safe/products", "id", "SQLI", False),
    BenchmarkCase("/safe/products", "id", "XSS", False),
    BenchmarkCase("/vulnerable/search", "q", "SQLI", False, "laptop"),
    BenchmarkCase("/vulnerable/search", "q", "XSS", True, "laptop"),
    BenchmarkCase("/safe/search", "q", "SQLI", False, "laptop"),
    BenchmarkCase("/safe/search", "q", "XSS", False, "laptop"),
)


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    detected: bool

    @property
    def outcome(self) -> str:
        if self.case.expected_vulnerable:
            return "TP" if self.detected else "FN"
        return "FP" if self.detected else "TN"


def compute_metrics(results: list[CaseResult]) -> dict[str, float | int | None]:
    counts = {name: sum(1 for r in results if r.outcome == name) for name in ("TP", "TN", "FP", "FN")}
    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if precision is not None and recall is not None else None)
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detection_rate": recall,
        "false_positive_rate": ratio(fp, fp + tn),
    }


async def run_cases(cases: tuple[BenchmarkCase, ...] = CASES) -> list[CaseResult]:
    transport = httpx.ASGITransport(app=app)
    results: list[CaseResult] = []
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL, follow_redirects=False) as client:
        for case in cases:
            url = f"{BASE_URL}{case.endpoint}"
            if case.check == "SQLI":
                finding = await scan_sqli_for_parameter(client, url, case.parameter, original_value=case.original_value)
            else:
                finding = await scan_reflected_xss_for_parameter(client, url, case.parameter)
            results.append(CaseResult(case=case, detected=finding is not None))
    return results


def render_markdown(results: list[CaseResult], metrics: dict[str, float | int | None], generated_at: str) -> str:
    lines = [
        "# ThreatSentry Scanner Benchmark (Experiment B)",
        "",
        "**TEST / BENCHMARK ONLY.** Real scanner runs against the controlled lab in `labs/`.",
        "These numbers measure the vulnerability scanner and must not be combined with the ML",
        "classification metrics (Experiment A) in `ml/reports/`.",
        "",
        f"Generated: {generated_at}  ",
        f"Cases: {len(results)} (fixed target set defined in `labs/benchmark.py`)",
        "",
        "## Results per case",
        "",
        "| Endpoint | Check | Expected vulnerable | Detected | Outcome |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| `{r.case.endpoint}` | {r.case.check} | {r.case.expected_vulnerable} | {r.detected} | {r.outcome} |")
    lines += ["", "## Metrics", "", "| Metric | Value |", "|---|---|"]
    lines += [f"| {key} | {value} |" for key, value in metrics.items()]
    lines += [
        "",
        "## Limitations",
        "",
        f"- Only {len(results)} probes on two synthetic parameters, so the metrics have very low statistical power.",
        "- The lab was written alongside the scanner; results do not generalise to real-world applications.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    results = asyncio.run(run_cases())
    metrics = compute_metrics(results)
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "scanner_benchmark.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "metrics": metrics,
                "cases": [{**asdict(r.case), "detected": r.detected, "outcome": r.outcome} for r in results],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (REPORT_DIR / "scanner_benchmark.md").write_text(render_markdown(results, metrics, generated_at), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
