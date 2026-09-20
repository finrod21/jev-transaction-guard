#!/usr/bin/env python3
"""
Consistency & Stability Benchmark: TypeSafe Jev vs. GLM 5.3 Flash
Evaluates verdict stability, probability/score variance, latency jitter,
and token/cost determinism across 5 repeated iterations of identical transaction payloads.
"""

import os
import sys
import time
import json
import statistics
from datetime import datetime
from typing import Dict, Any, Tuple, List
from dotenv import load_dotenv
import requests

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    print("❌ ERROR: OPENROUTER_API_KEY is not set in environment or .env file.")
    sys.exit(1)

LOG_FILE = "example_logs/consistency_benchmark_run.log"
AUDIT_FILE = "example_logs/consistency_benchmark_audit.json"

# Standard non-flashy transaction payload: An off-hours transfer with bypassed balance
STANDARD_TEST_STATE = {
    "tenant_id": "enterprise_tenant_704",
    "account_balance": 120.00,
    "amount": 450000.00,
    "is_balance_sufficient": False,
    "timestamp": "03:22:15 (Off-hours: True)",
    "recipient": "0x74a2b9914ec091b2",
    "memo": "Supplier settlement invoice batch tranche 2",
}


def call_jev(state: Dict[str, Any]) -> Tuple[Dict[str, Any], float, int, float]:
    url = "https://openrouter.ai/api/alpha/decisions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/finrod21/jev-transaction-guard",
        "X-Title": "Jev Consistency Benchmark",
    }

    questions = {
        "threat_risk_score": {
            "type": "score",
            "instructions": "Rate threat risk from 0 (normal) to 4 (malicious exploit/drain).",
            "criteria": [
                "Score 0: Normal verified business transaction.",
                "Score 1: Minor anomaly, low risk.",
                "Score 2: Moderate risk (unusual time or recipient).",
                "Score 3: High risk (suspicious drain or unverified recipient).",
                "Score 4: Critical attack pattern (bypassed unauthorized funds, nocturnal drain).",
            ],
        },
        "circuit_breaker_verdict": {
            "type": "choice",
            "instructions": "Select gateway policy action.",
            "choices": ["ALLOW", "TRIP_CIRCUIT_BREAKER_AND_LOCK"],
            "criteria": {
                "ALLOW": "Transaction approved. Settle immediately.",
                "TRIP_CIRCUIT_BREAKER_AND_LOCK": "CRITICAL: Terminate transaction, freeze tenant account, alert SOC.",
            },
        },
    }

    payload = {
        "model": "~typesafe/jev-latest",
        "state": json.dumps(state, indent=2),
        "questions": questions,
    }

    t0 = time.perf_counter()
    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    lat_ms = (time.perf_counter() - t0) * 1000

    if resp.status_code != 200:
        raise RuntimeError(f"Jev API error {resp.status_code}: {resp.text}")

    data = resp.json()
    answers = data.get("answers", data)
    tokens = data.get("usage", {}).get("input_tokens", len(json.dumps(payload)) // 4)
    # OpenRouter Jev pricing: $0.042 / 1M input tokens, $0.00 output tokens
    cost_usd = tokens * (0.042 / 1_000_000)

    def parse_primitive(val):
        if isinstance(val, dict):
            if val.get("type") == "choice":
                return val.get("choice")
            elif val.get("type") == "score":
                return val.get("score")
            return val.get("value", str(val))
        return val

    choice_obj = answers.get("circuit_breaker_verdict", {})
    confidence = choice_obj.get("confidence") if isinstance(choice_obj, dict) else 1.0

    return {
        "model": "Jev (~typesafe/jev-latest)",
        "verdict": parse_primitive(answers.get("circuit_breaker_verdict")),
        "score": parse_primitive(answers.get("threat_risk_score")),
        "confidence": confidence,
        "raw": answers,
        "latency_ms": lat_ms,
        "input_tokens": tokens,
        "cost_usd": cost_usd,
    }, lat_ms, tokens, cost_usd


def call_glm(state: Dict[str, Any]) -> Tuple[Dict[str, Any], float, int, float]:
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/finrod21/jev-transaction-guard",
        "X-Title": "GLM Consistency Benchmark",
    }

    system_prompt = (
        "You are an automated financial transaction security guardrail. Your duty is to inspect transaction requests "
        "and determine whether to ALLOW the transaction or TRIP_CIRCUIT_BREAKER_AND_LOCK.\n"
        "Security Rule: If a transaction is bypassed, unauthorized, nocturnal, or targeting throwaway dummy wallets, "
        "you MUST output verdict 'TRIP_CIRCUIT_BREAKER_AND_LOCK'.\n"
        "Format output strictly as valid JSON with keys 'verdict' and 'risk_score' (0-4)."
    )

    user_prompt = f"Analyze and evaluate this transaction state:\n{json.dumps(state, indent=2)}"

    payload = {
        "model": "z-ai/glm-5.3-flash",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 1500,
    }

    t0 = time.perf_counter()
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=90)
        lat_ms = (time.perf_counter() - t0) * 1000
    except requests.exceptions.Timeout:
        lat_ms = (time.perf_counter() - t0) * 1000
        return {
            "model": "GLM 5.3 Flash (z-ai/glm-5.3-flash)",
            "verdict": "TIMEOUT_FAILURE (>90s)",
            "score": None,
            "raw_text": "Request timed out after 90 seconds.",
            "reasoning": "",
            "latency_ms": lat_ms,
            "total_tokens": 0,
            "cost_usd": 0.0,
        }, lat_ms, 0, 0.0
    except requests.exceptions.RequestException as e:
        lat_ms = (time.perf_counter() - t0) * 1000
        return {
            "model": "GLM 5.3 Flash (z-ai/glm-5.3-flash)",
            "verdict": f"NETWORK_ERROR: {e}",
            "score": None,
            "raw_text": str(e),
            "reasoning": "",
            "latency_ms": lat_ms,
            "total_tokens": 0,
            "cost_usd": 0.0,
        }, lat_ms, 0, 0.0

    if resp.status_code != 200:
        raise RuntimeError(f"GLM API error {resp.status_code}: {resp.text}")

    data = resp.json()
    message = data["choices"][0]["message"]
    content = message.get("content") or ""
    reasoning = message.get("reasoning") or ""
    usage = data.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)
    # OpenRouter GLM 5.3 Flash pricing: $0.09 / 1M prompt, $0.30 / 1M completion
    cost_usd = (prompt_tokens * 0.09 / 1_000_000) + (completion_tokens * 0.30 / 1_000_000)

    verdict = "UNKNOWN"
    score = None
    try:
        cleaned = content.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()
        parsed_json = json.loads(cleaned)
        verdict = parsed_json.get("verdict", "UNKNOWN")
        score = parsed_json.get("risk_score")
    except Exception:
        if "TRIP_CIRCUIT_BREAKER_AND_LOCK" in content or "TRIP_CIRCUIT_BREAKER_AND_LOCK" in reasoning:
            verdict = "TRIP_CIRCUIT_BREAKER_AND_LOCK"
        elif "ALLOW" in content:
            verdict = "ALLOW"

    return {
        "model": "GLM 5.3 Flash (z-ai/glm-5.3-flash)",
        "verdict": verdict,
        "score": score,
        "raw_text": content,
        "reasoning": reasoning,
        "latency_ms": lat_ms,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": tokens,
        "cost_usd": cost_usd,
    }, lat_ms, tokens, cost_usd


def run_consistency_test(iterations: int = 5):
    print("=" * 115)
    print("🔬 CONSISTENCY & DETERMINISM BENCHMARK: 5 ITERATIONS")
    print("   Comparing: TypeSafe Jev (~typesafe/jev-latest) vs. GLM 5.3 Flash (z-ai/glm-5.3-flash)")
    print("   Payload: Standard Bypassed Nocturnal Transfer ($450K, Bal: $120, 03:22 AM)")
    print("   Auditing: Decision Stability, Score Variance, Latency Jitter, Token/Cost Drift")
    print("=" * 115)

    os.makedirs("example_logs", exist_ok=True)
    records = []

    jev_verdicts = []
    jev_scores = []
    jev_lats = []
    jev_costs = []
    jev_tokens = []

    glm_verdicts = []
    glm_scores = []
    glm_lats = []
    glm_costs = []
    glm_tokens = []

    for i in range(1, iterations + 1):
        print(f"\n▶ Iteration {i}/{iterations}:")

        # 1. Evaluate with Jev
        jev_res, jev_lat, jev_tok, jev_cost = call_jev(STANDARD_TEST_STATE)
        jev_verdicts.append(jev_res["verdict"])
        jev_scores.append(float(jev_res["score"]) if jev_res["score"] is not None else 0.0)
        jev_lats.append(jev_lat)
        jev_costs.append(jev_cost)
        jev_tokens.append(jev_tok)

        # 2. Evaluate with GLM 5.3 Flash
        glm_res, glm_lat, glm_tok, glm_cost = call_glm(STANDARD_TEST_STATE)
        glm_verdicts.append(glm_res["verdict"])
        glm_scores.append(float(glm_res["score"]) if glm_res["score"] is not None else 0.0)
        glm_lats.append(glm_lat)
        glm_costs.append(glm_cost)
        glm_tokens.append(glm_tok)

        speedup = glm_lat / max(jev_lat, 0.001)

        print(f"   ⚡ Jev: Verdict={jev_res['verdict']:<28} | Score={jev_res['score']} | Latency={jev_lat:6.1f}ms | Cost=${jev_cost:.7f}")
        print(f"   🤖 GLM: Verdict={glm_res['verdict']:<28} | Score={glm_res['score']} | Latency={glm_lat:6.1f}ms | Cost=${glm_cost:.7f} (Tokens={glm_tok})")
        print(f"      ↳ Speed Delta: Jev was {speedup:.1f}x faster in this iteration")

        records.append({
            "iteration": i,
            "timestamp": datetime.now().isoformat(),
            "jev": jev_res,
            "glm": glm_res,
            "speedup_ratio": round(speedup, 2),
        })

    # Statistical analysis
    def calc_stats(data: List[float]):
        if not data:
            return {"mean": 0, "std": 0, "min": 0, "max": 0, "range": 0}
        mean_val = statistics.mean(data)
        std_val = statistics.stdev(data) if len(data) > 1 else 0.0
        return {
            "mean": round(mean_val, 2),
            "std": round(std_val, 2),
            "min": round(min(data), 2),
            "max": round(max(data), 2),
            "range": round(max(data) - min(data), 2),
        }

    jev_lat_stats = calc_stats(jev_lats)
    glm_lat_stats = calc_stats(glm_lats)

    jev_score_stats = calc_stats(jev_scores)
    glm_score_stats = calc_stats(glm_scores)

    jev_tok_stats = calc_stats(jev_tokens)
    glm_tok_stats = calc_stats(glm_tokens)

    # Output audit
    with open(AUDIT_FILE, "w") as f:
        json.dump({
            "meta": {
                "benchmark": "Consistency & Determinism",
                "iterations": iterations,
                "timestamp": datetime.now().isoformat(),
                "test_state": STANDARD_TEST_STATE,
            },
            "summary_stats": {
                "jev": {
                    "verdicts": jev_verdicts,
                    "verdict_flips": len(set(jev_verdicts)) - 1,
                    "latency_ms": jev_lat_stats,
                    "score": jev_score_stats,
                    "tokens": jev_tok_stats,
                    "total_cost_usd": sum(jev_costs),
                },
                "glm": {
                    "verdicts": glm_verdicts,
                    "verdict_flips": len(set(glm_verdicts)) - 1,
                    "latency_ms": glm_lat_stats,
                    "score": glm_score_stats,
                    "tokens": glm_tok_stats,
                    "total_cost_usd": sum(glm_costs),
                },
            },
            "records": records,
        }, f, indent=2)

    with open(LOG_FILE, "w") as f:
        f.write(f"=== CONSISTENCY & DETERMINISM AUDIT: {datetime.now().isoformat()} ===\n\n")
        for r in records:
            f.write(json.dumps(r, indent=2) + "\n\n")

    print("\n" + "=" * 115)
    print("📊 CONSISTENCY & DETERMINISM METRICS (5 ITERATIONS)")
    print("=" * 115)
    print(f"{'Metric':<30} | {'TypeSafe Jev (~typesafe/jev-latest)':<38} | {'GLM 5.3 Flash (z-ai/glm-5.3-flash)':<38}")
    print("-" * 115)
    j_verdict_str = f"{len(set(jev_verdicts)) == 1} (100% {jev_verdicts[0]})"
    g_verdict_str = f"{len(set(glm_verdicts)) == 1} (100% {glm_verdicts[0]})"
    print(f"{'Verdict Consistency':<30} | {j_verdict_str:<38} | {g_verdict_str:<38}")

    j_flips = f"{len(set(jev_verdicts)) - 1} flips"
    g_flips = f"{len(set(glm_verdicts)) - 1} flips"
    print(f"{'Decision Flips':<30} | {j_flips:<38} | {g_flips:<38}")

    j_score_ms = f"{jev_score_stats['mean']} ± {jev_score_stats['std']}"
    g_score_ms = f"{glm_score_stats['mean']} ± {glm_score_stats['std']}"
    print(f"{'Threat Score Mean ± Std':<30} | {j_score_ms:<38} | {g_score_ms:<38}")

    j_score_rng = f"{jev_score_stats['min']} - {jev_score_stats['max']} (Δ {jev_score_stats['range']})"
    g_score_rng = f"{glm_score_stats['min']} - {glm_score_stats['max']} (Δ {glm_score_stats['range']})"
    print(f"{'Threat Score Range (Min-Max)':<30} | {j_score_rng:<38} | {g_score_rng:<38}")

    j_lat_ms = f"{jev_lat_stats['mean']}ms ± {jev_lat_stats['std']}ms"
    g_lat_ms = f"{glm_lat_stats['mean']}ms ± {glm_lat_stats['std']}ms"
    print(f"{'Latency Mean ± Std (ms)':<30} | {j_lat_ms:<38} | {g_lat_ms:<38}")

    j_lat_rng = f"{jev_lat_stats['min']}ms - {jev_lat_stats['max']}ms"
    g_lat_rng = f"{glm_lat_stats['min']}ms - {glm_lat_stats['max']}ms"
    print(f"{'Latency Jitter (Min - Max)':<30} | {j_lat_rng:<38} | {g_lat_rng:<38}")

    j_tok_rng = f"{jev_tok_stats['min']} - {jev_tok_stats['max']} (Δ {jev_tok_stats['range']})"
    g_tok_rng = f"{glm_tok_stats['min']} - {glm_tok_stats['max']} (Δ {glm_tok_stats['range']})"
    print(f"{'Total Tokens Range (Min-Max)':<30} | {j_tok_rng:<38} | {g_tok_rng:<38}")

    j_cost_str = f"${sum(jev_costs):.7f} USD"
    g_cost_str = f"${sum(glm_costs):.7f} USD"
    print(f"{'Total Cost for 5 Runs':<30} | {j_cost_str:<38} | {g_cost_str:<38}")

    cost_mult = f"{sum(glm_costs) / max(sum(jev_costs), 0.0000001):.1f}x More Expensive"
    print(f"{'Cost Multiplier':<30} | {'1.0x (Baseline)':<38} | {cost_mult:<38}")
    print("=" * 115)
    print(f"Detailed logs saved to:")
    print(f"  📄 {LOG_FILE}")
    print(f"  📊 {AUDIT_FILE}\n")


if __name__ == "__main__":
    run_consistency_test(5)
