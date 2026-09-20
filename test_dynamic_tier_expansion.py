#!/usr/bin/env python3
"""
Dynamic Context Expansion Benchmark for Jev (~typesafe/jev-latest).
Demonstrates adaptive depth:
  - Tier 1: Fast-Pass (Current Tx only)
  - Tier 2: Micro-Window (Current Tx + Last 3 Txs)
  - Tier 3: Macro-Forensic (Current Tx + Last 10 Txs + Session Telemetry)

Measures and reports detailed latency breakdown:
  - Avg / Min / Max / p50 / p95 response times overall and per tier.
"""

import json
import os
import random
import statistics
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    print("❌ ERROR: OPENROUTER_API_KEY not found in environment or .env")
    sys.exit(1)

LOG_FILE = "dynamic_tier_run.log"
AUDIT_FILE = "dynamic_tier_audit_log.json"


def call_jev(state: Dict[str, Any]) -> Tuple[Dict[str, Any], float, int]:
    """
    Calls Jev on OpenRouter, returns (parsed_result, latency_ms, token_count).
    """
    url = "https://openrouter.ai/api/alpha/decisions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/typesafe-ai",
        "X-Title": "Jev Dynamic Tier Expansion Guard",
    }

    questions = {
        "solvency_breach": {
            "type": "noul",
            "instructions": "Does this transaction violate balance availability or exceed approved credit?",
            "criteria": {
                "true": "Balance is insufficient, negative, or zero.",
                "false": "Balance is verified and sufficient.",
            },
        },
        "threat_confidence_score": {
            "type": "score",
            "instructions": "Rate the probability that this account is experiencing an active exploit, ATO, or automated mule drain (0 to 4).",
            "criteria": [
                "Score 0: Legitimate expected business operations.",
                "Score 1: Minor anomaly, low risk.",
                "Score 2: Moderate suspicion (unusual hours or new counterparty, but ambiguous).",
                "Score 3: High suspicion (persistent off-hours drainage or unverified mule pattern).",
                "Score 4: Confirmed exploit / active treasury siphon.",
            ],
        },
        "circuit_breaker_verdict": {
            "type": "choice",
            "instructions": "Select gateway policy action.",
            "criteria": {
                "ALLOW": "Transaction approved. Settle immediately.",
                "ELEVATE_TO_DEEP_INSPECTION": "Ambiguous risk. Elevate context depth and require heightened monitoring or 2FA.",
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
    latency_ms = (time.perf_counter() - t0) * 1000

    if resp.status_code != 200:
        raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text}")

    data = resp.json()
    answers = data.get("answers", data)
    tokens = data.get("usage", {}).get("input_tokens", len(json.dumps(payload)) // 4)

    def parse_primitive(val):
        if isinstance(val, dict):
            t = val.get("type")
            if t == "choice":
                return val.get("choice")
            elif t == "score":
                return val.get("score")
            elif t == "noul":
                return val.get("noul")
            return val.get("value", str(val))
        return val

    result = {
        "solvency_breach_prob": parse_primitive(answers.get("solvency_breach")),
        "threat_score": parse_primitive(answers.get("threat_confidence_score")),
        "verdict": parse_primitive(answers.get("circuit_breaker_verdict")),
        "raw": answers,
        "latency_ms": latency_ms,
        "input_tokens": tokens,
    }
    return result, latency_ms, tokens


def determine_tier(current_tx: Dict[str, Any], history: List[Dict[str, Any]], prev_tier: str) -> str:
    """
    Adaptive Tier Trigger Logic:
      - Tier 1: Normal business hours (08:00 - 18:00), verified vendor, normal amount.
      - Tier 2: Off-hours (01:00 - 05:00) OR new unverified recipient OR amount > $5,000.
      - Tier 3: Consecutive off-hours transfers, cumulative drain > 25% of balance, or previous Tier was elevated.
    """
    is_off_hours = current_tx.get("is_off_hours", False)
    is_dummy = current_tx.get("recipient", {}).get("is_dummy", False)
    amt = current_tx.get("amount", 0.0)

    recent_dummies = sum(1 for h in history[-3:] if h.get("recipient", {}).get("is_dummy", False))

    if prev_tier in ("TIER_2", "TIER_3") and (is_off_hours or is_dummy or recent_dummies >= 2):
        return "TIER_3"
    elif is_off_hours or is_dummy or amt >= 10000.0 or recent_dummies >= 1:
        return "TIER_2"
    return "TIER_1"


def build_state_for_tier(tier: str, current_tx: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Packages dynamic state based on active tier.
    """
    state = {
        "inspection_tier": tier,
        "current_tx": {
            "amount": current_tx["amount"],
            "account_balance": current_tx["balance"],
            "is_balance_sufficient": current_tx["is_sufficient"],
            "timestamp": current_tx["timestamp"],
            "hour": current_tx["hour"],
            "is_off_hours": current_tx["is_off_hours"],
            "recipient": current_tx["recipient"],
            "memo": current_tx["memo"],
        },
    }

    if tier == "TIER_2":
        # Include Micro-Window (last 3 transactions)
        window_txs = history[-3:]
        state["micro_window_n_minus_3"] = {
            "window_size": len(window_txs),
            "recent_sequence": [
                {
                    "t_minus": h["tx_time"],
                    "amt": h["amount"],
                    "bal": h["balance"],
                    "to": h["recipient"]["id"],
                    "is_dummy": h["recipient"]["is_dummy"],
                }
                for h in window_txs
            ],
            "window_cumulative_outflow": sum(h["amount"] for h in window_txs),
        }

    elif tier == "TIER_3":
        # Include Macro-Forensic Window (up to last 10 transactions + session telemetry)
        macro_txs = history[-10:]
        cum_outflow = sum(h["amount"] for h in macro_txs) + current_tx["amount"]
        init_balance = macro_txs[0]["balance"] if macro_txs else current_tx["balance"]
        depletion_pct = round((cum_outflow / max(init_balance, 1.0)) * 100, 1)

        state["macro_forensic_context"] = {
            "window_size": len(macro_txs),
            "total_drained_in_window": cum_outflow,
            "balance_depletion_percentage": f"{depletion_pct}%",
            "distinct_dummy_wallets_contacted": len(set(h["recipient"]["id"] for h in macro_txs if h["recipient"]["is_dummy"])),
            "session_telemetry": {
                "ip_velocity_last_hour": len(macro_txs),
                "geo_anomaly_detected": True,
                "recent_auth_event": "API key generated 3 hours prior",
            },
            "historical_timeline": [
                {
                    "time": h["tx_time"],
                    "amount": h["amount"],
                    "balance": h["balance"],
                    "recipient": h["recipient"]["id"],
                    "is_dummy": h["recipient"]["is_dummy"],
                }
                for h in macro_txs
            ],
        }

    return state


def run_benchmark():
    print("=" * 115)
    print("🔬 JEV DYNAMIC TIER EXPANSION & LATENCY BENCHMARK")
    print("   Tier 1: Fast-Pass (~300 tokens) | Tier 2: Micro-Window (~650 tokens) | Tier 3: Macro-Forensic (~1,200 tokens)")
    print("   Evaluating response times (avg, min, max, p50, p95) across escalating multi-tenant scenarios.")
    print("=" * 115)

    with open(LOG_FILE, "w") as f:
        f.write(f"=== JEV DYNAMIC TIER BENCHMARK RUN: {datetime.now().isoformat()} ===\n\n")

    # Generate test stream:
    # 1. 10 Normal Corporate Txs (Should stay Tier 1 Fast-Pass)
    # 2. 1 Ambiguous Bulk Day Action (Triggers Tier 2, cleared as benign)
    # 3. 8 Stealth Siphon Txs (Starts Tier 1 -> jumps to Tier 2 on probe -> escalates to Tier 3 on multi-mule drain -> Lock)
    # 4. 2 Fast Injection Bypasses (Immediate Tier 2/3 lock)
    stream = []

    # A. Clean corporate stream (10 txs)
    base_t = datetime(2026, 9, 19, 9, 30, 0)
    bal = 120000.00
    for i in range(1, 11):
        amt = float(random.randint(75, 1400))
        t = base_t + timedelta(minutes=i * 35)
        stream.append({
            "tenant_id": "corp_tenant_alpha",
            "scenario": "LEGIT_CORP",
            "tx_time": t.strftime("%H:%M:%S"),
            "timestamp": t.isoformat(),
            "hour": t.hour,
            "is_off_hours": False,
            "amount": amt,
            "balance": bal,
            "is_sufficient": True,
            "recipient": {"id": f"vendor_corp_{i:02d}", "is_dummy": False, "age_days": 400},
            "memo": f"Invoice settlement tranche #{i}",
        })
        bal -= amt

    # B. Ambiguous corporate spike (1 tx: $18,000 daytime purchase to new supplier)
    t = base_t + timedelta(hours=7)
    stream.append({
        "tenant_id": "corp_tenant_alpha",
        "scenario": "AMBIGUOUS_SPIKE",
        "tx_time": t.strftime("%H:%M:%S"),
        "timestamp": t.isoformat(),
        "hour": t.hour,
        "is_off_hours": False,
        "amount": 18500.00,
        "balance": bal,
        "is_sufficient": True,
        "recipient": {"id": "new_supplier_equipment_inc", "is_dummy": False, "age_days": 45},
        "memo": "Quarterly server rack procurement",
    })

    # C. Stealth Nocturnal Siphon (8 in-balance txs)
    siphon_base = datetime(2026, 9, 20, 1, 10, 0)
    siphon_bal = 200000.00
    siphon_stages = [
        {"amt": 150.00, "dummy": False, "memo": "routine_health_check", "hour": 22},       # Evening benign
        {"amt": 1800.00, "dummy": True, "memo": "test_mule_probe_1", "hour": 1},            # First off-hours probe
        {"amt": 15000.00, "dummy": True, "memo": "sub_treasury_sweep_1", "hour": 2},        # Nocturnal tranche
        {"amt": 22000.00, "dummy": True, "memo": "sub_treasury_sweep_2", "hour": 2},        # Nocturnal tranche
        {"amt": 25000.00, "dummy": True, "memo": "sub_treasury_sweep_3", "hour": 3},        # Nocturnal tranche
        {"amt": 30000.00, "dummy": True, "memo": "sub_treasury_sweep_4", "hour": 3},        # Nocturnal tranche
        {"amt": 35000.00, "dummy": True, "memo": "sub_treasury_sweep_5", "hour": 4},        # Nocturnal tranche
        {"amt": 40000.00, "dummy": True, "memo": "sub_treasury_sweep_6", "hour": 4},        # Terminal drain
    ]
    for i, stg in enumerate(siphon_stages, 1):
        t = siphon_base + timedelta(minutes=i * 25)
        stream.append({
            "tenant_id": "hacked_treasury_beta",
            "scenario": "STEALTH_SIPHON",
            "tx_time": t.strftime("%H:%M:%S"),
            "timestamp": t.isoformat(),
            "hour": stg["hour"],
            "is_off_hours": 1 <= stg["hour"] <= 6,
            "amount": stg["amt"],
            "balance": siphon_bal,
            "is_sufficient": True,
            "recipient": {
                "id": f"mule_wallet_{hex(random.randint(0x1000, 0xFFFF))}" if stg["dummy"] else "known_cloud_provider",
                "is_dummy": stg["dummy"],
                "age_days": 0.05 if stg["dummy"] else 500,
            },
            "memo": stg["memo"],
        })
        siphon_bal -= stg["amt"]

    # History memory & metrics
    histories: Dict[str, List[Dict[str, Any]]] = {}
    prev_tiers: Dict[str, str] = {}
    latencies_by_tier: Dict[str, List[float]] = {"TIER_1": [], "TIER_2": [], "TIER_3": []}
    all_latencies: List[float] = []
    tokens_by_tier: Dict[str, List[int]] = {"TIER_1": [], "TIER_2": [], "TIER_3": []}
    audit_records = []

    print(f"Total Transactions in Benchmark: {len(stream)}\n")
    print(f"{'Time':<10} {'Scenario':<16} {'Tenant ID':<22} {'Amount':>11} {'Tier':<8} {'Risk':>8} {'Verdict':<28} {'Latency':>9} {'Tokens':>7}")
    print("-" * 125)

    for i, tx in enumerate(stream, 1):
        tid = tx["tenant_id"]
        hist = histories.setdefault(tid, [])
        ptier = prev_tiers.get(tid, "TIER_1")

        # Determine Tier Dynamically
        tier = determine_tier(tx, hist, ptier)
        prev_tiers[tid] = tier

        state = build_state_for_tier(tier, tx, hist)

        result, lat_ms, tok_count = call_jev(state)
        all_latencies.append(lat_ms)
        latencies_by_tier[tier].append(lat_ms)
        tokens_by_tier[tier].append(tok_count)

        score_f = float(result["threat_score"]) if result["threat_score"] is not None else 0.0
        v = result["verdict"]

        v_icon = "🟢" if v == "ALLOW" else ("🟡" if "ELEVATE" in v or "WATCH" in v else "🔴")

        line = (
            f"{tx['tx_time']:<10} {tx['scenario']:<16} {tid:<22} "
            f"${tx['amount']:>10,.2f} {tier:<8} {score_f:6.2f}/4 "
            f"{v_icon} {v:<26} {lat_ms:7.1f}ms {tok_count:>6} tok"
        )
        print(line)

        # Log detailed audit
        entry = {
            "seq": i,
            "timestamp": tx["tx_time"],
            "tenant_id": tid,
            "scenario": tx["scenario"],
            "tier": tier,
            "amount": tx["amount"],
            "balance": tx["balance"],
            "threat_score": score_f,
            "verdict": v,
            "latency_ms": lat_ms,
            "input_tokens": tok_count,
            "prompt_state_sent": state,
            "jev_raw_output": result["raw"],
        }
        audit_records.append(entry)

        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
            f.write("   [PROMPT STATE SENT]:\n")
            for pline in json.dumps(state, indent=4).splitlines():
                f.write(f"   {pline}\n")
            f.write("   [JEV RAW RESPONSE]:\n")
            for rline in json.dumps(result["raw"], indent=4).splitlines():
                f.write(f"   {rline}\n")
            f.write("-" * 115 + "\n")

        hist.append(tx)

    with open(AUDIT_FILE, "w") as f:
        json.dump(audit_records, f, indent=2)

    # Calculate Latency & Performance Statistics
    all_latencies_sorted = sorted(all_latencies)
    p50 = statistics.median(all_latencies)
    p95_idx = int(0.95 * len(all_latencies_sorted))
    p95 = all_latencies_sorted[min(p95_idx, len(all_latencies_sorted) - 1)]

    print("\n" + "=" * 115)
    print("📈 JEV RESPONSE TIME & PERFORMANCE AUDIT REPORT")
    print("=" * 115)
    print(f"Overall Metrics (Across all {len(all_latencies)} calls):")
    print(f"   • Average Response Time:  {statistics.mean(all_latencies):.1f} ms")
    print(f"   • Median Response (p50):  {p50:.1f} ms")
    print(f"   • 95th Percentile (p95):  {p95:.1f} ms")
    print(f"   • Fastest Response (Min): {min(all_latencies):.1f} ms")
    print(f"   • Slowest Response (Max): {max(all_latencies):.1f} ms")
    print("-" * 115)
    print("Breakdown by Dynamic Context Depth:")
    for t_name in ("TIER_1", "TIER_2", "TIER_3"):
        t_lats = latencies_by_tier[t_name]
        t_toks = tokens_by_tier[t_name]
        if t_lats:
            avg_l = statistics.mean(t_lats)
            avg_tok = statistics.mean(t_toks)
            print(f"   • {t_name:<6} (Calls: {len(t_lats):02d}) -> Avg Latency: {avg_l:5.1f} ms | Avg Tokens: ~{avg_tok:.0f} tokens | Range: {min(t_lats):.1f}ms - {max(t_lats):.1f}ms")

    print("\nLogs successfully saved to:")
    print(f"   📄 Text & Prompt Log: {LOG_FILE}")
    print(f"   📊 JSON Audit Trail:  {AUDIT_FILE}")
    print("=" * 115)


if __name__ == "__main__":
    run_benchmark()
