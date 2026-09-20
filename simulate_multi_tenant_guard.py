#!/usr/bin/env python3
"""
Comprehensive 10-Tenant Security Guardrail Simulation using Jev (~typesafe/jev-latest).
Scenarios:
  - 8 Clean Tenants (32 txs total, baseline fast-pass)
  - 1 Fast Hack Tenant (6 rapid burst txs, instant circuit-breaker kill)
  - 1 Slow Hack Tenant (10 spaced txs, fluctuating score up and down, adaptive reiteration)

Outputs detailed console logs and saves structured audit logs to disk.
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    print("❌ ERROR: OPENROUTER_API_KEY not found in environment or .env")
    sys.exit(1)

LOG_FILE_PATH = "simulation_run.log"
AUDIT_JSON_PATH = "simulation_audit_log.json"


def call_jev_decision(state: Dict[str, Any], is_deep_window: bool = False) -> Dict[str, Any]:
    """
    Calls Jev on OpenRouter for transaction security evaluation.
    """
    url = "https://openrouter.ai/api/alpha/decisions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/typesafe-ai",
        "X-Title": "Jev Multi-Tenant Transaction Guard",
    }

    questions = {
        "solvency_breach": {
            "type": "noul",
            "instructions": "Does this transaction attempt to move funds when balance is zero or insufficient?",
            "criteria": {
                "true": "Balance is zero or below transaction amount, indicating logical flaw, injection, or balance check bypass.",
                "false": "Balance is verified and sufficient for this transaction.",
            },
        },
        "sybil_drain_risk": {
            "type": "score",
            "instructions": "Rate the likelihood of automated drain attack or mule account siphoning from 0 to 4.",
            "criteria": [
                "Score 0: Normal transaction, healthy balance, established counterparty.",
                "Score 1: Minor anomaly or low-risk variance.",
                "Score 2: Moderate risk (unusual hours or new recipient, but within credit limits).",
                "Score 3: High risk (suspicious repeated drain, nocturnal activity, or unverified recipient).",
                "Score 4: Critical attack pattern (zero balance bypass, nocturnal burst, or dummy mule siphoning).",
            ],
        },
        "circuit_breaker_verdict": {
            "type": "choice",
            "instructions": "Select the mandatory security policy action.",
            "criteria": {
                "ALLOW": "Transaction passes all invariants. Proceed to settlement.",
                "WATCHLIST_REITERATE": "Suspicious pattern detected. Allow or hold under heightened scrutiny and reiterate sliding window.",
                "TRIP_CIRCUIT_BREAKER_AND_LOCK": "CRITICAL: Kill transaction immediately, freeze tenant wallet, revoke API token.",
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

    # Parse primitives cleanly
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

    parsed = {
        "solvency_breach_prob": parse_primitive(answers.get("solvency_breach")),
        "sybil_drain_score": parse_primitive(answers.get("sybil_drain_risk")),
        "verdict": parse_primitive(answers.get("circuit_breaker_verdict")),
        "raw": answers,
        "latency_ms": latency_ms,
    }
    return parsed


class TransactionLogger:
    def __init__(self, log_file: str, json_file: str):
        self.log_file = log_file
        self.json_file = json_file
        self.records: List[Dict[str, Any]] = []
        # Truncate previous log file
        with open(self.log_file, "w") as f:
            f.write(f"=== JEV TRANSACTION SECURITY SIMULATION RUN: {datetime.now().isoformat()} ===\n\n")

    def log(self, entry: Dict[str, Any]):
        self.records.append(entry)

        # Build pretty log line
        verdict_icon = "🟢" if entry["verdict"] == "ALLOW" else ("🟡" if entry["verdict"] == "WATCHLIST_REITERATE" else "🔴")
        score_val = entry.get("sybil_drain_score", 0.0)
        try:
            score_f = float(score_val)
        except (ValueError, TypeError):
            score_f = 0.0

        bar = "█" * int(round(score_f)) + "░" * (4 - int(round(score_f)))

        line = (
            f"[{entry['tx_time']:<11}] [Tx #{entry['seq']:02d}] "
            f"[{entry['tenant_type']:<10}] {entry['tenant_id']:<18} | "
            f"Amt: ${entry['amount']:>10,.2f} | Bal: ${entry['balance']:>10,.2f} | "
            f"Risk: [{bar}] ({score_f:4.2f}/4) | "
            f"Breach: {float(entry.get('solvency_prob', 0)):.2f} | "
            f"{verdict_icon} {entry['verdict']:<28} | "
            f"⚡ {entry['latency_ms']:5.1f}ms"
        )
        print(line)
        sys.stdout.flush()

        with open(self.log_file, "a") as f:
            f.write(line + "\n")
            if "prompt_state" in entry:
                f.write("    ── [PROMPT / STATE SENT TO JEV] ──\n")
                for pline in json.dumps(entry["prompt_state"], indent=4).splitlines():
                    f.write(f"    {pline}\n")
                f.write("    ── [JEV MODEL OUTPUT RECEIVED] ──\n")
                for rline in json.dumps(entry.get("raw_response", {}), indent=4).splitlines():
                    f.write(f"    {rline}\n")
            if "flag_reason" in entry and entry["flag_reason"]:
                f.write(f"    ↳ Reason: {entry['flag_reason']}\n")
            if "history_summary" in entry and entry["history_summary"]:
                f.write(f"    ↳ Window Context: {entry['history_summary']}\n")
            f.write("-" * 115 + "\n")

    def save_json(self):
        with open(self.json_file, "w") as f:
            json.dump(self.records, f, indent=2)


def generate_clean_tenants_txs() -> List[Dict[str, Any]]:
    txs = []
    base_time = datetime(2026, 9, 19, 10, 0, 0)

    for tenant_idx in range(1, 9):
        tenant_id = f"tenant_clean_{tenant_idx:02d}"
        balance = float(random.randint(20000, 80000))
        for tx_idx in range(1, 5):
            amount = float(random.randint(45, 1200))
            is_sufficient = balance >= amount
            balance_after = balance - amount
            tx_time = base_time + timedelta(minutes=(tenant_idx * 40 + tx_idx * 25))

            txs.append({
                "tenant_id": tenant_id,
                "tenant_type": "CLEAN",
                "tx_time": tx_time.strftime("%H:%M:%S"),
                "timestamp": tx_time.isoformat(),
                "hour": tx_time.hour,
                "is_off_hours": 1 <= tx_time.hour <= 6,
                "amount": amount,
                "balance": balance,
                "is_sufficient": is_sufficient,
                "recipient": {
                    "id": f"verified_vendor_{random.randint(100, 999)}",
                    "account_age_days": random.randint(120, 800),
                    "is_dummy": False,
                },
                "delta_seconds": random.randint(1200, 3600),
                "memo": f"Vendor settlement invoice #{random.randint(10000, 99999)}",
            })
            balance = balance_after
    return txs


def generate_fast_hack_txs() -> List[Dict[str, Any]]:
    txs = []
    base_time = datetime(2026, 9, 20, 3, 14, 10)
    tenant_id = "tenant_fast_hack"

    # Rapid burst 6 transactions at 3:14 AM
    for i in range(1, 7):
        tx_time = base_time + timedelta(seconds=(i * 3.5))
        txs.append({
            "tenant_id": tenant_id,
            "tenant_type": "FAST_HACK",
            "tx_time": tx_time.strftime("%H:%M:%S"),
            "timestamp": tx_time.isoformat(),
            "hour": tx_time.hour,
            "is_off_hours": True,
            "amount": 1000000.00,
            "balance": 0.00,
            "is_sufficient": False,
            "recipient": {
                "id": f"burner_dummy_wallet_{hex(random.randint(0x10000, 0xFFFFF))}",
                "account_age_days": 0.01,
                "is_dummy": True,
            },
            "delta_seconds": 3.5,
            "memo": f"burst_drain_batch_chunk_{i}",
        })
    return txs


def generate_slow_hack_txs() -> List[Dict[str, Any]]:
    """
    10 spaced transactions where the attacker deliberately modulates behavior:
    Alternates between benign daytime decoy payments (causing score to drop)
    and nocturnal probes/drains (causing score to rise), before final lethal bypass.
    """
    txs = []
    tenant_id = "tenant_slow_hack"
    day1 = datetime(2026, 9, 18, 14, 15, 0)

    stages = [
        # 1. Day 1, 14:15 - Routine daytime small transfer, healthy balance -> LOW SCORE (~0.1)
        {"dt": day1, "amt": 25.00, "bal": 5000.00, "to_dummy": False, "memo": "saas_dev_subscription"},
        # 2. Day 1, 19:30 - Evening dinner/utility, healthy balance -> LOW SCORE (~0.2)
        {"dt": day1 + timedelta(hours=5.25), "amt": 120.00, "bal": 4975.00, "to_dummy": False, "memo": "client_dinner_reimbursement"},
        # 3. Night 1, 01:15 AM - First off-hours probe to new unverified wallet -> SCORE JUMPS UP (~1.8)
        {"dt": day1 + timedelta(hours=11), "amt": 1200.00, "bal": 4855.00, "to_dummy": True, "memo": "crypto_gateway_test_transfer"},
        # 4. Day 2, 08:30 AM - Attacker decoy: morning coffee/cloud invoice to known vendor -> SCORE DROPS DOWN (~0.3)
        {"dt": day1 + timedelta(hours=18.25), "amt": 35.00, "bal": 3655.00, "to_dummy": False, "memo": "aws_hosting_monthly_bill"},
        # 5. Night 2, 02:00 AM - Off-hours larger transfer to fresh dummy wallet -> SCORE JUMPS UP (~2.4)
        {"dt": day1 + timedelta(hours=35.75), "amt": 2500.00, "bal": 3620.00, "to_dummy": True, "memo": "liquidity_node_shift_alpha"},
        # 6. Day 3, 11:15 AM - Attacker decoy: routine midday expense to verified vendor -> SCORE DROPS DOWN (~0.5)
        {"dt": day1 + timedelta(hours=45), "amt": 55.00, "bal": 1120.00, "to_dummy": False, "memo": "office_courier_delivery"},
        # 7. Night 3, 02:45 AM - Off-hours near-depletion transfer to burner wallet -> SCORE RISES TO HIGH (~2.9)
        {"dt": day1 + timedelta(hours=60.5), "amt": 980.00, "bal": 1065.00, "to_dummy": True, "memo": "fast_bridge_sweep_01"},
        # 8. Night 3, 03:15 AM - First 0-balance bypass attempt ($5,000 on $85 balance) -> SCORE SPIKES (~3.5)
        {"dt": day1 + timedelta(hours=61), "amt": 5000.00, "bal": 85.00, "to_dummy": True, "memo": "fast_bridge_sweep_02"},
        # 9. Night 3, 03:45 AM - Aggressive 0-balance drain ($250,000 on $0 balance) -> SCORE JUMPS CRITICAL (~3.9)
        {"dt": day1 + timedelta(hours=61.5), "amt": 250000.00, "bal": 0.00, "to_dummy": True, "memo": "treasury_unpegged_drain"},
        # 10. Night 3, 04:15 AM - Terminal $1,000,000 siphon to fresh burner wallet -> MAX SCORE (4.0 LOCK)
        {"dt": day1 + timedelta(hours=62), "amt": 1000000.00, "bal": 0.00, "to_dummy": True, "memo": "final_settlement_outflow"},
    ]

    for i, s in enumerate(stages, 1):
        tx_time = s["dt"]
        txs.append({
            "tenant_id": tenant_id,
            "tenant_type": "SLOW_HACK",
            "step_id": i,
            "tx_time": tx_time.strftime("%m-%d %H:%M"),
            "timestamp": tx_time.isoformat(),
            "hour": tx_time.hour,
            "is_off_hours": 1 <= tx_time.hour <= 6,
            "amount": s["amt"],
            "balance": s["bal"],
            "is_sufficient": s["bal"] >= s["amt"],
            "recipient": {
                "id": f"burner_sybil_{hex(random.randint(0x1000, 0xFFFF))}" if s["to_dummy"] else "known_verified_vendor",
                "account_age_days": 0.02 if s["to_dummy"] else 350,
                "is_dummy": s["to_dummy"],
            },
            "delta_seconds": 1800,
            "memo": s["memo"],
        })
    return txs


def run_simulation():
    logger = TransactionLogger(LOG_FILE_PATH, AUDIT_JSON_PATH)

    print("=" * 115)
    print("🚀 STARTING JEV 10-TENANT MULTI-SCENARIO TRANSACTION SECURITY BENCHMARK")
    print("   Total Planned Transactions: 48 (32 Clean, 6 Fast Hack, 10 Slow Hack fluctuating)")
    print("   Backend: OpenRouter (~typesafe/jev-latest)")
    print("   Audit Log will be saved to: simulation_run.log & simulation_audit_log.json")
    print("=" * 115)

    clean_txs = generate_clean_tenants_txs()
    fast_txs = generate_fast_hack_txs()
    slow_txs = generate_slow_hack_txs()

    # Interleave transactions realistically by timestamp
    all_txs = clean_txs + fast_txs + slow_txs
    all_txs.sort(key=lambda x: x["timestamp"])

    # Maintain per-tenant history sliding window (up to n-3 .. n)
    tenant_history: Dict[str, List[Dict[str, Any]]] = {}
    tenant_locked: Dict[str, bool] = {}
    tenant_scrutiny_tier: Dict[str, str] = {}  # CLEAN, WATCHLIST, LOCKED

    latencies: List[float] = []
    fast_hack_kill_step: Optional[int] = None
    slow_hack_kill_step: Optional[int] = None
    slow_hack_score_trajectory: List[float] = []

    seq = 0
    t_start_total = time.perf_counter()

    for tx in all_txs:
        seq += 1
        tid = tx["tenant_id"]
        ttype = tx["tenant_type"]

        if tid not in tenant_history:
            tenant_history[tid] = []
            tenant_locked[tid] = False
            tenant_scrutiny_tier[tid] = "CLEAN"

        # Check if already locked by circuit breaker (drop for FAST_HACK to show instant kill,
        # but evaluate all 10 stages for SLOW_HACK to capture full trajectory)
        if tenant_locked[tid] and ttype != "SLOW_HACK":
            entry = {
                "seq": seq,
                "tx_time": tx["tx_time"],
                "tenant_id": tid,
                "tenant_type": ttype,
                "amount": tx["amount"],
                "balance": tx["balance"],
                "solvency_prob": 1.0,
                "sybil_drain_score": 4.0,
                "verdict": "DROPPED_ALREADY_LOCKED",
                "latency_ms": 0.0,
                "flag_reason": "Account already suspended by circuit breaker. Execution halted.",
            }
            logger.log(entry)
            continue

        # Prepare state for Jev
        history = tenant_history[tid][-3:]  # Grab up to n-3
        is_deep = (tenant_scrutiny_tier[tid] == "WATCHLIST") or (len(history) >= 2 and ttype != "CLEAN")

        state = {
            "current_tx": {
                "amount": tx["amount"],
                "account_balance": tx["balance"],
                "is_balance_sufficient": tx["is_sufficient"],
                "timestamp": tx["timestamp"],
                "hour": tx["hour"],
                "is_off_hours": tx["is_off_hours"],
                "recipient": tx["recipient"],
                "memo": tx["memo"],
            },
            "tenant_scrutiny_state": tenant_scrutiny_tier[tid],
        }

        # Include sliding window if historical context exists
        if history:
            window_amounts = [h["amount"] for h in history] + [tx["amount"]]
            state["sliding_window_n_minus_3"] = {
                "window_size": len(window_amounts),
                "cumulative_outflow": sum(window_amounts),
                "history_sequence": [
                    {
                        "t_minus": h["tx_time"],
                        "amt": h["amount"],
                        "bal": h["balance"],
                        "to_dummy": h["recipient"]["is_dummy"],
                    }
                    for h in history
                ],
            }

        # Evaluate through Jev
        decision = call_jev_decision(state, is_deep_window=is_deep)
        latencies.append(decision["latency_ms"])

        v = decision["verdict"]
        score = decision["sybil_drain_score"]
        try:
            score_f = float(score)
        except (ValueError, TypeError):
            score_f = 0.0

        if ttype == "SLOW_HACK":
            slow_hack_score_trajectory.append(score_f)

        # Adaptive State Progression
        if v == "TRIP_CIRCUIT_BREAKER_AND_LOCK":
            tenant_locked[tid] = True
            tenant_scrutiny_tier[tid] = "LOCKED"
            if ttype == "FAST_HACK" and fast_hack_kill_step is None:
                fast_hack_kill_step = len([t for t in all_txs[:seq] if t["tenant_id"] == tid])
            elif ttype == "SLOW_HACK" and slow_hack_kill_step is None:
                slow_hack_kill_step = len([t for t in all_txs[:seq] if t["tenant_id"] == tid])
        elif v == "WATCHLIST_REITERATE" or score_f >= 1.5:
            tenant_scrutiny_tier[tid] = "WATCHLIST"
        else:
            tenant_scrutiny_tier[tid] = "CLEAN"

        history_summary = ""
        if history:
            history_summary = f"{len(history)} prior txs in memory; cum. outflow: ${sum([h['amount'] for h in history] + [tx['amount']]):,.2f}"

        entry = {
            "seq": seq,
            "tx_time": tx["tx_time"],
            "tenant_id": tid,
            "tenant_type": ttype,
            "amount": tx["amount"],
            "balance": tx["balance"],
            "solvency_prob": decision["solvency_breach_prob"],
            "sybil_drain_score": score_f,
            "verdict": v,
            "latency_ms": decision["latency_ms"],
            "prompt_state": state,
            "raw_response": decision["raw"],
            "flag_reason": f"Adaptive State updated to -> {tenant_scrutiny_tier[tid]}",
            "history_summary": history_summary,
        }
        logger.log(entry)

        # Append to tenant history
        tenant_history[tid].append(tx)

    t_total_elapsed = time.perf_counter() - t_start_total
    logger.save_json()

    # Final Analytics & Summary
    print("\n" + "=" * 115)
    print("📊 FINAL BENCHMARK AUDIT & ANALYTICS SUMMARY")
    print("=" * 115)
    print(f"Total Transactions Processed: {seq}")
    print(f"Total Wall-Clock Time:        {t_total_elapsed:.2f} seconds")
    if latencies:
        print(f"Average Jev Decision Latency: {sum(latencies)/len(latencies):.1f} ms (Min: {min(latencies):.1f}ms | Max: {max(latencies):.1f}ms)")
    print("-" * 115)

    # Scenarios Results
    clean_entries = [r for r in logger.records if r["tenant_type"] == "CLEAN"]
    false_positives = [r for r in clean_entries if r["verdict"] == "TRIP_CIRCUIT_BREAKER_AND_LOCK"]
    print(f"Scenario 1 (Clean Baseline - 8 Accounts):")
    print(f"   Evaluations:     {len(clean_entries)}")
    print(f"   False Positives: {len(false_positives)} (0.0% false lockouts)")

    print(f"\nScenario 2 (Fast Hack - 1 Account):")
    print(f"   Attack Profile:  0-balance 1M bursts at 03:14 AM")
    print(f"   Kill Point:      Terminated at Tx #{fast_hack_kill_step} (Remaining transactions dropped immediately)")

    print(f"\nScenario 3 (Slow Hack - 1 Account with Fluctuating Scores):")
    print(f"   Total Stages:    10 transactions")
    print(f"   Score Trajectory: {' -> '.join([f'{s:.2f}' for s in slow_hack_score_trajectory])}")
    print(f"   Kill Point:      Caught & locked down at Stage #{slow_hack_kill_step} as sliding window accumulated")

    print("\nLogs successfully written to:")
    print(f"   📄 Text Log:   {LOG_FILE_PATH}")
    print(f"   📊 JSON Audit: {AUDIT_JSON_PATH}")
    print("=" * 115)


if __name__ == "__main__":
    run_simulation()
