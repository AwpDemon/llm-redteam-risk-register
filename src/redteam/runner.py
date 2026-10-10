"""Run the attack + benign suites against one defense configuration and persist raw transcripts.

Output: ``<out_dir>/<defense>.attacks.jsonl`` and ``<out_dir>/<defense>.benign.jsonl``; one JSON object per
case with the full turn record (reply, tool events, tokens, latency, guard hits) plus deterministic grades.
Runs are resumable: cases already present in the file are skipped, so a long local run can be interrupted.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .client import ChatClient
from .graders import grade_attack, grade_benign
from .judge import judge_row
from .suite import AttackCase, BenignCase
from .target.app import DefenseConfig, HarborApp


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run_attacks(
    client: ChatClient,
    defense: DefenseConfig,
    cases: Iterable[AttackCase],
    out_dir: Path,
    *,
    seeds: Iterable[int] = (7,),
    temperature: float = 0.0,
) -> Path:
    path = out_dir / f"{defense.name}.attacks.jsonl"
    done = {(r["case_id"], r["seed"]) for r in read_jsonl(path)}
    for case, seed in [(c, s) for s in seeds for c in cases]:
        if (case.id, seed) in done:
            continue
        app = HarborApp(client, defense, temperature=temperature, seed=seed)
        t0 = time.perf_counter()
        turn, _ = app.respond(case.prompt, history=case.history, attachments=case.attachments)
        td = turn.to_dict()
        g = grade_attack(case, td)
        row = {
            "case_id": case.id,
            "category": case.category,
            "defense": defense.name,
            "model": client.model,
            "seed": seed,
            "temperature": temperature,
            "deterministic_success": g.success,
            "fired": g.fired,
            "turn": td,
        }
        _append(path, row)
        _log(
            f"[{defense.name}] {case.id:<7} s={seed} det={g.success!s:<5} calls={turn.model_calls} "
            f"out_tok={turn.completion_tokens:<5} {time.perf_counter() - t0:5.1f}s"
        )
    return path


def run_benign(
    client: ChatClient,
    defense: DefenseConfig,
    cases: Iterable[BenignCase],
    out_dir: Path,
    *,
    seeds: Iterable[int] = (7,),
    temperature: float = 0.0,
) -> Path:
    path = out_dir / f"{defense.name}.benign.jsonl"
    done = {(r["case_id"], r["seed"]) for r in read_jsonl(path)}
    for case, seed in [(c, s) for s in seeds for c in cases]:
        if (case.id, seed) in done:
            continue
        app = HarborApp(client, defense, temperature=temperature, seed=seed)
        turn, _ = app.respond(case.prompt)
        td = turn.to_dict()
        row = {
            "case_id": case.id,
            "defense": defense.name,
            "model": client.model,
            "seed": seed,
            "temperature": temperature,
            **grade_benign(case, td),
            "turn": td,
        }
        _append(path, row)
        _log(f"[{defense.name}] {case.id:<7} s={seed} correct={row['correct']!s:<5} refused={row['refused']}")
    return path


def run_judge(client: ChatClient, cases: dict[str, AttackCase], attacks_path: Path, *, all_cases: bool) -> Path:
    """Judge transcripts. ``all_cases=False`` judges only judge-graded cases (what scoring needs);
    ``all_cases=True`` also judges deterministically graded cases (for judge-vs-human calibration)."""
    out = attacks_path.with_name(attacks_path.name.replace(".attacks.jsonl", ".judge.jsonl"))
    done = {(r["case_id"], r["seed"]) for r in read_jsonl(out)}
    for row in read_jsonl(attacks_path):
        case = cases[row["case_id"]]
        if (row["case_id"], row["seed"]) in done or not (all_cases or case.judge_only):
            continue
        j = {**judge_row(client, case, row), "seed": row["seed"]}
        _append(out, j)
        _log(f"[judge] {case.id:<7} s={row['seed']} {j['judge_success']}")
    return out
