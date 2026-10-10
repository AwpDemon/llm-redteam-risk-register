"""Grader calibration against hand labels.

A grader is only as trustworthy as its agreement with a careful human. This module compares, on a
stratified sample of transcripts that were hand-labeled using docs/labeling_guide.md:

  * the LLM judge's verdict            vs. the hand label
  * the deterministic grader's verdict vs. the hand label (where a deterministic grader exists)
  * the final score used in the report vs. the hand label

and reports accuracy, precision, recall and Cohen's kappa for each.
"""

from __future__ import annotations

import csv
import json
import random
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

from .report import INK, INK2, SEQ_BLUE, SURFACE, load_scored
from .runner import read_jsonl
from .stats import cohen_kappa, confusion
from .suite import load_attacks

LABEL_FIELDS = ["defense", "case_id", "seed", "human_success", "labeler", "note"]


def read_labels(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as f:
        return [r for r in csv.DictReader(f) if not r["defense"].startswith("#")]


def stratified_sample(runs_dir: Path, defenses: list[str], per_category: int, seed: int = 13) -> list[tuple]:
    """Pick (defense, case_id, seed) triples: per defense, ``per_category`` distinct cases per category."""
    rng = random.Random(seed)
    picks = []
    for d in defenses:
        by_cat: dict[str, list[dict]] = defaultdict(list)
        for r in read_jsonl(runs_dir / f"{d}.attacks.jsonl"):
            by_cat[r["category"]].append(r)
        for _cat, rows in sorted(by_cat.items()):
            cases = sorted({r["case_id"] for r in rows})
            for cid in rng.sample(cases, min(per_category, len(cases))):
                seeds = sorted(r["seed"] for r in rows if r["case_id"] == cid)
                picks.append((d, cid, rng.choice(seeds)))
    return picks


def _metrics(truth: list[int], pred: list[int]) -> dict[str, Any]:
    m = confusion(truth, pred)
    m["kappa"] = cohen_kappa(truth, pred) if truth else float("nan")
    return m


def run_calibration(runs_dir: Path, labels_path: Path, results_dir: Path, fig_dir: Path) -> str:
    labels = read_labels(labels_path)
    if not labels:
        return f"no labels found at {labels_path}"
    scored: dict[str, dict[tuple, dict]] = {}
    for d in {lab["defense"] for lab in labels}:
        scored[d] = {(r["case_id"], r["seed"]): r for r in load_scored(runs_dir, d)}

    judge_only = {c.id for c in load_attacks()[1] if c.judge_only}
    pairs: dict[str, tuple[list[int], list[int]]] = {
        "deterministic": ([], []),
        "judge": ([], []),
        "judge_on_judge_scored_cases": ([], []),
        "final": ([], []),
    }
    disagreements = []
    for lab in labels:
        row = scored.get(lab["defense"], {}).get((lab["case_id"], int(lab["seed"])))
        if row is None:
            continue
        h = int(lab["human_success"])
        for key, val in (
            ("judge", row["judge_success"]),
            ("deterministic", row["deterministic_success"]),
            ("final", row["success"]),
        ):
            if val is not None:
                pairs[key][0].append(h)
                pairs[key][1].append(int(val))
                if key == "judge" and lab["case_id"] in judge_only:
                    pairs["judge_on_judge_scored_cases"][0].append(h)
                    pairs["judge_on_judge_scored_cases"][1].append(int(val))
        if row["judge_success"] is not None and int(row["judge_success"]) != h:
            disagreements.append(
                {
                    "defense": lab["defense"],
                    "case_id": lab["case_id"],
                    "seed": lab["seed"],
                    "human": h,
                    "judge": int(row["judge_success"]),
                    "note": lab["note"],
                }
            )
    res = {k: _metrics(t, p) for k, (t, p) in pairs.items() if t}
    res["n_labels"] = len(labels)
    res["judge_disagreements"] = disagreements
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "calibration.json").write_text(json.dumps(res, indent=2), encoding="utf-8", newline="\n")

    lines = [
        "| Grader vs. hand label | n | Accuracy | Precision | Recall | Cohen's kappa |",
        "|---|---|---|---|---|---|",
    ]
    names = {
        "deterministic": "Deterministic graders (where defined)",
        "judge": "LLM judge, all labeled transcripts",
        "judge_on_judge_scored_cases": "LLM judge, judge-scored cases only",
        "final": "Final score used in results",
    }
    for k in names:
        if k in res:
            m = res[k]
            lines.append(
                f"| {names[k]} | {m['n']} | {m['accuracy']:.2f} | {m['precision']:.2f} | {m['recall']:.2f} "
                f"| {m['kappa']:.2f} |"
            )
    md = "\n".join(lines)
    (results_dir / "calibration.md").write_text(md + "\n", encoding="utf-8", newline="\n")
    if "judge" in res:
        _confusion_figure(res["judge"], fig_dir / "judge_calibration.png")
    return md


def _confusion_figure(m: dict[str, Any], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    mat = [[m["tn"], m["fp"]], [m["fn"], m["tp"]]]
    cmap = LinearSegmentedColormap.from_list("seq", ["#f4f8fd"] + SEQ_BLUE)
    fig, ax = plt.subplots(figsize=(4.8, 4.0), facecolor=SURFACE)
    ax.imshow(mat, cmap=cmap, vmin=0, vmax=max(max(r) for r in mat))
    top = max(max(r) for r in mat)
    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                str(mat[i][j]),
                ha="center",
                va="center",
                fontsize=14,
                color="white" if mat[i][j] > 0.55 * top else INK,
            )
    ax.set_xticks([0, 1], ["Judge: failed", "Judge: succeeded"], color=INK2)
    ax.set_yticks([0, 1], ["Human: failed", "Human: succeeded"], color=INK2)
    ax.tick_params(length=0)
    ax.spines[:].set_visible(False)
    ax.set_title(
        f"LLM judge vs. hand labels (n={m['n']})\naccuracy {m['accuracy']:.2f}, kappa {m['kappa']:.2f}",
        loc="left",
        fontsize=10,
        color=INK,
    )
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def render_transcript(row: dict[str, Any], case) -> str:
    t = row["turn"]
    tools = (
        "\n".join(
            f"    - {e['name']}({json.dumps(e['args'])}) -> "
            + ("EXECUTED" if e["executed"] else f"BLOCKED: {e['blocked_reason']}")
            for e in t["tool_events"]
        )
        or "    (none)"
    )
    att = ("\nATTACHMENT:\n" + textwrap.indent("\n".join(case.attachments), "    ")) if case.attachments else ""
    return (
        f"=== {row['defense']} {case.id} seed={row['seed']} [{case.category}] {case.technique}\n"
        f"PROMPT: {case.prompt[:600]}{att}\nCRITERION: {case.success_criteria}\n"
        + (f"REFERENCE: {case.reference}\n" if case.reference else "")
        + f"TOOLS:\n{tools}\nGUARD: input={t['blocked_by']} output={t['output_filter_hits']}\n"
        f"REPLY:\n{textwrap.indent(t['reply'][:2500], '    ')}\n"
    )


def interactive_label(runs_dir: Path, defense: str, labels_path: Path, labeler: str) -> int:  # pragma: no cover
    _, cases = load_attacks()
    cmap = {c.id: c for c in cases}
    done = {(lab["defense"], lab["case_id"], lab["seed"]) for lab in read_labels(labels_path)}
    new = not labels_path.exists()
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with labels_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LABEL_FIELDS)
        if new:
            w.writeheader()
        for d, cid, seed in stratified_sample(runs_dir, [defense], per_category=10):
            if (d, cid, str(seed)) in done:
                continue
            row = next(
                r for r in read_jsonl(runs_dir / f"{d}.attacks.jsonl") if r["case_id"] == cid and r["seed"] == seed
            )
            print(render_transcript(row, cmap[cid]))
            ans = input("Attack succeeded? [y]es / [n]o / [s]kip / [q]uit: ").strip().lower()
            if ans == "q":
                break
            if ans not in ("y", "n"):
                continue
            note = input("note (optional): ").strip()
            w.writerow(
                {
                    "defense": d,
                    "case_id": cid,
                    "seed": seed,
                    "human_success": int(ans == "y"),
                    "labeler": labeler,
                    "note": note,
                }
            )
            f.flush()
    return 0
