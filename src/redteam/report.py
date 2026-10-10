"""Aggregate run files into the numbers and figures quoted in the README.

Scoring rule per trial: the deterministic verdict if the case has deterministic graders, otherwise the LLM
judge verdict. Statistics:

* Trial-level ASR = share of (case, seed) trials where the attack succeeded.
* Its 95% CI is a Wilson interval computed with an EFFECTIVE sample size equal to the number of cases, not
  the number of trials. Trials of the same case share a prompt and are strongly correlated, so 5 seeds of one
  case are not 5 independent observations. Treating each case as one observation is the most conservative
  assumption (design effect = seeds per case) and, unlike a bootstrap, still gives a non-zero upper bound when
  0 of n attacks succeed (0/60 -> upper bound ~6%, not 0%). The naive all-trials Wilson interval is also
  stored in summary.json for comparison.
* Case-level "any-seed" ASR = share of cases where at least one seed succeeded (an attacker who retries).
  Cases are independent, so this uses an ordinary Wilson interval.
* Defense vs. baseline: paired, case-clustered bootstrap CI on the change in trial-level ASR, and an exact
  McNemar test on case-level any-seed outcomes.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from .graders import grade_attack, grade_benign
from .runner import read_jsonl
from .stats import mcnemar_exact, paired_bootstrap_diff, wilson
from .suite import load_attacks, load_benign

DEFENSE_ORDER = ["baseline", "prompt_hardening", "guardrails", "tool_policy", "full"]
DEFENSE_LABEL = {
    "baseline": "Baseline (no controls)",
    "prompt_hardening": "Prompt hardening only",
    "guardrails": "I/O filters + retrieval sanitization",
    "tool_policy": "Tool policy only",
    "full": "Full defense (all layers)",
}

# Reference palette (dataviz skill, light mode)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]


def case_ci(per_case: list[float]) -> tuple[float, float, float]:
    """Mean of per-case rates with a Wilson CI at effective n = number of cases (see module docstring)."""
    n = len(per_case)
    p = float(np.mean(per_case))
    _, lo, hi = wilson(p * n, n)
    return p, lo, hi


def load_scored(runs_dir: Path, defense: str) -> list[dict[str, Any]]:
    """Attack rows with a final ``success`` field (bool) and ``scored_by``.

    Deterministic grades are RE-COMPUTED from the stored transcript with the current suite definition, so a
    grader fix applies to old runs without re-querying the model (graders are pure functions of the turn).
    """
    _, cases = load_attacks()
    by_id = {c.id: c for c in cases}
    rows = read_jsonl(runs_dir / f"{defense}.attacks.jsonl")
    judge = {(j["case_id"], j["seed"]): j for j in read_jsonl(runs_dir / f"{defense}.judge.jsonl")}
    out = []
    for r in rows:
        g = grade_attack(by_id[r["case_id"]], r["turn"])
        r["deterministic_success"], r["fired"] = g.success, g.fired
        j = judge.get((r["case_id"], r["seed"]))
        r["judge_success"] = j["judge_success"] if j else None
        if r["deterministic_success"] is not None:
            r["success"], r["scored_by"] = bool(r["deterministic_success"]), "deterministic"
        elif j and j["judge_success"] is not None:
            r["success"], r["scored_by"] = bool(j["judge_success"]), "judge"
        else:
            r["success"], r["scored_by"] = None, "unscored"
        out.append(r)
    return out


def load_benign_scored(runs_dir: Path, defense: str) -> list[dict[str, Any]]:
    """Benign rows re-graded with the current suite definition (same reasoning as load_scored)."""
    cases = {c.id: c for c in load_benign()}
    rows = read_jsonl(runs_dir / f"{defense}.benign.jsonl")
    for r in rows:
        r.update(grade_benign(cases[r["case_id"]], r["turn"]))
    return rows


def _per_case(rows: list[dict[str, Any]]) -> dict[str, list[int]]:
    d: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        if r["success"] is not None:
            d[r["case_id"]].append(int(r["success"]))
    return d


def asr_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pc = _per_case(rows)
    if not pc:
        return {"n_cases": 0, "n_trials": 0}
    means = [float(np.mean(v)) for v in pc.values()]
    p, lo, hi = case_ci(means)
    any_k = sum(1 for v in pc.values() if max(v) == 1)
    ap, alo, ahi = wilson(any_k, len(pc))
    trials = sum(len(v) for v in pc.values())
    k = sum(sum(v) for v in pc.values())
    _, wlo, whi = wilson(k, trials)
    return {
        "n_cases": len(pc),
        "n_trials": trials,
        "successes": k,
        "asr": p,
        "ci_low": lo,
        "ci_high": hi,
        "wilson_naive_low": wlo,
        "wilson_naive_high": whi,
        "any_seed_asr": ap,
        "any_seed_ci_low": alo,
        "any_seed_ci_high": ahi,
    }


def benign_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    by: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by[r["case_id"]].append(r)
    acc = [float(np.mean([x["correct"] for x in v])) for v in by.values()]
    ref = [float(np.mean([x["refused"] for x in v])) for v in by.values()]
    a, alo, ahi = case_ci(acc)
    f, flo, fhi = case_ci(ref)
    return {
        "n_cases": len(by),
        "n_trials": len(rows),
        "accuracy": a,
        "accuracy_ci": [alo, ahi],
        "false_refusal": f,
        "false_refusal_ci": [flo, fhi],
    }


def cost_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    t = [r["turn"] for r in rows]
    if not t:
        return {}
    return {
        "mean_latency_s": float(np.mean([x["latency_s"] for x in t])),
        "p95_latency_s": float(np.percentile([x["latency_s"] for x in t], 95)),
        "mean_prompt_tokens": float(np.mean([x["prompt_tokens"] for x in t])),
        "mean_completion_tokens": float(np.mean([x["completion_tokens"] for x in t])),
        "max_completion_tokens": int(max(x["completion_tokens"] for x in t)),
        "mean_model_calls": float(np.mean([x["model_calls"] for x in t])),
        "input_filter_blocks": sum(1 for x in t if x["blocked_by"]),
        "output_filter_triggers": sum(1 for x in t if x["output_filter_hits"]),
        "sanitized_sentences": int(sum(x["sanitized_sentences"] for x in t)),
        "tool_calls_blocked": sum(1 for x in t for e in x["tool_events"] if not e["executed"]),
    }


def build_summary(runs_dir: Path, baseline: str = "baseline") -> dict[str, Any]:
    cats, _ = load_attacks()
    present = [d for d in DEFENSE_ORDER if (runs_dir / f"{d}.attacks.jsonl").exists()]
    present += sorted(
        p.name.split(".")[0] for p in runs_dir.glob("*.attacks.jsonl") if p.name.split(".")[0] not in present
    )
    summary: dict[str, Any] = {"defenses": {}, "categories": {k: v for k, v in cats.items()}}
    scored = {d: load_scored(runs_dir, d) for d in present}
    for d in present:
        rows = scored[d]
        model = rows[0]["model"] if rows else None
        blk = {
            "label": DEFENSE_LABEL.get(d, d),
            "model": model,
            "temperature": rows[0]["temperature"] if rows else None,
            "seeds": sorted({r["seed"] for r in rows}),
            "unscored_trials": sum(1 for r in rows if r["success"] is None),
            "overall": asr_block(rows),
            "by_category": {c: asr_block([r for r in rows if r["category"] == c]) for c in cats},
            "benign": benign_block(load_benign_scored(runs_dir, d)),
            "cost_attacks": cost_block(rows),
            "cost_benign": cost_block(read_jsonl(runs_dir / f"{d}.benign.jsonl")),
            "scored_by": {k: sum(1 for r in rows if r["scored_by"] == k) for k in ("deterministic", "judge")},
        }
        if d != baseline and baseline in scored:
            blk["vs_baseline"] = compare(scored[baseline], rows)
            blk["vs_baseline_by_category"] = {
                c: compare([r for r in scored[baseline] if r["category"] == c], [r for r in rows if r["category"] == c])
                for c in cats
            }
        summary["defenses"][d] = blk
    return summary


def compare(before_rows, after_rows) -> dict[str, Any]:
    b, a = _per_case(before_rows), _per_case(after_rows)
    common = sorted(set(b) & set(a))
    if not common:
        return {}
    bm = [float(np.mean(b[c])) for c in common]
    am = [float(np.mean(a[c])) for c in common]
    diff, lo, hi = paired_bootstrap_diff(bm, am)
    fixed, broke, p = mcnemar_exact([max(b[c]) for c in common], [max(a[c]) for c in common])
    return {
        "n_cases": len(common),
        "asr_change": diff,
        "ci_low": lo,
        "ci_high": hi,
        "cases_fixed": fixed,
        "cases_broken": broke,
        "mcnemar_p": p,
    }


# ---------------------------------------------------------------- rendering
def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def to_markdown(s: dict[str, Any]) -> str:
    ds = s["defenses"]
    lines = [
        "### Overall attack success rate (ASR) and cost on legitimate traffic",
        "",
        "| Configuration | ASR, all trials [95% CI] | ASR, any of 5 seeds [95% CI] | Change vs. baseline "
        "[95% CI] | Benign accuracy | Benign false refusals | Mean output tokens per attack turn |",
        "|---|---|---|---|---|---|---|",
    ]
    for b in ds.values():
        o = b["overall"]
        if not o.get("n_cases"):
            continue
        v = b.get("vs_baseline")
        change = f"{100 * v['asr_change']:+.0f} pts [{100 * v['ci_low']:+.0f}, {100 * v['ci_high']:+.0f}]" if v else "-"
        be = b["benign"]
        lines.append(
            f"| {b['label']} | {_pct(o['asr'])} [{_pct(o['ci_low'])}, {_pct(o['ci_high'])}] "
            f"| {_pct(o['any_seed_asr'])} [{_pct(o['any_seed_ci_low'])}, {_pct(o['any_seed_ci_high'])}] "
            f"| {change} | {_pct(be['accuracy']) if be else '-'} | {_pct(be['false_refusal']) if be else '-'} "
            f"| {b['cost_attacks']['mean_completion_tokens']:.0f} |"
        )
    cats = s["categories"]
    names = [d for d in ds if ds[d]["overall"].get("n_cases")]
    lines += [
        "",
        "### ASR by category (all trials; 95% Wilson CI, effective n = cases)",
        "",
        "| Category | OWASP | n cases | " + " | ".join(ds[d]["label"] for d in names) + " |",
        "|---|---|---|" + "---|" * len(names),
    ]
    for c, meta in cats.items():
        cells = []
        for d in names:
            blk = ds[d]["by_category"][c]
            cells.append(
                f"{_pct(blk['asr'])} [{_pct(blk['ci_low'])}-{_pct(blk['ci_high'])}]" if blk.get("n_cases") else "-"
            )
        n = ds[names[0]]["by_category"][c].get("n_cases", 0)
        lines.append(f"| {meta['label']} | {', '.join(meta['owasp'])} | {n} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def make_figures(s: dict[str, Any], fig_dir: Path) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.edgecolor": INK2,
            "axes.labelcolor": INK,
            "xtick.color": INK2,
            "ytick.color": INK2,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    fig_dir.mkdir(parents=True, exist_ok=True)
    ds = s["defenses"]
    cats = s["categories"]
    out: list[Path] = []

    # 1. Baseline vs full by category (2 series, horizontal bars with CI whiskers)
    if "baseline" in ds and "full" in ds:
        labels = [cats[c]["label"] for c in cats]
        y = np.arange(len(labels))
        fig, ax = plt.subplots(figsize=(8.5, 4.8))
        h = 0.36
        for i, (d, color) in enumerate([("baseline", SERIES[0]), ("full", SERIES[1])]):
            vals = [ds[d]["by_category"][c] for c in cats]
            p = np.array([v["asr"] for v in vals])
            err = np.clip(
                np.array([[v["asr"] - v["ci_low"] for v in vals], [v["ci_high"] - v["asr"] for v in vals]]), 0, None
            )
            yy = y + (i - 0.5) * (h + 0.04)
            ax.barh(yy, p * 100, height=h, color=color, label=ds[d]["label"], zorder=2)
            ax.errorbar(p * 100, yy, xerr=err * 100, fmt="none", ecolor=INK2, elinewidth=1, capsize=2, zorder=3)
            for yv, pv in zip(yy, p, strict=True):
                ax.text(min(pv * 100 + 1.5, 101), yv, f"{pv * 100:.0f}%", va="center", fontsize=8, color=INK)
        ax.set_yticks(y, labels)
        ax.invert_yaxis()
        ax.set_xlim(0, 105)
        ax.set_xlabel("Attack success rate, % of trials (whiskers: 95% Wilson CI, effective n = cases)", labelpad=6)
        ax.grid(axis="x", color=GRID, zorder=0)
        ax.legend(loc="upper center", bbox_to_anchor=(0.4, -0.13), ncol=2, frameon=False)
        o_b, o_f = ds["baseline"]["overall"], ds["full"]["overall"]
        ax.set_title(
            f"Attack success by category: {o_b['asr'] * 100:.0f}% baseline vs "
            f"{o_f['asr'] * 100:.0f}% with all controls",
            loc="left",
            color=INK,
            fontsize=11,
        )
        fig.tight_layout()
        p = fig_dir / "asr_by_category.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        out.append(p)

    # 2. Ablation heatmap (category x configuration), sequential blue
    names = [d for d in ds if ds[d]["overall"].get("n_cases")]
    if len(names) >= 2:
        from matplotlib.colors import LinearSegmentedColormap

        cmap = LinearSegmentedColormap.from_list("seq", ["#f4f8fd"] + SEQ_BLUE)
        mat = np.array(
            [[ds[d]["by_category"][c].get("asr", np.nan) for d in names] for c in cats]
            + [[ds[d]["overall"]["asr"] for d in names]]
        )
        fig, ax = plt.subplots(figsize=(1.7 * len(names) + 3.2, 4.8))
        ax.imshow(mat, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        for i in range(mat.shape[0]):
            for j in range(mat.shape[1]):
                label = "n/a" if np.isnan(mat[i, j]) else f"{mat[i, j] * 100:.0f}%"
                ax.text(
                    j,
                    i,
                    label,
                    ha="center",
                    va="center",
                    fontsize=9,
                    color="white" if mat[i, j] > 0.55 else INK,
                    fontweight="bold" if i == len(cats) else None,
                )
        ax.set_xticks(
            range(len(names)), [ds[d]["label"].replace(" + ", "\n+ ").replace(" (", "\n(") for d in names], fontsize=8
        )
        ax.set_yticks(range(mat.shape[0]), [cats[c]["label"] for c in cats] + ["All attacks"])
        ax.axhline(len(cats) - 0.5, color=SURFACE, lw=3)
        ax.spines[:].set_visible(False)
        ax.tick_params(length=0)
        ax.set_title("Ablation: attack success rate by control layer", loc="left", color=INK, fontsize=11)
        fig.tight_layout()
        p = fig_dir / "ablation_heatmap.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        out.append(p)

    # 3. Security vs. utility trade-off (one series, direct labels)
    pts = [(d, ds[d]) for d in names if ds[d]["benign"]]
    if len(pts) >= 2:
        fig, ax = plt.subplots(figsize=(7.2, 4.6))
        offsets = {"guardrails": (-8, 6, "right"), "tool_policy": (8, -12, "left")}
        for d, b in pts:
            x, yv = b["benign"]["accuracy"] * 100, b["overall"]["asr"] * 100
            ax.scatter(x, yv, s=70, color=SERIES[0], edgecolor=SURFACE, linewidth=2, zorder=3)
            dx, dy, ha = offsets.get(d, (8, 6, "left"))
            ax.annotate(b["label"], (x, yv), textcoords="offset points", xytext=(dx, dy), ha=ha, fontsize=8, color=INK)
        ax.set_xlabel("Benign accuracy, % of legitimate requests answered correctly (higher is better)")
        ax.set_ylabel("Attack success rate, % (lower is better)")
        ax.grid(color=GRID, zorder=0)
        ax.set_xlim(50, 102)
        ax.set_ylim(0, max(5, max(b["overall"]["asr"] * 100 for _, b in pts) * 1.2))
        ax.set_title("Security vs. usefulness of each configuration", loc="left", color=INK, fontsize=11)
        fig.tight_layout()
        p = fig_dir / "security_vs_utility.png"
        fig.savefig(p, dpi=160)
        plt.close(fig)
        out.append(p)
    return out


def build_report(runs_dir: Path, results_dir: Path, fig_dir: Path, baseline: str = "baseline") -> dict[str, Any]:
    s = build_summary(runs_dir, baseline)
    md = to_markdown(s)
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8", newline="\n")
    (results_dir / "summary.md").write_text(md + "\n", encoding="utf-8", newline="\n")
    figs = make_figures(s, fig_dir)
    return {"summary": s, "markdown": md, "figures": [str(f) for f in figs]}


def gate(runs_dir: Path, defense: str, max_asr: float, max_false_refusal: float = 1.0) -> tuple[bool, str]:
    s = build_summary(runs_dir)
    d = s["defenses"].get(defense)
    if not d or not d["overall"].get("n_cases"):
        return False, f"no scored run for defense '{defense}' in {runs_dir}"
    asr = d["overall"]["asr"]
    fr = d["benign"].get("false_refusal", 0.0) if d["benign"] else 0.0
    ok = asr <= max_asr and fr <= max_false_refusal
    msg = (
        f"{'PASS' if ok else 'FAIL'}: {defense} ASR={asr:.3f} (max {max_asr}), "
        f"false_refusal={fr:.3f} (max {max_false_refusal}), unscored={d['unscored_trials']}"
    )
    return ok, msg
