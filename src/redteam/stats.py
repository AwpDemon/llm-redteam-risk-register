"""Small, dependency-light statistics used in the report.

- Wilson score interval for a single proportion (attack success rate, ASR). Preferred over the textbook
  "p +/- 1.96*sqrt(p(1-p)/n)" (Wald) interval because Wald collapses to [0, 0] when 0 of n attacks succeed
  and is badly calibrated for small n -- exactly the regime of a red-team suite.
- Paired bootstrap CI for the change in ASR between two defenses run on the SAME cases.
- Exact McNemar test for paired binary outcomes (did the mitigation flip outcomes more often one way?).
- Cohen's kappa for judge-vs-human agreement (agreement corrected for chance).
"""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float, float]:
    """Return (p_hat, lower, upper) for k successes out of n trials."""
    if n == 0:
        return float("nan"), 0.0, 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def paired_bootstrap_diff(
    before: Sequence[int], after: Sequence[int], n_boot: int = 10_000, seed: int = 0
) -> tuple[float, float, float]:
    """(after - before) mean difference with a 95% percentile CI, resampling cases (pairs) with replacement."""
    b = np.asarray(before, dtype=float)
    a = np.asarray(after, dtype=float)
    if b.shape != a.shape or b.size == 0:
        raise ValueError("before/after must be non-empty and the same length")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, b.size, size=(n_boot, b.size))
    diffs = (a[idx] - b[idx]).mean(axis=1)
    return float((a - b).mean()), float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))


def mcnemar_exact(before: Sequence[int], after: Sequence[int]) -> tuple[int, int, float]:
    """Two-sided exact McNemar test. Returns (b, c, p) where b = 1->0 flips (fixed), c = 0->1 flips (broken)."""
    b = sum(1 for x, y in zip(before, after, strict=True) if x == 1 and y == 0)
    c = sum(1 for x, y in zip(before, after, strict=True) if x == 0 and y == 1)
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return b, c, min(1.0, 2 * tail)


def cohen_kappa(x: Sequence[int], y: Sequence[int]) -> float:
    if len(x) != len(y) or not x:
        raise ValueError("need two equal-length non-empty label lists")
    n = len(x)
    po = sum(1 for a, b in zip(x, y, strict=True) if a == b) / n
    px, py = sum(x) / n, sum(y) / n
    pe = px * py + (1 - px) * (1 - py)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def confusion(truth: Sequence[int], pred: Sequence[int]) -> dict[str, float]:
    tp = sum(1 for t, p in zip(truth, pred, strict=True) if t and p)
    tn = sum(1 for t, p in zip(truth, pred, strict=True) if not t and not p)
    fp = sum(1 for t, p in zip(truth, pred, strict=True) if not t and p)
    fn = sum(1 for t, p in zip(truth, pred, strict=True) if t and not p)
    n = len(truth)
    return {
        "n": n,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": (tp + tn) / n if n else float("nan"),
        "precision": tp / (tp + fp) if tp + fp else float("nan"),
        "recall": tp / (tp + fn) if tp + fn else float("nan"),
    }
