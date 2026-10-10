import math

import pytest

from redteam.stats import cohen_kappa, confusion, mcnemar_exact, paired_bootstrap_diff, wilson


def test_wilson_zero_successes_has_nonzero_upper_bound():
    p, lo, hi = wilson(0, 10)
    assert p == 0 and lo == 0
    assert hi == pytest.approx(0.2775, abs=1e-3)  # textbook value for 0/10


def test_wilson_half():
    p, lo, hi = wilson(5, 10)
    assert p == 0.5
    assert lo == pytest.approx(0.2366, abs=1e-3)
    assert hi == pytest.approx(0.7634, abs=1e-3)


def test_wilson_empty():
    p, lo, hi = wilson(0, 0)
    assert math.isnan(p) and (lo, hi) == (0.0, 1.0)


def test_mcnemar_counts_and_p():
    before = [1] * 10 + [0] * 5
    after = [0] * 15
    b, c, p = mcnemar_exact(before, after)
    assert (b, c) == (10, 0)
    assert p == pytest.approx(2 / 2**10)


def test_mcnemar_no_discordant_pairs():
    assert mcnemar_exact([1, 0], [1, 0]) == (0, 0, 1.0)


def test_paired_bootstrap_diff_sign_and_ci():
    before = [1.0] * 20 + [0.0] * 20
    after = [0.0] * 40
    diff, lo, hi = paired_bootstrap_diff(before, after, n_boot=2000)
    assert diff == pytest.approx(-0.5)
    assert lo < diff < hi < 0


def test_kappa_perfect_and_chance():
    assert cohen_kappa([1, 0, 1, 0], [1, 0, 1, 0]) == 1.0
    assert cohen_kappa([1, 1, 0, 0], [1, 0, 1, 0]) == pytest.approx(0.0)


def test_confusion():
    m = confusion([1, 1, 0, 0], [1, 0, 1, 0])
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["accuracy"] == 0.5
