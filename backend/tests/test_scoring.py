import pytest

from app.core.config import Settings
from app.core.scoring import compute_utility_score, explain_utility_score

CFG = Settings(_env_file=None)


def score(conf=1.0, epss=0.1, cvss=5.0, kev=False, crit=1.0, pct=None):
    return compute_utility_score(conf, epss, cvss, kev, crit, pct, CFG)


# ---- original behaviour kept ---------------------------------------------------------
def test_unreachable_vulnerability_is_suppressed():
    s, tier = score(conf=0.0, epss=0.95, cvss=9.8, kev=True, crit=1.5)
    assert tier == "SUPPRESSED_NOISE" and s <= 15.0


def test_direct_reachable_kev_vulnerability_is_critical():
    s, tier = score(1.0, 0.89, 9.8, True)
    assert tier == "CRITICAL_ACTION" and s >= 90.0


def test_transitive_reachable_moderate_epss_is_monitor():
    s, tier = score(0.7, 0.20, 6.5, False)
    assert tier == "MONITOR" and 25.0 <= s <= 40.0


# ---- new behaviour -------------------------------------------------------------------
def test_reachable_critical_cvss_is_never_below_monitor():
    """Regression: reachable CVSS 9.8 with tiny EPSS used to fall to LOW_RISK when transitive."""
    s, tier, bd = explain_utility_score(0.7, 0.02, 9.8, False, 1.0, None, CFG)
    assert tier in ("MONITOR", "CRITICAL_ACTION") and s >= 30.0


def test_reachable_kev_is_always_critical():
    s, tier, bd = explain_utility_score(0.7, 0.01, 4.0, True, 0.7, None, CFG)
    assert tier == "CRITICAL_ACTION" and bd.floor_applied == "KEV"


def test_unreachable_never_exceeds_cap_even_for_kev():
    s, tier = score(conf=0.0, epss=1.0, cvss=10.0, kev=True, crit=2.0)
    assert s <= CFG.suppressed_cap and tier == "SUPPRESSED_NOISE"


def test_criticality_is_clamped_so_it_cannot_dominate():
    assert score(crit=2.0) == score(crit=CFG.criticality_max)
    assert score(crit=0.1) == score(crit=CFG.criticality_min)


def test_epss_scaling_is_not_negligible_for_small_values():
    low, _ = score(epss=0.0, cvss=5.0)
    small, _ = score(epss=0.04, cvss=5.0)
    assert small - low > 3.0  # linear weighting would add only 0.45*0.04*100 = 1.8


def test_percentile_overrides_raw_epss():
    a, _ = score(epss=0.01, pct=0.95)
    b, _ = score(epss=0.01, pct=0.10)
    assert a > b


@pytest.mark.parametrize("field,lo,hi", [("epss", 0.01, 0.9), ("cvss", 3.0, 9.0)])
def test_score_is_monotonic(field, lo, hi):
    assert score(**{field: lo}) [0] <= score(**{field: hi})[0]


def test_reachability_confidence_is_monotonic():
    assert score(conf=0.7)[0] <= score(conf=1.0)[0]


def test_inputs_are_clamped_not_crashing():
    s, tier = score(conf=5.0, epss=7.0, cvss=99.0, kev=True, crit=50.0)
    assert 0.0 <= s <= 100.0


def test_tier_thresholds_are_respected():
    s, tier = score(1.0, 0.0, 6.0, False)  # 0.35*0.6 = 21
    assert tier == "LOW_RISK" and s < CFG.tier_monitor


def test_breakdown_is_populated():
    _, _, bd = explain_utility_score(1.0, 0.5, 7.0, False, 1.0, None, CFG)
    assert bd.weighted_threat > 0 and bd.reachability_factor == 1.0 and bd.raw_score > 0


def test_weights_are_configurable():
    heavy_kev = Settings(_env_file=None, w_epss=0.1, w_cvss=0.1, w_kev=0.8)
    with_kev = compute_utility_score(1.0, 0.1, 5.0, True, 1.0, None, heavy_kev)[0]
    no_kev = compute_utility_score(1.0, 0.1, 5.0, False, 1.0, None, heavy_kev)[0]
    assert with_kev - no_kev > 70
