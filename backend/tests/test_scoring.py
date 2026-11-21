from app.core.scoring import compute_utility_score

def test_unreachable_vulnerability_is_suppressed():
    score, tier = compute_utility_score(
        reachability_conf=0.0,
        epss_score=0.95,
        cvss_score=9.8,
        is_in_kev=True,
        business_criticality=1.5,
    )
    assert tier == "SUPPRESSED_NOISE"
    assert score <= 15.0

def test_direct_reachable_kev_vulnerability_is_critical():
    score, tier = compute_utility_score(
        reachability_conf=1.0,
        epss_score=0.89,
        cvss_score=9.8,
        is_in_kev=True,
        business_criticality=1.0,
    )
    assert tier == "CRITICAL_ACTION"
    assert score >= 90.0

def test_transitive_reachable_moderate_epss_is_monitor():
    score, tier = compute_utility_score(
        reachability_conf=0.75,
        epss_score=0.20,
        cvss_score=6.5,
        is_in_kev=False,
        business_criticality=1.0,
    )
    assert tier == "LOW_RISK" or tier == "MONITOR"
    assert 20.0 <= score <= 45.0