from typing import Tuple

def compute_utility_score(
    reachability_conf: float,
    epss_score: float,
    cvss_score: float,
    is_in_kev: bool,
    business_criticality: float = 1.0,
) -> Tuple[float, str]:
    """
    Computes a Multi-Attribute Utility Score in [0, 100] and assigns a priority tier.

    Formula:
    - If unreachable (reachability_conf == 0.0):
      Utility collapses into the SUPPRESSED_NOISE band (capped at 15.0) regardless of CVSS.
    - If reachable (reachability_conf > 0.0):
      BaseThreat = 0.45 * EPSS + 0.35 * (CVSS / 10.0) + 0.20 * I(KEV)
      Utility = min(100.0, BaseThreat * reachability_conf * business_criticality * 100)
    """
    # Clamp inputs safely
    reachability_conf = max(0.0, min(1.0, reachability_conf))
    epss_score = max(0.0, min(1.0, epss_score))
    normalized_cvss = max(0.0, min(10.0, cvss_score)) / 10.0
    kev_indicator = 1.0 if is_in_kev else 0.0

    if reachability_conf == 0.0:
        residual_risk = (0.60 * epss_score) + (0.40 * normalized_cvss)
        score = round(residual_risk * 15.0, 2)
        return score, "SUPPRESSED_NOISE"

    weighted_threat = (
        (0.45 * epss_score)
        + (0.35 * normalized_cvss)
        + (0.20 * kev_indicator)
    )
    raw_utility = weighted_threat * reachability_conf * business_criticality * 100.0
    final_score = round(min(100.0, raw_utility), 2)

    if final_score >= 60.0:
        tier = "CRITICAL_ACTION"
    elif final_score >= 30.0:
        tier = "MONITOR"
    else:
        tier = "LOW_RISK"

    return final_score, tier