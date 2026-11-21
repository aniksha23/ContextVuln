"""
Deterministic Multi-Attribute Utility scoring. No LLM, no randomness, no network.

    EPSS signal   = epss_percentile if provided, else epss ** settings.epss_exponent
    weighted      = w_epss*EPSS_signal + w_cvss*(CVSS/10) + w_kev*I(KEV)
    utility       = weighted * reachability_confidence * clamp(business_criticality)  (x100, cap 100)

    Floors (only when reachable):
        CISA-KEV            -> at least kev_floor_score  (CRITICAL_ACTION)
        CVSS >= 9.0         -> at least high_cvss_floor_score (MONITOR)

    Confirmed unreachable -> score capped at suppressed_cap, tier SUPPRESSED_NOISE.
"""
from typing import Optional, Tuple

from app.core.config import Settings, settings as default_settings
from app.core.schemas import ScoreBreakdown, Tier


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def tier_for_score(score: float, cfg: Settings = default_settings) -> str:
    if score >= cfg.tier_critical:
        return Tier.CRITICAL_ACTION.value
    if score >= cfg.tier_monitor:
        return Tier.MONITOR.value
    return Tier.LOW_RISK.value


def explain_utility_score(
    reachability_conf: float,
    epss_score: float,
    cvss_score: float,
    is_in_kev: bool,
    business_criticality: float = 1.0,
    epss_percentile: Optional[float] = None,
    cfg: Settings = default_settings,
) -> Tuple[float, str, ScoreBreakdown]:
    """Same as compute_utility_score but also returns a ScoreBreakdown for the UI."""
    reachability_conf = _clamp(reachability_conf, 0.0, 1.0)
    epss = _clamp(epss_score, 0.0, 1.0)
    cvss_signal = _clamp(cvss_score, 0.0, 10.0) / 10.0
    kev_signal = 1.0 if is_in_kev else 0.0

    if epss_percentile is not None:
        epss_signal = _clamp(epss_percentile, 0.0, 1.0)
    else:
        epss_signal = epss ** cfg.epss_exponent if epss > 0 else 0.0

    bd = ScoreBreakdown(
        epss_signal=round(epss_signal, 4),
        cvss_signal=round(cvss_signal, 4),
        kev_signal=kev_signal,
        reachability_factor=reachability_conf,
    )

    # ---- Confirmed unreachable: collapse into the noise band ----
    if reachability_conf == 0.0:
        residual = 0.60 * epss_signal + 0.40 * cvss_signal
        score = round(residual * cfg.suppressed_cap, 2)
        bd.weighted_threat = round(residual, 4)
        bd.raw_score = score
        bd.notes.append("Unreachable: score capped into the suppressed band.")
        return score, Tier.SUPPRESSED_NOISE.value, bd

    criticality = _clamp(business_criticality, cfg.criticality_min, cfg.criticality_max)
    weighted = (
        cfg.w_epss * epss_signal + cfg.w_cvss * cvss_signal + cfg.w_kev * kev_signal
    )
    raw = min(100.0, weighted * reachability_conf * criticality * 100.0)

    bd.weighted_threat = round(weighted, 4)
    bd.criticality_factor = criticality
    bd.raw_score = round(raw, 2)

    score = raw
    if is_in_kev and score < cfg.kev_floor_score:
        score = cfg.kev_floor_score
        bd.floor_applied = "KEV"
        bd.notes.append("Listed in CISA KEV and reachable: raised to the CRITICAL floor.")
    elif cvss_score >= cfg.high_cvss_threshold and score < cfg.high_cvss_floor_score:
        score = cfg.high_cvss_floor_score
        bd.floor_applied = "HIGH_CVSS"
        bd.notes.append("CVSS >= 9.0 and reachable: never ranked below MONITOR.")

    score = round(min(100.0, score), 2)
    return score, tier_for_score(score, cfg), bd


def compute_utility_score(
    reachability_conf: float,
    epss_score: float,
    cvss_score: float,
    is_in_kev: bool,
    business_criticality: float = 1.0,
    epss_percentile: Optional[float] = None,
    cfg: Settings = default_settings,
) -> Tuple[float, str]:
    """Backward compatible API: returns (score 0-100, tier string)."""
    score, tier, _ = explain_utility_score(
        reachability_conf, epss_score, cvss_score, is_in_kev,
        business_criticality, epss_percentile, cfg,
    )
    return score, tier
