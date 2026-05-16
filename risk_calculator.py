def calculate_aggregate_risk(local_score, vt_result=None, zap_result=None):
    score = local_score
    if vt_result and vt_result.get("available") and vt_result.get("status") == "completed":
        score += vt_result.get("malicious",  0) * 5
        score += vt_result.get("suspicious", 0) * 2
    if zap_result and zap_result.get("available"):
        rc = zap_result.get("risk_counts", {})
        score += rc.get("High",   0) * 10
        score += rc.get("Medium", 0) * 5
        score += rc.get("Low",    0) * 1
    return min(score, 100)