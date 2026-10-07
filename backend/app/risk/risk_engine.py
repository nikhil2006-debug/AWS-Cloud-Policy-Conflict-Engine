"""Transparent weighted risk score (no ML). Every component is 0-100.
Risk = 0.35*Security + 0.25*Criticality + 0.20*Usage + 0.20*Dependency"""

WEIGHTS = {"security": 0.35, "criticality": 0.25, "usage": 0.20, "dependency": 0.20}
SENSITIVE = ("prod", "private", "secret", "confidential", "finance", "backup", "pii", "customer", "hr")


def level(score):
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def _security(c):
    base = 90 if c["coverage"] == "FULL" else 55
    broad = any(a == "*" or a.endswith(":*") for a in c["allow"]["actions"])
    return min(100, base + (10 if broad else 0))


def _criticality(c):
    res = c["resource"].lower()
    if res in ("*", "arn:aws:s3:::*"):
        return 90
    return 85 if any(k in res for k in SENSITIVE) else 50


def _usage(events):
    if events == 0:
        return 10
    if events <= 5:
        return 40
    if events <= 20:
        return 70
    return 90


def _dependency(principals_with_access):
    return min(100, 25 * max(principals_with_access, 1))


def compute_risk(conflict, usage_events, principals_with_access):
    comp = {
        "security": _security(conflict),
        "criticality": _criticality(conflict),
        "usage": _usage(usage_events),
        "dependency": _dependency(principals_with_access),
    }
    score = round(sum(WEIGHTS[k] * v for k, v in comp.items()))
    return {"risk_score": score, "severity": level(score), "components": comp, "weights": WEIGHTS}


def activity_count(events, principal):
    """How many recent CloudTrail events mention this principal (used for 'Active Usage')."""
    if principal == "*":
        return len(events)
    return sum(1 for e in events
               if principal in (e.get("CloudTrailEvent") or "") or principal == e.get("Username"))