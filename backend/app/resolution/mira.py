"""MIRA - Minimal Impact Resolution Algorithm.
Impact = affected access paths + dependent resources + service disruption + security exposure
(each term 0-25, total 0-100).  Choose MIN(impact) subject to:
  1. the candidate resolves the conflict, 2. security exposure <= MAX_EXPOSURE."""

MAX_EXPOSURE = 20


def _collateral(stmt, statements):
    """Other statements in the same policy that a policy-level edit could disturb."""
    return sum(1 for s in statements
               if s["source_key"] == stmt["source_key"] and s["statement_id"] != stmt["statement_id"])


def _dep(stmt):
    return min(25, 5 * max(0, stmt["attached_to_count"] - 1))


def _cand(cid, strategy, desc, change, paths, dep, disruption, exposure):
    paths, dep, disruption, exposure = (min(25, max(0, x)) for x in (paths, dep, disruption, exposure))
    return {
        "id": cid, "strategy": strategy, "description": desc, "proposed_change": change,
        "impact_score": paths + dep + disruption + exposure,
        "breakdown": {"access_paths": paths, "dependent_resources": dep,
                      "service_disruption": disruption, "security_exposure": exposure},
        "feasible": exposure <= MAX_EXPOSURE,
    }


def run_mira(conflict, statements, usage_score):
    a, d = conflict["allow"], conflict["deny"]
    res = conflict["resource"]
    uf = round(usage_score / 100 * 10)
    ca, cd = _collateral(a, statements), _collateral(d, statements)

    cands = [
        _cand("A", "REMOVE_ALLOW",
              f"Remove Allow statement '{a['policy_id']}' from policy '{a['policy_name']}'.",
              {"edit": "DELETE_STATEMENT", "policy": a["policy_name"], "statement": a["policy_id"]},
              paths=3 + 3 * ca, dep=_dep(a), disruption=8 + uf, exposure=0),
        _cand("B", "REMOVE_DENY",
              f"Remove Deny statement '{d['policy_id']}' from policy '{d['policy_name']}'.",
              {"edit": "DELETE_STATEMENT", "policy": d["policy_name"], "statement": d["policy_id"]},
              paths=15 + 3 * cd, dep=_dep(d), disruption=2,
              exposure=25 if conflict["coverage"] == "FULL" else 15),
        _cand("C", "NARROW_ALLOW",
              f"Restrict Allow '{a['policy_id']}' so it no longer overlaps the Deny on {res}.",
              {"edit": "MODIFY_STATEMENT", "policy": a["policy_name"], "statement": a["policy_id"],
               "change": f"Limit Resource/Action to exclude '{res}'"},
              paths=4 + 3 * ca, dep=_dep(a), disruption=4 + uf // 2, exposure=0),
    ]
    if not d["condition"]:
        cands.append(_cand(
            "D", "CONDITION_DENY",
            f"Add a Condition to Deny '{d['policy_id']}' (e.g. aws:PrincipalTag / aws:SourceIp) so it only blocks intended callers.",
            {"edit": "ADD_CONDITION", "policy": d["policy_name"], "statement": d["policy_id"]},
            paths=6 + 3 * cd, dep=_dep(d), disruption=2, exposure=8))

    feasible = [c for c in cands if c["feasible"]]
    best = min(feasible, key=lambda c: (c["impact_score"], c["breakdown"]["security_exposure"])) if feasible else None
    return {"candidates": cands, "recommended": best,
            "constraints": {"max_security_exposure": MAX_EXPOSURE, "must_resolve_conflict": True}}