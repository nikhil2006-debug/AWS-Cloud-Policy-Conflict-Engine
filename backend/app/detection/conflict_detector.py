"""Allow-vs-Deny detector.
AWS semantics: an explicit Deny always overrides an Allow. We report every overlapping
Allow/Deny pair as a *potential* conflict (some are intentional guardrails) and classify:
  FULL    - the Deny completely nullifies the Allow (Allow is dead/shadowed)
  PARTIAL - only part of the Allow's scope is denied, or the Deny is conditional
Known limitation: two partial wildcards like 's3:Get*' vs 's3:*Object' are not detected."""
from fnmatch import fnmatchcase


def _glob(p):
    return p.replace("[", "[[]")


def matches(pattern, value, ci=False):
    if ci:
        pattern, value = pattern.lower(), value.lower()
    return fnmatchcase(value, _glob(pattern))


def pattern_overlap(allow_pat, deny_pat, ci=False):
    """Returns None (disjoint) or (representative, deny_covers_allow)."""
    if matches(deny_pat, allow_pat, ci):      # deny pattern is as broad or broader
        return allow_pat, True
    if matches(allow_pat, deny_pat, ci):      # deny is narrower than allow
        return deny_pat, False
    return None


def _principals_overlap(a, b):
    return a == b or "*" in (a, b)


def _summary(s):
    keys = ("statement_id", "policy_id", "policy_name", "policy_type", "principal", "effect",
            "actions", "resources", "condition", "source_arn", "source_key", "attached_to_count")
    return {k: s[k] for k in keys}


def _covered(a_act, a_res, deny):
    return any(matches(da, a_act, True) and matches(dr, a_res)
               for da in deny["actions"] for dr in deny["resources"])


def find_overlaps(allow, deny):
    overlaps = []
    for aa in allow["actions"]:
        for da in deny["actions"]:
            act = pattern_overlap(aa, da, ci=True)
            if not act:
                continue
            for ar in allow["resources"]:
                for dr in deny["resources"]:
                    res = pattern_overlap(ar, dr)
                    if res:
                        overlaps.append({
                            "action": act[0], "resource": res[0],
                            "allow_action": aa, "deny_action": da,
                            "allow_resource": ar, "deny_resource": dr,
                            "deny_covers": act[1] and res[1],
                        })
    return overlaps


def detect_conflicts(statements):
    allows = [s for s in statements if s["effect"] == "Allow"]
    denies = [s for s in statements if s["effect"] == "Deny"]
    conflicts = []
    for a in allows:
        for d in denies:
            if not _principals_overlap(a["principal"], d["principal"]):
                continue
            overlaps = find_overlaps(a, d)
            if not overlaps:
                continue
            cid = f"CONFLICT-{len(conflicts) + 1:03d}"
            full = (not d["condition"]) and all(
                _covered(x, y, d) for x in a["actions"] for y in a["resources"])
            first = overlaps[0]
            more = f" (+{len(overlaps) - 1} more)" if len(overlaps) > 1 else ""
            conflicts.append({
                "conflict_id": cid,
                "type": "ALLOW_DENY",
                "principal": a["principal"] if a["principal"] != "*" else d["principal"],
                "action": first["action"] + more,
                "resource": first["resource"],
                "coverage": "FULL" if full else "PARTIAL",
                "conditional": bool(d["condition"] or a["condition"]),
                "overlaps": overlaps,
                "allow": _summary(a),
                "deny": _summary(d),
            })
    return conflicts