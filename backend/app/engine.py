from datetime import datetime, timezone

from app.mock_aws.loader import discover          # later: from app.discovery.resource_discovery import discover
from app.parser.policy_parser import normalize_policy, normalize_bucket_policy
from app.graph.cpdg import CPDG
from app.detection.conflict_detector import detect_conflicts
from app.risk.risk_engine import compute_risk, activity_count
from app.resolution.mira import run_mira


def analyze(discovered):
    """Pure pipeline: discovered AWS data -> findings. Works with mock or real AWS data."""
    statements, docs, unsupported, policy_count = [], {}, 0, 0

    # 1) PARSER
    for role in discovered["roles"]:
        for pol in role["policies"]:
            policy_count += 1
            docs[f'{role["name"]}|{pol["name"]}'] = pol["document"]
            st, un = normalize_policy(role["name"], pol["name"], pol["document"],
                                      pol.get("arn"), pol.get("attached_to_count", 1))
            statements += st
            unsupported += un
    for b in discovered["buckets"]:
        if b.get("policy"):
            policy_count += 1
            docs[f'{b["name"]}|bucket-policy:{b["name"]}'] = b["policy"]
            st, un = normalize_bucket_policy(b["name"], b["policy"])
            statements += st
            unsupported += un

    # 2) CPDG + 3) CONFLICT DETECTION
    graph = CPDG().build(statements)
    conflicts = detect_conflicts(statements)
    for c in conflicts:
        graph.add_conflict_edge(c["allow"]["statement_id"], c["deny"]["statement_id"])

    # 4) RISK + 5) MIRA
    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for c in conflicts:
        usage = activity_count(discovered.get("events", []), c["principal"])
        deps = graph.principals_with_access(graph.resource_node_id(c["overlaps"][0]["allow_resource"]))
        risk = compute_risk(c, usage, deps)
        mira = run_mira(c, statements, risk["components"]["usage"])
        rec = mira["recommended"]
        findings.append({
            **c, **risk,
            "resource_name": CPDG.resource_node_id(c["overlaps"][0]["deny_resource"]).split(":", 1)[1],
            "usage_events": usage,
            "mira": mira,
            "recommendation": rec["description"] if rec else "No feasible automatic resolution - manual review required",
            "impact_score": rec["impact_score"] if rec else None,
            "reason": (f"Lowest impact ({rec['impact_score']}/100) among feasible candidates; "
                       f"security exposure within limit.") if rec else "All candidates weaken security.",
            "graph": graph.subgraph(c),
            "source_documents": {k: docs[k] for k in (c["allow"]["source_key"], c["deny"]["source_key"]) if k in docs},
            "status": "DETECTED",
            "timestamp": now,
            "history": [],
        })

    summary = {
        "scanned_at": now,
        "roles": len(discovered["roles"]),
        "buckets": len(discovered["buckets"]),
        "resources_discovered": len(discovered["roles"]) + len(discovered["buckets"]),
        "policies_analyzed": policy_count,
        "statements_analyzed": len(statements),
        "unsupported_statements": unsupported,
        "conflicts_found": len(findings),
        "high_risk": sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL")),
    }
    return findings, summary


def run_scan():
    return analyze(discover())