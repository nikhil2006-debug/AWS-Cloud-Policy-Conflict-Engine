from app.parser.policy_parser import normalize_policy
from app.detection.conflict_detector import detect_conflicts
from app.engine import analyze


def pol(effect, action, resource, sid="S", condition=None):
    stmt = {"Sid": sid, "Effect": effect, "Action": action, "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def stmts(*pairs, role="Role1"):
    out = []
    for name, doc in pairs:
        s, _ = normalize_policy(role, name, doc)
        out += s
    return out


B = "arn:aws:s3:::demo-bucket/*"


def test_allow_allow_no_conflict():
    assert detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", B)), ("B", pol("Allow", "s3:GetObject", B)))) == []


def test_deny_deny_no_conflict():
    assert detect_conflicts(stmts(("A", pol("Deny", "s3:GetObject", B)), ("B", pol("Deny", "s3:GetObject", B)))) == []


def test_allow_deny_exact_is_full_conflict():
    c = detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", B, "AllowS3Read")),
                               ("D", pol("Deny", "s3:GetObject", B, "DenyS3Read"))))
    assert len(c) == 1 and c[0]["coverage"] == "FULL" and c[0]["type"] == "ALLOW_DENY"


def test_different_actions_no_conflict():
    assert detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", B)), ("D", pol("Deny", "s3:DeleteObject", B)))) == []


def test_wildcard_allow_vs_specific_deny_is_partial():
    c = detect_conflicts(stmts(("A", pol("Allow", "s3:*", B)), ("D", pol("Deny", "s3:GetObject", B))))
    assert len(c) == 1 and c[0]["coverage"] == "PARTIAL"


def test_specific_allow_vs_wildcard_deny_is_full():
    c = detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", B)), ("D", pol("Deny", "s3:*", B))))
    assert c[0]["coverage"] == "FULL"


def test_partial_resource_overlap():
    c = detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", "arn:aws:s3:::b/*")),
                               ("D", pol("Deny", "s3:GetObject", "arn:aws:s3:::b/private/*"))))
    assert len(c) == 1 and c[0]["coverage"] == "PARTIAL"


def test_disjoint_resources_no_conflict():
    assert detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", "arn:aws:s3:::a/*")),
                                  ("D", pol("Deny", "s3:GetObject", "arn:aws:s3:::b/*")))) == []


def test_action_case_insensitive():
    assert len(detect_conflicts(stmts(("A", pol("Allow", "S3:getobject", B)), ("D", pol("Deny", "s3:GetObject", B))))) == 1


def test_conditional_deny_is_partial():
    c = detect_conflicts(stmts(("A", pol("Allow", "s3:GetObject", B)),
                               ("D", pol("Deny", "s3:GetObject", B, condition={"Bool": {"aws:SecureTransport": "false"}}))))
    assert c[0]["coverage"] == "PARTIAL" and c[0]["conditional"]


def test_different_principals_no_conflict():
    s = stmts(("A", pol("Allow", "s3:GetObject", B)), role="R1") + stmts(("D", pol("Deny", "s3:GetObject", B)), role="R2")
    assert detect_conflicts(s) == []


def test_multiple_statements_and_lists():
    doc = {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": [B]},
        {"Effect": "Deny", "Action": ["s3:PutObject"], "Resource": B}]}
    c = detect_conflicts(stmts(("Mixed", doc)))
    assert len(c) == 1 and c[0]["action"].lower() == "s3:putobject"


def test_full_pipeline_risk_and_mira():
    discovered = {"roles": [{"name": "CloudPolicyDemoRole", "policies": [
        {"name": "AllowS3Read", "arn": "arn:x:allow", "document": pol("Allow", "s3:GetObject", B, "AllowS3Read"), "attached_to_count": 1},
        {"name": "DenyS3Read", "arn": "arn:x:deny", "document": pol("Deny", "s3:GetObject", B, "DenyS3Read"), "attached_to_count": 1}]}],
        "buckets": [], "events": []}
    findings, summary = analyze(discovered)
    f = findings[0]
    assert summary["conflicts_found"] == 1
    assert 0 <= f["risk_score"] <= 100 and f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    rec = f["mira"]["recommended"]
    assert rec["feasible"] and rec["strategy"] != "REMOVE_DENY"          # security constraint respected
    assert rec["impact_score"] == min(c["impact_score"] for c in f["mira"]["candidates"] if c["feasible"])
    assert any(e["relation"] == "CONFLICTS_WITH" for e in f["graph"]["edges"])