from app.mock_aws.loader import discover
from app.parser.policy_parser import normalize_policy
from app.detection.conflict_detector import detect_conflicts

data = discover()
statements = []
for role in data["roles"]:
    for pol in role["policies"]:
        stmts, _ = normalize_policy(role["name"], pol["name"], pol["document"], pol["arn"], pol["attached_to_count"])
        statements += stmts

conflicts = detect_conflicts(statements)
print("Conflicts found:", len(conflicts))
for c in conflicts:
    print(c["conflict_id"], c["type"], c["principal"], c["action"], c["resource"], c["coverage"])
    print("  ALLOW:", c["allow"]["policy_id"], "| DENY:", c["deny"]["policy_id"])