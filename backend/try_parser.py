import json
from app.mock_aws.loader import discover
from app.parser.policy_parser import normalize_policy

data = discover()
print("Roles:", [r["name"] for r in data["roles"]])
print("Buckets:", [b["name"] for b in data["buckets"]])

statements = []
for role in data["roles"]:
    for pol in role["policies"]:
        stmts, unsupported = normalize_policy(role["name"], pol["name"], pol["document"], pol["arn"], pol["attached_to_count"])
        statements += stmts

print(json.dumps(statements, indent=2))