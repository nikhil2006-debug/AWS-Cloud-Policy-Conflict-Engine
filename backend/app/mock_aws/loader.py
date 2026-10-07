"""Mock AWS. discover() returns the SAME shape the real boto3 discovery will return later,
so replacing mock with real AWS is a one-line change in engine.py."""
import json
from pathlib import Path

HERE = Path(__file__).parent


def _load(name):
    with open(HERE / name, encoding="utf-8") as f:
        return json.load(f)


def discover():
    roles = _load("iam_roles.json")
    policy_files = [_load("allow_policy.json"), _load("deny_policy.json")]
    by_name = {p["PolicyName"]: p for p in policy_files}

    for role in roles:
        role["policies"] = []
        for pname in role.pop("attached_policies"):
            p = by_name[pname]
            role["policies"].append({
                "name": p["PolicyName"],
                "arn": p["Arn"],
                "kind": "managed",
                "document": p["Document"],
                "attached_to_count": 1,
            })

    return {
        "roles": roles,
        "buckets": _load("s3_buckets.json"),
        "events": _load("cloudtrail_events.json"),
    }