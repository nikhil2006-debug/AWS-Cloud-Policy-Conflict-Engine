"""Policy normalization: every statement -> one common structure."""


def _as_list(v):
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _statements(document):
    stmts = document.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else list(stmts)


def _principal_name(p: str) -> str:
    if p == "*":
        return "*"
    if ":role/" in p:
        return p.split("/")[-1]
    return p


def _bucket_principals(principal):
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        out = []
        for v in principal.values():
            out.extend(_as_list(v))
        return [_principal_name(p) for p in out]
    return [_principal_name(str(principal))]


def _make(owner, principal, policy_name, policy_type, idx, stmt, source_arn, attached):
    sid = stmt.get("Sid")
    return {
        "statement_id": f"{principal}|{policy_name}|{idx}",
        "policy_id": sid or f"{policy_name}#{idx}",
        "policy_name": policy_name,
        "policy_type": policy_type,
        "principal": principal,
        "effect": stmt["Effect"],
        "actions": _as_list(stmt.get("Action")),
        "resources": _as_list(stmt.get("Resource")),
        "condition": stmt.get("Condition") or None,
        "source_arn": source_arn,
        "source_key": f"{owner}|{policy_name}",
        "attached_to_count": attached,
    }


def normalize_policy(role_name, policy_name, document, source_arn=None, attached_to_count=1):
    """IAM identity policy attached to a role. Returns (statements, unsupported_count)."""
    out, unsupported = [], 0
    for idx, stmt in enumerate(_statements(document)):
        if "NotAction" in stmt or "NotResource" in stmt:
            unsupported += 1  # documented limitation of the MVP
            continue
        out.append(_make(role_name, role_name, policy_name, "IAM", idx, stmt, source_arn, attached_to_count))
    return out, unsupported


def normalize_bucket_policy(bucket, document):
    """S3 resource policy; one normalized statement per principal."""
    out, unsupported = [], 0
    name = f"bucket-policy:{bucket}"
    for idx, stmt in enumerate(_statements(document)):
        if "NotAction" in stmt or "NotResource" in stmt or "NotPrincipal" in stmt:
            unsupported += 1
            continue
        for p in _bucket_principals(stmt.get("Principal", "*")):
            out.append(_make(bucket, p, name, "S3_BUCKET", idx, stmt, None, 1))
    return out, unsupported