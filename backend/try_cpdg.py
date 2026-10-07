from app.mock_aws.loader import discover
from app.parser.policy_parser import normalize_policy
from app.detection.conflict_detector import detect_conflicts
from app.graph.cpdg import CPDG

data = discover()
statements = []
for role in data["roles"]:
    for pol in role["policies"]:
        stmts, _ = normalize_policy(role["name"], pol["name"], pol["document"], pol["arn"], pol["attached_to_count"])
        statements += stmts

graph = CPDG().build(statements)
conflicts = detect_conflicts(statements)
for c in conflicts:
    graph.add_conflict_edge(c["allow"]["statement_id"], c["deny"]["statement_id"])
    sub = graph.subgraph(c)
    print(c["conflict_id"], "- nodes:")
    for n in sub["nodes"]:
        print("   ", n["type"], "|", n["label"])
    print("edges:")
    for e in sub["edges"]:
        print("   ", graph.nodes[e["source"]]["label"], "--", e["relation"], "->", graph.nodes[e["target"]]["label"])