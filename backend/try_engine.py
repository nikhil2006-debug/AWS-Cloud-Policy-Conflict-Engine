import json
from app.engine import run_scan

findings, summary = run_scan()
print(json.dumps(summary, indent=2))
for f in findings:
    print(f["conflict_id"], f["severity"], "risk =", f["risk_score"])
    print("components:", f["components"])
    for c in f["mira"]["candidates"]:
        print("  ", c["id"], c["strategy"], c["impact_score"], "feasible" if c["feasible"] else "REJECTED")
    print("Recommended:", f["mira"]["recommended"]["strategy"], "| impact", f["impact_score"])
    print("Reason:", f["reason"])