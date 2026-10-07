import os 
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.engine import run_scan
from app.database.local_store import get_store

app = FastAPI(title="Cloud Policy Conflict Engine")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

LAST_SCAN = {}


def _log(item, text):
    item.setdefault("history", []).append({"event": text, "at": datetime.now(timezone.utc).isoformat()})


@app.get("/health")
def health():
    return {"status": "ok", "storage": get_store().mode}


@app.post("/scan")
def scan():
    global LAST_SCAN
    findings, summary = run_scan()
    store = get_store()
    for f in findings:
        old = store.get(f["conflict_id"])
        if old and old.get("status") != "DETECTED":      # keep applied / rolled-back state
            f["status"], f["history"] = old["status"], old.get("history", [])
        store.put(f)
    LAST_SCAN = summary
    return {**summary, "conflicts": [
        {k: f[k] for k in ("conflict_id", "type", "severity", "risk_score", "impact_score", "resource_name")}
        for f in findings]}


@app.get("/resources")
def resources():
    return LAST_SCAN or {"message": "No scan yet - POST /scan first"}


@app.get("/conflicts")
def conflicts():
    return get_store().list()


@app.get("/conflicts/{conflict_id}")
def conflict(conflict_id: str):
    item = get_store().get(conflict_id)
    if not item:
        raise HTTPException(404, "Conflict not found")
    return item


@app.get("/graph/{conflict_id}")
def graph(conflict_id: str):
    return conflict(conflict_id)["graph"]


@app.post("/conflicts/{conflict_id}/apply")
def apply_fix(conflict_id: str):
    """SIMULATED: backs up the original policy documents and marks the fix as applied."""
    item = conflict(conflict_id)
    if item["status"] == "APPLIED_SIMULATED":
        raise HTTPException(400, "Already applied")
    item["backup"] = item["source_documents"]
    item["status"] = "APPLIED_SIMULATED"
    _log(item, "Backup created and fix applied (simulated): " + item["mira"]["recommended"]["strategy"])
    get_store().put(item)
    return item


@app.post("/conflicts/{conflict_id}/rollback")
def rollback(conflict_id: str):
    item = conflict(conflict_id)
    if item["status"] != "APPLIED_SIMULATED":
        raise HTTPException(400, "Nothing to roll back")
    item["status"] = "ROLLED_BACK"
    _log(item, "Original configuration restored from backup")
    get_store().put(item)
    return item


# ---------- serve the React dashboard (keep this block at the very bottom) ----------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")