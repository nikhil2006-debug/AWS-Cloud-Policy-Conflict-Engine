"""Local JSON-file database. Same interface (put / get / list) that the DynamoDB version
will have later, so swapping it is a one-line change in get_store()."""
import json
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "conflicts.json"


class LocalStore:
    mode = "local-json"
    error = None

    def __init__(self, path=DATA_FILE):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}", encoding="utf-8")

    def _read(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data):
        self.path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def put(self, item):
        data = self._read()
        data[item["conflict_id"]] = item
        self._write(data)

    def get(self, conflict_id):
        return self._read().get(conflict_id)

    def list(self):
        return sorted(self._read().values(), key=lambda i: i.get("risk_score", 0), reverse=True)


_store = None


def get_store():
    global _store
    if _store is None:
        _store = LocalStore()      # later: _store = DynamoStore()
    return _store