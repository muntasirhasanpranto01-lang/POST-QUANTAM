from __future__ import annotations

import json
from datetime import datetime, timezone
from .db import connect

def now(): return datetime.now(timezone.utc).isoformat()
def audit(event_type, actor, subject_id, details):
    with connect() as conn: conn.execute("INSERT INTO audit_events(event_type,actor,subject_id,details_json,created_at) VALUES(?,?,?,?,?)", (event_type,actor,subject_id,json.dumps(details,sort_keys=True),now()))
def export_jsonl():
    with connect() as conn: rows = conn.execute("SELECT event_type,actor,subject_id,details_json,created_at FROM audit_events ORDER BY id").fetchall()
    return "".join(json.dumps({"event_type":r[0],"actor":r[1],"subject_id":r[2],"details":json.loads(r[3]),"created_at":r[4]},sort_keys=True)+"\n" for r in rows)
