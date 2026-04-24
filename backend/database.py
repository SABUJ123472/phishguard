import os
import logging
import datetime
import threading
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError

log = logging.getLogger(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "")

_client = None
_db     = None
_lock   = threading.Lock()

def get_db():
    global _client, _db
    if _db is not None:
        return _db
    with _lock:
        if _db is not None:
            return _db
        if not MONGO_URI:
            log.warning("MONGO_URI not set — DB features disabled")
            return None
        try:
            _client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=10000,
                maxPoolSize=10,
                retryWrites=True,
            )
            _client.admin.command("ping")
            _db = _client["phishguard"]
            _db.scans.create_index([("time", DESCENDING)], background=True)
            _db.scans.create_index([("verdict", 1)],        background=True)
            _db.scans.create_index([("url", 1)],            background=True)
            log.info("MongoDB connected")
            return _db
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            log.error("MongoDB connection failed: %s", e)
            return None

def _to_iso(doc: dict) -> dict:
    if isinstance(doc.get("time"), datetime.datetime):
        doc["time"] = doc["time"].isoformat()
    return doc

def save_scan(result: dict):
    db = get_db()
    if db is None:
        return
    try:
        doc = {**result}
        if isinstance(doc.get("time"), str):
            try:
                doc["time"] = datetime.datetime.fromisoformat(
                    doc["time"].replace("Z", "+00:00")
                )
            except Exception:
                doc["time"] = datetime.datetime.now(datetime.UTC)
        db.scans.insert_one(doc)
    except PyMongoError as e:
        log.error("save_scan failed: %s", e)

def get_recent_scans(limit: int = 20) -> list:
    db = get_db()
    if db is None:
        return []
    try:
        return [
            _to_iso(doc)
            for doc in db.scans.find({}, {"_id": 0})
                               .sort("time", DESCENDING)
                               .limit(limit)
        ]
    except PyMongoError as e:
        log.error("get_recent_scans failed: %s", e)
        return []

def get_stats() -> dict:
    db = get_db()
    if db is None:
        return {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
    try:
        pipeline = [{"$group": {"_id": "$verdict", "count": {"$sum": 1}}}]
        stats = {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
        for r in db.scans.aggregate(pipeline):
            v = (r["_id"] or "").upper()
            stats["total"] += r["count"]
            if v == "PHISHING":   stats["phishing"]   = r["count"]
            elif v == "SUSPICIOUS": stats["suspicious"] = r["count"]
            elif v == "SAFE":       stats["safe"]       = r["count"]
        return stats
    except PyMongoError as e:
        log.error("get_stats failed: %s", e)
        return {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}

def search_scans(url_query: str, limit: int = 20) -> list:
    db = get_db()
    if db is None:
        return []
    try:
        # Escape regex special chars to prevent ReDoS
        escaped = re.escape(url_query)
        return [
            _to_iso(doc)
            for doc in db.scans.find(
                {"url": {"$regex": escaped, "$options": "i"}},
                {"_id": 0}
            ).sort("time", DESCENDING).limit(limit)
        ]
    except PyMongoError as e:
        log.error("search_scans failed: %s", e)
        return []

def is_connected() -> bool:
    return get_db() is not None

import re  # needed for search_scans regex escaping
