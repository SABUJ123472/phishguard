import os
import logging
import datetime
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

log = logging.getLogger(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "")  # Set in .env or Render env vars

_client = None
_db = None

def get_db():
    global _client, _db
    if _db is not None:
        return _db
    if not MONGO_URI:
        log.warning("MONGO_URI not set — database features disabled.")
        return None
    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _client.admin.command("ping")
        _db = _client["phishguard"]
        # Indexes for fast queries
        _db.scans.create_index([("time", DESCENDING)])
        _db.scans.create_index([("verdict", 1)])
        _db.scans.create_index([("url", 1)])
        log.info("MongoDB connected — database: phishguard")
        return _db
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        log.error("MongoDB connection failed: %s", e)
        return None


def save_scan(result: dict):
    """Save a scan result to MongoDB."""
    db = get_db()
    if db is None:
        return
    try:
        doc = {**result}
        # Convert time string to datetime object for proper MongoDB storage
        if isinstance(doc.get("time"), str):
            try:
                doc["time"] = datetime.datetime.fromisoformat(doc["time"].replace("Z", "+00:00"))
            except Exception:
                doc["time"] = datetime.datetime.now(datetime.UTC)
        db.scans.insert_one(doc)
    except Exception as e:
        log.error("Failed to save scan: %s", e)


def get_recent_scans(limit: int = 20) -> list:
    """Fetch most recent scans from MongoDB."""
    db = get_db()
    if db is None:
        return []
    try:
        cursor = db.scans.find(
            {}, {"_id": 0}
        ).sort("time", DESCENDING).limit(limit)
        results = []
        for doc in cursor:
            # Convert datetime back to ISO string for JSON response
            if isinstance(doc.get("time"), datetime.datetime):
                doc["time"] = doc["time"].isoformat()
            results.append(doc)
        return results
    except Exception as e:
        log.error("Failed to fetch scans: %s", e)
        return []


def get_stats() -> dict:
    """Return aggregate scan statistics."""
    db = get_db()
    if db is None:
        return {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
    try:
        pipeline = [
            {"$group": {
                "_id": "$verdict",
                "count": {"$sum": 1}
            }}
        ]
        result = list(db.scans.aggregate(pipeline))
        stats = {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
        for r in result:
            verdict = (r["_id"] or "").upper()
            count = r["count"]
            stats["total"] += count
            if verdict == "PHISHING":
                stats["phishing"] = count
            elif verdict == "SUSPICIOUS":
                stats["suspicious"] = count
            elif verdict == "SAFE":
                stats["safe"] = count
        return stats
    except Exception as e:
        log.error("Failed to get stats: %s", e)
        return {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}


def search_scans(url_query: str, limit: int = 20) -> list:
    """Search scans by URL substring."""
    db = get_db()
    if db is None:
        return []
    try:
        cursor = db.scans.find(
            {"url": {"$regex": url_query, "$options": "i"}},
            {"_id": 0}
        ).sort("time", DESCENDING).limit(limit)
        results = []
        for doc in cursor:
            if isinstance(doc.get("time"), datetime.datetime):
                doc["time"] = doc["time"].isoformat()
            results.append(doc)
        return results
    except Exception as e:
        log.error("Failed to search scans: %s", e)
        return []


def is_connected() -> bool:
    return get_db() is not None
