"""
database.py  –  SnortIDS  Supabase backend
Replaces the local SQLite implementation with Supabase (PostgreSQL).

Drop-in replacement: all function signatures are identical to the
original SQLite version so app.py requires zero changes.
"""

import os
from datetime import datetime

from dotenv import load_dotenv
from supabase import create_client, Client

# ── Bootstrap ──────────────────────────────────────────────────
load_dotenv()  # reads .env from project root

_client = None

def _db() -> Client:
    """Return the shared Supabase client (lazy-loaded)."""
    global _client
    if _client is not None:
        return _client
        
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError(
            "Supabase credentials missing. "
            "In production (Vercel), add SUPABASE_URL and SUPABASE_KEY to your Environment Variables."
        )

    _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client



# ── Compatibility stub ─────────────────────────────────────────
def init_db():
    """
    No-op: tables are created via supabase_schema.sql.
    Kept so app.py (which calls init_db()) works unchanged.
    """
    pass


# ── Inserts ────────────────────────────────────────────────────
def insert_alert(target: str, severity: str, message: str, rule: str):
    _db().table("alerts").insert({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target":    target,
        "severity":  severity,
        "message":   message,
        "rule":      rule,
    }).execute()


def insert_scan_log(target: str, scan_type: str,
                    result_summary: str, alert_count: int = 0):
    _db().table("scan_logs").insert({
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target":         target,
        "scan_type":      scan_type,
        "result_summary": result_summary,
        "alert_count":    alert_count,
    }).execute()


# ── Reads ──────────────────────────────────────────────────────
def get_alerts(limit: int = 100) -> list[dict]:
    resp = (
        _db().table("alerts")
        .select("*")
        .order("id", desc=True)
        .limit(limit)
        .execute()
    )
    return resp.data or []


def get_scan_logs(limit: int = 100) -> list[dict]:
    resp = (
        _db().table("scan_logs")
        .select("*")
        .order("id", desc=True)
        .limit(limit)
        .execute()
    )
    return resp.data or []


# ── Delete ─────────────────────────────────────────────────────
def clear_alerts():
    # Delete all rows – Supabase requires a WHERE clause,
    # so we filter on id > 0 (always true).
    _db().table("alerts").delete().gt("id", 0).execute()


# ── Stats ──────────────────────────────────────────────────────
def get_stats() -> dict:
    total_alerts = (
        _db().table("alerts").select("id", count="exact").execute().count or 0
    )
    total_scans = (
        _db().table("scan_logs").select("id", count="exact").execute().count or 0
    )
    critical = (
        _db().table("alerts")
        .select("id", count="exact")
        .eq("severity", "Critical")
        .execute()
        .count or 0
    )
    return {
        "total_alerts":   total_alerts,
        "total_scans":    total_scans,
        "critical_alerts": critical,
    }
