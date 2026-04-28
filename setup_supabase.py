"""
setup_supabase.py  –  One-time table creation for SnortIDS
Run once: python setup_supabase.py
"""
import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

url = os.environ["SUPABASE_URL"]
key = os.environ["SUPABASE_KEY"]
sb  = create_client(url, key)

SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    target      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    rule        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    target          TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    result_summary  TEXT NOT NULL,
    alert_count     INTEGER DEFAULT 0
);

ALTER TABLE alerts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='alerts' AND policyname='allow_all_alerts') THEN
    CREATE POLICY allow_all_alerts    ON alerts    FOR ALL USING (true) WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='scan_logs' AND policyname='allow_all_scan_logs') THEN
    CREATE POLICY allow_all_scan_logs ON scan_logs FOR ALL USING (true) WITH CHECK (true);
  END IF;
END $$;
"""

try:
    result = sb.rpc("exec_sql", {"query": SQL}).execute()
    print("Tables created via RPC.")
except Exception as e:
    # exec_sql RPC may not exist; try a simple test insert instead
    print(f"RPC not available ({e}). Verifying connection with a test query...")

# Verify connection by reading from tables (they must already exist)
try:
    r1 = sb.table("alerts").select("id", count="exact").limit(1).execute()
    r2 = sb.table("scan_logs").select("id", count="exact").limit(1).execute()
    print(f"✅ Connected to Supabase successfully!")
    print(f"   alerts table    – {r1.count} existing rows")
    print(f"   scan_logs table – {r2.count} existing rows")
except Exception as e:
    print(f"❌ Table access failed: {e}")
    print()
    print("Please run supabase_schema.sql manually in your Supabase SQL editor:")
    print("  https://supabase.com/dashboard/project/hfyuinbxvawvspjmpfta/sql/new")
