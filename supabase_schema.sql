-- SnortIDS – Supabase Schema
-- Run this once in your Supabase SQL Editor:
-- https://supabase.com/dashboard/project/hfyuinbxvawvspjmpfta/sql

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    target      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    rule        TEXT NOT NULL
);

-- Scan logs table
CREATE TABLE IF NOT EXISTS scan_logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    target          TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    result_summary  TEXT NOT NULL,
    alert_count     INTEGER DEFAULT 0
);

-- Allow public read/write (no auth required for this local tool)
ALTER TABLE alerts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "allow_all_alerts"    ON alerts    FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "allow_all_scan_logs" ON scan_logs FOR ALL USING (true) WITH CHECK (true);
