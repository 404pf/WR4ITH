#!/usr/bin/env python3
"""
WR4ITH - db.py
SQLite backend. Zero setup, no daemon, single file.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wr4ith.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS history (
            sl_no         INTEGER PRIMARY KEY AUTOINCREMENT,
            target        TEXT NOT NULL,
            scan_date     TEXT NOT NULL,
            risk_level    TEXT DEFAULT 'UNKNOWN',
            raw_scan      TEXT,
            full_response TEXT
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no       INTEGER NOT NULL,
            vuln_name   TEXT NOT NULL,
            severity    TEXT DEFAULT 'medium',
            port        TEXT DEFAULT '',
            service     TEXT DEFAULT '',
            description TEXT DEFAULT '',
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS fixes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no    INTEGER NOT NULL,
            vuln_id  INTEGER NOT NULL,
            fix_text TEXT NOT NULL,
            source   TEXT DEFAULT 'ai',
            FOREIGN KEY (sl_no)    REFERENCES history(sl_no)         ON DELETE CASCADE,
            FOREIGN KEY (vuln_id)  REFERENCES vulnerabilities(id)    ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS poc_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER NOT NULL,
            vuln_id      INTEGER NOT NULL,
            status       TEXT DEFAULT 'UNTESTED',
            test_request TEXT DEFAULT '',
            test_response TEXT DEFAULT '',
            evidence     TEXT DEFAULT '',
            tested_at    TEXT DEFAULT '',
            FOREIGN KEY (sl_no)   REFERENCES history(sl_no)        ON DELETE CASCADE,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)   ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS exploits (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER NOT NULL,
            exploit_name TEXT NOT NULL,
            tool_used    TEXT DEFAULT '',
            payload      TEXT DEFAULT '',
            result       TEXT DEFAULT 'unknown',
            notes        TEXT DEFAULT '',
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()


# ── sessions ──────────────────────────────────

def create_session(target: str) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO history (target, scan_date) VALUES (?,?)",
              (target, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    sl_no = c.lastrowid
    conn.commit()
    conn.close()
    return sl_no


def save_summary(sl_no, raw_scan, full_response, risk_level):
    conn = get_connection()
    conn.execute("UPDATE history SET raw_scan=?, full_response=?, risk_level=? WHERE sl_no=?",
                 (raw_scan, full_response, risk_level, sl_no))
    conn.commit()
    conn.close()


def get_all_history():
    conn = get_connection()
    rows = conn.execute(
        "SELECT sl_no, target, scan_date, risk_level FROM history ORDER BY sl_no DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session(sl_no: int) -> dict:
    conn = get_connection()
    h = conn.execute("SELECT * FROM history WHERE sl_no=?", (sl_no,)).fetchone()
    vs = conn.execute("SELECT * FROM vulnerabilities WHERE sl_no=?", (sl_no,)).fetchall()
    fs = conn.execute("SELECT * FROM fixes WHERE sl_no=?", (sl_no,)).fetchall()
    es = conn.execute("SELECT * FROM exploits WHERE sl_no=?", (sl_no,)).fetchall()
    conn.close()
    return {
        "history":         dict(h) if h else {},
        "vulnerabilities": [dict(v) for v in vs],
        "fixes":           [dict(f) for f in fs],
        "exploits":        [dict(e) for e in es],
    }


# ── save ──────────────────────────────────────

def save_vulnerability(sl_no, vuln_name, severity, port, service, description) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO vulnerabilities (sl_no,vuln_name,severity,port,service,description) VALUES (?,?,?,?,?,?)",
              (sl_no, vuln_name, severity, port, service, description))
    vid = c.lastrowid
    conn.commit()
    conn.close()
    return vid


def save_fix(sl_no, vuln_id, fix_text, source="ai"):
    conn = get_connection()
    conn.execute("INSERT INTO fixes (sl_no,vuln_id,fix_text,source) VALUES (?,?,?,?)",
                 (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    conn.execute("INSERT INTO exploits (sl_no,exploit_name,tool_used,payload,result,notes) VALUES (?,?,?,?,?,?)",
                 (sl_no, exploit_name, tool_used, payload, result, notes))
    conn.commit()
    conn.close()


# ── edit ──────────────────────────────────────

def edit_vulnerability(vid, field, value):
    if field not in {"vuln_name","severity","port","service","description"}:
        print(f"  [!] Invalid field: {field}"); return
    conn = get_connection()
    conn.execute(f"UPDATE vulnerabilities SET {field}=? WHERE id=?", (value, vid))
    conn.commit(); conn.close()
    print(f"  [+] Updated vuln #{vid}")

def edit_fix(fid, new_text):
    conn = get_connection()
    conn.execute("UPDATE fixes SET fix_text=? WHERE id=?", (new_text, fid))
    conn.commit(); conn.close()
    print(f"  [+] Updated fix #{fid}")

def edit_exploit(eid, field, value):
    if field not in {"exploit_name","tool_used","payload","result","notes"}:
        print(f"  [!] Invalid field: {field}"); return
    conn = get_connection()
    conn.execute(f"UPDATE exploits SET {field}=? WHERE id=?", (value, eid))
    conn.commit(); conn.close()
    print(f"  [+] Updated exploit #{eid}")

def edit_summary_risk(sl_no, risk):
    conn = get_connection()
    conn.execute("UPDATE history SET risk_level=? WHERE sl_no=?", (risk, sl_no))
    conn.commit(); conn.close()
    print(f"  [+] Risk updated to {risk}")


# ── delete ────────────────────────────────────

def delete_vulnerability(vid):
    conn = get_connection()
    conn.execute("DELETE FROM fixes WHERE vuln_id=?", (vid,))
    conn.execute("DELETE FROM vulnerabilities WHERE id=?", (vid,))
    conn.commit(); conn.close()
    print(f"  [+] Deleted vuln #{vid}")

def delete_fix(fid):
    conn = get_connection()
    conn.execute("DELETE FROM fixes WHERE id=?", (fid,))
    conn.commit(); conn.close()
    print(f"  [+] Deleted fix #{fid}")

def delete_exploit(eid):
    conn = get_connection()
    conn.execute("DELETE FROM exploits WHERE id=?", (eid,))
    conn.commit(); conn.close()
    print(f"  [+] Deleted exploit #{eid}")

def delete_full_session(sl_no):
    conn = get_connection()
    conn.execute("DELETE FROM history WHERE sl_no=?", (sl_no,))
    conn.commit(); conn.close()
    print(f"  [+] Session #{sl_no} wiped.")


# ── getters for menus ─────────────────────────

def get_vulnerabilities(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT id,sl_no,vuln_name,severity,port,service,description FROM vulnerabilities WHERE sl_no=?", (sl_no,)).fetchall()
    conn.close()
    return [tuple(r) for r in rows]

def get_fixes(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT id,sl_no,vuln_id,fix_text,source FROM fixes WHERE sl_no=?", (sl_no,)).fetchall()
    conn.close()
    return [tuple(r) for r in rows]

def get_exploits(sl_no):
    conn = get_connection()
    rows = conn.execute("SELECT id,sl_no,exploit_name,tool_used,payload,result,notes FROM exploits WHERE sl_no=?", (sl_no,)).fetchall()
    conn.close()
    return [tuple(r) for r in rows]


# ── poc results ──────────────────────────────

def save_poc_result(sl_no, vuln_id, status, test_request, test_response, evidence):
    from datetime import datetime
    conn = get_connection()
    # upsert — replace existing result for same vuln
    conn.execute(
        "DELETE FROM poc_results WHERE vuln_id=?", (vuln_id,)
    )
    conn.execute(
        "INSERT INTO poc_results (sl_no,vuln_id,status,test_request,test_response,evidence,tested_at) VALUES (?,?,?,?,?,?,?)",
        (sl_no, vuln_id, status, test_request, test_response, evidence,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_poc_results(sl_no):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id,sl_no,vuln_id,status,test_request,test_response,evidence,tested_at FROM poc_results WHERE sl_no=?",
        (sl_no,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_poc_result_for_vuln(vuln_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM poc_results WHERE vuln_id=?", (vuln_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ── print helpers ─────────────────────────────

RISK_COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[91m",
    "MEDIUM":   "\033[93m", "LOW":  "\033[92m",
    "UNKNOWN":  "\033[90m",
}

def risk_color(level):
    return RISK_COLORS.get(str(level).upper(), "\033[0m")

def print_history(rows):
    print(f"\n  {'#':<6} {'TARGET':<40} {'DATE':<22} RISK")
    print(f"  {'─'*6} {'─'*40} {'─'*22} {'─'*10}")
    for r in rows:
        rc = risk_color(r['risk_level'])
        print(f"  {r['sl_no']:<6} {r['target']:<40} {r['scan_date']:<22} {rc}{r['risk_level']}\033[0m")
    print()

def print_session(data):
    if not data["history"]: print("  [!] Not found."); return
    h = data["history"]
    rc = risk_color(h.get("risk_level","UNKNOWN"))
    print(f"\n\033[33m{'─'*20} SESSION #{h['sl_no']} {'─'*20}\033[0m")
    print(f"  Target : {h['target']}")
    print(f"  Date   : {h['scan_date']}")
    print(f"  Risk   : {rc}{h.get('risk_level','UNKNOWN')}\033[0m")

    if data["vulnerabilities"]:
        print(f"\n  \033[91m[ VULNERABILITIES ]\033[0m")
        for v in data["vulnerabilities"]:
            fixes = [f for f in data["fixes"] if f["vuln_id"] == v["id"]]
            rc2 = risk_color(v["severity"])
            print(f"  ├─ [{rc2}{v['severity'].upper()}\033[0m] {v['vuln_name']}")
            if v["port"]:      print(f"  │   Port: {v['port']} | Service: {v['service']}")
            if v["description"]: print(f"  │   {v['description']}")
            for fix in fixes:  print(f"  │   \033[92mFIX:\033[0m {fix['fix_text']}")
            print("  │")

    if data["exploits"]:
        print(f"\n  \033[93m[ EXPLOITS ]\033[0m")
        for e in data["exploits"]:
            print(f"  ├─ {e['exploit_name']} | Tool: {e['tool_used']}")
            if e["payload"]: print(f"  │   Payload: {e['payload']}")
            if e["notes"]:   print(f"  │   Notes:   {e['notes']}")
            print("  │")
    print()
