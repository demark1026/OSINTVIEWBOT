"""SQLite for the scaffold. Same schema ports directly to Postgres."""
import sqlite3, threading, time, json
from .config import DB_PATH

_lock = threading.Lock()
_c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_c.executescript("""
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INT, delta INT,
  reason TEXT, ref TEXT UNIQUE, ts REAL);
CREATE TABLE IF NOT EXISTS usage(user_id INT, ts REAL);
CREATE TABLE IF NOT EXISTS audit(ts REAL, user_id INT, action TEXT, target TEXT);
CREATE TABLE IF NOT EXISTS consent(user_id INT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS optout(target TEXT PRIMARY KEY, ts REAL);
""")

def balance(uid):
    return _c.execute("SELECT COALESCE(SUM(delta),0) FROM ledger WHERE user_id=?", (uid,)).fetchone()[0]

def credit(uid, n, reason, ref):
    """Idempotent: a repeated ref (Telegram charge id) is ignored."""
    with _lock:
        try:
            _c.execute("INSERT INTO ledger(user_id,delta,reason,ref,ts) VALUES(?,?,?,?,?)",
                       (uid, n, reason, ref, time.time()))
            return True
        except sqlite3.IntegrityError:
            return False

def spend(uid, n, reason):
    with _lock:
        _c.execute("BEGIN IMMEDIATE")
        if balance(uid) < n:
            _c.execute("ROLLBACK"); return False
        _c.execute("INSERT INTO ledger(user_id,delta,reason,ts) VALUES(?,?,?,?)",
                   (uid, -n, reason, time.time()))
        _c.execute("COMMIT"); return True

def refund(uid, n, reason):
    credit(uid, n, "refund:" + reason, None)

def rate_ok(uid, limit):
    now = time.time()
    with _lock:
        n = _c.execute("SELECT COUNT(*) FROM usage WHERE user_id=? AND ts>?", (uid, now - 60)).fetchone()[0]
        if n >= limit: return False
        _c.execute("INSERT INTO usage VALUES(?,?)", (uid, now)); return True

def audit(uid, action, target):
    _c.execute("INSERT INTO audit VALUES(?,?,?,?)", (time.time(), uid, action, target))

def has_consent(uid):
    return _c.execute("SELECT 1 FROM consent WHERE user_id=?", (uid,)).fetchone() is not None

def give_consent(uid):
    _c.execute("INSERT OR REPLACE INTO consent VALUES(?,?)", (uid, time.time()))

def opted_out(target):
    return _c.execute("SELECT 1 FROM optout WHERE target=?", (target.lower(),)).fetchone() is not None

def add_optout(target):
    _c.execute("INSERT OR REPLACE INTO optout VALUES(?,?)", (target.lower(), time.time()))
