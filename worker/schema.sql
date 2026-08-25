-- ============================================================
--  שיבוץ מקומות — סכימת מסד הנתונים (Cloudflare D1 / SQLite)
--  כל "בית כנסת" הוא יחידה נפרדת. משתמש שייך לבית כנסת אחד.
-- ============================================================

CREATE TABLE IF NOT EXISTS shuls (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  created_by  TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL DEFAULT '',
  pw            TEXT NOT NULL,              -- pbkdf2$<iterations>$<salt>$<hash>
  shul_id       TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'gabbai',   -- owner | gabbai
  can_edit      INTEGER NOT NULL DEFAULT 1,
  is_super      INTEGER NOT NULL DEFAULT 0,       -- מנהל-על (רואה הכל)
  must_change   INTEGER NOT NULL DEFAULT 0,       -- חייב להחליף סיסמה בכניסה
  status        TEXT NOT NULL DEFAULT 'active',   -- active | blocked
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_shul ON users(shul_id);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,              -- SHA-256 של הטוקן, לא הטוקן עצמו
  user_id    TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS charts (
  shul_id    TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  rev        INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  updated_by TEXT
);

CREATE TABLE IF NOT EXISTS chart_history (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  shul_id    TEXT NOT NULL,
  rev        INTEGER NOT NULL,
  taken      INTEGER NOT NULL DEFAULT 0,
  data       TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_hist ON chart_history(shul_id, id DESC);

CREATE TABLE IF NOT EXISTS invites (
  code       TEXT PRIMARY KEY,
  shul_id    TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_shul ON invites(shul_id);

-- הגנה מפני ניחוש סיסמאות
CREATE TABLE IF NOT EXISTS login_attempts (
  email     TEXT PRIMARY KEY,
  fails     INTEGER NOT NULL DEFAULT 0,
  last_fail TEXT
);
