/**
 * שיבוץ מקומות — בית מדרש תפארת יהודה
 * Cloudflare Worker + D1
 *
 * מודל: כל משתמש שנרשם יוצר "בית כנסת" משלו ונעשה בעליו.
 * בעל בית כנסת יכול לצרף גבאים נוספים לאותו בית כנסת (קוד הזמנה).
 * משתמש רואה אך ורק את הנתונים של בית הכנסת שלו.
 * מנהל-על (SUPER_ADMIN_EMAIL) רואה את כולם ויכול להחליף סיסמאות.
 */

const SESSION_DAYS   = 30;
const INVITE_HOURS   = 72;
const HISTORY_KEEP   = 30;
const MAX_FAILS      = 8;
const LOCKOUT_MIN    = 15;
const MAX_CHART_BYTES = 512 * 1024;

/* ============================================================
   עזרים כלליים
   ============================================================ */

const enc = new TextEncoder();

function nowISO() { return new Date().toISOString(); }
function plusDays(n) { return new Date(Date.now() + n * 864e5).toISOString(); }
function plusHours(n) { return new Date(Date.now() + n * 36e5).toISOString(); }

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}
function bad(message, status = 400) { return json({ error: message }, status); }

function uid() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function b64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(str) {
  const raw = atob(str);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ============================================================
   סיסמאות — PBKDF2-SHA256
   מספר החזרות נשמר בתוך ההאש עצמו, כך שניתן להעלות אותו
   בעתיד מבלי לשבור סיסמאות קיימות.
   ============================================================ */

function iterationsOf(env) {
  const n = parseInt(env.PBKDF2_ITERATIONS || '', 10);
  return Number.isFinite(n) && n >= 1000 ? n : 20000;
}

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256);
  return new Uint8Array(bits);
}

async function hashPassword(password, env) {
  const iterations = iterationsOf(env);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, iterations);
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(hash)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [scheme, iter, saltB, hashB] = String(stored).split('$');
    if (scheme !== 'pbkdf2') return false;
    const iterations = parseInt(iter, 10);
    if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 600000) return false;
    const got = await derive(password, unb64(saltB), iterations);
    return sameBytes(got, unb64(hashB));
  } catch { return false; }
}

function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'הסיסמה חייבת להכיל לפחות 8 תווים';
  if (pw.length > 200) return 'הסיסמה ארוכה מדי';
  return null;
}
function normEmail(v) { return String(v || '').trim().toLowerCase(); }
function emailProblem(email) {
  if (!email || email.length > 200) return 'כתובת מייל לא תקינה';
  if (!/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email)) return 'כתובת מייל לא תקינה';
  return null;
}

/* ============================================================
   הפעלות (Sessions)
   ============================================================ */

function cookieValue(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function sessionCookie(token, maxAgeSec) {
  const bits = [
    `sid=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ];
  return bits.join('; ');
}

async function createSession(env, userId) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const id = await sha256hex(token);
  await env.DB.prepare(
    'INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(id, userId, nowISO(), plusDays(SESSION_DAYS)).run();
  return token;
}

async function currentUser(req, env) {
  const token = cookieValue(req, 'sid');
  if (!token) return null;
  const id = await sha256hex(token);
  const row = await env.DB.prepare(
    `SELECT u.*, s.expires_at AS sess_exp, sh.name AS shul_name
       FROM sessions s
       JOIN users u  ON u.id = s.user_id
       JOIN shuls sh ON sh.id = u.shul_id
      WHERE s.id = ?`).bind(id).first();
  if (!row) return null;
  if (new Date(row.sess_exp).getTime() < Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
    return null;
  }
  if (row.status !== 'active') return null;
  row.session_id = id;
  return row;
}

function publicUser(u) {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    canEdit: !!u.can_edit,
    isSuper: !!u.is_super,
    mustChange: !!u.must_change,
    shulId: u.shul_id,
    shulName: u.shul_name,
  };
}

/* ============================================================
   הגנה מפני ניחוש סיסמאות
   ============================================================ */

async function lockedOut(env, email) {
  const row = await env.DB.prepare('SELECT fails, last_fail FROM login_attempts WHERE email = ?')
    .bind(email).first();
  if (!row || row.fails < MAX_FAILS) return 0;
  const since = Date.now() - new Date(row.last_fail).getTime();
  const left = LOCKOUT_MIN * 60000 - since;
  if (left <= 0) {
    await env.DB.prepare('DELETE FROM login_attempts WHERE email = ?').bind(email).run();
    return 0;
  }
  return Math.ceil(left / 60000);
}
async function noteFail(env, email) {
  await env.DB.prepare(
    `INSERT INTO login_attempts (email, fails, last_fail) VALUES (?, 1, ?)
     ON CONFLICT(email) DO UPDATE SET fails = fails + 1, last_fail = excluded.last_fail`)
    .bind(email, nowISO()).run();
}
async function clearFails(env, email) {
  await env.DB.prepare('DELETE FROM login_attempts WHERE email = ?').bind(email).run();
}

/* ============================================================
   מפות
   ============================================================ */

const EMPTY_CHART = '{}';

async function getChart(env, shulId) {
  const row = await env.DB.prepare('SELECT * FROM charts WHERE shul_id = ?').bind(shulId).first();
  if (row) return row;
  await env.DB.prepare(
    'INSERT OR IGNORE INTO charts (shul_id, data, rev, updated_at) VALUES (?, ?, 0, ?)')
    .bind(shulId, EMPTY_CHART, nowISO()).run();
  return { shul_id: shulId, data: EMPTY_CHART, rev: 0, updated_at: nowISO(), updated_by: null };
}

function countTaken(dataStr) {
  try {
    const o = JSON.parse(dataStr);
    let n = 0;
    for (const k in o) {
      const r = o[k];
      if (r && ((r.first || '').trim() || (r.last || '').trim())) n++;
    }
    return n;
  } catch { return 0; }
}

async function writeChart(env, shulId, dataStr, byName) {
  const cur = await getChart(env, shulId);
  const rev = (cur.rev || 0) + 1;
  const at = nowISO();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO charts (shul_id, data, rev, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(shul_id) DO UPDATE SET
         data = excluded.data, rev = excluded.rev,
         updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
      .bind(shulId, dataStr, rev, at, byName),
    env.DB.prepare(
      `INSERT INTO chart_history (shul_id, rev, taken, data, updated_at, updated_by)
       VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(shulId, rev, countTaken(dataStr), dataStr, at, byName),
    env.DB.prepare(
      `DELETE FROM chart_history
        WHERE shul_id = ?
          AND id NOT IN (SELECT id FROM chart_history WHERE shul_id = ? ORDER BY id DESC LIMIT ?)`)
      .bind(shulId, shulId, HISTORY_KEEP),
  ]);
  return { rev, updatedAt: at, updatedBy: byName };
}

/* ============================================================
   יצירת הטבלאות — רצה אוטומטית בפעם הראשונה שה-Worker עולה,
   כדי שלא צריך להריץ שום SQL ידנית בהתקנה.
   ============================================================ */

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS shuls (
     id TEXT PRIMARY KEY, name TEXT NOT NULL,
     created_at TEXT NOT NULL, created_by TEXT)`,
  `CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
     pw TEXT NOT NULL, shul_id TEXT NOT NULL,
     role TEXT NOT NULL DEFAULT 'gabbai', can_edit INTEGER NOT NULL DEFAULT 1,
     is_super INTEGER NOT NULL DEFAULT 0, must_change INTEGER NOT NULL DEFAULT 0,
     status TEXT NOT NULL DEFAULT 'active',
     created_at TEXT NOT NULL, last_login_at TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_users_shul ON users(shul_id)`,
  `CREATE TABLE IF NOT EXISTS sessions (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
     created_at TEXT NOT NULL, expires_at TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)`,
  `CREATE TABLE IF NOT EXISTS charts (
     shul_id TEXT PRIMARY KEY, data TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 0,
     updated_at TEXT, updated_by TEXT)`,
  `CREATE TABLE IF NOT EXISTS chart_history (
     id INTEGER PRIMARY KEY AUTOINCREMENT, shul_id TEXT NOT NULL, rev INTEGER NOT NULL,
     taken INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL,
     updated_at TEXT NOT NULL, updated_by TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_hist ON chart_history(shul_id, id DESC)`,
  `CREATE TABLE IF NOT EXISTS invites (
     code TEXT PRIMARY KEY, shul_id TEXT NOT NULL, created_by TEXT,
     created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_by TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_invites_shul ON invites(shul_id)`,
  `CREATE TABLE IF NOT EXISTS login_attempts (
     email TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, last_fail TEXT)`,
];

/**
 * הטבלאות נוצרות רק אם הן באמת חסרות — לא בכל עלייה של ה-Worker.
 * כך אין 12 שאילתות מיותרות בכל התחלה קרה, וזה קורה בפועל פעם אחת בחיי המערכת.
 */
function isMissingTable(err) {
  return /no such table/i.test(String((err && err.message) || err));
}
async function runWithSchema(request, env, url, ctx) {
  const retry = request.clone();     // הגוף נקרא פעם אחת בלבד — שומרים עותק
  try {
    return await api(request, env, url, ctx);
  } catch (err) {
    if (!isMissingTable(err)) throw err;
    await env.DB.batch(SCHEMA.map((sql) => env.DB.prepare(sql)));
    return await api(retry, env, url, ctx);
  }
}

/* ============================================================
   ניתוב
   ============================================================ */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith('/api/')) {
      // כל השאר — הקובץ הסטטי של האפליקציה
      const res = await env.ASSETS.fetch(request);
      if (res.status === 404) {
        return env.ASSETS.fetch(new Request(new URL('/index.html', url), request));
      }
      return res;
    }

    try {
      return await runWithSchema(request, env, url, ctx);
    } catch (err) {
      console.error('API error', err && err.stack ? err.stack : err);
      return bad('שגיאת שרת פנימית', 500);
    }
  },
};

async function readBody(request) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) throw new Error('bad content type');
  const text = await request.text();
  if (text.length > MAX_CHART_BYTES + 4096) throw new Error('payload too large');
  return JSON.parse(text || '{}');
}

async function api(request, env, url, ctx) {
  const path = url.pathname.replace(/\/+$/, '') || '/api';
  const method = request.method.toUpperCase();

  if (path === '/api/health') return json({ ok: true, time: nowISO() });

  /* ---------------- הרשמה ---------------- */
  if (path === '/api/register' && method === 'POST') {
    const body = await readBody(request);
    const email = normEmail(body.email);
    const eProb = emailProblem(email);
    if (eProb) return bad(eProb);
    const pProb = passwordProblem(body.password);
    if (pProb) return bad(pProb);

    const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (exists) return bad('כתובת המייל כבר רשומה במערכת', 409);

    const name = String(body.name || '').trim().slice(0, 80);
    const invite = String(body.invite || '').trim().toUpperCase();

    let shulId, role, canEdit;
    if (invite) {
      const inv = await env.DB.prepare('SELECT * FROM invites WHERE code = ?').bind(invite).first();
      if (!inv) return bad('קוד ההזמנה אינו קיים');
      if (inv.used_by) return bad('קוד ההזמנה כבר נוצל');
      if (new Date(inv.expires_at).getTime() < Date.now()) return bad('פג תוקפו של קוד ההזמנה');
      shulId = inv.shul_id; role = 'gabbai'; canEdit = 1;
    } else {
      const shulName = String(body.shulName || '').trim().slice(0, 120);
      if (!shulName) return bad('יש להזין את שם בית הכנסת');
      shulId = uid();
      await env.DB.prepare('INSERT INTO shuls (id, name, created_at) VALUES (?, ?, ?)')
        .bind(shulId, shulName, nowISO()).run();
      role = 'owner'; canEdit = 1;
    }

    const superEmail = normEmail(env.SUPER_ADMIN_EMAIL);
    let isSuper = superEmail && email === superEmail ? 1 : 0;
    if (!superEmail) {
      const any = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
      if ((any?.n || 0) === 0) isSuper = 1;   // המשתמש הראשון במערכת
    }

    const id = uid();
    await env.DB.prepare(
      `INSERT INTO users (id, email, name, pw, shul_id, role, can_edit, is_super, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, email, name, await hashPassword(body.password, env), shulId, role, canEdit, isSuper, nowISO())
      .run();

    if (invite) {
      await env.DB.prepare('UPDATE invites SET used_by = ? WHERE code = ?').bind(id, invite).run();
    } else {
      await env.DB.prepare('UPDATE shuls SET created_by = ? WHERE id = ?').bind(id, shulId).run();
      await getChart(env, shulId);
    }

    const token = await createSession(env, id);
    const u = await env.DB.prepare(
      `SELECT u.*, sh.name AS shul_name FROM users u JOIN shuls sh ON sh.id = u.shul_id WHERE u.id = ?`)
      .bind(id).first();
    return json({ user: publicUser(u) }, 200,
      { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
  }

  /* ---------------- כניסה ---------------- */
  if (path === '/api/login' && method === 'POST') {
    const body = await readBody(request);
    const email = normEmail(body.email);
    if (!email || typeof body.password !== 'string') return bad('פרטי כניסה חסרים');

    const wait = await lockedOut(env, email);
    if (wait) return bad(`יותר מדי ניסיונות כושלים. נסה שוב בעוד ${wait} דקות`, 429);

    const u = await env.DB.prepare(
      `SELECT u.*, sh.name AS shul_name FROM users u JOIN shuls sh ON sh.id = u.shul_id WHERE u.email = ?`)
      .bind(email).first();

    const ok = u ? await verifyPassword(body.password, u.pw) : false;
    if (!ok) {
      await noteFail(env, email);
      return bad('מייל או סיסמה שגויים', 401);
    }
    if (u.status !== 'active') return bad('החשבון חסום. פנה למנהל המערכת', 403);

    await clearFails(env, email);
    await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').bind(nowISO(), u.id).run();
    const token = await createSession(env, u.id);
    return json({ user: publicUser(u) }, 200,
      { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
  }

  /* ---------------- יציאה ---------------- */
  if (path === '/api/logout' && method === 'POST') {
    const token = cookieValue(request, 'sid');
    if (token) {
      await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(await sha256hex(token)).run();
    }
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
  }

  /* ---------------- מי אני ---------------- */
  const me = await currentUser(request, env);

  if (path === '/api/me') {
    if (!me) return json({ user: null });
    return json({ user: publicUser(me) });
  }

  if (!me) return bad('נדרשת התחברות', 401);

  /* ---------------- החלפת סיסמה עצמית ---------------- */
  if (path === '/api/password' && method === 'POST') {
    const body = await readBody(request);
    const pProb = passwordProblem(body.next);
    if (pProb) return bad(pProb);
    if (!me.must_change) {
      const ok = await verifyPassword(String(body.current || ''), me.pw);
      if (!ok) return bad('הסיסמה הנוכחית שגויה', 403);
    }
    await env.DB.prepare('UPDATE users SET pw = ?, must_change = 0 WHERE id = ?')
      .bind(await hashPassword(body.next, env), me.id).run();
    // ניתוק כל שאר ההפעלות
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id <> ?')
      .bind(me.id, me.session_id).run();
    return json({ ok: true });
  }

  if (path === '/api/profile' && method === 'POST') {
    const body = await readBody(request);
    const name = String(body.name || '').trim().slice(0, 80);
    const shulName = String(body.shulName || '').trim().slice(0, 120);
    await env.DB.prepare('UPDATE users SET name = ? WHERE id = ?').bind(name, me.id).run();
    if (shulName && me.role === 'owner') {
      await env.DB.prepare('UPDATE shuls SET name = ? WHERE id = ?').bind(shulName, me.shul_id).run();
    }
    return json({ ok: true });
  }

  /* ---------------- המפה ---------------- */
  if (path === '/api/chart' && method === 'GET') {
    const c = await getChart(env, me.shul_id);
    // ?since=<rev> — אם אין שינוי מחזירים תשובה זעירה במקום את כל המפה.
    const since = url.searchParams.get('since');
    if (since !== null && Number(since) === Number(c.rev)) {
      return json({ unchanged: true, rev: c.rev });
    }
    return json({ data: JSON.parse(c.data || '{}'), rev: c.rev, updatedAt: c.updated_at, updatedBy: c.updated_by });
  }

  if (path === '/api/chart/rev' && method === 'GET') {
    const c = await getChart(env, me.shul_id);
    return json({ rev: c.rev, updatedAt: c.updated_at, updatedBy: c.updated_by });
  }

  if (path === '/api/chart' && method === 'PUT') {
    if (!me.can_edit) return bad('אין לך הרשאת עריכה במפה זו', 403);
    const body = await readBody(request);
    if (typeof body.data !== 'object' || body.data === null) return bad('נתונים לא תקינים');
    const dataStr = JSON.stringify(body.data);
    if (dataStr.length > MAX_CHART_BYTES) return bad('המפה גדולה מדי', 413);

    const cur = await getChart(env, me.shul_id);
    if (body.rev !== undefined && body.force !== true && Number(body.rev) !== Number(cur.rev)) {
      return json({
        error: 'conflict',
        message: 'המפה עודכנה במקום אחר',
        server: { data: JSON.parse(cur.data || '{}'), rev: cur.rev, updatedAt: cur.updated_at, updatedBy: cur.updated_by },
      }, 409);
    }
    const res = await writeChart(env, me.shul_id, dataStr, me.name || me.email);
    return json({ ok: true, ...res });
  }

  /* ---------------- היסטוריית גרסאות ---------------- */
  if (path === '/api/history' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT id, rev, taken, updated_at, updated_by FROM chart_history
        WHERE shul_id = ? ORDER BY id DESC LIMIT ?`).bind(me.shul_id, HISTORY_KEEP).all();
    return json({ items: results || [] });
  }

  if (path === '/api/history/restore' && method === 'POST') {
    if (!me.can_edit) return bad('אין לך הרשאת עריכה במפה זו', 403);
    const body = await readBody(request);
    const row = await env.DB.prepare('SELECT * FROM chart_history WHERE id = ? AND shul_id = ?')
      .bind(Number(body.id), me.shul_id).first();
    if (!row) return bad('הגרסה לא נמצאה', 404);
    const res = await writeChart(env, me.shul_id, row.data, (me.name || me.email) + ' (שחזור)');
    return json({ ok: true, data: JSON.parse(row.data || '{}'), ...res });
  }

  /* ---------------- ניהול גבאים (בעל בית הכנסת) ---------------- */
  const isOwner = me.role === 'owner' || me.is_super;

  if (path === '/api/members' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT id, email, name, role, can_edit, status, created_at, last_login_at, must_change
         FROM users WHERE shul_id = ? ORDER BY role DESC, created_at ASC`).bind(me.shul_id).all();
    const { results: inv } = await env.DB.prepare(
      `SELECT code, created_at, expires_at, used_by FROM invites
        WHERE shul_id = ? AND used_by IS NULL AND expires_at > ? ORDER BY created_at DESC`)
      .bind(me.shul_id, nowISO()).all();
    return json({ members: results || [], invites: inv || [], me: me.id });
  }

  if (path === '/api/members/invite' && method === 'POST') {
    if (!isOwner) return bad('רק בעל בית הכנסת יכול לצרף גבאים', 403);
    const code = [...crypto.getRandomValues(new Uint8Array(4))]
      .map((b) => b.toString(36).toUpperCase().padStart(2, '0')).join('').slice(0, 8);
    await env.DB.prepare(
      'INSERT INTO invites (code, shul_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
      .bind(code, me.shul_id, me.id, nowISO(), plusHours(INVITE_HOURS)).run();
    return json({ code, expiresAt: plusHours(INVITE_HOURS) });
  }

  if (path === '/api/members/invite' && method === 'DELETE') {
    if (!isOwner) return bad('אין הרשאה', 403);
    const body = await readBody(request);
    await env.DB.prepare('DELETE FROM invites WHERE code = ? AND shul_id = ?')
      .bind(String(body.code || ''), me.shul_id).run();
    return json({ ok: true });
  }

  const memberMatch = path.match(/^\/api\/members\/([a-f0-9]{32})$/);
  if (memberMatch) {
    if (!isOwner) return bad('אין הרשאה', 403);
    const targetId = memberMatch[1];
    const target = await env.DB.prepare('SELECT * FROM users WHERE id = ? AND shul_id = ?')
      .bind(targetId, me.shul_id).first();
    if (!target) return bad('המשתמש לא נמצא', 404);
    if (target.id === me.id) return bad('לא ניתן לשנות את החשבון של עצמך מכאן');
    if (target.role === 'owner' && !me.is_super) return bad('לא ניתן לשנות את בעל בית הכנסת', 403);

    if (method === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
        env.DB.prepare('DELETE FROM users WHERE id = ?').bind(targetId),
      ]);
      return json({ ok: true });
    }

    if (method === 'POST') {
      const body = await readBody(request);
      if (body.action === 'password') {
        const pProb = passwordProblem(body.password);
        if (pProb) return bad(pProb);
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET pw = ?, must_change = 1 WHERE id = ?')
            .bind(await hashPassword(body.password, env), targetId),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
        ]);
        return json({ ok: true });
      }
      if (body.action === 'canEdit') {
        await env.DB.prepare('UPDATE users SET can_edit = ? WHERE id = ?')
          .bind(body.value ? 1 : 0, targetId).run();
        return json({ ok: true });
      }
      if (body.action === 'status') {
        const st = body.value === 'blocked' ? 'blocked' : 'active';
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(st, targetId),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
        ]);
        return json({ ok: true });
      }
      return bad('פעולה לא מוכרת');
    }
  }

  /* ---------------- מנהל-על ---------------- */
  if (path.startsWith('/api/admin/')) {
    if (!me.is_super) return bad('אין הרשאת ניהול', 403);

    if (path === '/api/admin/shuls' && method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT sh.id, sh.name, sh.created_at,
                (SELECT COUNT(*) FROM users u WHERE u.shul_id = sh.id) AS users,
                (SELECT taken FROM chart_history h WHERE h.shul_id = sh.id ORDER BY h.id DESC LIMIT 1) AS taken,
                (SELECT updated_at FROM charts c WHERE c.shul_id = sh.id) AS updated_at
           FROM shuls sh ORDER BY sh.created_at DESC`).all();
      return json({ shuls: results || [] });
    }

    if (path === '/api/admin/users' && method === 'GET') {
      const shulId = url.searchParams.get('shul') || '';
      const stmt = shulId
        ? env.DB.prepare(
            `SELECT u.id, u.email, u.name, u.role, u.status, u.can_edit, u.is_super,
                    u.created_at, u.last_login_at, sh.name AS shul_name
               FROM users u JOIN shuls sh ON sh.id = u.shul_id
              WHERE u.shul_id = ? ORDER BY u.created_at ASC`).bind(shulId)
        : env.DB.prepare(
            `SELECT u.id, u.email, u.name, u.role, u.status, u.can_edit, u.is_super,
                    u.created_at, u.last_login_at, sh.name AS shul_name
               FROM users u JOIN shuls sh ON sh.id = u.shul_id
              ORDER BY u.created_at DESC LIMIT 500`);
      const { results } = await stmt.all();
      return json({ users: results || [] });
    }

    const adminUser = path.match(/^\/api\/admin\/users\/([a-f0-9]{32})$/);
    if (adminUser && method === 'POST') {
      const body = await readBody(request);
      const targetId = adminUser[1];
      const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return bad('המשתמש לא נמצא', 404);

      if (body.action === 'password') {
        const pProb = passwordProblem(body.password);
        if (pProb) return bad(pProb);
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET pw = ?, must_change = 1 WHERE id = ?')
            .bind(await hashPassword(body.password, env), targetId),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
        ]);
        return json({ ok: true });
      }
      if (body.action === 'status') {
        if (targetId === me.id) return bad('לא ניתן לחסום את עצמך');
        const st = body.value === 'blocked' ? 'blocked' : 'active';
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(st, targetId),
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId),
        ]);
        return json({ ok: true });
      }
      return bad('פעולה לא מוכרת');
    }

    const adminShul = path.match(/^\/api\/admin\/shuls\/([a-f0-9]{32})$/);
    if (adminShul && method === 'DELETE') {
      const shulId = adminShul[1];
      if (shulId === me.shul_id) return bad('לא ניתן למחוק את בית הכנסת שלך מכאן');
      await env.DB.batch([
        env.DB.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE shul_id = ?)').bind(shulId),
        env.DB.prepare('DELETE FROM users WHERE shul_id = ?').bind(shulId),
        env.DB.prepare('DELETE FROM invites WHERE shul_id = ?').bind(shulId),
        env.DB.prepare('DELETE FROM chart_history WHERE shul_id = ?').bind(shulId),
        env.DB.prepare('DELETE FROM charts WHERE shul_id = ?').bind(shulId),
        env.DB.prepare('DELETE FROM shuls WHERE id = ?').bind(shulId),
      ]);
      return json({ ok: true });
    }
  }

  return bad('לא נמצא', 404);
}
