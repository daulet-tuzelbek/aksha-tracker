// Ақша Трекер API. Stores only ciphertext produced on the user's device, plus an event log (type, time).
// Apple Pay purchases arrive as plain text over HTTPS and are sealed at once with the user's public key;
// the plain text is never written to disk or to logs.
'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const {DatabaseSync} = require('node:sqlite');
const subtle = crypto.webcrypto.subtle;

const PORT = +(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || '/data/aksha.db';
const TZ_OFFSET_MIN = +(process.env.TZ_OFFSET_MIN || 300); // Kazakhstan, UTC+5
const SESSION_DAYS = 30;

const db = new DatabaseSync(DB_PATH);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, acct TEXT NOT NULL, auth TEXT NOT NULL, rec TEXT NOT NULL, created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, acct TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS months(acct TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, ym TEXT NOT NULL, box TEXT NOT NULL, PRIMARY KEY(acct, ym));
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, acct TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, row TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS paykeys(acct TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, th TEXT UNIQUE NOT NULL, pub TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inbox(id INTEGER PRIMARY KEY, acct TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, box TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fam(fid TEXT NOT NULL, doc TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER, PRIMARY KEY(fid, doc));`);

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashSecret = s => { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + crypto.scryptSync(s, salt, 32).toString('hex'); };
const checkSecret = (s, stored) => { const [salt, h] = String(stored).split(':'); if (!salt || !h) return false; const x = crypto.scryptSync(s, Buffer.from(salt, 'hex'), 32); return crypto.timingSafeEqual(x, Buffer.from(h, 'hex')); };
const ID_RE = /^a[0-9a-f]{28}$/, YM_RE = /^\d{4}-\d{2}$/, FID_RE = /^[A-Za-z0-9]{8,40}$/, DOC_RE = /^[A-Za-z0-9]{1,20}_\d{4}-\d{2}$/, TOK_RE = /^[A-Za-z0-9_-]{20,80}$/;
const isSecret = s => typeof s === 'string' && s.length >= 20 && s.length <= 200;

// simple in-memory rate limits
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(); const a = (hits.get(key) || []).filter(t => now - t < windowMs); a.push(now); hits.set(key, a);
  if (hits.size > 50000) hits.clear();
  return a.length > max;
}

function send(res, code, obj, type = 'application/json') {
  const body = type === 'application/json' ? JSON.stringify(obj) : String(obj);
  res.writeHead(code, {'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'});
  res.end(body);
}
function readBody(req, limit = 8 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('too big'), {code: 413})); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); req.on('error', reject);
  });
}
const json = s => { try { return JSON.parse(s || '{}'); } catch { return {}; } };
const ip = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

function newSession(acct) {
  const tok = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(th, acct, expires) VALUES(?,?,?)').run(sha(tok), acct, Date.now() + SESSION_DAYS * 864e5);
  return tok;
}
function auth(req) {
  const m = String(req.headers.authorization || '').match(/^Bearer ([A-Za-z0-9_-]{20,80})$/); if (!m) return null;
  const th = sha(m[1]); const s = db.prepare('SELECT acct, expires FROM sessions WHERE th=?').get(th);
  if (!s || s.expires < Date.now()) return null;
  if (s.expires - Date.now() < (SESSION_DAYS - 1) * 864e5) db.prepare('UPDATE sessions SET expires=? WHERE th=?').run(Date.now() + SESSION_DAYS * 864e5, th);
  return s.acct;
}
const serverLog = (acct, e, extra = {}) => { try { db.prepare('INSERT INTO logs(acct,row,at) VALUES(?,?,?)').run(acct, JSON.stringify({e, at: new Date().toISOString(), ...extra}), new Date().toISOString()); } catch {} };

// Apple Pay: seal {text, d, tm} with the account's RSA-OAEP public key, same format the app uses.
async function seal(pubJwk, obj) {
  const RSA = {name: 'RSA-OAEP', hash: 'SHA-256'};
  const pub = await subtle.importKey('jwk', pubJwk, RSA, false, ['encrypt']);
  const raw = crypto.randomBytes(32); const aes = await subtle.importKey('raw', raw, {name: 'AES-GCM'}, false, ['encrypt']);
  const iv = crypto.randomBytes(12);
  const ct = await subtle.encrypt({name: 'AES-GCM', iv}, aes, Buffer.from(JSON.stringify(obj)));
  const wk = await subtle.encrypt(RSA, pub, raw);
  return {wk: Buffer.from(wk).toString('base64'), iv: iv.toString('base64'), ct: Buffer.from(ct).toString('base64')};
}
function localNow() { const d = new Date(Date.now() + TZ_OFFSET_MIN * 6e4); const iso = d.toISOString(); return {d: iso.slice(0, 10), tm: iso.slice(11, 16)}; }

async function handle(req, res) {
  const url = new URL(req.url, 'http://x'); const p = url.pathname; const M = req.method;
  if (p === '/api/health') return send(res, 200, {ok: 1});

  // ── Apple Pay (no login; secret token in the URL) ──
  let m = p.match(/^\/api\/pay\/([A-Za-z0-9_-]{20,80})$/);
  if (m && (M === 'GET' || M === 'POST')) {
    if (limited('pay:' + ip(req), 300, 3600e3)) return send(res, 429, 'Слишком много запросов', 'text/plain');
    const k = db.prepare('SELECT acct, pub FROM paykeys WHERE th=?').get(sha(m[1]));
    if (!k) return send(res, 404, 'Неизвестная ссылка. Откройте приложение и скопируйте ссылку заново.', 'text/plain');
    let text = url.searchParams.get('t') || '';
    if (!text && M === 'POST') { const b = await readBody(req, 16384); const ct = String(req.headers['content-type'] || ''); if (/json/.test(ct)) text = String(json(b).text || json(b).t || ''); else if (/form/.test(ct)) text = new URLSearchParams(b).get('text') || new URLSearchParams(b).get('t') || ''; else text = b; }
    text = text.trim().slice(0, 1000);
    if (!text) return send(res, 400, 'Пустой текст', 'text/plain');
    const box = await seal(JSON.parse(k.pub), {text, ...localNow()});
    db.prepare('INSERT INTO inbox(acct, box, at) VALUES(?,?,?)').run(k.acct, JSON.stringify(box), Date.now());
    db.prepare('DELETE FROM inbox WHERE acct=? AND id NOT IN (SELECT id FROM inbox WHERE acct=? ORDER BY id DESC LIMIT 1000)').run(k.acct, k.acct);
    return send(res, 200, 'Сохранено', 'text/plain');
  }

  if (!p.startsWith('/api/')) {
    if (process.env.STATIC_FILE && M === 'GET') { res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache'}); return res.end(require('node:fs').readFileSync(process.env.STATIC_FILE)); }
    return send(res, 404, {error: 'not_found'});
  }
  if (M !== 'GET' && M !== 'DELETE' && !/json/.test(String(req.headers['content-type'] || ''))) return send(res, 415, {error: 'json_only'});
  const body = M === 'GET' || M === 'DELETE' ? {} : json(await readBody(req));

  // ── accounts ──
  if (p === '/api/signup' && M === 'POST') {
    if (limited('signup:' + ip(req), 20, 3600e3)) return send(res, 429, {error: 'rate'});
    const {id, auth: a, rec, acct} = body;
    if (!ID_RE.test(id || '') || !isSecret(a) || !isSecret(rec) || !acct || typeof acct !== 'object') return send(res, 400, {error: 'bad'});
    if (db.prepare('SELECT 1 FROM accounts WHERE id=?').get(id)) return send(res, 409, {error: 'exists'});
    db.prepare('INSERT INTO accounts(id, acct, auth, rec, created, updated) VALUES(?,?,?,?,?,?)').run(id, JSON.stringify(acct), hashSecret(a), hashSecret(rec), Date.now(), Date.now());
    return send(res, 200, {token: newSession(id)});
  }
  if ((p === '/api/login' || p === '/api/login-rec') && M === 'POST') {
    const {id} = body; const secret = p === '/api/login' ? body.auth : body.rec;
    if (!ID_RE.test(id || '') || !isSecret(secret)) return send(res, 400, {error: 'bad'});
    if (limited('login:' + id, 10, 900e3) || limited('loginip:' + ip(req), 60, 900e3)) return send(res, 429, {error: 'rate'});
    const row = db.prepare('SELECT acct, auth, rec FROM accounts WHERE id=?').get(id);
    if (!row || !checkSecret(secret, p === '/api/login' ? row.auth : row.rec)) { if (row) serverLog(id, p === '/api/login' ? 'login_failed' : 'recovery_failed'); return send(res, 401, {error: 'denied'}); }
    return send(res, 200, {token: newSession(id), acct: JSON.parse(row.acct)});
  }

  const me = auth(req);
  if (!me) return send(res, 401, {error: 'auth'});

  if (p === '/api/session' && M === 'GET') { const r = db.prepare('SELECT acct FROM accounts WHERE id=?').get(me); return r ? send(res, 200, {id: me, acct: JSON.parse(r.acct)}) : send(res, 401, {error: 'auth'}); }
  if (p === '/api/logout' && M === 'POST') { db.prepare('DELETE FROM sessions WHERE th=?').run(sha(String(req.headers.authorization).slice(7))); return send(res, 200, {ok: 1}); }
  if (p === '/api/acct' && M === 'PUT') { if (!body.acct || typeof body.acct !== 'object') return send(res, 400, {error: 'bad'}); db.prepare('UPDATE accounts SET acct=?, updated=? WHERE id=?').run(JSON.stringify(body.acct), Date.now(), me); return send(res, 200, {ok: 1}); }
  if (p === '/api/auth' && M === 'PUT') { if (!isSecret(body.auth)) return send(res, 400, {error: 'bad'}); db.prepare('UPDATE accounts SET auth=? WHERE id=?').run(hashSecret(body.auth), me); return send(res, 200, {ok: 1}); }
  if (p === '/api/acct' && M === 'DELETE') { db.prepare('DELETE FROM accounts WHERE id=?').run(me); return send(res, 200, {ok: 1}); }

  if (p === '/api/months' && M === 'GET') return send(res, 200, db.prepare('SELECT ym, box FROM months WHERE acct=?').all(me).map(r => ({ym: r.ym, box: JSON.parse(r.box)})));
  m = p.match(/^\/api\/months\/(\d{4}-\d{2})$/);
  if (m && M === 'PUT') { if (!body.box) return send(res, 400, {error: 'bad'}); db.prepare('INSERT INTO months(acct, ym, box) VALUES(?,?,?) ON CONFLICT(acct, ym) DO UPDATE SET box=excluded.box').run(me, m[1], JSON.stringify(body.box)); return send(res, 200, {ok: 1}); }
  if (m && M === 'DELETE') { db.prepare('DELETE FROM months WHERE acct=? AND ym=?').run(me, m[1]); return send(res, 200, {ok: 1}); }

  if (p === '/api/logs' && M === 'POST') { const r = body.row || {}; const clean = {e: String(r.e || '').slice(0, 40), at: new Date().toISOString()}; for (const [k, v] of Object.entries(r)) if (!['e', 'at'].includes(k) && (typeof v === 'number' || (typeof v === 'string' && v.length < 40))) clean[k] = v; db.prepare('INSERT INTO logs(acct,row,at) VALUES(?,?,?)').run(me, JSON.stringify(clean), clean.at); db.prepare('DELETE FROM logs WHERE acct=? AND id NOT IN (SELECT id FROM logs WHERE acct=? ORDER BY id DESC LIMIT 500)').run(me, me); return send(res, 200, {ok: 1}); }
  if (p === '/api/logs' && M === 'GET') return send(res, 200, db.prepare('SELECT row FROM logs WHERE acct=? ORDER BY id DESC LIMIT 30').all(me).map(r => JSON.parse(r.row)));

  if (p === '/api/pay/setup' && M === 'PUT') {
    if (!TOK_RE.test(body.token || '') || !body.pub || body.pub.kty !== 'RSA') return send(res, 400, {error: 'bad'});
    const pub = {kty: 'RSA', n: String(body.pub.n), e: String(body.pub.e), alg: 'RSA-OAEP-256', ext: true};
    db.prepare('INSERT INTO paykeys(acct, th, pub) VALUES(?,?,?) ON CONFLICT(acct) DO UPDATE SET th=excluded.th, pub=excluded.pub').run(me, sha(body.token), JSON.stringify(pub));
    return send(res, 200, {ok: 1});
  }
  if (p === '/api/inbox' && M === 'GET') return send(res, 200, db.prepare('SELECT id, box FROM inbox WHERE acct=? ORDER BY id').all(me).map(r => ({id: r.id, ...JSON.parse(r.box)})));
  if (p === '/api/inbox/ack' && M === 'POST') { const ids = (body.ids || []).filter(Number.isInteger).slice(0, 1000); const st = db.prepare('DELETE FROM inbox WHERE acct=? AND id=?'); ids.forEach(i => st.run(me, i)); return send(res, 200, {ok: 1}); }

  // ── family: documents encrypted with the family key ──
  m = p.match(/^\/api\/fam\/([A-Za-z0-9]{8,40})(?:\/([A-Za-z0-9_-]{1,40}))?$/);
  if (m) {
    const [, fid, doc] = m;
    if (!doc && M === 'GET') return send(res, 200, db.prepare('SELECT doc, data FROM fam WHERE fid=?').all(fid).map(r => ({id: r.doc, data: JSON.parse(r.data)})));
    if (doc && DOC_RE.test(doc) && M === 'PUT') { db.prepare('INSERT INTO fam(fid, doc, data, updated) VALUES(?,?,?,?) ON CONFLICT(fid, doc) DO UPDATE SET data=excluded.data, updated=excluded.updated').run(fid, doc, JSON.stringify(body.data || {}), Date.now()); return send(res, 200, {ok: 1}); }
    if (doc && M === 'DELETE') { db.prepare('DELETE FROM fam WHERE fid=? AND doc=?').run(fid, doc); return send(res, 200, {ok: 1}); }
  }
  return send(res, 404, {error: 'not_found'});
}

// expired sessions cleanup
setInterval(() => { try { db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now()); } catch {} }, 3600e3).unref();

http.createServer((req, res) => {
  handle(req, res).catch(e => { if (!res.headersSent) send(res, e.code === 413 ? 413 : 500, {error: e.code === 413 ? 'too_big' : 'server'}); console.error('error', req.method, new URL(req.url, 'http://x').pathname.replace(/\/api\/pay\/.+/, '/api/pay/…'), e.message); });
}).listen(PORT, () => console.log('aksha api on', PORT));
