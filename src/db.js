// KV-backed data layer for Cloudflare Pages.
// Every table is one JSON array stored under the KV key `t:<table>`. A small SQL dispatcher below understands the
// handful of statement shapes used by the panel, so the rest of the code keeps calling `db.all/one/run/batch` exactly
// as it did with D1. An in-isolate cache removes the KV read-after-write delay inside one request/isolate.
export const GB = 1024 ** 3;

export const DEFAULT_SITES = ['https://www.google.com/generate_204', 'https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204',
  'https://www.cloudflare.com/cdn-cgi/trace', 'https://www.apple.com/library/test/success.html', 'https://www.msftconnecttest.com/connecttest.txt',
  'https://detectportal.firefox.com/success.txt', 'https://www.youtube.com/generate_204', 'https://www.wikipedia.org/'];

export const DEFAULTS = {
  domain: '', tls_port: '443', max_users: '100', white_limit: '10', white_sni: '0', upstream: '',
  cfg_src: 'panel', cfg_custom: '', warp: '', masque: '', test_sites: JSON.stringify(DEFAULT_SITES), site_rr: '0', loc_last: '[]', job: '',
  cf_token: '', cf_account: '', cf_worker: 'xr-panel',
  spoof_sni: '', spoof_ip: '', spoof_port: '', ff_on: '0', ech_on: '0', ech_i: '-1', ipv6: '', frag_on: '0', frag_prof: '',
};

// Hash of the factory password "admin" (PBKDF2-SHA256, 20000 iterations, fixed salt), precomputed so the very first
// request does not spend CPU on key derivation. Anyone who changes the password gets a fresh random salt (auth.js).
export const DEFAULT_PW_HASH = "pbkdf2$20000$eHItcGFuZWwtZGVmYXVsdA==$s+Lo8kL8Eesv44WE/n1xuTrM/JMOfBjYMI/fR8KVyFg=";

const DEFAULTS_ROW = {
  users: { id: 0, name: '', uuid: '', limit_gb: 0, used: 0, expire: 0, enabled: 1, created: 0, grp_id: 0, white: 0, wp_secret: '' },
  settings: { k: '', v: '' },
  grps: { id: 0, name: '', cc: '' },
  proxies: { id: 0, grp_id: 0, host: '', port: 0, proto: '', ms: 0 },
  relays: { p: '', token: '', status: 'idle', steps: '', domain: '', ref: '', ping: '', err: '', upd: 0 },
  scan_ips: { id: 0, kind: '', host: '', port: 0, tls: 1, ms: 0, via: '', ts: 0 },
  cand: { id: 0, host: '', port: 0, proto: '' },
};
const UNIQUE = { users: ['uuid'], settings: ['k'], relays: ['p'], scan_ips: ['kind', 'host', 'port', 'tls'] };
const num = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

export const now = () => Math.floor(Date.now() / 1000);
/** 32 hex characters: the user's own Telegram Web Proxy secret. */
export const newSecret = () => [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');

// ---------------------------------------------------------------- KV cache ----------------------------------------------------------------
let cacheKV = null, cache = null;
function store(kv) {
  if (cacheKV !== kv || !cache) { cacheKV = kv; cache = new Map(); }
  return cache;
}
export function resetInit() { ready = null; cache = null; cacheKV = null; }

// ---------------------------------------------------------------- SQL helpers ----------------------------------------------------------------
/** Split a string on a separator that is not inside quotes or parentheses. */
function splitTop(str, sep = ',') {
  const out = []; let depth = 0, quote = '', start = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (quote) { if (c === quote) { if (str[i + 1] === quote) i++; else quote = ''; } continue; }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(' ) depth++;
    else if (c === ')') depth--;
    else if (depth === 0 && str.startsWith(sep, i)) { out.push(str.slice(start, i)); i += sep.length - 1; start = i + 1; }
  }
  out.push(str.slice(start)); return out;
}
/** Replace each `?` with a marker bound to a positional argument, leaving quoted values alone. */
function bindExpr(expr, args, cur) { return String(expr).replace(/\?/g, () => `__P${cur.i++}__`); }
function value(tok, args) {
  const t = String(tok).trim();
  let m;
  if ((m = t.match(/^__P(\d+)__$/))) return args[+m[1]];
  if ((m = t.match(/^'([\s\S]*)'$/))) return m[1].replace(/''/g, "'");
  if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
  if (/^(true|false)$/i.test(t)) return /^true$/i.test(t) ? 1 : 0;
  return t;
}
function cmp(a, b, op) {
  if (op === '=' || op === '==') return a == b;
  if (op === '!=' || op === '<>') return a != b;
  const x = Number(a), y = Number(b);
  if (op === '>') return x > y; if (op === '<') return x < y;
  if (op === '>=') return x >= y; if (op === '<=') return x <= y;
  return false;
}
/** Evaluate a WHERE expression. `get` resolves a (possibly qualified) column name. */
function cond(expr, get, args) {
  if (!expr || !expr.trim()) return true;
  const text = expr;
  const test = e => {
    e = e.trim().replace(/^\(([\s\S]*)\)$/, '$1');
    for (const op of [' OR ', ' AND ']) {
      const parts = splitTop(e, op);
      if (parts.length > 1) return op === ' OR ' ? parts.some(test) : parts.every(test);
    }
    let m = e.match(/^(\w+)\s+IN\s+\(([\s\S]*)\)$/i);
    if (m) return splitTop(m[2]).map(x => value(x, args)).includes(get(m[1]));
    m = e.match(/^(\w+)\s+IS\s+(NOT\s+)?NULL$/i);
    if (m) { const nul = get(m[1]) == null || get(m[1]) === ''; return m[2] ? !nul : nul; }
    m = e.match(/^(\w+)\s*(=|==|!=|<>|>=|<=|>|<)\s*([\s\S]+)$/);
    if (m) return cmp(get(m[1]), value(m[3], args), m[2]);
    return true;
  };
  return test(text);
}
function orderBy(expr, get, args, cur) {
  if (!expr || !expr.trim()) return null;
  const keys = splitTop(expr).map(x => {
    const m = x.trim().match(/^(\w+)(?:\s+(ASC|DESC))?$/i);
    return m ? [m[1], /DESC/i.test(m[2] || '') ? -1 : 1] : null;
  }).filter(Boolean);
  if (!keys.length) return null;
  return (a, b) => {
    for (const [k, dir] of keys) {
      const x = get(k, a), y = get(k, b);
      const r = typeof x === 'number' && typeof y === 'number' ? x - y : String(x ?? '').localeCompare(String(y ?? ''));
      if (r) return r < 0 ? -dir : dir;
    }
    return 0;
  };
}

/** Find a SQL keyword that is not inside quotes or parentheses. */
function findKw(str, kw) {
  const re = new RegExp('\\b' + kw.replace(/ /g, '\\s+') + '\\b', 'gi'); let m;
  while ((m = re.exec(str))) {
    let depth = 0, quote = '';
    for (let i = 0; i < m.index; i++) { const c = str[i]; if (quote) { if (c === quote) quote = ''; continue; } if (c === "'" || c === '"' || c === '`') quote = c; else if (c === '(') depth++; else if (c === ')') depth--; }
    if (!depth && !quote) return m.index;
  }
  return -1;
}
/** Build the row set and a column resolver for a FROM clause (optionally one JOIN). */
async function fromClause(rest, tables) {
  const pos = [['JOIN', findKw(rest, 'JOIN')], ['WHERE', findKw(rest, 'WHERE')], ['ORDER BY', findKw(rest, 'ORDER BY')], ['LIMIT', findKw(rest, 'LIMIT')]].filter(x => x[1] >= 0).sort((a, b) => a[1] - b[1]);
  const seg = name => { const p = pos.find(x => x[0] === name); if (!p) return null; const i = pos.find(x => x[1] > p[1]); return rest.slice(p[1] + name.length, i ? i[1] : rest.length).trim(); };
  const where = seg('WHERE'), order = seg('ORDER BY'), limit = seg('LIMIT');
  let head, on = null;
  const j = findKw(rest, 'JOIN');
  if (j >= 0) {
    head = rest.slice(0, j).trim();
    const tail = rest.slice(j + 4).trim(), oi = findKw(tail, 'ON');
    const spec = (oi >= 0 ? tail.slice(0, oi) : tail).trim().split(/\s+/);
    const om = (oi >= 0 ? tail.slice(oi + 2) : '').match(/^\s*(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)/);
    on = { t2: spec[0], a2: spec[1] || spec[0], l: om && [om[1], om[2]], r: om && [om[3], om[4]] };
  } else {
    const first = pos.length ? pos[0][1] : rest.length;
    head = rest.slice(0, first).trim();
  }
  const hs = head.split(/\s+/), t1 = hs[0], a1 = hs[1] || t1;
  if (on) {
    const left = await tables(t1), right = await tables(on.t2), rows = [];
    for (const l of left) for (const r of right) if (l[on.r[1]] == r[on.l[1]]) rows.push({ $l: l, $r: r });
    const get = (name, row = {}) => {
      const [q, col] = name.includes('.') ? name.split('.') : [null, name];
      const src = q === a1 ? row.$l : q === on.a2 ? row.$r : ((row.$l && col in row.$l) ? row.$l : row.$r);
      return src ? src[col] : undefined;
    };
    return { rows, get, where, order, limit, flat: false };
  }
  const rows = await tables(t1);
  const get = (name, row = {}) => { const col = name.includes('.') ? name.split('.').pop() : name; return row[col]; };
  return { rows, get, where, order, limit, flat: true };
}

// ---------------------------------------------------------------- DB ----------------------------------------------------------------
export class DB {
  constructor(env) { this.kv = env.KV || env.kv; this.cache = store(this.kv); }
  async data(name) {
    if (this.cache.has(name)) return this.cache.get(name);
    const rows = await this.kv.get('t:' + name, 'json');
    const arr = Array.isArray(rows) ? rows : [];
    this.cache.set(name, arr); return arr;
  }
  async tables(name) { return this.data(name); }
  async save(name) { await this.kv.put('t:' + name, JSON.stringify(this.cache.get(name) || [])); }
  async all(sql, ...a) { return exec(this, String(sql).replace(/\s+/g, ' ').trim(), a, false); }
  async one(sql, ...a) { const r = await exec(this, String(sql).replace(/\s+/g, ' ').trim(), a, false); return r[0] || null; }
  async run(sql, ...a) { await exec(this, String(sql).replace(/\s+/g, ' ').trim(), a, true); return { success: true }; }
  async batch(list) { for (const [sql, ...a] of list) await this.run(sql, ...a); return []; }
  async S() { const o = {}; for (const r of await this.all('SELECT k,v FROM settings')) o[r.k] = r.v; return o; }
  async set(k, v) { await this.run('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, String(v)); }
}

async function exec(db, sql, args, write) {
  const cur = { i: 0 };
  // ---- SELECT ----
  let m = sql.match(/^SELECT\s+([\s\S]+?)\s+FROM\s+([\s\S]+)$/i);
  if (m) {
    const cols = m[1].trim(); let rest = m[2].trim();
    const gi = findKw(rest, 'GROUP BY'); let groupCol = null;
    if (gi >= 0) { groupCol = rest.slice(gi + 8).trim().split(/\s+/)[0]; rest = rest.slice(0, gi).trim(); }
    const f = await fromClause(rest, n => db.data(n));
    let rows = f.rows.slice();
    const w = f.where ? bindExpr(f.where, args, cur) : null;
    if (w) rows = rows.filter(r => cond(w, name => f.get(name, r), args));
    const gm = cols.match(/^(.+?)\s*,\s*COUNT\(\*\)\s+(\w+)$/i);
    if (groupCol || gm) {
      const keyExpr = groupCol || gm[1].trim(), countKey = gm ? gm[2] : 'c';
      const groups = new Map();
      for (const r of rows) { const k = String(f.get(keyExpr, r)); groups.set(k, (groups.get(k) || 0) + 1); }
      rows = [...groups].map(([k, c]) => { const o = {}; o[keyExpr.split('.').pop()] = /^\d+$/.test(k) ? Number(k) : k; o[countKey] = c; return o; });
      const gget = name => rows[0] && rows[0][name.split('.').pop()];
      const gc = orderBy(f.order, (name, r) => r[name.split('.').pop()], args, cur);
      if (gc) rows.sort(gc);
      let gl = null; if (f.limit) gl = value(bindExpr(f.limit.trim(), args, cur), args);
      if (gl != null && isFinite(gl)) rows = rows.slice(0, Math.max(0, Math.floor(gl)));
      return rows;
    }
    if (/^COUNT\(\*\)\s+\w+$/i.test(cols)) return [{ c: rows.length }];
    const cmpRows = orderBy(f.order, (name, r) => f.get(name, r), args, cur);
    if (cmpRows) rows.sort(cmpRows);
    let limit = null;
    if (f.limit) limit = value(bindExpr(f.limit.trim(), args, cur), args);
    if (limit != null && isFinite(limit)) rows = rows.slice(0, Math.max(0, Math.floor(limit)));
    if (cols === '*') return rows.map(r => f.flat ? { ...r } : { ...r.$l, ...r.$r });
    return rows.map(r => {
      const o = {};
      for (const c of splitTop(cols)) {
        const name = c.trim(), alias = name.split(/\s+AS\s+/i);
        o[alias[1] || alias[0].split('.').pop()] = f.get(alias[0], r);
      }
      return o;
    });
  }
  // ---- INSERT ----
  m = sql.match(/^INSERT(?:\s+OR\s+IGNORE)?\s+INTO\s+(\w+)\s*\(([^)]*)\)\s+VALUES\s*([\s\S]+)$/i);
  if (m) {
    const table = m[1], keys = splitTop(m[2]).map(x => x.trim().replace(/`/g, ''));
    let vals = m[3]; let conflict = null, ignore = /\bINSERT\s+OR\s+IGNORE\b/i.test(sql), returning = false;
    let cm = vals.match(/\s+ON\s+CONFLICT\(([^)]*)\)\s+DO\s+UPDATE\s+SET\s+([\s\S]+)$/i);
    if (cm) { conflict = splitTop(cm[1]).map(x => x.trim()); vals = vals.slice(0, cm.index); }
    else { cm = vals.match(/\s+ON\s+CONFLICT\b[\s\S]*$/i); if (cm) vals = vals.slice(0, cm.index); }
    if (/\s+RETURNING\s+\*/i.test(vals)) { returning = true; vals = vals.replace(/\s+RETURNING\s+\*/i, ''); }
    vals = bindExpr(vals, args, cur);
    const groups = splitTop(vals).map(g => g.trim().replace(/^\(|\)$/g, ''));
    const rows = await db.data(table), made = [];
    for (const g of groups) {
      const parts = splitTop(g); const row = { ...(DEFAULTS_ROW[table] || {}) };
      keys.forEach((k, i) => { row[k] = value(parts[i], args); });
      if ('id' in (DEFAULTS_ROW[table] || {}) || (rows.length && 'id' in rows[0])) row.id = rows.reduce((mx, r) => Math.max(mx, num(r.id)), 0) + 1;
      const ck = conflict || UNIQUE[table] || [];
      const hit = ck.length ? rows.find(r => ck.every(k => r[k] === row[k])) : null;
      if (hit) {
        if (ignore) continue;
        if (cm) for (const ass of splitTop(cm[2])) {
          const [k, ex] = ass.split('=');
          hit[k.trim()] = /^excluded\./i.test(ex.trim()) ? row[ex.trim().slice(9)] : value(ex, args);
        }
        else Object.assign(hit, row);
        made.push({ ...hit });
      } else { rows.push(row); made.push({ ...row }); }
    }
    await db.save(table);
    return returning ? made : [];
  }
  // ---- UPDATE ----
  m = sql.match(/^UPDATE\s+(\w+)\s+SET\s+([\s\S]+?)(?:\s+WHERE\s+([\s\S]+?))?(?:\s+RETURNING\s+\*)?$/i);
  if (m) {
    const [, table, setClause, where] = m; const rows = await db.data(table);
    const sets = splitTop(setClause).map(x => { const p = x.indexOf('='); return [x.slice(0, p).trim(), bindExpr(x.slice(p + 1), args, cur)]; });
    const w = where ? bindExpr(where, args, cur) : null;
    const out = [];
    for (const r of rows) {
      if (!cond(w, name => r[name], args)) continue;
      for (const [k, ex] of sets) {
        const plus = ex.match(/^(\w+)\s*\+\s*(__P\d+|-?\d+(?:\.\d+)?)$/);
        if (plus && plus[1] === k) r[k] = num(r[k]) + num(value(plus[2], args));
        else r[k] = value(ex, args);
      }
      out.push({ ...r });
    }
    await db.save(table); return out;
  }
  // ---- DELETE ----
  m = sql.match(/^DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+([\s\S]+))?$/i);
  if (m) {
    const [, table, where] = m; const rows = await db.data(table);
    const w = where ? bindExpr(where, args, cur) : null;
    const keep = w ? rows.filter(r => !cond(w, name => r[name], args)) : [];
    db.cache.set(table, keep); await db.save(table); return [];
  }
  throw new Error('unsupported SQL: ' + sql);
}

// ---------------------------------------------------------------- setup ----------------------------------------------------------------
let ready = null;
export function init(env) {
  return ready || (ready = (async () => {
    const db = new DB(env), s = await db.S(), seed = { ...DEFAULTS };
    for (const [k, v] of Object.entries(seed)) if (!(k in s)) s[k] = String(v);
    if (!('pw' in s)) {
      const secret = [...crypto.getRandomValues(new Uint8Array(24))].map(b => b.toString(16).padStart(2, '0')).join('');
      s.pw = DEFAULT_PW_HASH; s.secret = secret;
    }
    db.cache.set('settings', Object.entries(s).map(([k, v]) => ({ k, v: String(v) })));
    await db.save('settings');
    const users = await db.data('users'); let changed = false;
    for (const u of users) if (!u.wp_secret) { u.wp_secret = newSecret(); changed = true; }
    if (changed) await db.save('users');
  })().catch(e => { ready = null; throw e; }));
}

export function state(u) {
  if (!u.enabled) return 'disabled';
  if (u.expire && u.expire < now()) return 'expired';
  if (u.limit_gb && u.used >= u.limit_gb * GB) return 'limited';
  return 'active';
}
export function left(u) {
  if (!u.expire) return 'no expiry';
  const d = Math.floor((u.expire - now()) / 86400); return d >= 0 ? `${d}d left` : 'expired';
}
export const pct = u => (u.limit_gb ? Math.min(100, Math.round(u.used / (u.limit_gb * GB) * 100)) : 0);
export function fmt(b) {
  for (const x of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (b < 1024 || x === 'TB') return x === 'B' ? `${Math.floor(b)} B` : `${b.toFixed(1)} ${x}`;
    b /= 1024;
  }
}
