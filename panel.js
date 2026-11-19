// xr PANEL — single-file Cloudflare Pages build (generated).
// All modules are merged into isolated scopes; the D1 data layer and Telegram Web Proxy need no Durable Object.
import { connect } from 'cloudflare:sockets';

const __mod_auth = (() => {
  // --- auth.js ---
// Password hashing (PBKDF2 via WebCrypto), signed session cookie, flash messages.
const enc = new TextEncoder();
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ITER = 20000;                                     // Workers cap PBKDF2 at 100000; 20000 keeps login inside small CPU budgets

async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
async function hashPw(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITER}$${b64(salt)}$${b64(await pbkdf2(pw, salt, ITER))}`;
}
async function checkPw(stored, pw) {
  const [t, it, s, h] = String(stored || '').split('$');
  if (t !== 'pbkdf2') return false;
  const a = await pbkdf2(pw, unb64(s), +it), b = unb64(h);
  let d = a.length ^ b.length; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)))].map(x => x.toString(16).padStart(2, '0')).join('');
}
const cookies = req => Object.fromEntries((req.headers.get('Cookie') || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), decodeURIComponent(c.slice(i + 1))]; }));
async function makeSession(secret, days = 7) { const exp = Math.floor(Date.now() / 1000) + days * 86400; return `${exp}.${await hmac(secret, 'ok.' + exp)}`; }
async function validSession(secret, v) {
  const [exp, sig] = String(v || '').split('.');
  if (!exp || !sig || +exp < Date.now() / 1000) return false;
  const want = await hmac(secret, 'ok.' + exp); let d = want.length ^ sig.length; for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ (sig.charCodeAt(i) || 0); return d === 0;
}
const cookie = (name, val, o = {}) => `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; Secure; SameSite=Lax` + (o.max !== undefined ? `; Max-Age=${o.max}` : '');

  return { hashPw, checkPw, cookies, makeSession, validSession, cookie };
})();

const __mod_db = (() => {
// D1 data layer for Cloudflare Pages.
// Users, settings and every other table live in one D1 database (`env.DB`).
const GB = 1024 ** 3;

const DEFAULT_SITES = ['https://www.google.com/generate_204', 'https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204',
  'https://www.cloudflare.com/cdn-cgi/trace', 'https://www.apple.com/library/test/success.html', 'https://www.msftconnecttest.com/connecttest.txt',
  'https://detectportal.firefox.com/success.txt', 'https://www.youtube.com/generate_204', 'https://www.wikipedia.org/'];

const DEFAULTS = {
  domain: '', tls_port: '443', max_users: '100', white_limit: '10', white_sni: '0', upstream: '',
  cfg_src: 'panel', cfg_custom: '', warp: '', masque: '', test_sites: JSON.stringify(DEFAULT_SITES), site_rr: '0', loc_last: '[]', job: '',
  cf_token: '', cf_account: '', cf_worker: 'xr-panel',
  spoof_sni: '', spoof_ip: '', spoof_port: '', ff_on: '0', ech_on: '0', ech_i: '-1', ipv6: '', frag_on: '0', frag_prof: '',
};

// Kept for the single-file build's public API; a fresh install hashes the factory password with hashPw() instead.
const DEFAULT_PW_HASH = "pbkdf2$20000$eHItcGFuZWwtZGVmYXVsdA==$s+Lo8kL8Eesv44WE/n1xuTrM/JMOfBjYMI/fR8KVyFg=";

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, uuid TEXT UNIQUE, limit_gb REAL DEFAULT 0, used INTEGER DEFAULT 0, expire INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, created INTEGER, grp_id INTEGER DEFAULT 0, white INTEGER DEFAULT 0, wp_secret TEXT DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)`,
  `CREATE TABLE IF NOT EXISTS grps(id INTEGER PRIMARY KEY, name TEXT, cc TEXT DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS proxies(id INTEGER PRIMARY KEY, grp_id INTEGER, host TEXT, port INTEGER, proto TEXT, ms INTEGER)`,
  `CREATE TABLE IF NOT EXISTS relays(p TEXT PRIMARY KEY, token TEXT, status TEXT DEFAULT 'idle', steps TEXT, domain TEXT, ref TEXT, ping TEXT, err TEXT, upd INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS scan_ips(id INTEGER PRIMARY KEY, kind TEXT, host TEXT, port INTEGER DEFAULT 0, tls INTEGER DEFAULT 1, ms INTEGER, via TEXT, ts INTEGER, UNIQUE(kind,host,port,tls))`,
  `CREATE TABLE IF NOT EXISTS cand(id INTEGER PRIMARY KEY, host TEXT, port INTEGER, proto TEXT)`,
];

const now = () => Math.floor(Date.now() / 1000);
/** 32 hex characters: the user's own Telegram Web Proxy secret. */
const newSecret = () => [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');

class DB {
  constructor(env) { this.d = env.DB; }
  async all(sql, ...a) { return (await this.d.prepare(sql).bind(...a).all()).results || []; }
  async one(sql, ...a) { return (await this.d.prepare(sql).bind(...a).first()) || null; }
  async run(sql, ...a) { return this.d.prepare(sql).bind(...a).run(); }
  async batch(list) { return this.d.batch(list.map(([sql, ...a]) => this.d.prepare(sql).bind(...a))); }
  // D1 writes are immediate; these keep multi-step jobs (location scanner) working without any buffering.
  begin() {}
  async flush() {}
  async S() { const o = {}; for (const r of await this.all('SELECT k,v FROM settings')) o[r.k] = r.v; return o; }
  async set(k, v) { await this.run('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, String(v)); }
}

let ready = null;
function init(env, hashPw) {
  // runs once per isolate; every statement is idempotent
  return ready || (ready = (async () => {
    const db = new DB(env);
    await db.batch(SCHEMA.map(s => [s]));
    // databases created before per-user web-proxy secrets: add the column once, then give every existing user a secret
    try { await db.run("ALTER TABLE users ADD COLUMN wp_secret TEXT DEFAULT ''"); } catch (e) { if (!/duplicate column/i.test(String((e && e.message) || e))) throw e; }
    for (const u of await db.all("SELECT id FROM users WHERE wp_secret IS NULL OR wp_secret=''")) await db.run('UPDATE users SET wp_secret=? WHERE id=?', newSecret(), u.id);
    await db.batch(Object.entries(DEFAULTS).map(([k, v]) => ['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', k, v]));
    const have = await db.one("SELECT 1 x FROM settings WHERE k='pw'");
    if (!have) {
      const secret = [...crypto.getRandomValues(new Uint8Array(24))].map(b => b.toString(16).padStart(2, '0')).join('');
      await db.batch([['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', 'pw', await hashPw('admin')], ['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', 'secret', secret]]);
    }
  })().catch(e => { ready = null; throw e; }));
}
function resetInit() { ready = null; }

function state(u) {
  if (!u.enabled) return 'disabled';
  if (u.expire && u.expire < now()) return 'expired';
  if (u.limit_gb && u.used >= u.limit_gb * GB) return 'limited';
  return 'active';
}
function left(u) {
  if (!u.expire) return 'no expiry';
  const d = Math.floor((u.expire - now()) / 86400); return d >= 0 ? `${d}d left` : 'expired';
}
const pct = u => (u.limit_gb ? Math.min(100, Math.round(u.used / (u.limit_gb * GB) * 100)) : 0);
function fmt(b) {
  for (const x of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (b < 1024 || x === 'TB') return x === 'B' ? `${Math.floor(b)} B` : `${b.toFixed(1)} ${x}`;
    b /= 1024;
  }
}

  return { GB, DEFAULT_SITES, DEFAULTS, DEFAULT_PW_HASH, now, newSecret, resetInit, DB, init, state, left, pct, fmt };

})();

const __mod_util = (() => {
  // --- util.js ---
// Small byte helpers shared by the protocol engines (relay.js, vmess.js, shadowsocks.js).
const te = new TextEncoder(), td = new TextDecoder();

const toU8 = d => d instanceof Uint8Array ? d : d instanceof ArrayBuffer ? new Uint8Array(d) : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : te.encode(String(d));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g) || [], h => parseInt(h, 16));
const uuidBytes = id => unhex(id.replace(/-/g, ''));
const u16 = n => Uint8Array.of((n >> 8) & 255, n & 255);
const rnd = n => crypto.getRandomValues(new Uint8Array(n));

/** base64 of any text (Persian / emoji / anything). Plain btoa() throws on characters above Latin-1, so encode as UTF-8 first. */
const b64 = x => { const u = typeof x === 'string' ? te.encode(x) : toU8(x); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };

/** Read an address as written in VLESS (1 v4, 2 domain, 3 v6), Trojan / Shadowsocks (1 v4, 3 domain, 4 v6) headers. */
function readAddr(b, i, atyp, v6atyp, domainAtyp = 2) {
  if (atyp === 1) return b.length >= i + 4 ? [`${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`, i + 4] : null;
  if (atyp === domainAtyp) { if (i >= b.length || b.length < i + 1 + b[i]) return null; return [td.decode(b.slice(i + 1, i + 1 + b[i])), i + 1 + b[i]]; }
  if (atyp === v6atyp) { if (b.length < i + 16) return null; const dv = new DataView(b.buffer, b.byteOffset + i, 16); return [Array.from({ length: 8 }, (_, k) => dv.getUint16(k * 2).toString(16)).join(':'), i + 16]; }
  return null;
}

/** One DNS query over HTTPS (the only UDP the relays carry). */
async function dnsOverHttps(q) {
  const r = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' }, body: q });
  return new Uint8Array(await r.arrayBuffer());
}

/** Growable receive buffer: append WebSocket messages, take exact byte counts. */
class RxBuf {
  constructor() { this.b = new Uint8Array(0); }
  get length() { return this.b.length; }
  push(d) { this.b = this.b.length ? cat(this.b, d) : d; }
  peek(n) { return this.b.subarray(0, n); }
  take(n) { const o = this.b.slice(0, n); this.b = this.b.subarray(n); return o; }
  all() { const o = this.b; this.b = new Uint8Array(0); return o; }
}

  return { te, td, toU8, cat, hex, unhex, uuidBytes, u16, rnd, b64, readAddr, dnsOverHttps, RxBuf };
})();

const __mod_links = (() => {
  const { DEFAULT_SITES } = __mod_db;
  const { b64 } = __mod_util;
  // --- links.js ---
// Subscription links: advanced options (spoof / F+F / fragment / ECH / IPv6), config domain, White IPs.

const SS = 'chacha20-ietf-poly1305';
const ALL = ['vless', 'vmess', 'shadowsocks', 'trojan'];
const NATIVE = ALL;                                 // every protocol is terminated inside the Worker
const protos = () => ALL;                           // (an optional upstream only changes where the bytes go)

const Q = x => encodeURIComponent(x).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const ECH = [
  ['Static config', 'base64', 'AEX+DQBBXgAgACBsvLac2HVdvp+J2QTKPNjn24b5D6yHyxAcG0m+cmDcXAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA='],
  ['crypto.cloudflare.com', 'udp 8.8.8.8', 'crypto.cloudflare.com+udp://8.8.8.8'],
  ['ridanbe.net', 'udp 8.8.8.8', 'ridanbe.net+udp://8.8.8.8'],
  ['iranva.ir', 'udp 1.1.1.1', 'iranva.ir+udp://1.1.1.1'],
  ['cloudflare-ech.com', 'udp 1.1.1.1', 'cloudflare-ech.com+udp://1.1.1.1'],
];

// ---- Fragment profiles: "fast" is exactly the F+F mask; slower networks get longer pauses and fewer splits ----
const FRAG_TIERS = { fast: ['0', '1', '11'], mid: ['1', '3', '8'], slow: ['2', '6', '5'] };
function fragMask(tier) {
  const [d1, d2, ms] = FRAG_TIERS[tier];
  return JSON.stringify({ tcp: [{ type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: [d1], maxSplit: '0' } },
    { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: [d2], maxSplit: ms } }] });
}
const FM = fragMask('fast');
function fragProf(s) {
  let p = null; try { p = JSON.parse(s.frag_prof || 'null'); } catch { }
  return p && typeof p === 'object' && p.tier in FRAG_TIERS ? p : (p && p.tier === 'none' ? p : null);
}
function fragFm(s) { const p = s.frag_on === '1' ? fragProf(s) : null; return p && p.tier in FRAG_TIERS ? fragMask(p.tier) : ''; }
function tierOf(rtt, ok) {
  if (ok <= 0) return 'none';
  if (rtt < 150 && ok >= 0.9) return 'fast';
  if (rtt < 400 && ok >= 0.6) return 'mid';
  return 'slow';
}

// ---- test sites (round robin) ----
function cleanSite(u) {
  u = (u || '').trim(); if (!u) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = 'https://' + u;
  let x; try { x = new URL(u); } catch { return null; }
  if (!['http:', 'https:'].includes(x.protocol) || !/^[A-Za-z0-9.\-]{1,253}$/.test(x.hostname) || !x.hostname.includes('.') || u.length > 300) return null;
  return u;
}
function sitesList(s) {
  let L = []; try { L = JSON.parse(s.test_sites || '[]'); } catch { }
  const out = []; for (const u of Array.isArray(L) ? L : []) { const c = cleanSite(String(u)); if (c && !out.includes(c)) out.push(c); }
  return out.length ? out : [...DEFAULT_SITES];
}

// ---- advanced options -> (snispoofing JSON | null, F+F on, ECH value) ----
function adv(s) {
  const [sni, sip, sp] = ['spoof_sni', 'spoof_ip', 'spoof_port'].map(k => (s[k] || '').trim());
  let spoof = null;
  if (sni && sip) spoof = `{\n  "active" : true,\n  "fakeSni" : ${JSON.stringify(sni)},\n  "spoofIp" : ${JSON.stringify(sip)},\n  "targetPort" : ${/^\d+$/.test(sp) ? parseInt(sp, 10) : 0}\n}`;
  const i = parseInt(s.ech_i || '-1', 10);
  return [spoof, s.ff_on === '1', (s.ech_on === '1' && i >= 0 && i < ECH.length) ? ECH[i][2] : ''];
}

// ---- which domain the configs point to ----
async function relayDomain(db, p) { const r = await db.one('SELECT domain FROM relays WHERE p=?', p); return (r && r.domain) || ''; }
const RELAY_NAMES = { vercel: 'Vercel', netlify: 'Netlify', railway: 'Railway' };
function panelDomain(s, host) { const d = (s.domain || '').trim(); return d && d !== 'example.com' ? d : host; }
async function cfgDom(db, s, host) {
  const src = s.cfg_src || 'panel';
  if (src.startsWith('relay:')) { const d = await relayDomain(db, src.slice(6)); if (d) return [d, '443', RELAY_NAMES[src.slice(6)] || 'Relay']; }
  if (src === 'custom' && s.cfg_custom) { const [h, p] = s.cfg_custom.split(':'); return [h, p || s.tls_port, 'Custom']; }
  return [panelDomain(s, host), s.tls_port, 'Direct'];
}

async function whiteList(db, s) {
  const lim = Math.max(0, parseInt(s.white_limit || '0', 10) || 0);
  const ips = lim ? await db.all("SELECT * FROM scan_ips WHERE kind='ip' ORDER BY ms ASC, id ASC LIMIT ?", lim) : [];
  const snis = s.white_sni === '1' ? (await db.all("SELECT host FROM scan_ips WHERE kind='sni' ORDER BY ms ASC LIMIT 50")).map(r => r.host) : [];
  return [ips, snis];
}

async function links(db, u, s, host) {
  const [d, port, label] = await cfgDom(db, s, host); const uid = u.uuid; const isip = /^[\d.]+$/.test(d); const ins = isip ? '&allowInsecure=1' : '';
  const [spoof, ffOn, ech] = adv(s);
  const fm = fragFm(s) || (ffOn ? FM : ''); const ff = !!fm;
  const prof = s.frag_on === '1' ? fragProf(s) : null; const bad = new Set((prof && prof.bad) || []);
  const echq = ech ? `&ech=${Q(ech)}` : '';
  const a6 = (s.ipv6 || '').trim().replace(/^\[|\]$/g, ''); const ua = a6.includes(':') ? `[${a6}]` : a6;
  const hosts = [[label, d, port, null, true, d, ua]];                    // (name, address, port, tag, tls, sni, address override)
  if (u.white) {
    const [ips, snis] = await whiteList(db, s); let k = 0;
    for (const x of ips) {
      const h = x.host; const tls = !!x.tls; let sn = d;
      if (tls && snis.length) { sn = snis[k % snis.length]; k++; }
      hosts.push([h.includes(':') ? h.slice(0, 16) : h, h.includes(':') ? `[${h}]` : h, x.port, null, tls, sn, '']);
    }
  }
  const out = [];
  for (const [nm, addr0, p, tag, tls, sni, ov] of hosts) {
    const raw = ov ? (a6 || addr0) : addr0; const addr = ov || addr0;
    for (const pr of protos(s)) {
      const fu = ff && !(bad.has(pr) && fragFm(s));
      const extra = echq + (fu ? `&fm=${Q(fm)}` : '');
      const path = tag ? `/ws/${tag}/${pr}/${uid}` : `/ws/${pr}/${uid}`;
      const ps = `${u.name}-${nm}-${pr}`;
      const t = tls ? `security=tls&type=ws&host=${d}&sni=${sni}&path=${Q(path)}${ins}${extra}` + (fu ? '&fp=unsafe' : '') : `security=none&type=ws&host=${d}&path=${Q(path)}`;
      const add = l => out.push([nm, pr, l]);
      if (pr === 'vless') {
        const z = isip ? '1' : '0';
        if (tls) add(`vless://${uid}@${addr}:${p}?sni=${sni}&security=tls&encryption=none&type=ws&alpn=http%2F1.1&insecure=${z}&host=${d}&path=${Q(path)}&allowInsecure=${z}` + (spoof ? `&snispoofing=${Q(spoof)}` : '') + extra + `&fp=${fu ? 'unsafe' : 'chrome'}#${Q(ps)}`);
        else add(`vless://${uid}@${addr}:${p}?security=none&encryption=none&type=ws&host=${d}&path=${Q(path)}#${Q(ps)}`);
      } else if (pr === 'trojan') add(`trojan://${uid}@${addr}:${p}?${t}#${Q(ps)}`);
      else if (pr === 'shadowsocks') add(`ss://${b64(`${SS}:${uid}`)}@${addr}:${p}?${t}#${Q(ps)}`);
      else {
        const j = { v: '2', ps, add: raw.replace(/^\[|\]$/g, ''), port: String(p), id: uid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: d, path, tls: tls ? 'tls' : '' };
        if (tls) j.sni = sni;
        add('vmess://' + b64(JSON.stringify(j)));
      }
    }
  }
  return out;
}

  return { SS, ALL, NATIVE, protos, Q, ECH, FRAG_TIERS, fragMask, FM, fragProf, fragFm, tierOf, cleanSite, sitesList, adv, relayDomain, RELAY_NAMES, panelDomain, cfgDom, whiteList, links };
})();

const __mod_proxy = (() => {
  // --- proxy.js ---
// Outbound TCP through SOCKS5 / SOCKS4 / HTTP(S) proxies using the Workers socket API (`connect` is injected).
const te = new TextEncoder(), td = new TextDecoder();
const TARGET = ['1.1.1.1', 80];
const timeout = (p, ms, what = 'timeout') => { let t; return Promise.race([p, new Promise((_, r) => { t = setTimeout(() => r(new Error(what)), ms); })]).finally(() => clearTimeout(t)); };

// Buffered reader over a socket: handshakes read exact amounts, the relay then continues with whatever is left.
class Rd {
  constructor(sock) { this.r = sock.readable.getReader(); this.buf = new Uint8Array(0); this.done = false; }
  async pull() { const { value, done } = await this.r.read(); if (done) { this.done = true; return false; } const n = new Uint8Array(this.buf.length + value.length); n.set(this.buf); n.set(value, this.buf.length); this.buf = n; return true; }
  async need(n) { while (this.buf.length < n) if (!(await this.pull())) throw new Error('closed'); const o = this.buf.slice(0, n); this.buf = this.buf.slice(n); return o; }
  async until(marker, max = 8192) { const m = te.encode(marker); for (; ;) { const i = indexOf(this.buf, m); if (i >= 0) { const o = this.buf.slice(0, i + m.length); this.buf = this.buf.slice(i + m.length); return o; } if (this.buf.length > max || !(await this.pull())) throw new Error('bad answer'); } }
  async next() { if (this.buf.length) { const o = this.buf; this.buf = new Uint8Array(0); return { value: o, done: false }; } return this.r.read(); }
  release() { try { this.r.releaseLock(); } catch { } }
}
function indexOf(a, m) { outer: for (let i = 0; i + m.length <= a.length; i++) { for (let j = 0; j < m.length; j++) if (a[i + j] !== m[j]) continue outer; return i; } return -1; }

const isV4 = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
const isV6 = h => h.includes(':');
function v4(h) { return Uint8Array.from(h.split('.').map(Number)); }

async function handshake(w, rd, proto, host, port) {
  const p2 = Uint8Array.of(port >> 8, port & 255);
  if (proto === 'socks5') {
    await w.write(Uint8Array.of(5, 1, 0)); const r = await rd.need(2); if (r[0] !== 5 || r[1] !== 0) throw new Error('socks5 auth');
    const addr = isV4(host) ? [1, ...v4(host)] : isV6(host) ? [4, ...ipv6Bytes(host)] : [3, host.length, ...te.encode(host)];
    await w.write(Uint8Array.from([5, 1, 0, ...addr, ...p2]));
    const h = await rd.need(4); if (h[1] !== 0) throw new Error('socks5 refused');
    const rest = h[3] === 1 ? 6 : h[3] === 4 ? 18 : (await rd.need(1))[0] + 2; await rd.need(rest);
  } else if (proto === 'socks4') {
    const ip = isV4(host) ? v4(host) : Uint8Array.of(0, 0, 0, 1);
    await w.write(Uint8Array.from([4, 1, ...p2, ...ip, 0, ...(isV4(host) ? [] : [...te.encode(host), 0])]));
    const r = await rd.need(8); if (r[1] !== 0x5a) throw new Error('socks4 refused');
  } else {
    await w.write(te.encode(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    const head = td.decode(await rd.until('\r\n\r\n')); if (!/^HTTP\/1\.[01] 200/.test(head)) throw new Error('connect refused');
  }
}
function ipv6Bytes(h) {
  const [a, b] = h.split('::'); const A = a ? a.split(':') : [], B = b !== undefined && b ? b.split(':') : [];
  const g = [...A, ...Array(Math.max(0, 8 - A.length - B.length)).fill('0'), ...B]; const o = [];
  for (const x of g) { const n = parseInt(x || '0', 16); o.push(n >> 8, n & 255); } return o;
}

/** Open host:port through one proxy ({host,port,proto}). Resolves {sock, rd, w}. */
async function viaProxy(connect, px, host, port, ms = 6000) {
  const sock = connect({ hostname: px.host, port: px.port }, px.proto === 'https' ? { secureTransport: 'on', allowHalfOpen: false } : undefined);
  const w = sock.writable.getWriter(), rd = new Rd(sock);
  try { await timeout((async () => { await sock.opened; await handshake(w, rd, px.proto === 'https' ? 'http' : px.proto, host, port); })(), ms); }
  catch (e) { try { sock.close(); } catch { } throw e; }
  return { sock, rd, w };
}
async function direct(connect, host, port, ms = 6000) {
  const sock = connect({ hostname: host, port }); await timeout(sock.opened, ms, 'connect timeout');
  return { sock, rd: new Rd(sock), w: sock.writable.getWriter() };
}

/** Round trip through a proxy to TARGET, in ms, or null. */
async function probe(connect, proto, host, port, ms = 4000) {
  const t = Date.now(); let c;
  try { c = await viaProxy(connect, { host, port, proto }, TARGET[0], TARGET[1], ms); return Math.max(1, Date.now() - t); }
  catch { return null; }
  finally { if (c) { try { c.sock.close(); } catch { } } }
}
const PROBES = ['socks5', 'socks4', 'http', 'https'];
async function probeAll(connect, host, port) {
  const res = await Promise.all(PROBES.map(async p => ({ proto: p, ms: await probe(connect, p, host, port) })));
  const ok = res.filter(x => x.ms !== null); return [res, ok.length ? ok.reduce((a, b) => (b.ms < a.ms ? b : a)) : null];
}

  return { TARGET, timeout, Rd, indexOf, handshake, ipv6Bytes, viaProxy, direct, probe, PROBES, probeAll };
})();

const __mod_loc = (() => {
  const { probe, PROBES } = __mod_proxy;
  const { now } = __mod_db;
  // --- loc.js ---
// Locations: country groups of exit proxies, geo lookup, Auto location and Recovery.
// A Worker request is short, so the job is driven in small steps: the browser calls /api/loc/step until it is done (or stopped).

const valid = (host, port) => /^[A-Za-z0-9.\-:]{1,253}$/.test(host || '') && /^\d+$/.test(String(port)) && +port > 0 && +port < 65536;
function isGlobal(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
  }
  const x = ip.toLowerCase(); return !(x === '::1' || x === '::' || x.startsWith('fe80') || x.startsWith('fc') || x.startsWith('fd'));
}
async function resolve(host, fetchFn = fetch) {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  try { const r = await (await fetchFn(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: 'application/dns-json' } })).json(); const a = (r.Answer || []).find(x => x.type === 1); return a ? a.data : null; } catch { return null; }
}

const GEO = new Map();
async function geo(host, fetchFn = fetch) {
  const ip = await resolve(host, fetchFn); if (!ip || !isGlobal(ip)) return null; if (GEO.has(ip)) return GEO.get(ip);
  const tries = [[`https://ipwho.is/${ip}`, d => d.success && [d.country_code, d.country]], [`http://ip-api.com/json/${ip}?fields=status,country,countryCode`, d => d.status === 'success' && [d.countryCode, d.country]]];
  for (const [url, get] of tries) {
    try { const d = await (await fetchFn(url, { headers: { 'User-Agent': 'xr-panel' } })).json(); const r = get(d); if (r && /^[A-Za-z]{2}$/.test(r[0] || '')) { const g = { cc: r[0].toLowerCase(), name: String(r[1] || r[0]).trim().slice(0, 60) }; GEO.set(ip, g); return g; } } catch { }
  }
  return null;
}
async function geoBatch(ips, fetchFn = fetch) {
  const out = {}, todo = []; for (const ip of ips) { if (GEO.has(ip)) out[ip] = GEO.get(ip); else todo.push(ip); }
  for (let i = 0; i < todo.length; i += 100) {
    try {
      const r = await fetchFn('http://ip-api.com/batch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(todo.slice(i, i + 100).map(q => ({ query: q, fields: 'status,country,countryCode,query' }))) });
      for (const d of await r.json()) if (d.status === 'success' && /^[A-Za-z]{2}$/.test(d.countryCode || '')) { const g = { cc: d.countryCode.toLowerCase(), name: String(d.country || d.countryCode).trim().slice(0, 60) }; GEO.set(d.query, g); out[d.query] = g; }
    } catch { }
  }
  for (const ip of todo.filter(x => !out[x]).slice(0, 6)) { const g = await geo(ip, fetchFn); if (g) out[ip] = g; }
  return out;
}

// ---------- groups ----------
async function groups(db) {
  const px = await db.all('SELECT * FROM proxies ORDER BY ms'), cnt = {};
  for (const r of await db.all('SELECT grp_id,COUNT(*) c FROM users GROUP BY grp_id')) cnt[r.grp_id] = r.c;
  return (await db.all('SELECT * FROM grps ORDER BY name')).map(g => { const p = px.filter(x => x.grp_id === g.id); return { id: g.id, name: g.name, cc: g.cc, px: p, n: p.length, users: cnt[g.id] || 0 }; });
}
async function dropIfEmpty(db, gid) {
  if (!(await db.one('SELECT 1 x FROM proxies WHERE grp_id=?', gid))) await db.batch([['DELETE FROM grps WHERE id=?', gid], ['UPDATE users SET grp_id=0 WHERE grp_id=?', gid]]);
}
async function putProxy(db, h, p, proto, ms, g) {
  let row = g.cc ? await db.one('SELECT id FROM grps WHERE cc=?', g.cc) : await db.one("SELECT id FROM grps WHERE name='Other' AND cc=''");
  if (!row) { await db.run('INSERT INTO grps(name,cc) VALUES(?,?)', g.name, g.cc); row = await db.one('SELECT id FROM grps WHERE cc=? AND name=? ORDER BY id DESC', g.cc, g.name); }
  await db.run('INSERT INTO proxies(grp_id,host,port,proto,ms) VALUES(?,?,?,?,?)', row.id, h, p, proto, ms);
}

// ---------- free proxy lists ----------
const PX_SOURCES = [['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', 'socks5'], ['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt', 'socks4'],
  ['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt', 'http'], ['https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt', 'socks5'],
  ['https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt', 'http'], ['https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt', 'socks5'],
  ['https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt', ''], ['https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=6000&country=all&simplified=true', 'socks5'],
  ['https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=6000&country=all&simplified=true', 'http'], ['https://www.proxy-list.download/api/v1/get?type=socks5', 'socks5'],
  ['https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt', 'socks5'], ['https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt', 'http'],
  ['https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt', 'socks5'], ['https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt', 'http'],
  ['https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt', 'socks5'], ['https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt', 'http']];
const PX_RE = /(?:([a-z0-9]+):\/\/)?((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})/gi;
async function fetchList(url, hint, fetchFn = fetch) {
  let txt;
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
    let r; try { r = await fetchFn(url, { headers: { 'User-Agent': 'xr-panel' }, signal: ctrl.signal }); } finally { clearTimeout(t); }
    if (!r.ok) return null; txt = (await r.text()).slice(0, 2_000_000);
  } catch { return null; }
  const out = new Map();
  for (const m of txt.matchAll(PX_RE)) {
    let pr = (m[1] || hint || '').toLowerCase(); if (pr === 'socks5h') pr = 'socks5'; const h = m[2], pt = +m[3];
    if (!['socks5', 'socks4', 'http', 'https', ''].includes(pr) || !isGlobal(h) || !(pt > 0 && pt < 65536)) continue; out.set(`${h}:${pt}`, pr);
  }
  return out;
}
async function candidates(skip, fetchFn = fetch, max = 600) {
  const res = await Promise.all(PX_SOURCES.map(([u, h]) => fetchList(u, h, fetchFn))), all = new Map();
  for (const r of res) for (const [k, v] of r || []) if (!skip.has(k) && !all.has(k)) all.set(k, v);
  const list = [...all].map(([k, v]) => { const i = k.lastIndexOf(':'); return [k.slice(0, i), +k.slice(i + 1), v]; });
  for (let i = list.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [list[i], list[j]] = [list[j], list[i]]; }
  return { list: list.slice(0, max), good: res.filter(Boolean).length, total: PX_SOURCES.length, found: list.length };
}

// ---------- the job (state lives in settings.job) ----------
const LOC_MAX = 10, BATCH = 12, CONC = 6;       // 12 candidates x up to 3 protocol tries stays under the 50-subrequest limit of the free plan
const blank = () => ({ run: false, stop: false, kind: '', total: 0, done: 0, added: 0, tried: 0, alive: 0, msg: '', seq: 0, log: [], used: [], have: [], last: [], need: {}, pool: [] });
async function getJob(db) { try { return { ...blank(), ...JSON.parse((await db.one("SELECT v FROM settings WHERE k='job'"))?.v || '{}') }; } catch { return blank(); } }
const saveJob = (db, j) => db.set('job', JSON.stringify(j));
const lg = (j, cls, txt) => { j.seq++; j.log.push([j.seq, cls, txt]); if (j.log.length > 120) j.log.splice(0, j.log.length - 120); };
function view(j, since = 0) { return { run: j.run, kind: j.kind, total: j.total, done: j.done, added: j.added, tried: j.tried, alive: j.alive, msg: j.msg, stopping: false, seq: j.seq, log: j.log.filter(x => x[0] > since) }; }

async function startJob(db, kind, fetchFn = fetch) {
  const cur = await getJob(db); if (cur.run && now() - (cur.ts || 0) < 120) return { error: 'Another job is running', kind: cur.kind };
  const j = { ...blank(), run: true, kind, ts: now() };
  const existing = new Set((await db.all('SELECT host,port FROM proxies')).map(r => `${r.host}:${r.port}`));
  if (kind === 'auto') {
    j.have = (await db.all("SELECT cc FROM grps WHERE cc!=''")).map(r => r.cc); try { j.last = JSON.parse((await db.one("SELECT v FROM settings WHERE k='loc_last'"))?.v || '[]'); } catch { } j.total = LOC_MAX; lg(j, 'i', 'looking for proxies…');
  } else {
    const rows = await db.all("SELECT p.id,p.host,p.port,g.cc,g.name FROM proxies p JOIN grps g ON g.id=p.grp_id WHERE g.cc!='' ORDER BY g.name,p.ms");
    if (!rows.length) { j.run = false; lg(j, 'bad', 'No country groups to recover yet.'); await saveJob(db, j); return { ok: true }; }
    for (const r of rows) (j.need[r.cc] = j.need[r.cc] || []).push({ id: r.id, name: r.name, host: r.host, port: r.port });
    j.total = rows.length; lg(j, 'i', `${rows.length} proxies in ${Object.keys(j.need).length} countries to replace`);
  }
  let c = await candidates(existing, fetchFn); lg(j, 'i', `${c.good}/${c.total} proxy sites answered · ${c.found} candidates`);
  if (!c.list.length) {                                     // one source or another is often just briefly unreachable; retry once before giving up
    lg(j, 'w', 'no candidates on the first try, retrying once…');
    c = await candidates(existing, fetchFn); lg(j, 'i', `${c.good}/${c.total} proxy sites answered · ${c.found} candidates`);
  }
  if (!c.list.length) {
    j.run = false; j.msg = 'auto-stopped · 0 found';
    lg(j, 'bad', c.good === 0
      ? 'Every free proxy-list source failed to answer (network/DNS from this Worker, or the sources are blocking Cloudflare right now) — this is NOT a stop you triggered.'
      : 'Sources answered but no usable host:port was found in them this time — this is NOT a stop you triggered.');
    await saveJob(db, j); return { ok: true };
  }
  await db.run('DELETE FROM cand');
  for (let i = 0; i < c.list.length; i += 30) { const ch = c.list.slice(i, i + 30); await db.run(`INSERT INTO cand(host,port,proto) VALUES ${ch.map(() => '(?,?,?)').join(',')}`, ...ch.flat()); }
  await saveJob(db, j); return { ok: true };
}
async function stopJob(db) { const j = await getJob(db); if (j.run) { j.run = false; j.stop = true; j.msg = `stopped · ${j.added} ${j.kind === 'recover' ? 'replaced' : 'added'}`; lg(j, 'w', j.msg); await saveJob(db, j); } return view(j); }

async function probeOne(connect, [h, p, pr]) {
  for (const x of (PROBES.includes(pr) && pr !== 'https' ? [pr] : ['socks5', 'http', 'socks4'])) { const ms = await probe(connect, x, h, p, 3000); if (ms) return { host: h, port: p, proto: x, ms }; }
  return null;
}
async function pool(items, n, fn) { const out = []; let i = 0; await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } })); return out; }

async function stepJob(db, connect, fetchFn = fetch) {
  const j = await getJob(db); if (!j.run) return view(j);
  const rows = await db.all('SELECT id,host,port,proto FROM cand ORDER BY id LIMIT ?', BATCH);
  const finish = async () => {
    if (j.kind === 'auto') {
      if (j.added < LOC_MAX) for (const r of j.pool.sort((a, b) => a.ms - b.ms)) { if (j.added >= LOC_MAX) break; if (!j.used.includes(r.g.cc)) await take(r, ' · known country'); }
      if (j.used.length) await db.set('loc_last', JSON.stringify(j.used));
      if (!j.added) lg(j, 'bad', 'No working proxy found this time. Try again in a minute.');
    } else { const left = Object.values(j.need).reduce((n, v) => n + v.length, 0); if (left) lg(j, 'w', `${left} proxy(ies) kept their old address: no replacement from the same country was found.`); }
    j.run = false; j.pool = []; j.msg = `finished · ${j.added} ${j.kind === 'recover' ? 'replaced' : 'added'}`; lg(j, 'ok', j.msg); await db.run('DELETE FROM cand');
  };
  const take = async (r, why) => { await putProxy(db, r.host, r.port, r.proto, r.ms, r.g); j.used.push(r.g.cc); j.added++; j.done = j.added; lg(j, 'ok', `+ ${r.g.name} · ${r.host}:${r.port} · ${r.proto} ${r.ms}ms${why}`); };
  if (!rows.length) { await finish(); await saveJob(db, j); return view(j); }
  await db.run(`DELETE FROM cand WHERE id IN (${rows.map(() => '?').join(',')})`, ...rows.map(r => r.id));
  const ok = (await pool(rows, CONC, r => probeOne(connect, [r.host, r.port, r.proto]))).filter(Boolean);
  j.tried += rows.length; j.alive += ok.length;
  if (ok.length) {
    const g = await geoBatch(ok.map(r => r.host), fetchFn);
    for (const r of ok.sort((a, b) => a.ms - b.ms)) {
      r.g = g[r.host]; if (!r.g) continue; const cc = r.g.cc;
      if (j.kind === 'auto') {
        if (j.added >= LOC_MAX || j.used.includes(cc)) continue;
        if (j.have.includes(cc) || j.last.includes(cc)) { j.pool.push(r); continue; }
        await take(r, '');
      } else if ((j.need[cc] || []).length) {
        const old = j.need[cc].shift();
        await db.run('UPDATE proxies SET host=?,port=?,proto=?,ms=? WHERE id=?', r.host, r.port, r.proto, r.ms, old.id); j.added++; j.done = j.added;
        lg(j, 'ok', `↻ ${old.name} · ${old.host}:${old.port} → ${r.host}:${r.port} · ${r.proto} ${r.ms}ms`);
      }
    }
  }
  lg(j, 'd', `· ${j.tried} checked · ${j.alive} alive`);
  if ((j.kind === 'auto' && j.added >= LOC_MAX) || (j.kind === 'recover' && !Object.values(j.need).some(v => v.length))) await finish();
  j.ts = now(); await saveJob(db, j); return view(j);
}

  return { valid, isGlobal, resolve, geo, geoBatch, groups, dropIfEmpty, putProxy, PX_SOURCES, fetchList, candidates, LOC_MAX, BATCH, CONC, getJob, view, startJob, stopJob, stepJob };
})();

const __mod_crypto = (() => {
  const { cat } = __mod_util;
  // --- crypto.js ---
// Cryptographic primitives the native VMess / Shadowsocks engines need and WebCrypto does not offer
// (MD5, SHAKE128, ChaCha20-Poly1305, synchronous SHA-256/HMAC for the VMess KDF), plus thin WebCrypto
// wrappers for the parts it does well (AES-GCM, HKDF-SHA1, AES single-block). No dependencies.

// ------------------------------------------------------------------ SHA-256 / SHA-224
const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
const IV256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const IV224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
function sha2(msg, iv, words) {
  const H = new Uint32Array(iv), len = msg.length, padLen = ((len + 9 + 63) >> 6) << 6, m = new Uint8Array(padLen); m.set(msg); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(padLen - 8, Math.floor(len * 8 / 2 ** 32)); dv.setUint32(padLen - 4, (len * 8) >>> 0);
  const w = new Uint32Array(64), r = (x, n) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < padLen; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) { const s0 = r(w[i - 15], 7) ^ r(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = r(w[i - 2], 17) ^ r(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) >>> 0, S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(words * 4), ov = new DataView(out.buffer); for (let i = 0; i < words; i++) ov.setUint32(i * 4, H[i]); return out;
}
const sha256 = msg => sha2(msg, IV256, 8);
const sha224 = msg => sha2(msg, IV224, 7);

/** HMAC over any hash function `H(bytes) -> bytes` with a 64-byte block (the VMess KDF nests these). */
function hmacWith(H, key) {
  if (key.length > 64) key = H(key);
  const k = new Uint8Array(64); k.set(key); const ip = k.map(b => b ^ 0x36), op = k.map(b => b ^ 0x5c);
  return data => H(cat(op, H(cat(ip, data))));
}
const hmacSha256 = (key, data) => hmacWith(sha256, key)(data);

// ------------------------------------------------------------------ MD5 (VMess command key, Shadowsocks key derivation)
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));
function md5(msg) {
  const len = msg.length, padLen = ((len + 9 + 63) >> 6) << 6, m = new Uint8Array(padLen); m.set(msg); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(padLen - 8, (len * 8) >>> 0, true); dv.setUint32(padLen - 4, Math.floor(len * 8 / 2 ** 32), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476; const M = new Uint32Array(16);
  for (let o = 0; o < padLen; o += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(o + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; } else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; } else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; } else { F = C ^ (B | ~D); g = (7 * i) & 15; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0; A = D; D = C; C = B; B = (B + ((F << MD5_S[i]) | (F >>> (32 - MD5_S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer); ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true); return out;
}

/** OpenSSL EVP_BytesToKey(MD5, no salt, 1 round): how Shadowsocks turns a password into the master key. */
function evpBytesToKey(password, keyLen) {
  let out = new Uint8Array(0), prev = new Uint8Array(0);
  while (out.length < keyLen) { prev = md5(cat(prev, password)); out = cat(out, prev); }
  return out.slice(0, keyLen);
}

// ------------------------------------------------------------------ small checksums
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(b) { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function fnv1a(b) { let h = 0x811c9dc5; for (let i = 0; i < b.length; i++) h = Math.imul(h ^ b[i], 0x01000193) >>> 0; return h; }
function ctEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

// ------------------------------------------------------------------ SHAKE128 (VMess chunk-length masking and padding stream)
const M64 = (1n << 64n) - 1n, rotl64 = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;
const ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const RC = (() => { let R = 1; const out = []; for (let t = 0; t < 24; t++) { let rc = 0n; for (let j = 0; j < 7; j++) { if (R & 1) rc |= 1n << BigInt((1 << j) - 1); R <<= 1; if (R & 0x100) R ^= 0x171; } out.push(rc); } return out; })();
function keccakF(st) {
  const C = new Array(5);
  for (let r = 0; r < 24; r++) {
    for (let x = 0; x < 5; x++) C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    for (let x = 0; x < 5; x++) { const d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) st[y + x] ^= d; }
    let t = st[1]; for (let i = 0; i < 24; i++) { const j = PILN[i], b = st[j]; st[j] = rotl64(t, ROTC[i]); t = b; }
    for (let y = 0; y < 25; y += 5) { const row = st.slice(y, y + 5); for (let x = 0; x < 5; x++) st[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5]); }
    st[0] ^= RC[r];
  }
}
class Shake128 {
  constructor(input) {
    if (input.length >= 168) throw new Error('shake input too long');
    this.st = new Array(25).fill(0n); const blk = new Uint8Array(168); blk.set(input); blk[input.length] ^= 0x1f; blk[167] ^= 0x80;
    for (let i = 0; i < 21; i++) { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(blk[i * 8 + k]); this.st[i] ^= v; }
    this.buf = new Uint8Array(0); this.pos = 0;
  }
  squeeze() { keccakF(this.st); const o = new Uint8Array(168); for (let i = 0; i < 21; i++) { let v = this.st[i]; for (let k = 0; k < 8; k++) { o[i * 8 + k] = Number(v & 255n); v >>= 8n; } } this.buf = o; this.pos = 0; }
  read(n) { const out = new Uint8Array(n); for (let i = 0; i < n; i++) { if (this.pos >= this.buf.length) this.squeeze(); out[i] = this.buf[this.pos++]; } return out; }
  u16() { const b = this.read(2); return (b[0] << 8) | b[1]; }
}

// ------------------------------------------------------------------ ChaCha20-Poly1305 (RFC 8439)
const le32 = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
// One 64-byte keystream block per call; the rounds are unrolled on locals because that is what makes it fast.
function chachaBlockInto(out, s, counter) {
  let x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7], x8 = s[8], x9 = s[9], x10 = s[10], x11 = s[11], x12 = counter | 0, x13 = s[13], x14 = s[14], x15 = s[15];
  for (let i = 0; i < 10; i++) {
    x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 16) | (x12 >>> 16);
    x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 12) | (x4 >>> 20);
    x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 8) | (x12 >>> 24);
    x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 7) | (x4 >>> 25);
    x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 16) | (x13 >>> 16);
    x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 12) | (x5 >>> 20);
    x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 8) | (x13 >>> 24);
    x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 7) | (x5 >>> 25);
    x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 16) | (x14 >>> 16);
    x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 12) | (x6 >>> 20);
    x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 8) | (x14 >>> 24);
    x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 7) | (x6 >>> 25);
    x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 16) | (x15 >>> 16);
    x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 12) | (x7 >>> 20);
    x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 8) | (x15 >>> 24);
    x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 7) | (x7 >>> 25);
    x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 16) | (x15 >>> 16);
    x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 12) | (x5 >>> 20);
    x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 8) | (x15 >>> 24);
    x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 7) | (x5 >>> 25);
    x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 16) | (x12 >>> 16);
    x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 12) | (x6 >>> 20);
    x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 8) | (x12 >>> 24);
    x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 7) | (x6 >>> 25);
    x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 16) | (x13 >>> 16);
    x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 12) | (x7 >>> 20);
    x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 8) | (x13 >>> 24);
    x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 7) | (x7 >>> 25);
    x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 16) | (x14 >>> 16);
    x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 12) | (x4 >>> 20);
    x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 8) | (x14 >>> 24);
    x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 7) | (x4 >>> 25);
  }
  out[0] = x0 + s[0]; out[1] = x1 + s[1]; out[2] = x2 + s[2]; out[3] = x3 + s[3]; out[4] = x4 + s[4]; out[5] = x5 + s[5]; out[6] = x6 + s[6]; out[7] = x7 + s[7];
  out[8] = x8 + s[8]; out[9] = x9 + s[9]; out[10] = x10 + s[10]; out[11] = x11 + s[11]; out[12] = x12 + counter; out[13] = x13 + s[13]; out[14] = x14 + s[14]; out[15] = x15 + s[15];
}
function chachaState(key, nonce) {
  const s = new Int32Array(16); s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = le32(key, i * 4); for (let i = 0; i < 3; i++) s[13 + i] = le32(nonce, i * 4); return s;
}
function chachaBlock(key, counter, nonce) {
  const w = new Uint32Array(16); chachaBlockInto(w, chachaState(key, nonce), counter); return new Uint8Array(w.buffer.slice(0));   // little-endian hosts only (every JS engine we target)
}
function chachaXor(key, nonce, counter, data) {
  const out = new Uint8Array(data.length), s = chachaState(key, nonce), w = new Uint32Array(16), ks = new Uint8Array(w.buffer);
  for (let o = 0, c = counter; o < data.length; o += 64, c++) { chachaBlockInto(w, s, c); const n = Math.min(64, data.length - o); for (let i = 0; i < n; i++) out[o + i] = data[o + i] ^ ks[i]; }
  return out;
}
// Poly1305 on ten 13-bit limbs: every partial product stays far below 2^53, so plain doubles are exact.
const P1305 = (1n << 130n) - 5n;
function limbs(m) { const l = new Array(10); for (let i = 0; i < 10; i++) { const bit = 13 * i, by = bit >> 3; l[i] = ((m[by] | (m[by + 1] << 8) | (m[by + 2] << 16)) >>> (bit & 7)) & 0x1fff; } return l; }
function poly1305(key, msg) {
  const rb = new Uint8Array(17); rb.set(key.subarray(0, 16)); for (const i of [3, 7, 11, 15]) rb[i] &= 15; for (const i of [4, 8, 12]) rb[i] &= 252;
  const [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9] = limbs(rb), s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5, s5 = r5 * 5, s6 = r6 * 5, s7 = r7 * 5, s8 = r8 * 5, s9 = r9 * 5;
  let h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0, h8 = 0, h9 = 0; const m = new Uint8Array(17);
  for (let off = 0; off < msg.length; off += 16) {
    const n = Math.min(16, msg.length - off); if (n < 16) m.fill(0); m.set(msg.subarray(off, off + n)); m[n] = 1;
    h0 += ((m[0] | (m[1] << 8) | (m[2] << 16)) >>> 0) & 0x1fff;
    h1 += ((m[1] | (m[2] << 8) | (m[3] << 16)) >>> 5) & 0x1fff;
    h2 += ((m[3] | (m[4] << 8) | (m[5] << 16)) >>> 2) & 0x1fff;
    h3 += ((m[4] | (m[5] << 8) | (m[6] << 16)) >>> 7) & 0x1fff;
    h4 += ((m[6] | (m[7] << 8) | (m[8] << 16)) >>> 4) & 0x1fff;
    h5 += ((m[8] | (m[9] << 8) | (m[10] << 16)) >>> 1) & 0x1fff;
    h6 += ((m[9] | (m[10] << 8) | (m[11] << 16)) >>> 6) & 0x1fff;
    h7 += ((m[11] | (m[12] << 8) | (m[13] << 16)) >>> 3) & 0x1fff;
    h8 += ((m[13] | (m[14] << 8) | (m[15] << 16)) >>> 0) & 0x1fff;
    h9 += ((m[14] | (m[15] << 8) | (m[16] << 16)) >>> 5) & 0x1fff;
    let d0 = h0 * r0 + h1 * s9 + h2 * s8 + h3 * s7 + h4 * s6 + h5 * s5 + h6 * s4 + h7 * s3 + h8 * s2 + h9 * s1;
    let d1 = h0 * r1 + h1 * r0 + h2 * s9 + h3 * s8 + h4 * s7 + h5 * s6 + h6 * s5 + h7 * s4 + h8 * s3 + h9 * s2;
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s9 + h4 * s8 + h5 * s7 + h6 * s6 + h7 * s5 + h8 * s4 + h9 * s3;
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s9 + h5 * s8 + h6 * s7 + h7 * s6 + h8 * s5 + h9 * s4;
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 + h5 * s9 + h6 * s8 + h7 * s7 + h8 * s6 + h9 * s5;
    let d5 = h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1 + h5 * r0 + h6 * s9 + h7 * s8 + h8 * s7 + h9 * s6;
    let d6 = h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2 + h5 * r1 + h6 * r0 + h7 * s9 + h8 * s8 + h9 * s7;
    let d7 = h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3 + h5 * r2 + h6 * r1 + h7 * r0 + h8 * s9 + h9 * s8;
    let d8 = h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4 + h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * s9;
    let d9 = h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5 + h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    let c;
    h0 = d0 & 0x1fff; c = (d0 - h0) / 8192;
    d1 += c; h1 = d1 & 0x1fff; c = (d1 - h1) / 8192;
    d2 += c; h2 = d2 & 0x1fff; c = (d2 - h2) / 8192;
    d3 += c; h3 = d3 & 0x1fff; c = (d3 - h3) / 8192;
    d4 += c; h4 = d4 & 0x1fff; c = (d4 - h4) / 8192;
    d5 += c; h5 = d5 & 0x1fff; c = (d5 - h5) / 8192;
    d6 += c; h6 = d6 & 0x1fff; c = (d6 - h6) / 8192;
    d7 += c; h7 = d7 & 0x1fff; c = (d7 - h7) / 8192;
    d8 += c; h8 = d8 & 0x1fff; c = (d8 - h8) / 8192;
    d9 += c; h9 = d9 & 0x1fff; c = (d9 - h9) / 8192;
    h0 += c * 5; c = h0 >>> 13; h0 &= 0x1fff; h1 += c;
  }
  let H = 0n; for (const x of [h9, h8, h7, h6, h5, h4, h3, h2, h1, h0]) H = (H << 13n) + BigInt(x); H %= P1305;
  let S = 0n; for (let i = 15; i >= 0; i--) S = (S << 8n) | BigInt(key[16 + i]);
  let T = (H + S) & ((1n << 128n) - 1n); const out = new Uint8Array(16); for (let i = 0; i < 16; i++) { out[i] = Number(T & 255n); T >>= 8n; } return out;
}
function chachaMac(key, nonce, aad, ct) {
  const otk = chachaBlock(key, 0, nonce).subarray(0, 32), pad = n => new Uint8Array((16 - (n % 16)) % 16), len = new Uint8Array(16), dv = new DataView(len.buffer);
  dv.setUint32(0, aad.length, true); dv.setUint32(8, ct.length, true); return poly1305(otk, cat(aad, pad(aad.length), ct, pad(ct.length), len));
}
function chachaSeal(key, nonce, pt, aad = new Uint8Array(0)) { const ct = chachaXor(key, nonce, 1, pt); return cat(ct, chachaMac(key, nonce, aad, ct)); }
function chachaOpen(key, nonce, boxed, aad = new Uint8Array(0)) {
  if (boxed.length < 16) throw new Error('short');
  const ct = boxed.subarray(0, boxed.length - 16); if (!ctEq(chachaMac(key, nonce, aad, ct), boxed.subarray(boxed.length - 16))) throw new Error('bad tag');
  return chachaXor(key, nonce, 1, ct);
}

// ------------------------------------------------------------------ WebCrypto wrappers
const EMPTY = new Uint8Array(0);
/** AEAD with `seal(nonce, data, aad)` / `open(nonce, boxed, aad)` -> Promise<Uint8Array>; `open` rejects on a bad tag. */
function makeAead(kind, key) {
  if (kind === 'chacha20-poly1305') return { tag: 16, seal: async (n, d, a = EMPTY) => chachaSeal(key, n, d, a), open: async (n, d, a = EMPTY) => chachaOpen(key, n, d, a) };
  const k = crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return {
    tag: 16,
    seal: async (n, d, a = EMPTY) => new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: n, additionalData: a, tagLength: 128 }, await k, d)),
    open: async (n, d, a = EMPTY) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: n, additionalData: a, tagLength: 128 }, await k, d)),
  };
}
async function hkdfSha1(ikm, salt, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-1', salt, info }, k, len * 8));
}
// WebCrypto has no raw AES block mode: one CBC block with a zero IV *is* one ECB block.
const ZERO16 = new Uint8Array(16);
async function aesBlockEncrypt(key, block) {
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO16 }, k, block)).slice(0, 16);
}
async function aesBlockDecrypt(key, block) {
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']);
  // Append E(block xor 0x10..) so the CBC padding check passes; the first plaintext block is the answer.
  const x = block.map(b => b ^ 16), c2 = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO16 }, k, x)).slice(0, 16);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ZERO16 }, k, cat(block, c2)));
}

  return { sha256, sha224, hmacWith, hmacSha256, md5, evpBytesToKey, crc32, fnv1a, ctEq, Shake128, poly1305, chachaSeal, chachaOpen, makeAead, hkdfSha1, aesBlockEncrypt, aesBlockDecrypt };
})();

const __mod_shadowsocks = (() => {
  const { evpBytesToKey, hkdfSha1, makeAead } = __mod_crypto;
  const { te, toU8, cat, u16, rnd, readAddr, RxBuf } = __mod_util;
  // --- shadowsocks.js ---
// Native Shadowsocks (AEAD) over WebSocket. Both common ciphers are accepted and detected from the first chunk:
// chacha20-ietf-poly1305 and aes-256-gcm. The password is the user's uuid, the user is named by the path
// (/ws/shadowsocks/<uuid>), so there is no key search: one derivation, at most two trial decryptions.
//
//   stream   = salt(32) then chunks  [AEAD(len, 2 bytes)] [AEAD(payload, <= 0x3FFF)]   (nonce = LE counter, +1 per AEAD call)
//   subkey   = HKDF-SHA1(master key, salt, "ss-subkey")        master key = EVP_BytesToKey(MD5, password)
//   1st data = atyp addr port, then the payload (possibly spread over several chunks)

const SS_CIPHERS = { 'chacha20-ietf-poly1305': 'chacha20-poly1305', 'aes-256-gcm': 'aes-gcm' };
const SALT = 32, TAG = 16, MAX = 0x3fff, INFO = te.encode('ss-subkey');

const seenSalt = new Map();       // replay filter for the handshake salt, per isolate
function freshSalt(s) {
  const now = Date.now(), k = [...s].join(',');
  for (const [x, t] of seenSalt) if (now - t > 300000) seenSalt.delete(x); else break;
  if (seenSalt.has(k)) return false; seenSalt.set(k, now); return true;
}

function counterNonce(n) { const o = new Uint8Array(12); for (let i = 0; i < 6 && n; i++) { o[i] = n % 256; n = Math.floor(n / 256); } return o; }
class Half { constructor(kind, subkey) { this.aead = makeAead(kind, subkey); this.n = 0; } nonce() { return counterNonce(this.n++); } }

/** -> 'more' | null (invalid) | {host, port, rest} */
function parseTarget(b) {
  if (b.length < 1) return 'more'; const t = b[0]; let need;
  if (t === 1) need = 7; else if (t === 4) need = 19; else if (t === 3) { if (b.length < 2) return 'more'; need = 4 + b[1]; } else return null;
  if (b.length < need) return 'more';
  const [host, i] = readAddr(b, 1, t, 4, 3); return { host, port: (b[i] << 8) | b[i + 1], rest: b.slice(i + 2) };
}

/** Encrypt side of a connection: random salt first, then length + payload boxes. */
async function makeEncoder(master, kind) {
  const salt = rnd(SALT), half = new Half(kind, await hkdfSha1(master, salt, INFO, 32)); let sent = false;
  return async payload => {
    const out = [];
    if (!sent) { out.push(salt); sent = true; }
    for (let i = 0; i < payload.length; i += MAX) { const p = payload.subarray(i, i + MAX); out.push(await half.aead.seal(half.nonce(), u16(p.length)), await half.aead.seal(half.nonce(), p)); }
    return cat(...out);
  };
}

function serveShadowsocks(ws, { user, dial, meter, ctx, early }) {
  const master = evpBytesToKey(te.encode(user.uuid), 32), rx = new RxBuf(), head = new RxBuf();
  let kind = null, dec = null, pendingLen = -1, remote = null, enc = null, closed = false, started = Promise.resolve();
  const close = reason => { if (closed) return; closed = true; try { remote && remote.sock && remote.sock.close(); } catch { } try { ws.close(reason ? 1008 : 1000, reason || ''); } catch { } meter.stop(); };
  meter.bind(close);

  async function detect() {                                          // salt + first length box decide the cipher
    if (rx.length < SALT + 2 + TAG) return false;
    const b = rx.peek(rx.length), salt = b.subarray(0, SALT), box = b.subarray(SALT, SALT + 2 + TAG);
    for (const k of Object.values(SS_CIPHERS)) {
      const h = new Half(k, await hkdfSha1(master, salt, INFO, 32));
      try { await h.aead.open(h.nonce(), box); } catch { continue; }
      if (!freshSalt(salt)) { close('replay'); return false; }
      kind = k; dec = new Half(k, await hkdfSha1(master, salt, INFO, 32)); rx.take(SALT); return true;
    }
    close('bad key'); return false;
  }
  async function chunks() {
    const out = [];
    for (; ;) {
      if (pendingLen < 0) {
        if (rx.length < 2 + TAG) break; const l = await dec.aead.open(dec.nonce(), rx.take(2 + TAG)); pendingLen = (l[0] << 8) | l[1];
        if (pendingLen > MAX) throw new Error('chunk too large');
      }
      if (rx.length < pendingLen + TAG) break;
      out.push(await dec.aead.open(dec.nonce(), rx.take(pendingLen + TAG))); pendingLen = -1;
    }
    return out;
  }
  async function toRemote(p) { if (p.length) await remote.w.write(p); }
  async function onData(raw) {
    const d = toU8(raw); meter.add(d.length); if (meter.dead || closed) return; rx.push(d);
    if (!kind && !(await detect())) { if (!closed && rx.length > 65536) close('bad key'); return; }
    let ps; try { ps = await chunks(); } catch { return close('bad chunk'); }
    for (const p of ps) {
      if (remote) { await toRemote(p); continue; }
      head.push(p); const t = parseTarget(head.peek(head.length));
      if (t === 'more') { if (head.length > 512) return close('bad header'); continue; }
      if (!t) return close('bad header');
      try { remote = await dial(t.host, t.port); } catch { return close('exit failed'); }
      enc = await makeEncoder(master, kind); head.all();
      (async () => {
        try { for (; ;) { const { value, done } = await remote.rd.next(); if (done) break; const f = await enc(value); meter.add(f.length); ws.send(f); if (meter.dead) break; } } catch { }
        close();
      })();
      await toRemote(t.rest);
    }
  }
  const run = d => { started = started.then(() => onData(d)).catch(() => close('error')); };
  ws.addEventListener('message', e => run(e.data)); ws.addEventListener('close', () => close()); ws.addEventListener('error', () => close());
  if (early && early.length) run(early);
  return { close };
}

  return { SS_CIPHERS, parseTarget, makeEncoder, serveShadowsocks };
})();

const __mod_vmess = (() => {
  const { md5, sha256, hmacWith, hmacSha256, crc32, fnv1a, Shake128, makeAead, aesBlockDecrypt } = __mod_crypto;
  const { te, toU8, cat, uuidBytes, u16, rnd, readAddr, dnsOverHttps, RxBuf } = __mod_util;
  // --- vmess.js ---
// Native VMess over WebSocket (the AEAD format, alterId = 0, which is what every current client sends).
//
//   request  = authid(16) | AEAD(header length)(2+16) | connection nonce(8) | AEAD(header)(n+16)
//   header   = ver(1) iv(16) key(16) V(1) opt(1) pad<<4|sec(1) 0(1) cmd(1) port(2) atyp(1) addr pad(P) fnv1a(4)
//   body     = chunks  [len(2, masked by SHAKE128(iv))] [AEAD(payload)] [padding]
//   response = AEAD(len) AEAD([V 0 0 0]) then the same chunk framing with the *response* key / iv
//
// The user is known from the WebSocket path (/ws/vmess/<uuid>), so the command key comes from that one uuid
// and there is nothing to search; wrong keys fail the auth-id or the AEAD tag and the socket is closed.

const MAGIC = te.encode('c48619fe-8f02-49e0-b9e9-edf763e17e21');
const cmdKeyOf = uuid => md5(cat(uuidBytes(uuid), MAGIC));

/** VMess AEAD KDF: HMAC-SHA256 whose hash function is, layer by layer, the HMAC built for the previous path element. */
function kdf(key, ...path) {
  let H = d => hmacSha256(te.encode('VMess AEAD KDF'), d);
  for (const p of path) H = hmacWith(H, toU8(p));
  return H(key);
}
const kdf16 = (key, ...path) => kdf(key, ...path).subarray(0, 16), kdf12 = (key, ...path) => kdf(key, ...path).subarray(0, 12);
const ZERO = new Uint8Array(0);

const SEC = { AES128GCM: 3, CHACHA: 4 };
const OPT = { CHUNK_STREAM: 1, CHUNK_MASK: 4, PADDING: 8, AUTH_LEN: 16 };
const AEAD_NAME = { 3: 'aes-gcm', 4: 'chacha20-poly1305' };
const bodyKey = (sec, key16) => sec === SEC.CHACHA ? cat(md5(key16), md5(md5(key16))) : key16;

// Replay protection for the 120 s auth-id window (per isolate; the AEAD tag already pins the user).
const seen = new Map();
function fresh(id) {
  const now = Date.now(), k = [...id].join(',');
  for (const [x, t] of seen) if (now - t > 240000) seen.delete(x); else break;
  if (seen.has(k)) return false; seen.set(k, now); return true;
}

/** Try to read the request header from `b`. -> null (need more bytes) | {fail:true} | {hdr, used} */
async function openRequest(cmdKey, b, now = Date.now()) {
  if (b.length < 42) return null;
  const authid = b.subarray(0, 16), plain = await aesBlockDecrypt(kdf16(cmdKey, 'AES Auth ID Encryption'), authid);
  const dv = new DataView(plain.buffer, plain.byteOffset, 16), ts = Number(dv.getBigUint64(0));
  if (crc32(plain.subarray(0, 12)) !== dv.getUint32(12) || Math.abs(now / 1000 - ts) > 120) return { fail: 'auth id' };
  const nonce = b.subarray(34, 42);
  let n;
  try { n = new DataView((await makeAead('aes-gcm', kdf16(cmdKey, 'VMess Header AEAD Key_Length', authid, nonce)).open(kdf12(cmdKey, 'VMess Header AEAD Nonce_Length', authid, nonce), b.subarray(16, 34), authid)).buffer).getUint16(0); }
  catch { return { fail: 'length tag' }; }
  if (b.length < 42 + n + 16) return null;
  let h;
  try { h = await makeAead('aes-gcm', kdf16(cmdKey, 'VMess Header AEAD Key', authid, nonce)).open(kdf12(cmdKey, 'VMess Header AEAD Nonce', authid, nonce), b.subarray(42, 42 + n + 16), authid); }
  catch { return { fail: 'header tag' }; }
  if (!fresh(authid)) return { fail: 'replay' };
  return { hdr: parseHeader(h), used: 42 + n + 16 };
}

function parseHeader(h) {
  if (h.length < 42 || h[0] !== 1) return { fail: 'version' };
  const dv = new DataView(h.buffer, h.byteOffset, h.length), end = h.length - 4;
  if (fnv1a(h.subarray(0, end)) !== dv.getUint32(end)) return { fail: 'checksum' };
  const pad = h[35] >> 4, sec = h[35] & 15, cmd = h[37], port = dv.getUint16(38), a = readAddr(h, 41, h[40], 3, 2);
  if (!a || a[1] + pad > end) return { fail: 'address' };
  return { iv: h.slice(1, 17), key: h.slice(17, 33), v: h[33], opt: h[34], sec, cmd, port, host: a[0] };
}

/** Response header: two AEAD boxes keyed from SHA-256 of the request key / iv. */
async function sealResponse(reqKey, reqIv, v) {
  const rk = sha256(reqKey).subarray(0, 16), ri = sha256(reqIv).subarray(0, 16);
  const l = await makeAead('aes-gcm', kdf16(rk, 'AEAD Resp Header Len Key')).seal(kdf12(ri, 'AEAD Resp Header Len IV'), u16(4));
  const p = await makeAead('aes-gcm', kdf16(rk, 'AEAD Resp Header Key')).seal(kdf12(ri, 'AEAD Resp Header IV'), Uint8Array.of(v, 0, 0, 0));
  return cat(l, p);
}

/** One direction of the chunk stream: nonce = counter(2, BE) | iv[2..12], sizes masked / padded from SHAKE128(iv). */
class Chunks {
  constructor(sec, key16, iv16, opt) {
    this.aead = makeAead(AEAD_NAME[sec], bodyKey(sec, key16)); this.iv = iv16; this.n = 0;
    this.mask = !!(opt & OPT.CHUNK_MASK); this.pad = !!(opt & OPT.PADDING); this.shake = this.mask ? new Shake128(iv16) : null; this.cur = null;
    if (this.pad && !this.mask) throw new Error('padding needs masking');
  }
  nonce() { const o = new Uint8Array(12); o.set(this.iv.subarray(2, 12), 2); o[0] = (this.n >> 8) & 255; o[1] = this.n & 255; this.n = (this.n + 1) & 0xffff; return o; }
  /** Pull every complete chunk out of `rx`: returns payloads (empty array element = end-of-stream marker as `null`). */
  async read(rx) {
    const out = [];
    for (; ;) {
      if (!this.cur) {
        if (rx.length < 2) break; const raw = rx.take(2), pad = this.pad ? this.shake.u16() % 64 : 0, size = this.mask ? ((raw[0] << 8 | raw[1]) ^ this.shake.u16()) : (raw[0] << 8 | raw[1]);
        this.cur = { size, pad };
      }
      if (rx.length < this.cur.size) break;
      const { size, pad } = this.cur; this.cur = null; const blob = rx.take(size);
      if (size === 16 + pad) { out.push(null); break; }
      if (size < 16 + pad) throw new Error('bad chunk');
      out.push(await this.aead.open(this.nonce(), blob.subarray(0, size - pad)));
    }
    return out;
  }
  async write(payload) {
    const pad = this.pad ? this.shake.u16() % 64 : 0, size = payload.length + 16 + pad, enc = this.mask ? size ^ this.shake.u16() : size;
    return cat(u16(enc), await this.aead.seal(this.nonce(), payload), pad ? rnd(pad) : ZERO);
  }
}

const MAX_OUT = 8000;            // clients read each chunk into an 8 KiB buffer

/** Serve one accepted WebSocket as VMess. `dial(host, port)` opens the exit; `meter` counts bytes; `bind(close)` registers cleanup. */
function serveVmess(ws, { user, dial, meter, ctx, early }) {
  const cmdKey = cmdKeyOf(user.uuid), rx = new RxBuf();
  let phase = 0, hdr = null, rd = null, wr = null, remote = null, closed = false, started = Promise.resolve(), eof = false;
  const close = reason => { if (closed) return; closed = true; try { remote && remote.sock && remote.sock.close(); } catch { } try { ws.close(reason ? 1008 : 1000, reason || ''); } catch { } meter.stop(); };
  meter.bind(close);

  async function sendBody(payload) { for (let i = 0; i < payload.length; i += MAX_OUT) { const f = await wr.write(payload.subarray(i, i + MAX_OUT)); meter.add(f.length); ws.send(f); } }
  async function deliver(payloads) {
    for (const p of payloads) {
      if (p === null) { eof = true; try { remote.w && await remote.w.close(); } catch { } return; }
      if (!p.length) continue;
      if (hdr.cmd === 2) { const a = await dnsOverHttps(p).catch(() => null); if (a) await sendBody(a); }   // UDP: DNS only, one datagram per chunk
      else await remote.w.write(p);
    }
  }
  async function onData(raw) {
    const d = toU8(raw); meter.add(d.length); if (meter.dead || closed) return; rx.push(d);
    if (phase === 0) {
      const r = await openRequest(cmdKey, rx.peek(rx.length));
      if (!r) { if (rx.length > 65536) close('header too large'); return; }
      if (r.fail || r.hdr.fail) return close('bad request');
      hdr = r.hdr; rx.take(r.used);
      const sec = hdr.sec, ok = (sec === SEC.AES128GCM || sec === SEC.CHACHA) && (hdr.opt & OPT.CHUNK_STREAM) && !(hdr.opt & OPT.AUTH_LEN) && (hdr.cmd === 1 || (hdr.cmd === 2 && hdr.port === 53));
      if (!ok) return close('unsupported');
      try {
        rd = new Chunks(sec, hdr.key, hdr.iv, hdr.opt);
        const rk = sha256(hdr.key).subarray(0, 16), ri = sha256(hdr.iv).subarray(0, 16); wr = new Chunks(sec, rk, ri, hdr.opt);
      } catch { return close('unsupported'); }
      if (hdr.cmd === 1) {
        try { remote = await dial(hdr.host, hdr.port); } catch { return close('exit failed'); }
        phase = 2;
        const head = await sealResponse(hdr.key, hdr.iv, hdr.v); meter.add(head.length); ws.send(head);
        (async () => {
          try { for (; ;) { const { value, done } = await remote.rd.next(); if (done) break; await sendBody(value); if (meter.dead) break; } } catch { }
          try { if (!closed) { const f = await wr.write(ZERO); ws.send(f); } } catch { }
          close();
        })();
      } else { remote = { w: null }; phase = 2; const head = await sealResponse(hdr.key, hdr.iv, hdr.v); meter.add(head.length); ws.send(head); }
    }
    try { await deliver(await rd.read(rx)); } catch { close('bad chunk'); }
  }
  const run = d => { started = started.then(() => onData(d)).catch(() => close('error')); };
  ws.addEventListener('message', e => run(e.data)); ws.addEventListener('close', () => close()); ws.addEventListener('error', () => close());
  if (early && early.length) run(early);
  return { close };
}

  return { cmdKeyOf, kdf, SEC, openRequest, parseHeader, sealResponse, Chunks, serveVmess };
})();

const __mod_relay = (() => {
  const { direct, viaProxy, timeout } = __mod_proxy;
  const { state, now, GB } = __mod_db;
  const { sha224: sha224Core } = __mod_crypto;
  const { te, td, toU8, cat, hex, uuidBytes, readAddr, dnsOverHttps } = __mod_util;
  const { serveVmess } = __mod_vmess;
  const { serveShadowsocks } = __mod_shadowsocks;
  // --- relay.js ---
// The Xray replacement: VLESS, VMess, Shadowsocks and Trojan over WebSocket are all terminated here, and the bytes
// leave through the user's exit group (SOCKS5 / SOCKS4 / HTTP proxies) or directly. With an upstream set, any protocol
// is relayed unchanged to that server instead. Every connection is metered; volume, expiry and the enabled flag are enforced live.

const sha224 = sha224Core;
const trojanHash = uuid => hex(sha224(te.encode(uuid)));

// ---------- protocol headers ----------
/** -> {cmd, host, port, rest, reply} or null when the header is wrong / belongs to another user */
function parseVless(b, uuid) {
  if (b.length < 24) return null; const id = uuidBytes(uuid);
  for (let i = 0; i < 16; i++) if (b[1 + i] !== id[i]) return null;
  const o = 18 + b[17]; const cmd = b[o], port = (b[o + 1] << 8) | b[o + 2], atyp = b[o + 3]; if (cmd !== 1 && cmd !== 2) return null;
  let host, i = o + 4;
  if (atyp === 2) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 3); if (!a) return null; [host, i] = a; }
  return { cmd, host, port, rest: b.slice(i), reply: Uint8Array.of(b[0], 0) };
}
function parseTrojan(b, uuid) {
  if (b.length < 62) return null; if (new TextDecoder().decode(b.slice(0, 56)) !== trojanHash(uuid) || b[56] !== 13 || b[57] !== 10) return null;
  const cmd = b[58], atyp = b[59]; if (cmd !== 1) return null; let host, i = 60;
  if (atyp === 3) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 4, 3); if (!a) return null; [host, i] = a; }
  const port = (b[i] << 8) | b[i + 1]; return { cmd: 1, host, port, rest: b.slice(i + 4), reply: null };
}

// ---------- usage accounting + enforcement ----------
// Counts every byte of a session, writes it to D1 in batches and kills the session the moment the account stops being
// active: volume is checked locally against what was left at the last write (so the cut is exact for one session and
// within a few KB across sessions), expiry by a timer that re-reads the account when it fires.
const FLUSH_BYTES = 512 * 1024, FLUSH_MS = 30000, MIN_FLUSH = 16 * 1024, TIMER_MAX = 2 ** 31 - 1;
const leftBytes = u => u.limit_gb ? Math.max(0, u.limit_gb * GB - (u.used || 0)) : Infinity;
class Meter {
  constructor(db, user, { wait, onDead } = {}) {
    this.db = db; this.id = user.id; this.n = 0; this.total = 0; this.last = Date.now(); this.dead = false; this.reason = '';
    this.wait = wait || (() => { }); this.onDead = onDead || null; this.kill = null; this.timer = null; this.sync(user);
  }
  sync(u) { this.expire = u.expire || 0; this.left = leftBytes(u); this.thr = Math.min(FLUSH_BYTES, Math.max(MIN_FLUSH, this.left / 4)); }
  /** Register the session's teardown and start watching the expiry. */
  bind(kill) { this.kill = kill; this.arm(); }
  arm() {
    clearTimeout(this.timer); this.timer = null; if (!this.expire || this.dead) return;
    const ms = this.expire * 1000 - Date.now(); if (ms <= 0) return this.die('expired');
    this.timer = setTimeout(() => this.recheck(), Math.min(ms, TIMER_MAX) + 50); if (this.timer && this.timer.unref) this.timer.unref();
  }
  async recheck() {
    try { this.apply(await this.db.one('SELECT * FROM users WHERE id=?', this.id)); }
    catch { if (this.expire * 1000 <= Date.now()) this.die('expired'); else this.arm(); }
  }
  apply(u) {
    if (this.dead) return;
    if (!u || state(u) !== 'active') return this.die(u ? state(u) : 'removed');
    this.sync(u); this.arm();
  }
  die(reason) {
    if (this.dead) return; this.dead = true; this.reason = reason; clearTimeout(this.timer); this.timer = null;
    if (this.onDead) { try { this.onDead(); } catch { } }
    try { this.kill && this.kill('account ' + reason); } catch { }
    this.wait(this.flush());
  }
  add(k) {
    this.n += k; this.total += k; if (this.dead) return;
    if (this.n >= this.left) return this.die('limited');
    if (this.n >= this.thr || Date.now() - this.last > FLUSH_MS) this.wait(this.flush());
  }
  async flush() {
    const k = this.n; this.n = 0; this.last = Date.now(); if (!k) return;
    try { this.apply(await this.db.one('UPDATE users SET used=used+? WHERE id=? RETURNING *', k, this.id)); }
    catch { this.n += k; }
  }
  stop() { clearTimeout(this.timer); this.timer = null; if (this.n) this.wait(this.flush()); }
}

// ---------- exits ----------
async function dialer(db, connect, user) {
  const px = user.grp_id ? await db.all('SELECT host,port,proto FROM proxies WHERE grp_id=? ORDER BY ms LIMIT 4', user.grp_id) : [];
  return async (host, port) => {
    for (const p of px) { try { return await viaProxy(connect, p, host, port); } catch { } }
    if (px.length) throw new Error('every exit proxy of this group failed');
    return direct(connect, host, port);
  };
}

/** Serve one accepted WebSocket (`ws`) for a native user: dispatches on the protocol. */
function serveNative(ws, opts) {
  if (opts.proto === 'vmess') return serveVmess(ws, opts);
  if (opts.proto === 'shadowsocks') return serveShadowsocks(ws, opts);
  return serveVlessTrojan(ws, opts);
}

function serveVlessTrojan(ws, { proto, user, dial, meter, early }) {
  let phase = 0, remote = null, started = Promise.resolve(), udp = false, replyPending = null, closed = false;
  const close = reason => { if (closed) return; closed = true; try { remote && remote.sock && remote.sock.close(); } catch { } try { ws.close(reason ? 1008 : 1000, reason || ''); } catch { } meter.stop(); };
  meter.bind(close);
  const onData = async raw => {
    const data = toU8(raw); meter.add(data.length);
    if (meter.dead || closed) return;
    if (phase === 0) {
      phase = 1;
      const h = proto === 'vless' ? parseVless(data, user.uuid) : parseTrojan(data, user.uuid);
      if (!h) { close(); return; }
      replyPending = h.reply;
      if (h.cmd === 2) {                                   // UDP: DNS only
        if (h.port !== 53) { close(); return; } udp = true; remote = { dns: true }; phase = 2; if (h.rest.length) await onUdp(h.rest); return;
      }
      try { remote = await dial(h.host, h.port); } catch { close(); return; }
      phase = 2; const w = remote.w; if (h.rest.length) await w.write(h.rest);
      (async () => {
        try {
          for (; ;) {
            const { value, done } = await remote.rd.next(); if (done) break;
            let out = value; if (replyPending) { out = cat(replyPending, value); replyPending = null; } meter.add(value.length); ws.send(out); if (meter.dead) break;
          }
        } catch { }
        close();
      })();
      return;
    }
    if (udp) return onUdp(data);
    if (remote && remote.w) await remote.w.write(data);
  };
  async function onUdp(buf) {                              // VLESS UDP framing: [len(2) | dns query]*
    let i = 0; while (i + 2 <= buf.length) {
      const n = (buf[i] << 8) | buf[i + 1]; const q = buf.slice(i + 2, i + 2 + n); i += 2 + n; if (q.length < n) break;
      const a = await dnsOverHttps(q).catch(() => null); if (!a) continue;
      const out = cat(Uint8Array.of(a.length >> 8, a.length & 255), a); meter.add(out.length);
      ws.send(replyPending ? (() => { const r = cat(replyPending, out); replyPending = null; return r; })() : out);
    }
  }
  const run = d => { started = started.then(() => onData(d)).catch(() => close()); };
  ws.addEventListener('message', e => run(e.data)); ws.addEventListener('close', () => close()); ws.addEventListener('error', () => close());
  if (early && early.length) run(early);
  return { close };
}

/** Relay one accepted WebSocket to an upstream server unchanged (any protocol), metering both directions. */
async function serveUpstream(ws, { upstream, path, protocolHeader, meter, fetchFn = fetch }) {
  const url = 'https://' + upstream.replace(/^https?:\/\//, '').replace(/\/.*$/, '') + path;
  const headers = { Upgrade: 'websocket' }; if (protocolHeader) headers['Sec-WebSocket-Protocol'] = protocolHeader;
  let up = null, over = false; const queue = [];
  const end = reason => { if (over) return; over = true; try { up && up.close(); } catch { } try { ws.close(reason ? 1008 : 1000, reason || ''); } catch { } meter.stop(); };
  meter.bind(end);
  ws.addEventListener('message', e => { const d = toU8(e.data); meter.add(d.length); if (meter.dead) return; if (up) up.send(e.data); else queue.push(e.data); });   // buffer until the upstream is open
  ws.addEventListener('close', () => end()); ws.addEventListener('error', () => end());
  try { const r = await timeout(fetchFn(url, { headers }), 10000, 'upstream timeout'); up = r.webSocket; } catch { }
  if (!up) { try { ws.close(1011, 'upstream unreachable'); } catch { } over = true; meter.stop(); return false; }
  up.accept();
  up.addEventListener('message', e => { meter.add(toU8(e.data).length); if (!meter.dead) ws.send(e.data); });
  up.addEventListener('close', () => end()); up.addEventListener('error', () => end());
  for (const d of queue.splice(0)) up.send(d);
  return true;
}

const WS_PATH = /^\/ws\/(?:[A-Za-z0-9_-]+\/)?(vless|vmess|shadowsocks|trojan)\/([0-9a-fA-F-]{36})$/;
function earlyData(h) { if (!h) return null; try { const b = atob(h.replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from(b, c => c.charCodeAt(0)); } catch { return null; } }

  return { toU8, sha224, trojanHash, parseVless, parseTrojan, Meter, dialer, serveNative, serveUpstream, WS_PATH, earlyData };
})();

const __mod_relays = (() => {
  const { now } = __mod_db;
  // --- relays.js ---
// Remote relays (Vercel / Netlify / Railway): a tiny proxy on another platform that forwards visitors to this Worker.
// A Worker request is short, so a deploy is a small state machine: /deploy runs the first calls, then every poll of
// /api/relays/<p> advances it one step (build -> reach panel -> ping) until it finishes.

const MARK = 'xr-panel-ok';
class RelayError extends Error { }
const STEPS = [['auth', 'Token'], ['create', 'Deploy'], ['build', 'Build'], ['verify', 'Reach panel'], ['ping', 'Ping']];
const fresh = () => STEPS.map(([k, l]) => ({ k, l, st: 'wait', m: '' }));
const rand = () => [...crypto.getRandomValues(new Uint8Array(3))].map(b => b.toString(16).padStart(2, '0')).join('');
const b64 = s => btoa(unescape(encodeURIComponent(s)));

async function req(method, url, token, body, o0 = {}) {
  const o = typeof o0 === 'function' ? { fetch: o0 } : (o0 || {});
  const h = { Accept: 'application/json', 'User-Agent': 'xr-panel' }; if (token) h.Authorization = 'Bearer ' + token;
  let b = o.raw; if (body !== undefined) { h['Content-Type'] = 'application/json'; b = JSON.stringify(body); } if (o.ctype) h['Content-Type'] = o.ctype;
  const r = await (o.fetch || fetch)(url, { method, headers: h, body: b }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 300) }; } return [r.status, j];
}

// ---------- Vercel ----------
const VERCEL_RELAY = `// xr relay (Vercel). Forwards HTTP and WebSocket traffic to the panel.
const http = require('http'), https = require('https');
const { WebSocketServer, WebSocket } = require('ws');
const TARGET = new URL(__TARGET__), HOST = TARGET.hostname, PORT = TARGET.port || 443;
const SKIP = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','host']);
function fwd(h) { const o = {}; for (const k in h) if (!SKIP.has(k)) o[k] = h[k]; o.host = HOST; return o; }
const server = http.createServer((req, res) => {
  const up = https.request({ hostname: HOST, port: PORT, method: req.method, path: req.url, headers: fwd(req.headers), servername: HOST }, (r) => {
    const h = { ...r.headers }; delete h['transfer-encoding']; delete h['connection']; delete h['keep-alive']; res.writeHead(r.statusCode, h); r.pipe(res); });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }); res.end('relay: panel unreachable'); });
  res.on('close', () => up.destroy()); req.pipe(up);
});
const wss = new WebSocketServer({ server, perMessageDeflate: false });
wss.on('connection', (client, req) => {
  const protos = (req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const up = new WebSocket('wss://' + HOST + ':' + PORT + req.url, protos, { headers: { 'User-Agent': req.headers['user-agent'] || 'relay' }, servername: HOST, perMessageDeflate: false });
  const queue = []; const kill = () => { try { client.terminate(); } catch (e) {} try { up.terminate(); } catch (e) {} };
  up.on('open', () => { for (const [d, b] of queue) up.send(d, { binary: b }); queue.length = 0; });
  client.on('message', (d, bin) => { if (up.readyState === WebSocket.OPEN) up.send(d, { binary: bin }); else if (up.readyState === WebSocket.CONNECTING) queue.push([d, bin]); });
  up.on('message', (d, bin) => { if (client.readyState === WebSocket.OPEN) client.send(d, { binary: bin }); });
  client.on('close', kill); up.on('close', kill); client.on('error', kill); up.on('error', kill);
});
module.exports = server; module.exports.default = server;
`;
const vercel = {
  name: 'Vercel', ws: 'beta', token_url: 'https://vercel.com/account/settings/tokens',
  hint: 'Deploys a Node function that forwards HTTP and WebSocket traffic to the panel. WebSocket on Vercel Functions is in beta: each connection is cut after about 5 minutes and the client reconnects by itself.',
  files: url => [['api/relay.js', VERCEL_RELAY.replace('__TARGET__', JSON.stringify(url))], ['package.json', '{"name":"xr-relay","version":"1.0.0","private":true,"dependencies":{"ws":"8.18.0"}}'], ['vercel.json', '{"rewrites":[{"source":"/(.*)","destination":"/api/relay"}]}']]
    .map(([file, d]) => ({ file, encoding: 'base64', data: b64(d) })),
  err: (j, c) => ((j && j.error) || {}).message || 'HTTP ' + c,
  async start(t, run, f) {
    const API = 'https://api.vercel.com'; run.step('auth', 'run');
    let [c, j] = await req('GET', API + '/v2/user', t, undefined, f); if (c === 401 || c === 403) throw new RelayError('Vercel rejected this token (create one at vercel.com/account/settings/tokens).'); if (c !== 200) throw new RelayError('Vercel: ' + this.err(j, c));
    run.step('auth', 'ok', (j.user || {}).username || '');
    const name = run.ref.name || 'xr-relay-' + rand(); run.step('create', 'run', name);
    [c, j] = await req('POST', API + '/v13/deployments?skipAutoDetectionConfirmation=1&forceNew=1', t, { name, target: 'production', files: this.files(run.upUrl), projectSettings: { framework: null, buildCommand: null, outputDirectory: null } }, f);
    if (c >= 300) throw new RelayError('Vercel: ' + this.err(j, c));
    Object.assign(run.ref, { name, project: j.projectId || name, dep: j.id, phase: 'build' }); run.step('create', 'ok', name); run.step('build', 'run', 'queued');
  },
  async tick(t, run, f) {
    const API = 'https://api.vercel.com', [c, j] = await req('GET', `${API}/v13/deployments/${run.ref.dep}`, t, undefined, f); const rs = (j.readyState || j.status || '').toUpperCase();
    if (['ERROR', 'CANCELED', 'BLOCKED'].includes(rs)) throw new RelayError(`Vercel build ${rs.toLowerCase()}: ${j.errorMessage || 'see the Vercel dashboard'}`);
    if (rs !== 'READY') { run.step('build', 'run', rs.toLowerCase() || 'waiting'); return false; }
    await req('PATCH', `${API}/v9/projects/${run.ref.project}`, t, { ssoProtection: null }, f);       // production domain must be public
    const al = (j.alias || []).filter(a => a.endsWith('.vercel.app')); const dom = al.find(a => a === run.ref.name + '.vercel.app') || [...al].sort((a, b) => a.length - b.length)[0] || j.url || '';
    if (!dom) throw new RelayError('Vercel did not return a domain'); run.step('build', 'ok', 'ready'); run.domain = dom; return true;
  },
  async remove(t, ref, f) { const pid = ref.project || ref.name; if (!pid) return; const [c, j] = await req('DELETE', `https://api.vercel.com/v9/projects/${pid}`, t, undefined, f); if (![200, 204, 404].includes(c)) throw new RelayError('Vercel: ' + this.err(j, c)); },
};

// ---------- Netlify (static site with one proxy rule; zip written by hand) ----------
const crcT = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = u8 => { let c = 0xFFFFFFFF; for (const b of u8) c = crcT[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
function zip(files) {                              // stored (no compression), enough for two tiny files
  const te = new TextEncoder(), parts = [], cd = []; let off = 0;
  for (const [name, text] of files) {
    const n = te.encode(name), d = te.encode(text), c = crc32(d), h = new DataView(new ArrayBuffer(30)); h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint32(14, c, true); h.setUint32(18, d.length, true); h.setUint32(22, d.length, true); h.setUint16(26, n.length, true);
    parts.push(new Uint8Array(h.buffer), n, d);
    const e = new DataView(new ArrayBuffer(46)); e.setUint32(0, 0x02014b50, true); e.setUint16(4, 20, true); e.setUint16(6, 20, true); e.setUint32(16, c, true); e.setUint32(20, d.length, true); e.setUint32(24, d.length, true); e.setUint16(28, n.length, true); e.setUint32(42, off, true); cd.push(new Uint8Array(e.buffer), n);
    off += 30 + n.length + d.length;
  }
  const size = cd.reduce((a, x) => a + x.length, 0), end = new DataView(new ArrayBuffer(22)); end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true); end.setUint32(12, size, true); end.setUint32(16, off, true);
  const all = [...parts, ...cd, new Uint8Array(end.buffer)], out = new Uint8Array(all.reduce((a, x) => a + x.length, 0)); let i = 0; for (const x of all) { out.set(x, i); i += x.length; } return out;
}
const netlify = {
  name: 'Netlify', ws: 'http', token_url: 'https://app.netlify.com/user/applications#personal-access-tokens',
  hint: 'Deploys a static site with one proxy rule that forwards every request to the panel. Netlify proxies are HTTP only: the panel and subscription pages work through it, but WebSocket configs do not (Netlify has no WebSocket upgrade, 26 s proxy timeout).',
  err: (j, c) => (j && (j.message || j.raw)) || 'HTTP ' + c,
  async start(t, run, f) {
    const API = 'https://api.netlify.com/api/v1'; run.step('auth', 'run');
    let [c, j] = await req('GET', API + '/user', t, undefined, f); if (c === 401 || c === 403) throw new RelayError('Netlify rejected this token (create a personal access token in User settings > Applications).'); if (c !== 200) throw new RelayError('Netlify: ' + this.err(j, c));
    run.step('auth', 'ok', j.email || j.full_name || ''); run.step('create', 'run'); let sid = run.ref.site, dom = run.ref.domain;
    if (!sid) {
      let made = false; for (let i = 0; i < 4 && !made; i++) { [c, j] = await req('POST', API + '/sites', t, { name: 'xr-relay-' + rand() }, f); if (c === 200 || c === 201) made = true; else if (c !== 422) throw new RelayError('Netlify: ' + this.err(j, c)); }
      if (!made) throw new RelayError('Netlify could not create a site: ' + this.err(j, c)); sid = j.id; dom = `${j.name}.netlify.app`; Object.assign(run.ref, { site: sid, domain: dom });
    }
    [c, j] = await req('POST', `${API}/sites/${sid}/deploys`, t, undefined, { raw: zip([['_redirects', `/*  ${run.upUrl}/:splat  200!\n`], ['index.html', '<!doctype html><meta charset="utf-8"><title>relay</title>\n']]), ctype: 'application/zip', fetch: f });
    if (c >= 300) throw new RelayError('Netlify: ' + this.err(j, c)); run.ref.dep = j.id; run.ref.phase = 'build'; run.step('create', 'ok', dom); run.step('build', 'run', 'uploading');
  },
  async tick(t, run, f) {
    const [c, j] = await req('GET', `https://api.netlify.com/api/v1/deploys/${run.ref.dep}`, t, undefined, f), st = (j.state || '').toLowerCase();
    if (['error', 'rejected'].includes(st)) throw new RelayError('Netlify deploy failed: ' + (j.error_message || st));
    if (st !== 'ready') { run.step('build', 'run', st || 'waiting'); return false; } run.step('build', 'ok', 'ready'); run.domain = run.ref.domain; return true;
  },
  async remove(t, ref, f) { if (!ref.site) return; const [c, j] = await req('DELETE', `https://api.netlify.com/api/v1/sites/${ref.site}`, t, undefined, f); if (![200, 204, 404].includes(c)) throw new RelayError('Netlify: ' + this.err(j, c)); },
};

// ---------- Railway (stock nginx image configured through variables) ----------
const NGINX = `map $http_upgrade $connection_upgrade { default upgrade; '' close; }
server {
  listen 8080 default_server;
  server_name _;
  resolver 1.1.1.1 8.8.8.8 valid=60s ipv6=off;
  client_max_body_size 0;
  location / {
    set $up "https://__HOST__:__PORT__";
    proxy_pass $up;
    proxy_http_version 1.1;
    proxy_ssl_server_name on;
    proxy_ssl_name __HOST__;
    proxy_set_header Host __HOST__;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_read_timeout 1d;
    proxy_send_timeout 1d;
  }
}
`;
const RW_START = `sh -c 'printf "%s" "$RELAY_CONF" > /etc/nginx/conf.d/default.conf && exec nginx -g "daemon off;"'`;
const railway = {
  name: 'Railway', ws: 'ws', token_url: 'https://railway.com/account/tokens',
  hint: 'Deploys the nginx image as a Railway service that forwards HTTP and WebSocket traffic to the panel. Use an Account token (create it with “No workspace”).',
  async gql(t, query, variables, f) {
    const [c, j] = await req('POST', 'https://backboard.railway.com/graphql/v2', t, { query, variables: variables || {} }, f);
    if (c === 401 || c === 403) throw new RelayError('Railway rejected this token (use an Account token from railway.com/account/tokens).');
    if (j.errors) throw new RelayError('Railway: ' + String(j.errors[0].message || 'error').slice(0, 200)); if (c >= 300 || !j.data) throw new RelayError('Railway: HTTP ' + c); return j.data;
  },
  async start(t, run, f) {
    run.step('auth', 'run'); let who = {}; try { who = (await this.gql(t, 'query{me{name email}}', null, f)).me || {}; } catch (e) { if (/rejected/.test(e.message)) throw e; }
    run.step('auth', 'ok', who.email || who.name || ''); run.step('create', 'run');
    const conf = NGINX.replaceAll('__HOST__', run.upHost).replaceAll('__PORT__', String(run.upPort)), ref = run.ref;
    if (ref.service && ref.env) { try { await this.gql(t, 'mutation($i:VariableCollectionUpsertInput!){variableCollectionUpsert(input:$i)}', { i: { projectId: ref.project, environmentId: ref.env, serviceId: ref.service, variables: { RELAY_CONF: conf, PORT: '8080' }, skipDeploys: true } }, f); } catch { for (const k of Object.keys(ref)) delete ref[k]; } }
    if (!ref.service) {
      const d = (await this.gql(t, 'mutation($i:ProjectCreateInput!){projectCreate(input:$i){id environments{edges{node{id name}}}}}', { i: { name: 'xr-relay-' + rand(), defaultEnvironmentName: 'production' } }, f)).projectCreate;
      Object.assign(ref, { project: d.id, env: d.environments.edges[0].node.id });
      ref.service = (await this.gql(t, 'mutation($i:ServiceCreateInput!){serviceCreate(input:$i){id}}', { i: { projectId: d.id, name: 'relay', source: { image: 'nginx:alpine' }, variables: { RELAY_CONF: conf, PORT: '8080' } } }, f)).serviceCreate.id;
    }
    for (let i = 0; i < 6; i++) { try { await this.gql(t, 'mutation($s:String!,$e:String!,$i:ServiceInstanceUpdateInput!){serviceInstanceUpdate(serviceId:$s,environmentId:$e,input:$i)}', { s: ref.service, e: ref.env, i: { startCommand: RW_START } }, f); break; } catch (e) { if (i === 5) throw e; await new Promise(r => setTimeout(r, 1500)); } }
    await this.gql(t, 'mutation($s:String!,$e:String!){serviceInstanceDeploy(serviceId:$s,environmentId:$e)}', { s: ref.service, e: ref.env }, f);
    if (!ref.domain) ref.domain = (await this.gql(t, 'mutation($i:ServiceDomainCreateInput!){serviceDomainCreate(input:$i){domain}}', { i: { serviceId: ref.service, environmentId: ref.env, targetPort: 8080 } }, f)).serviceDomainCreate.domain;
    run.step('create', 'ok', ref.domain); ref.phase = 'build'; run.step('build', 'run', 'queued');
  },
  async tick(t, run, f) {
    const r = run.ref, e = (await this.gql(t, 'query($i:DeploymentListInput!){deployments(input:$i,first:1){edges{node{id status}}}}', { i: { projectId: r.project, serviceId: r.service, environmentId: r.env } }, f)).deployments.edges, st = e.length ? e[0].node.status : 'WAITING';
    if (['FAILED', 'CRASHED'].includes(st)) throw new RelayError(`Railway deployment ${st.toLowerCase()}. Open the project on railway.com to read its logs.`);
    if (st !== 'SUCCESS') { run.step('build', 'run', st.toLowerCase()); return false; } run.step('build', 'ok', 'success'); run.domain = r.domain; return true;
  },
  async remove(t, ref, f) { if (!ref.project) return; try { await this.gql(t, 'mutation($id:String!){projectDelete(id:$id)}', { id: ref.project }, f); } catch (e) { if (!/not found/i.test(e.message)) throw e; } },
};
const PROVIDERS = { vercel, netlify, railway };
const WS_TAG = { ws: 'WebSocket', beta: 'WS beta', http: 'HTTP only' };

// ---------- persistence + state machine ----------
const j = (s, d) => { try { return JSON.parse(s) ?? d; } catch { return d; } };
async function row(db, p) { return (await db.one('SELECT * FROM relays WHERE p=?', p)) || {}; }
async function save(db, p, kw) {
  if (!(await db.one('SELECT 1 x FROM relays WHERE p=?', p))) await db.run("INSERT INTO relays(p,status) VALUES(?,'idle')", p);
  kw.upd = now(); const ks = Object.keys(kw); await db.run(`UPDATE relays SET ${ks.map(k => k + '=?').join(',')} WHERE p=?`, ...ks.map(k => kw[k]), p);
}
async function view(db, p) {
  const r = await row(db, p), m = PROVIDERS[p];
  return { id: p, name: m.name, ws: m.ws, tag: WS_TAG[m.ws], hint: m.hint, token_url: m.token_url, status: r.status || 'idle', steps: j(r.steps, null) || fresh(), domain: r.domain || '', err: r.err || '', ping: j(r.ping, null), has_token: !!r.token, has_ref: Object.keys(j(r.ref, {})).length > 0 };
}
const allViews = async db => Promise.all(Object.keys(PROVIDERS).map(p => view(db, p)));
const active = async db => (await allViews(db)).filter(v => v.domain);

class Run {
  constructor(db, p, steps, ref, up) { Object.assign(this, { db, p, steps, ref, domain: '', upHost: up[0], upPort: up[1], upUrl: 'https://' + up[0] + (up[1] === 443 ? '' : ':' + up[1]) }); }
  step(k, st, msg = '') { for (const s of this.steps) if (s.k === k) { s.st = st; s.m = String(msg).slice(0, 40); } }
  async flush(extra = {}) { await save(this.db, this.p, { steps: JSON.stringify(this.steps), ref: JSON.stringify(this.ref), ...extra }); }
  async fail(msg) { for (const s of this.steps) if (s.st === 'run') s.st = 'fail'; await this.flush({ status: 'failed', err: msg }); }
}

async function ping(domain, f = fetch, n = 2) {
  const web = []; for (let i = 0; i < n; i++) { const t = Date.now(); try { const r = await f(`https://${domain}/relay-check?t=${t}`, { headers: { 'Cache-Control': 'no-cache' } }); if (r.status === 200 && (await r.text()).includes(MARK)) web.push(Math.max(1, Date.now() - t)); } catch { } }
  return { tcp: null, web: web.length ? Math.min(...web) : null, ok: web.length > 0, at: now() };
}

/** First phase: auth + create. Returns an error string or null. */
async function startDeploy(db, p, token, up, f = fetch) {
  const m = PROVIDERS[p]; if (!m) return 'Unknown relay'; const r = await row(db, p);
  if (r.status === 'deploying' && now() - (r.upd || 0) < 900) return 'A deploy is already running';
  token = token || r.token || ''; if (!token) return 'Paste an API token first';
  const run = new Run(db, p, fresh(), j(r.ref, {}), up); await save(db, p, { token, status: 'deploying', steps: JSON.stringify(run.steps), err: '' });
  try { await m.start(token, run, f); await run.flush({ status: 'deploying' }); } catch (e) { await run.fail(e instanceof RelayError ? e.message : 'Unexpected error: ' + e.message); }
  return null;
}
/** Advance a running deploy by one step; called by every status poll. */
async function advance(db, p, up, f = fetch) {
  const m = PROVIDERS[p], r = await row(db, p); if (r.status !== 'deploying') return;
  const ref = j(r.ref, {}); if (!ref.phase) return; const run = new Run(db, p, j(r.steps, null) || fresh(), ref, up); run.domain = r.domain || '';
  try {
    if (ref.phase === 'build') {
      if (now() - (r.upd || 0) > 900) throw new RelayError('Deploy timed out'); if (!(await m.tick(r.token, run, f))) { await run.flush(); return; }
      ref.phase = 'verify'; ref.vstart = now(); ref.vtries = 0; run.step('verify', 'run', 'waiting'); await run.flush({ domain: run.domain }); return;
    }
    if (ref.phase === 'verify') {
      const dom = r.domain || run.domain; const t = Date.now(); let code = 0, body = '';
      try { const x = await f(`https://${dom}/relay-check?t=${t}`, { headers: { 'Cache-Control': 'no-cache' } }); code = x.status; body = await x.text(); } catch { }
      if (code === 200 && body.includes(MARK)) { run.step('verify', 'ok', `${Date.now() - t} ms`); ref.phase = 'ping'; run.step('ping', 'run'); await run.flush(); return; }
      const why = ({ 0: 'not reachable yet', 401: 'blocked by the platform (401)', 404: 'up, not forwarding yet (404)' })[code] || (code === 200 ? 'answers, but not from the panel (200)' : 'HTTP ' + code);
      ref.vtries = (ref.vtries || 0) + 1; run.step('verify', 'run', why);
      if (now() - ref.vstart > 150) throw new RelayError(`Relay never reached the panel: ${why}. Check the panel domain/port in Settings.`);
      await run.flush(); return;
    }
    if (ref.phase === 'ping') {
      const dom = r.domain, pg = await ping(dom, f); run.step('ping', pg.ok ? 'ok' : 'fail', pg.ok ? `${pg.web} ms` : 'no answer'); delete ref.phase;
      await run.flush({ status: 'ok', ping: JSON.stringify(pg), err: '' });
    }
  } catch (e) { delete ref.phase; await run.fail(e instanceof RelayError ? e.message : 'Unexpected error: ' + e.message); }
}
async function doPing(db, p, f = fetch) { const d = (await row(db, p)).domain; if (!d) return null; const pg = await ping(d, f, 3); await save(db, p, { ping: JSON.stringify(pg) }); return pg; }
async function remove(db, p, f = fetch) {
  const r = await row(db, p); if (!r.p) return null;
  try { await PROVIDERS[p].remove(r.token || '', j(r.ref, {}), f); } catch (e) { return e.message; } await db.run('DELETE FROM relays WHERE p=?', p); return null;
}

  return { MARK, RelayError, STEPS, zip, PROVIDERS, WS_TAG, row, save, view, allViews, active, ping, startDeploy, advance, doPing, remove };
})();

const __mod_static = (() => {
  // --- static.js ---
// GENERATED from ./public/static. Do not edit.
const STATIC = {"a.js":["text/javascript; charset=utf-8","const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);\n$('#menu')&&($('#menu').onclick=()=>document.body.classList.toggle('nav'));\n$('#scrim')&&($('#scrim').onclick=()=>document.body.classList.remove('nav'));\n$$('.acc>.hd').forEach(h=>h.onclick=()=>h.parentElement.classList.toggle('open'));\n$$('.pn').forEach(p=>p.inert=!p.classList.contains('open'));\n$$('[data-pn]').forEach(b=>b.onclick=()=>{const a=b.closest('.acc,.box'),p=a.querySelector('.pn[data-p=\"'+b.dataset.pn+'\"]'),o=!p.classList.contains('open');\n a.querySelectorAll('.pn').forEach(x=>{x.classList.remove('open');x.inert=true});a.querySelectorAll('[data-pn]').forEach(x=>x.classList.remove('on'));\n if(o){p.classList.add('open');p.inert=false;b.classList.add('on')}});\n$$('[data-copy]').forEach(b=>b.onclick=e=>{e.stopPropagation();const t=b.dataset.copy,l=b.dataset.l=b.dataset.l||b.textContent,ok=()=>{b.textContent='Copied';setTimeout(()=>b.textContent=l,1400)};\n if(navigator.clipboard&&isSecureContext)navigator.clipboard.writeText(t).then(ok);else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();ok()}});\nif($('[data-bar]'))setInterval(async()=>{try{const r=await(await fetch('/api/status')).json();for(const k in r){const e=$('[data-k='+k+']');if(e)e.textContent=r[k]}$$('[data-bar]').forEach(b=>b.style.setProperty('--v',r[b.dataset.bar]))}catch(e){}},4000);\n\n$$('form[data-slow]').forEach(f=>f.addEventListener('submit',()=>{const b=f.querySelector('button:not([type=button])');b.disabled=true;b.textContent='Checking…'}));\n$$('[data-check]').forEach(b=>b.onclick=async()=>{const f=b.closest('form'),r=f.querySelector('.res'),h=f.querySelector('[name=host]').value,p=f.querySelector('[name=port]').value;\n r.innerHTML='<span class=\"chip\" style=\"border-color:var(--yl);color:var(--yl)\">Checking…</span>';\n try{const d=await(await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:h,port:p})})).json();\n  if(d.error){r.innerHTML='<span class=\"chip\">'+d.error+'</span>';return}\n  const esc=t=>String(t).replace(/[&<>\"']/g,c=>'&#'+c.charCodeAt(0)+';'),G=d.geo&&/^[a-z]{2}$/.test(d.geo.cc)?'<span class=\"chip ok\"><img class=\"flag\" src=\"/flag/'+d.geo.cc+'.svg\" alt=\"\"> → '+esc(d.geo.name)+'</span>':'<span class=\"chip\">Country unknown → Other</span>';\n  r.innerHTML=G+(d.best?'<span class=\"chip ok best\">✓ Fastest: '+d.best.proto+' '+d.best.ms+'ms</span>':'<span class=\"chip\">✕ No protocol connected</span>')+d.results.map(x=>'<span class=\"chip'+(x.ms!==null?' ok':'')+'\">'+(x.ms!==null?'✓ ':'✕ ')+x.proto+(x.ms!==null?' '+x.ms+'ms':'')+'</span>').join('')\n }catch(e){r.innerHTML='<span class=\"chip\">Check failed</span>'}});\n\n/* locks: zoom + text selection/copy outside inputs */\nconst okEl=t=>((t&&t.nodeType===3?t.parentElement:t)||document.body).closest('input,textarea,select');\n['gesturestart','gesturechange','gestureend'].forEach(t=>document.addEventListener(t,e=>e.preventDefault()));\ndocument.addEventListener('touchmove',e=>{if(e.touches.length>1)e.preventDefault()},{passive:false});\naddEventListener('wheel',e=>{if(e.ctrlKey)e.preventDefault()},{passive:false});\naddEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&['+','-','=','0'].includes(e.key))e.preventDefault()});\n['selectstart','contextmenu','copy','cut','dragstart'].forEach(t=>document.addEventListener(t,e=>{if(!okEl(e.target))e.preventDefault()}));\n/* theme toggle: glass button, Telegram-stars style burst + page shockwave */\nconst STAR='<svg viewBox=\"0 0 24 24\"><path d=\"M12 2l2.9 6.6 7.1.6-5.4 4.7 1.7 7-6.3-3.8-6.3 3.8 1.7-7L2 9.2l7.1-.6z\"/></svg>';\nfunction burst(x,y){const rg=document.createElement('div');rg.className='ring';rg.style.left=x+'px';rg.style.top=y+'px';document.body.appendChild(rg);\n rg.animate([{transform:'translate(-50%,-50%) scale(.5)',opacity:.95},{transform:'translate(-50%,-50%) scale(3.4)',opacity:0}],{duration:900,easing:'cubic-bezier(.2,.8,.2,1)'}).onfinish=()=>rg.remove();\n for(let i=0;i<18;i++){const s=document.createElement('i');s.className='star';s.innerHTML=STAR;const z=10+Math.random()*16;\n  s.style.cssText=`left:${x}px;top:${y}px;width:${z}px;height:${z}px;color:${['#ffb02e','#ffd35c','#ff8a3d'][i%3]}`;document.body.appendChild(s);\n  const a=Math.random()*6.283,d=50+Math.random()*110,dx=Math.cos(a)*d,dy=Math.sin(a)*d-30,r1=(Math.random()-.5)*240,r2=(Math.random()-.5)*400;\n  s.animate([{transform:'translate(-50%,-50%) scale(.2) rotate(0)',opacity:1},{transform:`translate(calc(-50% + ${dx}px),calc(-50% + ${dy}px)) scale(1) rotate(${r1}deg)`,opacity:1,offset:.55},\n   {transform:`translate(calc(-50% + ${dx*1.15}px),calc(-50% + ${dy+55}px)) scale(.3) rotate(${r2}deg)`,opacity:0}],{duration:900+Math.random()*500,easing:'cubic-bezier(.2,.8,.2,1)'}).onfinish=()=>s.remove()}}\nfunction wobble(x,y){if(matchMedia('(prefers-reduced-motion: reduce)').matches)return;\n /* Web Animations API: never touches classes, so the elements' own CSS animations (rise) are not re-triggered */\n const E='cubic-bezier(.32,.72,0,1)',P='perspective(700px)';\n $$('main .box,main .acc,main h1,main .toast,main .login form,main .chip,.side a,.top').forEach(e=>{\n  const r=e.getBoundingClientRect(),dx=r.x+r.width/2-x,dy=r.y+r.height/2-y,d=Math.hypot(dx,dy)||1,tx=dx/d*7,ty=dy/d*7;\n  e._w&&e._w.cancel();\n  e._w=e.animate([{transform:'none',easing:E},\n   {transform:`${P} translate(${tx}px,${ty}px) rotateX(5deg) rotateY(-4deg) scale(1.025)`,offset:.22,easing:E},\n   {transform:`${P} translate(${-tx*.6}px,${-ty*.6}px) rotateX(-3deg) rotateY(2.5deg) scale(.99)`,offset:.48,easing:E},\n   {transform:`${P} rotateX(1.2deg) scale(1.005)`,offset:.72,easing:E},\n   {transform:'none'}],{duration:1400,delay:Math.min(d/1800,.5)*1000,fill:'backwards'})})}\n$('#theme').onclick=e=>{const b=e.currentTarget,r=b.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,H=document.documentElement,n=H.dataset.theme==='light'?'dark':'light';\n b.animate([{transform:'scale(1)'},{transform:'scale(.8)'},{transform:'scale(1.14)'},{transform:'scale(1)'}],{duration:750,easing:'cubic-bezier(.32,.72,0,1)'});\n burst(x,y);wobble(x,y);H.classList.add('theming');setTimeout(()=>H.classList.remove('theming'),1000);\n setTimeout(()=>{H.dataset.theme=n;try{localStorage.setItem('th',n)}catch(_){}},120)};\n\n/* config-domain picker: custom row */\n$$('[data-custom]').forEach(b=>b.onclick=()=>{const r=b.closest('.in').querySelector('[data-cust]');r.hidden=!r.hidden;if(!r.hidden)r.querySelector('input').focus()});\n/* relays: live tracking + ping */\nconst esc=t=>String(t).replace(/[&<>\"']/g,c=>'&#'+c.charCodeAt(0)+';'),SYM={ok:'✓',run:'…',fail:'✕',wait:'·'};\nfunction relayPing(acc,pg){const e=acc.querySelector('[data-ping]');if(!pg)return;\n e.innerHTML=(pg.ok?'<span class=\"chip ok\">panel ⇄ relay · '+pg.web+' ms</span>':'<span class=\"chip\">✕ no answer through the relay</span>')+(pg.tcp?'<span class=\"chip ok\">TCP '+pg.tcp+' ms</span>':'')}\nfunction relayView(acc,v){acc.dataset.st=v.status;\n const t=acc.querySelector('[data-tag]');t.textContent={idle:'off',deploying:'deploying',ok:'on',failed:'failed'}[v.status];t.className='tag'+(v.status==='ok'?' active':v.status==='failed'?' expired':'');\n const s=acc.querySelector('[data-steps]');s.hidden=v.status==='idle';\n s.innerHTML=v.steps.map(x=>'<span class=\"chip '+x.st+'\">'+SYM[x.st]+' '+esc(x.l)+(x.m&&(x.st==='ok'||x.st==='run')?' · '+esc(x.m):'')+'</span>').join('');\n const er=acc.querySelector('[data-err]');er.hidden=!v.err;er.textContent=v.err;\n const o=acc.querySelector('[data-out]');o.hidden=!v.domain;acc.querySelector('[data-dom]').textContent=v.domain;\n const c=o.querySelector('[data-copy]');if(c)c.dataset.copy=v.domain;relayPing(acc,v.ping);\n acc.querySelector('[data-go]').disabled=v.status==='deploying'}\nasync function relayPoll(acc){const p=acc.dataset.relay;\n for(;;){try{const v=await(await fetch('/api/relays/'+p)).json();relayView(acc,v);\n   if(v.status!=='deploying'){if(v.status==='ok'&&!acc.dataset.done){acc.dataset.done=1;setTimeout(()=>location.replace('/relays?o='+p),1200)}return}}catch(e){}\n  await new Promise(r=>setTimeout(r,1500))}}\n$$('[data-relay]').forEach(acc=>{if(acc.dataset.st==='deploying')relayPoll(acc);\n const b=acc.querySelector('[data-rping]');if(!b)return;\n const run=async()=>{b.disabled=true;b.textContent='Pinging…';try{const d=await(await fetch('/api/relays/'+acc.dataset.relay+'/ping',{method:'POST'})).json();relayPing(acc,d.ping)}catch(e){}b.disabled=false;b.textContent='Ping'};\n b.onclick=run;if(acc.dataset.st==='ok'){run();setInterval(run,30000)}});\n\n/* settings: test-site list (add / remove rows) */\n$$('[data-sites]').forEach(f=>{const L=f.querySelector('[data-list]');\n f.addEventListener('click',e=>{const r=e.target.closest('[data-rm]');if(r){r.closest('.site').remove();return}\n  if(e.target.closest('[data-add]')){const d=document.createElement('div');d.className='row site';\n   d.innerHTML='<input name=\"site\" placeholder=\"https://example.com/generate_204\" autocapitalize=\"off\" autocomplete=\"off\" spellcheck=\"false\"><button type=\"button\" class=\"btn o pk\" data-rm aria-label=\"Remove\">−</button>';L.append(d);d.querySelector('input').focus()}});\n f.addEventListener('submit',()=>L.querySelectorAll('input').forEach(i=>{if(!i.value.trim())i.closest('.site').remove()}))});\n\n/* settings: Telegram data-center test */ $$('[data-tgtest]').forEach(b=>b.onclick=async()=>{const o=$('[data-tgout]');b.disabled=true;o.innerHTML='<span class=\"chip\">Testing…</span>';\n try{const d=await(await fetch('/api/tg/test',{method:'POST'})).json();o.innerHTML=d.results.map(x=>'<span class=\"chip'+(x.ok?' ok':'')+'\">'+(x.ok?'✓ ':'✕ ')+'DC'+x.dc+(x.ok?' · '+x.ms+' ms':'')+'</span>').join('')}catch(e){o.innerHTML='<span class=\"chip\">Test failed</span>'}b.disabled=false});\n"],"bolt.svg":["image/svg+xml","<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\"><rect width=\"24\" height=\"24\" rx=\"6\" fill=\"#080b0a\"/><path d=\"M13.2 2.5 5 13.6h5.6l-1 7.9 9.4-12.1h-5.8z\" fill=\"#52e39a\" stroke=\"#52e39a\" stroke-width=\"1\" stroke-linejoin=\"round\"/></svg>"],"convert.js":["text/javascript; charset=utf-8","/* xr PANEL converter (window.CONV): v2ray links <-> Clash <-> sing-box, bulk edit, QR, WireGuard -> Clash / AmneziaWG / Wiresock. All in the browser. */\n(() => {\n'use strict';\nconst E = t => String(t).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\nconst b64d = s => { s = s.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\\s+/g, ''); while (s.length % 4) s += '='; try { const bin = atob(s); return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))); } catch (e) { return null; } };\nconst b64e = s => btoa(String.fromCharCode(...new TextEncoder().encode(s)));\nconst dec = s => { try { return decodeURIComponent(s); } catch (e) { return s; } };\nconst num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };\nconst csv = v => (v ? String(v).split(',').map(s => s.trim()).filter(Boolean) : []);\nconst hostFmt = h => h.includes(':') && !h.startsWith('[') ? '[' + h + ']' : h;\n\n/* ---------- YAML (the subset Clash files use) ---------- */\nfunction yamlParse(src) {\n  const L = []; for (const raw of src.split(/\\r?\\n/)) { if (/^\\s*(#|---|\\.\\.\\.)/.test(raw) || !raw.trim()) continue; const t = stripComment(raw); if (t.trim()) L.push({ ind: t.match(/^ */)[0].length, t: t.trim() }); }\n  let i = 0;\n  function stripComment(s) { let q = null; for (let k = 0; k < s.length; k++) { const c = s[k]; if (q) { if (c === q && s[k - 1] !== '\\\\') q = null; } else if (c === '\"' || c === \"'\") q = c; else if (c === '#' && (k === 0 || /\\s/.test(s[k - 1]))) return s.slice(0, k).replace(/\\s+$/, ''); } return s; }\n  function splitKV(t) { let q = null, d = 0; for (let k = 0; k < t.length; k++) { const c = t[k]; if (q) { if (c === q) q = null; } else if (c === '\"' || c === \"'\") q = c; else if ('{['.includes(c)) d++; else if ('}]'.includes(c)) d--; else if (c === ':' && !d && (k === t.length - 1 || t[k + 1] === ' ')) return [unq(t.slice(0, k).trim()), t.slice(k + 1).trim()]; } return null; }\n  function unq(s) { if (/^\".*\"$/.test(s)) { try { return JSON.parse(s); } catch (e) { return s.slice(1, -1); } } if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, \"'\"); return s; }\n  function scalar(s) { s = s.trim(); if (s === '') return null; if (s[0] === '{' || s[0] === '[') return flow(s); if (/^[\"']/.test(s)) return unq(s); if (/^(true|yes)$/i.test(s)) return true; if (/^(false|no)$/i.test(s)) return false; if (/^(null|~)$/i.test(s)) return null; if (/^-?\\d+$/.test(s) && s.length < 16) return +s; if (/^-?\\d*\\.\\d+$/.test(s)) return +s; return s; }\n  function flow(s) {\n    let p = 0; const ws = () => { while (/\\s/.test(s[p] || '')) p++; };\n    const val = () => { ws(); if (s[p] === '{') { p++; const o = {}; for (; ;) { ws(); if (s[p] === '}') { p++; return o; } let k = tok(':'); ws(); if (s[p] === ':') p++; o[unq(k)] = val(); ws(); if (s[p] === ',') p++; } } if (s[p] === '[') { p++; const a = []; for (; ;) { ws(); if (s[p] === ']') { p++; return a; } a.push(val()); ws(); if (s[p] === ',') p++; } } return scalar(tok(',}]')); };\n    const tok = stops => { ws(); let q = s[p] === '\"' || s[p] === \"'\" ? s[p] : null, st = p; if (q) { p++; while (p < s.length && s[p] !== q) p++; p++; return s.slice(st, p); } while (p < s.length && !stops.includes(s[p])) p++; return s.slice(st, p).trim(); };\n    return val();\n  }\n  function block(ind) { return L[i].t.startsWith('- ') || L[i].t === '-' ? list(L[i].ind) : map(L[i].ind); }\n  function list(ind) {\n    const a = [];\n    while (i < L.length && L[i].ind === ind && (L[i].t.startsWith('- ') || L[i].t === '-')) {\n      const rest = L[i].t.slice(1).trim();\n      if (!rest) { i++; a.push(i < L.length && L[i].ind > ind ? block(L[i].ind) : null); continue; }\n      if (splitKV(rest) && !/^[\\[{\"']/.test(rest)) { L[i] = { ind: ind + 2, t: rest }; a.push(map(ind + 2)); } else { i++; a.push(scalar(rest)); }\n    } return a;\n  }\n  function map(ind) {\n    const o = {};\n    while (i < L.length && L[i].ind === ind && !L[i].t.startsWith('- ')) {\n      const kv = splitKV(L[i].t); if (!kv) { i++; continue; } const [k, v] = kv; i++;\n      if (v === '') o[k] = i < L.length && (L[i].ind > ind || (L[i].ind === ind && L[i].t.startsWith('- '))) ? block(L[i].ind) : null; else o[k] = scalar(v);\n    } return o;\n  }\n  return L.length ? block(L[0].ind) : null;\n}\nconst yq = s => (typeof s === 'string' && (s === '' || /^[\\w.\\-\\/+@]+$/.test(s) && !/^(true|false|null|yes|no|~|[\\d.]+)$/i.test(s)) ? (s === '' ? '\"\"' : s) : JSON.stringify(s));\nfunction yamlDump(v, ind = 0, inList = false) {\n  const pad = ' '.repeat(ind);\n  if (Array.isArray(v)) return v.length && v.every(x => typeof x !== 'object' || x === null) ? '[' + v.map(x => typeof x === 'string' ? yq(x) : x).join(', ') + ']' : v.map(x => pad + '- ' + yamlDump(x, ind + 2, true).replace(/^\\s+/, '')).join('\\n');\n  if (v && typeof v === 'object') { const e = Object.entries(v).filter(([, x]) => x !== undefined && x !== null && x !== '' && !(Array.isArray(x) && !x.length)); return e.map(([k, x], n) => { const lead = inList && n === 0 ? '' : pad; const sub = x && typeof x === 'object' && !(Array.isArray(x) && x.every(y => typeof y !== 'object' || y === null)); return lead + k + ':' + (sub ? '\\n' + yamlDump(x, ind + 2) : ' ' + yamlDump(x, ind + 2)); }).join('\\n'); }\n  return typeof v === 'string' ? yq(v) : String(v);\n}\n\n/* ---------- links -> model ---------- */\n/* model: { type, name, server, port, id (uuid | password), method, net, tls ('' | tls | reality), sni, host, path, alpn:[], fp, pbk, sid, spx, flow, svc, insecure, obfs, obfsPw, user, aid } */\nfunction parseLink(raw) {\n  raw = raw.trim(); const m = raw.match(/^([a-z0-9]+):\\/\\//i); if (!m) return null; const sch = m[1].toLowerCase(), rest = raw.slice(m[0].length);\n  try {\n    if (sch === 'vmess') {\n      const j = JSON.parse(b64d(rest.split('#')[0]) || 'null'); if (!j) return null;\n      return { type: 'vmess', name: j.ps || '', server: j.add, port: num(j.port, 443), id: j.id, aid: num(j.aid, 0), method: j.scy || 'auto', net: j.net || 'tcp', tls: j.tls === 'tls' ? 'tls' : '', sni: j.sni || '', host: j.host || '', path: j.path || '', alpn: csv(j.alpn), fp: j.fp || '', svc: j.net === 'grpc' ? j.path || '' : '', htype: j.type || '' };\n    }\n    if (sch === 'ss') {\n      const [body, name = ''] = rest.split('#'); let main = body.split('?')[0], q = new URLSearchParams(body.split('?')[1] || '');\n      let userinfo, hp; if (main.includes('@')) { const at = main.lastIndexOf('@'); userinfo = main.slice(0, at); hp = main.slice(at + 1); const d = b64d(dec(userinfo)); userinfo = d && d.includes(':') ? d : dec(userinfo); } else { const d = b64d(main); if (!d) return null; const at = d.lastIndexOf('@'); userinfo = d.slice(0, at); hp = d.slice(at + 1); }\n      const i = userinfo.indexOf(':'), hm = hp.replace(/\\/$/, '').match(/^(\\[[^\\]]+\\]|[^:]+):(\\d+)$/); if (!hm || i < 0) return null;\n      const p = { type: 'ss', name: dec(name), server: hm[1].replace(/^\\[|\\]$/g, ''), port: +hm[2], method: userinfo.slice(0, i), id: userinfo.slice(i + 1), net: q.get('type') || 'tcp', tls: q.get('security') === 'tls' ? 'tls' : '', sni: q.get('sni') || '', host: q.get('host') || '', path: q.get('path') || '', alpn: csv(q.get('alpn')), fp: q.get('fp') || '', plugin: q.get('plugin') || '' };\n      return p;\n    }\n    const u = new URL(raw); const q = u.searchParams, server = u.hostname.replace(/^\\[|\\]$/g, ''), port = num(u.port, 443), name = dec((u.hash || '').slice(1)), id = dec(u.username);\n    const tr = { name, server, port, net: q.get('type') || 'tcp', tls: q.get('security') === 'reality' ? 'reality' : q.get('security') === 'tls' ? 'tls' : '', sni: q.get('sni') || q.get('peer') || '', host: q.get('host') || '', path: q.get('path') || '', alpn: csv(q.get('alpn')), fp: q.get('fp') || '', pbk: q.get('pbk') || '', sid: q.get('sid') || '', spx: q.get('spx') || '', flow: q.get('flow') || '', svc: q.get('serviceName') || '', insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1', htype: q.get('headerType') || '', mode: q.get('mode') || '' };\n    if (sch === 'vless') return { type: 'vless', id, ...tr, enc: q.get('encryption') || 'none' };\n    if (sch === 'trojan') return { type: 'trojan', id: dec(u.username), ...tr, tls: tr.tls || 'tls' };\n    if (sch === 'hysteria2' || sch === 'hy2') return { type: 'hysteria2', id: dec(u.username + (u.password ? ':' + u.password : '')), name, server, port, tls: 'tls', sni: q.get('sni') || '', insecure: q.get('insecure') === '1', obfs: q.get('obfs') || '', obfsPw: q.get('obfs-password') || '', alpn: csv(q.get('alpn')) };\n    if (sch === 'socks' || sch === 'socks5' || sch === 'http' || sch === 'https') { let user = dec(u.username), pw = dec(u.password); if (user && !pw) { const d = b64d(user); if (d && d.includes(':')) [user, pw] = d.split(/:(.*)/s); } return { type: sch.startsWith('socks') ? 'socks' : 'http', name, server, port: num(u.port, sch === 'https' ? 443 : 1080), user, id: pw, tls: sch === 'https' ? 'tls' : '' }; }\n  } catch (e) { return null; } return null;\n}\n\nfunction toLink(p) {\n  const H = hostFmt(p.server), tag = '#' + encodeURIComponent(p.name || ''), Q = (o) => { const s = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== '' && v !== undefined && v !== null && v !== false) s.set(k, v === true ? '1' : v); return s.toString().replace(/\\+/g, '%20'); };\n  const tq = () => Q({ type: p.net && p.net !== 'tcp' ? p.net : (p.type === 'vless' ? 'tcp' : ''), security: p.tls || (p.type === 'vless' ? 'none' : ''), sni: p.sni, host: p.host, path: p.net === 'grpc' ? '' : p.path, serviceName: p.svc, alpn: (p.alpn || []).join(','), fp: p.fp, pbk: p.pbk, sid: p.sid, spx: p.spx, flow: p.flow, allowInsecure: p.insecure, headerType: p.htype && p.htype !== 'none' ? p.htype : '', mode: p.mode });\n  switch (p.type) {\n    case 'vmess': return 'vmess://' + b64e(JSON.stringify({ v: '2', ps: p.name || '', add: p.server, port: String(p.port), id: p.id, aid: String(p.aid || 0), scy: p.method || 'auto', net: p.net || 'tcp', type: p.htype || 'none', host: p.host || '', path: p.net === 'grpc' ? p.svc : p.path || '', tls: p.tls === 'tls' ? 'tls' : '', sni: p.sni || '', alpn: (p.alpn || []).join(','), fp: p.fp || '' }));\n    case 'vless': return `vless://${encodeURIComponent(p.id)}@${H}:${p.port}?${Q({ encryption: p.enc || 'none' })}&${tq()}${tag}`;\n    case 'trojan': return `trojan://${encodeURIComponent(p.id)}@${H}:${p.port}?${tq()}${tag}`;\n    case 'ss': return `ss://${b64e(p.method + ':' + p.id).replace(/=+$/, '')}@${H}:${p.port}${p.net && p.net !== 'tcp' || p.tls || p.plugin ? '?' + Q({ type: p.net !== 'tcp' ? p.net : '', security: p.tls, sni: p.sni, host: p.host, path: p.path, plugin: p.plugin }) : ''}${tag}`;\n    case 'hysteria2': return `hysteria2://${encodeURIComponent(p.id)}@${H}:${p.port}?${Q({ sni: p.sni, insecure: p.insecure, obfs: p.obfs, 'obfs-password': p.obfsPw, alpn: (p.alpn || []).join(',') })}${tag}`;\n    case 'socks': return `socks://${b64e((p.user || '') + ':' + (p.id || '')).replace(/=+$/, '')}@${H}:${p.port}${tag}`;\n    case 'http': return `${p.tls ? 'https' : 'http'}://${p.user ? encodeURIComponent(p.user) + ':' + encodeURIComponent(p.id || '') + '@' : ''}${H}:${p.port}${tag}`;\n  } return '';\n}\n\n/* ---------- model <-> Clash / sing-box ---------- */\nconst NET_CL = { tcp: 'tcp', ws: 'ws', grpc: 'grpc', h2: 'h2', http: 'h2', httpupgrade: 'ws' };\nfunction toClash(p) {\n  const c = { name: p.name || p.server, type: { ss: 'ss', socks: 'socks5' }[p.type] || p.type, server: p.server, port: p.port, udp: true };\n  if (p.type === 'vless' || p.type === 'vmess') { c.uuid = p.id; if (p.type === 'vmess') { c.alterId = p.aid || 0; c.cipher = p.method || 'auto'; } if (p.flow) c.flow = p.flow; }\n  else if (p.type === 'trojan' || p.type === 'hysteria2') c.password = p.id; else if (p.type === 'ss') { c.cipher = p.method; c.password = p.id; if (p.plugin) c.plugin = p.plugin; }\n  else if (p.type === 'socks' || p.type === 'http') { if (p.user) c.username = p.user; if (p.id) c.password = p.id; if (p.tls) c.tls = true; return c; }\n  if (p.type === 'hysteria2') { c.sni = p.sni; if (p.insecure) c['skip-cert-verify'] = true; if (p.obfs) { c.obfs = p.obfs; c['obfs-password'] = p.obfsPw; } if (p.alpn && p.alpn.length) c.alpn = p.alpn; return c; }\n  if (p.type !== 'ss') { c.network = NET_CL[p.net] || p.net || 'tcp'; if (p.tls) c.tls = true; if (p.sni) c[p.type === 'trojan' ? 'sni' : 'servername'] = p.sni; if (p.insecure) c['skip-cert-verify'] = true; if (p.fp) c['client-fingerprint'] = p.fp; if (p.alpn && p.alpn.length) c.alpn = p.alpn; }\n  if (p.tls === 'reality') c['reality-opts'] = { 'public-key': p.pbk, 'short-id': p.sid };\n  if (p.net === 'ws' || p.net === 'httpupgrade') c['ws-opts'] = { path: p.path || '/', headers: p.host ? { Host: p.host } : undefined, 'v2ray-http-upgrade': p.net === 'httpupgrade' || undefined };\n  if (p.net === 'grpc') c['grpc-opts'] = { 'grpc-service-name': p.svc || p.path };\n  if (p.net === 'h2' || p.net === 'http') c['h2-opts'] = { path: p.path || '/', host: p.host ? [p.host] : undefined };\n  return c;\n}\nfunction fromClash(c) {\n  const t = { socks5: 'socks', ssr: 'ssr' }[c.type] || c.type; if (!['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'].includes(t)) return null;\n  const p = { type: t, name: c.name || '', server: c.server, port: num(c.port, 443), id: c.uuid || c.password || c.auth || '', method: t === 'ss' ? c.cipher : c.cipher, aid: c.alterId, net: c.network || 'tcp', tls: c['reality-opts'] ? 'reality' : (c.tls || t === 'trojan' || t === 'hysteria2') ? 'tls' : '', sni: c.servername || c.sni || '', insecure: !!c['skip-cert-verify'], fp: c['client-fingerprint'] || '', alpn: c.alpn || [], flow: c.flow || '', user: c.username || '', plugin: c.plugin || '' };\n  if (c['reality-opts']) { p.pbk = c['reality-opts']['public-key']; p.sid = c['reality-opts']['short-id']; }\n  const ws = c['ws-opts']; if (ws) { p.path = ws.path || ''; p.host = (ws.headers && (ws.headers.Host || ws.headers.host)) || ''; if (ws['v2ray-http-upgrade']) p.net = 'httpupgrade'; }\n  if (c['grpc-opts']) p.svc = c['grpc-opts']['grpc-service-name'] || ''; const h2 = c['h2-opts']; if (h2) { p.path = h2.path || ''; p.host = [].concat(h2.host || [])[0] || ''; }\n  if (t === 'hysteria2') { p.obfs = c.obfs || ''; p.obfsPw = c['obfs-password'] || ''; }\n  return p;\n}\nfunction toSing(p) {\n  const o = { type: { ss: 'shadowsocks', socks: 'socks' }[p.type] || p.type, tag: p.name || p.server, server: p.server, server_port: p.port };\n  if (p.type === 'vless') { o.uuid = p.id; if (p.flow) o.flow = p.flow; } else if (p.type === 'vmess') { o.uuid = p.id; o.security = p.method || 'auto'; o.alter_id = p.aid || 0; }\n  else if (p.type === 'trojan' || p.type === 'hysteria2') o.password = p.id; else if (p.type === 'ss') { o.method = p.method; o.password = p.id; if (p.plugin) { const [pl, ...r] = p.plugin.split(';'); o.plugin = pl; o.plugin_opts = r.join(';'); } }\n  else { if (p.user) o.username = p.user; if (p.id) o.password = p.id; if (p.tls) o.tls = { enabled: true }; return o; }\n  if (p.tls || p.type === 'hysteria2') { o.tls = { enabled: true, server_name: p.sni || undefined, insecure: p.insecure || undefined, alpn: p.alpn && p.alpn.length ? p.alpn : undefined }; if (p.fp) o.tls.utls = { enabled: true, fingerprint: p.fp }; if (p.tls === 'reality') o.tls.reality = { enabled: true, public_key: p.pbk, short_id: p.sid }; }\n  if (p.type === 'hysteria2' && p.obfs) o.obfs = { type: p.obfs, password: p.obfsPw };\n  if (p.type !== 'ss' && p.type !== 'hysteria2') {\n    if (p.net === 'ws') o.transport = { type: 'ws', path: p.path || '/', headers: p.host ? { Host: p.host } : undefined };\n    else if (p.net === 'grpc') o.transport = { type: 'grpc', service_name: p.svc || p.path };\n    else if (p.net === 'httpupgrade') o.transport = { type: 'httpupgrade', path: p.path || '/', host: p.host || undefined };\n    else if (p.net === 'h2' || p.net === 'http') o.transport = { type: 'http', path: p.path || '/', host: p.host ? [p.host] : undefined };\n  } return o;\n}\nfunction fromSing(o) {\n  const t = { shadowsocks: 'ss', socks: 'socks' }[o.type] || o.type; if (!['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'].includes(t)) return null;\n  const tl = o.tls || {}, tr = o.transport || {}, p = { type: t, name: o.tag || '', server: o.server, port: num(o.server_port, 443), id: o.uuid || o.password || '', method: o.method || o.security || '', aid: o.alter_id, net: ({ http: 'h2' }[tr.type]) || tr.type || 'tcp', tls: tl.reality && tl.reality.enabled ? 'reality' : tl.enabled ? 'tls' : '', sni: tl.server_name || '', insecure: !!tl.insecure, fp: tl.utls ? tl.utls.fingerprint : '', alpn: tl.alpn || [], flow: o.flow || '', user: o.username || '', host: (tr.headers && tr.headers.Host) || [].concat(tr.host || [])[0] || '', path: tr.path || '', svc: tr.service_name || '', pbk: tl.reality ? tl.reality.public_key : '', sid: tl.reality ? tl.reality.short_id : '' };\n  if (o.plugin) p.plugin = o.plugin + (o.plugin_opts ? ';' + o.plugin_opts : ''); if (o.obfs) { p.obfs = o.obfs.type; p.obfsPw = o.obfs.password; } return p;\n}\n\n/* any text -> list of models (+ notes) */\nfunction extract(text) {\n  const t = text.trim(), notes = []; if (!t) return { list: [], notes };\n  const out = [];\n  try { if (/^[\\[{]/.test(t)) { const j = JSON.parse(t); const arr = Array.isArray(j) ? j : j.outbounds || j.proxies || []; for (const o of arr) { const p = fromSing(o); if (p) out.push(p); } if (out.length) return { list: out, notes }; } } catch (e) {}\n  if (/^\\s*(proxies|proxy-groups|port|mixed-port|mode)\\s*:/m.test(t) || /^\\s*-\\s+(name|\\{)/m.test(t)) { try { const y = yamlParse(t); const arr = (y && y.proxies) || (Array.isArray(y) ? y : []); let skipped = 0; for (const c of arr) { const p = fromClash(c); p ? out.push(p) : skipped++; } if (skipped) notes.push(skipped + ' unsupported entr' + (skipped === 1 ? 'y' : 'ies') + ' skipped'); if (out.length) return { list: out, notes }; } catch (e) { notes.push('YAML could not be read'); } }\n  let body = t; if (!/:\\/\\//.test(t)) { const d = b64d(t); if (d && /:\\/\\//.test(d)) body = d; }\n  let bad = 0; for (const m of body.matchAll(/\\b(?:vless|vmess|trojan|ss|hysteria2|hy2|socks5?|https?):\\/\\/[^\\s\"'<>]+/gi)) { const p = parseLink(m[0]); p ? out.push(p) : bad++; }\n  if (bad) notes.push(bad + ' link' + (bad === 1 ? '' : 's') + ' could not be read'); return { list: out, notes };\n}\nwindow.CONV = { yamlParse, yamlDump, parseLink, toLink, toClash, fromClash, toSing, fromSing, extract, b64d, b64e };\n\n/* ---------- UI ---------- */\nconst copy = (t, b) => XRNET_COPY(t, b);\nconst XRNET_COPY = async (t, btn) => { try { await navigator.clipboard.writeText(t); } catch (e) { const x = document.createElement('textarea'); x.value = t; document.body.append(x); x.select(); document.execCommand('copy'); x.remove(); } if (btn) { const l = btn.dataset.l = btn.dataset.l || btn.textContent; btn.textContent = 'Copied'; setTimeout(() => btn.textContent = l, 1300); } };\nconst dl = (name, text) => WG.download(name, text);\nconst fetchSub = async url => { const r = await (await fetch('/api/fetch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) })).json(); if (!r.ok) throw new Error(r.error || 'failed'); return r.text; };\nconst TYPES = ['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'];\n\nfunction mountConfigs(root, mode) {\n  const bulk = mode === 'links';\n  root.innerHTML = `<p class=\"hint\">${bulk ? 'Paste links, a base64 subscription, Clash YAML or sing-box JSON (or fetch a subscription URL). Filter, edit in bulk, then copy or scan.' : 'Paste any of: links, base64 subscription, Clash YAML, sing-box JSON. Pick the output format.'}</p>\n  <textarea data-in rows=\"6\" spellcheck=\"false\" placeholder=\"vless://… vmess://… trojan://… ss://…  or  proxies: …  or  { &quot;outbounds&quot;: … }\"></textarea>\n  <div class=\"row\"><input data-url placeholder=\"Subscription URL (fetched by the panel)\" spellcheck=\"false\" autocapitalize=\"off\" style=\"flex:1;min-width:200px\"><button type=\"button\" class=\"btn o tl\" data-fetch>Fetch</button><label class=\"btn o yl\" style=\"margin:0\">File<input type=\"file\" data-file hidden></label></div>\n  <p class=\"hint err\" data-msg hidden></p><div class=\"st\" data-chips></div>\n  ${bulk ? `<div class=\"f\"><label>Address (one per line, makes a copy of each config)<textarea data-o=\"addr\" rows=\"2\" spellcheck=\"false\" placeholder=\"keep original\"></textarea></label><label>Port<input data-o=\"port\" inputmode=\"numeric\" placeholder=\"keep\"></label><label>SNI<input data-o=\"sni\" placeholder=\"keep\" spellcheck=\"false\"></label><label>Host header<input data-o=\"host\" placeholder=\"keep\" spellcheck=\"false\"></label><label>Name template<input data-o=\"name\" value=\"{name}\" spellcheck=\"false\"></label></div><p class=\"hint\">Template tokens: {n} number · {name} original · {proto} · {addr}</p>` : `<div class=\"tabs\" data-fmt><button type=\"button\" class=\"on\" data-o2=\"clash\">Clash</button><button type=\"button\" data-o2=\"sing\">Sing-box</button><button type=\"button\" data-o2=\"links\">Links</button><button type=\"button\" data-o2=\"sub\">Base64 sub</button></div>`}\n  <div data-out></div>`;\n  const q = s => root.querySelector(s), st = { list: [], types: new Set(TYPES), fmt: 'clash' };\n  const msg = (t, bad = true) => { const m = q('[data-msg]'); m.hidden = !t; m.textContent = t || ''; m.className = 'hint ' + (bad ? 'err' : ''); };\n  const apply = () => {\n    let L = st.list.filter(p => st.types.has(p.type)); if (!bulk) return L;\n    const O = n => (q(`[data-o=\"${n}\"]`).value || '').trim(), addrs = O('addr').split(/[\\s,]+/).filter(Boolean), port = num(O('port'), 0), tpl = q('[data-o=\"name\"]').value || '{name}', res = []; let n = 0;\n    for (const p of L) for (const a of (addrs.length ? addrs : [null])) { const c = { ...p }; if (a) c.server = a.replace(/^\\[|\\]$/g, ''); if (port) c.port = port; if (O('sni')) c.sni = O('sni'); if (O('host')) c.host = O('host'); n++; c.name = tpl.replace(/\\{n\\}/g, n).replace(/\\{name\\}/g, p.name || '').replace(/\\{proto\\}/g, p.type).replace(/\\{addr\\}/g, c.server); res.push(c); }\n    return res;\n  };\n  const chips = () => { const cnt = {}; st.list.forEach(p => cnt[p.type] = (cnt[p.type] || 0) + 1); q('[data-chips]').innerHTML = Object.keys(cnt).map(t => `<button type=\"button\" class=\"cb ${st.types.has(t) ? 'sel' : ''}\" data-t=\"${t}\">${t} · ${cnt[t]}</button>`).join(''); };\n  const render = () => {\n    const L = apply(), out = q('[data-out]');\n    if (!L.length) { out.innerHTML = ''; return; }\n    if (bulk) {\n      const links = L.map(toLink);\n      out.innerHTML = `<div class=\"sv-h\"><b>${L.length} config${L.length === 1 ? '' : 's'}</b><span><button type=\"button\" class=\"btn o tl\" data-all>Copy all</button><button type=\"button\" class=\"btn o yl\" data-b64>Copy base64</button><button type=\"button\" class=\"btn o tl\" data-save>.txt</button></span></div><div class=\"cfgs\">${L.map((p, i) => `<div class=\"cfg\"><div><b>${E(p.name || p.server)}</b><small>${p.type}${p.net && p.net !== 'tcp' ? ' · ' + E(p.net) : ''}${p.tls ? ' · ' + p.tls : ''} · ${E(p.server)}:${p.port}</small></div><span><button type=\"button\" class=\"btn o tl\" data-c=\"${i}\">Copy</button><button type=\"button\" class=\"btn o pu\" data-q=\"${i}\">QR</button></span><div class=\"qr\" data-qr=\"${i}\" hidden></div></div>`).join('')}</div>`;\n      out.querySelector('[data-all]').onclick = e => copy(links.join('\\n'), e.target); out.querySelector('[data-b64]').onclick = e => copy(b64e(links.join('\\n')), e.target); out.querySelector('[data-save]').onclick = () => dl('configs.txt', links.join('\\n'));\n      out.querySelectorAll('[data-c]').forEach(b => b.onclick = e => copy(links[b.dataset.c], e.target));\n      out.querySelectorAll('[data-q]').forEach(b => b.onclick = () => { const box = out.querySelector(`[data-qr=\"${b.dataset.q}\"]`); if (box.hidden) { try { box.innerHTML = QR.svg(links[b.dataset.q], 4); } catch (e) { box.textContent = 'Too long for a QR code'; } } box.hidden = !box.hidden; });\n    } else {\n      const f = st.fmt; let txt = '', ext = 'txt', skipped = 0;\n      if (f === 'clash') { txt = 'proxies:\\n' + yamlDump(L.map(toClash), 2).replace(/^/gm, '').split('\\n').map(l => l).join('\\n'); txt = 'proxies:\\n' + yamlDump(L.map(toClash), 2); ext = 'yaml'; }\n      else if (f === 'sing') { txt = JSON.stringify({ outbounds: L.map(toSing) }, null, 2); ext = 'json'; }\n      else { const ls = L.map(toLink); txt = f === 'sub' ? b64e(ls.join('\\n')) : ls.join('\\n'); }\n      out.innerHTML = `<textarea class=\"code\" rows=\"12\" readonly spellcheck=\"false\"></textarea><div class=\"row\"><button type=\"button\" class=\"btn o tl\" data-cp>Copy</button><button type=\"button\" class=\"btn o yl\" data-dl>Download</button></div>`; out.querySelector('textarea').value = txt;\n      out.querySelector('[data-cp]').onclick = e => copy(txt, e.target); out.querySelector('[data-dl]').onclick = () => dl('converted.' + ext, txt);\n    }\n  };\n  const load = text => { const { list, notes } = extract(text); st.list = list; st.types = new Set(TYPES); chips(); msg(!list.length ? 'Nothing recognised in this text.' : notes.join(' · '), !list.length); render(); };\n  q('[data-in]').addEventListener('input', () => load(q('[data-in]').value));\n  q('[data-chips]').onclick = e => { const b = e.target.closest('[data-t]'); if (!b) return; st.types.has(b.dataset.t) ? st.types.delete(b.dataset.t) : st.types.add(b.dataset.t); chips(); render(); };\n  root.querySelectorAll('[data-o]').forEach(i => i.addEventListener('input', render));\n  const fm = q('[data-fmt]'); if (fm) fm.onclick = e => { const b = e.target.closest('button'); if (!b) return; fm.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); st.fmt = b.dataset.o2; render(); };\n  q('[data-fetch]').onclick = async e => { const u = q('[data-url]').value.trim(); if (!u) return; const b = e.target; b.disabled = true; msg(''); try { const t = await fetchSub(u); q('[data-in]').value = t.slice(0, 600000); load(t); } catch (x) { msg(x.message); } b.disabled = false; };\n  q('[data-file]').onchange = async e => { const f = e.target.files[0]; if (f) { const t = await f.text(); q('[data-in]').value = t.slice(0, 600000); load(t); } };\n}\n\n/* ---------- WireGuard converter ---------- */\nfunction mountWG(root) {\n  const { I_PRESETS, IK, JUNK } = WG;\n  root.innerHTML = `<p class=\"hint\">Paste or upload WireGuard <code>.conf</code> files (a WARP config works too) and convert them to Clash, AmneziaWG or Wiresock.</p>\n  <textarea data-in rows=\"8\" spellcheck=\"false\" placeholder=\"[Interface]&#10;PrivateKey = …&#10;Address = …&#10;&#10;[Peer]&#10;PublicKey = …&#10;Endpoint = host:port\"></textarea>\n  <div class=\"row\"><label class=\"btn o yl\" style=\"margin:0\">Upload .conf<input type=\"file\" data-file accept=\".conf,.txt\" multiple hidden></label></div>\n  <p class=\"hint err\" data-msg hidden></p>\n  <div class=\"grp\"><h3>Output</h3><div class=\"tabs\" data-kind><button type=\"button\" class=\"on\" data-k=\"clash\">Clash</button><button type=\"button\" data-k=\"awg\">AmneziaWG</button><button type=\"button\" data-k=\"wiresock\">Wiresock</button></div></div>\n  <div data-opts>\n    <div class=\"grp\"><h3>Junk packets</h3><div class=\"tabs\" data-junk><button type=\"button\" class=\"on\" data-j=\"light\">Light</button><button type=\"button\" data-j=\"heavy\">Heavy</button><button type=\"button\" data-j=\"custom\">Custom</button><button type=\"button\" data-j=\"random\">Random</button></div></div>\n    <div class=\"f\" data-cj hidden><label>Jc<input data-f=\"jc\" value=\"3\" inputmode=\"numeric\"></label><label>Jmin<input data-f=\"jmin\" value=\"1\" inputmode=\"numeric\"></label><label>Jmax<input data-f=\"jmax\" value=\"3\" inputmode=\"numeric\"></label></div>\n    <div data-i hidden><label class=\"ck\"><input type=\"checkbox\" data-f=\"a15\"> Amnezia 1.5 packets (I1–I5)</label><div data-a15 hidden><div class=\"row\" style=\"margin-top:0\">${[1, 2, 3, 4].map(n => `<button type=\"button\" class=\"btn o tl\" data-set=\"${n}\">Set ${n}</button>`).join('')}</div>${IK.map(k => `<label class=\"wide\">${k.toUpperCase()}<input data-f=\"${k}\" spellcheck=\"false\"></label>`).join('')}</div></div>\n    <div class=\"f\"><label>MTU<input data-f=\"mtu\" placeholder=\"keep\" inputmode=\"numeric\"></label><label>Endpoint<input data-f=\"ep\" placeholder=\"keep\" spellcheck=\"false\"></label><label data-rs>Reserved (a,b,c)<input data-f=\"rs\" placeholder=\"optional\" spellcheck=\"false\"></label><label data-wsk hidden>Id / Ip / Ib<input data-f=\"ws\" placeholder=\"Id, QUIC, Chrome\" spellcheck=\"false\"></label></div>\n  </div>\n  <div data-out></div>`;\n  const q = s => root.querySelector(s), f = n => q(`[data-f=\"${n}\"]`); let kind = 'clash', junk = 'light', files = [];\n  const msg = t => { const m = q('[data-msg]'); m.hidden = !t; m.textContent = t || ''; };\n  const model = (c, i) => {\n    const I = c.iface, P = c.peers[0]; if (!I || !I.privatekey || !P || !P.publickey || !P.endpoint) return null;\n    const m = { name: (files[i] ? files[i].replace(/\\.\\w+$/, '') : 'wg-' + (i + 1)), private: I.privatekey, public: P.publickey, psk: P.presharedkey || '', address: I.address || '', dns: I.dns || '1.1.1.1', mtu: +f('mtu').value || +I.mtu || 1280, allowed: P.allowedips || '0.0.0.0/0, ::/0', endpoint: f('ep').value.trim() || P.endpoint, keepalive: +P.persistentkeepalive || '', reserved: f('rs').value.split(',').map(x => parseInt(x)).filter(n => n >= 0 && n < 256).slice(0, 3) };\n    if (kind !== 'clash') { const have = I.jc !== undefined; let j; if (junk === 'custom') j = { jc: f('jc').value, jmin: f('jmin').value, jmax: f('jmax').value }; else if (junk === 'random') j = WG.randJunk(); else j = JUNK[junk]; m.awg = WG.awgBase(j); if (have && junk === 'light' && false) m.awg = { ...m.awg }; if (kind === 'awg' && f('a15').checked) IK.forEach(k => m.awg[k] = f(k).value.trim()); if (kind === 'wiresock') { const [id, ip, ib] = f('ws').value.split(',').map(s => s.trim()); m.ws = { id, ip: ip || 'QUIC', ib: ib || 'Chrome' }; } }\n    return m;\n  };\n  const render = () => {\n    const text = q('[data-in]').value.trim(); const out = q('[data-out]'); out.innerHTML = '';\n    const blocks = text ? text.split(/(?=^\\s*\\[Interface\\])/mi).filter(b => /\\[Interface\\]/i.test(b)) : []; if (!blocks.length) { msg(text ? 'No [Interface] section found.' : ''); return; }\n    const ms = blocks.map((b, i) => model(WG.parseConf(b), i)); const ok = ms.filter(Boolean); msg(ok.length < ms.length ? (ms.length - ok.length) + ' config(s) skipped: PrivateKey, PublicKey and Endpoint are required.' : '');\n    if (!ok.length) return; const txt = kind === 'clash' ? 'proxies:\\n' + ok.map(m => WG.toClash(m).replace(/^/gm, '  ')).join('\\n') : ok.map(m => WG.toConf(m, kind)).join('\\n\\n');\n    out.innerHTML = `<textarea class=\"code\" rows=\"14\" readonly spellcheck=\"false\"></textarea><div class=\"row\"><button type=\"button\" class=\"btn o tl\" data-cp>Copy</button><button type=\"button\" class=\"btn o yl\" data-dl>Download</button></div>`; out.querySelector('textarea').value = txt;\n    out.querySelector('[data-cp]').onclick = e => copy(txt, e.target);\n    out.querySelector('[data-dl]').onclick = () => { if (kind === 'clash' || ok.length === 1) dl(kind === 'clash' ? 'wireguard-clash.yaml' : (ok[0].name || 'wg') + '.conf', txt); else ok.forEach((m, i) => setTimeout(() => dl((m.name || 'wg' + i) + '.conf', WG.toConf(m, kind)), i * 350)); };\n  };\n  const tabs = (el, attr, fn) => el.onclick = e => { const b = e.target.closest('button'); if (!b) return; el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); fn(b.dataset[attr]); render(); };\n  tabs(q('[data-kind]'), 'k', k => { kind = k; q('[data-opts] .grp').hidden = q('[data-cj]').hidden = k === 'clash'; q('[data-junk]').parentElement.hidden = k === 'clash'; q('[data-cj]').hidden = k === 'clash' || junk !== 'custom'; q('[data-i]').hidden = k !== 'awg'; q('[data-rs]').hidden = k !== 'clash'; q('[data-wsk]').hidden = k !== 'wiresock'; });\n  tabs(q('[data-junk]'), 'j', j => { junk = j; q('[data-cj]').hidden = j !== 'custom'; });\n  q('[data-junk]').parentElement.hidden = true; q('[data-cj]').hidden = true;\n  f('a15').onchange = () => { q('[data-a15]').hidden = !f('a15').checked; render(); };\n  root.querySelectorAll('[data-set]').forEach(b => b.onclick = () => { IK.forEach(k => f(k).value = I_PRESETS[b.dataset.set][k] || ''); render(); });\n  root.querySelectorAll('[data-f]').forEach(i => i.addEventListener('input', render)); q('[data-in]').addEventListener('input', () => { files = []; render(); });\n  q('[data-file]').onchange = async e => { files = [...e.target.files].map(x => x.name); const t = (await Promise.all([...e.target.files].map(x => x.text()))).join('\\n\\n'); q('[data-in]').value = t.slice(0, 400000); render(); };\n}\n\ndocument.addEventListener('DOMContentLoaded', () => { const a = document.querySelector('[data-conv=\"links\"]'), b = document.querySelector('[data-conv=\"wg\"]'), c = document.querySelector('[data-conv=\"formats\"]'); if (a) mountConfigs(a, 'links'); if (b) mountWG(b); if (c) mountConfigs(c, 'formats'); });\n})();\n"],"frag.js":["text/javascript; charset=utf-8","/* Advanced > Fragment: measures THIS browser's network on the Settings test sites (round robin, a few per run),\n   saves the result, then checks from this browser that the WebSocket endpoint of each config type answers. */\n(() => {\n'use strict';\nconst acc = document.querySelector('[data-frag]'); if (!acc || acc.dataset.on !== '1') return;\nconst $ = s => acc.querySelector(s), E = t => String(t).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\nconst post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json());\nconst med = a => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };\nconst wsOpen = path => new Promise(res => { let w, done = false; const end = ok => { if (done) return; done = true; try { w && w.close(); } catch (e) { } res(ok); }; try { w = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + path); w.onopen = () => end(true); w.onerror = () => end(false); w.onclose = () => end(false); setTimeout(() => end(false), 4000); } catch (e) { res(false); } });\nconst NAMES = { vless: 'VLESS', trojan: 'Trojan', shadowsocks: 'Shadowsocks', vmess: 'VMess' };\nlet busy = false;\n\nasync function hit(url, timeout = 4000) {\n  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), timeout), t0 = performance.now();\n  try { await fetch(url + (url.includes('?') ? '&' : '?') + '_=' + Date.now() + Math.random().toString(36).slice(2, 6), { mode: 'no-cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ac.signal }); return performance.now() - t0; }\n  catch (e) { return null; } finally { clearTimeout(tm); }\n}\nasync function measure() {\n  const r = await post('/api/sites/next'), all = [], warm = []; let tries = 0, okc = 0, skipped = 0;\n  const sites = (r.sites || []).filter(u => { const bad = u.startsWith('http:') && location.protocol === 'https:'; if (bad) skipped++; return !bad; });   // https page cannot fetch plain http\n  await Promise.all(sites.map(async u => { for (let k = 0; k < 3; k++) { tries++; const ms = await hit(u); if (ms !== null) { okc++; all.push(ms); if (k) warm.push(ms); } } }));\n  const use = warm.length ? warm : all, c = navigator.connection || {}, m = med(use), dev = med(use.map(x => Math.abs(x - m)));\n  return { rtt: m, ok: tries ? okc / tries : 0, jitter: dev, n: tries, sites: sites, skipped, net: { type: c.effectiveType, downlink: c.downlink, rtt: c.rtt } };\n}\nconst chips = (p, ver) => `<span class=\"chip ${p.tier !== 'none' ? 'ok' : ''}\">${p.tier === 'none' ? 'no fragment' : E(p.tier)}</span><span class=\"chip ok\">${Math.round(p.rtt)} ms</span><span class=\"chip ${p.ok >= .6 ? 'ok' : 'run'}\">${Math.round(p.ok * 100)}% reachable</span>` + (ver === true ? '<span class=\"chip ok\">✓ verified</span>' : ver === false ? '<span class=\"chip\">✕ failed check</span>' : '');\nconst tag = t => { const e = acc.querySelector('[data-ftag]'); e.textContent = t; e.className = 'tag' + (t !== 'none' && t !== 'on' && t !== 'measuring' ? ' active' : ''); };\n\nasync function run() {\n  if (busy) return; busy = true; const go = $('[data-fgo]'), msg = $('[data-fmsg]'), res = $('[data-fres]'), st = $('[data-fst]');\n  go.disabled = true; tag('measuring'); st.innerHTML = '<span class=\"chip run\">measuring…</span>'; res.innerHTML = ''; msg.textContent = 'Testing your connection on the next sites in the list…';\n  try {\n    const m = await measure(), d = await post('/advanced/fragment/save', m);\n    if (!d.ok) throw new Error(d.error || 'save failed');\n    const p = d.profile; st.innerHTML = chips(p); tag(p.tier === 'none' ? 'none' : p.tier);\n    const used = m.sites.map(u => { try { return new URL(u).hostname; } catch (e) { return u; } }).join(', ');\n    if (p.tier === 'none') { msg.textContent = `No test site answered (${used || 'none usable'}). Nothing was applied: configs stay without a fragment.`; return; }\n    msg.textContent = `Measured on ${used}. Checking that each config type answers…`;\n    const v = await post('/api/fragment/test'); if (!v.ok) throw new Error(v.error || 'check failed');\n    await Promise.all(v.results.filter(x => !x.skip).map(async x => { const t0 = performance.now(); x.ok = await wsOpen(x.path); x.ms = Math.round(performance.now() - t0); x.text = x.ok ? 'ws open' : 'no answer'; }));\n    const live = v.results.filter(x => !x.skip); v.verified = live.length ? live.every(x => x.ok) : null;\n    await post('/api/fragment/verdict', { bad: live.filter(x => !x.ok).map(x => x.proto), verified: v.verified });\n    st.innerHTML = chips(p, v.verified === null ? undefined : v.verified);\n    res.innerHTML = v.results.map(x => `<div class=\"cfg\"><div><b>${E(NAMES[x.proto] || x.proto)}</b><small>${x.skip ? 'not applied · ' + E(x.text) : E(x.text) + (x.ms ? ' · ' + x.ms + ' ms' : '')}</small></div><span class=\"chip ${x.skip || v.verified === null ? 'wait' : x.ok ? 'ok' : ''}\">${x.skip ? '—' : x.ok ? '✓ works' : '✕ failed'}</span></div>`).join('');\n    const bad = v.results.filter(x => !x.skip && !x.ok).map(x => NAMES[x.proto] || x.proto), good = v.results.filter(x => !x.skip && x.ok).map(x => NAMES[x.proto] || x.proto);\n    msg.textContent = v.verified === null ? 'Fragment saved and applied to VLESS, Trojan and Shadowsocks. No protocol of this panel could be checked.'\n      : v.verified ? 'Fragment is applied to ' + good.join(', ') + ' and each WebSocket endpoint answered. (The fragment itself is performed by your client app.)'\n      : (bad.join(', ') + ' failed the check with a fragment, so they get no fragment. Applied to: ' + (good.join(', ') || 'nothing') + '.');\n  } catch (e) { msg.textContent = 'Error: ' + (e.message || e); tag('on'); }\n  finally { busy = false; go.disabled = false; }\n}\n$('[data-fgo]').onclick = run;\nrun();      // switched on (or page opened with Fragment on): measure right away, next sites in the rotation\n})();\n"],"loc.js":["text/javascript; charset=utf-8","/* Locations: Auto location + Recovery. Both run in small steps on the Worker (free proxy lists -> verified -> geo-located); this page drives the steps and shows progress. */\n(() => {\n'use strict';\nconst box = document.querySelector('[data-loc]'); if (!box) return;\nconst E = t => String(t).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\nconst seg = box.querySelector('[data-lseg]'), prog = box.querySelector('[data-lprog]'), log = box.querySelector('[data-llog]');\nconst btn = {}; box.querySelectorAll('[data-lgo]').forEach(b => { btn[b.dataset.lgo] = b; b.dataset.l = b.textContent; });\nconst post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json().catch(() => ({})));\nlet since = 0, timer = 0, wasRun = false, t0 = Date.now();\n\nconst msg = sessionStorage.getItem('locmsg');\nif (msg) { sessionStorage.removeItem('locmsg'); const d = document.createElement('div'); d.className = 'toast'; d.textContent = msg; document.querySelector('main').prepend(d); }\n\nfunction paint(st) {\n  for (const k in btn) {\n    const b = btn[k], mine = st.run && st.kind === k;\n    b.classList.toggle('live', mine); b.disabled = st.run && !mine;\n    b.textContent = mine ? (st.stopping ? 'Stopping…' : 'Stop · ' + b.dataset.l) : b.dataset.l;\n  }\n  if (st.run || st.seq) { seg.hidden = log.hidden = false; }\n  const word = st.kind === 'recover' ? 'replaced' : 'added', p = st.total ? Math.round(st.done / st.total * 100) : 0;\n  seg.style.setProperty('--v', st.run && !st.total ? 6 : p);\n  prog.textContent = st.run || st.msg ? `${st.msg || 'running'} · ${st.added} ${word}${st.total ? '/' + st.total : ''} · ${st.tried} checked · ${st.alive} alive` : 'idle';\n  for (const [, cls, txt] of st.log) { const d = document.createElement('div'); d.className = 'l ' + cls; d.innerHTML = `<i>${((Date.now() - t0) / 1000).toFixed(0).padStart(3, '0')}s</i>${E(txt)}`; log.append(d); }\n  if (st.log.length) { while (log.childElementCount > 300) log.firstChild.remove(); log.scrollTop = log.scrollHeight; }\n}\nasync function tick() {\n  let st; try { st = await (await fetch('/api/loc/status?since=' + since, { cache: 'no-store' })).json(); } catch (e) { timer = setTimeout(tick, 2000); return; }\n  if (st.run) { try { const s2 = await post('/api/loc/step'); if (s2 && 'run' in s2) { st = s2; st.log = (st.log || []).filter(x => x[0] > since); } } catch (e) { timer = setTimeout(tick, 2500); return; } }\n  if (st.log.length) since = Math.max(since, ...st.log.map(x => x[0]));\n  paint(st);\n  if (st.run) { wasRun = true; timer = setTimeout(tick, 200); return; }\n  if (wasRun && st.added) { sessionStorage.setItem('locmsg', st.msg); setTimeout(() => location.reload(), 1400); }\n  wasRun = false;\n}\nfor (const k in btn) btn[k].onclick = async () => {\n  const st = await (await fetch('/api/loc/status?since=' + since, { cache: 'no-store' })).json();\n  if (st.run && st.kind === k) { await post('/api/loc/stop'); clearTimeout(timer); tick(); return; }\n  if (st.run) return;\n  log.textContent = ''; since = 0; t0 = Date.now(); wasRun = true;\n  const r = await post('/api/loc/start', { kind: k }); if (r.ok === false) { wasRun = false; }\n  clearTimeout(timer); tick();\n};\ntick();   // resume the view when the page is opened while a job is running\n})();\n"],"net.js":["text/javascript; charset=utf-8","/* xr PANEL network tools. Everything here runs in YOUR browser, on YOUR network, so a \"clean\" result is clean for you.\n   - IP scanner:   Cloudflare IPv4/IPv6 on TLS + non-TLS ports, custom ports\n   - SNI scanner:  which domains really sit behind Cloudflare (verified through /cdn-cgi/trace)\n   - Endpoint scanner (WARP / MASQUE): TCP-level reachability of the endpoint IPs (browsers cannot send UDP). */\n(() => {\n'use strict';\nconst B = BigInt, now = () => performance.now(), sleep = ms => new Promise(r => setTimeout(r, ms));\nconst E = t => String(t).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\n\n/* ---------- IP maths (BigInt, v4 + v6) ---------- */\nconst p4 = s => { const p = s.split('.'); if (p.length !== 4) return null; let n = 0n; for (const x of p) { if (!/^\\d{1,3}$/.test(x) || +x > 255) return null; n = (n << 8n) | B(+x); } return n; };\nconst f4 = n => [24n, 16n, 8n, 0n].map(k => Number((n >> k) & 255n)).join('.');\nconst p6 = s => {\n  s = s.toLowerCase(); const two = s.split('::'); if (two.length > 2 || s.includes('%')) return null;\n  const a = two[0] ? two[0].split(':') : [], b = two.length === 2 && two[1] ? two[1].split(':') : [];\n  if (two.length === 1 ? a.length !== 8 : a.length + b.length > 7) return null;\n  const g = two.length === 1 ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b]; let n = 0n;\n  for (const x of g) { if (!/^[0-9a-f]{1,4}$/.test(x)) return null; n = (n << 16n) | B(parseInt(x, 16)); } return n;\n};\nconst f6 = n => {\n  const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> B(i * 16)) & 0xffffn));\n  let bs = -1, bl = 0; for (let i = 0; i < 8;) { if (g[i]) { i++; continue; } let j = i; while (j < 8 && !g[j]) j++; if (j - i > bl) { bs = i; bl = j - i; } i = j; }\n  const h = g.map(x => x.toString(16)); if (bl < 2) return h.join(':');\n  return h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');\n};\nconst rnd = max => { // uniform-enough BigInt in [0, max)\n  if (max <= 1n) return 0n; const bits = max.toString(2).length + 16; let h = ''; for (let i = 0; i < Math.ceil(bits / 4); i++) h += Math.floor(Math.random() * 16).toString(16);\n  return B('0x' + h) % max;\n};\nconst pick = a => a[Math.floor(Math.random() * a.length)];\nfunction parseRange(line) {\n  line = line.replace(/#.*/, '').trim(); if (!line) return null;\n  const [a, b] = line.split('/'), v6 = a.includes(':'), base = v6 ? p6(a) : p4(a); if (base === null) return null;\n  const bits = v6 ? 128 : 32, pl = b === undefined ? bits : +b; if (!/^\\d+$/.test(String(pl)) || pl > bits) return null;\n  const size = B(bits - pl), mask = (1n << size) - 1n; return { v: v6 ? 6 : 4, base: base & ~mask, size, pl, text: line };\n}\nconst parseRanges = txt => { const ok = [], bad = []; for (const l of txt.split(/[\\n,;]+/)) { if (!l.replace(/#.*/, '').trim()) continue; const r = parseRange(l); r ? ok.push(r) : bad.push(l.trim()); } return { ok, bad }; };\n\n/* Cloudflare edge ranges (cloudflare.com/ips) */\nconst CF4 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];\nconst CF6 = ['2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'];\nconst WARP4 = ['8.6.112.0/24', '8.34.70.0/24', '8.34.146.0/24', '8.35.211.0/24', '8.39.125.0/24', '8.39.204.0/24', '8.39.214.0/24', '8.47.69.0/24', '162.159.192.0/24', '162.159.195.0/24', '188.114.96.0/24', '188.114.97.0/24', '188.114.98.0/24', '188.114.99.0/24'];\nconst WARP6 = ['2606:4700:d0::/48', '2606:4700:d1::/48'];\nconst MASQUE4 = ['162.159.197.0/24', '162.159.198.0/24'], MASQUE6 = ['2606:4700:103::/48'];\nconst WARP_PORTS = [500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886];\nconst MASQUE_PORTS = [443, 500, 1701, 4443, 4500, 8443, 8095];\nconst DEFAULT_PORT = 2053;                                    // default port of the scanners (was 8080)\nconst TLS_PORTS = [2053, 443, 2083, 2087, 2096, 8443], HTTP_PORTS = [80, 8880, 8080, 2052, 2082, 2086, 2095];\n/* ports browsers refuse to connect to (Chromium/Firefox \"restricted ports\") */\nconst BAD_PORTS = new Set([1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080]);\nconst SNI_DEFAULT = ['www.cloudflare.com', 'cloudflare.com', 'blog.cloudflare.com', 'developers.cloudflare.com', 'workers.cloudflare.com', 'speed.cloudflare.com', 'dash.cloudflare.com', 'cdnjs.cloudflare.com', 'discord.com', 'gateway.discord.gg', 'medium.com', 'www.digitalocean.com', 'www.udemy.com', 'openai.com', 'chatgpt.com', 'www.gitlab.com', 'www.canva.com', 'www.shopify.com', 'www.zendesk.com', 'www.nordvpn.com', 'www.ikea.com', 'www.crunchyroll.com', 'www.coindesk.com', 'www.statista.com', 'www.wattpad.com', 'www.npmjs.com', 'www.kaggle.com', 'www.notion.so', 'www.figma.com', 'www.pixiv.net'];\n\n/* Draw n IPs from a list of ranges. mode.pool = IPv4 ranges whose addresses are embedded in the IPv6 low 32 bits (how Cloudflare lays out its v6 edge). */\nfunction sample(ranges, n, mode = {}) {\n  const out = new Set(), per = Math.max(1, Math.ceil(n / Math.max(1, ranges.length))), pool = (mode.pool || []).map(parseRange).filter(Boolean);\n  for (const r of ranges) {\n    const total = r.size > 40n ? Infinity : Number(1n << r.size); let got = 0, tries = 0;\n    if (total <= per) { for (let i = 0n; i < BigInt(total); i++) out.add(r.v === 4 ? f4(r.base + i) : f6(r.base + i)); continue; }\n    while (got < per && tries++ < per * 8) {\n      let ip;\n      if (r.v === 4) { const o = r.base + rnd(1n << r.size); if (r.size >= 8n && (o & 255n) % 255n === 0n) continue; ip = f4(o); }\n      else if (mode.smart6 && r.pl <= 96 && pool.length) {\n        const m = pick(pool), v4 = m.base + rnd(1n << m.size); let o = r.base | v4;\n        if (r.pl <= 32) o |= B(pick(mode.mids || [0])) << 80n;                  // 2606:4700:3030:: style prefixes\n        ip = f6(o);\n      } else ip = f6(r.base + rnd(1n << r.size));\n      if (!out.has(ip)) { out.add(ip); got++; }\n    }\n  }\n  const a = [...out]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a.slice(0, n);\n}\n\n/* ---------- probes ---------- */\nconst hostUrl = h => h.includes(':') ? '[' + h + ']' : h;\nconst FETCH = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };\nasync function timedFetch(url, mode, timeout) {\n  const ac = new AbortController(), t0 = now(), tm = setTimeout(() => ac.abort(), timeout);\n  try { const r = await fetch(url, { ...FETCH, mode, signal: ac.signal }); return { ok: true, ms: now() - t0, r, ac, tm }; }\n  catch (e) { clearTimeout(tm); return { ok: false, ms: now() - t0, timeout: ac.signal.aborted }; }\n}\nconst traceInfo = txt => (/(^|\\n)(fl|colo)=/.test(txt)) ? { cf: true, colo: (txt.match(/colo=(\\w+)/) || [])[1] || '', loc: (txt.match(/loc=(\\w+)/) || [])[1] || '' } : { cf: false };\n\n/* plain HTTP: needs an http:// page (or \"insecure content: allow\") because of mixed-content rules */\nasync function probeHttp(host, port, timeout, verify = true) {\n  const url = `http://${hostUrl(host)}:${port}/cdn-cgi/trace`, a = await timedFetch(url, 'no-cors', timeout);\n  if (!a.ok) return { ok: false, ms: a.ms, timeout: a.timeout };\n  clearTimeout(a.tm); const res = { ok: true, ms: a.ms, via: 'http' };\n  if (verify) { const v = await timedFetch(url + '?v=' + Date.now(), 'cors', 2000); if (v.ok) { try { const i = traceInfo(await v.r.text()); if (i.cf) Object.assign(res, { via: 'cf', colo: i.colo }); } catch (e) {} clearTimeout(v.tm); } }\n  return res;\n}\n/* TLS ports: the certificate cannot match a bare IP, so the page can only see \"an error\" -> we time it.\n   A completed handshake fails after ~2 round trips; a closed or filtered port fails instantly (reset) or never (timeout). */\nasync function probeTls(host, port, timeout, cal) {\n  const a = await timedFetch(`https://${hostUrl(host)}:${port}/cdn-cgi/trace`, 'no-cors', timeout);\n  if (a.ok) { clearTimeout(a.tm); return { ok: true, ms: a.ms, via: 'tls' }; }\n  if (a.timeout) return { ok: false, ms: a.ms, timeout: true };\n  return a.ms >= (cal ? cal.minHs : 0) ? { ok: true, ms: a.ms, via: 'tls' } : { ok: false, ms: a.ms, reset: true };\n}\nasync function probe(host, port, tls, timeout, cal, verify) { return tls ? probeTls(host, port, timeout, cal) : probeHttp(host, port, timeout, verify); }\n\n/* domain behind Cloudflare? trace is read through CORS when allowed, so the answer is verified instead of guessed */\nasync function probeSni(domain, timeout) {\n  const url = `https://${domain}/cdn-cgi/trace?v=${Date.now()}`, a = await timedFetch(url, 'cors', timeout);\n  if (a.ok) {\n    let txt = ''; try { txt = await a.r.text(); } catch (e) {} clearTimeout(a.tm);\n    const i = traceInfo(txt); let ms = a.ms;\n    if (i.cf) { const b = await timedFetch(url + '&w=1', 'cors', timeout); if (b.ok) { clearTimeout(b.tm); ms = Math.min(ms, b.ms); } }   // warm connection ~ 1 round trip\n    return i.cf ? { ok: true, ms, via: 'cf', colo: i.colo } : { ok: false, ms, why: 'not Cloudflare' };\n  }\n  if (a.timeout) return { ok: false, ms: a.ms, why: 'timeout' };\n  const b = await timedFetch(url, 'no-cors', timeout);           // reachable but CORS hides the body\n  if (b.ok) { clearTimeout(b.tm); return { ok: true, ms: b.ms, via: 'open' }; }\n  return { ok: false, ms: b.ms, why: b.timeout ? 'timeout' : 'blocked' };\n}\n\n/* self-test: tells the user what this browser/network can and cannot measure */\nasync function calibrate(timeout = 3000) {\n  const cal = { tls: false, tlsMs: 0, http: null, v6: false, minHs: 0, fastReject: 0, secure: location.protocol === 'https:' };\n  const good = await timedFetch('https://1.1.1.1/cdn-cgi/trace', 'cors', timeout); if (good.ok) { clearTimeout(good.tm); cal.tls = true; cal.tlsMs = Math.round(good.ms); }\n  const bad = await timedFetch('https://192.0.2.1/', 'no-cors', timeout);       // TEST-NET-1: must never answer\n  if (!bad.ok && !bad.timeout) { cal.fastReject = bad.ms; cal.minHs = Math.max(bad.ms * 1.6, 4); } else clearTimeout(bad.tm);\n  const h = await probeHttp('1.1.1.1', 80, timeout, false);\n  cal.http = !h.ok && cal.secure && h.ms < 25 ? 'blocked' : true;      // only mixed-content blocking disables plain HTTP; a filtered 1.1.1.1 says nothing about other IPs\n  const v6 = await timedFetch('https://[2606:4700:4700::1111]/cdn-cgi/trace', 'cors', timeout); if (v6.ok) { clearTimeout(v6.tm); cal.v6 = true; }\n  return cal;\n}\n\n/* ---------- engine ---------- */\nasync function pool(n, conc, fn, ctl) { let i = 0; await Promise.all(Array.from({ length: Math.min(conc, n) }, async () => { while (i < n && !ctl.stop) await fn(i++); })); }\n\n/* ---------- UI bits ---------- */\nconst BOLT = '<svg class=\"bolt\" viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M13.2 2.5 5 13.6h5.6l-1 7.9 9.4-12.1h-5.8z\"/></svg>';\nconst COPY = async (t, btn) => { try { await navigator.clipboard.writeText(t); } catch (e) { const x = document.createElement('textarea'); x.value = t; document.body.append(x); x.select(); document.execCommand('copy'); x.remove(); } if (btn) { const l = btn.dataset.l = btn.dataset.l || btn.textContent; btn.textContent = 'Copied'; setTimeout(() => btn.textContent = l, 1300); } };\nconst fmtT = s => String(Math.floor(s / 60)).padStart(2, '0') + ':' + (s % 60).toFixed(1).padStart(4, '0');\n\nclass Log {\n  constructor(el) { this.el = el; this.q = []; this.t0 = now(); this.raf = 0; }\n  reset() { this.el.textContent = ''; this.t0 = now(); }\n  add(cls, txt) { this.q.push([cls, txt, (now() - this.t0) / 1000]); if (!this.raf) this.raf = requestAnimationFrame(() => this.flush()); }\n  flush() {\n    this.raf = 0; const f = document.createDocumentFragment();\n    for (const [c, t, s] of this.q.splice(0)) { const d = document.createElement('div'); d.className = 'l ' + c; d.innerHTML = `<i>${fmtT(s)}</i>${t}`; f.append(d); }\n    this.el.append(f); while (this.el.childElementCount > 260) this.el.firstChild.remove(); this.el.scrollTop = this.el.scrollHeight;\n  }\n}\nconst chipSet = (items, on, cls = '') => { on = on.map(String); return items.map(p => `<button type=\"button\" class=\"cb ${cls} ${on.includes(String(p)) ? 'sel' : ''}\" data-v=\"${p}\">${p}</button>`).join(''); };   // ports are numbers, defaults were strings -> nothing was pre-selected\nconst selOf = el => [...el.querySelectorAll('.cb.sel')].map(b => b.dataset.v);\nfunction bindChips(root) { root.addEventListener('click', e => { const b = e.target.closest('.cb'); if (b && root.contains(b)) b.classList.toggle('sel'); }); }\n\n/* write the fastest endpoint into the WireGuard / Masque panels (they listen for this event) */\nconst fmtEp = r => (r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port;\nasync function useFastest(kind, hint) {\n  let r = hint; if (!r) { try { r = (await (await fetch('/api/net/list?kind=' + kind)).json())[0]; } catch (e) {} }\n  if (!r) return null; window.dispatchEvent(new CustomEvent('xr:endpoint', { detail: { kind, host: r.host, port: r.port, ms: r.ms } })); return r;\n}\n\n/* saved list (server side) */\nclass Saved {\n  constructor(el, kind, limit = 0) { this.el = el; this.kind = kind; this.limit = limit; this.load(); }\n  async load() {\n    let rows = []; try { rows = await (await fetch('/api/net/list?kind=' + this.kind)).json(); } catch (e) {}\n    this.rows = rows; const k = this.kind;\n    this.el.innerHTML = `<div class=\"sv-h\"><b>Saved · ${rows.length}</b><span><button type=\"button\" class=\"btn o tl\" data-a=\"copy\">Copy</button><button type=\"button\" class=\"btn o pk\" data-a=\"clear\">Clear</button></span></div>` +\n      (rows.length ? `<div class=\"xr\">${rows.slice(0, 60).map((r, i) => `<div class=\"${this.limit && i < this.limit && k === 'ip' ? 'use' : ''}\"><span>${E(this.fmt(r))}</span><em>${r.ms} ms</em><button type=\"button\" class=\"x\" data-id=\"${r.id}\" aria-label=\"Delete\">×</button></div>`).join('')}</div>` : '<p class=\"hint\">Nothing saved yet.</p>');\n    this.el.onclick = async e => {\n      const b = e.target.closest('button'); if (!b) return;\n      if (b.dataset.a === 'copy') return COPY(rows.map(r => this.fmt(r)).join('\\n'), b);\n      if (b.dataset.a === 'clear') { if (!confirm('Delete every saved ' + k + ' entry?')) return; await post('/api/net/delete', { kind: k, all: 1 }); }\n      else if (b.dataset.id) await post('/api/net/delete', { kind: k, id: +b.dataset.id }); else return;\n      this.load();\n    };\n  }\n  fmt(r) { const h = r.host.includes(':') ? `[${r.host}]` : r.host; return this.kind === 'sni' ? r.host : `${h}:${r.port}`; }\n}\nconst post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());\n\n/* result board shared by every scanner */\nclass Board {\n  constructor(el, kind, fmt) { this.el = el; this.kind = kind; this.rows = []; this.fmt = fmt; this.dirty = 0; }\n  reset() { this.rows = []; this.draw(); }\n  add(r) { this.rows.push(r); if (!this.dirty) this.dirty = setTimeout(() => { this.dirty = 0; this.draw(); }, 200); }\n  top(n) { return [...this.rows].sort((a, b) => (a.rank || 0) - (b.rank || 0) || a.ms - b.ms).slice(0, n); }\n  draw() {\n    const t = this.top(40); this.el.innerHTML = t.length ? `<div class=\"xr\">${t.map((r, i) => `<div><u>${i + 1}</u><span>${E(this.fmt(r))}</span><small class=\"v-${r.via}\">${E(r.via === 'cf' ? 'cf' + (r.colo ? '·' + r.colo : '') : r.via)}</small><em>${Math.round(r.ms)} ms</em></div>`).join('')}</div>` : '';\n  }\n}\n\n/* ---------- scanner panel (IP / SNI / WARP / MASQUE share this shell) ---------- */\nfunction shell(root, { title, note, fast }) {\n  root.innerHTML = `<p class=\"hint\">${note}</p><div class=\"st\" data-st></div>\n  <div data-body></div>\n  <div class=\"row\"><button type=\"button\" class=\"btn\" data-go>Start</button><button type=\"button\" class=\"btn o pk\" data-stop disabled>Stop</button><button type=\"button\" class=\"btn o yl\" data-test>Self-test</button>${fast ? `<button type=\"button\" class=\"btn o tl\" data-fast>${BOLT}Use fastest</button>` : ''}</div>\n  <div class=\"seg\" style=\"--v:0\"><i></i><span data-prog>idle</span></div>\n  <div class=\"xlog\" data-log aria-live=\"polite\"></div>\n  <h3 class=\"sub\">Results</h3><div data-board></div>\n  <div class=\"row\"><button type=\"button\" class=\"btn o tl\" data-save disabled>Save top</button><label class=\"ck\"><input type=\"checkbox\" data-auto checked> auto-save when finished</label></div>\n  <div class=\"saved\" data-saved></div>`;\n  return { body: root.querySelector('[data-body]'), go: root.querySelector('[data-go]'), stop: root.querySelector('[data-stop]'), test: root.querySelector('[data-test]'),\n    seg: root.querySelector('.seg'), prog: root.querySelector('[data-prog]'), log: new Log(root.querySelector('[data-log]')), board: root.querySelector('[data-board]'),\n    save: root.querySelector('[data-save]'), fast: root.querySelector('[data-fast]'), auto: root.querySelector('[data-auto]'), saved: root.querySelector('[data-saved]'), st: root.querySelector('[data-st]') };\n}\nfunction showCal(ui, cal) {\n  const c = (ok, t) => `<span class=\"chip ${ok === true ? 'ok' : ok === 'warn' ? 'run' : ''}\">${ok === true ? '✓' : ok === 'warn' ? '!' : '✕'} ${t}</span>`;\n  ui.st.innerHTML = c(cal.tls, 'TLS' + (cal.tls ? ' ' + cal.tlsMs + ' ms' : '')) + c(cal.fastReject ? 'warn' : true, cal.fastReject ? 'timing coarse' : 'timing') +\n    c(cal.http === true ? true : 'warn', cal.http === 'blocked' ? 'HTTP blocked (https page)' : 'HTTP') + c(cal.v6, 'IPv6');\n}\nconst tick = (ui, done, total, alive, best, t0) => { const p = total ? done / total : 0, s = (now() - t0) / 1000; ui.seg.style.setProperty('--v', Math.round(p * 100)); ui.prog.textContent = `${done}/${total} · ${alive} alive · best ${best ? Math.round(best) + ' ms' : '–'} · ${(done / Math.max(s, .1)).toFixed(1)}/s`; };\n\nfunction mountScanner(root, cfg) {\n  const ui = shell(root, cfg), ctl = { stop: false }; let cal = null, running = false;\n  ui.body.innerHTML = cfg.form(); bindChips(ui.body);\n  const get = n => ui.body.querySelector(`[data-f=\"${n}\"]`);\n  const board = new Board(ui.board, cfg.kind, cfg.fmt), saved = new Saved(ui.saved, cfg.kind, +root.dataset.limit || 0);\n  const ensureCal = async () => { if (cal) return cal; ui.log.add('i', 'self-test…'); cal = await calibrate(); showCal(ui, cal); return cal; };\n  ui.test.onclick = async () => { ui.test.disabled = true; cal = null; await ensureCal(); ui.log.add(cal.tls ? 'ok' : 'bad', cal.tls ? `Cloudflare reachable · ${cal.tlsMs} ms` : 'Cloudflare 1.1.1.1 not reachable from this network'); ui.test.disabled = false; };\n  ui.save.onclick = async () => { const items = board.top(+(get('keep') || { value: 50 }).value || 50).map(cfg.item); if (!items.length) return; const r = await post('/api/net/save', { kind: cfg.kind, items }); ui.log.add('ok', `saved ${r.saved}`); saved.load(); };\n  ui.stop.onclick = () => { ctl.stop = true; ui.log.add('w', 'stopping…'); };\n  if (ui.fast) ui.fast.onclick = async () => {\n    const r = await useFastest(cfg.kind, board.top(1)[0]); ui.log.add(r ? 'ok' : 'bad', r ? `fastest ${E(fmtEp(r))} · ${Math.round(r.ms)} ms → ${cfg.kind === 'warp' ? 'WireGuard' : 'Masque'} endpoint` : 'no endpoint yet — run a scan first');\n  };\n  ui.go.onclick = async () => {\n    if (running) return; running = true; ctl.stop = false; ui.go.disabled = true; ui.stop.disabled = false; ui.save.disabled = true; ui.log.reset(); board.reset();\n    const t0 = now(); let done = 0, alive = 0, best = 0, skipped = 0;\n    try {\n      if (cfg.gate) { const why = await cfg.gate(); if (why) { ui.log.add('bad', why); ui.st.innerHTML = `<span class=\"chip\">✕ ${E(why)}</span>`; return; } }\n      await ensureCal();\n      const plan = await cfg.plan({ get, cal, log: ui.log }); if (!plan) return;\n      const total = plan.total; ui.log.add('i', plan.info);\n      const upd = () => tick(ui, done, total, alive, best, t0), iv = setInterval(upd, 250);\n      await pool(plan.units.length, plan.conc, async i => {\n        const res = await plan.run(plan.units[i], ctl);\n        alive += res.alive !== undefined ? res.alive : res.hits.length; for (const r of res.hits) { if (!best || r.ms < best) best = r.ms; board.add(r); ui.log.add('ok', cfg.line(r)); }\n        if (res.note) ui.log.add(res.cls || 'd', res.note);\n        done += res.count; skipped += res.miss || 0;\n        if (res.miss && skipped % 50 < res.miss) ui.log.add('d', `· ${skipped} without answer so far`);\n      }, ctl);\n      clearInterval(iv); upd();\n      ui.log.add(alive ? 'ok' : 'bad', `${ctl.stop ? 'stopped' : 'done'} · ${alive} alive of ${done} · ${((now() - t0) / 1000).toFixed(1)}s`);\n      ui.save.disabled = !alive; if (alive && ui.auto.checked && !ctl.stop) ui.save.onclick();\n    } catch (e) { ui.log.add('bad', 'error: ' + E(e.message || e)); }\n    finally { running = false; ui.go.disabled = false; ui.stop.disabled = true; }\n  };\n  return { ui, board, saved, setBusy: v => { if (!running) ui.go.disabled = v; } };\n}\n\n/* ---------- IP scanner ---------- */\nconst rangeTxt = a => a.join('\\n');\nfunction mountIP(root) {\n  const wrap = document.createElement('div'); root.append(wrap);\n  const tabs = document.createElement('div'); tabs.className = 'tabs'; tabs.innerHTML = '<button type=\"button\" class=\"on\" data-t=\"ip\">IP</button><button type=\"button\" data-t=\"sni\">SNI</button>';\n  wrap.append(tabs); const a = document.createElement('div'), b = document.createElement('div'); b.hidden = true; wrap.append(a, b);\n  tabs.onclick = e => { const t = e.target.closest('button'); if (!t) return; tabs.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === t)); a.hidden = t.dataset.t !== 'ip'; b.hidden = t.dataset.t !== 'sni'; };\n  a.dataset.limit = root.dataset.limit || 0;\n\n  mountScanner(a, {\n    kind: 'ip', note: 'Scans Cloudflare IPs from this browser, so the result is clean for <b>your</b> network. TLS ports are timed (a bare IP cannot match a certificate, so this is meant for Cloudflare ranges); plain-HTTP ports are verified through <code>/cdn-cgi/trace</code>.',\n    fmt: r => `${r.host.includes(':') ? '[' + r.host + ']' : r.host}:${r.port}`, item: r => ({ host: r.host, port: r.port, tls: r.tls, ms: r.ms, via: r.via }),\n    line: r => `<b>${E(r.host)}</b>:${r.port} <u>${r.tls ? 'tls' : 'http'}</u> ${Math.round(r.ms)}ms ${r.via === 'cf' ? '<s>cf·' + E(r.colo || '?') + '</s>' : ''}`,\n    form: () => `\n      <div class=\"grp\"><h3>Version</h3>${chipSet(['IPv4', 'IPv6'], ['IPv4', 'IPv6'], 'ver')}</div>\n      <div class=\"grp\" data-f=\"tls\"><h3>TLS ports</h3>${chipSet(TLS_PORTS, [DEFAULT_PORT, 443, 2083, 2087, 2096, 8443].map(String))}</div>\n      <div class=\"grp\" data-f=\"http\"><h3>Non-TLS ports</h3>${chipSet(HTTP_PORTS, ['80', '8880'])}</div>\n      <div class=\"grp\"><h3>Custom port</h3><div class=\"row\" style=\"margin:0\"><input data-f=\"cport\" inputmode=\"numeric\" placeholder=\"e.g. 2408\" style=\"max-width:130px\"><select data-f=\"ctype\"><option value=\"1\">TLS</option><option value=\"0\">non-TLS</option></select><button type=\"button\" class=\"btn o tl\" data-f=\"cadd\">Add</button></div></div>\n      <label class=\"wide\">Ranges · IPs or CIDR, one per line<textarea data-f=\"ranges\" rows=\"5\" spellcheck=\"false\">${rangeTxt([...CF4, ...CF6])}</textarea></label>\n      <div class=\"f\"><label>IPs to test<input data-f=\"count\" inputmode=\"numeric\" value=\"150\"></label><label>Parallel<input data-f=\"conc\" inputmode=\"numeric\" value=\"30\"></label><label>Timeout (ms)<input data-f=\"timeout\" inputmode=\"numeric\" value=\"3000\"></label><label>Keep best<input data-f=\"keep\" inputmode=\"numeric\" value=\"50\"></label></div>\n      <label class=\"ck\"><input type=\"checkbox\" data-f=\"smart6\" checked> smart IPv6 (Cloudflare-style addresses)</label>`,\n    async plan({ get, cal, log }) {\n      const q = n => get(n), num = (n, d, lo, hi) => Math.min(hi, Math.max(lo, parseInt(q(n).value) || d));\n      const vers = selOf(root.querySelector('.grp')); const want4 = vers.includes('IPv4'), want6 = vers.includes('IPv6');\n      const ports = [...selOf(q('tls')).map(p => [+p, true]), ...selOf(q('http')).map(p => [+p, false])];\n      const bad = ports.filter(([p]) => BAD_PORTS.has(p)); if (bad.length) log.add('w', `browser refuses port ${bad.map(x => x[0]).join(', ')} — skipped`);\n      let P = ports.filter(([p]) => !BAD_PORTS.has(p));\n      if (cal.http !== true && P.some(x => !x[1])) { log.add('w', cal.http === 'blocked' ? 'non-TLS ports need an http:// panel page (or “insecure content: allow” for this site) — skipped' : 'plain HTTP unavailable — non-TLS ports skipped'); P = P.filter(x => x[1]); }\n      if (!P.length) { log.add('bad', 'no usable port selected'); return null; }\n      const { ok, bad: badR } = parseRanges(q('ranges').value); if (badR.length) log.add('w', 'ignored: ' + E(badR.slice(0, 3).join(' · ')));\n      let R = ok.filter(r => (r.v === 4 ? want4 : want6)); if (!cal.v6) { const n = R.length; R = R.filter(r => r.v === 4); if (n !== R.length) log.add('w', 'no IPv6 on this network — IPv6 ranges skipped'); }\n      if (!R.length) { log.add('bad', 'no valid range for the selected versions'); return null; }\n      const count = num('count', 150, 1, 5000), timeout = num('timeout', 3000, 500, 15000), conc = num('conc', 30, 1, 120), verify = true;\n      const ips = sample(R, count, { smart6: q('smart6').checked, pool: ['104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13'], mids: [0, 0x3030, 0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x3036, 0x3037] });\n      return {\n        units: ips, conc, total: ips.length * P.length, info: `${ips.length} IPs × ${P.length} ports · ${conc} parallel · ${timeout} ms`,\n        async run(ip, ctl) {\n          const hits = []; let miss = 0, fails = 0, cnt = 0;\n          for (const [port, tls] of [...P].sort(() => Math.random() - .5)) {          // an IP that times out twice in a row is skipped\n            if (ctl.stop) break; cnt++;\n            const r = await probe(ip, port, tls, timeout, cal, verify);\n            if (r.ok && (r.via === 'cf' || r.ms >= 2)) { fails = 0; hits.push({ host: ip, port, tls, ms: r.ms, via: r.via, colo: r.colo }); } else { miss++; fails = r.timeout ? fails + 1 : 0; if (fails >= 2) break; }\n          }\n          return { hits, miss, count: P.length, note: null, cnt };\n        }\n      };\n    }\n  }).ui.body.addEventListener('click', e => {\n    const b = e.target.closest('[data-f=\"cadd\"]'); if (!b) return; const f = n => a.querySelector(`[data-f=\"${n}\"]`), p = parseInt(f('cport').value);\n    if (!(p > 0 && p < 65536)) return; const tls = f('ctype').value === '1', grp = f(tls ? 'tls' : 'http');\n    if (!grp.querySelector(`[data-v=\"${p}\"]`)) grp.insertAdjacentHTML('beforeend', `<button type=\"button\" class=\"cb sel cust\" data-v=\"${p}\">${p}</button>`); f('cport').value = '';\n  });\n\n  mountScanner(b, {\n    kind: 'sni', note: 'Finds domains that really are behind Cloudflare: each one is asked for <code>/cdn-cgi/trace</code> and must answer like a Cloudflare edge. The scan runs from this browser, so latency is yours.',\n    fmt: r => r.host, item: r => ({ host: r.host, port: 0, tls: true, ms: r.ms, via: r.via }),\n    line: r => `<b>${E(r.host)}</b> ${Math.round(r.ms)}ms <s>${r.via === 'cf' ? 'cf·' + E(r.colo || '?') : 'reachable'}</s>`,\n    form: () => `<label class=\"wide\">Domains · one per line (paste your own list or import a file)<textarea data-f=\"list\" rows=\"6\" spellcheck=\"false\">${SNI_DEFAULT.join('\\n')}</textarea></label>\n      <div class=\"row\" style=\"margin-top:0\"><label class=\"btn o tl\" style=\"margin:0\">Import .txt<input type=\"file\" data-f=\"file\" accept=\".txt,text/plain\" hidden></label></div>\n      <div class=\"f\"><label>Parallel<input data-f=\"conc\" inputmode=\"numeric\" value=\"12\"></label><label>Timeout (ms)<input data-f=\"timeout\" inputmode=\"numeric\" value=\"4000\"></label><label>Keep best<input data-f=\"keep\" inputmode=\"numeric\" value=\"30\"></label></div>\n      <label class=\"ck\"><input type=\"checkbox\" data-f=\"loose\"> include reachable domains that hide the trace (CORS) — unverified</label>`,\n    async plan({ get, log }) {\n      const list = [...new Set(get('list').value.split(/[\\s,;]+/).map(s => s.trim().toLowerCase().replace(/^https?:\\/\\//, '').replace(/[\\/?#].*$/, '')).filter(s => /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\\.[a-z0-9-]{2,}$/.test(s)))];\n      if (!list.length) { log.add('bad', 'no valid domain'); return null; }\n      const timeout = Math.min(15000, Math.max(800, parseInt(get('timeout').value) || 4000)), conc = Math.min(40, Math.max(1, parseInt(get('conc').value) || 12)), loose = get('loose').checked;\n      return {\n        units: list, conc, total: list.length, info: `${list.length} domains · ${conc} parallel`,\n        async run(d) { const r = await probeSni(d, timeout); const hit = r.ok && (r.via === 'cf' || loose);\n          return { hits: hit ? [{ host: d, port: 0, tls: true, ms: r.ms, via: r.via, colo: r.colo }] : [], count: 1, miss: hit ? 0 : 1, note: !hit && r.why === 'not Cloudflare' ? `<b>${E(d)}</b> answers, but not from Cloudflare` : null, cls: 'w' }; }\n      };\n    }\n  }).ui.body.querySelector('[data-f=\"file\"]').onchange = async e => { const f = e.target.files[0]; if (f) b.querySelector('[data-f=\"list\"]').value = (await f.text()).slice(0, 400000); };\n}\n\n/* ---------- WARP / MASQUE endpoint scanner ---------- */\nfunction mountEndpoints(root) {\n  const modeBox = document.createElement('div'); modeBox.className = 'tabs'; modeBox.innerHTML = '<button type=\"button\" class=\"on\" data-t=\"warp\">WARP</button><button type=\"button\" data-t=\"masque\">MASQUE</button>';\n  const a = document.createElement('div'), b = document.createElement('div'); b.hidden = true; root.append(modeBox, a, b);\n  modeBox.onclick = e => { const t = e.target.closest('button'); if (!t) return; modeBox.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === t)); a.hidden = t.dataset.t !== 'warp'; b.hidden = t.dataset.t !== 'masque'; };\n  /* MASQUE only scans once a MASQUE device is registered (the endpoint list is useless without one) */\n  const masqueReady = async () => { try { const d = await (await fetch('/api/masque', { cache: 'no-store' })).json(); return !!(d && d.private_key); } catch (e) { return false; } };\n  const make = (el, kind, label, r4, r6, ports, pool) => {\n    const isM = kind === 'masque';\n    const sc = mountScanner(el, {\n    kind, fast: true, note: `${label} endpoints speak UDP, which a browser cannot send. For every endpoint IP this scan checks the <b>reachability and round-trip time</b> (TCP) and then tests <b>each ${label} port</b> on it. A port that answers over TCP is marked <code>tcp</code> (verified open); a port that cannot be proven from a browser is kept as <code>udp</code> (IP is alive, the UDP port itself can only be confirmed by the client app). Verified ports are ranked first.${isM ? ' <b>Needs a registered Masque device.</b>' : ''}`,\n    gate: isM ? async () => (await masqueReady()) ? null : 'Register Masque first — scanning is disabled until a Masque device exists' : null,\n    fmt: r => `${r.host.includes(':') ? '[' + r.host + ']' : r.host}:${r.port}`, item: r => ({ host: r.host, port: r.port, tls: false, ms: r.ms, via: r.via || 'tcp' }),\n    line: r => `<b>${E(r.host)}</b>:${r.port} ${Math.round(r.ms)}ms <s>${r.via === 'tcp' ? 'tcp ✓' : 'udp ?'}</s>`,\n    form: () => `<div class=\"grp\"><h3>Version</h3>${chipSet(['IPv4', 'IPv6'], ['IPv4', 'IPv6'], 'ver')}</div>\n      <label class=\"wide\">Ranges<textarea data-f=\"ranges\" rows=\"4\" spellcheck=\"false\">${rangeTxt([...r4, ...r6])}</textarea></label>\n      <label class=\"wide\">Ports to scan (comma separated)<textarea data-f=\"ports\" rows=\"2\" spellcheck=\"false\">${ports.join(', ')}</textarea></label>\n      <div class=\"f\"><label>IPs to test<input data-f=\"count\" inputmode=\"numeric\" value=\"120\"></label><label>Ports kept per IP<input data-f=\"pp\" inputmode=\"numeric\" value=\"${ports.length}\"></label><label>Parallel<input data-f=\"conc\" inputmode=\"numeric\" value=\"12\"></label><label>Timeout (ms)<input data-f=\"timeout\" inputmode=\"numeric\" value=\"2500\"></label><label>Keep best<input data-f=\"keep\" inputmode=\"numeric\" value=\"30\"></label></div>`,\n    async plan({ get, cal, log }) {\n      const vers = selOf(el.querySelector('.grp')), { ok } = parseRanges(get('ranges').value);\n      let R = ok.filter(r => vers.includes(r.v === 4 ? 'IPv4' : 'IPv6')); if (!cal.v6) R = R.filter(r => r.v === 4);\n      const P = [...new Set(get('ports').value.split(/[\\s,;]+/).map(Number).filter(p => p > 0 && p < 65536))]; if (!R.length || !P.length) { log.add('bad', 'need a range and a port'); return null; }\n      const timeout = Math.min(15000, Math.max(500, parseInt(get('timeout').value) || 2500)), conc = Math.min(60, Math.max(1, parseInt(get('conc').value) || 12)), pp = Math.min(P.length, Math.max(1, parseInt(get('pp').value) || P.length));\n      const ips = sample(R, Math.min(5000, Math.max(1, parseInt(get('count').value) || 120)), { smart6: true, pool, mids: [0] });\n      const probes = [[443, true]]; if (cal.http === true) probes.push([80, false]);\n      const refused = P.filter(p => BAD_PORTS.has(p)); if (refused.length) log.add('w', `browser refuses port ${refused.join(', ')} — kept as unverified udp`);\n      return {\n        units: ips, conc, total: ips.length, info: `${ips.length} endpoint IPs × ${P.length} ports (${P.join(', ')}) · reachability on ${probes.map(p => p[0]).join('/')} then every port`,\n        async run(ip, ctl) {\n          let best = null; for (const [p, tls] of probes) { if (ctl.stop) break; const r = await probe(ip, p, tls, timeout, cal, false); if (r.ok && (!best || r.ms < best)) best = r.ms; }\n          if (best === null || ctl.stop) return { hits: [], count: 1, miss: 1 };\n          const res = await Promise.all(P.map(async port => {\n            if (port === 443) return { port, ok: true, ms: best };                      // already measured above\n            if (BAD_PORTS.has(port)) return { port, ok: false };\n            const r = await probeTls(ip, port, timeout, cal); return { port, ok: r.ok, ms: r.ms };\n          }));\n          const open = res.filter(x => x.ok).map(x => ({ host: ip, port: x.port, tls: false, ms: x.ms, via: 'tcp', rank: 0 }));\n          const rest = res.filter(x => !x.ok).sort(() => Math.random() - .5).map(x => ({ host: ip, port: x.port, tls: false, ms: best, via: 'udp', rank: 1 }));\n          return { hits: [...open, ...rest].slice(0, pp), count: 1, alive: 1 };\n        }\n      };\n    }\n    });\n    if (isM) {   // Start stays disabled until Masque is registered\n      const sync = async () => { const ok = await masqueReady(); sc.setBusy(!ok); sc.ui.st.innerHTML = ok ? '' : '<span class=\"chip\">✕ Masque not registered — register it above to enable scanning</span>'; };\n      sync(); window.addEventListener('xr:reg', e => { if (e.detail && e.detail.kind === 'masque') sync(); });\n    }\n    return sc;\n  };\n  make(a, 'warp', 'WARP', WARP4, WARP6, WARP_PORTS, WARP4); make(b, 'masque', 'MASQUE', MASQUE4, MASQUE6, MASQUE_PORTS, MASQUE4);\n}\n\n/* ---------- boot ---------- */\nwindow.XRNET = { BOLT, useFastest, fmtEp, p4, f4, p6, f6, parseRange, parseRanges, sample, probe, probeSni, calibrate, COPY, post, Saved, CF4, CF6, WARP_PORTS, MASQUE_PORTS };\ndocument.addEventListener('DOMContentLoaded', () => {\n  const ip = document.querySelector('[data-scan=\"ip\"]'), ep = document.querySelector('[data-scan=\"ep\"]');\n  if (ip) mountIP(ip); if (ep) mountEndpoints(ep);\n});\nif (document.readyState !== 'loading') { const ip = document.querySelector('[data-scan=\"ip\"]'), ep = document.querySelector('[data-scan=\"ep\"]'); if (ip && !ip.firstChild) mountIP(ip); if (ep && !ep.firstChild) mountEndpoints(ep); }\n})();\n"],"qr.js":["text/javascript; charset=utf-8","/* Small QR code encoder (byte mode, error correction M, versions 1-40) -> window.QR.svg(text) */\n(() => {\n'use strict';\nconst ECC = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];\nconst BLK = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];\n\nconst rawModules = v => { let r = (16 * v + 128) * v + 64; if (v >= 2) { const a = Math.floor(v / 7) + 2; r -= (25 * a - 10) * a - 55; if (v >= 7) r -= 36; } return r; };\nconst dataCodewords = v => Math.floor(rawModules(v) / 8) - ECC[v] * BLK[v];\nconst alignPos = v => { if (v === 1) return []; const n = Math.floor(v / 7) + 2, step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2, r = [6]; for (let p = v * 4 + 10; r.length < n; p -= step) r.splice(1, 0, p); return r; };\n\n/* Reed-Solomon over GF(256) */\nconst mul = (x, y) => { let z = 0; for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; } return z & 255; };\nconst rsDiv = n => { const r = new Array(n).fill(0); r[n - 1] = 1; let root = 1; for (let i = 0; i < n; i++) { for (let j = 0; j < n; j++) { r[j] = mul(r[j], root); if (j + 1 < n) r[j] ^= r[j + 1]; } root = mul(root, 2); } return r; };\nconst rsRem = (data, div) => { const r = div.map(() => 0); for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => r[i] ^= mul(c, f)); } return r; };\n\nfunction addEcc(data, v) {\n  const nb = BLK[v], el = ECC[v], raw = Math.floor(rawModules(v) / 8), short = nb - raw % nb, sl = Math.floor(raw / nb), div = rsDiv(el), blocks = []; let k = 0;\n  for (let i = 0; i < nb; i++) { const d = data.slice(k, k + sl - el + (i < short ? 0 : 1)); k += d.length; const e = rsRem(d, div); if (i < short) d.push(0); blocks.push(d.concat(e)); }\n  const out = []; for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== sl - el || j >= short) out.push(b[i]); }); return out;\n}\n\nfunction encode(text) {\n  const bytes = [...new TextEncoder().encode(text)]; let v = 1;\n  for (; ; v++) { if (v > 40) throw new Error('Too long for a QR code'); if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= dataCodewords(v) * 8) break; }\n  const bits = []; const put = (x, n) => { for (let i = n - 1; i >= 0; i--) bits.push((x >>> i) & 1); };\n  put(4, 4); put(bytes.length, v < 10 ? 8 : 16); bytes.forEach(b => put(b, 8));\n  const cap = dataCodewords(v) * 8; put(0, Math.min(4, cap - bits.length)); put(0, (8 - bits.length % 8) % 8);\n  for (let p = 0xec; bits.length < cap; p ^= 0xec ^ 0x11) put(p, 8);\n  const cw = []; for (let i = 0; i < bits.length; i += 8) cw.push(parseInt(bits.slice(i, i + 8).join(''), 2));\n  return { v, words: addEcc(cw, v) };\n}\n\nfunction build(v, words, mask) {\n  const n = v * 4 + 17, m = Array.from({ length: n }, () => new Array(n).fill(false)), fn = Array.from({ length: n }, () => new Array(n).fill(false));\n  const set = (x, y, d) => { m[y][x] = d; fn[y][x] = true; };\n  for (let i = 0; i < n; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }\n  const finder = (cx, cy) => { for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) { const d = Math.max(Math.abs(dx), Math.abs(dy)), x = cx + dx, y = cy + dy; if (x >= 0 && x < n && y >= 0 && y < n) set(x, y, d !== 2 && d !== 4); } };\n  finder(3, 3); finder(n - 4, 3); finder(3, n - 4);\n  const ap = alignPos(v); for (let i = 0; i < ap.length; i++) for (let j = 0; j < ap.length; j++) { if ((i === 0 && j === 0) || (i === 0 && j === ap.length - 1) || (i === ap.length - 1 && j === 0)) continue; for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1); }\n  const fmt = (() => { const d = (0 << 3) | mask; let r = d; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537); return ((d << 10) | r) ^ 0x5412; })();   // M = 00\n  const b = i => ((fmt >>> i) & 1) !== 0;\n  for (let i = 0; i <= 5; i++) set(8, i, b(i)); set(8, 7, b(6)); set(8, 8, b(7)); set(7, 8, b(8)); for (let i = 9; i < 15; i++) set(14 - i, 8, b(i));\n  for (let i = 0; i < 8; i++) set(n - 1 - i, 8, b(i)); for (let i = 8; i < 15; i++) set(8, n - 15 + i, b(i)); set(8, n - 8, true);\n  if (v >= 7) { let r = v; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25); const bitsV = (v << 12) | r; for (let i = 0; i < 18; i++) { const bit = ((bitsV >>> i) & 1) !== 0, a = n - 11 + i % 3, c = Math.floor(i / 3); set(a, c, bit); set(c, a, bit); } }\n  let i = 0; for (let right = n - 1; right >= 1; right -= 2) { if (right === 6) right = 5; for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) { const x = right - j, up = ((right + 1) & 2) === 0, y = up ? n - 1 - vert : vert; if (!fn[y][x] && i < words.length * 8) { m[y][x] = ((words[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0; i++; } } }\n  const inv = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x, y) => x % 3 === 0, (x, y) => (x + y) % 3 === 0, (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => x * y % 2 + x * y % 3 === 0, (x, y) => (x * y % 2 + x * y % 3) % 2 === 0, (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0][mask];\n  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!fn[y][x] && inv(x, y)) m[y][x] = !m[y][x];\n  return m;\n}\n\nfunction penalty(m) {\n  const n = m.length; let p = 0;\n  const run = line => { let s = 0, c = 1; for (let i = 1; i <= n; i++) { if (i < n && line[i] === line[i - 1]) c++; else { if (c >= 5) s += 3 + c - 5; c = 1; } } return s; };\n  const fin = line => { let s = 0; const pat = [1, 0, 1, 1, 1, 0, 1]; for (let i = 0; i + 6 < n; i++) { if (pat.every((b, k) => (line[i + k] ? 1 : 0) === b)) { const l = i >= 4 && [1, 2, 3, 4].every(k => !line[i - k]), r = i + 10 < n + 0 && [7, 8, 9, 10].every(k => !line[i + k]); if (l || i < 4 && [1, 2, 3, 4].every(k => i - k < 0 || !line[i - k])) s += 40; if (r || i + 10 >= n) s += 40; } } return s; };\n  for (let y = 0; y < n; y++) { p += run(m[y]); p += fin(m[y]); } for (let x = 0; x < n; x++) { const col = m.map(r => r[x]); p += run(col); p += fin(col); }\n  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) if (m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) p += 3;\n  let dark = 0; for (const r of m) for (const c of r) if (c) dark++; p += (Math.ceil(Math.abs(dark * 20 - n * n * 10) / (n * n)) - 1) * 10; return p;\n}\n\nfunction matrix(text) { const { v, words } = encode(text); let best = null, bp = Infinity; for (let k = 0; k < 8; k++) { const m = build(v, words, k), s = penalty(m); if (s < bp) { bp = s; best = m; } } return best; }\nfunction svg(text, px = 4) {\n  const m = matrix(text), n = m.length, q = 4; let d = '';\n  for (let y = 0; y < n; y++) { let x = 0; while (x < n) { if (!m[y][x]) { x++; continue; } let e = x; while (e < n && m[y][e]) e++; d += `M${x + q} ${y + q}h${e - x}v1h-${e - x}z`; x = e; } }\n  const s = (n + 2 * q); return `<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ${s} ${s}\" width=\"${s * px}\" height=\"${s * px}\" shape-rendering=\"crispEdges\"><rect width=\"${s}\" height=\"${s}\" fill=\"#fff\"/><path d=\"${d}\" fill=\"#000\"/></svg>`;\n}\nwindow.QR = { svg, matrix, _encode: encode, _build: build };\n})();\n"],"s.css":["text/css; charset=utf-8",":root{--on:#04140a;--sh:#0006;--cbg:#0a0e0d;--gr:transparent;--bg:#080b0a;--pn:#101614;--ln:#26302c;--tl:#52e39a;--pk:#f27a86;--yl:#e8b84a;--pu:#7fe3ee;--tx:#e8efea;--mt:#8a968f;--spring:cubic-bezier(.32,.72,0,1);--pop:cubic-bezier(.34,1.56,.64,1)}\n*{box-sizing:border-box;margin:0}\nbody{background:var(--bg);color:var(--tx);font:21px/1.25 'VT323',ui-monospace,monospace;min-height:100dvh;background-image:linear-gradient(var(--gr) 1px,transparent 1px),linear-gradient(90deg,var(--gr) 1px,transparent 1px);background-size:24px 24px}\nh1,h3,label,.brand,.side a,.btn,.tag{font-family:'Press Start 2P',ui-monospace,monospace;font-weight:400}\nh1{font-size:15px;color:var(--pk);margin-bottom:22px;line-height:1.6}h1 small{color:var(--mt);font-size:10px;margin-left:8px}\nh3{font-size:10px;color:var(--mt);margin-bottom:12px}\nmain{padding:20px 16px calc(40px + env(safe-area-inset-bottom));max-width:980px;margin:0 auto}\n.side{position:fixed;inset:0 auto 0 0;width:230px;background:var(--pn);border-right:3px solid var(--ln);padding:24px 16px;display:flex;flex-direction:column;gap:10px;z-index:30;transition:transform .75s var(--spring)}\n.brand{color:var(--tl);font-size:13px;line-height:1.6;margin-bottom:16px}\n.side a{color:var(--tx);text-decoration:none;font-size:10px;padding:14px 12px;border:3px solid transparent;transition:transform .5s var(--pop),border-color .4s,color .4s}\n.side a.on{border-color:var(--tl);color:var(--tl);box-shadow:4px 4px 0 var(--sh)}.side a:active{transform:scale(.95)}.side .out{margin-top:auto;color:var(--pk)}\n.top,#scrim{display:none}\n@media(min-width:900px){body.app main{margin-left:260px;max-width:none;padding:32px}}\n@media(max-width:899px){\n .top{display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:20;background:var(--pn);border-bottom:3px solid var(--ln);padding:12px 16px;padding-top:calc(12px + env(safe-area-inset-top))}.top .brand{margin:0}\n .top button{background:none;border:3px solid var(--tl);width:44px;height:44px;display:grid;place-content:center;gap:5px;transition:transform .5s var(--pop)}.top button:active{transform:scale(.9)}\n .top i{display:block;width:18px;height:3px;background:var(--tl)}\n .side{transform:translateX(-105%);padding-top:calc(24px + env(safe-area-inset-top))}.nav .side{transform:none;box-shadow:8px 0 0 var(--sh)}\n #scrim{display:block;position:fixed;inset:0;background:#000a;opacity:0;pointer-events:none;z-index:25;transition:opacity .7s var(--spring)}.nav #scrim{opacity:1;pointer-events:auto}}\n.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:18px}\n.box{background:var(--pn);border:3px solid var(--c,var(--ln));padding:16px;box-shadow:5px 5px 0 var(--sh);animation:rise 1.1s var(--spring) backwards}\n.box:nth-child(2){animation-delay:.08s}.box:nth-child(3){animation-delay:.16s}.box:nth-child(4){animation-delay:.24s}.box:nth-child(n+5){animation-delay:.32s}\n@keyframes rise{from{opacity:0;transform:translateY(26px) scale(.97)}}\n.tl{--c:var(--tl)}.pk{--c:var(--pk)}.yl{--c:var(--yl)}.pu{--c:var(--pu)}.box h3{color:var(--c)}\n.big{font-size:34px;overflow-wrap:anywhere}.box small{color:var(--mt)}\n.bar{height:16px;border:3px solid var(--ln);margin-top:10px;background:repeating-linear-gradient(90deg,var(--c,var(--tl)) 0 8px,transparent 8px 12px) 0 0/calc(var(--v,0)*1%) 100% no-repeat;transition:background-size 1s var(--spring)}\n.acc{background:var(--pn);border:3px solid var(--ln);margin-bottom:14px;box-shadow:5px 5px 0 var(--sh);transition:border-color .6s}.acc.open{border-color:var(--tl)}\n.hd{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:16px;cursor:pointer;font-size:24px;-webkit-tap-highlight-color:transparent}\n.bd{display:grid;grid-template-rows:0fr;transition:grid-template-rows .8s var(--spring)}.open>.bd{grid-template-rows:1fr}\n.bd>div{overflow:hidden;padding:0 16px;opacity:0;transition:opacity .6s var(--spring),padding .8s var(--spring)}.open>.bd>div{opacity:1;padding:4px 16px 18px}\n.tag{font-size:9px;padding:6px 8px;border:3px solid var(--mt);color:var(--mt)}.tag.active{border-color:var(--tl);color:var(--tl)}.tag.expired,.tag.limited{border-color:var(--pk);color:var(--pk)}\n.meta{color:var(--mt);margin-bottom:6px}code{display:block;margin:12px 0;padding:10px;background:var(--cbg);border:3px dashed var(--ln);word-break:break-all;font:18px/1.2 ui-monospace,monospace;color:var(--yl)}\n.f{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;align-items:end;margin-top:12px}\nlabel{font-size:9px;color:var(--mt);display:grid;gap:8px;line-height:1.5}label.ck{display:flex;align-items:center;gap:8px}\ninput,select{font:21px 'VT323',monospace;background:var(--bg);color:var(--tx);border:3px solid var(--ln);padding:10px;width:100%;min-height:46px;border-radius:0;outline:none;transition:border-color .4s}\ninput:focus,select:focus{border-color:var(--tl)}input[type=checkbox]{width:22px;min-height:22px;accent-color:var(--tl)}\n.btn{display:inline-block;font-size:10px;color:var(--on);background:var(--c,var(--tl));border:3px solid var(--c,var(--tl));padding:14px 16px;cursor:pointer;text-decoration:none;box-shadow:4px 4px 0 var(--sh);transition:transform .5s var(--pop),box-shadow .5s var(--pop);min-height:46px}\n.btn:active{transform:translate(3px,3px) scale(.96);box-shadow:1px 1px 0 var(--sh)}.btn.o{background:none;color:var(--c,var(--tl))}.row{display:flex;flex-wrap:wrap;gap:12px;margin-top:14px}\n.toast{background:var(--pn);border:3px solid var(--yl);color:var(--yl);padding:12px 14px;margin-bottom:16px;animation:rise 1s var(--spring)}\n.login{min-height:100dvh;display:grid;place-items:center;padding:20px}.login form{width:min(380px,100%);background:var(--pn);border:3px solid var(--tl);padding:24px;display:grid;gap:18px;box-shadow:8px 8px 0 var(--sh);animation:rise 1.2s var(--spring)}\np.hint{color:var(--mt);margin:8px 0}\n@media(prefers-reduced-motion:reduce){*{animation:none!important;transition-duration:.01s!important}}\n.chip{font:9px 'Press Start 2P',monospace;padding:7px 9px;border:3px solid var(--pk);color:var(--pk);margin:4px 6px 0 0;display:inline-block;animation:rise .8s var(--spring)}\n.chip.ok{border-color:var(--tl);color:var(--tl)}.chip.best{background:var(--tl);color:var(--on)}.res{min-height:0}.up{align-items:center;margin-top:8px}\n\n:root[data-theme=light]{--bg:#f2f9f4;--pn:#ffffff;--ln:#cfdcd3;--tl:#1b8a4a;--pk:#c0392b;--yl:#a06a00;--pu:#0b7a8a;--tx:#101a14;--mt:#5d6a62;--on:#fff;--sh:#10281a14;--cbg:#0000000a;--gr:transparent}\n/* theme colors are registered props: they tween on :root, so every element follows in sync */\n@property --on{syntax:'<color>';inherits:true;initial-value:#04140a}\n@property --sh{syntax:'<color>';inherits:true;initial-value:#0006}\n@property --cbg{syntax:'<color>';inherits:true;initial-value:#0a0e0d}\n@property --gr{syntax:'<color>';inherits:true;initial-value:transparent}\n@property --bg{syntax:'<color>';inherits:true;initial-value:#080b0a}\n@property --pn{syntax:'<color>';inherits:true;initial-value:#101614}\n@property --ln{syntax:'<color>';inherits:true;initial-value:#26302c}\n@property --tl{syntax:'<color>';inherits:true;initial-value:#52e39a}\n@property --pk{syntax:'<color>';inherits:true;initial-value:#f27a86}\n@property --yl{syntax:'<color>';inherits:true;initial-value:#e8b84a}\n@property --pu{syntax:'<color>';inherits:true;initial-value:#7fe3ee}\n@property --tx{syntax:'<color>';inherits:true;initial-value:#e8efea}\n@property --mt{syntax:'<color>';inherits:true;initial-value:#8a968f}\n:root{transition:--on .7s ease,--sh .7s ease,--cbg .7s ease,--gr .7s ease,--bg .7s ease,--pn .7s ease,--ln .7s ease,--tl .7s ease,--pk .7s ease,--yl .7s ease,--pu .7s ease,--tx .7s ease,--mt .7s ease}\nhtml{touch-action:manipulation;-webkit-text-size-adjust:100%}\nbody{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent}\ninput,textarea,select{-webkit-user-select:text;user-select:text}\n.glass{position:fixed;top:calc(12px + env(safe-area-inset-top));right:14px;z-index:40;width:48px;height:48px;border-radius:50%;display:grid;place-items:center;cursor:pointer;color:var(--tx);\n border:1px solid rgba(255,255,255,.3);background:linear-gradient(145deg,rgba(255,255,255,.24),rgba(255,255,255,.05));-webkit-backdrop-filter:blur(14px) saturate(1.7);backdrop-filter:blur(14px) saturate(1.7);\n box-shadow:inset 0 1px 1px rgba(255,255,255,.55),inset 0 -8px 12px rgba(255,255,255,.05),0 8px 22px rgba(0,0,0,.35)}\n:root[data-theme=light] .glass{border-color:rgba(0,0,0,.08);background:linear-gradient(145deg,rgba(255,255,255,.8),rgba(255,255,255,.35));box-shadow:inset 0 1px 1px #fff,0 8px 22px rgba(40,40,80,.18)}\n.glass svg{overflow:visible}.glass g,.glass .moon{transform-box:fill-box;transform-origin:center;transition:transform .8s var(--spring),opacity .6s var(--spring)}\n:root[data-theme=dark] .sun,:root:not([data-theme=light]) .sun{opacity:0;transform:rotate(-90deg) scale(.4)}:root[data-theme=light] .moon{opacity:0;transform:rotate(90deg) scale(.4)}\n.ring{position:fixed;z-index:99;pointer-events:none;width:44px;height:44px;border:3px solid #ffa63d;border-radius:50%;box-shadow:0 0 18px #ffa63d88}\n.star{position:fixed;z-index:99;pointer-events:none;display:block}.star svg{width:100%;height:100%;fill:currentColor;filter:drop-shadow(0 0 4px #ffb02e99)}\nbody:not(.app) main{padding-top:calc(76px + env(safe-area-inset-top))}\n\n/* nested panels inside an accordion (Edit, Proxies...) */\n.pn{display:grid;grid-template-rows:0fr;transition:grid-template-rows .7s var(--spring)}.pn.open{grid-template-rows:1fr}\n.pn>div{overflow:hidden;min-height:0}.pn .in{margin-top:14px;padding:2px 0 4px 14px;border-left:3px solid var(--ln)}\n.row>form{display:contents}\n.btn.o.on{background:var(--c,var(--tl));color:var(--on)}\n.cnt{opacity:.7;margin-left:6px}\n.stack{display:flex;flex-direction:column}\nhtml.theming :not(.glass):not(.glass *){transition:none!important}\n\n/* country flags + group picker */\n.flag{width:30px;height:22px;object-fit:cover;border:2px solid var(--ln);display:inline-block;vertical-align:middle;flex:none;background:var(--bg);box-shadow:2px 2px 0 var(--sh)}\n.flag.none{display:inline-grid;place-items:center;font:9px 'Press Start 2P',monospace;color:var(--mt)}\n.chip .flag{width:22px;height:16px;margin:-3px 4px -3px 0}\n.gn{display:flex;align-items:center;gap:12px;min-width:0}\n.opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;margin-top:10px}\n.opt{display:flex;align-items:center;gap:10px;font:21px 'VT323',monospace;color:var(--tx);background:var(--bg);border:3px solid var(--ln);padding:10px 12px;cursor:pointer;text-align:left;min-height:46px;box-shadow:3px 3px 0 var(--sh);transition:transform .5s var(--pop),border-color .4s,color .4s}\n.opt small{color:var(--mt);margin-left:auto;font-size:18px}.opt:active{transform:scale(.96)}.opt.on{border-color:var(--tl);color:var(--tl)}\n.opt small{white-space:nowrap}.opt span:not(.flag){min-width:0;overflow-wrap:anywhere}.hint+.box{margin-top:14px}\n\n/* on/off switch (Advanced, Clients): knob is exactly centred, travels edge to edge with equal 3px gaps */\nlabel.sw{display:flex;align-items:center;gap:14px;cursor:pointer;color:var(--tx);font-size:10px;margin-top:12px;width:fit-content;-webkit-tap-highlight-color:transparent}\n.sw input{position:absolute;opacity:0;width:0;height:0;min-height:0;padding:0;border:0}\n.sw i{display:block;flex:none;box-sizing:border-box;width:54px;height:30px;border:1px solid var(--ln);border-radius:999px;background:var(--bg);position:relative;transition:border-color .4s,background .4s}\n.sw i::after{content:'';position:absolute;box-sizing:border-box;top:50%;left:3px;width:22px;height:22px;margin-top:-11px;border-radius:50%;background:var(--mt);transform:translateX(0);transition:transform .45s var(--spring),background .4s}\n.sw input:checked+i{border-color:var(--tl)}.sw input:checked+i::after{transform:translateX(24px);background:var(--tl)}\n.sw input:focus-visible+i{border-color:var(--yl)}\n\n/* relays + config-domain picker */\n[hidden]{display:none!important}\n.chip.run{border-color:var(--yl);color:var(--yl)}.chip.wait{border-color:var(--ln);color:var(--mt)}\np.hint a{color:var(--tl)}p.err{color:var(--pk)}\n.dp{grid-column:1/-1}.dp>.btn{max-width:100%;overflow-wrap:anywhere;text-align:left}\n[data-steps]{margin:6px 0}.btn[disabled]{opacity:.5;pointer-events:none}\n\n/* xr PANEL look: calm, rounded, letter-spaced mono headings, sans body */\nbody{font:16px/1.4 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background-image:none}\nh1,h3,label,.brand,.side a,.btn,.tag,.chip,.opt small{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;text-transform:uppercase;letter-spacing:.14em}\n.brand{color:var(--tl);font-size:15px;letter-spacing:.3em;text-align:center}.side .brand{text-align:left}\nh1{font-size:13px;color:var(--tl);letter-spacing:.25em}h3{font-size:11px}label{font-size:11px}\n.btn{font-size:11px;border-radius:14px;box-shadow:none;border-width:2px;padding:13px 18px;font-weight:600}.btn.o.on{color:var(--on)}\n.box,.acc,.toast,.login form,.side,.top{border-width:1px;border-radius:18px;box-shadow:none}\n.side{border-radius:0;border-right:1px solid var(--ln)}.top{border-radius:0;border-width:0 0 1px}\n.side a{font-size:11px;border-width:0;border-radius:14px;padding:14px}.side a.on{background:color-mix(in srgb,var(--pu) 22%,transparent);color:var(--pu);box-shadow:none}\n.top button{border-width:1px;border-radius:12px;border-color:var(--tl)}\ninput,select{font:16px system-ui,sans-serif;border-width:1px;border-radius:12px}\n.hd{font-size:17px;font-weight:600}.tag,.chip{font-size:10px;border-width:1px;border-radius:999px;padding:6px 10px}\ncode{font:14px ui-monospace,Menlo,monospace;border-width:1px;border-radius:12px;color:var(--tl)}\n.opt{font:15px system-ui,sans-serif;border-width:1px;border-radius:14px;box-shadow:none}.opt small{font-size:11px}\n.bar{border-width:1px;border-radius:999px;height:12px}\n.flag{border-width:1px;border-radius:4px;box-shadow:none}.chip.best{color:var(--on)}.big{font-size:30px}\n.glass{box-shadow:0 6px 18px #0005}\n\n/* ---------- network tools ---------- */\n.tabs{display:flex;gap:6px;margin:6px 0 14px;flex-wrap:wrap}\n.tabs button{font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;padding:11px 16px;border:1px solid var(--ln);border-radius:12px;background:transparent;color:var(--mt);cursor:pointer}\n.tabs button.on{color:var(--pu);border-color:var(--pu);background:color-mix(in srgb,var(--pu) 14%,transparent)}\n.grp{margin:12px 0}.grp>h3{margin:0 0 8px}\n.cb{font:600 12px/1 ui-monospace,Menlo,monospace;padding:9px 12px;margin:0 6px 6px 0;border:1px solid var(--ln);border-radius:10px;background:transparent;color:var(--mt);cursor:pointer;min-width:48px}\n.cb.sel{color:var(--on);background:var(--tl);border-color:var(--tl)}\ntextarea{width:100%;font:13px/1.45 ui-monospace,Menlo,monospace;background:var(--bg);color:var(--tx);border:1px solid var(--ln);border-radius:12px;padding:12px;resize:vertical;user-select:text;-webkit-user-select:text}\ntextarea.code{color:var(--tl);min-height:200px}label.wide{display:block;margin:10px 0}label.wide textarea,label.wide input{margin-top:6px}\nlabel.ck{display:flex;align-items:center;gap:10px;margin:12px 0;font:12px system-ui,sans-serif;letter-spacing:0;text-transform:none;color:var(--mt);cursor:pointer}label.ck input{width:18px;height:18px;min-height:0;accent-color:var(--tl)}\nselect{font:15px system-ui,sans-serif;background:var(--bg);color:var(--tx);border:1px solid var(--ln);border-radius:12px;padding:12px;min-height:46px;max-width:100%}\nh3.sub{margin:18px 0 8px}\n.st{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 4px;min-height:0}\n/* progress: pixel segments */\n.seg{position:relative;height:26px;margin:14px 0 10px;border:1px solid var(--ln);border-radius:8px;overflow:hidden;background:repeating-linear-gradient(90deg,transparent 0 9px,var(--bg) 9px 11px),var(--pn)}\n.seg i{position:absolute;inset:0 auto 0 0;width:calc(var(--v)*1%);background:repeating-linear-gradient(90deg,var(--tl) 0 9px,transparent 9px 11px);transition:width .25s linear;opacity:.9}\n.seg span{position:absolute;inset:0;display:flex;align-items:center;padding:0 10px;font:600 11px ui-monospace,Menlo,monospace;color:var(--tx);text-shadow:0 0 4px var(--bg),0 0 4px var(--bg);letter-spacing:.04em;white-space:nowrap;overflow:hidden}\n/* log */\n.xlog{height:210px;overflow:auto;background:#050807;border:1px solid var(--ln);border-radius:12px;padding:8px 10px;font:12px/1.55 ui-monospace,'SF Mono',Menlo,monospace;user-select:text;-webkit-user-select:text;overscroll-behavior:contain}\n:root[data-theme=light] .xlog{background:#0f1a14}\n.xlog .l{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#9db3a6}.xlog .l i{font-style:normal;color:#4d6358;margin-right:8px}\n.xlog .ok{color:#52e39a}.xlog .bad{color:#f27a86}.xlog .w{color:#e8b84a}.xlog .i{color:#7fe3ee}.xlog .d{color:#587064}\n.xlog b{font-weight:600;color:#e8efea}.xlog u{text-decoration:none;color:#7fe3ee;margin:0 4px}.xlog s{text-decoration:none;color:#e8b84a}\n/* result rows */\n.xr{display:grid;gap:4px}.xr>div{display:grid;grid-template-columns:auto 1fr auto auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid var(--ln);border-radius:10px;font:13px ui-monospace,Menlo,monospace;background:var(--pn)}\n.xr>div:not(:has(u)){grid-template-columns:1fr auto auto}.xr u{text-decoration:none;color:var(--mt);font-size:11px;min-width:18px}\n.xr span{overflow-wrap:anywhere;user-select:text;-webkit-user-select:text}.xr em{font-style:normal;color:var(--yl);font-weight:600}\n.xr small{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--mt)}.xr small.v-cf{color:var(--tl)}\n.xr>div.use{border-color:var(--tl);box-shadow:inset 3px 0 0 var(--tl)}\n.xr .x{border:0;background:transparent;color:var(--pk);font:700 18px/1 system-ui;padding:0 4px;cursor:pointer}\n.sv-h{display:flex;justify-content:space-between;align-items:center;gap:10px;margin:18px 0 8px}.sv-h b{font:600 11px ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--mt)}.sv-h .btn{padding:8px 12px;margin-left:6px}\n/* register button: red until registered, then green */\n.btn.reg{background:var(--pk);border-color:var(--pk);color:#fff}.btn.reg.ok{background:var(--tl);border-color:var(--tl);color:var(--on)}\n.regrow{align-items:center;gap:14px}.reg-i{font:600 12px ui-monospace,monospace;letter-spacing:.06em}.reg-i.ok{color:var(--tl)}.reg-i.no{color:var(--pk)}\n.btn[disabled]{opacity:.45;pointer-events:none}\n.cfgs{display:grid;gap:6px}.cfg{display:grid;grid-template-columns:1fr auto;gap:8px 12px;align-items:center;padding:10px 12px;border:1px solid var(--ln);border-radius:12px;background:var(--pn)}\n.cfg b{display:block;font:600 14px system-ui,sans-serif;text-transform:none;letter-spacing:0;overflow-wrap:anywhere}.cfg small{display:block;font:11px ui-monospace,monospace;color:var(--mt);margin-top:2px;overflow-wrap:anywhere}\n.cfg .btn{padding:8px 12px;margin-left:6px}.qr{grid-column:1/-1;display:flex;justify-content:center;padding:6px}.qr svg{max-width:100%;height:auto;border-radius:10px;background:#fff}\n\n/* lightning bolt */\n.bolt{width:1.15em;height:1.15em;fill:var(--tl);vertical-align:-.2em;margin-right:.4em;flex:none;filter:drop-shadow(0 0 6px color-mix(in srgb,var(--tl) 55%,transparent))}\n.side .brand{display:flex;align-items:center;gap:2px;text-align:left}.side .brand .bolt{width:1.6em;height:1.6em;margin-right:.5em}.side .brand span{line-height:1.25}\n.top .brand{display:flex;align-items:center;justify-content:center}.login .brand{display:flex;justify-content:center;align-items:center}\n.btn .bolt{fill:currentColor;filter:none;margin:0 .5em 0 0;width:1.2em;height:1.2em;vertical-align:-.25em}\n\n/* Locations: running job button + test-site list */\n.btn.live{background:var(--pk);border-color:var(--pk);color:#fff;animation:livepulse 1.4s ease-in-out infinite}\n@keyframes livepulse{50%{opacity:.7}}\n.sites{display:grid;gap:8px;margin:10px 0}.site{margin:0;flex-wrap:nowrap;align-items:center}.site input{flex:1;min-width:0}.site .btn{padding:10px 16px;min-height:46px}\n"],"wg.js":["text/javascript; charset=utf-8","/* WireGuard / AmneziaWG / Wiresock helpers (window.WG) + the WireGuard and MASQUE panels of the Network page. */\n(() => {\n'use strict';\nconst E = t => String(t).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\nconst ri = (a, b) => a + Math.floor(Math.random() * (b - a + 1));\nconst hex = s => [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join('');\nconst AWG = ['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4'], IK = ['i1', 'i2', 'i3', 'i4', 'i5'];\n\n/* AmneziaWG 1.5 \"signature\" packets. They imitate a protocol's first datagram so DPI sees something familiar.\n   Syntax: <b 0x..> fixed bytes, <r N> N random bytes. Built here from parts (no captured blobs). */\nconst dns = d => '<r 2><b 0x' + '01000001000000000000' + d.split('.').map(l => l.length.toString(16).padStart(2, '0') + hex(l)).join('') + '0000010001>';\nconst sip = '<b 0x' + hex('INVITE sip:bob@biloxi.com SIP/2.0\\r\\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\\r\\nMax-Forwards: 70\\r\\nTo: Bob <sip:bob@biloxi.com>\\r\\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\\r\\nCall-ID: a84b4c76e66710@pc33.atlanta.com\\r\\nCSeq: 314159 INVITE\\r\\nContent-Length: 0\\r\\n\\r\\n') + '>';\nconst quic = n => `<b 0xc00000000108><r 8><b 0x0000${(0x4000 | n).toString(16).padStart(4, '0')}><r ${n}>`;\nconst I_PRESETS = {\n  1: { i1: dns('www.apple.com'), i2: dns('www.apple.com').replace('0000010001>', '00001c0001>'), i3: '', i4: '', i5: '' },\n  2: { i1: sip, i2: '', i3: '', i4: '', i5: '' },\n  3: { i1: quic(1180), i2: '', i3: '', i4: '', i5: '' },\n  4: { i1: quic(1180), i2: '<r 64>', i3: '', i4: '', i5: '' },\n};\nconst JUNK = { light: { jc: 3, jmin: 1, jmax: 3 }, heavy: { jc: 5, jmin: 10, jmax: 40 } };\nconst randJunk = () => { const jmin = ri(1, 1279); return { jc: ri(1, 128), jmin, jmax: ri(jmin + 1, 1280) }; };\nconst fixJunk = j => { j = { ...j }; j.jc = Math.max(1, +j.jc || 3); j.jmin = Math.max(1, +j.jmin || 1); j.jmax = +j.jmax || j.jmin + 1; if (j.jmax <= j.jmin) j.jmax = j.jmin + 1; return j; };\nconst awgBase = j => ({ ...fixJunk(j), s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 });\n\n/* .conf parser: keeps unknown keys, supports several [Peer] blocks */\nfunction parseConf(text) {\n  const c = { iface: {}, peers: [] }; let cur = null;\n  for (let line of text.split(/\\r?\\n/)) {\n    line = line.replace(/^\\s*[#;].*$/, '').trim(); if (!line) continue;\n    const m = line.match(/^\\[(\\w+)\\]$/); if (m) { cur = m[1].toLowerCase() === 'peer' ? (c.peers.push({}), c.peers[c.peers.length - 1]) : c.iface; continue; }\n    const i = line.indexOf('='); if (i < 0 || !cur) continue; cur[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();\n  }\n  return c;\n}\nconst splitEp = ep => { const i = ep.lastIndexOf(':'); return { host: ep.slice(0, i).replace(/^\\[|\\]$/g, ''), port: +ep.slice(i + 1) || 0 }; };\nconst listOf = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);\nconst addrs = a => { const l = listOf(a); return { v4: l.find(x => !x.includes(':')) || '', v6: l.find(x => x.includes(':')) || '' }; };\n\n/* model: { name, private, public, psk, address, dns, mtu, allowed, endpoint, keepalive, reserved:[..], awg:{..}, ws:{id,ip,ib} } */\nfunction toConf(m, kind) {\n  const L = ['# ' + (m.name || 'xr PANEL'), '[Interface]', 'PrivateKey = ' + m.private, 'Address = ' + m.address];\n  if (m.dns) L.push('DNS = ' + m.dns); L.push('MTU = ' + (m.mtu || 1280));\n  if (kind === 'awg' || kind === 'wiresock') {\n    const a = m.awg || awgBase(JUNK.light); for (const k of AWG) L.push(k[0].toUpperCase() + k.slice(1) + ' = ' + a[k]);\n    if (kind === 'awg') { for (const k of IK) if (a[k]) L.push(k.toUpperCase() + ' = ' + a[k]); for (const [k, v] of Object.entries(a.x || {})) L.push(k + ' = ' + v); }\n    else { const w = m.ws || {}; if (w.id) L.push('Id = ' + w.id); if (w.ip) L.push('Ip = ' + w.ip); if (w.ib) L.push('Ib = ' + w.ib); }\n  }\n  L.push('', '[Peer]', 'PublicKey = ' + m.public); if (m.psk) L.push('PresharedKey = ' + m.psk);\n  L.push('AllowedIPs = ' + (m.allowed || '0.0.0.0/0, ::/0')); if (m.keepalive) L.push('PersistentKeepalive = ' + m.keepalive);\n  L.push('Endpoint = ' + m.endpoint); return L.join('\\n');\n}\nconst yq = s => /^[\\w.\\-\\/:+]+$/.test(s) ? s : JSON.stringify(s);\nfunction toClash(m) {\n  const e = splitEp(m.endpoint), a = addrs(m.address), L = ['- name: ' + yq(m.name || 'WARP'), '  type: wireguard', '  server: ' + yq(e.host), '  port: ' + e.port];\n  if (a.v4) L.push('  ip: ' + a.v4.replace(/\\/\\d+$/, '')); if (a.v6) L.push('  ipv6: ' + a.v6.replace(/\\/\\d+$/, ''));\n  L.push('  private-key: ' + yq(m.private), '  public-key: ' + yq(m.public)); if (m.psk) L.push('  pre-shared-key: ' + yq(m.psk));\n  L.push('  allowed-ips: [' + listOf(m.allowed || '0.0.0.0/0, ::/0').map(yq).join(', ') + ']'); if (m.reserved && m.reserved.length) L.push('  reserved: [' + m.reserved.join(', ') + ']');\n  L.push('  udp: true', '  mtu: ' + (m.mtu || 1280), '  remote-dns-resolve: true', '  dns: [' + listOf(m.dns || '1.1.1.1').map(yq).join(', ') + ']'); if (m.keepalive) L.push('  persistent-keepalive: ' + m.keepalive);\n  if (m.awg) { L.push('  amnezia-wg-option:'); for (const k of [...AWG, ...IK]) if (m.awg[k] !== undefined && m.awg[k] !== '') L.push(`    ${k}: ${typeof m.awg[k] === 'number' ? m.awg[k] : JSON.stringify(m.awg[k])}`); }\n  return L.join('\\n');\n}\nfunction toXray(m) {\n  const a = addrs(m.address), ad = [a.v4 && (a.v4.includes('/') ? a.v4 : a.v4 + '/32'), a.v6 && (a.v6.includes('/') ? a.v6 : a.v6 + '/128')].filter(Boolean);\n  const s = { secretKey: m.private, address: ad, peers: [{ publicKey: m.public, ...(m.psk ? { preSharedKey: m.psk } : {}), allowedIPs: listOf(m.allowed || '0.0.0.0/0, ::/0'), endpoint: m.endpoint, keepAlive: +m.keepalive || 25 }], mtu: +m.mtu || 1280 };\n  if (m.reserved && m.reserved.length) s.reserved = m.reserved; return JSON.stringify({ protocol: 'wireguard', tag: 'warp', settings: s }, null, 2);\n}\nconst download = (name, text) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); };\nwindow.WG = { AWG, IK, I_PRESETS, JUNK, randJunk, fixJunk, awgBase, parseConf, splitEp, listOf, addrs, toConf, toClash, toXray, download, hex };\n\n/* ---------- Network page: WireGuard (WARP) ---------- */\nconst jget = async u => { try { return await (await fetch(u)).json(); } catch (e) { return {}; } };\nconst jpost = async u => { try { const r = await fetch(u, { method: 'POST' }); return await r.json(); } catch (e) { return { ok: false, error: 'Network error' }; } };\n\nfunction regButton(btn, info, url, getUrl, onOk, label) {\n  let data = null;\n  const paint = () => { btn.classList.toggle('ok', !!data); info.textContent = data ? 'registered · ' + (data.v4 || data.ipv4 || '') : 'not registered'; info.className = 'reg-i ' + (data ? 'ok' : 'no'); window.dispatchEvent(new CustomEvent('xr:reg', { detail: { kind: label === 'MASQUE' ? 'masque' : 'warp', ok: !!data } })); };\n  (async () => { const d = await jget(getUrl); data = d && d.private_key ? d : null; paint(); onOk(data); })();\n  btn.onclick = async () => {\n    if (data && !confirm('Register a new ' + label + ' device? The current keys will be replaced.')) return;\n    btn.disabled = true; const l = btn.textContent; btn.textContent = 'Registering…'; const r = await jpost(url); btn.disabled = false; btn.textContent = l;\n    if (r.ok) { data = r; paint(); onOk(data); } else { info.textContent = r.error || 'failed'; info.className = 'reg-i no'; }\n  };\n}\n\nfunction mountWG(root) {\n  root.innerHTML = `<p class=\"hint\">The panel registers a Cloudflare WARP device for you (this cannot be done from a browser). Then build WireGuard / AmneziaWG / Wiresock configs, or Xray and Clash outbounds, with the endpoint you want.</p>\n  <div class=\"row regrow\"><button type=\"button\" class=\"btn reg\" data-reg>Warp register</button><span class=\"reg-i no\" data-info>checking…</span></div>\n  <div class=\"f\"><label>Endpoint<input data-f=\"ep\" value=\"engage.cloudflareclient.com:2408\" spellcheck=\"false\" autocapitalize=\"off\"></label>\n  <label>Saved endpoints<select data-f=\"pick\"><option value=\"\">pick…</option></select></label>\n  <label>MTU<input data-f=\"mtu\" value=\"1280\" inputmode=\"numeric\"></label><label>DNS<input data-f=\"dns\" value=\"1.1.1.1\" spellcheck=\"false\"></label>\n  <label>Allowed IPs<input data-f=\"allowed\" value=\"0.0.0.0/0, ::/0\" spellcheck=\"false\"></label><label>Keepalive<input data-f=\"ka\" placeholder=\"off\" inputmode=\"numeric\"></label></div>\n  <div class=\"row\" style=\"margin-top:0\"><button type=\"button\" class=\"btn o tl\" data-fast>${XRNET.BOLT}Use fastest endpoint</button><span class=\"hint\" data-fastmsg></span></div>\n  <div class=\"grp\"><h3>Type</h3><div class=\"tabs\" data-kind><button type=\"button\" class=\"on\" data-k=\"wg\">WireGuard</button><button type=\"button\" data-k=\"awg\">AmneziaWG</button><button type=\"button\" data-k=\"wiresock\">Wiresock</button></div></div>\n  <div data-awg hidden>\n    <div class=\"grp\"><h3>Junk packets</h3><div class=\"tabs\" data-junk><button type=\"button\" class=\"on\" data-j=\"light\">Light</button><button type=\"button\" data-j=\"heavy\">Heavy</button><button type=\"button\" data-j=\"custom\">Custom</button></div></div>\n    <div class=\"f\" data-cj hidden><label>Jc<input data-f=\"jc\" value=\"3\" inputmode=\"numeric\"></label><label>Jmin<input data-f=\"jmin\" value=\"1\" inputmode=\"numeric\"></label><label>Jmax<input data-f=\"jmax\" value=\"3\" inputmode=\"numeric\"></label></div>\n    <div class=\"row\" style=\"margin-top:0\"><button type=\"button\" class=\"btn o yl\" data-rnd>Random junk</button></div>\n    <div data-pa><label class=\"ck\"><input type=\"checkbox\" data-f=\"a15\"> Amnezia 1.5 packets (I1–I5)</label>\n      <div data-a15 hidden><div class=\"row\" style=\"margin-top:0\">${[1, 2, 3, 4].map(n => `<button type=\"button\" class=\"btn o tl\" data-set=\"${n}\">Set ${n}</button>`).join('')}</div>\n      <div class=\"grp\">${[1, 2, 3, 4, 5].map(n => `<label class=\"wide\">I${n}<input data-f=\"i${n}\" spellcheck=\"false\" autocapitalize=\"off\"></label>`).join('')}</div></div>\n      <label class=\"ck\"><input type=\"checkbox\" data-f=\"a3\"> Amnezia 3.0 timing (experimental)</label>\n      <div class=\"f\" data-a3 hidden>${[['ContentPaddingAddition', '27-97'], ['MaxHandshakeAttempts', '18-26'], ['KeepaliveTimeout', '9-16'], ['RejectAfterTime', '171-196'], ['RekeyAfterTime', '116-131'], ['RekeyTimeout', '6-9']].map(([k, v]) => `<label>${k}<input data-x=\"${k}\" value=\"${v}\"></label>`).join('')}</div>\n      <label class=\"ck\"><input type=\"checkbox\" data-f=\"a31\"> Amnezia 3.1 (random trailers, no cookies)</label></div>\n    <div data-pw hidden><div class=\"f\"><label>Id<input data-f=\"wid\" placeholder=\"optional\"></label><label>Ip (mimic)<input data-f=\"wip\" value=\"QUIC\"></label><label>Ib (browser)<input data-f=\"wib\" value=\"Chrome\"></label></div></div>\n  </div>\n  <div class=\"row\"><button type=\"button\" class=\"btn\" data-gen disabled>Generate</button></div>\n  <div data-out hidden><div class=\"tabs\" data-fmt><button type=\"button\" class=\"on\" data-o=\"conf\">Config</button><button type=\"button\" data-o=\"xray\">Xray</button><button type=\"button\" data-o=\"clash\">Clash</button></div>\n  <textarea class=\"code\" data-text readonly rows=\"12\" spellcheck=\"false\"></textarea>\n  <p class=\"hint\" data-res></p><div class=\"row\"><button type=\"button\" class=\"btn o tl\" data-copy2>Copy</button><button type=\"button\" class=\"btn o yl\" data-dl>Download</button></div></div>`;\n  const q = s => root.querySelector(s), f = n => q(`[data-f=\"${n}\"]`); let warp = null, kind = 'wg', fmt = 'conf', junk = 'light', cur = null;\n  const gen = q('[data-gen]');\n  regButton(q('[data-reg]'), q('[data-info]'), '/api/warp/register', '/api/warp', d => { warp = d; gen.disabled = !d; if (d && !f('ep').dataset.t) f('ep').value = (d.endpoint_host || 'engage.cloudflareclient.com') + ':2408'; }, 'WARP');\n  (async () => { const rows = await jget('/api/net/list?kind=warp'); f('pick').insertAdjacentHTML('beforeend', rows.slice(0, 40).map(r => `<option value=\"${E((r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port)}\">${E((r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port)} · ${r.ms} ms</option>`).join('')); })();\n  f('pick').onchange = e => { if (e.target.value) { f('ep').value = e.target.value; f('ep').dataset.t = 1; } }; f('ep').oninput = () => f('ep').dataset.t = 1;\n  const setEp = d => { f('ep').value = XRNET.fmtEp(d); f('ep').dataset.t = 1; q('[data-fastmsg]').textContent = `${XRNET.fmtEp(d)} · ${Math.round(d.ms)} ms`; if (cur && warp) gen.onclick(); };\n  window.addEventListener('xr:endpoint', e => { if (e.detail.kind === 'warp') setEp(e.detail); });\n  q('[data-fast]').onclick = async () => { const r = await XRNET.useFastest('warp'); if (!r) q('[data-fastmsg]').textContent = 'No saved WARP endpoint — scan first'; };\n  const tabs = (el, attr, fn) => el.onclick = e => { const b = e.target.closest('button'); if (!b) return; el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); fn(b.dataset[attr]); };\n  const view = () => { q('[data-awg]').hidden = kind === 'wg'; q('[data-pa]').hidden = kind !== 'awg'; q('[data-pw]').hidden = kind !== 'wiresock'; if (cur) render(); };\n  tabs(q('[data-kind]'), 'k', k => { kind = k; view(); });\n  tabs(q('[data-junk]'), 'j', j => { junk = j; q('[data-cj]').hidden = j !== 'custom'; });\n  tabs(q('[data-fmt]'), 'o', o => { fmt = o; render(); });\n  f('a15').onchange = () => q('[data-a15]').hidden = !f('a15').checked; f('a3').onchange = () => q('[data-a3]').hidden = !f('a3').checked;\n  root.querySelectorAll('[data-set]').forEach(b => b.onclick = () => { const s = I_PRESETS[b.dataset.set]; IK.forEach(k => f(k).value = s[k] || ''); });\n  q('[data-rnd]').onclick = () => { const j = randJunk(); f('jc').value = j.jc; f('jmin').value = j.jmin; f('jmax').value = j.jmax; q('[data-junk] [data-j=\"custom\"]').click(); };\n  const awgModel = () => {\n    const j = junk === 'custom' ? { jc: f('jc').value, jmin: f('jmin').value, jmax: f('jmax').value } : JUNK[junk], a = awgBase(j);\n    if (kind === 'awg') { if (f('a15').checked) IK.forEach(k => a[k] = f(k).value.trim()); a.x = {}; if (f('a3').checked) root.querySelectorAll('[data-x]').forEach(i => { if (i.value.trim()) a.x[i.dataset.x] = i.value.trim(); }); if (f('a31').checked) { a.x.RandomTrailers = 'on'; a.x.DisableCookies = 'on'; } }\n    return a;\n  };\n  const model = () => ({ name: 'WARP', private: warp.private_key, public: warp.peer_public_key, address: [warp.v4, warp.v6].filter(Boolean).map((a, i) => a.includes('/') ? a : a + (i ? '/128' : '/32')).join(', '),\n    dns: f('dns').value.trim(), mtu: +f('mtu').value || 1280, allowed: f('allowed').value.trim(), endpoint: f('ep').value.trim(), keepalive: +f('ka').value || '', reserved: warp.reserved,\n    awg: kind === 'wg' ? null : awgModel(), ws: { id: f('wid').value.trim(), ip: f('wip').value.trim(), ib: f('wib').value.trim() } });\n  const render = () => {\n    if (!cur) return; const m = cur, t = q('[data-text]'); q('[data-fmt]').hidden = false;\n    t.value = fmt === 'conf' ? toConf(m, kind) : fmt === 'xray' ? toXray(m) : toClash(m);\n    q('[data-res]').textContent = 'Reserved bytes: [' + (m.reserved || []).join(', ') + '] — needed by Xray, Clash and sing-box; the plain .conf does not use them.';\n  };\n  gen.onclick = () => { if (!warp) return; if (!/^(\\[[0-9a-f:]+\\]|[\\w.\\-]+):\\d{1,5}$/i.test(f('ep').value.trim())) { alert('Endpoint must look like host:port or [ipv6]:port'); return; } cur = model(); q('[data-out]').hidden = false; render(); };\n  q('[data-copy2]').onclick = e => XRNET.COPY(q('[data-text]').value, e.target);\n  q('[data-dl]').onclick = () => download(fmt === 'conf' ? (kind === 'wg' ? 'warp.conf' : kind + '.conf') : fmt === 'xray' ? 'warp-outbound.json' : 'warp-clash.yaml', q('[data-text]').value);\n}\n\n/* ---------- Network page: MASQUE ---------- */\nfunction mountMasque(root) {\n  root.innerHTML = `<p class=\"hint\">MASQUE is WARP's newer tunnel (HTTP/3 CONNECT-IP). The panel registers a separate device and enrolls a P-256 key. The output is a <b>usque</b> client config. Xray and Clash have no MASQUE support yet.</p>\n  <div class=\"row regrow\"><button type=\"button\" class=\"btn reg\" data-reg>Masque register</button><span class=\"reg-i no\" data-info>checking…</span></div>\n  <div class=\"f\"><label>Endpoint IP<input data-f=\"ep4\" spellcheck=\"false\"></label><label>Endpoint IPv6<input data-f=\"ep6\" spellcheck=\"false\"></label><label>Saved endpoints<select data-f=\"pick\"><option value=\"\">pick…</option></select></label></div>\n  <div class=\"row\" style=\"margin-top:0\"><button type=\"button\" class=\"btn o tl\" data-fast>${XRNET.BOLT}Use fastest endpoint</button><span class=\"hint\" data-fastmsg></span></div>\n  <p class=\"hint\">Ports used by MASQUE: <b>443, 500, 1701, 4443, 4500, 8443, 8095</b> (UDP).</p>\n  <div class=\"row\"><button type=\"button\" class=\"btn\" data-gen disabled>Generate</button></div>\n  <div data-out hidden><textarea class=\"code\" data-text readonly rows=\"12\" spellcheck=\"false\"></textarea><p class=\"hint\" data-res></p><div class=\"row\"><button type=\"button\" class=\"btn o tl\" data-copy2>Copy</button><button type=\"button\" class=\"btn o yl\" data-dl>Download config.json</button></div></div>`;\n  const q = s => root.querySelector(s), f = n => q(`[data-f=\"${n}\"]`); let d = null, made = false;\n  const gen = q('[data-gen]');\n  const pem = k => k.startsWith('-----') ? k : '-----BEGIN PUBLIC KEY-----\\n' + (k.match(/.{1,64}/g) || []).join('\\n') + '\\n-----END PUBLIC KEY-----\\n';\n  const show = () => { if (!d || !made) { q('[data-out]').hidden = true; return; } q('[data-out]').hidden = false; q('[data-res]').textContent = 'Save as config.json and run it with usque (MASQUE client). Endpoint ports: 443, 500, 1701, 4443, 4500, 8443, 8095.';\n    q('[data-text]').value = JSON.stringify({ private_key: d.private_key, endpoint_v4: f('ep4').value.trim() || d.endpoint_v4, endpoint_v6: f('ep6').value.trim() || d.endpoint_v6, endpoint_pub_key: pem(d.endpoint_pub_key), license: d.license, id: d.id, access_token: d.access_token, ipv4: d.ipv4, ipv6: d.ipv6, sni: 'consumer-masque.cloudflareclient.com' }, null, 2); };\n  regButton(q('[data-reg]'), q('[data-info]'), '/api/masque/register', '/api/masque', x => { d = x; gen.disabled = !x; if (x) { f('ep4').value = f('ep4').value || x.endpoint_v4; f('ep6').value = f('ep6').value || x.endpoint_v6; } else made = false; show(); }, 'MASQUE');\n  gen.onclick = () => { if (!d) return; made = true; show(); };\n  (async () => { const rows = await jget('/api/net/list?kind=masque'); f('pick').insertAdjacentHTML('beforeend', rows.slice(0, 40).map(r => `<option value=\"${E(r.host)}\">${E(r.host)}:${r.port} · ${r.ms} ms</option>`).join('')); })();\n  f('pick').onchange = e => { if (e.target.value) { f(e.target.value.includes(':') ? 'ep6' : 'ep4').value = e.target.value; show(); } }; f('ep4').oninput = f('ep6').oninput = show;\n  const setEp = x => { f(x.host.includes(':') ? 'ep6' : 'ep4').value = x.host; q('[data-fastmsg]').textContent = `${XRNET.fmtEp(x)} · ${Math.round(x.ms)} ms — use port ${x.port}`; show(); };\n  window.addEventListener('xr:endpoint', e => { if (e.detail.kind === 'masque') setEp(e.detail); });\n  q('[data-fast]').onclick = async () => { const r = await XRNET.useFastest('masque'); if (!r) q('[data-fastmsg]').textContent = 'No saved MASQUE endpoint — scan first'; };\n  q('[data-copy2]').onclick = e => XRNET.COPY(q('[data-text]').value, e.target); q('[data-dl]').onclick = () => download('config.json', q('[data-text]').value);\n}\n\ndocument.addEventListener('DOMContentLoaded', () => { const a = document.querySelector('[data-wg]'), b = document.querySelector('[data-masque]'); if (a) mountWG(a); if (b) mountMasque(b); });\n})();\n"]};

  return { STATIC };
})();

const __mod_html = (() => {
  // --- html.js ---
// Tiny escaping template tag: values are escaped unless wrapped in raw().
class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = s => new Raw(String(s));
const esc = t => String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const val = v => v instanceof Raw ? v.s : Array.isArray(v) ? v.map(val).join('') : (v === null || v === undefined || v === false) ? '' : esc(v);
const html = (strs, ...vals) => new Raw(strs.reduce((o, s, i) => o + s + (i < vals.length ? val(vals[i]) : ''), ''));
const join = (list, f) => new Raw(list.map(f).map(val).join(''));

  return { Raw, raw, esc, html, join };
})();

const __mod_version = (() => {
  // --- version.js ---
// Build identity. Update VERSION/BUILD when you publish a new version of the Pages project.
const VERSION = "1.2.0", BUILD = "44eca47c2919", REPO = "amirh00sain/xrpanel", BRANCH = "main";

  return { VERSION, BUILD, REPO, BRANCH };
})();

const __mod_ui = (() => {
  const { html, raw, join, esc } = __mod_html;
  const { state, left, pct, fmt } = __mod_db;
  const { BUILD } = __mod_version;
  const { ECH, FM, fragProf, fragMask, sitesList, protos, NATIVE } = __mod_links;
  // --- ui.js ---
// Pages. Same markup and classes as the original Flask templates, so s.css / a.js work unchanged.

const BOLT = raw('<svg class="bolt" viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 2.5 5 13.6h5.6l-1 7.9 9.4-12.1h-5.8z"/></svg>');
const NAV = [['home', '/', 'Home'], ['users', '/users', 'Users'], ['locations', '/locations', 'Locations'], ['clients', '/clients', 'Clients'], ['relays', '/relays', 'Relays'], ['network', '/network', 'Network'], ['convert', '/convert', 'Convert'], ['advanced', '/advanced', 'Advanced'], ['settings', '/settings', 'Settings']];
const flash = ms => join(ms, m => html`<div class="toast">${m}</div>`);

function layout(c, title, body, js = []) {
  const chrome = c.chrome;
  return html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover"><title>${title || 'xr PANEL'}</title><link rel="icon" type="image/svg+xml" href="/static/bolt.svg"><meta name="robots" content="noindex"><script>try{document.documentElement.dataset.theme=localStorage.getItem("th")||"dark"}catch(e){document.documentElement.dataset.theme="dark"}</script>
<link rel="stylesheet" href="/static/s.css?v=${BUILD}"></head><body class="${chrome ? 'app' : ''}">
<button id="theme" class="glass" aria-label="Toggle theme"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><g class="sun"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.2M12 19.8V22M4.9 4.9l1.6 1.6M17.5 17.5l1.6 1.6M2 12h2.2M19.8 12H22M4.9 19.1l1.6-1.6M17.5 6.5l1.6-1.6"/></g><path class="moon" d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg></button>
${chrome ? html`<header class="top"><button id="menu" aria-label="Menu"><i></i><i></i><i></i></button><b class="brand">${BOLT}xr PANEL</b></header><div id="scrim"></div>
<nav class="side"><b class="brand">${BOLT}<span>xr<br>PANEL</span></b>${join(NAV, ([e, h, l]) => html`<a href="${h}" class="${c.endpoint === e ? 'on' : ''}">${l}</a>`)}<a class="out" href="/logout">Logout</a></nav>` : ''}
<main>${chrome ? flash(c.flashes) : ''}${body}</main>
<script src="/static/a.js?v=${BUILD}"></script>${join(js, f => html`<script src="/static/${f}?v=${BUILD}"></script>`)}</body></html>`;
}

const flag = (cc, name = '') => cc ? html`<img class="flag" src="/flag/${cc}.svg" alt="${cc.toUpperCase()}" title="${name}" loading="lazy" onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'flag none',textContent:'?'}))">` : html`<span class="flag none" title="${name}">?</span>`;
const hint = (...a) => html`<p class="hint">${html(...a)}</p>`;

const login = c => layout(c, 'xr PANEL', html`<div class="login"><form method="post" action="/login"><b class="brand">${BOLT}xr PANEL</b>${flash(c.flashes)}
<label>Username<input name="user" value="admin" autocomplete="username" required></label>
<label>Password<input name="pw" type="password" autocomplete="current-password" autofocus required></label>
<button class="btn">Sign in</button></form></div>`);

// ---------------- home ----------------
function homeStats(st) { return st; }
const home = (c, st) => layout(c, 'Home', html`<h1>Home</h1><section class="grid">
<div class="box tl"><h3>Users</h3><p class="big"><span data-k="active">${st.active}</span>/<span data-k="users">${st.users}</span></p><small>active / total</small><div class="bar" data-bar="ap" style="--v:${st.ap}"></div></div>
<div class="box pk"><h3>Traffic</h3><p class="big" data-k="traffic">${st.traffic}</p><div class="bar" data-bar="tp" style="--v:${st.tp}"></div></div>
<div class="box yl"><h3>Mode</h3><p class="big" data-k="mode">${st.mode}</p><small>${st.mode === 'Built-in' ? 'VLESS, VMess, Shadowsocks and Trojan run inside the Pages Function' : 'every protocol is relayed to your upstream'}</small></div>
<div class="box pu"><h3>Exits</h3><p class="big"><span data-k="groups">${st.groups}</span><small> groups</small></p><small><span data-k="proxies">${st.proxies}</span> proxies</small></div>
<div class="box tl"><h3>Clean IPs</h3><p class="big" data-k="ips">${st.ips}</p><small>saved by the scanner</small></div>
<div class="box pk"><h3>Relays</h3><p class="big" data-k="relays">${st.relays}</p><small>deployed on other platforms</small></div>
<div class="box tl" id="cfbox"><h3>Requests today</h3><p class="big"><span id="cf-used">…</span></p><small id="cf-left">Cloudflare account · resets 00:00 UTC</small><div class="bar" id="cf-bar" style="--v:0"></div></div>
<div class="box yl"><h3>Fragment</h3><p class="big" data-k="frag">${st.frag}</p></div>
<div class="box pu"><h3>Runtime</h3><p class="big">Pages</p><small>D1 database</small></div></section><script>(function(){var n=function(x){return Number(x).toLocaleString()};fetch('/api/cf').then(function(r){return r.json()}).then(function(d){var u=document.getElementById('cf-used'),l=document.getElementById('cf-left'),b=document.getElementById('cf-bar');if(!d.ok){u.textContent='—';l.textContent='Cloudflare token not configured';return}u.textContent=n(d.used);if(d.limit){l.textContent=n(d.left)+' left of '+n(d.limit)+' · resets 00:00 UTC';b.style.setProperty('--v',Math.min(100,d.used*100/d.limit))}else l.textContent='used today · resets 00:00 UTC'}).catch(function(){})})()</script>`);

// ---------------- users ----------------
function users(c, list, s, grps, q) {
  const gm = Object.fromEntries(grps.map(g => [g.id, g]));
  return layout(c, 'Users', html`<h1>Users <small>${list.length}/${s.max_users}</small></h1>
<div class="acc"><div class="hd"><span>+ New user</span></div><div class="bd"><div>
<form class="f" method="post" action="/users/add">
<label>Name<input name="name" required></label><label>Limit GB (0 = none)<input name="limit" type="number" step="any" min="0" value="0"></label>
<label>Days (0 = none)<input name="days" type="number" min="0" value="30"></label>
<button class="btn">Create</button></form></div></div></div>
${list.length ? join(list, u => {
    const st = state(u), g = gm[u.grp_id], o = q.get('o') === String(u.id), pp = o ? q.get('p') : '', su = c.suburl(u);
    return html`<div class="acc ${o ? 'open' : ''}"><div class="hd"><span class="gn">${u.name}${g ? flag(g.cc, g.name) : ''}</span><em class="tag ${st}">${st}</em></div><div class="bd"><div>
<p class="meta">${fmt(u.used)} / ${u.limit_gb ? u.limit_gb + ' GB' : 'unlimited'} · ${left(u)} · exit: ${g ? g.name : 'direct'}</p>
<div class="bar" style="--v:${pct(u)}"></div><code>${su}</code>
<div class="row">
<button type="button" class="btn o tl ${pp === 'edit' ? 'on' : ''}" data-pn="edit">Edit</button>
<button type="button" class="btn o pu ${pp === 'loc' ? 'on' : ''}" data-pn="loc">Location</button>
<button type="button" class="btn o pu" data-copy="${su}">Copy sub</button>
<button type="button" class="btn o tl" data-copy="${u.tg}">Telegram proxy</button>
<a class="btn o yl" href="/clients?u=${u.uuid}">Apps</a>
<form method="post" action="/users/${u.id}/delete" data-m="Delete ${u.name}?" onsubmit="return confirm(this.dataset.m)"><button class="btn o pk">Delete</button></form>
</div>
<div class="pn ${pp === 'edit' ? 'open' : ''}" data-p="edit"><div><div class="in">
<form class="f" method="post" action="/users/${u.id}/edit" style="margin-top:0">
<label>Name<input name="name" value="${u.name}" required></label><label>Limit GB<input name="limit" type="number" step="any" min="0" value="${u.limit_gb}"></label>
<label>Days from now (empty = keep)<input name="days" type="number" min="0"></label>
<label class="ck"><input type="checkbox" name="enabled" ${u.enabled ? raw('checked') : ''}>Enabled</label><label class="ck"><input type="checkbox" name="reset">Reset usage</label>
<button class="btn">Save</button></form>
<form method="post" action="/users/${u.id}/wpsecret" data-m="Make a new Telegram secret? The old link stops working." onsubmit="return confirm(this.dataset.m)"><button class="btn o yl">New Telegram secret</button></form>
</div></div></div>
<div class="pn ${pp === 'loc' ? 'open' : ''}" data-p="loc"><div><div class="in">
<h3>Exit location</h3>
<p class="hint">Pick the group this user's traffic leaves through. With several IPs in the group the Worker tries the fastest first.</p>
<form class="opts" method="post" action="/users/${u.id}/group">
<button class="opt ${!g ? 'on' : ''}" name="g" value="0"><span class="flag none">·</span>Direct</button>
${join(grps, x => html`<button class="opt ${g && g.id === x.id ? 'on' : ''}" name="g" value="${x.id}">${flag(x.cc, x.name)}<span>${x.name}</span><small>${x.n} IP</small></button>`)}
</form>
${!grps.length ? html`<p class="hint">No groups yet. Add an IP in Locations first.</p>` : ''}
</div></div></div>
</div></div></div>`;
  }) : html`<p class="hint">No users yet. Open “New user” to create the first one.</p>`}`);
}

// ---------------- clients ----------------
function clients(c, items, sel, wn, wl) {
  return layout(c, 'Clients', html`<h1>Clients</h1>
${items.length ? join(items, ({ x, sub, groups }) => html`<div class="acc ${x.uuid === sel ? 'open' : ''}"><div class="hd"><span class="gn">${x.name}</span><em class="tag ${state(x)}">${state(x)}</em></div><div class="bd"><div>
<code>${sub}</code><div class="row" style="margin-top:0"><button class="btn" data-copy="${sub}">Copy sub link</button></div>
<form method="post" action="/clients/${x.id}/white" class="wl"><label class="sw"><input type="checkbox" name="on" value="1" ${x.white ? raw('checked') : ''} onchange="this.form.submit()"><i></i><span>White IP</span></label><small class="hint">${wn} clean IP${wn === 1 ? '' : 's'} ready · limit ${wl}. When on, this client's sub gets one set of configs per clean IP, fastest first.</small></form>
${join(groups, ([g, apps]) => html`<h3 style="margin:20px 0 12px">${g}</h3>
${join(apps, ([n, d, i]) => html`<div class="acc"><div class="hd"><span>${n}</span><em class="tag ${i ? 'active' : ''}">${i ? 'one-tap import' : 'manual'}</em></div><div class="bd"><div>
<div class="row" style="margin-top:0"><a class="btn o yl" href="${d}" target="_blank" rel="noopener">Download</a>
${i ? html`<a class="btn" href="${i}">Import</a>` : html`<button class="btn o tl" data-copy="${sub}">Copy sub link</button>`}</div>
${!i ? html`<p class="hint">No import link for this app. Copy the sub link and paste it in the app manually.</p>` : ''}
</div></div></div>`)}`)}
</div></div></div>`) : html`<p class="hint">Create a user first.</p>`}`);
}

// ---------------- sub (public) ----------------
const sub = (c, u, st, L, su, groups, tg = '') => layout(c, 'VPN', html`<h1>${u.name}</h1>
<section class="grid"><div class="box tl"><h3>Status</h3><p class="big">${st}</p></div>
<div class="box pk"><h3>Traffic</h3><p class="big">${fmt(u.used)}</p><small>of ${u.limit_gb ? u.limit_gb + ' GB' : 'unlimited'}</small><div class="bar" style="--v:${pct(u)}"></div></div>
<div class="box yl"><h3>Expires</h3><p class="big">${left(u)}</p></div></section><br>
<div class="box pu"><h3>Subscription link</h3><code>${su}</code><button class="btn" data-copy="${su}">Copy link</button>
<p class="hint">Add this same link in your app. Apps read the configs from it directly; browsers see this page.</p></div><br>
${tg ? html`<div class="box tl"><h3>Telegram Web Proxy</h3><code>${tg}</code><div class="row"><button class="btn" data-copy="${tg}">Copy link</button><a class="btn o tl" href="${tg}">Open in Telegram</a></div>
<p class="hint">Your own proxy for Telegram, over https on port 443. It is tied to this account: the same volume and expiry apply, and it stops with the account.</p></div><br>` : ''}
${join(groups, ([g, apps]) => html`<h1>${g}</h1><section class="grid">${join(apps, ([n, d, i]) => html`<div class="box pu"><h3>${n}</h3><div class="row"><a class="btn o yl" href="${d}" target="_blank" rel="noopener">Download</a>${i ? html`<a class="btn" href="${i}">Import</a>` : ''}</div></div>`)}</section><br>`)}
<h1>Configs</h1>${L.length ? join(L, ([nm, pr, l]) => html`<div class="acc"><div class="hd"><span>${nm}</span><em class="tag active">${pr}</em></div><div class="bd"><div><code>${l}</code><button class="btn o tl" data-copy="${l}">Copy</button></div></div></div>`) : html`<p class="hint">This account is ${st}, so no configs are available.</p>`}`);

// ---------------- locations ----------------
const locations = (c, grps) => layout(c, 'Locations', html`<h1>Locations</h1>
<p class="hint">Add a proxy IP and port. The Worker verifies it (SOCKS5, SOCKS4, HTTP, HTTPS), finds the country of the IP and files it into that country's group. A user assigned to a group exits through its IPs, fastest first.</p>
<div class="box pu" data-loc><h3>Auto</h3><p class="hint"><b>Auto location</b> downloads free proxy lists, keeps only working proxies and adds up to 10 locations, one per country, preferring countries you do not have and did not get last time. <b>Recovery</b> takes the IP and port of every current country and swaps them for new working ones from the same country. Click a running button again to stop it.</p>
<div class="row"><button type="button" class="btn" data-lgo="auto">Auto location</button><button type="button" class="btn o yl" data-lgo="recover">Recovery</button></div>
<div class="seg" style="--v:0" data-lseg hidden><i></i><span data-lprog>idle</span></div><div class="xlog" data-llog hidden aria-live="polite"></div></div><br>
<div class="box tl"><h3>Add IP</h3><form class="f" method="post" action="/locations/add" data-slow>
<label>Proxy IP<input name="host" placeholder="1.2.3.4" required></label><label>Port<input name="port" type="number" min="1" max="65535" required></label>
<button type="button" class="btn o yl" data-check>Check</button><div class="res" style="grid-column:1/-1"></div><button class="btn">Add</button></form></div><br>
${grps.length ? join(grps, g => html`<div class="acc"><div class="hd"><span class="gn">${flag(g.cc, g.name)}${g.name}</span><em class="tag active">${g.n} IP</em></div><div class="bd"><div>
${join(g.px, x => html`<form class="row up" method="post" action="/proxies/${x.id}/delete"><span class="chip ok">✓ ${x.proto} ${x.ms}ms</span><span>${x.host}:${x.port}</span><button class="btn o pk">Remove</button></form>`)}
<p class="hint">${g.users} user${g.users === 1 ? '' : 's'} use this group.${g.n > 1 ? ' Traffic goes through the fastest IP; if it fails the next one is tried.' : ''}</p>
<form method="post" action="/groups/${g.id}/delete" data-m="Delete group ${g.name} and its IPs?" onsubmit="return confirm(this.dataset.m)"><div class="row"><button class="btn o pk">Delete group</button></div></form>
</div></div></div>`) : html`<p class="hint">No groups yet. Add the first IP above and its country group is created automatically.</p>`}`, ['loc.js']);

// ---------------- network / convert ----------------
const network = (c, s, cnt) => layout(c, 'Network', html`<h1>Network</h1>
<p class="hint">Scanners run in <b>your browser</b>, on your own connection, so the IPs they find are clean for you. Results are saved in the panel and used by clients with the White IP switch.</p>
<div class="acc"><div class="hd"><span>IP Scanner</span><em class="tag ${cnt.ip ? 'active' : ''}">${cnt.ip} saved</em></div><div class="bd"><div data-scan="ip" data-limit="${s.white_limit}"></div></div></div>
<div class="acc"><div class="hd"><span>WireGuard</span><em class="tag ${s.warp ? 'active' : 'expired'}">${s.warp ? 'registered' : 'not registered'}</em></div><div class="bd"><div data-wg></div></div></div>
<div class="acc"><div class="hd"><span>Masque</span><em class="tag ${s.masque ? 'active' : 'expired'}">${s.masque ? 'registered' : 'not registered'}</em></div><div class="bd"><div data-masque></div></div></div>
<div class="acc"><div class="hd"><span>Endpoint Scanner</span><em class="tag ${cnt.warp + cnt.masque ? 'active' : ''}">${cnt.warp + cnt.masque} saved</em></div><div class="bd"><div data-scan="ep"></div></div></div>`, ['net.js', 'wg.js']);

const convert = c => layout(c, 'Convert', html`<h1>Convert</h1>
<p class="hint">Everything here runs in your browser. Nothing you paste is sent anywhere, except a subscription URL, which the Worker fetches for you.</p>
<div class="acc open"><div class="hd"><span>V2Ray Links</span><em class="tag">edit · QR</em></div><div class="bd"><div data-conv="links"></div></div></div>
<div class="acc"><div class="hd"><span>WireGuard</span><em class="tag">clash · amnezia · wiresock</em></div><div class="bd"><div data-conv="wg"></div></div></div>
<div class="acc"><div class="hd"><span>Clash / Sing-box</span><em class="tag">↔ links</em></div><div class="bd"><div data-conv="formats"></div></div></div>`, ['qr.js', 'wg.js', 'convert.js']);

// ---------------- relays ----------------
const STAG = { idle: 'off', deploying: 'deploying', ok: 'on', failed: 'failed' }, SSYM = { ok: '✓', run: '…', fail: '✕', wait: '·' };
const relays = (c, rv, o, panel, ok) => layout(c, 'Relays', html`<h1>Relays</h1>
<p class="hint">A relay is a small proxy deployed on a hosting platform. Anyone who opens the relay domain is forwarded to this Worker${panel ? html` (<b>${panel}</b>)` : ''}. Paste an API token, the Worker deploys it, tracks the result and measures the ping from here.</p>
${!ok ? html`<div class="toast">Set a public panel domain in Settings first (a custom domain or your pages.dev address). Relays need an address to forward to.</div>` : ''}
${join(rv, v => html`<div class="acc ${o === v.id || v.status === 'deploying' ? 'open' : ''}" data-relay="${v.id}" data-st="${v.status}">
<div class="hd"><span>${v.name}</span><em class="tag ${v.status === 'ok' ? 'active' : ''} ${v.status === 'failed' ? 'expired' : ''}" data-tag>${STAG[v.status]}</em></div>
<div class="bd"><div>
<p class="hint">${v.hint}</p>
<form class="f" method="post" action="/relays/${v.id}/deploy" style="margin-top:0">
<label>API token<input name="token" type="password" autocomplete="off" autocapitalize="off" placeholder="${v.has_token ? 'saved · leave empty to reuse' : 'paste token'}" ${v.has_token ? '' : raw('required')}></label>
<button class="btn" data-go ${v.status === 'deploying' ? raw('disabled') : ''}>${v.has_ref ? 'Redeploy' : 'Deploy'}</button></form>
<p class="hint"><a href="${v.token_url}" target="_blank" rel="noopener">Get a token</a> · the token is stored only in this Pages project's D1 database and is never shown again.</p>
<div data-steps ${v.status === 'idle' ? raw('hidden') : ''}>${join(v.steps, s => html`<span class="chip ${s.st}">${SSYM[s.st]} ${s.l}${s.m && (s.st === 'ok' || s.st === 'run') ? ' · ' + s.m : ''}</span>`)}</div>
<p class="hint err" data-err ${!v.err ? raw('hidden') : ''}>${v.err}</p>
<div data-out ${!v.domain ? raw('hidden') : ''}>
<code data-dom>${v.domain}</code>
<div data-ping>${v.ping ? html`${v.ping.ok ? html`<span class="chip ok">panel ⇄ relay · ${v.ping.web} ms</span>` : html`<span class="chip">✕ no answer through the relay</span>`}` : ''}</div>
<div class="row"><button type="button" class="btn o tl" data-copy="${v.domain}">Copy domain</button><button type="button" class="btn o yl" data-rping>Ping</button></div>
</div>
${v.has_ref ? html`<div class="row"><form method="post" action="/relays/${v.id}/remove" data-m="Delete the ${v.name} relay?" onsubmit="return confirm(this.dataset.m)"><button class="btn o pk">Remove</button></form></div>` : ''}
</div></div></div>`)}`);

// ---------------- advanced ----------------
const sw = (k, on) => html`<form method="post" action="/advanced/toggle/${k}"><label class="sw"><input type="checkbox" name="on" ${on ? raw('checked') : ''} onchange="this.form.submit()"><i></i><span>${on ? 'On' : 'Off'}</span></label></form>`;
function advanced(c, s, spoof, o) {
  const ei0 = parseInt(s.ech_i, 10), ei = ei0 >= 0 && ei0 < ECH.length ? ei0 : -1, fp = s.frag_on === '1' ? fragProf(s) : null, fpAny = fragProf(s), nsites = sitesList(s).length;
  const fmprev = fpAny && fpAny.tier !== 'none' ? fragMask(fpAny.tier) : '';
  return layout(c, 'Advanced', html`<h1>Advanced</h1>
<div class="acc ${o === 'spoof' ? 'open' : ''}"><div class="hd"><span>Spoof</span><em class="tag ${spoof ? 'active' : ''}">${spoof ? 'on' : 'off'}</em></div><div class="bd"><div>
<p class="hint">Fill SNI and IP and every VLESS config gets the <b>snispoofing</b> parameter. Port is optional (empty = 0). Leave SNI or IP empty to turn it off.</p>
<form class="f" method="post" action="/advanced/spoof" style="margin-top:0">
<label>SNI<input name="sni" value="${s.spoof_sni}" placeholder="sni here" autocapitalize="off" autocomplete="off"></label>
<label>IP<input name="ip" value="${s.spoof_ip}" placeholder="ip here" autocapitalize="off" autocomplete="off"></label>
<label>Port<input name="port" type="number" min="0" max="65535" value="${s.spoof_port}" placeholder="0"></label>
<button class="btn">Save</button></form></div></div></div>

<div class="acc ${o === 'ff' ? 'open' : ''}"><div class="hd"><span>F+F</span><em class="tag ${s.ff_on === '1' ? 'active' : ''}">${s.ff_on === '1' ? 'on' : 'off'}</em></div><div class="bd"><div>
${sw('ff', s.ff_on === '1')}
<p class="hint">When on, every supported config (VLESS, Trojan, Shadowsocks) gets this finalMask and the fingerprint is set to <b>unsafe</b>:</p>
<code>${FM}</code></div></div></div>

<div class="acc ${o === 'frag' ? 'open' : ''}" data-frag data-on="${s.frag_on}"><div class="hd"><span>Fragment</span><em class="tag ${s.frag_on === '1' && fp && fp.tier !== 'none' ? 'active' : ''}" data-ftag>${s.frag_on === '1' && fp ? fp.tier : (s.frag_on === '1' ? 'on' : 'off')}</em></div><div class="bd"><div>
${sw('frag', s.frag_on === '1')}
<p class="hint">When on, the panel measures <b>your browser's connection</b> automatically (round-trip time and success rate on the test sites from Settings, ${nsites} in rotation) and gives every config that can carry it a fragment tuned to that network: fast, mid or slow.</p>
${s.frag_on === '1' ? html`
<div class="st" data-fst>${fp ? html`<span class="chip ${fp.tier !== 'none' ? 'ok' : ''}">${fp.tier !== 'none' ? fp.tier : 'no fragment'}</span><span class="chip ok">${fp.rtt} ms</span><span class="chip ${fp.ok >= 0.6 ? 'ok' : 'run'}">${Math.round(fp.ok * 100)}% reachable</span>${fp.verified !== null && fp.verified !== undefined ? html`<span class="chip ${fp.verified ? 'ok' : ''}">${fp.verified ? '✓ verified' : '✕ failed check'}</span>` : ''}` : html`<span class="chip run">measuring…</span>`}</div>
<div class="row"><button type="button" class="btn o tl" data-fgo>Measure again</button></div>
<div class="cfgs" data-fres></div>
<p class="hint" data-fmsg>${fp && fp.tier !== 'none' ? 'Fragment applied to the VLESS, Shadowsocks and Trojan configs of this panel (VMess links have no fragment field).' : (fp ? 'The network could not be measured, so no fragment is added.' : '')}</p>
${fmprev ? html`<code data-fcode>${fmprev}</code>` : ''}
<p class="hint">Not touched: VMess (its link has no field for a fragment) and plain non-TLS White IP configs (no handshake to fragment). A protocol whose WebSocket endpoint does not answer in the live check gets no fragment.</p>`
    : html`<p class="hint">Turn it on to start the first measurement. The result is saved and written into the subscription links of all supported configs. It replaces the fixed F+F mask while it is on.</p>`}
</div></div></div>

<div class="acc ${o === 'ech' ? 'open' : ''}"><div class="hd"><span>ECH</span><em class="tag ${s.ech_on === '1' && ei >= 0 ? 'active' : ''}">${s.ech_on === '1' && ei >= 0 ? 'on' : 'off'}</em></div><div class="bd"><div>
${sw('ech', s.ech_on === '1')}
${s.ech_on === '1' ? html`
<div class="row"><button type="button" class="btn o pu ${o === 'ech' && ei < 0 ? 'on' : ''}" data-pn="ech">${ei >= 0 ? 'ECH: ' + ECH[ei][0] : 'Choose ECH'}</button></div>
<div class="pn ${o === 'ech' && ei < 0 ? 'open' : ''}" data-p="ech"><div><div class="in">
<h3>ECH list</h3>
<form class="opts" method="post" action="/advanced/ech">
${join(ECH, ([n, d], i) => html`<button class="opt ${ei === i ? 'on' : ''}" name="e" value="${i}"><span>${n}</span><small>${d}</small></button>`)}
</form></div></div></div>
<p class="hint">${ei >= 0 ? 'The selected ECH is applied to all supported configs (VLESS, Trojan, Shadowsocks).' : 'No ECH selected yet. Pick one and it is applied to all supported configs.'}</p>`
    : html`<p class="hint">Turn it on, then pick an ECH from the list. The choice is applied to all supported configs (VLESS, Trojan, Shadowsocks).</p>`}
</div></div></div>

<div class="acc ${o === 'ipv6' ? 'open' : ''}"><div class="hd"><span>IPv6</span><em class="tag ${s.ipv6 ? 'active' : ''}">${s.ipv6 ? 'on' : 'off'}</em></div><div class="bd"><div>
<p class="hint">Whatever you enter here becomes the address of every config (IPv6 is wrapped in [ ] automatically). SNI and host stay the domain. Leave empty to use the domain.</p>
<form class="f" method="post" action="/advanced/ipv6" style="margin-top:0">
<label>Address<input name="ip" value="${s.ipv6}" placeholder="2606:4700::1111" autocapitalize="off" autocomplete="off"></label>
<button class="btn">Save</button></form></div></div></div>`, ['frag.js']);
}

// ---------------- settings ----------------
function settings(c, s, o) {
  const { sites, defaultPw, detected, relays, panelDom, cfgSrc, cfgLabel, upd } = c.settings;
  const fields = [['domain', 'Domain (empty = auto)'], ['tls_port', 'Port used in every config (Cloudflare serves 443, 8443, 2053, 2083, 2087, 2096)'], ['max_users', 'Max users'], ['white_limit', 'White IP limit'], ['upstream', 'Upstream (optional, empty = everything runs in the Worker)']];
  return layout(c, 'Settings', html`<h1>Settings</h1>
${defaultPw ? html`<div class="toast">Default password “admin” is still active. Change it below.</div>` : ''}
<div class="box pk"><h3>Password</h3><form class="f" method="post" action="/settings/password"><label>Current<input name="old" type="password" required></label>
<label>New<input name="new" type="password" required></label><button class="btn pk">Change</button></form></div><br>
<div class="box tl"><h3>Server</h3><p class="hint">Auto-detected from how you opened this panel: ${detected}</p><form class="f" method="post" action="/settings/save">
${join(fields, ([k, l]) => html`<label>${l}<input name="${k}" value="${s[k]}"${k === 'upstream' ? raw(' placeholder="relay.example.com or relay.example.com:8443"') : ''}></label>
${k === 'domain' && relays.length ? html`<div class="dp"><button type="button" class="btn o pu" data-pn="cfgdom">Configs use: ${cfgLabel} ▾</button>
<div class="pn" data-p="cfgdom"><div><div class="in"><h3>Domain used by configs</h3>
<div class="opts">
<button form="cfgform" name="pick" value="panel" class="opt ${cfgSrc === 'panel' ? 'on' : ''}"><span>${panelDom}</span><small>panel</small></button>
${join(relays, r => html`<button form="cfgform" name="pick" value="relay:${r.id}" class="opt ${cfgSrc === 'relay:' + r.id ? 'on' : ''}"><span>${r.domain}</span><small>${r.name} · ${r.tag}</small></button>`)}
<button type="button" class="opt ${cfgSrc === 'custom' ? 'on' : ''}" data-custom><span>Custom…</span></button></div>
<div class="row" data-cust ${cfgSrc !== 'custom' ? raw('hidden') : ''}><input form="cfgform" name="custom" value="${s.cfg_custom}" placeholder="sub.example.com" autocapitalize="off" autocomplete="off" style="flex:1;min-width:180px"><button form="cfgform" name="pick" value="custom" class="btn">Use</button></div>
<p class="hint">Every generated config (address, host, SNI) uses the domain you pick. Relay domains always use port 443.</p>
</div></div></div></div>` : ''}`)}
<label class="ck"><input type="checkbox" name="white_sni" value="1" ${s.white_sni === '1' ? raw('checked') : ''}> White IPs use scanned SNI</label><button class="btn">Save</button></form><form id="cfgform" method="post" action="/settings/cfgdomain"></form></div><br>
<div class="box pu ${o === 'sites' ? 'open' : ''}"><h3>Test sites</h3><p class="hint">Links the Fragment measurement uses to test your connection. Each measurement takes the next few sites of the list, so every site is used in turn. Add or remove as many as you like.</p>
<form method="post" action="/settings/sites" data-sites><div class="sites" data-list>
${join(sites, u => html`<div class="row site"><input name="site" value="${u}" placeholder="https://example.com/generate_204" autocapitalize="off" autocomplete="off" spellcheck="false"><button type="button" class="btn o pk" data-rm aria-label="Remove">−</button></div>`)}</div>
<div class="row"><button type="button" class="btn o tl" data-add>+ Add site</button><button class="btn">Save</button><button class="btn o yl" name="reset" value="1" formnovalidate>Reset to 9 defaults</button></div></form></div><br>
<div class="box yl"><h3>Relay mode</h3>${!s.upstream || !s.upstream.trim()
    ? html`<p class="hint"><b>Built-in.</b> The Worker itself terminates <b>VLESS</b>, <b>VMess</b>, <b>Shadowsocks</b> and <b>Trojan</b> over WebSocket on the port above and sends traffic out directly or through the user's exit group. Volume and expiry are enforced live, per user.</p>`
    : html`<p class="hint"><b>Upstream relay.</b> Every protocol is relayed unchanged to <b>${s.upstream}</b> using the same <code>/ws/&lt;protocol&gt;/&lt;uuid&gt;</code> path. Quotas and expiry are enforced here; traffic is metered here.</p>`}
<p class="hint">Changes apply immediately: there is no config to write and nothing to restart.</p></div><br>
<div class="box tl ${o === 'update' ? 'open' : ''}"><h3>Update</h3>
<p class="hint">Running <b>v${upd.version}</b> · build <code>${upd.build}</code> · source <code>github.com/${upd.repo}</code> (${upd.branch}). This is a Cloudflare Pages project: push a commit to your Git repository (or redeploy in the Cloudflare dashboard) to update. Users, settings and D1 data are kept.</p></div><br>
<div class="box pk"><h3>Telegram Web Proxy</h3><p class="hint">Every user has a secret of their own, made when the user is created; the link is on the user's subscription page and on the Users page. The proxy needs this Pages Function to reach Telegram's data centers: test it here.</p>
<div class="row"><button type="button" class="btn o pk" data-tgtest>Test Telegram data centers</button></div><div class="res" data-tgout></div></div>`);
}

  return { layout, login, homeStats, home, users, clients, sub, locations, network, convert, relays, advanced, settings, NATIVE };
})();

const __mod_warp = (() => {
  // --- warp.js ---
// Cloudflare WARP registration done by the Worker (browsers cannot call this API: no CORS).
//  - WireGuard device: X25519 key pair (WebCrypto) -> POST /reg
//  - MASQUE device:    ECDSA P-256 key pair (WebCrypto) -> POST /reg, then PATCH /reg/{id} to enroll the key
const API = 'https://api.cloudflareclient.com/v0a4005/reg', UA = 'insomnia/8.6.1';
const MASQUE_PORTS = [443, 500, 1701, 4443, 4500, 8443, 8095];
class WarpError extends Error { }

const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

async function wgKeypair() {
  const k = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey)), pub = new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey));
  return [b64(pkcs8.slice(-32)), b64(pub)];                // the private scalar is the last 32 bytes of the PKCS#8 wrapper
}
const der = (tag, body) => { const n = body.length; return Uint8Array.from([tag, ...(n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]), ...body]); };
const cat = (...a) => Uint8Array.from(a.flatMap(x => [...x]));
const hex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
async function ecKeypair() {
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', k.privateKey), spki = new Uint8Array(await crypto.subtle.exportKey('spki', k.publicKey));
  const pt = cat([4], b64u(jwk.x), b64u(jwk.y)), oidP256 = hex('2a8648ce3d030107');
  const priv = der(0x30, cat(der(2, [1]), der(4, b64u(jwk.d)), der(0xA0, der(6, oidP256)), der(0xA1, der(3, cat([0], pt)))));   // SEC1 ECPrivateKey
  return [b64(priv), b64(spki)];
}

async function call(method, url, body, token, fetchFn = fetch) {
  const h = { 'User-Agent': UA, 'Content-Type': 'application/json' }; if (token) h.Authorization = 'Bearer ' + token;
  let r; try { r = await fetchFn(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }); } catch (e) { throw new WarpError('Could not reach Cloudflare: ' + (e.message || e)); }
  if (!r.ok) throw new WarpError('Cloudflare answered HTTP ' + r.status);
  try { return await r.json(); } catch { return {}; }
}
const register = (pub, f) => call('POST', API, { install_id: '', fcm_token: '', tos: new Date().toISOString(), type: 'Android', model: 'PC', locale: 'en_US', warp_enabled: true, key: pub }, undefined, f);
const hostOf = ep => { ep = (ep || '').trim(); if (ep.startsWith('[')) return ep.slice(1, ep.indexOf(']')); const m = ep.match(/^(.*):\d+$/); return m && ep.split(':').length === 2 ? m[1] : ep; };

async function registerWireguard(f = fetch) {
  const [priv, pub] = await wgKeypair(), j = await register(pub, f);
  try {
    const c = j.config, peer = c.peers[0], a = c.interface.addresses;
    return { private_key: priv, peer_public_key: peer.public_key, v4: a.v4, v6: a.v6, reserved: [...Uint8Array.from(atob(c.client_id), x => x.charCodeAt(0))], endpoint_host: hostOf((peer.endpoint || {}).host) || 'engage.cloudflareclient.com', id: j.id || '', account: (j.account || {}).id || '', license: (j.account || {}).license || '', created: Math.floor(Date.now() / 1000) };
  } catch { throw new WarpError('Cloudflare returned an unexpected answer'); }
}
async function registerMasque(f = fetch) {
  const [, wpub] = await wgKeypair(), j = await register(wpub, f);
  if (!j.id || !j.token) throw new WarpError('Cloudflare returned an unexpected answer');
  const [priv, pub] = await ecKeypair();
  const r = await call('PATCH', `${API}/${j.id}`, { key: pub, key_type: 'secp256r1', tunnel_type: 'masque', name: 'xr-panel' }, j.token, f);
  try {
    const c = r.config, peer = c.peers[0], a = c.interface.addresses, ep = peer.endpoint || {};
    return { private_key: priv, public_key: pub, endpoint_pub_key: peer.public_key, endpoint_v4: hostOf(ep.v4) || '162.159.198.2', endpoint_v6: hostOf(ep.v6) || '2606:4700:103::2', ipv4: a.v4, ipv6: a.v6, id: j.id, access_token: j.token, license: ((r.account || j.account) || {}).license || '', created: Math.floor(Date.now() / 1000) };
  } catch { throw new WarpError('Cloudflare returned an unexpected answer'); }
}

  return { MASQUE_PORTS, WarpError, wgKeypair, ecKeypair, registerWireguard, registerMasque };
})();

const __mod_webproxy = (() => {
  const { DB, state } = __mod_db;
  const { panelDomain } = __mod_links;
  const { Meter } = __mod_relay;
  const randomSecret = __mod_db.newSecret;
  // --- webproxy.js ---
// Telegram "Web Proxy" (the tdesktop web-proxy-bridge-v1 protocol), served from the panel's own domain.
// A browser-side bridge page (served at "/") performs the MTProto obfuscated handshake and opens a
// WebSocket back to this Pages Function; the in-isolate RelaySession relays the decrypted bytes on to a
// real Telegram data-center over TLS. No upstream/relay server and no Durable Object is used — this is a
// native protocol implementation, like VLESS/Trojan already are in relay.js.
//
// Unlike a classic MTProxy (raw TCP, blockable by IP/port), the client reaches this over https/wss on
// 443, so it rides on the same domain + TLS fingerprint as everything else the panel serves.
//
// Every user has a secret of their own (users.wp_secret, made when the user is created). The secret picks the
// user; the bootstrap and session tokens are signed with it and carry the user id, so regenerating the secret
// revokes them. The session meters every byte against that user's volume and expiry (stored in D1) and cuts it.

const te = new TextEncoder(), td = new TextDecoder();

// ---------------- wire framing between the bridge page and the Durable Object ----------------
const FRAME = Object.freeze({ OPEN: 0x01, DATA: 0x02, CLOSE: 0x03, WINDOW: 0x04, PING: 0x05, PONG: 0x06, HELLO: 0x10, WELCOME: 0x11, BYE: 0x1f });
const HEADER_SIZE = 8, MAX_PAYLOAD = 1024 * 1024, MAX_BATCH_FRAMES = 4096, INITIAL_WINDOW = 4 * 1024 * 1024, DATA_CHUNK = 64 * 1024, MAX_WS_MESSAGE = 2 * 1024 * 1024;

function encodeFrame(type, streamId, payload = new Uint8Array()) {
  if (streamId < 0 || streamId > 0xffffff || payload.length > MAX_PAYLOAD) throw new Error('invalid frame');
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = type; out[1] = streamId >>> 16; out[2] = streamId >>> 8; out[3] = streamId;
  new DataView(out.buffer).setUint32(4, payload.length); out.set(payload, HEADER_SIZE); return out;
}
function parseFrames(input) {
  const frames = []; let offset = 0;
  while (offset < input.length) {
    if (frames.length >= MAX_BATCH_FRAMES || input.length - offset < HEADER_SIZE) throw new Error('bad batch');
    const view = new DataView(input.buffer, input.byteOffset + offset, HEADER_SIZE); const length = view.getUint32(4);
    if (length > MAX_PAYLOAD || offset + HEADER_SIZE + length > input.length) throw new Error('bad payload');
    frames.push({ type: input[offset], streamId: (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3], payload: input.subarray(offset + HEADER_SIZE, offset + HEADER_SIZE + length) });
    offset += HEADER_SIZE + length;
  }
  if (!frames.length) throw new Error('empty batch'); return frames;
}
function u32(value) { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value); return out; }
function clampInt(value, min, max, fallback) { const n = Number.parseInt(value, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; }

// ---------------- MTProto obfuscated handshake (AES-256-CTR) ----------------
const TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
const TELEGRAM_DCS = Object.freeze({ 1: '149.154.175.50', 2: '149.154.167.51', 3: '149.154.175.100', 4: '149.154.167.91', 5: '149.154.171.5' });

class AesCtrStream {
  constructor(keyBytes, ivBytes) {
    if (keyBytes.length !== 32 || ivBytes.length !== 16) throw new Error('bad AES material');
    this.keyPromise = crypto.subtle.importKey('raw', keyBytes, 'AES-CTR', false, ['encrypt']);
    this.counter = new Uint8Array(ivBytes); this.spare = new Uint8Array();
  }
  async crypt(input) {
    const src = input instanceof Uint8Array ? input : new Uint8Array(input);
    const out = new Uint8Array(src.length); let pos = 0;
    if (this.spare.length) { const n = Math.min(this.spare.length, src.length); for (let i = 0; i < n; i++) out[i] = src[i] ^ this.spare[i]; this.spare = this.spare.subarray(n); pos = n; }
    if (pos < src.length) {
      const need = src.length - pos, blocks = Math.ceil(need / 16), zeros = new Uint8Array(blocks * 16), key = await this.keyPromise;
      const ks = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: this.counter, length: 128 }, key, zeros));
      addBlocks(this.counter, blocks);
      for (let i = 0; i < need; i++) out[pos + i] = src[pos + i] ^ ks[i];
      if (need < ks.length) this.spare = ks.subarray(need);
    }
    return out;
  }
}
function addBlocks(counter, blocks) { let carry = blocks; for (let i = 15; i >= 0 && carry; i--) { const sum = counter[i] + (carry & 255); counter[i] = sum & 255; carry = Math.floor(carry / 256) + (sum >>> 8); } }
function reverse(bytes) { return Uint8Array.from(bytes).reverse(); }
function concat(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }

function parseProxySecret(value) {
  const s = String(value || '').toLowerCase();
  if (/^[0-9a-f]{32}$/.test(s)) return hex(s);
  if (/^dd[0-9a-f]{32}$/.test(s)) return hex(s.slice(2));
  throw new Error('wp_secret must be 32 hex characters, optionally prefixed with dd');
}
function hex(s) { const x = new Uint8Array(s.length / 2); for (let i = 0; i < x.length; i++) x[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16); return x; }

async function acceptClientHandshake(packet, secret) {
  if (packet.length !== 64) throw new Error('bad handshake length');
  const material = packet.subarray(8, 56), rev = reverse(material);
  const decKey = await sha256(concat(material.subarray(0, 32), secret)); const dec = new AesCtrStream(decKey, material.subarray(32, 48));
  const encKey = await sha256(concat(rev.subarray(0, 32), secret)); const enc = new AesCtrStream(encKey, rev.subarray(32, 48));
  const plain = await dec.crypt(packet);
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const tag = view.getUint32(56, true), dcId = view.getInt16(60, true);
  if (!TAGS.has(tag) || !TELEGRAM_DCS[Math.abs(dcId)]) throw new Error('invalid MTProxy handshake');
  return { tag, dcId, clientDecrypt: dec, clientEncrypt: enc };
}
async function createTelegramHandshake(tag, dcId) {
  let nonce; do { nonce = new Uint8Array(64); crypto.getRandomValues(nonce); } while (reserved(nonce));
  const v = new DataView(nonce.buffer); v.setUint32(56, tag, true); v.setInt16(60, dcId, true); nonce[62] = nonce[63] = 0;
  const material = nonce.subarray(8, 56), rev = reverse(material);
  const encrypt = new AesCtrStream(material.subarray(0, 32), material.subarray(32, 48));
  const decrypt = new AesCtrStream(rev.subarray(0, 32), rev.subarray(32, 48));
  const encrypted = await encrypt.crypt(nonce); const wire = new Uint8Array(nonce); wire.set(encrypted.subarray(56), 56);
  return { wire, encrypt, decrypt };
}
function reserved(n) { const v = new DataView(n.buffer, n.byteOffset, n.byteLength), x = v.getUint32(0, true); return n[0] === 0xef || x === 0x44414548 || x === 0x54534f50 || x === 0x20544547 || x === 0xeeeeeeee || x === 0xdddddddd || v.getUint32(4, true) === 0; }

// ---------------- bootstrap / session-token signing (keyed by the user's own secret, the user id travels in the token) ----------------
async function hmac(keyBytes, data) { const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', key, data)); }
const signingKey = hexSecret => te.encode(`xr-panel/webproxy-signing/v1\n${String(hexSecret || '')}`);
const noSecret = v => !/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/.test(String(v || ''));

async function createBootstrap(hexSecret, uid, ttl = 300) {
  const payload = base64url(te.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + ttl, n: randomToken(16), u: uid })));
  const signature = base64url(await hmac(signingKey(hexSecret), te.encode(payload)));
  return `${payload}.${signature}`;
}
/** The user id a bootstrap token claims (NOT trusted until verifyBootstrap passes with that user's secret). */
function bootstrapUser(token) { try { const d = JSON.parse(td.decode(base64urlDecode(String(token || '').split('.')[0]))); return Number.isInteger(d.u) && d.u > 0 ? d.u : 0; } catch { return 0; } }
async function verifyBootstrap(hexSecret, token) {
  if (noSecret(hexSecret)) return false;
  const [payload, signature, extra] = String(token || '').split('.'); if (!payload || !signature || extra) return false;
  const expected = base64url(await hmac(signingKey(hexSecret), te.encode(payload))); if (!constantTimeEqual(signature, expected)) return false;
  try { const data = JSON.parse(td.decode(base64urlDecode(payload))); return Number.isInteger(data.exp) && data.exp >= Math.floor(Date.now() / 1000); } catch { return false; }
}
// session token = nonce(12) | user id(4) | mac(16)  -> 32 bytes -> 43 base64url characters (the bridge page checks that shape)
async function createSessionToken(hexSecret, host, uid) {
  const body = new Uint8Array(16); body.set(crypto.getRandomValues(new Uint8Array(12))); new DataView(body.buffer).setUint32(12, uid);
  const mac = await sessionMac(hexSecret, host, body); const bytes = new Uint8Array(32); bytes.set(body); bytes.set(mac.subarray(0, 16), 16); return base64url(bytes);
}
/** The user id a session token claims (NOT trusted until verifySessionToken passes with that user's secret). */
function sessionUser(token) { if (!/^[A-Za-z0-9_-]{43}$/.test(token || '')) return 0; try { return new DataView(base64urlDecode(token).buffer).getUint32(12) || 0; } catch { return 0; } }
async function verifySessionToken(hexSecret, host, token) {
  if (noSecret(hexSecret) || !/^[A-Za-z0-9_-]{43}$/.test(token || '')) return false;
  const bytes = base64urlDecode(token); if (base64url(bytes) !== token) return false;
  const mac = await sessionMac(hexSecret, host, bytes.subarray(0, 16)); return constantTimeEqual(base64url(bytes.subarray(16)), base64url(mac.subarray(0, 16)));
}
function sessionMac(hexSecret, host, body) { const context = te.encode('xr-panel/webproxy-session/v2\n' + host + '\n'); const bytes = new Uint8Array(context.length + body.length); bytes.set(context); bytes.set(body, context.length); return hmac(signingKey(hexSecret), bytes); }
async function capabilityMatches(candidate, host, hexSecret) {
  if (!/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/.test(String(hexSecret || ''))) return false;
  const secret = hex(String(hexSecret).toLowerCase().replace(/^dd/, ''));
  const context = te.encode(`tdesktop-web-proxy-bridge-v1\n${host}`);
  const expected = base64url(await hmac(secret, context));
  return constantTimeEqual(candidate, expected);
}
function randomToken(n) { const v = new Uint8Array(n); crypto.getRandomValues(v); return base64url(v); }
function base64url(bytes) { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function base64urlDecode(value) { const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4); return Uint8Array.from(atob(padded), c => c.charCodeAt(0)); }
function constantTimeEqual(a, b) { if (a.length !== b.length) return false; let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0; }

/** Can this Worker open a TCP connection to every Telegram data center? (the one thing the Web Proxy needs from Cloudflare) */
async function testDataCenters(connectFn, ms = 5000) {
  return Promise.all(Object.entries(TELEGRAM_DCS).map(async ([dc, ip]) => {
    const t0 = Date.now(); let sock;
    try {
      sock = connectFn({ hostname: ip, port: 443 }, { allowHalfOpen: false }); Promise.resolve(sock.closed).catch(() => { });
      await new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error('timeout')), ms); Promise.resolve(sock.opened).then(v => { clearTimeout(t); resolve(v); }, e => { clearTimeout(t); reject(e); }); });
      return { dc: +dc, ip, ok: true, ms: Date.now() - t0 };
    } catch (e) { return { dc: +dc, ip, ok: false, error: String((e && e.message) || e).slice(0, 80) }; }
    finally { try { sock && sock.close(); } catch { } }
  }));
}

/** The link a user opens in Telegram: it points the app's web proxy at this panel with that user's own secret. */
function telegramLink(secret, domain) { return `https://t.me/webproxy?server=${encodeURIComponent(domain)}&secret=${encodeURIComponent(String(secret || '').toLowerCase())}`; }

// ---------------- the bridge page (what Telegram Desktop opens to perform the handshake) ----------------
function bridgePage(host, bootstrap) {
  const scriptNonce = randomNonce();
  const config = JSON.stringify({ origin: `https://${host}`, bootstrap, batchLimit: MAX_WS_MESSAGE, maxPendingItems: 1024, connectTimeout: 15000 });
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Proxy</title></head>
<body><main><h1>Connection bridge</h1><p>This page is opened by a compatible Telegram client.</p></main>
<script nonce="${scriptNonce}">
(()=>{'use strict';
const cfg=${config};
let port=null, sessionToken='', socket=null, creating=false, closed=false;
const pending=[]; let pendingBytes=0;
const bootstrapAbort=new AbortController(); let connectTimer=null;
const fragment=new URLSearchParams(location.hash.slice(1));
const nonce=fragment.get('android')||'';
history.replaceState(null,'','/');
function status(state){try{port&&port.postMessage({t:'status',state})}catch{}}
function splitFrames(buffer){
 const input=new Uint8Array(buffer); let off=0,count=0,out=[];
 while(off<input.length){
  if(++count>4096||input.length-off<8)throw Error('bad frame');
  const view=new DataView(input.buffer,input.byteOffset+off,8); const len=view.getUint32(4);
  if(len>1048576||off+8+len>input.length)throw Error('bad frame');
  out.push(buffer.slice(off,off+8+len)); off+=8+len;
 }
 if(!out.length)throw Error('empty'); return out;
}
function sendToApp(buffer){for(const frame of splitFrames(buffer))port.postMessage(frame,[frame]);}
function fail(){if(closed)return;status('failed');close(false)}
async function createSession(hello){
 try{
  const response=await fetch(cfg.origin+'/api/v1/session',{method:'POST',headers:{Authorization:'Bearer '+cfg.bootstrap,'Content-Type':'application/octet-stream','X-Carrier-Mode':'websocket'},body:hello,mode:'same-origin',redirect:'error',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:bootstrapAbort.signal});
  if(!response.ok||response.headers.get('X-Carrier-Mode')!=='websocket')throw Error('session');
  sessionToken=response.headers.get('X-Session-Token')||'';
  if(!/^[A-Za-z0-9_-]{43}$/.test(sessionToken))throw Error('token');
  const welcome=await response.arrayBuffer();
  if(closed)return;
  if(welcome.byteLength!==8||new Uint8Array(welcome)[0]!==0x11||new Uint8Array(welcome).slice(1).some(v=>v!==0))throw Error('welcome');
  sendToApp(welcome);
  if(!closed)openSocket();
 }catch(e){fail()}
}
function openSocket(){
 const target=cfg.origin.replace(/^https:/,'wss:')+'/api/v1/ws';
 socket=new WebSocket(target,'tproxy-v1.'+sessionToken); socket.binaryType='arraybuffer';
 socket.onopen=()=>{
  if(closed)return; clearTimeout(connectTimer);connectTimer=null;status('connected');
  try{for(const data of pending){if(socket.bufferedAmount+data.byteLength>cfg.batchLimit)return fail();socket.send(data)}}catch{return fail()}
  pending.length=0;pendingBytes=0;
 };
 socket.onmessage=e=>{if(closed)return;if(!(e.data instanceof ArrayBuffer)||!e.data.byteLength||e.data.byteLength>cfg.batchLimit)return fail();try{sendToApp(e.data)}catch{return fail()}};
 socket.onerror=()=>{}; socket.onclose=()=>{if(!closed)fail()};
}
function fromApp(data){
 if(closed)return;
 if(data instanceof ArrayBuffer){
  if(!data.byteLength||data.byteLength>cfg.batchLimit)return fail();
  try{splitFrames(data)}catch{return fail()}
  if(!creating){creating=true;connectTimer=setTimeout(fail,cfg.connectTimeout);createSession(data);return}
  if(!sessionToken||!socket||socket.readyState!==WebSocket.OPEN){if(pending.length>=cfg.maxPendingItems||pendingBytes+data.byteLength>cfg.batchLimit)return fail();pending.push(data);pendingBytes+=data.byteLength;return}
  if(socket.bufferedAmount+data.byteLength>cfg.batchLimit)return fail();
  try{socket.send(data)}catch{fail()}
 }else if(data&&data.t==='close')close(true);
}
function activate(next){port=next;port.onmessage=e=>fromApp(e.data);port.start&&port.start();status('connecting')}
const native=globalThis.TelegramWebProxy;
if(/^[A-Za-z0-9_-]{43}$/.test(nonce)&&native&&typeof native.postMessage==='function'){
 const adapter={onmessage:null,start(){},close(){native.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){for(const frame of splitFrames(value))native.postMessage(frame)}
  else native.postMessage(JSON.stringify(value));
 }};
 native.onmessage=e=>{let d=e.data;if(typeof d==='string'){try{d=JSON.parse(d)}catch{return}}adapter.onmessage&&adapter.onmessage({data:d})};
 activate(adapter);native.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce}));
}
addEventListener('message',e=>{
 if(closed||port||e.source!==parent||!e.data||e.data.t!=='tproxy-init'||e.data.v!==1||e.ports.length!==1)return;
 try{const u=new URL(e.origin);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port)return}catch{return}
 activate(e.ports[0]);
});
function close(notify){if(closed)return;closed=true;clearTimeout(connectTimer);connectTimer=null;bootstrapAbort.abort();pending.length=0;pendingBytes=0;try{socket&&socket.close()}catch{}if(notify&&sessionToken)fetch(cfg.origin+'/api/v1/session',{method:'DELETE',headers:{Authorization:'Bearer '+sessionToken},keepalive:true,mode:'same-origin',redirect:'error',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'}).catch(()=>{});try{port&&port.close()}catch{}}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script></body></html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${scriptNonce}'; connect-src https://${host} wss://${host}; style-src 'none'; img-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; sandbox allow-same-origin allow-scripts`,
      'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
}
function randomNonce() { return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(18)))); }

// ---------------- route entry points, called from index.js (all public — no admin cookie) ----------------
const noStore = () => ({ 'Cache-Control': 'no-store' });
const bearer = req => { const v = req.headers.get('Authorization') || ''; return v.startsWith('Bearer ') ? v.slice(7) : ''; };
const isBinary = v => /^application\/octet-stream(?:\s*;.*)?$/i.test(v || '');
async function readHello(request) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader(), bytes = new Uint8Array(9); let length = 0;
  try { for (; ;) { const { value, done } = await reader.read(); if (done) return bytes.subarray(0, length); if (length + value.length > bytes.length) { await reader.cancel(); return new Uint8Array(); } bytes.set(value, length); length += value.length; } }
  finally { reader.releaseLock(); }
}
function isHello(bytes) { try { const frames = parseFrames(bytes); return frames.length === 1 && frames[0].type === FRAME.HELLO && frames[0].streamId === 0 && frames[0].payload.length === 1 && frames[0].payload[0] === 1; } catch { return false; } }

const capCache = new Map();
async function userByCapability(reg, cap, host) {
  const key = host + '|' + cap, hit = capCache.get(key);
  if (hit) { const u = await reg.byId(hit); if (u && await capabilityMatches(cap, host, u.wp_secret)) return u; capCache.delete(key); }
  for (const u of await reg.list()) if (await capabilityMatches(cap, host, u.wp_secret)) { capCache.set(key, u.id); if (capCache.size > 2000) capCache.delete(capCache.keys().next().value); return reg.byId(u.id); }
  return null;
}
const usable = u => !!u && state(u) === 'active' && !noSecret(u.wp_secret);

const cleanHost = v => String(v || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
const cleanSecret = v => { const x = String(v || '').trim().toLowerCase(); return /^dd[0-9a-f]{32}$/.test(x) ? x.slice(2) : x; };

/** GET "/" when a bridge/telegram query is present. `reg` = { byId, bySecret, list } over the users. Returns a Response, or null to fall through to the normal panel home.
 *  The link may carry extra parameters (port, ...) and the server may be written with a port or in capitals: only `server` + `secret` (or one `bridge` capability) matter. */
async function handleRoot(url, s, host, reg) {
  const expectedHost = panelDomain(s, host), here = cleanHost(host), want = cleanHost(expectedHost);
  const bridgeVal = url.searchParams.get('bridge');
  const isBridgeShape = !!bridgeVal && /^[A-Za-z0-9_-]{43}$/.test(bridgeVal) && !url.searchParams.has('secret');
  const isTelegramShape = !isBridgeShape && url.searchParams.has('server') && url.searchParams.has('secret');
  if (!isBridgeShape && !isTelegramShape) return null;
  let user = null;
  if (isTelegramShape) {
    const server = cleanHost(url.searchParams.get('server'));
    if (server !== want && server !== here) return null;
    user = await reg.bySecret(cleanSecret(url.searchParams.get('secret')));
  } else {
    user = await userByCapability(reg, bridgeVal, expectedHost);
    if (!user && here !== want) user = await userByCapability(reg, bridgeVal, host);
  }
  if (!usable(user)) return null;                                           // unknown secret, disabled, expired or over its volume
  return bridgePage(host, await createBootstrap(user.wp_secret, user.id));  // the page talks to the host it was opened from
}
async function handleSession(request, s, host, reg) {
  const expectedHost = panelDomain(s, host);
  if (request.method === 'DELETE') {
    const token = bearer(request), u = await reg.byId(sessionUser(token)); if (!u || !(await verifySessionToken(u.wp_secret, expectedHost, token))) return new Response('Not found', { status: 404 });
    return new Response(null, { status: 204, headers: noStore() }); // session cleanup happens when the socket closes
  }
  if (request.method !== 'POST' || !isBinary(request.headers.get('Content-Type'))) return new Response('Not found', { status: 404 });
  const bootstrap = bearer(request), u = bootstrap ? await reg.byId(bootstrapUser(bootstrap)) : null;
  if (!usable(u) || !(await verifyBootstrap(u.wp_secret, bootstrap))) return new Response('Not found', { status: 404 });
  const hello = await readHello(request); if (!isHello(hello)) return new Response('Not found', { status: 404 });
  const sessionToken = await createSessionToken(u.wp_secret, expectedHost, u.id);
  const welcome = encodeFrame(FRAME.WELCOME, 0);
  return new Response(welcome, { status: 200, headers: { ...noStore(), 'Content-Type': 'application/octet-stream', 'X-Session-Token': sessionToken, 'X-Carrier-Mode': 'websocket' } });
}
async function handleWs(request, s, host, env, reg, ctx, connectFn) {
  if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
  const expectedHost = panelDomain(s, host);
  const protocols = (request.headers.get('Sec-WebSocket-Protocol') || '').split(',').map(v => v.trim());
  const protocol = protocols.find(v => v.startsWith('tproxy-v1.')); const token = protocol?.slice('tproxy-v1.'.length);
  const u = await reg.byId(sessionUser(token));
  if (!usable(u) || !(await verifySessionToken(u.wp_secret, expectedHost, token))) return new Response('Not found', { status: 404 });
  return new RelaySession(ctx, env, connectFn).upgrade(protocol, u);
}

// ---------------- one session per connected Telegram client, relays to the real Telegram DC ----------------
const LIMITS = Object.freeze({ itemCost: 256, ingressBytes: 8 * 1024 * 1024, ingressItems: 128, uplinkBytes: 8 * 1024 * 1024, uplinkItems: 8192, streamBytes: INITIAL_WINDOW + 1024 * 1024, streamItems: 4096, downlinkBytes: 8 * 1024 * 1024, downlinkItems: 8192, handshakeTimeout: 15000, connectTimeout: 10000, writeTimeout: 30000 });

class RelaySession {
  constructor(ctx, env, connect) {
    this.ctx = ctx; this.env = env; this.connect = connect; this.closed = false; this.ws = null;
    this.db = new DB(env);
    this.streams = new Map(); this.closedIds = new Set(); this.maxStreams = 64;
    this.messageChain = Promise.resolve(); this.ingressBytes = 0; this.ingressItems = 0;
    this.uplinkBytes = 0; this.uplinkItems = 0; this.downlinkBytes = 0; this.downlinkItems = 0;
    this.downlinkWaiters = new Set(); this.secret = null; this.meter = null;
  }
  /** Upgrade the incoming Pages Function request to a WebSocket and start relaying in this isolate. */
  upgrade(protocol, user) {
    if (this.closed) return new Response('session closed', { status: 404 });
    if (this.ws) return new Response('already connected', { status: 409 });
    if (!user || state(user) !== 'active' || noSecret(user.wp_secret)) return new Response('forbidden', { status: 403 });
    this.secret = parseProxySecret(user.wp_secret); this.meter = new Meter(this.db, user, { wait: p => this.ctx.waitUntil(p) }); this.meter.bind(reason => this.protocolError(reason));
    const pair = new WebSocketPair(); const client = pair[0], server = pair[1]; server.accept(); this.ws = server;
    server.addEventListener('message', e => this.enqueueMessage(e.data));
    server.addEventListener('close', () => this.shutdown('websocket_close'));
    server.addEventListener('error', () => this.shutdown('websocket_error'));
    return new Response(null, { status: 101, webSocket: client, headers: protocol ? { 'Sec-WebSocket-Protocol': protocol } : {} });
  }
  enqueueMessage(data) {
    if (this.closed) return;
    const length = data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : 0;
    if (!length || length > MAX_WS_MESSAGE) return this.protocolError('invalid_websocket_message');
    const cost = length + LIMITS.itemCost;
    if (this.ingressBytes + cost > LIMITS.ingressBytes || this.ingressItems >= LIMITS.ingressItems) return this.protocolError('ingress_queue_limit');
    this.ingressBytes += cost; this.ingressItems++;
    this.messageChain = this.messageChain.then(() => this.onMessage(data)).catch(() => this.protocolError('message_handler_failed')).finally(() => { this.ingressBytes -= cost; this.ingressItems--; });
    this.ctx.waitUntil(this.messageChain); return this.messageChain;
  }
  async onMessage(data) {
    if (this.closed) return;
    if (data instanceof Blob) data = await data.arrayBuffer();
    if (this.closed) return;
    if (!(data instanceof ArrayBuffer) || !data.byteLength || data.byteLength > MAX_WS_MESSAGE) return this.protocolError('invalid_websocket_message');
    let frames; try { frames = parseFrames(new Uint8Array(data)); } catch { return this.protocolError('frame_parse_failed'); }
    for (const frame of frames) {
      if (frame.streamId === 0) { if (frame.type !== FRAME.PONG || frame.payload.length > 64) return this.protocolError('invalid_control_frame'); }
      else if (frame.type === FRAME.OPEN) this.openStream(frame);
      else if (frame.type === FRAME.DATA) this.queueWrite(frame);
      else if (frame.type === FRAME.WINDOW) this.addWindow(frame);
      else if (frame.type === FRAME.CLOSE) { if (frame.payload.length) return this.protocolError('invalid_close'); if (!this.streams.has(frame.streamId) && !this.closedIds.has(frame.streamId)) return this.protocolError('unknown_stream'); this.closeStream(frame.streamId, false); }
      else return this.protocolError('unknown_frame_type');
      if (this.closed) return;
    }
  }
  openStream(frame) {
    const id = frame.streamId;
    if (!id || frame.payload.length || this.streams.has(id) || this.closedIds.has(id)) return this.protocolError('invalid_open');
    if (this.streams.size >= this.maxStreams) { this.rememberClosed(id); return this.sendFrame(FRAME.CLOSE, id); }
    const stream = { id, socket: null, writer: null, handshake: new Uint8Array(), handshakeBytes: 0, receiveWindow: INITIAL_WINDOW, sendCredit: INITIAL_WINDOW, closed: false, queue: [], queueHead: 0, pendingBytes: 0, pendingItems: 0, draining: false, abort: new AbortController(), sent: [], sentHead: 0, downlinkBytes: 0, downlinkItems: 0 };
    stream.handshakeTimer = setTimeout(() => this.closeStream(id, true), LIMITS.handshakeTimeout);
    this.streams.set(id, stream);
  }
  queueWrite(frame) {
    const stream = this.streams.get(frame.streamId);
    if (!stream) { if (this.closedIds.has(frame.streamId) && frame.payload.length) return; return this.protocolError('unknown_stream'); }
    const length = frame.payload.length; if (!length || length > stream.receiveWindow) return this.protocolError('invalid_data_window');
    this.meter.add(length); if (this.closed) return;                     // volume / expiry are enforced here, on the user's own account
    const cost = length + HEADER_SIZE + LIMITS.itemCost;
    if (stream.pendingBytes + cost > LIMITS.streamBytes || stream.pendingItems >= LIMITS.streamItems || this.uplinkBytes + cost > LIMITS.uplinkBytes || this.uplinkItems >= LIMITS.uplinkItems) return this.closeStream(stream.id, true);
    stream.receiveWindow -= length; stream.pendingBytes += cost; stream.pendingItems++; this.uplinkBytes += cost; this.uplinkItems++;
    stream.queue.push({ payload: new Uint8Array(frame.payload), cost });
    if (!stream.draining) { stream.draining = true; this.ctx.waitUntil(this.drainStream(stream)); }
  }
  releaseWrite(stream, item) { stream.pendingBytes -= item.cost; stream.pendingItems--; this.uplinkBytes -= item.cost; this.uplinkItems--; }
  async drainStream(stream) {
    try {
      while (!stream.closed && !this.closed && stream.queueHead < stream.queue.length) {
        const item = stream.queue[stream.queueHead]; stream.queue[stream.queueHead++] = null;
        try { await this.writeStream(stream, item.payload); } finally { this.releaseWrite(stream, item); }
        if (stream.queueHead === stream.queue.length) { stream.queue = []; stream.queueHead = 0; }
        else if (stream.queueHead >= 64) { stream.queue = stream.queue.slice(stream.queueHead); stream.queueHead = 0; }
      }
    } catch { this.closeStream(stream.id, true); } finally { stream.draining = false; }
  }
  active(stream) { if (stream.closed || this.closed) throw new Error('stream closed'); }
  async writeStream(stream, payload) {
    this.active(stream); let grant = payload.length;
    if (!stream.writer) {
      const take = Math.min(64 - stream.handshake.length, payload.length);
      const joined = new Uint8Array(stream.handshake.length + take); joined.set(stream.handshake); joined.set(payload.subarray(0, take), stream.handshake.length);
      stream.handshake = joined; stream.handshakeBytes += take;
      if (joined.length < 64) return;
      if (!this.secret) throw new Error('no secret');
      const client = await acceptClientHandshake(joined, this.secret); this.active(stream);
      const tg = await createTelegramHandshake(client.tag, client.dcId); this.active(stream);
      clearTimeout(stream.handshakeTimer); stream.handshakeTimer = null;
      const socket = this.connect({ hostname: TELEGRAM_DCS[Math.abs(client.dcId)], port: 443 }, { allowHalfOpen: false });
      stream.socket = socket; Promise.resolve(socket.closed).catch(() => { });
      await waitFor(socket.opened, stream.abort.signal, LIMITS.connectTimeout, 'connect timeout'); this.active(stream);
      stream.writer = socket.writable.getWriter();
      stream.clientDecrypt = client.clientDecrypt; stream.clientEncrypt = client.clientEncrypt;
      stream.tgEncrypt = tg.encrypt; stream.tgDecrypt = tg.decrypt; stream.handshake = new Uint8Array();
      await waitFor(stream.writer.write(tg.wire), stream.abort.signal, LIMITS.writeTimeout, 'write timeout'); this.active(stream);
      this.ctx.waitUntil(this.readStream(stream));
      grant = stream.handshakeBytes + payload.length - take; stream.handshakeBytes = 0; payload = payload.subarray(take);
    }
    for (let offset = 0; offset < payload.length; offset += DATA_CHUNK) {
      const plain = await stream.clientDecrypt.crypt(payload.subarray(offset, offset + DATA_CHUNK)); this.active(stream);
      const encrypted = await stream.tgEncrypt.crypt(plain); this.active(stream);
      await waitFor(stream.writer.write(encrypted), stream.abort.signal, LIMITS.writeTimeout, 'write timeout'); this.active(stream);
    }
    this.grantWindow(stream, grant);
  }
  grantWindow(stream, length) { if (stream.closed || this.closed || !length) return; stream.receiveWindow += length; this.sendFrame(FRAME.WINDOW, stream.id, u32(length)); }
  addWindow(frame) {
    if (frame.payload.length !== 4) return this.protocolError('invalid_window');
    const amount = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4).getUint32(0); if (!amount) return this.protocolError('invalid_window');
    const stream = this.streams.get(frame.streamId); if (!stream) { if (this.closedIds.has(frame.streamId)) return; return this.protocolError('unknown_stream'); }
    if (amount > INITIAL_WINDOW - stream.sendCredit) return this.protocolError('window_overflow');
    stream.sendCredit += amount; let remaining = amount;
    while (remaining) {
      const item = stream.sent[stream.sentHead]; const used = Math.min(remaining, item.remaining);
      item.remaining -= used; remaining -= used; stream.downlinkBytes -= used; this.downlinkBytes -= used;
      if (!item.remaining) { const overhead = HEADER_SIZE + LIMITS.itemCost; stream.downlinkBytes -= overhead; this.downlinkBytes -= overhead; stream.downlinkItems--; this.downlinkItems--; stream.sent[stream.sentHead++] = null; }
    }
    if (stream.sentHead === stream.sent.length) { stream.sent = []; stream.sentHead = 0; } else if (stream.sentHead >= 64) { stream.sent = stream.sent.slice(stream.sentHead); stream.sentHead = 0; }
    this.wakeDownlink();
  }
  downlinkRoom(stream) { if (this.downlinkItems >= LIMITS.downlinkItems) return 0; return Math.max(0, Math.min(DATA_CHUNK, stream.sendCredit, LIMITS.downlinkBytes - this.downlinkBytes - HEADER_SIZE - LIMITS.itemCost)); }
  async waitDownlink(stream) { while (!stream.closed && !this.closed && !this.downlinkRoom(stream)) await new Promise(resolve => this.downlinkWaiters.add(resolve)); return !stream.closed && !this.closed; }
  wakeDownlink() { const waiters = [...this.downlinkWaiters]; this.downlinkWaiters.clear(); for (const resolve of waiters) resolve(); }
  async readStream(stream) {
    const reader = stream.socket.readable.getReader();
    try {
      while (await this.waitDownlink(stream)) {
        const { value, done } = await reader.read(); if (done || stream.closed || this.closed) break;
        const bytes = value instanceof Uint8Array ? value : new Uint8Array(value); let offset = 0;
        while (offset < bytes.length && await this.waitDownlink(stream)) {
          const size = Math.min(bytes.length - offset, this.downlinkRoom(stream)); if (!size) continue;
          this.meter.add(size); if (this.closed) break;
          const cost = size + HEADER_SIZE + LIMITS.itemCost; stream.sendCredit -= size; stream.sent.push({ remaining: size });
          stream.downlinkBytes += cost; stream.downlinkItems++; this.downlinkBytes += cost; this.downlinkItems++;
          const plain = await stream.tgDecrypt.crypt(bytes.subarray(offset, offset + size)); this.active(stream);
          const encrypted = await stream.clientEncrypt.crypt(plain); this.active(stream);
          this.sendFrame(FRAME.DATA, stream.id, encrypted); offset += size;
        }
      }
    } catch { } finally { ignoreFailure(() => reader.cancel()); try { reader.releaseLock(); } catch { } this.closeStream(stream.id, true); }
  }
  closeStream(id, notify) {
    const stream = this.streams.get(id); if (!stream) return;
    this.streams.delete(id); this.rememberClosed(id); stream.closed = true;
    clearTimeout(stream.handshakeTimer); stream.handshakeTimer = null; stream.abort.abort();
    for (let i = stream.queueHead; i < stream.queue.length; i++) this.releaseWrite(stream, stream.queue[i]);
    stream.queue = []; stream.queueHead = 0; stream.handshake = new Uint8Array();
    this.downlinkBytes -= stream.downlinkBytes; this.downlinkItems -= stream.downlinkItems; stream.downlinkBytes = 0; stream.downlinkItems = 0; stream.sent = []; stream.sentHead = 0;
    this.wakeDownlink(); ignoreFailure(() => stream.writer?.abort()); ignoreFailure(() => stream.socket?.close());
    if (notify && !this.closed) this.sendFrame(FRAME.CLOSE, id);
  }
  rememberClosed(id) { this.closedIds.add(id); if (this.closedIds.size > 4096) this.closedIds.delete(this.closedIds.values().next().value); }
  sendFrame(type, streamId, payload = new Uint8Array()) { if (this.closed || !this.ws || this.ws.readyState !== 1) return; try { this.ws.send(encodeFrame(type, streamId, payload)); } catch { this.shutdown('websocket_send_failed'); } }
  protocolError(reason = 'protocol_error') { this.sendFrame(FRAME.BYE, 0); this.shutdown(reason); }
  shutdown() { if (this.closed) return; this.closed = true; if (this.meter) this.meter.stop(); for (const id of [...this.streams.keys()]) this.closeStream(id, false); this.wakeDownlink(); try { this.ws?.close(1000, 'session closed'); } catch { } this.ws = null; }
}
function waitFor(promise, signal, timeout, reason) {
  return new Promise((resolve, reject) => {
    const aborted = () => finish(reject, new Error('stream closed')); let timer, settled = false;
    const finish = (settle, value) => { if (settled) return; settled = true; clearTimeout(timer); signal.removeEventListener('abort', aborted); settle(value); };
    Promise.resolve(promise).then(value => finish(resolve, value), error => finish(reject, error));
    if (signal.aborted) return aborted();
    signal.addEventListener('abort', aborted, { once: true }); timer = setTimeout(() => finish(reject, new Error(reason)), timeout);
  });
}
function ignoreFailure(fn) { try { Promise.resolve(fn()).catch(() => { }); } catch { } }

  return { FRAME, HEADER_SIZE, MAX_PAYLOAD, MAX_BATCH_FRAMES, INITIAL_WINDOW, DATA_CHUNK, MAX_WS_MESSAGE, encodeFrame, parseFrames, u32, clampInt, TELEGRAM_DCS, AesCtrStream, parseProxySecret, acceptClientHandshake, createTelegramHandshake, hmac, createBootstrap, bootstrapUser, verifyBootstrap, createSessionToken, sessionUser, verifySessionToken, capabilityMatches, testDataCenters, randomSecret, telegramLink, bridgePage, handleRoot, handleSession, handleWs, LIMITS, RelaySession };
})();

const __mod__mock_index = (() => {
  const { DB, init, state, fmt, GB, now, DEFAULTS, DEFAULT_SITES, newSecret } = __mod_db;
  const { hashPw, checkPw, makeSession, validSession, cookies, cookie } = __mod_auth;
  const { links, cfgDom, whiteList, cleanSite, sitesList, fragProf, tierOf, FRAG_TIERS, ECH, adv, protos, NATIVE, ALL, panelDomain } = __mod_links;
  const UI = __mod_ui;
  const LOC = __mod_loc;
  const WP = __mod_warp;
  const RL = __mod_relays;
  const { probeAll } = __mod_proxy;
  const { b64 } = __mod_util;
  const { Meter, dialer, serveNative, serveUpstream, WS_PATH, earlyData } = __mod_relay;
  const WPX = __mod_webproxy;
  const { STATIC } = __mod_static;
  const { VERSION, BUILD, REPO, BRANCH } = __mod_version;
  // --- _mock_index.js ---
// xr PANEL for Cloudflare Pages + D1. No Xray: VLESS / VMess / Shadowsocks / Trojan are terminated in the Pages
// Function and relayed over TCP sockets; D1 holds users, settings and every other table.
const connect = () => { throw new Error('socket stub'); };

const CLIENTS = [['iOS', [['Streisand', 'https://apps.apple.com/app/streisand/id6450534064', 'streisand://import/{u}'], ['V2Box', 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690', 'v2box://install-sub?url={u}&name=VPN'], ['Shadowrocket', 'https://apps.apple.com/app/shadowrocket/id932747118', 'shadowrocket://add/sub://{b}']]],
  ['Android', [['v2rayNG', 'https://github.com/2dust/v2rayNG/releases', 'v2rayng://install-sub?url={u}&name=VPN'], ['Hiddify', 'https://github.com/hiddify/hiddify-app/releases', 'hiddify://import/{u}'], ['NekoBox', 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases', null]]]];
const clientGroups = su => CLIENTS.map(([g, a]) => [g, a.map(([n, d, i]) => [n, d, i ? i.replace('{u}', encodeURIComponent(su)).replace('{b}', b64(su)) : null])]);
const KINDS = ['ip', 'sni', 'warp', 'masque'];
const NOFLAG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 3"><rect width="4" height="3" fill="#3a3a4a"/><path d="M1 .5v2M1 .5h1.7l-.4.5.4.5H1" fill="#8c8ca0"/></svg>';
const MARK = RL.MARK;
const noDb = () => new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>xr PANEL · D1 missing</title><body style="font:16px system-ui;max-width:640px;margin:12vh auto;padding:0 20px;line-height:1.6"><h2>xr PANEL is running, but its D1 database is not attached</h2><p>The Pages project needs a D1 binding named <b>DB</b>.</p><p>Cloudflare dashboard → Workers &amp; Pages → this Pages project → Settings → Bindings → Add → D1 database → variable name <b>DB</b> → pick the database → Redeploy.</p><p dir="rtl">پنل بالا آمده ولی D1 به آن وصل نیست. در Cloudflare: Workers &amp; Pages ← همین پروژه Pages ← Settings ← Bindings ← Add ← D1 database ← نام متغیر <b>DB</b> ← دیتابیس را انتخاب کنید ← Redeploy.</p>', { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });

const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const HTML = (h, extra = {}) => new Response(String(h), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra } });
const body = async req => { try { return await req.json(); } catch { return {}; } };

function makeApp({ connectFn = connect, fetchFn = (...a) => fetch(...a), pair = () => new WebSocketPair(), wsResponse = (ws, headers) => new Response(null, { status: 101, webSocket: ws, headers }) } = {}) {
  const userCache = new Map();
  // Web-proxy lookups read the account fresh (they happen once per connection, not per packet), so a disabled, expired
  // or over-limit user is refused at once. Only the list used to match the bridge capability is cached (15 s).
  const wpRows = { t: 0, rows: [] };
  const dropCaches = () => { userCache.clear(); wpRows.t = 0; };
  const wpReg = db => ({
    list: async () => { if (Date.now() - wpRows.t > 15000) { wpRows.rows = await db.all("SELECT id,wp_secret FROM users WHERE wp_secret!=''"); wpRows.t = Date.now(); } return wpRows.rows; },
    byId: async id => id > 0 ? db.one('SELECT * FROM users WHERE id=?', id) : null,
    bySecret: async sec => /^[0-9a-f]{32}$/.test(sec) ? db.one('SELECT * FROM users WHERE wp_secret=?', sec) : null,
  });
  const hostOf = url => url.hostname;

  async function ctxFor(db, req, url, extra = {}) {
    const flashes = []; const ck = cookies(req); if (ck.flash) { try { flashes.push(...JSON.parse(ck.flash)); } catch { } }
    const s = extra.s || await db.S();
    const base = (s.domain || '').trim() && s.domain.trim() !== 'example.com' ? `https://${s.domain.trim()}` : `${url.protocol}//${url.host}`;
    return { s, flashes, chrome: extra.chrome !== false, endpoint: extra.endpoint, suburl: u => `${base}/sub/${u.uuid}`, host: hostOf(url), clearFlash: flashes.length > 0 };
  }
  const page = (c, h, extra) => HTML(h, c.clearFlash ? { 'set-cookie': cookie('flash', '', { max: 0 }), ...extra } : extra);
  const redirect = (to, ...msgs) => { const h = new Headers({ Location: to }); if (msgs.length) h.append('set-cookie', cookie('flash', JSON.stringify(msgs), { max: 30 })); return new Response(null, { status: 302, headers: h }); };

  async function status(db, s) {
    const us = await db.all('SELECT * FROM users'); const act = us.filter(u => state(u) === 'active').length, used = us.reduce((a, u) => a + (u.used || 0), 0), quota = us.reduce((a, u) => a + (u.limit_gb || 0) * GB, 0);
    const g = (await db.one('SELECT COUNT(*) c FROM grps')).c, p = (await db.one('SELECT COUNT(*) c FROM proxies')).c, ips = (await db.one("SELECT COUNT(*) c FROM scan_ips WHERE kind='ip'")).c;
    const rl = (await db.one("SELECT COUNT(*) c FROM relays WHERE domain!='' AND domain IS NOT NULL")).c, fp = s.frag_on === '1' ? fragProf(s) : null;
    return { users: us.length, active: act, ap: us.length ? Math.round(act / us.length * 100) : 0, traffic: fmt(used), tp: quota ? Math.min(100, Math.round(used / quota * 100)) : 0, mode: (s.upstream || '').trim() ? 'Upstream' : 'Built-in', groups: g, proxies: p, ips, relays: rl, frag: fp ? fp.tier : (s.frag_on === '1' ? 'measuring' : 'off') };
  }

  async function panelTarget(db, s, url) {
    const h = panelDomain(s, url.hostname), p = /^\d+$/.test(s.tls_port) ? +s.tls_port : 443;
    const ok = /^[\d.]+$/.test(h) ? LOC.isGlobal(h) : (h !== 'localhost' && h.includes('.')); return ok ? [h, p] : null;
  }

  // ---------------- WebSocket relay ----------------
  async function wsRoute(req, env, ctx, m) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    const proto = m[1], uid = m[2].toLowerCase(), db = new DB(env); await init(env, hashPw);
    let hit = userCache.get(uid); if (!hit || Date.now() - hit.t > 15000) { hit = { t: Date.now(), u: await db.one('SELECT * FROM users WHERE uuid=?', uid), s: await db.S() }; userCache.set(uid, hit); }
    const { u, s } = hit; if (!u || state(u) !== 'active') return new Response('Forbidden', { status: 403 });
    const up = (s.upstream || '').trim();
    const [client, server] = Object.values(pair()); server.accept(); const ph = req.headers.get('Sec-WebSocket-Protocol') || '';
    const meter = new Meter(db, u, { wait: p => ctx.waitUntil(p), onDead: () => userCache.delete(uid) });
    if (up) ctx.waitUntil(serveUpstream(server, { upstream: up, path: `/ws/${proto}/${uid}`, protocolHeader: ph, meter, fetchFn }));
    else serveNative(server, { proto, user: u, dial: await dialer(db, connectFn, u), meter, ctx, early: earlyData(ph) });
    return wsResponse(client, ph ? { 'Sec-WebSocket-Protocol': ph } : {});
  }

  // ---------------- main ----------------
  async function handle(req, env, ctx) {
    const url = new URL(req.url), path = url.pathname, method = req.method;
    if (!(env && env.DB) && !path.startsWith('/static/') && path !== '/relay-check' && path !== '/healthz') return noDb();
    const wm = path.match(WS_PATH); if (wm) return wsRoute(req, env, ctx, wm);
    if (path.startsWith('/static/')) {
      const f = Object.hasOwn(STATIC, path.slice(8)) ? STATIC[path.slice(8)] : null; if (!f || !['GET', 'HEAD'].includes(method)) return new Response('Not found', { status: 404 });
      return new Response(method === 'HEAD' ? null : f[1], { headers: { 'content-type': f[0], 'cache-control': 'public, max-age=86400', 'x-content-type-options': 'nosniff' } });
    }
    if (path === '/relay-check') return new Response(MARK, { headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
    await init(env, hashPw); const db = new DB(env); let s = await db.S();

    if (path === '/login') {
      if (method === 'POST') {
        const f = await req.formData();
        if (f.get('user') === 'admin' && await checkPw(s.pw, String(f.get('pw') || ''))) return new Response(null, { status: 302, headers: { Location: '/', 'set-cookie': cookie('xr', await makeSession(s.secret), { max: 7 * 86400 }) } });
        await new Promise(r => setTimeout(r, 800)); return redirect('/login', 'Wrong username or password');
      }
      const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.login(c));
    }
    if (path === '/logout') return new Response(null, { status: 302, headers: { Location: '/login', 'set-cookie': cookie('xr', '', { max: 0 }) } });

    // public subscription
    let m;
    if ((m = path.match(/^\/sub\/([0-9a-fA-F-]{36})$/))) {
      const u = await db.one('SELECT * FROM users WHERE uuid=?', m[1].toLowerCase()); if (!u) return new Response('Not found', { status: 404 });
      const st = state(u), L = st === 'active' ? await links(db, u, s, url.hostname) : [];
      if (!u.wp_secret) { u.wp_secret = newSecret(); await db.run('UPDATE users SET wp_secret=? WHERE id=?', u.wp_secret, u.id); }
      if ((req.headers.get('Accept') || '').includes('text/html') && !url.searchParams.get('raw')) { const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.sub(c, u, st, L, c.suburl(u), clientGroups(c.suburl(u)), st === 'active' ? WPX.telegramLink(u.wp_secret, panelDomain(s, url.hostname)) : '')); }
      return new Response(b64(L.map(x => x[2]).join('\n')), { headers: { 'content-type': 'text/plain', 'subscription-userinfo': `upload=0; download=${u.used}; total=${Math.floor(u.limit_gb * GB)}; expire=${u.expire}`, 'profile-update-interval': '1', 'profile-title': 'VPN' } });
    }

    // ---- native Telegram Web Proxy (MTProto over WebSocket), one secret per user — public, no admin cookie ----
    if (path === '/healthz') return J({ ok: true });
    if (path === '/api/v1/session') return WPX.handleSession(req, s, url.hostname, wpReg(db));
    if (path === '/api/v1/ws') return WPX.handleWs(req, s, url.hostname, env, wpReg(db), ctx, connectFn);
    if (path === '/' && url.search) { const r = await WPX.handleRoot(url, s, url.hostname, wpReg(db)); if (r) return r; }

    // everything below needs a session
    if (!(await validSession(s.secret, cookies(req).xr))) return method === 'GET' && !path.startsWith('/api/') ? redirect('/login') : (path.startsWith('/api/') ? J({ error: 'login required' }, 401) : redirect('/login'));
    const C = (endpoint, extra = {}) => ctxFor(db, req, url, { s, endpoint, ...extra });
    const form = async () => { let f; try { f = await req.formData(); } catch { f = new FormData(); } return { get: k => f.get(k), all: k => f.getAll(k), has: k => f.has(k) }; };

    if (path === '/' ) { const c = await C('home'); return page(c, UI.home(c, await status(db, s))); }
    if (path === '/api/status') return J(await status(db, s));
    if (path === '/api/cf') return J(await cfUsage(env));

    if ((m = path.match(/^\/flag\/([a-z]{2})\.svg$/))) {
      const cache = typeof caches !== 'undefined' ? caches.default : null, key = new Request(`https://flags.invalid/${m[1]}.svg`);
      const hit = cache && await cache.match(key); if (hit) return hit;
      for (const src of [`https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.2.3/flags/4x3/${m[1]}.svg`, `https://flagcdn.com/${m[1]}.svg`]) {
        try { const r = await fetchFn(src); const t = r.ok ? await r.text() : ''; if (/<svg/i.test(t) && !/<script|onload|foreignobject/i.test(t)) { const res = new Response(t, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'private, max-age=86400' } }); if (cache) ctx.waitUntil(cache.put(key, res.clone())); return res; } } catch { }
      }
      return new Response(NOFLAG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' } });
    }

    if (path === '/api/probe' && method === 'POST') {
      const d = await body(req), h = String(d.host || '').trim(), p = String(d.port || '').trim(); if (!LOC.valid(h, p)) return J({ error: 'Enter a valid IP/host and port' }, 400);
      const [[res, best], g] = await Promise.all([probeAll(connectFn, h, +p), LOC.geo(h, fetchFn)]); return J({ results: res, best, geo: g });
    }

    // ---- users ----
    if (path === '/users') { const c = await C('users'), us = await db.all('SELECT * FROM users ORDER BY id DESC'), dom = panelDomain(s, url.hostname); for (const u of us) { if (!u.wp_secret) { u.wp_secret = newSecret(); await db.run('UPDATE users SET wp_secret=? WHERE id=?', u.wp_secret, u.id); } u.tg = WPX.telegramLink(u.wp_secret, dom); } return page(c, UI.users(c, us, s, await LOC.groups(db), url.searchParams)); }
    if (path === '/users/add' && method === 'POST') {
      const f = await form(); if ((await db.one('SELECT COUNT(*) c FROM users')).c >= parseInt(s.max_users, 10)) return redirect('/users', 'User limit reached. Raise it in Settings.');
      const days = parseFloat(f.get('days') || 0) || 0; await db.run('INSERT INTO users(name,uuid,limit_gb,expire,created,wp_secret) VALUES(?,?,?,?,?,?)', (f.get('name') || '').trim() || 'user', crypto.randomUUID(), parseFloat(f.get('limit') || 0) || 0, days ? Math.floor(now() + days * 86400) : 0, now(), newSecret());
      return redirect('/users', 'User created');
    }
    if ((m = path.match(/^\/users\/(\d+)\/(edit|group|delete|wpsecret)$/)) && method === 'POST') {
      const id = +m[1], f = await form(); dropCaches();
      if (m[2] === 'edit') {
        await db.run('UPDATE users SET name=?,limit_gb=?,enabled=? WHERE id=?', (f.get('name') || '').trim(), parseFloat(f.get('limit') || 0) || 0, f.has('enabled') ? 1 : 0, id);
        if (f.get('days') !== null && f.get('days') !== '') { const d = parseFloat(f.get('days')) || 0; await db.run('UPDATE users SET expire=? WHERE id=?', d ? Math.floor(now() + d * 86400) : 0, id); }
        if (f.has('reset')) await db.run('UPDATE users SET used=0 WHERE id=?', id); return redirect(`/users?o=${id}&p=edit`, 'User saved');
      }
      if (m[2] === 'wpsecret') { await db.run('UPDATE users SET wp_secret=? WHERE id=?', newSecret(), id); return redirect(`/users?o=${id}&p=edit`, 'New Telegram Web Proxy secret made · the old link stops working'); }
      if (m[2] === 'group') { const g = await db.one('SELECT * FROM grps WHERE id=?', parseInt(f.get('g') || 0, 10) || 0); await db.run('UPDATE users SET grp_id=? WHERE id=?', g ? g.id : 0, id); return redirect(`/users?o=${id}&p=loc`, g ? `Traffic now exits through ${g.name}` : 'Traffic now exits directly from the Worker'); }
      await db.run('DELETE FROM users WHERE id=?', id); return redirect('/users', 'User deleted');
    }

    // ---- locations ----
    if (path === '/locations') { const c = await C('locations'); return page(c, UI.locations(c, await LOC.groups(db))); }
    if (path === '/locations/add' && method === 'POST') {
      const f = await form(), h = (f.get('host') || '').trim(), p = (f.get('port') || '').trim();
      if (!LOC.valid(h, p)) return redirect('/locations', 'Enter a valid IP/host and port');
      if (await db.one('SELECT 1 x FROM proxies WHERE host=? AND port=?', h, +p)) return redirect('/locations', 'This IP is already in a group');
      const [, best] = await probeAll(connectFn, h, +p); if (!best) return redirect('/locations', 'No protocol connected. IP not added.');
      const g = (await LOC.geo(h, fetchFn)) || { cc: '', name: 'Other' }; await LOC.putProxy(db, h, +p, best.proto, best.ms, g); dropCaches();
      return redirect('/locations', `Added to ${g.name} · ${best.proto} ${best.ms}ms` + (g.cc ? '' : ' · country unknown (private IP or lookup failed)'));
    }
    if ((m = path.match(/^\/proxies\/(\d+)\/delete$/)) && method === 'POST') { const r = await db.one('SELECT grp_id FROM proxies WHERE id=?', +m[1]); if (r) { await db.run('DELETE FROM proxies WHERE id=?', +m[1]); await LOC.dropIfEmpty(db, r.grp_id); dropCaches(); } return redirect('/locations'); }
    if ((m = path.match(/^\/groups\/(\d+)\/delete$/)) && method === 'POST') { await db.run('DELETE FROM proxies WHERE grp_id=?', +m[1]); await LOC.dropIfEmpty(db, +m[1]); await db.run('DELETE FROM grps WHERE id=?', +m[1]); dropCaches(); return redirect('/locations'); }
    if (path === '/api/loc/start' && method === 'POST') { const r = await LOC.startJob(db, (await body(req)).kind === 'recover' ? 'recover' : 'auto', fetchFn); return r.error ? J({ ok: false, ...r }, 409) : J({ ok: true }); }
    if (path === '/api/loc/step' && method === 'POST') { dropCaches(); return J(await LOC.stepJob(db, connectFn, fetchFn)); }
    if (path === '/api/loc/stop' && method === 'POST') return J({ ok: true, ...(await LOC.stopJob(db)) });
    if (path === '/api/loc/status') return J(LOC.view(await LOC.getJob(db), +(url.searchParams.get('since') || 0)));

    // ---- clients ----
    if (path === '/clients') {
      const c = await C('clients'), us = await db.all('SELECT * FROM users ORDER BY id DESC'), [ips] = await whiteList(db, s);
      return page(c, UI.clients(c, us.map(x => { const su = c.suburl(x); return { x, sub: su, groups: clientGroups(su) }; }), url.searchParams.get('u') || '', ips.length, s.white_limit || '0'));
    }
    if ((m = path.match(/^\/clients\/(\d+)\/white$/)) && method === 'POST') { const f = await form(); await db.run('UPDATE users SET white=? WHERE id=?', f.has('on') ? 1 : 0, +m[1]); const u = await db.one('SELECT uuid FROM users WHERE id=?', +m[1]); return redirect(`/clients?u=${u ? u.uuid : ''}`); }

    // ---- test sites / fragment ----
    if (path === '/api/sites/next' && method === 'POST') {
      const L = sitesList(s), n = L.length, cur = (parseInt(s.site_rr || 0, 10) || 0) % n, w = Math.min(n, 3); await db.set('site_rr', (cur + w) % n);
      return J({ sites: Array.from({ length: w }, (_, i) => L[(cur + i) % n]), total: n, start: cur });
    }
    if (path === '/advanced') { const c = await C('advanced'); return page(c, UI.advanced(c, s, adv(s)[0], url.searchParams.get('o') || '')); }
    if (path === '/advanced/spoof' && method === 'POST') {
      const f = await form(), [sni, ip, port] = ['sni', 'ip', 'port'].map(k => (f.get(k) || '').trim());
      if ((sni && !/^[A-Za-z0-9.\-]{1,253}$/.test(sni)) || (ip && !/^[A-Za-z0-9.\-:]{1,253}$/.test(ip)) || (port && !(/^\d+$/.test(port) && +port <= 65535))) return redirect('/advanced?o=spoof', 'Invalid SNI, IP or port');
      await db.batch([['UPDATE settings SET v=? WHERE k=?', sni, 'spoof_sni'], ['UPDATE settings SET v=? WHERE k=?', ip, 'spoof_ip'], ['UPDATE settings SET v=? WHERE k=?', port, 'spoof_port']]);
      return redirect('/advanced?o=spoof', sni && ip ? 'Spoof saved · applied to VLESS configs' : 'Spoof is off (fill both SNI and IP to turn it on)');
    }
    if (path === '/advanced/ipv6' && method === 'POST') {
      const v = ((await form()).get('ip') || '').trim().replace(/^\[|\]$/g, ''); if (v && !/^[A-Za-z0-9.:\-]{1,253}$/.test(v)) return redirect('/advanced?o=ipv6', 'Invalid address');
      await db.set('ipv6', v); return redirect('/advanced?o=ipv6', v ? 'Address saved · used in all configs' : 'Address cleared · configs use the domain again');
    }
    if ((m = path.match(/^\/advanced\/toggle\/(ff|ech|frag)$/)) && method === 'POST') {
      const on = (await form()).has('on') ? '1' : '0'; await db.set(m[1] + '_on', on); if (m[1] === 'frag' && on === '1') await db.set('frag_prof', ''); return redirect('/advanced?o=' + m[1]);
    }
    if (path === '/advanced/ech' && method === 'POST') { const i = parseInt((await form()).get('e'), 10); if (i >= 0 && i < ECH.length) { await db.set('ech_i', i); return redirect('/advanced?o=ech', `ECH: ${ECH[i][0]} · applied to all configs`); } return redirect('/advanced?o=ech'); }
    if (path === '/advanced/fragment/save' && method === 'POST') {
      const d = await body(req), rtt = Math.max(0, parseFloat(d.rtt)), ok = Math.min(1, Math.max(0, parseFloat(d.ok))), jit = Math.max(0, parseFloat(d.jitter || 0)), n = Math.max(0, parseInt(d.n || 0, 10) || 0);
      if (!isFinite(rtt) || !isFinite(ok)) return J({ ok: false, error: 'Bad measurement' }, 400);
      const tier = tierOf(rtt, ok), net = d.net && typeof d.net === 'object' ? d.net : {}, sites = (d.sites || []).slice(0, 12).map(u => cleanSite(String(u))).filter(Boolean);
      const prof = { tier: tier in FRAG_TIERS ? tier : 'none', rtt: Math.round(rtt), ok: Math.round(ok * 100) / 100, jitter: Math.round(jit || 0), n, sites, ts: now(), net: Object.fromEntries(['type', 'downlink', 'rtt'].filter(k => net[k] != null).map(k => [k, String(net[k]).slice(0, 12)])), verified: null };
      await db.set('frag_prof', JSON.stringify(prof)); return J({ ok: true, tier, profile: prof });
    }
    if (path === '/api/fragment/test' && method === 'POST') {
      const pr = fragProf(s); if (!pr) return J({ ok: false, error: 'Nothing measured yet' }, 400);
      const first = await db.one('SELECT uuid FROM users WHERE enabled=1 LIMIT 1'), uid = first ? first.uuid : crypto.randomUUID(), on = protos(s);
      return J({ ok: true, results: ALL.map(p => p === 'vmess' ? { proto: p, skip: true, text: 'no fragment field in vmess links' } : on.includes(p) ? { proto: p, path: `/ws/${p}/${uid}` } : { proto: p, skip: true, text: 'needs an upstream relay' }) });
    }
    if (path === '/api/fragment/verdict' && method === 'POST') {
      const d = await body(req), pr = fragProf(s); if (!pr) return J({ ok: false }, 400); const bad = (d.bad || []).filter(x => ALL.includes(x));
      pr.bad = bad; pr.verified = d.verified === null ? null : !bad.length; pr.verified_ts = now(); await db.set('frag_prof', JSON.stringify(pr)); return J({ ok: true });
    }

    // ---- settings ----
    if (path === '/settings') {
      const c = await C('settings'), rv = await RL.active(db), [d, , lbl] = await cfgDom(db, s, url.hostname), src = lbl === 'Direct' ? 'panel' : lbl === 'Custom' ? 'custom' : s.cfg_src;
      c.settings = { sites: sitesList(s), defaultPw: await checkPw(s.pw, 'admin'), detected: url.hostname, relays: rv, panelDom: panelDomain(s, url.hostname), cfgSrc: src, cfgLabel: src === 'panel' ? 'panel' : d, upd: updInfo(env, s) };
      return page(c, UI.settings(c, s, url.searchParams.get('o') || ''));
    }
    if (path === '/settings/cfgdomain' && method === 'POST') {
      const fd = await req.formData(), pick = String(fd.get('pick') || '');
      if (pick === 'panel') { await db.set('cfg_src', 'panel'); return redirect('/settings', 'Configs use the panel domain: ' + panelDomain(s, url.hostname)); }
      if (pick.startsWith('relay:')) { const r = await RL.row(db, pick.slice(6)); if (r.domain) { await db.set('cfg_src', pick); return redirect('/settings', 'Configs use ' + r.domain); } return redirect('/settings'); }
      if (pick === 'custom') {
        const v = String(fd.get('custom') || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/\/+$/, '');
        if (!/^[a-z0-9.\-]{1,253}(:\d{1,5})?$/.test(v)) return redirect('/settings', 'Enter a domain like sub.example.com or sub.example.com:8443');
        await db.batch([['UPDATE settings SET v=? WHERE k=?', v, 'cfg_custom'], ['UPDATE settings SET v=? WHERE k=?', 'custom', 'cfg_src']]); return redirect('/settings', 'Configs use ' + v);
      }
      return redirect('/settings');
    }
    if (path === '/settings/cf' && method === 'POST') {
      const f = await form(), tok = String(f.get('cf_token') || '').trim(), acc = String(f.get('cf_account') || '').trim(), nm = String(f.get('cf_worker') || '').trim() || 'xr-panel';
      if (acc && !/^[0-9a-f]{32}$/i.test(acc)) return redirect('/settings?o=update', 'Account ID is 32 letters and digits (Cloudflare dashboard -> Workers & Pages -> right column)');
      if (!/^[A-Za-z0-9_-]{1,63}$/.test(nm)) return redirect('/settings?o=update', 'Worker name: letters, digits, - and _ only');
      if (tok && !/^[A-Za-z0-9_-]{20,200}$/.test(tok)) return redirect('/settings?o=update', 'That does not look like a Cloudflare API token');
      await db.batch([['UPDATE settings SET v=? WHERE k=?', acc, 'cf_account'], ['UPDATE settings SET v=? WHERE k=?', nm, 'cf_worker']]);
      if (tok) await db.set('cf_token', tok); else if (f.has('cf_clear')) await db.set('cf_token', '');
      return redirect('/settings?o=update', 'Cloudflare access saved');
    }
    if (path === '/api/tg/test' && method === 'POST') return J({ results: await WPX.testDataCenters(connectFn) });
    if (path === '/settings/password' && method === 'POST') {
      const f = await form(); if (!(await checkPw(s.pw, f.get('old') || ''))) return redirect('/settings', 'Current password is wrong');
      if ((f.get('new') || '').length < 4) return redirect('/settings', 'New password needs at least 4 characters'); await db.set('pw', await hashPw(f.get('new'))); return redirect('/settings', 'Password changed');
    }
    if (path === '/settings/save' && method === 'POST') {
      const f = await form(); dropCaches();
      for (const k of ['domain', 'tls_port', 'max_users', 'upstream']) if (f.get(k) !== null) { let v = String(f.get(k)).trim(); if (k === 'tls_port' && !(/^\d+$/.test(v) && +v >= 1 && +v <= 65535)) continue; if (k === 'upstream') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); if (k === 'domain') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); await db.set(k, v); }
      if (f.get('white_limit') !== null) { const v = String(f.get('white_limit')).trim(); await db.set('white_limit', /^\d+$/.test(v) ? Math.min(+v, 200) : 10); await db.set('white_sni', f.has('white_sni') ? '1' : '0'); }
      return redirect('/settings', 'Settings saved');
    }
    if (path === '/settings/sites' && method === 'POST') {
      const f = await form(); let L, msg;
      if (f.has('reset')) { L = [...DEFAULT_SITES]; msg = `Test sites reset to the ${L.length} defaults`; }
      else { L = []; for (const u of f.all('site').slice(0, 40)) { const c = cleanSite(u); if (c && !L.includes(c)) L.push(c); } if (!L.length) return redirect('/settings?o=sites', 'Keep at least one valid site (like https://www.google.com/generate_204)'); msg = `Saved ${L.length} test site${L.length === 1 ? '' : 's'}`; }
      await db.batch([['UPDATE settings SET v=? WHERE k=?', JSON.stringify(L), 'test_sites'], ['UPDATE settings SET v=? WHERE k=?', '0', 'site_rr']]); return redirect('/settings?o=sites', msg);
    }

    // ---- network / WARP / MASQUE ----
    if (path === '/network') { const cnt = {}; for (const k of KINDS) cnt[k] = (await db.one('SELECT COUNT(*) c FROM scan_ips WHERE kind=?', k)).c; const c = await C('network'); return page(c, UI.network(c, s, cnt)); }
    if (path === '/api/net/list') { const k = url.searchParams.get('kind'); if (!KINDS.includes(k)) return J({}, 400); return J(await db.all('SELECT id,host,port,tls,ms,via,ts FROM scan_ips WHERE kind=? ORDER BY ms ASC, id ASC LIMIT 500', k)); }
    if (path === '/api/net/save' && method === 'POST') {
      const d = await body(req), k = d.kind; if (!KINDS.includes(k)) return J({}, 400); let n = 0;
      if (k === 'masque') { let mj = {}; try { mj = JSON.parse(s.masque || '{}'); } catch { } if (!mj.private_key) return J({ saved: 0, error: 'Register Masque first' }, 403); }
      const stmts = [];
      for (const x of (d.items || []).slice(0, 2000)) {
        const h = String(x.host || '').trim().toLowerCase().replace(/^\[|\]$/g, ''), p = parseInt(x.port || 0, 10), ms = Math.max(1, Math.round(parseFloat(x.ms))), tls = x.tls === false || x.tls === 0 ? 0 : 1;
        const okHost = k === 'sni' ? /^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$/.test(h) && h.includes('.') : /^[\d.]+$/.test(h) || /^[0-9a-f:]+$/.test(h) && h.includes(':');
        if (!okHost || !(p >= 0 && p <= 65535) || !isFinite(ms)) continue;
        stmts.push(['INSERT INTO scan_ips(kind,host,port,tls,ms,via,ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,host,port,tls) DO UPDATE SET ms=excluded.ms,via=excluded.via,ts=excluded.ts', k, h, p, tls, ms, String(x.via || '').slice(0, 12), now()]); n++;
      }
      for (let i = 0; i < stmts.length; i += 50) await db.batch(stmts.slice(i, i + 50)); return J({ saved: n });
    }
    if (path === '/api/net/delete' && method === 'POST') { const d = await body(req); if (!KINDS.includes(d.kind)) return J({}, 400); if (d.all) await db.run('DELETE FROM scan_ips WHERE kind=?', d.kind); else await db.run('DELETE FROM scan_ips WHERE kind=? AND id=?', d.kind, parseInt(d.id || 0, 10)); return J({ ok: true }); }
    const sj = k => { try { return JSON.parse(s[k] || 'null') || {}; } catch { return {}; } };
    if (path === '/api/warp') return J(sj('warp')); if (path === '/api/masque') return J(sj('masque'));
    if ((m = path.match(/^\/api\/(warp|masque)\/register$/)) && method === 'POST') {
      try { const v = m[1] === 'warp' ? await WP.registerWireguard(fetchFn) : await WP.registerMasque(fetchFn); await db.set(m[1], JSON.stringify(v)); return J({ ok: true, ...v }); }
      catch (e) { return J({ ok: false, error: e.message }, 502); }
    }
    if (path === '/api/fetch' && method === 'POST') return fetchSub(await body(req));
    if (path === '/convert') { const c = await C('convert'); return page(c, UI.convert(c)); }

    // ---- relays ----
    if (path === '/relays') { const t = await panelTarget(db, s, url), c = await C('relays'); return page(c, UI.relays(c, await RL.allViews(db), url.searchParams.get('o') || '', t ? `${t[0]}:${t[1]}` : '', !!t)); }
    if ((m = path.match(/^\/relays\/(vercel|netlify|railway)\/(deploy|remove)$/)) && method === 'POST') {
      const p = m[1];
      if (m[2] === 'deploy') { const t = await panelTarget(db, s, url); if (!t) return redirect(`/relays?o=${p}`, `Set your public panel domain in Settings first (now: ${panelDomain(s, url.hostname)}).`); const e = await RL.startDeploy(db, p, ((await form()).get('token') || '').trim(), t, fetchFn); return e ? redirect(`/relays?o=${p}`, e) : redirect(`/relays?o=${p}`); }
      const e = await RL.remove(db, p, fetchFn); if (e) return redirect(`/relays?o=${p}`, 'Could not remove: ' + e);
      if (s.cfg_src === 'relay:' + p) await db.set('cfg_src', 'panel'); return redirect(`/relays?o=${p}`, 'Relay removed');
    }
    if ((m = path.match(/^\/api\/relays\/(vercel|netlify|railway)(\/ping)?$/))) {
      const p = m[1]; if (m[2]) return method === 'POST' ? J({ ping: await RL.doPing(db, p, fetchFn) }) : J({}, 405);
      const t = await panelTarget(db, s, url); if (t) await RL.advance(db, p, t, fetchFn); return J(await RL.view(db, p));
    }
    return new Response('Not found', { status: 404 });
  }

  const updInfo = () => ({ version: VERSION, build: BUILD, repo: REPO, branch: BRANCH });

  async function fetchSub(d) {
    let u = String(d.url || '').trim();
    for (let i = 0; i < 4; i++) {
      let x; try { x = new URL(u); } catch { return J({ ok: false, error: 'Enter a full http(s) link' }, 400); }
      if (!['http:', 'https:'].includes(x.protocol) || !x.hostname) return J({ ok: false, error: 'Enter a full http(s) link' }, 400);
      const ip = await LOC.resolve(x.hostname, fetchFn); if (!ip || !LOC.isGlobal(ip)) return J({ ok: false, error: 'Only public hosts are allowed' }, 400);
      let r; try { r = await fetchFn(u, { headers: { 'User-Agent': 'v2rayN/7.0' }, redirect: 'manual' }); } catch (e) { return J({ ok: false, error: 'Could not fetch: ' + (e.message || e) }, 502); }
      if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.get('location')) { u = new URL(r.headers.get('location'), u).href; continue; }
      if (!r.ok) return J({ ok: false, error: 'The server answered HTTP ' + r.status }, 502);
      return J({ ok: true, text: (await r.text()).slice(0, 2_000_000) });
    }
    return J({ ok: false, error: 'Too many redirects' }, 502);
  }

  return { fetch: async (req, env, ctx) => { try { return await handle(req, env, ctx); } catch (e) { console.error(e); return new Response('Internal error: ' + (e.message || e), { status: 500 }); } } };
}


// ---- Cloudflare account usage (requests today) ----
let _cf = { t: 0, v: null };
async function cfUsage(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { ok: false, error: 'not_configured' };
  if (_cf.v && Date.now() - _cf.t < 60000) return _cf.v;
  const d = new Date(), from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const gq = async (field, must) => {
    try {
      const q = 'query($a:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$a}){x:' + field + '(limit:10000,filter:{datetime_geq:$f,datetime_leq:$t}){sum{requests}}}}}';
      const r = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: 'Bearer ' + env.CF_API_TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ query: q, variables: { a: env.CF_ACCOUNT_ID, f: from.toISOString(), t: d.toISOString() } }) });
      const j = await r.json();
      if (j.errors && j.errors.length) throw new Error(j.errors[0].message);
      return (((j.data || {}).viewer || {}).accounts || [{}])[0].x.reduce((n, x) => n + ((x.sum || {}).requests || 0), 0);
    } catch (e) { if (must) throw e; return 0; }
  };
  let v;
  try {
    const used = (await gq('workersInvocationsAdaptive', true)) + (await gq('pagesFunctionsInvocationsAdaptiveGroups', false)), limit = Number(env.CF_REQ_LIMIT) || 0;
    v = { ok: true, used, limit, left: limit ? Math.max(0, limit - used) : null, reset: from.getTime() + 86400000 };
  } catch (e) { return { ok: false, error: String(e.message || e) }; }
  _cf = { t: Date.now(), v };
  return v;
}

const __DEFAULT__ = makeApp();

  return { makeApp, default: __DEFAULT__ };
})();

const __mod_index = (() => {
  const { DB, init, state, fmt, GB, now, DEFAULTS, DEFAULT_SITES, newSecret } = __mod_db;
  const { hashPw, checkPw, makeSession, validSession, cookies, cookie } = __mod_auth;
  const { links, cfgDom, whiteList, cleanSite, sitesList, fragProf, tierOf, FRAG_TIERS, ECH, adv, protos, NATIVE, ALL, panelDomain } = __mod_links;
  const UI = __mod_ui;
  const LOC = __mod_loc;
  const WP = __mod_warp;
  const RL = __mod_relays;
  const { probeAll } = __mod_proxy;
  const { b64 } = __mod_util;
  const { Meter, dialer, serveNative, serveUpstream, WS_PATH, earlyData } = __mod_relay;
  const WPX = __mod_webproxy;
  const { STATIC } = __mod_static;
  const { VERSION, BUILD, REPO, BRANCH } = __mod_version;
  // --- index.js ---
// xr PANEL for Cloudflare Pages + D1. No Xray: VLESS / VMess / Shadowsocks / Trojan are terminated in the Pages
// Function and relayed over TCP sockets; D1 holds users, settings and every other table.

const CLIENTS = [['iOS', [['Streisand', 'https://apps.apple.com/app/streisand/id6450534064', 'streisand://import/{u}'], ['V2Box', 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690', 'v2box://install-sub?url={u}&name=VPN'], ['Shadowrocket', 'https://apps.apple.com/app/shadowrocket/id932747118', 'shadowrocket://add/sub://{b}']]],
  ['Android', [['v2rayNG', 'https://github.com/2dust/v2rayNG/releases', 'v2rayng://install-sub?url={u}&name=VPN'], ['Hiddify', 'https://github.com/hiddify/hiddify-app/releases', 'hiddify://import/{u}'], ['NekoBox', 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases', null]]]];
const clientGroups = su => CLIENTS.map(([g, a]) => [g, a.map(([n, d, i]) => [n, d, i ? i.replace('{u}', encodeURIComponent(su)).replace('{b}', b64(su)) : null])]);
const KINDS = ['ip', 'sni', 'warp', 'masque'];
const NOFLAG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 3"><rect width="4" height="3" fill="#3a3a4a"/><path d="M1 .5v2M1 .5h1.7l-.4.5.4.5H1" fill="#8c8ca0"/></svg>';
const MARK = RL.MARK;
const noDb = () => new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>xr PANEL · D1 missing</title><body style="font:16px system-ui;max-width:640px;margin:12vh auto;padding:0 20px;line-height:1.6"><h2>xr PANEL is running, but its D1 database is not attached</h2><p>The Pages project needs a D1 binding named <b>DB</b>.</p><p>Cloudflare dashboard → Workers &amp; Pages → this Pages project → Settings → Bindings → Add → D1 database → variable name <b>DB</b> → pick the database → Redeploy.</p><p dir="rtl">پنل بالا آمده ولی D1 به آن وصل نیست. در Cloudflare: Workers &amp; Pages ← همین پروژه Pages ← Settings ← Bindings ← Add ← D1 database ← نام متغیر <b>DB</b> ← دیتابیس را انتخاب کنید ← Redeploy.</p>', { status: 503, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });

const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const HTML = (h, extra = {}) => new Response(String(h), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra } });
const body = async req => { try { return await req.json(); } catch { return {}; } };

function makeApp({ connectFn = connect, fetchFn = (...a) => fetch(...a), pair = () => new WebSocketPair(), wsResponse = (ws, headers) => new Response(null, { status: 101, webSocket: ws, headers }) } = {}) {
  const userCache = new Map();
  // Web-proxy lookups read the account fresh (they happen once per connection, not per packet), so a disabled, expired
  // or over-limit user is refused at once. Only the list used to match the bridge capability is cached (15 s).
  const wpRows = { t: 0, rows: [] };
  const dropCaches = () => { userCache.clear(); wpRows.t = 0; };
  const wpReg = db => ({
    list: async () => { if (Date.now() - wpRows.t > 15000) { wpRows.rows = await db.all("SELECT id,wp_secret FROM users WHERE wp_secret!=''"); wpRows.t = Date.now(); } return wpRows.rows; },
    byId: async id => id > 0 ? db.one('SELECT * FROM users WHERE id=?', id) : null,
    bySecret: async sec => /^[0-9a-f]{32}$/.test(sec) ? db.one('SELECT * FROM users WHERE wp_secret=?', sec) : null,
  });
  const hostOf = url => url.hostname;

  async function ctxFor(db, req, url, extra = {}) {
    const flashes = []; const ck = cookies(req); if (ck.flash) { try { flashes.push(...JSON.parse(ck.flash)); } catch { } }
    const s = extra.s || await db.S();
    const base = (s.domain || '').trim() && s.domain.trim() !== 'example.com' ? `https://${s.domain.trim()}` : `${url.protocol}//${url.host}`;
    return { s, flashes, chrome: extra.chrome !== false, endpoint: extra.endpoint, suburl: u => `${base}/sub/${u.uuid}`, host: hostOf(url), clearFlash: flashes.length > 0 };
  }
  const page = (c, h, extra) => HTML(h, c.clearFlash ? { 'set-cookie': cookie('flash', '', { max: 0 }), ...extra } : extra);
  const redirect = (to, ...msgs) => { const h = new Headers({ Location: to }); if (msgs.length) h.append('set-cookie', cookie('flash', JSON.stringify(msgs), { max: 30 })); return new Response(null, { status: 302, headers: h }); };

  async function status(db, s) {
    const us = await db.all('SELECT * FROM users'); const act = us.filter(u => state(u) === 'active').length, used = us.reduce((a, u) => a + (u.used || 0), 0), quota = us.reduce((a, u) => a + (u.limit_gb || 0) * GB, 0);
    const g = (await db.one('SELECT COUNT(*) c FROM grps')).c, p = (await db.one('SELECT COUNT(*) c FROM proxies')).c, ips = (await db.one("SELECT COUNT(*) c FROM scan_ips WHERE kind='ip'")).c;
    const rl = (await db.one("SELECT COUNT(*) c FROM relays WHERE domain!='' AND domain IS NOT NULL")).c, fp = s.frag_on === '1' ? fragProf(s) : null;
    return { users: us.length, active: act, ap: us.length ? Math.round(act / us.length * 100) : 0, traffic: fmt(used), tp: quota ? Math.min(100, Math.round(used / quota * 100)) : 0, mode: (s.upstream || '').trim() ? 'Upstream' : 'Built-in', groups: g, proxies: p, ips, relays: rl, frag: fp ? fp.tier : (s.frag_on === '1' ? 'measuring' : 'off') };
  }

  async function panelTarget(db, s, url) {
    const h = panelDomain(s, url.hostname), p = /^\d+$/.test(s.tls_port) ? +s.tls_port : 443;
    const ok = /^[\d.]+$/.test(h) ? LOC.isGlobal(h) : (h !== 'localhost' && h.includes('.')); return ok ? [h, p] : null;
  }

  // ---------------- WebSocket relay ----------------
  async function wsRoute(req, env, ctx, m) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    const proto = m[1], uid = m[2].toLowerCase(), db = new DB(env); await init(env, hashPw);
    let hit = userCache.get(uid); if (!hit || Date.now() - hit.t > 15000) { hit = { t: Date.now(), u: await db.one('SELECT * FROM users WHERE uuid=?', uid), s: await db.S() }; userCache.set(uid, hit); }
    const { u, s } = hit; if (!u || state(u) !== 'active') return new Response('Forbidden', { status: 403 });
    const up = (s.upstream || '').trim();
    const [client, server] = Object.values(pair()); server.accept(); const ph = req.headers.get('Sec-WebSocket-Protocol') || '';
    const meter = new Meter(db, u, { wait: p => ctx.waitUntil(p), onDead: () => userCache.delete(uid) });
    if (up) ctx.waitUntil(serveUpstream(server, { upstream: up, path: `/ws/${proto}/${uid}`, protocolHeader: ph, meter, fetchFn }));
    else serveNative(server, { proto, user: u, dial: await dialer(db, connectFn, u), meter, ctx, early: earlyData(ph) });
    return wsResponse(client, ph ? { 'Sec-WebSocket-Protocol': ph } : {});
  }

  // ---------------- main ----------------
  async function handle(req, env, ctx) {
    const url = new URL(req.url), path = url.pathname, method = req.method;
    if (!(env && env.DB) && !path.startsWith('/static/') && path !== '/relay-check' && path !== '/healthz') return noDb();
    const wm = path.match(WS_PATH); if (wm) return wsRoute(req, env, ctx, wm);
    if (path.startsWith('/static/')) {
      const f = Object.hasOwn(STATIC, path.slice(8)) ? STATIC[path.slice(8)] : null; if (!f || !['GET', 'HEAD'].includes(method)) return new Response('Not found', { status: 404 });
      return new Response(method === 'HEAD' ? null : f[1], { headers: { 'content-type': f[0], 'cache-control': 'public, max-age=86400', 'x-content-type-options': 'nosniff' } });
    }
    if (path === '/relay-check') return new Response(MARK, { headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
    await init(env, hashPw); const db = new DB(env); let s = await db.S();

    if (path === '/login') {
      if (method === 'POST') {
        const f = await req.formData();
        if (f.get('user') === 'admin' && await checkPw(s.pw, String(f.get('pw') || ''))) return new Response(null, { status: 302, headers: { Location: '/', 'set-cookie': cookie('xr', await makeSession(s.secret), { max: 7 * 86400 }) } });
        await new Promise(r => setTimeout(r, 800)); return redirect('/login', 'Wrong username or password');
      }
      const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.login(c));
    }
    if (path === '/logout') return new Response(null, { status: 302, headers: { Location: '/login', 'set-cookie': cookie('xr', '', { max: 0 }) } });

    // public subscription
    let m;
    if ((m = path.match(/^\/sub\/([0-9a-fA-F-]{36})$/))) {
      const u = await db.one('SELECT * FROM users WHERE uuid=?', m[1].toLowerCase()); if (!u) return new Response('Not found', { status: 404 });
      const st = state(u), L = st === 'active' ? await links(db, u, s, url.hostname) : [];
      if (!u.wp_secret) { u.wp_secret = newSecret(); await db.run('UPDATE users SET wp_secret=? WHERE id=?', u.wp_secret, u.id); }
      if ((req.headers.get('Accept') || '').includes('text/html') && !url.searchParams.get('raw')) { const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.sub(c, u, st, L, c.suburl(u), clientGroups(c.suburl(u)), st === 'active' ? WPX.telegramLink(u.wp_secret, panelDomain(s, url.hostname)) : '')); }
      return new Response(b64(L.map(x => x[2]).join('\n')), { headers: { 'content-type': 'text/plain', 'subscription-userinfo': `upload=0; download=${u.used}; total=${Math.floor(u.limit_gb * GB)}; expire=${u.expire}`, 'profile-update-interval': '1', 'profile-title': 'VPN' } });
    }

    // ---- native Telegram Web Proxy (MTProto over WebSocket), one secret per user — public, no admin cookie ----
    if (path === '/healthz') return J({ ok: true });
    if (path === '/api/v1/session') return WPX.handleSession(req, s, url.hostname, wpReg(db));
    if (path === '/api/v1/ws') return WPX.handleWs(req, s, url.hostname, env, wpReg(db), ctx, connectFn);
    if (path === '/' && url.search) { const r = await WPX.handleRoot(url, s, url.hostname, wpReg(db)); if (r) return r; }

    // everything below needs a session
    if (!(await validSession(s.secret, cookies(req).xr))) return method === 'GET' && !path.startsWith('/api/') ? redirect('/login') : (path.startsWith('/api/') ? J({ error: 'login required' }, 401) : redirect('/login'));
    const C = (endpoint, extra = {}) => ctxFor(db, req, url, { s, endpoint, ...extra });
    const form = async () => { let f; try { f = await req.formData(); } catch { f = new FormData(); } return { get: k => f.get(k), all: k => f.getAll(k), has: k => f.has(k) }; };

    if (path === '/' ) { const c = await C('home'); return page(c, UI.home(c, await status(db, s))); }
    if (path === '/api/status') return J(await status(db, s));
    if (path === '/api/cf') return J(await cfUsage(env));

    if ((m = path.match(/^\/flag\/([a-z]{2})\.svg$/))) {
      const cache = typeof caches !== 'undefined' ? caches.default : null, key = new Request(`https://flags.invalid/${m[1]}.svg`);
      const hit = cache && await cache.match(key); if (hit) return hit;
      for (const src of [`https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.2.3/flags/4x3/${m[1]}.svg`, `https://flagcdn.com/${m[1]}.svg`]) {
        try { const r = await fetchFn(src); const t = r.ok ? await r.text() : ''; if (/<svg/i.test(t) && !/<script|onload|foreignobject/i.test(t)) { const res = new Response(t, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'private, max-age=86400' } }); if (cache) ctx.waitUntil(cache.put(key, res.clone())); return res; } } catch { }
      }
      return new Response(NOFLAG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' } });
    }

    if (path === '/api/probe' && method === 'POST') {
      const d = await body(req), h = String(d.host || '').trim(), p = String(d.port || '').trim(); if (!LOC.valid(h, p)) return J({ error: 'Enter a valid IP/host and port' }, 400);
      const [[res, best], g] = await Promise.all([probeAll(connectFn, h, +p), LOC.geo(h, fetchFn)]); return J({ results: res, best, geo: g });
    }

    // ---- users ----
    if (path === '/users') { const c = await C('users'), us = await db.all('SELECT * FROM users ORDER BY id DESC'), dom = panelDomain(s, url.hostname); for (const u of us) { if (!u.wp_secret) { u.wp_secret = newSecret(); await db.run('UPDATE users SET wp_secret=? WHERE id=?', u.wp_secret, u.id); } u.tg = WPX.telegramLink(u.wp_secret, dom); } return page(c, UI.users(c, us, s, await LOC.groups(db), url.searchParams)); }
    if (path === '/users/add' && method === 'POST') {
      const f = await form(); if ((await db.one('SELECT COUNT(*) c FROM users')).c >= parseInt(s.max_users, 10)) return redirect('/users', 'User limit reached. Raise it in Settings.');
      const days = parseFloat(f.get('days') || 0) || 0; await db.run('INSERT INTO users(name,uuid,limit_gb,expire,created,wp_secret) VALUES(?,?,?,?,?,?)', (f.get('name') || '').trim() || 'user', crypto.randomUUID(), parseFloat(f.get('limit') || 0) || 0, days ? Math.floor(now() + days * 86400) : 0, now(), newSecret());
      return redirect('/users', 'User created');
    }
    if ((m = path.match(/^\/users\/(\d+)\/(edit|group|delete|wpsecret)$/)) && method === 'POST') {
      const id = +m[1], f = await form(); dropCaches();
      if (m[2] === 'edit') {
        await db.run('UPDATE users SET name=?,limit_gb=?,enabled=? WHERE id=?', (f.get('name') || '').trim(), parseFloat(f.get('limit') || 0) || 0, f.has('enabled') ? 1 : 0, id);
        if (f.get('days') !== null && f.get('days') !== '') { const d = parseFloat(f.get('days')) || 0; await db.run('UPDATE users SET expire=? WHERE id=?', d ? Math.floor(now() + d * 86400) : 0, id); }
        if (f.has('reset')) await db.run('UPDATE users SET used=0 WHERE id=?', id); return redirect(`/users?o=${id}&p=edit`, 'User saved');
      }
      if (m[2] === 'wpsecret') { await db.run('UPDATE users SET wp_secret=? WHERE id=?', newSecret(), id); return redirect(`/users?o=${id}&p=edit`, 'New Telegram Web Proxy secret made · the old link stops working'); }
      if (m[2] === 'group') { const g = await db.one('SELECT * FROM grps WHERE id=?', parseInt(f.get('g') || 0, 10) || 0); await db.run('UPDATE users SET grp_id=? WHERE id=?', g ? g.id : 0, id); return redirect(`/users?o=${id}&p=loc`, g ? `Traffic now exits through ${g.name}` : 'Traffic now exits directly from the Worker'); }
      await db.run('DELETE FROM users WHERE id=?', id); return redirect('/users', 'User deleted');
    }

    // ---- locations ----
    if (path === '/locations') { const c = await C('locations'); return page(c, UI.locations(c, await LOC.groups(db))); }
    if (path === '/locations/add' && method === 'POST') {
      const f = await form(), h = (f.get('host') || '').trim(), p = (f.get('port') || '').trim();
      if (!LOC.valid(h, p)) return redirect('/locations', 'Enter a valid IP/host and port');
      if (await db.one('SELECT 1 x FROM proxies WHERE host=? AND port=?', h, +p)) return redirect('/locations', 'This IP is already in a group');
      const [, best] = await probeAll(connectFn, h, +p); if (!best) return redirect('/locations', 'No protocol connected. IP not added.');
      const g = (await LOC.geo(h, fetchFn)) || { cc: '', name: 'Other' }; await LOC.putProxy(db, h, +p, best.proto, best.ms, g); dropCaches();
      return redirect('/locations', `Added to ${g.name} · ${best.proto} ${best.ms}ms` + (g.cc ? '' : ' · country unknown (private IP or lookup failed)'));
    }
    if ((m = path.match(/^\/proxies\/(\d+)\/delete$/)) && method === 'POST') { const r = await db.one('SELECT grp_id FROM proxies WHERE id=?', +m[1]); if (r) { await db.run('DELETE FROM proxies WHERE id=?', +m[1]); await LOC.dropIfEmpty(db, r.grp_id); dropCaches(); } return redirect('/locations'); }
    if ((m = path.match(/^\/groups\/(\d+)\/delete$/)) && method === 'POST') { await db.run('DELETE FROM proxies WHERE grp_id=?', +m[1]); await LOC.dropIfEmpty(db, +m[1]); await db.run('DELETE FROM grps WHERE id=?', +m[1]); dropCaches(); return redirect('/locations'); }
    if (path === '/api/loc/start' && method === 'POST') { const r = await LOC.startJob(db, (await body(req)).kind === 'recover' ? 'recover' : 'auto', fetchFn); return r.error ? J({ ok: false, ...r }, 409) : J({ ok: true }); }
    if (path === '/api/loc/step' && method === 'POST') { dropCaches(); return J(await LOC.stepJob(db, connectFn, fetchFn)); }
    if (path === '/api/loc/stop' && method === 'POST') return J({ ok: true, ...(await LOC.stopJob(db)) });
    if (path === '/api/loc/status') return J(LOC.view(await LOC.getJob(db), +(url.searchParams.get('since') || 0)));

    // ---- clients ----
    if (path === '/clients') {
      const c = await C('clients'), us = await db.all('SELECT * FROM users ORDER BY id DESC'), [ips] = await whiteList(db, s);
      return page(c, UI.clients(c, us.map(x => { const su = c.suburl(x); return { x, sub: su, groups: clientGroups(su) }; }), url.searchParams.get('u') || '', ips.length, s.white_limit || '0'));
    }
    if ((m = path.match(/^\/clients\/(\d+)\/white$/)) && method === 'POST') { const f = await form(); await db.run('UPDATE users SET white=? WHERE id=?', f.has('on') ? 1 : 0, +m[1]); const u = await db.one('SELECT uuid FROM users WHERE id=?', +m[1]); return redirect(`/clients?u=${u ? u.uuid : ''}`); }

    // ---- test sites / fragment ----
    if (path === '/api/sites/next' && method === 'POST') {
      const L = sitesList(s), n = L.length, cur = (parseInt(s.site_rr || 0, 10) || 0) % n, w = Math.min(n, 3); await db.set('site_rr', (cur + w) % n);
      return J({ sites: Array.from({ length: w }, (_, i) => L[(cur + i) % n]), total: n, start: cur });
    }
    if (path === '/advanced') { const c = await C('advanced'); return page(c, UI.advanced(c, s, adv(s)[0], url.searchParams.get('o') || '')); }
    if (path === '/advanced/spoof' && method === 'POST') {
      const f = await form(), [sni, ip, port] = ['sni', 'ip', 'port'].map(k => (f.get(k) || '').trim());
      if ((sni && !/^[A-Za-z0-9.\-]{1,253}$/.test(sni)) || (ip && !/^[A-Za-z0-9.\-:]{1,253}$/.test(ip)) || (port && !(/^\d+$/.test(port) && +port <= 65535))) return redirect('/advanced?o=spoof', 'Invalid SNI, IP or port');
      await db.batch([['UPDATE settings SET v=? WHERE k=?', sni, 'spoof_sni'], ['UPDATE settings SET v=? WHERE k=?', ip, 'spoof_ip'], ['UPDATE settings SET v=? WHERE k=?', port, 'spoof_port']]);
      return redirect('/advanced?o=spoof', sni && ip ? 'Spoof saved · applied to VLESS configs' : 'Spoof is off (fill both SNI and IP to turn it on)');
    }
    if (path === '/advanced/ipv6' && method === 'POST') {
      const v = ((await form()).get('ip') || '').trim().replace(/^\[|\]$/g, ''); if (v && !/^[A-Za-z0-9.:\-]{1,253}$/.test(v)) return redirect('/advanced?o=ipv6', 'Invalid address');
      await db.set('ipv6', v); return redirect('/advanced?o=ipv6', v ? 'Address saved · used in all configs' : 'Address cleared · configs use the domain again');
    }
    if ((m = path.match(/^\/advanced\/toggle\/(ff|ech|frag)$/)) && method === 'POST') {
      const on = (await form()).has('on') ? '1' : '0'; await db.set(m[1] + '_on', on); if (m[1] === 'frag' && on === '1') await db.set('frag_prof', ''); return redirect('/advanced?o=' + m[1]);
    }
    if (path === '/advanced/ech' && method === 'POST') { const i = parseInt((await form()).get('e'), 10); if (i >= 0 && i < ECH.length) { await db.set('ech_i', i); return redirect('/advanced?o=ech', `ECH: ${ECH[i][0]} · applied to all configs`); } return redirect('/advanced?o=ech'); }
    if (path === '/advanced/fragment/save' && method === 'POST') {
      const d = await body(req), rtt = Math.max(0, parseFloat(d.rtt)), ok = Math.min(1, Math.max(0, parseFloat(d.ok))), jit = Math.max(0, parseFloat(d.jitter || 0)), n = Math.max(0, parseInt(d.n || 0, 10) || 0);
      if (!isFinite(rtt) || !isFinite(ok)) return J({ ok: false, error: 'Bad measurement' }, 400);
      const tier = tierOf(rtt, ok), net = d.net && typeof d.net === 'object' ? d.net : {}, sites = (d.sites || []).slice(0, 12).map(u => cleanSite(String(u))).filter(Boolean);
      const prof = { tier: tier in FRAG_TIERS ? tier : 'none', rtt: Math.round(rtt), ok: Math.round(ok * 100) / 100, jitter: Math.round(jit || 0), n, sites, ts: now(), net: Object.fromEntries(['type', 'downlink', 'rtt'].filter(k => net[k] != null).map(k => [k, String(net[k]).slice(0, 12)])), verified: null };
      await db.set('frag_prof', JSON.stringify(prof)); return J({ ok: true, tier, profile: prof });
    }
    if (path === '/api/fragment/test' && method === 'POST') {
      const pr = fragProf(s); if (!pr) return J({ ok: false, error: 'Nothing measured yet' }, 400);
      const first = await db.one('SELECT uuid FROM users WHERE enabled=1 LIMIT 1'), uid = first ? first.uuid : crypto.randomUUID(), on = protos(s);
      return J({ ok: true, results: ALL.map(p => p === 'vmess' ? { proto: p, skip: true, text: 'no fragment field in vmess links' } : on.includes(p) ? { proto: p, path: `/ws/${p}/${uid}` } : { proto: p, skip: true, text: 'needs an upstream relay' }) });
    }
    if (path === '/api/fragment/verdict' && method === 'POST') {
      const d = await body(req), pr = fragProf(s); if (!pr) return J({ ok: false }, 400); const bad = (d.bad || []).filter(x => ALL.includes(x));
      pr.bad = bad; pr.verified = d.verified === null ? null : !bad.length; pr.verified_ts = now(); await db.set('frag_prof', JSON.stringify(pr)); return J({ ok: true });
    }

    // ---- settings ----
    if (path === '/settings') {
      const c = await C('settings'), rv = await RL.active(db), [d, , lbl] = await cfgDom(db, s, url.hostname), src = lbl === 'Direct' ? 'panel' : lbl === 'Custom' ? 'custom' : s.cfg_src;
      c.settings = { sites: sitesList(s), defaultPw: await checkPw(s.pw, 'admin'), detected: url.hostname, relays: rv, panelDom: panelDomain(s, url.hostname), cfgSrc: src, cfgLabel: src === 'panel' ? 'panel' : d, upd: updInfo(env, s) };
      return page(c, UI.settings(c, s, url.searchParams.get('o') || ''));
    }
    if (path === '/settings/cfgdomain' && method === 'POST') {
      const fd = await req.formData(), pick = String(fd.get('pick') || '');
      if (pick === 'panel') { await db.set('cfg_src', 'panel'); return redirect('/settings', 'Configs use the panel domain: ' + panelDomain(s, url.hostname)); }
      if (pick.startsWith('relay:')) { const r = await RL.row(db, pick.slice(6)); if (r.domain) { await db.set('cfg_src', pick); return redirect('/settings', 'Configs use ' + r.domain); } return redirect('/settings'); }
      if (pick === 'custom') {
        const v = String(fd.get('custom') || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/\/+$/, '');
        if (!/^[a-z0-9.\-]{1,253}(:\d{1,5})?$/.test(v)) return redirect('/settings', 'Enter a domain like sub.example.com or sub.example.com:8443');
        await db.batch([['UPDATE settings SET v=? WHERE k=?', v, 'cfg_custom'], ['UPDATE settings SET v=? WHERE k=?', 'custom', 'cfg_src']]); return redirect('/settings', 'Configs use ' + v);
      }
      return redirect('/settings');
    }
    if (path === '/settings/cf' && method === 'POST') {
      const f = await form(), tok = String(f.get('cf_token') || '').trim(), acc = String(f.get('cf_account') || '').trim(), nm = String(f.get('cf_worker') || '').trim() || 'xr-panel';
      if (acc && !/^[0-9a-f]{32}$/i.test(acc)) return redirect('/settings?o=update', 'Account ID is 32 letters and digits (Cloudflare dashboard -> Workers & Pages -> right column)');
      if (!/^[A-Za-z0-9_-]{1,63}$/.test(nm)) return redirect('/settings?o=update', 'Worker name: letters, digits, - and _ only');
      if (tok && !/^[A-Za-z0-9_-]{20,200}$/.test(tok)) return redirect('/settings?o=update', 'That does not look like a Cloudflare API token');
      await db.batch([['UPDATE settings SET v=? WHERE k=?', acc, 'cf_account'], ['UPDATE settings SET v=? WHERE k=?', nm, 'cf_worker']]);
      if (tok) await db.set('cf_token', tok); else if (f.has('cf_clear')) await db.set('cf_token', '');
      return redirect('/settings?o=update', 'Cloudflare access saved');
    }
    if (path === '/api/tg/test' && method === 'POST') return J({ results: await WPX.testDataCenters(connectFn) });
    if (path === '/settings/password' && method === 'POST') {
      const f = await form(); if (!(await checkPw(s.pw, f.get('old') || ''))) return redirect('/settings', 'Current password is wrong');
      if ((f.get('new') || '').length < 4) return redirect('/settings', 'New password needs at least 4 characters'); await db.set('pw', await hashPw(f.get('new'))); return redirect('/settings', 'Password changed');
    }
    if (path === '/settings/save' && method === 'POST') {
      const f = await form(); dropCaches();
      for (const k of ['domain', 'tls_port', 'max_users', 'upstream']) if (f.get(k) !== null) { let v = String(f.get(k)).trim(); if (k === 'tls_port' && !(/^\d+$/.test(v) && +v >= 1 && +v <= 65535)) continue; if (k === 'upstream') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); if (k === 'domain') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); await db.set(k, v); }
      if (f.get('white_limit') !== null) { const v = String(f.get('white_limit')).trim(); await db.set('white_limit', /^\d+$/.test(v) ? Math.min(+v, 200) : 10); await db.set('white_sni', f.has('white_sni') ? '1' : '0'); }
      return redirect('/settings', 'Settings saved');
    }
    if (path === '/settings/sites' && method === 'POST') {
      const f = await form(); let L, msg;
      if (f.has('reset')) { L = [...DEFAULT_SITES]; msg = `Test sites reset to the ${L.length} defaults`; }
      else { L = []; for (const u of f.all('site').slice(0, 40)) { const c = cleanSite(u); if (c && !L.includes(c)) L.push(c); } if (!L.length) return redirect('/settings?o=sites', 'Keep at least one valid site (like https://www.google.com/generate_204)'); msg = `Saved ${L.length} test site${L.length === 1 ? '' : 's'}`; }
      await db.batch([['UPDATE settings SET v=? WHERE k=?', JSON.stringify(L), 'test_sites'], ['UPDATE settings SET v=? WHERE k=?', '0', 'site_rr']]); return redirect('/settings?o=sites', msg);
    }

    // ---- network / WARP / MASQUE ----
    if (path === '/network') { const cnt = {}; for (const k of KINDS) cnt[k] = (await db.one('SELECT COUNT(*) c FROM scan_ips WHERE kind=?', k)).c; const c = await C('network'); return page(c, UI.network(c, s, cnt)); }
    if (path === '/api/net/list') { const k = url.searchParams.get('kind'); if (!KINDS.includes(k)) return J({}, 400); return J(await db.all('SELECT id,host,port,tls,ms,via,ts FROM scan_ips WHERE kind=? ORDER BY ms ASC, id ASC LIMIT 500', k)); }
    if (path === '/api/net/save' && method === 'POST') {
      const d = await body(req), k = d.kind; if (!KINDS.includes(k)) return J({}, 400); let n = 0;
      if (k === 'masque') { let mj = {}; try { mj = JSON.parse(s.masque || '{}'); } catch { } if (!mj.private_key) return J({ saved: 0, error: 'Register Masque first' }, 403); }
      const stmts = [];
      for (const x of (d.items || []).slice(0, 2000)) {
        const h = String(x.host || '').trim().toLowerCase().replace(/^\[|\]$/g, ''), p = parseInt(x.port || 0, 10), ms = Math.max(1, Math.round(parseFloat(x.ms))), tls = x.tls === false || x.tls === 0 ? 0 : 1;
        const okHost = k === 'sni' ? /^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$/.test(h) && h.includes('.') : /^[\d.]+$/.test(h) || /^[0-9a-f:]+$/.test(h) && h.includes(':');
        if (!okHost || !(p >= 0 && p <= 65535) || !isFinite(ms)) continue;
        stmts.push(['INSERT INTO scan_ips(kind,host,port,tls,ms,via,ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,host,port,tls) DO UPDATE SET ms=excluded.ms,via=excluded.via,ts=excluded.ts', k, h, p, tls, ms, String(x.via || '').slice(0, 12), now()]); n++;
      }
      for (let i = 0; i < stmts.length; i += 50) await db.batch(stmts.slice(i, i + 50)); return J({ saved: n });
    }
    if (path === '/api/net/delete' && method === 'POST') { const d = await body(req); if (!KINDS.includes(d.kind)) return J({}, 400); if (d.all) await db.run('DELETE FROM scan_ips WHERE kind=?', d.kind); else await db.run('DELETE FROM scan_ips WHERE kind=? AND id=?', d.kind, parseInt(d.id || 0, 10)); return J({ ok: true }); }
    const sj = k => { try { return JSON.parse(s[k] || 'null') || {}; } catch { return {}; } };
    if (path === '/api/warp') return J(sj('warp')); if (path === '/api/masque') return J(sj('masque'));
    if ((m = path.match(/^\/api\/(warp|masque)\/register$/)) && method === 'POST') {
      try { const v = m[1] === 'warp' ? await WP.registerWireguard(fetchFn) : await WP.registerMasque(fetchFn); await db.set(m[1], JSON.stringify(v)); return J({ ok: true, ...v }); }
      catch (e) { return J({ ok: false, error: e.message }, 502); }
    }
    if (path === '/api/fetch' && method === 'POST') return fetchSub(await body(req));
    if (path === '/convert') { const c = await C('convert'); return page(c, UI.convert(c)); }

    // ---- relays ----
    if (path === '/relays') { const t = await panelTarget(db, s, url), c = await C('relays'); return page(c, UI.relays(c, await RL.allViews(db), url.searchParams.get('o') || '', t ? `${t[0]}:${t[1]}` : '', !!t)); }
    if ((m = path.match(/^\/relays\/(vercel|netlify|railway)\/(deploy|remove)$/)) && method === 'POST') {
      const p = m[1];
      if (m[2] === 'deploy') { const t = await panelTarget(db, s, url); if (!t) return redirect(`/relays?o=${p}`, `Set your public panel domain in Settings first (now: ${panelDomain(s, url.hostname)}).`); const e = await RL.startDeploy(db, p, ((await form()).get('token') || '').trim(), t, fetchFn); return e ? redirect(`/relays?o=${p}`, e) : redirect(`/relays?o=${p}`); }
      const e = await RL.remove(db, p, fetchFn); if (e) return redirect(`/relays?o=${p}`, 'Could not remove: ' + e);
      if (s.cfg_src === 'relay:' + p) await db.set('cfg_src', 'panel'); return redirect(`/relays?o=${p}`, 'Relay removed');
    }
    if ((m = path.match(/^\/api\/relays\/(vercel|netlify|railway)(\/ping)?$/))) {
      const p = m[1]; if (m[2]) return method === 'POST' ? J({ ping: await RL.doPing(db, p, fetchFn) }) : J({}, 405);
      const t = await panelTarget(db, s, url); if (t) await RL.advance(db, p, t, fetchFn); return J(await RL.view(db, p));
    }
    return new Response('Not found', { status: 404 });
  }

  const updInfo = () => ({ version: VERSION, build: BUILD, repo: REPO, branch: BRANCH });

  async function fetchSub(d) {
    let u = String(d.url || '').trim();
    for (let i = 0; i < 4; i++) {
      let x; try { x = new URL(u); } catch { return J({ ok: false, error: 'Enter a full http(s) link' }, 400); }
      if (!['http:', 'https:'].includes(x.protocol) || !x.hostname) return J({ ok: false, error: 'Enter a full http(s) link' }, 400);
      const ip = await LOC.resolve(x.hostname, fetchFn); if (!ip || !LOC.isGlobal(ip)) return J({ ok: false, error: 'Only public hosts are allowed' }, 400);
      let r; try { r = await fetchFn(u, { headers: { 'User-Agent': 'v2rayN/7.0' }, redirect: 'manual' }); } catch (e) { return J({ ok: false, error: 'Could not fetch: ' + (e.message || e) }, 502); }
      if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.get('location')) { u = new URL(r.headers.get('location'), u).href; continue; }
      if (!r.ok) return J({ ok: false, error: 'The server answered HTTP ' + r.status }, 502);
      return J({ ok: true, text: (await r.text()).slice(0, 2_000_000) });
    }
    return J({ ok: false, error: 'Too many redirects' }, 502);
  }

  return { fetch: async (req, env, ctx) => { try { return await handle(req, env, ctx); } catch (e) { console.error(e); return new Response('Internal error: ' + (e.message || e), { status: 500 }); } } };
}


// ---- Cloudflare account usage (requests today) ----
let _cf = { t: 0, v: null };
async function cfUsage(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { ok: false, error: 'not_configured' };
  if (_cf.v && Date.now() - _cf.t < 60000) return _cf.v;
  const d = new Date(), from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const gq = async (field, must) => {
    try {
      const q = 'query($a:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$a}){x:' + field + '(limit:10000,filter:{datetime_geq:$f,datetime_leq:$t}){sum{requests}}}}}';
      const r = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: 'Bearer ' + env.CF_API_TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ query: q, variables: { a: env.CF_ACCOUNT_ID, f: from.toISOString(), t: d.toISOString() } }) });
      const j = await r.json();
      if (j.errors && j.errors.length) throw new Error(j.errors[0].message);
      return (((j.data || {}).viewer || {}).accounts || [{}])[0].x.reduce((n, x) => n + ((x.sum || {}).requests || 0), 0);
    } catch (e) { if (must) throw e; return 0; }
  };
  let v;
  try {
    const used = (await gq('workersInvocationsAdaptive', true)) + (await gq('pagesFunctionsInvocationsAdaptiveGroups', false)), limit = Number(env.CF_REQ_LIMIT) || 0;
    v = { ok: true, used, limit, left: limit ? Math.max(0, limit - used) : null, reset: from.getTime() + 86400000 };
  } catch (e) { return { ok: false, error: String(e.message || e) }; }
  _cf = { t: Date.now(), v };
  return v;
}

const __DEFAULT__ = makeApp();

  return { makeApp, default: __DEFAULT__ };
})();

const app = __mod_index.default;

// Cloudflare Pages entry point.
export async function onRequest(context) {
  return app.fetch(context.request, context.env, context);
}
// Also works as a single-module Cloudflare Worker (default export).
export default { fetch: (request, env, ctx) => app.fetch(request, env, ctx) };
