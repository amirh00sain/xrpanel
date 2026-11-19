// The Xray replacement: VLESS, VMess, Shadowsocks and Trojan over WebSocket are all terminated here, and the bytes
// leave through the user's exit group (SOCKS5 / SOCKS4 / HTTP proxies) or directly. With an upstream set, any protocol
// is relayed unchanged to that server instead. Every connection is metered; volume, expiry and the enabled flag are enforced live.
import { direct, viaProxy, timeout } from './proxy.js';
import { state, now, GB } from './db.js';
import { sha224 as sha224Core } from './crypto.js';
import { te, td, toU8, cat, hex, uuidBytes, readAddr, dnsOverHttps } from './util.js';
import { serveVmess } from './vmess.js';
import { serveShadowsocks } from './shadowsocks.js';

export { toU8 };
export const sha224 = sha224Core;
export const trojanHash = uuid => hex(sha224(te.encode(uuid)));

// ---------- protocol headers ----------
/** -> {cmd, host, port, rest, reply} or null when the header is wrong / belongs to another user */
export function parseVless(b, uuid) {
  if (b.length < 24) return null; const id = uuidBytes(uuid);
  for (let i = 0; i < 16; i++) if (b[1 + i] !== id[i]) return null;
  const o = 18 + b[17]; const cmd = b[o], port = (b[o + 1] << 8) | b[o + 2], atyp = b[o + 3]; if (cmd !== 1 && cmd !== 2) return null;
  let host, i = o + 4;
  if (atyp === 2) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 3); if (!a) return null; [host, i] = a; }
  return { cmd, host, port, rest: b.slice(i), reply: Uint8Array.of(b[0], 0) };
}
export function parseTrojan(b, uuid) {
  if (b.length < 62) return null; if (new TextDecoder().decode(b.slice(0, 56)) !== trojanHash(uuid) || b[56] !== 13 || b[57] !== 10) return null;
  const cmd = b[58], atyp = b[59]; if (cmd !== 1) return null; let host, i = 60;
  if (atyp === 3) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 4, 3); if (!a) return null; [host, i] = a; }
  const port = (b[i] << 8) | b[i + 1]; return { cmd: 1, host, port, rest: b.slice(i + 4), reply: null };
}

// ---------- usage accounting + enforcement ----------
// Counts every byte of a session, writes it to KV in batches and kills the session the moment the account stops being
// active: volume is checked locally against what was left at the last write (so the cut is exact for one session and
// within a few KB across sessions), expiry by a timer that re-reads the account when it fires.
const FLUSH_BYTES = 512 * 1024, FLUSH_MS = 30000, MIN_FLUSH = 16 * 1024, TIMER_MAX = 2 ** 31 - 1;
const leftBytes = u => u.limit_gb ? Math.max(0, u.limit_gb * GB - (u.used || 0)) : Infinity;
export class Meter {
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
export async function dialer(db, connect, user) {
  const px = user.grp_id ? await db.all('SELECT host,port,proto FROM proxies WHERE grp_id=? ORDER BY ms LIMIT 4', user.grp_id) : [];
  return async (host, port) => {
    for (const p of px) { try { return await viaProxy(connect, p, host, port); } catch { } }
    if (px.length) throw new Error('every exit proxy of this group failed');
    return direct(connect, host, port);
  };
}

/** Serve one accepted WebSocket (`ws`) for a native user: dispatches on the protocol. */
export function serveNative(ws, opts) {
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
export async function serveUpstream(ws, { upstream, path, protocolHeader, meter, fetchFn = fetch }) {
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

export const WS_PATH = /^\/ws\/(?:[A-Za-z0-9_-]+\/)?(vless|vmess|shadowsocks|trojan)\/([0-9a-fA-F-]{36})$/;
export function earlyData(h) { if (!h) return null; try { const b = atob(h.replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from(b, c => c.charCodeAt(0)); } catch { return null; } }
