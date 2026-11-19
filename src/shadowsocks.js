// Native Shadowsocks (AEAD) over WebSocket. Both common ciphers are accepted and detected from the first chunk:
// chacha20-ietf-poly1305 and aes-256-gcm. The password is the user's uuid, the user is named by the path
// (/ws/shadowsocks/<uuid>), so there is no key search: one derivation, at most two trial decryptions.
//
//   stream   = salt(32) then chunks  [AEAD(len, 2 bytes)] [AEAD(payload, <= 0x3FFF)]   (nonce = LE counter, +1 per AEAD call)
//   subkey   = HKDF-SHA1(master key, salt, "ss-subkey")        master key = EVP_BytesToKey(MD5, password)
//   1st data = atyp addr port, then the payload (possibly spread over several chunks)
import { evpBytesToKey, hkdfSha1, makeAead } from './crypto.js';
import { te, toU8, cat, u16, rnd, readAddr, RxBuf } from './util.js';

export const SS_CIPHERS = { 'chacha20-ietf-poly1305': 'chacha20-poly1305', 'aes-256-gcm': 'aes-gcm' };
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
export function parseTarget(b) {
  if (b.length < 1) return 'more'; const t = b[0]; let need;
  if (t === 1) need = 7; else if (t === 4) need = 19; else if (t === 3) { if (b.length < 2) return 'more'; need = 4 + b[1]; } else return null;
  if (b.length < need) return 'more';
  const [host, i] = readAddr(b, 1, t, 4, 3); return { host, port: (b[i] << 8) | b[i + 1], rest: b.slice(i + 2) };
}

/** Encrypt side of a connection: random salt first, then length + payload boxes. */
export async function makeEncoder(master, kind) {
  const salt = rnd(SALT), half = new Half(kind, await hkdfSha1(master, salt, INFO, 32)); let sent = false;
  return async payload => {
    const out = [];
    if (!sent) { out.push(salt); sent = true; }
    for (let i = 0; i < payload.length; i += MAX) { const p = payload.subarray(i, i + MAX); out.push(await half.aead.seal(half.nonce(), u16(p.length)), await half.aead.seal(half.nonce(), p)); }
    return cat(...out);
  };
}

export function serveShadowsocks(ws, { user, dial, meter, ctx, early }) {
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
