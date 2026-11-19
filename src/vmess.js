// Native VMess over WebSocket (the AEAD format, alterId = 0, which is what every current client sends).
//
//   request  = authid(16) | AEAD(header length)(2+16) | connection nonce(8) | AEAD(header)(n+16)
//   header   = ver(1) iv(16) key(16) V(1) opt(1) pad<<4|sec(1) 0(1) cmd(1) port(2) atyp(1) addr pad(P) fnv1a(4)
//   body     = chunks  [len(2, masked by SHAKE128(iv))] [AEAD(payload)] [padding]
//   response = AEAD(len) AEAD([V 0 0 0]) then the same chunk framing with the *response* key / iv
//
// The user is known from the WebSocket path (/ws/vmess/<uuid>), so the command key comes from that one uuid
// and there is nothing to search; wrong keys fail the auth-id or the AEAD tag and the socket is closed.
import { md5, sha256, hmacWith, hmacSha256, crc32, fnv1a, Shake128, makeAead, aesBlockDecrypt } from './crypto.js';
import { te, toU8, cat, uuidBytes, u16, rnd, readAddr, dnsOverHttps, RxBuf } from './util.js';

const MAGIC = te.encode('c48619fe-8f02-49e0-b9e9-edf763e17e21');
export const cmdKeyOf = uuid => md5(cat(uuidBytes(uuid), MAGIC));

/** VMess AEAD KDF: HMAC-SHA256 whose hash function is, layer by layer, the HMAC built for the previous path element. */
export function kdf(key, ...path) {
  let H = d => hmacSha256(te.encode('VMess AEAD KDF'), d);
  for (const p of path) H = hmacWith(H, toU8(p));
  return H(key);
}
const kdf16 = (key, ...path) => kdf(key, ...path).subarray(0, 16), kdf12 = (key, ...path) => kdf(key, ...path).subarray(0, 12);
const ZERO = new Uint8Array(0);

export const SEC = { AES128GCM: 3, CHACHA: 4 };
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
export async function openRequest(cmdKey, b, now = Date.now()) {
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

export function parseHeader(h) {
  if (h.length < 42 || h[0] !== 1) return { fail: 'version' };
  const dv = new DataView(h.buffer, h.byteOffset, h.length), end = h.length - 4;
  if (fnv1a(h.subarray(0, end)) !== dv.getUint32(end)) return { fail: 'checksum' };
  const pad = h[35] >> 4, sec = h[35] & 15, cmd = h[37], port = dv.getUint16(38), a = readAddr(h, 41, h[40], 3, 2);
  if (!a || a[1] + pad > end) return { fail: 'address' };
  return { iv: h.slice(1, 17), key: h.slice(17, 33), v: h[33], opt: h[34], sec, cmd, port, host: a[0] };
}

/** Response header: two AEAD boxes keyed from SHA-256 of the request key / iv. */
export async function sealResponse(reqKey, reqIv, v) {
  const rk = sha256(reqKey).subarray(0, 16), ri = sha256(reqIv).subarray(0, 16);
  const l = await makeAead('aes-gcm', kdf16(rk, 'AEAD Resp Header Len Key')).seal(kdf12(ri, 'AEAD Resp Header Len IV'), u16(4));
  const p = await makeAead('aes-gcm', kdf16(rk, 'AEAD Resp Header Key')).seal(kdf12(ri, 'AEAD Resp Header IV'), Uint8Array.of(v, 0, 0, 0));
  return cat(l, p);
}

/** One direction of the chunk stream: nonce = counter(2, BE) | iv[2..12], sizes masked / padded from SHAKE128(iv). */
export class Chunks {
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
export function serveVmess(ws, { user, dial, meter, ctx, early }) {
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
