// Small byte helpers shared by the protocol engines (relay.js, vmess.js, shadowsocks.js).
export const te = new TextEncoder(), td = new TextDecoder();

export const toU8 = d => d instanceof Uint8Array ? d : d instanceof ArrayBuffer ? new Uint8Array(d) : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : te.encode(String(d));
export const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
export const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
export const unhex = s => Uint8Array.from(s.match(/../g) || [], h => parseInt(h, 16));
export const uuidBytes = id => unhex(id.replace(/-/g, ''));
export const u16 = n => Uint8Array.of((n >> 8) & 255, n & 255);
export const rnd = n => crypto.getRandomValues(new Uint8Array(n));

/** base64 of any text (Persian / emoji / anything). Plain btoa() throws on characters above Latin-1, so encode as UTF-8 first. */
export const b64 = x => { const u = typeof x === 'string' ? te.encode(x) : toU8(x); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); };

/** Read an address as written in VLESS (1 v4, 2 domain, 3 v6), Trojan / Shadowsocks (1 v4, 3 domain, 4 v6) headers. */
export function readAddr(b, i, atyp, v6atyp, domainAtyp = 2) {
  if (atyp === 1) return b.length >= i + 4 ? [`${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`, i + 4] : null;
  if (atyp === domainAtyp) { if (i >= b.length || b.length < i + 1 + b[i]) return null; return [td.decode(b.slice(i + 1, i + 1 + b[i])), i + 1 + b[i]]; }
  if (atyp === v6atyp) { if (b.length < i + 16) return null; const dv = new DataView(b.buffer, b.byteOffset + i, 16); return [Array.from({ length: 8 }, (_, k) => dv.getUint16(k * 2).toString(16)).join(':'), i + 16]; }
  return null;
}

/** One DNS query over HTTPS (the only UDP the relays carry). */
export async function dnsOverHttps(q) {
  const r = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' }, body: q });
  return new Uint8Array(await r.arrayBuffer());
}

/** Growable receive buffer: append WebSocket messages, take exact byte counts. */
export class RxBuf {
  constructor() { this.b = new Uint8Array(0); }
  get length() { return this.b.length; }
  push(d) { this.b = this.b.length ? cat(this.b, d) : d; }
  peek(n) { return this.b.subarray(0, n); }
  take(n) { const o = this.b.slice(0, n); this.b = this.b.subarray(n); return o; }
  all() { const o = this.b; this.b = new Uint8Array(0); return o; }
}
