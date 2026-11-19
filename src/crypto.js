// Cryptographic primitives the native VMess / Shadowsocks engines need and WebCrypto does not offer
// (MD5, SHAKE128, ChaCha20-Poly1305, synchronous SHA-256/HMAC for the VMess KDF), plus thin WebCrypto
// wrappers for the parts it does well (AES-GCM, HKDF-SHA1, AES single-block). No dependencies.
import { cat } from './util.js';

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
export const sha256 = msg => sha2(msg, IV256, 8);
export const sha224 = msg => sha2(msg, IV224, 7);

/** HMAC over any hash function `H(bytes) -> bytes` with a 64-byte block (the VMess KDF nests these). */
export function hmacWith(H, key) {
  if (key.length > 64) key = H(key);
  const k = new Uint8Array(64); k.set(key); const ip = k.map(b => b ^ 0x36), op = k.map(b => b ^ 0x5c);
  return data => H(cat(op, H(cat(ip, data))));
}
export const hmacSha256 = (key, data) => hmacWith(sha256, key)(data);

// ------------------------------------------------------------------ MD5 (VMess command key, Shadowsocks key derivation)
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const MD5_K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));
export function md5(msg) {
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
export function evpBytesToKey(password, keyLen) {
  let out = new Uint8Array(0), prev = new Uint8Array(0);
  while (out.length < keyLen) { prev = md5(cat(prev, password)); out = cat(out, prev); }
  return out.slice(0, keyLen);
}

// ------------------------------------------------------------------ small checksums
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
export function crc32(b) { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
export function fnv1a(b) { let h = 0x811c9dc5; for (let i = 0; i < b.length; i++) h = Math.imul(h ^ b[i], 0x01000193) >>> 0; return h; }
export function ctEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

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
export class Shake128 {
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
export function poly1305(key, msg) {
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
export function chachaSeal(key, nonce, pt, aad = new Uint8Array(0)) { const ct = chachaXor(key, nonce, 1, pt); return cat(ct, chachaMac(key, nonce, aad, ct)); }
export function chachaOpen(key, nonce, boxed, aad = new Uint8Array(0)) {
  if (boxed.length < 16) throw new Error('short');
  const ct = boxed.subarray(0, boxed.length - 16); if (!ctEq(chachaMac(key, nonce, aad, ct), boxed.subarray(boxed.length - 16))) throw new Error('bad tag');
  return chachaXor(key, nonce, 1, ct);
}

// ------------------------------------------------------------------ WebCrypto wrappers
const EMPTY = new Uint8Array(0);
/** AEAD with `seal(nonce, data, aad)` / `open(nonce, boxed, aad)` -> Promise<Uint8Array>; `open` rejects on a bad tag. */
export function makeAead(kind, key) {
  if (kind === 'chacha20-poly1305') return { tag: 16, seal: async (n, d, a = EMPTY) => chachaSeal(key, n, d, a), open: async (n, d, a = EMPTY) => chachaOpen(key, n, d, a) };
  const k = crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return {
    tag: 16,
    seal: async (n, d, a = EMPTY) => new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: n, additionalData: a, tagLength: 128 }, await k, d)),
    open: async (n, d, a = EMPTY) => new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: n, additionalData: a, tagLength: 128 }, await k, d)),
  };
}
export async function hkdfSha1(ikm, salt, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-1', salt, info }, k, len * 8));
}
// WebCrypto has no raw AES block mode: one CBC block with a zero IV *is* one ECB block.
const ZERO16 = new Uint8Array(16);
export async function aesBlockEncrypt(key, block) {
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO16 }, k, block)).slice(0, 16);
}
export async function aesBlockDecrypt(key, block) {
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt', 'decrypt']);
  // Append E(block xor 0x10..) so the CBC padding check passes; the first plaintext block is the answer.
  const x = block.map(b => b ^ 16), c2 = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO16 }, k, x)).slice(0, 16);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ZERO16 }, k, cat(block, c2)));
}
