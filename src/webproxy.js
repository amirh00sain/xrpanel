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
import { DB, state } from './db.js';
import { panelDomain } from './links.js';
import { Meter } from './relay.js';

const te = new TextEncoder(), td = new TextDecoder();

// ---------------- wire framing between the bridge page and the Durable Object ----------------
export const FRAME = Object.freeze({ OPEN: 0x01, DATA: 0x02, CLOSE: 0x03, WINDOW: 0x04, PING: 0x05, PONG: 0x06, HELLO: 0x10, WELCOME: 0x11, BYE: 0x1f });
export const HEADER_SIZE = 8, MAX_PAYLOAD = 1024 * 1024, MAX_BATCH_FRAMES = 4096, INITIAL_WINDOW = 4 * 1024 * 1024, DATA_CHUNK = 64 * 1024, MAX_WS_MESSAGE = 2 * 1024 * 1024;

export function encodeFrame(type, streamId, payload = new Uint8Array()) {
  if (streamId < 0 || streamId > 0xffffff || payload.length > MAX_PAYLOAD) throw new Error('invalid frame');
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = type; out[1] = streamId >>> 16; out[2] = streamId >>> 8; out[3] = streamId;
  new DataView(out.buffer).setUint32(4, payload.length); out.set(payload, HEADER_SIZE); return out;
}
export function parseFrames(input) {
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
export function u32(value) { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value); return out; }
export function clampInt(value, min, max, fallback) { const n = Number.parseInt(value, 10); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; }

// ---------------- MTProto obfuscated handshake (AES-256-CTR) ----------------
const TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
export const TELEGRAM_DCS = Object.freeze({ 1: '149.154.175.50', 2: '149.154.167.51', 3: '149.154.175.100', 4: '149.154.167.91', 5: '149.154.171.5' });

export class AesCtrStream {
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

export function parseProxySecret(value) {
  const s = String(value || '').toLowerCase();
  if (/^[0-9a-f]{32}$/.test(s)) return hex(s);
  if (/^dd[0-9a-f]{32}$/.test(s)) return hex(s.slice(2));
  throw new Error('wp_secret must be 32 hex characters, optionally prefixed with dd');
}
function hex(s) { const x = new Uint8Array(s.length / 2); for (let i = 0; i < x.length; i++) x[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16); return x; }

export async function acceptClientHandshake(packet, secret) {
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
export async function createTelegramHandshake(tag, dcId) {
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
export async function hmac(keyBytes, data) { const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', key, data)); }
const signingKey = hexSecret => te.encode(`xr-panel/webproxy-signing/v1\n${String(hexSecret || '')}`);
const noSecret = v => !/^(?:[0-9a-f]{32}|dd[0-9a-f]{32})$/.test(String(v || ''));

export async function createBootstrap(hexSecret, uid, ttl = 300) {
  const payload = base64url(te.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + ttl, n: randomToken(16), u: uid })));
  const signature = base64url(await hmac(signingKey(hexSecret), te.encode(payload)));
  return `${payload}.${signature}`;
}
/** The user id a bootstrap token claims (NOT trusted until verifyBootstrap passes with that user's secret). */
export function bootstrapUser(token) { try { const d = JSON.parse(td.decode(base64urlDecode(String(token || '').split('.')[0]))); return Number.isInteger(d.u) && d.u > 0 ? d.u : 0; } catch { return 0; } }
export async function verifyBootstrap(hexSecret, token) {
  if (noSecret(hexSecret)) return false;
  const [payload, signature, extra] = String(token || '').split('.'); if (!payload || !signature || extra) return false;
  const expected = base64url(await hmac(signingKey(hexSecret), te.encode(payload))); if (!constantTimeEqual(signature, expected)) return false;
  try { const data = JSON.parse(td.decode(base64urlDecode(payload))); return Number.isInteger(data.exp) && data.exp >= Math.floor(Date.now() / 1000); } catch { return false; }
}
// session token = nonce(12) | user id(4) | mac(16)  -> 32 bytes -> 43 base64url characters (the bridge page checks that shape)
export async function createSessionToken(hexSecret, host, uid) {
  const body = new Uint8Array(16); body.set(crypto.getRandomValues(new Uint8Array(12))); new DataView(body.buffer).setUint32(12, uid);
  const mac = await sessionMac(hexSecret, host, body); const bytes = new Uint8Array(32); bytes.set(body); bytes.set(mac.subarray(0, 16), 16); return base64url(bytes);
}
/** The user id a session token claims (NOT trusted until verifySessionToken passes with that user's secret). */
export function sessionUser(token) { if (!/^[A-Za-z0-9_-]{43}$/.test(token || '')) return 0; try { return new DataView(base64urlDecode(token).buffer).getUint32(12) || 0; } catch { return 0; } }
export async function verifySessionToken(hexSecret, host, token) {
  if (noSecret(hexSecret) || !/^[A-Za-z0-9_-]{43}$/.test(token || '')) return false;
  const bytes = base64urlDecode(token); if (base64url(bytes) !== token) return false;
  const mac = await sessionMac(hexSecret, host, bytes.subarray(0, 16)); return constantTimeEqual(base64url(bytes.subarray(16)), base64url(mac.subarray(0, 16)));
}
function sessionMac(hexSecret, host, body) { const context = te.encode('xr-panel/webproxy-session/v2\n' + host + '\n'); const bytes = new Uint8Array(context.length + body.length); bytes.set(context); bytes.set(body, context.length); return hmac(signingKey(hexSecret), bytes); }
export async function capabilityMatches(candidate, host, hexSecret) {
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
export async function testDataCenters(connectFn, ms = 5000) {
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

export { newSecret as randomSecret } from './db.js';
/** The link a user opens in Telegram: it points the app's web proxy at this panel with that user's own secret. */
export function telegramLink(secret, domain) { return `https://t.me/webproxy?server=${encodeURIComponent(domain)}&secret=${encodeURIComponent(String(secret || '').toLowerCase())}`; }

// ---------------- the bridge page (what Telegram Desktop opens to perform the handshake) ----------------
export function bridgePage(host, bootstrap) {
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
export async function handleRoot(url, s, host, reg) {
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
export async function handleSession(request, s, host, reg) {
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
export async function handleWs(request, s, host, env, reg, ctx, connectFn) {
  if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
  const expectedHost = panelDomain(s, host);
  const protocols = (request.headers.get('Sec-WebSocket-Protocol') || '').split(',').map(v => v.trim());
  const protocol = protocols.find(v => v.startsWith('tproxy-v1.')); const token = protocol?.slice('tproxy-v1.'.length);
  const u = await reg.byId(sessionUser(token));
  if (!usable(u) || !(await verifySessionToken(u.wp_secret, expectedHost, token))) return new Response('Not found', { status: 404 });
  return new RelaySession(ctx, env, connectFn).upgrade(protocol, u);
}

// ---------------- one session per connected Telegram client, relays to the real Telegram DC ----------------
export const LIMITS = Object.freeze({ itemCost: 256, ingressBytes: 8 * 1024 * 1024, ingressItems: 128, uplinkBytes: 8 * 1024 * 1024, uplinkItems: 8192, streamBytes: INITIAL_WINDOW + 1024 * 1024, streamItems: 4096, downlinkBytes: 8 * 1024 * 1024, downlinkItems: 8192, handshakeTimeout: 15000, connectTimeout: 10000, writeTimeout: 30000 });

export class RelaySession {
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
