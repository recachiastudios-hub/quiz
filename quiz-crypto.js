/*
 * quiz-crypto.js — compresses + encrypts quiz links for Quiz Builder.
 * © Youssef Hisham 2026
 *
 * Keep this file in the SAME folder as index.html.
 *   quiz -> compact JSON -> deflate -> AES-GCM -> base64url   (links look like  #q=...)
 *
 * To change the key: replace KEY_HEX with any 32 hex characters (0-9, a-f).
 * Links made with the old key stop working, so make new links afterwards.
 *
 * Note: the browser has to download this file to open a quiz, so the key is not
 * a real secret. This hides the answers from the link itself, not from a determined student.
 */
(function () {
const KEY_HEX = '3eff7e99a83a2cca8b346f029164e6e2';

function hexToBytes(h) { return Uint8Array.from(h.match(/.{2}/g), x => parseInt(x, 16)); }
function bytesToB64(bytes) {
  let s = '';
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function pipeBytes(bytes, stream) {
  const w = stream.writable.getWriter();
  w.write(bytes).catch(() => {});
  w.close().catch(() => {});
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}
function linkKey() {
  return crypto.subtle.importKey('raw', hexToBytes(KEY_HEX), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encodeSecure(q) {
  // MC: [text, A, B, C, D, letter]   TF: [text, 'T' or 'F']
  const compact = {
    i: q.id,
    q: q.questions.map(it => it.type === 'mc'
      ? [it.text, ...it.choices, it.answer]
      : [it.text, it.answer === 'True' ? 'T' : 'F'])
  };
  const raw = new TextEncoder().encode(JSON.stringify(compact));
  const packed = await pipeBytes(raw, new CompressionStream('deflate-raw'));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await linkKey(), packed));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return bytesToB64(out);
}

async function decodeSecure(s) {
  const buf = b64ToBytes(s);
  const iv = buf.slice(0, 12);
  const packed = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await linkKey(), buf.slice(12)));
  const raw = await pipeBytes(packed, new DecompressionStream('deflate-raw'));
  const c = JSON.parse(new TextDecoder().decode(raw));
  return {
    v: 1,
    id: c.i,
    questions: c.q.map(a => a.length === 6
      ? { type: 'mc', text: a[0], choices: a.slice(1, 5), answer: a[5] }
      : { type: 'tf', text: a[0], answer: a[1] === 'T' ? 'True' : 'False' })
  };
}

  window.QuizCrypto = { encode: encodeSecure, decode: decodeSecure };
})();
