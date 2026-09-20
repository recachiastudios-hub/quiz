/*
 * quiz-crypto.js — compresses + encrypts quiz links for Quiz Builder.
 * © Youssef Hisham 2026
 *
 * Keep this file in the SAME folder as index.html.
 *   quiz -> compact JSON -> deflate -> AES-GCM -> base64url   (links look like  #q=...)
 *
 * The quiz settings travel inside the encrypted part too (so a student can't edit them):
 *   time limit, hide the green / red flash, shuffle questions and answers.
 * Links made before those settings existed still open (they get the defaults).
 *
 * Question types packed into the link:
 *   Multiple choice  ->  [text, A, B, C, D, letter]
 *   True / False     ->  [text, 'T' or 'F']
 *   Custom Choice    ->  {k:'c', x:text, c:[choices...], a:[correct indexes...]}
 *   Written          ->  {k:'w', x:text}
 * Links made before Custom Choice and Written existed still open.
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

function packQuestion(it) {
  if (it.type === 'mc') return [it.text, ...it.choices, it.answer];
  if (it.type === 'tf') return [it.text, it.answer === 'True' ? 'T' : 'F'];
  if (it.type === 'cc') return { k: 'c', x: it.text, c: it.choices, a: it.answers };
  if (it.type === 'wr') return { k: 'w', x: it.text };
  throw new Error('unknown question type: ' + it.type);
}

function unpackQuestion(a) {
  if (Array.isArray(a)) {
    return a.length === 6
      ? { type: 'mc', text: a[0], choices: a.slice(1, 5), answer: a[5] }
      : { type: 'tf', text: a[0], answer: a[1] === 'T' ? 'True' : 'False' };
  }
  if (a && a.k === 'c') return { type: 'cc', text: a.x, choices: a.c, answers: a.a };
  if (a && a.k === 'w') return { type: 'wr', text: a.x };
  throw new Error('unknown question format');
}

async function encodeSecure(q) {
  const compact = {
    i: q.id,
    q: q.questions.map(packQuestion)
  };
  // Settings are only written when they differ from the default, which keeps the link short:
  //   t = time limit in seconds (left out = unlimited)
  //   h = 1 when the green / red flash is hidden (left out = flash shown)
  //   s = 0 when shuffling is turned off (left out = shuffled)
  if (Number(q.t) > 0) compact.t = Math.floor(Number(q.t));
  if (q.hf === true) compact.h = 1;
  if (q.sh === false) compact.s = 0;
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
    t: Number(c.t) > 0 ? Math.floor(Number(c.t)) : 0,
    hf: c.h === 1,
    sh: c.s !== 0,
    questions: c.q.map(unpackQuestion)
  };
}

  window.QuizCrypto = { encode: encodeSecure, decode: decodeSecure };
})();
