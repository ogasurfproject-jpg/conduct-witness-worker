// ed25519_key.mjs : is a 32-byte Ed25519 public key one a signature can mean something under? (nenrin-verify 0.4.2)
//
// OpenSSL, and so Node's crypto and WebCrypto, verify against any 32 bytes that decode to a curve point. Three kinds
// of such keys break what a signature is used for here:
//   - a point of small order (order 1, 2, 4 or 8). R = the identity point and S = 0 is then a valid signature on
//     every message, with no private key at all.
//   - a mixed-order point A + T (a real key A plus a small-order T). Its holder signs with A's private key, and it is
//     a different 32-byte string from A, so one private key can pose as several keys: several witnesses in a TSUGI
//     quorum, or a party posing as its own "independent" witness in provenance R1.
//   - an encoding that is not canonical: y >= p, or x = 0 with the sign bit set, so one point has two spellings.
// Both kinds of point were found by independent attacks on these verifiers on 2026-10-04 (two rounds: the
// first found small order, the second found mixed order after the first fix). ed25519KeyOk(raw) is true only for
// the canonical encoding of a point P != identity with L * P = identity, that is a point of the prime-order
// subgroup, the same rule agreement-v0's verifier applies. Arithmetic is plain BigInt on the twisted Edwards curve
// -x^2 + y^2 = 1 + d x^2 y^2 over p = 2^255 - 19, in extended coordinates with the complete addition law (no
// inversions, no special cases). Results are cached per key, since a bundle names the same key many times.
// Twins in Python: sdk-python/src/nenrin_verify/provenance.py and recovery-v0/recovery_verify.py.
const ED_P = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const edMod = (a) => { const r = a % ED_P; return r < 0n ? r + ED_P : r; };
function edPow(b, e) { let r = 1n; b = edMod(b); while (e > 0n) { if (e & 1n) r = (r * b) % ED_P; b = (b * b) % ED_P; e >>= 1n; } return r; }
const ED_D = edMod(-121665n * edPow(121666n, ED_P - 2n));
const ED_D2 = (2n * ED_D) % ED_P;
const ED_SQRT_M1 = edPow(2n, (ED_P - 1n) / 4n);

// extended coordinates (X, Y, Z, T): x = X/Z, y = Y/Z, x*y = T/Z. add-2008-hwcd-3, complete for a = -1.
function edAdd(P, Q) {
  const A = edMod((P[1] - P[0]) * (Q[1] - Q[0])), B = edMod((P[1] + P[0]) * (Q[1] + Q[0]));
  const C = edMod(P[3] * ED_D2 % ED_P * Q[3]), D = edMod(2n * P[2] * Q[2]);
  const E = edMod(B - A), F = edMod(D - C), G = edMod(D + C), H = edMod(B + A);
  return [E * F % ED_P, G * H % ED_P, F * G % ED_P, E * H % ED_P];
}
function edMul(P, n) {
  let R = [0n, 1n, 1n, 0n], Q = P;
  while (n > 0n) { if (n & 1n) R = edAdd(R, Q); Q = edAdd(Q, Q); n >>= 1n; }
  return R;
}
const edIsIdentity = (P) => P[0] % ED_P === 0n && edMod(P[1] - P[2]) === 0n;

function ed25519KeyCheck(raw) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? raw[i] & 0x7f : raw[i]);
  const sign = (raw[31] >> 7) & 1;
  if (y >= ED_P) return false;                                   // non-canonical y
  const u = edMod(y * y - 1n), v = edMod(ED_D * y * y + 1n);
  const x2 = (u * edPow(v, ED_P - 2n)) % ED_P;
  let x = edPow(x2, (ED_P + 3n) / 8n);
  if ((x * x) % ED_P !== x2) x = (x * ED_SQRT_M1) % ED_P;
  if ((x * x) % ED_P !== x2) return false;                       // not on the curve
  if (x === 0n && sign === 1) return false;                      // -0: non-canonical
  if (Number(x & 1n) !== sign) x = ED_P - x;
  const P = [x, y, 1n, (x * y) % ED_P];
  if (edIsIdentity(P)) return false;                             // the identity (order 1)
  return edIsIdentity(edMul(P, ED_L));                           // L * P = O: prime-order subgroup, not small or mixed order
}

const ED_KEY_CACHE = new Map();
export function ed25519KeyOk(raw) {
  if (!raw || raw.length !== 32) return false;
  const k = Buffer.from(raw).toString("hex");
  let ok = ED_KEY_CACHE.get(k);
  if (ok === undefined) { ok = ed25519KeyCheck(raw); if (ED_KEY_CACHE.size >= 4096) ED_KEY_CACHE.clear(); ED_KEY_CACHE.set(k, ok); }
  return ok;
}

// Canonical standard base64 only (RFC 4648 section 4: the standard alphabet, padding present, no whitespace, unused
// trailing bits zero), so one key or signature has exactly one spelling. Returns the n bytes, or null.
const ED_B64_STD = /^[A-Za-z0-9+/]*={0,2}$/;
export function b64Exact(s, n) {
  if (typeof s !== "string" || s.length === 0 || s.length % 4 !== 0 || !ED_B64_STD.test(s)) return null;
  const b = Buffer.from(s, "base64");
  if (b.length !== n || b.toString("base64") !== s) return null;
  return Uint8Array.from(b);
}
