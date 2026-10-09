// smoke.mjs: end to end against a running witness (default: wrangler dev on 127.0.0.1:8787).
//   node test/smoke.mjs [witness origin] [target origin]
// Sends one real nenrin-witness-request-v1, then accepts the reply with the reference acceptor
// (vendor/recovery-v0/witness_request.mjs acceptObservation): signature, request hash, endpoint, and the key at key_url.
// Also checks the three refusals a witness must make: itself, a non-public target, and a malformed request.
import { buildRequest, a2aEnvelope, requestSha256, extractObservation, acceptObservation, fetchWitnessKey } from "../vendor/recovery-v0/witness_request.mjs";
const W = (process.argv[2] || "http://127.0.0.1:8787").replace(/\/+$/, "");
const TARGET = (process.argv[3] || "https://gate.horizonshield.dev").replace(/\/+$/, "");
const R = []; const t = (n, ok, d = "") => R.push({ n, ok: !!ok, d: String(d).slice(0, 300) });
const get = async (p) => (await fetch(W + p, { headers: { accept: "application/json" } })).json();
const post = async (body) => (await fetch(W + "/a2a", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
const hex = (c) => c.repeat(64);

const home = await get("/");
const card = await get("/.well-known/agent-card.json");
const consent = await get("/.well-known/mcp-conduct.json");
const key = await get("/keys/witness.json");
const ext = (card.capabilities && card.capabilities.extensions || []).find((e) => e.uri === "https://gate.horizonshield.dev/ext/conduct/v1");
t("card declares conduct-v1 with witness_policy.reciprocal true", ext && ext.params.witness_policy.reciprocal === true);
t("consent file says reciprocal and names the key on the same host", consent.witness_policy.reciprocal === true && new URL(consent.witness_key_url).host === new URL(W).host);
t("key served, same as the one on /", key.public_key_ed25519_b64 && key.public_key_ed25519_b64 === home.public_key_ed25519_b64);
t("key is stable across requests", (await get("/keys/witness.json")).public_key_ed25519_b64 === key.public_key_ed25519_b64);

const req = buildRequest({ origin: TARGET, subjectSha256: hex("a"), poolSha256: hex("b"), beacon: { kind: "bitcoin_block", height: "970550", hash: hex("c") } });
const reply = await post(a2aEnvelope(req));
const rec = extractObservation(reply);
t("answered with a signed observation", rec && rec.signature_ed25519_b64, JSON.stringify(reply).slice(0, 300));
if (rec) {
  const acc = await acceptObservation({ record: rec, requestSha256: await requestSha256(req), endpoint: TARGET, ownHost: "gate.horizonshield.dev", fetchKey: (u) => fetchWitnessKey(u) });
  t("the reference acceptor accepts it (signature, request hash, endpoint, key at key_url)", acc.ok, JSON.stringify(acc.refusals));
  t("observation lists all nine surfaces", Object.keys(rec.observed).length === 9, Object.keys(rec.observed).join(","));
  t("observation carries no expected values", !JSON.stringify(rec.observed).includes('"expected"'));
}
const declined = async (r) => JSON.stringify((await post(a2aEnvelope(r))).result || {});
const self = buildRequest({ origin: W.replace(/^http:/, "https:"), subjectSha256: hex("a"), poolSha256: hex("b"), beacon: { kind: "b", height: "1", hash: hex("c") } });
t("refuses to witness itself (self_witness or not public)", /declined: (self_witness|target_not_public)/.test(await declined(self)));
const inside = buildRequest({ origin: "https://169.254.169.254", subjectSha256: hex("a"), poolSha256: hex("b"), beacon: { kind: "b", height: "1", hash: hex("c") } });
t("refuses an IP literal target (target_not_public)", /declined: target_not_public/.test(await declined(inside)));
const local = buildRequest({ origin: "https://metadata.internal", subjectSha256: hex("a"), poolSha256: hex("b"), beacon: { kind: "b", height: "1", hash: hex("c") } });
t("refuses an internal name (target_not_public)", /declined: target_not_public/.test(await declined(local)));
const bad = { ...req, subject_sha256: "nope" };
t("refuses a malformed request (bad_request)", /declined: bad_request/.test(await declined(bad)));
const notRpc = await post({ jsonrpc: "2.0", id: 1, method: "tasks/get" });
t("only message/send is served", notRpc.error && notRpc.error.code === -32601);

for (const r of R) console.log((r.ok ? "ok    " : "FAIL  ") + r.n + (r.ok ? "" : "  :: " + r.d));
const bad2 = R.filter((r) => !r.ok).length;
console.log("\n" + (R.length - bad2) + "/" + R.length + " passed against " + W);
process.exitCode = bad2 ? 1 : 0;
