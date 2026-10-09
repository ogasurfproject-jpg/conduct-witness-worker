// conduct-witness-worker: a TSUGI re-verification witness on Cloudflare Workers, in one deploy.
//
// What it serves, on whatever host it is deployed to (your workers.dev name, or your own domain):
//   GET  /                              what this is, its key, how to check it
//   GET  /.well-known/agent-card.json   an A2A agent card declaring the A2A Conduct Extension v1 as a reciprocal witness
//   GET  /.well-known/mcp-conduct.json  the consent file: witness_policy.reciprocal = true, and where the key is
//   GET  /keys/witness.json             {"public_key_ed25519_b64"}: the domain-bound witness key (conduct-v1.1 11.4)
//   POST /a2a                           JSON-RPC message/send carrying a nenrin-witness-request-v1 data part
//
// The measuring and signing are the reference implementation (vendor/recovery-v0/witness_reply.mjs answerRequest),
// unchanged. Two things differ from running it under Node, and both are on purpose:
//   - the key is generated inside the Worker on first use and kept in the WITNESS_KV namespace; it never leaves your
//     Cloudflare account and nobody, including HORIZON SHIELD, ever sees it;
//   - the platform fetch is the measuring fetch. Cloudflare Workers do not route to private, link-local or loopback
//     addresses, so the SSRF pin of the Node reference is a property of the platform here; the hostname screen
//     (targetAllowed) still runs on every request.
import { answerRequest, extractRequest, rpcReply, targetAllowed, REPLY_VERSION } from "../vendor/recovery-v0/witness_reply.mjs";
import { measureSurfaces } from "../vendor/recovery-v0/drift_witness.mjs";
import { REQUEST_SCHEMA } from "../vendor/recovery-v0/witness_request.mjs";
import * as a2aSdk from "@a2a-js/sdk";

const WORKER_VERSION = "0.1.0";
const CONDUCT_URI = "https://gate.horizonshield.dev/ext/conduct/v1";
const KEY_PATH = "/keys/witness.json";
const KV_KEY = "witness_key_jwk_v1";
const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj, null, 2) + "\n", { status, headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": "*", ...extra } });
const b64urlToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const bytesToB64 = (b) => btoa(String.fromCharCode(...b));

// The witness key: generated once, kept in KV. If two first requests race, the one whose write lands last wins and
// both callers re-read it, so every later request signs with the same key.
async function witnessKey(env) {
  if (!env.WITNESS_KV) throw new Error("the WITNESS_KV binding is missing: add a KV namespace bound as WITNESS_KV (wrangler.jsonc)");
  let stored = await env.WITNESS_KV.get(KV_KEY, "json");
  if (!stored) {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    await env.WITNESS_KV.put(KV_KEY, JSON.stringify({ jwk, created_at: new Date().toISOString() }));
    stored = await env.WITNESS_KV.get(KV_KEY, "json");
  }
  const priv = await crypto.subtle.importKey("jwk", stored.jwk, { name: "Ed25519" }, false, ["sign"]);
  const pubRaw = b64urlToBytes(stored.jwk.x);
  return { priv, pubRaw, pubB64: bytesToB64(pubRaw), created_at: stored.created_at };
}

function agentCard(origin, host) {
  return {
    protocolVersion: "0.3.0",
    name: "Conduct witness (" + host + ")",
    description: "A reciprocal witness for the A2A Conduct Extension v1. Asked with a nenrin-witness-request-v1, it measures the named public surfaces of another agent from its own vantage and returns one observation signed with the key at " + origin + KEY_PATH + ". It is not told what to expect, it does not witness itself, and it measures public HTTPS origins only.",
    url: origin + "/a2a",
    preferredTransport: "JSONRPC",
    version: WORKER_VERSION,
    capabilities: {
      streaming: false,
      extensions: [{
        uri: CONDUCT_URI,
        required: false,
        params: {
          compensation: { paid_by: "public", referral_fee: false, listing_fee: false },
          measured_endpoints: [origin + "/a2a"],
          witness_intake: "https://ledger.horizonshield.dev/witness",
          witness_policy: { reciprocal: true },
          witness_reply: { transport: "a2a", answers: origin + "/a2a", request_schema: REQUEST_SCHEMA, reply_schema: "nenrin-witness-observation-v1", key_url: origin + KEY_PATH },
        },
      }],
    },
    defaultInputModes: ["application/json"],
    defaultOutputModes: ["application/json"],
    skills: [{ id: "conduct-witness", name: "Witness a conduct re-verification", description: "Measure the requested public surfaces of an agent and sign what was seen.", tags: ["witness", "conduct", "nenrin"] }],
  };
}

function home(origin, host, key) {
  return {
    what_this_is: "A TSUGI re-verification witness (conduct-witness-worker " + WORKER_VERSION + ", witness_reply " + REPLY_VERSION + ") on " + host + ".",
    signed_domain: host,
    key_url: origin + KEY_PATH,
    public_key_ed25519_b64: key.pubB64,
    key_created_at: key.created_at,
    agent_card: origin + "/.well-known/agent-card.json",
    consent: origin + "/.well-known/mcp-conduct.json",
    a2a: origin + "/a2a",
    what_it_does: "Answers a nenrin-witness-request-v1 with one signed nenrin-witness-observation-v1. It measures only what the request names, only public https origins, never itself, and it is not told the expected values.",
    what_being_in_the_pool_means: "Only that this card meets the four conditions. A draw from a public Bitcoin block decides who is asked; the operator of the ledger cannot pick. Being in the pool is not a claim that anyone trusts this witness.",
    source: "https://github.com/ogasurfproject-jpg/conduct-witness-worker",
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = url.origin, host = url.host.toLowerCase();
    try {
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type" } });
      if (request.method === "GET") {
        const key = await witnessKey(env);
        if (url.pathname === KEY_PATH) return json({ public_key_ed25519_b64: key.pubB64, alg: "ed25519", domain: host, what_this_is: "the domain-bound witness key of " + host + " (conduct-v1.1 11.4). Observations signed with it are attributable to this domain." });
        if (url.pathname === "/.well-known/agent-card.json") return json(agentCard(origin, host));
        if (url.pathname === "/.well-known/mcp-conduct.json") return json({ schema: "mcp-conduct-consent-v1", witness_policy: { reciprocal: true }, witness_key_url: origin + KEY_PATH, a2a: origin + "/a2a" });
        if (url.pathname === "/" || url.pathname === "") return json(home(origin, host, key));
        return json({ error: "not found", see: origin + "/" }, 404);
      }
      if (request.method !== "POST" || (url.pathname !== "/a2a" && url.pathname !== "/")) return json({ error: "POST a JSON-RPC message/send with a " + REQUEST_SCHEMA + " data part to /a2a" }, 405);
      const text = await request.text();
      if (text.length > 1_000_000) return json({ error: "too large" }, 413);
      let rpc; try { rpc = JSON.parse(text); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, 400); }
      if (!rpc || rpc.method !== "message/send") return json({ jsonrpc: "2.0", id: (rpc && rpc.id) || null, error: { code: -32601, message: "only message/send is served here" } });
      const wr = extractRequest(rpc);
      if (!wr) return json({ jsonrpc: "2.0", id: rpc.id || null, error: { code: -32602, message: "no " + REQUEST_SCHEMA + " data part in the message" } });
      const key = await witnessKey(env);
      const colo = request.cf && request.cf.colo ? request.cf.colo : "unknown";
      const result = await answerRequest(wr, {
        signedDomain: host, keyUrl: origin + KEY_PATH, priv: key.priv, pubRaw: key.pubRaw,
        measure: (target, o) => measureSurfaces(target, { ...o, sdk: a2aSdk }),
        fetchImpl: (u, init = {}) => {
          // every URL a measurement visits (the target and its card's jku) passes the same hostname screen
          const ta = targetAllowed(new URL(u).origin);
          if (!ta.ok) return Promise.reject(new Error("target_not_public: " + ta.why));
          return fetch(u, { ...init, redirect: "manual" });
        },
        resolver: null,
        vantage: "Cloudflare Workers, colo " + colo + " (" + host + ")",
      });
      return json(rpcReply(rpc.id || null, result));
    } catch (e) {
      return json({ error: "internal", why: String((e && e.message) || e).slice(0, 300) }, 500);
    }
  },
};

