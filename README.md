# conduct-witness-worker

A re-verification witness for the A2A Conduct Extension v1, running on Cloudflare Workers. One deploy gives you a
working witness: the key is made inside your Worker, the agent card and consent file are served for you, and your
`/a2a` answers witness requests.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ogasurfproject-jpg/conduct-witness-worker)

## Why witnesses are needed

When an agent breaks and is repaired, TSUGI (the recovery layer of NENRIN) does not let the operator say "fixed" on
its own word. It draws witnesses at random from a public pool, using a Bitcoin block nobody can predict, and asks each
one to measure the repaired agent's public surfaces. A repair counts only when enough independent witnesses agree.

The pool needs witnesses run by different people. Today it has one. This Worker is the shortest way to be the second.

## What a witness does, and does not do

- It answers one kind of message, a `nenrin-witness-request-v1`, by measuring the named public surfaces of the named
  agent from its own vantage and returning one observation signed with its key.
- It is not told what to expect, so it cannot be steered toward an answer. It writes down what it saw.
- It refuses to witness itself, refuses IP literals, internal names and anything that is not public HTTPS, and is
  limited by the platform: Cloudflare Workers do not route to private, link-local or loopback addresses.
- It executes nothing from the request. The strings in a request are only used as a target and a list of surface names.
- Being in the pool is not a claim that anyone trusts you. Your signature says who saw it, not that it is true.

The measuring and signing code is the reference implementation from
[horizon-shield](https://github.com/ogasurfproject-jpg/horizon-shield/tree/main/workers/hs-ledger/nenrin/recovery-v0),
copied byte for byte into `vendor/` (hashes and source commit in `vendor/VENDORED.json`). `src/worker.mjs` only adds the
Worker around it.

## Deploy

With the button above: Cloudflare forks this repository into your GitHub account, creates the `WITNESS_KV` namespace and
deploys. Or from a terminal:

```sh
git clone https://github.com/ogasurfproject-jpg/conduct-witness-worker && cd conduct-witness-worker
npm install
npx wrangler deploy          # creates the WITNESS_KV namespace on the first deploy
```

Then open the Worker's address once. The first request makes the key:

```sh
curl -s https://conduct-witness.<your-subdomain>.workers.dev/
```

A custom domain (Workers, Settings, Domains & Routes) makes the witness attributable to your own domain rather than a
workers.dev name. Either works for the pool.

## What it serves

| Path | What |
|---|---|
| `GET /` | what this is, the public key, the links below |
| `GET /.well-known/agent-card.json` | A2A agent card declaring conduct-v1 with `witness_policy.reciprocal: true` |
| `GET /.well-known/mcp-conduct.json` | the consent file the pool reads |
| `GET /keys/witness.json` | `{"public_key_ed25519_b64"}`, the domain-bound witness key |
| `POST /a2a` | JSON-RPC `message/send` with a `nenrin-witness-request-v1` data part |

The private key never leaves your Cloudflare account. It sits in your `WITNESS_KV` namespace, readable by you only.
To rotate, delete the `witness_key_jwk_v1` key in that namespace; the next request makes a new one (and the pool picks
up the new public key the next time it is rebuilt).

## Check it yourself

```sh
npm install
npx wrangler dev --local --local-protocol https --port 8787 &
NODE_TLS_REJECT_UNAUTHORIZED=0 node test/smoke.mjs https://127.0.0.1:8787
```

`test/smoke.mjs` sends one real witness request and accepts the reply with the reference acceptor (signature, request
hash, endpoint, and the key served at `key_url`), then checks the refusals: itself, an IP literal, an internal name, a
malformed request. Against your deployed Worker: `node test/smoke.mjs https://<your worker>`.

## Join the pool

Open an issue in [horizon-shield](https://github.com/ogasurfproject-jpg/horizon-shield/issues/new) titled
`witness: <your origin>`. The pool is rebuilt with the reference admission check
(`recovery-v0/witness_pool_build.mjs`): four conditions, and every card that meets them is admitted; the operator does
not pick. How each member arrived (invited, referred, or on its own) is published beside the pool.

## License

MIT, the same license as the horizon-shield sources in `vendor/`.
