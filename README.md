# Agentic transparency log

This repository is a public, append-only copy of the signed transparency anchors published by [Agentic](https://useagentic.app). It exists so that Agentic cannot quietly rewrite an organization's audit history: once an anchor is here and timestamped, changing it would show against this copy and against the Bitcoin timestamp.

## What an anchor is

Every Agentic organization has a hash-chained audit log. Each worker run signs a checkpoint of the newest log entry for each organization. Then:

1. The newest checkpoint of every organization becomes a leaf of an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle tree. The leaf data is the canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) of `{"type":"agentic.checkpoint.v1","tenant_id","last_seq","last_hash","signed_at","kid"}`.
2. Real leaves are padded with random hashes to a power of two of at least 16 and sorted, so the tree does not reveal how many organizations there are or which leaf belongs to whom.
3. The root is signed as a compact JWS (Ed25519). The header is exactly `{"alg":"EdDSA","typ":"agentic-anchor+jwt","kid":"<RFC 7638 thumbprint>"}` and the claims are `{"ver":1,"iss","seq","prev","root","tree_size","iat"}`.
4. `prev` is `sha256:` plus the hex SHA-256 of the previous anchor's JWS string, and 64 zeros for anchor 1. `seq` increases by one with no gaps.

## Layout

| Path | Contents |
| --- | --- |
| `anchors/NNNNNN.json` | One anchor: `seq`, `jws`, `prev_hash`, `anchor_hash`, `root`, `tree_size`, every leaf hash, `kid`, `signed_at` |
| `anchors/NNNNNN.json.ots` | The OpenTimestamps proof for that file |
| `jwks.json` | The JWKS as last fetched from `https://useagentic.app/.well-known/jwks.json` |
| `keys-history.json` | Every key ever seen in the JWKS, so anchors signed before a key was revoked still verify here |
| `lib.mjs`, `verify.mjs`, `mirror.mjs` | Verification and mirroring, Node 20, no dependencies |

`.github/workflows/mirror.yml` runs every 10 minutes. It fetches anchors newer than the last one here from `/api/v1/transparency/anchors`, checks each signature, its root against its leaves and its link to the previous mirrored anchor, writes it, then stamps it with OpenTimestamps. It also checks that the newest mirrored anchor is still served unchanged. If any check fails, the run fails and nothing past the last good anchor is written.

## Verify it yourself

Check the whole chain in this repository:

```sh
git clone https://github.com/carterweinstein-hash/agentic-transparency
cd agentic-transparency
node verify.mjs
node verify.mjs --jwks https://useagentic.app/.well-known/jwks.json   # against the live keys instead
```

Check that your organization's history is in a published anchor. Save the response of `GET https://useagentic.app/api/v1/audit/checkpoints/latest` (signed in as an owner, admin or auditor) to `latest.json`, then:

```sh
node verify.mjs checkpoint latest.json
```

That checks:

1. The checkpoint signature against the published key named by its `kid`.
2. The leaf hash recomputed from the checkpoint.
3. The inclusion proof against the root of the anchor, with the RFC 9162 algorithm.
4. That the anchor served by Agentic is byte for byte the one mirrored here.

Then check that your checkpoint's `last_hash` matches your own export: `npx tsx scripts/verify-export.ts <export.json> --key https://useagentic.app/.well-known/jwks.json` in the Agentic repository verifies an evidence export's hash chain and checkpoint signatures offline.

## Timestamps

Each anchor file is stamped with [OpenTimestamps](https://opentimestamps.org), which is free and commits to Bitcoin through public calendar servers. A new proof is pending until a calendar's commitment is in a block, usually a few hours, and the next mirror runs upgrade it. To check one:

```sh
pip install opentimestamps-client
ots info anchors/000001.json.ots      # shows the attestations
ots verify anchors/000001.json.ots    # needs a local Bitcoin Core node
```

You can also drop the `.json` and `.json.ots` files on [opentimestamps.org](https://opentimestamps.org) to verify in the browser. A timestamp proves the file existed by that block, so an anchor rewritten later cannot carry an older proof.

## Limits

- This copy only protects anchors after they are mirrored. Until the next run, about 10 minutes, a change to the newest anchor would not be caught here.
- The repository lives on GitHub under the same owner as Agentic. Its git history and the OpenTimestamps proofs are what make silent changes detectable. Clone it to keep your own copy.
- An anchor proves which checkpoints existed and in what order. It does not reveal or prove anything about the audit events themselves, which stay private to each organization.

## License

Apache-2.0
