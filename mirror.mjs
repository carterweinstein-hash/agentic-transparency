#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copies new signed anchors from Agentic into anchors/, verifying each one against the published keys and the
// previous mirrored anchor before writing it. Run by .github/workflows/mirror.yml. Exits 1 on any verification
// failure so the run fails visibly, and 0 without changes when the endpoints are not deployed yet.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { anchorFile, keysFromJwks, verifyAnchorRecord } from "./lib.mjs";

const BASE = (process.env.AGENTIC_URL ?? "https://useagentic.app").replace(/\/$/, "");
const dir = new URL(".", import.meta.url).pathname;
const anchorsDir = join(dir, "anchors");
mkdirSync(anchorsDir, { recursive: true });

async function get(path) {
  const res = await fetch(`${BASE}${path}`, { headers: { accept: "application/json", "user-agent": "agentic-transparency-mirror" } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${path} answered ${res.status}`);
  return res.json();
}

const jwks = await get("/.well-known/jwks.json");
const list0 = jwks && (await get("/api/v1/transparency/anchors?after_seq=0&limit=1"));
if (!jwks || !list0) {
  console.log("Anchors are not published at this address yet, nothing to do");
  process.exit(0);
}

// keys-history.json keeps every key ever published, so anchors signed before a revocation still verify here.
const historyPath = join(dir, "keys-history.json");
const history = existsSync(historyPath) ? JSON.parse(readFileSync(historyPath, "utf8")) : { keys: [] };
const byKid = new Map(history.keys.map((k) => [k.kid, k]));
for (const k of jwks.keys) byKid.set(k.kid, { ...byKid.get(k.kid), ...k });
const merged = { keys: [...byKid.values()].sort((a, b) => String(a.created_at ?? "").localeCompare(String(b.created_at ?? ""))) };
keysFromJwks(merged);
writeFileSync(historyPath, `${JSON.stringify(merged, null, 2)}\n`);
writeFileSync(join(dir, "jwks.json"), `${JSON.stringify({ keys: jwks.keys }, null, 2)}\n`);
const keys = keysFromJwks(merged);

const files = readdirSync(anchorsDir).filter((f) => /^\d{6}\.json$/.test(f)).sort();
let previous = files.length ? JSON.parse(readFileSync(join(anchorsDir, files.at(-1)), "utf8")) : null;
let added = 0;
if (previous) {
  const remote = await get(`/api/v1/transparency/anchors/${previous.seq}`);
  if (!remote || remote.jws !== previous.jws) {
    console.error(`Anchor ${previous.seq} served now differs from the copy mirrored earlier. History was changed.`);
    process.exit(1);
  }
}
for (;;) {
  const page = await get(`/api/v1/transparency/anchors?after_seq=${previous?.seq ?? 0}&limit=200`);
  const items = page?.data ?? [];
  for (const item of items) {
    const full = await get(`/api/v1/transparency/anchors/${item.seq}`);
    if (!full) throw new Error(`anchor ${item.seq} disappeared`);
    const rec = { seq: full.seq, jws: full.jws, prev_hash: full.prev_hash, anchor_hash: full.anchor_hash, root: full.root, tree_size: full.tree_size, leaves: full.leaves, kid: full.kid, signed_at: full.signed_at };
    const err = verifyAnchorRecord(rec, keys, previous);
    if (err) {
      console.error(`Verification failed, nothing after seq ${previous?.seq ?? 0} was written: ${err}`);
      process.exit(1);
    }
    writeFileSync(join(anchorsDir, anchorFile(rec.seq)), `${JSON.stringify(rec, null, 2)}\n`);
    previous = rec;
    added++;
  }
  if (!page?.next_after_seq) break;
}
console.log(`Mirrored ${added} new anchors${previous ? `, head seq ${previous.seq}` : ""}`);
