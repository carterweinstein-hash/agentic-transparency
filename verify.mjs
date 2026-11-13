#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Verifies the mirrored anchors in this repository, and optionally that a checkpoint is included in one.
//
//   node verify.mjs                          check every anchor in anchors/ against keys-history.json
//   node verify.mjs --jwks <file|url>        check against another key set, for example the live JWKS
//   node verify.mjs checkpoint latest.json   also check a saved /api/v1/audit/checkpoints/latest response
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { anchorFile, checkpointLeafData, keysFromJwks, leafHash, verifyAnchorRecord, verifyCheckpointSignature, verifyInclusion } from "./lib.mjs";

const args = process.argv.slice(2);
const dir = new URL(".", import.meta.url).pathname;
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

async function loadKeys() {
  const src = flag("--jwks") ?? join(dir, "keys-history.json");
  const doc = /^https?:\/\//.test(src) ? await (await fetch(src)).json() : JSON.parse(readFileSync(src, "utf8"));
  return keysFromJwks(doc);
}

function fail(msg) {
  console.error(`FAIL ${msg}`);
  process.exit(1);
}

const keys = await loadKeys();
const anchorsDir = join(dir, "anchors");
const files = existsSync(anchorsDir) ? readdirSync(anchorsDir).filter((f) => /^\d{6}\.json$/.test(f)).sort() : [];
let previous = null;
for (const f of files) {
  const rec = JSON.parse(readFileSync(join(anchorsDir, f), "utf8"));
  if (f !== anchorFile(rec.seq)) fail(`${f} holds seq ${rec.seq}`);
  const err = verifyAnchorRecord(rec, keys, previous);
  if (err) fail(err);
  previous = rec;
}
console.log(`ok ${files.length} anchors, chain intact${previous ? `, head seq ${previous.seq} ${previous.anchor_hash}` : ""}`);

const ci = args.indexOf("checkpoint");
if (ci >= 0) {
  const body = JSON.parse(readFileSync(args[ci + 1], "utf8"));
  const cp = body.checkpoint;
  const a = body.anchor;
  if (!cp) fail("the response has no checkpoint");
  if (!verifyCheckpointSignature(cp, keys)) fail("checkpoint signature does not verify against the key set");
  if (!a) fail("the checkpoint is not anchored yet, try again after the next worker run");
  const mirrored = join(anchorsDir, anchorFile(a.anchor_seq));
  if (!existsSync(mirrored)) fail(`anchor ${a.anchor_seq} is not mirrored here yet`);
  const rec = JSON.parse(readFileSync(mirrored, "utf8"));
  if (rec.jws !== a.anchor_jws) fail(`anchor ${a.anchor_seq} served by the API differs from the mirrored copy`);
  const leaf = leafHash(checkpointLeafData(cp));
  if (leaf.toString("hex") !== a.leaf_hash) fail("the leaf hash does not match the checkpoint");
  if (!verifyInclusion(leaf, a.leaf_index, rec.tree_size, a.proof.map((p) => Buffer.from(p, "hex")), Buffer.from(rec.root.slice(7), "hex"))) fail("inclusion proof does not verify");
  console.log(`ok checkpoint last_seq ${cp.last_seq} of ${cp.tenant_id} is leaf ${a.leaf_index} of anchor ${a.anchor_seq}`);
}
