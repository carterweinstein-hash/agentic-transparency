// SPDX-License-Identifier: Apache-2.0
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { ANCHOR_TYP, ZERO_HASH, anchorHash, checkpointLeafData, keysFromJwks, leafHash, merkleRoot, thumbprint, verifyAnchorRecord, verifyCheckpointSignature, verifyInclusion, canonicalize } from "./lib.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const x = publicKey.export({ format: "jwk" }).x;
const kid = thumbprint({ x });
const keys = keysFromJwks({ keys: [{ kty: "OKP", crv: "Ed25519", x, kid, alg: "EdDSA", use: "sig" }] });
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

function anchor(seq, prev, leaves) {
  const root = `sha256:${merkleRoot(leaves.map((h) => Buffer.from(h, "hex"))).toString("hex")}`;
  const input = `${b64({ alg: "EdDSA", typ: ANCHOR_TYP, kid })}.${b64({ ver: 1, iss: "https://useagentic.app", seq, prev, root, tree_size: leaves.length, iat: 1800000000 + seq })}`;
  const jws = `${input}.${sign(null, Buffer.from(input), privateKey).toString("base64url")}`;
  return { seq, jws, prev_hash: prev, anchor_hash: anchorHash(jws), root, tree_size: leaves.length, leaves, kid, signed_at: new Date().toISOString() };
}
const leaves = () => Array.from({ length: 16 }, () => createHash("sha256").update(randomBytes(32)).digest("hex")).sort();

test("RFC 8037 thumbprint and RFC 6962 constants", () => {
  assert.equal(thumbprint({ x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  assert.equal(merkleRoot([]).toString("hex"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(leafHash("").toString("hex"), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
});

test("a chain verifies and every kind of rewrite is caught", () => {
  const a1 = anchor(1, ZERO_HASH, leaves());
  const a2 = anchor(2, anchorHash(a1.jws), leaves());
  assert.equal(verifyAnchorRecord(a1, keys, null), null);
  assert.equal(verifyAnchorRecord(a2, keys, a1), null);
  assert.match(verifyAnchorRecord(anchor(2, ZERO_HASH, leaves()), keys, a1), /prev is not the hash/);
  assert.match(verifyAnchorRecord(anchor(3, anchorHash(a1.jws), leaves()), keys, a1), /sequence gap/);
  assert.match(verifyAnchorRecord({ ...a2, leaves: [...a2.leaves.slice(1), "00".repeat(32)] }, keys, a1), /root does not match/);
  assert.match(verifyAnchorRecord({ ...a2, root: a1.root }, keys, a1), /does not match the signed claims/);
  const [h, , s] = a2.jws.split(".");
  assert.match(verifyAnchorRecord({ ...a2, jws: `${h}.${b64({ ver: 1, seq: 2 })}.${s}` }, keys, a1), /signature bad_signature/);
  assert.match(verifyAnchorRecord(a1, new Map(), null), /unknown_key/);
});

test("a checkpoint signature and inclusion proof verify", () => {
  const spki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const cp = { tenant_id: "7d4c0a52-6a43-4f0e-9a3b-2d0c1f4b9e11", last_seq: 9, last_hash: `sha256:${"ab".repeat(32)}`, signed_at: "2026-11-13T12:00:00.000Z", key_version: 1, public_key: spki };
  cp.signature = sign(null, Buffer.from(canonicalize({ tenant_id: cp.tenant_id, last_seq: 9, last_hash: cp.last_hash, signed_at: cp.signed_at, key_version: 1 })), privateKey).toString("base64");
  assert.equal(verifyCheckpointSignature(cp, keys), true);
  assert.equal(verifyCheckpointSignature({ ...cp, last_seq: 10 }, keys), false);
  const leaf = leafHash(checkpointLeafData(cp));
  const ls = [leaf, ...Array.from({ length: 3 }, () => leafHash(randomBytes(8)))];
  const root = merkleRoot(ls);
  // proof for index 0 in a tree of 4: sibling leaf, then the right subtree root
  const proof = [ls[1], merkleRoot(ls.slice(2))];
  assert.equal(verifyInclusion(leaf, 0, 4, proof, root), true);
  assert.equal(verifyInclusion(leaf, 1, 4, proof, root), false);
});
