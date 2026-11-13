// SPDX-License-Identifier: Apache-2.0
// Verification for Agentic transparency anchors. Node 20 or later, no dependencies.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

export const ANCHOR_TYP = "agentic-anchor+jwt";
export const ZERO_HASH = `sha256:${"0".repeat(64)}`;

const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
export const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");
export const anchorHash = (jws) => `sha256:${sha256Hex(jws)}`;

/** RFC 8785 canonical JSON for the value shapes used here: objects, arrays, strings, integers, booleans, null. */
export function canonicalize(v) {
  if (v === null) return "null";
  if (typeof v === "boolean" || typeof v === "number") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("non finite number");
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map((x) => canonicalize(x === undefined ? null : x)).join(",")}]`;
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
}

/** RFC 7638 thumbprint of an Ed25519 public JWK. */
export const thumbprint = (jwk) => createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest("base64url");
export const jwkFromSpki = (spkiB64) => {
  const j = createPublicKey({ key: Buffer.from(spkiB64, "base64"), format: "der", type: "spki" }).export({ format: "jwk" });
  return { kty: "OKP", crv: "Ed25519", x: j.x };
};

// RFC 6962 hashing
export const leafHash = (data) => sha(Buffer.from([0]), Buffer.from(data));
const nodeHash = (l, r) => sha(Buffer.from([1]), l, r);
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha();
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}
/** RFC 9162 section 2.1.3.2. */
export function verifyInclusion(leaf, index, size, proof, root) {
  if (index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

/** Keys by kid from a JWKS document. Revoked keys are never in it. */
export function keysFromJwks(jwks) {
  const m = new Map();
  for (const k of jwks.keys ?? []) {
    if (k.kty !== "OKP" || k.crv !== "Ed25519" || typeof k.x !== "string") continue;
    if (thumbprint(k) !== k.kid) throw new Error(`JWKS key ${k.kid} does not match its thumbprint`);
    m.set(k.kid, k);
  }
  return m;
}

/** Verifies a compact JWS whose header must be exactly {alg: EdDSA, typ, kid}. */
export function verifyJws(jws, typ, keys) {
  const parts = typeof jws === "string" ? jws.split(".") : [];
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return { error: "malformed" };
  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  } catch {
    return { error: "malformed" };
  }
  if (Object.keys(header).sort().join(",") !== "alg,kid,typ" || header.alg !== "EdDSA" || header.typ !== typ) return { error: "bad_header" };
  const jwk = keys.get(header.kid);
  if (!jwk) return { error: "unknown_key" };
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  if (!edVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], "base64url"))) return { error: "bad_signature" };
  return { header, payload };
}

/**
 * Checks one anchor record (the body of /api/v1/transparency/anchors/{seq}) on its own and against the record
 * before it: signature, claims matching the record, root recomputed from the leaves, seq and prev chaining.
 */
export function verifyAnchorRecord(rec, keys, previous) {
  const v = verifyJws(rec.jws, ANCHOR_TYP, keys);
  if (v.error) return `seq ${rec.seq}: signature ${v.error}`;
  const c = v.payload;
  if (c.ver !== 1) return `seq ${rec.seq}: unknown version`;
  if (c.seq !== rec.seq || c.prev !== rec.prev_hash || c.root !== rec.root || c.tree_size !== rec.tree_size || v.header.kid !== rec.kid) return `seq ${rec.seq}: record does not match the signed claims`;
  if (rec.anchor_hash !== anchorHash(rec.jws)) return `seq ${rec.seq}: anchor_hash is not the hash of the JWS`;
  if (!Array.isArray(rec.leaves) || rec.leaves.length !== c.tree_size) return `seq ${rec.seq}: leaf count differs from tree_size`;
  const root = `sha256:${merkleRoot(rec.leaves.map((h) => Buffer.from(h, "hex"))).toString("hex")}`;
  if (root !== c.root) return `seq ${rec.seq}: root does not match the leaves`;
  if (previous === null) {
    if (c.seq !== 1 || c.prev !== ZERO_HASH) return `seq ${rec.seq}: the first anchor must have seq 1 and a zero prev`;
  } else if (previous !== undefined) {
    if (c.seq !== previous.seq + 1) return `seq ${rec.seq}: sequence gap after ${previous.seq}`;
    if (c.prev !== anchorHash(previous.jws)) return `seq ${rec.seq}: prev is not the hash of anchor ${previous.seq}`;
  }
  return null;
}

/** The leaf data for a checkpoint as returned by /api/v1/audit/checkpoints/latest. */
export const checkpointLeafData = (cp) =>
  canonicalize({ type: "agentic.checkpoint.v1", tenant_id: cp.tenant_id, last_seq: Number(cp.last_seq), last_hash: cp.last_hash, signed_at: new Date(cp.signed_at).toISOString(), kid: thumbprint(jwkFromSpki(cp.public_key)) });

/** Checkpoint signature: Ed25519 over canonical {tenant_id, last_seq, last_hash, signed_at, key_version}. */
export function verifyCheckpointSignature(cp, keys) {
  const kid = thumbprint(jwkFromSpki(cp.public_key));
  const jwk = keys.get(kid);
  if (!jwk) return false;
  const msg = canonicalize({ tenant_id: cp.tenant_id, last_seq: Number(cp.last_seq), last_hash: cp.last_hash, signed_at: cp.signed_at, key_version: cp.key_version });
  return edVerify(null, Buffer.from(msg), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }), Buffer.from(cp.signature, "base64"));
}

export const anchorFile = (seq) => `${String(seq).padStart(6, "0")}.json`;
