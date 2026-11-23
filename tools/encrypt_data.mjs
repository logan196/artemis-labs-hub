#!/usr/bin/env node
// Encrypts the hub's private content into data/payload.enc.json.
//
// Collects data/labs.json + data/renderings.json plus every local image/video
// they reference (PI photos, institution logos, renderings) so neither the
// client roster nor any identifying filename or byte lands in the public repo.
//
// Key: 32 bytes hex at ~/.artemis/hub-master-key (created on first run).
// That hex string is also the recovery key accepted by the lock screen.
// Publish flow: python3 tools/build_data.py && node tools/encrypt_data.mjs && git push
import { webcrypto as wc } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const KEY_PATH = join(homedir(), ".artemis", "hub-master-key");

let fresh = false;
if (!existsSync(KEY_PATH)) {
  mkdirSync(dirname(KEY_PATH), { recursive: true });
  writeFileSync(KEY_PATH, Buffer.from(wc.getRandomValues(new Uint8Array(32))).toString("hex") + "\n");
  chmodSync(KEY_PATH, 0o600);
  fresh = true;
}
const keyHex = readFileSync(KEY_PATH, "utf8").trim();
if (!/^[0-9a-f]{64}$/i.test(keyHex)) throw new Error(`${KEY_PATH} must be 64 hex chars`);

const labs = JSON.parse(readFileSync(join(ROOT, "data/labs.json"), "utf8"));
const renderings = JSON.parse(readFileSync(join(ROOT, "data/renderings.json"), "utf8"));

// Gather every repo-relative asset path mentioned anywhere in the two JSONs.
const images = {};
const seen = new Set();
(function walk(v) {
  if (typeof v === "string") {
    if (/^(assets|renderings)\//.test(v) && !seen.has(v)) {
      seen.add(v);
      const p = join(ROOT, v);
      if (existsSync(p)) images[v] = readFileSync(p).toString("base64");
    }
  } else if (Array.isArray(v)) v.forEach(walk);
  else if (v && typeof v === "object") Object.values(v).forEach(walk);
})([labs, renderings]);

// The brand mark stays public (used by the shell favicon); don't duplicate it.
delete images["assets/marks/artemis_mark.svg"];

const plaintext = new TextEncoder().encode(JSON.stringify({ labs, renderings, images }));
const iv = wc.getRandomValues(new Uint8Array(12));
const key = await wc.subtle.importKey("raw", Buffer.from(keyHex, "hex"), "AES-GCM", false, ["encrypt"]);
const ct = new Uint8Array(await wc.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));

const out = {
  v: 1,
  iv: Buffer.from(iv).toString("base64"),
  ct: Buffer.from(ct).toString("base64"),
};
writeFileSync(join(ROOT, "data/payload.enc.json"), JSON.stringify(out));
console.log(`payload.enc.json written: ${(ct.length / 1024).toFixed(0)} KB ciphertext, ${Object.keys(images).length} embedded assets`);
if (fresh) {
  console.log(`\nNEW MASTER KEY created at ${KEY_PATH}`);
  console.log("This hex string is the recovery key — store a copy in iCloud Keychain or 1Password:");
  console.log(keyHex);
}
