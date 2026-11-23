#!/usr/bin/env node
// Inverse of encrypt_data.mjs: restores data/labs.json, data/renderings.json
// and every embedded asset from data/payload.enc.json using the master key.
// Run after a fresh clone (plaintext is gitignored and lives only locally).
import { webcrypto as wc } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const keyHex = readFileSync(join(homedir(), ".artemis", "hub-master-key"), "utf8").trim();
const env = JSON.parse(readFileSync(join(ROOT, "data/payload.enc.json"), "utf8"));
const b64d = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const key = await wc.subtle.importKey("raw", Buffer.from(keyHex, "hex"), "AES-GCM", false, ["decrypt"]);
const pt = await wc.subtle.decrypt({ name: "AES-GCM", iv: b64d(env.iv) }, key, b64d(env.ct));
const { labs, renderings, images } = JSON.parse(new TextDecoder().decode(pt));

writeFileSync(join(ROOT, "data/labs.json"), JSON.stringify(labs, null, 1));
writeFileSync(join(ROOT, "data/renderings.json"), JSON.stringify(renderings, null, 1));
let n = 0;
for (const [path, data] of Object.entries(images || {})) {
  const p = join(ROOT, path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, Buffer.from(data, "base64"));
  n++;
}
console.log(`restored labs.json, renderings.json and ${n} assets`);
