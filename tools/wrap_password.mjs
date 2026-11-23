#!/usr/bin/env node
// Wraps the hub master key under a password → data/passwrap.json.
// The lock screen then accepts this password as well as the raw recovery key.
// Usage: node tools/wrap_password.mjs "your passphrase"
// Re-run with a new phrase any time; the old one stops working on push.
import { webcrypto as wc } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pw = process.argv[2];
if (!pw) { console.error('usage: node tools/wrap_password.mjs "passphrase"'); process.exit(1); }

const keyHex = readFileSync(join(homedir(), ".artemis", "hub-master-key"), "utf8").trim();
const master = Buffer.from(keyHex, "hex");

const ITER = 600000;
const salt = wc.getRandomValues(new Uint8Array(16));
const base = await wc.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
const kek = await wc.subtle.deriveKey(
  { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER },
  base, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
);
const iv = wc.getRandomValues(new Uint8Array(12));
const wrapped = new Uint8Array(await wc.subtle.encrypt({ name: "AES-GCM", iv }, kek, master));

writeFileSync(join(ROOT, "data/passwrap.json"), JSON.stringify({
  v: 1, kdf: "PBKDF2-SHA256", iter: ITER,
  salt: Buffer.from(salt).toString("base64"),
  wrapIv: Buffer.from(iv).toString("base64"),
  wrappedKey: Buffer.from(wrapped).toString("base64"),
}));
console.log(`data/passwrap.json written (PBKDF2 ${ITER} rounds). Commit and push to activate.`);
if (pw.length < 12 || /^[a-z]+$/i.test(pw)) {
  console.log("WARNING: short/dictionary passwords can be brute-forced offline from the public repo. Prefer a long phrase.");
}
