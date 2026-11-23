// Unlock layer for the Artemis client hub.
//
// The hub's content ships only as data/payload.enc.json (AES-256-GCM).
// The 32-byte master key is never in the repo; it arrives one of two ways:
//   1. Touch ID — a WebAuthn passkey assertion with the PRF extension yields a
//      per-credential secret; HKDF of it unwraps the master key stored
//      (wrapped) in data/keywrap.json.
//   2. Recovery — the raw master-key hex pasted by hand.
// The unwrapped key is kept in sessionStorage for the tab's lifetime only.

const SS_KEY = "artemis_hub_mk";
const HKDF_SALT = new TextEncoder().encode("artemis-hub-v1");
const HKDF_INFO = new TextEncoder().encode("artemis-hub-wrap-v1");

export const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};
export const hex = {
  enc: (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join(""),
  dec: (s) => Uint8Array.from(s.match(/.{2}/g).map((h) => parseInt(h, 16))),
};

export async function deriveKEK(prfOutput) {
  const base = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: HKDF_INFO },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

export async function wrapMaster(kek, masterRaw) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, masterRaw);
  return { wrapIv: b64.enc(iv), wrappedKey: b64.enc(ct) };
}

export async function unwrapMaster(kek, keywrap) {
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.dec(keywrap.wrapIv) }, kek, b64.dec(keywrap.wrappedKey),
  );
  return new Uint8Array(raw);
}

// Touch ID assertion that evaluates the PRF extension. Throws if the browser
// or credential cannot produce PRF output.
export async function assertPRF(keywrap) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: b64.dec(keywrap.credId) }],
      userVerification: "required",
      timeout: 60000,
      extensions: { prf: { eval: { first: b64.dec(keywrap.prfSalt) } } },
    },
  });
  const prf = cred.getClientExtensionResults()?.prf?.results?.first;
  if (!prf) throw new Error("no-prf");
  return prf;
}

export async function fetchKeywrap() {
  try {
    const r = await fetch("data/keywrap.json", { cache: "no-store" });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

export async function decryptPayload(masterRaw) {
  const env = await (await fetch("data/payload.enc.json")).json();
  const key = await crypto.subtle.importKey("raw", masterRaw, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(env.iv) }, key, b64.dec(env.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

export function remember(masterRaw) { try { sessionStorage.setItem(SS_KEY, hex.enc(masterRaw)); } catch {} }
export function forget() { try { sessionStorage.removeItem(SS_KEY); } catch {} }

// Returns the decrypted payload if this tab already unlocked, else null.
export async function tryResume() {
  const h = (() => { try { return sessionStorage.getItem(SS_KEY); } catch { return null; } })();
  if (!h || !/^[0-9a-f]{64}$/i.test(h)) return null;
  try { return await decryptPayload(hex.dec(h)); }
  catch { forget(); return null; }
}

// Turns the payload's embedded assets into blob URLs and rewrites every
// reference inside labs/renderings so the rest of the app is unchanged.
const MIME = { webp: "image/webp", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", svg: "image/svg+xml", gif: "image/gif", mp4: "video/mp4", webm: "video/webm" };
export function hydrate(payload) {
  const urls = {};
  for (const [path, data] of Object.entries(payload.images || {})) {
    const ext = path.split(".").pop().toLowerCase();
    urls[path] = URL.createObjectURL(new Blob([b64.dec(data)], { type: MIME[ext] || "application/octet-stream" }));
  }
  const walk = (v) => {
    if (typeof v === "string") return urls[v] || v;
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return { DATA: walk(payload.labs), REND: walk(payload.renderings) };
}
