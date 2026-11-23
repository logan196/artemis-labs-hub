# Artemis Biolabs · All labs

A static client hub for every lab Artemis Biolabs has built work for: lab pages, report cards, and a particle landing for each report that opens the live portal.

- Live: https://logan196.github.io/artemis-labs-hub/
- Content is **encrypted at rest**: `data/labs.json` + `data/renderings.json` + every referenced PI photo/logo/hero image are packed into `data/payload.enc.json` (AES-256-GCM). Plaintext stays local only (gitignored).
- Unlock: Touch ID (WebAuthn passkey + PRF extension; enroll once at `setup.html`, which emits `data/keywrap.json`) or the recovery key — the hex in `~/.artemis/hub-master-key`.
- Publish flow: `python3 tools/build_data.py && node tools/encrypt_data.mjs && git commit && git push`.
- Renderings: drop files in `renderings/` and list them in `data/renderings.json` (see `renderings/README.md`). The hub and lab pages show them automatically.
- Routes: `#/` all labs, `#/lab/<id>` one lab, `#/lab/<id>/<report>` a report landing.
- No build step, no plaintext client data in the repo. Three.js r170 is vendored in `vendor/` (MIT, see `vendor/three.LICENSE.txt`). Fonts: Inter and Source Serif 4 (SIL OFL).

Independent demos built from public data. Not affiliated with or endorsed by the labs shown.
