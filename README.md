# URL Safety Checker

A Chrome extension (Manifest V3) paired with a FastAPI backend that evaluates a webpage in real time and flags it as **Safe**, **Suspicious**, or **Dangerous**. It inspects SSL certificate validity, domain age (WHOIS), redirect chains, DNS records, and phishing/affiliate-link indicators, then shows the verdict as an in-page popup.

## Features

- **Automatic page scanning** — runs on every page load and overlays a verdict card in the top-right corner
- **SSL certificate inspection** — issuer, subject, validity window, SAN entries, and expiry status
- **WHOIS domain age lookup** — flags very recently registered domains
- **Redirect chain tracing** — follows up to 10 hops and records status codes
- **DNS resolution** — A and CNAME records for the target host
- **IP-literal host detection** — flags URLs that use a raw IP instead of a domain
- **URL shortener detection** — bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, rb.gy
- **Suspicious keyword detection** — words like `free`, `verify`, `login`, `prize`, `claim` in the URL
- **Brand look-alike detection** — fuzzy-matches the domain against a known brand name (RapidFuzz)
- **Affiliate / tracking link detection** — flags query params such as `ref`, `aff`, `utm_source`, `tag`, with extra client-side checks in the extension itself
- **Weighted risk scoring** — combines all signals into a single 0–100 score and verdict

## How it works

```
Page loads
   │
   ▼
content.js  ──sends current URL──▶  background.js (service worker)
                                          │
                                          ▼
                          POST http://127.0.0.1:8000/check_url/
                                          │
                                          ▼
                     FastAPI backend: redirect trace, DNS, SSL,
                     WHOIS, heuristics, weighted risk score
                                          │
                                          ▼
                          background.js layers an extra
                          client-side affiliate-keyword check
                                          │
                                          ▼
                     content.js renders the verdict card in-page
                     (with Continue / Block controls if an
                     affiliate/tracking link was detected)
```

## Tech stack

| Layer     | Technology |
|-----------|------------|
| Backend   | Python, FastAPI, Uvicorn |
| Analysis  | `requests`, `dnspython`, `python-whois`, `tldextract`, `rapidfuzz`, `cryptography` |
| Extension | Vanilla JavaScript, Chrome Extension Manifest V3 |

## Project structure

```
url-safety-checker/
├── app.py             # FastAPI backend — URL analysis & risk scoring
├── requirements.txt   # Python dependencies
├── manifest.json      # Chrome extension manifest (MV3)
├── background.js      # Service worker — talks to the backend
├── content.js         # Injected script — renders the in-page verdict popup
├── popup.html          # Extension toolbar popup UI
├── popup.js             # Popup UI logic
├── icon128.png           # Extension icon
├── _env                    # Placeholder for environment variables (currently unused)
└── README.md
```

## Prerequisites

- Python 3.10+
- Google Chrome (or any Chromium-based browser that supports MV3)

## Setup

### 1. Backend

```bash
git clone https://github.com/<your-username>/url-safety-checker.git
cd url-safety-checker

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Confirm it's running by visiting `http://127.0.0.1:8000/` — you should see:

```json
{"status": "ok", "time": "..."}
```

> The extension is hardcoded to call `http://127.0.0.1:8000`, so the backend must be running locally on port 8000 before you browse.

### 2. Chrome extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the project folder (the one containing `manifest.json`)
5. Pin the extension icon for quick access (optional)

## Usage

With the backend running, every page you visit is scanned automatically. A card appears in the top-right corner showing the verdict, risk score, SSL expiry, domain age, the reasons behind the score, and the redirect chain. If an affiliate or tracking link is detected, you'll also get **Continue** / **Block** options.

## API reference

### `POST /check_url/`

**Request body**

```json
{
  "url": "http://example.com/page?ref=123",
  "known_brand": "example"
}
```

`known_brand` is optional — when provided, the domain is fuzzy-matched against it to catch look-alike/typosquat domains.

**Response body (abridged)**

```json
{
  "url": "http://example.com/page?ref=123",
  "timestamp": "2026-08-06T12:00:00+00:00",
  "redirect_chain": [{ "url": "http://example.com/page?ref=123", "status": 200 }],
  "dns": { "A": ["93.184.216.34"], "CNAME": [] },
  "ssl": { "present": true, "issuer": "...", "expired": false, "notAfter": "..." },
  "whois": { "creation_date": "...", "age_days": 9125, "registrar": "..." },
  "is_ip": false,
  "is_shortener": false,
  "suspicious_word": false,
  "lookalike": { "score": 100, "reason": "similarity_ratio=100 between 'example.com' and 'example'" },
  "affiliate": true,
  "affiliate_reason": "affiliate detected in original URL: http://example.com/page?ref=123",
  "risk_score": 30,
  "reasons": ["affiliate_link_detected (...)"],
  "verdict": "SUSPICIOUS"
}
```

### `GET /`

Health check — returns `{"status": "ok", "time": "..."}`.

## Risk scoring

Each signal adds points to a 0–100 score (capped at 100):

| Signal | Points |
|---|---|
| Suspicious word in URL | +10 |
| IP address instead of domain | +20 |
| Known URL shortener | +8 |
| No SSL certificate | +15 |
| SSL certificate expired | +12 |
| More than 3 redirects | +10 |
| Domain registered < 30 days ago | +15 |
| Look-alike match to known brand (similarity > 75) | +5 to +20 (scaled) |
| Affiliate/tracking link detected | +30 |

**Verdict thresholds**

| Score | Verdict |
|---|---|
| ≥ 50 | 🔴 DANGEROUS |
| 20–49 | 🟡 SUSPICIOUS |
| < 20 | 🟢 SAFE |

## Known limitations / roadmap

- The popup's **"Check This Page"** button sends a `check_url_manual` message, but `content.js` doesn't currently listen for it — manual re-scans from the popup aren't wired up yet.
- The `management` permission and the "suspicious extensions" warning banner in `popup.html` are UI-ready but `background.js` doesn't yet detect or report installed extensions.
- The backend has no authentication or rate limiting — anything able to reach `127.0.0.1:8000` can call it.
- CORS is currently wide open (`allow_origins=["*"]`); tighten this before running the backend anywhere beyond localhost.
- WHOIS lookups depend on each registrar's WHOIS server and can be slow or fail for some TLDs.
- `_env` is an empty placeholder — no environment variables are read by `app.py` at the moment.

## Disclaimer

This tool produces a heuristic risk indicator, not a definitive security verdict. Use it as one input among others, and use your own judgment — especially on pages asking for credentials or payment details.

## License

No license file is currently included. Add one (e.g., MIT) if you plan to share or accept contributions to this project.
