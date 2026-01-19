# app.py
import time
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, parse_qs

import requests
import tldextract
import whois
import dns.resolver
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from rapidfuzz import fuzz
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dateutil.parser import parse as parse_date
import logging

# ---- Logging ----
logging.basicConfig(level=logging.INFO)

# ---- FastAPI app ----
app = FastAPI(title="URL Safety Backend")

# ---- CORS configuration ----
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---- Request model ----
class CheckRequest(BaseModel):
    url: str
    known_brand: str | None = None


# ---- Helpers ----
def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return url if parsed.scheme else "http://" + url


def get_redirect_chain(start_url: str, max_hops: int = 10):
    chain = []
    current = start_url
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (URL-Safety-Checker)"})

    for _ in range(max_hops):
        try:
            resp = session.get(current, allow_redirects=False, timeout=15)
            status = resp.status_code
        except Exception as e:
            chain.append({"url": current, "status": "ERR", "error": str(e)})
            break

        chain.append({"url": current, "status": status})

        if 300 <= status < 400 and "Location" in resp.headers:
            next_url = urljoin(current, resp.headers["Location"])
            if next_url == current:
                break
            current = next_url
        else:
            break

    return chain


def dns_lookup(domain: str):
    info = {"A": [], "CNAME": []}
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        info["A"] = [r.to_text() for r in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        info["CNAME"] = [r.to_text() for r in answers]
    except Exception:
        pass
    return info


# ---- FIXED SSL FUNCTION (IMPORTANT) ----
def fetch_ssl_info(hostname: str, port: int = 443, timeout: int = 6):
    data = {
        "present": False,
        "issuer": None,
        "subject": None,
        "notBefore": None,
        "notAfter": None,
        "expired": True,
        "san": [],
        "error": None
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())

                data["present"] = True
                data["issuer"] = cert.issuer.rfc4514_string()
                data["subject"] = cert.subject.rfc4514_string()

                # FIX: Attach timezone to avoid false expiration
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

                data["notBefore"] = not_before.isoformat()
                data["notAfter"] = not_after.isoformat()

                # FIX: Accurate expiry check
                now = datetime.now(timezone.utc)
                data["expired"] = now > not_after

                # SAN extraction
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    data["san"] = ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    data["san"] = []

    except Exception as e:
        data["error"] = str(e)
        data["expired"] = True

    return data


def whois_info(domain: str):
    result = {"domain": domain, "creation_date": None, "age_days": None,
              "registrar": None, "whois_raw": None, "whois_error": None}
    try:
        w = whois.whois(domain)
        result["whois_raw"] = str(w)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, str):
            created = parse_date(created)

        if created:
            ts = created.timestamp()
            result["creation_date"] = str(created)
            result["age_days"] = int((time.time() - ts) / 86400)

        result["registrar"] = w.registrar

    except Exception as e:
        result["whois_error"] = str(e)

    return result


def is_ip_host(host: str):
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def is_shortener_domain(domain: str):
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy"}
    return any(s in domain for s in shorteners)


def suspicious_word_check(url: str):
    suspicious_words = ["free", "reward", "verify", "login", "gift", "prize",
                        "claim", "secure", "update"]
    return any(w in url.lower() for w in suspicious_words)


def lookalike_score(domain: str, known_brand: str | None):
    if not known_brand:
        return {"score": 0, "reason": None}

    cand = tldextract.extract(domain).registered_domain or domain
    ratio = fuzz.ratio(cand.lower(), known_brand.lower())

    return {"score": int(ratio),
            "reason": f"similarity_ratio={ratio} between '{cand}' and '{known_brand}'"}


# ---- Affiliate Detection ----
def detect_affiliate_global(redirect_chain, original_url):
    affiliate_keywords = ["aff", "ref", "affiliate_id", "utm_source",
                          "partner", "tracking_id", "tag"]

    # Check original URL
    parsed_orig = urlparse(original_url)
    query_params_orig = parse_qs(parsed_orig.query)
    if any(k in query_params_orig for k in affiliate_keywords):
        return True, f"affiliate detected in original URL: {original_url}"

    # Check redirects
    for entry in redirect_chain:
        url = entry.get("url", "").lower()
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if any(k in query_params for k in affiliate_keywords):
            return True, f"affiliate redirect detected: {url}"

    return False, None


# ---- Risk computation ----
def compute_risk(data: dict):
    score = 0
    reasons = []

    if data.get("suspicious_word"):
        score += 10; reasons.append("suspicious_word_in_url")

    if data.get("is_ip"):
        score += 20; reasons.append("url_uses_ip_instead_of_domain")

    if data.get("is_shortener"):
        score += 8; reasons.append("uses_url_shortener")

    ssl_info = data.get("ssl", {})

    if not ssl_info.get("present", False):
        score += 15; reasons.append("no_ssl")

    if ssl_info.get("expired"):
        score += 12; reasons.append("ssl_expired")

    if len(data.get("redirect_chain", [])) > 3:
        score += 10; reasons.append("many_redirects")

    age = data.get("whois", {}).get("age_days")
    if age is not None and age < 30:
        score += 15; reasons.append("very_new_domain")

    lk_score = data.get("lookalike", {}).get("score", 0)
    if lk_score > 75:
        add = min(20, int((lk_score - 75) / 25 * 20) + 5)
        score += add
        reasons.append(f"looks_similar_to_known_brand ({data.get('lookalike', {}).get('reason')})")

    if data.get("affiliate"):
        score += 30
        reasons.append(f"affiliate_link_detected ({data.get('affiliate_reason')})")

    return {"score": min(score, 100), "reasons": reasons}


# ---- Main endpoint ----
@app.post("/check_url/")
def check_url(payload: CheckRequest):
    url_in = payload.url
    if not url_in:
        raise HTTPException(status_code=400, detail="No URL provided")

    url = normalize_url(url_in)
    host = urlparse(url).hostname or ""

    out = {"url": url, "timestamp": datetime.now(timezone.utc).isoformat()}

    out["redirect_chain"] = get_redirect_chain(url)
    out["dns"] = dns_lookup(host)

    out["ssl"] = (fetch_ssl_info(host)
                  if host and not is_ip_host(host)
                  else {"present": False, "error": "host is IP or missing", "expired": True})

    out["whois"] = whois_info(host)

    out["is_ip"] = is_ip_host(host)
    out["is_shortener"] = is_shortener_domain(host)
    out["suspicious_word"] = suspicious_word_check(url)
    out["lookalike"] = lookalike_score(host, payload.known_brand)

    out["affiliate"], out["affiliate_reason"] = detect_affiliate_global(
        out.get("redirect_chain", []), original_url=url)

    risk = compute_risk(out)
    out["risk_score"] = risk["score"]
    out["reasons"] = risk["reasons"]

    if out["risk_score"] >= 50:
        out["verdict"] = "DANGEROUS"
    elif out["risk_score"] >= 20:
        out["verdict"] = "SUSPICIOUS"
    else:
        out["verdict"] = "SAFE"

    return out


# ---- Health check ----
@app.get("/")
def root():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}
