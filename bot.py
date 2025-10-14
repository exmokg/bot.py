#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MAX DNS/SSL/WHOIS/NET Telegram Bot — «всё в одном», расширенная версия
Фичи сверх базовой:
- ⚡ Параллельные запросы (asyncio.gather + семафоры), ускоренная проверка propagation
- 🧠 TTL-кэш (async) для DNS/HTTP/WHOIS (уменьшает нагрузку)
- 🔐 DNS-over-HTTPS (Cloudflare/Google) в дополнение к классическому DNS
- 📫 Глубже почтовые проверки: парсер DMARC/SPF, DKIM по selector
- 🌐 HTTP анализ: редирект-цепочка, HSTS, CSP, CORS, cookies (Secure/HttpOnly/SameSite), x-заголовки
- 🚀 HTTP/2 (ALPN h2) детект, замер таймингов (DNS/Connect/TTFB/Total) через aiohttp Trace
- 🔒 TLS: версия, cipher, ALPN, OCSP stapling (если доступно в SSL), протоколы TLS1.0..1.3
- 🧾 Экспорт полного аудита /audit в JSON и Markdown, отправка файла
- 🧰 Утилиты: пароли/QR/hash/Base64/цвета/единицы/времена + улучшения
- 🧯 Троттлинг (token bucket) на пользователя (защита от спама тяжёлыми задачами)
- 📜 JSON-логи в файл + аккуратные ошибки
"""

import asyncio
import logging
import json
import os
import re
import time
import ssl
import platform
import base64
import ipaddress
import string
import secrets
import hashlib
import qrcode
import nmap
import tempfile
import zipfile
import io
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from PIL import Image
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

# ===== third-party =====
import aiohttp
import dns.resolver
import dns.reversename
import dns.exception
import dns.rdatatype

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardButton, BufferedInputFile
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

# ================== CONFIG ==================
BOT_TOKEN = os.getenv("BOT_TOKEN", "8397920275:AAGoDwL7SDG9d4G60zFfgjOWyM_iYiTRir0")
LOG_FILE = os.getenv("LOG_FILE", "bot.log.jsonl")
DEFAULT_TIMEOUT = 6.0
MAX_PARALLEL = 20  # глобальная конкуренция для «веерных» проверок
PROPAGATION_NS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    "64.6.64.6", "64.6.65.6", "76.76.2.0", "76.76.10.0", "4.2.2.2"
]

# ================== LOGGING ==================
class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.utcnow().isoformat()+"Z",
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "name": record.name,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

logger = logging.getLogger("maxbot")
logger.setLevel(logging.INFO)
_sh = logging.StreamHandler()
_sh.setFormatter(JsonFormatter())
logger.addHandler(_sh)
if LOG_FILE:
    _fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _fh.setFormatter(JsonFormatter())
    logger.addHandler(_fh)

# ================== TTL CACHE (async) ==================
class AsyncTTLCache:
    def __init__(self, maxsize=256, ttl=300):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data: OrderedDict = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key):
        async with self._lock:
            if key in self._data:
                ts, val = self._data[key]
                if time.time() - ts < self.ttl:
                    self._data.move_to_end(key, last=True)
                    return val
                else:
                    self._data.pop(key, None)
            return None

    async def set(self, key, value):
        async with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key, last=True)
            if len(self._data) > self.maxsize:
                self._data.popitem(last=False)

def async_ttl_cached(cache: AsyncTTLCache):
    def deco(fn):
        async def wrapped(*args, **kwargs):
            key = (fn.__name__, args[1:], tuple(sorted(kwargs.items())))
            hit = await cache.get(key)
            if hit is not None:
                return hit
            res = await fn(*args, **kwargs)
            await cache.set(key, res)
            return res
        return wrapped
    return deco

# ================== RATE LIMITER (per user) ==================
class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate = rate_per_sec
        self.capacity = capacity
        self.tokens = capacity
        self.updated = time.monotonic()

    def allow(self, n=1) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

rate_map: Dict[int, TokenBucket] = defaultdict(lambda: TokenBucket(rate_per_sec=1.5, capacity=6))

def ensure_rate(user_id: int, cost=1) -> bool:
    return rate_map[user_id].allow(cost)

# ================== HELPERS ==================
def is_valid_domain(d: str) -> bool:
    if not d or len(d) > 253: return False
    if d.endswith("."): d = d[:-1]
    return re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$", d) is not None

def code_list(items: List[str], limit=8) -> str:
    if not items: return "—"
    return "\n".join(f"• <code>{x}</code>" for x in items[:limit])

def guess_ns_location(ip: str) -> str:
    mapping = {
        "8.8.": "Google", "8.8.4.": "Google", "1.1.": "Cloudflare", "1.0.": "Cloudflare",
        "9.9.": "Quad9", "149.112.": "Quad9", "208.67.": "OpenDNS", "94.140.": "AdGuard",
        "64.6.": "Neustar", "76.76.": "ControlD", "4.2.2.": "Level3/Verizon"
    }
    for p, name in mapping.items():
        if ip.startswith(p): return f"{name} (Global)"
    return "Unknown"

# ================== CORE SERVICES ==================
dns_cache = AsyncTTLCache(ttl=180, maxsize=512)
http_cache = AsyncTTLCache(ttl=120, maxsize=256)
whois_cache = AsyncTTLCache(ttl=600, maxsize=128)

class DNS:
    TYPES = ["A","AAAA","MX","NS","TXT","CNAME","SOA","PTR","SRV","CAA","DS","DNSKEY"]

    def __init__(self):
        self.sema = asyncio.Semaphore(MAX_PARALLEL)

    @async_ttl_cached(dns_cache)
    async def resolve(self, qname: str, rtype: str, nameserver: Optional[str]=None, timeout: float=DEFAULT_TIMEOUT) -> Dict[str,Any]:
        resolver = dns.resolver.Resolver(configure=(nameserver is None))
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.lifetime = timeout
        try:
            ans = resolver.resolve(qname, rtype, raise_on_no_answer=False)
            recs = [r.to_text() for r in ans] if ans else []
            ttl = getattr(ans.rrset, 'ttl', None) if ans and ans.rrset else None
            return {"success": True, "records": recs, "ttl": ttl, "ns": nameserver or ",".join(resolver.nameservers)}
        except Exception as e:
            return {"success": False, "error": str(e), "records": [], "ttl": None, "ns": nameserver or ""}

    async def doh_query(self, qname: str, rtype: str, provider: str="cloudflare") -> Dict[str,Any]:
        url = None
        if provider == "cloudflare":
            url = f"https://cloudflare-dns.com/dns-query?name={qname}&type={rtype}"
        elif provider == "google":
            url = f"https://dns.google/resolve?name={qname}&type={rtype}"
        else:
            return {"success": False, "error": "Неизвестный DoH провайдер"}
        headers = {"accept": "application/dns-json"}
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers, timeout=DEFAULT_TIMEOUT) as r:
                    js = await r.json()
                    ans = js.get("Answer", []) or []
                    recs = []
                    for a in ans:
                        if rtype.upper() == "TXT" and "data" in a:
                            recs.append(a["data"].strip('"'))
                        elif "data" in a:
                            recs.append(a["data"])
                    return {"success": True, "records": recs, "doh": provider, "status": js.get("Status")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def propagation(self, domain: str, rtype: str="A") -> Dict[str,Any]:
        base = await self.resolve(domain, rtype)
        base_set = set(base.get("records", []))
        async def run(ns):
            async with self.sema:
                r = await self.resolve(domain, rtype, nameserver=ns)
                st = "error"
                if r["success"]:
                    rs = set(r["records"])
                    st = "propagated" if (base_set and rs == base_set) or (not base_set and rs) else "differs"
                return ns, {"status": st, "records": r.get("records", []), "location": guess_ns_location(ns)}
        items = await asyncio.gather(*(run(ns) for ns in PROPAGATION_NS))
        res = dict(items)
        ok = sum(1 for v in res.values() if v["status"]=="propagated")
        pct = int(ok*100/len(PROPAGATION_NS)) if PROPAGATION_NS else 0
        return {"domain": domain, "rtype": rtype, "ok": ok, "total": len(PROPAGATION_NS), "pct": pct, "results": res}

    async def all_records(self, domain: str) -> Dict[str,Any]:
        async def q(t):
            return t, await self.resolve(domain, t)
        pairs = await asyncio.gather(*(q(t) for t in self.TYPES))
        data = {k:v for k,v in pairs}
        ok = sum(1 for t in self.TYPES if data[t].get("records"))
        return {"domain": domain, "records": data, "ok": ok, "total": len(self.TYPES)}

    async def reverse_ptr(self, ip: str) -> Dict[str,Any]:
        try:
            rev = dns.reversename.from_address(ip)
            r = await self.resolve(str(rev), "PTR")
            return {"success": r["success"], "ptr": r.get("records", [])}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def health(self, domain: str) -> Dict[str,Any]:
        ns = await self.resolve(domain,"NS")
        soa = await self.resolve(domain,"SOA")
        a = await self.resolve(domain,"A")
        aaaa = await self.resolve(domain,"AAAA")
        mx = await self.resolve(domain,"MX")
        txt = await self.resolve(domain,"TXT")
        spf_ok = any("v=spf1" in r.lower() for r in txt.get("records", []))
        dmarc = await self.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_ok = any("v=dmarc1" in r.lower() for r in dmarc.get("records", []))
        score = 100
        warn, err = [], []
        if not ns.get("records"): err.append("Нет NS"); score -= 30
        if not a.get("records") and not aaaa.get("records"): err.append("Нет A/AAAA"); score -= 25
        if not mx.get("records"): warn.append("Нет MX (почта не будет доставляться)"); score -= 10
        if not spf_ok: warn.append("Нет SPF"); score -= 10
        if not dmarc_ok: warn.append("Нет DMARC"); score -= 10
        status = "healthy" if score>=85 else "warning" if score>=65 else "critical"
        return {"domain": domain, "score": score, "status": status,
                "checks":{"NS":ns,"SOA":soa,"A":a,"AAAA":aaaa,"MX":mx,"TXT":txt,"DMARC":dmarc},
                "warnings": warn,"errors": err}

    async def dmarc_parse(self, domain: str) -> Dict[str,Any]:
        r = await self.resolve(f"_dmarc.{domain}", "TXT")
        pol = {}
        for t in r.get("records", []):
            if "v=DMARC1" in t.upper():
                for kv in t.split(";"):
                    kv=kv.strip()
                    if "=" in kv:
                        k,v = kv.split("=",1)
                        pol[k.strip()] = v.strip()
        return {"success": True, "raw": r.get("records", []), "policy": pol}

    async def spf_parse(self, domain: str) -> Dict[str,Any]:
        r = await self.resolve(domain,"TXT")
        spf = [t for t in r.get("records", []) if "v=spf1" in t.lower()]
        mech = []
        for s in spf:
            mech.extend([x for x in s.split() if x!="v=spf1"])
        return {"success": True, "records": spf, "mechanisms": mech}

    async def dkim_lookup(self, domain: str, selector: str) -> Dict[str,Any]:
        return await self.resolve(f"{selector}._domainkey.{domain}", "TXT")

dns_svc = DNS()

class SSL:
    async def tls_info(self, domain: str, port: int=443) -> Dict[str,Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        try:
            reader, writer = await asyncio.open_connection(domain, port, ssl=ctx, server_hostname=domain)
            ssl_obj = writer.get_extra_info('ssl_object')
            cert = ssl_obj.getpeercert()
            proto = ssl_obj.version()
            cipher = ssl_obj.cipher()
            alpn = None
            try:
                alpn = ssl_obj.selected_alpn_protocol()
            except Exception:
                pass
            ocsp = None
            try:
                ocsp = ssl_obj.ocsp_response  # Py3.11+
            except Exception:
                pass
            # parse SAN
            san = []
            for t in cert.get("subjectAltName", []):
                if t[0].lower() == "dns":
                    san.append(t[1])
            nb, na = cert.get("notBefore"), cert.get("notAfter")
            days_left = None
            try:
                if na:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return {"success": True, "protocol": proto, "cipher": cipher[0] if cipher else None,
                    "alpn": alpn, "ocsp_stapled": bool(ocsp),
                    "cert":{"subject":" / ".join("=".join(x) for x in sum(cert.get("subject",[]),())),
                            "issuer":" / ".join("=".join(x) for x in sum(cert.get("issuer",[]),())),
                            "not_before": nb, "not_after": na, "san": san, "days_left": days_left}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def tls_versions(self, domain: str) -> Dict[str,Any]:
        support = {}
        for ver,label in [
            (ssl.TLSVersion.TLSv1, "TLS1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS1.1"),
            (ssl.TLSVersion.TLSv1_2, "TLS1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLS1.3"),
        ]:
            try:
                ctx = ssl.create_default_context()
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                r, w = await asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain)
                w.close(); 
                try: await w.wait_closed()
                except Exception: pass
                support[label] = True
            except Exception:
                support[label] = False
        issues = []
        if support.get("TLS1.0") or support.get("TLS1.1"):
            issues.append("Включены устаревшие протоколы (TLS1.0/1.1)")
        grade = "A"
        if issues: grade = "B"
        if support.get("TLS1.0"): grade = "C"
        return {"success": True, "support": support, "issues": issues, "grade_like": grade}

ssl_svc = SSL()

class HTTP:
    def __init__(self):
        self.trace = None

    async def _session(self):
        trace = aiohttp.TraceConfig()
        timings = {"dns": None, "conn": None, "ttfb": None, "total": None}
        t0 = {"start": None, "conn": None, "req": None}

        async def on_start(session, ctx, params):
            t0["start"] = time.perf_counter()

        async def on_dns_end(session, ctx, params):
            timings["dns"] = (time.perf_counter() - t0["start"]) * 1000

        async def on_conn_end(session, ctx, params):
            timings["conn"] = (time.perf_counter() - t0["start"]) * 1000
            t0["conn"] = time.perf_counter()

        async def on_hdr_sent(session, ctx, params):
            t0["req"] = time.perf_counter()

        async def on_end(session, ctx, params):
            timings["total"] = (time.perf_counter() - t0["start"]) * 1000

        async def on_chunk(session, ctx, params):
            if timings["ttfb"] is None and t0["req"] is not None:
                timings["ttfb"] = (time.perf_counter() - t0["req"]) * 1000

        trace.on_request_start.append(on_start)
        trace.on_dns_resolvehost_end.append(on_dns_end)
        trace.on_connection_create_end.append(on_conn_end)
        trace.on_request_headers_sent.append(on_hdr_sent)
        trace.on_request_end.append(on_end)
        trace.on_response_chunk_received.append(on_chunk)

        self.trace = (trace, timings)
        return aiohttp.ClientSession(trace_configs=[trace])

    @async_ttl_cached(http_cache)
    async def head_or_get(self, url: str, allow_redirects=True) -> Dict[str,Any]:
        try:
            async with (await self._session()) as s:
                try:
                    async with s.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects) as r:
                        content = await r.text(errors="ignore") if r.status>=400 else ""
                        ver = f"{r.version.major}.{r.version.minor}"
                        return {"success": True, "url": str(r.url), "status": r.status,
                                "headers": dict(r.headers), "version": ver, "timings": self.trace[1], "content": content}
                except Exception:
                    async with s.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects) as r:
                        body = await r.text(errors="ignore")
                        ver = f"{r.version.major}.{r.version.minor}"
                        return {"success": True, "url": str(r.url), "status": r.status,
                                "headers": dict(r.headers), "version": ver, "timings": self.trace[1], "content": body[:50000]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def security_report(self, url: str) -> Dict[str,Any]:
        r = await self.head_or_get(url, allow_redirects=True)
        if not r.get("success"): return r
        h = {k.lower(): v for k,v in r.get("headers", {}).items()}
        score = 100
        notes = []
        # HSTS
        if "strict-transport-security" not in h:
            score -= 10; notes.append("Нет HSTS")
        # CSP
        csp = h.get("content-security-policy")
        if not csp:
            score -= 10; notes.append("Нет CSP")
        elif "upgrade-insecure-requests" not in csp.lower():
            notes.append("CSP без upgrade-insecure-requests")
        # X-* headers
        if "x-frame-options" not in h: score -= 5; notes.append("Нет X-Frame-Options")
        if "x-content-type-options" not in h: score -= 5; notes.append("Нет X-Content-Type-Options")
        if "referrer-policy" not in h: score -= 5; notes.append("Нет Referrer-Policy")
        # Cookies
        cookies = r.get("headers", {}).get("Set-Cookie") or r.get("headers", {}).get("set-cookie")
        if cookies:
            flags_ok = all(("Secure" in c and "HttpOnly" in c) for c in cookies.split(","))
            if not flags_ok:
                score -= 5; notes.append("Cookies без Secure/HttpOnly")
        # CORS
        aco = h.get("access-control-allow-origin")
        if aco and aco.strip() == "*":
            score -= 5; notes.append("CORS: ACAO *")
        grade = "A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F"
        return {"success": True, "grade": grade, "score": score, "notes": notes,
                "http_version": r.get("version"), "timings": r.get("timings"),
                "final_url": r.get("url"), "status": r.get("status"), "headers": r.get("headers")}

http_svc = HTTP()

# ================== WHOIS / RDAP ==================
class WHOIS:
    @async_ttl_cached(whois_cache)
    async def domain_whois(self, domain: str) -> Dict[str,Any]:
        # TCP/43 WHOIS with referral follow
        tld = domain.split(".")[-1].lower()
        servers = {
            "com":"whois.verisign-grs.com", "net":"whois.verisign-grs.com",
            "org":"whois.pir.org", "info":"whois.afilias.net", "io":"whois.nic.io",
            "ru":"whois.tcinet.ru", "su":"whois.tcinet.ru", "by":"whois.cctld.by",
            "de":"whois.denic.de", "uk":"whois.nic.uk", "dev":"whois.nic.google", "app":"whois.nic.google"
        }
        server = servers.get(tld, "whois.verisign-grs.com")
        try:
            reader, writer = await asyncio.open_connection(server, 43)
            writer.write((domain+"\r\n").encode()); await writer.drain()
            data = await reader.read(-1)
            writer.close(); 
            try: await writer.wait_closed()
            except Exception: pass
            text = data.decode(errors="replace")
            m = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
            if m:
                try:
                    s2 = m.group(1).strip()
                    reader, writer = await asyncio.open_connection(s2, 43)
                    writer.write((domain+"\r\n").encode()); await writer.drain()
                    d2 = await reader.read(-1)
                    writer.close(); 
                    try: await writer.wait_closed()
                    except Exception: pass
                    text = d2.decode(errors="replace")
                except Exception:
                    pass
            return {"success": True, "server": server, "raw": text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def availability(self, domain: str) -> Dict[str,Any]:
        w = await self.domain_whois(domain)
        raw = w.get("raw","").lower()
        available = any(x in raw for x in ["no match for", "not found", "available", "no entries found"])
        return {"success": True, "available": available, "whois_server": w.get("server")}

    async def domain_dates(self, domain: str) -> Dict[str,Any]:
        w = await self.domain_whois(domain)
        raw = w.get("raw","")
        def find(*labels):
            for lb in labels:
                m = re.search(lb + r":\s*(.+)", raw, re.I)
                if m: return m.group(1).strip()
        return {"success": True,
                "created": find("Creation Date","Created On","Created"),
                "updated": find("Updated Date","Last Updated On","Updated"),
                "expiry": find("Registry Expiry Date","Expiration Date","Expiry Date","Expires On"),
                "registrar": find("Registrar","Registrar Name")}

    async def ip_rdap(self, ip: str) -> Dict[str,Any]:
        eps = [
            f"https://rdap.arin.net/registry/ip/{ip}",
            f"https://rdap.db.ripe.net/ip/{ip}",
            f"https://rdap.apnic.net/ip/{ip}",
            f"https://rdap.lacnic.net/rdap/ip/{ip}",
            f"https://rdap.afrinic.net/rdap/ip/{ip}",
        ]
        last = None
        for url in eps:
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(url, timeout=DEFAULT_TIMEOUT) as r:
                        if r.status == 200:
                            return {"success": True, "rdap": await r.json()}
                        else:
                            last = f"{url} -> HTTP {r.status}"
            except Exception as e:
                last = str(e)
        return {"success": False, "error": last}

whois_svc = WHOIS()

# ================== TELEGRAM ==================
storage = MemoryStorage()
bot = Bot(token=BOT_TOKEN, parse_mode=ParseMode.HTML)
dp = Dispatcher(storage=storage)

class S(StatesGroup):
    main = State()
    wait_domain = State()
    wait_ip = State()
    wait_text = State()

def main_menu_kb():
    kb = InlineKeyboardBuilder()
    kb.row(
        InlineKeyboardButton(text="🔍 DNS", callback_data="menu_dns"),
        InlineKeyboardButton(text="🌐 WHOIS/IP", callback_data="menu_whois"),
    )
    kb.row(
        InlineKeyboardButton(text="🔒 SSL & HTTP", callback_data="menu_ssl_http"),
        InlineKeyboardButton(text="🛰️ Network", callback_data="menu_net"),
    )
    kb.row(
        InlineKeyboardButton(text="🧰 Utilities", callback_data="menu_utils"),
        InlineKeyboardButton(text="📦 Audit/Export", callback_data="menu_audit"),
    )
    return kb.as_markup()

@dp.message(CommandStart())
async def start(m: Message):
    await m.answer("🚀 <b>MAX DNS/SSL/WHOIS/NET Bot</b>\nВыбирай раздел:", reply_markup=main_menu_kb())

# ========== COMMANDS ==========
@dp.message(Command("audit"))
async def cmd_audit(m: Message):
    if not ensure_rate(m.from_user.id, cost=2):
        await m.reply("⏳ Слишком часто. Попробуйте позже."); return
    parts = m.text.split()
    if len(parts) < 2 or not is_valid_domain(parts[1]):
        await m.reply("Формат: <code>/audit example.com</code>"); return
    domain = parts[1].lower()
    wait = await m.reply("⏳ Делаю полный аудит…")
    report = await full_audit(domain)
    j = json.dumps(report, ensure_ascii=False, indent=2)
    data = j.encode()
    await m.answer_document(BufferedInputFile(data, filename=f"audit_{domain}.json"), caption="📦 JSON отчёт")
    md = render_audit_markdown(report)
    await m.answer_document(BufferedInputFile(md.encode("utf-8"), filename=f"audit_{domain}.md"), caption="🧾 Markdown отчёт")
    await wait.delete()

@dp.message(Command("report"))
async def cmd_report(m: Message):
    if not ensure_rate(m.from_user.id, cost=2):
        await m.reply("⏳ Слишком часто. Попробуйте позже."); return
    parts = m.text.split()
    if len(parts)<2 or not is_valid_domain(parts[1]):
        await m.reply("Формат: <code>/report example.com [md|json]</code>"); return
    domain = parts[1].lower()
    kind = parts[2].lower() if len(parts)>2 else "both"
    wait = await m.reply("⏳ Генерирую отчёт…")
    report = await full_audit(domain)
    if kind in ("json","both"):
        j = json.dumps(report, ensure_ascii=False, indent=2)
        await m.answer_document(BufferedInputFile(j.encode(), filename=f"report_{domain}.json"), caption="📦 JSON")
    if kind in ("md","both"):
        md = render_audit_markdown(report)
        await m.answer_document(BufferedInputFile(md.encode("utf-8"), filename=f"report_{domain}.md"), caption="🧾 Markdown")
    await wait.delete()

# ========== MENUS ==========
@dp.callback_query(F.data=="menu_dns")
async def menu_dns(c: CallbackQuery):
    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="Lookup (A/AAAA/MX…)", callback_data="dns_lookup"))
    kb.row(InlineKeyboardButton(text="Propagation", callback_data="dns_propag"))
    kb.row(InlineKeyboardButton(text="All Records", callback_data="dns_all"))
    kb.row(InlineKeyboardButton(text="Health/Email", callback_data="dns_health"))
    kb.row(InlineKeyboardButton(text="DoH Query", callback_data="dns_doh"))
    kb.row(InlineKeyboardButton(text="DMARC/SPF/DKIM", callback_data="dns_mail"))
    kb.row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main"))
    await c.message.edit_text("🔍 <b>DNS</b> — выбери инструмент", reply_markup=kb.as_markup()); await c.answer()

@dp.callback_query(F.data=="menu_whois")
async def menu_whois(c: CallbackQuery):
    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="Domain WHOIS", callback_data="whois_domain"))
    kb.row(InlineKeyboardButton(text="Availability", callback_data="whois_avail"))
    kb.row(InlineKeyboardButton(text="Dates/Registrar", callback_data="whois_dates"))
    kb.row(InlineKeyboardButton(text="IP RDAP", callback_data="whois_ip"))
    kb.row(InlineKeyboardButton(text="IP Analysis", callback_data="whois_ip_analyze"))
    kb.row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main"))
    await c.message.edit_text("🌐 <b>WHOIS / IP</b>", reply_markup=kb.as_markup()); await c.answer()

@dp.callback_query(F.data=="menu_ssl_http")
async def menu_ssl_http(c: CallbackQuery):
    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="TLS Info/ALPN", callback_data="ssl_tls"))
    kb.row(InlineKeyboardButton(text="TLS Versions", callback_data="ssl_proto"))
    kb.row(InlineKeyboardButton(text="HTTP Security", callback_data="http_sec"))
    kb.row(InlineKeyboardButton(text="HTTP Timings", callback_data="http_time"))
    kb.row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main"))
    await c.message.edit_text("🔒 <b>SSL & HTTP</b>", reply_markup=kb.as_markup()); await c.answer()

@dp.callback_query(F.data=="menu_net")
async def menu_net(c: CallbackQuery):
    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="Ping", callback_data="net_ping"))
    kb.row(InlineKeyboardButton(text="Traceroute", callback_data="net_trace"))
    kb.row(InlineKeyboardButton(text="Port Scan", callback_data="net_scan"))
    kb.row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main"))
    await c.message.edit_text("🛰️ <b>Network</b>", reply_markup=kb.as_markup()); await c.answer()

@dp.callback_query(F.data=="menu_utils")
async def menu_utils(c: CallbackQuery):
    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="Password", callback_data="u_pwd"))
    kb.row(InlineKeyboardButton(text="QR Code", callback_data="u_qr"))
    kb.row(InlineKeyboardButton(text="Hash/Base64", callback_data="u_hash"))
    kb.row(InlineKeyboardButton(text="Colors/Units/Time", callback_data="u_misc"))
    kb.row(InlineKeyboardButton(text="Clone Site", callback_data="u_clone"))
    kb.row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main"))
    await c.message.edit_text("🧰 <b>Utilities</b>", reply_markup=kb.as_markup()); await c.answer()

@dp.callback_query(F.data=="menu_audit")
async def menu_audit(c: CallbackQuery):
    await c.message.edit_text("🧾 <b>Audit/Export</b>\nКоманды:\n• <code>/audit example.com</code>\n• <code>/report example.com [md|json]</code>\n", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="back_main")).as_markup()); await c.answer()

@dp.callback_query(F.data=="back_main")
async def back_main(c: CallbackQuery):
    await c.message.edit_text("🏠 Главное меню", reply_markup=main_menu_kb()); await c.answer()

# ========== DNS Actions ==========
@dp.callback_query(F.data=="dns_lookup")
async def dns_lookup(c: CallbackQuery):
    await c.message.edit_text("Введите <b>домен</b> и тип (опц.) — например: <code>example.com A</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_lookup"})

@dp.callback_query(F.data=="dns_propag")
async def dns_propag(c: CallbackQuery):
    await c.message.edit_text("Введите домен (опц. тип) — <code>example.com A</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_propag"})

@dp.callback_query(F.data=="dns_all")
async def dns_all(c: CallbackQuery):
    await c.message.edit_text("Введите домен — <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_all"})

@dp.callback_query(F.data=="dns_health")
async def dns_health(c: CallbackQuery):
    await c.message.edit_text("Введите домен — <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_health"})

@dp.callback_query(F.data=="dns_doh")
async def dns_doh(c: CallbackQuery):
    await c.message.edit_text("Введите: <code>example.com A cloudflare|google</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_doh"})

@dp.callback_query(F.data=="dns_mail")
async def dns_mail(c: CallbackQuery):
    await c.message.edit_text("Введите: <code>example.com [dkim_selector]</code>\nDKIM selector опционален.", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_dns")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"dns_mail"})

# ========== WHOIS Actions ==========
@dp.callback_query(F.data=="whois_domain")
async def whois_domain(c: CallbackQuery):
    await c.message.edit_text("Домен: <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_whois")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"whois_domain"})

@dp.callback_query(F.data=="whois_avail")
async def whois_avail(c: CallbackQuery):
    await c.message.edit_text("Проверка доступности домена: <code>brand-new-domain.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_whois")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"whois_avail"})

@dp.callback_query(F.data=="whois_dates")
async def whois_dates(c: CallbackQuery):
    await c.message.edit_text("Домен: <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_whois")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"whois_dates"})

@dp.callback_query(F.data=="whois_ip")
async def whois_ip(c: CallbackQuery):
    await c.message.edit_text("IP для RDAP: <code>8.8.8.8</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_whois")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"whois_ip"})

@dp.callback_query(F.data=="whois_ip_analyze")
async def whois_ip_analyze(c: CallbackQuery):
    await c.message.edit_text("Введите IP для детального анализа:", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_whois")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"whois_ip_analyze"})

# ========== SSL/HTTP Actions ==========
@dp.callback_query(F.data=="ssl_tls")
async def ssl_tls(c: CallbackQuery):
    await c.message.edit_text("Введите домен: <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_ssl_http")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"ssl_tls"})

@dp.callback_query(F.data=="ssl_proto")
async def ssl_proto(c: CallbackQuery):
    await c.message.edit_text("Введите домен: <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_ssl_http")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"ssl_proto"})

@dp.callback_query(F.data=="http_sec")
async def http_sec(c: CallbackQuery):
    await c.message.edit_text("Введите URL: <code>https://example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_ssl_http")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"http_sec"})

@dp.callback_query(F.data=="http_time")
async def http_time(c: CallbackQuery):
    await c.message.edit_text("Введите URL: <code>https://example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_ssl_http")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"http_time"})

# ========== NET Actions ==========
@dp.callback_query(F.data=="net_ping")
async def net_ping(c: CallbackQuery):
    await c.message.edit_text("Пинговка: <code>1.1.1.1</code> или <code>google.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_net")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"net_ping"})

@dp.callback_query(F.data=="net_trace")
async def net_trace(c: CallbackQuery):
    await c.message.edit_text("Traceroute: <code>example.com</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_net")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"net_trace"})

@dp.callback_query(F.data=="net_scan")
async def net_scan(c: CallbackQuery):
    await c.message.edit_text("Скан портов: <code>scanme.nmap.org 1-100</code>", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_net")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"net_scan"})

# ========== Utilities ==========
@dp.callback_query(F.data=="u_pwd")
async def u_pwd(c: CallbackQuery):
    await c.message.edit_text("Длина 8/12/16/24 или введите число 4–128.", reply_markup=InlineKeyboardBuilder()
        .row(InlineKeyboardButton(text="8", callback_data="pwd_8"), InlineKeyboardButton(text="12", callback_data="pwd_12"))
        .row(InlineKeyboardButton(text="16", callback_data="pwd_16"), InlineKeyboardButton(text="24", callback_data="pwd_24"))
        .row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_utils")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"u_pwd"})

@dp.callback_query(F.data=="u_qr")
async def u_qr(c: CallbackQuery):
    await c.message.edit_text("Введи текст/URL для QR.", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_utils")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"u_qr"})

@dp.callback_query(F.data=="u_hash")
async def u_hash(c: CallbackQuery):
    await c.message.edit_text("Введи текст для Hash/Base64. Используй префиксы: <code>b64:</code>encode, <code>b64d:</code>decode.", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_utils")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"u_hash"})

@dp.callback_query(F.data=="u_misc")
async def u_misc(c: CallbackQuery):
    await c.message.edit_text("Color (#RRGGBB или rgb), Units (<code>10 km to mi</code>), Timestamp (unix или <code>YYYY-MM-DD HH:MM</code>)", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_utils")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"u_misc"})

@dp.callback_query(F.data=="u_clone")
async def u_clone(c: CallbackQuery):
    await c.message.edit_text("Введите URL сайта для клонирования (https://example.com):", reply_markup=InlineKeyboardBuilder().row(InlineKeyboardButton(text="⬅️ Назад", callback_data="menu_utils")).as_markup())
    await dp.storage.set_data(chat=c.message.chat.id, user=c.from_user.id, data={"mode":"u_clone_url"})

# ========== Text Input Handler ==========
@dp.message()
async def text_router(m: Message):
    data = await dp.storage.get_data(chat=m.chat.id, user=m.from_user.id)
    mode = data.get("mode") if data else None
    if not mode:
        await m.reply("Команда не распознана. Используйте меню или /audit /report.")
        return
    if not ensure_rate(m.from_user.id):
        await m.reply("⏳ Слишком часто. Попробуйте позже.")
        return
    try:
        if mode == "dns_lookup":
            parts = m.text.split()
            domain = parts[0].lower()
            rtype = parts[1].upper() if len(parts)>1 else "A"
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            r = await dns_svc.resolve(domain, rtype)
            await m.reply(fmt_dns_lookup(domain, rtype, r))
        elif mode == "dns_propag":
            parts = m.text.split()
            domain = parts[0].lower()
            rtype = parts[1].upper() if len(parts)>1 else "A"
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            r = await dns_svc.propagation(domain, rtype)
            await m.reply(fmt_propagation(r))
        elif mode == "dns_all":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            r = await dns_svc.all_records(domain)
            await m.reply(fmt_all_records(r))
        elif mode == "dns_health":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            d = await dns_svc.health(domain)
            await m.reply(fmt_dns_health(d))
        elif mode == "dns_doh":
            parts = m.text.split()
            domain = parts[0].lower()
            rtype = parts[1].upper() if len(parts)>1 else "A"
            prov = parts[2].lower() if len(parts)>2 else "cloudflare"
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            r = await dns_svc.doh_query(domain, rtype, provider=prov)
            await m.reply(fmt_doh(domain, rtype, prov, r))
        elif mode == "dns_mail":
            parts = m.text.split()
            domain = parts[0].lower()
            selector = parts[1] if len(parts)>1 else None
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            spf = await dns_svc.spf_parse(domain)
            dmarc = await dns_svc.dmarc_parse(domain)
            dkim = await dns_svc.dkim_lookup(domain, selector) if selector else {"success": True, "records":[]}
            await m.reply(fmt_mail(domain, spf, dmarc, dkim, selector))
        elif mode == "whois_domain":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            w = await whois_svc.domain_whois(domain)
            await m.reply(fmt_whois(domain, w))
        elif mode == "whois_avail":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            a = await whois_svc.availability(domain)
            await m.reply(f"✅ Домен <b>{domain}</b>: {'свободен' if a.get('available') else 'занят'} (сервер: <code>{a.get('whois_server')}</code>)")
        elif mode == "whois_dates":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            d = await whois_svc.domain_dates(domain)
            await m.reply(fmt_dates(domain, d))
        elif mode == "whois_ip":
            ip = m.text.strip()
            try: ipaddress.ip_address(ip)
            except Exception: return await m.reply("Некорректный IP.")
            r = await whois_svc.ip_rdap(ip)
            await m.reply(fmt_rdap(ip, r))
        elif mode == "whois_ip_analyze":
            ip = m.text.strip()
            try: ipaddress.ip_address(ip)
            except Exception: return await m.reply("Некорректный IP.")
            r = await analyze_ip(ip)
            await m.reply(fmt_ip_analysis(r))
        elif mode == "ssl_tls":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            info = await ssl_svc.tls_info(domain)
            await m.reply(fmt_tls(domain, info))
        elif mode == "ssl_proto":
            domain = m.text.strip().lower()
            if not is_valid_domain(domain): return await m.reply("Некорректный домен.")
            vers = await ssl_svc.tls_versions(domain)
            await m.reply(fmt_tls_versions(domain, vers))
        elif mode == "http_sec":
            url = m.text.strip()
            if not re.match(r"^https?://", url): return await m.reply("Укажите корректный URL (http/https).")
            rep = await http_svc.security_report(url)
            await m.reply(fmt_http_sec(rep))
        elif mode == "http_time":
            url = m.text.strip()
            if not re.match(r"^https?://", url): return await m.reply("Укажите корректный URL (http/https).")
            r = await http_svc.head_or_get(url)
            await m.reply(fmt_http_time(r))
        elif mode == "net_ping":
            host = m.text.strip()
            r = await net_ping(host)
            await m.reply(fmt_ping(host, r))
        elif mode == "net_trace":
            host = m.text.strip()
            r = await net_trace(host)
            await m.reply(fmt_trace(host, r))
        elif mode == "net_scan":
            parts = m.text.split()
            if len(parts) < 1:
                return await m.reply("Формат: <code>host [ports]</code> например scanme.nmap.org 1-100")
            host = parts[0]
            ports = parts[1] if len(parts) > 1 else '1-1024'
            nm = nmap.PortScanner()
            try:
                nm.scan(host, ports)
                open_ports = []
                if host in nm:
                    for proto in nm[host]:
                        for port in nm[host][proto]:
                            state = nm[host][proto][port]['state']
                            if state == 'open':
                                name = nm[host][proto][port]['name']
                                open_ports.append(f"{port}/{proto} open ({name})")
                msg = "🧰 <b>Port Scan</b>\n" + ("\n".join(open_ports) if open_ports else "Открытых портов не найдено.")
                await m.reply(msg)
            except Exception as e:
                await m.reply(f"Ошибка сканирования: {str(e)}")
        elif mode == "u_pwd":
            ln = m.text.strip()
            if not ln.isdigit(): return await m.reply("Введите число 4–128.")
            await send_password(m, int(ln))
        elif mode == "u_qr":
            from io import BytesIO
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
            qr.add_data(m.text); qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = BytesIO(); img.save(buf, format="PNG")
            await m.answer_photo(BufferedInputFile(buf.getvalue(), filename="qr.png"), caption="📱 QR готов")
        elif mode == "u_hash":
            txt = m.text
            if txt.startswith("b64:"):
                out = base64.b64encode(txt[4:].encode()).decode()
                await m.reply(f"🧬 Base64:\n<code>{out}</code>")
            elif txt.startswith("b64d:"):
                try:
                    out = base64.b64decode(txt[5:].encode()).decode("utf-8","replace")
                    await m.reply(f"🧬 Base64 decode:\n<code>{out}</code>")
                except Exception as e:
                    await m.reply(f"Ошибка decode: {e}")
            else:
                await m.reply(
                    "🧮 Hashes:\n"
                    f"MD5: <code>{hashlib.md5(txt.encode()).hexdigest()}</code>\n"
                    f"SHA1: <code>{hashlib.sha1(txt.encode()).hexdigest()}</code>\n"
                    f"SHA256: <code>{hashlib.sha256(txt.encode()).hexdigest()}</code>\n"
                    f"SHA512: <code>{hashlib.sha512(txt.encode()).hexdigest()}</code>"
                )
        elif mode == "u_misc":
            t = m.text.strip()
            if t.startswith("#") or t.lower().startswith("rgb"):
                await m.reply(fmt_color(convert_color(t)))
            elif " to " in t or " TO " in t or ">" in t:
                try:
                    conv = convert_units(t)
                    await m.reply(f"📐 {conv['from']} → <b>{conv['result']:.6g} {conv['to_unit']}</b>")
                except Exception as e:
                    await m.reply(f"❌ {e}")
            else:
                try:
                    r = parse_timestamp(t)
                    if r["direction"] == "ts->date":
                        await m.reply(f"⏱️ {r['timestamp']} → <code>{r['utc']}</code> (UTC)")
                    else:
                        await m.reply(f"⏱️ {r['utc']} → <code>{r['timestamp']}</code>")
                except Exception as e:
                    await m.reply(f"❌ {e}")
        elif mode == "u_clone_url":
            url = m.text.strip()
            if not re.match(r"^https?://", url):
                return await m.reply("Некорректный URL")
            data['clone_url'] = url
            await dp.storage.set_data(chat=m.chat.id, user=m.from_user.id, data=data)
            await m.reply("Введите новый домен:")
            data['mode'] = "u_clone_domain"
            await dp.storage.set_data(chat=m.chat.id, user=m.from_user.id, data=data)
        elif mode == "u_clone_domain":
            new_domain = m.text.strip()
            if not is_valid_domain(new_domain):
                return await m.reply("Некорректный домен")
            data['new_domain'] = new_domain
            await dp.storage.set_data(chat=m.chat.id, user=m.from_user.id, data=data)
            await m.reply("Копировать медиафайлы? (да/нет)")
            data['mode'] = "u_clone_media"
            await dp.storage.set_data(chat=m.chat.id, user=m.from_user.id, data=data)
        elif mode == "u_clone_media":
            copy_media = m.text.lower() == 'да'
            await m.reply("Начинаю клонирование...")
            await clone_site(data['clone_url'], data['new_domain'], copy_media, m)
            del data['mode']
            if 'clone_url' in data: del data['clone_url']
            if 'new_domain' in data: del data['new_domain']
            await dp.storage.set_data(chat=m.chat.id, user=m.from_user.id, data=data)
        else:
            await m.reply("Неизвестный режим.")
    except Exception as e:
        logger.exception("handler error")
        await m.reply(f"❌ Ошибка: {e}")

# ====== quick formatters ======
def fmt_dns_lookup(domain, rtype, r):
    if not r.get("success"):
        return f"❌ DNS {domain} {rtype}\n{r.get('error')}"
    return (f"🔍 <b>DNS Lookup</b>\nДомен: <b>{domain}</b>\nТип: <b>{rtype}</b>\n"
            f"TTL: <code>{r.get('ttl')}</code>\n"
            f"Ответы:\n{code_list(r.get('records', []), 12)}")

def fmt_propagation(res):
    pct = res.get("pct",0); ok = res.get("ok",0); total = res.get("total",0)
    filled = int(10*pct/100); bar = "█"*filled + "░"*(10-filled)
    lines = []
    for ns, it in list(res.get("results", {}).items())[:18]:
        mark = "✅" if it["status"]=="propagated" else "🟡" if it["status"]=="differs" else "❌"
        lines.append(f"{mark} {ns} — {it['location']}")
    return (f"🌍 <b>DNS Propagation</b>\nДомен: <b>{res['domain']}</b>, тип: <b>{res['rtype']}</b>\n"
            f"{bar} {pct}%  ({ok}/{total})\n" + "\n".join(lines))

def fmt_all_records(r):
    out = [f"📋 <b>Все записи для {r['domain']}</b> ({r['ok']}/{r['total']})"]
    for t, rr in r["records"].items():
        if rr.get("records"):
            out.append(f"✅ {t} ({len(rr['records'])}):\n{code_list(rr['records'],6)}")
        else:
            out.append(f"❌ {t}: нет данных")
    return "\n".join(out)

def fmt_dns_health(d):
    icon = "✅" if d["status"]=="healthy" else "🟡" if d["status"]=="warning" else "❌"
    s = [f"{icon} <b>DNS Health</b> для <b>{d['domain']}</b>\nОценка: {d['score']}/100"]
    if d["warnings"]:
        s.append("\n⚠️ Предупреждения:\n"+"\n".join("• "+w for w in d["warnings"]))
    if d["errors"]:
        s.append("\n❌ Ошибки:\n"+"\n".join("• "+e for e in d["errors"]))
    return "\n".join(s)

def fmt_doh(domain, rtype, prov, r):
    if not r.get("success"): return f"❌ DoH {prov} {domain} {rtype}\n{r.get('error')}"
    return (f"🔐 <b>DoH</b> {prov}\nДомен: <b>{domain}</b>, тип: <b>{rtype}</b>\n"
            f"Статус: <code>{r.get('status')}</code>\nОтветы:\n{code_list(r.get('records', []), 12)}")

def fmt_mail(domain, spf, dmarc, dkim, selector):
    dmarc_pol = dmarc.get("policy",{})
    pol_line = ", ".join(f"{k}={v}" for k,v in dmarc_pol.items()) or "—"
    return (f"✉️ <b>Mail Records</b> для <b>{domain}</b>\n"
            f"SPF ({len(spf.get('records',[]))}):\n{code_list(spf.get('records',[]),4)}\n"
            f"Механизмы SPF: <code>{' '.join(spf.get('mechanisms',[])[:20]) or '—'}</code>\n\n"
            f"DMARC:\n{code_list(dmarc.get('raw',[]),2)}\n"
            f"Политика: <code>{pol_line}</code>\n\n"
            f"DKIM{f' (selector {selector})' if selector else ''}:\n{code_list(dkim.get('records',[]),3)}")

def fmt_whois(domain, w):
    if not w.get("success"): return f"❌ WHOIS {domain}\n{w.get('error')}"
    head = "\n".join(w.get("raw","").splitlines()[:30])
    return f"🔍 <b>WHOIS</b> <b>{domain}</b>\n<code>{head}</code>\n…"

def fmt_dates(domain, d):
    return (f"🕓 <b>Dates</b> {domain}\n"
            f"Created: <code>{d.get('created') or '—'}</code>\n"
            f"Updated: <code>{d.get('updated') or '—'}</code>\n"
            f"Expiry: <code>{d.get('expiry') or '—'}</code>\n"
            f"Registrar: <code>{d.get('registrar') or '—'}</code>")

def fmt_rdap(ip, r):
    if not r.get("success"): return f"❌ RDAP {ip}\n{r.get('error')}"
    js = r.get("rdap",{})
    return f"🗺️ <b>IP RDAP</b> {ip}\nName: <code>{js.get('name') or js.get('handle')}</code>\nCountry: <code>{js.get('country')}</code>"

def fmt_tls(domain, info):
    if not info.get("success"): return f"❌ TLS {domain}\n{info.get('error')}"
    c = info["cert"]
    return (f"🔒 <b>TLS</b> {domain}\n"
            f"Proto: <code>{info.get('protocol')}</code>\n"
            f"Cipher: <code>{info.get('cipher')}</code>\n"
            f"ALPN: <code>{info.get('alpn') or '—'}</code>\n"
            f"OCSP stapling: <b>{'да' if info.get('ocsp_stapled') else 'нет'}</b>\n\n"
            f"Issuer: <code>{c.get('issuer')}</code>\n"
            f"Subject: <code>{c.get('subject')}</code>\n"
            f"NotAfter: <code>{c.get('not_after')}</code>\n"
            f"Days Left: <b>{c.get('days_left')}</b>\n"
            f"SAN ({len(c.get('san',[]))}):\n{code_list(c.get('san',[]),10)}")

def fmt_tls_versions(domain, v):
    s = [f"🛡️ <b>TLS Versions</b> {domain} (grade {v.get('grade_like')})"]
    sup=v.get("support",{})
    s.append(f"TLS1.0: {'✅' if sup.get('TLS1.0') else '❌'} | TLS1.1: {'✅' if sup.get('TLS1.1') else '❌'} | TLS1.2: {'✅' if sup.get('TLS1.2') else '❌'} | TLS1.3: {'✅' if sup.get('TLS1.3') else '❌'}")
    if v.get("issues"):
        s.append("\n".join("• "+x for x in v["issues"]))
    return "\n".join(s)

def fmt_http_sec(rep):
    if not rep.get("success"): return f"❌ HTTP Security\n{rep.get('error')}"
    return (f"🛡️ <b>HTTP Security</b>\nURL: <code>{rep.get('final_url')}</code>\n"
            f"HTTP: <b>{rep.get('status')}</b>, Version: <code>{rep.get('http_version')}</code>\n"
            f"Score: <b>{rep.get('score')}</b> (grade {rep.get('grade')})\n"
            + ("\nЗаметки:\n" + "\n".join("• "+x for x in rep.get('notes',[])) if rep.get('notes') else ""))

def fmt_http_time(r):
    if not r.get("success"): return f"❌ HTTP\n{r.get('error')}"
    t = r.get("timings") or {}
    return (f"⏱️ <b>HTTP Timings</b>\nURL: <code>{r.get('url')}</code>\n"
            f"Status: <b>{r.get('status')}</b>, Version: <code>{r.get('version')}</code>\n"
            f"DNS: {round(t.get('dns') or 0,1)} ms, Connect: {round(t.get('conn') or 0,1)} ms, TTFB: {round(t.get('ttfb') or 0,1)} ms, Total: {round(t.get('total') or 0,1)} ms")

# ====== NET helpers ======
async def net_ping(host: str) -> Dict[str,Any]:
    is_win = platform.system().lower().startswith("win")
    cmd = ["ping", "-n" if is_win else "-c", "4", host]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        text = out.decode(errors="replace") + err.decode(errors="replace")
        loss = re.search(r"(\d+)%\s*loss", text, re.I) if is_win else re.search(r"(\d+(?:\.\d+)?)% packet loss", text)
        avg = None
        if is_win:
            m = re.search(r"Average = (\d+)\w*", text);  avg = float(m.group(1)) if m else None
        else:
            m = re.search(r"rtt [\w/]+= .*?/(\d+\.\d+)/", text); avg = float(m.group(1)) if m else None
        return {"success": True, "loss": float(loss.group(1)) if loss else None, "avg": avg, "raw": text}
    except Exception as e:
        return {"success": False, "error": str(e)}

async def net_trace(host: str) -> Dict[str,Any]:
    is_win = platform.system().lower().startswith("win")
    cmd = ["tracert", host] if is_win else ["traceroute", "-n", host]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        text = out.decode(errors="replace") + err.decode(errors="replace")
        return {"success": True, "raw": text}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fmt_ping(host, r):
    if not r.get("success"): return f"❌ Ping {host}\n{r.get('error')}"
    return f"📶 <b>Ping</b> {host}\nLoss: {r.get('loss')}%  Avg: {r.get('avg')} ms\n<code>{r.get('raw','')[:1500]}</code>"

def fmt_trace(host, r):
    if not r.get("success"): return f"❌ Traceroute {host}\n{r.get('error')}"
    return f"🧭 <b>Traceroute</b> {host}\n<code>{r.get('raw','')[:1800]}</code>"

async def analyze_ip(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024', arguments='-O -sV --script vuln')
        device = 'Unknown'
        if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            device = nm[ip]['osmatch'][0]['name']
        open_ports = []
        vulnerabilities = []
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto]:
                state = nm[ip][proto][port]['state']
                if state == 'open':
                    service = nm[ip][proto][port].get('name', 'unknown')
                    version = nm[ip][proto][port].get('version', '')
                    open_ports.append(f"{port}/{proto} {service} {version}")
                    if 'script' in nm[ip][proto][port]:
                        for script, output in nm[ip][proto][port]['script'].items():
                            if 'vuln' in script.lower():
                                vulnerabilities.append(f"Port {port}: {output[:200]}")
        return {"ip": ip, "device": device, "open_ports": open_ports, "vulnerabilities": vulnerabilities}
    except Exception as e:
        return {"error": str(e)}

def fmt_ip_analysis(r):
    if 'error' in r: return f"❌ {r['error']}"
    return f"📡 <b>IP Analysis</b> {r['ip']}\nDevice/OS: <code>{r['device']}</code>\nOpen Ports:\n{'\n'.join(r['open_ports']) or 'None'}\nVulnerabilities:\n{'\n'.join(r['vulnerabilities']) or 'None'}\n\nNote: Password guessing not performed due to ethical reasons. Common defaults: admin/admin, root/root, etc. Use only with permission."

# ====== UTIL helpers ======
async def send_password(m: Message, length: int):
    if not (4 <= length <= 128):
        await m.reply("Длина 4–128"); return
    alph = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/\\|`~"
    pwd = "".join(secrets.choice(alph) for _ in range(length))
    classes = [any(c.islower() for c in pwd), any(c.isupper() for c in pwd), any(c.isdigit() for c in pwd), any(c in "!@#$%^&*()-_=+[]{};:,.?/\\|`~" for c in pwd)]
    score = sum(classes)*10 + min(length, 40)
    strength = "Strong" if score>=40 else "Medium" if score>=25 else "Weak"
    emoji = "🟢" if score>=40 else "🟡" if score>=25 else "🔴"
    await m.reply(f"🔑 Пароль:\n<code>{pwd}</code>\nСила: {emoji} {strength} ({score}/50)")

def convert_color(s: str) -> Dict[str,Any]:
    s = s.strip().lower()
    def clamp(v): return max(0, min(255, v))
    def rgb_to_hsl(r,g,b):
        r_,g_,b_=r/255,g/255,b/255; mx,mn=max(r_,g_,b_),min(r_,g_,b_)
        l=(mx+mn)/2
        if mx==mn: h=sat=0
        else:
            d=mx-mn
            sat = d/(2-mx-mn) if l>0.5 else d/(mx+mn)
            if mx==r_: h=((g_-b_)/d + (6 if g_<b_ else 0))/6
            elif mx==g_: h=((b_-r_)/d + 2)/6
            else: h=((r_-g_)/d + 4)/6
        return round(h*360), round(sat*100), round(l*100)
    if s.startswith("#") and len(s)==7:
        r=int(s[1:3],16); g=int(s[3:5],16); b=int(s[5:7],16)
    elif s.startswith("rgb"):
        nums=list(map(int,re.findall(r"\d+",s))); 
        if len(nums)!=3: raise ValueError("rgb(r,g,b)")
        r,g,b=[clamp(x) for x in nums]
    else:
        raise ValueError("Ожидается #RRGGBB или rgb(r,g,b)")
    h,ss,ll=rgb_to_hsl(r,g,b)
    if (r,g,b)==(0,0,0): c=m=y=0; k=1
    else:
        c=1-r/255; m=1-g/255; y=1-b/255; k=min(c,m,y); c=(c-k)/(1-k); m=(m-k)/(1-k); y=(y-k)/(1-k)
    return {"hex": f"#{r:02x}{g:02x}{b:02x}","rgb": f"rgb({r},{g},{b})","hsl": f"hsl({h},{ss}%,{ll}%)","cmyk": f"cmyk({round(c*100)},{round(m*100)},{round(y*100)},{round(k*100)})"}

def fmt_color(d):
    return f"🎨 HEX: <code>{d['hex']}</code>\nRGB: <code>{d['rgb']}</code>\nHSL: <code>{d['hsl']}</code>\nCMYK: <code>{d['cmyk']}</code>"

def convert_units(expr: str) -> Dict[str,Any]:
    parts = re.split(r"\s+to\s+|\s*>\s*", expr.strip(), flags=re.I)
    if len(parts)!=2: raise ValueError("Формат: '<значение> <ед> to <ед>'")
    left,right = parts
    m = re.match(r"^\s*([\-+]?\d+(?:\.\d+)?)\s*([A-Za-z°]+)\s*$", left)
    if not m: raise ValueError("Левая часть: '<число> <ед>'")
    val=float(m.group(1)); u_from=m.group(2).lower(); u_to=right.strip().lower()
    length = {"m":1,"km":1000,"cm":0.01,"mm":0.001,"mi":1609.344,"yd":0.9144,"ft":0.3048,"in":0.0254}
    mass = {"kg":1,"g":0.001,"lb":0.45359237,"oz":0.028349523125}
    def t(v,f,t):
        if f=="c" and t=="f": return v*9/5+32
        if f=="f" and t=="c": return (v-32)*5/9
        if f=="c" and t=="k": return v+273.15
        if f=="k" and t=="c": return v-273.15
        if f=="f" and t=="k": return (v-32)*5/9+273.15
        if f=="k" and t=="f": return (v-273.15)*9/5+32
        raise ValueError("Температурная конверсия не поддерживается")
    if u_from in length and u_to in length:
        meters=val*length[u_from]; res=meters/length[u_to]; kind="length"
    elif u_from in mass and u_to in mass:
        kg=val*mass[u_from]; res=kg/mass[u_to]; kind="mass"
    elif u_from in {"c","f","k"} and u_to in {"c","f","k"}:
        res=t(val,u_from,u_to); kind="temperature"
    else:
        raise ValueError("Единицы не поддерживаются")
    return {"kind": kind, "from": f"{val} {u_from}", "to_unit": u_to, "result": res}

def parse_timestamp(value: str) -> Dict[str,Any]:
    value=value.strip()
    if re.fullmatch(r"\d{10,13}", value):
        ts=int(value[:10]); dt=datetime.fromtimestamp(ts, tz=timezone.utc)
        return {"direction":"ts->date","timestamp":ts,"utc":dt.isoformat()}
    m=re.match(r"(\d{4})-(\d{2})-(\d{2})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$", value)
    if not m: raise ValueError("UNIX или 'YYYY-MM-DD HH:MM[:SS]' (UTC)")
    y,mo,d,hh,mm,ss=m.groups(); hh=int(hh or 0); mm=int(mm or 0); ss=int(ss or 0)
    dt=datetime(int(y),int(mo),int(d),hh,mm,ss,tzinfo=timezone.utc)
    return {"direction":"date->ts","timestamp":int(dt.timestamp()),"utc":dt.isoformat()}

async def clone_site(old_url, new_domain, copy_media, m: Message):
    old_netloc = urlparse(old_url).netloc
    visited = set()
    to_fetch = [old_url]
    async with aiohttp.ClientSession() as session:
        with tempfile.TemporaryDirectory() as tmpdir:
            while to_fetch:
                url = to_fetch.pop(0)
                if url in visited: continue
                visited.add(url)
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200: continue
                        content = await resp.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        for tag in soup.find_all(['a', 'link', 'script', 'img', 'source']):
                            attr = 'href' if tag.name in ['a', 'link'] else 'src' if tag.name in ['script', 'img', 'source'] else None
                            if attr and tag.get(attr):
                                old_link = tag[attr]
                                abs_link = urljoin(url, old_link)
                                if urlparse(abs_link).netloc == old_netloc:
                                    new_link = abs_link.replace(old_netloc, new_domain, 1)
                                    tag[attr] = new_link
                                    if is_media(abs_link) and copy_media:
                                        async with session.get(abs_link) as mresp:
                                            if mresp.status == 200:
                                                mcontent = await mresp.read()
                                                rel_path = urlparse(abs_link).path.lstrip('/')
                                                path = os.path.join(tmpdir, rel_path)
                                                os.makedirs(os.path.dirname(path), exist_ok=True)
                                                with open(path, 'wb') as f:
                                                    f.write(mcontent)
                                    if not is_media(abs_link):
                                        to_fetch.append(abs_link)
                        rel_path = urlparse(url).path.lstrip('/')
                        if not rel_path or rel_path.endswith('/'): rel_path = os.path.join(rel_path, 'index.html')
                        path = os.path.join(tmpdir, rel_path)
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                        with open(path, 'w', encoding='utf-8') as f:
                            f.write(str(soup))
                except Exception as e:
                    logger.error(f"Error cloning {url}: {e}")
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(tmpdir):
                    for file in files:
                        zf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), tmpdir))
            buf.seek(0)
            await m.answer_document(BufferedInputFile(buf.getvalue(), filename=f"{new_domain}.zip"), caption="Клон сайта готов")

def is_media(url):
    ext = os.path.splitext(url)[1].lower()
    return ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.css', '.js', '.mp4', '.webm', '.mp3', '.ogg', '.wav', '.pdf', '.ico']

# ================== FULL AUDIT ==================
async def full_audit(domain: str) -> Dict[str,Any]:
    dns_a = dns_svc.resolve(domain,"A")
    dns_aaaa = dns_svc.resolve(domain,"AAAA")
    dns_mx = dns_svc.resolve(domain,"MX")
    dns_ns = dns_svc.resolve(domain,"NS")
    dns_txt = dns_svc.resolve(domain,"TXT")
    dmarc = dns_svc.dmarc_parse(domain)
    spf = dns_svc.spf_parse(domain)
    tls = ssl_svc.tls_info(domain)
    tlsver = ssl_svc.tls_versions(domain)
    httpsec = http_svc.security_report(f"https://{domain}")
    who = whois_svc.domain_dates(domain)
    (A,AAAA,MX,NS,TXT,DMARC,SPF,TLS,TLSVER,HTTPSEC,WHO) = await asyncio.gather(
        dns_a, dns_aaaa, dns_mx, dns_ns, dns_txt, dmarc, spf, tls, tlsver, httpsec, who
    )
    health = await dns_svc.health(domain)
    return {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "dns": {"A":A,"AAAA":AAAA,"MX":MX,"NS":NS,"TXT":TXT},
        "mail": {"SPF":SPF,"DMARC":DMARC},
        "tls": {"info":TLS,"versions":TLSVER},
        "http": HTTPSEC,
        "whois": WHO,
        "health": health
    }

def render_audit_markdown(rep: Dict[str,Any]) -> str:
    d = rep
    def sect(title:str, body:str)->str: return f"## {title}\n{body}\n\n"
    out = [f"# Audit report for {d['domain']}\nGenerated: {d['generated_at']}\n"]
    def lst(rr): 
        arr = rr.get("records") or []
        return "\n".join(f"- `{x}`" for x in arr) if arr else "_—_"
    out.append(sect("DNS A", lst(d["dns"]["A"])))
    out.append(sect("DNS AAAA", lst(d["dns"]["AAAA"])))
    out.append(sect("DNS MX", lst(d["dns"]["MX"])))
    out.append(sect("DNS NS", lst(d["dns"]["NS"])))
    out.append(sect("DNS TXT", lst(d["dns"]["TXT"])))
    spf = d["mail"]["SPF"]; dmarc = d["mail"]["DMARC"]
    out.append(sect("SPF", lst(spf)))
    pol = dmarc.get("policy",{})
    pol_s = ", ".join(f"{k}={v}" for k,v in pol.items()) or "—"
    out.append(sect("DMARC", ( "\n".join(f"- `{x}`" for x in dmarc.get("raw",[])) or "—") + f"\n\n**Policy:** `{pol_s}`"))
    tls = d["tls"]["info"]; tlsver = d["tls"]["versions"]
    if tls.get("success"):
        c = tls["cert"]
        out.append(sect("TLS Info", f"- Proto: `{tls.get('protocol')}`\n- Cipher: `{tls.get('cipher')}`\n- ALPN: `{tls.get('alpn')}`\n- OCSP stapling: `{tls.get('ocsp_stapled')}`\n- Issuer: `{c.get('issuer')}`\n- NotAfter: `{c.get('not_after')}`\n- Days Left: `{c.get('days_left')}`"))
    else:
        out.append(sect("TLS Info", f"Error: {tls.get('error')}"))
    sv = tlsver.get("support",{})
    out.append(sect("TLS Versions", f"- TLS1.0: {'yes' if sv.get('TLS1.0') else 'no'}\n- TLS1.1: {'yes' if sv.get('TLS1.1') else 'no'}\n- TLS1.2: {'yes' if sv.get('TLS1.2') else 'no'}\n- TLS1.3: {'yes' if sv.get('TLS1.3') else 'no'}"))
    http = d["http"]
    if http.get("success"):
        notes = "\n".join(f"- {n}" for n in http.get("notes",[])) or "—"
        out.append(sect("HTTP Security", f"- URL: `{http.get('final_url')}`\n- Status: `{http.get('status')}`\n- Version: `{http.get('http_version')}`\n- Score: `{http.get('score')}` (grade {http.get('grade')})\n- Notes:\n{notes}"))
    else:
        out.append(sect("HTTP Security", f"Error: {http.get('error')}"))
    who = d["whois"]
    out.append(sect("WHOIS (dates)", f"- Created: `{who.get('created')}`\n- Updated: `{who.get('updated')}`\n- Expiry: `{who.get('expiry')}`\n- Registrar: `{who.get('registrar')}`"))
    h = d["health"]
    out.append(sect("DNS Health", f"- Status: **{h.get('status')}** ({h.get('score')}/100)\n- Warnings: {len(h.get('warnings',[]))}\n- Errors: {len(h.get('errors',[]))}"))
    return "\n".join(out)

# ================== START ==================
async def main():
    if BOT_TOKEN == "PUT_YOUR_TOKEN_HERE":
        logger.warning("Установите BOT_TOKEN env или пропишите токен в коде.")
    logger.info("Starting MAX bot…")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass