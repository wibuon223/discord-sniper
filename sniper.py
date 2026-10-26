#!/usr/bin/env python3
"""
discord username sniper — gen · check · hits

Discord's public check route (POST /api/v9/unique-username/username-attempt-unauthed)
is bucketed PER EXIT IP: ~3 lookups, then 429 with retry_after ~11-15 min.
So speed = fresh IPs, not threads. This tool rotates proxies per request, parks a
burned IP for its own retry_after, and never re-checks a name.

    sniper.py gen   --len 3                       # 17576 names, resumable
    sniper.py check -i names.txt                  # check a list
    sniper.py run   --pattern "_??"               # gen + check streaming
    sniper.py hits  --export hits.txt
    sniper.py proxies validate --url http://pxy.empty.codes/resi?token=...
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import random
import re
import sqlite3
import string
import sys
import threading
import time
import urllib.request
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "sniper.db")
DEFAULT_HITS = os.path.join(HERE, "hits.txt")

API = "https://discord.com/api/v9"
CHECK_URL = API + "/unique-username/username-attempt-unauthed"
PING_URL = API + "/gateway"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "discord/1.0.9197 Chrome/138.0.7204.251 Electron/37.2.6 Safari/537.36")
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "User-Agent": UA,
    "Origin": "https://discord.com",
    "Referer": "https://discord.com/register",
}

NAME_RE = re.compile(r"^[a-z0-9._]+$")
RESERVED = {"discord", "everyone", "here"}

AVAILABLE, TAKEN, INVALID, RATE_LIMITED, PROXY_DEAD, ERROR = (
    "available", "taken", "invalid", "rate_limited", "proxy_dead", "error")


# ─────────────────────────── name rules ───────────────────────────
def valid_username(n: str) -> bool:
    # proven by live probe: leading/trailing "_" and "." are accepted (200), ".." is not (400)
    if not (2 <= len(n) <= 32) or not NAME_RE.match(n):
        return False
    if ".." in n or n in RESERVED:
        return False
    return True


# ─────────────────────────── generator ────────────────────────────
def _idx(name: str, alphabet: str) -> int:
    base = len(alphabet)
    i = 0
    for ch in name:
        i = i * base + alphabet.index(ch)
    return i


def _name(i: int, alphabet: str, length: int) -> str:
    base = len(alphabet)
    out = []
    for _ in range(length):
        i, r = divmod(i, base)
        out.append(alphabet[r])
    return "".join(reversed(out))


def passes(name: str, cfg) -> bool:
    if cfg.no_double and any(a == b for a, b in zip(name, name[1:])):
        return False
    if cfg.all_unique and len(set(name)) != len(name):
        return False
    vowels = sum(c in "aeiou" for c in name)
    if cfg.vowel and vowels == 0:
        return False
    if cfg.no_vowel and vowels > 0:
        return False
    if cfg.exclude and re.search(cfg.exclude, name):
        return False
    if cfg.include and not re.search(cfg.include, name):
        return False
    return valid_username(name)


def make_alphabet(cfg) -> str:
    a = "abcdefghijklmnopqrstuvwxyz"
    if cfg.digits:
        a += "0123456789"
    if cfg.underscore:
        a += "_"
    if cfg.dot:
        a += "."
    return a


def gen_names(cfg, start: str | None = None, skip=None):
    """Yield names in stable lexicographic order, resumable from `start`.
    `skip` is a preloaded set of already-checked names — cheaper than a DB hit per name."""
    skip = skip or frozenset()
    for name in _gen_names(cfg, start):
        if name in skip:
            continue
        yield name


def _gen_names(cfg, start: str | None = None):
    if cfg.pattern:
        if "?" not in cfg.pattern and "*" not in cfg.pattern:
            name = cfg.pattern.lower()
            if passes(name, cfg):
                yield name
            return
        alphabet = make_alphabet(cfg)
        toks = []
        for ch in cfg.pattern.lower():
            if ch == "?":
                toks.append(alphabet)
            elif ch == "*":
                toks.append(alphabet)
            else:
                toks.append(ch)
        # '*' expands to 1..max chars of alphabet; '?' is exactly one char
        expansions = [toks]
        if "*" in cfg.pattern:
            expansions = []
            for k in range(0, 4):
                seq = []
                for ch in cfg.pattern.lower():
                    seq.append(alphabet * k if ch == "*" else (alphabet if ch == "?" else ch))
                expansions.append(seq)
        for seq in expansions:
            for combo in itertools.product(*seq):
                name = "".join(combo)
                if start and name <= start:
                    continue
                if passes(name, cfg):
                    yield name
        return

    alphabet = make_alphabet(cfg)
    length = cfg.length
    total = len(alphabet) ** length
    if cfg.random:
        # sample the whole space instead of grinding a-prefix first: available names are
        # scattered, and a small IP budget should cover breadth, not depth
        rnd = random.Random(cfg.seed)
        tried: set[str] = set()
        while len(tried) < total:
            i = rnd.randrange(total)
            if i in tried:
                continue
            tried.add(i)
            name = _name(i, alphabet, length)
            if passes(name, cfg):
                yield name
        return
    i = _idx(start, alphabet) + 1 if start and set(start) <= set(alphabet) else 0
    for n in range(i, total):
        name = _name(n, alphabet, length)
        if passes(name, cfg):
            yield name


# ─────────────────────────── store ────────────────────────────
class Store:
    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()
        c = self.conn()
        c.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS names(
                name TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT,
                checked_at REAL, proxy TEXT);
            CREATE INDEX IF NOT EXISTS idx_status ON names(status);
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        """)
        c.commit()

    def conn(self):
        if not hasattr(self._local, "c"):
            self._local.c = sqlite3.connect(self.path, timeout=30)
            self._local.c.execute("PRAGMA journal_mode=WAL")
        return self._local.c

    def put(self, name, status, detail="", proxy=""):
        c = self.conn()
        c.execute("INSERT INTO names(name,status,detail,checked_at,proxy) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET status=excluded.status, "
                  "detail=excluded.detail, checked_at=excluded.checked_at, proxy=excluded.proxy",
                  (name, status, detail, time.time(), proxy))
        c.commit()

    def seen(self, name) -> bool:
        r = self.conn().execute("SELECT status FROM names WHERE name=?", (name,)).fetchone()
        return bool(r) and r[0] not in (ERROR, RATE_LIMITED)

    def get_meta(self, k, default=None):
        r = self.conn().execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def set_meta(self, k, v):
        c = self.conn()
        c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                  (k, str(v)))
        c.commit()

    def rows(self, status=None, limit=None):
        q, a = "SELECT name,status,detail,checked_at FROM names", []
        if status:
            q += " WHERE status=?"; a.append(status)
        q += " ORDER BY checked_at DESC"
        if limit:
            q += " LIMIT ?"; a.append(limit)
        return self.conn().execute(q, a).fetchall()

    def count(self, status=None):
        if status:
            return self.conn().execute("SELECT count(*) FROM names WHERE status=?", (status,)).fetchone()[0]
        return self.conn().execute("SELECT count(*) FROM names").fetchone()[0]


# ─────────────────────────── proxies ────────────────────────────
class Proxy:
    __slots__ = ("url", "alive", "parked_until", "fails", "uses", "note", "_lock")

    def __init__(self, url):
        self.url = url.strip()
        self.alive = True
        self.parked_until = 0.0
        self.fails = 0
        self.uses = 0
        self.note = ""
        self._lock = threading.Lock()

    def free(self) -> bool:
        return self.alive and self.parked_until <= time.time()

    def park(self, seconds: float, note=""):
        with self._lock:
            self.parked_until = time.time() + max(seconds, 1.0)
            self.note = note

    def __repr__(self):
        return f"<{self.url} alive={self.alive} park={max(0, int(self.parked_until - time.time()))}s>"


class ProxyPool:
    def __init__(self, urls, state_path=None):
        self.proxies = [Proxy(u) for u in dict.fromkeys(u.strip() for u in urls if u.strip())]
        self._lock = threading.Lock()
        self.state_path = state_path
        self._load()

    # park state survives restarts: burning a 30-min IP twice for nothing is the
    # difference between a trickle and a dry pool
    def _load(self):
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            st = json.load(open(self.state_path))
        except Exception:
            return
        now = time.time()
        for p in self.proxies:
            s = st.get(p.url)
            if not s:
                continue
            if s.get("dead") and now - s.get("ts", 0) < 1800:
                p.alive = False
                p.note = s.get("note", "")
            pu = float(s.get("parked_until") or 0)
            if pu > now:
                p.parked_until = pu

    def _save(self):
        if not self.state_path:
            return
        try:
            now = time.time()
            st = {p.url: {"dead": not p.alive, "parked_until": p.parked_until,
                          "note": p.note, "ts": now} for p in self.proxies}
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(st, f)
            os.replace(tmp, self.state_path)
        except Exception:
            pass

    def __len__(self):
        return len(self.proxies)

    def next(self, timeout=900.0) -> Proxy:
        """Blocking pick: least-recently-used free proxy; else sleep to earliest unpark."""
        end = time.time() + timeout
        while True:
            with self._lock:
                free = [p for p in self.proxies if p.free()]
                if free:
                    p = min(free, key=lambda x: x.uses)
                    p.uses += 1
                    return p
                alive = [p for p in self.proxies if p.alive]
                if not alive:
                    raise RuntimeError("no usable proxies left")
                wait = min(p.parked_until for p in alive) - time.time()
            if time.time() > end:
                raise TimeoutError("all proxies parked")
            time.sleep(max(0.05, min(wait, 5.0)))

    def park(self, p: Proxy, seconds: float, note=""):
        p.park(seconds, note)
        self._save()

    def kill(self, p: Proxy, note=""):
        with self._lock:
            p.alive = False
            p.note = note or p.note
        self._save()

    def stats(self):
        alive = sum(p.alive for p in self.proxies)
        ready = sum(p.free() for p in self.proxies)
        extra = ""
        if alive and not ready:
            nxt = min(p.parked_until for p in self.proxies if p.alive) - time.time()
            extra = f", next in {max(0, int(nxt))}s"
        return f"proxies {ready}/{alive} ready (of {len(self.proxies)}{extra})"


def load_proxies(args) -> list[str]:
    urls: list[str] = []
    if args.proxy:
        urls += args.proxy
    if args.proxy_file:
        path = os.path.expanduser(args.proxy_file)
        if os.path.exists(path):
            with open(path) as f:
                urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        else:
            eprint(f"proxy-file {path} not found — falling back to direct")
    if args.proxy_url:
        for u in args.proxy_url:
            try:
                raw = urllib.request.urlopen(u, timeout=20).read().decode()
                urls += [l.strip() for l in raw.splitlines() if "://" in l or re.match(r"^[\w.-]+:\d+$", l.strip())]
            except Exception as e:
                eprint(f"proxy-url {u}: {e}")
    out = []
    for u in urls:
        u = u.strip()
        if not u:
            continue
        if "://" not in u:
            u = "http://" + u
        if u not in out:
            out.append(u)
    return out


# ─────────────────────────── http ────────────────────────────
_clients: dict[str, object] = {}
_cl = threading.Lock()


def _client(proxy: str | None):
    import httpx
    key = proxy or "direct"
    with _cl:
        c = _clients.get(key)
        if c is None:
            c = httpx.Client(
                proxy=proxy, timeout=httpx.Timeout(20.0, connect=15.0),
                headers={"User-Agent": UA}, follow_redirects=False,
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
                verify=False,
            )
            _clients[key] = c
        return c


def _socks_post(proxy_url: str, url: str, body: bytes, timeout=20.0):
    """Minimal HTTPS POST over SOCKS5 (no socksio installed)."""
    import ssl
    import socks  # PySocks
    from urllib.parse import urlparse
    import http.client

    pr = urlparse(proxy_url)
    ph, pp = pr.hostname, pr.port or 1080
    u = urlparse(url)
    host = u.hostname
    port = u.port or 443
    path = u.path + (("?" + u.query) if u.query else "")

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, ph, pp, rdns=True)
    s.settimeout(timeout)
    s.connect((host, port))
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(s, server_hostname=host)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = ss
    conn.request("POST", path, body=body, headers=HEADERS)
    r = conn.getresponse()
    data = r.read()
    status, hdrs = r.status, dict(r.getheaders())
    conn.close()
    return status, hdrs, data


def api_post(username: str, proxy: str | None, timeout=20.0):
    body = json.dumps({"username": username}).encode()
    if proxy and proxy.startswith(("socks5", "socks4")):
        return _socks_post(proxy, CHECK_URL, body, timeout)
    r = _client(proxy).post(CHECK_URL, content=body, headers=HEADERS)
    return r.status_code, dict(r.headers), r.content


def api_ping(proxy: str | None, timeout=15.0):
    if proxy and proxy.startswith(("socks5", "socks4")):
        import ssl
        import socks
        from urllib.parse import urlparse
        import http.client
        pr = urlparse(proxy)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, pr.hostname, pr.port or 1080, rdns=True)
        s.settimeout(timeout)
        s.connect(("discord.com", 443))
        ss = ssl.create_default_context().wrap_socket(s, server_hostname="discord.com")
        conn = http.client.HTTPConnection("discord.com", 443, timeout=timeout)
        conn.sock = ss
        conn.request("GET", "/api/v9/gateway", headers=HEADERS)
        r = conn.getresponse()
        r.read()
        return r.status
    return _client(proxy).get(PING_URL).status_code


# ─────────────────────────── checker ────────────────────────────
def check_name(name: str, proxy: Proxy | None):
    """→ (status, detail)"""
    try:
        st, hdrs, data = api_post(name, proxy.url if proxy else None)
    except Exception as e:
        msg = repr(e)[:160]
        if any(k in msg for k in ("Tunnel connection failed", "407", "Proxy", "SOCKS", "ConnectError", "SSLEOF", "timed out", "Timeout")):
            return PROXY_DEAD, msg
        return ERROR, msg

    txt = data[:400].decode("utf-8", "replace")
    if st == 200:
        try:
            j = json.loads(txt)
        except Exception:
            return ERROR, txt
        return (TAKEN if j.get("taken") else AVAILABLE), txt
    if st == 429:
        try:
            ra = json.loads(txt).get("retry_after", 900)
        except Exception:
            ra = 900
        return RATE_LIMITED, str(ra)
    if st == 400:
        return INVALID, txt
    if st in (401, 403, 404):
        return ERROR, f"HTTP {st}: {txt}"
    if st == 407:
        return PROXY_DEAD, "407 proxy auth"
    return ERROR, f"HTTP {st}: {txt}"


def dry_check(name: str):
    h = hashlib.md5(name.encode()).hexdigest()
    return (AVAILABLE if h[0] == "0" else TAKEN), "dry"


# ─────────────────────────── runner ────────────────────────────
def eprint(*a):
    print(*a, file=sys.stderr, flush=True)


ROTATING_HINTS = ("p.webshare.io", "-rotate", "brd.superproxy.io", "zproxy.lum-superproxy.io")


def is_rotating(url: str) -> bool:
    """Rotating providers hand out a new exit IP per request, so a 429 means *that
    exit* is burned — retrying after a short cool-down is nearly free and often lands
    a fresh IP. Parking them for the full window throws away the whole point."""
    return any(h in url for h in ROTATING_HINTS)


class Runner:
    def __init__(self, args, store: Store, skip=None):
        self.a = args
        self.store = store
        self.skip = skip if skip is not None else set()
        self.pool = ProxyPool(load_proxies(args),
                              state_path=os.path.join(HERE, "proxy_state.json"))
        if not len(self.pool):
            # CI runners get a fresh egress IP every run — use it instead of dying
            self.pool = ProxyPool(["direct://"], state_path=None)
        self.dry = args.checker == "dry"
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.n = dict(checked=0, taken=0, avail=0, invalid=0, err=0, rl=0, dead_proxy=0)
        self.hits: list[str] = []
        self.t0 = time.time()
        self.hit_f = open(args.hits_out, "a") if args.hits_out else None

    # one name, with proxy retries
    def work(self, name: str):
        if self.stop.is_set() or name in self.skip or self.store.seen(name):
            return
        if self.dry:
            st, d = dry_check(name)
        else:
            st, d = ERROR, "no proxy"
            attempts = 0
            while attempts < self.a.retries and not self.stop.is_set():
                try:
                    p = self.pool.next(timeout=self.a.proxy_wait)
                except Exception as e:
                    if self.a.keep_going and not self.stop.is_set():
                        if not getattr(self, "_dry_warned", False):
                            self._dry_warned = True
                            eprint(f"\npool parked ({e}) — --keep-going: nunggu IP balik, gak exit")
                        time.sleep(min(30.0, self.a.proxy_wait))
                        continue
                    eprint(f"\npool dry: {e} — semua IP parked/dead. "
                           f"tambah proxy (--proxy-file / --proxy-url), pakai --keep-going, "
                           f"atau turunkan --proxy-wait.")
                    self.stop.set()
                    break
                attempts += 1
                st, d = check_name(name, None if p.url.startswith("direct") else p)
                if st == RATE_LIMITED:
                    if p.url.startswith("direct"):
                        # runner IP has no 3-check bucket worth waiting on; next CI
                        # run gets a brand-new egress IP, so stop instead of idling
                        eprint(f"\n[429] runner IP burned — ending run (next job = fresh IP)")
                        self.stop.set()
                        break
                    park_s = float(d or 900)
                    if is_rotating(p.url):
                        park_s = min(park_s, self.a.rotate_cooldown)
                    self.pool.park(p, park_s, "429")
                    with self.lock:
                        if self.n["rl"] == 0:
                            eprint(f"\n[429] ip burned, parked {float(d or 900):.0f}s — "
                                   f"1 IP ≈ 3 checks per window, need fresh IPs")
                        self.n["rl"] += 1
                    continue
                if st == PROXY_DEAD:
                    self.pool.kill(p, d)
                    with self.lock:
                        self.n["dead_proxy"] += 1
                    continue
                break
        self.record(name, st, d)

    def record(self, name, st, d):
        self.store.put(name, st, str(d)[:200])
        self.skip.add(name)
        with self.lock:
            self.n["checked"] += 1
            if st == AVAILABLE:
                self.n["avail"] += 1
                self.hits.append(name)
                line = f"[HIT] {name}"
                print("\r" + line.ljust(60), flush=True)
                if self.hit_f:
                    self.hit_f.write(name + "\n"); self.hit_f.flush()
                if self.a.webhook:
                    threading.Thread(target=post_webhook, args=(self.a.webhook, name), daemon=True).start()
                if getattr(self.a, "telegram", False):
                    threading.Thread(target=notify_telegram,
                                     args=(name, classify(name)), daemon=True).start()
                if self.a.stop_after_hits and len(self.hits) >= self.a.stop_after_hits:
                    self.stop.set()
            elif st == TAKEN:
                self.n["taken"] += 1
            elif st == INVALID:
                self.n["invalid"] += 1
            else:
                self.n["err"] += 1

    def progress(self):
        if not sys.stderr.isatty() or self.a.quiet:
            return
        while not self.done:
            time.sleep(0.7)
            e = time.time() - self.t0
            n = self.n
            rate = n["checked"] / e if e else 0
            left = ""
            if self.a.limit and rate > 0:
                left = f" eta={max(0, (self.a.limit - n['checked']) / rate):.0f}s"
            pool = "" if self.dry else " " + self.pool.stats()
            eprint(f"\rchecked {n['checked']}  hit {n['avail']}  taken {n['taken']}  "
                   f"429 {n['rl']}  err {n['err']}  {rate:.2f}/s{left}{pool}          ")

    def run(self, names, drain=True):
        self.done = False
        t = threading.Thread(target=self.progress, daemon=True)
        t.start()
        q = deque()
        qlock = threading.Lock()
        producers_done = False

        def worker():
            while True:
                with qlock:
                    if q:
                        name = q.popleft()
                    elif producers_done or self.stop.is_set():
                        return
                    else:
                        name = None
                if name is None:
                    time.sleep(0.02)
                    continue
                try:
                    self.work(name)
                except Exception as e:
                    eprint(f"worker: {e!r}")

        workers = [threading.Thread(target=worker, daemon=True) for _ in range(self.a.workers)]
        for w in workers:
            w.start()

        taken = 0
        for name in names:
            if self.stop.is_set():
                break
            with qlock:
                q.append(name)
            taken += 1
            if self.a.limit and taken >= self.a.limit:
                break
            while len(q) > self.a.workers * 8 and not self.stop.is_set():
                time.sleep(0.02)
        producers_done = True
        if not drain:
            # deadline hit: don't spend 20 more minutes draining a queue we can
            # re-derive next run (progress lives in the DB, not a cursor)
            self.stop.set()
        for w in workers:
            w.join()
        self.done = True
        time.sleep(0.05)
        eprint()
        return self.summary()

    def summary(self):
        e = time.time() - self.t0
        n = self.n
        print(f"\nchecked {n['checked']} in {e:.0f}s ({n['checked'] / e if e else 0:.2f}/s) · "
              f"hit {n['avail']} · taken {n['taken']} · invalid {n['invalid']} · 429 {n['rl']} · err {n['err']}")
        if self.hits:
            print("HITS: " + " ".join(self.hits[:40]) + (" …" if len(self.hits) > 40 else ""))


def post_webhook(url: str, name: str):
    try:
        req = urllib.request.Request(url, data=json.dumps(
            {"content": f"**HIT** `{name}` — https://discord.com/register"}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": UA})
        urllib.request.urlopen(req, timeout=15).read()
    except Exception:
        pass


# ──────────────── families · telegram · web export ────────────────
FAMILIES = [
    ("3-letter", dict(length=3)),
    ("3-alnum", dict(length=3, digits=True)),
    ("4-letter", dict(length=4)),
    ("4-alnum", dict(length=4, digits=True)),
    ("5-letter", dict(length=5)),
    ("3-unique", dict(pattern="_??")),
    ("4-unique", dict(pattern="_???")),
]

_FAM_DEFAULTS = dict(pattern=None, length=3, digits=False, underscore=False, dot=False,
                     no_double=False, all_unique=False, vowel=False, no_vowel=False,
                     include=None, exclude=None, random=False, seed=None, limit=None)


def fam_cfg(kw):
    d = dict(_FAM_DEFAULTS)
    d.update(kw)
    return argparse.Namespace(**d)


def classify(name: str) -> str:
    for fam, kw in FAMILIES:
        cfg = fam_cfg(kw)
        if cfg.pattern:
            wild = cfg.pattern.count("?")
            if len(name) == wild + cfg.pattern.count("_") and name.startswith("_") \
                    and name[1:].isalpha():
                return fam
        elif len(name) == cfg.length:
            if cfg.digits:
                if name.isalnum() and any(c.isdigit() for c in name):
                    return fam
            elif name.isalpha():
                return fam
    return f"{len(name)}-other"


def send_telegram(text: str):
    tok = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not tok or not chat:
        return
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{tok}/sendMessage",
        data=json.dumps({"chat_id": chat, "text": text,
                         "disable_web_page_preview": True}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:
        eprint(f"telegram: {e!r}")


def notify_telegram(name: str, family: str):
    send_telegram(f"🎯 DISCORD HIT: {name}\n"
                  f"family: {family}  ·  len {len(name)}\n"
                  f"https://discord.com/register")


def export_hits(store, path):
    rows = store.rows(None, None)
    hits = [{"name": n, "family": classify(n), "len": len(n), "found": int(ts or 0)}
            for n, st, _d, ts in rows if st == AVAILABLE]
    by_fam: dict[str, int] = {}
    for h in hits:
        by_fam[h["family"]] = by_fam.get(h["family"], 0) + 1
    payload = {"updated": int(time.time()), "count": len(hits),
               "by_family": by_fam, "hits": sorted(hits, key=lambda h: -h["found"])}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(payload, f, indent=1)
    os.replace(tmp, path)
    eprint(f"hits.json → {path} ({len(hits)} hits)")
    return payload


# ─────────────────────────── commands ────────────────────────────
def cmd_grind(a, store):
    """Priority grind across families with a wall-clock budget (for CI runners)."""
    deadline = time.time() + a.minutes * 60 if a.minutes else None
    skip = {n for (n,) in store.conn().execute("SELECT name FROM names")}
    fams = [(f, kw) for f, kw in FAMILIES if not a.only or f in a.only]
    if not fams:
        eprint(f"no such family; pick from {[f for f, _ in FAMILIES]}")
        return
    runner = Runner(a, store, skip=skip)
    fam_iter = iter(fams)
    cur = {"fam": None}

    def fam_stats():
        seen: dict[str, list[int]] = {}
        for n, st in store.conn().execute("SELECT name, status FROM names"):
            s = seen.setdefault(classify(n), [0, 0])
            s[0] += 1
            if st == AVAILABLE:
                s[1] += 1
        return seen

    stats = fam_stats()

    def names():
        for fam, kw in fam_iter:
            cfg = fam_cfg(kw)
            cur["fam"] = fam
            checked, found = stats.get(fam, [0, 0])
            if a.dead_after and checked >= a.dead_after and found == 0:
                eprint(f"\n== skip {fam}: {checked} checked, 0 hits (dead) ==")
                continue
            eprint(f"\n== family {fam} ({checked} checked, {found} hits so far) ==")
            if not a.quiet:
                print(f"[family] {fam}")
            for n in gen_names(cfg, None, skip=runner.skip):
                if deadline and time.time() > deadline:
                    return
                yield n

    runner.run(names(), drain=False)
    hits = export_hits(store, a.hits_json)
    if hits["count"]:
        eprint(f"total hits in db: {hits['count']} · by family {hits['by_family']}")
    if getattr(a, "telegram", False):
        new = runner.n["avail"]
        if new:
            send_telegram(f"✅ run done: +{new} hit · total {hits['count']}\n"
                          f"{json.dumps(hits['by_family'])}")


def cmd_gen(a, store):
    cfg = a
    start = a.start
    count = 0
    out = open(a.out, "w") if a.out else sys.stdout
    try:
        for name in gen_names(cfg, start):
            out.write(name + "\n")
            count += 1
            if a.limit and count >= a.limit:
                break
    finally:
        if a.out:
            out.close()
    if a.out:
        eprint(f"{count} names → {a.out}")


def cmd_check(a, store):
    if a.input == "-":
        names = (l.strip().lower() for l in sys.stdin if l.strip())
    else:
        names = (l.strip().lower() for l in open(a.input) if l.strip())
    names = (n for n in names if not store.seen(n))
    r = Runner(a, store)
    r.run(names)


def cmd_run(a, store):
    """No cursor needed: the DB *is* the progress. Already-checked names are skipped,
    so a rerun continues where the last one died."""
    done = store.count()
    if done and not a.start:
        eprint(f"{done} names already in db — skipping them")
    r = Runner(a, store)
    r.run(gen_names(a, a.start))


def cmd_plan(a, store):
    """Honest capacity math: 1 IP ≈ 3 checks, then parked ~13 min."""
    alphabet = make_alphabet(a)
    if not a.pattern:
        total = len(alphabet) ** a.length
        filtered = sum(1 for _ in itertools.islice(gen_names(a), 3_000_000)) if (
            a.no_double or a.all_unique or a.vowel or a.no_vowel or a.include or a.exclude) else total
    else:
        filtered = sum(1 for _ in itertools.islice(gen_names(a), 3_000_000))
    per_ip_hour = 3 * 3600 / 800  # ~3 checks per ~800s window
    print(f"space        {total if not a.pattern else '?'} combos")
    print(f"after filter {filtered}")
    print(f"1 IP        ~{per_ip_hour:.1f} checks/hour")
    for n in (10, 100, 1_000, 10_000):
        hrs = filtered / (per_ip_hour * n)
        print(f"{n:>6} IPs   ~{hrs:8.1f} h   (~{hrs / 24:.1f} days)")


def cmd_hits(a, store):
    rows = store.rows(AVAILABLE, a.limit) if not a.taken else store.rows(TAKEN, a.limit)
    for name, status, detail, ts in rows:
        print(name)
    if a.export:
        with open(a.export, "w") as f:
            for name, *_ in rows:
                f.write(name + "\n")
        eprint(f"{len(rows)} → {a.export}")
    if not rows:
        eprint("no hits yet")


def cmd_stats(a, store):
    order = [AVAILABLE, TAKEN, INVALID, ERROR]
    tot = store.count()
    print(f"total {tot}")
    for s in order:
        print(f"  {s:<10} {store.count(s)}")
    cur = store.conn().execute("SELECT k, v FROM meta WHERE k LIKE 'cursor:%'").fetchall()
    for k, v in cur:
        print(f"  {k} = {v}")


PUBLIC_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://openproxylist.xyz/http.txt",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
]


def cmd_harvest(a, store):
    """Grow the pool: public lists → TLS-reachable → passes a REAL username check.
    Free exits are ~0.8% usable for Discord's auth route, so this has to run in a loop.
    """
    import concurrent.futures as cf

    cands: set[str] = set()
    for u in dict.fromkeys(PUBLIC_SOURCES + (a.source or [])):
        try:
            raw = urllib.request.urlopen(u, timeout=25).read().decode("utf-8", "replace")
        except Exception as e:
            eprint(f"src fail {u.split('/')[2]}: {repr(e)[:60]}")
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" in line:
                cands.add(line)
            elif "@" in line:  # user:pass@host:port (gateway /proxies.txt style)
                cands.add("http://" + line)
        for m in re.finditer(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})", raw):
            cands.add(f"http://{m.group(1)}:{m.group(2)}")
    if a.max_candidates:
        cands = set(list(cands)[:a.max_candidates])
    eprint(f"harvest: {len(cands)} candidates")

    def ping(u):
        try:
            return u if api_ping(u, timeout=7) == 200 else None
        except Exception:
            return None

    alive = []
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for r in ex.map(ping, cands):
            if r:
                alive.append(r)
    eprint(f"reachable {len(alive)}")

    probe_name = "".join(random.choice(string.ascii_lowercase) for _ in range(11))

    def chk(u):
        try:
            st, _ = check_name(probe_name, Proxy(u))
            return u if st in (TAKEN, AVAILABLE) else None
        except Exception:
            return None

    usable = []
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for r in ex.map(chk, alive):
            if r:
                usable.append(r)
    eprint(f"usable for username route {len(usable)}")

    existing = [l.strip() for l in open(a.out)] if os.path.exists(a.out) else []
    merged = list(dict.fromkeys(existing + usable))
    with open(a.out, "w") as f:
        f.write("\n".join(merged) + "\n")
    eprint(f"pool {len(existing)} → {len(merged)} (+{len(merged) - len(existing)})")


def cmd_proxies(a, store):
    urls = load_proxies(a)
    if not urls:
        eprint("no proxies given (--proxy/--proxy-file/--proxy-url)"); return
    eprint(f"validating {len(urls)} proxies against discord…")
    good, bad = [], 0
    lock = threading.Lock()

    def one(u):
        nonlocal bad
        try:
            st = api_ping(u)
            ok = st in (200, 204)
        except Exception as e:
            ok = False
        with lock:
            if ok:
                good.append(u)
                print(f"OK   {u}")
            else:
                bad += 1
    ths = [threading.Thread(target=one, args=(u,)) for u in urls]
    for i in range(0, len(ths), 32):
        batch = ths[i:i + 32]
        for t in batch: t.start()
        for t in batch: t.join()
    print(f"\n{len(good)} alive / {len(urls)} tested")
    if a.out and good:
        open(a.out, "w").write("\n".join(good) + "\n")
        eprint(f"→ {a.out}")


def cmd_doctor(a, store):
    print("direct:  ", end="")
    try:
        print(f"HTTP {api_ping(None)}")
    except Exception as e:
        print("ERR", repr(e)[:120])
    for u in load_proxies(a):
        print(f"{u:<60}", end="")
        try:
            print(f"HTTP {api_ping(u)}")
        except Exception as e:
            print("ERR", repr(e)[:80])
    print(store.path, "→", store.count(), "names")


def main():
    ap = argparse.ArgumentParser(prog="sniper", description="discord username sniper")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def gen_opts(p):
        p.add_argument("--len", dest="length", type=int, default=3)
        p.add_argument("--pattern", help="template: ? = any char, * = 0-3 chars ('_??', '_ie')")
        p.add_argument("--digits", action="store_true")
        p.add_argument("--underscore", action="store_true")
        p.add_argument("--dot", action="store_true")
        p.add_argument("--no-double", action="store_true", help="no adjacent repeats (aab)")
        p.add_argument("--all-unique", action="store_true")
        p.add_argument("--vowel", action="store_true", help="must contain a vowel")
        p.add_argument("--no-vowel", action="store_true")
        p.add_argument("--include", help="regex must match")
        p.add_argument("--exclude", help="regex must not match")
        p.add_argument("--start", help="resume cursor (name to continue after)")
        p.add_argument("--random", action="store_true", help="sample the whole space randomly")
        p.add_argument("--seed", type=int, default=None, help="seed for --random")
        p.add_argument("--limit", type=int)

    def net_opts(p):
        p.add_argument("--proxy", action="append", help="proxy url (repeatable)")
        p.add_argument("--proxy-file")
        p.add_argument("--proxy-url", action="append", help="url serving a proxy list")
        p.add_argument("--checker", choices=["http", "dry"], default="http")
        p.add_argument("--workers", type=int, default=8)
        p.add_argument("--retries", type=int, default=3)
        p.add_argument("--proxy-wait", type=float, default=60,
                       help="seconds to wait for a parked IP to come back (default 60)")
        p.add_argument("--keep-going", action="store_true",
                       help="never exit on an exhausted pool: sleep until an IP unparks")
        p.add_argument("--rotate-cooldown", type=float, default=25,
                       help="retry a rotating proxy after this many seconds on 429 (default 25)")
        p.add_argument("--webhook")
        p.add_argument("--telegram", action="store_true",
                       help="push every hit to Telegram (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)")
        p.add_argument("--hits-out", default=DEFAULT_HITS,
                       help="live-append only AVAILABLE names (default hits.txt)")
        p.add_argument("--stop-after-hits", type=int, default=0)
        p.add_argument("--quiet", action="store_true")

    g = sub.add_parser("gen", help="generate names")
    gen_opts(g); g.add_argument("--out")

    c = sub.add_parser("check", help="check names from a file")
    c.add_argument("-i", "--input", required=True, help="file or - for stdin")
    net_opts(c); gen_opts(c)

    r = sub.add_parser("run", help="generate + check streaming")
    gen_opts(r); net_opts(r)

    h = sub.add_parser("hits", help="show/export available names")
    h.add_argument("--limit", type=int)
    h.add_argument("--taken", action="store_true")
    h.add_argument("--export")

    sub.add_parser("stats", help="counters + cursors")
    pl = sub.add_parser("plan", help="how long would this sweep take")
    gen_opts(pl)
    gr = sub.add_parser("grind", help="priority families with a time budget (CI)")
    net_opts(gr)
    gr.add_argument("--minutes", type=float, default=20)
    gr.add_argument("--only", action="append", help="restrict to family name(s)")
    gr.add_argument("--dead-after", type=int, default=400,
                    help="skip a family after N checks with 0 hits (default 400)")
    gr.add_argument("--hits-json", default=os.path.join(HERE, "docs", "hits.json"))
    gr.set_defaults(limit=0)

    hv = sub.add_parser("harvest", help="scan public lists and grow proxies.txt")
    hv.add_argument("--source", action="append")
    hv.add_argument("--workers", type=int, default=120)
    hv.add_argument("--max-candidates", type=int, default=0)
    hv.add_argument("--out", default=os.path.join(HERE, "proxies.txt"))
    pr = sub.add_parser("proxies", help="validate proxies")
    pr.add_argument("--proxy", action="append"); pr.add_argument("--proxy-file")
    pr.add_argument("--proxy-url", action="append"); pr.add_argument("--out")
    d = sub.add_parser("doctor", help="connectivity check")
    d.add_argument("--proxy", action="append"); d.add_argument("--proxy-file")
    d.add_argument("--proxy-url", action="append")

    a = ap.parse_args()
    store = Store(a.db)
    {"gen": cmd_gen, "check": cmd_check, "run": cmd_run, "hits": cmd_hits,
     "stats": cmd_stats, "plan": cmd_plan, "harvest": cmd_harvest, "grind": cmd_grind,
     "proxies": cmd_proxies, "doctor": cmd_doctor}[a.cmd](a, store)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        eprint("\nstopped")
