"""Source fetchers. Each returns a list of Item (new or changed content only is decided by the caller,
except *snapshot* sources (advisory pages) which compare against the last snapshot themselves)."""
from __future__ import annotations

import difflib
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Callable
from urllib.parse import urljoin

import feedparser
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparse

from .core import Item, State, norm_ws, now_utc, stable_hash

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/129.0.0.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "Accept-Language": "en-GB,en;q=0.9,ru;q=0.6,lv;q=0.5"}
TIMEOUT = 30


class SoftFail(Exception):
    """The source could not be read, but this is a known/benign condition (e.g. bot-blocking by a CDN)
    and another source covers the same signal. Reported as a note, not as a failure."""


def http_get(url: str, **kw) -> requests.Response:
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kw)
    r.raise_for_status()
    return r


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "lxml")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    return norm_ws(soup.get_text(" "))


def parse_date(s) -> str | None:
    if not s:
        return None
    try:
        d = dtparse.parse(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None


def too_old(published: str | None, max_age_days: int | None) -> bool:
    if not max_age_days or not published:
        return False
    try:
        d = datetime.fromisoformat(published)
    except Exception:
        return False
    return d < now_utc() - timedelta(days=max_age_days)


def matches_any(text: str, words: list[str] | None) -> bool:
    if not words:
        return True
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


def text_diff(old: str, new: str, max_lines: int = 14) -> str:
    """Compact word-level-ish diff: sentence granularity."""
    def sents(s):
        return [x.strip() for x in re.split(r"(?<=[.!?])\s+", s or "") if x.strip()]
    a, b = sents(old), sents(new)
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        for s in a[i1:i2]:
            out.append("− " + s)
        for s in b[j1:j2]:
            out.append("+ " + s)
    if len(out) > max_lines:
        out = out[:max_lines] + [f"… ({len(out) - max_lines} more changes)"]
    return "\n".join(out)


# ------------------------------------------------------------------ RSS / Atom

def fetch_rss(src: dict, state: State) -> list[Item]:
    items: list[Item] = []
    try:
        r = http_get(src["url"])
        feed = feedparser.parse(r.content)
        entries = feed.entries
    except Exception as e:
        if src.get("fallback_html"):
            return fetch_html_links({**src, "url": src["fallback_html"], "selector": src.get("fallback_selector", "a")}, state)
        raise
    if not entries and src.get("fallback_html"):
        return fetch_html_links({**src, "url": src["fallback_html"], "selector": src.get("fallback_selector", "a")}, state)

    for e in entries[:60]:
        title = norm_ws(getattr(e, "title", "") or "")
        link = getattr(e, "link", "") or ""
        summary = html_to_text(getattr(e, "summary", "") or getattr(e, "description", "") or "")
        published = parse_date(getattr(e, "published", None) or getattr(e, "updated", None))
        if not title:
            continue
        if not matches_any(title + " " + summary, src.get("include")):
            continue
        if too_old(published, src.get("max_age_days")):
            continue
        items.append(Item(source_id=src["id"], source_name=src["name"], title=title, url=link,
                          text=summary[:1200], published=published, kind="news" if src.get("tier") == "news" else "alert",
                          tier=src.get("tier", "news"), note=src.get("note", "")))
    return items


# ------------------------------------------------------------------ HTML: list of links

def fetch_html_links(src: dict, state: State) -> list[Item]:
    r = http_get(src["url"])
    soup = BeautifulSoup(r.text, "lxml")
    items, seen = [], set()
    for a in soup.select(src.get("selector", "a")):
        title = norm_ws(a.get_text(" "))
        href = a.get("href") or ""
        if not title or len(title) < 8 or not href:
            continue
        url = urljoin(src["url"], href)
        if url in seen:
            continue
        seen.add(url)
        if not matches_any(title, src.get("include")):
            continue
        items.append(Item(source_id=src["id"], source_name=src["name"], title=title, url=url,
                          kind="alert", tier=src.get("tier", "official"), note=src.get("note", "")))
    return items[:40]


# ------------------------------------------------------------------ HTML: text snapshot (diff)

def fetch_html_text(src: dict, state: State) -> list[Item]:
    r = http_get(src["url"])
    soup = BeautifulSoup(r.text, "lxml")
    for t in soup(["script", "style", "noscript", "nav", "footer", "header"]):
        t.decompose()
    chunks = []
    for sel in src.get("selectors", ["main", "body"]):
        for el in soup.select(sel):
            txt = norm_ws(el.get_text(" "))
            if txt and txt not in chunks:
                chunks.append(txt)
    text = "\n".join(chunks)[:20000]
    if not text:
        text = norm_ws(soup.get_text(" "))[:20000]
    return _snapshot_change(src, state, text, meta={}, title_prefix="Page changed")


def _snapshot_change(src: dict, state: State, text: str, meta: dict, title_prefix: str, level_hint: int | None = None) -> list[Item]:
    """Compare text against the last snapshot; emit an Item describing the change."""
    h = stable_hash(text)
    prev = state.get_snapshot(src["id"])
    state.set_snapshot(src["id"], {"hash": h, "text": text[:20000], "meta": meta})
    if prev is None:
        return []  # first run: baseline only
    if prev.get("hash") == h:
        return []
    diff = text_diff(prev.get("text", ""), text)
    it = Item(source_id=src["id"], source_name=src["name"], title=f"{title_prefix}: {src['name']}",
              url=src.get("page") or src["url"], text=diff, kind="advisory_change",
              tier=src.get("tier", "official"), uid=stable_hash(src["id"], h))
    if level_hint is not None:
        it.level = level_hint
    return [it]


# ------------------------------------------------------------------ US State Department advisory page

LEVEL_RE = re.compile(r"Level\s*([1-4])\s*[:\-–]\s*([^|<\n]+)", re.I)


def fetch_state_dept_advisory(src: dict, state: State) -> list[Item]:
    try:
        r = http_get(src["url"])
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code in (403, 429, 503):
            # travel.state.gov's CDN blocks some data-centre IPs. The advisories RSS feed (source
            # us_state_rss) carries the full text of every updated advisory, so nothing is lost.
            raise SoftFail(f"page blocked ({e.response.status_code}); relying on the advisories RSS feed")
        raise
    soup = BeautifulSoup(r.text, "lxml")
    title = norm_ws((soup.find("h1") or soup.find("title")).get_text(" ")) if (soup.find("h1") or soup.find("title")) else ""
    m = LEVEL_RE.search(title) or LEVEL_RE.search(soup.get_text(" ")[:5000])
    level = int(m.group(1)) if m else None
    level_text = norm_ws(m.group(2)) if m else ""
    # advisory body: the emergency-alert text block or the main content
    body_el = (soup.select_one(".tsg-rwd-emergency-alert-text") or soup.select_one(".tsg-rwd-content-page-parsysxxx")
               or soup.select_one("#main") or soup.select_one("main") or soup.body)
    for t in body_el(["script", "style", "noscript", "nav"]):
        t.decompose()
    body = norm_ws(body_el.get_text(" "))
    # trim boilerplate after the advisory content if present
    for marker in ("Travel Advisory Levels", "Assistance for U.S. Citizens", "Last Update:"):
        i = body.find(marker)
        if i > 500:
            body = body[:i]
    date_m = re.search(r"(?:Reissued|Updated|Last Update)[^A-Za-z0-9]{0,5}([A-Z][a-z]+ \d{1,2}, \d{4})", r.text)
    meta = {"level": level, "level_text": level_text, "date": date_m.group(1) if date_m else None}

    prev = state.get_snapshot(src["id"])
    items = _snapshot_change(src, state, body, meta, title_prefix="Advisory text changed")
    if prev and level is not None and prev.get("meta", {}).get("level") not in (None, level):
        old = prev["meta"]["level"]
        hint = {1: 1, 2: 2, 3: 3, 4: 4}[level] if level > old else 1
        items = [Item(source_id=src["id"], source_name=src["name"],
                      title=f"US advisory level {'RAISED' if level > old else 'lowered'}: {old} → {level} ({level_text})",
                      url=src["url"], text=items[0].text if items else "", kind="advisory_change",
                      tier="official", level=hint, reason=f"level change {old}→{level}",
                      uid=stable_hash(src["id"], "level", str(level)))]
    elif items:
        items[0].title = f"US advisory text changed (still Level {level}: {level_text})"
    return items


# ------------------------------------------------------------------ UK FCDO content API

FCDO_ALERT_LEVEL = {
    "avoid_all_travel_to_whole_country": 4,
    "avoid_all_travel_to_parts": 3,
    "avoid_all_but_essential_travel_to_whole_country": 3,
    "avoid_all_but_essential_travel_to_parts": 2,
}


def fetch_fcdo(src: dict, state: State) -> list[Item]:
    data = http_get(src["url"]).json()
    details = data.get("details", {})
    alert_status = sorted(details.get("alert_status") or [])
    changes = details.get("change_history") or []
    changes = sorted(changes, key=lambda c: c.get("public_timestamp", ""), reverse=True)
    latest = changes[0] if changes else {}
    parts = {p.get("slug"): html_to_text(p.get("body", "")) for p in details.get("parts", [])}
    key_text = "\n".join(parts.get(s, "") for s in ("warnings-and-insurance", "safety-and-security"))
    summary_text = html_to_text(details.get("summary", "") if isinstance(details.get("summary"), str) else "")
    text = f"ALERT_STATUS: {alert_status}\nSUMMARY: {summary_text}\n{key_text}"
    meta = {"alert_status": alert_status, "latest_change": latest.get("note"), "latest_change_ts": latest.get("public_timestamp"),
            "public_updated_at": data.get("public_updated_at")}
    prev = state.get_snapshot(src["id"])
    items: list[Item] = []
    page = src.get("page") or data.get("base_path", "")
    if prev:
        pm = prev.get("meta", {})
        # 1) alert status changes (hard signal)
        if pm.get("alert_status") != alert_status:
            new_flags = [a for a in alert_status if a not in (pm.get("alert_status") or [])]
            lvl = max([FCDO_ALERT_LEVEL.get(a, 3) for a in new_flags] or [2])
            items.append(Item(source_id=src["id"], source_name=src["name"],
                              title=f"FCDO alert status changed: {', '.join(alert_status) or 'none'}",
                              url=page, text=f"was: {pm.get('alert_status')} → now: {alert_status}",
                              kind="advisory_change", tier="official", level=lvl, reason="FCDO alert_status changed",
                              uid=stable_hash(src["id"], "alert", json.dumps(alert_status))))
        # 2) new change-history note
        if latest and latest.get("public_timestamp") and latest.get("public_timestamp") != pm.get("latest_change_ts"):
            items.append(Item(source_id=src["id"], source_name=src["name"],
                              title=f"FCDO update: {latest.get('note', '').strip()}",
                              url=page, text=text_diff(prev.get("text", ""), text),
                              published=parse_date(latest.get("public_timestamp")), kind="advisory_change",
                              tier="official", uid=stable_hash(src["id"], "change", latest.get("public_timestamp"))))
    state.set_snapshot(src["id"], {"hash": stable_hash(text), "text": text[:20000], "meta": meta})
    return items


# ------------------------------------------------------------------ Telegram public channel preview

def fetch_telegram(src: dict, state: State) -> list[Item]:
    handle = src["handle"]
    r = http_get(f"https://t.me/s/{handle}")
    soup = BeautifulSoup(r.text, "lxml")
    items = []
    for msg in soup.select(".tgme_widget_message"):
        post = msg.get("data-post") or ""
        if not post:
            continue
        txt_el = msg.select_one(".tgme_widget_message_text")
        text = norm_ws(txt_el.get_text(" ")) if txt_el else ""
        if not text:
            continue
        t_el = msg.select_one(".tgme_widget_message_date time")
        published = parse_date(t_el.get("datetime")) if t_el else None
        if too_old(published, src.get("max_age_days", 2)):
            continue
        title = text[:140] + ("…" if len(text) > 140 else "")
        items.append(Item(source_id=src["id"], source_name=src["name"], title=title, url=f"https://t.me/{post}",
                          text=text[:1500], published=published, kind="post", tier="osint",
                          note=src.get("note", ""), lang="ru" if re.search(r"[а-яА-Я]", text) else "en"))
    return items


# ------------------------------------------------------------------ Polymarket

def fetch_polymarket(src: dict, state: State) -> list[Item]:
    seen_slugs, markets = set(), []
    for q in src.get("queries", []):
        try:
            data = http_get("https://gamma-api.polymarket.com/public-search", params={"q": q}).json()
        except Exception:
            continue
        for ev in data.get("events", []) or []:
            if ev.get("closed") or not ev.get("active", True):
                continue
            for m in ev.get("markets", []) or []:
                slug = m.get("slug") or ev.get("slug")
                if not slug or slug in seen_slugs or m.get("closed"):
                    continue
                q_title = m.get("question") or ev.get("title") or ""
                if not matches_any(q_title, src.get("include")):
                    continue
                if src.get("exclude") and matches_any(q_title, src.get("exclude")):
                    continue
                end = m.get("endDate") or ev.get("endDate") or ""
                if end and end < now_utc().isoformat():
                    continue
                try:
                    prices = json.loads(m.get("outcomePrices") or "[]")
                    yes = float(prices[0]) if prices else None
                except Exception:
                    yes = None
                if yes is None:
                    continue
                seen_slugs.add(slug)
                markets.append({"slug": slug, "question": q_title, "yes": round(yes * 100, 1), "end": end[:10],
                                "url": f"https://polymarket.com/event/{ev.get('slug', slug)}",
                                "volume": float(m.get("volumeNum") or m.get("volume") or 0)})
    markets.sort(key=lambda x: -x["volume"])
    markets = markets[:12]
    prev = state.get_snapshot(src["id"]) or {}
    prev_m = {m["slug"]: m for m in prev.get("markets", [])}
    items = []
    for m in markets:
        p = prev_m.get(m["slug"])
        if not p:
            continue
        delta = m["yes"] - p["yes"]
        if abs(delta) >= src.get("move_watch_pp", 5):
            lvl = 3 if abs(delta) >= src.get("move_elevated_pp", 15) and delta > 0 else 2
            items.append(Item(source_id=src["id"], source_name=src["name"],
                              title=f"Market moved {delta:+.0f} pp: “{m['question']}” now {m['yes']:.0f}%",
                              url=m["url"], text=f"was {p['yes']:.0f}% → now {m['yes']:.0f}% (resolves {m['end']})",
                              kind="market", tier="market", level=lvl, reason=f"probability moved {delta:+.1f} pp",
                              uid=stable_hash(src["id"], m["slug"], now_utc().strftime("%Y%m%d%H"))))
    state.set_snapshot(src["id"], {"markets": markets, "hash": stable_hash(json.dumps(markets, sort_keys=True))})
    return items


FETCHERS: dict[str, Callable[[dict, State], list[Item]]] = {
    "rss": fetch_rss,
    "html_links": fetch_html_links,
    "html_text": fetch_html_text,
    "state_dept_advisory": fetch_state_dept_advisory,
    "fcdo": fetch_fcdo,
    "telegram": fetch_telegram,
    "polymarket": fetch_polymarket,
}
