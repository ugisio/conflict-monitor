"""CLI entry point.

  python -m monitor poll     # fetch all sources, post level>=3 immediately, queue the rest for the digest
  python -m monitor digest   # post the digest of everything queued since the last digest
  python -m monitor auto     # digest if the local hour is a digest hour, otherwise poll (used by the scheduler)
  python -m monitor check    # fetch + classify, print what would be posted, send nothing, save nothing
  python -m monitor test     # send a test message + current status to the channel
"""
from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime, timedelta

from .core import Item, State, load_config, local_tz, now_utc
from .classify import classify, dedupe, title_key, corroborate, cluster
from .digest import build_digest
from .fetchers import FETCHERS, SoftFail
from .telegram import Telegram, format_alert, format_status, guide_text, guide_link
from . import llm


def collect(cfg: dict, state: State, dry: bool = False) -> list[Item]:
    """Fetch every source, keep only new items, classify them.
    The first time a list-type source is seen, its existing items are baselined (marked seen, not reported)
    so that switching the monitor on does not flood the channel with old news."""
    new_items: list[Item] = []
    llm_on = llm.enabled(cfg)
    current_ids = {s["id"] for s in cfg["sources"]}
    state.status["health"] = {k: v for k, v in state.status.get("health", {}).items() if k in current_ids}
    for src in cfg["sources"]:
        fn = FETCHERS.get(src["type"])
        if not fn:
            print(f"[skip] unknown source type {src['type']} ({src['id']})")
            continue
        try:
            fetched = fn(src, state)
            first_sight = src["id"] not in state.seen and src["type"] in ("rss", "html_links", "telegram")
            fresh = []
            for it in fetched:
                if state.is_seen(src["id"], it.uid):
                    continue
                if not dry:
                    state.mark_seen(src["id"], it.uid)
                if first_sight:
                    continue
                it.tier = src.get("tier", it.tier)
                it.note = it.note or src.get("note", "")
                c = classify(it, src, cfg, llm_enabled=llm_on)
                if c is None:
                    continue
                if c.kind in ("news", "post", "alert") and state.title_seen(title_key(c.title)):
                    continue                      # same story already reported (another outlet / re-indexed)
                fresh.append(c)
            if not dry:
                state.seen.setdefault(src["id"], {})  # remember that this source has been baselined
            state.set_health(src["id"], True, n_items=len(fetched))
            tag = " (baselined)" if first_sight else ""
            print(f"[ok]   {src['id']:<22} fetched={len(fetched):<3} new_relevant={len(fresh)}{tag}")
            new_items += fresh
        except SoftFail as e:
            state.set_health(src["id"], True, error=str(e))
            print(f"[note] {src['id']:<22} {e}")
        except Exception as e:
            state.set_health(src["id"], False, error=f"{type(e).__name__}: {e}")
            print(f"[FAIL] {src['id']:<22} {type(e).__name__}: {str(e)[:160]}")
    new_items = dedupe(new_items)
    if new_items:
        new_items = llm.grade(new_items, cfg)
    for it in new_items:
        it.raw_level = it.level                      # remember the pre-corroboration grade
    new_items = corroborate(new_items, state.status.get("recent_levels", []))
    new_items = cluster(new_items, state.stories)     # further reports of a known story are folded, not re-alerted
    kept = [it for it in new_items if it.level >= 1]
    if not dry:
        for it in kept:
            state.mark_title(title_key(it.title))
    return kept


def record(state: State, it: Item):
    state.record_level(it, raw_level=getattr(it, "raw_level", it.level), title_key=title_key(it.title))


def ensure_guide(tg: Telegram, state: State, cfg: dict):
    """Post the level-guide message once and remember its id so status/alerts can link to it."""
    if state.status.get("guide_message_id") or tg.dry:
        return
    mid = tg.send(guide_text(cfg), silent=True)
    if mid:
        state.status["guide_message_id"] = mid


def alert_text(item: Item, cfg: dict, tz, state: State) -> str:
    text = format_alert(item, cfg, tz)
    link = guide_link(state, cfg)
    return f"{text}\n{link}" if link else text


def update_status_message(tg: Telegram, state: State, cfg: dict, tz, force: bool = False):
    """Keep one pinned 'CURRENT LEVEL' message in the channel. Edited in place while the level is unchanged;
    re-posted (with sound when the level rises) whenever the level changes."""
    ensure_guide(tg, state, cfg)
    overall, row = state.overall_level(cfg["alerts"]["overall_window_hours"])
    prev = state.status.get("overall_level", 0)
    health = state.status.get("health", {})
    text = format_status(overall, row, cfg, tz, sum(1 for h in health.values() if h.get("ok")), len(health),
                         guide=guide_link(state, cfg))
    state.status["status_text"] = text
    mid = state.status.get("pinned_message_id")
    changed = overall != prev
    if mid and not force and not changed and tg.edit(tg.channel, mid, text):
        pass                                   # refreshed in place
    else:
        new_mid = tg.send(text, silent=not (overall > prev), pin=True)
        if new_mid and not tg.dry:             # never remember dry-run ids
            state.status["pinned_message_id"] = new_mid
        if changed or not state.status.get("overall_since"):
            state.status["overall_since"] = now_utc().isoformat(timespec="seconds")
    state.status["overall_level"] = overall


def latest_digest_slot(cfg: dict) -> datetime | None:
    """The most recent digest slot (08:00 / 20:00 local, today or yesterday) that has already passed."""
    tz = local_tz(cfg)
    now = datetime.now(tz)
    slots = [now.replace(hour=h, minute=0, second=0, microsecond=0) - timedelta(days=d)
             for d in (0, 1) for h in cfg["alerts"]["digest_hours_local"]]
    passed = [t for t in slots if t <= now]
    return max(passed) if passed else None


def digest_due(cfg: dict, state: State) -> bool:
    """A digest is due once the latest slot has passed and no digest has been sent since that slot.
    Runs are not guaranteed to land inside the slot hour (GitHub's scheduler skips and delays runs),
    so whichever run comes first after the slot sends it."""
    slot = latest_digest_slot(cfg)
    if slot is None:
        return False
    last = state.status.get("last_digest")
    if not last:
        return True
    try:
        return datetime.fromisoformat(last).astimezone(slot.tzinfo) < slot
    except Exception:
        return True


def digest_label(cfg: dict) -> str:
    slot = latest_digest_slot(cfg)
    tz = local_tz(cfg)
    if slot is None:
        return "Digest"
    label = "Morning digest" if slot.hour < 14 else "Evening digest"
    if datetime.now(tz) - slot > timedelta(hours=1):
        label += f" (for {slot.strftime('%H:%M')}, delayed)"
    return label


def run_poll(cfg: dict, state: State, tg: Telegram):
    tz = local_tz(cfg)
    ensure_guide(tg, state, cfg)
    items = collect(cfg, state)
    imm = cfg["alerts"]["immediate_min_level"]
    dm_min = cfg["alerts"]["dm_min_level"]
    warn_now = cfg["alerts"].get("immediate_warnings", True)
    for it in sorted(items, key=lambda x: -x.level):
        if it.repeat_of:
            state.add_pending(it)            # counted in the digest, never re-alerted
            continue
        record(state, it)
        if it.level >= imm:
            text = alert_text(it, cfg, tz, state)
            tg.send(text, silent=False, pin=(it.level >= dm_min))
            if it.level >= dm_min:
                tg.dm_all(state, text)
            it.posted = True
        elif warn_now and it.warning:
            tg.send(alert_text(it, cfg, tz, state), silent=True)   # on arrival, but no alarm sound
            it.posted = True
        state.add_pending(it)
    update_status_message(tg, state, cfg, tz)
    tg.sync_subscribers(state, os.environ.get("CHANNEL_INVITE_LINK"))
    state.status["runs"] = state.status.get("runs", 0) + 1
    state.save()
    print(f"poll done: {len(items)} new item(s), {sum(1 for i in items if i.posted)} posted immediately")


def run_digest(cfg: dict, state: State, tg: Telegram, label: str | None = None):
    tz = local_tz(cfg)
    ensure_guide(tg, state, cfg)
    imm, dm_min = cfg["alerts"]["immediate_min_level"], cfg["alerts"]["dm_min_level"]
    warn_now = cfg["alerts"].get("immediate_warnings", True)
    fresh = collect(cfg, state)          # pick up anything since the last poll too
    for it in sorted(fresh, key=lambda x: -x.level):
        if it.repeat_of:
            state.add_pending(it)
            continue
        record(state, it)
        if it.level >= imm:              # urgent things never wait for the digest
            text = alert_text(it, cfg, tz, state)
            tg.send(text, pin=(it.level >= dm_min))
            if it.level >= dm_min:
                tg.dm_all(state, text)
            it.posted = True
        elif warn_now and it.warning:
            tg.send(alert_text(it, cfg, tz, state), silent=True)
            it.posted = True
        state.add_pending(it)
    items = state.take_pending()
    items = sorted(dedupe(items), key=lambda x: -x.level)
    overall, row = state.overall_level(cfg["alerts"]["overall_window_hours"])
    if not items and not cfg["alerts"].get("digest_when_empty", True):
        state.status["last_digest"] = now_utc().isoformat(timespec="seconds")
        state.save()
        return
    label = label or digest_label(cfg)
    bottom = llm.bottom_line(items, overall, cfg) if items else ""
    tg.send(build_digest(items, state, cfg, tz, overall, row, bottom, label), silent=False)
    update_status_message(tg, state, cfg, tz)
    tg.sync_subscribers(state, os.environ.get("CHANNEL_INVITE_LINK"))
    state.status["last_digest"] = now_utc().isoformat(timespec="seconds")
    state.status["runs"] = state.status.get("runs", 0) + 1
    state.save()
    print(f"digest sent: {len(items)} item(s), overall L{overall}")


def run_check(cfg: dict, state: State):
    tz = local_tz(cfg)
    items = collect(cfg, state, dry=True)
    print("\n---- would report ----")
    for it in sorted(items, key=lambda x: -x.level):
        print(f"L{it.level} [{it.source_name}] {it.title}  <{it.url}>  ({it.reason})")
    print(f"\n{len(items)} item(s). Nothing was sent or saved.")


def run_test(cfg: dict, state: State, tg: Telegram):
    tz = local_tz(cfg)
    tg.send(f"🛰 <b>CONFLICT MONITOR — test message</b> · {datetime.now(tz).strftime('%a %d %b %H:%M')}\n"
            f"Bot is connected and can post here. Monitoring {len(cfg['sources'])} sources. Digests at "
            f"{' and '.join(f'{h:02d}:00' for h in cfg['alerts']['digest_hours_local'])} ({cfg['region']['timezone']}).")
    ensure_guide(tg, state, cfg)
    update_status_message(tg, state, cfg, tz, force=True)
    tg.sync_subscribers(state, os.environ.get("CHANNEL_INVITE_LINK"))
    state.save()
    print("test message sent")


def main(argv: list[str]):
    mode = argv[0] if argv else "auto"
    cfg = load_config()
    state = State()
    tcfg = cfg.get("telegram", {}) or {}
    tg = Telegram(channel=os.environ.get("TELEGRAM_CHANNEL_ID") or tcfg.get("channel_id"))
    if not os.environ.get("CHANNEL_INVITE_LINK") and tcfg.get("invite_link"):
        os.environ["CHANNEL_INVITE_LINK"] = tcfg["invite_link"]
    if mode == "auto":
        mode = "digest" if digest_due(cfg, state) else "poll"
        print(f"auto → {mode} (local time {datetime.now(local_tz(cfg)).strftime('%H:%M')})")
    try:
        if mode == "poll":
            run_poll(cfg, state, tg)
        elif mode == "digest":
            run_digest(cfg, state, tg)
        elif mode == "check":
            run_check(cfg, state)
        elif mode == "test":
            run_test(cfg, state, tg)
        else:
            print(__doc__)
            sys.exit(2)
    except Exception:
        traceback.print_exc()
        state.save()       # keep whatever progress we made (seen/snapshots) so we don't re-alert
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
