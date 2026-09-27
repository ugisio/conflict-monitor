"""Thin Telegram Bot API client (HTML parse mode) + message formatting."""
from __future__ import annotations

import html
import os
import time
from datetime import datetime, timezone

import requests

from .core import Item, State

API = "https://api.telegram.org/bot{token}/{method}"
MAX_LEN = 4000


class Telegram:
    def __init__(self, token: str | None = None, channel: str | None = None):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.channel = channel or os.environ.get("TELEGRAM_CHANNEL_ID", "")
        self.dry = not self.token or os.environ.get("MONITOR_DRY_RUN") == "1"

    # -- low level --
    _dry_counter = 1000

    def call(self, method: str, **params):
        if self.dry:
            Telegram._dry_counter += 1
            print(f"[dry-run] {method} {str(params)[:300]}")
            return {"ok": True, "result": {"message_id": Telegram._dry_counter}}
        for attempt in range(3):
            r = requests.post(API.format(token=self.token, method=method), json=params, timeout=30)
            if r.status_code == 429:
                time.sleep(int(r.json().get("parameters", {}).get("retry_after", 3)) + 1)
                continue
            data = r.json()
            if not data.get("ok"):
                raise RuntimeError(f"Telegram {method} failed: {data.get('description')}")
            return data
        raise RuntimeError(f"Telegram {method}: rate limited")

    def send(self, text: str, chat_id: str | int | None = None, silent: bool = False, pin: bool = False) -> int | None:
        chat_id = chat_id or self.channel
        last_id = None
        for chunk in split_message(text):
            res = self.call("sendMessage", chat_id=chat_id, text=chunk, parse_mode="HTML",
                            disable_web_page_preview=True, disable_notification=silent)
            last_id = res["result"].get("message_id")
            time.sleep(0.3)
        if pin and last_id:
            try:
                self.call("pinChatMessage", chat_id=chat_id, message_id=last_id, disable_notification=True)
            except Exception as e:
                print(f"[telegram] pin failed: {e}")
        return last_id

    def edit(self, chat_id: str | int, message_id: int, text: str) -> bool:
        try:
            self.call("editMessageText", chat_id=chat_id, message_id=message_id, text=text,
                      parse_mode="HTML", disable_web_page_preview=True)
            return True
        except Exception as e:
            print(f"[telegram] edit failed: {e}")
            return False

    def dm_all(self, state: State, text: str):
        for cid in state.subscribers.get("chat_ids", []):
            try:
                self.send(text, chat_id=cid)
            except Exception as e:
                print(f"[telegram] DM to {cid} failed: {e}")

    def sync_subscribers(self, state: State, invite_link: str | None = None):
        """Register anyone who sent /start to the bot in a private chat; reply with a welcome."""
        if self.dry:
            return
        offset = int(state.subscribers.get("last_update_id", 0)) + 1
        try:
            data = self.call("getUpdates", offset=offset, timeout=0, allowed_updates=["message"])
        except Exception as e:
            print(f"[telegram] getUpdates failed: {e}")
            return
        for upd in data.get("result", []):
            state.subscribers["last_update_id"] = max(int(state.subscribers.get("last_update_id", 0)), upd["update_id"])
            msg = upd.get("message") or {}
            chat = msg.get("chat") or {}
            text = (msg.get("text") or "").strip().lower()
            if chat.get("type") != "private":
                continue
            cid = chat["id"]
            if text.startswith("/start") and cid not in state.subscribers["chat_ids"]:
                state.subscribers["chat_ids"].append(cid)
                link = f"\nChannel: {invite_link}" if invite_link else ""
                self.send("✅ You're subscribed to <b>Conflict Monitor</b> direct alerts (level 4+)."
                          f"{link}\nSend /stop to unsubscribe.", chat_id=cid)
            elif text.startswith("/stop") and cid in state.subscribers["chat_ids"]:
                state.subscribers["chat_ids"].remove(cid)
                self.send("Unsubscribed from direct alerts. The channel still works.", chat_id=cid)
            elif text.startswith("/status"):
                self.send(state.status.get("status_text") or "No status yet.", chat_id=cid)


# ------------------------------------------------------------------ formatting

def esc(s: str) -> str:
    return html.escape(s or "", quote=False)


def split_message(text: str) -> list[str]:
    if len(text) <= MAX_LEN:
        return [text]
    parts, cur = [], ""
    for line in text.split("\n"):
        if len(cur) + len(line) + 1 > MAX_LEN:
            parts.append(cur)
            cur = ""
        cur += line + "\n"
    if cur.strip():
        parts.append(cur)
    return parts


def fmt_time(iso: str | None, tz) -> str:
    try:
        d = datetime.fromisoformat(iso) if iso else datetime.now(timezone.utc)
    except Exception:
        d = datetime.now(timezone.utc)
    return d.astimezone(tz).strftime("%a %d %b %H:%M")


def badge(level: int, scale: dict) -> str:
    s = scale[max(0, min(5, level))]
    return f"{s['emoji']} <b>L{level} {s['name']}</b>"


def format_alert(item: Item, cfg: dict, tz) -> str:
    scale = cfg["scale"]
    when = fmt_time(item.published or item.first_seen, tz)
    lines = [f"{badge(item.level, scale)} · {esc(item.source_name)} · {when}", f"<b>{esc(item.title)}</b>"]
    if item.summary:
        lines.append(esc(item.summary))
    elif item.text and item.kind in ("advisory_change", "alert", "market"):
        lines.append(f"<pre>{esc(item.text[:700])}</pre>" if item.kind == "advisory_change" else esc(item.text[:400]))
    if item.note:
        lines.append(f"<i>Source note: {esc(item.note)}</i>")
    if item.reason:
        lines.append(f"<i>Why: {esc(item.reason)}</i>")
    if item.url:
        lines.append(f'<a href="{esc(item.url)}">Source</a>')
    if item.level >= 3:
        lines.append(f"\n<i>{esc(scale[item.level]['meaning'])}</i>")
    return "\n".join(lines)


def format_status(overall: int, since_row: dict | None, cfg: dict, tz, health_ok: int, health_total: int) -> str:
    scale = cfg["scale"]
    s = scale[overall]
    lines = [f"📟 <b>CURRENT LEVEL: {s['emoji']} L{overall} {s['name']}</b>", esc(s["meaning"])]
    if since_row:
        lines.append(f"Driven by: {esc(since_row.get('title', ''))} ({esc(since_row.get('source', ''))}, {fmt_time(since_row.get('ts'), tz)})")
    lines.append(f"Updated {fmt_time(None, tz)} · sources OK {health_ok}/{health_total}")
    lines.append(legend(scale))
    return "\n".join(lines)


def legend(scale: dict) -> str:
    return "Scale: " + " ".join(f"{scale[i]['emoji']}{i} {scale[i]['name'].title()}" for i in range(5, -1, -1))
