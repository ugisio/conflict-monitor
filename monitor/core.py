"""Core data model, config loading and JSON state persistence."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import yaml

ROOT = Path(os.environ.get("MONITOR_ROOT", Path(__file__).resolve().parent.parent))
STATE_DIR = ROOT / "state"
CONFIG_PATH = ROOT / "config.yaml"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # normalise scale keys to int
    cfg["scale"] = {int(k): v for k, v in cfg["scale"].items()}
    return cfg


def local_tz(cfg: dict) -> ZoneInfo:
    return ZoneInfo(cfg["region"].get("timezone", "UTC"))


def stable_hash(*parts: str) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update((p or "").encode("utf-8", "ignore"))
        h.update(b"\x1f")
    return h.hexdigest()[:16]


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


@dataclass
class Item:
    source_id: str
    source_name: str
    title: str
    url: str
    text: str = ""
    published: Optional[str] = None      # ISO 8601
    kind: str = "news"                   # advisory_change | alert | post | news | market | status
    uid: str = ""
    level: int = 0
    reason: str = ""
    summary: str = ""
    tier: str = "news"
    note: str = ""
    lang: str = "en"
    posted: bool = False
    first_seen: str = field(default_factory=lambda: now_utc().isoformat(timespec="seconds"))

    def __post_init__(self):
        if not self.uid:
            self.uid = stable_hash(self.source_id, self.url or self.title, self.title)
        self.title = norm_ws(self.title)
        self.text = (self.text or "").strip()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Item":
        known = {k: d.get(k) for k in cls.__dataclass_fields__ if k in d}
        return cls(**known)


class State:
    """All persistent state lives as JSON files under state/ (committed back by the workflow)."""

    def __init__(self, state_dir: Path = STATE_DIR):
        self.dir = state_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.seen: dict[str, dict[str, str]] = self._load("seen.json", {})
        self.snapshots: dict[str, dict[str, Any]] = self._load("snapshots.json", {})
        self.pending: list[dict] = self._load("pending.json", [])
        self.status: dict[str, Any] = self._load("status.json", {
            "overall_level": 0, "overall_since": None, "pinned_message_id": None,
            "last_digest": None, "recent_levels": [], "health": {}, "runs": 0,
        })
        self.subscribers: dict[str, Any] = self._load("subscribers.json", {"chat_ids": [], "last_update_id": 0})
        # normalised headlines already reported (any source) → first-seen time; stops the same story
        # arriving again from another outlet or a re-indexed Google News entry a few hours later
        self.titles: dict[str, str] = self._load("titles.json", {})

    # -- io --
    def _load(self, name: str, default):
        p = self.dir / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return default
        return default

    def _save(self, name: str, data):
        p = self.dir / name
        p.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    def save(self):
        self.prune()
        self._save("seen.json", self.seen)
        self._save("snapshots.json", self.snapshots)
        self._save("pending.json", self.pending)
        self._save("status.json", self.status)
        self._save("subscribers.json", self.subscribers)
        self._save("titles.json", self.titles)

    # -- headline memory (cross-run, cross-source duplicate detection) --
    def title_seen(self, key: str) -> bool:
        return bool(key) and key in self.titles

    def mark_title(self, key: str):
        if key:
            self.titles[key] = now_utc().isoformat(timespec="seconds")

    # -- seen --
    def is_seen(self, source_id: str, uid: str) -> bool:
        return uid in self.seen.get(source_id, {})

    def mark_seen(self, source_id: str, uid: str):
        self.seen.setdefault(source_id, {})[uid] = now_utc().isoformat(timespec="seconds")

    def prune(self, days: int = 45):
        cutoff = (now_utc() - timedelta(days=days)).isoformat()
        for sid in list(self.seen):
            self.seen[sid] = {u: t for u, t in self.seen[sid].items() if t >= cutoff}
        cutoff_rl = (now_utc() - timedelta(days=14)).isoformat()
        self.status["recent_levels"] = [r for r in self.status.get("recent_levels", []) if r.get("ts", "") >= cutoff_rl][-300:]
        cutoff_t = (now_utc() - timedelta(days=10)).isoformat()
        self.titles = {k: t for k, t in self.titles.items() if t >= cutoff_t}

    # -- snapshots (last known content per source) --
    def get_snapshot(self, source_id: str) -> Optional[dict]:
        return self.snapshots.get(source_id)

    def set_snapshot(self, source_id: str, data: dict):
        data = dict(data)
        data["updated"] = now_utc().isoformat(timespec="seconds")
        self.snapshots[source_id] = data

    # -- pending digest items --
    def add_pending(self, item: Item):
        self.pending.append(item.to_dict())

    def take_pending(self) -> list[Item]:
        items = [Item.from_dict(d) for d in self.pending]
        self.pending = []
        return items

    # -- health --
    def set_health(self, source_id: str, ok: bool, error: str = "", n_items: int = 0):
        h = self.status.setdefault("health", {}).setdefault(source_id, {})
        h["ok"] = ok
        h["error"] = (error or "")[:200]
        h["last_run"] = now_utc().isoformat(timespec="seconds")
        if ok:
            h["last_ok"] = h["last_run"]
            h["items_last"] = n_items
        h["fail_streak"] = 0 if ok else h.get("fail_streak", 0) + 1

    # -- overall level --
    def record_level(self, item: Item):
        self.status.setdefault("recent_levels", []).append({
            "ts": now_utc().isoformat(timespec="seconds"), "level": item.level,
            "title": item.title[:120], "source": item.source_name,
        })

    def overall_level(self, window_hours: int) -> tuple[int, Optional[dict]]:
        cutoff = (now_utc() - timedelta(hours=window_hours)).isoformat()
        best, best_row = 0, None
        for r in self.status.get("recent_levels", []):
            if r.get("ts", "") >= cutoff and r.get("level", 0) > best:
                best, best_row = r["level"], r
        return best, best_row
