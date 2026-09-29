"""Digest message builder."""
from __future__ import annotations

from collections import defaultdict
from .core import Item, State
from .telegram import esc, fmt_time, badge, legend


def build_digest(items: list[Item], state: State, cfg: dict, tz, overall: int, since_row: dict | None,
                 bottom: str = "", label: str = "Digest") -> str:
    scale = cfg["scale"]
    when = fmt_time(None, tz)
    health = state.status.get("health", {})
    ok = sum(1 for h in health.values() if h.get("ok"))
    total = len(health)
    lines = [f"🛰 <b>CONFLICT MONITOR — {esc(label)}</b> · {when}",
             f"Overall: {badge(overall, scale)} <i>(highest in last {cfg['alerts']['overall_window_hours']}h)</i>"]
    if bottom:
        lines += ["", f"<b>Bottom line:</b> {esc(bottom)}"]

    if not items:
        lines += ["", f"{scale[0]['emoji']} Nothing new since the last digest. All monitored sources unchanged."]
    else:
        by_level: dict[int, list[Item]] = defaultdict(list)
        for it in items:
            by_level[it.level].append(it)
        for lvl in sorted(by_level, reverse=True):
            if lvl == 0:
                continue
            lines += ["", f"{scale[lvl]['emoji']} <b>L{lvl} {scale[lvl]['name']}</b>"]
            for it in sorted(by_level[lvl], key=lambda x: (x.tier != "official", x.published or ""), reverse=False)[:15]:
                flag = " 🔔" if it.posted else ""
                if getattr(it, "warning", False):
                    flag = " 🗣" + flag
                link = f' — <a href="{esc(it.url)}">{esc(it.source_name)}</a>' if it.url else f" — {esc(it.source_name)}"
                body = esc(it.summary or it.title)
                lines.append(f"• {body}{link}{flag}")
            if len(by_level[lvl]) > 15:
                lines.append(f"  … and {len(by_level[lvl]) - 15} more")

    # markets snapshot
    pm = state.get_snapshot("polymarket") or {}
    mk = pm.get("markets") or []
    if mk:
        lines += ["", "📈 <b>Prediction markets</b>"]
        for m in mk[:5]:
            lines.append(f"• {m['yes']:.0f}% — <a href=\"{esc(m['url'])}\">{esc(m['question'][:90])}</a>")

    # quiet sources & health
    quiet = [s["name"] for s in cfg["sources"] if s.get("tier") == "official" and not any(it.source_id == s["id"] for it in items)]
    if quiet:
        lines += ["", f"{scale[0]['emoji']} <i>Unchanged: {esc(', '.join(quiet[:12]))}</i>"]
    failing = [sid for sid, h in health.items() if not h.get("ok") and h.get("fail_streak", 0) >= 3]
    if failing:
        names = {s["id"]: s["name"] for s in cfg["sources"]}
        lines.append(f"⚠️ <i>Sources failing: {esc(', '.join(names.get(f, f) for f in failing))}</i>")
    lines += ["", f"<i>Sources OK {ok}/{total} · 🔔 = already posted · 🗣 = official warning</i>", legend(scale)]
    return "\n".join(lines)
