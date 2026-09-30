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
        heads = [it for it in items if not getattr(it, "repeat_of", "")]
        head_titles = {it.title for it in heads}
        # further reports of a story: folded into its head line, or one summary line if the head was in an earlier digest
        folded: dict[str, int] = defaultdict(int)
        orphans: dict[str, int] = defaultdict(int)
        for it in items:
            rep = getattr(it, "repeat_of", "")
            if rep:
                (folded if rep in head_titles else orphans)[rep] += 1
        for lvl in sorted(by_level, reverse=True):
            if lvl == 0:
                continue
            group = [it for it in by_level[lvl] if not getattr(it, "repeat_of", "")]
            orphan_here = {t: n for t, n in orphans.items() if any(it.level == lvl and it.repeat_of == t for it in by_level[lvl])}
            if not group and not orphan_here:
                continue
            lines += ["", f"{scale[lvl]['emoji']} <b>L{lvl} {scale[lvl]['name']}</b>"]
            for it in sorted(group, key=lambda x: (x.tier != "official", x.published or ""), reverse=False)[:15]:
                flag = " 🔔" if it.posted else ""
                if getattr(it, "warning", False):
                    flag = " 🗣" + flag
                more = f" <i>(+{folded[it.title]} more report{'s' if folded[it.title] != 1 else ''})</i>" if folded.get(it.title) else ""
                link = f' — <a href="{esc(it.url)}">{esc(it.source_name)}</a>' if it.url else f" — {esc(it.source_name)}"
                body = esc(it.summary or it.title)
                lines.append(f"• {body}{link}{more}{flag}")
            if len(group) > 15:
                lines.append(f"  … and {len(group) - 15} more")
            for t, n in orphan_here.items():
                lines.append(f"↳ <i>{n} more report{'s' if n != 1 else ''} on “{esc(t[:90])}” (already in the channel)</i>")

    # markets snapshot
    pm = state.get_snapshot("polymarket") or {}
    mk = pm.get("markets") or []
    if mk:
        lines += ["", "📈 <b>Prediction markets</b>"]
        for m in mk[:5]:
            lines.append(f"• {m['yes']:.0f}% — <a href=\"{esc(m['url'])}\">{esc(m['question'][:90])}</a>")

    # quiet sources & health
    official = [s for s in cfg["sources"] if s.get("tier") == "official"]
    quiet = [s["name"] for s in official if not any(it.source_id == s["id"] for it in items)]
    if quiet and len(quiet) == len(official):
        lines += ["", f"{scale[0]['emoji']} <i>All {len(official)} official advisories unchanged.</i>"]
    elif quiet:
        lines += ["", f"{scale[0]['emoji']} <i>{len(quiet)} of {len(official)} official advisories unchanged.</i>"]
    failing = [sid for sid, h in health.items() if not h.get("ok") and h.get("fail_streak", 0) >= 3]
    if failing:
        names = {s["id"]: s["name"] for s in cfg["sources"]}
        lines.append(f"⚠️ <i>Sources failing: {esc(', '.join(names.get(f, f) for f in failing))}</i>")
    lines += ["", f"<i>Sources OK {ok}/{total} · 🔔 = already posted · 🗣 = official warning</i>", legend(scale)]
    return "\n".join(lines)
