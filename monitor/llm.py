"""Optional Claude layer: grades relevance/severity of news & OSINT items and writes one-line English
summaries plus the digest "bottom line". Silently disabled when ANTHROPIC_API_KEY is not set."""
from __future__ import annotations

import json
import os
import re
from .core import Item

SYSTEM = """You are the triage analyst for a small early-warning service for people living in Latvia.
Goal: help them notice, early, signs that a military conflict involving Latvia / the Baltic states is becoming
more likely, and never miss hard triggers (embassy departures, airspace/border closures, mobilisation, NATO Article 4/5).
Be calm, factual, non-sensational. Rumours from unverified channels must not be graded above 3 unless corroborated
by an official source in the same batch.

Alert scale:
0 QUIET — irrelevant to Latvia/Baltic security, or noise.
1 INFO — routine update, minor wording edit, general regional news.
2 WATCH — notable: security-related wording changes, exercises/build-up, drones, sabotage, sharper rhetoric.
3 ELEVATED — advisory level raised, embassy staff reduction / authorized departure, security alert, several signals converge.
4 URGENT — 'leave now' / ordered departure, airspace or border closure, mobilisation, Article 4/5 invoked.
5 CRITICAL — attack/incursion under way or imminent, martial law / state of emergency.

Return ONLY a JSON array; one object per input item, same order, fields:
{"i": <index>, "level": <0-5>, "summary": "<one English sentence, max 160 chars, what happened + why it matters>", "why": "<max 12 words>"}"""


def enabled(cfg: dict) -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and cfg.get("llm", {}).get("enabled_if_key_present", True)


def _client():
    import anthropic  # imported lazily so the package is optional
    return anthropic.Anthropic()


def grade(items: list[Item], cfg: dict) -> list[Item]:
    """Refine level & summary for news/osint/market items. Official advisory levels are never lowered."""
    if not enabled(cfg) or not items:
        return items
    model = cfg.get("llm", {}).get("model", "claude-haiku-4-5")
    batch = cfg.get("llm", {}).get("max_items_per_call", 30)
    client = _client()
    for start in range(0, len(items), batch):
        chunk = items[start:start + batch]
        payload = [{"i": i, "source": it.source_name, "source_note": it.note, "tier": it.tier,
                    "rule_level": it.level, "title": it.title, "text": it.text[:900], "published": it.published}
                   for i, it in enumerate(chunk)]
        try:
            msg = client.messages.create(
                model=model, max_tokens=4000, system=SYSTEM,
                messages=[{"role": "user", "content": "Items:\n" + json.dumps(payload, ensure_ascii=False)}],
            )
            raw = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
            m = re.search(r"\[.*\]", raw, re.S)
            graded = json.loads(m.group(0)) if m else []
        except Exception as e:  # LLM problems must never break the run
            print(f"[llm] grading failed: {e}")
            continue
        for g in graded:
            try:
                it = chunk[int(g["i"])]
            except Exception:
                continue
            lvl = int(g.get("level", it.level))
            lvl = max(0, min(5, lvl))
            if it.tier == "official":
                it.level = max(it.level, lvl)           # never lower an official-source level
            else:
                it.level = lvl
            if g.get("summary"):
                it.summary = str(g["summary"])[:220]
            if g.get("why"):
                it.reason = str(g["why"])[:120]
    return items


def bottom_line(items: list[Item], overall: int, cfg: dict) -> str:
    """2–3 sentence digest summary. Empty string when LLM is disabled or fails."""
    if not enabled(cfg) or not items:
        return ""
    model = cfg.get("llm", {}).get("model", "claude-haiku-4-5")
    lines = [f"[L{it.level}] {it.source_name}: {it.summary or it.title}" for it in sorted(items, key=lambda x: -x.level)[:40]]
    prompt = (f"Current overall level: {overall}. Items since the last digest:\n" + "\n".join(lines) +
              "\n\nWrite the 'Bottom line' for the digest: 2–3 plain English sentences for non-experts living in Latvia. "
              "Say what changed, whether the picture is calmer/same/tenser than before, and what (if anything) to do. "
              "No headers, no emoji, no bullet points.")
    try:
        msg = _client().messages.create(model=model, max_tokens=300, system=SYSTEM.split("Return ONLY")[0],
                                        messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    except Exception as e:
        print(f"[llm] bottom line failed: {e}")
        return ""
