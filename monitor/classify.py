"""Rule-based relevance + severity scoring. Deterministic, works without any API key.
The optional LLM layer (llm.py) can refine levels/summaries for news, OSINT posts and markets."""
from __future__ import annotations

import re
from .core import Item

# (regex, level) — highest match wins. Bilingual EN/RU (+ a little DE/LV).
RULES: list[tuple[str, int]] = [
    # ---- 5 CRITICAL
    (r"\b(attack|invasion|incursion|strike)s? (on|against|into) (latvia|estonia|lithuania|the baltics?|nato territory)", 5),
    (r"(вторжени|нападени|удар(ы|ов)?) (в|на|по) (латви|эстони|литв|прибалт|балти)", 5),
    (r"\bmartial law\b|военное положение|karastāvokl", 5),
    (r"article 5 (has been|was|is) (invoked|triggered)|статья 5 (активирован|задействован)", 5),
    # ---- 4 URGENT
    (r"ordered departure|depart(ure)? (of|for) (all|non-emergency)|leave (the country )?(now|immediately)|depart immediately|evacuat(e|ion|ing)", 4),
    (r"\bdo not travel\b", 4),
    (r"airspace (is |has been |will be )?(closed|closure|shut)|clos(e|es|ed|ing|ure of) (its |the |all |national )?airspace|воздушн\w+ пространств\w+ (закрыт|закрыва)", 4),
    (r"border(s)? (is |are |has been |have been )?(closed|sealed)|clos(e|es|ed|ing) (its |the |all )?border|границ\w* (закрыт|закрыва|перекры)", 4),
    (r"(general |partial )?mobili[sz]ation|мобилизац", 4),
    (r"\barticle 5\b|статья 5|статьи 5", 4),
    (r"state of emergency|чрезвычайн\w+ (положени|ситуаци)|ārkārtējā situācija", 4),
    (r"shelter in place|air[- ]raid (siren|alert|warning)|воздушн\w+ тревог", 4),
    (r"nuclear (weapon|strike|threat|alert)|ядерн\w+ (удар|оруж|угроз)", 4),
    # ---- 3 ELEVATED
    (r"authori[sz]ed departure|non-?emergency (u\.?s\.? )?(government )?(employees|personnel|staff)|reduc(e|ed|ing|tion of) (embassy |diplomatic )?staff|drawdown", 3),
    (r"reconsider travel|advise against all but essential travel|advise against all travel", 3),
    (r"\barticle 4\b|статья 4|статьи 4", 3),
    (r"security alert", 3),
    (r"(troop|force|military) (build[- ]?up|movement|concentration|deployment)|наращива\w+ (войск|сил|группировк)|переброск\w+ (войск|техник)", 3),
    (r"violat(e|ed|ion of) (latvian|estonian|lithuanian|nato|polish|finnish)? ?airspace|наруш\w+ воздушн\w+ пространств", 3),
    (r"\bincursion\b|\binvasion\b|вторжени", 3),
    (r"sabotage|диверси|hybrid attack|гибридн\w+ (атак|войн)", 3),
    (r"(explosion|blast|attack|strike|missile|shelling) .{0,80}(latvia|estonia|lithuania|baltic|kaliningrad|pskov|belarus)", 3),
    (r"(взрыв|атак|удар|ракет).{0,80}(латви|эстони|литв|прибалт|балти|калининград|псков|беларус)", 3),
    (r"embassy (closes|closed|closing|suspend)|посольств\w+ (закрыва|приостанав)", 3),
    (r"nato (deploys|reinforces|sends).{0,60}(baltic|latvia|estonia|lithuania)", 3),
    # ---- 2 WATCH
    (r"\bdrone|\buav\b|беспилотник|\bдрон|\bбпла\b", 2),
    (r"cyber ?attack|кибератак|gps (jamming|spoofing)|глушени", 2),
    (r"military exercise|exercises?\b.{0,40}(russia|belarus|zapad|nato)|учени[яй]|zapad|запад-20", 2),
    (r"\bexplosion\b|\bblast\b|взрыв", 2),
    (r"\bdetain|\barrest|espionage|spy|шпион|задержан", 2),
    (r"threat(en|ens|ened)?\b|угро[зж]", 2),
    (r"escalat|эскалац|provocat|провокац", 2),
    (r"(security|safety) (situation|update|advice) (has )?(changed|updated)|warnings and insurance", 2),
    (r"navy|warship|submarine|fleet|военн\w+ корабл|флот", 2),
    (r"suwa[lł]ki|сувалк", 2),
    # ---- 1 INFO
    (r"demonstration alert|weather alert|health alert|editorial change|entry requirements|entry-exit system|\bees\b|visa|passport", 1),
    (r"\bexercise\b|\btraining\b|\bdrill|\breservist|\bconscript|\bnbs\b|zemessardze|national guard|home guard", 1),
    (r"(defen[cs]e|military|army|border guard|security) (minister|ministry|budget|spending|chief|commander)", 1),
]
_COMPILED = [(re.compile(p, re.I), lvl) for p, lvl in RULES]

# Security-adjacent words: a region-relevant news item that scores 0 but contains one of these is worth
# a look by the LLM layer (when enabled) — otherwise it is dropped as ordinary news.
SOFT = re.compile(r"militar|defen[cs]e|\barmy\b|\btroops?\b|soldier|\bborder|security|\bnato\b|\bwar\b|weapon|missile|"
                  r"russia|kremlin|belarus|армия|военн|границ|безопасност|войск|оборон|росси|беларус|нато", re.I)

# Planning / hypothetical framing: "preparing an evacuation plan", "exercise simulates border closure",
# "could close airspace". A real signal, but one notch below the same words describing an actual event.
HYPOTHETICAL = re.compile(
    r"\b(plans?|planning|planned|prepar\w*|drill|drills|exercise|exercises|scenario|simulat\w*|contingency|"
    r"in case of|would|could|might|may|hypothetical|table-?top|rehears\w*|"
    r"план\w*|готов\w*|учени\w*|сценари\w*|отработ\w*|на случай)\b", re.I)


# Baltic-specific words in a title strongly imply relevance for OSINT/news.
def relevance(text: str, cfg: dict) -> tuple[bool, list[str]]:
    t = (text or "").lower()
    core = [k for k in cfg["region"]["core_keywords"] if k.lower() in t]
    ctx = [k for k in cfg["region"]["context_keywords"] if k.lower() in t]
    return (bool(core), core + ctx)


def score(text: str) -> tuple[int, str]:
    best, why = 0, ""
    for rx, lvl in _COMPILED:
        m = rx.search(text or "")
        if m and lvl > best:
            best, why = lvl, m.group(0)
    return best, why


def classify(item: Item, src: dict, cfg: dict, llm_enabled: bool = False) -> Item | None:
    """Return the item with level/reason set, or None if it should be dropped as irrelevant.
    Items that come back with level 0 are LLM candidates only (dropped later if the LLM leaves them at 0)."""
    text = f"{item.title}\n{item.text}"
    tier = src.get("tier", "news")

    # Official Latvia-specific sources are always relevant; news/OSINT must mention the region.
    if tier in ("news", "osint"):
        ok, hits = relevance(text, cfg)
        if not ok:
            return None
        item.reason = "region: " + ", ".join(hits[:4])

    if item.level == 0 or tier in ("news", "osint"):
        lvl, why = score(text)
        base = src.get("base_level", 0)
        if tier in ("news", "osint"):
            if lvl == 0:
                # ordinary regional news — keep only as an LLM candidate if it is security-adjacent
                if llm_enabled and SOFT.search(text):
                    item.reason += " · candidate"
                    return item
                return None
            # Unverified sources cannot by themselves produce URGENT/CRITICAL; cap at 3 without LLM confirmation.
            lvl = min(lvl, 3)
            # A generic keyword hit in a long OSINT post that only *mentions* the region: soften by one.
            if item.kind == "post" and lvl >= 2 and not relevance(item.title, cfg)[0]:
                lvl -= 1
            # Plans, drills and hypotheticals about a hard trigger are WATCH material, not an alarm.
            if lvl >= 3 and HYPOTHETICAL.search(item.title):
                lvl -= 1
                item.reason += " · planning/hypothetical wording, softened"
        item.level = max(item.level, lvl, base if lvl >= 1 or tier == "official" else 0)
        if why:
            item.reason = (item.reason + " · " if item.reason else "") + f"matched “{why}”"
    # Official advisory *text* change with no keyword hit is still at least INFO.
    if item.kind == "advisory_change" and item.level == 0:
        item.level = 1
        item.reason = item.reason or "wording changed"
    if item.level == 0 and tier == "official":
        item.level = 1
    return item


def dedupe(items: list[Item]) -> list[Item]:
    """Drop near-duplicate headlines across sources (keep the highest level / official one)."""
    def key(t: str) -> str:
        t = re.sub(r"[^a-zа-я0-9 ]", " ", t.lower())
        words = [w for w in t.split() if len(w) > 3][:8]
        return " ".join(words)
    best: dict[str, Item] = {}
    order = {"official": 0, "market": 1, "news": 2, "osint": 3}
    for it in items:
        k = key(it.title)
        if k in best:
            cur = best[k]
            if (it.level, -order.get(it.tier, 9)) > (cur.level, -order.get(cur.tier, 9)):
                best[k] = it
        else:
            best[k] = it
    return list(best.values())
