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
    # Embassy staffing language, in the forms the State Department / FCDO actually use:
    (r"ordered departure|order(ed|s)? (the )?departure|depart(ure)? (of|for) (all|non-emergency)|"
     r"leave (the country |[a-z]+ )?(now|immediately)|depart immediately|evacuat(e|ion|ing)|"
     r"(embassy|consulate)( in [a-z]+)? (has )?(suspended (all )?operations|closed|is closed)", 4),
    (r"\bdo not travel\b", 4),
    (r"airspace (is |has been |will be )?(closed|closure|shut)|clos(e|es|ed|ing|ure of) (its |the |all |national )?airspace|воздушн\w+ пространств\w+ (закрыт|закрыва)", 4),
    (r"border(s)? (is |are |has been |have been )?(closed|sealed)|clos(e|es|ed|ing) (its |the |all )?border|границ\w* (закрыт|закрыва|перекры)", 4),
    (r"(general |partial )?mobili[sz]ation|мобилизац", 4),
    (r"\barticle 5\b|статья 5|статьи 5", 4),
    (r"state of emergency|чрезвычайн\w+ (положени|ситуаци)|ārkārtējā situācija", 4),
    (r"shelter in place|air[- ]raid (siren|alert|warning)|воздушн\w+ тревог", 4),
    # Nuclear: only actual threats/use/deployment near us are URGENT. Policy talk about nuclear weapons is WATCH (below).
    (r"nuclear (strike|attack|alert)|threat(en|ens|ened)?s? (to use )?nuclear|nuclear threat|"
     r"tactical nuclear weapons? (deploy|moved|transferred|stationed)|"
     r"(moves?|moving|moved|deploys?|deploying|deployed|transfers?|transferred|stations?|stationed) (its )?(tactical )?nuclear (weapons?|warheads?|missiles?)|"
     r"ядерн\w+ (удар|угроз)", 4),
    # ---- 3 ELEVATED
    (r"authori[sz]ed departure|authori[sz]e[ds]? (the )?(voluntary )?departure|voluntary departure|"
     r"departure of (family members|eligible family|dependants|dependents|non-?emergency)|"
     r"non-?emergency (u\.?s\.? )?(government )?(employees|personnel|staff)|"
     r"reduc(e|es|ed|ing|tion of|tion in) (its |the |embassy )?(embassy |diplomatic |consular )?(staff|personnel|footprint|presence)|"
     r"drawdown|minimum staffing|skeleton staff|"
     r"suspend(ed|s|ing)? (routine |all |consular |visa |most )?(services|operations)|"
     r"(consular|visa) services (are |have been |will be )?(suspended|limited|unavailable)|"
     r"limited (staffing|capacity to (assist|provide))|ability to (provide|assist).{0,40}(limited|reduced)", 3),
    (r"reconsider travel|advise against all but essential travel|advise against all travel", 3),
    (r"\barticle 4\b|статья 4|статьи 4", 3),
    (r"security alert", 3),
    (r"(troop|force|military) (build[- ]?up|movement|concentration|deployment)|наращива\w+ (войск|сил|группировк)|переброск\w+ (войск|техник)", 3),
    (r"violat(e|ed|ion of) (latvian|estonian|lithuanian|nato|polish|finnish)? ?airspace|наруш\w+ воздушн\w+ пространств", 3),
    # Incursions/invasions count only when aimed at our region (background mentions of Ukraine are stripped below).
    (r"(incursion|invasion)s? (into|of|in) (latvia|estonia|lithuania|the baltics?|baltic|poland|finland|nato)|"
     r"(latvian|estonian|lithuanian|baltic|polish|finnish|nato) (airspace |territory |border )?incursion|"
     r"вторжени\w* (в|на) (латви|эстони|литв|прибалт|балти|польш|финлянд)", 3),
    (r"(explosion|blast|attack|strike|missile|shelling) .{0,80}(latvia|estonia|lithuania|baltic|kaliningrad|pskov|belarus)", 3),
    (r"(взрыв|атак|удар|ракет).{0,80}(латви|эстони|литв|прибалт|балти|калининград|псков|беларус)", 3),
    (r"embassy (closes|closed|closing|suspend)|посольств\w+ (закрыва|приостанав)", 3),
    (r"nato (deploys|reinforces|sends).{0,60}(baltic|latvia|estonia|lithuania)", 3),
    # ---- 2 WATCH
    (r"sabotage|диверси|hybrid attack|гибридн\w+ (атак|войн)|arson|поджог", 2),
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
    (r"nuclear|ядерн", 2),
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
    r"\b(plans?|planning|planned|prepar\w*|drill|drills|exercise|exercises|tests?|testing|scenario|simulat\w*|contingency|"
    r"in (the )?(case|event) of|if\b|should russia|were to|what if|would|could|might|may|hypothetical|table-?top|"
    r"rehears\w*|warns? of|warned of|warning of|debate|proposal|proposes?|considers?|considering|moves? to|"
    r"lift(s|ing)? (the )?ban|"
    r"план\w*|готов\w*|учени\w*|сценари\w*|отработ\w*|на случай|в случае|если\b|предлага\w*|обсужда\w*)\b", re.I)


# Threats voiced by state media, pundits and propagandists, and analysis/opinion pieces about them, are
# rhetoric (WATCH), not an official act. Threats by the government itself are not softened.
RHETORIC = re.compile(
    r"state[- ](media|tv|television|run|controlled)|propagand|pundit|tv (host|show|anchor)|talk[- ]show|blogger|"
    r"columnist|op-ed|opinion|analysis|explainer|explained|rhetoric|\bsignals?\b|pressure campaign|"
    r"пропаганд|телевед|госсми|госканал|пропагандист", re.I)


# Hybrid incidents (arson, sabotage, vandalism, cyber) are WATCH even when a headline calls them an "attack";
# the L3 attack rule is for kinetic events (explosions, missiles, shelling, strikes).
INCIDENT = re.compile(r"arson|sabotage|vandal|graffiti|cyber|hack(ed|ers?|ing)|поджог|диверси|кибер", re.I)
KINETIC = re.compile(r"explosion|blast|missile|shelling|air ?strike|bomb|взрыв|ракет|обстрел", re.I)


# Background references that appear in half of all Baltic news and say nothing about today's risk:
# "since Russia's full-scale invasion of Ukraine", "the war in Ukraine", … Removed before scoring.
BACKGROUND = re.compile(
    r"(since |after |following |amid |because of |due to )?(the |russia'?s |moscow'?s )?(full[- ]scale |illegal |unprovoked |brutal )?"
    r"(invasion|war|aggression|assault|attack) (of|in|on|against) ukraine|"
    r"(since|after|following) (the |russia'?s )?(full[- ]scale )?invasion\b|"
    r"russia'?s (full[- ]scale )?invasion\b|russia-ukraine war|war in ukraine|ukraine war|"
    r"(полномасштабн\w+ )?(вторжени\w*|войн\w*|нападени\w*|агресси\w*) (росси\w+ )?(в|на|против) украин\w*|"
    r"с начала (полномасштабн\w+ )?(вторжени\w*|войн\w*)", re.I)


def clean(text: str) -> str:
    return BACKGROUND.sub(" ", text or "")


# Routine embassy closures ("closed in observance of Thanksgiving", "holiday closure") are INFO, not an alarm.
ROUTINE_CLOSURE = re.compile(
    r"holiday|in observance|thanksgiving|christmas|new year|independence day|labou?r day|memorial day|"
    r"veterans day|presidents'? day|juneteenth|easter|midsummer|jāņi|ligo|līgo|closed (on|for) (monday|tuesday|wednesday|"
    r"thursday|friday)|праздни|выходн", re.I)
EMBASSY_WORDS = re.compile(r"embassy|consulate|посольств", re.I)


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
        base = src.get("base_level", 0)
        if tier in ("news", "osint"):
            # The headline decides. Body/summary text (where background mentions live) can add at most WATCH.
            lvl_t, why_t = score(clean(item.title))
            lvl_b, why_b = score(clean(item.text))
            lvl_b = min(lvl_b, 2)
            lvl, why = (lvl_t, why_t) if lvl_t >= lvl_b else (lvl_b, why_b + " (in text)")
        else:
            lvl, why = score(text)
        # "Embassy closed" because of a public holiday is routine, whatever the source.
        if lvl >= 3 and EMBASSY_WORDS.search(why) and ROUTINE_CLOSURE.search(text):
            lvl = 1
            item.reason = (item.reason + " · " if item.reason else "") + "routine holiday closure"
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
            elif lvl >= 3 and RHETORIC.search(item.title):
                lvl -= 1
                item.reason += " · rhetoric / commentary, softened"
            if lvl == 3 and INCIDENT.search(item.title) and not KINETIC.search(item.title):
                lvl = 2
                item.reason += " · hybrid incident (sabotage/arson/cyber) → WATCH"
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


def corroborate(items: list[Item], recent: list[dict], hours: int = 6) -> list[Item]:
    """News/OSINT items at L3 stay ELEVATED only when another *independent* outlet reported the *same story*
    in its own words (not a re-indexed copy of the same headline) with an L3+ grade within the last `hours` —
    this run or earlier runs. A lone headline is held at WATCH with a note. Official sources are never held."""
    from datetime import datetime, timedelta, timezone
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    prior = [r for r in recent if r.get("ts", "") >= cutoff and r.get("raw_level", r.get("level", 0)) >= 3]
    hot_now = [it for it in items if it.level >= 3]
    for it in items:
        if it.tier not in ("news", "osint") or it.level != 3:
            continue
        k = title_key(it.title)
        witnesses = [r for r in prior if r.get("source") != it.source_name and r.get("title_key") != k
                     and same_story(it.title, r.get("title", ""))]
        witnesses += [o for o in hot_now if o is not it and o.source_name != it.source_name and title_key(o.title) != k
                      and same_story(it.title, o.title)]
        if not witnesses:
            it.level = 2
            it.reason += " · single source, held at WATCH until another source corroborates"
        else:
            w = witnesses[0]
            it.reason += " · corroborated by " + (w.get("source") if isinstance(w, dict) else w.source_name)
    return items


_GENERIC = {"russi", "ukrai", "lithu", "eston", "latvi", "balti", "polan", "polis", "finla", "finni", "belar",
            "kalin", "europ", "kreml", "mosco", "gover", "minis", "presi", "offic", "repor", "again", "about",
            "their", "there", "would", "could", "shoul", "state", "after", "warns", "warni", "threa", "secur",
            "milit", "defen", "attac", "count", "regio", "citiz", "peopl", "natio", "borde"}


def story_stems(title: str) -> set[str]:
    """Crude topic fingerprint of a headline: 5-letter stems of its content words, minus region/generic words."""
    t = re.sub(r"\s+[-–|]\s+[^-–|]{2,40}$", "", (title or "").lower())
    return {w[:5] for w in re.findall(r"[a-zа-яё]{5,}", t)} - _GENERIC


def same_story(a: str, b: str) -> bool:
    """Two headlines are about the same story when they share a distinctive content word
    ("nuclear"/"nuclear", "arson"/"arson", "milrem"/"milrem"). Region names and generic security words
    don't count, so 'air-raid siren test' cannot corroborate 'nuclear threats'."""
    return bool(story_stems(a) & story_stems(b))


def title_key(t: str) -> str:
    """Normalised headline for duplicate detection: publisher suffix ("… - Euronews") removed,
    lower-cased, punctuation stripped, first 8 words longer than 3 letters."""
    t = re.sub(r"\s+[-–|]\s+[^-–|]{2,40}$", "", t or "")      # drop trailing " - Publisher"
    t = re.sub(r"[^a-zа-яėįųūąčęšžāēīōūģķļņ0-9 ]", " ", t.lower())
    words = [w for w in t.split() if len(w) > 3][:8]
    return " ".join(words)


def dedupe(items: list[Item]) -> list[Item]:
    """Drop near-duplicate headlines across sources (keep the highest level / official one)."""
    key = title_key
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
