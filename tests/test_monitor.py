"""Offline tests: parsers on fixtures, classifier rules, message formatting. No network."""
import json
import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["MONITOR_DRY_RUN"] = "1"

from monitor.core import Item, State, load_config, local_tz  # noqa: E402
from monitor import fetchers, classify  # noqa: E402
from monitor.telegram import Telegram, format_alert, split_message  # noqa: E402
from monitor.digest import build_digest  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
CFG = load_config()


class FakeResp:
    def __init__(self, text="", data=None, status=200):
        self.text = text
        self.content = text.encode("utf-8")
        self._data = data
        self.status_code = status

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


def tmp_state(tmp_path):
    return State(tmp_path / "state")


# ---------------------------------------------------------------- classifier

def _src(tier="news", **kw):
    return {"id": "x", "name": "X", "tier": tier, **kw}


def test_rules_hard_triggers():
    assert classify.score("US Embassy Riga: Ordered departure of non-emergency personnel")[0] == 4
    assert classify.score("Latvia closes its airspace along the eastern border")[0] == 4
    assert classify.score("Россия объявила частичную мобилизацию")[0] == 4
    assert classify.score("NATO ambassadors meet after Estonia invokes Article 4")[0] == 3
    assert classify.score("Security Alert: U.S. Embassy Riga")[0] == 3
    assert classify.score("Drone fragments found near Rēzekne")[0] == 2
    assert classify.score("Defence minister announces reservist training")[0] == 1
    assert classify.score("Foreign minister visits Riga for talks")[0] == 0   # ordinary news → not reported


def test_news_relevance_filter():
    it = Item(source_id="x", source_name="X", title="Missile strike on Kyiv kills three", url="u")
    assert classify.classify(it, _src("news"), CFG) is None            # no Baltic keyword → dropped
    it = Item(source_id="x", source_name="X", title="Russian drone crosses into Latvia near Daugavpils", url="u")
    out = classify.classify(it, _src("news"), CFG)
    assert out is not None and out.level == 2
    it = Item(source_id="x", source_name="X", title="Latvia closes border with Belarus after incident", url="u")
    out = classify.classify(it, _src("osint"), CFG)
    assert out.level == 3                                             # OSINT capped at 3 without corroboration
    it = Item(source_id="x", source_name="X", title="Poland and Lithuania preparing cross-border evacuation plan for Baltic states", url="u")
    out = classify.classify(it, _src("news"), CFG)
    assert out.level == 2 and "softened" in out.reason                # a plan, not an evacuation → WATCH
    it = Item(source_id="x", source_name="X", title="Lithuania begins evacuation of border villages near Belarus", url="u")
    assert classify.classify(it, _src("news"), CFG).level == 3         # an actual evacuation stays ELEVATED


def test_calibration_cases_from_first_night():
    """Headlines that were graded L3 on the first night and should not have been."""
    cases = {
        "Lithuania moves to lift ban on nuclear weapons as ‘Russians do not attack the strong’ - euobserver.com": 2,
        "Lithuanian border municipalities warn of evacuation problems in event of Russian attack - The New Voice of Ukraine": 2,
        "Poland and Lithuania preparing cross-border evacuation plan for Baltic states - Euronews.com": 2,
    }
    for title, want in cases.items():
        out = classify.classify(Item(source_id="x", source_name="X", title=title, url="u"), _src("news"), CFG)
        assert out is not None and out.level == want, (title, out and out.level)
    # …while the real thing keeps its level
    real = {
        "Russia threatens nuclear strike on Baltic states over Kaliningrad transit": 3,   # news cap
        "US Embassy Riga: ordered departure of non-emergency personnel": 3,               # news cap
    }
    for title, want in real.items():
        assert classify.classify(Item(source_id="x", source_name="X", title=title, url="u"), _src("news"), CFG).level == want


def test_background_ukraine_mentions_do_not_score():
    """The LRT article that was graded L3 on 28 Sep: 'invasion' only appeared as background in the summary."""
    it = Item(source_id="lrt", source_name="LRT", title="Russian language study falls, German rises in Lithuanian schools", url="u",
              text="The share of pupils choosing Russian has fallen every year since Russia's full-scale invasion of Ukraine, "
                   "while German and Spanish are rising, the education ministry said.")
    assert classify.classify(it, _src("news"), CFG) is None          # ordinary news → dropped entirely
    # body text can add at most WATCH, never an alert
    it = Item(source_id="x", source_name="X", title="Latvian parliament debates school funding", url="u",
              text="Officials also discussed a drone incursion into Latvia last week.")
    assert classify.classify(it, _src("news"), CFG).level == 2
    # …but the same thing in the headline is ELEVATED (a drone incursion is an incident → WATCH; troops are not)
    it = Item(source_id="x", source_name="X", title="Russian drone incursion into Latvia confirmed by army", url="u")
    assert classify.classify(it, _src("news"), CFG).level == 2
    it = Item(source_id="x", source_name="X", title="Russian military incursion into Latvia confirmed by army", url="u")
    assert classify.classify(it, _src("news"), CFG).level == 3
    assert "invasion" not in classify.clean("since Russia's invasion of Ukraine, Latvia has")


def test_corroboration_holds_lone_headlines():
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    out = classify.corroborate([a], recent=[])
    assert out[0].level == 2 and "single source" in out[0].reason
    # a second, independent outlet reporting the SAME event in its own words → both stay ELEVATED
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    b = Item(source_id="err", source_name="ERR", title="Army confirms Russian drone crossed into Latvia near Daugavpils", url="2", tier="news", level=3)
    out = classify.corroborate([a, b], recent=[])
    assert out[0].level == 3 and out[1].level == 3 and "corroborated by" in out[0].reason
    # an unrelated L3 story from another outlet is NOT corroboration (a siren test cannot confirm a nuclear threat)
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    u = Item(source_id="lrt", source_name="LRT", title="Lithuania to test air raid sirens on Tuesday", url="5", tier="news", level=3)
    out = classify.corroborate([a, u], recent=[])
    assert out[0].level == 2 and out[1].level == 2
    # the same headline re-indexed by another aggregator does NOT count either
    c = Item(source_id="gn", source_name="Google News", title="Russian drone incursion into Latvia confirmed by army - Delfi", url="3", tier="news", level=3)
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    out = classify.corroborate([a, c], recent=[])
    assert out[0].level == 2
    # earlier runs count too (raw_level ≥3 within the window), official sources are never held
    from datetime import datetime, timezone
    recent = [{"ts": datetime.now(timezone.utc).isoformat(), "raw_level": 3, "level": 2, "source": "ERR",
               "title": "Drone from Russia crashed in eastern Latvia, army says", "title_key": "drone from russia crashed eastern latvia army says"}]
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    o = Item(source_id="us", source_name="US Embassy Riga alerts", title="Security Alert", url="4", tier="official", level=3)
    out = classify.corroborate([a, o], recent=recent)
    assert out[0].level == 3 and out[1].level == 3


def test_rhetoric_and_incidents_are_watch_not_elevated():
    """Today's false-highs (29 Sep): state-media nuclear rhetoric and an arson attack both read as L3."""
    for title, want in {
        "Nuclear Threats Against Lithuania Signal New Pressure Campaign on NATO - Odessa Journal": 2,
        "Why Russian State Media Threatened Lithuania with a Nuclear Strike - lansinginstitute": 2,
        "Estonia slams Russian 'sabotage' after arson attack on defence company Milrem Robotics - Euronews": 2,
        "ISS chief: Milrem arson was first successful Russian attack on Estonia this year": 2,
        "Lithuania to test air raid sirens on Tuesday": 2,
        "Kremlin: Russia will respond to NATO troops in Baltics with nuclear strike": 3,      # official threat
        "Explosion at ammunition depot near Daugavpils, Latvia, army says": 3,               # kinetic
    }.items():
        it = Item(source_id="x", source_name="X", title=title, url="u", text="", kind="news")
        out = classify.classify(it, _src("news"), CFG)
        assert out is not None and out.level == want, f"{title} → L{out.level if out else None}"


def test_title_key_and_cross_run_duplicates(tmp_path):
    a = "Lithuanian border municipalities warn of evacuation problems in event of Russian attack - The New Voice of Ukraine"
    b = "Lithuanian border municipalities warn of evacuation problems in event of Russian attack - english.nv.ua"
    assert classify.title_key(a) == classify.title_key(b)
    st = tmp_state(tmp_path)
    st.mark_title(classify.title_key(a))
    assert st.title_seen(classify.title_key(b))


def test_official_source_min_level():
    it = Item(source_id="x", source_name="X", title="Health – editorial change", url="u", kind="advisory_change")
    out = classify.classify(it, _src("official"), CFG)
    assert out.level == 1


def test_dedupe_prefers_official():
    a = Item(source_id="a", source_name="Google News", title="Latvia closes border with Belarus", url="1", tier="news", level=3)
    b = Item(source_id="b", source_name="LSM", title="Latvia closes border with Belarus", url="2", tier="official", level=3)
    out = classify.dedupe([a, b])
    assert len(out) == 1 and out[0].source_name == "LSM"


# ---------------------------------------------------------------- fetchers on fixtures

def test_telegram_preview_parser(tmp_path):
    html = (FIX / "tme_channel.html").read_text(encoding="utf-8")
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=html)):
        items = fetchers.fetch_telegram({"id": "tg", "name": "TG", "handle": "demo", "max_age_days": 100000}, tmp_state(tmp_path))
    assert len(items) == 2
    assert items[0].url == "https://t.me/demo/101"
    assert "Latvia" in items[0].text and items[0].published.startswith("2026-09-26")
    assert items[1].lang == "ru"


def test_fcdo_alert_status_change(tmp_path):
    st = tmp_state(tmp_path)
    src = {"id": "fcdo", "name": "FCDO", "url": "u", "page": "p", "tier": "official"}
    base = json.loads((FIX / "fcdo_latvia.json").read_text(encoding="utf-8"))
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(data=base)):
        assert fetchers.fetch_fcdo(src, st) == []                    # baseline
    changed = json.loads(json.dumps(base))
    changed["details"]["alert_status"] = ["avoid_all_but_essential_travel_to_whole_country"]
    changed["details"]["change_history"].insert(0, {"note": "FCDO now advises against all but essential travel to Latvia",
                                                    "public_timestamp": "2026-10-01T09:00:00Z"})
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(data=changed)):
        items = fetchers.fetch_fcdo(src, st)
    kinds = sorted((i.level, i.title[:20]) for i in items)
    assert any(i.level == 3 and "alert status" in i.title for i in items)
    assert any("FCDO update" in i.title for i in items)


def test_state_dept_level_change(tmp_path):
    st = tmp_state(tmp_path)
    src = {"id": "us", "name": "US", "url": "u", "tier": "official"}
    page1 = (FIX / "state_dept_latvia.html").read_text(encoding="utf-8")
    page2 = page1.replace("Level 1: Exercise Normal Precautions", "Level 3: Reconsider Travel") \
                 .replace("Exercise normal precautions in Latvia.", "Reconsider travel to Latvia due to the security situation near the border.")
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=page1)):
        assert fetchers.fetch_state_dept_advisory(src, st) == []
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=page2)):
        items = fetchers.fetch_state_dept_advisory(src, st)
    assert len(items) == 1 and items[0].level == 3 and "RAISED" in items[0].title
    assert "Reconsider travel" in items[0].text


def test_rss_filter_and_age(tmp_path):
    xml = (FIX / "state_rss.xml").read_text(encoding="utf-8")
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=xml)):
        items = fetchers.fetch_rss({"id": "r", "name": "R", "url": "u", "tier": "official",
                                    "include": ["latvia", "estonia"]}, tmp_state(tmp_path))
    assert [i.title for i in items] == ["Latvia - Level 1: Exercise Normal Precautions"]


def test_embassy_staffing_phrasings():
    """The wording embassies actually use, buried in advisory text (official tier → full text is scored)."""
    src = _src("official")
    for text, want in {
        "The Department has authorized the voluntary departure of family members of U.S. government employees.": 3,
        "Routine consular services are suspended until further notice.": 3,
        "The embassy has reduced its staff and its ability to provide services is limited.": 3,
        "On 3 October the Department ordered the departure of non-emergency U.S. government employees.": 4,
        "The Embassy in Riga has suspended operations.": 4,
        "Embassy staff attended a reception with the defence minister.": 1,   # official min level, digest only
        "The U.S. Embassy in Riga will be closed on Thursday, November 27 in observance of Thanksgiving.": 1,
    }.items():
        it = Item(source_id="o", source_name="O", title="Advisory text changed", url="u", text=text, kind="advisory_change")
        assert classify.classify(it, src, CFG).level == want, text


def test_rss_diff_mode_catches_wording_changes(tmp_path):
    """The video's key signal: the advisory level stays the same, but the wording about embassy staff changes."""
    st = tmp_state(tmp_path)
    src = {"id": "us_state_rss", "name": "US State Dept advisories (feed)", "url": "u", "tier": "official",
           "include": ["latvia"], "diff_titles": ["Latvia"]}
    xml1 = (FIX / "state_rss.xml").read_text(encoding="utf-8")
    xml2 = xml1.replace("Exercise normal precautions in Latvia.",
                        "Exercise normal precautions in Latvia. The Department has authorized the voluntary departure of "
                        "family members of U.S. government employees due to the security situation.")
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=xml1)):
        first = fetchers.fetch_rss(src, st)                      # first sighting: reported normally, baseline stored
    assert [i.kind for i in first] == ["alert"]
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=xml1)):
        assert fetchers.fetch_rss(src, st) == []                 # unchanged text: silent
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(text=xml2)):
        changed = fetchers.fetch_rss(src, st)
    assert len(changed) == 1 and changed[0].kind == "advisory_change"
    assert "+ " in changed[0].text and "authorized the voluntary departure" in changed[0].text
    out = classify.classify(changed[0], src, CFG)
    assert out.level >= 3                                        # official wording change about staff → alert, no hold
    assert classify.corroborate([out], recent=[])[0].level >= 3


def test_polymarket_move(tmp_path):
    st = tmp_state(tmp_path)
    src = {"id": "polymarket", "name": "PM", "queries": ["x"], "include": ["nato"], "move_watch_pp": 5, "move_elevated_pp": 15}
    ev = {"events": [{"slug": "nato-x-russia", "title": "NATO x Russia clash?", "active": True, "closed": False,
                      "markets": [{"slug": "m1", "question": "NATO x Russia clash by 2027?", "outcomePrices": '["0.10","0.90"]',
                                   "endDate": "2027-01-01T00:00:00Z", "volumeNum": 1000}]}]}
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(data=ev)):
        assert fetchers.fetch_polymarket(src, st) == []
    ev["events"][0]["markets"][0]["outcomePrices"] = '["0.27","0.73"]'
    with mock.patch.object(fetchers, "http_get", return_value=FakeResp(data=ev)):
        items = fetchers.fetch_polymarket(src, st)
    assert len(items) == 1 and items[0].level == 3 and "+17 pp" in items[0].title


# ---------------------------------------------------------------- formatting

def test_alert_and_digest_format(tmp_path):
    st = tmp_state(tmp_path)
    tz = local_tz(CFG)
    it = Item(source_id="us_embassy_riga", source_name="US Embassy Riga alerts", title="Security Alert: Authorized departure",
              url="https://lv.usembassy.gov/x", text="Non-emergency staff may depart.", level=3, reason="matched “authorized departure”",
              tier="official", kind="alert")
    txt = format_alert(it, CFG, tz)
    assert txt.startswith("🟠 <b>L3 ELEVATED</b>") and "Source</a>" in txt
    st.record_level(it)
    d = build_digest([it], st, CFG, tz, *st.overall_level(72), bottom="Calm but watchful.", label="Evening digest")
    assert "CONFLICT MONITOR — Evening digest" in d and "Bottom line" in d and "L3 ELEVATED" in d
    assert all(len(p) <= 4000 for p in split_message("x\n" * 5000))


def test_dry_run_send():
    tg = Telegram(token="", channel="@x")
    assert tg.dry and tg.send("hello") > 0


# ---------------------------------------------------------------- status message & digest timing

def test_overall_level_uses_latest_item_and_reports_since(tmp_path):
    """The pinned status names the *latest* item at the top level, says since when that level has held,
    and how many items hold it — not the oldest item in the window."""
    from datetime import datetime, timedelta, timezone
    st = tmp_state(tmp_path)
    now = datetime.now(timezone.utc)
    st.status["recent_levels"] = [
        {"ts": (now - timedelta(hours=50)).isoformat(timespec="seconds"), "level": 2, "title": "Old L2 - Euronews.com",
         "source": "Google News — Latvia security", "url": "https://x/old"},
        {"ts": (now - timedelta(hours=5)).isoformat(timespec="seconds"), "level": 1, "title": "Info item", "source": "ERR"},
        {"ts": (now - timedelta(hours=2)).isoformat(timespec="seconds"), "level": 2, "title": "New L2 - LSM",
         "source": "Google News — Latvia security", "url": "https://x/new"},
        {"ts": (now - timedelta(hours=100)).isoformat(timespec="seconds"), "level": 4, "title": "Expired L4", "source": "X"},
    ]
    level, row = st.overall_level(72)
    assert level == 2
    assert row["title"] == "New L2 - LSM" and row["url"] == "https://x/new"
    assert row["since"].startswith((now - timedelta(hours=50)).isoformat(timespec="seconds")[:13])
    assert row["n"] == 2


def test_status_message_layout(tmp_path):
    from monitor.telegram import format_status
    row = {"title": "Poland and Lithuania preparing cross-border evacuation plan - Euronews.com", "level": 2,
           "source": "Google News — Latvia security", "url": "https://news.example/1",
           "ts": "2026-09-27T20:01:33+00:00", "since": "2026-09-27T20:01:33+00:00", "n": 3,
           "reason": "region: lithuania · planning/hypothetical wording, softened · matched “evacuation”"}
    text = format_status(2, row, CFG, local_tz(CFG), 23, 23, guide='<a href="https://t.me/c/1/2">📖 Level guide</a>')
    lines = text.split("\n")
    assert lines[0] == ("📟 <b>CURRENT LEVEL: 🟡 L2 WATCH.</b> Poland and Lithuania preparing cross-border evacuation plan")
    assert lines[1].startswith('<a href="https://news.example/1">Euronews.com via Google News — Latvia security</a>')
    assert "at L2 since Sun 27 Sep 23:01 (3 items at this level in 72 h)" in lines[1]
    # the generic level definition is never inline (it read like a claim about the item); the item's own reason is
    assert lines[2].startswith("<b>Why L2:</b>") and "evacuation" in lines[2]
    assert lines[3] == "<b>Suggested action at L2:</b> Stay aware."
    assert "highest of the last 72 h" in lines[4] and "Level guide" in lines[4]
    assert "Means" not in text and "embassy" not in text.lower()
    quiet = format_status(0, None, CFG, local_tz(CFG), 23, 23).split("\n")
    assert quiet[0] == "📟 <b>CURRENT LEVEL: ⚪ L0 QUIET.</b>" and quiet[1].startswith("Nothing new")
    # L4 alerts carry only the suggested action, not the definition
    from monitor.telegram import format_alert, guide_text
    it = Item(source_id="o", source_name="O", title="Latvia - Level 4: Do Not Travel — advisory text changed", url="u",
              text="+ ordered departure", kind="advisory_change", tier="official", level=4, reason="matched “ordered departure”")
    a = format_alert(it, CFG, local_tz(CFG))
    assert "<b>Suggested action at L4:</b> Execute your plan." in a and "means" not in a.lower()
    assert "LEVEL GUIDE" in guide_text(CFG) and "L3 ELEVATED" in guide_text(CFG)


def test_digest_catches_up_after_missed_slot(tmp_path):
    """Scheduled runs are not guaranteed to land inside the 08:00/20:00 hour, so a digest is due on the
    first run after a slot until one has been sent for it — and never twice for the same slot."""
    from datetime import datetime, timedelta
    from monitor import __main__ as m
    tz = local_tz(CFG)
    st = tmp_state(tmp_path)

    class FakeDT(datetime):
        _now = None

        @classmethod
        def now(cls, tz=None):
            return cls._now.astimezone(tz) if tz else cls._now

    with mock.patch.object(m, "datetime", FakeDT):
        FakeDT._now = datetime(2026, 9, 29, 10, 32, tzinfo=tz)      # 10:32, no run landed at 08:xx
        assert m.digest_due(CFG, st)                                   # never sent → due
        assert m.digest_label(CFG) == "Morning digest (for 08:00, delayed)"
        st.status["last_digest"] = datetime(2026, 9, 29, 10, 33, tzinfo=tz).isoformat(timespec="seconds")
        FakeDT._now = datetime(2026, 9, 29, 15, 7, tzinfo=tz)
        assert not m.digest_due(CFG, st)                               # 08:00 slot already covered
        FakeDT._now = datetime(2026, 9, 29, 20, 7, tzinfo=tz)
        assert m.digest_due(CFG, st) and m.digest_label(CFG) == "Evening digest"
        st.status["last_digest"] = datetime(2026, 9, 29, 20, 8, tzinfo=tz).isoformat(timespec="seconds")
        FakeDT._now = datetime(2026, 9, 30, 4, 48, tzinfo=tz)
        assert not m.digest_due(CFG, st)                               # nothing due overnight
        FakeDT._now = datetime(2026, 9, 30, 8, 7, tzinfo=tz)
        assert m.digest_due(CFG, st) and m.digest_label(CFG) == "Morning digest"


def test_official_warnings_are_kept_and_posted_silently(tmp_path):
    """Senior officials' warnings about Russian action against NATO/Europe (owner's examples, 29 Sep) are relevant
    without a Baltic keyword, graded WATCH, flagged, and posted on arrival without an alarm."""
    belgium = ("BREAKING: Belgiums Chief of Defence Frederik Vansina has said Russia could occupy a small party of NATO "
               "territory in a large escalation of directly attack infrastructure on NATO territory in a false flag attack "
               "using Ukrainian drones. That would be an article 5…")
    tusk = ("Polish Prime Minister Donald Tusk: “Poland is facing very difficult weeks and months ahead due to increasing "
            "aggressive Russian actions, our security services are doing everything in their power to stop actions "
            "expanding to Polish territory.”")
    for post in (belgium, tusk):
        it = Item(source_id="tg", source_name="Clash Report", title=post[:140] + "…", url="https://t.me/x/1", text=post, kind="post")
        out = classify.classify(it, _src("osint"), CFG)
        assert out is not None and out.warning and out.level == 2, post[:60]
    for title, want in {
        "Russia could attack a Nato country within months, Danish intelligence says": True,
        "German defence minister Pistorius: Russia could be ready to attack NATO by 2029": True,
        "NATO chief calls for calm as intel agency warns Russia may ramp up hybrid attacks - ABC News": True,
        "Poland requests Article 4 consultations after Russian drones shot down": False,   # relevant anyway (Article 4 is core)
        "Defence minister opens new kindergarten in Poznań": None,                          # dropped
        "Tusk: Poland to raise defence spending to 5% of GDP": None,
        "India warns new US tariffs over Russian oil could impact ties": None,
        "Finnish president Stubb: Russia is not going to attack Finland": None,
    }.items():
        it = Item(source_id="x", source_name="X", title=title, url="u", text="", kind="news")
        out = classify.classify(it, _src("news"), CFG)
        if want is None:
            assert out is None, title
        else:
            assert out is not None and out.warning == want and out.level >= 2, title
    # the alert header marks it, and the poll posts it immediately but silently
    it = Item(source_id="x", source_name="X", title="Rutte: NATO must be ready for war with Russia within five years", url="u", kind="news")
    out = classify.classify(it, _src("news"), CFG)
    assert format_alert(out, CFG, local_tz(CFG)).startswith("🗣 <b>OFFICIAL WARNING</b> · 🟡 <b>L2 WATCH</b>")
    from monitor import __main__ as m
    st = tmp_state(tmp_path)
    sent = []
    class TG(Telegram):
        def send(self, text, chat_id=None, silent=False, pin=False):
            sent.append((text[:40], silent)); return 1
        def sync_subscribers(self, *a, **k): pass
    with mock.patch.object(m, "collect", return_value=[out]):
        m.run_poll(CFG, st, TG())
    assert any(t.startswith("🗣") and silent for t, silent in sent)
