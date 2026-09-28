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
    # …but the same thing in the headline is ELEVATED
    it = Item(source_id="x", source_name="X", title="Russian drone incursion into Latvia confirmed by army", url="u")
    assert classify.classify(it, _src("news"), CFG).level == 3
    assert "invasion" not in classify.clean("since Russia's invasion of Ukraine, Latvia has")


def test_corroboration_holds_lone_headlines():
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    out = classify.corroborate([a], recent=[])
    assert out[0].level == 2 and "single source" in out[0].reason
    # a second, independent outlet with a different L3 story within the window → both stay ELEVATED
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    b = Item(source_id="err", source_name="ERR", title="Estonia reports airspace violation by Russian jets", url="2", tier="news", level=3)
    out = classify.corroborate([a, b], recent=[])
    assert out[0].level == 3 and out[1].level == 3 and "corroborated by" in out[0].reason
    # the same story from another outlet does NOT count as corroboration
    c = Item(source_id="gn", source_name="Google News", title="Russian drone incursion into Latvia confirmed by army - Delfi", url="3", tier="news", level=3)
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    out = classify.corroborate([a, c], recent=[])
    assert out[0].level == 2
    # earlier runs count too (raw_level ≥3 within the window), official sources are never held
    from datetime import datetime, timezone
    recent = [{"ts": datetime.now(timezone.utc).isoformat(), "raw_level": 3, "level": 2, "source": "ERR", "title_key": "estonia reports airspace violation russian jets"}]
    a = Item(source_id="lsm", source_name="LSM", title="Russian drone incursion into Latvia confirmed by army", url="1", tier="news", level=3)
    o = Item(source_id="us", source_name="US Embassy Riga alerts", title="Security Alert", url="4", tier="official", level=3)
    out = classify.corroborate([a, o], recent=recent)
    assert out[0].level == 3 and out[1].level == 3


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
