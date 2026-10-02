# Conflict Monitor

Early-warning feed for **Latvia and the Baltics**, delivered to a private Telegram channel.
It watches official travel advisories, embassy alerts, regional news, OSINT Telegram channels and
prediction markets; **diffs the wording** of advisories (the real early signal), grades every item on a
0–5 scale, posts urgent items immediately and everything else in two daily digests.

Runs for free on **GitHub Actions** (no server) and needs no paid API. Rules-only by default; an optional
Claude API key adds AI-written summaries and finer triage of news/OSINT posts.

## Alert scale

| Level | Badge | Meaning | What to do |
|---|---|---|---|
| 5 | ⚫ **CRITICAL** | Attack/incursion under way or imminent; martial law or state of emergency | Act on your plan now; follow civil-defence instructions |
| 4 | 🔴 **URGENT** | "Leave now" / ordered departure of embassy staff, airspace or border closure, mobilisation, NATO Article 4/5 invoked | Execute your plan |
| 3 | 🟠 **ELEVATED** | Advisory level raised, embassy staff reduction / authorized departure, security alert, several signals converge | Prepare: documents, cash, fuel, go-bag, family plan |
| 2 | 🟡 **WATCH** | Security-related wording change, exercises or build-up, drones/sabotage incidents, sharper rhetoric | Stay aware |
| 1 | 🟢 **INFO** | Routine updates, minor edits, general regional news | Nothing |
| 0 | ⚪ **QUIET** | Nothing new | — |

* Level **3+** → posted to the channel immediately, with notification.
* Level **4+** → also pinned and sent as a **direct message** to everyone who has sent `/start` to the bot.
* Level **1–2** → collected into the **digests** at 08:00 and 20:00 (Europe/Riga).
* 🗣 **Official warnings** — a head of government, defence/foreign minister, chief of defence, intelligence chief or
  NATO leadership publicly warning about Russian action against NATO/Europe — are WATCH but are posted **on arrival,
  silently** (`alerts.immediate_warnings`), even when they don't mention the Baltics.
* A pinned **📟 CURRENT LEVEL** message shows the highest level seen in the last 72 h, names the latest item at that
  level and says *why* it got the level. The level definitions live in one pinned **📖 Level guide** message.

Every message starts with the badge (emoji + `L<n> NAME`), so the channel can be scanned at a glance.

## Sources (edit `config.yaml`)

**Official (text is diffed between runs)**
- US State Department advisories: the Latvia page (level + full text; blocked from GitHub, so a soft source) and the
  advisories RSS feed, whose Latvia/Estonia/Lithuania entries are snapshot-diffed sentence by sentence
- US Embassy security/other alerts: Riga, Tallinn, Vilnius, Warsaw, Helsinki
- UK FCDO travel advice for Latvia, Estonia and Lithuania (content API: alert status + change history + text)
- Israel: the announcement pages of the Israeli embassies in Riga, Vilnius, Tallinn, Helsinki and Warsaw (staff
  reductions, suspended consular services, closures) and two Google News queries — Israeli embassy / NSC news in
  the region, and NSC travel-warning updates (a warning raised for one of our countries is ELEVATED). The NSC's own
  level table on gov.il refuses scripted access (bot-protected page, data API answers 403 to GitHub; the
  tlvflights.com mirror is Cloudflare-blocked), so it is followed through the press, which reports every change.
- Canada and Germany travel advice pages for Latvia

**Regional news (feeds; only security-relevant items that mention the region pass)**
- LSM (Latvia), ERR (Estonia), LRT (Lithuania) English services
- Google News queries for Latvia/Baltic security, embassy movements, airspace/NOTAM closures and NATO–Baltic news
  (EASA's conflict-zone bulletin list is JavaScript-only and NATO's RSS is dead, so news queries cover those signals)

**OSINT / breaking-news Telegram channels (read from public previews, no account needed)**
- Clash Report, Disclose.tv (EN) · NEXTA Live, Meduza, ASTRA, Novaya Gazeta Europe (RU, independent) ·
  Rybar (RU, pro-Kremlin — adversary-side signal, labelled as such)

**Prediction markets**
- Polymarket markets about Russia/NATO/Baltics; a move of ≥5 pp since the last check is reported, ≥15 pp upward is ELEVATED.

Twitter/X is deliberately not used (paid API); most OSINT accounts mirror to Telegram.

## How it works

```
every 30 min (GitHub Actions cron)
  fetch all sources ─► drop already-seen items ─► relevance filter (region keywords)
  ─► rule-based severity (EN/RU regexes) ─► [optional Claude grading] ─► dedupe
  ─► level ≥3: post now (+DM/pin if ≥4)   ─► everything: queue for digest
  ─► update pinned CURRENT LEVEL           ─► commit state/ back to the repo
08:00 / 20:00 Riga: the first run after each of these times also posts the digest of queued items
```

State (what has been seen, last advisory texts, pending digest items, subscribers) lives in `state/*.json`
and is committed back to the repo by the workflow — no database needed.

Safety rails: news/OSINT sources alone can never produce URGENT/CRITICAL (capped at 3 without corroboration);
official sources are never downgraded; the first run only baselines feeds instead of flooding the channel;
a source that fails three runs in a row is flagged in the digest.

## Setup

1. **Telegram**: bot `@ConflictMonitorLV_bot` (created with @BotFather) and the private channel *Conflict Monitor*.
   The bot must be an **administrator** of the channel with *Post messages*, *Edit messages* and *Pin messages*.
   Quickest way: open `https://t.me/ConflictMonitorLV_bot?startchannel&admin=post_messages+edit_messages+pin_messages`
   in the Telegram app and pick the channel.
2. **Secret**: in this repo → *Settings → Secrets and variables → Actions → New repository secret*:
   `TELEGRAM_BOT_TOKEN` = the token BotFather gave you.
   Optional: `ANTHROPIC_API_KEY` (AI summaries), `TELEGRAM_CHANNEL_ID` / `CHANNEL_INVITE_LINK` (override `config.yaml`).
3. **Test**: *Actions → Conflict Monitor → Run workflow → mode: test*. A test message with the scale appears in the channel.
4. From then on the schedule runs itself. Invite friends with the channel's invite link; anyone who also wants
   direct messages for level 4+ sends `/start` to the bot.

If the repo is **private**, GitHub's free minutes (2,000/month) comfortably cover the 30-minute schedule; a public
repo has unlimited minutes. GitHub pauses schedules in repos with no activity for 60 days — the state commits count as
activity, but if it ever pauses, re-enable it in the Actions tab.

### The GitHub cron is not reliable — add an external trigger

GitHub only *tries* to run the `schedule`; under load it delays or silently drops runs, and in practice this repo saw
about one run every 4–6 hours instead of every 30 minutes. The digest logic copes (a missed 08:00 digest is sent by the
next run, labelled "delayed"), but for genuine 30-minute polling let a free external cron service start the workflow
via `workflow_dispatch`:

1. GitHub → *Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token*:
   repository access = only `conflict-monitor`, permission **Actions: Read and write** (Metadata is added automatically),
   expiry as long as allowed. Copy the token — it is shown once.
2. On a cron service (e.g. https://cron-job.org, free) create a job every 30 minutes:
   * URL `https://api.github.com/repos/ugisio/conflict-monitor/actions/workflows/monitor.yml/dispatches`, method **POST**
   * headers `Authorization: Bearer <the token>`, `Accept: application/vnd.github+json`,
     `X-GitHub-Api-Version: 2022-11-28`, `Content-Type: application/json`
   * body `{"ref":"main","inputs":{"mode":"auto"}}`
   A `204 No Content` response means the run was queued. The GitHub cron stays as a backup; the `concurrency` group
   makes sure two runs never overlap.

The token can only start this repo's workflows — it cannot read the bot token or change code — so the blast radius
if the cron service leaked it is "someone runs the monitor more often".

## Local use

```bash
pip install -r requirements.txt
python -m monitor check        # fetch + classify, print what would be posted, send nothing
python -m monitor poll         # needs TELEGRAM_BOT_TOKEN in the environment
python -m pytest tests/        # offline tests (fixtures, no network)
```

## Tuning

- `region.core_keywords` — what counts as "about us" for news/OSINT posts (EN/RU/DE).
- `alerts.immediate_min_level`, `dm_min_level`, `digest_hours_local`, `overall_window_hours`.
- `monitor/classify.py` `RULES` — the severity regexes; add a line to catch a new kind of signal.
- Add a source: append to `sources` in `config.yaml` (`rss`, `telegram`, `html_text`, `html_links`, `fcdo`, `state_dept_advisory`, `polymarket`).
