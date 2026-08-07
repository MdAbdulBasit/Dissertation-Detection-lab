#!/usr/bin/env python3
"""
Build the labelled alert dataset from Wazuh alerts.json + data/detonation_log.csv.

WHY THIS EXISTS
    Hand-grepping alerts.log stopped working on 2026-08-06: ~1300 alerts for agent win-endpoint in a
    single session, output not window-scoped, and a REG_MULTI_SZ value containing null bytes (T1082
    test 30) made grep treat the file as binary and silently print nothing at all - indistinguishable
    from "no alerts found". This reads alerts.json, which is structured and null-safe.

WHAT IT DOES
    1. Loads every detonation window from data/detonation_log.csv, skipping rows marked SUPERSEDED.
    2. Applies the labelling rule from LABELLING_SCHEME.md:
           label = 1  IF  alert.timestamp in [window_start - 5s, window_end + 30s]  (both UTC)
                      AND alert.agent.name == 'win-endpoint'
           label = 0  OTHERWISE
    3. Applies the documented exclusion list (see LABELLING_SCHEME.md section 3) and records how many
       rows each filter removed, so the methodology can state it.
    4. Deduplicates the net.exe -> net1.exe pairing.
    5. Writes the labelled dataset and a per-technique / per-class / per-rule count summary that fills
       the alert-count columns in COVERAGE_TABLE.md.

USAGE
    Run on Blue, where alerts.json lives:
        sudo python3 export_labelled_alerts.py \
            --alerts /var/ossec/logs/alerts/alerts.json \
            --windows detonation_log.csv \
            --out-dataset labelled_alerts.csv \
            --out-summary alert_counts.csv

    Then copy the two small CSVs back to the repo from the host:
        scp basit@192.168.56.101:~/labelled_alerts.csv .
        scp basit@192.168.56.101:~/alert_counts.csv .

    Add --keep-net1 or --no-exclusions to measure how much the filtering decisions actually change the
    result. Reviewers ask; being able to answer with a number is worth the flag.
"""

import argparse
import csv
import glob
import gzip
import io
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

# =====================================================================================================
# HARNESS-ARTEFACT NORMALISATION
#
# Atomic Red Team invokes cmd.exe by BARE NAME; PowerShell resolves the full path however it is called
# (`& cmd.exe`, `Start-Process -FilePath 'cmd.exe'` - both tested 2026-08-06). So the recorded command
# lines differ in FORM even when the commands are identical:
#     attack:  "cmd.exe" /c systeminfo & reg query HKLM\...
#     benign:  "C:\Windows\system32\cmd.exe" /c systeminfo & hostname
# Wazuh then matches different rules on the same underlying event:
#     92052  Windows command prompt started by an abnormal process   (attack only, 67 obs.)
#     92004  Powershell process spawned Windows command shell instance (benign only, 25 obs.)
# Zero overlap, so BOTH rule ID and raw command line are perfect class discriminators - and both are
# artefacts of the emulation tool, not of behaviour.
#
# This cannot be engineered away from the benign side: the difference is intrinsic to how ART launches
# processes versus how PowerShell does. So normalise it out at feature-extraction time instead, and
# state it as a limitation. Two derived columns are emitted:
#     command_line_normalised - absolute .exe paths reduced to basenames
#     rule_canonical          - rules describing the same event collapsed to one identifier
# Train on the normalised columns. Retaining the raw ones lets you quantify how much the artefact was
# worth, which is a robustness check worth reporting.
# =====================================================================================================

_ABS_EXE = re.compile(r'[A-Za-z]:\\(?:[^\\"\s]+\\)*([^\\"\s]+\.exe)', re.I)


def normalise_cmdline(s):
    if not s:
        return ""
    t = s.replace("\\\\", "\\")            # Wazuh double-escapes backslashes in JSON
    return _ABS_EXE.sub(lambda m: m.group(1).lower(), t)


# Rules that fire on the same underlying event but differ only by how the parent was expressed.
# Both are "cmd.exe created by a non-cmd, non-explorer parent" - see 0800-sysmon_id_1.xml.
RULE_CANONICAL = {
    "92052": "cmd-spawned-by-nonshell-parent",
    "92004": "cmd-spawned-by-nonshell-parent",
}

# From LABELLING_SCHEME.md. The buffer absorbs Sysmon -> agent -> manager forwarding lag, not clock
# skew (skew is ~0 when chrony is actually synced - verify with chronyc tracking, not timedatectl).
#
# ⚠️ POST_BUFFER WAS 30s AND THAT WAS FAR TOO SMALL. Measured on 2026-08-06 across 330 alerts falling
# within 300s of a window_end:
#     p50 15.3s | p75 35.6s | p90 58.1s | p95 70.2s | p99 111.0s | max 168.5s
# At 30s, 96 of 330 alerts (29%) fell outside their own window and were labelled 0 - so real attack and
# benign-mirror activity was being silently moved into the negative class, under-counting both classes
# and poisoning the negatives. Whole windows produced "zero alerts" (T1087.001 attack r1, benign r2-r5)
# purely because their alerts arrived 35-79s late.
#
# 120s covers the measured p99. The lag is driven by Wazuh agent event batching and is load-dependent -
# it was worst when the endpoint had ~331 MB free RAM of 3 GB - so RE-MEASURE each session with
# --lag-report rather than trusting this constant.
#
# CONSTRAINT: the inter-run gap in Invoke-LabRun.ps1 must EXCEED this buffer, or consecutive windows
# overlap and contaminate each other's classes. Gap defaults were raised to 180-300s to match.
PRE_BUFFER = timedelta(seconds=5)
POST_BUFFER = timedelta(seconds=120)

TARGET_AGENT = "win-endpoint"

# Rule groups rather than ID ranges: more robust across Wazuh ruleset updates.
EXCLUDED_GROUPS = {
    "vulnerability-detector",  # CVE inventory (~360 alerts on 2026-08-06), not behavioural detection
    "sca",                     # CIS policy findings (~350), not behavioural detection
}

# PowerShell writes this file every time it evaluates execution policy for a script, so the harness
# itself generates it on every invocation. Accounted for ~300 alerts across rules 92217, 92213, 92201,
# 92200 and 92021 - including 92213 at level 15, the highest-severity alert in the entire dataset.
HARNESS_FILE_MARKER = "__PSScriptPolicyTest"

# The Wazuh agent's own SCA module runs `net user` and `powershell secedit /export`. Command lines are
# identical to the atomics', so discriminate on process lineage instead.
SELF_MONITORING_IMAGES = {"secedit.exe"}
SELF_MONITORING_PARENTS = {"wazuh-agent.exe"}


# =====================================================================================================
# ⚠️ alerts.json ROTATES DAILY. Wazuh moves the previous day's alerts into
#     /var/ossec/logs/alerts/<YYYY>/<Mmm>/ossec-alerts-<DD>.json[.gz]
# and starts a fresh alerts.json. Reading only the live file therefore silently loses every earlier
# session: on 2026-08-07 an export covering 40 detonation windows returned alerts for ONE technique,
# because T1082's and T1087.001's alerts from the previous day had already been archived. The windows
# were all still present, so the output looked like "those techniques produced no alerts".
#
# --alerts accepts multiple paths and shell globs, and .gz archives are read transparently. Always pass
# the archive directory as well as the live file when re-exporting across sessions.
# =====================================================================================================

def iter_alert_files(patterns):
    """Expand globs, de-duplicate, and return files sorted oldest-first by name."""
    seen, out = set(), []
    for pat in patterns:
        matches = sorted(glob.glob(pat)) or ([pat] if "*" not in pat else [])
        for p in matches:
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def open_alert_file(path):
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def parse_alert_ts(raw):
    """Wazuh writes e.g. 2026-08-06T06:43:50.123+0000."""
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        pass
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def parse_window_ts(raw):
    """detonation_log.csv stores naive UTC: 2026-08-06 06:43:44."""
    return datetime.strptime(raw.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def load_windows(path):
    windows, skipped = [], 0
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            if not row.get("window_start") or not row.get("window_end"):
                continue
            # Superseded rows have no usable telemetry behind them (clock fault, dead pipeline,
            # contaminated mirror). Including them would resurrect known-bad data.
            if "SUPERSEDED" in (row.get("notes") or "").upper():
                skipped += 1
                continue
            try:
                start = parse_window_ts(row["window_start"])
                end = parse_window_ts(row["window_end"])
            except ValueError:
                skipped += 1
                continue
            windows.append({
                "session_id": row.get("session_id", ""),
                "type": (row.get("type") or "").strip().lower(),
                "technique_id": (row.get("technique_id") or "").strip(),
                # 'baseline' = the technique's own custom rules were NOT yet deployed, so these windows
                # measure DEFAULT detection. 'custom' = deployed, measuring detection after engineering.
                # Both halves of the COVERAGE_TABLE.md row need their own counts, so never merge them.
                "ruleset_phase": (row.get("ruleset_phase") or "custom").strip().lower(),
                "label_from": start - PRE_BUFFER,
                "label_to": end + POST_BUFFER,
                "start": start,
                "end": end,
            })
    return windows, skipped


def dig(d, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def basename_lower(p):
    if not p:
        return ""
    return p.replace("/", "\\").split("\\")[-1].lower()


def classify_exclusion(alert):
    """Return a reason string if this alert should be dropped, else None."""
    groups = set(dig(alert, "rule", "groups", default=[]) or [])
    hit = groups & EXCLUDED_GROUPS
    if hit:
        return f"group:{sorted(hit)[0]}"

    eventdata = dig(alert, "data", "win", "eventdata", default={}) or {}

    target = eventdata.get("targetFilename") or ""
    if HARNESS_FILE_MARKER.lower() in target.lower():
        return "harness:PSScriptPolicyTest"

    # Deletion of those same files (rule 92021) carries the path in a different field depending on
    # the Sysmon event, so check the raw message too.
    full_log = alert.get("full_log") or ""
    if HARNESS_FILE_MARKER.lower() in full_log.lower():
        return "harness:PSScriptPolicyTest"

    image = basename_lower(eventdata.get("image"))
    parent = basename_lower(eventdata.get("parentImage"))
    if image in SELF_MONITORING_IMAGES or parent in SELF_MONITORING_PARENTS:
        return "self-monitoring:wazuh-agent/SCA"

    return None


def report_lag(alerts_path, windows):
    """Measure Sysmon -> agent -> manager forwarding lag, which sets the correct POST_BUFFER.

    For each alert, attribute it to the most recent window whose start precedes it, then measure how
    long after that window_end the alert actually arrived. Load-dependent, so re-run every session.
    """
    wins = sorted((w["start"], w["end"], w["session_id"]) for w in windows)
    lags = []
    with open(alerts_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if dig(alert, "agent", "name") != TARGET_AGENT:
                continue
            ts = parse_alert_ts(alert.get("timestamp"))
            if ts is None:
                continue
            prior = [w for w in wins if w[0] - PRE_BUFFER <= ts]
            if not prior:
                continue
            lag = (ts - prior[-1][1]).total_seconds()
            if -10 <= lag <= 300:
                lags.append(lag)

    if not lags:
        print("No alerts fell within 300s of any window - cannot measure lag.")
        return
    lags.sort()
    print(f"Forwarding-lag distribution over {len(lags)} alerts within 300s of a window_end:")
    for p in (50, 75, 90, 95, 99):
        print(f"  p{p:<3d} {lags[min(int(len(lags) * p / 100), len(lags) - 1)]:7.1f}s")
    print(f"  max  {lags[-1]:7.1f}s")
    rec = int(lags[min(int(len(lags) * 0.99), len(lags) - 1)]) + 10
    print(f"\nRecommended --post-buffer: {rec}s (measured p99 + 10s margin)")
    print(f"Inter-run gap in Invoke-LabRun.ps1 must EXCEED that, or windows overlap:"
          f" set -MinGapSeconds to at least {rec + 60}.")
    for cut in (30, 60, 120, 180):
        n = sum(1 for l in lags if l > cut)
        print(f"  at a +{cut}s buffer, {n} of {len(lags)} alerts ({100*n/len(lags):.0f}%) fall outside their window")


def main():
    global POST_BUFFER          # must precede any reference to it in this function
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", nargs="+",
                    default=["/var/ossec/logs/alerts/alerts.json",
                             "/var/ossec/logs/alerts/*/*/ossec-alerts-*.json",
                             "/var/ossec/logs/alerts/*/*/ossec-alerts-*.json.gz"],
                    help="One or more alert files or globs. Defaults to the live alerts.json PLUS the "
                         "rotated archives - alerts.json rotates daily, so the live file alone loses "
                         "every earlier session.")
    ap.add_argument("--windows", default="detonation_log.csv")
    ap.add_argument("--out-dataset", default="labelled_alerts.csv")
    ap.add_argument("--out-summary", default="alert_counts.csv")
    ap.add_argument("--keep-net1", action="store_true",
                    help="Keep net1.exe alerts. net.exe spawns net1.exe with identical arguments, so "
                         "every net command yields two alerts and counts are inflated 2x.")
    ap.add_argument("--no-exclusions", action="store_true",
                    help="Skip the documented exclusion list, to quantify its effect.")
    ap.add_argument("--post-buffer", type=int, default=int(POST_BUFFER.total_seconds()),
                    help="Seconds after window_end still counted as in-window. Default is the measured "
                         "p99 forwarding lag. Vary it to report label sensitivity.")
    ap.add_argument("--lag-report", action="store_true",
                    help="Measure and print the forwarding-lag distribution, then exit. Run this every "
                         "session - the lag is load-dependent and sets the correct buffer.")
    args = ap.parse_args()

    POST_BUFFER = timedelta(seconds=args.post_buffer)

    windows, skipped_windows = load_windows(args.windows)
    if not windows:
        sys.exit(f"No usable windows in {args.windows} (skipped {skipped_windows} superseded/invalid).")

    if args.lag_report:
        report_lag(args.alerts, windows)
        return

    print(f"Loaded {len(windows)} usable windows ({skipped_windows} skipped as superseded/invalid)")
    print(f"Label buffer: -{PRE_BUFFER.total_seconds():.0f}s / +{POST_BUFFER.total_seconds():.0f}s")
    for tech in sorted({w['technique_id'] for w in windows}):
        atk = sum(1 for w in windows if w['technique_id'] == tech and w['type'] == 'attack')
        ben = sum(1 for w in windows if w['technique_id'] == tech and w['type'] == 'benign')
        print(f"  {tech}: {atk} attack, {ben} benign")

    total = wrong_agent = unparsable = 0
    excluded = Counter()
    net1_dropped = 0
    # Wazuh's live alerts.json and the rotated archive can BOTH contain the same day's alerts, so
    # globbing the archive directory alongside the live file double-counts. Observed 2026-08-07:
    # T1033 baseline read 330 attack alerts instead of 165, exactly 2x, while older techniques whose
    # archives exist in only one form were unaffected - so the inflation was silent and technique-
    # specific. Deduplicate on the alert's own unique id rather than trusting the file set.
    seen_ids = set()
    dup_dropped = 0
    rows = []
    # (technique, class, rule_id) -> count ; class is 'attack' / 'benign' / 'unlabelled'
    summary = defaultdict(Counter)

    alert_files = iter_alert_files(args.alerts)
    if not alert_files:
        sys.exit(f"No alert files matched: {args.alerts}")
    print(f"\nReading {len(alert_files)} alert file(s):")
    for p in alert_files:
        print(f"  {p}")

    for path in alert_files:
      with open_alert_file(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                unparsable += 1
                continue

            total += 1

            # Alert id is unique per alert (e.g. "1785998198.5644897"). Fall back to a composite key
            # if it is ever absent.
            aid = alert.get("id") or (
                f"{alert.get('timestamp','')}|{dig(alert,'rule','id',default='')}|{alert.get('full_log','')[:200]}"
            )
            if aid in seen_ids:
                dup_dropped += 1
                continue
            seen_ids.add(aid)

            if dig(alert, "agent", "name") != TARGET_AGENT:
                wrong_agent += 1
                continue

            ts = parse_alert_ts(alert.get("timestamp"))
            if ts is None:
                unparsable += 1
                continue

            if not args.no_exclusions:
                reason = classify_exclusion(alert)
                if reason:
                    excluded[reason] += 1
                    continue

            eventdata = dig(alert, "data", "win", "eventdata", default={}) or {}
            image = basename_lower(eventdata.get("image"))
            if not args.keep_net1 and image == "net1.exe":
                net1_dropped += 1
                continue

            match = next((w for w in windows if w["label_from"] <= ts <= w["label_to"]), None)

            rule_id = dig(alert, "rule", "id", default="")
            mitre = dig(alert, "rule", "mitre", "id", default=[]) or []

            rows.append({
                "timestamp": alert.get("timestamp", ""),
                "label": 1 if match else 0,
                "class": match["type"] if match else "unlabelled",
                "technique_id": match["technique_id"] if match else "",
                "ruleset_phase": match["ruleset_phase"] if match else "",
                "session_id": match["session_id"] if match else "",
                "rule_id": rule_id,
                "rule_canonical": RULE_CANONICAL.get(str(rule_id), str(rule_id)),
                "rule_level": dig(alert, "rule", "level", default=""),
                "rule_description": dig(alert, "rule", "description", default=""),
                "rule_mitre": ";".join(mitre),
                "image": eventdata.get("image", ""),
                "parent_image": eventdata.get("parentImage", ""),
                "command_line": eventdata.get("commandLine", ""),
                "command_line_normalised": normalise_cmdline(eventdata.get("commandLine", "")),
                "target_filename": eventdata.get("targetFilename", ""),
            })

            key = (match["technique_id"] if match else "-",
                   match["ruleset_phase"] if match else "-",
                   match["type"] if match else "unlabelled")
            summary[key][rule_id] += 1

    with open(args.out_dataset, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["timestamp"])
        w.writeheader()
        w.writerows(rows)

    with open(args.out_summary, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["technique_id", "ruleset_phase", "class", "rule_id", "count"])
        for (tech, phase, cls) in sorted(summary):
            for rule_id, n in summary[(tech, phase, cls)].most_common():
                w.writerow([tech, phase, cls, rule_id, n])

    print(f"\nRead {total} alerts; {dup_dropped} duplicates across files, "
          f"{wrong_agent} from other agents, {unparsable} unparsable")
    if dup_dropped:
        print(f"  (the live alerts.json and a rotated archive overlap - deduplicated on alert id)")
    if excluded:
        print("\nExcluded by documented filters:")
        for reason, n in excluded.most_common():
            print(f"  {n:6d}  {reason}")
        print(f"  {sum(excluded.values()):6d}  TOTAL EXCLUDED")
    if net1_dropped:
        print(f"  {net1_dropped:6d}  net1.exe duplicates (net.exe spawns it with identical arguments)")

    labelled = sum(1 for r in rows if r["label"] == 1)
    print(f"\nKept {len(rows)} alerts: {labelled} labelled 1 (in a window), {len(rows) - labelled} labelled 0")

    print("\nPer-technique counts for COVERAGE_TABLE.md (attack / benign), split by ruleset phase:")
    print("  baseline = custom rules NOT deployed -> the 'Default detected?' column")
    print("  custom   = custom rules deployed     -> the 'Detected after?' column")
    techs = sorted({t for (t, p, c) in summary if t != "-"})
    for tech in techs:
        for phase in ("baseline", "custom"):
            atk = sum(summary[(tech, phase, "attack")].values())
            ben = sum(summary[(tech, phase, "benign")].values())
            if not (atk or ben):
                continue
            print(f"  {tech} [{phase}]: {atk} / {ben}")
            for cls in ("attack", "benign"):
                if summary[(tech, phase, cls)]:
                    top = ", ".join(f"{rid}x{n}" for rid, n in summary[(tech, phase, cls)].most_common(8))
                    print(f"      {cls:7s}: {top}")

    # A rule appearing in only ONE class is a candidate harness artefact, not a detection. This is the
    # check that caught the cmd.exe lineage problem; run it after every batch.
    print("\nClass-exclusive rules per phase (candidate harness artefacts):")
    flagged = False
    for tech in techs:
        for phase in ("baseline", "custom"):
            atk_rules = set(summary[(tech, phase, "attack")])
            ben_rules = set(summary[(tech, phase, "benign")])
            if not (atk_rules or ben_rules):
                continue
            only_atk, only_ben = atk_rules - ben_rules, ben_rules - atk_rules
            shared = atk_rules & ben_rules
            print(f"  {tech} [{phase}]: {len(shared)} shared, {len(only_atk)} attack-only, {len(only_ben)} benign-only")
            if shared:
                print(f"      shared      : {sorted(shared)}")
            if only_atk:
                print(f"      attack-only : {sorted(only_atk)}")
            if only_ben:
                print(f"      benign-only : {sorted(only_ben)}")
            if only_atk and only_ben:
                flagged = True
    if flagged:
        print("\n  ⚠️  Rules exclusive to each class exist. If they describe the same underlying event"
              "\n      (check the rule XML), add them to RULE_CANONICAL and train on rule_canonical +"
              "\n      command_line_normalised rather than the raw columns.")

    if labelled == 0:
        print("\n*** ZERO alerts fell inside any window. Do not treat this as a detection failure. ***")
        print("    Check, in order: (1) chronyc tracking on Blue - System time within a few ms and")
        print("    Leap status Normal; (2) agent name is exactly 'win-endpoint' - agent-auth without")
        print("    -A enrols under the hostname instead; (3) the pipeline proof in")
        print("    PREFLIGHT_CHECKLIST.md 6a. All three have caused exactly this symptom.")


if __name__ == "__main__":
    main()
