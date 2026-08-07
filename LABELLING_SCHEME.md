# GROUND-TRUTH LABELLING SCHEME

Resolves a conflict between the two lab handovers. Fix this **before** data collection — relabelling
after the fact is not reliably possible.

## The conflict

| Source | Definition |
|--------|------------|
| `LAB_HANDOVER_PHASE2.md` §7c | `ground_truth_label` = attack-generated (1) vs benign (0) |
| Lab-session handover §8.5 | labels = true-positive vs false-positive |

These are not the same thing. The first labels the **event's origin**; the second labels the **rule's
correctness**. They happen to agree on the obvious cases and diverge on the ones that matter.

## Decision: label on provenance, derive TP/FP from it

`ground_truth_label` records **what caused the event**, not whether the rule was right:

- **1** — the event was produced by an atomic test I deliberately executed
- **0** — the event was produced by anything else

This is the operative definition because provenance is *objectively knowable* — the detonation log
records exactly which atomic ran and when. "Was this rule correct?" is a judgement call and would make
the target variable subjective, which is fatal for a supervised model.

True/false positive then falls out as a **derived interpretation**, not a separate label:

| Alert fired | `ground_truth_label` | Interpretation |
|-------------|---------------------|----------------|
| Yes | 1 | True positive |
| Yes | 0 | **False positive** |
| No (no alert) | 1 | False negative — counts toward coverage, not in the alert CSV |
| No (no alert) | 0 | True negative — not in the alert CSV |

Note the last two rows: a false negative produces **no row** in the alert dataset. Coverage
(did the rule fire at all?) is measured in the coverage table, not the CSV. Keep the two separate —
conflating them is a common way to accidentally overstate recall.

## Mechanism: detonation windows

Provenance is established by timestamp, so every atomic execution must be bracketed and logged.

### ⚠️ Record windows in UTC — verified 2026-08-05

The two VMs run different clocks, and this would silently invalidate the entire dataset if ignored.

| Machine | Timezone | Writes timestamps as |
|---------|----------|----------------------|
| Blue (Wazuh manager) | `Etc/UTC` (+0000), NTP synced | `2026-08-05T23:09:31.370+0000` — **UTC**, explicit offset |
| Windows endpoint | `GMT Standard Time`, DST active in August | **Local = UTC+1** |

**Measured skew after correcting for timezone: ~0 seconds** (as at 2026-08-05).

> ⚠️ **This does not hold automatically — re-measure every session.** On 2026-08-06 Blue was found ~4 h
> behind true UTC because `systemd-timesyncd` was running but had never synced
> (`System clock synchronized: no`). The timezone was still correctly `Etc/UTC`, so a timezone-only
> check passes while absolute time is badly wrong. Verify the `synchronized:` line in `timedatectl`,
> not just the zone — see PREFLIGHT_CHECKLIST.md §8. With Blue's clock wrong, windows recorded from
> Windows match no alerts at all and the positive class silently empties.

That makes this a labelling hazard rather than a clock problem. `Get-Date` on Windows returns 00:04
while Wazuh records the same instant as 23:04. Every detonation window recorded in Windows local time
would sit one hour *after* its own alerts, so **every attack alert would be labelled 0** — the positive
class would come out empty, with no error raised. The failure is silent and only shows up as
inexplicable model metrics after all 15 techniques are done.

**Therefore: always record windows in UTC.**

```powershell
(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")   # window_start (UTC)
Invoke-AtomicTest T1059.001 -TestNumbers 1
(Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")   # window_end (UTC)
```

Do **not** use bare `Get-Date`. Append the UTC values to `data/detonation_log.csv`; the column is named
`window_start` / `window_end` and is UTC by definition.

Labelling rule applied at export time:

```
label = 1  IF  alert.timestamp ∈ [window_start − 5s, window_end + 120s]    (both UTC)
           AND alert.agent == 'win-endpoint'
label = 0  OTHERWISE
```

> ⚠️ **The post-buffer was +30s until 2026-08-06 and that was badly wrong.** Measured over 330 alerts
> arriving within 300s of a `window_end`:
>
> | p50 | p75 | p90 | p95 | p99 | max |
> |-----|-----|-----|-----|-----|-----|
> | 15.3s | 35.6s | 58.1s | 70.2s | **111.0s** | **168.5s** |
>
> At +30s, **96 of 330 alerts (29%) fell outside their own window and were labelled 0** — real attack
> and benign-mirror activity was being moved into the negative class, simultaneously under-counting the
> positives and poisoning the negatives. Entire windows appeared to produce *zero* alerts (T1087.001
> attack r1 and benign r2–r5) purely because their alerts arrived 35–79s late. Nothing in the pipeline
> errored; the counts were just quietly wrong.
>
> **The lag is Wazuh agent event batching, and it is load-dependent** — worst when the endpoint had
> ~331 MB free of 3 GB. So it is not a constant to be trusted:
>
> ```bash
> sudo python3 export_labelled_alerts.py --alerts /var/ossec/logs/alerts/alerts.json \
>     --windows detonation_log.csv --lag-report
> ```
>
> Run that **every session** and set `--post-buffer` from the measured p99. Report label sensitivity by
> re-running the export at several buffer values — if the conclusions move, say so.
>
> **Coupled constraint:** the inter-run gap must exceed the buffer, or consecutive windows overlap and
> contaminate each other. `Invoke-LabRun.ps1` gap defaults were raised from 60–120s to **180–300s** to
> match, and it now warns below 150s.
>
> ### Gap reduced to 45–90s from T1016 onward — deliberate, and here is the reasoning
>
> The 180–300s gaps cost ~20 minutes per 5-repeat run, roughly 80 minutes per technique across both
> phases. From **T1016** the gaps are **45–90s**, which is *below* the 120s buffer. That is a considered
> trade-off, not an oversight:
>
> - **Between repeats of the same class it is harmless.** Both runs carry the same class label, so a late
>   alert from run 1 landing in run 2's range is still labelled correctly. Only *per-window* attribution
>   blurs, and per-window counts serve only as a sanity check — the coverage table uses class totals.
> - **It actually loses fewer alerts.** With a gap wider than the buffer there is a dead zone between
>   windows where late alerts match nothing and are labelled 0. Narrower gaps absorb them into the next
>   window of the same class instead.
> - **Between the attack run and the benign run it would be fatal**, since attack's late alerts would be
>   labelled benign. That boundary stays wide: the two are separate invocations with operator time
>   between them, and must never be less than ~3 minutes apart.
>
> ⚠️ **Gaps must match within a technique.** A phase run at 45–90s captures a higher proportion of its own
> late alerts than one run at 180–300s, so mixing them inflates the later phase for reasons unrelated to
> the rules. T1087.001, T1082 and T1033 were all captured at 180–300s in both phases; T1016 onward uses
> 45–90s in both phases. **Do not compare totals across that boundary** — compare within a technique.
>
> **This is why the pipeline is worth building before the dataset.** The fault was invisible in the
> lab — services healthy, clock synced, rules firing — and only appeared as "some windows have no
> alerts" once counts were computed programmatically. Discovered on technique 2 of 15, it cost one
> re-export. Discovered after fifteen, it would have invalidated the entire dataset.

The ±buffer absorbs Sysmon → agent → manager forwarding lag, not clock skew (skew is ~0). Re-verify the
timezone relationship at the start of each session — a VM snapshot revert or a DST transition can change
it, and the UK leaves BST in late October, before the September deadline but worth knowing if work runs on.

---

## Known false-positive sources — handle explicitly at export time

These fire inside detonation windows but are **not** caused by the emulated technique. Each must be
either excluded or flagged, and the decision stated in the methodology.

### 1. Rule 92213 (level 15) — PowerShell execution-policy test files ⚠️ harness-induced

Confirmed 2026-08-06. Every observed 92213 alert is a Sysmon EID 11 (FileCreate) for
`C:\Users\<user>\AppData\Local\Temp\__PSScriptPolicyTest_<random>.ps1`, image
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. PowerShell writes this file every time it
evaluates execution policy for a script, so **`Invoke-LabRun.ps1` generates it on every invocation** —
it is an artefact of how the lab measures, not of what it measures.

Why this matters more than a normal FP:

- **Level 15 is the maximum.** It will dominate any severity-weighted metric, ranking, or triage
  ordering unless removed.
- **It contaminates both classes equally**, since attack and benign runs use the same
  `powershell.exe -File` invocation. So it is not class-separating — but it inflates volume in both and
  will make a count-based model look better calibrated than it is.
- **Filter on `targetFilename` containing `__PSScriptPolicyTest`**, not on rule 92213 wholesale — 92213
  is a legitimate rule (mapped to T1105) and genuine hits should survive.

The rule's own regex confirms the mechanism — it matches any of `exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|
msi|vbe` under `\Users\...\AppData\Local\Temp\`, and PowerShell's policy-test file is a `.ps1` in exactly
that directory:
```xml
<rule id="92213" level="15">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)[c-z]:\\Users\\.+\\AppData\\Local\\Temp\\.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|msi|vbe)</field>
```

It is also a real finding in its own right: a maximum-severity default rule firing continuously on
benign interpreter behaviour is exactly the alert-fatigue problem the triage layer exists to address.
Report it as evidence, then exclude it from the dataset.

### 1a. Rule 92213 again — `Add-Type` / `csc.exe` inline C# compilation ⚠️ largest artefact found

Found on T1059.001, 2026-08-07, and bigger than the PSScriptPolicyTest case. `AtomicTestHarnesses` calls
`Add-Type`, which compiles inline C#:

| Creator | Target file | Alerts |
|---------|-------------|--------|
| `powershell.exe` | `…\AppData\Local\Temp\<rand>\<rand>.dll` | 280 |
| `csc.exe` | `…\AppData\Local\Temp\<rand>\<rand>.cmdline` | 140 |

Both trip rule **92213 at level 15**. That was **420 of 481 attack alerts — 87% of the class — against
zero in benign**, because the mirror does not use the harness. A perfect class discriminator manufactured
entirely by the test tooling.

Filter on the compiler's two-level temp scratch pattern, **not** on `csc.exe` generally:

```
\\AppData\\Local\\Temp\\[^\\]+\\[^\\]+\.(dll|cmdline|pdb|err|out|cs|tmp)$
```

> ⚠️ **`csc.exe` compilation is also a real adversary behaviour** — T1027.004 Compile After Delivery. In
> this lab every such event is harness-driven, but an evaluation of T1027.004 would need this exclusion
> removed and re-justified.

> ⚠️ **Collapse Wazuh's doubled backslashes before matching any path.** The field arrives as
> `C:\\Users\\…\\Temp\\x\\y.dll`. The first version of this filter used single separators, matched
> nothing, and reported an exclusion count of **zero** — no error, no warning, 420 harness alerts left in
> the dataset. Caught only by re-checking whether rule 92213 had actually disappeared. **Verify the
> outcome of a filter, never that it ran.**

### 1b. WMI process lineage — rules 92070 / 92071

`AtomicTestHarnesses` launches PowerShell **via WMI** so it can control the exact command line. Rules
`92070` ("WMI created a powershell process") and `92071` ("a powershell process created by WMI executed a
base64 encoded command") therefore fire only in the attack class and can never match a mirror that
spawns directly. Both also map to **T1047 + T1059.001**, so they arguably describe a different technique.
Exclude from separability claims; do not widen the mirror to chase them.

### 2. Rule 92031 / 100200 — Wazuh agent's own SCA module

The agent's SCA module runs `net user` and `powershell secedit /export` on a schedule, under parent
`wazuh-agent.exe` / `SecEdit.exe`. Confirmed firing 2026-08-06 at 06:38:53. Discriminate on parent
process, not command line — the command line is identical to the atomic's.

### 3. Full noise inventory measured 2026-08-06 — the alert-fatigue result

Per-rule totals for agent `win-endpoint` across the whole day (**not** window-scoped — indicative of
composition, not of any single detonation). Ranked:

| Rule | Level | Count | Description | Cause |
|------|-------|-------|-------------|-------|
| 92217 | 6 | 143 | Executable dropped in Windows root folder | PowerShell policy test in `C:\Windows\Temp` |
| 92213 | 15 | 102 | Executable file dropped in folder commonly used by malware | PowerShell policy test in `AppData\Local\Temp` |
| 92032 | 3 | 79 | Suspicious Windows cmd shell execution | atomics (mapped T1087 + T1059.003) |
| 92052 | 4 | 69 | Windows command prompt started by an abnormal process | atomics (T1059.003) |
| 100200 | 10 | 46 | T1087.001 Local Account Discovery via net.exe | custom rule — genuine |
| 92021 | 3 | 23 | Powershell was used to delete files or directories | PowerShell cleaning up its own policy test files |
| 92201 | 9 | 23 | powershell.exe created a scripting file under Temp/User data | PowerShell policy test |
| 92066 | 4 | 19 | SecEdit.exe launched by powershell.exe | **Wazuh's own SCA module** |
| 92200 | 6 | 9 | Scripting file created under Windows Temp or User folder | PowerShell policy test |
| 92027 | 4 | 7 | Powershell process spawned powershell instance | harness invocation |
| 92219 | 6 | 16 | Possible DLL search order hijack | Windows Update files in `SoftwareDistribution` |
| 92307 | 3 | ~40 | Evidence of new service creation in registry | boot-time service enumeration |
| 23503–23506 | 5–13 | ~360 | `CVE-xxxx affects Microsoft Windows 10 Pro` | Vulnerability Detector inventory after re-enrolment |
| 19007–19014 | 3–9 | ~350 | CIS benchmark findings | SCA policy scan after re-enrolment |
| 92033 | 3 | **1** | **Discovery activity spawned via powershell execution** | the only discovery-named default rule — fired **once** |

**What this establishes.** Roughly **300 alerts trace to PowerShell's execution-policy test files alone**
(rules 92217, 92213, 92201, 92200, 92021 — creation *and* deletion), and a further ~730 to the Wazuh
agent's own SCA and vulnerability scans triggered by agent re-enrolment. Against that, the entire set of
alerts plausibly related to the emulated techniques is roughly 200 — and the only default rule whose
description mentions **discovery** fired exactly **once** across every run of the day.

So the noise is not incidental; it is the overwhelming majority, it includes the single highest-severity
alert (92213 at level 15), and most of it originates in the monitoring stack and the interpreter rather
than in anything an attacker did. **This is the alert-fatigue problem quantified on real data, and it is
the empirical justification for the ML triage layer.** Present the table as a finding.

**Exclusion list for the labelled dataset** — apply all of these before training:

1. `targetFilename` contains `__PSScriptPolicyTest` → drop (rules 92217, 92213, 92201, 92200, 92021).
2. `rule.id` in 23503–23506 → drop. Vulnerability inventory, not behavioural detection.
3. `rule.id` in 19007–19014 → drop. SCA policy findings, not behavioural detection.
4. Parent process `wazuh-agent.exe` or image `SecEdit.exe` under a `powershell.exe` parent → drop
   (rule 92066 and the SCA `net user` case).
5. `rule.id` 92307 and 92219 → review; both were boot/Windows-Update artefacts here.

Document every exclusion and its rationale in the methodology. An unexplained filter looks like
cherry-picking; a measured, justified one is a contribution.

> ⚠️ **Do not derive these counts with `grep` on `alerts.log`.** At this volume the output is unusable by
> hand, is not window-scoped, and silently breaks on null bytes. Extract from `alerts.json` or the
> indexer, join to `data/detonation_log.csv` on the window columns, and apply the labelling rule
> programmatically.

### 3a. ⚠️ Multi-technique atomics break window-based labelling — found on T1016, 2026-08-07

Window labelling assigns **every** alert inside a detonation window to **one** technique. That is only
valid if the atomics in that window exercise only that technique. **Malware-emulation atomics do not.**

Measured on T1016 with tests 1, 2, 4, 7, 9. Tests 4 (**TrickBot Style**) and 7 (**Qakbot Recon**) are
realistic recon *sequences*, and the process images prove it:

| Image | Count | Actual technique |
|-------|-------|------------------|
| `net.exe` | 30 | T1087 / T1135 depending on subcommand |
| `whoami.exe` | 5 | **T1033** |
| `nltest.exe` | 5 | **T1482** Domain Trust Discovery |
| `ipconfig`, `arp`, `route`, `netstat`, `nbtstat`, `nslookup` | 55 | T1016 — the actual target |

Consequently the custom rules fired **correctly** and looked wrong: `100200` matched `net user` as
T1087.001 and `100240` matched `whoami` as T1033, both inside a window labelled T1016. Default rules did
the same — `92034`/`92035` mapped `net view` to T1135, which is right for that command.

**This is not a detection failure and must not be recorded as one.** It is an artefact of attributing a
multi-technique test sequence to a single technique.

**Rule adopted:** for per-technique precision measurement, use atomics that exercise **only** the target
technique. Malware-emulation sequences are excluded from per-technique rows and are better suited to a
separate chained-attack evaluation, where multi-technique attribution is the point rather than a
confound. Record every such exclusion — a reviewer will ask why TrickBot and Qakbot were dropped, and
"they span five techniques so the row would be uninterpretable" is a good answer.

**Check for it on every technique:** if the attack class fires a *previous* technique's custom rule, the
atomic almost certainly spans techniques. That signal is now visible in the export's class-exclusive
listing.

### 3b. Execution techniques are structurally multi-technique — and no test selection fixes it

Found on T1059.003, 2026-08-07, after a re-run that failed to fix the problem.

The T1059.003 baseline fired custom rule `100240` (T1033 `whoami`) five times, with images
`cmd.exe` 30, `calc.exe` 5, `wscript.exe` 5, `whoami.exe` 5. Diagnosing this as one bad atomic —
test 3, "Suspicious Execution via Windows Command Shell" — the test set was narrowed to 1, 2, 5, 6 and
re-run. **The contamination was identical** (44 → 45 alerts, same images, same `100240` count). The
diagnosis was wrong.

**The actual cause is that T1059.003 is a container technique.** "Windows Command Shell" means *executing
commands through cmd.exe* — but a command shell has to execute *something*, and whatever it executes has
its own ATT&CK mapping. The atomics write batch and VBScript files whose payloads are `whoami` (T1033),
`calc.exe`, and `wscript` running a `.vbs` (T1059.005, a sibling sub-technique). There is no test
selection that avoids this, because a test that executes nothing would not exercise the technique.

**This is a real distinction between technique families, not a lab defect:**

| Family | Atomics are | Per-technique attribution |
|--------|-------------|---------------------------|
| **Discovery** (T1082, T1033, T1016, T1087.001) | self-contained — the discovery command *is* the technique | Clean, achievable with test selection |
| **Execution** (T1059.001, T1059.003) | containers — the payload belongs to another technique | **Structurally impossible** to isolate |

**Consequences to apply and to state in the methodology:**

1. For Execution techniques, window labels identify *the technique under test*, not every alert in the
   window. Sibling-technique alerts inside the window are **correctly detected behaviour**, not errors —
   `100240` firing on the payload's `whoami` is the rule working.
2. Report Execution-technique alert counts **split by whether the alert maps to the technique under test**,
   rather than as a single total.
3. Do **not** re-run to chase this. One re-run was spent on a wrong diagnosis; the T1016 precedent does not
   transfer, because there the contamination came from *optional* malware-emulation atomics that could
   simply be dropped.
4. The `rule_mitre` column already carries what is needed to separate them at analysis time.

### 4. `net.exe` → `net1.exe` duplication

Every `net` command produces two process-creation events and therefore two alerts. Deduplicate before
counting anything or building count-based features. See `COVERAGE_TABLE.md` T1087.001.

**Sanity check before trusting any export:** take one known detonation, find its alerts, and confirm the
timestamps fall inside the recorded window. If they are exactly one hour out, a local-time value was
recorded by mistake.

## Edge cases — decide once, apply consistently

| Case | Label | Reasoning |
|------|-------|-----------|
| Alert in window, technique matches the atomic | 1 | Core true positive |
| Alert in window, *different* technique fires | 0 | Collateral — that rule was wrong, so it's an FP for that rule |
| Alert from ART prerequisite setup or cleanup | 1 | The atomic caused it; flag in limitations that setup/teardown noise is included |
| Alert during a benign session | 0 | Always — even if it looks attack-like |
| Alert from Blue itself (Ubuntu FIM, sshd, sudo) | **excluded from dataset** | Not part of the research question; filter to `agent.name = win-endpoint` |
| Alert with no matching window, endpoint agent | 0 | Background noise — legitimately part of the negative class |
| **Process parented by `wazuh-agent.exe`** | **0 — overrides the window** | Monitoring-tool self-noise. See below |

**The Blue-agent exclusion is not optional.** Wazuh generates a continuous stream of Linux
file-integrity, authentication and sudo alerts from the manager host itself. Left in, they would
dominate the negative class, be trivially separable by `agent_name`, and inflate every metric —
the model would learn "agent == win-endpoint" as a proxy for "attack".

### The Wazuh agent triggers its own detection rules — discovered 2026-08-05

Rule 100200 (T1087.001) fired four times with no attack running. Every firing looked like this:

```
CommandLine:  net user   /   C:\Windows\system32\net1 user
ParentImage:  C:\Program Files (x86)\ossec-agent\wazuh-agent.exe
User:         NT AUTHORITY\SYSTEM
CurrentDirectory: C:\Program Files (x86)\ossec-agent\
```

The cause is the agent's own **Security Configuration Assessment** module. The
`cis_win10_enterprise.yml` policy runs `net user` to audit local account settings, which is
functionally identical to the discovery technique being detected. The agent log confirms SCA
evaluating that policy on a schedule.

**Why this matters, in two directions.**

It is a **contamination risk**. SCA runs periodically and unpredictably. If a scan lands inside a
detonation window, those alerts would be labelled 1 under the window rule — attributing the monitoring
tool's activity to the attack. That inflates the positive class with events the attack did not cause,
and it would be invisible in aggregate. Hence the override: **`parentImage` ending in
`wazuh-agent.exe` forces label 0 regardless of window.**

It is also a **genuine research asset**, and arguably a better one than anything that could be staged
deliberately. It is a real, recurring, automated false positive arising from a legitimate security tool
performing a legitimate audit — precisely the alert-fatigue problem the dissertation addresses. It also
carries clean discriminating features (`parentImage`, `user`, `currentDirectory`) that the model can
learn from, which is exactly the argument for ML-based prioritisation over severity alone.

Worth writing up in Chapter 4 as an observed finding rather than a nuisance: *the monitoring
infrastructure is itself a false-positive source, and severity-only ranking cannot distinguish it from
an attacker running the same command.*

**Generalise this check.** Other techniques in the set will collide with agent self-activity and with
Sysmon/SCA behaviour the same way. For every new rule, inspect the parent process of the first few
firings before accepting them as detections — a rule that appears to work may only be detecting the
monitoring stack.

## Export-time checklist

1. Filter to `agent.name = win-endpoint`
2. Join alerts against `detonation_log.csv` on timestamp
3. Apply the labelling rule above
4. Report class balance (expect heavy 0-majority — that is correct and intended)
5. Spot-check 10 labelled rows by hand against the alert log before trusting the whole file
