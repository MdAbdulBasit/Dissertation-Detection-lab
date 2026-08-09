# RULE-ID REGISTER

**Purpose:** Wazuh silently ignores duplicate rule IDs — it uses the FIRST occurrence and logs
`WARNING (7612): Rule ID 'X' is duplicated`. Detection then appears to "not work" for no visible
reason. This register pre-allocates a block per technique so IDs are never guessed.

**Custom range:** 100000–120000 (Wazuh reserves below 100000 for built-in rules).
**Block size:** 10 IDs per technique — several techniques need more than one rule (different atomics,
different Sysmon event types, or a broad rule plus a tightened variant).

> ### ⚠️ Block reallocation, 2026-08-08 — T1547.001 ⇄ T1112
>
> T1547.001 was allocated `100260–100269`. Its rules were written into `100290–100299`, which the table
> assigned to **T1112**, because I went straight to "the next free-looking block" instead of reading the
> row for the technique I was working on. Not caught until the technique was deployed, smoke-tested and
> both phases measured.
>
> **The blocks are swapped rather than the rules renumbered.** Renumbering would change rule IDs that are
> already recorded in `labelled_alerts.csv` for a completed 5+5 custom phase, so either the measurement
> is re-run or the dataset disagrees with the ruleset. T1112 has not started, so `100260–100269` is free
> and the swap costs nothing. The allocation is an internal bookkeeping convention, not a constraint —
> but a *silent* deviation from it would be exactly the kind of thing that makes a rule register
> untrustworthy, so it is recorded here rather than quietly corrected.
>
> **Process fix:** the "before adding any rule" check below now starts with reading this table's row for
> the technique, not just grepping for a free ID. A free ID and the *right* ID are different questions.

**Before adding any rule:**
```bash
sudo grep -c 'id="<NEW_ID>"' /var/ossec/etc/rules/local_rules.xml   # must return 0
```
**After adding any rule:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t     # must be clean, no 7612 warning
sudo systemctl restart wazuh-manager
```

---

## Allocation

| Block | Technique | Tactic | Sysmon EID | IDs used | Status |
|-------|-----------|--------|------------|----------|--------|
| 100200–100209 | T1087.001 Local Account Discovery | Discovery | 1 | **100200** | ✅ Deployed — see note 1 |
| 100210–100219 | T1059.001 PowerShell | Execution | 1 | **none** | ✅ **NO RULE NEEDED — default is correct. See note 5** |
| 100220–100229 | T1059.003 Windows Command Shell | Execution | 1 | **none** | ✅ **NO RULE NEEDED — default is correct. See note 6** |
| 100230–100239 | T1082 System Information Discovery | Discovery | 1 | **100230, 100231, 100232, 100233** | 🟡 Written, not yet deployed — see note 2 |
| 100240–100249 | T1033 System Owner/User Discovery | Discovery | 1 | **100240, 100241** | 🟡 Written, not yet deployed — see note 3 |
| 100250–100259 | T1016 Network Config Discovery | Discovery | 1 | **100250, 100251, 100252** | 🟡 Written, not yet deployed — see note 4 |
| 100260–100269 | **T1112 Modify Registry** *(reallocated — see below)* | Defense Evasion | **13 + 1** | **100260, 100261, 100262, 100263, 100264** | ✅ Deployed + measured over **three** phases 2026-08-08 — notes 10, 10a, 10b, 10c |
| 100270–100279 | T1053.005 Scheduled Task | Persistence | 1 | **100270, 100271** | 🟡 Written, not yet deployed — see note 7 |
| 100280–100289 | T1136.001 Create Local Account | Persistence | 1 / **Security 4720** | **100280, 100281, 100282, 100283** | ✅ Deployed + smoke-tested 2026-08-08 — see note 8 |
| 100290–100299 | **T1547.001 Registry Run Keys** *(reallocated — see below)* | Persistence | **13 + 11** | **100290, 100291, 100292, 100294** · ~~100293 retired, ID reserved~~ | ✅ Deployed + measured 2026-08-08 — notes 9, 9a, 9b |
| 100300–100309 | T1218.011 Rundll32 | Defense Evasion | 1 | — | Not started |
| 100310–100319 | T1070.004 File Deletion | Defense Evasion | 11/23 | — | Not started |
| 100320–100329 | T1003.001 LSASS Memory | Credential Access | 10 | — | Not started |
| 100330–100339 | T1560.001 Archive via Utility | Collection | 1/11 | — | Not started |
| 100340–100349 | T1105 Ingress Tool Transfer | Command & Control | 3 | — | Not started |
| 100350–100359 | T1003.002 SAM Registry Dump | Credential Access | 1/13 | — | Fallback for T1003.001 |
| 100360–100369 | T1552.001 Credentials in Files | Credential Access | 1 | — | Fallback for T1003.001 |
| 100370+ | *unallocated* | | | | Reserve |

---

## Per-rule detail

| Rule ID | Technique | Level | Chained from | Match field | Deployed | Notes |
|---------|-----------|-------|--------------|-------------|----------|-------|
| 100200 | T1087.001 | 10 | `sysmon_eid1_detections` | `originalFileName` `(?i)net1?\.exe` **+ `commandLine` `(?i)\s+(user\|localgroup\|group\|accounts)\b`** | Yes | Note 1 precision fix **applied** — command-line condition is in the deployed rule. Measured 5 atk / 2 ben alerts (deduped) |
| 100230 | T1082 | 8 | `sysmon_eid1_detections` | `originalFileName` `(?i)^(systeminfo\|hostname)\.exe$` | No | Single-purpose tools, no command-line condition needed |
| 100231 | T1082 | 8 | `sysmon_eid1_detections` | `originalFileName` `wmic\.exe` + `commandLine` `(os\|bios\|computersystem\|csproduct\|diskdrive\|qfe\|environment)` | No | wmic is multi-purpose — command-line condition required |
| 100232 | T1082 | 8 | `sysmon_eid1_detections` | `originalFileName` `reg\.exe` + `commandLine` host-identity value names | No | reg.exe is multi-purpose — constrained to host-identity keys |
| 100233 | T1082 | 8 | `sysmon_eid1_detections` | `originalFileName` `powershell` + `commandLine` cmdlet/WMI-class names | No | Closes the cmdlet blind spot; cannot see interactive use — needs EID 4104 |
| 100240 | T1033 | 8 | `sysmon_eid1_detections` | `originalFileName` `^whoami\.exe$` | No | Single-purpose tool. Closes the dominant gap — `whoami` was being attributed to T1087 by rule 92032 |
| 100241 | T1033 | 8 | `sysmon_eid1_detections` | `originalFileName` `powershell` + `commandLine` identity patterns | No | Covers atomics T1033-4 (env vars) and T1033-5 (`WindowsIdentity::GetCurrent`) |
| 100250 | T1016 | 8 | `sysmon_eid1_detections` | `originalFileName` `^(ipconfig\|arp\|route\|nbtstat\|netstat\|nslookup)\.exe$` | No | All single-purpose network utilities |
| 100251 | T1016 | 8 | `sysmon_eid1_detections` | `originalFileName` `netsh\.exe` + `commandLine` `\bshow\b` | No | ⚠️ `show` is mandatory — `netsh advfirewall set` is T1562.004, not Discovery |
| 100252 | T1016 | 8 | `sysmon_eid1_detections` | `originalFileName` `net1?\.exe` + `commandLine` `\s+config\b` | No | Disjoint from 100200 by construction — `config` vs account subcommands |
| 100270 | T1053.005 | **10** | `sysmon_eid1_detections` | `originalFileName` `schtasks\.exe` + `commandLine` `\s/(create\|change)\b` | No | ⚠️ `/query` excluded (enumeration, used by mirror); `/delete` excluded (T1070.009, and it's our own cleanup) |
| 100271 | T1053.005 | **10** | `sysmon_eid1_detections` | `originalFileName` `powershell` + `commandLine` `Register-\|Set-\|New-ScheduledTask\|MSFT_ScheduledTask` | No | `Get-ScheduledTask` excluded — enumeration, not persistence |

---

## Notes

### Note 1 — precision defect in rule 100200 (open decision)

As written, 100200 fires on **any** `net.exe` / `net1.exe` process creation, because it matches only
on `originalFileName` and never inspects the command line. It therefore maps `net start`, `net stop`,
`net use`, `net view`, `net share` and every other `net` subcommand to **T1087.001 Local Account
Discovery** at level 10.

Why this matters beyond noise: the dissertation's central claim is that engineered rules add
*sub-technique precision* over the SIEM defaults. A rule that labels unrelated `net` subcommands as
account discovery is imprecise in exactly the dimension the thesis claims to improve, and an examiner
reading the rule will see it immediately.

It also inflates the positive class artificially — routine `net use` drive mappings would be counted
as T1087.001 detections in the ML dataset.

**Recommended fix** — add a command-line condition so the rule matches only account-enumeration
subcommands (`user`, `localgroup`, `accounts`, `group`):

```xml
<rule id="100200" level="10">
  <if_group>sysmon_eid1_detections</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)net1?\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s+(user|localgroup|group|accounts)\b</field>
  <description>T1087.001 Local Account Discovery via net.exe</description>
  <mitre><id>T1087.001</id></mitre>
</rule>
```

**Cost of fixing:** the T1087.001 result must be re-run and re-recorded. Cheap now (1 technique),
expensive later — the same broad-match pattern would otherwise be copied into all 14 remaining rules.

**If NOT fixed:** record explicitly as a limitation in Chapter 4, and expect the ML feature importance
to show `rule_id` 100200 as a weak/noisy predictor.

**Decision:** ✅ **Fixed.** The command-line condition is present in the deployed rule (see
`wazuh_rules/local_rules.xml`). T1087.001 was re-run afterwards; measured 5 attack / 2 benign alerts
after `net1.exe` deduplication. The broad-match pattern was therefore never copied into the T1082 rules —
100231 and 100232 both carry command-line conditions for exactly this reason.

---

### Note 2 — T1082 rules 100230–100233, written 2026-08-06, deployment pending

Written from a measured baseline rather than from assumption: across 5 detonation windows and 14 atomic
tests, stock Wazuh detected T1082 **zero** times and instead attributed the activity to **T1087** and
**T1059.003** — wrong technique and wrong tactic. Full analysis in `COVERAGE_TABLE.md` row 4.

Four rules rather than one, because T1082 is exercised through four distinct mechanisms and a single
broad rule would repeat the note-1 defect:

| ID | Mechanism | Command-line condition? |
|----|-----------|--------------------------|
| 100230 | `systeminfo.exe`, `hostname.exe` | No — single-purpose tools |
| 100231 | `wmic.exe` host queries | Yes — wmic does far more than discovery |
| 100232 | `reg.exe` host-identity keys | Yes — reg.exe does far more than discovery |
| 100233 | PowerShell cmdlets / WMI classes | Yes — matches cmdlet and class names |

**⚠️ Deployment checklist — do not skip the verification step.**

```bash
sudo grep -c 'id="10023' /var/ossec/etc/rules/local_rules.xml   # expect 0 BEFORE deploying
sudo /var/ossec/bin/wazuh-analysisd -t                          # must be clean, no 7612 warning
sudo systemctl restart wazuh-manager
```

Then **prove each rule fires**. The `originalFileName` values are asserted from PE version resources
and have not yet been observed in this lab's telemetry. A rule that silently never matches looks
identical to a technique that is not detected — that confusion has already cost this project a day.
Re-detonate T1082 and confirm 100230–100233 all appear before recording any "detected after" result.

**Known limitation of 100233:** it sees cmdlets only when passed via `-Command` or `-File`. Interactive
cmdlet use creates no new process, so EID 1 never fires. Full coverage needs PowerShell **Script Block
Logging (EID 4104)**, which this endpoint's own SCA scan reports as disabled (CIS Win10 v4.0.0, "Ensure
'Turn on PowerShell Script Block Logging' is set to 'Enabled'"). Enabling it is an evidence-backed
recommendation, not a guess.

---

### Note 3 — T1033 rules 100240–100241, written 2026-08-07, deployment pending

Written against a measured baseline of 165 attack alerts over 5 windows (atomics 1, 4, 5, 6, 7).

**The default ruleset is partly right here, and that is recorded rather than glossed over.** Rule 92022
correctly maps `qwinsta.exe` session enumeration to T1033 — 19 alerts. But `whoami.exe`, the dominant
variant of this technique, produced 15 alerts of which **every one** was rule 92032, mapped to
`T1087` + `T1059.003`. The most common T1033 command is therefore attributed to the wrong technique
*and* the wrong tactic, while a less common variant is attributed correctly.

| ID | Mechanism | Command-line condition? | Why |
|----|-----------|--------------------------|-----|
| 100240 | `whoami.exe` | No — single-purpose tool | Closes the dominant gap |
| 100241 | PowerShell identity enumeration | Yes | Atomics T1033-4 (env vars), T1033-5 (`WindowsIdentity::GetCurrent`) |

**Two rules deliberately NOT written** — each omission is a finding in its own right:

1. **No `qwinsta` / `quser` rule.** Default 92022 already maps it to T1033 correctly. Writing one would
   duplicate correct behaviour and inflate the measured contribution of the custom ruleset. A
   detection-engineering project that only ever adds rules is not measuring anything.
2. **No rule for `wmic useraccount get /ALL`** (present in atomic T1033-1). Enumerating local accounts is
   arguably **T1087.001**, not T1033. ART files it under T1033, so the atomic spans two techniques.
   Recorded as a limitation rather than resolved with a rule that would mislabel it either way.

**Cross-rule check performed before writing:** verified that `100231` (T1082 WMIC) does *not* fire on
T1033's `wmic useraccount get /ALL` — `useraccount` is absent from its alias list, and the telemetry
confirms T1033's wmic alerts show only rule 92032. Without that check, my own rule would have
misattributed T1033 activity to T1082 — precisely the fault being criticised in the defaults. **Run this
check for every new technique whose commands overlap an existing rule.**

**⚠️ Deployment checklist:**

```bash
sudo grep -c 'id="10024' /var/ossec/etc/rules/local_rules.xml   # expect 0 BEFORE deploying
sudo /var/ossec/bin/wazuh-analysisd -t                          # must be clean, no 7612
sudo systemctl restart wazuh-manager
```

Then smoke-test both rules before recording any "detected after" result.

---

### Note 4 — T1016 rules 100250–100252, written 2026-08-07, deployment pending

Baseline measured over 5 windows, atomics 1/2/9, 44 attack alerts. **Nothing in the default ruleset maps
to T1016.** What fires is `92032` (→ T1087 + T1059.003), `92052` (→ T1059.003) and `92036`
(→ T1059.003 + T1574.001). Same failure mode as T1082.

**Running tally across four techniques — three distinct failure modes, not four:**

| Technique | Default behaviour |
|-----------|-------------------|
| T1087.001 | Parent-only — detects it, loses sub-technique precision |
| T1082 | Misattributed — no mapping to T1082 at all |
| T1033 | Partial — correct for `qwinsta`, `whoami` misattributed to T1087 |
| T1016 | Misattributed — no mapping to T1016 at all |

| ID | Mechanism | Command-line condition? |
|----|-----------|--------------------------|
| 100250 | `ipconfig`, `arp`, `route`, `nbtstat`, `netstat`, `nslookup` | No — single-purpose tools |
| 100251 | `netsh` enumeration | **Yes, mandatory** |
| 100252 | `net config` | Yes |

**⚠️ Why 100251's condition is not optional.** `netsh advfirewall … show` is discovery, but
`netsh advfirewall set` **disables the firewall** and is **T1562.004 Impair Defenses**. A rule matching
`netsh` broadly would map firewall tampering to Discovery — exactly the class of error this project
measures in the default ruleset. Requiring `\bshow\b` keeps the two apart.

**Disjointness check against 100200.** `100252` requires `config`; `100200` requires
`user|localgroup|group|accounts`. No `net.exe` invocation can satisfy both. Confirmed empirically on the
T1016 re-run: `net.exe` appeared 5 times and fired neither rule, because `net config` matches only the
new condition.

**Test-set caveat carried from LABELLING_SCHEME.md §3a.** The first T1016 baseline used tests
1/2/4/7/9 and was discarded — tests 4 (TrickBot) and 7 (Qakbot) are multi-technique recon sequences that
also run `net`, `whoami` and `nltest`, so `100200` and `100240` fired *correctly* inside a window labelled
T1016 and per-technique attribution became impossible. Tests 1, 2 and 9 exercise T1016 alone, confirmed
by zero `1002xx` rules in the re-run's attack class.

**⚠️ Deployment checklist:**

```bash
sudo grep -c 'id="10025' /var/ossec/etc/rules/local_rules.xml   # expect 0 BEFORE deploying
sudo /var/ossec/bin/wazuh-analysisd -t                          # must be clean, no 7612
sudo systemctl restart wazuh-manager
```

Smoke-test all three before recording anything.

---

### Note 5 — T1059.001: block `100210`–`100219` left EMPTY on purpose

Baseline measured over 5+5 windows (atomics 6, 13–17): **61 attack / 15 benign**. **The default ruleset
detects this technique correctly**, so no rule was written and the block stays unallocated.

| Default rule | Maps to | Fires in |
|--------------|---------|----------|
| `92027` Powershell process spawned powershell instance | **T1059.001** | attack **and** benign (21 / 10) |
| `92057` Powershell spawned a powershell process which executed a **base64 encoded command** | **T1059.001** | attack **and** benign (5 / 5) |
| `92070` WMI created a powershell process | T1047 + T1059.001 | attack only — harness lineage |
| `92071` WMI-created powershell executed a base64 encoded command | T1047 + T1059.001 | attack only — harness lineage |

**Why writing a rule here would be wrong.** It would duplicate working detection and inflate the measured
contribution of the custom ruleset. Same discipline as declining to write a `qwinsta` rule for T1033 —
where the default is right, record it as right. Five techniques in, the custom ruleset has been shown
necessary for four and unnecessary for one, and that ratio is far more credible than five for five.

**Why this is the strongest case for the ML layer in the study.** `92057` explicitly detects base64
obfuscation, maps to the correct technique, and **still fires on the benign mirror** — because the mirror
invokes `-EncodedCommand` the way a scheduled task or deployment script does. Better rule logic cannot fix
this: encoded PowerShell is genuinely used by both attackers and automation. The discriminator has to be
context, which is precisely what the triage model is for.

**Reserve the block anyway.** Atomics 10 (fileless), 11 (NTFS ADS) and 12 (remoting) were excluded from
this pass because each needs distinct detection logic — script-block content, ADS parsing, WinRM. If a
second T1059.001 pass covers them, `100210`+ is where those rules go.

---

### Note 6 — T1059.003: block `100220`–`100229` also left EMPTY on purpose

Baseline over 5+5 windows (atomics 1, 2, 5, 6): **45 attack / 15 benign**. Three default rules map to
T1059.003 and **two fire in both classes**:

| Default rule | Maps to | Fires in |
|--------------|---------|----------|
| `92004` Powershell process spawned Windows command shell instance | **T1059.003** | attack **and** benign (5 / 10) |
| `92032` Suspicious Windows cmd shell execution | T1087 + **T1059.003** | attack **and** benign (15 / 5) |
| `92052` cmd prompt started by an abnormal process | **T1059.003** | attack only (10) |
| `92005` | T1059 — **parent only** | attack only (5) |

**The clearest false-positive case in the study.** `92004` and `92032` key on `cmd.exe` process lineage,
so they fire in *every* technique that shells out — they appear in all six techniques' attack classes and
in every benign mirror that uses `cmd.exe`. No rule refinement fixes this: a command shell looks identical
whoever runs it. Two techniques now show the default is adequate, which is what makes the four gaps
credible.

**⚠️ A misdiagnosis worth recording.** `100240` (T1033 `whoami`) fired 5× in the attack class. I attributed
that to multi-technique atomic test 3 and re-ran with tests 1, 2, 5, 6 — **the contamination was
identical**. T1059.003 is a *container* technique: a shell must execute something, and the payload
(`whoami`, `wscript` running a `.vbs` → T1059.005) carries its own mapping. No test selection avoids it.
The T1016 precedent did not transfer, because there the offending atomics were optional malware
emulations that could simply be dropped. See `LABELLING_SCHEME.md` §3b — Execution techniques are
structurally different from Discovery techniques for per-technique attribution.

---

### Note 7 — T1053.005 rules `100270`–`100271`, deployed and verified 2026-08-08

First Persistence technique, and the **starkest default failure of the seven measured**: nothing maps to
T1053.005, and every rule that fired maps to **Execution**. A technique that plants a task surviving reboot
is reported as "powershell spawned powershell".

| ID | Mechanism | Level |
|----|-----------|-------|
| 100270 | `schtasks /create` or `/change` | **10** |
| 100271 | `Register-`/`Set-`/`New-ScheduledTask`, `MSFT_ScheduledTask` | **10** |

**Level 10, not the 8 used for Discovery.** A scheduled task grants return access after reboot; host
enumeration is reconnaissance. Severity tracks consequence rather than copying the previous rule's number.

**Three exclusions in `100270`, each load-bearing:**

1. **`/query` excluded** — enumeration, not persistence, and the benign mirror uses it. Matching it would
   label task *listing* as Persistence.
2. **`/delete` excluded** — that is **T1070.009 Indicator Removal**, a different technique.
3. And practically: `schtasks /delete` appears **57 times** in the dataset because it is *this lab's own
   cleanup*. A broad `schtasks` rule would have recorded 57 of our own maintenance operations as
   persistence attacks.

**`(?i)` is mandatory.** Atomic 2 issues `SCHTASKS /Create` in uppercase. A rule written without
case-insensitivity silently misses a third of the atomics — and silence is indistinguishable from
non-detection.

**⚠️ Smoke-test lesson worth generalising.** `100270` first appeared not to fire. The cause was the test,
not the rule: it ran `schtasks` directly from `powershell.exe`. All 57 `schtasks.exe` events in the dataset
have parent `cmd.exe` and match built-in rule `92032`, which is what places them in
`sysmon_eid1_detections` — the group `100270` chains from. Without a `cmd.exe` parent the event never
enters that group and the child rule has nothing to chain onto. **Smoke tests must reproduce the atomic's
process lineage, not merely run the same binary.** Confirmed by retesting through `cmd.exe /c`.

---

### Note 12 — T1560.001: predictions recorded before detonating

Written 2026-08-09 **before** the baseline run. Fourth technique pre-registered.

**Every default rule claiming T1560 depends on a logging feature that is switched off.** `91825`
(`Compress-7Zip`), `91826` (`Copy-Item`), `91827`, `91846` (`::CreateFromDirectory`) all chain from
`91802` — **PowerShell Script Block Logging, EID 4104** — and `EnableScriptBlockLogging` is unset on this
endpoint, verified by query during T1112. Nothing else in the ruleset maps to T1560.

That is the T1112 wall reached by a different route: not a sensor filter, but a **Windows logging feature
that is off by default**. And the two connect — **T1112's atomic 33 disables PowerShell logging**, so an
adversary who performs Modify Registry first blinds the only detection Wazuh has for Archive via Utility.
A measurable technique-chaining dependency, not a hypothetical one.

**FALSIFIABLE PREDICTIONS:**

1. **Zero** T1560.001 attribution in the baseline, from any rule.
2. **Zero** alerts from `91825`/`91826`/`91846` — they cannot fire without EID 4104.
3. The `.cab` output produces no file-create alert: `92200` matches only
   `\.(bat|cmd|lnk|pif|vbs|vbe|js|wsh|ps1)`, and `.cab`/`.zip` are absent from that list.
4. What fires instead is generic process-creation telemetry for `makecab.exe`.

**⚠️ ONLY 1 OF 12 ATOMICS IS USABLE, and that is a finding about the test set rather than a limitation
to apologise for.** Tests **1–4** require rar / winrar / winzip / 7zip to be installed — third-party
archivers this endpoint does not have, and installing them mid-study changes the environment being
measured. Test **10** targets ESXi. Test **12** copies the **entire AppData tree** and zips it, which on
a 4 GB endpoint takes minutes and would balloon the window far past comparability — the same reason
T1082's test 28 and T1218.011's test 2 were excluded. That leaves **test 11, `makecab.exe`**, the only
built-in Windows archiver in the set.

The narrowness is itself worth reporting: ATT&CK's Archive via Utility is dominated by third-party
tooling, so on a clean Windows host the technique reduces to `makecab` and `tar` — and neither appears
anywhere in the default ruleset.

---

### Note 11 — T1218.011: predictions recorded before detonating

Written 2026-08-09 **before** the baseline run. Third technique pre-registered this way.

**Default coverage is two rules, and one of them is structurally dead on this host.**

| Rule | Lvl | Condition | Verdict |
|---|---|---|---|
| `92079` | 10 | `if_sid 92078` + commandLine contains `rundll32` | **can never fire here** |
| `92081` | 15 | `originalFileName = RUNDLL32.EXE` + commandLine matching `\.(html\|htm\|txt\|png\|jpg\|pdf)"*,#` | very narrow |

`92078` requires **`currentDirectory = E:\` AND `cmd.exe` in the command line** — an ISO-mount scenario,
and it is itself mapped to **T1204.002 User Execution**, not T1218.011. This endpoint has no E: drive.
So `92079`, the only general-looking rundll32 rule, is gated behind a condition that cannot occur, and
T1218.011's real coverage is `92081` alone.

**FALSIFIABLE PREDICTIONS:**

1. **Zero** alerts carrying rule id `92079` — its parent's `E:\` condition cannot be met.
2. **Zero** alerts carrying `92081` — the atomics load `.dll` exports and the `vbscript:` handler, none
   of which match its document-extension pattern.
3. Therefore **zero T1218.011 attribution in the baseline**, from any rule.
4. What fires instead is generic execution telemetry (`92052`/`92004`/`92032` → T1059.x), the same
   wrong-tactic pattern as T1082, T1016 and T1112 — Defense Evasion read as Execution.

**Test set 9, 15, 16** — `pcwutl.dll,LaunchApplication`, `url.dll,FileProtocolHandler`, and
`zipfldr.dll,RouteTheCall`. Each verified to exit cleanly with code 0 before the phase ran.

**Three tests excluded, each for a measured reason rather than a judgement call:**

- **Test 2** — *excluded after a failed first run, not in advance.* The `vbscript:`/`RunHTMLApplication`
  handler never terminates: rundll32 persists as an HTA host until ART's 120s timeout kills it
  (`Exit code: -1`). Window 1 measured **193 seconds** against ~10s for its siblings. Same defect that
  excluded T1082's test 28 — a hanging atomic inflates the window, and a 193s window with a 120s buffer
  sweeps in far more ambient telemetry than the others, so its counts are not comparable. Attack run 1
  of the aborted phase is superseded with this reason.
- **Test 12** — downloads `calc.dll` from GitHub at runtime. A network dependency converts a detection
  failure into an environmental one; same reasoning as WinPwn, PowerView, Mimikatz.
- **Test 13** — `copy %windir%\System32\calc.exe not_an_scr.scr` with no `/Y`, so runs 2–5 hit an
  *"Overwrite? (Yes/No/All)"* prompt. **The third time this exact trap has appeared** (T1053.005's task
  collision, T1547.001's `REG ADD` without `/F`). Caught in preflight rather than mid-phase.

**⚠️ Mirror asymmetry, recorded rather than engineered away.** The mirror covers
`pcwutl.dll,LaunchApplication` and `url.dll,FileProtocolHandler` — the two atomic mechanisms with real
administrative counterparts — plus `shell32.dll,Control_RunDLL desk.cpl`, which is what happens whenever
anyone opens Display Settings. It does **not** cover `zipfldr.dll,RouteTheCall`, which has no plausible
benign invocation from a command line. Consequence for analysis: a rule keyed on *"rundll32 with a
DLL,Export"* should fire in both classes, while a rule naming `zipfldr` specifically would be attack-only
**by mirror scope** — the `100241`/`100251` category, not the `100260` category. The distinction matters
and the two must not be reported the same way.

**⚠️ One mirror mechanism deliberately omitted, and it is the opposite of the earlier mirror defects.**
The benign mirror covers `pcwutl.dll,LaunchApplication`, `url.dll,FileProtocolHandler` and
`shell32.dll,Control_RunDLL desk.cpl`, but **not** atomic 2's `vbscript:"\..\mshtml,RunHTMLApplication`.
That construction has no legitimate administrative use; writing a benign counterpart would manufacture a
false negative. If a rule keyed on it comes out attack-only, that is a **genuine discriminator** — the
same status as `100260` — and must be reported differently from `100241`/`100251`/`100271`/`100282`,
which were attack-only because the *mirror* was too narrow rather than because the *behaviour* has no
benign form.

---

### Note 10 — T1112: predictions recorded before detonating, and a likely SEVENTH failure mode

Written 2026-08-08 **before** the baseline run, from reading the ruleset and the agent config. Same
discipline as note 9, for the same reason: a failure-mode taxonomy assembled after seeing the data is
open to the charge of being fitted to it.

**T1112 has more nominal coverage than any technique so far, and probably the least usable.** Three
sources claim it, none of them Sysmon EID 13:

| Source | Rules | What it actually is |
|---|---|---|
| Wazuh **FIM** (`syscheck`) | `594`, `597`, `598`, `750`, `751`, `752` — all L5 | *"Registry Key/Value Integrity Checksum Changed / Deleted / Added"* |
| Sysmon EID 13 | `92304`–`92306` | UAC-bypass rules for **one key**, `Classes\Folder\shell\open\command`; T1112 is a secondary tag beside T1548.002 |
| PowerShell **Script Block Logging** (EID 4104) | `91813`, `91814` | **Cannot fire — logging is disabled on this endpoint.** Verified, not assumed: `EnableScriptBlockLogging` returns nothing |

**The FIM coverage has two independent limits, and it is important to keep them apart.**

**(a) SCOPE — an allow-list, and it is HKLM-only.** The agent watches exactly 20 registry paths. Every
one begins `HKEY_LOCAL_MACHINE`. **There is not a single `HKEY_CURRENT_USER` entry.** A large share of
the 90 T1112 atomics write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\...` — the
"Disable Task Manager", "NoRun", "NoControlPanel" family — and are therefore outside the monitored set
by construction. Coverage limited to paths someone enumerated in advance is a different thing from
behavioural detection, and an adversary needs only to pick a key nobody listed.

**(b) LATENCY — `<frequency>43200</frequency>`, a 12-hour scan, with no real-time registry option
configured.** Registry FIM is scan-based. A detonation window here is ~20s with a 120s label buffer, so
the scan interval is roughly **360× the entire observation window**. A FIM alert for a modification made
now arrives, on average, six hours later.

**Proposed seventh failure mode: LATENT COVERAGE.** The rule exists, it is correctly aimed at registry
modification, it emits an alert — and it cannot arrive in time to matter. Distinct from all six:

| Mode | Rule exists? | Aimed right? | Emits? | Arrives in time? |
|---|---|---|---|---|
| parent-only (T1087.001) | yes | parent only | yes | yes |
| wrong tactic (T1082, T1016, T1053.005) | no | — | for something else | yes |
| partial coverage (T1033) | one variant | yes | partly | yes |
| adequate (T1059.001/003) | yes | yes | yes | yes |
| sibling misattribution (T1136.001) | yes | **no** | yes | yes |
| suppressed severity (T1547.001) | yes | yes | **no** | — |
| **latent coverage (T1112, predicted)** | **yes** | **yes** | **yes** | **NO** |

**FALSIFIABLE PREDICTIONS for the baseline run:**

1. **Zero** FIM alerts (`594`/`597`/`598`/`750`/`751`/`752`) inside any detonation window, for **any**
   atomic — including ones that write to allow-listed HKLM paths.
2. HKCU-targeting atomics produce no registry-sourced alert of any kind: outside the FIM allow-list, and
   no Sysmon EID 13 rule matches generic policy keys.
3. **The discriminating prediction.** HKLM atomics on *allow-listed* paths also produce nothing
   in-window. If true, allow-list membership makes **no observable difference at incident timescales**,
   which separates latency from scope as the binding constraint. If allow-listed paths *do* alert
   promptly, then scan-based FIM is not the limit and this whole note is wrong.
4. What fires instead is process-level execution telemetry for `reg.exe` / `powershell.exe` — the same
   wrong-tactic misattribution measured in T1082 and T1016, this time reading Defense Evasion as
   Execution.

**Retrospective support already in hand:** T1547.001's atomic 3 wrote to
`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`, which **is** on the allow-list, and produced no
FIM alert whatsoever across five runs. That is prediction 3 already holding once, unplanned.

**⚠️ Do not "fix" the endpoint to make this measurable.** Adding HKCU paths or shortening the scan
interval would improve the lab's detection and destroy the finding. The default configuration is the
object of study.

#### Note 10a — predictions scored, and the defect in `92041`

Baseline 2026-08-08, 5+5 windows, atomics 1/2/33/60. **55 attack / 41 benign.** All four predictions held.

| # | Prediction | Outcome |
|---|---|---|
| 1 | Zero FIM alerts in any window | ✅ none of `594`/`597`/`598`/`750`/`751`/`752` appeared |
| 2 | HKCU atomics produce no registry-sourced alert | ✅ the only registry paths that alerted were the two HKLM Run writes |
| 3 | **Allow-listed HKLM paths also silent in-window** | ✅ atomic 2 writes `HKLM\…\CurrentVersion\Run`, which **is** on the list, and produced no FIM alert. **Latency is the binding constraint, not scope** |
| 4 | Execution telemetry fires instead | ✅ `92052`/`92004`/`92027` → T1059.x. Defense Evasion read as Execution |

**`92041` is the sharpest vendor defect found anywhere in this study.** It is the only default rule that
fires *and* claims T1112 — and it is a **process-creation** rule in `0800-sysmon_id_1.xml` that never
reads the registry:

```
(?i)add.+\/d\s+(")?(?:[A-Za-z\d+\/]{4})*(?:[A-Za-z\d+\/]{3}=|[A-Za-z\d+\/]{2}==)?
```

Every group after `/d` is quantified `*` or `?`. **Zero repetitions satisfy the whole pattern**, so it
matches any `reg add … /d <anything>` — verified down to `add x /d ` with nothing following. Consequences:

- Fired **exactly once per `reg add` issued**: 6 per attack run, 3 per benign run → 30/15. It is a
  `reg.exe` execution counter wearing a base64 detector's description.
- Asserts **T1027 Obfuscated Files in all 45 cases**, none of which involve obfuscation.
- **Structurally blind to PowerShell registry modification** — `Set-ItemProperty` spawns no `reg.exe`.

A defect of **precision**, not coverage. Precision defects are what generate alert fatigue: they fire
constantly, at level 10, carrying no information. Worth pairing with `92219` (Windows Update) and with
`100200`, which had the same class of defect **twice** under my own authorship — that repetition is what
makes the pattern structural rather than a vendor failing.

#### Note 10b — three phases, and the finding that the sensor is the ceiling

`baseline` (default rules + default sensor) → `custom` (custom rules + default sensor) → `custom-sensor`
(custom rules + widened sensor). Three phases because the remediation has two independent parts, and
conflating them would have hidden the result entirely.

| Rule | Lvl | base A/B | custom A/B | sensor A/B | |
|---|---|---|---|---|---|
| `92041` | 10 | 30 / 15 | **0 / 0** | 0 / 0 | displaced |
| `100264` | 10 | 0 / 0 | **30 / 15** | 30 / 15 | 1:1 replacement, false T1027 removed |
| `100263` | 12 | 0 / 0 | **0 / 0** | **0 / 0** | correct — no atomic writes real base64 |
| `100260` | 12 | 0 / 0 | **0 / 0** | **20 / 0** | invisible until the sensor emitted |
| `100261` | 8 | 0 / 0 | **0 / 0** | **0 / 5** | " |
| `100262` | 8 | 0 / 0 | **0 / 0** | **18 / 10** | " |
| **totals** | | **55 / 41** | **55 / 41** | **93 / 55** | |

**The rule fix changed attribution, not volume — 55/41 → 55/41, identical.** That is the cleanest
possible statement of what repairing a broken rule buys you: the same alerts, correctly labelled.

**`100260`–`100262` were correct, deployed, and fired 0/0** because Sysmon's config gates which registry
keys emit EID 13 at all. Measured directly: 400 EID 13 events sampled, **81** Run-key writes, **0** for
`ModuleLogging`, **0** for `ZoneMap`. **Nine added config lines** — two `TargetObject` entries, zero
removals, diffed line by line — moved them to 20/0, 0/5, 18/10.

> **No SIEM rule can close a gap the sensor never emits.** Every custom rule in this project up to here
> worked because it keyed on EID 1, which Sysmon emits broadly. The moment a technique's evidence lives
> somewhere the sensor filters, rule quality stops being the constraint. This reframes the project's own
> premise, and it is measured rather than argued.

**Two allow-lists stack, and neither covers the important key.** Sysmon's include-list gates what exists;
Wazuh FIM's 20 HKLM paths on a 12-hour scan gate what is checked. The endpoint runs SwiftOnSecurity's
config — the most widely deployed community Sysmon config — whose registry include-list watches Defender
exclusions, UAC tampering, Security Center and `Policies\Explorer\Run`, but **not**
`Policies\Microsoft\Windows\PowerShell\`. Atomic 33 disabled PowerShell script-block and module logging
on this endpoint and **nothing in the pipeline saw it**.

#### ⭐ Note 10c — the first custom rule that cleanly separates the classes, and why

Unplanned, and the most useful single result for the ML chapter. Two custom rules, **same technique, same
phase, same data source, same atomics**:

| Rule | Keys on | attack / benign |
|---|---|---|
| `100260` | the **direction** of the change — DWORD set to zero, i.e. a control being *disabled* | **20 / 0** |
| `100262` | the **location** of the change — browser zone configuration | **18 / 10** |

The atomic disables PowerShell logging; the benign mirror enables it. Same key, same writer, same rule
surface, opposite intent.

> **A rule that encodes intent can separate the classes. A rule that encodes mechanism cannot.**

Nine techniques produced no cleanly discriminating custom rule; every apparent one turned out to be a
mirror artefact (`100241`, `100251`, `100271`, `100282`). This is not: disabling security logging is
intrinsically adversarial in a way that enabling it is not, and the mirror exercises the same key in the
same way. It marks the boundary of what rule logic can do unaided — and tells the triage model precisely
what kind of feature to look for: not *which* key or *which* binary, but *which way* the change went.

**⚠️ And its limitation is the same lesson inverted.** "Disable" is not always zero:
`EnableModuleLogging=0` disables, but `DisableAntiSpyware=1` also disables. Polarity depends on how the
value name is phrased, so `100260` misses every `Disable*=1` setting — **including Defender tampering**.
Encoding intent requires knowing what each value *means*, and enumerating that is the same brittle
list-maintenance this technique criticises in the FIM allow-list. Recorded as a limitation rather than
patched with a longer regex, because the gap is the argument.

---

### Note 9 — T1547.001: a PREDICTION recorded before detonating, and a likely sixth failure mode

Written 2026-08-08 **before** the baseline run, from reading `/var/ossec/ruleset/rules/0860-sysmon_id_13.xml`.
Recorded in advance deliberately: every previous technique was characterised *after* seeing the data,
which makes the failure-mode taxonomy vulnerable to the charge that it was fitted to the results. This
one is falsifiable in advance.

**First: registry telemetry proven to exist before anything depends on it.** Sysmon on the endpoint is
emitting EID 1 (354), 11 (77), 22 (30), 3 (19), 5 (12), **13 (7)** and 12 (1) in a 500-event sample. An
event type that is not logged is indistinguishable from a technique that is not detected, and that
confusion has already cost this project a day. **Still unproven and needed later: EID 23/26 (file
delete) for T1070.004 and EID 10 (process access) for T1003.001.** Neither appeared in the sample; EID
10 is normally filtered to lsass-targeting only, so it may be present but idle. Prove both before
starting those techniques, not during.

**The default posture for T1547.001 is unlike anything measured so far.** Wazuh has a dedicated,
*correctly mapped* rule for Run-key persistence — and it is silent:

```
92300  level 0   if_group sysmon_event_13   targetObject matches ...CurrentVersion\Run    -> T1547.001
  92301  level 12  if_sid 92300   details matches \.(lnk|vbs|vba)                          -> T1547.001
  92302  level 6   if_sid 92300   image matches reg\.exe                                   -> T1547.001
  92303  level 12  if_sid 92300   details matches (VNC|tvnserver\.exe)                     -> T1547.001
```

Level 0 in Wazuh means *matched but no alert emitted*. So 92300 is a parent used only to gate three
narrow children. A Run key whose value is a plain `.exe` path, or `powershell.exe -enc <payload>`,
written by anything other than `reg.exe`, matches 92300 — and produces **nothing**.

**Proposed sixth failure mode: SUPPRESSED SEVERITY.** The rule exists, the ATT&CK mapping is right, the
path regex is right, and the general case is still invisible. Distinct from all five so far:

| Mode | Rule exists? | Mapping right? | Alert emitted? |
|---|---|---|---|
| parent-only (T1087.001) | yes | parent technique only | yes |
| wrong tactic (T1082, T1016, T1053.005) | no rule for the technique | n/a | yes, for something else |
| partial coverage (T1033) | for one variant | yes | yes, partially |
| adequate (T1059.001/003) | yes | yes | yes |
| sibling misattribution (T1136.001) | yes | **no** | yes |
| **suppressed severity (T1547.001, predicted)** | **yes** | **yes** | **no** |

**FALSIFIABLE PREDICTIONS for the baseline run** — if these fail, the mode is wrong and the note gets
rewritten rather than quietly dropped:

1. Atomics that write a Run key via **`reg.exe`** produce `92302` at level 6.
2. Atomics that write the same key via **PowerShell** (`Set-ItemProperty`/`New-ItemProperty`) produce
   **zero** T1547.001 alerts.
3. No alert at all carries rule id `92300`, because level 0 is never emitted.
4. Any atomic pointing a Run key at a `.lnk`/`.vbs` produces `92301` at level 12 — the default is not
   uniformly blind, and where it fires it fires *harder* than my custom rules will.

**Prediction 2 is the interesting one.** It means the same behaviour — same registry key, same
persistence, same outcome at next logon — is detected or invisible depending only on which binary
performed the write. That is a within-technique contrast the earlier techniques could not produce.

**Planned rules `100290`–`100291`,** subject to the measurement:

- `100290` level 12 — `if_sid 92300` plus a `details` condition for interpreters and suspicious paths
  (`powershell`, `cmd.exe`, `mshta`, `rundll32`, `wscript`, `-enc`, `AppData\Local\Temp`, `.bat`, `.ps1`).
- `100291` level 8 — `if_sid 92300` with **no further conditions**: the catch-all that stops the general
  case being silent.

⚠️ **Ordering matters and is not the same problem as before.** Wazuh evaluates sibling children in load
order, and `local_rules.xml` loads last, so `92301`–`92303` are tested before either custom rule. The
vendor's high-severity rules therefore keep their behaviour and the custom catch-all only picks up what
they miss — which is the correct outcome, but it must be **verified in the export**, not assumed.
`100290` must also appear *before* `100291` in the file or the catch-all will swallow everything.

⚠️ **Startup-folder variants of T1547.001 are EID 11, not 13**, and nothing in `0860-sysmon_id_13.xml`
covers them. Check whether the selected atomics include them; if so that is a second, separate gap in
the same technique and needs its own rule against `targetFilename`.

#### Note 9a — the predictions, scored

Baseline run 2026-08-08, 5+5 windows, atomics 1/3/7/12. **27 attack / 31 benign** after excluding
Windows Update noise.

| # | Prediction | Outcome |
|---|---|---|
| 1 | `reg.exe` write → `92302` at level 6 | ✅ **confirmed** — 4 attack alerts, level 6 |
| 2 | PowerShell write → **zero** T1547.001 alerts | ✅ **confirmed** — only 9 alerts in the whole technique carry a registry `targetObject`, and `92302`'s 4+5 accounts for all of them |
| 3 | `92300` never appears | ✅ **confirmed** — absent; level 0 is never emitted |
| 4 | Run value pointing at `.lnk`/`.vbs` → `92301` at L12 | ⚠️ **UNTESTED** — no atomic in the set writes such a value. Atomic 7 drops a `.lnk` into the Startup *folder*, which is a file event. Recorded as untested, not as confirmed |

**Prediction 2 verified positively, not by absence.** This technique predicts silence, so "no alerts"
cannot distinguish a working run from a broken one. The registry values and the `.lnk` were confirmed
present with `reg query` and `Test-Path` before cleanup, so the atomics definitely executed.

**The result is stronger than the prediction.** Two things came out that were not anticipated:

**(a) The benign class is noisier than the attack class — 31 vs 27.** First time in nine techniques. And
`92302`, the *only* rule in the default ruleset that correctly maps to T1547.001, fires **4 attack / 5
benign**. The sole correct detection available favours the wrong class. For a rule-based SOC this is the
worst possible shape: the one true positive signal has a negative likelihood ratio.

**(b) Two further gaps, independent of severity.**

- **Path coverage.** `92300`'s regex requires `RUN` immediately after `CURRENTVERSION`, so
  `HKCU\...\CurrentVersion\Policies\Explorer\Run` (atomic 12) never reaches it. A real Run-key location
  with no rule at all. The alternation *is* unanchored, so `RUNONCE` and `RUNONCEEX` match by accident —
  the regex is simultaneously too loose and too tight.
- **Wrong data source.** The Startup-folder variant is EID 11. `0860-sysmon_id_13.xml` covers registry
  only, so atomic 7's `.lnk` drop produced no T1547.001 attribution.

**Misattribution sits on top of the silence.** `92041` (L10) → **T1027 + T1112**, `92201` (L9) →
**T1105 + T1059**, both firing in *both* classes. `92041` was initially assumed to be an EID 13 rule
from its description ("Value added to registry key has Base64-like value") — it carries no
`targetObject` or `details`, which is how it was identified as reading Windows Security event **4657**
instead. Worth remembering: **a rule's description tells you what it looks for, not which log it reads.**

**⚠️ The exporter gained `target_object`, `details` and `event_type` for this technique.** Before that,
a registry alert exported as a rule id and nothing else — `HKCU\...\Run` and
`HKCU\...\Policies\Explorer\Run` were indistinguishable in the dataset, and that distinction is the
entire finding. Any future technique on a new data source should be checked for the same problem before
its baseline, not after.

**Rules `100290`–`100291` stand as designed in note 9**, with one addition now justified by the data: a
third rule for the Startup-folder file drop against EID 11 `targetFilename`, since that gap is real and
separate. Numbering `100292`.

#### Note 9b — custom phase result, and the ordering rule that changes how every count is read

Deployed `100290` (L12), `100291` (L8), `100292` (L10), `100294` (L10). **`100293` written, then retired
before the phase ran — see below. ID reserved, never reuse.**

**Custom phase: 35 attack / 45 benign**, against baseline 27 / 35.

| Rule | Lvl | base A/B | custom A/B | |
|---|---|---|---|---|
| `100290` | 12 | 0 / 0 | **5 / 5** | interpreter or staged payload in a Run value |
| `100291` | 8 | 0 / 0 | **5 / 10** | catch-all — the silence, removed |
| `100292` | 10 | 0 / 0 | **5 / 5** | `Policies\Explorer\Run` path gap |
| `100294` | 10 | 0 / 0 | **5 / 5** | Startup-folder `.lnk` |
| `92302` | 6 | 4 / 5 | **0 / 0** | displaced |
| `92201` | 9 | 5 / 5 | **0 / 0** | displaced |

**⭐ First technique with zero class-exclusive custom rules — 4 of 4 fire in both classes.** Every earlier
technique stranded at least one rule in one class as a mirror artefact (`100241`, `100251`, `100271`,
`100282`). The difference here is that the gap was **predicted from the rule's own regex before the run**
and closed, rather than discovered in the export and caveated. That check — *for each new rule, which
class can possibly match it?* — belongs in the pre-run routine permanently.

The 5/10 on `100291` is the mirror working exactly as designed: the atomics write one plain-path Run
value and one interpreter payload; the mirror writes two plain-path values and one interpreter payload.
So `100290` lands 5/5 and `100291` lands 5/10.

**⚠️ WAZUH EVALUATES SIBLING CHILD RULES BY DESCENDING LEVEL.** Measured across three independent
observations, none consistent with load order or ID order:

```
100291 (L8)  displaced  92302  (L6)   reg.exe Run-key write
100294 (L10) displaced  92201  (L9)   powershell-created Startup .lnk
100290 (L12) displaced  100291 (L8)   interpreter payload
```

**This changes how every custom-phase count in this project must be read.** Of the 20 attack / 25 benign
T1547.001-attributed alerts, **9 / 10 are RELABELLED** from `92302` and `92201`, and **11 / 15 are NEWLY
VISIBLE**. Quoting 20/25 as new detection would overstate the contribution roughly twofold. Earlier
techniques need re-checking for the same effect before their numbers are quoted in Chapter 4.

**Levels were not lowered to dodge the displacement.** Setting `100291` to level 5 would hand the
`reg.exe` case back to the vendor rule and make the comparison tidier. It would also mean **choosing a
severity to control evaluation order rather than to express how serious the behaviour is**, which is bad
detection engineering and would be dishonest in a study about detection quality. Autostart persistence
is a level 8.

**`100293` retired as unreachable.** It chained from `92201` (L9) with a Startup-folder condition, but
`100294` (L10) is `92201`'s sibling under `92200` and always wins for exactly those paths, so `92201`
can never be the deepest match there and its child can never fire. Dead code in a deployed ruleset is a
defect; the ID stays reserved so anyone matching alerts against this register finds no unexplained gap.

**⚠️ A REASONING ERROR, recorded in full because the method matters more than the conclusion.** On seeing
the smoke test produce `100294` instead of `92201`, I concluded that `92201` had never matched the
Startup `.lnk` at all, that `92200` was the real misattributing rule, and I edited that "correction" into
the ruleset comments and this register. **It was wrong.** The smoke test ran *after* `100294` was
deployed and already outranking `92201`; it could say nothing about how the baseline behaved. The
measured phases settle it — `92201` 5/5 baseline → 0/0 custom, `100294` 0/0 → 5/5. The original analysis
was right and the correction was the error.

> **A post-deployment observation cannot be used to infer pre-deployment behaviour.** This is the entire
> reason the protocol measures a baseline phase before a single rule is written, and I violated it in the
> middle of the technique that most depends on it.

**Vendor precision defect found in passing.** `92041` (L10, *"Value added to registry key has Base64-like
pattern"*, mapped to **T1027 Obfuscated Files or Information**) fired on `C:\ProgramData\Smoke\viareg.exe`
— a plain file path with nothing base64 about it. It sits at 4/5 and 5/5 across both phases and both
classes: a level-10 alert asserting obfuscation that carries no information whatsoever. Worth citing
alongside `92219` as evidence that vendor rule *precision*, not just vendor rule *coverage*, is part of
the alert-fatigue problem.

**⚠️ Deployed/repo divergence to reconcile at the next deployment.** The block pasted onto Blue carries
the pre-correction ordering comment. Rule *behaviour* is identical — comments do not execute — but
`wazuh_rules/local_rules.xml` in the repo is authoritative and the deployed copy should be refreshed
wholesale when T1112's rules go in.

---

### Note 8 — T1136.001 rules `100280`–`100282`, and a fifth failure mode

Baseline over 5+5 windows (atomics 4, 5, 8, 9): **156 attack / 72 benign**. The default ruleset behaved
differently here from all seven earlier techniques — it **detects the behaviour accurately and describes
it correctly, then tags it with the wrong ATT&CK technique**:

| Default rule | Description | Maps to | Should be |
|---|---|---|---|
| `60109` | *"User account enabled or created"* | **T1098** | **T1136.001** |
| `60110` | *"User account changed"* | T1098 | T1098 ✓ |
| `60111` | *"User account disabled or deleted"* | T1098 + T1531 | T1531 ✓ |
| `60154` | *"Administrators Group Changed"* | **T1484** | T1098 |
| `60160` | *"Domain Users Group Changed"* | **T1484** | T1098 |
| `60170` | *"Users Group Changed"* | **T1484** | T1098 |

`60109` fires on Windows Security event **4720**, whose literal meaning is "a user account was created" —
T1136.001 by definition. And the group rules map *local* group membership changes to **T1484 Domain
Policy Modification**, a domain mechanism this WORKGROUP endpoint does not possess.

**Fifth failure mode: SIBLING MISATTRIBUTION.** Same tactic family, adjacent technique, correct
description. Arguably the most insidious of the five — the alert text reads correctly and only the tag is
wrong, so a coverage matrix built from these mappings shows T1136.001 as uncovered while showing T1098
and T1484 as covered, both incorrectly.

**`100280` REFINES rather than duplicates.** It chains from `60109` via `if_sid`, so the default rule
still performs the detection and the custom rule only corrects the attribution. That is a cheaper class
of remediation than the from-scratch detection needed for T1082 and T1016, and the contrast is worth
drawing in the write-up: *some* SIEM gaps are mapping errors fixable in one line, others are genuine
blind spots.

**🔎 Independent confirmation of the error class — the vendor ruleset makes the same mistake.**

The smoke test for `100280`–`100283` was greped out of `alerts.json` alongside the built-in rules, and
two default rules turned out to be firing on *every* account-modification command:

```
92039  "A net.exe account discovery command was initiated"
         net1  user SmokeAcct Lab#Smoke2026 /add     <- CREATION  reported as discovery
         net1  user SmokeAcct /delete                <- DELETION  reported as discovery
         net1  user LabBenignSvc Lab#Benign2026 /add
         net1  user LabSmoke281 /del
92031  "Discovery activity executed"
         net1  localgroup administrators "T1136.001_Admin" /add     <- group ADD    as discovery
         net1  localgroup administrators LabSmoke281 /delete        <- group REMOVE as discovery
```

Every one of those is a **modification**, not an enumeration. The default ruleset therefore classifies
account creation, account deletion, group addition and group removal all as **Discovery** — a
tactic-level error across four distinct behaviours.

This matters more than the individual finding. Rule `100200` had exactly this defect twice (`/add`, then
`/del`), and both times it was my own authoring error. Finding the identical error in the shipped Wazuh
ruleset shows the failure mode is **structural, not personal**: substring-matching on a multi-purpose
binary's command line without excluding the modifying switches is a trap that a vendor with a full
detection-engineering team fell into as well. That reframes the contribution — the project is not
"Wazuh got it wrong and I got it right", it is "this class of rule is systematically fragile, here is
how to test for it".

**Alerts are corrected by ADDITION, not REPLACEMENT — and that raises volume.** `100281` and `92039` both
fire on the same `net user /add` event, because `92039` sits at a different depth in the rule chain than
a direct child of `sysmon_eid1_detections`. So the endpoint now emits one correct alert and one wrong one
for the same action. Only the Security-log side gets true displacement, where `100280`/`100283` chain via
`if_sid` and suppress the parent. This is left in place deliberately rather than papered over with
`overwrite="yes"`, because it is an honest operational result: **bolting local rules onto a SIEM does not
remove the misattributed alerts, it adds correct ones alongside them, increasing analyst load in the
short term.** That is a direct argument for the triage layer, and it should be quantified in the results
chapter as alerts-per-detonation before and after.

**Before/after evidence is in a single log file.** Group-change events before 05:02 UTC on 2026-08-08 show
bare `60154`/`60160`/`60170`; the same events after the manager restart show `100283`. Same host, same
event type, ruleset changed at a known timestamp — usable as a figure without further processing.

**⚠️ Second defect found in rule 100200.** The negation added earlier that day excluded `/add`, `/delete`
and `/active` — but Windows accepts `/del`, and `net user /del <name>` therefore still fired 100200,
reporting account **deletion** as account **discovery**. Observed twice in this baseline. Regex widened to
`(add|delete|del|active|act)`. General lesson: **Windows command-line switches are routinely abbreviated;
match the short forms.** This is the second precision defect found in the same rule, both by checking
which existing rules fire on the *next* technique's commands.
