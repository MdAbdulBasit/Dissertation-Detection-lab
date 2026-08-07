# RULE-ID REGISTER

**Purpose:** Wazuh silently ignores duplicate rule IDs — it uses the FIRST occurrence and logs
`WARNING (7612): Rule ID 'X' is duplicated`. Detection then appears to "not work" for no visible
reason. This register pre-allocates a block per technique so IDs are never guessed.

**Custom range:** 100000–120000 (Wazuh reserves below 100000 for built-in rules).
**Block size:** 10 IDs per technique — several techniques need more than one rule (different atomics,
different Sysmon event types, or a broad rule plus a tightened variant).

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
| 100210–100219 | T1059.001 PowerShell | Execution | 1 | — | Not started |
| 100220–100229 | T1059.003 Windows Command Shell | Execution | 1 | — | Not started |
| 100230–100239 | T1082 System Information Discovery | Discovery | 1 | **100230, 100231, 100232, 100233** | 🟡 Written, not yet deployed — see note 2 |
| 100240–100249 | T1033 System Owner/User Discovery | Discovery | 1 | **100240, 100241** | 🟡 Written, not yet deployed — see note 3 |
| 100250–100259 | T1016 Network Config Discovery | Discovery | 1 | **100250, 100251, 100252** | 🟡 Written, not yet deployed — see note 4 |
| 100260–100269 | T1547.001 Registry Run Keys | Persistence | 13 | — | Not started |
| 100270–100279 | T1053.005 Scheduled Task | Persistence | 1 | — | Not started |
| 100280–100289 | T1136.001 Create Local Account | Persistence | 1 | — | Not started |
| 100290–100299 | T1112 Modify Registry | Defense Evasion | 13 | — | Not started |
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
