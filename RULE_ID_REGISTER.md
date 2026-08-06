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
| 100240–100249 | T1033 System Owner/User Discovery | Discovery | 1 | — | Not started |
| 100250–100259 | T1016 Network Config Discovery | Discovery | 1 | — | Not started |
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
