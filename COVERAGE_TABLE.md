# DETECTION COVERAGE RESULTS

This table is the primary Chapter 4 findings artefact (`LAB_HANDOVER_PHASE2.md` §7a).
One row per technique. Fill it as each technique completes — do not batch it up at the end.

**Legend**
`Default detected?` — Yes / Parent-only / No, using stock Wazuh rules with no customisation
`Level` — Wazuh alert level (1–15)
`Sub-technique gap?` — did the default map to the parent only, while the custom rule mapped to the sub-technique? This column is the measured version of the dissertation's central claim.

> **⚠️ Always enumerate atomic test numbers before running.** They are global within a technique across
> all platforms and do **not** start at 1. T1087.001 lists 8–11 under `windows`; tests 1–7 are
> Linux/macOS. Passing a wrong number returns *"Found 0 atomic tests applicable to windows platform"*,
> which is indistinguishable from a broken ART install and cost an investigation on 2026-08-05.
>
> **Listed-under-windows ≠ targets-Windows.** T1087.001 test 11 is enumerated under the `windows`
> platform because it *executes from* Windows, but it targets an **ESXi host** that this lab does not
> have. It will always fail. Check what each test actually touches, not just which platform ART files
> it under, and exclude off-target tests from the denominator.
>
> ```powershell
> Invoke-AtomicTest <ID> -ShowDetailsBrief
> ```
>
> Record the applicable numbers in the `Atomic avail.` column. Exclude tests targeting other platforms
> (ESXi, Azure, AWS) — they fail for environmental reasons and must **not** be recorded as detection
> failures. Note the exclusion so the coverage figures stay honest.

---

| # | Technique | Tactic | EID | Atomic avail. | Default detected? | Default rule / level / ATT&CK | Custom rule | Detected after? | Custom level | Sub-technique gap? | Alert count (atk/benign) | Notes |
|---|-----------|--------|-----|---------------|-------------------|-------------------------------|-------------|-----------------|--------------|--------------------|--------------------------|-------|
| 1 | T1059.001 PowerShell | Execution | 1 | | | | | | | | | |
| 2 | T1059.003 Cmd Shell | Execution | 1 | | | | | | | | | |
| 3 | T1087.001 Local Acct Discovery | Discovery | 1 | 8, 9, 10 (11 excl.) | **Parent-only** | 92031 / L3 / T1087 | 100200 | Yes | L10 | **Yes** | **50 / 15** (5+5 windows, +120s buffer) | Rule tightened 2026-08-05 to require an enumeration subcommand. **FP source: Wazuh agent's own SCA module runs `net user`** (parent `wazuh-agent.exe`) — see LABELLING_SCHEME.md. Test 11 excluded: targets ESXi, environmental — **not** a detection failure. **2026-08-06: rule confirmed firing on the atomic (L10, tags attack/discovery/local) AND on the benign admin mirror (`net user`, `net localgroup administrators`) at the identical level — rule-based detection cannot separate the two classes. This is the measured motivation for the ML triage layer, not a rule defect.** Final counts from the balanced 5+5 run at 09:51–10:11 (Defender off both sides, mirror matching ART's `cmd.exe` lineage, +120s label buffer): **50 attack / 15 benign**, i.e. 10 and 3 alerts per window with no variance. Rule **100200 fires in both classes — 25 attack / 10 benign** — so the custom rule cannot separate legitimate account enumeration from the atomic, which is the intended finding. Earlier readings of this row (10/4, then 10/17) were wrong for two reasons since corrected: the attack class had only 1 window against benign's 5, and the +30s label buffer discarded late alerts — 4 of 5 benign windows appeared to produce *zero* alerts purely because theirs arrived 35–79s after `window_end`. **Alert volume is inflated 2× by `net.exe` spawning `net1.exe`** with identical arguments — every `net` invocation yields two process-creation events and therefore two alerts (5 atk invocations → 10; 2 benign → 4). Deduplicate on this before quoting alert volumes or building count-based ML features. **Coverage gap — rule 100200 is blind to cmdlet-based enumeration:** test 9's `Get-LocalUser` / `Get-LocalGroup` / `Get-LocalGroupMember` produced **no** alerts, because the rule keys on `net` with an enumeration subcommand. An adversary using only PowerShell cmdlets for the same sub-technique evades it. Candidate follow-up rule against Sysmon EID 1 PowerShell telemetry or Script Block Logging |
| 4 | T1082 System Info Discovery | Discovery | 1, 11 | 1,7,9,11,27,29,30,34,35,36,37,38,39,40 (14 of 30) | **No** | 92052 / L4 / **T1059.003**; 92032 / L3 / **T1087** | **100230, 100231, 100232, 100233** | **Yes — all four fire** | L8 | **N/A — T1082 has no sub-techniques; the gap here is worse, see notes** | baseline **147 / 26** · custom **187 / 29**, of which custom-rule **59 / 16** | **DEFAULT MISATTRIBUTES RATHER THAN MISSES.** No default rule maps to T1082 at all. What fires is generic execution telemetry: 92052 (`cmd.exe` spawned by a non-explorer/non-cmd parent → T1059.003) and 92032 (child of `cmd.exe /C` → **T1087 + T1059.003**). So T1082 activity is actively attributed to **T1087 Account Discovery and T1059.003 Command Shell** — wrong technique *and* wrong tactic (Execution, not Discovery). For an analyst this is worse than silence: it points the investigation at the wrong behaviour. Stronger finding than T1087.001's parent-only loss of precision. **⚠️ Rule 92213 (L15, T1105) is 100% harness-induced FP** — its pcre2 matches `.ps1` under `\AppData\Local\Temp\`, and PowerShell writes `__PSScriptPolicyTest_<rand>.ps1` there on every script invocation, so `Invoke-LabRun.ps1` triggers max-severity alerts by existing. Filter on `targetFilename`, not rule ID. See LABELLING_SCHEME.md. Excluded 14–23 (WinPwn — downloads external tooling, spans dozens of techniques), 24 (Azure), 31/32 (ESXi), 10 (Griffon JScript — different mechanism, revisit), 28 (hangs to ART's 120s timeout, inflating the window to 2m14s). **⚠️ ALERT COUNTS INVALID — BENIGN CLASS MUST BE RE-RUN.** 146 attack vs 1 benign, and that lone benign alert was rule 60702 (VSS idle timeout), unrelated ambient noise: the mirror produced **zero** technique-relevant alerts. Cause is a harness artefact, not a detection result — ART executes command_prompt tests as `cmd.exe /c "<cmd>"`, while the mirror ran the same commands directly from `powershell.exe`. Both rules that fired key on cmd.exe lineage rather than on discovery behaviour (92032 requires `parentImage=cmd.EXE` + `parentCommandLine` containing ` /C `; 92052 requires `originalFileName=cmd.EXE` with a non-explorer/cmd parent). Attack-side parents were 75 `cmd.exe` / 70 `powershell.exe`; benign side had **no** `cmd.exe` at all. So the classes were perfectly separable on "was cmd.exe involved" — a classifier would score ~100% by learning Atomic Red Team's wrapper and the FP-reduction claim would be vacuous. `Invoke-LabRun.ps1` mirrors now route native CLI through `cmd.exe /c` with `&`-chained commands to match ART's process lineage, and cmdlets through a child `powershell.exe`. **Final counts after three rounds of fixing: 146 attack / 25 benign, 5+5 windows, Defender off on both sides.** Rule 92032 now fires in **both** classes (75 atk / 15 ben) so the classes are genuinely confusable. Two residual harness artefacts remain and are handled at feature-extraction time rather than in the lab: (i) `92052` attack-only vs `92004` benign-only — same underlying event, differing only because ART invokes `cmd.exe` by bare name while PowerShell resolves the full path, so both are collapsed via `rule_canonical` and command lines are path-normalised; (ii) `92027` attack-only (5 obs.), since ART's PowerShell executor spawns a child `powershell.exe` — mirror now does the same, so this closes on the next run. **Volume asymmetry (146 vs 25) is a function of test-set size — 14 atomic tests against 4 mirror command groups — not of behaviour; normalise or exclude count features.** See BENIGN_ACTIVITY_PROTOCOL.md §2a. — **RESULT AFTER DEPLOYING 100230–100233 (measured 2026-08-06, 5+5 windows, phase `custom`):** all four rules fire, in **both** classes — atk 100232×15, 100231×10, 100230×5, 100233×2; ben 100230×5, 100231×4, 100232×4, 100233×4. **35 process-creation events are now detected that the default ruleset saw not at all** — `hostname.exe` and `reg.exe` host-identity queries produced zero alerts in the baseline phase, so this is added visibility rather than relabelling; a further 4 `wmic.exe` events fire 100231 *and* 92032 (dual attribution, correct technique now present alongside the generic one). **Counts above are at the corrected +120s label buffer.** An earlier read of this row reported custom-phase attack as 117 and blamed a drop from baseline on memory pressure causing incomplete atomics — **that was wrong.** The apparent drop, and the per-window variance behind it (14/18/35/21/29), were entirely an artefact of the old +30s buffer discarding late-arriving alerts. Measured forwarding lag reaches p99 111s and max 201s, so 31% of alerts were falling outside their own window. At +120s the custom phase reads **187** attack alerts against baseline's 147 — higher, not lower. See LABELLING_SCHEME.md for the lag distribution and buffer-sensitivity table. Established claims: (i) default attributes T1082 **zero** times across 5 baseline windows, (ii) all four custom rules detect it through four distinct mechanisms, (iii) all four also fire on legitimate administration — the `custom` phase shows **7 rules shared between classes and none exclusive to benign** — so rule logic alone cannot separate them, which is the measured warrant for the ML triage layer |
| 5 | T1033 System Owner/User | Discovery | 1 | | | | | | | | | |
| 6 | T1016 Network Config Discovery | Discovery | 1 | | | | | | | | | |
| 7 | T1547.001 Registry Run Keys | Persistence | 13 | | | | | | | | | |
| 8 | T1053.005 Scheduled Task | Persistence | 1 | | | | | | | | | |
| 9 | T1136.001 Create Local Account | Persistence | 1 | | | | | | | | | |
| 10 | T1112 Modify Registry | Defense Evasion | 13 | | | | | | | | | |
| 11 | T1218.011 Rundll32 | Defense Evasion | 1 | | | | | | | | | |
| 12 | T1070.004 File Deletion | Defense Evasion | 11/23 | | | | | | | | | |
| 13 | T1003.001 LSASS Memory | Credential Access | 10 | | | | | | | | | ⚠️ Highest risk of being blocked |
| 14 | T1560.001 Archive via Utility | Collection | 1/11 | | | | | | | | | |
| 15 | T1105 Ingress Tool Transfer | Command & Control | 3 | | | | | | | | | Transfer from Kali over labnet |

---

## Summary counters (recompute as you go)

| Metric | Value |
|--------|-------|
| Techniques attempted | **2 / 15** (T1087.001, T1082) |
| Detected by default Wazuh **at the correct technique** | **0** — T1087.001 parent-only (T1087), T1082 misattributed to T1087 + T1059.003 |
| Detected after custom rules | **2** |
| Custom rules deployed | **5** — 100200, 100230, 100231, 100232, 100233 |
| **Precision gaps closed** | **2** (1 parent-only → sub-technique, 1 misattribution → correct technique) |
| Techniques dropped / failed | 0 |
| Sysmon event types exercised | 1 of 5 (EID 1) |
| Tactics covered | 1 of 7 (Discovery) |
| Labelled dataset size | **1,000 alerts** — 454 in-window, 546 out |
| Detonation windows recorded | 61 rows, **30 usable**, 31 superseded with documented reasons |
| Alerts excluded as non-behavioural | **1,277** — 642 CVE inventory, 468 SCA, 93 harness, 74 self-monitoring |
| Duplicate alerts removed | 73 (`net.exe` → `net1.exe` pairing) |

**Signal-to-noise, measured:** of 3,217 alerts read, 867 came from other agents, 1,277 were excluded as
non-behavioural, and 454 were attributable to a detonation window. Roughly **14% of all alerts related to
anything anyone deliberately did.** That is the alert-fatigue result the triage layer answers.

## Dropped or modified techniques

Record every deviation from the planned set and the reason. These become methodology and limitations
notes in the dissertation — an unexplained gap between the planned and delivered technique set is the
kind of thing an examiner asks about.

| Technique | Planned | What happened | Substituted with | Reason |
|-----------|---------|---------------|------------------|--------|
| | | | | |
