# PROJECT PLAN

**Last updated:** 2026-08-10 — **ALL EXPERIMENTAL WORK COMPLETE.**
**Status:** **15 of 15 techniques · 7 of 7 tactics · 37 custom rules · 278 usable windows ·
2,683 labelled in-window alerts · Navigator layers and triage model complete.**

>
> Two figures in the text below are **superseded and not reproducible from the committed dataset**:
> the *3,217 alerts / ~14% deliberate* figure (a two-technique snapshot — the final export retains
> 4,976 alerts, 2,683 of them in-window) and any per-technique count, all of which were re-measured.

**Original header, 2026-08-06:** 2 of 15 techniques complete · 5 custom rules deployed ·
1,000-alert labelled dataset · committed `a7265c6`.


### Complete

| Technique | Default detection | Custom rules | Alerts (atk / ben) |
|-----------|-------------------|--------------|--------------------|
| T1087.001 Local Account Discovery | **Parent-only** — maps to T1087, level 3 | `100200` @ L10 | 50 / 15 |
| T1082 System Information Discovery | **Misattributed** — maps to T1087 + T1059.003, wrong technique *and* tactic | `100230`–`100233` @ L8 | baseline 147/26 · custom 187/29 |

**Zero correct default attributions across both techniques.** That is the finding the whole project rests on.

### Apparatus built and working

- **`scripts/Invoke-LabRun.ps1`** — UTC-bracketed detonation runner. `-Repeat` for sample size, randomised
  180–300 s inter-run gaps, Defender preflight that prompts on both classes, benign mirrors that reproduce
  ART's process lineage (`cmd.exe` bare-name via `Start-Process`, `&`-chained commands, child
  `powershell.exe` for cmdlets). Runs from `\\VBOXSVR\lab` and writes CSV rows straight into the repo.
- **`scripts/export_labelled_alerts.py`** — reads `alerts.json`, joins to detonation windows, applies the
  labelling rule and exclusion list, deduplicates `net1.exe`, splits counts by ruleset phase, flags
  class-exclusive rules, and measures forwarding lag with `--lag-report`.
- **`LABELLING_SCHEME.md`** — labelling rule with a *measured* buffer, full false-positive exclusion list
  with counts, and the harness-artefact analysis.
- **`PREFLIGHT_CHECKLIST.md`** — every fault below, with its signature and recovery.
- **`RULE_ID_REGISTER.md`** — ID blocks pre-allocated per technique, per-rule detail, deployment checklist.

---

## Six faults found this session — why two techniques took a day

Every one of these was **silent**. Nothing errored; the data was simply wrong.

| Fault | Symptom | Would have caused |
|-------|---------|-------------------|
| Blue's clock 4 h behind UTC | Timezone check passed; `synchronized: no` ignored | Every attack alert labelled 0 — empty positive class |
| Atomic test numbers not starting at 1 | *"Found 0 atomic tests applicable to windows"* | Looks identical to a broken ART install |
| Agent enrolment loop after snapshot | `agent_control` said **Active** the whole time | 10 detonation windows with no telemetry behind them |
| ART harness fingerprint | 146 attack alerts vs **1** benign | Classifier scores ~100% by learning the test tool |
| Label buffer 30 s vs 111 s p99 lag | Some windows showed "zero alerts" | 31% of true positives sitting in the negative class |
| Host disk 48 GB → 16 GB | None until a write fails | Detached `.vdi`, as on 2026-07-15 |

Found at technique 2, each cost a re-run. Found at technique 15, any one of them would have invalidated
the entire dataset — and the model trained on it.


```bash
sudo python3 ~/export_labelled_alerts.py --alerts /var/ossec/logs/alerts/alerts.json \
    --windows ~/detonation_log.csv --lag-report
```

### 1. T1033 System Owner/User Discovery — block `100240`–`100249`

The loop, now that it is proven end to end:

1. **Enumerate** test numbers — omit `-TestNumbers` and the script lists them. Never assume; they are
   global within a technique and do not start at 1.
2. **Baseline phase** — attack `-Repeat 5`, then benign `-Repeat 5`. Export. Record what the default does.
3. **Write rules** — Sigma first, then the Wazuh translation. Match on `originalFileName`, and add a
   command-line condition wherever the tool is multi-purpose.
4. **Deploy** — `wazuh-analysisd -t` must be clean, restart the manager, then **smoke-test that each rule
   actually fires**. A rule that silently never matches looks exactly like a technique that is not detected.
5. **Custom phase** — attack and benign again, export, fill the row.

Benign mirror is already written and lineage-correct: `Invoke-ViaCmd 'whoami & whoami /groups'`.

Expect the T1082 pattern to repeat — `whoami` is routine administration, so the custom rule should fire in
both classes. That is the result, not a defect.

### 2. T1016 Network Config Discovery — block `100250`–`100259`

Same loop. Mirror ready: `Invoke-ViaCmd 'ipconfig /all & route print & arp -a'`. Same EID and tactic as
T1033, so the rule pattern carries straight over.


**Techniques 5–15**, batched by Sysmon event ID so telemetry understanding is reused within a session:

| Order | Techniques | EID | Note |
|-------|-----------|-----|------|
| B | T1059.001, T1059.003 | 1 | Execution; broader command-line matching |
| C | T1053.005, T1136.001 | 1 | Persistence via process creation |
| D | T1547.001, T1112 | 13 | **First registry work** — new event type, do together |
| E | T1218.011, T1070.004 | 1, 11/23 | File-delete events are new |
| F | T1560.001 | 1/11 | Collection |
| G | **T1003.001** | 10 | Highest risk. Verify Defender off *first* |
| H | T1105 | 3 | Last — needs Kali booted; watch RAM |

**Then:**

1. **ATT&CK Navigator layers** — default coverage vs custom coverage, side by side. Strongest single visual
   for Chapter 4.
2. **Cmdlet-blind-spot rule for T1087.001** — `100201`, mirroring what `100233` does for T1082. Rule 100200
   detected nothing from `Get-LocalUser` / `Get-LocalGroup`.
3. **PowerShell Script Block Logging (EID 4104)** — the endpoint's own SCA scan reports it disabled. Without
   it, no rule can see interactively-typed cmdlets. Evidence-backed recommendation, already documented.
4. **Triage model** — Random Forest / XGBoost on the labelled export. Train on `rule_canonical` and
   `command_line_normalised`, not the raw columns. Report feature importance, and run the robustness check:
   retrain without rule-ID and command-line-path features and show performance holds.
5. **Write-up limitations**, all evidenced rather than asserted: Defender disabled, execution policy relaxed,
   single-node Wazuh with default credentials, no domain controller, the ART harness fingerprint, window
   durations varying with host memory pressure, and the 2026-08-06 clock and label-buffer incidents as
   data-integrity findings.

---

## The headline result so far

Default Wazuh gets the technique wrong in both cases measured — parent-only for one, entirely
misattributed for the other. Engineered rules fix the attribution. But those same engineered rules fire on
legitimate administration too: T1082's custom phase shows **7 rules shared between the attack and benign
classes and none exclusive to benign**, and rule 100200 fires 25 times on attack and 10 on benign.

Rule logic provably cannot separate the classes. That is the measured warrant for the ML triage layer — the
central claim of the dissertation, now backed by data rather than argument.

Supporting figure: of 3,217 alerts collected, **roughly 14% relate to anything anyone deliberately did. ** This was measured over two techniques and cannot be recomputed: `labelled_alerts.csv` is a filtered export, not raw SIEM volume, and the study-period total was never recorded. The reproducible replacement is rule `92213` — level 15, the maximum severity Wazuh can assign — firing **115 times across the retained dataset with exactly 5 true detections (4.3% useful)**.
The rest is vulnerability inventory, SCA policy scans, PowerShell's own housekeeping and the monitoring
agent watching itself.
