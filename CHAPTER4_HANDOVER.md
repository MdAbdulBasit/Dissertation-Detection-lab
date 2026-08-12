# CHAPTER 4 HANDOVER — analysis phase complete

**Abdul Basit Mohammed (c5038891) · Sheffield Hallam · Supervisor: Dr Sina Pournouri**
**Prepared 2026-08-10.** Everything below is regenerated from committed artefacts, not transcribed.

> **Purpose.** This document answers the checklist from the writing session and states, item by item,
> what exists and how it was verified. **All three open decisions are now RESOLVED** — the failure-mode
> taxonomy is fixed at eight, the alert-fatigue figure is `92213` at 115/5, and the FP-reduction result
> leads with the mechanism. See §11. **Nothing here is awaiting your judgement; the remaining work is
> selection — deciding what fits a 2,000–2,500 word chapter.**

---

## 1. Status

**All experimental work is complete. Nothing remains to run in the lab.**

| | |
|---|---|
| Techniques | **15 / 15** |
| Tactics | **7 / 7** — Execution, Discovery, Persistence, Defense Evasion, Credential Access, Collection, C2 |
| Custom Wazuh rules deployed | **37** (`100293` retired as unreachable, ID reserved) |
| Detonation windows logged | 344 |
| — superseded / aborted, each with a written reason | 66 |
| — **usable** | **278** |
| — of those, produced **no alert at all** | **19** |
| Alerts retained by the export | **4,976** |
| — **in-window (the labelled dataset)** | **2,683** — 1,919 attack / 764 benign |
| — out-of-window | 2,293 |
| Windows represented in the dataset | 259 |

---

## 2. Checklist response

| Requested | Status | Where |
|---|---|---|
| The eight failure modes described | ✅ **Locked at eight**, each with its own evidence row — §3 | `COVERAGE_TABLE.md` |
| The sensor-ceiling result | ✅ Complete, three techniques | §4 |
| Coverage table | ✅ Complete, all 15 rows. **Summary counters were stale, fixed today** | `COVERAGE_TABLE.md` |
| Dataset stats incl. the ~14% figure | ✅ Stats verified. **~14% dropped; replaced by `92213` 115/5** — §5.2 | §5.2 |
| ML metrics with the robustness check | ✅ Complete, and stronger than required | §6 |
| Limitations material | ✅ Complete | §9 |
| *Your guidance:* robustness without rule-ID/path features | ✅ **Done — performance holds.** §6.2 | `ml/README.md` |
| *Your guidance:* confusion matrices | ✅ §6.4 — **and now a figure** | `ml/figures/fig1` |
| *Your guidance:* feature importance rankings | ✅ §6.7 — **and now a figure** | `ml/figures/fig2` |
| *Your guidance:* Navigator layers side by side | ✅ Rendered and verified | `navigator_layers/figures/` |
| *Your guidance:* §3.4 baseline — rule level alone, no ML | ✅ **Built today. Criterion met.** §6.6 | |
| *Your guidance:* running note of surprises | ✅ §10 | |

---

## 3. The default-ruleset failure modes

✅ **RESOLVED — the taxonomy is fixed at EIGHT and this table is canonical.** The repository previously
said five, seven and eight in different places; `COVERAGE_TABLE.md` still says *"seven failure modes"*
in one place and *"the most insidious of the five"* in another, both of which are superseded by this
list. "Partial coverage" is treated as a variant of sibling misattribution and "latent coverage" is
folded into the sensor ceiling (§4). Each of the eight has its own distinct mechanism and evidence.

| # | Failure mode | What it means | Evidence |
|---|---|---|---|
| **1** | **Blind** | No alert carries the technique **or its parent**. Not a labelling problem — nothing fires. | 7 of 15 techniques at baseline |
| **2** | **Parent-only attribution** | Behaviour detected, but tagged with the parent technique, losing the sub-technique. | `92031` → `T1087` for T1087.001: **25 attack / 10 benign** |
| **3** | **Outright misattribution** | Activity visible but assigned to a different technique entirely. | T1082, T1016 → `T1059.003`, `T1087`, `T1574.001` |
| **4** | **Wrong tactic** | Correct that *something* happened, wrong about what it means. | T1053.005 persistence reported as **Execution** |
| **5** | **Sibling misattribution** | Detected, described correctly in prose, tagged as a *neighbouring* technique. | T1033 `whoami` → `T1087` via `92032` |
| **6** | **Suppressed severity** | Fires at a level too low to surface in triage. | T1547.001 — and the first technique where **benign is noisier than attack** (27 vs 31) |
| **7** | **False precision** | Fires with a confident, specific claim the evidence does not support. | `92041` matches **any** `reg add … /d`; asserted T1027 obfuscation in **45 of 45** |
| **8** | **Argument-order evasion** | Correct rule, defeated by how a human types the command. | `92040` (L12) needs `add\s`. Atomic `net user /add NAME PASS` fires; mirror `net user NAME PASS /add` does **not** |

### 3.1 ⭐ The cleanest single result in the study — and it was nearly lost

For T1087.001 the baseline and custom phases produce **identical detection volumes** with different
attribution:

| Phase | Rule | ATT&CK tag | Attack | Benign |
|---|---|---|---|---|
| baseline | `92031` | **T1087** (parent) | 25 | 10 |
| custom | `100200` | **T1087.001** (sub) | 25 | 10 |

**The custom rule added no detections. It re-attributed the same ones to the correct sub-technique.**
That is the dissertation's central claim with the usual confound — different alert volumes between
phases — absent by construction.

⚠️ **This was disclaimed in `COVERAGE_TABLE.md` for four days as "not reproducible from the committed
dataset".** The disclaimer was an artefact of a bug: the export's `net1.exe` de-duplication keyed on
process image, deleting every `net1` alert even when no `net.exe` parent existed. `92031` was one of
three vendor rules erased by it (with `92039`, `92040`). Fixed, verified, and the note corrected today —
but the original text is retained in the table as a methodological record. **A correct conclusion was
downgraded because tooling had silently removed the evidence.**

---

## 4. The sensor-ceiling result

**Three techniques could not be detected by any rule, because the telemetry did not exist.** The
constraint was the sensor, not the detection logic.

| Technique | What was missing | Fix |
|---|---|---|
| **T1112** Modify Registry | Default Sysmon config did not emit the registry events | Widened `sysmonconfig.xml` |
| **T1070.004** File Deletion | EID 26 `FileDeleteDetected` **silently discarded** | Config declared `schemaversion="4.50"`; needs **4.60+** |
| **T1003.001** LSASS Memory | Default config did not emit EID 10 process-access | Widened config |

### 4.1 The T1070.004 sub-result is the most quotable

Sysmon **printed *"Configuration file validated"*** and then discarded the events, because the schema
version predated the feature. No error, no warning. Found only by probing for the event ID directly
after rules that should have fired did not.

**A validated sensor configuration is not a working one.** This is a detection-engineering finding
independent of ATT&CK and worth its own paragraph.

### 4.2 The sharpest intent-versus-mechanism pair

T1003.001 is the strongest case in the study that **rules cannot encode intent**. The benign mirror runs
a **character-identical command line** to the attack. Only the sensor's `targetImage` field distinguishes
them — nothing in the command line does. `92900` is level 12 and correctly mapped, and still cannot
separate the classes.

Contrast with **T1070.004**, where `100310`/`100311` read the EID 1 command line and work under the
**default** sensor with no config change. Same tactic, opposite conclusion about where the ceiling sits.

---

## 5. Dataset statistics

### 5.1 Verified figures — use these

| | |
|---|---|
| Alerts retained by the export | **4,976** |
| In-window (labelled dataset) | **2,683** — 1,919 attack (71.5%) / 764 benign (28.5%) |
| Out-of-window | 2,293 |
| Usable detonation windows | **278** of 344 logged; 66 superseded/aborted |
| Windows producing ≥1 in-window alert | 259 |
| **Usable windows producing NO alert at all** | **19** |
| Label buffer | +120 s, sized from measured forwarding lag (`LABELLING_SCHEME.md`) |
| Custom rules that fired | 34 of 37 |
| **…of those, that also fire on benign activity** | **24 of 34** |

**"24 of 34 custom rules fire on benign administrator activity too" is the strongest single sentence
available for the ML argument.** The older documents say "8 of 12" — that was true when written.

### 5.2 ✅ RESOLVED — the alert-fatigue statistic, and what replaced the ~14% figure

**Decision: the ~14% figure is dropped. Rule `92213` replaces it.** Use the statistic below.

#### ⭐ The alert-fatigue result, in one number

> **Rule `92213` — level 15, the maximum severity Wazuh can assign — fires 115 times across the
> retained dataset. Exactly 5 of those are genuine detections of the technique it is mapped to.
> 4.3% useful.**

Full breakdown, recomputable from `data/labelled_alerts.csv` in one line:

| `92213` alerts | Count | What they are |
|---|---|---|
| **Genuine T1105 detections** | **5** | The only correct firings, in T1105 attack windows |
| Outside any detonation window | 84 | Neither class; nobody was doing anything deliberate |
| Benign mirror | 21 | 10 T1070.004 baseline · 10 T1070.004 custom-sensor · 1 T1053.005 |
| T1059.003 attack windows | 5 | Attack class, but T1105 is not the technique under test |
| **Total** | **115** | |

The rule's description is *"Executable file dropped in folder commonly used by malware."* It is a
maximum-severity alert that is **wrong 96% of the time**, and an analyst working strictly top-down by
severity would open all 115.

⚠️ **A previous version of this section proposed `92213` at "551 fires, 5 detections". That figure is
not reproducible** — it predates the exporter's OS-background filters and was carried forward from
`COVERAGE_TABLE.md`'s summary-counter row. **It had exactly the same defect as the ~14% figure it was
meant to replace**, which is why every number in this document is now recomputed at the point of use.

#### Why ~14% had to go

The claim *"of 3,217 alerts collected, roughly 14% relate to anything anyone deliberately did"* comes
from `PROJECT_PLAN.md` and dates from a snapshot when **only two techniques had been measured**:

- `labelled_alerts.csv` is the **filtered export** (alerts near windows, minus OS-background artefacts),
  not raw SIEM volume. Its in-window share is **53.9%** — a different quantity, not a corrected one.
- `alert_counts.csv` is a per-rule breakdown of the same 4,976 alerts, not total SIEM volume.
- The total alert count for the full study period was never recorded.

If a proportion is wanted alongside `92213`, the defensible phrasing is: *"of 4,976 alerts retained
around detonation windows, 2,683 (53.9%) fall inside one; the remainder is vulnerability inventory, SCA
policy scans, PowerShell housekeeping and the agent monitoring itself."* **Do not carry 14% forward.**

---

## 6. Machine-learning results

Everything below: `scripts/triage_model.py` → `ml/triage_results.csv`, narrative in `ml/README.md`.
Grouping unit is the **detonation window**; no window spans train and test.

### 6.1 Headline

| Split | Features | atk F1 | ben F1 | **macro F1** | PR-AUC |
|---|---|---|---|---|---|
| GroupKFold by window | A — everything | 0.883 | 0.764 | **0.823** | 0.977 |
| GroupKFold by window | **B — no rule identity** | 0.844 | 0.724 | **0.784** | 0.973 |
| GroupKFold by window | C — sanitised text only | 0.814 | 0.708 | **0.761** | 0.962 |
| LeaveOneTechniqueOut | A — everything | 0.745 | 0.375 | **0.560** | 0.736 |
| LeaveOneTechniqueOut | B — no rule identity | 0.706 | 0.372 | **0.539** | 0.736 |
| LeaveOneTechniqueOut | C — sanitised text only | 0.660 | 0.420 | **0.540** | 0.721 |

### 6.2 ⭐ The robustness check — performance holds

You asked specifically whether removing rule-ID and path features collapses performance.

**It does not. 0.823 → 0.784, a loss of 0.039, against a fold standard deviation of 0.071.**

This was the main worry: `92052` alone is 359 attack / 2 benign, so a model could have scored well by
memorising which rule fired. It did not need to. Feature set **C**, sanitised command-line text with no
rule identity and no process paths at all, still reaches **0.761**.

**Report B as the headline, not A.** A is included to show what the leak would have been worth.

### 6.3 Variance — the headline is a distribution

**macro F1 0.783, sd 0.071, range 0.681–0.856** over 3 seeds × 5 folds = 15 fits.
The worst fold still clears every rule-based baseline in §6.5.

### 6.4 Confusion matrix — the error balance macro F1 hides

Random Forest, B_no_rule, GroupKFold, threshold 0.5:

| | predicted benign | predicted attack |
|---|---|---|
| **actual benign** (764) | 701 | **63** false alarms |
| **actual attack** (1,919) | **471 missed** | 1,448 |

**Misses 24.5% of attacks; false-alarms on 8.2% of benign.** For triage that is the wrong way round —
a false positive costs minutes, a false negative is an unexamined intrusion. **Do not quote the 0.5
threshold as an operating point.** See §6.6.

### 6.5 Rule-based baselines — the comparison the argument needs

| Triage heuristic | macro F1 |
|---|---|
| severity ≥ 6 | **0.428** ← best rule heuristic |
| severity ≥ 8 | 0.426 |
| severity ≥ 10 | 0.367 |
| severity ≥ 12 | 0.281 |
| **Always guess "attack"** | **0.417** |
| Alert tagged with the correct technique (*perfect attribution*) | **0.412** |
| **Any of the 37 engineered rules fired** | **0.379** |
| **Model (B_no_rule)** | **0.784 ± 0.071** |

**Two of the three rule-based heuristics lose to escalating everything.** Perfect ATT&CK attribution is
worth *nothing* for triage. This is the Navigator finding reproduced by an independent method.

### 6.6 ⭐⭐ The §3.4 success criterion — met

Your criterion: *"a measurable false-positive reduction against a detection-only baseline, **without loss
of recall**."* Detection-only baseline = **rank by Wazuh rule level alone, no ML**. Recall held at the
baseline's own value in every row.

| Detection-only baseline | its recall | its FPs | Model @ ≥ same recall | model FPs | **FP reduction** |
|---|---|---|---|---|---|
| **rule level ≥ 4** | **0.691** | **605** | thr 0.79 (recall 0.706) | **2** | **99.7%** |
| rule level ≥ 5 | 0.397 | 354 | thr 0.95 (recall 0.601) | 1 | 99.7% |
| rule level ≥ 8 | 0.369 | 316 | thr 0.99 (recall 0.372) | 0 | 100% |
| rule level ≥ 10 | 0.195 | 140 | thr 0.99 | 0 | 100% |
| rule level ≥ 12 | 0.063 | 32 | thr 0.99 | 0 | 100% |

**At the baseline's best achievable recall (69.1%), the model matches it with 2 false positives instead
of 605.** No detection traded away. **Criterion met.**

#### Why it is so large — state the mechanism, or the number looks implausible

| Rule level | Attack | Benign | % attack |
|---|---|---|---|
| 3 | 593 | 159 | 78.9% |
| 4 | 565 | 251 | 69.2% |
| 5 | 38 | 33 | 53.5% |
| 8 | 328 | 170 | 65.9% |
| 10 | 254 | 108 | 70.2% |
| 12 | 111 | 11 | **91.0%** |
| **15** | **10** | **21** | **32.3%** |

- **Level ≥ 4 flags 79.2% of benign but only 69.1% of attack** — as a ranking signal it is *worse than
  useless*; filtering on it discards attacks faster than noise.
- **Level 15, the maximum Wazuh can assign, is 32.3% attack — majority false positive.** An analyst
  working strictly top-down by severity starts with the least reliable alerts in the queue.
- **Level 12 is the only informative band** (91.0% attack) and holds 111 of 1,919 attack alerts — 5.8%.
- **The baseline cannot exceed 69.1% recall at any setting**, because 593 attack alerts sit at level 3.

**The reduction is large because severity carries almost no signal — not because the model is
remarkable.** Frame it that way and it is unassailable.

#### But the deployable operating point is more modest — report both

| Threshold | Reviewed | % of queue | Missed | Precision | Recall |
|---|---|---|---|---|---|
| **0.20** | 2,273 | **84.7%** | **20** | 0.835 | **0.990** |
| 0.25 | 2,179 | 81.2% | 69 | 0.849 | 0.964 |
| 0.40 | 1,877 | 70.0% | 218 | 0.906 | 0.886 |
| 0.50 *(default)* | 1,511 | 56.3% | **471** | 0.958 | 0.755 |

**Holding recall at 99%, the workload saving is ~15%, not an order of magnitude.** Both results are
true: a 99.7% FP reduction *at the baseline's recall*, and a ~15% queue reduction *at high recall*. They
answer different questions and the chapter should carry both.

### 6.7 Feature importances — top signals after sanitisation

`exe` (71.3% attack, n=1244) · `schtasks` (52.6%, n=95) · `powershell` (73.7%, n=491) ·
`net user` (59.2%, n=125) · `wmic` (88.0%, n=150) · `_img=curl.exe` (92.3%, n=65) ·
`delete` (30.8% — benign-leaning) · `reg add` (58.2%)

**All mixed-class.** No single token approaches 0% or 100% — which is the check that the sanitisation
held. Before sanitisation the top features were `calc exe` at **100% attack** and `noprofile command`
at **2.1%**, both pure harness artefacts.

### 6.8 Random Forest vs XGBoost

| Classifier | GroupKFold | LeaveOneTechniqueOut |
|---|---|---|
| Random Forest | **0.784** | 0.539 |
| XGBoost | 0.780 | **0.575** |

**Indistinguishable within techniques** (0.004, against sd 0.071). XGBoost is modestly better on unseen
techniques and still fails there. **Model selection was not the bottleneck**; feature representation and
leakage removal were. Both `README.md` and `PROGRESS_SUMMARY.md` promised this comparison — it is done.

### 6.9 Per-technique generalisation — erratic, not uniformly poor

LeaveOneTechniqueOut, B_no_rule. Best **T1070.004 0.822**, T1053.005 0.730, T1059.001 0.712.
Worst **T1136.001 0.288** — *the technique with the most data* (478 alerts). Benign F1 is exactly
**0.000** for T1016 and T1059.003: the model calls everything an attack.

The ~0.54 average hides a 0.288–0.822 range. Say so.

---

## 7. ATT&CK Navigator result

| | Default | Engineered |
|---|---|---|
| Blind | **7** | **0** |
| Parent only / misattributed | 1 | 0 |
| Detected at correct technique | 4 | **14** |
| Detected **and** never fires on benign | **3** | **1** |

**Thirty-seven rules eliminated every blind spot and did not improve discrimination.** Two of the
default's three are qualified on the layer itself (T1033 partial coverage; T1136.001 is argument order,
not intent), so **the honest reading is one genuine discriminator before and one after — both T1105.**

Figures: `navigator_layers/figures/01_default_ruleset_v19.svg` and `02_custom_ruleset_v19.svg`.
Both verified to contain all 15 techniques.

⚠️ **Quote technique counts (7/1/4/3 → 0/0/14/1) from `COVERAGE_TABLE.md`, never coloured cells from the
images.** The v19 layers draw multi-tactic techniques once per tactic, so 15 techniques render as 19
cells. An examiner who counts cells will get a different number from your text.

⚠️ **ATT&CK v19 (28 April 2026) split Defense Evasion into Stealth and Defense Impairment**, after data
collection. The study is mapped to v14; both layer versions are committed. Worth a limitations
paragraph — a coverage figure dates the moment the framework moves.

---

## 8. The convergent finding

Across fifteen techniques, **every rule that separated the classes encoded *what was done to what*;
every rule that failed encoded *how*.**

Three independent methods agree:

1. **Navigator** — discriminating detections went 3 → 1 while blind spots went 7 → 0.
2. **Rule baselines** — the 37 rules as a triage signal score 0.379, *below* escalating everything.
3. **Per-rule counts** — 24 of the 34 custom rules that fired also fire on benign administration.

### 8.1 ⭐ T1560.001 — the finding isolated inside a single technique

The cross-technique pairs vary the technique, the sensor and the day. **This one holds all of them
constant** and varies only what the rule keys on, which makes it the best-controlled comparison in the
study.

| Detection keys on | Rules | Attack | Benign |
|---|---|---|---|
| **Mechanism** — the archiving utility itself | `100330` + `100332` | **5** | **5** |
| **Object** — whether the command line names a credential store | `100332` alone | **5** | **0** |

Same binary (`makecab.exe`), same technique, same ruleset, same author, same day. The mechanism is
present in both classes; **only the object separates them.**

**Tier-independent confirmation.** In the **baseline**, before any custom rule existed, vendor rule
`92032` fired **5 attack / 5 benign** on `makecab.exe`, and the raw telemetry shows `makecab.exe`
process creations at **5 attack / 5 benign in both phases**. The 5/5 does not depend on our rules or on
Wazuh's level ordering.

⚠️ **Do not quote the raw per-rule counts.** `100330` reads 0/5 and `100331` reads 0/5, and **neither
means the rule failed to fire on attacks**:

- **`100330` was displaced** (artefact cause 3). The attack ran `makecab.exe C:\Temp\sam.hiv
  C:\Temp\art.zip`; `100330` (L8) matched it, but `100332` (L12) matched the same event and outranks it.
  Hence the summed row above.
- **`100331` is mirror scope** (artefact cause 1, in the *opposite* direction to the study's other
  cause-1 rules). The mirror archives twice per run — `makecab` **and** `powershell Compress-Archive` —
  while the atomic only ever runs `makecab`. `100331` could not have fired on the attack under any
  ruleset, so it says nothing about discrimination.

Presenting either 0/5 as evidence of discrimination would commit precisely the error the artefact
taxonomy in `COVERAGE_TABLE.md` exists to prevent — conflating cause (3) or (1) with cause (4).

---

## 9. Limitations

- **259 windows is the real sample size**, not 2,683 alerts. Alerts within a window are near-duplicates.
- One endpoint, one OS build, **one operator's command style**.
- The benign mirror is *designed* to resemble the attack. A production benign distribution is far wider
  and messier, so real-world precision would be **lower**.
- **72/28 attack-to-benign is an artefact of running attacks deliberately.** A real queue is
  overwhelmingly benign. **Every precision figure here is an upper bound.**
- Deleting harness tokens removed some legitimate signal along with the leak (an attacker really might
  use `-EncodedCommand`). Biases *against* the model — the safe direction.
- **Teardown asymmetry**: the benign mirror cleans up inside the labelled window; `-Cleanup` runs
  outside it. Measured cost 0.001 macro F1, but the design flaw is general.
- No hyperparameter search — defensible in hindsight, since XGBoost matched RF to 0.004.
- **T1016**: `100251`/`100252` are attack-only because of *mirror scope*, not detection quality. The
  mirror ran `ipconfig`/`route`/`arp` but not `netsh show`/`net config`. Exclude from separability claims.
- **ATT&CK v19 drift** (§7).
- **Rule `100201`** (T1087.001 PowerShell-cmdlet blind spot) documented but not built — future work.

### 9.0 ⭐ Silent tooling failure is the dominant threat to a study like this

**Not a list of mishaps — a methodological finding, and the one most likely to transfer.** Across the
project, **seven distinct defects reached a committed artefact. Not one announced itself.** Every tool
involved reported success.

| # | What failed | What the tool reported | How it was caught |
|---|---|---|---|
| 1 | Sysmon discarded every `FileDeleteDetected` event — schema declared `4.50`, feature needs `4.60+` | ***"Configuration file validated"*** and *"Configuration updated"* | Probing for EID 26 directly after rules that should have fired didn't |
| 2 | Export de-duplication deleted three vendor rules (`92031`, `92039`, `92040`) by keying on process image | Ran clean; row counts merely looked lower | Noticing a rule cited in the write-up had no rows |
| 3 | Four stale counts (`551`, `258`, `4,636`, `~14%`) survived pipeline changes, one in a *summary-counter* row | Nothing checks prose | Recomputing before quoting |
| 4 | Navigator layers rendered **5 of 15** techniques — sub-techniques need an expanded parent row | Valid JSON, correct scores, correct tactics | Opening the file in the Navigator |
| 5 | First SVG export contained **5 of 15** techniques — exports what is on screen | Download succeeded | Grepping the SVG for expected labels |
| 6 | Three of six ML figures unusable — overlapping labels | Script logged success six times | Rendering to PNG and looking |
| 7 | Two coverage-table rows broken — one split across twelve lines, one with two extra columns | GitHub renders the mess without complaint | Counting cells on unescaped pipes |

**The pattern: validation checks structure, and structure was almost always fine. What failed was
meaning — and meaning is only visible in the rendered output.** A config that loads is not a config
that works; valid JSON is not a readable figure; a script that exits zero has not necessarily drawn
anything legible.

Three defences emerged, and they are the transferable contribution:

- **Probe for the effect, never trust the acknowledgement** (defect 1).
- **Recompute every number at the point of use; treat prose as a pointer, not a source** (defects 2, 3).
- **Render and look — there is no substitute** (defects 4, 5, 6, 7).

`scripts/check_docs.py` mechanises what can be mechanised. **It cannot catch defects 4, 5 or 6**, which
is precisely the point: the residual risk in this class of work is not analytical, it is
infrastructural, and it is only reachable by inspecting output a human can read.

### 9.1 Four layers of data leakage, each of which looked like signal

**This is the most transferable methodological finding in the project.**

1. **Names** — 18% of alerts carried a give-away token: `atomic` (127/0), `deleteme` (64/0),
   `T1xxx` (231/5), `benign` (0/138) — the class name, literally in the command lines.
2. **Habits** — after stripping names, top features became `noprofile command` (2.1% attack) and
   `calc exe` (**100%** attack). That is *my harness's invocation style* and ART's demo payload, not
   attacker behaviour. The model was recognising **who wrote the command**.
3. **The placeholder itself** — substituting `HARNESSFLAG` did not fix layer 2, it *renamed* it. The
   marker stayed a top feature at 11% attack. **A placeholder cannot sanitise a token only one class
   emits.** The tokens had to be deleted outright.
4. **Experimental design** — `user delete`, n=27, **0.0% attack**, found *after* the leakage section was
   written. Only the benign mirror tears down inside the measured window. Measured by removing the
   alerts and refitting: **0.784 → 0.783**. Immaterial, but no sanitiser would ever have caught it.

**Leak-hunting has no natural stopping point. The honest claim is "none remaining that I could find",
never "none".**

---

## 10. Surprises — Chapter 5 discussion material

1. **Wazuh severity is slightly anti-correlated with ground truth.** Level ≥ 4 flags a higher share of
   benign (79.2%) than attack (69.1%). Level 15 is 32.3% attack. Nobody expects the severity field —
   the primary triage mechanism in every SIEM — to be actively misleading.
2. **Precise rules *displaced* wrong ones rather than adding to them.** T1016: `92032` fell 23 → 5 while
   33 correct attributions appeared — misattributed alerts dropped ~52%. Repeated across techniques.
   Better rules make the queue *smaller*, which was not the expectation.
3. **Perfect ATT&CK attribution is worth nothing for triage** (0.412, below guessing at 0.417). The
   entire premise of ATT&CK-mapped detection is *attribution*, and attribution does not help
   prioritisation. This is the most uncomfortable result in the project and the most interesting.
4. **A validated Sysmon config silently discarded events** for a schema-version mismatch, printing
   *"Configuration file validated"*.
5. **XGBoost changed nothing.** Effort conventionally spent on model selection was the least productive
   thing available.
6. **Model choice didn't matter; the export pipeline did.** A de-duplication bug deleted three vendor
   rules and nearly cost the study its cleanest result (§3.1).
7. **The Navigator layers were correct as data and wrong as a figure** — 15 valid entries that rendered
   as 5 techniques, because sub-techniques need an expanded parent row. Then the first SVG export
   silently contained 5 of 15 for the same reason. **Two failures of the same kind, neither detectable
   without rendering.**
8. **The technique with the most training data generalises worst** (T1136.001, 478 alerts, 0.288).

---

## 11. ✅ All three decisions RESOLVED — nothing is open

| # | Decision | Resolution |
|---|---|---|
| 1 | **Failure-mode count** — repo said five, seven and eight in different places | ✅ **Eight.** The taxonomy in §3 is canonical; each mode has its own evidence row. All documents reconciled. |
| 2 | **The ~14% figure** — not reproducible | ✅ **Dropped.** Replaced by rule `92213`: **115 fires at level 15, 5 genuine detections, 4.3% useful** (§5.2, with full breakdown). |
| 3 | **Which FP-reduction number leads** | ✅ **Lead with the mechanism, not the number.** Open with *why* the baseline is weak — severity ≥ 4 flags 79.2% of benign against 69.1% of attack, and level 15 is 32.3% attack — so the **99.7%** reads as a measurement of the baseline rather than a boast. **Then immediately give the operating-point table and the confusion matrix**, showing the ~15% realistic saving and the 24.5% miss rate at the default threshold. |

**Nothing in this document is awaiting a decision.** Everything below is settled and recomputed.

⚠️ **The only residual risk is infrastructural, not analytical** — see §9.0. Three of the seven silent
failures catalogued there cannot be caught by `check_docs.py` and are only reachable by rendering the
output and looking at it.

---

## 11a. Figures — all eight are built and visually verified

| # | File | Use it for |
|---|---|---|
| 1 | `ml/figures/fig1_confusion_matrix.svg` | The error balance — 471 missed vs 63 false alarms |
| 2 | `ml/figures/fig2_feature_importance.svg` | Top 18 features, each with its attack share |
| 3 | `ml/figures/fig3_precision_recall.svg` | Model curve with every rule heuristic below it |
| 4 | `ml/figures/fig4_operating_points.svg` | Recall vs analyst workload — deployability |
| 5 | `ml/figures/fig5_severity_vs_truth.svg` | **Severity anti-correlated with truth** |
| 6 | `ml/figures/fig6_rule_baselines.svg` | Model vs the ruleset, against "escalate everything" |
| **7** | `ml/figures/fig7_coverage_comparison.svg` | **Coverage, default vs engineered — use this, not the Navigator export** |
| **8** | `ml/figures/fig8_intent_vs_mechanism.svg` | ⭐ **The convergent finding — three matched pairs** |
| A1 | `navigator_layers/figures/01_default_ruleset_v19.svg` | *Appendix* — full enterprise matrix, stock |
| A2 | `navigator_layers/figures/02_custom_ruleset_v19.svg` | *Appendix* — full enterprise matrix, engineered |

**Suggested pairings.** **Figure 7 is the coverage story** — the full-matrix exports A1/A2 render ~600
techniques to show 15 and are unreadable at A4, so they belong in the appendix as evidence while
Figure 7 goes in the chapter. **Figures 1 and 4 must be published together** — Figure 1 alone
understates the 24.5% miss rate, Figure 4 alone hides it. **Figure 8 is the one to lead the chapter
with**: it is the central claim, and it had no visual until now.

⚠️ **Three of the six ML figures were unusable on first render** — overlapping labels in figs 3, 5 and 6
— while the script logged success every time. Fixed and re-inspected. **Re-render and look at the image
after any change**; layout defects are invisible to every other check. Same lesson as the Navigator
layers, which validated perfectly as JSON and drew 5 of 15 techniques.

---

## 12. Where everything lives

| Artefact | Path |
|---|---|
| Per-technique findings (primary) | `COVERAGE_TABLE.md` |
| Plain-language summary | `PROGRESS_SUMMARY.md` |
| ML narrative + all tables | `ml/README.md` |
| ML raw metrics | `ml/triage_results.csv` |
| ML code (reproduces everything in §6) | `scripts/triage_model.py` |
| Navigator layers — **citable, v14** | `navigator_layers/01_default_ruleset.json`, `02_custom_ruleset.json` |
| Navigator layers — renderable, v19 | `navigator_layers/*_v19.json` |
| **Chapter 4 figures — coverage (SVG)** | `navigator_layers/figures/` |
| **Chapter 4 figures — ML (SVG)** | `ml/figures/` |
| Layer generator | `scripts/build_navigator_layers.py` |
| ML figure generator | `scripts/make_ml_figures.py` |
| Labelled dataset | `data/labelled_alerts.csv` |
| Detonation log | `data/detonation_log.csv` |
| Rule definitions | `wazuh_rules/local_rules.xml` |
| Rule ID allocation + predictions | `RULE_ID_REGISTER.md` |
| Ground-truth label definition | `LABELLING_SCHEME.md` |
| Benign-class generation protocol | `BENIGN_ACTIVITY_PROTOCOL.md` |

**Reproduce §6:** `pip install scikit-learn xgboost --break-system-packages` then
`python3 scripts/triage_model.py`
**Reproduce §7:** `python3 scripts/build_navigator_layers.py`
**Reproduce all ML figures:** `python3 scripts/make_ml_figures.py`
