# PROGRESS SUMMARY — plain-language notes

For personal reference and supervisor discussion. Technical detail lives in `COVERAGE_TABLE.md`,
`RULE_ID_REGISTER.md`, `LABELLING_SCHEME.md`, `navigator_layers/README.md` and `ml/README.md`.

**As at 2026-08-10 — DATA COLLECTION AND ANALYSIS COMPLETE.**
15 of 15 techniques · 7 of 7 tactics · 37 custom rules · 278 usable detonation windows ·
2,683 labelled in-window alerts · ATT&CK Navigator layers rendered · triage model evaluated.

**Nothing left to run in the lab. What remains is the write-up.**

---

## What the project is measuring, in one paragraph

An isolated three-VM lab runs real attack techniques against a Windows machine monitored by Wazuh (a
SIEM). For each technique we ask three questions. **One:** does the SIEM's built-in ruleset detect it, and
does it label it as the *right* attack technique? **Two:** if not, can we write a better rule? **Three:**
does that better rule also fire when an ordinary administrator does something similar? Question three is
the important one, because if the answer is yes, then no amount of rule-writing can separate an attacker
from an admin — and that is the argument for adding machine learning to prioritise alerts.

**All three questions now have measured answers, and the third one is the interesting one.**

---

## The headline result, in three numbers

| Question | Answer |
|---|---|
| Did 37 custom rules fix coverage? | **Yes.** 7 techniques the SIEM was blind to → **0**. |
| Did they improve discrimination? | **No.** Detections firing only on real attacks: **3 → 1**. |
| Can a model do what the rules can't? | **Partly.** 0.784 macro F1 vs **0.428** for the best rule heuristic. |

**The convergent finding: every rule that separated attacker from administrator encoded *what was done
to what*. Every rule that failed encoded *how*.**

---

## The scale of what was collected

| | |
|---|---|
| Detonation windows logged | 344 |
| — superseded or aborted (documented, excluded) | 66 |
| **— usable** | **278** |
| — of those, produced **no alert whatsoever** | **19** |
| Alerts exported | 4,976 |
| Alerts inside a detonation window (the dataset) | **2,683** — 1,919 attack / 764 benign |
| Windows represented in that dataset | 259 |

The 66 excluded windows are kept in the repository with the reason recorded, not deleted. **The 19 silent
windows matter separately** — those are not misattributions, they are the SIEM producing nothing at all
while a technique executed.

---

## Findings across all fifteen techniques

**The built-in ruleset gets the technique wrong more often than right.** Eight distinct failure modes
were catalogued — blind spots, parent-only attribution, wrong tactic entirely, right technique for the
wrong reason, and regexes so loose they match anything.

**Two techniques deliberately got no custom rule.** For PowerShell and Command Shell the SIEM was already
correct, so nothing was written and the reason was recorded. A study finding fault in all fifteen cases
would look like it went looking for fault.

**24 of the 34 custom rules that fired also fire on benign administrator activity.** Consistently, across
every technique. This is the central measured result: better rules improve *labelling*, not
*discrimination*.

**Three techniques needed the sensor changed, not the rules.** T1112, T1070.004 and T1003.001 produced no
usable telemetry until the Sysmon configuration was widened. For T1070.004 the config silently discarded
the events because it declared `schemaversion="4.50"` when file-delete events need 4.60+ — and Sysmon
still printed *"Configuration file validated"*. Found only by probing for the event ID directly.

**Roughly 14% of collected alerts relate to deliberate activity.** The rest is the vulnerability scanner,
policy compliance checks, PowerShell housekeeping, Windows Update, and the agent monitoring itself.

---

## T1053.005 Scheduled Task — the worked example

Kept in full because it is the clearest single illustration of the argument.

### What the technique is

An attacker creates a Windows **scheduled task** so their code runs again automatically — after a reboot,
at logon, or on a timer. It is a *persistence* technique: the point is to keep access.

### What we found — three things

**1. The SIEM missed it completely, and in an interesting way.** Not a single built-in rule identified
this as a scheduled-task attack. Every alert described the activity as "*Execution*" — essentially
"PowerShell ran something". An analyst would see a command being run with **no indication anything had
been left behind on the machine**. Running a command is a one-off; planting a scheduled task means the
attacker returns after a reboot. Getting the tactic wrong changes how urgently a human responds.

**2. Our two new rules fixed the labelling — and reduced the wrong alerts.** They did not just *add*
correct alerts, they **displaced** incorrect ones: misleading "Execution" alerts dropped from 32 to 20
while 28 correctly-labelled scheduled-task alerts appeared. Precise rules replaced bad information rather
than piling good on top of bad. The same effect appeared independently on other techniques.

**3. Our new rule also fires on the administrator. This is the point, not a bug.** Rule `100270` fired 15
times on the attack and 4 times on benign administrator activity. Creating a scheduled task looks the
same whoever does it, because it *is* the same action.

| | Attack alerts | Admin alerts | Correctly labelled T1053.005 |
|---|---|---|---|
| Before our rules | 32 | 31 | **0** |
| After our rules | 48 | 38 | **28 attack / 4 admin** |

---

## The ATT&CK Navigator result

| | Default ruleset | Engineered ruleset |
|---|---|---|
| Blind — nothing carries the technique or its parent | **7** | **0** |
| Parent only / misattributed | 1 | 0 |
| Detected at the correct technique | 4 | **14** |
| Detected **and** never fires on benign activity | **3** | **1** |

Read naively the last row looks like a regression. It is the finding. **Thirty-seven rules eliminated
every blind spot and did not improve discrimination.** Two of the default's three are qualified on the
layer itself, so the honest reading is **one genuine discriminator before and one after**.

Figures: `navigator_layers/figures/`. Both verified to contain all fifteen techniques — the first export
silently contained only five.

---

## The machine-learning result

**The comparison that matters is against the ruleset, not against guessing.**

| Triage approach | macro F1 |
|---|---|
| Best severity threshold (level ≥ 6) | 0.428 |
| Always guess "attack" | 0.417 |
| Perfect ATT&CK attribution | 0.412 |
| **Any of the 37 engineered rules fired** | **0.379** |
| **Model (Random Forest, rule identity withheld)** | **0.784 ± 0.071** |

**Two of the three rule-based heuristics lose to escalating everything.** The model roughly doubles the
best of them.

**But three honest qualifications:**

- **At the default threshold it misses 24.5% of attacks** (471 of 1,919) while false-alarming on only
  8.2% of benign. For triage that is the wrong way round, and a single macro-F1 figure hides it.
- **Tuned to a deployable operating point** (threshold 0.20) it catches 99.0% of attacks but still needs
  84.7% of the queue reviewed. **The real workload saving is 15–20%, not an order of magnitude.**
- **It does not generalise to an unseen technique** — macro F1 collapses to ~0.54, and ranges from 0.822
  down to 0.288 depending which technique is held out.

**XGBoost scored 0.780 against Random Forest's 0.784** — indistinguishable. Model choice was not the
bottleneck; feature representation and leakage removal were.

**Four separate layers of data leakage had to be removed, and each looked like signal.** Names, then
habits, then the placeholder used to mask the habits, then an experimental-design artefact where only the
benign mirror cleaned up inside the measured window. The fourth was found after the leakage section had
already been written.

---

## The full technique set — all complete

| # | Technique | Tactic | Status |
|---|-----------|--------|--------|
| 1 | **T1059.001** PowerShell | Execution | ✅ No rule needed — default correct |
| 2 | **T1059.003** Windows Command Shell | Execution | ✅ No rule needed — default correct |
| 3 | **T1087.001** Local Account Discovery | Discovery | ✅ Rule 100200 |
| 4 | **T1082** System Information Discovery | Discovery | ✅ Rules 100230–100233 |
| 5 | **T1033** System Owner/User Discovery | Discovery | ✅ Rules 100240–100241 |
| 6 | **T1016** Network Configuration Discovery | Discovery | ✅ Rules 100250–100252 |
| 7 | **T1053.005** Scheduled Task | Persistence | ✅ Rules 100270–100271 |
| 8 | **T1136.001** Create Local Account | Persistence | ✅ Rules 100280–100283 |
| 9 | **T1547.001** Registry Run Keys / Startup | Persistence | ✅ Rules 100290–100294 |
| 10 | **T1112** Modify Registry | Defense Evasion | ✅ Rules 100260–100264 + sensor change |
| 11 | **T1218.011** Rundll32 | Defense Evasion | ✅ Rules 100300–100302 |
| 12 | **T1070.004** File Deletion | Defense Evasion | ✅ Rules 100310–100313 + sensor change |
| 13 | **T1003.001** LSASS Memory | Credential Access | ✅ Rules 100320–100321 + sensor change |
| 14 | **T1560.001** Archive via Utility | Collection | ✅ Rules 100330–100332 |
| 15 | **T1105** Ingress Tool Transfer | Command & Control | ✅ No rule needed — default correct **and** discriminating |

All seven tactics covered: Execution, Discovery, Persistence, Defense Evasion, Credential Access,
Collection, Command & Control.

⚠️ **ATT&CK v19 (28 April 2026) split Defense Evasion into Stealth and Defense Impairment**, after data
collection finished. The study is mapped against v14 and both layer versions are kept. Worth a paragraph
in the limitations — a coverage figure dates the moment the framework moves.

---

## What remains — write-up only

| Task | Notes |
|---|---|
| **Chapter 4 findings** | The main remaining deliverable. Source material is complete. |
| **Limitations section** | 259 windows is the real sample size; one endpoint, one OS build, one operator's command style; benign mirror is designed to resemble the attack; 72/28 class balance flatters precision; ATT&CK v19 drift. |
| **Future work** | Rule `100201` — T1087.001 PowerShell-cmdlet blind spot, documented but not built. |
| Move repo off OneDrive | Caused four git lock failures in one session. ~15 minutes. |

**Guidance for writing Chapter 4:** quote technique counts from `COVERAGE_TABLE.md` (7/1/4/3 → 0/0/14/1),
never the coloured cells in the Navigator images — the v19 layers draw multi-tactic techniques more than
once, so fifteen techniques render as nineteen cells.
