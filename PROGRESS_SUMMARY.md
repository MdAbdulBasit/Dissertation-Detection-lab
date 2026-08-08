# PROGRESS SUMMARY — plain-language notes

For personal reference and supervisor discussion. Technical detail lives in `COVERAGE_TABLE.md`,
`RULE_ID_REGISTER.md` and `LABELLING_SCHEME.md`.

**As at 2026-08-08:** 7 of 15 techniques complete · 12 custom rules · 109 detonation windows ·
3,365-row labelled dataset · 3 of 7 tactics covered.

---

## What the project is measuring, in one paragraph

An isolated three-VM lab runs real attack techniques against a Windows machine monitored by Wazuh (a
SIEM). For each technique we ask three questions. **One:** does the SIEM's built-in ruleset detect it, and
does it label it as the *right* attack technique? **Two:** if not, can we write a better rule? **Three:**
does that better rule also fire when an ordinary administrator does something similar? Question three is
the important one, because if the answer is yes, then no amount of rule-writing can separate an attacker
from an admin — and that is the argument for adding machine learning to prioritise alerts.

---

## T1053.005 Scheduled Task — what we did and found

### What the technique is

An attacker creates a Windows **scheduled task** so their code runs again automatically — after a reboot,
at logon, or on a timer. It is a *persistence* technique: the point is to keep access.

### What we did

1. Chose **5 of the 12** available test cases. The other 7 were excluded for stated reasons — some need a
   second computer we don't have, some need Microsoft Office, and several are actually *different*
   techniques that ART happens to file under this one.
2. Ran those 5 tests, **five times over**, with the SIEM's default rules only. Recorded the exact start
   and end time of each run.
3. Separately ran a **"benign" version** — an administrator creating and removing a scheduled task, which
   is completely normal system administration.
4. Looked at every alert the SIEM produced inside those time windows.
5. Wrote **two new detection rules**, deployed them, and repeated the whole thing.

### What we found — three things

**1. The SIEM missed it completely, and in an interesting way.**

Not a single built-in rule identified this as a scheduled-task attack. Every alert it produced described
the activity as "*Execution*" — essentially "PowerShell ran something". So an analyst looking at these
alerts would see a command being run, with **no indication that anything had been left behind on the
machine**. The difference matters: running a command is a one-off; planting a scheduled task means the
attacker gets back in after a reboot. Getting the tactic wrong changes how urgently a human responds.

This is the most serious kind of miss we have found so far. Two earlier techniques were also mislabelled,
but this is the first where a *Persistence* attack was reported as mere *Execution*.

**2. Our two new rules fixed the labelling — and reduced the wrong alerts.**

This was the more useful result. We expected the new rules to *add* correct alerts. They did, but they also
**displaced** the incorrect ones: the misleading "Execution" alerts dropped from 32 to 20, while 28
correctly-labelled scheduled-task alerts appeared. So precise rules did not just add noise on top of
existing noise — they replaced bad information with good.

The same effect showed up independently on an earlier technique, so it is a repeatable finding, not a
one-off.

**3. Our new rule also fires on the administrator. This is the point, not a bug.**

Rule `100270` fired 15 times on the attack and 4 times on the benign administrator activity. Creating a
scheduled task looks the same whoever does it, because it *is* the same action. No cleverer rule fixes
that. This is the evidence that rule logic alone cannot separate attacker from administrator, and therefore
the justification for the ML triage layer the dissertation proposes.

### The numbers

| | Attack alerts | Admin alerts | Correctly labelled as T1053.005 |
|---|---|---|---|
| Before our rules | 32 | 31 | **0** |
| After our rules | 48 | 38 | **28 attack / 4 admin** |

### A lab problem we had to solve along the way

The first six techniques only *read* information from the machine, so they could be repeated safely. This
one **creates** something. Run 1 created the scheduled tasks; runs 2–5 then tried to create tasks that
already existed and failed — one even froze for two minutes waiting for a "replace? Y/N" prompt that
nobody was there to answer. So four of five runs measured *failure to create a task*, which is a
completely different thing from creating one.

Fixed by adding automatic cleanup between runs, carefully timed to happen in a gap where it cannot be
mistaken for part of the attack. This machinery is now needed for three more techniques still to come.

---

## Findings so far across all seven techniques

**The built-in ruleset gets the technique wrong far more often than it gets it right.** Of seven measured:

| How the default ruleset behaved | Techniques |
|---|---|
| **Correct** — no custom rule needed | T1059.001, T1059.003 |
| **Partly correct** — right for one variant, wrong for the common one | T1033 |
| **Wrong technique / wrong tactic** | T1082, T1016, T1053.005 |
| **Right technique but too vague** (parent instead of specific) | T1087.001 |

**Two techniques needed no rule at all, and that matters.** For PowerShell and Command Shell the SIEM was
already correct, so we deliberately wrote nothing and recorded why. A study that found fault in all fifteen
cases would look like it went looking for fault.

**8 of our 12 custom rules fire on benign administrator activity too.** Consistently, across every
technique. This is the central measured result: better rules improve *labelling*, but do not improve
*discrimination*. Something other than rule logic has to decide which alerts a human should look at first.

**Most alerts have nothing to do with anyone attacking anything.** Roughly 14% of collected alerts relate
to deliberate activity. The rest are the vulnerability scanner, policy compliance checks, PowerShell's own
housekeeping, Windows Update, and the monitoring agent watching itself.

---

## The full technique set — 15 techniques across 7 tactics

| # | Technique | Tactic | Sysmon event | Status |
|---|-----------|--------|--------------|--------|
| 1 | **T1059.001** PowerShell | Execution | 1 | ✅ Done — no rule needed |
| 2 | **T1059.003** Windows Command Shell | Execution | 1 | ✅ Done — no rule needed |
| 3 | **T1087.001** Local Account Discovery | Discovery | 1 | ✅ Done — rule 100200 |
| 4 | **T1082** System Information Discovery | Discovery | 1 | ✅ Done — rules 100230–100233 |
| 5 | **T1033** System Owner/User Discovery | Discovery | 1 | ✅ Done — rules 100240–100241 |
| 6 | **T1016** Network Configuration Discovery | Discovery | 1 | ✅ Done — rules 100250–100252 |
| 7 | **T1053.005** Scheduled Task | Persistence | 1 | ✅ Done — rules 100270–100271 |
| 8 | T1136.001 Create Local Account | Persistence | 1 | ⬜ Next |
| 9 | T1547.001 Registry Run Keys / Startup Folder | Persistence | **13** | ⬜ First registry work |
| 10 | T1112 Modify Registry | Defense Evasion | **13** | ⬜ |
| 11 | T1218.011 Rundll32 | Defense Evasion | 1 | ⬜ |
| 12 | T1070.004 File Deletion | Defense Evasion | **11 / 23** | ⬜ New event types |
| 13 | T1003.001 LSASS Memory | Credential Access | **10** | ⬜ Highest risk |
| 14 | T1560.001 Archive via Utility | Collection | 1 / 11 | ⬜ |
| 15 | T1105 Ingress Tool Transfer | Command & Control | **3** | ⬜ Needs Kali VM |

**Fallbacks held in reserve** if T1003.001 (LSASS) proves impossible: T1003.002 SAM Registry Dump and
T1552.001 Credentials in Files, both Credential Access.

### The seven tactics

| Tactic | What the attacker is trying to do | Techniques | Covered? |
|--------|-----------------------------------|------------|----------|
| **Execution** | Run their code | T1059.001, T1059.003 | ✅ |
| **Discovery** | Learn about the machine and network | T1087.001, T1082, T1033, T1016 | ✅ |
| **Persistence** | Survive a reboot / keep access | T1053.005, T1136.001, T1547.001 | 🟡 1 of 3 |
| **Defense Evasion** | Avoid being seen | T1112, T1218.011, T1070.004 | ⬜ |
| **Credential Access** | Steal passwords | T1003.001 | ⬜ |
| **Collection** | Gather data to steal | T1560.001 | ⬜ |
| **Command & Control** | Talk to the attacker's server | T1105 | ⬜ |

### Why this set

The techniques were chosen to span the attack lifecycle rather than cluster in one area, and to exercise
**five different Sysmon event types** (1 process creation, 3 network, 10 process access, 11 file creation,
13 registry) so the detection work isn't all one shape. Around half are deliberately **high-overlap** with
routine administration — `whoami`, `ipconfig`, `systeminfo`, PowerShell, cmd — because those are what
manufacture the false positives the thesis then attempts to reduce.

---

## What remains

**8 techniques.** Roughly 45 minutes each now the process is settled, though the three that create
persistent state need the slower cleanup cycle, and registry techniques (9, 10) move to Sysmon event 13 —
new telemetry, so expect the first one to surface its own problems the way the first process-creation
technique did.

**Then the analysis phase:** ATT&CK Navigator coverage maps (default versus custom, side by side), the
labelled dataset export, and the Random Forest / XGBoost triage model that the whole measurement exercise
exists to justify.
