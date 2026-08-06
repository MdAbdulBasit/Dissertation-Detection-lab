# BENIGN ACTIVITY PROTOCOL — generating the negative class

Required by `LAB_HANDOVER_PHASE2.md` §5. Absent from the lab-session workflow, which generates
attack data only.

---

## 1. Why the obvious approach fails

PHASE2 §5 suggests "normal Windows usage… legitimate PowerShell (e.g. `Get-Process`, `Get-Service`)"
plus idle time. That will not work on its own, and it is worth being precise about why.

Sysmon on an idle Windows box generates a large volume of **events** but very few **alerts**. Wazuh
only raises an alert when a rule matches. `Get-Process` and `Get-Service` match nothing. So the
negative class would come out nearly empty, and — worse — the few benign alerts that did appear would
be trivially distinguishable from the attack alerts.

A model trained on that data learns *"an alert exists, therefore it is an attack."* It would score
near-perfect precision and recall, and the result would be meaningless: the false-positive reduction
claim requires false positives to reduce, and there would be none.

## 2. The requirement this imposes

**The benign activity must trigger the same rules as the attacks, in a legitimate context.**

The negative class has to be *confusable* with the positive class. This is the whole basis of the
research question — an alert saying "`whoami` executed" is identical whether an attacker or an
administrator ran it. What separates them is context: parent process, time of day, what else happened
around it, clustering. Those are exactly the features the model has to learn from, and they only exist
if benign activity covers the same command surface.

This is also why the PHASE2 technique set deliberately includes ~8 high-overlap techniques
(`whoami`, `ipconfig`, `systeminfo`, PowerShell, cmd). Those are not there to be detected —
they are there to **manufacture the false positives** the thesis then reduces.

## 2a. ⚠️ The harness fingerprint — measured 2026-08-06, and the hardest problem in this design

"Same commands" is **not sufficient**. Atomic Red Team leaves its own fingerprint on the telemetry, and
if the benign class doesn't reproduce it, the classes separate on the *tool* rather than on behaviour.
This was found twice in one session, each time as a perfect discriminator:

| Round | Benign invocation | Attack (ART) invocation | Result |
|-------|-------------------|-------------------------|--------|
| 0 | commands run directly from `powershell.exe` | `cmd.exe /c "<cmd>"` | **146 attack alerts vs 1 benign.** Rules 92032 and 92052 both key on cmd.exe lineage, so benign fired essentially nothing |
| 1 | `& cmd.exe /c '<cmd>'` | `"cmd.exe" /c <cmd> & <cmd>` | benign rose to 30 and 92032 fired in both — but PowerShell's `&` resolves the full path, so benign recorded `"C:\Windows\system32\cmd.exe" /c …` and fired **92004**, while attack recorded `"cmd.exe" /c …` and fired **92052**. 25 vs 67, zero overlap: still 100% separable on rule ID |
| 2 | `Start-Process -FilePath 'cmd.exe' -ArgumentList "/c <cmd>"`, commands chained with `&` | same | matches ART's command-line form and child fan-out — **verify on the next export** |

**What to check after every benign run**, because this will keep recurring as new techniques are added:

1. Do the same rule IDs appear in both classes, at comparable volume?
2. Is any rule ID exclusive to one class? If so, that rule is a harness artefact, not a detection.
3. Do the recorded `commandLine` strings have the same *form* — same path style, same chaining?

### The tension this creates — state it in the methodology

Reproducing ART's invocation form makes the classes genuinely confusable, but it also means the benign
class is "ART-shaped benign activity" rather than what a real administrator does. A real admin types
`systeminfo` at an interactive prompt; they do not spawn `cmd.exe /c` chains from PowerShell. So there
is a direct trade-off:

- **Match the harness form** (chosen here) — clean, behaviour-only comparison; benign is less
  representative of real administration.
- **Use realistic admin behaviour** — representative, but the classes separate on invocation artefacts
  and the model learns the harness instead of the behaviour.

Chosen approach: match the form, and treat it as a stated limitation. As a robustness check, retrain
with rule ID and command-line-path features removed — if performance holds, the result does not rest on
the artefact. This is worth reporting either way: **that an emulation framework's own execution wrapper
is more detectable than the technique it emulates is a finding about purple-team methodology**, not just
a lab problem to be engineered away.

## 3. Benign session procedure

Run a benign session **per technique campaign**, logged the same way as detonations but with
`type = benign` in `data/detonation_log.csv`. Target roughly **3–5× more benign alert volume than
attack alert volume**.

### 3a. Technique-mirroring commands (the important part)

Run these as an ordinary interactive admin, from an interactive shell — *not* scripted back-to-back,
which produces an unnaturally tight cluster the model can trivially separate on inter-arrival time.
Space them out, interleave with real work, vary the order.

| Mirrors | Legitimate command | Plausible admin reason |
|---------|-------------------|------------------------|
| T1087.001 | `net user`, `net localgroup administrators` | Audit who has local admin |
| T1082 | `systeminfo`, `msinfo32` | Check patch level / RAM before an install |
| T1033 | `whoami`, `whoami /groups` | Confirm which account a session is running as |
| T1016 | `ipconfig /all`, `route print`, `arp -a` | Troubleshoot connectivity |
| T1059.001 | `Get-EventLog`, `Get-ChildItem`, `Test-NetConnection` | Routine admin scripting |
| T1059.003 | `dir`, `tasklist`, `sc query`, `ping` | Everyday command-line work |
| T1053.005 | `schtasks /query`, create a real scheduled task | Set up a genuine maintenance job |
| T1547.001 | Install a legitimate program that adds a Run key | Normal software installation |
| T1112 | Change a display or Explorer setting via GUI | Ordinary configuration change |
| T1070.004 | Delete files, empty Recycle Bin, `cleanmgr` | Housekeeping |
| T1560.001 | Zip a folder via Explorer or `Compress-Archive` | Archive documents |
| T1105 | Download a file in a browser over NAT | Fetch an installer |

**Do not mirror T1003.001 (LSASS).** Nothing legitimately reads LSASS memory on a workstation. Its
value in the set is precisely that it has a near-empty negative class — it anchors the "critical,
always act" end of the severity gradient. Leaving it unmirrored is correct, not an omission.

### 3b. Background noise

Run alongside the above, and let it accumulate across sessions:

- Open/close Office, browser, Explorer; browse directories; edit and save files
- Install *and* uninstall one harmless program (e.g. 7-Zip, Notepad++)
- Let Windows Update and built-in scheduled tasks run naturally
- Leave the endpoint idle and running for 30–60 minute stretches
- Log off and back on; lock/unlock

### 3c. Optional supplement

OTRF Security-Datasets include benign events surrounding attacks. Useful as a supplement **only if**
the endpoint-generated volume proves too thin — but note in the methodology that it is a different
host with a different Sysmon config, which is a threat to validity. Prefer self-generated data.

## 4. Sequencing rule

Do **not** interleave benign and attack activity inside the same clock window. Provenance labelling is
timestamp-based (see `LABELLING_SCHEME.md`); overlapping windows makes labels ambiguous and
unrecoverable.

Recommended per-technique cycle:

```
1. Benign session          (30–45 min)  → type = benign
2. Quiet gap               (2 min)      → clean boundary
3. Detonation window       (2–5 min)    → type = attack
4. Quiet gap               (2 min)
5. Benign session          (30–45 min)  → type = benign
```

The trailing benign session matters: it prevents "attacks happen late in the capture" becoming an
accidental time-based signal the model can exploit.

## 5. Snapshot warning

PHASE2 §6 suggests reverting the endpoint snapshot between campaigns to keep data clean. If you do,
**the benign baseline is reverted too** — installed programs, created tasks, browser history all
disappear. Either:

- **(a)** re-run benign activity after every revert (expensive, ~40 min per technique × 14), or
- **(b)** don't revert between techniques; revert only if something breaks

**Recommended: (b).** Accumulated benign state is an *asset* here — a machine with real history looks
more like a production endpoint than a freshly reverted one, and the drift is realistic rather than
contaminating. Record the choice in the methodology either way.

## 6. Verification before scaling up

After the first benign session, confirm it actually produced alerts:

```bash
sudo grep -a -c "Rule:" /var/ossec/logs/alerts/alerts.log
```

If a 40-minute benign session yields near-zero alerts, the negative class is not being generated and
there is no point running 13 more techniques. Fix it then — check the mirroring commands are firing
rules, and widen the command set if not.
