# PROJECT PLAN — from 1/15 techniques to submission

Status at 2026-08-06: **T1087.001 complete** (10 atk / 4 benign alerts, clean paired windows).
Infrastructure faults found and fixed this session: Blue clock 4 h out, atomic test numbering,
`\\VBOXSVR\lab` documented before it existed.

---

## Part 1 — Outstanding housekeeping (do in this order; 2 and 3 are coupled)

### 1. Move the repo out of OneDrive ⟵ **do this first, it unblocks git**

OneDrive syncs `.git/`, which caused an `index.lock` that could not be released and blocked all commits.
This repo is the dissertation's evidence base; two storage incidents have already cost VMs.

On the host, in PowerShell:
```powershell
robocopy "C:\Users\Abdul\OneDrive\Documents\msc-dissertation-detection-lab\dissertation-detection-lab" "C:\dev\dissertation-detection-lab" /E
```
Then remove the stale lock at the destination and confirm git works:
```powershell
del "C:\dev\dissertation-detection-lab\.git\index.lock"
```
```powershell
cd C:\dev\dissertation-detection-lab ; git status
```
Verify the copy is complete **before** deleting the OneDrive original. GitHub (`origin`) remains the
offsite backup, so OneDrive is not needed for redundancy.

> ⚠️ After moving, re-select `C:\dev\dissertation-detection-lab` as the working folder in Cowork,
> or assistant access points at the old path.

### 2. Commit and push, then pull the scripts onto the endpoint

`scripts/` has never been committed, which is why there was no route to the endpoint.

```powershell
git add -A ; git commit -m "Add lab scaffolding and T1087.001 results" ; git push
```

Then **either** define the shared folder (preferred — gives a route for evidence *out* of the guest as
well), or pull over NAT.

**Shared folder.** Guest Additions is confirmed installed on the endpoint (`VBoxService` running), so
`System error 53` meant no share was defined. VM window → Devices → Shared Folders → Shared Folders
Settings → add: path `C:\dev\dissertation-detection-lab`, name `lab`, **Auto-mount ✓, Make Permanent ✓,
Read-only ✗**. Verify in the guest:
```powershell
Test-Path \\VBOXSVR\lab\scripts\Invoke-LabRun.ps1
```

**Fallback, if the share still fails.** Pull the script over NAT (no Guest Additions involved):
```powershell
mkdir C:\lab
```
```powershell
iwr https://raw.githubusercontent.com/MdAbdulBasit/dissertation-detection-lab/main/scripts/Invoke-LabRun.ps1 -OutFile C:\lab\Invoke-LabRun.ps1
```
Requires the GitHub repo to be public. `Invoke-LabRun.ps1` prints its CSV row to the console, so
evidence can be transferred by copying that line even without a writable share.

This task is the highest-leverage item here: it removes hand-typed commands from the loop, which is
what consumed most of 2026-08-06.

### 3. Configure chrony durably (Blue)

`makestep 1 3` only steps the clock during the first three updates. Sources flapped at startup,
consuming that allowance, so a 4 h error was detected and left uncorrected.

```bash
grep -E "makestep|rtcsync" /etc/chrony/chrony.conf
```
```bash
sudo sed -i 's/^makestep .*/makestep 1 -1/' /etc/chrony/chrony.conf
```
If `rtcsync` is absent, add it:
```bash
echo rtcsync | sudo tee -a /etc/chrony/chrony.conf
```
```bash
sudo systemctl restart chrony ; chronyc tracking
```
Pass criterion is `chronyc tracking` — System time within a few ms and `Leap status : Normal`.
**Not** `timedatectl`'s `System clock synchronized:` line, which stays `no` on a chrony host.

### 4. Confirm Defender is *disabled* before T1003.001

Note the direction: the lab needs real-time protection **off**, not working. LSASS access is the one
technique Defender will reliably block, and a blocked payload is indistinguishable from a broken rule.

```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IsTamperProtected, AntivirusEnabled
```
```powershell
Get-MpPreference | Select -ExpandProperty ExclusionPath
```
Want `RealTimeProtectionEnabled : False`, `IsTamperProtected : False`, and exclusions covering
`C:\AtomicRedTeam` and `C:\Users\Public`. Real-time protection **re-enables itself on reboot and after
Windows Update**. If it is back on, disable Tamper Protection first via the Windows Security UI (it
cannot be turned off from PowerShell), then:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
Record the state in the `defender_realtime_off` column every run — it is currently `unverified` for all
three T1087.001 runs.

### 5. Snapshot the working state — not yet done, and overdue

Everything is currently green: clock synced, agent active, rule 100200 firing, one technique complete.
Given the 2026-07-15 VDI detachment and the Kali loss, snapshot now:

- Blue → `Blue-clock-fixed-rule-working`
- Windows → `Win-sensors-verified-T1087-done`

Also close out the one-time cleanup in `PREFLIGHT_CHECKLIST.md` §8.1 (single rule `100200`, remove
stale agent `001`, resolve the rule-precision decision).

---

## Part 2 — ⚠️ Decide now: sample size for the ML model

**This changes the data-collection plan, so it cannot wait until modelling starts.**

T1087.001 produced 10 attack alerts. At that rate 15 techniques yields roughly **150 attack alerts**,
and after deduplicating the `net.exe`/`net1.exe` pairing, closer to **75 distinct events**. That is far
too small to train and honestly evaluate Random Forest / XGBoost — a held-out test set would contain a
couple of dozen rows, and reported precision/recall would carry enormous confidence intervals.

Options, cheapest first:

1. **Repeat each detonation 5–10 times** across separate windows. `Invoke-LabRun.ps1` makes this nearly
   free once task 2 is done. 15 techniques × 8 runs ≈ 1,200 attack alerts, with matched benign volume.
   Vary the operator context slightly between runs so the model does not learn a constant.
2. **Widen the benign class** using `BENIGN_ACTIVITY_PROTOCOL.md` — schedule benign mirrors to run
   repeatedly, unattended, over hours. Negative-class volume is essentially free.
3. **Reframe the contribution** if volume stays low: present the triage model as a demonstrator with a
   stated small-sample limitation, and lead on the coverage/precision findings instead.

Option 1 plus 2 is strongly preferable. Decide before running technique 2, because retrofitting repeat
runs later means redoing every technique.

---

## Part 3 — Remaining 14 techniques

Batch by Sysmon event ID so telemetry understanding and rule patterns are reused within a session.

| Order | Techniques | EID | Why grouped |
|-------|-----------|-----|-------------|
| A | T1082, T1033, T1016 | 1 | Same tactic and sensor as the completed T1087.001 — fastest wins, reuse the rule pattern |
| B | T1059.001, T1059.003 | 1 | Script/shell execution; broader command-line matching |
| C | T1053.005, T1136.001 | 1 | Persistence via process creation |
| D | T1547.001, T1112 | 13 | First registry work — new event type, do together |
| E | T1218.011, T1070.004 | 1, 11/23 | Defence evasion; file-delete events are new |
| F | T1560.001 | 1/11 | Collection |
| G | **T1003.001** | 10 | Highest risk. Requires Part 1 task 4 verified first |
| H | T1105 | 3 | Last — needs Kali booted; watch RAM on the 16 GB host |

Per technique, the loop is: enumerate test numbers → detonate (bracketed) → benign mirror → count
alerts → fill the coverage row → register any new rule ID → commit.

**Always enumerate atomic test numbers first.** They are global within a technique and do not start at 1.

---

## Part 4 — Analysis and write-up

1. **Close the cmdlet blind spot.** Rule `100200` detected nothing from `Get-LocalUser` /
   `Get-LocalGroup`. Write a companion rule against PowerShell telemetry or Script Block Logging and
   re-run T1087.001-9. Expect the same gap in other techniques — check for it each time.
2. **ATT&CK Navigator layers** — default Wazuh coverage vs custom-rule coverage, side by side. The
   strongest single visual for Chapter 4.
3. **Export and label** — pull alerts from the indexer, apply the `LABELLING_SCHEME.md` rule, and
   **deduplicate the `net1.exe` pairing** before any counting or feature building.
4. **Triage model** — Random Forest / XGBoost, with feature importance reported. The dissertation's
   central claim rests on this separating classes that rule logic provably cannot.
5. **Methodology limitations**, all already evidenced: Defender disabled, PowerShell execution policy
   relaxed, single-node Wazuh with default credentials, no domain controller (so no domain-account
   discovery variants), and the 2026-08-06 clock fault as a documented data-integrity incident.

---

## Headline result so far

Rule `100200` fires identically — same rule, same level 10 — on the atomic and on legitimate
administrative enumeration. Rule logic alone cannot separate the classes. That is the measured
motivation for the ML triage layer, and it is a finding rather than a defect.
