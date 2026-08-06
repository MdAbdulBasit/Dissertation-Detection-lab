# PER-SESSION PREFLIGHT CHECKLIST

Run this at the start of every lab session. Each item is here because it has already broken, or
because it silently resets between sessions.

---

## 0. Host disk space — CHECK FIRST

This has already caused two incidents: Kali was deleted during a host disk cleanup, and on 2026-07-15
a full C: drive detached Blue's `.vdi` and left it unbootable.

In PowerShell on the host:
```powershell
Get-PSDrive C | Select-Object Used,Free,@{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}
```

**Need ≥ 20 GB free** before booting VMs. Wazuh index growth plus snapshots consume space steadily,
and every technique campaign adds alert data. If below 20 GB, free space before doing anything else.

Also confirm VMs are in `C:\Users\Abdul\VirtualBox VMs\` — never in Downloads or any folder a cleanup
tool will touch.

## 1. Boot order and RAM discipline

16 GB host. Boot **Blue first**, then Windows. Kali only if the technique needs it
(T1105 Ingress Tool Transfer, or any CALDERA work). Rule development does not need Kali.

## 2. Blue — service and health check

```bash
ssh basit@192.168.56.101
```
```bash
# All four must be active (running)
sudo systemctl is-active wazuh-indexer wazuh-manager filebeat wazuh-dashboard

# Cluster health must be green (yellow = single-node replica warning, acceptable; red = stop)
curl -sk -u admin:admin https://10.10.10.10:9200/_cluster/health?pretty | grep status

# Disk headroom on Blue — alert indices grow with every campaign
df -h /

# Confirm alerts index is receiving
curl -sk -u admin:admin "https://10.10.10.10:9200/_cat/indices/wazuh-alerts-*?v&h=index,docs.count,store.size"
```

**Expect:** four `active`, status `green` or `yellow`, root filesystem well under 80% used, and a
`wazuh-alerts-4.x-<date>` index with a non-zero doc count.

## 3. Blue — agent check

```bash
sudo /var/ossec/bin/agent_control -l
```
**Expect:** `Name: win-endpoint` and `Active`. **The ID is not stable** — every re-enrolment issues a new
one. It has been 001 → 002 → 003/004 → **005** (as at 2026-08-06). Check the *name* and the *state*, never
a hard-coded ID.

> ⚠️ **`agent-auth.exe` without `-A` enrols under the machine hostname.** On 2026-08-06 a recovery
> re-enrolment created `DESKTOP-2VJPE09` instead of `win-endpoint`. Nothing errors — the agent connects
> happily and alerts flow. But `LABELLING_SCHEME.md` matches `alert.agent == 'win-endpoint'`, so every
> attack alert would have been labelled `0` and the positive class would have emptied silently. Always:
> ```powershell
> & "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 10.10.10.10 -A win-endpoint
> ```
> Agent 001 in `BUILD_LOG.md` carries the hostname for exactly this reason.

> ⚠️ **Stop `WazuhSvc` before re-enrolling.** The agent service has auto-enrolment enabled and will
> re-register `win-endpoint` on its own while you work, so `agent-auth -A win-endpoint` then fails with
> *"Duplicate agent name … Unable to add agent"* against a registration you cannot see it creating. The
> working order is: `Stop-Service WazuhSvc` → remove the stale registration on Blue → `agent-auth … -A
> win-endpoint` (expect `Valid key received`) → `Start-Service WazuhSvc`.

## 4. Blue — rule integrity

```bash
# Every deployed custom ID must appear exactly once
sudo grep -o 'id="[0-9]\{6\}"' /var/ossec/etc/rules/local_rules.xml | sort | uniq -c

# Must be clean — no error, no "7612 duplicated" warning
sudo /var/ossec/bin/wazuh-analysisd -t
```
Cross-check the IDs found against `RULE_ID_REGISTER.md`.

## 5. Windows — Defender state ⚠️ RESETS ON REBOOT

This is the single most likely cause of an atomic "failing" for the wrong reason. Real-time protection
re-enables itself after a reboot, and after Windows Update.

In an **elevated** PowerShell:
```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected, AntivirusEnabled
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**Want:** `RealTimeProtectionEnabled : False`, `IsTamperProtected : False`,
and exclusions covering `C:\AtomicRedTeam` and `C:\Users\Public`.

If real-time protection is back on, disable it again (Tamper Protection must be off first, via
Windows Security UI — it cannot be disabled from PowerShell):
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

If an atomic produces no telemetry, **check this before debugging the rule.** A blocked payload and a
broken rule look identical from the Wazuh side.

> Note: `LAB_HANDOVER_PHASE2.md` §2 describes only a Defender *exclusion path* and therefore rates
> T1003.001 (LSASS) as high-risk. `BUILD_LOG.md` confirms real-time protection and Tamper Protection
> are fully disabled *as well as* exclusions being set. The LSASS risk is accordingly lower than
> PHASE2 assumes — but only while protection is actually off, which this check verifies.

## 6. Windows — sensor and agent

```powershell
Get-Service -Name "*ysmon*", "WazuhSvc" | Select-Object Name, Status

# Sysmon event channel forwarding must still be present, or Sysmon logs locally and never reaches Blue
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "Sysmon"
```
**Expect:** both services `Running`, and a match on `Microsoft-Windows-Sysmon/Operational`.
If the `Select-String` returns nothing, forwarding config was lost — re-add the `<localfile>` block and
restart `WazuhSvc`.

## 6a. ⚠️ PROVE THE PIPELINE END TO END — do this every session, before any detonation

**Every check above can pass while zero events reach Blue.** On 2026-08-06 ten T1082 detonation windows
(~20 minutes of runs) were executed against a dead pipeline and produced no telemetry at all. At the
time: all four Blue services `active`, `agent_control -l` reporting `ID: 002, win-endpoint, Active`,
`Sysmon64` running, Defender off, clocks synced. Everything looked healthy.

`Active` in `agent_control` reflects **keepalives only**. Keepalive and event delivery are separate
channels, and one can be fine while the other is dead.

The actual test — detonate one known-good command and confirm the alert lands:

```powershell
net user
```
Then immediately on Blue:
```bash
sudo tail -5 /var/ossec/logs/alerts/alerts.log
```
**Expect rule `100200` within a few seconds.** If nothing appears, stop — do not run atomics.

> ⚠️ **Always pass `-a` when grepping `alerts.log`.** Atomic output containing null bytes — notably
> T1082 test 30, which reads a `REG_MULTI_SZ` BIOS value rendered as
> `Oracle VirtualBox Version 7.2.12\0Oracle…` — makes the file binary as far as grep is concerned. From
> then on it prints only `binary file matches` and suppresses every result, which reads exactly like
> "no alerts found":
> ```bash
> sudo grep -a -B1 "Rule: 100200" /var/ossec/logs/alerts/alerts.log | tail -8
> ```
> `alerts.json` is the more robust source for scripted extraction; reserve `alerts.log` for eyeballing.

### The failure signature to look for

```bash
sudo tail -20 /var/ossec/logs/ossec.log
```
An **enrollment loop** looks like this, repeating every ~60 s:
```
wazuh-authd: INFO: Received request for a new agent (win-endpoint) from: 10.10.10.20
wazuh-authd: WARNING: Duplicate name 'win-endpoint', rejecting enrollment.
             Agent '002' can't be replaced since it is not disconnected.
```
This means the agent lost its key (a reboot or a restored snapshot will do it) and is asking to
re-enrol, while the manager refuses because a live registration already holds that name. Recovery — on
Blue:
```bash
sudo /var/ossec/bin/manage_agents -r 002
sudo systemctl restart wazuh-manager
```
Then on the endpoint, elevated:
```powershell
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 10.10.10.10
Restart-Service WazuhSvc
```
Re-run the end-to-end proof above before detonating.

> Also check `sudo ls -la /var/ossec/logs/alerts/` — if `alerts.log` and `alerts.json` share an mtime
> well in the past, delivery stopped at that moment. Correlate it with what you did then. In the
> 2026-08-06 case both stopped at 05:01, exactly when the VMs were shut down for snapshots.

## 7. Windows — execution policy, then Atomic Red Team module

**Order matters.** The default execution policy (`Restricted`) blocks ART's `powershell-yaml`
dependency, and `Import-Module` fails with `PSSecurityException / UnauthorizedAccess`. Relax the policy
first, in **every new PowerShell session**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

`-Scope Process` applies only to the current window and reverts when it closes — no persistent change
to the machine's security posture. Both commands must run in the **same** window as the atomic; the
module import does not survive a new session.

To run the lab scripts from the shared folder:
```powershell
powershell.exe -ExecutionPolicy Bypass -File \\VBOXSVR\lab\scripts\Invoke-LabRun.ps1 -Type attack -TechniqueId T1059.001
```

> **⚠️ Prerequisite — the `lab` shared folder must exist first.** `\\VBOXSVR\lab` requires (a) VirtualBox
> Guest Additions installed in the Windows guest and (b) a shared folder named exactly `lab` pointing at
> the repo root, auto-mounted and **not** read-only. Neither was configured as of 2026-08-06 — the path
> was documented here before it was built, and every script invocation failed with
> *"The argument ... does not exist"*. Verify before relying on it:
> ```powershell
> Test-Path \\VBOXSVR\lab\scripts\Invoke-LabRun.ps1
> ```
> This mount is load-bearing for more than convenience: `Invoke-LabRun.ps1` writes its CSV row to
> `$PSScriptRoot\..\data\`, so without the share there is no route for detonation evidence to reach the
> repo, and it would have to be ferried out of the guest by hand for all 15 techniques.

> **Methodology note:** PowerShell execution policy had to be relaxed on the endpoint for Atomic Red
> Team to load. Record this alongside the Defender decision — both are deliberate lab configuration
> choices that would not be made on a production endpoint, and both belong in the methodology chapter
> as stated limitations on how closely the environment models a real one.

## 8. Clock — ⚠️ REGRESSED 2026-08-06. Check `synchronized: yes`, not just the timezone.

**Timezone state (stable):** Blue runs `Etc/UTC` and Wazuh writes UTC with an explicit `+0000` offset.
Windows runs `GMT Standard Time` with DST active, so **Windows local = UTC+1** in August.

**2026-08-05 measurement — no longer valid:** true skew was ~0 s and the one-hour gap was display
timezone only. On **2026-08-06** Blue was found ~4 h **behind** true UTC (`timedatectl` reported local
and universal time both 00:15 while the endpoint's UTC was 04:22). Timezone was still correctly
`Etc/UTC` — so **the timezone check passes while the clock is badly wrong**, which is why §8 previously
missed it. The tell was:

```
System clock synchronized: no
NTP service: active
```

`NTP service: active` only means the daemon is running, **not** that it has ever synced. A VM suspend,
snapshot revert, or the 2026-07-15 host disk incident can leave the guest clock stranded.

> ⚠️ **Do not use `timedatectl`'s `System clock synchronized:` line as the pass criterion on this host.**
> With chrony as the NTP client it stays `no` even when the clock is perfectly synced — confirmed
> 2026-08-06, when `chronyc tracking` reported `0.000000000 seconds slow of NTP time` while
> `timedatectl` still said `synchronized: no`. The authoritative check is `chronyc tracking`:
> **System time within a few ms and `Leap status : Normal`.** Ignore `RMS offset`, which is a decaying
> historical average and stays large for hours after a big correction.

**Impact if missed:** detonation windows are recorded from Windows (correct UTC) while alerts are
stamped by Blue (wrong). The labelling rule then matches nothing, every attack alert is labelled `0`,
and the positive class comes out empty with no error raised.

**Blue uses `chrony`, not `systemd-timesyncd`** — `systemd-timesyncd.service` does not exist on this
host. Fix and re-verify before detonating:
```bash
sudo chronyc makestep     # force an immediate step correction
chronyc tracking          # PASS = System time within a few ms + Leap status: Normal
sudo hwclock --systohc    # push corrected time to the RTC, or a reboot restores the fault
```

**Why chrony detects the error but does not fix it.** Ubuntu ships `makestep 1 3`, which steps the clock
only during the first three updates after start; after that it only slews, and a multi-hour offset will
never close by slewing. On 2026-08-06 chrony logged `System clock wrong by 14960.071860 seconds`
(4 h 09 m) and left it — the NTP sources had flapped offline/online during startup, consuming the step
allowance. Durable fix, in `/etc/chrony/chrony.conf`:

```
makestep 1 -1
```

`-1` means always step regardless of update count, so a stranded clock is corrected at every start
rather than silently tolerated. Restart chrony after editing.

After a large forward step, restart the Wazuh stack so services are not holding pre-jump time:
```bash
sudo systemctl restart wazuh-manager filebeat
```

Note: `chronyc tracking` reporting a large offset while `NTP service: active` is the signature of this
fault. `active` means the daemon runs, never that it has synced.

**Consequence:** detonation windows must be recorded in **UTC**, never in Windows local time. See
`LABELLING_SCHEME.md`. Recording local time would place every window one hour after its own alerts and
label the entire positive class as benign, silently.

Confirm the relationship still holds:
```powershell
"Local: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  UTC: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))"
```
```bash
timedatectl | grep -E 'Universal|Time zone|synchronized'
```
**Expect:** Windows UTC value and Blue universal time within a few seconds of each other. A snapshot
revert or DST change can alter this — the UK leaves BST in late October.

## 9. Kali — only when needed

```bash
cd ~/caldera && python3 server.py --insecure
```
Not a service; must be started manually. UI at `http://localhost:8888`, login `red`/`admin`.
The Sandcat agent on Windows is a transient process and does **not** survive a reboot — redeploy each
red-team session.

## 10. End of session

- [ ] Coverage table row filled for anything completed
- [ ] Rule-ID register updated
- [ ] Detonation log rows appended
- [ ] Git commit and push
- [ ] VirtualBox snapshot if a new working state was reached

---

## One-time cleanup (from lab-session handover §8.1 — do once, then delete this section)

- [ ] Confirm exactly one rule `100200` in `local_rules.xml`
- [ ] Remove stale agent 001: `sudo /var/ossec/bin/manage_agents -r 001`
- [ ] Snapshot Blue as `Blue-first-rule-working`
- [ ] Snapshot Windows as `Win-sensors-verified`
- [ ] Resolve the rule 100200 precision decision (`RULE_ID_REGISTER.md` note 1)
