# BUILD LOG — MSc Dissertation Detection Lab

**Student:** Abdul Basit Mohammed | **Institution:** Sheffield Hallam University
**Project:** Detection Engineering with Intelligent Alert Triage — a MITRE ATT&CK-mapped detection pipeline with ML-based alert prioritisation.

This log records the construction of the purple-team lab that forms the practical infrastructure of the dissertation. It is written as a running record so that the environment can be rebuilt from scratch and so that methodology decisions are traceable.

---

## 1. Lab architecture

Three virtual machines on a single host, connected on an isolated internal network so that emulated attacks are sealed off from the real network.

| Role | VM | OS | Purpose | labnet IP |
|------|----|----|---------|-----------|
| Red | Kali VM | Kali Linux (official pre-built image) | CALDERA C2 + attack tooling | 10.10.10.30 |
| Blue | BlueTeam_Wazuh_VM | Ubuntu Server 25.04 | Wazuh SIEM (indexer + manager + filebeat + dashboard) | 10.10.10.10 |
| Endpoint | Endpoint_Windows10_VM | Windows 10 Pro | Victim/sensor — Sysmon + Wazuh agent + Atomic Red Team | 10.10.10.20 |

**Host:** Lenovo laptop, Windows 11 Home, 16 GB RAM. Single hardware constraint — the three VMs are not all run at full load simultaneously.

**Networking:** each VM has two adapters — Adapter 1 NAT (internet for package downloads) and Adapter 2 Internal Network named `labnet` (isolated VM-to-VM). Blue additionally has Adapter 3 Host-Only (`vboxnet0`, 192.168.56.0/24) for host management access (SSH + dashboard). Blue host-only IP: 192.168.56.101.

**Hypervisor:** VirtualBox (chosen after VMware Workstation proved incompatible with the host's Windows 11 Hyper-V/VBS/Credential Guard security stack). VirtualBox runs in Hyper-V mode with host security left enabled.

---

## 2. Current status — all components operational

- **Blue / Wazuh SIEM — fully operational.** Indexer, manager, filebeat and dashboard all running. Cluster health green. Alerts flowing end to end (`wazuh-alerts-*` index populated).
- **Windows endpoint — reporting to Blue.** Wazuh agent enrolled and shown as **active** in the dashboard (agent ID 001, `DESKTOP-2VJPE09`, 10.10.10.20). Sysmon (SwiftOnSecurity config) and Atomic Red Team installed and verified.
- **Kali / red team — CALDERA operational (source install).** Sandcat agent successfully deployed to the Windows endpoint over labnet.

---

## 3. What is installed, by VM

### Blue (Wazuh SIEM)
- Wazuh 4.14.6 central components installed via the **step-by-step method** (not the all-in-one assistant — see lessons below).
- Indexer JVM heap capped at 2 GB (`-Xms2g` / `-Xmx2g`) set **before** first start.
- systemd `DefaultTimeoutStartSec` raised to 600 s to accommodate slow first-time service start on constrained hardware.
- Certificates generated with `wazuh-certs-tool.sh` against a single-node `config.yml` (all three roles on 10.10.10.10).
- Dashboard reachable at `https://192.168.56.101` (self-signed cert). Default credentials `admin`/`admin` (lab only — a production deployment would rotate these with `wazuh-passwords-tool.sh`).

### Windows endpoint
- Sysmon v15.21 with SwiftOnSecurity configuration.
- Atomic Red Team (Invoke-AtomicRedTeam) with `C:\AtomicRedTeam` and `C:\Users\Public` added to Defender exclusions.
- Wazuh agent 4.14.6, manager set to 10.10.10.10, enrolled via `agent-auth.exe` and running.
- CALDERA Sandcat agent (`splunkd.exe`) in `C:\Users\Public`, group `red`.
- **AtomicTestHarnesses PowerShell module** — installed 2026-08-07 from the PowerShell Gallery via
  `Invoke-AtomicTest T1059.001 -TestNumbers 13,14,15,16 -GetPrereqs`. Required by the
  `ATHPowerShellCommandLineParameter` atomics (T1059.001 tests 13–16), which otherwise fail with
  *"not recognized as the name of a cmdlet"* — a failure that looks identical to a technique going
  undetected. Recorded here because it is a change to the endpoint's installed software and therefore
  affects reproducibility. This is a one-time install, unlike WinPwn/PowerView/AdFind which download on
  every execution and are excluded on those grounds.
- **Endpoint RAM raised 3072 MB → 4096 MB** on 2026-08-07 to reduce the Sysmon→agent forwarding-lag tail.
  Fast Startup disabled (`powercfg /h off`) after the RAM change sent the VM into Automatic Repair — a
  hibernation resume image is invalid once the hardware profile changes.
- **VirtualBox Guest Additions installed** — `VBoxService` confirmed `Running` 2026-08-06. Was installed
  during initial VM setup but never recorded here, which led to it being assumed absent. No shared
  folders were defined against it, so `\\VBOXSVR\<name>` returned *System error 53* until the `lab`
  share was added (see PREFLIGHT_CHECKLIST.md §7).
- Windows Defender Tamper Protection and real-time protection disabled — a deliberate lab decision so that emulated techniques execute and are caught by the detection pipeline rather than pre-empted by Defender. (This should be stated explicitly in the dissertation methodology.)

### Kali (red team)
- CALDERA installed from the official MITRE source (git clone), not the Kali apt package.
- Started with `cd ~/caldera && python3 server.py --insecure` (drop `--build` after first run).
- Dependencies present: Go 1.26.4, Node.js/npm.

---

## 4. Hard-won lessons (rebuild notes)

These are the non-obvious fixes discovered during the build. Recorded so the environment can be rebuilt without repeating the same dead ends.

1. **Wazuh on a low-resource VM: use the step-by-step install, not `-a`.** The all-in-one assistant repeatedly rolled everything back when any single component failed. Installing indexer → server → dashboard separately isolates failures and keeps working components in place.
2. **Cap the indexer heap before first start**, and raise the systemd start timeout. A fresh indexer trying to initialise on a slow VM was being killed by systemd's default ~90 s timeout before it finished.
3. **Grow the disk partition to its full size.** The virtual disk was 50 GB but the Ubuntu LVM volume only claimed ~24 GB; it filled during install and caused misleading "disk full / broken pipe" dashboard extraction failures. Fixed with `lvextend -l +100%FREE` then `resize2fs` (no data loss) — now 48 GB.
4. **If a Wazuh install fails mid-way, fully purge before retrying** — leftover half-configured packages (status `pF`) block reinstalls. `dpkg` maintainer scripts sometimes have to be neutralised to force removal.
5. **CALDERA: use the git-clone source install, not the Kali apt package** — the packaged build shipped broken default data (every API call returned 500). Node.js/npm and Go must be present for the web UI build and agent compilation.
6. **Windows Wazuh agent does not auto-enrol.** The MSI installs it but the service dies on start (error 1067, no key). Run `agent-auth.exe -m <manager-ip>` to enrol, then `NET START WazuhSvc`.
7. **TLS certificate address matching.** Filebeat and the dashboard must connect to the indexer on the IP the certificate was issued for (10.10.10.10), not `localhost`/`127.0.0.1`, or the handshake fails.

---

## 5. Next steps

Superseded — see **`PROJECT_PLAN.md`** for the current plan (housekeeping, sample-size decision,
remaining 14 techniques batched by Sysmon event ID, and the analysis/write-up phases).

Stage 5 (first end-to-end detection test) is **complete** as of 2026-08-06: T1087.001 tests 8, 9, 10
detonated with UTC-bracketed windows, rule `100200` confirmed firing at level 10, 10 attack / 4 benign
alerts recorded. Remaining from the original list:

- Verify the Kali/CALDERA red side after host reboots (server is not set to auto-start). Needed for
  T1105 only.
- Research phase: Sigma → Wazuh rules, ATT&CK Navigator coverage layers, alert export to Python for
  Random Forest / XGBoost triage modelling.

## Update - host disk incident & lab hardening (2026-07-15)

Host C: drive filled to under 500 MB free, which caused the Blue VM's virtual disk (.vdi) to become detached from its VirtualBox storage controller. Blue failed to boot with "could not read from boot medium". No data was lost - the .vdi file was intact, and re-attaching it under Controller: SATA restored the VM fully. Freed ~97 GB of host space by uninstalling non-essential software.

All three VMs were then re-verified operational post-incident (Wazuh dashboard, Windows Wazuh agent active, CALDERA server healthy, Sandcat agent redeployed) and VirtualBox snapshots were taken of each as clean restore points.

Note: the CALDERA Sandcat agent runs as a transient hidden process, not a service, so it does not persist across Windows reboots and must be redeployed when starting a red-team session. The Wazuh agent, installed as a Windows service (WazuhSvc), does persist and auto-starts.
