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

- **Stage 5 — first end-to-end detection test:** run `Invoke-AtomicTest T1087.001` on the Windows endpoint while tailing `/var/ossec/logs/alerts/alerts.log` on Blue, to confirm the full attack → Sysmon → agent → SIEM pipeline.
- Verify the Kali/CALDERA red side after the host was rebooted (server is not set to auto-start).
- Begin the research phase: Sigma rules → Wazuh local rules, ATT&CK Navigator coverage layers, alert export to Python for Random Forest / XGBoost triage modelling.
