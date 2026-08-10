# dissertation-detection-lab

Practical lab for the MSc Cyber Security dissertation **"Integrating Detection Engineering and Machine
Learning for SOC Alert Prioritisation"** — Abdul Basit Mohammed (c5038891), Sheffield Hallam
University. Supervisor: Dr Sina Pournouri.

**Research question:** Can combining ATT&CK-mapped detection engineering with machine-learning-based
alert prioritisation improve both threat detection coverage and alert manageability in a Security
Operations Centre?

---

## Repository index

| Path | Contents |
|------|----------|
| `PREFLIGHT_CHECKLIST.md` | **Start every session here.** Health checks and the things that silently reset |
| `RULE_ID_REGISTER.md` | Pre-allocated Wazuh rule IDs per technique — prevents the duplicate-ID trap |
| `COVERAGE_TABLE.md` | Primary Chapter 4 findings artefact — one row per technique |
| `LABELLING_SCHEME.md` | Ground-truth label definition and edge cases. Fixed before collection |
| `BENIGN_ACTIVITY_PROTOCOL.md` | How the ML negative class is generated, and why the obvious approach fails |
| `BUILD_LOG.md` | How the lab was built; hard-won lessons and rebuild notes |
| `BUILD_STEPS.md` | Step-by-step build commands |
| `sigma_rules/` | Detection-as-code artefacts — Sigma `.yml` per technique |
| `navigator_layers/` | ATT&CK Navigator layers (v14 citable + v19 renderable) and exported SVG figures |
| `data/` | Detonation log and exported alert datasets |
| `ml/` | Triage model results — Random Forest **and** XGBoost, rule-based baselines, operating points |
| `evidence/` | Screenshots and raw output for Chapter 4 figures |

## Lab topology

| Role | VM | OS | labnet IP | Purpose |
|------|----|----|-----------|---------|
| Blue | BlueTeam_Wazuh_VM | Ubuntu Server 25.04 | 10.10.10.10 | Wazuh 4.14.6 SIEM |
| Endpoint | Endpoint_Windows10_VM | Windows 10 Pro | 10.10.10.20 | Sysmon + Wazuh agent + Atomic Red Team |
| Red | KALi_RedTeam_VM | Kali 2026.2 | 10.10.10.30 | CALDERA C2 |

Host: Windows 11, 16 GB RAM, VirtualBox. Blue also on host-only `vboxnet0` at **192.168.56.101**
(SSH + dashboard). See `BUILD_LOG.md` §1 for full networking detail.

## Quick access

```bash
ssh basit@192.168.56.101                              # Blue
sudo tail -f /var/ossec/logs/alerts/alerts.log        # live alerts
sudo /var/ossec/bin/agent_control -l                  # agent status
```
Dashboard: `https://192.168.56.101` — `admin`/`admin` (lab only)
Custom rules: `/var/ossec/etc/rules/local_rules.xml` on Blue

## Progress

**Phase 1 — lab build: complete.** All three VMs operational, attack → Sysmon → agent → SIEM pipeline
verified end to end.

**Phase 2 — detection engineering: 1 of 15 techniques complete.**
T1087.001 fires custom rule 100200 (L10, sub-technique mapped) alongside default 92031 (L3, parent
only). That side-by-side is the dissertation's core argument in miniature.

**Phase 3 — ML alert prioritisation: not started.** Blocked on data collection.

Scope: 15 techniques across 7 tactics and 5 Sysmon event types, approved with supervisor.
Deadline **1 September 2026**.

## Working conventions

- Custom Wazuh rule IDs come from `RULE_ID_REGISTER.md`. Never guess an ID — duplicates fail silently.
- Sigma first, then translate to Wazuh XML. The Sigma rule is the portable artefact.
- Every technique gets: a coverage table row, a Sigma rule, evidence screenshots, and a Git commit.
- Every deviation from the planned technique set gets recorded with its reason — these become
  methodology and limitations notes.
- No credentials, keys or VM disk images in this repository.
