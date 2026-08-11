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

## ✅ ALL PHASES COMPLETE — 2026-08-10. Only the write-up remains.

**Start here:** [`CHAPTER4_HANDOVER.md`](CHAPTER4_HANDOVER.md) — every result, every figure, every
open decision, in one document.

**Phase 1 — lab build: complete.** Three VMs, attack → Sysmon → agent → SIEM verified end to end.

**Phase 2 — detection engineering: 15 of 15 techniques, 7 of 7 tactics, 37 custom rules.**
278 usable detonation windows of 344 logged, 66 superseded with a written reason. 2,683 labelled
in-window alerts (1,919 attack / 764 benign) from 4,976 retained. Eight distinct default-ruleset
failure modes characterised.

**Phase 3 — ML alert prioritisation: complete.** Random Forest reaches macro F1 **0.784 ± 0.071**
with rule identity withheld, against **0.428** for the best rule-based heuristic. Cross-validated by
detonation window; XGBoost matches it to 0.004.

### The headline findings

| | |
|---|---|
| Coverage | Blind techniques **7 → 0** after 37 rules |
| Discrimination | Detections that never fire on benign activity **3 → 1** |
| Rules as a triage signal | **0.379** macro F1 — *below* the 0.417 for escalating everything |
| Perfect ATT&CK attribution as a triage signal | **0.412** — also below escalating everything |
| §3.4 criterion (FP reduction at matched recall) | **99.7%** — 605 false positives → 2 |
| Realistic workload saving at 99% recall | **~15%** |

**The convergent finding:** across fifteen techniques, every rule that separated attacker from
administrator encoded *what was done to what*; every rule that failed encoded *how*.

Scope: 15 techniques across 7 tactics and 5 Sysmon event types, approved with supervisor.
Deadline **1 September 2026**.

## Working conventions

- Custom Wazuh rule IDs come from `RULE_ID_REGISTER.md`. Never guess an ID — duplicates fail silently.
- Sigma first, then translate to Wazuh XML. The Sigma rule is the portable artefact.
- Every technique gets: a coverage table row, a Sigma rule, evidence screenshots, and a Git commit.
- Every deviation from the planned technique set gets recorded with its reason — these become
  methodology and limitations notes.
- No credentials, keys or VM disk images in this repository.
