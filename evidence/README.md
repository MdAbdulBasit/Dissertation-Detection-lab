# Evidence — screenshots and raw output

Chapter 4 figures and the audit trail behind every claim (`LAB_HANDOVER_PHASE2.md` §7d).

**Naming:** `<TECHNIQUE_ID>_<what_it_shows>.png`
e.g. `T1087.001_default_vs_custom_rule.png`

## Required per technique

- Wazuh dashboard showing the custom rule firing (rule ID and level legible)
- Terminal output of the atomic execution
- Before/after comparison — default rule and custom rule side by side

## Project-level figures

- ATT&CK Navigator coverage heatmap
- Confusion matrices (RF, XGBoost)
- Feature importance plots
- Baseline vs ML comparison chart

## Capture standards

Zoom in enough that rule IDs, levels and ATT&CK IDs are readable when printed at figure size in the
dissertation — a full-desktop screenshot scaled to half a page is illegible and will not survive
examination. Include the timestamp in frame where possible; it ties the figure back to the detonation
log.

The T1087.001 side-by-side (default 92031 / L3 / T1087 alongside custom 100200 / L10 / T1087.001)
is the highest-value single figure in the chapter — it is the whole argument in one image.
