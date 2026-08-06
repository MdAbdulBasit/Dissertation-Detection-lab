# ATT&CK Navigator layers

Coverage heatmap JSON layers (`LAB_HANDOVER_PHASE2.md` §7b). A key Chapter 4 figure.

**Planned layers:**

| File | Shows |
|------|-------|
| `baseline_default_wazuh.json` | What stock Wazuh detects, and at what ATT&CK depth |
| `engineered_custom_rules.json` | What the custom Sigma/Wazuh rules detect |
| `coverage_comparison.json` | Difference layer — the sub-technique gaps closed |

The comparison layer is the one that carries the argument: it visualises parent-only default coverage
against sub-technique engineered coverage across all 15 techniques.

Build at <https://mitre-attack.github.io/attack-navigator/>, export JSON here, and screenshot to
`evidence/`. Record the Navigator and ATT&CK version used — layer format is version-specific and an
old layer may not load in a newer Navigator.
