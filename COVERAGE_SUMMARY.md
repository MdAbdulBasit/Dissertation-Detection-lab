# Coverage summary — appendix table

The compact, appendix-ready version of `COVERAGE_TABLE.md`, which is the ~90,000-character working
record and is not readable as an appendix. Scores are read from `scripts/build_navigator_layers.py`, so
this table cannot disagree with the Navigator figures. Counts come from `data/labelled_alerts.csv`.

| # | Technique ID | Technique | Tactic | Default outcome | Custom rules | Attack alerts | Benign alerts |
|---|---|---|---|---|---|---|---|
| 1 | T1087.001 | Local Account Discovery | Discovery | Parent only | 100200 | 50 | 15 |
| 2 | T1082 | System Information Discovery | Discovery | Blind | 100230-100233 | 186 | 29 |
| 3 | T1033 | System Owner/User Discovery | Discovery | Detected, discriminating | 100240-100241 | 152 | 15 |
| 4 | T1016 | System Network Configuration Discovery | Discovery | Blind | 100250-100252 | 54 | 16 |
| 5 | T1059.001 | PowerShell | Execution | Detected | None | 61 | 15 |
| 6 | T1059.003 | Windows Command Shell | Execution | Detected | None | 45 | 15 |
| 7 | T1053.005 | Scheduled Task | Persistence | Blind | 100270-100271 | 48 | 38 |
| 8 | T1136.001 | Create Local Account | Persistence | Detected, discriminating | 100280-100283 | 169 | 56 |
| 9 | T1547.001 | Registry Run Keys / Startup Folder | Persistence | Detected | 100290-100292, 100294 | 35 | 45 |
| 10 | T1112 | Modify Registry | Defense Evasion | Detected | 100260-100264 | 85 | 55 |
| 11 | T1218.011 | Rundll32 | Defense Evasion | Blind | 100300-100302 | 30 | 15 |
| 12 | T1070.004 | File Deletion | Defense Evasion | Blind | 100310-100313 | 47 | 30 |
| 13 | T1560.001 | Archive via Utility | Collection | Blind | 100330-100332 | 10 | 17 |
| 14 | T1003.001 | LSASS Memory | Credential Access | Blind | 100320-100321 | 16 | 10 |
| 15 | T1105 | Ingress Tool Transfer | Command and Control | Detected, discriminating | None | 85 | 15 |

**Totals:** 37 custom rules deployed · 1073 attack alerts · 386 benign alerts across
the final phase of all 15 techniques.

## Reading this table

**"Default outcome" is the BASELINE phase** — stock Wazuh 4.14.6 with no customisation. It gives the
headline coverage result:

| Outcome | Techniques |
|---|---|
| Blind — no alert carries the technique or its parent | **7** |
| Parent only — behaviour seen, sub-technique lost | **1** |
| Detected at the correct technique | **4** |
| Detected **and** never fires on benign activity | **3** |

After the 37 custom rules this becomes **0 / 0 / 14 / 1** — every blind spot closed, and the count of
detections that fire *only* on genuine attack activity falls from 3 to 1. **That is the
central finding: rule engineering solves coverage, not discrimination.**

**Alert counts are the FINAL phase** — `custom` for most techniques, `custom-sensor` for T1112,
T1070.004 and T1003.001 which required a widened Sysmon configuration, and `baseline` for the three
given no custom rule.

**Three techniques have no custom rules** — T1059.001, T1059.003 and T1105 — because the default
ruleset was already correct. T1105's default is also the only *discriminating* vendor detection in the
study. Writing rules there would have duplicated working detection and inflated the apparent
contribution of this project.

⚠️ **`100293` is absent from the T1547.001 range.** It was written, found unreachable, and retired;
the ID remains reserved so it cannot be reused.

