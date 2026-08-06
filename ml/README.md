# ML phase — alert prioritisation

Per `LAB_HANDOVER_PHASE2.md` §8. Jupyter notebook plus saved metrics and plots.

## Inputs

- `../data/alerts_dataset.csv` — one row per alert, labelled per `../LABELLING_SCHEME.md`
- `../data/detonation_log.csv` — provenance windows used to derive labels

## Pipeline

1. Load, filter to `agent_name = win-endpoint`, encode categoricals
2. Stratified train/test split — **stratify on the label**, the classes are deliberately imbalanced
3. Train Random Forest and XGBoost (justified via Grinsztajn et al. 2022; Jalalvand et al. 2024;
   Wang et al. 2024 AlertPro)
4. Evaluate: precision, recall, F1, **false-positive rate**; confusion matrices
5. Feature importance rankings — supports the explainability argument in the methodology
6. **Baseline comparison** — the critical step

## The baseline comparison is the result

The success criterion from the methodology is a *measurable reduction in false-positive rate without a
corresponding loss of recall*. That is a comparison, not a single model score. An F1 of 0.95 means
nothing on its own.

The baseline is **ranking alerts by `rule_level` alone** — i.e. detection engineering with no ML, which
is what a SOC using stock severity does today. Compare like for like: take the top-N alerts by
`rule_level`, take the top-N by model score, and compare precision and FP-rate at the same N.

Report both. If the ML ranking does not beat `rule_level` ranking, that is a legitimate finding and
should be reported as such rather than buried — a negative result on a well-constructed experiment is
publishable and defensible.

## Watch for

- **Leakage via `rule_id`** — if a custom rule only ever fires during detonations, `rule_id` becomes a
  near-perfect proxy for the label and the model learns nothing generalisable. Check feature importance
  for a single dominant `rule_id`/`rule_level` feature, and report a variant with it removed.
- **Leakage via timestamp** — if attacks cluster in time, the model can learn the clock instead of the
  behaviour. The benign-session sequencing in `../BENIGN_ACTIVITY_PROTOCOL.md` §4 is designed to
  prevent this; verify it worked.
- **Tiny positive class** — with 15 techniques the positive class may be small. Report absolute counts
  alongside every percentage, and prefer stratified cross-validation over a single split.

## Outputs to save here

Notebook, `metrics.json`, confusion matrix plots, feature importance plots, baseline comparison table.
