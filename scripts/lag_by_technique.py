"""DO NOT USE — retained only as a worked example of a measurement bug.

Written 2026-08-08 to split forwarding lag by technique. It reported a p50 of ~200s against
export_labelled_alerts.py's 16s on the same data, and every technique looked equally slow, which was
the tell: a real pipeline problem does not affect all techniques identically.

The defect was the attribution rule. It took the FIRST window whose `end + 300s` tail contained the
alert:

    for s, e, t in wins:
        if s - 5s <= ts <= e + 300s:
            lag = ts - e
            break

With gaps of 180-300s, every window's 300s tail overlaps the whole of the next window. So an alert
belonging to window N+1, arriving 15s after it, was charged to window N and recorded as ~200s of lag.
The correct rule, which report_lag() in export_labelled_alerts.py already used, is the MOST RECENT
window whose start precedes the alert:

    prior = [w for w in wins if w.start - PRE_BUFFER <= ts]
    lag   = ts - prior[-1].end

Two lessons worth keeping:

1. When a new measurement disagrees with an existing one by an order of magnitude, suspect the new
   measurement first. The instinct here was to trust the fresh script over the established function.

2. Re-implementing logic that already exists elsewhere in the codebase to answer a variant question is
   how the two drift apart. The split by technique was added INTO report_lag() instead, so it shares
   the attribution rule by construction and cannot disagree with the headline figure.

Use:  sudo python3 export_labelled_alerts.py --windows ~/detonation_log.csv --lag-report
"""

raise SystemExit(__doc__)
