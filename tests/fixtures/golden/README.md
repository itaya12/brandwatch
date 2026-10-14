# Golden dataset (spec §18) — structure only in Phase 0

Four classes, 100 entries each, filled in Phase 1 and used to calibrate scoring weights and to
report precision / recall / FP rate / FN rate on every scoring change:

| File | Class | What it is for |
|---|---|---|
| `phishing.jsonl` | known phishing | true positives |
| `legit.jsonl` | legitimate, unrelated | true negatives |
| `brand_related_legit.jsonl` | legitimate and brand-related (partners, resellers, fan sites) | the realistic FP surface |
| `suspicious_not_phishing.jsonl` | brand-support / brand-review / lookalike-but-benign | where the real FP problem lives |

Each line: `{"url": ..., "brand": ..., "label": ..., "recorded_evidence": {...}, "notes": ...}`.
Recorded provider responses (VCR-style) live next to each entry so the suite never calls a live API.
The public demo uses a fictional brand; no real brand's assets are committed here.
