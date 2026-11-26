held-out set, seal verified

| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| before | file | 5 | 8 | 5 | 8 | 0.50 | 0.39 | 0.43 |
| before | vuln | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| before | exact | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| before | flow | 3 | 10 | 2 | 11 | 0.60 | 0.23 | 0.33 |

before: 353 findings on the vulnerable trees, 35 s
FP/TN come from the fixed trees: precision here is case-level against the fixed release.
