held-out set, seal verified

| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| d3 | file | 5 | 8 | 5 | 8 | 0.50 | 0.39 | 0.43 |
| d3 | vuln | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| d3 | exact | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| d3 | flow | 3 | 10 | 2 | 11 | 0.60 | 0.23 | 0.33 |
| d4 | file | 5 | 8 | 5 | 8 | 0.50 | 0.39 | 0.43 |
| d4 | vuln | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| d4 | exact | 4 | 9 | 4 | 9 | 0.50 | 0.31 | 0.38 |
| d4 | flow | 3 | 10 | 2 | 11 | 0.60 | 0.23 | 0.33 |

d3: 347 findings on the vulnerable trees, 34 s; d4: 347 findings on the vulnerable trees, 35 s
FP/TN come from the fixed trees: precision here is case-level against the fixed release.
