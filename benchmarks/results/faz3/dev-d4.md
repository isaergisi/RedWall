| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| d3 | file | 14 | 3 | 1 | 6 | 0.93 | 0.82 | 0.88 |
| d3 | vuln | 13 | 4 | 1 | 6 | 0.93 | 0.77 | 0.84 |
| d3 | exact | 9 | 8 | 1 | 6 | 0.90 | 0.53 | 0.67 |
| d3 | flow | 3 | 14 | 0 | 7 | 1.00 | 0.18 | 0.30 |
| d4 | file | 14 | 3 | 1 | 6 | 0.93 | 0.82 | 0.88 |
| d4 | vuln | 13 | 4 | 1 | 6 | 0.93 | 0.77 | 0.84 |
| d4 | exact | 9 | 8 | 1 | 6 | 0.90 | 0.53 | 0.67 |
| d4 | flow | 3 | 14 | 0 | 7 | 1.00 | 0.18 | 0.30 |

d3: 756 findings on the vulnerable trees, 17 s; d4: 754 findings on the vulnerable trees, 18 s
FP/TN come from the fixed trees: precision here is case-level against the fixed release.

| case | advisory | CWE | d3 | d4 |
|---|---|---|---|---|
| gerapy-configure | CVE-2021-43857 | 78 | medium, #13/14 P2, cleared after fix | medium, #13/14 P2, cleared after fix |
| gerapy-clone | fixed with CVE-2021-43857 in 0.9.8 | 78 | high, #1/14 P1, cleared after fix | high, #1/14 P1, cleared after fix |
| gerapy-parse | fixed with CVE-2021-43857 in 0.9.8 | 78 | high, #2/14 P1, cleared after fix | high, #2/14 P1, cleared after fix |
| pgadmin-binary-path | CVE-2023-5002 | 78 | high, #1/554 P1, cleared after fix | high, #1/552 P1, cleared after fix |
| pyload-cnl-eval-js | CVE-2023-0297 | 94 | missed | missed |
| calibreweb-cover-ssrf | CVE-2022-0939 | 918 | missed | missed |
| openwebui-model-upload | CVE-2024-7034 (rejected by vendor/CNA: admin-only endpoint) | 22 | high, #1/35 P1 | high, #1/35 P1 |
| langflow-validate-exec | CVE-2025-3248 | 94 | low, #17/32 P3, still flagged after fix | low, #17/32 P3, still flagged after fix |
| ray-cpu-profile | CVE-2023-6019 | 78 | missed | missed |
| archery-101-describe | GHSL-2022-101 | 89 | medium, #30/31 P3 | medium, #30/31 P3 |
| archery-102-execute-check | GHSL-2022-102 | 89 | medium, #19/31 P3, shared sink only | medium, #19/31 P3, shared sink only |
| archery-103-explain-check | GHSL-2022-103 | 89 | medium, #18/31 P3 | medium, #18/31 P3 |
| archery-104-param-edit | GHSL-2022-104 | 89 | missed | missed |
| archery-105-table-list | GHSL-2022-105 | 89 | medium, #16/31 P3, shared sink only | medium, #16/31 P3, shared sink only |
| archery-106-table-info | GHSL-2022-106 | 89 | medium, #16/31 P3, shared sink only | medium, #16/31 P3, shared sink only |
| archery-107-sqltuning | GHSL-2022-107 | 89 | medium, #26/31 P3 | medium, #26/31 P3 |
| archery-108-explain | GHSL-2022-108 | 89 | medium, #16/31 P3, shared sink only | medium, #16/31 P3, shared sink only |

d3: 13/17 detected (9 at an advisory-specific sink); d4: 13/17 detected (9 at an advisory-specific sink)
