| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| before | file | 14 | 3 | 1 | 6 | 0.93 | 0.82 | 0.88 |
| before | vuln | 13 | 4 | 1 | 6 | 0.93 | 0.77 | 0.84 |
| before | exact | 9 | 8 | 1 | 6 | 0.90 | 0.53 | 0.67 |
| before | flow | 3 | 14 | 0 | 7 | 1.00 | 0.18 | 0.30 |

before: 753 findings on the vulnerable trees, 20 s
FP/TN come from the fixed trees: precision here is case-level against the fixed release.

| case | advisory | CWE | before |
|---|---|---|---|
| gerapy-configure | CVE-2021-43857 | 78 | medium, #13/14 P2, cleared after fix |
| gerapy-clone | fixed with CVE-2021-43857 in 0.9.8 | 78 | high, #1/14 P1, cleared after fix |
| gerapy-parse | fixed with CVE-2021-43857 in 0.9.8 | 78 | high, #2/14 P1, cleared after fix |
| pgadmin-binary-path | CVE-2023-5002 | 78 | high, #1/556 P1, cleared after fix |
| pyload-cnl-eval-js | CVE-2023-0297 | 94 | missed |
| calibreweb-cover-ssrf | CVE-2022-0939 | 918 | missed |
| openwebui-model-upload | CVE-2024-7034 (rejected by vendor/CNA: admin-only endpoint) | 22 | high, #1/35 P1 |
| langflow-validate-exec | CVE-2025-3248 | 94 | low, #17/32 P3, still flagged after fix |
| ray-cpu-profile | CVE-2023-6019 | 78 | missed |
| archery-101-describe | GHSL-2022-101 | 89 | medium, #30/31 P3 |
| archery-102-execute-check | GHSL-2022-102 | 89 | medium, #19/31 P3, shared sink only |
| archery-103-explain-check | GHSL-2022-103 | 89 | medium, #18/31 P3 |
| archery-104-param-edit | GHSL-2022-104 | 89 | missed |
| archery-105-table-list | GHSL-2022-105 | 89 | medium, #16/31 P3, shared sink only |
| archery-106-table-info | GHSL-2022-106 | 89 | medium, #16/31 P3, shared sink only |
| archery-107-sqltuning | GHSL-2022-107 | 89 | medium, #26/31 P3 |
| archery-108-explain | GHSL-2022-108 | 89 | medium, #16/31 P3, shared sink only |

before: 13/17 detected (9 at an advisory-specific sink)
