| scenario | d4 vuln (file/vuln/exact/flow) | d4 safe | d5 vuln (file/vuln/exact/flow) | d5 safe |
|---|---|---|---|---|
| s01_three_files | .... | quiet | xxxx | quiet |
| s02_relative_imports | .... | quiet | xxxx | quiet |
| s03_src_layout | xxx. | quiet | xxxx | quiet |
| s04_init_reexport | xxx. | quiet | xxxx | quiet |
| s05_factory | .... | quiet | xxxx | quiet |
| s06_inheritance | xxx. | quiet | xxxx | quiet |
| s07_self_method | xx.. | FLAGGED | xxxx | FLAGGED |
| s08_sanitizer_other_file | xxxx | quiet | xxxx | quiet |
| s09_validator_helper | xxxx | FLAGGED | xxxx | quiet |
| s10_cyclic_import | xx.. | FLAGGED | xxxx | FLAGGED |
| s11_recursion | .... | quiet | xxxx | quiet |
| s13_fastapi_typed_param | .... | quiet | xxxx | FLAGGED |
| s14_grpc_servicer | xxx. | quiet | xxx. | quiet |
| s15_syntax_error_file | xxxx | quiet | xxxx | quiet |

| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| d4 | file | 9 | 5 | 3 | 11 | 0.75 | 0.64 | 0.69 |
| d4 | vuln | 9 | 5 | 3 | 11 | 0.75 | 0.64 | 0.69 |
| d4 | exact | 7 | 7 | 1 | 13 | 0.88 | 0.50 | 0.64 |
| d4 | flow | 3 | 11 | 1 | 13 | 0.75 | 0.21 | 0.33 |
| d5 | file | 14 | 0 | 3 | 11 | 0.82 | 1.00 | 0.90 |
| d5 | vuln | 14 | 0 | 3 | 11 | 0.82 | 1.00 | 0.90 |
| d5 | exact | 14 | 0 | 1 | 13 | 0.93 | 1.00 | 0.97 |
| d5 | flow | 13 | 1 | 1 | 13 | 0.93 | 0.93 | 0.93 |

s12_getattr_dispatch (d4): reported without certainty; safe twin flagged

s12_getattr_dispatch (d5): reported without certainty; safe twin flagged
