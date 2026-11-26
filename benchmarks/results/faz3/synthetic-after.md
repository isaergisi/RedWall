| scenario | before vuln (file/vuln/exact/flow) | before safe | after vuln (file/vuln/exact/flow) | after safe |
|---|---|---|---|---|
| s01_three_files | .... | quiet | .... | quiet |
| s02_relative_imports | .... | quiet | .... | quiet |
| s03_src_layout | xxx. | quiet | xxx. | quiet |
| s04_init_reexport | xxx. | quiet | xxx. | quiet |
| s05_factory | .... | quiet | .... | quiet |
| s06_inheritance | x... | quiet | x... | quiet |
| s07_self_method | xx.. | FLAGGED | xx.. | FLAGGED |
| s08_sanitizer_other_file | xxxx | quiet | xxxx | quiet |
| s09_validator_helper | xxxx | FLAGGED | xxxx | FLAGGED |
| s10_cyclic_import | xx.. | FLAGGED | xx.. | FLAGGED |
| s11_recursion | .... | quiet | .... | quiet |
| s13_fastapi_typed_param | .... | quiet | .... | quiet |
| s14_grpc_servicer | xxx. | quiet | xxx. | quiet |
| s15_syntax_error_file | xxxx | quiet | xxxx | quiet |

| tool | level | TP | FN | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| before | file | 9 | 5 | 3 | 11 | 0.75 | 0.64 | 0.69 |
| before | vuln | 8 | 6 | 3 | 11 | 0.73 | 0.57 | 0.64 |
| before | exact | 6 | 8 | 1 | 13 | 0.86 | 0.43 | 0.57 |
| before | flow | 3 | 11 | 1 | 13 | 0.75 | 0.21 | 0.33 |
| after | file | 9 | 5 | 3 | 11 | 0.75 | 0.64 | 0.69 |
| after | vuln | 8 | 6 | 3 | 11 | 0.73 | 0.57 | 0.64 |
| after | exact | 6 | 8 | 1 | 13 | 0.86 | 0.43 | 0.57 |
| after | flow | 3 | 11 | 1 | 13 | 0.75 | 0.21 | 0.33 |

s12_getattr_dispatch (before): reported without certainty; safe twin flagged

s12_getattr_dispatch (after): reported without certainty; safe twin flagged
