# Held-out set (phase 3)

`cases.json` holds 13 published vulnerabilities in 13 open-source Python web applications. It was selected
and sealed on 2026-11-26, before any phase 3 engine change (RedWall at commit `8b17a8c`), so that phase 3
can be measured on code nobody looked at while designing it. `SEAL` holds the sha256 of the manifest's
`projects` and `cases` (canonical JSON, see `benchmarks/realworld/score.py:manifest_digest`).

## How to use it

```bash
python benchmarks/realworld/run.py --manifest benchmarks/heldout/cases.json \
    --redwall-src before=/path/to/main-checkout --redwall-src after=.
```

- Run it only to measure a finished change, before and after.
- Report the aggregate numbers. Do not open per-case misses to design or tune a rule: the set stops being
  held-out the moment that happens. If it ever does, say so in the report and select a new set.
- `run.py` refuses to score a manifest whose digest does not match `SEAL`, unless `--allow-unsealed` is
  passed, and then marks the run as unsealed.

## Selection protocol

1. **Pool.** GitHub Advisory Database (`github/advisory-database`, commit `fb93ce73`, 2026-11-25),
   reviewed advisories only, ecosystem PyPI, published 2023-01-01 to 2025-06-30, at least one CWE in
   {22, 77, 78, 79, 89, 90, 94, 95, 502, 601, 611, 643, 918, 1336}, and at least one reference to a GitHub
   fix commit. The 8 projects of the phase 2 set (`benchmarks/realworld/cves.json`) are excluded.
   Result: 374 advisories in 193 packages.
2. **Server applications only.** RedWall's taint rules model network requests, so the pool was restricted
   to packages that are deployable web applications or servers (libraries, SDKs and CLI tools removed by
   reading the package description). Result: 155 advisories in 37 packages.
3. **Order.** Packages sorted by name and shuffled with `random.Random(20261126)`; within each package the
   advisories were sorted and shuffled with the same generator. Packages were then walked in that order and
   the first advisory meeting the criteria below was taken, at most one per project. The walk stopped at 13
   accepted cases.
4. **Inclusion.** A server-side flow from a network request to a Python sink, where both ends are in the
   project's own Python code and the source and sink lines can be determined from the fix commit's parent.
   Cases where the code had a validator that the advisory bypasses are included (the validator is part of
   the realistic difficulty).
5. **Exclusion.** Stored or second-order flows (data goes through a database or a file first); XSS that
   lives in templates or JavaScript; client-side code; Windows-only issues; fixes that change configuration
   or a feature flag rather than a flow; flows through file contents, archives or third-party parsers;
   fixes bundled with unrelated changes so the vulnerable lines cannot be isolated; fix commits that can no
   longer be fetched.
6. **Ground truth.** Lines are taken at the parent of the fix commit (`ref`). Sinks are the lines the fix
   protects; sources are where the attacker-controlled value enters Python code.

### Packages walked, in order

| Package | Outcome |
|---|---|
| jupyterlab | skipped: XSS in frontend code |
| apache-airflow | skipped: second-order flows, feature flags, stored XSS |
| esphome | **esphome-config-write** |
| docassemble.webapp | skipped: fix bundled with unrelated changes |
| vantage6 | skipped: client-side / algorithm container pickle |
| flask-appbuilder | skipped: configuration / validator setting |
| octoprint | skipped: stored template injection |
| invokeai | **invokeai-delete-image** (the other advisory is about file contents) |
| jupyter-server | **jupyterserver-login-next** |
| mobsf | **mobsf-login-next** (another advisory is about APK contents) |
| nautobot | skipped: template-only |
| apache-superset | skipped: Jinja macro / authorization issues |
| mindsdb | **mindsdb-file-url** (others: third-party SQL parser, release-only commit) |
| modoboa | skipped: JavaScript / template XSS |
| streamlit | **streamlit-component-path** (another advisory is Windows-only) |
| mlflow | **mlflow-delete-artifact** (others: Windows-only, client-side, second-order, local recipes, content type) |
| litellm | **litellm-global-spend** (others: configuration import, third-party library, environment secret) |
| gradio | skipped: ground truth not determinable from the fix |
| scancodeio | skipped: second-order (background job) |
| lollms | skipped: fix commits no longer fetchable |
| copyparty | **copyparty-dot-cpr** (others: JavaScript / template XSS) |
| kiwitcms | skipped from the advisory text alone: stored XSS and HTTP header configuration |
| postgraas-server | **postgraas-create-db** |
| geonode | **geonode-sld-xxe** |
| indico | skipped from the advisory text alone: XSS in a third-party package and in templates |
| ckan | skipped: documentation-only commit / template XSS |
| ethyca-fides | **fides-ui-catchall** |
| whoogle-search | **whoogle-config-name** |

After whoogle-search two more packages were inspected as reserves in case a case above fell through
(dtale: feature flag; llamafactory: local script, both rejected). None was needed, and the remaining 7
packages were not looked at. The set is small (13 cases), so a single case is worth 7.7
percentage points of recall: differences of one or two cases are noise, and reports should say so.
