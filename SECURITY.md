# Security Policy — RedForge

## Purpose and authorization

RedForge is **defensive security tooling**: an automated red-team harness for
LLM applications you own, plus the reference defense stack it validates. Run
campaigns only against systems you are authorized to test. Bundled résumés,
names, and payloads are synthetic.

## Threat model (for the harness itself)

| Threat | Defense |
|---|---|
| Evidence files leak secrets collected during campaigns | Outputs are size-capped (`max_evidence_chars`) and the report stores masked evidence; band/URL patterns are scrubbed by the target's OutputFilter before they can persist |
| Campaign artifacts persist canary/audit markers | Detectors run on in-memory responses; persisted evidence notes flag rather than reproduce sensitive content |
| Harness becomes an attack proxy | No bundled payload executes network calls; exfil URLs are `.example` domains that go nowhere by construction |
| Supply chain | Minimal deps (pydantic/httpx/pyyaml/numpy); optional OTel/Langfuse extras are lazy-imported; CI runs pip-audit |
| Report tampering | Reports are plain markdown/JSON under your `--out` control; treat the CI gate's JSON as the signed artifact of record |

## Reporting

Open a GitHub issue marked `security`. Do not attach hostile payloads; name
the taxonomy id that misbehaved.
