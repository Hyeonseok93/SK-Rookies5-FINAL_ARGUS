# ARGUS 1-1 XSS / CSRF Module Scope

## Detects

- Reflected XSS by isolated parameter fuzzing and response reflection analysis.
- Stored XSS by mutation request followed by readable GET verification.
- Cross-role Stored XSS by low-privileged write followed by admin-reader GET verification.
- CSRF risk where cookie-only requests can perform authenticated state changes.
- CORS origin reflection and unsafe cross-origin credential behavior.
- Security header gaps: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS.

## Safety Defaults

- Skip destructive DELETE requests.
- Skip state-transition endpoints such as approve, reject, ban, restore, close, reopen, cancel.
- Mutate only one injectable parameter at a time.
- Prefer verified api-tree endpoints and verified authentication artifacts.

## Runtime Artifacts

- Code lives under `backend/diagnosis/modules/1-1/`.
- Reports must be written through `DiagnosisModule.save_report()` to `backend/data/report/1-1/latest.yaml`.
- Evidence files, if added later, should be placed under `backend/data/report/1-1/evidence/`.
