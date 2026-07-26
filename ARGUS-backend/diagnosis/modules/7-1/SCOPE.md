# 7-1 Client Request Method

HTTP **method policy** only — not directory listing (7-2) or response header disclosure (7-3).

## httpx (always)

- **TRACE**: 2xx + body echoes request (path or `HTTP/1.`) → fail (high)
- **OPTIONS**: parse `Allow:` for TRACE/TRACK/CONNECT (medium/high); PUT/DELETE when `strict_risky`

## ZAP (optional)

- Active scanner **90028** (Insecure HTTP Method) only
- Workspace reset before/after; priority seed from httpx hit URLs
- Alerts mapped to 7-1 findings (`90028-3` TRACE, etc.)

## Probe targets

Same as 7-3: `base_only` / `sample` / `full` api-tree modes.
