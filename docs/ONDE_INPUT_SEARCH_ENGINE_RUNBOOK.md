# ONDE Input Search Engine Runbook

This guide matches the `feat/input-search-engine` branch with the local ONDE Docker setup.

## Local Targets

| Purpose | URL |
| --- | --- |
| Frontend UI | `http://localhost:5173` |
| User API | `http://localhost:8080` |
| Admin API | `http://localhost:8081` |
| ZAP proxy | `http://127.0.0.1:8090` |

The frontend nginx proxy should route:

| Frontend Prefix | Backend Target |
| --- | --- |
| `/user-api/` | `http://api:8080/` |
| `/admin-api/` | `http://admin:8081/` |

## Input Files

Use the ONDE examples already committed in this branch:

| Input | File |
| --- | --- |
| OpenAPI / Swagger | `examples/swagger.json` |
| API list | `examples/onde-api-list.txt` |
| API list with params | `examples/onde-api-list.params.txt` |
| UI route list | `examples/onde-url-list.txt` |
| UI route list with notes | `examples/onde-url-list.params.txt` |

For the dashboard Build step, upload `examples/swagger.json` as the Swagger/OpenAPI source.
If using text inputs, prefer `examples/onde-api-list.params.txt` because it includes search query parameters.

## Login APIs

Swagger defines two login endpoints:

| Role | Method | Path | Body Fields | Token Field |
| --- | --- | --- | --- | --- |
| User | `POST` | `/api/v1/auth/login` | `email`, `password` | `accessToken` |
| Admin | `POST` | `/api/v1/auth/admin/login` | `email`, `password` | `accessToken` |

Recommended dashboard login endpoint entries:

```text
http://localhost:8080/api/v1/auth/login
http://localhost:8081/api/v1/auth/admin/login
```

If only the user API is being tested, register only:

```text
http://localhost:8080/api/v1/auth/login
```

## Test Account Setup

Add test accounts in the dashboard before Verify or diagnosis modules that require authentication.

Example user account shape:

```json
{
  "role": "user",
  "email": "uki2961@naver.com",
  "password": "Qwer1234!"
}
```

Admin accounts should be entered separately and mapped to the admin login endpoint.

## Search Endpoints To Check

The branch is centered on input/search endpoint discovery. Confirm these endpoints appear after Build:

| Endpoint | Expected Params |
| --- | --- |
| `GET /api/v1/accommodations/search` | `region`, `checkIn`, `checkOut`, `guests`, `page`, `size` |
| `GET /api/v1/flights/search` | `tripType`, `departures`, `arrivals`, `dates`, `passengerCount`, `seatClass` |
| `GET /api/v1/cars/search` | `location`, `pickup`, `returnTime`, `carType` |
| `GET /api/v1/rental_cars/search` | `location`, `pickup`, `returnTime`, `carType` |

Quick local smoke test:

```bash
curl -i "http://localhost:5173/user-api/api/v1/accommodations/search?checkIn=2026-07-02&checkOut=2026-07-03&guests=2&page=0&size=20"
```

Expected result: `HTTP/1.1 200` with `success: true`.

## Suggested Dashboard Flow

1. Start ONDE local Docker services.
2. Start ARGUS backend and frontend for this branch.
3. Build inventory with `examples/swagger.json`.
4. Confirm `api-tree` includes the search endpoints and login endpoints above.
5. Add user/admin test accounts.
6. Save login endpoints if auto-discovery does not resolve both login APIs.
7. Run Verify.
8. Run diagnosis modules that need the verified inventory and login sessions.

## Notes

- `backend/config.yaml` already defaults to `http://localhost:8080` and `http://localhost:8081`.
- `auth.id_field=email`, `auth.pw_field=password`, and cookie token delivery are already configured.
- If the frontend returns `503`, verify `frontend/nginx.conf` points to local Docker services and rebuild the frontend image.
