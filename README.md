# Smart Lists AI Service

Smart Lists AI Service is the FastAPI companion service to
[Smart Lists](https://github.com/kzhirikhin/smart-lists). It accepts a bounded,
validated snapshot of a list, asks Anthropic Claude for an insight and returns
the generated text to the web application.

The service is intentionally small: it has one public health endpoint and one
service-to-service AI endpoint. User authentication, list authorization and the
per-user daily quota remain in the Smart Lists web application.

## Security architecture

Security is the central design constraint of this service. List titles, items,
notes and questions are private, untrusted input, while every successful request
can also incur an external AI cost. The implementation therefore combines
authentication, bounded inputs, prompt isolation, restrained logging and a
keyless deployment pipeline.

### Defense in depth

**Service authentication.** `POST /insights` requires a Google-signed ID token
in `Authorization`. Cloud Run checks the caller's IAM permission before the
request reaches the container, and the service independently verifies the same
token again: signature against Google's public keys, `aud` against the
service's own address, and `email` against the one service account allowed to
call. The second check is not redundant — if the IAM policy is ever opened up,
the signature is the only remaining barrier, and a signature cannot be forged.

No shared secret is involved in either direction. End-user authentication and
list-level authorization are performed by the Smart Lists web application
before it calls this API.

**Keyless access to Anthropic.** The service holds no Anthropic API key. It
presents the Google-signed ID token of its own Cloud Run identity and exchanges
it for a ten-minute access token. A leaked configuration grants nothing: every
value the service is configured with is a non-secret identifier.

**Bounded work at the API boundary.** Raw ASGI middleware authenticates the
caller before parsing the body and caps both the declared and actually read
body at 100,000 bytes, including chunked requests. Pydantic then validates
every field before the Anthropic request is created. The contract caps list
size, string lengths, groups, notes and the combined note budget. Requests are
additionally limited to five per minute per source IP.

**Prompt-injection containment.** User-controlled fields are serialized as
JSON inside one explicitly marked untrusted-data block. `<`, `>` and `&` are
escaped so input cannot close that block, and the system prompt instructs the
model not to treat any payload field as an instruction. Metadata that can be
derived from validated data is recomputed by this service instead of being
trusted from the caller.

This reduces the prompt-injection surface; it does not make model output
trusted. Callers must still render the returned text safely and must never
execute it as code or instructions.

**Data-minimizing logs and errors.** Normal request logs contain method, path,
status, latency and source IP. Insight logs contain counts and boolean flags,
not list titles, item names, notes, questions, tokens or secrets. Upstream
failures are returned to the caller as generic errors.

**Production-safe defaults.** Swagger UI and ReDoc are disabled unless `DEBUG`
is explicitly enabled. The machine-readable OpenAPI schema remains available
at `/openapi.json`. Secrets come from environment variables and `.env` is
ignored by Git. Production should always keep `DEBUG=false`.

### Least privilege and keyless delivery

GitHub Actions uses `contents: read` by default. Tests receive deliberately
non-functional placeholder credentials and mock the Anthropic network call, so
CI does not need production secrets.

Deployment authenticates to Google Cloud through GitHub OIDC and Workload
Identity Federation. The workflow receives a short-lived identity for a
dedicated deployer service account; no long-lived Google Cloud service-account
key is stored in GitHub. The deployed revision is pinned to the commit SHA even
though a convenience `latest` image tag is also published.

A separate CI job runs Gitleaks against the complete Git history with redacted
output. This matters because deleting a leaked value in a later commit does not
remove it from earlier commits.

### Trust boundaries and limitations

- Cloud Run ingress, TLS, IAM policy and the service's runtime identity are
  infrastructure concerns and are not defined in this repository.
- The caller's ID token identifies the Smart Lists server, not an individual
  user. It is minted server-side and must never reach a browser or mobile
  client.
- Any code running inside the container can reach the metadata server and
  obtain the service's identity token. The container is the security boundary,
  not the unprivileged user it runs as.
- The in-process rate limiter is per application instance, not a global quota.
  The web application separately enforces the authoritative per-user daily
  limit.
- Source-IP detection trusts the first `X-Forwarded-For` value. Run the service
  only behind a controlled proxy such as Cloud Run; direct exposure would let a
  client influence that value.
- `DEBUG=true` exposes `/docs` and `/redoc`; it is for local development only.

## API

### `GET /health`

Unauthenticated liveness endpoint:

```json
{
  "status": "ok"
}
```

Health checks are intentionally omitted from normal access logs.

### `POST /insights`

Required header:

```http
Authorization: Bearer <Google ID token>
Content-Type: application/json
```

Example request:

```json
{
  "title": "Trip to Tokyo",
  "items": [
    {
      "name": "Book a hotel",
      "is_completed": false,
      "note": "Late check-in is required"
    },
    {
      "name": "Buy a rail pass",
      "is_completed": true,
      "sub_items": [
        { "name": "Compare regional passes", "is_completed": true },
        { "name": "Order online", "is_completed": true }
      ]
    }
  ],
  "groups": ["Travel"],
  "list_note": "Prefer direct routes",
  "notes_meta": {
    "list_note_included": true,
    "included_item_notes": 1,
    "omitted_item_notes": 0
  },
  "user_message": "What should I prioritize?"
}
```

Example response:

```json
{
  "insight": "Book the hotel first because the late check-in requirement narrows your options..."
}
```

The response language follows `user_message` when present, otherwise the
language of the list content.

Common error responses:

| Status | Meaning |
| --- | --- |
| `403` | The supplied service credential is invalid |
| `413` | Declared or streamed request body exceeds 100,000 bytes |
| `422` | Authenticated request data failed validation |
| `429` | Per-IP rate limit exceeded |
| `500` | The service could not produce a valid text result |
| `502` | Anthropic returned an API error |

## Request limits

| Input | Limit |
| --- | --- |
| Title | 1–200 characters |
| Items | Up to 50 top-level entries |
| Item name | 1–200 characters |
| Sub-items | Up to 100 per item and 100 in total |
| Sub-item name | 1–200 characters |
| Groups | Up to 20 |
| Group name | 1–100 characters |
| User message | Up to 500 characters |
| List note | Up to 4,000 characters |
| Note on one item | Up to 4,000 characters |
| Note on one sub-item | Up to 4,000 characters |
| Item notes included | Up to 10 across both levels |
| Combined item-note text | Up to 8,000 characters across both levels |
| Requests | 5 per minute per source IP and process |

Optional text is trimmed, CRLF/CR line endings are normalized to LF and
whitespace-only values become `null`.

An entry may carry sub-items, nested exactly one level deep. `sub_items` is
optional and defaults to an empty list, so a caller released before sub-items
existed keeps working unchanged. A sub-item belongs to its entry: it is never
sent on its own, and an entry that has sub-items counts as completed only when
all of them are.

## How it works

1. The Smart Lists Server Action authenticates the user, checks access to the
   list, loads the data from PostgreSQL and applies its per-user daily quota.
2. It mints a Google ID token for this service and sends the bounded list
   snapshot with it.
3. FastAPI verifies the token before reading the body, enforces the streaming
   byte limit, validates the body and applies the per-IP rate limit.
4. The service recomputes trusted note metadata and serializes all user content
   into an isolated JSON block.
5. The asynchronous Anthropic client calls
   `claude-haiku-4-5-20251001` with a 30-second timeout and a 2,048-token output
   cap, refreshing its federated access token when the cached one expires.
6. The first text block is returned as `{ "insight": "..." }`.

## Tech stack

- Python 3.13;
- FastAPI and Uvicorn;
- Pydantic and pydantic-settings;
- Anthropic Python SDK;
- SlowAPI;
- pytest and FastAPI TestClient;
- Docker, Google Artifact Registry and Google Cloud Run;
- GitHub Actions with Google Cloud Workload Identity Federation.

Exact package versions are pinned in `requirements.txt`.

## Local setup

1. Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

On macOS or Linux, activate it with `source venv/bin/activate`.

2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

3. Create `.env` in the repository root:

```env
EXPECTED_CALLER_SA=caller@your-project.iam.gserviceaccount.com
SERVICE_AUDIENCE=https://insights-api.example.run.app
ANTHROPIC_FEDERATION_RULE_ID=fdrl_replace_me
ANTHROPIC_ORGANIZATION_ID=00000000-0000-0000-0000-000000000000
ANTHROPIC_SERVICE_ACCOUNT_ID=svac_replace_me
ANTHROPIC_WORKSPACE_ID=wrkspc_replace_me
DEBUG=true
```

None of these are secrets, and none of them work outside Google Cloud. Both
directions of authentication need infrastructure the local machine does not
have: incoming tokens are signed by Google, and outgoing ones come from the
metadata server. A local instance therefore answers `403`, which is expected —
verify behaviour with the test suite instead.

4. Start the development server:

```bash
uvicorn app.main:app --reload
```

The API is available at [http://localhost:8000](http://localhost:8000).
With `DEBUG=true`, interactive documentation is available at
[http://localhost:8000/docs](http://localhost:8000/docs).

5. Configure the Smart Lists web repository:

```env
INSIGHTS_SERVICE_URL=http://localhost:8000
```

The variable is server-only and must never use a `NEXT_PUBLIC_` prefix. The web
application mints the ID token itself and needs no shared credential.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `EXPECTED_CALLER_SA` | Yes | Service account email allowed to call this API |
| `SERVICE_AUDIENCE` | Yes | Comma-separated `aud` values — this service's own addresses |
| `ANTHROPIC_FEDERATION_RULE_ID` | Yes | `fdrl_*` federation rule |
| `ANTHROPIC_ORGANIZATION_ID` | Yes | Anthropic organization UUID |
| `ANTHROPIC_SERVICE_ACCOUNT_ID` | Yes | `svac_*` identity assumed at Anthropic |
| `ANTHROPIC_WORKSPACE_ID` | Yes | `wrkspc_*` workspace the token is scoped to |
| `DEBUG` | No | Enables `/docs` and `/redoc`; defaults to `false` |

Every value is a non-secret identifier. The service has no API key and no
shared secret, so there is nothing here to rotate.

## Testing

Run the complete suite:

```bash
pytest tests/ -v
```

The tests use placeholder settings and mock Anthropic. They cover the health
endpoint, service authentication, schema and note-budget limits, optional-text
normalization, prompt construction, the untrusted-data boundary and the
identity-token request that authenticates the service to Anthropic. No
credentials and no network access are required.

## Docker

Build and run a local image:

```bash
docker build -t smart-lists-fastapi-service .
docker run --rm -p 8000:8000 --env-file .env smart-lists-fastapi-service
```

`docker-compose.yml` runs the same local build and binds the port to loopback.
It used to pull a prebuilt image from a GHCR account that no longer exists —
a released owner name can be claimed by anyone, so a stale reference like that
would run a stranger's image on a developer machine. The active production
workflow builds the repository itself, pushes to Google Artifact Registry and
deploys to Cloud Run; the Compose file is not the Cloud Run deployment
definition.

## Deployment

A push to `main` runs tests first. Only a successful test job allows the deploy
job, attached to the `production` GitHub Environment, to:

1. exchange the GitHub OIDC token for a short-lived Google Cloud identity;
2. build the container;
3. publish SHA and `latest` tags to Artifact Registry;
4. deploy the SHA-tagged image to the `insights-api` Cloud Run service in
   `us-central1`.

The Environment accepts deployments only from `main`.

Configure the environment variables listed above in the Cloud Run runtime
environment. The service runs under a dedicated user-managed service account,
which the deploy step names explicitly: the Anthropic federation rule is bound
to that account's `sub` and `email`, so a silent fallback to the project
default account would break authentication.

## Project structure

```text
app/
  core/
    anthropic_auth.py     Identity token and Anthropic federation credentials
    caller_auth.py        Google ID token verification for the caller
    config.py             Environment-backed settings
    limiter.py            Source-IP rate limiter
    logging_config.py     Application logging
    request_boundary.py   Early caller authentication and streaming body cap
  models/
    insights.py           Request, response and validation budgets
  routers/
    insights.py           Rate-limited /insights orchestration
  services/
    ai.py                 Prompt construction and Anthropic call
  main.py                 FastAPI app, middleware and error handlers
bruno/                    Manual API collection
tests/                    API and prompt-boundary tests
.github/workflows/
  ci.yml                  Tests and full-history secret scan
  deploy.yml              Test-gated keyless Cloud Run deployment
```

## Commands

| Command | Purpose |
| --- | --- |
| `uvicorn app.main:app --reload` | Start the local development server |
| `pytest tests/ -v` | Run all tests |
| `docker build -t smart-lists-fastapi-service .` | Build the container |
| `docker run --rm -p 8000:8000 --env-file .env smart-lists-fastapi-service` | Run the local container |

## Documentation for agents

- `AGENTS.md` — mandatory repository rules, in Russian;
- `PROJECT_MEMORY.md` — current architecture, invariants and decisions, in
  Russian;
- `CLAUDE.md` — imports the shared agent instructions.
