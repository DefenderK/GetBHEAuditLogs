# BloodHound audit API flow

This guide explains the request sequence implemented by both example clients. It is deliberately language-neutral so the same flow can be reused in another integration.

## Endpoints

| Method and path | When used | State impact |
|---|---|---|
| `GET /api/v2/audit` | Always; retrieves audit records | Read-only |
| `GET /api/v2/spec` | Not called by the tools; useful to inspect the tenant's installed API contract | Read-only |

The tools use a signed API token or an existing bearer JWT. They do not submit user credentials or create a login session.

## 1. Resolve configuration

Each client resolves settings in the same order:

1. Command line
2. Environment variables
3. JSON config
4. Interactive prompt

The client validates that exactly one complete authentication method is selected. This prevents an old bearer token in the environment from silently overriding a signed token in a config file.

With `-Interactive`/`--interactive`, settings are resolved into a session draft. Explicit menu changes then take precedence for that session, so switching authentication methods clears the other method without editing the environment or config. Returning to the main menu during an incomplete edit discards that draft. The same validation, query building, signing, and pagination functions serve interactive and command-line requests.

The connection test calls `GET /api/v2/audit` in the selected time window with no investigation filters and a maximum of one inspected record. A successful empty response still proves audit endpoint access. A full investigation requires review and a run selection. It writes matched events to a temporary JSONL cache; the results viewer reads at most 50 summary records into memory and can seek any full event by its displayed number. Exports read the cache without a new HTTP request, and existing output files require an explicit overwrite selection. Session caches are deleted on exit; failed reruns preserve the previous successful cache.

## 2. Authenticate

### Signed requests

For a signed request, the exact method and URI—including the encoded query string—must be used in the signature.

For example:

```text
GET/api/v2/audit?after=2026-08-18T00%3A00%3A00Z&before=2026-08-19T00%3A00%3A00Z&sort_by=-created_at&sort_by=-id&skip=0&limit=500
```

The clients implement the chained HMAC-SHA256 process documented by BloodHound:

```text
operation_digest = HMAC-SHA256(token_key, METHOD + request_uri)
date_digest      = HMAC-SHA256(operation_digest, request_date[0:13])
signature_digest = HMAC-SHA256(date_digest, exact_body_bytes_or_empty)
Signature        = Base64(signature_digest)
```

The request carries:

```http
Authorization: bhesignature TOKEN_ID
RequestDate: 2026-08-18T12:34:56.000000Z
Signature: BASE64_HMAC
```

Every retry is re-signed so the timestamp remains current.

### Bearer JWT

An existing JWT is sent as:

```http
Authorization: Bearer JWT_VALUE
```

JWTs are short-lived and are best suited to interactive or one-time calls.

## 3. Freeze the time window

Before pagination, the client computes a fixed `after` and `before` value in UTC.

- `days` or `hours`: subtract the requested duration from one captured current time.
- `start` and `end`: parse ISO-8601/RFC3339 values; values without an offset are treated as UTC.
- Date-only start: that day's `00:00:00Z`.
- Date-only end: the next day's `00:00:00Z`, used as an exclusive boundary.
- No time option: the configured `default_days`, which defaults to seven.

Freezing `before` keeps new events created during a long export outside the current pagination set.

## 4. Build supported API filters

The clients call:

```text
GET /api/v2/audit
```

with these query parameters:

```text
after=RFC3339_START
before=RFC3339_END
sort_by=-created_at
sort_by=-id
actor_id=eq:VALUE
actor_name=eq:VALUE
actor_email=eq:VALUE
action=eq:VALUE
request_id=eq:VALUE
source=eq:VALUE
status=eq:success|failure
skip=OFFSET
limit=PAGE_SIZE
```

Only populated filters are sent. Exact filter values containing `:` are rejected locally because they do not satisfy the endpoint's documented predicate grammar.

`intent` is a real returned audit status, but the endpoint description only documents `success` and `failure` as accepted status predicates. The examples therefore apply `intent` after retrieval.

## 5. Paginate

The API response is an envelope rather than a bare array:

```json
{
  "count": 3,
  "limit": 2,
  "skip": 0,
  "data": {
    "logs": []
  }
}
```

The client starts with `skip=0` and advances by the number of records actually returned, not blindly by the requested page size. Pagination ends when an empty page confirms exhaustion or the optional local maximum is reached. This normally adds one final empty-page request.

A short page does not end retrieval: servers may cap the page size. The response `count` is advisory because older BloodHound releases could report counts outside the requested date range; v9.9.0 fixed that behaviour. A final mismatch produces a stderr warning, without changing structured stdout. The client does not infer completeness from the count alone.

Ordering uses descending `created_at` followed by descending unique `id`, so equal timestamps have a stable tie-breaker. The fixed time boundary does not provide a database snapshot: deletions or other changes during offset pagination can still affect results.

Every page must contain an array at `data.logs`, and each entry must be an object. If present, `count` must be a non-negative integer and `skip` must match the requested offset. Oversized responses and consecutive repeated pages fail clearly. These checks do not require a fixed set of record properties, preserving support for new audit fields.

## 6. Apply client-side search

Exact filters run on the server. The optional free-text search serializes each returned record to JSON and performs a case-insensitive substring comparison. This reaches both stable top-level properties and action-specific nested `fields` content without inventing unsupported query parameters.

Search occurs after the API record limit. For example, `max-records=1000` means "inspect at most 1,000 API records," not "keep fetching until 1,000 text matches exist."

## 7. Format output

- JSON and JSON Lines preserve the complete returned records.
- CSV selects stable schema columns and serializes `fields` into `fields_json`.
- The table selects a small human-readable subset and truncates wide values for display only.

Diagnostics and count summaries use stderr. Structured stdout can therefore be redirected or piped without log messages corrupting it.

JSONL/CSV exports to a file write one matched record at a time to a temporary file beside the destination. The clients close the file and replace the destination only after retrieval succeeds. Handled errors clean up the temporary file and preserve existing output. Empty CSV exports include the header; empty JSONL exports are empty files. Other output modes remain buffered.

## Errors and retries

The clients retry rate limits, temporary gateway/service errors, and network failures with bounded exponential backoff. `Retry-After` seconds are honored when supplied. Authentication and permission failures are not retried.

Python explicitly retries connection and response-read timeouts as well as URL errors, and reports a clear error when retries are exhausted. Signed requests are re-signed for each attempt.

Expected meanings:

- `400`: invalid time/filter syntax.
- `401`: invalid/expired authentication or a bad signature.
- `403`: the identity lacks audit-log permission.
- `429`: rate limit; retry.

## API contract sources

- [Audit endpoint source](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/audit.audit.yaml)
- [Top-level BloodHound OpenAPI source](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/openapi.yaml)
- [Official authentication guide](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api)

For a specific deployment, the API Explorer and authenticated `GET /api/v2/spec` response are the authoritative installed-version references.
