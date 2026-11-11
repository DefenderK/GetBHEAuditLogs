# GetBHEAuditLogs

Two equivalent, read-only example clients that export audit logs from the BloodHound API: one in PowerShell and one in Python.

The examples are intended as a reference example for Bloodhound users to demonstrate how to use the API to pull information from the BloodHound Audit Log. The audit endpoint is tagged for both BloodHound Community Edition and BloodHound Enterprise in the upstream OpenAPI specification.
This tool is not made or supported by SpecterOps and should be used for learning purposes.

## What the tools do

- Call the real `GET /api/v2/audit` endpoint.
- Support signed API token ID/key authentication (recommended) and bearer JWTs.
- Accept relative ranges such as the last 12 hours or 7 days.
- Accept absolute ISO-8601/RFC3339 start and end times.
- Use exact server-side actor, action, request, source, and status filters.
- Search case-insensitively across the complete returned record, including nested `fields` values.
- Follow `skip`/`limit` pagination until an empty page confirms exhaustion, even when the server caps page sizes or reports an inaccurate count.
- Write a console table, JSON, JSON Lines, or CSV; JSONL/CSV file exports stream to disk.
- Retry transient network failures and HTTP `429`, `502`, `503`, and `504` responses.

Both versions have matching options and output semantics. They use only built-in PowerShell/.NET features or the Python standard library.

## Requirements

- PowerShell 5.1 or later, or
- Python 3.10 or later
- A BloodHound URL and an identity permitted to read audit logs

No Python packages need to be installed.

## Quick start

Signed API tokens are the recommended choice for integrations.

The entry points are [powershell/Get-BHAuditLogs.ps1](powershell/Get-BHAuditLogs.ps1) and [python/get_bh_audit_logs.py](python/get_bh_audit_logs.py).

### PowerShell

```powershell
$env:BH_URL = 'https://your-bloodhound.example'
$env:BH_TOKEN_ID = 'your-token-id'
$env:BH_TOKEN_KEY = 'your-token-key'

.\powershell\Get-BHAuditLogs.ps1 -Days 7 -OutputFormat table
```

### Python

```powershell
$env:BH_URL = 'https://your-bloodhound.example'
$env:BH_TOKEN_ID = 'your-token-id'
$env:BH_TOKEN_KEY = 'your-token-key'

python .\python\get_bh_audit_logs.py --days 7 --output-format table
```

If credentials are omitted in an interactive terminal, either tool can prompt for them. Add `-NoPrompt` or `--no-prompt` for unattended use.

## Interactive investigations

Open the guided menus with:

```powershell
.\powershell\Get-BHAuditLogs.ps1 -Interactive
python .\python\get_bh_audit_logs.py --interactive
```

You can also supply existing command-line settings, environment variables, or a JSON config to prefill the session. Interactive mode is explicit and cannot be combined with `NoPrompt`/`--no-prompt`; ordinary command-line usage keeps its existing behaviour.

```text
[1] Connection and authentication
[2] Quick investigations
[3] Build a custom query
[4] Output settings
[5] Advanced settings
[6] Review and run
[7] Current results
[R] Return to main menu
[Q] Quit
```

| Menu | Options |
|---|---|
| Connection | Load a JSON config, enter a base URL (including local Docker), select signed token or bearer JWT, or test audit access with at most one record. Credentials are entered without echo and hidden in summaries. |
| Quick investigations | Recent activity, failed login events, a particular actor, an action, a request ID, or text in nested details. Each preset selects the last 24 hours and replaces previous filters. Events matching a preset do not by themselves prove a completed change. |
| Custom query | Combine, edit, or clear actor ID/name/email, action, request ID, source, status, and full-record search. Choose the last 1/12/24 hours, 7/30 days, custom hours/days, or absolute dates. |
| Output | Table, JSON, JSONL, or CSV, with an optional file destination. Interactive console output is a bounded preview; use an export for all matched records. |
| Advanced | Page size, maximum API records inspected before search (0 means all), timeout, retry count/delay, verbose diagnostics, and TLS certificate validation. |
| Review/run | Inspect the effective URL, exclusive UTC boundaries, filters, limits, output, and TLS settings before choosing to run. A PowerShell-compatible command is shown with credentials omitted; supply authentication through the corresponding `BH_*` environment variables. |
| Current results | Show up to 50 numbered event summaries, inspect any matched event's full JSON (including events beyond the preview), export the cached results, return to edit settings, or review and rerun. |

Use `R` or `Q` at any menu prompt. `R` abandons an incomplete settings edit and returns to the main menu; `Q` exits. In a filter value prompt, `-` clears that filter. Changes to settings affect the next investigation; existing cached results remain available until a successful rerun replaces them.

After saving a URL, the connection menu stays open if neither a complete signed token pair nor a bearer JWT is configured. Enter authentication there without reopening the menu, or press `R` to return while keeping the saved URL.

Actor/action/request/source filters are exact server-side comparisons. Search is a client-side substring comparison over the complete record, including nested `fields`; `intent` status is also filtered client-side. Time summaries show UTC boundaries; date-only end values include the entire day.

Each investigation caches matching records as JSONL in a temporary session directory, keeping the console preview bounded. Details and exports read that cache without another API request. JSONL/CSV file exports stream from the cache; JSON/table exports buffer the results. Existing destination files require an explicit `YES` before replacement. Session cache files are removed on normal exit and handled errors; an abruptly terminated process may leave temporary audit data behind.

Initial values follow the usual command line > environment > config order. Loading another config inside the menu replaces connection and advanced/output settings using that config and the current environment, while keeping the selected time range, investigation filters, record limit, and destination. Choosing an authentication method explicitly clears the other method for the current session without changing environment variables or saving credentials to disk. No connection profiles or `.env` files are written.

## Common examples

The following pairs perform the same operation.

### Absolute date range to JSON

A date-only end includes that complete UTC calendar day by sending the following midnight as the exclusive API `before` value.

```powershell
.\powershell\Get-BHAuditLogs.ps1 `
  -Start '2026-08-01' -End '2026-08-18' `
  -OutputFormat json -OutputFile '.\output\audit.json'
```

```powershell
python .\python\get_bh_audit_logs.py `
  --start '2026-08-01' --end '2026-08-18' `
  --output-format json --output-file '.\output\audit.json'
```

### Failed login events from the last 24 hours

```powershell
.\powershell\Get-BHAuditLogs.ps1 `
  -Hours 24 -Action LoginAttempt -Status failure `
  -OutputFormat csv -OutputFile '.\output\failed-logins.csv'
```

```powershell
python .\python\get_bh_audit_logs.py `
  --hours 24 --action LoginAttempt --status failure `
  --output-format csv --output-file '.\output\failed-logins.csv'
```

### Search nested audit fields

`Search` is a case-insensitive client-side substring search over each complete JSON record. It is useful when the value of interest lives inside the action-specific `fields` object.

```powershell
.\powershell\Get-BHAuditLogs.ps1 -Days 30 -Search 'example-service' -OutputFormat jsonl
```

```powershell
python .\python\get_bh_audit_logs.py --days 30 --search 'example-service' --output-format jsonl
```

### Bound a large investigation

`MaxRecords` limits the number of API records inspected, before client-side search is applied. Zero means all records in the requested range.

```powershell
.\powershell\Get-BHAuditLogs.ps1 -Days 90 -PageSize 250 -MaxRecords 5000
```

```powershell
python .\python\get_bh_audit_logs.py --days 90 --page-size 250 --max-records 5000
```

## Equivalent option names

| Purpose | PowerShell | Python |
|---|---|---|
| Guided menus | `-Interactive` | `--interactive` |
| BloodHound URL | `-Url` | `--url` |
| Signed token | `-TokenId`, `-TokenKey` | `--token-id`, `--token-key` |
| Bearer JWT | `-BearerToken` | `--bearer-token` |
| Relative time | `-Days` or `-Hours` | `--days` or `--hours` |
| Absolute time | `-Start`, `-End` | `--start`, `--end` |
| Exact filters | `-ActorId`, `-ActorName`, `-ActorEmail`, `-Action`, `-RequestId`, `-Source`, `-Status` | `--actor-id`, `--actor-name`, `--actor-email`, `--action`, `--request-id`, `--source`, `--status` |
| Full-record search | `-Search` | `--search` |
| Pagination | `-PageSize`, `-MaxRecords` | `--page-size`, `--max-records` |
| Output | `-OutputFormat`, `-OutputFile` | `--output-format`, `--output-file` |
| Disable prompts | `-NoPrompt` | `--no-prompt` |
| Development TLS bypass | `-SkipCertificateCheck` | `--insecure` |
| Diagnostics | PowerShell common `-Verbose` | `--verbose` |

Run `Get-Help .\powershell\Get-BHAuditLogs.ps1 -Full` or `python .\python\get_bh_audit_logs.py --help` for the complete command syntax.

## Authentication

The tools accept values in this priority order:

1. Command-line parameters
2. Environment variables
3. A JSON config file
4. Interactive prompts

If values from different sources populate more than one authentication method, the tool fails closed and asks you to clear the stale values.

### 1. Signed API token ID/key (recommended)

Set `BH_TOKEN_ID` and `BH_TOKEN_KEY`, use the matching command-line options, or place them in a local ignored config file. Every request is signed using BloodHound's chained HMAC-SHA256 scheme.

### 2. Bearer JWT

Set `BH_BEARER_TOKEN` or use the bearer command-line option. JWTs are intended for temporary access and expire.

### Environment variables

| Variable | Meaning |
|---|---|
| `BH_URL` | BloodHound base URL |
| `BH_TOKEN_ID` / `BH_TOKEN_KEY` | Signed API token pair |
| `BH_BEARER_TOKEN` | Short-lived JWT |
| `BH_TIMEOUT` | HTTP timeout in seconds |
| `BH_VERIFY_SSL` | `true` or `false`; defaults to `true` |

### Config files

Copy the example for the language you use:

```powershell
Copy-Item .\powershell\Get-BHAuditLogs.config.example.json .\powershell\Get-BHAuditLogs.config.json
Copy-Item .\python\get_bh_audit_logs.config.example.json .\python\get_bh_audit_logs.config.json
```

Those destination names are loaded automatically and ignored by Git. You can also select another file with `-Config` or `--config`. Do not commit a populated config.

Environment variables are read from the current process; `.env` files are not loaded automatically.

For a local Docker deployment, set `url` in the config (or `BH_URL`) to the published BloodHound address, for example `http://localhost:8080`. Replace `8080` with the actual published port and provide a token from that instance. When running the client inside another container, use an address reachable from that container instead of host loopback.

## API endpoint and filters

The export operation uses one read-only endpoint:

```text
GET /api/v2/audit
```

The tools send these supported query parameters:

| Parameter | Use |
|---|---|
| `after`, `before` | Exclusive RFC3339 time boundaries |
| `skip`, `limit` | Offset pagination |
| `sort_by=-created_at&sort_by=-id` | Newest-first ordering with a unique ID tie-breaker |
| `actor_id`, `actor_name`, `actor_email` | Exact actor filters using `eq:` |
| `action` | Exact action such as `LoginAttempt` |
| `request_id` | Exact request correlation ID |
| `source` | Exact source filter exposed by the API |
| `status` | Exact `success` or `failure` server filter |

Audit records can also have `status: intent`. Because the endpoint documentation only promises `success` and `failure` as status-filter values, the tools retrieve and filter `intent` client-side.

The response shape used for pagination is:

```json
{
  "count": 1,
  "limit": 500,
  "skip": 0,
  "data": {
    "logs": [
      {
        "id": 103,
        "created_at": "2026-08-18T12:00:00Z",
        "actor_id": "11111111-1111-1111-1111-111111111111",
        "actor_name": "Example Admin",
        "actor_email": "admin@example.invalid",
        "action": "CreateAuthToken",
        "fields": { "name": "example-service" },
        "request_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "source_ip_address": "192.0.2.10",
        "status": "success",
        "commit_id": "dddddddd-dddd-dddd-dddd-dddddddddddd"
      }
    ]
  }
}
```

There are no general `resource` or `severity` properties in the audit-log schema. Action-specific resource information may appear in `fields`, where `-Search`/`--search` can find it. Severity is a concept used by other BloodHound data types, not this audit endpoint.

For the full request sequence and signing explanation, see [docs/API_FLOW.md](docs/API_FLOW.md).

## Output formats

- `table`: human-readable console summary.
- `json`: a lossless JSON array of matched audit records.
- `jsonl`: one lossless JSON object per line, useful for streaming into other tools.
- `csv`: stable audit columns plus `fields_json`, a compact JSON representation of the nested `fields` object.

JSONL and CSV exports with `OutputFile`/`--output-file` stream matched records to a temporary file in the destination directory. The destination is replaced only after retrieval and writing succeed. Handled failures remove the temporary file and preserve any existing destination. Other output modes retain matched records in memory.

Progress and the final count summary are written to stderr so redirected JSON, JSONL, and CSV stdout remain machine-readable.

## Repository layout

```text
GetBHEAuditLogs/
|-- powershell/
|   |-- Get-BHAuditLogs.ps1
|   `-- Get-BHAuditLogs.config.example.json
|-- python/
|   |-- get_bh_audit_logs.py
|   |-- get_bh_audit_logs.config.example.json
|   `-- requirements.txt
|-- docs/
|   `-- API_FLOW.md
|-- LICENSE
`-- README.md
```

## Security and operational notes

- The tools only issue read-only audit export requests.
- TLS validation is enabled by default. Use the bypass switches only for controlled development systems.
- Audit logs can contain names, email addresses, IP addresses, queries, and other sensitive action details. Protect exported files accordingly.
- A `before` snapshot boundary is fixed before pagination starts so new audit events do not continually expand the result set.
- Use JSONL/CSV file output for large exports. Table, JSON, and stdout output retain matched records in memory.
- `MaxRecords` intentionally stops after the configured number of inspected records; it does not mean the entire range was exported.
- BloodHound v9.9.0 fixed audit counts that did not respect date ranges. These clients treat `count` as advisory, continue until an empty page, and warn on stderr if the final retrieved total differs. A warning warrants checking the server version and export completeness; it does not identify the cause by itself.
- Malformed records, mismatched response offsets, and consecutive repeated pages fail the export instead of silently discarding data or continuing indefinitely.
- Check the authenticated tenant's API Explorer or `GET /api/v2/spec` when targeting a materially different BloodHound release.

## References

- [BloodHound OpenAPI audit endpoint](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/paths/audit.audit.yaml)
- [Working with the BloodHound API](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api)
- [BloodHound OpenAPI specification](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/openapi.yaml)

## License and disclaimer

Licensed under the MIT License; see [LICENSE](LICENSE).

This independent example is provided as-is and is not an official SpecterOps product. Use it only with systems and audit data you are authorized to access.
