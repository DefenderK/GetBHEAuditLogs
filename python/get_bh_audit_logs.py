#!/usr/bin/env python3
"""Read BloodHound audit logs through GET /api/v2/audit.

This example intentionally uses only the Python standard library so the API,
authentication, pagination, and filtering flow is easy to study.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import getpass
import hashlib
import hmac
import io
import json
import math
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


API_PATH = "/api/v2/audit"
RETRYABLE_STATUS_CODES = {429, 502, 503, 504}
CSV_COLUMNS = [
    "id",
    "created_at",
    "actor_id",
    "actor_name",
    "actor_email",
    "action",
    "status",
    "request_id",
    "source_ip_address",
    "commit_id",
    "fields_json",
]


class AuditLogError(RuntimeError):
    """A configuration, authentication, HTTP, or response error."""


@dataclass(frozen=True)
class Credentials:
    bearer_token: str | None = None
    token_id: str | None = None
    token_key: str | None = None

    def validate(self) -> None:
        has_bearer = bool(self.bearer_token)
        has_id = bool(self.token_id)
        has_key = bool(self.token_key)
        if has_bearer and (has_id or has_key):
            raise AuditLogError(
                "Choose one authentication method: bearer token or signed token ID/key."
            )
        if has_id != has_key:
            raise AuditLogError("Signed authentication requires both token ID and token key.")
        if not has_bearer and not (has_id and has_key):
            raise AuditLogError("No complete authentication method was provided.")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def format_rfc3339(value: dt.datetime) -> str:
    value = value.astimezone(dt.timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_datetime(value: str, *, end_of_date: bool = False) -> dt.datetime:
    """Parse RFC3339/ISO-8601; naive values are treated as UTC.

    A date-only end is converted to the next UTC midnight because BloodHound's
    `before` parameter is exclusive.
    """
    text = value.strip()
    try:
        if len(text) == 10 and text[4] == "-" and text[7] == "-":
            parsed_date = dt.date.fromisoformat(text)
            if end_of_date:
                parsed_date += dt.timedelta(days=1)
            return dt.datetime.combine(parsed_date, dt.time.min, dt.timezone.utc)
        normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuditLogError(f"Invalid date/time '{value}'. Use ISO-8601/RFC3339.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def resolve_time_range(
    *,
    days: float | None,
    hours: float | None,
    start: str | None,
    end: str | None,
    default_days: float,
    now: dt.datetime | None = None,
) -> tuple[dt.datetime, dt.datetime]:
    now = (now or utc_now()).astimezone(dt.timezone.utc)
    relative_count = int(days is not None) + int(hours is not None)
    absolute_used = start is not None or end is not None
    if relative_count > 1 or (relative_count and absolute_used):
        raise AuditLogError("Use only one time mode: --days, --hours, or --start with --end.")
    if absolute_used:
        if not start or not end:
            raise AuditLogError("Absolute time ranges require both --start and --end.")
        after = parse_datetime(start)
        before = parse_datetime(end, end_of_date=True)
    else:
        if days is not None:
            if days <= 0:
                raise AuditLogError("--days must be greater than zero.")
            delta = dt.timedelta(days=days)
        elif hours is not None:
            if hours <= 0:
                raise AuditLogError("--hours must be greater than zero.")
            delta = dt.timedelta(hours=hours)
        else:
            if default_days <= 0:
                raise AuditLogError("default_days must be greater than zero.")
            delta = dt.timedelta(days=default_days)
        after, before = now - delta, now
    if after >= before:
        raise AuditLogError("The start of the time range must be before the end.")
    return after, before


def make_signature_headers(
    method: str,
    uri: str,
    token_id: str,
    token_key: str,
    *,
    body: bytes | None = None,
    request_time: dt.datetime | None = None,
) -> dict[str, str]:
    timestamp = format_rfc3339(request_time or utc_now())
    operation = f"{method.upper()}{uri}".encode("utf-8")
    operation_digest = hmac.new(token_key.encode("utf-8"), operation, hashlib.sha256).digest()
    date_digest = hmac.new(operation_digest, timestamp[:13].encode("utf-8"), hashlib.sha256).digest()
    body_digest = hmac.new(date_digest, body or b"", hashlib.sha256).digest()
    return {
        "Authorization": f"bhesignature {token_id}",
        "RequestDate": timestamp,
        "Signature": base64.b64encode(body_digest).decode("ascii"),
    }


def _retry_delay(attempt: int, retry_after: str | None, base_delay: float) -> float:
    if retry_after:
        try:
            return max(0.0, min(float(retry_after), 60.0))
        except ValueError:
            pass
    return min(base_delay * (2**attempt), 60.0)


class BloodHoundClient:
    def __init__(
        self,
        base_url: str,
        credentials: Credentials,
        *,
        timeout: float = 30,
        verify_ssl: bool = True,
        max_retries: int = 3,
        retry_delay: float = 1,
        verbose: bool = False,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise AuditLogError("BloodHound URL must be an absolute http:// or https:// URL.")
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verbose = verbose
        self.ssl_context = None if verify_ssl else ssl._create_unverified_context()
        credentials.validate()

    def request_json(
        self,
        method: str,
        path: str,
        *,
        query: Sequence[tuple[str, str]] | None = None,
    ) -> Any:
        query_string = urllib.parse.urlencode(query or [], doseq=True)
        uri = path if not query_string else f"{path}?{query_string}"
        body_bytes = None

        for attempt in range(self.max_retries + 1):
            headers = {"Accept": "application/json", "User-Agent": "GetBHEAuditLogs-Python/1.0"}
            if self.credentials.bearer_token:
                headers["Authorization"] = f"Bearer {self.credentials.bearer_token}"
            else:
                headers.update(
                    make_signature_headers(
                        method,
                        uri,
                        self.credentials.token_id or "",
                        self.credentials.token_key or "",
                        body=body_bytes,
                    )
                )
            request = urllib.request.Request(
                f"{self.base_url}{uri}", data=body_bytes, headers=headers, method=method.upper()
            )
            if self.verbose:
                print(f"{method.upper()} {uri} (attempt {attempt + 1})", file=sys.stderr)
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout, context=self.ssl_context
                ) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                details = exc.read().decode("utf-8", errors="replace")[:1000]
                if exc.code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    delay = _retry_delay(attempt, exc.headers.get("Retry-After"), self.retry_delay)
                    if self.verbose:
                        print(f"HTTP {exc.code}; retrying in {delay:g}s", file=sys.stderr)
                    time.sleep(delay)
                    continue
                hint = {
                    400: "Check the time range and filter values.",
                    401: "Check the authentication values and token/JWT validity.",
                    403: "The authenticated principal may lack permission to read audit logs.",
                }.get(exc.code, "")
                raise AuditLogError(
                    f"BloodHound returned HTTP {exc.code}. {hint} Response: {details}"
                ) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < self.max_retries:
                    delay = _retry_delay(attempt, None, self.retry_delay)
                    if self.verbose:
                        print(f"Network error; retrying in {delay:g}s", file=sys.stderr)
                    time.sleep(delay)
                    continue
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else str(exc)
                raise AuditLogError(f"Could not reach BloodHound: {reason}") from exc
            except json.JSONDecodeError as exc:
                raise AuditLogError("BloodHound returned a non-JSON response.") from exc
        raise AuditLogError("Request failed after all retry attempts.")

def _validated_filter(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if ":" in value:
        raise AuditLogError(f"{name} cannot contain ':' when used as an exact API filter.")
    return f"eq:{value}"


def build_base_query(
    after: dt.datetime,
    before: dt.datetime,
    filters: Mapping[str, str | None],
) -> list[tuple[str, str]]:
    query = [
        ("after", format_rfc3339(after)),
        ("before", format_rfc3339(before)),
        ("sort_by", "-created_at"),
        ("sort_by", "-id"),
    ]
    for name in ("actor_id", "actor_name", "actor_email", "action", "request_id", "source"):
        filtered = _validated_filter(name, filters.get(name))
        if filtered:
            query.append((name, filtered))
    status = filters.get("status")
    # The API reference documents success/failure for this predicate even though
    # returned records may also contain intent. Intent is filtered client-side.
    if status in {"success", "failure"}:
        query.append(("status", f"eq:{status}"))
    return query


def record_matches(record: Mapping[str, Any], search: str | None, status: str | None) -> bool:
    if status and str(record.get("status", "")).casefold() != status.casefold():
        return False
    if not search:
        return True
    haystack = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str).casefold()
    return search.casefold() in haystack


RequestPage = Callable[[Sequence[tuple[str, str]]], Mapping[str, Any]]


def fetch_audit_logs(
    request_page: RequestPage,
    base_query: Sequence[tuple[str, str]],
    *,
    page_size: int,
    max_records: int,
    search: str | None,
    status: str | None,
    verbose: bool = False,
    record_sink: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    if page_size <= 0:
        raise AuditLogError("page_size must be greater than zero.")
    if max_records < 0:
        raise AuditLogError("max_records cannot be negative.")
    fetched = 0
    matched: list[dict[str, Any]] = []
    expected_total: int | None = None
    previous_page: list[Any] | None = None
    matched_count = 0

    while True:
        remaining = max_records - fetched if max_records else page_size
        request_limit = min(page_size, remaining) if max_records else page_size
        if request_limit <= 0:
            break
        page_query = list(base_query) + [("skip", str(fetched)), ("limit", str(request_limit))]
        response = request_page(page_query)
        try:
            logs = response["data"]["logs"]
        except (KeyError, TypeError) as exc:
            raise AuditLogError("Response did not contain data.logs.") from exc
        if not isinstance(logs, list):
            raise AuditLogError("Response data.logs was not an array.")
        if any(not isinstance(item, Mapping) for item in logs):
            raise AuditLogError("Response data.logs contained a record that was not an object.")
        if len(logs) > request_limit:
            raise AuditLogError("Response contained more records than the requested limit.")
        if "skip" in response and (type(response["skip"]) is not int or response["skip"] != fetched):
            raise AuditLogError("Response skip did not match the requested offset.")
        if "count" in response and (type(response["count"]) is not int or response["count"] < 0):
            raise AuditLogError("Response count must be a non-negative integer.")
        if logs and logs == previous_page:
            raise AuditLogError("BloodHound repeated the previous page; pagination made no progress.")
        previous_page = logs
        if expected_total is None and "count" in response:
            expected_total = response["count"]
        fetched += len(logs)
        for item in logs:
            if record_matches(item, search, status):
                matched_count += 1
                if record_sink is None:
                    matched.append(dict(item))
                else:
                    record_sink(dict(item))
        if verbose:
            total_text = str(expected_total) if expected_total is not None else "unknown"
            print(f"Fetched {fetched}/{total_text}; matched {matched_count}", file=sys.stderr)
        # Counts on older releases may not respect the time window, and servers
        # may cap page sizes. Only an empty page proves exhaustion.
        if not logs:
            if expected_total is not None and fetched != expected_total:
                print(
                    f"Warning: API count was {expected_total}, but pagination returned {fetched} "
                    "records. Older BloodHound releases may report inaccurate date-range counts; "
                    "verify the server version and export completeness.",
                    file=sys.stderr,
                )
            break
        if max_records and fetched >= max_records:
            break
    return matched, fetched


def logs_to_csv(logs: Sequence[Mapping[str, Any]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for record in logs:
        row = {key: record.get(key, "") for key in CSV_COLUMNS if key != "fields_json"}
        row["fields_json"] = json.dumps(
            record.get("fields", {}), ensure_ascii=False, separators=(",", ":"), default=str
        )
        writer.writerow(row)
    return output.getvalue()


def logs_to_table(logs: Sequence[Mapping[str, Any]]) -> str:
    columns = ["created_at", "actor_name", "action", "status", "source_ip_address"]
    if not logs:
        return "No audit logs matched."
    widths = {name: len(name) for name in columns}
    rows: list[dict[str, str]] = []
    maximums = {"created_at": 27, "actor_name": 24, "action": 32, "status": 8, "source_ip_address": 30}
    for record in logs:
        row: dict[str, str] = {}
        for name in columns:
            value = str(record.get(name, "")).replace("\r", " ").replace("\n", " ")
            limit = maximums[name]
            value = value if len(value) <= limit else value[: limit - 1] + "…"
            row[name] = value
            widths[name] = max(widths[name], len(value))
        rows.append(row)
    header = "  ".join(name.ljust(widths[name]) for name in columns)
    divider = "  ".join("-" * widths[name] for name in columns)
    body = ["  ".join(row[name].ljust(widths[name]) for name in columns) for row in rows]
    return "\n".join([header, divider, *body])


def render_output(logs: Sequence[Mapping[str, Any]], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(list(logs), ensure_ascii=False, indent=2, default=str) + "\n"
    if output_format == "jsonl":
        return "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
            for record in logs
        )
    if output_format == "csv":
        return logs_to_csv(logs)
    return logs_to_table(logs) + "\n"


def write_output(content: str, output_file: str | None) -> None:
    if output_file:
        path = Path(output_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    else:
        sys.stdout.write(content)


def stream_export(
    output_file: str,
    output_format: str,
    fetch: Callable[[Callable[[dict[str, Any]], None]], tuple[list[dict[str, Any]], int]],
) -> tuple[int, int]:
    """Publish a streamed JSONL/CSV file only after successful retrieval."""
    path = Path(output_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    matched = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary_path = handle.name
            if output_format == "csv":
                handle.write(logs_to_csv([]))

            def emit(record: dict[str, Any]) -> None:
                nonlocal matched
                if output_format == "csv":
                    handle.write(logs_to_csv([record]).split("\n", 1)[1])
                else:
                    handle.write(render_output([record], "jsonl"))
                matched += 1

            _, fetched = fetch(emit)
        os.replace(temporary_path, path)
        temporary_path = None
        return fetched, matched
    finally:
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        default_path = Path(__file__).with_name("get_bh_audit_logs.config.json")
        if not default_path.exists():
            return {}
        path = str(default_path)
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise AuditLogError(f"Config file not found: {config_path}")
    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditLogError(f"Could not read config file: {exc}") from exc
    if not isinstance(loaded, dict):
        raise AuditLogError("Config file root must be a JSON object.")
    return loaded


def _env_bool(name: str) -> bool | None:
    value = os.environ.get(name)
    if value is None:
        return None
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise AuditLogError(f"{name} must be true or false.")


def _first(*values: Any) -> Any:
    return next((value for value in values if value is not None and value != ""), None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export BloodHound audit logs via GET /api/v2/audit.")
    parser.add_argument("--config", help="JSON config file (default: config beside this script, if present)")
    parser.add_argument("--interactive", action="store_true", help="Open guided investigation menus")
    parser.add_argument("--url", help="BloodHound base URL")
    parser.add_argument("--token-id", help="Signed-request API token ID")
    parser.add_argument("--token-key", help="Signed-request API token key")
    parser.add_argument("--bearer-token", help="Short-lived JWT bearer token")
    parser.add_argument("--no-prompt", action="store_true", help="Fail instead of prompting for missing values")
    parser.add_argument("--days", type=float, help="Relative time range in days")
    parser.add_argument("--hours", type=float, help="Relative time range in hours")
    parser.add_argument("--start", help="Absolute start in ISO-8601/RFC3339")
    parser.add_argument("--end", help="Absolute end in ISO-8601/RFC3339")
    parser.add_argument("--actor-id")
    parser.add_argument("--actor-name")
    parser.add_argument("--actor-email")
    parser.add_argument("--action", help="Exact audit action, for example LoginAttempt")
    parser.add_argument("--request-id")
    parser.add_argument("--source", help="Exact source filter supported by the API")
    parser.add_argument("--status", choices=("intent", "success", "failure"))
    parser.add_argument("--search", help="Case-insensitive substring search over the complete record")
    parser.add_argument("--page-size", type=int)
    parser.add_argument(
        "--max-records", type=int, default=0, help="Maximum API records to inspect; 0 means all"
    )
    parser.add_argument("--output-format", choices=("table", "json", "jsonl", "csv"))
    parser.add_argument("--output-file")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--max-retries", type=int)
    parser.add_argument("--retry-delay", type=float)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation")
    parser.add_argument("--verbose", action="store_true")
    return parser


def _prompt_for_auth(
    token_id: str | None,
    token_key: str | None,
    bearer: str | None,
    no_prompt: bool,
) -> tuple[str | None, str | None, str | None]:
    if any((token_id, token_key, bearer)) or no_prompt:
        return token_id, token_key, bearer
    method = input("Authentication method [signed/bearer] (signed): ").strip().casefold()
    method = method or "signed"
    if method == "signed":
        token_id = input("BloodHound token ID: ").strip()
        token_key = getpass.getpass("BloodHound token key: ")
    elif method == "bearer":
        bearer = getpass.getpass("BloodHound bearer JWT: ")
    else:
        raise AuditLogError("Authentication method must be signed or bearer.")
    return token_id, token_key, bearer


def prepare_options(args: argparse.Namespace, config: Mapping[str, Any], *, use_environment: bool = True) -> dict[str, Any]:
    environment = os.environ if use_environment else {}
    base_url = _first(args.url, environment.get("BH_URL"), config.get("url"), config.get("bh_url"))
    if not base_url and not args.no_prompt:
        base_url = input("BloodHound URL: ").strip()
    if not base_url:
        raise AuditLogError("BloodHound URL is required (--url, BH_URL, config, or prompt).")

    token_id = _first(args.token_id, environment.get("BH_TOKEN_ID"), config.get("token_id"))
    token_key = _first(args.token_key, environment.get("BH_TOKEN_KEY"), config.get("token_key"))
    bearer = _first(
        args.bearer_token, environment.get("BH_BEARER_TOKEN"), config.get("bearer_token")
    )
    token_id, token_key, bearer = _prompt_for_auth(token_id, token_key, bearer, args.no_prompt)

    timeout = float(_first(args.timeout, environment.get("BH_TIMEOUT"), config.get("timeout_seconds"), 30))
    max_retries = int(_first(args.max_retries, config.get("max_retries"), 3))
    retry_delay = float(_first(args.retry_delay, config.get("retry_delay_seconds"), 1))
    verify_env = _env_bool("BH_VERIFY_SSL") if use_environment else None
    verify_ssl = bool(_first(verify_env, config.get("verify_ssl"), True)) and not args.insecure
    if timeout <= 0 or max_retries < 0 or retry_delay < 0:
        raise AuditLogError("Timeout must be positive; retry values cannot be negative.")

    auth_groups = int(bool(bearer)) + int(bool(token_id or token_key))
    if auth_groups > 1:
        raise AuditLogError(
            "Multiple authentication methods were populated. Clear stale CLI, BH_*, or config values."
        )
    credentials = Credentials(
        bearer_token=str(bearer) if bearer else None,
        token_id=str(token_id) if token_id else None,
        token_key=str(token_key) if token_key else None,
    )
    credentials.validate()

    after, before = resolve_time_range(
        days=args.days,
        hours=args.hours,
        start=args.start,
        end=args.end,
        default_days=float(config.get("default_days", config.get("default_time_range_days", 7))),
    )
    filters = {
        "actor_id": args.actor_id,
        "actor_name": args.actor_name,
        "actor_email": args.actor_email,
        "action": args.action,
        "request_id": args.request_id,
        "source": args.source,
        "status": args.status,
    }
    base_query = build_base_query(after, before, filters)
    page_size = int(_first(args.page_size, config.get("page_size"), config.get("batch_size"), 500))
    output_format = str(_first(args.output_format, config.get("output_format"), "table")).casefold()
    if output_format not in {"table", "json", "jsonl", "csv"}:
        raise AuditLogError("output_format must be table, json, jsonl, or csv.")

    client = BloodHoundClient(
        str(base_url),
        credentials,
        timeout=timeout,
        verify_ssl=verify_ssl,
        max_retries=max_retries,
        retry_delay=retry_delay,
        verbose=args.verbose,
    )
    if page_size <= 0 or args.max_records < 0:
        raise AuditLogError("Page size must be positive; maximum records cannot be negative.")
    return dict(client=client, after=after, before=before, query=base_query,
                page_size=page_size, output_format=output_format)


class MenuReturn(Exception):
    pass


class MenuQuit(Exception):
    pass


def menu_input(prompt: str, *, secret: bool = False, show_navigation: bool = True) -> str:
    if not secret and prompt.startswith("[1]"):
        print("\n".join(re.split(r" (?=\[\d+\])", prompt)))
        print("[R] Return to main menu\n[Q] Quit")
        prompt, show_navigation = "Select an option", False
    suffix = " [R: main menu, Q: quit]" if show_navigation else ""
    text = (getpass.getpass if secret else input)(prompt + suffix + ": ").strip()
    if text.casefold() == "r":
        raise MenuReturn()
    if text.casefold() == "q":
        raise MenuQuit()
    return text


def menu_number(prompt: str, *, integer: bool = False, minimum: float = 0) -> float | int:
    text = menu_input(prompt)
    try:
        value = int(text) if integer else float(text)
    except ValueError as exc:
        raise AuditLogError("Enter a valid number.") from exc
    if not math.isfinite(value) or value < minimum:
        raise AuditLogError(f"Enter a finite number of at least {minimum}.")
    return value


def interactive_defaults(args: argparse.Namespace, config: Mapping[str, Any]) -> argparse.Namespace:
    state = argparse.Namespace(**vars(args))
    for name, env, keys, default in (
        ("url", "BH_URL", ("url", "bh_url"), None),
        ("token_id", "BH_TOKEN_ID", ("token_id",), None),
        ("token_key", "BH_TOKEN_KEY", ("token_key",), None),
        ("bearer_token", "BH_BEARER_TOKEN", ("bearer_token",), None),
        ("timeout", "BH_TIMEOUT", ("timeout_seconds",), 30),
        ("max_retries", "", ("max_retries",), 3),
        ("retry_delay", "", ("retry_delay_seconds",), 1),
        ("page_size", "", ("page_size", "batch_size"), 500),
        ("output_format", "", ("output_format",), "table"),
    ):
        setattr(state, name, _first(getattr(args, name), os.environ.get(env),
                                    *(config.get(key) for key in keys), default))
    verify = _first(_env_bool("BH_VERIFY_SSL"), config.get("verify_ssl"), True)
    if not isinstance(verify, bool):
        raise AuditLogError("verify_ssl in JSON config must be true or false.")
    state.insecure = args.insecure or not verify
    state.output_format = str(state.output_format).casefold()
    state.no_prompt = True
    if state.days is None and state.hours is None and not state.start and not state.end:
        state.days = float(_first(config.get("default_days"), config.get("default_time_range_days"), 7))
    return state


def interactive_prepare(state: argparse.Namespace) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(state.url or "")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AuditLogError("Use a base URL without embedded credentials, query, or fragment.")
    return prepare_options(state, {}, use_environment=False)


def equivalent_command(state: argparse.Namespace, prepared: Mapping[str, Any]) -> str:
    # PowerShell quoting, matching the README's Windows examples. Credentials
    # are deliberately omitted; supply them through BH_* environment variables.
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    parts = ["python .\\python\\get_bh_audit_logs.py", "--url", quote(state.url),
             "--start", quote(format_rfc3339(prepared["after"])),
             "--end", quote(format_rfc3339(prepared["before"]))]
    for name in ("actor_id", "actor_name", "actor_email", "action", "request_id", "source",
                 "status", "search", "page_size", "max_records", "timeout", "max_retries",
                 "retry_delay", "output_format", "output_file"):
        value = getattr(state, name)
        if value is not None and value != "":
            parts.extend(["--" + name.replace("_", "-"), quote(value)])
    if state.insecure:
        parts.append("--insecure")
    if state.verbose:
        parts.append("--verbose")
    parts.append("--no-prompt")
    return " ".join(parts)


def interactive_review(state: argparse.Namespace, prepared: Mapping[str, Any]) -> None:
    print(f"\nConnection: {state.url}; authentication: "
          + ("conflicting methods" if state.bearer_token and (state.token_id or state.token_key)
             else "bearer [hidden]" if state.bearer_token else "signed token [hidden]"))
    print(f"UTC boundaries (exclusive): after {format_rfc3339(prepared['after'])}; "
          f"before {format_rfc3339(prepared['before'])}")
    print("Filters:", ", ".join(f"{key}={getattr(state, key)}" for key in (
        "actor_id", "actor_name", "actor_email", "action", "request_id", "source", "status", "search"
    ) if getattr(state, key)) or "none")
    print(f"Output: {state.output_format}; destination: {state.output_file or 'console preview'}")
    print(f"Maximum records inspected BEFORE search: {state.max_records or 'all'}; page size: {state.page_size}")
    print(f"Timeout: {state.timeout}s; retries: {state.max_retries}; delay: {state.retry_delay}s; "
          f"TLS verification: {'OFF' if state.insecure else 'ON'}; verbose: {state.verbose}")
    print("Equivalent PowerShell command (credentials omitted; set BH_* authentication variables):")
    print(equivalent_command(state, prepared))


def export_cached_results(cache: Path, output_format: str, destination: str) -> bool:
    if output_format not in {"table", "json", "jsonl", "csv"}:
        raise AuditLogError("Choose table, json, jsonl, or csv.")
    if not destination:
        raise AuditLogError("Enter an output file path.")
    path = Path(destination).expanduser()
    if path.exists() and menu_input(f"Replace existing file {path}? Type YES").casefold() != "yes":
        print("Export cancelled; existing file preserved.")
        return False

    def fetch(sink):
        count = 0
        with cache.open(encoding="utf-8") as handle:
            for line in handle:
                sink(json.loads(line))
                count += 1
        return [], count

    if output_format in {"jsonl", "csv"}:
        stream_export(str(path), output_format, fetch)
    else:
        records: list[dict[str, Any]] = []
        fetch(records.append)
        write_output(render_output(records, output_format), str(path))
    print(f"Exported cached results to {path}; no new API request.")
    return True


def interactive_results(cache: Path, state: argparse.Namespace, matched: int, fetched: int) -> str:
    print(f"\nRetrieved {fetched}; matched {matched}. "
          + ("Record limit reached; results may be partial." if state.max_records and fetched >= state.max_records else ""))
    with cache.open(encoding="utf-8") as handle:
        preview = [json.loads(line) for _, line in zip(range(50), handle)]
    print(f"Showing first {len(preview)} of {matched} matches:")
    if preview:
        lines = logs_to_table(preview).splitlines()
        print(f"{'No.':<4} {lines[0]}")
        print(f"---- {lines[1]}")
        for number, line in enumerate(lines[2:], 1):
            print(f"{f'[{number}]':<4} {line}")
    else:
        print("No audit logs matched.")
    while True:
        try:
            print()
            choice = menu_input("[1] Full event JSON [2] Export current results [3] Edit query [4] Review and rerun")
            if choice == "1":
                number = menu_number(f"Event number (1-{matched}; includes matches beyond preview)", integer=True, minimum=1)
                if number > matched:
                    raise AuditLogError("Event number is outside the current results.")
                with cache.open(encoding="utf-8") as handle:
                    for index, line in enumerate(handle, 1):
                        if index == number:
                            print(json.dumps(json.loads(line), ensure_ascii=False, indent=2))
                            break
            elif choice == "2":
                fmt = menu_input("Format: table/json/jsonl/csv").casefold()
                destination = menu_input("Output file path")
                export_cached_results(cache, fmt, destination)
            elif choice in {"3", "4"}:
                return choice
            else:
                print("Choose 1-4, R, or Q.")
        except (AuditLogError, OSError, ValueError) as exc:
            print(f"Error: {exc}")


def interactive_mode(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    state = interactive_defaults(args, config)
    banner = r""" ____  _   _    _             _ _ _   _
| __ )| | | |  / \  _   _  __| (_) |_| |    ___   __ _ ___
|  _ \| |_| | / _ \| | | |/ _` | | __| |   / _ \ / _` / __|
| |_) |  _  |/ ___ \ |_| | (_| | | |_| |__| (_) | (_| \__ \
|____/|_| |_/_/   \_\__,_|\__,_|_|\__|_____\___/ \__, |___/
                                                |___/
"""
    print(("\033[36m" + banner + "\033[0m") if sys.stdout.isatty() else banner)
    filters = ("actor_id", "actor_name", "actor_email", "action", "request_id", "source", "status", "search")
    cache: Path | None = None
    totals = (0, 0)
    result_state = state
    try:
        with tempfile.TemporaryDirectory(prefix="bh-audit-session-") as directory:
            while True:
                try:
                    # Summary excludes credential values and tolerates incomplete settings.
                    try:
                        host = urllib.parse.urlsplit(state.url or "").hostname or "not configured"
                    except ValueError:
                        host = "invalid URL (use connection settings to correct)"
                    print(f"\nBloodHound Audit Logs | host: {host} | output: {state.output_format} | "
                          f"maximum inspected: {state.max_records or 'all'}")
                    print("Current filters: " + (", ".join(f"{name}={getattr(state, name)}" for name in filters if getattr(state, name)) or "none"))
                    print("Time: " + (f"{state.start} to {state.end}" if state.start or state.end else f"last {state.hours} hours" if state.hours is not None else f"last {state.days} days"))
                    print("[1] Connection/authentication\n[2] Quick investigations\n[3] Custom query\n"
                          "[4] Output\n[5] Advanced\n[6] Review/run\n[7] Current results\n"
                          "[R] Return to main menu\n[Q] Quit")
                    choice = menu_input("Select an option", show_navigation=False)
                    draft = argparse.Namespace(**vars(state))
                    if choice == "1":
                        awaiting_auth = False
                        while True:
                            draft = argparse.Namespace(**vars(state))
                            action = menu_input("[1] Load JSON config [2] Set URL [3] Signed token [4] Bearer JWT [5] Test audit access")
                            if action == "1":
                                path = menu_input("Config path")
                                if not path:
                                    raise AuditLogError("Enter a config path.")
                                loaded = load_config(path)
                                # An explicit load replaces connection/settings, keeping investigation filters.
                                clean = build_parser().parse_args([])
                                draft = interactive_defaults(clean, loaded)
                                for name in (*filters, "days", "hours", "start", "end", "max_records", "output_file"):
                                    setattr(draft, name, getattr(state, name))
                                print("Config loaded (environment values take precedence); credentials hidden.")
                            elif action == "2":
                                draft.url = menu_input("Base URL, e.g. http://localhost:8080")
                            elif action == "3":
                                draft.token_id = menu_input("Token ID", secret=True)
                                draft.token_key = menu_input("Token key", secret=True)
                                draft.bearer_token = None
                            elif action == "4":
                                draft.bearer_token = menu_input("Bearer JWT", secret=True)
                                draft.token_id = draft.token_key = None
                            elif action == "5":
                                prepared = interactive_prepare(state)
                                fetch_audit_logs(lambda query: prepared["client"].request_json("GET", API_PATH, query=query),
                                                 build_base_query(prepared["after"], prepared["before"], {}),
                                                 page_size=1, max_records=1, search=None, status=None)
                                print("Audit access succeeded (an empty result is valid).")
                            else:
                                raise AuditLogError("Choose 1-5.")
                            state = draft
                            awaiting_auth = awaiting_auth or action == "2"
                            signed = bool(state.token_id and state.token_key and not state.bearer_token)
                            bearer = bool(state.bearer_token and not (state.token_id or state.token_key))
                            if not awaiting_auth or signed or bearer:
                                break
                            print("URL saved. Configure a complete signed token or bearer JWT to finish connection setup, or use R to return.")
                    elif choice == "2":
                        action = menu_input("[1] Recent activity [2] Failed logins [3] Actor [4] Action [5] Request ID [6] Search nested details")
                        if action not in {"1", "2", "3", "4", "5", "6"}:
                            raise AuditLogError("Choose 1-6.")
                        for name in filters:
                            setattr(draft, name, None)
                        draft.days = draft.start = draft.end = None
                        draft.hours = 24
                        if action == "2":
                            draft.action, draft.status = "LoginAttempt", "failure"
                        elif action == "3":
                            field = menu_input("Actor field: id/name/email").casefold()
                            if field not in {"id", "name", "email"}:
                                raise AuditLogError("Choose id, name, or email.")
                            setattr(draft, "actor_" + field, menu_input("Exact actor value"))
                        elif action in {"4", "5", "6"}:
                            name = {"4": "action", "5": "request_id", "6": "search"}[action]
                            setattr(draft, name, menu_input(f"{name} value"))
                        print("Preset selects the last 24 hours and replaces previous filters. Matching events do not prove a completed change.")
                    elif choice == "3":
                        print("Actor/action/request/source filters are exact server filters. Search is a client-side substring across all fields; intent status is also client-side.")
                        action = menu_input("[1] Time range [2] Edit filter [3] Clear all filters")
                        if action == "1":
                            mode = menu_input("[1] Last hour [2] 12 hours [3] 24 hours [4] 7 days [5] 30 days [6] Custom hours [7] Custom days [8] Absolute UTC dates")
                            draft.days = draft.hours = draft.start = draft.end = None
                            if mode in {"1", "2", "3", "4", "5"}:
                                draft.hours = {"1": 1, "2": 12, "3": 24, "4": 168, "5": 720}[mode]
                            elif mode in {"6", "7"}:
                                setattr(draft, "hours" if mode == "6" else "days", menu_number("Positive duration", minimum=0.000001))
                            elif mode == "8":
                                draft.start = menu_input("UTC start date/time")
                                draft.end = menu_input("UTC end date/time (date-only includes entire day)")
                                resolve_time_range(days=None, hours=None, start=draft.start, end=draft.end, default_days=7)
                            else:
                                raise AuditLogError("Choose 1-8.")
                        elif action == "2":
                            field = menu_input("Filter: " + "/".join(filters)).casefold().replace("-", "_")
                            if field not in filters:
                                raise AuditLogError("Unknown filter.")
                            value = menu_input(f"{field}: enter value, or '-' to clear")
                            value = None if value == "-" else value
                            if field == "status" and value not in {None, "intent", "success", "failure"}:
                                raise AuditLogError("Status must be intent, success, or failure.")
                            if field not in {"search", "status"}:
                                _validated_filter(field, value)
                            setattr(draft, field, value)
                        elif action == "3":
                            for name in filters:
                                setattr(draft, name, None)
                        else:
                            raise AuditLogError("Choose 1-3.")
                    elif choice == "4":
                        draft.output_format = menu_input("Output format: table/json/jsonl/csv").casefold()
                        if draft.output_format not in {"table", "json", "jsonl", "csv"}:
                            raise AuditLogError("Unknown output format.")
                        draft.output_file = menu_input("Destination path, or '-' for console preview")
                        if draft.output_file == "-":
                            draft.output_file = None
                        print("JSONL/CSV files stream to disk; JSON/table exports buffer records. Console preview shows at most 50 numbered events.")
                    elif choice == "5":
                        action = menu_input("[1] Page size [2] Maximum records inspected [3] Timeout [4] Retry count [5] Retry delay [6] Verbose [7] TLS verification")
                        options = {"1": ("page_size", True, 1), "2": ("max_records", True, 0),
                                   "3": ("timeout", True, 1), "4": ("max_retries", True, 0), "5": ("retry_delay", False, 0)}
                        if action in options:
                            name, integer, minimum = options[action]
                            setattr(draft, name, menu_number(name + (" (0 means all, before search)" if name == "max_records" else ""), integer=integer, minimum=minimum))
                        elif action in {"6", "7"}:
                            value = menu_input("Enable verbose? yes/no" if action == "6" else "Validate TLS certificates? yes/no").casefold()
                            if value not in {"yes", "no"}:
                                raise AuditLogError("Choose yes or no.")
                            setattr(draft, "verbose" if action == "6" else "insecure", value == ("yes" if action == "6" else "no"))
                        else:
                            raise AuditLogError("Choose 1-7.")
                    elif choice in {"6", "7"}:
                        rerun = choice == "6"
                        if not rerun and cache is None:
                            raise AuditLogError("Run an investigation first.")
                        while True:
                            if rerun:
                                prepared = interactive_prepare(state)
                                interactive_review(state, prepared)
                                if menu_input("Run this query? yes/no").casefold() != "yes":
                                    break
                                target = Path(directory) / (str(time.time_ns()) + ".jsonl")

                                def fetch(sink):
                                    return fetch_audit_logs(
                                        lambda query: prepared["client"].request_json("GET", API_PATH, query=query),
                                        prepared["query"], page_size=int(state.page_size), max_records=state.max_records,
                                        search=state.search, status=state.status, verbose=state.verbose, record_sink=sink,
                                    )

                                fetched, matched = stream_export(str(target), "jsonl", fetch)
                                if cache is not None:
                                    cache.unlink(missing_ok=True)
                                cache, totals = target, (matched, fetched)
                                result_state = argparse.Namespace(**vars(state))
                                if state.output_file:
                                    export_cached_results(cache, state.output_format, state.output_file)
                            assert cache is not None
                            rerun = interactive_results(cache, result_state, *totals) == "4"
                            if not rerun:
                                break
                    else:
                        raise AuditLogError("Choose 1-7, R, or Q.")
                    state = draft
                except MenuReturn:
                    continue
                except (AuditLogError, OSError, ValueError, OverflowError) as exc:
                    print(f"Error: {exc}")
    except (MenuQuit, EOFError):
        print("Interactive session ended.")
        return 0


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    if args.interactive:
        if args.no_prompt:
            raise AuditLogError("--interactive cannot be combined with --no-prompt.")
        return interactive_mode(args, config)
    prepared = prepare_options(args, config)
    client = prepared["client"]
    base_query = prepared["query"]
    page_size = prepared["page_size"]
    output_format = prepared["output_format"]
    def fetch(record_sink=None):
        return fetch_audit_logs(
            lambda query: client.request_json("GET", API_PATH, query=query),
            base_query,
            page_size=page_size,
            max_records=args.max_records,
            search=args.search,
            status=args.status,
            verbose=args.verbose,
            record_sink=record_sink,
        )

    if args.output_file and output_format in {"jsonl", "csv"}:
        fetched, matched_count = stream_export(args.output_file, output_format, fetch)
    else:
        logs, fetched = fetch()
        matched_count = len(logs)
        content = render_output(logs, output_format)
        write_output(content, args.output_file)
    destination = args.output_file or "stdout"
    print(
        f"Retrieved {fetched} audit record(s); {matched_count} matched; output: {destination}",
        file=sys.stderr,
    )
    return 0


def main() -> int:
    try:
        return run()
    except (AuditLogError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
