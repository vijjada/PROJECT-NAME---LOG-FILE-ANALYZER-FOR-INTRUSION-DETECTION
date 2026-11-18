from collections import Counter, defaultdict, deque
from datetime import timedelta
import re
from urllib.parse import unquote, urlsplit

from appsec_log_analyzer.models import Alert, Event

_SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/admin",
    "/actuator",
    "/phpmyadmin",
    "/wp-admin",
    "/server-status",
    "/debug",
    "/config",
)
_DIRECT_EXPOSURE_PATHS = ("/.env", "/.git", "/actuator/env", "/config")
_INJECTION_PATTERNS = {
    "path_traversal_probe": re.compile(r"(?:^|/)\.\.(?:/|$)", re.IGNORECASE),
    "sql_injection_probe": re.compile(
        r"\bunion\s+select\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
        r"|;\s*--|\bdrop\s+table\b",
        re.IGNORECASE,
    ),
    "xss_probe": re.compile(
        r"<\s*script\b|javascript\s*:|onerror\s*=", re.IGNORECASE
    ),
}


def _decoded_request(event: Event) -> str:
    value = f"{urlsplit(event.path).path}?{urlsplit(event.path).query}"
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value.replace("\\", "/")


def _alert(
    category: str,
    severity: str,
    source_ip: str,
    timestamp,
    count: int,
    summary: str,
    indicators: tuple[str, ...] = (),
) -> Alert:
    return Alert(category, severity, source_ip, timestamp, count, summary, indicators)


def _peak_in_window(
    events: list[Event],
    window_seconds: int,
    predicate,
) -> tuple[int, Event | None, list[Event]]:
    window: deque[Event] = deque()
    peak = 0
    anchor = None
    peak_events: list[Event] = []
    duration = timedelta(seconds=window_seconds)

    for event in events:
        if not predicate(event):
            continue
        window.append(event)
        while window and event.timestamp - window[0].timestamp > duration:
            window.popleft()
        if len(window) > peak:
            peak = len(window)
            anchor = event
            peak_events = list(window)
    return peak, anchor, peak_events


def detect(
    events: tuple[Event, ...] | list[Event],
    *,
    window_seconds: int = 60,
    request_threshold: int = 10,
    auth_failure_threshold: int = 5,
    probe_threshold: int = 5,
) -> list[Alert]:
    if min(window_seconds, request_threshold, auth_failure_threshold, probe_threshold) < 1:
        raise ValueError("Detection thresholds and window must be positive.")

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    for source_ip, source_events in by_ip.items():
        source_events.sort(key=lambda event: event.timestamp)

        auth_count, anchor, _ = _peak_in_window(
            source_events,
            window_seconds,
            lambda event: event.kind == "auth_failure"
            or event.kind == "http_request" and event.status_code in {401, 403},
        )
        if auth_count >= auth_failure_threshold and anchor:
            alerts.append(
                _alert(
                    "authentication_failure_burst",
                    "high",
                    source_ip,
                    anchor.timestamp,
                    auth_count,
                    f"{auth_count} authentication failures within {window_seconds}s.",
                )
            )

        request_count, anchor, _ = _peak_in_window(
            source_events,
            window_seconds,
            lambda event: event.kind == "http_request",
        )
        if request_count >= request_threshold and anchor:
            alerts.append(
                _alert(
                    "request_rate_spike",
                    "medium",
                    source_ip,
                    anchor.timestamp,
                    request_count,
                    f"{request_count} HTTP requests within {window_seconds}s; review for abuse.",
                )
            )

        error_count, anchor, _ = _peak_in_window(
            source_events,
            window_seconds,
            lambda event: event.kind == "http_request"
            and event.status_code is not None
            and event.status_code >= 500,
        )
        if error_count >= 5 and anchor:
            alerts.append(
                _alert(
                    "server_error_burst",
                    "medium",
                    source_ip,
                    anchor.timestamp,
                    error_count,
                    f"{error_count} HTTP 5xx responses within {window_seconds}s.",
                )
            )

        recent_paths: deque[tuple[Event, str]] = deque()
        path_counts: Counter[str] = Counter()
        peak_paths: set[str] = set()
        path_anchor = None
        for event in source_events:
            if event.kind != "http_request":
                continue
            path = urlsplit(event.path).path.lower()
            if any(path == prefix or path.startswith(prefix + "/") for prefix in _SENSITIVE_PATHS):
                recent_paths.append((event, path))
                path_counts[path] += 1
            while (
                recent_paths
                and event.timestamp - recent_paths[0][0].timestamp
                > timedelta(seconds=window_seconds)
            ):
                _, old_path = recent_paths.popleft()
                path_counts[old_path] -= 1
                if path_counts[old_path] == 0:
                    del path_counts[old_path]
            if len(path_counts) > len(peak_paths):
                peak_paths = set(path_counts)
                path_anchor = event
        if len(peak_paths) >= probe_threshold and path_anchor:
            alerts.append(
                _alert(
                    "sensitive_path_probe",
                    "high",
                    source_ip,
                    path_anchor.timestamp,
                    len(peak_paths),
                    f"{len(peak_paths)} distinct sensitive paths requested within {window_seconds}s.",
                    tuple(sorted(peak_paths)),
                )
            )

        seen_direct: set[tuple[str, str]] = set()
        for event in source_events:
            if event.kind != "http_request":
                continue
            parsed_path = urlsplit(event.path).path.lower()
            for path_prefix in _DIRECT_EXPOSURE_PATHS:
                if parsed_path == path_prefix or parsed_path.startswith(path_prefix + "/"):
                    key = ("sensitive_resource_probe", parsed_path)
                    if key not in seen_direct:
                        alerts.append(
                            _alert(
                                "sensitive_resource_probe",
                                "high",
                                source_ip,
                                event.timestamp,
                                1,
                                "Request targeted a commonly exposed configuration or repository path.",
                                (parsed_path,),
                            )
                        )
                        seen_direct.add(key)
                    break

            decoded = _decoded_request(event)
            for category, pattern in _INJECTION_PATTERNS.items():
                if pattern.search(decoded):
                    key = (category, event.path)
                    if key not in seen_direct:
                        alerts.append(
                            _alert(
                                category,
                                "high",
                                source_ip,
                                event.timestamp,
                                1,
                                "Request matched a suspicious input pattern; validate in application context.",
                            )
                        )
                        seen_direct.add(key)
                    break

    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.category))
