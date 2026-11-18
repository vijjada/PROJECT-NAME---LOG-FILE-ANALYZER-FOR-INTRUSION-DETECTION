from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from typing import Iterable

from appsec_log_analyzer.models import Event

_APACHE_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?$'
)
_SSH_LINE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) '
    r'(?P<time>\d{2}:\d{2}:\d{2}) \S+ sshd(?:\[\d+\])?: (?P<message>.*)$'
)
_SSH_AUTH = re.compile(
    r'(?P<action>Failed password for (?:invalid user )?|Accepted '
    r'(?:password|publickey) for |Invalid user )(?P<user>\S+) '
    r'from (?P<ip>[0-9A-Fa-f:.]+) port \d+'
)


@dataclass(frozen=True, slots=True)
class ParseResult:
    log_format: str
    total_lines: int
    parsed_lines: int
    ignored_lines: int
    events: tuple[Event, ...]


def _valid_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def parse_apache_line(line: str) -> Event | None:
    match = _APACHE_LINE.fullmatch(line.strip())
    if not match:
        return None

    try:
        source_ip = _valid_ip(match["ip"])
        timestamp = datetime.strptime(
            match["time"], "%d/%b/%Y:%H:%M:%S %z"
        )
        parts = match["request"].split()
        if len(parts) != 3:
            return None
        method, path, _protocol = parts
        status = int(match["status"])
    except (ValueError, OverflowError):
        return None

    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        kind="http_request",
        method=method.upper(),
        path=path,
        status_code=status,
    )


def parse_ssh_line(line: str, year: int | None = None) -> Event | None:
    match = _SSH_LINE.fullmatch(line.strip())
    if not match:
        return None
    auth = _SSH_AUTH.search(match["message"])
    if not auth:
        return None

    try:
        source_ip = _valid_ip(auth["ip"])
        timestamp = datetime.strptime(
            f"{year or datetime.now().year} {match['month']} "
            f"{match['day']} {match['time']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None

    action = auth["action"]
    kind = "auth_success" if action.startswith("Accepted") else "auth_failure"
    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        kind=kind,
        username=auth["user"],
    )


def parse_lines(lines: Iterable[str], log_format: str = "auto") -> ParseResult:
    if log_format not in {"auto", "apache", "ssh"}:
        raise ValueError(f"Unsupported log format: {log_format}")

    events: list[Event] = []
    total_lines = parsed_lines = 0
    for line in lines:
        total_lines += 1
        if not line.strip():
            continue
        event: Event | None
        if log_format in {"auto", "apache"}:
            event = parse_apache_line(line)
            if event is not None:
                events.append(event)
                parsed_lines += 1
                continue
        if log_format in {"auto", "ssh"}:
            event = parse_ssh_line(line)
            if event is not None:
                events.append(event)
                parsed_lines += 1

    detected_format = log_format
    if log_format == "auto":
        kinds = {event.kind for event in events}
        detected_format = (
            "mixed"
            if {"http_request", "auth_failure", "auth_success"} & kinds
            and "http_request" in kinds
            and bool(kinds & {"auth_failure", "auth_success"})
            else "ssh"
            if kinds and "http_request" not in kinds
            else "apache"
        )
    return ParseResult(
        log_format=detected_format,
        total_lines=total_lines,
        parsed_lines=parsed_lines,
        ignored_lines=total_lines - parsed_lines,
        events=tuple(events),
    )
