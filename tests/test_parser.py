from appsec_log_analyzer.parser import parse_apache_line, parse_lines, parse_ssh_line


def test_parses_apache_common_log_line() -> None:
    event = parse_apache_line(
        '203.0.113.8 - - [18/Nov/2026:12:00:00 +0000] '
        '"POST /login HTTP/1.1" 401 128'
    )

    assert event is not None
    assert event.source_ip == "203.0.113.8"
    assert event.path == "/login"
    assert event.status_code == 401


def test_rejects_invalid_ip_and_malformed_apache_line() -> None:
    assert parse_apache_line(
        '999.0.0.1 - - [18/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1'
    ) is None
    assert parse_apache_line("not a log line") is None


def test_parses_ssh_authentication_failure() -> None:
    event = parse_ssh_line(
        "Nov 18 12:00:00 host sshd[123]: Failed password for invalid user "
        "admin from 198.51.100.9 port 2200 ssh2",
        year=2026,
    )

    assert event is not None
    assert event.kind == "auth_failure"
    assert event.username == "admin"


def test_auto_parser_detects_mixed_log_formats() -> None:
    result = parse_lines(
        [
            '203.0.113.8 - - [18/Nov/2026:12:00:00 +0000] '
            '"GET / HTTP/1.1" 200 1',
            "Nov 18 12:00:00 host sshd[123]: Failed password for root "
            "from 198.51.100.9 port 2200 ssh2",
        ]
    )

    assert result.log_format == "mixed"
    assert result.parsed_lines == 2
    assert result.ignored_lines == 0
