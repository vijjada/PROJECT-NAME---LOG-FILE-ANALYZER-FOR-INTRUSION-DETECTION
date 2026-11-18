from datetime import datetime, timedelta, timezone

from appsec_log_analyzer.detector import detect
from appsec_log_analyzer.models import Event


def _request(
    seconds: int,
    *,
    ip: str = "203.0.113.8",
    path: str = "/",
    status: int = 200,
) -> Event:
    return Event(
        timestamp=datetime(2026, 11, 18, tzinfo=timezone.utc)
        + timedelta(seconds=seconds),
        source_ip=ip,
        kind="http_request",
        method="GET",
        path=path,
        status_code=status,
    )


def test_detects_authentication_failure_burst() -> None:
    events = tuple(_request(i, path="/login", status=401) for i in range(5))

    alerts = detect(events)

    assert any(alert.category == "authentication_failure_burst" for alert in alerts)


def test_detects_http_rate_spike_only_inside_window() -> None:
    burst = tuple(_request(i) for i in range(10))
    spread = tuple(_request(i * 120) for i in range(10))

    assert any(alert.category == "request_rate_spike" for alert in detect(burst))
    assert not any(alert.category == "request_rate_spike" for alert in detect(spread))


def test_detects_sensitive_path_probing_and_config_path() -> None:
    paths = ("/admin", "/wp-admin", "/phpmyadmin", "/debug", "/server-status")
    alerts = detect(tuple(_request(i, path=path, status=404) for i, path in enumerate(paths)))

    assert any(alert.category == "sensitive_path_probe" for alert in alerts)
    config_alerts = detect((_request(0, path="/.env", status=404),))
    assert any(alert.category == "sensitive_resource_probe" for alert in config_alerts)


def test_detects_traversal_sql_injection_and_xss_signatures() -> None:
    paths = (
        "/download?file=../../etc/passwd",
        "/search?q=union%20select%20password",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    )

    categories = {
        alert.category
        for alert in detect(tuple(_request(i, path=path) for i, path in enumerate(paths)))
    }

    assert {"path_traversal_probe", "sql_injection_probe", "xss_probe"} <= categories


def test_detects_ssh_authentication_burst() -> None:
    start = datetime(2026, 11, 18, tzinfo=timezone.utc)
    events = tuple(
        Event(
            timestamp=start + timedelta(seconds=i),
            source_ip="198.51.100.9",
            kind="auth_failure",
        )
        for i in range(5)
    )

    assert any(
        alert.category == "authentication_failure_burst" for alert in detect(events)
    )


def test_rejects_non_positive_thresholds() -> None:
    try:
        detect((), window_seconds=0)
    except ValueError as error:
        assert "positive" in str(error)
    else:
        raise AssertionError("Expected invalid threshold to be rejected")
