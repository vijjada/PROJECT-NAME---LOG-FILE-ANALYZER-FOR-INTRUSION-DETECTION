from dataclasses import asdict, dataclass
from datetime import datetime
import ipaddress


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: datetime
    source_ip: str
    kind: str
    method: str = ""
    path: str = ""
    status_code: int | None = None
    username: str = ""


@dataclass(frozen=True, slots=True)
class Alert:
    category: str
    severity: str
    source_ip: str
    timestamp: datetime
    count: int
    summary: str
    indicators: tuple[str, ...] = ()

    def to_dict(self, redact_ip: bool = False) -> dict[str, object]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["indicators"] = list(self.indicators)
        if redact_ip:
            address = ipaddress.ip_address(self.source_ip)
            prefix = 24 if address.version == 4 else 64
            data["source_ip"] = str(
                ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            )
        return data
