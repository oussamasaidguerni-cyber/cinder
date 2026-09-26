from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    CLOSED = "CLOSED"


class AlertType(str, Enum):
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
    POWERSHELL_ACTIVITY = "POWERSHELL_ACTIVITY"
    WEB_ATTACK = "WEB_ATTACK"
    PHISHING = "PHISHING"
    OUTBOUND_CONNECTION = "OUTBOUND_CONNECTION"
    OTHER = "OTHER"


class Alert(BaseModel):
    id: str
    timestamp: datetime
    source: str
    source_ip: str
    destination: str
    alert_type: AlertType
    severity: Severity
    status: AlertStatus
    raw_log: str
    description: str


class AlertSummary(BaseModel):
    id: str
    timestamp: datetime
    source: str
    source_ip: str
    destination: str
    alert_type: AlertType
    severity: Severity
    status: AlertStatus


class StatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_type: dict[str, int]