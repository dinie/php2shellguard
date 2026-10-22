from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class CheckRequest(BaseModel):
    """Passive header observations forwarded by the browser extension."""

    url: str
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    cookie_names: List[str] = Field(default_factory=list)


class CveInfo(BaseModel):
    id: str
    cvss: float
    title: str
    summary: str


class CheckResponse(BaseModel):
    host: str
    status: str
    php_version: Optional[str] = None
    branch: Optional[str] = None
    patched_version: Optional[str] = None
    evidence_source: Optional[str] = None
    reason: str
    cves: List[CveInfo]
    checked_at: datetime


class HostLatest(BaseModel):
    host: str
    status: str
    php_version: Optional[str] = None
    source: Optional[str] = None
    total_checks: int
    first_seen: datetime
    last_seen: datetime


class StatsResponse(BaseModel):
    total_checks: int
    checks_today: int
    unique_hosts: int
    status_counts: Dict[str, int]
    host_status_counts: Dict[str, int]
    version_counts: List[Dict]
    daily: List[Dict]
    recent: List[Dict]
