"""Versioned contracts shared by sandbox, persistence, API and CLI."""

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def now() -> str:
    return datetime.now(UTC).isoformat()


def identity(*parts: str) -> str:
    return sha256("\x00".join(parts).encode()).hexdigest()[:32]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Limits(StrictModel):
    max_files: int = Field(default=20000, ge=1, le=100000)
    max_bytes: int = Field(default=268435456, ge=1024, le=536870912)
    max_file_bytes: int = Field(default=33554432, ge=1024, le=67108864)
    max_depth: int = Field(default=3, ge=1, le=5)
    tool_timeout: int = Field(default=90, ge=1, le=180)
    max_output: int = Field(default=16777216, ge=1024, le=33554432)


class ScanOptions(StrictModel):
    limits: Limits = Field(default_factory=Limits)
    components: bool = True
    vulnerabilities: bool = True


class Evidence(StrictModel):
    id: str
    path: str
    artifact_sha256: str
    line: int | None = None
    offset: int | None = None
    key: str | None = None
    excerpt: str = ""
    observation: dict[str, Any] = Field(default_factory=dict)
    analyzer: str


class Finding(StrictModel):
    id: str
    fingerprint: str
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    path: str
    component_id: str | None = None
    evidence_ids: list[str]
    explanation: str
    remediation: str
    analyzer: str
    analyzer_version: str = "1.0.0"
    rule_version: str = "1.0.0"
    references: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class FileRecord(StrictModel):
    path: str
    sha256: str = ""
    size: int
    mode: int
    uid: int = 0
    gid: int = 0
    kind: str = "file"
    link_target: str | None = None
    preview: str | None = None
    role: str = "other"
    elf: dict[str, Any] | None = None


class Component(StrictModel):
    id: str
    name: str
    version: str
    ecosystem: str
    purl: str = ""
    identity_method: str = "package-metadata"
    evidence_ids: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)


class Stage(StrictModel):
    id: str
    version: str = "1.0.0"
    state: Literal["success", "failure", "skipped", "unsupported", "partial"]
    message: str
    duration_ms: int = 0
    diagnostics: list[str] = Field(default_factory=list)


class AnalysisResult(StrictModel):
    schema_version: str = "1.0"
    artifact_sha256: str
    outcome: Literal["complete", "partial", "failed", "unsupported"]
    format: str
    payloads: list[dict[str, Any]] = Field(default_factory=list)
    files: list[FileRecord] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    stages: list[Stage] = Field(default_factory=list)
    sbom: dict[str, Any] | None = None
    native_inventory: dict[str, Any] | None = None
    manifest: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Static analysis cannot establish service reachability or exploitability.",
            "Package-manager-free firmware may have incomplete component inventory.",
            "Missing canary symbols do not prove absence of stack protection.",
        ]
    )


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)


class ScanCreate(StrictModel):
    artifact_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    label: str = Field(default="", max_length=100)
    options: ScanOptions = Field(default_factory=ScanOptions)


class TriageUpdate(StrictModel):
    status: Literal["open", "acknowledged", "false-positive", "accepted-risk", "resolved"]
    note: str = Field(default="", max_length=4000)
    suppress: bool = False
    reason: str = Field(default="", max_length=1000)
    expires_at: datetime | None = None


class AIQuestion(StrictModel):
    question: str = Field(min_length=1, max_length=2000)
    finding_ids: list[str] = Field(default_factory=list, max_length=20)
    compare_scan_id: str | None = None


class AIClaim(StrictModel):
    kind: Literal["observation", "interpretation", "hypothesis", "limitation"]
    text: str = Field(max_length=3000)
    citations: list[str] = Field(max_length=20)


class AIAnswer(StrictModel):
    claims: list[AIClaim] = Field(max_length=20)
    cannot_answer: bool
