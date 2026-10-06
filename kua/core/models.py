"""Core domain models for Kubernetes readiness analysis, findings, and reports."""

from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    """Finding severity levels with deterministic rank ordering."""

    BLOCKER = "BLOCKER"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparison (higher means more severe)."""
        ranks = {
            Severity.BLOCKER: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks[self]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


class Phase(StrEnum):
    """Upgrade workflow execution phases."""

    PRE_CP = "pre-cp"
    CP = "cp"
    ADDONS = "addons"
    NODES = "nodes"
    POST = "post"


class FindingSource(StrEnum):
    """Origin of a readiness finding."""

    RULE = "rule"
    INSIGHT = "insight"
    LLM = "llm"


class ResourceRef(BaseModel):
    """Reference to a specific Kubernetes resource."""

    model_config = ConfigDict(frozen=True)

    kind: str
    name: str
    namespace: str | None = None

    def __str__(self) -> str:
        """Return canonical resource representation (kind/namespace/name or kind/name)."""
        if self.namespace:
            return f"{self.kind}/{self.namespace}/{self.name}"
        return f"{self.kind}/{self.name}"


class Finding(BaseModel):
    """Deterministic or LLM-annotated upgrade readiness finding."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        pattern=r"^[A-Z0-9]+(-[A-Z0-9]+)+$",
        description="Stable finding identifier (e.g. 'DRAIN-PDB-ZERO-DISRUPTION').",
    )
    severity: Severity = Field(description="Finding severity level.")
    title: str = Field(
        max_length=120,
        description="Concise description of the finding (<=120 characters).",
    )
    detail: str = Field(description="Detailed explanation and technical context.")
    resources: list[ResourceRef] = Field(
        default_factory=list,
        description="Affected Kubernetes resources.",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured supporting facts and raw collector signals.",
    )
    remediation: str = Field(description="Clear action required to resolve or mitigate.")
    source: FindingSource = Field(description="Origin source of this finding.")
    phase: Phase = Field(description="Upgrade phase this finding pertains to.")
    docs_url: str | None = Field(
        default=None,
        description="Optional documentation or remediation URL.",
    )


class ClusterRef(BaseModel):
    """Identifier and location reference for a Kubernetes cluster."""

    model_config = ConfigDict(frozen=True)

    provider: str = Field(
        default="eks",
        description="Cloud or Kubernetes provider type.",
    )
    name: str = Field(description="Cluster name.")
    region: str = Field(description="Cloud region or location.")
    account_id: str | None = Field(
        default=None,
        description="Account or project ID owning the cluster.",
    )


class NodeGroupInfo(BaseModel):
    """Information regarding a node group, node pool, or compute pool in the cluster."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Node group or pool name.")
    kind: Literal["managed", "self_managed", "karpenter", "fargate"] = Field(
        description="Compute group architecture kind."
    )
    kubelet_versions: dict[str, int] = Field(
        default_factory=dict,
        description="Distribution of kubelet versions to node counts.",
    )
    os: Literal["linux", "windows", "bottlerocket", "unknown"] = Field(
        default="linux",
        description="Operating system family of nodes.",
    )
    ami_type: str | None = Field(
        default=None,
        description="AMI type (e.g. 'AL2023_x86_64_STANDARD', 'CUSTOM').",
    )
    custom_ami: bool = Field(
        default=False,
        description="Whether this node group uses a custom AMI.",
    )
    launch_template: str | None = Field(
        default=None,
        description="Launch template name or ID, if applicable.",
    )
    desired: int | None = Field(
        default=None,
        description="Desired node count capacity.",
    )
    min: int | None = Field(
        default=None,
        description="Minimum node count capacity.",
    )
    max: int | None = Field(
        default=None,
        description="Maximum node count capacity.",
    )
    subnets: list[str] = Field(
        default_factory=list,
        description="Subnet IDs configured for this compute pool.",
    )
    instance_types: list[str] = Field(
        default_factory=list,
        description="EC2 or VM instance types utilized by this node group.",
    )
    availability_zones: list[str] = Field(
        default_factory=list,
        description="Availability zones where nodes are provisioned.",
    )

    @model_validator(mode="before")
    @classmethod
    def _remap_min_max(cls, data: Any) -> Any:
        """Allow min_size and max_size aliases during initialization."""
        if isinstance(data, dict):
            mapped = dict(data)
            if "min_size" in mapped and "min" not in mapped:
                mapped["min"] = mapped.pop("min_size")
            if "max_size" in mapped and "max" not in mapped:
                mapped["max"] = mapped.pop("max_size")
            return mapped
        return data

    @property
    def min_size(self) -> int | None:
        """Alias property for min capacity."""
        return self.min

    @property
    def max_size(self) -> int | None:
        """Alias property for max capacity."""
        return self.max


class AddonInfo(BaseModel):
    """Information regarding a Kubernetes cluster add-on or plugin."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Addon name.")
    version: str = Field(description="Currently installed addon version.")
    managed_by: Literal["eks-addon", "helm", "manifest", "unknown"] = Field(
        description="Installation and lifecycle manager for this addon."
    )
    namespace: str = Field(
        default="kube-system",
        description="Namespace where the addon resides.",
    )
    chart: str | None = Field(
        default=None,
        description="Helm chart name, if managed by Helm.",
    )
    image: str | None = Field(
        default=None,
        description="Primary container image tag/digest, if applicable.",
    )


class ClusterSnapshot(BaseModel):
    """Immutable snapshot of facts collected during a single cluster readiness scan."""

    model_config = ConfigDict(frozen=True)

    cluster: ClusterRef = Field(description="Cluster reference metadata.")
    control_plane_version: str = Field(
        description="Current Kubernetes control plane minor version (e.g. '1.30')."
    )
    platform_version: str | None = Field(
        default=None,
        description="Provider platform version (e.g. EKS platform version 'eks.1').",
    )
    node_groups: list[NodeGroupInfo] = Field(
        default_factory=list,
        description="Collected node groups and compute pools.",
    )
    addons: list[AddonInfo] = Field(
        default_factory=list,
        description="Installed addons and system components.",
    )
    workloads: dict[str, Any] = Field(
        default_factory=dict,
        description="Workload summaries and inventory facts.",
    )
    pdbs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="PodDisruptionBudgets discovered in the cluster.",
    )
    insights: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Provider-specific insights (e.g. EKS upgrade insights).",
    )
    deprecated_api_usage: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Deprecated or removed Kubernetes API calls identified.",
    )
    capacity: dict[str, Any] = Field(
        default_factory=dict,
        description="Cluster capacity and IP headroom metrics.",
    )
    baseline_ref: str | None = Field(
        default=None,
        description="Reference identifier or timestamp for pre-upgrade metrics baseline.",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this snapshot was collected.",
    )
    collector_errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal collector errors encountered during scan.",
    )


class RiskReport(BaseModel):
    """Complete upgrade readiness risk assessment report."""

    model_config = ConfigDict(frozen=True)

    fingerprint: str = Field(description="Cryptographic fingerprint of the ClusterSnapshot.")
    cluster: ClusterRef = Field(description="Cluster metadata reference.")
    current_version: str = Field(description="Current control plane minor version.")
    target_version: str = Field(description="Target control plane minor version.")
    upgrade_path: list[str] = Field(
        description="List of sequential intermediate minor version hops."
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of all detected readiness findings.",
    )
    overall_risk: Literal["LOW", "MEDIUM", "HIGH", "BLOCKED"] = Field(
        description="Overall calculated risk level."
    )
    llm_narrative: str | None = Field(
        default=None,
        description="Advisory reasoning narrative produced by Bedrock.",
    )
    llm_model_id: str | None = Field(
        default=None,
        description="Bedrock model identifier used for reasoning, if generated.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this report was compiled.",
    )

    @classmethod
    def overall_from_findings(
        cls, findings: Sequence[Finding]
    ) -> Literal["LOW", "MEDIUM", "HIGH", "BLOCKED"]:
        """Derive overall risk level from findings.

        Deterministic logic:
        - Any BLOCKER -> BLOCKED
        - Any HIGH -> HIGH
        - Any MEDIUM -> MEDIUM
        - Otherwise -> LOW
        """
        severities = {f.severity for f in findings}
        if Severity.BLOCKER in severities:
            return "BLOCKED"
        if Severity.HIGH in severities:
            return "HIGH"
        if Severity.MEDIUM in severities:
            return "MEDIUM"
        return "LOW"
