"""Configuration schemas and validation models for kua."""

import re
from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ClusterConfig(BaseModel):
    """Configuration for the target Kubernetes cluster."""

    provider: Literal["eks"] = Field(
        default="eks",
        description="Kubernetes provider type (currently only 'eks' is supported).",
    )
    name: str = Field(
        description="Name of the Kubernetes cluster.",
    )
    region: str = Field(
        description="AWS region where the cluster is located (must be non-empty and lowercase).",
    )
    account_id: str | None = Field(
        default=None,
        description="AWS account ID owning the cluster.",
    )
    role_arn: str | None = Field(
        default=None,
        description="IAM role ARN to assume for scanning the cluster.",
    )

    @field_validator("region")
    @classmethod
    def validate_region(cls, v: str) -> str:
        """Validate that region is non-empty and lowercase."""
        if not v or not v.strip():
            raise ValueError("region must be non-empty")
        if v != v.lower():
            raise ValueError("region must be lowercase")
        return v


class BedrockConfig(BaseModel):
    """Configuration for Amazon Bedrock LLM reasoning layer."""

    region: str | None = Field(
        default=None,
        description="AWS region for Bedrock API calls. Defaults to cluster region if not set.",
    )
    # TODO: verify current Bedrock model ID / inference profile
    model_id: str = Field(
        default="anthropic.claude-sonnet-4-5",
        description="Bedrock model ID or inference profile identifier.",
    )
    max_tokens: int = Field(
        default=4096,
        description="Maximum tokens for Bedrock reasoning response generation.",
    )
    temperature: float = Field(
        default=0.0,
        description="Sampling temperature for Bedrock reasoning (0.0 for deterministic output).",
    )
    enabled: bool = Field(
        default=True,
        description="Whether Bedrock AI reasoning and risk narrative generation is enabled.",
    )
    timeout_seconds: int = Field(
        default=120,
        description="API timeout in seconds for Bedrock requests.",
    )

    @field_validator("region")
    @classmethod
    def validate_region(cls, v: str | None) -> str | None:
        """Validate that region is non-empty and lowercase when set."""
        if v is None:
            return v
        if not v or not v.strip():
            raise ValueError("region must be non-empty")
        if v != v.lower():
            raise ValueError("region must be lowercase")
        return v

    @field_validator("model_id")
    @classmethod
    def validate_model_id(cls, v: str) -> str:
        """Validate that model_id is a non-empty string."""
        if not v or not v.strip():
            raise ValueError("model_id must be a non-empty string")
        return v


class AuditConfig(BaseModel):
    """Configuration for hash-chained audit logging."""

    log_group_prefix: str = Field(
        default="/k8s-upgrade-agent",
        description="Prefix for CloudWatch audit log group names.",
    )
    create_log_group: bool = Field(
        default=False,
        description="Whether kua is permitted to create the CloudWatch log group if missing.",
    )
    retention_days: int = Field(
        default=365,
        description="Retention period in days for CloudWatch audit log groups.",
    )
    kms_key_arn: str | None = Field(
        default=None,
        description="KMS CMK ARN used to encrypt the CloudWatch audit log group.",
    )
    local_mirror_dir: str = Field(
        default=".kua/audit",
        description="Local directory where audit event streams are mirrored as JSONL files.",
    )


class MetricsConfig(BaseModel):
    """Configuration for baseline metrics capture and post-upgrade verification."""

    source: Literal["prometheus", "cloudwatch", "none"] = Field(
        default="none",
        description="Metrics backend for workload baseline capture and health verification.",
    )
    prometheus_url: str | None = Field(
        default=None,
        description="Base URL for Prometheus API (required if source is 'prometheus').",
    )
    baseline_window: str = Field(
        default="24h",
        description="Time duration window used for metric baselines (e.g. '24h', '1h').",
    )
    checks: list[str] = Field(
        default_factory=list,
        description="List of metric check expressions evaluated during verification.",
    )

    @model_validator(mode="after")
    def validate_prometheus_url(self) -> Self:
        """Validate that prometheus_url is non-empty when source is 'prometheus'."""
        if self.source == "prometheus" and (
            not self.prometheus_url or not self.prometheus_url.strip()
        ):
            raise ValueError(
                "prometheus_url is required and must be non-empty when source is 'prometheus'"
            )
        return self


class ScanConfig(BaseModel):
    """Configuration for cluster readiness scanning."""

    target_version: str | None = Field(
        default=None,
        description="Target Kubernetes minor version (e.g. '1.31'). None targets the next minor.",
    )
    namespaces_exclude: list[str] = Field(
        default_factory=lambda: ["kube-node-lease"],
        description="List of Kubernetes namespaces excluded from scanning.",
    )
    helm_release_secrets: bool = Field(
        default=False,
        description="Whether to inspect Helm release secrets directly (opt-in).",
    )
    manifest_paths: list[str] = Field(
        default_factory=list,
        description="Local directory paths with manifests or Helm charts to scan statically.",
    )
    max_findings_per_rule: int = Field(
        default=200,
        description="Maximum findings collected per individual rule to prevent report blowup.",
    )

    @field_validator("target_version")
    @classmethod
    def validate_target_version(cls, v: str | None) -> str | None:
        """Validate that target_version matches pattern ^1\\.\\d{1,2}$ when set."""
        if v is None:
            return v
        if not re.match(r"^1\.\d{1,2}$", v):
            raise ValueError(
                f"target_version must match pattern '^1.\\d{{1,2}}$' (e.g. '1.31'), got '{v}'"
            )
        return v


class KuaSettings(BaseSettings):
    """Unified configuration settings for kua."""

    cluster: ClusterConfig = Field(
        description="Configuration of the target Kubernetes/EKS cluster.",
    )
    bedrock: BedrockConfig = Field(
        default_factory=BedrockConfig,
        description="Configuration for Bedrock LLM reasoning.",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Configuration for hash-chained audit logging.",
    )
    metrics: MetricsConfig = Field(
        default_factory=MetricsConfig,
        description="Configuration for metrics collection and verification.",
    )
    scan: ScanConfig = Field(
        default_factory=ScanConfig,
        description="Configuration for readiness scanning.",
    )

    model_config = SettingsConfigDict(
        env_prefix="KUA_",
        env_nested_delimiter="__",
    )

    @model_validator(mode="after")
    def _default_bedrock_region_from_cluster(self) -> Self:
        """Default Bedrock region to cluster region if not explicitly configured."""
        if self.bedrock.region is None:
            self.bedrock.region = self.cluster.region
        return self
