"""Unit tests for configuration models and loader."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kua.config import (
    AuditConfig,
    BedrockConfig,
    ClusterConfig,
    KuaSettings,
    MetricsConfig,
    ScanConfig,
    load_settings,
)
from kua.config.loader import deep_merge
from kua.core.errors import ConfigError


class TestSafeDefaults:
    """Verify that default settings adhere to safety and read-only principles."""

    def test_audit_defaults_are_safe(self) -> None:
        """create_log_group must default to False to prevent unexpected mutation."""
        audit = AuditConfig()
        assert audit.create_log_group is False
        assert audit.retention_days == 365
        assert audit.log_group_prefix == "/k8s-upgrade-agent"
        assert audit.kms_key_arn is None
        assert audit.local_mirror_dir == ".kua/audit"

    def test_scan_defaults_are_safe(self) -> None:
        """helm_release_secrets must default to False to avoid reading k8s secrets by default."""
        scan = ScanConfig()
        assert scan.helm_release_secrets is False
        assert scan.target_version is None
        assert scan.namespaces_exclude == ["kube-node-lease"]
        assert scan.manifest_paths == []
        assert scan.max_findings_per_rule == 200

    def test_metrics_defaults(self) -> None:
        """Metrics default to 'none' and require no Prometheus URL."""
        metrics = MetricsConfig()
        assert metrics.source == "none"
        assert metrics.prometheus_url is None
        assert metrics.baseline_window == "24h"
        assert metrics.checks == []

    def test_bedrock_defaults(self) -> None:
        """Bedrock reasoning defaults to enabled with temperature 0.0."""
        bedrock = BedrockConfig()
        assert bedrock.region is None
        assert bedrock.model_id == "anthropic.claude-sonnet-4-5"
        assert bedrock.max_tokens == 4096
        assert bedrock.temperature == 0.0
        assert bedrock.enabled is True
        assert bedrock.timeout_seconds == 120

    def test_kua_settings_bedrock_region_default(self) -> None:
        """Bedrock region defaults to cluster region if not explicitly provided."""
        settings = KuaSettings(cluster=ClusterConfig(name="test-cluster", region="eu-west-1"))
        assert settings.bedrock.region == "eu-west-1"

    def test_kua_settings_bedrock_region_explicit(self) -> None:
        """Explicit Bedrock region is preserved and not overwritten by cluster region."""
        settings = KuaSettings(
            cluster=ClusterConfig(name="test-cluster", region="eu-west-1"),
            bedrock=BedrockConfig(region="us-east-1"),
        )
        assert settings.bedrock.region == "us-east-1"


class TestValidationFailures:
    """Verify validation constraints and error messages."""

    @pytest.mark.parametrize(
        "invalid_version",
        ["1.31.0", "v1.31", "1", "1.", "2.0", "1.310", "latest", ""],
    )
    def test_invalid_target_version_raises(self, invalid_version: str) -> None:
        """target_version must match pattern ^1\\.\\d{1,2}$."""
        with pytest.raises(ValidationError, match="target_version must match pattern"):
            ScanConfig(target_version=invalid_version)

    @pytest.mark.parametrize("valid_version", ["1.28", "1.30", "1.31", "1.9", None])
    def test_valid_target_version_passes(self, valid_version: str | None) -> None:
        """Valid target_version strings and None are accepted."""
        scan = ScanConfig(target_version=valid_version)
        assert scan.target_version == valid_version

    @pytest.mark.parametrize("invalid_region", ["US-WEST-2", "Eu-Central-1", "AP-SOUTH-1"])
    def test_uppercase_region_raises(self, invalid_region: str) -> None:
        """region must be lowercase."""
        with pytest.raises(ValidationError, match="region must be lowercase"):
            ClusterConfig(name="prod", region=invalid_region)

    @pytest.mark.parametrize("empty_region", ["", "   "])
    def test_empty_region_raises(self, empty_region: str) -> None:
        """region must be non-empty."""
        with pytest.raises(ValidationError, match="region must be non-empty"):
            ClusterConfig(name="prod", region=empty_region)

    def test_bedrock_uppercase_region_raises(self) -> None:
        """Bedrock region if set must also be lowercase."""
        with pytest.raises(ValidationError, match="region must be lowercase"):
            BedrockConfig(region="US-EAST-1")

    @pytest.mark.parametrize("empty_region", ["", "   "])
    def test_bedrock_empty_region_raises(self, empty_region: str) -> None:
        """Bedrock region if set cannot be empty or whitespace."""
        with pytest.raises(ValidationError, match="region must be non-empty"):
            BedrockConfig(region=empty_region)

    @pytest.mark.parametrize("empty_model_id", ["", "   "])
    def test_empty_model_id_raises(self, empty_model_id: str) -> None:
        """model_id must be a non-empty string."""
        with pytest.raises(ValidationError, match="model_id must be a non-empty string"):
            BedrockConfig(model_id=empty_model_id)

    def test_prometheus_source_requires_url(self) -> None:
        """source='prometheus' without prometheus_url raises ValidationError."""
        with pytest.raises(ValidationError, match="prometheus_url is required"):
            MetricsConfig(source="prometheus", prometheus_url=None)

    def test_prometheus_source_with_empty_url_raises(self) -> None:
        """source='prometheus' with whitespace or empty URL raises ValidationError."""
        with pytest.raises(ValidationError, match="prometheus_url is required"):
            MetricsConfig(source="prometheus", prometheus_url="   ")

    def test_prometheus_source_with_valid_url(self) -> None:
        """source='prometheus' with non-empty URL succeeds."""
        metrics = MetricsConfig(
            source="prometheus",
            prometheus_url="http://prometheus.monitoring:9090",
        )
        assert metrics.source == "prometheus"
        assert metrics.prometheus_url == "http://prometheus.monitoring:9090"


class TestDeepMerge:
    """Verify recursive dictionary merging and list replacement behavior."""

    def test_nested_dict_merge(self) -> None:
        """Nested dicts should merge recursively without dropping unmentioned keys."""
        base: dict[str, Any] = {
            "cluster": {"name": "c1", "region": "us-west-2"},
            "audit": {"retention_days": 365},
        }
        override: dict[str, Any] = {
            "cluster": {"name": "c2"},
            "audit": {"create_log_group": True},
        }
        merged = deep_merge(base, override)
        assert merged == {
            "cluster": {"name": "c2", "region": "us-west-2"},
            "audit": {"retention_days": 365, "create_log_group": True},
        }

    def test_lists_replace_not_append(self) -> None:
        """Lists in overrides must replace lists in base rather than appending."""
        base: dict[str, Any] = {"scan": {"namespaces_exclude": ["kube-system", "kube-node-lease"]}}
        override: dict[str, Any] = {"scan": {"namespaces_exclude": ["custom-ns"]}}
        merged = deep_merge(base, override)
        assert merged["scan"]["namespaces_exclude"] == ["custom-ns"]


class TestPrecedenceAndOverrides:
    """Verify configuration precedence order: CLI overrides -> Env vars -> YAML file -> Defaults."""

    def test_file_beats_defaults(self, tmp_path: Path) -> None:
        """Values in YAML file beat model defaults."""
        config_file = tmp_path / "kua.yaml"
        config_file.write_text(
            """
cluster:
  name: yaml-cluster
  region: ap-south-1
audit:
  retention_days: 90
"""
        )
        settings = load_settings(config_file)
        assert settings.cluster.name == "yaml-cluster"
        assert settings.cluster.region == "ap-south-1"
        assert settings.audit.retention_days == 90
        # Default value for untouched field
        assert settings.audit.create_log_group is False

    def test_env_var_beats_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables beat values defined in YAML file."""
        config_file = tmp_path / "kua.yaml"
        config_file.write_text(
            """
cluster:
  name: yaml-cluster
  region: us-east-1
audit:
  retention_days: 90
"""
        )
        monkeypatch.setenv("KUA_CLUSTER__NAME", "env-cluster")
        monkeypatch.setenv("KUA_AUDIT__RETENTION_DAYS", "180")

        settings = load_settings(config_file)
        assert settings.cluster.name == "env-cluster"
        assert settings.cluster.region == "us-east-1"
        assert settings.audit.retention_days == 180

    def test_cli_override_beats_env_var_and_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI overrides dictionary beats both environment variables and YAML file values."""
        config_file = tmp_path / "kua.yaml"
        config_file.write_text(
            """
cluster:
  name: yaml-cluster
  region: us-east-1
scan:
  target_version: "1.30"
  max_findings_per_rule: 50
"""
        )
        monkeypatch.setenv("KUA_CLUSTER__NAME", "env-cluster")
        monkeypatch.setenv("KUA_SCAN__TARGET_VERSION", "1.31")

        overrides = {
            "cluster": {"name": "cli-cluster"},
            "scan": {"target_version": "1.32"},
        }

        settings = load_settings(config_file, overrides=overrides)
        assert settings.cluster.name == "cli-cluster"
        assert settings.scan.target_version == "1.32"
        # max_findings_per_rule retained from YAML file
        assert settings.scan.max_findings_per_rule == 50
        # region retained from YAML file
        assert settings.cluster.region == "us-east-1"

    def test_nested_environment_variable_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nested environment variables correctly populate nested models."""
        monkeypatch.setenv("KUA_CLUSTER__NAME", "prod-cluster")
        monkeypatch.setenv("KUA_CLUSTER__REGION", "us-west-2")
        monkeypatch.setenv("KUA_AUDIT__CREATE_LOG_GROUP", "true")
        monkeypatch.setenv("KUA_SCAN__HELM_RELEASE_SECRETS", "true")
        monkeypatch.setenv("KUA_SCAN__TARGET_VERSION", "1.31")

        settings = load_settings()
        assert settings.cluster.name == "prod-cluster"
        assert settings.cluster.region == "us-west-2"
        assert settings.audit.create_log_group is True
        assert settings.scan.helm_release_secrets is True
        assert settings.scan.target_version == "1.31"


class TestLoaderErrors:
    """Verify loader error handling for invalid files and configurations."""

    def test_missing_file_raises_config_error(self, tmp_path: Path) -> None:
        """Providing a non-existent path raises ConfigError."""
        missing_file = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigError, match="Configuration file not found"):
            load_settings(missing_file)

    def test_malformed_yaml_raises_config_error(self, tmp_path: Path) -> None:
        """Providing malformed YAML raises ConfigError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("cluster: [invalid yaml {:")
        with pytest.raises(ConfigError, match="Failed to read or parse YAML file"):
            load_settings(bad_file)

    def test_non_mapping_yaml_raises_config_error(self, tmp_path: Path) -> None:
        """YAML root that is not a mapping raises ConfigError."""
        bad_file = tmp_path / "list.yaml"
        bad_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="must be a mapping"):
            load_settings(bad_file)

    def test_load_example_kua_yaml(self) -> None:
        """examples/kua.yaml must load and validate cleanly."""
        example_path = Path("examples/kua.yaml")
        assert example_path.is_file()
        settings = load_settings(example_path)
        assert settings.cluster.name == "prod-eks-01"
        assert settings.cluster.region == "ap-south-1"
        assert settings.bedrock.region == "ap-south-1"
        assert settings.scan.target_version == "1.31"
