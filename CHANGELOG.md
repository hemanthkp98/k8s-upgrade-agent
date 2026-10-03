# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold and tooling configuration for `k8s-upgrade-agent` (`kua`).
- CLI entrypoint with `version` and placeholder `scan` commands.
- Strict linting, formatting (`ruff`), and type checking (`mypy`).
- Initial unit test harness and CI workflow.
- Pydantic v2 configuration models in `kua.config.settings` (`ClusterConfig`, `BedrockConfig`, `AuditConfig`, `MetricsConfig`, `ScanConfig`, `KuaSettings`).
- Configuration loader `load_settings` in `kua.config.loader` enforcing CLI overrides > environment variables (`KUA_*`) > YAML file > defaults precedence.
- Safe-by-default configuration (`create_log_group: false`, `helm_release_secrets: false`).
- Exception hierarchy with `KuaError` and `ConfigError` in `kua.core.errors`.
- Fully documented example configuration file `examples/kua.yaml`.
- Comprehensive unit test suite for configuration defaults, validation constraints, and precedence rules.
- Core domain models in `kua.core.models` (`Severity`, `Phase`, `FindingSource`, `ResourceRef`, `Finding`, `ClusterRef`, `NodeGroupInfo`, `AddonInfo`, `ClusterSnapshot`, `RiskReport`).
- Rank-based comparison and ordering helpers for `Severity` enum (`BLOCKER`=5 ... `INFO`=1).
- Deterministic overall risk evaluation via `RiskReport.overall_from_findings`.
- Kubernetes version parsing and arithmetic in `kua.core.versions` (`MinorVersion`, `upgrade_path`, `kubelet_skew_ok`, `max_skew_after_hop`).
- Extended exception hierarchy with `VersionError`, `CollectorError`, and `AuthError` in `kua.core.errors`.
- Comprehensive unit test suites in `tests/unit/core/test_models.py` and `tests/unit/core/test_versions.py`.
