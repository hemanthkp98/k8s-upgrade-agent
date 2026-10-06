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
- `AuditError` exception in `kua.core.errors` (re-exported in `kua.core`).
- Audit event definitions (`AuditEventType`, `AuditEvent`) in `kua.audit.events` with UTC ISO8601 timestamps and Pydantic v2 immutability.
- Deterministic canonical JSON serialization (`canonical_json`), SHA-256 hash computation (`compute_hash`), stateful `HashChain`, and verification algorithm (`verify_chain`) in `kua.audit.chain`.
- Recursive sensitive payload redaction (`redact`) in `kua.audit.redact` covering passwords, secrets, tokens, credentials, AWS access keys, PEM private keys, JWT tokens, environment variable lists, and string truncation.
- Protocol-driven audit sinks in `kua.audit.sinks`: `LocalJsonlSink` (append-only with fsync), `CloudWatchSink` (CloudWatch limits-aware batching, retry with exponential backoff, and optional log group creation), and `MultiSink` (multi-target fan-out and fail-loud semantics).
- `AuditLogger` orchestrator and `new_run_id` generator in `kua.audit.logger` with buffering and context manager support.
- Comprehensive unit test suites in `tests/unit/audit/test_chain.py`, `tests/unit/audit/test_redact.py`, `tests/unit/audit/test_sinks.py`, and `tests/unit/audit/test_logger.py`.
- `make_boto_session` and `caller_identity` in `kua.providers.eks.session` for regional session initialization, STS role assumption (`kua-scan`), and caller identity resolution for audit events.
- `get_eks_token` in `kua.providers.eks.auth` generating pre-signed STS Bearer tokens with `x-k8s-aws-id` header mirroring `aws eks get-token` (14m refresh horizon).
- `build_k8s_api_client` in `kua.providers.eks.auth` for in-process EKS endpoint & CA resolution, temporary certificate management with `atexit` cleanup, and token auto-refresh hook (`TokenRefresher`).
- Actionable `AuthError` reporting for `eks:DescribeCluster` permission denial, HTTP 401 unauthorized (unmapped IAM principal), and private cluster connection timeouts.
- `check_k8s_access` in `kua.providers.eks.auth` checking required scanner permissions via Kubernetes `SelfSubjectAccessReview`.
- Comprehensive unit test suites in `tests/unit/providers/eks/test_session.py` and `tests/unit/providers/eks/test_auth.py`.
- `Provider` protocol and `get_provider` factory in `kua.providers.base` defining provider-agnostic interfaces for cluster inventory collection, versions, add-ons, node groups, and Kubernetes client construction.
- `EksProvider` in `kua.providers.eks.provider` collecting EKS cluster metadata, normalized control plane version, platform version, managed node groups (with AL2023, custom AMI, Bottlerocket, and Windows detection), managed add-ons, and version compatibility matrices via boto3 paginators.
- Result caching for cluster description and add-on version compatibility matrices.
- Non-fatal error aggregation tracking API issues without breaking partial inventory collection.
- Comprehensive unit test suites in `tests/unit/providers/test_base.py` and `tests/unit/providers/eks/test_provider.py`.
- `classify_node` and compute architecture classification in `kua.providers.eks.compute` detecting Managed Node Groups, Karpenter NodePools/provisioners, Fargate profiles, EKS Auto Mode, and self-managed groups (via `alpha.eksctl.io/nodegroup-name` or EC2 ASG tag lookup).
- Operating system detection for Linux, Windows, and Bottlerocket OS, plus normalized kubelet version extraction via `MinorVersion`.
- Karpenter CRD detection (`nodepools.karpenter.sh`, `provisioners.karpenter.sh`) via `ApiextensionsV1Api` storing installation status in compute evidence.
- Discovery of EKS Fargate profiles independent of active pod allocations.
- Integration of live node inspection into `EksProvider.list_node_groups` aggregating per-group kubelet version distributions, instance types, and availability zones.
- Test fixture node datasets under `tests/fixtures/nodes/` covering managed, Karpenter, Fargate, Auto Mode, self-managed, mixed-version, Windows, and Bottlerocket nodes.
- Comprehensive unit test suite in `tests/unit/providers/eks/test_compute.py`.


