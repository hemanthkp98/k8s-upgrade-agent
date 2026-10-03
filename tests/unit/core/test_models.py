"""Unit tests for core domain models, severities, findings, and reports."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kua.core.models import (
    AddonInfo,
    ClusterRef,
    ClusterSnapshot,
    Finding,
    FindingSource,
    NodeGroupInfo,
    Phase,
    ResourceRef,
    RiskReport,
    Severity,
)


class TestSeverity:
    """Test Severity enumeration, rank property, and ordering comparisons."""

    def test_severity_ranks(self) -> None:
        """Verify numeric rank mappings."""
        assert Severity.BLOCKER.rank == 5
        assert Severity.HIGH.rank == 4
        assert Severity.MEDIUM.rank == 3
        assert Severity.LOW.rank == 2
        assert Severity.INFO.rank == 1

    def test_severity_ordering(self) -> None:
        """Severities compare based on severity rank, not lexicographical string order."""
        assert Severity.BLOCKER > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert Severity.BLOCKER >= Severity.BLOCKER
        assert Severity.INFO <= Severity.LOW

    def test_max_severity(self) -> None:
        """max() correctly identifies the highest severity from a sequence."""
        severities = [Severity.LOW, Severity.HIGH, Severity.INFO, Severity.MEDIUM]
        assert max(severities) == Severity.HIGH
        severities_with_blocker = [*severities, Severity.BLOCKER]
        assert max(severities_with_blocker) == Severity.BLOCKER

    def test_sorted_severities(self) -> None:
        """Sorting a list of severities sorts from lowest to highest rank."""
        unsorted = [Severity.BLOCKER, Severity.INFO, Severity.HIGH, Severity.LOW]
        assert sorted(unsorted) == [
            Severity.INFO,
            Severity.LOW,
            Severity.HIGH,
            Severity.BLOCKER,
        ]

    def test_compare_non_severity_returns_not_implemented(self) -> None:
        """Comparing Severity with a non-Severity object returns NotImplemented."""
        assert Severity.BLOCKER.__lt__(1) is NotImplemented
        assert Severity.BLOCKER.__le__(1) is NotImplemented
        assert Severity.BLOCKER.__gt__(1) is NotImplemented
        assert Severity.BLOCKER.__ge__(1) is NotImplemented


class TestResourceRef:
    """Test ResourceRef string representations and validation."""

    def test_namespaced_resource_str(self) -> None:
        """Namespaced resource formats as kind/namespace/name."""
        ref = ResourceRef(kind="Pod", namespace="production", name="api-server-79d")
        assert str(ref) == "Pod/production/api-server-79d"

    def test_cluster_scoped_resource_str(self) -> None:
        """Cluster-scoped resource formats as kind/name."""
        ref = ResourceRef(kind="Node", name="ip-10-0-1-50.ec2.internal")
        assert str(ref) == "Node/ip-10-0-1-50.ec2.internal"

    def test_resource_ref_frozen(self) -> None:
        """ResourceRef instances are immutable."""
        ref = ResourceRef(kind="Node", name="node-1")
        with pytest.raises(ValidationError):
            ref.name = "node-2"  # type: ignore[misc]


class TestFinding:
    """Test Finding id validation, title constraints, and immutability."""

    @pytest.mark.parametrize(
        "valid_id",
        [
            "DRAIN-PDB-ZERO-DISRUPTION",
            "API-DEPRECATED-1-31",
            "EKS-INSIGHT-ADDON-VPC-CNI",
            "SEC-01",
            "A-B-C-D-E",
        ],
    )
    def test_valid_finding_id(self, valid_id: str) -> None:
        """Valid finding IDs matching ^[A-Z0-9]+(-[A-Z0-9]+)+$ pass."""
        finding = Finding(
            id=valid_id,
            severity=Severity.HIGH,
            title="Valid finding",
            detail="Detail",
            remediation="Fix it",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )
        assert finding.id == valid_id

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "lowercase-id",
            "NOHYPHENS",
            "NO_UNDERSCORES-HERE",
            "-LEADING-HYPHEN",
            "TRAILING-HYPHEN-",
            "DOUBLE--HYPHEN",
            "INV@LID-CHARS",
            "",
            "   ",
        ],
    )
    def test_invalid_finding_id_raises(self, invalid_id: str) -> None:
        """Invalid finding IDs raise ValidationError."""
        with pytest.raises(ValidationError, match="id"):
            Finding(
                id=invalid_id,
                severity=Severity.MEDIUM,
                title="Title",
                detail="Detail",
                remediation="Fix",
                source=FindingSource.RULE,
                phase=Phase.CP,
            )

    def test_title_max_length(self) -> None:
        """Title must be <= 120 characters."""
        valid_title = "x" * 120
        f = Finding(
            id="TEST-01",
            severity=Severity.INFO,
            title=valid_title,
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.POST,
        )
        assert f.title == valid_title

        invalid_title = "x" * 121
        with pytest.raises(ValidationError, match="title"):
            Finding(
                id="TEST-01",
                severity=Severity.INFO,
                title=invalid_title,
                detail="Detail",
                remediation="Remediation",
                source=FindingSource.RULE,
                phase=Phase.POST,
            )

    def test_finding_is_frozen(self) -> None:
        """Finding instances cannot be mutated."""
        f = Finding(
            id="TEST-01",
            severity=Severity.INFO,
            title="Title",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.POST,
        )
        with pytest.raises(ValidationError):
            f.severity = Severity.HIGH  # type: ignore[misc]


class TestNodeGroupInfo:
    """Test NodeGroupInfo capacity aliases and defaults."""

    def test_min_max_size_aliases(self) -> None:
        """min_size and max_size can be used during instantiation and accessed as properties."""
        ng = NodeGroupInfo(
            name="ng-prod-1",
            kind="managed",
            min_size=2,
            max_size=10,
            desired=5,
        )
        assert ng.min == 2
        assert ng.max == 10
        assert ng.min_size == 2
        assert ng.max_size == 10

    def test_standard_min_max(self) -> None:
        """Standard min and max fields work directly."""
        ng = NodeGroupInfo(
            name="ng-prod-2",
            kind="self_managed",
            min=1,
            max=5,
        )
        assert ng.min == 1
        assert ng.max == 5
        assert ng.min_size == 1
        assert ng.max_size == 5

    def test_default_os(self) -> None:
        """Default OS family is linux."""
        ng = NodeGroupInfo(name="ng-1", kind="karpenter")
        assert ng.os == "linux"
        # Validate existing instance passes through model_validate
        validated = NodeGroupInfo.model_validate(ng)
        assert validated == ng
        # Validate non-dict input to validator returns input directly
        assert NodeGroupInfo._remap_min_max("non-dict") == "non-dict"


class TestClusterSnapshotAndRiskReport:
    """Test snapshot and report creation and risk aggregation."""

    def _sample_cluster_ref(self) -> ClusterRef:
        return ClusterRef(provider="eks", name="prod-eks", region="us-west-2")

    def test_cluster_snapshot_creation(self) -> None:
        """ClusterSnapshot correctly holds all collected inventory facts."""
        snap = ClusterSnapshot(
            cluster=self._sample_cluster_ref(),
            control_plane_version="1.30",
            platform_version="eks.3",
            node_groups=[NodeGroupInfo(name="mng-1", kind="managed")],
            addons=[
                AddonInfo(
                    name="vpc-cni",
                    version="v1.18.1-eksbuild.1",
                    managed_by="eks-addon",
                    namespace="kube-system",
                )
            ],
        )
        assert snap.control_plane_version == "1.30"
        assert snap.platform_version == "eks.3"
        assert len(snap.node_groups) == 1
        assert len(snap.addons) == 1
        assert isinstance(snap.collected_at, datetime)

    def test_overall_from_findings_logic(self) -> None:
        """Verify deterministic overall risk calculation from findings."""
        b_finding = Finding(
            id="TEST-BLOCKER",
            severity=Severity.BLOCKER,
            title="Blocker",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )
        h_finding = Finding(
            id="TEST-HIGH",
            severity=Severity.HIGH,
            title="High",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )
        m_finding = Finding(
            id="TEST-MEDIUM",
            severity=Severity.MEDIUM,
            title="Medium",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )
        l_finding = Finding(
            id="TEST-LOW",
            severity=Severity.LOW,
            title="Low",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )
        i_finding = Finding(
            id="TEST-INFO",
            severity=Severity.INFO,
            title="Info",
            detail="Detail",
            remediation="Remediation",
            source=FindingSource.RULE,
            phase=Phase.PRE_CP,
        )

        # Empty findings -> LOW
        assert RiskReport.overall_from_findings([]) == "LOW"
        # Only INFO or LOW -> LOW
        assert RiskReport.overall_from_findings([l_finding, i_finding]) == "LOW"
        # Any MEDIUM (and no higher) -> MEDIUM
        assert RiskReport.overall_from_findings([l_finding, m_finding]) == "MEDIUM"
        # Any HIGH (and no blocker) -> HIGH
        assert RiskReport.overall_from_findings([m_finding, h_finding]) == "HIGH"
        # Any BLOCKER -> BLOCKED
        assert RiskReport.overall_from_findings([h_finding, b_finding]) == "BLOCKED"

    def test_risk_report_instantiation(self) -> None:
        """RiskReport instantiates with full metadata and is immutable."""
        report = RiskReport(
            fingerprint="sha256:abc123def456",
            cluster=self._sample_cluster_ref(),
            current_version="1.30",
            target_version="1.31",
            upgrade_path=["1.31"],
            overall_risk="LOW",
            findings=[],
            generated_at=datetime.now(UTC),
        )
        assert report.current_version == "1.30"
        assert report.overall_risk == "LOW"
        with pytest.raises(ValidationError):
            report.overall_risk = "HIGH"  # type: ignore[misc]
