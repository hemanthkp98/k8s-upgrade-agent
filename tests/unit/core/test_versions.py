"""Unit tests for Kubernetes version parsing, arithmetic, and skew calculations."""

import pytest

from kua.core.errors import VersionError
from kua.core.versions import (
    MinorVersion,
    kubelet_skew_ok,
    max_skew_after_hop,
    upgrade_path,
)


class TestMinorVersion:
    """Test parsing and arithmetic helpers for MinorVersion."""

    @pytest.mark.parametrize(
        ("input_str", "expected_major", "expected_minor"),
        [
            ("1.30", 1, 30),
            ("v1.30", 1, 30),
            ("1.30.4", 1, 30),
            ("v1.30.4-eks-a1b2c3", 1, 30),
            ("v1.28.0-alpha.1", 1, 28),
            (" 1.31 ", 1, 31),
            ("v1.8", 1, 8),
            ("2.0.0", 2, 0),
        ],
    )
    def test_parse_valid_versions(
        self, input_str: str, expected_major: int, expected_minor: int
    ) -> None:
        """Valid version strings with various prefixes and suffixes parse correctly."""
        ver = MinorVersion.parse(input_str)
        assert ver.major == expected_major
        assert ver.minor == expected_minor
        assert str(ver) == f"{expected_major}.{expected_minor}"

    @pytest.mark.parametrize(
        "invalid_str",
        [
            "",
            "   ",
            "1",
            "v1",
            "latest",
            "invalid",
            "1.",
            ".30",
            "v.30",
            "alpha.1.30",
        ],
    )
    def test_parse_invalid_versions_raises(self, invalid_str: str) -> None:
        """Garbage or malformed version strings raise VersionError."""
        with pytest.raises(VersionError, match="Invalid Kubernetes version"):
            MinorVersion.parse(invalid_str)

    def test_parse_non_string_raises(self) -> None:
        """Non-string inputs raise VersionError."""
        with pytest.raises(VersionError, match="Invalid Kubernetes version"):
            MinorVersion.parse(None)  # type: ignore[arg-type]

    def test_next_minor(self) -> None:
        """next() increments the minor version by 1."""
        ver = MinorVersion(1, 30)
        nxt = ver.next()
        assert nxt == MinorVersion(1, 31)
        assert str(nxt) == "1.31"

    def test_diff_minor(self) -> None:
        """diff() returns signed minor version distance."""
        v31 = MinorVersion(1, 31)
        v28 = MinorVersion(1, 28)
        assert v31.diff(v28) == 3
        assert v28.diff(v31) == -3
        assert v31.diff(v31) == 0
        # Different major versions
        v20 = MinorVersion(2, 0)
        assert v20.diff(v31) == 69

    def test_ordering(self) -> None:
        """MinorVersion instances support total ordering."""
        v28 = MinorVersion(1, 28)
        v30 = MinorVersion(1, 30)
        v31 = MinorVersion(1, 31)
        assert v28 < v30 < v31
        assert sorted([v31, v28, v30]) == [v28, v30, v31]


class TestUpgradePath:
    """Test upgrade path calculation."""

    def test_multi_hop_path(self) -> None:
        """Intermediate minors are produced sequentially excluding current and including target."""
        assert upgrade_path("1.29", "1.32") == ["1.30", "1.31", "1.32"]

    def test_single_hop_path(self) -> None:
        """Single minor hop produces list containing only target."""
        assert upgrade_path("1.30", "1.31") == ["1.31"]

    def test_same_version_returns_empty_list(self) -> None:
        """When current equals target, upgrade path is empty."""
        assert upgrade_path("1.30", "1.30") == []
        assert upgrade_path("v1.30.4", "1.30") == []

    def test_downgrade_raises_version_error(self) -> None:
        """Target version older than current raises VersionError with downgrade message."""
        with pytest.raises(VersionError, match="downgrade not supported"):
            upgrade_path("1.31", "1.30")


class TestKubeletSkew:
    """Test Kubernetes skew policy rules."""

    def test_skew_within_allowed_limit(self) -> None:
        """Kubelet up to 3 minors older than API server is valid."""
        # Exact 3 minor distance
        assert kubelet_skew_ok(api="1.31", kubelet="1.28") is True
        # 1 minor distance
        assert kubelet_skew_ok(api="1.31", kubelet="1.30") is True
        # Same version
        assert kubelet_skew_ok(api="1.31", kubelet="1.31") is True

    def test_skew_exceeding_limit_fails(self) -> None:
        """Kubelet 4 or more minors older than API server fails skew check."""
        assert kubelet_skew_ok(api="1.32", kubelet="1.28") is False

    def test_kubelet_newer_than_api_fails(self) -> None:
        """Kubelet newer than API server violates skew rules."""
        assert kubelet_skew_ok(api="1.30", kubelet="1.31") is False

    def test_custom_max_older(self) -> None:
        """Custom max_older threshold is respected."""
        assert kubelet_skew_ok(api="1.31", kubelet="1.29", max_older=2) is True
        assert kubelet_skew_ok(api="1.31", kubelet="1.28", max_older=2) is False


class TestMaxSkewAfterHop:
    """Test max_skew_after_hop calculation."""

    def test_max_skew_calculation(self) -> None:
        """Calculates maximum skew across diverse node group kubelet versions."""
        node_versions = ["1.28", "1.29", "1.30"]
        # Upgrading API server to 1.31: oldest is 1.28, skew is 3
        assert max_skew_after_hop(node_versions, "1.31") == 3
        # Upgrading API server to 1.32: oldest is 1.28, skew is 4
        assert max_skew_after_hop(node_versions, "1.32") == 4

    def test_max_skew_empty_nodes(self) -> None:
        """Empty node list yields skew of 0."""
        assert max_skew_after_hop([], "1.31") == 0
