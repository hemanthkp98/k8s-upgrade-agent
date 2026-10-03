"""Kubernetes version arithmetic, upgrade path calculation, and skew verification."""

import re
from dataclasses import dataclass

from kua.core.errors import VersionError

_VERSION_PATTERN = re.compile(r"^v?(?P<major>\d+)\.(?P<minor>\d+)(?:\..*)?$")


@dataclass(frozen=True, order=True)
class MinorVersion:
    """Represents a Kubernetes major.minor version with arithmetic helpers."""

    major: int
    minor: int

    @classmethod
    def parse(cls, s: str) -> "MinorVersion":
        """Parse a version string (e.g. '1.30', 'v1.30', '1.30.4', 'v1.30.4-eks-a1b2c3').

        Args:
            s: Version string to parse.

        Returns:
            A parsed MinorVersion instance.

        Raises:
            VersionError: If the string cannot be parsed as a valid Kubernetes version.
        """
        if not s or not isinstance(s, str):
            raise VersionError(f"Invalid Kubernetes version string: {s!r}")

        match = _VERSION_PATTERN.match(s.strip())
        if not match:
            raise VersionError(f"Invalid Kubernetes version format: {s!r}")

        return cls(int(match.group("major")), int(match.group("minor")))

    def __str__(self) -> str:
        """Return the canonical 'major.minor' representation."""
        return f"{self.major}.{self.minor}"

    def next(self) -> "MinorVersion":
        """Return the next minor version (+1 minor)."""
        return MinorVersion(self.major, self.minor + 1)

    def diff(self, other: "MinorVersion") -> int:
        """Return the signed minor version distance (self - other).

        Args:
            other: The MinorVersion to compare against.

        Returns:
            Positive int if self is newer than other, negative if older, 0 if identical.
        """
        if self.major != other.major:
            return (self.major - other.major) * 100 + (self.minor - other.minor)
        return self.minor - other.minor


def upgrade_path(current: str, target: str) -> list[str]:
    """Calculate the sequential intermediate minor versions required to reach target.

    Excludes the current version and includes the target version.
    Returns an empty list if current equals target.

    Args:
        current: Current cluster minor version (e.g. '1.29').
        target: Target minor version (e.g. '1.32').

    Returns:
        List of intermediate version strings (e.g. ['1.30', '1.31', '1.32']).

    Raises:
        VersionError: If target is older than current (downgrade not supported).
    """
    cur_ver = MinorVersion.parse(current)
    tgt_ver = MinorVersion.parse(target)

    if cur_ver == tgt_ver:
        return []

    if tgt_ver < cur_ver:
        raise VersionError(f"downgrade not supported: {current} -> {target}")

    path: list[str] = []
    hop = cur_ver.next()
    while hop <= tgt_ver:
        path.append(str(hop))
        hop = hop.next()

    return path


def kubelet_skew_ok(api: str, kubelet: str, max_older: int = 3) -> bool:
    """Verify Kubernetes version skew policy between API server and kubelet.

    Kubelet must never be newer than the API server, and must be at most
    `max_older` minor versions behind the API server (default 3 minors per
    Kubernetes >= 1.28 skew policy).

    Args:
        api: Kubernetes API server version string.
        kubelet: Kubelet version string.
        max_older: Maximum allowed minor versions older (default 3).

    Returns:
        True if skew policy is satisfied; False otherwise.
    """
    api_ver = MinorVersion.parse(api)
    kube_ver = MinorVersion.parse(kubelet)

    if kube_ver > api_ver:
        return False

    return api_ver.diff(kube_ver) <= max_older


def max_skew_after_hop(node_versions: list[str], new_api: str) -> int:
    """Calculate the maximum minor version skew between nodes and a proposed new API server version.

    Args:
        node_versions: List of kubelet version strings currently in the cluster.
        new_api: The proposed target API server version string.

    Returns:
        The maximum minor version distance (new_api - oldest_node). Returns 0 if
        node_versions is empty.
    """
    if not node_versions:
        return 0

    api_ver = MinorVersion.parse(new_api)
    skews = [api_ver.diff(MinorVersion.parse(node_ver)) for node_ver in node_versions]
    return max(skews)
