"""Base provider protocol and provider factory."""

from typing import Any, Protocol, runtime_checkable

from kubernetes.client import ApiClient

from kua.config.settings import KuaSettings
from kua.core.errors import ConfigError
from kua.core.models import AddonInfo, ClusterRef, NodeGroupInfo


@runtime_checkable
class Provider(Protocol):
    """Protocol defining the interface for cloud and cluster infrastructure providers."""

    name: str

    def cluster_ref(self) -> ClusterRef:
        """Return the cluster identity and location reference."""
        ...

    def control_plane_version(self) -> str:
        """Return the current normalized control plane minor version (e.g. '1.30')."""
        ...

    def platform_version(self) -> str | None:
        """Return provider-specific platform version (e.g. 'eks.1'), if applicable."""
        ...

    def list_node_groups(self) -> list[NodeGroupInfo]:
        """List and describe node groups and compute pools in the cluster."""
        ...

    def list_provider_addons(self) -> list[AddonInfo]:
        """List managed add-ons provisioned through the provider."""
        ...

    def compatible_addon_versions(self, addon: str, k8s_version: str) -> list[str]:
        """List compatible versions of a managed add-on for a given Kubernetes minor version."""
        ...

    def upgrade_insights(self, target: str) -> list[dict[str, Any]]:
        """Retrieve provider upgrade readiness insights or deprecation warnings."""
        ...

    def capacity_facts(self) -> dict[str, Any]:
        """Retrieve provider capacity, quota, and IP headroom facts."""
        ...

    def k8s_api_client(self) -> ApiClient:
        """Construct and return an authenticated Kubernetes ApiClient."""
        ...


def get_provider(settings: KuaSettings) -> Provider:
    """Factory function returning a configured Provider for the cluster in settings.

    Args:
        settings: Active KuaSettings.

    Returns:
        Provider instance corresponding to settings.cluster.provider.

    Raises:
        ConfigError: If the provider is unsupported.
    """
    provider_name = settings.cluster.provider
    if provider_name == "eks":
        from kua.providers.eks.provider import EksProvider

        return EksProvider(settings)

    raise ConfigError(f"Unsupported provider: '{provider_name}'. Only 'eks' is supported.")
