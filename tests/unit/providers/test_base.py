"""Unit tests for the Provider base protocol and provider factory."""

import pytest

from kua.config.settings import ClusterConfig, KuaSettings
from kua.core.errors import ConfigError
from kua.providers.base import Provider, get_provider
from kua.providers.eks.provider import EksProvider


def test_get_provider_eks() -> None:
    """get_provider returns an EksProvider when provider is 'eks'."""
    settings = KuaSettings(
        cluster=ClusterConfig(provider="eks", name="test-cluster", region="us-west-2")
    )
    provider = get_provider(settings)
    assert isinstance(provider, EksProvider)
    assert isinstance(provider, Provider)
    assert provider.name == "eks"


def test_get_provider_unsupported() -> None:
    """get_provider raises ConfigError for unsupported providers."""
    # Bypass pydantic validation for testing future/unknown provider strings
    settings = KuaSettings(cluster=ClusterConfig(name="test-cluster", region="us-west-2"))
    object.__setattr__(settings.cluster, "provider", "unsupported-cloud")

    with pytest.raises(ConfigError, match="Unsupported provider: 'unsupported-cloud'"):
        get_provider(settings)
