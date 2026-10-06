"""Unit tests for EksProvider and EKS cluster inventory collector."""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber

from kua.config.settings import ClusterConfig, KuaSettings
from kua.core.errors import CollectorError
from kua.core.models import AddonInfo, ClusterRef, NodeGroupInfo
from kua.providers.base import Provider
from kua.providers.eks.provider import EksProvider


@pytest.fixture
def mock_session() -> boto3.Session:
    """Fixture returning a boto3 session configured for testing."""
    return boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-west-2",
    )


@pytest.fixture
def test_settings() -> KuaSettings:
    """Fixture returning test KuaSettings."""
    return KuaSettings(
        cluster=ClusterConfig(
            provider="eks",
            name="prod-eks",
            region="us-west-2",
            account_id="123456789012",
        )
    )


def test_eks_provider_implements_protocol(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """EksProvider conforms to the Provider protocol."""
    provider = EksProvider(test_settings, session=mock_session)
    assert isinstance(provider, Provider)
    assert provider.name == "eks"


def test_cluster_ref(test_settings: KuaSettings, mock_session: boto3.Session) -> None:
    """cluster_ref returns cluster identification and configured account_id."""
    provider = EksProvider(test_settings, session=mock_session)
    ref = provider.cluster_ref()
    assert isinstance(ref, ClusterRef)
    assert ref.provider == "eks"
    assert ref.name == "prod-eks"
    assert ref.region == "us-west-2"
    assert ref.account_id == "123456789012"


def test_cluster_ref_resolves_caller_identity_when_account_id_none(
    mock_session: boto3.Session,
) -> None:
    """cluster_ref queries STS caller identity if account_id is not explicitly set."""
    settings = KuaSettings(
        cluster=ClusterConfig(provider="eks", name="prod-eks", region="us-west-2", account_id=None)
    )
    provider = EksProvider(settings, session=mock_session)

    sts_client = mock_session.client("sts")
    with (
        Stubber(sts_client) as sts_stubber,
        patch.object(mock_session, "client", return_value=sts_client),
    ):
        sts_stubber.add_response(
            "get_caller_identity",
            {"Account": "999888777666", "Arn": "arn:aws:iam::999888777666:user/tester"},
            {},
        )
        ref = provider.cluster_ref()
        assert ref.account_id == "999888777666"


def test_control_plane_and_platform_version(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """control_plane_version normalizes version and platform_version returns platformVersion."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_response(
            "describe_cluster",
            {
                "cluster": {
                    "name": "prod-eks",
                    "version": "v1.30.2-eks-a1b2c3",
                    "platformVersion": "eks.5",
                }
            },
            {"name": "prod-eks"},
        )

        cp_ver = provider.control_plane_version()
        assert cp_ver == "1.30"

        # Cached describe_cluster ensures no duplicate API call
        plat_ver = provider.platform_version()
        assert plat_ver == "eks.5"

        stubber.assert_no_pending_responses()


def test_control_plane_version_error(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """control_plane_version raises CollectorError when describe_cluster fails."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_client_error("describe_cluster", "ResourceNotFoundException")

        with pytest.raises(CollectorError, match="Control plane version not found"):
            provider.control_plane_version()

        assert len(provider.errors) == 1
        assert "Failed to describe EKS cluster" in provider.errors[0]


def test_list_node_groups_pagination_and_custom_ami(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """list_node_groups paginates across 2 pages and classifies standard vs custom AMIs."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        # Page 1 of list_nodegroups
        stubber.add_response(
            "list_nodegroups",
            {"nodegroups": ["ng-standard"], "nextToken": "page-2-token"},
            {"clusterName": "prod-eks"},
        )
        # describe_nodegroup for ng-standard (from page 1)
        stubber.add_response(
            "describe_nodegroup",
            {
                "nodegroup": {
                    "nodegroupName": "ng-standard",
                    "amiType": "AL2023_x86_64_STANDARD",
                    "scalingConfig": {"minSize": 2, "maxSize": 10, "desiredSize": 4},
                    "subnets": ["subnet-01", "subnet-02"],
                    "instanceTypes": ["m5.large"],
                }
            },
            {"clusterName": "prod-eks", "nodegroupName": "ng-standard"},
        )

        # Page 2 of list_nodegroups
        stubber.add_response(
            "list_nodegroups",
            {"nodegroups": ["ng-custom"]},
            {"clusterName": "prod-eks", "nextToken": "page-2-token"},
        )
        # describe_nodegroup for ng-custom (from page 2)
        stubber.add_response(
            "describe_nodegroup",
            {
                "nodegroup": {
                    "nodegroupName": "ng-custom",
                    "amiType": "CUSTOM",
                    "launchTemplate": {"name": "custom-lt", "version": "3"},
                    "scalingConfig": {"minSize": 1, "maxSize": 6, "desiredSize": 2},
                    "subnets": ["subnet-03"],
                    "instanceTypes": ["c5.xlarge"],
                }
            },
            {"clusterName": "prod-eks", "nodegroupName": "ng-custom"},
        )

        groups = provider.list_node_groups()
        stubber.assert_no_pending_responses()

        assert len(groups) == 2

        # Verify ng-standard
        ng1 = groups[0]
        assert isinstance(ng1, NodeGroupInfo)
        assert ng1.name == "ng-standard"
        assert ng1.kind == "managed"
        assert ng1.custom_ami is False
        assert ng1.ami_type == "AL2023_x86_64_STANDARD"
        assert ng1.os == "linux"
        assert ng1.min == 2
        assert ng1.max == 10
        assert ng1.desired == 4
        assert ng1.subnets == ["subnet-01", "subnet-02"]
        assert ng1.instance_types == ["m5.large"]
        assert ng1.kubelet_versions == {}

        # Verify ng-custom
        ng2 = groups[1]
        assert isinstance(ng2, NodeGroupInfo)
        assert ng2.name == "ng-custom"
        assert ng2.kind == "managed"
        assert ng2.custom_ami is True
        assert ng2.ami_type == "CUSTOM"
        assert ng2.launch_template == "custom-lt:3"
        assert ng2.min == 1
        assert ng2.max == 6
        assert ng2.desired == 2
        assert ng2.subnets == ["subnet-03"]
        assert ng2.instance_types == ["c5.xlarge"]
        assert ng2.kubelet_versions == {}


def test_list_provider_addons_pagination(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """list_provider_addons paginates across 2 pages and returns AddonInfo list."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        # Page 1 of list_addons
        stubber.add_response(
            "list_addons",
            {"addons": ["vpc-cni", "coredns"], "nextToken": "token-addons-2"},
            {"clusterName": "prod-eks"},
        )
        # describe_addon for vpc-cni (page 1)
        stubber.add_response(
            "describe_addon",
            {
                "addon": {
                    "addonName": "vpc-cni",
                    "addonVersion": "v1.18.1-eksbuild.1",
                    "status": "ACTIVE",
                }
            },
            {"clusterName": "prod-eks", "addonName": "vpc-cni"},
        )
        # describe_addon for coredns (page 1)
        stubber.add_response(
            "describe_addon",
            {
                "addon": {
                    "addonName": "coredns",
                    "addonVersion": "v1.11.1-eksbuild.4",
                    "status": "ACTIVE",
                }
            },
            {"clusterName": "prod-eks", "addonName": "coredns"},
        )

        # Page 2 of list_addons
        stubber.add_response(
            "list_addons",
            {"addons": ["kube-proxy"]},
            {"clusterName": "prod-eks", "nextToken": "token-addons-2"},
        )
        # describe_addon for kube-proxy (page 2)
        stubber.add_response(
            "describe_addon",
            {
                "addon": {
                    "addonName": "kube-proxy",
                    "addonVersion": "v1.30.0-eksbuild.1",
                    "status": "ACTIVE",
                }
            },
            {"clusterName": "prod-eks", "addonName": "kube-proxy"},
        )

        addons = provider.list_provider_addons()
        stubber.assert_no_pending_responses()

        assert len(addons) == 3
        for addon in addons:
            assert isinstance(addon, AddonInfo)
            assert addon.managed_by == "eks-addon"
            assert addon.namespace == "kube-system"

        assert addons[0].name == "vpc-cni"
        assert addons[0].version == "v1.18.1-eksbuild.1"
        assert addons[1].name == "coredns"
        assert addons[1].version == "v1.11.1-eksbuild.4"
        assert addons[2].name == "kube-proxy"
        assert addons[2].version == "v1.30.0-eksbuild.1"


def test_compatible_addon_versions_filtering_and_caching(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """compatible_addon_versions correctly filters matching k8s versions and caches results."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_response(
            "describe_addon_versions",
            {
                "addons": [
                    {
                        "addonName": "vpc-cni",
                        "addonVersions": [
                            {
                                "addonVersion": "v1.18.3-eksbuild.1",
                                "compatibilities": [
                                    {"clusterVersion": "1.31"},
                                    {"clusterVersion": "1.30"},
                                ],
                            },
                            {
                                "addonVersion": "v1.17.0-eksbuild.1",
                                "compatibilities": [
                                    {"clusterVersion": "1.29"},
                                    {"clusterVersion": "1.30"},
                                ],
                            },
                        ],
                    }
                ]
            },
            {"addonName": "vpc-cni", "kubernetesVersion": "1.31"},
        )

        compat = provider.compatible_addon_versions("vpc-cni", "1.31")
        assert compat == ["v1.18.3-eksbuild.1"]

        # Cache check: second call with same arguments does not invoke stubbed API
        compat_cached = provider.compatible_addon_versions("vpc-cni", "1.31")
        assert compat_cached == ["v1.18.3-eksbuild.1"]

        stubber.assert_no_pending_responses()


def test_non_fatal_errors_recorded(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """Non-fatal API errors in list_node_groups and list_provider_addons are appended to errors."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        # list_nodegroups succeeds with 1 group, but describe_nodegroup fails
        stubber.add_response(
            "list_nodegroups",
            {"nodegroups": ["failing-ng"]},
            {"clusterName": "prod-eks"},
        )
        stubber.add_client_error("describe_nodegroup", "InternalServerError")

        # list_addons succeeds with 1 addon, but describe_addon fails
        stubber.add_response(
            "list_addons",
            {"addons": ["failing-addon"]},
            {"clusterName": "prod-eks"},
        )
        stubber.add_client_error("describe_addon", "AccessDeniedException")

        groups = provider.list_node_groups()
        addons = provider.list_provider_addons()

        stubber.assert_no_pending_responses()

        assert groups == []
        assert addons == []
        assert len(provider.errors) == 2
        assert "Failed to describe nodegroup 'failing-ng'" in provider.errors[0]
        assert "Failed to describe addon 'failing-addon'" in provider.errors[1]


def test_upgrade_insights_and_capacity_facts(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """upgrade_insights and capacity_facts return expected formats."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_response(
            "list_insights",
            {"insights": [{"id": "insight-1", "category": "UPGRADE_READINESS"}]},
            {"clusterName": "prod-eks"},
        )
        insights = provider.upgrade_insights("1.31")
        assert len(insights) == 1
        assert insights[0]["id"] == "insight-1"
        stubber.assert_no_pending_responses()

    facts = provider.capacity_facts()
    assert facts == {}


def test_k8s_api_client_delegation(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """k8s_api_client delegates to build_k8s_api_client with provider credentials."""
    provider = EksProvider(test_settings, session=mock_session)

    with patch("kua.providers.eks.provider.build_k8s_api_client") as mock_build:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        client = provider.k8s_api_client()
        mock_build.assert_called_once_with(mock_session, "prod-eks", "us-west-2")
        assert client == mock_client


def test_eks_provider_init_default_session(test_settings: KuaSettings) -> None:
    """EksProvider initializes default session via make_boto_session if session is omitted."""
    with patch("kua.providers.eks.provider.make_boto_session") as mock_make_session:
        fake_session = MagicMock()
        mock_make_session.return_value = fake_session
        provider = EksProvider(test_settings)
        mock_make_session.assert_called_once_with(
            region="us-west-2",
            role_arn=None,
        )
        assert provider.session == fake_session


def test_node_groups_windows_bottlerocket_and_lt_variants(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """list_node_groups detects Windows and Bottlerocket OS and handles launch template shapes."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_response(
            "list_nodegroups",
            {"nodegroups": ["ng-win", "ng-bottle"]},
            {"clusterName": "prod-eks"},
        )
        # ng-win with string launchTemplate
        stubber.add_response(
            "describe_nodegroup",
            {
                "nodegroup": {
                    "nodegroupName": "ng-win",
                    "amiType": "WINDOWS_CORE_2022_x86_64",
                    "launchTemplate": {"id": "lt-direct-id"},
                }
            },
            {"clusterName": "prod-eks", "nodegroupName": "ng-win"},
        )
        # ng-bottle with name-only launch template
        stubber.add_response(
            "describe_nodegroup",
            {
                "nodegroup": {
                    "nodegroupName": "ng-bottle",
                    "amiType": "BOTTLEROCKET_x86_64",
                    "launchTemplate": {"name": "lt-no-ver"},
                }
            },
            {"clusterName": "prod-eks", "nodegroupName": "ng-bottle"},
        )

        groups = provider.list_node_groups()
        stubber.assert_no_pending_responses()

        assert len(groups) == 2
        assert groups[0].os == "windows"
        assert groups[0].launch_template == "lt-direct-id"
        assert groups[1].os == "bottlerocket"
        assert groups[1].launch_template == "lt-no-ver"


def test_list_provider_addons_custom_namespace(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """list_provider_addons extracts custom namespaceConfig when present."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_response(
            "list_addons",
            {"addons": ["custom-addon"]},
            {"clusterName": "prod-eks"},
        )
        stubber.add_response(
            "describe_addon",
            {
                "addon": {
                    "addonName": "custom-addon",
                    "addonVersion": "v1.0.0",
                    "namespaceConfig": {"namespace": "custom-system"},
                }
            },
            {"clusterName": "prod-eks", "addonName": "custom-addon"},
        )

        addons = provider.list_provider_addons()
        stubber.assert_no_pending_responses()

        assert len(addons) == 1
        assert addons[0].namespace == "custom-system"


def test_upgrade_insights_errors_handled(
    test_settings: KuaSettings,
    mock_session: boto3.Session,
) -> None:
    """upgrade_insights handles ClientError and exceptions gracefully."""
    provider = EksProvider(test_settings, session=mock_session)

    with Stubber(provider.eks_client) as stubber:
        stubber.add_client_error("list_insights", "InternalServerError")
        insights = provider.upgrade_insights("1.31")
        assert insights == []
        assert any("Failed to retrieve upgrade insights" in e for e in provider.errors)
