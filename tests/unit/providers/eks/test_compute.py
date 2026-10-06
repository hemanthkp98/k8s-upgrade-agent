"""Unit tests for compute type detection and classification in EKS clusters."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
from botocore.stub import Stubber
from kubernetes.client import (
    ApiClient,
    ApiException,
    V1Node,
    V1NodeList,
    V1ObjectMeta,
)

from kua.config.settings import ClusterConfig, KuaSettings
from kua.core.models import NodeGroupInfo
from kua.providers.eks.compute import (
    classify_node,
    detect_karpenter_crds,
    discover_compute_inventory,
    extract_instance_id,
    list_cluster_fargate_profiles,
    list_cluster_nodes,
    resolve_asg_names,
)
from kua.providers.eks.provider import EksProvider

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "nodes"


def _load_fixture(filename: str) -> list[dict]:
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


def test_extract_instance_id() -> None:
    """extract_instance_id correctly parses AWS provider IDs."""
    assert extract_instance_id("aws:///us-west-2a/i-0123456789abcdef0") == "i-0123456789abcdef0"
    assert extract_instance_id("i-0123456789abcdef0") == "i-0123456789abcdef0"
    assert extract_instance_id("aws:///us-west-2b/i-abcdef1234567890") == "i-abcdef1234567890"
    assert extract_instance_id(None) is None
    assert extract_instance_id("invalid-format") is None


def test_classify_managed_node_fixture() -> None:
    """Managed node fixture is classified with nodegroup name, linux OS, and normalized version."""
    nodes = _load_fixture("managed.json")
    classification = classify_node(nodes[0])

    assert classification.kind == "managed"
    assert classification.group_name == "mng-standard"
    assert classification.os_family == "linux"
    assert classification.kubelet_version == "1.30"
    assert classification.az == "us-west-2a"
    assert classification.instance_type == "m5.large"
    assert classification.auto_mode is False


def test_classify_karpenter_fixtures() -> None:
    """Karpenter v1 and legacy provisioner nodes are properly classified."""
    nodes = _load_fixture("karpenter.json")

    # Node 1: v1 nodepool
    c1 = classify_node(nodes[0])
    assert c1.kind == "karpenter"
    assert c1.group_name == "karpenter:default"
    assert c1.os_family == "linux"
    assert c1.kubelet_version == "1.30"
    assert c1.instance_type == "c5.xlarge"

    # Node 2: legacy provisioner
    c2 = classify_node(nodes[1])
    assert c2.kind == "karpenter"
    assert c2.group_name == "karpenter:legacy-pool"
    assert c2.os_family == "linux"
    assert c2.instance_type == "m5a.large"


def test_classify_fargate_fixture() -> None:
    """Fargate nodes are classified under fargate:<profile>."""
    nodes = _load_fixture("fargate.json")
    c = classify_node(nodes[0])

    assert c.kind == "fargate"
    assert c.group_name == "fargate:fp-workloads"
    assert c.os_family == "linux"
    assert c.kubelet_version == "1.30"


def test_classify_auto_mode_fixture() -> None:
    """EKS Auto Mode nodes are classified with group 'auto-mode' and auto_mode=True."""
    nodes = _load_fixture("auto_mode.json")
    c = classify_node(nodes[0])

    assert c.kind == "managed"
    assert c.group_name == "auto-mode"
    assert c.auto_mode is True
    assert c.os_family == "linux"
    assert c.instance_type == "m7i.large"


def test_classify_self_managed_fixtures() -> None:
    """Self-managed nodes detect eksctl label or resolve via ASG mapping."""
    nodes = _load_fixture("self_managed.json")

    # Node 1: with alpha.eksctl.io/nodegroup-name
    c1 = classify_node(nodes[0])
    assert c1.kind == "self_managed"
    assert c1.group_name == "self-managed-eksctl"
    assert c1.instance_type == "t3.large"

    # Node 2: without label, unmapped
    c2 = classify_node(nodes[1])
    assert c2.kind == "self_managed"
    assert c2.group_name == "unknown"

    # Node 2: with ASG mapping
    asg_map = {"i-07777777777777777": "asg-prod-nodes"}
    c2_mapped = classify_node(nodes[1], asg_map=asg_map)
    assert c2_mapped.kind == "self_managed"
    assert c2_mapped.group_name == "asg-prod-nodes"


def test_classify_windows_and_bottlerocket_fixtures() -> None:
    """Operating systems Windows and Bottlerocket are detected accurately."""
    win_nodes = _load_fixture("windows.json")
    c_win = classify_node(win_nodes[0])
    assert c_win.os_family == "windows"
    assert c_win.group_name == "mng-windows"

    br_nodes = _load_fixture("bottlerocket.json")
    c_br = classify_node(br_nodes[0])
    assert c_br.os_family == "bottlerocket"
    assert c_br.group_name == "mng-bottlerocket"


def test_mixed_version_aggregation_in_inventory() -> None:
    """Multiple nodes in the same nodegroup aggregate distinct kubelet versions."""
    nodes = _load_fixture("mixed_version.json")
    managed_groups = [
        NodeGroupInfo(
            name="mng-mixed",
            kind="managed",
            kubelet_versions={},
            os="linux",
            desired=2,
        )
    ]

    merged, evidence = discover_compute_inventory(
        managed_groups=managed_groups,
        nodes=nodes,
    )

    assert len(merged) == 1
    ng = merged[0]
    assert ng.name == "mng-mixed"
    assert ng.kubelet_versions == {"1.29": 1, "1.30": 1}
    assert ng.availability_zones == ["us-west-2a", "us-west-2b"]
    assert evidence["node_count"] == 2


def test_resolve_asg_names_with_ec2_stub() -> None:
    """resolve_asg_names queries EC2 describe_instances and parses ASG name tag."""
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-west-2",
    )
    ec2_client = session.client("ec2")

    with Stubber(ec2_client) as stubber, patch.object(session, "client", return_value=ec2_client):
        stubber.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-1234567890abcdef0",
                                "Tags": [
                                    {
                                        "Key": "aws:autoscaling:groupName",
                                        "Value": "k8s-worker-asg",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
            {"InstanceIds": ["i-1234567890abcdef0"]},
        )

        res = resolve_asg_names(session, "us-west-2", ["i-1234567890abcdef0"])
        assert res == {"i-1234567890abcdef0": "k8s-worker-asg"}
        stubber.assert_no_pending_responses()


def test_detect_karpenter_crds() -> None:
    """detect_karpenter_crds identifies installed CRD or reports absent on 404."""
    mock_api_client = MagicMock(spec=ApiClient)

    # 1. Detected nodepools.karpenter.sh
    with patch("kua.providers.eks.compute.ApiextensionsV1Api") as mock_crd_cls:
        mock_crd_api = MagicMock()
        mock_crd_cls.return_value = mock_crd_api
        mock_crd_api.read_custom_resource_definition.return_value = MagicMock()

        res = detect_karpenter_crds(mock_api_client)
        assert res["installed"] is True
        assert res["crd"] == "nodepools.karpenter.sh"

    # 2. Both absent (404)
    with patch("kua.providers.eks.compute.ApiextensionsV1Api") as mock_crd_cls:
        mock_crd_api = MagicMock()
        mock_crd_cls.return_value = mock_crd_api
        mock_crd_api.read_custom_resource_definition.side_effect = ApiException(status=404)

        res = detect_karpenter_crds(mock_api_client)
        assert res["installed"] is False
        assert res["crd"] is None


def test_list_cluster_fargate_profiles() -> None:
    """list_cluster_fargate_profiles returns profile names from EKS API."""
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-west-2",
    )
    eks_client = session.client("eks")

    with Stubber(eks_client) as stubber:
        stubber.add_response(
            "list_fargate_profiles",
            {"fargateProfileNames": ["fp-system", "fp-apps"]},
            {"clusterName": "test-cluster"},
        )

        profiles = list_cluster_fargate_profiles(eks_client, "test-cluster")
        assert profiles == ["fp-system", "fp-apps"]
        stubber.assert_no_pending_responses()


def test_list_cluster_nodes_pagination() -> None:
    """list_cluster_nodes paginates across multiple pages using _continue token."""
    mock_api_client = MagicMock(spec=ApiClient)

    with patch("kua.providers.eks.compute.CoreV1Api") as mock_core_cls:
        mock_core = MagicMock()
        mock_core_cls.return_value = mock_core

        # Page 1
        page1 = V1NodeList(
            items=[V1Node(metadata=V1ObjectMeta(name="node-1"))],
            metadata=MagicMock(_continue="token-page-2"),
        )
        # Page 2
        page2 = V1NodeList(
            items=[V1Node(metadata=V1ObjectMeta(name="node-2"))],
            metadata=MagicMock(_continue=None),
        )

        mock_core.list_node.side_effect = [page1, page2]

        nodes = list_cluster_nodes(mock_api_client, limit=50)
        assert len(nodes) == 2
        assert nodes[0].metadata.name == "node-1"
        assert nodes[1].metadata.name == "node-2"


def test_discover_compute_inventory_with_empty_fargate_profile() -> None:
    """discover_compute_inventory creates 0-desired NodeGroupInfo for Fargate profiles."""
    managed_groups = [
        NodeGroupInfo(
            name="mng-1",
            kind="managed",
            kubelet_versions={},
            os="linux",
        )
    ]
    fargate_profiles = ["fp-empty"]

    merged, _evidence = discover_compute_inventory(
        managed_groups=managed_groups,
        nodes=[],
        fargate_profiles=fargate_profiles,
    )

    assert len(merged) == 2
    fargate_ng = next(ng for ng in merged if ng.kind == "fargate")
    assert fargate_ng.name == "fargate:fp-empty"
    assert fargate_ng.desired == 0
    assert fargate_ng.kubelet_versions == {}


def test_eks_provider_integration_with_k8s_client() -> None:
    """EksProvider.list_node_groups integrates EKS API and Kubernetes node inventory."""
    mock_session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-west-2",
    )
    settings = KuaSettings(
        cluster=ClusterConfig(provider="eks", name="prod-eks", region="us-west-2")
    )
    mock_k8s_client = MagicMock(spec=ApiClient)
    provider = EksProvider(settings, session=mock_session, k8s_client=mock_k8s_client)

    nodes = _load_fixture("managed.json") + _load_fixture("karpenter.json")

    with (
        Stubber(provider.eks_client) as stubber,
        patch(
            "kua.providers.eks.provider.list_cluster_fargate_profiles",
            return_value=["fp-workloads"],
        ),
        patch("kua.providers.eks.provider.list_cluster_nodes", return_value=nodes),
        patch(
            "kua.providers.eks.provider.detect_karpenter_crds",
            return_value={"installed": True, "crd": "nodepools.karpenter.sh"},
        ),
    ):
        stubber.add_response(
            "list_nodegroups",
            {"nodegroups": ["mng-standard"]},
            {"clusterName": "prod-eks"},
        )
        stubber.add_response(
            "describe_nodegroup",
            {
                "nodegroup": {
                    "nodegroupName": "mng-standard",
                    "amiType": "AL2023_x86_64_STANDARD",
                    "scalingConfig": {"minSize": 1, "maxSize": 5, "desiredSize": 1},
                    "subnets": ["subnet-1"],
                    "instanceTypes": ["m5.large"],
                }
            },
            {"clusterName": "prod-eks", "nodegroupName": "mng-standard"},
        )

        groups = provider.list_node_groups()
        stubber.assert_no_pending_responses()

        # mng-standard + karpenter:default + karpenter:legacy-pool + fargate:fp-workloads = 4
        assert len(groups) == 4

        mng = next(g for g in groups if g.name == "mng-standard")
        assert mng.kubelet_versions == {"1.30": 1}

        karp1 = next(g for g in groups if g.name == "karpenter:default")
        assert karp1.kind == "karpenter"
        assert karp1.kubelet_versions == {"1.30": 1}

        karp2 = next(g for g in groups if g.name == "karpenter:legacy-pool")
        assert karp2.kind == "karpenter"

        fargate = next(g for g in groups if g.name == "fargate:fp-workloads")
        assert fargate.kind == "fargate"
        assert fargate.desired == 0

        assert provider.compute_evidence["auto_mode"] is False
        assert provider.compute_evidence["karpenter"]["installed"] is True
        assert provider.compute_evidence["node_count"] == 3
