"""Compute type detection and classification for EKS clusters."""

import re
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Literal

import boto3
from botocore.exceptions import ClientError
from kubernetes.client import (
    ApiClient,
    ApiException,
    ApiextensionsV1Api,
    CoreV1Api,
)

from kua.core.models import NodeGroupInfo
from kua.core.versions import MinorVersion


@dataclass(frozen=True)
class NodeClassification:
    """Classified compute attributes for a single Kubernetes Node."""

    group_name: str
    kind: Literal["managed", "self_managed", "karpenter", "fargate"]
    os_family: Literal["linux", "windows", "bottlerocket", "unknown"]
    kubelet_version: str
    az: str | None
    instance_type: str | None
    auto_mode: bool = False


def _get_field(obj: Any, field_name: str, default: Any = None) -> Any:
    """Extract attribute or dict key gracefully."""
    if isinstance(obj, dict):
        return obj.get(field_name, default)
    return getattr(obj, field_name, default)


def extract_instance_id(provider_id: str | None) -> str | None:
    """Extract EC2 instance ID from providerID string.

    Examples:
        'aws:///us-west-2a/i-0123456789abcdef0' -> 'i-0123456789abcdef0'
        'i-0123456789abcdef0' -> 'i-0123456789abcdef0'
    """
    if not provider_id:
        return None
    match = re.search(r"\b(i-[0-9a-fA-F]+)\b", provider_id)
    if match:
        return match.group(1)
    return None


def resolve_asg_names(
    session: boto3.Session,
    region: str,
    instance_ids: list[str],
) -> dict[str, str]:
    """Look up EC2 Auto Scaling Group names for given instance IDs.

    Args:
        session: Active boto3 session.
        region: AWS region.
        instance_ids: List of EC2 instance IDs.

    Returns:
        Mapping of instance_id -> ASG name.
    """
    if not instance_ids:
        return {}

    asg_map: dict[str, str] = {}
    ec2 = session.client("ec2", region_name=region)

    chunk_size = 100
    for i in range(0, len(instance_ids), chunk_size):
        chunk = instance_ids[i : i + chunk_size]
        with suppress(ClientError):
            resp = ec2.describe_instances(InstanceIds=chunk)
            for reservation in resp.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    inst_id = instance.get("InstanceId")
                    if not inst_id:
                        continue
                    tags = instance.get("Tags", [])
                    for tag in tags:
                        if tag.get("Key") == "aws:autoscaling:groupName":
                            asg_map[inst_id] = tag.get("Value", "unknown")
                            break

    return asg_map


def classify_node(
    node: Any,
    asg_map: dict[str, str] | None = None,
) -> NodeClassification:
    """Classify a Kubernetes Node by compute architecture, OS, version, and location.

    Classification order:
    1. EKS Auto Mode: 'eks.amazonaws.com/compute-type' == 'auto' -> managed, 'auto-mode'
    2. Fargate: 'eks.amazonaws.com/compute-type' == 'fargate' -> fargate, 'fargate:<profile>'
    3. Managed: 'eks.amazonaws.com/nodegroup' label present -> managed, label value
    4. Karpenter: 'karpenter.sh/nodepool' or 'karpenter.sh/provisioner-name' -> karpenter
    5. Self-managed: 'alpha.eksctl.io/nodegroup-name' label, or ASG name from EC2, or 'unknown'

    Args:
        node: Kubernetes V1Node object or dict.
        asg_map: Optional pre-resolved instance_id -> ASG name mapping.

    Returns:
        NodeClassification instance.
    """
    metadata = _get_field(node, "metadata") or {}
    labels: dict[str, str] = _get_field(metadata, "labels") or {}

    spec = _get_field(node, "spec") or {}
    provider_id: str | None = _get_field(spec, "provider_id") or _get_field(spec, "providerID")

    status = _get_field(node, "status") or {}
    node_info = _get_field(status, "node_info") or _get_field(status, "nodeInfo") or {}

    # 1. Operating System
    raw_os_val = (
        _get_field(node_info, "operating_system") or _get_field(node_info, "operatingSystem") or ""
    )
    raw_os = str(raw_os_val).lower()
    raw_os_image = str(_get_field(node_info, "os_image") or _get_field(node_info, "osImage") or "")

    os_family: Literal["linux", "windows", "bottlerocket", "unknown"] = "linux"
    if raw_os == "windows":
        os_family = "windows"
    elif "bottlerocket" in raw_os_image.lower():
        os_family = "bottlerocket"

    # 2. Kubelet version
    raw_kube_val = (
        _get_field(node_info, "kubelet_version") or _get_field(node_info, "kubeletVersion") or ""
    )
    raw_kubelet = str(raw_kube_val)
    try:
        kubelet_version = str(MinorVersion.parse(raw_kubelet))
    except Exception:
        kubelet_version = raw_kubelet or "unknown"

    # 3. Location & Hardware
    az: str | None = labels.get("topology.kubernetes.io/zone") or labels.get(
        "failure-domain.beta.kubernetes.io/zone"
    )
    instance_type: str | None = labels.get("node.kubernetes.io/instance-type") or labels.get(
        "beta.kubernetes.io/instance-type"
    )

    # 4. Compute Architecture Classification
    compute_type = labels.get("eks.amazonaws.com/compute-type")
    if compute_type == "auto":
        return NodeClassification(
            group_name="auto-mode",
            kind="managed",
            os_family=os_family,
            kubelet_version=kubelet_version,
            az=az,
            instance_type=instance_type,
            auto_mode=True,
        )

    if compute_type == "fargate":
        profile = labels.get("eks.amazonaws.com/fargate-profile") or "unknown"
        return NodeClassification(
            group_name=f"fargate:{profile}",
            kind="fargate",
            os_family=os_family,
            kubelet_version=kubelet_version,
            az=az,
            instance_type=instance_type,
        )

    if "eks.amazonaws.com/nodegroup" in labels:
        group_name = labels["eks.amazonaws.com/nodegroup"]
        return NodeClassification(
            group_name=group_name,
            kind="managed",
            os_family=os_family,
            kubelet_version=kubelet_version,
            az=az,
            instance_type=instance_type,
        )

    karpenter_pool = labels.get("karpenter.sh/nodepool") or labels.get(
        "karpenter.sh/provisioner-name"
    )
    if karpenter_pool:
        return NodeClassification(
            group_name=f"karpenter:{karpenter_pool}",
            kind="karpenter",
            os_family=os_family,
            kubelet_version=kubelet_version,
            az=az,
            instance_type=instance_type,
        )

    # Self-managed fallback
    if "alpha.eksctl.io/nodegroup-name" in labels:
        asg_name = labels["alpha.eksctl.io/nodegroup-name"]
    else:
        inst_id = extract_instance_id(provider_id)
        asg_name = (asg_map.get(inst_id) if (asg_map and inst_id) else None) or "unknown"

    return NodeClassification(
        group_name=asg_name,
        kind="self_managed",
        os_family=os_family,
        kubelet_version=kubelet_version,
        az=az,
        instance_type=instance_type,
    )


def detect_karpenter_crds(api_client: ApiClient) -> dict[str, Any]:
    """Detect whether Karpenter CRDs are installed in the cluster.

    Args:
        api_client: Authenticated Kubernetes ApiClient.

    Returns:
        Dict containing installed flag and CRD name if detected.
    """
    crd_api = ApiextensionsV1Api(api_client)
    for crd_name in ("nodepools.karpenter.sh", "provisioners.karpenter.sh"):
        try:
            crd_api.read_custom_resource_definition(name=crd_name)
            return {"installed": True, "crd": crd_name}
        except ApiException as e:
            if e.status == 404:
                continue
            break
        except Exception:
            break

    return {"installed": False, "crd": None}


def list_cluster_fargate_profiles(eks_client: Any, cluster_name: str) -> list[str]:
    """List all Fargate profile names configured for the EKS cluster.

    Args:
        eks_client: boto3 EKS client.
        cluster_name: Target cluster name.

    Returns:
        List of Fargate profile names.
    """
    profiles: list[str] = []
    try:
        paginator = eks_client.get_paginator("list_fargate_profiles")
        for page in paginator.paginate(clusterName=cluster_name):
            profiles.extend(page.get("fargateProfileNames", []))
    except (ClientError, Exception):
        with suppress(ClientError, Exception):
            resp = eks_client.list_fargate_profiles(clusterName=cluster_name)
            profiles.extend(resp.get("fargateProfileNames", []))
    return profiles


def list_cluster_nodes(api_client: ApiClient, limit: int = 100) -> list[Any]:
    """List all Node objects from Kubernetes API using pagination.

    Args:
        api_client: Authenticated Kubernetes ApiClient.
        limit: Page size limit.

    Returns:
        List of Kubernetes Node objects.
    """
    core_v1 = CoreV1Api(api_client)
    nodes: list[Any] = []
    _continue: str | None = None

    while True:
        kwargs: dict[str, Any] = {"limit": limit}
        if _continue:
            kwargs["_continue"] = _continue

        resp = core_v1.list_node(**kwargs)
        items = _get_field(resp, "items") or []
        nodes.extend(items)

        metadata = _get_field(resp, "metadata")
        _continue = _get_field(metadata, "_continue") if metadata else None
        if not _continue:
            break

    return nodes


def discover_compute_inventory(
    managed_groups: list[NodeGroupInfo],
    nodes: list[Any],
    fargate_profiles: list[str] | None = None,
    asg_map: dict[str, str] | None = None,
    karpenter_evidence: dict[str, Any] | None = None,
) -> tuple[list[NodeGroupInfo], dict[str, Any]]:
    """Merge managed node group facts with live Node objects to produce complete inventory.

    Args:
        managed_groups: Managed node groups retrieved from EKS API.
        nodes: Live Kubernetes Node objects.
        fargate_profiles: Optional list of Fargate profile names from EKS API.
        asg_map: Optional mapping of instance ID to ASG name for self-managed nodes.
        karpenter_evidence: Optional Karpenter CRD detection evidence.

    Returns:
        Tuple of (complete list of NodeGroupInfo, compute_evidence dict).
    """
    grouped_classifications: dict[str, list[NodeClassification]] = {}
    has_auto_mode = False

    for node in nodes:
        classification = classify_node(node, asg_map=asg_map)
        grouped_classifications.setdefault(classification.group_name, []).append(classification)
        if classification.auto_mode:
            has_auto_mode = True

    managed_map: dict[str, NodeGroupInfo] = {ng.name: ng for ng in managed_groups}
    merged_results: list[NodeGroupInfo] = []

    # 1. Update managed node groups with node versions and AZs
    for ng_name, ng in managed_map.items():
        node_list = grouped_classifications.pop(ng_name, [])
        if node_list:
            versions = Counter(n.kubelet_version for n in node_list)
            discovered_azs = sorted(list({n.az for n in node_list if n.az}))
            discovered_insts = sorted(list({n.instance_type for n in node_list if n.instance_type}))

            all_azs = sorted(list(set(ng.availability_zones + discovered_azs)))
            all_insts = sorted(list(set(ng.instance_types + discovered_insts)))

            updated_ng = ng.model_copy(
                update={
                    "kubelet_versions": dict(versions),
                    "availability_zones": all_azs,
                    "instance_types": all_insts,
                }
            )
            merged_results.append(updated_ng)
        else:
            merged_results.append(ng)

    # 2. Build NodeGroupInfo for non-managed or unmapped groups
    for group_name, node_list in sorted(grouped_classifications.items()):
        first = node_list[0]
        versions = Counter(n.kubelet_version for n in node_list)
        discovered_azs = sorted(list({n.az for n in node_list if n.az}))
        discovered_insts = sorted(list({n.instance_type for n in node_list if n.instance_type}))

        merged_results.append(
            NodeGroupInfo(
                name=group_name,
                kind=first.kind,
                kubelet_versions=dict(versions),
                os=first.os_family,
                desired=len(node_list),
                instance_types=discovered_insts,
                availability_zones=discovered_azs,
            )
        )

    # 3. Add any Fargate profiles that have 0 running nodes
    if fargate_profiles:
        existing_fargate_groups = {ng.name for ng in merged_results if ng.kind == "fargate"}
        for profile in sorted(fargate_profiles):
            expected_group_name = f"fargate:{profile}"
            if expected_group_name not in existing_fargate_groups:
                merged_results.append(
                    NodeGroupInfo(
                        name=expected_group_name,
                        kind="fargate",
                        kubelet_versions={},
                        os="linux",
                        desired=0,
                    )
                )

    compute_evidence: dict[str, Any] = {
        "node_count": len(nodes),
        "auto_mode": has_auto_mode,
        "fargate_profiles": fargate_profiles or [],
        "karpenter": karpenter_evidence or {"installed": False, "crd": None},
    }

    return merged_results, compute_evidence
