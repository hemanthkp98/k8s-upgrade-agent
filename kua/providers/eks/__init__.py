"""EKS provider session, authentication, inventory, and compute utilities."""

from kua.providers.eks.auth import build_k8s_api_client, check_k8s_access, get_eks_token
from kua.providers.eks.compute import (
    NodeClassification,
    classify_node,
    detect_karpenter_crds,
    discover_compute_inventory,
    list_cluster_fargate_profiles,
    list_cluster_nodes,
    resolve_asg_names,
)
from kua.providers.eks.provider import EksProvider
from kua.providers.eks.session import caller_identity, make_boto_session

__all__ = [
    "EksProvider",
    "NodeClassification",
    "build_k8s_api_client",
    "caller_identity",
    "check_k8s_access",
    "classify_node",
    "detect_karpenter_crds",
    "discover_compute_inventory",
    "get_eks_token",
    "list_cluster_fargate_profiles",
    "list_cluster_nodes",
    "make_boto_session",
    "resolve_asg_names",
]
