"""Amazon EKS infrastructure provider and inventory collector."""

from typing import Any, Literal

import boto3
from botocore.exceptions import ClientError
from kubernetes.client import ApiClient

from kua.config.settings import KuaSettings
from kua.core.errors import CollectorError
from kua.core.models import AddonInfo, ClusterRef, NodeGroupInfo
from kua.core.versions import MinorVersion
from kua.providers.base import Provider
from kua.providers.eks.auth import build_k8s_api_client
from kua.providers.eks.compute import (
    _get_field,
    detect_karpenter_crds,
    discover_compute_inventory,
    extract_instance_id,
    list_cluster_fargate_profiles,
    list_cluster_nodes,
    resolve_asg_names,
)
from kua.providers.eks.session import caller_identity, make_boto_session


class EksProvider(Provider):
    """EKS implementation of the Provider protocol for cluster facts and operations."""

    name: str = "eks"

    def __init__(
        self,
        settings: KuaSettings,
        session: boto3.Session | None = None,
        k8s_client: ApiClient | None = None,
        auto_k8s: bool | None = None,
    ) -> None:
        """Initialize the EKS provider with configuration and an optional boto3 session.

        Args:
            settings: Active KuaSettings.
            session: Optional pre-configured boto3.Session. If None, created via make_boto_session.
            k8s_client: Optional pre-configured Kubernetes ApiClient.
            auto_k8s: Whether to automatically construct a Kubernetes ApiClient if none provided.
                      Defaults to True when session is None, False when session is provided.
        """
        self.settings = settings
        self.cluster_name = settings.cluster.name
        self.region = settings.cluster.region
        self.account_id = settings.cluster.account_id
        self._k8s_client = k8s_client
        self._auto_k8s = auto_k8s if auto_k8s is not None else (session is None)

        if session is not None:
            self.session = session
        else:
            self.session = make_boto_session(
                region=self.region,
                role_arn=settings.cluster.role_arn,
            )

        self.eks_client = self.session.client("eks", region_name=self.region)
        self.errors: list[str] = []
        self._cluster_describe_cache: dict[str, Any] | None = None
        self._addon_compat_cache: dict[tuple[str, str], list[str]] = {}
        self.compute_evidence: dict[str, Any] = {}

    def _describe_cluster(self) -> dict[str, Any]:
        """Fetch and cache EKS describe_cluster output."""
        if self._cluster_describe_cache is None:
            try:
                resp = self.eks_client.describe_cluster(name=self.cluster_name)
                self._cluster_describe_cache = dict(resp.get("cluster", {}))
            except ClientError as e:
                self.errors.append(f"Failed to describe EKS cluster '{self.cluster_name}': {e}")
                self._cluster_describe_cache = {}
        return self._cluster_describe_cache if self._cluster_describe_cache is not None else {}

    def cluster_ref(self) -> ClusterRef:
        """Return the cluster identity and location reference."""
        account_id = self.account_id
        if not account_id:
            try:
                ident = caller_identity(self.session)
                account_id = ident.get("Account") or None
            except Exception:
                account_id = None

        return ClusterRef(
            provider="eks",
            name=self.cluster_name,
            region=self.region,
            account_id=account_id,
        )

    def control_plane_version(self) -> str:
        """Return the current normalized control plane minor version (e.g. '1.30')."""
        cluster = self._describe_cluster()
        raw_version = cluster.get("version")
        if not raw_version:
            raise CollectorError(
                f"Control plane version not found for EKS cluster '{self.cluster_name}'"
            )
        try:
            return str(MinorVersion.parse(raw_version))
        except Exception as e:
            self.errors.append(f"Failed to parse control plane version '{raw_version}': {e}")
            return str(raw_version)

    def platform_version(self) -> str | None:
        """Return provider platform version (e.g. 'eks.1'), if available."""
        cluster = self._describe_cluster()
        val = cluster.get("platformVersion")
        return str(val) if val else None

    def list_node_groups(
        self,
        k8s_client: ApiClient | None = None,
    ) -> list[NodeGroupInfo]:
        """List and classify node groups across compute architectures and pools."""
        paginator = self.eks_client.get_paginator("list_nodegroups")
        managed_groups: list[NodeGroupInfo] = []

        try:
            pages = paginator.paginate(clusterName=self.cluster_name)
            for page in pages:
                for ng_name in page.get("nodegroups", []):
                    try:
                        resp = self.eks_client.describe_nodegroup(
                            clusterName=self.cluster_name,
                            nodegroupName=ng_name,
                        )
                        ng = resp.get("nodegroup", {})
                        ami_type = ng.get("amiType")
                        custom_ami = ami_type == "CUSTOM"

                        lt = ng.get("launchTemplate")
                        lt_str: str | None = None
                        if lt and isinstance(lt, dict):
                            name_or_id = lt.get("name") or lt.get("id")
                            ver = lt.get("version")
                            if name_or_id and ver:
                                lt_str = f"{name_or_id}:{ver}"
                            elif name_or_id:
                                lt_str = str(name_or_id)
                        elif lt:
                            lt_str = str(lt)

                        scaling = ng.get("scalingConfig", {})
                        desired = scaling.get("desiredSize")
                        min_size = scaling.get("minSize")
                        max_size = scaling.get("maxSize")
                        subnets = list(ng.get("subnets", []))
                        instance_types = list(ng.get("instanceTypes", []))

                        os_family: Literal["linux", "windows", "bottlerocket", "unknown"] = "linux"
                        if ami_type:
                            ami_upper = str(ami_type).upper()
                            if "WINDOWS" in ami_upper:
                                os_family = "windows"
                            elif "BOTTLEROCKET" in ami_upper:
                                os_family = "bottlerocket"

                        managed_groups.append(
                            NodeGroupInfo(
                                name=ng_name,
                                kind="managed",
                                kubelet_versions={},
                                os=os_family,
                                ami_type=ami_type,
                                custom_ami=custom_ami,
                                launch_template=lt_str,
                                desired=desired,
                                min=min_size,
                                max=max_size,
                                subnets=subnets,
                                instance_types=instance_types,
                                availability_zones=[],
                            )
                        )
                    except ClientError as e:
                        self.errors.append(f"Failed to describe nodegroup '{ng_name}': {e}")
        except ClientError as e:
            self.errors.append(f"Failed to list EKS nodegroups: {e}")

        # Resolve Kubernetes client for live node classification
        client = k8s_client or self._k8s_client
        if client is None and self._auto_k8s:
            try:
                client = self.k8s_api_client()
            except Exception as e:
                self.errors.append(f"Failed to connect to Kubernetes API: {e}")

        if client is None:
            # If no Kubernetes API connection is available, return managed node groups
            return managed_groups

        # Discover Fargate profiles
        fargate_profiles: list[str] = []
        try:
            fargate_profiles = list_cluster_fargate_profiles(
                self.eks_client,
                self.cluster_name,
            )
        except Exception as e:
            self.errors.append(f"Failed to list Fargate profiles: {e}")

        # List live nodes
        nodes: list[Any] = []
        try:
            nodes = list_cluster_nodes(client)
        except Exception as e:
            self.errors.append(f"Failed to list Kubernetes nodes: {e}")

        # Detect Karpenter CRDs
        karpenter_evidence: dict[str, Any] = {"installed": False, "crd": None}
        try:
            karpenter_evidence = detect_karpenter_crds(client)
        except Exception as e:
            self.errors.append(f"Failed to detect Karpenter CRDs: {e}")

        # Identify self-managed instance IDs requiring ASG lookup
        unlabelled_instance_ids: list[str] = []
        for node in nodes:
            metadata = _get_field(node, "metadata") or {}
            labels = _get_field(metadata, "labels") or {}
            if (
                "eks.amazonaws.com/compute-type" not in labels
                and "eks.amazonaws.com/nodegroup" not in labels
                and "karpenter.sh/nodepool" not in labels
                and "karpenter.sh/provisioner-name" not in labels
                and "alpha.eksctl.io/nodegroup-name" not in labels
            ):
                spec = _get_field(node, "spec") or {}
                provider_id = _get_field(spec, "provider_id") or _get_field(spec, "providerID")
                inst_id = extract_instance_id(provider_id)
                if inst_id:
                    unlabelled_instance_ids.append(inst_id)

        asg_map: dict[str, str] = {}
        if unlabelled_instance_ids:
            try:
                asg_map = resolve_asg_names(
                    self.session,
                    self.region,
                    unlabelled_instance_ids,
                )
            except Exception as e:
                self.errors.append(f"Failed to resolve EC2 ASG names: {e}")

        # Merge managed node group facts with live nodes
        all_groups, evidence = discover_compute_inventory(
            managed_groups=managed_groups,
            nodes=nodes,
            fargate_profiles=fargate_profiles,
            asg_map=asg_map,
            karpenter_evidence=karpenter_evidence,
        )
        self.compute_evidence = evidence
        return all_groups

    def list_provider_addons(self) -> list[AddonInfo]:
        """List managed add-ons installed on the EKS cluster."""
        paginator = self.eks_client.get_paginator("list_addons")
        addons: list[AddonInfo] = []

        try:
            pages = paginator.paginate(clusterName=self.cluster_name)
            for page in pages:
                for addon_name in page.get("addons", []):
                    try:
                        resp = self.eks_client.describe_addon(
                            clusterName=self.cluster_name,
                            addonName=addon_name,
                        )
                        data = resp.get("addon", {})
                        addon_ver = str(data.get("addonVersion", "unknown"))
                        ns_config = data.get("namespaceConfig")
                        ns: str = (
                            str(ns_config.get("namespace"))
                            if isinstance(ns_config, dict) and ns_config.get("namespace")
                            else "kube-system"
                        )

                        addons.append(
                            AddonInfo(
                                name=addon_name,
                                version=addon_ver,
                                managed_by="eks-addon",
                                namespace=ns,
                            )
                        )
                    except ClientError as e:
                        self.errors.append(f"Failed to describe addon '{addon_name}': {e}")
        except ClientError as e:
            self.errors.append(f"Failed to list EKS addons: {e}")

        return addons

    def compatible_addon_versions(self, addon: str, k8s_version: str) -> list[str]:
        """List compatible versions of a managed add-on for a given Kubernetes minor version."""
        try:
            norm_k8s = str(MinorVersion.parse(k8s_version))
        except Exception:
            norm_k8s = k8s_version

        cache_key = (addon, norm_k8s)
        if cache_key in self._addon_compat_cache:
            return self._addon_compat_cache[cache_key]

        paginator = self.eks_client.get_paginator("describe_addon_versions")
        compatible: list[str] = []

        try:
            pages = paginator.paginate(addonName=addon, kubernetesVersion=k8s_version)
            for page in pages:
                for addon_entry in page.get("addons", []):
                    if addon_entry.get("addonName") != addon:
                        continue
                    for ver_entry in addon_entry.get("addonVersions", []):
                        ver_str = ver_entry.get("addonVersion")
                        if not ver_str:
                            continue

                        compat_list = ver_entry.get("compatibilities", [])
                        is_compat = False
                        if not compat_list:
                            # If no compatibilities matrix provided in response, trust API filter
                            is_compat = True
                        else:
                            for compat in compat_list:
                                cv = compat.get("clusterVersion")
                                if cv:
                                    try:
                                        cv_norm = str(MinorVersion.parse(cv))
                                    except Exception:
                                        cv_norm = cv
                                    if cv_norm == norm_k8s or cv == k8s_version:
                                        is_compat = True
                                        break

                        if is_compat and ver_str not in compatible:
                            compatible.append(ver_str)
        except ClientError as e:
            self.errors.append(
                f"Failed to describe addon versions for '{addon}' on k8s '{k8s_version}': {e}"
            )

        self._addon_compat_cache[cache_key] = compatible
        return compatible

    def upgrade_insights(self, target: str) -> list[dict[str, Any]]:
        """Retrieve EKS upgrade insights. May return [] if unsupported or none found."""
        try:
            if hasattr(self.eks_client, "list_insights"):
                resp = self.eks_client.list_insights(clusterName=self.cluster_name)
                insights_raw = resp.get("insights", [])
                insights: list[dict[str, Any]] = [dict(i) for i in insights_raw]
                return insights
        except ClientError as e:
            self.errors.append(
                f"Failed to retrieve upgrade insights for cluster '{self.cluster_name}': {e}"
            )
        except Exception as e:
            self.errors.append(f"Upgrade insights unavailable: {e}")
        return []

    def capacity_facts(self) -> dict[str, Any]:
        """Retrieve provider capacity, quota, and IP headroom facts (stub for V01-T14)."""
        return {}

    def k8s_api_client(self) -> ApiClient:
        """Construct and return an authenticated Kubernetes ApiClient."""
        return build_k8s_api_client(self.session, self.cluster_name, self.region)
