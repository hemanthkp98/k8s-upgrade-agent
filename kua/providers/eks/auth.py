"""Authentication and Kubernetes client factory for Amazon EKS."""

import atexit
import base64
import contextlib
import os
import tempfile
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import kubernetes.client as k8s
import urllib3.exceptions
from botocore.exceptions import ClientError
from kubernetes.client.rest import ApiException

from kua.core.errors import AuthError

REQUIRED_PERMISSIONS: list[dict[str, Any]] = [
    {"name": "list nodes", "resource_attributes": {"verb": "list", "resource": "nodes"}},
    {"name": "list pods", "resource_attributes": {"verb": "list", "resource": "pods"}},
    {
        "name": "list deployments",
        "resource_attributes": {"verb": "list", "resource": "deployments", "group": "apps"},
    },
    {
        "name": "list statefulsets",
        "resource_attributes": {"verb": "list", "resource": "statefulsets", "group": "apps"},
    },
    {
        "name": "list daemonsets",
        "resource_attributes": {"verb": "list", "resource": "daemonsets", "group": "apps"},
    },
    {
        "name": "list pdbs",
        "resource_attributes": {
            "verb": "list",
            "resource": "poddisruptionbudgets",
            "group": "policy",
        },
    },
    {
        "name": "list namespaces",
        "resource_attributes": {"verb": "list", "resource": "namespaces"},
    },
    {
        "name": "list customresourcedefinitions",
        "resource_attributes": {
            "verb": "list",
            "resource": "customresourcedefinitions",
            "group": "apiextensions.k8s.io",
        },
    },
    {
        "name": "get /metrics",
        "non_resource_attributes": {"verb": "get", "path": "/metrics"},
    },
]


def get_eks_token(session: boto3.Session, cluster_name: str) -> tuple[str, datetime]:
    """Generate a pre-signed STS Bearer token for authenticating to an EKS cluster.

    This implements the authentication protocol used by `aws eks get-token`:
    1. Generates a pre-signed STS GetCallerIdentity URL valid for 60 seconds.
    2. Injects the required 'x-k8s-aws-id' header with the target cluster name before signing.
    3. Encodes the signed URL with base64 urlsafe encoding (stripped of '=' padding)
       prefixed with 'k8s-aws-v1.'.
    4. Sets token expiry to 14 minutes (STS tokens are valid for 15 minutes; refreshes early).

    Args:
        session: Active boto3.Session with credentials.
        cluster_name: EKS cluster identifier.

    Returns:
        Tuple of (token_string, expiry_utc_datetime).

    Raises:
        AuthError: If generating the token fails.
    """
    try:
        sts = session.client("sts")

        def _add_cluster_header(request: Any, **kwargs: Any) -> None:
            request.headers["x-k8s-aws-id"] = cluster_name

        sts.meta.events.register("before-sign.sts.GetCallerIdentity", _add_cluster_header)

        presigned_url = sts.generate_presigned_url(
            "get_caller_identity",
            Params={},
            ExpiresIn=60,
            HttpMethod="GET",
        )

        encoded_url = (
            base64.urlsafe_b64encode(presigned_url.encode("utf-8")).rstrip(b"=").decode("utf-8")
        )
        token = f"k8s-aws-v1.{encoded_url}"
        now = datetime.now(UTC)
        expiry = now + timedelta(minutes=14)
        return token, expiry
    except Exception as e:
        raise AuthError(f"Failed to generate EKS authentication token: {e}") from e


class TokenRefresher:
    """Callable refresh hook for Kubernetes Configuration to renew EKS token on expiration."""

    def __init__(
        self,
        session: boto3.Session,
        cluster_name: str,
        initial_expiry: datetime,
    ) -> None:
        self.session = session
        self.cluster_name = cluster_name
        self.token_expiry = initial_expiry

    def __call__(self, conf: Any) -> None:
        """Invoked by kubernetes Configuration before requests when token needs refresh."""
        now = datetime.now(UTC)
        if now >= self.token_expiry:
            token, expiry = get_eks_token(self.session, self.cluster_name)
            self.token_expiry = expiry
            conf.api_key["authorization"] = f"Bearer {token}"


def build_k8s_api_client(
    session: boto3.Session,
    cluster_name: str,
    region: str,
) -> k8s.ApiClient:
    """Build a configured Kubernetes ApiClient for an EKS cluster with token auto-refresh.

    Describes the cluster via AWS EKS API, extracts the API endpoint and certificate
    authority bundle, writes the CA to a temporary file (cleaned up on process exit),
    and initializes an ApiClient with an automatic bearer token refresh hook.

    Args:
        session: Active boto3.Session.
        cluster_name: Target EKS cluster name.
        region: AWS region.

    Returns:
        Configured kubernetes.client.ApiClient instance.

    Raises:
        AuthError: On missing IAM permissions (eks:DescribeCluster), missing cluster,
                   or connection issues.
    """
    eks = session.client("eks", region_name=region)
    try:
        response = eks.describe_cluster(name=cluster_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AccessDeniedException":
            raise AuthError(
                f"scanner role lacks eks:DescribeCluster permission on cluster '{cluster_name}'"
            ) from e
        raise AuthError(f"Failed to describe EKS cluster '{cluster_name}': {e}") from e

    cluster = response.get("cluster", {})
    endpoint = cluster.get("endpoint")
    if not endpoint:
        raise AuthError(f"EKS cluster '{cluster_name}' does not have an API server endpoint")

    ca_data_b64 = cluster.get("certificateAuthority", {}).get("data")
    if not ca_data_b64:
        raise AuthError(f"EKS cluster '{cluster_name}' missing certificate authority data")

    try:
        ca_bytes = base64.b64decode(ca_data_b64, validate=True)
    except Exception as e:
        raise AuthError(
            f"Invalid base64 certificate authority in cluster '{cluster_name}': {e}"
        ) from e

    # Write CA to temporary file and register deletion on exit
    ca_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix="kua-eks-ca-", suffix=".crt", delete=False
    )
    ca_file.write(ca_bytes)
    ca_file.flush()
    ca_file.close()

    def _cleanup_ca() -> None:
        with contextlib.suppress(OSError):
            os.remove(ca_file.name)

    atexit.register(_cleanup_ca)

    token, expiry = get_eks_token(session, cluster_name)
    conf = k8s.Configuration()
    conf.host = endpoint
    conf.ssl_ca_cert = ca_file.name
    conf.api_key = {"authorization": f"Bearer {token}"}
    conf.refresh_api_key_hook = TokenRefresher(
        session=session,
        cluster_name=cluster_name,
        initial_expiry=expiry,
    )
    return k8s.ApiClient(configuration=conf)


def check_k8s_access(api_client: k8s.ApiClient) -> list[str]:
    """Check required Kubernetes permissions using SelfSubjectAccessReview.

    Args:
        api_client: Configured Kubernetes ApiClient.

    Returns:
        List of missing permission descriptions (e.g. ['list nodes', 'get /metrics']).
        Returns an empty list if all required permissions are granted.

    Raises:
        AuthError: If authentication fails (HTTP 401) or cluster endpoint is unreachable/private.
    """
    auth_api = k8s.AuthorizationV1Api(api_client)
    missing: list[str] = []

    for perm in REQUIRED_PERMISSIONS:
        spec_kwargs: dict[str, Any] = {}
        if "resource_attributes" in perm:
            spec_kwargs["resource_attributes"] = k8s.V1ResourceAttributes(
                **perm["resource_attributes"]
            )
        elif "non_resource_attributes" in perm:
            spec_kwargs["non_resource_attributes"] = k8s.V1NonResourceAttributes(
                **perm["non_resource_attributes"]
            )

        body = k8s.V1SelfSubjectAccessReview(spec=k8s.V1SelfSubjectAccessReviewSpec(**spec_kwargs))

        try:
            resp = auth_api.create_self_subject_access_review(body=body)
            if not getattr(resp.status, "allowed", False):
                missing.append(perm["name"])
        except ApiException as e:
            if e.status == 401:
                raise AuthError(
                    "IAM principal not mapped: add an EKS access entry with "
                    "AmazonEKSViewPolicy or equivalent"
                ) from e
            raise AuthError(f"Kubernetes API error during access review: {e}") from e
        except (
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.MaxRetryError,
            urllib3.exceptions.TimeoutError,
            TimeoutError,
        ) as e:
            raise AuthError(
                "cluster endpoint is private; run kua from inside the VPC or "
                "enable public endpoint access for your IP"
            ) from e
        except Exception as e:
            raise AuthError(f"Unexpected error checking Kubernetes permissions: {e}") from e

    return missing
