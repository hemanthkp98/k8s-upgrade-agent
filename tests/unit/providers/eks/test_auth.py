"""Unit tests for EKS authentication and Kubernetes client factory."""

import base64
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import kubernetes.client as k8s
import pytest
import urllib3.exceptions
from botocore.stub import Stubber
from kubernetes.client.rest import ApiException
from moto import mock_aws

from kua.core.errors import AuthError
from kua.providers.eks.auth import build_k8s_api_client, check_k8s_access, get_eks_token


@mock_aws
def test_get_eks_token_format_and_headers() -> None:
    """get_eks_token generates a valid k8s-aws-v1 token containing signed cluster headers."""
    session = boto3.Session(region_name="us-west-2")
    cluster_name = "test-prod-cluster"

    token, expiry = get_eks_token(session, cluster_name)

    # 1. Prefix assertion
    assert token.startswith("k8s-aws-v1.")

    # 2. No padding
    raw_b64 = token.removeprefix("k8s-aws-v1.")
    assert not raw_b64.endswith("=")

    # 3. Decodes to signed STS URL
    # Add back padding if necessary for decoding
    padding = "=" * ((4 - len(raw_b64) % 4) % 4)
    decoded_url = base64.urlsafe_b64decode(raw_b64 + padding).decode("utf-8")

    parsed = urllib.parse.urlparse(decoded_url)
    params = urllib.parse.parse_qs(parsed.query)

    assert params.get("Action") == ["GetCallerIdentity"]
    assert "X-Amz-Signature" in params

    signed_headers = params.get("X-Amz-SignedHeaders", [""])[0].split(";")
    assert "x-k8s-aws-id" in signed_headers
    assert "host" in signed_headers

    # 4. Expiry is roughly now + 14 minutes
    now = datetime.now(UTC)
    diff = expiry - now
    assert 13 <= diff.total_seconds() / 60 <= 15


def test_build_k8s_api_client_success() -> None:
    """build_k8s_api_client constructs an ApiClient with host, CA cert file, and token."""
    session = boto3.Session(
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        region_name="us-west-2",
    )
    cluster_name = "eks-prod"
    region = "us-west-2"

    raw_ca = b"-----BEGIN CERTIFICATE-----\nFAKECERTDATA\n-----END CERTIFICATE-----"
    ca_b64 = base64.b64encode(raw_ca).decode("utf-8")
    endpoint = "https://123456789ABCDEF.gr7.us-west-2.eks.amazonaws.com"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_response(
        "describe_cluster",
        {
            "cluster": {
                "name": cluster_name,
                "endpoint": endpoint,
                "certificateAuthority": {"data": ca_b64},
            }
        },
        {"name": cluster_name},
    )

    # Intercept session.client("eks") to return stubbed client
    orig_client = session.client

    def mock_client(service_name: str, *args: object, **kwargs: object) -> object:
        if service_name == "eks":
            return eks
        return orig_client(service_name, *args, **kwargs)

    session.client = mock_client  # type: ignore[method-assign]

    with stubber:
        client = build_k8s_api_client(session, cluster_name, region)

    conf = client.configuration
    assert conf.host == endpoint
    assert conf.ssl_ca_cert is not None
    assert Path(conf.ssl_ca_cert).exists()
    assert Path(conf.ssl_ca_cert).read_bytes() == raw_ca
    assert conf.api_key["authorization"].startswith("Bearer k8s-aws-v1.")


def test_build_k8s_api_client_token_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """ApiClient refresh hook fetches a new token when current token has expired."""
    session = boto3.Session(
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        region_name="us-west-2",
    )
    cluster_name = "eks-refresh"
    region = "us-west-2"

    raw_ca = b"-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----"
    ca_b64 = base64.b64encode(raw_ca).decode("utf-8")
    endpoint = "https://refresh-cluster.eks.amazonaws.com"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_response(
        "describe_cluster",
        {
            "cluster": {
                "name": cluster_name,
                "endpoint": endpoint,
                "certificateAuthority": {"data": ca_b64},
            }
        },
        {"name": cluster_name},
    )

    orig_client = session.client
    session.client = lambda s, *a, **kw: eks if s == "eks" else orig_client(s, *a, **kw)  # type: ignore[method-assign]

    tokens_generated = ["token-1", "token-2"]

    def mock_get_eks_token(s: boto3.Session, c: str) -> tuple[str, datetime]:
        t = tokens_generated.pop(0)
        # Expired immediately for token-1 so hook triggers refresh
        return t, datetime.now(UTC) - timedelta(seconds=10)

    monkeypatch.setattr("kua.providers.eks.auth.get_eks_token", mock_get_eks_token)

    with stubber:
        client = build_k8s_api_client(session, cluster_name, region)

    assert client.configuration.api_key["authorization"] == "Bearer token-1"

    # Trigger hook
    client.configuration.refresh_api_key_hook(client.configuration)
    assert client.configuration.api_key["authorization"] == "Bearer token-2"


def test_build_k8s_api_client_access_denied() -> None:
    """build_k8s_api_client raises actionable AuthError when eks:DescribeCluster is denied."""
    session = boto3.Session(region_name="us-west-2")
    cluster_name = "eks-denied"
    region = "us-west-2"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_client_error(
        "describe_cluster",
        service_error_code="AccessDeniedException",
        service_message="User is not authorized to perform: eks:DescribeCluster",
        expected_params={"name": cluster_name},
    )

    orig_client1 = session.client
    session.client = lambda s, *a, **kw: eks if s == "eks" else orig_client1(s, *a, **kw)  # type: ignore[method-assign]

    with stubber, pytest.raises(AuthError) as exc_info:
        build_k8s_api_client(session, cluster_name, region)

    assert "scanner role lacks eks:DescribeCluster permission" in str(exc_info.value)


def test_build_k8s_api_client_missing_endpoint_or_ca() -> None:
    """Missing endpoint or certificateAuthority data raises AuthError."""
    session = boto3.Session(region_name="us-west-2")
    cluster_name = "eks-no-ep"
    region = "us-west-2"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_response(
        "describe_cluster",
        {"cluster": {"name": cluster_name, "endpoint": ""}},
        {"name": cluster_name},
    )
    orig_client2 = session.client
    session.client = lambda s, *a, **kw: eks if s == "eks" else orig_client2(s, *a, **kw)  # type: ignore[method-assign]

    with stubber, pytest.raises(AuthError) as exc_info:
        build_k8s_api_client(session, cluster_name, region)

    assert "does not have an API server endpoint" in str(exc_info.value)


def test_check_k8s_access_all_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_k8s_access returns empty list when all access reviews are allowed."""
    mock_api = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status.allowed = True
    mock_api.create_self_subject_access_review.return_value = mock_resp

    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    missing = check_k8s_access(dummy_client)

    assert missing == []
    assert mock_api.create_self_subject_access_review.call_count == 9


def test_check_k8s_access_missing_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    """check_k8s_access returns names of resources/verbs where allowed is False."""
    mock_api = MagicMock()

    def mock_review(body: k8s.V1SelfSubjectAccessReview) -> MagicMock:
        resp = MagicMock()
        # Disallow 'nodes' and '/metrics'
        is_nodes = (
            body.spec.resource_attributes is not None
            and body.spec.resource_attributes.resource == "nodes"
        )
        if is_nodes or body.spec.non_resource_attributes:
            resp.status.allowed = False
        else:
            resp.status.allowed = True
        return resp

    mock_api.create_self_subject_access_review.side_effect = mock_review
    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    missing = check_k8s_access(dummy_client)

    assert "list nodes" in missing
    assert "get /metrics" in missing
    assert "list pods" not in missing


def test_check_k8s_access_unauthorized_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP 401 Unauthorized raises actionable AuthError pointing to EKS access entries."""
    mock_api = MagicMock()
    mock_api.create_self_subject_access_review.side_effect = ApiException(
        status=401,
        reason="Unauthorized",
    )
    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    with pytest.raises(AuthError) as exc_info:
        check_k8s_access(dummy_client)

    assert "IAM principal not mapped: add an EKS access entry with AmazonEKSViewPolicy" in str(
        exc_info.value
    )


def test_check_k8s_access_private_endpoint_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connection timeout raises actionable AuthError for private clusters."""
    mock_api = MagicMock()
    mock_api.create_self_subject_access_review.side_effect = urllib3.exceptions.ConnectTimeoutError(
        None, "Connection to 10.0.0.1 timed out"
    )
    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    with pytest.raises(AuthError) as exc_info:
        check_k8s_access(dummy_client)

    assert "cluster endpoint is private; run kua from inside the VPC" in str(exc_info.value)


def test_get_eks_token_failure() -> None:
    """get_eks_token wraps unexpected errors in AuthError."""
    mock_session = MagicMock()
    mock_session.client.side_effect = RuntimeError("STS unreachable")

    with pytest.raises(AuthError) as exc_info:
        get_eks_token(mock_session, "my-cluster")

    assert "Failed to generate EKS authentication token" in str(exc_info.value)


def test_build_k8s_api_client_missing_ca() -> None:
    """Missing CA data raises AuthError."""
    session = boto3.Session(region_name="us-west-2")
    cluster_name = "eks-no-ca"
    region = "us-west-2"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_response(
        "describe_cluster",
        {"cluster": {"name": cluster_name, "endpoint": "https://ep", "certificateAuthority": {}}},
        {"name": cluster_name},
    )
    orig_client3 = session.client
    session.client = lambda s, *a, **kw: eks if s == "eks" else orig_client3(s, *a, **kw)  # type: ignore[method-assign]

    with stubber, pytest.raises(AuthError) as exc_info:
        build_k8s_api_client(session, cluster_name, region)

    assert "missing certificate authority data" in str(exc_info.value)


def test_build_k8s_api_client_invalid_ca() -> None:
    """Invalid base64 CA data raises AuthError."""
    session = boto3.Session(region_name="us-west-2")
    cluster_name = "eks-bad-ca"
    region = "us-west-2"

    eks = session.client("eks", region_name=region)
    stubber = Stubber(eks)
    stubber.add_response(
        "describe_cluster",
        {
            "cluster": {
                "name": cluster_name,
                "endpoint": "https://ep",
                "certificateAuthority": {"data": "not-valid-base64-==="},
            }
        },
        {"name": cluster_name},
    )
    orig_client4 = session.client
    session.client = lambda s, *a, **kw: eks if s == "eks" else orig_client4(s, *a, **kw)  # type: ignore[method-assign]

    with stubber, pytest.raises(AuthError) as exc_info:
        build_k8s_api_client(session, cluster_name, region)

    assert "Invalid base64 certificate authority" in str(exc_info.value)


def test_check_k8s_access_generic_api_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generic non-401 ApiException raises AuthError."""
    mock_api = MagicMock()
    mock_api.create_self_subject_access_review.side_effect = ApiException(
        status=500,
        reason="Internal Server Error",
    )
    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    with pytest.raises(AuthError) as exc_info:
        check_k8s_access(dummy_client)

    assert "Kubernetes API error during access review" in str(exc_info.value)


def test_check_k8s_access_unexpected_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unexpected exceptions raise AuthError."""
    mock_api = MagicMock()
    mock_api.create_self_subject_access_review.side_effect = RuntimeError("Fatal socket error")
    monkeypatch.setattr(k8s, "AuthorizationV1Api", lambda client: mock_api)

    dummy_client = MagicMock()
    with pytest.raises(AuthError) as exc_info:
        check_k8s_access(dummy_client)

    assert "Unexpected error checking Kubernetes permissions" in str(exc_info.value)
