"""Unit tests for EKS session management and caller identity resolution."""

from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from kua.core.errors import AuthError
from kua.providers.eks.session import caller_identity, make_boto_session


def test_make_boto_session_default() -> None:
    """make_boto_session returns a session with configured region when no role_arn is given."""
    session = make_boto_session(region="us-west-2")
    assert session.region_name == "us-west-2"


@mock_aws
def test_make_boto_session_with_role_arn() -> None:
    """make_boto_session assumes the target role and configures temporary credentials."""
    role_arn = "arn:aws:iam::123456789012:role/kua-scanner"
    session = make_boto_session(
        region="us-east-1",
        role_arn=role_arn,
        session_name="test-session",
    )

    assert session.region_name == "us-east-1"
    credentials = session.get_credentials()
    assert credentials is not None
    assert credentials.access_key.startswith("ASIA")
    assert credentials.token is not None


def test_make_boto_session_assume_role_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """make_boto_session raises AuthError if STS assume_role fails."""
    mock_sts = MagicMock()
    mock_sts.assume_role.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Not authorized to assume role"}},
        "AssumeRole",
    )

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts

    monkeypatch.setattr("boto3.Session", lambda **kwargs: mock_session)

    with pytest.raises(AuthError) as exc_info:
        make_boto_session(region="us-west-2", role_arn="arn:aws:iam::123456789012:role/bad-role")

    assert "Failed to assume scanner role" in str(exc_info.value)
    assert "AccessDenied" in str(exc_info.value)


@mock_aws
def test_caller_identity_success() -> None:
    """caller_identity retrieves Account, Arn, and UserId from STS."""
    session = boto3.Session(region_name="us-west-2")
    identity = caller_identity(session)

    assert "Account" in identity
    assert "Arn" in identity
    assert "UserId" in identity
    assert len(identity["Account"]) > 0


def test_caller_identity_failure() -> None:
    """caller_identity raises AuthError when STS get_caller_identity fails."""
    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "AuthFailure", "Message": "AWS was not able to validate credentials"}},
        "GetCallerIdentity",
    )
    mock_session.client.return_value = mock_sts

    with pytest.raises(AuthError) as exc_info:
        caller_identity(mock_session)

    assert "Failed to retrieve AWS caller identity" in str(exc_info.value)
