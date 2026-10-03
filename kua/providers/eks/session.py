"""AWS session management and caller identity resolution for EKS provider."""

from typing import Any

import boto3
from botocore.exceptions import ClientError

from kua.core.errors import AuthError


def make_boto_session(
    region: str,
    role_arn: str | None = None,
    session_name: str = "kua-scan",
) -> boto3.Session:
    """Create a boto3 Session configured for the target region and optional assumed role.

    If role_arn is specified, assumes the role via STS (3600 second duration) and builds
    a session from the temporary credentials. Otherwise, returns a session using the
    default credential resolution chain.

    Args:
        region: AWS region name (e.g. 'us-west-2').
        role_arn: Optional IAM role ARN to assume.
        session_name: Session name for the assumed role session.

    Returns:
        A configured boto3.Session instance.

    Raises:
        AuthError: If assuming the role fails.
    """
    if not role_arn:
        return boto3.Session(region_name=region)

    # Use base session to assume the target role
    base_session = boto3.Session(region_name=region)
    sts_client = base_session.client("sts")

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise AuthError(f"Failed to assume scanner role '{role_arn}': {e}") from e

    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def caller_identity(session: boto3.Session) -> dict[str, Any]:
    """Retrieve AWS caller identity for audit logging.

    Args:
        session: Active boto3.Session.

    Returns:
        Dict containing Account, Arn, and UserId.

    Raises:
        AuthError: If retrieving caller identity fails.
    """
    sts_client = session.client("sts")
    try:
        response = sts_client.get_caller_identity()
        return {
            "Account": response.get("Account", ""),
            "Arn": response.get("Arn", ""),
            "UserId": response.get("UserId", ""),
        }
    except ClientError as e:
        raise AuthError(f"Failed to retrieve AWS caller identity: {e}") from e
