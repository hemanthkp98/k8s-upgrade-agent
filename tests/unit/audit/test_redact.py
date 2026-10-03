"""Unit tests for payload redaction rules."""

from kua.audit.redact import redact


def test_redact_sensitive_dict_keys() -> None:
    """Keys matching sensitive patterns have their values redacted regardless of case."""
    sensitive_payload = {
        "password": "supersecretpassword",
        "PASSWORD": "UPPERCASE_PASSWORD",
        "db_password": "my_db_password",
        "secret": "my-secret-val",
        "client_secret": "client-secret-xyz",
        "token": "ghp_1234567890",
        "access_token": "abcdef",
        "apikey": "key123",
        "api_key": "key456",
        "API_KEY": "KEY789",
        "private_key": "privkeycontent",
        "credential": "usercredential",
        "credentials": "multiplecredentials",
        "authorization": "Bearer something",
        "safe_field": "visible_value",
        "number": 42,
    }

    result = redact(sensitive_payload)

    assert result["password"] == "***REDACTED***"
    assert result["PASSWORD"] == "***REDACTED***"
    assert result["db_password"] == "***REDACTED***"
    assert result["secret"] == "***REDACTED***"
    assert result["client_secret"] == "***REDACTED***"
    assert result["token"] == "***REDACTED***"
    assert result["access_token"] == "***REDACTED***"
    assert result["apikey"] == "***REDACTED***"
    assert result["api_key"] == "***REDACTED***"
    assert result["API_KEY"] == "***REDACTED***"
    assert result["private_key"] == "***REDACTED***"
    assert result["credential"] == "***REDACTED***"
    assert result["credentials"] == "***REDACTED***"
    assert result["authorization"] == "***REDACTED***"
    assert result["safe_field"] == "visible_value"
    assert result["number"] == 42


def test_redact_nested_dicts_and_lists() -> None:
    """Redaction operates recursively within nested dictionaries and lists."""
    nested = {
        "cluster": "prod-1",
        "sub": {
            "token": "secret-token",
            "info": "ok",
        },
        "items": [
            {"api_key": "secret-api-key", "label": "item-1"},
            {"safe": True},
        ],
    }

    result = redact(nested)
    assert result["cluster"] == "prod-1"
    assert result["sub"]["token"] == "***REDACTED***"
    assert result["sub"]["info"] == "ok"
    assert result["items"][0]["api_key"] == "***REDACTED***"
    assert result["items"][0]["label"] == "item-1"
    assert result["items"][1]["safe"] is True


def test_redact_aws_access_key_id() -> None:
    """AWS access keys (AKIA/ASIA + 16 alphanumeric) are masked in strings."""
    standalone_akia = "AKIAIOSFODNN7EXAMPLE"
    standalone_asia = "ASIAIOSFODNN7EXAMPLE"
    embedded = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in shell"

    assert redact(standalone_akia) == "***REDACTED***"
    assert redact(standalone_asia) == "***REDACTED***"
    assert redact(embedded) == "export AWS_ACCESS_KEY_ID=***REDACTED*** in shell"


def test_redact_pem_private_key() -> None:
    """Strings containing PEM private key blocks are replaced."""
    pem_rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    pem_generic = (
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgE...\n-----END PRIVATE KEY-----"
    )

    pem_embedded = "cert_data: -----BEGIN EC PRIVATE KEY----- xyz"

    assert redact(pem_rsa) == "***REDACTED***"
    assert redact(pem_generic) == "***REDACTED***"
    assert redact(pem_embedded) == "***REDACTED***"


def test_redact_jwt_token() -> None:
    """Strings matching JWT token structure are masked."""
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozsbx"
    header = f"Authorization: Bearer {jwt}"

    assert redact(jwt) == "***REDACTED***"
    assert redact(header) == "Authorization: Bearer ***REDACTED***"


def test_redact_env_var_lists() -> None:
    """Environment variable lists shaped {'name': ..., 'value': ...} keep name and redact value."""
    env_vars = [
        {"name": "DATABASE_HOST", "value": "postgres.internal"},
        {"name": "PORT", "value": "5432"},
        {"name": "DB_PASSWORD", "value": "plain-text-pass"},
    ]

    result = redact(env_vars)

    assert len(result) == 3
    assert result[0] == {"name": "DATABASE_HOST", "value": "***REDACTED***"}
    assert result[1] == {"name": "PORT", "value": "***REDACTED***"}
    assert result[2] == {"name": "DB_PASSWORD", "value": "***REDACTED***"}


def test_redact_string_truncation() -> None:
    """Strings longer than 4000 characters are truncated with an informative suffix."""
    short_str = "x" * 4000
    assert redact(short_str) == short_str

    long_str = "a" * 4500
    result = redact(long_str)
    assert len(result) == 4000 + len("…[truncated 500 chars]")
    assert result.startswith("a" * 4000)
    assert result.endswith("…[truncated 500 chars]")


def test_redact_tuples_and_primitives() -> None:
    """Tuples and primitive values are handled properly."""
    assert redact(123) == 123
    assert redact(45.67) == 45.67
    assert redact(True) is True
    assert redact(None) is None
    assert redact(("AKIAIOSFODNN7EXAMPLE", 100)) == ("***REDACTED***", 100)
    assert redact({"AKIAIOSFODNN7EXAMPLE", "plain"}) == {"***REDACTED***", "plain"}
