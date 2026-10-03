"""Exception hierarchy for kua."""


class KuaError(Exception):
    """Base exception for all errors in kua."""


class ConfigError(KuaError):
    """Raised when configuration loading or validation fails."""


class VersionError(KuaError):
    """Raised for invalid version strings or unsupported version operations (e.g. downgrades)."""


class CollectorError(KuaError):
    """Raised when a cluster collector fails to gather state."""


class AuthError(KuaError):
    """Raised when authentication or authorization with a cluster or cloud provider fails."""
