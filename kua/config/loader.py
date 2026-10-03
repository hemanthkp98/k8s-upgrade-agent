"""Configuration loader for kua supporting YAML, environment, and CLI overrides."""

from pathlib import Path
from typing import Any

from pydantic_settings import EnvSettingsSource
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from kua.config.settings import KuaSettings
from kua.core.errors import ConfigError


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively deep merge two dictionaries.

    Nested dictionaries are merged recursively. Lists, primitives, and other
    values in ``override`` replace those in ``base``.
    """
    result: dict[str, Any] = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings(
    path: Path | str | None = None,
    overrides: dict[str, Any] | None = None,
) -> KuaSettings:
    """Load unified KuaSettings according to the configuration precedence hierarchy.

    Precedence order (highest to lowest):
    1. CLI overrides dictionary (``overrides``)
    2. Environment variables prefixed with ``KUA_`` (nested with ``__``)
    3. YAML configuration file (from ``path``)
    4. Model default values

    Args:
        path: Optional file path to a YAML configuration file. If provided and
            the file does not exist or cannot be parsed, raises ``ConfigError``.
        overrides: Optional dictionary of overrides (e.g. from CLI flags).

    Returns:
        A validated instance of ``KuaSettings``.

    Raises:
        ConfigError: If ``path`` is provided but does not exist, cannot be read,
            is invalid YAML, or does not contain a mapping.
        pydantic.ValidationError: If the resulting merged settings fail schema validation.
    """
    yaml_data: dict[str, Any] = {}

    if path is not None:
        path_obj = Path(path)
        if not path_obj.is_file():
            raise ConfigError(f"Configuration file not found: {path_obj}")

        yaml = YAML(typ="safe")
        try:
            loaded = yaml.load(path_obj)
        except (YAMLError, OSError) as exc:
            raise ConfigError(f"Failed to read or parse YAML file '{path_obj}': {exc}") from exc

        if loaded is not None:
            if not isinstance(loaded, dict):
                msg = f"YAML root in '{path_obj}' must be a mapping, got {type(loaded).__name__}"
                raise ConfigError(msg)
            yaml_data = dict(loaded)

    # Extract environment variables matching KUA_* using pydantic-settings EnvSettingsSource
    env_source = EnvSettingsSource(KuaSettings, env_prefix="KUA_", env_nested_delimiter="__")
    env_data: dict[str, Any] = env_source()

    # Apply precedence hierarchy: YAML -> Env -> CLI Overrides
    merged = deep_merge(yaml_data, env_data)
    if overrides:
        merged = deep_merge(merged, overrides)

    return KuaSettings(**merged)
