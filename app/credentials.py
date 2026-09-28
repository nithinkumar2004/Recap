"""Secure per-user storage for Recap CLI credentials."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping


def credentials_path() -> Path:
    """Return the user-level credentials file path, outside analyzed repositories."""
    override = os.environ.get("RECAP_CONFIG_DIR")
    if override:
        config_dir = Path(override).expanduser()
    elif os.name == "nt":
        config_dir = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "recap"
    else:
        config_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "recap"
    return config_dir / "credentials.json"


def load_credentials() -> dict[str, str]:
    """Read saved credentials, returning an empty mapping if none are available."""
    path = credentials_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}
    return {
        key: value
        for key, value in data.items()
        if key in {"OPENROUTER_API_KEY", "GITHUB_TOKEN"} and isinstance(value, str) and value
    }


def save_credentials(credentials: Mapping[str, str]) -> None:
    """Write credentials atomically with owner-only directory and file permissions."""
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.parent.chmod(0o700)

    existing = load_credentials()
    existing.update({key: value for key, value in credentials.items() if value})

    file_descriptor, temporary_name = tempfile.mkstemp(prefix=".credentials-", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as credentials_file:
            json.dump(existing, credentials_file, indent=2)
            credentials_file.write("\n")
        os.replace(temporary_name, path)
        if os.name != "nt":
            path.chmod(0o600)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
