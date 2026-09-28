"""Tests for private user-level credential storage."""
import json
import os
import stat

from app.config import Settings
from app.credentials import credentials_path, load_credentials, save_credentials
import cli


def test_credentials_are_saved_and_merged_in_private_config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RECAP_CONFIG_DIR", str(tmp_path / "recap-config"))

    save_credentials({"OPENROUTER_API_KEY": "router-secret"})
    save_credentials({"GITHUB_TOKEN": "github-secret"})

    assert load_credentials() == {
        "OPENROUTER_API_KEY": "router-secret",
        "GITHUB_TOKEN": "github-secret",
    }
    assert credentials_path().parent == tmp_path / "recap-config"
    assert not (tmp_path / "credentials.json").exists()

    if os.name != "nt":
        assert stat.S_IMODE(credentials_path().stat().st_mode) == 0o600
        assert stat.S_IMODE(credentials_path().parent.stat().st_mode) == 0o700


def test_credentials_loader_ignores_unknown_or_invalid_values(tmp_path, monkeypatch):
    monkeypatch.setenv("RECAP_CONFIG_DIR", str(tmp_path))
    credentials_path().write_text(
        json.dumps({"OPENROUTER_API_KEY": "router-secret", "OTHER": "not-a-credential", "GITHUB_TOKEN": 42}),
        encoding="utf-8",
    )

    assert load_credentials() == {"OPENROUTER_API_KEY": "router-secret"}


def test_settings_do_not_read_target_repository_dotenv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RECAP_ENV_FILE", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    (tmp_path / ".env").write_text(
        "OPENROUTER_API_KEY=target-repo-secret\nGITHUB_TOKEN=target-repo-token\n",
        encoding="utf-8",
    )

    settings = Settings()

    assert settings.OPENROUTER_API_KEY == ""
    assert settings.GITHUB_TOKEN == ""


def test_cli_prompts_for_openrouter_then_github_when_credentials_are_missing(monkeypatch):
    prompts = []
    saved = []
    monkeypatch.setattr(cli.settings, "OPENROUTER_API_KEY", "")
    monkeypatch.setattr(cli.settings, "GITHUB_TOKEN", "")
    monkeypatch.setattr(cli, "load_credentials", lambda: {})
    monkeypatch.setattr(cli, "save_credentials", lambda credentials: saved.append(credentials))

    def fake_prompt(message, password):
        prompts.append((message, password))
        return "router-key" if len(prompts) == 1 else "github-token"

    monkeypatch.setattr(cli.Prompt, "ask", fake_prompt)

    cli.ensure_credentials()

    assert [message for message, _ in prompts] == [
        "Enter your OpenRouter API key",
        "Enter your GitHub access token",
    ]
    assert all(password for _, password in prompts)
    assert saved == [{"OPENROUTER_API_KEY": "router-key", "GITHUB_TOKEN": "github-token"}]
    assert cli.settings.OPENROUTER_API_KEY == "router-key"
    assert cli.settings.GITHUB_TOKEN == "github-token"
