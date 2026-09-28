# Recap Release Captain

Recap analyzes Git repository changes, runs verification and security checks, and produces a release recommendation.

## Install once; do not activate an environment

On Windows, the easiest source-checkout run is:

```bat
run.bat --demo
```

The first run creates a private `.venv` and installs Recap. To analyze a project, run `run.bat` from that Git repository, or pass its path: `run.bat C:\path\to\project`. Python 3.10 or newer and Git must be installed. Docker is optional; without it, sandboxed tests fail closed unless local fallback is explicitly enabled.

For a command available from any project directory, install Recap with `pipx`:

Recommended from this source checkout: install with `pipx`, which creates and manages an isolated environment and places the `recap` command on your PATH:

```bash
pipx install .
pipx ensurepath
```

Open a new terminal after `pipx ensurepath`. From then on, run `recap` directly from any project directory; activating the internal environment is not needed. On Windows, bootstrap pipx with `py -m pip install --user pipx`, then `py -m pipx ensurepath`.
On Debian/Ubuntu Linux, install pipx with `sudo apt install pipx` before these commands.

For a machine without Python, download the standalone `recap` Linux executable or `recap.exe` Windows executable from the project's GitHub Releases and place it in a directory on PATH. The release workflow builds one executable per OS. Git must still be installed for local repository analysis; Docker is optional for sandboxed test execution.

For contributors, use `pipx install --editable '.[dev]'` from this directory to install the command and test dependencies.

## Configure credentials

On the first live run, `recap` requests an OpenRouter API key and then a GitHub access token. Input is hidden. It stores credentials in the user configuration directory, outside the repository being analyzed, with restrictive permissions on Linux and macOS.

Alternatively, export `OPENROUTER_API_KEY` and `GITHUB_TOKEN` in the shell before running Recap. To load settings from a dotenv file, explicitly set `RECAP_ENV_FILE` to that file's path. Recap intentionally does not read `.env` from the analyzed project's working directory.

## Run

```sh
# From inside a Git repository
recap

# Target a local repository
recap /path/to/project

# Target a GitHub repository
recap owner/repo

# View all command options
recap --help
```

The source checkout's full documentation is in the repository-level README.
