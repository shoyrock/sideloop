# Code quality in Sideloop

`AGENTS.md` is the canonical instruction file. This guide describes the local
tooling and its limits; it is not another set of coding rules.

## Project and agent integration

Sideloop is a standard-library Python application with vanilla JavaScript/CSS
embedded in `sideloop/index.html`. Bash starts processes and invokes the signer.
Native C/C++ changes are maintained as patches against pinned AltServer sources;
Docker builds and tests them. Python regression tests use `unittest` in `tests/`.
There was no existing formatter, linter, type checker, JavaScript package manager,
project MCP configuration, or SonarQube integration at bootstrap.

Codex reads root `AGENTS.md` and discovers project skills under `.agents/skills`.
The three installed skills include their required supporting Markdown files.
No Claude, Cursor, or Copilot rule copies are necessary for this checkout.

The local instructions explicitly distinguish Boudra's **code** Unslop from the
owner's existing user-level prose skill of the same name. Use the project path,
not an ambiguous `$unslop` invocation. Generic skill heuristics must not override
the established Python layout, central `tests/` directory, boundary validation,
or the requested scope. Skill metadata such as `allowed-tools` is not a Codex
permission grant. No skill grants permission to publish or delegate work.

Discovery is verified: the active Codex session lists all three project skills,
and the official Skills CLI reports each with project scope and the Codex agent.
Root `AGENTS.md` is present in the session's project instructions. All local
Markdown references resolve. No competing Claude, Cursor, Copilot, nested agent,
or project MCP instructions were found. The root instructions also link each
skill directly, allowing an agent to load it without relying on name matching.
In a new checkout, start Codex inside the repository. If the skills do not appear,
restart Codex; do not reinstall or create duplicate global copies first.
Agent guidance influences behavior; the automated checks below enforce only
their specified checks, not every maintainability judgment.

Official mechanisms: [Codex skills](https://learn.chatgpt.com/docs/build-skills)
and [AGENTS.md discovery](https://learn.chatgpt.com/docs/agent-configuration/agents-md).

## Installed skill sources

| Skill | Repository | Pinned commit | Source directory |
| --- | --- | --- | --- |
| clean-code | [ciembor/agent-rules-books](https://github.com/ciembor/agent-rules-books) | `893a88a6fce3a80c565bf39ac65021b43a8b2990` | `clean-code` |
| refactoring | [ciembor/agent-rules-books](https://github.com/ciembor/agent-rules-books) | `893a88a6fce3a80c565bf39ac65021b43a8b2990` | `refactoring` |
| unslop | [boudra/unslop](https://github.com/boudra/unslop) | `662ece848dcadf94c4dd0b7d59bbab4ad1fb3950` | `skills/unslop` |

Installation used the official [Agent Skills CLI](https://github.com/vercel-labs/skills),
`skills@1.7.4` (source commit `a80e4c9d12d607631249d4d7d059f835d4b2f13a`).
Its npm tarball integrity is
`sha512-lHZJksE8UImNAr+LL6unqq7jERjdFw5EJasm17srycwL7rXHGdCmgu1L1ttLxUO9i3rdH+QQig+px0icHqLmRw==`.
The skill manifests/references and installer entrypoint, copying, execution,
telemetry, and optional-install paths were inspected before execution. The
selected skills contain Markdown guidance, not executable helpers. This is a
scoped source review, not a full audit of the CLI's transitive dependencies.

`skills-lock.json` records source commits and the installer's content hashes.
Upstream MIT notices are in `.agents/licenses/`. All 20 installed skill files
match the pinned upstream Git blobs byte-for-byte. The initial Windows install
used CRLF line endings, which made Git's whitespace check reject the vendored
files. Their original LF bytes were restored and the lock hashes recalculated
with the CLI's algorithm. `.gitattributes` preserves those bytes across checkouts.
No global skills were installed or replaced. No hooks were installed and no
shell install scripts were run. npm lifecycle scripts and CLI telemetry were disabled.

Once committed, the vendored skill directories travel with a clone; installing
again is not needed for ordinary development. To reproduce after reviewing the
pinned sources, use PowerShell with Node.js >=22.20:

```powershell
$env:DISABLE_TELEMETRY = '1'
$env:DO_NOT_TRACK = '1'
$env:npm_config_ignore_scripts = 'true'
npm.cmd exec --yes --ignore-scripts --package=skills@1.7.4 -- skills add https://github.com/ciembor/agent-rules-books/tree/893a88a6fce3a80c565bf39ac65021b43a8b2990 --skill clean-code refactoring --agent codex --copy --yes
npm.cmd exec --yes --ignore-scripts --package=skills@1.7.4 -- skills add https://github.com/boudra/unslop/tree/662ece848dcadf94c4dd0b7d59bbab4ad1fb3950 --skill unslop --agent codex --copy --yes
```

To check discovery without reinstalling, use the same environment settings and:

```powershell
npm.cmd exec --yes --ignore-scripts --package=skills@1.7.4 -- skills list --agent codex --json
```

Use `npm` instead of `npm.cmd` on Linux. The existing skill versions were retained
after their source text, lock hashes and references were verified. The cached CLI
package matched its recorded tarball integrity; a fresh npm metadata request
timed out during verification, so no claim is made about the newest CLI version.

Reinstallation replaces those skill directories. Review any local edits first.
For an update, review the new upstream instructions and files, choose a specific
commit, reinstall only the requested skills, and update this table and lockfile.
The CLI hashes raw bytes. `.gitattributes` disables checkout conversion for
vendored skills so those hashes survive cloning on another operating system.
Reinstalling under a different Git line-ending configuration can still change
the hash without changing Markdown semantics; compare the pinned source too.

## Local checks

Use Python >=3.11 (the application image uses 3.13), Bash, and Node.js. Git Bash
is supported on Windows; Node 22 or newer is recommended. Ruff is the only new
Python development dependency. Version 0.17.1 is pinned with wheel SHA-256 hashes
for Windows amd64 and glibc Linux amd64, matching the current deployment target.
Other architectures need their official wheel hash added before installation.

PowerShell:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.txt
.venv/Scripts/python.exe tools/check_quality.py
```

Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.txt
.venv/bin/python tools/check_quality.py
```

If using the existing `uv` installation, the equivalent setup is `uv venv .venv`
followed by `uv pip install --require-hashes --only-binary :all: -r requirements-dev.txt`.
No application dependencies or runtime behavior change.

The static gate is read-only and fails on a missing tool or failing check:

- Ruff parses Python and applies `E9` and Pyflakes `F` checks in `sideloop/`,
  `scripts/`, `tools/`, and `tests/`. Eight existing files have explicit `F401`
  exceptions for unused imports in `pyproject.toml`. Those files' unused imports
  remain unchecked until their exceptions are removed during authorized cleanup.
- Ruff format checking applies to the new `tools/check_quality.py`. Existing
  source has mixed formatting; enforcing a whole-tree formatter would require
  unrelated edits. `.editorconfig` supplies editor defaults and protects native
  patches, vendored skills, and local token files from automatic rewriting.
- `bash -n` parses the shell scripts; Node `--check` parses inline JavaScript.
  These checks do not execute application code or contact Apple/devices. They
  do not prove browser behavior, shell runtime behavior, or CSS correctness.

For an individual Python file, use the dev interpreter with
`-m ruff format --check path/to/file.py` to inspect formatting and
`-m ruff check path/to/file.py` to lint. Format only files within the task's scope.
Do not run whole-repository autofix as part of normal validation.

There is no full static type checker: the existing Python code is mostly
unannotated, and imposing one now would create a second migration. Add useful
boundary annotations as code changes; revisit type checking for an annotated
module when it can enforce a meaningful contract. Ruff is not a type checker.

## Regression and native checks

On Linux with the project's existing runtime tools available:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The complete suite uses POSIX PTYs, process behavior, Bash, and OpenSSL. Do not
interpret running only portable tests on Windows as a complete regression run.
Tests use temporary state and fake Apple/device transports; live Apple accounts
and phones are not required for the regression suite.

For static checks in isolation on an amd64 Docker host:

```sh
docker build --platform linux/amd64 -f tools/Dockerfile.quality -t sideloop:quality-local .
docker run --rm --network none sideloop:quality-local
```

`tools/forgejo-build.sh` now builds this development-only image and runs the
static gate **before** the application build. Existing Linux regressions, native
TLS verification, AFC fault-injection checks during compilation, and container
smoke tests remain in place. Test execution is network-isolated; building images
needs the existing package registries. A static failure stops the build because
the script uses `set -euo pipefail`. Quality logs go to ignored `output/`.

Only the local machine or the owner's Forgejo runners at
`https://forgejo.onlylan.duckdns.org/` may run builds. Nothing uses GitHub runners.
The build script enforces the gate whenever it runs, including on Forgejo.
This bootstrap does not register a workflow, submit a remote build, or configure
branch protection. The existing runner workflow must invoke this script for the
gate to apply; publishing or promoting an image is a separate operation.
The quality Dockerfile pins the Debian base digest and Ruff hashes; Debian's
package repositories supply the other development tools, so this is not a
bit-for-bit reproducible OS toolchain.

## Optional tooling and verification limits

[Serena](https://github.com/oraios/serena) offers language-server-based symbol
navigation and refactoring through MCP. It was evaluated but not configured:
this repository has a small Python package, inline UI, and a few native patches,
and its immediate quality gaps are linting and consistent review. Adding an MCP
server and language-server setup is not justified for this bootstrap. Revisit
if cross-module navigation becomes a demonstrated bottleneck. No SonarQube
integration was found; no account, paid service, or credential was introduced.

Verification on 2026-10-21 passed the static gate and 12 portable regression
tests (eight authentication retry tests and four diagnostic tests). Isolated
fixtures verified that valid Unicode and module scripts pass, and that undefined
Python names, broken shell/JavaScript, unclosed script tags, and formatting
violations fail the gate. The earlier bootstrap also checked Forgejo's failure
propagation with a stubbed Docker command. These are not container tests.

The local Docker Linux engine is not running. The quality container and complete
Linux/native/container suite were not run for this bootstrap, and no remote job
was submitted. On an authorized Docker host, run the quality-container command
above and the normal Forgejo build checks before treating container validation
as complete. No full type checker is configured; adding one remains a separate
scoped change rather than part of this bootstrap.

Keep `AGENTS.md`, `.agents/`, `skills-lock.json`, `.editorconfig`, this guide,
the quality config/tools, and ignore-file changes in version control so another
checkout receives the same setup. Keep `.local/`, `.venv/`, private review notes
and tokens out of commits. No publication or deployment is part of this setup.
