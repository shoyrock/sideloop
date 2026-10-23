# Working in Sideloop

This file is the canonical project guidance for coding agents. Detailed setup,
tool versions, validation commands, and limitations are in
[docs/code-quality.md](docs/code-quality.md).

## Coding standards

- Inspect nearby code and reuse existing behavior before implementing. Keep
  Python application logic in `sideloop/`, process entrypoints in `scripts/`,
  developer tooling in `tools/`, and regression tests in `tests/`. The UI is
  vanilla JavaScript/CSS in `sideloop/index.html`; do not add a framework casually.
- Use meaningful names, explicit dependencies, clear control flow, and focused
  functions/modules. Comments explain intent, constraints, or non-obvious decisions.
- Keep related logic together with clear responsibilities. Avoid giant files,
  circular dependencies, utility dumping grounds, speculative abstractions,
  pass-through wrappers, unnecessary dependencies, and excessive fragmentation.
- Follow local naming, imports, formatting, types, and test conventions. Preserve
  public interfaces, error semantics, persisted data, and observable behavior
  during refactoring unless the task explicitly calls for a behavior change.
- Keep changes focused. Do not reorganize or reformat unrelated code. Preserve
  `altserver/*.patch` byte-for-byte unless editing the patch intentionally;
  `.gitattributes` protects its mixed line endings.

## Proportionate skill workflow

- Before substantial implementation, inspect architectural boundaries and read
  [.agents/skills/clean-code/SKILL.md](.agents/skills/clean-code/SKILL.md), then its
  required mini reference. Read the
  [refactoring skill](.agents/skills/refactoring/SKILL.md) and mini reference when
  restructuring existing code; establish the behavior to preserve first.
- When a substantial plan risks unnecessary complexity, perform a forward review
  using the project [code Unslop skill](.agents/skills/unslop/SKILL.md) and relevant
  category references. After substantial implementation, use it to review the
  full changed files and diff for complexity, duplication, naming, nesting, and
  organization. Fix problems within scope and rerun affected checks.
- Use the explicit project Unslop path: a user-level skill with the same name may
  concern prose. Project conventions take priority over generic skill examples:
  retain `tests/`, use Python idioms, and do not introduce abstractions, move files,
  remove boundary validation, or spawn agents merely to satisfy a skill heuristic.
- Add meaningful regression tests when behavior changes. Run
  `python tools/check_quality.py` with the dev environment, then relevant tests;
  Linux regression command: `python3 -m unittest discover -s tests -p 'test_*.py' -v`.
  Native/container changes also need the Forgejo checks in the linked guide.
  Use the configured formatter on files in scope and any applicable type checks;
  do not apply repository-wide autofixes or add competing tools for a small edit.
  Report what ran, failures, and unavailable checks; never imply an unrun test passed.
- Small edits need only proportionate review and validation. Claim skill use only
  after actually reading its instructions and required references.

## Local credentials

The user wants agents working in this checkout to share the user-provided GitHub
personal access token. When present, it is stored in `.local/github-token` as
UTF-8 text without a trailing newline. The directory is excluded by `.gitignore`
and `.dockerignore`; it must stay excluded.

Read the token into memory only for authorized GitHub or GHCR operations. Never
print it, put it in command arguments, commit it, or include it in an image or
artifact. For Docker login, use `--password-stdin`. The file is local to this
checkout and is not transferred by cloning or creating another worktree.

If the file is absent, the previous publishing token was not retained. The user
can run `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Save-GitHubToken.ps1`
to enter and save it through a hidden prompt. Do
not ask the user to paste a token into chat. Connector authentication is separate
and cannot be exported as this token.

## Builds

Use the local machine or the user's Forgejo runners at
`https://forgejo.onlylan.duckdns.org/`. Do not use GitHub runners.
