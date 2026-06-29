# Releasing mcp-audit to PyPI

The package builds clean and passes `twine check`. Publishing is a human step because it needs your
PyPI account and an API token (an agent cannot create accounts or hold credentials).

Once this is done, `pip install mcp-audit` works for everyone, which is a big lift over the current
`pipx install git+https://...` line.

## One time setup
1. Create a PyPI account at https://pypi.org and verify your email.
2. Make an API token: PyPI, Account settings, API tokens, Add token (scope: entire account for the first
   upload, then you can scope it to the project).

## Each release
```bash
cd ventures/mcp-forge/mcp-audit
# 1. bump the version in BOTH pyproject.toml and mcp_audit/__init__.py (keep them equal)
python3 -m pip install --quiet build twine
rm -rf dist
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*      # username: __token__   password: your API token
```

## After the first upload
- Update the README install line from the git+ URL to `pip install mcp-audit`.
- Tag the release: `git tag vX.Y.Z && git push origin vX.Y.Z`.

## Notes
- The version lives in two files (pyproject.toml and mcp_audit/__init__.py). Keep them in sync.
- If the name `mcp-audit` is already taken on PyPI, pick another (for example `mcp-config-audit`) and
  update the `name` in pyproject.toml plus the README.
- Build verified on 2026-06-29: mcp_audit-0.1.6 wheel + sdist, twine check PASSED.
