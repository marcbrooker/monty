# Cedar Policy Examples

These examples demonstrate how to use Cedar policies to control what sandboxed Python code can do in Monty.

## Setup

Install the package:

```bash
uv add pydantic-monty
```

Or from this repo (development):

```bash
make dev-py
```

## Running

Each example is a standalone Python script:

```bash
python policy-examples/01_read_only.py
python policy-examples/02_write_restricted.py
python policy-examples/03_external_functions.py
python policy-examples/04_env_vars.py
python policy-examples/05_blocklist_mode.py
python policy-examples/06_combined_policy.py
```

## Overview

| Example | Demonstrates |
|---------|-------------|
| `01_read_only.py` | Allow filesystem reads, deny writes |
| `02_write_restricted.py` | Allow writes only to specific paths |
| `03_external_functions.py` | Allowlist specific external function calls |
| `04_env_vars.py` | Restrict which environment variables are readable |
| `05_blocklist_mode.py` | Allow-by-default with explicit forbid rules |
| `06_combined_policy.py` | A realistic policy combining multiple rules |

## Cedar Action Reference

| Action | Controls |
|--------|----------|
| `Monty::Action::"fs:read"` | Reading files, stat, resolve |
| `Monty::Action::"fs:write"` | Writing/appending files |
| `Monty::Action::"fs:exists"` | Existence checks |
| `Monty::Action::"fs:list"` | Directory listing |
| `Monty::Action::"fs:create"` | Creating directories |
| `Monty::Action::"fs:delete"` | Deleting files/directories |
| `Monty::Action::"fs:rename"` | Renaming/moving |
| `Monty::Action::"env:read"` | Environment variable access |
| `Monty::Action::"ext:call"` | External function calls |

Policies match resources using `resource.path` (filesystem) or `resource.name` (env vars, functions). Use Cedar's `like` operator for glob patterns (e.g. `resource.path like "/data/*"`).
