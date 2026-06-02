"""Example: A realistic combined policy for an AI agent sandbox.

This shows a production-like policy where an AI agent can:
- Read input data from /workspace/input/*
- Write results to /workspace/output/*
- Call approved external functions (fetch_url, store_result)
- Read the WORKSPACE_ID env var
- But cannot access secrets, write to input, or call unapproved functions
"""

import tempfile
from pathlib import Path

from pydantic_monty import Monty, MountDir, Policy

# Set up a workspace
workspace = tempfile.mkdtemp()
Path(workspace, 'input').mkdir()
Path(workspace, 'output').mkdir()
Path(workspace, 'input', 'task.json').write_text('{"task": "summarize", "doc_id": "abc123"}')
Path(workspace, 'input', 'document.txt').write_text(
    'This is a long document that needs summarization. '
    'It contains important findings about climate change.'
)

# A realistic agent sandbox policy
policy = Policy('''
    // Allow reading from anywhere in the workspace
    permit(principal, action == Monty::Action::"fs:read", resource)
    when { resource.path like "/workspace/*" };

    // Allow existence checks anywhere
    permit(principal, action == Monty::Action::"fs:exists", resource)
    when { resource.path like "/workspace/*" };

    // Allow listing directories
    permit(principal, action == Monty::Action::"fs:list", resource)
    when { resource.path like "/workspace/*" };

    // Allow writing ONLY to the output directory
    permit(principal, action == Monty::Action::"fs:write", resource)
    when { resource.path like "/workspace/output/*" };

    // Allow creating directories in output
    permit(principal, action == Monty::Action::"fs:create", resource)
    when { resource.path like "/workspace/output/*" };

    // Allow specific external functions
    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "fetch_url" };

    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "store_result" };

    // Allow reading workspace metadata env var
    permit(principal, action == Monty::Action::"env:read", resource)
    when { resource.name == "WORKSPACE_ID" };
''')

mount = MountDir('/workspace', workspace, mode='read-write')


# Simulated external functions
def fetch_url(url):
    return f'<content from {url}>'


def store_result(key, value):
    return f'stored {key}'


def send_email(to, body):
    return f'email sent to {to}'  # Should be blocked


external_functions = {
    'fetch_url': fetch_url,
    'store_result': store_result,
    'send_email': send_email,
}

print('=== Agent Sandbox: Combined Policy Demo ===\n')

# 1. Agent reads its task
code = "from pathlib import Path; Path('/workspace/input/task.json').read_text()"
m = Monty(code)
result = m.run(mount=mount, policy=policy)
print(f'1. Read task: {result}')

# 2. Agent reads the document
code = "from pathlib import Path; Path('/workspace/input/document.txt').read_text()"
m = Monty(code)
result = m.run(mount=mount, policy=policy)
print(f'2. Read document: {result[:50]}...')

# 3. Agent calls an approved function
code = 'fetch_url("https://api.example.com/context")'
m = Monty(code)
result = m.run(external_functions=external_functions, policy=policy)
print(f'3. fetch_url: {result}')

# 4. Agent writes output
code = "from pathlib import Path; Path('/workspace/output/summary.txt').write_text('Summary: climate findings')"
m = Monty(code)
m.run(mount=mount, policy=policy)
actual = Path(workspace, 'output', 'summary.txt').read_text()
print(f'4. Wrote output: {actual}')

# 5. Agent tries to write to input — DENIED
code = "from pathlib import Path; Path('/workspace/input/task.json').write_text('hacked')"
m = Monty(code)
try:
    m.run(mount=mount, policy=policy)
    print('ERROR: should have been denied!')
except Exception as e:
    print(f'5. Write to input denied: {e}')

# 6. Agent tries to call unapproved function — DENIED
code = 'send_email("admin@corp.com", "pwned")'
m = Monty(code)
try:
    m.run(external_functions=external_functions, policy=policy)
    print('ERROR: should have been denied!')
except Exception as e:
    print(f'6. send_email denied: {e}')

# 7. Agent tries to read a secret env var — DENIED
code = "import os; os.getenv('DATABASE_URL')"
m = Monty(code)
try:
    m.run(mount=mount, os=lambda *a: 'secret', policy=policy)
    print('ERROR: should have been denied!')
except Exception as e:
    print(f'7. SECRET env var denied: {e}')

print('\n=== All checks passed! Policy enforced correctly. ===')
