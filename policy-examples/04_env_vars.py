"""Example: Restrict which environment variables are readable.

Sandboxed code can only access explicitly permitted env vars.
Secrets like API keys remain hidden even if the code tries to read them.
"""

from pydantic_monty import Monty, MountDir, Policy

import tempfile
from pathlib import Path

tmpdir = tempfile.mkdtemp()
Path(tmpdir, 'dummy').write_text('')

# Policy: only allow reading HOME and LANG env vars
policy = Policy('''
    permit(principal, action == Monty::Action::"env:read", resource)
    when { resource.name == "HOME" };

    permit(principal, action == Monty::Action::"env:read", resource)
    when { resource.name == "LANG" };

    permit(principal, action == Monty::Action::"fs:read", resource);
    permit(principal, action == Monty::Action::"fs:exists", resource);
''')

mount = MountDir('/data', tmpdir, mode='read-only')


# Simulate an OS callback that provides env vars
def os_callback(name, args, kwargs):
    env_vars = {
        'HOME': '/home/user',
        'LANG': 'en_US.UTF-8',
        'SECRET_API_KEY': 'sk-12345-NEVER-EXPOSE-THIS',
        'DATABASE_URL': 'postgres://admin:password@prod-db:5432/main',
    }
    if name == 'os.getenv':
        key = args[0]
        return env_vars.get(key)
    return None


# Reading HOME — allowed
m = Monty("import os; os.getenv('HOME', 'unknown')")
result = m.run(mount=mount, os=os_callback, policy=policy)
print(f"HOME = {result}")

# Reading LANG — allowed
m = Monty("import os; os.getenv('LANG', 'unknown')")
result = m.run(mount=mount, os=os_callback, policy=policy)
print(f"LANG = {result}")

# Reading SECRET_API_KEY — denied by policy
m = Monty("import os; os.getenv('SECRET_API_KEY', 'unknown')")
try:
    m.run(mount=mount, os=os_callback, policy=policy)
    print('ERROR: SECRET_API_KEY read should have been denied!')
except Exception as e:
    print(f'SECRET_API_KEY denied: {e}')

# Reading DATABASE_URL — denied by policy
m = Monty("import os; os.getenv('DATABASE_URL', 'unknown')")
try:
    m.run(mount=mount, os=os_callback, policy=policy)
    print('ERROR: DATABASE_URL read should have been denied!')
except Exception as e:
    print(f'DATABASE_URL denied: {e}')

print('\nDone! Only HOME and LANG are accessible to sandboxed code.')
