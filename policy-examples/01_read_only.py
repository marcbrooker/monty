"""Example: Allow filesystem reads, deny everything else.

This is the most common pattern — sandboxed code can read data
but cannot modify the host filesystem.
"""

import tempfile
from pathlib import Path

from pydantic_monty import Monty, MountDir, Policy

# Create a temp directory with some files to read
tmpdir = tempfile.mkdtemp()
Path(tmpdir, 'config.json').write_text('{"key": "value", "count": 42}')
Path(tmpdir, 'data.txt').write_text('hello from the sandbox')

# Policy: allow reads and existence checks, deny everything else
policy = Policy('''
    permit(principal, action == Monty::Action::"fs:read", resource);
    permit(principal, action == Monty::Action::"fs:exists", resource);
''')

mount = MountDir('/data', tmpdir, mode='read-write')

# Reading works
m = Monty("from pathlib import Path; Path('/data/config.json').read_text()")
result = m.run(mount=mount, policy=policy)
print(f'Read config.json: {result}')

# Existence check works
m = Monty("from pathlib import Path; Path('/data/data.txt').exists()")
result = m.run(mount=mount, policy=policy)
print(f'data.txt exists: {result}')

# Writing is denied by policy (even though mount is read-write)
m = Monty("from pathlib import Path; Path('/data/hack.txt').write_text('pwned')")
try:
    m.run(mount=mount, policy=policy)
    print('ERROR: write should have been denied!')
except Exception as e:
    print(f'Write denied: {e}')

print('\nDone! Policy allowed reads but blocked writes.')
