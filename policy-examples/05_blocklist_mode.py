"""Example: Allow-by-default with explicit forbid rules (blocklist mode).

Instead of denying everything and allowlisting specific actions,
this mode starts permissive and blocks only the dangerous operations.
Useful when you trust the code mostly but want guardrails.
"""

import tempfile
from pathlib import Path

from pydantic_monty import Monty, MountDir, Policy

tmpdir = tempfile.mkdtemp()
Path(tmpdir, 'readme.txt').write_text('project notes')
Path(tmpdir, 'output').mkdir()

# Policy: allow everything EXCEPT writes and deletes
policy = Policy(
    '''
    forbid(principal, action == Monty::Action::"fs:write", resource);
    forbid(principal, action == Monty::Action::"fs:delete", resource);
    forbid(principal, action == Monty::Action::"fs:rename", resource);
    ''',
    default='allow',
)

mount = MountDir('/data', tmpdir, mode='read-write')

# Reading — allowed (no forbid rule)
m = Monty("from pathlib import Path; Path('/data/readme.txt').read_text()")
result = m.run(mount=mount, policy=policy)
print(f'Read: {result}')

# Listing — allowed (no forbid rule)
m = Monty("from pathlib import Path; list(p.name for p in Path('/data').iterdir())")
result = m.run(mount=mount, policy=policy)
print(f'Listed: {result}')

# Existence check — allowed (no forbid rule)
m = Monty("from pathlib import Path; Path('/data/readme.txt').exists()")
result = m.run(mount=mount, policy=policy)
print(f'Exists: {result}')

# Writing — blocked by explicit forbid
m = Monty("from pathlib import Path; Path('/data/output/file.txt').write_text('data')")
try:
    m.run(mount=mount, policy=policy)
    print('ERROR: write should have been denied!')
except Exception as e:
    print(f'Write denied: {e}')

# Delete — blocked by explicit forbid
m = Monty("from pathlib import Path; Path('/data/readme.txt').unlink()")
try:
    m.run(mount=mount, policy=policy)
    print('ERROR: delete should have been denied!')
except Exception as e:
    print(f'Delete denied: {e}')

print('\nDone! Blocklist mode: everything works except writes/deletes/renames.')
