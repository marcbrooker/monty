"""Example: Allow writes only to a specific output directory.

Sandboxed code can read from anywhere but can only write to /data/output/*.
This is useful when you want code to produce results in a controlled location.
"""

import tempfile
from pathlib import Path

from pydantic_monty import Monty, MountDir, Policy

# Create a temp directory with an output subdirectory
tmpdir = tempfile.mkdtemp()
Path(tmpdir, 'input.txt').write_text('source data')
Path(tmpdir, 'output').mkdir()

# Policy: read anywhere, write only to /data/output/*
policy = Policy('''
    permit(principal, action == Monty::Action::"fs:read", resource);
    permit(principal, action == Monty::Action::"fs:exists", resource);
    permit(principal, action == Monty::Action::"fs:list", resource);
    permit(principal, action == Monty::Action::"fs:create", resource)
    when { resource.path like "/data/output/*" };
    permit(principal, action == Monty::Action::"fs:write", resource)
    when { resource.path like "/data/output/*" };
''')

mount = MountDir('/data', tmpdir, mode='read-write')

# Read from input — allowed
m = Monty("from pathlib import Path; Path('/data/input.txt').read_text()")
result = m.run(mount=mount, policy=policy)
print(f'Read input.txt: {result}')

# Write to output directory — allowed
m = Monty("from pathlib import Path; Path('/data/output/result.txt').write_text('processed')")
m.run(mount=mount, policy=policy)
print(f'Wrote to output/result.txt: {Path(tmpdir, "output", "result.txt").read_text()}')

# Write to root — denied
m = Monty("from pathlib import Path; Path('/data/input.txt').write_text('overwritten!')")
try:
    m.run(mount=mount, policy=policy)
    print('ERROR: write to root should have been denied!')
except Exception as e:
    print(f'Write to root denied: {e}')

print('\nDone! Writes restricted to /data/output/* only.')
