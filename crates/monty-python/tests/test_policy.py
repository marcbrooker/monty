"""Tests for Cedar policy enforcement via the Policy class."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from inline_snapshot import snapshot

from pydantic_monty import Monty, MountDir, Policy


@pytest.fixture
def test_dir() -> Generator[Path, None, None]:
    """Creates a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / 'hello.txt').write_text('hello world')
        (p / 'output').mkdir()
        yield p


# =============================================================================
# Policy construction
# =============================================================================


def test_policy_invalid_text():
    with pytest.raises(ValueError) as exc_info:
        Policy('not valid cedar')
    assert 'policy parse error' in str(exc_info.value)


def test_policy_invalid_default():
    with pytest.raises(ValueError) as exc_info:
        Policy('', default='maybe')  # pyright: ignore[reportArgumentType]
    assert str(exc_info.value) == snapshot("invalid default decision 'maybe': must be 'deny' or 'allow'")


def test_policy_empty_deny_default():
    # Empty policy with deny default should block everything.
    Policy('', default='deny')


# =============================================================================
# Filesystem policy tests
# =============================================================================


def test_policy_permits_read(test_dir: Path):
    policy = Policy(
        'permit(principal, action == Monty::Action::"fs:read", resource);'
        'permit(principal, action == Monty::Action::"fs:exists", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    result = m.run(mount=md, policy=policy)
    assert result == snapshot('hello world')


def test_policy_denies_read(test_dir: Path):
    # Empty policy = deny all
    policy = Policy('')
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    with pytest.raises(Exception) as exc_info:
        m.run(mount=md, policy=policy)
    assert "policy denied action 'fs:read'" in str(exc_info.value)


def test_policy_permits_read_denies_write(test_dir: Path):
    policy = Policy(
        'permit(principal, action == Monty::Action::"fs:read", resource);'
        'permit(principal, action == Monty::Action::"fs:exists", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-write')
    # Read should work
    m_read = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    assert m_read.run(mount=md, policy=policy) == snapshot('hello world')

    # Write should be denied by policy
    m_write = Monty("from pathlib import Path; Path('/data/output/new.txt').write_text('x')")
    with pytest.raises(Exception) as exc_info:
        m_write.run(mount=md, policy=policy)
    assert "policy denied action 'fs:write'" in str(exc_info.value)


def test_policy_path_pattern(test_dir: Path):
    policy = Policy(
        'permit(principal, action == Monty::Action::"fs:read", resource)'
        '  when { resource.path like "/data/output/*" };'
        'permit(principal, action == Monty::Action::"fs:exists", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-only')

    # Read from /data/output/* is not testable with read-only since there's nothing there,
    # but read from /data/hello.txt should be denied since it doesn't match /data/output/*
    m = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    with pytest.raises(Exception) as exc_info:
        m.run(mount=md, policy=policy)
    assert "policy denied action 'fs:read'" in str(exc_info.value)


# =============================================================================
# External function policy tests
# =============================================================================


def test_policy_permits_external_function():
    policy = Policy(
        'permit(principal, action == Monty::Action::"ext:call", resource)'
        '  when { resource.name == "safe_func" };'
    )
    m = Monty('safe_func()')
    result = m.run(
        external_functions={'safe_func': lambda: 42},
        policy=policy,
    )
    assert result == snapshot(42)


def test_policy_denies_external_function():
    policy = Policy(
        'permit(principal, action == Monty::Action::"ext:call", resource)'
        '  when { resource.name == "safe_func" };'
    )
    m = Monty('dangerous()')
    with pytest.raises(Exception) as exc_info:
        m.run(
            external_functions={'dangerous': lambda: 'hacked'},
            policy=policy,
        )
    assert "policy denied action 'ext:call'" in str(exc_info.value)
    assert 'dangerous' in str(exc_info.value)


# =============================================================================
# Environment variable policy tests
# =============================================================================


def test_policy_permits_env_read(test_dir: Path):
    policy = Policy(
        'permit(principal, action == Monty::Action::"env:read", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("import os; os.getenv('HOME', 'default')")
    # With env:read permitted, the OS call should proceed (may need OS handler)
    # Using os= callback to provide the env
    result = m.run(
        mount=md,
        os=lambda name, args, kwargs: 'test_home',
        policy=policy,
    )
    assert result == snapshot('test_home')


def test_policy_denies_env_read(test_dir: Path):
    # Only permit filesystem, not env
    policy = Policy(
        'permit(principal, action == Monty::Action::"fs:read", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("import os; os.getenv('SECRET', 'fallback')")
    with pytest.raises(Exception) as exc_info:
        m.run(
            mount=md,
            os=lambda name, args, kwargs: 'should_not_reach',
            policy=policy,
        )
    assert "policy denied action 'env:read'" in str(exc_info.value)


# =============================================================================
# Allow-by-default mode (blocklist)
# =============================================================================


def test_allow_default_permits_everything(test_dir: Path):
    policy = Policy('', default='allow')
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    result = m.run(mount=md, policy=policy)
    assert result == snapshot('hello world')


def test_allow_default_with_forbid(test_dir: Path):
    policy = Policy(
        'forbid(principal, action == Monty::Action::"fs:write", resource);',
        default='allow',
    )
    md = MountDir('/data', str(test_dir), mode='read-write')
    # Read should still work
    m_read = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    assert m_read.run(mount=md, policy=policy) == snapshot('hello world')

    # Write should be denied by explicit forbid
    m_write = Monty("from pathlib import Path; Path('/data/output/new.txt').write_text('x')")
    with pytest.raises(Exception) as exc_info:
        m_write.run(mount=md, policy=policy)
    assert "policy denied action 'fs:write'" in str(exc_info.value)


# =============================================================================
# Policy with start() method
# =============================================================================


def test_policy_with_start(test_dir: Path):
    policy = Policy(
        'permit(principal, action == Monty::Action::"fs:read", resource);'
        'permit(principal, action == Monty::Action::"fs:exists", resource);'
    )
    md = MountDir('/data', str(test_dir), mode='read-only')
    m = Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    result = m.start(mount=md, policy=policy)
    # Should complete successfully (start auto-dispatches OS calls when mount is provided)
    assert result.output == snapshot('hello world')
