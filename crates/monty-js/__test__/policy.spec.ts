import test from 'ava'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

import { Monty, MountDir, Policy, MontyRuntimeError } from '../wrapper'

// =============================================================================
// Helper: create a temporary directory with test files
// =============================================================================

function createTestDir(): { dir: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'monty-policy-test-'))
  fs.writeFileSync(path.join(dir, 'hello.txt'), 'hello world')
  fs.mkdirSync(path.join(dir, 'output'))
  return {
    dir,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  }
}

// =============================================================================
// Policy construction
// =============================================================================

test('Policy construction with valid text', (t) => {
  const policy = new Policy('permit(principal, action == Monty::Action::"fs:read", resource);')
  t.truthy(policy)
})

test('Policy construction with empty text', (t) => {
  const policy = new Policy('')
  t.truthy(policy)
})

test('Policy construction with invalid text throws', (t) => {
  const error = t.throws(() => new Policy('not valid cedar'))
  t.true(error?.message.includes('policy parse error'))
})

test('Policy construction with invalid default throws', (t) => {
  const error = t.throws(() => new Policy('', { default: 'maybe' }))
  t.true(error?.message.includes("invalid default decision 'maybe'"))
})

// =============================================================================
// Filesystem policy tests
// =============================================================================

test('Policy permits read', (t) => {
  const { dir, cleanup } = createTestDir()
  try {
    const policy = new Policy(
      'permit(principal, action == Monty::Action::"fs:read", resource);' +
        'permit(principal, action == Monty::Action::"fs:exists", resource);',
    )
    const md = new MountDir('/data', dir, { mode: 'read-only' })
    const m = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    const result = m.run({ mount: md, policy })
    t.is(result, 'hello world')
  } finally {
    cleanup()
  }
})

test('Policy denies read (empty policy = deny all)', (t) => {
  const { dir, cleanup } = createTestDir()
  try {
    const policy = new Policy('')
    const md = new MountDir('/data', dir, { mode: 'read-only' })
    const m = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    const error = t.throws(() => m.run({ mount: md, policy }), { instanceOf: MontyRuntimeError })
    t.true(error?.message.includes("policy denied action 'fs:read'"))
  } finally {
    cleanup()
  }
})

test('Policy permits read but denies write', (t) => {
  const { dir, cleanup } = createTestDir()
  try {
    const policy = new Policy(
      'permit(principal, action == Monty::Action::"fs:read", resource);' +
        'permit(principal, action == Monty::Action::"fs:exists", resource);',
    )
    const md = new MountDir('/data', dir, { mode: 'read-write' })

    // Read should work
    const m1 = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    t.is(m1.run({ mount: md, policy }), 'hello world')

    // Write should be denied
    const m2 = new Monty("from pathlib import Path; Path('/data/output/new.txt').write_text('x')")
    const error = t.throws(() => m2.run({ mount: md, policy }), { instanceOf: MontyRuntimeError })
    t.true(error?.message.includes("policy denied action 'fs:write'"))
  } finally {
    cleanup()
  }
})

// =============================================================================
// External function policy tests
// =============================================================================

test('Policy permits specific external function', (t) => {
  const policy = new Policy(
    'permit(principal, action == Monty::Action::"ext:call", resource) when { resource.name == "safe_func" };',
  )
  const m = new Monty('safe_func()')
  const result = m.run({
    external_functions: { safe_func: () => 42 },
    policy,
  })
  t.is(result, 42)
})

test('Policy denies unmatched external function', (t) => {
  const policy = new Policy(
    'permit(principal, action == Monty::Action::"ext:call", resource) when { resource.name == "safe_func" };',
  )
  const m = new Monty('dangerous()')
  const error = t.throws(
    () =>
      m.run({
        external_functions: { dangerous: () => 'hacked' },
        policy,
      }),
    { instanceOf: MontyRuntimeError },
  )
  t.true(error?.message.includes("policy denied action 'ext:call'"))
  t.true(error?.message.includes('dangerous'))
})

// =============================================================================
// Allow-by-default mode
// =============================================================================

test('Allow-by-default permits everything without explicit forbid', (t) => {
  const { dir, cleanup } = createTestDir()
  try {
    const policy = new Policy('', { default: 'allow' })
    const md = new MountDir('/data', dir, { mode: 'read-only' })
    const m = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    t.is(m.run({ mount: md, policy }), 'hello world')
  } finally {
    cleanup()
  }
})

test('Allow-by-default with explicit forbid blocks writes', (t) => {
  const { dir, cleanup } = createTestDir()
  try {
    const policy = new Policy('forbid(principal, action == Monty::Action::"fs:write", resource);', {
      default: 'allow',
    })
    const md = new MountDir('/data', dir, { mode: 'read-write' })

    // Read still works
    const m1 = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
    t.is(m1.run({ mount: md, policy }), 'hello world')

    // Write blocked
    const m2 = new Monty("from pathlib import Path; Path('/data/output/new.txt').write_text('x')")
    const error = t.throws(() => m2.run({ mount: md, policy }), { instanceOf: MontyRuntimeError })
    t.true(error?.message.includes("policy denied action 'fs:write'"))
  } finally {
    cleanup()
  }
})
