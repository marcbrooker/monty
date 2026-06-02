<div align="center">
  <h1>Monty + Cedar Policy</h1>
</div>
<div align="center">
  <h3>An experimental fork of Monty with Cedar policy-based access control.</h3>
</div>

---

**Experimental fork** - This is an experimental fork of [Monty](https://github.com/pydantic/monty) that adds [Cedar](https://www.cedarpolicy.com/) policy support for fine-grained authorization of sandbox operations. Cedar policies let you declaratively control which filesystem paths, environment variables, and external functions sandboxed code can access.

A minimal, secure Python interpreter written in Rust for use by AI.

Monty avoids the cost, latency, complexity and general faff of using a full container based sandbox for running LLM generated code.

Instead, it lets you safely run Python code written by an LLM embedded in your agent, with startup times measured in single digit microseconds not hundreds of milliseconds.

What Monty **can** do:

- Run a reasonable subset of Python code - enough for your agent to express what it wants to do
- Completely block access to the host environment: filesystem, env variables and network access are all implemented via external function calls the developer can control
- Call functions on the host - only functions you give it access to
- Run typechecking - monty supports full modern python type hints and comes with [ty](https://docs.astral.sh/ty/) included in a single binary to run typechecking
- Be snapshotted to bytes at external function calls, meaning you can store the interpreter state in a file or database, and resume later
- Startup extremely fast (<1μs to go from code to execution result), and has runtime performance that is similar to CPython (generally between 5x faster and 5x slower)
- Be called from Rust, Python, or Javascript - because Monty has no dependencies on cpython, you can use it anywhere you can run Rust
- Control resource usage - Monty can track memory usage, allocations, stack depth, and execution time and cancel execution if it exceeds preset limits
- Collect stdout and stderr and return it to the caller
- Run async or sync code on the host via async or sync code on the host
- Use a small subset of the standard library: `sys`, `os`, `typing`, `asyncio`, `re`, `datetime`, `json`, `dataclasses` (soon)

What Monty **cannot** do:

- Use the rest of the standard library
- Use third party libraries (like Pydantic), support for external python library is not a goal
- define classes (support should come soon)
- use match statements (again, support should come soon)

---

In short, Monty is extremely limited and designed for **one** use case:

**To run code written by agents.**

For motivation on why you might want to do this, see:

- [Codemode](https://blog.cloudflare.com/code-mode/) from Cloudflare
- [Programmatic Tool Calling](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling) from Anthropic
- [Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp) from Anthropic
- [Smol Agents](https://github.com/huggingface/smolagents) from Hugging Face

In very simple terms, the idea of all the above is that LLMs can work faster, cheaper and more reliably if they're asked to write Python (or Javascript) code, instead of relying on traditional tool calling. Monty makes that possible without the complexity of a sandbox or risk of running code directly on the host.

**Note:** Monty will (soon) be used to implement `codemode` in [Pydantic AI](https://github.com/pydantic/pydantic-ai)

## Usage

Monty can be called from Python, JavaScript/TypeScript or Rust.

### Python

To install:

```bash
uv add pydantic-monty
```

(Or `pip install pydantic-monty` for the boomers)

Usage:

```python
from typing import Any

import pydantic_monty

code = """
async def agent(prompt: str, messages: Messages):
    while True:
        print(f'messages so far: {messages}')
        output = await call_llm(prompt, messages)
        if isinstance(output, str):
            return output
        messages.extend(output)

await agent(prompt, [])
"""

type_definitions = """
from typing import Any

Messages = list[dict[str, Any]]

async def call_llm(prompt: str, messages: Messages) -> str | Messages:
    raise NotImplementedError()

prompt: str = ''
"""

m = pydantic_monty.Monty(
    code,
    inputs=['prompt'],
    script_name='agent.py',
    type_check=True,
    type_check_stubs=type_definitions,
)


Messages = list[dict[str, Any]]


async def call_llm(prompt: str, messages: Messages) -> str | Messages:
    if len(messages) < 2:
        return [{'role': 'system', 'content': 'example response'}]
    else:
        return f'example output, message count {len(messages)}'


async def main():
    output = await m.run_async(
        inputs={'prompt': 'testing'},
        external_functions={'call_llm': call_llm},
    )
    print(output)
    #> example output, message count 2


if __name__ == '__main__':
    import asyncio

    asyncio.run(main())
```

#### Iterative Execution with External Functions

Use `start()` and `resume()` to handle external function calls iteratively,
giving you control over each call:

```python
import pydantic_monty

code = """
data = fetch(url)
len(data)
"""

m = pydantic_monty.Monty(code, inputs=['url'])

# Start execution - pauses when fetch() is called
result = m.start(inputs={'url': 'https://example.com'})

print(type(result))
#> <class 'pydantic_monty.FunctionSnapshot'>
print(result.function_name)  # fetch
#> fetch
print(result.args)
#> ('https://example.com',)

# Perform the actual fetch, then resume with the result
result = result.resume({'return_value': 'hello world'})

print(type(result))
#> <class 'pydantic_monty.MontyComplete'>
print(result.output)
#> 11
```

#### Serialization

Both `Monty` and snapshot types like `FunctionSnapshot` can be serialized to bytes and restored later.
This allows caching parsed code or suspending execution across process boundaries:

```python
import pydantic_monty

# Serialize parsed code to avoid re-parsing
m = pydantic_monty.Monty('x + 1', inputs=['x'])
data = m.dump()

# Later, restore and run
m2 = pydantic_monty.Monty.load(data)
print(m2.run(inputs={'x': 41}))
#> 42

# Serialize execution state mid-flight
m = pydantic_monty.Monty('fetch(url)', inputs=['url'])
progress = m.start(inputs={'url': 'https://example.com'})
state = progress.dump()

# Later, restore and resume (e.g., in a different process)
progress2 = pydantic_monty.load_snapshot(state)
result = progress2.resume({'return_value': 'response data'})
print(result.output)
#> response data
```

### Cedar Policies

This fork adds Cedar policy support to control what sandboxed code is allowed to do. Policies are written in the [Cedar language](https://www.cedarpolicy.com/) and evaluated against every sandbox operation.

#### Basic Example: Allow reads, deny writes

```python
from pydantic_monty import Monty, MountDir, Policy

# Define a policy that allows reading files under /data but denies all writes
policy = Policy('''
    permit(principal, action == Monty::Action::"fs:read", resource)
    when { resource.path like "/data/*" };

    permit(principal, action == Monty::Action::"fs:exists", resource);
''')

m = Monty("from pathlib import Path; Path('/data/config.json').read_text()")
result = m.run(
    mount=MountDir('/data', './my_data_dir', mode='read-write'),
    policy=policy,
)
# Reading works - policy permits fs:read on /data/*

m_write = Monty("from pathlib import Path; Path('/data/hack.txt').write_text('pwned')")
m_write.run(mount=MountDir('/data', './my_data_dir', mode='read-write'), policy=policy)
# Raises PermissionError: policy denied action 'fs:write' on '/data/hack.txt'
```

#### Controlling external function access

```python
from pydantic_monty import Monty, Policy

# Only allow calling specific external functions
policy = Policy('''
    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "fetch_weather" };

    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "get_time" };
''')

m = Monty('result = fetch_weather("London")')
result = m.run(
    external_functions={'fetch_weather': lambda city: f'Sunny in {city}'},
    policy=policy,
)
# Works - fetch_weather is permitted

m2 = Monty('result = run_shell("rm -rf /")')
m2.run(
    external_functions={'run_shell': lambda cmd: __import__('os').system(cmd)},
    policy=policy,
)
# Raises PermissionError: policy denied action 'ext:call' on 'run_shell'
```

#### Restricting environment variable access

```python
from pydantic_monty import Monty, MountDir, Policy

# Allow reading only specific env vars
policy = Policy('''
    permit(principal, action == Monty::Action::"env:read", resource)
    when { resource.name == "HOME" || resource.name == "PATH" };

    permit(principal, action == Monty::Action::"fs:read", resource);
    permit(principal, action == Monty::Action::"fs:exists", resource);
''')

m = Monty("import os; os.getenv('HOME', 'unknown')")
m.run(mount=MountDir('/data', '/tmp'), os=lambda *a: '/home/user', policy=policy)
# Works - HOME is permitted

m2 = Monty("import os; os.getenv('SECRET_API_KEY', 'unknown')")
m2.run(mount=MountDir('/data', '/tmp'), os=lambda *a: 'leaked!', policy=policy)
# Raises PermissionError: policy denied action 'env:read' on 'SECRET_API_KEY'
```

#### Allow-by-default mode (blocklist)

```python
from pydantic_monty import Monty, MountDir, Policy

# Start permissive, then block specific actions
policy = Policy(
    'forbid(principal, action == Monty::Action::"fs:write", resource);',
    default='allow',
)

# Everything works except writes
m = Monty("from pathlib import Path; Path('/data/file.txt').read_text()")
m.run(mount=MountDir('/data', './data', mode='read-write'), policy=policy)  # OK

m = Monty("from pathlib import Path; Path('/data/file.txt').write_text('x')")
m.run(mount=MountDir('/data', './data', mode='read-write'), policy=policy)
# Raises PermissionError: policy denied action 'fs:write' on '/data/file.txt'
```

#### JavaScript/TypeScript

```typescript
import { Monty, MountDir, Policy } from '@pydantic/monty'

const policy = new Policy(`
    permit(principal, action == Monty::Action::"fs:read", resource)
    when { resource.path like "/data/*" };
    permit(principal, action == Monty::Action::"fs:exists", resource);
`)

const m = new Monty("from pathlib import Path; Path('/data/hello.txt').read_text()")
const result = m.run({ mount: new MountDir('/data', './data'), policy })
```

#### Available actions

| Cedar Action | Controls |
|---|---|
| `Monty::Action::"fs:read"` | Reading files, stat, resolve, absolute path |
| `Monty::Action::"fs:write"` | Writing/appending to files, open in write mode |
| `Monty::Action::"fs:exists"` | Existence checks (exists, is_file, is_dir, is_symlink) |
| `Monty::Action::"fs:list"` | Directory listing (iterdir) |
| `Monty::Action::"fs:create"` | Creating directories (mkdir) |
| `Monty::Action::"fs:delete"` | Deleting files and directories |
| `Monty::Action::"fs:rename"` | Renaming/moving files |
| `Monty::Action::"env:read"` | Reading environment variables |
| `Monty::Action::"ext:call"` | Calling external (host) functions |

Policies use Cedar's `resource.path` attribute for filesystem operations (matched with `like` for glob patterns) and `resource.name` for env vars and external functions.

---

### Rust

```rust
use monty::{MontyRun, MontyObject, NoLimitTracker, PrintWriter};

let code = r#"
def fib(n):
    if n <= 1:
        return n
    return fib(n - 1) + fib(n - 2)

fib(x)
"#;

let runner = MontyRun::new(code.to_owned(), "fib.py", vec!["x".to_owned()]).unwrap();
let result = runner.run(vec![MontyObject::Int(10)], NoLimitTracker, PrintWriter::Stdout).unwrap();
assert_eq!(result, MontyObject::Int(55));
```

#### Serialization

`MontyRun` and `RunProgress` can be serialized using the `dump()` and `load()` methods:

```rust
use monty::{MontyRun, MontyObject, NoLimitTracker, PrintWriter};

// Serialize parsed code
let runner = MontyRun::new("x + 1".to_owned(), "main.py", vec!["x".to_owned()]).unwrap();
let bytes = runner.dump().unwrap();

// Later, restore and run
let runner2 = MontyRun::load(&bytes).unwrap();
let result = runner2.run(vec![MontyObject::Int(41)], NoLimitTracker, PrintWriter::Stdout).unwrap();
assert_eq!(result, MontyObject::Int(42));
```

## PydanticAI Integration

Monty will power code-mode in
[Pydantic AI](https://github.com/pydantic/pydantic-ai). Instead of making
sequential tool calls, the LLM writes Python code that calls your tools
as functions and Monty executes it safely.

```python test="skip"
import asyncio
import json

import logfire
from httpx import AsyncClient
from pydantic_ai import Agent, RunContext
from pydantic_ai.toolsets.code_mode import CodeModeToolset
from pydantic_ai.toolsets.function import FunctionToolset
from typing_extensions import TypedDict

logfire.configure()
logfire.instrument_pydantic_ai()


class LatLng(TypedDict):
    lat: float
    lng: float


weather_toolset: FunctionToolset[AsyncClient] = FunctionToolset()


@weather_toolset.tool
async def get_lat_lng(
    ctx: RunContext[AsyncClient], location_description: str
) -> LatLng:
    """Get the latitude and longitude of a location."""
    # NOTE: the response here will be random, and is not related to the location description.
    r = await ctx.deps.get(
        'https://demo-endpoints.pydantic.workers.dev/latlng',
        params={'location': location_description},
    )
    r.raise_for_status()
    return json.loads(r.content)


@weather_toolset.tool
async def get_temp(ctx: RunContext[AsyncClient], lat: float, lng: float) -> float:
    """Get the temp at a location."""
    # NOTE: the responses here will be random, and are not related to the lat and lng.
    r = await ctx.deps.get(
        'https://demo-endpoints.pydantic.workers.dev/number',
        params={'min': 10, 'max': 30},
    )
    r.raise_for_status()
    return float(r.text)


@weather_toolset.tool
async def get_weather_description(
    ctx: RunContext[AsyncClient], lat: float, lng: float
) -> str:
    """Get the weather description at a location."""
    # NOTE: the responses here will be random, and are not related to the lat and lng.
    r = await ctx.deps.get(
        'https://demo-endpoints.pydantic.workers.dev/weather',
        params={'lat': lat, 'lng': lng},
    )
    r.raise_for_status()
    return r.text


agent = Agent(
    'gateway/anthropic:claude-sonnet-4-5',
    # toolsets=[weather_toolset],
    toolsets=[CodeModeToolset(weather_toolset)],
    deps_type=AsyncClient,
)


async def main():
    async with AsyncClient() as client:
        await agent.run('Compare the weather of London, Paris, and Tokyo.', deps=client)


if __name__ == '__main__':
    asyncio.run(main())
```

## Community Bindings

- **Go**: [gomonty](https://github.com/ewhauser/gomonty/) - Go bindings for the Monty interpreter
- **Dart/Flutter**: dart_monty [(github)](https://github.com/runyaga/dart_monty) [(pub.dev)](https://pub.dev/packages/dart_monty)- Dart/Flutter bindings for Monty

# Alternatives

There are generally two responses when you show people Monty:

1. Oh my god, this solves so many problems, I want it.
2. Why not X?

Where X is some alternative technology. Oddly often these responses are combined, suggesting people have not yet found an alternative that works for them, but are incredulous that there's really no good alternative to creating an entire Python implementation from scratch.

I'll try to run through the most obvious alternatives, and why there aren't right for what we wanted.

NOTE: all these technologies are impressive and have widespread uses, this commentary on their limitations for our use case should not be seen as a criticism. Most of these solutions were not conceived with the goal of providing an LLM sandbox, which is why they're not necessary great at it.

| Tech               | Language completeness | Security     | Start latency | FOSS       | Setup complexity | File mounting  | Snapshotting |
| ------------------ | --------------------- | ------------ | ------------- | ---------- | ---------------- | -------------- | ------------ |
| Monty              | partial               | strict       | 0.06ms        | free / OSS | easy             | easy           | easy         |
| Docker             | full                  | good         | 195ms         | free / OSS | intermediate     | easy           | intermediate |
| Pyodide            | full                  | poor         | 2800ms        | free / OSS | intermediate     | easy           | hard         |
| starlark-rust      | very limited          | good         | 1.7ms         | free / OSS | easy             | not available? | impossible?  |
| WASI / Wasmer      | partial, almost full  | strict       | 66ms          | free \*    | intermediate     | easy           | intermediate |
| sandboxing service | full                  | strict       | 1033ms        | not free   | intermediate     | hard           | intermediate |
| YOLO Python        | full                  | non-existent | 0.1ms / 30ms  | free / OSS | easy             | easy / scary   | hard         |

See [./scripts/startup_performance.py](scripts/startup_performance.py) for the script used to calculate the startup performance numbers.

Details on each row below:

### Monty

- **Language completeness**: No classes (yet), limited stdlib, no third-party libraries
- **Security**: Explicitly controlled filesystem, network, and env access, strict limits on execution time and memory usage
- **Start latency**: Starts in microseconds
- **Setup complexity**: just `pip install pydantic-monty` or `npm install @pydantic/monty`, ~4.5MB download
- **File mounting**: Strictly controlled, see [#85](https://github.com/pydantic/monty/pull/85)
- **Snapshotting**: Monty's pause and resume functionality with `dump()` and `load()` makes it trivial to pause, resume and fork execution

### Docker

- **Language completeness**: Full CPython with any library
- **Security**: Process and filesystem isolation, network policies, but container escapes exist, memory limitation is possible
- **Start latency**: Container startup overhead (~195ms measured)
- **Setup complexity**: Requires Docker daemon, container images, orchestration, `python:3.14-alpine` is 50MB - docker can't be installed from PyPI
- **File mounting**: Volume mounts work well
- **Snapshotting**: Possible with durable execution solutions like Temporal, or snapshotting an image and saving it as a Docker image.

### Pyodide

- **Language completeness**: Full CPython compiled to WASM, almost all libraries available
- **Security**: Relies on browser/WASM sandbox - not designed for server-side isolation, python code can run arbitrary code in the JS runtime, only deno allows isolation, memory limits are hard/impossible to enforce with deno
- **Start latency**: WASM runtime loading is slow (~2800ms cold start)
- **Setup complexity**: Need to load WASM runtime, handle async initialization, pyodide NPM package is ~12MB, deno is ~50MB - Pyodide can't be called with just PyPI packages
- **File mounting**: Virtual filesystem via browser APIs
- **Snapshotting**: Possible with durable execution solutions like Temporal presumably, but hard

### starlark-rust

See [starlark-rust](https://github.com/facebook/starlark-rust).

- **Language completeness**: Configuration language, not Python - no classes, exceptions, async
- **Security**: Deterministic and hermetic by design
- **Start latency**: runs embedded in the process like Monty, hence impressive startup time
- **Setup complexity**: Usable in python via [starlark-pyo3](https://github.com/inducer/starlark-pyo3)
- **File mounting**: No file handling by design AFAIK?
- **Snapshotting**: Impossible AFAIK?

### WASI / Wasmer

Running Python in WebAssembly via [Wasmer](https://wasmer.io/).

- **Language completeness**: Full CPython, pure Python external packages work via mounting, external packages with C bindings don't work
- **Security**: In principle WebAssembly should provide strong sandboxing guarantees.
- **Start latency**: The [wasmer](https://pypi.org/project/wasmer/) python package hasn't been updated for 3 years and I couldn't find docs on calling Python in wasmer from Python, so I called it via subprocess. Start latency was 66ms.
- **Setup complexity**: wasmer download is 100mb, the "python/python" package is 50mb.
- **FOSS**: I marked this as "free \*" since the cost is zero but not everything seems to be open source. As of 2026-02-10 the [`python/python` wasmer package](https://wasmer.io/python/python) package has no readme, no license, no source link and no indication of how it's built, the recently uploaded versions show size as "0B" although the download is ~50MB - the build process for the Python binary is not clear and transparent. _(If I'm wrong here, please create an issue to correct correct me)_
- **File mounting**: Supported
- **Snapshotting**: Supported via journaling

### sandboxing service

Services like [Daytona](https://daytona.io), [E2B](https://e2b.dev), [Modal](https://modal.com).

There are similar challenges, more setup complexity but lower network latency for setting up your own sandbox setup with k8s.

- **Language completeness**: Full CPython with any library
- **Security**: Professionally managed container isolation
- **Start latency**: Network round-trip and container startup time. I got ~1s cold start time with Daytona EU from London, Daytona advertise sub 90ms latency, presumably that's for an existing container, not clear if it includes network latency
- **FOSS**: Pay per execution or compute time, some implementations are open source
- **Setup complexity**: API integration, auth tokens - fine for startups but generally a non-start for enterprises
- **File mounting**: Upload/download via API calls
- **Snapshotting**: Possible with durable execution solutions like Temporal, also the services offer some solutions for this, I think based con docker containers

### YOLO Python

Running Python directly via `exec()` (~0.1ms) or subprocess (~30ms).

- **Language completeness**: Full CPython with any library
- **Security**: None - full filesystem, network, env vars, system commands
- **Start latency**: Near-zero for `exec()`, ~30ms for subprocess
- **Setup complexity**: None
- **File mounting**: Direct filesystem access (that's the problem)
- **Snapshotting**: Possible with durable execution solutions like Temporal
