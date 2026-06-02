"""Example: Allowlist specific external function calls.

Only the functions explicitly named in the policy can be called by
sandboxed code. This prevents an LLM from calling dangerous functions
even if they are registered.
"""

from pydantic_monty import Monty, Policy

# Policy: only allow fetch_weather and get_time
policy = Policy('''
    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "fetch_weather" };

    permit(principal, action == Monty::Action::"ext:call", resource)
    when { resource.name == "get_time" };
''')


# Define some external functions
def fetch_weather(city):
    return f'Sunny, 22C in {city}'


def get_time():
    return '2026-06-02T10:30:00Z'


def delete_database():
    return 'DATABASE DELETED!'  # This should never be callable


all_functions = {
    'fetch_weather': fetch_weather,
    'get_time': get_time,
    'delete_database': delete_database,
}

# Calling allowed functions works
m = Monty('fetch_weather("London")')
result = m.run(external_functions=all_functions, policy=policy)
print(f'fetch_weather: {result}')

m = Monty('get_time()')
result = m.run(external_functions=all_functions, policy=policy)
print(f'get_time: {result}')

# Calling a disallowed function is blocked
m = Monty('delete_database()')
try:
    m.run(external_functions=all_functions, policy=policy)
    print('ERROR: delete_database should have been denied!')
except Exception as e:
    print(f'delete_database denied: {e}')

print('\nDone! Only allowlisted functions are callable.')
