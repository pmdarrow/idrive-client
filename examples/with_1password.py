#!/usr/bin/env python3
"""Read one explicitly selected 1Password item once, retain it only in memory.

Use --interactive for several CLI operations under a single 1Password read.
Use --binary to select another executable, such as target/release/idrive-bench.
No password is included in subprocess arguments, logs, environment, or files.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--account', required=True)
p.add_argument('--vault', default='Personal')
p.add_argument('--item', required=True)
p.add_argument('--interactive', action='store_true')
p.add_argument('--binary', type=Path, default=Path(__file__).resolve().parents[1] / 'target/release/idrive-rs',
               help='Executable to run (default: target/release/idrive-rs; use target/release/idrive-bench for benchmarks)')
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
result = subprocess.run(['op', 'item', 'get', a.item, '--account', a.account, '--vault', a.vault, '--format', 'json'], stdout=subprocess.PIPE, check=True)
item = json.loads(result.stdout)
fields = item.get('fields', [])
login = {name: next(f['value'] for f in fields if f.get('purpose') == purpose)
         for name, purpose in [('username', 'USERNAME'), ('password', 'PASSWORD')]}
# Release the original item and unrelated fields immediately.
del result, item, fields

def run(command):
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        command = ['help']
    return subprocess.run([str(a.binary), *command], input=json.dumps(login).encode()).returncode

if a.interactive:
    print(f'Credentials cached in this process. Enter arguments for {a.binary.name}; exit clears the session.', file=sys.stderr)
    while True:
        try:
            command = shlex.split(input(f'{a.binary.name}> '))
        except (EOFError, KeyboardInterrupt):
            break
        if command in (['exit'], ['quit']):
            break
        if command:
            run(command)
else:
    sys.exit(run(a.command))
