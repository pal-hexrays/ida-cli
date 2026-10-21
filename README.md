# icli

icli lets you analyse binaries with IDA Pro from the command line or from scripts, without opening the IDA window.

You can use it to:

- decompile and disassemble functions
- list functions, strings, imports and other objects
- find cross-references and build call graphs
- rename, comment, retype and patch, then undo these changes
- compare two versions of a binary
- run commands in batches, in scripts or in CI

## What you need

- IDA Pro 9.x with a licence that includes idalib
- [uv](https://docs.astral.sh/uv/)
- Python 3.12 or later

icli finds IDA through the `IDADIR` environment variable. If `IDADIR` is not set, icli uses the IDA folder recorded in `~/.idapro/ida-config.json`. To record it there, run IDA's `py-activate-idalib.py` script once.

## Install icli

```sh
git clone git@github.com:pal-hexrays/ida-cli.git
cd ida-cli
uv sync
```

Check that icli works:

```sh
uv run icli --help
```

## Examples

Describe a file without creating an IDA database:

```sh
uv run icli identify sample.o
```

Decompile a function:

```sh
uv run icli decompile sample.o main
```

List functions larger than 40 bytes:

```sh
uv run icli list functions sample.o --where 'size > 40'
```

Find what calls a function:

```sh
uv run icli xrefs sample.o check_update
```

Add a comment, see the change, then undo it:

```sh
uv run icli comment sample.o main "entry point"
uv run icli log sample.o
uv run icli undo sample.o
```

Run several commands while opening the database only once:

```sh
uv run icli do sample.o -- list functions --count :: resolve main
```

Run Python inside IDA:

```sh
uv run icli exec sample.o -c 'len(list(db.functions))'
```

## How output works

When you run icli in a terminal, it prints readable text. When you send its output to a file or another program, it prints one JSON object per line.

To choose the format yourself, use `--format`:

- `--format text` for readable text
- `--format json` for a single JSON document
- `--format jsonl` for one JSON object per line
- `--format csv` or `--format tsv` for tables

To see the JSON Schema of a command's output, run `icli schema COMMAND`, for example `icli schema decompile`.

## Where icli stores databases

The first time you use a binary, icli loads and analyses it, then saves the IDA database in a cache. Later commands on the same binary reuse that database.

The cache is in:

- `~/Library/Caches/icli` on macOS
- `~/.cache/icli` on Linux
- `%LOCALAPPDATA%\icli` on Windows

To save the database at a path you choose, use `--db`:

```sh
uv run icli --db sample.i64 analyze sample.o
```

Each command starts an IDA process, which takes about one second. If you run many commands, use `icli do`, `icli batch` or `icli serve` to keep the database open.

## Exit codes

icli returns an exit code that tells scripts what happened. For example, 0 means success, 1 means nothing was found, and 3 means only part of the work succeeded. For the full list, run:

```sh
uv run icli help exit-codes
```

## Get help

- `icli help` lists all commands.
- `icli help COMMAND` explains one command.
- `icli help TOPIC` explains a topic, such as `selectors`, `formats` or `examples`.

The full manual is in `src/icli/data/icli.1`. To read it as a man page, run `man src/icli/data/icli.1`.

## Configuration

icli reads settings from these files. When a setting appears in more than one place, the first one in this list wins:

1. options on the command line
2. `ICLI_*` environment variables
3. `.icli.toml` in the current folder or a parent folder
4. `icli.toml` in `$ICLI_HOME`, which defaults to `~/.idapro`
5. `cfg/icli.toml` in the IDA folder

To change a setting, use `icli config set`, for example:

```sh
uv run icli config set --global defaults.addr hex
```

## Limits

- IDA Teams (`vault`) and Lumina (`lumina`) commands are included but not tested against a live server.
- On macOS, debugging a local program needs Developer Mode. You can debug through a remote IDA debug server with `--remote host:port`.
- `--jobs` is accepted but does not run work in parallel.
- `export cpp` writes the same pseudocode as `export c`.

## How icli works

icli has two parts:

- **The client** (`src/icli/cli`) reads your command, prints the output and never loads IDA.
- **The engine** (`src/icli/engine`) runs inside an IDA process and uses [ida-domain](https://github.com/HexRaysSA/ida-domain) and the IDA Python SDK.

[ida-nexus](https://github.com/HexRaysSA/ida-nexus) starts the IDA process and passes requests between the two parts. If an IDA window with the ida-nexus plugin already has the same binary open, icli works in that window instead.

## Run the tests

```sh
uv run pytest
```

The tests in `tests/e2e` need IDA. The tests in `tests/unit` do not.
