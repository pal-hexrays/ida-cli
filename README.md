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

The full manual is at the [end of this README](#manual). Its source is `src/icli/data/icli.1`. To read it as a man page, run `man src/icli/data/icli.1`.

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

## Build a single-file binary

```sh
uv run --with pyinstaller pyinstaller icli.spec
```

The binary is `dist/icli`. It still needs IDA Pro installed on the computer that runs it.

CI builds binaries for Linux, Windows and macOS on every push. You can download them from the workflow run's artifacts.

## Make a release

Releases work as in ida-hcli. In GitHub, open **Actions**, choose **Release**, then **Run workflow**, and pick a release type:

- **dev** makes a pre-release, such as `0.1.1-dev.1`.
- **release-patch** makes the next patch version, such as `0.1.1`.
- **release-minor** makes the next minor version, such as `0.2.0`.

The workflow runs the unit tests, sets the new version, tags it, builds the six binaries and attaches them to a GitHub Release. The binaries are not signed yet, so macOS and Windows warn before running them.

## Run the tests

```sh
uv run pytest
```

The tests in `tests/e2e` need IDA. The tests in `tests/unit` do not.

To run the tests in `tests/e2e` against a binary, set `ICLI_BINARY` to its path.

## Manual

This is the icli(1) man page, converted from `src/icli/data/icli.1`.

### NAME

icli - IDA Pro command-line interface: non-interactive binary analysis, decompilation and annotation

### SYNOPSIS

```
icli [global-options] command [command-options] [target] [selector...]
icli do [global-options] target -- step [:: step]...
icli identify [options] file...
icli diff [options] old new
icli exec [options] target [-c code|file|-]
icli ref query
icli help [command|topic]
```

Commands, by group:

|  |  |
|:---|:---|
| triage | identify, info, loaders, processors |
| analysis | analyze, status |
| query | list, show, disasm, decompile, xrefs, callgraph, search, resolve |
| edit | rename, comment, type, func, make, patch, tag |
| journal | apply, log, undo |
| knowledge | sig, til, lumina, load |
| output | export |
| compare | diff, port |
| automation | do, batch, exec, ref, assert |
| dynamic | debug, trace |
| storage | db, cache, vault, serve |
| meta | config, schema, completion, legacy, help |

### DESCRIPTION

**icli** exposes the IDA kernel, the Hex-Rays decompilers, the type system, FLIRT, Lumina, IDA Teams and the debugger as small, composable commands that never open a window, never ask a question and never wait for a keystroke. Instructions come from the command line (and optionally standard input); results go to standard output; diagnostics go to standard error; every invocation ends with a documented exit status.

**icli** is built on idalib and is intended for shell pipelines, Makefiles, CI jobs and batch processing. For interactive text-mode use, see **idat**(1).

### CONCEPTS

#### Targets

A *target* names the database a command operates on. It may be:

*a database*  
(*app.i64*; a legacy *.idb* is upgraded on first write, see **db upgrade**).

*an input file*  
(*app.exe*, *libc.so.6*, *fw.bin*, *classes.dex*). **icli** looks up the cached database for that input (see **Database cache**) and creates it on demand.

*a container member*  
<i>container</i><b>::</b><i>member</i> selects one member of a multi-image input without extracting it: *app.apk::classes2.dex*, *dyld_shared_cache_arm64e::libsystem_kernel.dylib*, *Foo.app/Contents/MacOS/Foo::arm64* (fat slice), *firmware.zip::rootfs/bin/busybox*.

*a remote database*  
<b>vault://</b><i>site</i><b>/</b><i>path</i><b>\[@</b><i>rev</i><b>\]</b> checks a database out of an IDA Teams server (credentials from **VAULT\_\***, see **ENVIRONMENT**).

*a handle*  
<b>@</b><i>name</i> registered with **db tag**, or a bare **@** meaning “the target of the previous **icli** command in this shell”.

With no target, **icli** uses **\$ICLI_DB**, then the only *.i64* in the current directory, and otherwise fails with status 2.

#### Database cache

When the target is an input file and **--db** is not given, the database lives at *\$ICLI_CACHE_DIR/*xx*/*key*.i64*, where *key* is a hash of the input's SHA-256, every load option, and the kernel version. Re-running any command on an unchanged input reuses the analysed database; changing one byte, or one load option, yields a new one. **--db** *path* pins the location (to share it or keep it in a project); **--no-cache** analyses into a temporary database discarded on exit.

#### Analysis lifecycle

A database moves monotonically through four states, reported by **icli status**:

**loaded**  
The loader has mapped segments, applied fixups, created entries, imports and exports. No auto-analysis has run.

**analyzing**  
Auto-analysis queues are not empty (interrupted, or stopped by **--analysis-timeout**).

**analyzed**  
All queues are empty, including FLIRT, type library application and the final pass (**auto_is_ok**() in SDK terms).

**enriched**  
Optional passes requested with **analyze --with** (Lumina, PDB/DWARF, RTTI, language metadata, whole-program decompilation) have completed.

Every command declares the minimum state it needs and **icli** catches up first, printing progress on standard error. That is what makes **icli decompile ./a.out main** a valid first command on a never-seen file. **--analysis** **auto**\|**none**\|**wait** controls this (see **GLOBAL OPTIONS**).

#### Selections

Most commands take one or more *selectors*: expressions denoting a set of addresses, ranges, functions, names, strings, types or diff records. Several selectors are a union. A selector of **-** reads selectors from standard input, one per line; JSON objects with an **ea**, **start**, **from** or **to** field are accepted, so the output of one **icli** command feeds the next. The full grammar is in **SELECTORS**.

#### Fields

Every object **icli** knows about has named *fields*: **ea**, **name**, **size**, **xrefs_to**, **cyclomatic**, **pseudocode**, ... The same names are used as

- keys of **json**/**jsonl**/**csv** records,

- variables in selector predicates: **func:\*\[size \> 0x400 && xrefs_to \>= 10\]**,

- placeholders in text templates: **-t '{ea} {size:\>8} {name}'**,

- placeholders in edit arguments: **rename app.exe dummy 'f\_{hash:.8}'**,

- placeholders in output paths: **-o 'src/{name}.c'**.

See **FIELDS AND TEMPLATES**.

#### The journal

Edit commands are declarative: they state the desired end state. **icli rename app.exe 0x401000 parse_header** exits 0 whether or not the name was already *parse_header*, and reports **unchanged** in the latter case. Each effective change is appended to a journal stored inside the database (netnode **\$icli.journal**), so it travels with the file and through IDA Teams. Records carry revision, time, author, command, and before/after values. **log**, **undo** and **apply** read, revert and replay it.

#### Chains

**icli do** opens one database and runs a sequence of steps against it, strictly left to right, separated by **::**. Each step is an ordinary command with its target omitted. Selections and settings never leak between steps unless stated with **--keep-selection** (the result of the previous step becomes the selector **%**). Chains may be stored as *recipes* and invoked as <b>@</b><i>name</i> (see **icli do**).

#### Python

Anything the commands do not cover is done in Python, against the same database, with the IDA Domain API (**ida_domain**; see [](https://ida-domain.docs.hex-rays.com/)).

**icli exec**  
runs Python in the database's process with **db** (an ida-domain **Database**) and **ida_domain** pre-bound. Its return value becomes ordinary records, so the result flows back into **jq**, templates and **icli apply**.

**icli ref**  
searches the ida-domain API reference shipped with the installed IDA, by task or by name, and returns signatures with examples.

**--show-code**  
on any command prints the ida-domain code the command is equivalent to, so a command that almost does what you want can be copied and adapted.

Under **icli serve**, **exec** sessions keep their imports and variables between calls, and the same database can be served to **ida-mcp**(1) clients at the same time (see **icli serve --mcp**).

### GLOBAL OPTIONS

Global options precede the command name. Most can also be set in a configuration file or the environment (see **CONFIGURATION**).

<b>--db</b><i> path</i>  
Use or create the database at *path*, bypassing the cache.

**--no-cache**  
Analyse into a temporary database removed on exit.

**--read-only**  
Open read-only; any edit fails with status 13 (idat **-v**).

**--analysis** auto\|none\|wait  
**auto** (default) advances the database to the state the command needs. **none** never analyses; commands needing more fail with status 12. **wait** is **auto** but waits for another process that holds the database and is analysing, instead of failing with status 11.

<b>--analysis-timeout</b><i> duration</i>  
Stop advancing analysis after *duration* (**90s**, **15m**, **2h**). The database is saved in state **analyzing** and the command runs on the partial result, exiting 3.

<b>-f</b><i>,</i><b> </b><i>--format</i><b> fmt</b>  
Stream output format: **text**, **json**, **jsonl**, **csv**, **tsv**, **raw**. Default **text** on a terminal, **jsonl** otherwise. See **OUTPUT FORMATS**.

<b>-t</b><i>,</i><b> </b><i>--template</i><b> tmpl</b>  
Render each record through a text template instead of **--format**. See **FIELDS AND TEMPLATES**.

<b>--fields</b><i> list</i>  
Fields to emit, in order (**--fields=ea,name,size**). **icli schema** lists the valid fields per command.

<b>--schema-version</b><i> N</i>  
Emit records using major schema version *N* (default: newest).

**--no-header**  
Omit header rows in **csv**/**tsv**/**text**.

**-0**, **--null**  
Terminate records with NUL (for **xargs -0**).

<b>--addr</b><i> style</i>  
How addresses print: **hex** (default, **0x401000**), **bare**, **seg** (**.text:00401000**), **rva** (from image base), or **file** (input file offset; empty if not file-backed).

**--color** auto\|always\|never  
Colorise text output, using IDA's color tags for listings and pseudocode. Honours **NO_COLOR**.

**-q**, **--quiet**  
No progress or informational messages. Errors still print.

**-v**, **--verbose**  
More messages; repeat for kernel output (**-vv** shows the IDA output window, **-vvv** adds loader and plugin debug output, like idat **-z**).

<b>--log</b><i> file</i>  
Append all kernel messages to *file* (idat **-L**; default **\$IDALOG**).

<b>--set</b><i> KEY</i><b>=</b><i>VALUE</i>  
Override a configuration directive for this invocation. Unqualified keys target *ida.cfg*; a prefix selects another file: **hexrays.MAX_FUNCSIZE=128**, **dwarf.DWARF_LOAD_LOCALS=NO**, **lumina.LUMINA_TLS=YES**. Flag words accept named bits: **ANALYSIS=+FLIRT,-UNK**, **hexrays.HEXOPTIONS=-COLLAPSE_LVARS**. Unknown keys are an error (status 2), because a mistyped override is the commonest cause of “it did nothing”. Replaces idat **-d** and **-D**; **icli** picks the right timing itself.

<b>--plugin-opt</b><i> name</i><b>:</b><i>option</i>  
Pass an option to a plugin (idat **-O**).

<b>-j</b><i>,</i><b> </b><i>--jobs</i><b> n</b>  
Worker threads for parallel work (**decompile --all**, **export c**, **diff**, **sig make**, **lumina pull**). Default: number of CPUs. Never changes results, only speed.

<b>-C</b><i> dir</i>  
Change to *dir* first, like **git -C**.

**--no-server**  
Do not forward to a running **icli serve**.

**--no-plugins**  
Load only plugins the command strictly requires.

**--dry-run**  
For edits: print the journal records that would be written and change nothing. Exit 0 if there would be changes, 1 if the edit is a no-op.

**--strict**  
Promote warnings to errors: a selector matching nothing, an ambiguous demangled name, a truncated type, pseudocode containing **JUMPOUT** or **\_\_asm**.

**--allow-execute**  
Permit commands that run the target program (**debug**, **trace**). Without it they exit 2.

**--show-code**  
Do not run the command; print the ida-domain Python it is equivalent to, ready for **icli exec**. Selectors and predicates are expanded into explicit loops and filters. Exit 0.

**--version**  
Print the **icli** version, kernel version and build, edition (Pro, Home, Free, Classroom), available decompilers, and exit.

### LOAD OPTIONS

Accepted by every command whose target is an input file. They are part of the cache key. On an existing database they are an error (status 2) unless they match how it was loaded.

<b>--loader</b><i> name</i>  
Force a loader by module name: **pe**, **elf**, **macho**, **coff**, **dex**, **dsc** (dyld shared cache), **uefi_fv**, **wasm**, **windmp**, **omf**, **ne**, **lx**, **xbe**, **hexagon_mbn**, **ihex**, **ar**, or **binary** for a flat file. **icli loaders** *file* shows which loaders accept a file, in the order the GUI would offer them.

<b>--processor</b><i> name\[:variant\]</i>  
Force a processor module: **metapc**, **arm**, **arm:ARMv7-M**, **mips**, **mipsl**, **ppc**, **ppcl**, **riscv**, **arc**, **tricore**, **hexagon**, **xtensa**, **v850**, **m68k**, **8051**, **dalvik**, **java**, **cli**, **wasm**, ... **icli processors** lists them.

**--bitness** 16\|32\|64, **--endian** little\|big  
Defaults for raw images and bi-endian processors.

<b>--base</b><i> addr</i>  
Load address in bytes (idat **-b** used paragraphs).

<b>--entry</b><i> addr</i>  
Entry point for flat binaries.

<b>--compiler</b><i> id\[:abi\]</i>  
Compiler and ABI: **gcc**, **clang**, **visual**, **borland**, **watcom**; e.g. **gcc:lp64**.

<b>--segment</b><i> name</i><b>=</b><i>start-end\[:class\]\[:perm\]\[@file\[:offset\]\]</i>  
Create a segment, optionally backed by *file* (repeatable). Describes bootrom + flash + SRAM + MMIO layouts in one command.

<b>--svd</b><i> file.svd</i>  
Import a CMSIS-SVD peripheral description.

<b>--load-opt</b><i> loader</i><b>.</b><i>key</i><b>=</b><i>value</i>  
Loader-specific options: **pe.resources=yes** (idat **-R**), **macho.all_slices=yes**, **elf.debug_dir=/usr/lib/debug**, **dsc.modules=libsystem_c.dylib,libobjc.A.dylib**.

<b>--symbols</b><i> src\[,src...\]</i>  
Debug information sources: **auto** (default), **none**, *file.pdb*, *file.debug*, *Foo.dSYM*, **symsrv** (Microsoft symbol server via **\_NT_SYMBOL_PATH**), **debuginfod** (by build-id via **DEBUGINFOD_URLS**).

<b>--encoding</b><i> name</i>  
Default string encoding (**utf-8**, **cp1252**, **utf-16le**, ...).

**--no-segmentation**  
Do not create segmentation (idat **-x**).

<b>--pack</b><i> compress\|pack\|none</i>  
How the database is saved (idat **-P+**, **-P**, **-P-**).

### COMMANDS

Every command accepts **-h**/**--help**. Below, *target* is as in **Targets** and *sel* is a selector. Commands that accept selectors accept **-** for standard input.

#### Triage

<b>icli identify \[<b>--hash</b> <i>algo</i>,...\] \[<b>--deep</b>\] <i>file</i>...</b>  
Describe files **without creating a database:** only the loaders' **accept_file** probes, compiler and packer heuristics, and hashing run. One record per file: **path**, **loader**, **loaders** (all accepting), **format**, **arch**, **bitness**, **endian**, **compiler**, **packer**, **size**, **entropy**, **sections** (with per-section entropy), **md5**, **sha1**, **sha256**, **imphash**, **tlsh**, **ssdeep**, **pdb** (path and GUID), **build_id**, **signed**, **signer**, **n_imports**, **n_exports**. **--deep** also runs the loader in a scratch database to count functions and strings. Exits 1 if any file was accepted by no loader. Takes thousands of files per minute; this is the corpus-triage entry point.

<b>icli info <i>target</i></b>  
Summarise a database: input name, size, hashes, loader, processor, bitness, endianness, compiler/ABI, image base, entry points, counts (segments; functions total/library/named/thunk; strings; types), applied signatures and type libraries, debug info found, lifecycle state, creating and last-saving IDA version, cache key.

<b>icli loaders \[<i>file</i>\]</b>  
List loaders; with a file, those accepting it with the formats and processors they propose, in priority order.

<b>icli processors \[<i>glob</i>\]</b>  
List processor modules, variants, and which have a decompiler and an assembler.

#### Analysis

<b>icli analyze \[<i>options</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
Bring the database to **analyzed**. With selectors, (re)queue only those ranges.

**--reanalyze**  
Discard analysis results and run auto-analysis again, keeping user edits (re-applied from the journal).

<b>--with</b><i> pass\[,pass...\]</i>  
Optional passes; moves to **enriched**: **lumina** (pull and apply metadata), **pdb**, **dwarf**, **rtti** (C++ class hierarchies), **eh** (exception tables), **golang**, **rust**, **swift**, **objc**, **findmain** (locate and name the real **main**), **decompile** (decompile everything once to propagate types).

<b>--without</b><i> pass\[,pass...\]</i>  
Disable a default pass (**--without=flirt**).

<b>--sig</b><i> name</i><b> , </b><i>--til</i><b> name</b>  
Extra FLIRT signature / type library to apply during analysis (repeatable).

**--progress**  
Progress as JSON lines on standard error:

    {"_t":"progress","queue":"code","ea":"0x4012a0","pct":42}

<b>icli status <i>target</i></b>  
Lifecycle state, pending items per analysis queue, lock holder (pid, host or server socket), journal length, dirtiness relative to a vault revision. Exits 0 if **analyzed** or later, 3 otherwise.

#### Query

<b>icli list <i>kind</i> \[<i>options</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
List objects of *kind*, restricted to the selectors if given. *kind* is one of: **functions**, **names**, **strings**, **imports**, **exports**, **entries**, **segments**, **xrefs**, **types**, **tils**, **sigs**, **comments**, **bookmarks**, **tags**, **problems**, **fixups**, **blocks**, **patches**, **lvars** (decompiler local variables), **switches**.

<b>--where</b><i> expr</i>  
Filter with a predicate over the kind's fields: **'size \> 0x400 && !lib'**, **'module ~ "(?i)ws2_32"'**. Same language as selector predicates.

<b>--match</b><i> glob</i><b>, </b><i>--regex</i><b> re</b>  
Filter by name.

<b>--sort</b><i> field\[:desc\]</i>  
Order (default: by address).

<b>-n</b><i>,</i><b> </b><i>--limit</i><b> N</b>  
At most *N* records.

**--count**  
Print only the count.

**--demangle** \| **--no-demangle**  
Name style (default: as configured).

<b>icli show <i>target</i> sel...</b>  
Everything known about each address: segment, flags, item kind and size, name, owning function, comments, operand representations, xrefs both ways, type; for functions also prototype, frame layout and chunks.

<b>icli disasm \[<i>options</i>\] <i>target</i> sel...</b>  
Disassembly. A selector naming a function prints the whole function, chunks included.

**--bytes** \[*N*\]  
Show opcode bytes.

**--no-xrefs**, **--no-comments**, **--no-prefix**  
Trim the listing.

<b>--syntax</b><i> name</i>  
Assembler dialect offered by the module (**masm**, **gas**, **intel**, **att**).

**--graph** \[dot\|gdl\|json\]  
Basic-block graph instead of a listing.

**--microcode**\[=*maturity*\]  
Hex-Rays microcode at **generated**, **preoptimized**, **locopt**, **calls**, **glbopt1**, **glbopt2**, **glbopt3**, or **lvars**.

In **json** each record is one instruction: **ea**, **size**, **bytes**, **mnem**, **operands** (text, type, value), **text**.

<b>icli decompile \[<i>options</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
Decompile the functions containing the selected addresses with the decompiler matching the processor.

**--all**  
Every non-library function, in parallel with **-j**.

**--with-types**  
Prefix the output with the declarations of every user type referenced, giving a self-contained C file.

**--at-line**  
For each selected address print only the pseudocode line(s) it maps to, prefixed by the function name. Ideal for call sites piped from **xrefs**.

**--ctree**  
Emit the ctree as JSON (node, ea, type, children).

**--line-map**  
In **json** output, map each line to the addresses it covers and each local variable to its storage.

**--fresh**  
Ignore pseudocode cached in the database.

<b>--hexrays-option</b><i> \[+\|-\]NAME,...</i>  
Toggle **HEXOPTIONS** bits for this run.

Failures do not abort **--all**: each failed function yields a record with **status=failed**, **hexrays_err** and the failing address; exit status is 3. A single requested function that fails exits 8.

<b>icli xrefs \[<b>--to</b>\|<b>--from</b>\] \[<b>--type</b> <i>t</i>\] \[<b>--depth</b> <i>N</i>\] <i>target</i> sel...</b>  
Cross-references to (default) or from the selection; types **call**, **jump**, **flow**, **read**, **write**, **offset**, **text**, **info**. Records: **from**, **to**, **type**, **func_from**, **func_to**, **user**.

<b>icli callgraph \[<b>--callers</b>\|<b>--callees</b>\] \[<b>--depth</b> <i>N</i>\] \[<b>--graph</b> <i>dot</i>\|<i>gdl</i>\|<i>json</i>\] <i>target</i> sel...</b>  
Call graph rooted at the selected functions.

<b>icli search \[<i>options</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
Search the selected ranges (default: everything). Exactly one of: <b>--bytes</b><i> "55 8B EC ?? ?? 83"</i> (IDA binary pattern), <b>--imm</b><i> value</i><b>,</b> <b>--insn</b><i> "call \*ds:\*Alloc\*"</i> (instruction pattern), <b>--text</b><i> re</i> (over listing lines), <b>--pseudo</b><i> re</i> (over pseudocode; decompiles as needed), <b>--string</b><i> re</i> (over string literals, reporting referencing functions), **--crypto** (known constants: AES S-boxes, SHA/MD5 IVs, CRC tables, ...).

<b>icli resolve \[<b>--ranges</b>\] <i>target</i> sel...</b>  
Evaluate selectors and print the resulting addresses. The canonical way to test a selector and to turn names into addresses for other tools. Exits 1 if the result is empty.

#### Edit

All edit commands are idempotent, accept **--dry-run** and <b>--message</b><i> text</i> (journal annotation), print one record per change (or **unchanged**), and expand **{field}** templates per selected item. A value previously set by a user (as opposed to auto-analysis) is only overwritten with **--force**; otherwise the conflict exits 9.

<b>icli rename \[<i>options</i>\] <i>target</i> sel name</b>\
<b>icli rename \[<i>options</i>\] <i>target</i> <b>-</b>\|<i>map.tsv</i></b>  
Set names. From a file or standard input, each line is <i>sel</i><b>\t</b><i>name</i> or a JSON object with **ea** and **name**. *name* is a template: **'f\_{hash:.8}'** names each function after its body hash, stable across builds. Options: **--local**, **--public**, **--weak**, <b>--regex</b><i> s/re/repl/</i> (rewrite existing names), <b>--lvar</b><i> func</i> (rename a decompiler local variable), **--unique** (suffix **\_1**, **\_2** on collision instead of failing), **--clear** (restore the dummy name).

<b>icli comment \[<b>--kind</b> <i>k</i>\] \[<b>--append</b>\] <i>target</i> sel text</b>  
Set a comment; *k* is **regular**, **repeatable**, **anterior**, **posterior**, **function**, or **pseudocode** (attached to the ctree item at that address). Empty *text* removes it.

<b>icli type <i>subcommand</i> ...</b>  
> <b>type set <i>target</i> sel decl</b>  
> Apply a C declaration to an address, function or local variable. *decl* is a template: **'NTSTATUS \_\_stdcall {name}(PDEVICE_OBJECT, PIRP)'**. **--propagate** re-decompiles callers so the new type flows outward.
>
> <b>type get <i>target</i> sel</b>  
> Print the type at an address.
>
> <b>type add <i>target</i> <i>file.h</i>\|<b>-</b></b>  
> Parse declarations into local types using the clang-based parser (**--parser=legacy** for the old one). **-I**, **-D** and **--target** *triple* are passed to the preprocessor. Identical types are left alone; a conflicting definition exits 9 unless **--replace**.
>
> <b>type import <i>target</i> source name...</b>  
> Copy types from a type library or another database.
>
> <b>type del <i>target</i> name...</b>  
> Delete local types.
>
> <b>type dump <i>target</i> \[<i>name</i>...\]</b>  
> Print local types as a compilable, topologically sorted C header.
>
> <b>type op <i>target</i> sel <b>--operand</b> <i>N</i> <b>--as</b> <i>kind</i>\[<b>:</b><i>arg</i>\]</b>  
> Operand representation: **hex**, **dec**, **char**, **offset\[:base\]**, **enum:name**, **stroff:struct**, **stkvar**.
>
> <b>type callsite <i>target</i> sel decl</b>  
> Override the prototype at one call site.

<b>icli func <b>create</b>\|<b>delete</b>\|<b>set</b>\|<b>tail</b> ...</b>  
Create a function (**--end** optional), delete it (keeping instructions), change bounds, flags (**--flags +noret,-lib**) or frame, add/remove chunks.

<b>icli make <i>kind</i> target sel \[<i>options</i>\]</b>  
Convert items: **code** (and analyse onward), **byte**, **word**, **dword**, **qword**, **float**, **double**, **string** \[**--encoding**\], **array --count** *n*, <b>struct --type </b><i>name</i><b>,</b> **offset** \[**--base**\], **align**, **unknown** (undefine); **--jumptable** *spec* declares a switch table.

<b>icli patch <i>subcommand</i> ...</b>  
> <b>patch bytes <i>target</i> sel hex</b>  
> Patch bytes in the database.
>
> <b>patch asm <i>target</i> sel insn...</b>  
> Assemble and patch (processors with an assembler).
>
> <b>patch nop <i>target</i> sel</b>  
> Replace items with same-length NOPs.
>
> <b>patch revert <i>target</i> \[<i>sel</i>...\]</b>  
> Restore original bytes.

Writing the patched file is an export: **icli export exe**, **icli export dif**.

<b>icli tag \[<b>--remove</b>\] \[<b>--color</b> <i>rrggbb</i>\] <i>target</i> sel tag...</b>  
Attach free-form tags (and optionally a background colour) to items. Tags are selectable (**tag:crypto**) and survive in the database. Bookmarks are tags named <b>bookmark:<i>text</i></b>.

#### Journal

<b>icli apply \[<i>options</i>\] <i>target</i> \[<i>journal.jsonl</i>\|<b>-</b>\]</b>  
Replay journal records (any record an edit command emits, and any query record that carries the same fields). **--on-conflict=fail\|skip\|ours\|theirs**; **--only rename,type** (restrict kinds); **--rebase** translates addresses when the target has a different base or is a different build, using function matching (see **diff**).

<b>icli log \[<b>--since</b> <i>rev</i>\|<i>time</i>\] \[<b>--author</b> <i>u</i>\] \[<b>--kind</b> <i>k</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
Print the journal, oldest first: an audit log of who changed what.

<b>icli undo \[<b>--to</b> <i>rev</i>\|<b>-n</b> <i>N</i>\] <i>target</i></b>  
Revert the last *N* entries (default 1) by applying their inverses, which are themselves journaled.

#### Knowledge

<b>icli sig <i>subcommand</i> ...</b>  
FLIRT signatures.

<b>sig apply <i>target</i> name...\|<b>auto</b></b>  
Apply *.sig* files by name (searched in *\$IDAUSR/sig/proc* then *\$IDADIR/sig/proc*) or path; **auto** uses the loader's startup signatures. Reports matches per file.

<b>sig match <i>target</i> name...</b>  
What a signature file would rename, without applying.

<b>sig make \[<i>options</i>\] <b>-o</b> <i>out.sig</i> <i>source</i>...</b>  
Build signatures from databases or static libraries (*.a*, *.lib*; loaded with the **ar** loader). <b>--library-name</b><i> text</i><b>,</b> <b>--select</b><i> sel</i> (which functions), **--pat-only** (stop at *.pat*), **--collisions** fail\|skip\|first (replaces the interactive *.exc* editing step of **sigmake**(1)).

<b>sig list \[<b>--processor</b> <i>p</i>\]</b>  
Available signature files and their library names.

<b>icli til <i>subcommand</i> ...</b>  
Type libraries: **list** (available *.til*), **dump** *file.til* \[*name*...\] (as C), **make** <b>-o</b><i> out.til</i> \[**--target** *triple*\] \[**-I** *dir*\] *header*... (replaces **tilib**(1) for the common case), **merge** <b>-o</b><i> out.til</i> *in.til*..., **export** *target* <b>-o</b><i> out.til</i> (local types as a library).

<b>icli lumina <i>subcommand</i> ...</b>  
Lumina, using the server from *ida.cfg* or <b>--server</b><i> host</i><b>:</b><i>port</i><b>.</b>

<b>lumina pull \[<b>--apply</b>\] <i>target</i> \[<i>sel</i>...\]</b>  
Fetch metadata for the selected (default: all) functions. Without **--apply**, print candidates (name, prototype, comments, frame, **score**) as records ready for review and **icli apply**.

<b>lumina push <i>target</i> \[<i>sel</i>...\]</b>  
Push metadata of selected user-named functions; refuses dummy names.

<b>lumina del\|<b>history</b> <i>target</i> sel...</b>  
Delete own metadata; show a function's history.

<b>icli load <i>kind</i> target file \[<i>options</i>\]</b>  
Add data to an existing database: **pdb**, **dwarf** (separate debug file or .dSYM), **svd**, **map** (linker map), **idc**, **names** (address/name CSV or MAP), **coverage** (drcov, lighthouse; sets the **coverage** field), **binary** <b>--at</b><i> addr</i> (another blob as a segment), **snapshot** (memory dump).

#### Output

<b>icli export <i>format</i> \[<i>options</i>\] <i>target</i> \[<i>sel</i>...\]</b>  
Produce a file from the database to **-o** *path* (standard output by default). The format is named explicitly; it is never guessed from the extension. Formats that take a selector honour it; the others write the whole database. **-o** accepts templates: with a per-item template such as **-o 'src/{name}.c'**, one file is written per selected item. See **Export formats** under **OUTPUT FORMATS**.

#### Compare

<b>icli diff \[<i>options</i>\] <i>old</i> new</b>  
Compare two databases (or input files, analysed first) function by function. Records have **diff** = **identical**, **changed**, **added**, **removed**, **renamed**, plus **similarity** (0.0-1.0), **ea**, **other_ea**, and **changed_blocks**. Exit 0 if identical, 1 if differences were found (like **diff**(1)).

<b>--match</b><i> strategy\[,strategy...\]</i>  
Matching rounds in order: **name**, **hash** (operand-agnostic body hash), **flirt**, **lumina**, **structural** (CFG and call-graph neighbourhood, constants, strings). Default: **name,hash,lumina,structural**.

<b>--threshold</b><i> score</i>  
Minimum similarity for **changed** (default 0.6).

**--pseudocode**, **--asm**  
Attach a unified diff of pseudocode or normalised disassembly to each changed function.

<b>--emit-journal</b><i> file</i>  
Write journal records that port *old*'s user names, types and comments onto *new*.

<b>icli port \[<b>--what</b> <i>names</i>,<i>types</i>,<i>comments</i>,<i>tags</i>\] \[<b>--match</b> <i>...</i>\] <i>from</i> to</b>  
Shorthand for **diff --emit-journal** piped into **apply --rebase**: carry annotations from an analysed build onto a new one in one step. Edits land in *to*'s journal and can be reviewed with **log** or reverted with **undo**.

#### Automation

<b>icli do \[<b>--keep-going</b>\] <i>target</i> <b>--</b> <i>step</i> \[<b>::</b> <i>step</i>\]...</b>\
<b>icli do <i>target</i> <b>@</b><i>recipe</i> \[<i>step</i>...\]</b>  
Open *target* once and run each *step* — any command line with the target omitted — left to right. This is the ordered-pipeline mode: one load, many operations, many outputs.

- Analysis runs only where a step needs it, so steps before the first query can change how analysis proceeds (apply types, signatures, segments).

- A step's selector may be **%**, meaning the records produced by the previous step.

- The database is saved once, at the end, and only if every step succeeded (or **--keep-going** was given). **--no-save** discards all changes; useful for pure reports.

- A recipe is a file in *\$IDAUSR/icli/recipes/* (*name*.icli) with one step per line; <b>@</b><i>name</i> splices it in.

<b>icli batch \[<b>--keep-going</b>\] <i>target</i> \[<i>file</i>\|<b>-</b>\]</b>  
Like **do**, but steps are read one per line from a file or standard input; each step's records are written as they complete, tagged with **step**. For programs that drive **icli** interactively without IDAPython.

<b>icli exec \[<i>options</i>\] <i>target</i> \[<b>-c</b> <i>code</i> \| <i>file.py</i> \| <b>-</b>\] \[<b>--</b> <i>args</i>...\]</b>  
Run Python against the database, after bringing it to **analyzed**. Semantics match the **execute_python** tool of **ida-mcp**(1). API documentation: [](https://ida-domain.docs.hex-rays.com/).

- **db** is the current ida-domain **Database**; **ida_domain** and the classic **ida\_\*** modules are importable as usual.

- If the code ends with an expression, its value is the result. Otherwise, if it defines **run(db)**, **main(db)** or **execute(db)**, that function is called and its return value is the result.

- The result becomes records: a mapping is one record, an iterable of mappings is a stream, and a scalar is **{"\_t":"value","value":...}**. Records that carry **ea** and journal fields (**name**, **type**, **comment**, ...) can be piped straight into **icli apply**.

- The code's own **stdout** and **stderr** are kept apart from the results: with **-f json** they are returned as **stdout** and **stderr** fields, otherwise they are passed through to standard error.

- Changes the code makes are journaled as one **exec** record holding the code's SHA-256 (and the code itself unless **--no-record-code**), so **icli undo** reverts a whole **exec** at once.

Options:

<b>-c</b><i> code</i>  
Code on the command line. Otherwise a file, or **-** for standard input.

<b>--each</b><i> sel</i>  
Run once per selected item with **item** (the record, with all its fields) and **ea** bound; results are concatenated.

<b>--session</b><i> name</i>  
Keep imports, variables and definitions between calls. Requires **icli serve**; the session lives as long as the server's lease. Without it every call starts with fresh globals.

<b>--timeout</b><i> duration</i>  
Abort the code after *duration* (default 6m; the initial analysis wait is not counted). The database is rolled back to the state before the call.

**--read-only**  
Fail with status 13 if the code tries to modify the database.

**--no-save**  
Discard the code's changes after it returns.

**--lang** py\|idc  
IDC instead of Python (only a trailing expression is supported).

**sys.argv** receives *args*; <b>sys.exit(<i>n</i>)</b> and <b>qexit(<i>n</i>)</b> set the exit status. An uncaught exception exits 16 with the traceback on standard error.

<b>icli ref \[<b>-n</b> <i>N</i>\] \[<b>--full</b>\] <i>query</i>...</b>  
Search the ida-domain API reference of the **installed** IDA (so it never disagrees with the API it describes), by task or by name:

    icli ref "decompile function"
    icli ref xrefs to address
    icli ref Functions.get_callers

Each hit gives a signature, a one-line description and a short example. **--full** prints the whole entry; **-f jsonl** returns records with **symbol**, **signature**, **doc**, **example**. Works offline and without a target. The index is the one served by the **reference** tool of **ida-mcp**(1); the full documentation is at [](https://ida-domain.docs.hex-rays.com/).

<b>icli assert <i>target</i> sel cond</b>  
Check a condition on the size of a selection and exit 1 if it fails; *cond* is (**==**\|**!=**\|**\<**\|**\<=**\|**\>**\|**\>=**) *n*. **icli assert app.exe 'func:\*\[hexrays_err != 0\]' '\<= 3'** fails a CI job when more than three functions stop decompiling. Exit 0 prints nothing; exit 1 prints the offending items.

#### Dynamic

These commands execute the target program and require **--allow-execute**. Backends: **linux**, **win32**, **mac**, **gdb**, **windbg**, **bochs**, **dalvik**, **pin**, **replay**; remote with <b>--remote</b><i> host</i><b>:</b><i>port</i> and **\$ICLI_DEBUG_PASSWORD** (idat **-r**).

<b>icli debug run \[<b>--debugger</b> <i>d</i>\] \[<b>--break</b> <i>sel</i>\[<b>:</b><i>cond</i>\]...\] \[<b>--regs</b> <i>list</i>\] \[<b>--dump</b> <i>expr</i><b>:</b><i>size</i>\] \[<b>--timeout</b> <i>t</i>\] <i>target</i> \[<b>--</b> <i>args</i>...\]</b>  
Start the program; at each breakpoint emit a record (thread, address, registers, memory, stack trace) and continue. Unanswerable debugger prompts take their defaults from *exceptions.cfg*. Exit 10 on timeout.

<b>icli debug attach \[<b>--pid</b> <i>N</i>\|<b>--name</b> <i>proc</i>\] <i>target</i> \[<i>as</i> for run\]</b>  
Attach to a running process.

<b>icli debug snapshot \[<b>--at</b> <i>sel</i>\] <i>target</i></b>  
Run to an address (default: entry), copy process memory into the database, and mark the database for reanalysis.

<b>icli trace \[<b>--mode</b> <i>insn</i>\|<i>block</i>\|<i>func</i>\] \[<b>--range</b> <i>sel</i>\] \[<b>--coverage</b>\] <i>target</i> \[<b>--</b> <i>args</i>...\]</b>  
Record an execution trace as records; **--coverage** emits only executed basic blocks and fills the **coverage** field.

#### Storage

<b>icli db <i>subcommand</i> ...</b>  
> <b>db path <i>target</i></b>  
> Print the database path (computes the cache key; creates nothing).
>
> <b>db create <i>target</i> <b>-o</b> <i>db.i64</i></b>  
> Load and analyse into an explicit file.
>
> **db pack** \[**--mode** compress\|pack\] *db*, <b>db unpack <i>db</i></b>  
> Convert between a single *.i64* and its components (*.id0*, *.id1*, *.id2*, *.nam*, *.til*).
>
> <b>db upgrade \[<b>-o</b> <i>out.i64</i>\] <i>old.idb</i></b>  
> Convert 32-bit *.idb* and older formats to the current *.i64*.
>
> <b>db check <i>db</i></b>  
> Verify b-tree integrity; exit 14 if corrupt.
>
> <b>db gc <i>db</i></b>  
> Compact the b-tree.
>
> <b>db tag <i>name</i> target</b>  
> Register a handle usable as <b>@</b><i>name</i><b>.</b>
>
> <b>db copy <i>src</i> dst</b>  
> Copy safely while in use (takes a read lock).
>
> <b>db unlock \[<b>--force</b>\] <i>db</i></b>  
> Remove a stale lock (verifies the holder is gone unless **--force**).

<b>icli cache ls\|<b>rm</b> <i>target</i>\|<b>key</b> <i>target</i>\|<b>prune</b> \[<b>--older-than</b> <i>d</i>\] \[<b>--max-size</b> <i>s</i>\] \[<b>--orphans</b>\]</b>  
Inspect and maintain the database cache.

<b>icli vault <i>subcommand</i> ...</b>  
IDA Teams, mirroring **hv**(1): **sync**, **checkout**, **add**, **commit**, **revert**, **diff**, **log**, **info**. **vault merge** performs the three-way database merge non-interactively; conflicts are records, resolved by **--strategy=ours\|theirs\|fail**. **vault commit** refuses a database in state **analyzing** unless **--force**.

<b>icli serve \[<i>options</i>\] <i>target</i>...</b>  
Keep databases open in a background process listening on a Unix socket (named pipe on Windows) at *\$XDG_RUNTIME_DIR/icli/*key*.sock*. Every **icli** command on a served database is forwarded transparently: no load, no b-tree warm-up, millisecond answers. **--detach**, <b>--idle-timeout</b><i> d</i> (default 30m), <b>--save-every</b><i> d</i><b>,</b> <b>--listen</b><i> addr</i> (TCP, requires **--token-file**), **--stop**.

The server is an ida-nexus database service: it owns the workers, leases and cancellation, and attaches to a database already open in the IDA GUI instead of opening a second copy. **--mcp** \[*stdio*\|<i>http:<i>addr</i></i>\] also exposes the same session as an MCP server with the **ida-mcp**(1) tool set; edits from MCP clients land in the same journal.

#### Meta

<b>icli config get\|<b>set</b>\|<b>unset</b>\|<b>list</b> \[<b>--global</b>\|<b>--project</b>\] \[<i>key</i> \[<i>value</i>\]\]</b>  
Read and write **icli** configuration (*ida.cfg* is never written; use **--set**).

<b>icli schema \[<i>command</i> \[<i>kind</i>\]\]</b>  
JSON Schema of the records a command emits (**icli.function/1**, **icli.xref/1**, ...).

<b>icli completion bash\|<b>zsh</b>\|<b>fish</b>\|<b>powershell</b></b>  
Shell completion; names and selectors complete against the database of the target already on the command line.

<b>icli help \[<i>command</i>\|<i>topic</i>\]</b>  
Topics: **selectors**, **fields**, **templates**, **formats**, **exit-codes**, **journal**, **cache**, **recipes**, **settings**, **exec**.

### SELECTORS

A selector denotes a set of items. It is evaluated against the database after it reaches the state the command needs, and is a *snapshot:* inside **icli do**, a later step re-evaluates its own selectors against the then-current database.

#### Address atoms

|  |  |
|:---|:---|
| **`0x401000`**, **`401000h`**, **`0x8000_1234`** | linear address (**`_`** ignored) |
| **`0d4198400`** | decimal; a bare decimal is rejected as ambiguous |
| **`main`**, **`?OnPaint@CView@@MAEXPAVCDC@@@Z`** | name, mangled or demangled |
| **`"CView::OnPaint"`** | demangled name (all overloads) |
| **`.text:401000`**, **`seg000:0100`** | segment-relative |
| **`rva:0x1000`**, **`off:0x400`** | image-base relative; input file offset |
| **`main+0x2c`**, **`$entry-4`** | arithmetic on any atom |
| **`$entry $base $min $max`** | entry point, image base, bounds |

#### Ranges

|                      |                           |
|:---------------------|:--------------------------|
| **`0x1000..0x2000`** | half-open \[start, end)   |
| **`0x1000+0x100`**   | start and size            |
| **`main..`**         | to the end of the segment |

#### Typed selectors

|  |  |
|:---|:---|
| <b>`func:`</b><i>glob</i> | functions by name (**`func:*`** all) |
| <b>`func@`</b><i>addr</i> | the function containing *addr* (all chunks) |
| <b>`seg:`</b><i>name</i> | a segment (**`seg:.text`**, **`seg:__TEXT.__text`**) |
| <b>`name:`</b><i>glob</i> | any named item |
| <b>`str:`</b><i>glob</i> | string literals by value |
| <b>`imp:`</b><i>mod</i><b>`!`</b><i>sym</i> | imports (**`imp:*!recv`**, **`imp:kernel32!Create*`**) |
| <b>`exp:`</b><i>glob</i> | exports |
| **`entry`** | entry points, TLS callbacks, init arrays |
| <b>`type:`</b><i>glob</i> | local types; data items of that type |
| <b>`bytes:`</b><i>hex</i> | addresses where a byte pattern occurs |
| <b>`tag:`</b><i>t</i> | items tagged with **icli tag** |
| **`lib thunk noret dummy named`** | function classes |
| **`patched lumina problem`** | patched bytes; Lumina-enriched; problem list |
| <b>`diff:`</b><i>class</i> | diff records (**`changed`**, **`added`**, ...) |
| <b>`@`</b><i>file</i> | selectors listed in a file, one per line |
| **`%`** | the previous step's records (**icli do** only) |
| **`-`** | standard input |

Globs are the default; <b>/</b><i>re</i><b>/\[i\]</b> gives a regular expression: **func:/^ssl\_/i**.

#### Graph operators

|  |  |
|:---|:---|
| <b>`callers(`</b><i>s</i><b>`)`</b><i>,</i> <b>`callees(`</b><i>s</i><b>`)`</b> | direct callers / callees of functions in *s* |
| <b>`callers(`</b><i>s</i><b>`,`</b><i>N</i><b>`)`</b><i>,</i> <b>`callers*(`</b><i>s</i><b>`)`</b> | up to depth *N*; transitive closure |
| <b>`xrefs(`</b><i>s</i><b>`)`</b><i>,</i> <b>`drefs(`</b><i>s</i><b>`)`</b><i>,</i> <b>`crefs(`</b><i>s</i><b>`)`</b> | items referencing *s* (all, data, code) |
| <b>`refs(`</b><i>s</i><b>`)`</b> | items referenced by *s* |
| <b>`blocks(`</b><i>s</i><b>`)`</b> | basic blocks of the functions in *s* |
| <b>`func(`</b><i>s</i><b>`)`</b> | the functions containing *s* |
| <b>`uses_type(`</b><i>t</i><b>`)`</b> | functions whose prototype or lvars use type *t* |

#### Set operators

|                            |                                     |
|:---------------------------|:------------------------------------|
| **`a , b`** or **`a \| b`** | union                               |
| **`a & b`**                | intersection                        |
| **`a ~ b`**                | difference                          |
| **`!a`**                   | complement (within the kind of *a*) |
| **`( ... )`**              | grouping                            |

Difference is **~**, not **-**, so it never collides with address arithmetic.

#### Predicates

Any selector may be followed by one or more <b>\[</b><i>expr</i><b>\]</b> filters over its items' **FIELDS**:

    func:*[size > 0x400][xrefs_to >= 10]       big and popular
    func:sub_*[insns > 200 && hexrays_err != 0]
                                               large, unnamed, undecompilable
    str:*http*[xrefs_to == 0]                  unreferenced URLs
    callers(imp:*!VirtualProtect, 3)[!lib]     user code near VirtualProtect
    diff:changed[similarity < 0.9]             substantially changed

Operators: **== != \< \<= \> \>= && \|\| !** and **~** (regex match on strings, **module ~ "(?i)ws2"**). Fields that need the decompiler (**pseudocode**, **hexrays_err**, **lvars**) trigger decompilation; this is correct but can be slow.

#### Quoting

Selectors containing **( ) \| & ! \* \[ \] ~ \$** must be quoted for the shell. Single quotes are recommended.

### FIELDS AND TEMPLATES

#### Common fields

**icli schema** is authoritative; the most used fields are:

|  |  |
|:---|:---|
| **ea**, **end**, **size** | start, end, size in bytes |
| **kind** | function, data, string, type, import, xref, diff, ... |
| **name**, **demangled**, **mangled** | names |
| **type** | C declaration or prototype |
| **segment**, **flags** | segment name; LIB, THUNK, NORET, ... |
| **lib**, **thunk**, **noret**, **dummy** | booleans |
| **xrefs_to**, **xrefs_from** | reference counts |
| **callers**, **callees** | distinct calling / called functions |
| **blocks**, **insns**, **cyclomatic** | CFG metrics |
| **hash** | operand-agnostic body hash (stable across rebuilds) |
| **bytes**, **bytes_sha256** | raw bytes (hex, truncated), their hash |
| **comment**, **rcomment** | regular, repeatable comment |
| **flirt**, **lumina** | matching library; none\|pulled\|conflict |
| **coverage** | hit count from **load coverage** / **trace** |
| **tags** | tags from **icli tag** |
| **value**, **encoding** | string literal contents, encoding |
| **module**, **ordinal** | imports and exports |
| **disasm** | disassembly text |
| **pseudocode**, **hexrays_err** | decompiler output; error code (0 = ok) |
| **microcode** | microcode at **--maturity** |
| **diff**, **similarity**, **other_ea** | diff class, score, matched address |
| **index**, **count** | position in, and size of, the result set |
| **input**, **db**, **processor** | context |

#### Templates

**-t** *tmpl* renders each record as text. Placeholders are <b>{</b><i>field</i><b>}</b> with an optional Python-style format spec <b>{</b><i>field</i><b>:</b><i>spec</i><b>}:</b>

|                     |                            |
|:--------------------|:---------------------------|
| **`{ea}`**          | 0x401000 (per **--addr**)  |
| **`{size:>8}`**     | right-aligned in 8 columns |
| **`{size:#x}`**     | hexadecimal with prefix    |
| **`{name:<40.40}`** | padded and truncated to 40 |
| **`{hash:.8}`**     | first 8 characters         |
| **`{tags:,}`**      | list joined by commas      |
| **`{{`** **`}}`**   | literal braces             |

Escapes **\n**, **\t**, **\0** are recognised. A record gets a trailing newline unless the template ends with **\c**. **--header** *tmpl* and **--footer** *tmpl* are rendered once, before and after the records, with **count** available.

Templates also appear in edit arguments (**rename**, **type set**, **comment**) and in **-o** paths, where a per-item template writes one file per item. Characters invalid in file names are replaced with **\_**.

### OUTPUT FORMATS

#### Stream formats

Records written to standard output by query, edit and compare commands.

**text**  
Aligned columns, optionally coloured. For people; not a stable interface.

**jsonl**  
One JSON object per record. Default when standard output is not a terminal. Every record carries **\_t** (record type) so mixed streams demultiplex with **jq**. Addresses are strings, so 64-bit values survive tools that use doubles.

**json**  
One document:

    {"schema":"icli.function/1", "database":{...},
     "records":[...], "warnings":[...]}

**csv**, **tsv**  
RFC 4180 with a header row; nested values are JSON in one cell.

**raw**  
The natural payload: pseudocode for **decompile**, listing text for **disasm**, bytes for **export bin**.

Diagnostics never go to standard output. With **json** or **jsonl**, diagnostics on standard error are JSON lines too:

> {"_t":"diag","level":"warning","code":"NOMATCH","msg":"..."}

#### Export formats

Named explicitly to **icli export**.

|  |  |  |
|:---|:---|:---|
| **format** | **selection** | **contents** |
| i64 | yes | database; with a selector, a minimal database holding only the |
|  |  | selected functions, their callees' prototypes and the types they |
|  |  | use — a self-contained decompiler bug reproducer |
| asm | yes | assemblable source (OFILE_ASM); **--with-types** |
| lst | yes | listing with addresses (OFILE_LST) |
| html | yes | hyperlinked listing (GENFLG_GENHTML); **--highlight** *records* |
| map | no | MAP file (OFILE_MAP); **--segments --demangle --locals** |
| idc | no | IDC script recreating all user annotations (OFILE_IDC) |
| python | no | the same as IDAPython |
| journal | no | the edit journal (= **icli log -f jsonl**) |
| dif | no | patch list (OFILE_DIF) |
| exe | no | patched input file (OFILE_EXE); **--in-place** needs **--force** |
| bin | yes | raw bytes of the selected ranges |
| c | yes | pseudocode, preceded by needed declarations; **-j** parallel |
| cpp | yes | same, with C++ class reconstruction |
| mc | yes | microcode at **--maturity** |
| h | no | local types as a C header (= **type dump**) |
| til | no | local types as a type library |
| sig, pat | yes | FLIRT signature / pattern of the selected functions |
| dot, gdl | yes | call graph (**--graph calls\|flow\|xrefs**) |
| svg | yes | rendered graph |
| sqlite | no | every **list** kind as a table, for ad-hoc SQL |
| sarif | yes | SARIF 2.1 results, one per selected item, for code scanning |

### CONFIGURATION

**icli** reads its own settings from TOML and kernel settings from the usual *.cfg* files. Precedence, highest first:

1.  command-line options;

2.  **ICLI\_\*** environment variables;

3.  *.icli.toml* in the current directory or the nearest parent (stopping at a *.git* directory);

4.  *\$IDAUSR/icli.toml*;

5.  *\$IDADIR/cfg/icli.toml*;

6.  built-in defaults.

Kernel directives follow IDA's own order (*\$IDADIR/cfg/ida.cfg*, *\$IDAUSR/cfg/ida.cfg*, *\$IDAUSR/idauser.cfg*), then the **\[ida\]** and **\[hexrays\]** tables of the **icli** files, then **--set**.

    # .icli.toml
    [defaults]
    format      = "jsonl"
    addr        = "rva"
    analysis    = "wait"

    [load]
    compiler    = "visual"
    symbols     = ["auto", "symsrv"]

    [analyze]
    with        = ["lumina", "rtti", "pdb"]

    [ida]                       # same as --set
    OPCODE_BYTES = 8
    ANALYSIS     = "+FLIRT,+HFLIRT,-UNK"

    [hexrays]
    MAX_NCOMMAS  = 8

    [cache]
    dir      = "~/.cache/icli"
    max-size = "50G"

    [alias]                     # git-style
    hot   = "list functions --sort callers:desc -n 20"
    fails = "list functions --where 'hexrays_err != 0'"

### ENVIRONMENT

**IDADIR**  
Installation directory (modules, loaders, plugins, *cfg/*, *sig/*, *til/*, *ids/*). Default: the directory containing **icli**.

**IDAUSR**  
User directories (path list) searched before **IDADIR**. Default *~/.idapro* on Linux and macOS, *%APPDATA%\Hex-Rays\IDA Pro* on Windows.

**IDALOG**  
Kernel message log (as **--log**).

**ICLI_DB**  
Default target.

**ICLI_CACHE_DIR**  
Database cache. Default *\$XDG_CACHE_HOME/icli*, *~/Library/Caches/icli* on macOS, *%LOCALAPPDATA%\icli* on Windows.

**ICLI_FORMAT**, **ICLI_JOBS**  
Defaults for **--format** and **--jobs**.

**ICLI_SOCKET**, **ICLI_NO_SERVER**  
Use a specific **icli serve** socket; or never forward.

**ICLI_LAST**  
Maintained by the shell integration from **icli completion** so that a bare **@** works.

**ICLI_AUTHOR**  
Author for journal records. Default: the licence holder, then **\$USER**.

**ICLI_ALLOW_EXECUTE**  
If **1**, acts as **--allow-execute**. For sandboxed CI only.

**ICLI_DEBUG_PASSWORD**  
Remote debug server password.

**VAULT_HOST**, **VAULT_USER**, **VAULT_PASS**, **VAULT_SITE**  
IDA Teams connection, as for **hv**(1).

**\_NT_SYMBOL_PATH**, **DEBUGINFOD_URLS**  
Symbol sources for **--symbols symsrv**/**debuginfod**.

**NO_COLOR**  
Disable colour.

**TMPDIR**  
Temporary databases for **--no-cache**.

### FILES

*\$ICLI_CACHE_DIR/*xx*/*key*.i64*  
Cached databases.

*\$ICLI_CACHE_DIR/index.sqlite*  
Cache index: key, input path and hash, load options, state, sizes, access times.

*\$XDG_RUNTIME_DIR/icli/*key*.sock*  
**icli serve** sockets.

*db*.i64.lock  
Lock file (pid, host, mode).

*\$IDAUSR/icli/recipes/*name*.icli*  
Recipes for <b>icli do @</b><i>name</i><b>.</b>

*\$IDAUSR/icli.toml*, *./.icli.toml*  
**icli** configuration.

*\$IDADIR/cfg/ida.cfg*, *\$IDADIR/cfg/hexrays.cfg*, *\$IDAUSR/idauser.cfg*  
Kernel and decompiler configuration.

*\$IDADIR/sig/*proc*/\*.sig*, *\$IDADIR/til/*proc*/\*.til*, *\$IDADIR/ids/*  
FLIRT signatures, type libraries, import name databases.

### EXIT STATUS

Codes are stable across releases. When several apply, the lowest non-zero code wins, except that 3 yields to any hard error.

**0**  
Success. For edits, also when nothing needed to change.

**1**  
Negative result: **search**, **resolve** or **list --where** found nothing; **assert** failed; **diff** found differences; **--dry-run** edit would change nothing; **identify** met an unrecognised file.

**2**  
Usage error: unknown command, option or **--set** key; malformed selector; load option conflicting with an existing database; dynamic command without **--allow-execute**.

**3**  
Partial: analysis timed out, some functions failed to decompile, some journal records were skipped. Output is complete for what succeeded.

**4**  
Input file not found or unreadable.

**5**  
A selector the command requires resolved to nothing.

**6**  
Load failure: no loader accepted the file, or the loader or processor rejected it.

**7**  
Licence: no valid licence, or the edition lacks the feature (e.g. the decompiler for this processor).

**8**  
Decompilation of a single requested function failed.

**9**  
Edit conflict: a user-set value without **--force**, a name already in use, a differing type definition.

**10**  
Timeout (debugger, server, or **--analysis-timeout** under **--strict**).

**11**  
Database locked by another process.

**12**  
Database below the required lifecycle state with **--analysis=none**.

**13**  
Write attempted on a read-only database.

**14**  
Database corrupt, or created by a newer IDA.

**15**  
Network error (Lumina, IDA Teams, symbol server, remote debugger).

**16**  
Script error: uncaught exception in **exec**. Code calling <b>qexit(</b><i>n</i><b>)</b> exits with *n* instead.

**70**  
Internal error (INTERR). The number is printed; the database is not saved.

**130**  
Interrupted. The database is saved consistent; analysis resumes next time.

### EXAMPLES

#### First contact

Decompile **main** of a file never seen before. It is loaded, analysed and cached; the second run takes milliseconds:

    $ icli decompile ./crackme main

Triage a directory without creating any database:

    $ icli identify samples/* \
          -t '{sha256:.16}  {arch:<10} {compiler:<14} {packer} {path}'

What would IDA do with this blob?

    $ icli loaders mystery.img

Raw Cortex-M firmware with SRAM, a peripheral map, and a summary as JSON:

    $ icli info -f json --processor arm:ARMv7-M --base 0x08000000 \
          --segment SRAM=0x20000000-0x20020000:DATA:rw \
          --svd STM32F407.svd fw.bin | jq .

Fully enriched analysis with a time budget, in CI:

    $ icli -q --analysis-timeout 20m analyze \
          --with lumina,pdb,rtti,findmain app.exe
    $ echo $?           # 0 complete, 3 partial

One library out of a dyld shared cache; one dex out of an APK:

    $ icli list exports dyld_shared_cache_arm64e::libsystem_kernel.dylib
    $ icli decompile --all app.apk::classes2.dex 'func:/^Lcom\/example\//'

#### Querying

The 20 largest non-library functions, as a table:

    $ icli list functions --where '!lib' --sort size:desc -n 20 \
          -t '{ea}  {size:>8}  {xrefs_to:>4}  {demangled}' app.exe

Functions that both receive network data and call **memcpy**:

    $ icli resolve app.exe 'callers*(imp:*!recv) & callers(imp:*!memcpy)'

Every call site of **system**, with the decompiled line:

    $ icli xrefs --type call app.exe 'imp:*!system' \
      | icli decompile --at-line app.exe -

Strings that look like URLs and who uses them:

    $ icli search --string '^https?://' app.exe \
      | jq -r '[.value, (.funcs | join(","))] | @tsv'

Known crypto constants and the functions referencing them:

    $ icli search --crypto -t '{ea} {name:<20} {refs}' app.exe

Imports from crypto DLLs as CSV:

    $ icli -f csv list imports app.exe \
          --where 'module ~ "(?i)bcrypt|advapi32"'

Call graph of the network layer:

    $ icli callgraph --callees --depth 3 --graph dot app.exe net_dispatch \
      | dot -Tsvg > net.svg

#### Editing

Rename every remaining dummy function after its body hash, so names stay stable across rebuilds; preview first:

    $ icli --dry-run rename app.exe 'func:*[dummy]' 'f_{hash:.8}'
    $ icli rename app.exe 'func:*[dummy]' 'f_{hash:.8}'     # again: no-op

Retype all dispatch routines and let the types propagate:

    $ icli type set --propagate drv.sys 'func:Dispatch*' \
          'NTSTATUS __stdcall {name}(PDEVICE_OBJECT, PIRP)'

Import a header, then apply a prototype:

    $ icli type add app.exe -I ./include proto.h
    $ icli type set app.exe 0x401230 'int parse_packet(pkt_t *p, size_t n)'

Bulk rename from another tool's output:

    $ cut -f1,2 matches.tsv | icli rename app.i64 -

Tag everything within three calls of CryptoAPI:

    $ icli tag --color ffe0e0 mal.exe 'callers(imp:advapi32!Crypt*, 3)' crypto

Patch a branch and write both a DIF and the patched file:

    $ icli patch asm app.exe 'check_update+0x1c' 'jmp short loc_skip'
    $ icli export dif -o app.dif app.exe
    $ icli export exe -o app.patched.exe app.exe

Review the week's changes and undo a mistake:

    $ icli log --since 7d -f text app.i64
    $ icli undo --to 412 app.i64

#### The edit loop

Lumina proposals, filtered by confidence, reviewed, applied:

    $ icli lumina pull app.exe \
      | jq -c 'select(.score >= 0.9)' \
      | icli apply --only rename,type app.exe -

Keep annotations in git rather than in a binary database:

    $ icli export journal -o app.journal.jsonl app.exe
    $ git add app.journal.jsonl && git commit -m "annotations"
    # elsewhere, same input:
    $ icli apply app.exe app.journal.jsonl

Carry all names, types and comments from 1.2 to 1.3:

    $ icli port --what names,types,comments app-1.2.i64 app-1.3.exe

#### Decompiler

Everything into one compilable-looking C file, 16 threads:

    $ icli -j 16 export c -o app.c app.exe

One file per user function:

    $ icli export c -o 'src/{name}.c' app.exe 'func:*[!lib && !thunk]'

Which functions fail to decompile, and why:

    $ icli list functions --where 'hexrays_err != 0' \
          -t '{ea} {name} err={hexrays_err}' app.exe

Microcode before and after global optimisation, ready to diff:

    $ icli do app.exe -- \
          export mc --maturity locopt -o pre.mc  parse_hdr :: \
          export mc --maturity lvars  -o post.mc parse_hdr
    $ diff -u pre.mc post.mc

A minimal database reproducing a decompiler bug, to attach to a report:

    $ icli export i64 -o repro.i64 big.i64 sub_7ff6a0

#### Signatures and types

Build FLIRT signatures for a static library, then use them:

    $ icli sig make --library-name "mbedTLS 3.5 x64" --collisions skip \
          -o mbedtls35.sig libmbedcrypto.a libmbedtls.a
    $ icli sig apply fw.i64 ./mbedtls35.sig

A type library from an SDK:

    $ icli til make --target x86_64-pc-windows-msvc -I sdk/inc \
          -o vendor.til sdk/inc/vendor.h

#### Diffing

Patch Tuesday: changed functions with a pseudocode diff:

    $ icli -j 16 diff --pseudocode --threshold 0.5 \
          old/ntoskrnl.exe new/ntoskrnl.exe \
      | jq -r 'select(.diff == "changed") | .patch' | less -R

Sorted by similarity, as a table:

    $ icli diff -t '{similarity:.3f}  {ea} <- {other_ea}  {name}' \
          old.i64 new.i64 | sort -n | head

#### Pipelines, chains and CI

One load, many outputs:

    $ icli do kernel.elf -- \
          sig apply auto :: \
          analyze --with rtti :: \
          export lst -o kernel.lst :: \
          export map -o kernel.map :: \
          export c   -o kernel.c   :: \
          export h   -o kernel.h

A chain where each step feeds the next through **%**:

    $ icli do mal.exe -- \
          search --crypto :: \
          tag % crypto :: \
          export c -o crypto.c 'func(%)'

A reusable recipe, *\$IDAUSR/icli/recipes/win-triage.icli*:

    sig apply auto
    analyze --with rtti,findmain
    export sarif -o {input}.sarif 'callers(imp:*!strcpy | imp:*!sprintf)'
    export journal -o {input}.journal.jsonl

    $ icli do sample.exe @win-triage

Fail a CI job if more than three functions stop decompiling:

    $ icli assert app.exe 'func:*[hexrays_err != 0]' '<= 3'

Triage a corpus in parallel:

    $ find samples/ -type f -print0 \
      | xargs -0 -P 8 -n 1 icli -q --analysis-timeout 5m info > triage.jsonl

Thousands of small queries against one hot database:

    $ icli serve --detach --idle-timeout 2h kernel.i64
    $ time icli list functions --count kernel.i64     # ~10 ms

Load everything into SQLite:

    $ icli export sqlite -o app.db app.exe
    $ sqlite3 app.db 'SELECT name, size FROM functions WHERE callers = 0'

Run a Python file and propagate its verdict:

    $ icli exec app.exe find_bugs.py -- --min-score 7 \
      || echo "findings: $?"

#### Python

Look up the API:

    $ icli ref "rename local variable"

A command that almost does what you want, as code to adapt:

    $ icli list functions --where 'size > 0x400' --show-code app.exe
    for f in db.functions:
        if f.size > 0x400:
            yield {"ea": f.start_ea, "name": db.functions.get_name(f),
                   "size": f.size}

A one-off query whose result is ordinary records:

    $ icli exec app.exe -c '[{"ea": f.start_ea,
                              "name": db.functions.get_name(f)}
                             for f in db.functions if f.size > 0x1000]' \
      | jq -r .name

Code proposes names; review them; apply them (journaled, undoable):

    $ icli exec app.exe guess_names.py > proposals.jsonl
    $ jq -c 'select(.confidence > 0.8)' proposals.jsonl | icli apply app.exe -

Per-item code over a selection:

    $ icli exec app.exe --each 'func:*[!lib]' \
          -c '{"ea": ea, "loops": count_loops(db, ea)}'

A persistent session, also served over MCP:

    $ icli serve --detach --mcp http:127.0.0.1:8737 app.i64
    $ icli exec app.i64 --session work -c 'import networkx as nx'
    $ icli exec app.i64 --session work -c 'g = build_cfg(db, "main")'
    $ icli exec app.i64 --session work -c 'nx.dag_longest_path_length(g)'

#### Dynamic

Code coverage from a test run, highlighted in a listing:

    $ icli --allow-execute trace --coverage app.exe \
          -- tests/input1 > cov.jsonl
    $ icli export html --highlight cov.jsonl -o cov.html app.exe
    $ icli list functions --where 'coverage == 0' app.exe 'func:parse*'

Log the arguments of a function on every call:

    $ icli --allow-execute debug run --break parse_packet --regs rcx,rdx \
          --timeout 60s app.exe -- --port 8080

#### Teams

    $ icli rename vault://corp/router/router.i64 0x8001_2340 nvram_get
    $ icli vault commit -m "named nvram accessors" \
          vault://corp/router/router.i64

### NOTES

#### Migrating from idat

**icli legacy --** *idat-args* runs an **idat** command line unchanged. Equivalents:

|                     |                                                 |
|:--------------------|:------------------------------------------------|
| **idat**            | **icli**                                        |
| -A -B *file*        | icli analyze *file*; icli export asm,lst        |
| -a                  | --analysis none                                 |
| -c                  | analyze --reanalyze, or --no-cache              |
| -t                  | db create with no input                         |
| -o*file*            | --db *file*                                     |
| -p*proc*            | --processor *proc*                              |
| -T*type*            | --loader *name*                                 |
| -b*para*            | --base *addr* (bytes, not paragraphs)           |
| -i*addr*            | --entry *addr*                                  |
| -R                  | --load-opt pe.resources=yes                     |
| -x                  | --no-segmentation                               |
| -d / -D *key*=*val* | --set *key*=*val*                               |
| -O*plugin*:*opt*    | --plugin-opt *plugin*:*opt*                     |
| -Ohexrays:*...*:ALL | icli export c                                   |
| -S*script*          | icli exec *target* *script.py*                  |
| -L*file*            | --log *file*                                    |
| -P+ / -P / -P-      | --pack compress\|pack\|none                     |
| -v                  | --read-only                                     |
| -r*dbg*             | icli --allow-execute debug run --debugger *dbg* |
| -z*flags*           | -vvv                                            |

#### Stability

Command and option names, exit codes, and the field names of **json**, **jsonl**, **csv**, **tsv** output are the stable interface. Fields may be added in minor releases; a field is never removed or renamed without a schema version bump, and the previous schema stays available via **--schema-version** for one major release. **text** output carries no guarantee.

#### Determinism

With the same input, IDA version, load options and configuration, analysis is deterministic: two cold runs produce byte-identical **list** output. **-j** never changes results. Lumina pulls and symbol downloads are not deterministic; they are recorded in the journal so that **icli apply** reproduces them offline.

#### Security

Loading untrusted input is analysis, not execution. Nothing runs the target without **--allow-execute**; scripts stored in databases are never run automatically; loader plugins from **IDAUSR** are honoured, so do not point **IDAUSR** at untrusted directories.

#### Performance

Opening a multi-gigabyte database costs seconds; a served database answers in milliseconds. Scripts issuing more than a handful of commands against one database should use **icli serve**, **icli do**, **icli batch**, or **icli exec --session**.

#### Editions

**icli** requires IDA Pro or IDA Home with idalib. Decompilation requires the corresponding decompiler licence. Lumina push, IDA Teams and remote debugging follow the edition's terms.

### BUGS

The cache key covers the input and load options, not external files read during analysis (PDB, separate DWARF, Lumina). Run **analyze --reanalyze** after they change.

Fields that need the decompiler (**pseudocode**, **hexrays_err**) in a predicate or template silently decompile; an innocent **list** can become very slow.

Structural matching in **diff** is quadratic in the number of functions left unmatched by the cheaper rounds; very large, heavily changed binaries can take minutes.

**patch asm** is only as good as the processor module's assembler; most non-x86/ARM modules have none and the command exits 2.

Per-item **-o** templates sanitise file names, so two C++ overloads may collide; use **'{name}\_{ea}.c'** when in doubt.

Report bugs with the output of **icli -vv --version** and, when possible, **icli export i64** of the affected function and **icli export journal**.

### SEE ALSO

**ida**(1), **idat**(1), **ida-mcp**(1), **hv**(1), **sigmake**(1), **tilib**(1), **idapyswitch**(1), **jq**(1)

SDK headers: *idalib.hpp*, *loader.hpp*, *auto.hpp*, *typeinf.hpp*, *hexrays.hpp*, *lumina.hpp*.

IDA documentation  
[](https://docs.hex-rays.com/)

IDA Domain API (used by **icli exec**, **icli ref**, **--show-code**)  
[](https://ida-domain.docs.hex-rays.com/)

IDA MCP server  
[](https://github.com/HexRaysSA/ida-mcp)

IDA Nexus (database service behind **icli serve**)  
[](https://github.com/HexRaysSA/ida-nexus)
