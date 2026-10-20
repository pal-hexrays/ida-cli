"""Shell completion: scripts, and candidates computed by ``icli __complete``.

Commands, subcommands and options complete from the registry; after a
target on the command line, selectors complete against that target's
database (function names), using the cache (an analysed database answers
quickly, a served one in milliseconds)."""

from __future__ import annotations

from pathlib import Path


def _commands() -> dict:
    from .registry import COMMANDS, load_commands

    load_commands()
    return {n: c for n, c in COMMANDS.items() if not n.startswith("_")}


def _options(cmd, sub: str | None) -> list[str]:
    from .main import command_parser

    p = command_parser(cmd, sub)
    return sorted({o for a in p._actions for o in a.option_strings if o.startswith("--")})  # noqa: SLF001


def candidates(words: list[str]) -> list[str]:
    """``words`` is the command line after ``icli``; the last is the prefix."""
    cmds = _commands()
    prefix = words[-1] if words else ""
    positional = [w for w in words[:-1] if not w.startswith("-")]
    if not positional:
        return sorted(n for n in cmds if n.startswith(prefix))
    name = positional[0]
    cmd = cmds.get(name)
    if cmd is None:
        return []
    sub = positional[1] if cmd.subcommands and len(positional) > 1 else None
    if cmd.subcommands and sub is None:
        return sorted(s for s in cmd.subcommands if s.startswith(prefix))
    if prefix.startswith("-"):
        return [o for o in _options(cmd, sub) if o.startswith(prefix)]
    rest = positional[2 if sub else 1:]
    if cmd.target != "none" and rest:
        target = rest[0]
        if Path(target).exists():
            return _names(target, prefix)
    return []


def _names(target: str, prefix: str) -> list[str]:
    from .opening import resolve_target
    from .options import GlobalOptions

    g = GlobalOptions()
    try:
        t = resolve_target(target, g)
    except Exception:
        return []
    if t.db is None or not (t.db.exists() or t.db.with_suffix(".id0").exists()):
        return []  # never trigger a first analysis from a <TAB>
    from .opening import open_session

    g.output.quiet = True
    g.analysis = "none"
    try:
        s = open_session(target, g, lambda *a: None)
    except Exception:
        return []
    try:
        res = s.call("list", {"kind": "functions", "match": f"{prefix}*" if prefix else None},
                     ctx={"fields": ["name"]}, need="loaded")
    except Exception:
        return []
    finally:
        s.close()
    return sorted({r["name"] for r in res.get("records", []) if r.get("name")})


def script(shell: str) -> str:
    if shell == "bash":
        return '''# icli bash completion: eval "$(icli completion bash)"
_icli_complete() {
    local IFS=$'\\n'
    COMPREPLY=($(icli __complete -- "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null))
    if [ ${#COMPREPLY[@]} -eq 0 ]; then
        COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
    fi
    export ICLI_LAST="${COMP_WORDS[2]}"
}
complete -o default -F _icli_complete icli
'''
    if shell == "zsh":
        return '''#compdef icli
# icli zsh completion: eval "$(icli completion zsh)"
_icli() {
    local -a reply
    reply=("${(@f)$(icli __complete -- "${words[@]:1:$((CURRENT-1))}" 2>/dev/null)}")
    if [[ -n "${reply[1]}" ]]; then
        compadd -- "${reply[@]}"
    else
        _files
    fi
}
compdef _icli icli
'''
    if shell == "fish":
        return '''# icli fish completion: icli completion fish | source
function __icli_complete
    set -l tokens (commandline -opc) (commandline -ct)
    icli __complete -- $tokens[2..-1] 2>/dev/null
end
complete -c icli -f -a '(__icli_complete)'
'''
    if shell == "powershell":
        return '''# icli PowerShell completion: icli completion powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName icli -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = $commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.ToString() }
    if ($wordToComplete -eq '') { $words += '' }
    icli __complete -- @words 2>$null | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
'''
    raise ValueError(shell)
