# fable-tripwire

A Claude Code mod that blocks hard-to-undo commands until a person clears them once.

It hooks every `Bash`, `PowerShell`, `Edit` and `Write` call, and the Terminal panel's `run_in_terminal` tool. A call that matches a tripwire is refused with a message the model reads as an error: it names the tripwire, tells the model not to retry, reword, split or work around it, and tells it to write a brief, run a read-only reviewer subagent, show the user the verdict, and ask the user to type `/tripwire allow <name>`. Only a person can clear a tripwire: Enter at the prompt, Remote Control, or an SDK host such as the desktop app with someone at it; a command run by a plugin, a peer session, an unattended `claude -p`, or an unstamped channel is refused.

A clearance given after a denial is bound to the exact command that was denied (whitespace aside): a reworded retry is denied again. A clearance given with no recent denial clears the next matching command.

## Install

At the prompt of a terminal session:

```
/plugin install fable-tripwire --marketplace norkington/fable-tripwire
```

Answer `y` to add the marketplace, then choose a scope; the user scope loads the mod in every later session. From a shell:

```
claude plugin install fable-tripwire --marketplace norkington/fable-tripwire
```

In the desktop app, where `/plugin` does not run: click + next to the prompt box, then Plugins, Add marketplace with `norkington/fable-tripwire`, then Add plugin. A mod installed from a terminal at the user scope loads in the desktop app's sessions too.

## Tripwires

| name | fires on |
| --- | --- |
| `delete` | recursive deletes in any spelling: `rm -r`, `Remove-Item -Recurse`, `rd /s`, pipelines into a deleter, `find -delete`, `xargs rm`, `shutil.rmtree`, `fs.rm`, `rimraf`, `robocopy /MIR`. A `-WhatIf` preview never trips. A lone delete of one regenerable directory (`build`, `build-<x>`, `dist`, `node_modules`, `CMakeFiles`, caches; not `.venv`) is exempt: one operand, no wildcard. A `git` command earlier on the line makes `rm` git-rm, which is free. |
| `format` | `Format-Volume`, `Clear-Disk`, `diskpart`, `mkfs`, `format X:` (the drive letter alone; `ruff format C:\...` is a path) |
| `execute` | a `.ps1` (or a script named `cleanup`) run with `-Execute` in any abbreviation |
| `public` | `gh repo edit/create --visibility public`, `gh api` visibility changes |
| `history` | `git push --force` / `-f` / `+ref` / `--mirror`, `reset --hard`, `clean -f` (not a dry run), `checkout .`, `restore .`, `stash drop/clear`, filter-branch/repo; `git -C <path>` forms included. `--force-with-lease` to a named feature branch stays free; with no refspec, or aimed at `main`/`master`, it trips. `branch -D` stays free. |
| `security` | mutating forms only: Defender cmdlets, a persistent execution policy, firewall `set/add/delete`, `bcdedit /set`, `auditpol /set`, `net user <name> <pw>`, `net accounts /…`, local users, security services, policy and logon registry keys. Queries, `Get-*`, `Get-Help` and `-Scope Process` are free. |
| `upload` | scp/rsync with a remote as the last operand, sftp, `curl -F`/`-d @file`/`-T`, `Invoke-RestMethod -InFile/-Form`, `gh gist create`, `gh release`, `aws s3`, `rclone`, `gsutil`, `hf upload`. Anything aimed at localhost stays free. |
| `linux` | `wsl --mount`, `\\wsl$`, ext4 readers (for a dual-boot machine whose Linux side Windows must not read) |
| `opaque` | an encoded command given to a PowerShell host, `iex`, piping into a shell or interpreter, fetch-then-run on one line. `grep -e`, `sed -e` and a `\|sh` inside a quoted pattern are free. |
| `config` | editing, or writing from a shell to, `.claude/settings*.json`, `.claude/hooks/`, `.claude/dev-mods/`, `.claude/mods/`, `.claude/plugins/`, `.claude/agents/`, `.claude.json`, managed settings. The guard guards itself. |

A shell script written with `Write` or `Edit` is checked like a command (any `.ps1`, `.bat`, `.cmd`, `.sh`; `.py` and `.js` only under temp and scratch folders, so a project's own source is not scanned). `/tripwire list` prints the table in the session.

## The command

- `/tripwire allow <name>` clears that tripwire once, for 15 minutes, bound to the command last denied under that name. The first matching call passes; the next is blocked again. `/tripwire allow` with no name clears the last denied command whatever its tripwires.
- `/tripwire status` shows what is armed, for how long, and for which command.
- `/tripwire disarm` drops a clearance.
- `/tripwire list` names every tripwire.

## Guarantees and limits

- A guard that errors before passing a call on fails closed: the call is refused with instructions, never let through.
- Of several concurrent calls that match one clearance, exactly one passes (compare-and-set on the stored clearance).
- Not covered: a `.py` or `.js` file written inside a project and run afterwards; a command typed by the person; anything another plugin loaded above this one chooses to bypass.

## Tuned to one machine

The rules were written for one Windows 11 workstation and its habits. The `execute` rule names a dry-run-first `cleanup` script; the `linux` rule guards a dual-boot partition; the regenerable-directory exemption lists that machine's build folders; the `upload` rule leaves localhost free for a local inference server; and the denial text tells the model to run a `fable-advisor` subagent, a read-only reviewer defined in that user's `~/.claude/agents`. Installing elsewhere, read `COMMAND_RULES` in `hooks/register.ts` and change what doesn't fit, and either define such a subagent or edit the denial text so the model simply shows the user the denial and asks for the clearance. The tests in `tests/` list every string each rule is meant to catch or ignore; keep them green.

## Developing it

- `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`: the manifest and the one-entry marketplace that makes this folder installable
- `hooks/hooks.json` and `hooks/register.ts`: the hooks module
- `types/index.d.ts`: the `armed` and `denied` state values' types
- `tests/tripwire.test.ts`: run with the engine's `claude plugin test <this folder>`

Validate with `claude plugin validate --json <this folder>`. Both commands need the Claude Code version that wrote the types (2.1.309 or later), not an older CLI on PATH. To load a checkout of the mod in every session without installing it, name its folder in `CLAUDE_CODE_PLUGIN_DIRS` in the `env` block of `~/.claude/settings.json`.

## License

MIT, see `LICENSE`.
