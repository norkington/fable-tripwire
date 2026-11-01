import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Armed } from '../types'

// A person clears one tripwire with `/tripwire allow <name>`; the first call
// that trips it then passes, once, within this window. A clearance given after
// a denial is bound to the exact command that was denied.
const TTL_MIN = 15
const TTL_MS = TTL_MIN * 60 * 1000

const armed = atom({ plugin: 'fable-tripwire', key: 'armed' } as const, null)
const denied = atom({ plugin: 'fable-tripwire', key: 'denied' } as const, null)

// `unless` exempts a match: a routine form of the same command.
type Rule = { name: string; why: string; test: RegExp; unless?: RegExp }

// Most patterns stop at | ; & and newlines, so a flag on a later command in a
// pipeline is never read onto an earlier one. None uses the g flag: a RegExp
// with g keeps state between tests.
const SEG = String.raw`[^|;&\n]*`

// A -WhatIf preview deletes nothing and must neither trip nor spend a
// clearance; -WhatIf:$false is a real delete.
const NOT_WHATIF = String.raw`(?![^|;&\n]*-WhatIf(?![\w:]))`

// Registry writes that change a security setting, in either order on a line.
const REG_VERB = String.raw`\b(?:reg(?:\.exe)?\s+(?:add|delete)|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b`
const REG_KEYS = String.raw`(?:\\Policies\\|Windows Defender|WinDefend|SmartScreen|\\Lsa\\|EnableLUA|\\Winlogon|AutoAdminLogon|DefaultPassword|\\DeviceGuard)`

// Claude Code's own settings, hooks, mods and agents: the guard guards itself.
const GUARDED_DIRS = String.raw`(?:settings(?:\.local)?\.json|hooks[\\/]|dev-mods[\\/]|mods[\\/]|plugins[\\/]|agents[\\/])`
const GUARDED_PATH = String.raw`(?:^|[\\/])\.claude[\\/]${GUARDED_DIRS}|[\\/]\.claude\.json$|[\\/]ClaudeCode[\\/]managed-settings\.json$`
const GUARDED_IN_CMD = String.raw`[\\/]\.claude(?:[\\/]${GUARDED_DIRS}|\.json\b)|[\\/]ClaudeCode[\\/]managed-settings\.json`
const WRITE_VERB = String.raw`\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|Rename-Item|New-Item|Remove-Item|cp|mv|tee|robocopy|xcopy|sed\s+-i|json\.dump|open\()\b`

// A lone delete of one regenerable directory is a rebuild, not a tripwire.
// `build` and build-<x>, not `building`. Not here: .venv (the ComfyUI one
// carries a numpy pin broken on purpose).
const DISPOSABLE = String.raw`(?:build(?:[-_.][\w.-]*)?|dist|node_modules|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|htmlcov|CMakeFiles)`

const COMMAND_RULES: Rule[] = [
  {
    // A `git` command earlier on the segment (git, then whitespace: not a
    // path like Git\bin) makes `rm` git-rm, which deletes nothing on disk.
    name: 'delete',
    why: 'recursive delete',
    test: new RegExp(
      String.raw`(?<!\bgit(?:\.exe)?\s[^|;&\n]*)\brm\b${NOT_WHATIF}\s+[^|;&\n]*?(?<=\s)-(?:\w*r\w*|-recursive)\b` +
        String.raw`|\b(?:Remove-Item|ri|rmdir|rd|del|erase)\b${NOT_WHATIF}${SEG}(?:\s-r\w*\b|\s\/s\b)` +
        String.raw`|\|\s*(?:Remove-Item|ri|rm|del|erase)\b${NOT_WHATIF}` +
        String.raw`|\bfind\b${SEG}\s-delete\b|\bxargs\b${SEG}\brm\b|\bshutil\.rmtree\b|\bfs\.rm(?:Sync)?\s*\(|\brimraf\b|\[(?:System\.)?IO\.Directory\]::Delete\(|\brobocopy\b${SEG}\s\/(?:MIR|PURGE)\b`,
      'i',
    ),
    // One operand, no wildcard, no trailing .., whose last component is a
    // regenerable directory; a second operand or a glob still trips.
    unless: new RegExp(
      String.raw`^\s*(?:cmake\s+-E\s+)?(?:rm|Remove-Item|ri|rd|rmdir)\b(?:\s+-\S+)*\s+["']?(?:[A-Za-z]:)?[\\/]?(?:[^\s"'*?\\/]+[\\/])*${DISPOSABLE}[\\/]?["']?(?:\s+-(?:Recurse|Force|r|rf|fr|f|WhatIf|Confirm(?::\$false)?|ErrorAction\s+\w+))*\s*$`,
      'i',
    ),
  },
  {
    // A real `format D:` ends at the drive letter; a path goes on with \ or /.
    name: 'format',
    why: 'formats or re-initialises a disk',
    test: /\b(?:Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition|diskpart|mkfs(?:\.\w+)?|wipefs)\b|\bformat(?:\.com)?\s+[a-z]:(?=\s|$)/i,
  },
  {
    name: 'execute',
    why: 'runs a dry-run-first script for real',
    test: /(?:\.ps1\b|[\\/]cleanup\b|&\s*\$\w+)[^|;&\n]*\s-Ex(?:e(?:c(?:u(?:te?)?)?)?)?\b/i,
  },
  {
    name: 'public',
    why: 'makes a repo public',
    test: /\bgh\s+repo\s+(?:edit|create)\b[^|;&\n]*(?:--visibility[\s=]+["']?public\b|--public\b)|\bgh\s+api\b[^|;&\n]*(?:visibility=public|private=false|(?:-X|--method)\s+PATCH\b[^|;&\n]*repos\/)/i,
  },
  {
    // Case-sensitive: git verbs and flags are lowercase, and -D is not -d.
    // Global options (-C <path>, -c k=v, --no-pager) may sit before the verb.
    // --force-with-lease to a named feature branch stays free (it refuses to
    // clobber unseen remote work, and the rebase-then-push workflow needs it
    // daily); with no refspec, or aimed at main/master, it trips.
    name: 'history',
    why: 'rewrites or discards git history or working changes',
    test: /\bgit(?:\s+-[cC]\s+\S+|\s+--\S+)*\s+(?:push\b(?:[^|;&\n]*(?:\s--force\b(?!-with-lease|-if-includes)|\s-\w*f\w*\b|\s\+\S+|\s--mirror\b)|(?![^|;&\n]*\s[^-\s]\S*\s+[^-\s]\S*)[^|;&\n]*\s--force-with-lease\b|(?=[^|;&\n]*\b(?:main|master)\b)[^|;&\n]*\s--force-with-lease\b)|reset\s+(?:-\S+\s+)*--hard\b|clean(?![^|;&\n]*\s(?:-\w*n\w*|--dry-run)\b)\b[^|;&\n]*\s(?:-\w*f\w*|--force)\b|filter-branch\b|filter-repo\b|(?:checkout|restore)\s+(?:--\s+)?\.(?:\s|$)|stash\s+(?:drop|clear)\b)/,
  },
  {
    // Mutating forms only: queries (show, /enum, /get, Get-*) and a
    // process-scoped execution policy persist nothing. Get-Help on a cmdlet
    // is reading about it. `net accounts` with any option changes policy.
    name: 'security',
    why: 'changes a security setting',
    test: new RegExp(
      String.raw`(?<!\bGet-(?:Help|Command)\s+)\b(?:Set-MpPreference|Add-MpPreference|Remove-MpPreference|Set-ExecutionPolicy(?![^|;&\n]*-Scope\s+Process\b)|Set-NetFirewallProfile|Set-NetFirewallRule|New-NetFirewallRule|Remove-NetFirewallRule|Disable-NetFirewallRule|Enable-NetFirewallRule|Disable-WindowsOptionalFeature|Set-ProcessMitigation|Set-LocalUser|New-LocalUser|Remove-LocalUser|Add-LocalGroupMember|Remove-LocalGroupMember)\b` +
        String.raw`|\bnetsh\s+(?:adv)?firewall\b${SEG}\s(?:set|add|delete|reset|import)\s|\bbcdedit\b${SEG}\s\/(?:set|delete\w*|create|copy|default|boot\w*|display\w*|timeout|import)\b|\bauditpol\s+\/(?:set|clear|restore|remove)\b|\bsecedit\s+\/(?:configure|import)\b|\bnet\s+accounts\s+\/|\bnet\s+(?:user|localgroup)\b${SEG}\s\S+\s+\S` +
        String.raw`|\b(?:Set-Service|Stop-Service|sc(?:\.exe)?\s+(?:config|stop|delete))\b${SEG}\b(?:WinDefend|WdNisSvc|Sense|MDCoreSvc|wscsvc|mpssvc|SecurityHealthService)\b` +
        String.raw`|${REG_VERB}[^\n]*${REG_KEYS}|${REG_KEYS}[^\n]*${REG_VERB}`,
      'i',
    ),
  },
  {
    // Uploads to a host: for scp/rsync the remote must be the last operand
    // (a remote first is a download); flags may follow it. Anything aimed at
    // localhost stays free; the local llama-server is curled daily.
    name: 'upload',
    why: 'sends files off this machine',
    test: /\b(?:scp|rsync)\b[^|;&\n]*\s(?:\S+@)?[A-Za-z0-9][A-Za-z0-9.-]+:\S*(?=(?:\s+-\S+)*\s*(?:$|[|;&\n]))|\bsftp\b[^|;&\n]*\s(?:\S+@)?[A-Za-z0-9][A-Za-z0-9.-]+:|\bcurl\b(?![^|;&\n]*(?:localhost|127\.0\.0\.1|\[::1\]))[^|;&\n]*(?:\s-T\s|--upload-file\b|\s-[A-Za-z]*[dF]\s+["']?[^\s"']*@|--(?:data(?:-binary|-raw|-urlencode)?|form(?:-string)?)[\s=]+["']?[^\s"']*@)|\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b(?![^|;&\n]*(?:localhost|127\.0\.0\.1))[^|;&\n]*\s-(?:InFile|Form)\b|\bgh\s+gist\s+create\b|\b(?:huggingface-cli|hf)\s+upload\b|\baws\s+s3\s+(?:cp|sync|mv)\b|\brclone\s+(?:copy|sync|move|copyto)\b|\bgsutil\s+(?:cp|rsync|mv)\b|\bgh\s+release\s+(?:create|upload)\b/i,
  },
  {
    name: 'linux',
    why: 'reads the Linux side from Windows',
    test: /\bwsl(?:\.exe)?\s+--mount\b|\\\\wsl(?:\$|\.localhost)\\|\b(?:ext2fsd|ext2explore|linuxreader|ext4fsd|Ext2Read)\b/i,
  },
  {
    // An encoded command means something only to the PowerShell host, so it
    // is anchored on one (grep -e, sed -e and git grep -e stay free). A pipe
    // target is followed by whitespace or the end; inside a quoted regex
    // alternation it is followed by |, ) or a quote.
    name: 'opaque',
    why: 'runs a script the guard cannot read',
    test: /\b(?:powershell|pwsh)(?:\.exe)?\b[^|;&\n]*[\s'"]-e(?:c|n\w*)?\s+\S|\b(?:iex|Invoke-Expression)\b|\|\s*(?:sh|bash|powershell|pwsh|python3?|node|perl|cmd)(?:\.exe)?\b(?![|)"'])|\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*[;&]+\s*&?\s*(?:\.[\\/]|sh\s|bash\s|powershell|pwsh|python|node)/i,
  },
  {
    name: 'config',
    why: 'writes Claude Code settings, hooks, mods or this guard from a shell',
    test: new RegExp(String.raw`(?:${WRITE_VERB}${SEG}|>>?\s*\S*)${GUARDED_IN_CMD}`, 'i'),
  },
]

// Files whose edit is a security setting in its own right.
const FILE_RULES: Rule[] = [
  {
    name: 'config',
    why: 'edits Claude Code settings, hooks, mods or this guard',
    test: new RegExp(GUARDED_PATH, 'i'),
  },
]

// A script written now and run next: its body is checked like a command.
// Shell scripts anywhere; Python and JS only in temp and scratch folders,
// where code is a vehicle for commands rather than a project's source.
const SHELL_SCRIPT = /\.(?:ps1|psm1|bat|cmd|sh|bash)$/i
const SCRATCH_SCRIPT = /[\\/](?:Temp|tmp|scratchpad)[\\/].*\.(?:py|js|mjs|cjs|ts)$/i
const isScript = (path: string) => SHELL_SCRIPT.test(path) || SCRATCH_SCRIPT.test(path)

const RULE_NAMES = [...new Set([...COMMAND_RULES, ...FILE_RULES].map(r => r.name))]

// Line continuations (PowerShell backtick, sh backslash) folded, so a flag on
// the next physical line is read onto its command.
const fold = (s: string) => s.replace(/`\r?\n\s*/g, ' ').replace(/\\\r?\n\s*/g, ' ')

// The identity of a command for binding a clearance: whitespace-normalised.
const key = (s: string) => s.replace(/\s+/g, ' ').trim()

const excerpt = (s: string) => {
  const one = key(s)

  return one.length > 80 ? `${one.slice(0, 77)}...` : one
}

// Display only: a surface that lacks status or toast must never reach the decision.
const show = (f: () => unknown) => {
  try {
    void Promise.resolve(f()).catch(() => undefined)
  } catch {
    // display only
  }
}

const failed = ($: EngineInterface) => ({
  deny:
    `${$.plugin.name}: its guard errored before deciding, so this call is refused. ` +
    'Do not retry or rework the call. Tell the user the tripwire guard failed and stop; ' +
    'they can run /tripwire status.',
})

// null: let the call through. { deny }: answer for it.
async function check($: EngineInterface, rules: Rule[], raw: string) {
  const subject = fold(raw)
  const hits = rules.filter(r => r.test.test(subject) && !(r.unless?.test(subject) ?? false))
  if (hits.length === 0) {
    return null
  }

  const names = hits.map(h => h.name)
  const now = await $.clock.now()
  const k = key(subject)

  // Decide and consume in one compare-and-set. The predicate runs again on
  // every retry, so `won` is the decision that landed: of several concurrent
  // callers, exactly one takes a clearance.
  let won = false
  await update($, armed, (cur: Armed | null) => {
    won =
      cur !== null &&
      now - cur.at < TTL_MS &&
      (cur.name === '*' || names.every(n => n === cur.name)) &&
      (cur.subject === undefined || cur.subject === k)

    return won ? null : cur
  })

  const label = names.map(n => `"${n}"`).join(', ')
  if (won) {
    show(() => $.ui.status(undefined))
    show(() => $.ui.toast(`Tripwire ${names.join(', ')}: allowed once`))

    return null
  }

  await update($, denied, () => ({ names, subject: k, at: now }))
  const ask = names.length === 1 ? `/tripwire allow ${names[0]}` : '/tripwire allow'
  show(() => $.ui.status(`tripwire ${names.join(', ')} blocked · ${ask}`))
  show(() => $.ui.toast(`Tripwire ${names.join(', ')}: ${hits.map(h => h.why).join('; ')}`))

  return {
    deny:
      `${$.plugin.name}: tripwire ${label} (${hits.map(h => h.why).join('; ')}): ${excerpt(subject)}. ` +
      'Do not retry, reword, split, or work around it: not in a script, not through another shell tool. ' +
      'If this command only searches, prints or commits text, say so and ask the user for the clearance; otherwise ' +
      'write a brief (CLAUDE.md, "The brief"), run the fable-advisor subagent, show the user its verdict, ' +
      `and ask the user to type ${ask}. Only the user may type that; never run /tripwire yourself. ` +
      `That clears this exact command once, for ${TTL_MIN} minutes.`,
  }
}

export const register: Register = on => {
  // Whether a person is at this session: the REPL, or an SDK host (the desktop
  // app) with a surface attached. A `claude -p` child has neither.
  let attended = false

  on('session.start', async ($, e, next) => {
    attended = e.isInteractive === true || e.surface !== null
    await $.command.register({
      name: 'tripwire',
      description: 'Clear a Fable tripwire once, or show which one is armed',
      argumentHint: 'allow <name> | status | disarm | list',
    })

    return next(e)
  })

  on('session.attach', ($, e, next) => {
    attended = true

    return next(e)
  })

  // A new prompt means the person has seen the last block: show only a live clearance.
  on('prompt.submit', async ($, e, next) => {
    const now = await $.clock.now()
    const arm = await read($, armed)
    show(() => $.ui.status(arm !== null && now - arm.at < TTL_MS ? `tripwire ${arm.name} armed` : undefined))

    return next(e)
  }).catch(($, e, next) => next(e))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) =>
    (await check($, COMMAND_RULES, e.command)) ?? next(e),
  ).catch(($, e, next) => (next.called ? next(e) : failed($)))

  on('tool.call', { tool: 'PowerShell' }, async ($, e, next) =>
    (await check($, COMMAND_RULES, e.command)) ?? next(e),
  ).catch(($, e, next) => (next.called ? next(e) : failed($)))

  // The Terminal panel tool types a line into the user's own shell, outside
  // any sandbox: one line, no pipes or variables, so the plain forms are
  // exactly what reaches it.
  on('tool.call', { tool: 'mcp__terminal__run_in_terminal' }, async ($, e, next) =>
    (await check($, COMMAND_RULES, String((e as { command?: unknown }).command ?? ''))) ?? next(e),
  ).catch(($, e, next) => (next.called ? next(e) : failed($)))

  on('tool.call', { tool: 'Edit' }, async ($, e, next) =>
    (await check($, FILE_RULES, e.file_path)) ??
    (isScript(e.file_path) ? await check($, COMMAND_RULES, e.new_string) : null) ??
    next(e),
  ).catch(($, e, next) => (next.called ? next(e) : failed($)))

  on('tool.call', { tool: 'Write' }, async ($, e, next) =>
    (await check($, FILE_RULES, e.file_path)) ??
    (isScript(e.file_path) ? await check($, COMMAND_RULES, e.content) : null) ??
    next(e),
  ).catch(($, e, next) => (next.called ? next(e) : failed($)))

  on('command.run', { command: 'tripwire' }, async ($, e) => {
    const [verb = 'status', name = '*'] = (e.args ?? '').trim().split(/\s+/).filter(Boolean)
    const now = await $.clock.now()
    const arm = await read($, armed)
    const live = arm !== null && now - arm.at < TTL_MS ? arm : null

    if (verb === 'list') {
      const seen = new Set<string>()
      const lines = [...COMMAND_RULES, ...FILE_RULES]
        .filter(r => !seen.has(r.name) && seen.add(r.name))
        .map(r => `${r.name}: ${r.why}`)

      return { text: lines.join('\n') }
    }

    if (verb === 'status') {
      if (!live) {
        show(() => $.ui.status(undefined))
      }

      return {
        text: live
          ? `Armed: ${live.name}, ${Math.ceil((TTL_MS - (now - live.at)) / 60000)} min left` +
            (live.subject ? `, for: ${excerpt(live.subject)}` : '.')
          : 'Nothing armed.',
      }
    }

    if (verb === 'disarm') {
      await update($, armed, () => null)
      show(() => $.ui.status(undefined))

      return { text: 'Disarmed.' }
    }

    if (verb === 'allow') {
      if (name !== '*' && !RULE_NAMES.includes(name)) {
        return { text: `No tripwire named "${name}". Try /tripwire list.` }
      }

      // Only a person's own keystroke arms. The engine stamps every command a
      // person runs; a plugin, a peer session, a channel, an unattended SDK
      // host and an unstamped run are refused, unknown kinds included.
      const kind = e.origin?.kind ?? 'unstamped'
      const person = kind === 'composer' || kind === 'bridge' || (kind === 'sdk' && attended)
      if (!person) {
        return {
          text: `Refused: /tripwire allow counts only when a person types it (this came from "${kind}"${kind === 'sdk' ? ' with no one at the prompt' : ''}).`,
        }
      }

      // Bind the clearance to the command the person was just shown, when the
      // name covers it; with no recent denial it clears the next one.
      const last = await read($, denied)
      const bound =
        last !== null && now - last.at < TTL_MS && (name === '*' || last.names.includes(name))
          ? last.subject
          : undefined
      await update($, armed, () => ({ name, at: now, subject: bound }))
      show(() => $.ui.status(`tripwire ${name} armed, ${TTL_MIN} min`))

      return {
        text: bound
          ? `Tripwire "${name}" cleared once for the blocked command: ${excerpt(bound)}`
          : `Tripwire "${name}" cleared once, for the next ${TTL_MIN} minutes.`,
        context: [`The user cleared tripwire "${name}" once. Retry the blocked call now, byte-for-byte unchanged.`],
      }
    }

    return { text: 'Usage: /tripwire allow <name> | status | disarm | list' }
  })
}
