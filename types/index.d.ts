// A person's clearance from /tripwire allow: which tripwire ('*' for any one),
// when (ms, $.clock), and, when it followed a denial, the exact command it is
// for (whitespace-normalised). The first call that trips it passes once;
// after TTL it is as if unset.
export type Armed = { name: string; at: number; subject?: string }

// The last denial, so a clearance can bind to the command the person saw.
export type Denied = { names: string[]; subject: string; at: number }

declare module 'claude-code' {
  interface PluginState {
    'fable-tripwire': { armed: Armed | null; denied: Denied | null }
  }
}
