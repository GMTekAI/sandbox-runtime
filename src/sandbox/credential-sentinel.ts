/**
 * Per-session sentinel registry for credential masking.
 *
 * A masked credential's real value is replaced inside the sandbox with a
 * sentinel of the form `fake_value_<uuid4>`. The sandboxed process sees only
 * the sentinel; the host-side proxy substitutes sentinel→real on egress to
 * allowlisted destinations. The map lives only in process memory — it is
 * never written to disk and never logged.
 */

import { randomUUID } from 'node:crypto'

export const SENTINEL_PREFIX = 'fake_value_'

/**
 * Bidirectional sentinel↔real-value map for one sandbox session.
 *
 * `register()` is idempotent for a given real value so a credential carried
 * by multiple sources (e.g. the same token in two env vars) maps to one
 * sentinel and one substitution.
 */
export class SentinelRegistry {
  private readonly sentinelToReal = new Map<string, string>()
  private readonly realToSentinel = new Map<string, string>()

  /**
   * Return the sentinel for `realValue`, minting a fresh one on first use.
   * The sentinel is `fake_value_<uuid4>`: long enough that an accidental
   * collision with legitimate header content is negligible, and free of
   * shell/URL metacharacters so it survives `--setenv` and `env NAME=value`
   * unquoted.
   */
  register(realValue: string): string {
    const existing = this.realToSentinel.get(realValue)
    if (existing !== undefined) return existing
    const sentinel = SENTINEL_PREFIX + randomUUID()
    this.sentinelToReal.set(sentinel, realValue)
    this.realToSentinel.set(realValue, sentinel)
    return sentinel
  }

  /** Real value for `sentinel`, or undefined if not registered. */
  lookupReal(sentinel: string): string | undefined {
    return this.sentinelToReal.get(sentinel)
  }

  /** Iterate registered `[sentinel, realValue]` pairs. */
  entries(): IterableIterator<[string, string]> {
    return this.sentinelToReal.entries()
  }

  /** Number of registered sentinels. */
  get size(): number {
    return this.sentinelToReal.size
  }

  /** Drop every mapping. Called on session teardown. */
  clear(): void {
    this.sentinelToReal.clear()
    this.realToSentinel.clear()
  }
}
