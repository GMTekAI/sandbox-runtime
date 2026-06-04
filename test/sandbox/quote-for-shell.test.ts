import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { quoteForShell } from '../../src/sandbox/sandbox-utils.js'

describe('quoteForShell', () => {
  it('leaves safe arguments unquoted', () => {
    expect(quoteForShell(['echo', 'hello'])).toBe('echo hello')
    expect(quoteForShell(['/usr/bin/env', '-n', 'a_b.c-d/e'])).toBe(
      '/usr/bin/env -n a_b.c-d/e',
    )
  })

  it('single-quotes arguments containing unsafe characters', () => {
    expect(quoteForShell(['a b'])).toBe("'a b'")
    expect(quoteForShell(['$HOME'])).toBe("'$HOME'")
    expect(quoteForShell(['x; rm -rf /'])).toBe("'x; rm -rf /'")
  })

  it('rewrites embedded single quotes', () => {
    expect(quoteForShell(["it's"])).toBe("'it'\\''s'")
  })

  it('quotes the empty string', () => {
    expect(quoteForShell([''])).toBe("''")
  })

  it('quotes = in any position (zsh EQUALS / magic_equal_subst)', () => {
    expect(quoteForShell(['=ls'])).toBe("'=ls'")
    expect(quoteForShell(['VAR=value'])).toBe("'VAR=value'")
    expect(quoteForShell(['VAR=~/x'])).toBe("'VAR=~/x'")
  })

  it('quotes : (tilde expansion after : in assignment-like words)', () => {
    expect(quoteForShell(['PATH=a:~/bin'])).toBe("'PATH=a:~/bin'")
    expect(quoteForShell(['a:b'])).toBe("'a:b'")
  })

  it('keeps base64 arguments intact', () => {
    expect(quoteForShell(['aGVsbG8gd29ybGQ+/+='])).toBe("'aGVsbG8gd29ybGQ+/+='")
  })

  it('round-trips hostile arguments through bash -c', () => {
    const args = [
      'simple',
      'with space',
      "single'quote",
      '"double"',
      '$HOME',
      'new\nline',
      '',
      'a;b|c&d',
      '`backtick`',
      'glob*?[x]',
      'back\\slash',
      '!hist',
      'VAR=value',
      '=ls',
      '~tilde',
      '-n',
      "many'''quotes'",
    ]
    // printf '%s\0' emits each argv element NUL-terminated, so the child's
    // argv can be recovered exactly even when args contain newlines.
    const cmd = quoteForShell(['printf', '%s\\0', ...args])
    for (const shell of ['bash', 'zsh']) {
      // zsh matters: it is a valid binShell and applies EQUALS and
      // tilde expansion to unquoted words where bash does not.
      const r = spawnSync(shell, ['-c', cmd], { encoding: 'utf8' })
      if (r.error) continue // shell not installed on this host
      expect(r.status).toBe(0)
      // Drop the trailing empty element after the final NUL.
      expect(r.stdout.split('\0').slice(0, -1)).toEqual(args)
    }
  })
})
