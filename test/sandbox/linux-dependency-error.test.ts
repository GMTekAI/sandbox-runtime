import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as which from '../../src/utils/which.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import {
  checkLinuxDependencies,
  getLinuxDependencyStatus,
} from '../../src/sandbox/linux-sandbox-utils.js'

// Spies set up in beforeEach, torn down in afterEach. Each test overrides
// just the piece it's exercising. spyOn patches the export binding, so
// linux-sandbox-utils' own imports see the replacement.
let whichSpy: ReturnType<typeof spyOn>
let bpfSpy: ReturnType<typeof spyOn>
let applySpy: ReturnType<typeof spyOn>

beforeEach(() => {
  whichSpy = spyOn(which, 'whichSync').mockImplementation(
    (bin: string) => `/usr/bin/${bin}`,
  )
  bpfSpy = spyOn(seccomp, 'getPreGeneratedBpfPath').mockReturnValue(
    '/path/to/filter.bpf',
  )
  applySpy = spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(
    '/path/to/apply-seccomp',
  )
})

afterEach(() => {
  whichSpy.mockRestore()
  bpfSpy.mockRestore()
  applySpy.mockRestore()
})

describe('checkLinuxDependencies', () => {
  test('returns no errors or warnings when all dependencies present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns error when bwrap missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns error when socat missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns multiple errors when both bwrap and socat missing', () => {
    whichSpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(2)
  })

  test('returns warning (not error) when seccomp missing', () => {
    bpfSpy.mockReturnValue(null)
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.warnings).toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test('returns warning when only bpf file present (no apply binary)', () => {
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings.length).toBe(1)
  })

  test('passes custom seccomp paths through to the resolvers', () => {
    checkLinuxDependencies({
      bpfPath: '/custom/path.bpf',
      applyPath: '/custom/apply',
    })

    expect(bpfSpy).toHaveBeenCalledWith('/custom/path.bpf')
    expect(applySpy).toHaveBeenCalledWith('/custom/apply')
  })
})

describe('getLinuxDependencyStatus', () => {
  test('reports all available when everything installed', () => {
    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
    expect(status.hasSeccompBpf).toBe(true)
    expect(status.hasSeccompApply).toBe(true)
  })

  test('reports bwrap unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(false)
    expect(status.hasSocat).toBe(true)
  })

  test('reports socat unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasSocat).toBe(false)
    expect(status.hasBwrap).toBe(true)
  })

  test('reports seccomp unavailable when files missing', () => {
    bpfSpy.mockReturnValue(null)
    applySpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus()

    expect(status.hasSeccompBpf).toBe(false)
    expect(status.hasSeccompApply).toBe(false)
    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
  })
})
