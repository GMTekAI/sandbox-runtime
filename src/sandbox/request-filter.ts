/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import { logForDebugging } from '../utils/debug.js'

export type RequestDecision = {
  action: 'allow' | 'deny'
  /**
   * Human-readable reason. For denials this is surfaced to the sandboxed
   * client in the response body so the agent can tell a policy block from a
   * network failure.
   */
  reason?: string
}

/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`. v1 populates method, URL, and
 *   headers; `request.body` is `null` (body inspection is a follow-up).
 *   `request.signal` aborts when the client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed.
 */
export type FilterRequestCallback = (
  request: Request,
) => Promise<RequestDecision>

/**
 * Build a `Request`, run the callback, and if denied write the 403 response.
 * Returns true if the request may proceed upstream.
 */
export async function decideAndRespond(
  filterRequest: FilterRequestCallback,
  req: IncomingMessage,
  res: ServerResponse,
  url: string,
  signal: AbortSignal,
): Promise<boolean> {
  let webReq: Request
  try {
    webReq = new Request(url, {
      method: req.method,
      headers: incomingHeaders(req),
      // v1: body inspection deferred. Callbacks see request.body === null.
      // TODO(terminating-tls): tee req → ReadableStream so policies can read
      // the body without consuming the upstream pipe.
      signal,
    })
  } catch (err) {
    // Malformed URL/headers from the client — deny rather than crash.
    deny(res, {
      action: 'deny',
      reason: `malformed request: ${(err as Error).message}`,
    })
    return false
  }

  let decision: RequestDecision
  try {
    decision = await filterRequest(webReq)
  } catch (err) {
    decision = {
      action: 'deny',
      reason: `filterRequest threw: ${(err as Error).message}`,
    }
  }

  if (decision.action === 'allow') {
    logForDebugging(`[request-filter] allow ${req.method} ${url}`)
    return true
  }

  deny(res, decision)
  return false
}

function deny(res: ServerResponse, decision: RequestDecision): void {
  const reason = decision.reason ?? 'denied by filterRequest'
  logForDebugging(`[request-filter] deny: ${reason}`)
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(403, {
    'Content-Type': 'text/plain',
    'X-Proxy-Error': 'blocked-by-sandbox-runtime',
  })
  res.end(reason + '\n')
}

function incomingHeaders(req: IncomingMessage): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const vv of v) h.append(k, vv)
    } else {
      h.append(k, v)
    }
  }
  return h
}
