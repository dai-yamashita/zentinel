# Proxy Architecture

This document describes the internal architecture of the Zentinel proxy dataplane.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Zentinel Proxy                                  │
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Listeners  │    │   Routes    │    │  Upstreams  │    │   Agents    │  │
│  │             │    │             │    │             │    │             │  │
│  │  - HTTP     │───▶│  - Matcher  │───▶│  - Pools    │    │  - WAF      │  │
│  │  - HTTPS    │    │  - Priority │    │  - LB       │    │  - Auth     │  │
│  │  - H2       │    │  - Scoped   │    │  - Health   │    │  - Custom   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                  │                  │                  │          │
│         ▼                  ▼                  ▼                  ▼          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         ZentinelProxy                                  │  │
│  │                    (implements ProxyHttp)                              │  │
│  │                                                                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │  │
│  │  │  Rate    │  │ Circuit  │  │  Cache   │  │  GeoIP   │  │  Static  │ │  │
│  │  │  Limit   │  │ Breaker  │  │ Manager  │  │  Filter  │  │  Files   │ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        Observability Layer                             │  │
│  │                                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │  │
│  │  │   Metrics    │    │   Logging    │    │   Tracing    │            │  │
│  │  │ (Prometheus) │    │ (Structured) │    │ (OpenTelemetry)           │  │
│  │  └──────────────┘    └──────────────┘    └──────────────┘            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Request Lifecycle

The complete flow of a request through the proxy:

```
Client Request
      │
      ▼
┌─────────────────┐
│ 1. TLS Handshake│  SNI-based certificate selection
│    (if HTTPS)   │  mTLS client verification
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. Trace ID     │  Generate or extract from headers
│    Generation   │  X-Trace-Id, X-Correlation-Id, X-Request-Id
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. Route Match  │  Path, host, header, method matching
│                 │  Priority-based evaluation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. Rate Limit   │  Token bucket per route/client
│    Check        │  Local or distributed (Redis/Memcached)
└────────┬────────┘
         │
    ┌────┴────┐
    │ Limited?│───Yes──▶ Return 429
    └────┬────┘
         │ No
         ▼
┌─────────────────┐
│ 5. GeoIP Filter │  Block/allow by country
│    (if enabled) │  MaxMind or IP2Location
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 6. Agent Call   │  on_request_headers
│    (Headers)    │  WAF, auth, custom logic
└────────┬────────┘
         │
    ┌────┴────┐
    │ Blocked?│───Yes──▶ Return block response
    └────┬────┘
         │ Allow
         ▼
┌─────────────────┐
│ 7. Body Read    │  Stream or buffer based on config
│    (if present) │  Decompression with limits
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 8. Agent Call   │  on_request_body (if configured)
│    (Body)       │  WAF body inspection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 9. Upstream     │  P2C, least-tokens, consistent hash
│    Selection    │  Health-aware selection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 10. Circuit     │  Check circuit breaker state
│     Breaker     │  Fast-fail if open
└────────┬────────┘
         │
    ┌────┴────┐
    │  Open?  │───Yes──▶ Return 503
    └────┬────┘
         │ Closed/Half-Open
         ▼
┌─────────────────┐
│ 11. Shadow      │  Fire-and-forget to canary
│     Request     │  Based on sampling rate
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 12. Upstream    │  With connection pooling
│     Request     │  Timeout enforcement
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 13. Agent Call  │  on_response_headers
│     (Response)  │  Header mutations
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 14. Cache Check │  Store if cacheable
│     (if enabled)│  Serve from cache on hit
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 15. Response    │  Compression, header rewrites
│     Processing  │  Agent body processing
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 16. Access Log  │  Structured JSON or combined format
│                 │  Trace ID, latency, status
└────────┬────────┘
         │
         ▼
   Client Response
```

## Component Interactions

### Configuration Hot Reload

```
┌──────────────────────────────────────────────────────────────────┐
│                        Hot Reload Flow                            │
└──────────────────────────────────────────────────────────────────┘

     ┌───────────┐         ┌───────────┐         ┌───────────┐
     │   File    │         │  Signal   │         │   API     │
     │  Change   │         │  (SIGHUP) │         │  Trigger  │
     └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
           │                     │                     │
           └──────────────┬──────┴─────────────────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ ConfigManager   │
                 │   .reload()     │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │   Parse New     │
                 │   Config File   │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │    Validate     │──── Fail ────▶ Rollback + Log
                 │   (Schema +     │
                 │   References)   │
                 └────────┬────────┘
                          │ Pass
                          ▼
                 ┌─────────────────┐
                 │  Atomic Swap    │
                 │                 │
                 │  - Routes       │
                 │  - Upstreams    │
                 │  - Rate Limits  │
                 │  - Agents       │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Graceful Drain  │
                 │ Old Connections │
                 └────────┬────────┘
                          │
                          ▼
                    Reload Complete
```

What a reload does with each top-level block is declared in
`crates/proxy/src/reload/coverage.rs` (#572). The list is an exhaustive
destructure of `Config`, so a new block does not compile until it declares
one:

| Block | On reload |
|-------|-----------|
| `routes`, `upstreams`, `filters`, `agents`, `rate-limits`, `namespaces` | Reconciled: route matchers, route components (error pages, API schema validators, static file servers), pools, health checks, rate limiters, geo filters and agents are rebuilt |
| `waf`, `limits` | Reconciled: read from the current configuration per request / connection |
| `listeners`, `system`, `observability`, `cache` | **Restart required.** A reload that changes one logs a warning naming the block |

The reload handler applies a new configuration in three steps around the swap
of the route matchers:

1. What the new routes refer to goes in first: agents are loaded and replaced,
   route components are rebuilt, geo filters are added or replaced, and rate
   limiters, active health checks and upstream pools are added or replaced.
   Limiters, health checks and geo filters whose configuration did not change
   keep their state. The databases of the geo filters that are added or changed
   are opened before anything is changed; if one does not open, nothing is
   swapped and the reload is rolled back, as it is when the routes do not
   compile.
2. The route matchers are swapped.
3. What the new configuration no longer lists comes out last: agents, geo
   filters, rate limiters, health checks and upstream pools.

A route added by a reload, or whose rate limit or upstream it changed, is
therefore never served without its new limiter or pool, and the routes of the
previous configuration keep theirs until the swap. The upstream pools are built
before the swap, bounded by 10 seconds (the time service discovery lookups may
take). If that runs out, no new pool is installed: the new routes still go
live, the previous pools stay, and a route that names a new upstream fails with
"Upstream pool not found" until the next reload.

#### Requests that arrive during a reload

A reload (or a rollback) stores the configuration first and swaps in the route
matcher afterwards, once what the routes refer to is ready: their agents and
components, geo filters, rate limiters, health checks and upstream pools. The
upstream pools are built first, and an upstream that uses service discovery can
make that wait up to 10 seconds, which the interval then includes. A request
that arrives in between is matched by the previous matcher, so its route may
list a filter id that the stored configuration no longer defines (a filter that
was renamed or removed). Each configuration is valid on its own (validation
rejects a route that lists an undefined filter), so the mismatch exists only in
that interval.

Where a request's route is decided, the proxy takes the configuration
snapshot the request is served under, and checks that every filter id the
route lists is defined in it. Every later filter lookup of the request reads
the same snapshot. If an id is not defined, the route's `failure-mode`
decides:

| `failure-mode` | The request |
|----------------|-------------|
| `closed` (default) | Is answered with `503`. The log names the route and the undefined filter ids |
| `open` | Continues with the filters that are defined. The log names the route and the undefined filter ids |

Both are counted in `zentinel_route_filters_undefined_total`, labelled
`action="refused"` or `action="continued"`. Each affected request logs a
warning, and each refused one an error as well, so a burst of log lines is
expected while the interval lasts.

### Agent Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                     Agent Pipeline                                │
└──────────────────────────────────────────────────────────────────┘

                    Request
                       │
                       ▼
            ┌───────────────────┐
            │   AgentManager    │
            │                   │
            │  Route's agents:  │
            │  [waf, auth, log] │
            └─────────┬─────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │   WAF   │   │  Auth   │   │  Log    │
  │  Agent  │   │  Agent  │   │  Agent  │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       │  Semaphore   │  Semaphore   │  Semaphore
       │  (isolated)  │  (isolated)  │  (isolated)
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │ Circuit │   │ Circuit │   │ Circuit │
  │ Breaker │   │ Breaker │   │ Breaker │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │  Pool   │   │  Pool   │   │  Pool   │
  │  (UDS)  │   │ (gRPC)  │   │  (UDS)  │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       └──────────────┼──────────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Merge Decisions   │
            │                   │
            │ - First BLOCK wins│
            │ - Merge mutations │
            │ - Collect tags    │
            └───────────────────┘
```

### Upstream Selection

```
┌──────────────────────────────────────────────────────────────────┐
│                   Load Balancing Flow                             │
└──────────────────────────────────────────────────────────────────┘

                    Request
                       │
                       ▼
            ┌───────────────────┐
            │   UpstreamPool    │
            │   "api-cluster"   │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │  Get Healthy      │
            │  Targets          │
            └─────────┬─────────┘
                      │
                      ▼
    ┌─────────────────────────────────────┐
    │         Load Balancer               │
    │                                     │
    │  ┌─────────┐  ┌─────────────────┐  │
    │  │   P2C   │  │ Least Tokens    │  │
    │  │ (default)│  │ (for inference) │  │
    │  └─────────┘  └─────────────────┘  │
    │                                     │
    │  ┌─────────────┐  ┌─────────────┐  │
    │  │ Consistent  │  │  Adaptive   │  │
    │  │    Hash     │  │ (latency)   │  │
    │  └─────────────┘  └─────────────┘  │
    └─────────────────┬───────────────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Selected Target   │
            │ 10.0.0.2:8080     │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Connection Pool   │
            │ (reuse or create) │
            └─────────┬─────────┘
                      │
                      ▼
               Send Request
```

### Retrying After an Upstream Error

An error after the connection to the upstream was established, a connection
dropped before the response header for example, can be followed by another
attempt at the same request. The proxy does not send the request again when
the upstream may already have acted on it:

| Request | Sent again after such an error |
|---------|--------------------------------|
| Method GET, HEAD, OPTIONS, TRACE, PUT or DELETE | Yes, as the error type allows |
| Any other method, such as POST, PATCH or QUERY | No, unless the route's `retry-policy` sets `retry-non-idempotent #true` |
| Body larger than the retry buffer | No, whatever the method: the body cannot be replayed |

The methods in the first row are the idempotent methods of RFC 9110 section
9.2.2. Method names are case-sensitive, so `get` is not one of them. The same
rule decides whether a request is sent again on a status code listed in
`retryable-status-codes`.

When the proxy does not send the request again, the client gets the error, a
502 for a dropped connection. The log says `Not retrying a request that may
have been sent to the upstream`, with a `reason` of `non_idempotent_method`,
`retry_buffer_truncated` or `max_attempts`, and
`zentinel_upstream_retries_refused_total{reason}` counts it.

The table does not cover a request that an HTTP/2 upstream says it did not
process: it reset the stream with REFUSED_STREAM, or sent a GOAWAY whose last
stream id is lower than the request's stream (RFC 9113 section 8.7). Pingora's
HTTP/2 client marks both errors retryable; for a GOAWAY that is the error of a
received GOAWAY with NO_ERROR, which the `h2` library gives only to the streams
above the last stream id and to requests it has not sent yet. The proxy sends
such a request again whatever its method, so a POST, a gRPC call included, is
not answered with a 502 by a graceful shutdown of an HTTP/2 upstream. The
method is not looked at, and neither is `retry-non-idempotent`, because the
upstream has not acted on the request. The retry buffer still is, since the
body must be sent again: a body larger than the buffer is not sent again, as in
the table. So is the route's `max-attempts` (see "Attempts per request"): a
request that has made its attempts is not sent again, whatever its method.

Pingora marks HTTP_1_1_REQUIRED, with which the upstream asks for HTTP/1.1, in
the same way, and the proxy treats it the same; section 8.7 does not cover it.
An invalid HTTP/2 frame is different: the GOAWAY with PROTOCOL_ERROR that the
`h2` library sends then reaches every stream of the connection, including
ones the upstream may have processed. Pingora marks it retryable too, but the
proxy checks the request like any other error after it may have been sent: its
method, then the retry buffer, then `max-attempts`.

Pingora's default `error_while_proxy` (since Pingora 0.9) refuses a POST in
every one of these cases; the proxy differs from it for REFUSED_STREAM, GOAWAY
and HTTP_1_1_REQUIRED, on purpose.

The case likely to come up first is a connection the proxy kept for reuse,
which the upstream closed while it was idle. A POST sent on it, and a gRPC
call is a POST, used to be sent again silently on a new connection. It now
gets a 502, and the client decides whether to send it again. To restore the
earlier behavior for a route, set `retry-non-idempotent #true` in its
`retry-policy`.

The retry buffer holds 64 KiB of the request body by default. On a route that
reads the whole body (API schema validation, body inspection, the prompt
check of an inference route, MCP) it is sized to that route's limit instead:
the route's body size limit, never above the global one, or the MCP envelope
limit.

A failure to connect happens before the request is sent, so the method and the
body do not matter. When the target is a host name with another address, the
request is tried on that address. The method and body rules above do not apply
to that retry; `max-attempts` below does, so a route whose `retry-policy` sets
`max-attempts 1` does not try it.

#### Attempts per request

`max-attempts` in a route's `retry-policy` is how many attempts one request may
make, the first one included, whatever made the proxy try again: a retryable
status code, an error after the connection was established, or a failed
connection to one address of a host name that has another. With
`max-attempts 3`, a GET whose connection the upstream keeps dropping is sent
three times, and the client then gets the error. After a retryable status code
the last attempt lets the upstream's response through instead.

The limit applies to the requests that an HTTP/2 upstream did not process too,
although the method does not matter for them: with `max-attempts 3`, a POST
that the upstream answers with REFUSED_STREAM every time is sent to it three
times, and the client gets a 502.

When `max-attempts` stops a retry after an error, the log says `Not retrying a
request that may have been sent to the upstream` with `reason` `max_attempts`.
When it stops a retry on another address of a host name, the log says `Not
retrying on another address of the target`. Both are counted by
`zentinel_upstream_retries_refused_total{reason="max_attempts"}`, and the
client gets the error of the last attempt.

`max-attempts` is a number of attempts, counted the same way for a status
code, an error and another address, so `max-attempts 1` asks for no retry at
all. On such a route:

- When the first address of a host name target does not accept the connection,
  the request fails instead of moving to the next address. The failed address
  is passed over for 30 seconds, so the following requests use the next one.
- A request sent on a connection kept for reuse that the upstream had closed
  while it was idle is not sent again on a new connection, whatever its
  method, and the client gets a 502.

To keep these retries, set `max-attempts` to 2 or more. A `retry-policy` that
does not set `max-attempts` allows 3 attempts.

A route without a `retry-policy` has no limit of its own: a request that fails
after an error is sent again until the server's limit of 16 attempts per
request is reached, or the circuit breaker of the target opens. That limit
also applies to a route whose `max-attempts` is above 16: the request stops
after 16 attempts.

`backoff` and `max-backoff` delay each attempt after the first, whichever of
these made the proxy try again.

## Rate Limiting Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   Rate Limiting Layers                            │
└──────────────────────────────────────────────────────────────────┘

                         Request
                            │
                            ▼
                  ┌───────────────────┐
                  │ Extract Rate Key  │
                  │ (client-ip, header,│
                  │  route, etc.)     │
                  └─────────┬─────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
   ┌───────────┐     ┌───────────┐     ┌───────────┐
   │   Local   │     │   Redis   │     │ Memcached │
   │   Rate    │     │   Rate    │     │   Rate    │
   │  Limiter  │     │  Limiter  │     │  Limiter  │
   └─────┬─────┘     └─────┬─────┘     └─────┬─────┘
         │                  │                  │
         │   In-memory      │  Sliding window  │  Fixed window
         │   token bucket   │  with sorted set │  with incr
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Allowed/Limited  │
                  └───────────────────┘


  For Inference Routes:

                         Request
                            │
                            ▼
                  ┌───────────────────┐
                  │   Count Tokens    │
                  │  (tiktoken/est.)  │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Token Rate Limit  │
                  │ (tokens/minute)   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │   Token Budget    │
                  │ (daily/monthly)   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Cost Tracking    │
                  │ ($ per request)   │
                  └───────────────────┘
```

## Circuit Breaker States

```
┌──────────────────────────────────────────────────────────────────┐
│                   Circuit Breaker FSM                             │
└──────────────────────────────────────────────────────────────────┘


         ┌──────────────────────────────────────────┐
         │                                          │
         │  ┌────────┐                              │
         │  │ CLOSED │◀──────────────────┐          │
         │  └───┬────┘                   │          │
         │      │                        │          │
         │      │ failure_count++        │          │
         │      │                        │          │
         │      ▼                        │          │
         │  ┌────────────────────┐       │          │
         │  │ failure_count >=   │──No───┘          │
         │  │ threshold?         │                  │
         │  └────────┬───────────┘                  │
         │           │ Yes                          │
         │           ▼                              │
         │     ┌──────────┐                         │
         │     │   OPEN   │                         │
         │     └────┬─────┘                         │
         │          │                               │
         │          │ (all requests fast-fail)      │
         │          │                               │
         │          │ after timeout_secs            │
         │          ▼                               │
         │   ┌────────────┐                         │
         │   │ HALF-OPEN  │                         │
         │   └──────┬─────┘                         │
         │          │                               │
         │    ┌─────┴─────┐                         │
         │    │           │                         │
         │    ▼           ▼                         │
         │  Success    Failure                      │
         │    │           │                         │
         │    │ success   │ failure                 │
         │    │ count++   │ → OPEN                  │
         │    │           │                         │
         │    ▼           │                         │
         │  count >=      │                         │
         │  threshold?    │                         │
         │    │           │                         │
         │    ▼           │                         │
         │  CLOSED ◀──────┘                         │
         │                                          │
         └──────────────────────────────────────────┘

  Configuration:
  - failure_threshold: 5 (consecutive failures to open)
  - success_threshold: 2 (consecutive successes to close)
  - timeout_secs: 30 (time in open state before half-open)
  - half_open_max_requests: 1 (trial requests let through in half-open)
```

### What a request tells the breaker

What a request tells the breaker of the target it was sent to. An attempt is
reported at most once. An error of the upstream after the connection was
established is reported when it happens, which is also how an attempt that a
retry replaces is counted. Any other outcome is reported when the request
ends, for its last attempt:

| Outcome | Reported as |
|---------|-------------|
| Status below 500 | Success |
| Status of 500 or more | Failure |
| Connection failure, upstream timeout, upstream read or write error | Failure |
| Client went away, client body over its limit, request or response refused by an agent or filter | No result |

A request with no result is neither a success nor a failure: it does not
reset the run of failures, count towards closing the breaker, or reach the
load balancer's health and latency accounting. When it was a half-open trial,
it gives its trial slot back so another request can take its place; so does
the attempt before a retry, if it reported nothing.

`failure_threshold` counts the failures that are reported. An error of the
upstream after the connection was established counts once per attempt, an
attempt that a retry replaces included. Any other outcome counts once, for the
last attempt. A connection failure that a retry replaces, and a 5xx response
that is discarded for a retry, are not counted.

Shadow requests are never half-open trials: while a target's breaker is open
or half-open it receives no shadow traffic.

If a trial is lost altogether (the request was dropped before it could report
or give its slot back), the half-open period does not wait for it forever.
When the period began (or last started over) at least `timeout_secs` ago and
every slot is still taken, the next request starts it over and is let through
as a new trial. No setting controls this; it reuses `timeout_secs`.

## Scoped Configuration

```
┌──────────────────────────────────────────────────────────────────┐
│                   Scope Hierarchy                                 │
└──────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │     Global      │
                    │                 │
                    │ - Default limits│
                    │ - Global routes │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
     ┌────────────┐   ┌────────────┐   ┌────────────┐
     │ Namespace A│   │ Namespace B│   │ Namespace C│
     │            │   │            │   │            │
     │ - Overrides│   │ - Overrides│   │ - Overrides│
     │ - NS routes│   │ - NS routes│   │ - NS routes│
     └──────┬─────┘   └──────┬─────┘   └──────┬─────┘
            │                │                │
     ┌──────┼──────┐         │         ┌──────┼──────┐
     │      │      │         │         │      │      │
     ▼      ▼      ▼         ▼         ▼      ▼      ▼
  ┌─────┐┌─────┐┌─────┐  ┌─────┐   ┌─────┐┌─────┐┌─────┐
  │Svc 1││Svc 2││Svc 3│  │Svc 4│   │Svc 5││Svc 6││Svc 7│
  └─────┘└─────┘└─────┘  └─────┘   └─────┘└─────┘└─────┘


  Visibility Rules:
  ┌─────────────────────────────────────────────────────────────┐
  │ Scope Level    │ Can See Routes From                        │
  ├─────────────────────────────────────────────────────────────┤
  │ Global         │ Global only                                │
  │ Namespace      │ Global + Own Namespace                     │
  │ Service        │ Global + Namespace + Own Service           │
  └─────────────────────────────────────────────────────────────┘

  Inheritance Chain (for config):
  Service config ─▶ Namespace config ─▶ Global config
         │                  │                │
         └──── overrides ───┴── overrides ───┘
```

## Memory Management

```
┌──────────────────────────────────────────────────────────────────┐
│                   Bounded Memory Design                           │
└──────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │                     Memory Bounds                                │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Request Body Buffer     │  max_body_size_bytes (config)        │
  │  Response Cache          │  max_size_bytes (100MB default)      │
  │  Static File Cache       │  max 1MB per file (mmap > 10MB)      │
  │  Route Match Cache       │  LRU with max_items                  │
  │  Agent Call Queue        │  Semaphore (100 concurrent default)  │
  │  Rate Limit State        │  Per-key with TTL expiration         │
  │  Connection Pool         │  max_connections per upstream        │
  │                                                                  │
  └─────────────────────────────────────────────────────────────────┘

  Decompression Protection:
  ┌─────────────────────────────────────────────────────────────────┐
  │  max_ratio: 100x       │  Prevents zip bombs                    │
  │  max_output: 10MB      │  Absolute size limit; for a            │
  │                        │  request body: `max-inspection-bytes`  │
  │  incremental check     │  Stop early if ratio exceeded          │
  └─────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Lock-Free Hot Paths

```rust
// DashMap for concurrent access without global locks
let rate_limiters: DashMap<RouteId, RateLimiter> = DashMap::new();

// Atomic operations for counters
let request_count: AtomicU64 = AtomicU64::new(0);
```

### 2. Registry Pattern for Atomic Config Swap

```rust
// Old config continues serving in-flight requests
// New config takes effect for new requests atomically
let config: Arc<RwLock<Config>> = Arc::new(RwLock::new(config));

// Swap is atomic - no torn reads
*config.write() = new_config;
```

### 3. Queue Isolation (Noisy Neighbor Prevention)

```rust
// Each agent has its own semaphore
struct Agent {
    semaphore: Semaphore,  // Limits concurrent calls to THIS agent
    // ...
}

// Slow agent A doesn't affect agent B's queue
```

### 4. Fire-and-Forget for Non-Critical Paths

```rust
// Shadow requests don't block the response
tokio::spawn(async move {
    let _ = shadow_request(req).await;
    // Result ignored - fire and forget
});
```

### 5. Graceful Degradation

```rust
// Fallback to local rate limiting if Redis fails
match redis_check().await {
    Ok(result) => result,
    Err(_) => local_rate_limiter.check(),
}
```
