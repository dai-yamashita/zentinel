# Configuration Schema Reference

Complete reference for all Zentinel configuration options.

## Table of Contents

- [Server](#server)
- [Listeners](#listeners)
  - [ACME](#acmeconfig)
  - [DNS Provider](#dnsproviderconfig)
- [Routes](#routes)
- [Upstreams](#upstreams)
- [Filters](#filters)
- [Agents](#agents)
- [WAF](#waf)
- [Observability](#observability)
- [Limits](#limits)
- [Cache](#cache)
- [Accepted but not applied](#accepted-but-not-applied)

---

## Server

Global server configuration.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `worker-threads` | `u32` | `0` | Number of worker threads (0 = auto-detect CPU cores) |
| `max-connections` | `u32` | `10000` | Not applied ([details](#accepted-but-not-applied)). Client connections are not limited |
| `graceful-shutdown-timeout-secs` | `u64` | `30` | On SIGTERM/SIGINT, how long to wait for open connections to close before exiting (seconds). The process exits earlier once none are left. A second SIGTERM/SIGINT while it waits ends the process at once |
| `daemon` | `bool` | `false` | Run as daemon, as with `-d`. The configuration is checked before the fork, so a broken one fails in the foreground |
| `pid-file` | `string` | `/tmp/pingora.pid` | Path to the PID file a daemon writes (an existing one is renamed to `<pid-file>.old`) |
| `user` | `string` | - | User a daemon switches to once the configuration, TLS keys and log files are loaded, before listeners are bound. Ignored in the foreground |
| `group` | `string` | primary group of `user` | Group a daemon switches to, at the same point as `user`. Ignored in the foreground |
| `working-directory` | `string` | - | Working directory |
| `trace-id-format` | `string` | `"tinyflake"` | Trace ID format (`tinyflake` or `uuid`) |
| `auto-reload` | `bool` | `false` | Auto-reload config on file changes |
| `route-cache-size` | `u32` | `1000` | Max entries in the route-match cache (per route set); must be > 0. Evictions counted in `zentinel_route_cache_evictions_total` |
| `client-ipv6-prefix-length` | `u8` | `64` | How many leading bits of an IPv6 client address identify one client in the per-client limits: `max-connections-per-client` (global, namespace and service) and every rate limit keyed on the client's address (`client-ip`, `client-ip-and-path`, `client-ip-and-mcp-tool`, and the per-client token rate limit and token budget of inference routes). The addresses of one prefix are counted as one client. A whole number from 1 to 128; anything else is a configuration error. `128` counts each IPv6 address on its own, which suits unrelated hosts that share one `/64` (a LAN, a hosting provider's subnet). IPv4 addresses, and IPv4-mapped IPv6 addresses (which are the IPv4 client), are always counted one by one. Read at startup |

> **Hot reload caveat:** routes, upstreams, filters, and agents are applied by
> hot reload (SIGHUP / auto-reload). Listener bindings and `system` settings
> are **not** — the proxy logs a warning if they changed and keeps the running
> values until restart.

---

## Listeners

Port binding configuration.

### ListenerConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique listener identifier |
| `address` | `string` | **required** | Socket address (e.g., `0.0.0.0:8080`) |
| `protocol` | `string` | `"http"` | Protocol: `http`, `https`, `h2`, `h3`, `h2c` |
| `tls` | `TlsConfig` | - | TLS configuration: required for `https` and `h2`, and an error for `http` (the default) and `h2c` |
| `default-route` | `string` | - | Default route if no match |
| `request-timeout-secs` | `u64` | `60` | Request timeout |
| `keepalive-timeout-secs` | `u64` | `75` | Keep-alive timeout |
| `max-concurrent-streams` | `u32` | `100` | Not applied ([details](#accepted-but-not-applied)). The listener's HTTP/2 stream limit is not set from it |

### TlsConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `cert-file` | `string` | **required** | Certificate file path |
| `key-file` | `string` | **required** | Private key file path |
| `ca-file` | `string` | - | CA certificate for client verification |
| `min-version` | `string` | `"tls1.2"` | Lowest TLS version to accept: `1.2` or `1.3` (see below) |
| `max-version` | `string` | - | Highest TLS version to accept, written like `min-version`; TLS 1.3 when not set |
| `cipher-suite` | `string` (repeatable) | `[]` | Cipher suite, one node per suite (empty = defaults) |
| `client-auth` | `bool` | `false` | Require client certificates (mTLS) |
| `ocsp-stapling` | `bool` | `true` | Staple OCSP responses fetched from each certificate's AIA responder; `cert-file` must include the issuer |
| `session-resumption` | `bool` | `true` | Let clients resume earlier sessions; `#false` makes every connection a full handshake (see below) |
| `sni` | `SniCertificate` (repeatable) | `[]` | Additional certs for SNI, one block per cert |
| `acme` | `AcmeConfig` | - | ACME automatic certificate management |

Unknown nodes inside `tls` and `sni` blocks are rejected at parse time.

**`min-version` and `max-version`.** Only TLS 1.2 and TLS 1.3 are supported.
Each is written as `1.2`, `tls1.2` or `tlsv1.2` (likewise `1.3`), in any letter
case, and the listener accepts the versions from `min-version` up to
`max-version`. Any other value, such as `"TLS 1.3"`, `"tls13"`, `"1.4"` or
`"1.0"`, is a load error that names the listener, the value and the accepted
values; TLS 1.0 and 1.1 are not supported. A `min-version` above `max-version`
(for example `min-version "1.3"` with `max-version "1.2"`) leaves no version to
serve and is an error: at load for KDL, in `validate` for a config built from
JSON, TOML or code. The same value for both pins one version.

**`session-resumption`.** With `true`, each listener keeps rustls's default
session cache in process memory: up to 256 sessions, dropping the oldest first
when it is full, with no time-based expiry on the server and nothing kept
across a restart. Clients that kept their session state can then skip the full
handshake: over TLS 1.2 by session ID, over TLS 1.3 by ticket. Every TLS 1.3
handshake, a resumed one included, sends two tickets (none when the client does
not offer `psk_dhe_ke`); each takes one cache entry, is good for one
resumption, and is advertised to the client as valid for 24 hours. TLS 1.2
session tickets are not used. A session resumes only for the same server name
and cipher suite. Write
`session-resumption #false` to turn this off: no session is stored, no ticket
is issued, and every connection does a full handshake.

### AcmeConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `email` | `string` | **required** | Contact email for ACME account |
| `domains` | `[string]` | **required** | Domains to include in certificate |
| `server-url` | `string` | - | Custom ACME directory URL (e.g., ZeroSSL) |
| `staging` | `bool` | `false` | Use Let's Encrypt staging environment |
| `eab` | `ExternalAccountBinding` | - | EAB credentials (required by some CAs) |
| `storage` | `string` | `/var/lib/zentinel/acme` | Certificate storage directory |
| `renew-before-days` | `u32` | `30` | Days before expiry to trigger renewal |
| `challenge-type` | `string` | `"http-01"` | Challenge type: `http-01` or `dns-01` |
| `key-type` | `string` | `"ecdsa-p256"` | Key type: `ecdsa-p256`, `ecdsa-p384` |
| `dns-provider` | `DnsProviderConfig` | - | DNS provider (required for dns-01) |

### ExternalAccountBinding

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `kid` | `string` | **required** | Key ID provided by the ACME CA |
| `hmac-key` | `string` | **required** | HMAC key (base64url-encoded) from the CA |

### DnsProviderConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `type` | `string` | **required** | Provider: `cloudflare`, `hetzner`, `webhook` |
| `credentials-file` | `string` | - | Path to credentials file (for `hetzner`: a Hetzner Cloud API token with Read & Write permission; old DNS Console tokens no longer work) |
| `credentials-env` | `string` | - | Environment variable with credentials |
| `api-timeout-secs` | `u64` | `30` | API request timeout |
| `url` | `string` | - | Webhook URL (for webhook provider) |
| `auth-header` | `string` | - | Auth header name (for webhook provider) |
| `propagation` | `PropagationConfig` | `{}` | Propagation check settings |

### PropagationConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `initial-delay-secs` | `u64` | `10` | Wait before first propagation check |
| `check-interval-secs` | `u64` | `5` | Interval between checks |
| `timeout-secs` | `u64` | `120` | Max time to wait for propagation |
| `nameservers` | `[string]` | `[]` | DNS servers to query (empty = public DNS) |

### ListenerProtocol

| Value | Description |
|-------|-------------|
| `http` | HTTP/1.1, cleartext |
| `https` | TLS, HTTP/2 or HTTP/1.1 negotiated with ALPN. Needs a `tls` block |
| `h2` | The same as `https`. Needs a `tls` block |
| `h3` | HTTP/3 (QUIC). Not implemented: rejected by validation |
| `h2c` | HTTP/2 over cleartext TCP with prior knowledge. No `tls` block; a client that does not open with the HTTP/2 preface within 10 s is refused (`505` if it sent something else) |

---

## Routes

Request routing configuration.

### RouteConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique route identifier |
| `priority` | `string` | `"normal"` | Priority: `low`, `normal`, `high`, `critical` |
| `matches` | `[MatchCondition]` | **required** | Match conditions |
| `upstream` | `string` | - | Target upstream ID |
| `service-type` | `string` | `"web"` | Service type |
| `policies` | `RoutePolicies` | `{}` | Route policies |
| `cache` | `RouteCacheConfig` | - | HTTP caching config (see [Cache](#routecacheconfig)) |
| `filters` | `[string]` | `[]` | Filter IDs to apply |
| `builtin-handler` | `string` | - | Built-in handler (for `builtin` service type) |
| `waf-enabled` | `bool` | `false` | Not applied ([details](#accepted-but-not-applied)). It does not change how requests are handled; a route's traffic is inspected by the agents its `filters` list |
| `circuit-breaker` | `CircuitBreakerConfig` | - | Circuit breaker settings |
| `retry-policy` | `RetryPolicy` | - | Retry policy |
| `static-files` | `StaticFileConfig` | - | Static file config (for `static` type) |
| `api-schema` | `ApiSchemaConfig` | - | API schema validation |
| `inference` | `InferenceConfig` | - | Inference config (for `inference` type) |
| `error-pages` | `ErrorPageConfig` | - | Custom error pages |
| `websocket` | `bool` | `false` | Enable WebSocket upgrade |
| `websocket-inspection` | `bool` | `false` | Inspect WebSocket frames. No WebSocket extension (such as `permessage-deflate`) is negotiated on the route, and a frame that cannot be decoded closes the connection. See [WebSocket inspection](../../proxy/docs/websocket.md) |
| `websocket-max-frame-size` | `bytes` | `1MB` | Largest WebSocket frame payload the route's inspection decodes, as a byte count or a size such as `"4MB"`. Between 1 byte and 16MB. A larger frame closes the connection with status 1009. A frame too large for an agent's transport to carry in one message fails the call to the agent and follows its filter's `failure-mode`. Only used with `websocket-inspection`, and `zentinel lint` warns when it is set without |
| `shadow` | `ShadowConfig` | - | Traffic mirroring config |
| `fallback` | `FallbackConfig` | - | Fallback routing config. A block of the route itself, beside `inference`; inside `inference` it is not read |

### RetryPolicy

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-attempts` | `u32` | `3` | Attempts at one request, the first one included |

`max-attempts` bounds how often one request is sent to the upstream, whatever
made the proxy try again: a retryable status code, an error after the
connection was established, or a failed connection to one address of a host
name target that has another. With `max-attempts 3` a request is attempted at
most three times. `max-attempts 1` asks for no retry at all: a request that
fails on a connection kept for reuse, or on the first address of a host name
target, is not tried again. It applies to a request that an HTTP/2 upstream
did not process (REFUSED_STREAM, GOAWAY) too, whatever its method. A
`max-attempts` above 16 changes nothing beyond 16, where the server stops a
request.

A route without a `retry-policy` has no such limit. A request that fails after
an error on such a route is sent again until the server's limit of 16 attempts
per request is reached, or the circuit breaker of the target opens. See
[Retrying After an Upstream Error](../../proxy/docs/architecture.md) for what
is retried and when a retry is refused.

> The other keys of `retry-policy` (`retryable-status-codes`, `backoff`,
> `max-backoff`, `per-attempt-timeout`, `retry-non-idempotent`) are not listed
> in this table yet. `timeout-ms`, `backoff-base-ms` and `backoff-max-ms`,
> which appeared in older examples, are rejected at parse time.

### MatchCondition

| Type | Example | Description |
|------|---------|-------------|
| `path-prefix` | `"/api"` | Match path prefix |
| `path` | `"/health"` | Match exact path |
| `path-regex` | `"^/users/\\d+$"` | Match path regex |
| `host` | `"api.example.com"` | Match Host header |
| `header` | `name="X-Api-Key"` | Match header presence/value |
| `method` | `["GET", "POST"]` | Match HTTP methods |
| `query-param` | `"version" "v2"` | Match query parameter |

`query-param "name"` matches a request whose query string has a parameter of
that name, with any value: `?name=1`, `?name=` and `?name` all count.
`query-param "name" "value"` also requires the parameter's value to equal
`value`. The comparison is exact and case-sensitive, after the request's names
and values are percent-decoded (`+` is not read as a space). A name or value
whose decoding is not valid UTF-8 is compared as it was written. A query string
that repeats a name is compared on its last occurrence. The query string is not
part of the path, so `path`, `path-prefix` and `path-regex` never see it.

```kdl
route "v2-api" {
    matches {
        path-prefix "/api"
        query-param "version" "v2"
    }
    upstream "api-v2"
}
```

### ServiceType

| Value | Description |
|-------|-------------|
| `web` | Traditional web service (default) |
| `api` | REST API with JSON responses |
| `static` | Static file hosting |
| `builtin` | Built-in handler |
| `inference` | LLM/AI inference endpoint |

### BuiltinHandler

| Value | Description |
|-------|-------------|
| `status` | JSON status page |
| `health` | Health check endpoint |
| `metrics` | Prometheus metrics |
| `not-found` | 404 handler |
| `config` | Config dump (admin) |
| `upstreams` | Upstream health (admin) |
| `cache-purge` | Cache purge (admin) |
| `cache-stats` | Cache statistics (admin) |

A builtin route is served on the listeners that serve the route, like any
other: written at the top level, it answers on every listener without a
`namespace`. Declare `metrics` and the handlers marked "admin" in a namespace
whose listener is bound to loopback, as the embedded default configuration does
for `metrics` (see
[Builtin routes and listeners](kdl-format.md#builtin-routes-and-listeners)).

A `builtin` route's `filters` apply to it as they do to a proxied route's
request: rate limit, geo, redirect and CORS preflight, and agent filters run
before the handler answers (agents get the `request-headers` event only), and
`headers` and CORS filters apply to its response. A route with `filters` passes
every check a proxied route passes first: `rate-limits` (`global`,
`default-rps`) and the route's own rate limit, the request-body limit,
`max-header-count` and `max-header-size`, and the WebSocket upgrade check. Do
not put `filters` on a route that is probed for health. A route with no
`filters` is answered first, before any of these checks, and calls no agent:
`policies { rate-limit }`, `max-body-size`, `rate-limits { global }` and
`default-rps` do not apply to it. No `builtin` route is refused by
`limits { max-in-flight-requests }`.

### RoutePolicies

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `request-headers` | `HeaderModifications` | `{}` | Request header modifications |
| `response-headers` | `HeaderModifications` | `{}` | Response header modifications |
| `timeout-secs` | `u64` | - | Request timeout override |
| `max-body-size` | `string` | - | Body size limit (e.g., `"10MB"`) |
| `rate-limit` | `RateLimitPolicy` | - | Rate limit policy |
| `failure-mode` | `string` | `"closed"` | Failure mode: `open` or `closed`. Also decides what a request gets when the route lists a filter the active configuration does not define, which only happens while a reload or rollback is being applied: `closed` answers 503, `open` continues with the filters that are defined |
| `cache` | `RouteCacheConfig` | - | Not read inside `policies`: a route's cache is the route's own `cache` block, beside `policies` (see [RouteCacheConfig](#routecacheconfig)) |

### RouteCacheConfig

Per-route cache configuration, written as a `cache` block in the route itself,
beside `policies`. A `cache` block inside `policies` is not read.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable caching for this route |
| `default-ttl-secs` | `u64` | `3600` | Default TTL in seconds, for a response without `max-age` or `s-maxage`. At most 2147483648 (2^31); a larger value is applied as 2147483648, with a warning at startup |
| `max-size-bytes` | `usize` | - | Max cached response size |
| `cacheable-methods` | `[string]` | `["GET", "HEAD"]` | HTTP methods to cache |
| `cacheable-status-codes` | `[u16]` | `[200, 203, 204, 206, 300, 301]` | Status codes to cache (each 100 to 599) |
| `stale-while-revalidate-secs` | `u32` | - | Serve stale while refreshing (at most `4294967295`) |
| `stale-if-error-secs` | `u32` | - | Serve stale on upstream error (at most `4294967295`) |
| `vary-headers` | `[string]` | `[]` | Not applied ([details](#accepted-but-not-applied)). The response's `Vary` decides which request headers keep entries apart |
| `ignore-query-params` | `[string]` | `[]` | Not applied ([details](#accepted-but-not-applied)). The query string is part of the cache key as written |
| `exclude-extensions` | `[string]` | `[]` | File extensions to exclude from caching (without dot, e.g., `"php"`, `"html"`) |
| `exclude-paths` | `[string]` | `[]` | Path patterns to exclude from caching (glob: `*`, `**`, `?`) |

Other names are not settings and are reported as unknown keys by
`zentinel lint`: `ttl-secs` (the TTL is `default-ttl-secs`),
`respect-cache-control` and `ignore-no-cache`.

Responses to requests with `Authorization` (unless `Cache-Control` has `public`, `s-maxage` or `must-revalidate`), responses with `Set-Cookie`, and responses with `Vary: *` are not stored. Any other `Vary` keeps one entry per value of the request headers it names. See [What the Response Cache Stores](kdl-format.md#what-the-response-cache-stores).

### InferenceConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `provider` | `string` | `"generic"` | Provider: `generic`, `openai`, `anthropic` |
| `model-header` | `string` | - | Not applied ([details](#accepted-but-not-applied)). Model routing reads the model name only from the `x-model` or `x-model-id` request header; token counting also reads `model` from the request body |
| `rate-limit` | `TokenRateLimit` | - | Token-based rate limiting |
| `budget` | `TokenBudgetConfig` | - | Token budget tracking |
| `cost-attribution` | `CostAttributionConfig` | - | Per-model pricing |
| `routing` | `InferenceRouting` | - | Not applied ([details](#accepted-but-not-applied)). No upstream is chosen by it; an upstream's strategy is its `load-balancing` |
| `model-routing` | `ModelRoutingConfig` | - | Model-based upstream routing: `model "<pattern>" upstream="<id>"` rules and `default-upstream "<id>"`, written directly in the block (a `mappings { mapping ... }` block is not read) |
| `guardrails` | `GuardrailsConfig` | - | Semantic guardrails |

### TokenRateLimit

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `tokens-per-minute` | `u64` | **required** | Max tokens per minute |
| `requests-per-minute` | `u64` | - | Max requests per minute |
| `burst-tokens` | `u64` | `10000` | Burst token allowance |
| `estimation-method` | `string` | `"chars"` | Token estimation: `chars`, `words`, `tiktoken` |

### TokenBudgetConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `period` | `string` | `"daily"` | Budget period: `hourly`, `daily`, `monthly`, or seconds |
| `limit` | `u64` | **required** | Total tokens allowed in the period |
| `alert-thresholds` | `[f64]` | `[0.80, 0.90, 0.95]` | Usage fractions that fire alerts |
| `enforce` | `bool` | `true` | Block requests when exhausted |
| `rollover` | `bool` | `false` | Carry unused tokens into the next period |
| `burst-allowance` | `f64` | - | Soft-limit burst fraction above the limit |
| `max-tenants` | `usize` | `10000` | Max distinct tenants tracked in memory; expired tenants are evicted at the cap (see `zentinel_inference_budget_tenants` / `zentinel_inference_budget_tenant_evictions_total` metrics) |

### GuardrailsConfig

| Property | Type | Description |
|----------|------|-------------|
| `prompt-injection` | `PromptInjectionConfig` | Prompt injection detection |
| `pii-detection` | `PiiDetectionConfig` | PII detection |

### PromptInjectionConfig

Checked on the request body. On a route with it enabled, the whole request
body is read before an upstream is chosen, up to the route's body-size limit
(`413` above it). See [Prompt check](../../proxy/docs/inference.md#prompt-check).

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `#false` | Run the check |
| `agent` | `string` | **required** | Guardrail agent to ask (over a Unix socket) |
| `action` | `string` | `"log"` | When the agent flags the content: `block`, `warn` or `log` |
| `block-status` | `int` | `400` | Status of the refusal when `action "block"` and the agent flags the content (also of a refusal for a body with no text to check, under `failure-mode "closed"`) |
| `block-message` | `string` | - | Message of the refusal when `action "block"` and the agent flags the content |
| `timeout-ms` | `int` | `500` | How long to wait for the agent |
| `failure-mode` | `string` | `"open"` | When the check cannot be made (agent timeout or failure, no text to check in the body): `open` forwards the request, `closed` refuses it. Not for the body-size limit: a body over it gets `413` either way |

The text checked is taken from the request body as described in
[Prompt check](../../proxy/docs/inference.md#prompt-check): `messages[].content`
(a string, or the `text` of its parts), `prompt`, or `input` (a string or an
array of strings), `text`, `query`, `question`. A body of another shape, or
with a `Content-Encoding` other than `identity`, has no text to check. A
WebSocket upgrade and a proxied MCP tool call are not checked.

### FallbackConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `fallback-upstream` | `[FallbackUpstream]` | `[]` | Ordered fallback upstreams, one `fallback-upstream "<id>" { provider ...; model-mapping { ... } }` node each. An `upstream` node, or `model-mapping` directly in `fallback`, is not read |
| `triggers` | `FallbackTriggers` | `{}` | Conditions that trigger fallback |
| `max-attempts` | `u32` | `3` | Max fallback attempts |

---

## Upstreams

Backend server pool configuration.

### UpstreamConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique upstream identifier |
| `targets` | `[UpstreamTarget]` | **required** unless `discovery` is set | Backend targets |
| `discovery` | `UpstreamDiscovery` | - | Service discovery source for targets |
| `load-balancing` | `string` | `"round-robin"` | Load balancing algorithm |
| `health-check` | `HealthCheck` | - | Health check configuration |
| `connection-pool` | `ConnectionPoolConfig` | `{}` | Connection pool settings |
| `timeouts` | `UpstreamTimeouts` | `{}` | Timeout settings |
| `tls` | `UpstreamTlsConfig` | - | TLS configuration. `ca-cert` inside it is not applied ([details](#accepted-but-not-applied)) |
| `http-version` | `HttpVersionConfig` | `{}` | HTTP version settings |
| `h2c` | `bool` | `#false` | HTTP/2 over cleartext TCP with prior knowledge. Only without `tls`; never falls back to HTTP/1.1 |

### HttpVersionConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `min-version` | `1` or `2` | `1` | Lowest HTTP version to use with the upstream |
| `max-version` | `1` or `2` | `2` | Highest HTTP version to use with the upstream |
| `h2-ping-interval` | `int` (seconds) | `0` (off) | HTTP/2 PING interval on idle connections |
| `max-h2-streams` | `int` | `100` | Concurrent streams per HTTP/2 connection |

With `tls`, HTTP/2 is negotiated with ALPN within this range. Without `tls`
there is no negotiation: the upstream is spoken to over HTTP/1.1, unless
`h2c #true` is set, which uses HTTP/2 only. A plain upstream with
`min-version 2` and no `h2c` is a configuration error, as is `h2c` together
with `tls`, `max-version 1` or `min-version 1`.

### UpstreamDiscovery

Written as `discovery "<kind>" { ... }`. Targets resolved from the source are
added to any statically configured `targets`, and re-resolved on the interval
below. Settings are checked against the named kind: a setting belonging to a
different kind is a configuration error, not an ignored key.

| Kind | Settings | Refresh |
|------|----------|---------|
| `static` | `backends` (one or more `host:port`) | never |
| `dns` | `hostname`, `port`, `refresh-interval` (`30`) | `refresh-interval` |
| `dns-srv` | `service`, `refresh-interval` (`30`) | `refresh-interval` |
| `consul` | `address`, `service`, `datacenter`, `only-passing` (`#true`), `tag`, `refresh-interval` (`30`) | `refresh-interval` |
| `kubernetes` | `namespace`, `service`, `port-name`, `kubeconfig`, `refresh-interval` (`30`) | `refresh-interval` |
| `file` | `path`, `watch-interval` (`5`) | `watch-interval` |

Intervals are in seconds and must be greater than zero.

### UpstreamTarget

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `address` | `string` | **required** | Target address (host:port) |
| `weight` | `u32` | `1` | Weight for load balancing |
| `max-requests` | `u32` | - | Max concurrent requests |
| `metadata` | `map` | `{}` | Target metadata |

### LoadBalancingAlgorithm

| Value | Description |
|-------|-------------|
| `round-robin` | Round-robin (default) |
| `weighted-round-robin` | Weighted round-robin |
| `random` | Random selection |
| `least-connections` | Least connections |
| `ip-hash` | Client IP hash |

### HealthCheck

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `type` | `string` | **required** | Check type: `tcp`, `http`, `https`, `grpc`, `inference` |
| `path` | `string` | - | HTTP path (for http/https) |
| `interval-secs` | `u64` | `10` | Check interval |
| `timeout-secs` | `u64` | `5` | Check timeout |
| `healthy-threshold` | `u32` | `2` | Successes to mark healthy |
| `unhealthy-threshold` | `u32` | `3` | Failures to mark unhealthy |

### ConnectionPoolConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-connections` | `u32` | `100` | Not applied ([details](#accepted-but-not-applied)). Connections to a target are not capped by it |
| `max-idle` | `u32` | `20` | Not applied ([details](#accepted-but-not-applied)). The idle connections kept are a fixed value for the whole proxy (256), not set per upstream |
| `idle-timeout-secs` | `u64` | `60` | Idle connection timeout |
| `max-lifetime-secs` | `u64` | - | Not applied ([details](#accepted-but-not-applied)). Connections are not closed because of their age. `max-lifetime` is the same setting |

### UpstreamTimeouts

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `connect-secs` | `u64` | `10` | Connection timeout |
| `request-secs` | `u64` | `60` | Request timeout |
| `read-secs` | `u64` | `30` | Read timeout |
| `write-secs` | `u64` | `30` | Write timeout |

---

## Filters

Reusable filter definitions.

### FilterConfig

| Property | Type | Description |
|----------|------|-------------|
| `id` | `string` | Unique filter identifier |
| `type` | `string` | Filter type |
| *...* | *varies* | Type-specific properties |

### Filter Types

#### rate-limit

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-rps` | `u32` | **required** | Max requests per second |
| `burst` | `u32` | `10` | Burst size |
| `key` | `string` | `"client-ip"` | Rate limit key |
| `on-limit` | `string` | `"reject"` | Action: `reject`, `delay`, `log-only` |
| `status-code` | `u16` | `429` | Response status when limited (100 to 599) |
| `backend` | `string` | `"local"` | Storage: `local`, `redis`, `memcached` |
| `max-keys` | `usize` | `100000` | Max distinct keys tracked in memory; idle keys are evicted at the cap (see `zentinel_rate_limit_keys` / `zentinel_rate_limit_key_evictions_total` metrics) |

#### headers

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `phase` | `string` | `"request"` | Phase: `request`, `response`, `both` |
| `set` | `map` | `{}` | Headers to set |
| `add` | `map` | `{}` | Headers to add |
| `remove` | `[string]` | `[]` | Headers to remove |

#### compress

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `algorithms` | `[string]` | `["gzip"]` | `gzip`, `zstd`, in order of preference: the first one the client accepts (q > 0) is used. `br` (`brotli`) is accepted but skipped with a warning: Pingora's Brotli encoder does not finish its stream. `deflate` is rejected. Also accepted comma-separated in one string. Does not transcode a response the upstream already encoded in a coding the client accepts |
| `min-size` | `u32` | `1024` | Minimum size to compress |
| `content-types` | `[string]` | `text/html`, `text/css`, `application/json`, `application/javascript` | MIME type prefixes to compress |
| `level` | `u8` | `6` | Compression level (1-9) |

#### cors

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `allowed-origins` | `[string]` | `["*"]` | Allowed origins |
| `allowed-methods` | `[string]` | *all methods* | Allowed methods |
| `allowed-headers` | `[string]` | `[]` | Allowed headers |
| `exposed-headers` | `[string]` | `[]` | Exposed headers |
| `allow-credentials` | `bool` | `false` | Allow credentials |
| `max-age-secs` | `u64` | `86400` | Preflight cache time |

#### geo

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `database-path` | `string` | **required** | Path to GeoIP database. The file must open at startup, or Zentinel does not start; `zentinel test` and `zentinel validate` open it too. A reload whose configuration names a file that does not open is rejected |
| `database-type` | `string` | - | Database type: `maxmind`, `ip2location`. Taken from the extension of `database-path` when unset (`.mmdb` is MaxMind, `.bin` is IP2Location, in any case). Required when the extension is neither. Any other value is an error |
| `action` | `string` | `"block"` | Action: `block`, `allow`, `log-only`. Any other value is an error |
| `countries` | `[string]` | `[]` | ISO 3166-1 alpha-2 codes: two uppercase ASCII letters. KDL upper-cases what is written; JSON and TOML are not changed, so a lower-case code there is an error. Every KDL argument is read, and each may hold a comma-separated list: `countries "RU" "CN"` and `countries "RU,CN"` are the same. Must not be empty when `action` is `allow` |
| `on-failure` | `string` | `"open"` | Failure mode when a lookup fails: `open`, `closed`. Any other value is an error |
| `status-code` | `u16` | `403` | Block status code (100 to 599) |
| `cache-ttl-secs` | `u64` | `3600` | Lookup cache TTL |

#### agent

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `agent` | `string` | **required** | Agent ID reference |
| `phase` | `string` | `"request"` | Execution phase |
| `timeout-ms` | `u64` | - | Timeout override for every call this filter's agent gets on the route (request and response headers and bodies); can only shorten the agent's `timeout-ms` |
| `failure-mode` | `string` | - | What a failed call to the agent means on routes using the filter: `open` continues, `closed` refuses (503; on a response body, the response is aborted). Unset uses the route's `policies { failure-mode }`. Applies to every request and response path and to WebSocket frames. A request body longer than the agent's limit, or than `body-inspection { max-inspection-bytes }`, follows it too: `closed` refuses with 413, `open` skips the agent |
| `inspect-body` | `bool` | - | `#false` sends this agent no request body on routes using the filter; unset or `#true` leaves it to the agent's `events` |
| `max-body-bytes` | `u64` | - | Lowers the agent's `max-request-body-bytes` for routes using the filter; cannot raise it |

---

## Agents

External processing agent configuration.

### AgentConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique agent identifier |
| `type` | `string` | **required** | Agent type: `waf`, `auth`, `rate-limit`, `custom` |
| `transport` | `AgentTransport` | **required** | Transport configuration |
| `events` | `[string]` | **required** | Events to handle |
| `timeout-ms` | `u64` | `1000` | Call timeout (must be > 0) |
| `connect-timeout-ms` | `u64` | `5000` | Longest a new connection waits for the agent to accept it and answer the handshake (must be > 0). An agent that does not answer is not used and is reconnected in the background; its filters follow their `failure-mode` |
| `failure-mode` | `string` | - | **Deprecated, no effect** (#586). A failed call follows the agent filter's `failure-mode`, else the route's `policies { failure-mode }`, on every path including WebSocket frames. Reported by `zentinel test`; will be removed in a later release |
| `circuit-breaker` | `CircuitBreakerConfig` | - | Circuit breaker |
| `max-request-body-bytes` | `u64` | `1048576` (1 MiB) | Max request body inspected by this agent. Larger bodies follow the filter's `failure-mode`: `closed` blocks with 413, `open` skips this agent with a warning and metric |
| `max-response-body-bytes` | `u64` | `1048576` (1 MiB) | Max response body inspected by this agent (same failure-mode semantics) |
| `request-body-mode` | `string` | `"buffer"` | How the request body is sent: `buffer` (the whole body, held back until the agents have decided; one longer than `max-inspection-bytes` is not sent, see [BodyInspectionPolicy](#bodyinspectionpolicy)), `stream` (each chunk as it arrives), `hybrid` / `hybrid:<bytes>` (buffer up to the threshold, default 64 KiB, then stream), `inspect-first` (the whole body, up to the route's body-size limit, decided on before the upstream is contacted; request-header changes apply; #608). One body goes to all of a route's body agents in one mode; when they disagree, `inspect-first` wins over `buffer` over `hybrid` (largest threshold) over `stream` |
| `max-concurrent-calls` | `u32` | `100` | Most calls to this agent at once. A call waits for a free slot within its `timeout-ms` (the filter's, else the agent's), which covers the wait and the call together; a call that gets no slot in time is not made and follows the filter's `failure-mode` (`closed`: 504) |

### AgentTransport

```kdl
// Unix socket
transport {
    unix-socket "/var/run/agent.sock"
}

// gRPC
transport {
    grpc {
        address "localhost:50051"
        tls { ... }
    }
}

// HTTP
transport {
    http {
        url "http://localhost:8080/agent"
        tls { ... }
    }
}
```

### AgentEvent

| Value | Description |
|-------|-------------|
| `request-headers` | Request headers received |
| `request-body` | Request body chunks |
| `response-headers` | Response headers received |
| `response-body` | Response body chunks |
| `log` | Request complete (logging) |
| `websocket-frame` | WebSocket frame received |

---

## WAF

Web Application Firewall configuration.

### WafConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `engine` | `string` | **required** | Engine: `modsecurity`, `coraza`, `custom` |
| `mode` | `string` | `"prevention"` | Mode: `off`, `detection`, `prevention` |
| `audit-log` | `bool` | `true` | Enable audit logging |
| `ruleset` | `WafRuleset` | **required** | Ruleset configuration |
| `body-inspection` | `BodyInspectionPolicy` | `{}` | Body inspection policy |

### WafRuleset

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `crs-version` | `string` | **required** | CRS version (e.g., `"4.0"`) |
| `custom-rules-dir` | `string` | - | Custom rules directory |
| `paranoia-level` | `u8` | `1` | Paranoia level (1-4) |
| `anomaly-threshold` | `u32` | `5` | Anomaly score threshold |
| `exclusions` | `[RuleExclusion]` | `[]` | Rule exclusions |

### BodyInspectionPolicy

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `inspect-request-body` | `bool` | `true` | Send request bodies to the route's agents that subscribe to `request_body`. `#false` keeps them from every agent. Without a `waf` block, request bodies go to those agents too, with the defaults below except `content-types` (every content type is sent) |
| `inspect-response-body` | `bool` | `false` | Not applied ([details](#accepted-but-not-applied)). A response body goes to the agents that subscribe to the `response-body` event |
| `max-inspection-bytes` | `u64` | `1048576` | The most of a request body held for the agents in `request-body-mode "buffer"`, counted as received. A content-coded body may not decode to more than this either (`decompress`), in every mode that decodes it. A body of up to this many bytes is sent whole; a longer one is not sent to any agent, and each agent's filter `failure-mode` decides (see below). With `0`, every body that is not empty is a longer one. The response-body byte count kept for inspection is capped by it too; it is only traced, and never refuses or changes a response |
| `content-types` | `[string]` | *form/json/xml* | Content types to inspect. An entry matches as a case-insensitive prefix, and `type/subtype` also matches `type/<name>+subtype` (see [below](#which-request-bodies-are-inspected-content-types)). A request with a body and no `Content-Type` is inspected whatever the list says, unless `inspect-untyped-bodies` is `#false`. A `Content-Type` with a byte outside visible ASCII is inspected whatever the list says |
| `inspect-untyped-bodies` | `bool` | `true` | Inspect the body of a request that has no `Content-Type` (absent or blank) whatever `content-types` lists. `#false` leaves such a request to the list, where it is matched as the empty string; a `Content-Type` with a byte outside visible ASCII is not "none" and is inspected either way (see [below](#which-request-bodies-are-inspected-content-types)) |
| `decompress` | `bool` | `true` | Decode a request body in a supported `Content-Encoding` (`gzip`, `x-gzip`, `deflate`, `br`) for the agents, within `max-decompression-ratio` and `max-inspection-bytes`. With `#false`, such a body is not decoded and follows the agents' `failure-mode` (see below) |
| `max-decompression-ratio` | `f32` | `100.0` | The largest ratio of decoded to received size |

#### Request bodies longer than `max-inspection-bytes`

In `request-body-mode "buffer"` (the default) an agent is sent the whole
body, or none of it: a fragment is not the body an agent decides on. A body
longer than `max-inspection-bytes` is handled by each agent's filter
`failure-mode`, as a body over the agent's own `max-request-body-bytes` is:

- `closed` (the default, from the route's `policies { failure-mode }` when
  the filter sets none): the request is refused with 413, and no part of the
  body reaches the upstream.
- `open`: the agent is skipped, with a warning and the agent's
  `body_size_skips` metric, and is sent nothing. The request goes on with
  the whole body.

A body of exactly `max-inspection-bytes` is within the limit and is sent
whole, with `is_last` set. With `max-inspection-bytes 0`, every body that is
not empty is over the limit, so each agent's `failure-mode` decides; before,
an agent was sent nothing and the body passed. To keep bodies from the
agents, use `inspect-request-body #false` instead.

This is a change for routes whose bodies are inspected: before, an agent was
sent the first `max-inspection-bytes` bytes of a longer body, the rest was
passed on without being inspected, and the agent's `failure-mode` was never
applied to it. Only bodies that are inspected are affected: those of agents
that subscribe to `request_body` (and whose filter does not set
`inspect-body #false`), unless `inspect-request-body` is `#false`, and only
of a content type that `content-types` allows, or of none (see
[below](#which-request-bodies-are-inspected-content-types)). With a `waf`
block that is `content-types`, by default
`application/x-www-form-urlencoded`, `multipart/form-data`,
`application/json`, `application/xml` and `text/xml`; without a `waf` block
it is every content type. On such a route, by default a body over 1 MiB is
now refused with 413.

A body in a `Content-Encoding` that is decoded for the agents (see
[Content-coded request bodies](#content-coded-request-bodies)) is over the
limit as well when it decodes to more than `max-inspection-bytes`, and is
handled the same way: `closed` refuses the request with 413, and `open`
skips the agent; the upstream is sent the body as the client sent it.
`max-inspection-bytes` stops a body that is not coded in `buffer` mode only.
In the other modes such a body is held to the agent's own
`max-request-body-bytes` (1 MiB by default) alone, which applies in every
mode, so a coded body is held to `max-inspection-bytes` more strictly there
only when the agent's limit is the larger of the two:

- `buffer`: a body is over the limit when it is longer than
  `max-inspection-bytes` as received, or as decoded.
- `hybrid`, for a body held whole within its threshold: a body that is not
  coded is not stopped by `max-inspection-bytes`; a coded one is over the
  limit when it decodes to more than `max-inspection-bytes`.
- `inspect-first`: a body that is not coded is not stopped by
  `max-inspection-bytes` (it is read up to the route's body-size limit); a
  coded one is over the limit when it decodes to more than
  `max-inspection-bytes`.
- `stream`: a coded body is not decoded (see below).

Raising `max-inspection-bytes` lets such a body through.

To accept larger bodies:

- raise `max-inspection-bytes` (and the agent's `max-request-body-bytes`,
  1 MiB by default). Setting it needs a `waf` block, which brings in the
  default `content-types` allowlist: if the route's bodies are of other
  types, list them in `content-types` too. A coded body needs it to be at
  least the size of the body decoded;
- or set the filter's `failure-mode "open"`, to skip the agent for them;
- or give the agent `request-body-mode "stream"` or `"hybrid"`, which send it
  the body in chunks as it arrives instead of holding it to
  `max-inspection-bytes` (the agent's own `max-request-body-bytes` still
  applies). A body in a `Content-Encoding` cannot be decoded in chunks: with
  these modes it is refused with 415 by a `closed` agent (see
  [Content-coded request bodies](#content-coded-request-bodies));
- or keep the bodies from the agents: `inspect-body #false` on the agent's
  filter for one agent, `inspect-request-body #false` for all of them.

#### Content-coded request bodies

Every `Content-Encoding` header of a request is read, each as a
comma-separated list, without regard to case or to the spaces around a
name; `identity` stands for no coding (RFC 9110 section 8.4). A body in one
supported coding is decoded for the agents when `decompress` is on, which
it is by default, and the body is held whole: `gzip` (`x-gzip`), `deflate`
(the zlib format, or a raw deflate stream) and `br` (`brotli` is accepted
for it too).

A body that is not decoded cannot be inspected as sent, so each body
agent's filter `failure-mode` decides, as it does for a body that cannot be
decoded:

- `closed` (the default): the request is refused with 415, and no part of
  the body reaches the upstream.
- `open`: the request goes on, with a warning and the
  `zentinel_decompression_total` count with the reason `not_decoded`. The
  agent is sent none of the body, as for a body over `max-inspection-bytes`,
  and the upstream is sent the body as the client sent it.

A body is not decoded when `decompress` is `#false`, when its coding is not
one of those above (`zstd`, for one), when there are several codings
(`gzip, br`), and when the agent is sent the body in pieces: with
`request-body-mode "stream"` always, even with `decompress #true`, and with
`"hybrid"` for a body longer than the buffer threshold, which is not held
whole.

A body that cannot be decoded because its data is not valid, or because it
goes over `max-decompression-ratio`, is refused with 400 by a `closed` agent;
an `open` one is sent none of it. A body that decodes to more than
`max-inspection-bytes` is not an invalid one: it is over the inspection
limit (413 for `closed`, the agent skipped for `open`; see
[above](#request-bodies-longer-than-max-inspection-bytes)). It is counted as
`size_exceeded` in `zentinel_decompression_total` all the same. The decoding
checks the size and then the ratio after each chunk of output, and stops at
the first limit reached: a body that reaches `max-decompression-ratio`
before it reaches `max-inspection-bytes` fails to decode (400), as before.
With the defaults (`1048576` and `100.0`) that is a body of less than about
10 KB as received that decodes to more than 1 MiB. The upstream is always
sent the body as the client sent it.

What the agents get of a body that is decoded:

- The `Content-Encoding` header stays as the client sent it in the request
  headers event, and the body arrives decoded. An agent that decodes the body
  itself has to expect that; with `decompress #true` set explicitly, that is
  how it was before.
- The decoded size is what is compared with the agent's own
  `max-request-body-bytes`, so a body that is small as received can be over
  it: a `closed` agent refuses the request with 413, and an `open` one is
  skipped. The decoded body is held in memory as well, up to
  `max-inspection-bytes` for a request.
- The `encoding` label of `zentinel_decompression_total` and
  `zentinel_decompression_ratio` is `gzip`, `deflate` or `br`, where it was
  the value of the header as the client wrote it; `other` stands for any
  other coding or several (see [observability](../../common/docs/observability.md)).

This is a change for routes whose bodies are inspected (see above for
which): before, `decompress` was `#false` by default, and the agents were
sent a body in any `Content-Encoding` still compressed, without a warning.
So was a body whose header was a list or was sent as more than one header,
even with `decompress #true`. By default, a `gzip`, `deflate` or `br` body
is now decoded for the agents, and a body that is not decoded is refused
with 415 where an agent fails `closed`; that includes a coded body for an
agent with `request-body-mode "stream"`, even with `decompress #true`. There
is no setting that sends a coded body to the agents compressed. To let such
bodies through without inspecting them, set the filter's
`failure-mode "open"` (with the warning and the metric), or keep the bodies
from the agents with `inspect-body #false` on the filter or
`inspect-request-body #false`. With `decompress #false`, bodies are not
decoded, and each one in a coding follows the `failure-mode` as above,
where before it was sent to the agents compressed. Where decoding fails, an
`open` agent used to be sent the body compressed, and is now sent none of
it. A body that decodes to more than `max-inspection-bytes` was decoded up
to ten times that, with `decompress #true` set, and was refused with 400 past
it; it is now over the inspection limit, as above.

#### Which request bodies are inspected (`content-types`)

An entry of `content-types` is compared without regard to ASCII case
(RFC 9110 section 8.3.1), ignoring leading whitespace and the parameters
(`; charset=utf-8`) of the request's `Content-Type`. It matches as a prefix,
so `application/json` covers `application/json; charset=utf-8`. An entry
`type/subtype` also matches the structured-syntax media types (RFC 6839) of
the same top-level type that end in `+subtype`, `type/<name>+subtype`, with
or without parameters:

| Entry | Also matches |
|-------|--------------|
| `application/json` | `application/vnd.api+json`, `application/problem+json`, `application/merge-patch+json` |
| `application/xml` | `application/soap+xml`, `application/atom+xml` |
| `text/xml` | `text/foo+xml` |

The top-level type has to be the same as the entry's. `text/vnd.api+json` is
not covered by `application/json`, and `image/svg+xml` is not covered by
`application/xml`: such a type is often handled as something else (an image,
for `image/svg+xml`), and one that is to be inspected can be written as an
entry of its own. A list without an `application/json` entry does not cover
the `+json` types either. The rule reads an entry without its own
parameters, and a request with several `Content-Type` headers is inspected
when any one of them matches.

A request that has a body and no `Content-Type` (absent or blank) is
inspected whatever `content-types` lists, as the proxy cannot tell how the
upstream will read that body. With `inspect-untyped-bodies #false` such a
request is matched as the empty string instead, so it is inspected only if
the list has an empty entry (`""`), which matches every request. A request
without a body is matched that way too. Whether a request has a body is
Pingora's decision: for HTTP/1 from the framing (a `Content-Length` other
than 0, or a `Transfer-Encoding`), for HTTP/2 from the stream.

`Content-Type` values are compared as bytes. A byte outside visible ASCII in a
parameter (`application/json; x=\xff`) does not hide the media type, so the
entry and the `+subtype` rule still match it; and a value with such a byte that
matches no entry is inspected anyway, whatever the list and
`inspect-untyped-bodies` say, as the proxy cannot tell which media type the
upstream will read from it.

All of this is the matching of the `waf` block's `content-types`. Without a
`waf` block there is no list and every request body is inspected already, so
nothing changes.

This is a change where a `waf` block's list applies (see above for which
bodies are inspected): before, the default list did not match a body of a
structured-syntax media type such as `application/vnd.api+json`, and a body
without a `Content-Type` was matched as the empty string, so the agents
were sent neither. They are now sent both, by default. The agents see more
requests, with the load and the latency that adds. These bodies are held to
`max-inspection-bytes` and to the agents' `failure-mode`: on a route whose
agent fails `closed`, an upload with no `Content-Type` that is over the
limit, such as one sent with `curl -T`, is now refused with 413 where it
went through before, and a `Content-Encoding` is decoded or refused as
described above. To leave bodies with no `Content-Type` to the list
again, set `inspect-untyped-bodies #false`; listing the types in
`content-types` does not do it. To keep bodies from the agents
altogether, use `inspect-body #false` on the agent's filter
for one agent, or `inspect-request-body #false` for all of them.

---

## Observability

Metrics, logging, and tracing configuration.

### ObservabilityConfig

| Property | Type | Description |
|----------|------|-------------|
| `metrics` | `MetricsConfig` | Metrics configuration |
| `logging` | `LoggingConfig` | Logging configuration |
| `tracing` | `TracingConfig` | Distributed tracing |

### MetricsConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable metrics |
| `address` | `string` | `"127.0.0.1:9090"` | Metrics endpoint address (loopback only; set e.g. `"0.0.0.0:9090"` to scrape from another host) |
| `path` | `string` | `"/metrics"` | Metrics path |
| `high-cardinality` | `bool` | `false` | Include high-cardinality metrics |

### LoggingConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `level` | `string` | `"info"` | Not applied ([details](#accepted-but-not-applied)). The proxy's own log takes its level from the `RUST_LOG` environment variable (`info`, or `debug` with `--verbose`) |
| `format` | `string` | `"json"` | Not applied ([details](#accepted-but-not-applied)). The proxy's own log is written as text |
| `timestamps` | `bool` | `true` | Include timestamps |
| `file` | `string` | - | Log file path |
| `access-log` | `AccessLogConfig` | - | Access log config |
| `error-log` | `ErrorLogConfig` | - | Error log config |
| `audit-log` | `AuditLogConfig` | - | Audit log config |

`level` and `format` here are not the `level` of `error-log` or the `format` of
`access-log`, which are applied.

File logs are opt-in: a log is opened only when its block is present (and not
`enabled #false`). Each file is independent. An access or error log that cannot
be opened is reported at startup, naming the log and its path, and stays off
while the other logs keep working. A configured audit log that cannot be opened
stops startup, so a deployment never runs without the audit trail it asked for.

### AccessLogConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable access logging |
| `file` | `string` | `/var/log/zentinel/access.log` | Log file path |
| `format` | `string` | `"json"` | Log format |
| `sample-rate` | `f64` | `1.0` | Sampling rate (0.0-1.0) |
| `include-trace-id` | `bool` | `true` | Include trace ID (the same setting as `fields { trace-id }`) |
| `fields` | block | every field `#true` | Which fields an entry has |

Each entry records the request's method, path and query string (when the
request has one), as the request arrived:

- `json` format: the query string is the `query` field (absent when the request
  has none). A field set to `#false` in `fields` is left out of the entry. The
  entry has no field for the HTTP version.
- `combined` format: the request line is `METHOD path?query PROTOCOL`, for
  example `GET /search?q=a HTTP/2.0`. `PROTOCOL` is `HTTP/1.0`, `HTTP/1.1` or
  `HTTP/2.0`, the version the request came in on. This format has fixed columns,
  so of `fields` it applies only `query`: with `query #false` the request line
  has no `?query`.

The query string is written as the client sent it, percent-encoding included,
and `query` is on by default. To keep it out of the log:

```kdl
access-log {
    fields {
        query #false
    }
}
```

`fields` takes one `#true` or `#false` setting per field. A field that is not
written stays on.

| Key | `json` entry field |
|-----|--------------------|
| `timestamp` | `timestamp` |
| `trace-id` | `trace_id` |
| `method` | `method` |
| `path` | `path` |
| `query` | `query` |
| `status` | `status` |
| `latency-ms` | `duration_ms` |
| `body-bytes-sent` | `body_bytes_sent` |
| `upstream-addr` | `upstream_addr` |
| `connection-reused` | `connection_reused` |
| `rate-limit-hit` | `rate_limit_hit` |
| `geo-country` | `geo_country` |
| `user-agent` | `user_agent` |
| `referer` | `referer` |
| `client-ip` | `client_ip` |

`fields` is a block, and each key takes its value as an argument (`query #false`).
Anything else is a config error: a `fields` without a block, a value that is not
`#true` or `#false`, a value written as a property, or a key (or `fields`
itself) written twice. A key that is not in the table is reported by
`zentinel test` as ignored. `include-trace-id` and `fields { trace-id }` set the
same field, so when both are written they must agree; different values are a
config error.

### TracingConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `backend` | `TracingBackend` | **required** | Tracing backend |
| `sampling-rate` | `f64` | `0.01` | Sampling rate |
| `service-name` | `string` | `"zentinel"` | Service name |

### TracingBackend

| Type | Properties |
|------|------------|
| `jaeger` | `endpoint` |
| `zipkin` | `endpoint` |
| `otlp` | `endpoint` |

---

## Limits

Global resource limits. These are the single-file names; a directory config also
accepts the older `-bytes` spellings (`max-header-size-bytes`, `max-body-size-bytes`),
which a single-file config ignores.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-header-size` | `u64` | `8192` | Max header size |
| `max-header-count` | `u32` | `100` | Max number of headers |
| `max-body-size` | `u64` | `10485760` | Max request body size |
| `max-connections-per-client` | `u32` | unlimited | Max connections per client (not set: no limit): per IPv4 address, or per IPv6 prefix (see `client-ipv6-prefix-length` in the Server block) |

`max-header-size` and `max-header-count` apply to every request that reaches
the route's filters: proxied routes, `static` routes, and `builtin` routes
that have `filters`.

---

## Cache

HTTP response caching configuration.

### CacheStorageConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable caching |
| `backend` | `string` | `"memory"` | Backend: `memory`, `disk`, `hybrid` |
| `max-size` | `usize` | `104857600` | Max cache size in bytes (100MB); `max-size-bytes` is accepted as well |
| `eviction-limit` | `usize` | - | Eviction trigger threshold in bytes |
| `lock-timeout` | `u64` | `10` | Cache lock timeout in seconds; `lock-timeout-secs` is accepted as well |
| `disk-path` | `string` | - | Disk cache path |
| `disk-shards` | `u32` | `16` | Number of disk shards |
| `disk-max-size` | `usize` | - | Disk tier max size (hybrid only) |

---

## Accepted but not applied

These settings are read from the file and then used by nothing, so they do not
change how the proxy behaves. Loading still succeeds, as it always has. Each
one is logged as a warning when the configuration is loaded, naming the setting
and where it is written; `zentinel lint` reports it; and `zentinel test
--strict` fails on it. The fix is to remove the line. They are reported
whatever value is written, including the default.

| Setting | Where | What happens instead |
|---------|-------|----------------------|
| `max-connections` | `system` | Client connections are not limited |
| `max-concurrent-streams` | `listener` | The listener's HTTP/2 stream limit is not set from it |
| `waf-enabled` | `route` | It does not change how requests are handled. A route's traffic is inspected by the agents its `filters` list |
| `cache { ... }` | inside a route's `policies` | The block is not read, so the route is not cached by it. A route's cache is the `cache` block in the route itself, beside `policies`; moving the block there turns the cache on |
| `vary-headers` | route `cache` | The response's `Vary` header decides which request headers keep entries apart |
| `ignore-query-params` | route `cache` | The query string is part of the cache key as written |
| `ca-cert` | upstream `tls` | The file is not read. The upstream's certificate is verified against the platform's trusted root certificates |
| `max-connections`, `max-idle`, `max-lifetime-secs` (`max-lifetime`) | upstream `connection-pool` | Not applied. `idle-timeout-secs` is |
| `level`, `format` | `observability { logging }` | The proxy's own log takes its level from `RUST_LOG` (`info`, or `debug` with `--verbose`) and is written as text. The `level` of `error-log` and the `format` of `access-log` are applied |
| `inspect-response-body` | `waf { body-inspection }` | A response body goes to the agents that subscribe to the `response-body` event |
| `model-header` | `inference` | It names no header that is read. Model routing reads the model name only from the `x-model` or `x-model-id` request header, and token counting also reads `model` from the request body |
| `routing { strategy, queue-depth-header }` | `inference` | No upstream is chosen by it. An upstream's strategy is its `load-balancing` setting |

A setting leaves this list when the proxy starts to apply it.

Some keys are not read at all, usually because they are written in the wrong
place. In a route's `inference` and `fallback` blocks, and in the blocks inside
them (`rate-limit`, `budget`, `cost-attribution`, `guardrails`, `model-routing`,
`triggers`, `fallback-upstream`), every key or property that the parser does
not read is reported the same way, saying what the block does read. Some that
were written in these docs and examples:

| Written | What is read |
|---------|--------------|
| `upstream "x"` in `fallback` | `fallback-upstream "x" { ... }` |
| `provider="x"` on a `fallback-upstream` | a child node: `provider "x"` |
| `model-mapping` directly in `fallback` | `model-mapping` inside `fallback-upstream` |
| a `fallback` block inside `inference` | `fallback` beside `inference`, in the route |
| `mappings { mapping ... }`, `model-header` in `model-routing` | `model "<pattern>" upstream="<id>"` rules and `default-upstream` |
| `key` in `rate-limit` or `budget` | not a setting of either |
| `daily-limit`, `monthly-limit`, `alert-threshold` in `budget` | `limit` over a `period`, and `alert-thresholds` |
| `models { ... }` in `cost-attribution`, `input-cost-per-1k` | `pricing { model "<pattern>" { input-cost-per-million ...; output-cost-per-million ... } }` |
| `token-estimation` in `inference`, `detect-types` or `types` in `pii-detection` | `estimation-method` in `rate-limit`, `categories` |
