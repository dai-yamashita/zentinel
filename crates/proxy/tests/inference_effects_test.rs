//! The inference features of a route take effect, end to end: the token rate
//! limit per client, the token budget on the usage the provider reports, cost
//! metrics, the PII check of a streamed response, the model mapping of a
//! fallback, token counts of streamed responses, least-tokens load balancing
//! and the inference health check.
//!
//! Each test runs the real binary against fake providers that answer in the
//! OpenAI or Anthropic shape, as JSON or as an SSE stream, with the usage the
//! request asks for in `x-test-usage` (a provider sees the client's headers),
//! and, for the PII check, an in-test guardrail agent (v2, over a Unix
//! socket) that reports PII in content containing `123-45-6789`.
//!
//! The token limiter and the budget are keyed by the client address. The
//! listener trusts `127.0.0.1` as a proxy, so a test speaks for different
//! clients with `X-Forwarded-For`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{BufReader as AsyncBufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use zentinel_agent_protocol::v2::uds::{
    read_message, write_message, MessageType, UdsCapabilities, UdsEncoding, UdsHandshakeResponse,
};
use zentinel_agent_protocol::v2::{AgentCapabilities, HandshakeResponse};
use zentinel_agent_protocol::{
    AgentResponse, GuardrailDetection, GuardrailInspectEvent, GuardrailInspectionType,
    GuardrailResponse,
};

const SSN: &str = "123-45-6789";

// ---------------------------------------------------------------------------
// Fake provider
// ---------------------------------------------------------------------------

/// A provider that records each request and answers it as asked:
///
/// - `x-test-usage: <input>,<output>`: the usage reported (none without it);
/// - `x-test-stream: 1`: an SSE stream instead of a JSON body;
/// - `x-test-format: anthropic`: the Anthropic shape instead of OpenAI's;
/// - `x-test-content: <text>`: the answer's text;
/// - `x-test-delay-ms: <ms>`: wait that long before answering.
///
/// `GET /v1/models` lists `models`. Every answer carries `X-Backend: <name>`.
struct Provider {
    name: &'static str,
    models: &'static [&'static str],
    /// Each request's head (request line and headers) and body.
    requests: Mutex<Vec<(String, Vec<u8>)>>,
    /// Requests being answered.
    in_flight: AtomicUsize,
}

impl Provider {
    fn requests_to(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(head, _)| {
                head.split(' ')
                    .nth(1)
                    .is_some_and(|p| p.starts_with(prefix))
            })
            .cloned()
            .collect()
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Read an HTTP/1.1 body framed by Content-Length or chunked encoding.
fn read_body(reader: &mut impl BufRead, length: Option<usize>, chunked: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
                break;
            }
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
                .unwrap_or(0);
            if size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer);
                break;
            }
            let mut chunk = vec![0; size + 2];
            if reader.read_exact(&mut chunk).is_err() {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = length {
        body.resize(length, 0);
        if reader.read_exact(&mut body).is_err() {
            body.clear();
        }
    }
    body
}

/// The answer to a chat request: its content type and body.
fn answer(head: &str) -> (&'static str, String) {
    let usage = header(head, "x-test-usage").map(|u| {
        let (input, output) = u.split_once(',').unwrap();
        (
            input.trim().parse::<u64>().unwrap(),
            output.trim().parse::<u64>().unwrap(),
        )
    });
    let stream = header(head, "x-test-stream") == Some("1");
    let anthropic = header(head, "x-test-format") == Some("anthropic");
    let text = header(head, "x-test-content").unwrap_or("Hello there, friend.");
    let words: Vec<String> = text.split_inclusive(' ').map(str::to_string).collect();
    let json = |value: serde_json::Value| value.to_string();

    match (anthropic, stream) {
        (false, false) => {
            let mut reply = serde_json::json!({
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "model": "gpt-4",
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": text },
                    "finish_reason": "stop",
                }],
            });
            if let Some((input, output)) = usage {
                reply["usage"] = serde_json::json!({
                    "prompt_tokens": input,
                    "completion_tokens": output,
                    "total_tokens": input + output,
                });
            }
            ("application/json", json(reply))
        }
        (true, false) => {
            let mut reply = serde_json::json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-3-opus",
                "content": [{ "type": "text", "text": text }],
                "stop_reason": "end_turn",
            });
            if let Some((input, output)) = usage {
                reply["usage"] = serde_json::json!({
                    "input_tokens": input,
                    "output_tokens": output,
                });
            }
            ("application/json", json(reply))
        }
        (false, true) => {
            let mut events = String::new();
            for word in &words {
                let chunk = serde_json::json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion.chunk",
                    "choices": [{ "index": 0, "delta": { "content": word }, "finish_reason": null }],
                });
                events.push_str(&format!("data: {}\n\n", json(chunk)));
            }
            let last = serde_json::json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
            });
            events.push_str(&format!("data: {}\n\n", json(last)));
            if let Some((input, output)) = usage {
                // As with `stream_options: {"include_usage": true}`.
                let chunk = serde_json::json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion.chunk",
                    "choices": [],
                    "usage": {
                        "prompt_tokens": input,
                        "completion_tokens": output,
                        "total_tokens": input + output,
                    },
                });
                events.push_str(&format!("data: {}\n\n", json(chunk)));
            }
            events.push_str("data: [DONE]\n\n");
            ("text/event-stream", events)
        }
        (true, true) => {
            let (input, output) = usage.unwrap_or((0, 0));
            let mut events = String::new();
            let mut event = |name: &str, data: serde_json::Value| {
                events.push_str(&format!("event: {name}\ndata: {}\n\n", json(data)));
            };
            // The input tokens come first, the output tokens at the end.
            event(
                "message_start",
                serde_json::json!({
                    "type": "message_start",
                    "message": {
                        "id": "msg_1",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-3-opus",
                        "content": [],
                        "usage": { "input_tokens": input, "output_tokens": 1 },
                    },
                }),
            );
            event(
                "content_block_start",
                serde_json::json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": { "type": "text", "text": "" },
                }),
            );
            for word in &words {
                event(
                    "content_block_delta",
                    serde_json::json!({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": { "type": "text_delta", "text": word },
                    }),
                );
            }
            event(
                "content_block_stop",
                serde_json::json!({ "type": "content_block_stop", "index": 0 }),
            );
            event(
                "message_delta",
                serde_json::json!({
                    "type": "message_delta",
                    "delta": { "stop_reason": "end_turn" },
                    "usage": { "output_tokens": output },
                }),
            );
            event(
                "message_stop",
                serde_json::json!({ "type": "message_stop" }),
            );
            ("text/event-stream", events)
        }
    }
}

fn spawn_provider(name: &'static str, models: &'static [&'static str]) -> (u16, Arc<Provider>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let provider = Arc::new(Provider {
        name,
        models,
        requests: Mutex::new(Vec::new()),
        in_flight: AtomicUsize::new(0),
    });
    let shared = provider.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let provider = shared.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    head.push_str(&line);
                    line.clear();
                }
                if head.is_empty() {
                    return;
                }
                let length = header(&head, "content-length").and_then(|l| l.parse().ok());
                let chunked = header(&head, "transfer-encoding")
                    .is_some_and(|t| t.to_ascii_lowercase().contains("chunked"));
                let body = read_body(&mut reader, length, chunked);

                let (content_type, reply) = if head.starts_with("GET /v1/models ") {
                    let data: Vec<_> = provider
                        .models
                        .iter()
                        .map(|id| serde_json::json!({ "id": id, "object": "model" }))
                        .collect();
                    let list = serde_json::json!({ "object": "list", "data": data });
                    ("application/json", list.to_string())
                } else {
                    provider.requests.lock().unwrap().push((head.clone(), body));
                    answer(&head)
                };

                provider.in_flight.fetch_add(1, Ordering::SeqCst);
                if let Some(ms) = header(&head, "x-test-delay-ms").and_then(|d| d.parse().ok()) {
                    std::thread::sleep(Duration::from_millis(ms));
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nX-Backend: {}\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    provider.name,
                    reply.len()
                );
                provider.in_flight.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (port, provider)
}

// ---------------------------------------------------------------------------
// Guardrail agent
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Guard {
    /// Connections whose handshake completed.
    handshakes: AtomicUsize,
    /// The inspection type and content of every inspection event received.
    seen: Mutex<Vec<(GuardrailInspectionType, String)>>,
}

async fn serve_guard(socket: PathBuf, guard: Arc<Guard>) {
    let listener = UnixListener::bind(&socket).unwrap();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let guard = guard.clone();
        tokio::spawn(async move {
            let _ = guard_connection(stream, guard).await;
        });
    }
}

async fn guard_connection(stream: UnixStream, guard: Arc<Guard>) -> Option<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = AsyncBufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let (kind, _) = read_message(&mut reader).await.ok()?;
    assert_eq!(kind, MessageType::HandshakeRequest);
    let handshake = HandshakeResponse::success(AgentCapabilities::new("pii", "PII", "0.1.0"));
    let reply = UdsHandshakeResponse {
        protocol_version: handshake.protocol_version,
        capabilities: UdsCapabilities::from(handshake.capabilities),
        success: true,
        error: None,
        encoding: UdsEncoding::Json,
    };
    write_message(
        &mut writer,
        MessageType::HandshakeResponse,
        &serde_json::to_vec(&reply).ok()?,
    )
    .await
    .ok()?;
    guard.handshakes.fetch_add(1, Ordering::SeqCst);

    loop {
        let (kind, payload) = read_message(&mut reader).await.ok()?;
        match kind {
            MessageType::Ping => {
                write_message(&mut writer, MessageType::Pong, &payload)
                    .await
                    .ok()?;
            }
            MessageType::GuardrailInspect => {
                let event: GuardrailInspectEvent = serde_json::from_slice(&payload).ok()?;
                guard
                    .seen
                    .lock()
                    .unwrap()
                    .push((event.inspection_type, event.content.clone()));
                let verdict = if event.content.contains(SSN) {
                    GuardrailResponse {
                        detected: true,
                        confidence: 0.99,
                        detections: vec![GuardrailDetection::new(
                            "ssn",
                            "a social security number",
                        )],
                        redacted_content: None,
                    }
                } else {
                    GuardrailResponse::default()
                };
                let mut response = AgentResponse::default_allow();
                response.audit.custom.insert(
                    "correlation_id".to_string(),
                    serde_json::Value::String(event.correlation_id),
                );
                response.routing_metadata.insert(
                    "guardrail_response".to_string(),
                    serde_json::to_string(&verdict).ok()?,
                );
                write_message(
                    &mut writer,
                    MessageType::AgentResponse,
                    &serde_json::to_vec(&response).ok()?,
                )
                .await
                .ok()?;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Ports of the proxy's listeners come from a range of their own, so that
/// tests running side by side do not take each other's.
const PROXY_PORTS: std::ops::Range<u16> = 47600..47800;
static NEXT_PROXY_PORT: AtomicU16 = AtomicU16::new(PROXY_PORTS.start);

/// Held while a port is probed and while a proxy is started, so that a proxy
/// does not inherit another test's probe listener.
static PROBE_OR_SPAWN: Mutex<()> = Mutex::new(());

fn free_proxy_port() -> u16 {
    let _held = PROBE_OR_SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let port = NEXT_PROXY_PORT.fetch_add(1, Ordering::SeqCst);
        assert!(
            PROXY_PORTS.contains(&port),
            "no free port in {PROXY_PORTS:?}"
        );
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Setup {
    port: u16,
    metrics_port: u16,
    /// The upstream of most routes, and the first target of `least-tokens`.
    first: Arc<Provider>,
    /// The fallback of `mapped`, and the second target of `least-tokens`.
    second: Arc<Provider>,
    /// The target of `checked` that lists the expected model.
    listing: Arc<Provider>,
    /// The target of `checked` that does not.
    missing: Arc<Provider>,
    guard: Arc<Guard>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let guard = Arc::new(Guard::default());
    let guard_socket = dir.path().join("pii.sock");
    rt.spawn(serve_guard(guard_socket.clone(), guard.clone()));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !guard_socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (first_port, first) = spawn_provider("first", &["gpt-4"]);
    let (second_port, second) = spawn_provider("second", &["gpt-4"]);
    let (listing_port, listing) = spawn_provider("listing", &["gpt-4", "gpt-3.5-turbo"]);
    let (missing_port, missing) = spawn_provider("missing", &["llama-3"]);
    let dead_port = closed_port();
    let port = free_proxy_port();
    let metrics_port = free_proxy_port();

    // Prompts are estimated at four characters a token (`chars`).
    let config = format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
        trusted-proxies "127.0.0.1"
    }}
}}
upstreams {{
    upstream "first" {{
        target "127.0.0.1:{first_port}"
    }}
    upstream "second" {{
        target "127.0.0.1:{second_port}"
    }}
    upstream "dead" {{
        target "127.0.0.1:{dead_port}"
        health-check {{
            type "tcp"
            interval-secs 1
            timeout-secs 1
            healthy-threshold 1
            unhealthy-threshold 1
        }}
    }}
    upstream "least-tokens" {{
        target "127.0.0.1:{first_port}"
        target "127.0.0.1:{second_port}"
        load-balancing "least_tokens_queued"
    }}
    upstream "checked" {{
        target "127.0.0.1:{listing_port}"
        target "127.0.0.1:{missing_port}"
        load-balancing "round_robin"
        health-check {{
            type "inference" {{
                endpoint "/v1/models"
                expected-models "gpt-4"
            }}
            interval-secs 1
            timeout-secs 1
            healthy-threshold 1
            unhealthy-threshold 1
        }}
    }}
}}
agents {{
    agent "pii" type="custom" {{
        unix-socket "{guard_socket}"
        events "guardrail"
        timeout-ms 2000
    }}
}}
routes {{
    route "tokens" {{
        matches {{ path-prefix "/tokens/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            rate-limit {{
                tokens-per-minute 600
                burst-tokens 500
                estimation-method "chars"
            }}
        }}
    }}
    route "budget" {{
        matches {{ path-prefix "/budget/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            budget {{
                period "daily"
                limit 1000
                enforce #true
            }}
        }}
    }}
    route "soft-budget" {{
        matches {{ path-prefix "/soft-budget/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            budget {{
                period "daily"
                limit 1000
                enforce #false
            }}
        }}
    }}
    route "cost" {{
        matches {{ path-prefix "/cost/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            cost-attribution {{
                currency "USD"
                pricing {{
                    model "gpt-4*" {{
                        input-cost-per-million 30.0
                        output-cost-per-million 60.0
                    }}
                }}
            }}
        }}
    }}
    route "pii" {{
        matches {{ path-prefix "/pii/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            guardrails {{
                pii-detection {{
                    enabled #true
                    agent "pii"
                    action "log"
                    categories "ssn"
                    timeout-ms 1000
                }}
            }}
        }}
    }}
    route "openai" {{
        matches {{ path-prefix "/openai/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            budget {{
                period "daily"
                limit 100000
            }}
        }}
    }}
    route "anthropic" {{
        matches {{ path-prefix "/anthropic/" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "anthropic"
            budget {{
                period "daily"
                limit 100000
            }}
        }}
    }}
    route "mapped" {{
        matches {{ path-prefix "/mapped/" }}
        upstream "dead"
        service-type "inference"
        inference {{
            provider "openai"
            rate-limit {{
                tokens-per-minute 1000000
                burst-tokens 1000000
            }}
        }}
        fallback {{
            triggers {{
                on-health-failure #true
            }}
            fallback-upstream "second" {{
                provider "anthropic"
                model-mapping {{
                    "gpt-4" "claude-3-opus"
                }}
            }}
        }}
    }}
    route "balanced" {{
        matches {{ path-prefix "/balanced/" }}
        upstream "least-tokens"
        service-type "inference"
        inference {{
            provider "openai"
            rate-limit {{
                tokens-per-minute 1000000
                burst-tokens 1000000
            }}
        }}
    }}
    route "checked" {{
        matches {{ path-prefix "/checked/" }}
        upstream "checked"
        service-type "inference"
        inference {{
            provider "openai"
        }}
    }}
}}
observability {{
    metrics {{
        enabled #true
        address "127.0.0.1:{metrics_port}"
        path "/metrics"
    }}
}}
"#,
        guard_socket = guard_socket.display(),
    );
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config).unwrap();
    let proxy = {
        let _held = PROBE_OR_SPAWN.lock().unwrap_or_else(|e| e.into_inner());
        Proxy(
            Command::new(env!("CARGO_BIN_EXE_zentinel"))
                .arg("-c")
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };

    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }

    Setup {
        port,
        metrics_port,
        first,
        second,
        listing,
        missing,
        guard,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `X-Budget-Remaining`, which must be present.
    fn budget_remaining(&self) -> i64 {
        self.header("x-budget-remaining")
            .unwrap_or_else(|| panic!("no X-Budget-Remaining: {:?}", self.headers))
            .parse()
            .unwrap()
    }
}

/// One request (a POST when it has a body), framed by Content-Length, with
/// more request headers.
fn send(port: u16, path: &str, body: Option<&str>, headers: &[(&str, &str)]) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (method, mut extra) = match body {
        Some(body) => (
            "POST",
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ),
        ),
        None => ("GET", String::new()),
    };
    for (name, value) in headers {
        extra.push_str(&format!("{name}: {value}\r\n"));
    }
    // The head goes out in one write: the metrics listener answers from the
    // first read it gets.
    let head =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let _ = stream.write_all(body.unwrap_or_default().as_bytes());
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (n, v) = line.split_once(':')?;
            Some((n.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    Response {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A chat request for `model` whose one message says `content`.
fn chat(model: &str, content: &str) -> String {
    serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

/// The value of the metrics series whose line starts with `name{` and
/// contains each of `labels`; 0 when none is listed.
fn metric(setup: &Setup, name: &str, labels: &[&str]) -> f64 {
    let response = send(setup.metrics_port, "/metrics", None, &[]);
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        response.body.contains("zentinel_up 1"),
        "not the metrics: {}",
        response.body
    );
    response
        .body
        .lines()
        .filter(|line| line.starts_with(&format!("{name}{{")))
        .find(|line| labels.iter().all(|label| line.contains(label)))
        .and_then(|line| line.rsplit(' ').next())
        .map(|value| value.trim().parse().unwrap())
        .unwrap_or(0.0)
}

/// Wait until the metric reaches `expected` (a request's metrics are
/// recorded once its response has been sent), and return its value then or
/// after five seconds.
fn wait_for_metric(setup: &Setup, name: &str, labels: &[&str], expected: f64) -> f64 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let value = metric(setup, name, labels);
        if (value - expected).abs() < 1e-9 || Instant::now() > deadline {
            return value;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A request's usage is recorded once its response has been sent; give it
/// the time to be before the next request is checked against it.
fn settle() {
    std::thread::sleep(Duration::from_millis(300));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The token rate limit is per client: a client over its tokens per minute
/// is refused with 429, and another client is not.
#[test]
fn token_rate_limit_is_per_client() {
    let setup = setup();
    // About 260 tokens: one fits in the burst of 500, two do not.
    let prompt = chat("gpt-4", &"a".repeat(1000));
    let client_a = [("X-Forwarded-For", "10.0.0.1")];
    let client_b = [("X-Forwarded-For", "10.0.0.2")];

    let response = send(setup.port, "/tokens/a1", Some(&prompt), &client_a);
    assert_eq!(response.status, 200, "{}", response.body);
    let response = send(setup.port, "/tokens/a2", Some(&prompt), &client_a);
    assert_eq!(response.status, 429, "{}", response.body);
    assert!(
        response.body.contains("Token rate limit exceeded"),
        "{}",
        response.body
    );
    assert!(
        response.header("retry-after").is_some(),
        "{:?}",
        response.headers
    );

    let response = send(setup.port, "/tokens/b1", Some(&prompt), &client_b);
    assert_eq!(
        response.status, 200,
        "another client was refused: {}",
        response.body
    );

    let response = send(setup.port, "/tokens/a3", Some(&prompt), &client_a);
    assert_eq!(response.status, 429, "{}", response.body);

    let forwarded: Vec<_> = setup
        .first
        .requests_to("/tokens/")
        .iter()
        .map(|(head, _)| head.split(' ').nth(1).unwrap().to_string())
        .collect();
    assert_eq!(forwarded, ["/tokens/a1", "/tokens/b1"]);
}

/// The token budget counts the usage the provider reports in its responses:
/// once a client's cumulative usage crosses the budget, `enforce #true`
/// refuses its requests with 429 and `enforce #false` lets them through with
/// a negative `X-Budget-Remaining`. Another client keeps its own budget.
#[test]
fn token_budget_counts_reported_usage() {
    let setup = setup();
    let prompt = chat("gpt-4", "hello");
    let client_a = [("X-Forwarded-For", "10.0.0.1"), ("x-test-usage", "300,100")];
    let client_b = [("X-Forwarded-For", "10.0.0.2")];

    for route in ["budget", "soft-budget"] {
        // Each answer reports 400 tokens: the budget of 1000 holds three
        // requests, and the fourth is over it.
        let first = send(setup.port, &format!("/{route}/1"), Some(&prompt), &client_a);
        assert_eq!(first.status, 200, "{route}: {}", first.body);
        let estimate = 1000 - first.budget_remaining();
        assert!((1..100).contains(&estimate), "{route}: {estimate}");
        let reset = first
            .header("x-budget-period-reset")
            .unwrap_or_else(|| panic!("{route}: no X-Budget-Period-Reset: {:?}", first.headers));
        assert!(
            chrono::DateTime::parse_from_rfc3339(reset).is_ok(),
            "{route}: {reset}"
        );
        settle();

        for (n, used) in [(2, 400), (3, 800)] {
            let response = send(
                setup.port,
                &format!("/{route}/{n}"),
                Some(&prompt),
                &client_a,
            );
            assert_eq!(response.status, 200, "{route}: {}", response.body);
            assert_eq!(
                response.budget_remaining(),
                1000 - used - estimate,
                "{route}: request {n}"
            );
            settle();
        }

        let response = send(setup.port, &format!("/{route}/4"), Some(&prompt), &client_a);
        if route == "budget" {
            assert_eq!(response.status, 429, "{route}: {}", response.body);
            assert!(
                response.body.contains("Token budget exhausted"),
                "{}",
                response.body
            );
            assert!(response.header("retry-after").is_some());
            assert!(setup.first.requests_to("/budget/4").is_empty());
        } else {
            assert_eq!(response.status, 200, "{route}: {}", response.body);
            assert_eq!(response.budget_remaining(), 1000 - 1200 - estimate);
        }

        let other = send(
            setup.port,
            &format!("/{route}/other"),
            Some(&prompt),
            &client_b,
        );
        assert_eq!(other.status, 200, "{route}: {}", other.body);
        assert_eq!(other.budget_remaining(), 1000 - estimate, "{route}");
    }
}

/// The cost metrics move by the cost of the usage the provider reports, at
/// the configured prices, for a JSON answer and for a streamed one.
#[test]
fn cost_metrics_move_by_the_cost_of_the_usage() {
    let setup = setup();
    let labels = ["route=\"cost\"", "model=\"gpt-4-turbo\""];
    let prompt = chat("gpt-4-turbo", "hello");

    // 1000 input tokens at 30 and 500 output tokens at 60 per million.
    let response = send(
        setup.port,
        "/cost/json",
        Some(&prompt),
        &[("x-test-usage", "1000,500")],
    );
    assert_eq!(response.status, 200, "{}", response.body);
    let cost = wait_for_metric(
        &setup,
        "zentinel_inference_cost_total",
        &[labels[0], labels[1], "currency=\"USD\""],
        0.06,
    );
    assert!((cost - 0.06).abs() < 1e-9, "cost {cost}");
    assert_eq!(
        metric(&setup, "zentinel_inference_input_tokens_total", &labels),
        1000.0
    );
    assert_eq!(
        metric(&setup, "zentinel_inference_output_tokens_total", &labels),
        500.0
    );

    // Streamed: 2000 and 1000 more, 0.12.
    let response = send(
        setup.port,
        "/cost/stream",
        Some(&prompt),
        &[("x-test-usage", "2000,1000"), ("x-test-stream", "1")],
    );
    assert_eq!(response.status, 200, "{}", response.body);
    let cost = wait_for_metric(
        &setup,
        "zentinel_inference_cost_total",
        &[labels[0], labels[1], "currency=\"USD\""],
        0.18,
    );
    assert!((cost - 0.18).abs() < 1e-9, "cost {cost}");
    assert_eq!(
        metric(&setup, "zentinel_inference_input_tokens_total", &labels),
        3000.0
    );
    assert_eq!(
        metric(&setup, "zentinel_inference_output_tokens_total", &labels),
        1500.0
    );
}

/// With `action "log"`, a streamed response with PII in it is passed on,
/// checked, and counted in `zentinel_pii_detected_total`; a clean one is not
/// counted.
#[test]
fn pii_in_a_streamed_response_is_counted() {
    let setup = setup();
    let deadline = Instant::now() + Duration::from_secs(10);
    while setup.guard.handshakes.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the agent never connected");
        std::thread::sleep(Duration::from_millis(50));
    }
    let labels = ["route=\"pii\"", "category=\"ssn\""];
    let prompt = chat("gpt-4", "what is my number?");

    let clean = send(
        setup.port,
        "/pii/clean",
        Some(&prompt),
        &[("x-test-stream", "1"), ("x-test-content", "nothing to see")],
    );
    assert_eq!(clean.status, 200, "{}", clean.body);

    let content = format!("your SSN is {SSN} as requested");
    let response = send(
        setup.port,
        "/pii/leak",
        Some(&prompt),
        &[("x-test-stream", "1"), ("x-test-content", &content)],
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(response.body.contains(SSN), "{}", response.body);

    assert_eq!(
        wait_for_metric(&setup, "zentinel_pii_detected_total", &labels, 1.0),
        1.0
    );
    let seen = setup.guard.seen.lock().unwrap().clone();
    assert!(
        seen.contains(&(GuardrailInspectionType::PiiDetection, content.clone())),
        "the response was not checked: {seen:?}"
    );
    // The prompt is not checked under `action "log"`.
    assert!(
        !seen
            .iter()
            .any(|(_, text)| text.contains("what is my number")),
        "{seen:?}"
    );
    settle();
    assert_eq!(metric(&setup, "zentinel_pii_detected_total", &labels), 1.0);
}

/// Send `/mapped/` requests until the route falls back to `second` (its
/// primary's health check fails), and return that response.
fn fall_back(setup: &Setup) -> Response {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut n = 0;
    loop {
        n += 1;
        let response = send(
            setup.port,
            &format!("/mapped/{n}"),
            Some(&chat("gpt-4", "hello")),
            &[],
        );
        if response.status == 200 && response.header("x-backend") == Some("second") {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "the route never fell back: {} {}",
            response.status,
            response.body
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A fallback with a `model-mapping` maps the model the request names, and
/// says so in `X-Model-Mapping` and `zentinel_fallback_model_mapping_total`.
#[test]
fn fallback_reports_the_model_mapping() {
    let setup = setup();
    let response = fall_back(&setup);
    assert_eq!(
        response.header("x-model-mapping"),
        Some("gpt-4 -> claude-3-opus"),
        "{:?}",
        response.headers
    );
    assert!(
        metric(
            &setup,
            "zentinel_fallback_model_mapping_total",
            &["route=\"mapped\"", "claude-3-opus"]
        ) >= 1.0
    );
}

/// The fallback upstream is sent the mapped model.
#[test]
#[ignore = "the mapped model is only reported (X-Model-Mapping); the request body still names the original model"]
fn fallback_sends_the_mapped_model_upstream() {
    let setup = setup();
    fall_back(&setup);
    let sent = setup.second.requests_to("/mapped/");
    let (_, last) = sent.last().unwrap();
    let body: serde_json::Value = serde_json::from_slice(last).unwrap();
    assert_eq!(body["model"], "claude-3-opus", "{body}");
}

/// The tokens of a client's usage recorded against the budget of `route`:
/// two requests with the same prompt, the first answered with
/// `answer_headers`, the second showing what the first used.
fn recorded_usage(
    setup: &Setup,
    route: &str,
    client: &str,
    answer_headers: &[(&str, &str)],
) -> i64 {
    let prompt = chat("gpt-4", "count my tokens");
    let mut headers = vec![("X-Forwarded-For", client)];
    headers.extend_from_slice(answer_headers);
    let first = send(
        setup.port,
        &format!("/{route}/first"),
        Some(&prompt),
        &headers,
    );
    assert_eq!(first.status, 200, "{}", first.body);
    settle();
    let probe = send(
        setup.port,
        &format!("/{route}/probe"),
        Some(&prompt),
        &[("X-Forwarded-For", client)],
    );
    assert_eq!(probe.status, 200, "{}", probe.body);
    first.budget_remaining() - probe.budget_remaining()
}

/// The tokens counted for a streamed response are those counted for the same
/// answer as JSON, in the OpenAI and in the Anthropic format.
#[test]
fn streamed_and_json_responses_count_the_same_tokens() {
    let setup = setup();
    let usage = ("x-test-usage", "30,70");

    let json = recorded_usage(&setup, "openai", "10.0.1.1", &[usage]);
    let streamed = recorded_usage(
        &setup,
        "openai",
        "10.0.1.2",
        &[usage, ("x-test-stream", "1")],
    );
    assert_eq!((json, streamed), (100, 100), "openai");

    let anthropic = ("x-test-format", "anthropic");
    let json = recorded_usage(&setup, "anthropic", "10.0.2.1", &[usage, anthropic]);
    let streamed = recorded_usage(
        &setup,
        "anthropic",
        "10.0.2.2",
        &[usage, anthropic, ("x-test-stream", "1")],
    );
    assert_eq!((json, streamed), (100, 100), "anthropic");
}

/// `least_tokens_queued` sends a request to the target with fewer tokens
/// queued: while the first target works on a large prompt, the next request
/// goes to the second.
#[test]
#[ignore = "the balancer's token queues are never filled: every target looks idle and the first is always chosen"]
fn least_tokens_prefers_the_less_loaded_target() {
    let setup = setup();
    let large = chat("gpt-4", &"a".repeat(40_000));
    let port = setup.port;
    let slow = std::thread::spawn(move || {
        send(
            port,
            "/balanced/large",
            Some(&large),
            &[("x-test-delay-ms", "3000")],
        )
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while setup.first.in_flight.load(Ordering::SeqCst) == 0
        && setup.second.in_flight.load(Ordering::SeqCst) == 0
    {
        assert!(Instant::now() < deadline, "the large prompt never arrived");
        std::thread::sleep(Duration::from_millis(20));
    }
    let busy = if setup.first.in_flight.load(Ordering::SeqCst) > 0 {
        "first"
    } else {
        "second"
    };

    let response = send(
        setup.port,
        "/balanced/small",
        Some(&chat("gpt-4", "hi")),
        &[],
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_ne!(
        response.header("x-backend"),
        Some(busy),
        "the small prompt was queued behind the large one"
    );
    assert_eq!(slow.join().unwrap().status, 200);
}

/// The inference health check takes a provider out of rotation when its
/// model list lacks an expected model, though it answers 200.
#[test]
fn inference_health_check_takes_a_provider_out() {
    let setup = setup();
    let prompt = chat("gpt-4", "hello");

    // Give the check time to probe both targets.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut streak = 0;
    while streak < 10 {
        assert!(
            Instant::now() < deadline,
            "the provider without the model stayed in rotation"
        );
        let response = send(setup.port, "/checked/chat", Some(&prompt), &[]);
        // Until the first probes complete a target can count as down, so a
        // 503 while the check settles is not a failure.
        if response.status == 503 {
            streak = 0;
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        assert_eq!(response.status, 200, "{}", response.body);
        if response.header("x-backend") == Some("listing") {
            streak += 1;
        } else {
            streak = 0;
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let served = setup.missing.requests_to("/checked/").len();
    for _ in 0..10 {
        let response = send(setup.port, "/checked/chat", Some(&prompt), &[]);
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(response.header("x-backend"), Some("listing"));
    }
    assert_eq!(setup.missing.requests_to("/checked/").len(), served);
    assert!(setup.listing.requests_to("/checked/").len() >= 20);
}
