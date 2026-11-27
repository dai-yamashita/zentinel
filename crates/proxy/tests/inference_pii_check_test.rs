//! The PII check of an inference route (`guardrails { pii-detection }`) with
//! `action "block"` runs on the request body, before an upstream is chosen.
//!
//! `action "block"` used to do nothing on the request: the PII check only ran
//! after the response was sent, on streamed responses only, and only logged
//! and counted what it found. A prompt with PII in it reached the upstream.
//! This runs the real binary against a backend that records every request,
//! with an in-test guardrail agent (v2, over a Unix socket) that reports PII
//! in content containing `123-45-6789`.

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

const MARKER: &str = "UPSTREAM-MARKER";
const SSN: &str = "123-45-6789";
const BLOCK_MESSAGE: &str = "no personal data, please";

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Each request's head (request line and headers) and body.
type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn spawn_backend(listener: TcpListener, requests: Requests) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let requests = requests.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut length = 0;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    head.push_str(&line);
                    line.clear();
                }
                if head.is_empty() {
                    return;
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                requests.lock().unwrap().push((head, body));
                let reply = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            });
        }
    });
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

/// The agent's answer for a piece of content: `None` is no answer at all.
fn verdict(content: &str) -> Option<Result<GuardrailResponse, &'static str>> {
    if content.contains("hang-phrase") {
        None
    } else if content.contains("agent-error-phrase") {
        Some(Err("this is not a guardrail response"))
    } else if content.contains(SSN) {
        Some(Ok(GuardrailResponse {
            detected: true,
            confidence: 0.99,
            detections: vec![GuardrailDetection::new("ssn", "a social security number")],
            redacted_content: None,
        }))
    } else {
        Some(Ok(GuardrailResponse::default()))
    }
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
                let Some(answer) = verdict(&event.content) else {
                    continue;
                };
                let mut response = AgentResponse::default_allow();
                response.audit.custom.insert(
                    "correlation_id".to_string(),
                    serde_json::Value::String(event.correlation_id),
                );
                let raw = match answer {
                    Ok(guardrail) => serde_json::to_string(&guardrail).ok()?,
                    Err(garbage) => garbage.to_string(),
                };
                response
                    .routing_metadata
                    .insert("guardrail_response".to_string(), raw);
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

/// A route's PII guardrail.
fn pii_check(action: &str, failure_mode: &str, extra: &str) -> String {
    format!(
        r#"
        inference {{
            provider "generic"
            guardrails {{
                pii-detection {{
                    enabled #true
                    agent "pii"
                    action "{action}"
                    categories "ssn"
                    timeout-ms 500
                    failure-mode "{failure_mode}"
                    {extra}
                }}
            }}
        }}"#
    )
}

/// Ports of the proxy's listeners come from a range of their own, so that
/// tests running side by side do not take each other's.
const PROXY_PORTS: std::ops::Range<u16> = 47500..47600;
static NEXT_PROXY_PORT: AtomicU16 = AtomicU16::new(PROXY_PORTS.start);

/// Held while a port is probed and while a proxy is started, so that a
/// proxy does not inherit another test's probe listener.
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

struct Setup {
    port: u16,
    metrics_port: u16,
    requests: Requests,
    guard: Arc<Guard>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

impl Setup {
    fn upstream_requests(&self) -> Vec<(String, Vec<u8>)> {
        self.requests.lock().unwrap().clone()
    }
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

    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let requests = Requests::default();
    spawn_backend(backend_listener, requests.clone());
    let port = free_proxy_port();
    let metrics_port = free_proxy_port();

    let closed = pii_check(
        "block",
        "closed",
        &format!(r#"block-status 451; block-message "{BLOCK_MESSAGE}""#),
    );
    let open = pii_check("block", "open", "");
    let log = pii_check("log", "closed", "");
    let config = format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend_port}"
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
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        service-type "inference"
        {closed}
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        service-type "inference"
        {open}
    }}
    route "log" {{
        matches {{ path-prefix "/log" }}
        upstream "backend"
        service-type "inference"
        {log}
    }}
}}
observability {{
    metrics {{
        enabled #true
        address "127.0.0.1:{metrics_port}"
        path "/metrics"
    }}
    logging {{
        error-log {{
            enabled #true
            file "{error_log}"
        }}
    }}
}}
"#,
        error_log = dir.path().join("error.log").display(),
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
    let deadline = Instant::now() + Duration::from_secs(10);
    while guard.handshakes.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the guardrail agent never connected"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // A clean prompt passes the check once the agent answers.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, _) = send(port, "/closed/warmup", Some(chat("warm up").as_bytes()));
        if status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent never answered: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    guard.seen.lock().unwrap().clear();
    requests.lock().unwrap().clear();

    Setup {
        port,
        metrics_port,
        requests,
        guard,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A chat request whose one message says `content`.
fn chat(content: &str) -> String {
    serde_json::json!({
        "model": "m1",
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

/// One request (a POST when it has a body), framed by Content-Length.
fn send(port: u16, path: &str, body: Option<&[u8]>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (method, length) = match body {
        Some(body) => ("POST", format!("Content-Length: {}\r\n", body.len())),
        None => ("GET", String::new()),
    };
    // The head goes out in one write: the metrics listener answers from the
    // first read it gets.
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{length}\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.unwrap_or_default()).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

fn post(setup: &Setup, path: &str, body: &str) -> (u16, String) {
    send(setup.port, path, Some(body.as_bytes()))
}

/// The value of the metrics series whose line starts with `name{` and
/// contains each of `labels`; 0 when none is listed.
fn metric(setup: &Setup, name: &str, labels: &[&str]) -> u64 {
    let (status, body) = send(setup.metrics_port, "/metrics", None);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("zentinel_up 1"), "not the metrics: {body}");
    body.lines()
        .filter(|line| line.starts_with(&format!("{name}{{")))
        .find(|line| labels.iter().all(|label| line.contains(label)))
        .and_then(|line| line.rsplit(' ').next())
        .map(|count| count.trim().parse().unwrap())
        .unwrap_or(0)
}

/// The `error` and `message` of a refusal's JSON body.
fn refusal(body: &str) -> (String, String) {
    let json: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"));
    let field = |name: &str| json[name].as_str().unwrap_or_default().to_string();
    (field("error"), field("message"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A prompt with PII in it is refused under `action "block"`, with the
/// guardrail's `block-status` and `block-message` (400 and a default message
/// when not set), and the upstream is sent nothing.
#[test]
fn a_prompt_with_pii_is_refused_before_the_upstream() {
    let setup = setup();
    let prompt = chat(&format!("my SSN is {SSN}"));

    let (status, body) = post(&setup, "/closed/chat", &prompt);
    assert_eq!(status, 451, "{body}");
    assert_eq!(
        refusal(&body),
        ("pii_blocked".to_string(), BLOCK_MESSAGE.to_string())
    );

    let (status, body) = post(&setup, "/open/chat", &prompt);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        refusal(&body),
        (
            "pii_blocked".to_string(),
            "Request blocked: personal data detected".to_string()
        )
    );

    assert!(
        setup.upstream_requests().is_empty(),
        "the upstream was sent a prompt with PII in it"
    );
    let seen = setup.guard.seen.lock().unwrap().clone();
    let expected = (
        GuardrailInspectionType::PiiDetection,
        format!("my SSN is {SSN}"),
    );
    assert_eq!(seen, [expected.clone(), expected], "the text was checked");

    assert_eq!(
        metric(
            &setup,
            "zentinel_blocked_requests_total",
            &["reason=\"pii\""]
        ),
        2
    );
    assert_eq!(
        metric(
            &setup,
            "zentinel_pii_detected_total",
            &["route=\"closed\"", "category=\"ssn\""]
        ),
        1
    );
}

/// A prompt without PII reaches the upstream unchanged.
#[test]
fn a_clean_prompt_reaches_the_upstream_unchanged() {
    let setup = setup();
    let prompt = chat("what is the capital of France?");

    for route in ["/closed/chat", "/open/chat"] {
        let (status, body) = post(&setup, route, &prompt);
        assert_eq!(status, 200, "{route}: {body}");
        assert!(body.contains(MARKER), "{route}: {body}");
    }
    let requests = setup.upstream_requests();
    assert_eq!(requests.len(), 2);
    for (_, body) in requests {
        assert_eq!(body, prompt.as_bytes());
    }
}

/// A check that cannot be made follows the guardrail's `failure-mode`:
/// `closed` refuses with 503 (the agent's call failed), 504 (no answer in
/// `timeout-ms`) or `block-status` (no text in the body); `open` forwards.
#[test]
fn a_failed_check_follows_the_failure_mode() {
    let setup = setup();

    let (status, body) = post(&setup, "/closed/chat", &chat("agent-error-phrase"));
    assert_eq!(status, 503, "{body}");
    assert_eq!(refusal(&body).0, "pii_blocked");
    let (status, body) = post(&setup, "/closed/chat", &chat("hang-phrase"));
    assert_eq!(status, 504, "{body}");
    let (status, body) = post(&setup, "/closed/chat", "not json");
    assert_eq!(status, 451, "{body}");
    assert_eq!(
        refusal(&body).1,
        "Request blocked: its content could not be read for the check"
    );
    assert!(setup.upstream_requests().is_empty());
    assert_eq!(
        metric(
            &setup,
            "zentinel_blocked_requests_total",
            &["reason=\"pii_check_failed\""]
        ),
        3
    );

    for body in [
        chat("agent-error-phrase"),
        chat("hang-phrase"),
        "not json".into(),
    ] {
        let (status, reply) = post(&setup, "/open/chat", &body);
        assert_eq!(status, 200, "{body}: {reply}");
    }
    assert_eq!(setup.upstream_requests().len(), 3);
}

/// `action "log"` does not check the request: a prompt with PII in it is
/// forwarded, and the agent is not asked.
#[test]
fn log_does_not_check_the_request() {
    let setup = setup();
    let prompt = chat(&format!("my SSN is {SSN}"));

    let (status, body) = post(&setup, "/log/chat", &prompt);
    assert_eq!(status, 200, "{body}");
    assert_eq!(setup.upstream_requests().len(), 1);
    assert!(setup.guard.seen.lock().unwrap().is_empty());
}
