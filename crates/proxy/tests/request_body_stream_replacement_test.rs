//! An agent in `request-body-mode "stream"` that replaces a request body
//! chunk: the upstream gets the replacement's bytes, not the base64 text the
//! protocol carries them in (#836); a replacement that is not valid base64
//! follows the body agents' failure mode.
//! Runs the real binary with a v2 agent and a backend that records bodies.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, BodyMutation, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-REPLACE";

fn free_ports(range: std::ops::Range<u16>) -> (u16, u16) {
    let mut free = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok());
    (
        free.next().expect("a free port"),
        free.next()
            .unwrap_or_else(|| panic!("two free ports in {range:?}")),
    )
}

/// A backend answering 200 with [`MARKER`], recording each body it gets.
fn spawn_backend(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    line.clear();
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    return;
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&body).into_owned());
                let body = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Status and raw response of a request with `body`.
fn send(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, raw)
}

/// Replaces `secret` with `XXXXXX` (same length, so `Content-Length`
/// still holds), and answers a chunk containing `garble` with a replacement
/// that is not base64.
struct Redactor;

#[async_trait::async_trait]
impl AgentHandlerV2 for Redactor {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("redactor", "Redactor", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if event.uri.contains("probe-block") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let data =
            String::from_utf8_lossy(&engine.decode(&event.data).unwrap_or_default()).into_owned();
        if data.contains("garble") {
            return AgentResponse::default_allow().with_request_body_mutation(
                BodyMutation::replace(event.chunk_index, "!!! not base64 !!!".to_string()),
            );
        }
        if data.contains("secret") {
            let redacted = data.replace("secret", "XXXXXX");
            return AgentResponse::default_allow().with_request_body_mutation(
                BodyMutation::replace(event.chunk_index, engine.encode(redacted)),
            );
        }
        AgentResponse::default_allow()
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("redactor.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("redactor", socket.clone(), Box::new(Redactor));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(ports);
    let seen = Arc::new(Mutex::new(Vec::new()));
    spawn_backend(backend, seen.clone());
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
        target "127.0.0.1:{backend}"
    }}
}}
agents {{
    agent "redactor" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        request-body-mode "stream"
        timeout-ms 2000
    }}
}}
filters {{
    filter "redactor" {{
        type "agent"
        agent "redactor"
        failure-mode "closed"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "redactor"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display()
    );
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config).unwrap();
    let proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    // Wait until the agent is connected and consulted.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (blocked, _) = send(port, "GET", "/probe-block", "");
        let (fine, _) = send(port, "GET", "/fine", "");
        if blocked == 403 && fine == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {blocked} {fine}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// The upstream gets the replacement's bytes, exactly.
#[test]
fn a_replaced_chunk_reaches_the_upstream_as_its_bytes() {
    let setup = setup(19980..19986);
    let (status, raw) = send(setup.port, "POST", "/upload", "{\"token\":\"secret\"}");
    assert_eq!(status, 200, "{raw}");
    let seen = setup.seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|b| b == "{\"token\":\"XXXXXX\"}"),
        "the upstream did not get the replacement byte for byte: {seen:?}"
    );
    assert!(!seen.iter().any(|b| b.contains("secret")), "{seen:?}");
}

/// A replacement that is not base64 is not answered by forwarding the
/// original chunk: with a `closed` filter the request gets 503.
#[test]
fn a_replacement_that_is_not_base64_fails_closed() {
    let setup = setup(19986..19992);
    let (status, raw) = send(setup.port, "POST", "/upload", "{\"token\":\"garble\"}");
    assert_eq!(status, 503, "{raw}");
    let seen = setup.seen.lock().unwrap().clone();
    assert!(!seen.iter().any(|b| b.contains("garble")), "{seen:?}");
    assert!(!seen.iter().any(|b| b.contains("not base64")), "{seen:?}");
}
