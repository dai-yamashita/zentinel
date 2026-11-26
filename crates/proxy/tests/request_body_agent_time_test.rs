//! `body-agent-time-ms`: the most time body agents may spend on one request
//! body in `stream` mode, summed over its chunks (#833). Once it is spent, a
//! `closed` filter refuses the request with 504 and an `open` one sends the
//! rest of the body on without the agents.
//! Runs the real binary with a v2 agent and a backend that records bodies.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-AGENTTIME";

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
                let mut chunked = false;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                        if name.eq_ignore_ascii_case("transfer-encoding")
                            && value.to_ascii_lowercase().contains("chunked")
                        {
                            chunked = true;
                        }
                    }
                    line.clear();
                }
                let body = if chunked {
                    let mut body = Vec::new();
                    loop {
                        let mut size = String::new();
                        if reader.read_line(&mut size).is_err() {
                            return;
                        }
                        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
                            return;
                        };
                        let mut chunk = vec![0; size + 2];
                        if reader.read_exact(&mut chunk).is_err() {
                            return;
                        }
                        if size == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..size]);
                    }
                    body
                } else {
                    let mut body = vec![0; length];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    body
                };
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

/// Sends a chunked `POST` of `parts`, pausing between them so the proxy
/// reads each as its own chunk; status and raw response.
fn send_in_parts(port: u16, parts: &[&str]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    for part in parts {
        // A write fails once the proxy has refused the request and closed.
        if write!(stream, "{:x}\r\n{part}\r\n", part.len()).is_err() {
            break;
        }
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = write!(stream, "0\r\n\r\n");
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

/// Takes 300 ms over every body chunk; counts the chunks it gets.
struct Slow {
    chunks: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Slow {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("slow", "Slow", "0.1.0")
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

    async fn on_request_body_chunk(&self, _event: RequestBodyChunkEvent) -> AgentResponse {
        self.chunks.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        AgentResponse::default_allow()
    }
}

struct Setup {
    port: u16,
    metrics_port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    chunks: Arc<AtomicUsize>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>, failure_mode: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("slow.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let chunks = Arc::new(AtomicUsize::new(0));
    let server = UdsAgentServerV2::new(
        "slow",
        socket.clone(),
        Box::new(Slow {
            chunks: chunks.clone(),
        }),
    );
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(ports.clone());
    // A range of its own, so tests running side by side never reach for
    // each other's ports.
    let metrics_port = (ports.start + 1000..ports.end + 1000)
        .find(|&p| TcpListener::bind(("127.0.0.1", p)).is_ok())
        .expect("a free metrics port");
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
    agent "slow" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        request-body-mode "stream"
        timeout-ms 2000
        body-agent-time-ms 500
    }}
}}
filters {{
    filter "slow" {{
        type "agent"
        agent "slow"
        failure-mode "{failure_mode}"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "slow"
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
        metrics_port,
        seen,
        chunks,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

impl Setup {
    /// The value of the sample `name{labels}` on the metrics endpoint.
    fn metric(&self, sample: &str) -> Option<f64> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.metrics_port)).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .ok()?;
        let mut raw = String::new();
        let _ = stream.read_to_string(&mut raw);
        raw.lines()
            .find(|line| line.starts_with(sample))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
    }
}

const PARTS: [&str; 5] = ["part-1;", "part-2;", "part-3;", "part-4;", "part-5;"];

/// `closed`: once 500 ms of agent time is spent (two 300 ms chunks), the
/// request is refused with 504 and the agent sees no further chunks.
#[test]
fn spent_body_agent_time_fails_closed() {
    let setup = setup(20324..20330, "closed");
    let (status, raw) = send_in_parts(setup.port, &PARTS);
    assert_eq!(status, 504, "{raw}");
    let chunks = setup.chunks.load(Ordering::SeqCst);
    assert!(
        chunks < PARTS.len(),
        "the agent was sent every chunk ({chunks}) although its time was spent"
    );
    let seen = setup.seen.lock().unwrap().clone();
    assert!(!seen.iter().any(|b| b.contains("part-5")), "{seen:?}");
}

/// `open`: once the time is spent, the rest of the body goes on without the
/// agent, so the upstream gets all of it.
#[test]
fn spent_body_agent_time_sends_the_rest_on_when_open() {
    let setup = setup(20330..20336, "open");
    let (status, raw) = send_in_parts(setup.port, &PARTS);
    assert_eq!(status, 200, "{raw}");
    let chunks = setup.chunks.load(Ordering::SeqCst);
    assert!(
        chunks < PARTS.len(),
        "the agent was sent every chunk ({chunks}) although its time was spent"
    );
    let seen = setup.seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|b| b == &PARTS.concat()),
        "the upstream did not get the whole body: {seen:?}"
    );
}

/// The streamed chunks, their bytes and how long the agents took are
/// counted per route, and so is the body whose agent time was spent.
#[test]
fn streamed_body_chunks_and_spent_agent_time_are_counted() {
    let setup = setup(20336..20342, "open");
    let (status, raw) = send_in_parts(setup.port, &PARTS);
    assert_eq!(status, 200, "{raw}");
    let chunks = setup.chunks.load(Ordering::SeqCst) as f64;
    let route = "{route=\"all\"}";
    assert_eq!(
        setup.metric(&format!("zentinel_agent_body_chunks_total{route}")),
        Some(chunks),
        "one count per chunk the agent was sent"
    );
    let bytes = setup
        .metric(&format!("zentinel_agent_body_bytes_total{route}"))
        .expect("bytes counted");
    assert!(bytes >= chunks, "{bytes} bytes for {chunks} chunks");
    assert_eq!(
        setup.metric(&format!(
            "zentinel_agent_body_chunk_duration_seconds_count{route}"
        )),
        Some(chunks)
    );
    let slow = setup
        .metric(&format!(
            "zentinel_agent_body_chunk_duration_seconds_sum{route}"
        ))
        .expect("durations observed");
    assert!(
        slow >= 0.3 * chunks,
        "the agent takes 300 ms per chunk: {slow} s"
    );
    assert_eq!(
        setup
            .metric("zentinel_agent_body_time_exceeded_total{failure_mode=\"open\",route=\"all\"}"),
        Some(1.0)
    );
}
