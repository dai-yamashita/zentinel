//! A request body with a `Content-Encoding` is inspected as what it says it
//! is, or follows the agents' `failure-mode`.
//!
//! The body agents were sent a content-coded body still compressed, without
//! a warning or a metric, when:
//!
//! - `body-inspection { decompress }` was not set. It was `#false` by
//!   default; it is `#true` now.
//! - the header was a list (`gzip, br`) or was sent as more than one
//!   `Content-Encoding` header: the value of the first header was compared
//!   whole, and anything but exactly `gzip`, `deflate` or `br` went on
//!   undecoded.
//! - the coding is not one that is decoded (`zstd`).
//! - the agent's `request-body-mode` sends the body in pieces, so that it
//!   cannot be decoded: `stream`, and `hybrid` for a body that goes past its
//!   threshold.
//!
//! Now every `Content-Encoding` header is read as a list, ignoring case and
//! the spaces around a name, and `identity` is dropped. A body in one
//! supported coding is decoded for the agents when `decompress` is on and
//! the body is held whole. A body that is not decoded (`decompress #false`,
//! a coding that is not supported, several codings, or a body in pieces)
//! cannot be inspected as sent: each body agent's `failure-mode` decides.
//! `closed` refuses with 415 before any of the body reaches the upstream;
//! `open` lets the request through, sends the agents none of the body, and
//! logs a warning and counts `zentinel_decompression_total` with the reason
//! `not_decoded`. A body that cannot be decoded for another reason (invalid
//! data, over the ratio limit) is handled alike, with 400. A body that
//! decodes to more than `max-inspection-bytes` is handled as one that is over
//! it as received: 413 for `closed`, and `open` is sent none of it.
//!
//! Runs the real binary against a backend that records the bodies it gets,
//! with in-test v2 agents that record the body events they are sent.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestBodyChunkEvent};

/// The body the clients send, before any coding.
const TEXT: &[u8] = "{\"name\":\"caf\u{e9}\"}".as_bytes();

/// What an agent was sent of a request body: the data of each event.
type Events = Arc<Mutex<Vec<Vec<u8>>>>;

/// What the backend got: the request line and the body.
type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// The ports this file hands to the proxies, for their listener and their
/// metrics endpoint. No other test of the crate takes ports from this range,
/// and it lies below the range the OS picks its own from.
const PROXY_PORTS: std::ops::Range<u16> = 28400..28600;

/// Where the next port of `PROXY_PORTS` is taken from.
static NEXT_PROXY_PORT: AtomicU16 = AtomicU16::new(0);

/// Held while a port is probed and while a proxy is started. A child process
/// started while another thread has a probe listener open can inherit it
/// (sockets are not created close-on-exec in one step on every platform, macOS
/// among them), and the proxy that inherits it keeps that port in use until it
/// exits, so the proxy that is meant to listen there never gets it.
static PROBE_OR_SPAWN: Mutex<()> = Mutex::new(());

/// A port of `PROXY_PORTS` that nothing listens on. The tests of this file
/// run side by side, so each takes the next number and checks that it can be
/// bound, rather than letting the OS pick a port to be given up and bound
/// again by the proxy, which two tests can both be given.
fn proxy_port() -> u16 {
    let _held = PROBE_OR_SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let size = PROXY_PORTS.end - PROXY_PORTS.start;
    for _ in 0..size {
        let port = PROXY_PORTS.start + NEXT_PROXY_PORT.fetch_add(1, Ordering::Relaxed) % size;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in {PROXY_PORTS:?}");
}

/// A backend answering 200 to everything, recording each request's body.
fn spawn_backend(listener: TcpListener, requests: Requests) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let requests = requests.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let mut length = 0usize;
                let mut chunked = false;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if request_line.is_empty() {
                        request_line = line.trim_end().to_string();
                    } else if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        } else if name.eq_ignore_ascii_case("transfer-encoding") {
                            chunked = value.to_ascii_lowercase().contains("chunked");
                        }
                    }
                    line.clear();
                }
                if request_line.is_empty() {
                    return;
                }
                // What arrived, also when the connection ends early.
                let mut body = Vec::new();
                if chunked {
                    loop {
                        let mut size_line = String::new();
                        if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
                            break;
                        }
                        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                        if size == 0 {
                            break;
                        }
                        let mut chunk = vec![0; size];
                        if reader.read_exact(&mut chunk).is_err() {
                            break;
                        }
                        body.extend_from_slice(&chunk);
                        let mut crlf = [0; 2];
                        let _ = reader.read_exact(&mut crlf);
                    }
                } else {
                    body = vec![0; length];
                    let mut got = 0;
                    while got < length {
                        match reader.read(&mut body[got..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got += n,
                        }
                    }
                    body.truncate(got);
                }
                requests.lock().unwrap().push((request_line, body));
                let reply = "ok\n";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            });
        }
    });
}

/// Allows everything, recording the data of the body events it is sent.
struct Recorder {
    events: Events,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        self.events.lock().unwrap().push(data);
        AgentResponse::default_allow()
    }
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How a request body is framed.
enum Framing<'a> {
    /// One `Content-Length` body.
    Length(&'a [u8]),
    /// A chunked body, one chunk per slice, then the terminating chunk.
    Chunked(&'a [&'a [u8]]),
}

/// POST to `path` with the given extra header lines; the status. Panics when
/// the connection cannot be made.
fn post_framed(port: u16, path: &str, headers: &[&str], framing: Framing<'_>) -> u16 {
    try_post_framed(port, path, headers, framing).expect("connect to the proxy")
}

/// `post_framed`, with the error of connecting returned. A proxy that has just
/// started can refuse or reset a connection a moment after it first accepted
/// one, so `setup` asks again.
fn try_post_framed(
    port: u16,
    path: &str,
    headers: &[&str],
    framing: Framing<'_>,
) -> std::io::Result<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n"
    )
    .into_bytes();
    for header in headers {
        request.extend_from_slice(header.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    match framing {
        Framing::Length(body) => {
            request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            request.extend_from_slice(body);
        }
        Framing::Chunked(chunks) => {
            request.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
            for chunk in chunks {
                request.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                request.extend_from_slice(chunk);
                request.extend_from_slice(b"\r\n");
            }
            request.extend_from_slice(b"0\r\n\r\n");
        }
    }
    // The proxy may answer and close before it has read all of a body it
    // refuses; the status is what counts.
    let _ = stream.write_all(&request);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    Ok(String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

/// POST `body` to `path` with the given extra header lines; the status.
fn post(port: u16, path: &str, headers: &[&str], body: &[u8]) -> u16 {
    post_framed(port, path, headers, Framing::Length(body))
}

/// `len` bytes that do not compress.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u32 = 12345;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// `deflate` as RFC 9110 defines it: the zlib format.
fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// `deflate` as a raw deflate stream (RFC 1951) that starts with a stored
/// block, which is not the last and holds one byte. Its first two bytes,
/// `78 01`, are also a valid zlib header: `0x78` is the block header (not
/// final, stored) with padding bits that a stored block leaves unread, and
/// `0x01` is the low byte of the block's `LEN`.
fn raw_deflate_that_starts_like_zlib(data: &[u8]) -> Vec<u8> {
    let (first, rest) = data.split_at(1);
    let mut stream = vec![0x78, 0x01, 0x00, 0xfe, 0xff];
    stream.extend_from_slice(first);
    // The last block.
    stream.push(0x01);
    let len = u16::try_from(rest.len()).unwrap();
    stream.extend_from_slice(&len.to_le_bytes());
    stream.extend_from_slice(&(!len).to_le_bytes());
    stream.extend_from_slice(rest);
    stream
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut encoder = ::brotli::CompressorWriter::new(&mut output, 4096, 4, 22);
        encoder.write_all(data).unwrap();
    }
    output
}

/// The `waf` block of the proxy's configuration.
#[derive(Clone, Copy)]
enum Waf {
    /// None: the agents are sent request bodies without one.
    NoBlock,
    /// A `body-inspection` block that does not set `decompress`.
    DecompressUnset,
    /// A `body-inspection` block with `decompress #false`.
    DecompressOff,
    /// A `body-inspection` block with `max-inspection-bytes 64`, which is
    /// the most of a request body as received, and the most of it decoded.
    SmallLimit,
}

impl Waf {
    fn kdl(self) -> &'static str {
        match self {
            Waf::NoBlock => "",
            Waf::DecompressUnset => {
                "waf {\n    mode \"off\"\n    body-inspection {\n        \
                 inspect-request-body #true\n    }\n}"
            }
            Waf::DecompressOff => {
                "waf {\n    mode \"off\"\n    body-inspection {\n        \
                 inspect-request-body #true\n        decompress #false\n    }\n}"
            }
            Waf::SmallLimit => {
                "waf {\n    mode \"off\"\n    body-inspection {\n        \
                 inspect-request-body #true\n        max-inspection-bytes 64\n    }\n}"
            }
        }
    }
}

struct Setup {
    port: u16,
    /// Where the proxy serves its metrics.
    metrics_port: u16,
    requests: Requests,
    /// What the agent of the `/closed` route (failure mode `closed`) was sent.
    closed: Events,
    /// What the agent of the `/open` route (failure mode `open`) was sent.
    open: Events,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(waf: Waf, mode: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let closed: Events = Arc::default();
    let open: Events = Arc::default();
    let mut sockets = Vec::new();
    for (name, events) in [("closed", &closed), ("open", &open)] {
        let socket = dir.path().join(format!("{name}.sock"));
        let server = UdsAgentServerV2::new(
            name,
            socket.clone(),
            Box::new(Recorder {
                events: events.clone(),
            }),
        );
        rt.spawn(async move {
            let _ = server.run().await;
        });
        sockets.push(socket);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sockets.iter().all(|s| s.exists()) {
        assert!(Instant::now() < deadline, "the agents never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The backend's listener is handed over still open; the proxy's ports
    // come from a range of their own.
    let backend = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let requests: Requests = Arc::default();
    spawn_backend(backend, requests.clone());
    let port = proxy_port();
    let metrics_port = proxy_port();
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
    agent "closed" type="custom" {{
        unix-socket "{closed}"
        events "request_body"
        request-body-mode "{mode}"
        timeout-ms 2000
    }}
    agent "open" type="custom" {{
        unix-socket "{open}"
        events "request_body"
        request-body-mode "{mode}"
        timeout-ms 2000
    }}
}}
filters {{
    filter "closed" {{
        type "agent"
        agent "closed"
        failure-mode "closed"
    }}
    filter "open" {{
        type "agent"
        agent "open"
        failure-mode "open"
    }}
}}
{waf}
routes {{
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        filters "closed"
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        filters "open"
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
        closed = sockets[0].display(),
        open = sockets[1].display(),
        waf = waf.kdl(),
        mode = mode,
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
    // Wait until the agents are connected and consulted: each is sent the
    // body of a request without a content coding.
    let deadline = Instant::now() + Duration::from_secs(10);
    let warm_up = |route: &str| {
        let path = format!("/{route}/warmup");
        try_post_framed(port, &path, &[], Framing::Length(TEXT)).unwrap_or_else(|e| {
            eprintln!("warm-up request to {path}: {e}; asking again");
            0
        })
    };
    loop {
        let a = warm_up("closed");
        let b = warm_up("open");
        let consulted = !closed.lock().unwrap().is_empty() && !open.lock().unwrap().is_empty();
        if a == 200 && b == 200 && consulted {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agents were never consulted: {a} {b}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    closed.lock().unwrap().clear();
    open.lock().unwrap().clear();
    requests.lock().unwrap().clear();
    Setup {
        port,
        metrics_port,
        requests,
        closed,
        open,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

impl Setup {
    /// The lines of the proxy's metrics that start with `prefix`, scraped
    /// once the proxy serves them.
    fn metrics(&self, prefix: &str) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", self.metrics_port)) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = write!(
                    stream,
                    "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                );
                let mut raw = Vec::new();
                let _ = stream.read_to_end(&mut raw);
                let raw = String::from_utf8_lossy(&raw);
                if raw.starts_with("HTTP/1.1 200") {
                    return raw
                        .lines()
                        .filter(|line| line.starts_with(prefix))
                        .map(str::to_string)
                        .collect();
                }
            }
            assert!(Instant::now() < deadline, "the metrics were never served");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// What the agent of `route` was sent for the next request, and that
    /// request's status, and the body the upstream got: `None` when the
    /// request never reached it. The agent's record is emptied first; it has
    /// been consulted by the time the proxy answers.
    fn send(
        &self,
        route: &str,
        case: usize,
        headers: &[&str],
        body: &[u8],
    ) -> (u16, Vec<Vec<u8>>, Option<Vec<u8>>) {
        self.send_framed(route, case, headers, Framing::Length(body))
    }

    fn send_framed(
        &self,
        route: &str,
        case: usize,
        headers: &[&str],
        framing: Framing<'_>,
    ) -> (u16, Vec<Vec<u8>>, Option<Vec<u8>>) {
        let events = if route == "closed" {
            &self.closed
        } else {
            &self.open
        };
        events.lock().unwrap().clear();
        let path = format!("/{route}/case{case}");
        let status = post_framed(self.port, &path, headers, framing);
        let seen = events.lock().unwrap().clone();
        // The upstream is sent the request's headers before the body is
        // read, so it records a request even when the body is refused. It is
        // waited for, so that what it got is looked at once it is recorded.
        let deadline = Instant::now() + Duration::from_secs(10);
        let upstream_body = loop {
            let found = self
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|(line, _)| line.contains(&format!(" {path} ")))
                .map(|(_, body)| body.clone());
            if found.is_some() || Instant::now() >= deadline {
                break found;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        (status, seen, upstream_body)
    }

    /// Check a body that is refused with `refused_with` by a `closed` agent,
    /// and let through by an `open` one that is sent none of it, with the
    /// upstream getting the body as sent.
    fn check_refused_or_skipped(
        &self,
        case: usize,
        headers: &[&str],
        body: &[u8],
        refused_with: u16,
    ) {
        let (status, seen, upstream) = self.send("closed", case, headers, body);
        assert_eq!(
            status, refused_with,
            "{headers:?}: a closed agent refuses the body"
        );
        assert!(
            seen.is_empty(),
            "{headers:?}: the agent is not sent the body"
        );
        assert_eq!(
            upstream,
            Some(Vec::new()),
            "{headers:?}: the upstream is reached, and none of the body is"
        );

        let (status, seen, upstream) = self.send("open", case, headers, body);
        assert_eq!(status, 200, "{headers:?}: an open agent lets it through");
        assert!(
            seen.is_empty(),
            "{headers:?}: an open agent is sent none of it"
        );
        assert_eq!(upstream.as_deref(), Some(body), "{headers:?}");
    }
}

/// With nothing set, a gzip body is decoded for the agents, and the
/// upstream still gets it as the client sent it.
#[test]
fn a_gzip_body_is_decoded_for_the_agents_by_default() {
    let setup = setup(Waf::DecompressUnset, "buffer");
    let body = gzip(TEXT);
    for (case, route) in ["closed", "open"].into_iter().enumerate() {
        let (status, seen, upstream) = setup.send(route, case, &["Content-Encoding: gzip"], &body);
        assert_eq!(status, 200, "{route}");
        assert_eq!(
            seen,
            vec![TEXT.to_vec()],
            "{route}: the agent is sent the body decoded"
        );
        assert_eq!(
            upstream.as_deref(),
            Some(&body[..]),
            "{route}: the upstream gets the body as sent"
        );
    }
}

/// The same without a `waf` block, where the agents are sent request bodies
/// all the same.
#[test]
fn a_gzip_body_is_decoded_for_the_agents_without_a_waf_block() {
    let setup = setup(Waf::NoBlock, "buffer");
    let body = gzip(TEXT);
    let (status, seen, upstream) = setup.send("closed", 0, &["Content-Encoding: gzip"], &body);
    assert_eq!(status, 200);
    assert_eq!(
        seen,
        vec![TEXT.to_vec()],
        "the agent is sent the body decoded"
    );
    assert_eq!(
        upstream.as_deref(),
        Some(&body[..]),
        "the upstream gets the body as sent"
    );
}

/// A single coding is found in a list, whatever its case, with `identity`
/// left out, and across `Content-Encoding` headers.
#[test]
fn a_single_supported_coding_is_decoded_however_the_header_is_written() {
    let setup = setup(Waf::DecompressUnset, "buffer");
    let gz = gzip(TEXT);
    let cases: Vec<(Vec<&str>, Vec<u8>)> = vec![
        (vec!["Content-Encoding: GZIP"], gz.clone()),
        (vec!["Content-Encoding: identity,  Gzip ,"], gz.clone()),
        (
            vec!["Content-Encoding: identity", "Content-Encoding: gzip"],
            gz.clone(),
        ),
        (vec!["Content-Encoding: x-gzip"], gz.clone()),
        (vec!["Content-Encoding: deflate"], deflate(TEXT)),
        (
            vec!["Content-Encoding: deflate"],
            raw_deflate_that_starts_like_zlib(TEXT),
        ),
        (vec!["Content-Encoding: BR"], brotli(TEXT)),
        (vec!["Content-Encoding: brotli"], brotli(TEXT)),
    ];
    for (case, (headers, body)) in cases.iter().enumerate() {
        let (status, seen, upstream) = setup.send("closed", case, headers, body);
        assert_eq!(status, 200, "{headers:?}");
        assert_eq!(
            seen,
            vec![TEXT.to_vec()],
            "{headers:?}: the agent is sent the body decoded"
        );
        assert_eq!(
            upstream.as_deref(),
            Some(&body[..]),
            "{headers:?}: the upstream gets it as sent"
        );
    }
}

/// No coding, or only `identity`: the body is sent as it is.
#[test]
fn a_body_without_a_content_coding_is_sent_to_the_agents_as_it_is() {
    let setup = setup(Waf::DecompressUnset, "buffer");
    for (case, headers) in [
        vec![],
        vec!["Content-Encoding: identity"],
        vec!["Content-Encoding: "],
    ]
    .iter()
    .enumerate()
    {
        let (status, seen, upstream) = setup.send("closed", case, headers, TEXT);
        assert_eq!(status, 200, "{headers:?}");
        assert_eq!(seen, vec![TEXT.to_vec()], "{headers:?}");
        assert_eq!(upstream.as_deref(), Some(TEXT), "{headers:?}");
    }
}

/// `decompress #false` keeps the body as sent, and a body that is not
/// decoded is not inspected: a `closed` agent refuses it with 415 before
/// any of it reaches the upstream, and an `open` one is sent none of it.
#[test]
fn with_decompress_off_the_failure_mode_decides() {
    let setup = setup(Waf::DecompressOff, "buffer");
    setup.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &gzip(TEXT), 415);

    // The coding is not looked at when the body is not decoded, so a body
    // without one is untouched.
    let (status, seen, _) = setup.send("closed", 2, &[], TEXT);
    assert_eq!(status, 200);
    assert_eq!(seen, vec![TEXT.to_vec()]);
}

/// A coding that is not supported, or several of them, cannot be decoded:
/// the failure mode decides, as for `decompress #false`.
#[test]
fn a_body_in_a_coding_that_is_not_decoded_follows_the_failure_mode() {
    let setup = setup(Waf::DecompressUnset, "buffer");
    let stacked = brotli(&gzip(TEXT));
    let cases: Vec<(Vec<&str>, Vec<u8>)> = vec![
        (vec!["Content-Encoding: zstd"], b"not-decoded".to_vec()),
        (vec!["Content-Encoding: ZSTD "], b"not-decoded".to_vec()),
        (vec!["Content-Encoding: gzip, br"], stacked.clone()),
        (
            vec!["Content-Encoding: gzip", "Content-Encoding: br"],
            stacked.clone(),
        ),
        (vec!["Content-Encoding: gzip, zstd"], stacked.clone()),
    ];
    for (case, (headers, body)) in cases.iter().enumerate() {
        setup.check_refused_or_skipped(case, headers, body, 415);
    }

    // No body, nothing to inspect: the header alone refuses nothing.
    let (status, seen, _) = setup.send("closed", 100, &["Content-Encoding: zstd"], b"");
    assert_eq!(status, 200);
    assert!(seen.is_empty());
}

/// A body that cannot be decoded for another reason (it is not valid data,
/// or goes over the ratio limit) is refused with 400 by a `closed` agent,
/// and an `open` one is sent none of it.
#[test]
fn a_body_that_fails_to_decode_follows_the_failure_mode() {
    let setup = setup(Waf::DecompressUnset, "buffer");

    // Not valid gzip.
    setup.check_refused_or_skipped(0, &["Content-Encoding: gzip"], b"not-gzip", 400);

    // Over the ratio limit (100), in the zlib format: 500000 bytes of zeros
    // are some 500 bytes of data.
    let zeros = deflate(&vec![0u8; 500_000]);
    assert!(zeros.len() * 100 < 500_000);
    setup.check_refused_or_skipped(1, &["Content-Encoding: deflate"], &zeros, 400);
}

/// A body that decodes to more than `max-inspection-bytes` is handled as a
/// body that is over it as received: a `closed` agent refuses it with 413,
/// and an `open` one is sent none of it.
#[test]
fn a_coded_body_follows_the_failure_mode_over_the_inspection_limits() {
    let setup = setup(Waf::SmallLimit, "buffer");

    // Decoded, 1000 bytes of zeros are over the 64 allowed, and well inside
    // the ratio limit.
    let zeros = gzip(&[0u8; 1000]);
    assert!(zeros.len() <= 64 && zeros.len() * 100 > 1000);
    setup.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &zeros, 413);

    // The same in the other codings.
    let zeros = deflate(&[0u8; 1000]);
    assert!(zeros.len() <= 64);
    setup.check_refused_or_skipped(1, &["Content-Encoding: deflate"], &zeros, 413);
    let zeros = brotli(&[0u8; 1000]);
    assert!(zeros.len() <= 64);
    setup.check_refused_or_skipped(2, &["Content-Encoding: br"], &zeros, 413);

    // As received, a body of more than 64 bytes is over the limit, coded or
    // not.
    let noise = gzip(&noise(200));
    assert!(noise.len() > 64);
    setup.check_refused_or_skipped(3, &["Content-Encoding: gzip"], &noise, 413);
}

/// The decoding checks the size and then the ratio after each chunk of
/// output, and stops at the first limit it reaches. A body that is small as
/// received reaches `max-decompression-ratio` before it decodes to more than
/// `max-inspection-bytes`: it fails to decode, as it did before. When the
/// first chunk of output is already over `max-inspection-bytes`, the size is
/// what is found, though the ratio is over as well.
#[test]
fn a_highly_compressed_body_follows_the_limit_it_reaches_first() {
    // 2 MiB of zeros are some 2 KB of data: over the ratio limit (100) after
    // some 200 KB of output, before the 1 MiB of the default.
    let setup_default = setup(Waf::DecompressUnset, "buffer");
    let zeros = gzip(&vec![0u8; 2 * 1024 * 1024]);
    assert!(zeros.len() * 100 < 1024 * 1024);
    setup_default.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &zeros, 400);

    // With `max-inspection-bytes 64`, the first chunk of output of a
    // megabyte of zeros is over it, and over the ratio too.
    let setup_small = setup(Waf::SmallLimit, "buffer");
    let zeros = brotli(&vec![0u8; 1_000_000]);
    assert!(zeros.len() <= 64, "{} bytes", zeros.len());
    assert!(zeros.len() * 100 < 4096, "{} bytes", zeros.len());
    setup_small.check_refused_or_skipped(0, &["Content-Encoding: br"], &zeros, 413);
}

/// A body of exactly `max-inspection-bytes` is within the limit, decoded as
/// it is as received; one byte more is over it.
#[test]
fn a_body_decoded_to_exactly_the_inspection_limit_is_within_it() {
    let setup = setup(Waf::SmallLimit, "buffer");

    let exact = gzip(&[b'a'; 64]);
    assert!(exact.len() <= 64);
    for (case, route) in ["closed", "open"].into_iter().enumerate() {
        let (status, seen, upstream) = setup.send(route, case, &["Content-Encoding: gzip"], &exact);
        assert_eq!(status, 200, "{route}");
        assert_eq!(seen, vec![vec![b'a'; 64]], "{route}: sent whole");
        assert_eq!(upstream.as_deref(), Some(&exact[..]), "{route}");
    }

    let over = gzip(&[b'a'; 65]);
    assert!(over.len() <= 64);
    setup.check_refused_or_skipped(2, &["Content-Encoding: gzip"], &over, 413);
}

/// A body whose decoding stops at the limit is counted, as one that fails to
/// decode is, with the reason `size_exceeded`, whatever its failure mode.
#[test]
fn a_body_decoded_over_the_inspection_limit_is_counted() {
    let setup = setup(Waf::SmallLimit, "buffer");
    let zeros = gzip(&[0u8; 1000]);
    for (case, route) in ["closed", "open"].into_iter().enumerate() {
        setup.send(route, case, &["Content-Encoding: gzip"], &zeros);
    }

    let counts = setup.metrics("zentinel_decompression_total");
    assert_eq!(
        counts,
        vec!["zentinel_decompression_total{encoding=\"gzip\",result=\"size_exceeded\"} 2"],
        "counted for each request"
    );
}

/// The limit applies to every `request-body-mode` that decodes: `hybrid` for
/// a body held whole within its threshold, and `inspect-first`, which
/// decides before the upstream is contacted.
#[test]
fn a_body_decoded_over_the_inspection_limit_is_handled_alike_in_every_mode() {
    let zeros = gzip(&[0u8; 1000]);
    assert!(zeros.len() <= 64);

    let hybrid = setup(Waf::SmallLimit, "hybrid:1024");
    hybrid.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &zeros, 413);

    let first = setup(Waf::SmallLimit, "inspect-first");
    let status = post(
        first.port,
        "/closed/case0",
        &["Content-Encoding: gzip"],
        &zeros,
    );
    assert_eq!(status, 413, "a closed agent refuses the body");
    assert!(first.closed.lock().unwrap().is_empty());
    assert!(
        !first
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(line, _)| line.contains(" /closed/case0 ")),
        "the upstream is not contacted"
    );
    let (status, seen, upstream) = first.send("open", 0, &["Content-Encoding: gzip"], &zeros);
    assert_eq!(status, 200, "an open agent lets it through");
    assert!(seen.is_empty(), "an open agent is sent none of it");
    assert_eq!(upstream.as_deref(), Some(&zeros[..]));
}

/// An agent that is sent the body in chunks as they arrive cannot be sent
/// it decoded: whatever the coding, the failure mode decides.
#[test]
fn a_body_sent_in_chunks_is_not_decoded_and_follows_the_failure_mode() {
    let setup = setup(Waf::DecompressUnset, "stream");
    setup.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &gzip(TEXT), 415);

    // Without a coding, the body is streamed as before.
    let (status, seen, upstream) = setup.send("closed", 2, &[], TEXT);
    assert_eq!(status, 200);
    assert_eq!(seen, vec![TEXT.to_vec()]);
    assert_eq!(upstream.as_deref(), Some(TEXT));
}

/// A body that arrives in several chunks is decided on once: it is counted
/// once, however many chunks follow, and an `open` agent is sent none of
/// them.
#[test]
fn a_body_in_several_chunks_is_decided_on_once() {
    let setup = setup(Waf::DecompressUnset, "stream");
    let body = noise(300);
    let chunks: Vec<&[u8]> = body.chunks(100).collect();
    assert_eq!(chunks.len(), 3);
    let (status, seen, upstream) = setup.send_framed(
        "open",
        0,
        &["Content-Encoding: gzip"],
        Framing::Chunked(&chunks),
    );
    assert_eq!(status, 200);
    assert!(seen.is_empty(), "an open agent is sent none of the chunks");
    assert_eq!(upstream.as_deref(), Some(&body[..]));

    let counts = setup.metrics("zentinel_decompression_total");
    assert_eq!(
        counts,
        vec!["zentinel_decompression_total{encoding=\"gzip\",result=\"not_decoded\"} 1"],
        "counted once for the request"
    );
}

/// `hybrid` mode holds a body whole up to its threshold: one that fits is
/// decoded. One that goes past it is sent in pieces, which cannot be
/// decoded, so the failure mode decides. A start cut short is not decoded
/// to be sent on, whatever the coding.
#[test]
fn a_body_past_the_hybrid_threshold_is_not_decoded() {
    // Fits: whole before the end of the buffer.
    let setup_fits = setup(Waf::DecompressUnset, "hybrid:1024");
    let body = gzip(TEXT);
    let (status, seen, upstream) = setup_fits.send("closed", 0, &["Content-Encoding: gzip"], &body);
    assert_eq!(status, 200);
    assert_eq!(seen, vec![TEXT.to_vec()], "the body is decoded");
    assert_eq!(upstream.as_deref(), Some(&body[..]));

    // Past it: 8 bytes are held, and the body is longer.
    let setup_past = setup(Waf::DecompressUnset, "hybrid:8");
    setup_past.check_refused_or_skipped(0, &["Content-Encoding: gzip"], &gzip(TEXT), 415);
    setup_past.check_refused_or_skipped(1, &["Content-Encoding: br"], &brotli(TEXT), 415);
    setup_past.check_refused_or_skipped(2, &["Content-Encoding: deflate"], &deflate(TEXT), 415);

    let counts = setup_past.metrics("zentinel_decompression_total");
    assert!(
        counts.iter().all(|line| line.contains("not_decoded")),
        "no body was decoded or failed to decode: {counts:?}"
    );
}

/// A body that is not decoded is counted with the reason `not_decoded`,
/// under a bounded `encoding`: the coding when it is one that is decoded,
/// `other` for anything else.
#[test]
fn a_body_that_is_not_decoded_is_counted() {
    let setup = setup(Waf::DecompressUnset, "buffer");
    let body = gzip(TEXT);
    for (case, coding) in ["zstd", "x-private-coding", "gzip, br"]
        .into_iter()
        .enumerate()
    {
        let header = format!("Content-Encoding: {coding}");
        let (status, _, _) = setup.send("open", case, &[header.as_str()], &body);
        assert_eq!(status, 200, "{coding}");
    }
    let (status, _, _) = setup.send("open", 10, &["Content-Encoding: GZIP"], &body);
    assert_eq!(status, 200);

    let counts = setup.metrics("zentinel_decompression_total");
    let count = |encoding: &str, result: &str| {
        let series =
            format!("zentinel_decompression_total{{encoding=\"{encoding}\",result=\"{result}\"}}");
        counts
            .iter()
            .find_map(|line| line.strip_prefix(&series))
            .map(|value| value.trim().to_string())
    };
    assert_eq!(
        count("other", "not_decoded").as_deref(),
        Some("3"),
        "{counts:?}"
    );
    assert_eq!(count("gzip", "success").as_deref(), Some("1"), "{counts:?}");
    assert_eq!(count("GZIP", "success"), None, "{counts:?}");
}

/// `inspect-first` decides on the whole body before an upstream is chosen:
/// a coded body is decoded for the agents, and one that is not decoded is
/// refused without the upstream being contacted at all.
#[test]
fn an_inspect_first_body_is_decoded_or_refused_before_the_upstream() {
    let setup = setup(Waf::DecompressUnset, "inspect-first");
    let body = gzip(TEXT);

    let (status, seen, upstream) = setup.send("closed", 0, &["Content-Encoding: gzip"], &body);
    assert_eq!(status, 200);
    assert_eq!(
        seen,
        vec![TEXT.to_vec()],
        "the agent is sent the body decoded"
    );
    assert_eq!(
        upstream.as_deref(),
        Some(&body[..]),
        "the upstream gets the body as sent"
    );

    setup.closed.lock().unwrap().clear();
    let status = post(
        setup.port,
        "/closed/case1",
        &["Content-Encoding: zstd"],
        b"not-decoded",
    );
    assert_eq!(status, 415, "a closed agent refuses the body");
    assert!(setup.closed.lock().unwrap().is_empty());
    assert!(
        !setup
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(line, _)| line.contains(" /closed/case1 ")),
        "the upstream is not contacted"
    );
}
