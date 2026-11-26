//! The token rate limit, the token budget and model routing of an inference
//! route read the request body.
//!
//! The limits used to be checked in `request_filter` against a buffer that is
//! only filled later, in `request_body_filter`, so every request was
//! estimated as if its body were empty, and model routing read the model
//! only from the `x-model` / `x-model-id` headers. This runs the real binary
//! against two backends that record every request.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Backend {
    /// Each request's head (request line and headers) and body.
    requests: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Backend {
    fn requests_to(&self, path: &str) -> Vec<(String, Vec<u8>)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(head, _)| head.contains(&format!(" {path} ")))
            .cloned()
            .collect()
    }
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
        let mut read = 0;
        while read < length {
            match reader.read(&mut body[read..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n,
            }
        }
        body.truncate(read);
    }
    body
}

/// A backend that records each request and answers `200` with `name`.
fn spawn_backend(listener: TcpListener, backend: Arc<Backend>, name: &'static str) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let backend = backend.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let (mut length, mut chunked) = (None, false);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().ok();
                        }
                        if name.eq_ignore_ascii_case("transfer-encoding")
                            && value.to_ascii_lowercase().contains("chunked")
                        {
                            chunked = true;
                        }
                    }
                    head.push_str(&line);
                    line.clear();
                }
                if head.is_empty() {
                    return;
                }
                let body = read_body(&mut reader, length, chunked);
                backend.requests.lock().unwrap().push((head, body));
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{name}",
                    name.len()
                );
            });
        }
    });
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

/// Ports of the proxy's listener come from a range of its own, so that tests
/// running side by side do not take each other's.
const PROXY_PORTS: std::ops::Range<u16> = 47400..47500;
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

struct Setup {
    port: u16,
    first: Arc<Backend>,
    second: Arc<Backend>,
    _proxy: Proxy,
    _dir: tempfile::TempDir,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();

    let first_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let first = Arc::new(Backend::default());
    spawn_backend(first_listener, first.clone(), "first");
    let second_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let second = Arc::new(Backend::default());
    spawn_backend(second_listener, second.clone(), "second");
    let port = free_proxy_port();

    // A prompt of 4000 characters is estimated at 1000 tokens (`chars`: four
    // characters a token); an empty body at 1.
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
    upstream "first" {{
        target "127.0.0.1:{first_port}"
    }}
    upstream "second" {{
        target "127.0.0.1:{second_port}"
    }}
}}
routes {{
    route "tokens" {{
        matches {{ path-prefix "/tokens" }}
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
        matches {{ path-prefix "/budget" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            budget {{
                period "daily"
                limit 500
            }}
        }}
    }}
    route "limited" {{
        matches {{ path-prefix "/limited" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            rate-limit {{
                tokens-per-minute 100000
                burst-tokens 100000
            }}
        }}
        policies {{
            max-body-size 1024
        }}
    }}
    route "routed" {{
        matches {{ path-prefix "/routed" }}
        upstream "first"
        service-type "inference"
        inference {{
            provider "openai"
            model-routing {{
                model "x" upstream="second"
                default-upstream "first"
            }}
        }}
    }}
}}
"#
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
        first,
        second,
        _proxy: proxy,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A chat request for `model` whose one message says `content`.
fn chat(model: &str, content: &str) -> String {
    serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

fn parse_response(raw: &[u8]) -> (u16, String) {
    let raw = String::from_utf8_lossy(raw).into_owned();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

/// A POST framed by Content-Length, with more request headers.
fn post_with(port: u16, path: &str, body: &[u8], headers: &[(&str, &str)]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut extra = format!("Content-Length: {}\r\n", body.len());
    for (name, value) in headers {
        extra.push_str(&format!("{name}: {value}\r\n"));
    }
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{extra}\r\n"
    );
    stream.write_all(head.as_bytes()).unwrap();
    // The proxy may answer and close before the whole body is sent.
    let _ = stream.write_all(body);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

fn post(port: u16, path: &str, body: &[u8]) -> (u16, String) {
    post_with(port, path, body, &[])
}

/// A POST whose body is sent in chunks, so that its length is not declared.
fn post_chunked(port: u16, path: &str, chunks: &[&[u8]]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    for chunk in chunks {
        if write!(stream, "{:x}\r\n", chunk.len()).is_err()
            || stream.write_all(chunk).is_err()
            || stream.write_all(b"\r\n").is_err()
        {
            break;
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The token rate limit counts the prompt: a prompt estimated above the
/// bucket is refused, though an empty body's estimate would have passed, and
/// a small one passes before and after it.
#[test]
fn token_rate_limit_counts_the_prompt() {
    let setup = setup();
    let small = chat("m1", "hello");
    let big = chat("m1", &"a".repeat(4000));

    let (status, body) = post(setup.port, "/tokens/small", small.as_bytes());
    assert_eq!(status, 200, "{body}");

    let (status, body) = post(setup.port, "/tokens/big", big.as_bytes());
    assert_eq!(status, 429, "{body}");
    assert!(body.contains("Token rate limit exceeded"), "{body}");
    assert!(
        setup.first.requests_to("/tokens/big").is_empty(),
        "a refused prompt reached the upstream"
    );

    let (status, body) = post(setup.port, "/tokens/small-again", small.as_bytes());
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        setup.first.requests_to("/tokens/small-again")[0].1,
        small.as_bytes()
    );
}

/// The token budget is checked on the estimate of the prompt.
#[test]
fn token_budget_counts_the_prompt() {
    let setup = setup();
    let small = chat("m1", "hello");
    let big = chat("m1", &"a".repeat(4000));

    let (status, body) = post(setup.port, "/budget/big", big.as_bytes());
    assert_eq!(status, 429, "{body}");
    assert!(body.contains("Token budget exhausted"), "{body}");
    assert!(setup.first.requests_to("/budget/big").is_empty());

    let (status, body) = post(setup.port, "/budget/small", small.as_bytes());
    assert_eq!(status, 200, "{body}");
}

/// A body over the route's `max-body-size` is refused with 413 before the
/// upstream is contacted.
#[test]
fn body_over_the_limit_is_refused() {
    let setup = setup();
    let big = chat("m1", &"a".repeat(2000));

    let (status, body) = post(setup.port, "/limited/big", big.as_bytes());
    assert_eq!(status, 413, "{body}");
    assert!(setup.first.requests_to("/limited/big").is_empty());

    let small = chat("m1", "hello");
    let (status, body) = post(setup.port, "/limited/small", small.as_bytes());
    assert_eq!(status, 200, "{body}");
}

/// Model routing reads the body's `model` when no header names one, and the
/// upstream it chooses receives the body byte for byte.
#[test]
fn model_routing_reads_the_body() {
    let setup = setup();
    // Spacing, escapes and non-ASCII text that a re-serialization would change.
    let body = "{ \"model\" : \"x\",\n  \"messages\": [{\"role\":\"user\",\
                \"content\":\"h\\u00e9llo \u{1F600} \\\"quoted\\\"\"}] }\n";

    let (status, answer) = post(setup.port, "/routed/body", body.as_bytes());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer, "second");
    let seen = setup.second.requests_to("/routed/body");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, body.as_bytes(), "the body was changed");
    assert!(setup.first.requests_to("/routed/body").is_empty());

    // Sent in chunks, without a declared length: read whole all the same.
    let (status, answer) = post_chunked(
        setup.port,
        "/routed/chunked",
        &[&body.as_bytes()[..10], &body.as_bytes()[10..]],
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer, "second");
    assert_eq!(
        setup.second.requests_to("/routed/chunked")[0].1,
        body.as_bytes()
    );

    // Another model, or none: the default upstream.
    let other = chat("y", "hello");
    let (status, answer) = post(setup.port, "/routed/other", other.as_bytes());
    assert_eq!((status, answer.as_str()), (200, "first"));
    assert_eq!(
        setup.first.requests_to("/routed/other")[0].1,
        other.as_bytes()
    );
}

/// The `x-model` header takes precedence over the body's `model`.
#[test]
fn model_header_takes_precedence() {
    let setup = setup();

    let body = chat("y", "hello");
    let (status, answer) = post_with(
        setup.port,
        "/routed/header",
        body.as_bytes(),
        &[("x-model", "x")],
    );
    assert_eq!((status, answer.as_str()), (200, "second"));
    assert_eq!(
        setup.second.requests_to("/routed/header")[0].1,
        body.as_bytes()
    );

    let body = chat("x", "hello");
    let (status, answer) = post_with(
        setup.port,
        "/routed/header-other",
        body.as_bytes(),
        &[("x-model-id", "y")],
    );
    assert_eq!((status, answer.as_str()), (200, "first"));
}
