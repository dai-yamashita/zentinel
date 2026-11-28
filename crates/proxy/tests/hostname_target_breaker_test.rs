//! The circuit breaker of a target written as `host:port`.
//!
//! The pool keeps one breaker per target as it is configured. A target that is
//! a hostname connects to the address the name resolves to, and the result of
//! a request used to be reported under that address, which names no breaker:
//! the breaker of a `localhost:<port>` target never counted a failure, so it
//! never opened, while the same backend written as `127.0.0.1:<port>` did.
//!
//! Each test runs the real binary against a backend that fails every request
//! and counts what reaches it. Once the breaker has opened, a request is
//! refused by the proxy and the count stops growing.
//!
//! `localhost` resolves to `::1` first on many systems, so the backend listens
//! on both loopback addresses (on the same port): which of them the proxy
//! dials, and whether it has to move on from a refused one, does not change
//! what is counted.

#![cfg(unix)]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BREAKER_OPENED_LOG: &str = "Circuit breaker opened";
const BACKEND_FAILURE_BODY: &str = "backend-failed";
/// Consecutive failures that open the breaker in these tests.
const FAILURE_THRESHOLD: usize = 3;
/// Requests sent once the breaker has opened.
const REQUESTS_AFTER_OPEN: usize = 5;

#[derive(Clone, Copy)]
enum Failure {
    /// Answer `500` and close.
    ServerError,
    /// Read the request and close the connection without answering.
    DropConnection,
}

/// A backend that fails every request in the same way, counting the requests
/// it receives.
struct Backend {
    port: u16,
    received: Arc<AtomicUsize>,
}

impl Backend {
    fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

/// A listener on `127.0.0.1` and, where the host has an IPv6 loopback, one on
/// `[::1]` with the same port.
fn bind_loopback() -> Vec<TcpListener> {
    for _ in 0..100 {
        let v4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = v4.local_addr().unwrap().port();
        match TcpListener::bind(("::1", port)) {
            Ok(v6) => return vec![v4, v6],
            // Taken on `::1`: try another port.
            Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
            // No IPv6 loopback: `localhost` cannot resolve to `::1` either.
            Err(e) => {
                eprintln!("note: no listener on [::1]:{port} ({e}); the backend is IPv4 only");
                return vec![v4];
            }
        }
    }
    panic!("no port is free on both loopback addresses");
}

fn spawn_backend(failure: Failure) -> Backend {
    let listeners = bind_loopback();
    let port = listeners[0].local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    for listener in listeners {
        let received = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let received = received.clone();
                std::thread::spawn(move || serve(stream, failure, &received));
            }
        });
    }
    Backend { port, received }
}

fn serve(mut stream: TcpStream, failure: Failure, received: &AtomicUsize) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut length = 0usize;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    received.fetch_add(1, Ordering::SeqCst);
    match failure {
        Failure::ServerError => {
            let _ = write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{BACKEND_FAILURE_BODY}",
                BACKEND_FAILURE_BODY.len()
            );
        }
        Failure::DropConnection => {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Proxy {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, port: u16, config: &str) -> Proxy {
        let path = dir.join("zentinel.kdl");
        std::fs::write(&path, config).unwrap();
        let log = dir.join("zentinel.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        let proxy = Proxy { child, port, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
        proxy
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Send one request with `method`; the status and body of the answer.
    ///
    /// The status is `0` when no answer could be read. The proxy can answer
    /// and close before it has read the body (when the upstream dropped the
    /// connection, or when it refuses the request), and on Linux the client's
    /// write or read then fails with a reset.
    fn request(&self, method: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let body = "{\"payload\":\"x\"}";
        let request = format!(
            "{method} /work HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        // One write, so the head is not sent in pieces. It can still fail when
        // the proxy has already answered and closed; the answer is read anyway.
        let _ = stream.write_all(request.as_bytes());
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let status = raw
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = raw.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        (status, body.to_string())
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether the log says the breaker named `breaker` opened.
fn breaker_opened(log: &str, breaker: &str) -> bool {
    log.lines()
        .any(|line| line.contains(BREAKER_OPENED_LOG) && line.contains(breaker))
}

fn config(port: u16, target: &str) -> String {
    format!(
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
        target "{target}"
        circuit-breaker {{
            failure-threshold {FAILURE_THRESHOLD}
            success-threshold 1
            timeout-seconds 300
        }}
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

/// Send requests that each fail at the backend until the breaker has opened,
/// then check that the proxy refuses the rest without contacting it.
///
/// `method` is one the proxy sends only once when the connection is dropped
/// (a POST), so a request is one failure of the target.
fn assert_breaker_opens(failure: Failure, method: &str, target: impl Fn(u16) -> String) {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(failure);
    let port = free_port();
    let target = target(backend.port);
    let proxy = Proxy::start(dir.path(), port, &config(port, &target));

    for n in 1..=FAILURE_THRESHOLD {
        let (status, body) = proxy.request(method);
        // `0`: the connection was reset before an answer could be read.
        assert!(
            status == 0 || status >= 500,
            "request {n} answered {status}: {body:?}"
        );
        if matches!(failure, Failure::ServerError) {
            assert_eq!(
                body, BACKEND_FAILURE_BODY,
                "request {n} did not reach the backend"
            );
        }
    }

    // The failures are reported as the requests end: the breaker opens
    // shortly after the last of them. A breaker is named `<upstream>/<target>`.
    let breaker = format!("backend/{target}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !breaker_opened(&proxy.log(), &breaker) {
        assert!(
            Instant::now() < deadline,
            "the breaker `{breaker}` did not open after {FAILURE_THRESHOLD} failures \
             (the backend received {}); log:\n{}",
            backend.received(),
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let received = backend.received();
    for n in 1..=REQUESTS_AFTER_OPEN {
        let (status, body) = proxy.request(method);
        // What reached the backend is checked below; `0` is a reset.
        assert!(
            (status == 0 || status >= 500) && body != BACKEND_FAILURE_BODY,
            "request {n} after the breaker opened was not refused by the proxy: \
             {status} {body:?}"
        );
    }
    assert_eq!(
        backend.received(),
        received,
        "requests reached `{target}` after its breaker opened; log:\n{}",
        proxy.log()
    );
}

/// A `500` is reported when the request ends.
#[test]
fn hostname_target_opens_its_breaker_on_error_responses() {
    assert_breaker_opens(Failure::ServerError, "GET", |port| {
        format!("localhost:{port}")
    });
}

/// A connection the backend drops is reported when the error happens.
#[test]
fn hostname_target_opens_its_breaker_on_dropped_connections() {
    assert_breaker_opens(Failure::DropConnection, "POST", |port| {
        format!("localhost:{port}")
    });
}

/// The same backend written as an address, which already worked.
#[test]
fn address_target_opens_its_breaker_on_error_responses() {
    assert_breaker_opens(Failure::ServerError, "GET", |port| {
        format!("127.0.0.1:{port}")
    });
}

/// The same backend written as an address, which already worked.
#[test]
fn address_target_opens_its_breaker_on_dropped_connections() {
    assert_breaker_opens(Failure::DropConnection, "POST", |port| {
        format!("127.0.0.1:{port}")
    });
}
