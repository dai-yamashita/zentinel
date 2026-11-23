//! A request that an HTTP/2 upstream says it did not process is sent again,
//! whatever its method.
//!
//! RFC 9113 section 8.7: a stream reset with REFUSED_STREAM, and a stream
//! with an identifier above the last stream id of a GOAWAY, were closed
//! before any processing took place. Pingora's HTTP/2 client marks the error
//! retryable, and the proxy sends the request again, a `POST` included, as
//! long as its body can still be replayed. A body larger than the retry
//! buffer cannot, so the request is not sent again. The route's `max-attempts`
//! bounds these retries as it does any other: a request that has made its
//! attempts is not sent again, whatever its method.
//!
//! The tests run the real binary against an HTTP/2 server (the `h2` crate) on
//! a plain socket, reached with `h2c #true`. Where a test needs frames the
//! `h2` crate does not send (GOAWAY without closing the connection, closing
//! it without GOAWAY), the first connection is played by hand.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Larger than the 64 KiB retry buffer the proxy uses by default.
const LARGE_BODY_BYTES: usize = 128 * 1024;

/// The ports of the proxy and of its metrics listener come from this range,
/// which no other test uses.
const PORTS: std::ops::Range<u16> = 23410..23450;
static NEXT_PORT: AtomicU16 = AtomicU16::new(PORTS.start);

/// A port of [`PORTS`] that nothing listens on.
fn next_port() -> u16 {
    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        assert!(PORTS.contains(&port), "no free port left in {PORTS:?}");
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// How often a proxy is started again, on new ports, when another process
/// holds one of its ports.
const START_ATTEMPTS: usize = 3;

/// Why a proxy did not start.
enum StartFailure {
    /// Another process holds one of its ports; the log says so.
    PortTaken(String),
    /// Anything else.
    Other(String),
}

/// Whether `log` shows that the proxy bound its metrics port and started to
/// serve on its HTTP port. The HTTP listener binds when the service starts,
/// and logs nothing when it has bound.
fn listens(log: &str, port: u16, metrics_port: u16) -> bool {
    let has_line = |parts: &[&str]| {
        log.lines()
            .any(|line| parts.iter().all(|part| line.contains(part)))
    };
    has_line(&[
        "Metrics server listening",
        &format!("127.0.0.1:{metrics_port}"),
    ]) && has_line(&["HTTP listening on", &format!("127.0.0.1:{port}")])
        && has_line(&["Starting service"])
}

/// What the log says when another process holds a port of the proxy.
fn port_taken(log: &str) -> Option<&'static str> {
    if log.contains("Failed to bind metrics server") {
        Some("the metrics port is taken")
    } else if log.contains("is in use, will try again") {
        Some("the HTTP port is taken")
    } else {
        None
    }
}

/// What the backend does to the first request or connection it is sent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// It reads the request, body included, and resets its stream with
    /// REFUSED_STREAM.
    RefuseStream,
    /// It does as [`Fault::RefuseStream`] does for the first request, and for
    /// every request after it.
    RefuseEveryStream,
    /// On the first connection it answers the first request header with
    /// GOAWAY(NO_ERROR) and a last stream id of 0, so that request, which is
    /// on stream 1, was not processed. It keeps the connection open: closing
    /// it at once can reset the connection before the proxy has read the
    /// GOAWAY, and the proxy then sees an I/O error.
    GoAway,
    /// On the first connection it reads the request, body included, and
    /// closes the connection without GOAWAY or RST_STREAM: the request may
    /// have been processed.
    DropConnection,
}

/// What the backend saw.
#[derive(Default)]
struct State {
    /// Requests it read in full and did not send a GOAWAY for.
    accepted: AtomicUsize,
    /// GOAWAY frames it sent.
    go_aways: AtomicUsize,
    /// The size of the body of each request it answered.
    answered: Mutex<Vec<usize>>,
}

/// The server side of the first connection for [`Fault::GoAway`] and
/// [`Fault::DropConnection`], written by hand because the `h2` crate closes a
/// connection as soon as it has sent GOAWAY, and has no way to close one
/// without a frame. It answers the client's SETTINGS and reads frames until
/// the client closes the connection or, for [`Fault::DropConnection`], until
/// the request has ended. For [`Fault::GoAway`] it sends GOAWAY once, when a
/// HEADERS frame arrives.
async fn serve_first_connection_by_hand(
    mut socket: tokio::net::TcpStream,
    fault: Fault,
    state: Arc<State>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MAX_FRAME_BYTES: usize = 1 << 20;
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const SETTINGS: u8 = 0x4;
    const END_STREAM: u8 = 0x1;
    const ACK: u8 = 0x1;
    // Length 0, type SETTINGS, no flags, stream 0.
    const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, SETTINGS, 0, 0, 0, 0, 0];
    const SETTINGS_ACK: [u8; 9] = [0, 0, 0, SETTINGS, ACK, 0, 0, 0, 0];
    // Length 8, type GOAWAY, no flags, stream 0; last stream id 0, NO_ERROR.
    const GOAWAY: [u8; 17] = [0, 0, 8, 0x7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let mut preface = [0u8; 24];
    if socket.read_exact(&mut preface).await.is_err()
        || socket.write_all(&EMPTY_SETTINGS).await.is_err()
    {
        return;
    }
    let mut sent_go_away = false;
    loop {
        let mut header = [0u8; 9];
        if socket.read_exact(&mut header).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        if length > MAX_FRAME_BYTES {
            return;
        }
        let mut payload = vec![0u8; length];
        if socket.read_exact(&mut payload).await.is_err() {
            return;
        }
        let (kind, flags) = (header[3], header[4]);
        if fault == Fault::DropConnection
            && (kind == HEADERS || kind == DATA)
            && flags & END_STREAM != 0
        {
            // The request has ended. Returning closes the socket.
            state.accepted.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if kind == SETTINGS && flags & ACK == 0 {
            if socket.write_all(&SETTINGS_ACK).await.is_err() {
                return;
            }
        } else if fault == Fault::GoAway && kind == HEADERS && !sent_go_away {
            sent_go_away = true;
            // Counted before the write: once the proxy has read the frame,
            // the test may look at the count.
            state.go_aways.fetch_add(1, Ordering::SeqCst);
            if socket.write_all(&GOAWAY).await.is_err() {
                return;
            }
        }
    }
}

struct Backend {
    port: u16,
    state: Arc<State>,
}

/// An HTTP/2 backend that treats its first request or connection as `fault`
/// says and answers every other request with a 200 and the body `ok`.
fn spawn_backend(fault: Fault) -> Backend {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let state = Arc::new(State::default());
    let shared = state.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let mut connections = 0usize;
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        continue;
                    };
                    let first_connection = connections == 0;
                    connections += 1;
                    let state = shared.clone();
                    tokio::spawn(async move {
                        if first_connection
                            && matches!(fault, Fault::GoAway | Fault::DropConnection)
                        {
                            serve_first_connection_by_hand(socket, fault, state).await;
                            return;
                        }
                        let Ok(mut connection) = h2::server::handshake(socket).await else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            let number = state.accepted.fetch_add(1, Ordering::SeqCst);
                            let state = state.clone();
                            tokio::spawn(async move {
                                let mut body = request.into_body();
                                let mut length = 0usize;
                                while let Some(Ok(chunk)) = body.data().await {
                                    length += chunk.len();
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                }
                                if fault == Fault::RefuseEveryStream
                                    || (fault == Fault::RefuseStream && number == 0)
                                {
                                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                                    return;
                                }
                                state.answered.lock().unwrap().push(length);
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-length", 2)
                                    .body(())
                                    .unwrap();
                                if let Ok(mut out) = respond.send_response(response, false) {
                                    let _ = out.send_data(bytes::Bytes::from_static(b"ok"), true);
                                }
                            });
                        }
                    });
                }
            });
    });
    Backend { port, state }
}

impl Backend {
    fn accepted(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    fn go_aways(&self) -> usize {
        self.state.go_aways.load(Ordering::SeqCst)
    }

    fn answered(&self) -> Vec<usize> {
        self.state.answered.lock().unwrap().clone()
    }
}

struct Proxy {
    child: Child,
    port: u16,
    metrics_port: u16,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, backend: &Backend) -> Proxy {
        Proxy::start_with(dir, backend, "")
    }

    /// Starts the proxy with `retry_policy` in the route, a `retry-policy`
    /// block or nothing.
    fn start_with(dir: &Path, backend: &Backend, retry_policy: &str) -> Proxy {
        Proxy::launch(dir, |port, metrics_port| {
            config(port, metrics_port, backend.port, retry_policy)
        })
    }

    /// Starts the proxy on two free ports, `make_config` writing its
    /// configuration for them. If another process takes one of the ports
    /// between the check and the proxy's bind, the proxy says so in its log;
    /// it is stopped and started again on new ports.
    fn launch(dir: &Path, make_config: impl Fn(u16, u16) -> String) -> Proxy {
        let mut taken = Vec::new();
        for attempt in 0..START_ATTEMPTS {
            let (port, metrics_port) = (next_port(), next_port());
            let config = make_config(port, metrics_port);
            match Proxy::spawn(dir, attempt, port, metrics_port, &config) {
                Ok(proxy) => return proxy,
                Err(StartFailure::PortTaken(log)) => taken.push(log),
                Err(StartFailure::Other(why)) => panic!("{why}"),
            }
        }
        panic!(
            "every start found a port taken by another process; logs:\n{}",
            taken.join("\n--\n")
        );
    }

    /// Starts the proxy and waits until its own log says that it listens on
    /// both ports: a connection that succeeds could be one to another
    /// process that holds the port.
    fn spawn(
        dir: &Path,
        attempt: usize,
        port: u16,
        metrics_port: u16,
        config: &str,
    ) -> Result<Proxy, StartFailure> {
        let path = dir.join(format!("zentinel-{attempt}.kdl"));
        std::fs::write(&path, config).unwrap();
        let log = dir.join(format!("zentinel-{attempt}.log"));
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        // Dropping it, on a failure below too, stops this child.
        let mut proxy = Proxy {
            child,
            port,
            metrics_port,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let log = proxy.log();
            if let Some(why) = port_taken(&log) {
                return Err(StartFailure::PortTaken(format!("{why}:\n{log}")));
            }
            if let Ok(Some(status)) = proxy.child.try_wait() {
                return Err(StartFailure::Other(format!(
                    "the proxy exited ({status}) before it listened; log:\n{log}"
                )));
            }
            if listens(&log, port, metrics_port)
                && TcpStream::connect(("127.0.0.1", port)).is_ok()
                && TcpStream::connect(("127.0.0.1", metrics_port)).is_ok()
            {
                // Read after the connections: a bind that failed is in the log
                // by now.
                let log = proxy.log();
                return match port_taken(&log) {
                    Some(why) => Err(StartFailure::PortTaken(format!("{why}:\n{log}"))),
                    None => Ok(proxy),
                };
            }
            if Instant::now() >= deadline {
                return Err(StartFailure::Other(format!(
                    "the proxy never listened; log:\n{log}"
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits for `text` to appear in the log; the log is written by another
    /// process, so it may trail the answer the client got.
    fn wait_for_log(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.log().contains(text) {
            assert!(
                Instant::now() < deadline,
                "the log never said {text:?}; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The value of `zentinel_upstream_retries_refused_total` for `reason`, 0
    /// if there is no such series. The metrics answer must be a 200: a failed
    /// read is not a 0.
    fn retries_refused(&self, reason: &str) -> u64 {
        let mut stream = TcpStream::connect(("127.0.0.1", self.metrics_port)).unwrap_or_else(|e| {
            panic!(
                "no connection to the metrics port: {e}; log:\n{}",
                self.log()
            )
        });
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET /metrics HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = Vec::new();
        if let Err(e) = stream.read_to_end(&mut raw) {
            panic!("reading the metrics failed: {e}; log:\n{}", self.log());
        }
        let raw = String::from_utf8_lossy(&raw);
        assert!(
            raw.starts_with("HTTP/1.1 200"),
            "the metrics answer was {:?}; log:\n{}",
            raw.lines().next(),
            self.log()
        );
        let series = format!("zentinel_upstream_retries_refused_total{{reason=\"{reason}\"}}");
        raw.lines()
            .find_map(|line| line.strip_prefix(series.as_str()))
            .and_then(|value| value.trim().parse::<f64>().ok())
            .map_or(0, |value| value as u64)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config(port: u16, metrics_port: u16, backend: u16, retry_policy: &str) -> String {
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
        target "127.0.0.1:{backend}"
        h2c #true
        // The breaker must not open before max-attempts stops the retries.
        circuit-breaker {{
            failure-threshold 1000
            success-threshold 1
            timeout-seconds 300
        }}
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        {retry_policy}
    }}
}}
observability {{
    metrics {{
        enabled #true
        address "127.0.0.1:{metrics_port}"
        path "/metrics"
    }}
}}
"#
    )
}

/// A `retry-policy` with `max_attempts` and a short backoff.
fn retry_policy(max_attempts: u32) -> String {
    format!(
        r#"retry-policy {{
            max-attempts {max_attempts}
            backoff "1ms"
            max-backoff "1ms"
        }}"#
    )
}

/// Sends one request with a body of `body_len` bytes over HTTP/1.1 and returns
/// the status of the answer, 0 if there was none, and its body.
fn send(port: u16, method: &str, body_len: usize) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let head = format!(
        "{method} /item HTTP/1.1\r\nHost: a.example\r\nContent-Length: {body_len}\r\n\
         Connection: close\r\n\r\n"
    );
    // The proxy may answer before the whole body is written; that is not
    // what these tests look at.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&vec![b'a'; body_len]);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw);
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

#[test]
fn a_post_on_a_stream_the_upstream_refused_is_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::RefuseStream);
    let proxy = Proxy::start(dir.path(), &backend);

    let (status, body) = send(proxy.port, "POST", 6);

    assert_eq!(
        (status, body.as_str()),
        (200, "ok"),
        "a POST on a stream the upstream reset with REFUSED_STREAM was not sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(backend.accepted(), 2);
    assert_eq!(backend.answered(), vec![6]);
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
    assert_eq!(proxy.retries_refused("retry_buffer_truncated"), 0);
}

#[test]
fn a_post_the_upstream_did_not_process_before_goaway_is_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::GoAway);
    let proxy = Proxy::start(dir.path(), &backend);

    let (status, body) = send(proxy.port, "POST", 6);

    assert_eq!(
        (status, body.as_str()),
        (200, "ok"),
        "a POST the upstream answered with GOAWAY(NO_ERROR) was not sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(backend.go_aways(), 1);
    assert_eq!(backend.accepted(), 1);
    assert_eq!(backend.answered(), vec![6]);
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
    assert_eq!(proxy.retries_refused("retry_buffer_truncated"), 0);
}

/// The upstream read the request and closed the connection without a word, so
/// it may have processed it: nothing says it did not. The error is a
/// `ReadError`, which `error_while_proxy` does not retry at all, so this does
/// not reach the method check; it pins that nothing marks such a request as
/// unprocessed.
#[test]
fn a_post_on_a_connection_the_upstream_dropped_after_reading_it_is_not_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::DropConnection);
    let proxy = Proxy::start(dir.path(), &backend);

    let (status, _) = send(proxy.port, "POST", 6);

    assert_eq!(
        backend.accepted(),
        1,
        "a POST the upstream had read was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    assert!(backend.answered().is_empty());
}

/// The upstream did not process the request, but its body was larger than the
/// retry buffer, so it cannot be sent a second time. The backend reads the
/// whole body before it refuses the stream: by then the proxy has read it all
/// from the client and the buffer has overflowed.
#[test]
fn a_refused_post_whose_body_exceeded_the_retry_buffer_is_not_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::RefuseStream);
    let proxy = Proxy::start(dir.path(), &backend);

    let (status, _) = send(proxy.port, "POST", LARGE_BODY_BYTES);

    assert_eq!(
        backend.accepted(),
        1,
        "a request whose body could not be replayed was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    proxy.wait_for_log("retry_buffer_truncated");
    assert_eq!(proxy.retries_refused("retry_buffer_truncated"), 1);
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
}

/// The route's `max-attempts` bounds the retries of a request the upstream
/// did not process, as it does the others, although the method is not looked
/// at for them. The backend refuses every stream, so each attempt is sent
/// again until `max-attempts` stops it.
fn check_refused_post_stops_at_max_attempts(max_attempts: u32) {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::RefuseEveryStream);
    let proxy = Proxy::start_with(dir.path(), &backend, &retry_policy(max_attempts));

    let (status, _) = send(proxy.port, "POST", 6);

    assert_eq!(
        backend.accepted(),
        max_attempts as usize,
        "with max-attempts {max_attempts} the upstream was sent a POST it kept refusing a \
         different number of times; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    assert!(backend.answered().is_empty());
    proxy.wait_for_log("Not retrying a request that may have been sent to the upstream");
    assert_eq!(
        proxy.retries_refused("max_attempts"),
        1,
        "log:\n{}",
        proxy.log()
    );
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
    assert_eq!(proxy.retries_refused("retry_buffer_truncated"), 0);
}

#[test]
fn a_refused_post_is_sent_again_until_the_route_max_attempts() {
    check_refused_post_stops_at_max_attempts(3);
}

/// `max-attempts 1` asks for no retry at all, for a refused stream too.
#[test]
fn a_refused_post_is_not_sent_again_when_the_route_max_attempts_is_1() {
    check_refused_post_stops_at_max_attempts(1);
}

/// The limit does not stop a retry before it is reached: the backend refuses
/// the first stream only, and the second attempt is the last one allowed.
#[test]
fn a_refused_post_is_sent_again_when_the_route_has_an_attempt_left() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Fault::RefuseStream);
    let proxy = Proxy::start_with(dir.path(), &backend, &retry_policy(2));

    let (status, body) = send(proxy.port, "POST", 6);

    assert_eq!(
        (status, body.as_str()),
        (200, "ok"),
        "a refused POST was not sent again with an attempt left; log:\n{}",
        proxy.log()
    );
    assert_eq!(backend.accepted(), 2);
    assert_eq!(backend.answered(), vec![6]);
    assert_eq!(proxy.retries_refused("max_attempts"), 0);
}
