//! Header values an agent receives, for values with bytes outside visible
//! ASCII.
//!
//! A header value is bytes, not necessarily text. The agent is handed
//! strings, so a value that is valid UTF-8 (`café`) arrives as that
//! text, and one that is not (a lone `0xFF`) arrives with each byte as the
//! Unicode code point of the same value (U+00FF). Neither arrives as an
//! empty string. The upstream and the client keep seeing the original
//! bytes.
//!
//! The mapping is not reversible: `caf\xe9` and `caf\xc3\xa9` both arrive
//! as `café`. An agent that writes such a value back in a header change
//! therefore makes the upstream, or the client, receive the UTF-8 bytes of
//! the string, not the original bytes (`Set` replaces the header, `Add`
//! appends a second one next to it).
//!
//! Runs the real binary against a backend that records each request it
//! receives and an in-test v2 agent that records the headers of each
//! request-headers and response-headers event.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestHeadersEvent, ResponseHeadersEvent,
};

type Headers = HashMap<String, Vec<String>>;

/// The backend's listener, kept bound so that its port cannot be taken
/// before the backend uses it, and a free port for the proxy to listen on
/// (it is written into the configuration, so it can only be checked here).
fn bind_backend_and_pick_proxy_port(range: std::ops::Range<u16>) -> (TcpListener, u16) {
    let mut free = range
        .clone()
        .filter_map(|port| TcpListener::bind(("127.0.0.1", port)).ok());
    let backend = free.next().expect("a free port");
    let proxy = free
        .next()
        .unwrap_or_else(|| panic!("two free ports in {range:?}"));
    let proxy_port = proxy.local_addr().unwrap().port();
    (backend, proxy_port)
}

/// Whether `haystack` contains `needle` as a contiguous run of bytes.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The raw values of every `name` header line in `head`, in order.
fn header_line_values(head: &[u8], name: &str) -> Vec<Vec<u8>> {
    head.split(|&byte| byte == b'\n')
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|&byte| byte == b':')?;
            let (line_name, rest) = line.split_at(colon);
            line_name
                .eq_ignore_ascii_case(name.as_bytes())
                .then(|| rest[1..].trim_ascii().to_vec())
        })
        .collect()
}

/// The header values the backend sends on every response, as raw bytes: one
/// valid UTF-8 value, one that is not UTF-8, and a plain one.
const BACKEND_UTF8: &[u8] = b"X-Backend-Utf8: caf\xc3\xa9\r\n";
const BACKEND_INVALID: &[u8] = b"X-Backend-Invalid: a\xffb\r\n";
const BACKEND_PLAIN: &[u8] = b"X-Backend-Plain: plain\r\n";

/// A backend answering 200 to everything, recording each request's head
/// (raw bytes) in `seen`.
fn spawn_backend(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = Vec::new();
                let mut line = Vec::new();
                while reader.read_until(b'\n', &mut line).is_ok()
                    && line != b"\r\n"
                    && !line.is_empty()
                {
                    head.extend_from_slice(&line);
                    line.clear();
                }
                seen.lock().unwrap().push(head);
                let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n".to_vec();
                response.extend_from_slice(BACKEND_UTF8);
                response.extend_from_slice(BACKEND_INVALID);
                response.extend_from_slice(BACKEND_PLAIN);
                response.extend_from_slice(b"Connection: close\r\n\r\nok\n");
                let _ = stream.write_all(&response);
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

/// A response as raw header lines: the values are bytes.
struct Response {
    status: u16,
    head: Vec<u8>,
}

/// Sends `GET path` with `extra_headers` (raw bytes, each line ending in
/// CRLF) and returns what came back.
fn request(port: u16, path: &str, extra_headers: &[u8]) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut raw_request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n").into_bytes();
    raw_request.extend_from_slice(extra_headers);
    raw_request.extend_from_slice(b"\r\n");
    stream.write_all(&raw_request).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = raw[..split].to_vec();
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    Response { status, head }
}

/// The headers the test agent writes back, by name (lowercase): a `Set` of
/// each in `set` and an `Add` of each in `add`, with the value the agent
/// received, for every event that carries the header.
#[derive(Clone, Copy)]
struct WriteBack<'a> {
    set: &'a [&'a str],
    add: &'a [&'a str],
}

/// The agent that writes nothing back.
const NO_WRITE_BACK: WriteBack<'static> = WriteBack { set: &[], add: &[] };

/// Records the headers of every request-headers and response-headers event,
/// and writes back the headers it is told to.
#[derive(Clone)]
struct Recorder {
    requests: Arc<Mutex<Vec<Headers>>>,
    responses: Arc<Mutex<Vec<Headers>>>,
    set: Vec<String>,
    add: Vec<String>,
}

impl Recorder {
    fn new(write_back: WriteBack<'_>) -> Self {
        let names = |names: &[&str]| names.iter().map(|name| name.to_string()).collect();
        Recorder {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
            set: names(write_back.set),
            add: names(write_back.add),
        }
    }

    /// The header changes that write back what `headers` carries.
    fn write_back_ops(&self, headers: &Headers) -> Vec<HeaderOp> {
        let first = |name: &String| Some((name.clone(), headers.get(name)?.first()?.clone()));
        let sets = self
            .set
            .iter()
            .filter_map(first)
            .map(|(name, value)| HeaderOp::Set { name, value });
        let adds = self
            .add
            .iter()
            .filter_map(first)
            .map(|(name, value)| HeaderOp::Add { name, value });
        sets.chain(adds).collect()
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::ResponseHeaders)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let response = self
            .write_back_ops(&event.headers)
            .into_iter()
            .fold(AgentResponse::default_allow(), |response, op| {
                response.add_request_header(op)
            });
        self.requests.lock().unwrap().push(event.headers);
        response
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let response = self
            .write_back_ops(&event.headers)
            .into_iter()
            .fold(AgentResponse::default_allow(), |response, op| {
                response.add_response_header(op)
            });
        self.responses.lock().unwrap().push(event.headers);
        response
    }
}

struct Setup {
    port: u16,
    recorder: Recorder,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

/// Starts the proxy, a backend and the agent, which writes back the headers
/// `write_back` names, and nothing else.
fn setup(ports: std::ops::Range<u16>, write_back: WriteBack<'_>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("recorder.sock");
    let recorder = Recorder::new(write_back);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("recorder", socket.clone(), Box::new(recorder.clone()));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (backend_listener, port) = bind_backend_and_pick_proxy_port(ports);
    let backend = backend_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    spawn_backend(backend_listener, seen.clone());
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
    agent "recorder" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "response_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "recorder" {{
        type "agent"
        agent "recorder"
        failure-mode "closed"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "recorder"
        policies {{ failure-mode "closed"; }}
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
    // Wait until the agent is connected and consulted on the response.
    let deadline = Instant::now() + Duration::from_secs(10);
    while recorder.responses.lock().unwrap().is_empty() {
        let probe = request(port, "/probe", b"");
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted (status {})",
            probe.status
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        recorder,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// The values of `name` in the one recorded event whose `marker` header is
/// `marker_value`.
fn recorded<'a>(events: &'a [Headers], marker_value: &str, name: &str) -> &'a [String] {
    let matching: Vec<&Headers> = events
        .iter()
        .filter(|headers| {
            headers
                .get("x-case")
                .is_some_and(|values| values.iter().any(|value| value == marker_value))
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "events marked {marker_value}: {events:?}"
    );
    values(matching[0], name)
}

/// The values of header `name` in `headers`.
fn values<'a>(headers: &'a Headers, name: &str) -> &'a [String] {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} in {headers:?}"))
}

/// A request header value that is valid UTF-8 reaches the agent as that
/// text, and one that is not valid UTF-8 reaches it byte by byte as
/// U+0000..U+00FF; neither is an empty string. The upstream still receives
/// the original bytes.
#[test]
fn agent_receives_request_header_values_with_non_ascii_bytes() {
    let setup = setup(19770..19775, NO_WRITE_BACK);
    let resp = request(
        setup.port,
        "/req",
        b"X-Case: req\r\nX-Name: caf\xc3\xa9\r\nX-Invalid: a\xffb\r\nX-Plain: plain\r\n",
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.requests.lock().unwrap().clone();
    assert_eq!(
        recorded(&events, "req", "x-name"),
        ["caf\u{e9}"],
        "{events:?}"
    );
    assert_eq!(
        recorded(&events, "req", "x-invalid"),
        ["a\u{ff}b"],
        "{events:?}"
    );
    assert_eq!(recorded(&events, "req", "x-plain"), ["plain"], "{events:?}");

    // The upstream was sent the original bytes, not the agent's text.
    let seen = setup.seen.lock().unwrap();
    let upstream = seen
        .iter()
        .find(|head| contains_bytes(head, b"/req"))
        .expect("the upstream saw the request");
    assert!(contains_bytes(upstream, b"caf\xc3\xa9"), "{upstream:?}");
    assert!(contains_bytes(upstream, b"a\xffb"), "{upstream:?}");
}

/// The same for the headers of the upstream's response. The client still
/// receives the original bytes.
#[test]
fn agent_receives_response_header_values_with_non_ascii_bytes() {
    let setup = setup(19775..19780, NO_WRITE_BACK);
    // `setup` has already consulted the agent on its probes: only the
    // event recorded after this request belongs to it.
    let before = setup.recorder.responses.lock().unwrap().len();
    let resp = request(setup.port, "/resp", b"");
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.responses.lock().unwrap().clone();
    let [headers] = &events[before..] else {
        panic!(
            "one response event for the request: {:?}",
            &events[before..]
        );
    };
    assert_eq!(
        values(headers, "x-backend-utf8"),
        ["caf\u{e9}"],
        "{headers:?}"
    );
    assert_eq!(
        values(headers, "x-backend-invalid"),
        ["a\u{ff}b"],
        "{headers:?}"
    );
    assert_eq!(values(headers, "x-backend-plain"), ["plain"], "{headers:?}");

    // The client was sent the original bytes.
    assert!(
        contains_bytes(&resp.head, b"caf\xc3\xa9"),
        "{:?}",
        resp.head
    );
    assert!(contains_bytes(&resp.head, b"a\xffb"), "{:?}", resp.head);
}

/// The mapping is not reversible: `caf\xe9` and `caf\xc3\xa9` both reach the
/// agent as `café`. An agent that writes that string back with `Set` makes
/// the upstream receive its UTF-8 bytes, `caf\xc3\xa9`, whichever of the two
/// the client sent. A header the agent does not write back keeps its
/// original bytes.
#[test]
fn agent_writing_back_a_request_header_value_sends_it_upstream_as_utf8() {
    let setup = setup(
        19796..19801,
        WriteBack {
            set: &["x-latin1", "x-utf8"],
            add: &[],
        },
    );
    let resp = request(
        setup.port,
        "/write-back",
        b"X-Case: wb\r\nX-Latin1: caf\xe9\r\nX-Utf8: caf\xc3\xa9\r\nX-Kept: a\xffb\r\n",
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    // Different bytes from the client, the same string for the agent.
    let events = setup.recorder.requests.lock().unwrap().clone();
    assert_eq!(
        recorded(&events, "wb", "x-latin1"),
        ["caf\u{e9}"],
        "{events:?}"
    );
    assert_eq!(
        recorded(&events, "wb", "x-utf8"),
        ["caf\u{e9}"],
        "{events:?}"
    );

    let seen = setup.seen.lock().unwrap();
    let upstream = seen
        .iter()
        .find(|head| head.starts_with(b"GET /write-back "))
        .expect("the upstream saw the request");
    // The same bytes for the upstream: the UTF-8 of the string. The byte
    // the client sent as 0xE9 is not forwarded.
    assert_eq!(
        header_line_values(upstream, "x-latin1"),
        [b"caf\xc3\xa9".to_vec()],
        "{upstream:?}"
    );
    assert_eq!(
        header_line_values(upstream, "x-utf8"),
        [b"caf\xc3\xa9".to_vec()],
        "{upstream:?}"
    );
    // Not written back: the original bytes.
    assert_eq!(
        header_line_values(upstream, "x-kept"),
        [b"a\xffb".to_vec()],
        "{upstream:?}"
    );
}

/// The same for the headers of the upstream's response: an agent that writes
/// back the string `aÿb` it received for `a\xffb` makes the client receive
/// its UTF-8 bytes, `a\xc3\xbfb`. A value that was UTF-8 already is
/// unchanged.
#[test]
fn agent_writing_back_a_response_header_value_sends_it_to_the_client_as_utf8() {
    let setup = setup(
        19801..19806,
        WriteBack {
            set: &["x-backend-utf8", "x-backend-invalid"],
            add: &[],
        },
    );
    // `setup` has already consulted the agent on its probes: only the
    // event recorded after this request belongs to it.
    let before = setup.recorder.responses.lock().unwrap().len();
    let resp = request(setup.port, "/write-back", b"");
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.responses.lock().unwrap().clone();
    let [headers] = &events[before..] else {
        panic!(
            "one response event for the request: {:?}",
            &events[before..]
        );
    };
    assert_eq!(
        values(headers, "x-backend-utf8"),
        ["caf\u{e9}"],
        "{headers:?}"
    );
    assert_eq!(
        values(headers, "x-backend-invalid"),
        ["a\u{ff}b"],
        "{headers:?}"
    );

    assert_eq!(
        header_line_values(&resp.head, "x-backend-utf8"),
        [b"caf\xc3\xa9".to_vec()],
        "{:?}",
        resp.head
    );
    assert_eq!(
        header_line_values(&resp.head, "x-backend-invalid"),
        [b"a\xc3\xbfb".to_vec()],
        "{:?}",
        resp.head
    );
    // Not written back: the original value.
    assert_eq!(
        header_line_values(&resp.head, "x-backend-plain"),
        [b"plain".to_vec()],
        "{:?}",
        resp.head
    );
    assert!(!resp.head.contains(&0xff), "{:?}", resp.head);
}

/// With `Add` the agent's string is appended next to the header the client
/// sent, which is not touched: the upstream receives the original bytes and,
/// after them, the UTF-8 bytes of the string.
#[test]
fn agent_adding_a_request_header_value_sends_the_string_as_utf8_beside_the_original() {
    let setup = setup(
        19780..19785,
        WriteBack {
            set: &[],
            add: &["x-latin1"],
        },
    );
    let resp = request(
        setup.port,
        "/add-back",
        b"X-Case: add\r\nX-Latin1: caf\xe9\r\n",
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.requests.lock().unwrap().clone();
    assert_eq!(
        recorded(&events, "add", "x-latin1"),
        ["caf\u{e9}"],
        "{events:?}"
    );

    let seen = setup.seen.lock().unwrap();
    let upstream = seen
        .iter()
        .find(|head| head.starts_with(b"GET /add-back "))
        .expect("the upstream saw the request");
    assert_eq!(
        header_line_values(upstream, "x-latin1"),
        [b"caf\xe9".to_vec(), b"caf\xc3\xa9".to_vec()],
        "{upstream:?}"
    );
}

/// The same for the headers of the upstream's response: the client receives
/// `a\xffb` as the upstream sent it and, after it, `a\xc3\xbfb`.
#[test]
fn agent_adding_a_response_header_value_sends_the_string_as_utf8_beside_the_original() {
    let setup = setup(
        19785..19790,
        WriteBack {
            set: &[],
            add: &["x-backend-invalid"],
        },
    );
    // `setup` has already consulted the agent on its probes: only the
    // event recorded after this request belongs to it.
    let before = setup.recorder.responses.lock().unwrap().len();
    let resp = request(setup.port, "/add-back", b"");
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.responses.lock().unwrap().clone();
    let [headers] = &events[before..] else {
        panic!(
            "one response event for the request: {:?}",
            &events[before..]
        );
    };
    assert_eq!(
        values(headers, "x-backend-invalid"),
        ["a\u{ff}b"],
        "{headers:?}"
    );

    assert_eq!(
        header_line_values(&resp.head, "x-backend-invalid"),
        [b"a\xffb".to_vec(), b"a\xc3\xbfb".to_vec()],
        "{:?}",
        resp.head
    );
}
