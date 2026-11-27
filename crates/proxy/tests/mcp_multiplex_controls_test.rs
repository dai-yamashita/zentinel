//! A tool call on a route that fronts several MCP servers gets the controls a
//! call on a plain MCP route gets: the route's body agents inspect it, and
//! rate limits keyed on the MCP tool apply. The call used to be rewritten and
//! forwarded before either ran.
//! Runs the real binary with a v2 agent and an MCP server stub.

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
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

fn free_port(range: std::ops::Range<u16>) -> u16 {
    range
        .clone()
        .find(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok())
        .unwrap_or_else(|| panic!("a free port in {range:?}"))
}

/// An MCP server stub: answers `initialize` with a session, any other request
/// with a result, and records every request body it is sent.
fn spawn_mcp_server(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut length = 0usize;
                    let mut line = String::new();
                    let mut got_request = false;
                    while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty()
                    {
                        got_request = true;
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse().unwrap_or(0);
                            }
                        }
                        line.clear();
                    }
                    if !got_request {
                        return;
                    }
                    let mut body = vec![0; length];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    let body = String::from_utf8_lossy(&body).into_owned();
                    let id = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.get("id").cloned())
                        .unwrap_or(serde_json::Value::Null);
                    let initialize = body.contains("\"initialize\"");
                    seen.lock().unwrap().push(body);
                    let reply = if initialize {
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":{
                            "protocolVersion":"2026-07-28","capabilities":{"tools":{}},
                            "serverInfo":{"name":"stub","version":"1"}}})
                    } else {
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":{
                            "content":[{"type":"text","text":"ok"}]}})
                    }
                    .to_string();
                    if write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Mcp-Session-Id: stub-session\r\nContent-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    )
                    .is_err()
                    {
                        return;
                    }
                }
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

/// Status of a `tools/call` for `tool` with `argument`.
fn call_tool(port: u16, tool: &str, argument: &str) -> (u16, String) {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": tool, "arguments": {"q": argument}}
    })
    .to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nContent-Length: {}\r\n\r\n{body}",
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

/// Blocks a request body containing `block-me`.
struct Inspector;

#[async_trait::async_trait]
impl AgentHandlerV2 for Inspector {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("inspector", "Inspector", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        if String::from_utf8_lossy(&data).contains("block-me") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

/// A route fronting two MCP servers under the prefixes `a` and `b` (a route
/// with one is a plain MCP route), with `filters`.
fn setup(ports: std::ops::Range<u16>, filters: &str, filter_blocks: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("inspector.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("inspector", socket.clone(), Box::new(Inspector));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let port = free_port(ports.clone());
    let mcp_port = free_port(port + 1..ports.end);
    let other_port = free_port(mcp_port + 1..ports.end);
    let seen = Arc::new(Mutex::new(Vec::new()));
    spawn_mcp_server(mcp_port, seen.clone());
    spawn_mcp_server(other_port, Arc::new(Mutex::new(Vec::new())));
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
    upstream "mcp-a" {{
        target "127.0.0.1:{mcp_port}"
    }}
    upstream "mcp-b" {{
        target "127.0.0.1:{other_port}"
    }}
}}
agents {{
    agent "inspector" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        timeout-ms 2000
    }}
}}
filters {{
    {filter_blocks}
}}
routes {{
    route "mcp" {{
        matches {{ path "/mcp" }}
        upstream "mcp-a"
        filters {filters}
        mcp {{
            require-validated-version #false
            session-key "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            upstreams {{
                upstream "mcp-a" prefix="a" path="/mcp"
                upstream "mcp-b" prefix="b" path="/mcp"
            }}
        }}
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
    // The agent connects in the background: wait until a call goes through.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, _) = call_tool(port, "a.warmup", "fine");
        if status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the route never answered 200: {status}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    Setup {
        port,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

const INSPECTOR: &str = r#"filter "inspector" {
        type "agent"
        agent "inspector"
        failure-mode "closed"
    }"#;

/// The route's body agent inspects the tool call: a call it blocks gets 403
/// and never reaches the MCP server; one it allows arrives with the tool
/// name the server knows.
#[test]
fn a_body_agent_inspects_a_multiplexed_tool_call() {
    let setup = setup(20400..20420, "\"inspector\"", INSPECTOR);
    let (status, raw) = call_tool(setup.port, "a.search", "please block-me now");
    assert_eq!(status, 403, "{raw}");
    let seen = setup.seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|b| b.contains("block-me")),
        "the blocked call reached the MCP server: {seen:?}"
    );

    let (status, raw) = call_tool(setup.port, "a.search", "harmless");
    assert_eq!(status, 200, "{raw}");
    let seen = setup.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|b| b.contains("harmless") && b.contains("\"name\":\"search\"")),
        "the allowed call did not reach the server under its own name: {seen:?}"
    );
}

/// A rate limit keyed on the MCP tool applies to a multiplexed tool call.
#[test]
fn a_per_tool_rate_limit_applies_to_a_multiplexed_tool_call() {
    let limit = r#"filter "per-tool" {
        type "rate-limit"
        key "mcp-tool"
        max-rps 1
        burst 1
    }"#;
    let setup = setup(20420..20440, "\"per-tool\"", limit);
    // `setup` spent the warm-up tool's budget; this tool has its own.
    let (first, raw) = call_tool(setup.port, "a.expensive", "one");
    assert_eq!(first, 200, "{raw}");
    let (second, raw) = call_tool(setup.port, "a.expensive", "two");
    assert_eq!(second, 429, "{raw}");
    let seen = setup.seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|b| b.contains("\"two\"")),
        "the rate-limited call reached the MCP server: {seen:?}"
    );
}
