//! SIGTERM and SIGINT stop accepting, let the requests in flight finish, and
//! end the process once they have or `graceful-shutdown-timeout-secs` is up.
//!
//! The proxy used to log "draining connections" and call `exit(0)` at once,
//! so a request in flight when `systemctl restart` ran was cut off.
//!
//! Runs the real binary against a backend that answers slowly.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend that waits `delay` before it answers 200 "ok".
fn slow_backend(delay: Duration) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind backend");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                std::thread::sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    port
}

/// Send one request on a new connection, from a thread, and report what came
/// back: the status line's code and the body, or `None` if the connection was
/// cut before a response.
fn request_in_background(proxy: u16) -> mpsc::Receiver<Option<(u16, String)>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let mut stream = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .ok()?;
            stream
                .write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
                .ok()?;
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            let code = response.split_whitespace().nth(1)?.parse().ok()?;
            let body = response.rsplit("\r\n\r\n").next()?.to_string();
            Some((code, body))
        })();
        let _ = tx.send(result);
    });
    rx
}

struct Proxy {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Proxy {
    fn start(config: &Path, port: u16) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (tx, lines) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut proxy = Self {
            child,
            lines,
            log: Vec::new(),
        };
        proxy.wait_for("Zentinel proxy started successfully");
        // The line is logged before the listeners are bound.
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        proxy
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let found = line.contains(needle);
                    self.log.push(line);
                    if found {
                        return;
                    }
                }
                Err(_) => {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        panic!(
                            "the proxy exited ({status:?}) before {needle:?}; log:\n{}",
                            self.log.join("\n")
                        );
                    }
                }
            }
        }
        panic!("never saw {needle:?}; log:\n{}", self.log.join("\n"));
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    /// Wait for the process to exit, returning how it did and when.
    fn wait_exit(&mut self, within: Duration) -> (ExitStatus, Instant) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status, Instant::now());
            }
            assert!(
                Instant::now() < deadline,
                "the proxy was still running {within:?} after the signal; log:\n{}",
                self.log.join("\n")
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(dir: &Path, proxy: u16, backend: u16, timeout_secs: u64) -> std::path::PathBuf {
    let config = dir.join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{
    worker-threads 1
    graceful-shutdown-timeout-secs {timeout_secs}
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{proxy}"
        protocol "http"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
        ),
    )
    .unwrap();
    config
}

/// A request that takes 2 s is half done when the signal arrives. It must
/// finish with its 200, a connection opened during the drain must be refused,
/// and the process must then exit 0 well before the 20 s timeout.
fn in_flight_request_finishes(sig: libc::c_int) {
    let backend = slow_backend(Duration::from_secs(2));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(700));
    let signalled = Instant::now();
    proxy.signal(sig);

    std::thread::sleep(Duration::from_millis(500));
    let refused = TcpStream::connect_timeout(
        &([127, 0, 0, 1], proxy_port).into(),
        Duration::from_millis(500),
    );
    assert!(
        refused.is_err(),
        "a connection was accepted during the drain"
    );

    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some((200, "ok".to_string())),
        "the request in flight was cut off; log:\n{}",
        proxy.log.join("\n")
    );
    assert!(status.success(), "{status:?}");
    let took = exited - signalled;
    assert!(
        took >= Duration::from_millis(1200) && took < Duration::from_secs(10),
        "exited {took:?} after the signal; the request needed about 1.3 s more"
    );
}

#[test]
fn sigterm_lets_the_request_in_flight_finish() {
    in_flight_request_finishes(libc::SIGTERM);
}

#[test]
fn sigint_lets_the_request_in_flight_finish() {
    in_flight_request_finishes(libc::SIGINT);
}

#[test]
fn an_idle_proxy_exits_at_once() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 30),
        proxy_port,
    );

    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);
    let (status, exited) = proxy.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "{status:?}");
    assert!(
        exited - signalled < Duration::from_secs(5),
        "an idle proxy took {:?} to exit with a 30 s timeout",
        exited - signalled
    );
}

#[test]
fn a_request_that_outlasts_the_timeout_is_cut_off_at_the_timeout() {
    let backend = slow_backend(Duration::from_secs(30));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 2),
        proxy_port,
    );

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(500));
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);

    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    let took = exited - signalled;
    assert!(status.success(), "{status:?}");
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_secs(6),
        "exited {took:?} after the signal, with a 2 s timeout"
    );
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        None,
        "the request should have been cut off"
    );
}
