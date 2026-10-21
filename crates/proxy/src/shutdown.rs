//! Graceful shutdown on SIGTERM and SIGINT.
//!
//! Both signals stop the listeners from accepting, let the connections
//! already open finish, and end the process once none are left or
//! `graceful-shutdown-timeout-secs` has passed, whichever comes first.
//!
//! Pingora does the first step itself: on SIGTERM it tells the listeners to
//! stop accepting and the open connections to close after their current
//! request. It then sleeps for `grace_period_seconds` whether or not anything
//! is still open, and stops its runtimes without waiting for the work in
//! them. [`drain`] is the part that watches the connections, so the process
//! can end as soon as they are gone, and not before. It ends the process
//! itself, within the timeout, so Pingora's own sleep (300 s by default, which
//! `-u` upgrades still use for the old process) never gets to run out.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_core::server::{ExecutionPhase, ShutdownSignal, ShutdownSignalWatch};
use tokio::sync::broadcast;
use tokio::time::sleep;
use zentinel_common::limits::ConnectionLimiter;

/// How often the open connections are counted while draining.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How a drain ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Drained {
    /// No connection was left open, after this long.
    Complete(Duration),
    /// The timeout passed with this many connections still open.
    TimedOut { open: usize },
}

/// SIGTERM and SIGINT both mean a graceful shutdown. Pingora's own watcher
/// treats SIGINT as a fast shutdown that stops without waiting for anything,
/// which is not what `server.md` promises for it. SIGQUIT keeps its Pingora
/// meaning: hand the listening sockets to a new process (`-u`) and then
/// shut down gracefully.
pub struct ZentinelShutdownSignals;

#[async_trait]
impl ShutdownSignalWatch for ZentinelShutdownSignals {
    async fn recv(&self) -> ShutdownSignal {
        use tokio::signal::unix::{signal, SignalKind};

        let mut quit = signal(SignalKind::quit()).expect("register SIGQUIT");
        let mut terminate = signal(SignalKind::terminate()).expect("register SIGTERM");
        let mut interrupt = signal(SignalKind::interrupt()).expect("register SIGINT");

        tokio::select! {
            _ = quit.recv() => ShutdownSignal::GracefulUpgrade,
            _ = terminate.recv() => ShutdownSignal::GracefulTerminate,
            _ = interrupt.recv() => ShutdownSignal::GracefulTerminate,
        }
    }
}

/// Wait until the listeners have stopped accepting and no connection is
/// open, or until `timeout` has passed.
///
/// `phases` is the server's execution phase channel, subscribed before the
/// server was started so that a phase announced before this call is still
/// queued. Pingora reports `GracefulTerminate` after it has told
/// the listeners to stop; counting before that could find the proxy empty a
/// moment before one more connection is accepted.
///
/// The count has to be zero twice in a row, so that a connection accepted
/// just before the listener closed, and not yet counted, is not missed.
pub async fn drain(
    connections: &ConnectionLimiter,
    phases: &mut broadcast::Receiver<ExecutionPhase>,
    timeout: Duration,
) -> Drained {
    let start = Instant::now();
    let deadline = start + timeout;

    let stopped_accepting = async {
        loop {
            match phases.recv().await {
                Ok(
                    ExecutionPhase::GracefulTerminate
                    | ExecutionPhase::ShutdownStarted
                    | ExecutionPhase::ShutdownGracePeriod,
                ) => break,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                // The server is gone, so nothing is accepting.
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    let _ = tokio::time::timeout(timeout, stopped_accepting).await;

    let mut empty_polls = 0;
    loop {
        let open = connections.total();
        if open == 0 {
            empty_polls += 1;
            if empty_polls == 2 {
                return Drained::Complete(start.elapsed());
            }
        } else {
            empty_polls = 0;
        }
        let now = Instant::now();
        if now >= deadline {
            return Drained::TimedOut { open };
        }
        sleep(POLL_INTERVAL.min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announced(phase: ExecutionPhase) -> broadcast::Receiver<ExecutionPhase> {
        let (tx, rx) = broadcast::channel(8);
        tx.send(phase).unwrap();
        // Keep the sender alive for the test by leaking it into the receiver's
        // lifetime: a dropped sender reads as a closed channel, which also
        // ends the wait, and that is not what these tests are about.
        std::mem::forget(tx);
        rx
    }

    #[tokio::test]
    async fn an_idle_proxy_is_drained_at_once() {
        let connections = ConnectionLimiter::new();
        let outcome = drain(
            &connections,
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_secs(30),
        )
        .await;
        match outcome {
            Drained::Complete(took) => assert!(took < Duration::from_secs(1), "{took:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn waits_for_an_open_connection_to_close() {
        let connections = ConnectionLimiter::new();
        let permit = connections.try_acquire(None, None, None).unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            drop(permit);
        });
        let outcome = drain(
            &connections,
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_secs(30),
        )
        .await;
        match outcome {
            Drained::Complete(took) => assert!(
                took >= Duration::from_millis(300) && took < Duration::from_secs(5),
                "{took:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn gives_up_at_the_timeout_with_connections_still_open() {
        let connections = ConnectionLimiter::new();
        let _held = connections.try_acquire(None, None, None).unwrap();
        let start = Instant::now();
        let outcome = drain(
            &connections,
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(outcome, Drained::TimedOut { open: 1 });
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn does_not_count_before_the_listeners_have_stopped() {
        let connections = ConnectionLimiter::new();
        let (tx, mut rx) = broadcast::channel(8);
        let announce = tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            tx.send(ExecutionPhase::GracefulTerminate).unwrap();
            tx
        });
        let outcome = drain(&connections, &mut rx, Duration::from_secs(30)).await;
        match outcome {
            Drained::Complete(took) => assert!(took >= Duration::from_millis(300), "{took:?}"),
            other => panic!("{other:?}"),
        }
        let _ = announce.await;
    }
}
