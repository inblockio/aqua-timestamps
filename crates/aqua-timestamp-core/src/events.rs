//! SSE event types and broadcast bus for the Aqua Timestamp aggregator.
//!
//! The [`EventBus`] wraps a Tokio broadcast channel so any number of
//! SSE handler tasks can subscribe and receive the same stream of
//! [`SseEvent`]s without coupling the sealer to individual HTTP
//! connections. The sealer emits events after each successful epoch seal;
//! the SSE route handler converts them to `text/event-stream` frames.
//!
//! Failure semantics: [`EventBus::send`] silently drops events when there
//! are no active subscribers (broadcast send to zero receivers is not an
//! error here). Lagged receivers are dropped per the Tokio broadcast
//! contract; the SSE handler should reconnect on [`RecvError::Lagged`].

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// All event types the service can emit over the SSE stream.
///
/// Tagged with `#[serde(tag = "type", rename_all = "snake_case")]` so the
/// JSON wire format is:
/// ```json
/// {"type": "epoch_sealed", "epoch_id": 1, "leaf_count": 5, ...}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SseEvent {
    /// Emitted once per epoch after the sealer commits the epoch record
    /// and all witness revisions to storage.
    EpochSealed {
        epoch_id: u64,
        leaf_count: u64,
        merkle_root: String,
        timestamp: u64,
    },
    /// Emitted after the EVM anchor tx is confirmed (or stub-filled on
    /// RPC failure). `block` is 0 for stub outcomes.
    AnchorEvm {
        epoch_id: u64,
        tx_hash: String,
        block: u64,
        network: String,
    },
    /// Emitted after the qTSA anchor completes (or stub-filled on
    /// provider failure). `gen_time` is the RFC 3161 `genTime` string.
    AnchorQtsa {
        epoch_id: u64,
        tsa_provider: String,
        gen_time: String,
    },
    /// Periodic liveness ping from the health-tick task.
    HealthTick {
        uptime_secs: u64,
        epochs_total: u64,
        leaves_total: u64,
    },
}

impl SseEvent {
    /// SSE event name used as the `event:` field in the `text/event-stream`
    /// protocol.
    pub fn event_name(&self) -> &'static str {
        match self {
            SseEvent::EpochSealed { .. } => "epoch:sealed",
            SseEvent::AnchorEvm { .. } => "anchor:evm",
            SseEvent::AnchorQtsa { .. } => "anchor:qtsa",
            SseEvent::HealthTick { .. } => "health:tick",
        }
    }
}

/// Broadcast hub for [`SseEvent`]s.
///
/// Wraps a [`tokio::sync::broadcast::Sender`]; clone the bus (or call
/// [`EventBus::subscribe`]) to fan out to SSE connections. Sending while
/// there are no subscribers is a no-op (the underlying channel discards
/// the message rather than returning an error).
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<SseEvent>,
}

impl EventBus {
    /// Create a new bus with the given broadcast channel capacity.
    ///
    /// `capacity` is the number of messages buffered per subscriber
    /// before lagging begins. A value of 64 is a reasonable default for
    /// low-throughput services; increase it if epoch seals are rapid.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event to all active subscribers.
    ///
    /// Returns the number of subscribers that received the event.
    /// Returns `0` (not an error) when there are no active subscribers.
    pub fn send(&self, event: SseEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// Subscribe to the event stream.
    ///
    /// Each subscriber receives its own buffered copy of all events
    /// published after the subscription is created.
    pub fn subscribe(&self) -> broadcast::Receiver<SseEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_bus_send_and_receive() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        let event = SseEvent::EpochSealed {
            epoch_id: 7,
            leaf_count: 3,
            merkle_root: "0xdeadbeef".into(),
            timestamp: 1_000_000,
        };

        bus.send(event);

        let received = rx.recv().await.expect("should receive event");

        // Verify event_name dispatch.
        assert_eq!(received.event_name(), "epoch:sealed");

        // Verify JSON round-trip includes the type tag and all fields.
        let json = serde_json::to_value(&received).expect("serialization failed");
        assert_eq!(json["type"], "epoch_sealed");
        assert_eq!(json["epoch_id"], 7u64);
        assert_eq!(json["leaf_count"], 3u64);
        assert_eq!(json["merkle_root"], "0xdeadbeef");
        assert_eq!(json["timestamp"], 1_000_000u64);
    }

    #[tokio::test]
    async fn no_subscribers_does_not_panic() {
        let bus = EventBus::new(16);

        // Sending with zero subscribers must not panic; send() returns 0.
        let n = bus.send(SseEvent::HealthTick {
            uptime_secs: 60,
            epochs_total: 2,
            leaves_total: 10,
        });
        assert_eq!(n, 0);

        // Sending a second event type is also fine.
        bus.send(SseEvent::AnchorEvm {
            epoch_id: 1,
            tx_hash: "0x00".into(),
            block: 0,
            network: "sepolia".into(),
        });
    }
}
