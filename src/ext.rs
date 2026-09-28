//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use http::HeaderName;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// The names of a message's header fields in the order its header block carries them,
/// repeats included, which a `HeaderMap` loses by grouping a repeated name's values.
///
/// h2 inserts one into each request and response it receives. A request or response
/// sent with one is encoded in its order: each listed name takes the next value of that
/// name, and values it doesn't list follow in map order. Trailers carry theirs beside
/// the map, through [`RecvStream::poll_trailers_with_order`] and
/// [`SendStream::send_trailers_with_order`].
///
/// [`RecvStream::poll_trailers_with_order`]: crate::RecvStream::poll_trailers_with_order
/// [`SendStream::send_trailers_with_order`]: crate::SendStream::send_trailers_with_order
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeaderOrder(pub Vec<HeaderName>);

/// The frames a peer sent on a connection that shape its HTTP/2 fingerprint, in the order
/// received: every frame but DATA, CONTINUATION (a `Headers` entry stands for its whole
/// header block) and PUSH_PROMISE, up to a limit.
///
/// A server built with [`record_frames`](crate::server::Builder::record_frames) keeps one
/// per connection and hands it to each request inside its [`HeadersFrame`]. Clones share
/// the log, which keeps growing while the connection lives, so a request sees at least
/// every frame up to its own HEADERS.
#[derive(Clone, Debug)]
pub struct FrameLog(Arc<Mutex<FrameLogInner>>);

#[derive(Debug)]
struct FrameLogInner {
    frames: Vec<LoggedFrame>,
    limit: usize,
    dropped: usize,
}

impl FrameLog {
    pub(crate) fn new(limit: usize) -> Self {
        FrameLog(Arc::new(Mutex::new(FrameLogInner {
            frames: Vec::new(),
            limit,
            dropped: 0,
        })))
    }

    fn lock(&self) -> MutexGuard<'_, FrameLogInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, frame: LoggedFrame) {
        let mut inner = self.lock();
        if inner.frames.len() < inner.limit {
            inner.frames.push(frame);
        } else {
            inner.dropped += 1;
        }
    }

    /// The frames logged so far, in the order received.
    pub fn frames(&self) -> Vec<LoggedFrame> {
        self.lock().frames.clone()
    }

    /// How many frames arrived after the log reached its limit, and were not logged.
    pub fn dropped(&self) -> usize {
        self.lock().dropped
    }
}

/// A frame in a [`FrameLog`], with its fields as sent.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoggedFrame {
    /// A SETTINGS frame: every parameter's identifier and value in wire order, unknown
    /// identifiers and repeats included.
    Settings {
        /// The ACK flag.
        ack: bool,
        /// `(identifier, value)` pairs.
        params: Vec<(u16, u32)>,
    },
    /// A WINDOW_UPDATE frame; stream 0 is the connection.
    WindowUpdate {
        /// The stream the update applies to.
        stream_id: u32,
        /// The window size increment.
        increment: u32,
    },
    /// A PRIORITY frame.
    Priority {
        /// The stream the priority applies to.
        stream_id: u32,
        /// The priority it sets.
        priority: StreamPriority,
    },
    /// A HEADERS frame, with any CONTINUATION frames completing its header block.
    Headers {
        /// The stream it opens or continues.
        stream_id: u32,
        /// The END_STREAM flag.
        end_stream: bool,
        /// Its priority fields, when it carries the PRIORITY flag.
        priority: Option<StreamPriority>,
        /// Its pseudo-header fields, in block order.
        pseudo_order: Vec<PseudoHeader>,
    },
    /// A PING frame.
    Ping {
        /// The ACK flag.
        ack: bool,
        /// The opaque data.
        payload: [u8; 8],
    },
    /// A RST_STREAM frame.
    Reset {
        /// The stream reset.
        stream_id: u32,
        /// The error code.
        error_code: u32,
    },
    /// A GOAWAY frame.
    GoAway {
        /// The last stream identifier.
        last_stream_id: u32,
        /// The error code.
        error_code: u32,
    },
    /// A frame of a type this crate doesn't know, such as a GREASE type.
    Unknown {
        /// The frame type.
        kind: u8,
        /// The flags.
        flags: u8,
        /// The stream identifier.
        stream_id: u32,
        /// The payload length.
        length: u32,
        /// The payload.
        payload: Bytes,
    },
}

/// A stream's priority fields as a HEADERS or PRIORITY frame carries them (RFC 7540
/// §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamPriority {
    /// The stream this one depends on.
    pub dependency: u32,
    /// The weight byte as sent: the weight minus one (0 for weight 1, 255 for 256).
    pub weight: u8,
    /// The exclusive flag.
    pub exclusive: bool,
}

/// A pseudo-header field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoHeader {
    /// `:method`
    Method,
    /// `:scheme`
    Scheme,
    /// `:authority`
    Authority,
    /// `:path`
    Path,
    /// `:protocol`
    Protocol,
    /// `:status`
    Status,
}

/// How a request's HEADERS frame was sent: its stream, priority fields and pseudo-header
/// order, beside its connection's [`FrameLog`].
///
/// A server built with [`record_frames`](crate::server::Builder::record_frames) inserts
/// one into each request.
#[derive(Clone, Debug)]
pub struct HeadersFrame {
    /// The request's stream identifier.
    pub stream_id: u32,
    /// Its priority fields, when the HEADERS frame carried the PRIORITY flag.
    pub priority: Option<StreamPriority>,
    /// Its pseudo-header fields, in block order.
    pub pseudo_order: Vec<PseudoHeader>,
    /// The frames its connection's peer sent.
    pub connection: FrameLog,
}
