//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use http::HeaderName;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Waker};

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
    /// Where every frame logged from now on goes, the limit aside (see
    /// [`FrameLog::subscribe`]).
    subscribers: Vec<tokio::sync::mpsc::UnboundedSender<LoggedFrame>>,
    /// Called with every frame logged from now on (see [`FrameLog::on_frame`]).
    hooks: Vec<FrameHook>,
    /// The bodies kept of the messages whose streams are open, by stream (see
    /// [`HeadersFrame::body`]).
    bodies: HashMap<u32, Weak<Mutex<ReceivedBody>>>,
}

#[derive(Clone)]
struct FrameHook(Arc<dyn Fn(&LoggedFrame) + Send + Sync>);

impl fmt::Debug for FrameHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("FrameHook(..)")
    }
}

impl FrameLog {
    pub(crate) fn new(limit: usize) -> Self {
        FrameLog(Arc::new(Mutex::new(FrameLogInner {
            frames: Vec::new(),
            limit,
            dropped: 0,
            subscribers: Vec::new(),
            hooks: Vec::new(),
            bodies: HashMap::new(),
        })))
    }

    fn lock(&self) -> MutexGuard<'_, FrameLogInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, frame: LoggedFrame) {
        let mut inner = self.lock();
        inner
            .subscribers
            .retain(|subscriber| subscriber.send(frame.clone()).is_ok());
        let hooks = inner.hooks.clone();
        if inner.frames.len() < inner.limit {
            inner.frames.push(frame.clone());
        } else {
            inner.dropped += 1;
        }
        drop(inner);
        for hook in hooks {
            (hook.0)(&frame);
        }
    }

    /// The frames logged so far, in the order received.
    pub fn frames(&self) -> Vec<LoggedFrame> {
        self.lock().frames.clone()
    }

    /// Every frame the log holds, in the order received, then each frame received from
    /// now on as it arrives, past the log's limit too, until the connection ends.
    pub fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<LoggedFrame> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut inner = self.lock();
        for frame in &inner.frames {
            let _ = sender.send(frame.clone());
        }
        inner.subscribers.push(sender);
        receiver
    }

    /// How many frames arrived after the log reached its limit, and were not logged.
    pub fn dropped(&self) -> usize {
        self.lock().dropped
    }

    /// Calls `hook` with each frame received from now on as it arrives, past the log's
    /// limit too: after the subscribers got it (see [`Self::subscribe`]), and before the
    /// connection acts on it.
    pub fn on_frame(&self, hook: impl Fn(&LoggedFrame) + Send + Sync + 'static) {
        self.lock().hooks.push(FrameHook(Arc::new(hook)));
    }

    /// Starts keeping the body of the message whose header block opened `stream_id`.
    pub(crate) fn open_body(&self, stream_id: u32) -> BodyFrames {
        let body = BodyFrames::default();
        let mut inner = self.lock();
        inner.bodies.retain(|_, body| body.strong_count() > 0);
        inner.bodies.insert(stream_id, Arc::downgrade(&body.0));
        body
    }

    /// The body kept of the message on `stream_id`, or `None` when none is; `end` stops
    /// keeping it.
    pub(crate) fn kept_body(&self, stream_id: u32, end: bool) -> Option<Weak<Mutex<ReceivedBody>>> {
        let mut inner = self.lock();
        if end {
            inner.bodies.remove(&stream_id)
        } else {
            inner.bodies.get(&stream_id).cloned()
        }
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
        /// The additional debug data.
        debug_data: Bytes,
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
    /// Its pseudo-header fields sent as never-indexed literals, which an intermediary
    /// sends so too (RFC 7541 §6.2.3); its fields' values are marked sensitive.
    pub never_indexed: Vec<PseudoHeader>,
    /// How its header block went.
    pub encoding: HeaderBlockEncoding,
    /// How its body goes, kept as it arrives.
    pub body: BodyFrames,
    /// The frames its connection's peer sent.
    pub connection: FrameLog,
}

/// How a header block went on the wire: its HPACK dynamic table size updates and each
/// field's representation (RFC 7541), and how its HEADERS frame and the CONTINUATION
/// frames after it carried it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HeaderBlockEncoding {
    /// The dynamic table size updates at its start, in order (RFC 7541 §6.3).
    pub size_updates: Vec<usize>,
    /// Its fields in block order, pseudo-header fields first.
    pub fields: Vec<EncodedField>,
    /// The HEADERS frame's pad length, when it carried the PADDED flag.
    pub padding: Option<u8>,
    /// The lengths of the block's fragments: the HEADERS frame's, then each
    /// CONTINUATION frame's.
    pub fragments: Vec<usize>,
}

/// A header field as a header block carried it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EncodedField {
    /// Its name, a pseudo-header field's with its colon.
    pub name: Bytes,
    /// Its value.
    pub value: Bytes,
    /// How it went.
    pub representation: FieldRepresentation,
}

/// How a header field went in an HPACK header block (RFC 7541 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldRepresentation {
    /// By the index of its static or dynamic table entry (§6.1).
    Indexed(usize),
    /// As a literal (§6.2).
    Literal {
        /// Whether, and how, it enters the dynamic table.
        indexing: LiteralIndexing,
        /// The index of the table entry naming it, or `None` for a literal name.
        name_index: Option<usize>,
        /// Whether its literal name is Huffman-coded.
        name_huffman: bool,
        /// Whether its value is Huffman-coded.
        value_huffman: bool,
    },
}

/// How a literal header field touches the HPACK dynamic table (RFC 7541 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LiteralIndexing {
    /// It enters the table (§6.2.1).
    Incremental,
    /// It doesn't (§6.2.2).
    Without,
    /// It doesn't, nor may an intermediary encoding it again add it (§6.2.3).
    Never,
}

/// How a message's body went on the wire past its header block, kept as it arrives:
/// each DATA frame that carried padding or no data or ended the stream (the others
/// carried data unpadded), and how its trailers' header block went. Clones share it.
#[derive(Clone, Debug, Default)]
pub struct BodyFrames(Arc<Mutex<ReceivedBody>>);

#[derive(Debug, Default)]
pub(crate) struct ReceivedBody {
    /// How many DATA frames carrying data arrived.
    data_frames: u64,
    /// The DATA frames kept and not yet taken.
    frames: VecDeque<DataFrame>,
    trailers: Option<HeaderBlockEncoding>,
}

/// A DATA frame a [`BodyFrames`] keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataFrame {
    /// How many DATA frames carrying data went before it on its stream.
    pub index: u64,
    /// The length of its data.
    pub len: usize,
    /// Its pad length, when it carried the PADDED flag.
    pub padding: Option<u8>,
    /// The END_STREAM flag.
    pub end_stream: bool,
}

/// The most DATA frames a [`BodyFrames`] holds untaken; it drops any more.
const MAX_KEPT_DATA_FRAMES: usize = 1024;

impl BodyFrames {
    pub(crate) fn upgrade(kept: &Weak<Mutex<ReceivedBody>>) -> Option<Self> {
        kept.upgrade().map(BodyFrames)
    }

    fn lock(&self) -> MutexGuard<'_, ReceivedBody> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push_data(&self, len: usize, padding: Option<u8>, end_stream: bool) {
        let mut body = self.lock();
        let index = body.data_frames;
        if len > 0 {
            body.data_frames += 1;
        }
        if (padding.is_some() || len == 0 || end_stream) && body.frames.len() < MAX_KEPT_DATA_FRAMES
        {
            body.frames.push_back(DataFrame {
                index,
                len,
                padding,
                end_stream,
            });
        }
    }

    pub(crate) fn set_trailers(&self, encoding: HeaderBlockEncoding) {
        self.lock().trailers = Some(encoding);
    }

    /// Removes and returns the DATA frames kept so far that went no later than the DATA
    /// frame carrying data at `through`, or every one kept given `None`.
    pub fn take(&self, through: Option<u64>) -> Vec<DataFrame> {
        let mut body = self.lock();
        let end = match through {
            Some(through) => body.frames.partition_point(|frame| frame.index <= through),
            None => body.frames.len(),
        };
        body.frames.drain(..end).collect()
    }

    /// Takes how the trailers' header block went, once it arrived.
    pub fn take_trailers(&self) -> Option<HeaderBlockEncoding> {
        self.lock().trailers.take()
    }
}

/// A frame of a server's connection preface a [`DeferredPreface`] supplies: its SETTINGS,
/// exactly as given, and the frames right after it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefaceFrame {
    /// The SETTINGS frame: `(identifier, value)` in order, unknown identifiers and repeats
    /// included. The known parameters set the connection's own settings.
    Settings(Vec<(u16, u32)>),
    /// A connection-level WINDOW_UPDATE, by its increment.
    WindowUpdate(u32),
    /// A frame of a type this crate doesn't know, sent as given.
    Unknown {
        /// The frame type.
        kind: u8,
        /// The flags.
        flags: u8,
        /// The stream identifier.
        stream_id: u32,
        /// The payload.
        payload: Bytes,
    },
}

/// A server connection's preface supplied once known (see
/// [`server::Builder::deferred_preface`](crate::server::Builder::deferred_preface)): the
/// connection reads the client's preface and frames meanwhile but sends nothing until the
/// preface arrives on its [`PrefaceSender`], which it then writes ahead of everything
/// else, then the frames its [`Relay`] relays. A sender dropped without sending releases
/// the connection with its own configured SETTINGS. Clones share the one preface, for a
/// builder handed a preface to be cloned; the connection built from it takes it.
#[derive(Clone, Debug)]
pub struct DeferredPreface {
    preface: Arc<Mutex<tokio::sync::oneshot::Receiver<Vec<PrefaceFrame>>>>,
    relay: Relay,
}

/// Supplies a [`DeferredPreface`].
#[derive(Debug)]
pub struct PrefaceSender(tokio::sync::oneshot::Sender<Vec<PrefaceFrame>>);

/// A preface a connection waits for, and the sender supplying it.
pub fn deferred_preface() -> (PrefaceSender, DeferredPreface) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    (
        PrefaceSender(sender),
        DeferredPreface {
            preface: Arc::new(Mutex::new(receiver)),
            relay: Relay::default(),
        },
    )
}

impl PrefaceSender {
    /// Sends `frames` as the connection's preface: its SETTINGS (the connection's own when
    /// `frames` has none) and the frames right after it.
    pub fn send(self, frames: Vec<PrefaceFrame>) {
        let _ = self.0.send(frames);
    }
}

/// Ends a server connection as its caller relays another connection's end, from another
/// task (see [`server::Builder::relayed_end`](crate::server::Builder::relayed_end)): with
/// that connection's GOAWAYs, then its close. Clones share it.
#[derive(Clone, Debug, Default)]
pub struct RelayedEnd(Arc<Mutex<RelayedEndInner>>);

#[derive(Debug, Default)]
struct RelayedEndInner {
    /// The GOAWAYs to send: their last stream id, error code and debug data.
    go_aways: Vec<(u32, u32, Bytes)>,
    close: bool,
    task: Option<Waker>,
}

impl RelayedEnd {
    /// An end nothing was relayed of yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends a GOAWAY of `error_code` and `debug_data` naming `last_stream_id`, or, when
    /// earlier, the stream the GOAWAY it sent before named, and refuses (REFUSED_STREAM)
    /// each open stream the client opened past it, which the GOAWAY tells went
    /// unprocessed. The connection then accepts no later stream, and stays open until
    /// [`Self::close`] or the client closes it.
    pub fn go_away(&self, last_stream_id: u32, error_code: u32, debug_data: Bytes) {
        let mut inner = self.lock();
        inner
            .go_aways
            .push((last_stream_id, error_code, debug_data));
        inner.wake();
    }

    /// Closes the connection once it has no streams, with no GOAWAY of its own.
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.close = true;
        inner.wake();
    }

    fn lock(&self) -> MutexGuard<'_, RelayedEndInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The GOAWAYs to send, and whether to close once idle; `cx` is woken when more come.
    pub(crate) fn poll_take(&self, cx: &mut Context<'_>) -> (Vec<(u32, u32, Bytes)>, bool) {
        let mut inner = self.lock();
        inner.task = Some(cx.waker().clone());
        (std::mem::take(&mut inner.go_aways), inner.close)
    }
}

impl RelayedEndInner {
    fn wake(&mut self) {
        if let Some(task) = self.task.take() {
            task.wake();
        }
    }
}

impl DeferredPreface {
    /// Relays frames on the connection taking this preface, after it (see [`Relay`]).
    pub fn relay(&self) -> Relay {
        self.relay.clone()
    }

    /// The frames to send, once supplied (none when the sender was dropped).
    pub(crate) fn poll_frames(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Vec<PrefaceFrame>> {
        let mut receiver = self.preface.lock().unwrap_or_else(PoisonError::into_inner);
        std::future::Future::poll(std::pin::Pin::new(&mut *receiver), cx)
            .map(|frames| frames.unwrap_or_default())
    }
}

/// A frame another connection's peer sent, which a server connection relays to its client
/// (see [`Relay`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayedFrame {
    /// A SETTINGS frame: `(identifier, value)` in order, unknown identifiers and repeats
    /// included, whatever SETTINGS sent before await acknowledgement. The known parameters
    /// apply to the connection as its own once the client acknowledges it.
    Settings(Vec<(u16, u32)>),
    /// A PING carrying this payload.
    Ping([u8; 8]),
    /// A WINDOW_UPDATE of `increment` for the connection (`stream_id` 0) or a client's
    /// stream, growing its window by it; a stream's window then grows only by these,
    /// rather than by the data released, as the relaying peer's does. None for a stream
    /// the connection doesn't have, or an increment the window can't take.
    WindowUpdate {
        /// The connection (0) or the client's stream.
        stream_id: u32,
        /// The window size increment.
        increment: u32,
    },
    /// A frame of a type HTTP/2 doesn't define, sent as given.
    Unknown {
        /// The frame type.
        kind: u8,
        /// The flags.
        flags: u8,
        /// The stream identifier.
        stream_id: u32,
        /// The payload.
        payload: Bytes,
    },
}

/// The client's acknowledgement of a frame a [`Relay`] relayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayedAck {
    /// Of the earliest relayed SETTINGS frame it hadn't acknowledged.
    Settings,
    /// Of a relayed PING carrying this payload.
    Ping([u8; 8]),
}

/// Relays another connection's peer's frames to the client of the server connection
/// taking a [`DeferredPreface`] (see [`DeferredPreface::relay`]): each goes out as it comes,
/// in order, once that preface went out, and the client's acknowledgements of them come
/// back (see [`Relay::on_ack`]). Clones share it.
#[derive(Clone, Debug, Default)]
pub struct Relay(Arc<Mutex<RelayInner>>);

#[derive(Debug, Default)]
struct RelayInner {
    frames: VecDeque<RelayedFrame>,
    task: Option<Waker>,
    on_ack: Option<AckHook>,
    /// Whether the connection ended.
    closed: bool,
}

#[derive(Clone)]
struct AckHook(Arc<dyn Fn(RelayedAck) + Send + Sync>);

impl fmt::Debug for AckHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("AckHook(..)")
    }
}

impl Relay {
    fn lock(&self) -> MutexGuard<'_, RelayInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends `frame` to the client, after the frames sent before it.
    pub fn send(&self, frame: RelayedFrame) {
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        inner.frames.push_back(frame);
        if let Some(task) = inner.task.take() {
            task.wake();
        }
    }

    /// Calls `hook` with each of the client's acknowledgements of the relayed frames from
    /// now on as the connection receives it, before it receives the next frame, in place
    /// of the hook given before.
    pub fn on_ack(&self, hook: impl Fn(RelayedAck) + Send + Sync + 'static) {
        self.lock().on_ack = Some(AckHook(Arc::new(hook)));
    }

    /// The frames to relay so far; `cx` is woken when more come.
    pub(crate) fn poll_take(&self, cx: &mut Context<'_>) -> VecDeque<RelayedFrame> {
        let mut inner = self.lock();
        inner.task = Some(cx.waker().clone());
        std::mem::take(&mut inner.frames)
    }

    /// Tells the client's acknowledgement `ack`.
    pub(crate) fn acked(&self, ack: RelayedAck) {
        let hook = self.lock().on_ack.clone();
        if let Some(hook) = hook {
            (hook.0)(ack);
        }
    }

    /// Tells that the connection ended: nothing more is relayed.
    pub(crate) fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.frames.clear();
        inner.on_ack = None;
    }
}
