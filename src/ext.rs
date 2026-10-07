//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use http::HeaderName;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

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

    /// Whether it is a token (RFC 9110 §5.6.2), as a `:protocol` value must be (RFC 8441
    /// §4).
    pub(crate) fn is_token(&self) -> bool {
        let tchar = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
        !self.as_str().is_empty() && self.as_str().bytes().all(tchar)
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
    /// How many frames were logged, the limit aside, and how many before the client's
    /// SETTINGS and PINGs went to the relaying peer (see [`Relay::forward_from_now`]).
    logged: u64,
    forward_from: Option<u64>,
    /// Where every frame logged from now on goes, the limit aside (see
    /// [`FrameLog::subscribe`]).
    subscribers: Vec<tokio::sync::mpsc::UnboundedSender<LoggedFrame>>,
    /// Called with every frame logged from now on (see [`FrameLog::on_frame`]).
    hooks: Vec<FrameHook>,
    /// Ready once the connection may read the next frame but DATA (see
    /// [`FrameLog::gate_reads`]).
    gate: Option<ReadGate>,
    /// The streams of the latest requests the connection didn't hand over, oldest first,
    /// and the hooks called with each from now on (see [`FrameLog::on_unhandled`]).
    unhandled: VecDeque<u32>,
    unhandled_hooks: Vec<UnhandledHook>,
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

#[derive(Clone)]
struct ReadGate(Arc<dyn Fn(&mut Context<'_>) -> std::task::Poll<()> + Send + Sync>);

impl fmt::Debug for ReadGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("ReadGate(..)")
    }
}

#[derive(Clone)]
struct UnhandledHook(Arc<dyn Fn(u32) + Send + Sync>);

impl fmt::Debug for UnhandledHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("UnhandledHook(..)")
    }
}

/// How many of the latest requests a connection didn't hand over a [`FrameLog`] keeps.
const UNHANDLED: usize = 1024;

impl FrameLog {
    pub(crate) fn new(limit: usize) -> Self {
        FrameLog(Arc::new(Mutex::new(FrameLogInner {
            frames: Vec::new(),
            limit,
            dropped: 0,
            logged: 0,
            forward_from: None,
            subscribers: Vec::new(),
            hooks: Vec::new(),
            gate: None,
            unhandled: VecDeque::new(),
            unhandled_hooks: Vec::new(),
            bodies: HashMap::new(),
        })))
    }

    fn lock(&self) -> MutexGuard<'_, FrameLogInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn push(&self, frame: LoggedFrame) {
        let mut inner = self.lock();
        inner.logged += 1;
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

    pub(crate) fn set_limit(&self, limit: usize) {
        self.lock().limit = limit;
    }

    fn forward_from_now(&self) -> u64 {
        let mut inner = self.lock();
        let logged = inner.logged;
        *inner.forward_from.get_or_insert(logged)
    }

    /// Whether the latest frame logged came once the client's SETTINGS and PINGs go to the
    /// relaying peer (see [`Relay::forward_from_now`]).
    fn forwards_latest(&self) -> bool {
        let inner = self.lock();
        matches!(inner.forward_from, Some(from) if inner.logged > from)
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

    /// Has the connection read each next frame but DATA only once `room` is ready, from
    /// now on, in place of the one given before: a caller passing the frames on as they
    /// arrive (see [`Self::subscribe`]) holds the client back while it lags, as the peer
    /// it passes them to would, rather than having them queue without bound. DATA, which
    /// the log doesn't pass on, goes by, bounded by flow control and the data received
    /// and not yet released.
    pub fn gate_reads(
        &self,
        room: impl Fn(&mut Context<'_>) -> std::task::Poll<()> + Send + Sync + 'static,
    ) {
        self.lock().gate = Some(ReadGate(Arc::new(room)));
    }

    /// Ready once the connection may read the next frame but DATA (see [`Self::gate_reads`]).
    pub(crate) fn poll_gate(&self, cx: &mut Context<'_>) -> std::task::Poll<()> {
        let gate = self.lock().gate.clone();
        gate.map_or(std::task::Poll::Ready(()), |gate| (gate.0)(cx))
    }

    /// Calls `hook` with the stream of each request whose HEADERS the connection received
    /// but won't hand over (refused, reset as malformed, answered itself, or opened past
    /// its GOAWAY), as it does, after those so far (the latest 1,024).
    pub fn on_unhandled(&self, hook: impl Fn(u32) + Send + Sync + 'static) {
        let hook = UnhandledHook(Arc::new(hook));
        let mut inner = self.lock();
        let past: Vec<u32> = inner.unhandled.iter().copied().collect();
        inner.unhandled_hooks.push(hook.clone());
        drop(inner);
        for stream_id in past {
            (hook.0)(stream_id);
        }
    }

    /// Tells that the connection won't hand over the request on `stream_id` (see
    /// [`Self::on_unhandled`]).
    pub(crate) fn unhandled(&self, stream_id: u32) {
        let mut inner = self.lock();
        if inner.unhandled.len() == UNHANDLED {
            inner.unhandled.pop_front();
        }
        inner.unhandled.push_back(stream_id);
        let hooks = inner.unhandled_hooks.clone();
        drop(inner);
        for hook in hooks {
            (hook.0)(stream_id);
        }
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
///
/// A response sent with one has its header block encoded as it says, as far as the
/// connection's own table allows: each field takes the representation of the first field
/// it lists by that name and value not taken yet, else by that name, and a representation
/// naming a table entry the connection's table doesn't hold at that index names one that
/// does, or goes as a literal entering the table; fields it doesn't list, and size updates
/// above the peer's limit, go as the connection would send them, and a sensitive field
/// goes never indexed. The HEADERS frame takes its padding, and the fragments their
/// lengths, as far as the block and the peer's frame size allow.
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
    /// Whether it dropped a DATA frame it had to keep (see [`BodyFrames::dropped`]).
    dropped: bool,
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

    /// Keeps a DATA frame received, as far as it holds room for it; whether it did, or
    /// had no need to.
    pub(crate) fn push_data(&self, len: usize, padding: Option<u8>, end_stream: bool) -> bool {
        let mut body = self.lock();
        let index = body.data_frames;
        if len > 0 {
            body.data_frames += 1;
        }
        if !(padding.is_some() || len == 0 || end_stream) {
            return true;
        }
        if body.frames.len() >= MAX_KEPT_DATA_FRAMES {
            body.dropped = true;
            return false;
        }
        body.frames.push_back(DataFrame {
            index,
            len,
            padding,
            end_stream,
        });
        true
    }

    pub(crate) fn set_trailers(&self, encoding: HeaderBlockEncoding) {
        self.lock().trailers = Some(encoding);
    }

    /// Whether it dropped a DATA frame it had to keep, already holding 1,024
    /// untaken: a layout replayed from it misses that frame's padding or ending.
    pub fn dropped(&self) -> bool {
        self.lock().dropped
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

/// How a body goes on the wire past its header block, as another connection received
/// it: its DATA frames that carried padding or no data or ended the stream, and how its
/// trailers' header block went.
///
/// A response sent with a [`SendBodyLayout`] goes so: ahead of each chunk of its body go
/// the empty DATA frames the layout has there, the chunk takes its frame's padding when
/// their lengths match, and its end goes in a frame of its own when the layout's did. A
/// padded frame the peer's frame size or flow control can't take whole goes split, data
/// first, its padding kept. Its trailers' header block goes as [`HeaderBlockEncoding`]
/// says.
pub trait BodyLayout: Send + Sync {
    /// Removes and returns the DATA frames it holds that went no later than the DATA
    /// frame carrying data at `through`, or every one given `None`.
    fn take(&self, through: Option<u64>) -> Vec<DataFrame>;

    /// Takes how the trailers' header block went, once it arrived.
    fn take_trailers(&self) -> Option<HeaderBlockEncoding>;

    /// Tells that the body's chunks didn't match the DATA frames [`Self::take`] gave, so
    /// those went laid out otherwise: the ones carrying padding or nothing as empty frames
    /// of their own, so that the peer's flow control still takes what the other
    /// connection's did.
    fn misplaced(&self) {}

    /// Tells that the stream was reset once `sent` octets of flow-controlled data went on
    /// it: the rest of the body doesn't go.
    fn reset(&self, _sent: u64) {}
}

/// A response extension sending its body as a [`BodyLayout`] says.
#[derive(Clone)]
pub struct SendBodyLayout(pub Arc<dyn BodyLayout>);

impl fmt::Debug for SendBodyLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("SendBodyLayout(..)")
    }
}

/// The parameters a server connection taking a [`DeferredPreface`] sends, and enforces,
/// for `params`: its preface's SETTINGS (`preface`, see [`PrefaceFrame::Settings`]), or one
/// it relays ([`RelayedFrame::Settings`]). As given, but past the most it takes, as that:
/// HEADER_TABLE_SIZE past 1 MiB, MAX_HEADER_LIST_SIZE past 16 MiB, and
/// MAX_CONCURRENT_STREAMS past the most it was built to accept (`max_concurrent_streams`,
/// see [`server::Builder::max_concurrent_streams`](crate::server::Builder::max_concurrent_streams)),
/// which its preface's also gets when it has none. A caller relaying another peer's
/// SETTINGS can tell from it where the client's diverge.
pub fn sent_settings(
    params: &[(u16, u32)],
    max_concurrent_streams: Option<u32>,
    preface: bool,
) -> Vec<(u16, u32)> {
    crate::frame::sent_params(params, max_concurrent_streams, preface)
}

/// A frame of a server's connection preface a [`DeferredPreface`] supplies: its SETTINGS,
/// as given (but see [`sent_settings`]), and the frames right after it.
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
            relay: Relay(Arc::default(), FrameLog::new(0)),
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
    /// The GOAWAYs still to send, in order, at most [`RELAYED_GO_AWAYS`].
    go_aways: VecDeque<RelayedGoAway>,
    close: bool,
    task: Option<Waker>,
    /// How many GOAWAYs were relayed, and the number of the last that went.
    relayed: u64,
    sent: u64,
    /// The tasks waiting for one to go (see [`RelayedEnd::poll_sent`]).
    sent_tasks: Vec<Waker>,
    /// The bytes the connection wrote to the client (see [`RelayedEnd::written`]).
    written: Arc<std::sync::atomic::AtomicU64>,
}

/// A GOAWAY to send (see [`RelayedEnd::go_away`]): its last stream id, error code and
/// debug data, the client's streams the other connection carried that it leaves
/// unprocessed, sorted, and its number.
#[derive(Debug)]
pub(crate) struct RelayedGoAway {
    pub(crate) last_stream_id: u32,
    pub(crate) error_code: u32,
    pub(crate) debug_data: Bytes,
    pub(crate) refused: Vec<u32>,
    pub(crate) number: u64,
}

/// How many GOAWAYs a [`RelayedEnd`] holds unsent; one past them merges into the last.
const RELAYED_GO_AWAYS: usize = 4;

impl RelayedEnd {
    /// An end nothing was relayed of yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends a GOAWAY of `error_code` and `debug_data` the other connection sent naming
    /// `last_stream_id`, the client's streams it carried past that, still open, being
    /// `refused`. The GOAWAY names the latest stream the client opened that isn't refused
    /// when later (one another connection carried, or answered without one, which went on
    /// regardless), or, when earlier, the stream the GOAWAY it sent before named; each
    /// refused stream, and each open one past the stream it names, is refused
    /// (REFUSED_STREAM), as unprocessed. The connection then accepts no later stream, and
    /// stays open until [`Self::close`] or the client closes it.
    ///
    /// Each goes out once the frames queued before it went. Past four waiting so, a GOAWAY
    /// merges into the last: that one then names the lower last stream id of the two, with
    /// this one's error code, debug data and number, refusing the streams either refuses.
    ///
    /// Returns its number (one more than the last's), for [`Self::poll_sent`].
    pub fn go_away(
        &self,
        last_stream_id: u32,
        error_code: u32,
        debug_data: Bytes,
        mut refused: Vec<u32>,
    ) -> u64 {
        refused.sort_unstable();
        refused.dedup();
        let mut inner = self.lock();
        inner.relayed += 1;
        let number = inner.relayed;
        let waiting = inner.go_aways.len();
        match inner.go_aways.back_mut() {
            Some(last) if waiting >= RELAYED_GO_AWAYS => {
                last.last_stream_id = last.last_stream_id.min(last_stream_id);
                last.error_code = error_code;
                last.debug_data = debug_data;
                last.refused.extend(refused);
                last.refused.sort_unstable();
                last.refused.dedup();
                last.number = number;
            }
            _ => inner.go_aways.push_back(RelayedGoAway {
                last_stream_id,
                error_code,
                debug_data,
                refused,
                number,
            }),
        }
        inner.wake();
        number
    }

    /// Ready once the GOAWAY numbered `number` (see [`Self::go_away`]), or one merged with
    /// it or after it, went: written after the frames queued before it and ahead of those
    /// queued from then on. Also ready once the connection is gone.
    pub fn poll_sent(&self, cx: &mut Context<'_>, number: u64) -> Poll<()> {
        let mut inner = self.lock();
        if inner.sent >= number {
            return Poll::Ready(());
        }
        if !inner
            .sent_tasks
            .iter()
            .any(|task| task.will_wake(cx.waker()))
        {
            inner.sent_tasks.push(cx.waker().clone());
        }
        Poll::Pending
    }

    /// How many bytes the connection wrote to the client so far: while it reads none, a
    /// GOAWAY waiting for the frames queued before it (see [`Self::poll_sent`]) doesn't go.
    pub fn written(&self) -> u64 {
        self.lock()
            .written
            .load(std::sync::atomic::Ordering::Relaxed)
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

    /// Whether to close once idle and the GOAWAYs went; `cx` is woken when either changes.
    pub(crate) fn poll_close(&self, cx: &mut Context<'_>) -> bool {
        let mut inner = self.lock();
        inner.task = Some(cx.waker().clone());
        inner.close
    }

    /// The counter of the bytes the connection writes (see [`Self::written`]).
    pub(crate) fn written_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.lock().written)
    }

    /// Takes the next GOAWAY to send, the connection having sent the frames queued before.
    pub(crate) fn take_go_away(&self) -> Option<RelayedGoAway> {
        self.lock().go_aways.pop_front()
    }

    /// Notes that the GOAWAY numbered `number` went (`u64::MAX`: the connection is gone).
    pub(crate) fn sent(&self, number: u64) {
        let mut inner = self.lock();
        inner.sent = inner.sent.max(number);
        inner.sent_tasks.drain(..).for_each(Waker::wake);
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

    /// The [`FrameLog`] of the connection taking this preface, from before it reads the
    /// client's preface, when built to record frames (see
    /// [`record_frames`](crate::server::Builder::record_frames)); otherwise it logs none.
    pub fn frame_log(&self) -> FrameLog {
        self.relay.1.clone()
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
    /// included (but see [`sent_settings`]), whatever SETTINGS sent before await
    /// acknowledgement. The known parameters apply to the connection as its own once the
    /// client acknowledges it.
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
    /// A PRIORITY frame, sent as given.
    Priority {
        /// The client's stream the priority applies to.
        stream_id: u32,
        /// The priority it sets.
        priority: StreamPriority,
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
    /// The acknowledgement of the client's earliest SETTINGS frame awaiting one (see
    /// [`Relay::relay_acks`]), which applies as it goes out. None when none awaits one.
    SettingsAck,
    /// The acknowledgement of the client's PING carrying this payload (see
    /// [`Relay::relay_acks`]). None when no such PING awaits one.
    PingAck([u8; 8]),
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
#[derive(Clone, Debug)]
pub struct Relay(Arc<Mutex<RelayInner>>, FrameLog);

#[derive(Debug, Default)]
struct RelayInner {
    frames: VecDeque<RelayedFrame>,
    /// The octets of the payloads of the SETTINGS and unknown frames among them.
    octets: usize,
    task: Option<Waker>,
    /// The caller's task waiting for room (see [`Relay::poll_ready`]).
    ready: Option<Waker>,
    on_ack: Option<AckHook>,
    /// Whether the client's SETTINGS and PINGs await relayed acknowledgements (see
    /// [`Relay::relay_acks`]), and whether its PINGs no longer do (see
    /// [`Relay::release_pings`]).
    relays_acks: bool,
    releases_pings: bool,
    /// The client's streams whose windows grow only by relayed WINDOW_UPDATEs from the
    /// data they release next on, each with whether the relaying peer is sent the padding
    /// they receive (see [`Relay::mirror_stream_window`]).
    mirrored: HashMap<u32, bool>,
    /// The padding the client's streams received that the relaying peer isn't sent, by
    /// stream, which grows their windows here (see [`Relay::release_padding`]).
    released_padding: Vec<(u32, u32)>,
    /// The octets of data the relaying peer was sent so far (see [`Relay::set_peer_sent`]).
    peer_sent: u64,
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

/// How many frames sent through a [`Relay`] await the connection at most, and the octets
/// of the SETTINGS and unknown frames' payloads among them, before it has no room (see
/// [`Relay::poll_ready`]).
const RELAYED_FRAMES: usize = 1024;
const RELAYED_OCTETS: usize = 1 << 20;

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
        inner.octets += match &frame {
            RelayedFrame::Settings(params) => params.len() * 6,
            RelayedFrame::Unknown { payload, .. } => payload.len(),
            _ => 0,
        };
        inner.frames.push_back(frame);
        inner.wake();
    }

    /// Ready once the frames sent (see [`Self::send`]) leave room for more, or the
    /// connection ended: at most 1,024 of them, or 1 MiB of SETTINGS and unknown frames'
    /// payloads, await the connection, which takes them as the client reads what it sent
    /// before, so a client slow to read holds the caller back rather than more frames.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> std::task::Poll<()> {
        let mut inner = self.lock();
        if inner.closed || (inner.frames.len() < RELAYED_FRAMES && inner.octets < RELAYED_OCTETS) {
            return std::task::Poll::Ready(());
        }
        inner.ready = Some(cx.waker().clone());
        std::task::Poll::Pending
    }

    /// Grows the receive window of the client's stream `stream_id`, mirrored (see
    /// [`Self::mirror_stream_window`]), and the connection's, by `octets` of the padding it
    /// received (pad length fields included) that the relaying peer wasn't sent, so whose
    /// WINDOW_UPDATEs don't grow them by it.
    pub fn release_padding(&self, stream_id: u32, octets: u32) {
        let mut inner = self.lock();
        inner.released_padding.push((stream_id, octets));
        inner.wake();
    }

    /// Leaves acknowledging the client's SETTINGS and PINGs from now on to the relaying
    /// peer, whose acknowledgements of them the frames relayed carry
    /// ([`RelayedFrame::SettingsAck`], [`RelayedFrame::PingAck`]): a SETTINGS frame then
    /// applies as its acknowledgement goes out. Those the client sends before its first
    /// request are still acknowledged at once, unless logged after
    /// [`Self::forward_from_now`]. Ends with [`Self::ack_locally`]. Those it sends after its
    /// first request go to the relaying peer, even while the connection acknowledges them
    /// itself: the relayed acknowledgements of those are dropped.
    pub fn relay_acks(&self) {
        self.set_relays_acks(true);
    }

    /// Makes the client's SETTINGS and PINGs the connection's [`FrameLog`] (see
    /// [`DeferredPreface::frame_log`]) logs from now on go to the relaying peer, as those
    /// after its first request do, before that request too: how many frames it logged
    /// before, which it handles as before. Calls after the first change nothing and tell
    /// the same number.
    pub fn forward_from_now(&self) -> u64 {
        self.1.forward_from_now()
    }

    /// Whether the client's latest frame logged came after [`Self::forward_from_now`].
    pub(crate) fn forwards_latest(&self) -> bool {
        self.1.forwards_latest()
    }

    /// Makes the connection acknowledge the client's SETTINGS and PINGs itself again, at
    /// once those awaiting a relayed acknowledgement: once no peer relays them.
    pub fn ack_locally(&self) {
        self.set_relays_acks(false);
    }

    fn set_relays_acks(&self, relays_acks: bool) {
        let mut inner = self.lock();
        inner.relays_acks = relays_acks;
        if let Some(task) = inner.task.take() {
            task.wake();
        }
    }

    /// Leaves the client's PINGs awaiting a relayed acknowledgement unacknowledged, as the
    /// relaying peer left them, rather than have them hold back its frames (see
    /// [`Self::relay_acks`]), and those it sends from now on until the connection
    /// acknowledges them itself ([`Self::ack_locally`]); an acknowledgement still relayed
    /// goes on.
    pub fn release_pings(&self) {
        let mut inner = self.lock();
        inner.releases_pings = true;
        if let Some(task) = inner.task.take() {
            task.wake();
        }
    }

    /// Makes the receive window of the client's stream `stream_id` grow only by the
    /// relayed WINDOW_UPDATEs ([`RelayedFrame::WindowUpdate`]) from the data it releases
    /// next on, rather than by that data, as the relaying peer's window does once that data
    /// went on to it; by its padding too, as it comes, unless `relays_padding` says the
    /// relaying peer is sent that as well, whose WINDOW_UPDATEs then grow it by that (see
    /// [`Self::release_padding`] for the padding it isn't sent after all).
    pub fn mirror_stream_window(&self, stream_id: u32, relays_padding: bool) {
        self.lock().mirrored.insert(stream_id, relays_padding);
    }

    /// Tells that the relaying peer was sent `octets` of flow-controlled data so far, the
    /// data the client's streams released after [`Self::mirror_stream_window`] among it,
    /// so that the relayed connection WINDOW_UPDATEs ([`RelayedFrame::WindowUpdate`] of
    /// stream 0) from now on grow the connection's window only by what they grant past
    /// the rest: the client's window then tracks the peer's.
    pub fn set_peer_sent(&self, octets: u64) {
        self.lock().peer_sent = octets;
    }

    /// The octets of data the relaying peer was sent so far (see [`Self::set_peer_sent`]).
    pub(crate) fn peer_sent(&self) -> u64 {
        self.lock().peer_sent
    }

    /// Whether the client's SETTINGS and PINGs await relayed acknowledgements.
    pub(crate) fn relays_acks(&self) -> bool {
        self.lock().relays_acks
    }

    /// Whether the client's PINGs await relayed acknowledgements no longer (see
    /// [`Self::release_pings`]).
    pub(crate) fn releases_pings(&self) -> bool {
        self.lock().releases_pings
    }

    /// Whether `stream_id`'s window was made to grow only by relayed WINDOW_UPDATEs since
    /// last asked, and if so whether the relaying peer is sent its padding (see
    /// [`Self::mirror_stream_window`]).
    pub(crate) fn take_mirrored(&self, stream_id: u32) -> Option<bool> {
        self.lock().mirrored.remove(&stream_id)
    }

    /// The streams made to grow only by relayed WINDOW_UPDATEs since last asked (see
    /// [`Self::take_mirrored`]).
    pub(crate) fn take_all_mirrored(&self) -> HashMap<u32, bool> {
        std::mem::take(&mut self.lock().mirrored)
    }

    /// The padding the client's streams received that the relaying peer wasn't sent, told
    /// since last asked (see [`Self::release_padding`]).
    pub(crate) fn take_released_padding(&self) -> Vec<(u32, u32)> {
        std::mem::take(&mut self.lock().released_padding)
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
        inner.octets = 0;
        if let Some(ready) = inner.ready.take() {
            ready.wake();
        }
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
        inner.mirrored.clear();
        inner.released_padding.clear();
        if let Some(ready) = inner.ready.take() {
            ready.wake();
        }
    }
}

impl RelayInner {
    /// Wakes the connection's task.
    fn wake(&mut self) {
        if let Some(task) = self.task.take() {
            task.wake();
        }
    }
}
