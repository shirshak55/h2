use crate::codec::UserError;
use crate::frame::{Reason, StreamId};
use crate::{client, server};

use crate::ext::{DeferredPreface, PrefaceFrame, Relay, RelayedAck, RelayedEnd, RelayedFrame};
use crate::frame::DEFAULT_INITIAL_WINDOW_SIZE;
use crate::proto::ping_pong::ReceivedPing;
use crate::proto::*;

use bytes::{BufMut, Bytes, BytesMut};
use futures_core::Stream;
use std::collections::VecDeque;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncRead;

/// How many relayed SETTINGS frames, or PINGs, may await the client's ACKs at once: those
/// past them wait, so that the relaying caller waits too (see `Relay::poll_ready`).
const MAX_RELAYED_WAITING: usize = 1024;

/// An H2 connection
#[derive(Debug)]
pub(crate) struct Connection<T, P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Read / write frame values
    codec: Codec<T, Prioritized<B>>,

    /// The preface still to send, while writes wait for it (see
    /// `server::Builder::deferred_preface`).
    deferred_preface: Option<DeferredPreface>,

    /// Whether the peer's GOAWAY leaves closing to the peer (see
    /// `server::Builder::leave_close_to_client`).
    leave_close_to_client: bool,

    /// The end of another connection it ends as (see `server::Builder::relayed_end`),
    /// whether it closed, and the number of the relayed GOAWAY waiting to be written.
    relayed_end: Option<RelayedEnd>,
    relayed_close: bool,
    relayed_unsent: Option<u64>,

    /// The frames relayed to the peer after the deferred preface (see `Relay`), and those
    /// taken from it still to send.
    relay: Option<Relay>,
    relayed: VecDeque<RelayedFrame>,

    /// The most streams the peer may open at once that the connection was built to accept,
    /// past which relayed SETTINGS, and the deferred preface's, can't raise it.
    max_concurrent_streams: Option<u32>,

    inner: ConnectionInner<P, B>,
}

// Extracted part of `Connection` which does not depend on `T`. Reduces the amount of duplicated
// method instantiations.
#[derive(Debug)]
struct ConnectionInner<P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Tracks the connection level state transitions.
    state: State,

    /// An error to report back once complete.
    ///
    /// This exists separately from State in order to support
    /// graceful shutdown.
    error: Option<frame::GoAway>,

    /// Pending GOAWAY frames to write.
    go_away: GoAway,

    /// Ping/pong handler
    ping_pong: PingPong,

    /// Connection settings
    settings: Settings,

    /// Stream state handler
    streams: Streams<B, P>,

    /// A `tracing` span tracking the lifetime of the connection.
    span: tracing::Span,

    /// Client or server
    _phantom: PhantomData<P>,
}

struct DynConnection<'a, B: Buf = Bytes> {
    state: &'a mut State,

    go_away: &'a mut GoAway,

    streams: DynStreams<'a, B>,

    error: &'a mut Option<frame::GoAway>,

    ping_pong: &'a mut PingPong,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub next_stream_id: StreamId,
    pub initial_max_send_streams: usize,
    pub max_send_buffer_size: usize,
    pub reset_stream_duration: Duration,
    pub reset_stream_max: usize,
    pub remote_reset_stream_max: usize,
    pub local_error_reset_streams_max: Option<usize>,
    pub settings: frame::Settings,
    pub data_frame_budget: usize,
    pub deferred_preface: Option<DeferredPreface>,
    pub leave_close_to_client: bool,
    pub relayed_end: Option<RelayedEnd>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DataFrameBudget {
    Auto,
    Configured(usize),
}

impl DataFrameBudget {
    pub(crate) fn resolve(self, connection_window: Option<WindowSize>) -> usize {
        match self {
            Self::Configured(budget) => budget,
            Self::Auto => {
                let window = connection_window.unwrap_or(DEFAULT_INITIAL_WINDOW_SIZE);
                let budget = window as usize / 2;

                budget.max(DEFAULT_DATA_FRAME_BUDGET)
            }
        }
    }
}

#[derive(Debug)]
enum State {
    /// Currently open in a sane state
    Open,

    /// The codec must be flushed
    Closing(Reason, Initiator),

    /// In a closed state
    Closed(Reason, Initiator),
}

impl<T, P, B> Connection<T, P, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    P: Peer,
    B: Buf,
{
    pub fn new(mut codec: Codec<T, Prioritized<B>>, config: Config) -> Connection<T, P, B> {
        fn streams_config(config: &Config) -> streams::Config {
            streams::Config {
                initial_max_send_streams: config.initial_max_send_streams,
                local_max_buffer_size: config.max_send_buffer_size,
                local_next_stream_id: config.next_stream_id,
                local_push_enabled: config.settings.is_push_enabled().unwrap_or(true),
                extended_connect_protocol_enabled: config
                    .settings
                    .is_extended_connect_protocol_enabled()
                    .unwrap_or(false),
                local_reset_duration: config.reset_stream_duration,
                local_reset_max: config.reset_stream_max,
                remote_reset_max: config.remote_reset_stream_max,
                remote_init_window_sz: DEFAULT_INITIAL_WINDOW_SIZE,
                remote_max_initiated: config
                    .settings
                    .max_concurrent_streams()
                    .map(|max| max as usize),
                local_max_error_reset_streams: config.local_error_reset_streams_max,
                data_frame_budget: config.data_frame_budget,
            }
        }
        let mut streams = Streams::new(streams_config(&config));
        if let Some(preface) = &config.deferred_preface {
            streams.set_relay(preface.relay());
        }
        if let Some(end) = &config.relayed_end {
            codec.count_written(end.written_counter());
        }
        let span = tracing::debug_span!(parent: None, "Connection", peer = %P::NAME);
        span.follows_from(tracing::Span::current());
        Connection {
            codec,
            relay: config.deferred_preface.as_ref().map(DeferredPreface::relay),
            relayed: VecDeque::new(),
            max_concurrent_streams: config.settings.max_concurrent_streams(),
            deferred_preface: config.deferred_preface,
            leave_close_to_client: config.leave_close_to_client,
            relayed_end: config.relayed_end,
            relayed_close: false,
            relayed_unsent: None,
            inner: ConnectionInner {
                state: State::Open,
                error: None,
                go_away: GoAway::new(),
                ping_pong: PingPong::new(),
                settings: Settings::new(config.settings),
                streams,
                span,
                _phantom: PhantomData,
            },
        }
    }

    /// connection flow control
    pub(crate) fn set_target_window_size(&mut self, size: WindowSize) {
        let _res = self.inner.streams.set_target_connection_window_size(size);
        // TODO: proper error handling
        debug_assert!(_res.is_ok());
    }

    /// Send a new SETTINGS frame with an updated initial window size.
    pub(crate) fn set_initial_window_size(&mut self, size: WindowSize) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(size));
        self.inner.settings.send_settings(settings)
    }

    /// Send a new SETTINGS frame with extended CONNECT protocol enabled.
    pub(crate) fn set_enable_connect_protocol(&mut self) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_enable_connect_protocol(Some(1));
        self.inner.settings.send_settings(settings)
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by this peer.
    pub(crate) fn max_send_streams(&self) -> usize {
        self.inner.streams.max_send_streams()
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by the remote peer.
    pub(crate) fn max_recv_streams(&self) -> usize {
        self.inner.streams.max_recv_streams()
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        self.inner.streams.num_wired_streams()
    }

    /// Returns `Ready` when the connection is ready to receive a frame.
    ///
    /// Returns `Error` as this may raise errors that are caused by delayed
    /// processing of received frames.
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        let _e = self.inner.span.enter();
        let span = tracing::trace_span!("poll_ready");
        let _e = span.enter();
        // The order of these calls don't really matter too much
        ready!(self.inner.ping_pong.send_pending_pong(cx, &mut self.codec))?;
        ready!(self.inner.ping_pong.send_pending_ping(cx, &mut self.codec))?;
        ready!(self
            .inner
            .settings
            .poll_send(cx, &mut self.codec, &mut self.inner.streams))?;
        ready!(self.inner.streams.send_pending_refusal(cx, &mut self.codec))?;

        Poll::Ready(Ok(()))
    }

    /// Applies the relay's asks to mirror the client's streams' windows and to grow them by
    /// padding (see `Relay::mirror_stream_window`, `Relay::release_padding`), ahead of the
    /// WINDOW_UPDATEs due, so that none goes out for what the relaying peer grants.
    fn apply_relayed_windows(&mut self) {
        let Some(relay) = &self.relay else {
            return;
        };
        for (stream_id, relays_padding) in relay.take_all_mirrored() {
            self.inner
                .streams
                .mirror_stream_window(stream_id.into(), relays_padding);
        }
        for (stream_id, octets) in relay.take_released_padding() {
            self.inner.streams.release_padding(stream_id.into(), octets);
        }
    }

    /// Sends the frames relayed so far (see `Relay`), in order, once the deferred preface
    /// went out, and the acknowledgements due of the client's SETTINGS and PINGs no longer
    /// awaiting relayed ones; pending, so that the connection reads no more of the client's
    /// frames, while as many of its PINGs as may await relayed ACKs do, unless it owes
    /// ACKs of the frames relayed, which it would otherwise never send.
    fn poll_relay(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        let Some(relay) = &self.relay else {
            return Poll::Ready(Ok(()));
        };
        let relays_acks = self.inner.set_forwarding(relay);
        if self.deferred_preface.is_some() {
            return Poll::Ready(Ok(()));
        }
        if !relays_acks {
            while self.inner.settings.is_awaiting() {
                ready!(self.codec.poll_ready(cx))?;
                self.inner
                    .settings
                    .ack_awaiting(&mut self.codec, &mut self.inner.streams)?;
            }
            while let Some(payload) = self.inner.ping_pong.first_awaiting() {
                ready!(self.codec.poll_ready(cx))?;
                self.inner.ping_pong.ack_awaiting();
                self.codec
                    .buffer(frame::Ping::pong(payload).into())
                    .expect("invalid ping frame");
            }
        }
        // Taken once those taken before went, so that a client slow to read holds the
        // relaying caller back (see `Relay::poll_ready`).
        loop {
            if self.relayed.is_empty() {
                self.relayed = relay.poll_take(cx);
                if self.relayed.is_empty() {
                    break;
                }
            }
            // A relayed SETTINGS frame or PING waits while as many as may await the
            // client's ACKs do.
            match self.relayed.front() {
                Some(RelayedFrame::Settings(_))
                    if self.inner.settings.relayed_waiting() >= MAX_RELAYED_WAITING =>
                {
                    break
                }
                Some(RelayedFrame::Ping(_))
                    if self.inner.ping_pong.relayed_waiting() >= MAX_RELAYED_WAITING =>
                {
                    break
                }
                _ => {}
            }
            ready!(self.codec.poll_ready(cx))?;
            match self.relayed.pop_front().expect("a frame is relayed") {
                RelayedFrame::Settings(params) => {
                    let mut settings = frame::Settings::default();
                    let params = frame::sent_params(&params, self.max_concurrent_streams, false);
                    settings.set_wire(params).map_err(|_| {
                        Error::library_go_away_data(
                            Reason::INTERNAL_ERROR,
                            "invalid_relayed_settings",
                        )
                    })?;
                    self.codec
                        .buffer(settings.clone().into())
                        .expect("invalid settings frame");
                    // The client may open streams up to a raise before it acknowledges it.
                    if let Some(max) = settings.max_concurrent_streams() {
                        let max = (max as usize).max(self.inner.streams.max_recv_streams());
                        self.inner.streams.set_max_recv_streams(max);
                    }
                    if settings.is_extended_connect_protocol_enabled() == Some(true) {
                        self.inner.streams.enable_connect_protocol();
                    }
                    self.inner.settings.sent_relayed(settings);
                }
                RelayedFrame::Ping(payload) => {
                    self.codec
                        .buffer(frame::Ping::new(payload).into())
                        .expect("invalid ping frame");
                    self.inner.ping_pong.sent_relayed(payload);
                }
                RelayedFrame::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    let stream_id = StreamId::from(stream_id);
                    if let Some(increment) =
                        self.inner.streams.relay_window_update(stream_id, increment)
                    {
                        self.codec
                            .buffer(frame::WindowUpdate::new(stream_id, increment).into())
                            .expect("invalid window update frame");
                    }
                }
                RelayedFrame::Unknown {
                    kind,
                    flags,
                    stream_id,
                    payload,
                } => {
                    let mut frame = BytesMut::with_capacity(frame::HEADER_LEN + payload.len());
                    frame.put_uint(payload.len() as u64, 3);
                    frame.put_u8(kind);
                    frame.put_u8(flags);
                    frame.put_u32(stream_id);
                    frame.put(payload);
                    self.codec.buffer_raw(&frame);
                }
                RelayedFrame::SettingsAck => self
                    .inner
                    .settings
                    .recv_relayed_ack(&mut self.codec, &mut self.inner.streams)?,
                RelayedFrame::PingAck(payload) => {
                    if self.inner.ping_pong.take_awaiting(&payload) {
                        self.codec
                            .buffer(frame::Ping::pong(payload).into())
                            .expect("invalid ping frame");
                    }
                }
            }
        }
        // Woken as more frames are relayed (see `Relay::poll_take`).
        if self.relayed.is_empty()
            && self.inner.ping_pong.is_awaiting_full()
            && self.inner.ping_pong.relayed_waiting() == 0
            && self.inner.settings.relayed_waiting() == 0
        {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    /// Send any pending GOAWAY frames.
    ///
    /// This will return `Some(reason)` if the connection should be closed
    /// afterwards. If this is a graceful shutdown, this returns `None`.
    fn poll_go_away(&mut self, cx: &mut Context) -> Poll<Option<io::Result<Reason>>> {
        let polled = self.inner.go_away.send_pending_go_away(cx, &mut self.codec);
        if !self.inner.go_away.is_sending() {
            if let (Some(number), Some(relayed)) = (self.relayed_unsent, &self.relayed_end) {
                relayed.sent(number);
                self.relayed_unsent = None;
            }
        }
        polled
    }

    pub fn go_away_from_user(&mut self, e: Reason) {
        self.inner.as_dyn().go_away_from_user(e)
    }

    fn take_error(&mut self, ours: Reason, initiator: Initiator) -> Result<(), Error> {
        let (debug_data, theirs) = self
            .inner
            .error
            .take()
            .as_ref()
            .map_or((Bytes::new(), Reason::NO_ERROR), |frame| {
                (frame.debug_data().clone(), frame.reason())
            });

        match (ours, theirs) {
            (Reason::NO_ERROR, Reason::NO_ERROR) => Ok(()),
            (ours, Reason::NO_ERROR) => Err(Error::GoAway(Bytes::new(), ours, initiator)),
            // If both sides reported an error, give their
            // error back to th user. We assume our error
            // was a consequence of their error, and less
            // important.
            (_, theirs) => Err(Error::remote_go_away(debug_data, theirs)),
        }
    }

    /// Closes the connection by transitioning to a GOAWAY state
    /// iff there are no streams or references
    pub fn maybe_close_connection_if_no_streams(&mut self) {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        if !self.inner.streams.has_streams_or_other_references() {
            self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
        }
    }

    /// Checks if there are any streams
    pub fn has_streams(&self) -> bool {
        self.inner.streams.has_streams()
    }

    /// Checks if there are any streams or references left
    pub fn has_streams_or_other_references(&self) -> bool {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        self.inner.streams.has_streams_or_other_references()
    }

    pub(crate) fn take_user_pings(&mut self) -> Option<UserPings> {
        self.inner.ping_pong.take_user_pings()
    }

    /// Advances the internal state of the connection.
    pub fn poll(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // XXX(eliza): cloning the span is unfortunately necessary here in
        // order to placate the borrow checker — `self` is mutably borrowed by
        // `poll2`, which means that we can't borrow `self.span` to enter it.
        // The clone is just an atomic ref bump.
        let span = self.inner.span.clone();
        let _e = span.enter();
        let span = tracing::trace_span!("poll");
        let _e = span.enter();

        if let Some(deferred) = &mut self.deferred_preface {
            if let Poll::Ready(frames) = deferred.poll_frames(cx) {
                self.deferred_preface = None;
                self.send_preface(frames)?;
            }
        }

        if let Some(relayed) = &self.relayed_end {
            self.relayed_close = relayed.poll_close(cx);
        }

        loop {
            tracing::trace!(connection.state = ?self.inner.state);
            // TODO: probably clean up this glob of code
            match self.inner.state {
                // When open, continue to poll a frame
                State::Open => {
                    let result = match self.poll2(cx) {
                        Poll::Ready(result) => result,
                        // The connection is not ready to make progress
                        Poll::Pending => {
                            // Ensure all window updates have been sent.
                            //
                            // This will also handle flushing `self.codec`
                            ready!(self.inner.streams.poll_complete(cx, &mut self.codec))?;

                            // Each relayed GOAWAY goes once the frames queued before it went.
                            if let Some(go_away) =
                                self.relayed_end.as_ref().and_then(RelayedEnd::take_go_away)
                            {
                                self.inner.as_dyn().relay_go_away(
                                    go_away.last_stream_id.into(),
                                    go_away.error_code.into(),
                                    go_away.debug_data,
                                    &go_away.refused,
                                );
                                self.relayed_unsent = Some(go_away.number);
                                continue;
                            }

                            if ((self.inner.error.is_some() && !self.leave_close_to_client)
                                || self.inner.go_away.should_close_on_idle())
                                && !self.inner.streams.has_streams()
                            {
                                self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
                                continue;
                            }

                            if self.relayed_close
                                && !self.inner.go_away.is_sending()
                                && !self.inner.streams.has_streams()
                            {
                                self.inner.state =
                                    State::Closing(Reason::NO_ERROR, Initiator::Library);
                                continue;
                            }

                            return Poll::Pending;
                        }
                    };

                    self.inner.as_dyn().handle_poll2_result(result)?
                }
                State::Closing(reason, initiator) => {
                    tracing::trace!("connection closing after flush");
                    // Flush/shutdown the codec
                    ready!(self.codec.shutdown(cx))?;

                    // Transition the state to error
                    self.inner.state = State::Closed(reason, initiator);
                }
                State::Closed(reason, initiator) => {
                    return Poll::Ready(self.take_error(reason, initiator));
                }
            }
        }
    }

    /// Writes a deferred preface: its SETTINGS (the configured one when `frames` has
    /// none) and the frames after it, ahead of everything buffered meanwhile, and applies
    /// the SETTINGS as this connection's own.
    fn send_preface(&mut self, frames: Vec<PrefaceFrame>) -> Result<(), Error> {
        let mut settings = self
            .inner
            .settings
            .replace_pending_local(frame::Settings::default());
        let mut front = BytesMut::new();
        let mut window = None;
        let mut sent_settings = false;
        for frame in frames {
            match frame {
                PrefaceFrame::Settings(params) => {
                    let params = frame::sent_params(&params, self.max_concurrent_streams, true);
                    settings.set_wire(params).map_err(|_| {
                        Error::library_go_away_data(
                            Reason::INTERNAL_ERROR,
                            "invalid_preface_settings",
                        )
                    })?;
                    settings.encode(&mut front);
                    sent_settings = true;
                }
                PrefaceFrame::WindowUpdate(incr) => {
                    frame::WindowUpdate::new(StreamId::zero(), incr).encode(&mut front);
                    window = Some(window.unwrap_or(0) + incr);
                }
                PrefaceFrame::Unknown {
                    kind,
                    flags,
                    stream_id,
                    payload,
                } => {
                    front.put_uint(payload.len() as u64, 3);
                    front.put_u8(kind);
                    front.put_u8(flags);
                    front.put_u32(stream_id);
                    front.put(payload);
                }
            }
        }
        if !sent_settings {
            let mut first = BytesMut::new();
            settings.encode(&mut first);
            first.unsplit(front);
            front = first;
        }
        self.inner
            .streams
            .apply_preface(&settings, window)
            .map_err(Error::library_go_away)?;
        self.inner.settings.replace_pending_local(settings);
        self.codec.release_writes(front);
        Ok(())
    }

    fn poll2(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // This happens outside of the loop to prevent needing to do a clock
        // check and then comparison of the queue possibly multiple times a
        // second (and thus, the clock wouldn't have changed enough to matter).
        self.clear_expired_reset_streams();

        loop {
            // First, ensure that the `Connection` is able to receive a frame
            //
            // The order here matters:
            // - poll_go_away may buffer a graceful shutdown GOAWAY frame
            // - If it has, we've also added a PING to be sent in poll_ready
            if let Some(reason) = ready!(self.poll_go_away(cx)?) {
                if self.inner.go_away.should_close_now() {
                    if self.inner.go_away.is_user_initiated() {
                        // A user initiated abrupt shutdown shouldn't return
                        // the same error back to the user.
                        return Poll::Ready(Ok(()));
                    } else {
                        return Poll::Ready(Err(Error::library_go_away(reason)));
                    }
                }
                // Only NO_ERROR should be waiting for idle, but a relayed GOAWAY's
                debug_assert!(
                    reason == Reason::NO_ERROR || self.inner.go_away.is_relayed(),
                    "graceful GOAWAY should be NO_ERROR"
                );
            }
            self.apply_relayed_windows();
            ready!(self.poll_ready(cx))?;
            ready!(self.poll_relay(cx))?;
            // No more frames while the data received waits to be taken (see
            // `Recv::poll_buffered_room`).
            ready!(self.inner.streams.poll_buffered_room(cx));

            let frame = ready!(Pin::new(&mut self.codec).poll_next(cx)?);
            if let (Some(relay), Some(Frame::Settings(_) | Frame::Ping(_))) = (&self.relay, &frame)
            {
                self.inner.set_forwarding(relay);
            }
            match self.inner.as_dyn().recv_frame(frame)? {
                ReceivedFrame::Settings(frame) => {
                    if self.inner.settings.recv_settings(
                        frame,
                        &mut self.codec,
                        &mut self.inner.streams,
                    )? {
                        self.relay_acked(RelayedAck::Settings);
                    }
                }
                ReceivedFrame::RelayedAck(ack) => self.relay_acked(ack),
                ReceivedFrame::Continue => (),
                ReceivedFrame::Done => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn clear_expired_reset_streams(&mut self) {
        self.inner.streams.clear_expired_reset_streams();
    }

    fn relay_acked(&self, ack: RelayedAck) {
        if let Some(relay) = &self.relay {
            relay.acked(ack);
        }
    }
}

impl<P, B> ConnectionInner<P, B>
where
    P: Peer,
    B: Buf,
{
    /// Tells whether the client's SETTINGS and PINGs from now on go to the relaying peer,
    /// and whether they await its ACKs, which it returns: those sent before its first
    /// request (its preface's) are acknowledged here, the relaying peer having acknowledged
    /// its own peer's, unless logged after `Relay::forward_from_now`.
    fn set_forwarding(&mut self, relay: &Relay) -> bool {
        let forwards =
            !self.streams.as_dyn().last_processed_id().is_zero() || relay.forwards_latest();
        let relays_acks = relay.relays_acks() && forwards;
        self.settings.set_relays_acks(relays_acks, forwards);
        self.ping_pong.set_relays_acks(relays_acks, forwards);
        relays_acks
    }

    fn as_dyn(&mut self) -> DynConnection<'_, B> {
        let ConnectionInner {
            state,
            go_away,
            streams,
            error,
            ping_pong,
            ..
        } = self;
        let streams = streams.as_dyn();
        DynConnection {
            state,
            go_away,
            streams,
            error,
            ping_pong,
        }
    }
}

impl<B> DynConnection<'_, B>
where
    B: Buf,
{
    fn go_away(&mut self, id: StreamId, e: Reason) {
        let frame = frame::GoAway::new(id, e);
        self.streams.send_go_away(id);
        self.go_away.go_away(frame);
    }

    /// Sends a GOAWAY relayed from another connection (see `RelayedEnd::go_away`), `refused`
    /// sorted.
    fn relay_go_away(
        &mut self,
        last_stream_id: StreamId,
        reason: Reason,
        debug_data: Bytes,
        refused: &[u32],
    ) {
        // The latest stream the client opened that the other connection didn't leave
        // unprocessed went on regardless.
        let mut processed = self.streams.last_processed_id();
        while processed > last_stream_id && refused.binary_search(&u32::from(processed)).is_ok() {
            processed = StreamId::from(u32::from(processed).saturating_sub(2));
        }
        let last_stream_id = last_stream_id.max(processed);
        let last_stream_id = self
            .go_away
            .going_away()
            .map_or(last_stream_id, |going_away| {
                last_stream_id.min(going_away.last_processed_id())
            });
        self.streams.send_go_away(last_stream_id);
        self.go_away.relay(frame::GoAway::with_debug_data(
            last_stream_id,
            reason,
            debug_data,
        ));
        self.streams.refuse(last_stream_id, refused);
    }

    /// The last stream a GOAWAY sent now names: the latest processed, but not past the one
    /// a GOAWAY sent before named, which a relayed one can set below it.
    fn go_away_id(&self) -> StreamId {
        let last_processed_id = self.streams.last_processed_id();
        self.go_away
            .going_away()
            .map_or(last_processed_id, |going_away| {
                last_processed_id.min(going_away.last_processed_id())
            })
    }

    fn go_away_now(&mut self, e: Reason) {
        let frame = frame::GoAway::new(self.go_away_id(), e);
        self.go_away.go_away_now(frame);
    }

    fn go_away_now_data(&mut self, e: Reason, data: Bytes) {
        let frame = frame::GoAway::with_debug_data(self.go_away_id(), e, data);
        self.go_away.go_away_now(frame);
    }

    fn go_away_from_user(&mut self, e: Reason) {
        let last_processed_id = self.go_away_id();
        let frame = frame::GoAway::new(last_processed_id, e);
        self.go_away.go_away_from_user(frame);

        // Notify all streams of reason we're abruptly closing.
        self.streams.handle_error(Error::user_go_away(e));
    }

    fn handle_poll2_result(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        match result {
            // The connection has shutdown normally
            Ok(()) => {
                *self.state = State::Closing(Reason::NO_ERROR, Initiator::Library);
                Ok(())
            }
            // Attempting to read a frame resulted in a connection level
            // error. This is handled by setting a GOAWAY frame followed by
            // terminating the connection.
            Err(Error::GoAway(debug_data, reason, initiator)) => {
                self.handle_go_away(reason, debug_data, initiator);
                Ok(())
            }
            // Attempting to read a frame resulted in a stream level error.
            // Locally detected stream errors are reported to the peer with
            // RST_STREAM. Remotely initiated resets have already been applied
            // by the streams state machine and must not be echoed back.
            Err(Error::Reset(id, reason, initiator)) => {
                if initiator == Initiator::Remote {
                    tracing::trace!(?id, ?reason, ?initiator, "stream reset");
                    return Ok(());
                }

                debug_assert_eq!(initiator, Initiator::Library);
                tracing::trace!(?id, ?reason, ?initiator, "stream error");
                match self.streams.send_reset(id, reason) {
                    Ok(()) => (),
                    Err(crate::proto::error::GoAway { debug_data, reason }) => {
                        self.handle_go_away(reason, debug_data, Initiator::Library);
                    }
                }
                Ok(())
            }
            // Attempting to read a frame resulted in an I/O error. All
            // active streams must be reset.
            //
            // TODO: Are I/O errors recoverable?
            Err(Error::Io(kind, inner)) => {
                tracing::debug!(error = ?kind, "Connection::poll; IO error");
                let e = Error::Io(kind, inner);

                // Reset all active streams
                self.streams.handle_error(e.clone());

                // Some client implementations drop the connections without notifying its peer
                // Attempting to read after the client dropped the connection results in UnexpectedEof
                // If as a server, we don't have anything more to send, just close the connection
                // without error
                //
                // See https://github.com/hyperium/hyper/issues/3427
                if self.streams.is_buffer_empty()
                    && matches!(kind, io::ErrorKind::UnexpectedEof)
                    && (self.streams.is_server()
                        || self.error.as_ref().map(|f| f.reason() == Reason::NO_ERROR)
                            == Some(true))
                {
                    *self.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
                    return Ok(());
                }

                // Return the error
                Err(e)
            }
        }
    }

    fn handle_go_away(&mut self, reason: Reason, debug_data: Bytes, initiator: Initiator) {
        let e = Error::GoAway(debug_data.clone(), reason, initiator);
        tracing::debug!(error = ?e, "Connection::poll; connection error");

        // We may have already sent a GOAWAY for this error,
        // if so, don't send another, just flush and close up.
        if self
            .go_away
            .going_away()
            .map_or(false, |frame| frame.reason() == reason)
        {
            tracing::trace!("    -> already going away");
            *self.state = State::Closing(reason, initiator);
            return;
        }

        // Reset all active streams
        self.streams.handle_error(e);
        self.go_away_now_data(reason, debug_data);
    }

    fn recv_frame(&mut self, frame: Option<Frame>) -> Result<ReceivedFrame, Error> {
        use crate::frame::Frame::*;
        match frame {
            Some(Headers(frame)) => {
                tracing::trace!(?frame, "recv HEADERS");
                self.streams.recv_headers(frame)?;
            }
            Some(Data(frame)) => {
                tracing::trace!(?frame, "recv DATA");
                self.streams.recv_data(frame)?;
            }
            Some(Reset(frame)) => {
                tracing::trace!(?frame, "recv RST_STREAM");
                self.streams.recv_reset(frame)?;
            }
            Some(PushPromise(frame)) => {
                tracing::trace!(?frame, "recv PUSH_PROMISE");
                self.streams.recv_push_promise(frame)?;
            }
            Some(Settings(frame)) => {
                tracing::trace!(?frame, "recv SETTINGS");
                return Ok(ReceivedFrame::Settings(frame));
            }
            Some(GoAway(frame)) => {
                tracing::trace!(?frame, "recv GOAWAY");
                // This should prevent starting new streams,
                // but should allow continuing to process current streams
                // until they are all EOS. Once they are, State should
                // transition to GoAway.
                self.streams.recv_go_away(&frame)?;
                *self.error = Some(frame);
            }
            Some(Ping(frame)) => {
                tracing::trace!(?frame, "recv PING");
                match self.ping_pong.recv_ping(frame) {
                    ReceivedPing::Shutdown => {
                        assert!(
                            self.go_away.is_going_away(),
                            "received unexpected shutdown ping"
                        );

                        let last_processed_id = self.go_away_id();
                        self.go_away(last_processed_id, Reason::NO_ERROR);
                    }
                    ReceivedPing::Relayed(payload) => {
                        return Ok(ReceivedFrame::RelayedAck(RelayedAck::Ping(payload)));
                    }
                    ReceivedPing::MustAck
                    | ReceivedPing::Unknown
                    | ReceivedPing::AwaitsRelayedAck => {}
                }
            }
            Some(WindowUpdate(frame)) => {
                tracing::trace!(?frame, "recv WINDOW_UPDATE");
                self.streams.recv_window_update(frame)?;
            }
            Some(Priority(frame)) => {
                tracing::trace!(?frame, "recv PRIORITY");
                // TODO: handle
            }
            None => {
                tracing::trace!("codec closed");
                self.streams.recv_eof(false).expect("mutex poisoned");
                return Ok(ReceivedFrame::Done);
            }
        }
        Ok(ReceivedFrame::Continue)
    }
}

enum ReceivedFrame {
    Settings(frame::Settings),
    /// The peer's ACK of a relayed frame.
    RelayedAck(RelayedAck),
    Continue,
    Done,
}

impl<T, B> Connection<T, client::Peer, B>
where
    T: AsyncRead + AsyncWrite,
    B: Buf,
{
    pub(crate) fn streams(&self) -> &Streams<B, client::Peer> {
        &self.inner.streams
    }
}

impl<T, B> Connection<T, server::Peer, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    pub fn next_incoming(&mut self) -> Option<StreamRef<B>> {
        self.inner.streams.next_incoming()
    }

    // Graceful shutdown only makes sense for server peers.
    pub fn go_away_gracefully(&mut self) {
        if self.inner.go_away.is_going_away() {
            // No reason to start a new one.
            return;
        }

        // According to http://httpwg.org/specs/rfc7540.html#GOAWAY:
        //
        // > A server that is attempting to gracefully shut down a connection
        // > SHOULD send an initial GOAWAY frame with the last stream
        // > identifier set to 2^31-1 and a NO_ERROR code. This signals to the
        // > client that a shutdown is imminent and that initiating further
        // > requests is prohibited. After allowing time for any in-flight
        // > stream creation (at least one round-trip time), the server can
        // > send another GOAWAY frame with an updated last stream identifier.
        // > This ensures that a connection can be cleanly shut down without
        // > losing requests.
        self.inner.as_dyn().go_away(StreamId::MAX, Reason::NO_ERROR);

        // We take the advice of waiting 1 RTT literally, and wait
        // for a pong before proceeding.
        self.inner.ping_pong.ping_shutdown();
    }
}

impl<T, P, B> Drop for Connection<T, P, B>
where
    P: Peer,
    B: Buf,
{
    fn drop(&mut self) {
        // Ignore errors as this indicates that the mutex is poisoned.
        let _ = self.inner.streams.recv_eof(true);
        if let Some(relay) = &self.relay {
            relay.close();
        }
        if let Some(relayed) = &self.relayed_end {
            relayed.sent(u64::MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_data_frame_budget_scales_with_connection_window() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(None),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(DEFAULT_INITIAL_WINDOW_SIZE)),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(DataFrameBudget::Auto.resolve(Some(1024 * 1024)), 512 * 1024);
    }

    #[test]
    fn auto_data_frame_budget_has_minimum() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(1)),
            DEFAULT_DATA_FRAME_BUDGET
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(MAX_WINDOW_SIZE)),
            MAX_WINDOW_SIZE as usize / 2
        );
    }

    #[test]
    fn configured_data_frame_budget_is_unchanged() {
        assert_eq!(
            DataFrameBudget::Configured(123).resolve(Some(MAX_WINDOW_SIZE)),
            123
        );
    }
}
