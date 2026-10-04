use crate::codec::UserError;
use crate::error::Reason;
use crate::proto::*;
use std::collections::VecDeque;
use std::task::{Context, Poll};

#[derive(Debug)]
pub(crate) struct Settings {
    /// Our own SETTINGS to send to the remote when the socket is ready.
    to_send: Option<frame::Settings>,
    /// The SETTINGS sent, our own and relayed ones (see `Relay`), awaiting the remote's
    /// ACK in the order sent, each with whether it was relayed; each ACK applies the
    /// earliest.
    waiting: VecDeque<(frame::Settings, bool)>,
    /// Received SETTINGS frame pending processing. The ACK must be written to
    /// the socket first then the settings applied **before** receiving any
    /// further frames.
    remote: Option<frame::Settings>,
    /// Whether the connection has received the initial SETTINGS frame from the
    /// remote peer.
    has_received_remote_initial_settings: bool,
}

impl Settings {
    pub(crate) fn new(local: frame::Settings) -> Self {
        Settings {
            to_send: None,
            // We assume the initial local SETTINGS were flushed during
            // the handshake process.
            waiting: VecDeque::from([(local, false)]),
            remote: None,
            has_received_remote_initial_settings: false,
        }
    }

    /// Handles a received SETTINGS frame; whether it acknowledged a relayed one.
    pub(crate) fn recv_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<bool, Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            match self.waiting.pop_front() {
                Some((local, relayed)) => {
                    tracing::debug!("received settings ACK; applying {:?}", local);

                    if let Some(max) = local.max_frame_size() {
                        codec.set_max_recv_frame_size(max as usize);
                    }

                    if let Some(max) = local.max_header_list_size() {
                        codec.set_max_recv_header_list_size(max as usize);
                    }

                    if let Some(val) = local.header_table_size() {
                        codec.set_recv_header_table_size(val as usize);
                    }

                    streams.apply_local_settings(&local)?;
                    Ok(relayed)
                }
                None => {
                    // We haven't sent any SETTINGS frames to be ACKed, so
                    // this is very bizarre! Remote is either buggy or malicious.
                    proto_err!(conn: "received unexpected settings ack");
                    Err(Error::library_go_away(Reason::PROTOCOL_ERROR))
                }
            }
        } else {
            // We always ACK before reading more frames, so `remote` should
            // always be none!
            assert!(self.remote.is_none());
            self.remote = Some(frame);
            Ok(false)
        }
    }

    /// The SETTINGS sent and awaiting its ACK, replaced by `frame`: the frame a deferred
    /// preface sends instead of the configured one.
    pub(crate) fn replace_pending_local(&mut self, frame: frame::Settings) -> frame::Settings {
        match self.waiting.front_mut() {
            Some((local, false)) => std::mem::replace(local, frame),
            _ => {
                self.waiting.push_front((frame, false));
                frame::Settings::default()
            }
        }
    }

    pub(crate) fn send_settings(&mut self, frame: frame::Settings) -> Result<(), UserError> {
        assert!(!frame.is_ack());
        if self.to_send.is_some() || self.waiting.iter().any(|(_, relayed)| !relayed) {
            return Err(UserError::SendSettingsWhilePending);
        }
        tracing::trace!("queue to send local settings: {:?}", frame);
        self.to_send = Some(frame);
        Ok(())
    }

    /// Notes `frame`, a relayed SETTINGS frame just sent, which awaits its ACK.
    pub(crate) fn sent_relayed(&mut self, frame: frame::Settings) {
        self.waiting.push_back((frame, true));
    }

    /// Sets `true` to `self.has_received_remote_initial_settings`.
    /// Returns `true` if this method is called for the first time.
    /// (i.e. it is the initial SETTINGS frame from the remote peer)
    fn mark_remote_initial_settings_as_received(&mut self) -> bool {
        let has_received = self.has_received_remote_initial_settings;
        self.has_received_remote_initial_settings = true;
        !has_received
    }

    pub(crate) fn poll_send<T, B, C, P>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Poll<Result<(), Error>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if let Some(settings) = self.remote.clone() {
            if !dst.poll_ready(cx)?.is_ready() {
                return Poll::Pending;
            }

            // Create an ACK settings frame
            let frame = frame::Settings::ack();

            // Buffer the settings frame
            dst.buffer(frame.into()).expect("invalid settings frame");

            tracing::trace!("ACK sent; applying settings");

            let is_initial = self.mark_remote_initial_settings_as_received();
            streams.apply_remote_settings(&settings, is_initial)?;

            if let Some(val) = settings.header_table_size() {
                dst.set_send_header_table_size(val as usize);
            }

            if let Some(val) = settings.max_frame_size() {
                dst.set_max_send_frame_size(val as usize);
            }
        }

        self.remote = None;

        if let Some(settings) = self.to_send.take() {
            if !dst.poll_ready(cx)?.is_ready() {
                self.to_send = Some(settings);
                return Poll::Pending;
            }

            // Buffer the settings frame
            dst.buffer(settings.clone().into())
                .expect("invalid settings frame");
            tracing::trace!("local settings sent; waiting for ack: {:?}", settings);

            self.waiting.push_back((settings, false));
        }

        Poll::Ready(Ok(()))
    }
}
