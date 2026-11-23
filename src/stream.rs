//! Readers as streams of packets and writers as sinks of packets.

use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use futures_core::Stream;
use futures_sink::Sink;

use crate::Packet;
use crate::io::{Reader, Writer};
use crate::layer::{Ip, Layer};

/// Room kept ahead for one packet: the largest IP packet.
const PACKET: usize = 65_536;
/// The blocks the buffers of a stream's packets are cut from.
const BLOCK: usize = 1 << 20;
/// Packets a sink gathers before it hands them to the writer.
const BATCH: usize = 64;

/// A reader as a stream of packets. Each item is one packet, cut from its segment and with a
/// complete checksum, in a buffer of its own; the buffers are cut from larger blocks, so the
/// stream allocates once for many packets. An error is an item too, and the stream goes on.
pub struct PacketStream<L: Layer = Ip> {
    reader: Reader<L>,
    block: BytesMut,
}

impl<L: Layer> Unpin for PacketStream<L> {}

impl<L: Layer> PacketStream<L> {
    /// A stream that reads with `reader`.
    pub fn new(reader: Reader<L>) -> PacketStream<L> {
        PacketStream { reader, block: BytesMut::new() }
    }

    /// The reader.
    pub fn get_ref(&self) -> &Reader<L> {
        &self.reader
    }

    /// The reader, for its settings.
    pub fn get_mut(&mut self) -> &mut Reader<L> {
        &mut self.reader
    }

    /// The reader back.
    pub fn into_inner(self) -> Reader<L> {
        self.reader
    }
}

impl<L: Layer> Stream for PacketStream<L> {
    type Item = io::Result<BytesMut>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<io::Result<BytesMut>>> {
        let this = self.get_mut();
        if this.block.len() < PACKET {
            this.block = BytesMut::zeroed(BLOCK);
        }
        let length = match ready!(this.reader.poll_recv_packet(cx, &mut this.block)) {
            Ok(length) => length,
            Err(error) => return Poll::Ready(Some(Err(error))),
        };
        Poll::Ready(Some(Ok(this.block.split_to(length))))
    }
}

/// A writer as a sink of packets of type `B`, such as `Vec<u8>` or `Bytes`. Packets are copied
/// as they come and handed to the writer together when the sink is flushed or has gathered a
/// batch, so the writer joins and writes them as one batch. Their checksums are taken as
/// unverified.
pub struct PacketSink<B, L: Layer = Ip> {
    writer: Writer<L>,
    bytes: Vec<u8>,
    packets: Vec<Range<usize>>,
    item: PhantomData<fn(B)>,
}

impl<B, L: Layer> Unpin for PacketSink<B, L> {}

impl<B: AsRef<[u8]>, L: Layer> PacketSink<B, L> {
    /// A sink that writes with `writer`.
    pub fn new(writer: Writer<L>) -> PacketSink<B, L> {
        PacketSink { writer, bytes: Vec::new(), packets: Vec::new(), item: PhantomData }
    }

    /// The writer.
    pub fn get_ref(&self) -> &Writer<L> {
        &self.writer
    }

    /// The writer, for its settings.
    pub fn get_mut(&mut self) -> &mut Writer<L> {
        &mut self.writer
    }

    /// The writer back. Packets gathered and not flushed are lost.
    pub fn into_inner(self) -> Writer<L> {
        self.writer
    }

    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.packets.is_empty() {
            let packets: Vec<Packet<'_>> = self.packets.iter().map(|range| Packet::new(&self.bytes[range.clone()])).collect();
            ready!(self.writer.poll_send(cx, &packets))?;
            self.packets.clear();
            self.bytes.clear();
        }
        self.writer.poll_writable(cx)
    }
}

impl<B: AsRef<[u8]>, L: Layer> Sink<B> for PacketSink<B, L> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.packets.len() >= BATCH {
            ready!(this.poll_write(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: B) -> io::Result<()> {
        let this = self.get_mut();
        let start = this.bytes.len();
        this.bytes.extend_from_slice(item.as_ref());
        this.packets.push(start..this.bytes.len());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_write(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_write(cx)
    }
}

impl<L: Layer> Reader<L> {
    /// The reader as a stream of packets.
    pub fn into_stream(self) -> PacketStream<L> {
        PacketStream::new(self)
    }
}

impl<L: Layer> Writer<L> {
    /// The writer as a sink of packets of type `B`.
    pub fn into_sink<B: AsRef<[u8]>>(self) -> PacketSink<B, L> {
        PacketSink::new(self)
    }
}
