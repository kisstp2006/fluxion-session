// SPDX-License-Identifier: BSD-2-Clause

//! One end of a session, once its keys are agreed: messages in, datagrams
//! out, and back.
//!
//! A message goes on one of three channels. `unreliable` arrives or not, in
//! any order - a sound, a shot's spark. `sequenced` arrives or not, but
//! never after a newer one - a state that the next one replaces. `reliable`
//! arrives, once, in the order sent, however the network loses, doubles and
//! reorders - a chat line, a kill, a map change; one too large for a
//! datagram goes in pieces and is whole again at the other end.
//!
//! What waits to go is gathered into as few datagrams as it fits in, each
//! carrying the acknowledgement of the last 33 that came; a reliable message
//! goes again until a datagram carrying it is acknowledged. From the
//! acknowledgements the round trip and the loss are measured. A budget of
//! bytes a second holds the sending back: what is unreliable and over it is
//! let go, what is reliable waits.
//!
//! Time is given, never read: `flush` and `receive` take the time now, in
//! nanoseconds of any clock that only goes forward.

const std = @import("std");
const testing = std.testing;
const crypto = @import("crypto.zig");
const sequence = @import("sequence.zig");
const wire = @import("wire.zig");
const transport_ = @import("transport.zig");
const Transport = transport_.Transport;
const Address = transport_.Address;

const Connection = @This();

pub const Channel = enum(u2) {
    unreliable = 0,
    sequenced = 1,
    reliable = 2,
};

/// The channel the two ends speak to each other on, not to the game.
const control: u2 = 3;

const Control = enum(u8) {
    /// The server took the client, into its slot.
    accepted = 1,
    /// This end has gone, and why.
    disconnect = 2,
    _,
};

pub const Config = struct {
    /// Bytes a second this end sends at most, every channel's.
    rate: u32 = 256 * 1024,
    /// How long the other end may be silent before it is taken for gone.
    timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// How long this end stays silent at most: what keeps a quiet session
    /// open, and its acknowledgements going.
    keepalive_ns: u64 = 100 * std.time.ns_per_ms,
    /// The largest reliable message, whole.
    max_message: u32 = 64 * 1024,
    /// The most bytes of reliable messages waiting, sent and not yet
    /// acknowledged: past it, sending one fails.
    max_queued: u32 = 1024 * 1024,
};

pub const Message = struct {
    channel: Channel,
    /// Good until the next `next`.
    data: []const u8,
};

pub const Stats = struct {
    sent_packets: u64 = 0,
    sent_bytes: u64 = 0,
    received_packets: u64 = 0,
    received_bytes: u64 = 0,
    /// Packets sent and never acknowledged.
    lost_packets: u64 = 0,
    /// Unreliable messages the budget let go.
    dropped_messages: u64 = 0,
    /// Packets refused: forged, played again, or of no sense.
    refused_packets: u64 = 0,
};

pub const SendError = error{ TooLarge, QueueFull, OutOfMemory };
pub const ReceiveError = error{ Forged, Replayed, Malformed, OutOfMemory };

/// The plain part of a data packet: its flags, the newest packet number
/// acknowledged and the 32 before it.
const ack_size = 1 + 2 + 4;
/// A message's own header at most: its kind, id, piece and length.
const message_head = 1 + 2 + 2 + 2;
const max_plain = wire.max_datagram - wire.sealed_overhead;
/// The most a message of one datagram carries: an unreliable message's
/// largest, and a reliable one's piece.
pub const max_piece = max_plain - ack_size - message_head;
/// Reliable messages on their way at once, and packets remembered.
const window = 256;
/// Reliable messages one packet carries at most.
const max_ids = 32;

const Sent = struct {
    time: u64,
    acked: bool = false,
    count: u8 = 0,
    ids: [max_ids]u16 = undefined,
};

const Outgoing = struct {
    data: []u8,
    sent_at: ?u64 = null,
    index: u8 = 0,
    /// 0 for a whole message; else how many pieces it is in.
    pieces: u8 = 0,
};

const Held = struct {
    channel: Channel,
    data: []u8,
};

gpa: std.mem.Allocator,
config: Config,
protocol: u64,
keys: crypto.Keys,
stats: Stats = .{},

/// The number of the next packet sent; what came.
number: u64 = 1,
replay: sequence.ReplayWindow = .{},

got_any: bool = false,
got_newest: u16 = 0,
got_bits: u32 = 0,
ack_due: bool = false,

sent: sequence.Buffer(Sent, window) = .{},
/// The round trip, smoothed.
rtt_ns: f64 = 100 * std.time.ns_per_ms,
rtt_measured: bool = false,
/// The share of packets lost, smoothed.
loss: f32 = 0,

next_id: u16 = 0,
oldest: u16 = 0,
outgoing: sequence.Buffer(Outgoing, window) = .{},
/// Reliable messages not yet in the window: their ids come as it frees.
backlog: std.ArrayList(Outgoing) = .empty,
backlog_at: usize = 0,
queued: usize = 0,

expected: u16 = 0,
incoming: sequence.Buffer(Outgoing, window) = .{},
assembling: std.ArrayList(u8) = .empty,
assembling_next: u8 = 0,

sequenced_next: u16 = 0,
sequenced_newest: ?u16 = null,

/// Unreliable and sequenced messages, framed, waiting for this flush.
pending: std.ArrayList(u8) = .empty,
pending_ends: std.ArrayList(u32) = .empty,

inbox: std.ArrayList(Held) = .empty,
inbox_at: usize = 0,
given: ?[]u8 = null,

/// The slot this end says the client was taken into, until the client is
/// heard from; the slot the server said.
announce: ?u16 = null,
accepted: ?u16 = null,
/// Why the other end said it went.
said_gone: ?u8 = null,
/// What came made no sense: the other end is broken or hostile.
broken: bool = false,

tokens: f64,
refilled: u64,
last_received: u64,
last_sent: u64,

pub fn init(gpa: std.mem.Allocator, config: Config, protocol: u64, keys: crypto.Keys, now: u64) Connection {
    std.debug.assert(config.max_message <= 255 * max_piece);
    var made: Connection = .{
        .gpa = gpa,
        .config = config,
        .protocol = protocol,
        .keys = keys,
        .tokens = burstOf(config),
        .refilled = now,
        .last_received = now,
        .last_sent = 0,
    };
    // Number 0 each way was the handshake's.
    made.replay.take(0);
    return made;
}

fn burstOf(config: Config) f64 {
    return @max(@as(f64, @floatFromInt(config.rate)) / 10.0, 4 * wire.max_datagram);
}

pub fn deinit(self: *Connection) void {
    var id = self.oldest;
    while (id != self.next_id) : (id +%= 1) {
        if (self.outgoing.get(id)) |o| self.gpa.free(o.data);
    }
    for (self.backlog.items[self.backlog_at..]) |o| self.gpa.free(o.data);
    self.backlog.deinit(self.gpa);
    for (self.incoming.numbers, 0..) |n, i| {
        if (n != std.math.maxInt(u32)) self.gpa.free(self.incoming.items[i].data);
    }
    self.assembling.deinit(self.gpa);
    self.pending.deinit(self.gpa);
    self.pending_ends.deinit(self.gpa);
    for (self.inbox.items[self.inbox_at..]) |held| self.gpa.free(held.data);
    self.inbox.deinit(self.gpa);
    if (self.given) |given| self.gpa.free(given);
    self.keys.wipe();
    self.* = undefined;
}

// --- Sending ---------------------------------------------------------------

/// `data` to go on `channel`, with the next flush - a reliable message until
/// the other end has it. Copied.
pub fn send(self: *Connection, channel: Channel, data: []const u8) SendError!void {
    switch (channel) {
        .unreliable, .sequenced => {
            if (data.len > max_piece) return error.TooLarge;
            const start = self.pending.items.len;
            errdefer self.pending.shrinkRetainingCapacity(start);
            var head: [message_head]u8 = undefined;
            const id = if (channel == .sequenced) self.sequenced_next else null;
            const framed = frame(&head, @intFromEnum(channel), id, null, data.len);
            try self.pending.appendSlice(self.gpa, framed);
            try self.pending.appendSlice(self.gpa, data);
            try self.pending_ends.append(self.gpa, @intCast(self.pending.items.len));
            if (channel == .sequenced) self.sequenced_next +%= 1;
        },
        .reliable => {
            if (data.len > self.config.max_message) return error.TooLarge;
            if (self.queued + data.len > self.config.max_queued) return error.QueueFull;
            const pieces: usize = if (data.len <= max_piece) 1 else (data.len + max_piece - 1) / max_piece;
            const start = self.backlog.items.len;
            errdefer {
                for (self.backlog.items[start..]) |o| self.gpa.free(o.data);
                self.backlog.shrinkRetainingCapacity(start);
            }
            try self.backlog.ensureUnusedCapacity(self.gpa, pieces);
            for (0..pieces) |i| {
                const part = data[i * max_piece .. @min(data.len, (i + 1) * max_piece)];
                self.backlog.appendAssumeCapacity(.{
                    .data = try self.gpa.dupe(u8, part),
                    .index = @intCast(i),
                    .pieces = if (pieces == 1) 0 else @intCast(pieces),
                });
            }
            self.queued += data.len;
            self.admit();
        },
    }
}

/// Backlogged reliable messages into the window, as far as it has room.
fn admit(self: *Connection) void {
    while (self.backlog_at < self.backlog.items.len and self.next_id -% self.oldest < window) {
        _ = self.outgoing.put(self.next_id, self.backlog.items[self.backlog_at]);
        self.backlog_at += 1;
        self.next_id +%= 1;
    }
    if (self.backlog_at == self.backlog.items.len) {
        self.backlog.clearRetainingCapacity();
        self.backlog_at = 0;
    }
}

/// A message's header into `head`: kind, id, piece and length.
fn frame(head: *[message_head]u8, kind: u2, id: ?u16, piece: ?[2]u8, len: usize) []u8 {
    var at: usize = 1;
    head[0] = @as(u8, kind) | (@as(u8, @intFromBool(piece != null)) << 2);
    if (id) |n| {
        std.mem.writeInt(u16, head[at..][0..2], n, .little);
        at += 2;
    }
    if (piece) |p| {
        head[at..][0..2].* = p;
        at += 2;
    }
    std.mem.writeInt(u16, head[at..][0..2], @intCast(len), .little);
    return head[0 .. at + 2];
}

/// What waits, into datagrams to `to`: as few as it fits, as many as the
/// budget allows; an acknowledgement, or a sign of life, if nothing waits
/// and one is due.
pub fn flush(self: *Connection, now: u64, out: Transport, to: *const Address) void {
    const elapsed = now -| self.refilled;
    self.refilled = now;
    self.tokens = @min(burstOf(self.config), self.tokens + @as(f64, @floatFromInt(elapsed)) * @as(f64, @floatFromInt(self.config.rate)) / std.time.ns_per_s);
    const resend_after: u64 = @intFromFloat(@max(self.rtt_ns * 1.5, 20 * std.time.ns_per_ms));

    var scan = self.oldest;
    var pending_at: usize = 0;
    var packets: usize = 0;
    while (packets < 64) : (packets += 1) {
        var plain: [max_plain]u8 = undefined;
        var at: usize = ack_size;
        var record: Sent = .{ .time = now };
        var carried = false;

        if (self.announce) |slot| {
            if (packets == 0) {
                at += self.writeControl(plain[at..], .accepted, slot);
                carried = true;
            }
        }
        while (scan != self.next_id and record.count < max_ids) : (scan +%= 1) {
            const o = self.outgoing.get(scan) orelse continue;
            if (o.sent_at) |when| {
                if (now -| when < resend_after) continue;
            }
            var head: [message_head]u8 = undefined;
            const framed = frame(&head, @intFromEnum(Channel.reliable), scan, if (o.pieces > 0) .{ o.index, o.pieces } else null, o.data.len);
            if (at + framed.len + o.data.len > plain.len) break;
            @memcpy(plain[at..][0..framed.len], framed);
            at += framed.len;
            @memcpy(plain[at..][0..o.data.len], o.data);
            at += o.data.len;
            o.sent_at = now;
            record.ids[record.count] = scan;
            record.count += 1;
            carried = true;
        }
        while (pending_at < self.pending_ends.items.len) {
            const begin: usize = if (pending_at == 0) 0 else self.pending_ends.items[pending_at - 1];
            const end = self.pending_ends.items[pending_at];
            if (at + (end - begin) > plain.len) break;
            @memcpy(plain[at..][0 .. end - begin], self.pending.items[begin..end]);
            at += end - begin;
            pending_at += 1;
            carried = true;
        }
        if (!carried and !self.ack_due and now -| self.last_sent < self.config.keepalive_ns) break;
        if (self.tokens <= 0) break;

        plain[0] = @intFromBool(self.got_any);
        std.mem.writeInt(u16, plain[1..3], self.got_newest, .little);
        std.mem.writeInt(u32, plain[3..7], self.got_bits, .little);
        const number = self.number;
        self.number += 1;
        if (self.sent.get(@truncate(number))) |old| {
            if (!old.acked) self.lostOne(true);
        }
        _ = self.sent.put(@truncate(number), record);
        var sealed: [wire.max_datagram]u8 = undefined;
        const packet = wire.sealPacket(&sealed, .data, self.protocol, number, plain[0..at], self.keys.send);
        out.send(to, packet);
        self.tokens -= @floatFromInt(packet.len);
        self.stats.sent_packets += 1;
        self.stats.sent_bytes += packet.len;
        self.ack_due = false;
        self.last_sent = now;
        if (!carried) break;
    }
    self.stats.dropped_messages += self.pending_ends.items.len - pending_at;
    self.pending.clearRetainingCapacity();
    self.pending_ends.clearRetainingCapacity();
}

fn writeControl(self: *Connection, out: []u8, kind: Control, value: u16) usize {
    _ = self;
    var head: [message_head]u8 = undefined;
    const framed = frame(&head, control, null, null, 3);
    @memcpy(out[0..framed.len], framed);
    out[framed.len] = @intFromEnum(kind);
    std.mem.writeInt(u16, out[framed.len + 1 ..][0..2], value, .little);
    return framed.len + 3;
}

/// The other end told this one has gone, `reason` why: three times, in
/// three datagrams, past the budget - one is likely to arrive.
pub fn sayGone(self: *Connection, now: u64, out: Transport, to: *const Address, reason: u8) void {
    for (0..3) |_| {
        var plain: [ack_size + message_head + 3]u8 = undefined;
        plain[0] = 0;
        @memset(plain[1..ack_size], 0);
        const len = ack_size + self.writeControl(plain[ack_size..], .disconnect, reason);
        var sealed: [wire.max_datagram]u8 = undefined;
        const packet = wire.sealPacket(&sealed, .data, self.protocol, self.number, plain[0..len], self.keys.send);
        self.number += 1;
        out.send(to, packet);
        self.stats.sent_packets += 1;
        self.stats.sent_bytes += packet.len;
    }
    self.last_sent = now;
}

fn lostOne(self: *Connection, lost: bool) void {
    if (lost) self.stats.lost_packets += 1;
    self.loss = self.loss * 0.95 + (if (lost) @as(f32, 0.05) else 0);
}

// --- Receiving -------------------------------------------------------------

/// A data packet that came from the other end: opened, its acknowledgements
/// taken and its messages kept for `next`. A packet not sealed by the other
/// end, or come before, is refused and changes nothing.
pub fn receive(self: *Connection, now: u64, packet: []const u8) ReceiveError!void {
    errdefer self.stats.refused_packets += 1;
    if (packet.len < wire.sealed_overhead + ack_size or packet[0] != @intFromEnum(wire.Kind.data)) return error.Malformed;
    const number = wire.numberOf(packet);
    if (!self.replay.fresh(number)) return error.Replayed;
    var buffer: [wire.max_datagram]u8 = undefined;
    const plain = crypto.open(&buffer, packet[9..], &wire.associated(.data, self.protocol), number, self.keys.receive) catch return error.Forged;
    self.replay.take(number);
    self.last_received = now;
    self.stats.received_packets += 1;
    self.stats.received_bytes += packet.len;
    // The client was heard from: it knows its slot.
    self.announce = null;

    const n: u16 = @truncate(number);
    if (!self.got_any) {
        self.got_any = true;
        self.got_newest = n;
        self.got_bits = 0;
    } else if (sequence.newer(n, self.got_newest)) {
        const ahead = n -% self.got_newest;
        self.got_bits = if (ahead > 32) 0 else if (ahead == 32) @as(u32, 1) << 31 else (self.got_bits << @intCast(ahead)) | (@as(u32, 1) << @intCast(ahead - 1));
        self.got_newest = n;
    } else {
        const behind = self.got_newest -% n;
        if (behind >= 1 and behind <= 32) self.got_bits |= @as(u32, 1) << @intCast(behind - 1);
    }
    self.ack_due = true;

    if (plain[0] & 1 != 0) {
        const ack = std.mem.readInt(u16, plain[1..3], .little);
        const bits = std.mem.readInt(u32, plain[3..7], .little);
        self.acknowledged(now, ack);
        for (0..32) |i| {
            if (bits & (@as(u32, 1) << @intCast(i)) != 0) self.acknowledged(now, ack -% @as(u16, @intCast(i + 1)));
        }
        self.admit();
    }
    self.read(plain[ack_size..]) catch |err| {
        self.broken = true;
        return err;
    };
}

fn acknowledged(self: *Connection, now: u64, n: u16) void {
    const record = self.sent.get(n) orelse return;
    if (record.acked) return;
    record.acked = true;
    const sample: f64 = @floatFromInt(now -| record.time);
    self.rtt_ns = if (self.rtt_measured) self.rtt_ns * 0.875 + sample * 0.125 else sample;
    self.rtt_measured = true;
    self.lostOne(false);
    for (record.ids[0..record.count]) |id| {
        const o = self.outgoing.get(id) orelse continue;
        self.queued -= o.data.len;
        self.gpa.free(o.data);
        self.outgoing.remove(id);
    }
    while (self.oldest != self.next_id and self.outgoing.get(self.oldest) == null) self.oldest +%= 1;
}

fn read(self: *Connection, messages: []const u8) ReceiveError!void {
    var at: usize = 0;
    while (at < messages.len) {
        const head = messages[at];
        at += 1;
        if (head >> 3 != 0) return error.Malformed;
        const kind: u2 = @truncate(head);
        const in_pieces = head & 4 != 0;
        var id: u16 = 0;
        if (kind == 1 or kind == 2) {
            if (at + 2 > messages.len) return error.Malformed;
            id = std.mem.readInt(u16, messages[at..][0..2], .little);
            at += 2;
        }
        var index: u8 = 0;
        var pieces: u8 = 0;
        if (in_pieces) {
            if (kind != 2 or at + 2 > messages.len) return error.Malformed;
            index = messages[at];
            pieces = messages[at + 1];
            if (pieces < 2 or index >= pieces) return error.Malformed;
            at += 2;
        }
        if (at + 2 > messages.len) return error.Malformed;
        const len = std.mem.readInt(u16, messages[at..][0..2], .little);
        at += 2;
        if (at + len > messages.len) return error.Malformed;
        const data = messages[at..][0..len];
        at += len;
        switch (kind) {
            0 => try self.keep(.unreliable, data),
            1 => {
                if (self.sequenced_newest == null or sequence.newer(id, self.sequenced_newest.?)) {
                    self.sequenced_newest = id;
                    try self.keep(.sequenced, data);
                }
            },
            2 => {
                // Only what the window can hold: older is had already.
                if (id -% self.expected >= window or self.incoming.get(id) != null) continue;
                _ = self.incoming.put(id, .{ .data = try self.gpa.dupe(u8, data), .index = index, .pieces = pieces });
                try self.deliver();
            },
            3 => {
                if (len != 3) return error.Malformed;
                const value = std.mem.readInt(u16, data[1..3], .little);
                switch (@as(Control, @enumFromInt(data[0]))) {
                    .accepted => self.accepted = value,
                    .disconnect => self.said_gone = @truncate(value),
                    _ => return error.Malformed,
                }
            },
        }
    }
}

/// The reliable messages next in order, as far as they have come.
fn deliver(self: *Connection) ReceiveError!void {
    while (self.incoming.get(self.expected)) |o| {
        const piece = o.*;
        self.incoming.remove(self.expected);
        self.expected +%= 1;
        if (piece.pieces == 0) {
            if (self.assembling_next != 0) {
                self.gpa.free(piece.data);
                return error.Malformed;
            }
            self.inbox.append(self.gpa, .{ .channel = .reliable, .data = piece.data }) catch |err| {
                self.gpa.free(piece.data);
                return err;
            };
            continue;
        }
        defer self.gpa.free(piece.data);
        if (piece.index != self.assembling_next or self.assembling.items.len + piece.data.len > self.config.max_message)
            return error.Malformed;
        try self.assembling.appendSlice(self.gpa, piece.data);
        self.assembling_next += 1;
        if (self.assembling_next == piece.pieces) {
            const whole = try self.gpa.dupe(u8, self.assembling.items);
            self.assembling.clearRetainingCapacity();
            self.assembling_next = 0;
            self.inbox.append(self.gpa, .{ .channel = .reliable, .data = whole }) catch |err| {
                self.gpa.free(whole);
                return err;
            };
        }
    }
}

fn keep(self: *Connection, channel: Channel, data: []const u8) ReceiveError!void {
    const copy = try self.gpa.dupe(u8, data);
    self.inbox.append(self.gpa, .{ .channel = channel, .data = copy }) catch |err| {
        self.gpa.free(copy);
        return err;
    };
}

/// The next message that came, in the order it came; null when none waits.
pub fn next(self: *Connection) ?Message {
    if (self.given) |given| self.gpa.free(given);
    self.given = null;
    if (self.inbox_at == self.inbox.items.len) {
        self.inbox.clearRetainingCapacity();
        self.inbox_at = 0;
        return null;
    }
    const held = self.inbox.items[self.inbox_at];
    self.inbox_at += 1;
    self.given = held.data;
    return .{ .channel = held.channel, .data = held.data };
}

pub fn timedOut(self: *const Connection, now: u64) bool {
    return now -| self.last_received > self.config.timeout_ns;
}

// --- Tests -----------------------------------------------------------------

const Pair = struct {
    network: transport_.Network,
    a: Connection,
    b: Connection,
    ea: *transport_.Network.Endpoint,
    eb: *transport_.Network.Endpoint,

    fn init(self: *Pair, conditions: transport_.Network.Conditions, seed: u64, config: Config) !void {
        self.network = .init(testing.allocator, conditions, seed);
        self.ea = try self.network.endpoint(1);
        self.eb = try self.network.endpoint(2);
        const one: crypto.Key = @splat(1);
        const two: crypto.Key = @splat(2);
        self.a = .init(testing.allocator, config, 7, .{ .send = one, .receive = two }, 0);
        self.b = .init(testing.allocator, config, 7, .{ .send = two, .receive = one }, 0);
    }

    fn deinit(self: *Pair) void {
        self.a.deinit();
        self.b.deinit();
        self.network.deinit();
    }

    /// A tick of `step`: both ends send what waits and take what came.
    fn tick(self: *Pair, step: u64) !void {
        self.network.now += step;
        const now = self.network.now;
        self.a.flush(now, self.ea.transport(), &self.eb.address);
        self.b.flush(now, self.eb.transport(), &self.ea.address);
        var buffer: [wire.max_datagram]u8 = undefined;
        while (self.eb.transport().receive(&buffer)) |d| self.b.receive(now, d.data) catch {};
        while (self.ea.transport().receive(&buffer)) |d| self.a.receive(now, d.data) catch {};
    }
};

test "reliable messages arrive once, in order, whole, through loss, doubling and reordering" {
    var pair: Pair = undefined;
    try pair.init(.{ .latency_ns = 30 * std.time.ns_per_ms, .jitter_ns = 40 * std.time.ns_per_ms, .loss = 0.25, .duplicate = 0.1 }, 5, .{});
    defer pair.deinit();

    var big: [5000]u8 = undefined;
    for (&big, 0..) |*byte, i| byte.* = @truncate(i * 7);
    var sent: u32 = 0;
    var got: u32 = 0;
    var got_big = false;
    var tick: u32 = 0;
    while (tick < 2000 and (got < 300 or !got_big)) : (tick += 1) {
        if (sent < 300) {
            var text: [4]u8 = undefined;
            std.mem.writeInt(u32, &text, sent, .little);
            try pair.a.send(.reliable, &text);
            sent += 1;
            if (sent == 150) try pair.a.send(.reliable, &big);
        }
        try pair.tick(16 * std.time.ns_per_ms);
        while (pair.b.next()) |m| {
            try testing.expectEqual(Channel.reliable, m.channel);
            if (m.data.len == big.len) {
                try testing.expectEqual(@as(u32, 150), got);
                try testing.expectEqualSlices(u8, &big, m.data);
                got_big = true;
                continue;
            }
            try testing.expectEqual(got, std.mem.readInt(u32, m.data[0..4], .little));
            got += 1;
        }
    }
    try testing.expectEqual(@as(u32, 300), got);
    try testing.expect(got_big);
    try testing.expect(pair.network.lost > 0);
    // What is acknowledged is let go.
    for (0..100) |_| try pair.tick(16 * std.time.ns_per_ms);
    try testing.expectEqual(@as(usize, 0), pair.a.queued);
    try testing.expect(pair.a.rtt_ns > 30 * std.time.ns_per_ms and pair.a.rtt_ns < 200 * std.time.ns_per_ms);
}

test "a sequenced message is never taken after a newer one" {
    var pair: Pair = undefined;
    try pair.init(.{ .latency_ns = 10 * std.time.ns_per_ms, .jitter_ns = 50 * std.time.ns_per_ms }, 9, .{});
    defer pair.deinit();
    var newest: ?u8 = null;
    var count: u32 = 0;
    for (0..200) |i| {
        try pair.a.send(.sequenced, &.{@truncate(i)});
        try pair.tick(5 * std.time.ns_per_ms);
        while (pair.b.next()) |m| {
            if (newest) |n| try testing.expect(m.data[0] > n);
            newest = m.data[0];
            count += 1;
        }
    }
    // Jitter made some come late, and they were let go.
    try testing.expect(count > 20 and count < 200);
}

test "a packet played again, or changed, is refused" {
    var pair: Pair = undefined;
    try pair.init(.{}, 1, .{});
    defer pair.deinit();
    try pair.a.send(.unreliable, "fire");
    pair.a.flush(1, pair.ea.transport(), &pair.eb.address);
    var buffer: [wire.max_datagram]u8 = undefined;
    const d = pair.eb.transport().receive(&buffer).?;
    var copy: [wire.max_datagram]u8 = undefined;
    @memcpy(copy[0..d.data.len], d.data);
    try pair.b.receive(1, d.data);
    try testing.expectEqualStrings("fire", pair.b.next().?.data);
    try testing.expectError(error.Replayed, pair.b.receive(2, copy[0..d.data.len]));
    copy[12] ^= 0x40;
    std.mem.writeInt(u64, copy[1..9], 99, .little);
    try testing.expectError(error.Forged, pair.b.receive(2, copy[0..d.data.len]));
    try testing.expect(pair.b.next() == null);
    try testing.expectEqual(@as(u64, 2), pair.b.stats.refused_packets);
}

test "the budget lets unreliable messages go and holds reliable ones back" {
    var pair: Pair = undefined;
    try pair.init(.{}, 1, .{ .rate = 20 * 1024 });
    defer pair.deinit();
    var payload: [1000]u8 = @splat(1);
    for (0..100) |_| try pair.a.send(.unreliable, &payload);
    for (0..40) |_| try pair.a.send(.reliable, &payload);
    try pair.tick(1);
    try testing.expect(pair.a.stats.dropped_messages > 50);
    try testing.expect(pair.a.stats.sent_bytes < 10 * 1024);
    var got: usize = 0;
    for (0..400) |_| {
        try pair.tick(10 * std.time.ns_per_ms);
        while (pair.b.next()) |m| {
            if (m.channel == .reliable) got += 1;
        }
    }
    try testing.expectEqual(@as(usize, 40), got);
}

test "what is too large, or too much, is refused when sent" {
    var pair: Pair = undefined;
    try pair.init(.{}, 1, .{ .max_message = 4096, .max_queued = 8192 });
    defer pair.deinit();
    var big: [max_piece + 1]u8 = @splat(0);
    try testing.expectError(error.TooLarge, pair.a.send(.unreliable, &big));
    var huge: [5000]u8 = @splat(0);
    try testing.expectError(error.TooLarge, pair.a.send(.reliable, &huge));
    try pair.a.send(.reliable, huge[0..4000]);
    try pair.a.send(.reliable, huge[0..4000]);
    try testing.expectError(error.QueueFull, pair.a.send(.reliable, huge[0..4000]));
}

test "a silent end times out, and one that says it goes is heard" {
    var pair: Pair = undefined;
    try pair.init(.{}, 1, .{ .timeout_ns = std.time.ns_per_s });
    defer pair.deinit();
    try pair.tick(10);
    try testing.expect(!pair.b.timedOut(500 * std.time.ns_per_ms));
    try testing.expect(pair.b.timedOut(2 * std.time.ns_per_s));
    pair.a.sayGone(20, pair.ea.transport(), &pair.eb.address, 4);
    try pair.tick(10);
    try testing.expectEqual(@as(?u8, 4), pair.b.said_gone);
}
