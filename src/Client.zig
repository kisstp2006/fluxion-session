// SPDX-License-Identifier: BSD-2-Clause

//! A client: joins one server, by its address, and speaks to it over a
//! `Connection` once taken in. A client that knows the server's public key
//! - from a list it trusts, or the rendezvous that named the server - gives
//! it as `server_key`, and no one between the two can stand in for the
//! server; without it, the session is still sealed, but the first answer is
//! believed.
//!
//! `connect`, then `update` once a tick and `next` for what happened:
//! joined, gone, or a message.

const std = @import("std");
const crypto = @import("crypto.zig");
const wire = @import("wire.zig");
const transport_ = @import("transport.zig");
const Connection = @import("Connection.zig");
const X25519 = std.crypto.dh.X25519;
const Transport = transport_.Transport;
const Address = transport_.Address;
const Reason = wire.Reason;

const Client = @This();

pub const Config = struct {
    protocol: u64,
    connection: Connection.Config = .{},
    /// The server's public key, if known: a server with another is refused.
    server_key: ?crypto.Key = null,
    /// How long joining may take.
    join_timeout_ns: u64 = 5 * std.time.ns_per_s,
    /// How often a handshake packet goes again while no answer comes.
    resend_ns: u64 = 100 * std.time.ns_per_ms,
};

pub const State = enum { disconnected, requesting, responding, connected };

pub const Event = union(enum) {
    /// Taken into slot `client` of the server.
    connected: u16,
    disconnected: Reason,
    message: Connection.Message,
};

gpa: std.mem.Allocator,
transport: Transport,
config: Config,
state: State = .disconnected,
server: Address = undefined,
pair: X25519.KeyPair = undefined,
server_public: crypto.Key = undefined,
cookie: crypto.Cookie = undefined,
keys: crypto.Keys = undefined,
hello: [wire.max_hello]u8 = undefined,
hello_len: usize = 0,
connection: ?Connection = null,
/// The slot the server took this client into.
slot: u16 = 0,
started: u64 = 0,
tried: u64 = 0,
events: [4]Event = undefined,
events_len: u8 = 0,
events_at: u8 = 0,

pub fn init(gpa: std.mem.Allocator, out: Transport, config: Config) Client {
    return .{ .gpa = gpa, .transport = out, .config = config };
}

pub fn deinit(self: *Client) void {
    self.forget();
    self.* = undefined;
}

fn forget(self: *Client) void {
    if (self.connection) |*c| c.deinit();
    self.connection = null;
    if (self.state == .responding) self.keys.wipe();
    std.crypto.secureZero(u8, &self.pair.secret_key);
    self.state = .disconnected;
}

/// Joining the server at `address`, saying `hello` - at most 256 bytes: a
/// name, a password, a token. A session there was is left first.
pub fn connect(self: *Client, io: std.Io, now: u64, address: Address, hello: []const u8) error{TooLarge}!void {
    if (hello.len > wire.max_hello) return error.TooLarge;
    self.disconnect(now);
    self.server = address;
    self.pair = X25519.KeyPair.generate(io);
    @memcpy(self.hello[0..hello.len], hello);
    self.hello_len = hello.len;
    self.state = .requesting;
    self.started = now;
    self.request(now);
}

/// Off the server, and the server told.
pub fn disconnect(self: *Client, now: u64) void {
    if (self.connection) |*c| {
        if (self.state == .connected) c.sayGone(now, self.transport, &self.server, @intFromEnum(Reason.left));
    }
    self.forget();
}

pub fn send(self: *Client, channel: Connection.Channel, data: []const u8) !void {
    if (self.state != .connected) return error.NotConnected;
    try self.connection.?.send(channel, data);
}

/// The round trip to the server, in nanoseconds.
pub fn rtt(self: *const Client) ?f64 {
    return if (self.state == .connected) self.connection.?.rtt_ns else null;
}

fn request(self: *Client, now: u64) void {
    var out: [wire.request_size]u8 = @splat(0);
    out[0] = @intFromEnum(wire.Kind.request);
    std.mem.writeInt(u64, out[1..9], self.config.protocol, .little);
    @memcpy(out[9..41], &self.pair.public_key);
    self.transport.send(&self.server, &out);
    self.tried = now;
}

fn respond(self: *Client, now: u64) void {
    var out: [wire.response_head + wire.max_hello + crypto.tag_length]u8 = undefined;
    out[0] = @intFromEnum(wire.Kind.response);
    std.mem.writeInt(u64, out[1..9], self.config.protocol, .little);
    @memcpy(out[9..41], &self.pair.public_key);
    @memcpy(out[41..57], &self.cookie);
    const len = wire.response_head + self.hello_len + crypto.tag_length;
    crypto.seal(out[wire.response_head..len], self.hello[0..self.hello_len], &wire.associated(.response, self.config.protocol), 0, self.keys.send);
    self.transport.send(&self.server, out[0..len]);
    self.tried = now;
}

fn happen(self: *Client, event: Event) void {
    if (self.events_len == self.events.len) return;
    self.events[self.events_len] = event;
    self.events_len += 1;
}

fn end(self: *Client, reason: Reason) void {
    self.forget();
    self.happen(.{ .disconnected = reason });
}

/// What came taken, what waits sent; joining moved on, or given up.
pub fn update(self: *Client, now: u64) void {
    var buffer: [wire.max_datagram + 1]u8 = undefined;
    var taken: u32 = 0;
    while (taken < 4096) : (taken += 1) {
        const datagram = self.transport.receive(&buffer) orelse break;
        if (self.state == .disconnected) continue;
        if (datagram.data.len == 0 or datagram.data.len > wire.max_datagram or !crypto.sameAddress(datagram.from, self.server)) continue;
        self.take(now, datagram.data);
    }
    switch (self.state) {
        .disconnected => {},
        .requesting, .responding => {
            if (now -| self.started > self.config.join_timeout_ns) {
                self.end(.timed_out);
            } else if (now -| self.tried >= self.config.resend_ns) {
                if (self.state == .requesting) self.request(now) else self.respond(now);
            }
        },
        .connected => {
            const c = &self.connection.?;
            if (c.said_gone) |reason| {
                self.end(@enumFromInt(reason));
            } else if (c.broken) {
                c.sayGone(now, self.transport, &self.server, @intFromEnum(Reason.broken));
                self.end(.broken);
            } else if (c.timedOut(now)) {
                self.end(.timed_out);
            } else {
                c.flush(now, self.transport, &self.server);
            }
        },
    }
}

fn take(self: *Client, now: u64, data: []const u8) void {
    switch (@as(wire.Kind, @enumFromInt(data[0]))) {
        .challenge => {
            if (self.state != .requesting or data.len != wire.challenge_size or wire.protocolOf(data) != self.config.protocol) return;
            const public = data[9..41].*;
            if (self.config.server_key) |known| {
                if (!std.crypto.timing_safe.eql(crypto.Key, known, public)) return;
            }
            self.server_public = public;
            self.cookie = data[41..57].*;
            self.keys = crypto.Keys.agree(self.pair.secret_key, self.pair.public_key, public, true, self.config.protocol, self.cookie) catch return;
            self.state = .responding;
            self.respond(now);
        },
        .denied => {
            if (self.state != .responding or data.len != wire.sealed_overhead + 1 or wire.numberOf(data) != 0) return;
            var reason: [1]u8 = undefined;
            _ = crypto.open(&reason, data[9..], &wire.associated(.denied, self.config.protocol), 0, self.keys.receive) catch return;
            self.end(@enumFromInt(reason[0]));
        },
        .data => {
            if (self.state == .responding) {
                // The first sealed packet from the server: its connection
                // made, to open it.
                var c: Connection = .init(self.gpa, self.config.connection, self.config.protocol, self.keys, now);
                c.receive(now, data) catch {
                    c.deinit();
                    return;
                };
                self.keys.wipe();
                self.connection = c;
                self.state = .connected;
                if (c.accepted) |slot| {
                    self.slot = slot;
                    self.happen(.{ .connected = slot });
                }
                return;
            }
            if (self.state != .connected) return;
            const c = &self.connection.?;
            const had = c.accepted;
            c.receive(now, data) catch return;
            if (had == null) if (c.accepted) |slot| {
                self.slot = slot;
                self.happen(.{ .connected = slot });
            };
        },
        else => {},
    }
}

/// What happened since: joined, gone, and the messages that came.
pub fn next(self: *Client) ?Event {
    if (self.events_at < self.events_len) {
        const event = self.events[self.events_at];
        self.events_at += 1;
        return event;
    }
    self.events_len = 0;
    self.events_at = 0;
    if (self.state != .connected) return null;
    const m = self.connection.?.next() orelse return null;
    return .{ .message = m };
}
