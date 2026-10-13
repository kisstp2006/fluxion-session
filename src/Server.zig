// SPDX-License-Identifier: BSD-2-Clause

//! A server: clients join it in slots, up to `max_clients`, and each has a
//! `Connection` of its own. A dedicated server runs it alone; a listen
//! server runs it beside a client of its own, over the same transport kind.
//!
//! Joining is a handshake of two round trips. A client asks with its public
//! key, in a request padded so that what answers it is smaller; the server
//! answers with its own key and a cookie, remembering nothing; the client
//! sends the cookie back with its hello, sealed under the keys both ends
//! now share; and the server, the cookie found good, takes it into a slot.
//! A client that never received the cookie - one whose address is forged -
//! never gets that far, and the costly key agreement is done at most
//! `max_handshakes_per_second` times a second.
//!
//! `update` once a tick takes what came and sends what waits; `next` gives
//! what happened since: a client joined, a client went, a message came.

const std = @import("std");
const crypto = @import("crypto.zig");
const wire = @import("wire.zig");
const transport_ = @import("transport.zig");
const Connection = @import("Connection.zig");
const X25519 = std.crypto.dh.X25519;
const Transport = transport_.Transport;
const Address = transport_.Address;
const Reason = wire.Reason;

const Server = @This();

pub const Config = struct {
    /// What game, and what version of it: one of another never joins.
    protocol: u64,
    max_clients: u16 = 16,
    connection: Connection.Config = .{},
    /// The server's lasting secret key, for a server clients know by its
    /// public key; one made for this run if null.
    secret_key: ?crypto.Key = null,
    max_handshakes_per_second: u32 = 200,
    /// What a LAN search is answered with; no answer if null.
    discovery: ?Discovery = null,
    /// Datagrams one `update` takes at most: the rest wait for the next.
    max_datagrams_per_update: u32 = 4096,
};

pub const Discovery = struct {
    name: []const u8,
    /// Anything more: the map, the mode.
    info: []const u8 = "",
};

pub const Event = union(enum) {
    /// A client took slot `client`, saying `hello` - good until the next
    /// `next`. A server that will not have it kicks it.
    connected: struct { client: u16, hello: []const u8 },
    disconnected: struct { client: u16, reason: Reason },
    message: struct { client: u16, channel: Connection.Channel, data: []const u8 },
};

const Slot = struct {
    connection: ?*Connection = null,
    address: Address = undefined,
};

const Happened = struct {
    client: u16,
    /// A joining's hello, owned; null for a going.
    hello: ?[]u8,
    reason: Reason = .left,
};

gpa: std.mem.Allocator,
transport: Transport,
config: Config,
public_key: crypto.Key,
secret_key: crypto.Key,
cookie_secret: crypto.Key,
slots: []Slot,
happened: std.ArrayList(Happened) = .empty,
happened_at: usize = 0,
given: ?[]u8 = null,
reading: u16 = 0,
handshake_tokens: f64,
refilled: u64 = 0,
name: [wire.max_answer_text]u8 = undefined,
name_len: u8 = 0,
info: [wire.max_answer_text]u8 = undefined,
info_len: u8 = 0,
/// Datagrams that made no sense, or came at a cost not paid.
refused: u64 = 0,

pub fn init(gpa: std.mem.Allocator, io: std.Io, out: Transport, config: Config) !Server {
    std.debug.assert(config.max_clients > 0);
    const pair = if (config.secret_key) |key|
        X25519.KeyPair{ .secret_key = key, .public_key = try X25519.recoverPublicKey(key) }
    else
        X25519.KeyPair.generate(io);
    var cookie_secret: crypto.Key = undefined;
    io.random(&cookie_secret);
    const slots = try gpa.alloc(Slot, config.max_clients);
    @memset(slots, .{});
    var made: Server = .{
        .gpa = gpa,
        .transport = out,
        .config = config,
        .public_key = pair.public_key,
        .secret_key = pair.secret_key,
        .cookie_secret = cookie_secret,
        .slots = slots,
        .handshake_tokens = @floatFromInt(config.max_handshakes_per_second),
    };
    if (config.discovery) |d| made.describe(d.name, d.info);
    return made;
}

/// Frees what the server holds. Its clients are not told: `close` first.
pub fn deinit(self: *Server) void {
    for (self.slots) |slot| {
        if (slot.connection) |c| {
            c.deinit();
            self.gpa.destroy(c);
        }
    }
    self.gpa.free(self.slots);
    for (self.happened.items[self.happened_at..]) |h| if (h.hello) |hello| self.gpa.free(hello);
    self.happened.deinit(self.gpa);
    if (self.given) |given| self.gpa.free(given);
    std.crypto.secureZero(u8, &self.secret_key);
    std.crypto.secureZero(u8, &self.cookie_secret);
    self.* = undefined;
}

/// Every client told the server is closing, and let go.
pub fn close(self: *Server, now: u64) void {
    for (self.slots, 0..) |slot, i| {
        if (slot.connection != null) self.drop(now, @intCast(i), .server_closed, true);
    }
}

/// What a LAN search is answered with from now on: cut to 64 bytes each.
pub fn describe(self: *Server, name: []const u8, info: []const u8) void {
    self.name_len = @intCast(@min(name.len, wire.max_answer_text));
    @memcpy(self.name[0..self.name_len], name[0..self.name_len]);
    self.info_len = @intCast(@min(info.len, wire.max_answer_text));
    @memcpy(self.info[0..self.info_len], info[0..self.info_len]);
    if (self.config.discovery == null) self.config.discovery = .{ .name = "" };
}

pub fn clients(self: *const Server) u16 {
    var n: u16 = 0;
    for (self.slots) |slot| n += @intFromBool(slot.connection != null);
    return n;
}

pub fn connection(self: *Server, client: u16) ?*Connection {
    if (client >= self.slots.len) return null;
    return self.slots[client].connection;
}

pub fn addressOf(self: *const Server, client: u16) ?Address {
    if (client >= self.slots.len or self.slots[client].connection == null) return null;
    return self.slots[client].address;
}

/// `data` to `client` on `channel`.
pub fn send(self: *Server, client: u16, channel: Connection.Channel, data: []const u8) !void {
    const c = self.connection(client) orelse return error.NotConnected;
    try c.send(channel, data);
}

/// `data` to every client; one whose queue is full misses it - and, on the
/// reliable channel, is better kicked.
pub fn broadcast(self: *Server, channel: Connection.Channel, data: []const u8) void {
    for (self.slots) |slot| {
        if (slot.connection) |c| c.send(channel, data) catch {};
    }
}

/// `client` sent away, and told so.
pub fn kick(self: *Server, now: u64, client: u16) void {
    if (self.connection(client) == null) return;
    self.drop(now, client, .kicked, true);
}

/// What came taken, what waits sent, the silent let go.
pub fn update(self: *Server, now: u64) void {
    const elapsed = now -| self.refilled;
    self.refilled = now;
    const most: f64 = @floatFromInt(self.config.max_handshakes_per_second);
    self.handshake_tokens = @min(most, self.handshake_tokens + most * @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s);

    var buffer: [wire.max_datagram + 1]u8 = undefined;
    var taken: u32 = 0;
    while (taken < self.config.max_datagrams_per_update) : (taken += 1) {
        const datagram = self.transport.receive(&buffer) orelse break;
        if (datagram.data.len == 0 or datagram.data.len > wire.max_datagram) {
            self.refused += 1;
            continue;
        }
        self.take(now, datagram.from, datagram.data);
    }

    for (self.slots, 0..) |slot, i| {
        const c = slot.connection orelse continue;
        if (c.said_gone) |reason| {
            self.drop(now, @intCast(i), @enumFromInt(reason), false);
        } else if (c.broken) {
            self.drop(now, @intCast(i), .broken, true);
        } else if (c.timedOut(now)) {
            self.drop(now, @intCast(i), .timed_out, false);
        } else {
            c.flush(now, self.transport, &slot.address);
        }
    }
}

fn take(self: *Server, now: u64, from: Address, data: []const u8) void {
    switch (@as(wire.Kind, @enumFromInt(data[0]))) {
        .data => {
            const slot = self.slotOf(from) orelse {
                self.refused += 1;
                return;
            };
            self.slots[slot].connection.?.receive(now, data) catch {};
        },
        .request => self.challenge(now, from, data),
        .response => self.respond(now, from, data),
        .query => self.answer(from, data),
        else => self.refused += 1,
    }
}

fn slotOf(self: *const Server, address: Address) ?u16 {
    for (self.slots, 0..) |slot, i| {
        if (slot.connection != null and crypto.sameAddress(slot.address, address)) return @intCast(i);
    }
    return null;
}

fn challenge(self: *Server, now: u64, from: Address, data: []const u8) void {
    if (data.len != wire.request_size or wire.protocolOf(data) != self.config.protocol or self.slotOf(from) != null) {
        self.refused += 1;
        return;
    }
    const public = data[9..41].*;
    var out: [wire.challenge_size]u8 = undefined;
    out[0] = @intFromEnum(wire.Kind.challenge);
    std.mem.writeInt(u64, out[1..9], self.config.protocol, .little);
    @memcpy(out[9..41], &self.public_key);
    @memcpy(out[41..57], &crypto.cookie(self.cookie_secret, from, public, now / crypto.cookie_period_ns));
    self.transport.send(&from, &out);
}

fn respond(self: *Server, now: u64, from: Address, data: []const u8) void {
    if (data.len < wire.response_head + crypto.tag_length or data.len > wire.response_head + wire.max_hello + crypto.tag_length or
        wire.protocolOf(data) != self.config.protocol or self.slotOf(from) != null)
    {
        self.refused += 1;
        return;
    }
    const public = data[9..41].*;
    const cookie = data[41..57].*;
    if (!crypto.cookieGood(self.cookie_secret, from, public, now, cookie) or self.handshake_tokens < 1) {
        self.refused += 1;
        return;
    }
    self.handshake_tokens -= 1;
    var keys = crypto.Keys.agree(self.secret_key, self.public_key, public, false, self.config.protocol, cookie) catch {
        self.refused += 1;
        return;
    };
    var hello_buffer: [wire.max_hello]u8 = undefined;
    const hello = crypto.open(&hello_buffer, data[wire.response_head..], &wire.associated(.response, self.config.protocol), 0, keys.receive) catch {
        keys.wipe();
        self.refused += 1;
        return;
    };
    const free = for (self.slots, 0..) |slot, i| {
        if (slot.connection == null) break @as(u16, @intCast(i));
    } else null;
    const slot = free orelse return self.deny(from, &keys, .full);
    const made = self.gpa.create(Connection) catch return self.deny(from, &keys, .full);
    const copy = self.gpa.dupe(u8, hello) catch {
        self.gpa.destroy(made);
        return self.deny(from, &keys, .full);
    };
    self.happened.append(self.gpa, .{ .client = slot, .hello = copy }) catch {
        self.gpa.free(copy);
        self.gpa.destroy(made);
        return self.deny(from, &keys, .full);
    };
    made.* = .init(self.gpa, self.config.connection, self.config.protocol, keys, now);
    made.announce = slot;
    self.slots[slot] = .{ .connection = made, .address = from };
}

fn deny(self: *Server, to: Address, keys: *crypto.Keys, reason: Reason) void {
    defer keys.wipe();
    var out: [wire.sealed_overhead + 1]u8 = undefined;
    const packet = wire.sealPacket(&out, .denied, self.config.protocol, 0, &.{@intFromEnum(reason)}, keys.send);
    self.transport.send(&to, packet);
}

fn answer(self: *Server, from: Address, data: []const u8) void {
    if (data.len != wire.query_size or wire.protocolOf(data) != self.config.protocol or self.config.discovery == null) {
        self.refused += 1;
        return;
    }
    var out: [wire.query_size]u8 = undefined;
    out[0] = @intFromEnum(wire.Kind.answer);
    @memcpy(out[1..17], data[1..17]);
    std.mem.writeInt(u16, out[17..19], self.clients(), .little);
    std.mem.writeInt(u16, out[19..21], self.config.max_clients, .little);
    var at: usize = 21;
    out[at] = self.name_len;
    @memcpy(out[at + 1 ..][0..self.name_len], self.name[0..self.name_len]);
    at += 1 + self.name_len;
    out[at] = self.info_len;
    @memcpy(out[at + 1 ..][0..self.info_len], self.info[0..self.info_len]);
    at += 1 + self.info_len;
    self.transport.send(&from, out[0..at]);
}

fn drop(self: *Server, now: u64, client: u16, reason: Reason, tell: bool) void {
    const slot = &self.slots[client];
    const c = slot.connection.?;
    if (tell) c.sayGone(now, self.transport, &slot.address, @intFromEnum(reason));
    c.deinit();
    self.gpa.destroy(c);
    slot.* = .{};
    // Its going is known even when memory is short: what is not said in an
    // event is said by the slot being empty.
    self.happened.append(self.gpa, .{ .client = client, .hello = null, .reason = reason }) catch {};
}

/// What happened since: joinings and goings first, then each client's
/// messages, in the order they came.
pub fn next(self: *Server) ?Event {
    if (self.given) |given| self.gpa.free(given);
    self.given = null;
    if (self.happened_at < self.happened.items.len) {
        const h = self.happened.items[self.happened_at];
        self.happened_at += 1;
        if (h.hello) |hello| {
            self.given = hello;
            return .{ .connected = .{ .client = h.client, .hello = hello } };
        }
        return .{ .disconnected = .{ .client = h.client, .reason = h.reason } };
    }
    self.happened.clearRetainingCapacity();
    self.happened_at = 0;
    while (self.reading < self.slots.len) : (self.reading += 1) {
        const c = self.slots[self.reading].connection orelse continue;
        if (c.next()) |m| return .{ .message = .{ .client = self.reading, .channel = m.channel, .data = m.data } };
    }
    self.reading = 0;
    return null;
}
