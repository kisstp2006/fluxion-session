// SPDX-License-Identifier: BSD-2-Clause

//! A game's way through NATs, by a rendezvous server: a `Transport` over
//! its own socket's, which a `Server` or a `Client` is given in its place.
//!
//! A server says it is there (`register`) - and keeps saying so, which also
//! keeps its NAT open to the rendezvous - and is told its id and the address
//! the world sees it at. Asked to by the rendezvous, it sends a few
//! datagrams to a player who wants to join it: what opens its NAT to them.
//!
//! A player asks for the servers of a game (`search`, then `found`), and to
//! be introduced to one (`introduce`): once the rendezvous answers, `direct`
//! is the server's address, to join as any. Where that does not open in
//! time - both NATs giving a new port for each address they send to - the
//! player joins `relayed(id)` instead: an address that is no one's on the
//! internet, whose datagrams this sends through the rendezvous, and whose
//! answers come back from it as from there. The session is sealed end to
//! end either way: the rendezvous carries what it cannot read.
//!
//! What the rendezvous says is taken here and never reaches the session; a
//! session's own datagrams pass as they came.

const std = @import("std");
const rv = @import("rendezvous.zig");
const transport_ = @import("transport.zig");
const crypto = @import("crypto.zig");

const Nat = @This();
const Transport = transport_.Transport;
const Address = transport_.Address;
const Datagram = transport_.Datagram;

pub const Config = struct {
    /// How often a server says it is there: well inside the rendezvous's
    /// time to forget it, and a NAT's to close.
    register_every_ns: u64 = 10 * std.time.ns_per_s,
    /// The datagrams a server sends a player to open its NAT to them, and
    /// how far apart.
    pings: u8 = 5,
    ping_every_ns: u64 = 100 * std.time.ns_per_ms,
    /// How often an introduction not answered is asked again.
    ask_every_ns: u64 = 500 * std.time.ns_per_ms,
};

/// A server of the game, as the rendezvous lists it.
pub const Found = struct {
    id: u64,
    players: u16,
    most: u16,
    name: [rv.max_text]u8 = undefined,
    name_len: u8 = 0,
    info: [rv.max_text]u8 = undefined,
    info_len: u8 = 0,

    pub fn nameText(self: *const Found) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn infoText(self: *const Found) []const u8 {
        return self.info[0..self.info_len];
    }
};

/// A player a server sends its opening datagrams to, and how many are left.
const Opening = struct {
    to: Address,
    left: u8,
    next: u64,
};

gpa: std.mem.Allocator,
inner: Transport,
rendezvous: Address,
protocol: u64,
config: Config,
random: std.Random.DefaultPrng,

// A server's.
registering: bool = false,
players: u16 = 0,
most: u16 = 0,
name: [rv.max_text]u8 = undefined,
name_len: u8 = 0,
info: [rv.max_text]u8 = undefined,
info_len: u8 = 0,
registered_at: u64 = 0,
/// The id the rendezvous knows it by, and the address the world sees it
/// at: null until it answers.
id: ?u64 = null,
public: ?Address = null,
openings: std.ArrayList(Opening) = .empty,

// A player's.
nonce: u64 = 0,
page: u16 = 0,
found_servers: std.ArrayList(Found) = .empty,
/// The server being introduced to, when it was last asked for, and its
/// address once the rendezvous says it; whether there is no such server.
introducing: ?u64 = null,
asked_at: u64 = 0,
direct: ?Address = null,
gone: bool = false,

pub fn init(gpa: std.mem.Allocator, inner: Transport, rendezvous: Address, protocol: u64, config: Config, seed: u64) Nat {
    return .{ .gpa = gpa, .inner = inner, .rendezvous = rendezvous, .protocol = protocol, .config = config, .random = .init(seed) };
}

pub fn deinit(self: *Nat) void {
    self.openings.deinit(self.gpa);
    self.found_servers.deinit(self.gpa);
}

pub fn transport(self: *Nat) Transport {
    return .{ .ptr = self, .vtable = &.{ .send = send, .receive = receive } };
}

// --- A server's -----------------------------------------------------------------

/// Listed by the rendezvous from now on, as `name` with `info` and its
/// players - said again whenever they change, and every while.
pub fn register(self: *Nat, now: u64, name: []const u8, info: []const u8, players: u16, most: u16) void {
    const changed = !self.registering or players != self.players or most != self.most or
        !std.mem.eql(u8, name[0..@min(name.len, rv.max_text)], self.name[0..self.name_len]) or
        !std.mem.eql(u8, info[0..@min(info.len, rv.max_text)], self.info[0..self.info_len]);
    self.registering = true;
    self.players = players;
    self.most = most;
    self.name_len = @intCast(@min(name.len, rv.max_text));
    @memcpy(self.name[0..self.name_len], name[0..self.name_len]);
    self.info_len = @intCast(@min(info.len, rv.max_text));
    @memcpy(self.info[0..self.info_len], info[0..self.info_len]);
    if (changed) self.sayThere(now);
}

fn sayThere(self: *Nat, now: u64) void {
    self.registered_at = now;
    var out: [1 + 8 + 4 + 2 * (1 + rv.max_text)]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.register);
    std.mem.writeInt(u64, out[1..9], self.protocol, .little);
    std.mem.writeInt(u16, out[9..11], self.players, .little);
    std.mem.writeInt(u16, out[11..13], self.most, .little);
    var at: usize = 13;
    at += rv.putText(out[at..], self.name[0..self.name_len]);
    at += rv.putText(out[at..], self.info[0..self.info_len]);
    self.inner.send(&self.rendezvous, out[0..at]);
}

// --- A player's -----------------------------------------------------------------

/// The rendezvous asked for the game's servers: `found` from its answers.
pub fn search(self: *Nat) void {
    self.found_servers.clearRetainingCapacity();
    self.nonce = self.random.random().int(u64);
    self.page = 0;
    self.askPage(0);
}

fn askPage(self: *Nat, page: u16) void {
    var out: [rv.list_size]u8 = @splat(0);
    out[0] = @intFromEnum(rv.Kind.list);
    std.mem.writeInt(u64, out[1..9], self.protocol, .little);
    std.mem.writeInt(u64, out[9..17], self.nonce, .little);
    std.mem.writeInt(u16, out[17..19], page, .little);
    self.inner.send(&self.rendezvous, &out);
}

pub fn found(self: *const Nat) []const Found {
    return self.found_servers.items;
}

/// Introduced to server `id`: `direct` its address once the rendezvous
/// says it - and the server told to open its NAT to this player.
pub fn introduce(self: *Nat, now: u64, id: u64) void {
    self.introducing = id;
    self.direct = null;
    self.gone = false;
    self.nonce = self.random.random().int(u64);
    self.ask(now);
}

fn ask(self: *Nat, now: u64) void {
    const id = self.introducing orelse return;
    self.asked_at = now;
    var out: [rv.introduce_size]u8 = @splat(0);
    out[0] = @intFromEnum(rv.Kind.introduce);
    std.mem.writeInt(u64, out[1..9], id, .little);
    std.mem.writeInt(u64, out[9..17], self.nonce, .little);
    self.inner.send(&self.rendezvous, &out);
}

/// The address server `id` is joined at through the rendezvous: datagrams
/// to it go through it, and its answers come back as from it.
pub fn relayed(id: u64) Address {
    return rv.relayed(1, id);
}

/// Whether `address` is one joined through the rendezvous.
pub fn isRelayed(address: Address) bool {
    return rv.relayedOf(address) != null;
}

// --- Both -----------------------------------------------------------------------

/// A server said there again, and the openings it owes sent; a player's
/// introduction asked again until it is answered.
pub fn update(self: *Nat, now: u64) void {
    if (self.registering and now -| self.registered_at >= self.config.register_every_ns) self.sayThere(now);
    if (self.introducing != null and self.direct == null and !self.gone and now -| self.asked_at >= self.config.ask_every_ns) self.ask(now);
    var i: usize = 0;
    while (i < self.openings.items.len) {
        const opening = &self.openings.items[i];
        if (now >= opening.next and opening.left > 0) {
            self.ping(opening.to);
            opening.left -= 1;
            opening.next = now + self.config.ping_every_ns;
        }
        if (opening.left == 0) _ = self.openings.swapRemove(i) else i += 1;
    }
}

fn ping(self: *Nat, to: Address) void {
    var out: [rv.ping_size]u8 = @splat(0);
    out[0] = @intFromEnum(rv.Kind.ping);
    self.inner.send(&to, &out);
}

fn send(ptr: *anyopaque, to: *const Address, data: []const u8) void {
    const self: *Nat = @ptrCast(@alignCast(ptr));
    const whose = rv.relayedOf(to.*) orelse return self.inner.send(to, data);
    if (data.len > transport_.max_datagram) return;
    var out: [rv.max_datagram]u8 = undefined;
    // To a server joined through the rendezvous, or to a player it carries.
    out[0] = @intFromEnum(if (whose[0] == 1) rv.Kind.to_server else rv.Kind.to_client);
    std.mem.writeInt(u64, out[1..9], whose[1], .little);
    @memcpy(out[9 .. 9 + data.len], data);
    self.inner.send(&self.rendezvous, out[0 .. 9 + data.len]);
}

fn receive(ptr: *anyopaque, buffer: []u8) ?Datagram {
    const self: *Nat = @ptrCast(@alignCast(ptr));
    var own: [rv.max_datagram + 1]u8 = undefined;
    var tries: u32 = 0;
    while (tries < 256) : (tries += 1) {
        const datagram = self.inner.receive(&own) orelse return null;
        const kind = rv.Kind.of(datagram.data) orelse {
            // A session's own.
            const n = @min(datagram.data.len, buffer.len);
            @memcpy(buffer[0..n], datagram.data[0..n]);
            return .{ .from = datagram.from, .data = buffer[0..n] };
        };
        // A peer's opening datagram: done its work by coming.
        if (kind == .ping) continue;
        // Nothing else but the rendezvous's own word is taken.
        if (!crypto.sameAddress(datagram.from, self.rendezvous)) continue;
        const data = datagram.data;
        switch (kind) {
            .from_client, .from_server => {
                if (data.len <= rv.relay_head) continue;
                const value = std.mem.readInt(u64, data[1..9], .little);
                const n = @min(data.len - rv.relay_head, buffer.len);
                @memcpy(buffer[0..n], data[9 .. 9 + n]);
                return .{ .from = rv.relayed(if (kind == .from_server) 1 else 2, value), .data = buffer[0..n] };
            },
            else => self.heard(kind, data),
        }
    }
    return null;
}

/// What the rendezvous said: the server's id and public address, a page of
/// servers, an introduction, a player to open to, a server gone.
fn heard(self: *Nat, kind: rv.Kind, data: []const u8) void {
    switch (kind) {
        .registered => {
            if (data.len != 1 + 8 + 18) return;
            self.id = std.mem.readInt(u64, data[1..9], .little);
            self.public = rv.getAddress(data[9..27]);
        },
        .listed => self.heardList(data),
        .peer => {
            if (data.len != 1 + 8 + 8 + 18) return;
            if (std.mem.readInt(u64, data[1..9], .little) != self.nonce) return;
            const wanted = self.introducing orelse return;
            if (std.mem.readInt(u64, data[9..17], .little) != wanted) return;
            self.direct = rv.getAddress(data[17..35]);
        },
        .punch => {
            if (data.len != 1 + 18 or !self.registering or self.config.pings == 0) return;
            const to = rv.getAddress(data[1..19]);
            for (self.openings.items) |*held| {
                if (crypto.sameAddress(held.to, to)) {
                    held.left = self.config.pings;
                    return;
                }
            }
            if (self.openings.items.len >= 256) return;
            self.ping(to);
            self.openings.append(self.gpa, .{ .to = to, .left = self.config.pings, .next = 0 }) catch {};
        },
        .unknown => {
            if (data.len != 9) return;
            if (std.mem.readInt(u64, data[1..9], .little) == self.introducing) self.gone = true;
        },
        else => {},
    }
}

fn heardList(self: *Nat, data: []const u8) void {
    if (data.len < 14 or std.mem.readInt(u64, data[1..9], .little) != self.nonce) return;
    const page = std.mem.readInt(u16, data[9..11], .little);
    if (page != self.page) return;
    const total = std.mem.readInt(u16, data[11..13], .little);
    const count = data[13];
    var at: usize = 14;
    for (0..count) |_| {
        if (at + 12 > data.len) return;
        var entry: Found = .{
            .id = std.mem.readInt(u64, data[at..][0..8], .little),
            .players = std.mem.readInt(u16, data[at + 8 ..][0..2], .little),
            .most = std.mem.readInt(u16, data[at + 10 ..][0..2], .little),
        };
        at += 12;
        const name = rv.getText(data[at..]) orelse return;
        at += name[1];
        const info = rv.getText(data[at..]) orelse return;
        at += info[1];
        entry.name_len = @intCast(name[0].len);
        @memcpy(entry.name[0..name[0].len], name[0]);
        entry.info_len = @intCast(info[0].len);
        @memcpy(entry.info[0..info[0].len], info[0]);
        self.found_servers.append(self.gpa, entry) catch return;
    }
    // The next page, while there is one.
    if (self.found_servers.items.len < total and count > 0) {
        self.page += 1;
        self.askPage(self.page);
    }
}
