// SPDX-License-Identifier: BSD-2-Clause

//! A rendezvous server: what lets the players of a game reach its servers
//! across the internet, NATs and all. See `rendezvous.zig` for what it says.
//!
//! Servers tell it they are there; it keeps each, with the address the
//! world sees it at, for `server_ttl_ns` after it last said so. Players ask
//! it for the servers of their game, and to be introduced to one - then
//! reach it directly - or, where no way opens, send through it: it carries a
//! session's sealed datagrams between the two, keeping each player's link for
//! `link_ttl_ns` after it was last used, at most `max_relay_bytes_per_second`
//! each.
//!
//! It keeps no state for what asks but a server's own word and a player's
//! relayed datagrams, and it answers no more than it is asked.

const std = @import("std");
const rv = @import("rendezvous.zig");
const transport_ = @import("transport.zig");
const crypto = @import("crypto.zig");

const Rendezvous = @This();
const Transport = transport_.Transport;
const Address = transport_.Address;

pub const Config = struct {
    server_ttl_ns: u64 = 30 * std.time.ns_per_s,
    link_ttl_ns: u64 = 60 * std.time.ns_per_s,
    max_servers: usize = 4096,
    max_links: usize = 4096,
    /// What a player may send through it a second, and what its server may
    /// send back.
    max_relay_bytes_per_second: u64 = 512 * 1024,
    /// Servers listed in one answer.
    page: usize = 12,
};

pub const Server = struct {
    id: u64,
    address: Address,
    protocol: u64,
    players: u16,
    most: u16,
    name: [rv.max_text]u8 = undefined,
    name_len: u8 = 0,
    info: [rv.max_text]u8 = undefined,
    info_len: u8 = 0,
    seen: u64,

    pub fn nameText(self: *const Server) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// A player's way through it to a server: by the player's address, and
/// the token the server knows them by.
const Link = struct {
    token: u64,
    player: Address,
    server: u64,
    seen: u64,
    /// Bytes this second, each way, and when the second began.
    up: u64 = 0,
    down: u64 = 0,
    second: u64 = 0,
};

gpa: std.mem.Allocator,
transport: Transport,
config: Config,
random: std.Random.DefaultPrng,
servers: std.ArrayList(Server) = .empty,
links: std.ArrayList(Link) = .empty,
/// Datagrams it carried, and those it dropped: unknown, too many, nonsense.
relayed: u64 = 0,
dropped: u64 = 0,

pub fn init(gpa: std.mem.Allocator, out: Transport, config: Config, seed: u64) Rendezvous {
    return .{ .gpa = gpa, .transport = out, .config = config, .random = .init(seed) };
}

pub fn deinit(self: *Rendezvous) void {
    self.servers.deinit(self.gpa);
    self.links.deinit(self.gpa);
}

/// What came answered and carried on; the servers and links not heard of
/// for long forgotten.
pub fn update(self: *Rendezvous, now: u64) void {
    var buffer: [rv.max_datagram + 1]u8 = undefined;
    var taken: u32 = 0;
    while (taken < 8192) : (taken += 1) {
        const datagram = self.transport.receive(&buffer) orelse break;
        self.take(now, datagram.from, datagram.data);
    }
    var i: usize = 0;
    while (i < self.servers.items.len) {
        if (now -| self.servers.items[i].seen > self.config.server_ttl_ns) _ = self.servers.swapRemove(i) else i += 1;
    }
    i = 0;
    while (i < self.links.items.len) {
        if (now -| self.links.items[i].seen > self.config.link_ttl_ns) _ = self.links.swapRemove(i) else i += 1;
    }
}

fn take(self: *Rendezvous, now: u64, from: Address, data: []const u8) void {
    const kind = rv.Kind.of(data) orelse return self.drop();
    switch (kind) {
        .register => self.register(now, from, data),
        .list => self.list(from, data),
        .introduce => self.introduce(from, data),
        .to_server => self.toServer(now, from, data),
        .to_client => self.toClient(now, from, data),
        else => self.drop(),
    }
}

fn drop(self: *Rendezvous) void {
    self.dropped += 1;
}

fn serverAt(self: *Rendezvous, address: Address) ?*Server {
    for (self.servers.items) |*held| {
        if (crypto.sameAddress(held.address, address)) return held;
    }
    return null;
}

fn serverById(self: *Rendezvous, id: u64) ?*Server {
    for (self.servers.items) |*held| {
        if (held.id == id) return held;
    }
    return null;
}

fn register(self: *Rendezvous, now: u64, from: Address, data: []const u8) void {
    if (data.len < 1 + 8 + 4 + 2) return self.drop();
    const name = rv.getText(data[13..]) orelse return self.drop();
    const info = rv.getText(data[13 + name[1] ..]) orelse return self.drop();
    const server = self.serverAt(from) orelse made: {
        if (self.servers.items.len >= self.config.max_servers) return self.drop();
        var id: u64 = 0;
        while (id == 0 or self.serverById(id) != null) id = self.random.random().int(u64);
        self.servers.append(self.gpa, .{ .id = id, .address = from, .protocol = 0, .players = 0, .most = 0, .seen = now }) catch return self.drop();
        break :made &self.servers.items[self.servers.items.len - 1];
    };
    server.protocol = std.mem.readInt(u64, data[1..9], .little);
    server.players = std.mem.readInt(u16, data[9..11], .little);
    server.most = std.mem.readInt(u16, data[11..13], .little);
    server.name_len = @intCast(name[0].len);
    @memcpy(server.name[0..name[0].len], name[0]);
    server.info_len = @intCast(info[0].len);
    @memcpy(server.info[0..info[0].len], info[0]);
    server.seen = now;
    var out: [1 + 8 + 18]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.registered);
    std.mem.writeInt(u64, out[1..9], server.id, .little);
    rv.putAddress(out[9..27], from);
    self.transport.send(&from, &out);
}

fn list(self: *Rendezvous, from: Address, data: []const u8) void {
    if (data.len != rv.list_size) return self.drop();
    const protocol = std.mem.readInt(u64, data[1..9], .little);
    const nonce = std.mem.readInt(u64, data[9..17], .little);
    const page = std.mem.readInt(u16, data[17..19], .little);
    var out: [rv.list_size]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.listed);
    std.mem.writeInt(u64, out[1..9], nonce, .little);
    std.mem.writeInt(u16, out[9..11], page, .little);
    var total: u16 = 0;
    var count: u8 = 0;
    var at: usize = 14;
    for (self.servers.items) |*server| {
        if (server.protocol != protocol) continue;
        defer total += 1;
        if (total / self.config.page != page) continue;
        const need = 8 + 4 + 2 + @as(usize, server.name_len) + server.info_len;
        if (at + need > out.len) continue;
        std.mem.writeInt(u64, out[at..][0..8], server.id, .little);
        std.mem.writeInt(u16, out[at + 8 ..][0..2], server.players, .little);
        std.mem.writeInt(u16, out[at + 10 ..][0..2], server.most, .little);
        at += 12;
        at += rv.putText(out[at..], server.nameText());
        at += rv.putText(out[at..], server.info[0..server.info_len]);
        count += 1;
    }
    std.mem.writeInt(u16, out[11..13], total, .little);
    out[13] = count;
    self.transport.send(&from, out[0..at]);
}

fn introduce(self: *Rendezvous, from: Address, data: []const u8) void {
    if (data.len != rv.introduce_size) return self.drop();
    const id = std.mem.readInt(u64, data[1..9], .little);
    const nonce = std.mem.readInt(u64, data[9..17], .little);
    const server = self.serverById(id) orelse return self.unknown(from, id);
    // The player told where the server is; the server, where the player is.
    var peer: [1 + 8 + 8 + 18]u8 = undefined;
    peer[0] = @intFromEnum(rv.Kind.peer);
    std.mem.writeInt(u64, peer[1..9], nonce, .little);
    std.mem.writeInt(u64, peer[9..17], id, .little);
    rv.putAddress(peer[17..35], server.address);
    self.transport.send(&from, &peer);
    var punch: [1 + 18]u8 = undefined;
    punch[0] = @intFromEnum(rv.Kind.punch);
    rv.putAddress(punch[1..19], from);
    self.transport.send(&server.address, &punch);
}

fn unknown(self: *Rendezvous, to: Address, id: u64) void {
    var out: [9]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.unknown);
    std.mem.writeInt(u64, out[1..9], id, .little);
    self.transport.send(&to, &out);
}

/// Whether `link` may carry `bytes` more this second, one way or the other.
fn allowed(self: *Rendezvous, now: u64, link: *Link, bytes: usize, up: bool) bool {
    if (now -| link.second >= std.time.ns_per_s) {
        link.second = now;
        link.up = 0;
        link.down = 0;
    }
    const used = if (up) &link.up else &link.down;
    if (used.* + bytes > self.config.max_relay_bytes_per_second) return false;
    used.* += bytes;
    link.seen = now;
    return true;
}

fn toServer(self: *Rendezvous, now: u64, from: Address, data: []const u8) void {
    if (data.len <= rv.relay_head or data.len > rv.max_datagram) return self.drop();
    const id = std.mem.readInt(u64, data[1..9], .little);
    const server = self.serverById(id) orelse return self.unknown(from, id);
    const link = for (self.links.items) |*held| {
        if (held.server == id and crypto.sameAddress(held.player, from)) break held;
    } else made: {
        if (self.links.items.len >= self.config.max_links) return self.drop();
        var token: u64 = 0;
        while (token == 0 or self.linkByToken(token) != null) token = self.random.random().int(u64);
        self.links.append(self.gpa, .{ .token = token, .player = from, .server = id, .seen = now, .second = now }) catch return self.drop();
        break :made &self.links.items[self.links.items.len - 1];
    };
    if (!self.allowed(now, link, data.len, true)) return self.drop();
    var out: [rv.max_datagram]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.from_client);
    std.mem.writeInt(u64, out[1..9], link.token, .little);
    @memcpy(out[9..data.len], data[9..]);
    self.relayed += 1;
    self.transport.send(&server.address, out[0..data.len]);
}

fn linkByToken(self: *Rendezvous, token: u64) ?*Link {
    for (self.links.items) |*held| {
        if (held.token == token) return held;
    }
    return null;
}

fn toClient(self: *Rendezvous, now: u64, from: Address, data: []const u8) void {
    if (data.len <= rv.relay_head or data.len > rv.max_datagram) return self.drop();
    const token = std.mem.readInt(u64, data[1..9], .little);
    const link = self.linkByToken(token) orelse return self.drop();
    // Only the server the link is to answers through it.
    const server = self.serverById(link.server) orelse return self.drop();
    if (!crypto.sameAddress(server.address, from)) return self.drop();
    if (!self.allowed(now, link, data.len, false)) return self.drop();
    var out: [rv.max_datagram]u8 = undefined;
    out[0] = @intFromEnum(rv.Kind.from_server);
    std.mem.writeInt(u64, out[1..9], link.server, .little);
    @memcpy(out[9..data.len], data[9..]);
    self.relayed += 1;
    self.transport.send(&link.player, out[0..data.len]);
}
