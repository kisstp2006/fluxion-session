// SPDX-License-Identifier: BSD-2-Clause

//! Finds the servers of a LAN: a query sent to the broadcast address - or
//! to any address - and the answers gathered, each server once, with its
//! name, its players and how long it took to answer. Answers are not
//! sealed: a list to pick from, not a promise; joining is what is sealed.

const std = @import("std");
const wire = @import("wire.zig");
const crypto = @import("crypto.zig");
const transport_ = @import("transport.zig");
const Transport = transport_.Transport;
const Address = transport_.Address;

const Browser = @This();

pub const Found = struct {
    address: Address,
    players: u16,
    most: u16,
    /// From when the query went to when the answer came.
    ping_ns: u64,
    name_buffer: [wire.max_answer_text]u8,
    name_len: u8,
    info_buffer: [wire.max_answer_text]u8,
    info_len: u8,

    pub fn name(self: *const Found) []const u8 {
        return self.name_buffer[0..self.name_len];
    }

    pub fn info(self: *const Found) []const u8 {
        return self.info_buffer[0..self.info_len];
    }
};

gpa: std.mem.Allocator,
transport: Transport,
protocol: u64,
nonce: u64 = 0,
asked: u64 = 0,
found: std.ArrayList(Found) = .empty,
/// The most servers kept: a LAN flooded with answers fills no memory.
most: usize = 64,

pub fn init(gpa: std.mem.Allocator, out: Transport, protocol: u64) Browser {
    return .{ .gpa = gpa, .transport = out, .protocol = protocol };
}

pub fn deinit(self: *Browser) void {
    self.found.deinit(self.gpa);
    self.* = undefined;
}

/// A new search, to `to` - the broadcast address and the game's port, on a
/// transport allowed to broadcast: what was found before is forgotten.
pub fn search(self: *Browser, io: std.Io, now: u64, to: Address) void {
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    self.nonce = std.mem.readInt(u64, &nonce, .little);
    self.asked = now;
    self.found.clearRetainingCapacity();
    self.ask(to);
}

/// The same search asked of one more address too: a server known by name.
pub fn ask(self: *Browser, to: Address) void {
    var out: [wire.query_size]u8 = @splat(0);
    out[0] = @intFromEnum(wire.Kind.query);
    std.mem.writeInt(u64, out[1..9], self.protocol, .little);
    std.mem.writeInt(u64, out[9..17], self.nonce, .little);
    self.transport.send(&to, &out);
}

/// The answers that came, taken.
pub fn update(self: *Browser, now: u64) void {
    var buffer: [wire.max_datagram + 1]u8 = undefined;
    var taken: u32 = 0;
    while (taken < 1024) : (taken += 1) {
        const datagram = self.transport.receive(&buffer) orelse break;
        self.take(now, datagram.from, datagram.data);
    }
}

fn take(self: *Browser, now: u64, from: Address, data: []const u8) void {
    if (data.len < 23 or data.len > wire.query_size or data[0] != @intFromEnum(wire.Kind.answer)) return;
    if (wire.protocolOf(data) != self.protocol or std.mem.readInt(u64, data[9..17], .little) != self.nonce) return;
    var found: Found = .{
        .address = from,
        .players = std.mem.readInt(u16, data[17..19], .little),
        .most = std.mem.readInt(u16, data[19..21], .little),
        .ping_ns = now -| self.asked,
        .name_buffer = undefined,
        .name_len = data[21],
        .info_buffer = undefined,
        .info_len = 0,
    };
    var at: usize = 22;
    if (found.name_len > wire.max_answer_text or at + found.name_len + 1 > data.len) return;
    @memcpy(found.name_buffer[0..found.name_len], data[at..][0..found.name_len]);
    at += found.name_len;
    found.info_len = data[at];
    at += 1;
    if (found.info_len > wire.max_answer_text or at + found.info_len != data.len) return;
    @memcpy(found.info_buffer[0..found.info_len], data[at..][0..found.info_len]);
    for (self.found.items) |*known| {
        if (crypto.sameAddress(known.address, from)) {
            known.* = found;
            return;
        }
    }
    if (self.found.items.len >= self.most) return;
    self.found.append(self.gpa, found) catch {};
}
