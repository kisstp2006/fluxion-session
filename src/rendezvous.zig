// SPDX-License-Identifier: BSD-2-Clause

//! What a rendezvous server and the games that use it say to each other:
//! the datagrams, by their first byte - apart from a session's own, which
//! are 1 to 7 - and the addresses in them.
//!
//! A server behind a NAT is reached from the internet through one: it tells
//! the rendezvous it is there, ten times a minute (`register`), and the
//! rendezvous learns the address the world sees it at. A player asks for the
//! servers of their game (`list`), and to be introduced to one
//! (`introduce`): the rendezvous tells each the other's address (`peer`,
//! `punch`), the server sends a few datagrams to the player (`ping`) - what
//! opens its NAT to them - and the player joins it directly. Where that
//! cannot open - two NATs that give a new port for each address - the
//! session goes through the rendezvous instead (`to_server`, `from_client`,
//! `to_client`, `from_server`): sealed end to end, as ever, so it carries
//! what it cannot read.
//!
//!   register     [65][protocol u64][players u16][most u16][name n u8][name][info n u8][info]
//!   registered   [66][id u64][the address it is seen at, 18]
//!   list         [67][protocol u64][nonce u64][page u16][zeros to 1000]
//!   listed       [68][nonce u64][page u16][total u16][count u8] then each:
//!                [id u64][players u16][most u16][name n u8][name][info n u8][info]
//!   introduce    [69][id u64][nonce u64][zeros to 64]
//!   peer         [70][nonce u64][id u64][the server's address, 18]
//!   punch        [71][the player's address, 18]
//!   ping         [72][zeros to 8]
//!   to_server    [73][id u64][a session's datagram]
//!   from_client  [74][token u64][a session's datagram]
//!   to_client    [75][token u64][a session's datagram]
//!   from_server  [76][id u64][a session's datagram]
//!   unknown      [77][id u64]
//!
//! What asks is never smaller than what answers it - a list is as large as
//! the page it is answered with - so a forged address is sent no more than
//! the forger sent.

const std = @import("std");
const crypto = @import("crypto.zig");
const Address = std.Io.net.IpAddress;

pub const Kind = enum(u8) {
    register = 65,
    registered = 66,
    list = 67,
    listed = 68,
    introduce = 69,
    peer = 70,
    punch = 71,
    ping = 72,
    to_server = 73,
    from_client = 74,
    to_client = 75,
    from_server = 76,
    unknown = 77,
    _,

    pub fn of(data: []const u8) ?Kind {
        if (data.len == 0 or data[0] < 65 or data[0] > 77) return null;
        return @enumFromInt(data[0]);
    }
};

pub const list_size = 1000;
pub const introduce_size = 64;
pub const ping_size = 9;
pub const max_text = 64;
/// What a relayed datagram carries besides the session's own: its kind and
/// whose it is.
pub const relay_head = 9;
/// The most a rendezvous datagram is: a session's largest, relayed.
pub const max_datagram = @import("transport.zig").max_datagram + relay_head;

/// 18 bytes for an address, as a cookie is made of it.
pub fn putAddress(out: []u8, address: Address) void {
    @memcpy(out[0..18], &crypto.addressBytes(address));
}

pub fn getAddress(in: []const u8) Address {
    const port = std.mem.readInt(u16, in[16..18], .little);
    const mapped = std.mem.allEqual(u8, in[0..10], 0) and in[10] == 0xff and in[11] == 0xff;
    if (mapped) return .{ .ip4 = .{ .bytes = in[12..16].*, .port = port } };
    return .{ .ip6 = .{ .bytes = in[0..16].*, .port = port } };
}

/// A name or an info line, cut to `max_text`, with its length first.
pub fn putText(out: []u8, text: []const u8) usize {
    const n = @min(text.len, max_text, out.len - 1);
    out[0] = @intCast(n);
    @memcpy(out[1 .. 1 + n], text[0..n]);
    return 1 + n;
}

/// The text at `in`, and how many bytes it took; null for one cut short.
pub fn getText(in: []const u8) ?struct { []const u8, usize } {
    if (in.len == 0 or in[0] > max_text or in.len < 1 + @as(usize, in[0])) return null;
    return .{ in[1 .. 1 + @as(usize, in[0])], 1 + @as(usize, in[0]) };
}

/// The address a relayed peer is known by on this side: not one of the
/// internet's - fd00::/8, which no one routes - with whose it is in it, a
/// server by its id (`side` 1) or a player by its token (2).
pub fn relayed(side: u8, value: u64) Address {
    var bytes: [16]u8 = @splat(0);
    bytes[0] = 0xfd;
    bytes[1] = 0x00;
    bytes[2] = side;
    std.mem.writeInt(u64, bytes[8..16], value, .big);
    return .{ .ip6 = .{ .bytes = bytes, .port = 1 } };
}

/// Whose a relayed address is - `side` and its id or token - or null for an
/// address of the internet's.
pub fn relayedOf(address: Address) ?struct { u8, u64 } {
    const a = switch (address) {
        .ip6 => |held| held,
        .ip4 => return null,
    };
    if (a.bytes[0] != 0xfd or a.bytes[1] != 0x00 or a.port != 1 or (a.bytes[2] != 1 and a.bytes[2] != 2)) return null;
    return .{ a.bytes[2], std.mem.readInt(u64, a.bytes[8..16], .big) };
}

test "an address, a text and a relayed address go there and back" {
    var bytes: [18]u8 = undefined;
    const four: Address = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 27015 } };
    putAddress(&bytes, four);
    try std.testing.expect(crypto.sameAddress(getAddress(&bytes), four));
    var text: [80]u8 = undefined;
    const n = putText(&text, "de_dust2");
    const back = getText(text[0..n]).?;
    try std.testing.expectEqualStrings("de_dust2", back[0]);
    const relay = relayed(2, 0xABCD);
    try std.testing.expectEqual(@as(u64, 0xABCD), relayedOf(relay).?[1]);
    try std.testing.expect(relayedOf(four) == null);
}
