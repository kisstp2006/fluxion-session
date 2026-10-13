// SPDX-License-Identifier: BSD-2-Clause

//! The datagrams of a session, by their first byte, and their sizes.
//!
//!   request   [1][protocol u64][client key 32][zeros to 256]
//!   challenge [2][protocol u64][server key 32][cookie 16]
//!   response  [3][protocol u64][client key 32][cookie 16][sealed hello, number 0]
//!   denied    [4][packet number u64][sealed reason]
//!   data      [5][packet number u64][sealed ack and messages]
//!   query     [6][protocol u64][nonce u64][zeros to 160]
//!   answer    [7][protocol u64][nonce u64][players u16][most u16][name][info]
//!
//! What asks is never smaller than what answers it: a forged address gets
//! no more bytes sent to it than the forger sent.

const std = @import("std");
const crypto = @import("crypto.zig");
pub const max_datagram = @import("transport.zig").max_datagram;

pub const Kind = enum(u8) {
    request = 1,
    challenge = 2,
    response = 3,
    denied = 4,
    data = 5,
    query = 6,
    answer = 7,
    _,
};

pub const request_size = 256;
pub const challenge_size = 1 + 8 + 32 + crypto.cookie_length;
/// The most a client says of itself on joining: a name, a password, a token.
pub const max_hello = 256;
pub const response_head = 1 + 8 + 32 + crypto.cookie_length;
pub const query_size = 160;
pub const max_answer_text = 64;

/// What a sealed packet adds: its kind, its number and its tag.
pub const sealed_overhead = 1 + 8 + crypto.tag_length;

/// What sealed packets vouch for besides what they hide: their kind and the
/// protocol, so a packet of another game, or another kind, never opens.
pub fn associated(kind: Kind, protocol: u64) [9]u8 {
    var ad: [9]u8 = undefined;
    ad[0] = @intFromEnum(kind);
    std.mem.writeInt(u64, ad[1..9], protocol, .little);
    return ad;
}

/// `plain` sealed as a packet of `kind` numbered `number`, into `out`.
pub fn sealPacket(out: []u8, kind: Kind, protocol: u64, number: u64, plain: []const u8, key: crypto.Key) []u8 {
    const len = 9 + plain.len + crypto.tag_length;
    out[0] = @intFromEnum(kind);
    std.mem.writeInt(u64, out[1..9], number, .little);
    crypto.seal(out[9..len], plain, &associated(kind, protocol), number, key);
    return out[0..len];
}

pub fn numberOf(packet: []const u8) u64 {
    return std.mem.readInt(u64, packet[1..9], .little);
}

pub fn protocolOf(packet: []const u8) u64 {
    return std.mem.readInt(u64, packet[1..9], .little);
}

/// Why a session ended.
pub const Reason = enum(u8) {
    /// The other end said it was going.
    left = 1,
    /// The server sent the client away.
    kicked = 2,
    /// Nothing came for too long - or, joining, no answer came.
    timed_out = 3,
    /// The server stopped.
    server_closed = 4,
    /// What came made no sense.
    broken = 5,
    /// The server had no room.
    full = 6,
    /// The server would not take this client.
    refused = 7,
    _,
};
