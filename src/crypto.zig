// SPDX-License-Identifier: BSD-2-Clause

//! What keeps a session's packets its own: a key each way, agreed with
//! X25519 and drawn out with HKDF-SHA256, and each packet sealed with
//! ChaCha20-Poly1305 under its own number - read by no one else, and a
//! packet changed, made up or played again refused.
//!
//! The server keeps no state for a stranger: what it answers a request with
//! is a cookie, an HMAC over the asker's address, its key and the time, that
//! only the server can make and that a forged address never receives.

const std = @import("std");
const testing = std.testing;
const X25519 = std.crypto.dh.X25519;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Address = std.Io.net.IpAddress;

pub const key_length = 32;
pub const tag_length = Aead.tag_length;
pub const cookie_length = 16;
/// How long a cookie is good for: its period and the one before.
pub const cookie_period_ns: u64 = 10 * std.time.ns_per_s;

pub const Key = [key_length]u8;
pub const Cookie = [cookie_length]u8;

/// The two keys of a session: what this end seals with, and what it opens.
pub const Keys = struct {
    send: Key,
    receive: Key,

    /// The keys of a session agreed with `secret` and the other end's
    /// `public` key. Both ends get the same two, each the other way round:
    /// `client` says which end this is. Fails for a public key that is no
    /// key - one that would make every session's secret the same.
    pub fn agree(secret: Key, own_public: Key, other_public: Key, client: bool, protocol: u64, given: Cookie) error{BadKey}!Keys {
        var shared = X25519.scalarmult(secret, other_public) catch return error.BadKey;
        defer std.crypto.secureZero(u8, &shared);
        var salt: [8]u8 = undefined;
        std.mem.writeInt(u64, &salt, protocol, .little);
        var prk = Hkdf.extract(&salt, &shared);
        defer std.crypto.secureZero(u8, &prk);
        // What the keys are drawn for: both public keys, the client's first,
        // and the cookie - one session's keys, no other's.
        var context: [key_length * 2 + cookie_length + 1]u8 = undefined;
        const client_public = if (client) own_public else other_public;
        const server_public = if (client) other_public else own_public;
        @memcpy(context[0..32], &client_public);
        @memcpy(context[32..64], &server_public);
        @memcpy(context[64..80], &given);
        var to_server: Key = undefined;
        var to_client: Key = undefined;
        context[80] = 'c';
        Hkdf.expand(&to_server, &context, prk);
        context[80] = 's';
        Hkdf.expand(&to_client, &context, prk);
        return if (client) .{ .send = to_server, .receive = to_client } else .{ .send = to_client, .receive = to_server };
    }

    pub fn wipe(self: *Keys) void {
        std.crypto.secureZero(u8, &self.send);
        std.crypto.secureZero(u8, &self.receive);
    }
};

fn nonceOf(number: u64) [Aead.nonce_length]u8 {
    var nonce: [Aead.nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[4..12], number, .little);
    return nonce;
}

/// `message` sealed into `out` - as long as it and a tag - under `key` and
/// packet `number`, `header` vouched for but not hidden. A number is used
/// once a key: the caller counts them.
pub fn seal(out: []u8, message: []const u8, header: []const u8, number: u64, key: Key) void {
    std.debug.assert(out.len == message.len + tag_length);
    Aead.encrypt(out[0..message.len], out[message.len..][0..tag_length], message, header, nonceOf(number), key);
}

/// What `sealed` - a message and its tag - says, into `out`; refused if any
/// of it, or `header`, is not what was sealed under `key` and `number`.
pub fn open(out: []u8, sealed: []const u8, header: []const u8, number: u64, key: Key) error{Forged}![]u8 {
    if (sealed.len < tag_length) return error.Forged;
    const len = sealed.len - tag_length;
    std.debug.assert(out.len >= len);
    Aead.decrypt(out[0..len], sealed[0..len], sealed[len..][0..tag_length].*, header, nonceOf(number), key) catch return error.Forged;
    return out[0..len];
}

/// 18 bytes an address is known by: its IPv6 bytes - an IPv4 one as it
/// maps there - and its port.
pub fn addressBytes(address: Address) [18]u8 {
    var bytes: [18]u8 = @splat(0);
    switch (address) {
        .ip4 => |a| {
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            @memcpy(bytes[12..16], &a.bytes);
            std.mem.writeInt(u16, bytes[16..18], a.port, .little);
        },
        .ip6 => |a| {
            @memcpy(bytes[0..16], &a.bytes);
            std.mem.writeInt(u16, bytes[16..18], a.port, .little);
        },
    }
    return bytes;
}

pub fn sameAddress(a: Address, b: Address) bool {
    return std.mem.eql(u8, &addressBytes(a), &addressBytes(b));
}

/// The cookie the server gives `address` asking with `public` in time
/// period `period`.
pub fn cookie(secret: Key, address: Address, public: Key, period: u64) Cookie {
    var message: [18 + key_length + 8]u8 = undefined;
    @memcpy(message[0..18], &addressBytes(address));
    @memcpy(message[18..50], &public);
    std.mem.writeInt(u64, message[50..58], period, .little);
    var mac: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac, &message, &secret);
    return mac[0..cookie_length].*;
}

/// Whether `given` is the cookie made for `address` and `public` now, or
/// in the period before.
pub fn cookieGood(secret: Key, address: Address, public: Key, now_ns: u64, given: Cookie) bool {
    const period = now_ns / cookie_period_ns;
    if (std.crypto.timing_safe.eql(Cookie, cookie(secret, address, public, period), given)) return true;
    return period > 0 and std.crypto.timing_safe.eql(Cookie, cookie(secret, address, public, period - 1), given);
}

test "both ends agree on the same keys, each the other way round" {
    const io = testing.io;
    const client = X25519.KeyPair.generate(io);
    const server = X25519.KeyPair.generate(io);
    const c: Cookie = @splat(7);
    const at_client = try Keys.agree(client.secret_key, client.public_key, server.public_key, true, 42, c);
    const at_server = try Keys.agree(server.secret_key, server.public_key, client.public_key, false, 42, c);
    try testing.expectEqualSlices(u8, &at_client.send, &at_server.receive);
    try testing.expectEqualSlices(u8, &at_client.receive, &at_server.send);
    try testing.expect(!std.mem.eql(u8, &at_client.send, &at_client.receive));
    // Another protocol, other keys.
    const other = try Keys.agree(client.secret_key, client.public_key, server.public_key, true, 43, c);
    try testing.expect(!std.mem.eql(u8, &other.send, &at_client.send));
    // A key that is no key is refused.
    try testing.expectError(error.BadKey, Keys.agree(client.secret_key, client.public_key, @splat(0), true, 42, c));
}

test "a sealed packet opens only as it was sealed" {
    const key: Key = @splat(3);
    var sealed: [5 + tag_length]u8 = undefined;
    seal(&sealed, "hello", "hdr", 9, key);
    var out: [5]u8 = undefined;
    try testing.expectEqualStrings("hello", try open(&out, &sealed, "hdr", 9, key));
    try testing.expectError(error.Forged, open(&out, &sealed, "hdr", 10, key));
    try testing.expectError(error.Forged, open(&out, &sealed, "hdX", 9, key));
    sealed[0] ^= 1;
    try testing.expectError(error.Forged, open(&out, &sealed, "hdr", 9, key));
    try testing.expectError(error.Forged, open(&out, sealed[0..3], "hdr", 9, key));
}

test "a cookie is good for its own address and key, for two periods" {
    const secret: Key = @splat(1);
    const here: Address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 5000 } };
    const there: Address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 3 }, .port = 5000 } };
    const public: Key = @splat(2);
    const now: u64 = 100 * cookie_period_ns + 1;
    const c = cookie(secret, here, public, now / cookie_period_ns);
    try testing.expect(cookieGood(secret, here, public, now, c));
    try testing.expect(cookieGood(secret, here, public, now + cookie_period_ns, c));
    try testing.expect(!cookieGood(secret, here, public, now + 2 * cookie_period_ns, c));
    try testing.expect(!cookieGood(secret, there, public, now, c));
    try testing.expect(!cookieGood(secret, here, @splat(5), now, c));
}
