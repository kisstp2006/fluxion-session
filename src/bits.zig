// SPDX-License-Identifier: BSD-2-Clause

//! Numbers in as few bits as they need: what keeps a game's state small on
//! the wire. A `Writer` packs values of any width from 1 to 64 bits one
//! after another into a buffer; a `Reader` takes them back in the same
//! order, and says so - `error.Overflow` - where the bytes it was given run
//! out, so a packet that lies about its contents is refused, not trusted.
//!
//! Quantising: a float in a known range kept to a known step - a position to
//! a sixteenth of a unit, an angle to a 65536th of a turn - in the bits that
//! step needs, and a unit vector in two small numbers.

const std = @import("std");
const testing = std.testing;

pub const Error = error{Overflow};

/// Packs bits into `buffer`, the first written in the lowest bits of its
/// first byte.
pub const Writer = struct {
    buffer: []u8,
    /// How many bits are written.
    at: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    /// `value`'s lowest `count` bits, 0 to 64.
    pub fn bits(self: *Writer, value: u64, count: u7) Error!void {
        std.debug.assert(count <= 64);
        if (self.at + count > self.buffer.len * 8) return error.Overflow;
        var left = count;
        var rest = value;
        while (left > 0) {
            const byte = self.at / 8;
            const shift: u3 = @intCast(self.at % 8);
            const room: u7 = 8 - @as(u7, shift);
            const take: u7 = @min(room, left);
            const mask: u64 = if (take == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(take)) - 1;
            if (shift == 0) self.buffer[byte] = 0;
            self.buffer[byte] |= @as(u8, @intCast(rest & mask)) << shift;
            rest = if (take == 64) 0 else rest >> @intCast(take);
            left -= take;
            self.at += take;
        }
    }

    pub fn boolean(self: *Writer, value: bool) Error!void {
        try self.bits(@intFromBool(value), 1);
    }

    /// An unsigned number in groups of seven bits and a flag, as many as it
    /// needs: small numbers in a byte.
    pub fn varint(self: *Writer, value: u64) Error!void {
        var rest = value;
        while (true) {
            try self.bits(rest & 0x7f, 7);
            rest >>= 7;
            try self.boolean(rest != 0);
            if (rest == 0) return;
        }
    }

    /// `value` in `min`..`max` to `step`: the bits that range needs.
    pub fn quantized(self: *Writer, value: f32, min: f32, max: f32, step: f32) Error!void {
        const count = stepsIn(min, max, step);
        const clamped = std.math.clamp(value, min, max);
        const index: u64 = @intFromFloat(@round((clamped - min) / step));
        try self.bits(@min(index, count), bitsFor(count));
    }

    /// An angle, in radians, to a 65536th of a turn.
    pub fn angle(self: *Writer, radians: f32) Error!void {
        const turn = radians / (2.0 * std.math.pi);
        const wrapped = turn - @floor(turn);
        try self.bits(@as(u64, @intFromFloat(@round(wrapped * 65536.0))) & 0xffff, 16);
    }

    /// The raw bytes of `data`, whole, after its length.
    pub fn bytes(self: *Writer, data: []const u8) Error!void {
        try self.varint(data.len);
        for (data) |byte| try self.bits(byte, 8);
    }

    /// How many bytes are used: the last part-filled one counted.
    pub fn used(self: Writer) usize {
        return (self.at + 7) / 8;
    }

    pub fn written(self: Writer) []u8 {
        return self.buffer[0..self.used()];
    }
};

/// Takes back what a `Writer` packed, in the order it packed it.
pub const Reader = struct {
    buffer: []const u8,
    at: usize = 0,

    pub fn init(buffer: []const u8) Reader {
        return .{ .buffer = buffer };
    }

    pub fn bits(self: *Reader, count: u7) Error!u64 {
        std.debug.assert(count <= 64);
        if (self.at + count > self.buffer.len * 8) return error.Overflow;
        var value: u64 = 0;
        var got: u7 = 0;
        while (got < count) {
            const byte = self.at / 8;
            const shift: u3 = @intCast(self.at % 8);
            const room: u7 = 8 - @as(u7, shift);
            const take: u7 = @min(room, count - got);
            const mask: u64 = (@as(u64, 1) << @intCast(take)) - 1;
            const part = (@as(u64, self.buffer[byte]) >> shift) & mask;
            value |= part << @intCast(got);
            got += take;
            self.at += take;
        }
        return value;
    }

    pub fn boolean(self: *Reader) Error!bool {
        return try self.bits(1) == 1;
    }

    /// Ten groups at most: a longer one is a lie.
    pub fn varint(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var shift: u7 = 0;
        while (shift < 70) : (shift += 7) {
            const group = try self.bits(7);
            if (shift == 63 and group > 1) return error.Overflow;
            value |= group << @intCast(shift);
            if (!try self.boolean()) return value;
        }
        return error.Overflow;
    }

    pub fn quantized(self: *Reader, min: f32, max: f32, step: f32) Error!f32 {
        const count = stepsIn(min, max, step);
        const index = try self.bits(bitsFor(count));
        if (index > count) return error.Overflow;
        return min + @as(f32, @floatFromInt(index)) * step;
    }

    /// An angle, in radians from 0 to a turn.
    pub fn angle(self: *Reader) Error!f32 {
        return @as(f32, @floatFromInt(try self.bits(16))) / 65536.0 * 2.0 * std.math.pi;
    }

    /// Bytes a `Writer.bytes` wrote, no more than `most`: pointing into a
    /// copy made in `out`.
    pub fn bytes(self: *Reader, out: []u8, most: usize) Error![]u8 {
        const told = try self.varint();
        if (told > most or told > out.len) return error.Overflow;
        const len: usize = @intCast(told);
        for (out[0..len]) |*byte| byte.* = @intCast(try self.bits(8));
        return out[0..len];
    }

    /// Whether every bit given was read: what a whole message should be.
    pub fn done(self: Reader) bool {
        return (self.at + 7) / 8 == self.buffer.len;
    }
};

fn stepsIn(min: f32, max: f32, step: f32) u64 {
    std.debug.assert(max > min and step > 0);
    return @intFromFloat(@ceil((max - min) / step));
}

/// The bits `count` needs to be written.
pub fn bitsFor(count: u64) u7 {
    if (count == 0) return 1;
    return @intCast(64 - @clz(count));
}

test "numbers of every width go and come back, and a short buffer is refused" {
    var buffer: [64]u8 = undefined;
    var w: Writer = .init(&buffer);
    try w.bits(5, 3);
    try w.boolean(true);
    try w.bits(0xdeadbeef, 32);
    try w.bits(std.math.maxInt(u64), 64);
    try w.varint(300);
    try w.varint(0);
    try w.angle(std.math.pi / 2.0);
    try w.quantized(12.34, -100, 100, 1.0 / 16.0);
    try w.bytes("hello");

    var r: Reader = .init(w.written());
    try testing.expectEqual(@as(u64, 5), try r.bits(3));
    try testing.expect(try r.boolean());
    try testing.expectEqual(@as(u64, 0xdeadbeef), try r.bits(32));
    try testing.expectEqual(std.math.maxInt(u64), try r.bits(64));
    try testing.expectEqual(@as(u64, 300), try r.varint());
    try testing.expectEqual(@as(u64, 0), try r.varint());
    try testing.expectApproxEqAbs(@as(f32, std.math.pi / 2.0), try r.angle(), 1e-4);
    try testing.expectApproxEqAbs(@as(f32, 12.34), try r.quantized(-100, 100, 1.0 / 16.0), 1.0 / 32.0);
    var out: [16]u8 = undefined;
    try testing.expectEqualStrings("hello", try r.bytes(&out, 16));
    try testing.expectError(error.Overflow, r.bits(16));

    var small: [1]u8 = undefined;
    var tight: Writer = .init(&small);
    try tight.bits(1, 8);
    try testing.expectError(error.Overflow, tight.bits(1, 1));
}

test "a length longer than allowed is refused, not copied" {
    var buffer: [32]u8 = undefined;
    var w: Writer = .init(&buffer);
    try w.bytes("a long enough text");
    var r: Reader = .init(w.written());
    var out: [32]u8 = undefined;
    try testing.expectError(error.Overflow, r.bytes(&out, 4));
}
