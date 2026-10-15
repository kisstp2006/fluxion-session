// SPDX-License-Identifier: BSD-2-Clause

//! Sequence numbers, as a protocol of datagrams counts: 16 bits that wrap,
//! compared as the nearer way round; the window that refuses a packet seen
//! before; and a buffer of what was sent or received under the last few
//! numbers.

const std = @import("std");
const testing = std.testing;

/// Whether `a` comes after `b`, the numbers wrapping at 65536: the nearer
/// way round decides.
pub fn newer(a: u16, b: u16) bool {
    return (a > b and a - b <= 32768) or (a < b and b - a > 32768);
}

/// The packets a connection has taken, by their 64-bit numbers: one seen
/// before, or too old to tell, is refused - what keeps a recorded packet
/// from being played back.
pub const ReplayWindow = struct {
    pub const size = 256;
    /// The newest number taken, and what each slot last took.
    newest: u64 = 0,
    seen: [size]u64 = @splat(std.math.maxInt(u64)),

    /// Whether `number` may be taken: newer than the window's back, and not
    /// taken before.
    pub fn fresh(self: *const ReplayWindow, number: u64) bool {
        if (number + size <= self.newest) return false;
        return self.seen[@intCast(number % size)] != number;
    }

    /// `number` taken. Only after its packet was found genuine.
    pub fn take(self: *ReplayWindow, number: u64) void {
        if (number > self.newest) self.newest = number;
        self.seen[@intCast(number % size)] = number;
    }
};

/// What is kept for each of the last `size` numbers: a slot a number, the
/// number it last held beside it.
pub fn Buffer(comptime T: type, comptime size: usize) type {
    return struct {
        const Self = @This();
        numbers: [size]u32 = @splat(std.math.maxInt(u32)),
        items: [size]T = undefined,

        pub fn put(self: *Self, number: u16, item: T) *T {
            const at = number % size;
            self.numbers[at] = number;
            self.items[at] = item;
            return &self.items[at];
        }

        /// What `number` holds, null where its slot was taken by another.
        pub fn get(self: *Self, number: u16) ?*T {
            const at = number % size;
            if (self.numbers[at] != number) return null;
            return &self.items[at];
        }

        pub fn remove(self: *Self, number: u16) void {
            const at = number % size;
            if (self.numbers[at] == number) self.numbers[at] = std.math.maxInt(u32);
        }
    };
}

test "sequence numbers compare the nearer way round" {
    try testing.expect(newer(1, 0));
    try testing.expect(!newer(0, 1));
    try testing.expect(newer(0, 65535));
    try testing.expect(newer(10, 65530));
    try testing.expect(!newer(65530, 10));
}

test "a packet number taken once is refused again, and one too old is refused" {
    var window: ReplayWindow = .{};
    try testing.expect(window.fresh(0));
    window.take(0);
    try testing.expect(!window.fresh(0));
    window.take(1000);
    try testing.expect(window.fresh(999));
    try testing.expect(!window.fresh(1000 - ReplayWindow.size));
    try testing.expect(window.fresh(1001));
}

test "a buffer slot keeps only its own number's item" {
    var buffer: Buffer(u32, 4) = .{};
    _ = buffer.put(1, 10);
    try testing.expectEqual(@as(u32, 10), buffer.get(1).?.*);
    _ = buffer.put(5, 50);
    try testing.expect(buffer.get(1) == null);
    try testing.expectEqual(@as(u32, 50), buffer.get(5).?.*);
}
