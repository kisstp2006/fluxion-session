// SPDX-License-Identifier: BSD-2-Clause

//! A server and a player each behind a NAT, a rendezvous between them, over
//! a network in memory: found, introduced, joined directly where the NATs
//! open to each other, and through the rendezvous where they cannot.

const std = @import("std");
const testing = std.testing;
const session = @import("root.zig");
const Network = session.transport.Network;

const ms = std.time.ns_per_ms;
const protocol: u64 = 0xF1C5_0001;

const World = struct {
    network: Network,
    rendezvous_end: *Network.Endpoint,
    rendezvous: session.Rendezvous,
    server_end: *Network.Endpoint,
    server_nat: session.Nat,
    server: session.Server,
    player_end: *Network.Endpoint,
    player_nat: session.Nat,
    player: session.Client,
    connected: bool = false,
    server_got: usize = 0,
    player_got: usize = 0,

    fn init(self: *World, server_kind: Network.NatKind, player_kind: Network.NatKind) !void {
        self.network = .init(testing.allocator, .{ .latency_ns = 15 * ms, .jitter_ns = 5 * ms }, 7);
        errdefer self.network.deinit();
        self.rendezvous_end = try self.network.endpoint(27000);
        self.rendezvous = .init(testing.allocator, self.rendezvous_end.transport(), .{}, 1);
        const server_box = try self.network.nat(server_kind, .{ 198, 51, 100, 1 });
        const player_box = try self.network.nat(player_kind, .{ 203, 0, 113, 1 });
        self.server_end = try self.network.endpointBehind(server_box, 27015);
        self.player_end = try self.network.endpointBehind(player_box, 40000);
        self.server_nat = .init(testing.allocator, self.server_end.transport(), self.rendezvous_end.address, protocol, .{}, 2);
        self.player_nat = .init(testing.allocator, self.player_end.transport(), self.rendezvous_end.address, protocol, .{}, 3);
        self.server = try .init(testing.allocator, testing.io, self.server_nat.transport(), .{ .protocol = protocol });
        self.player = .init(testing.allocator, self.player_nat.transport(), .{ .protocol = protocol });
        self.connected = false;
        self.server_got = 0;
        self.player_got = 0;
    }

    fn deinit(self: *World) void {
        self.player.deinit();
        self.server.deinit();
        self.player_nat.deinit();
        self.server_nat.deinit();
        self.rendezvous.deinit();
        self.network.deinit();
    }

    fn tick(self: *World) !void {
        self.network.now += 16 * ms;
        const now = self.network.now;
        self.rendezvous.update(now);
        self.server_nat.update(now);
        self.player_nat.update(now);
        self.server.update(now);
        self.player.update(now);
        while (self.server.next()) |event| switch (event) {
            .connected => |c| try self.server.send(c.client, .reliable, "welcome"),
            .message => |m| {
                try testing.expectEqualStrings("hi", m.data);
                self.server_got += 1;
            },
            .disconnected => {},
        };
        while (self.player.next()) |event| switch (event) {
            .connected => {
                self.connected = true;
                try self.player.send(.reliable, "hi");
            },
            .message => |m| {
                try testing.expectEqualStrings("welcome", m.data);
                self.player_got += 1;
            },
            .disconnected => {},
        };
    }

    /// The server listed, found and introduced to: its id.
    fn introduced(self: *World) !u64 {
        self.server_nat.register(self.network.now, "Teszt", "de_dust2", 0, 10);
        for (0..10) |_| try self.tick();
        try testing.expect(self.server_nat.id != null);
        // The world sees it at its NAT's address, not its own.
        try testing.expectEqual(@as(u8, 198), self.server_nat.public.?.ip4.bytes[0]);
        self.player_nat.search();
        for (0..10) |_| try self.tick();
        const found = self.player_nat.found();
        try testing.expectEqual(@as(usize, 1), found.len);
        try testing.expectEqualStrings("Teszt", found[0].nameText());
        try testing.expectEqualStrings("de_dust2", found[0].infoText());
        try testing.expectEqual(self.server_nat.id.?, found[0].id);
        self.player_nat.introduce(self.network.now, found[0].id);
        for (0..10) |_| {
            try self.tick();
            if (self.player_nat.direct != null) break;
        }
        try testing.expect(self.player_nat.direct != null);
        return found[0].id;
    }

    /// Joined at `address` within `ticks`: whether.
    fn joins(self: *World, address: session.Address, ticks: usize) !bool {
        try self.player.connect(testing.io, self.network.now, address, "player");
        for (0..ticks) |_| {
            try self.tick();
            if (self.connected) break;
        }
        return self.connected;
    }
};

test "behind two home routers, the server is found and joined directly" {
    var world: World = undefined;
    try world.init(.restricted, .restricted);
    defer world.deinit();
    const id = try world.introduced();
    _ = id;
    try testing.expect(try world.joins(world.player_nat.direct.?, 60));
    for (0..30) |_| try world.tick();
    try testing.expectEqual(@as(usize, 1), world.server_got);
    try testing.expectEqual(@as(usize, 1), world.player_got);
    // Not through the rendezvous: the server has the player at their NAT's
    // address.
    try testing.expectEqual(@as(u64, 0), world.rendezvous.relayed);
    try testing.expectEqual(@as(u8, 203), world.server.addressOf(world.player.slot).?.ip4.bytes[0]);
}

test "behind two NATs no opening gets through, the session goes through the rendezvous" {
    var world: World = undefined;
    try world.init(.symmetric, .symmetric);
    defer world.deinit();
    const id = try world.introduced();
    // Directly: nothing comes back.
    try testing.expect(!try world.joins(world.player_nat.direct.?, 60));
    world.player.disconnect(world.network.now);
    // Through the rendezvous: joined, and the messages go both ways.
    try testing.expect(try world.joins(session.Nat.relayed(id), 60));
    for (0..30) |_| try world.tick();
    try testing.expectEqual(@as(usize, 1), world.server_got);
    try testing.expectEqual(@as(usize, 1), world.player_got);
    try testing.expect(world.rendezvous.relayed > 4);
    try testing.expect(session.Nat.isRelayed(world.server.addressOf(world.player.slot).?));
}

test "a server that stops saying it is there is forgotten, and an unknown one is said to be" {
    var world: World = undefined;
    try world.init(.full_cone, .full_cone);
    defer world.deinit();
    const id = try world.introduced();
    world.server_nat.registering = false;
    // Past the rendezvous's time to forget it.
    for (0..2000) |_| try world.tick();
    world.player_nat.search();
    for (0..10) |_| try world.tick();
    try testing.expectEqual(@as(usize, 0), world.player_nat.found().len);
    world.player_nat.introduce(world.network.now, id);
    for (0..10) |_| try world.tick();
    try testing.expect(world.player_nat.gone);
}

test "the rendezvous carries nothing for a forged server, nor nonsense" {
    var world: World = undefined;
    try world.init(.full_cone, .full_cone);
    defer world.deinit();
    _ = try world.introduced();
    var prng: std.Random.DefaultPrng = .init(5);
    const noise = try world.network.endpoint(31000);
    var buffer: [1300]u8 = undefined;
    for (0..2000) |_| {
        const n = prng.random().intRangeAtMost(usize, 0, buffer.len);
        prng.random().bytes(buffer[0..n]);
        if (n > 0 and prng.random().boolean()) buffer[0] = prng.random().intRangeAtMost(u8, 65, 77);
        noise.transport().send(&world.rendezvous_end.address, buffer[0..n]);
    }
    // A player's token answered by someone who is not their server.
    var forged: [20]u8 = @splat(0);
    forged[0] = 75;
    noise.transport().send(&world.rendezvous_end.address, &forged);
    for (0..20) |_| try world.tick();
    try testing.expectEqual(@as(u64, 0), world.rendezvous.relayed);
    var ours: usize = 0;
    for (world.rendezvous.servers.items) |held| {
        if (held.protocol == protocol) ours += 1;
    }
    try testing.expectEqual(@as(usize, 1), ours);
}
