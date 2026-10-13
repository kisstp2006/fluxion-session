// SPDX-License-Identifier: BSD-2-Clause

//! A server and its clients, end to end, over a network in memory - and
//! once over real UDP sockets.

const std = @import("std");
const testing = std.testing;
const session = @import("root.zig");
const Server = session.Server;
const Client = session.Client;
const Network = session.transport.Network;

const ms = std.time.ns_per_ms;
const protocol: u64 = 0xF1C5_0001;

const World = struct {
    network: Network,
    server_end: *Network.Endpoint,
    server: Server,
    ends: [4]*Network.Endpoint,
    clients: [4]Client,

    fn init(self: *World, conditions: Network.Conditions, config: Server.Config, client_config: Client.Config) !void {
        self.network = .init(testing.allocator, conditions, 11);
        errdefer self.network.deinit();
        self.server_end = try self.network.endpoint(27015);
        self.server = try .init(testing.allocator, testing.io, self.server_end.transport(), config);
        for (&self.ends, &self.clients, 0..) |*end, *client, i| {
            end.* = try self.network.endpoint(@intCast(40000 + i));
            client.* = .init(testing.allocator, end.*.transport(), client_config);
        }
    }

    fn deinit(self: *World) void {
        for (&self.clients) |*client| client.deinit();
        self.server.deinit();
        self.network.deinit();
    }

    fn tick(self: *World, step: u64) void {
        self.network.now += step;
        self.server.update(self.network.now);
        for (&self.clients) |*client| client.update(self.network.now);
    }

    fn connect(self: *World, i: usize, hello: []const u8) !void {
        try self.clients[i].connect(testing.io, self.network.now, self.server_end.address, hello);
    }
};

test "clients join, say hello, and messages go both ways" {
    var world: World = undefined;
    try world.init(.{ .latency_ns = 20 * ms, .jitter_ns = 10 * ms, .loss = 0.1 }, .{ .protocol = protocol }, .{ .protocol = protocol });
    defer world.deinit();
    try world.connect(0, "alice");
    try world.connect(1, "bob");

    var hellos: [2][]const u8 = .{ "", "" };
    var joined: usize = 0;
    var server_got: usize = 0;
    var client_got: [2]usize = .{ 0, 0 };
    var hello_copies: [2][8]u8 = undefined;
    for (0..300) |_| {
        world.tick(16 * ms);
        while (world.server.next()) |event| switch (event) {
            .connected => |c| {
                @memcpy(hello_copies[c.client][0..c.hello.len], c.hello);
                hellos[c.client] = hello_copies[c.client][0..c.hello.len];
                joined += 1;
                try world.server.send(c.client, .reliable, "welcome");
            },
            .message => |m| {
                try testing.expectEqualStrings("hi", m.data);
                server_got += 1;
            },
            .disconnected => return error.TestUnexpectedResult,
        };
        for (world.clients[0..2], 0..) |*client, i| {
            while (client.next()) |event| switch (event) {
                .connected => try client.send(.reliable, "hi"),
                .message => |m| {
                    try testing.expectEqualStrings("welcome", m.data);
                    client_got[i] += 1;
                },
                .disconnected => return error.TestUnexpectedResult,
            };
        }
    }
    try testing.expectEqual(@as(usize, 2), joined);
    try testing.expectEqual(@as(usize, 2), server_got);
    try testing.expectEqual(@as(usize, 1), client_got[0]);
    try testing.expectEqual(@as(usize, 1), client_got[1]);
    try testing.expectEqualStrings("alice", hellos[world.clients[0].slot]);
    try testing.expectEqualStrings("bob", hellos[world.clients[1].slot]);
    try testing.expectEqual(@as(u16, 2), world.server.clients());
}

test "a full server says so, and a slot freed is taken again" {
    var world: World = undefined;
    try world.init(.{ .latency_ns = 5 * ms }, .{ .protocol = protocol, .max_clients = 1 }, .{ .protocol = protocol });
    defer world.deinit();
    try world.connect(0, "first");
    for (0..20) |_| world.tick(16 * ms);
    try testing.expectEqual(Client.State.connected, world.clients[0].state);
    try world.connect(1, "second");
    var refused: ?session.Reason = null;
    for (0..20) |_| {
        world.tick(16 * ms);
        while (world.clients[1].next()) |event| switch (event) {
            .disconnected => |r| refused = r,
            else => {},
        };
    }
    try testing.expectEqual(@as(?session.Reason, .full), refused);

    // The first goes; the server is told, and the second gets in.
    world.clients[0].disconnect(world.network.now);
    var gone: ?session.Reason = null;
    for (0..10) |_| {
        world.tick(16 * ms);
        while (world.server.next()) |event| switch (event) {
            .disconnected => |d| gone = d.reason,
            else => {},
        };
    }
    try testing.expectEqual(@as(?session.Reason, .left), gone);
    try world.connect(1, "second");
    for (0..20) |_| world.tick(16 * ms);
    try testing.expectEqual(Client.State.connected, world.clients[1].state);
}

test "a kicked client is told, and a silent one times out" {
    var world: World = undefined;
    try world.init(.{ .latency_ns = 5 * ms }, .{ .protocol = protocol, .connection = .{ .timeout_ns = 2 * std.time.ns_per_s } }, .{ .protocol = protocol, .connection = .{ .timeout_ns = 2 * std.time.ns_per_s } });
    defer world.deinit();
    try world.connect(0, "");
    try world.connect(1, "");
    for (0..20) |_| world.tick(16 * ms);
    world.server.kick(world.network.now, world.clients[0].slot);
    var kicked = false;
    for (0..10) |_| {
        world.tick(16 * ms);
        while (world.clients[0].next()) |event| {
            if (event == .disconnected) kicked = event.disconnected == .kicked;
        }
    }
    try testing.expect(kicked);
    while (world.server.next()) |_| {}

    // Client 1 falls silent: its datagrams lost from now on.
    world.network.conditions.loss = 1;
    var timed_out = false;
    for (0..200) |_| {
        world.tick(16 * ms);
        while (world.server.next()) |event| {
            if (event == .disconnected) timed_out = event.disconnected.reason == .timed_out;
        }
    }
    try testing.expect(timed_out);
    try testing.expectEqual(Client.State.disconnected, world.clients[1].state);
}

test "a server with another key than the one known is not joined" {
    var world: World = undefined;
    try world.init(.{}, .{ .protocol = protocol }, .{ .protocol = protocol, .server_key = @splat(9), .join_timeout_ns = std.time.ns_per_s });
    defer world.deinit();
    try world.connect(0, "");
    for (0..100) |_| world.tick(16 * ms);
    try testing.expectEqual(Client.State.disconnected, world.clients[0].state);
    try testing.expectEqual(@as(u16, 0), world.server.clients());

    // With the right key, it is.
    world.clients[0].config.server_key = world.server.public_key;
    try world.connect(0, "");
    for (0..10) |_| world.tick(16 * ms);
    try testing.expectEqual(Client.State.connected, world.clients[0].state);
}

test "a forged response, a request of another game and a short one get nothing" {
    var world: World = undefined;
    try world.init(.{}, .{ .protocol = protocol }, .{ .protocol = protocol });
    defer world.deinit();
    const attacker = (try world.network.endpoint(50000)).transport();
    var buffer: [2048]u8 = undefined;

    // Another game's request, and one not padded: no challenge comes back.
    var request: [session.wire.request_size]u8 = @splat(0);
    request[0] = @intFromEnum(session.wire.Kind.request);
    std.mem.writeInt(u64, request[1..9], protocol + 1, .little);
    attacker.send(&world.server_end.address, &request);
    std.mem.writeInt(u64, request[1..9], protocol, .little);
    attacker.send(&world.server_end.address, request[0..100]);
    world.tick(ms);
    world.tick(ms);
    try testing.expect(attacker.receive(&buffer) == null);

    // A response with a made-up cookie: no slot, no answer.
    var response: [session.wire.response_head + session.crypto.tag_length]u8 = @splat(0);
    response[0] = @intFromEnum(session.wire.Kind.response);
    std.mem.writeInt(u64, response[1..9], protocol, .little);
    response[9] = 9;
    attacker.send(&world.server_end.address, &response);
    // A data packet from an address with no slot.
    var data: [64]u8 = @splat(0);
    data[0] = @intFromEnum(session.wire.Kind.data);
    attacker.send(&world.server_end.address, &data);
    world.tick(ms);
    world.tick(ms);
    try testing.expect(attacker.receive(&buffer) == null);
    try testing.expectEqual(@as(u16, 0), world.server.clients());
    try testing.expect(world.server.refused >= 4);

    // A challenge is smaller than the request that asked it.
    std.mem.writeInt(u64, request[1..9], protocol, .little);
    attacker.send(&world.server_end.address, &request);
    world.tick(ms);
    world.tick(ms);
    const challenge = attacker.receive(&buffer).?;
    try testing.expect(challenge.data.len < request.len);
}

test "the handshakes a second are capped" {
    var world: World = undefined;
    try world.init(.{}, .{ .protocol = protocol, .max_handshakes_per_second = 2, .max_clients = 4 }, .{ .protocol = protocol });
    defer world.deinit();
    for (0..4) |i| try world.connect(i, "");
    world.tick(ms);
    world.tick(ms);
    world.tick(ms);
    try testing.expectEqual(@as(u16, 2), world.server.clients());
    // A second later the budget is back, and the rest get in.
    for (0..80) |_| world.tick(16 * ms);
    try testing.expectEqual(@as(u16, 4), world.server.clients());
}

test "a LAN search finds the server, its name and its players" {
    var world: World = undefined;
    try world.init(.{ .latency_ns = 2 * ms }, .{ .protocol = protocol, .max_clients = 10, .discovery = .{ .name = "Fluxion CS2", .info = "de_dust2" } }, .{ .protocol = protocol });
    defer world.deinit();
    try world.connect(0, "");
    for (0..10) |_| world.tick(16 * ms);

    var browser: session.Browser = .init(testing.allocator, (try world.network.endpoint(50001)).transport(), protocol);
    defer browser.deinit();
    browser.search(testing.io, world.network.now, world.server_end.address);
    for (0..3) |_| {
        world.tick(2 * ms);
        browser.update(world.network.now);
    }
    try testing.expectEqual(@as(usize, 1), browser.found.items.len);
    const found = browser.found.items[0];
    try testing.expectEqualStrings("Fluxion CS2", found.name());
    try testing.expectEqualStrings("de_dust2", found.info());
    try testing.expectEqual(@as(u16, 1), found.players);
    try testing.expectEqual(@as(u16, 10), found.most);
    try testing.expectEqual(@as(u64, 4 * ms), found.ping_ns);
}

test "a server closing tells its clients" {
    var world: World = undefined;
    try world.init(.{ .latency_ns = 5 * ms }, .{ .protocol = protocol }, .{ .protocol = protocol });
    defer world.deinit();
    try world.connect(0, "");
    for (0..10) |_| world.tick(16 * ms);
    world.server.close(world.network.now);
    var reason: ?session.Reason = null;
    for (0..5) |_| {
        world.tick(16 * ms);
        while (world.clients[0].next()) |event| {
            if (event == .disconnected) reason = event.disconnected;
        }
    }
    try testing.expectEqual(@as(?session.Reason, .server_closed), reason);
}

test "a session over real UDP sockets" {
    const io = testing.io;
    var server_socket = try session.transport.Udp.open(io, .{ .ip4 = .loopback(0) }, .{});
    defer server_socket.close();
    var client_socket = try session.transport.Udp.open(io, .{ .ip4 = .loopback(0) }, .{});
    defer client_socket.close();
    var server: Server = try .init(testing.allocator, io, server_socket.transport(), .{ .protocol = protocol });
    defer server.deinit();
    var client: Client = .init(testing.allocator, client_socket.transport(), .{ .protocol = protocol });
    defer client.deinit();

    var now: u64 = 0;
    try client.connect(io, now, server_socket.socket.address, "udp");
    var echoed = false;
    var tries: usize = 0;
    while (!echoed and tries < 20000) : (tries += 1) {
        now += ms;
        server.update(now);
        client.update(now);
        while (server.next()) |event| switch (event) {
            .message => |m| try server.send(m.client, .unreliable, m.data),
            else => {},
        };
        while (client.next()) |event| switch (event) {
            .connected => try client.send(.reliable, "ping"),
            .message => |m| echoed = std.mem.eql(u8, m.data, "ping"),
            .disconnected => return error.TestUnexpectedResult,
        };
    }
    try testing.expect(echoed);
}

test "noise, sealed or not, crashes nothing and leaks nothing" {
    var world: World = undefined;
    try world.init(.{}, .{ .protocol = protocol, .discovery = .{ .name = "x" } }, .{ .protocol = protocol });
    defer world.deinit();
    try world.connect(0, "");
    for (0..10) |_| world.tick(16 * ms);
    const noise = (try world.network.endpoint(50002)).transport();
    var prng: std.Random.DefaultPrng = .init(3);
    const r = prng.random();
    var packet: [session.wire.max_datagram]u8 = undefined;
    for (0..20000) |_| {
        const len = r.uintAtMost(usize, packet.len);
        r.bytes(packet[0..len]);
        if (len > 0) packet[0] = r.intRangeAtMost(u8, 0, 8);
        noise.send(&world.server_end.address, packet[0..len]);
        world.network.now += 1;
        world.server.update(world.network.now);
    }
    try testing.expectEqual(@as(u16, 1), world.server.clients());

    // Sealed with the right key, but of no sense: refused, or taken as what
    // it happens to say, and never a crash.
    const keys: session.crypto.Keys = .{ .send = @splat(1), .receive = @splat(2) };
    var c: session.Connection = .init(testing.allocator, .{}, protocol, keys, 0);
    defer c.deinit();
    var plain: [session.wire.max_datagram - session.wire.sealed_overhead]u8 = undefined;
    for (1..20000) |n| {
        const len = r.uintAtMost(usize, plain.len);
        r.bytes(plain[0..len]);
        // Mostly well-formed kinds, to reach deeper.
        if (len > 7) plain[7] &= 7;
        const sealed = session.wire.sealPacket(&packet, .data, protocol, n, plain[0..len], keys.receive);
        c.receive(0, sealed) catch {};
        while (c.next()) |_| {}
        c.broken = false;
    }
}
