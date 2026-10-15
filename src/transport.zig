// SPDX-License-Identifier: BSD-2-Clause

//! Where datagrams go and come from. A session asks only two things of its
//! transport - send this to there, and give me what came, without waiting -
//! so it runs the same over a UDP socket, over a relay, or over `Network`:
//! a made-up one in memory, with the delay, jitter, loss and doubling a test
//! asks for, on a clock the test turns.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
pub const Address = Io.net.IpAddress;

/// The largest datagram a session sends or takes: what crosses the
/// internet unsplit.
pub const max_datagram = 1200;

pub const Datagram = struct {
    from: Address,
    data: []u8,
};

pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ptr: *anyopaque, to: *const Address, data: []const u8) void,
        /// The next datagram that came, into `buffer`; null if none is
        /// waiting. Never waits.
        receive: *const fn (ptr: *anyopaque, buffer: []u8) ?Datagram,
    };

    pub fn send(self: Transport, to: *const Address, data: []const u8) void {
        self.vtable.send(self.ptr, to, data);
    }

    pub fn receive(self: Transport, buffer: []u8) ?Datagram {
        return self.vtable.receive(self.ptr, buffer);
    }
};

/// A UDP socket. What fails to go - a host that cannot be reached, a full
/// buffer - is counted and let go, as UDP lets it go anyway.
pub const Udp = struct {
    io: Io,
    socket: Io.net.Socket,
    failed_sends: u64 = 0,

    pub const Options = struct {
        /// Whether datagrams may go to a broadcast address: what finds
        /// servers on a LAN.
        broadcast: bool = false,
    };

    /// A socket on `address`: port 0 for any free one, `socket.address`
    /// saying which.
    pub fn open(io: Io, address: Address, options: Options) !Udp {
        return .{ .io = io, .socket = try address.bind(io, .{ .mode = .dgram, .allow_broadcast = options.broadcast }) };
    }

    pub fn close(self: *Udp) void {
        self.socket.close(self.io);
    }

    pub fn port(self: Udp) u16 {
        return self.socket.address.getPort();
    }

    pub fn transport(self: *Udp) Transport {
        return .{ .ptr = self, .vtable = &.{ .send = send, .receive = receive } };
    }

    fn send(ptr: *anyopaque, to: *const Address, data: []const u8) void {
        const self: *Udp = @ptrCast(@alignCast(ptr));
        self.socket.send(self.io, to, data) catch {
            self.failed_sends += 1;
        };
    }

    fn receive(ptr: *anyopaque, buffer: []u8) ?Datagram {
        const self: *Udp = @ptrCast(@alignCast(ptr));
        const now: Io.Timeout = .{ .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake } };
        // A datagram refused on the way - a port that is closed - says so
        // to the next receive; it is skipped, not taken for the end.
        var tries: u8 = 0;
        while (tries < 8) : (tries += 1) {
            const message = self.socket.receiveTimeout(self.io, buffer, now) catch |err| switch (err) {
                error.Timeout => return null,
                else => continue,
            };
            return .{ .from = message.from, .data = message.data };
        }
        return null;
    }
};

/// A network in memory, for tests: endpoints at addresses, datagrams
/// between them arriving after `latency` and up to `jitter` more - so out
/// of order - some lost, some twice, as `Conditions` say. Its time is
/// `now`, moved by the test.
pub const Network = struct {
    gpa: std.mem.Allocator,
    conditions: Conditions,
    random: std.Random.DefaultPrng,
    now: u64 = 0,
    in_flight: std.ArrayList(Flying) = .empty,
    endpoints: std.ArrayList(*Endpoint) = .empty,
    boxes: std.ArrayList(*Box) = .empty,
    sent: u64 = 0,
    lost: u64 = 0,
    bytes: u64 = 0,

    pub const Conditions = struct {
        latency_ns: u64 = 0,
        jitter_ns: u64 = 0,
        /// The share of datagrams lost, and doubled, 0 to 1.
        loss: f32 = 0,
        duplicate: f32 = 0,
    };

    const Flying = struct {
        arrives: u64,
        from: Address,
        to: Address,
        data: []u8,
    };

    pub const Endpoint = struct {
        network: *Network,
        address: Address,
        /// The NAT it is behind, if any: `address` its own, inside.
        box: ?*Box = null,

        pub fn transport(self: *Endpoint) Transport {
            return .{ .ptr = self, .vtable = &.{ .send = send, .receive = receive } };
        }

        fn send(ptr: *anyopaque, to: *const Address, data: []const u8) void {
            const self: *Endpoint = @ptrCast(@alignCast(ptr));
            const from = if (self.box) |box| box.outward(self.address, to.*) orelse return else self.address;
            self.network.carry(from, to.*, data);
        }

        fn receive(ptr: *anyopaque, buffer: []u8) ?Datagram {
            const self: *Endpoint = @ptrCast(@alignCast(ptr));
            return self.network.take(self, buffer);
        }
    };

    /// How a NAT maps those behind it, as RFC 4787 sorts them.
    pub const NatKind = enum {
        /// One port outside for each endpoint inside, open to anyone once
        /// it has sent anything.
        full_cone,
        /// One port outside for each endpoint inside, open only to the
        /// addresses it has sent to: what most home routers are.
        restricted,
        /// A new port outside for each address an endpoint sends to, open
        /// only to that address: what no opening datagram gets through.
        symmetric,
    };

    /// A NAT: the address the world sees those behind it at, and its ports.
    pub const Box = struct {
        gpa: std.mem.Allocator,
        kind: NatKind,
        outside: [4]u8,
        next_port: u16 = 50000,
        mappings: std.ArrayList(Mapping) = .empty,
        permits: std.ArrayList(Permit) = .empty,

        const Mapping = struct { inside: Address, remote: ?Address, port: u16 };
        const Permit = struct { inside: Address, remote: Address };

        fn deinit(self: *Box) void {
            self.mappings.deinit(self.gpa);
            self.permits.deinit(self.gpa);
        }

        /// The address a datagram from `inside` to `to` leaves at; its way
        /// back opened as the kind of NAT opens it.
        fn outward(self: *Box, inside: Address, to: Address) ?Address {
            const remote: ?Address = if (self.kind == .symmetric) to else null;
            const port = for (self.mappings.items) |held| {
                if (!held.inside.eql(&inside)) continue;
                if (remote) |wanted| {
                    if (!held.remote.?.eql(&wanted)) continue;
                }
                break held.port;
            } else made: {
                const port = self.next_port;
                self.next_port += 1;
                self.mappings.append(self.gpa, .{ .inside = inside, .remote = remote, .port = port }) catch return null;
                break :made port;
            };
            const known = for (self.permits.items) |held| {
                if (held.inside.eql(&inside) and held.remote.eql(&to)) break true;
            } else false;
            if (!known) self.permits.append(self.gpa, .{ .inside = inside, .remote = to }) catch return null;
            return .{ .ip4 = .{ .bytes = self.outside, .port = port } };
        }

        /// Whether a datagram from `from` to `to`, outside, reaches
        /// `inside`.
        fn lets(self: *const Box, inside: Address, from: Address, to: Address) bool {
            for (self.mappings.items) |held| {
                if (!held.inside.eql(&inside)) continue;
                const at: Address = .{ .ip4 = .{ .bytes = self.outside, .port = held.port } };
                if (!at.eql(&to)) continue;
                switch (self.kind) {
                    .full_cone => return true,
                    .symmetric => return held.remote.?.eql(&from),
                    .restricted => for (self.permits.items) |permit| {
                        if (permit.inside.eql(&inside) and permit.remote.eql(&from)) return true;
                    },
                }
            }
            return false;
        }
    };

    pub fn init(gpa: std.mem.Allocator, conditions: Conditions, seed: u64) Network {
        return .{ .gpa = gpa, .conditions = conditions, .random = .init(seed) };
    }

    pub fn deinit(self: *Network) void {
        for (self.in_flight.items) |flying| self.gpa.free(flying.data);
        self.in_flight.deinit(self.gpa);
        for (self.endpoints.items) |made| self.gpa.destroy(made);
        self.endpoints.deinit(self.gpa);
        for (self.boxes.items) |made| {
            made.deinit();
            self.gpa.destroy(made);
        }
        self.boxes.deinit(self.gpa);
    }

    /// A NAT of `kind`, the world seeing those behind it at `outside`.
    pub fn nat(self: *Network, kind: NatKind, outside: [4]u8) !*Box {
        const made = try self.gpa.create(Box);
        errdefer self.gpa.destroy(made);
        made.* = .{ .gpa = self.gpa, .kind = kind, .outside = outside };
        try self.boxes.append(self.gpa, made);
        return made;
    }

    /// An endpoint behind `box`, at 10.0.0.1:`port` inside it.
    pub fn endpointBehind(self: *Network, box: *Box, port: u16) !*Endpoint {
        const made = try self.endpoint(port);
        made.address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = port } };
        made.box = box;
        return made;
    }

    /// An endpoint at 127.0.0.1:`port`.
    pub fn endpoint(self: *Network, port: u16) !*Endpoint {
        const made = try self.gpa.create(Endpoint);
        errdefer self.gpa.destroy(made);
        made.* = .{ .network = self, .address = .{ .ip4 = .loopback(port) } };
        try self.endpoints.append(self.gpa, made);
        return made;
    }

    fn carry(self: *Network, from: Address, to: Address, data: []const u8) void {
        self.sent += 1;
        self.bytes += data.len;
        const r = self.random.random();
        if (r.float(f32) < self.conditions.loss) {
            self.lost += 1;
            return;
        }
        const copies: u8 = if (r.float(f32) < self.conditions.duplicate) 2 else 1;
        for (0..copies) |_| {
            const jitter = if (self.conditions.jitter_ns > 0) r.uintLessThan(u64, self.conditions.jitter_ns) else 0;
            const copy = self.gpa.dupe(u8, data) catch return;
            self.in_flight.append(self.gpa, .{ .arrives = self.now + self.conditions.latency_ns + jitter, .from = from, .to = to, .data = copy }) catch {
                self.gpa.free(copy);
                return;
            };
        }
    }

    fn take(self: *Network, end: *Endpoint, buffer: []u8) ?Datagram {
        // The one arrived first, of those for `end` - through its NAT, those
        // it lets in.
        var best: ?usize = null;
        for (self.in_flight.items, 0..) |flying, i| {
            if (flying.arrives > self.now) continue;
            const mine = if (end.box) |box| box.lets(end.address, flying.from, flying.to) else flying.to.eql(&end.address);
            if (!mine) continue;
            if (best == null or flying.arrives < self.in_flight.items[best.?].arrives) best = i;
        }
        const i = best orelse return null;
        const flying = self.in_flight.orderedRemove(i);
        defer self.gpa.free(flying.data);
        const len = @min(flying.data.len, buffer.len);
        @memcpy(buffer[0..len], flying.data[0..len]);
        return .{ .from = flying.from, .data = buffer[0..len] };
    }
};

test "a network in memory delivers after its delay, and loses what it is told to" {
    var network: Network = .init(testing.allocator, .{ .latency_ns = 50 }, 1);
    defer network.deinit();
    const a = try network.endpoint(1);
    const b = try network.endpoint(2);
    a.transport().send(&b.address, "hi");
    var buffer: [16]u8 = undefined;
    try testing.expect(b.transport().receive(&buffer) == null);
    network.now = 50;
    const got = b.transport().receive(&buffer).?;
    try testing.expectEqualStrings("hi", got.data);
    try testing.expect(got.from.eql(&a.address));
    try testing.expect(b.transport().receive(&buffer) == null);

    network.conditions.loss = 1;
    a.transport().send(&b.address, "gone");
    network.now = 1000;
    try testing.expect(b.transport().receive(&buffer) == null);
    try testing.expectEqual(@as(u64, 1), network.lost);
}

test "a UDP socket sends and takes, never waiting" {
    const io = testing.io;
    var a = try Udp.open(io, .{ .ip4 = .loopback(0) }, .{});
    defer a.close();
    var b = try Udp.open(io, .{ .ip4 = .loopback(0) }, .{});
    defer b.close();
    var buffer: [max_datagram]u8 = undefined;
    try testing.expect(a.transport().receive(&buffer) == null);
    b.transport().send(&a.socket.address, "hello");
    // Over loopback it is there at once, or a moment later.
    var got: ?Datagram = null;
    for (0..1000) |_| {
        got = a.transport().receive(&buffer);
        if (got != null) break;
    }
    try testing.expectEqualStrings("hello", got.?.data);
    try testing.expectEqual(b.port(), got.?.from.getPort());
}
