// SPDX-License-Identifier: BSD-2-Clause

//! `fluxion-rendezvous`: a rendezvous server, for a machine the internet
//! can reach - a VPS, a forwarded port at home. Games' servers say they are
//! there, players find and are introduced to them, and it carries the
//! sessions no NAT lets through. See `Rendezvous.zig`.
//!
//! ```bash
//! fluxion-rendezvous                 # UDP 27000
//! fluxion-rendezvous --port 27100
//! ```
//!
//! Every minute it says how many servers and links it keeps, and what it
//! carried.

const std = @import("std");
const session = @import("fluxion_session");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    var port: u16 = 27000;
    var i: usize = 1;
    while (i < arguments.len) : (i += 1) {
        if (std.mem.eql(u8, arguments[i], "--port") and i + 1 < arguments.len) {
            port = std.fmt.parseInt(u16, arguments[i + 1], 10) catch {
                std.log.err("--port wants a number: {s}", .{arguments[i + 1]});
                return error.BadPort;
            };
            i += 1;
        } else if (std.mem.eql(u8, arguments[i], "--help")) {
            std.log.info("fluxion-rendezvous [--port 27000]", .{});
            return;
        }
    }
    var socket = session.transport.Udp.open(io, .{ .ip4 = .unspecified(port) }, .{}) catch |err| {
        std.log.err("UDP port {d} did not open: {t}", .{ port, err });
        return err;
    };
    defer socket.close();
    var seed: u64 = undefined;
    io.random(std.mem.asBytes(&seed));
    var rendezvous: session.Rendezvous = .init(init.gpa, socket.transport(), .{}, seed);
    defer rendezvous.deinit();
    std.log.info("a rendezvous on UDP port {d}", .{port});
    var said: u64 = 0;
    while (true) {
        const now = nowOf(io);
        rendezvous.update(now);
        if (now -| said >= 60 * std.time.ns_per_s) {
            said = now;
            std.log.info("{d} servers, {d} links; {d} datagrams carried, {d} dropped", .{ rendezvous.servers.items.len, rendezvous.links.items.len, rendezvous.relayed, rendezvous.dropped });
        }
        io.sleep(.fromMilliseconds(1), .awake) catch return;
    }
}

fn nowOf(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    return if (now <= 0) 0 else @intCast(now);
}
