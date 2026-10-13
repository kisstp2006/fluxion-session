// SPDX-License-Identifier: BSD-2-Clause

//! Sessions of a networked game, over UDP: a server that clients join,
//! sealed end to end; three channels a message can go on; and the search
//! for servers on a LAN. See README.md.

pub const Server = @import("Server.zig");
pub const Client = @import("Client.zig");
pub const Connection = @import("Connection.zig");
pub const Browser = @import("Browser.zig");
pub const Channel = Connection.Channel;
pub const Reason = wire.Reason;

pub const transport = @import("transport.zig");
pub const Transport = transport.Transport;
pub const Address = transport.Address;
pub const bits = @import("bits.zig");
pub const sequence = @import("sequence.zig");
pub const crypto = @import("crypto.zig");
pub const wire = @import("wire.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("session_test.zig");
}
