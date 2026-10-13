# Fluxion Session

Sessions for networked games, over UDP, in Zig: a server that clients join, every packet sealed, and three channels a message can go on.

A game's state goes out tens of times a second, and a datagram lost is better forgotten than waited for. A chat line, a kill or a map change still has to arrive, in order. Here both go over one UDP socket. Lost datagrams are not resent; what is reliable is resent until it is acknowledged. The other end receives as few datagrams as the messages fit in, each acknowledging the last 33 that came.

It knows nothing of the engine. It needs a clock, a way to send datagrams, and a way to receive them. A dedicated server, a listen server and a client all use it the same way.

## Use

```zig
const session = @import("fluxion_session");

// The server: a dedicated one, or the host's own beside its client.
var socket = try session.transport.Udp.open(io, .{ .ip4 = .unspecified(27015) }, .{});
var server: session.Server = try .init(gpa, io, socket.transport(), .{
    .protocol = 0xC52_0001, // what game, what version
    .max_clients = 10,
    .discovery = .{ .name = "My server", .info = "de_dust2" },
});
defer server.deinit();

// Each tick:
server.update(now_ns);
while (server.next()) |event| switch (event) {
    .connected => |c| log("{d} joined as {s}", .{ c.client, c.hello }),
    .disconnected => |d| log("{d} left: {t}", .{ d.client, d.reason }),
    .message => |m| handle(m.client, m.channel, m.data),
};
server.broadcast(.sequenced, snapshot);
```

```zig
// The client.
var socket = try session.transport.Udp.open(io, .{ .ip4 = .unspecified(0) }, .{});
var client: session.Client = .init(gpa, socket.transport(), .{ .protocol = 0xC52_0001 });
defer client.deinit();
try client.connect(io, now_ns, try .parse("192.168.1.20", 27015), "player name");

// Each tick:
client.update(now_ns);
while (client.next()) |event| switch (event) {
    .connected => |slot| log("in, slot {d}", .{slot}),
    .disconnected => |reason| log("out: {t}", .{reason}),
    .message => |m| handle(m.channel, m.data),
};
try client.send(.unreliable, input);
```

The time passed in is nanoseconds of a clock that only goes forward. Nothing in the library reads the clock or waits. `update` takes what has come and sends what is waiting, and returns.

## Pieces

| | What it is |
| --- | --- |
| `Server` | Clients in slots up to `max_clients`. `update`, `next`, `send`, `broadcast`, `kick`, `close`, `clients`, `connection(client)` for its round trip and counts. |
| `Client` | Joins one server. `connect` with a hello of up to 256 bytes (a name, a password, a token), then `update`, `next`, `send` and `disconnect`. A `server_key` given in its config refuses a server with any other key. |
| `Connection` | One end of a session once the keys are agreed: channels, acknowledgements, round trip (`rtt_ns`), loss, the budget, and `stats`. |
| `Channel` | `unreliable`: arrives or not, in any order. `sequenced`: arrives or not, never after a newer one. `reliable`: arrives once, in order; up to `max_message` (64 KiB), sent in pieces when larger than a datagram. |
| `Browser` | Finds servers on a LAN: `search` to the broadcast address, `update`, then `found`, with each server's name, info, players and ping. |
| `transport` | `Transport`, the two calls a session makes: send this there, and give me what has come without waiting. `Udp` is a socket. `Network` is a network in memory for tests, with latency, jitter, loss and duplication. |
| `bits` | `Writer` and `Reader`: values of 1 to 64 bits, varints, quantized floats, angles at 16 bits. They build small messages; a message that lies about its length is refused. |
| `Reason` | Why a session ended: `left`, `kicked`, `timed_out`, `server_closed`, `broken`, `full`, `refused`. |

A message received is good until the next `next`.

## Security

- **Sealed both ways.** Every packet after the handshake is sealed with ChaCha20-Poly1305. Each way has its own key, drawn with HKDF-SHA256 from an X25519 agreement. A packet's number is its nonce and is never used twice. A packet that has been changed, forged, or replayed is refused, and nothing changes.
- **A forged address gets nothing.** A request has to be 256 bytes, and the challenge that answers it is 57 bytes. The challenge carries a cookie: an HMAC of the asker's address, its key and the time. The server keeps no state until the cookie comes back, and only the real address receives it. The costly key agreement runs at most `max_handshakes_per_second` times a second.
- **The server's identity.** With `server_key`, the client refuses a server that cannot prove it holds that key, so nothing in between can stand in for it. Without it, the session is still sealed, but the first answer is trusted. A server keeps its key from run to run with `secret_key`.
- **Bounded.** Datagrams are 1200 bytes at most. A reliable message is at most `max_message`. At most `max_queued` reliable bytes wait to be sent. 256 reliable messages are in flight at a time, and a receiving end never holds more. An update takes a bounded number of datagrams. A peer that sends nonsense under a valid seal is disconnected as `broken`.
- **Answers on the LAN are not sealed.** They are a list to pick from. Joining is what is sealed.

## Not yet

These are planned in this order: NAT traversal through a rendezvous server, with hole punching and a relay for peers that cannot reach each other; and a browser transport.
