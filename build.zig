// SPDX-License-Identifier: BSD-2-Clause

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("fluxion_session", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The rendezvous server, a program of its own: `zig build rendezvous`.
    const rendezvous = b.addExecutable(.{ .name = "fluxion-rendezvous", .root_module = b.createModule(.{
        .root_source_file = b.path("src/rendezvous_main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "fluxion_session", .module = mod }},
    }) });
    b.installArtifact(rendezvous);
    b.step("rendezvous", "Build the rendezvous server").dependOn(&b.addInstallArtifact(rendezvous, .{}).step);

    const tests = b.addTest(.{ .name = "fluxion-session-tests", .root_module = mod });
    b.step("test", "Run the tests").dependOn(&b.addRunArtifact(tests).step);
}
