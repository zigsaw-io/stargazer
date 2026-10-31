const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", @import("build.zig.zon").version);

    // What Zig packages import as "stargazer".
    const mod = b.addModule("stargazer", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("options", options);

    const exe = b.addExecutable(.{
        .name = "stargazer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "stargazer", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the stargazer command");
    run_step.dependOn(&run_cmd.step);

    // The C interface, as a static and a shared library, and its header. On
    // Windows the DLL's import library is stargazer.lib, so the static one
    // can't be.
    const static_name = if (target.result.os.tag == .windows) "stargazer_static" else "stargazer";
    const static = b.addLibrary(.{ .name = static_name, .linkage = .static, .root_module = cModule(b, mod, target, optimize) });
    const shared = b.addLibrary(.{ .name = "stargazer", .linkage = .dynamic, .root_module = cModule(b, mod, target, optimize) });
    b.installArtifact(static);
    b.installArtifact(shared);
    b.installFile("include/stargazer.h", "include/stargazer.h");

    const test_step = b.step("test", "Run the unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = mod })).step);

    // A C program built against the header and the static library, so that
    // the two can't drift apart.
    const smoke = b.addExecutable(.{
        .name = "stargazer-c-smoke",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    smoke.root_module.addCSourceFile(.{
        .file = b.path("tests/c/smoke.c"),
        .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-Werror" },
    });
    smoke.root_module.addIncludePath(b.path("include"));
    smoke.root_module.linkLibrary(static);
    const c_step = b.step("test-c", "Build a C program against stargazer.h and run it");
    c_step.dependOn(&b.addRunArtifact(smoke).step);
}

fn cModule(b: *std.Build, mod: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/c.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "stargazer", .module = mod }},
    });
}
