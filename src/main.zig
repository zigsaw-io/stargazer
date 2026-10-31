//! The stargazer command: eStargz blobs made, listed, read, checked and
//! extracted, for tests and for use outside zigsaw.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const stargazer = @import("stargazer");
const estargz = stargazer.estargz;
const Source = stargazer.Source;
const Toc = stargazer.Toc;

const usage =
    \\usage: stargazer <command> [options]
    \\
    \\commands:
    \\  convert [--chunk-size=<bytes>] <tar> <blob>
    \\                          make an eStargz blob of a tar, or of a gzip-compressed one
    \\  info <blob>             where the TOC is, its digest, and what it lists
    \\  ls <blob>               list the entries: type, mode, size, name
    \\  cat <blob> <name>       write a file's contents to stdout, checked
    \\  verify [--toc-digest=<digest>] <blob>
    \\                          check the layout against the TOC, the TOC against the
    \\                          digest if given, and every file's and chunk's digest
    \\  extract [--jobs=<n>] <blob> <dir>
    \\                          write the directories and files into a new directory, checked
    \\  plan [--max-requests=<n>] [--min-gap=<bytes>] <old>... <new>
    \\                          how much of the new blob an update could copy from the old
    \\                          ones, and how much it must fetch, in how many requests
    \\  version                 print the version
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    // Thread-safe, for extract's workers.
    const gpa = std.heap.smp_allocator;
    run(init.io, gpa, arena, args[1..]) catch |err| {
        var buf: [1024]u8 = undefined;
        var stderr = Io.File.stderr().writerStreaming(init.io, &buf);
        switch (err) {
            error.Usage => stderr.interface.writeAll(usage) catch {},
            error.Reported => {},
            else => stderr.interface.print("stargazer: {s}\n", .{@errorName(err)}) catch {},
        }
        stderr.interface.flush() catch {};
        std.process.exit(if (err == error.Usage) 2 else 1);
    };
}

fn run(io: Io, gpa: Allocator, arena: Allocator, all_args: []const [:0]const u8) !void {
    if (all_args.len == 0) return error.Usage;
    const command = all_args[0];
    var options: std.StringHashMapUnmanaged([]const u8) = .empty;
    var args: std.ArrayList([]const u8) = .empty;
    for (all_args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--")) {
            const eq = std.mem.indexOfScalar(u8, arg, '=') orelse return error.Usage;
            try options.put(arena, arg[2..eq], arg[eq + 1 ..]);
        } else try args.append(arena, arg);
    }

    var out_buf: [64 * 1024]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};

    if (std.mem.eql(u8, command, "version")) {
        try expectArgs(args.items, 0, options, &.{});
        try out.print("{s}\n", .{stargazer.version});
    } else if (std.mem.eql(u8, command, "convert")) {
        try expectArgs(args.items, 2, options, &.{"chunk-size"});
        var opts: estargz.Options = .{};
        if (options.get("chunk-size")) |text| opts.chunk_size = std.fmt.parseInt(u64, text, 10) catch return error.Usage;
        if (opts.chunk_size == 0) return error.Usage;
        try convert(io, gpa, args.items[0], args.items[1], opts, out);
    } else if (std.mem.eql(u8, command, "info")) {
        try expectArgs(args.items, 1, options, &.{});
        var blob = try Blob.open(io, gpa, args.items[0]);
        defer blob.close(io);
        try info(blob.reader, out);
    } else if (std.mem.eql(u8, command, "ls")) {
        try expectArgs(args.items, 1, options, &.{});
        var blob = try Blob.open(io, gpa, args.items[0]);
        defer blob.close(io);
        for (blob.reader.files) |f| {
            if (f.name.len == 0) continue;
            try out.print("{s: <8} {o:0>4} {d: >12} {s}", .{ @tagName(f.entry.type), (f.entry.mode orelse 0) & 0o7777, f.size, f.name });
            if (f.entry.linkName) |link| try out.print(" -> {s}", .{link});
            try out.writeByte('\n');
        }
    } else if (std.mem.eql(u8, command, "cat")) {
        try expectArgs(args.items, 2, options, &.{});
        var blob = try Blob.open(io, gpa, args.items[0]);
        defer blob.close(io);
        const f = blob.reader.lookup(args.items[1]) orelse return reported(io, "{s}: no such file in {s}", .{ args.items[1], args.items[0] });
        if (f.entry.type != .reg) return reported(io, "{s}: not a regular file", .{args.items[1]});
        var scratch: estargz.Reader.Scratch = .{};
        defer scratch.deinit(gpa);
        try blob.reader.readFile(gpa, &scratch, f, out);
    } else if (std.mem.eql(u8, command, "verify")) {
        try expectArgs(args.items, 1, options, &.{"toc-digest"});
        var blob = try Blob.open(io, gpa, args.items[0]);
        defer blob.close(io);
        if (options.get("toc-digest")) |want| {
            const digest = Toc.parseDigest(want) catch return error.Usage;
            if (!std.mem.eql(u8, &digest, &blob.reader.toc_digest))
                return reported(io, "the TOC's digest is {s}, not {s}", .{ &Toc.formatDigest(blob.reader.toc_digest), want });
        }
        const report = try blob.reader.verify(gpa);
        try out.print("ok: {d} entries, {d} chunks, {d} gzip members, {d} bytes uncompressed\n", .{
            report.entries, report.chunks, report.members, report.uncompressed_size,
        });
    } else if (std.mem.eql(u8, command, "extract")) {
        try expectArgs(args.items, 2, options, &.{"jobs"});
        var opts: estargz.Reader.ExtractOptions = .{};
        if (options.get("jobs")) |text| opts.jobs = std.fmt.parseInt(usize, text, 10) catch return error.Usage;
        if (opts.jobs == 0) return error.Usage;
        var blob = try Blob.open(io, gpa, args.items[0]);
        defer blob.close(io);
        try blob.reader.extract(io, gpa, args.items[1], opts);
    } else if (std.mem.eql(u8, command, "plan")) {
        if (args.items.len < 2) return error.Usage;
        try expectArgs(args.items, args.items.len, options, &.{ "max-requests", "min-gap" });
        var opts: stargazer.plan.Plan.CoalesceOptions = .{};
        if (options.get("max-requests")) |text| opts.max_requests = std.fmt.parseInt(usize, text, 10) catch return error.Usage;
        if (options.get("min-gap")) |text| opts.min_gap = std.fmt.parseInt(u64, text, 10) catch return error.Usage;
        if (opts.max_requests == 0) return error.Usage;
        try plan(io, gpa, arena, args.items[0 .. args.items.len - 1], args.items[args.items.len - 1], opts, out);
    } else return error.Usage;
}

fn plan(io: Io, gpa: Allocator, arena: Allocator, old_paths: []const []const u8, new_path: []const u8, options: stargazer.plan.Plan.CoalesceOptions, out: *Io.Writer) !void {
    const olds = try arena.alloc(Blob, old_paths.len);
    const readers = try arena.alloc(*const estargz.Reader, old_paths.len);
    var opened: usize = 0;
    defer for (olds[0..opened]) |*b| b.close(io);
    for (old_paths, olds, readers) |path, *b, *r| {
        b.* = try Blob.open(io, gpa, path);
        opened += 1;
        r.* = b.reader;
    }
    var new = try Blob.open(io, gpa, new_path);
    defer new.close(io);

    var p = try stargazer.plan.make(gpa, new.reader, readers);
    defer p.deinit();
    var opts = options;
    // Opening the blob read its TOC and footer.
    opts.have_from = new.reader.footer.toc_offset;
    try p.coalesce(opts);
    const size = new.reader.source.size;
    const tail = size - opts.have_from;
    const percent = struct {
        fn of(part: u64, whole: u64) f64 {
            return if (whole == 0) 0 else 100 * @as(f64, @floatFromInt(part)) / @as(f64, @floatFromInt(whole));
        }
    }.of;
    try out.print("blob size          {d}\n", .{size});
    try out.print("copied             {d} ({d:.1}%)\n", .{ p.copied(), percent(p.copied(), size) });
    try out.print("fetched            {d} ({d:.1}%) in {d} requests, and {d} of TOC and footer\n", .{
        p.fetched() - tail, percent(p.fetched() - tail, size), p.requests(opts.have_from), tail,
    });
}

fn expectArgs(args: []const []const u8, n: usize, options: std.StringHashMapUnmanaged([]const u8), allowed: []const []const u8) !void {
    if (args.len != n) return error.Usage;
    var it = options.keyIterator();
    next: while (it.next()) |key| {
        for (allowed) |a| if (std.mem.eql(u8, key.*, a)) continue :next;
        return error.Usage;
    }
}

fn reported(io: Io, comptime fmt: []const u8, args: anytype) error{Reported} {
    var buf: [1024]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &buf);
    stderr.interface.print("stargazer: " ++ fmt ++ "\n", args) catch {};
    stderr.interface.flush() catch {};
    return error.Reported;
}

/// A blob file opened through its TOC.
const Blob = struct {
    file: *Source.File,
    reader: *estargz.Reader,

    fn open(io: Io, gpa: Allocator, path: []const u8) !Blob {
        const file = try gpa.create(Source.File);
        errdefer gpa.destroy(file);
        file.* = .{ .io = io, .file = Io.Dir.cwd().openFile(io, path, .{}) catch |err|
            return reported(io, "{s}: {s}", .{ path, @errorName(err) }) };
        errdefer file.file.close(io);
        const reader = estargz.Reader.open(gpa, file.source(try file.file.length(io)), .{}) catch |err|
            return reported(io, "{s}: {s}", .{ path, @errorName(err) });
        return .{ .file = file, .reader = reader };
    }

    fn close(b: *Blob, io: Io) void {
        const gpa = b.reader.gpa;
        b.reader.deinit();
        b.file.file.close(io);
        gpa.destroy(b.file);
    }
};

fn convert(io: Io, gpa: Allocator, in_path: []const u8, out_path: []const u8, options: estargz.Options, out: *Io.Writer) !void {
    var in_file = Io.Dir.cwd().openFile(io, in_path, .{}) catch |err| return reported(io, "{s}: {s}", .{ in_path, @errorName(err) });
    defer in_file.close(io);
    var file: Source.File = .{ .io = io, .file = in_file };
    const source = file.source(try in_file.length(io));
    var in_buf: [64 * 1024]u8 = undefined;
    var in: Source.Reader = .init(source, 0, source.size, &in_buf);

    // A gzip-compressed tar is read through all its members.
    var magic: [2]u8 = undefined;
    const gzipped = source.size >= 2 and blk: {
        try source.readAll(0, &magic);
        break :blk magic[0] == 0x1f and magic[1] == 0x8b;
    };
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var tar_buf: [64 * 1024]u8 = undefined;
    var members: stargazer.gzip.MemberReader = .init(gpa, &in, window, &tar_buf, null);
    const tar_in = if (gzipped) &members.interface else &in.interface;

    var out_file = Io.Dir.cwd().createFile(io, out_path, .{}) catch |err| return reported(io, "{s}: {s}", .{ out_path, @errorName(err) });
    defer out_file.close(io);
    var blob_buf: [64 * 1024]u8 = undefined;
    var blob = out_file.writer(io, &blob_buf);
    const result = estargz.convert(gpa, tar_in, &blob.interface, options) catch |err| {
        if (err == error.ReadFailed) {
            if (members.err) |cause| return cause;
            if (in.err) |cause| return cause;
        }
        return err;
    };
    try blob.interface.flush();

    try out.print("toc digest         {s}\n", .{&Toc.formatDigest(result.toc_digest)});
    try out.print("blob digest        {s}\n", .{&Toc.formatDigest(result.blob_digest)});
    try out.print("blob size          {d}\n", .{result.blob_size});
    try out.print("uncompressed size  {d}\n", .{result.uncompressed_size});
    try out.print("toc entries        {d}\n", .{result.entries});
}

fn info(r: *const estargz.Reader, out: *Io.Writer) !void {
    var regular: usize = 0;
    var dirs: usize = 0;
    var other: usize = 0;
    var bytes: u64 = 0;
    var chunks: usize = 0;
    for (r.files) |f| switch (f.entry.type) {
        .reg => {
            regular += 1;
            bytes += f.size;
            chunks += f.chunks.len;
        },
        .dir => dirs += 1,
        else => other += 1,
    };
    try out.print("format             {s}\n", .{if (r.footer.legacy) "stargz (legacy)" else "eStargz"});
    try out.print("toc offset         {d}\n", .{r.footer.toc_offset});
    try out.print("toc digest         {s}\n", .{&Toc.formatDigest(r.toc_digest)});
    try out.print("toc size           {d}\n", .{r.toc_json.len});
    try out.print("files              {d} ({d} bytes, {d} chunks)\n", .{ regular, bytes, chunks });
    try out.print("directories        {d}\n", .{dirs});
    try out.print("other entries      {d}\n", .{other});
}
