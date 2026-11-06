//! The C interface. include/stargazer.h declares it, and must match it;
//! tests/c/smoke.c, built against the header, checks that they do.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const stargazer = @import("stargazer");
const estargz = stargazer.estargz;
const Source = stargazer.Source;
const Toc = stargazer.Toc;

const gpa = std.heap.smp_allocator;

const Status = enum(c_int) {
    ok = 0,
    io = -1,
    format = -2,
    digest = -3,
    no_memory = -4,
    invalid = -5,
    not_found = -6,
    unsupported = -7,
};

pub const ReadAtFn = *const fn (ctx: ?*anyopaque, offset: u64, buf: [*]u8, len: usize) callconv(.c) i64;
pub const ReadFn = *const fn (ctx: ?*anyopaque, buf: [*]u8, len: usize) callconv(.c) i64;
pub const WriteFn = *const fn (ctx: ?*anyopaque, buf: [*]const u8, len: usize) callconv(.c) c_int;

/// What `sg_last_error` gives: the name of the calling thread's last error.
threadlocal var last_error: [128:0]u8 = @splat(0);

fn fail(err: anyerror) c_int {
    const name = @errorName(err);
    const n = @min(name.len, last_error.len);
    @memcpy(last_error[0..n], name[0..n]);
    last_error[n] = 0;
    const status: Status = switch (err) {
        error.OutOfMemory => .no_memory,
        error.EstargzDigestMismatch, error.EstargzTocMismatch => .digest,
        error.CallbackFailed, error.ReadFailed, error.WriteFailed => .io,
        error.EstargzUnsupportedEntry, error.TarUnsupportedType, error.TarGlobalHeader => .unsupported,
        else => .format,
    };
    return @backingInt(status);
}

fn invalid(what: []const u8) c_int {
    const n = @min(what.len, last_error.len);
    @memcpy(last_error[0..n], what[0..n]);
    last_error[n] = 0;
    return @backingInt(Status.invalid);
}

const version_z = std.fmt.comptimePrint("{s}", .{stargazer.version});

export fn sg_version() [*:0]const u8 {
    return version_z;
}

export fn sg_last_error() [*:0]const u8 {
    return &last_error;
}

/// A blob read through the caller's callback.
const CallbackSource = struct {
    read_at: ReadAtFn,
    ctx: ?*anyopaque,

    fn source(s: *const CallbackSource, size: u64) Source {
        return .{ .context = s, .readAtFn = readAt, .size = size };
    }

    fn readAt(context: *const anyopaque, offset: u64, buffer: []u8) anyerror!usize {
        const s: *const CallbackSource = @ptrCast(@alignCast(context));
        const n = s.read_at(s.ctx, offset, buffer.ptr, buffer.len);
        if (n < 0 or n > buffer.len) return error.CallbackFailed;
        return @intCast(n);
    }
};

/// Bytes written to the caller's callback.
const CallbackWriter = struct {
    write: WriteFn,
    ctx: ?*anyopaque,
    failed: bool = false,
    interface: Io.Writer,

    fn init(write: WriteFn, ctx: ?*anyopaque, buffer: []u8) CallbackWriter {
        return .{ .write = write, .ctx = ctx, .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *CallbackWriter = @alignCast(@fieldParentPtr("interface", w));
        try c.pass(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            try c.pass(bytes);
            n += bytes.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try c.pass(last);
        return n + last.len * splat;
    }

    fn pass(c: *CallbackWriter, bytes: []const u8) Io.Writer.Error!void {
        if (bytes.len == 0) return;
        if (c.write(c.ctx, bytes.ptr, bytes.len) != 0) {
            c.failed = true;
            return error.WriteFailed;
        }
    }
};

/// A stream read from the caller's callback.
const CallbackReader = struct {
    read: ReadFn,
    ctx: ?*anyopaque,
    failed: bool = false,
    interface: Io.Reader,

    fn init(read: ReadFn, ctx: ?*anyopaque, buffer: []u8) CallbackReader {
        return .{ .read = read, .ctx = ctx, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const c: *CallbackReader = @alignCast(@fieldParentPtr("interface", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = c.read(c.ctx, dest.ptr, dest.len);
        if (n < 0 or n > dest.len) {
            c.failed = true;
            return error.ReadFailed;
        }
        if (n == 0) return error.EndOfStream;
        w.advance(@intCast(n));
        return @intCast(n);
    }
};

const Handle = struct {
    callback: CallbackSource,
    reader: *estargz.Reader,
    scratch: estargz.Reader.Scratch = .{},
    arena: std.heap.ArenaAllocator,
    toc_digest: [Toc.digest_len:0]u8,
    /// NUL-terminated copies of each file's link name and digest.
    link_names: []?[:0]const u8,
    digests: []?[:0]const u8,
};

const Entry = extern struct {
    name: [*:0]const u8,
    type: c_int,
    mode: u32,
    size: u64,
    link_name: ?[*:0]const u8,
    digest: ?[*:0]const u8,
    chunks: u32,
};

export fn sg_reader_open(read_at: ?ReadAtFn, ctx: ?*anyopaque, size: u64, out: ?*?*Handle) c_int {
    const callback = read_at orelse return invalid("read_at is NULL");
    const result = out orelse return invalid("out is NULL");
    const h = gpa.create(Handle) catch |err| return fail(err);
    h.* = .{
        .callback = .{ .read_at = callback, .ctx = ctx },
        .reader = undefined,
        .arena = .init(gpa),
        .toc_digest = undefined,
        .link_names = &.{},
        .digests = &.{},
    };
    h.reader = estargz.Reader.open(gpa, h.callback.source(size), .{}) catch |err| {
        h.arena.deinit();
        gpa.destroy(h);
        return fail(err);
    };
    prepare(h) catch |err| {
        sg_reader_free(h);
        return fail(err);
    };
    result.* = h;
    return @backingInt(Status.ok);
}

fn prepare(h: *Handle) !void {
    const arena = h.arena.allocator();
    h.toc_digest = Toc.formatDigest(h.reader.toc_digest) ++ [_:0]u8{};
    h.link_names = try arena.alloc(?[:0]const u8, h.reader.files.len);
    h.digests = try arena.alloc(?[:0]const u8, h.reader.files.len);
    for (h.reader.files, h.link_names, h.digests) |f, *link, *digest| {
        link.* = if (f.entry.linkName) |l| try arena.dupeSentinel(u8, l, 0) else null;
        digest.* = if (f.entry.digest) |d| try arena.dupeSentinel(u8, d, 0) else null;
    }
}

export fn sg_reader_free(h: ?*Handle) void {
    const handle = h orelse return;
    handle.scratch.deinit(gpa);
    handle.reader.deinit();
    handle.arena.deinit();
    gpa.destroy(handle);
}

export fn sg_reader_toc_digest(h: *const Handle) [*:0]const u8 {
    return &h.toc_digest;
}

export fn sg_reader_count(h: *const Handle) usize {
    return h.reader.files.len;
}

export fn sg_reader_entry(h: *const Handle, index: usize, out: ?*Entry) c_int {
    const result = out orelse return invalid("out is NULL");
    if (index >= h.reader.files.len) return invalid("index out of range");
    const f = &h.reader.files[index];
    result.* = .{
        .name = f.name.ptr,
        .type = switch (f.entry.type) {
            .dir => 1,
            .reg => 2,
            .symlink => 3,
            .hardlink => 4,
            .char => 5,
            .block => 6,
            .fifo => 7,
            .chunk => unreachable,
        },
        .mode = @truncate(f.entry.mode orelse 0),
        .size = f.size,
        .link_name = if (h.link_names[index]) |l| l.ptr else null,
        .digest = if (h.digests[index]) |d| d.ptr else null,
        .chunks = @intCast(f.chunks.len),
    };
    return @backingInt(Status.ok);
}

export fn sg_reader_lookup(h: *const Handle, name: ?[*:0]const u8, index: ?*usize) c_int {
    const n = name orelse return invalid("name is NULL");
    const result = index orelse return invalid("index is NULL");
    const f = h.reader.lookup(std.mem.span(n)) orelse {
        const msg = "not found";
        @memcpy(last_error[0..msg.len], msg);
        last_error[msg.len] = 0;
        return @backingInt(Status.not_found);
    };
    result.* = (@intFromPtr(f) - @intFromPtr(h.reader.files.ptr)) / @sizeOf(estargz.Reader.File);
    return @backingInt(Status.ok);
}

export fn sg_reader_read_file(h: *Handle, index: usize, write: ?WriteFn, ctx: ?*anyopaque) c_int {
    const callback = write orelse return invalid("write is NULL");
    if (index >= h.reader.files.len) return invalid("index out of range");
    const f = &h.reader.files[index];
    if (f.entry.type != .reg) return invalid("not a regular file");
    var buf: [64 * 1024]u8 = undefined;
    var w: CallbackWriter = .init(callback, ctx, &buf);
    h.reader.readFile(gpa, &h.scratch, f, &w.interface) catch |err|
        return fail(if (w.failed) error.CallbackFailed else err);
    w.interface.flush() catch return fail(error.CallbackFailed);
    return @backingInt(Status.ok);
}

export fn sg_reader_read_range(h: *Handle, index: usize, offset: u64, length: u64, write: ?WriteFn, ctx: ?*anyopaque, first: ?*u64) c_int {
    const callback = write orelse return invalid("write is NULL");
    const start = first orelse return invalid("first is NULL");
    if (index >= h.reader.files.len) return invalid("index out of range");
    const f = &h.reader.files[index];
    if (f.entry.type != .reg) return invalid("not a regular file");
    const chunks = f.chunksIn(offset, offset +| length);
    start.* = if (chunks.len > 0) chunks[0].file_offset else offset;
    // Each chunk whole, and only once its digest checks.
    var chunk: Io.Writer.Allocating = .init(gpa);
    defer chunk.deinit();
    for (chunks) |c| {
        chunk.clearRetainingCapacity();
        h.reader.readChunk(gpa, &h.scratch, c, &chunk.writer) catch |err| return fail(err);
        const bytes = chunk.written();
        if (callback(ctx, bytes.ptr, bytes.len) != 0) return fail(error.CallbackFailed);
    }
    return @backingInt(Status.ok);
}

export fn sg_reader_verify(h: *const Handle, toc_digest: ?[*:0]const u8) c_int {
    if (toc_digest) |text| {
        const want = Toc.parseDigest(std.mem.span(text)) catch return invalid("toc_digest isn't sha256:<hex>");
        if (!std.mem.eql(u8, &want, &h.reader.toc_digest)) return fail(error.EstargzTocMismatch);
    }
    _ = h.reader.verify(gpa) catch |err| return fail(err);
    return @backingInt(Status.ok);
}

const ConvertOptions = extern struct {
    chunk_size: u64,
    level: c_int,
};

const ConvertResult = extern struct {
    toc_digest: [Toc.digest_len + 1]u8,
    blob_digest: [Toc.digest_len + 1]u8,
    blob_size: u64,
    uncompressed_size: u64,
    entries: u64,
};

export fn sg_convert(read: ?ReadFn, read_ctx: ?*anyopaque, write: ?WriteFn, write_ctx: ?*anyopaque, options: ?*const ConvertOptions, out: ?*ConvertResult) c_int {
    const read_cb = read orelse return invalid("read is NULL");
    const write_cb = write orelse return invalid("write is NULL");
    var opts: estargz.Options = .{};
    if (options) |o| {
        if (o.chunk_size != 0) opts.chunk_size = o.chunk_size;
        opts.level = switch (o.level) {
            0, 6 => .level_6,
            1 => .level_1,
            2 => .level_2,
            3 => .level_3,
            4 => .level_4,
            5 => .level_5,
            7 => .level_7,
            8 => .level_8,
            9 => .level_9,
            else => return invalid("level isn't 0 to 9"),
        };
    }
    var in_buf: [64 * 1024]u8 = undefined;
    var in: CallbackReader = .init(read_cb, read_ctx, &in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var w: CallbackWriter = .init(write_cb, write_ctx, &out_buf);
    const result = estargz.convert(gpa, &in.interface, &w.interface, opts) catch |err|
        return fail(if (in.failed or w.failed) error.CallbackFailed else err);
    w.interface.flush() catch return fail(error.CallbackFailed);
    if (out) |o| o.* = .{
        .toc_digest = Toc.formatDigest(result.toc_digest) ++ [_]u8{0},
        .blob_digest = Toc.formatDigest(result.blob_digest) ++ [_]u8{0},
        .blob_size = result.blob_size,
        .uncompressed_size = result.uncompressed_size,
        .entries = result.entries,
    };
    return @backingInt(Status.ok);
}
