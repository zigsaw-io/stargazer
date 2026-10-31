//! eStargz: a gzip-compressed tar whose files can be found and read one by
//! one, through a table of contents (TOC) at its end. Its gzip members start
//! at the top of the blob, at the top of each non-empty file's payload, every
//! chunk size bytes inside a large one, at the TOC's tar header, and at the
//! footer, which says where the TOC is. The spec is docs/estargz.md in
//! containerd's stargz-snapshotter; where it leaves a choice, this does what
//! its Go package, estargz, does at v0.19.1.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Source = @import("Source.zig");
const Toc = @import("Toc.zig");
const tar = @import("tar.zig");
const gzip = @import("gzip.zig");

pub const toc_name = "stargz.index.json";
pub const prefetch_landmark = ".prefetch.landmark";
pub const no_prefetch_landmark = ".no.prefetch.landmark";
/// What a landmark file holds.
pub const landmark_contents = 0x0f;
/// The annotations a layer's descriptor carries in the manifest.
pub const toc_digest_annotation = "containerd.io/snapshot/stargz/toc.digest";
pub const uncompressed_size_annotation = "io.containers.estargz.uncompressed-size";
pub const footer_size = 51;
pub const legacy_footer_size = 47;
pub const default_chunk_size = 4 << 20;

/// Names a layer's own files can't have: the TOC's and the landmarks'.
pub fn isReserved(clean_name: []const u8) bool {
    for ([_][]const u8{ toc_name, prefetch_landmark, no_prefetch_landmark }) |reserved| {
        if (std.mem.eql(u8, clean_name, reserved)) return true;
    }
    return false;
}

/// A tar entry's name as Go's reader cleans it: relative, without "." or ".."
/// parts, a ".." at the top dropped.
/// Allocates `name.len + 1` bytes, once.
pub fn cleanName(arena: Allocator, name: []const u8) ![:0]const u8 {
    var out: std.ArrayList(u8) = try .initCapacity(arena, name.len + 1);
    var it = std.mem.tokenizeScalar(u8, name, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            out.items.len = std.mem.lastIndexOfScalar(u8, out.items, '/') orelse 0;
            continue;
        }
        if (out.items.len > 0) out.appendAssumeCapacity('/');
        out.appendSliceAssumeCapacity(part);
    }
    out.appendAssumeCapacity(0);
    return out.items[0 .. out.items.len - 1 :0];
}

/// Whether a clean name can be created below a directory on any system: not
/// empty, and without a backslash, a colon or a control character.
pub fn isSafeName(clean_name: []const u8) bool {
    if (clean_name.len == 0) return false;
    for (clean_name) |c| if (c < 0x20 or c == '\\' or c == ':') return false;
    return true;
}

/// The footer: an empty gzip member whose Extra field has subfield "SG" with
/// the TOC's offset, as `%016xSTARGZ`.
pub fn footer(toc_offset: u64) [footer_size]u8 {
    var f: [footer_size]u8 = undefined;
    // No time, no compression flags, "unknown" OS, as Go writes it.
    f[0..10].* = .{ 0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0xff };
    f[10..16].* = .{ 26, 0, 'S', 'G', 22, 0 };
    _ = std.fmt.bufPrint(f[16..38], "{x:0>16}STARGZ", .{toc_offset}) catch unreachable;
    f[38..43].* = empty_stored_block;
    @memset(f[43..], 0);
    return f;
}

/// A final stored block of no bytes.
const empty_stored_block = [_]u8{ 1, 0, 0, 0xff, 0xff };

pub const Footer = struct {
    toc_offset: u64,
    size: usize,
    /// Google CRFS's stargz, whose Extra field has no subfield header.
    legacy: bool,
};

/// Finds the footer in `tail`, a blob's last bytes (51 of them, or as many as
/// it has): eStargz's, or legacy stargz's.
pub fn parseFooter(tail: []const u8) !Footer {
    if (tail.len >= footer_size) {
        if (parseFooterBytes(tail[tail.len - footer_size ..], true)) |offset|
            return .{ .toc_offset = offset, .size = footer_size, .legacy = false };
    }
    if (tail.len >= legacy_footer_size) {
        if (parseFooterBytes(tail[tail.len - legacy_footer_size ..], false)) |offset|
            return .{ .toc_offset = offset, .size = legacy_footer_size, .legacy = true };
    }
    return error.EstargzNoFooter;
}

/// Any time, compression flags and OS in the gzip header; the rest exactly.
fn parseFooterBytes(f: []const u8, subfield: bool) ?u64 {
    if (!std.mem.eql(u8, f[0..4], &.{ 0x1f, 0x8b, 0x08, 0x04 })) return null;
    const xlen = std.mem.readInt(u16, f[10..12], .little);
    var extra = f[12..];
    if (subfield) {
        if (xlen != 26 or !std.mem.eql(u8, extra[0..4], &.{ 'S', 'G', 22, 0 })) return null;
        extra = extra[4..];
    } else if (xlen != 22) return null;
    if (!std.mem.eql(u8, extra[16..22], "STARGZ")) return null;
    const offset = std.fmt.parseInt(u64, extra[0..16], 16) catch return null;
    const crc_and_size: [8]u8 = @splat(0);
    if (!std.mem.eql(u8, extra[22..], &(empty_stored_block ++ crc_and_size))) return null;
    return offset;
}

pub const Options = struct {
    /// Payloads are split into gzip members of this many bytes, as Go's
    /// writer splits them.
    chunk_size: u64 = default_chunk_size,
    /// zlib's default, which zigsaw's gzip layers use too; Go's writer uses 9.
    level: flate.Compress.Options = .level_6,
};

pub const Result = struct {
    toc_digest: [Sha256.digest_length]u8,
    blob_digest: [Sha256.digest_length]u8,
    blob_size: u64,
    /// Of the tar inside the blob: what `uncompressed_size_annotation` gives.
    uncompressed_size: u64,
    /// The TOC's, chunks included.
    entries: usize,
};

/// Writes the entries of the tar stream `in` to `out` as eStargz: the
/// no-prefetch landmark first, then every entry with its header bytes as
/// they were, then the TOC and the footer. `in`'s end-of-archive blocks are
/// left out; the TOC's entry ends the archive. The same input and options
/// always make the same bytes. `in` must have a buffer of at least 512 bytes;
/// `out` isn't flushed.
pub fn convert(gpa: Allocator, in: *Io.Reader, out: *Io.Writer, options: Options) !Result {
    std.debug.assert(options.chunk_size > 0);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var counter_buf: [64 * 1024]u8 = undefined;
    var counter: Counter = .init(out, &counter_buf);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const compress = try gpa.create(flate.Compress);
    defer gpa.destroy(compress);
    var m: Members = .{ .counter = &counter, .compress = compress, .window = window, .level = options.level };

    var entries: std.ArrayList(Toc.Entry) = .empty;
    var users: Names = .{};
    var groups: Names = .{};
    const zeros: [2 * tar.block_size]u8 = @splat(0);

    {
        try m.write(&try tarHeader(no_prefetch_landmark, 1));
        const offset = try m.boundary();
        const contents = [_]u8{landmark_contents};
        try m.write(&contents);
        try m.write(zeros[0..tar.padding(1)]);
        const digest = try hashText(arena, &contents);
        try entries.append(arena, .{
            .name = no_prefetch_landmark,
            .type = .reg,
            .size = 1,
            .offset = offset,
            .digest = digest,
            .chunkDigest = digest,
        });
    }

    var it: tar.Iterator = .init(gpa, in);
    defer it.deinit();
    while (try it.next()) |e| {
        if (isReserved(try cleanName(arena, e.name))) return error.EstargzReservedName;
        try m.write(e.raw);
        var ent: Toc.Entry = .{
            .name = try arena.dupe(u8, e.name),
            .type = switch (e.kind) {
                .regular => .reg,
                .hardlink => .hardlink,
                .symlink => .symlink,
                .char => .char,
                .block => .block,
                .directory => .dir,
                .fifo => .fifo,
            },
            .size = if (e.kind == .regular) nonZero(e.size) else null,
            .modtime = try formatModtime(arena, e.mtime),
            .linkName = if (e.kind == .hardlink or e.kind == .symlink) try arena.dupe(u8, e.link_name) else null,
            .mode = nonZero(e.mode),
            .uid = nonZero(e.uid),
            .gid = nonZero(e.gid),
            .userName = try users.ifChanged(arena, e.uid, e.uname),
            .groupName = try groups.ifChanged(arena, e.gid, e.gname),
            .devMajor = if (e.kind == .char or e.kind == .block) nonZero(e.dev_major) else null,
            .devMinor = if (e.kind == .char or e.kind == .block) nonZero(e.dev_minor) else null,
            .xattrs = try xattrMap(arena, e.xattrs),
        };
        if (e.kind != .regular) {
            try entries.append(arena, ent);
        } else if (e.size == 0) {
            // Go gives an empty file the digest of no bytes.
            ent.digest = try hashText(arena, "");
            try entries.append(arena, ent);
        } else {
            const first = entries.items.len;
            var file_hash: Sha256 = .init(.{});
            var written: u64 = 0;
            while (written < e.size) {
                const remain = e.size - written;
                const size = @min(remain, options.chunk_size);
                // A file's last chunk goes to its end, without a size.
                if (remain > options.chunk_size) ent.chunkSize = size;
                ent.offset = try m.boundary();
                ent.chunkOffset = nonZero(written);
                var chunk_hash: Sha256 = .init(.{});
                var left = size;
                while (left > 0) {
                    const bytes = try it.takePayload(left);
                    if (bytes.len == 0) return error.TarTruncated;
                    chunk_hash.update(bytes);
                    file_hash.update(bytes);
                    try m.write(bytes);
                    left -= bytes.len;
                }
                ent.chunkDigest = try digestText(arena, chunk_hash.finalResult());
                try entries.append(arena, ent);
                written += size;
                ent = .{ .name = ent.name, .type = .chunk };
            }
            entries.items[first].digest = try digestText(arena, file_hash.finalResult());
        }
        try m.write(try it.takePadding());
    }

    const toc_offset = try m.boundary();
    var json: Io.Writer.Allocating = .init(arena);
    try Toc.write(.{ .version = 1, .entries = entries.items }, &json.writer);
    var toc_digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(json.written(), &toc_digest, .{});
    try m.write(&try tarHeader(toc_name, json.written().len));
    try m.write(json.written());
    try m.write(zeros[0..tar.padding(json.written().len)]);
    try m.write(&zeros);
    try m.end();
    try counter.writer.writeAll(&footer(toc_offset));
    try counter.writer.flush();

    return .{
        .toc_digest = toc_digest,
        .blob_digest = counter.hash.finalResult(),
        .blob_size = counter.count,
        .uncompressed_size = m.uncompressed,
        .entries = entries.items.len,
    };
}

fn nonZero(v: anytype) ?@TypeOf(v) {
    return if (v == 0) null else v;
}

/// "sha256:<hex>" of `bytes`.
fn hashText(arena: Allocator, bytes: []const u8) ![]const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digestText(arena, digest);
}

fn digestText(arena: Allocator, digest: [Sha256.digest_length]u8) ![]const u8 {
    return arena.dupe(u8, &Toc.formatDigest(digest));
}

/// A ustar header as Zig's tar writer makes it, but with mode 0, as Go's
/// writer gives the landmark and the TOC.
fn tarHeader(name: []const u8, size: u64) ![tar.block_size]u8 {
    var h: std.tar.Writer.Header = .init(.regular);
    h.mode = "0000000".*;
    try h.setPath("", name);
    try h.setSize(size);
    try h.updateChecksum();
    return std.mem.toBytes(h);
}

/// As Go formats it: UTC to the second, none for 0.
fn formatModtime(arena: Allocator, mtime: i64) !?[]const u8 {
    if (mtime == 0) return null;
    if (mtime < 0) return error.EstargzTimeBefore1970;
    const seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(mtime) };
    const year_day = seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = seconds.getDaySeconds();
    return try std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,                 month_day.month.numeric(),        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
    });
}

/// Sorted by key, with values in base64, as Go marshals a map of bytes.
fn xattrMap(arena: Allocator, xattrs: []const tar.Entry.Xattr) !?std.json.ArrayHashMap([]const u8) {
    if (xattrs.len == 0) return null;
    const sorted = try arena.dupe(tar.Entry.Xattr, xattrs);
    std.mem.sort(tar.Entry.Xattr, sorted, {}, struct {
        fn lessThan(_: void, a: tar.Entry.Xattr, b: tar.Entry.Xattr) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lessThan);
    var map: std.json.ArrayHashMap([]const u8) = .{};
    const encoder = std.base64.standard.Encoder;
    for (sorted) |x| {
        const value = encoder.encode(try arena.alloc(u8, encoder.calcSize(x.value.len)), x.value);
        try map.map.put(arena, try arena.dupe(u8, x.key), value);
    }
    return map;
}

/// A uid's or gid's name, given only when it differs from the last one given
/// for that id, as Go gives it.
const Names = struct {
    last: std.AutoHashMapUnmanaged(u64, []const u8) = .empty,

    fn ifChanged(n: *Names, arena: Allocator, id: u64, name: []const u8) !?[]const u8 {
        if (name.len == 0) return null;
        const gop = try n.last.getOrPut(arena, id);
        if (gop.found_existing and std.mem.eql(u8, gop.value_ptr.*, name)) return null;
        gop.value_ptr.* = try arena.dupe(u8, name);
        return gop.value_ptr.*;
    }
};

/// Passes bytes on to `out`, counting and hashing them.
const Counter = struct {
    out: *Io.Writer,
    /// Bytes passed on.
    count: u64 = 0,
    hash: Sha256 = .init(.{}),
    writer: Io.Writer,

    fn init(out: *Io.Writer, buffer: []u8) Counter {
        return .{ .out = out, .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    /// Where the next byte written goes in the output.
    fn position(c: *const Counter) u64 {
        return c.count + c.writer.end;
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const c: *Counter = @alignCast(@fieldParentPtr("writer", w));
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

    fn pass(c: *Counter, bytes: []const u8) Io.Writer.Error!void {
        c.hash.update(bytes);
        try c.out.writeAll(bytes);
        c.count += bytes.len;
    }
};

/// The output's gzip members, one open at a time.
const Members = struct {
    counter: *Counter,
    compress: *flate.Compress,
    window: []u8,
    level: flate.Compress.Options,
    open: bool = false,
    /// Bytes compressed: the size of the tar inside.
    uncompressed: u64 = 0,

    fn write(m: *Members, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        if (!m.open) {
            m.compress.* = try .init(&m.counter.writer, m.window, .gzip, m.level);
            m.open = true;
        }
        try m.compress.writer.writeAll(bytes);
        m.uncompressed += bytes.len;
    }

    fn end(m: *Members) !void {
        if (!m.open) return;
        try m.compress.finish();
        m.open = false;
    }

    /// Ends the open member; returns where the next one starts.
    fn boundary(m: *Members) !u64 {
        try m.end();
        return m.counter.position();
    }
};

/// An eStargz blob opened through its TOC.
pub const Reader = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    source: Source,
    footer: Footer,
    toc: Toc,
    toc_json: []const u8,
    toc_digest: [Sha256.digest_length]u8,
    /// The TOC's entries but chunks, in its order.
    files: []File,
    by_name: std.StringHashMapUnmanaged(usize) = .empty,

    pub const File = struct {
        entry: *const Toc.Entry,
        /// Cleaned: relative, without "." or ".." parts; "" for the root.
        name: [:0]const u8,
        /// A regular file's; 0 for any other.
        size: u64,
        digest: ?[Sha256.digest_length]u8,
        chunks: []const Chunk,
    };

    pub const Chunk = struct {
        /// Where its gzip member starts in the blob, and where it ends: where
        /// the next starts, or the TOC.
        offset: u64,
        end: u64,
        /// Where it starts in the member's uncompressed bytes.
        inner_offset: u64,
        /// Where it starts in the file.
        file_offset: u64,
        size: u64,
        digest: ?[Sha256.digest_length]u8,
    };

    pub const OpenOptions = struct {
        /// The most bytes the TOC may have, compressed or not.
        max_toc_len: usize = 256 << 20,
    };

    /// Reads the footer and the TOC, and checks that the TOC holds together:
    /// each file's chunks cover it, members are in order, names are unique.
    /// Doesn't check the TOC's digest against anything: see `toc_digest`.
    pub fn open(gpa: Allocator, source: Source, options: OpenOptions) !*Reader {
        const r = try gpa.create(Reader);
        errdefer gpa.destroy(r);
        r.* = .{
            .gpa = gpa,
            .arena = .init(gpa),
            .source = source,
            .footer = undefined,
            .toc = undefined,
            .toc_json = undefined,
            .toc_digest = undefined,
            .files = undefined,
        };
        errdefer r.arena.deinit();
        const arena = r.arena.allocator();

        var tail: [footer_size]u8 = undefined;
        const tail_len: usize = @intCast(@min(source.size, footer_size));
        try source.readAll(source.size - tail_len, tail[0..tail_len]);
        r.footer = try parseFooter(tail[0..tail_len]);
        const toc_end = source.size - r.footer.size;
        if (r.footer.toc_offset >= toc_end) return error.EstargzBadFooter;
        if (toc_end - r.footer.toc_offset > options.max_toc_len) return error.EstargzTocTooLong;

        const compressed = try arena.alloc(u8, @intCast(toc_end - r.footer.toc_offset));
        try source.readAll(r.footer.toc_offset, compressed);
        r.toc_json = try readTocMember(arena, compressed, options.max_toc_len);
        Sha256.hash(r.toc_json, &r.toc_digest, .{});
        r.toc = try Toc.parse(arena, r.toc_json);
        try r.index();
        return r;
    }

    pub fn deinit(r: *Reader) void {
        const gpa = r.gpa;
        r.arena.deinit();
        gpa.destroy(r);
    }

    fn readTocMember(arena: Allocator, compressed: []const u8, max_len: usize) ![]const u8 {
        var in: Io.Reader = .fixed(compressed);
        const window = try arena.alloc(u8, flate.max_window_len);
        var d: flate.Decompress = .init(&in, .gzip, window);
        var it: tar.Iterator = .init(arena, &d.reader);
        const e = (it.next() catch return error.EstargzBadToc) orelse return error.EstargzBadToc;
        if (e.kind != .regular or !std.mem.eql(u8, try cleanName(arena, e.name), toc_name)) return error.EstargzBadToc;
        if (e.size > max_len) return error.EstargzTocTooLong;
        // Grown as the bytes come, not as big as the header claims.
        var json: std.ArrayList(u8) = .empty;
        while (json.items.len < e.size) {
            const bytes = it.takePayload(e.size - json.items.len) catch return error.EstargzBadToc;
            if (bytes.len == 0) return error.EstargzBadToc;
            try json.appendSlice(arena, bytes);
        }
        return json.items;
    }

    fn index(r: *Reader) !void {
        const arena = r.arena.allocator();
        var files: std.ArrayList(File) = .empty;
        var chunks: std.ArrayList(Chunk) = .empty;
        // Each file's first chunk and how many it has.
        var ranges: std.ArrayList([2]usize) = .empty;
        var open_file: ?usize = null;
        var next_offset: u64 = 0;
        for (r.toc.entries) |*e| {
            if (e.type == .chunk) {
                const i = open_file orelse return error.EstargzBadToc;
                try addChunk(arena, &chunks, e, files.items[i].size, &next_offset, r.footer.toc_offset);
                ranges.items[i][1] += 1;
                continue;
            }
            if (open_file) |i| if (next_offset != files.items[i].size) return error.EstargzBadToc;
            open_file = null;
            const size = if (e.type == .reg) e.size orelse 0 else 0;
            try files.append(arena, .{
                .entry = e,
                .name = try cleanName(arena, e.name),
                .size = size,
                .digest = if (e.digest) |d| try Toc.parseDigest(d) else null,
                .chunks = &.{},
            });
            try ranges.append(arena, .{ chunks.items.len, 0 });
            if (size > 0) {
                const i = files.items.len - 1;
                open_file = i;
                next_offset = 0;
                try addChunk(arena, &chunks, e, size, &next_offset, r.footer.toc_offset);
                ranges.items[i][1] = 1;
            }
        }
        if (open_file) |i| if (next_offset != files.items[i].size) return error.EstargzBadToc;

        // A member ends where the next starts. Chunks that share a member
        // (innerOffset) end where it does.
        var next_start = r.footer.toc_offset;
        var i = chunks.items.len;
        while (i > 0) {
            i -= 1;
            const c = &chunks.items[i];
            c.end = next_start;
            if (c.inner_offset == 0) next_start = c.offset;
        }
        var last: u64 = 0;
        for (chunks.items) |c| {
            if (c.offset < last or c.offset >= c.end) return error.EstargzBadToc;
            last = c.offset;
        }

        for (files.items, ranges.items, 0..) |*f, range, n| {
            f.chunks = chunks.items[range[0]..][0..range[1]];
            if (f.name.len == 0) continue;
            const gop = try r.by_name.getOrPut(arena, f.name);
            if (gop.found_existing) {
                // A directory may come twice; anything else would be ambiguous.
                if (f.entry.type != .dir or files.items[gop.value_ptr.*].entry.type != .dir) return error.EstargzDuplicateName;
            } else gop.value_ptr.* = n;
        }
        r.files = files.items;
    }

    fn addChunk(arena: Allocator, chunks: *std.ArrayList(Chunk), e: *const Toc.Entry, file_size: u64, next_offset: *u64, toc_offset: u64) !void {
        const offset = e.offset orelse return error.EstargzBadToc;
        const file_offset = e.chunkOffset orelse 0;
        if (file_offset != next_offset.* or file_offset >= file_size or offset >= toc_offset) return error.EstargzBadToc;
        const rest = file_size - file_offset;
        const size = if (e.chunkSize) |s| (if (s > 0) s else rest) else rest;
        if (size > rest) return error.EstargzBadToc;
        try chunks.append(arena, .{
            .offset = offset,
            .end = undefined,
            .inner_offset = e.innerOffset orelse 0,
            .file_offset = file_offset,
            .size = size,
            .digest = if (e.chunkDigest) |d| try Toc.parseDigest(d) else null,
        });
        next_offset.* = file_offset + size;
    }

    /// The file of a name, as a tar entry may give it ("./a/b", "a/b/").
    pub fn lookup(r: *const Reader, name: []const u8) ?*const File {
        var buf: [4096]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const clean = cleanName(fba.allocator(), name) catch return null;
        const i = r.by_name.get(clean) orelse return null;
        return &r.files[i];
    }

    /// Buffers for reading, which a thread can reuse from file to file.
    pub const Scratch = struct {
        compressed: std.ArrayList(u8) = .empty,
        window: ?[]u8 = null,

        pub fn deinit(s: *Scratch, gpa: Allocator) void {
            s.compressed.deinit(gpa);
            if (s.window) |w| gpa.free(w);
        }
    };

    /// Writes a regular file's contents to `out`, checking each chunk's
    /// digest and the file's.
    pub fn readFile(r: *const Reader, gpa: Allocator, scratch: *Scratch, file: *const File, out: *Io.Writer) !void {
        var file_hash: Sha256 = .init(.{});
        for (file.chunks) |c| try r.readChunk(gpa, scratch, c, out, &file_hash);
        if (file.digest) |want| {
            if (!std.mem.eql(u8, &file_hash.finalResult(), &want)) return error.EstargzDigestMismatch;
        }
    }

    fn readChunk(r: *const Reader, gpa: Allocator, scratch: *Scratch, c: Chunk, out: *Io.Writer, file_hash: *Sha256) !void {
        try scratch.compressed.resize(gpa, @intCast(c.end - c.offset));
        try r.source.readAll(c.offset, scratch.compressed.items);
        const window = scratch.window orelse w: {
            scratch.window = try gpa.alloc(u8, flate.max_window_len);
            break :w scratch.window.?;
        };
        var in: Io.Reader = .fixed(scratch.compressed.items);
        var d: flate.Decompress = .init(&in, .gzip, window);
        d.reader.discardAll64(c.inner_offset) catch |err| return memberError(&d, err);
        var chunk_hash: Sha256 = .init(.{});
        var left = c.size;
        while (left > 0) {
            const bytes = d.reader.peekGreedy(1) catch |err| return memberError(&d, err);
            const n: usize = @intCast(@min(@as(u64, bytes.len), left));
            chunk_hash.update(bytes[0..n]);
            file_hash.update(bytes[0..n]);
            try out.writeAll(bytes[0..n]);
            d.reader.toss(n);
            left -= n;
        }
        if (c.digest) |want| {
            if (!std.mem.eql(u8, &chunk_hash.finalResult(), &want)) return error.EstargzDigestMismatch;
        }
    }

    fn memberError(d: *const flate.Decompress, err: Io.Reader.Error) anyerror {
        return switch (err) {
            error.EndOfStream => error.EstargzTruncatedChunk,
            error.ReadFailed => d.err orelse error.ReadFailed,
        };
    }

    pub const ExtractOptions = struct {
        /// Threads that write files. Defender's scanning on Windows makes
        /// more than 4 gain little (zigsaw measured it).
        jobs: usize = 4,
    };

    /// Writes the blob's directories and regular files below `dest_path`,
    /// which is created, checking every chunk. Fails on any other kind of
    /// entry, and on a file that already exists; leaves out the landmarks.
    /// `gpa` must be thread-safe.
    pub fn extract(r: *const Reader, io: Io, gpa: Allocator, dest_path: []const u8, options: ExtractOptions) !void {
        try Io.Dir.cwd().createDirPath(io, dest_path);
        var dest = try Io.Dir.cwd().openDir(io, dest_path, .{});
        defer dest.close(io);

        var work: std.ArrayList(*const File) = .empty;
        defer work.deinit(gpa);
        for (r.files) |*f| {
            if (f.name.len == 0 and f.entry.type == .dir) continue;
            if (!isSafeName(f.name)) return error.EstargzUnsafeName;
            if (isReserved(f.name)) continue;
            switch (f.entry.type) {
                .dir => try dest.createDirPath(io, f.name),
                .reg => {
                    if (std.fs.path.dirnamePosix(f.name)) |parent| try dest.createDirPath(io, parent);
                    try work.append(gpa, f);
                },
                else => return error.EstargzUnsupportedEntry,
            }
        }
        if (work.items.len == 0) return;

        const workers = try gpa.alloc(ExtractWorker, @max(1, @min(work.items.len, options.jobs)));
        defer gpa.free(workers);
        var next: std.atomic.Value(usize) = .init(0);
        for (workers) |*w| w.* = .{ .io = io, .gpa = gpa, .reader = r, .dest = dest, .files = work.items, .next = &next };
        defer for (workers) |*w| w.scratch.deinit(gpa);

        var group: Io.Group = .init;
        for (workers) |*w| group.concurrent(io, ExtractWorker.run, .{w}) catch w.run();
        group.await(io) catch |err| return err;
        for (workers) |w| if (w.err) |err| return err;
    }

    const ExtractWorker = struct {
        io: Io,
        gpa: Allocator,
        reader: *const Reader,
        dest: Io.Dir,
        files: []const *const File,
        /// Index of the next file to take, shared by all workers.
        next: *std.atomic.Value(usize),
        scratch: Scratch = .{},
        err: ?anyerror = null,

        fn run(w: *ExtractWorker) void {
            w.extractFiles() catch |err| {
                w.err = err;
                // Make the other workers stop early.
                _ = w.next.swap(w.files.len, .monotonic);
            };
        }

        fn extractFiles(w: *ExtractWorker) !void {
            var buf: [64 * 1024]u8 = undefined;
            while (true) {
                const i = w.next.fetchAdd(1, .monotonic);
                if (i >= w.files.len) return;
                const f = w.files[i];
                var out = try w.dest.createFile(w.io, f.name, .{ .exclusive = true });
                defer out.close(w.io);
                var writer = out.writer(w.io, &buf);
                try w.reader.readFile(w.gpa, &w.scratch, f, &writer.interface);
                try writer.interface.flush();
            }
        }
    };

    pub const Report = struct {
        /// Tar entries, the TOC's own and the landmark's included.
        entries: usize,
        chunks: usize,
        members: usize,
        uncompressed_size: u64,
    };

    /// Reads the whole blob and checks it against the TOC: the tar entries
    /// are the TOC's, in its order, with its names, kinds, sizes and modes;
    /// every chunk's gzip member starts where the TOC says, at the chunk's
    /// first byte; the TOC's entry is the last, and starts a member; the
    /// digests of every file and chunk; a landmark (but in legacy stargz).
    pub fn verify(r: *const Reader, gpa: Allocator) !Report {
        var in_buf: [64 * 1024]u8 = undefined;
        var in: Source.Reader = .init(r.source, 0, r.source.size, &in_buf);
        const window = try gpa.alloc(u8, flate.max_window_len);
        defer gpa.free(window);
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        defer gpa.free(out_buf);
        var members: std.ArrayList(gzip.MemberReader.Member) = .empty;
        defer members.deinit(gpa);
        var stream: gzip.MemberReader = .init(gpa, &in, window, out_buf, &members);
        var it: tar.Iterator = .init(gpa, &stream.interface);
        defer it.deinit();
        // Member starts the TOC implies, checked against the real ones at the end.
        var expected: std.ArrayList(gzip.MemberReader.Member) = .empty;
        defer expected.deinit(gpa);
        var name_buf: [4096]u8 = undefined;

        var report: Report = .{ .entries = 0, .chunks = 0, .members = 0, .uncompressed_size = 0 };
        var next_file: usize = 0;
        var landmark = false;
        while (true) {
            const e = (it.next() catch |err| return streamError(&stream, err)) orelse return error.EstargzNoToc;
            report.entries += 1;
            var fba: std.heap.FixedBufferAllocator = .init(&name_buf);
            const name = try cleanName(fba.allocator(), e.name);
            if (std.mem.eql(u8, name, toc_name)) {
                try expected.append(gpa, .{ .compressed = r.footer.toc_offset, .uncompressed = e.offset });
                if (e.size != r.toc_json.len) return error.EstargzTocMismatch;
                var hash: Sha256 = .init(.{});
                try hashPayload(&it, &stream, e.size, &.{&hash});
                if (!std.mem.eql(u8, &hash.finalResult(), &r.toc_digest)) return error.EstargzTocMismatch;
                if ((it.next() catch |err| return streamError(&stream, err)) != null) return error.EstargzEntryAfterToc;
                break;
            }
            if (next_file >= r.files.len) return error.EstargzTocMismatch;
            const f = &r.files[next_file];
            next_file += 1;
            if (!std.mem.eql(u8, name, f.name) or !kindMatches(e.kind, f.entry.type) or
                e.size != f.size or e.mode != (f.entry.mode orelse 0)) return error.EstargzTocMismatch;
            if (e.kind == .hardlink or e.kind == .symlink) {
                if (!std.mem.eql(u8, e.link_name, f.entry.linkName orelse "")) return error.EstargzTocMismatch;
            }
            if (isReserved(name)) landmark = true;
            const payload_start = it.pos;
            var file_hash: Sha256 = .init(.{});
            for (f.chunks) |c| {
                const at = payload_start + c.file_offset; // file_offset < size
                if (c.inner_offset > at) return error.EstargzMemberMisplaced;
                try expected.append(gpa, .{ .compressed = c.offset, .uncompressed = at - c.inner_offset });
                var chunk_hash: Sha256 = .init(.{});
                try hashPayload(&it, &stream, c.size, &.{ &chunk_hash, &file_hash });
                if (c.digest) |want| {
                    if (!std.mem.eql(u8, &chunk_hash.finalResult(), &want)) return error.EstargzDigestMismatch;
                }
                report.chunks += 1;
            }
            if (f.digest) |want| {
                if (!std.mem.eql(u8, &file_hash.finalResult(), &want)) return error.EstargzDigestMismatch;
            }
        }
        if (next_file != r.files.len) return error.EstargzTocMismatch;
        if (!landmark and !r.footer.legacy) return error.EstargzNoLandmark;

        // Every member start the TOC implies is a real one.
        var starts: std.AutoHashMapUnmanaged(u64, u64) = .empty;
        defer starts.deinit(gpa);
        for (members.items) |m| try starts.put(gpa, m.compressed, m.uncompressed);
        for (expected.items) |want| {
            const got = starts.get(want.compressed) orelse return error.EstargzMemberMisplaced;
            if (got != want.uncompressed) return error.EstargzMemberMisplaced;
        }
        // The footer is a member of its own, the last.
        if (members.items.len == 0 or members.items[members.items.len - 1].compressed != r.source.size - r.footer.size)
            return error.EstargzBadFooter;
        report.members = members.items.len;
        report.uncompressed_size = stream.produced;
        return report;
    }

    fn kindMatches(kind: tar.Kind, t: Toc.Type) bool {
        return switch (kind) {
            .regular => t == .reg,
            .hardlink => t == .hardlink,
            .symlink => t == .symlink,
            .char => t == .char,
            .block => t == .block,
            .directory => t == .dir,
            .fifo => t == .fifo,
        };
    }

    fn hashPayload(it: *tar.Iterator, stream: *gzip.MemberReader, n: u64, hashes: []const *Sha256) !void {
        var left = n;
        while (left > 0) {
            const bytes = it.takePayload(left) catch |err| return streamError(stream, err);
            if (bytes.len == 0) return error.TarTruncated;
            for (hashes) |hash| hash.update(bytes);
            left -= bytes.len;
        }
    }

    fn streamError(stream: *const gzip.MemberReader, err: anyerror) anyerror {
        return if (err == error.ReadFailed) stream.err orelse err else err;
    }
};

/// A tar of a few files, one of them `big_len` bytes, converted with chunks
/// of `chunk_size` bytes.
fn testBlob(gpa: Allocator, chunk_size: u64) !struct { []u8, Result } {
    var archive: Io.Writer.Allocating = .init(gpa);
    defer archive.deinit();
    var w: std.tar.Writer = .{ .underlying_writer = &archive.writer };
    try w.writeDir("bin", .{ .mode = 0o755 });
    try w.writeFileBytes("bin/tool.exe", "MZ tool", .{});
    try w.writeFileBytes("empty", "", .{});
    try w.writeDir("share", .{ .mode = 0o755 });
    var big: [big_len]u8 = undefined;
    testBytes(&big);
    try w.writeFileBytes("share/big.dat", &big, .{});
    try w.writeFileBytes("long/" ++ tar.repeat("d", 120) ++ "/file.txt", "deep", .{ .mode = 0o600 });
    try w.finishPedantically();

    var in: Io.Reader = .fixed(archive.written());
    var blob: Io.Writer.Allocating = .init(gpa);
    errdefer blob.deinit();
    const result = try convert(gpa, &in, &blob.writer, .{ .chunk_size = chunk_size });
    return .{ try blob.toOwnedSlice(), result };
}

const big_len = 10_000;

/// Bytes that compress somewhat, from a fixed LCG.
fn testBytes(buf: []u8) void {
    var x: u32 = 7;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = "stargazer\n"[(x >> 24) % 10];
    }
}

/// The blob with its TOC swapped for `json`.
fn withToc(gpa: Allocator, blob: []const u8, toc_offset: u64, json: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try out.writer.writeAll(blob[0..@intCast(toc_offset)]);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var c: flate.Compress = try .init(&out.writer, window, .gzip, .level_6);
    try c.writer.writeAll(&try tarHeader(toc_name, json.len));
    try c.writer.writeAll(json);
    try c.writer.splatByteAll(0, tar.padding(json.len) + 2 * tar.block_size);
    try c.finish();
    try out.writer.writeAll(&footer(toc_offset));
    return out.toOwnedSlice();
}

test "the footer, and legacy stargz's" {
    const f = footer(0x1234abcd);
    try std.testing.expectEqualSlices(u8, &.{ 0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 0xff, 26, 0, 'S', 'G', 22, 0 }, f[0..16]);
    try std.testing.expectEqualStrings("000000001234abcdSTARGZ", f[16..38]);
    try std.testing.expectEqual(Footer{ .toc_offset = 0x1234abcd, .size = 51, .legacy = false }, try parseFooter(&f));

    var legacy: [legacy_footer_size]u8 = undefined;
    legacy[0..12].* = .{ 0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 0xff, 22, 0 };
    legacy[12..34].* = "00000000000000ffSTARGZ".*;
    legacy[34..39].* = empty_stored_block;
    @memset(legacy[39..], 0);
    var tail: [footer_size]u8 = @splat('x');
    tail[4..].* = legacy;
    try std.testing.expectEqual(Footer{ .toc_offset = 0xff, .size = 47, .legacy = true }, try parseFooter(&tail));

    try std.testing.expectError(error.EstargzNoFooter, parseFooter(f[1..]));
    var bad = f;
    bad[30] = 'z';
    try std.testing.expectError(error.EstargzNoFooter, parseFooter(&bad));
}

test "converted, read back, and checked whole" {
    const gpa = std.testing.allocator;
    const blob, const result = try testBlob(gpa, 4096);
    defer gpa.free(blob);
    try std.testing.expectEqual(blob.len, result.blob_size);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(blob, &digest, .{});
    try std.testing.expectEqualSlices(u8, &digest, &result.blob_digest);

    const blob_const: []const u8 = blob;
    const r = try Reader.open(gpa, .fromBytes(&blob_const), .{});
    defer r.deinit();
    try std.testing.expectEqualSlices(u8, &result.toc_digest, &r.toc_digest);
    try std.testing.expectEqual(result.entries, r.toc.entries.len);
    const names = [_][]const u8{ no_prefetch_landmark, "bin", "bin/tool.exe", "empty", "share", "share/big.dat", "long/" ++ tar.repeat("d", 120) ++ "/file.txt" };
    try std.testing.expectEqual(names.len, r.files.len);
    for (names, r.files) |want, f| try std.testing.expectEqualStrings(want, f.name);

    const big = r.lookup("./share/big.dat").?;
    try std.testing.expectEqual(3, big.chunks.len);
    try std.testing.expectEqual(4096, big.chunks[1].file_offset);
    try std.testing.expectEqual(big_len - 8192, big.chunks[2].size);
    var scratch: Reader.Scratch = .{};
    defer scratch.deinit(gpa);
    var got: Io.Writer.Allocating = .init(gpa);
    defer got.deinit();
    try r.readFile(gpa, &scratch, big, &got.writer);
    var want: [big_len]u8 = undefined;
    testBytes(&want);
    try std.testing.expectEqualSlices(u8, &want, got.written());
    try std.testing.expectEqual(0o600, r.lookup("long/" ++ tar.repeat("d", 120) ++ "/file.txt").?.entry.mode.?);
    try std.testing.expectEqual(null, r.lookup("missing"));

    const report = try r.verify(gpa);
    try std.testing.expectEqual(names.len + 1, report.entries);
    try std.testing.expectEqual(6, report.chunks);
    try std.testing.expectEqual(result.uncompressed_size, report.uncompressed_size);
}

test "the same bytes every time" {
    // eStargz layers' digests are what this makes. If this fails after a
    // change of Zig or of this code, every eStargz layer gets a new digest,
    // and no published image reproduces.
    const gpa = std.testing.allocator;
    const a, _ = try testBlob(gpa, 4096);
    defer gpa.free(a);
    const b, _ = try testBlob(gpa, 4096);
    defer gpa.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(a, &digest, .{});
    try std.testing.expectEqualStrings("e426cd9358e56e13ec71d0f33e7fa8fb5444f1f51ecfbd52ce23bc62adef7741", &std.fmt.bytesToHex(digest, .lower));
}

test "a TOC that doesn't hold together, or lies" {
    const gpa = std.testing.allocator;
    const blob, _ = try testBlob(gpa, 4096);
    defer gpa.free(blob);
    const blob_const: []const u8 = blob;
    const r = try Reader.open(gpa, .fromBytes(&blob_const), .{});
    defer r.deinit();

    // A chunk left out: the file's chunks don't cover it.
    var dropped: Io.Writer.Allocating = .init(gpa);
    defer dropped.deinit();
    var entries: std.ArrayList(Toc.Entry) = .empty;
    defer entries.deinit(gpa);
    for (r.toc.entries) |e| {
        if (e.type == .chunk and e.chunkOffset.? == 4096) continue;
        try entries.append(gpa, e);
    }
    try Toc.write(.{ .version = 1, .entries = entries.items }, &dropped.writer);
    const short: []const u8 = try withToc(gpa, blob, r.footer.toc_offset, dropped.written());
    defer gpa.free(short);
    try std.testing.expectError(error.EstargzBadToc, Reader.open(gpa, .fromBytes(&short), .{}));

    // A chunk's digest that isn't its bytes'.
    var lie: Io.Writer.Allocating = .init(gpa);
    defer lie.deinit();
    const changed = try gpa.dupe(Toc.Entry, r.toc.entries);
    defer gpa.free(changed);
    for (changed) |*e| {
        if (e.type == .chunk) e.chunkDigest = "sha256:" ++ tar.repeat("0", 64);
    }
    try Toc.write(.{ .version = 1, .entries = changed }, &lie.writer);
    const lying: []const u8 = try withToc(gpa, blob, r.footer.toc_offset, lie.written());
    defer gpa.free(lying);
    const lr = try Reader.open(gpa, .fromBytes(&lying), .{});
    defer lr.deinit();
    var scratch: Reader.Scratch = .{};
    defer scratch.deinit(gpa);
    var sink: Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    try std.testing.expectError(error.EstargzDigestMismatch, lr.readFile(gpa, &scratch, lr.lookup("share/big.dat").?, &sink.writer));
    try std.testing.expectError(error.EstargzDigestMismatch, lr.verify(gpa));

    // An offset that isn't where the chunk's member starts.
    var moved: Io.Writer.Allocating = .init(gpa);
    defer moved.deinit();
    for (changed, r.toc.entries) |*e, orig| e.* = orig;
    for (changed) |*e| {
        if (std.mem.eql(u8, e.name, "bin/tool.exe")) e.offset.? += 1;
    }
    try Toc.write(.{ .version = 1, .entries = changed }, &moved.writer);
    const misplaced: []const u8 = try withToc(gpa, blob, r.footer.toc_offset, moved.written());
    defer gpa.free(misplaced);
    const mr = try Reader.open(gpa, .fromBytes(&misplaced), .{});
    defer mr.deinit();
    if (mr.verify(gpa)) |_| return error.TestUnexpectedSuccess else |_| {}
}

test "names a layer can't have" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ toc_name, "./" ++ no_prefetch_landmark, "x/../" ++ prefetch_landmark }) |name| {
        var archive: Io.Writer.Allocating = .init(gpa);
        defer archive.deinit();
        var w: std.tar.Writer = .{ .underlying_writer = &archive.writer };
        try w.writeFileBytes(name, "x", .{});
        var in: Io.Reader = .fixed(archive.written());
        var blob: Io.Writer.Allocating = .init(gpa);
        defer blob.deinit();
        try std.testing.expectError(error.EstargzReservedName, convert(gpa, &in, &blob.writer, .{}));
    }
}

test "extracted into a directory" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const blob, _ = try testBlob(gpa, 4096);
    defer gpa.free(blob);
    const blob_const: []const u8 = blob;
    const r = try Reader.open(gpa, .fromBytes(&blob_const), .{});
    defer r.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(base);
    const dest = try std.fs.path.join(gpa, &.{ base, "out" });
    defer gpa.free(dest);
    try r.extract(io, gpa, dest, .{ .jobs = 3 });

    var out = try Io.Dir.cwd().openDir(io, dest, .{});
    defer out.close(io);
    const tool = try out.readFileAlloc(io, "bin/tool.exe", gpa, .unlimited);
    defer gpa.free(tool);
    try std.testing.expectEqualStrings("MZ tool", tool);
    const big = try out.readFileAlloc(io, "share/big.dat", gpa, .unlimited);
    defer gpa.free(big);
    try std.testing.expectEqual(big_len, big.len);
    // The landmark isn't one of the layer's files.
    try std.testing.expectError(error.FileNotFound, out.statFile(io, no_prefetch_landmark, .{}));
    // Nor is anything written twice.
    try std.testing.expectError(error.PathAlreadyExists, r.extract(io, gpa, dest, .{}));
}

test "fuzz: any bytes open, read and verify, or fail, but never crash" {
    try std.testing.fuzz({}, fuzzAnyBytes, .{});
}

test "fuzz: a blob with bytes changed opens, reads and verifies, or fails" {
    try std.testing.fuzz({}, fuzzDamaged, .{});
}

fn fuzzAnyBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [16 * 1024]u8 = undefined;
    const n = smith.slice(&buf);
    // Even with a footer, so that the TOC is looked for.
    var blob: [buf.len + footer_size]u8 = undefined;
    @memcpy(blob[0..n], buf[0..n]);
    blob[n..][0..footer_size].* = footer(smith.valueRangeAtMost(u64, 0, n));
    exercise(std.testing.allocator, blob[0 .. n + footer_size]);
}

fn fuzzDamaged(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    const blob, _ = try testBlob(gpa, 4096);
    defer gpa.free(blob);
    while (!smith.eosWeightedSimple(3, 1)) blob[smith.index(blob.len)] = smith.value(u8);
    exercise(gpa, blob);
}

test "damaged blobs and TOCs, from a fixed seed, fail but never crash" {
    // `--fuzz` isn't implemented for Windows yet; this runs everywhere.
    const gpa = std.testing.allocator;
    const blob, _ = try testBlob(gpa, 4096);
    defer gpa.free(blob);
    const blob_const: []const u8 = blob;
    const r = try Reader.open(gpa, .fromBytes(&blob_const), .{});
    defer r.deinit();
    var prng: std.Random.DefaultPrng = .init(0x57a2);
    const random = prng.random();

    const damaged = try gpa.dupe(u8, blob);
    defer gpa.free(damaged);
    for (0..300) |_| {
        @memcpy(damaged, blob);
        for (0..random.intRangeAtMost(usize, 1, 4)) |_| damaged[random.uintLessThan(usize, damaged.len)] = random.int(u8);
        exercise(gpa, damaged);
    }

    // TOCs whose numbers and names lie, in a blob otherwise right.
    const entries = try gpa.dupe(Toc.Entry, r.toc.entries);
    defer gpa.free(entries);
    const lies = [_]u64{ 0, 1, 511, 512, 4095, 4096, blob.len, std.math.maxInt(u64), std.math.maxInt(u64) - 1 };
    for (0..300) |_| {
        @memcpy(entries, r.toc.entries);
        const e = &entries[random.uintLessThan(usize, entries.len)];
        const lie = lies[random.uintLessThan(usize, lies.len)];
        switch (random.uintLessThan(u8, 8)) {
            0 => e.size = lie,
            1 => e.offset = lie,
            2 => e.chunkOffset = lie,
            3 => e.chunkSize = lie,
            4 => e.innerOffset = lie,
            5 => e.type = random.enumValue(Toc.Type),
            6 => e.name = "../../escape",
            else => e.chunkDigest = null,
        }
        var json: Io.Writer.Allocating = .init(gpa);
        defer json.deinit();
        try Toc.write(.{ .version = 1, .entries = entries }, &json.writer);
        const lying = try withToc(gpa, blob, r.footer.toc_offset, json.written());
        defer gpa.free(lying);
        exercise(gpa, lying);
    }
}

/// Everything a reader does, its errors ignored.
fn exercise(gpa: Allocator, blob: []const u8) void {
    const r = Reader.open(gpa, .fromBytes(&blob), .{ .max_toc_len = 1 << 20 }) catch return;
    defer r.deinit();
    var scratch: Reader.Scratch = .{};
    defer scratch.deinit(gpa);
    var buf: [4096]u8 = undefined;
    var sink: Io.Writer.Discarding = .init(&buf);
    for (r.files) |*f| {
        if (f.entry.type == .reg) r.readFile(gpa, &scratch, f, &sink.writer) catch {};
        _ = r.lookup(f.name);
    }
    _ = r.verify(gpa) catch {};
}

test "names that are safe to create" {
    try std.testing.expect(isSafeName("a/b.txt"));
    try std.testing.expect(!isSafeName(""));
    try std.testing.expect(!isSafeName("a\\..\\b"));
    try std.testing.expect(!isSafeName("C:x"));
    var buf: [64]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    try std.testing.expectEqualStrings("b", try cleanName(fba.allocator(), "/../a/../b/./"));
}
