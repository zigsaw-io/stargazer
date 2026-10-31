//! Tar streams read with every header byte kept, so that they can be written
//! out again unchanged, as eStargz keeps a layer's headers. ustar and GNU
//! headers, GNU long names and pax extended headers are understood; global
//! pax headers and GNU sparse files are refused, as Go's eStargz writer
//! refuses them.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const block_size = 512;

pub const Kind = enum { regular, hardlink, symlink, char, block, directory, fifo };

pub const Entry = struct {
    /// Where the entry's first header starts in the stream.
    offset: u64,
    /// The entry's headers, extended ones and their padding included, as read.
    raw: []const u8,
    /// The whole path: pax's `path`, a GNU long name, or ustar's prefix and name.
    name: []const u8,
    link_name: []const u8,
    kind: Kind,
    /// Bytes of payload; 0 for every kind but `regular`, as in Go's reader.
    size: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    uname: []const u8,
    gname: []const u8,
    /// Seconds since 1970.
    mtime: i64,
    dev_major: u64,
    dev_minor: u64,
    /// pax's `SCHILY.xattr.` records, in the order read.
    xattrs: []const Xattr,

    pub const Xattr = struct { key: []const u8, value: []const u8 };
};

/// The zero bytes after `size` bytes of payload.
pub fn padding(size: u64) usize {
    return @intCast((block_size - size % block_size) % block_size);
}

/// The entries of a tar stream, one at a time.
pub const Iterator = struct {
    in: *Io.Reader,
    gpa: Allocator,
    /// Bytes taken from `in`: the position in the stream.
    pos: u64 = 0,
    raw: std.ArrayList(u8) = .empty,
    strings: std.heap.ArenaAllocator,
    xattrs: std.ArrayList(Entry.Xattr) = .empty,
    payload_left: u64 = 0,
    padding_left: usize = 0,
    ended: bool = false,
    /// The most header bytes an entry may have, extended headers included.
    max_header_len: usize = 1 << 20,

    /// `in` must have a buffer of at least `block_size` bytes.
    pub fn init(gpa: Allocator, in: *Io.Reader) Iterator {
        std.debug.assert(in.buffer.len >= block_size);
        return .{ .in = in, .gpa = gpa, .strings = .init(gpa) };
    }

    pub fn deinit(it: *Iterator) void {
        it.raw.deinit(it.gpa);
        it.xattrs.deinit(it.gpa);
        it.strings.deinit();
    }

    /// The next entry, or null at the end of the archive. Skips what's left of
    /// the last entry's payload. The entry's slices live until the next call.
    pub fn next(it: *Iterator) !?Entry {
        if (it.ended) return null;
        try it.skipRest();
        it.raw.clearRetainingCapacity();
        it.xattrs.clearRetainingCapacity();
        _ = it.strings.reset(.retain_capacity);
        const arena = it.strings.allocator();
        const offset = it.pos;

        var long_name: ?[]const u8 = null;
        var long_link: ?[]const u8 = null;
        var pax: Pax = .{};
        while (true) {
            const extended = it.raw.items.len > 0;
            // Zig's writer may leave out the end-of-archive blocks.
            if (!extended) if (it.in.peekByte()) |_| {} else |err| switch (err) {
                error.EndOfStream => {
                    it.ended = true;
                    return null;
                },
                error.ReadFailed => return err,
            };
            const block: [block_size]u8 = (try it.takeRaw(block_size))[0..block_size].*;
            if (std.mem.allEqual(u8, &block, 0)) {
                if (extended) return error.TarTruncated;
                it.raw.clearRetainingCapacity();
                try it.expectZerosToEnd();
                it.ended = true;
                return null;
            }
            const h: Header = try .parse(arena, &block);
            switch (h.typeflag) {
                'L' => long_name = trimNul(try it.extension(arena, h.size)),
                'K' => long_link = trimNul(try it.extension(arena, h.size)),
                'x' => try pax.parse(it.gpa, try it.extension(arena, h.size), &it.xattrs),
                'g' => return error.TarGlobalHeader,
                else => {
                    const kind = kindOf(h.typeflag) orelse return error.TarUnsupportedType;
                    const size = if (kind == .regular) pax.size orelse h.size else 0;
                    // So that the payload and its padding can be added up.
                    if (size > std.math.maxInt(u64) - block_size) return error.TarBadNumber;
                    it.payload_left = size;
                    it.padding_left = padding(size);
                    return .{
                        .offset = offset,
                        .raw = it.raw.items,
                        .name = pax.path orelse long_name orelse h.name,
                        .link_name = pax.link_path orelse long_link orelse h.link_name,
                        .kind = kind,
                        .size = size,
                        .mode = h.mode,
                        .uid = pax.uid orelse h.uid,
                        .gid = pax.gid orelse h.gid,
                        .uname = pax.uname orelse h.uname,
                        .gname = pax.gname orelse h.gname,
                        .mtime = pax.mtime orelse h.mtime,
                        .dev_major = h.dev_major,
                        .dev_minor = h.dev_minor,
                        .xattrs = it.xattrs.items,
                    };
                },
            }
        }
    }

    /// Up to `max` bytes of the current entry's payload, from `in`'s buffer;
    /// they live until `in` or the iterator is used again.
    pub fn takePayload(it: *Iterator, max: u64) ![]const u8 {
        const want = @min(max, it.payload_left);
        if (want == 0) return &.{};
        const bytes = it.in.peekGreedy(1) catch |err| return truncated(err);
        const n: usize = @intCast(@min(@as(u64, bytes.len), want));
        it.in.toss(n);
        it.pos += n;
        it.payload_left -= n;
        return bytes[0..n];
    }

    /// The padding after the payload, which must have been taken whole.
    pub fn takePadding(it: *Iterator) ![]const u8 {
        std.debug.assert(it.payload_left == 0);
        const n = it.padding_left;
        const bytes = it.in.take(n) catch |err| return truncated(err);
        it.pos += n;
        it.padding_left = 0;
        return bytes;
    }

    fn skipRest(it: *Iterator) !void {
        const n = it.payload_left + it.padding_left;
        it.in.discardAll64(n) catch |err| return truncated(err);
        it.pos += n;
        it.payload_left = 0;
        it.padding_left = 0;
    }

    fn takeRaw(it: *Iterator, n: usize) ![]u8 {
        if (it.raw.items.len + n > it.max_header_len) return error.TarHeaderTooLong;
        const dest = try it.raw.addManyAsSlice(it.gpa, n);
        it.in.readSliceAll(dest) catch |err| return truncated(err);
        it.pos += n;
        return dest;
    }

    /// An extended header's content and its padding, kept in `raw`; returns
    /// a copy of the content.
    fn extension(it: *Iterator, arena: Allocator, size: u64) ![]const u8 {
        if (size > it.max_header_len) return error.TarHeaderTooLong;
        const content = try arena.dupe(u8, try it.takeRaw(@intCast(size)));
        _ = try it.takeRaw(padding(size));
        return content;
    }

    /// The end of the archive may be followed by more zero blocks, but by
    /// nothing else: an entry after it would be lost.
    fn expectZerosToEnd(it: *Iterator) !void {
        while (it.in.peekGreedy(1)) |bytes| {
            for (bytes) |b| if (b != 0) return error.TarDataAfterEnd;
            it.in.toss(bytes.len);
            it.pos += bytes.len;
        } else |err| switch (err) {
            error.EndOfStream => {},
            error.ReadFailed => return err,
        }
    }
};

fn truncated(err: Io.Reader.Error) error{ TarTruncated, ReadFailed } {
    return switch (err) {
        error.EndOfStream => error.TarTruncated,
        error.ReadFailed => error.ReadFailed,
    };
}

fn kindOf(typeflag: u8) ?Kind {
    return switch (typeflag) {
        '0', 0, '7' => .regular,
        '1' => .hardlink,
        '2' => .symlink,
        '3' => .char,
        '4' => .block,
        '5' => .directory,
        '6' => .fifo,
        else => null,
    };
}

const Header = struct {
    typeflag: u8,
    name: []const u8,
    link_name: []const u8,
    size: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    mtime: i64,
    uname: []const u8,
    gname: []const u8,
    dev_major: u64,
    dev_minor: u64,

    fn parse(arena: Allocator, b: *const [block_size]u8) !Header {
        try checkChecksum(b);
        const ustar = std.mem.eql(u8, b[257..263], "ustar\x00");
        const gnu = std.mem.eql(u8, b[257..265], "ustar  \x00");
        const name = cstr(b[0..100]);
        const prefix = if (ustar) cstr(b[345..500]) else "";
        return .{
            .typeflag = b[156],
            .name = if (prefix.len > 0) try std.mem.concat(arena, u8, &.{ prefix, "/", name }) else try arena.dupe(u8, name),
            .link_name = try arena.dupe(u8, cstr(b[157..257])),
            .size = try number(b[124..136]),
            .mode = try number(b[100..108]),
            .uid = try number(b[108..116]),
            .gid = try number(b[116..124]),
            .mtime = std.math.cast(i64, try number(b[136..148])) orelse return error.TarBadNumber,
            .uname = if (ustar or gnu) try arena.dupe(u8, cstr(b[265..297])) else "",
            .gname = if (ustar or gnu) try arena.dupe(u8, cstr(b[297..329])) else "",
            .dev_major = if (ustar or gnu) try number(b[329..337]) else 0,
            .dev_minor = if (ustar or gnu) try number(b[337..345]) else 0,
        };
    }
};

/// Accepts the unsigned sum, which the standard asks for, and the signed one
/// some old writers made.
fn checkChecksum(b: *const [block_size]u8) !void {
    const want = try number(b[148..156]);
    var unsigned: u64 = 0;
    var signed: i64 = 0;
    for (b, 0..) |c, i| {
        const v: u8 = if (i >= 148 and i < 156) ' ' else c;
        unsigned += v;
        signed += @as(i8, @bitCast(v));
    }
    if (want != unsigned and std.math.cast(i64, want) != signed) return error.TarBadChecksum;
}

/// An octal field, or a GNU base-256 one (its first byte's high bit set).
fn number(field: []const u8) !u64 {
    if (field[0] & 0x80 != 0) {
        if (field[0] == 0xff) return error.TarBadNumber; // negative
        var v: u64 = field[0] & 0x7f;
        for (field[1..]) |c| {
            if (v >> 56 != 0) return error.TarBadNumber;
            v = (v << 8) | c;
        }
        return v;
    }
    const digits = std.mem.trim(u8, field, " \x00");
    if (digits.len == 0) return 0;
    return std.fmt.parseInt(u64, digits, 8) catch error.TarBadNumber;
}

fn cstr(field: []const u8) []const u8 {
    return field[0 .. std.mem.indexOfScalar(u8, field, 0) orelse field.len];
}

fn trimNul(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "\x00");
}

const Pax = struct {
    path: ?[]const u8 = null,
    link_path: ?[]const u8 = null,
    size: ?u64 = null,
    uid: ?u64 = null,
    gid: ?u64 = null,
    uname: ?[]const u8 = null,
    gname: ?[]const u8 = null,
    mtime: ?i64 = null,

    /// Records are "<length> <key>=<value>\n"; `content` must outlive `p`.
    fn parse(p: *Pax, gpa: Allocator, content: []const u8, xattrs: *std.ArrayList(Entry.Xattr)) !void {
        var rest = content;
        while (rest.len > 0) {
            const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.TarBadPax;
            const len = std.fmt.parseInt(usize, rest[0..space], 10) catch return error.TarBadPax;
            if (len <= space + 1 or len > rest.len or rest[len - 1] != '\n') return error.TarBadPax;
            const record = rest[space + 1 .. len - 1];
            rest = rest[len..];
            const eq = std.mem.indexOfScalar(u8, record, '=') orelse return error.TarBadPax;
            const key = record[0..eq];
            const value = record[eq + 1 ..];
            if (std.mem.eql(u8, key, "path")) {
                p.path = value;
            } else if (std.mem.eql(u8, key, "linkpath")) {
                p.link_path = value;
            } else if (std.mem.eql(u8, key, "size")) {
                p.size = std.fmt.parseInt(u64, value, 10) catch return error.TarBadPax;
            } else if (std.mem.eql(u8, key, "uid")) {
                p.uid = std.fmt.parseInt(u64, value, 10) catch return error.TarBadPax;
            } else if (std.mem.eql(u8, key, "gid")) {
                p.gid = std.fmt.parseInt(u64, value, 10) catch return error.TarBadPax;
            } else if (std.mem.eql(u8, key, "uname")) {
                p.uname = value;
            } else if (std.mem.eql(u8, key, "gname")) {
                p.gname = value;
            } else if (std.mem.eql(u8, key, "mtime")) {
                // Seconds, with an optional fraction.
                const whole = value[0 .. std.mem.indexOfScalar(u8, value, '.') orelse value.len];
                p.mtime = std.fmt.parseInt(i64, whole, 10) catch return error.TarBadPax;
            } else if (std.mem.startsWith(u8, key, "SCHILY.xattr.")) {
                try xattrs.append(gpa, .{ .key = key["SCHILY.xattr.".len..], .value = value });
            } else if (std.mem.startsWith(u8, key, "GNU.sparse.")) {
                return error.TarUnsupportedType;
            }
        }
    }
};

/// `s` `n` times, at compile time.
pub fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    return comptime blk: {
        const buf: [n][s.len]u8 = @splat(s[0..s.len].*);
        break :blk @ptrCast(&buf);
    };
}

/// A ustar header of any type, which Zig's writer can't make, for tests.
pub fn testHeader(name: []const u8, typeflag: u8, size: u64) [block_size]u8 {
    var h: std.tar.Writer.Header = .init(.regular);
    h.setPath("", name) catch unreachable;
    h.setSize(size) catch unreachable;
    var b: [block_size]u8 = std.mem.toBytes(h);
    b[156] = typeflag;
    @memset(b[148..156], ' ');
    var sum: u64 = 0;
    for (b) |c| sum += c;
    _ = std.fmt.bufPrint(b[148..154], "{o:0>6}", .{sum}) catch unreachable;
    b[154] = 0;
    return b;
}

/// Tar bytes as Zig's writer makes them, with a path in ustar's prefix and
/// name and one in a GNU long name, for tests.
pub fn testArchive(gpa: Allocator) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var w: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try w.writeDir("bin", .{ .mode = 0o755 });
    try w.writeFileBytes("bin/tool.exe", "MZ tool", .{});
    try w.writeFileBytes("empty", "", .{});
    try w.writeFileBytes("long/" ++ repeat("d", 120) ++ "/file.txt", "deep", .{});
    try w.writeFileBytes("gnu/" ++ repeat("e", 120), "longer", .{});
    try w.writeLink("link", "bin/tool.exe", .{});
    try w.finishPedantically();
    return out.toOwnedSlice();
}

test "entries, their payloads, and every header byte" {
    const gpa = std.testing.allocator;
    const archive = try testArchive(gpa);
    defer gpa.free(archive);

    var in: Io.Reader = .fixed(archive);
    var it: Iterator = .init(gpa, &in);
    defer it.deinit();
    var kept: Io.Writer.Allocating = .init(gpa);
    defer kept.deinit();

    const want = [_]struct { []const u8, Kind, u64 }{
        .{ "bin", .directory, 0 },
        .{ "bin/tool.exe", .regular, 7 },
        .{ "empty", .regular, 0 },
        .{ "long/" ++ repeat("d", 120) ++ "/file.txt", .regular, 4 },
        .{ "gnu/" ++ repeat("e", 120), .regular, 6 },
        .{ "link", .symlink, 0 },
    };
    for (want) |w| {
        const e = (try it.next()).?;
        try std.testing.expectEqualStrings(w[0], e.name);
        try std.testing.expectEqual(w[1], e.kind);
        try std.testing.expectEqual(w[2], e.size);
        try kept.writer.writeAll(e.raw);
        while (true) {
            const bytes = try it.takePayload(3);
            if (bytes.len == 0) break;
            try kept.writer.writeAll(bytes);
        }
        try kept.writer.writeAll(try it.takePadding());
    }
    try std.testing.expectEqual(null, try it.next());
    try std.testing.expectEqual(null, try it.next());
    // Everything but the end-of-archive blocks, byte for byte.
    try std.testing.expectEqualSlices(u8, archive[0 .. archive.len - 2 * block_size], kept.written());
    try std.testing.expectEqual(archive.len, it.pos);
}

test "a mode, a checksum, a pax header" {
    const gpa = std.testing.allocator;
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const records = "16 path=a/b/c.d\n" ++ "29 SCHILY.xattr.user.k=value\n" ++ "14 mtime=12.5\n";
    try out.writer.writeAll(&testHeader("PaxHeader", 'x', records.len));
    try out.writer.writeAll(records);
    try out.writer.splatByteAll(0, padding(records.len));
    var w: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try w.writeFileBytes("ignored", "x", .{ .mode = 0o640 });

    var in: Io.Reader = .fixed(out.written());
    var it: Iterator = .init(gpa, &in);
    defer it.deinit();
    const e = (try it.next()).?;
    try std.testing.expectEqualStrings("a/b/c.d", e.name);
    try std.testing.expectEqual(0o640, e.mode);
    try std.testing.expectEqual(12, e.mtime);
    try std.testing.expectEqual(1, e.xattrs.len);
    try std.testing.expectEqualStrings("user.k", e.xattrs[0].key);
    try std.testing.expectEqualStrings("value", e.xattrs[0].value);
    try std.testing.expectEqual(0, e.offset);
    try std.testing.expectEqual(3 * block_size, e.raw.len);
    // The stream ends without end-of-archive blocks, as Zig's writer allows.
    try std.testing.expectEqual(null, try it.next());

    // A changed byte breaks the checksum.
    const bad = try gpa.dupe(u8, out.written());
    defer gpa.free(bad);
    bad[3 * block_size + 10] ^= 1;
    var bad_in: Io.Reader = .fixed(bad[3 * block_size ..]);
    var bad_it: Iterator = .init(gpa, &bad_in);
    defer bad_it.deinit();
    try std.testing.expectError(error.TarBadChecksum, bad_it.next());
}
