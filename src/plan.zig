//! Updates between eStargz blobs: which gzip members of a new blob are
//! already in old ones, and which bytes must be fetched.
//!
//! A member of the new blob is reused when one of an old blob has the same
//! compressed length, the same payload (by chunk digest and size), and, for
//! a file's last chunk, the same padding and the same entries after it up to
//! the next payload, as the TOC gives them: their tar headers are in the
//! member too. The TOC can't prove those headers byte for byte, so a reused
//! member is a strong guess, and the caller must check the blob it builds
//! against its digest. It rests on the writer: the same bytes, compressed
//! alone at the same level, make the same member.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Source = @import("Source.zig");
const Toc = @import("Toc.zig");
const tar = @import("tar.zig");
const estargz = @import("estargz.zig");
const Reader = estargz.Reader;

pub const Member = struct {
    offset: u64,
    end: u64,
    kind: Kind,
    /// What another member must match to stand in for this one; null if
    /// none can (the TOC's, or one that packs several payloads).
    key: ?[Sha256.digest_length]u8,

    pub const Kind = enum {
        /// The headers before the first payload.
        lead,
        chunk,
        /// The TOC's member and the footer.
        toc,
    };

    pub fn len(m: Member) u64 {
        return m.end - m.offset;
    }
};

/// The blob's members, in order, from its start to its end.
pub fn members(arena: Allocator, r: *const Reader) ![]Member {
    // Each entry's user and group name: the TOC gives one only when it
    // changes for that id.
    const users = try arena.alloc([]const u8, r.files.len);
    const groups = try arena.alloc([]const u8, r.files.len);
    {
        var last_user: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
        var last_group: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
        for (r.files, users, groups) |f, *u, *g| {
            const uid = f.entry.uid orelse 0;
            const gid = f.entry.gid orelse 0;
            if (f.entry.userName) |name| try last_user.put(arena, uid, name);
            if (f.entry.groupName) |name| try last_group.put(arena, gid, name);
            u.* = last_user.get(uid) orelse "";
            g.* = last_group.get(gid) orelse "";
        }
    }
    const headers: Headers = .{ .files = r.files, .users = users, .groups = groups };

    var list: std.ArrayList(Member) = .empty;
    const first_payload = for (r.files, 0..) |f, i| {
        if (f.chunks.len > 0) break i;
    } else null;
    const lead_end = if (first_payload) |i| r.files[i].chunks[0].offset else r.footer.toc_offset;
    if (lead_end > 0) {
        var h: Sha256 = .init(.{});
        hashU64(&h, @backingInt(Member.Kind.lead));
        hashU64(&h, lead_end);
        headers.hash(&h, 0);
        try list.append(arena, .{ .offset = 0, .end = lead_end, .kind = .lead, .key = h.finalResult() });
    }

    for (r.files, 0..) |f, i| {
        var j: usize = 0;
        while (j < f.chunks.len) : (j += 1) {
            const c = f.chunks[j];
            if (c.inner_offset != 0) continue;
            // Chunks after it with an inner offset share its member.
            var shared = false;
            var k = j + 1;
            while (k < f.chunks.len and f.chunks[k].inner_offset != 0) : (k += 1) shared = true;
            const last = j + 1 == f.chunks.len;
            // A member can also be shared with the next file's first chunk.
            if (last) {
                if (nextChunk(r.files, i)) |next| shared = shared or next.inner_offset != 0;
            }
            var key: ?[Sha256.digest_length]u8 = null;
            if (!shared) if (c.digest) |digest| {
                var h: Sha256 = .init(.{});
                hashU64(&h, @backingInt(Member.Kind.chunk));
                hashU64(&h, c.end - c.offset);
                h.update(&digest);
                hashU64(&h, c.size);
                hashU64(&h, @intFromBool(last));
                if (last) {
                    hashU64(&h, tar.padding(f.size));
                    headers.hash(&h, i + 1);
                }
                key = h.finalResult();
            };
            try list.append(arena, .{ .offset = c.offset, .end = c.end, .kind = .chunk, .key = key });
        }
    }

    try list.append(arena, .{ .offset = r.footer.toc_offset, .end = r.source.size, .kind = .toc, .key = null });
    return list.items;
}

fn nextChunk(files: []const Reader.File, i: usize) ?Reader.Chunk {
    for (files[i + 1 ..]) |f| if (f.chunks.len > 0) return f.chunks[0];
    return null;
}

/// The tar headers of the entries from one up to the next with a payload, as
/// far as the TOC tells them.
const Headers = struct {
    files: []const Reader.File,
    users: []const []const u8,
    groups: []const []const u8,

    fn hash(hs: Headers, h: *Sha256, from: usize) void {
        for (hs.files[from..], hs.users[from..], hs.groups[from..]) |f, user, group| {
            const e = f.entry;
            hashU64(h, 1);
            hashBytes(h, e.name);
            hashU64(h, @backingInt(e.type));
            hashU64(h, e.size orelse 0);
            hashBytes(h, e.modtime orelse "");
            hashBytes(h, e.linkName orelse "");
            hashU64(h, e.mode orelse 0);
            hashU64(h, e.uid orelse 0);
            hashU64(h, e.gid orelse 0);
            hashBytes(h, user);
            hashBytes(h, group);
            hashU64(h, e.devMajor orelse 0);
            hashU64(h, e.devMinor orelse 0);
            if (e.xattrs) |x| {
                hashU64(h, x.map.count());
                var it = x.map.iterator();
                while (it.next()) |kv| {
                    hashBytes(h, kv.key_ptr.*);
                    hashBytes(h, kv.value_ptr.*);
                }
            } else hashU64(h, 0);
            if (f.chunks.len > 0) return;
        }
        // The end of the entries.
        hashU64(h, 0);
    }
};

fn hashU64(h: *Sha256, v: u64) void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    h.update(&b);
}

fn hashBytes(h: *Sha256, bytes: []const u8) void {
    hashU64(h, bytes.len);
    h.update(bytes);
}

/// A run of the new blob's bytes, in order: copied from an old blob, or
/// fetched from the new one.
pub const Piece = union(enum) {
    copy: struct { source: usize, offset: u64, len: u64 },
    fetch: struct { offset: u64, len: u64 },

    pub fn len(p: Piece) u64 {
        return switch (p) {
            inline else => |x| x.len,
        };
    }
};

pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    /// They cover the new blob from its start to its end.
    pieces: []Piece,

    pub fn deinit(p: *Plan) void {
        p.arena.deinit();
    }

    pub fn copied(p: Plan) u64 {
        var n: u64 = 0;
        for (p.pieces) |piece| if (piece == .copy) {
            n += piece.len();
        };
        return n;
    }

    pub fn fetched(p: Plan) u64 {
        var n: u64 = 0;
        for (p.pieces) |piece| if (piece == .fetch) {
            n += piece.len();
        };
        return n;
    }

    /// How many fetches start before `have_from`, the offset from which the
    /// caller already has the new blob's bytes (its tail, read to open it).
    pub fn requests(p: Plan, have_from: u64) usize {
        var n: usize = 0;
        for (p.pieces) |piece| if (piece == .fetch and piece.fetch.offset < have_from) {
            n += 1;
        };
        return n;
    }

    pub const CoalesceOptions = struct {
        /// At most this many fetches before `have_from`.
        max_requests: usize = 64,
        /// Copies between two fetches no longer than this are fetched
        /// instead: another request costs more.
        min_gap: u64 = 64 << 10,
        /// From here on the caller has the bytes already.
        have_from: u64 = std.math.maxInt(u64),
    };

    /// Fetches what lies between two fetches, where that saves a request:
    /// every gap up to `min_gap`, then the shortest gaps until there are at
    /// most `max_requests`.
    pub fn coalesce(p: *Plan, options: CoalesceOptions) !void {
        std.debug.assert(options.max_requests > 0);
        const arena = p.arena.allocator();
        // Gaps: runs of copies with a fetch on both sides, by the index of
        // their first piece and where they end.
        const Gap = struct { first: usize, end: usize, len: u64 };
        var gaps: std.ArrayList(Gap) = .empty;
        var i: usize = 0;
        while (i < p.pieces.len) : (i += 1) {
            if (p.pieces[i] != .fetch or i + 1 >= p.pieces.len or p.pieces[i + 1] != .copy) continue;
            var end = i + 1;
            var len: u64 = 0;
            while (end < p.pieces.len and p.pieces[end] == .copy) : (end += 1) len += p.pieces[end].len();
            if (end == p.pieces.len) break;
            // Fetching more of what the caller has saves no request.
            if (p.pieces[end].fetch.offset >= options.have_from) break;
            try gaps.append(arena, .{ .first = i + 1, .end = end, .len = len });
            i = end - 1;
        }

        const merge = try arena.alloc(bool, gaps.items.len);
        @memset(merge, false);
        var count = p.requests(options.have_from);
        for (gaps.items, merge) |g, *m| if (g.len <= options.min_gap) {
            m.* = true;
            count -= 1;
        };
        if (count > options.max_requests) {
            const order = try arena.alloc(usize, gaps.items.len);
            for (order, 0..) |*o, n| o.* = n;
            std.mem.sort(usize, order, @as([]const Gap, gaps.items), struct {
                fn less(g: []const Gap, a: usize, b: usize) bool {
                    return g[a].len < g[b].len or (g[a].len == g[b].len and a < b);
                }
            }.less);
            for (order) |n| {
                if (count <= options.max_requests) break;
                if (merge[n]) continue;
                merge[n] = true;
                count -= 1;
            }
        }

        var out: std.ArrayList(Piece) = .empty;
        var g: usize = 0;
        i = 0;
        while (i < p.pieces.len) {
            if (g < gaps.items.len and i == gaps.items[g].first) {
                const gap = gaps.items[g];
                g += 1;
                if (merge[g - 1]) {
                    out.items[out.items.len - 1].fetch.len += gap.len;
                    i = gap.end;
                    continue;
                }
            }
            try appendPiece(arena, &out, p.pieces[i]);
            i += 1;
        }
        p.pieces = out.items;
    }
};

/// Adds a piece, joining it to the last one if it goes on from it.
fn appendPiece(arena: Allocator, list: *std.ArrayList(Piece), piece: Piece) !void {
    if (list.items.len > 0) {
        const last = &list.items[list.items.len - 1];
        switch (piece) {
            .fetch => |f| if (last.* == .fetch and last.fetch.offset + last.fetch.len == f.offset) {
                last.fetch.len += f.len;
                return;
            },
            .copy => |c| if (last.* == .copy and last.copy.source == c.source and last.copy.offset + last.copy.len == c.offset) {
                last.copy.len += c.len;
                return;
            },
        }
    }
    try list.append(arena, piece);
}

/// Plans the new blob from the old ones: each member found in one of them
/// (the first that has it) is copied, the rest fetched.
pub fn make(gpa: Allocator, new: *const Reader, olds: []const *const Reader) !Plan {
    var p: Plan = .{ .arena = .init(gpa), .pieces = &.{} };
    errdefer p.arena.deinit();
    const arena = p.arena.allocator();

    const Where = struct { source: usize, offset: u64 };
    var have: std.AutoHashMapUnmanaged([Sha256.digest_length]u8, Where) = .empty;
    for (olds, 0..) |old, n| {
        for (try members(arena, old)) |m| {
            const key = m.key orelse continue;
            const gop = try have.getOrPut(arena, key);
            if (!gop.found_existing) gop.value_ptr.* = .{ .source = n, .offset = m.offset };
        }
    }

    var list: std.ArrayList(Piece) = .empty;
    for (try members(arena, new)) |m| {
        const where = if (m.key) |key| have.get(key) else null;
        try appendPiece(arena, &list, if (where) |w|
            .{ .copy = .{ .source = w.source, .offset = w.offset, .len = m.len() } }
        else
            .{ .fetch = .{ .offset = m.offset, .len = m.len() } });
    }
    p.pieces = list.items;
    return p;
}

/// Writes the new blob by the plan, from the old blobs and the new one. The
/// caller checks what it gets against the blob's digest.
pub fn apply(p: Plan, olds: []const Source, new: Source, out: *Io.Writer) !void {
    var buf: [64 * 1024]u8 = undefined;
    for (p.pieces) |piece| {
        const source, var offset, var left = switch (piece) {
            .copy => |c| .{ olds[c.source], c.offset, c.len },
            .fetch => |f| .{ new, f.offset, f.len },
        };
        while (left > 0) {
            const n: usize = @intCast(@min(left, buf.len));
            try source.readAll(offset, buf[0..n]);
            try out.writeAll(buf[0..n]);
            offset += n;
            left -= n;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests

const TestFile = struct { name: []const u8, data: []const u8, mode: u32 = 0o644 };

fn testConvert(gpa: Allocator, files: []const TestFile, chunk_size: u64) ![]u8 {
    var archive: Io.Writer.Allocating = .init(gpa);
    defer archive.deinit();
    var w: std.tar.Writer = .{ .underlying_writer = &archive.writer };
    try w.writeDir("dir", .{ .mode = 0o755 });
    for (files) |f| {
        if (f.data.len == 0 and std.mem.endsWith(u8, f.name, "/")) {
            try w.writeDir(f.name[0 .. f.name.len - 1], .{ .mode = f.mode });
        } else try w.writeFileBytes(f.name, f.data, .{ .mode = f.mode });
    }
    try w.finishPedantically();
    var in: Io.Reader = .fixed(archive.written());
    var blob: Io.Writer.Allocating = .init(gpa);
    errdefer blob.deinit();
    _ = try estargz.convert(gpa, &in, &blob.writer, .{ .chunk_size = chunk_size });
    return blob.toOwnedSlice();
}

/// Plans `new` from `olds`, builds it, and checks it's `new`. Returns the
/// plan, coalesced as given.
fn testRoundTrip(gpa: Allocator, olds: []const []const u8, new: []const u8, options: ?Plan.CoalesceOptions) !Plan {
    var readers: std.ArrayList(*Reader) = .empty;
    defer {
        for (readers.items) |r| r.deinit();
        readers.deinit(gpa);
    }
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(gpa);
    for (olds) |*old| {
        try sources.append(gpa, .fromBytes(old));
        try readers.append(gpa, try Reader.open(gpa, .fromBytes(old), .{}));
    }
    const new_const: []const u8 = new;
    const r = try Reader.open(gpa, .fromBytes(&new_const), .{});
    defer r.deinit();

    var p = try make(gpa, r, readers.items);
    errdefer p.deinit();
    if (options) |o| try p.coalesce(o);
    var covered: u64 = 0;
    for (p.pieces) |piece| {
        if (piece == .fetch) try std.testing.expectEqual(covered, piece.fetch.offset);
        covered += piece.len();
    }
    try std.testing.expectEqual(new.len, covered);
    try std.testing.expectEqual(new.len, p.copied() + p.fetched());

    var built: Io.Writer.Allocating = .init(gpa);
    defer built.deinit();
    try apply(p, sources.items, .fromBytes(&new_const), &built.writer);
    try std.testing.expectEqualSlices(u8, new, built.written());
    return p;
}

fn testData(buf: []u8, seed: u32) void {
    var x: u32 = seed;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = "stargazer\n"[(x >> 24) % 10];
    }
}

test "an unchanged file is copied, a changed one fetched" {
    const gpa = std.testing.allocator;
    var a: [9000]u8 = undefined;
    testData(&a, 1);
    var b: [5000]u8 = undefined;
    testData(&b, 2);
    var b2 = b;
    b2[100] = '!';
    const old = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/b.dat", .data = &b }, .{ .name = "dir/c.txt", .data = "c" } }, 4096);
    defer gpa.free(old);
    const new = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/b.dat", .data = &b2 }, .{ .name = "dir/c.txt", .data = "c" } }, 4096);
    defer gpa.free(new);

    var p = try testRoundTrip(gpa, &.{old}, new, null);
    defer p.deinit();
    // a.dat's three chunks (and the lead) copied; b.dat fetched; c.txt
    // copied; the TOC fetched.
    try std.testing.expect(p.copied() > a.len / 2);
    try std.testing.expect(p.fetched() < new.len / 2);
    try std.testing.expectEqual(.copy, std.meta.activeTag(p.pieces[0]));
    try std.testing.expectEqual(.fetch, std.meta.activeTag(p.pieces[p.pieces.len - 1]));

    // The same blob needs only its TOC.
    var same = try testRoundTrip(gpa, &.{new}, new, null);
    defer same.deinit();
    try std.testing.expectEqual(2, same.pieces.len);
    const r_const: []const u8 = new;
    const r = try Reader.open(gpa, .fromBytes(&r_const), .{});
    defer r.deinit();
    try std.testing.expectEqual(new.len - r.footer.toc_offset, same.fetched());
    try std.testing.expectEqual(0, same.requests(r.footer.toc_offset));
}

test "a file whose next entry changed is fetched: its member holds that header" {
    const gpa = std.testing.allocator;
    var a: [3000]u8 = undefined;
    testData(&a, 3);
    const old = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/b.txt", .data = "b" } }, 4096);
    defer gpa.free(old);
    const renamed = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/B.txt", .data = "b" } }, 4096);
    defer gpa.free(renamed);
    const moded = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/b.txt", .data = "b", .mode = 0o755 } }, 4096);
    defer gpa.free(moded);
    for ([_][]const u8{ renamed, moded }) |new| {
        var p = try testRoundTrip(gpa, &.{old}, new, null);
        defer p.deinit();
        // a.dat's member ends with b.txt's header, so it's fetched; b.txt's
        // own member, its payload alone, is copied.
        try std.testing.expectEqual(4, p.pieces.len);
        for ([_]std.meta.Tag(Piece){ .copy, .fetch, .copy, .fetch }, p.pieces) |want, got| try std.testing.expectEqual(want, std.meta.activeTag(got));
    }
}

test "members found in any of several old blobs" {
    const gpa = std.testing.allocator;
    var a: [3000]u8 = undefined;
    testData(&a, 4);
    var b: [3000]u8 = undefined;
    testData(&b, 5);
    const one = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/x", .data = "1" } }, 4096);
    defer gpa.free(one);
    const two = try testConvert(gpa, &.{ .{ .name = "dir/b.dat", .data = &b }, .{ .name = "dir/y", .data = "2" } }, 4096);
    defer gpa.free(two);
    const new = try testConvert(gpa, &.{ .{ .name = "dir/a.dat", .data = &a }, .{ .name = "dir/b.dat", .data = &b }, .{ .name = "dir/y", .data = "2" } }, 4096);
    defer gpa.free(new);
    var p = try testRoundTrip(gpa, &.{ one, two }, new, null);
    defer p.deinit();
    var sources: [2]bool = .{ false, false };
    for (p.pieces) |piece| if (piece == .copy) {
        sources[piece.copy.source] = true;
    };
    try std.testing.expect(sources[1]);
}

test "coalescing: short gaps, then the shortest until few enough requests" {
    const gpa = std.testing.allocator;
    var p: Plan = .{ .arena = .init(gpa), .pieces = &.{} };
    defer p.deinit();
    var pieces = [_]Piece{
        .{ .fetch = .{ .offset = 0, .len = 10 } },
        .{ .copy = .{ .source = 0, .offset = 0, .len = 5 } },
        .{ .fetch = .{ .offset = 15, .len = 10 } },
        .{ .copy = .{ .source = 0, .offset = 100, .len = 1000 } },
        .{ .copy = .{ .source = 1, .offset = 0, .len = 50 } },
        .{ .fetch = .{ .offset = 1075, .len = 10 } },
        .{ .copy = .{ .source = 0, .offset = 2000, .len = 300 } },
        .{ .fetch = .{ .offset = 1385, .len = 10 } },
        .{ .copy = .{ .source = 0, .offset = 3000, .len = 7 } },
        .{ .fetch = .{ .offset = 1402, .len = 20 } },
    };
    p.pieces = &pieces;
    try std.testing.expectEqual(5, p.requests(std.math.maxInt(u64)));
    try p.coalesce(.{ .min_gap = 5, .max_requests = 2, .have_from = 1402 });
    // The 5-byte gap merges by size; then the 300 (shorter than 1050); the
    // 7-byte gap before what the caller has stays.
    try std.testing.expectEqual(2, p.requests(1402));
    try std.testing.expectEqual(1422 - 1000 - 50 - 7, p.fetched());
    try std.testing.expectEqualDeep(Piece{ .fetch = .{ .offset = 0, .len = 25 } }, p.pieces[0]);
    try std.testing.expectEqualDeep(Piece{ .fetch = .{ .offset = 1075, .len = 320 } }, p.pieces[3]);
}

test "random edits: what's built is always the new blob" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x66);
    for (0..40) |_| try randomEdits(gpa, prng.random());
}

test "fuzz: random edits, the new blob built" {
    try std.testing.fuzz({}, fuzzEdits, .{});
}

fn fuzzEdits(_: void, smith: *std.testing.Smith) !void {
    var prng: std.Random.DefaultPrng = .init(smith.value(u64));
    try randomEdits(std.testing.allocator, prng.random());
}

/// A few files, some of them big enough for several chunks; then some
/// changed, added, removed or renamed. Both converted, planned, built.
fn randomEdits(gpa: Allocator, random: std.Random) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var files: std.ArrayList(TestFile) = .empty;
    // Names are numbered, so that none comes twice.
    var next: usize = 0;
    const n = random.intRangeAtMost(usize, 1, 8);
    for (0..n) |_| {
        next += 1;
        const data = try arena.alloc(u8, random.intRangeAtMost(usize, 0, 3 * 1024));
        testData(data, random.int(u32));
        const name = if (random.boolean())
            try std.fmt.allocPrint(arena, "dir/sub{d}/", .{next})
        else
            try std.fmt.allocPrint(arena, "dir/f{d}.dat", .{next});
        try files.append(arena, .{ .name = name, .data = if (std.mem.endsWith(u8, name, "/")) "" else data });
    }
    const old = try testConvert(gpa, files.items, 1024);
    defer gpa.free(old);

    for (0..random.intRangeAtMost(usize, 1, 3)) |_| {
        const i = random.uintLessThan(usize, files.items.len);
        switch (random.uintLessThan(u8, 5)) {
            0 => if (files.items[i].data.len > 0) {
                const data = try arena.dupe(u8, files.items[i].data);
                data[random.uintLessThan(usize, data.len)] ^= 1;
                files.items[i].data = data;
            },
            1 => {
                next += 1;
                try files.insert(arena, i, .{ .name = try std.fmt.allocPrint(arena, "dir/new{d}.txt", .{next}), .data = "new" });
            },
            2 => if (files.items.len > 1) {
                _ = files.orderedRemove(i);
            },
            3 => if (!std.mem.endsWith(u8, files.items[i].name, "/")) {
                next += 1;
                files.items[i].name = try std.fmt.allocPrint(arena, "dir/moved{d}.dat", .{next});
            },
            else => files.items[i].mode = 0o600,
        }
    }
    const new = try testConvert(gpa, files.items, 1024);
    defer gpa.free(new);
    var p = try testRoundTrip(gpa, &.{old}, new, .{ .max_requests = random.intRangeAtMost(usize, 1, 4), .min_gap = random.uintAtMost(u64, 600) });
    p.deinit();
}
