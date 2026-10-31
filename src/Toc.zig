//! A layer's table of contents, as eStargz keeps it in `stargz.index.json`:
//! an entry per tar entry, and one per chunk of a large file after its first.
//! zstd:chunked's derives from it; `endOffset` is its own.

const Toc = @This();
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

version: u32,
entries: []Entry,

pub const Type = enum { dir, reg, symlink, hardlink, char, block, fifo, chunk };

/// The fields in the order Go's writer emits them. A null one is left out,
/// as Go leaves out a zero one.
pub const Entry = struct {
    name: []const u8,
    type: Type,
    /// A regular file's size.
    size: ?u64 = null,
    /// UTC, RFC 3339.
    modtime: ?[]const u8 = null,
    linkName: ?[]const u8 = null,
    mode: ?u64 = null,
    uid: ?u64 = null,
    gid: ?u64 = null,
    /// Only on the first entry of a uid or gid with this name.
    userName: ?[]const u8 = null,
    groupName: ?[]const u8 = null,
    /// Where the gzip member with the payload, or this chunk of it, starts.
    offset: ?u64 = null,
    /// Where the payload starts in that member's uncompressed bytes.
    innerOffset: ?u64 = null,
    devMajor: ?u64 = null,
    devMinor: ?u64 = null,
    /// Values in base64.
    xattrs: ?std.json.ArrayHashMap([]const u8) = null,
    /// A regular file's, "sha256:<hex>".
    digest: ?[]const u8 = null,
    chunkOffset: ?u64 = null,
    /// Left out for a file's last chunk, which goes to its end.
    chunkSize: ?u64 = null,
    chunkDigest: ?[]const u8 = null,
    /// zstd:chunked's: where the chunk's compressed bytes end.
    endOffset: ?u64 = null,
};

/// Writes the TOC as Go's writer does: indented with tabs.
pub fn write(toc: Toc, w: *Io.Writer) !void {
    try std.json.Stringify.value(toc, .{ .whitespace = .indent_tab, .emit_null_optional_fields = false }, w);
}

/// Parses TOC JSON, whose strings then live in `arena`.
pub fn parse(arena: Allocator, json: []const u8) !Toc {
    const toc = std.json.parseFromSliceLeaky(Toc, arena, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.TocBadJson;
    if (toc.version != 1) return error.TocBadVersion;
    return toc;
}

pub const digest_len = "sha256:".len + 2 * Sha256.digest_length;

/// "sha256:<hex>".
pub fn formatDigest(digest: [Sha256.digest_length]u8) [digest_len]u8 {
    return ("sha256:" ++ std.fmt.bytesToHex(digest, .lower)).*;
}

pub fn parseDigest(text: []const u8) ![Sha256.digest_length]u8 {
    if (text.len != digest_len or !std.mem.startsWith(u8, text, "sha256:")) return error.TocBadDigest;
    var digest: [Sha256.digest_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, text["sha256:".len..]) catch return error.TocBadDigest;
    return digest;
}

test "written as Go writes it, and read back" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var entries = [_]Entry{
        .{ .name = "bin", .type = .dir, .mode = 0o755 },
        .{ .name = "bin/a", .type = .reg, .size = 9, .mode = 0o644, .offset = 123, .digest = "sha256:00", .chunkSize = 5, .chunkDigest = "sha256:01" },
        .{ .name = "bin/a", .type = .chunk, .offset = 200, .chunkOffset = 5, .chunkDigest = "sha256:02" },
    };
    var out: Io.Writer.Allocating = .init(arena);
    try write(.{ .version = 1, .entries = &entries }, &out.writer);
    try std.testing.expectEqualStrings("{\n" ++
        "\t\"version\": 1,\n" ++
        "\t\"entries\": [\n" ++
        "\t\t{\n" ++
        "\t\t\t\"name\": \"bin\",\n" ++
        "\t\t\t\"type\": \"dir\",\n" ++
        "\t\t\t\"mode\": 493\n" ++
        "\t\t},\n" ++
        "\t\t{\n" ++
        "\t\t\t\"name\": \"bin/a\",\n" ++
        "\t\t\t\"type\": \"reg\",\n" ++
        "\t\t\t\"size\": 9,\n" ++
        "\t\t\t\"mode\": 420,\n" ++
        "\t\t\t\"offset\": 123,\n" ++
        "\t\t\t\"digest\": \"sha256:00\",\n" ++
        "\t\t\t\"chunkSize\": 5,\n" ++
        "\t\t\t\"chunkDigest\": \"sha256:01\"\n" ++
        "\t\t},\n" ++
        "\t\t{\n" ++
        "\t\t\t\"name\": \"bin/a\",\n" ++
        "\t\t\t\"type\": \"chunk\",\n" ++
        "\t\t\t\"offset\": 200,\n" ++
        "\t\t\t\"chunkOffset\": 5,\n" ++
        "\t\t\t\"chunkDigest\": \"sha256:02\"\n" ++
        "\t\t}\n" ++
        "\t]\n" ++
        "}", out.written());

    const toc = try parse(arena, out.written());
    try std.testing.expectEqual(3, toc.entries.len);
    try std.testing.expectEqual(Type.chunk, toc.entries[2].type);
    try std.testing.expectEqual(5, toc.entries[2].chunkOffset.?);
    try std.testing.expectEqual(null, toc.entries[2].size);

    // Go's fields zigsaw doesn't use, such as NumLink, are ignored.
    const go = try parse(arena,
        \\{"version":1,"entries":[{"name":"x","type":"reg","NumLink":0,"size":0}]}
    );
    try std.testing.expectEqualStrings("x", go.entries[0].name);
    try std.testing.expectError(error.TocBadVersion, parse(arena,
        \\{"version":2,"entries":[]}
    ));
}

test "digests" {
    var d: [32]u8 = undefined;
    Sha256.hash("", &d, .{});
    const text = formatDigest(d);
    try std.testing.expectEqualStrings("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &text);
    try std.testing.expectEqualSlices(u8, &d, &try parseDigest(&text));
    try std.testing.expectError(error.TocBadDigest, parseDigest("sha512:00"));
}
