//! gzip streams of several members, as eStargz blobs are. Zig's decompressor
//! reads one member and stops, without an error; these read them all.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const Source = @import("Source.zig");

/// Whether another gzip member follows the one just read from `in`. Zero
/// bytes up to the end are padding, which GNU gzip ignores too; other bytes
/// fail.
pub fn anotherMember(in: *Io.Reader) !bool {
    if (in.peek(2)) |magic| {
        if (magic[0] == 0x1f and magic[1] == 0x8b) return true;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return err,
    }
    while (in.peekGreedy(1)) |bytes| {
        for (bytes) |b| if (b != 0) return error.GzipTrailingGarbage;
        in.toss(bytes.len);
    } else |err| switch (err) {
        error.EndOfStream => return false,
        error.ReadFailed => return err,
    }
}

/// The uncompressed bytes of every member of a gzip stream in a source, one
/// after another, noting where each member starts. It must not move once
/// read from.
pub const MemberReader = struct {
    in: *Source.Reader,
    window: []u8,
    decompress: flate.Decompress = undefined,
    in_member: bool = false,
    done: bool = false,
    /// Uncompressed bytes given so far.
    produced: u64 = 0,
    /// Where each member starts, appended as they start, if not null.
    members: ?*std.ArrayList(Member),
    gpa: Allocator,
    /// Why the last read failed, if it did.
    err: ?anyerror = null,
    interface: Io.Reader,

    pub const Member = struct {
        /// Offset in the source.
        compressed: u64,
        /// Offset in the uncompressed stream.
        uncompressed: u64,
    };

    /// `window` must be `flate.max_window_len` bytes long.
    pub fn init(gpa: Allocator, in: *Source.Reader, window: []u8, buffer: []u8, members: ?*std.ArrayList(Member)) MemberReader {
        return .{
            .in = in,
            .window = window,
            .members = members,
            .gpa = gpa,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const m: *MemberReader = @fieldParentPtr("interface", io_r);
        while (true) {
            if (m.done) return error.EndOfStream;
            if (!m.in_member) {
                if (m.members) |list| list.append(m.gpa, .{
                    .compressed = m.in.logicalPos(),
                    .uncompressed = m.produced,
                }) catch |err| {
                    m.err = err;
                    return error.ReadFailed;
                };
                m.decompress = .init(&m.in.interface, .gzip, m.window);
                m.in_member = true;
            }
            const n = m.decompress.reader.stream(w, limit) catch |err| switch (err) {
                error.EndOfStream => {
                    m.in_member = false;
                    m.done = !(anotherMember(&m.in.interface) catch |e| {
                        m.err = if (m.in.err) |in_err| in_err else e;
                        return error.ReadFailed;
                    });
                    continue;
                },
                error.ReadFailed => {
                    m.err = if (m.decompress.err) |d_err| d_err else if (m.in.err) |in_err| in_err else err;
                    return error.ReadFailed;
                },
                error.WriteFailed => return error.WriteFailed,
            };
            m.produced += n;
            return n;
        }
    }
};

fn member(out: *Io.Writer, data: []const u8) !void {
    var window: [flate.max_window_len]u8 = undefined;
    var c: flate.Compress = try .init(out, &window, .gzip, .level_6);
    try c.writer.writeAll(data);
    try c.finish();
}

test "every member, and where each starts" {
    const gpa = std.testing.allocator;
    var buf: [4096]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try member(&out, "first\n");
    const second_at = out.end;
    try member(&out, "second\n");
    try member(&out, "");
    try out.splatByteAll(0, 100);
    const bytes: []const u8 = out.buffered();

    var in_buf: [64]u8 = undefined;
    var in: Source.Reader = .init(.fromBytes(&bytes), 0, bytes.len, &in_buf);
    var members: std.ArrayList(MemberReader.Member) = .empty;
    defer members.deinit(gpa);
    var window: [flate.max_window_len]u8 = undefined;
    var m_buf: [512]u8 = undefined;
    var m: MemberReader = .init(gpa, &in, &window, &m_buf, &members);
    var got: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&got);
    _ = try m.interface.streamRemaining(&w);
    try std.testing.expectEqualStrings("first\nsecond\n", w.buffered());
    try std.testing.expectEqual(3, members.items.len);
    try std.testing.expectEqual(MemberReader.Member{ .compressed = second_at, .uncompressed = 6 }, members.items[1]);
}

test "bytes after the last member that aren't padding fail" {
    var buf: [256]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try member(&out, "data");
    try out.writeAll("\x00junk");
    var in: Io.Reader = .fixed(out.buffered());
    var window: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .gzip, &window);
    var got: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&got);
    _ = try d.reader.streamRemaining(&w);
    try std.testing.expectError(error.GzipTrailingGarbage, anotherMember(&in));
}
