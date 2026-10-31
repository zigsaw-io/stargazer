//! Where a blob's bytes come from: anything that reads at an offset, such as
//! a file, bytes in memory, or a caller's ranged HTTP requests.

const Source = @This();
const std = @import("std");
const Io = std.Io;

context: *const anyopaque,
/// Reads up to `buffer.len` bytes at `offset`; returns how many, 0 only at
/// the end of the blob.
readAtFn: *const fn (context: *const anyopaque, offset: u64, buffer: []u8) anyerror!usize,
/// The blob's length.
size: u64,

/// Reads `buffer.len` bytes at `offset`, or fails with `error.EndOfStream`.
pub fn readAll(s: Source, offset: u64, buffer: []u8) !void {
    var done: usize = 0;
    while (done < buffer.len) {
        const n = try s.readAtFn(s.context, offset + done, buffer[done..]);
        if (n == 0) return error.EndOfStream;
        done += n;
    }
}

/// A source over `bytes.*`, which must outlive it.
pub fn fromBytes(bytes: *const []const u8) Source {
    return .{ .context = @ptrCast(bytes), .readAtFn = readBytes, .size = bytes.len };
}

fn readBytes(context: *const anyopaque, offset: u64, buffer: []u8) anyerror!usize {
    const bytes: *const []const u8 = @ptrCast(@alignCast(context));
    if (offset >= bytes.len) return 0;
    const start: usize = @intCast(offset);
    const n = @min(buffer.len, bytes.len - start);
    @memcpy(buffer[0..n], bytes.*[start..][0..n]);
    return n;
}

/// A file read at offsets, so that several threads can share it.
pub const File = struct {
    io: Io,
    file: Io.File,

    /// A source of the file's first `size` bytes; `f` must outlive it.
    pub fn source(f: *const File, size: u64) Source {
        return .{ .context = f, .readAtFn = readFile, .size = size };
    }

    fn readFile(context: *const anyopaque, offset: u64, buffer: []u8) anyerror!usize {
        const f: *const File = @ptrCast(@alignCast(context));
        return f.file.readPositional(f.io, &.{buffer}, offset);
    }
};

/// The bytes of a source from `start` to `end`, as a stream.
pub const Reader = struct {
    source: Source,
    /// Where the next read from the source starts.
    pos: u64,
    end: u64,
    /// Why the last read failed, if it did.
    err: ?anyerror = null,
    interface: Io.Reader,

    pub fn init(source: Source, start: u64, end: u64, buffer: []u8) Reader {
        return .{
            .source = source,
            .pos = start,
            .end = end,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    /// The offset in the source of the next byte the stream gives.
    pub fn logicalPos(r: *const Reader) u64 {
        return r.pos - r.interface.bufferedLen();
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *Reader = @fieldParentPtr("interface", io_r);
        if (r.pos >= r.end) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const want: usize = @intCast(@min(@as(u64, dest.len), r.end - r.pos));
        const n = r.source.readAtFn(r.source.context, r.pos, dest[0..want]) catch |err| {
            r.err = err;
            return error.ReadFailed;
        };
        if (n == 0) {
            r.err = error.EndOfStream;
            return error.ReadFailed;
        }
        r.pos += n;
        w.advance(n);
        return n;
    }
};

test "a range of bytes, read as a stream" {
    const bytes: []const u8 = "0123456789";
    const source: Source = .fromBytes(&bytes);
    var buf: [4]u8 = undefined;
    var r: Reader = .init(source, 2, 9, &buf);
    var out: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&out);
    _ = try r.interface.streamRemaining(&w);
    try std.testing.expectEqualStrings("2345678", w.buffered());
    try std.testing.expectEqual(9, r.logicalPos());
}
