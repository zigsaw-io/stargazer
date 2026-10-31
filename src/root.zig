//! stargazer: seekable layer formats for container images, for Zig and C.
//! eStargz is the first. See README.md.

pub const Source = @import("Source.zig");
pub const Toc = @import("Toc.zig");
pub const tar = @import("tar.zig");
pub const gzip = @import("gzip.zig");
pub const estargz = @import("estargz.zig");

/// The package's, from build.zig.zon.
pub const version: []const u8 = @import("options").version;

test {
    @import("std").testing.refAllDecls(@This());
}
