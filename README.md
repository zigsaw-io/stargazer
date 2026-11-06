# Stargazer

Seekable layer formats for container images, in Zig, for Zig and C. The
first is [eStargz](https://github.com/containerd/stargz-snapshotter/blob/main/docs/estargz.md):
a gzip-compressed tar whose files can be found, read and checked one by one,
through a table of contents at its end, and which any gzip reader still reads
as a plain tar. Made for [zigsaw](https://github.com/zigsaw-io/zigsaw), and
usable on its own, on Windows, Linux and macOS.

- **A deterministic writer.** The same tar and options always make the same
  bytes: tar headers are kept byte for byte, and a test pins the output.
- **A reader through a read-at callback**, so a blob can be a file, bytes in
  memory, or ranged HTTP requests the caller makes. It checks every chunk's
  digest as it reads, and reads part of a file a chunk at a time, as a
  filesystem that fetches files on demand serves them.
- **A strict verifier**: the tar entries are the TOC's, every gzip member
  starts where the TOC says, every digest matches.
- **Checked against containerd's Go package**, both ways: Go reads what
  stargazer writes, and stargazer what Go writes.
- **Update plans**: which gzip members of a new blob old blobs already
  have, and which byte ranges must be fetched, so an update can build the
  new blob from the old one and a few ranged requests.

Version 0.4.0. The TOC model is general enough for zstd:chunked's, which
derives from eStargz's; that format comes when Zig has a zstd compressor.

## The command

```
zig build -Doptimize=ReleaseFast
zig-out/bin/stargazer convert layer.tar.gz layer.esgz   # or a plain tar
zig-out/bin/stargazer convert --prioritized=first.txt layer.tar layer.esgz
zig-out/bin/stargazer verify --toc-digest=sha256:... layer.esgz
zig-out/bin/stargazer ls layer.esgz
zig-out/bin/stargazer cat layer.esgz usr/bin/tool > tool
zig-out/bin/stargazer extract --jobs=4 layer.esgz dir
zig-out/bin/stargazer plan old.esgz new.esgz
```

`convert` prints the TOC's digest and the tar's size, the values of the
`containerd.io/snapshot/stargz/toc.digest` and
`io.containers.estargz.uncompressed-size` annotations a layer's descriptor
carries. With `--prioritized`, a file of names, one a line, those files
come first, each after its parent directories, then the prefetch landmark:
what a lazy reader fetches before anything asks for it. That needs a plain
tar, read twice.

## From Zig

```zig
// build.zig.zon: .stargazer = .{ .path = "stargazer" }, or a URL and hash
const stargazer = @import("stargazer");
const estargz = stargazer.estargz;

const result = try estargz.convert(gpa, &tar_reader, &blob_writer, .{});
// Prioritized files need a tar that can be read anywhere.
_ = try estargz.convertSource(gpa, tar_source, &blob_writer, .{ .prioritized = &.{"bin/tool"} }, null);

const r = try estargz.Reader.open(gpa, source, .{});
defer r.deinit();
if (!std.mem.eql(u8, &r.toc_digest, &want)) return error.WrongToc;
var scratch: estargz.Reader.Scratch = .{};
defer scratch.deinit(gpa);
try r.readFile(gpa, &scratch, r.lookup("usr/bin/tool").?, &out);
// Or part of it: the chunks that hold those bytes, each whole and checked.
const file = r.lookup("usr/lib/big.so").?;
for (file.chunksIn(offset, offset + len)) |c| try r.readChunk(gpa, &scratch, c, &out);
```

`source` is a `stargazer.Source`: `Source.fromBytes`, `Source.File`, or any
read-at function.

An update between two blobs, the new one opened through ranged requests:

```zig
var p = try stargazer.plan.make(gpa, new_reader, &.{old_reader});
defer p.deinit();
// Fewer, longer requests; the tail read to open the new blob is at hand.
try p.coalesce(.{ .max_requests = 64, .have_from = tail_start });
for (p.pieces) |piece| switch (piece) {
    .copy => |c| {}, // c.len bytes of old blob c.source from c.offset
    .fetch => |f| {}, // f.len bytes of the new blob from f.offset
};
```

A member is copied when an old one has the same compressed length, payload
digest and, for a file's last chunk, the same entries after it up to the
next payload as the TOC lists them: their tar headers are in the member
too. The TOC can't prove those headers byte for byte, so check the blob
built against its digest. `plan.apply` builds it from `Source`s.

## From C

`zig build` installs `include/stargazer.h`, a static library
(`libstargazer.a`, or `stargazer_static.lib` on Windows) and a shared one.
Functions return `SG_OK` or a negative status, and `sg_last_error()` names
the error. [tests/c/smoke.c](tests/c/smoke.c) uses all of it.

```c
sg_reader *r;
if (sg_reader_open(read_at, ctx, size, &r) != SG_OK) fail(sg_last_error());
size_t i;
if (sg_reader_lookup(r, "usr/bin/tool", &i) == SG_OK) sg_reader_read_file(r, i, write, out);
sg_reader_free(r);
```

## Tests

```
zig build test          # unit tests; fuzz targets run once
zig build test-c        # a C program built against the header
zig build test --fuzz=100K                 # Linux only, in Zig 0.17
sh conformance/run.sh "$PWD/zig-out/bin/stargazer"   # needs Go 1.25
```

## Choices where the spec leaves one

As containerd's Go writer does, except where noted:

- The no-prefetch landmark comes first, unless files are prioritized: then
  they do, each after its parent directories, in the order given, then the
  prefetch landmark, then everything else in the tar's order, as Go's
  `WithPrioritizedFiles` lays them out (the conformance check compares).
- Members start at each payload and every 4 MiB inside one; no
  `innerOffset` packing, which Go's verifier can't check.
- The TOC is tab-indented JSON with Go's fields in Go's order, zero values
  left out.
- Deflate level 6, not 9, as zigsaw's gzip layers use.
- `stargz.index.json` and the landmarks' names are refused in the input.
- The input's end-of-archive blocks are left out; the TOC's entry ends the
  archive.

## Licence

MIT; see [LICENSE](LICENSE).
