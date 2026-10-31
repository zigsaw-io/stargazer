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
  digest as it reads.
- **A strict verifier**: the tar entries are the TOC's, every gzip member
  starts where the TOC says, every digest matches.
- **Checked against containerd's Go package**, both ways: Go reads what
  stargazer writes, and stargazer what Go writes.

Version 0.1.0. The TOC model is general enough for zstd:chunked's, which
derives from eStargz's; that format comes when Zig has a zstd compressor.

## The command

```
zig build -Doptimize=ReleaseFast
zig-out/bin/stargazer convert layer.tar.gz layer.esgz   # or a plain tar
zig-out/bin/stargazer verify --toc-digest=sha256:... layer.esgz
zig-out/bin/stargazer ls layer.esgz
zig-out/bin/stargazer cat layer.esgz usr/bin/tool > tool
zig-out/bin/stargazer extract --jobs=4 layer.esgz dir
```

`convert` prints the TOC's digest and the tar's size, the values of the
`containerd.io/snapshot/stargz/toc.digest` and
`io.containers.estargz.uncompressed-size` annotations a layer's descriptor
carries.

## From Zig

```zig
// build.zig.zon: .stargazer = .{ .path = "stargazer" }, or a URL and hash
const stargazer = @import("stargazer");
const estargz = stargazer.estargz;

const result = try estargz.convert(gpa, &tar_reader, &blob_writer, .{});

const r = try estargz.Reader.open(gpa, source, .{});
defer r.deinit();
if (!std.mem.eql(u8, &r.toc_digest, &want)) return error.WrongToc;
var scratch: estargz.Reader.Scratch = .{};
defer scratch.deinit(gpa);
try r.readFile(gpa, &scratch, r.lookup("usr/bin/tool").?, &out);
```

`source` is a `stargazer.Source`: `Source.fromBytes`, `Source.File`, or any
read-at function.

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

- The no-prefetch landmark comes first; no files are prioritized.
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
