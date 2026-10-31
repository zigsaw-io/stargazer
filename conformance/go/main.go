// Conformance checks against containerd's Go package, estargz: the reference
// implementation of eStargz. See ../run.sh.
//
//	conformance mktar <out.tar>
//	    a tar of every kind of entry stargazer and Go handle, written by Go
//	conformance build <chunk-size> <in.tar> <out.blob>
//	    an eStargz blob made by Go; prints its TOC digest
//	conformance check <blob> <toc-digest>
//	    opens a blob with Go's reader, checks the TOC's digest and every
//	    chunk's, and lists the tree as `stargazer ls` does, sorted
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/containerd/stargz-snapshotter/estargz"
	digest "github.com/opencontainers/go-digest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "mktar":
		if len(os.Args) != 3 {
			usage()
		}
		err = mktar(os.Args[2])
	case "build":
		if len(os.Args) != 5 {
			usage()
		}
		err = build(os.Args[2], os.Args[3], os.Args[4])
	case "check":
		if len(os.Args) != 4 {
			usage()
		}
		err = check(os.Args[2], os.Args[3])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: conformance mktar <out.tar> | build <chunk-size> <in.tar> <out> | check <blob> <toc-digest>")
	os.Exit(2)
}

// Bytes that compress somewhat, from a fixed LCG.
func data(n int, seed uint32) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = "stargazer\n"[(x>>24)%10]
	}
	return b
}

func mktar(out string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	entries := []struct {
		hdr  tar.Header
		body []byte
	}{
		{tar.Header{Typeflag: tar.TypeDir, Name: "bin/", Mode: 0o755}, nil},
		{tar.Header{Typeflag: tar.TypeReg, Name: "bin/tool", Mode: 0o755}, []byte("#!/bin/sh\necho tool\n")},
		{tar.Header{Typeflag: tar.TypeReg, Name: "empty", Mode: 0o644}, nil},
		{tar.Header{Typeflag: tar.TypeDir, Name: "share/", Mode: 0o755}, nil},
		// Several chunks at the 64 KiB the checks use, and exactly two.
		{tar.Header{Typeflag: tar.TypeReg, Name: "share/big.dat", Mode: 0o644}, data(300_000, 1)},
		{tar.Header{Typeflag: tar.TypeReg, Name: "share/two.dat", Mode: 0o644}, data(2 * 65536, 2)},
		// Names too long for ustar, which Go writes with pax. Parents come
		// first, as in layers: Go's reader makes up directories that aren't
		// in the tar, which stargazer doesn't.
		{tar.Header{Typeflag: tar.TypeDir, Name: "deep/", Mode: 0o755}, nil},
		{tar.Header{Typeflag: tar.TypeDir, Name: "deep/" + strings.Repeat("d", 150) + "/", Mode: 0o750}, nil},
		{tar.Header{Typeflag: tar.TypeReg, Name: "deep/" + strings.Repeat("d", 150) + "/file.txt", Mode: 0o600}, []byte("deep\n")},
		{tar.Header{Typeflag: tar.TypeReg, Name: "owned", Mode: 0o640, Uid: 1000, Gid: 1000, Uname: "user", Gname: "group"}, []byte("owned\n")},
		{tar.Header{Typeflag: tar.TypeReg, Name: "xattr", Mode: 0o644, PAXRecords: map[string]string{"SCHILY.xattr.user.k": "v"}}, []byte("x\n")},
		{tar.Header{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "bin/tool", Mode: 0o777}, nil},
		{tar.Header{Typeflag: tar.TypeLink, Name: "hard", Linkname: "bin/tool", Mode: 0o755}, nil},
	}
	for _, e := range entries {
		h := e.hdr
		h.Size = int64(len(e.body))
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		if _, err := tw.Write(e.body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return os.WriteFile(out, buf.Bytes(), 0o644)
}

func build(chunk, in, out string) error {
	chunkSize, err := strconv.Atoi(chunk)
	if err != nil {
		return err
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	blob, err := estargz.Build(io.NewSectionReader(f, 0, st.Size()), estargz.WithChunkSize(chunkSize))
	if err != nil {
		return err
	}
	defer blob.Close()
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	if _, err := io.Copy(o, blob); err != nil {
		o.Close()
		return err
	}
	if err := o.Close(); err != nil {
		return err
	}
	fmt.Println(blob.TOCDigest())
	return nil
}

func check(path, tocDigest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	r, err := estargz.Open(io.NewSectionReader(f, 0, st.Size()))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	want, err := digest.Parse(tocDigest)
	if err != nil {
		return err
	}
	verifier, err := r.VerifyTOC(want)
	if err != nil {
		return fmt.Errorf("verify TOC: %w", err)
	}

	var lines []string
	var walk func(name string, e *estargz.TOCEntry) error
	walk = func(name string, e *estargz.TOCEntry) error {
		if name != "" {
			line := fmt.Sprintf("%-8s %04o %12d %s", e.Type, e.Mode&0o7777, e.Size, name)
			if e.LinkName != "" {
				line += " -> " + e.LinkName
			}
			lines = append(lines, line)
		}
		if e.Type == "reg" && e.Size > 0 {
			if err := checkFile(r, verifier, name, e); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		var err error
		e.ForeachChild(func(base string, child *estargz.TOCEntry) bool {
			childName := base
			if name != "" {
				childName = name + "/" + base
			}
			err = walk(childName, child)
			return err == nil
		})
		return err
	}
	root, ok := r.Lookup("")
	if !ok {
		return fmt.Errorf("no root")
	}
	if err := walk("", root); err != nil {
		return err
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

// Reads a file, checking each chunk with Go's verifier and the whole with
// the TOC's digest.
func checkFile(r *estargz.Reader, verifier estargz.TOCEntryVerifier, name string, e *estargz.TOCEntry) error {
	sr, err := r.OpenFile(name)
	if err != nil {
		return err
	}
	whole := sha256.New()
	for off := int64(0); off < e.Size; {
		ce, ok := r.ChunkEntryForOffset(name, off)
		if !ok {
			return fmt.Errorf("no chunk at %d", off)
		}
		v, err := verifier.Verifier(ce)
		if err != nil {
			return err
		}
		chunk := make([]byte, ce.ChunkSize)
		if _, err := sr.ReadAt(chunk, ce.ChunkOffset); err != nil && err != io.EOF {
			return err
		}
		v.Write(chunk)
		if !v.Verified() {
			return fmt.Errorf("chunk at %d doesn't match its digest", off)
		}
		whole.Write(chunk)
		off = ce.ChunkOffset + ce.ChunkSize
	}
	if got := digest.NewDigest(digest.SHA256, whole); got.String() != e.Digest {
		return fmt.Errorf("digest %s, the TOC has %s", got, e.Digest)
	}
	return nil
}
