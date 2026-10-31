/*
 * stargazer: seekable layer formats for container images. eStargz first.
 *
 * Written by hand to match src/c.zig; tests/c/smoke.c, built against this
 * header, checks that they do.
 *
 * Every function that can fail returns SG_OK or a negative status, and then
 * sg_last_error() names the error, for the calling thread. A reader may be
 * used by one thread at a time.
 */
#ifndef STARGAZER_H
#define STARGAZER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SG_OK 0
#define SG_ERR_IO (-1)          /* a callback failed */
#define SG_ERR_FORMAT (-2)      /* not eStargz, or malformed */
#define SG_ERR_DIGEST (-3)      /* a digest didn't match */
#define SG_ERR_NO_MEMORY (-4)
#define SG_ERR_INVALID (-5)     /* a bad argument */
#define SG_ERR_NOT_FOUND (-6)
#define SG_ERR_UNSUPPORTED (-7) /* a kind of entry this can't handle */

/* Entry types. */
#define SG_DIR 1
#define SG_REG 2
#define SG_SYMLINK 3
#define SG_HARDLINK 4
#define SG_CHAR 5
#define SG_BLOCK 6
#define SG_FIFO 7

/* The annotations an eStargz layer's descriptor carries in the manifest. */
#define SG_TOC_DIGEST_ANNOTATION "containerd.io/snapshot/stargz/toc.digest"
#define SG_UNCOMPRESSED_SIZE_ANNOTATION "io.containers.estargz.uncompressed-size"

/* Reads up to len bytes at offset into buf; returns how many (0 only at the
 * end of the blob), or a negative number on failure. */
typedef int64_t (*sg_read_at_fn)(void *ctx, uint64_t offset, uint8_t *buf, size_t len);
/* Reads up to len bytes of a stream into buf; returns how many (0 at its
 * end), or a negative number on failure. */
typedef int64_t (*sg_read_fn)(void *ctx, uint8_t *buf, size_t len);
/* Writes all len bytes; returns 0, or anything else on failure. */
typedef int (*sg_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/* The library's version, such as "0.1.0". */
const char *sg_version(void);
/* The name of the calling thread's last error. */
const char *sg_last_error(void);

typedef struct sg_reader sg_reader;

typedef struct {
    const char *name;      /* cleaned: relative, without "." or ".."; "" for the root */
    int type;              /* SG_DIR, SG_REG, ... */
    uint32_t mode;         /* the tar header's mode */
    uint64_t size;         /* a regular file's; 0 for any other */
    const char *link_name; /* a link's target, or NULL */
    const char *digest;    /* a regular file's, "sha256:<hex>", or NULL */
    uint32_t chunks;       /* gzip members the file's contents are in */
} sg_entry;

/* Opens an eStargz blob of size bytes through its footer and TOC. The TOC's
 * digest isn't checked against anything: compare sg_reader_toc_digest() with
 * the layer's annotation, or pass it to sg_reader_verify(). */
int sg_reader_open(sg_read_at_fn read_at, void *ctx, uint64_t size, sg_reader **out);
void sg_reader_free(sg_reader *r);
/* "sha256:<hex>" of the TOC's JSON; lives as long as the reader. */
const char *sg_reader_toc_digest(const sg_reader *r);
/* Entries: the TOC's, in its order, without the chunks of large files. */
size_t sg_reader_count(const sg_reader *r);
/* Fills *out; its strings live as long as the reader. */
int sg_reader_entry(const sg_reader *r, size_t index, sg_entry *out);
/* The index of a name, as a tar entry may give it ("./a/b", "a/b/"). */
int sg_reader_lookup(const sg_reader *r, const char *name, size_t *index);
/* Writes a regular file's contents, checking each chunk's digest. */
int sg_reader_read_file(sg_reader *r, size_t index, sg_write_fn write, void *ctx);
/* Reads the whole blob and checks it against the TOC: entries, the gzip
 * members' places, every digest; and the TOC's digest, if toc_digest isn't
 * NULL. */
int sg_reader_verify(const sg_reader *r, const char *toc_digest);

typedef struct {
    uint64_t chunk_size; /* 0 for 4 MiB */
    int level;           /* deflate's, 1 to 9; 0 for 6 */
} sg_convert_options;

typedef struct {
    char toc_digest[72];  /* "sha256:<hex>", NUL-terminated */
    char blob_digest[72];
    uint64_t blob_size;
    uint64_t uncompressed_size; /* for SG_UNCOMPRESSED_SIZE_ANNOTATION */
    uint64_t entries;           /* the TOC's, chunks included */
} sg_convert_result;

/* Writes the tar stream read as eStargz, deterministically: the same tar and
 * options make the same bytes. options and out may be NULL. */
int sg_convert(sg_read_fn read, void *read_ctx, sg_write_fn write, void *write_ctx,
               const sg_convert_options *options, sg_convert_result *out);

#ifdef __cplusplus
}
#endif

#endif
