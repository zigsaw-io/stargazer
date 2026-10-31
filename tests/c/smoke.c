/* Builds against include/stargazer.h and checks the C interface end to end:
 * a tar made here is converted, opened, listed, read and verified. */
#include "stargazer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s:%d: %s (%s)\n", __FILE__, __LINE__, #cond,     \
                    sg_last_error());                                          \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    size_t pos;
} buffer;

static int append(buffer *b, const void *bytes, size_t len) {
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 4096;
        while (cap < b->len + len) cap *= 2;
        uint8_t *data = realloc(b->data, cap);
        if (!data) return -1;
        b->data = data;
        b->cap = cap;
    }
    memcpy(b->data + b->len, bytes, len);
    b->len += len;
    return 0;
}

static int write_cb(void *ctx, const uint8_t *buf, size_t len) {
    return append(ctx, buf, len);
}

static int64_t read_cb(void *ctx, uint8_t *buf, size_t len) {
    buffer *b = ctx;
    size_t n = b->len - b->pos < len ? b->len - b->pos : len;
    memcpy(buf, b->data + b->pos, n);
    b->pos += n;
    return (int64_t)n;
}

static int64_t read_at_cb(void *ctx, uint64_t offset, uint8_t *buf, size_t len) {
    buffer *b = ctx;
    if (offset >= b->len) return 0;
    size_t n = b->len - offset < len ? (size_t)(b->len - offset) : len;
    memcpy(buf, b->data + offset, n);
    return (int64_t)n;
}

/* A ustar header. */
static void header(buffer *b, const char *name, char type, unsigned long size, unsigned mode) {
    uint8_t h[512];
    memset(h, 0, sizeof h);
    snprintf((char *)h, 100, "%s", name);
    snprintf((char *)h + 100, 8, "%07o", mode);
    snprintf((char *)h + 108, 8, "%07o", 0);
    snprintf((char *)h + 116, 8, "%07o", 0);
    snprintf((char *)h + 124, 12, "%011lo", size);
    snprintf((char *)h + 136, 12, "%011o", 0);
    h[156] = (uint8_t)type;
    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);
    memset(h + 148, ' ', 8);
    unsigned sum = 0;
    for (size_t i = 0; i < sizeof h; i++) sum += h[i];
    snprintf((char *)h + 148, 7, "%06o", sum);
    append(b, h, sizeof h);
}

int main(void) {
    static const char hello[] = "hello from C\n";
    static const uint8_t zeros[1024];
    buffer tar = {0}, blob = {0}, contents = {0};

    header(&tar, "dir", '5', 0, 0755);
    header(&tar, "dir/hello.txt", '0', sizeof hello - 1, 0644);
    append(&tar, hello, sizeof hello - 1);
    append(&tar, zeros, 512 - (sizeof hello - 1));
    append(&tar, zeros, sizeof zeros);

    printf("stargazer %s\n", sg_version());
    sg_convert_options options = {.chunk_size = 0, .level = 0};
    sg_convert_result result;
    CHECK(sg_convert(read_cb, &tar, write_cb, &blob, &options, &result) == SG_OK);
    CHECK(result.blob_size == blob.len);
    CHECK(strncmp(result.toc_digest, "sha256:", 7) == 0);

    sg_reader *r = NULL;
    CHECK(sg_reader_open(read_at_cb, &blob, blob.len, &r) == SG_OK);
    CHECK(strcmp(sg_reader_toc_digest(r), result.toc_digest) == 0);
    /* The landmark, the directory, the file. */
    CHECK(sg_reader_count(r) == 3);
    sg_entry e;
    CHECK(sg_reader_entry(r, 1, &e) == SG_OK);
    CHECK(strcmp(e.name, "dir") == 0 && e.type == SG_DIR && e.mode == 0755);

    size_t index = 0;
    CHECK(sg_reader_lookup(r, "./dir/hello.txt", &index) == SG_OK);
    CHECK(sg_reader_entry(r, index, &e) == SG_OK);
    CHECK(e.type == SG_REG && e.size == sizeof hello - 1 && e.chunks == 1 && e.digest != NULL);
    CHECK(sg_reader_read_file(r, index, write_cb, &contents) == SG_OK);
    CHECK(contents.len == sizeof hello - 1 && memcmp(contents.data, hello, contents.len) == 0);
    CHECK(sg_reader_lookup(r, "missing", &index) == SG_ERR_NOT_FOUND);

    CHECK(sg_reader_verify(r, result.toc_digest) == SG_OK);
    CHECK(sg_reader_verify(r, "sha256:0000000000000000000000000000000000000000000000000000000000000000") == SG_ERR_DIGEST);
    sg_reader_free(r);

    /* A damaged blob doesn't open, or doesn't verify. */
    blob.data[blob.len - 30] ^= 0xff;
    CHECK(sg_reader_open(read_at_cb, &blob, blob.len, &r) == SG_ERR_FORMAT);

    free(tar.data);
    free(blob.data);
    free(contents.data);
    printf("ok\n");
    return 0;
}
