#define _FILE_OFFSET_BITS 64 // the ISO is 2.7GB - past 32-bit off_t without this, on a -m32 build
#include "xdvdfs.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#define SEC XDVDFS_SECTOR

typedef struct {
    uint32_t startLba;
    uint32_t size;
    uint8_t attrs;
    char name[256];
} DirEntry;

static int parse_dir_buf(const uint8_t *d, size_t dlen, DirEntry *out, int max_out) {
    int n = 0;
    size_t off = 0;
    while (off + 14 <= dlen && n < max_out) {
        uint32_t startLba, size;
        memcpy(&startLba, d + off + 4, 4);
        memcpy(&size, d + off + 8, 4);
        uint8_t attrs = d[off + 12];
        uint8_t nl = d[off + 13];
        if (nl == 0 || nl > 200 || off + 14 + nl > dlen) break;
        int ok = 1;
        for (int i = 0; i < nl; i++) {
            uint8_t c = d[off + 14 + i];
            if (c < 32 || c >= 127) { ok = 0; break; }
        }
        if (!ok) break;
        DirEntry *e = &out[n++];
        e->startLba = startLba;
        e->size = size;
        e->attrs = attrs;
        memcpy(e->name, d + off + 14, nl);
        e->name[nl] = 0;
        off = (off + 14 + nl + 3) & ~(size_t) 3;
    }
    return n;
}

static int read_dir_entries(Xdvdfs *x, uint32_t lba, uint32_t size, DirEntry *out, int max_out) {
    size_t nsec = (size + SEC - 1) / SEC;
    if (nsec == 0) nsec = 1;
    uint8_t *buf = malloc(nsec * SEC);
    if (pread(x->fd, buf, nsec * SEC, (off_t) lba * SEC) != (ssize_t) (nsec * SEC)) {
        free(buf);
        return -1;
    }
    int n = parse_dir_buf(buf, nsec * SEC, out, max_out);
    free(buf);
    return n;
}

int xdvdfs_open(Xdvdfs *x, const char *iso_path) {
    x->fd = open(iso_path, O_RDONLY);
    if (x->fd < 0) {
        perror("xdvdfs_open: open");
        return -1;
    }

    uint8_t vd[SEC];
    ssize_t got = pread(x->fd, vd, SEC, 32 * (off_t) SEC);
    if (got != SEC) {
        fprintf(stderr, "xdvdfs_open: pread of volume descriptor got %zd, wanted %d: %s\n",
                got, SEC, strerror(errno));
        return -1;
    }
    if (memcmp(vd, "MICROSOFT*XBOX*MEDIA", 20) != 0) {
        fprintf(stderr, "xdvdfs_open: bad volume descriptor magic\n");
        return -1;
    }
    memcpy(&x->root_lba, vd + 20, 4);
    memcpy(&x->root_size, vd + 24, 4);
    return 0;
}

const char *xdvdfs_strip_prefix(const char *path) {
    static const char *prefixes[] = {
        "\\Device\\CdRom0\\", "\\??\\D:\\", "\\Device\\Harddisk0\\Partition1\\",
        "D:\\", "\\",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t plen = strlen(prefixes[i]);
        if (strncasecmp(path, prefixes[i], plen) == 0) {
            return path + plen;
        }
    }
    return path;
}

int xdvdfs_lookup(Xdvdfs *x, const char *path, XdvdfsEntry *out) {
    uint32_t lba = x->root_lba, size = x->root_size;
    char pathbuf[512];
    snprintf(pathbuf, sizeof(pathbuf), "%s", path);
    for (char *p = pathbuf; *p; p++) if (*p == '/') *p = '\\';

    char *saveptr = NULL;
    char *comp = strtok_r(pathbuf, "\\", &saveptr);
    if (comp == NULL) {
        // empty path -> root itself
        out->found = 1; out->is_dir = 1; out->lba = lba; out->size = size;
        return 1;
    }

    DirEntry entries[256];
    while (comp) {
        int n = read_dir_entries(x, lba, size, entries, 256);
        if (n < 0) { out->found = 0; return 0; }
        DirEntry *match = NULL;
        for (int i = 0; i < n; i++) {
            if (strcasecmp(entries[i].name, comp) == 0) { match = &entries[i]; break; }
        }
        if (!match) { out->found = 0; return 0; }

        char *next = strtok_r(NULL, "\\", &saveptr);
        int is_dir = (match->attrs & 0x10) != 0;
        if (next == NULL) {
            out->found = 1;
            out->is_dir = is_dir;
            out->lba = match->startLba;
            out->size = match->size;
            return 1;
        }
        if (!is_dir) { out->found = 0; return 0; } // path continues past a file
        lba = match->startLba;
        size = match->size;
        comp = next;
    }
    out->found = 0;
    return 0;
}

int64_t xdvdfs_read(Xdvdfs *x, const XdvdfsEntry *e, uint32_t offset, void *buf, uint32_t len) {
    if (offset >= e->size) return 0;
    uint32_t avail = e->size - offset;
    if (len > avail) len = avail;
    ssize_t got = pread(x->fd, buf, len, (off_t) e->lba * SEC + offset);
    return got;
}
