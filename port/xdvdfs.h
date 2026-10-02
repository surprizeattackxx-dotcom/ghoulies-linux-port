// Minimal read-only XDVDFS (Xbox DVD filesystem) reader, backing the native
// loader's file-I/O kernel functions. Reads directly from the mounted ISO -
// no extraction step. See Xbox Ghoulies Linux Port.md ("XDVDFS directory
// entry layout - corrected 2026-10-01") for why the entry layout here is
// NOT what recon/xfs.py and extract.py use (they have the field order
// backwards - this was found and triple-verified against known-good sector
// numbers and a content hash before being used here).
#ifndef XDVDFS_H
#define XDVDFS_H

#include <stdint.h>
#include <stddef.h>

#define XDVDFS_SECTOR 2048

typedef struct {
    int fd;
    uint32_t root_lba;
    uint32_t root_size;
} Xdvdfs;

typedef struct {
    int found;
    int is_dir;
    uint32_t lba;
    uint32_t size;
} XdvdfsEntry;

// Opens the ISO and reads the volume descriptor (sector 32). Returns 0 on
// success, -1 on failure (bad magic, can't open file, etc).
int xdvdfs_open(Xdvdfs *x, const char *iso_path);

// Looks up a '\'-or-'/'-separated path (case-insensitive per component,
// matching Xbox FS convention) starting from the disc root. `path` should
// already have any NT-namespace prefix (\Device\CdRom0\, D:\, \??\, etc.)
// stripped - see xdvdfs_strip_prefix.
int xdvdfs_lookup(Xdvdfs *x, const char *path, XdvdfsEntry *out);

// Strips a leading NT/DOS path prefix in place, returning a pointer into the
// same buffer at the first real path component. Doesn't allocate.
const char *xdvdfs_strip_prefix(const char *path);

// Reads `len` bytes at byte `offset` within the given entry's data into buf.
// Returns bytes read, or -1 on error.
int64_t xdvdfs_read(Xdvdfs *x, const XdvdfsEntry *e, uint32_t offset, void *buf, uint32_t len);

#endif
