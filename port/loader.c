// Native Linux loader for default.xbe (Grabbed by the Ghoulies, original Xbox).
//
// What this does, honestly:
//   - Parses the XBE directly from the file (section table, entry point, kernel
//     thunk table), the same way scripts/decode_section_table.py does, so it's
//     not relying on anything hardcoded from the Ghidra side.
//   - Maps the whole image (header + 32 sections) as ONE big RWX anonymous
//     mapping at the Xbox's own addresses, because the sections are packed
//     tightly in virtual space (not page-aligned relative to each other -
//     e.g. the D3D section starts at 0x171020), so per-section mprotect with
//     correct permissions isn't straightforward without splitting pages that
//     are shared between sections wanting different permissions. One RWX
//     region is a deliberate v1 simplification, not a correctness bug: looser
//     permissions never change program behavior, they just don't catch bugs
//     the hardware would have caught. Tightening this is future work.
//   - Sets up a minimal fake TIB (Thread Information Block) reachable via the
//     FS segment register, because entry()'s first instructions are the
//     classic MSVC SEH prologue (`mov eax, fs:[0]` etc.) and will fault on
//     literally the first instruction without it. Linux's own glibc/NPTL uses
//     %gs for its TLS on x86-32, leaving %fs free - this is the same trick
//     Wine uses to give Windows code a usable FS-based TEB on Linux.
//   - Patches every entry in the Kernel Image Thunk Table to point at a stub
//     (see kstubs.h) that reports which xboxkrnl function got called and
//     exits, instead of a real implementation. This is intentional: real
//     kernel functions (thread creation, virtual memory, etc.) deserve to be
//     implemented correctly one at a time, not rushed. Running this tells you
//     exactly which one to implement next.
//
// Build (needs a 32-bit toolchain - see the we-build distrobox):
//   gcc -m32 -no-pie -o loader loader.c -lpthread
//
// This is 32-bit x86 code throughout. No CPU emulation anywhere - the whole
// point established earlier today is that original Xbox code IS x86, so it
// runs directly on the host CPU.

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64 // see xdvdfs.c - the ISO is 2.7GB, past 32-bit off_t on this -m32 build
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <asm/ldt.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <malloc.h> // malloc_usable_size - for ExQueryPoolBlockSize
#include <ctype.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/uio.h> // process_vm_readv - fault-safe memory reads inside the SIGSEGV handler
#include "xdvdfs.h"

#define ISO_PATH "/home/donnie/Downloads/Grabbed by the Ghoulies (USA) (En,Fr,De,Es,It).iso"

#define XBE_PATH "../xbe/default.xbe"

#define XOR_EP_RETAIL  0xA8FC57ABu
#define XOR_KT_RETAIL  0x5B6D40B6u

// Installs a fake TIB reachable via %fs for the CALLING thread. Every Xbox
// thread (not just the first) needs this before it can run any code with an
// SEH prologue - each pthread has its own independent %fs register value, so
// this must run once per thread, not once per process.
//
// Uses modify_ldt(), not set_thread_area(). Found the hard way: Linux's
// set_thread_area() GDT mechanism has exactly 3 slots TOTAL PER PROCESS (not
// per thread - confirmed empirically, a 3-thread-plus-main-thread reproducer
// showed brand-new threads failing on their very first call once the
// process-wide pool was exhausted), and glibc's own NPTL already uses one of
// them for its %gs-based TLS, leaving just 2 for us - a hard wall for any
// game with more than two threads across its lifetime. modify_ldt() uses the
// LDT instead, which has thousands of slots and is exactly what Wine uses
// for the same reason (a real per-thread Win32 TEB segment). Verified
// working across 7 sequential/cross-thread allocations with no limit hit.
static int g_next_ldt_index = 0;
//
// FS:[0x28] is a second field discovered by actually running the CRT's
// thread-bootstrap code under gdb: it reads FS:[0x28] into a pointer, then
// reads THAT pointer's own +0x28 field as the destination for a memcpy of the
// game's TLS template data (size matches the 0x94-byte TlsDataSize seen
// earlier independently from the entry() decompile - a real cross-check,
// not a guess). This is not the standard NT TEB layout (Xbox's kernel used
// its own, smaller thread structure), so these offsets are reverse-engineered
// from observed behavior, not from a published struct - expect to keep
// extending this as further fields get hit.
static void setup_fs_tib_for_this_thread(void) {
    uint32_t *tib = calloc(256, sizeof(uint32_t));
    tib[0] = 0xFFFFFFFF; // empty SEH chain

    // FS:[0x4] is a pointer to a TLS slot array, confirmed via a clean
    // decompile of the actual getter/setter pair the CRT uses: both do
    // `*(int*)( *(int*)(FS:[4] + DAT_00434234*4) + 8 )` (get) or `= value`
    // (set). DAT_00434234 is the TLS directory's AddressOfIndex target -
    // entry()'s own startup code computes it as TlsDataSize/-4 (a standard
    // MSVC-toolchain module-TLS-index convention, not a bug or a TlsAlloc
    // result), which for this binary's real TlsDataSize (0x94, confirmed
    // independently several times today) is exactly **-37**. A small
    // zero-based array doesn't cover a negative index - verified live via
    // gdb that -37 is really what's read, not a guess. Allocated with
    // generous headroom on both sides of index 0 and the pointer handed out
    // as FS:[4] is offset to the middle, so both positive and negative
    // indices land safely inside it.
    #define TLS_SLOT_COUNT 256
    #define TLS_SLOT_MID (TLS_SLOT_COUNT / 2)
    uint32_t *tls_slots_base = calloc(TLS_SLOT_COUNT, sizeof(uint32_t));
    uint32_t *tls_slots = tls_slots_base + TLS_SLOT_MID; // slot[0] is the middle of the real buffer
    tib[1] = (uint32_t) (uintptr_t) tls_slots;
    tib[2] = 0x00000000; // stack limit: unused/unenforced in this v1

    uint32_t *xthread = calloc(256, sizeof(uint32_t));   // the structure FS:[0x28], FS:[0x20], and TLS slot[-37] all point to
    uint32_t *tls_block = calloc(4096, 1);                // generous vs. the ~0x94-byte TLS data seen so far
    xthread[0x28 / 4] = (uint32_t) (uintptr_t) tls_block; // xthread+0x28 -> TLS block
    tib[0x28 / 4] = (uint32_t) (uintptr_t) xthread;       // FS:[0x28] -> xthread
    tls_slots[-37] = (uint32_t) (uintptr_t) xthread;      // TLS slot[-37] -> xthread (xthread+8 is the get/set target)
    // FS:[0x20] -> same xthread block: observed check is `CMP [FS:[0x20]+0x250],0`,
    // a per-thread flag we want to read as zero/unset. Reusing xthread (already
    // zeroed, and big enough - offset 0x250 is well inside its 1KB) rather than
    // allocating a separate block for a single zero-check, since nothing so far
    // suggests these need to be different objects.
    tib[0x20 / 4] = (uint32_t) (uintptr_t) xthread;

    struct user_desc u;
    memset(&u, 0, sizeof(u));
    u.entry_number = __sync_fetch_and_add(&g_next_ldt_index, 1); // we pick the index for modify_ldt, unlike set_thread_area
    u.base_addr = (unsigned long) tib;
    u.limit = 0xFFFFFFFF;
    u.seg_32bit = 1;
    u.limit_in_pages = 1;
    u.useable = 1;

    if (syscall(SYS_modify_ldt, 0x11 /* write, struct user_desc format */, &u, sizeof(u)) != 0) {
        fprintf(stderr, "modify_ldt failed: errno=%d (%s), tid=%d, pid=%d, entry_number=%u\n",
                errno, strerror(errno), (int) syscall(SYS_gettid), (int) getpid(), u.entry_number);
        _exit(1);
    }
    uint16_t selector = (uint16_t) ((u.entry_number << 3) | 7); // LDT (TI bit set) + RPL 3
    __asm__ volatile ("mov %0, %%fs" : : "r" (selector));
}

// ----------------------------------------------------------------------
// Real xboxkrnl implementations (the ones that have been built so far -
// everything else still goes through the generic stub in kstubs.h).
// ----------------------------------------------------------------------

// PKSYSTEM_ROUTINE / PKSTART_ROUTINE signatures per the real Xbox kernel
// (cross-checked against Cxbx-Reloaded's src/core/kernel/common/types.h):
//   void NTAPI SystemRoutine(PKSTART_ROUTINE StartRoutine, PVOID StartContext);
//   void NTAPI StartRoutine(PVOID StartContext);
// Both stdcall. The game almost always supplies its own SystemRoutine (a CRT
// thread-bootstrap wrapper, confirmed by decompiling the real call site) -
// when it does, the kernel's job is just to call THAT with (StartRoutine,
// StartContext) and let it decide whether/how to call StartRoutine itself.
typedef void (__attribute__((stdcall)) *XbSystemRoutine)(void *StartRoutine, void *StartContext);
typedef void (__attribute__((stdcall)) *XbStartRoutine)(void *StartContext);

typedef struct {
    void *system_routine;
    void *start_routine;
    void *start_context;
} ThreadBootArgs;

static void install_altstack_for_this_thread(void); // defined near install_io_trap_handler below

static void *thread_trampoline(void *arg) {
    ThreadBootArgs *b = (ThreadBootArgs *) arg;
    setup_fs_tib_for_this_thread();
    install_altstack_for_this_thread();
    fprintf(stderr, "[thread 0x%lx] starting, system_routine=%p start_routine=%p context=%p\n",
            (unsigned long) pthread_self(), b->system_routine, b->start_routine, b->start_context);
    if (b->system_routine) {
        ((XbSystemRoutine) b->system_routine)(b->start_routine, b->start_context);
    } else if (b->start_routine) {
        ((XbStartRoutine) b->start_routine)(b->start_context);
    }
    fprintf(stderr, "[thread 0x%lx] system/start routine returned\n", (unsigned long) pthread_self());
    free(b);
    return NULL;
}

// Minimal handle table. Real Xbox handles are kernel object pointers; all we
// need right now is something NtClose can accept back and something unique
// enough not to collide with 0/NULL.
static pthread_t g_threads[64];
static int g_thread_count = 0;

// Joins every thread in g_threads[] except the calling thread itself (a
// thread can't join itself - this matters because HalReturnToFirmware's
// quick-reboot path calls this from inside one of those very threads).
static void wait_for_all_threads(void) {
    pthread_t self = pthread_self();
    for (int i = 0; i < g_thread_count; i++) {
        if (pthread_equal(g_threads[i], self)) continue;
        pthread_join(g_threads[i], NULL);
    }
}

static uint32_t NTAPI_STDCALL_PsCreateSystemThreadEx(
    uint32_t *ThreadHandle, uint32_t ThreadExtensionSize, uint32_t KernelStackSize,
    uint32_t TlsDataSize, uint32_t *ThreadId, void *StartRoutine, void *StartContext,
    uint32_t CreateSuspended, uint32_t DebuggerThread, void *SystemRoutine)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_PsCreateSystemThreadEx(
    uint32_t *ThreadHandle, uint32_t ThreadExtensionSize, uint32_t KernelStackSize,
    uint32_t TlsDataSize, uint32_t *ThreadId, void *StartRoutine, void *StartContext,
    uint32_t CreateSuspended, uint32_t DebuggerThread, void *SystemRoutine)
{
    (void) ThreadExtensionSize; (void) DebuggerThread;
    fprintf(stderr,
        "PsCreateSystemThreadEx: stack=0x%x tls=0x%x start=%p ctx=%p suspended=%u sysroutine=%p\n",
        KernelStackSize, TlsDataSize, StartRoutine, StartContext, CreateSuspended, SystemRoutine);

    if (CreateSuspended) {
        fprintf(stderr, "  (CreateSuspended requested but not implemented in this v1 - starting immediately)\n");
    }

    ThreadBootArgs *args = malloc(sizeof(*args));
    args->system_routine = SystemRoutine;
    args->start_routine = StartRoutine;
    args->start_context = StartContext;

    // Real hardware honors the requested KernelStackSize (often a tiny few
    // KB, since Xbox game code is written for it specifically); this loader
    // doesn't need to match that - using it as a literal pthread stack size
    // caused a real guard-page SIGSEGV (confirmed live via gdb: a clean
    // PUSH instruction faulting at a round-page-boundary ESP, deep inside
    // the NV2A graphics-init call chain's much heavier native stack usage -
    // this host's compiled code just uses more stack per frame than the
    // original Xbox binary's own stack budget assumed). A generous fixed
    // floor avoids the whole class of bug without needing to tune per-caller.
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stack_size = KernelStackSize > (64u * 1024 * 1024) ? KernelStackSize : (64u * 1024 * 1024);
    pthread_attr_setstacksize(&attr, stack_size);

    pthread_t tid;
    int rc = pthread_create(&tid, &attr, thread_trampoline, args);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        fprintf(stderr, "  pthread_create failed: %d\n", rc);
        return 0xC0000001u; // STATUS_UNSUCCESSFUL
    }

    uint32_t handle = 0x1000u + (uint32_t) g_thread_count;
    g_threads[g_thread_count++] = tid;
    if (ThreadHandle) *ThreadHandle = handle;
    if (ThreadId) *ThreadId = handle; // same value is fine for this v1 - nothing cross-checks them yet
    return 0; // STATUS_SUCCESS
}

// ----------------------------------------------------------------------
// File I/O, backed directly by the mounted ISO via xdvdfs.c - no extraction
// step (Don's call). Handles in the 0x2000+ range are file handles,
// distinct from the 0x1000+ range PsCreateSystemThreadEx hands out, so
// NtClose can tell which table to look in.
// ----------------------------------------------------------------------
static Xdvdfs g_iso;
static int g_iso_ready = 0;

// Harddisk0/Partition1 (the Xbox's internal hard drive - TDATA/UDATA save
// directories, etc.) used to just alias to the disc root, which can never
// contain a real "TDATA" folder - found live when NtCreateFile for
// "...\Harddisk0\partition1\TDATA" failed and triggered another quick-reboot
// loop. Real fix, not a patch over the symptom: give it actual backing on
// the host filesystem, auto-creating directories on demand exactly like a
// freshly-formatted Xbox hard drive would have an empty TDATA the first time
// a title creates it.
#define HDD_ROOT "hdd_root"

typedef enum { DEV_DVD, DEV_HARDDISK } DeviceKind;
typedef struct {
    int used;
    DeviceKind device;
    int host_backed;     // 1 = real host fd/dir (Harddisk0), 0 = XdvdfsEntry (DVD)
    XdvdfsEntry entry;    // valid when !host_backed
    int host_fd;          // valid when host_backed && !is_dir (-1 otherwise)
    int is_dir;
    uint32_t cursor;
    int partition_number; // parsed from "PartitionN" paths for Harddisk0, -1 otherwise (e.g. IOCTL_DISK_GET_PARTITION_INFO needs it)
} FileHandleEntry;
static FileHandleEntry g_file_handles[256];
static int g_file_handle_count = 0;

static int ensure_iso_open(void) {
    if (g_iso_ready) return 1;
    if (xdvdfs_open(&g_iso, ISO_PATH) != 0) {
        fprintf(stderr, "ensure_iso_open: failed to open ISO at %s\n", ISO_PATH);
        return 0;
    }
    g_iso_ready = 1;
    return 1;
}

// The partition root itself always exists on real hardware (formatting
// creates it; a game only creates subdirectories like TDATA within it) -
// pre-create it so opening it with plain FILE_OPEN semantics (no create
// flag) succeeds, same as it always would on a real console.
//
// Partition0 is different: found live (gdb + decompile, not a guess) that
// it's a real, always-present raw disk-cache-config partition on genuine
// hardware - a startup routine opens it as a FILE (not a directory) and
// reads a 512-byte sector at offset 0x800 looking for a magic number/version
// marking it as already-initialized. If the magic doesn't match, the code's
// own fallback path rebuilds in-memory defaults - exactly the behavior a
// truly fresh/unformatted drive would also trigger on real hardware. So a
// zeroed placeholder file is the *correct* representation of "never
// formatted," not a workaround: the open just needs to succeed, and letting
// the game's own real first-boot logic take it from there.
static int g_hdd_ready = 0;
static void ensure_hdd_ready(void) {
    if (g_hdd_ready) return;
    mkdir(HDD_ROOT, 0755);
    mkdir(HDD_ROOT "/partition1", 0755);
    // Partition0's raw bytes live at the same reserved sub-path
    // open_or_create_file uses for every other bare partition root's raw
    // form (see its comment) - partition0 is a directory now too, not a
    // flat file directly, so it can't collide the same way "Z:\index.dat"
    // did once this convention was made consistent across all partitions.
    mkdir(HDD_ROOT "/partition0", 0755);
    struct stat st;
    if (stat(HDD_ROOT "/partition0/__raw_partition_data__", &st) != 0) {
        int fd = open(HDD_ROOT "/partition0/__raw_partition_data__", O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) { ftruncate(fd, 1024 * 1024); close(fd); } // 1MB, generous margin over the 0x800+0x200 read seen
    }
    g_hdd_ready = 1;
}

// Translates a path already known to be under \Device\Harddisk0\ into a real
// path under HDD_ROOT on the host filesystem (backslashes -> slashes).
static void harddisk_host_path(const char *xbox_rel_path, char *out, size_t outsize) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", xbox_rel_path);
    for (char *p = buf; *p; p++) if (*p == '\\') *p = '/';
    snprintf(out, outsize, "%s/%s", HDD_ROOT, buf);
}

// mkdir -p equivalent for the path's parent directories (not the final
// component, which the caller creates itself as either a file or a dir).
static void mkdir_parents(const char *path) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(buf, 0755);
            *p = '/';
        }
    }
}

typedef struct { uint16_t Length, MaximumLength; char *Buffer; } XbString;      // real STRING layout
typedef struct { uint32_t RootDirectory; XbString *ObjectName; uint32_t Attributes; } XbObjectAttributes;
typedef struct { uint32_t Status; uint32_t Information; } XbIoStatusBlock;

// ----------------------------------------------------------------------
// Symbolic links: `IoCreateSymbolicLink(PSTRING SymbolicLinkName, PSTRING DeviceName)`,
// `IoDeleteSymbolicLink(PSTRING SymbolicLinkName)`. Real Xbox code uses these
// to alias a short name (e.g. "\??\T:") to a real device/path, then opens
// files through the alias. Seen live: a startup routine builds a
// "T:\$u\<hex>" style path and registers it via IoCreateSymbolicLink -
// without resolving these, any later open through that alias would fail.
// Maintained as a simple name->target table that NtOpenFile's path
// resolution checks (as a prefix substitution) before falling back to the
// fixed NT-namespace prefixes in xdvdfs_strip_prefix.
static void xb_string_to_c(XbString *s, char *out, size_t outsize) {
    int len = s->Length < (int) outsize - 1 ? s->Length : (int) outsize - 1;
    memcpy(out, s->Buffer, len);
    out[len] = 0;
}

typedef struct { int used; char name[64]; char target[256]; } SymlinkEntry;
static SymlinkEntry g_symlinks[32];

// If `path` starts with a registered symlink name, writes the resolved path
// (target + remainder of path past the alias) into out and returns 1;
// otherwise returns 0 and out is untouched. Symlinks are registered with
// their full NT-namespace name (e.g. "\??\Z:"), but found live: the game
// also opens paths using the bare drive letter directly (e.g. "Z:\index.dat",
// no "\??\" prefix) - real NT resolves both forms to the same object, since
// "\??\" is just the DosDevices directory a drive letter normally lives
// under. Matching only the full name silently failed to resolve these,
// falling through to the DVD-path branch and reporting a wrong-but-
// plausible-looking NOT_FOUND instead of the real Harddisk0 path.
static int resolve_symlink_prefix(const char *path, char *out, size_t outsize) {
    for (int i = 0; i < (int) (sizeof(g_symlinks) / sizeof(g_symlinks[0])); i++) {
        if (!g_symlinks[i].used) continue;
        const char *name = g_symlinks[i].name;
        size_t nlen = strlen(name);
        if (strncasecmp(path, name, nlen) == 0) {
            snprintf(out, outsize, "%s%s", g_symlinks[i].target, path + nlen);
            return 1;
        }
        static const char NT_DOS_DEVICES_PREFIX[] = "\\??\\";
        size_t prefix_len = sizeof(NT_DOS_DEVICES_PREFIX) - 1;
        if (nlen > prefix_len && strncmp(name, NT_DOS_DEVICES_PREFIX, prefix_len) == 0) {
            const char *bare_name = name + prefix_len;
            size_t bare_len = nlen - prefix_len;
            if (strncasecmp(path, bare_name, bare_len) == 0) {
                snprintf(out, outsize, "%s%s", g_symlinks[i].target, path + bare_len);
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t NTAPI_STDCALL_IoCreateSymbolicLink(XbString *SymbolicLinkName, XbString *DeviceName) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_IoCreateSymbolicLink(XbString *SymbolicLinkName, XbString *DeviceName) {
    char name[64], target[256];
    xb_string_to_c(SymbolicLinkName, name, sizeof(name));
    xb_string_to_c(DeviceName, target, sizeof(target));

    int slot = -1;
    for (int i = 0; i < (int) (sizeof(g_symlinks) / sizeof(g_symlinks[0])); i++) {
        if (g_symlinks[i].used && strcasecmp(g_symlinks[i].name, name) == 0) { slot = i; break; }
        if (!g_symlinks[i].used && slot < 0) slot = i;
    }
    if (slot < 0) {
        fprintf(stderr, "IoCreateSymbolicLink: table full, dropping \"%s\" -> \"%s\"\n", name, target);
        return 0xC0000001u;
    }
    snprintf(g_symlinks[slot].name, sizeof(g_symlinks[slot].name), "%s", name);
    snprintf(g_symlinks[slot].target, sizeof(g_symlinks[slot].target), "%s", target);
    g_symlinks[slot].used = 1;
    fprintf(stderr, "IoCreateSymbolicLink(\"%s\" -> \"%s\")\n", name, target);
    return 0; // STATUS_SUCCESS
}

static uint32_t NTAPI_STDCALL_IoDeleteSymbolicLink(XbString *SymbolicLinkName) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_IoDeleteSymbolicLink(XbString *SymbolicLinkName) {
    char name[64];
    xb_string_to_c(SymbolicLinkName, name, sizeof(name));
    for (int i = 0; i < (int) (sizeof(g_symlinks) / sizeof(g_symlinks[0])); i++) {
        if (g_symlinks[i].used && strcasecmp(g_symlinks[i].name, name) == 0) {
            g_symlinks[i].used = 0;
            fprintf(stderr, "IoDeleteSymbolicLink(\"%s\") - removed\n", name);
            return 0;
        }
    }
    fprintf(stderr, "IoDeleteSymbolicLink(\"%s\") - not found, ignoring\n", name);
    return 0; // STATUS_SUCCESS - deleting something absent isn't fatal here
}

// NtOpenSymbolicLinkObject: `NTSTATUS NtOpenSymbolicLinkObject(PHANDLE LinkHandle,
// POBJECT_ATTRIBUTES ObjectAttributes)`. Opens a handle to the symlink OBJECT
// itself (not through it, unlike resolve_symlink_prefix) - the name must
// match one registered via IoCreateSymbolicLink exactly. Handles live in
// their own 0x4000+ range so they never collide with file handles; NtClose
// already no-ops gracefully for anything outside the file-handle table.
#define MAX_SYMLINK_HANDLES 32
static int g_symlink_handle_target[MAX_SYMLINK_HANDLES]; // index into g_symlinks
static int g_symlink_handle_count = 0;

static uint32_t NTAPI_STDCALL_NtOpenSymbolicLinkObject(uint32_t *LinkHandle, XbObjectAttributes *ObjectAttributes) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_NtOpenSymbolicLinkObject(uint32_t *LinkHandle, XbObjectAttributes *ObjectAttributes) {
    char name[64];
    xb_string_to_c(ObjectAttributes->ObjectName, name, sizeof(name));

    for (int i = 0; i < (int) (sizeof(g_symlinks) / sizeof(g_symlinks[0])); i++) {
        if (g_symlinks[i].used && strcasecmp(g_symlinks[i].name, name) == 0) {
            if (g_symlink_handle_count >= MAX_SYMLINK_HANDLES) {
                fprintf(stderr, "NtOpenSymbolicLinkObject(\"%s\"): handle table full\n", name);
                return 0xC0000001u;
            }
            int idx = g_symlink_handle_count++;
            g_symlink_handle_target[idx] = i;
            *LinkHandle = 0x4000u + (uint32_t) idx;
            fprintf(stderr, "NtOpenSymbolicLinkObject(\"%s\" -> \"%s\") -> handle 0x%x\n",
                    name, g_symlinks[i].target, *LinkHandle);
            return 0;
        }
    }
    fprintf(stderr, "NtOpenSymbolicLinkObject(\"%s\") - not found\n", name);
    return 0xC0000034u; // STATUS_OBJECT_NAME_NOT_FOUND
}

// NtQuerySymbolicLinkObject: `NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle,
// PSTRING LinkTarget, PULONG ReturnedLength OPTIONAL)`. Copies the target
// string into the caller's buffer if MaximumLength allows, per Cxbx-
// Reloaded's EmuKrnlNt.cpp (ReactOS-derived): LinkTarget->Length gets the
// real length, ReturnedLength (if given) always gets MaximumLength.
static uint32_t NTAPI_STDCALL_NtQuerySymbolicLinkObject(uint32_t LinkHandle, XbString *LinkTarget, uint32_t *ReturnedLength) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_NtQuerySymbolicLinkObject(uint32_t LinkHandle, XbString *LinkTarget, uint32_t *ReturnedLength) {
    if (LinkHandle < 0x4000u || LinkHandle - 0x4000u >= (uint32_t) g_symlink_handle_count) {
        fprintf(stderr, "NtQuerySymbolicLinkObject(0x%x) - invalid handle\n", LinkHandle);
        return 0xC0000008u; // STATUS_INVALID_HANDLE
    }
    SymlinkEntry *e = &g_symlinks[g_symlink_handle_target[LinkHandle - 0x4000u]];
    uint32_t len = (uint32_t) strlen(e->target);
    uint32_t status = 0;
    if (len <= LinkTarget->MaximumLength) {
        memcpy(LinkTarget->Buffer, e->target, len);
        LinkTarget->Length = (uint16_t) len;
    } else {
        status = 0xC0000023u; // STATUS_BUFFER_TOO_SMALL
    }
    if (ReturnedLength) *ReturnedLength = LinkTarget->MaximumLength;
    fprintf(stderr, "NtQuerySymbolicLinkObject(0x%x -> \"%s\") -> %s\n",
            LinkHandle, e->target, status == 0 ? "ok" : "STATUS_BUFFER_TOO_SMALL");
    return status;
}

// Standard, stable Win32/NT constants (not Xbox-specific trivia - unchanged
// across every NT release since 3.1).
#define FILE_OPEN           1
#define FILE_CREATE         2
#define FILE_OPEN_IF        3
#define FILE_OVERWRITE      4
#define FILE_OVERWRITE_IF   5
#define FILE_DIRECTORY_FILE 0x00000001

// Matches a bare "PartitionN" or "PartitionN\" path (no further subpath).
// Found live: a disk-cache-slot allocator (FUN_0014bd84) computes a BRAND
// NEW partition NUMBER on a fresh/empty cache table (e.g. 43 on a
// just-initialized 41-slot table) and opens "\Device\Harddisk0\PartitionN\"
// via plain NtOpenFile, not NtCreateFile - meaning real hardware's FATX
// driver is expected to transparently provision that numbered partition on
// first reference, not the title itself. So this one case gets to
// auto-vivify even through NtOpenFile, same spirit as Partition0/1 already
// being pre-created, just generalized to any N instead of two hardcoded ones.
static int is_bare_partition_root(const char *rel_path) {
    if (strncasecmp(rel_path, "partition", 9) != 0) return 0;
    const char *p = rel_path + 9;
    if (!isdigit((unsigned char) *p)) return 0;
    while (isdigit((unsigned char) *p)) p++;
    return (*p == 0) || (p[0] == '\\' && p[1] == 0);
}

// Returns the leading "PartitionN" number if rel_path starts with one
// (regardless of what follows), or -1 otherwise. Used so IOCTLs like
// IOCTL_DISK_GET_PARTITION_INFO can report the real number back.
static int parse_partition_number(const char *rel_path) {
    if (strncasecmp(rel_path, "partition", 9) != 0) return -1;
    const char *p = rel_path + 9;
    if (!isdigit((unsigned char) *p)) return -1;
    return atoi(p);
}

// Shared by NtOpenFile and NtCreateFile. DVD/XDVDFS paths are read-only, so
// CreateDisposition/CreateOptions don't change anything there - there's
// nothing to create or overwrite on the disc. Harddisk0 paths are real now
// (see HDD_ROOT above), so disposition/options matter for those: this is
// where a title's TDATA/UDATA save directories actually get created on
// first use, same as a freshly-formatted Xbox hard drive would.
static uint32_t open_or_create_file(uint32_t *FileHandle, XbObjectAttributes *ObjectAttributes,
                                     XbIoStatusBlock *IoStatusBlock, const char *caller_name,
                                     uint32_t CreateDisposition, uint32_t CreateOptions) {
    if (!ensure_iso_open()) return 0xC0000001u; // STATUS_UNSUCCESSFUL

    XbString *name = ObjectAttributes->ObjectName;
    char path[512];
    xb_string_to_c(name, path, sizeof(path));

    // Resolve any registered symlink (IoCreateSymbolicLink) prefix before
    // anything else - e.g. a game-registered "T:\..." alias needs to become
    // its real target path before the fixed NT-namespace stripping/lookup.
    char resolved[512];
    if (resolve_symlink_prefix(path, resolved, sizeof(resolved))) {
        fprintf(stderr, "%s: resolved symlink \"%s\" -> \"%s\"\n", caller_name, path, resolved);
        snprintf(path, sizeof(path), "%s", resolved);
    }

    static const char *HD_PREFIX = "\\Device\\Harddisk0\\";
    if (strncasecmp(path, HD_PREFIX, strlen(HD_PREFIX)) == 0) {
        ensure_hdd_ready();
        // Real host-backed storage - see HDD_ROOT comment above for why.
        // Strip the device prefix (keeping "partition1\TDATA\..." etc as the
        // relative path) so the whole partition tree lives under HDD_ROOT.
        char host[700];
        harddisk_host_path(path + strlen(HD_PREFIX), host, sizeof(host));

        int want_dir = (CreateOptions & FILE_DIRECTORY_FILE) != 0;
        int may_create = (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OPEN_IF ||
                           CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == 0 /* FILE_SUPERSEDE */);
        int is_root = is_bare_partition_root(path + strlen(HD_PREFIX));
        if (is_root) may_create = 1; // see comment above

        // A bare "PartitionN" is addressed two genuinely different ways by
        // real hardware's single FATX filesystem living inside it: raw
        // sector-level access (used for the format writes seen live - 4KB
        // chunks of FATX boundary markers) AND, for dynamically-provisioned
        // cache partitions specifically, individual files within it (e.g.
        // "PartitionN\index.dat"). This loader can't parse FATX for real, so
        // it represents the raw-sector form as a flat host file and
        // individual files as entries in a host directory - but both used
        // to share the SAME host path (the bare partition name), so
        // whichever form got created first made the other kind of access
        // fail outright (a file can't contain files). Found live: this is
        // exactly why "Z:\index.dat" always came back NOT_FOUND once its
        // partition had been formatted. Fix: the bare-root *file* form now
        // lives at a reserved name inside the partition's own directory,
        // never at the partition's own name, so both forms coexist.
        if (is_root && !want_dir) {
            mkdir_parents(host);
            mkdir(host, 0755);
            size_t hostlen = strlen(host);
            snprintf(host + hostlen, sizeof(host) - hostlen, "/__raw_partition_data__");
        }

        struct stat st;
        int exists = (stat(host, &st) == 0);

        if (g_file_handle_count >= (int) (sizeof(g_file_handles) / sizeof(g_file_handles[0]))) {
            fprintf(stderr, "%s: file handle table full\n", caller_name);
            return 0xC0000001u;
        }

        if (want_dir) {
            if (!exists) {
                if (!may_create) {
                    fprintf(stderr, "%s(\"%s\" -> dir \"%s\") = NOT FOUND\n", caller_name, path, host);
                    IoStatusBlock->Status = 0xC0000034u;
                    return 0xC0000034u;
                }
                mkdir_parents(host);
                mkdir(host, 0755);
            }
            int idx = g_file_handle_count++;
            g_file_handles[idx] = (FileHandleEntry) {
                .used = 1, .device = DEV_HARDDISK, .host_backed = 1, .host_fd = -1, .is_dir = 1, .cursor = 0,
                .partition_number = parse_partition_number(path + strlen(HD_PREFIX))
            };
            *FileHandle = 0x2000u + (uint32_t) idx;
            IoStatusBlock->Status = 0;
            IoStatusBlock->Information = exists ? 1 : 2; // FILE_OPENED : FILE_CREATED
            fprintf(stderr, "%s(\"%s\" -> dir \"%s\") -> handle 0x%x (%s)\n",
                    caller_name, path, host, *FileHandle, exists ? "existing" : "created");
            return 0;
        }

        int flags = O_RDWR;
        if (may_create && CreateDisposition == FILE_OPEN) flags |= O_CREAT; // bare partition root override
        if (CreateDisposition == FILE_CREATE) flags |= O_CREAT | O_EXCL;
        else if (CreateDisposition == FILE_OPEN_IF) flags |= O_CREAT;
        else if (CreateDisposition == FILE_OVERWRITE) flags |= O_TRUNC;
        else if (CreateDisposition == FILE_OVERWRITE_IF) flags |= O_CREAT | O_TRUNC;
        else if (CreateDisposition == 0) flags |= O_CREAT | O_TRUNC; // FILE_SUPERSEDE
        // FILE_OPEN (1, and NtOpenFile's implicit default): no extra flags - must already exist.

        if ((flags & O_CREAT) && !exists) mkdir_parents(host);
        int fd = open(host, flags, 0644);
        if (fd < 0) {
            fprintf(stderr, "%s(\"%s\" -> file \"%s\") = NOT FOUND (%s)\n",
                    caller_name, path, host, strerror(errno));
            IoStatusBlock->Status = 0xC0000034u;
            return 0xC0000034u;
        }
        int idx = g_file_handle_count++;
        g_file_handles[idx] = (FileHandleEntry) {
            .used = 1, .device = DEV_HARDDISK, .host_backed = 1, .host_fd = fd, .is_dir = 0, .cursor = 0,
            .partition_number = parse_partition_number(path + strlen(HD_PREFIX))
        };
        *FileHandle = 0x2000u + (uint32_t) idx;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = exists ? 1 : 2; // FILE_OPENED : FILE_CREATED
        fprintf(stderr, "%s(\"%s\" -> file \"%s\") -> handle 0x%x (%s)\n",
                caller_name, path, host, *FileHandle, exists ? "existing" : "created");
        return 0;
    }

    // DVD/XDVDFS path - unchanged, read-only.
    const char *stripped = xdvdfs_strip_prefix(path);
    XdvdfsEntry e;
    int ok = xdvdfs_lookup(&g_iso, stripped, &e);
    fprintf(stderr, "%s(\"%s\" -> \"%s\") = %s\n", caller_name, path, stripped, ok ? "found" : "NOT FOUND");
    if (!ok) {
        IoStatusBlock->Status = 0xC0000034u; // STATUS_OBJECT_NAME_NOT_FOUND
        return 0xC0000034u;
    }

    if (g_file_handle_count >= (int) (sizeof(g_file_handles) / sizeof(g_file_handles[0]))) {
        fprintf(stderr, "%s: file handle table full\n", caller_name);
        return 0xC0000001u;
    }
    int idx = g_file_handle_count++;
    g_file_handles[idx] = (FileHandleEntry) {
        .used = 1, .device = DEV_DVD, .host_backed = 0, .entry = e, .host_fd = -1,
        .is_dir = e.is_dir, .cursor = 0, .partition_number = -1
    };
    *FileHandle = 0x2000u + (uint32_t) idx;
    IoStatusBlock->Status = 0;
    IoStatusBlock->Information = 1; // FILE_OPENED
    fprintf(stderr, "  -> handle 0x%x (lba=%u size=%u is_dir=%d)\n", *FileHandle, e.lba, e.size, e.is_dir);
    return 0; // STATUS_SUCCESS
}

static uint32_t NTAPI_STDCALL_NtOpenFile(
    uint32_t *FileHandle, uint32_t DesiredAccess, XbObjectAttributes *ObjectAttributes,
    XbIoStatusBlock *IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtOpenFile(
    uint32_t *FileHandle, uint32_t DesiredAccess, XbObjectAttributes *ObjectAttributes,
    XbIoStatusBlock *IoStatusBlock, uint32_t ShareAccess, uint32_t OpenOptions)
{
    (void) DesiredAccess; (void) ShareAccess;
    // NtOpenFile has no CreateDisposition - its real semantics are always
    // "must already exist" (equivalent to FILE_OPEN).
    return open_or_create_file(FileHandle, ObjectAttributes, IoStatusBlock, "NtOpenFile",
                                FILE_OPEN, OpenOptions);
}

static uint32_t NTAPI_STDCALL_NtCreateFile(
    uint32_t *FileHandle, uint32_t DesiredAccess, XbObjectAttributes *ObjectAttributes,
    XbIoStatusBlock *IoStatusBlock, void *AllocationSize, uint32_t FileAttributes,
    uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtCreateFile(
    uint32_t *FileHandle, uint32_t DesiredAccess, XbObjectAttributes *ObjectAttributes,
    XbIoStatusBlock *IoStatusBlock, void *AllocationSize, uint32_t FileAttributes,
    uint32_t ShareAccess, uint32_t CreateDisposition, uint32_t CreateOptions)
{
    (void) DesiredAccess; (void) AllocationSize; (void) FileAttributes; (void) ShareAccess;
    return open_or_create_file(FileHandle, ObjectAttributes, IoStatusBlock, "NtCreateFile",
                                CreateDisposition, CreateOptions);
}

// NtQueryVolumeInformationFile: `NTSTATUS NtQueryVolumeInformationFile(HANDLE FileHandle,
// PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FS_INFORMATION_CLASS FileInformationClass)`.
// FS_INFORMATION_CLASS / FILE_FS_SIZE_INFORMATION / FILE_FS_VOLUME_INFORMATION
// layouts and real reference constants (BytesPerSector=2048, SectorsPerAllocationUnit=1
// for a CD-ROM-class device) pulled from Cxbx-Reloaded's EmuKrnlNt.cpp. Only
// FileFsSizeInformation and FileFsVolumeInformation are implemented - those are
// the two classes with known, simple struct layouts and the ones this project
// has real data for; anything else fails loudly rather than guessing a struct
// layout that hasn't been seen in practice yet.
#define FileFsVolumeInformation    1
#define FileFsSizeInformation      3

typedef struct { int64_t a, b; uint32_t sectorsPerUnit, bytesPerSector; } XbFileFsSizeInformation;
typedef struct { int64_t creationTime; uint32_t serial, labelLen; uint8_t supportsObjects; char label[1]; } XbFileFsVolumeInformation;

static uint32_t NTAPI_STDCALL_NtQueryVolumeInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInformationClass)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtQueryVolumeInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInformationClass)
{
    fprintf(stderr, "NtQueryVolumeInformationFile(handle=0x%x, class=%u, len=%u)\n",
            FileHandle, FileInformationClass, Length);

    if (FileInformationClass == FileFsSizeInformation) {
        if (Length < sizeof(XbFileFsSizeInformation)) return 0xC0000023u; // STATUS_BUFFER_TOO_SMALL
        XbFileFsSizeInformation *info = (XbFileFsSizeInformation *) FileInformation;

        // Found live, not guessed: a real startup check (FUN_00150833) opens
        // \Device\Harddisk0\Partition1\, queries this exact class, and fails
        // (triggering an endless self-relaunch loop) unless
        // SectorsPerAllocationUnit * BytesPerSector == 0x4000 (16KB) - FATX's
        // real cluster size on the Xbox hard drive. Was reporting flat
        // CD-ROM-style values (2048/1) for every handle regardless of which
        // device was actually opened; this device-kind split is the fix.
        DeviceKind dev = DEV_DVD;
        int partition_number = -1;
        if (FileHandle >= 0x2000u && FileHandle - 0x2000u < (uint32_t) g_file_handle_count) {
            dev = g_file_handles[FileHandle - 0x2000u].device;
            partition_number = g_file_handles[FileHandle - 0x2000u].partition_number;
        }

        if (dev == DEV_HARDDISK) {
            // FATX convention, matching Cxbx-Reloaded's own reference values
            // for FILE_DEVICE_DISK2 (src/core/kernel/exports/EmuKrnlNt.cpp):
            // 512 bytes/sector, 32 sectors/unit = 16384 bytes/unit. This is
            // correct for Partition1 (the fixed TDATA/UDATA save partition -
            // confirmed via FUN_00150833's own check, which requires exactly
            // 0x4000 for it) but NOT universal: a gdb trace of a second,
            // separate caller (FUN_0014bfcf, verifying a freshly-auto-
            // provisioned disk-cache partition like Partition43) showed it
            // demanding 0x10000 (64KB) instead - real hardware's cache
            // partitions use a larger FATX cluster size than the main save
            // partition. Any partition other than 1 is one of these
            // dynamically-provisioned cache partitions (see FUN_0014bd84's
            // numbering, which starts at 3), so report 64KB for those.
            int is_cache_partition = (partition_number != 1);
            info->bytesPerSector = 512;
            info->sectorsPerUnit = is_cache_partition ? 128 : 32; // 128*512=0x10000, 32*512=0x4000
            info->a = info->b = 8 * 1024 * 1024 / (info->sectorsPerUnit * info->bytesPerSector); // 8MB placeholder partition worth of units
        } else {
            // Real values for our actual disc (not Cxbx's DVD-9 assumption -
            // we know our exact ISO size), CD-ROM-class device.
            uint64_t total_sectors = 2709585920ULL / 2048; // real ISO size, see Xbox Ghoulies Linux Port.md
            info->bytesPerSector = 2048;
            info->sectorsPerUnit = 1;
            info->a = info->b = (int64_t) total_sectors; // AvailableAllocationUnits: read-only disc, report all "available"
        }
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbFileFsSizeInformation);
        return 0;
    }

    if (FileInformationClass == FileFsVolumeInformation) {
        static const char label[] = "GHOULIES";
        uint32_t need = sizeof(XbFileFsVolumeInformation) - 1 + sizeof(label) - 1;
        if (Length < need) return 0xC0000023u; // STATUS_BUFFER_TOO_SMALL
        XbFileFsVolumeInformation *info = (XbFileFsVolumeInformation *) FileInformation;
        info->creationTime = 0;
        info->serial = 0x12345678u; // arbitrary but stable - nothing observed depends on a specific value yet
        info->labelLen = sizeof(label) - 1;
        info->supportsObjects = 0;
        memcpy(info->label, label, sizeof(label) - 1);
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = need;
        return 0;
    }

    fprintf(stderr, "  unhandled FileInformationClass %u - no struct layout implemented yet\n",
            FileInformationClass);
    return 0xC0000003u; // STATUS_INVALID_INFO_CLASS (close enough for an unimplemented class)
}

// NtQueryInformationFile: `NTSTATUS NtQueryInformationFile(HANDLE FileHandle,
// PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
// FILE_INFORMATION_CLASS FileInfo)`. Struct layouts from Cxbx-Reloaded's
// types.h. Computes real size/directory-ness from whichever backing the
// handle actually has (host fd/dir for Harddisk0, XdvdfsEntry for the DVD) -
// not hardcoded, since both are genuinely in use now.
#define FileBasicInformation       4
#define FileStandardInformation    5
#define FilePositionInformation    14
#define FileNetworkOpenInformation 34

typedef struct { int64_t a, b, c, d; uint32_t attrs; } XbFileBasicInformation;
typedef struct { int64_t allocSize, endOfFile; uint32_t links; uint8_t deletePending, isDir; } XbFileStandardInformation;
typedef struct { int64_t pos; } XbFilePositionInformation;
typedef struct { int64_t creationTime, lastAccessTime, lastWriteTime, changeTime, allocSize, endOfFile; uint32_t attrs; } XbFileNetworkOpenInformation;

#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_NORMAL    0x80

static uint32_t NTAPI_STDCALL_NtQueryInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInfo)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtQueryInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInfo)
{
    fprintf(stderr, "NtQueryInformationFile(handle=0x%x, class=%u, len=%u)\n", FileHandle, FileInfo, Length);

    if (FileHandle < 0x2000u || FileHandle - 0x2000u >= (uint32_t) g_file_handle_count) {
        return 0xC0000008u; // STATUS_INVALID_HANDLE
    }
    FileHandleEntry *fh = &g_file_handles[FileHandle - 0x2000u];

    int64_t size = 0;
    int is_dir = fh->is_dir;
    if (fh->host_backed) {
        if (!is_dir && fh->host_fd >= 0) {
            struct stat st;
            if (fstat(fh->host_fd, &st) == 0) size = st.st_size;
        }
    } else {
        size = fh->entry.size;
    }

    if (FileInfo == FileStandardInformation) {
        if (Length < sizeof(XbFileStandardInformation)) return 0xC0000023u;
        XbFileStandardInformation *info = (XbFileStandardInformation *) FileInformation;
        info->allocSize = size;
        info->endOfFile = size;
        info->links = 1;
        info->deletePending = 0;
        info->isDir = is_dir ? 1 : 0;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbFileStandardInformation);
        return 0;
    }

    if (FileInfo == FileBasicInformation) {
        if (Length < sizeof(XbFileBasicInformation)) return 0xC0000023u;
        XbFileBasicInformation *info = (XbFileBasicInformation *) FileInformation;
        info->a = info->b = info->c = info->d = 0; // timestamps: not modeled, zeroed rather than faked
        info->attrs = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbFileBasicInformation);
        return 0;
    }

    if (FileInfo == FilePositionInformation) {
        if (Length < sizeof(XbFilePositionInformation)) return 0xC0000023u;
        ((XbFilePositionInformation *) FileInformation)->pos = fh->cursor;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbFilePositionInformation);
        return 0;
    }

    if (FileInfo == FileNetworkOpenInformation) {
        if (Length < sizeof(XbFileNetworkOpenInformation)) return 0xC0000023u;
        XbFileNetworkOpenInformation *info = (XbFileNetworkOpenInformation *) FileInformation;
        info->creationTime = info->lastAccessTime = info->lastWriteTime = info->changeTime = 0; // not modeled
        info->allocSize = info->endOfFile = size;
        info->attrs = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbFileNetworkOpenInformation);
        return 0;
    }

    fprintf(stderr, "  unhandled FileInfo class %u - no struct layout implemented yet\n", FileInfo);
    return 0xC0000003u; // STATUS_INVALID_INFO_CLASS
}

// NtSetInformationFile: `NTSTATUS NtSetInformationFile(HANDLE FileHandle,
// PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
// FILE_INFORMATION_CLASS FileInfo)`. Struct layouts match the Query-side
// ones already defined above (same real NT classes, read vs. write of the
// same data) - only implementing the classes actually seen in practice.
#define FileDispositionInformation 13
#define FileEndOfFileInformation   20

typedef struct { uint8_t deleteFile; } XbFileDispositionInformation;
typedef struct { int64_t endOfFile; } XbFileEndOfFileInformation;

static uint32_t NTAPI_STDCALL_NtSetInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInfo)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtSetInformationFile(
    uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *FileInformation,
    uint32_t Length, uint32_t FileInfo)
{
    fprintf(stderr, "NtSetInformationFile(handle=0x%x, class=%u, len=%u)\n", FileHandle, FileInfo, Length);

    if (FileHandle < 0x2000u || FileHandle - 0x2000u >= (uint32_t) g_file_handle_count) {
        return 0xC0000008u; // STATUS_INVALID_HANDLE
    }
    FileHandleEntry *fh = &g_file_handles[FileHandle - 0x2000u];

    if (FileInfo == FilePositionInformation) {
        if (Length < sizeof(XbFilePositionInformation)) return 0xC0000023u;
        fh->cursor = (uint32_t) ((XbFilePositionInformation *) FileInformation)->pos;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = 0;
        return 0;
    }

    if (FileInfo == FileEndOfFileInformation) {
        if (Length < sizeof(XbFileEndOfFileInformation)) return 0xC0000023u;
        int64_t new_size = ((XbFileEndOfFileInformation *) FileInformation)->endOfFile;
        if (fh->host_backed && !fh->is_dir && fh->host_fd >= 0) {
            if (ftruncate(fh->host_fd, (off_t) new_size) != 0) {
                fprintf(stderr, "  ftruncate failed: %s\n", strerror(errno));
                return 0xC0000001u;
            }
        }
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = 0;
        return 0;
    }

    if (FileInfo == FileDispositionInformation) {
        if (Length < sizeof(XbFileDispositionInformation)) return 0xC0000023u;
        // Delete-on-close: real NT defers the actual unlink until the
        // handle closes, but nothing here depends on that exact timing
        // (no other open handle on the same file is kept around), so
        // deleting immediately when asked is behaviorally equivalent and
        // simpler than tracking a pending-delete flag through NtClose.
        if (((XbFileDispositionInformation *) FileInformation)->deleteFile && fh->host_backed) {
            char path[700];
            // /proc/self/fd is the simplest reliable way to recover a path
            // from an already-open fd without this loader tracking the
            // original host path on every handle just for this one case.
            char procpath[64];
            snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fh->host_fd);
            ssize_t n = readlink(procpath, path, sizeof(path) - 1);
            if (n > 0) {
                path[n] = 0;
                if (fh->is_dir) rmdir(path); else unlink(path);
            }
        }
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = 0;
        return 0;
    }

    fprintf(stderr, "  unhandled FileInfo class %u - no struct layout implemented yet\n", FileInfo);
    return 0xC0000003u; // STATUS_INVALID_INFO_CLASS
}

// NtReadFile / NtWriteFile: `NTSTATUS Nt{Read,Write}File(HANDLE FileHandle, HANDLE Event,
// PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
// PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset OPTIONAL)`. Real I/O
// for both backings: pread/pwrite for Harddisk0 (explicit offset, so our own
// tracked cursor never drifts from the OS's independent file-position idea),
// xdvdfs_read for the read-only DVD. Writing to a DVD handle correctly fails
// - there's nothing to write to on a real disc either. Event/ApcRoutine/
// ApcContext (async I/O) aren't modeled - every call here completes
// synchronously, which every caller so far has been fine with.
static uint32_t do_file_io(uint32_t FileHandle, XbIoStatusBlock *IoStatusBlock, void *Buffer,
                           uint32_t Length, int64_t *ByteOffset, int is_write, const char *caller_name) {
    if (FileHandle < 0x2000u || FileHandle - 0x2000u >= (uint32_t) g_file_handle_count) {
        return 0xC0000008u; // STATUS_INVALID_HANDLE
    }
    FileHandleEntry *fh = &g_file_handles[FileHandle - 0x2000u];
    uint64_t offset = ByteOffset ? (uint64_t) *ByteOffset : fh->cursor;
    uint32_t done = 0;

    if (fh->host_backed) {
        if (fh->is_dir || fh->host_fd < 0) return 0xC0000001u;
        ssize_t got = is_write ? pwrite(fh->host_fd, Buffer, Length, (off_t) offset)
                                : pread(fh->host_fd, Buffer, Length, (off_t) offset);
        if (got < 0) {
            fprintf(stderr, "%s: %s failed: %s\n", caller_name, is_write ? "pwrite" : "pread", strerror(errno));
            return 0xC0000001u;
        }
        done = (uint32_t) got;
    } else {
        if (is_write) {
            fprintf(stderr, "%s: refusing write to read-only DVD handle 0x%x\n", caller_name, FileHandle);
            return 0xC0000022u; // STATUS_ACCESS_DENIED
        }
        int64_t got = xdvdfs_read(&g_iso, &fh->entry, (uint32_t) offset, Buffer, Length);
        if (got < 0) return 0xC0000001u;
        done = (uint32_t) got;
    }

    fh->cursor = (uint32_t) (offset + done);
    IoStatusBlock->Status = 0;
    IoStatusBlock->Information = done;
    fprintf(stderr, "%s(handle=0x%x, offset=%llu, len=%u) -> %u bytes\n",
            caller_name, FileHandle, (unsigned long long) offset, Length, done);
    return 0;
}

static uint32_t NTAPI_STDCALL_NtReadFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, void *Buffer, uint32_t Length, int64_t *ByteOffset)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtReadFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, void *Buffer, uint32_t Length, int64_t *ByteOffset)
{
    (void) Event; (void) ApcRoutine; (void) ApcContext;
    return do_file_io(FileHandle, IoStatusBlock, Buffer, Length, ByteOffset, 0, "NtReadFile");
}

static uint32_t NTAPI_STDCALL_NtWriteFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, void *Buffer, uint32_t Length, int64_t *ByteOffset)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtWriteFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, void *Buffer, uint32_t Length, int64_t *ByteOffset)
{
    (void) Event; (void) ApcRoutine; (void) ApcContext;
    return do_file_io(FileHandle, IoStatusBlock, Buffer, Length, ByteOffset, 1, "NtWriteFile");
}

static uint32_t NTAPI_STDCALL_NtClose(uint32_t Handle) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_NtClose(uint32_t Handle) {
    if (Handle >= 0x2000u && Handle - 0x2000u < (uint32_t) g_file_handle_count) {
        FileHandleEntry *fh = &g_file_handles[Handle - 0x2000u];
        if (fh->host_backed && fh->host_fd >= 0) close(fh->host_fd);
        fh->used = 0;
        fprintf(stderr, "NtClose(0x%x) - closed file handle\n", Handle);
        return 0;
    }
    fprintf(stderr, "NtClose(0x%x) - no-op (not a tracked file handle)\n", Handle);
    return 0; // STATUS_SUCCESS
}

// NtQueryFullAttributesFile: `NTSTATUS NtQueryFullAttributesFile(POBJECT_ATTRIBUTES
// ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation)`. Stats a
// file/dir by path without keeping a handle open around it - real hardware
// opens briefly internally and closes again, so this does the same via
// open_or_create_file (reusing its symlink/Harddisk0/DVD path resolution),
// trying a file-open first and falling back to a directory-open, then fills
// the same struct layout NtQueryInformationFile's FileNetworkOpenInformation
// case uses.
static uint32_t NTAPI_STDCALL_NtQueryFullAttributesFile(XbObjectAttributes *ObjectAttributes, XbFileNetworkOpenInformation *FileInformation) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_NtQueryFullAttributesFile(XbObjectAttributes *ObjectAttributes, XbFileNetworkOpenInformation *FileInformation) {
    uint32_t handle;
    XbIoStatusBlock iosb;
    uint32_t status = open_or_create_file(&handle, ObjectAttributes, &iosb, "NtQueryFullAttributesFile", FILE_OPEN, 0);
    if (status != 0) {
        status = open_or_create_file(&handle, ObjectAttributes, &iosb, "NtQueryFullAttributesFile", FILE_OPEN, FILE_DIRECTORY_FILE);
    }
    if (status != 0) return status;

    FileHandleEntry *fh = &g_file_handles[handle - 0x2000u];
    int64_t size = 0;
    if (fh->host_backed) {
        if (!fh->is_dir && fh->host_fd >= 0) {
            struct stat st;
            if (fstat(fh->host_fd, &st) == 0) size = st.st_size;
        }
    } else {
        size = fh->entry.size;
    }
    FileInformation->creationTime = FileInformation->lastAccessTime = FileInformation->lastWriteTime = FileInformation->changeTime = 0;
    FileInformation->allocSize = FileInformation->endOfFile = size;
    FileInformation->attrs = fh->is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;

    fprintf(stderr, "NtQueryFullAttributesFile -> size=%lld attrs=0x%x\n", (long long) size, FileInformation->attrs);
    NTAPI_STDCALL_NtClose(handle);
    return 0;
}

// ----------------------------------------------------------------------
// Rtl*CriticalSection family. Deliberately does NOT interpret the guest's
// own RTL_CRITICAL_SECTION struct bytes at all (we don't know Xbox's exact
// layout for it, and don't need to) - instead keys a side-table purely off
// the guest pointer's address and backs every entry with a real recursive
// pthread_mutex_t. This also means RtlEnterCriticalSection works correctly
// even for a critical section the game never explicitly Initialized (e.g. a
// statically-zeroed one) - lazily creates on first use. Same approach Wine
// and Cxbx-Reloaded both use for guest synchronization objects: never trust
// the guest struct's internal bytes, always redirect to a host-native one.
typedef struct { void *key; pthread_mutex_t *mutex; } CsEntry;
static CsEntry g_cs_table[1024];
static int g_cs_count = 0;
static pthread_mutex_t g_cs_table_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t *cs_get_or_create(void *key) {
    pthread_mutex_lock(&g_cs_table_lock);
    for (int i = 0; i < g_cs_count; i++) {
        if (g_cs_table[i].key == key) {
            pthread_mutex_t *m = g_cs_table[i].mutex;
            pthread_mutex_unlock(&g_cs_table_lock);
            return m;
        }
    }
    if (g_cs_count >= (int) (sizeof(g_cs_table) / sizeof(g_cs_table[0]))) {
        fprintf(stderr, "cs_get_or_create: table full (%d entries) - raise the size\n", g_cs_count);
        pthread_mutex_unlock(&g_cs_table_lock);
        _exit(1);
    }
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); // NT critical sections are reentrant
    pthread_mutex_t *m = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(m, &attr);
    g_cs_table[g_cs_count].key = key;
    g_cs_table[g_cs_count].mutex = m;
    g_cs_count++;
    pthread_mutex_unlock(&g_cs_table_lock);
    return m;
}

static uint32_t NTAPI_STDCALL_RtlInitializeCriticalSection(void *cs) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlInitializeCriticalSection(void *cs) {
    cs_get_or_create(cs);
    return 0;
}

static uint32_t NTAPI_STDCALL_RtlEnterCriticalSection(void *cs) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlEnterCriticalSection(void *cs) {
    pthread_mutex_lock(cs_get_or_create(cs));
    return 0;
}

static uint32_t NTAPI_STDCALL_RtlLeaveCriticalSection(void *cs) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlLeaveCriticalSection(void *cs) {
    pthread_mutex_unlock(cs_get_or_create(cs));
    return 0;
}

static uint32_t NTAPI_STDCALL_RtlTryEnterCriticalSection(void *cs) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlTryEnterCriticalSection(void *cs) {
    return pthread_mutex_trylock(cs_get_or_create(cs)) == 0 ? 1 : 0; // BOOLEAN: nonzero = acquired
}

// HalRegisterShutdownNotification: per the real signature (Cxbx-Reloaded's
// src/core/kernel/common/hal.h), the game owns a HAL_SHUTDOWN_REGISTRATION
// struct (NotificationRoutine fn ptr, Priority, LIST_ENTRY) and just asks the
// kernel to add/remove it from the shutdown-notification list. There's no
// real shutdown path in this harness to ever walk that list and invoke the
// callback, so this genuinely just needs to accept-and-remember the
// registration (or forget it, on unregister) rather than silently no-op -
// implemented as real bookkeeping now so a future real shutdown path has
// something correct to call into, not something to redo.
typedef struct { void *registration; int active; } ShutdownReg;
static ShutdownReg g_shutdown_regs[32];
static int g_shutdown_reg_count = 0;

static void NTAPI_STDCALL_HalRegisterShutdownNotification(void *ShutdownRegistration, uint32_t Register) __attribute__((stdcall));
static void NTAPI_STDCALL_HalRegisterShutdownNotification(void *ShutdownRegistration, uint32_t Register) {
    for (int i = 0; i < g_shutdown_reg_count; i++) {
        if (g_shutdown_regs[i].registration == ShutdownRegistration) {
            g_shutdown_regs[i].active = Register ? 1 : 0;
            fprintf(stderr, "HalRegisterShutdownNotification(%p, %u) - updated existing registration\n",
                    ShutdownRegistration, Register);
            return;
        }
    }
    if (Register && g_shutdown_reg_count < (int) (sizeof(g_shutdown_regs) / sizeof(g_shutdown_regs[0]))) {
        g_shutdown_regs[g_shutdown_reg_count].registration = ShutdownRegistration;
        g_shutdown_regs[g_shutdown_reg_count].active = 1;
        g_shutdown_reg_count++;
    }
    fprintf(stderr, "HalRegisterShutdownNotification(%p, %u) - new registration (%d total)\n",
            ShutdownRegistration, Register, g_shutdown_reg_count);
}

// KeInitializeDpc: per the real signature (Cxbx-Reloaded's kernel.h),
// `void KeInitializeDpc(KDPC *Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)`.
// Same architecture as the critical-section table: the guest's KDPC pointer
// is treated as an opaque key, never interpreted - we store what a later
// KeInsertQueueDpc would need (routine + context) in our own side-table
// rather than writing into the guest struct. KeInsertQueueDpc itself isn't
// implemented yet (not hit by execution so far); this just records enough
// for that to be a real lookup, not a redo, when it is.
typedef struct { void *dpc; void *routine; void *context; } DpcEntry;
static DpcEntry g_dpc_table[256];
static int g_dpc_count = 0;

static void NTAPI_STDCALL_KeInitializeDpc(void *Dpc, void *DeferredRoutine, void *DeferredContext) __attribute__((stdcall));
static void NTAPI_STDCALL_KeInitializeDpc(void *Dpc, void *DeferredRoutine, void *DeferredContext) {
    for (int i = 0; i < g_dpc_count; i++) {
        if (g_dpc_table[i].dpc == Dpc) {
            g_dpc_table[i].routine = DeferredRoutine;
            g_dpc_table[i].context = DeferredContext;
            fprintf(stderr, "KeInitializeDpc(%p, routine=%p, ctx=%p) - updated existing\n",
                    Dpc, DeferredRoutine, DeferredContext);
            return;
        }
    }
    if (g_dpc_count < (int) (sizeof(g_dpc_table) / sizeof(g_dpc_table[0]))) {
        g_dpc_table[g_dpc_count++] = (DpcEntry) { Dpc, DeferredRoutine, DeferredContext };
    }
    fprintf(stderr, "KeInitializeDpc(%p, routine=%p, ctx=%p) - new (%d total)\n",
            Dpc, DeferredRoutine, DeferredContext, g_dpc_count);
}

// KeInitializeTimerEx: `void KeInitializeTimerEx(PKTIMER Timer, TIMER_TYPE Type)`.
// Same opaque-key side-table approach as the DPC table above - just records
// enough (type) that a later KeSetTimer/KeSetTimerEx implementation has
// something real to build on.
typedef struct { void *timer; uint32_t type; } TimerEntry;
static TimerEntry g_timer_table[256];
static int g_timer_count = 0;

static void NTAPI_STDCALL_KeInitializeTimerEx(void *Timer, uint32_t Type) __attribute__((stdcall));
static void NTAPI_STDCALL_KeInitializeTimerEx(void *Timer, uint32_t Type) {
    for (int i = 0; i < g_timer_count; i++) {
        if (g_timer_table[i].timer == Timer) {
            g_timer_table[i].type = Type;
            fprintf(stderr, "KeInitializeTimerEx(%p, type=%u) - updated existing\n", Timer, Type);
            return;
        }
    }
    if (g_timer_count < (int) (sizeof(g_timer_table) / sizeof(g_timer_table[0]))) {
        g_timer_table[g_timer_count++] = (TimerEntry) { Timer, Type };
    }
    fprintf(stderr, "KeInitializeTimerEx(%p, type=%u) - new (%d total)\n", Timer, Type, g_timer_count);
}

// HalGetInterruptVector / KeInitializeInterrupt / KeConnectInterrupt: the
// real device-interrupt-init cluster (seen live, called together from the
// NV2A graphics-init thread once its MMIO pokes stopped segfaulting).
// HalGetInterruptVector is pure math (ReactOS-derived constants, confirmed
// from Cxbx-Reloaded's CxbxKrnl.h: IRQ_BASE=0x30, MAX_BUS_INTERRUPT_LEVEL=27
// - these are fixed x86 PIC/IRQ conventions, not guesses). KeInitializeInterrupt/
// KeConnectInterrupt use the same opaque-guest-pointer side-table pattern as
// the DPC/timer tables above - the guest's KINTERRUPT struct layout is never
// interpreted. There's no real interrupt source in this harness (no actual
// async hardware raising IRQs), so "connecting" an interrupt is pure
// bookkeeping - correct behavior here, not a shortcut, since nothing will
// ever fire it without a real device behind it.
#define IRQ_BASE 0x30
#define MAX_BUS_INTERRUPT_LEVEL 27

static uint32_t NTAPI_STDCALL_HalGetInterruptVector(uint32_t BusInterruptLevel, uint32_t *Irql) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_HalGetInterruptVector(uint32_t BusInterruptLevel, uint32_t *Irql) {
    uint32_t vector = 0;
    if (BusInterruptLevel <= MAX_BUS_INTERRUPT_LEVEL) {
        vector = BusInterruptLevel + IRQ_BASE;
        if (Irql) *Irql = MAX_BUS_INTERRUPT_LEVEL - BusInterruptLevel;
    }
    fprintf(stderr, "HalGetInterruptVector(irq=%u) -> vector=0x%x\n", BusInterruptLevel, vector);
    return vector;
}

typedef struct { void *interrupt; void *service_routine; void *service_context; uint32_t bus_irq; int connected; } InterruptEntry;
static InterruptEntry g_interrupt_table[64];
static int g_interrupt_count = 0;

static InterruptEntry *interrupt_get_or_create(void *key) {
    for (int i = 0; i < g_interrupt_count; i++) {
        if (g_interrupt_table[i].interrupt == key) return &g_interrupt_table[i];
    }
    if (g_interrupt_count >= (int) (sizeof(g_interrupt_table) / sizeof(g_interrupt_table[0]))) return NULL;
    g_interrupt_table[g_interrupt_count] = (InterruptEntry) { .interrupt = key };
    return &g_interrupt_table[g_interrupt_count++];
}

static void NTAPI_STDCALL_KeInitializeInterrupt(
    void *Interrupt, void *ServiceRoutine, void *ServiceContext, uint32_t Vector,
    uint32_t Irql, uint32_t InterruptMode, uint32_t ShareVector) __attribute__((stdcall));
static void NTAPI_STDCALL_KeInitializeInterrupt(
    void *Interrupt, void *ServiceRoutine, void *ServiceContext, uint32_t Vector,
    uint32_t Irql, uint32_t InterruptMode, uint32_t ShareVector)
{
    (void) Irql; (void) InterruptMode; (void) ShareVector;
    InterruptEntry *e = interrupt_get_or_create(Interrupt);
    if (!e) {
        fprintf(stderr, "KeInitializeInterrupt(%p): table full, dropping\n", Interrupt);
        return;
    }
    e->service_routine = ServiceRoutine;
    e->service_context = ServiceContext;
    e->bus_irq = Vector - IRQ_BASE;
    e->connected = 0;
    fprintf(stderr, "KeInitializeInterrupt(%p, routine=%p, vector=0x%x -> irq=%u)\n",
            Interrupt, ServiceRoutine, Vector, e->bus_irq);
}

// HalReadWritePCISpace: `void HalReadWritePCISpace(ULONG BusNumber, ULONG SlotNumber,
// ULONG RegisterNumber, PVOID Buffer, ULONG Length, BOOLEAN WritePCISpace)`.
// Real hardware does this via CF8h/CFCh port I/O, which the io-trap handler
// (see install_io_trap_handler below) would silently absorb/all-1s anyway
// since there's no real PCI bus - implementing this directly instead gives a
// read-modify-write sequence (seen live: a register gets read, has bits
// ORed in, then written back) somewhere real to round-trip through, rather
// than every read coming back as the trap handler's generic "nothing here"
// value regardless of what was last written.
typedef struct { uint32_t bus, slot, reg; uint8_t data[4]; } PciCfgEntry;
static PciCfgEntry g_pci_cfg[64];
static int g_pci_cfg_count = 0;

static PciCfgEntry *pci_cfg_get_or_create(uint32_t bus, uint32_t slot, uint32_t reg) {
    for (int i = 0; i < g_pci_cfg_count; i++) {
        if (g_pci_cfg[i].bus == bus && g_pci_cfg[i].slot == slot && g_pci_cfg[i].reg == reg) return &g_pci_cfg[i];
    }
    if (g_pci_cfg_count >= (int) (sizeof(g_pci_cfg) / sizeof(g_pci_cfg[0]))) return NULL;
    PciCfgEntry *e = &g_pci_cfg[g_pci_cfg_count++];
    e->bus = bus; e->slot = slot; e->reg = reg;
    memset(e->data, 0, sizeof(e->data));
    return e;
}

static void NTAPI_STDCALL_HalReadWritePCISpace(
    uint32_t BusNumber, uint32_t SlotNumber, uint32_t RegisterNumber,
    void *Buffer, uint32_t Length, uint32_t WritePCISpace) __attribute__((stdcall));
static void NTAPI_STDCALL_HalReadWritePCISpace(
    uint32_t BusNumber, uint32_t SlotNumber, uint32_t RegisterNumber,
    void *Buffer, uint32_t Length, uint32_t WritePCISpace)
{
    if (Length > 4) Length = 4;
    PciCfgEntry *e = pci_cfg_get_or_create(BusNumber, SlotNumber, RegisterNumber);
    if (!e) {
        fprintf(stderr, "HalReadWritePCISpace: table full, dropping\n");
        return;
    }
    if (WritePCISpace) memcpy(e->data, Buffer, Length);
    else memcpy(Buffer, e->data, Length);
    fprintf(stderr, "HalReadWritePCISpace(bus=%u, slot=0x%x, reg=0x%x, len=%u, write=%u)\n",
            BusNumber, SlotNumber, RegisterNumber, Length, WritePCISpace);
}

static uint32_t NTAPI_STDCALL_KeConnectInterrupt(void *InterruptObject) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_KeConnectInterrupt(void *InterruptObject) {
    InterruptEntry *e = interrupt_get_or_create(InterruptObject);
    if (e && !e->connected) {
        e->connected = 1;
        fprintf(stderr, "KeConnectInterrupt(%p) -> connected (irq=%u)\n", InterruptObject, e->bus_irq);
        return 1; // TRUE
    }
    fprintf(stderr, "KeConnectInterrupt(%p) -> already connected or unknown\n", InterruptObject);
    return 0; // FALSE
}

// ExQueryNonVolatileSetting: `NTSTATUS ExQueryNonVolatileSetting(DWORD ValueIndex,
// DWORD *Type, PVOID Value, SIZE_T ValueLength, PSIZE_T ResultLength OPTIONAL)`.
// Reads a value out of the console's EEPROM/NVRAM. Real values per Cxbx-Reloaded's
// XC_VALUE_INDEX enum (src/core/kernel/common/types.h). Unlike the bookkeeping
// functions above, this one hands the game real data it may act on, so instead
// of a generic side-table this is a small fixed table of sane defaults for a
// USA retail disc (NTSC/Region 1, English, no special video/audio flags) -
// anything not in the table fails loudly rather than returning made-up bytes,
// same "fail informatively, don't lie" rule as everything else in this file.
#define XC_TIMEZONE_BIAS        0x00
#define XC_LANGUAGE             0x07
#define XC_VIDEO                0x08
#define XC_AUDIO                0x09
#define XC_DVD_REGION           0x12
#define XC_FACTORY_AV_REGION    0x103
#define XC_FACTORY_GAME_REGION  0x104
#define REG_DWORD_TYPE          4

static uint32_t NTAPI_STDCALL_ExQueryNonVolatileSetting(
    uint32_t ValueIndex, uint32_t *Type, void *Value, uint32_t ValueLength, uint32_t *ResultLength)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_ExQueryNonVolatileSetting(
    uint32_t ValueIndex, uint32_t *Type, void *Value, uint32_t ValueLength, uint32_t *ResultLength)
{
    uint32_t dword_val;
    switch (ValueIndex) {
        case XC_TIMEZONE_BIAS:       dword_val = 0; break;             // UTC
        case XC_LANGUAGE:            dword_val = 1; break;             // English
        case XC_VIDEO:               dword_val = 0; break;             // no special flags (safe 4:3 NTSC default)
        case XC_AUDIO:               dword_val = 0; break;             // stereo
        case XC_DVD_REGION:          dword_val = 1; break;             // Region 1 (matches our USA disc)
        case XC_FACTORY_AV_REGION:   dword_val = 1; break;             // NTSC
        case XC_FACTORY_GAME_REGION: dword_val = 1; break;             // NA (matches our USA disc)
        default:
            fprintf(stderr,
                "ExQueryNonVolatileSetting: unhandled ValueIndex 0x%x - no default for this one yet\n",
                ValueIndex);
            return 0xC0000001u; // STATUS_UNSUCCESSFUL
    }

    if (ResultLength) *ResultLength = sizeof(uint32_t);
    if (ValueLength < sizeof(uint32_t)) return 0xC0000023u; // STATUS_BUFFER_TOO_SMALL
    if (Type) *Type = REG_DWORD_TYPE;
    memcpy(Value, &dword_val, sizeof(uint32_t));
    fprintf(stderr, "ExQueryNonVolatileSetting(0x%x) = %u\n", ValueIndex, dword_val);
    return 0; // STATUS_SUCCESS
}

// RtlNtStatusToDosError: `ULONG RtlNtStatusToDosError(NTSTATUS Status)`. A
// handful of real, verified NTSTATUS->Win32-error mappings (the ones our own
// functions above can actually produce, plus a few universally common ones),
// falling back to ERROR_MR_MID_NOT_FOUND (317) for anything unmapped - that's
// not a cop-out, it's genuinely what the real function does for a status
// outside its table.
static uint32_t NTAPI_STDCALL_RtlNtStatusToDosError(uint32_t Status) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlNtStatusToDosError(uint32_t Status) {
    uint32_t dos_err;
    switch (Status) {
        case 0x00000000u: dos_err = 0;   break; // STATUS_SUCCESS -> ERROR_SUCCESS
        case 0xC0000001u: dos_err = 31;  break; // STATUS_UNSUCCESSFUL -> ERROR_GEN_FAILURE
        case 0xC0000023u: dos_err = 122; break; // STATUS_BUFFER_TOO_SMALL -> ERROR_INSUFFICIENT_BUFFER
        case 0xC0000034u: dos_err = 2;   break; // STATUS_OBJECT_NAME_NOT_FOUND -> ERROR_FILE_NOT_FOUND
        case 0xC0000022u: dos_err = 5;   break; // STATUS_ACCESS_DENIED -> ERROR_ACCESS_DENIED
        case 0xC000000Du: dos_err = 87;  break; // STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER
        case 0xC0000017u: dos_err = 8;   break; // STATUS_NO_MEMORY -> ERROR_NOT_ENOUGH_MEMORY
        default:
            fprintf(stderr, "RtlNtStatusToDosError(0x%x) - no specific mapping, "
                    "using genuine NT fallback ERROR_MR_MID_NOT_FOUND\n", Status);
            dos_err = 317; break; // ERROR_MR_MID_NOT_FOUND - real NT's own fallback value
    }
    return dos_err;
}

// KeSetTimer: `BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc OPTIONAL)`.
// DueTime is in 100ns units; negative = relative delay from now (the common
// case for a one-shot init-time timer), non-negative = absolute time, which
// isn't meaningfully convertible without modeling the Xbox's wall clock -
// treated as "fire immediately," a documented simplification, not silently
// wrong. When a Dpc is supplied, looks it up in the table KeInitializeDpc
// already populated and spawns a short-lived thread that sleeps for the
// delay then calls the real DeferredRoutine(Dpc, DeferredContext, NULL, NULL)
// with its own fresh FS/TIB, same as any other Xbox-code-running thread.
typedef struct { void *dpc_key; void *routine; void *context; double delay_sec; } TimerFireArgs;

static void *timer_fire_thread(void *arg) {
    TimerFireArgs *a = (TimerFireArgs *) arg;
    if (a->delay_sec > 0) {
        struct timespec ts = { (time_t) a->delay_sec, (long) ((a->delay_sec - (long) a->delay_sec) * 1e9) };
        nanosleep(&ts, NULL);
    }
    setup_fs_tib_for_this_thread();
    install_altstack_for_this_thread();
    fprintf(stderr, "[timer 0x%lx] firing DPC routine=%p ctx=%p\n",
            (unsigned long) pthread_self(), a->routine, a->context);
    if (a->routine) {
        typedef void (__attribute__((stdcall)) *DpcRoutine)(void *, void *, void *, void *);
        ((DpcRoutine) a->routine)(a->dpc_key, a->context, NULL, NULL);
    }
    free(a);
    return NULL;
}

static uint32_t NTAPI_STDCALL_KeSetTimer(void *Timer, int64_t DueTime, void *Dpc) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_KeSetTimer(void *Timer, int64_t DueTime, void *Dpc) {
    double delay_sec = 0.0;
    if (DueTime < 0) {
        delay_sec = (double) (-DueTime) / 1.0e7; // 100ns units -> seconds
    } else {
        fprintf(stderr, "KeSetTimer: absolute DueTime (%lld) not modeled, firing immediately\n",
                (long long) DueTime);
    }

    void *routine = NULL, *context = NULL;
    if (Dpc) {
        for (int i = 0; i < g_dpc_count; i++) {
            if (g_dpc_table[i].dpc == Dpc) {
                routine = g_dpc_table[i].routine;
                context = g_dpc_table[i].context;
                break;
            }
        }
        if (!routine) {
            fprintf(stderr, "KeSetTimer: Dpc %p was never seen by KeInitializeDpc - nothing to fire\n", Dpc);
        }
    }

    fprintf(stderr, "KeSetTimer(timer=%p, delay=%.3fs, dpc=%p)\n", Timer, delay_sec, Dpc);

    if (routine) {
        TimerFireArgs *a = malloc(sizeof(*a));
        a->dpc_key = Dpc; a->routine = routine; a->context = context; a->delay_sec = delay_sec;
        pthread_t tid;
        pthread_create(&tid, NULL, timer_fire_thread, a);
        pthread_detach(tid);
    }
    return 0; // BOOLEAN: previous state - simplified to "was not already set"
}

// ----------------------------------------------------------------------
// NtAllocateVirtualMemory / NtFreeVirtualMemory: real memory management,
// backed by real mmap/munmap. Standard Win32 PAGE_*/MEM_* constants below
// (these are stable, well-documented values, not Xbox-specific trivia -
// unlike the kernel ordinal table, there's no real risk of these being wrong).
//
// Each NtAllocateVirtualMemory call does its own mmap rather than tracking
// a VAD-style region tree. Verified this still correctly handles "reserve a
// big region, then commit a sub-range of it later" (confirmed live: a
// MEM_RESERVE of 0x100000 followed by a MEM_COMMIT of 0x1000 at the exact
// returned address both succeeded, with the commit's MAP_FIXED landing
// exactly on the earlier reservation) - this works because MAP_FIXED cleanly
// replaces only the overlapping pages, leaving the rest of a prior
// reservation's PROT_NONE mapping untouched either side of it.
// ----------------------------------------------------------------------
#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_WRITECOPY  0x80

#define MEM_COMMIT    0x00001000
#define MEM_RESERVE   0x00002000
#define MEM_TOP_DOWN  0x00100000

static int win_protect_to_posix(uint32_t protect) {
    switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return PROT_NONE;
        case PAGE_READONLY:          return PROT_READ;
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
        case PAGE_EXECUTE:           return PROT_EXEC;
        case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
        default:
            fprintf(stderr, "win_protect_to_posix: unrecognized Protect 0x%x, defaulting to RW\n", protect);
            return PROT_READ | PROT_WRITE;
    }
}

static uint32_t NTAPI_STDCALL_NtAllocateVirtualMemory(
    void **BaseAddress, uint32_t ZeroBits, uint32_t *AllocationSize,
    uint32_t AllocationType, uint32_t Protect) __attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtAllocateVirtualMemory(
    void **BaseAddress, uint32_t ZeroBits, uint32_t *AllocationSize,
    uint32_t AllocationType, uint32_t Protect)
{
    (void) ZeroBits;
    long pagesz = sysconf(_SC_PAGESIZE);
    uint32_t requested_size = *AllocationSize;
    uint32_t rounded_size = (requested_size + pagesz - 1) & ~(uint32_t) (pagesz - 1);
    if (rounded_size == 0) rounded_size = pagesz;

    int prot = (AllocationType & MEM_COMMIT) ? win_protect_to_posix(Protect) : PROT_NONE;
    void *hint = *BaseAddress;
    void *result;

    if (hint != NULL) {
        uintptr_t hint_aligned = (uintptr_t) hint & ~(uintptr_t) (pagesz - 1);
        int collides_with_xbe_image = (hint_aligned < 0x572000u); // below our image's top - see RVA table
        if (collides_with_xbe_image) {
            fprintf(stderr,
                "NtAllocateVirtualMemory: hint %p falls inside the loaded XBE image range - "
                "refusing MAP_FIXED there, letting the OS pick an address instead\n", hint);
            result = mmap(NULL, rounded_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        } else {
            result = mmap((void *) hint_aligned, rounded_size, prot,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (result == MAP_FAILED || (uintptr_t) result != hint_aligned) {
                fprintf(stderr,
                    "NtAllocateVirtualMemory: could not honor exact hint %p, falling back to OS-chosen address\n",
                    hint);
                result = mmap(NULL, rounded_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            }
        }
    } else {
        result = mmap(NULL, rounded_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    if (result == MAP_FAILED) {
        fprintf(stderr, "NtAllocateVirtualMemory: mmap failed for size 0x%x: %s\n",
                rounded_size, strerror(errno));
        return 0xC0000017u; // STATUS_NO_MEMORY
    }

    *BaseAddress = result;
    *AllocationSize = rounded_size;
    fprintf(stderr, "NtAllocateVirtualMemory(hint=%p, size=0x%x->0x%x, type=0x%x, protect=0x%x) -> %p\n",
            hint, requested_size, rounded_size, AllocationType, Protect, result);
    return 0; // STATUS_SUCCESS
}

static uint32_t NTAPI_STDCALL_NtFreeVirtualMemory(
    void **BaseAddress, uint32_t *FreeSize, uint32_t FreeType) __attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtFreeVirtualMemory(
    void **BaseAddress, uint32_t *FreeSize, uint32_t FreeType)
{
    (void) FreeType;
    fprintf(stderr, "NtFreeVirtualMemory(%p, size=0x%x)\n", *BaseAddress, *FreeSize);
    if (munmap(*BaseAddress, *FreeSize) != 0) {
        fprintf(stderr, "NtFreeVirtualMemory: munmap failed: %s\n", strerror(errno));
        return 0xC0000001u; // STATUS_UNSUCCESSFUL
    }
    return 0; // STATUS_SUCCESS
}

// MmPersistContiguousMemory: `void MmPersistContiguousMemory(PVOID BaseAddress,
// ULONG NumberOfBytes, BOOLEAN Persist)`. Marks a contiguous memory region to
// survive (or not) a soft-reset/quick-boot. This harness has no soft-reset
// concept at all to survive, so there is genuinely nothing to do beyond
// bookkeeping - a real, complete implementation here IS a no-op, not a
// shortcut around one.
static void NTAPI_STDCALL_MmPersistContiguousMemory(void *BaseAddress, uint32_t NumberOfBytes, uint32_t Persist) __attribute__((stdcall));
static void NTAPI_STDCALL_MmPersistContiguousMemory(void *BaseAddress, uint32_t NumberOfBytes, uint32_t Persist) {
    fprintf(stderr, "MmPersistContiguousMemory(%p, size=0x%x, persist=%u) - no-op (no soft-reset in this harness)\n",
            BaseAddress, NumberOfBytes, Persist);
}

// ----------------------------------------------------------------------
// DATA kernel exports. The xboxkrnl.exe.def file this project's ordinal
// table came from distinguishes functions (name decorated with a trailing
// @N stdcall byte count, e.g. "AvGetSavedDataAddress@0") from plain DATA
// symbols (bare name, no @N) - object-type constants, counters, and a
// handful of real variables like LaunchDataPage. That distinction got lost
// when the ordinal table was generated (every entry was treated as "a
// function to stub"), which is a real bug: the game dereferences a data
// export's thunk slot directly as a pointer to storage, not as a call
// target. Caught live via gdb: LaunchDataPage got patched with a function's
// code address, so `*LaunchDataPage` read garbage machine-code bytes as a
// pointer, which then crashed a few calls later when the game tried to
// zero-fill memory through it.
//
// Audited this properly after LaunchDataPage's bug nearly caused a second,
// silent (non-crashing) one: cross-checked the real 116-ordinal used-list
// (from WalkKernelThunk.java) against every bare-name (no "@N") entry in the
// original xboxkrnl.exe.def dump. Found 14 data exports this game actually
// uses, not just the one that happened to crash. The rest are harmless as
// zeroed placeholders (object-type constants nothing here type-checks
// against, crypto key material nothing here verifies); XeImageFileName and
// XboxKrnlVersion get real content since code was actually seen comparing
// against them. KeTickCount is zeroed, not a live counter - a real free-
// running tick needs a background-updating thread, not built yet; flagged as
// a known gap in case timing-sensitive code ever depends on it moving.
static uint32_t g_LaunchDataPage_storage = 0;        // starts NULL until something allocates it, like real hardware
static uint32_t g_generic_object_type_storage[4];    // shared dummy for the *ObjectType constants - nothing here type-checks handles
static uint8_t  g_xbox_hardware_info[32];            // zeroed: "no special hardware flags" (standard retail unit)
static uint8_t  g_crypto_key_storage[32];            // zeroed: XboxHDKey/XboxSignatureKey/XboxAlternateSignatureKeys/XePublicKeyData - nothing here verifies signatures
// Was zeroed as a "safe placeholder" - proven wrong live: a disk-cache-slot
// table manager (FUN_0014bd84, reads/writes a cache-allocation table on
// Harddisk0\Partition0) computes `uVar1 - 1` and `uVar5 - 1` from this value
// and uses the result as an array index. Zero underflows to 0xFFFFFFFF,
// driving an out-of-bounds write into a 41-slot local table and crashing
// inside memcpy. The code's own clamp (`if (0x29 < uVar5) uVar5 = 0x29`)
// confirms 0x29 (41) is the real capacity, so that's the sane non-zero value
// here, not an arbitrary guess.
static uint32_t g_hal_disk_cache_partition_count = 0x29;
static uint32_t g_ke_tick_count = 0;                 // NOT a live counter yet - see comment above
static uint32_t g_hal_boot_smc_video_mode = 0;
static uint32_t g_idex_channel_object = 0;
static struct { uint16_t Major, Minor, Build, Qfe; } g_xbox_krnl_version = { 1, 0, 5838, 0 }; // plausible real late-retail kernel version

// XeImageFileName's real layout - corrected via a fresh disassembly of the
// actual crash site (FUN_0015040d, the game's own exe-path/symlink-fixup
// routine): `MOVZX ECX, word ptr [EAX]` (Length @ +0) then
// `PUSH dword ptr [EAX+0x4]` (Buffer @ +4), i.e. naturally-aligned
// {Length(2); pad(2); Buffer(4)} = 8 bytes - NOT the packed 6-byte
// {Length(2);Buffer(4)} this was previously (wrongly) built as, which put
// Buffer at +2 and fed garbage stack bytes into Buffer's low two bytes to
// every caller that read it (the earlier "verified from disassembly" claim
// was reading a different access site and doesn't hold up against this one).
static struct { uint16_t Length; uint16_t _pad; char *Buffer; } g_xe_image_file_name_str;
static char g_xe_image_file_name_buf[] = "\\Device\\CdRom0\\default.xbe";

static void *data_storage_for_ordinal(int ordinal) {
    switch (ordinal) {
        case 164: return &g_LaunchDataPage_storage;       // LaunchDataPage
        case 16:  return g_generic_object_type_storage;   // ExEventObjectType
        case 71:  return g_generic_object_type_storage;   // IoFileObjectType
        case 259: return g_generic_object_type_storage;   // PsThreadObjectType
        case 322: return g_xbox_hardware_info;             // XboxHardwareInfo
        case 323: return g_crypto_key_storage;             // XboxHDKey
        case 325: return g_crypto_key_storage;             // XboxSignatureKey
        case 354: return g_crypto_key_storage;             // XboxAlternateSignatureKeys
        case 355: return g_crypto_key_storage;             // XePublicKeyData
        case 40:  return &g_hal_disk_cache_partition_count; // HalDiskCachePartitionCount
        case 156: return &g_ke_tick_count;                  // KeTickCount
        case 356: return &g_hal_boot_smc_video_mode;        // HalBootSMCVideoMode
        case 357: return &g_idex_channel_object;            // IdexChannelObject
        case 324: return &g_xbox_krnl_version;              // XboxKrnlVersion
        case 326:                                            // XeImageFileName - the real path, not a placeholder
            g_xe_image_file_name_str.Length = sizeof(g_xe_image_file_name_buf) - 1;
            g_xe_image_file_name_str.Buffer = g_xe_image_file_name_buf;
            return &g_xe_image_file_name_str;
        default:  return NULL;
    }
}

// MmAllocateContiguousMemory / MmFreeContiguousMemory: `PVOID MmAllocateContiguousMemory(ULONG NumberOfBytes)`,
// `void MmFreeContiguousMemory(PVOID BaseAddress)`. Real hardware needs these
// physically contiguous for DMA (GPU/audio). This harness has no real DMA
// engine - every consumer here is software reading/writing through normal
// virtual addresses, for which an ordinary mmap'd region is indistinguishable
// from "physically contiguous." mmap-backed, with a small side-table (keyed
// by returned base address) recording each allocation's size so Free knows
// how much to munmap.
typedef struct { void *base; uint32_t size; } ContigAlloc;
static ContigAlloc g_contig_allocs[256];
static int g_contig_alloc_count = 0;

static void *NTAPI_STDCALL_MmAllocateContiguousMemory(uint32_t NumberOfBytes) __attribute__((stdcall));
static void *NTAPI_STDCALL_MmAllocateContiguousMemory(uint32_t NumberOfBytes) {
    long pagesz = sysconf(_SC_PAGESIZE);
    uint32_t rounded = (NumberOfBytes + pagesz - 1) & ~(uint32_t) (pagesz - 1);
    if (rounded == 0) rounded = pagesz;
    void *p = mmap(NULL, rounded, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "MmAllocateContiguousMemory(0x%x): mmap failed: %s\n", NumberOfBytes, strerror(errno));
        return NULL;
    }
    if (g_contig_alloc_count < (int) (sizeof(g_contig_allocs) / sizeof(g_contig_allocs[0]))) {
        g_contig_allocs[g_contig_alloc_count++] = (ContigAlloc) { p, rounded };
    }
    fprintf(stderr, "MmAllocateContiguousMemory(0x%x->0x%x) -> %p\n", NumberOfBytes, rounded, p);
    return p;
}

// MmAllocateContiguousMemoryEx: `PVOID MmAllocateContiguousMemoryEx(ULONG NumberOfBytes,
// PHYSICAL_ADDRESS LowestAcceptableAddress, PHYSICAL_ADDRESS HighestAcceptableAddress,
// ULONG Alignment, ULONG ProtectionType)`. Same no-real-DMA reasoning as the
// plain MmAllocateContiguousMemory above - the address-range/alignment
// constraints only matter for a real physical allocator, so this ignores
// them and shares the same tracked-mmap pool (MmFreeContiguousMemory doesn't
// care which of the two allocated a given base).
static void *NTAPI_STDCALL_MmAllocateContiguousMemoryEx(
    uint32_t NumberOfBytes, uint32_t LowestAcceptableAddress, uint32_t HighestAcceptableAddress,
    uint32_t Alignment, uint32_t ProtectionType) __attribute__((stdcall));
static void *NTAPI_STDCALL_MmAllocateContiguousMemoryEx(
    uint32_t NumberOfBytes, uint32_t LowestAcceptableAddress, uint32_t HighestAcceptableAddress,
    uint32_t Alignment, uint32_t ProtectionType)
{
    (void) LowestAcceptableAddress; (void) HighestAcceptableAddress; (void) Alignment; (void) ProtectionType;
    void *p = NTAPI_STDCALL_MmAllocateContiguousMemory(NumberOfBytes);
    fprintf(stderr, "MmAllocateContiguousMemoryEx(0x%x, align=0x%x, protect=0x%x) -> %p\n",
            NumberOfBytes, Alignment, ProtectionType, p);
    return p;
}

// MmClaimGpuInstanceMemory: `PVOID MmClaimGpuInstanceMemory(SIZE_T NumberOfBytes,
// SIZE_T *NumberOfPaddingBytes)`. Real hardware carves this out of the top of
// unified RAM for the GPU's own framebuffer/texture memory, with alignment
// padding reported back. No real memory-layout constraint to match here (no
// real GPU, no shared-memory split to emulate) - just hand back ordinary
// allocated memory via the same tracked-mmap pool, with zero padding since
// nothing here needs a specific physical alignment.
static void *NTAPI_STDCALL_MmClaimGpuInstanceMemory(uint32_t NumberOfBytes, uint32_t *NumberOfPaddingBytes) __attribute__((stdcall));
static void *NTAPI_STDCALL_MmClaimGpuInstanceMemory(uint32_t NumberOfBytes, uint32_t *NumberOfPaddingBytes) {
    if (NumberOfPaddingBytes) *NumberOfPaddingBytes = 0;
    void *p = NTAPI_STDCALL_MmAllocateContiguousMemory(NumberOfBytes);
    fprintf(stderr, "MmClaimGpuInstanceMemory(0x%x) -> %p\n", NumberOfBytes, p);
    return p;
}

// MmLockUnlockBufferPages: `void MmLockUnlockBufferPages(PVOID BaseAddress,
// SIZE_T NumberOfBytes, BOOLEAN UnlockPages)`. Real hardware's own kernel
// treats this as pinning pages against relocation/paging - Cxbx-Reloaded's
// own source notes all its emulated pages are already non-relocatable,
// making this "pointless" even there. Every page in this loader is a fixed
// anonymous mmap with no swap/relocation behavior to pin against either, so
// a genuine no-op is the complete, correct behavior, not a stand-in.
static void NTAPI_STDCALL_MmLockUnlockBufferPages(void *BaseAddress, uint32_t NumberOfBytes, uint32_t UnlockPages) __attribute__((stdcall));
static void NTAPI_STDCALL_MmLockUnlockBufferPages(void *BaseAddress, uint32_t NumberOfBytes, uint32_t UnlockPages) {
    fprintf(stderr, "MmLockUnlockBufferPages(base=%p, size=0x%x, unlock=%u) - no-op, no relocation to pin against\n",
            BaseAddress, NumberOfBytes, UnlockPages);
}

// MmGetPhysicalAddress: `ULONG MmGetPhysicalAddress(PVOID BaseAddress)`.
// Translates virtual to physical. This loader has no separate physical
// address space at all - there's no real DMA engine reading a "physical"
// bus address behind the CPU's back, so the virtual address a buffer
// already lives at IS its own answer here (the same reasoning already used
// for MmClaimGpuInstanceMemory handing back ordinary process memory as
// "GPU accessible" memory - there's nothing physically separate to map to).
static void *NTAPI_STDCALL_MmGetPhysicalAddress(void *BaseAddress) __attribute__((stdcall));
static void *NTAPI_STDCALL_MmGetPhysicalAddress(void *BaseAddress) {
    fprintf(stderr, "MmGetPhysicalAddress(%p) -> %p (identity, no separate physical space)\n", BaseAddress, BaseAddress);
    return BaseAddress;
}

// KeStallExecutionProcessor: `void KeStallExecutionProcessor(ULONG MicroSeconds)`.
// A genuine, real busy-wait/delay - no emulation gap to paper over, just a
// real sleep for the requested duration.
// ExAllocatePool / ExAllocatePoolWithTag / ExFreePool: `PVOID
// ExAllocatePoolWithTag(SIZE_T NumberOfBytes, ULONG Tag)`, `PVOID
// ExAllocatePool(SIZE_T NumberOfBytes)` (just forwards with a generic tag on
// real hardware), `void ExFreePool(PVOID P)`. The Tag exists purely for
// real-hardware leak-tracking/debugging tools - semantically this is just
// the kernel's one non-paged pool (Xbox, unlike NT, only has the one pool),
// i.e. a plain heap allocator. The host's own malloc/free already behave
// exactly like that, so there's no real gap to emulate here.
static void *NTAPI_STDCALL_ExAllocatePoolWithTag(uint32_t NumberOfBytes, uint32_t Tag) __attribute__((stdcall));
static void *NTAPI_STDCALL_ExAllocatePoolWithTag(uint32_t NumberOfBytes, uint32_t Tag) {
    void *p = malloc(NumberOfBytes);
    fprintf(stderr, "ExAllocatePoolWithTag(0x%x, tag='%c%c%c%c') -> %p\n",
            NumberOfBytes, (char) (Tag & 0xFF), (char) ((Tag >> 8) & 0xFF),
            (char) ((Tag >> 16) & 0xFF), (char) ((Tag >> 24) & 0xFF), p);
    return p;
}

static void *NTAPI_STDCALL_ExAllocatePool(uint32_t NumberOfBytes) __attribute__((stdcall));
static void *NTAPI_STDCALL_ExAllocatePool(uint32_t NumberOfBytes) {
    return NTAPI_STDCALL_ExAllocatePoolWithTag(NumberOfBytes, 0x656e6f4e); // 'enoN' = "None" reversed, matches real kernel's own default tag
}

static void NTAPI_STDCALL_ExFreePool(void *P) __attribute__((stdcall));
static void NTAPI_STDCALL_ExFreePool(void *P) {
    free(P);
}

// ExQueryPoolBlockSize: `ULONG ExQueryPoolBlockSize(PVOID PoolBlock)`. Real
// hardware reports the real allocated block size (usually rounded up from
// the request), same thing `_msize`/`malloc_usable_size` report for a glibc
// allocation - using the real glibc value instead of just echoing back the
// original request size, since this exists precisely so callers can ask
// "how much room do I actually have," which includes any rounding.
static uint32_t NTAPI_STDCALL_ExQueryPoolBlockSize(void *PoolBlock) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_ExQueryPoolBlockSize(void *PoolBlock) {
    return (uint32_t) malloc_usable_size(PoolBlock);
}

// MmQueryAllocationSize: `ULONG MmQueryAllocationSize(PVOID BaseAddress)`.
// This is the page-allocator-side sibling of ExQueryPoolBlockSize above -
// for VirtualAlloc/MmAllocateContiguousMemory-style allocations rather than
// pool blocks. Looks up the real rounded size already recorded in the
// contiguous-allocation table (see MmAllocateContiguousMemory) rather than
// guessing a page-rounded value independently.
static uint32_t NTAPI_STDCALL_MmQueryAllocationSize(void *BaseAddress) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_MmQueryAllocationSize(void *BaseAddress) {
    for (int i = 0; i < g_contig_alloc_count; i++) {
        if (g_contig_allocs[i].base == BaseAddress) return g_contig_allocs[i].size;
    }
    fprintf(stderr, "MmQueryAllocationSize(%p) - not a tracked contiguous allocation\n", BaseAddress);
    return 0;
}

static void NTAPI_STDCALL_KeStallExecutionProcessor(uint32_t MicroSeconds) __attribute__((stdcall));
static void NTAPI_STDCALL_KeStallExecutionProcessor(uint32_t MicroSeconds) {
    usleep(MicroSeconds);
}

// AvSendTVEncoderOption: `void AvSendTVEncoderOption(PVOID RegisterBase,
// ULONG Option, ULONG Param, ULONG *Result)`. Real hardware pokes a
// physical TV-encoder chip (Focus/Conexant/Philips, model-dependent) over
// its own register interface for things like Macrovision mode, closed-
// captioning, flicker filtering. No real encoder chip exists here and
// nothing downstream has been seen to branch on *Result yet, so this is a
// real no-op (not a guess at encoder behavior) that reports success.
static void NTAPI_STDCALL_AvSendTVEncoderOption(void *RegisterBase, uint32_t Option, uint32_t Param, uint32_t *Result) __attribute__((stdcall));
static void NTAPI_STDCALL_AvSendTVEncoderOption(void *RegisterBase, uint32_t Option, uint32_t Param, uint32_t *Result) {
    fprintf(stderr, "AvSendTVEncoderOption(base=%p, option=0x%x, param=0x%x) - no-op, no real encoder\n",
            RegisterBase, Option, Param);
    if (Result) *Result = 0;
}

// FscSetCacheSize: `NTSTATUS FscSetCacheSize(ULONG NumberOfCachePages)`. Real
// hardware's File System Cache manager - even Cxbx-Reloaded's own
// implementation just validates and records this (the actual page
// allocation is commented out as unimplemented there too), so storing the
// value and validating against the real max is the complete, correct
// behavior, not a stub standing in for missing work.
#define FSCACHE_MAXIMUM_NUMBER_OF_CACHE_PAGES 2048
static uint32_t g_fsc_number_of_cache_pages = 0;

static uint32_t NTAPI_STDCALL_FscSetCacheSize(uint32_t NumberOfCachePages) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_FscSetCacheSize(uint32_t NumberOfCachePages) {
    fprintf(stderr, "FscSetCacheSize(%u pages)\n", NumberOfCachePages);
    if (NumberOfCachePages > FSCACHE_MAXIMUM_NUMBER_OF_CACHE_PAGES) return 0xC000000Du; // STATUS_INVALID_PARAMETER
    g_fsc_number_of_cache_pages = NumberOfCachePages;
    return 0;
}

// KeRaiseIrqlToDpcLevel / KfRaiseIrql / KfLowerIrql: real hardware uses IRQL
// to mask interrupts up to a given priority level, so code running at
// DISPATCH_LEVEL+ can't be preempted by a DPC or lower-priority interrupt.
// This loader has no real interrupt/DPC preemption to mask in the first
// place (DPCs/timers here are just plain host threads, not something that
// asynchronously interrupts a running thread) - so IRQL only needs to be
// tracked faithfully enough for save/restore pairing to balance correctly,
// not actually enforced. Per-thread (not global), matching real hardware
// where each thread/CPU has its own IRQL.
// The "Kf" prefix (vs "Ke") is Microsoft's own naming convention for the
// FASTCALL variants of a handful of hot-path kernel routines (KfRaiseIrql,
// KfLowerIrql, KfAcquireSpinLock, ...) - their single argument comes in a
// register (ECX on x86), not pushed on the stack like every stdcall kernel
// export elsewhere in this file. Declaring these as stdcall instead (an
// easy mistake, since nothing else here needs a different convention)
// caused the real bug this was found and fixed from: the stdcall callee
// popped a stack argument the fastcall caller never pushed, unbalancing
// the stack so the subsequent RET jumped to garbage (seen live: EIP ended
// up at 0x30c, a tiny address, classic stack-imbalance-after-return
// fingerprint - and since the jump target itself was unmapped, decoding it
// as a potential faulting instruction inside the signal handler caused a
// second, undeliverable SIGSEGV with zero diagnostics, the exact "silent
// death" signature as the earlier sigaltstack bug but a different cause).
#define DISPATCH_LEVEL 2
static __thread uint8_t g_current_irql = 0; // PASSIVE_LEVEL

static uint8_t NTAPI_FASTCALL_KfRaiseIrql(uint8_t NewIrql) __attribute__((fastcall));
static uint8_t NTAPI_FASTCALL_KfRaiseIrql(uint8_t NewIrql) {
    uint8_t old = g_current_irql;
    g_current_irql = NewIrql;
    return old;
}

static void NTAPI_FASTCALL_KfLowerIrql(uint8_t NewIrql) __attribute__((fastcall));
static void NTAPI_FASTCALL_KfLowerIrql(uint8_t NewIrql) {
    g_current_irql = NewIrql;
}

static uint8_t NTAPI_STDCALL_KeRaiseIrqlToDpcLevel(void) __attribute__((stdcall));
static uint8_t NTAPI_STDCALL_KeRaiseIrqlToDpcLevel(void) {
    return NTAPI_FASTCALL_KfRaiseIrql(DISPATCH_LEVEL);
}

static void NTAPI_STDCALL_MmFreeContiguousMemory(void *BaseAddress) __attribute__((stdcall));
static void NTAPI_STDCALL_MmFreeContiguousMemory(void *BaseAddress) {
    for (int i = 0; i < g_contig_alloc_count; i++) {
        if (g_contig_allocs[i].base == BaseAddress) {
            munmap(BaseAddress, g_contig_allocs[i].size);
            fprintf(stderr, "MmFreeContiguousMemory(%p) - freed 0x%x bytes\n", BaseAddress, g_contig_allocs[i].size);
            g_contig_allocs[i] = g_contig_allocs[--g_contig_alloc_count];
            return;
        }
    }
    fprintf(stderr, "MmFreeContiguousMemory(%p) - not a tracked allocation, ignoring\n", BaseAddress);
}

// HalReturnToFirmware: `DECLSPEC_NORETURN void HalReturnToFirmware(RETURN_FIRMWARE Routine)`.
// Real hardware documents this as NEVER RETURNING - confirmed this is the
// correct, intentional, documented behavior (not an error path) by checking
// the actual caller: it only reaches here when self-relaunching using the
// game's own real Title ID as the target (verified against the XBE's real
// certificate data, not a sentinel/error value).
//
// Routine 2 (ReturnFirmwareQuickReboot) is a warm reboot that preserves
// memory the game explicitly marked via MmPersistContiguousMemory and
// re-enters at the XBE's entry point - that's exactly what LaunchDataPage
// is for (passing the relaunch reason/title across the "reboot"). A naive
// execve() here would wipe this process and reset LaunchDataPage to NULL,
// causing an infinite reboot loop (the game would see a "cold start" again
// every time). The correct simulation: just call entry() again, in-process,
// keeping all C state (including the "persisted" allocation) intact - this
// matches real quick-reboot semantics without needing real OS-level exec.
// Capped at a handful of iterations as a safety net in case this ever loops
// for a reason other than the one actually observed and verified.
static uint32_t g_entry_va;
static int g_reboot_count = 0;

static void NTAPI_STDCALL_HalReturnToFirmware(uint32_t Routine) __attribute__((stdcall, noreturn));
static void NTAPI_STDCALL_HalReturnToFirmware(uint32_t Routine) {
    static const char *names[] = { "Halt", "Reboot", "QuickReboot", "Hard", "Fatal", "All" };
    const char *name = Routine <= 5 ? names[Routine] : "UNKNOWN";
    fprintf(stderr, "\n=== HalReturnToFirmware(%s) - real hardware never returns from this call ===\n", name);

    // Debug instrumentation: dump what's actually in LaunchDataPage right now,
    // to see whether the reason/title fields the game writes match what
    // FUN_0014ae89 (the "read launch data back" check) expects to find on
    // the next entry() pass - reason==2||3, or title matching our real cert
    // TitleID 0x4d530053.
    if (g_LaunchDataPage_storage != 0) {
        uint32_t *ldp = (uint32_t *) (uintptr_t) g_LaunchDataPage_storage;
        fprintf(stderr, "  LaunchDataPage @ 0x%x: reason=0x%x title/arg=0x%x\n",
                g_LaunchDataPage_storage, ldp[0], ldp[1]);
    } else {
        fprintf(stderr, "  LaunchDataPage is NULL at reboot time (unexpected - should hold what was just built)\n");
    }

    if (Routine == 2 /* ReturnFirmwareQuickReboot */) {
        if (++g_reboot_count > 8) {
            fprintf(stderr, "quick-reboot loop exceeded 8 iterations - something is genuinely wrong, stopping\n");
            _exit(1);
        }
        fprintf(stderr, "quick-reboot #%d: re-entering entry() at 0x%x, preserving all current state "
                "(this is the real LaunchDataPage mechanism working as intended, not a crash workaround)\n",
                g_reboot_count, g_entry_va);
        void (*entry_fn)(void) = (void (*)(void)) (uintptr_t) g_entry_va;
        entry_fn();
        // entry() returning here is normal (see the comment on main()'s own
        // call to it) - wait for whatever thread(s) it just created (tracked
        // in the same global g_threads[] table) before actually exiting.
        // Does NOT fall through to a real `return`: HalReturnToFirmware is
        // documented NORETURN, and the game's own code after the call site
        // that invoked us was never meant to execute - exiting here instead
        // of returning into it is the faithful behavior, not a shortcut.
        fprintf(stderr, "entry() returned (normal) after the quick-reboot - waiting on its thread(s)\n");
        wait_for_all_threads();
        _exit(0);
    }

    fprintf(stderr, "no real firmware/dashboard to return to in this harness - exiting\n");
    _exit(Routine == 0 ? 0 : 1);
}

// RtlInitAnsiString: `void RtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString)`.
// Pure, simple: fills in the STRING struct's Length/MaximumLength from
// strlen(SourceString), Buffer = SourceString itself (referenced, not
// copied - matches real semantics exactly, no simplification needed here).
static void NTAPI_STDCALL_RtlInitAnsiString(XbString *DestinationString, char *SourceString) __attribute__((stdcall));
static void NTAPI_STDCALL_RtlInitAnsiString(XbString *DestinationString, char *SourceString) {
    uint16_t len = SourceString ? (uint16_t) strlen(SourceString) : 0;
    DestinationString->Length = len;
    DestinationString->MaximumLength = len + 1;
    DestinationString->Buffer = SourceString;
}

// RtlEqualString: `BOOLEAN RtlEqualString(PSTRING String1, PSTRING String2, BOOLEAN CaseInsensitive)`.
// Pure comparison: lengths must match, then compare bytes.
static uint32_t NTAPI_STDCALL_RtlEqualString(XbString *String1, XbString *String2, uint32_t CaseInsensitive) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_RtlEqualString(XbString *String1, XbString *String2, uint32_t CaseInsensitive) {
    if (String1->Length != String2->Length) return 0;
    if (String1->Length == 0) return 1;
    int cmp = CaseInsensitive
        ? strncasecmp(String1->Buffer, String2->Buffer, String1->Length)
        : strncmp(String1->Buffer, String2->Buffer, String1->Length);
    return cmp == 0 ? 1 : 0;
}

// XeLoadSection / XeUnloadSection: `NTSTATUS Xe{Load,Unload}Section(PXBEIMAGE_SECTION Section)`.
// Section is a pointer directly into this XBE's own section table (the same
// verified struct layout as scripts/decode_section_table.py - Flags, RVA,
// VSize, RawAddr, RawSize, NameAddr, SectionReferenceCount, Head/TailRefCount
// pointers, Hash). Per Cxbx-Reloaded's reference implementation, real
// hardware lazily maps+zeroes+copies a section's data on first load
// (SectionReferenceCount 0->1) and frees it on last unload (1->0). This
// loader already maps every section with its real content upfront (see
// main()), so there's nothing to actually (un)load - just keep the
// reference-count bookkeeping correct for any code that checks it.
typedef struct {
    uint32_t Flags, VirtualAddress, VirtualSize, RawAddr, RawSize, SectionNameAddr;
    int32_t SectionReferenceCount;
    uint16_t *HeadReferenceCount, *TailReferenceCount;
    uint8_t Hash[20];
} XbSection;

static uint32_t NTAPI_STDCALL_XeLoadSection(XbSection *Section) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_XeLoadSection(XbSection *Section) {
    if (Section->SectionReferenceCount == 0) {
        if (Section->HeadReferenceCount) (*Section->HeadReferenceCount)++;
        if (Section->TailReferenceCount) (*Section->TailReferenceCount)++;
    }
    Section->SectionReferenceCount++;
    fprintf(stderr, "XeLoadSection(%p) - refcount now %d\n", (void *) Section, Section->SectionReferenceCount);
    return 0;
}

static uint32_t NTAPI_STDCALL_XeUnloadSection(XbSection *Section) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_XeUnloadSection(XbSection *Section) {
    if (Section->SectionReferenceCount <= 0) return 0xC000000Du; // STATUS_INVALID_PARAMETER
    Section->SectionReferenceCount--;
    fprintf(stderr, "XeUnloadSection(%p) - refcount now %d\n", (void *) Section, Section->SectionReferenceCount);
    return 0;
}

// NtDeviceIoControlFile: `NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event,
// PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
// ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength,
// PVOID OutputBuffer, ULONG OutputBufferLength)`. IoControlCode space is huge
// and device-specific (disk geometry, partition management, controller
// state, etc.) - only implementing codes actually seen in practice, logging
// clearly and failing informatively on anything else rather than guessing.
#define IOCTL_DISK_GET_DRIVE_GEOMETRY 0x70000
#define IOCTL_DISK_GET_PARTITION_INFO 0x74004
#define MEDIA_TYPE_FixedMedia 12

typedef struct { int64_t cylinders; uint32_t mediaType, tracksPerCylinder, sectorsPerTrack, bytesPerSector; } XbDiskGeometry;
typedef struct {
    int64_t startingOffset, partitionLength;
    uint32_t hiddenSectors, partitionNumber;
    uint8_t partitionType, bootIndicator, recognizedPartition, rewritePartition;
} XbPartitionInformation;

static uint32_t NTAPI_STDCALL_NtDeviceIoControlFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, uint32_t IoControlCode, void *InputBuffer,
    uint32_t InputBufferLength, void *OutputBuffer, uint32_t OutputBufferLength)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtDeviceIoControlFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, uint32_t IoControlCode, void *InputBuffer,
    uint32_t InputBufferLength, void *OutputBuffer, uint32_t OutputBufferLength)
{
    (void) Event; (void) ApcRoutine; (void) ApcContext; (void) InputBuffer;
    fprintf(stderr, "NtDeviceIoControlFile(handle=0x%x, code=0x%x, inLen=%u, outLen=%u)\n",
            FileHandle, IoControlCode, InputBufferLength, OutputBufferLength);

    if (IoControlCode == IOCTL_DISK_GET_DRIVE_GEOMETRY) {
        if (OutputBufferLength < sizeof(XbDiskGeometry)) return 0xC0000023u; // STATUS_BUFFER_TOO_SMALL
        XbDiskGeometry *geo = (XbDiskGeometry *) OutputBuffer;
        // Real retail Xbox HDD geometry values, from Cxbx-Reloaded's own
        // reference constants for FILE_DEVICE_DISK2 (EmuKrnlNt.cpp): 10GB
        // stock drive, 512 bytes/sector.
        geo->cylinders = 0x1400000;
        geo->mediaType = MEDIA_TYPE_FixedMedia;
        geo->tracksPerCylinder = 1;
        geo->sectorsPerTrack = 1;
        geo->bytesPerSector = 512;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbDiskGeometry);
        return 0;
    }

    if (IoControlCode == IOCTL_DISK_GET_PARTITION_INFO) {
        if (OutputBufferLength < sizeof(XbPartitionInformation)) return 0xC0000023u;
        if (FileHandle < 0x2000u || FileHandle - 0x2000u >= (uint32_t) g_file_handle_count) return 0xC0000008u;
        FileHandleEntry *fh = &g_file_handles[FileHandle - 0x2000u];
        XbPartitionInformation *info = (XbPartitionInformation *) OutputBuffer;
        // Real retail hardware reads this from a fixed partition table for
        // the small set of well-known partitions; our dynamically-numbered
        // cache partitions (see Partition43 etc. above) have no such fixed
        // table entry to read from, so this reports the real partition
        // number (tracked per-handle since NtOpenFile/NtCreateFile) with a
        // generous, bounded placeholder length (8MB, matching Cxbx's own
        // FILE_DEVICE_MEMORY_UNIT case for a similarly-dynamic allocation)
        // rather than fabricating a precise byte offset nothing here tracks.
        info->startingOffset = 0;
        info->partitionLength = 8 * 1024 * 1024;
        info->hiddenSectors = 0;
        info->partitionNumber = fh->partition_number >= 0 ? (uint32_t) fh->partition_number : 0;
        info->partitionType = 0;
        info->bootIndicator = 0;
        info->recognizedPartition = 1;
        info->rewritePartition = 0;
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = sizeof(XbPartitionInformation);
        return 0;
    }

    fprintf(stderr, "  unrecognized IoControlCode 0x%x - no device-specific handling yet\n", IoControlCode);
    IoStatusBlock->Status = 0xC0000010u; // STATUS_INVALID_DEVICE_REQUEST
    IoStatusBlock->Information = 0;
    return 0xC0000010u;
}

// NtFsControlFile: `NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event,
// PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
// ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength,
// PVOID OutputBuffer, ULONG OutputBufferLength)`. Filesystem-level control
// codes (vs. NtDeviceIoControlFile's device-level ones) - values confirmed
// from Cxbx-Reloaded's EmuFile.h (fsctl_dismount_volume/read_fatx_metadata/
// write_fatx_metadata), since these are Xbox-kernel-specific, not standard
// NT FSCTLs.
#define FSCTL_DISMOUNT_VOLUME     0x00090020u
#define FSCTL_READ_FATX_METADATA  0x0009411Cu
#define FSCTL_WRITE_FATX_METADATA 0x00098120u

// Matches Cxbx's fatx_volume_metadata: {ULONG offset; ULONG length; PVOID buffer;}
typedef struct { uint32_t offset; uint32_t length; void *buffer; } XbFatxVolumeMetadata;

static uint32_t NTAPI_STDCALL_NtFsControlFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, uint32_t FsControlCode, void *InputBuffer,
    uint32_t InputBufferLength, void *OutputBuffer, uint32_t OutputBufferLength)
__attribute__((stdcall));

static uint32_t NTAPI_STDCALL_NtFsControlFile(
    uint32_t FileHandle, uint32_t Event, void *ApcRoutine, void *ApcContext,
    XbIoStatusBlock *IoStatusBlock, uint32_t FsControlCode, void *InputBuffer,
    uint32_t InputBufferLength, void *OutputBuffer, uint32_t OutputBufferLength)
{
    (void) Event; (void) ApcRoutine; (void) ApcContext; (void) OutputBuffer; (void) OutputBufferLength;
    fprintf(stderr, "NtFsControlFile(handle=0x%x, code=0x%x, inLen=%u)\n",
            FileHandle, FsControlCode, InputBufferLength);

    if (FsControlCode == FSCTL_DISMOUNT_VOLUME) {
        // No real volume-mount concept in this loader (every handle is just
        // a host fd/path) - nothing to tear down, matches the no-op
        // precedent set by MmPersistContiguousMemory.
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = 0;
        return 0;
    }

    if (FsControlCode == FSCTL_READ_FATX_METADATA || FsControlCode == FSCTL_WRITE_FATX_METADATA) {
        if (InputBufferLength < sizeof(XbFatxVolumeMetadata)) return 0xC000000Du; // STATUS_INVALID_PARAMETER
        if (FileHandle < 0x2000u || FileHandle - 0x2000u >= (uint32_t) g_file_handle_count) return 0xC0000008u;
        FileHandleEntry *fh = &g_file_handles[FileHandle - 0x2000u];
        if (!fh->host_backed || fh->host_fd < 0) return 0xC0000001u;
        XbFatxVolumeMetadata *meta = (XbFatxVolumeMetadata *) InputBuffer;
        int is_write = (FsControlCode == FSCTL_WRITE_FATX_METADATA);
        // This handle is already a real host file (our Harddisk0 cache
        // partitions aren't a separate MU-metadata store the way Cxbx's
        // are) - so the metadata region lives at the same offsets inside
        // that same file.
        ssize_t got = is_write ? pwrite(fh->host_fd, meta->buffer, meta->length, (off_t) meta->offset)
                                : pread(fh->host_fd, meta->buffer, meta->length, (off_t) meta->offset);
        if (got < 0) {
            fprintf(stderr, "NtFsControlFile: %s failed: %s\n", is_write ? "pwrite" : "pread", strerror(errno));
            return 0xC0000001u;
        }
        fprintf(stderr, "  %s_fatx_metadata(offset=%u, length=%u) -> %zd bytes\n",
                is_write ? "write" : "read", meta->offset, meta->length, got);
        IoStatusBlock->Status = 0;
        IoStatusBlock->Information = (uint32_t) got;
        return 0;
    }

    fprintf(stderr, "  unrecognized FsControlCode 0x%x - no handling yet\n", FsControlCode);
    IoStatusBlock->Status = 0xC0000010u; // STATUS_INVALID_DEVICE_REQUEST
    IoStatusBlock->Information = 0;
    return 0xC0000010u;
}

// KeQuerySystemTime: `void KeQuerySystemTime(PLARGE_INTEGER CurrentTime)`.
// Real Windows FILETIME: 100ns intervals since 1601-01-01. Standard,
// well-documented conversion from the Unix epoch (11644473600 seconds
// difference) - not Xbox-specific trivia, safe from memory.
static void NTAPI_STDCALL_KeQuerySystemTime(int64_t *CurrentTime) __attribute__((stdcall));
static void NTAPI_STDCALL_KeQuerySystemTime(int64_t *CurrentTime) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t unix_100ns = (int64_t) ts.tv_sec * 10000000LL + ts.tv_nsec / 100;
    *CurrentTime = unix_100ns + 116444736000000000LL;
}

// MmQueryStatistics: `NTSTATUS MmQueryStatistics(PMM_STATISTICS MemoryStatistics)`.
// Struct from Cxbx-Reloaded's types.h: 9 ULONGs, {Length, TotalPhysicalPages,
// AvailablePages, VirtualMemoryBytesCommitted, VirtualMemoryBytesReserved,
// CachePagesCommitted, PoolPagesCommitted, StackPagesCommitted,
// ImagePagesCommitted}. Only hard requirement found in practice is
// Length==sizeof(struct) to get STATUS_SUCCESS back; the rest are plausible
// real-hardware-shaped placeholder values (64MB RAM / 4KB pages = 0x4000
// total, reporting half free) since nothing here tracks per-category page
// counts for real.
typedef struct {
    uint32_t Length, TotalPhysicalPages, AvailablePages, VirtualMemoryBytesCommitted,
             VirtualMemoryBytesReserved, CachePagesCommitted, PoolPagesCommitted,
             StackPagesCommitted, ImagePagesCommitted;
} XbMmStatistics;

static uint32_t NTAPI_STDCALL_MmQueryStatistics(XbMmStatistics *MemoryStatistics) __attribute__((stdcall));
static uint32_t NTAPI_STDCALL_MmQueryStatistics(XbMmStatistics *MemoryStatistics) {
    if (!MemoryStatistics) return 0xC000000Du; // STATUS_INVALID_PARAMETER
    if (MemoryStatistics->Length != sizeof(XbMmStatistics)) {
        fprintf(stderr, "MmQueryStatistics: unusual Length 0x%x\n", MemoryStatistics->Length);
        return 0xC000000Du;
    }
    MemoryStatistics->TotalPhysicalPages = 0x4000;          // 64MB / 4KB pages
    MemoryStatistics->AvailablePages = 0x2000;               // placeholder: half free
    MemoryStatistics->VirtualMemoryBytesCommitted = 0;
    MemoryStatistics->VirtualMemoryBytesReserved = 0;
    MemoryStatistics->CachePagesCommitted = 0;
    MemoryStatistics->PoolPagesCommitted = 0;
    MemoryStatistics->StackPagesCommitted = 0;
    MemoryStatistics->ImagePagesCommitted = 0;
    fprintf(stderr, "MmQueryStatistics() -> TotalPhysicalPages=0x%x AvailablePages=0x%x\n",
            MemoryStatistics->TotalPhysicalPages, MemoryStatistics->AvailablePages);
    return 0;
}

// ordinal -> real implementation, for the handful built so far. Everything
// else falls through to the generic stub table in kstubs.h.
static void *real_impl_for_ordinal(int ordinal) {
    switch (ordinal) {
        case 255: return (void *) NTAPI_STDCALL_PsCreateSystemThreadEx;      // PsCreateSystemThreadEx
        case 187: return (void *) NTAPI_STDCALL_NtClose;                     // NtClose
        case 291: return (void *) NTAPI_STDCALL_RtlInitializeCriticalSection; // RtlInitializeCriticalSection
        case 277: // RtlEnterCriticalSection
        case 278: return (void *) NTAPI_STDCALL_RtlEnterCriticalSection;      // RtlEnterCriticalSectionAndRegion (no APC concept here, same impl)
        case 294: // RtlLeaveCriticalSection
        case 295: return (void *) NTAPI_STDCALL_RtlLeaveCriticalSection;      // RtlLeaveCriticalSectionAndRegion (same)
        case 306: return (void *) NTAPI_STDCALL_RtlTryEnterCriticalSection;  // RtlTryEnterCriticalSection
        case 47:  return (void *) NTAPI_STDCALL_HalRegisterShutdownNotification; // HalRegisterShutdownNotification
        case 44:  return (void *) NTAPI_STDCALL_HalGetInterruptVector;      // HalGetInterruptVector
        case 46:  return (void *) NTAPI_STDCALL_HalReadWritePCISpace;       // HalReadWritePCISpace
        case 98:  return (void *) NTAPI_STDCALL_KeConnectInterrupt;         // KeConnectInterrupt
        case 109: return (void *) NTAPI_STDCALL_KeInitializeInterrupt;      // KeInitializeInterrupt
        case 107: return (void *) NTAPI_STDCALL_KeInitializeDpc;             // KeInitializeDpc
        case 113: return (void *) NTAPI_STDCALL_KeInitializeTimerEx;        // KeInitializeTimerEx
        case 24:  return (void *) NTAPI_STDCALL_ExQueryNonVolatileSetting;  // ExQueryNonVolatileSetting
        case 301: return (void *) NTAPI_STDCALL_RtlNtStatusToDosError;     // RtlNtStatusToDosError
        case 149: return (void *) NTAPI_STDCALL_KeSetTimer;                 // KeSetTimer
        case 184: return (void *) NTAPI_STDCALL_NtAllocateVirtualMemory;   // NtAllocateVirtualMemory
        case 199: return (void *) NTAPI_STDCALL_NtFreeVirtualMemory;       // NtFreeVirtualMemory
        case 202: return (void *) NTAPI_STDCALL_NtOpenFile;                 // NtOpenFile
        case 190: return (void *) NTAPI_STDCALL_NtCreateFile;               // NtCreateFile
        case 67:  return (void *) NTAPI_STDCALL_IoCreateSymbolicLink;       // IoCreateSymbolicLink
        case 69:  return (void *) NTAPI_STDCALL_IoDeleteSymbolicLink;       // IoDeleteSymbolicLink
        case 203: return (void *) NTAPI_STDCALL_NtOpenSymbolicLinkObject;   // NtOpenSymbolicLinkObject
        case 215: return (void *) NTAPI_STDCALL_NtQuerySymbolicLinkObject;  // NtQuerySymbolicLinkObject
        case 289: return (void *) NTAPI_STDCALL_RtlInitAnsiString;         // RtlInitAnsiString
        case 279: return (void *) NTAPI_STDCALL_RtlEqualString;             // RtlEqualString
        case 218: return (void *) NTAPI_STDCALL_NtQueryVolumeInformationFile; // NtQueryVolumeInformationFile
        case 211: return (void *) NTAPI_STDCALL_NtQueryInformationFile;    // NtQueryInformationFile
        case 226: return (void *) NTAPI_STDCALL_NtSetInformationFile;      // NtSetInformationFile
        case 219: return (void *) NTAPI_STDCALL_NtReadFile;                 // NtReadFile
        case 236: return (void *) NTAPI_STDCALL_NtWriteFile;                // NtWriteFile
        case 196: return (void *) NTAPI_STDCALL_NtDeviceIoControlFile;      // NtDeviceIoControlFile
        case 200: return (void *) NTAPI_STDCALL_NtFsControlFile;            // NtFsControlFile
        case 128: return (void *) NTAPI_STDCALL_KeQuerySystemTime;          // KeQuerySystemTime
        case 181: return (void *) NTAPI_STDCALL_MmQueryStatistics;          // MmQueryStatistics
        case 210: return (void *) NTAPI_STDCALL_NtQueryFullAttributesFile;  // NtQueryFullAttributesFile
        case 327: return (void *) NTAPI_STDCALL_XeLoadSection;              // XeLoadSection
        case 328: return (void *) NTAPI_STDCALL_XeUnloadSection;            // XeUnloadSection
        case 178: return (void *) NTAPI_STDCALL_MmPersistContiguousMemory;  // MmPersistContiguousMemory
        case 165: return (void *) NTAPI_STDCALL_MmAllocateContiguousMemory; // MmAllocateContiguousMemory
        case 166: return (void *) NTAPI_STDCALL_MmAllocateContiguousMemoryEx; // MmAllocateContiguousMemoryEx
        case 168: return (void *) NTAPI_STDCALL_MmClaimGpuInstanceMemory;   // MmClaimGpuInstanceMemory
        case 175: return (void *) NTAPI_STDCALL_MmLockUnlockBufferPages;    // MmLockUnlockBufferPages
        case 173: return (void *) NTAPI_STDCALL_MmGetPhysicalAddress;       // MmGetPhysicalAddress
        case 151: return (void *) NTAPI_STDCALL_KeStallExecutionProcessor;  // KeStallExecutionProcessor
        case 14:  return (void *) NTAPI_STDCALL_ExAllocatePool;             // ExAllocatePool
        case 15:  return (void *) NTAPI_STDCALL_ExAllocatePoolWithTag;      // ExAllocatePoolWithTag
        case 17:  return (void *) NTAPI_STDCALL_ExFreePool;                 // ExFreePool
        case 23:  return (void *) NTAPI_STDCALL_ExQueryPoolBlockSize;       // ExQueryPoolBlockSize
        case 180: return (void *) NTAPI_STDCALL_MmQueryAllocationSize;      // MmQueryAllocationSize
        case 2:   return (void *) NTAPI_STDCALL_AvSendTVEncoderOption;      // AvSendTVEncoderOption
        case 37:  return (void *) NTAPI_STDCALL_FscSetCacheSize;            // FscSetCacheSize
        case 129: return (void *) NTAPI_STDCALL_KeRaiseIrqlToDpcLevel;      // KeRaiseIrqlToDpcLevel
        case 160: return (void *) NTAPI_FASTCALL_KfRaiseIrql;               // KfRaiseIrql (fastcall!)
        case 161: return (void *) NTAPI_FASTCALL_KfLowerIrql;               // KfLowerIrql (fastcall!)
        case 171: return (void *) NTAPI_STDCALL_MmFreeContiguousMemory;     // MmFreeContiguousMemory
        case 49:  return (void *) NTAPI_STDCALL_HalReturnToFirmware;       // HalReturnToFirmware
        default:  return NULL;
    }
}

typedef struct {
    char name[40];
    uint32_t flags, rva, vsize, raw, rawsz;
} Section;

static uint8_t *file_buf;
static size_t file_len;

static uint32_t rd32(size_t off) {
    uint32_t v;
    memcpy(&v, file_buf + off, 4);
    return v;
}

static const char *cstr_at(size_t off) {
    return (const char *) (file_buf + off);
}

void kstub_hit(int ordinal, const char *name) {
    fprintf(stderr,
        "\n"
        "=== unimplemented xboxkrnl function called: %s (ordinal %d) ===\n"
        "This is the next real kernel function to implement.\n"
        "(return address not unwound in this v1 - check a disassembly/gdb\n"
        "backtrace for the exact caller if needed)\n",
        name, ordinal);
    _exit(1);
}

#include "kstubs.h"

// Synchronous NV2A register-read interception. Confirmed live (gdb +
// disassembly, not guessed) that FUN_0017c270 and FUN_0017f46f mutually
// recurse without bound through register 0xFD400100 ("is the channel
// busy"): FUN_0017c270 writes 0x1000 there then calls FUN_0017f46f, which
// immediately re-reads the SAME register and, seeing it non-zero, calls
// straight back into FUN_0017c270 - forever, since nothing here ever clears
// it. Every other NV2A hardware-wait fixed so far (PFB flush, DMA fence)
// involved an actual polling LOOP, giving a background watcher thread a
// window to intervene before the guest rechecked. This one doesn't: it's a
// straight-line read-and-branch with no loop, so nothing can race in ahead
// of the recheck. The only correct fix is synchronous: trap every access to
// the containing page (mprotect(PROT_NONE)) and emulate it, forcing THIS
// ONE register's value to always read as 0 ("never busy") while every other
// register on the same page behaves like ordinary memory via a backing
// shadow buffer. Decoding is deliberately narrow, not a general x86
// decoder: catalogued every unique instruction form that touches this page
// across all three call sites via byte-level disassembly first - MOV
// load/store/store-imm (0x8B/0x89/0xC7) and direct-memory CMP against an
// imm8 (0x83 /7) or a register in either operand order (0x39/0x3B), ModRM
// mod 00/01/10 (no-disp/disp8/disp32), no SIB, dword operands only - and
// anything outside
// that known set falls through to the ordinary crash-and-diagnose path
// below rather than being guessed at.
#define NV2A_BASE 0xFD000000u
#define NV2A_TRAP_PAGE_START (NV2A_BASE + 0x400000u)
#define NV2A_TRAP_PAGE_LEN   0x1000u
#define NV2A_CHANNEL_BUSY_REG (NV2A_BASE + 0x400100u)
static uint8_t g_nv2a_trap_shadow[NV2A_TRAP_PAGE_LEN];

// x86 general-register encoding order (0-7) as used in ModRM reg/rm fields,
// mapped to this platform's REG_* ucontext indices.
static const int NV2A_TRAP_REGMAP[8] = { REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI };

typedef enum { NV2A_OP_LOAD, NV2A_OP_STORE, NV2A_OP_CMP } Nv2aTrapOpKind;

// Decodes one of the narrow set of instruction forms seen touching the
// trapped page. Returns 1 on success (filling in *kind, *reg_index (LOAD) /
// *imm_value (STORE-imm/CMP) / *reg_index (STORE-reg), *ilen), 0 if this
// instruction isn't one of the known forms (caller should treat the fault
// as a real bug in that case).
static int nv2a_trap_decode(uint8_t *pc, Nv2aTrapOpKind *kind, int *reg_index, uint32_t *imm_value,
                             int *cmp_mem_is_left, int *ilen) {
    uint8_t op = pc[0];
    if (op != 0x8B && op != 0x89 && op != 0xC7 && op != 0x83 && op != 0x39 && op != 0x3B) return 0;
    uint8_t modrm = pc[1];
    uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 7u;
    uint8_t rm = modrm & 7u;
    if (mod == 0 && rm == 5) return 0; // disp32-only (no base reg) - not seen, not handled
    int disp_len = (mod == 1) ? 1 : (mod == 2) ? 4 : 0; // mod 00/01/10 = no-disp/disp8/disp32
    int sib_len = 0;
    if (rm == 4) { // SIB byte present (e.g. [base+index*scale+disp]) - address itself comes
        sib_len = 1; // from si_addr regardless, this is only to get the length right
        uint8_t sib = pc[2];
        uint8_t sib_base = sib & 7u;
        if (mod == 0 && sib_base == 5) disp_len = 4; // SIB's own "no base register" special case
    }
    int header_len = 2 + sib_len + disp_len;
    if (op == 0xC7) {
        if (reg != 0) return 0; // only the plain-MOV /0 form of 0xC7 is used here
        *kind = NV2A_OP_STORE;
        memcpy(imm_value, pc + header_len, 4);
        *ilen = header_len + 4;
        return 1;
    }
    if (op == 0x83) {
        if (reg != 7) return 0; // only /7 (CMP r/m32, imm8) seen - not ADD/OR/AND/etc
        *kind = NV2A_OP_CMP;
        *imm_value = (uint32_t) (int32_t) (int8_t) pc[header_len]; // sign-extended imm8
        *cmp_mem_is_left = 1; // CMP r/m32, imm8 => r/m - imm
        *ilen = header_len + 1;
        return 1;
    }
    if (op == 0x39 || op == 0x3B) { // CMP r/m32,r32 (0x39: mem-reg) / CMP r32,r/m32 (0x3B: reg-mem)
        *kind = NV2A_OP_CMP;
        *reg_index = reg;
        *cmp_mem_is_left = (op == 0x39);
        *ilen = header_len;
        return 1;
    }
    *reg_index = reg;
    *kind = (op == 0x89) ? NV2A_OP_STORE : NV2A_OP_LOAD;
    *ilen = header_len;
    return 1;
}

// Returns 1 and emulates the access (advancing EIP) if this fault is inside
// the trapped NV2A page and decodes cleanly; 0 otherwise (caller falls
// through to the normal diagnostic/crash path).
static int nv2a_trap_handle(ucontext_t *uc, void *fault_addr_v) {
    uintptr_t fault_addr = (uintptr_t) fault_addr_v;
    if (fault_addr < NV2A_TRAP_PAGE_START || fault_addr >= NV2A_TRAP_PAGE_START + NV2A_TRAP_PAGE_LEN) return 0;

    uint8_t *pc = (uint8_t *) (uintptr_t) uc->uc_mcontext.gregs[REG_EIP];
    Nv2aTrapOpKind kind;
    int reg_index = 0, ilen, cmp_mem_is_left = 0;
    uint32_t imm_value = 0;
    if (!nv2a_trap_decode(pc, &kind, &reg_index, &imm_value, &cmp_mem_is_left, &ilen)) return 0;

    uint32_t offset = (uint32_t) (fault_addr - NV2A_TRAP_PAGE_START);
    uint32_t current;
    memcpy(&current, &g_nv2a_trap_shadow[offset], 4);
    if (fault_addr == NV2A_CHANNEL_BUSY_REG) current = 0; // "the channel is never busy" - see block comment above

    if (kind == NV2A_OP_STORE) {
        uint32_t val = (pc[0] == 0xC7) ? imm_value : (uint32_t) uc->uc_mcontext.gregs[NV2A_TRAP_REGMAP[reg_index]];
        memcpy(&g_nv2a_trap_shadow[offset], &val, 4);
    } else if (kind == NV2A_OP_LOAD) {
        uc->uc_mcontext.gregs[NV2A_TRAP_REGMAP[reg_index]] = (int) current;
    } else { // NV2A_OP_CMP: SUB, discard result, set flags only
        uint32_t reg_val = (pc[0] == 0x83) ? imm_value : (uint32_t) uc->uc_mcontext.gregs[NV2A_TRAP_REGMAP[reg_index]];
        uint32_t a = cmp_mem_is_left ? current : reg_val;
        uint32_t b = cmp_mem_is_left ? reg_val : current;
        uint32_t result = a - b;
        uint32_t sign_a = a >> 31, sign_b = b >> 31, sign_r = result >> 31;
        uint32_t eflags = (uint32_t) uc->uc_mcontext.gregs[REG_EFL];
        eflags &= ~(uint32_t) (0x0001u /*CF*/ | 0x0040u /*ZF*/ | 0x0080u /*SF*/ | 0x0800u /*OF*/ | 0x0004u /*PF*/);
        if (a < b) eflags |= 0x0001u;
        if (result == 0) eflags |= 0x0040u;
        if (sign_r) eflags |= 0x0080u;
        if (sign_a != sign_b && sign_r != sign_a) eflags |= 0x0800u;
        uint8_t low = (uint8_t) result;
        low ^= low >> 4; low ^= low >> 2; low ^= low >> 1;
        if ((low & 1) == 0) eflags |= 0x0004u; // PF: set when low byte has EVEN parity
        uc->uc_mcontext.gregs[REG_EFL] = (int) eflags;
    }
    uc->uc_mcontext.gregs[REG_EIP] += ilen;
    return 1;
}

// x86 port I/O trap handler. Real NV2A/chipset init code (seen live, right
// after the fake-MMIO fix let graphics init get this far) executes raw
// `IN`/`OUT` instructions against legacy I/O ports (e.g. `OUT DX, AL` to port
// 0x80C0) - unlike the memory-mapped register pokes, these are real x86
// instructions requiring IOPL/ioperm() privilege a normal unprivileged
// process doesn't have, so the CPU raises a GPF that the kernel delivers as
// SIGSEGV. Granting real port access (ioperm()) would need root and would be
// pointless anyway - there's no real chipset behind these ports. Same
// philosophy as the fake MMIO region: there's nothing to forward the access
// to, so trap the fault, decode just enough of the one faulting instruction
// to know its length and direction, emulate it as a no-op (OUT: discard the
// value; IN: return all-1-bits, a conventional "nothing here" read), and
// resume just past it. Anything that ISN'T one of these specific opcodes at
// the fault site falls through to the default handler, so a genuine bug
// still crashes and gets diagnosed the normal way, not silently hidden.
// Reads guest memory from inside the SIGSEGV handler without risking a
// nested fault. A plain dereference of a bad address there (e.g. decoding
// the instruction at EIP after a call through a NULL function pointer, where
// EIP itself is 0) faults again while SIGSEGV is blocked, and the kernel
// kills the process with zero diagnostics - the same "silent death" seen
// before with the KfRaiseIrql stack imbalance. process_vm_readv on our own
// pid just returns EFAULT for unmapped memory instead.
static int safe_read(uintptr_t addr, void *out, size_t len) {
    struct iovec local = { out, len }, remote = { (void *) addr, len };
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t) len;
}

// Linux refuses to map anything below vm.mmap_min_addr (65536 by default),
// and on real Xbox hardware nothing lives there either - any fault in this
// range is a NULL pointer (plus a small field offset) dereference, never a
// fixed-address assumption the auto-provision path should paper over.
#define NULL_GUARD_LIMIT 0x10000u

// Prints the top of the guest stack. When the fault is deep in game code
// (or a call through a NULL function pointer, where [ESP] is the return
// address right after the offending CALL), these are the caller addresses
// to look up in Ghidra - the most useful single clue for root-causing it.
static void dump_guest_stack(ucontext_t *uc) {
    uint32_t esp = (uint32_t) uc->uc_mcontext.gregs[REG_ESP];
    uint32_t words[12];
    if (!safe_read(esp, words, sizeof(words))) {
        fprintf(stderr, "  stack @ ESP=0x%x is unreadable\n", esp);
        return;
    }
    fprintf(stderr, "  stack @ ESP=0x%x:", esp);
    for (int i = 0; i < 12; i++) fprintf(stderr, "%s0x%08x", (i % 6 == 0) ? "\n    " : " ", words[i]);
    fprintf(stderr, "\n");
}

static void io_trap_handler(int sig, siginfo_t *si, void *ucontext_v) {
    (void) sig;
    ucontext_t *uc = (ucontext_t *) ucontext_v;

    if (nv2a_trap_handle(uc, si->si_addr)) return;

    // Copy the instruction bytes out fault-safely instead of dereferencing
    // EIP directly (see safe_read). Byte at a time so an instruction ending
    // right before an unmapped page still decodes; unreadable tail bytes
    // stay zero, which none of the opcodes below match on.
    uint32_t eip = (uint32_t) uc->uc_mcontext.gregs[REG_EIP];
    uint8_t pc[16] = { 0 };
    int pc_readable = 0;
    while (pc_readable < (int) sizeof(pc) && safe_read(eip + pc_readable, &pc[pc_readable], 1)) pc_readable++;
    if (pc_readable == 0) {
        // The instruction FETCH itself faulted: execution jumped somewhere
        // with no code - a call through a NULL/garbage function pointer, or
        // a RET onto a corrupted return address. [ESP] (for a CALL) is the
        // return address just past the CALL site that made the bad jump.
        fprintf(stderr,
                "\n[io-trap] EIP=0x%x is not executable/mapped (fault addr=%p) - %s\n"
                "  EAX=0x%x EBX=0x%x ECX=0x%x EDX=0x%x ESI=0x%x EDI=0x%x EBP=0x%x ESP=0x%x\n",
                eip, si->si_addr,
                eip < NULL_GUARD_LIMIT ? "call through a NULL function pointer (or RET to garbage)"
                                       : "jump/call to an unmapped address (or RET to garbage)",
                (unsigned) uc->uc_mcontext.gregs[REG_EAX], (unsigned) uc->uc_mcontext.gregs[REG_EBX],
                (unsigned) uc->uc_mcontext.gregs[REG_ECX], (unsigned) uc->uc_mcontext.gregs[REG_EDX],
                (unsigned) uc->uc_mcontext.gregs[REG_ESI], (unsigned) uc->uc_mcontext.gregs[REG_EDI],
                (unsigned) uc->uc_mcontext.gregs[REG_EBP], (unsigned) uc->uc_mcontext.gregs[REG_ESP]);
        dump_guest_stack(uc);
        fflush(stderr);
        signal(SIGSEGV, SIG_DFL);
        return;
    }

    int has66 = (pc[0] == 0x66);
    uint8_t op = pc[has66 ? 1 : 0];
    int is_in = (op == 0xEC || op == 0xED || op == 0xE4 || op == 0xE5);
    int is_out = (op == 0xEE || op == 0xEF || op == 0xE6 || op == 0xE7);
    int has_imm8 = (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7);
    int is_word = has66 && (op == 0xED || op == 0xEF || op == 0xE5 || op == 0xE7);

    // A handful of other privileged x86 instructions real chipset-init code
    // uses that also fault (#GP, delivered as SIGSEGV) at CPL3 with no
    // special privilege granted: WBINVD (cache flush - meaningless without
    // real hardware needing coherency), CLI/STI (interrupt-flag toggle -
    // meaningless without a real IDT this process's interrupts flow through),
    // HLT (halt until interrupt - nothing would ever wake it here). All are
    // safe no-ops for the same reason the port-I/O ones above are.
    int is_wbinvd = (pc[0] == 0x0F && pc[1] == 0x09);
    int is_cli_sti_hlt = (pc[0] == 0xFA || pc[0] == 0xFB || pc[0] == 0xF4);
    if (is_wbinvd || is_cli_sti_hlt) {
        int priv_len = is_wbinvd ? 2 : 1;
        fprintf(stderr, "[io-trap] privileged instruction (%s) at EIP=0x%x - no-op\n",
                is_wbinvd ? "WBINVD" : (pc[0] == 0xFA ? "CLI" : pc[0] == 0xFB ? "STI" : "HLT"),
                (unsigned) uc->uc_mcontext.gregs[REG_EIP]);
        uc->uc_mcontext.gregs[REG_EIP] += priv_len;
        return;
    }

    if (!is_in && !is_out) {
        // Not a privileged-instruction fault. If it's a genuine "nothing is
        // mapped here at all" fault (SEGV_MAPERR, not a protection
        // violation on memory that DOES exist), this is the same class of
        // problem as the fake-MMIO/fake-kernel-module regions above: some
        // Xbox-side address-space assumption (a fixed scratch/stack-like
        // region computed by the game's own thread-bootstrap code - found
        // live hitting this exact case, a plain PUSH to an unmapped,
        // page-aligned address inside interrupt-table-indexing code; not
        // fully reverse-engineered, but the fault class is unambiguous)
        // doesn't hold on this host. Rather than only patching each
        // specific address as discovered (an unbounded, whack-a-mole list),
        // generically provision a page-aligned RW region around the fault
        // address on first touch and retry the SAME instruction - safe
        // specifically because MAPERR means there was no real data there to
        // clobber. A genuine protection-violation bug (SEGV_ACCERR, writing
        // to memory that exists but is read-only, etc.) still falls through
        // to the diagnostic-and-crash path below, so a real bug is never
        // silently hidden this way.
        // Capped, not unconditional: this was found live to mask a genuine,
        // CONFIRMED unbounded-recursion bug (FUN_0017c270 <-> FUN_0017f46f
        // mutually recursing through a hardware-completion register,
        // 0xFD400100 bit 0x1000, that nothing here ever clears - real
        // hardware would service it asynchronously between the two calls,
        // but there is no yield point in that path for a watcher thread to
        // exploit the way the PFB-flush/fence-ack fixes do). Verified by
        // temporarily also auto-healing SEGV_ACCERR the same way: the
        // recursion just kept cycling through the same handful of EIPs
        // (0x17f484 <-> 0x17c273 <-> 0x17f472 ...), consuming a fresh 256KB
        // stack page every single level with no sign of terminating on its
        // own - genuinely infinite, not just deep, given this host's memory.
        // Fixing this for real needs synchronous read interception on that
        // one register (page-granular mprotect(PROT_NONE) + decode-and-
        // emulate the handful of instruction forms that touch it) so it
        // reads back "already done" the instant it's checked - a real,
        // scoped next step, not something a background poll can reach,
        // reverted back to ACCERR-always-fatal here. A generous but finite
        // cap keeps the MAPERR path useful for genuine one-off "Xbox
        // assumed this address exists" cases while still surfacing a real
        // runaway as a crash, not unbounded memory growth.
        // Never auto-provision the NULL guard range. Found live: a plain
        // NULL dereference (si_addr == 0) came in here as SEGV_MAPERR like
        // any other unmapped address, and the downward-window math below
        // underflowed (0 - 0x40000 + 0x1000 = 0xFFFC1000), so MAP_FIXED was
        // asked for a range that wraps past 4GB and failed. That printed an
        // "auto-provision mmap failed" line that looked like the root cause
        // and hid the real NULL pointer bug behind it.
        static int auto_provision_count = 0;
        if (si->si_code == SEGV_MAPERR && (uintptr_t) si->si_addr < NULL_GUARD_LIMIT) {
            fprintf(stderr, "[io-trap] fault addr %p is in the NULL guard range - NULL pointer "
                    "dereference, not a fixed-address assumption; not auto-provisioning\n", si->si_addr);
        } else if (si->si_code == SEGV_MAPERR && auto_provision_count < 64) {
            auto_provision_count++;
            uintptr_t fault_addr = (uintptr_t) si->si_addr;
            long pagesz = sysconf(_SC_PAGESIZE);
            // This is a stack-growth fault (confirmed live: the triggering
            // instructions are PUSH/CALL), so memory ABOVE the fault address
            // is the thread's existing, already-in-use stack - a real bug in
            // an earlier version of this fix extended the mapped window
            // upward past the fault point too, which silently clobbered that
            // live stack content via MAP_FIXED (discarding real return
            // addresses/locals) and caused an immediate second, unrelated-
            // looking crash. Only ever extend downward, up to and including
            // the fault's own page - never past it.
            uintptr_t fault_page = fault_addr & ~(uintptr_t) (pagesz - 1);
            size_t region_len = (size_t) pagesz * 64;
            // Clamp the window's bottom at NULL_GUARD_LIMIT instead of
            // letting `fault_page - region_len` wrap for a fault just above it.
            uintptr_t region_start = (fault_page >= NULL_GUARD_LIMIT + region_len - (uintptr_t) pagesz)
                                         ? fault_page - region_len + (uintptr_t) pagesz
                                         : NULL_GUARD_LIMIT;
            region_len = fault_page + (uintptr_t) pagesz - region_start;
            void *mapped = mmap((void *) region_start, region_len, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            if (mapped != MAP_FAILED) {
                fprintf(stderr,
                        "[io-trap] unmapped-memory fault at EIP=0x%x, addr=%p - auto-provisioned "
                        "0x%zx bytes at %p (Xbox-side fixed-address assumption, no real data lost here)\n",
                        (unsigned) uc->uc_mcontext.gregs[REG_EIP], si->si_addr, region_len, mapped);
                return; // retry the faulting instruction now that the page exists
            }
            fprintf(stderr, "[io-trap] auto-provision mmap failed: %s (EIP=0x%x, fault addr=%p, wanted region=0x%x len=0x%zx)\n",
                    strerror(errno), (unsigned) uc->uc_mcontext.gregs[REG_EIP], si->si_addr,
                    (unsigned) region_start, region_len);
        }

        // Anything else - a real bug, not a hardware-access fault this
        // handler knows how to absorb. Print diagnostics directly (don't
        // just silently fall through to the default handler - gdb's own
        // SIGSEGV interception can otherwise swallow the backtrace entirely
        // once disposition is reset) then restore the default handler and
        // re-raise, so a core still gets generated for post-mortem analysis.
        uint32_t moffs_addr;
        memcpy(&moffs_addr, pc + 1, 4);
        fprintf(stderr,
                "\n[io-trap] fault at EIP=0x%x is NOT a recognized IN/OUT opcode "
                "(bytes: %02x %02x %02x %02x %02x, fault addr=%p, if MOV-moffs target=0x%x) - this is a real bug\n"
                "  EAX=0x%x EBX=0x%x ECX=0x%x EDX=0x%x ESI=0x%x EDI=0x%x EBP=0x%x ESP=0x%x\n",
                (unsigned) uc->uc_mcontext.gregs[REG_EIP], pc[0], pc[1], pc[2], pc[3], pc[4],
                si->si_addr, moffs_addr,
                (unsigned) uc->uc_mcontext.gregs[REG_EAX], (unsigned) uc->uc_mcontext.gregs[REG_EBX],
                (unsigned) uc->uc_mcontext.gregs[REG_ECX], (unsigned) uc->uc_mcontext.gregs[REG_EDX],
                (unsigned) uc->uc_mcontext.gregs[REG_ESI], (unsigned) uc->uc_mcontext.gregs[REG_EDI],
                (unsigned) uc->uc_mcontext.gregs[REG_EBP], (unsigned) uc->uc_mcontext.gregs[REG_ESP]);
        dump_guest_stack(uc);
        fflush(stderr);
        signal(SIGSEGV, SIG_DFL);
        return;
    }

    uint32_t port = has_imm8 ? pc[has66 ? 2 : 1] : (uc->uc_mcontext.gregs[REG_EDX] & 0xFFFF);
    int ilen = (has66 ? 1 : 0) + 1 + (has_imm8 ? 1 : 0);

    if (is_out) {
        uint32_t val = uc->uc_mcontext.gregs[REG_EAX];
        fprintf(stderr, "[io-trap] OUT port=0x%x val=0x%x (%s) - discarded, no real hardware there\n",
                port, val, is_word ? "word" : (op == 0xE7 || op == 0xEF ? "dword" : "byte"));
    } else {
        uint32_t fill = is_word ? 0xFFFFu : (op == 0xED ? 0xFFFFFFFFu : 0xFFu);
        uc->uc_mcontext.gregs[REG_EAX] = (uc->uc_mcontext.gregs[REG_EAX] & ~0xFFFFFFFFu) | fill;
        fprintf(stderr, "[io-trap] IN port=0x%x -> 0x%x (no real hardware there)\n", port, fill);
    }
    uc->uc_mcontext.gregs[REG_EIP] += ilen;
}

static void install_io_trap_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = io_trap_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) perror("sigaction(SIGSEGV)");
}

// sigaltstack is per-thread on Linux (NPTL), not process-wide - found live:
// a fault whose ESP had already been swapped to a bogus, unmapped address
// by guest code (not organic stack growth - confirmed by the address being
// insensitive to this loader's own pthread stack size) meant the kernel
// couldn't push a signal frame onto the CURRENT (broken) stack to invoke
// our handler at all, so it fell back to killing the process with zero
// diagnostics printed - silent death even with a handler installed. Every
// thread that might run guest code needs its own alternate signal stack
// registered so SIGSEGV delivery still works even when the guest's own
// stack pointer is garbage.
static void install_altstack_for_this_thread(void) {
    size_t sz = SIGSTKSZ > 65536 ? (size_t) SIGSTKSZ : 65536;
    void *mem = malloc(sz);
    if (!mem) { perror("malloc altstack"); return; }
    stack_t ss = { .ss_sp = mem, .ss_size = sz, .ss_flags = 0 };
    if (sigaltstack(&ss, NULL) != 0) perror("sigaltstack");
}

// Real NV2A hardware completes a triggered operation and clears the
// "pending" bit itself; our fake MMIO region is just inert RAM, so a
// write-bit-then-poll-until-cleared handshake (seen live: graphics init sets
// bit 0x10000 at register offset 0x100410 - a real NV2A PFB flush-trigger
// register - then spins reading it back forever) never completes and hangs
// the thread. Rather than intercepting every possible MMIO read (would need
// mprotect(PROT_NONE) + a full per-instruction decode/emulate loop, real
// work for a problem this specific case doesn't need), a small watcher
// thread polls the known trigger bit and clears it almost immediately,
// simulating "hardware" finishing instantly. Extend this list as further
// self-clearing trigger registers are discovered the same way.
// A second real hardware-wait pattern found the same way (live disassembly
// at the exact loop, not decompile guessing - the decompiler's own variable
// naming here was actively misleading, see the comment at the loop's C-level
// caller): `MOV EDX,[EBX]` / `MOV EAX,[ECX+0x44]` where ECX is `[EBX+0x1c10]`
// = 0xFD800000 (a raw NV2A channel-control register address, not a struct
// pointer) - the CPU writes a target value into its own global at a fixed
// address (0x181e10, confirmed stable across runs - the XBE has no ASLR)
// and polls register 0xFD800044 waiting for "the GPU" to echo it back
// (NV2A's real DMA-channel notifier/fence-ack mechanism). Mirroring the
// target into the fake register continuously simulates the GPU completing
// instantly, the same philosophy as the PFB-flush fix above.
// A third real hardware-wait loop found the same way (live disassembly of
// the actual loop in FUN_0017c921, 0x17c9b1-0x17c9fc): it polls three status
// bytes (bit 0x10 each, at GPU-base-relative offsets 0x3214, 0x2400, 0x3220)
// and only breaks out once the first two are set AND the third is clear -
// otherwise it falls through to the bottom of the loop body (which re-checks
// the now-fixed channel-busy register, then unconditionally jumps back to
// the top) forever. Unlike the two mutual-recursion functions above, this
// IS a real polling loop (calls FUN_0017c320/FUN_0017bd00 every iteration),
// so a background watcher can win the race here, same as the PFB-flush and
// fence-ack fixes - just needs the right two bits asserted.
// A fourth real hardware-wait loop, this time from the audio/APU side, not
// NV2A (found live via gdb attach + disassembly on the stuck thread, not
// guessed): `do {} while ((*(uint*)0xFE820010 & 0xFFFFFFFC) < 0x20);` - a
// classic "wait for at least N units of free space in the DMA FIFO before
// writing" hardware handshake (the masked-low-bits-then-compare pattern is
// the real hardware's own status-register convention, not an artifact of
// this loader). This register lives in the auto-provisioned MAPERR region
// (0xFE8xxxxx, the AC97/audio-DAC aperture auto-mapped the same way as the
// first NV2A MMIO pokes), not the fixed nv2a_fake mapping, but writing to it
// is safe regardless of mapping order - a write before the game's own first
// touch just causes the SAME auto-provision machinery to run from this
// thread instead, which is equally safe.
#define AUDIO_FIFO_FREE_SPACE_ADDR 0xFE820010u
#define GAME_FENCE_TARGET_ADDR 0x181e10u
#define NV2A_CHANNEL_FENCE_ACK_OFFSET 0x800044u
#define NV2A_CHANNEL_STATUS_A_OFFSET 0x3214u
#define NV2A_CHANNEL_STATUS_B_OFFSET 0x2400u
static void *nv2a_mmio_watcher(void *arg) {
    (void) arg;
    volatile uint32_t *pfb_flush = (volatile uint32_t *) (uintptr_t) (NV2A_BASE + 0x100410);
    volatile uint32_t *fence_target = (volatile uint32_t *) (uintptr_t) GAME_FENCE_TARGET_ADDR;
    volatile uint32_t *fence_ack = (volatile uint32_t *) (uintptr_t) (NV2A_BASE + NV2A_CHANNEL_FENCE_ACK_OFFSET);
    volatile uint8_t *status_a = (volatile uint8_t *) (uintptr_t) (NV2A_BASE + NV2A_CHANNEL_STATUS_A_OFFSET);
    volatile uint8_t *status_b = (volatile uint8_t *) (uintptr_t) (NV2A_BASE + NV2A_CHANNEL_STATUS_B_OFFSET);
    volatile uint32_t *audio_fifo_free = (volatile uint32_t *) (uintptr_t) AUDIO_FIFO_FREE_SPACE_ADDR;
    for (;;) {
        if (*pfb_flush & 0x10000u) *pfb_flush &= ~0x10000u;
        *fence_ack = *fence_target;
        *status_a |= 0x10u;
        *status_b |= 0x10u;
        *audio_fifo_free = 0xFFFFFFFFu; // "FIFO always has room" - see block comment above
        usleep(1000);
    }
    return NULL;
}

int main(void) {
    install_io_trap_handler();
    install_altstack_for_this_thread();
    int fd = open(XBE_PATH, O_RDONLY);
    if (fd < 0) { perror("open xbe"); return 1; }
    struct stat st;
    fstat(fd, &st);
    file_len = (size_t) st.st_size;
    file_buf = malloc(file_len);
    if (!file_buf) { fprintf(stderr, "malloc failed\n"); return 1; }
    if (read(fd, file_buf, file_len) != (ssize_t) file_len) {
        perror("read xbe"); return 1;
    }
    close(fd);

    uint32_t base      = rd32(0x104);
    uint32_t hdr_len    = rd32(0x108);
    uint32_t nsec       = rd32(0x11C);
    uint32_t sec_hdr_rva = rd32(0x120);
    uint32_t table_off  = sec_hdr_rva - base;
    uint32_t ep_enc     = rd32(0x128);
    uint32_t kt_enc     = rd32(0x158);
    uint32_t entry_va   = ep_enc ^ XOR_EP_RETAIL;
    uint32_t kthunk_va  = kt_enc ^ XOR_KT_RETAIL;
    g_entry_va = entry_va; // HalReturnToFirmware(QuickReboot) re-invokes this directly

    printf("XBE base=0x%x hdr_len=0x%x sections=%u entry=0x%x kthunk=0x%x\n",
           base, hdr_len, nsec, entry_va, kthunk_va);

    Section *secs = calloc(nsec, sizeof(Section));
    uint32_t img_min = base, img_max = base + hdr_len;

    for (uint32_t i = 0; i < nsec; i++) {
        size_t o = table_off + i * 0x38;
        uint32_t flags, rva, vsize, raw, rawsz, nameaddr;
        flags = rd32(o + 0x00);
        rva = rd32(o + 0x04);
        vsize = rd32(o + 0x08);
        raw = rd32(o + 0x0C);
        rawsz = rd32(o + 0x10);
        nameaddr = rd32(o + 0x14);
        Section *s = &secs[i];
        s->flags = flags; s->rva = rva; s->vsize = vsize;
        s->raw = raw; s->rawsz = rawsz;
        if (nameaddr) {
            snprintf(s->name, sizeof(s->name), "%s", cstr_at(nameaddr - base));
        } else {
            snprintf(s->name, sizeof(s->name), "sec%u", i);
        }
        if (rva < img_min) img_min = rva;
        if (rva + vsize > img_max) img_max = rva + vsize;
    }

    long pagesz = sysconf(_SC_PAGESIZE);
    uint32_t region_start = img_min & ~(pagesz - 1);
    uint32_t region_end = (img_max + pagesz - 1) & ~(pagesz - 1);
    size_t region_len = region_end - region_start;

    printf("mapping image region 0x%x - 0x%x (%zu bytes) as RWX\n",
           region_start, region_end, region_len);

    void *mapped = mmap((void *) (uintptr_t) region_start, region_len,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED) { perror("mmap image region"); return 1; }
    if ((uintptr_t) mapped != region_start) {
        fprintf(stderr, "mmap did not honor MAP_FIXED address (got %p, wanted 0x%x) "
                "- another mapping must already occupy this range\n",
                mapped, region_start);
        return 1;
    }

    // Real Xbox hardware maps xboxkrnl.exe itself at a fixed address around
    // 0x80010000. Some CRT static initializers probe it directly (seen live:
    // reads at [0x8001003c], derived offsets back to ~0x80010000, checking a
    // PE section for the 4-byte magic "INIT") - presumably a debug/feature-
    // detection hook, not core game logic. Rather than synthesizing a fake
    // kernel PE image (a much bigger, speculative undertaking), map this
    // region as zeroed/readable: the probe's own magic-number check then
    // naturally fails and it takes its existing "not present" path. Observed
    // behavior only goes a little below/above 0x80010000, so one generous
    // page-aligned region covers it with margin.
    // Also writable: 0x80000000 is also the cached alias of physical address
    // 0 on real hardware (a separate, unrelated convention from the kernel
    // probe above, both just happening to land in the same low region) -
    // graphics-init code was seen live writing a just-allocated buffer's
    // address to exactly 0x80000000, presumably a fixed low-memory handoff
    // slot some other subsystem reads back from. Write permission doesn't
    // change the probe's behavior (it only ever reads), so one region safely
    // serves both purposes.
    void *kmod_fake = mmap((void *) 0x80000000u, 0x20000,
                            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (kmod_fake == MAP_FAILED) {
        perror("mmap fake kernel module region");
        return 1;
    }

    // Same technique, different real hardware: the NV2A GPU's MMIO register
    // aperture lives at a fixed physical address starting at 0xFD000000 on
    // real Xbox hardware, and graphics-init code (seen live: a spawned
    // thread writing directly to 0xfd001804/0xfd600140/0xfd009140 and
    // segfaulting) pokes it directly as plain memory rather than through any
    // kernel call this loader could intercept. No real GPU exists in this
    // process, so there is nothing to forward these writes to yet - mapping
    // this range as ordinary RW memory makes the pokes land somewhere safe
    // (silently absorbed, reads back as whatever was last written/zero)
    // instead of crashing, which is step one toward seeing how much further
    // real game code runs before it needs actual rendered output. 16MB
    // covers the real NV2A's full register aperture (PMC/PFIFO/PGRAPH/
    // PCRTC/PRAMIN/etc. all live within that span on real hardware).
    void *nv2a_fake = mmap((void *) 0xFD000000u, 0x1000000,
                            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (nv2a_fake == MAP_FAILED) {
        perror("mmap fake NV2A MMIO region");
        return 1;
    }
    pthread_t nv2a_watcher_tid;
    if (pthread_create(&nv2a_watcher_tid, NULL, nv2a_mmio_watcher, NULL) != 0) {
        perror("pthread_create nv2a_mmio_watcher");
        return 1;
    }
    pthread_detach(nv2a_watcher_tid);

    // Carve the one page containing the "channel busy" register (0xFD400100)
    // out of the otherwise-plain-RW NV2A region and trap it for synchronous
    // emulation - see nv2a_trap_handle's block comment for why this
    // particular register needs that instead of the background-watcher
    // approach everything else on this page uses.
    if (mprotect((void *) (uintptr_t) NV2A_TRAP_PAGE_START, NV2A_TRAP_PAGE_LEN, PROT_NONE) != 0) {
        perror("mprotect nv2a register trap page");
        return 1;
    }

    // header
    memcpy((void *) (uintptr_t) base, file_buf, hdr_len);
    // sections
    for (uint32_t i = 0; i < nsec; i++) {
        Section *s = &secs[i];
        size_t copy_len = s->rawsz < s->vsize ? s->rawsz : s->vsize;
        if (copy_len > 0) {
            memcpy((void *) (uintptr_t) s->rva, file_buf + s->raw, copy_len);
        }
        printf("  loaded %-18s va=0x%-8x vsize=0x%-8x raw=0x%-8x rawsz=0x%-8x\n",
               s->name, s->rva, s->vsize, s->raw, s->rawsz);
    }

    // patch the kernel image thunk table: ordinals with a real implementation
    // (see real_impl_for_ordinal above) get that; everything else gets the
    // generic stub, which reports what was called and exits.
    uint32_t *kthunk = (uint32_t *) (uintptr_t) kthunk_va;
    int patched = 0, real_count = 0;
    for (int i = 0; i < 512; i++) {
        uint32_t v = kthunk[i];
        if (v == 0) break;
        if (v & 0x80000000u) {
            int ordinal = (int) (v & 0x7FFFFFFFu);
            void *data_slot = data_storage_for_ordinal(ordinal);
            if (data_slot) {
                kthunk[i] = (uint32_t) (uintptr_t) data_slot;
                patched++; real_count++;
                continue;
            }
            void *real = real_impl_for_ordinal(ordinal);
            void *fn = real ? real : (ordinal >= 0 && ordinal <= KSTUB_MAX ? (void *) KSTUB_TABLE[ordinal] : NULL);
            if (fn) {
                kthunk[i] = (uint32_t) (uintptr_t) fn;
                patched++;
                if (real) real_count++;
            } else {
                fprintf(stderr, "kernel thunk[%d]: ordinal %d has no stub (out of range)\n",
                        i, ordinal);
            }
        } else {
            fprintf(stderr, "kernel thunk[%d]: value 0x%x is not ordinal-tagged (unexpected)\n",
                    i, v);
        }
    }
    printf("patched %d kernel thunk slots (%d with real implementations, %d stubbed)\n",
           patched, real_count, patched - real_count);

    setup_fs_tib_for_this_thread();

    printf("FS set up, jumping to entry() at 0x%x\n\n", entry_va);
    fflush(stdout);

    void (*entry_fn)(void) = (void (*)(void)) (uintptr_t) entry_va;
    entry_fn();

    // entry() returning here is normal, not an error: per its own decompile,
    // it creates its one real system thread, closes its own handle to it,
    // and returns - the real work happens in that thread (and in whatever
    // threads a HalReturnToFirmware quick-reboot creates afterward). Wait
    // for all of them, tracked in the global g_threads[] table that every
    // PsCreateSystemThreadEx call (pre- or post-reboot) appends to.
    printf("entry() returned (normal) - waiting on spawned thread(s) so they get a chance to run...\n");
    wait_for_all_threads();
    return 0;
}
