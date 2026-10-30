/* Linux ARM EABI metadata reader. No libc, privilege changes or device writes.
 * Syscall numbers: Linux v4.9 arch/arm/include/uapi/asm/unistd.h.
 * Only stdout is written. Targets/attributes are compile-time constants.
 */
#ifdef PROBE_HOST_TEST
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#define N_WRITE SYS_write
#define N_EXIT SYS_exit
#define N_OPEN SYS_open
#define N_READ SYS_read
#define N_CLOSE SYS_close
#define N_UID SYS_getuid
#define N_EUID SYS_geteuid
#define N_GROUPS SYS_getgroups
#define N_XATTR SYS_getxattr
#define N_ACCESS SYS_access
#define N_CAPGET SYS_capget
static long call4(long n, long a, long b, long c, long d) {
    long r = syscall(n, a, b, c, d);
    return r == -1 ? -errno : r;
}
#elif defined(__arm__) && defined(__ARM_EABI__)
#define N_WRITE 4
#define N_EXIT 1
#define N_OPEN 5
#define N_READ 3
#define N_CLOSE 6
#define N_UID 199
#define N_EUID 201
#define N_GROUPS 205
#define N_XATTR 229
#define N_ACCESS 33
#define N_CAPGET 184
static long call4(long n, long a, long b, long c, long d) {
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r7 __asm__("r7") = n;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r7) : "memory", "cc");
    return r0;
}
#else
#error "ARM EABI required (PROBE_HOST_TEST is for local tests only)"
#endif

#ifndef PROBE_TEST_PREFIX
#define PROBE_TEST_PREFIX ""
#endif
static const char *paths[] = {
    "/usr/bin/fota-consumer", "/usr/bin/oma-dm-agent", "/usr/bin/launch_app",
    "/usr/bin/recovery-update.sh", "/usr/bin/rw-update-prepare.sh",
    "/usr/bin/rw-update-systemd.sh", "/opt/usr/data/fota/save", "/opt/data/recovery"
};
static const char *actual[] = {
    PROBE_TEST_PREFIX "/usr/bin/fota-consumer", PROBE_TEST_PREFIX "/usr/bin/oma-dm-agent",
    PROBE_TEST_PREFIX "/usr/bin/launch_app", PROBE_TEST_PREFIX "/usr/bin/recovery-update.sh",
    PROBE_TEST_PREFIX "/usr/bin/rw-update-prepare.sh", PROBE_TEST_PREFIX "/usr/bin/rw-update-systemd.sh",
    PROBE_TEST_PREFIX "/opt/usr/data/fota/save", PROBE_TEST_PREFIX "/opt/data/recovery"
};
static const char *attrs[] = {"security.capability", "security.SMACK64", "security.SMACK64EXEC"
#ifdef PROBE_TEST
    , "user.uglyos_fixture"
#endif
};
static unsigned char buf[256];
static unsigned int groups[128];
static unsigned int cap_header[2] = {0x20080522, 0};
static unsigned int cap_data[6];
static char output[32768];
static unsigned int used;
static void stop(int rc) { call4(N_EXIT, rc, 0, 0, 0); for (;;) {} }
static void outn(const char *s, unsigned int n) {
    if (n > sizeof(output) - used) stop(2);
    for (unsigned int i = 0; i < n; ++i) output[used++] = s[i];
}
static void flush(void) {
    const char *s = output; unsigned int n = used;
    while (n) {
        long r = call4(N_WRITE, 1, (long)s, n, 0);
        if (r == -4) continue;
        if (r <= 0) stop(2);
        s += r; n -= (unsigned int)r;
    }
}
static void out(const char *s) { unsigned int n = 0; while (s[n]) ++n; outn(s, n); }
static void number(long v) {
    char b[24]; unsigned int n = 0; unsigned long u;
    if (v < 0) { out("-"); u = 0UL - (unsigned long)v; } else u = (unsigned long)v;
    do { b[n++] = '0' + u % 10; u /= 10; } while (u);
    while (n) outn(&b[--n], 1);
}
static void hex(long n) {
    static const char digits[] = "0123456789abcdef";
    for (long i = 0; i < n; ++i) { char b[2] = {digits[buf[i] >> 4], digits[buf[i] & 15]}; outn(b, 2); }
}
static void mask(unsigned int lo, unsigned int hi) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4) outn(&digits[(hi >> i) & 15], 1);
    for (int i = 28; i >= 0; i -= 4) outn(&digits[(lo >> i) & 15], 1);
}
static int run(void) {
    out("{\"schema\":\"uglyos-watch3-security-metadata-v1\",\"test_fixture\":");
#ifdef PROBE_TEST
    out("true");
#else
    out("false");
#endif
    out(",\"uid\":"); number(call4(N_UID, 0, 0, 0, 0));
    out(",\"euid\":"); number(call4(N_EUID, 0, 0, 0, 0));
    long cr = call4(N_CAPGET, (long)cap_header, (long)cap_data, 0, 0);
    out(",\"capget_rc\":"); number(cr);
    out(",\"effective_caps_hex\":\""); if (!cr) mask(cap_data[0], cap_data[3]);
    out("\",\"permitted_caps_hex\":\""); if (!cr) mask(cap_data[1], cap_data[4]);
    out("\",\"inheritable_caps_hex\":\""); if (!cr) mask(cap_data[2], cap_data[5]); out("\"");
    long g = call4(N_GROUPS, 128, (long)groups, 0, 0);
    out(",\"groups_rc\":"); number(g); out(",\"groups\":[");
    if (g > 0 && g <= 128) for (long i = 0; i < g; ++i) { if (i) out(","); number(groups[i]); }
    out("],\"current_label_rc\":");
    long fd = call4(N_OPEN, (long)"/proc/self/attr/current", 0, 0, 0);
    long n = fd < 0 ? fd : call4(N_READ, fd, (long)buf, sizeof(buf), 0);
    if (fd >= 0) call4(N_CLOSE, fd, 0, 0, 0);
    number(n); out(",\"current_label_hex\":\""); if (n > 0) hex(n); out("\",\"files\":[");
    for (unsigned int i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        if (i) { out(","); }
        out("{\"path\":\""); out(paths[i]); out("\",\"write_access_rc\":");
        number(call4(N_ACCESS, (long)actual[i], 2, 0, 0)); out(",\"attrs\":[");
        for (unsigned int j = 0; j < sizeof(attrs)/sizeof(attrs[0]); ++j) {
            if (j) { out(","); }
            out("{\"name\":\""); out(attrs[j]); out("\",\"rc\":");
            n = call4(N_XATTR, (long)actual[i], (long)attrs[j], (long)buf, sizeof(buf));
            number(n); out(",\"hex\":\""); if (n > 0 && n <= (long)sizeof(buf)) hex(n); out("\"}");
        }
        out("]}");
    }
    out("]}\n"); flush(); return 0;
}
#ifdef PROBE_HOST_TEST
int main(void) { return run(); }
#else
void _start(void) { stop(run()); }
#endif
