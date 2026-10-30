/* Linux ARM EABI metadata reader. No libc, privilege changes or device writes.
 * Syscall numbers: Linux v4.9 arch/arm/include/uapi/asm/unistd.h.
 * Only stdout is written. Targets/attributes are compile-time constants.
 */
#ifdef PROBE_HOST_TEST
#include <errno.h>
#include <sys/syscall.h>
#include <sys/stat.h>
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
#define N_DENTS SYS_getdents64
#define N_PRCTL SYS_prctl
static long call4(long n, long a, long b, long c, long d) {
    long r = syscall(n, a, b, c, d, 0L);
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
#define N_DENTS 217
#define N_PRCTL 172
#define N_LSTAT64 196
static long call4(long n, long a, long b, long c, long d) {
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r4 __asm__("r4") = 0; /* prctl GET_NO_NEW_PRIVS requires arg5=0. */
    register long r7 __asm__("r7") = n;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r7) : "memory", "cc");
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
#ifdef PROBE_INVENTORY
static char output[65536];
#else
static char output[32768];
#endif
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
#ifdef PROBE_INVENTORY
/* Nonrecursive system-helper metadata only. ARM stat64/dirent64 layout is
 * from Linux v4.9 asm/stat.h and include/linux/dirent.h. No helper executes.
 */
static const char *roots[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib"};
static const char *real_roots[] = {PROBE_TEST_PREFIX "/bin", PROBE_TEST_PREFIX "/sbin",
    PROBE_TEST_PREFIX "/usr/bin", PROBE_TEST_PREFIX "/usr/sbin",
    PROBE_TEST_PREFIX "/usr/libexec", PROBE_TEST_PREFIX "/usr/lib"};
static unsigned char dents[4096];
static unsigned char statbuf[104] __attribute__((aligned(8)));
static char filename[256], fullpath[1024];
static unsigned int inv_rows;
#ifndef PROBE_HOST_TEST
static unsigned int le32(const unsigned char *p) {
    return (unsigned int)p[0] | (unsigned int)p[1]<<8 | (unsigned int)p[2]<<16 | (unsigned int)p[3]<<24;
}
#endif
static int join_path(const char *root, const char *name) {
    unsigned int n=0, j=0;
    while (root[j]) { if (n+2 >= sizeof(fullpath)) return 0; fullpath[n++]=root[j++]; }
    fullpath[n++]='/'; j=0;
    while (name[j]) { if (n+1 >= sizeof(fullpath)) return 0; fullpath[n++]=name[j++]; }
    fullpath[n]=0; return 1;
}
static long file_stat(unsigned int *mode, unsigned int *uid, unsigned int *gid,
                      unsigned int *size_lo, unsigned int *size_hi) {
#ifdef PROBE_HOST_TEST
    struct stat s;
    if (lstat(fullpath, &s)) return -errno;
    *mode=s.st_mode; *uid=s.st_uid; *gid=s.st_gid;
    *size_lo=(unsigned int)s.st_size; *size_hi=(unsigned int)((unsigned long long)s.st_size >> 32);
    (void)statbuf;
#else
    long r=call4(N_LSTAT64, (long)fullpath, (long)statbuf, 0, 0);
    if (r) return r;
    *mode=le32(statbuf+16); *uid=le32(statbuf+24); *gid=le32(statbuf+28);
    *size_lo=le32(statbuf+48); *size_hi=le32(statbuf+52);
#endif
    return 0;
}
static void inv_attr(const char *field, const char *name) {
    out(",\""); out(field); out("_rc\":");
    long n=call4(N_XATTR, (long)fullpath, (long)name, (long)buf, sizeof(buf));
    number(n); out(",\""); out(field); out("_hex\":\"");
    if (n>0 && n<=(long)sizeof(buf)) hex(n);
    out("\"");
}
static void inventory(void) {
    out(",\"privilege_inventory\":{\"schema\":\"uglyos-system-helper-metadata-v1\"");
    out(",\"no_new_privs_rc\":"); number(call4(N_PRCTL, 39, 0, 0, 0));
    out(",\"securebits_rc\":"); number(call4(N_PRCTL, 27, 0, 0, 0));
    unsigned int lo=0, hi=0, cap_errors=0;
    for (unsigned int c=0; c<64; ++c) {
        long r=call4(N_PRCTL, 23, c, 0, 0);
        if (r==1) { if (c<32) lo|=1U<<c; else hi|=1U<<(c-32); }
        else if (r<0 && r!=-22) ++cap_errors;
    }
    out(",\"bounding_caps_hex\":\""); mask(lo,hi); out("\",\"bounding_read_errors\":"); number(cap_errors);
    out(",\"directories\":[");
    for (unsigned int d=0; d<sizeof(roots)/sizeof(roots[0]); ++d) {
        unsigned int scanned=0, regular=0, stat_errors=0, cap_errors_dir=0, unsafe=0, dropped=0, count=0;
        long end=0; int complete=0;
        if (d) out(",");
        out("{\"path\":\""); out(roots[d]); out("\",\"open_rc\":");
        long fd=call4(N_OPEN,(long)real_roots[d],0,0,0);
        number(fd<0 ? fd : 0); out(",\"files\":[");
        if (fd>=0) for (unsigned int round=0; round<256; ++round) {
            long n=call4(N_DENTS,fd,(long)dents,sizeof(dents),0);
            if (n<=0) { end=n; complete=(n==0); break; }
            if (n>(long)sizeof(dents)) { end=-75; break; }
            unsigned int pos=0;
            while (pos<(unsigned int)n) {
                if ((unsigned int)n-pos<20) { end=-75; break; }
                unsigned int size=(unsigned int)dents[pos+16] | (unsigned int)dents[pos+17]<<8;
                if (size<20 || size>(unsigned int)n-pos) { end=-75; break; }
                unsigned int len=0; int safe=1;
                while (19+len<size && dents[pos+19+len]) {
                    unsigned char c=dents[pos+19+len];
                    if (!((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') ||
                          c=='_' || c=='-' || c=='.' || c=='+') || len>=255) safe=0;
                    if (len<255) filename[len]=(char)c;
                    ++len;
                }
                if (19+len>=size) { end=-75; break; }
                pos+=size;
                if (!safe) { ++unsafe; continue; }
                filename[len]=0;
                if (!len || (len==1 && filename[0]=='.') || (len==2 && filename[0]=='.' && filename[1]=='.')) continue;
                if (++scanned>4096) { scanned=4096; end=-75; break; }
                if (!join_path(real_roots[d],filename)) { ++unsafe; continue; }
                unsigned int mode=0, uid=0, gid=0, size_lo=0, size_hi=0;
                if (file_stat(&mode,&uid,&gid,&size_lo,&size_hi)) { ++stat_errors; continue; }
                if ((mode&0170000)!=0100000) continue; /* lstat: no symlink traversal */
                ++regular;
#ifdef PROBE_TEST
                const char *cap_name="user.uglyos_fixture";
#else
                const char *cap_name="security.capability";
#endif
                long cap=call4(N_XATTR,(long)fullpath,(long)cap_name,(long)buf,sizeof(buf));
                if (cap<0 && cap!=-61) ++cap_errors_dir;
                if (!(mode&06000) && cap<=0) continue;
                /* Reserve a worst-case row plus all remaining directory trailers. */
                if (inv_rows>=64 || sizeof(output)-used<8192) { ++dropped; continue; }
                ++inv_rows;
                if (count++) out(",");
                out("{\"name\":\""); out(filename); out("\",\"mode\":"); number(mode);
                out(",\"uid\":"); number(uid); out(",\"gid\":"); number(gid);
                out(",\"size_hex\":\""); mask(size_lo,size_hi);
                out("\",\"capability_rc\":"); number(cap); out(",\"capability_hex\":\"");
                if (cap>0 && cap<=(long)sizeof(buf)) hex(cap);
                out("\",\"read_access_rc\":"); number(call4(N_ACCESS,(long)fullpath,4,0,0));
                out(",\"exec_access_rc\":"); number(call4(N_ACCESS,(long)fullpath,1,0,0));
#ifdef PROBE_TEST
                inv_attr("label","user.uglyos_label"); inv_attr("exec_label","user.uglyos_exec_label");
#else
                inv_attr("label","security.SMACK64"); inv_attr("exec_label","security.SMACK64EXEC");
#endif
                out("}");
            }
            if (end) break;
            if (round==255) end=-75;
        }
        if (fd>=0) call4(N_CLOSE,fd,0,0,0);
        out("],\"scan_rc\":"); number(end); out(",\"complete\":"); out(complete ? "true" : "false");
        out(",\"entries_scanned\":"); number(scanned); out(",\"regular_files\":"); number(regular);
        out(",\"stat_errors\":"); number(stat_errors); out(",\"capability_errors\":"); number(cap_errors_dir);
        out(",\"unsafe_names\":"); number(unsafe); out(",\"dropped_records\":"); number(dropped); out("}");
    }
    out("]}");
}
#endif
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
    out("]");
#ifdef PROBE_INVENTORY
    inventory();
#endif
    out("}\n"); flush(); return 0;
}
#ifdef PROBE_HOST_TEST
int main(void) { return run(); }
#else
void _start(void) { stop(run()); }
#endif
