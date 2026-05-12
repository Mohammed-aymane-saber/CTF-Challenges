#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>

/* ── Globals ─────────────────────────────────────────────────────────────── */
static long          global_secret = 0;
static volatile long _unlock_token = 0;   /* cross-check set only in main()  */
static char          flag_buf[256];        /* XOR-encrypted flag ciphertext   */
static int           flag_len      = 0;

/* ── Seccomp: allow ONLY read/write/mprotect/rt_sigreturn/exit_group ──────── */
static void install_seccomp(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read,         5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write,        4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect,     3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group,   1, 0),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        _exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("prctl(PR_SET_SECCOMP)");
        _exit(1);
    }
}

/* ── forge_key ────────────────────────────────────────────────────────────── */
/* Returns (global_secret ^ 0x1812) in RAX when magic_word == 0xcafebabe.    */
/* The ROP chain calls this with RDI=0xcafebabe, then pivots RAX -> RDI.     */
long forge_key(long magic_word) {
    if (magic_word == 0xcafebabe) {
        return global_secret ^ 0x1812;
    }
    return 0;
}

/* ── _do_decrypt_and_print ───────────────────────────────────────────────── */
/* static + noinline: no exported symbol, no PLT/GOT entry.                  */
/* Decrypts into a LOCAL buffer — flag_buf (ciphertext) is never modified.   */
/* */
/* Two independent runtime guards (both verified algebraically):             */
/* Guard 1: key ^ 0x1812              == global_secret                     */
/* Guard 2: key ^ 0xdeadbeefcafea2ac  == _unlock_token                     */
/* */
/* Mask derivation:                                                          */
/* _unlock_token = global_secret ^ 0xdeadbeefcafebabe   (set in main)      */
/* key           = global_secret ^ 0x1812               (forge_key output) */
/* key ^ MASK    = global_secret ^ 0xdeadbeefcafebabe   = _unlock_token    */
/* => MASK = 0x1812 ^ 0xdeadbeefcafebabe = 0xdeadbeefcafea2ac              */
__attribute__((noinline))
static void _do_decrypt_and_print(long key) {
    /* Guard 1 */
    if ((key ^ 0x1812) != global_secret)
        _exit(1);

    /* Guard 2 */
    if ((key ^ (long)0xdeadbeefcafea2acLL) != _unlock_token)
        _exit(1);

    /* Both guards passed — decrypt flag_buf into local output buffer */
    unsigned char secret_bytes[8];
    long base = key ^ 0x1812;           /* recovers global_secret exactly    */
    memcpy(secret_bytes, &base, 8);

    char out[256];
    for (int i = 0; i < flag_len; i++)
        out[i] = flag_buf[i] ^ secret_bytes[i % 8];

    write(1, out, flag_len);
    write(1, "\n", 1);
}

/* ── unlock_vault ────────────────────────────────────────────────────────── */
/* Public symbol targeted by the ROP chain.                                  */
/* Silently exits on a wrong key — no oracle for attackers.                  */
void unlock_vault(long key) {
    if (key != (global_secret ^ 0x1812))
        _exit(1);
    _do_decrypt_and_print(key);
}

/* ── Gadget Loot ─────────────────────────────────────────────────────────── */
/* A collection of useful instructions masquerading as a junk function.      */
/* solve.py finds them by raw byte scan — independent of pwntools ROP cache. */
void gadget_loot(void) {
    __asm__ volatile(
        "pop %rax\n\t" "ret\n\t"
        "pop %rbx\n\t" "ret\n\t"
        "pop %rcx\n\t" "ret\n\t"
        "pop %rdx\n\t" "ret\n\t"
        "pop %rsi\n\t" "ret\n\t"
        "pop %rdi\n\t" "ret\n\t"
        "mov %rax, %rdi\n\t" "ret\n\t"
        "mov %rdi, %rax\n\t" "ret\n\t"
        "leave\n\t" "ret\n\t"
    );
}

/* ── vuln ────────────────────────────────────────────────────────────────── */
/* Stack buffer overflow: 64-byte buf, 200-byte read — classic BOF.          */
void vuln(void) {
    char buf[64];
    write(1, "Input: ", 7);
    read(0, buf, 200);
}

/* ── main ────────────────────────────────────────────────────────────────── */
/* 1. Generate global_secret  (/dev/urandom)                                */
/* 2. Read + XOR-encrypt flag.txt into flag_buf                             */
/* 3. Set _unlock_token = global_secret ^ 0xdeadbeefcafebabe                */
/* 4. Install seccomp  (open/execve blocked from here on)                   */
/* 5. Call vuln()                                                           */
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    /* 1. Random 8-byte secret */
    int urfd = open("/dev/urandom", O_RDONLY);
    if (urfd < 0) { perror("open /dev/urandom"); _exit(1); }
    if (read(urfd, &global_secret, sizeof(global_secret))
            != (ssize_t)sizeof(global_secret)) {
        perror("read urandom"); close(urfd); _exit(1);
    }
    close(urfd);

    /* 2. Read flag.txt and XOR-encrypt into flag_buf */
    int ffd = open("flag.txt", O_RDONLY);
    if (ffd < 0) { perror("open flag.txt"); _exit(1); }
    int n = read(ffd, flag_buf, (int)sizeof(flag_buf) - 1);
    if (n <= 0) { perror("read flag.txt"); close(ffd); _exit(1); }
    close(ffd);
    flag_len = n;

    unsigned char *sb = (unsigned char *)&global_secret;
    for (int i = 0; i < flag_len; i++)
        flag_buf[i] ^= sb[i % 8];

    /* 3. Cross-check token
     * _unlock_token = global_secret ^ 0xdeadbeefcafebabe
     * Guard 2 checks: key ^ 0xdeadbeefcafea2ac == _unlock_token
     * where 0xdeadbeefcafea2ac = 0xdeadbeefcafebabe ^ 0x1812             */
    _unlock_token = global_secret ^ (long)0xdeadbeefcafebabeLL;

    /* 4. Seccomp */
    install_seccomp();

    /* 5. Overflow me */
    vuln();

    return 0;
}
