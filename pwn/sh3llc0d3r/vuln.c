#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

/*
 * pwn-06: Shellcoder's Playground (hardened)
 *
 * Security profile:
 *   -fno-stack-protector   : no canary (only intended bypass)
 *   -no-pie                : fixed binary addresses
 *   NX enabled             : stack not executable
 *   Full RELRO             : GOT read-only
 *   ASLR (libc/stack)      : irrelevant, no ret2libc path
 *   mmap MAP_FIXED 0x1337000 : RWX page at known static address
 *                              discoverable via static analysis / GDB only
 *   bad byte filter        : blocks \x00 \x0a \x0f in shellcode
 *   seccomp whitelist      : only open(2) read(0) write(1) exit(60/231)
 *
 * Intended solution:
 *   1. Reverse binary to find exec_page address (0x1337000)
 *   2. Find buffer size (64) and RIP offset (72) via disassembly
 *   3. Write null-free, newline-free, \x0f-free ORW shellcode
 *   4. Overflow saved RIP -> 0x1337000
 */

#define SHELLCODE_MAX  512
#define EXEC_PAGE_ADDR 0x1337000

static void install_seccomp(void) {
    struct sock_filter filter[] = {
        /* load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        /* whitelist: read(0) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0,   0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* whitelist: write(1) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1,   0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* whitelist: open(2) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2,   0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* whitelist: exit(60) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 60,  0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* whitelist: exit_group(231) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 231, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* openat(257) — some libc open() wrappers use this */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 257, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* default: kill */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

static int check_bad_bytes(const unsigned char *buf, ssize_t len) {
    for (ssize_t i = 0; i < len; i++) {
        if (buf[i] == 0x00 ||   /* null   */
            buf[i] == 0x0a ||   /* newline */
            buf[i] == 0x0f) {   /* syscall prefix — forces encoding */
            return i;
        }
    }
    return -1;
}

void vuln(void) {
    char buf[64];
    printf("> ");
    fflush(stdout);
    read(STDIN_FILENO, buf, 200);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    /* RWX page at a fixed, static address — find it yourself */
    void *exec_page = mmap((void *)EXEC_PAGE_ADDR, 4096,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                           -1, 0);
    if (exec_page == MAP_FAILED) {
        return 1;
    }

    printf("Dummy question that we will assume that the vulnerable input is an answer field, just a UX enhancement\n");
    printf("Enter your answer size (integer between 1 and 512), then print your answer\n>: ");
    fflush(stdout);

    int sc_len = 0;
    if (scanf("%d\n", &sc_len) != 1 || sc_len <= 0 || sc_len > SHELLCODE_MAX) {
        return 1;
    }

    ssize_t n = read(STDIN_FILENO, exec_page, (size_t)sc_len);
    if (n <= 0) return 1;

    /* bad byte check — no null, no newline, no \x0f */
    int bad = check_bad_bytes(exec_page, n);
    if (bad >= 0) return 1;

    /* seccomp installed AFTER shellcode is staged — only ORW allowed */
    install_seccomp();

    vuln();


    printf("Exploit Failed :( , Try Harder ;)\n");

    return 0;
}
