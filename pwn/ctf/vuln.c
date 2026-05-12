#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#define DATA_DIR     "/srv/app/data"
#define USERNAME_MAX 32
#define PASSWORD_MAX 64
#define FIELD_MAX    256
#define FIELD5_BUF   64

#include <stdio.h>
#include <stdlib.h>

void win() {
    char flag[128];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        puts("flag.txt not found. Please create it.");
        exit(1);
    }
    fgets(flag, sizeof(flag), f);
    printf("\n========================================================================\n");
    printf("FLAG: %s\n", flag);
    printf("========================================================================\n");
    fclose(f);
    exit(0);
}

static char g_username[USERNAME_MAX + 1];
static char g_json_path[256];
static char g_pass_path[256];

/* ---------- Banner ---------- */
static void print_banner(void)
{
    puts(
"================================================================================\n"
"                                                                                \n"
"   ___ ____ ____      _      __        __     _       ____ ___ _______   __    \n"
"  |_ _/ ___/ ___|    / \\     \\ \\      / /    / \\     / ___|_ _|_   _\\ \\ / /    \n"
"   | |\\___ \\___ \\   / _ \\     \\ \\ /\\ / /    / _ \\   | |    | |   | |  \\ V /     \n"
"   | | ___) |__) | / ___ \\     \\ V  V /    / ___ \\  | |___ | |   | |   | |      \n"
"  |___|____/____/ /_/   \\_\\     \\_/\\_/    /_/   \\_\\  \\____|___|  |_|   |_|      \n"
"                                                                                \n"
"                       >>> WELCOME TO ISSAWA CITY <<<                           \n"
"================================================================================"
    );
}

static void install_seccomp(void)
{
    struct sock_filter filter[] = {
        /* Validate architecture */
        BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        /* Load syscall number */
        BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        /* Explicitly KILL execve and execveat */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve,       18, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat,     17, 0),

        /* Allow syscalls */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open,         15, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat,       14, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read,         13, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write,        12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close,        11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect,     10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn,  9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group,    8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk,           7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap,          6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat,         5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat,    4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom,     3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup,           2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex,         1, 0), /* <-- NEW */

        /* Default: KILL */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* ALLOW */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* execve/execveat KILL target */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };
    
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(NO_NEW_PRIVS)");
        exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(SECCOMP)");
        exit(1);
    }
}

/* ---------- Helpers ---------- */
static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static int is_alnum_only(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) {
        if (!isalnum((unsigned char)*s)) return 0;
    }
    return 1;
}

static void read_line(const char *prompt, char *out, size_t cap)
{
    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }
    if (!fgets(out, (int)cap, stdin)) {
        _exit(0);
    }
    chomp(out);
}

static int file_exists(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static void write_field_to_json(const char *field_name, const char *content)
{
    int fd = open(g_json_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char line[1024];
    int n = snprintf(line, sizeof(line),
                     "{\"%s\": \"%s\"}\n", field_name, content);
    if (n > 0) {
        if (n > (int)sizeof(line)) n = (int)sizeof(line);
        write(fd, line, (size_t)n);
    }
    close(fd);
}

/* ---------- Auth ---------- */
static void do_register(void)
{
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];

    read_line("Choose a username: ", username, sizeof(username));
    if (!is_alnum_only(username)) {
        puts("Username must be alphanumeric only.");
        return;
    }
    read_line("Choose a password: ", password, sizeof(password));
    if (!*password) {
        puts("Password cannot be empty.");
        return;
    }

    char json_path[256];
    char pass_path[256];
    snprintf(json_path, sizeof(json_path), "%s/%s.json", DATA_DIR, username);
    snprintf(pass_path, sizeof(pass_path), "%s/%s.pass", DATA_DIR, username);

    if (file_exists(json_path)) {
        puts("Username already taken.");
        return;
    }

    int fd = open(json_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open json");
        return;
    }
    close(fd);

    fd = open(pass_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open pass");
        return;
    }
    write(fd, password, strlen(password));
    close(fd);

    puts("Registration successful. You may now log in.");
}

static int do_login(void)
{
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];

    read_line("Username: ", username, sizeof(username));
    if (!is_alnum_only(username)) {
        puts("Invalid credentials.");
        return 0;
    }
    read_line("Password: ", password, sizeof(password));

    char json_path[256];
    char pass_path[256];
    snprintf(json_path, sizeof(json_path), "%s/%s.json", DATA_DIR, username);
    snprintf(pass_path, sizeof(pass_path), "%s/%s.pass", DATA_DIR, username);

    if (!file_exists(json_path)) {
        puts("Invalid credentials.");
        return 0;
    }

    int fd = open(pass_path, O_RDONLY);
    if (fd < 0) {
        puts("Invalid credentials.");
        return 0;
    }
    char stored[PASSWORD_MAX + 16];
    memset(stored, 0, sizeof(stored));
    ssize_t n = read(fd, stored, sizeof(stored) - 1);
    close(fd);
    if (n <= 0) {
        puts("Invalid credentials.");
        return 0;
    }
    stored[n] = '\0';
    chomp(stored);

    if (strcmp(stored, password) != 0) {
        puts("Invalid credentials.");
        return 0;
    }

    strncpy(g_username,  username,  sizeof(g_username)  - 1);
    strncpy(g_json_path, json_path, sizeof(g_json_path) - 1);
    strncpy(g_pass_path, pass_path, sizeof(g_pass_path) - 1);

    printf("Welcome back, %s.\n", g_username);
    return 1;
}

/* ---------- Vulnerable field editors ---------- */

/* Field 1: format string -> libc leak.
   A libc function pointer is pinned on the stack so that scanning
   the right vararg offset returns a libc address. */
static void edit_field1(void)
{
    volatile void *libc_anchor = (void *)&puts;
    char input[FIELD_MAX];
    char buf[FIELD_MAX * 2];

    read_line("Field 1 (display name): ", input, sizeof(input));

    /* VULN: user-controlled format string */
    snprintf(buf, sizeof(buf), input);

    write_field_to_json("field1", buf);
    (void)libc_anchor;
    puts("Field 1 saved.");
}

/* Field 2: format string -> rabbit hole.
   The frame is padded with non-leakable junk so early offsets
   yield meaningless data. */
static void edit_field2(void)
{
    char junk[160];
    for (size_t i = 0; i < sizeof(junk); i++) {
        junk[i] = (char)(0x41 + (int)(i % 23));
    }

    char input[FIELD_MAX];
    char buf[FIELD_MAX * 2];

    read_line("Field 2 (notes): ", input, sizeof(input));

    /* VULN: user-controlled format string (yields useless stack junk) */
    snprintf(buf, sizeof(buf), input);

    write_field_to_json("field2", buf);
    (void)junk;
    puts("Field 2 saved.");
}

/* Field 3: format string -> stack canary leak.
   Compiled with stack-protector, the canary lives in this frame
   and is reachable through the right vararg offset. */
static void edit_field3(void)
{
    char input[FIELD_MAX];
    char buf[FIELD_MAX * 2];

    read_line("Field 3 (bio): ", input, sizeof(input));

    /* VULN: user-controlled format string */
    snprintf(buf, sizeof(buf), input);

    write_field_to_json("field3", buf);
    puts("Field 3 saved.");
}

/* Field 4: normal input, no vulnerability. */
static void edit_field4(void)
{
    char input[FIELD_MAX];
    read_line("Field 4 (status): ", input, sizeof(input));
    write_field_to_json("field4", input);
    puts("Field 4 saved.");
}

/* ---------- Vulnerable menu (contains the BOF) ---------- */
static void vulnerable_menu(void)
{
    /* The buffer that field 5 will overflow lives in this frame.
       When this function returns (option 6), the smashed canary /
       saved RIP triggers the ROP chain. */
    char field5_buf[FIELD5_BUF];
    char line[16];

    while (1) {
        puts("");
        puts("--- ISSAWA CITY :: Profile Menu ---");
        puts("  1. Edit Field 1");
        puts("  2. Edit Field 2");
        puts("  3. Edit Field 3");
        puts("  4. Edit Field 4");
        puts("  5. Edit Field 5");
        puts("  6. Exit");
        fputs("> ", stdout);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) return;
        int choice = atoi(line);

        switch (choice) {
        case 1: edit_field1(); break;
        case 2: edit_field2(); break;
        case 3: edit_field3(); break;
        case 4: edit_field4(); break;
        case 5:
            puts("Field 5 (signature):");
            /* VULN: oversized read into a 64-byte buffer */
            read(0, field5_buf, 512);
            write_field_to_json("field5", "[binary]");
            puts("Field 5 saved.");
            break;
        case 6:
            puts("Goodbye.");
            return; /* canary check + return -> ROP fires here */
        default:
            puts("Invalid choice.");
        }
    }
}

/* ---------- main ---------- */
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    print_banner();

    printf("To see your data, visit http://%s:%s\n",
           getenv("WEB_DOMAIN"), getenv("HOST_WEB_PORT"));

    install_seccomp();

    char line[16];
    while (1) {
        puts("");
        puts("1. Register");
        puts("2. Login");
        puts("3. Exit");
        fputs("> ", stdout);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) break;
        int choice = atoi(line);

        if (choice == 1) {
            do_register();
        } else if (choice == 2) {
            if (do_login()) {
                vulnerable_menu();
                break;
            }
        } else if (choice == 3) {
            puts("Bye.");
            break;
        } else {
            puts("Invalid choice.");
        }
    }

    return 0;
}
