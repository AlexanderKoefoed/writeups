#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("fluff_patched")

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

    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)


    ret = p64(0x00000000004006a3)
    # Gadgets
    pop_rdi = p64(0x00000000004006a3)
    # 0x000000000040057b : pop rbp ; mov edi, 0x601038 ; jmp rax (0x601038 is .bss which is writeable)
    # No move gadgets, we have to use the stack pointer to write.

    p.interactive()

if __name__ == "__main__":
    main()
