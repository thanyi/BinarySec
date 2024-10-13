# BinarySec
This is a ctf:pwn note for myself. To be a better pwner, remember to be hungry all the time.

## 理论篇

### 栈相关
- [彻底弄懂Linux下的文件描述符（fd） |  半亩方塘](https://yushuaige.github.io/2020/08/14/彻底弄懂%20Linux%20下的文件描述符（fd）/)
- [栈ROP理论](basic/stack/stack介绍/stack介绍.md)
- [字符串格式化漏洞](basic/stack/Format_str.md)
-  [ret2dlresolve学习](basic/stack/ret2dlresolve学习和体会/ret2dlresolve学习和体会.md)
- [SROP学习](basic/stack/SROP/srop.md)
- [ssp攻击](basic/stack/ssp/ssp.md)
- [exit_hook在pwn题中的应用(低版本exit_hook)](https://www.cnblogs.com/bhxdn/p/14222558.html)
- [Glibc-2.35下对tls_dtor_list的利用详解(高版本exit_hook)](https://bbs.kanxue.com/thread-280518.htm)

### heap相关
- [heap相关](/basic/heap/heap介绍/heap%E4%BB%8B%E7%BB%8D.md)
- [fastbins attack：babyheap_0ctf_2017](basic/heap/heap介绍/fastbins%20attack_babyheap_0ctf_2017.md)
- [how2heap复现](https://www.ethanyi9.site/article/how2heap)
- [house of orange学习](/basic/heap/File_IO/house_of_orange/house_of_orange.md)

## 实战 WP
关于之前写的一些CTF的Write up会在这里更新,有的WP只有部分题目
- [XYCTF 2024](https://www.ethanyi9.site/article/xyctf)
- [Hgame 2024](https://www.ethanyi9.site/article/hgame)
- [VNCTF 2024](https://www.ethanyi9.site/article/vnctf)
- [beginCTF 2024](https://www.ethanyi9.site/article/begin-ctf)
- [极客大挑战 2023](https://www.ethanyi9.site/article/geekchallenge)

## 出题指南
整理参考一下别人的出题指南

- [Pwn出题指南
](https://www.cnblogs.com/tolele/p/16684567.html)

## 工具脚本命令
- [patchelf更改libc](tools/patchelf.md)
- [gdb调试](tools/gdb/gdb.md)
- [ropper](tools/ropper.md)