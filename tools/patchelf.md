# patchelf
这里使用的都是脚本例子，有需要的请根据这些例子自行修改

```python
patchelf --set-interpreter /home/kali/Desktop/glibc-all-in-one-master/libs/2.31-0ubuntu9.12_amd64/ld-linux-x86-64.so.2 --set-rpath /home/kali/Desktop/glibc-all-in-one-master/libs/2.31-0ubuntu9.12_amd64 ./pwn
```

```python
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --replace-needed libc.so.6 ./libc.so.6 ./pwn
```

记得给libc和ld打开执行权限