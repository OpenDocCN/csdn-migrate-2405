# Linux 设备驱动开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA`](https://zh.annas-archive.org/md5/6B7A321F07B3F3827350A558F12EF0DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

内核设备驱动程序开发是复杂操作系统中最重要的部分之一，而 Linux 就是这样的操作系统。设备驱动程序对于在工业、家庭或医疗应用等真实环境中使用计算机的开发人员非常重要。事实上，即使 Linux 现在得到了广泛的支持，每天仍然会创建新的外围设备，这些设备需要驱动程序才能在 GNU/Linux 机器上得到有效使用。

本书将介绍实现完整字符驱动程序（通常称为*char driver*）的方法，通过介绍在内核和用户空间之间交换数据的所有必要技术，实现与外围设备中断的进程同步，访问 I/O 内存映射到（内部或外部）设备，并在内核中高效地管理时间。

本书中提供的所有代码都与 Linux 4.18+版本兼容（即最新的 5.x 内核）。这些代码可以在 Marvell ESPRESSObin 上进行测试，该设备具有内置的 ARM 64 位 CPU，但也可以在任何其他类似的 GNU/Linux 嵌入式设备上使用。通过这种方式，读者可以验证他们所读内容是否被正确理解。

# 本书的读者对象

如果您想了解如何在 Linux 机器上实现完整的字符驱动程序，或者想了解几种内核机制的工作原理（例如工作队列、完成和内核定时器等），以更好地理解通用驱动程序的工作原理，那么本书适合您。

如果您需要了解如何编写自定义内核模块以及如何向其传递参数，或者如何读取和更好地管理内核消息，甚至如何向内核源代码添加自定义代码，那么本书就是为您而写的。

如果您需要更好地理解设备树，如何修改它，甚至如何编写新的设备树以满足您的需求，并学习如何管理新的设备驱动程序，那么您也会从本书中受益。

# 本书涵盖内容

第一章，*安装开发系统*，介绍了如何在 Ubuntu 18.04.1 LTS 上安装完整的开发系统，以及基于 Marvell ESPRESSObin 板的完整测试系统。本章还将介绍如何使用串行控制台，如何从头开始重新编译内核，并教授一些进行交叉编译和软件仿真的技巧。

第二章，*内核深度剖析*，讨论了如何创建自定义内核模块，以及如何读取和管理内核消息。这些技能对于帮助开发人员理解内核内部发生的事情非常有用。

第三章，*使用字符驱动程序*，探讨了如何实现一个非常简单的字符驱动程序，以及如何在其与用户空间之间交换数据。本章最后提出了一些例子，以突出*一切皆文件*的抽象与设备驱动程序之间的关系。

第四章，*使用设备树*，介绍了设备树。读者将学习如何阅读和理解它，如何编写自定义设备树，然后如何编译它以获得可以传递给内核的二进制形式。本章以使用 Armada 3720、i.Mx 7Dual 和 SAMA5D3 CPU 为例，介绍了下载固件（在外围设备内）以及如何使用 Pin MUX 工具配置 CPU 引脚的部分。

第五章，*管理中断和并发*，介绍了如何在 Linux 内核中管理中断和并发。它展示了如何安装中断处理程序，如何推迟工作到以后的时间，以及如何管理内核定时器。在本章末尾，读者将学习如何等待事件（如等待某些数据被读取）以及如何保护他们的数据免受竞争条件的影响。

第六章，*杂项内核内部*，讨论如何在内核内部动态分配内存，以及如何使用几个有用的辅助函数来进行一些日常编程操作（如字符串操作、列表和哈希表操作）。本章还将介绍如何进行 I/O 内存访问，以及如何在内核内部安全地花费时间以创建明确定义的繁忙循环延迟。

第七章，*高级字符驱动程序操作*，介绍了字符驱动程序上所有可用的高级操作：`ioctl()`、`mmap()`、`lseek()`、`poll()`/`select()`系统调用的实现，以及通过`SIGIO`信号进行异步 I/O。

附录 A，*附加信息：使用字符驱动程序*，这包含了第三章的附加信息。

附录 B，*附加信息：使用设备树*，这包含了第四章的附加信息。

附录 C，*附加信息：管理中断和并发*，这包含了第五章的附加信息。

附录 D，*附加信息：杂项内核内部*，这包含了第六章的附加信息。

附录 E，*附加信息：高级字符驱动程序操作*，这包含了第七章的附加信息。

# 为了充分利用本书

+   您应该对非图形文本编辑器（如`vi`、`emacs`或`nano`）有一些了解。您不能直接连接 LCD 显示器、键盘和鼠标到嵌入式套件上进行对文本文件的小修改，因此您应该对这些工具有一定的了解，以便远程进行这些修改。

+   您应该知道如何管理 Ubuntu 系统，或者至少是一个通用的基于 GNU/Linux 的系统。我的主机 PC 运行在 Ubuntu 18.04.1 LTS 上，但您也可以使用更新的 Ubuntu LTS 版本，或者带有一些修改的基于 Debian 的系统。您也可以使用其他 GNU/Linux 发行版，但这将需要您付出一些努力，主要是关于安装交叉编译工具、库依赖和软件包管理。

本书不涵盖 Windows、macOS 等外部系统，因为您不应该使用低技术的系统来开发高技术系统的代码！

+   熟悉 C 编程语言、C 编译器的工作原理以及如何管理 makefile 都是强制性要求。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 系统使用 WinRAR/7-Zip

+   Mac 系统使用 Zipeg/iZip/UnRarX

+   7-Zip/PeaZip for Linux

该书的代码包托管在 GitHub 上，网址为[`github.com/giometti/linux_device_driver_development_cookbook`](https://github.com/giometti/linux_device_driver_development_cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Linux-Device-Driver-Development-Cookbook`](https://github.com/PacktPublishing/Linux-Device-Driver-Development-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/9781838558802_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781838558802_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

文本文件夹名称、文件名、文件扩展名、路径名、虚拟 URL 和用户输入中的代码词显示如下："要获取前面的内核消息，我们可以使用`dmesg`和`tail -f /var/log/kern.log`命令。"

代码块设置如下：

```
#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("Hello World!\n");

    return 0;
}
```

您应该注意，本书中的大多数代码都采用 4 个空格缩进，而本书提供的文件中的示例代码使用 8 个空格缩进。因此，前面的代码将如下所示：

```
#include <stdio.h>

int main(int argc, char *argv[])
{
        printf("Hello World!\n");

        return 0;
}
```

显然，它们在实践中是完全等效的！

本书中使用的嵌入式套件的任何命令行输入或输出均按以下方式呈现：

```
# make CFLAGS="-Wall -O2" helloworld
cc -Wall -O2 helloworld.c -o helloworld
```

命令以粗体显示，而它们的输出以普通文本显示。您还应该注意，由于空间限制，提示字符串已被删除；实际上，在您的终端上，完整的提示应该如下所示：

```
root@espressobin:~# make CFLAGS="-Wall -O2" helloworld
cc -Wall -O2 helloworld.c -o helloworld
```

还要注意，由于书中的空间限制，您可能会遇到非常长的命令行，如下所示：

```
$ make CFLAGS="-Wall -O2" \
 CC=aarch64-linux-gnu-gcc \
 chrdev_test
aarch64-linux-gnu-gcc -Wall -O2 chrdev_test.c -o chrdev_test
```

否则，我不得不打破命令行。但是，在一些特殊情况下，您可能会发现以下格式的输出行（特别是内核消息）：

```
[ 526.318674] mem_alloc:mem_alloc_init: kmalloc(..., GFP_KERNEL) =ffff80007982f
000
[ 526.325210] mem_alloc:mem_alloc_init: kmalloc(..., GFP_ATOMIC) =ffff80007982f
000
```

不幸的是，这些行不能在印刷书籍中轻松重现，但您应该将它们视为单行。

在我的主机计算机上，作为非特权用户给出的任何命令行输入或输出均按以下方式编写：

```
$ tail -f /var/log/kern.log
```

当我需要以特权用户（root）的身份在我的主机计算机上给出命令时，命令行输入或输出将如下所示：

```
# insmod mem_alloc.ko
```

您应该注意，所有特权命令也可以由普通用户使用`sudo`命令以以下格式执行：

```
$ sudo <command>
```

因此，前面的命令可以由普通用户执行，如下所示：

```
$ sudo /insmod mem_alloc.ko
```

# 内核和日志消息

在几个 GNU/Linux 发行版上，内核消息通常具有以下形式：

```
[ 3.421397] mvneta d0030000.ethernet eth0: Using random mac address 3e:a1:6b:
f5:c3:2f
```

这是本书中的一行非常长的行，因此我们从每行的起始字符开始删除字符，直到真正的信息开始。因此，在上面的示例中，输出行将如下报告：

```
mvneta d0030000.ethernet eth0: Using random mac address 3e:a1:6b:f5:c3:2f
```

但是，正如前面所说，如果行仍然太长，它将被打破。

在终端中，长输出或重复或不太重要的行通过用三个点`...`替换来删除，如下所示：

```
output begin
output line 1
output line 2
...
output line 10
output end
```

当三个点位于行尾时，这意味着输出会继续，但出于空间原因，我决定将其截断。

# 文件修改

当您需要修改文本文件时，我将使用*统一上下文差异*格式，因为这是一种非常高效和紧凑的表示文本修改的方式。可以通过使用带有`-u`选项参数的`diff`命令或在`git`存储库中使用`git diff`命令来获得此格式。

作为一个简单的例子，让我们考虑`file1.old`中的以下文本：

```
This is first line
This is the second line
This is the third line
...
...
This is the last line
```

假设我们需要修改第三行，如下摘录所示：

```
This is first line
This is the second line
This is the new third line modified by me
...
...
This is the last line
```

您可以轻松理解，每次对文件进行简单修改都报告整个文件是不必要且占用空间；但是，通过使用*统一上下文差异*格式，前述修改可以写成如下形式：

```
$ diff -u file1.old file1.new
--- file1.old 2019-05-18 14:49:04.354377460 +0100
+++ file1.new 2019-05-18 14:51:57.450373836 +0100
@@ -1,6 +1,6 @@
 This is first line
 This is the second line
-This is the third line
+This is the new third line modified by me
 ...
 ...
 This is the last line
```

现在，修改非常清晰，并以紧凑的形式编写！它以两行标题开始，原始文件前面有`---`，新文件前面有`+++`。然后，它遵循一个或多个变更块，其中包含文件中的行差异。前面的示例只有一个块，其中未更改的行前面有一个空格字符，而要添加的行前面有一个`+`字符，要删除的行前面有一个`-`字符。

尽管出于空间原因，本书中大多数补丁的缩进都减少了，以适应印刷页面的宽度；但是，它们仍然是完全可读的。对于完整的补丁，您应该参考 GitHub 上提供的文件或 Packt 网站上的文件。

# 串行和网络连接

在本书中，我主要会使用两种不同类型的连接与嵌入式套件进行交互：串行控制台和 SSH 终端以及以太网连接。

串行控制台，通过 USB 连接实现，主要用于从命令行管理系统。它主要用于监视系统，特别是控制内核消息。

SSH 终端与串行控制台非常相似，即使不完全相同（例如，内核消息不会自动显示在终端上），但它可以像串行控制台一样用于从命令行给出命令和编辑文件。

在章节中，我将使用串行控制台上的终端或通过 SSH 连接来提供实现本书中所有原型所需的大部分命令和配置设置。

要从主机 PC 访问串行控制台，可以使用`minicon`命令，如下所示：

```
$ minicom -o -D /dev/ttyUSB0
```

但是，在第一章，*安装开发系统*中，这些方面都有解释，您不必担心。还要注意，在某些系统上，您可能需要 root 权限才能访问`/dev/ttyUSB0`设备。在这种情况下，您可以通过使用`sudo`命令或更好地通过使用以下命令将系统用户正确添加到正确的组来解决此问题：

```
$ sudo adduser $LOGNAME dialout
```

然后注销并重新登录，您应该能够无问题地访问串行设备。

要访问 SSH 终端，您可以使用以太网连接。它主要用于从主机 PC 或互联网下载文件，并且可以通过将以太网电缆连接到嵌入式套件的以太网端口，然后根据读者的 LAN 设置相应地配置端口来建立连接（请参阅第一章，*安装开发系统*中的所有说明）。

# 其他约定

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息"。

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。

# 章节

在本书中，您会经常看到几个标题（*准备就绪*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。

为了清晰地说明如何完成一个配方，使用以下各节：

# 准备就绪

本节告诉您在配方中可以期待什么，并描述如何设置配方所需的任何软件或任何预备设置。

# 如何做...

本节包含完成配方所需的步骤。

# 它是如何工作的...

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包括有关食谱的额外信息，以使您对食谱更加了解。

# 另请参阅

本节提供有关食谱的其他有用信息的链接。

# 联系我们

我们的读者反馈总是受欢迎的。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送电子邮件至 `customercare@packtpub.com`。

**勘误**: 尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在本书中发现错误，我们将不胜感激您向我们报告。请访问 [www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，我们将不胜感激您向我们提供位置地址或网站名称。请通过 `copyright@packt.com` 与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请访问 [authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问 [packt.com](http://www.packt.com/)。


# 第一章：安装开发系统

在本章中，我们将介绍并设置我们的工作平台。实际上，即使我们在工作 PC 上编写并测试自己的设备驱动程序，建议使用第二台设备来测试代码。这是因为我们将在内核空间工作，即使有一个小错误也可能导致严重的故障！此外，使用一个平台，可以测试各种外设，这些外设并不总是在 PC 上可用。当然，您可以自由选择使用自己的系统来编写和测试驱动程序，但在这种情况下，您需要注意适应您的板规格所需的修改。

在本书中，我将使用**Marvell ESPRESSObin**系统，这是一台功能强大的**ARM** 64 位机器，具有许多有趣的功能。在下图中，您可以看到 ESPRESSObin 与信用卡并排，可以了解到板的真实尺寸：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/4cd2a298-bcef-4ffd-8782-d274bab23e70.png)

我使用的是 ESPRESSObin 的 v5 版本，而在撰写本书时最新版本（于 2018 年 9 月宣布）是 v7，因此读者应该能够在本书出版时获得这个新版本。新的 ESPRESSObin v7 将提供 1GB DDR4 和 2GB DDR4 配置（而 v5 使用 DDR3 RAM 芯片），并且新的 1.2GHz 芯片组将取代目前销售的配置，其 CPU 频率限制为 800MHz 和 1GHz。即使快速查看新的板布局，我们可以看到单个 SATA 连接器取代了现有的 SATA 电源和接口的组合，LED 布局现在重新排列成一行，并且现在放置了一个内置的 eMMC。此外，这个新版本将配备一个可选的 802.11ac +蓝牙 4.2 迷你 PCIe 无线网络卡，需另外购买。

最后，您现在可以选择订购带有完整外壳的 v7 ESPRESSObin。该产品已获得 FCC 和 CE 认证，有助于实现大规模部署。有关修订版 v7（和 v5）的更多信息，请访问[`wiki.espressobin.net/tiki-index.php?page=Quick+User+Guide`](http://wiki.espressobin.net/tiki-index.php?page=Quick+User+Guide)。

为了测试我们的新驱动程序，我们将在本章中涵盖以下内容：

+   设置主机

+   使用串行控制台

+   配置和构建内核

+   设置目标机器

+   在外部硬件上进行本地编译

# 技术要求

以下是一些有用的技术信息的网址，我们可以在这些网址上获取有关板的技术信息：

+   主页：[`espressobin.net/`](http://espressobin.net/)

+   文档维基：[`wiki.espressobin.net/tiki-index.php`](http://wiki.espressobin.net/tiki-index.php)

+   论坛：[`espressobin.net/forums/`](http://espressobin.net/forums/)

查看[`espressobin.net/tech-spec/`](http://espressobin.net/tech-spec/)上的技术规格，我们得到以下信息，可以看到 ESPRESSObin v5 在计算能力、存储、网络和可扩展性方面的优势：

| **系统芯片** (**SoC**) | Marvell Armada 3700LP (88F3720) 双核 ARM Cortex A53 处理器，最高 1.2GHz |
| --- | --- |
| 系统内存 | 1GB DDR3 或可选 2GB DDR3 |
| 存储 | 1x SATA 接口 1x 微型 SD 卡槽，可选 4GB EMMC |

| 网络连接 | 1x Topaz 网络交换机 2x GbE 以太网 LAN

1x 以太网 WAN

1x 用于无线/蓝牙低功耗外设的 MiniPCIe 插槽 |

| USB | 1x USB 3.0 1x USB 2.0

1x 微型 USB 端口 |

| 扩展 | 2 个 46 针 GPIO 头，用于连接 I2C、GPIO、PWM、UART、SPI、MMC 等附件和扩展板。 |
| --- | --- |
| 杂项 | 复位按钮和 JTAG 接口 |
| 电源供应 | 12V DC 插孔或通过微型 USB 端口 5V |
| 功耗 | 1GHz 时小于 1W 的热耗散 |

特别是，下一张截图显示了 Marvell ESPRESSObin v5 的顶部视图（从现在开始，请注意我不会再明确添加“v5”）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/c50fb9d8-fdad-4677-ab8b-5931067dcbb2.png)

在前面的截图中，我们可以看到以下组件：

+   电源连接器（12V DC 插孔）

+   重置开关

+   微型 USB 设备端口（串行控制台）

+   以太网端口

+   USB 主机端口

下一张截图显示了板子的底部视图，微型 SD 卡槽位于其中；这是我们将在本章后面创建的微型 SD 卡的插入位置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/2a93e27f-64bf-41e2-99b0-d6164c1bc1db.png)

在这本书中，我们将看到如何管理（和重新安装）完整的 Debian 发行版，这将使我们能够拥有一系列准备运行的软件包，就像在普通 PC 上一样（事实上，Debian ARM64 版本等同于 Debian x86 版本）。之后，我们将为板载开发设备驱动程序，然后在可能的情况下，将它们与连接到 ESPRESSObin 本身的真实设备进行测试。本章还包括有关如何设置主机系统的简短教程，您可以使用它来设置基于 GNU/Linux 的工作机器或专用虚拟机。

本章中使用的代码和其他文件可以从 GitHub 上下载：[`github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_01`](https://github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_01)。

# 设置主机机器

正如每个优秀的设备驱动程序开发者所知，主机机器是绝对必要的。

即使嵌入式设备如今变得更加强大（以及 ESPRESSObin

是其中之一），主机机器可以帮助处理一些资源密集型的任务。

因此，在本节中，我们将展示如何设置我们的主机机器。

我们决定使用的主机机器可以是普通 PC 或虚拟机——它们是等效的——但重要的是它必须运行基于 GNU/Linux 的操作系统。

# 准备工作

在本书中，我将使用基于 Ubuntu 18.04 LTS 的系统，但您可以决定尝试在另一个主要的 Linux 发行版中复制一些设置和安装命令，对于 Debian 衍生版来说，这将需要很少的努力，或者在非 Debian 衍生版发行版中需要更多的复杂操作。

我不打算展示如何在 PC 上或虚拟机上安装全新的 Ubuntu 系统，因为对于真正的程序员来说，这是一项非常容易的任务；然而，作为本章的最后一步（*在外部硬件上进行本地编译*配方），我将介绍一个有趣的跨平台环境，并详细介绍如何安装它，这个环境被证明对于在主机机器上编译外部目标代码非常有用。当我们需要在开发 PC 上运行多个不同的操作系统时，这个过程非常有用。

因此，此时，读者应该已经拥有自己的 PC 运行（本地或虚拟化）全新安装的 Ubuntu 18.04 LTS 操作系统。

主机 PC 的主要用途是编辑和交叉编译我们的新设备驱动程序，并通过串行控制台管理我们的目标设备，创建其根文件系统等等。

为了正确执行此操作，我们需要一些基本工具；其中一些是通用的，而其他一些取决于我们将要编写驱动程序的特定平台。

通用工具肯定包括编辑器、版本控制系统和编译器及其相关组件，而特定平台工具主要是交叉编译器及其相关组件（在某些平台上，我们可能需要额外的工具，但我们的需求可能有所不同，在任何情况下，每个制造商都会为我们提供所有所需的舒适编译环境）。

关于编辑器：我不打算在上面浪费任何言语，因为读者可以使用他们想要的任何编辑器（例如，我仍然使用 vi 编辑器进行编程），但是对于其他工具，我将不得不更具体。

# 如何做...

现在我们的 GNU/Linux 发行版已经在我们的主机 PC 上运行起来了，我们可以开始安装一些我们在本书中要使用的程序：

1.  首先，让我们安装基本的编译工具：

```
$ sudo apt install gcc make pkg-config \
 bison flex ncurses-dev libssl-dev \
 qemu-user-static debootstrap
```

正如您已经知道的那样，`sudo`命令用于以特权用户身份执行命令。它应该已经存在于您的系统中，否则您可以使用`apt install sudo`命令作为 root 用户进行安装。

1.  接下来，我们必须测试编译工具。我们应该能够编译一个 C 程序。作为一个简单的测试，让我们使用存储在`helloworld.c`文件中的以下标准*Hello World*代码：

```
#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("Hello World!\n");

    return 0;
}
```

请记住，代码可以从我们的 GitHub 存储库中下载。

1.  现在，我们应该能够通过使用以下命令来编译它：

```
$ make CFLAGS="-Wall -O2" helloworld
cc -Wall -O2 helloworld.c -o helloworld
```

在上面的命令中，我们同时使用了编译器和`make`工具，这是在舒适和可靠的方式下编译每个 Linux 驱动程序所必需的。

您可以通过查看[`www.gnu.org/software/make/`](https://www.gnu.org/software/make/)来获取有关`make`的更多信息，对于`gcc`，您可以转到[`www.gnu.org/software/gcc/`](https://www.gnu.org/software/gcc/)。

1.  最后，我们可以在主机 PC 上进行测试，如下所示：

```
$ ./helloworld 
Hello World!
```

1.  下一步是安装交叉编译器。由于我们将使用 ARM64 系统，我们需要一个交叉编译器及其相关工具。要安装它们，我们只需使用以下命令：

```
$ sudo apt install gcc-7-aarch64-linux-gnu
```

请注意，我们还可以使用 ESPRESSObin 维基中报告的外部工具链，网址为[`wiki.espressobin.net/tiki-index.php?page=Build+From+Source+-+Toolchain`](http://wiki.espressobin.net/tiki-index.php?page=Build+From+Source+-+Toolchain)；但是，Ubuntu 工具链运行得很完美！

1.  安装完成后，通过使用上述*Hello World*程序来测试我们的新交叉编译器，如下所示：

```
$ sudo ln -s /usr/bin/aarch64-linux-gnu-gcc-7 /usr/bin/aarch64-linux-gnu-gcc
$ make CC=aarch64-linux-gnu-gcc CFLAGS="-Wall -O2" helloworld
aarch64-linux-gnu-gcc-7 -Wall -O2 helloworld.c -o helloworld
```

请注意，我已经删除了先前编译的`helloworld`程序，以便能够正确编译这个新版本。为此，我使用了`mv helloworld helloworld.x86_64`命令，因为我将再次需要 x86 版本。

还要注意，由于 Ubuntu 不会自动创建标准的交叉编译器名称`aarch64-linux-gnu-gcc`，我们必须在执行`make`之前手动执行上述`ln`命令。

1.  好了，现在我们可以通过使用以下`file`命令来验证为 ARM64 新创建的`helloworld`程序的版本。这将指出程序编译为哪个平台：

```
$ file helloworld
helloworld: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=c0d6e9ab89057e8f9101f51ad517a253e5fc4f10, not stripped
```

如果我们再次在先前重命名的版本`helloworld.x86_64`上使用`file`命令，我们会得到以下结果：

```
$ file helloworld.x86_64 
helloworld.x86_64: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cf932fab45d36f89c30889df98ed382f6f648203, not stripped
```

1.  要测试这个新版本是否真的是为 ARM64 平台而编译的，我们可以使用**QEMU**，这是一个开源的通用机器模拟器和虚拟化程序，能够在运行平台上执行外部代码。要安装它，我们可以使用`apt`命令，如上述代码中所示，指定`qemu-user-static`包：

```
$ sudo apt install qemu-user-static
```

1.  然后，我们可以执行我们的 ARM64 程序：

```
$ qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./helloworld
Hello World!
```

要获取有关 QEMU 的更多信息，一个很好的起点是它的主页[`www.qemu.org/`](https://www.qemu.org/)。

1.  下一步是安装版本控制系统。我们必须安装用于 Linux 项目的版本控制系统，即`git`。要安装它，我们可以像之前一样使用以下命令：

```
$ sudo apt install git
```

如果一切正常，我们应该能够按如下方式执行它：

```
$ git --help
usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]
           [--exec-path[=<path>]] [--html-path] [--man-path]
           [--info-path] [-p | --paginate | --no-pager]
           [--no-replace-objects] [--bare] [--git-dir=<path>]
           [--work-tree=<path>] [--namespace=<name>]
           <command> [<args>]

These are common Git commands used in various situations:

start a working area (see also: git help tutorial)
   clone Clone a repository into a new directory
   init Create an empty Git repository or reinitialise an existing one
...
```

在本书中，我将解释每个使用的`git`命令，但是为了完全了解这个强大的工具，我建议您开始阅读[`git-scm.com/`](https://git-scm.com/)。

# 另请参阅

+   有关 Debian 软件包管理的更多信息，您可以在互联网上搜索，但一个很好的起点是[`wiki.debian.org/Apt，`](https://wiki.debian.org/Apt)而有关编译工具（`gcc`，`make`和其他 GNU 软件）的最佳文档在[`www.gnu.org/software/`](https://www.gnu.org/software/)。

+   然后，有关`git`的更好文档的最佳位置在[`git-scm.com/book/en/v2`](https://git-scm.com/book/en/v2)，那里有在线提供的精彩书籍*Pro Git*！

# 使用串行控制台

正如已经说明的（以及任何嵌入式设备的真正程序员所知道的），串行控制台在设备驱动程序开发阶段是必不可少的！因此，让我们看看如何通过其串行控制台访问我们的 ESPRESSObin。

# 准备工作

如*技术要求*部分的截图所示，有一个微型 USB 连接器可用，并且直接连接到 ESPRESSObin 的串行控制台。因此，使用适当的 USB 电缆，我们可以将其连接到我们的主机 PC。

如果所有连接都正常，我们可以执行任何串行终端仿真器来查看串行控制台的数据。关于这个工具，我必须声明，作为编辑程序，我们可以使用任何我们喜欢的。但是，我将展示如何安装两个更常用的终端仿真程序——`minicom`和`screen`。

请注意，此工具并非绝对必需，其使用取决于您将要使用的平台；但是，在我看来，这是有史以来最强大的开发和调试工具！因此，您绝对需要它。

要安装`minicom`，请使用以下命令：

```
$ sudo apt install minicom
```

现在，要安装名为`screen`的终端仿真器**，**我们只需将`minicom`字符串替换为`screen`数据包名称，如下所示：

```
$ sudo apt install screen
```

它们都需要一个串行端口来工作，并且调用命令非常相似。为简洁起见，我将仅报告它们与 ESPRESSObin 连接的用法；但是，有关它们的更多信息，您应该参考它们的手册页（使用`man minicom`和`man screen`来显示它们）。

# 如何做到...

要测试与目标系统的串行连接，我们可以执行以下步骤：

1.  首先，我们必须找到正确的串行端口。由于 ESPRESSObin 使用 USB 模拟串行端口（波特率为 115,200），通常我们的目标端口被命名为`ttyUSB0`（但您的情况可能有所不同，因此在继续之前让我们验证一下），因此我们必须使用以下`minicom`命令来连接 ESPRESSObin 串行控制台：

```
$ minicom -o -D /dev/ttyUSB0
```

要正确访问串行控制台，我们可能需要适当的权限。实际上，我们可以尝试执行前面的`minicom`命令，但是我们没有输出！这是因为如果我们没有足够的权限访问端口，`minicom`命令会悄悄退出。我们可以通过简单地使用另一个命令来验证我们的权限，如下所示：

**`$ cat /dev/ttyUSB0`**

`cat: /dev/ttyUSB0: Permission denied`

在这种情况下，`cat`命令完美地告诉我们出了什么问题，因此我们可以使用`sudo`来解决这个问题，或者更好的是，通过正确将我们系统的用户添加到正确的组，如下所示：

**`$ ls -l /dev/ttyUSB0`** `crw-rw---- 1 root dialout 188, 0 Jan 12 23:06 /dev /ttyUSB0`

**`$ sudo adduser $LOGNAME dialout`**

然后，我们注销并重新登录，就可以无问题地访问串行设备了。

1.  使用`screen`的等效命令如下所示：

```
$ screen /dev/ttyUSB0 115200
```

请注意，在`minicom`上，我没有指定串行通信选项（波特率，奇偶校验等），而对于`screen`，我在命令行上添加了波特率；这是因为我的默认`minicom`配置会自动使用正确的通信选项，而`screen`使用 9,600 波特率作为默认波特率。有关如何进行此设置以适应您的需求的进一步信息，请参阅程序手册页。

1.  如果一切顺利，在正确的串行端口上执行终端仿真器后，打开我们的 ESPRESSObin（只需插入电源）。我们应该在终端上看到以下输出：

```
NOTICE: Booting Trusted Firmware
NOTICE: BL1: v1.3(release):armada-17.06.2:a37c108
NOTICE: BL1: Built : 14:31:03, Jul 5 2NOTICE: BL2: v1.3(release):armada-17.06.2:a37c108
NOTICE: BL2: Built : 14:31:04, Jul 5 201NOTICE: BL31: v1.3(release):armada-17.06.2:a37c108
NOTICE: BL31:

U-Boot 2017.03-armada-17.06.3-ga33ecb8 (Jul 05 2017 - 14:30:47 +0800)

Model: Marvell Armada 3720 Community Board ESPRESSOBin
       CPU @ 1000 [MHz]
       L2 @ 800 [MHz]
       TClock @ 200 [MHz]
       DDR @ 800 [MHz]
DRAM: 2 GiB
U-Boot DComphy-0: USB3 5 Gbps 
Comphy-1: PEX0 2.5 Gbps 
Comphy-2: SATA0 6 Gbps 
SATA link 0 timeout.
AHCI 0001.0300 32 slots 1 ports 6 Gbps 0x1 impl SATA mode
flags: ncq led only pmp fbss pio slum part sxs 
PCIE-0: Link down
MMC: sdhci@d0000: 0
SF: Detected w25q32dw with page size 256 Bytes, erase size 4 KiB, total 4 MiB
Net: eth0: neta@30000 [PRIME]
Hit any key to stop autoboot: 2 
```

# 另请参阅

+   有关如何连接 ESPRESSObin 串行端口的更多信息，您可以查看其关于串行连接的 wiki 部分[`wiki.espressobin.net/tiki-index.php?page=Serial+connection+-+Linux`](http://wiki.espressobin.net/tiki-index.php?page=Serial+connection+-+Linux)。

# 配置和构建内核

现在，是时候下载内核源代码，然后配置和构建它们了。这一步是必需的，原因有几个：第一个是我们需要一个内核来引导我们的 ESPRESSObin 以启动操作系统，第二个是我们需要一个配置好的内核源树来编译我们的驱动程序。

# 准备就绪

由于我们的 ESPRESSObin 现在已经支持到 vanilla 内核自 4.11 版本以来，我们可以使用以下`git`命令获取 Linux 源代码：

```
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
```

这个命令需要很长时间才能完成，所以我建议您喝杯您最喜欢的咖啡休息一下（就像真正的程序员应该做的那样）。

完成后，我们可以进入`linux`目录查看 Linux 源代码：

```
$ cd linux/
$ ls
arch CREDITS firmware ipc lib mm scripts usr
block crypto fs Kbuild LICENSES net security virt
certs Documentation include Kconfig MAINTAINERS README sound
COPYING drivers init kernel Makefile samples tools
```

这些源代码与最新的内核发布相关，可能不稳定，因此为了确保我们使用的是稳定的内核发布（或*长期发布*），让我们提取 4.18 版本，这是撰写本章时的当前稳定发布，如下所示：

```
$ git checkout -b v4.18 v4.18
```

# 如何做...

在开始编译之前，我们必须配置内核和我们的编译环境。

1.  最后一个任务非常简单，它包括执行以下环境变量分配：

```
$ export ARCH=arm64
$ export CROSS_COMPILE=aarch64-linux-gnu-
```

1.  然后，我们可以通过简单地使用以下命令选择 ESPRESSObin 标准内核配置：

```
$ make defconfig
```

根据您使用的内核版本，默认配置文件也可能称为`mvebu_defconfig`，也可能称为`mvebu_v5_defconfig`或`mvebu_v7_defconfig`。因此，请查看`linux/arch/arm64/configs/`目录，以查看哪个文件最适合您的需求。

在我的系统中，我有以下内容：

**`$ ls linux/arch/arm64/configs/`**

`defconfig`

1.  如果我们希望修改此默认配置，可以执行`make menuconfig`命令，这将显示一个漂亮的菜单，我们可以在其中输入我们的修改以满足我们的需求。以下屏幕截图显示了内核配置菜单在终端上的外观：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/0b6ceb4e-3a6e-4ace-b9f6-6eca264c1138.png)

1.  在继续之前，我们必须确保**分布式交换架构**（**DSA**）已经在内核中启用，否则我们将无法使用以太网端口！这是因为 ESPRESSObin 具有一个复杂（而且非常强大）的内部网络交换机，必须使用此特殊支持进行管理。

有关 DSA 的更多信息，您可以开始阅读`linux/Documentation/networking/dsa/dsa.txt`文件，该文件位于我们目前正在处理的内核源代码中。

1.  要启用 DSA 支持，只需在内核菜单中导航至网络支持。转到网络选项，最后启用分布式交换架构支持条目。之后，我们必须返回到菜单的顶层，然后选择这些条目：设备驱动程序 | 网络设备支持 | 分布式交换架构驱动程序，然后启用 Marvell 88E6xxx 以太网交换芯片支持，这是 ESPRESSObin 的内置交换芯片。

请记住，要将内核功能启用为模块或内置，您需要突出显示所需的功能，然后按空格键，直到<>字符内的字符更改为*（表示内置，即<*>)或 M（表示模块，即<M>)。

请注意，要将 DSA 作为内置启用而不是作为模块，我们必须禁用 802.1d 以太网桥接支持（即上面的条目）。

1.  好了，所有内核设置都就绪后，我们可以使用以下`make`命令开始内核编译：

```
$ make Image dtbs modules
```

与下载命令一样，此命令将需要很长时间才能完成，因此让我建议您再休息一下。但是，为了加快编译过程，您可以尝试使用`-j`选项参数，告诉`make`使用多个并行进程来编译代码。例如，在我的机器上，有八个 CPU 线程，我使用以下命令：

**`$ make -j8 Image dtbs modules`**

因此，让我们尝试使用以下`lscpu`命令来获取系统的 CPU 数量：

**`lscpu | grep '^CPU(s):'`**

`CPU(s): 8`

或者，在 Ubuntu/Debian 上，还有预安装的`nproc`实用程序，因此以下命令也可以完成任务：

**`$ make -j$(nproc)`**

完成后，我们应该将内核映像放入`arch/arm64/boot/Image`文件中，并将设备树二进制文件放入`arch/arm64/boot/dts/marvell/armada-3720-espressobin.dtb`文件中，这些文件已准备好传输到我们将在下一个配方中构建的 microSD 中，*设置目标机器*。

# 另请参阅

+   有关可用的 ESPRESSObin 内核版本以及如何获取、编译和安装它们的进一步信息，请参阅 ESPRESSObin 的维基页面[`wiki.espressobin.net/tiki-index.php?page=Build+From+Source+-+Kernel`](http://wiki.espressobin.net/tiki-index.php?page=Build+From+Source+-+Kernel)。

# 设置目标机器

现在，是时候在目标系统上安装我们需要的东西了；由于 ESPRESSObin 只带有引导加载程序出售，我们必须做一些工作，以便获得一个具有适当操作系统的完全功能系统。

在本书中，我将使用 Debian OS 为 ESPRESSObin，但您可以使用其他 OS，如[`wiki.espressobin.net/tiki-index.php?page=Software+HowTo`](http://wiki.espressobin.net/tiki-index.php?page=Software+HowTo)中所述。在这个网站上，您可以获取有关如何正确设置 ESPRESSObin 以满足您需求的更详细信息。

# 准备工作

即使 ESPRESSObin 可以从不同的介质引导，我们将使用 microSD，因为这是设置系统的最简单和最有用的方式。有关不同介质，请参阅 ESPRESSObin 的维基页面—参见[`wiki.espressobin.net/tiki-index.php?page=Boot+from+removable+storage+-+Ubuntu`](http://wiki.espressobin.net/tiki-index.php?page=Boot+from+removable+storage+-+Ubuntu)以获取一些示例。

# 如何做到这一点...

要设置 microSD，我们必须使用我们的主机 PC，因此插入它，然后找到相应的设备。

1.  如果我们使用 SD/microSD 插槽，一旦插入介质，我们将在内核消息中得到类似以下内容：

```
mmc0: cannot verify signal voltage switch
mmc0: new ultra high speed SDR50 SDHC card at address aaaa
mmcblk0: mmc0:aaaa SL08G 7.40 GiB 
 mmcblk0: p1
```

要在终端上获取内核消息，我们可以使用`dmesg`命令。

但是，如果我们要使用 microSD 到 USB 适配器内核，消息将如下所示：

```
usb 1-6: new high-speed USB device number 5 using xhci_hcd
usb 1-6: New USB device found, idVendor=05e3, idProduct=0736
usb 1-6: New USB device strings: Mfr=3, Product=4, SerialNumber=2
usb 1-6: Product: USB Storage
usb 1-6: Manufacturer: Generic
usb 1-6: SerialNumber: 000000000272
usb-storage 1-6:1.0: USB Mass Storage device detected
scsi host4: usb-storage 1-6:1.0
usbcore: registered new interface driver usb-storage
usbcore: registered new interface driver uas
scsi 4:0:0:0: Direct-Access Generic STORAGE DEVICE 0272 PQ: 0 ANSI: 0
sd 4:0:0:0: Attached scsi generic sg3 type 0
sd 4:0:0:0: [sdc] 15523840 512-byte logical blocks: (7.95 GB/7.40 GiB)
sd 4:0:0:0: [sdc] Write Protect is off
sd 4:0:0:0: [sdc] Mode Sense: 0b 00 00 08
sd 4:0:0:0: [sdc] No Caching mode page found
sd 4:0:0:0: [sdc] Assuming drive cache: write through
 sdc: sdc1
sd 4:0:0:0: [sdc] Attached SCSI removable disk
```

1.  另一个查找介质的简单方法是使用`lsblk`命令，如下所示：

```
$ lsblk 
NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
loop0 7:0 0 5M 1 loop /snap/gedit/66
loop1 7:1 0 4.9M 1 loop /snap/canonical-livepatch/50
...
sdb 8:16 0 931.5G 0 disk 
└─sdb1 8:17 0 931.5G 0 part /run/schroot/mount/ubuntu-xenial-amd64-f72c490
sr0 11:0 1 1024M 0 rom 
mmcblk0 179:0 0 7.4G 0 disk 
└─mmcblk0p1
        179:1 0 7.4G 0 part /media/giometti/5C60-6750
```

1.  现在很明显，我们的 microSD 卡在此列为`/dev/mmcblk0`，但它不是空的。由于我们想要清除它的所有内容，我们必须首先使用以下命令清除它：

```
$ sudo dd if=/dev/zero of=/dev/mmcblk0 bs=1M count=100
```

1.  在进行清除之前，您可能需要卸载设备，以便在媒体设备上安全工作，因此让我们使用`umount`命令在所有设备的所有分区上卸载它们，就像我将在我的 microSD 上的唯一定义的分区中所做的那样：

```
$ sudo umount /dev/mmcblk0p1
```

对于 microSD 上定义的每个分区，您必须重复此命令。

1.  现在，我们将使用下一个命令在空 SD 卡上创建一个新分区`/dev/mmcblk0p1`：

```
$ (echo n; echo p; echo 1; echo ''; echo ''; echo w) | sudo fdisk /dev/mmcblk0
```

如果一切正常，我们的 microSD 介质应该显示为格式化的，如下所示：

```
$ sudo fdisk -l /dev/mmcblk0
Disk /dev/mmcblk0: 7.4 GiB, 7948206080 bytes, 15523840 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x34f32673

Device Boot Start End Sectors Size Id Type
/dev/mmcblk0p1 2048 15523839 15521792 7.4G 83 Linux
```

1.  然后，我们必须使用以下命令将其格式化为 EXT4：

```
$ sudo mkfs.ext4 -O ^metadata_csum,⁶⁴bit -L root /dev/mmcblk0p1
```

请注意，此命令行仅适用于`e2fsprogs`版本>=1.43！如果您使用较旧的版本，应使用以下命令：

**`$ sudo mkfs.ext4 -L root /dev/mmcblk0p1`**

1.  接下来，在本地 Linux 机器上挂载此分区：

```
$ sudo mount /dev/mmcblk0p1 /mnt/
```

请注意，在某些操作系统（特别是 Ubuntu）上，一旦我们拔掉然后再次插入媒体设备，它就会自动挂载到`/media/$USER/root`中，其中`$USER`是一个保存您用户名的环境变量。例如，在我的机器上，我有以下内容：

**`$ ls -ld /media/$USER/root`**

`drwxr-xr-x 3 root root 4096 Jan 10 14:28 /media/giometti/root/`

# 添加 Debian 文件

我决定使用 Debian 作为目标操作系统，因为它是我用于开发（并且在可能的情况下用于生产）系统的最喜欢的发行版：

1.  要安装它，我们再次使用 QEMU 软件，使用以下命令：

```
$ sudo qemu-debootstrap \
 --arch=arm64 \
 --include="sudo,file,openssh-server" \
 --exclude="debfoster" \
 stretch ./debian-stretch-arm64 http://deb.debian.org/debian
```

您可能会看到有关密钥环的警告；它们是无害的，可以安全地忽略：

`W: 无法检查发布签名；`

我想这是另一个咖啡时间的命令。

1.  完成后，我们应该在`debian-stretch-arm64`中找到一个干净的 Debian 根文件系统，但是，在将其转移到 microSD 之前，我们应该像这样修复`hostname`文件的内容：

```
$ sudo bash -c 'echo espressobin | cat > ./debian-stretch-arm64/etc/hostname'
```

1.  然后，我们必须将串行设备`ttyMV0`添加到`/etc/securetty`文件中，以便能够通过串行设备`/dev/ttyMV0`登录为根用户。使用以下命令：

```
$ sudo bash -c 'echo -e "\n# Marvell serial ports\nttyMV0" | \
 cat >> ./debian-stretch-arm64/etc/securetty'
```

使用`man securetty`获取有关通过串行连接登录根用户的更多信息。

1.  最后一步，我们必须设置根密码：

```
$ sudo chroot debian-stretch-arm64/ passwd
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
```

在这里，我使用`root`字符串作为根用户的密码（您可以选择自己的密码）。

为了进一步了解`chroot`命令的使用，您可以使用`man chroot`命令，或者继续阅读本章的最后，我将更好地解释它的工作原理。

现在，我们可以使用以下命令将所有文件安全地复制到我们的 microSD 中：

```
$ sudo cp -a debian-stretch-arm64/* /media/$USER/root/
```

这是 microSD 内容应该是这样的：

```
$ ls /media/$USER/root/
bin   dev  home  lost+found  mnt  proc  run   srv  tmp  var
boot  etc  lib   media       opt  root  sbin  sys  usr
```

# 添加内核

在 OS 文件之后，我们还需要内核映像来获得运行的内核，并且在前面的部分中，我们将内核映像放入`arch/arm64/boot/Image`文件中，并将设备树二进制文件放入`arch/arm64/boot/dts/marvell/armada-3720-espressobin.dtb`文件中，这些文件已准备好转移到我们新创建的 microSD 中：

1.  让我们将它们复制到`/boot`目录中，就像这样：

```
$ sudo cp arch/arm64/boot/Image \
 arch/arm64/boot/dts/marvell/armada-3720-espressobin.dtb \
 /media/$USER/root/boot/
```

如果 microSD 中没有`/boot`目录，并且前面的命令返回错误，您可以使用以下命令进行恢复，并重新运行前面的`cp`命令：

`$ sudo mkdir /media/$USER/root/boot`

然后，`/boot`目录应该是这样的：

```
$ ls /media/$USER/root/boot/
armada-3720-espressobin.dtb  Image
```

1.  前面的文件足以启动系统；但是，为了安装内核模块和头文件，这对于编译新软件很有用，我们可以在将所有 Debian 文件安装到 microSD 后使用下一个命令（以避免用 Debian 文件覆盖）：

```
$ sudo -E make modules_install INSTALL_MOD_PATH=/media/$USER/root/
$ sudo -E make headers_install INSTALL_HDR_PATH=/media/$USER/root/usr/
```

好了，现在我们终于准备好将所有内容绑定在一起并运行我们的新 Debian 系统，所以让我们卸载 microSD 并将其插入 ESPRESSObin。

# 设置引导变量

上电后，我们应该从串行控制台获得引导加载程序的消息，然后我们应该看到超时运行到 0，然后执行自动引导：

1.  通过按键盘上的*Enter*键快速停止倒计时，以获得引导加载程序的提示，如下所示：

```
Model: Marvell Armada 3720 Community Board ESPRESSOBin
       CPU @ 1000 [MHz]
       L2 @ 800 [MHz]
       TClock @ 200 [MHz]
       DDR @ 800 [MHz]
DRAM: 2 GiB
U-Boot DComphy-0: USB3 5 Gbps 
Comphy-1: PEX0 2.5 Gbps 
Comphy-2: SATA0 6 Gbps 
SATA link 0 timeout.
AHCI 0001.0300 32 slots 1 ports 6 Gbps 0x1 impl SATA mode
flags: ncq led only pmp fbss pio slum part sxs 
PCIE-0: Link down
MMC: sdhci@d0000: 0
SF: Detected w25q32dw with page size 256 Bytes, erase size 4 KiB, total 4 MiB
Net: eth0: neta@30000 [PRIME]
Hit any key to stop autoboot: 0 
Marvell>>
```

ESPRESSObin 的引导加载程序是 U-Boot，其主页位于[`www.denx.de/wiki/U-Boot`](https://www.denx.de/wiki/U-Boot)。

1.  现在，让我们再次使用`ext4ls`命令检查 microSD 卡是否具有必要的文件，如下所示：

```
Marvell>> ext4ls mmc 0:1 boot
<DIR> 4096 .
<DIR> 4096 ..
        18489856 Image
            8359 armada-3720-espressobin.dtb
```

好了，一切就绪，所以只需要一些变量就可以从 microSD 卡启动。

1.  我们可以使用`echo`命令在任何时候显示当前定义的变量，并且可以使用`setenv`命令可选地重新配置它们。首先，检查并设置正确的镜像和设备树路径和名称：

```
Marvell>> echo $image_name
Image
Marvell>> setenv image_name boot/Image
Marvell>> echo $fdt_name
armada-3720-espressobin.dtb
Marvell>> setenv fdt_name boot/armada-3720-espressobin.dtb
```

请注意，文件名是正确的，但路径名不正确；这就是为什么我使用`setenv`命令正确重新定义它们。

1.  接下来，定义`bootcmd`变量，我们将使用它从 microSD 卡启动：

```
Marvell>> setenv bootcmd 'mmc dev 0; \
 ext4load mmc 0:1 $kernel_addr $image_name; \
 ext4load mmc 0:1 $fdt_addr $fdt_name; \
 setenv bootargs $console root=/dev/mmcblk0p1 rw rootwait; \
 booti $kernel_addr - $fdt_addr'
```

我们必须小心设置前面的根路径，指向我们提取 Debian 文件系统的位置（在我们的情况下是第一个分区）。

1.  使用`saveenv`命令随时保存设置的变量。

1.  最后，我们通过简单输入`reset`命令启动 ESPRESSObin，如果一切正常，我们应该看到系统启动并运行，最后，我们应该看到系统登录提示，如下所示：

```
Debian GNU/Linux 9 espressobin ttyMV0

giometti-VirtualBox login:
```

1.  现在，使用之前设置的`root`密码以 root 身份登录：

```
Debian GNU/Linux 9 espressobin ttyMV0

espressobin login: root
Password: 
Linux espressobin 4.18.0 #2 SMP PREEMPT Sun Jan 13 13:05:03 CET 2019 aarch64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@espressobin:~# 
```

# 设置网络

好了，现在我们的 ESPRESSObin 已经准备好执行我们的代码和驱动程序了！然而，在结束本节之前，让我们看一下网络配置，因为使用 SSH 连接登录到板上或者快速复制文件可能会进一步有用（即使我们可以移除 microSD，然后直接从主机 PC 复制文件）：

1.  查看 ESPRESSObin 上可用的网络接口，我们看到以下内容：

```
# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
 group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group
 default qlen 532
    link/ether 3a:ac:9b:44:90:e9 brd ff:ff:ff:ff:ff:ff
3: wan@eth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode DE
FAULT group default qlen 1000
    link/ether 3a:ac:9b:44:90:e9 brd ff:ff:ff:ff:ff:ff
4: lan0@eth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode D
EFAULT group default qlen 1000
    link/ether 3a:ac:9b:44:90:e9 brd ff:ff:ff:ff:ff:ff
5: lan1@eth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN mode D
EFAULT group default qlen 1000
    link/ether 3a:ac:9b:44:90:e9 brd ff:ff:ff:ff:ff:ff
```

`eth0`接口是将 CPU 与以太网交换机连接的接口，而`wan`、`lan0`和`lan1`接口是我们可以物理连接以太网电缆的接口（请注意，系统将它们称为`wan@eth0`、`lan0@eth0`和`lan1@eth1`，以突出它们是`eth0`的从属）。以下是 ESPRESSObin 的照片，我们可以看到每个以太网端口及其标签：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/ef6d52cc-44e8-47c7-a928-cefca0bcfe87.png)

1.  尽管它们的名称不同，但所有端口都是等效的，因此将以太网电缆连接到一个端口（我将使用`wan`），然后在`eth0`之后启用它，如下所示：

```
# ip link set eth0 up
mvneta d0030000.ethernet eth0: configuring for fixed/rgmii-id link mode
mvneta d0030000.ethernet eth0: Link is Up - 1Gbps/Full - flow control off
# ip link set wan up 
mv88e6085 d0032004.mdio-mii:01 wan: configuring for phy/ link mode
mv88e6085 d0032004.mdio-mii:01 wan: Link is Up - 100Mbps/Full - flow control rx/tx
```

请注意，在上述输出中，还有显示一切正常时应看到的内核消息。

1.  现在，我们可以手动设置 IP 地址，或者使用`dhclient`命令询问 DHCP 服务器，以获取上网所需的信息：

```
# dhclient wan
```

这是我的网络配置：

```
# ip addr show wan
3: wan@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP g
roup default qlen 1000
    link/ether 9e:9f:6b:5c:cf:fc brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.100/24 brd 192.168.0.255 scope global wan
       valid_lft forever preferred_lft forever
```

1.  现在，我们已经准备好安装新软件，或者尝试建立与 ESPRESSObin 的 SSH 连接；为此，让我们验证`/etc/ssh/sshd_config`文件中是否有以下 SSH 服务器的配置：

```
# grep 'PermitRootLogin yes' /etc/ssh/sshd_config
PermitRootLogin yes
```

1.  如果我们没有输出，就无法以 root 身份登录到我们的 ESPRESSObin，因此我们必须将`PermitRootLogin`设置更改为`yes`，然后重新启动守护程序：

```
# /etc/init.d/ssh restart

Restarting ssh (via systemctl): ssh.service.
```

1.  现在，在主机 PC 上，我们可以尝试通过 SSH 登录，如下所示：

```
$ ssh root@192.168.0.100
root@192.168.0.100's password: 
Linux espressobin 4.18.0 #2 SMP PREEMPT Sun Jan 13 13:05:03 CET 2019 aarch64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Nov 3 17:16:59 2016
-bash: warning: setlocale: LC_ALL: cannot change locale (en_GB.UTF-8)
```

# 参见

+   要获取有关如何在不同操作系统上设置 ESPRESSObin 的更多信息，您可以查看[`wiki.espressobin.net/tiki-index.php?page=Software+HowTo`](http://wiki.espressobin.net/tiki-index.php?page=Software+HowTo)。

+   有关`qemu-debootstrap`的更多信息，一个很好的起点是[`wiki.ubuntu.com/ARM/RootfsFromScratch/QemuDebootstrap`](https://wiki.ubuntu.com/ARM/RootfsFromScratch/QemuDebootstrap)。要管理以太网设备并获取有关 Debian 操作系统上网络的更多信息，您可以查看以下内容：[`wiki.debian.org/NetworkConfiguration`](https://wiki.debian.org/NetworkConfiguration)。

# 在外部硬件上进行本地编译

在结束本章之前，我想介绍一个有趣的跨平台系统，当我们需要在开发 PC 上运行多个不同的操作系统时非常有用。当我们需要一个完整的操作系统来编译设备驱动程序或应用程序，但没有目标设备来进行编译时，这一步非常有用。我们可以使用我们的主机 PC 来跨不同的操作系统和操作系统版本为外部硬件编译代码。

# 准备就绪

在我的职业生涯中，我使用了大量不同的平台，并且为它们所有都有一个虚拟机非常复杂且真正消耗系统资源（特别是如果我们决定同时运行其中几个！）。这就是为什么拥有一个可以在您的 PC 上执行外部代码的轻量级系统可能会很有趣。当然，这种方法不能用于测试设备驱动程序（我们需要真正的硬件来进行测试），但我们可以用它来快速运行本地编译器和/或本地用户空间代码，以防我们的嵌入式平台出现问题。让我们看看我在说什么。

在*设置目标机器*配方中，关于 Debian OS 安装，我们使用`chroot`命令设置根密码。这个命令得到了 QEMU 的支持；事实上，在`debian-stretch-arm64`目录中，我们有一个 ARM64 根文件系统，可以在 x86_64 平台上仅使用 QEMU 执行。很明显，以这种方式，我们应该能够执行任何我们想要的命令，当然，我们将能够像下一个配方中一样执行 Bash shell。

# 如何做...

现在是时候看看`chroot`是如何工作的了：

1.  通过使用我们的 x86_64 主机执行 ARM64 `bash`命令，如下所示：

```
$ sudo chroot debian-stretch-arm64/ bash
bash: warning: setlocale: LC_ALL: cannot change locale (en_GB.UTF-8)
root@giometti-VirtualBox:/# 
```

1.  然后，我们可以像在 ESPRESSObin 上那样使用每个 ARM64 命令；例如，要列出当前目录中的文件，我们可以使用以下命令：

```
# ls /
bin  dev  home media  opt   root  sbin  sys  usr
boot etc  lib  mnt    proc  run   srv   tmp  var
# cat /etc/hostname 
espressobin
```

但是，也有一些陷阱；例如，我们完全错过了`/proc`和`/sys`目录和程序，这些程序依赖于它们，肯定会失败：

```
# ls /{proc,sys}
/proc:

/sys:
# ps
Error: /proc must be mounted
  To mount /proc at boot you need an /etc/fstab line like:
      proc /proc proc defaults
  In the meantime, run "mount proc /proc -t proc"
```

为了解决这些问题，我们可以在执行`chroot`之前手动挂载这些缺失的目录，但由于它们太多了，这相当麻烦，所以我们可以尝试使用`schroot`实用程序，它反过来可以为我们完成所有这些步骤。让我们看看如何做。

有关`schroot`的详细信息，您可以使用`man schroot`查看其手册页面。

# 安装和配置 schroot

在 Ubuntu 中，这个任务非常简单：

1.  首先，我们以通常的方式安装程序：

```
$ sudo apt install schroot
```

1.  然后，我们必须配置它，以便正确进入我们的 ARM64 系统。为此，让我们将之前创建的根文件系统复制到一个专用目录中（在那里我们还可以添加任何其他我们希望用`schroot`模拟的发行版）：

```
$ sudo mkdir /srv/chroot/
$ sudo cp -a debian-stretch-arm64/ /srv/chroot/
```

1.  然后，我们必须通过在`schroot`配置目录中添加一个新文件来为我们的新系统创建适当的配置，如下所示：

```
$ sudo bash -c 'cat > /etc/schroot/chroot.d/debian-stretch-arm64 <<__EOF__
[debian-stretch-arm64]
description=Debian Stretch (arm64)
directory=/srv/chroot/debian-stretch-arm64
users=giometti
#groups=sbuild
#root-groups=root
#aliases=unstable,default
type=directory
profile=desktop
personality=linux
preserve-environment=true
__EOF__'
```

请注意，`directory`参数设置为包含我们的 ARM64 系统的路径，`users`设置为`giometti`，这是我的用户名（这是允许访问`chroot`环境的用户的逗号分隔列表—请参阅`man schroot.conf`）。

从前面的设置中，我们看到`profile`参数设置为`desktop`；这意味着它将考虑`/etc/schroot/desktop/`目录中的所有文件。特别是，`fstab`文件包含我们希望挂载到系统中的所有挂载点。因此，我们应该验证它至少包含以下行：

```
# <filesystem> <mount point> <type> <options> <dump> <pass>
/proc           /proc         none   rw,bind   0      0
/sys            /sys          none   rw,bind   0      0
/dev            /dev          none   rw,bind   0      0
/dev/pts        /dev/pts      none   rw,bind   0      0
/home           /home         none   rw,bind   0      0
/tmp            /tmp          none   rw,bind   0      0
/opt            /opt          none   rw,bind   0      0
/srv            /srv          none   rw,bind   0      0
tmpfs           /dev/shm      tmpfs  defaults  0      0
```

1.  现在，我们必须重新启动`schroot`服务，如下所示：

```
$ sudo systemctl restart schroot
```

请注意，您也可以使用老式的方法重新启动：

**`$ sudo /etc/init.d/schroot restart`**

1.  现在我们可以通过要求它们`schroot`来列出所有可用的环境，如下所示：

```
$ schroot -l
 chroot:debian-stretch-arm64
```

1.  好的，一切就绪，我们可以进入模拟的 ARM64 系统了：

```
$ schroot -c debian-stretch-arm64
bash: warning: setlocale: LC_ALL: cannot change locale (en_GB.UTF-8)
```

由于我们还没有安装任何区域设置支持，因此前面的警告是相当明显的，应该可以安全地忽略。

1.  现在，为了验证我们是否真的在执行 ARM64 代码，让我们尝试一些命令。例如，我们可以使用`uname`命令请求一些系统信息：

```
$ uname -a
Linux giometti-VirtualBox 4.15.0-43-generic #46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 aarch64 GNU/Linux
```

正如我们所看到的，系统显示其平台为`aarch64`，即 ARM64。然后，我们可以尝试执行之前交叉编译的`helloworld`程序；因为在`chroot`之后，当前目录没有改变（我们的主目录仍然是相同的），我们可以简单地回到编译的地方，然后像往常一样执行程序：

```
$ cd ~/Projects/ldddc/github/chapter_1/
$ file helloworld
helloworld: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=c0d6e9ab89057e8f9101f51ad517a253e5fc4f10, not stripped
$ ./helloworld
Hello World!
```

该程序仍然像我们在 ARM64 系统上时一样执行。太棒了！

# 配置模拟的操作系统

如果我们不配置新系统进行本地编译，那么我们刚才看到的关于`schroot`的一切都没有意义，为了这样做，我们可以使用我们在主机 PC 上使用的每个 Debian 工具：

1.  安装完整的编译环境后，我们可以在`schroot`环境中执行以下命令：

```
$ sudo apt install gcc make \
 bison flex ncurses-dev libssl-dev
```

请注意，`sudo`将要求您通常的密码，也就是您当前用于登录到主机 PC 的密码。

您可能不会从`sudo`获得密码请求，而会收到以下错误消息：

`sudo: no tty present and no askpass program specified`

您可以尝试再次执行前面的`sudo`命令，并添加`-S`选项参数。

`apt`命令可能会通知您某些软件包无法得到验证。只需忽略此警告并继续安装，按下*Y*键回答是。

如果一切顺利，我们现在应该能够执行之前使用的每个编译命令。例如，我们可以尝试再次本地重新编译`helloworld`程序（我们应该先删除当前的可执行文件；`make`将尝试重新编译它）：

```
$ rm helloworld
$ make CFLAGS="-Wall -O2" helloworld
cc -Wall -O2 helloworld.c -o helloworld
$ file helloworld
helloworld: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=1393450a08fb9eea22babfb9296ce848bb806c21, not stripped
$ ./helloworld
Hello World!
```

请注意，网络支持是完全功能的，因此我们现在正在主机 PC 上的模拟 ARM64 环境上工作，就像我们在 ESPRESSObin 上一样。

# 另请参阅

+   在互联网上，有关`schroot`使用的几个示例，一个很好的起点是[`wiki.debian.org/Schroot`](https://wiki.debian.org/Schroot)。


# 第二章：深入了解内核

简单的操作系统（如 MS-DOS）总是在单 CPU 模式下执行，但类 Unix 操作系统使用双模式来有效地实现时间共享和资源分配和保护。在 Linux 中，CPU 在任何时候都处于受信任的**内核模式**（我们可以做任何我们想做的事情）或受限的**用户模式**（某些操作不允许）。所有用户进程都在用户模式下执行，而核心内核本身和大多数设备驱动程序（除了在用户空间实现的驱动程序）都在内核模式下运行，因此它们可以无限制地访问整个处理器指令集以及完整的内存和 I/O 空间。

当用户模式进程需要访问外围设备时，它不能自己完成，而必须通过设备驱动程序或其他内核模式代码通过**系统调用**来传递请求，系统调用在控制进程活动和管理数据交换中起着重要作用。在本章中，我们不会看到系统调用（它们将在第三章中介绍），但我们将通过直接向内核源代码添加新代码或使用内核模块来开始在内核中编程，这是另一种更灵活的方式来向内核添加代码。

一旦我们开始编写内核代码，我们必须不要忘记，当处于用户模式时，每个资源分配（CPU、RAM 等）都由内核自动管理（当进程死亡时可以适当释放它们），在内核模式下，我们被允许独占处理器，直到我们自愿放弃 CPU 或发生中断或异常；此外，如果不适当释放，每个请求的资源（如 RAM）都会丢失。这就是为什么正确管理 CPU 使用和释放我们请求的任何资源非常重要！

现在，是时候第一次跳入内核了，因此在本章中，我们将涵盖以下示例：

+   向源代码添加自定义代码

+   使用内核消息

+   使用内核模块

+   使用模块参数

# 技术要求

在本章中，我们需要在第一章的*配置和构建内核*示例中已经下载的内核源代码，当然，我们还需要安装交叉编译器，就像在第一章的*设置主机机器*示例中所示。本章中使用的代码和其他文件可以从 GitHub 上下载：[`github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_02`](https://github.com/giometti/linux_device_driver_development_cookbook/tree/master/chapter_02)。

# 向源代码添加自定义代码

作为第一步，让我们看看如何向我们的内核源代码中添加一些简单的代码。在这个示例中，我们将简单地添加一些愚蠢的代码，只是为了演示它有多容易，但在本书的后面，我们将添加更复杂的代码。

# 准备工作

由于我们需要将我们的代码添加到 Linux 源代码中，让我们进入存放所有源代码的目录。在我的系统中，我使用位于我的主目录中的`Projects/ldddc/linux/`路径。以下是内核源代码的样子：

```
$ cd Projects/ldddc/linux/
$ ls
arch        Documentation  Kbuild       mm               scripts   virt
block       drivers        Kconfig      modules.builtin  security  vmlinux
built-in.a  firmware       kernel       modules.order    sound     vmlinux.o
certs       fs             lib          Module.symvers   stNXtP40
COPYING     include        LICENSES     net System.map
CREDITS     init           MAINTAINERS  README tools
crypto      ipc            Makefile     samples usr
```

现在，我们需要设置环境变量`ARCH`和`CROSS_COMPILE`，如下所示，以便能够为 ESPRESSObin 进行交叉编译代码：

```
$ export ARCH=arm64
$ export CROSS_COMPILE=aarch64-linux-gnu-
```

因此，如果我们尝试执行以下`make`命令，系统应该像往常一样开始编译内核：

```
$ make Image dtbs modules
  CALL scripts/checksyscalls.sh
...
```

请注意，您可以通过在以下命令行上指定它们来避免导出前面的变量：

`$ make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \`

`Image dtbs modules`

此时，内核源代码和编译环境已经准备就绪。

# 如何做...

让我们按照以下步骤来做：

1.  由于本书涉及设备驱动程序，让我们从 Linux 源代码的`drivers`目录下开始添加我们的代码，具体来说是在`drivers/misc`中，杂项驱动程序所在的地方。我们应该在`drivers/misc`中放置一个名为`dummy-code.c`的文件，内容如下：

```
/*
 * Dummy code
 */

#include <linux/module.h>

static int __init dummy_code_init(void)
{
    printk(KERN_INFO "dummy-code loaded\n");
    return 0;
}

static void __exit dummy_code_exit(void)
{
    printk(KERN_INFO "dummy-code unloaded\n");
}

module_init(dummy_code_init);
module_exit(dummy_code_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rodolfo Giometti");
MODULE_DESCRIPTION("Dummy code");
```

1.  我们的新文件`drivers/misc/dummy-code.c`如果不正确地插入到内核配置和构建系统中，将不会产生任何效果。为了做到这一点，我们必须修改`drivers/misc/Kconfig`和`drivers/misc/Makefile`文件如下。前者文件必须更改如下：

```
--- a/drivers/misc/Kconfig
+++ b/drivers/misc/Kconfig
@@ -527,4 +527,10 @@ source "drivers/misc/echo/Kconfig"
 source "drivers/misc/cxl/Kconfig"
 source "drivers/misc/ocxl/Kconfig"
 source "drivers/misc/cardreader/Kconfig"
+
+config DUMMY_CODE
+       tristate "Dummy code"
+       default n
+       ---help---
+         This module is just for demonstration purposes.
 endmenu
```

后者的修改如下：

```
--- a/drivers/misc/Makefile
+++ b/drivers/misc/Makefile
@@ -58,3 +58,4 @@ obj-$(CONFIG_ASPEED_LPC_SNOOP) += aspeed-lpc-snoop.o
 obj-$(CONFIG_PCI_ENDPOINT_TEST) += pci_endpoint_test.o
 obj-$(CONFIG_OCXL) += ocxl/
 obj-$(CONFIG_MISC_RTSX) += cardreader/
+obj-$(CONFIG_DUMMY_CODE) += dummy-code.o
```

请注意，您可以通过在 Linux 源代码的主目录中使用`patch`命令轻松添加前面的代码以及编译所需的任何内容，如下所示：

**`$ patch -p1 < add_custom_code.patch`**

1.  好吧，如果我们现在使用`make menuconfig`命令，并且我们通过设备驱动程序导航到杂项设备菜单条目的底部，我们应该会得到以下截图所示的内容：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev-cb/img/01c65282-ef07-458f-bc60-be630fb3a9e1.png)

在前面的截图中，我已经选择了虚拟代码条目，以便我们可以看到最终的设置应该是什么样子的。

请注意，虚拟代码条目必须选择为内置（`*`字符），而不是模块（`M`字符）。

还要注意，如果我们不执行`make menuconfig`命令，而是直接执行`make Image`命令来编译内核，那么构建系统将询问我们如何处理`DUMMY_CODE`设置，如下所示。显然，我们必须使用`y`字符回答是：

**`$ make Image`**

`scripts/kconfig/conf --syncconfig Kconfig`

`*`

`* 重新启动配置...`

`*`

`*`

`* 杂项设备`

`*`

`模拟设备数字电位器（AD525X_DPOT）[N/m/y/?] n`

`...`

`虚拟代码（DUMMY_CODE）[N/m/y/?]（NEW）y`

1.  如果一切都摆放正确，那么我们执行`make Image`命令重新编译内核。我们应该看到我们的新文件被编译然后添加到内核`Image`文件中，如下所示：

```
$ make Image
scripts/kconfig/conf --syncconfig Kconfig
...
  CC drivers/misc/dummy-code.o
  AR drivers/misc/built-in.a
  AR drivers/built-in.a
...
  LD vmlinux
  SORTEX vmlinux
  SYSMAP System.map
  OBJCOPY arch/arm64/boot/Image
```

1.  好了，现在我们要做的就是用刚刚重新构建的`Image`文件替换 microSD 上的`Image`文件，然后重新启动系统（参见第一章中的*如何添加内核*配方，*安装开发系统*）。

# 它是如何工作的...

现在，是时候看看之前所有步骤是如何工作的了。在接下来的章节中，我们将更好地解释这段代码的真正作用。但是，目前，我们应该注意以下内容。

在*步骤 1*中，请注意对`module_init()`和`module_exit()`的调用，这是内核提供的 C 宏，用于告诉内核，在系统启动或关闭期间，必须调用我们提供的函数，名为`dummy_code_init()`和`dummy_code_exit()`，这些函数只是打印一些信息消息。

在本章的后面，我们将详细了解`printk()`的作用以及`KERN_INFO`宏的含义，但是目前，我们只需要考虑它们用于在引导（或关闭）期间打印消息。例如，前面的代码指示内核在引导阶段的某个时候打印出消息 dummy-code loaded。

在*步骤 2*中，在`Makefile`中，我们只是告诉内核，如果启用了`CONFIG_DUMMY_CODE`（即`CONFIG_DUMMY_CODE=y`），那么必须编译并插入内核二进制文件（链接）`dummy-code.c`，而使用`Kconfig`文件，我们只是将新模块添加到内核配置系统中。

在*步骤 3*中，我们使用`make menuconfig`命令启用我们的代码的编译。

最后，在*步骤 4*中，我们重新编译内核以将我们的代码添加到其中。

在*步骤 5*中，在引导过程中，我们应该看到以下内核消息：

```
...
loop: module loaded
dummy-code loaded
ahci-mvebu d00e0000.sata: AHCI 0001.0300 32 slots 1 ports 6 Gbps
...
```

# 另请参阅

+   有关内核配置及其构建系统工作原理的更多信息，我们可以查看内核源代码中的内核文档文件，路径为`linux/Documentation/kbuild/kconfig-macro-language.txt`。

# 使用内核消息

正如前面所述，串行控制台在我们需要从头开始设置系统时非常有用，但如果我们希望在生成时立即看到内核消息，它也非常有用。为了生成内核消息，我们可以使用多个函数，在本教程中，我们将看看它们以及如何在串行控制台或通过 SSH 连接显示消息。

# 准备工作

我们的 ESPRESSObin 是生成内核消息的系统，所以我们需要与它建立连接。通过串行控制台，这些消息一旦到达就会自动显示，但如果我们使用 SSH 连接，我们仍然可以通过读取特定文件来显示它们，就像以下命令一样：

```
# tail -f /var/log/kern.log
```

然而，串行控制台值得特别注意：实际上，在我们的示例中，只有当`/proc/sys/kernel/printk`文件中最左边的数字大于七时，内核消息才会自动显示在串行控制台上，如下所示：

```
# cat /proc/sys/kernel/printk
10      4       1       7
```

这些魔术数字有明确定义的含义；特别是第一个代表内核必须在串行控制台上显示的错误消息级别。这些级别在`linux/include/linux/kern_levels.h`文件中定义，如下所示：

```
#define KERN_EMERG KERN_SOH "0"    /* system is unusable */
#define KERN_ALERT KERN_SOH "1"    /* action must be taken immediately */
#define KERN_CRIT KERN_SOH "2"     /* critical conditions */
#define KERN_ERR KERN_SOH "3"      /* error conditions */
#define KERN_WARNING KERN_SOH "4"  /* warning conditions */
#define KERN_NOTICE KERN_SOH "5"   /* normal but significant condition */
#define KERN_INFO KERN_SOH "6"     /* informational */
#define KERN_DEBUG KERN_SOH "7"    /* debug-level messages */
```

例如，如果前面文件的内容是 4，如下所示，只有具有`KERN_EMERG`、`KERN_ALERT`、`KERN_CRIT`和`KERN_ERR`级别的消息才会自动显示在串行控制台上：

```
# cat /proc/sys/kernel/printk
4       4       1       7
```

为了允许显示所有消息、它们的子集或不显示任何消息，我们必须使用`echo`命令修改`/proc/sys/kernel/printk`文件的最左边的数字，就像在以下示例中那样，我们以这种方式完全禁用所有内核消息的打印。这是因为没有消息的优先级可以大于 0：

```
 # echo 0 > /proc/sys/kernel/printk
```

内核消息的优先级从 0（最高）开始，到 7（最低）结束！

现在我们知道如何显示内核消息，我们可以尝试对内核代码进行一些修改，以便对内核消息进行一些实验。

# 如何做到...

在前面的示例中，我们看到可以使用`printk()`函数生成内核消息，但是还有其他函数可以替代`printk()`，以便获得更高效的消息和更紧凑可读的代码：

1.  使用以下宏（在`include/linux/printk.h`文件中定义），如下所示：

```
#define pr_emerg(fmt, ...) \
        printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...) \
        printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
        printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
        printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
        printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_notice(fmt, ...) \
        printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
        printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
```

1.  现在，要生成一个内核消息，我们可以这样做：查看这些定义，我们可以将前面示例中的`dummy_code_init()`和`dummy_code_exit()`函数重写到`dummy-code.c`文件中，如下所示：

```
static int __init dummy_code_init(void)
{
        pr_info("dummy-code loaded\n");
        return 0;
}

static void __exit dummy_code_exit(void)
{
        pr_info("dummy-code unloaded\n");
}
```

# 工作原理...

如果我们仔细观察前面的打印函数（`pr_info()`和类似的函数），我们会注意到它们还依赖于`pr_fmt(fmt)`参数，该参数可用于向我们的消息中添加其他有用的信息。例如，以下定义通过添加当前模块和调用函数名称来改变`pr_info()`生成的所有消息：

```
#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__
```

请注意，`pr_fmt()`宏定义必须出现在文件的开头，甚至在包含之前，才能生效。

如果我们将这行添加到我们的`dummy-code.c`中，内核消息将会按照描述发生变化：

```
/*
 * Dummy code
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__
#include <linux/module.h>
```

实际上，当执行`pr_info()`函数时，输出消息会告诉我们模块已被插入，变成以下形式，我们可以看到模块名称和调用函数名称，然后是加载消息：

```
dummy_code:dummy_code_init: dummy-code loaded
```

还有另一组打印函数，但在开始讨论它们之前，我们需要一些位于第三章中的信息，*使用设备树*，所以，暂时，我们只会继续使用这些函数。

# 还有更多...

有许多内核活动，其中许多确实很复杂，而且经常，内核开发人员必须处理几条消息，而不是所有消息都有趣；因此，我们需要找到一些方法来过滤出有趣的消息。

# 过滤内核消息

假设我们希望知道在引导期间检测到了哪些串行端口。我们知道可以使用`tail`命令，但是通过使用它，我们只能看到最新的消息；另一方面，我们可以使用`cat`命令来回忆自引导以来的所有内核消息，但那是大量的信息！或者，我们可以使用以下步骤来过滤内核消息：

1.  在这里，我们使用`grep`命令来过滤`uart`（或`UART`）字符串中的行：

```
# cat /var/log/kern.log | grep -i uart
Feb 7 19:33:14 espressobin kernel: [ 0.000000] earlycon: ar3700_uart0 at MMIO 0x00000000d0012000 (options '')
Feb 7 19:33:14 espressobin kernel: [ 0.000000] bootconsole [ar3700_uart0] enabled
Feb 7 19:33:14 espressobin kernel: [ 0.000000] Kernel command line: console=ttyMV0,115200 earlycon=ar3700_uart,0xd0012000 loglevel=0 debug root=/dev/mmcblk0p1 rw rootwait net.ifnames=0 biosdevname=0
Feb 7 19:33:14 espressobin kernel: [ 0.289914] Serial: AMBA PL011 UART driver
Feb 7 19:33:14 espressobin kernel: [ 0.296443] mvebu-uart d0012000.serial: could not find pctldev for node /soc/internal-regs@d0000000/pinctrl@13800/uart1-pins, deferring probe
...
```

前面的输出也可以通过使用`dmesg`命令来获得，这是一个专为此目的设计的工具：

```
# dmesg | grep -i uart
[ 0.000000] earlycon: ar3700_uart0 at MMIO 0x00000000d0012000 (options '')
[ 0.000000] bootconsole [ar3700_uart0] enabled
[ 0.000000] Kernel command line: console=ttyMV0,115200 earlycon=ar3700_uart,0
xd0012000 loglevel=0 debug root=/dev/mmcblk0p1 rw rootwait net.ifnames=0 biosdev
name=0
[ 0.289914] Serial: AMBA PL011 UART driver
[ 0.296443] mvebu-uart d0012000.serial: could not find pctldev for node /soc/
internal-regs@d0000000/pinctrl@13800/uart1-pins, deferring probe
...
```

请注意，虽然`cat`显示日志文件中的所有内容，甚至是来自先前操作系统执行的非常旧的消息，但`dmesg`仅显示当前操作系统执行的消息。这是因为`dmesg`直接从当前运行的系统通过其环形缓冲区（即存储所有消息的缓冲区）获取内核消息。

1.  另一方面，如果我们想收集有关早期引导活动的信息，我们仍然可以使用`dmesg`命令和`head`命令，以仅显示`dmesg`输出的前 10 行：

```
# dmesg | head -10 
[ 0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
[ 0.000000] Linux version 4.18.0-dirty (giometti@giometti-VirtualBox) (gcc ve
rsion 7.3.0 (Ubuntu/Linaro 7.3.0-27ubuntu1~18.04)) #5 SMP PREEMPT Sun Jan 27 13:
33:24 CET 2019
[ 0.000000] Machine model: Globalscale Marvell ESPRESSOBin Board
[ 0.000000] earlycon: ar3700_uart0 at MMIO 0x00000000d0012000 (options '')
[ 0.000000] bootconsole [ar3700_uart0] enabled
[ 0.000000] efi: Getting EFI parameters from FDT:
[ 0.000000] efi: UEFI not found.
[ 0.000000] cma: Reserved 32 MiB at 0x000000007e000000
[ 0.000000] NUMA: No NUMA configuration found
[ 0.000000] NUMA: Faking a node at [mem 0x0000000000000000-0x000000007fffffff]
```

1.  另一方面，如果我们对最后 10 行感兴趣，我们可以使用`tail`命令。实际上，我们已经看到，为了监视内核活动，我们可以像下面这样使用它：

```
# tail -f /var/log/kern.log
```

因此，要查看最后 10 行，我们可以执行以下操作：

```
# dmesg | tail -10 
```

1.  同样，也可以使用`dmesg`，通过添加`-w`选项参数，如下例所示：

```
# dmesg -w
```

1.  `dmesg`命令也可以根据它们的级别过滤内核消息，方法是使用`-l`（或`--level`）选项参数，如下所示：

```
# dmesg -l 3 
[ 1.687783] advk-pcie d0070000.pcie: link never came up
[ 3.153849] advk-pcie d0070000.pcie: Posted PIO Response Status: CA, 0xe00 @ 0x0
[ 3.688578] Unable to create integrity sysfs dir: -19
```

前面的命令显示具有`KERN_ERR`级别的内核消息，而以下是显示具有`KERN_WARNING`级别的消息的命令：

```
# dmesg -l 4
[ 3.164121] EINJ: ACPI disabled.
[ 3.197263] cacheinfo: Unable to detect cache hierarchy for CPU 0
[ 4.572660] xenon-sdhci d00d0000.sdhci: Timing issue might occur in DDR mode
[ 5.316949] systemd-sysv-ge: 10 output lines suppressed due to ratelimiting
```

1.  我们还可以组合级别，以同时具有`KERN_ERR`和`KERN_WARNING`：

```
# dmesg -l 3,4
[ 1.687783] advk-pcie d0070000.pcie: link never came up
[ 3.153849] advk-pcie d0070000.pcie: Posted PIO Response Status: CA, 0xe00 @ 0x0
[ 3.164121] EINJ: ACPI disabled.
[ 3.197263] cacheinfo: Unable to detect cache hierarchy for CPU 0
[ 3.688578] Unable to create integrity sysfs dir: -19
[ 4.572660] xenon-sdhci d00d0000.sdhci: Timing issue might occur in DDR mode
[ 5.316949] systemd-sysv-ge: 10 output lines suppressed due to ratelimiting
```

1.  最后，在大量嘈杂的消息的情况下，我们可以要求系统通过使用以下命令来清除内核环形缓冲区（存储所有内核消息的地方）：

```
# dmesg -C
```

现在，如果我们再次使用`dmesg`，我们将只看到新生成的内核消息。

# 另请参阅

+   有关内核消息管理的更多信息，一个很好的起点是`dmesg`手册页，我们可以通过执行`man dmesg`命令来显示它。

# 使用内核模块

了解如何向内核添加自定义代码是有用的，但是，当我们必须编写新的驱动程序时，将我们的代码编写为**内核模块**可能更有用。实际上，通过使用模块，我们可以轻松修改内核代码，然后在不需要每次重新启动系统的情况下进行测试！我们只需删除然后重新插入模块（在必要的修改之后）以测试我们代码的新版本。

在这个示例中，我们将看看即使在内核树之外的目录中，内核模块也可以被编译。

# 准备工作

要将我们的`dummy-code.c`文件转换为内核模块，我们只需更改内核设置，允许编译我们示例模块（在内核配置菜单中用`*`字符替换为`M`）。但是，在某些情况下，将我们的驱动程序发布到与内核源代码完全分开的专用存档中可能更有用。即使在这种情况下，也不需要对现有代码进行任何更改，我们将能够在内核源树内部或者在外部编译`dummy-code.c`！

要构建我们的第一个内核模块作为外部代码，我们可以安全地使用前面的`dummy-code.c`文件，然后将其放入一个专用目录，并使用以下`Makefile`：

```
ifndef KERNEL_DIR
$(error KERNEL_DIR must be set in the command line)
endif
PWD := $(shell pwd)
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

# This specifies the kernel module to be compiled
obj-m += dummy-code.o

# The default action
all: modules

# The main tasks
modules clean:
    make -C $(KERNEL_DIR) \
              ARCH=$(ARCH) \
              CROSS_COMPILE=$(CROSS_COMPILE) \
              SUBDIRS=$(PWD) $@
```

查看前面的代码，我们看到`KERNEL_DIR`变量必须在命令行上提供，指向 ESPRESSObin 之前编译的内核源代码的路径，而`ARCH`和`CROSS_COMPILE`变量不是强制性的，因为`Makefile`指定了它们（但是，在命令行上提供它们将优先）。

此外，我们应该验证`insmod`和`rmmod`命令是否在我们的 ESPRESSObin 中可用，如下所示：

```
# insmod -h
Usage:
        insmod [options] filename [args]
Options:
        -V, --version show version
        -h, --help show this help
```

如果不存在，那么可以通过使用通常的`apt install kmod`命令添加`kmod`软件包来安装它们。

# 如何做...

让我们看看如何通过以下步骤来做到这一点：

1.  在将`dummy-code.c`和`Makefile`文件放置在主机 PC 上的当前工作目录后，当使用`ls`命令时，它应该如下所示：

```
$ ls
dummy-code.c  Makefile
```

1.  然后，我们可以使用以下命令编译我们的模块：

```
$ make KERNEL_DIR=../../../linux/
make -C ../../../linux/ \
 ARCH=arm64 \
 CROSS_COMPILE=aarch64-linux-gnu- \
 SUBDIRS=/home/giometti/Projects/ldddc/github/chapter_2/module modules
make[1]: Entering directory '/home/giometti/Projects/ldddc/linux'
 CC [M] /home/giometti/Projects/ldddc/github/chapter_2/module/dummy-code.o
 Building modules, stage 2.
 MODPOST 1 modules
 CC /home/giometti/Projects/ldddc/github/chapter_2/module/dummy-code.mod.o
 LD [M] /home/giometti/Projects/ldddc/github/chapter_2/module/dummy-code.ko
make[1]: Leaving directory '/home/giometti/Projects/ldddc/linux'
```

如我们所见，现在我们在当前工作目录中有几个文件，其中一个名为`dummy-code.ko`；这是我们的内核模块，准备好传输到 ESPRESSObin！

1.  一旦模块已经移动到目标系统（例如，通过使用`scp`命令），我们可以使用`insmod`实用程序加载它，如下所示：

```
# insmod dummy-code.ko
```

1.  现在，通过使用`lsmod`命令，我们可以要求系统显示所有加载的模块。在我的 ESPRESSObin 上，我只有`dummy-code.ko`模块，所以我的输出如下所示：

```
# lsmod 
Module         Size  Used by
dummy_code    16384  0
```

请注意，由于内核模块名称中的`-`字符被替换为`_`，内核模块名称的`.ko`后缀已被删除。

1.  然后，我们可以使用`rmmod`命令从内核中删除我们的模块，如下所示：

```
# rmmod dummy_code
```

如果出现以下错误，请验证您是否运行了我们在第一章中获得的正确`Image`文件，*安装开发系统*

`rmmod: ERROR: ../libkmod/libkmod.c:514 lookup_builtin_file() could not open builtin file '/lib/modules/4.18.0-dirty/modules.builtin.bin'`

# 它是如何工作的...

`insmod`命令只是将我们的模块插入内核；之后，它执行`module_init()`函数。

在模块插入期间，如果我们在 SSH 连接上，终端上将看不到任何内容，我们必须使用`dmesg`来查看内核消息（或者在串行控制台上，在插入模块后，我们应该看到类似以下内容的内容：

```
dummy_code: loading out-of-tree module taints kernel.
dummy_code:dummy_code_init: dummy-code loaded
```

请注意，消息“加载非树模块会污染内核”只是一个警告，可以安全地忽略我们的目的。有关污染内核的更多信息，请参见[`www.kernel.org/doc/html/v4.15/admin-guide/tainted-kernels.html`](https://www.kernel.org/doc/html/v4.15/admin-guide/tainted-kernels.html)。

`rmmod`命令执行`module_exit()`函数，然后从内核中删除模块，执行`insmod`的逆步骤。

# 另请参阅

+   有关 modutils 的更多信息，它们的手册页是一个很好的起点（命令是：`man insmod`，`man rmmod`和`man modinfo`）；此外，我们可以通过阅读其手册页（`man modprobe`）来了解`modprobe`命令。

# 使用模块参数

在内核模块开发过程中，动态设置一些变量在模块插入时非常有用，而不仅仅是在编译时。在 Linux 中，可以通过使用内核模块的参数来实现，这允许通过在`insmod`命令的命令行上指定参数来传递参数给模块。

# 准备工作

为了举例说明，让我们考虑一个情况，我们有一个新的模块信息文件`module_par.c`（此文件也在我们的 GitHub 存储库中）。

# 如何做...

让我们看看如何通过以下步骤来做到这一点：

1.  首先，让我们定义我们的模块参数，如下所示：

```
static int var = 0x3f;
module_param(var, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(var, "an integer value");

static char *str = "default string";
module_param(str, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(str, "a string value");

#define ARR_SIZE 8
static int arr[ARR_SIZE];
static int arr_count;
module_param_array(arr, int, &arr_count, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(arr, "an array of " __stringify(ARR_SIZE) " values");
```

1.  然后，我们可以使用以下的`init`和`exit`函数：

```
static int __init module_par_init(void)
{
    int i;

    pr_info("loaded\n");
    pr_info("var = 0x%02x\n", var);
    pr_info("str = \"%s\"\n", str);
    pr_info("arr = ");
    for (i = 0; i < ARR_SIZE; i++)
        pr_cont("%d ", arr[i]);
    pr_cont("\n");

    return 0;
}

static void __exit module_par_exit(void)
{
    pr_info("unloaded\n");
}

module_init(module_par_init);
module_exit(module_par_exit);
```

1.  最后，在最后，我们可以像往常一样添加模块描述宏：

```
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rodolfo Giometti");
MODULE_DESCRIPTION("Module with parameters");
MODULE_VERSION("0.1");
```

# 工作原理...

编译完成后，应该会生成一个名为`module_par.ko`的新文件，可以加载到我们的 ESPRESSObin 中。但在这之前，让我们使用`modinfo`实用程序对其进行如下操作：

```
# modinfo module_par.ko 
filename:    /root/module_par.ko
version:     0.1
description: Module with parameters
author:      Rodolfo Giometti
license:     GPL
srcversion:  21315B65C307ABE9769814F
depends: 
name:        module_par
vermagic:    4.18.0 SMP preempt mod_unload aarch64
parm:        var:an integer value (int)
parm:        str:a string value (charp)
parm:        arr:an array of 8 values (array of int)
```

`modinfo`命令也包含在`kmod`软件包中，名为`insmod`。

正如我们在最后三行中所看到的（都以`parm：`字符串为前缀），我们在代码中使用`module_param（）`和`module_param_array（）`宏定义了模块的参数列表，并使用`MODULE_PARM_DESC（）`进行描述。

现在，如果我们像以前一样插入模块，我们会得到默认值，如下面的代码块所示：

```
# insmod module_par.ko 
[ 6021.345064] module_par:module_par_init: loaded
[ 6021.347028] module_par:module_par_init: var = 0x3f
[ 6021.351810] module_par:module_par_init: str = "default string"
[ 6021.357904] module_par:module_par_init: arr = 0 0 0 0 0 0 0 0
```

但是，如果我们使用下一个命令行，我们可以强制使用新值：

```
# insmod module_par.ko var=0x01 str=\"new value\" arr='1,2,3' 
[ 6074.175964] module_par:module_par_init: loaded
[ 6074.177915] module_par:module_par_init: var = 0x01
[ 6074.184932] module_par:module_par_init: str = "new value"
[ 6074.189765] module_par:module_par_init: arr = 1 2 3 0 0 0 0 0 
```

在尝试使用新值重新加载之前，请不要忘记使用`rmmod module_par`命令删除`module_par`模块！

最后，让我建议仔细查看以下模块参数定义：

```
static int var = 0x3f;
module_param(var, int, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(var, "an integer value");
```

首先，我们有代表参数的变量声明，然后是真正的模块参数定义（在这里我们指定类型和文件访问权限），然后是描述。

`modinfo`命令能够显示所有前面的信息，除了文件访问权限，这些权限是指与`sysfs`文件系统中的参数相关的文件！实际上，如果我们看一下`/sys/module/module_par/parameters/`目录，我们会得到以下内容：

```
# ls -l /sys/module/module_par/parameters/
total 0
-rw------- 1 root root 4096 Feb 1 12:46 arr
-rw------- 1 root root 4096 Feb 1 12:46 str
-rw------- 1 root root 4096 Feb 1 12:46 var
```

现在，应该清楚参数`S_IRUSR`和`S_IWUSR`的含义；它们允许模块用户（即 root 用户）写入这些文件，然后从中读取相应的参数。

`S_IRUSR`和相关函数的定义在以下文件中：`linux/include/uapi/linux/stat.h`。

# 另请参阅

+   关于内核模块的一般信息以及如何导出内核符号，您可以查看在线提供的*Linux 内核模块编程指南*，网址为[`www.tldp.org/LDP/lkmpg/2.6/html/index.html`](https://www.tldp.org/LDP/lkmpg/2.6/html/index.html)[.](https://www.tldp.org/LDP/lkmpg/2.6/html/index.html)
