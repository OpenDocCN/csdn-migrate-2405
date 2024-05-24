# Linux 内核编程第二部分（一）

> 原文：[`zh.annas-archive.org/md5/066F8708F0154057BE24B556F153766F`](https://zh.annas-archive.org/md5/066F8708F0154057BE24B556F153766F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书旨在帮助您以实际、实践的方式学习 Linux 字符设备驱动程序开发的基础知识，同时提供必要的理论背景，使您对这个广阔而有趣的主题领域有一个全面的了解。为了充分涵盖这些主题，本书的范围故意保持在（大部分）学习如何在 Linux 操作系统上编写`misc`类字符设备驱动程序。这样，您将能够深入掌握基本和必要的驱动程序编写技能，然后能够相对轻松地处理不同类型的 Linux 驱动程序项目。

重点是通过强大的**可加载内核模块**（**LKM**）框架进行实际驱动程序开发；大多数内核驱动程序开发都是以这种方式进行的。重点是在与驱动程序代码的实际操作中保持关注，必要时在足够深的层面上理解内部工作，并牢记安全性。

我们强烈推荐的一点是：要真正学习和理解细节，**最好先阅读并理解本书的伴侣《Linux 内核编程》**。它涵盖了各个关键领域 - 从源代码构建内核，通过 LKM 框架编写内核模块，内核内部包括内核架构，内存系统，内存分配/释放 API，CPU 调度等等。这两本书的结合将为您提供确定和深入的优势。

这本书没有浪费时间 - 第一章让您学习了 Linux 驱动程序框架的细节以及如何编写一个简单但完整的 misc 类字符设备驱动程序。接下来，您将学习如何做一些非常必要的事情：使用各种技术有效地与用户空间进程进行接口（其中一些还可以作为调试/诊断工具！）。然后介绍了理解和处理硬件（外围芯片）I/O 内存。接下来是详细介绍处理硬件中断。这包括学习和使用几种现代驱动程序技术 - 使用线程中断请求，利用资源管理的 API 进行驱动程序，I/O 资源分配等。它涵盖了顶部/底部是什么，使用任务队列和软中断，以及测量中断延迟。接下来是您通常会使用的内核机制 - 使用内核定时器，设置延迟，创建和管理内核线程和工作队列。

本书的剩余两章涉及一个相对复杂但对于现代专业级驱动程序或内核开发人员至关重要的主题：理解和处理内核同步。

本书使用了最新的，即写作时的 5.4 **长期支持**（**LTS**）Linux 内核。这是一个将从 2019 年 11 月一直维护（包括错误和安全修复）到 2025 年 12 月的内核！这是一个关键点，确保本书的内容在未来几年仍然保持当前和有效！

我们非常相信实践经验的方法：本书的 GitHub 存储库上的 20 多个内核模块（以及一些用户应用程序和 shell 脚本）使学习变得生动，有趣且有用。

我们真诚希望您从这本书中学到并享受到知识。愉快阅读！

# 这本书是为谁准备的

这本书主要是为刚开始学习设备驱动程序开发的 Linux 程序员准备的。Linux 设备驱动程序开发人员希望克服频繁和常见的内核/驱动程序开发问题，以及理解和学习执行常见驱动程序任务 - 现代**Linux 设备模型**（**LDM**）框架，用户-内核接口，执行外围 I/O，处理硬件中断，处理并发等等 - 将受益于本书。需要基本了解 Linux 内核内部（和常见 API），内核模块开发和 C 编程。

# 本书涵盖了什么

第一章，“编写简单的杂项字符设备驱动程序”，首先介绍了非常基础的内容 - 驱动程序应该做什么，设备命名空间，sysfs 和 LDM 的基本原则。然后我们深入讨论了编写简单字符设备驱动程序的细节；在此过程中，您将了解框架 - 实际上是“如果不是一个进程，它就是一个文件”哲学/架构的内部实现！您将学习如何使用各种方法实现杂项类字符设备驱动程序；几个代码示例有助于加深概念。还涵盖了在用户空间和内核空间之间复制数据的基本方法。还涵盖了关键的安全问题以及如何解决这些问题（在这种情况下）；实际上演示了一个“坏”驱动程序引发特权升级问题！

第二章，“用户空间和内核通信路径”，涵盖了如何在内核和用户空间之间进行通信，这对于您作为内核模块/驱动程序的作者来说至关重要。在这里，您将了解各种通信接口或路径。这是编写内核/驱动程序代码的重要方面。采用了几种技术：通过传统的 procfs 进行通信，通过 sysfs 进行驱动程序的更好方式，以及其他几种方式，通过 debugfs，netlink 套接字和 ioctl(2)系统调用。

第三章，“处理硬件 I/O 内存”，涵盖了驱动程序编写的一个关键方面 - 访问外围设备或芯片的硬件内存（映射内存 I/O）的问题和解决方案。我们涵盖了使用常见的内存映射 I/O（MMIO）技术以及（通常在 x86 上）端口 I/O（PIO）技术进行硬件 I/O 内存访问和操作。还展示了来自现有内核驱动程序的几个示例。

第四章，“处理硬件中断”，详细介绍了如何处理和处理硬件中断。我们首先简要介绍内核如何处理硬件中断，然后介绍了您如何“分配”IRQ 线（涵盖现代资源管理的 API），以及如何正确实现中断处理程序。然后涵盖了使用线程处理程序的现代方法（以及原因），不可屏蔽中断（NMI）等。还涵盖了在代码中使用“顶半部分”和“底半部分”中断机制的原因以及使用方式，以及有关硬件中断处理的 dos 和 don'ts 的关键信息。使用现代[e]BPF 工具集和 Ftrace 测量中断延迟，结束了这一关键章节。

第五章，“使用内核定时器、线程和工作队列”，涵盖了如何使用一些有用的（通常由驱动程序使用）内核机制 - 延迟、定时器、内核线程和工作队列。它们在许多实际情况下都很有用。如何执行阻塞和非阻塞延迟（根据情况），设置和使用内核定时器，创建和使用内核线程，理解和使用内核工作队列都在这里涵盖。几个示例模块，包括一个简单的加密解密（sed）示例驱动程序的三个版本，用于说明代码中学到的概念。

第六章，“内核同步-第一部分”，首先介绍了关于关键部分、原子性、锁概念的实现以及非常重要的原因。然后我们涵盖了在 Linux 内核中工作时的并发性问题；这自然地引出了重要的锁定准则，死锁的含义以及预防死锁的关键方法。然后深入讨论了两种最流行的内核锁技术 - 互斥锁和自旋锁，以及几个（驱动程序）代码示例。

第七章，*内核同步-第二部分*，继续探讨内核同步的内容。在这里，您将学习关键的锁定优化-使用轻量级原子和（更近期的）引用计数操作符来安全地操作整数，使用 RMW 位操作符来安全地执行位操作，以及使用读者-写者自旋锁而不是常规自旋锁。还讨论了缓存“错误共享”等固有风险。然后介绍了无锁编程技术的概述（重点是每 CPU 变量及其用法，并附有示例）。接着介绍了关键的主题，锁调试技术，包括内核强大的 lockdep 锁验证器的使用。该章节最后简要介绍了内存屏障（以及现有内核网络驱动程序对内存屏障的使用）。

我们再次强调，本书是为新手内核程序员编写设备驱动程序而设计的；本书不涵盖一些 Linux 驱动程序主题，包括其他类型的设备驱动程序（除了字符设备）、设备树等。Packt 提供了其他有价值的指南，帮助您在这些主题领域取得进展。本书将是一个很好的起点。

# 为了充分利用本书

为了充分利用本书，我们希望您具有以下知识和经验：

+   熟悉 Linux 系统的命令行操作。

+   C 编程语言。

+   了解如何通过**可加载内核模块**（LKM）框架编写简单的内核模块

+   了解（至少基本的）关键的 Linux 内核内部概念：内核架构，内存管理（以及常见的动态内存分配/释放 API），以及 CPU 调度。

+   这不是强制性的，但是具有 Linux 内核编程概念和技术的经验将会有很大帮助。

理想情况下，我们强烈建议先阅读本书的伴侣《Linux 内核编程》。

本书的硬件和软件要求以及其安装细节如下：

| **章节编号** | **所需软件（版本）** | **免费/专有** | **软件下载链接** | **硬件规格** | **所需操作系统** |
| --- | --- | --- | --- | --- | --- |

| 所有章节 | 最新的 Linux 发行版；我们使用 Ubuntu 18.04 LTS（以及 Fedora 31 / Ubuntu 20.04 LTS）；任何一个都可以。建议您将 Linux 操作系统安装为**虚拟机**（VM），使用 Oracle VirtualBox 6.x（或更高版本）作为 hypervisor | 免费（开源） | Ubuntu（桌面版）：[`ubuntu.com/download/desktop`](https://ubuntu.com/download/desktop)Oracle VirtualBox：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads) | *必需：*一台现代化的相对强大的 PC 或笔记本电脑，配备至少 4GB RAM（最少；越多越好），25GB 的可用磁盘空间和良好的互联网连接。*可选：*我们还使用树莓派 3B+作为测试平台。 | Linux 虚拟机在 Windows 主机上 -或-

Linux 作为独立的操作系统 |

详细的安装步骤（软件方面）：

1.  在 Windows 主机系统上安装 Linux 作为虚拟机；按照以下教程之一进行操作：

+   *在 Windows 中使用 VirtualBox 安装 Linux，Abhishek Prakash（It's FOSS！，2019 年 8 月）*：[`itsfoss.com/install-linux-in-virtualbox/`](https://itsfoss.com/install-linux-in-virtualbox/)

+   或者，这里有另一个教程可以帮助您完成相同的操作：*在 Oracle VirtualBox 上安装 Ubuntu*：[`brb.nci.nih.gov/seqtools/installUbuntu.html`](https://brb.nci.nih.gov/seqtools/installUbuntu.html)

1.  在 Linux 虚拟机上安装所需的软件包：

1.  登录到您的 Linux 虚拟机客户端，并首先在终端窗口（shell）中运行以下命令：

```
sudo apt update
sudo apt install gcc make perl
```

1.  1.  现在安装 Oracle VirtualBox Guest Additions。参考：*如何在 Ubuntu 中安装 VirtualBox Guest Additions*：[`www.tecmint.com/install-virtualbox-guest-additions-in-ubuntu/`](https://www.tecmint.com/install-virtualbox-guest-additions-in-ubuntu/)

（此步骤仅适用于使用 Oracle VirtualBox 作为 hypervisor 应用程序的 Ubuntu 虚拟机。）

1.  要安装软件包，请按以下步骤操作：

1.  在 Ubuntu 虚拟机中，首先运行`sudo apt update`命令

1.  现在，在一行中运行`sudo apt install git fakeroot build-essential tar ncurses-dev tar xz-utils libssl-dev bc stress python3-distutils libelf-dev linux-headers-$(uname -r) bison flex libncurses5-dev util-linux net-tools linux-tools-$(uname -r) exuberant-ctags cscope sysfsutils curl perf-tools-unstable gnuplot rt-tests indent tree pstree smem hwloc bpfcc-tools sparse flawfinder cppcheck tuna hexdump trace-cmd virt-what`命令。

1.  有用的资源：

+   Linux 内核官方在线文档：[`www.kernel.org/doc/html/latest/`](https://www.kernel.org/doc/html/latest/)。

+   Linux 驱动程序验证（LDV）项目，特别是*在线 Linux 驱动程序验证服务*页面：[`linuxtesting.org/ldv/online?action=rules`](http://linuxtesting.org/ldv/online?action=rules)。

+   SEALS - 简单嵌入式 ARM Linux 系统：[`github.com/kaiwan/seals/`](https://github.com/kaiwan/seals/)。

+   本书的每一章还有一个非常有用的*进一步阅读*部分，详细介绍更多资源。

1.  本书的伴随指南*Linux 内核编程，Kaiwan N Billimoria，Packt Publishing*的*第一章，内核工作区设置*中描述了详细的说明，以及其他有用的项目，安装 ARM 交叉工具链等。

我们已经在这些平台上测试了本书中的所有代码（它也有自己的 GitHub 存储库）：

+   x86_64 Ubuntu 18.04 LTS 客户操作系统（在 Oracle VirtualBox 6.1 上运行）

+   x86_64 Ubuntu 20.04.1 LTS 客户操作系统（在 Oracle VirtualBox 6.1 上运行）

+   x86_64 Ubuntu 20.04.1 LTS 本机操作系统

+   ARM Raspberry Pi 3B+（运行其发行版内核以及我们的自定义 5.4 内核）；轻度测试。

**如果您使用本书的数字版本，我们建议您自己输入代码，或者更好地，通过 GitHub 存储库访问代码（链接在下一节中可用）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

对于本书，我们将以名为`llkd`的用户登录。我强烈建议您遵循*经验主义方法：不要轻信任何人的话，而是尝试并亲身体验。*因此，本书为您提供了许多实践实验和内核驱动程序代码示例，您可以并且必须自己尝试；这将极大地帮助您取得实质性进展，并深入学习和理解 Linux 驱动程序/内核开发的各个方面。

## 下载示例代码文件

您可以从 GitHub 下载本书的示例代码文件，网址为[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供来自我们丰富的图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

## 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/9781801079518_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781801079518_ColorImages.pdf)。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码字词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“`ioremap()` API 返回`void *`类型的 KVA（因为它是一个地址位置）。”

代码块设置如下：

```
static int __init miscdrv_init(void)
{
    int ret;
    struct device *dev;
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
[...]
#include <linux/miscdevice.h>
#include <linux/fs.h>             
[...]
```

任何命令行输入或输出都以以下方式编写：

```
pi@raspberrypi:~ $ sudo cat /proc/iomem
```

**粗体**：表示一个新术语，一个重要词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从管理面板中选择“系统信息”。”

警告或重要说明看起来像这样。

提示和技巧看起来像这样。

# 取得联系

我们的读者的反馈总是受欢迎的。

**一般反馈**：如果您对本书的任何方面有疑问，请在消息主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在这本书中发现了错误，我们将不胜感激，如果您能向我们报告。请访问[www.packtpub.com/support/errata](https://www.packtpub.com/support/errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，我们将不胜感激，如果您能向我们提供位置地址或网站名称。请通过`copyright@packt.com`与我们联系，并附上材料的链接。

**如果您有兴趣成为作者**：如果有一个您在某个专题上有专业知识，并且您有兴趣写作或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

## 评论

请留下评论。一旦您阅读并使用了这本书，为什么不在购买它的网站上留下评论呢？潜在的读者可以看到并使用您的公正意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们的书的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。


# 第一部分：字符设备驱动程序基础知识

在这里，我们将涵盖设备驱动程序是什么，命名空间，Linux 设备模型（LDM）基础知识，以及字符设备驱动程序框架。我们将实现简单的 misc 驱动程序（利用内核的 misc 框架）。我们将建立用户和内核空间之间的通信（通过各种接口，如 debugfs、sysfs、netlink 套接字和 ioctl）。您将学习如何处理外围芯片上的硬件 I/O 内存，以及理解和处理硬件中断。您还将学习如何使用内核特性，如内核级定时器，创建内核线程，并使用工作队列。

本节包括以下章节：

+   第一章，编写简单的杂项字符设备驱动程序

+   第二章，用户内核通信路径

+   第三章，使用硬件 I/O 内存

+   第四章，处理硬件中断

+   第五章，使用内核定时器、线程和工作队列


# 第一章：编写一个简单的杂项字符设备驱动程序

毫无疑问，设备驱动程序是一个广阔而有趣的话题。不仅如此，它们可能是我们使用的**可加载内核模块**（**LKM**）框架中最常见的用途。在这里，我们将介绍如何编写一些简单但完整的 Linux 字符设备驱动程序，这些驱动程序属于一个名为`misc`的类；是的，这是杂项的缩写。我们希望强调的是，本章的范围和覆盖范围有限 - 在这里，我们不试图深入探讨 Linux 驱动程序模型及其许多框架的细节；相反，我们建议您通过本章的*进一步阅读*部分参考这个主题的几本优秀的书籍和教程。我们的目标是快速让您熟悉编写简单字符设备驱动程序的整体概念。

话虽如此，这本书确实有几章专门介绍驱动程序作者需要了解的内容。除了这个介绍性的章节，我们还详细介绍了驱动程序作者如何处理硬件 I/O 内存、硬件中断处理（以及其许多子主题）以及内核机制，如延迟、定时器、内核线程和工作队列。各种用户-内核通信路径或接口的使用也得到了详细介绍。本书的最后两章则专注于对于任何内核开发，包括驱动程序，都非常重要的内容 - 内核同步。

我们更喜欢编写一个简单的 Linux *字符* *设备驱动程序*，而不仅仅是我们的“常规”内核模块，原因如下：

+   到目前为止，我们的内核模块相当简单，只有`init`和`cleanup`函数，没有其他内容。设备驱动程序为内核提供了*多个*入口点；这些是与文件相关的系统调用，称为*驱动程序的方法*。因此，我们可以有一个`open()`方法，一个`read()`方法，一个`write()`方法，一个`llseek()`方法，一个`[unlocked|compat]_ioctl()`方法，一个`release()`方法等等。

FYI，驱动程序作者可以连接的所有可能的“方法”（函数）都在这个关键的内核数据结构中：`include/linux/fs.h:file_operations`（在*理解进程、驱动程序和内核之间的连接*部分中会更详细地介绍）。

+   这种情况更加现实，也更加有趣。

在本章中，我们将涵盖以下主题：

+   开始编写一个简单的杂项字符设备驱动程序

+   从内核到用户空间的数据复制，反之亦然

+   一个带有秘密的杂项驱动程序

+   问题和安全问题

# 技术要求

我假设您已经阅读了*前言*部分*为了充分利用本书*，并且已经适当地准备了一个运行 Ubuntu 18.04 LTS（或更高版本稳定发布版）的虚拟机，并安装了所有必需的软件包。如果没有，我强烈建议您首先这样做。为了充分利用本书，我强烈建议您首先设置好工作环境，包括克隆本书的 GitHub 代码库，并以实际操作的方式进行工作。代码库可以在这里找到：[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/ch1)。

# 开始编写一个简单的杂项字符设备驱动程序

在本节中，您将首先学习所需的背景材料 - 了解设备文件（或节点）及其层次结构的基础知识。之后，您将通过实际编写一个非常简单的`misc`字符驱动程序的代码来了解原始字符设备驱动程序背后的内核框架。在此过程中，我们将介绍如何创建设备节点并通过用户空间应用程序测试驱动程序。让我们开始吧！

## 了解设备基础知识

需要一些快速的背景知识。

**设备驱动程序**是操作系统和外围硬件设备之间的接口。它可以内联编写 - 也就是说，编译在内核映像文件中 - 或者更常见的是在内核源树之外编写为内核模块（我们在伴随指南*Linux 内核编程*的*第四章*，*编写您的第一个内核模块 - LKMs 第一部分*和*第五章*，*编写您的第一个内核模块 - LKMs 第二部分*中详细介绍了 LKM 框架）。无论哪种方式，驱动程序代码肯定在操作系统特权级别下在内核空间中运行（用户空间设备驱动程序确实存在，但可能存在性能问题；虽然在许多情况下很有用，但我们在这里不涉及它们。请查看*进一步阅读*部分）。

为了让用户空间应用程序能够访问内核中的底层设备驱动程序，需要一些 I/O 机制。Unix（因此也是 Linux）的设计是让进程打开一种特殊类型的文件 - **设备文件**或**设备节点**。这些文件通常位于`/dev`目录中，并且在现代系统中是动态和自动填充的。设备节点作为设备驱动程序的入口点。

为了让内核区分设备文件，它在它们的 inode 数据结构中使用了两个属性：

+   文件类型 - 字符（char）或块

+   主要和次要编号

您会发现**命名空间** - 设备类型和`{major＃，minor＃}`对 - 形成**层次结构**。设备（因此它们的驱动程序）在内核中以树状层次结构组织（内核中的驱动程序核心代码负责此操作）。首先根据设备类型进行层次划分 - 块或字符。在其中，每种类型都有一些*n*个主要编号，每个主要编号通过一些*m*个次要编号进一步分类；*图 1.1*显示了这种层次结构。

现在，块设备和字符设备之间的关键区别在于块设备具有（内核级）能力进行挂载，因此成为用户可访问的文件系统的一部分。字符设备无法挂载；因此，存储设备倾向于基于块。以这种方式考虑（有点简单但有用）：如果（硬件）设备既不是存储设备也不是网络设备，那么它就是字符设备。大量设备属于“字符”类，包括您典型的 I2C/SPI（集成电路/串行外围接口）传感器芯片（温度、压力、湿度等）、触摸屏、**实时时钟**（**RTC**）、媒体（视频、摄像头、音频）、键盘、鼠标等。USB 在内核中形成了一个基础设施支持的类。USB 设备可以是块设备（U 盘、USB 磁盘）、字符设备（鼠标、键盘、摄像头）或网络（USB dongles）设备。

从 Linux 2.6 开始，`{major:minor}`对是 inode 中的一个单个无符号 32 位数量，一个位掩码（它是`dev_t i_rdev`成员）。在这 32 位中，最高 12 位表示主要编号，剩下的最低 20 位表示次要编号。快速计算表明，因此可以有多达 2¹² = 4,096 个主要编号和 2²⁰个次要编号，即一百万个次要编号。因此，快速查看*图 1.1*；在块层次结构中，可能有 4,096 个主要编号，每个主要编号最多可以有 1 百万个次要编号。同样，在字符层次结构中，可能有 4,096 个主要编号，每个主要编号最多可以有 1 百万个次要编号。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/8443be53-6cc9-4d81-9522-26c8b89e34cc.png)

图 1.1 - 设备命名空间或层次结构

你可能会想：这个*主要号:次要号*对到底意味着什么？把主要号想象成代表设备的**类别**（它是 SCSI 磁盘，键盘，**电传打字机**（**tty**）或**伪终端**（**pty**）设备，回环设备（是的，这些是伪硬件设备），操纵杆，磁带设备，帧缓冲器，传感器芯片，触摸屏等等的设备类别）。确实有大量的设备；为了了解有多少，我们建议你查看这里的内核文档：[`www.kernel.org/doc/Documentation/admin-guide/devices.txt`](https://www.kernel.org/doc/Documentation/admin-guide/devices.txt)（这实际上是 Linux 操作系统所有可用设备的官方注册表。它正式称为**LANANA** - **Linux 分配的名称和编号管理机构**！只有这些人才能正式分配设备节点 - 类型和*主要号:次要号*到设备）。

次要号的含义（解释）完全由驱动程序的作者决定；内核不会干涉。通常，驱动程序解释设备的次要号，表示设备的物理或逻辑实例，或表示某种功能。（例如，**小型计算机系统接口**（**SCSI**）驱动程序 - 类型为块，主要号`#8` - 使用次要号表示多达 16 个磁盘的逻辑分区。另一方面，字符主要号`#119`由 VMware 的虚拟网络控制驱动程序使用。在这里，次要号被解释为第一个虚拟网络，第二个虚拟网络，依此类推。）同样，所有驱动程序本身都会为它们的次要号分配含义。但是每个好的规则都有例外。在这里，规则的例外 - 内核不解释次要号 - 是`misc`类（类型为字符，主要号`#10`）。它使用次要号作为第二级主要号。这将在下一节中介绍。

一个常见的问题是命名空间的耗尽。多年前做出的决定将各种各样的杂项字符设备 - 许多鼠标（不是动物王国的那种），传感器，触摸屏等等 - “收集”到一个称为`misc`或'**杂项**'类的类中，分配字符主要号为 10。在`misc`类中有许多设备及其对应的驱动程序。实际上，它们共享相同的主要号，并依赖于唯一的次要号来识别自己。我们将使用这个类编写一些驱动程序，并利用内核的`misc`框架。

许多设备已经通过**LANANA（Linux 分配的名称和编号管理机构）**分配到了`misc`字符设备类中。*图 1.2*显示了来自[`www.kernel.org/doc/Documentation/admin-guide/devices.txt`](https://www.kernel.org/doc/Documentation/admin-guide/devices.txt)的部分截图，显示了前几个`misc`设备，它们分配的次要号和简要描述。请查看参考链接获取完整列表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/a7dd011e-66e6-48a7-be40-7e7a4bd61a5e.png)

图 1.2 - 杂项设备的部分截图：字符类型，主要号 10

在*图 1.2*中，最左边的一列有`10 char`，指定它在设备层次结构（*图 1.1*）下分配了主要的`# 10`。右边的列是以`minor# = /dev/<foo> <description>`的形式；很明显，这是分配的次要号，后面跟着（在`=`号之后）设备节点和一行描述。

## 关于 Linux 设备模型的简短说明

不详细介绍，现代统一的 Linux 设备模型（LDM）的快速概述是重要的。从 2.6 内核开始，现代 Linux 具有一个奇妙的功能，即 LDM，它以一种广泛和大胆的方式实现了许多与系统和其中的设备有关的目标。在其许多功能中，它创建了一个复杂的分层树，统一了系统组件、所有外围设备及其驱动程序。这个树被暴露给用户空间，通过 sysfs 伪文件系统（类似于 procfs 将一些内核和进程/线程内部细节暴露给用户空间），通常挂载在/sys 下。在/sys 下，您会找到几个目录-您可以将它们视为 LDM 的“视口”。在我们的 x86_64 Ubuntu VM 上，我们展示了挂载在/sys 下的 sysfs 文件系统：

```
$ mount | grep -w sysfs
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
```

此外，看一眼里面：

```
$ ls -F /sys/
block/ bus/ class/ dev/ devices/ firmware/ fs/ hypervisor/ kernel/ module/ power/
```

将这些目录视为 LDM 的视口-查看系统上设备的不同方式。当然，随着事物的发展，进入的东西往往比出去的多（膨胀方面！）。一些非明显的目录现在已经进入了这里。尽管（与 procfs 一样）sysfs 被正式记录为应用程序二进制接口（ABI）接口，但这是可能随时更改/弃用的；现实情况是这个系统会一直存在-当然会随着时间的推移而发展。

LDM 可以被简单地认为具有-并将这些主要组件联系在一起-这些主要组件：

+   系统上的总线。

+   它们上的设备。

+   驱动设备的设备驱动程序（通常也称为客户端驱动程序）。

基本的 LDM 原则是***每个设备都必须驻留在总线上***。这可能看起来很明显：USB 设备将在 USB 总线上，PCI 设备将在 PCI 总线上，I2C 设备将在 I2C 总线上，依此类推。因此，在/sys/bus 层次结构下，您将能够通过它们所驻留的总线“看到”所有设备：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/52912a35-54ca-415f-8d53-6e566e2f2054.png)

图 1.3-现代 Linux 上的不同总线或总线驱动程序基础设施（在 x86_64 上）

内核的驱动程序核心提供总线驱动程序（通常是内核映像的一部分或根据需要在引导时自动加载），这当然使总线发挥作用。它们的工作是什么？至关重要的是，它们组织和识别上面的设备。如果出现新设备（也许您插入了一个 U 盘），USB 总线驱动程序将识别这一事实并将其绑定到其（USB 大容量存储）设备驱动程序！一旦成功绑定（有许多术语用于描述这一点：绑定、枚举、发现），内核驱动程序框架将调用驱动程序的注册 probe（）方法（函数）。现在，这个探测方法设置设备，分配资源、IRQ、内存设置，根据需要注册它等等。

关于 LDM 的另一个关键方面是，现代基于 LDM 的驱动程序通常应该执行以下操作：

+   向（专门的）内核框架注册。

+   向总线注册。

它注册自己的内核框架取决于您正在处理的设备类型；例如，驻留在 I2C 总线上的 RTC 芯片的驱动程序将通过 rtc_register_device（）API 将自己注册到内核的 RTC 框架，并通过 i2c_register_driver（）API 将自己注册到 I2C 总线（内部）。另一方面，驻留在 PCI 总线上的网络适配器（NIC）的驱动程序通常会通过 register_netdev（）API 将自己注册到内核的网络基础设施，并通过 pci_register_driver（）API 将自己注册到 PCI 总线。向专门的内核框架注册可以使驱动程序作者的工作变得更加容易-内核通常会提供辅助例程（甚至数据结构）来处理 I/O 细节等。例如，考虑先前提到的 RTC 芯片驱动程序。

你不需要知道如何通过 I2C 总线与芯片进行通信，在 I2C 协议要求的**串行时钟**（**SCL**）/**串行数据**（**SDA**）线上发送数据。内核 I2C 总线框架为您提供了方便的例程（例如通常使用的`i2c_smbus_*()`API），让您可以轻松地与问题芯片进行总线通信！

如果你想知道如何获取有关这些驱动程序 API 的更多信息，好消息是：官方的内核文档有很多内容可供参考。请查阅*Linux 驱动程序实现者 API 指南*：[`www.kernel.org/doc/html/latest/driver-api/index.html`](https://www.kernel.org/doc/html/latest/driver-api/index.html)。

（我们将在接下来的两章中展示驱动程序的`probe()`方法的一些示例；在那之前，请耐心等待。）相反，当设备从总线上分离或内核模块被卸载（或系统关闭时），分离会导致驱动程序的`remove()`（或`disconnect()`）方法被调用。在这两者之间，设备通过其驱动程序（总线和客户端）进行工作！

请注意，我们在这里忽略了很多内部细节，因为它们超出了本书的范围。重点是让你对 LDM 有一个概念性的理解。请参考*进一步阅读*部分的文章和链接，以获取更详细的信息。

在这里，我们希望保持我们的驱动程序覆盖范围非常简单和最小化，更专注于基本原理。因此，我们选择编写一个使用可能是最简单的内核框架 - `misc`或*杂项*内核框架的驱动程序。在这种情况下，驱动程序甚至不需要显式地向任何总线（驱动程序）注册。事实上，更像是这样：我们的驱动程序直接在硬件上工作，而无需任何特定的总线基础设施支持。

在我们特定的示例中，使用`misc`内核框架，由于我们没有显式地向任何总线（驱动程序）注册，因此我们甚至不需要`probe()`/`remove()`方法。这使得事情变得简单。另一方面，一旦你理解了这种最简单的驱动程序，我鼓励你进一步学习，尝试编写具有典型内核框架注册加总线驱动程序注册的设备驱动程序，从而使用`probe()`/`remove()`方法。一个很好的开始是学习如何编写一个简单的**平台驱动程序**，将其注册到内核的`misc`框架和*平台总线*，这是一个伪总线基础设施，支持不在任何物理总线上的设备（这比你最初想象的要常见得多；现代**SoC**（**系统芯片**）内置的几个外围设备不在任何物理总线上，因此它们的驱动程序通常是平台驱动程序）。要开始，请在内核源树中的`drivers/`目录下查找调用`platform_driver_register()` API 的代码。官方的内核文档在这里涵盖了平台设备和驱动程序：[`www.kernel.org/doc/html/latest/driver-api/driver-model/platform.html#platform-devices-and-drivers`](https://www.kernel.org/doc/html/latest/driver-api/driver-model/platform.html#platform-devices-and-drivers)。

作为额外的帮助，请注意以下内容：

- 请参阅第二章，*用户-内核通信路径*，特别是*创建一个简单的平台设备*和*平台设备*部分。

- 本章的一个练习（请参阅*问题*部分）是编写这样的驱动程序。我在这里提供了一个示例（非常简单的实现）：`solutions_to_assgn/ch12/misc_plat/`。

然而，我们确实需要内核的`misc`框架支持，因此我们向其注册。接下来，理解这一点也很关键：我们的驱动程序是逻辑驱动程序，意味着它没有实际的物理设备或芯片在驱动。这通常是情况（当然，您可以说这里正在处理的硬件是 RAM）。

因此，如果我们要编写属于`misc`类的 Linux 字符设备驱动程序，我们首先需要向其注册。接下来，我们将需要一个唯一（未使用的）次编号。同样，有一种方法可以让内核动态地为我们分配一个空闲的次编号。以下部分涵盖了这些方面以及更多内容。

## 编写 misc 驱动程序代码-第一部分

话不多说，让我们来看一下编写一个简单骨架字符`misc`设备驱动程序的代码吧！（当然，这只是部分实际代码；我强烈建议您`git clone`本书的 GitHub 存储库，详细查看并尝试自己编写代码。）

让我们一步一步来看：在我们的第一个设备驱动程序（使用 LKM 框架）的`init`代码中，我们必须首先使用适当的 Linux 内核框架向其注册我们的驱动程序；在这种情况下，使用`misc`框架。这是通过`misc_register()`API 完成的。它接受一个参数，即指向`miscdevice`类型的数据结构的指针，描述了我们正在设置的杂项设备：

```
// ch1/miscdrv/miscdrv.c
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
[...]
#include <linux/miscdevice.h>
#include <linux/fs.h>              /* the fops, file data structures */
[...]

static struct miscdevice llkd_miscdev = {
    .minor = MISC_DYNAMIC_MINOR, /* kernel dynamically assigns a free minor# */
    .name = "llkd_miscdrv",      /* when misc_register() is invoked, the kernel
             * will auto-create a device file as /dev/llkd_miscdrv ;
             * also populated within /sys/class/misc/ and /sys/devices/virtual/misc/ */
    .mode = 0666,            /* ... dev node perms set as specified here */
    .fops = &llkd_misc_fops, /* connect to this driver's 'functionality' */
};

static int __init miscdrv_init(void)
{
    int ret;
    struct device *dev;

    ret = misc_register(&llkd_miscdev);
    if (ret != 0) {
        pr_notice("misc device registration failed, aborting\n");
        return ret;
    }
    [ ... ]
```

在`miscdevice`结构实例中，我们进行了以下操作：

1.  我们将`minor`字段设置为`MISC_DYNAMIC_MINOR`。这会请求内核在成功注册后动态为我们分配一个可用的次编号（一旦注册成功，此`minor`字段将填充为分配的实际次编号）。

1.  我们初始化了`name`字段。在成功注册后，内核框架会自动为我们创建一个设备节点（形式为`/dev/<name>`）！如预期的那样，类型将是字符，主编号将是`10`，次编号将是动态分配的值。这是使用内核框架的优势之一；否则，我们可能需要想办法自己创建设备节点；顺便说一下，`mknod(1)`实用程序可以在具有 root 权限（或具有`CAP_MKNOD`权限）时创建设备文件；它通过调用`mknod(2)`系统调用来工作！

1.  设备节点的权限将设置为您初始化`mode`字段的值（在这里，我们故意保持它是宽松的，并且通过`0666`八进制值对所有人可读可写）。

1.  我们将推迟讨论文件操作（`fops`）结构成员的讨论到接下来的部分。

所有`misc`驱动程序都是字符类型，并使用相同的主编号（`10`），但当然需要唯一的次编号。

### 理解进程、驱动程序和内核之间的连接。

在这里，我们将深入了解 Linux 上字符设备驱动程序成功注册时的内核内部。实际上，您将了解底层原始字符驱动程序框架的工作原理。

`file_operations`结构，或者通常称为**fops**（发音为*eff-opps*），对于驱动程序作者来说至关重要；`fops`结构的大多数成员都是函数指针-将它们视为**虚方法**。它们代表了可能在（设备）文件上发出的所有可能的与文件相关的系统调用。因此，它有`open`、`read`、`write`、`poll`、`mmap`、`release`等多个成员（其中大多数是函数指针）。这个关键数据结构的一些成员在这里显示出来：

```
// include/linux/fs.h struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
[...]
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id); 
    int (*release) (struct inode *, struct file *);
[...]
    int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;
```

驱动程序作者（或底层内核框架）的一个关键工作是填充这些函数指针，从而将它们链接到驱动程序中的实际代码。当然，您不需要实现每个单独的函数；请参考“处理不支持的方法”部分了解详情。

现在，假设您已经编写了驱动程序来为一些`f_op`方法设置函数。一旦您的驱动程序通过内核框架注册到内核中，当任何用户空间进程（或线程）打开注册到该驱动程序的设备文件时，内核**虚拟文件系统开关**（**VFS**）层将接管。不深入细节，可以说 VFS 为设备文件分配并初始化了该进程的打开文件数据结构（`struct file`）。现在，回想一下我们`struct miscdevice`初始化中的最后一行；它是这样的：

```
   .fops = &llkd_misc_fops, /* connect to this driver's 'functionality' */
```

这行代码有一个关键的作用：它将进程的文件操作指针（在进程的打开文件结构中）与设备驱动程序的文件操作结构绑定在一起。*功能性 - 驱动程序将执行的操作 - *现在已经为此设备文件设置好了！

让我们详细说明一下。现在（在驱动程序初始化之后），用户模式进程通过对其发出`open(2)`系统调用来打开驱动程序的设备文件。假设一切顺利（应该如此），进程现在通过内核深处的`file_operations`结构指针连接到您的驱动程序。这里有一个关键点：在`open(2)`系统调用成功返回后，进程在该（设备）文件上发出任何与文件相关的系统调用`foo()`，内核 VFS 层将以面向对象的方式（我们在本书中之前已经指出过！）盲目地并信任地调用已注册的**`fops->foo()`**方法！用户空间进程打开的文件，通常是`/dev`中的设备文件，由`struct file`元数据结构在内部表示（指向此结构的指针`struct file *filp`被传递给驱动程序）。因此，在伪代码方面，当用户空间发出与文件相关的系统调用`foo()`时，内核 VFS 层实际上执行以下操作：

```
/* pseudocode: kernel VFS layer (not the driver) */
if (filp->f_op->foo)
    filp->f_op->foo(); /* invoke the 'registered' driver method corresponding to 'foo()' */
```

因此，如果打开设备文件的用户空间进程在其上调用`read(2)`系统调用，内核 VFS 将调用`filp->f_op->read(...)`，实际上将控制权重定向到设备驱动程序。作为设备驱动程序作者，您的工作是提供`read(2)`的功能！对于所有其他与文件相关的系统调用也是如此。这基本上是 Unix 和 Linux 实现的众所周知的*如果不是进程，就是文件设计*原则。

#### 处理不支持的方法

不必填充`f_ops`结构的每个成员，只需填充驱动程序支持的成员。如果是这种情况，并且您已经填充了一些方法但遗漏了，比如`poll`方法，如果用户空间进程在您的设备上调用`poll(2)`（也许您已经记录了它不应该这样做，但如果它这样做了呢？），那么会发生什么？在这种情况下，内核 VFS 检测到`foo`指针（在本例中为`poll`）为`NULL`，将返回适当的负整数（实际上，遵循相同的`0`/`-E`协议）。`glibc`代码将这个数乘以`-1`，并将调用进程的`errno`变量设置为该值，表示系统调用失败。

要注意的两点：

+   VFS 返回的负`errno`值通常并不直观。（例如，如果您将`f_op`的`read()`函数指针设置为`NULL`，VFS 会导致发送回`EINVAL`值。这使得用户空间进程认为`read(2)`失败是因为`"无效参数"`错误，但实际上根本不是这种情况！）

+   `lseek(2)`系统调用使驱动程序在文件中的指定位置寻址 - 当然，这里指的是设备。内核故意将`f_op`函数指针命名为`llseek`（注意两个`l`）。这只是为了提醒您，`lseek`的返回值可以是 64 位（long long）数量。现在，对于大多数硬件设备，`lseek`值是没有意义的，因此大多数驱动程序不需要实现它（不像文件系统）。现在问题是：即使您不支持`lseek`（您已将`f_op`的`llseek`成员设置为`NULL`），它仍然返回一个随机的正值，从而导致用户模式应用错误地得出它成功了的结论。因此，如果您不实现`lseek`，您需要执行以下操作：

1.  将`llseek`明确设置为特殊的`no_llseek`值，这将导致返回一个失败值（`-ESPIPE`；`非法寻址`）。

1.  在这种情况下，您还需要在驱动程序的`open()`方法中调用`nonseekable_open()`函数，指定文件是不可寻址的（通常在`open()`方法中这样调用：`return nonseekable_open(struct inode *inode, struct file *filp);`）。有关详细信息等，均在 LWN 文章中有所涵盖：[`lwn.net/Articles/97154/`](https://lwn.net/Articles/97154/)。您可以在此处看到这对许多驱动程序造成的更改：[`lwn.net/Articles/97180/`](https://lwn.net/Articles/97180/)。

如果您不支持某个功能，返回的适当值是`-ENOSYS`，这将使用户模式进程看到错误`Function not implemented`（当它调用`perror(3)`或`strerror(3)`库 API 时）。这是清晰的，明确的；用户空间开发人员现在将了解到您的驱动程序不支持此功能。因此，实现驱动程序的一种方法是为所有文件操作方法设置指针，并为驱动程序中的所有文件相关系统调用（`f_op`方法）编写例程。对于您支持的功能，编写代码；对于您未实现的功能，只需返回值`-ENOSYS`。虽然这样做有点费力，但它将导致用户空间的明确返回值。

## 编写 misc 驱动程序代码 - 第二部分

掌握了这些知识后，再次查看`ch1/miscdrv/miscdrv.c`的`init`代码。您将看到，就像在上一节中描述的那样，我们已将`miscdev`结构的`fops`成员初始化为`file_operations`结构，从而设置了驱动程序的功能。驱动程序的相关代码片段如下：

```
static const struct file_operations llkd_misc_fops = {
    .open = open_miscdrv,
    .read = read_miscdrv,
    .write = write_miscdrv,
    .release = close_miscdrv,
};

static struct miscdevice llkd_miscdev = {
    [ ... ]
    .fops = &llkd_misc_fops, /* connect to this driver's 'functionality' */
};
```

因此，现在您可以看到：当打开我们的设备文件的用户空间进程（或线程）调用`read(2)`系统调用时，内核 VFS 层将跟随指针（通用地，`filp->f_op->foo()`）并调用`read_miscdrv()`函数，实际上将控制权交给设备驱动程序！有关读取方法的编写方式将在下一节中介绍。

继续我们简单的`misc`驱动程序的`init`代码：

```
    [ ... ] 
    /* Retrieve the device pointer for this device */
    dev = llkd_miscdev.this_device;
    pr_info("LLKD misc driver (major # 10) registered, minor# = %d,"
            " dev node is /dev/%s\n", llkd_miscdev.minor, llkd_miscdev.name);
    dev_info(dev, "sample dev_info(): minor# = %d\n", llkd_miscdev.minor);
    return 0;        /* success */
}
```

我们的驱动程序检索到`device`结构的指针 - 这是每个驱动程序都需要的东西。在`misc`内核框架中，它在`miscdevice`结构的`this_device`成员中可用。

接下来，`pr_info()`显示动态获取的次要号。`dev_info()`辅助例程更有趣：作为驱动程序作者，**您应该在发出`printk`时使用这些`dev_xxx()`辅助程序**；它还将为设备添加有用的信息前缀。`dev_xxx()`和`pr_xxx()`辅助程序之间的语法唯一的区别是前者的第一个参数是指向设备结构的指针。

好的，让我们开始动手吧！我们构建驱动程序并将其`insmod`到内核空间（我们使用我们的`lkm`辅助脚本来执行）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/eef5c47b-24ea-480d-9ca9-c520c1f96fb0.png)

图 1.4 - 在 x86_64 Ubuntu VM 上构建和加载我们的 miscdrv.ko 骨架 misc 驱动程序的屏幕截图

（顺便说一句，正如你在*图 1.4*中看到的，我在一个更新的发行版 Ubuntu 20.04.1 LTS 上运行了 5.4.0-58-generic 内核的`misc`驱动程序。）请注意*图 1.4*底部的两个打印；第一个是通过`pr_info()`发出的（前缀是`pr_fmt()`宏的内容，如*Linux 内核编程-第四章，编写你的第一个内核模块-LKMs 第一部分*中的*通过 pr_fmt 宏标准化 printk 输出*部分所解释的）。第二个打印是通过`dev_info()`辅助例程发出的-它的前缀是`misc llkd_miscdrv`，表示它来自内核的`misc`框架，具体来说是来自`llkd_miscdrv`设备！（`dev_xxx()`例程是多功能的；根据它们所在的总线，它们将显示各种细节。这对于调试和日志记录很有用。我们再次重申：在编写驱动程序时，建议使用`dev_*()`例程。）你还可以看到`/dev/llkd_miscdrv`设备节点确实被创建了，具有预期的类型（字符）和主次对（这里是 10 和 56）。

## 编写杂项驱动程序代码-第三部分

现在，`init`代码已经完成，驱动程序功能已经通过文件操作结构设置好，并且驱动程序已经注册到内核的`misc`框架中。那么，接下来会发生什么呢？实际上，除非一个进程打开与你的驱动程序相关的设备文件并执行某种输入/输出（I/O，即读/写）操作，否则什么也不会发生。

因此，让我们假设一个用户模式进程（或线程）在你的驱动程序的设备节点上发出`open(2)`系统调用（回想一下，当驱动程序向内核的`misc`框架注册时，设备节点已经被自动创建）。最重要的是，正如你在*理解进程、驱动程序和内核之间的连接*部分学到的那样，对于在你的设备节点上发出的任何与文件相关的系统调用，VFS 基本上会调用驱动程序的（`f_op`）注册方法。因此，在这里，VFS 将执行这样的操作：`filp->f-op->open()`，从而在我们的`file_operations`结构中调用我们的驱动程序的`open`方法，即`open_miscdrv()`函数！

但是，作为驱动程序作者，你应该如何实现你的驱动程序的`open`方法的代码呢？关键点在于：你的`open`函数的签名**应该与**`file_operation`结构的`open`完全相同；实际上，对于任何函数都是如此。因此，我们实现`open_miscdrv()`函数如下：

```
/*
 * open_miscdrv()
 * The driver's open 'method'; this 'hook' will get invoked by the kernel VFS
 * when the device file is opened. Here, we simply print out some relevant info.
 * The POSIX standard requires open() to return the file descriptor on success;
 * note, though, that this is done within the kernel VFS (when we return). So,
 * all we do here is return 0 indicating success.
 * (The nonseekable_open(), in conjunction with the fop's llseek pointer set to
 * no_llseek, tells the kernel that our device is not seek-able).
 */
static int open_miscdrv(struct inode *inode, struct file *filp)
{
    char *buf = kzalloc(PATH_MAX, GFP_KERNEL);

    if (unlikely(!buf))
        return -ENOMEM;
    PRINT_CTX(); // displays process (or atomic) context info
    pr_info(" opening \"%s\" now; wrt open file: f_flags = 0x%x\n",
        file_path(filp, buf, PATH_MAX), filp->f_flags);
    kfree(buf);
    return nonseekable_open(inode, filp);
}
```

请注意我们的`open`例程`open_miscdrv()`函数的签名如何与`f_op`结构的`open`函数指针完全匹配（你可以随时在[`elixir.bootlin.com/linux/v5.4/source/include/linux/fs.h#L1814`](https://elixir.bootlin.com/linux/v5.4/source/include/linux/fs.h#L1814)查找 5.4 Linux 的`file_operations`结构）。

在这个简单的驱动程序中，在我们的`open`方法中，我们实际上没有太多事情要做。我们通过`kzalloc()`为缓冲区（用于保存设备路径名）分配一些内存，使用我们的`PRINT_CTX()`宏（在`convenient.h`头文件中）显示当前上下文-当前正在打开设备的进程。然后我们通过`pr_info()`发出一个`printk`显示一些 VFS 层的细节（路径名和打开标志值）；你可以使用方便的 API `file_path()`来获取文件的路径名，就像我们在这里做的一样（为此，我们需要分配并在使用后释放内核内存缓冲区）。然后，由于这个驱动程序不支持寻址，我们调用`nonseekable_open()` API（如*处理不支持的方法*部分所讨论的）。

对设备文件的`open(2)`系统调用应该成功。用户模式进程现在将拥有一个有效的文件描述符 - 打开文件的句柄（这里实际上是一个设备节点）。现在，假设用户模式进程想要从硬件中读取数据；因此，它发出`read(2)`系统调用。如前所述，内核 VFS 现在将自动调用我们的驱动程序的读取方法`read_miscdrv()`。再次强调，它的签名完全模仿了`file_operations`数据结构中的读取函数签名。这是我们驱动程序读取方法的简单代码：

```
/*
 * read_miscdrv()
 * The driver's read 'method'; it has effectively 'taken over' the read syscall
 * functionality! Here, we simply print out some info.
 * The POSIX standard requires that the read() and write() system calls return
 * the number of bytes read or written on success, 0 on EOF (for read) and -1 (-ve errno)
 * on failure; we simply return 'count', pretending that we 'always succeed'.
 */
static ssize_t read_miscdrv(struct file *filp, char __user *ubuf, size_t count, loff_t *off)
{
        pr_info("to read %zd bytes\n", count);
        return count;
}
```

前面的评论是不言自明的。在其中，我们发出`pr_info()`，显示用户空间进程想要读取的字节数。然后，我们简单地返回读取的字节数，意味着成功！实际上，我们（基本上）什么都没做。其余的驱动程序方法非常相似。

## 测试我们简单的 misc 驱动程序

让我们测试我们真正简单的骨架`misc`字符驱动程序（在`ch1/miscdrv`目录中；我们假设您已经按照*图 1.4*中所示构建并插入了它）。我们通过对其发出`open(2)`、`read(2)`、`write(2)`和`close(2)`系统调用来测试它；我们应该如何做呢？我们总是可以编写一个小的 C 程序来精确地做到这一点，但更简单的方法是使用有用的`dd(1)`“磁盘复制”实用程序。我们像这样使用它：

```
dd if=/dev/llkd_miscdrv of=readtest bs=4k count=1
```

内部`dd`通过`if=`（这里是`dd`的第一个参数；`if=`指定输入文件）打开我们传递给它的文件（`/dev/llkd_miscdrv`），它将从中读取（通过`read(2)`系统调用，当然）。输出将被写入由参数`of=`指定的文件（`dd`的第二个参数，是一个名为`readtest`的常规文件）；`bs`指定要执行 I/O 的块大小，`count`是要执行 I/O 的次数）。完成所需的 I/O 后，`dd`进程将`close(2)`这些文件。这个顺序反映在内核日志中（*图 1.5*）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/9c0a7520-4795-4889-b8c2-6117c7f1b00f.png)

图 1.5 - 屏幕截图显示我们通过 dd(1)最小化测试了 miscdrv 驱动程序的读取方法

在验证我们的驱动程序（LKM）已插入后，我们发出`dd(1)`命令，让它从我们的设备中读取 4,096 字节（因为块大小（`bs`）设置为`4k`，`count`设置为`1`）。我们让它通过`of=`选项开关将输出写入一个名为`readtest`的文件。查看内核日志，您可以看到（*图 1.5*）`dd`进程确实已经打开了我们的设备（我们的`PRINT_CTX()`宏的输出显示，它是当前运行我们驱动程序代码的进程上下文！）。接下来，我们可以看到（通过`pr_fmt()`的输出）控制转到我们驱动程序的读取方法，在其中我们发出一个简单的`printk`并返回值 4096，表示成功（尽管我们实际上并没有读取任何东西！）。然后，设备被`dd`关闭。此外，使用`hexdump(1)`实用程序进行快速检查，我们确实从驱动程序（在文件`readtest`中；请意识到这是因为`dd`将其读取缓冲区初始化为`NULL`）接收到了`0x1000`（4,096）个空值（如预期的那样）。

我们在代码中使用的`PRINT_CTX()`宏位于我们的`convenient.h`头文件中。请看一下；它非常有教育意义（我们尝试模拟内核`Ftrace`基础设施的`latency output`格式，它在一个小空间内显示了很多细节，一行输出）。这在第四章中的*处理硬件中断*部分中有详细说明。现在不要担心所有的细节...

*图 1.6*显示了我们（最小化地）通过`dd(1)`测试写入我们的驱动程序。这次我们通过利用内核内置的`mem`驱动程序的`/dev/urandom`功能，读取了`4k`的随机数据，并将随机数据写入我们的设备节点；实际上，写入我们的“设备”：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/3bf0f7e7-4cc3-49a7-a935-1bc099c22e46.png)

图 1.6 - 屏幕截图显示我们通过 dd(1)最小化测试我们的 miscdrv 驱动程序的写入方法

（顺便说一句，我还包括了一个简单的用户空间测试应用程序用于驱动程序；可以在这里找到：`ch1/miscdrv/rdwr_test.c`。我会留给你阅读它的代码并尝试。）

你可能会想：我们显然成功地从用户空间向驱动程序读取和写入数据，但是，等等，我们实际上从未在驱动程序代码中看到任何数据传输发生。是的，这是下一节的主题：您将如何实际将数据从用户空间进程缓冲区复制到内核驱动程序的缓冲区，反之亦然。继续阅读！

# 将数据从内核空间复制到用户空间，反之亦然

设备驱动程序的一个主要工作是使用户空间应用程序能够透明地读取和写入外围硬件设备的数据（通常是某种芯片；虽然它可能根本不是硬件），将设备视为普通文件。因此，要从设备读取数据，应用程序打开与该设备对应的设备文件，从而获得文件描述符，然后简单地使用该`fd`发出`read(2)`系统调用（*图 1.7*中的*步骤 1*）！内核 VFS 拦截读取，并且，正如我们所见，控制流到底层设备驱动程序的读取方法（当然是一个 C 函数）。驱动程序代码现在与硬件设备"通信"，实际执行 I/O，读取操作。（确切地说，硬件读取（或写入）的具体方式取决于硬件的类型——它是内存映射设备、端口、网络芯片等等？我们将在这里不再深入讨论；下一章会讲到。）驱动程序从设备读取数据后，现在将这些数据放入内核缓冲区`kbuf`（以下图中的*步骤 2*。当然，我们假设驱动程序作者通过`[k|v]malloc()`或其他适当的内核 API 为其分配了内存）。

现在我们在内核空间缓冲区中有硬件设备数据。我们应该如何将其传输到用户空间进程的内存缓冲区？我们将利用使这变得容易的内核 API，下面将介绍这一点。

## 利用内核 API 执行数据传输

现在，如前所述，让我们假设您的驱动程序已经读取了硬件数据，并且现在它存在于内核内存缓冲区中。我们如何将它传输到用户空间？一个天真的方法是简单地尝试通过`memcpy()`来执行这个操作，但*不，*那不起作用（为什么？一，它是不安全的，二，它非常依赖架构；它在一些架构上工作，在其他架构上不工作）。因此，一个关键点：内核提供了一对内联函数来在内核空间和用户空间之间传输数据。它们分别是`copy_to_user()`和`copy_from_user()`，并且确实非常常用。

使用它们很简单。两者都接受三个参数：`to`指针（目标缓冲区），`from`指针（源缓冲区）和`n`，要复制的字节数（将其视为`memcpy`操作）：

```
include <linux/uaccess.h>   /* Note! used to be <asm/uaccess.h> upto 4.11 */

unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
```

返回值是未复制的字节数；换句话说，返回值为`0`表示成功，非零返回值表示未复制给定数量的字节。如果发生非零返回，您应该（遵循通常的`0/-E`返回约定）返回一个错误，指示 I/O 故障，返回`-EIO`或`-EFAULT`（这样在用户空间设置`errno`的正数对应值）。以下（伪）代码说明了设备驱动程序如何使用`copy_to_user()`函数将一些数据从内核复制到用户空间：

```
static ssize_t read_method(struct file *filp, char __user *ubuf, size_t count, loff_t *off)
{
     char *kbuf = kzalloc(...);
     [ ... ]
     /* ... do what's required to get data from the hardware device into kbuf ... */
    if (copy_to_user(buf, kbuf, count)) {
        dev_warn(dev, "copy_to_user() failed\n");
        goto out_rd_fail;
    }
    [ ... ]
    return count;    /* success */
out_rd_fail:
    kfree(kbuf);
 return -EIO; /* or -EFAULT */
}
```

在这里，当然，我们假设您有一个有效的分配的内核内存缓冲区`kbuf`，以及一个有效的设备指针（`struct device *dev`）。*图 1.7*说明了前面（伪）代码试图实现的内容：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/2ddabab1-d742-40ea-992e-89083c8e7fdd.png)

图 1.7-读取：copy_to_user()：将数据从硬件复制到内核缓冲区，然后复制到用户空间缓冲区

使用`copy_from_user()`内联函数的语义也适用。它通常用于驱动程序的写入方法，将用户空间进程上下文中写入的数据拉入内核空间缓冲区。我们将让您自行想象这一点。

同样重要的是要意识到，这两个例程（`copy_[from|to]_user()`）在运行过程中可能会导致进程上下文（页面）故障，从而休眠；换句话说，调用调度程序。因此，**它们只能在安全休眠的进程上下文中使用，绝不能在任何类型的原子或中断上下文中使用**（我们在第四章中对`might_sleep()`助手进行了更多解释-一个调试辅助工具-在*不要阻塞-发现可能阻塞的代码路径*部分）。

对于好奇的读者（希望您是其中之一！），这里有一些链接，详细解释了**为什么**您不能只使用简单的`memcpy()`，而必须使用`copy_[from|to]_user()`内联函数来复制数据从内核到用户空间和反之：

+   [ht](https://stackoverflow.com/questions/14970698/copy-to-user-vs-memcpy)[tps://stackoverflow.com/questions/14970698/copy-to-user-vs-memcpy](https://stackoverflow.com/questions/14970698/copy-to-user-vs-memcpy) [](https://stackoverflow.com/questions/14970698/copy-to-user-vs-memcpy)

+   [https:](https://www.quora.com/Why-we-need-copy_from_user-as-the-kernel-can-access-all-the-memory-If-we-see-the-copy_from_user-implementation-again-we-are-copying-data-to-the-kernel-memory-using-memcpy-Doesnt-it-an-extra-overhead)[//www.quora.com/Why-we-need-copy_from_user-as-the-kernel-can-access-all-the-memory-If-we-see-the-copy_from_user-implementation-again-we-are-copying-data-to-the-kernel-memory-using-memcpy-Doesnt-it-an-extra-overhead](https://www.quora.com/Why-we-need-copy_from_user-as-the-kernel-can-access-all-the-memory-If-we-see-the-copy_from_user-implementation-again-we-are-copying-data-to-the-kernel-memory-using-memcpy-Doesnt-it-an-extra-overhead)。

在接下来的部分，我们将编写一个更完整的`misc`框架字符设备驱动程序，实际上执行一些 I/O，读取和写入数据。

# 一个带有秘密的杂项驱动程序

现在您了解了如何在用户空间和内核空间之间复制数据（以及反向），让我们基于我们之前的骨架（`ch1/miscdrv/`）杂项驱动程序编写另一个设备驱动程序（`ch1/miscdrv_rdwr`）。关键区别在于我们在整个过程中使用了一些全局数据项（在一个结构内），并实际进行了一些 I/O 读取和写入。在这里，让我们介绍**驱动程序上下文或私有驱动程序数据结构**的概念；这个想法是有一个方便访问的数据结构，其中包含所有相关信息。在这里，我们将这个结构命名为`struct drv_ctx`（在接下来的代码清单中可以看到）。在驱动程序初始化时，我们分配内存并对其进行初始化。

好吧，这里没有真正的秘密，只是让它听起来有趣。我们驱动程序上下文数据结构中的一个成员是所谓的秘密消息（它是`drv_ctx.oursecret`成员，以及一些（虚假）统计和配置词）。这是我们建议使用的简单“驱动程序上下文”或私有数据结构：

```
// ch1/miscdrv_rdwr/miscdrv_rdwr.c
[ ... ]
/* The driver 'context' (or private) data structure;
 * all relevant 'state info' reg the driver is here. */
struct drv_ctx {
    struct device *dev;
    int tx, rx, err, myword;
    u32 config1, config2;
    u64 config3;
#define MAXBYTES 128 /* Must match the userspace app; we should actually
                      * use a common header file for things like this */
    char oursecret[MAXBYTES];
};
static struct drv_ctx *ctx;
```

好的，现在让我们继续看代码并理解它。

## 编写“秘密”杂项设备驱动程序的代码

我们将讨论我们的秘密杂项字符设备驱动程序的实现细节分为五个部分：驱动程序初始化，读取方法，写入方法功能实现，驱动程序清理，最后是将使用我们的设备驱动程序的用户空间应用程序。

### 我们的秘密驱动程序-初始化代码

在我们的秘密设备驱动程序的`init`代码中（当然是一个内核模块，因此在`insmod(8)`上调用），我们首先将驱动程序注册为一个`misc`字符驱动程序与内核（通过`misc_register()` API，如前面的*编写 misc 驱动程序代码-第一部分*部分所示；我们不会在这里重复这段代码）。

接下来，我们通过有用的托管分配`devm_kzalloc()` API（正如您在配套指南*Linux 内核编程*，第八章，*模块作者的内核内存分配-第一部分*，在*使用内核的资源管理内存分配 API*部分中学到的）为我们的驱动程序的“上下文”结构分配内核内存，并对其进行初始化。请注意，您必须确保您首先获取设备指针`dev`，然后才能使用此 API；我们从我们的`miscdevice`结构的`this_device`成员中检索它（如下所示）：

```
// ch1/miscdrv_rdwr/​miscdrv_rdwr.c
[ ... ]
static int __init miscdrv_rdwr_init(void)
{
    int ret;
    struct device *dev;

    ret = misc_register(&llkd_miscdev);
    [ ... ]
    dev = llkd_miscdev.this_device;
    [ ... ]
    ctx = devm_kzalloc(dev, sizeof(struct drv_ctx), GFP_KERNEL);
    if (unlikely(!ctx))
        return -ENOMEM;

    ctx->dev = dev;
    strscpy(ctx->oursecret, "initmsg", 8);
    [ ... ]
    return 0;         /* success */
}
```

好吧，显然，我们已经初始化了`ctx`私有结构实例的`dev`成员以及`'secret'`字符串为`'initmsg'`字符串（并不是一个非常令人信服的秘密，但就让它保持这样吧）。这里的想法是，当用户空间进程（或线程）打开我们的设备文件并对其进行`read(2)`时，我们通过调用`copy_to_user()`助手函数将秘密传回（复制）给它！同样，当用户模式应用程序向我们写入数据（是的，通过`write(2)`系统调用），我们认为写入的数据是新的秘密。因此，我们从其用户空间缓冲区中获取它-通过`copy_from_user()`助手函数-并在驱动程序内存中更新它。

为什么不简单地使用`strcpy()`（或`strncpy()`）API 来初始化`ctx->oursecret`成员？这非常重要：从安全性的角度来看，它们不够安全。此外，内核社区已经将`strlcpy()` API 标记为**已弃用**（[`www.kernel.org/doc/html/latest/process/deprecated.html#strlcpy`](https://www.kernel.org/doc/html/latest/process/deprecated.html#strlcpy)）。总的来说，尽量避免使用已弃用的东西，如内核文档中所述：[`www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions`](https://www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions)。

很明显，这个新驱动程序的有趣部分是 I/O 功能- *读* 和 *写* 方法；继续进行吧！

### 我们的秘密驱动程序-读取方法

我们首先展示读取方法的相关代码-这是用户空间进程（或线程）如何读取我们驱动程序中的秘密信息（在其上下文结构中）的方法：

```
static ssize_t
read_miscdrv_rdwr(struct file *filp, char __user *ubuf, size_t count, loff_t *off)
{
    int ret = count, secret_len = strlen(ctx->oursecret);
    struct device *dev = ctx->dev;
    char tasknm[TASK_COMM_LEN];

    PRINT_CTX();
    dev_info(dev, "%s wants to read (upto) %zd bytes\n", get_task_comm(tasknm, current), count);

    ret = -EINVAL;
    if (count < MAXBYTES) {
    [...] *<< we don't display some validity checks here >>*

    /* In a 'real' driver, we would now actually read the content of the
     * [...]
     * Returns 0 on success, i.e., non-zero return implies an I/O fault).
     * Here, we simply copy the content of our context structure's 
 * 'secret' member to userspace. */
    ret = -EFAULT;
    if (copy_to_user(ubuf, ctx->oursecret, secret_len)) {
        dev_warn(dev, "copy_to_user() failed\n");
        goto out_notok;
    }
    ret = secret_len;

    // Update stats
    ctx->tx += secret_len; // our 'transmit' is wrt this driver
    dev_info(dev, " %d bytes read, returning... (stats: tx=%d, rx=%d)\n",
            secret_len, ctx->tx, ctx->rx);
out_notok:
    return ret;
}
```

`copy_to_user()`例程完成了它的工作-它将`ctx->oursecret`源缓冲区复制到目标指针`ubuf`用户空间缓冲区，用于`secret_len`字节，从而将秘密传输到用户空间应用程序。现在，让我们来看看驱动程序的写入方法。

### 我们的秘密驱动程序-写入方法

最终用户可以通过向驱动程序写入新的秘密来更改秘密，通过`write(2)`系统调用到驱动程序的设备节点。内核通过 VFS 层将写入重定向到我们的驱动程序的写入方法（正如您在*理解进程、驱动程序和内核之间的连接*部分中学到的）：

```
static ssize_t
write_miscdrv_rdwr(struct file *filp, const char __user *ubuf, size_t count, loff_t *off)
{
    int ret = count;
    void *kbuf = NULL;
    struct device *dev = ctx->dev;
    char tasknm[TASK_COMM_LEN];

    PRINT_CTX();
    if (unlikely(count > MAXBYTES)) { /* paranoia */
        dev_warn(dev, "count %zu exceeds max # of bytes allowed, "
                "aborting write\n", count);
        goto out_nomem;
    }
    dev_info(dev, "%s wants to write %zd bytes\n", get_task_comm(tasknm, current), count);

    ret = -ENOMEM;
    kbuf = kvmalloc(count, GFP_KERNEL);
    if (unlikely(!kbuf))
        goto out_nomem;
    memset(kbuf, 0, count);

    /* Copy in the user supplied buffer 'ubuf' - the data content
     * to write ... */
    ret = -EFAULT;
    if (copy_from_user(kbuf, ubuf, count)) {
        dev_warn(dev, "copy_from_user() failed\n");
        goto out_cfu;
     }

    /* In a 'real' driver, we would now actually write (for 'count' bytes)
     * the content of the 'ubuf' buffer to the device hardware (or 
     * whatever), and then return.
     * Here, we do nothing, we just pretend we've done everything :-)
     */
    strscpy(ctx->oursecret, kbuf, (count > MAXBYTES ? MAXBYTES : count));
    [...]
    // Update stats
    ctx->rx += count; // our 'receive' is wrt this driver

    ret = count;
    dev_info(dev, " %zd bytes written, returning... (stats: tx=%d, rx=%d)\n",
            count, ctx->tx, ctx->rx);
out_cfu:
    kvfree(kbuf);
out_nomem:
    return ret;
}
```

我们使用`kvmalloc()` API 来分配内存，以容纳我们将要复制的用户数据的缓冲区。当然，实际的复制是通过`copy_from_user()`例程完成的。在这里，我们使用它将用户空间应用程序传递的数据复制到我们的内核缓冲区`kbuf`中。然后，我们通过`strscpy()`例程更新我们的驱动程序上下文结构的`oursecret`成员到这个值，从而更新秘密！（随后对驱动程序的读取现在将显示新的秘密。）另外，请注意以下内容：

+   我们如何一贯地使用`dev_xxx()`助手代替通常的`printk`例程。这是设备驱动程序的推荐做法。

+   （现在典型的）使用`goto`进行最佳错误处理。

这涵盖了驱动程序的核心内容。

### 我们的秘密驱动程序 – 清理

重要的是要意识到我们必须释放我们分配的任何缓冲区。然而，在这里，由于我们在`init`代码中执行了托管分配（`devm_kzalloc()`），我们无需担心清理工作；内核会处理它。当然，在驱动程序的清理代码路径（在`rmmod(8)`上调用时），我们会从内核中注销`misc`驱动程序：

```
static void __exit miscdrv_rdwr_exit(void)
{
    misc_deregister(&llkd_miscdev);
    pr_info("LLKD misc (rdwr) driver deregistered, bye\n");
}
```

你会注意到，我们在这个版本的驱动程序中还似乎无用地使用了两个全局整数`ga`和`gb`。确实，在这里它们没有真正的意义；我们之所以有它们，只有在本书的最后两章关于内核同步的内容中才会变得清楚。现在请忽略它们。

在这一点上，你可能会意识到我们在这个驱动程序中任意访问全局数据的方式**可能会引起并发问题（*数据竞争！*）**；确实；我们将把内核并发和同步的深入重要的内容留到本书的最后两章。

### 我们的秘密驱动程序 – 用户空间测试应用程序

仅仅编写内核组件，即设备驱动程序，是不够的；你还必须编写一个用户空间应用程序来实际使用驱动程序。我们将在这里这样做。（同样，你也可以使用`dd(1)`。）

为了使用设备驱动程序，用户空间应用程序首先必须打开与之对应的设备文件。（在这里，为了节省空间，我们不完整显示应用程序代码，只显示其中最相关的部分。我们期望你已经克隆了本书的 Git 存储库并且在代码上进行了工作。）打开设备文件的代码如下：

```
// ch1/miscdrv_rdwr/rdwr_test_secret.c
int main(int argc, char **argv)
{
    char opt = 'r';
    int fd, flags = O_RDONLY;
    ssize_t n;
    char *buf = NULL;
    size_t num = 0;
[...]
    if ('w' == opt)
        flags = O_WRONLY;
    fd = open(argv[2], flags, 0); if (fd== -1) {
    [...]
```

这个应用程序的第二个参数是要打开的设备文件。为了读取或写入，进程将需要内存：

```
    if ('w' == opt)
        num = strlen(argv[3])+1;    // IMP! +1 to include the NULL byte!
    else
        num = MAXBYTES;
    buf = malloc(num);
    if (!buf) {
        [...]
```

接下来，让我们看看代码块，让应用程序调用（伪）设备上的读取或写入（取决于第一个参数是`r`还是`w`）（为简洁起见，我们不显示错误处理代码）：

```
    if ('r' == opt) {
        n = read(fd, buf, num);
        if( n < 0 ) [...]
        printf("%s: read %zd bytes from %s\n", argv[0], n, argv[2]);
        printf("The 'secret' is:\n \"%.*s\"\n", (int)n, buf);
    } else {
        strncpy(buf, argv[3], num);
        n = write(fd, buf, num);
        if( n < 0 ) [ ... ]
        printf("%s: wrote %zd bytes to %s\n", argv[0], n, argv[2]);
    }
    [...]
    free(buf);
    close(fd);
    exit(EXIT_SUCCESS); 
} 
```

（在尝试这个驱动程序之前，请确保先卸载之前的`miscdrv`驱动程序的内核模块。）现在，确保这个驱动程序已经构建并插入，否则将导致`open(2)`系统调用失败。我们展示了一些试运行。首先，让我们构建用户模式应用程序，插入驱动程序（*图 1.8*中未显示），并从刚创建的设备节点中读取：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/b40b7ebe-f9d3-4ec2-b1c0-199633935f2c.png)

图 1.8 – miscdrv_rdwr：（最小程度地）测试读取；原始秘密被揭示

用户模式应用程序成功从驱动程序接收了 7 个字节；这是（初始）秘密值，它显示出来。内核日志反映了驱动程序的初始化，几秒钟后，你可以看到（通过我们发出的`printk`的`dev_xxx()`实例）`rdwr_test_secret`应用程序在进程上下文中运行了驱动程序的代码。设备的打开，随后的读取和关闭方法都清晰可见。（注意进程名称被截断为`rdwr_test_secre`；这是因为任务结构的`comm`成员是被截断为 16 个字符的进程名称。）

在*图 1.9*中，我们展示了写入我们的设备节点的互补操作，改变了秘密值；随后的读取确实显示它已经生效：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/821a37e0-9a8b-4b33-93b0-eb4f40dc8639.png)

图 1.9 – miscdrv_rdwr：（最小程度地）测试写入；一个新的，优秀的秘密被写入

写入发生的内核日志部分在*图 1.9*中被突出显示。它有效；我绝对鼓励你自己尝试一下，一边查看内核日志。

现在，是时候深入一点了。事实是，作为驱动程序作者，你必须学会在*安全*方面非常小心，否则各种令人讨厌的惊喜都会等着你。下一节将让你了解这一关键领域。

# 问题和安全问题

对于新手驱动程序作者来说，一个重要的考虑是安全性。问题是，即使是在驱动程序中使用非常常见的`copy_[from|to]_user()`函数也可能让恶意用户很容易 - 且非法地 - 覆盖用户空间和内核空间的内存。如何？以下部分将详细解释这一点；然后，我们甚至会向您展示一个（有点牵强，但仍然有效）的黑客。

## 黑客秘密驱动程序

思考一下：我们有`copy_to_user()`辅助例程；第一个参数是目标`to`地址，应该是用户空间虚拟地址（UVA），当然。常规用法将遵守这一点，并提供一个合法和有效的用户空间虚拟地址作为目标地址，一切都会很好。

但如果我们不这样做呢？如果我们传递另一个用户空间地址，或者，检查一下 - 一个*内核*虚拟地址（KVA） - 替代它呢？`copy_to_user()`代码现在将以内核特权运行，用源地址（第二个参数）中的任何数据覆盖目标，覆盖字节数为第三个参数！实际上，黑客经常尝试这样的技术，将代码插入用户空间缓冲区并以内核特权执行，导致相当致命的**特权升级**（privesc）场景。

为了清楚地展示不仔细设计和实现驱动程序的不利影响，我们故意在先前驱动程序的读写方法中引入错误（实际上是错误！）的“坏”版本（尽管在这里，我们只考虑与非常常见的`copy_[from|to]_user()`例程有关的情况，而不考虑其他情况）。

为了更加亲身地感受这一点，我们将编写我们的`ch1/miscdrv_rdwr`驱动程序的“坏”版本。我们将称之为（非常聪明地）`ch1/bad_miscdrv`。在这个版本中，我们故意内置了两个有错误的代码路径：

+   驱动程序的读取方法中的一个

+   另一个更令人兴奋的，很快您将看到，在写方法中。

让我们检查两者。我们将从有错误的读取开始。

### 坏驱动程序 - 有错误的读取()

为了帮助您看到代码中发生了什么变化，我们首先对这个（故意）坏驱动程序代码与我们先前（好的）版本进行`diff(1)`，得到了差异，当然（在以下片段中，我们将输出限制为最相关的内容）。

```
// in ch1/bad_miscdrv
$ diff -u ../miscdrv_rdwr/miscdrv_rdwr.c bad_miscdrv.c
[ ... ]
+#include <linux/cred.h>            ​// access to struct cred
#include "../../convenient.h"
[ ... ]
static ssize_t read_miscdrv_rdwr(struct file *filp, char __user *ubuf,
[ ... ]
+ void *kbuf = NULL;
+ void *new_dest = NULL;
[ ... ]
+#define READ_BUG
+//#undef READ_BUG
+#ifdef READ_BUG
[ ... ]
+ new_dest = ubuf+(512*1024);
+#else
+ new_dest = ubuf;
+#endif
[ ... ]
+ if (copy_to_user(new_dest, ctx->oursecret, secret_len)) {
[ ... ]
```

因此，很明显：在我们“坏”驱动程序的读取方法中，如果定义了`READ_BUG`宏，我们将修改用户空间目标指针，使其指向一个非法位置（比我们实际应该复制数据的位置多 512 KB！）。这里的要点在于：我们可以做任意这样的事情，因为我们是以内核特权运行的*。*它会导致问题和错误是另一回事。

让我们试试：首先确保您已构建并加载了`bad_miscdrv`内核模块（您可以使用我们的`lkm`便利脚本来执行）。我们的试运行，通过我们的`ch1/bad_miscdrv/rdwr_test_hackit`用户模式应用程序发出`read(2)`系统调用，结果失败（请参见以下屏幕截图）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/7beb9fad-e2d5-495f-8d72-951812ac41e1.png)

图 1.10 - 屏幕截图显示我们的 bad_miscdrv 杂项驱动程序执行“坏”读取

啊，这很有趣；我们的测试应用程序（`rdwr_test_hackit`）的`read(2)`系统调用确实失败，`perror(3)`例程指示失败原因为`Bad address`。但是为什么？为什么驱动程序，以内核特权运行，实际上没有写入目标地址（这里是`0x5597245d46b0`，错误的地址；正如我们所知，它试图写入正确目标地址的 512 KB *之后*。我们故意编写了驱动程序的读取方法代码来这样做）。

这是因为内核确保`copy_[from|to]_user()`例程在尝试读取或写入非法地址时（理想情况下）会失败！在内部，进行了几项检查：`access_ok()`是一个简单的检查，只是确保 I/O 在预期段（用户或内核）中执行。现代 Linux 内核具有更好的检查；除了简单的`access_ok()`检查之外，内核还会通过（如果启用）**KASAN**（**内核地址消毒剂**，一种编译器插装特性；KASAN 确实非常有用，在开发和测试过程中是*必须的*！），检查对象大小（包括溢出检查），然后才调用执行实际复制的工作例程，`raw_copy_[from|to]_user()`。

好的，现在让我们继续讨论更有趣的情况，即有 bug 的写入，我们将（虽然以一种虚构的方式）安排成一次攻击！继续阅读...

### 坏驱动程序 - 有 bug 的写入 - 特权提升！

恶意黑客真正想要什么，他们的圣杯？当然是系统上的 root shell（得到 root 权限？）。通过在我们的驱动程序的写入方法中使用大量虚构的代码（因此这个黑客并不是一个真正好的黑客；它相当学术），让我们去获取它！为了做到这一点，我们修改用户模式应用程序以及设备驱动程序。让我们先看看用户模式应用程序的变化。

#### 用户空间测试应用程序修改

我们稍微修改了用户空间应用程序 - 实际上是我们的进程上下文。这个用户模式测试应用程序的特定版本在一个方面与之前的版本不同：我们现在有一个名为`HACKIT`的宏。如果定义了它（默认情况下是定义的），这个进程将故意只向用户空间缓冲区写入零，并将其发送到我们的坏驱动程序的写入方法。如果驱动程序定义了`DANGER_GETROOT_BUG`宏（默认情况下是定义的），那么它将把零写入进程的 UID 成员，从而使用户模式进程获得 root 权限！

在传统的 Unix/Linux 范式中，如果**真实用户 ID**（**RUID**）和/或**有效用户 ID**（**EUID**）（它们在`struct cred`中的任务结构中）被设置为特殊值零（`0`），这意味着该进程具有超级用户（root）权限。如今，POSIX 权限模型被认为是一种更优越的处理权限的方式，因为它允许在线程上分配细粒度的权限 - *capabilities*，而不是像 root 一样给予进程或线程对系统的完全控制。

这是用户空间测试应用程序与之前版本的快速`diff`，让您看到对代码所做的更改（再次，我们将输出限制在最相关的部分）：

```
// in ch1/bad_miscdrv
$ diff -u ../miscdrv/rdwr_test.c rdwr_test_hackit.c
[ ... ]
+#define HACKIT
[ ... ]
+#ifndef HACKIT
+     strncpy(buf, argv[3], num);
+#else
+     printf("%s: attempting to get root ...\n", argv[0]);
+     /*
+      * Write only 0's ... our 'bad' driver will write this into
+      * this process's current->cred->uid member, thus making us
+      * root !
+      */
+     memset(buf, 0, num);
 #endif
- } else { // test writing ..
          n = write(fd, buf, num);
[ ... ]
+     printf("%s: wrote %zd bytes to %s\n", argv[0], n, argv[2]);
+#ifdef HACKIT
+     if (getuid() == 0) {
+         printf(" !Pwned! uid==%d\n", getuid());
+         /* the hacker's holy grail: spawn a root shell */
+         execl("/bin/sh", "sh", (char *)NULL);
+     }
+#endif
[ ... ]
```

这意味着（所谓的）秘密从未被写入；没关系。现在，让我们看看对驱动程序所做的修改。

#### 设备驱动程序修改

为了查看我们的坏`misc`驱动程序的写入方法如何改变，我们将继续查看相同的`diff`（我们的坏驱动程序与好驱动程序的对比），就像我们在*坏驱动程序 - 有 bug 的读取*部分所做的那样。以下代码中的注释是相当不言自明的。看一下：

```
// in ch1/bad_miscdrv
$ diff -u ../miscdrv_rdwr/miscdrv_rdwr.c bad_miscdrv.c
[...]           
         // << this is within the driver's write method >>
 static ssize_t write_miscdrv_rdwr(struct file *filp, const char __user *ubuf,
 size_t count, loff_t *off)
 {
        int ret = count;
        struct device *dev = ctx->dev;
+       void *new_dest = NULL;
[ ... ]
+#define DANGER_GETROOT_BUG
+//#undef DANGER_GETROOT_BUG
+#ifdef DANGER_GETROOT_BUG
+     /* Make the destination of the copy_from_user() point to the current
+      * process context's (real) UID; this way, we redirect the driver to
+      * write zero's here. Why? Simple: traditionally, a UID == 0 is what
+      * defines root capability!
+      */
+      new_dest = &current->cred->uid; +      count = 4; /* change count as we're only updating a 32-bit quantity */
+      pr_info(" [current->cred=%px]\n", (TYPECST)current->cred);
+#else
+      new_dest = kbuf;
+#endif
```

从前面的代码中的关键点是，当定义了`DANGER_GETROOT_BUG`宏（默认情况下是定义的）时，我们将`new_dest`指针设置为凭证结构中（实际的）UID 成员的地址，这个结构本身位于任务结构中（由`current`引用）的进程上下文中！（如果所有这些听起来都很陌生，请阅读配套指南*Linux 内核编程*，第六章*内核内部要点-进程和线程*）。这样，当我们调用`copy_to_user()`例程执行写入用户空间时，它实际上将零写入`current->cred`中的进程 UID 成员。零的 UID 是（传统上）定义为 root。另外，请注意我们将写入限制为 4 个字节（因为我们只写入 32 位数量）。

（顺便说一句，我们的“坏”驱动程序构建确实发出了警告；在这里，由于是故意的，我们只是忽略了它）：

```
Linux-Kernel-Programming-Part-2/ch1/bad_miscdrv/bad_miscdrv.c:229:11: warning: assignment discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
 229 | new_dest = &current->cred->uid;
 |          ^
```

这里是`copy_from_user()`代码调用：

```
[...]
+       dev_info(dev, "dest addr = " ADDRFMT "\n", (TYPECST)new_dest);
        ret = -EFAULT;
-       if (copy_from_user(kbuf, ubuf, count)) {
+       if (copy_from_user(new_dest, ubuf, count)) {
                dev_warn(dev, "copy_from_user() failed\n");
                goto out_cfu;
        }
[...]
```

显然，前面的`copy_to_user()`例程将把用户提供的缓冲区`ubuf`写入到`new_dest`目标缓冲区中 - 关键是，我们已经指向了`current->cred->uid` - 用于`count`字节。

#### 现在让我们获取 root 权限

当然，实践出真知，对吧？所以，让我们试一下我们的黑客技巧；在这里，我们假设您已经卸载了之前版本的“misc”驱动程序，并构建并加载了`bad_miscdrv`内核模块到内存中：

在下一章中，您将学习作为驱动程序作者的一个关键任务 - 如何有效地将设备驱动程序与用户空间进程进行接口；详细介绍了几种有用的方法，并进行了对比。

图 1.11 - 屏幕截图显示我们的 bad_miscdrv misc 驱动程序执行了一个“坏”写操作，导致了 root 权限提升！

看看吧；**我们确实获得了 root 权限！**我们的`rdwr_test_hackit`应用程序检测到我们确实拥有 root 权限（通过一个简单的`getuid(2)`系统调用），然后做了合乎逻辑的事情：它执行了一个 root shell（通过一个`execl(3)`API），然后，我们进入了一个 root shell。我们展示了内核日志：

```
$ dmesg 
[ 63.847549] bad_miscdrv:bad_miscdrv_init(): LLKD 'bad' misc driver (major # 10) registered, minor# = 56
[ 63.848452] misc bad_miscdrv: A sample print via the dev_dbg(): (bad) driver initialized
[ 84.186882] bad_miscdrv:open_miscdrv_rdwr(): 000) rdwr_test_hacki :2765 | ...0 /* open_miscdrv_rdwr() */
[ 84.190521] misc bad_miscdrv: opening "bad_miscdrv" now; wrt open file: f_flags = 0x8001
[ 84.191557] bad_miscdrv:write_miscdrv_rdwr(): 000) rdwr_test_hacki :2765 | ...0 /* write_miscdrv_rdwr() */
[ 84.192358] misc bad_miscdrv: rdwr_test_hacki wants to write 4 bytes to (original) ubuf = 0x55648b8f36b0
[ 84.192971] misc bad_miscdrv: [current->cred=ffff9f67765c3b40]
[ 84.193392] misc bad_miscdrv: dest addr = ffff9f67765c3b44 count=4
[ 84.193803] misc bad_miscdrv: 4 bytes written, returning... (stats: tx=0, rx=4)
[ 89.002675] bad_miscdrv:close_miscdrv_rdwr(): 000) [sh]:2765 | ...0 /* close_miscdrv_rdwr() */
[ 89.005992] misc bad_miscdrv: filename: "bad_miscdrv"
$ 
```

您可以看到它是如何工作的：原始用户模式缓冲区`ubuf`的内核虚拟地址为`0x55648b8f36b0`。在黑客中，我们将其修改为新的目标地址（内核虚拟地址）`0xffff9f67765c3b44`，这是（在本例中）`struct cred`的 UID 成员的内核虚拟地址（在进程的任务结构中）。不仅如此，我们的驱动程序还将要写入的字节数（`count`）修改为`4`（字节），因为我们正在更新一个 32 位的数量。

请注意：这些黑客只是黑客。它们肯定会导致您的系统变得不稳定（在我们的“调试”内核上运行时，KASAN 实际上检测到了空指针解引用！）。

这些演示证明了一个事实，即作为内核和/或驱动程序作者，您必须时刻警惕编程问题、安全性等。有了这个，我们完成了本节，实际上也完成了本章。

# 总结

这结束了本章关于在 Linux 操作系统上编写简单的`misc`类字符设备驱动程序的内容；所以，太棒了，您现在知道了在 Linux 上编写设备驱动程序的基础知识！

本章以设备基础知识的介绍开始，重要的是，现代 LDM 的简要要点。然后，您学习了如何编写一个简单的字符设备驱动程序，并在内核的`misc`框架中注册。在此过程中，您还了解了进程、驱动程序和内核 VFS 之间的连接。在用户和内核地址空间之间复制数据是必不可少的；我们看到了如何做到这一点。一个更全面的`misc`驱动程序演示（我们的“秘密”驱动程序）向您展示了如何执行 I/O - 读取和写入 - 在用户和内核空间之间传输数据。本章的关键部分是最后一节，您在其中学习了（至少开始了）有关安全性和驱动程序的知识；一个“黑客”甚至演示了*privesc*攻击！

如前所述，编写 Linux 驱动程序这一广泛主题还有很多内容；事实上，整整一本书都是关于这个的！请查看本章的*进一步阅读*部分，找到相关的书籍和在线参考资料。

确保您对本章的内容清楚，完成所给的练习，查阅*进一步阅读*资源，然后深入下一章。

# 问题

1.  加载第一个`miscdrv`骨架`misc`驱动程序内核模块，并对其进行`lseek(2)`操作；会发生什么？（是否成功？`lseek`的返回值是什么？）如果没有，好的，您将如何解决这个问题？

1.  编写一个`misc`类字符驱动程序，它的行为类似于一个简单的转换程序（假设其路径名为`/dev/convert`）。例如，将华氏温度写入，它应该返回（写入内核日志）摄氏温度。因此，执行`echo 98.6 > /dev/convert`应该导致内核日志中写入值`37 C`。另外，做以下操作：

1.  验证传递给驱动程序的数据是否为数值。

1.  如何处理浮点值？（提示：参考*Linux 内核编程*，*第五章*，*编写您的第一个内核模块 LKM-第二部分*中的*内核中不允许浮点*一节。）

1.  编写一个“任务显示”驱动程序；在这里，我们希望用户空间进程将线程（或进程）PID 写入其中。当您从驱动程序的设备节点中读取（假设其路径名为`/dev/task_display`）时，您应该收到有关任务的详细信息（当然是从其任务结构中提取的）。例如，执行`echo 1 > /dev/task_display`，然后执行`cat /dev/task_display`应该使驱动程序将 PID 1 的任务详细信息发出到内核日志中。不要忘记添加有效性检查（检查 PID 是否有效等）。

1.  （稍微高级一点：）编写一个“正确的”基于 LDM 的驱动程序；这里介绍的`misc`驱动程序已经在内核的`misc`框架中注册，但是简单地、隐式地使用原始字符接口作为总线。LDM 更喜欢驱动程序必须在内核框架和总线驱动程序中注册。因此，编写一个“演示”驱动程序，它将自己注册到内核的`misc`框架和平台总线。这将涉及创建一个虚拟的平台设备。

（*请注意以下提示*：

a) 请参阅第二章，*用户-内核通信路径*，特别是*创建一个简单的平台设备*和*平台设备*部分。

b) 可以在这里找到对该驱动程序的可能解决方案：`solutions_to_assgn/ch12/misc_plat/`。

您会发现一些问题的答案在书的 GitHub 存储库中：[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn)。

# 进一步阅读

+   Linux 设备驱动程序书籍：

+   *Linux 设备驱动程序开发*，John Madieu，Packt，2017 年 10 月：[`www.amazon.in/Linux-Device-Drivers-Development-Madieu/dp/1785280007/ref=sr_1_2?keywords=linux+device+driver&qid=1555486515&s=books&sr=1-2`](https://www.amazon.in/Linux-Device-Drivers-Development-Madieu/dp/1785280007/ref=sr_1_2?keywords=linux+device+driver&qid=1555486515&s=books&sr=1-2)；覆盖面广，而且非常新（截至本文撰写时；它涵盖了 4.13 内核）

+   *嵌入式处理器的 Linux 驱动程序开发-第二版：学习使用 4.9 LTS 内核开发嵌入式 Linux 驱动程序*，Alberto Liberal de los Rios：[`www.amazon.in/Linux-Driver-Development-Embedded-Processors-ebook/dp/B07L512BHG/ref=sr_1_6?crid=3RLFFZQXGAMF4&keywords=linux+driver+development+embedded&qid=1555486342&s=books&sprefix=linux+driver+%2Cstripbooks%2C270&sr=1-6-catcorr`](https://www.amazon.in/Linux-Driver-Development-Embedded-Processors-ebook/dp/B07L512BHG/ref=sr_1_6?crid=3RLFFZQXGAMF4&keywords=linux+driver+development+embedded&qid=1555486342&s=books&sprefix=linux+driver+%2Cstripbooks%2C270&sr=1-6-catcorr)；非常好，而且很新（4.9 内核）

+   *Essential Linux Device Drivers*，Sreekrishnan Venkateswaran，Pearson：[`www.amazon.in/Essential-Drivers-Prentice-Software-Development/dp/0132396556/ref=tmm_hrd_swatch_0?_encoding=UTF8&qid=&sr=`](https://www.amazon.in/Essential-Drivers-Prentice-Software-Development/dp/0132396556/ref=tmm_hrd_swatch_0?_encoding=UTF8&qid=&sr=)；非常好，覆盖面广

+   《Linux 设备驱动程序》，Rubini，Hartmann，Corbet，第 3 版：[`www.amazon.in/Linux-Device-Drivers-Kernel-Hardware/dp/8173668493/ref=sr_1_1?keywords=linux+device+driver&qid=1555486515&s=books&sr=1-1`](https://www.amazon.in/Linux-Device-Drivers-Kernel-Hardware/dp/8173668493/ref=sr_1_1?keywords=linux+device+driver&qid=1555486515&s=books&sr=1-1)；古老但著名的 LDD3 书籍

+   官方内核文档：

+   Linux 内核设备模型：[`www.kernel.org/doc/html/latest/driver-api/driver-model/overview.html#the-linux-kernel-device-model`](https://www.kernel.org/doc/html/latest/driver-api/driver-model/overview.html#the-linux-kernel-device-model)。

+   内核驱动程序 API 手册；这是最近 Linux 内核源代码中执行`make pdfdocs`时生成的 PDF 文档之一。

+   已弃用的接口、语言特性、属性和约定：[`www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions`](https://www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions)。

+   实用教程：

+   《设备驱动程序，第八部分：访问 x86 特定的 I/O 映射硬件》，Anil K Pugalia，OpenSourceForU，2011 年 7 月：[`opensourceforu.com/2011/07/accessing-x86-specific-io-mapped-hardware-in-linux/`](https://opensourceforu.com/2011/07/accessing-x86-specific-io-mapped-hardware-in-linux/)

+   用户空间设备驱动程序；观看 Chris Simmonds 的这个有趣的视频演示：*如何避免为嵌入式 Linux 编写设备驱动程序*：[`www.youtube.com/watch?v=QIO2pJqMxjE&t=909s`](https://www.youtube.com/watch?v=QIO2pJqMxjE&t=909s)


# 第二章：用户-内核通信路径

考虑这种情况：你已经成功地为一个压力传感器设备开发了一个设备驱动程序（可能是通过使用内核的 I2C API 来通过 I2C 协议从芯片获取压力）。因此，你在驱动程序中有了当前的压力值，这当然意味着它在内核内存空间中。问题是，你现在如何让一个用户空间应用程序检索这个值呢？嗯，正如我们在上一章中学到的，你可以在驱动程序的 fops 结构中始终包含一个.read 方法。当用户空间应用程序发出 read(2)系统调用时，控制将通过虚拟文件系统（VFS）转移到你的驱动程序的 read 方法。在那里，你执行 copy_to_user()（或等效操作），使用户模式应用程序接收到该值。然而，还有其他一些更好的方法来做到这一点。

在本章中，你将了解可用的各种通信接口或路径，作为在用户和内核地址空间之间进行通信或接口的手段。这是编写驱动程序代码的一个重要方面，因为如果没有这些知识，你将如何能够实现一个关键的事情——在内核空间组件（通常是设备驱动程序，但实际上可以是任何东西）和用户空间进程或线程之间高效地传输信息？不仅如此，我们将学习的一些技术通常也用于调试（和/或诊断）目的。在本章中，我们将涵盖几种技术来实现内核和用户（虚拟）地址空间之间的通信：通过传统的 proc 文件系统 procfs 进行通信，通过 sys 文件系统 sysfs 进行驱动程序的更好方式，通过调试文件系统 debugfs 进行通信，通过 netlink 套接字进行通信，以及通过 ioctl(2)系统调用进行通信。

本章将涵盖以下主题：

+   与用户空间 C 应用程序通信/接口的内核驱动程序的方法

+   通过 proc 文件系统（procfs）进行接口

+   通过 sys 文件系统 sysfs 进行接口

+   通过调试文件系统 debugfs 进行接口

+   通过 netlink 套接字进行接口

+   通过 ioctl 系统调用进行接口

+   比较接口方法-表格

让我们开始吧！

# 技术要求

我假设你已经阅读了前言，相关部分是“充分利用本书”，并已经适当地准备了一个运行 Ubuntu 18.04 LTS（或更高稳定版本）的虚拟机，并安装了所有必需的软件包。如果没有，我建议你首先这样做。

为了充分利用本书，我强烈建议你首先设置工作环境，包括克隆本书的 GitHub 存储库（[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/ch2)）以获取相关代码，并以实际操作的方式进行工作。

# 与用户空间 C 应用程序通信/接口的内核驱动程序的方法

正如我们在介绍中提到的，在本章中，我们希望学习如何在内核空间组件（通常是设备驱动程序，但实际上可以是任何东西）和用户空间进程或线程之间高效地传输信息。首先，让我们简单列举内核或驱动程序作者可用的各种技术，用于与用户空间 C 应用程序进行通信或接口。嗯，用户空间组件可以是 C 应用程序，shell 脚本（这两者我们通常在本书中展示），甚至其他应用程序，如 C++/Java 应用程序，Python/Perl 脚本等。

正如我们在伴随指南*Linux 内核编程*的*第四章*，*编写您的第一个内核模块 - LKMs 第一部分*中的*库和系统调用 API*子章节中所看到的，用户空间应用程序和内核之间的基本接口包括设备驱动程序的系统调用 API*。现在，在上一章中，您学习了为 Linux 编写字符设备驱动程序的基础知识。在其中，您还学习了如何通过让用户模式应用程序打开设备文件并发出`read(2)`和`write(2)`系统调用来在用户和内核地址空间之间传输数据。这导致 VFS 调用驱动程序的读/写方法，并且您的驱动程序通过`copy_{from|to}_user()`API 执行数据传输。因此，这里的问题是：如果我们已经涵盖了这一点，那么在这方面还有什么其他要学习的呢？

啊，还有很多！事实上，还有其他几种用户模式应用程序和内核之间的接口技术。当然，它们都非常依赖于使用系统调用；毕竟，没有其他（同步的、程序化的）方式从用户空间进入内核！然而，这些技术是不同的。本章的目的是向您展示各种可用的通信接口，因为当然，根据项目的不同，可能有一种更适合使用。让我们来看看本章将用于用户和内核地址空间之间的接口的各种技术：

+   通过传统的 procfs 接口

+   通过 sysfs

+   通过 debugfs

+   通过 netlink 套接字进行接口

+   通过`ioctl(2)`系统调用

在本章中，我们将通过提供驱动程序代码示例详细讨论这些接口技术。此外，我们还将简要探讨它们对*调试*目的的适用性。因此，让我们从使用 procfs 接口开始。

# 通过 proc 文件系统（procfs）进行接口

在本节中，我们将介绍 proc 文件系统是什么，以及您如何将其作为用户和内核地址空间之间的接口。proc 文件系统是一个强大且易于编程的接口，通常用于状态报告和调试核心内核系统。

请注意，从 Linux 2.6 版本开始，对于上游贡献，这个接口*不*应该被驱动程序作者使用（它严格意味着仅用于内核内部使用）。尽管如此，为了完整起见，我们将在这里介绍它。

## 了解 proc 文件系统

Linux 有一个名为*proc*的虚拟文件系统；它的默认挂载点是`/proc`。关于 proc 文件系统的第一件事是要意识到，它的内容*不*在非易失性磁盘上。它的内容在 RAM 中，因此是易失性的。您在`/proc`下看到的文件和目录都是内核代码为 proc 设置的伪文件；内核通过（几乎）总是显示文件的*大小*为零来暗示这一事实：

```
$ mount | grep -w proc
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
$ ls -l /proc/
total 0
dr-xr-xr-x  8 root  root          0 Jan 27 11:13 1/
dr-xr-xr-x  8 root  root          0 Jan 29 08:22 10/
dr-xr-xr-x  8 root  root          0 Jan 29 08:22 11/
dr-xr-xr-x  8 root  root          0 Jan 29 08:22 11550/
[...]
-r--r--r--  1 root  root          0 Jan 29 08:22 consoles
-r--r--r--  1 root  root          0 Jan 29 08:19 cpuinfo
-r--r--r--  1 root  root          0 Jan 29 08:22 crypto
-r--r--r--  1 root  root          0 Jan 29 08:20 devices
-r--r--r--  1 root  root          0 Jan 29 08:22 diskstats
[...]
-r--r--r--  1 root  root          0 Jan 29 08:22 vmstat
-r--r--r--  1 root  root          0 Jan 29 08:22 zoneinfo
$ 
```

让我们总结一下关于 Linux 强大的 proc 文件系统的一些关键点。

/proc 下的对象（文件、目录、软链接等）都是伪对象；它们存在于 RAM 中！

### /proc 下的目录

/proc 下的目录的名称是整数值，代表当前在系统上运行的进程。目录的名称是进程的 PID（从技术上讲，它是进程的 TGID。我们在伴随指南*Linux 内核编程*的*第六章*，*内核和内存管理内部要点*中介绍了 TGID/PID）。

这个文件夹 - `/proc/PID/` - 包含有关此进程的信息。因此，例如，对于*init*或*systemd*进程（始终是 PID `1`），您可以在`/proc/1/`文件夹下查看有关此进程的详细信息（其属性、打开文件、内存布局、子进程等）。

例如，在这里，我们将获得 root shell 并执行`ls /proc/1`：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/b602d4a8-8d7b-4aca-ad53-c4f04ef4240d.png)

图 2.1 - 在 x86_64 客户系统上执行 ls /proc/1 的屏幕截图

关于`/proc/<PID>/...`下的伪文件和文件夹的完整详细信息可以在`proc(5)`的手册页中找到（通过`man 5 proc`来查看）；试一试并参考它！

请注意，`/proc`下的精确内容因内核版本和（CPU）架构而异；x86_64 架构往往具有最丰富的内容。

### proc 文件系统的目的

proc 文件系统的*目的*是双重的：

+   首先，它是一个简单的接口，供开发人员、系统管理员和任何人深入了解内核，以便他们可以获取有关进程、内核甚至硬件内部的信息。只需要使用这个接口，你就可以知道基本的 shell 命令，比如`cd`、`cat`、`echo`、`ls`等等。

+   其次，作为*root*用户，有时候是所有者，你可以写入`/proc/sys`下的某些伪文件，从而调整各种内核参数。这个功能被称为**sysctl***。例如，你可以在`/proc/sys/net/ipv4/`中调整各种 IPv4 网络参数。它们都在这里有文档：[`www.kernel.org/doc/Documentation/networking/ip-sysctl.txt`](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)。

更改基于 proc 的可调参数的值很容易；例如，让我们更改在任何给定时间点上允许的最大线程数。以*root*身份运行以下命令：

```
# cat /proc/sys/kernel/threads-max
15741
# echo 10000 > /proc/sys/kernel/threads-max
# cat /proc/sys/kernel/threads-max
10000
#
```

至此，我们完成了。然而，应该清楚的是，前面的操作是*易失性*的——更改只适用于本次会话；重新启动或重启将导致它恢复到默认值。那么，我们如何使更改*永久*生效呢？简短的答案是：使用`sysctl(8)`实用程序；参考其手册页以获取更多详细信息。

现在准备好编写一些 procfs 接口代码了吗？不要那么着急——下一节会告诉你为什么这可能*并不*是一个好主意。

### procfs 对驱动程序作者是禁用的

尽管我们可以使用 proc 文件系统与用户模式应用程序进行接口，但这里有一个重要的要点要注意！你必须意识到 procfs 是内核中许多类似设施的**应用程序二进制接口**（**ABI**）。内核社区并不保证它会保持稳定，就像内核*API*和它们的内部数据结构一样。事实上，自 2.6 内核以来，内核人员已经非常清楚地表明了这一点——*设备驱动程序作者（等等）不应该使用 procfs*来进行他们自己的目的或接口，调试或其他用途。在早期的 2.6 Linux 中，使用 proc 来进行上述目的是相当常见的（根据内核社区的说法，proc 是专为内核内部使用而滥用的！）。

因此，如果 procfs 被认为对于我们作为驱动程序作者来说是禁用的或不推荐使用的，那么我们用什么设施来与用户空间进程通信呢？驱动程序作者应该使用 sysfs 设施来*导出*他们的接口。实际上，不仅仅是 sysfs；你还有几种选择，比如 sysfs、debugfs、netlink 套接字和 ioctl 系统调用。我们将在本章后面详细介绍这些内容。

然而，现实情况是，关于驱动程序作者不使用 procfs 的这个“规则”是针对社区的。这意味着，如果你打算将你的驱动程序或内核模块上游到主线内核，从而在 GPLv2 许可下贡献你的代码，*那么*所有社区规则肯定适用。如果不是，那么你可以自行决定。当然，遵循内核社区的指南和规则只会是一件好事；我们强烈建议你这样做。在阻止非核心内容（如驱动程序）使用 proc 的方面，不幸的是，目前没有最新的内核文档可用于 proc API/ABI。

在 5.4.0 内核上，有大约 70 多个`proc_create()`内核 API 的调用者，其中有一些是（通常是较老的）驱动程序和文件系统。

尽管如此（您已经被警告！），让我们学习如何通过 procfs 与内核代码交互用户空间进程。

## 使用 procfs 与用户空间进行接口

作为内核模块或设备驱动程序开发人员，我们实际上可以在`/proc`下创建自己的条目，利用这作为与用户空间的简单接口。我们如何做到这一点？内核提供了 API 来在 procfs 下创建目录和文件。我们将在本节中学习如何使用它们。

### 基本的 procfs API

在这里，我们不打算深入研究 procfs API 集的细节；相反，我们将只涵盖足够让您能够理解和使用它们。要了解更深入的细节，请参考终极资源：内核代码库。我们将在这里介绍的例程已经被导出，因此可以供像您这样的驱动程序作者使用。此外，正如我们之前提到的，所有 procfs 文件对象实际上都是伪对象，也就是说它们只存在于 RAM 中。

在这里，我们假设您了解如何设计和实现一个简单的 LKM；您可以在本书的附属指南*Linux Kernel Programming*的第四和第五章中找到更多细节。

让我们开始探索一些简单的 procfs API，它们允许您执行一些关键任务-在 proc 文件系统下创建目录，创建（伪）文件，并分别删除它们。对于所有这些任务，请确保包含相关的头文件；也就是说，`#include <linux/proc_fs.h>`：

1.  在`/proc`下创建一个名为`name`的目录：

```
struct proc_dir_entry *proc_mkdir(const char *name,
                         struct proc_dir_entry *parent);
```

第一个参数是目录的名称，而第二个参数是要在其下创建它的父目录的指针。在这里传递`NULL`会在根目录下创建目录；也就是说，在`/proc`下。保存返回值，因为您通常会将其用作后续 API 的参数。

`proc_mkdir_data()`例程允许您传递一个数据项（`void *`）；请注意，它是通过`EXPORT_SYMBOL_GPL`导出的。

1.  创建一个名为`/proc/parent/name`的 procfs（伪）文件：

```
struct proc_dir_entry *proc_create(const char *name, umode_t mode,
                         struct proc_dir_entry *parent,
                         const struct file_operations *proc_fops);
```

这里的关键参数是`struct file_operations`，我们在上一章中介绍过。您需要用要实现的“方法”填充它（后面会更多介绍）。想想看：这真的是非常强大的东西；使用`fops`结构，您可以在驱动程序（或内核模块）中设置“回调”函数，内核的 proc 文件系统层将会遵守它们：当用户空间进程从您的 proc 文件中读取时，它（VFS）将调用驱动程序的`.read`方法或回调函数。如果用户空间应用程序写入，它将调用驱动程序的`.write`回调！

1.  删除一个 procfs 条目：

```
void remove_proc_entry(const char *name, struct proc_dir_entry *parent)
```

此 API 删除指定的`/proc/name`条目并释放它（如果未被使用）；类似地（通常更方便），使用`remove_proc_subtree()` API 来删除`/proc`中的整个子树（通常在清理或发生错误时）。

现在我们知道了基础知识，经验法则要求我们将这些 API 应用到实践中！为此，让我们找出在`/proc`下创建哪些目录/文件。

### 我们将创建四个 procfs 文件

为了清楚地说明 procfs 作为接口技术的用法，我们将让我们的内核模块在`/proc`下创建一个目录。在该目录下，它将创建四个 procfs（伪）文件。请注意，默认情况下，所有 procfs 文件的*owner:group*属性都是*root:root*。现在，创建一个名为`/proc/proc_simple_intf`的目录，并在其中创建四个（伪）文件。在`/proc/proc_simple_intf`目录下的四个 procfs（伪）文件的名称和属性如下表所示：

| **procfs 'file'的名称** | **R：读取回调上的操作，通过用户空间读取调用** | **W：写入回调上的操作，通过用户空间写入调用** | **Procfs 'file'权限** |
| --- | --- | --- | --- |
| `llkdproc_dbg_level` | 检索（到用户空间）全局变量的当前值；即 `debug_level` | 更新 `debug_level` 全局变量为用户空间写入的值 | `0644` |
| `llkdproc_show_pgoff` | 检索（到用户空间）内核的 `PAGE_OFFSET` 值 | – 无写回调 – | `0444` |
| `llkdproc_show_drvctx` | 检索（到用户空间）驱动程序“上下文”结构中的当前值；即 `drv_ctx` | – 无写回调 – | `0440` |
| `llkdproc_config1`（也被视为 `dbg_level`） | 检索（到用户空间）上下文变量的当前值；即 `drvctx->config1` | 更新驱动程序上下文成员 `drvctx->config1` 为用户空间写入的值 | `0644` |

我们将查看用于在 `/proc` 下创建 `proc_simple_intf` 目录和其中四个文件的 API 和实际代码（由于空间不足，我们实际上不会显示所有代码；只显示与“调试级别”获取和设置相关的代码；这不是问题，其余代码在概念上非常相似）。

### 尝试动态调试级别 procfs 控制

首先，让我们查看我们将在本章节中始终使用的“驱动程序上下文”数据结构（实际上，在上一章节中首次使用）：

```
// ch2/procfs_simple_intf/procfs_simple_intf.c
[ ... ]
/* Borrowed from ch1; the 'driver context' data structure;
 * all relevant 'state info' reg the driver and (fictional) 'device'
 * is maintained here.
 */
struct drv_ctx {
    int tx, rx, err, myword, power;
    u32 config1; /* treated as equivalent to 'debug level' of our driver */
    u32 config2;
    u64 config3;
#define MAXBYTES   128
    char oursecret[MAXBYTES];
};
static struct drv_ctx *gdrvctx;
static int debug_level; /* 'off' (0) by default ... */
```

在这里，我们还可以看到我们有一个名为 `debug_level` 的全局整数；这将动态控制“项目”的调试详细程度。调试级别分配了一个范围 `[0-2]`，我们有以下内容：

+   `0` 意味着*没有调试消息*（默认值）。

+   `1` 是*中等调试*详细程度。

+   `2` 意味着*高调试*详细程度。

整个架构的美妙之处 – 实际上整个重点在于 – 我们将能够通过我们创建的 procfs 接口从用户空间查询和设置这个 `debug_level` 变量！这将允许最终用户（出于安全原因，需要 *root* 访问权限）在运行时动态地改变调试级别（这是许多产品中常见的功能）。

在深入了解代码级细节之前，让我们先试一下，这样我们就知道可以期待什么：

1.  在这里，使用我们的 `lkm` 便捷包装脚本，我们必须构建并 `insmod(8)` 内核模块（本书源代码树中的 `ch2/proc_simple_intf`）：

```
$ cd <booksrc>/ch2/proc_simple_intf
$ ../../lkm procfs_simple_intf          *<-- builds the kernel module*
Version info:
[...]
[24826.234323] procfs_simple_intf:procfs_simple_intf_init():321: proc dir (/proc/procfs_simple_intf) created
[24826.240592] procfs_simple_intf:procfs_simple_intf_init():333: proc file 1 (/proc/procfs_simple_intf/llkdproc_debug_level) created
[24826.245072] procfs_simple_intf:procfs_simple_intf_init():348: proc file 2 (/proc/procfs_simple_intf/llkdproc_show_pgoff) created
[24826.248628] procfs_simple_intf:alloc_init_drvctx():218: allocated and init the driver context structure
[24826.251784] procfs_simple_intf:procfs_simple_intf_init():368: proc file 3 (/proc/procfs_simple_intf/llkdproc_show_drvctx) created
[24826.255145] procfs_simple_intf:procfs_simple_intf_init():378: proc file 4 (/proc/procfs_simple_intf/llkdproc_config1) created
[24826.259203] procfs_simple_intf initialized
$ 
```

在这里，我们构建并插入了内核模块；`dmesg(1)` 显示了内核 *printks*，显示我们创建的 procfs 文件之一是与动态调试功能相关的文件（在这里用粗体突出显示；由于这些是伪文件，文件大小将显示为 `0` 字节）。

1.  现在，让我们通过查询 `debug_level` 的当前值来测试它：

```
$ cat /proc/procfs_simple_intf/llkdproc_debug_level
debug_level:0
$
```

1.  很好，它是零 – 默认值 – 如预期的那样。现在，让我们将调试级别更改为 `2`：

```
$ sudo sh -c "echo 2 > /proc/procfs_simple_intf/llkdproc_debug_level"
$ cat /proc/procfs_simple_intf/llkdproc_debug_level
debug_level:2
$
```

请注意，我们必须以 *root* 身份发出 `echo`。正如我们所看到的，调试级别确实已经改变（为值 `2`）！尝试设置超出范围的值也被捕获（并且 `debug_level` 变量的值被重置为其最后有效的值），如下所示：

```
$ sudo sh -c "echo 5 > /proc/procfs_simple_intf/llkdproc_debug_level"
sh: echo: I/O error
$ dmesg
[...]
[ 6756.415727] procfs_simple_intf: trying to set invalid value for debug_level [allowed range: 0-2]; resetting to previous (2)
```

好的，它按预期工作。然而，问题是，所有这些在代码级别是如何工作的？继续阅读以了解详情！

### 通过 procfs 动态控制 debug_level

让我们回答前面提到的问题 – *代码中是如何做到的？* 实际上非常简单：

1.  首先，在内核模块的 `init` 代码中，我们必须创建我们的 procfs 目录，并以内核模块的名称命名它：

```
static struct proc_dir_entry *gprocdir;
[...]
gprocdir = proc_mkdir(OURMODNAME, NULL);
```

1.  同样，在内核模块的 `init` 代码中，我们必须创建控制项目“调试级别”的 `procfs` 文件：

```
// ch2/procfs_simple_intf/procfs_simple_intf.c[...]
#define PROC_FILE1           "llkdproc_debug_level"
#define PROC_FILE1_PERMS     0644
[...]
static int __init procfs_simple_intf_init(void)
{
    int stat = 0;
    [...]
    /* 1\. Create the PROC_FILE1 proc entry under the parent dir OURMODNAME;
     * this will serve as the 'dynamically view/modify debug_level'
     * (pseudo) file */
    if (!proc_create(PROC_FILE1, PROC_FILE1_PERMS, gprocdir,
 &fops_rdwr_dbg_level)) {
    [...]
    pr_debug("proc file 1 (/proc/%s/%s) created\n", OURMODNAME, PROC_FILE1);
    [...]
```

在这里，我们使用了 `proc_create()` API 来创建 *procfs* 文件，并将其“链接”到提供的 `file_operations` 结构。

1.  fops 结构（技术上是`struct file_operations`）在这里是关键的数据结构。正如我们在第一章 *编写简单的杂项字符设备驱动程序*中学到的，这是我们为设备上的各种文件操作分配*功能*的地方，或者在这种情况下，procfs 文件。这是初始化我们的 fops 的代码：

```
static const struct file_operations fops_rdwr_dbg_level = {
    .owner = THIS_MODULE,
    .open = myproc_open_dbg_level,
    .read = seq_read,
    .write = myproc_write_debug_level,
    .llseek = seq_lseek,
    .release = single_release,
};
```

1.  fops 的`open`方法指向一个我们必须定义的函数：

```
static int myproc_open_dbg_level(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show_debug_level, NULL);
}
```

使用内核的`single_open()` API，我们注册了这样一个事实，即每当这个文件被读取时-最终是通过用户空间的`read(2)`系统调用完成的- proc 文件系统将“回调”我们的`proc_show_debug_level()`例程（作为`single_open()`的第二个参数）。

我们不会在这里打扰`single_open()` API 的内部实现；如果你感兴趣，你可以在这里查找：`fs/seq_file.c:single_open()`。

因此，总结一下，要在 procfs 中注册一个“读”方法，我们需要做以下工作：

+   将`fops.open`指针初始化为`foo()`函数。

+   在`foo()`函数中，调用`single_open()`，将读回调函数作为第二个参数。

这里有一些历史；不深入讨论，可以说 procfs 的旧工作方式存在问题。特别是，你无法在没有手动迭代内容的情况下传输超过一个页面的数据（使用读或写）。在 2.6.12 引入的*序列迭代器*功能解决了这些问题。如今，使用`single_open()`及其类似功能（`seq_read`、`seq_lseek`和`seq_release`内置内核函数）是使用 procfs 的更简单和正确的方法。

1.  那么，当用户空间*写入*（通过`write(2)`系统调用）到一个 proc 文件时怎么办？简单：在前面的代码中，你可以看到我们已经注册了`fops_rdwr_dbg_level.write`方法作为`myproc_write_debug_level()`函数，这意味着每当写入这个（伪）文件时，这个函数将被*回调*（在*步骤 6*中解释了*读*回调之后）。

我们通过`single_open`注册的*读*回调函数的代码如下：

```
/* Our proc file 1: displays the current value of debug_level */
static int proc_show_debug_level(struct seq_file *seq, void *v)
{
    if (mutex_lock_interruptible(&mtx))
        return -ERESTARTSYS;
    seq_printf(seq, "debug_level:%d\n", debug_level);
    mutex_unlock(&mtx);
    return 0;
}
```

`seq_printf()`在概念上类似于熟悉的`sprintf()` API。它正确地将提供给它的数据打印到`seq_file`对象上。当我们在这里说“打印”时，我们真正的意思是它有效地将数据缓冲区传递给发出了读系统调用的用户空间进程或线程，从而*将数据传输到用户空间*。

哦，是的，`mutex_{un}lock*()` API 是什么情况？它们用于一些关键的*锁定*。我们将在第六章 *内核同步-第一部分*和第七章 *内核同步-第二部分*中对锁定进行详细讨论；现在，只需理解这些是必需的同步原语。

1.  我们通过`fops_rdwr_dbg_level.write`注册的*写*回调函数如下：

```
#define DEBUG_LEVEL_MIN     0
#define DEBUG_LEVEL_MAX     2
[...]
/* proc file 1 : modify the driver's debug_level global variable as per what user space writes */
static ssize_t myproc_write_debug_level(struct file *filp, 
                const char __user *ubuf, size_t count, loff_t *off)
{
   char buf[12];
   int ret = count, prev_dbglevel;
   [...]
   prev_dbglevel = debug_level;
 *// < ... validity checks (not shown here) ... >*
   /* Get the user mode buffer content into the kernel (into 'buf') */
   if (copy_from_user(buf, ubuf, count)) {
        ret = -EFAULT;
        goto out;
   }
   [...]
   ret = kstrtoint(buf, 0, &debug_level); /* update it! */
   if (ret)
        goto out;
  if (debug_level < DEBUG_LEVEL_MIN || debug_level > DEBUG_LEVEL_MAX) {
            [...]
            debug_level = prev_dbglevel;
            ret = -EFAULT; goto out;
   }
   /* just for fun, let's say that our drv ctx 'config1'
      represents the debug level */
   gdrvctx->config1 = debug_level;
   ret = count;
out:
   mutex_unlock(&mtx);
   return ret;
}
```

在我们的写方法实现中（注意它在结构上与字符设备驱动程序的写方法有多相似），我们进行了一些有效性检查，然后将用户空间进程写入的数据复制到我们这里（回想一下我们如何使用`echo`命令写入 procfs 文件），通过通常的`copy_from_user()`函数。然后，我们使用内核内置的`kstrtoint()` API（类似的还有几个）将字符串缓冲区转换为整数，并将结果存储在我们的全局变量中；也就是`debug_level`！再次验证它，如果一切正常，我们还设置（只是作为一个例子）我们驱动程序上下文的`config1`成员为相同的值，然后返回一个成功消息。

1.  内核模块的其余代码非常相似-我们为剩下的三个 procfs 文件设置功能。我留给你详细浏览代码并尝试它。

1.  另一个快速演示：让我们将`debug_level`设置为`1`，然后通过我们创建的第三个 procfs 文件转储驱动程序上下文结构：

```
$ cat /proc/procfs_simple_intf/llkdproc_debug_level
debug_level:0
$ sudo sh -c "echo 1 > /proc/procfs_simple_intf/llkdproc_debug_level"
```

1.  好的，`debug_level`变量现在将具有值`1`；现在，让我们转储驱动程序上下文结构：

```
$ cat /proc/procfs_simple_intf/llkdproc_show_drvctx 
cat: /proc/procfs_simple_intf/llkdproc_show_drvctx: Permission denied
$ sudo cat /proc/procfs_simple_intf/llkdproc_show_drvctx 
prodname:procfs_simple_intf
tx:0,rx:0,err:0,myword:0,power:1
config1:0x1,config2:0x48524a5f,config3:0x424c0a52
oursecret:AhA xxx
$ 
```

我们需要*root*访问权限才能这样做。一旦完成，我们可以清楚地看到我们的`drv_ctx`数据结构的所有成员。不仅如此，我们还验证了加粗显示的`config1`成员现在的值为`1`，因此反映了设计的“调试级别”。

另外，请注意输出是故意以高度可解析的格式生成到用户空间，几乎类似于 JSON。当然，作为一个小练习，你可以安排精确地做到这一点！

最近大量的**物联网**（**IoT**）产品使用 RESTful API 进行通信；通常解析的格式是 JSON。养成在易于解析的格式（如 JSON）中设计和实现内核到用户（反之亦然）的通信的习惯只会有所帮助。

有了这个，你已经学会了如何创建 procfs 目录、其中的文件，以及最重要的是如何创建和使用读写回调函数，以便当用户模式进程读取或写入你的 proc 文件时，你可以从内核深处做出适当的响应。正如我们之前提到的，由于空间不足，我们将不描述驱动其余三个 procfs 文件的代码。从概念上讲，这与我们刚刚讨论的非常相似。我们希望你能仔细阅读并尝试一下！

## 一些杂项 procfs API

让我们通过查看一些剩余的杂项 procfs API 来结束本节。你可以使用`proc_symlink()`函数在`/proc`中创建一个符号或软链接。

接下来，`proc_create_single_data()` API 可能非常有用；它被用作一个“快捷方式”，在那里你只需要将一个“读”方法附加到一个 procfs 文件：

```
struct proc_dir_entry *proc_create_single_data(const char *name, umode_t mode, struct     
        proc_dir_entry *parent, int (*show)(struct seq_file *, void *), void *data);
```

使用这个 API 可以消除对单独的 fops 数据结构的需求。我们可以使用这个函数来创建和处理我们的第二个 procfs 文件——`llkdproc_show_pgoff`文件：

```
... proc_create_single_data(PROC_FILE2, PROC_FILE2_PERMS, gprocdir, proc_show_pgoff, 0) ...
```

从用户空间读取时，内核的 VFS 和 proc 层代码路径将调用已注册的方法——我们模块的`proc_show_pgoff()`函数——在其中我们轻松地调用`seq_printf()`将`PAGE_OFFSET`的值发送到用户空间：

```
seq_printf(seq, "%s:PAGE_OFFSET:0x%px\n", OURMODNAME, PAGE_OFFSET);
```

此外，请注意`proc_create_single_data` API 的以下内容：

+   你可以利用`proc_create_single_data()`的第五个参数将任何数据项传递给读回调（在那里作为`seq_file`成员`private`检索，非常类似于我们在上一章中使用`filp->private_data`的方式）。

+   内核主线中的一些通常较老的驱动程序确实使用这个函数来创建它们的 procfs 接口。其中之一是 RTC 驱动程序（在`/proc/driver/rtc`设置一个条目）。SCSI `megaraid`驱动程序（`drivers/scsi/megaraid`）使用这个例程至少 10 次来设置它的 proc 接口（当启用配置选项时；默认情况下是启用的）。

小心！我发现在运行分发（默认）内核的 Ubuntu 18.04 LTS 系统上，这个 API——`proc_create_single_data()`——甚至都不可用，所以构建失败了。在我们自定义的“纯净”5.4 LTS 内核上，它运行得很好。

此外，关于我们在这里设置的 procfs API，有一些文档，尽管这些文档往往是用于内部使用而不是用于模块：[`www.kernel.org/doc/html/latest/filesystems/api-summary.html#the-proc-filesystem`](https://www.kernel.org/doc/html/latest/filesystems/api-summary.html#the-proc-filesystem)。

因此，正如我们之前提到的，使用 procfs API 是一个**因人而异**（**YMMV**）的情况！在发布之前，请仔细测试你的代码。最好遵循内核社区的指南，并简单地对 procfs 作为驱动程序接口技术说**不**。不用担心，我们将在本章的其余部分中看到更好的方法！

这完成了我们对使用 procfs 作为有用通信接口的覆盖。现在，让我们学习如何为驱动程序使用更合适的接口- sysfs 接口。

# 通过 sys 文件系统进行接口

2.6 Linux 内核发布的一个关键特性是现代*设备模型*的出现。基本上，一系列复杂的类似树状的分层数据结构对系统上所有设备进行建模。实际上，它远不止于此；**sysfs**树包括以下内容（以及其他内容）：

+   系统上存在的每个总线（也可以是虚拟或伪总线）

+   每个总线上的设备

+   每个绑定到总线上设备的设备驱动程序

因此，它不仅仅是外围设备，还有底层系统总线，每个总线上的设备以及绑定到设备的设备驱动程序，这些都是在运行时由设备模型创建和维护的。这个模型的内部工作对于您作为典型的驱动程序作者来说是不可见的；您不必真正担心它。在系统引导时，以及每当新设备变得可见时，*驱动程序核心*（内置内核机制的一部分）会在 sysfs 树下生成所需的虚拟文件。（相反，当设备被移除或分离时，其条目会从树中消失。）

请记住，从*与 proc 文件系统进行接口*部分可以看出，对于设备驱动程序的接口目的来说，使用 procfs 并不是真正正确的方法，至少对于想要上游移动的代码来说。那么，什么才是正确的方法呢？啊，*创建 sysfs（伪）文件被认为是设备驱动程序与用户空间进行接口的“正确方式”*。

所以，现在我们明白了！sysfs 是一个虚拟文件系统，通常挂载在`/sys`目录上。实际上，sysfs 与 procfs 非常相似，是一个内核导出的信息（设备和其他）树，发送到用户空间。您可以将 sysfs 视为对现代设备模型具有不同*视口*。通过 sysfs，您可以以几种不同的方式或通过不同的“视口”查看系统；例如，您可以通过它支持的各种总线（*总线*视图-PCI、USB、平台、I2C、SPI 等）查看系统，通过各种设备的“类”（*类*视图），通过*设备*本身，通过*块*设备视口等等。下面的屏幕截图显示了我在 Ubuntu 18.04 LTS VM 上的`/sys`目录的内容：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/bf6846b2-8f7a-47e3-98a2-be5528a87f22.png)

图 2.2 - 屏幕截图显示了 x86_64 Ubuntu VM 上 sysfs（/sys）的内容

我们可以看到，通过 sysfs，还有其他几个视口可以用来查看系统。当然，在这一部分，我们希望了解如何通过 sysfs 将设备驱动程序与用户空间进行接口，如何编写代码在 sysfs 下创建我们的驱动程序（伪）文件，以及如何注册从中读取/写入的回调。让我们首先看一下基本的 sysfs API。

## 在代码中创建一个 sysfs（伪）文件

在 sysfs 下创建伪（或虚拟）文件的一种方法是通过`device_create_file()`API。其签名如下：

```
drivers/base/core.c:int device_create_file(struct device *dev,
                         const struct device_attribute *attr);
```

让我们逐个考虑它的两个参数；首先，有一个指向`struct device`的指针。第二个参数是指向设备属性结构的指针；我们稍后将对其进行解释和处理（在*设置设备属性和创建 sysfs 文件*部分）。现在，让我们只关注第一个参数-设备结构。这似乎很直观-设备由一个称为`device`的元数据结构表示（它是驱动程序核心的一部分；您可以在`include/linux/device.h`头文件中查找其完整定义）。

请注意，当您编写（或处理）“真实”设备驱动程序时，很有可能会存在或产生一个通用的*设备结构*。这通常发生在*注册*设备时；一个底层设备结构通常作为该设备的专用结构的成员而提供。例如，所有结构，如`platform_device`、`pci_device`、`net_device`、`usb_device`、`i2c_client`、`serial_port`等，都嵌入了一个`struct device`成员。因此，您可以使用该设备结构指针作为在 sysfs 下创建文件的 API 的参数。请放心，您很快就会看到这在代码中被执行！因此，让我们通过创建一个简单的“平台设备”来获得一个设备结构。您将在下一节中学习如何做到这一点！

## 创建一个简单的平台设备

显然，为了在 sysfs 下创建（伪）文件，我们需要一些东西作为`device_create_file()`的第一个参数，即一个指向`struct device`的指针。然而，对于我们这里和现在的演示 sysfs 驱动程序，我们实际上没有任何真正的设备，因此也没有`struct device`可以操作！

那么，我们不能创建一个*人工*或*伪设备*并简单地使用它吗？是的，但是如何，更重要的是，为什么我们需要这样做？至关重要的是要理解，现代**Linux 设备模型**（**LDM**）是建立在三个关键组件上的：**必须存在一个底层总线，设备驻留在上面，并且设备由设备驱动程序“绑定”和驱动**。（我们已经在第一章中提到过，*编写一个简单的 misc 字符设备驱动程序*，在*A quick note on the Linux Device Model*部分）。

所有这些都必须注册到驱动核心。现在，不要担心驾驶它们的公交车和公交车司机；它们将在内核的驱动核心子系统内部注册和处理。然而，当没有真正的*设备*时，我们将不得不创建一个伪设备以便与模型一起工作。再次，有几种方法可以做这样的事情，但我们将创建**一个***平台设备**。*这个设备将“存在”于一个伪总线（即，它只存在于软件中）上，称为***平台总线***。

### 平台设备

一个快速但重要的侧面：*平台设备*通常用于表示嵌入式板内**系统芯片**（**SoC**）上各种设备的多样性。SoC 通常是一个集成了各种组件的非常复杂的芯片。除了处理单元（CPU/GPU）外，它可能还包括多个外围设备，包括以太网 MAC、USB、多媒体、串行 UART、时钟、I2C、SPI、闪存芯片控制器等。我们需要将这些组件枚举为平台设备的原因是 SoC 内部没有物理总线；因此使用平台总线。

传统上，用于实例化这些 SoC 平台设备的代码保存在内核源代码中的“板”文件（或文件）中（`arch/<arch>/...`）。由于它变得过载，它已经从纯内核源代码中移出，转移到一个称为**设备树**的有用硬件描述格式中（在内核源树中的**设备树源**（**DTS**）文件中）。

在我们的 Ubuntu 18.04 LTS 虚拟机中，让我们看看 sysfs 下的平台设备：

```
$ ls /sys/devices/platform/
alarmtimer  'Fixed MDIO bus.0'   intel_pmc_core.0   platform-framebuffer.0   reg-dummy   
serial8250 eisa.0  i8042  pcspkr power rtc_cmos uevent
$
```

*Bootlin*网站（以前称为*Free Electrons*）提供了关于嵌入式 Linux、驱动程序等方面的出色材料。他们网站上的这个链接指向了关于 LDM 的优秀材料：[`bootlin.com/pub/conferences/2019/elce/opdenacker-kernel-programming-device-model/`](https://bootlin.com/pub/conferences/2019/elce/opdenacker-kernel-programming-device-model/)。

回到驱动程序：我们通过`platform_device_register_simple()` API 将我们的（人工）平台设备注册到（已经存在的）平台总线驱动程序，从而使其存在。在我们这样做的时候，驱动核心将*生成*所需的 sysfs 目录和一些样板 sysfs 条目（或文件）。在这里，在我们的 sysfs 演示驱动程序的初始化代码中，我们将通过将其注册到驱动核心来设置一个（可能最简单的）*平台设备*：

```
// ch2/sysfs_simple_intf/sysfs_simple_intf.c
include <linux/platform_device.h>
static struct platform_device *sysfs_demo_platdev;
[...]
#define PLAT_NAME    "llkd_sysfs_simple_intf_device"
sysfs_demo_platdev =
     platform_device_register_simple(PLAT_NAME, -1, NULL, 0);
[...]
```

`platform_device_register_simple()` API 返回一个指向`struct platform_device`的指针。该结构的成员之一是`struct device dev`。我们现在得到了我们一直在寻找的：一个*设备* *结构*。此外，需要注意的是，当这个注册 API 运行时，效果在 sysfs 中是可见的。你可以很容易地看到新的平台设备，以及一些样板 sysfs 对象，由驱动核心在这里创建（通过 sysfs 对我们可见）；让我们构建和*insmod*我们的内核模块来看看这一点：

```
$ cd <...>/ch2/sysfs_simple_intf
$ make && sudo insmod ./sysfs_simple_intf.ko
[...]
$ ls -l /sys/devices/platform/llkd_sysfs_simple_intf_device/
total 0
-rw-r--r-- 1 root root 4.0K Feb 15 20:22 driver_override
-rw-r--r-- 1 root root 4.0K Feb 15 20:22 llkdsysfs_debug_level
-r--r--r-- 1 root root 4.0K Feb 15 20:22 llkdsysfs_pgoff
-r--r--r-- 1 root root 4.0K Feb 15 20:22 llkdsysfs_pressure
-r--r--r-- 1 root root 4.0K Feb 15 20:22 modalias
drwxr-xr-x 2 root root 0 Feb 15 20:22 power/
lrwxrwxrwx 1 root root 0 Feb 15 20:22 subsystem -> ../../../bus/platform/
-rw-r--r-- 1 root root 4.0K Feb 15 20:21 uevent
$ 
```

我们可以以不同的方式创建一个`struct device`；通用的方法是设置并发出`device_create()` API。创建 sysfs 文件的另一种方法，同时绕过设备结构的需要，是创建一个“对象”并调用`sysfs_create_file()` API。（在*进一步阅读*部分可以找到使用这两种方法的教程链接）。在这里，我们更喜欢使用“平台设备”，因为它更接近于编写（平台）驱动程序。

还有另一种有效的方法。正如我们在第一章中所看到的，*编写一个简单的杂项字符设备驱动程序*，我们构建了一个符合内核`misc`框架的简单字符驱动程序。在那里，我们实例化了一个`struct miscdevice`；一旦注册（通过`misc_register()` API），这个结构将包含一个名为`struct device *this_device;`的成员，因此我们可以将其用作有效的设备指针！因此，我们可以简单地扩展我们之前的`misc`设备驱动程序并在这里使用它。然而，为了学习一些关于平台驱动程序的知识，我们选择了这种方法。（我们将扩展我们之前的`misc`设备驱动程序以便它可以使用 sysfs API 并创建/使用 sysfs 文件的方法留给你作为练习）。

回到我们的驱动程序，与初始化代码相比，在*清理*代码中，我们必须取消注册我们的平台设备：

```
platform_device_unregister(sysfs_demo_platdev);
```

现在，让我们把所有这些知识联系在一起，实际上看一下生成 sysfs 文件的代码，以及它们的读取和写入回调函数！

## 把所有这些联系在一起——设置设备属性并创建 sysfs 文件

正如我们在本节开头提到的，`device_create_file()` API 是我们将用来创建我们的 sysfs 文件的 API：

```
int device_create_file(struct device *dev, const struct device_attribute *attr);
```

在上一节中，你学会了如何获取设备结构（我们 API 的第一个参数）。现在，让我们弄清楚如何初始化和使用第二个参数；也就是`device_attribute`结构。该结构本身定义如下：

```
// include/linux/device.hstruct device_attribute {
    struct attribute attr;
    ssize_t (*show)(struct device *dev, struct device_attribute *attr,
                    char *buf);
    ssize_t (*store)(struct device *dev, struct device_attribute *attr,
                     const char *buf, size_t count);
};
```

第一个成员`attr`本质上包括 sysfs 文件的*名称*和*模式*（权限掩码）。另外两个成员是函数指针（“虚函数”，类似于**文件操作**或**fops**结构中的函数）：

+   `show`：表示*读取回调*函数

+   `store`：表示*写入回调*函数

我们的工作是初始化这个`device_attribute`结构，从而设置 sysfs 文件。虽然你可以手动初始化它，但也有一个更简单的方法：内核提供了（几个）用于初始化`struct device_attribute`的宏；其中之一是`DEVICE_ATTR()`宏：

```
// include/linux/device.h
define DEVICE_ATTR(_name, _mode, _show, _store) \
   struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
```

注意`dev_attr_##_name`执行的“字符串化”，确保结构的名称后缀是作为`DEVICE_ATTR`的第一个参数传递的名称。此外，实际的“工作”宏，名为`__ATTR()`，实际上在预处理时在代码中实例化了一个`device_attribute`结构，通过字符串化使结构的名称变为`dev_attr_<name>`：

```
// include/linux/sysfs.h
#define __ATTR(_name, _mode, _show, _store) { \
    .attr = {.name = __stringify(_name), \
    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) }, \
    .show = _show, \
    .store = _store, \
}
```

此外，内核定义了额外的简单包装宏，以覆盖这些宏，以指定 sysfs 文件的*模式*（权限），从而使驱动程序作者更加简单。其中包括`DEVICE_ATTR_RW(_name)`，`DEVICE_ATTR_RO(_name)`和`DEVICE_ATTR_WO(_name)`：

```
#define DEVICE_ATTR_RW(_name) \
     struct device_attribute dev_attr_##_name = __ATTR_RW(_name)
#define __ATTR_RW(_name) __ATTR(_name, 0644, _name##_show, _name##_store)
```

有了这段代码，我们可以创建一个**读写**（**RW**），**只读**（**RO**）或**只写**（**WO**）的 sysfs 文件。现在，我们希望设置一个可以读取和写入的 sysfs 文件。在内部，这是一个“挂钩”或回调，用于查询或设置一个`debug_level`全局变量，就像我们之前在 procfs 的示例内核模块中所做的那样！

现在我们有了足够的背景知识，让我们深入了解代码！

### 实现我们的 sysfs 文件和它的回调的代码

让我们看看我们简单的*sysfs 接口驱动程序*的相关部分的代码，并逐步尝试一些东西：

1.  设置设备属性结构（通过`DEVICE_ATTR_RW`宏；有关更多信息，请参见前面的部分），并创建我们的第一个 sysfs（伪）文件：

```
// ch2/sysfs_simple_intf/sysfs_simple_intf.c
#define SYSFS_FILE1 llkdsysfs_debug_level
// [... *<we show the actual read/write callback functions just a bit further down>* ...]
static DEVICE_ATTR_RW(SYSFS_FILE1);

int __init sysfs_simple_intf_init(void)
{
 [...]
*/* << 0\. The platform device is created via the platform_device_register_simple() API; code already shown above ... >> */*

 // 1\. Create our first sysfile file : llkdsysfs_debug_level
 /* The device_create_file() API creates a sysfs attribute file for
  * given device (1st parameter); the second parameter is the pointer
  * to it's struct device_attribute structure dev_attr_<name> which was
  * instantiated by our DEV_ATTR{_RW|RO} macros above ... */
  stat = device_create_file(&sysfs_demo_platdev->dev, &dev_attr_SYSFS_FILE1);
[...]
```

从这里显示的宏的定义中，我们可以推断出`static DEVICE_ATTR_RW(SYSFS_FILE1);`实例化了一个初始化的`device_attribute`结构，名称为`llkdsysfs_debug_level`（因为这就是`SYSFS_FILE1`宏的评估结果），模式为`0644`；读回调名称将是`llkdsysfs_debug_level_show()`，写回调名称将是`llkdsysfs_debug_level_store()`！

1.  这是读取和写入回调的相关代码（同样，我们不会在这里显示整个代码）。首先，让我们看看读取回调：

```
/* debug_level: sysfs entry point for the 'show' (read) callback */
static ssize_t llkdsysfs_debug_level_show(struct device *dev,
                                          struct device_attribute *attr,
                                          char *buf)
{
        int n;
        if (mutex_lock_interruptible(&mtx))
                return -ERESTARTSYS;
        pr_debug("In the 'show' method: name: %s, debug_level=%d\n",   
                 dev->kobj.name, debug_level); 
        n = snprintf(buf, 25, "%d\n", debug_level);
        mutex_unlock(&mtx);
        return n;
}
```

这是如何工作的？在读取我们的 sysfs 文件时，将调用前面的回调函数。在其中，简单地写入用户提供的缓冲指针`buf`（它的第三个参数；我们使用内核的`snprintf()`API 来做到这一点），会将提供的值（这里是`debug_level`）传输到用户空间！

1.  让我们构建并`insmod(8)`内核模块（为方便起见，我们将使用我们的`lkm`包装脚本来执行）：

```
$ ../../lkm sysfs_simple_intf          // <-- build and insmod it[...]
[83907.192247] sysfs_simple_intf:sysfs_simple_intf_init():237: sysfs file [1] (/sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level) created
[83907.197279] sysfs_simple_intf:sysfs_simple_intf_init():250: sysfs file [2] (/sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_pgoff) created
[83907.201959] sysfs_simple_intf:sysfs_simple_intf_init():264: sysfs file [3] (/sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_pressure) created
[83907.205888] sysfs_simple_intf initialized
$
```

1.  现在，让我们列出并读取与调试级别相关的 sysfs 文件：

```
$ ls -l /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level
-rw-r--r-- 1 root root 4096 Feb   4 17:41 /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level
$ cat /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level
0
```

这反映了调试级别目前为`0`。

1.  现在，让我们来看看我们的*写回调*的代码，用于调试级别的 sysfs 文件：

```
#define DEBUG_LEVEL_MIN 0
#define DEBUG_LEVEL_MAX 2

static ssize_t llkdsysfs_debug_level_store(struct device *dev,
                                           struct device_attribute *attr,
                                           const char *buf, size_t count)
{
        int ret = (int)count, prev_dbglevel;
        if (mutex_lock_interruptible(&mtx))
                return -ERESTARTSYS;

        prev_dbglevel = debug_level;
        pr_debug("In the 'store' method:\ncount=%zu, buf=0x%px count=%zu\n"
        "Buffer contents: \"%.*s\"\n", count, buf, count, (int)count, buf);
        if (count == 0 || count > 12) {
                ret = -EINVAL;
                goto out;
        }

        ret = kstrtoint(buf, 0, &debug_level); /* update it! */
 *// < ... validity checks ... >*
        ret = count;
 out:
        mutex_unlock(&mtx);
        return ret;
}
```

同样，应该清楚`kstrtoint()`内核 API 用于将用户空间的`buf`字符串转换为整数值，然后我们进行验证。此外，`kstrtoint`的第三个参数是要写入的整数，因此更新它！

1.  现在，让我们尝试更新`debug_level`的值，从它的 sysfs 文件中：

```
$ sudo sh -c "echo 2 > /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level"
$ cat /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_debug_level
2
$
```

看，它有效了！

1.  就像我们在与 procfs 进行接口时所做的那样，我们在 sysfs 代码示例中提供了更多的代码。在这里，我们有另一个（只读）sysfs 接口来显示`PAGE_OFFSET`的值，还有一个新的接口。想象一下，这个驱动程序的工作是获取一个“pressure”值（可能通过一个 I2C 驱动的压力传感器芯片）。让我们假设我们已经这样做了，并将这个压力值存储在一个名为`gpressure`的整数全局变量中。要向用户空间“显示”当前的压力值，我们必须使用一个 sysfs 文件。在这里：

在内部，为了这个演示的目的，我们已经随机将`gpressure`全局变量设置为值`25`。

```
$ cat /sys/devices/platform/llkd_sysfs_simple_intf_device/llkdsysfs_pressure
25$
```

仔细看输出；为什么在`25`之后立即出现提示？因为我们只是打印了值本身 - 没有换行，什么都没有；这是预期的。显示“pressure”值的代码确实很简单：

```
/* show 'pressure' value: sysfs entry point for the 'show' (read) callback */
static ssize_t llkdsysfs_pressure_show(struct device *dev,
                       struct device_attribute *attr, char *buf)
{
        int n;
        if (mutex_lock_interruptible(&mtx))
                return -ERESTARTSYS;
        pr_debug("In the 'show' method: pressure=%u\n", gpressure);
        n = snprintf(buf, 25, "%u", gpressure);
        mutex_unlock(&mtx);
        return n;
}
/* The DEVICE_ATTR{_RW|RO|WO}() macro instantiates a struct device_attribute dev_attr_<name> here...   */
static DEVICE_ATTR_RO(llkdsysfs_pressure); 
```

有了这些，你已经学会了如何通过 sysfs 与用户空间进行接口交互！像往常一样，我敦促你实际编写代码并尝试这些技能；看一下本章末尾的*问题*部分，自己尝试（相关的）任务。现在，让我们继续学习 sysfs，了解一个关于其 ABI 的重要*规则*。

## “一个 sysfs 文件对应一个值”的规则

到目前为止，你已经了解了如何为用户空间内核接口目的创建和使用 sysfs，但有一个关键点我们一直忽略。关于使用 sysfs 文件，有一个“规则”，规定你只能读取或写入一个值！把这看作是*一个值对应一个文件*的规则。

因此，就像我们使用“压力”值的示例一样，我们只返回压力的当前值，没有其他内容。因此，与其他接口技术不同，sysfs 并不适用于那些可能希望将任意冗长的信息包（比如驱动程序上下文结构的内容）返回给用户空间的情况；换句话说，它并不适用于纯粹的“调试”目的。

内核文档和关于 sysfs 使用的“规则”可以在这里找到：[`www.kernel.org/doc/html/latest/admin-guide/sysfs-rules.html#rules-on-how-to-access-information-in-sysfs`](https://www.kernel.org/doc/html/latest/admin-guide/sysfs-rules.html#rules-on-how-to-access-information-in-sysfs)。

此外，这里有关于 sysfs API 的文档：[`www.kernel.org/doc/html/latest/filesystems/api-summary.html#the-filesystem-for-exporting-kernel-objects`](https://www.kernel.org/doc/html/latest/filesystems/api-summary.html#the-filesystem-for-exporting-kernel-objects)。

内核通常提供多种不同的方式来创建 sysfs 对象；例如，使用`sysfs_create_files()` API，你可以一次创建多个 sysfs 文件：`int __must_check sysfs_create_files(struct kobject *kobj, const struct attribute * const *attr);`。在这里，你需要提供一个指向`kobject`的指针和一个指向属性结构列表的指针。

这就结束了我们关于 sysfs 作为接口技术的讨论；总之，sysfs 确实被认为是驱动程序作者向用户空间显示和/或设置特定驱动程序值的*正确方式*。由于“一个 sysfs 文件对应一个值”的约定，sysfs 实际上并不理想地适用于调试信息的分发。这很好地引出了我们的下一个主题——debugfs！

# 通过调试文件系统（debugfs）进行接口

想象一下，作为 Linux 驱动程序开发人员，你面临的困境：你希望实现一种简单而优雅的方式，从你的驱动程序向用户空间提供调试“挂钩”。例如，用户只需在（伪）文件上执行`cat(1)`，就会导致你的驱动程序的“调试回调”函数被调用。然后它将继续向用户模式进程转储一些状态信息（也许是“驱动程序上下文”结构），用户模式进程将忠实地将其转储到标准输出。

好的，没问题：在 2.6 版本发布之前的日子里，我们可以（就像你在*通过 proc 文件系统（procfs）进行接口*部分学到的那样）愉快地使用 procfs 层来将我们的驱动程序与用户空间进行接口。然后，从 Linux 2.6 开始，内核社区否决了这种方法。我们被告知严格停止使用 procfs，而是使用 sysfs 层作为我们的驱动程序与用户空间进行接口的手段。然而，正如我们在*通过 sys 文件系统（sysfs）进行接口*部分看到的那样，它有一个严格的*一个值对应一个文件*的规则。这对于从驱动程序发送和接收单个值（通常是环境传感器值等）非常适用，但很快就排除了除了最简单的调试接口以外的所有情况。我们可以使用 ioctl 方法（正如我们将看到的）来设置一个调试接口，但这样做要困难得多。

那么，你能做什么呢？幸运的是，从大约 2.6.12 版的 Linux 开始，就有了一个优雅的解决方案，称为 debugfs。这个“调试文件系统”非常容易使用，并且在传达驱动程序作者（实际上是任何人）可以用它来做任何他们选择的目的时非常明确！没有一个文件规则 - 忘记那个，没有规则。

当然，就像我们处理的其他基于文件系统的方法一样 - procfs，sysfs 和现在的 debugfs - 内核社区明确声称所有这些接口都是 ABI，因此它们的稳定性和寿命是*不*被保证的。虽然这是正式采取的立场，但现实是这些接口已经成为现实世界中的事实标准；毫无征兆地将它们剥离出去真的不会为任何人服务。

以下截图显示了我们的 x86-64 Ubuntu 18.04.3 LTS 客户机上 debugfs 的内容（运行我们在伴随书籍*Linux Kernel Programming*，*第三章*，*从源代码构建 5.0 Linux 内核，第二部分*中构建的"custom" 5.4.0 内核）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/d01e778c-ea1a-4934-8283-30d35557238d.png)

图 2.3 - 展示了 x86_64 Linux VM 上 debugfs 文件系统内容的截图

与 procfs 和 sysfs 一样，由于 debugfs 是一个内核特性（毕竟它是一个虚拟文件系统！），它内部的内容非常依赖于内核版本和 CPU 架构。正如我们之前提到的，通过查看这个截图，现在应该很明显，debugfs 有很多真实世界的“用户”。

## 检查 debugfs 的存在

首先，为了利用强大的*debugfs*接口，它必须在内核配置中启用。相关的 Kconfig 宏是`CONFIG_DEBUG_FS`。让我们检查一下我们的 5.4 自定义内核上是否启用了它：

在这里，我们假设您已经将`CONFIG_IKCONFIG`和`CONFIG_IKCONFIG_PROC`选项设置为`y`，因此允许我们使用`/proc/config.gz`伪文件来访问当前内核的配置。

```
$ zcat /proc/config.gz | grep -w CONFIG_DEBUG_FS
CONFIG_DEBUG_FS=y
```

的确如此；它通常在发行版中默认启用。

接下来，debugfs 的默认挂载点是`/sys/kernel/debug`。因此，我们可以看到它在内部依赖于 sysfs 内核特性的存在和默认挂载，这是默认情况下的。让我们来检查一下在我们的 Ubuntu 18.04 x86_64 VM 上 debugfs 被挂载在哪里：

```
$ mount | grep -w debugfs
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
```

它可用并且挂载在预期的位置；也就是说，`/sys/kernel/debug`。

当然，最好的做法是永远不要假设这将永远是它被挂载的位置；在您的脚本或用户模式 C 程序中，要费心去检查和验证它。事实上，让我重新表达一下：*永远不要假设任何事情是一个很好的做法；做假设是错误的一个很好的来源*。

顺便说一下，一个有趣的 Linux 特性是文件系统可以被挂载在不同的，甚至多个位置；此外，一些人更喜欢创建一个符号链接到`/sys/kernel/debug`作为`/debug`；这取决于你，真的。

像往常一样，我们的意图是在 debugfs 的保护下创建我们的（伪）文件，然后注册并利用它们的读/写回调，以便将我们的驱动程序与用户空间进行接口。为此，我们需要了解 debugfs API 的基本用法。我们将在下一节中为您指向这方面的文档。

## 查找 debugfs API 文档

内核提供了关于使用 debugfs API 的简明而出色的文档（由 Jonathan Corbet, LWN 提供）：[`www.kernel.org/doc/Documentation/filesystems/debugfs.txt`](https://www.kernel.org/doc/Documentation/filesystems/debugfs.txt)（当然，您也可以直接在内核代码库中查找）。

我建议您参考这份文档，学习如何使用 debugfs API，因为它易于阅读和理解；这样，您就可以避免在这里不必要地重复相同的信息。除了前面提到的文档之外，现代内核文档系统（基于“Sphinx”）还提供了相当详细的 debugfs API 页面：[`www.kernel.org/doc/html/latest/filesystems/api-summary.html?highlight=debugfs#the-debugfs-filesystem`](https://www.kernel.org/doc/html/latest/filesystems/api-summary.html?highlight=debugfs#the-debugfs-filesystem)。

请注意，所有 debugfs API 都只向内核模块公开为 GPL（因此需要模块在“GPL”许可下发布（这可以是双重许可，但必须是“GPL”））。

## 与 debugfs 的接口示例

Debugfs 被故意设计为“没有特定规则”的思维方式，使其成为用于调试目的的理想接口。为什么？它允许您构造任意的字节流并将其发送到用户空间，包括使用`debugfs_create_blob()`API 发送二进制“blob”。

我们之前的示例内核模块使用 procfs 和 sysfs 构建和使用了三到四个（伪）文件。为了快速演示 debugfs，我们将只使用两个“文件”：

+   `llkd_dbgfs_show_drvctx`：正如您无疑猜到的那样，当读取时，它将导致我们（现在熟悉的）“驱动程序上下文”数据结构的当前内容被转储到控制台；我们将确保伪文件的模式是只读的（由 root）。

+   `llkd_dbgfs_debug_level`：这个文件的模式将是读写（仅由 root）；当读取时，它将显示`debug_level`的当前值；当写入一个整数时，我们将更新内核模块中的`debug_level`的值为传递的值。

在我们的内核模块的初始化代码中，我们将首先在`debugfs`下创建一个目录：

```
// ch2/debugfs_simple_intf/debugfs_simple_intf.c

static struct dentry *gparent;
[...]
static int debugfs_simple_intf_init(void)
{
    int stat = 0;
    struct dentry *file1, *file2;
    [...]
    gparent = debugfs_create_dir(OURMODNAME, NULL);
```

现在我们有了一个起点——一个目录——让我们继续创建它下面的 debugfs（伪）文件。

### 创建和使用第一个 debugfs 文件

为了可读性和节省空间，我们不会在这里展示错误处理代码部分。

就像在 procfs 的示例中一样，我们必须分配和初始化我们的“驱动程序上下文”数据结构的一个实例（我们没有在这里展示代码，因为它是重复的，请参考 GitHub 源代码）。

然后，通过通用的`debugfs_create_file()`API，我们必须创建一个`debugfs`文件，并将其与一个`file_operations`结构相关联。这实际上只是注册了一个读回调：

```
static const struct file_operations dbgfs_drvctx_fops = {
    .read = dbgfs_show_drvctx,
};
[...]
*// < ... init function ... >*
   /* Generic debugfs file + passing a pointer to a data structure as a
    * demo.. the 4th param is a generic void * ptr; it's contents will be
    * stored into the i_private field of the file's inode.
    */
#define DBGFS_FILE1 "llkd_dbgfs_show_drvctx"
    file1 = debugfs_create_file(DBGFS_FILE1, 0440, gparent,
                (void *)gdrvctx, &dbgfs_drvctx_fops);
    [...]
```

从 Linux 5.8 开始（请回忆我们正在使用 5.4 LTS 内核），一些 debugfs 创建 API 的返回值已被移除（它们将返回`void`）；Greg Kroah-Hartman 的补丁提到这样做是因为没有人在使用它们。这在 Linux 中非常典型——不需要的功能被剥离，内核继续演进……

显然，“读”回调是我们的`dbgfs_show_drvctx()`函数。作为提醒，每当读取`debugfs`文件（`llkd_dbgfs_show_drvctx`）时，这个函数会被 debugfs 层自动调用；这是我们的 debugfs 读回调函数的代码：

```
static ssize_t dbgfs_show_drvctx(struct file *filp, char __user * ubuf,
                                 size_t count, loff_t * fpos)
{
    struct drv_ctx *data = (struct drv_ctx *)filp->f_inode->i_private;
                       // retrieve the "data" from the inode
#define MAXUPASS 256   // careful- the kernel stack is small!
    char locbuf[MAXUPASS];

    if (mutex_lock_interruptible(&mtx))
        return -ERESTARTSYS;

   /* As an experiment, we set our 'config3' member of the drv ctx stucture
    * to the current 'jiffies' value (# of timer interrupts since boot);
    * so, every time we 'cat' this file, the 'config3' value should change!
    */
   data->config3 = jiffies;
   snprintf(locbuf, MAXUPASS - 1,
            "prodname:%s\n"
            "tx:%d,rx:%d,err:%d,myword:%d,power:%d\n"
            "config1:0x%x,config2:0x%x,config3:0x%llx (%llu)\n"
            "oursecret:%s\n",
            OURMODNAME,
            data->tx, data->rx, data->err, data->myword, data->power,
            data->config1, data->config2, data->config3, data->config3,
            data->oursecret);

    mutex_unlock(&mtx);
    return simple_read_from_buffer(ubuf, MAXUPASS, fpos, locbuf,
                                   strlen(locbuf));
}
```

请注意，我们通过解引用 debugfs 文件的 inode 成员`i_private`来检索“data”指针（我们的驱动程序上下文结构）。

正如我们在第一章中提到的，*编写一个简单的杂项字符设备驱动程序*，使用`data`指针从文件的 inode 中解引用驱动程序上下文结构是驱动程序作者为避免使用全局变量而采用的一种类似的常见技术之一。在这里，`gdrvctx` *是*一个全局变量，所以这是一个无关紧要的问题；我们只是用它来演示典型的用例。

使用`snprintf()`API，我们可以用当前驱动程序“上下文”结构的内容填充一个本地缓冲区，然后通过`simple_read_from_buffer()`API 将其传递给发出读取的用户空间应用程序，通常会导致它显示在终端/控制台窗口上。这`simple_read_from_buffer()`API 是`copy_to_user()`的一个包装器。

让我们试一试：

```
$ ../../lkm debugfs_simple_intf
[...]
[200221.725752] dbgfs_simple_intf: allocated and init the driver context structure
[200221.728158] dbgfs_simple_intf: debugfs file 1 <debugfs_mountpt>/dbgfs_simple_intf/llkd_dbgfs_show_drvctx created
[200221.732167] dbgfs_simple_intf: debugfs file 2 <debugfs_mountpt>/dbgfs_simple_intf/llkd_dbgfs_debug_level created
[200221.735723] dbgfs_simple_intf initialized
```

正如我们所看到的，两个 debugfs 文件都如预期地创建了；让我们验证一下（这里要小心；你只能以*root*身份查看 debugfs）：

```
$ ls -l /sys/kernel/debug/dbgfs_simple_intf
ls: cannot access '/sys/kernel/debug/dbgfs_simple_intf': Permission denied
$ sudo ls -l /sys/kernel/debug/dbgfs_simple_intf
total 0
-rw-r--r-- 1 root root 0 Feb  7 15:58 llkd_dbgfs_debug_level
-r--r----- 1 root root 0 Feb  7 15:58 llkd_dbgfs_show_drvctx
$
```

伪文件已创建并具有正确的权限。现在，让我们从`llkd_dbgfs_show_drvctx`文件中读取（作为 root 用户）：

```
$ sudo cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_show_drvctx
prodname:dbgfs_simple_intf
tx:0,rx:0,err:0,myword:0,power:1
config1:0x0,config2:0x48524a5f,config3:0x102fbcbc2 (4345023426)
oursecret:AhA yyy
$
```

它有效；几秒钟后再次进行读取。注意`config3`的值已经发生了变化。为什么？记得我们将它设置为`jiffies`值 - 自系统启动以来发生的定时器“滴答”/中断的数量：

```
$ sudo cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_show_drvctx | grep config3
config1:0x0,config2:0x48524a5f,config3:0x102fbe828 (4345030696)
$
```

创建并使用了第一个 debugfs 文件后，让我们了解第二个 debugfs 文件。

### 创建和使用第二个 debugfs 文件

让我们继续进行第二个 debugfs 文件。我们将使用一个有趣的快捷辅助 debugfs API，名为`debugfs_create_u32()`来创建它。这个 API*自动*设置内部回调，允许你在驱动程序中指定的无符号 32 位全局变量上进行读/写。这个“辅助”例程的主要优势在于，你不需要显式提供`file_operations`结构，甚至任何回调例程。debugfs 层“理解”并在内部设置事情，以便读取或写入数字（全局）变量总是有效的！看一下*init*代码路径中的以下代码，它创建并设置了我们的第二个 debugfs 文件：

```
static int debug_level;    /* 'off' (0) by default ... */ 
[...]
 /* 3\. Create the debugfs file for the debug_level global; we use the
    * helper routine to make it simple! There is a downside: we have no
    * chance to perform a validity check on the value being written.. */
#define DBGFS_FILE2     "llkd_dbgfs_debug_level"
   file2 = debugfs_create_u32(DBGFS_FILE2, 0644, gparent, &debug_level);
   [...]
   pr_debug("%s: debugfs file 2 <debugfs_mountpt>/%s/%s created\n",
             OURMODNAME, OURMODNAME, DBGFS_FILE2);
```

就是这么简单！现在，读取这个文件将产生`debug_level`的当前值；写入它将把它设置为写入的值。让我们来做这个：

```
$ sudo cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_debug_level
0
$ sudo sh -c "echo 5 > /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_debug_level"
$ sudo cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_debug_level
5
$ 
```

这样做是有效的，但这种“捷径”方法也有一个缺点：由于这一切都是在内部完成的，我们无法*验证*被写入的值。因此，在这里，我们将值`5`写入了`debug_level`；它有效，但是这是一个无效值（至少让我们假设是这样）！那么，如何纠正这个问题呢？简单：不要使用这种辅助方法；而是通过通用的`debugfs_create_file()`API 以“通常”的方式进行操作（就像我们为第一个 debugfs 文件所做的那样）。这里的优势在于，我们为读和写设置了显式的回调例程，通过在 fops 结构中指定它们，我们可以控制被写入的值（我把这个任务留给你作为练习）。就像生活一样，这是一个权衡；有得有失。

## 用于处理数字全局变量的辅助 debugfs API

你刚刚学会了如何使用`debugfs_create_u32()`辅助 API 来设置一个 debugfs 文件，以读/写一个无符号 32 位整数全局变量。事实上，debugfs 层提供了一堆类似的“辅助”API，用于隐式读/写模块内的数字（整数）全局变量。

用于创建可以读/写不同位大小的无符号整数（8 位、16 位、32 位和 64 位）全局变量的 debugfs 条目的辅助例程如下。最后一个参数是关键的 - 内核/模块中全局整数的地址：

```
// include/linux/debugfs.h
struct dentry *debugfs_create_u8(const char *name, umode_t mode,
                 struct dentry *parent, u8 *value);
struct dentry *debugfs_create_u16(const char *name, umode_t mode,
                 struct dentry *parent, u16 *value);
struct dentry *debugfs_create_u32(const char *name, umode_t mode,
                 struct dentry *parent, u32 *value);
struct dentry *debugfs_create_u64(const char *name, umode_t mode,
                 struct dentry *parent, u64 *value);
```

前面的 API 使用十进制基数；为了方便使用*十六进制基数*，我们有以下辅助程序：

```
struct dentry *debugfs_create_x8(const char *name, umode_t mode,
                 struct dentry *parent, u8 *value);
struct dentry *debugfs_create_x16(const char *name, umode_t mode,
                 struct dentry *parent, u16 *value);
struct dentry *debugfs_create_x32(const char *name, umode_t mode,
                 struct dentry *parent, u32 *value);
struct dentry *debugfs_create_x64(const char *name, umode_t mode,
                 struct dentry *parent, u64 *value);
```

另外，内核还为那些变量大小不确定的情况提供了一个辅助 API；因此，使用`debugfs_create_size_t()`辅助程序创建一个适用于`size_t`大小变量的 debugfs 文件。

对于那些只需要查看数字全局变量的驱动程序，或者在不担心无效值的情况下更新它的驱动程序，这些 debugfs 辅助 API 非常有用，实际上在主线内核中被几个驱动程序常用（我们很快将在 MMC 驱动程序中看到一个例子）。为了规避“有效性检查”问题，通常我们可以安排*用户空间*应用程序（或脚本）执行有效性检查；事实上，这通常是做事情的“正确方式”。

UNIX 范例有一句话：*提供机制，而不是策略*。

当使用*boolean*类型的全局变量时，debugfs 提供以下辅助 API：

```
struct dentry *debugfs_create_bool(const char *name, umode_t mode,
                  struct dentry *parent, bool *value);
```

从“文件”中读取将只返回`Y`或`N`（后面跟着一个换行符）；显然，如果第四个`value`参数的当前值非零，则返回`Y`，否则返回`N`。在写入时，可以写入`Y`或`N`或`1`或`0`；其他值将不被接受。

想想看：你可以通过写入`1`到一个名为`power`的布尔变量来通过你的“机器人”设备控制你的“机器人”设备驱动程序，以打开它，并使用`0`来关闭它！可能性是无穷无尽的。

debugfs 的内核文档提供了一些其他杂项 API；我留给你去看一看。现在我们已经介绍了如何创建和使用我们的演示 debugfs 伪文件，让我们学习如何删除它们。

### 删除 debugfs 伪文件(s)

当模块被移除（比如通过`rmmod(8)`），我们必须删除我们的 debugfs 文件。以前的做法是通过`debugfs_remove()` API，每个 debugfs 文件都必须单独删除（至少可以说是痛苦的）。现代方法使这变得非常简单：

```
void debugfs_remove_recursive(struct dentry *dentry);
```

传递指向整个“父”目录的指针（我们首先创建的那个），整个分支将被递归地删除；完美。

在这一点上不删除你的 debugfs 文件，因此将它们留在文件系统中处于孤立状态，这是在自找麻烦！想想看：当有人（试图）以后读取或写入它们时会发生什么？**一个内核 bug，或者一个*Oops***，就是这样。

#### 看到一个内核 bug - 一个 Oops！

让我们让它发生 - 一个内核 bug！激动人心，是吧！？

好的，要创建一个内核 bug，我们必须确保当我们移除（卸载）内核模块时，清理（删除）所有 debugfs 文件的 API，`debugfs_remove_recursive()`，*不*被调用。因此，每次移除模块后，我们的 debugfs 目录和文件似乎仍然存在！但是，如果你尝试对它们中的任何一个进行操作 - 读/写 - 它们将处于*孤立状态*，因此，在尝试取消引用其元数据时，内部 debugfs 代码路径将执行无效的内存引用，导致（内核级）bug。

在内核空间中，bug 确实是一件非常严重的事情；理论上，它永远不应该发生！这就是所谓的*Oops*；作为处理这个问题的一部分，将调用一个内部内核函数，通过`printk`将有用的诊断信息转储到内存中的内核日志缓冲区，以及控制台设备（在生产系统上，它也可能被定向到其他地方，以便以后可以检索和调查；例如，通过内核的*kdump*机制）。

让我们引入一个模块参数，控制我们是否（故意）导致*Oops*发生或不发生：

```
// ch2/debugfs_simple_intf/debugfs_simple_intf.c
[...]
/* Module parameters */
static int cause_an_oops;
module_param(cause_an_oops, int, 0644);
MODULE_PARM_DESC(cause_an_oops,
"Setting this to 1 can cause a kernel bug, an Oops; if 1, we do NOT perform required cleanup! so, after removal, any op on the debugfs files will cause an Oops! (default is 0, no bug)");
```

在我们的驱动程序的清理代码路径中，我们检查`cause_an_oops`变量是否非零，并故意*不*（递归地）删除我们的 debugfs 文件，从而设置 bug：

```
static void debugfs_simple_intf_cleanup(void)
{
        kfree(gdrvctx);
        if (!cause_an_oops)
 debugfs_remove_recursive(gparent);
        pr_info("%s removed\n", OURMODNAME);
}
```

当我们“正常”使用`insmod(8)`时，默认情况下，可怕的`cause_an_oops`模块参数为`0`，从而确保一切正常工作。但让我们冒险一下！我们正在构建内核模块，当我们插入它时，我们必须传递参数并将其设置为`1`（请注意，这里我们在我们的自定义`5.4.0-llkd01`内核上的 x86_64 Ubuntu 18.04 LTS 客户系统上以*root*身份运行）：

```
# id
uid=0(root) gid=0(root) groups=0(root)
# insmod ./debugfs_simple_intf.ko cause_an_oops=1
# cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_debug_level
0
# dmesg 
[ 2061.048140] dbgfs_simple_intf: allocated and init the driver context structure
[ 2061.050690] dbgfs_simple_intf: debugfs file 1 <debugfs_mountpt>/dbgfs_simple_intf/llkd_dbgfs_show_drvctx created
[ 2061.053638] dbgfs_simple_intf: debugfs file 2 <debugfs_mountpt>/dbgfs_simple_intf/llkd_dbgfs_debug_level created
[ 2061.057089] dbgfs_simple_intf initialized (fyi, our 'cause an Oops' setting is currently On)
# 
```

现在，让我们移除内核模块 - 在内部，用于清理（递归删除）我们的 debugfs 文件的代码不会运行。在这里，我们实际上是通过尝试读取我们的 debugfs 文件来触发内核 bug，*Oops*：

```
# rmmod debugfs_simple_intf
# cat /sys/kernel/debug/dbgfs_simple_intf/llkd_dbgfs_debug_level 
Killed
```

控制台上的`Killed`消息是不祥的！这是一个暗示，表明出了（严重的）问题。查看内核日志确认我们确实遇到了*Oops*！以下（部分裁剪的）屏幕截图显示了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/1b9849ec-98d3-4fa8-a772-87b4d6fa656b.png)

图 2.4 - 内核 Oops 的部分屏幕截图，内核级 bug

由于提供的内核调试详细信息超出了本书的范围，我们将不在此深入讨论。尽管如此，了解一点是相当直观的。仔细看前面的屏幕截图：在`BUG:`语句中，您可以看到导致 bug 的**内核虚拟地址**（**kva**），称为 Oops（我们在配套指南*Linux 内核编程-第七章，内存管理内部基础知识*中介绍了 kva 空间；这对于驱动程序作者来说是非常关键的信息）：

```
CPU: 1 PID: 4673 Comm: cat Tainted: G OE 5.4.0-llkd01 #2
```

这显示了 CPU（`1`）上正在运行的进程上下文（`cat`），被污染的标志和内核版本。输出中真正关键的一部分是：

```
RIP: 0010:debugfs_u32_get+0x5/0x20
```

这告诉你 CPU 指令指针（x86_64 上名为 RIP 的寄存器）在`debugfs_u32_get()`函数中，距离函数的机器码开始处的偏移量为`0x5`字节（此外，内核还计算出函数的长度为`0x20`字节）！

将这些信息与`objdump(1)`和`addr2line(1)`等强大工具结合使用，可以帮助准确定位代码中的 bug 的位置！

CPU 寄存器被转储；更好的是，*调用跟踪*或*调用堆栈* - 进程上下文的*内核模式堆栈的内容*（请参阅*Linux 内核编程*，*第六章*，*内核内部基础知识，进程和线程*，了解有关内核堆栈的详细信息）- 显示了导致此时刻的代码；也就是说，崩溃（从下到上读取堆栈跟踪）。另一个快速提示：如果调用跟踪输出中的内核函数前面有一个`?`符号，只需忽略它（这可能是之前留下的“闪烁”）。

实际上，生产系统上的内核 bug *必须* 导致整个系统恐慌（停机）。在非生产系统上（就像我们正在运行的那样），可能会发生内核恐慌，也可能不会；在这里，没有。尽管如此，内核 bug 必须以最高级别的严重性对待，它确实是一个停机故障，必须修复。大多数发行版将 procfs 文件`/proc/sys/kernel/panic_on_oops`设置为`0`，但在生产系统上，它通常会设置为值`1`。

这里的道义很明显：debugfs 没有自动清理；我们必须自己清理。好了，让我们通过查找内核中的一些实际使用情况来结束对 debugfs 的讨论。

## Debugfs - 实际用户

正如我们之前提到的，debugfs API 有几个“真实世界”的用户；我们能找到其中一些吗？好吧，有一种方法：只需在内核源树的`drivers/`目录下搜索名为`*debugfs*.c`的文件；您可能会感到惊讶（我在 5.4.0 内核树中找到了 114 个这样的文件！）。让我们看看其中的一些：

```
$ cd <kernel-source-tree> ; find drivers/ -iname "*debugfs*.c" 
drivers/block/drbd/drbd_debugfs.c
drivers/mmc/core/debugfs.c
drivers/platform/x86/intel_telemetry_debugfs.c
[...]
drivers/infiniband/hw/qib/qib_debugfs.c
drivers/infiniband/hw/hfi1/debugfs.c
[...]
drivers/media/usb/uvc/uvc_debugfs.c
drivers/acpi/debugfs.c
drivers/net/wireless/mediatek/mt76/debugfs.c
[...]
drivers/net/wireless/intel/iwlwifi/mvm/debugfs-vif.c
drivers/net/wimax/i2400m/debugfs.c
drivers/net/ethernet/broadcom/bnxt/bnxt_debugfs.c
drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c
drivers/net/ethernet/mellanox/mlx5/core/debugfs.c
[...]
drivers/misc/genwqe/card_debugfs.c
drivers/misc/mei/debugfs.c
drivers/misc/cxl/debugfs.c
[...]
drivers/usb/mtu3/mtu3_debugfs.c
drivers/sh/intc/virq-debugfs.c
drivers/soundwire/debugfs.c
[...]
drivers/crypto/ccree/cc_debugfs.c
```

看看（其中一些）它们；它们的代码公开了 debugfs 接口。这并不总是为了纯粹的调试目的；许多 debugfs 文件用于实际生产用途！例如，MMC 驱动程序包含以下代码行，该代码行使用 debugfs“辅助”API 获取 x32 全局变量：

```
drivers/mmc/core/debugfs.c:mmc_add_card_debugfs():
debugfs_create_x32("state", S_IRUSR, root, &card->state);
```

这将创建一个名为`state`的 debugfs 文件，当读取时，会显示卡的“状态”。

好的，这完成了我们如何通过强大的 debugfs 框架与用户空间进行接口的覆盖。我们的演示 debugfs 驱动程序创建了一个 debugfs 目录和其中的两个 debugfs 伪文件；然后您学会了如何为它们设置和使用读取和写入回调处理程序。像`debugfs_create_u32()`这样的“快捷”API 也很强大。不仅如此，我们甚至设法生成了一个内核错误 - 一个 Oops！现在，让我们学习如何通过一种特殊类型的套接字进行通信，称为 netlink 套接字。

# 通过 netlink 套接字进行接口

在这里，您将学习如何使用一个熟悉且无处不在的网络抽象 - 套接字，来进行内核和用户空间的接口！熟悉网络应用程序编程的程序员对其优势赞不绝口。

熟悉使用 C/C++和套接字 API 的网络编程在这里有所帮助。请参阅*进一步阅读*部分，了解有关此主题的一些好教程。

## 使用套接字的优势

除其他外，套接字技术为我们提供了几个优势（相对于其他典型的用户模式 IPC 机制，如管道，SysV IPC/POSIX IPC 机制（消息队列，共享内存，信号量等）），如下：

+   双向同时数据传输（全双工）。

+   在互联网上是无损的，至少在某些传输层协议（如 TCP）上，当然，在本地主机上也是如此，这在这里是适用的。

+   高速数据传输，尤其是在本地主机上！

+   流量控制语义始终有效。

+   异步通信；消息可以排队，因此发送方不必等待接收方。

+   特别是关于我们的主题，在其他用户<->内核通信路径（如 procfs，sysfs，debugfs 和 ioctl）中，用户空间应用程序必须启动到内核空间的传输；使用 netlink 套接字，*内核可以启动传输*。

+   此外，到目前为止我们所见过的所有其他机制（procfs，sysfs 和 debugfs），散布在整个文件系统中的各种接口文件可能会导致内核命名空间污染；使用 netlink 套接字（顺便说一句，使用 ioctl 也是如此），情况并非如此，因为没有文件。

这些优势可能有所帮助，具体取决于您正在开发的产品类型。现在，让我们了解一下 netlink 套接字是什么。

## 理解什么是 netlink 套接字

那么，netlink 套接字是什么？我们将保持简单 - *netlink 套接字*是一个仅存在于 Linux OS 自 2.2 版本以来的“特殊”套接字系列。使用它，您可以在用户模式进程（或线程）和内核中的组件之间建立**进程间通信**（**IPC**）；在我们的情况下，通常是一个驱动程序的内核模块。

在许多方面类似于 UNIX 域数据报套接字；它是用于*本地主机* *仅*通信，而不是跨系统。虽然 UNIX 域套接字使用路径名作为它们的命名空间（一个特殊的“套接字”文件），netlink 套接字使用 PID。从学究的角度来看，这是一个端口 ID 而不是进程 ID，尽管实际上，进程 ID 经常被用作命名空间。现代内核核心（除了驱动程序）在许多情况下使用 netlink 套接字 - 例如，iproute2 网络实用程序使用它来配置无线驱动程序。另一个有趣的例子是，udev 功能使用 netlink 套接字在内核 udev 实现和用户空间守护进程（udevd 或 systemd-udevd）之间进行通信，用于设备发现、设备节点供应等等。

在这里，我们将设计和实现一个简单的用户<->内核消息演示，使用 netlink 套接字。为此，我们将不得不编写两个程序（至少）——一个作为用户空间应用程序，发出基于套接字的系统调用，另一个作为内核空间组件（这里是内核模块）。我们将让用户空间进程向内核模块发送一个“消息”；内核模块应该接收并打印它（到内核日志缓冲区）。然后内核模块将回复给用户空间进程，该进程正阻塞在这个事件上。

因此，不再拖延，让我们开始编写一些使用 netlink 套接字的代码；我们将从用户空间应用程序开始。继续阅读！

## 编写用户空间 netlink 套接字应用程序

按照以下步骤运行*用户空间*应用程序：

1.  我们必须做的第一件事就是获得一个*套接字*。传统上，套接字被定义为通信的端点；因此，一对套接字形成一个连接。我们将使用`socket(2)`系统调用来执行此操作。它的签名是

`int socket(int domain, int type, int protocol);`。

不详细讨论，这是我们要做的：

+   +   我们将`domain`指定为特殊的`PF_NETLINK`家族的一部分，因此请求一个 netlink 套接字。

+   使用原始套接字将`type`设置为`SOCK_RAW`（有效地跳过传输层）。

+   `protocol`是要使用的协议。由于我们使用原始套接字，协议留待我们或内核实现；让内核 netlink 代码执行这一点是正确的方法。在这里，我们使用一个未使用的协议号；即`31`。

1.  下一步是通过通常的`bind(2)`系统调用语义绑定套接字。首先，我们必须为此目的初始化一个 netlink 源`socketaddr`结构（在其中我们指定家族为 netlink，PID 值为调用进程的 PID（仅用于单播））。以下代码是前面提到的前两个步骤（为了清晰起见，我们不会在这里显示错误检查代码）：

```
// ch2/netlink_simple_intf/userapp_netlink/netlink_userapp.c
#define NETLINK_MY_UNIT_PROTO        31
    // kernel netlink protocol # (registered by our kernel module)
#define NLSPACE 1024

[...] 
 /* 1\. Get ourselves an endpoint - a netlink socket! */
sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MY_UNIT_PROTO);
printf("%s:PID %d: netlink socket created\n", argv[0], getpid());

/* 2\. Setup the netlink source addr structure and bind it */
memset(&src_nl, 0, sizeof(src_nl));
src_nl.nl_family = AF_NETLINK;
/* Note carefully: nl_pid is NOT necessarily the PID of the sender process; it's actually 'port id' and can be any unique number */
src_nl.nl_pid = getpid();
src_nl.nl_groups = 0x0; // no multicast
bind(sd, (struct sockaddr *)&src_nl, sizeof(src_nl))
```

1.  接下来，我们必须初始化一个 netlink“目标地址”结构。在这里，我们将 PID 成员设置为`0`，这是一个特殊值，表示目标是内核：

```
/* 3\. Setup the netlink destination addr structure */
memset(&dest_nl, 0, sizeof(dest_nl));
dest_nl.nl_family = AF_NETLINK;
dest_nl.nl_groups = 0x0; // no multicast
dest_nl.nl_pid = 0;      // destined for the kernel
```

1.  接下来，我们必须分配和初始化一个 netlink“头”数据结构。除其他事项外，它指定了源 PID 和重要的是我们将传递给内核组件的数据“有效载荷”。在这里，我们正在使用辅助宏，如`NLMSG_DATA()`来指定 netlink 头结构内的正确数据位置：

```
/* 4\. Allocate and setup the netlink header (including the payload) */
nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(NLSPACE));
memset(nlhdr, 0, NLMSG_SPACE(NLSPACE));
nlhdr->nlmsg_len = NLMSG_SPACE(NLSPACE);
nlhdr->nlmsg_pid = getpid();
/* Setup the payload to transmit */
strncpy(NLMSG_DATA(nlhdr), thedata, strlen(thedata)+1);
```

1.  接下来，必须初始化一个`iovec`结构以引用 netlink 头，并初始化一个`msghdr`数据结构以指向目标地址和`iovec`：

```
/* 5\. Setup the iovec and ... */
memset(&iov, 0, sizeof(struct iovec));
iov.iov_base = (void *)nlhdr;
iov.iov_len = nlhdr->nlmsg_len;
[...]
/* ... now setup the message header structure */
memset(&msg, 0, sizeof(struct msghdr));
msg.msg_name = (void *)&dest_nl;   // dest addr
msg.msg_namelen = sizeof(dest_nl); // size of dest addr
msg.msg_iov = &iov;
msg.msg_iovlen = 1; // # elements in msg_iov
```

1.  最后，消息通过`sendmsg(2)`系统调用发送（传输）（它接受套接字描述符和前面提到的`msghdr`结构作为参数）：

```
/* 6\. Actually (finally!) send the message via sendmsg(2) */
nsent = sendmsg(sd, &msg, 0);
```

1.  内核组件——一个内核模块，我们将很快讨论——现在应该通过其 netlink 套接字接收消息并显示消息的内容；我们安排它然后礼貌地回复。为了抓取回复，我们的用户空间应用现在必须在套接字上执行阻塞读取：

```
/* 7\. Block on incoming msg from the kernel-space netlink component */
printf("%s: now blocking on kernel netlink msg via recvmsg() ...\n", argv[0]);
nrecv = recvmsg(sd, &msg, 0);
```

我们必须使用`recvmsg(2)`系统调用来执行此操作。当它被解除阻塞时，它说明消息已被接收。

为什么数据结构需要这么多的抽象和封装？嗯，这通常是事物演变的方式——`msghdr`结构被创建是为了让`sendmsg(2)`API 使用更少的参数。但这意味着参数必须放在某个地方；它们深深地嵌入在`msghdr`中，指向目标地址和`iovec`，`iovec`的`base`成员指向 netlink 头结构，其中包含有效载荷！哇。

作为一个实验，如果我们过早地构建和运行用户模式 netlink 应用程序，*没有*内核端的代码，会发生什么？当然会失败...但是具体是如何失败的呢？好吧，采用经验主义的方法。通过尝试使用受人尊敬的`strace(1)`实用程序，我们可以看到`socket(2)`系统调用返回失败，原因是`协议不受支持`：

```
$ strace -e trace=network ./netlink_userapp
socket(AF_NETLINK, SOCK_RAW, 0x1f /* NETLINK_??? */) = -1 EPROTONOSUPPORT (Protocol not supported)
netlink_u: netlink socket creation failed: Protocol not supported
+++ exited with 1 +++
$
```

这是正确的；内核中还没有`协议号 31`（`31` = `0x1f`，我们正在使用的协议号）！我们还没有做到这一点。所以，这是用户空间的情况。现在，让我们完成拼图，让它真正起作用！我们将通过查看内核组件（模块/驱动程序）的编写方式来完成这一点。

## 将内核空间 netlink 套接字代码编写为内核模块

内核为 netlink 提供了基础架构，包括 API 和数据结构；所有所需的都已导出，因此作为模块作者，这些都对您可用。我们使用其中的几个；编程内核 netlink 组件（我们的内核模块）的步骤在这里概述：

1.  就像用户空间应用程序一样，我们必须首先获取 netlink 套接字。内核 API 是`netlink_kernel_create()`，其签名如下：

```
struct sock * netlink_kernel_create(struct net *, int , struct netlink_kernel_cfg *);
```

第一个参数是一个通用网络结构；我们在这里传递内核现有和有效的`init_net`结构。第二个参数是要使用的*协议号（单位）*；我们将指定与用户空间应用程序相同的数字（`31`）。第三个参数是指向（可选）netlink 配置结构的指针；在这里，我们只将输入成员设置为我们的函数的空值。当用户空间进程（或线程）向内核 netlink 组件提供任何输入（即传输某些内容）时，将调用此函数。因此，在我们的内核模块的`init`例程中，我们有以下内容：

```
// ch2/netlink_simple_intf/kernelspace_netlink/netlink_simple_intf.c
#define OURMODNAME               "netlink_simple_intf"
#define NETLINK_MY_UNIT_PROTO    31 
    // kernel netlink protocol # that we're registering
static struct sock *nlsock;
[...]
static struct netlink_kernel_cfg nl_kernel_cfg = { 
    .input = netlink_recv_and_reply,
};
[...]
nlsock = netlink_kernel_create(&init_net, NETLINK_MY_UNIT_PROTO,
            &nl_kernel_cfg);
```

1.  正如我们之前提到的，当用户空间进程（或线程）向我们的内核（netlink）模块或驱动程序提供任何输入（即传输某些内容）时，将调用回调函数。重要的是要理解它在进程上下文中运行，而不是任何一种中断上下文；我们使用我们的`convenient.h:PRINT_CTX()`宏来验证这一点（我们将在第四章中介绍这一点，*处理硬件中断*，在*完全弄清上下文*部分）。在这里，我们只是显示接收到的消息，然后通过向我们的用户空间对等进程发送一个示例消息来进行回复。从传递给我们的回调函数的套接字缓冲结构中检索到的来自我们的用户空间对等进程的数据有效载荷可以从其中的 netlink 头结构中检索到。您可以在这里看到如何检索数据和发送者 PID：

```
static void netlink_recv_and_reply(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_tx;
    char *reply = "Reply from kernel netlink";
    int pid, msgsz, stat;

    /* Find that this code runs in process context, the process
     * (or thread) being the one that issued the sendmsg(2) */
    PRINT_CTX();

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /*pid of sending process */
    pr_info("%s: received from PID %d:\n"
        "\"%s\"\n", OURMODNAME, pid, (char *)NLMSG_DATA(nlh));
```

*套接字缓冲*数据结构 - `struct sk_buff` - 被认为是 Linux 内核网络协议栈中的关键数据结构。它包含有关网络数据包的所有元数据，包括对它的动态指针。它必须快速分配和释放（特别是当网络代码在中断上下文中运行时）；这确实是可能的，因为它在内核的 slab（SLUB）缓存上（有关内核 slab 分配器的详细信息，请参见配套指南*Linux 内核编程*，*第七章*，*内存管理内部 - 基础知识*，*第八章*，*模块作者的内核内存分配 - 第一部分*，以及*第九章*，*模块作者的内核内存分配 - 第二部分*）。

现在，我们需要了解，我们可以通过首先取消引用传递给我们的回调例程的套接字缓冲（`skb`）结构的`data`成员来检索网络数据包的有效载荷！接下来，这个`data`成员实际上是由我们的用户空间对等方设置的 netlink 消息头结构的指针。然后，我们取消引用它以获取实际的有效载荷。

1.  现在我们想要“回复”我们的用户空间对等进程；这涉及执行一些操作。首先，我们必须使用`nlmsg_new()` API 分配一个新的 netlink 消息，这实际上是对`alloc_skb()`的一个薄包装，通过`nlmsg_put()` API 将 netlink 消息添加到刚分配的套接字缓冲区中，然后使用适当的宏（`nlmsg_data()`）将数据（有效载荷）复制到 netlink 头中：

```
    //--- Let's be polite and reply
    msgsz = strlen(reply);
    skb_tx = nlmsg_new(msgsz, 0);
    [...]
    // Setup the payload
    nlh = nlmsg_put(skb_tx, 0, 0, NLMSG_DONE, msgsz, 0);
    NETLINK_CB(skb_tx).dst_group = 0; /* unicast only (cb is the
        * skb's control buffer), dest group 0 => unicast */
    strncpy(nlmsg_data(nlh), reply, msgsz);
```

1.  我们通过`nlmsg_unicast()` API 将回复发送给我们的用户空间对等进程（甚至可以进行 netlink 消息的多播）：

```
    // Send it
    stat = nlmsg_unicast(nlsock, skb_tx, pid);
```

1.  这只留下了清理工作（当内核模块被移除时调用）；`netlink_kernel_release()` API 实际上是`netlink_kernel_create()`的反向操作，它清理 netlink 套接字，关闭它：

```
static void __exit netlink_simple_intf_exit(void)
{
    netlink_kernel_release(nlsock);
    pr_info("%s: removed\n", OURMODNAME);
}
```

现在我们已经编写了用户空间应用程序和内核模块，以通过 netlink 套接字进行接口，让我们实际尝试一下！

## 尝试我们的 netlink 接口项目

是时候验证一切是否如广告所述。让我们开始吧：

1.  首先，构建并将内核模块插入内核内存：

我们的`lkm`便利脚本可以轻松完成这项工作；这个会话是在我们熟悉的 x86_64 客户端 VM 上进行的，运行的是 Ubuntu 18.04 LTS 和自定义的 5.4.0 Linux 内核。

```
$ cd <booksrc>/ch2/netlink_simple_intf/kernelspace_netlink $ ../../../lkm netlink_simple_intf
Version info:
Distro:     Ubuntu 18.04.4 LTS
Kernel: 5.4.0-llkd01
[...]
make || exit 1
[...] Building for: KREL=5.4.0-llkd01 ARCH=x86 CROSS_COMPILE= EXTRA_CFLAGS= -DDEBUG
  CC [M]  /home/llkd/booksrc/ch13/netlink_simple_intf/kernelspace_netlink/netlink_simple_intf.o
[...]
sudo insmod ./netlink_simple_intf.ko && lsmod|grep netlink_simple_intf
------------------------------
netlink_simple_intf    16384  0
[...]
[58155.082713] netlink_simple_intf: creating kernel netlink socket
[58155.084445] netlink_simple_intf: inserted
$ 
```

1.  有了这些，它已经加载并准备好了。接下来，我们将构建并尝试我们的用户空间应用程序：

```
$ cd ../userapp_netlink/
$ make netlink_userapp
[...] 
```

这导致了以下输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog-pt2/img/ce358d89-c70a-4d5b-8804-df86245ce2b1.png)

图 2.5 - 屏幕截图显示用户<->内核通过我们的示例 netlink 套接字代码进行通信

它起作用了；内核 netlink 模块接收并显示了从用户空间进程（`PID 7813`）发送给它的消息。然后内核模块以自己的消息回复给它的用户空间对等体，成功接收并显示它（通过`printf()`）。你也试试看。完成后，不要忘记使用`sudo rmmod netlink_simple_intf`删除内核模块。

另外：内核中存在一个连接器驱动程序。它的目的是简化基于 netlink 的通信的开发，使内核和用户空间开发人员都能更简单地设置和使用基于 netlink 的通信接口。我们不会在这里深入讨论；请参考内核中的文档（[`elixir.bootlin.com/linux/v5.4/source/Documentation/driver-api/connector.rst`](https://elixir.bootlin.com/linux/v5.4/source/Documentation/driver-api/connector.rst)）。内核源树中还提供了一些示例代码（在`samples/connector`中）。

有了这些，您已经学会了如何通过强大的 netlink 套接字机制在用户模式应用程序和内核组件之间进行接口。正如我们之前提到的，它在内核树中有几个实际用例。现在，让我们继续并涵盖另一种用户-内核接口方法，通过流行的`ioctl(2)`系统调用。

# 通过 ioctl 系统调用进行接口

**ioctl**是一个系统调用；为什么有个滑稽的名字*ioctl*？它是**输入输出控制**的缩写。虽然读取和写入系统调用（以及其他调用）用于有效地从设备（或文件；记住 UNIX 范式*如果不是进程，就是文件！*）传输*数据*，但*ioctl*系统调用用于向设备（通过其驱动程序）*发出* *命令*。例如，更改控制台设备的终端特性，格式化时向磁盘写入轨道，向步进电机发送控制命令，控制摄像头或音频设备等，都是发送命令给设备的实例。

让我们考虑一个虚构的例子。我们有一个设备，并为其开发了一个（字符）设备驱动程序。该设备有各种*寄存器*，通常是设备上的小型硬件内存，例如 8 位、16 位或 32 位 - 其中一些是控制寄存器。通过适当地对它们进行 I/O（读取和写入），我们控制设备（好吧，这确实是整个重点，不是吗；有关使用硬件内存和设备寄存器的详细工作细节将在下一章中介绍）。那么，作为驱动程序作者，您将如何与希望在此设备上执行各种控制操作的用户空间程序进行通信或接口？我们通常会设计用户空间 C（或 C++）程序，通过对设备文件执行`open(2)`来打开设备，并随后发出读取和写入系统调用。

但正如我们刚才提到的，当*传输* *数据*时，`read(2)`和`write(2)`系统调用 API 是适当的，而在这里，我们打算执行**控制操作**。那么，我们需要另一个系统调用来执行这样的操作...我们是否需要创建和编码一个新的系统调用（或多个系统调用）？不，比那简单得多：我们通过*ioctl 系统调用进行多路复用*，利用它来执行我们设备上需要的任何控制操作！如何做到？啊，回想一下上一章中至关重要的`file_operations`（fops）数据结构；我们现在将初始化另一个成员，`.ioctl`，为我们的 ioctl 方法函数，从而允许我们的设备驱动程序挂接到这个系统调用：

```
static struct file_operations ioct_intf_fops = { 
    .llseek = no_llseek,
    .ioctl = ioct_intf_ioctl,
    [...]
};
```

现实情况是，我们必须弄清楚在 Linux 内核版本 2.6.36 或更高版本上运行模块时，我们应该使用`ioctl`还是`file_operations`结构的`unlocked_ioctl`成员；接下来会更多地介绍这个问题。

实际上，向内核添加新的系统调用并不是一件轻松的事情！内核开发人员并不会随意添加系统调用 - 毕竟这是一个安全敏感的接口。有关此更多信息请参阅：[`www.kernel.org/doc/html/latest/kernel-hacking/hacking.html#ioctls-not-writing-a-new-system-call`](https://www.kernel.org/doc/html/latest/kernel-hacking/hacking.html#ioctls-not-writing-a-new-system-call)。

接下来会更多地介绍使用 ioctl 进行接口。

## 在用户空间和内核空间中使用 ioctl

`ioctl(2)`系统调用的签名如下：

```
#include <sys/ioctl.h>
int ioctl(int fd, unsigned long request, ...);
```

参数列表是*可变参数*。现实和通常情况下，我们传递两个或三个参数：

+   第一个参数很明显 - 打开的设备文件的文件描述符（在我们的情况下）。

+   第二个参数称为`request`，这是有趣的：它是要传递给驱动程序的命令。实际上，它是一个*编码*，封装了所谓的 ioctl 魔术数：一个数字和一个类型（读/写）。

+   （可选的）第三个参数，通常称为`arg`，也是一个`unsigned long`数量；我们使用它来以通常的方式传递一些数据给底层驱动程序，或者经常通过传递它的（虚拟）地址并让内核写入它来将数据返回给用户空间，利用 C 语言的所谓**值-结果**或**输入-输出**参数样式。

现在，正确使用 ioctl 并不像许多其他 API 那样简单。想一想：您很容易会遇到这样的情况，即几个用户空间应用程序正在向其底层设备驱动程序发出`ioctl(2)`系统调用（发出各种命令）。一个问题变得明显：内核 VFS 层如何将 ioctl 请求定向到正确的驱动程序？ioctl 通常在具有唯一*(major, minor)*号码的字符设备文件上执行；因此，另一个驱动程序如何接收您的 ioctl 命令（除非您故意、可能恶意地设置设备文件）？

然而，存在一个协议来实现对 ioctl 的安全和正确使用；每个应用程序和驱动程序都定义一个魔术数字，该数字将被编码到其所有 ioctl 请求中。首先，驱动程序将验证其接收到的每个 ioctl 请求是否包含*它的*魔术数字；只有在这种情况下，它才会继续处理；否则，它将简单地丢弃它。当然，这引出了对*ABI*的需求 - 我们需要为每个“注册”的驱动程序分配唯一的魔术数字（它可以是一个范围）。由于这创建了一个 ABI，内核文档将是相同的；您可以在这里找到有关谁在使用哪个魔术数字（或代码）的详细信息：[`www.kernel.org/doc/Documentation/ioctl/ioctl-number.txt`](https://www.kernel.org/doc/Documentation/ioctl/ioctl-number.txt)。

接下来，对底层驱动程序的 ioctl 请求基本上可以是四种情况之一：向设备“写入”命令，从设备“读取”（或查询）命令，执行读/写传输的命令，或者什么都不是的命令。这些信息（再次）通过定义某些位来*编码*到请求中：为了使这项工作更容易，我们有四个辅助宏，允许我们构造 ioctl 命令：

+   `_IO(type,nr)`: 编码一个没有参数的 ioctl 命令

+   `_IO**R**(type,nr,datatype)`: 编码一个用于从内核/驱动程序读取数据的 ioctl 命令

+   `_IO**W**(type,nr,datatype)`: 编码一个用于向内核/驱动程序写入数据的 ioctl 命令

+   `_IO**WR**(type,nr,datatype)`: 编码一个用于读/写传输的 ioctl 命令

这些宏在用户空间的`<sys/ioctl.h>`头文件中定义，在内核中位于`include/uapi/asm-generic/ioctl.h`。典型（并且相当明显的）最佳实践是创建一个*公共头*文件，定义应用程序/驱动程序的 ioctl 命令，并在用户模式应用程序和设备驱动程序中包含该文件。

在这里，作为演示，我们将设计并实现一个用户空间应用程序和一个内核空间设备驱动程序，以驱动一个通过`ioctl(2)`系统调用进行通信的虚构设备。因此，我们必须定义一些通过*ioctl*接口发出的命令。我们将在一个公共头文件中完成这个工作，如下所示：

```
// ch2/ioctl_intf/ioctl_llkd.h

/* The 'magic' number for our driver; see Documentation/ioctl/ioctl-number.rst 
 * Of course, we don't know for _sure_ if the magic # we choose here this
 * will remain free; it really doesn't matter, this is just for demo purposes;
 * don't try and upstream this without further investigation :-)
 */
#define IOCTL_LLKD_MAGIC        0xA8

#define IOCTL_LLKD_MAXIOCTL        3
/* our dummy ioctl (IOC) RESET command */
#define IOCTL_LLKD_IOCRESET     _IO(IOCTL_LLKD_MAGIC, 0)
/* our dummy ioctl (IOC) Query POWER command */
#define IOCTL_LLKD_IOCQPOWER    _IOR(IOCTL_LLKD_MAGIC, 1, int)
/* our dummy ioctl (IOC) Set POWER command */
#define IOCTL_LLKD_IOCSPOWER    _IOW(IOCTL_LLKD_MAGIC, 2, int)
```

我们必须尽量使宏中使用的名称有意义。我们的三个命令（用粗体标出）都以`IOCTL_LLKD_`为前缀，表明它们都是我们虚构的`LLKD`项目的 ioctl 命令；接下来，它们以`IOC{Q|S}`为后缀，其中`IOC`表示它是一个 ioctl 命令，`Q`表示它是一个查询操作，`S`表示它是一个设置操作。

现在，让我们从用户空间和内核空间（驱动程序）的代码级别学习如何设置事物。

### 用户空间 - 使用 ioctl 系统调用

`ioctl(2)`系统调用的*用户空间*签名如下：

```
#include <sys/ioctl.h>
int ioctl(int fd, unsigned long request, ...);
```

在这里，我们可以看到它接受一个可变参数列表；ioctl 的参数如下：

+   **第一个参数**：文件或设备的文件描述符（在我们的情况下）执行 ioctl 操作（我们通过在设备文件上执行*open*来获得`fd`）。

+   **第二个参数**：发出给底层设备驱动程序（或文件系统或任何`fd`代表的东西）的请求或命令。

+   **可选的第三（或更多）个参数**：通常，第三个参数是一个整数（或指向整数或数据结构的指针）；我们使用这种方法来在发出*设置*类型的命令时向驱动程序传递一些额外信息，或者通过众所周知的*传引用* C 范式从驱动程序中检索一些信息，其中我们传递指针并让驱动程序“poke”它，从而将参数视为实际上是一个返回值。

实际上，ioctl 经常被用作*通用*系统调用。使用 ioctl 在硬件和软件上执行命令操作的情况几乎令人尴尬地多！请参阅内核文档（`Documentation/ioctl/<...>`）以查看许多实际的真实世界示例。例如，您将在这里找到有关谁在 ioctl 中使用哪个魔术数字（或代码）的详细信息：[`www.kernel.org/doc/Documentation/ioctl/ioctl-number.txt`](https://www.kernel.org/doc/Documentation/ioctl/ioctl-number.txt)。

（类似地，`ioctl_list(2)`手册页面显示了 x86 内核中 ioctl 调用的完整列表；尽管这些文档文件似乎相当古老。现在似乎在这里：[`github.com/torvalds/linux/tree/master/Documentation/userspace-api/ioctl`](https://github.com/torvalds/linux/tree/master/Documentation/userspace-api/ioctl)。）

让我们来看一些用户空间 C 应用程序的片段，特别是在发出`ioctl(2)`系统调用时（为了简洁和可读性，我们省略了错误检查代码；完整的代码可以在本书的 GitHub 存储库中找到）：

```
// ch2/ioctl_intf/user space_ioctl/ioctl_llkd_userspace.c
#include "../ioctl_llkd.h"
[...]
ioctl(fd, IOCTL_LLKD_IOCRESET, 0);   // 1\. reset the device
ioctl(fd, IOCTL_LLKD_IOCQPOWER, &power); // 2\. query the 'power status'

// 3\. Toggle it's power status
if (0 == power) {
        printf("%s: Device OFF, powering it On now ...\n", argv[0]);
        if (ioctl(fd, IOCTL_LLKD_IOCSPOWER, 1) == -1) { [...]
        printf("%s: power is ON now.\n", argv[0]);
    } else if (1 == power) {
        printf("%s: Device ON, powering it OFF in 3s ...\n", argv[0]);
        sleep(3); /* yes, careful here of sleep & signals! */
        if (ioctl(fd, IOCTL_LLKD_IOCSPOWER, 0) == -1) { [...]
        printf("%s: power OFF ok, exiting..\n", argv[0]);
    }
[...]
```

我们的驱动程序如何处理这些用户空间发出的 ioctls 呢？让我们找出来。

### 内核空间-使用 ioctl 系统调用

在前面的部分中，我们看到内核驱动程序将不得不初始化其`file_operations`结构以包括`ioctl`方法。不过，这还不是全部：Linux 内核不断发展；在早期的内核版本中，开发人员使用了非常粗粒度的锁，虽然它起作用，但严重影响了性能（我们将在第六章和第七章中详细讨论锁定）。它是如此糟糕以至于被称为**Big Kernel Lock**（**BKL**）！好消息是，到了内核版本 2.6.36，开发人员摆脱了这个臭名昭著的锁。不过，这样做也产生了一些副作用：其中之一是发送到内核中的 ioctl 方法的参数数量从旧方法中的四个变为了新方法中的三个，这个新方法被称为`unlocked_ioctl`。因此，对于我们的演示驱动程序，我们将在初始化驱动程序的`file_operations`结构时使用以下*ioctl*方法：

```
// ch2/ioctl_intf/kerneldrv_ioctl/ioctl_llkd_kdrv.c
#include "../ioctl_llkd.h"
#include <linux/version.h>
[...]
static struct file_operations ioctl_intf_fops = { 
    .llseek = no_llseek,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
    .unlocked_ioctl = ioctl_intf_ioctl, // use the 'unlocked' version
#else
    .ioctl = ioctl_intf_ioctl, // 'old' way
#endif
};
```

显然，由于它在 fops 驱动程序中定义，ioctl 被认为是一个私有驱动程序接口（`driver-private`）。此外，在驱动程序代码中的函数定义中也必须考虑到关于更新的“解锁”版本的同样事实；我们的驱动程序也这样做了：

```
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static long ioctl_intf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#else
static int ioctl_intf_ioctl(struct inode *ino, struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
[...]
```

这里的关键代码是驱动程序的 ioctl 方法。想想看：一旦基本的有效性检查完成，驱动程序实际上所做的就是对用户空间应用程序发出的所有可能的有效 ioctl 命令执行*switch-case*。让我们来看一下以下代码（为了可读性，我们将跳过`#if LINUX_VERSION_CODE >= ...`宏指令，只显示现代 ioctl 函数签名以及一些有效性检查；您可以在本书的 GitHub 存储库中查看完整的代码）：

```
static long ioctl_intf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    pr_debug("In ioctl method, cmd=%d\n", _IOC_NR(cmd));

    /* Verify stuff: is the ioctl's for us? etc.. */
    [...]

    switch (cmd) {
    case IOCTL_LLKD_IOCRESET:
        pr_debug("In ioctl cmd option: IOCTL_LLKD_IOCRESET\n");
        /* ... Insert the code here to write to a control register to reset  
           the device ... */
        break;
    case IOCTL_LLKD_IOCQPOWER:  /* Get: arg is pointer to result */
        pr_debug("In ioctl cmd option: IOCTL_LLKD_IOCQPOWER\n"
            "arg=0x%x (drv) power=%d\n", (unsigned int)arg, power);
        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;
        /* ... Insert the code here to read a status register to query the
         * power state of the device ... * here, imagine we've done that 
         * and placed it into a variable 'power'
         */
        retval = __put_user(power, (int __user *)arg);
        break;
    case IOCTL_LLKD_IOCSPOWER:  /* Set: arg is the value to set */
        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;
        power = arg;
        /* ... Insert the code here to write a control register to set the
         * power state of the device ... */
        pr_debug("In ioctl cmd option: IOCTL_LLKD_IOCSPOWER\n"
            "power=%d now.\n", power);
        break;
    default:
        return -ENOTTY;
    }
[...]
```

`_IOC_NR`宏用于从`cmd`参数中提取命令号。在这里，我们可以看到驱动程序对通过用户空间进程发出的`ioctl`的三种有效情况做出了“反应”：

+   在接收到`IOCTL_LLKD_IOC**RESET**`命令时，它执行设备复位。

+   在接收到`IOCTL_LLKD_IOC**Q**POWER`命令时，它查询（`Q`表示查询）并返回当前的电源状态（通过将其值插入到第三个参数`arg`中，使用*value-result* C 编程方法）。

+   在接收到`IOCTL_LLKD_IOC**S**POWER`命令时，它设置（`S`表示设置）电源状态（设置为第三个参数`arg`中传递的值）。

当然，由于我们正在处理一个纯虚构的设备，我们的驱动程序实际上并不执行任何寄存器（或其他硬件）工作。这个驱动程序只是一个您可以利用的模板。

如果黑客试图发出我们的驱动程序不知道的命令（相当笨拙的黑客），会发生什么？好吧，初始的有效性检查会捕捉到它；即使他们没有，我们将在*ioctl*方法中命中`default`情况，导致驱动程序向用户空间返回`-ENOTTY`。这将通过 glibc“粘合”代码将用户空间进程（或线程的）`errno`值设置为`ENOTTY`，通知它 ioctl 方法无法提供服务。我们的用户空间`perror(3)` API 将显示`Inappropriate ioctl for device`错误消息。事实上，如果驱动程序没有*ioctl*方法（也就是说，如果`file_operations`结构中的 ioctl 成员设置为`NULL`），并且用户空间应用程序发出`ioctl`方法，就会发生这种情况。

我把这个用户空间/驱动程序项目示例留给你来尝试；为了方便起见，一旦加载了驱动程序（通过 insmod），您可以使用`ch2/userspace_ioctl/cr8devnode.sh`便捷脚本生成设备文件。设置好之后，运行用户空间应用程序；您会发现连续运行它会重复切换我们虚构设备的“电源状态”。

## ioctl 作为调试接口

正如我们在本章开头提到的，使用*ioctl*接口进行调试有什么问题？它可以用于这个目的。您可以随时在*switch-case*块中插入一个“debug”命令；它可以用于向用户空间应用程序提供有用的信息，例如驱动程序状态、关键变量的值（也包括健康监测）等。

不仅如此，除非明确向最终用户或客户记录，通过 ioctl 接口使用的精确命令是未知的；因此，您应该在提供足够的细节给其他团队或客户的同时记录接口。这带来了一个有趣的观点：您可能选择故意不记录某个 ioctl 命令；它现在是一个“隐藏”的命令，可以被现场工程师等人使用来检查设备。（我把这个任务留给你来完成。）

ioctl 的内核文档包括这个文件：[`www.kernel.org/doc/Documentation/ioctl/botching-up-ioctls.txt`](https://www.kernel.org/doc/Documentation/ioctl/botching-up-ioctls.txt)。虽然偏向于内核图形堆栈开发人员，但它描述了典型的设计错误、权衡和更多内容。

太棒了 - 你快完成了！您已经学会了如何通过各种技术将内核模块或驱动程序与用户模式进程或线程（在用户空间应用程序内）进行接口。我们从 procfs 开始，然后转向使用 sysfs 和 debugfs。netlink 套接字和 ioctl 系统调用完成了我们对这些接口方法的研究。

但是在所有这些选择中，项目中应该实际使用哪种？下一节将通过快速比较这些不同的接口方法来帮助您做出决定。

# 接口方法的比较 - 表格

在本节中，我们根据一些参数创建了一个快速比较表，列出了本章中描述的各种用户-内核接口方法：

| **参数/接口方法** | **procfs** | **sysfs** | **        debugfs** | **netlink socket** | **ioctl** |
| --- | --- | --- | --- | --- | --- |
| **开发的便利性** | 易于学习和使用。 | （相对）易于学习和使用。 | （非常）易于学习和使用。 | 更难；必须编写用户空间 C + 驱动程序代码 + 理解套接字 API。 | 公平/更难；必须编写用户空间 C + 驱动程序代码。 |
| **适用于什么用途** | 仅适用于核心内核（一些较旧的驱动程序可能仍在使用）；最好避免使用驱动程序。 | 设备驱动程序接口。 | 用于生产和调试目的的驱动程序（和其他）接口。 | 各种接口：用户包括设备驱动程序、核心网络代码、udev 系统等。 | 主要用于设备驱动程序接口（包括许多）。 |
| 接口可见性 | 对所有人可见；使用权限来控制访问。 | 对所有人可见；使用权限来控制访问。 | 对所有人可见；使用权限来控制访问。 | 从文件系统中隐藏；不会污染内核命名空间。 | 从文件系统中隐藏；不会污染内核命名空间。 |
| **驱动程序/模块作者的上游内核 ABI*** | 驱动程序中的使用已在主线中弃用。 | “正确的方式”；与用户空间接口驱动程序的正式接受方法。 | 在主线中得到很好的支持并被驱动程序和其他产品广泛使用。 | 得到很好的支持（自 2.2 版以来）。 | 得到很好的支持。 |
| **用于（驱动程序）调试目的** | 是的（尽管在主线中不应该）。 | 不是/不理想。 | 是的，非常有用！按设计“没有规则”。 | 不是/不理想。 | 是的；（甚至）通过隐藏命令。 |

* 正如我们之前提到的，内核社区文件 procfs、sysfs 和 debugfs 都是*ABI；它们的稳定性和寿命没有得到保证。虽然这是社区采纳的正式立场，但实际上使用这些文件系统的许多实际接口已成为现实世界中产品使用的事实接口。然而，我们应该遵循内核社区关于它们使用的“规则”和指南。

# 总结

在本章中，我们涵盖了设备驱动程序作者的一个重要方面-如何确切地*在用户和内核（驱动程序）空间之间进行接口*。我们向您介绍了几种接口方法；我们从一个较旧的接口开始，即通过古老的 proc 文件系统进行接口（然后提到了为什么这不是驱动程序作者首选的方法）。然后我们转向通过基于 2.6 的*sysfs*进行接口。这事实上是用户空间的*首选接口，至少对于设备驱动程序来说。然而，sysfs 有局限性（回想一下每个 sysfs 文件一个值的规则）。因此，使用完全自由格式的*debugfs*接口技术确实使编写调试（和其他）接口变得非常简单和强大。netlink 套接字是一种强大的接口技术，被网络子系统、udev 和一些驱动程序使用；尽管需要一些关于套接字编程和内核套接字缓冲区的知识。对于设备驱动程序进行通用命令操作，ioctl 系统调用是一个巨大的多路复用器，经常被设备驱动程序作者（和其他组件）用于与用户空间进行接口。

掌握了这些知识，您现在可以实际将您的驱动程序级代码与用户空间应用程序（或脚本）集成；通常，用户模式**图形用户界面**（**GUI**）将希望显示从内核或设备驱动程序接收到的一些值。您现在知道如何将这些值从内核空间设备驱动程序传递！

在下一章中，您将学习到一个典型的任务驱动程序作者必须执行的任务：与硬件芯片内存打交道！确保您对本章的内容清楚，完成提供的练习，查阅*进一步阅读*资源，然后深入下一章。到时见！

# 问题

1.  `sysfs_on_misc`：*sysfs 分配#1*：扩展我们在第一章中编写的一个`misc`设备驱动程序；设置两个 sysfs 文件及其读/写回调；从用户空间进行测试。

1.  `sysfs_addrxlate`：*sysfs 分配#2（稍微高级一点）*：*地址转换：*利用本章和*Linux 内核编程*书中获得的知识，*第七章，内存管理内部-基本知识*，*直接映射 RAM 和地址转换*部分，编写一个简单的平台驱动程序，提供两个名为`addrxlate_kva2pa`和`addrxlate_pa2kva`的 sysfs 接口文件。将 kva 写入 sysfs 文件`addrxlate_kva2pa`，驱动程序应读取并将*kva*转换为其对应的**物理地址**（**pa**）；然后，从同一文件中读取应导致显示*pa*。对`addrxlate_pa2kva` sysfs 文件执行相同操作。

1.  `dbgfs_disp_pgoff`：*debugfs 分配#1*：编写一个内核模块，在此处设置一个 debugfs 文件：`<debugfs_mount_point>/dbgfs_disp_pgoff`。在读取时，它应该显示（到用户空间）`PAGE_OFFSET`内核宏的当前值。

1.  `dbgfs_showall_threads`：*debugfs 分配#2*：编写一个内核模块，在此处设置一个 debugfs 文件：`<debugfs_mount_point>/dbgfs_showall_threads/dbgfs_showall_threads`。在读取时，它应该显示每个活动线程的一些属性。（这类似于我们在*Linux 内核编程*书中的代码：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/ch6/foreach/thrd_showall`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/ch6/foreach/thrd_showall)。请注意，线程仅在 insmod 时间显示*；*使用 debugfs 文件，您可以选择任何时间显示所有线程的信息）！

*建议的输出格式为 CSV 格式：*`TGID,PID,current,stack-start,name,#threads`。方括号中的`[name]`字段=>内核线程*;*

*`#threads`字段应该只显示一个正整数*；*这里没有输出意味着单线程进程；例如：`130,130,0xffff9f8b3cd38000,0xffffc13280420000,[watchdogd]`)

1.  *ioctl 分配#1*：使用提供的`ch2/ioctl_intf/`代码作为模板，编写一个用户空间 C 应用程序和一个内核空间（char）设备驱动程序，实现`ioctl`方法。添加一个名为`IOCTL_LLKD_IOCQPGOFF`的 ioctl 命令，以将`PAGE_OFFSET`（在内核中）的值返回给用户空间。

1.  `ioctl_undoc`：*ioctl 分配#2*：使用提供的`ch2/ioctl_intf/`代码作为模板，编写一个用户空间 C 应用程序和一个内核空间（char）设备驱动程序，实现`ioctl`方法。添加一个驱动程序上下文数据结构（我们在几个示例中使用了这些），然后分配和初始化它。现在，除了我们使用的三个以前的 ioctl 命令之外，还设置第四个未记录的命令（您可以称之为`IOCTL_LLKD_IOCQDRVSTAT`）。当通过`ioctl(2)`从用户空间查询时，它必须将驱动程序上下文数据结构的内容返回给用户空间；用户空间 C 应用程序必须打印出该结构的每个成员的当前内容。

您会发现一些问题的答案在书的 GitHub 存储库中：[`github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming-Part-2/tree/main/solutions_to_assgn)。

# 进一步阅读

您可以参考以下链接，了解本章涵盖的主题的更多信息。有关在 Linux 设备驱动程序中使用非常常见的 I2C 协议的更多信息，请访问以下链接：

+   有关 I2C 协议基础知识的文章：*如何在 STM32F103C8T6 中使用 I2C？STM32 I2C 教程*，2020 年 3 月：[`www.electronicshub.org/how-to-use-i2c-in-stm32f103c8t6/`](https://www.electronicshub.org/how-to-use-i2c-in-stm32f103c8t6/)

+   内核文档：实现 I2C 设备驱动程序：[`www.kernel.org/doc/html/latest/i2c/writing-clients.html`](https://www.kernel.org/doc/html/latest/i2c/writing-clients.html)
