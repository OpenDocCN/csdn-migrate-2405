# Linux 内核编程（二）

> 原文：[`zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7`](https://zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：编写您的第一个内核模块 - LKMs 第一部分

欢迎来到您学习 Linux 内核开发的基本方面-**可加载内核模块**（**LKM**）框架以及如何被*模块用户*或*模块作者*使用的旅程，他通常是内核或设备驱动程序员。这个主题相当广泛，因此分为两章-这一章和下一章。

在本章中，我们将首先快速了解 Linux 内核架构的基础知识，这将帮助我们理解 LKM 框架。然后，我们将探讨为什么内核模块有用，并编写我们自己的简单的*Hello, world* LKM，构建并运行它。我们将看到消息是如何写入内核日志的，并理解并利用 LKM Makefile。到本章结束时，您将已经学会了 Linux 内核架构和 LKM 框架的基础知识，并应用它来编写一个简单但完整的内核代码。

在本章中，我们涵盖了以下内容：

+   理解内核架构-第 I 部分

+   探索 LKMs

+   编写我们的第一个内核模块

+   内核模块的常见操作

+   理解内核日志和 printk

+   理解内核模块 Makefile 的基础知识

# 技术要求

如果您已经仔细遵循了第一章，*内核工作空间设置*，随后的技术先决条件已经得到了满足。（该章还提到了各种有用的开源工具和项目；我强烈建议您至少浏览一次。）为了您的方便，我们在这里总结了一些关键点。

要在 Linux 发行版（或自定义系统）上构建和使用内核模块，至少需要安装以下两个组件：

+   **工具链**：这包括编译器、汇编器、链接器/加载器、C 库和各种其他部分。如果为本地系统构建，正如我们现在假设的那样，那么任何现代 Linux 发行版都会预先安装本地工具链。如果没有，只需安装适用于您发行版的`gcc`软件包即可；在基于 Ubuntu 或 Debian 的 Linux 系统上，使用以下命令：

```
sudo apt install gcc
```

+   **内核头文件**：这些头文件将在编译过程中使用。实际上，您安装的软件包不仅安装内核头文件，还安装其他所需的部分（例如内核 Makefile）到系统上。再次强调，任何现代 Linux 发行版都应该预先安装内核头文件。如果没有（您可以使用`dpkg(1)`进行检查，如下所示），只需安装适用于您发行版的软件包；在基于 Ubuntu 或 Debian 的 Linux 系统上，使用以下命令：

```
$ sudo apt install linux-headers-generic $ dpkg -l | grep linux-headers | awk '{print $1, $2}'
ii linux-headers-5.3.0-28
ii linux-headers-5.3.0-28-generic
ii linux-headers-5.3.0-40
ii linux-headers-5.3.0-40-generic
ii linux-headers-generic-hwe-18.04
$ 
```

这里，使用`dpkg(1)`工具的第二个命令只是用来验证`linux-headers`软件包是否已经安装。

在某些发行版上，此软件包可能被命名为`kernel-headers-<ver#>`。此外，对于直接在树莓派上进行开发，安装名为`raspberrypi-kernel-headers`的相关内核头文件软件包。

本书的整个源代码树可在其 GitHub 存储库中找到，网址为[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)，本章的代码位于`ch4`目录下。我们期望您进行克隆：

```
git clone https://github.com/PacktPublishing/Linux-Kernel-Programming.git

```

本章的代码位于其目录名称下，`chn`（其中`n`是章节编号；所以在这里，它位于`ch4/`下）。

# 理解内核架构-第一部分

在本节中，我们开始加深对内核的理解。更具体地说，在这里，我们深入探讨了用户空间和内核空间以及构成 Linux 内核的主要子系统和各种组件。目前，这些信息在更高的抽象级别上处理，并且故意保持简洁。我们将在第六章，*内核内部基础知识-进程和线程**.*中更深入地了解内核的结构。

## 用户空间和内核空间

现代微处理器支持至少两个特权级别。以英特尔/AMD x86[-64]家族为例，支持四个特权级别（它们称之为*环级*），而 ARM（32 位）微处理器家族支持多达七个（ARM 称之为*执行模式*；其中六个是特权的，一个是非特权的）。

这里的关键点是，为了平台的安全性和稳定性，所有运行在这些处理器上的现代操作系统都将使用（至少）两个特权级别（或模式）：

+   **用户空间**：*应用程序*在*非特权用户模式*下运行

+   **内核空间**：*内核*（及其所有组件）在特权模式下运行- *内核模式*

以下图显示了这种基本架构：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/5d5b3064-6e8e-4b85-8ba3-26e71a262908.png)

图 4.1-基本架构-两个特权模式

接下来是有关 Linux 系统架构的一些细节；请继续阅读。

## 库和系统调用 API

用户空间应用程序通常依赖于**应用程序编程接口**（**APIs**）来执行它们的工作。*库*本质上是 API 的集合或存档，允许您使用标准化、编写良好且经过充分测试的接口（并利用通常的好处：无需重新发明轮子、可移植性、标准化等）。Linux 系统有几个库；即使在企业级系统上也不少见数百个。其中，*所有*用户模式 Linux 应用程序（可执行文件）都会被“自动链接”到一个重要的、始终使用的库中：`glibc`* - GNU 标准 C 库*，正如您将会了解的那样。然而，库只能在用户模式下使用；内核没有库（在接下来的章节中会详细介绍）。

库 API 的示例是众所周知的`printf(3)`（回想一下，来自第一章，*内核工作空间设置*，可以找到此 API 的 man 页面部分），`scanf(3)`，`strcmp(3)`，`malloc(3)`和`free(3)`。

现在，一个关键点：如果用户和内核是分开的地址空间，并且处于不同的特权级别，用户进程如何能够*访问*内核呢？简短的答案是*通过系统调用*。**系统调用**是一种特殊的 API，因为它是用户空间进程访问内核的唯一合法（同步）方式。换句话说，系统调用是进入内核空间的唯一合法*入口点*。它们有能力从非特权用户模式切换到特权内核模式（更多关于这一点和单片设计的内容请参阅第六章，*内核内部要点-进程和线程*，在*进程和中断上下文*部分）。系统调用的示例包括`fork(2)`，`execve(2)`，`open(2)`，`read(2)`，`write(2)`，`socket(2)`，`accept(2)`，`chmod(2)`等。

在线查看所有库和系统调用 API 的 man 页面：

- 库 API，man 第三部分：[`linux.die.net/man/3/`](https://linux.die.net/man/3/)

- 系统调用 API，man 第二部分：[`linux.die.net/man/2/`](https://linux.die.net/man/2/)

这里强调的重点是，用户应用程序和内核之间实际上只能通过系统调用进行通信；这就是接口。在本书中，我们不会深入探讨这些细节。如果您对了解更多感兴趣，请参考 Packt 出版的书籍*《Linux 系统编程实践》*，特别是*第一章，Linux 系统架构*。

## 内核空间组件

当然，本书完全专注于内核空间。今天的 Linux 内核是一个相当庞大和复杂的东西。在内部，它由几个主要子系统和几个组件组成。对内核子系统和组件的广泛枚举得到以下列表：

+   **核心内核**：这段代码处理任何现代操作系统的典型核心工作，包括（用户和内核）进程和线程的创建/销毁，CPU 调度，同步原语，信号，定时器，中断处理，命名空间，cgroups，模块支持，加密等等。

+   **内存管理（MM）**：这处理所有与内存相关的工作，包括设置和维护内核和进程**虚拟地址空间**（**VASes**）。

+   **VFS（用于文件系统支持）**：**虚拟文件系统开关**（**VFS**）是 Linux 内核中实际文件系统的抽象层（例如，`ext[2|4]`，`vfat`，`reiserfs`，`ntfs`，`msdos`，`iso9660`，JFFS2 和 UFS）的实现。

+   **块 IO**：实现实际文件 I/O 的代码路径，从 VFS 直到块设备驱动程序以及其中的所有内容（实际上，相当多！），都包含在这里。

+   **网络协议栈**：Linux 以其对模型各层的众所周知（和不那么众所周知）的网络协议的精确、高质量实现而闻名，TCP/IP 可能是其中最著名的。

+   **进程间通信（IPC）支持**：这里实现了 IPC 机制；Linux 支持消息队列，共享内存，信号量（旧的 SysV 和新的 POSIX），以及其他 IPC 机制。

+   **声音支持**：这里包含了实现音频的所有代码，从固件到驱动程序和编解码器。

+   **虚拟化支持**：Linux 已经成为大大小小的云提供商的极其受欢迎的选择，一个重要原因是其高质量、低占用的虚拟化引擎，**基于内核的虚拟机**（**KVM**）。

所有这些构成了主要的内核子系统；此外，我们还有这些：

+   特定于体系结构（即特定于 CPU）的代码

+   内核初始化

+   安全框架

+   许多类型的设备驱动程序

回想一下，在第二章中，*从源代码构建 5.x Linux 内核 - 第一部分*，*内核源代码树简要介绍*部分给出了与主要子系统和其他组件对应的内核源代码树（代码）布局。

众所周知，Linux 内核遵循**单片内核架构**。基本上，单片设计是指*所有*内核组件（我们在本节中提到的）都存在并共享内核地址空间（或内核*段*）。这可以清楚地在下图中看到：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/880b83aa-6e39-424c-84d5-a1904241bcac.png)

图 4.2 - Linux 内核空间 - 主要子系统和块

另一个你应该知道的事实是，这些地址空间当然是*虚拟*地址空间，而不是物理地址空间。内核将（利用硬件，如 MMU/TLB/高速缓存）*映射*，在页面粒度级别，虚拟页面到物理页面帧。它通过使用*主*内核分页表将内核虚拟页面映射到物理帧，并且对于每个存活的进程，它通过为每个进程使用单独的分页表将进程的虚拟页面映射到物理页面帧。

在第六章中，*内核内部要点 - 进程和线程*（以及后续章节）中，等待您更深入地了解内核和内存管理架构和内部。

现在我们对用户空间和内核空间有了基本的了解，让我们继续并开始我们的 LKM 框架之旅。

# 探索 LKM

简而言之，内核模块是一种提供内核级功能而不必在内核源代码树中工作的方法。

想象一种情景，你必须向 Linux 内核添加支持功能 - 也许是为了使用某个硬件外围芯片而添加一个新的设备驱动程序，一个新的文件系统，或者一个新的 I/O 调度程序。一种明显的方法是：更新内核源代码树，构建并测试新代码。

尽管这看起来很简单，实际上需要大量工作 - 我们编写的代码的每一次更改，无论多么微小，都需要我们重新构建内核映像，然后重新启动系统以进行测试。必须有一种更清洁、更简单的方法；事实上是有的 - *LKM 框架*！

## LKM 框架

LKM 框架是一种在内核源树之外编译内核代码的方法，通常被称为“树外”代码，从某种程度上使其独立于内核，然后将其插入或*插入*到内核内存中，使其运行并执行其工作，然后将其（或*拔出*）从内核内存中移除。 

内核模块的源代码通常由一个或多个 C 源文件、头文件和一个 Makefile 组成，通过`make(1)`构建成一个*内核模块*。内核模块本身只是一个二进制对象文件，而不是一个二进制可执行文件。在 Linux 2.4 及更早版本中，内核模块的文件名带有`.o`后缀；在现代的 2.6 Linux 及更高版本中，它的后缀是`.ko`（**k**ernel **o**bject）。构建完成后，你可以将这个`.ko`文件 - 内核模块 - 插入到运行时的内核中，有效地使其成为内核的一部分。

请注意，并非所有内核功能都可以通过 LKM 框架提供。一些核心功能，如核心 CPU 调度器代码、内存管理、信号、定时器、中断管理代码路径等，只能在内核内部开发。同样，内核模块只允许访问完整内核 API 的子集；稍后会详细介绍。

你可能会问：我如何*插入*一个对象到内核中？让我们简单点 - 答案是：通过`insmod(8)`实用程序。现在，让我们跳过细节（这些将在即将到来的*运行内核模块*部分中解释）。以下图提供了首先构建，然后将内核模块插入内核内存的概述：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/538b17b8-db71-480b-b991-8e396a816a0b.png)

图 4.3 - 构建然后将内核模块插入内核内存

不用担心：内核模块的 C 源代码以及其 Makefile 的实际代码将在接下来的部分中详细介绍；现在，我们只想获得概念上的理解。

内核模块被加载到内核内存中，并驻留在内核 VAS（*图 4.3*的下半部分）中，由内核为其分配的空间中。毫无疑问，*它是内核代码，并以内核特权运行*。这样，你作为内核（或驱动程序）开发人员就不必每次都重新配置、重建和重新启动系统。你只需要编辑内核模块的代码，重新构建它，从内存中删除旧版本（如果存在），然后插入新版本。这样可以节省时间，提高生产效率。

内核模块有利的一个原因是它们适用于动态产品配置。例如，内核模块可以设计为在不同的价格点提供不同的功能；为嵌入式产品生成最终图像的脚本可以根据客户愿意支付的价格安装一组特定的内核模块。以下是另一个示例，说明了这项技术在*调试*或故障排除场景中的应用：内核模块可以用于在现有产品上动态生成诊断和调试日志。诸如 kprobes 之类的技术正是允许这样做的。

实际上，LKM 框架通过允许我们向内核内存中插入和移除实时代码的方式，为我们提供了一种动态扩展内核功能的手段。这种根据我们的意愿插入和拔出内核功能的能力使我们意识到 Linux 内核不仅是纯粹的单片式，它也是*模块化*的。

## 内核源树中的内核模块

事实上，内核模块对象对我们来说并不陌生。在第三章，*从源代码构建 5.x Linux 内核-第二部分*，我们在内核构建过程中构建了内核模块并将其安装。

请记住，这些内核模块是内核源代码的一部分，并且通过在 tristate 内核 menuconfig 提示中选择`M`来配置为模块。它们被安装在`/lib/modules/$(uname -r)/`目录下。因此，要查看一下我们当前运行的 Ubuntu 18.04.3 LTS 客户机内核下安装的内核模块，我们可以这样做：

```
$ lsb_release -a 2>/dev/null |grep Description
Description:    Ubuntu 18.04.3 LTS
$ uname -r
5.0.0-36-generic
$ find /lib/modules/$(uname -r)/ -name "*.ko" | wc -l
5359
```

好吧，Canonical 和其他地方的人很忙！超过五千个内核模块...想想看-这是有道理的：发行商无法预先知道用户最终会使用什么硬件外围设备（特别是在像 x86 架构系统这样的通用计算机上）。内核模块作为一种方便的手段，可以支持大量硬件而不会使内核镜像文件（例如`bzImage`或`zImage`）变得非常臃肿。

我们 Ubuntu Linux 系统中安装的内核模块位于`/lib/modules/$(uname -r)/kernel`目录中，如下所示：

```
$ ls /lib/modules/5.0.0-36-generic/kernel/
arch/  block/  crypto/  drivers/  fs/  kernel/  lib/  mm/  net/  samples/  sound/  spl/  ubuntu/  virt/  zfs/
$ ls /lib/modules/5.4.0-llkd01/kernel/
arch/  crypto/  drivers/  fs/  net/  sound/
$ 
```

在这里，查看`/lib/modules/$(uname -r)`下的发行版内核（Ubuntu 18.04.3 LTS 运行`5.0.0-36-generic`内核）的`kernel/`目录的顶层，我们可以看到有许多子文件夹和成千上万的内核模块。相比之下，对于我们构建的内核（有关详细信息，请参阅第二章，*从源代码构建 5.x Linux 内核-第一部分*，和第三章，*从源代码构建 5.x Linux 内核-第二部分*），数量要少得多。您会回忆起我们在第二章中的讨论，*从源代码构建 5.x Linux 内核-第一部分*，我们故意使用了`localmodconfig`目标来保持构建的小巧和快速。因此，在这里，我们定制的 5.4.0 内核只构建了大约 60 个内核模块。

设备驱动程序是一个经常使用内核模块的领域。例如，让我们看一个作为内核模块架构的网络设备驱动程序。您可以在发行版内核的`kernel/drivers/net/ethernet`文件夹下找到几个（还有一些熟悉的品牌！）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/a3596e74-fd45-46b0-b1ed-c068d44daa3f.png)

图 4.4-我们发行版内核的以太网网络驱动程序（内核模块）的内容

许多基于 Intel 的笔记本电脑上都使用 Intel 1GbE **网络接口卡**（**NIC**）以太网适配器。驱动它的网络设备驱动程序称为`e1000`驱动程序。我们的 x86-64 Ubuntu 18.04.3 客户机（在 x86-64 主机笔记本电脑上运行）显示它确实使用了这个驱动程序：

```
$ lsmod | grep e1000
e1000                 139264  0
```

我们很快将更详细地介绍`lsmod(8)`（'列出模块'）实用程序。对我们来说更重要的是，我们可以看到它是一个内核模块！如何获取有关这个特定内核模块的更多信息？通过利用`modinfo(8)`实用程序很容易实现（为了可读性，我们在这里截断了它的详细输出）：

```
$ ls -l /lib/modules/5.0.0-36-generic/kernel/drivers/net/ethernet/intel/e1000
total 220
-rw-r--r-- 1 root root 221729 Nov 12 16:16 e1000.ko
$ modinfo /lib/modules/5.0.0-36-generic/kernel/drivers/net/ethernet/intel/e1000/e1000.ko
filename:       /lib/modules/5.0.0-36-generic/kernel/drivers/net/ethernet/intel/e1000/e1000.ko
version:        7.3.21-k8-NAPI
license:        GPL v2
description:    Intel(R) PRO/1000 Network Driver
author:         Intel Corporation, <linux.nics@intel.com>
srcversion:     C521B82214E3F5A010A9383
alias:          pci:v00008086d00002E6Esv*sd*bc*sc*i*
[...]
name:           e1000
vermagic:       5.0.0-36-generic SMP mod_unload 
[...]
parm:           copybreak:Maximum size of packet that is copied to a new 
                buffer on receive (uint)
parm:           debug:Debug level (0=none,...,16=all) (int)
$  
```

`modinfo(8)`实用程序允许我们查看内核模块的二进制图像并提取有关它的一些详细信息；有关使用`modinfo`的更多信息将在下一节中介绍。

另一种获取系统有用信息的方法，包括有关当前加载的内核模块的信息，是通过`systool(1)`实用程序。对于已安装的内核模块（有关在下一章中*自动加载系统引导时安装*内核模块的详细信息），执行`systool -m <module-name> -v`可以显示有关它的信息。查阅`systool(1)`手册页以获取使用详细信息。

最重要的是，内核模块已成为构建和分发某些类型的内核组件的*实用*方法，*设备驱动程序*是它们最常见的用例。其他用途包括但不限于文件系统、网络防火墙、数据包嗅探器和自定义内核代码。

因此，如果您想学习如何编写 Linux 设备驱动程序、文件系统或防火墙，您必须首先学习如何编写内核模块，从而利用内核强大的 LKM 框架。这正是我们接下来要做的事情。

# 编写我们的第一个内核模块

在引入新的编程语言或主题时，模仿原始的*K&R Hello, world*程序作为第一段代码已经成为一种被广泛接受的计算机编程传统。我很高兴遵循这一受尊敬的传统来介绍强大的 LKM 框架。在本节中，您将学习编写简单 LKM 的步骤。我们会详细解释代码。

## 介绍我们的 Hello, world LKM C 代码

话不多说，这里是一些简单的*Hello, world* C 代码，实现了遵循 Linux 内核的 LKM 框架：

出于可读性和空间限制的原因，这里只显示了源代码的关键部分。要查看完整的源代码，构建并运行它，本书的整个源树都可以在 GitHub 仓库中找到：[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)。我们期望您能够克隆它：

`git clone https://github.com/PacktPublishing/Linux-Kernel-Programming.git`

```
// ch4/helloworld_lkm/hellowworld_lkm.c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_AUTHOR("<insert your name here>");
MODULE_DESCRIPTION("LLKD book:ch4/helloworld_lkm: hello, world, our first LKM");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int __init helloworld_lkm_init(void)
{
    printk(KERN_INFO "Hello, world\n");
    return 0;     /* success */
}

static void __exit helloworld_lkm_exit(void)
{
    printk(KERN_INFO "Goodbye, world\n");
}

module_init(helloworld_lkm_init);
module_exit(helloworld_lkm_exit);
```

您可以立即尝试这个简单的*Hello, world*内核模块！只需像这里显示的那样`cd`到正确的源目录，并获取我们的辅助`lkm`脚本来构建和运行它：

```
$ cd <...>/ch4/helloworld_lkm
$ ../../lkm helloworld_lkm
Version info:
Distro:     Ubuntu 18.04.3 LTS
Kernel: 5.0.0-36-generic
[...]
dmesg[ 5399.230367] Hello, world
$ 
```

*如何*和*为什么*很快会有详细的解释。尽管代码很小，但我们的第一个内核模块需要仔细阅读和理解。请继续阅读。

## 分解

以下小节解释了前面*Hello, world* C 代码的几乎每一行。请记住，尽管程序看起来非常小和琐碎，但对于它和周围的 LKM 框架，有很多需要理解的地方。本章的其余部分将重点介绍这一点，并进行详细讨论。我强烈建议您花时间阅读和理解这些基础知识。这将在以后可能出现的难以调试的情况下对您有很大帮助。

### 内核头文件

我们使用`#include`包含了一些头文件。与用户空间的'C'应用程序开发不同，这些是*内核头文件*（如*技术要求*部分所述）。请回顾第三章，*从源代码构建 5.x Linux 内核 - 第二部分*，内核模块安装在特定的根可写分支下。让我们再次检查一下（这里，我们正在运行我们的客户 x86_64 Ubuntu VM，使用的是 5.0.0-36-generic 发行版内核）。

```
$ ls -l /lib/modules/$(uname -r)/
total 5552
lrwxrwxrwx  1 root root      39 Nov 12 16:16 build -> /usr/src/linux-headers-5.0.0-36-generic/
drwxr-xr-x  2 root root    4096 Nov 28 08:49 initrd/
[...]
```

请注意名为`build`的符号链接或软链接。它指向系统上内核头文件的位置。在前面的代码中，它位于`/usr/src/linux-headers-5.0.0-36-generic/`下！正如您将看到的，我们将向用于构建内核模块的 Makefile 提供这些信息。（此外，一些系统有一个名为`source`的类似软链接）。

`kernel-headers`或`linux-headers`软件包将有限的内核源树解压到系统上，通常位于`/usr/src/...`下。然而，这段代码并不完整，因此我们使用了短语*有限*源树。这是因为构建模块并不需要完整的内核源树 - 只需要打包和提取所需的组件（头文件，Makefile 等）。

我们的*Hello, world*内核模块中的第一行代码是`#include <linux/init.h>`。

编译器通过在`/lib/modules/$(uname -r)/build/include/`下搜索先前提到的内核头文件来解决这个问题。因此，通过跟随`build`软链接，我们可以看到它最终拾取了这个头文件：

```
$ ls -l /usr/src/linux-headers-5.0.0-36-generic/include/linux/init.h
-rw-r--r-- 1 root root 9704 Mar  4  2019 /usr/src/linux-headers-5.0.0-36-generic/include/linux/init.h
```

其他包含在内核模块源代码中的内核头文件也是如此。

### 模块宏

接下来，我们有一些形式为`MODULE_FOO()`的模块宏；大多数都很直观：

+   `MODULE_AUTHOR()`: 指定内核模块的作者

+   `MODULE_DESCRIPTION()`: 简要描述此 LKM 的功能

+   `MODULE_LICENSE()`: 指定内核模块发布的许可证

+   `MODULE_VERSION()`: 指定内核模块的（本地）版本

在没有源代码的情况下，如何将这些信息传达给最终用户（或客户）？啊，`modinfo(8)`实用程序正是这样做的！这些宏及其信息可能看起来微不足道，但在项目和产品中非常重要。例如，供应商通过在所有已安装的内核模块上使用`grep`对`modinfo`输出来确定代码正在运行的（开源）许可证。

### 入口和出口点

永远不要忘记，内核模块毕竟是*以内核特权运行的内核代码*。它*不是*一个应用程序，因此没有像我们熟悉和喜爱的`main()`函数那样的入口点。这当然引出了一个问题：内核模块的入口和出口点是什么？请注意，在我们简单的内核模块底部，以下行：

```
module_init(helloworld_lkm_init);
module_exit(helloworld_lkm_exit);
```

`module_[init|exit]()`代码是分别指定入口和出口点的宏。每个参数都是一个函数指针。使用现代 C 编译器，我们可以只指定函数的名称。因此，在我们的代码中，以下内容适用：

+   `helloworld_lkm_init()`函数是入口点。

+   `helloworld_lkm_exit()`函数是出口点。

这些入口和出口点几乎可以被认为是内核模块的*构造函数/析构函数*对。从技术上讲，当然不是这样，因为这不是面向对象的 C++代码，而是普通的 C。尽管如此，这是一个有用的类比。

### 返回值

注意`init`和`exit`函数的签名如下：

```
static int  __init <modulename>_init(void);
static void __exit <modulename>_exit(void);
```

作为良好的编码实践，我们已经使用了函数的命名格式`<modulename>__[init|exit]()`，其中`<modulename>`被替换为内核模块的名称。您会意识到这种命名约定只是这样 - 从技术上讲是不必要的，但它是直观的，因此有帮助。显然，这两个例程都不接收任何参数。

将这两个函数标记为`static`限定符意味着它们对这个内核模块是私有的。这正是我们想要的。

现在让我们继续讨论内核模块的`init`函数返回值所遵循的重要约定。

#### 0/-E 返回约定

内核模块的`init`函数要返回一个类型为`int`的值；这是一个关键方面。Linux 内核已经形成了一种*风格*或约定，如果你愿意的话，关于从中返回值的方式（从内核空间到用户空间进程）。LKM 框架遵循了俗称的`0/-E`约定：

+   成功时，返回整数值`0`。

+   失败时，返回用户空间全局未初始化整数`errno`的负值。

请注意，`errno`是一个全局变量，驻留在用户进程 VAS 中的未初始化数据段中。除了很少的例外情况，每当 Linux 系统调用失败时，都会返回`-1`，并且`errno`被设置为一个正值，表示失败代码；这项工作是由`glibc`在`syscall`返回路径上的“粘合”代码完成的。

此外，`errno`值实际上是全局英文错误消息表的索引（`const char * const sys_errlist[]`）；这就是`perror(3)`、`strerror_r`等函数如何打印出失败诊断信息的真正原因。

顺便说一句，您可以从这些（内核源树）头文件中查找可用的**错误代码完整列表**：`include/uapi/asm-generic/errno-base.h` 和 `include/uapi/asm-generic/errno.h`。

一个快速的例子可以帮助我们清楚地了解如何从内核模块的`init`函数返回：假设我们的内核模块的`init`函数正在尝试动态分配一些内核内存（有关`kmalloc()`API 等的详细信息将在以后的章节中介绍；现在请忽略它）。然后，我们可以这样编写代码：

```
[...]
ptr = kmalloc(87, GFP_KERNEL);
if (!ptr) {
    pr_warning("%s:%s:%d: kmalloc failed!\n", __FILE__, __func__, __LINE__);
    return -ENOMEM;
}
[...]
return 0;   /* success */
```

如果内存分配失败（很少见，但嘿，这是可能的！），我们会执行以下操作：

1.  首先，我们发出一个警告`printk`。实际上，在这种特殊情况下——"内存不足"——这是迂腐和不必要的。如果内核空间内存分配失败，内核肯定会发出足够的诊断信息！请参阅此链接以获取更多详细信息：[`lkml.org/lkml/2014/6/10/382`](https://lkml.org/lkml/2014/6/10/382)；我们之所以在这里这样做，只是因为讨论刚开始，为了读者的连贯性。

1.  返回`-ENOMEM`值：

+   在用户空间返回此值的层实际上是`glibc`；它有一些"粘合"代码，将此值乘以`-1`并将全局整数`errno`设置为它。

+   现在，`[f]init_module(2)`系统调用将返回`-1`，表示失败（这是因为`insmod(8)`实际上调用了这个系统调用，您很快就会看到）。

+   `errno`将被设置为`ENOMEM`，反映了由于内存分配失败而导致内核模块插入失败的事实。

相反，框架*期望*`init`函数在成功时返回值`0`。实际上，在旧的内核版本中，如果在成功时未返回`0`，内核模块将被突然从内核内存中卸载。如今，内核不会卸载内核模块，但会发出警告消息，指出已返回一个*可疑*的非零值。

清理例程没有太多可说的。它不接收任何参数，也不返回任何内容（`void`）。它的工作是在内核模块从内核内存中卸载之前执行所有必需的清理。

*不*在您的内核模块中包括`module_exit()`宏将使其不可能卸载（当然，除非系统关闭或重新启动）。有趣...（我建议您尝试这个小练习！）。

当然，事情永远不会那么简单：只有在内核构建时将`CONFIG_MODULE_FORCE_UNLOAD`标志设置为`Disabled`（默认情况下）时，才能保证这种阻止卸载的行为。

#### ERR_PTR 和 PTR_ERR 宏

在返回值的讨论中，您现在了解到内核模块的`init`例程必须返回一个整数。如果您希望返回一个指针呢？`ERR_PTR()`内联函数来帮助我们，允许我们返回一个指针，只需将其强制转换为`void *`即可。事实上，情况会更好：您可以使用`IS_ERR()`内联函数来检查错误（它实际上只是确定值是否在[-1 到-4095]范围内），通过`ERR_PTR()`内联函数将负错误值编码为指针，并使用相反的例程`PTR_ERR()`从指针中检索此值。

作为一个简单的例子，看看这里给出的被调用者代码。这次，我们的（示例）函数`myfunc()`返回一个指针（指向一个名为`mystruct`的结构），而不是一个整数：

```
struct mystruct * myfunc(void)
{
    struct mystruct *mys = NULL;
    mys = kzalloc(sizeof(struct mystruct), GFP_KERNEL);
    if (!mys)
        return ERR_PTR(-ENOMEM);
    [...]
    return mys;
}
```

调用者代码如下：

```
[...]
gmys = myfunc();
if (IS_ERR(gmys)) {
    pr_warn("%s: myfunc alloc failed, aborting...\n", OURMODNAME);
    stat = PTR_ERR(gmys); /* sets 'stat' to the value -ENOMEM */
    goto out_fail_1;
}
[...]
return stat;
out_fail_1:
    return stat;
}
```

顺便说一句，内联函数`ERR_PTR()`、`PTR_ERR()`和`IS_ERR()`都在（内核头文件）`include/linux/err.h`文件中。内核文档（[`kernel.readthedocs.io/en/sphinx-samples/kernel-hacking.html#return-conventions`](https://kernel.readthedocs.io/en/sphinx-samples/kernel-hacking.html#return-conventions)）讨论了内核函数的返回约定。此外，你可以在内核源代码树中的`crypto/api-samples`代码下找到这些函数的用法示例：[`www.kernel.org/doc/html/v4.17/crypto/api-samples.html`](https://www.kernel.org/doc/html/v4.17/crypto/api-samples.html)。

#### __init 和 __exit 关键字

一个微小的遗留问题：在前面的函数签名中我们看到的`__init`和`__exit`宏到底是什么？这些只是链接器插入的内存优化属性。

`__init`宏为代码定义了一个`init.text`部分。同样，任何声明了`__initdata`属性的数据都会进入`init.data`部分。这里的重点是`init`函数中的代码和数据在初始化期间只使用一次。一旦被调用，它就再也不会被调用；所以一旦被调用，它就会被释放掉（通过`free_initmem()`）。

`__exit`宏的情况类似，当然，这只对内核模块有意义。一旦调用`cleanup`函数，所有内存都会被释放。如果代码是静态内核映像的一部分（或者模块支持被禁用），这个宏就没有效果了。

好了，但到目前为止，我们还没有解释一些实际问题：你到底如何将内核模块对象加载到内核内存中，让它执行，然后卸载它，以及你可能希望执行的其他一些操作。让我们在下一节讨论这些问题。

# 内核模块的常见操作

现在让我们深入讨论一下你到底如何构建、加载和卸载内核模块。除此之外，我们还将介绍关于非常有用的`printk()`内核 API、使用`lsmod(8)`列出当前加载的内核模块的基础知识，以及用于在内核模块开发过程中自动执行一些常见任务的便利脚本。所以，让我们开始吧！

## 构建内核模块

我们强烈建议你尝试一下我们简单的*Hello, world*内核模块练习（如果你还没有这样做的话）！为此，我们假设你已经克隆了本书的 GitHub 存储库（[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)）。如果还没有，请现在克隆（参考*技术要求*部分获取详细信息）。

在这里，我们逐步展示了你到底如何构建并将我们的第一个内核模块插入到内核内存中。再次提醒一下：我们在运行 Ubuntu 18.04.3 LTS 发行版的 x86-64 Linux 虚拟机（在 Oracle VirtualBox 6.1 下）上执行了这些步骤。

1.  切换到本书源代码章节目录和子目录。我们的第一个内核模块位于自己的文件夹中（应该是这样！）叫做`helloworld_lkm`：

```
 cd <book-code-dir>/ch4/helloworld_lkm
```

`<book-code-dir>`当然是你克隆了本书的 GitHub 存储库的文件夹；在这里（见截图，图 4.5），你可以看到它是`/home/llkd/book_llkd/Linux-Kernel-Programming/`。

1.  现在验证代码库：

```
$ pwd
*<book-code-dir>*/ch4/helloworld_lkm
$ ls -l
total 8
-rw-rw-r-- 1 llkd llkd 1211 Jan 24 13:01 helloworld_lkm.c
-rw-rw-r-- 1 llkd llkd  333 Jan 24 13:01 Makefile
$ 
```

1.  使用`make`进行构建：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/bd85fe6e-cac7-4e9f-9d65-075cb8212f04.png)

图 4.5 - 列出并构建我们的第一个*Hello, world*内核模块

前面的截图显示内核模块已经成功构建。它是`./helloworld_lkm.ko`文件。（另外，注意我们是从我们之前章节中构建的自定义 5.4.0 内核引导的。）

## 运行内核模块

为了让内核模块运行，你需要首先将它加载到内核内存空间中。这被称为将模块*插入*到内核内存中。

将内核模块放入 Linux 内核段可以通过几种方式完成，最终都归结为调用`[f]init_module(2)`系统调用之一。为了方便起见，存在几个包装实用程序将这样做（或者您总是可以编写一个）。我们将在下面使用流行的`insmod(8)`（读作“**ins**ert **mod**ule”）实用程序；`insmod`的参数是要插入的内核模块的路径名：

```
$ insmod ./helloworld_lkm.ko 
insmod: ERROR: could not insert module ./helloworld_lkm.ko: Operation not permitted
$ 
```

它失败了！实际上，失败的原因应该是非常明显的。想一想：将代码插入内核在很大程度上甚至优于在系统上成为*root*（超级用户）- 再次提醒您：*它是内核代码，并且将以内核特权运行*。如果任何用户都被允许插入或删除内核模块，黑客将有一天的乐趣！部署恶意代码将变得相当简单。因此，出于安全原因，**只有具有 root 访问权限才能插入或删除内核模块**。

从技术上讲，作为*root*意味着进程（或线程）的**真实**和/或**有效** **UID**（**RUID**/**EUID**）值是特殊值*零*。不仅如此，而且现代内核通过现代和优越的 POSIX Capabilities 模型“看到”线程具有某些**capabilities**；只有具有`CAP_SYS_MODULE`能力的进程/线程才能（卸载）加载内核模块。我们建议读者查看`capabilities(7)`的手册页以获取更多详细信息。

所以，让我们再次尝试将我们的内核模块插入内存，这次使用`sudo(8)`的*root*权限：

```
$ sudo insmod ./helloworld_lkm.ko
[sudo] password for llkd: 
$ echo $?
0
```

现在可以了！正如前面提到的，`insmod(8)`实用程序通过调用`[f]init_module(2)`系统调用来工作。`insmod(8)`实用程序（实际上是内部的`[f]init_module(2)`系统调用）*失败*的情况是什么时候？

有一些情况：

+   **权限**：未以 root 身份运行或缺少`CAP_SYS_MODULE`能力（`errno <- EPERM`）。

+   `proc`文件系统中的内核可调参数，`/proc/sys/kernel/modules_disabled`，被设置为`1`（默认为`0`）。

+   具有相同名称的内核模块已经在内核内存中（`errno <- EEXISTS`）。

好的，一切看起来都很好。`$?`的结果为`0`意味着上一个 shell 命令成功了。这很好，但是我们的*Hello, world*消息在哪里？继续阅读！

## 快速查看内核 printk()

为了发出消息，用户空间的 C 开发人员通常会使用可靠的`printf(3)` glibc API（或者在编写 C++代码时可能会使用`cout`）。但是，重要的是要理解，在内核空间中，*没有库*。因此，我们*无法*访问老式的`printf()` API*。相反，它在内核中基本上被重新实现为`printk()`内核 API（想知道它的代码在哪里吗？它在内核源树中的这里：`kernel/printk/printk.c:printk()`）。

通过`printk()` API 发出消息非常简单，并且与使用`printf(3)`非常相似。在我们简单的内核模块中，这就是发生操作的地方：

```
printk(KERN_INFO "Hello, world\n");
```

虽然乍一看与`printf`非常相似，但`printk`实际上是非常不同的。在相似之处，API 接收一个格式字符串作为其参数。格式字符串几乎与`printf`的格式字符串完全相同。

但相似之处就到此为止。`printf`和`printk`之间的关键区别在于：用户空间的`printf(3)`库 API 通过根据请求格式化文本字符串并调用`write(2)`系统调用来工作，而后者实际上执行对`stdout` *设备*的写入，默认情况下是终端窗口（或控制台设备）。内核`printk` API 也根据请求格式化其文本字符串，但其*输出* *目的地*不同。它至少写入一个地方-以下列表中的第一个-可能还会写入几个地方：

+   RAM 中的内核日志缓冲区（易失性）

+   一个日志文件，内核日志文件（非易失性）

+   控制台设备

现在，我们将跳过关于`printk`工作原理的内部细节。另外，请忽略`printk` API 中的`KERN_INFO`标记；我们很快会涵盖所有这些内容。

当您通过`printk`发出消息时，可以保证输出进入内核内存（RAM）中的日志缓冲区。这实际上构成了**内核日志**。重要的是要注意，在图形模式下使用 X 服务器进程运行时（在典型的 Linux 发行版上工作时的默认环境），您永远不会直接看到`printk`输出。因此，这里显而易见的问题是：您如何查看内核日志缓冲区内容？有几种方法。现在，让我们简单快速地使用一种方法。

使用`dmesg(1)`实用程序！默认情况下，`dmesg`将将整个内核日志缓冲区内容转储到标准输出。在这里，我们使用它查找内核日志缓冲区的最后两行：

```
$ dmesg | tail -n2
[ 2912.880797] hello: loading out-of-tree module taints kernel.
[ 2912.881098] Hello, world
$ 
```

终于找到了：我们的*Hello, world*消息！

现在可以简单地忽略`loading out-of-tree module taints kernel.`的消息。出于安全原因，大多数现代 Linux 发行版将内核标记为*污染*（字面上是"污染"或"污染"）如果插入了第三方"out-of-tree"（或非签名）内核模块。 （嗯，这实际上更像是伪法律掩盖，类似于：“如果从这一点开始出了问题，我们不负责任等等...”；你懂的）。

为了有点变化，这里是我们在运行 5.4 Linux LTS 内核的 x86-64 CentOS 8 虚拟机上插入和移除*Hello, world*内核模块的屏幕截图（详细信息如下）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/8aed7347-fd0f-452d-9345-433a8952dfd0.png)

图 4.6 - 屏幕截图显示我们在 CentOS 8 x86-64 虚拟机上使用*Hello, world*内核模块

在由`dmesg(1)`实用程序显示的内核日志中，最左边的列中的数字是一个简单的时间戳，格式为`[秒.微秒]`，表示自系统启动以来经过的时间（尽管不建议将其视为完全准确）。顺便说一句，这个时间戳是一个`Kconfig`变量 - 一个内核配置选项 - 名为`CONFIG_PRINTK_TIME`；它可以被`printk.time`内核参数覆盖。

## 列出活动的内核模块

回到我们的内核模块：到目前为止，我们已经构建了它，将它加载到内核中，并验证了它的入口点`helloworld_lkm_init()`函数被调用，从而执行了`printk` API。那么，它现在做什么？嗯，实际上什么都不做；内核模块只是（愉快地？）坐在内核内存中什么都不做。实际上，我们可以很容易地使用`lsmod(8)`实用程序查找它。

```
$ lsmod | head
Module                  Size  Used by
helloworld_lkm         16384  0
isofs                  32768  0
fuse                  139264  3
tun                    57344  0
[...]
e1000                 155648  0
dm_mirror              28672  0
dm_region_hash         20480  1 dm_mirror
dm_log                 20480  2 dm_region_hash,dm_mirror
dm_mod                151552  11 dm_log,dm_mirror
$
```

`lsmod`显示当前驻留在内核内存中（或*活动*）的所有内核模块，按时间顺序排列。它的输出是列格式化的，有三列和一个可选的第四列。让我们分别看看每一列：

+   第一列显示内核模块的*名称*。

+   第二列是内核中占用的（静态）*大小*（以字节为单位）。

+   第三列是模块的*使用计数*。

+   可选的第四列（以及可能随后的更多内容）将在下一章中解释（在*理解模块堆叠*部分）。另外，在最近的 x86-64 Linux 内核上，似乎至少需要 16 KB 的内核内存来存储一个内核模块。

所以，很好：到目前为止，您已经成功构建、加载并运行了您的第一个内核模块到内核内存中，并且基本上可以工作：接下来呢？嗯，实际上并没有太多！我们只是在下一节学习如何卸载它。当然还有更多要学的...继续吧！

## 从内核内存中卸载模块

要卸载内核模块，我们使用方便的实用程序`rmmod(8)`（*删除模块*）：

```
$ rmmod 
rmmod: ERROR: missing module name.
$ rmmod helloworld_lkm
rmmod: ERROR: could not remove 'helloworld_lkm': Operation not permitted
rmmod: ERROR: could not remove module helloworld_lkm: Operation not permitted
$ sudo rmmod helloworld_lkm
[sudo] password for llkd: 
$ dmesg |tail -n2
[ 2912.881098] Hello, world
[ 5551.863410] Goodbye, world
$
```

`rmmod(8)` 的参数是内核模块的*名称*（如 `lsmod(8)` 的第一列中所示），而不是路径名。显然，就像 `insmod(8)` 一样，我们需要以 *root* 用户身份运行 `rmmod(8)` 实用程序才能成功。

在这里，我们还可以看到，由于我们的 `rmmod`，内核模块的退出例程（或 "析构函数"）`helloworld_lkm_exit()` 函数被调用。它反过来调用了 `printk`，发出了 *Goodbye, world* 消息（我们用 `dmesg` 查找到）。

`rmmod`（请注意，在内部，它变成了 `delete_module(2)` 系统调用）*失败* 的情况是什么时候？以下是一些情况：

+   **权限**：如果不以 root 用户身份运行，或者缺少 `CAP_SYS_MODULE` 能力（`errno <- EPERM`）。

+   如果另一个模块正在使用内核模块的代码和/或数据（如果存在依赖关系；这在下一章的 *模块堆叠* 部分中有详细介绍），或者模块当前正在被进程（或线程）使用，则模块使用计数将为正，并且 `rmmod` 将失败（`errno <- EBUSY`）。

+   内核模块没有使用 `module_exit()` 宏指定退出例程（或析构函数）*和* `CONFIG_MODULE_FORCE_UNLOAD` 内核配置选项被禁用。

与模块管理相关的几个便利实用程序只是指向单个 `kmod(8)` 实用程序的符号（软）链接（类似于流行的 *busybox* 实用程序所做的）。这些包装器是 `lsmod(8), rmmod(8)`, `insmod(8)`, `modinfo(8)`, `modprobe(8)`, 和 `depmod(8)`。让我们看看其中的一些：

```
$ ls -l $(which insmod) ; ls -l $(which lsmod) ; ls -l $(which rmmod)
lrwxrwxrwx 1 root root 9 Oct 24 04:50 /sbin/insmod -> /bin/kmod
lrwxrwxrwx 1 root root 9 Oct 24 04:50 /sbin/lsmod -> /bin/kmod
lrwxrwxrwx 1 root root 9 Oct 24 04:50 /sbin/rmmod -> /bin/kmod
$ 
```

请注意，这些实用程序的确切位置（`/bin`，`/sbin`或`/usr/sbin`）可能会随着发行版的不同而有所变化。

## 我们的 lkm 便利脚本

让我们用一个名为 `lkm` 的简单而有用的自定义 Bash 脚本来结束这个 *第一个内核模块* 的讨论，它可以通过自动化内核模块的构建、加载、`dmesg` 和卸载工作流程来帮助你。这是它的内容（完整的代码在书籍源代码树的根目录中）：

```
#!/bin/bash
# lkm : a silly kernel module dev - build, load, unload - helper wrapper script
[...]
unset ARCH
unset CROSS_COMPILE
name=$(basename "${0}")

# Display and run the provided command.
# Parameter(s) : the command to run
runcmd()
{
    local SEP="------------------------------"
    [ $# -eq 0 ] && return
    echo "${SEP}
$*
${SEP}"
    eval "$@"
    [ $? -ne 0 ] && echo " ^--[FAILED]"
}

### "main" here
[ $# -ne 1 ] && {
  echo "Usage: ${name} name-of-kernel-module-file (without the .c)"
  exit 1
}
[[ "${1}" = *"."* ]] && {
  echo "Usage: ${name} name-of-kernel-module-file ONLY (do NOT put any extension)."
  exit 1
}
echo "Version info:"
which lsb_release >/dev/null 2>&1 && {
  echo -n "Distro: "
  lsb_release -a 2>/dev/null |grep "Description" |awk -F':' '{print $2}'
}
echo -n "Kernel: " ; uname -r
runcmd "sudo rmmod $1 2> /dev/null"
runcmd "make clean"
runcmd "sudo dmesg -c > /dev/null"
runcmd "make || exit 1"
[ ! -f "$1".ko ] && {
  echo "[!] ${name}: $1.ko has not been built, aborting..."
  exit 1
}
runcmd "sudo insmod ./$1.ko && lsmod|grep $1"
runcmd dmesg
exit 0
```

给定内核模块的名称作为参数 - 没有任何扩展部分（例如 `.c`）- `lkm` 脚本执行一些有效性检查，显示一些版本信息，然后使用包装器 `runcmd()` bash 函数来显示并运行给定命令的名称，从而轻松完成 `clean/build/load/lsmod/dmesg` 工作流程。让我们在我们的第一个内核模块上试一试：

```
$ pwd
<...>/ch4/helloworld_lkm
$ ../../lkm
Usage: lkm name-of-kernel-module-file (without the .c)
$ ../../lkm helloworld_lkm
Version info:
Distro:          Ubuntu 18.04.3 LTS
Kernel: 5.0.0-36-generic
------------------------------
sudo rmmod helloworld_lkm 2> /dev/null
------------------------------
[sudo] password for llkd: 
------------------------------
sudo dmesg -C
------------------------------
------------------------------
make || exit 1
------------------------------
make -C /lib/modules/5.0.0-36-generic/build/ M=/home/llkd/book_llkd/Learn-Linux-Kernel-Development/ch4/helloworld_lkm modules
make[1]: Entering directory '/usr/src/linux-headers-5.0.0-36-generic'
  CC [M]  /home/llkd/book_llkd/Learn-Linux-Kernel-Development/ch4/helloworld_lkm/helloworld_lkm.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/llkd/book_llkd/Learn-Linux-Kernel-Development/ch4/helloworld_lkm/helloworld_lkm.mod.o
  LD [M]  /home/llkd/book_llkd/Learn-Linux-Kernel-Development/ch4/helloworld_lkm/helloworld_lkm.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.0.0-36-generic'
------------------------------
sudo insmod ./helloworld_lkm.ko && lsmod|grep helloworld_lkm
------------------------------
helloworld_lkm         16384  0
------------------------------
dmesg
------------------------------
[ 8132.596795] Hello, world
$ 
```

全部完成！记得使用 `rmmod(8)` 卸载内核模块。

恭喜！你现在已经学会了如何编写并尝试一个简单的 *Hello, world* 内核模块。不过，在你休息之前，还有很多工作要做；下一节将更详细地探讨有关内核日志记录和多功能 printk API 的关键细节。

# 理解内核日志和 printk

关于通过 printk 内核 API 记录内核消息仍有很多内容需要涵盖。本节深入探讨了一些细节。对于像你这样的新手内核开发人员来说，清楚地理解这些内容非常重要。

在本节中，我们将更详细地探讨内核日志记录。我们将了解到 printk 输出是如何处理的，以及其利弊。我们将讨论 printk 日志级别，现代系统如何通过 systemd 日志记录消息，以及如何将输出定向到控制台设备。我们将以限制 printk 和用户生成的打印输出，从用户空间生成 printk，并标准化 printk 输出格式的注意来结束本讨论。

我们之前在 *快速查看内核* *printk* 部分看到了使用内核 printk API 功能的基本知识。在这里，我们将更详细地探讨关于 `printk()` API 的使用。在我们简单的内核模块中，这是发出 "*Hello, world*" 消息的代码行：

```
printk(KERN_INFO "Hello, world\n");
```

再次强调，`printk`与`printf`类似，都涉及*格式字符串*以及其工作原理 - 但相似之处就到此为止。值得强调的是，`printf(3)`是一个*用户空间库*API，通过调用`write(2)`系统调用来工作，该系统调用写入*stdout 设备*，默认情况下通常是终端窗口（或控制台设备）。而`printk`是一个*内核空间*API，其输出实际上会被发送到至少一个位置，如下列表中所示的第一个位置，可能还会发送到更多位置：

+   内核日志缓冲区（在 RAM 中；易失性）

+   内核日志文件（非易失性）

+   控制台设备

让我们更详细地检查内核日志缓冲区。

## 使用内核内存环形缓冲区

内核日志缓冲区只是内核地址空间中的一个内存缓冲区，用于保存（记录）`printk`的输出。更具体地说，它是全局变量`__log_buf[]`。在内核源代码中的定义如下：

```
kernel/printk/printk.c:
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
```

它被设计为一个*环形缓冲区*；它有一个有限的大小（`__LOG_BUF_LEN`字节），一旦满了，就会从第一个字节开始覆盖。因此，它被称为“环形”或循环缓冲区）。在这里，我们可以看到大小是基于`Kconfig`变量`CONFIG_LOG_BUF_SHIFT`（C 中的`1 << n`表示`2^n`）。这个值是显示的，并且可以作为内核`(菜单)配置`的一部分被覆盖：`常规设置 > 内核日志缓冲区大小`。

它是一个整数值，范围为`12 - 25`（我们可以随时搜索`init/Kconfig`并查看其规范），默认值为`18`。因此，日志缓冲区的大小=2¹⁸=256 KB。但是，实际运行时的大小也受其他配置指令的影响，特别是`LOG_CPU_MAX_BUF_SHIFT`，它使大小成为系统上 CPU 数量的函数。此外，相关的`Kconfig`文件中说，*"当使用 log_buf_len 内核参数时，此选项将被忽略，因为它会强制使用环形缓冲区的确切（2 的幂）大小。"*因此，这很有趣；我们经常可以通过传递*内核参数*（通过引导加载程序）来覆盖默认值！

内核参数非常有用，种类繁多，值得一看。请参阅官方文档：[`www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)。来自 Linux 内核文档关于`log_buf_len`内核参数的片段揭示了细节：

```
log_buf_len=n[KMG]   Sets the size of the printk ring buffer,
                     in bytes. n must be a power of two and greater                
                     than the minimal size. The minimal size is defined
                     by LOG_BUF_SHIFT kernel config parameter. There is
                     also CONFIG_LOG_CPU_MAX_BUF_SHIFT config parameter
                     that allows to increase the default size depending  
                     on the number of CPUs. See init/Kconfig for more 
                     details.
```

无论内核日志缓冲区的大小如何，处理 printk API 时会出现两个问题：

+   它的消息被记录在*易失性*内存（RAM）中；如果系统崩溃或以任何方式断电，我们将丢失宝贵的内核日志（通常会影响我们的调试能力）。

+   默认情况下，日志缓冲区并不是很大，通常只有 256 KB；大量的打印会使环形缓冲区不堪重负，导致信息丢失。

我们该如何解决这个问题？继续阅读...

## 内核日志和 systemd 的 journalctl

解决前面提到的问题的一个明显方法是将内核的`printk`写入（追加）到文件中。这正是大多数现代 Linux 发行版的设置方式。日志文件的位置因发行版而异：传统上，基于 Red Hat 的发行版会写入`/var/log/messages`文件，而基于 Debian 的发行版会写入`/var/log/syslog`。传统上，内核的`printk`会连接到用户空间的*系统日志守护程序*（`syslogd`）以执行文件记录，因此自动获得更复杂功能的好处，如日志轮换、压缩和归档。

然而，在过去的几年里，系统日志已经完全被一个称为**systemd**的有用而强大的系统初始化新框架所取代（它取代了旧的 SysV init 框架，或者通常与其一起工作）。事实上，即使是嵌入式 Linux 设备也经常使用 systemd。在 systemd 框架内，日志记录由一个名为`systemd-journal`的守护进程执行，而`journalctl(1)`实用程序是其用户界面。

systemd 及其相关实用程序的详细覆盖范围超出了本书的范围。请参考本章的*进一步阅读*部分，了解更多相关内容。

使用日志记录来检索和解释日志的一个关键优势是，**所有**来自应用程序、库、系统守护进程、内核、驱动程序等的日志都会被写入（合并）在这里。这样，我们就可以看到一个（反向）时间线事件，而不必手动将不同的日志拼接成一个时间线。`journalctl(1)`实用程序的 man 页面详细介绍了它的各种选项。在这里，我们提供了一些（希望）基于这个实用程序的方便别名：

```
#--- a few journalctl(1) aliases
# jlog: current (from most recent) boot only, everything
alias jlog='/bin/journalctl -b --all --catalog --no-pager'
# jlogr: current (from most recent) boot only, everything,
#  in *reverse* chronological order
alias jlogr='/bin/journalctl -b --all --catalog --no-pager --reverse'
# jlogall: *everything*, all time; --merge => _all_ logs merged
alias jlogall='/bin/journalctl --all --catalog --merge --no-pager'
# jlogf: *watch* log, akin to 'tail -f' mode;
#  very useful to 'watch live' logs
alias jlogf='/bin/journalctl -f'
# jlogk: only kernel messages, this (from most recent) boot
alias jlogk='/bin/journalctl -b -k --no-pager'
```

注意`-b`选项`current boot`意味着日志是从当前系统启动日期显示的。可以使用`journalctl --list-boots`查看存储的系统（重新）启动的编号列表。

我们故意使用`--no-pager`选项，因为它允许我们进一步使用`[e]grep(1)`、`awk(1)`、`sort(1)`等来过滤输出，根据需要。以下是使用`journalctl(1)`的一个简单示例：

```
$ journalctl -k |tail -n2
Mar 17 17:33:16 llkd-vbox kernel: Hello, world
Mar 17 17:47:26 llkd-vbox kernel: Goodbye, world
$  
```

注意日志的默认格式：

```
[timestamp] [hostname] [source]: [... log message ...]
```

在这里`[source]`是内核消息的内核，或者写入消息的特定应用程序或服务的名称。

从`journalctl(1)`的 man 页面中看一些用法示例是有用的：

```
Show all kernel logs from previous boot:
    journalctl -k -b -1

Show a live log display from a system service apache.service:
    journalctl -f -u apache
```

将内核消息非易失性地记录到文件中当然是非常有用的。但要注意，存在一些情况，通常由硬件限制所决定，可能会使这种记录变得不可能。例如，一个小型、高度资源受限的嵌入式 Linux 设备可能会使用小型内部闪存芯片作为存储介质。现在，它不仅很小，而且所有的空间几乎都被应用程序、库、内核和引导加载程序所使用，而且闪存芯片有一个有效的擦写周期限制，它们可以承受的擦写周期数量有限。因此，写入几百万次可能会使其报废！因此，有时系统设计人员故意和/或另外使用更便宜的外部闪存存储器，比如（微）SD/MMC 卡（用于非关键数据），以减轻这种影响，因为它们很容易更换。

让我们继续了解 printk 日志级别。

## 使用 printk 日志级别

为了理解和使用 printk 日志级别，让我们从我们的`helloworld_lkm`内核模块的第一个 printk 开始，重现那一行代码：

```
printk(KERN_INFO "Hello, world\n");
```

现在让我们来解决房间里的大象：`KERN_INFO`到底意味着什么？首先，现在要小心：它*不是*你的本能反应所说的参数。注意它和格式字符串之间没有逗号字符，只有空格。`KERN_INFO`只是内核 printk 记录的**八个**日志级别中的一个。立即要理解的一个关键点是，这个日志级别*不是*任何优先级；它的存在允许我们*根据日志级别过滤消息*。内核为 printk 定义了八个可能的日志级别；它们是：

```
// include/linux/kern_levels.h
#ifndef __KERN_LEVELS_H__
#define __KERN_LEVELS_H__

#define KERN_SOH       "\001"             /* ASCII Start Of Header */
#define KERN_SOH_ASCII '\001'

#define KERN_EMERG    KERN_SOH      "0"   /* system is unusable */
#define KERN_ALERT    KERN_SOH      "1"   /* action must be taken  
                                             immediately */
#define KERN_CRIT     KERN_SOH      "2"   /* critical conditions */
#define KERN_ERR      KERN_SOH      "3"   /* error conditions */
#define KERN_WARNING  KERN_SOH      "4"   /* warning conditions */
#define KERN_NOTICE   KERN_SOH      "5"   /* normal but significant 
                                             condition */
#define KERN_INFO     KERN_SOH      "6"   /* informational */
#define KERN_DEBUG    KERN_SOH      "7"   /* debug-level messages */

#define KERN_DEFAULT  KERN_SOH      "d"   /* the default kernel loglevel */
```

因此，现在我们看到`KERN_<FOO>`日志级别只是被添加到由 printk 发出的内核消息的字符串（"0"、"1"、...、"7"）；没有更多。这使我们有了根据日志级别过滤消息的有用能力。它们右侧的注释清楚地向开发人员显示了何时使用哪个日志级别。

`KERN_SOH`是什么？那就是 ASCII **报头开始**（**SOH**）值`\001`。查看`ascii(7)`的 man 页面；`ascii(1)`实用程序以各种数字基数转储 ASCII 表。从这里，我们可以清楚地看到数字`1`（或`\001`）是`SOH`字符，这里遵循的是一个约定。

让我们快速看一下 Linux 内核源树中的一些实际示例。当内核的`hangcheck-timer`设备驱动程序（有点类似于软件看门狗）确定某个定时器到期（默认为 60 秒）被延迟超过一定阈值（默认为 180 秒）时，它会重新启动系统！在这里，我们展示了相关的内核代码 - `hangcheck-timer`驱动程序在这方面发出`printk`的地方：

```
// drivers/char/hangcheck-timer.c[...]if (hangcheck_reboot) {
  printk(KERN_CRIT "Hangcheck: hangcheck is restarting the machine.\n");
  emergency_restart();
} else {
[...]
```

查看`printk` API 是如何调用的，日志级别设置为`KERN_CRIT`。

另一方面，发出信息消息可能正是医生所开的处方：在这里，我们看到通用并行打印机驱动程序礼貌地通知所有相关方打印机着火了（相当低调，是吧？）

```
// drivers/char/lp.c[...]
 if (last != LP_PERRORP) {
     last = LP_PERRORP;
     printk(KERN_INFO "lp%d on fire\n", minor);
 }
```

您可能会认为设备着火将使`printk`符合“紧急”日志级别...好吧，至少`arch/x86/kernel/cpu/mce/p5.c:pentium_machine_check()`函数遵循了这一点：

```
// arch/x86/kernel/cpu/mce/p5.c
[...]
 pr_emerg("CPU#%d: Machine Check Exception: 0x%8X (type 0x%8X).\n",
         smp_processor_id(), loaddr, lotype);

    if (lotype & (1<<5)) {
        pr_emerg("CPU#%d: Possible thermal failure (CPU on fire ?).\n",
             smp_processor_id());
    } 
[...]
```

（`pr_<foo>()`方便宏将在下面介绍）。

**常见问题解答***：*如果在`printk()`中未指定日志级别，则打印将以什么日志级别发出？默认为`4`，即`KERN_WARNING`（*写入控制台*部分详细说明了为什么）。请注意，您应始终在使用`printk`时指定适当的日志级别。

有一种简单的方法来指定内核消息日志级别。这是我们接下来要深入研究的内容。

### pr_<foo>方便宏

这里提供的方便**`pr_<foo>()`**宏可以减轻编码痛苦。笨拙的

`printk(KERN_FOO "<format-str>");`被优雅地替换为

`pr_foo("<format-str>");`，其中`<foo>`是日志级别；鼓励使用它们：

```
// include/linux/printk.h:
[...]
/*
 * These can be used to print at the various log levels.
 * All of these will print unconditionally, although note that pr_debug()
 * and other debug macros are compiled out unless either DEBUG is defined
 * or CONFIG_DYNAMIC_DEBUG is set.
 */
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
[...]
/* pr_devel() should produce zero code unless DEBUG is defined */
#ifdef DEBUG
#define pr_devel(fmt, ...) \
    printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_devel(fmt, ...) \
    no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif
```

内核允许我们将`loglevel=n`作为内核命令行参数传递，其中`n`是介于`0`和`7`之间的整数，对应于先前提到的八个日志级别。预期的是（很快您将会了解到），所有具有低于传递的日志级别的`printk`实例也将被定向到控制台设备。

直接将内核消息写入控制台设备有时非常有用；下一节将详细介绍如何实现这一点。

### 连接到控制台

回想一下，`printk`输出可能会到达三个位置：

+   第一个是内核内存日志缓冲区（始终）

+   第二个是非易失性日志文件

+   最后一个（我们将在这里讨论）：*控制台设备*

传统上，控制台设备是一个纯内核功能，超级用户登录的初始终端窗口（`/dev/console`）在非图形环境中。有趣的是，在 Linux 上，我们可以定义几个控制台 - 一个**电传打字机终端**（**tty**）窗口（如`/dev/console`），文本模式 VGA，帧缓冲区，甚至是通过 USB 提供的串行端口（这在嵌入式系统开发中很常见；请参阅本章的*进一步阅读*部分中的有关 Linux 控制台的更多信息）。

例如，当我们通过 USB 到 RS232 TTL UART（USB 到串行）电缆将树莓派连接到 x86-64 笔记本电脑时（请参阅本章的*进一步阅读*部分，了解有关这个非常有用的附件以及如何在树莓派上设置它的博客文章！），然后使用`minicom(1)`（或`screen(1)`）获取串行控制台时，这就是显示为`tty`设备的内容 - 它是串行端口：

```
rpi # tty
/dev/ttyS0
```

这里的重点是，控制台通常是*足够重要*的日志消息的目标，包括那些源自内核深处的消息。Linux 的`printk`使用基于`proc`的机制有条件地将其数据传递到控制台设备。为了更好地理解这一点，让我们首先查看相关的`proc`伪文件：

```
$ cat /proc/sys/kernel/printk
4    4    1    7
$ 
```

我们将前面的四个数字解释为 printk 日志级别（`0`为最高，“紧急”级别为`7`为最低）。前面的四个整数序列的含义是这样的：

+   当前（控制台）日志级别

*- 暗示着所有低于此值的消息将出现在控制台设备上！*

+   缺乏显式日志级别的消息的默认级别

+   允许的最低日志级别

+   启动时的默认日志级别

由此可见，日志级别`4`对应于`KERN_WARNING`。因此，第一个数字为`4`（实际上是 Linux 发行版的典型默认值），*所有低于日志级别 4 的 printk 实例将出现在控制台设备上*，当然也会被记录到文件中-实际上，所有以下日志级别的消息：`KERN_EMERG`、`KERN_ALERT`、`KERN_CRIT`和`KERN_ERR`。

日志级别为`0 [KERN_EMERG]`的内核消息*总是*打印到控制台，确实打印到所有终端窗口和内核日志文件，而不受任何设置的影响。

值得注意的是，当在嵌入式 Linux 或任何内核开发中工作时，通常会在控制台设备上工作，就像刚才给出的树莓派示例一样。将`proc printk`伪文件的第一个整数值设置为`8`将*保证所有 printk 实例直接出现在控制台上*，**从而使 printk 的行为类似于常规的 printf！**在这里，我们展示了 root 用户如何轻松设置这一点：

```
# echo "8 4 1 7" > /proc/sys/kernel/printk
```

（当然，这必须以 root 身份完成。）这在开发和测试过程中非常方便。

在我的树莓派上，我保留了一个包含以下行的启动脚本：

`[ $(id -u) -eq 0 ] && echo "8 4 1 7" > /proc/sys/kernel/printk`

因此，以 root 身份运行时，这将生效，所有 printk 实例现在直接出现在`minicom(1)`控制台上，就像`printf`一样。

谈到多功能的树莓派，下一节演示了在树莓派上运行内核模块。

### 将输出写入树莓派控制台

接下来是我们的第二个内核模块！在这里，我们将发出九个 printk 实例，每个实例都在八个日志级别中的一个，另外一个通过`pr_devel()`宏（实际上只是`KERN_DEBUG`日志级别）。让我们来看看相关的代码：

```
// ch4/printk_loglvl/printk_loglvl.c
static int __init printk_loglvl_init(void)
{
    pr_emerg ("Hello, world @ log-level KERN_EMERG   [0]\n");
    pr_alert ("Hello, world @ log-level KERN_ALERT   [1]\n");
    pr_crit  ("Hello, world @ log-level KERN_CRIT    [2]\n");
    pr_err   ("Hello, world @ log-level KERN_ERR     [3]\n");
    pr_warn  ("Hello, world @ log-level KERN_WARNING [4]\n");
    pr_notice("Hello, world @ log-level KERN_NOTICE  [5]\n");
    pr_info  ("Hello, world @ log-level KERN_INFO    [6]\n");
    pr_debug ("Hello, world @ log-level KERN_DEBUG   [7]\n");
    pr_devel("Hello, world via the pr_devel() macro"
        " (eff @KERN_DEBUG) [7]\n");
    return 0; /* success */
}
static void __exit printk_loglvl_exit(void)
{
    pr_info("Goodbye, world @ log-level KERN_INFO [6]\n");
}
module_init(printk_loglvl_init);
module_exit(printk_loglvl_exit);
```

现在，我们将讨论在树莓派设备上运行前述`printk_loglvl`内核模块时的输出。如果您没有或者不方便使用树莓派，那没问题；请继续在 x86-64 虚拟机上尝试。

在树莓派设备上（我在这里使用的是运行默认树莓派 OS 的树莓派 3B+型号），我们登录并通过简单的`sudo -s`获取 root shell。然后我们构建内核模块。如果您在树莓派上安装了默认的树莓派镜像，所有必需的开发工具、内核头文件等都将预先安装！图 4.7 是在树莓派板上运行我们的`printk_loglvl`内核模块的截图。另外，重要的是要意识到我们正在**控制台设备**上运行，因为我们正在使用前面提到的 USB 转串口电缆通过`minicom(1)`终端仿真器应用程序（而不是简单地通过 SSH 连接）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/ad3ab2f1-3279-4131-872f-49d290740d47.png)

图 4.7 - minicom 终端仿真器应用程序窗口-控制台-带有 printk_loglvl 内核模块输出

从 x86-64 环境中注意到一些与之有点不同：在这里，默认情况下，`/proc/sys/kernel/printk`输出的第一个整数-当前控制台日志级别-是 3（而不是 4）。好吧，这意味着所有内核 printk 实例的日志级别低于日志级别 3 将直接出现在控制台设备上。看一下截图：情况确实如此！此外，正如预期的那样，“紧急”日志级别（`0`）的 printk 实例始终出现在控制台上，确实出现在每个打开的终端窗口上。

现在是有趣的部分：让我们（当然是作为 root）将当前控制台日志级别（记住，它是`/proc/sys/kernel/printk`输出中的第一个整数）设置为值`8`。这样，*所有的 printk*实例应该直接出现在控制台上。我们在这里精确测试了这一点：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/4140c171-54f0-4ebf-aca5-ebffc5db9963.png)

图 4.8 - minicom 终端 - 实际上是控制台 - 窗口，控制台日志级别设置为 8

确实，正如预期的那样，我们在控制台设备上看到了*所有*的`printk`实例，无需使用`dmesg`。

不过，等一下：`pr_debug()`和`pr_devel()`宏发出的内核消息在日志级别`KERN_DEBUG`（即整数值`7`）上发生了什么？它在这里*没有*出现，也没有在接下来的`dmesg`输出中出现？我们马上解释这一点，请继续阅读。

当然，通过`dmesg(1)`，所有内核消息（至少是 RAM 中内核日志缓冲区中的消息）都会显示出来。我们在这里看到了这种情况：

```
rpi # rmmod printk_loglvl
rpi # dmesg
[...]
[ 1408.603812] Hello, world @ log-level KERN_EMERG   [0]
[ 1408.611335] Hello, world @ log-level KERN_ALERT   [1]
[ 1408.618625] Hello, world @ log-level KERN_CRIT    [2]
[ 1408.625778] Hello, world @ log-level KERN_ERR     [3]
[ 1408.625781] Hello, world @ log-level KERN_WARNING [4]
[ 1408.625784] Hello, world @ log-level KERN_NOTICE  [5]
[ 1408.625787] Hello, world @ log-level KERN_INFO    [6]
[ 1762.985496] Goodbye, world @ log-level KERN_INFO    [6]
rpi # 
```

除了`KERN_DEBUG`之外的所有`printk`实例都可以通过`dmesg`实用程序查看内核日志来看到。那么，如何显示调试消息呢？接下来会介绍。

### 启用 pr_debug()内核消息

啊是的，`pr_debug()`原来是一个特殊情况：除非为内核模块*定义*了`DEBUG`符号，否则在日志级别`KERN_DEBUG`下的`printk`实例不会显示出来。我们编辑内核模块的 Makefile 以启用这一功能。至少有两种设置方法：

+   将这行插入到 Makefile 中：

```
CFLAGS_printk_loglvl.o := -DDEBUG
```

通用的是`CFLAGS_<filename>.o := -DDEBUG`。

+   我们也可以将这个语句插入到 Makefile 中：

```
EXTRA_CFLAGS += -DDEBUG
```

在我们的 Makefile 中，我们故意保持`-DDEBUG`注释掉，现在，为了尝试它，取消以下注释掉的行中的一个：

```
# Enable the pr_debug() as well (rm the comment from one of the lines below)
#EXTRA_CFLAGS += -DDEBUG
#CFLAGS_printk_loglvl.o := -DDEBUG
```

完成后，我们从内存中删除旧的过时内核模块，重新构建它，并使用我们的`lkm`脚本插入它。输出显示`pr_debug()`现在生效了：

```
# exit                      << exit from the previous root shell >>
$ ../../lkm printk_loglvl Version info:
Distro:     Ubuntu 18.04.3 LTS
Kernel: 5.4.0-llkd01
------------------------------
sudo rmmod printk_loglvl 2> /dev/null
------------------------------
[...]
sudo insmod ./printk_loglvl.ko && lsmod|grep printk_loglvl
------------------------------
printk_loglvl          16384  0
------------------------------
dmesg
------------------------------
[  975.271766] Hello, world @ log-level KERN_EMERG [0]
[  975.277729] Hello, world @ log-level KERN_ALERT [1]
[  975.283662] Hello, world @ log-level KERN_CRIT [2]
[  975.289561] Hello, world @ log-level KERN_ERR [3]
[  975.295394] Hello, world @ log-level KERN_WARNING [4]
[  975.301176] Hello, world @ log-level KERN_NOTICE [5]
[  975.306907] Hello, world @ log-level KERN_INFO [6]
[  975.312625] Hello, world @ log-level KERN_DEBUG [7]
[  975.312628] Hello, world via the pr_devel() macro (eff @KERN_DEBUG) [7]
$
```

`lkm`脚本输出的部分截图（图 4.9）清楚地显示了`dmesg`的颜色编码，`KERN_ALERT / KERN_CRIT / KERN_ERR`的背景以红色/粗体红色字体/红色前景颜色突出显示，`KERN_WARNING`以粗体黑色字体显示，帮助我们人类快速发现重要的内核消息。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/76a8a54e-f3c7-4d0a-9c5f-764cc68d4686.png)

图 4.9 - lkm 脚本输出的部分截图

请注意，当启用动态调试功能（`CONFIG_DYNAMIC_DEBUG=y`）时，`pr_debug()`的行为并不相同。

设备驱动程序作者应该注意，为了发出调试`printk`实例，他们应该避免使用`pr_debug()`。相反，建议设备驱动程序使用`dev_dbg()`宏（另外传递给相关设备的参数）。此外，`pr_devel()`是用于内核内部调试`printk`实例的，其输出在生产系统中永远不应该可见。

现在，回到控制台输出部分。因此，也许出于内核调试的目的（如果没有其他目的），有没有一种保证的方法可以确保*所有*的 printk 实例都被定向到控制台*？*是的，确实 - 只需传递名为`ignore_level`的内核（启动时）参数。有关此更多详细信息，请查阅官方内核文档中的描述：[`www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)。忽略 printk 日志级别也是可能的：如上所述，您可以通过这样做打开忽略 printk 日志级别的功能，从而允许所有 printk 出现在控制台设备上（反之亦然，通过向同一伪文件中回显 N 来关闭它）：

```
sudo bash -c "echo Y > /sys/module/printk/parameters/ignore_loglevel"
```

dmesg(1)实用程序也可以用于通过各种选项开关（特别是--console-level 选项）控制启用/禁用内核消息到控制台设备，以及控制台日志级别（即在该级别以下的消息将出现在控制台上）。我让你浏览一下 dmesg(1)的 man 页面以获取详细信息。

下一部分涉及另一个非常有用的日志记录功能：速率限制。

## 限制 printk 实例的速率

当我们从执行非常频繁的代码路径发出 printk 实例时，printk 实例的数量可能会迅速超出内核日志缓冲区（在 RAM 中；请记住它是一个循环缓冲区），从而覆盖可能是关键信息。此外，不断增长的非易失性日志文件然后几乎无限地重复相同的 printk 实例也不是一个好主意，会浪费磁盘空间，或者更糟糕的是，闪存空间。例如，想象一下在中断处理程序代码路径中有一个大的 printk。如果硬件中断以每秒 100 次的频率被调用，也就是每秒 100 次！

为了缓解这些问题，内核提供了一个有趣的替代方案：*速率限制*printk*。printk_ratelimited()宏的语法与常规 printk 相同；关键点是当满足某些条件时，它会有效地抑制常规打印。内核通过 proc 文件系统提供了两个控制文件，名为 printk_ratelimit 和 printk_ratelimit_burst，用于此目的。在这里，我们直接复制了 sysctl 文档（来自 https://www.kernel.org/doc/Documentation/sysctl/kernel.txt），该文档解释了这两个（伪）文件的确切含义：

```
printk_ratelimit:
Some warning messages are rate limited. printk_ratelimit specifies
the minimum length of time between these messages (in jiffies), by
default we allow one every 5 seconds.
A value of 0 will disable rate limiting.
==============================================================
printk_ratelimit_burst:
While long term we enforce one message per printk_ratelimit
seconds, we do allow a burst of messages to pass through.
printk_ratelimit_burst specifies the number of messages we can
send before ratelimiting kicks in.
```

在我们的 Ubuntu 18.04.3 LTS 客户系统上，我们发现它们（默认）的值如下：

```
$ cat /proc/sys/kernel/printk_ratelimit /proc/sys/kernel/printk_ratelimit_burst
5
10
$ 
```

这意味着默认情况下，在 5 秒的时间间隔内发生的相同消息最多可以通过 10 个实例，然后速率限制才会生效。

当 printk 速率限制器抑制内核 printk 实例时，会发出一条有用的消息，其中提到确切抑制了多少早期的 printk 回调。例如，我们有一个自定义内核模块，它利用 Kprobes 框架在每次调用 schedule()之前发出一个 printk 实例，这是内核的核心调度例程。

Kprobe 本质上是一个用于生产系统故障排除的仪器框架；使用它，您可以指定一个函数，该函数可以在给定内核例程之前或之后执行。细节超出了本书的范围。

现在，由于调度经常发生，常规的 printk 会导致内核日志缓冲区迅速溢出。正是这种情况需要使用速率限制的 printk。在这里，我们看到了我们示例内核模块的一些示例输出（我们这里不显示它的代码），它使用了 printk_ratelimited() API 通过设置一个称为 handle_pre_schedule()的*预处理程序*函数的 kprobe 来设置一个 printk 实例：

```
[ 1000.154763] kprobe schedule pre_handler: intr ctx = 0 :process systemd-journal:237
[ 1005.162183] handler_pre_schedule: 5860 callbacks suppressed
[ 1005.162185] kprobe schedule pre_handler: intr ctx = 0 :process dndX11:1071
```

在 Linux 内核的实时时钟（RTC）驱动程序的中断处理程序代码中，可以看到使用速率限制 printk 的代码级示例，位置在 drivers/char/rtc.c 中：

```
static void rtc_dropped_irq(struct timer_list *unused)
{ 
[...]
    spin_unlock_irq(&rtc_lock);
    printk_ratelimited(KERN_WARNING "rtc: lost some interrupts at         %ldHz.\n", freq);
    /* Now we have new data */
    wake_up_interruptible(&rtc_wait);
[...]
}
```

不要混淆 printk_ratelimited()宏和旧的（现在已弃用的）printk_ratelimit()宏。此外，实际的速率限制代码在 lib/ratelimit.c:___ratelimit()中。

此外，就像我们之前看到的 pr_<foo>宏一样，内核还提供了相应的 pr_<foo>_ratelimited 宏，用于在启用速率限制时以日志级别<foo>生成内核 printk。以下是它们的快速列表：

```
pr_emerg_ratelimited(fmt, ...)
pr_alert_ratelimited(fmt, ...)
pr_crit_ratelimited(fmt, ...) 
pr_err_ratelimited(fmt, ...)  
pr_warn_ratelimited(fmt, ...) 
pr_notice_ratelimited(fmt, ...)
pr_info_ratelimited(fmt, ...)  
```

我们能否从用户空间生成内核级消息？听起来很有趣；这是我们的下一个子主题。

## 从用户空间生成内核消息

我们程序员经常使用的一种流行的调试技术是在代码的各个地方添加打印，这经常可以帮助我们缩小问题的来源。这确实是一种有用的调试技术，称为**instrumenting**代码。内核开发人员经常使用值得尊敬的 printk API 来实现这一目的。

因此，想象一下，您已经编写了一个内核模块，并且正在调试它（通过添加几个 printk）。您的内核代码现在发出了几个 printk 实例，当然，您可以在运行时通过`dmesg`或其他方式看到。这很好，但是，特别是因为您正在运行一些自动化的用户空间测试脚本，您可能希望通过打印某个特定消息来查看脚本在我们的内核模块中启动某个动作的位置。作为一个具体的例子，假设我们希望日志看起来像这样：

```
test_script: msg 1 ; kernel_module: msg n, msg n+1, ..., msg n+m ; test_script: msg 2 ; ...
```

我们的用户空间测试脚本可以像内核的 printk 一样，将消息写入内核日志缓冲区，通过写入特殊的`/dev/kmsg`设备文件：

```
echo "test_script: msg 1" > /dev/kmsg
```

嗯，等一下 - 这样做当然需要以 root 访问权限运行。但是，请注意，这里简单的在`echo`之前加上`sudo(8)`是行不通的：

```
$ sudo echo "test_script: msg 1" > /dev/kmsg
bash: /dev/kmsg: Permission denied
$ sudo bash -c "echo \"test_script: msg 1\" > /dev/kmsg"
[sudo] password for llkd:
$ dmesg |tail -n1
[55527.523756] test_script: msg 1
$ 
```

第二次尝试中使用的语法是有效的，但是更简单的方法是获取一个 root shell 并执行此类任务。

还有一件事：`dmesg(1)`实用程序有几个选项，旨在使输出更易读；我们通过我们的`dmesg`的示例别名显示了其中一些选项，之后我们使用它。

```
$ alias dmesg='/bin/dmesg --decode --nopager --color --ctime'
$ dmesg | tail -n1
user :warn : [Sat Dec 14 17:21:50 2019] test_script: msg 1
$ 
```

通过特殊的`/dev/kmsg`设备文件写入内核日志的消息将以当前默认的日志级别打印，通常是`4 : KERN_WARNING`。我们可以通过实际在消息前加上所需的日志级别（作为字符串格式的数字）来覆盖这一点。例如，要在用户空间中以日志级别`6 : KERN_INFO`写入内核日志，使用以下命令：

```
$ sudo bash -c "echo \"<6>test_script: test msg at KERN_INFO\"   \
   > /dev/kmsg"
$ dmesg | tail -n2
user :warn : [Fri Dec 14 17:21:50 2018] test_script: msg 1
user :info : [Fri Dec 14 17:31:48 2018] test_script: test msg at KERN_INFO
```

我们可以看到我们后来的消息是以日志级别`6`发出的，就像`echo`中指定的那样。

用户生成的内核消息和内核`printk()`生成的消息之间实际上没有办法区分；它们看起来是一样的。因此，当然，可以简单地在消息中插入一些特殊的签名字节或字符串，例如`@user@`，以帮助您区分这些用户生成的打印消息和内核消息。

## 通过 pr_fmt 宏标准化 printk 输出

关于内核 printk 的最后一个但重要的一点；经常，为了给您的`printk()`输出提供上下文（*它到底发生在哪里？*），您可能会像这样编写代码，利用各种 gcc 宏（如`__FILE__`、`__func__`和`__LINE__`）。

```
pr_warning("%s:%s():%d: kmalloc failed!\n", OURMODNAME,  __func__, __LINE__);
```

这很好；问题是，如果您的项目中有很多 printk，要保证标准的 printk 格式（例如，首先显示模块名称，然后是函数名称，可能还有行号，就像这里看到的那样）总是由项目中的每个人遵循，这可能会相当痛苦。

输入`pr_fmt`宏；在代码的开头定义这个宏（必须在第一个`#include`之前），可以保证代码中每个后续的 printk 都将以这个宏指定的格式为前缀。让我们举个例子（我们展示了下一章的代码片段；不用担心，它真的非常简单，可以作为您未来内核模块的模板）。

```
// ch5/lkm_template/lkm_template.c
[ ... ]
 */
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
[ ... ]
static int __init lkm_template_init(void)
{
    pr_info("inserted\n");
    [ ... ]
```

`pr_fmt()`宏以粗体字突出显示；它使用预定义的`KBUILD_MODNAME`宏来替换您的内核模块的名称，并使用 gcc 的`__func__`指定符来显示我们当前运行的函数的名称！（您甚至可以添加一个`%d`，与相应的`__LINE__`宏匹配，以显示行号）。因此，最重要的是：我们在这个 LKM 的`init`函数中发出的`pr_info()`将在内核日志中显示如下：

```
[381534.391966] lkm_template:lkm_template_init(): inserted
```

注意 LKM 名称和函数名称是自动添加前缀的。这非常有用，而且非常常见；在内核中，成百上千的源文件以`pr_fmt()`开头。(在 5.4 内核代码库中快速搜索发现代码库中有超过 2000 个此宏的实例！我们也将遵循这个惯例，尽管并非所有的演示内核模块都是如此)。

`pr_fmt()`也影响了驱动程序作者推荐的 printk 使用方式 - 通过`dev_<foo>()`函数。

## 可移植性和 printk 格式说明符

关于多功能的 printk 内核 API，有一个问题需要考虑，那就是如何确保你的 printk 输出在任何 CPU 上看起来正确（格式正确）并且同样适用，无论位宽如何？这里涉及到可移植性问题；好消息是，熟悉提供的各种格式说明符将在这方面帮助你很多，实际上可以让你编写与体系结构无关的 printk。

重要的是要意识到`size_t` - 发音为*size type* - 是无符号整数的`typedef`；同样，`ssize_t`（*signed size type*）是有符号整数的`typedef`。

以下是一些常见的`printk`格式说明符，当编写可移植代码时要记住：

+   对于`size_t`，`ssize_t`（有符号和无符号）整数：分别使用`%zd`和`%zu`

+   内核指针：使用`%pK`进行安全处理（散列值），使用`%px`表示实际指针（在生产中不要使用！），另外，使用`%pa`表示物理地址（必须通过引用传递）

+   原始缓冲区作为十六进制字符的字符串：`%*ph`（其中`*`被字符的数量替换；用于 64 个字符以内的缓冲区，使用`print_hex_dump_bytes()`例程进行更多操作）；还有其他变体（请参阅内核文档，链接如下）

+   使用`%pI4`表示 IPv4 地址，使用`%pI6`表示 IPv6 地址（也有变体）

printk 格式说明符的详尽列表，以及何时使用（附有示例）是官方内核文档的一部分：[`www.kernel.org/doc/Documentation/printk-formats.txt`](https://www.kernel.org/doc/Documentation/printk-formats.txt)。内核还明确记录了在`printk()`语句中使用未装饰的`%p`可能会导致安全问题（链接：[`www.kernel.org/doc/html/latest/process/deprecated.html#p-format-specifier`](https://www.kernel.org/doc/html/latest/process/deprecated.html#p-format-specifier)）。我建议你浏览一下！

好了！让我们通过学习内核模块的 Makefile 如何构建内核来完成本章的内容。

# 理解内核模块 Makefile 的基础知识。

你可能已经注意到，我们倾向于遵循一种*每个目录一个内核模块*的规则。是的，这确实有助于保持事情井然有序。因此，让我们来看看我们的第二个内核模块，`ch4/printk_loglvl`。要构建它，我们只需`cd`到它的文件夹，输入`make`，然后（祈祷！）完成。我们有了`printk_loglevel.ko`内核模块对象（然后我们可以使用`insmod(8)/rmmod(8)`）。但是当我们输入`make`时，它究竟是如何构建的呢？啊，解释这一点正是本节的目的。

由于这是我们处理 LKM 框架及其相应 Makefile 的第一章，我们将保持事情简单，特别是在这里的 Makefile 方面。然而，在接下来的章节中，我们将介绍一个更复杂、更简单*更好*的 Makefile（仍然很容易理解）。然后我们将在所有后续的代码中使用这个更好的 Makefile；请留意并使用它！

正如你所知，`make`命令默认会在当前目录中查找名为`Makefile`的文件；如果存在，它将解析并执行其中指定的命令序列。这是我们的内核模块`printk_loglevel`项目的`Makefile`：

```
// ch4/printk_loglvl/Makefile
PWD       := $(shell pwd)obj-m     += printk_loglvl.o

# Enable the pr_debug() as well (rm the comment from the line below)
#EXTRA_CFLAGS += -DDEBUG
#CFLAGS_printk_loglvl.o := -DDEBUG

all:
    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
```

Unix 的`Makefile`语法基本上要求这样做：

```
target: [dependent-source-file(s)]
        rule(s)
```

`rule(s)`实例总是以`[Tab]`字符为前缀，而不是空格。

让我们了解一下这个 Makefile 的基本工作原理。首先，一个关键点是：内核的`Kbuild`系统（我们自第二章以来一直在提及和使用，*从源代码构建 5.x Linux 内核-第一部分*），主要使用两个软件变量字符串进行构建，这两个变量字符串在两个`obj-y`和`obj-m`变量中链接起来。

`obj-y`字符串包含要构建并*合并*到最终内核镜像文件中的所有对象的连接列表-未压缩的`vmlinux`和压缩（可引导）`[b]zImage`镜像。想一想-这是有道理的：`obj-y`中的`y`代表*Yes*。所有内核内置和`Kconfig`选项在内核配置过程中设置为`Y`（或默认为`Y`）的都通过此项链接在一起，构建，并最终通过`Kbuild`构建系统编织到最终的内核镜像文件中。

另一方面，现在很容易看到`obj-m`字符串是所有内核对象的连接列表，要*分别*构建为*内核模块*！这正是为什么我们的 Makefile 有这一重要行：

```
obj-m += printk_loglvl.o
```

实际上，它告诉`Kbuild`系统包括我们的代码；更正确地说，它告诉它隐式地将`printk_loglvl.c`源代码编译成`printk_loglvl.o`二进制对象，然后将此对象添加到`obj-m`列表中。接下来，由于`make`的默认规则是`all`规则，它被处理：

```
all:
    make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
```

这个单一语句的处理非常复杂；以下是发生的事情：

1.  `-C`选项开关到`make`使`make`进程*更改目录*（通过`chdir(2)`系统调用）到跟在`-C`后面的目录名。因此，它会更改到内核`build`文件夹（正如我们之前介绍的，这是通过`kernel-headers`包安装的`有限`内核源树的位置）。

1.  一旦到达那里，它就会*解析*内核*顶层*Makefile 的内容-也就是说，位于这个有限内核源树根目录中的 Makefile。这是一个关键点。这样可以保证所有内核模块与它们正在构建的内核紧密耦合（稍后会详细介绍）。这也保证了内核模块使用与内核镜像本身完全相同的一组规则构建，即编译器/链接器配置（`CFLAGS`选项，编译器选项开关等）。所有这些都是二进制兼容性所必需的。

1.  接下来，您可以看到变量`M`的初始化，指定的目标是`modules`；因此，`make`进程现在更改到由`M`变量指定的目录，您可以看到它设置为`$(PWD)` - 我们开始的文件夹（当前工作目录；Makefile 中的`PWD := $(shell pwd)`将其初始化为正确的值）！

有趣的是，这是一个递归构建：构建过程，非常重要的是，解析了内核顶层 Makefile 后，现在切换回内核模块的目录并构建其中的模块。

您是否注意到，构建内核模块时，还会生成相当多的中间工作文件？其中包括`modules.order`、`<file>.mod.c`、`<file>.o`、`Module.symvers`、`<file>.mod.o`、`.<file>.o.cmd`、`.<file>.ko.cmd`、一个名为`.tmp_versions/`的文件夹，当然还有内核模块二进制对象本身，`<file>.ko`-整个构建过程的重点。摆脱所有这些对象，包括内核模块对象本身，很容易：只需执行`make clean`。`clean`规则会将所有这些清理干净。（我们将在下一章中深入探讨`install`目标。）

您可以在这里查找`modules.order`和`modules.builtin`文件（以及其他文件）的用途：`Documentation/kbuild/kbuild.rst`。

另外，正如之前提到的，我们将在接下来的章节中介绍并使用一个更复杂的 Makefile 变体 - **一个更好的 Makefile**；它旨在帮助您，内核模块/驱动程序开发人员，通过运行与内核编码风格检查、静态分析、简单打包以及（一个虚拟目标）相关的目标，提高代码质量。

随着这一章的结束，我们结束了。干得好 - 您现在已经在学习 Linux 内核开发的道路上取得了良好的进展！

# 摘要

在本章中，我们介绍了 Linux 内核架构和 LKM 框架的基础知识。您了解了什么是内核模块以及它的用途。然后，我们编写了一个简单但完整的内核模块，一个非常基本的*Hello, world*。然后，材料进一步深入探讨了它的工作原理，以及如何加载它，查看模块列表并卸载它。详细介绍了使用 printk 进行内核日志记录，以及限制 printk 的速率，从用户空间生成内核消息，标准化其输出格式，并了解内核模块 Makefile 的基础知识。

这结束了本章；我敦促你去研究示例代码（通过本书的 GitHub 存储库），完成*问题*/作业，然后继续下一章，继续我们的 Linux 内核模块编写覆盖范围。

# 问题

最后，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会发现一些问题的答案在书的 GitHub 存储库中：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入了解有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）的*进一步阅读*文档。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。


# 第五章：编写您的第一个内核模块-LKMs 第二部分

本章是关于**可加载内核模块**（**LKM**）框架及如何使用它编写内核模块的覆盖的后半部分。为了充分利用它，我希望您在阅读本章之前完成上一章，并尝试那里的代码和问题。

在本章中，我们将继续上一章的内容。在这里，我们将介绍如何使用“更好”的 Makefile 来编写 LKMs，为 ARM 平台交叉编译内核模块（作为典型示例），模块堆叠是什么以及如何执行，以及如何设置和使用模块参数。在此过程中，除其他事项外，您还将了解内核 API/ABI 的稳定性（或者说，缺乏稳定性！），编写用户空间和内核代码之间的关键区别，系统启动时自动加载内核模块以及安全性问题以及如何解决它们。最后，我们将介绍内核文档（包括编码风格）和对主线的贡献。

简而言之，本章将涵盖以下主题：

+   一个“更好”的内核模块 Makefile 模板

+   交叉编译内核模块

+   收集最小系统信息

+   许可内核模块

+   为内核模块模拟“类库”功能

+   向内核模块传递参数

+   内核中不允许浮点数

+   系统启动时自动加载模块

+   内核模块和安全性-概述

+   内核开发人员的编码风格指南

+   为主线内核做出贡献

# 技术要求

本章的技术要求——所需的软件包——与第四章中的*技术要求*部分所示的内容相同，请参考。您可以在本书的 GitHub 存储库中找到本章的源代码。使用以下命令进行克隆：

```
git clone https://github.com/PacktPublishing/Linux-Kernel-Programming
```

书中显示的代码通常只是相关片段。请跟随存储库中的完整源代码。对于本章（以及随后的章节），有关技术要求的更多信息请参阅以下部分。

# 一个“更好”的内核模块 Makefile 模板

上一章向您介绍了用于从源代码生成内核模块、安装和清理的 Makefile。然而，正如我们在那里简要提到的，我现在将介绍我认为更好的“更好”的 Makefile，并解释它为什么更好。

最终，我们都必须编写更好、更安全的代码——无论是用户空间还是内核空间。好消息是，有几种工具可以帮助改进代码的健壮性和安全性，其中包括静态和动态分析器（在第一章中已经提到了几种，*内核工作空间设置*，我就不在这里重复了）。

我设计了一个简单但有用的内核模块 Makefile“模板”，其中包括几个目标，可帮助您运行这些工具。这些目标使您可以非常轻松地执行有价值的检查和分析；*可能是您会忘记、忽视或永远推迟的事情！* 这些目标包括以下内容：

+   “通常”的目标——`build`、`install`和`clean`。

+   内核编码风格生成和检查（通过`indent(1)`和内核的`checkpatch.pl`脚本，分别）。

+   内核静态分析目标（`sparse`、`gcc`和`flawfinder`），并提到**Coccinelle**。

+   一对“虚拟”的内核动态分析目标（`KASAN`和`LOCKDEP / CONFIG_PROVE_LOCKING`），鼓励您为所有测试用例配置、构建和使用“调试”内核。

+   一个简单的`tarxz-pkg`目标，将源文件打包并压缩到前一个目录。这使您可以将压缩的`tar-xz`文件传输到任何其他 Linux 系统，并在那里提取和构建 LKM。

+   一个“虚拟”的动态分析目标，指出您应该投入时间来配置和构建一个“调试”内核，并使用它来捕捉错误！（稍后将更多内容）

您可以在`ch5/lkm_template`目录中找到代码（以及`README`文件）。为了帮助您理解其用途和功能，并帮助您入门，以下图简单地显示了当运行其`help`目标时代码产生的输出的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/e357b706-c9dd-4dee-8bad-ac4ef8eb037a.png)

图 5.1 - 来自我们“更好”的 Makefile 的 helptarget 的输出

在*图 5.1*中，我们首先执行`make`，然后按两次*Tab*键，这样它就会显示所有可用的目标。请仔细研究并使用它！例如，运行`make sa`将导致它在您的代码上运行所有**静态分析**（`sa`）目标！

还需要注意的是，使用这个 Makefile 将需要您在系统上安装一些软件包/应用程序；这些包括（对于基本的 Ubuntu 系统）`indent(1)`，`linux-headers-$(uname -r)`，`sparse(1)`，`flawfinder(1)`，`cppcheck(1)`和`tar(1)`。（第一章，*内核工作区设置*，已经指出这些应该被安装）。

另外，请注意，Makefile 中所谓的**动态分析**（`da`）目标仅仅是不做任何事情，只是打印一条消息的虚拟目标。它们只是*提醒您*通过在适当配置的“调试”内核上运行代码来彻底测试您的代码！

说到“调试”内核，下一节将向您展示如何配置一个。

## 配置“调试”内核

（有关配置和构建内核的详细信息，请参阅第二章，*从源代码构建 5.x Linux 内核-第一部分*，和第三章，*从源代码构建 5.x Linux 内核-第二部分*）。

在*调试内核*上运行代码可以帮助您发现难以发现的错误和问题。我强烈建议在开发和测试期间这样做！在这里，我至少希望您配置您的自定义 5.4 内核，使以下内核调试配置选项打开（在`make menuconfig`界面中，您会发现大多数选项在`Kernel Hacking`子菜单下；以下列表是针对 Linux 5.4.0 的）：

+   `CONFIG_DEBUG_INFO`

+   `CONFIG_DEBUG_FS`（`debugfs`伪文件系统）

+   `CONFIG_MAGIC_SYSRQ`（Magic SysRq 热键功能）

+   `CONFIG_DEBUG_KERNEL`

+   `CONFIG_DEBUG_MISC`

+   内存调试：

+   `CONFIG_SLUB_DEBUG`。

+   `CONFIG_DEBUG_MEMORY_INIT`。

+   `CONFIG_KASAN`：这是**内核地址消毒剂**端口；但是，截至撰写本文时，它仅适用于 64 位系统。

+   `CONFIG_DEBUG_SHIRQ`

+   `CONFIG_SCHED_STACK_END_CHECK`

+   锁调试：

+   `CONFIG_PROVE_LOCKING`：非常强大的`lockdep`功能来捕获锁定错误！这将打开其他几个锁调试配置，详细说明在第十三章，*内核同步-第二部分*。

+   `CONFIG_LOCK_STAT`

+   `CONFIG_DEBUG_ATOMIC_SLEEP`

+   `CONFIG_STACKTRACE`

+   `CONFIG_DEBUG_BUGVERBOSE`

+   `CONFIG_FTRACE`（`ftrace`：在其子菜单中，至少打开一些“跟踪器”）

+   `CONFIG_BUG_ON_DATA_CORRUPTION`

+   `CONFIG_KGDB`（内核 GDB；可选）

+   `CONFIG_UBSAN`

+   `CONFIG_EARLY_PRINTK`

+   `CONFIG_DEBUG_BOOT_PARAMS`

+   `CONFIG_UNWINDER_FRAME_POINTER`（选择`FRAME_POINTER`和`CONFIG_STACK_VALIDATION`）

需要注意的几件事：

a) 如果您现在不明白先前提到的所有内核调试配置选项的作用，也不要太担心；在您完成本书时，大多数选项都会变得清晰起来。

b) 打开一些`Ftrace`跟踪器（或插件），例如`CONFIG_IRQSOFF_TRACER`，这在我们的*Linux 内核编程（第二部分）*书中的*处理硬件中断*章节中实际上会有用；（请注意，尽管 Ftrace 本身可能默认启用，但并非所有跟踪器都是默认启用的）。

请注意，打开这些配置选项*确实*会带来性能损失，但没关系。我们正在运行这种“调试”内核，目的是*捕捉错误和漏洞*（尤其是难以发现的种类！）。它确实可以拯救生命！在你的项目中，*你的工作流程应该涉及你的代码在以下两者上进行测试和运行*：

+   *调试*内核系统，其中所有必需的内核调试配置选项都已打开（如先前所示的最小配置）

+   *生产*内核系统（在其中所有或大部分先前的内核调试选项将被关闭）

毋庸置疑，我们将在本书中所有后续的 LKM 代码中使用先前的 Makefile 风格。

好了，现在你已经准备好了，让我们来探讨一个有趣且实际的场景-为另一个目标（通常是 ARM）编译你的内核模块。

# 交叉编译内核模块

在第三章中，*从源代码构建 5.x Linux 内核-第二部分*，在*为树莓派构建内核*部分，我们展示了如何为“外部”目标架构（如 ARM、PowerPC、MIPS 等）交叉编译 Linux 内核。基本上，对于内核模块也可以做同样的事情；通过适当设置“特殊”的`ARCH`和`CROSS_COMPILE`环境变量，可以轻松地交叉编译内核模块。

例如，假设我们正在开发一个嵌入式 Linux 产品；我们的代码将在一个具有 AArch32（ARM-32）CPU 的目标设备上运行。为什么不举一个实际的例子。让我们为树莓派 3 *单板计算机*（**SBC**）交叉编译我们的*Hello, world*内核模块！

这很有趣。你会发现，尽管看起来简单直接，但我们最终会进行四次迭代才成功。为什么？继续阅读以了解详情。

## 为交叉编译设置系统

交叉编译内核模块的先决条件非常明确：

+   我们需要为目标系统安装*内核源树*，作为主机系统工作空间的一部分，通常是 x86_64 台式机（对于我们的示例，使用树莓派作为目标，请参考官方树莓派文档：[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)）。

+   现在我们需要一个交叉工具链。通常，主机系统是 x86_64，而目标是 ARM-32，因此我们需要一个*x86_64 到 ARM32 的交叉工具链*。同样，正如在第三章中明确提到的，*从源代码构建 5.x Linux 内核-第二部分*，*为树莓派构建内核*，你必须下载并安装 Raspberry Pi 特定的 x86_64 到 ARM 工具链作为主机系统工作空间的一部分（请参考第三章，*从源代码构建 5.x Linux 内核-第二部分*，了解如何安装工具链）。

好了，从这一点开始，我将假设你已经安装了 x86_64 到 ARM 交叉工具链。我还将假设*工具链前缀*是`arm-linux-gnueabihf-`；我们可以通过尝试调用`gcc`交叉编译器来快速检查工具链是否已安装并将其二进制文件添加到路径中：

```
$ arm-linux-gnueabihf-gcc
arm-linux-gnueabihf-gcc: fatal error: no input files
compilation terminated.
$ 
```

它可以工作-只是我们没有传递任何 C 程序作为编译参数，因此它会报错。

你也可以使用`arm-linux-gnueabihf-gcc --version`命令查看编译器版本。

## 尝试 1-设置“特殊”的环境变量

实际上，交叉编译内核模块非常容易（或者我们认为是这样！）。只需确保适当设置“特殊”的`ARCH`和`CROSS_COMPILE`环境变量。按照以下步骤进行：

1.  让我们重新为树莓派目标构建我们的第一个*Hello, world*内核模块。以下是构建方法：

为了不破坏原始代码，我们创建一个名为`cross`的新文件夹，其中包含从第四章复制的（helloworld_lkm）代码，*编写你的第一个内核模块 - LKMs 第一部分*。

```
cd <dest-dir>/ch5/cross
```

这里，`<dest-dir>`是书的 GitHub 源树的根目录。

1.  现在，运行以下命令：

```
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```

但它并不会立即起作用（或者可能会起作用；请参阅以下信息框）。我们会得到编译失败，如下所示：

```
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make -C /lib/modules/5.4.0-llkd01/build/ M=/home/llkd/book_llkd/Linux-Kernel-Programming/ch5/cross modules
make[1]: Entering directory '/home/llkd/kernels/linux-5.4'
  CC [M]  /home/llkd/book_llkd/Linux-Kernel-Programming/ch5/cross/helloworld_lkm.o
arm-linux-gnueabihf-gcc: error: unrecognized command line option ‘-fstack-protector-strong’
scripts/Makefile.build:265: recipe for target '/home/llkd/book_llkd/Linux-Kernel-Programming/ch5/cross/helloworld_lkm.o' failed
[...]
make: *** [all] Error 2
$ 
```

为什么失败了？

假设所有工具都按照之前讨论的技术要求设置好，交叉编译应该可以工作。这是因为书中提供的`Makefile`是一个正确工作的，树莓派内核已经正确配置和构建，设备已经引导到这个内核，并且内核模块已经针对它进行了编译。在这本书中，这里的目的是解释细节；因此，我们从没有假设开始，并引导您正确执行交叉编译的过程。

前面的交叉编译尝试失败的线索在于，它试图使用 - *构建对* - 当前*主机系统*的内核源，而不是目标的内核源树。因此，*我们需要修改* *Makefile* *以指向目标的正确内核源树*。这样做真的很容易。在下面的代码中，我们看到了（已更正的）Makefile 代码的典型写法：

```
# ch5/cross/Makefile:
# To support cross-compiling for kernel modules:
# For architecture (cpu) 'arch', invoke make as:
# make ARCH=<arch> CROSS_COMPILE=<cross-compiler-prefix> 
ifeq ($(ARCH),arm)
  # *UPDATE* 'KDIR' below to point to the ARM Linux kernel source tree on 
  # your box
  KDIR ?= ~/rpi_work/kernel_rpi/linux
else ifeq ($(ARCH),arm64)
  # *UPDATE* 'KDIR' below to point to the ARM64 (Aarch64) Linux kernel 
  # source tree on your box
  KDIR ?= ~/kernel/linux-4.14
else ifeq ($(ARCH),powerpc)
  # *UPDATE* 'KDIR' below to point to the PPC64 Linux kernel source tree  
  # on your box
  KDIR ?= ~/kernel/linux-4.9.1
else
  # 'KDIR' is the Linux 'kernel headers' package on your host system; this 
  # is usually an x86_64, but could be anything, really (f.e. building 
  # directly on a Raspberry Pi implies that it's the host)
  KDIR ?= /lib/modules/$(shell uname -r)/build
endif

PWD          := $(shell pwd)
obj-m        += helloworld_lkm.o
EXTRA_CFLAGS += -DDEBUG

all:
    @echo
    @echo '--- Building : KDIR=${KDIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=${EXTRA_CFLAGS} ---'
    @echo
    make -C $(KDIR) M=$(PWD) modules
[...]
```

仔细查看（在前一节中解释的新的和“更好”的）Makefile，您将看到它是如何工作的：

+   最重要的是，我们有条件地设置`KDIR`变量，根据`ARCH`环境变量的值指向正确的内核源树（当然，我已经用一些内核源树的路径名作为 ARM[64]和 PowerPC 的示例；请用实际的内核源树路径替换路径名）

+   像往常一样，我们设置`obj-m += <module-name>.o`。

+   我们还设置`CFLAGS_EXTRA`以添加`DEBUG`符号（这样`DEBUG`符号就在我们的 LKM 中定义了，甚至`pr_debug()/pr_devel()`宏也可以工作）。

+   `@echo '<...>'`行等同于 shell 的`echo`命令；它只是在构建时发出一些有用的信息（`@`前缀隐藏了 echo 语句本身的显示）。

+   最后，我们有“通常”的 Makefile 目标：`all`，`install`和`clean` - 这些与之前相同，*除了*这个重要的变化：**我们让它改变目录**（通过`-C`开关）到`KDIR`的值！

+   尽管在上述代码中没有显示，但这个“更好”的 Makefile 有几个额外有用的目标。您应该花时间去探索和使用它们（如前一节所述；首先，只需输入`make help`，研究输出并尝试一些东西）。

完成所有这些后，让我们使用这个版本重试交叉编译并看看结果如何。

## 尝试 2 - 将 Makefile 指向目标的正确内核源树

现在，有了前一节中描述的*增强*Makefile，它*应该*可以工作。在我们将尝试这个的新目录中 - `cross`（因为我们是交叉编译，不是因为我们生气！） - 请按照以下步骤操作：

1.  使用适用于交叉编译的`make`命令尝试构建（第二次）。

```
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- 
--- Building : KDIR=~/rpi_work/kernel_rpi/linux ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- EXTRA_CFLAGS=-DDEBUG ---

make -C ~/rpi_work/kernel_rpi/linux M=/home/llkd/booksrc/ch5/cross modules
make[1]: Entering directory '/home/llkd/rpi_work/kernel_rpi/linux'

ERROR: Kernel configuration is invalid.
 include/generated/autoconf.h or include/config/auto.conf are missing.
 Run 'make oldconfig && make prepare' on kernel src to fix it.

 WARNING: Symbol version dump ./Module.symvers
 is missing; modules will have no dependencies and modversions.
[...]
make: *** [all] Error 2
$ 
```

实际失败的原因是，我们正在编译内核模块的树莓派内核仍处于“原始”状态。它甚至没有`.config`文件（以及其他所需的头文件，如前面的输出所告知的）存在于其根目录中，它需要（至少）被配置。

1.  为了解决这个问题，请切换到您的树莓派内核源树的根目录，并按照以下步骤操作：

```
$ cd ~/rpi-work/kernel_rpi/linux $ make ARCH=arm bcmrpi_defconfig
#
# configuration written to .config
#
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- oldconfig
scripts/kconfig/conf --oldconfig Kconfig
#
# configuration written to .config
#
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- prepare
scripts/kconfig/conf --silentoldconfig Kconfig
 CHK include/config/kernel.release
 UPD include/config/kernel.release
 WRAP arch/arm/include/generated/asm/bitsperlong.h
 WRAP arch/arm/include/generated/asm/clkdev.h
 [...]
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
 CHK include/config/kernel.release
 CHK include/generated/uapi/linux/version.h
 CHK include/generated/utsrelease.h
 [...]
 HOSTCC scripts/recordmcount
 HOSTCC scripts/sortextable
 [...]
$
```

请注意，这些步骤实际上与执行树莓派内核的部分构建非常相似！实际上，如果您已经按照第三章中所述的方式构建（交叉编译）了内核，*从源代码构建 5.x Linux 内核 - 第二部分*，那么内核模块的交叉编译应该可以在这里看到的中间步骤无需工作。

## 尝试 3 - 交叉编译我们的内核模块

现在我们在主机系统上有一个配置好的树莓派内核源树和增强的 Makefile（参见*尝试 2 - 将 Makefile 指向目标的正确内核源树*部分），它*应该*可以工作。让我们重试一下：

1.  我们（再次）尝试构建（交叉编译）内核。像往常一样，发出`make`命令，同时传递`ARCH`和`CROSS_COMPILE`环境变量：

```
$ ls -l
total 12
-rw-rw-r-- 1 llkd llkd 1456 Mar 18 17:48 helloworld_lkm.c
-rw-rw-r-- 1 llkd llkd 6470 Jul  6 17:30 Makefile
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- --- Building : KDIR=~/rpi_work/kernel_rpi/linux ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- EXTRA_CFLAGS=-DDEBUG ---

make -C ~/rpi_work/kernel_rpi/linux M=/home/llkd/booksrc/ch5/cross modules
make[1]: Entering directory '/home/llkd/rpi_work/kernel_rpi/linux' 
 WARNING: Symbol version dump ./Module.symvers
 is missing; modules will have no dependencies and modversions.

Building for: ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- EXTRA_CFLAGS= -DDEBUG
 CC [M] /home/llkd/book_llkd/Linux-Kernel-Programming/ch5/cross/helloworld_lkm.o
​  Building modules, stage 2.
  MODPOST 1 modules
  CC /home/llkd/booksrc/ch5/cross/helloworld_lkm.mod.o
  LD [M] /home/llkd/booksrc/ch5/cross/helloworld_lkm.ko
make[1]: Leaving directory '/home/llkd/rpi_work/kernel_rpi/linux'
$ file ./helloworld_lkm.ko 
./helloworld_lkm.ko: ELF 32-bit LSB relocatable, ARM, EABI5 version 1 (SYSV), BuildID[sha1]=17...e, not stripped
$
```

构建成功！`helloworld_lkm.ko`内核模块确实已经针对 ARM 架构进行了交叉编译（使用树莓派交叉工具链和内核源树）。

我们现在可以忽略关于`Module.symvers`文件的前面警告。因为（在这里）整个树莓派内核尚未构建。

另外，值得一提的是，在运行 GCC 9.x 或更高版本和内核版本为 4.9 或更高版本的最近主机上，会发出一些编译器属性警告。当我尝试使用`arm-linux-gnueabihf-gcc`版本 9.3.0 和树莓派内核版本 4.14.114 交叉编译这个内核模块时，会发出诸如此类的警告：

./include/linux/module.h:131:6: 警告：'init_module'指定的属性比其目标'helloworld_lkm_init'更少限制：'cold' [-Wmissing-attributes]

Miguel Ojeda 指出了这一点（[`lore.kernel.org/lkml/CANiq72=T8nH3HHkYvWF+vPMscgwXki1Ugiq6C9PhVHJUHAwDYw@mail.gmail.com/`](https://lore.kernel.org/lkml/CANiq72=T8nH3HHkYvWF+vPMscgwXki1Ugiq6C9PhVHJUHAwDYw@mail.gmail.com/)），甚至生成了一个处理此问题的补丁（[`github.com/ojeda/linux/commits/compiler-attributes-backport`](https://github.com/ojeda/linux/commits/compiler-attributes-backport)）。截至撰写本文时，该补丁已应用于内核主线和*最近的*树莓派内核（因此，`rpi-5.4.y`分支可以正常工作，但较早的分支，如`rpi-4.9.y`分支似乎没有）！因此会出现编译器警告...实际上，如果您看到这些警告，请将树莓派分支更新到`rpi-5.4.y`或更高版本（或者暂时忽略它们）。

1.  然而，实践出真知。因此，我们启动树莓派，通过`scp(1)`将交叉编译的内核模块对象文件传输到它，然后在树莓派上的`ssh(1)`会话中尝试它（以下输出直接来自设备）：

```
$ sudo insmod ./helloworld_lkm.ko insmod: ERROR: could not insert module ./helloworld_lkm.ko: Invalid module format $ 
```

很明显，前面代码中的`insmod(8)`失败了！*重要的是要理解为什么。*

这实际上与我们试图加载模块的内核版本不匹配以及模块已编译的内核版本有关。

1.  在树莓派上登录后，打印出我们正在运行的当前树莓派内核版本，并使用`modinfo(8)`实用程序打印出有关内核模块本身的详细信息：

```
rpi ~ $ cat /proc/version 
Linux version 4.19.75-v7+ (dom@buildbot) (gcc version 4.9.3 (crosstool-NG crosstool-ng-1.22.0-88-g8460611)) #1270 SMP Tue Sep 24 18:45:11 BST 2019
rpi ~ $ modinfo ./helloworld_lkm.ko 
filename: /home/pi/./helloworld_lkm.ko
version: 0.1
license: Dual MIT/GPL
description: LLKD book:ch5/cross: hello, world, our first Raspberry Pi LKM
author: Kaiwan N Billimoria
srcversion: 7DDCE78A55CF6EDEEE783FF
depends: 
name: helloworld_lkm
vermagic: 5.4.51-v7+ SMP mod_unload modversions ARMv7 p2v8 
rpi ~ $ 
```

从前面的输出中，很明显，我们在树莓派上运行`4.19.75-v7+`内核。实际上，这是我在设备的 microSD 卡上安装*默认*Raspbian OS 时继承的内核（这是一个故意引入的场景，最初*不*使用我们为树莓派早期构建的 5.4 内核）。另一方面，内核模块显示它已经针对`5.4.51-v7+` Linux 内核进行了编译（来自`modinfo(8)`的`vermagic`字符串显示了这一点）。*很明显，存在不匹配。*那又怎样呢？

Linux 内核有一个规则，是*内核* **应用二进制接口**（**ABI**）的一部分：**只有当内核模块构建在它上面时，它才会将内核模块插入内核内存** - 精确的内核版本，构建标志，甚至内核配置选项都很重要！

构建的内核是您在 Makefile 中指定的内核源位置（我们之前通过`KDIR`变量这样做）。

换句话说，内核模块与其构建的内核之外的内核**不兼容**。例如，如果我们在 Ubuntu 18.04 LTS 上构建一个内核模块，那么它将*只*在运行这个精确环境的系统上工作（库，内核或工具链）！它将*不*在 Fedora 29 或 RHEL 7.x，树莓派等上工作。现在 - 再次思考一下 - 这并不意味着内核模块完全不兼容。不，它们在不同架构之间是*源代码兼容*的（至少它们可以或者*应该*被编写成这样）。因此，假设你有源代码，你总是可以在给定的系统上*重新构建*一个内核模块，然后它将在该系统上工作。只是*二进制映像*（`.ko`文件）与其构建的精确内核之外的内核不兼容。

放松，这个问题实际上很容易发现。查看内核日志：

```
$ dmesg |tail -n2 [ 296.130074] helloworld_lkm: no symbol version for module_layout
[ 296.130093] helloworld_lkm: version magic '5.4.51-v7+ mod_unload modversions ARMv6 p2v8 ' should be '4.19.75-v7+ SMP mod_unload modversions ARMv7 p2v8 ' $ 
```

在设备上，当前运行的内核是：`4.19.75-v7+`。内核直接告诉我们，我们的内核模块已经构建在`5.4.51-v7+`内核版本上（它还显示了一些预期的内核配置）以及它应该是什么。存在不匹配！因此无法插入内核模块。

虽然我们在这里不使用这种方法，但是有一种方法可以确保成功构建和部署第三方的内核模块（只要它们的源代码是可用的），通过一个名为**DKMS**（**动态内核模块支持**）的框架。以下是直接从中引用的一句话：

<q>动态内核模块支持（DKMS）是一个启用生成 Linux 内核模块的程序/框架</q><q>其源代码通常驻留在内核源树之外。其概念是在安装新内核时自动重建 DKMS 模块。</q>

作为 DKMS 使用的一个例子，Oracle VirtualBox hypervisor（在 Linux 主机上运行时）使用 DKMS 自动构建和保持其内核模块的最新状态。

## 尝试 4 - 交叉编译我们的内核模块

因此，现在我们了解了问题，有两种可能的解决方案：

+   我们必须使用产品所需的自定义配置内核，并构建所有我们的内核模块。

+   或者，我们可以重建内核模块以匹配当前运行的内核设备。

现在，在典型的嵌入式 Linux 项目中，您几乎肯定会为目标设备拥有一个自定义配置的内核，您必须与之一起工作。产品的所有内核模块将/必须构建在其上。因此，我们遵循第一种方法 - 我们必须使用我们自定义配置和构建的（5.4！）内核引导设备，因为我们的内核模块是构建在其上的，现在它应该肯定可以工作。

我们（简要地）在第三章中涵盖了树莓派的内核构建，*从源代码构建 5.x Linux 内核 - 第二部分*。如果需要，可以返回那里查看详细信息。

好的，我将假设您已经按照第三章中涵盖的步骤，并且现在已经为树莓派配置和构建了一个 5.4 内核。关于如何将我们的自定义`zImage`复制到设备的 microSD 卡等细节在这里没有涵盖。我建议您查看官方的树莓派文档：[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)。

尽管如此，我们将指出一种方便的方法来在设备上切换内核（这里，我假设设备是运行 32 位内核的树莓派 3B+）：

1.  将您定制构建的`zImage`内核二进制文件复制到设备的 microSD 卡的`/boot`分区。将原始的 Raspberry Pi 内核映像 - Raspbian 内核映像 - 保存为`kernel7.img.orig`。

1.  从主机系统上复制（`scp`）刚刚交叉编译的内核模块（ARM 上的`helloworld_lkm.ko`，在上一节中完成）到 microSD 卡（通常是`/home/pi`）。

1.  接下来，再次在设备的 microSD 卡上，编辑`/boot/config.txt`文件，通过`kernel=xxx`行设置内核引导。设备上的此文件片段显示了这一点：

```
rpi $ cat /boot/config.txt
[...]
# KNB: enable the UART (for the adapter cable: USB To RS232 TTL UART 
# PL2303HX Converter USB to COM)
enable_uart=1
# KNB: select the kernel to boot from via kernel=xxx
#kernel=kernel7.img.orig
kernel=zImage
rpi $ 
```

1.  保存并重新启动后，我们登录到设备并重试我们的内核模块。图 5.2 是一个屏幕截图，显示了刚刚交叉编译的`helloworld_lkm.ko`内核模块在树莓派设备上的使用：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/0d9aae0b-cd43-4afc-9080-0936ceeb5098.png)

图 5.2 - 在树莓派上使用的交叉编译的 LKM

啊，成功了！请注意，这次当前内核版本（`5.4.51-v7+`）与模块构建时的内核版本完全匹配 - 在`modinfo(8)`输出中，我们可以看到`vermagic`字符串显示为`5.4.51-v7+`。

如果您看到`rmmod(8)`出现非致命错误（尽管清理钩子仍然被调用），原因是您尚未完全在设备上设置新构建的内核。您将不得不复制所有内核模块（位于`/lib/modules/<kernel-ver>`下）并在那里运行`depmod(8)`实用程序。在这里，我们不会深入探讨这些细节 - 如前所述，树莓派的官方文档涵盖了所有这些步骤。

当然，树莓派是一个非常强大的系统；您可以在树莓派上安装（默认的）Raspbian 操作系统以及开发工具和内核头文件，从而在板上编译内核模块！（无需交叉编译。）然而，在这里，我们遵循了交叉编译的方法，因为这在嵌入式 Linux 项目中很典型。

LKM 框架是一个相当庞大的工作。还有很多需要探索的地方。让我们开始吧。在下一节中，我们将研究如何从内核模块中获取一些最小的系统信息。

# 收集最小的系统信息

在我们上一节的简单演示中（`ch5/cross/helloworld_lkm.c`），我们已经硬编码了一个`printk()`来发出一个`"Hello/Goodbye, Raspberry Pi world\n"`字符串，无论内核模块是否真的在树莓派设备上运行。为了更好地“检测”一些系统细节（如 CPU 或操作系统），我们建议您参考我们的样本`ch5/min_sysinfo/min_sysinfo.c`内核模块。在下面的代码片段中，我们只显示相关函数：

```
// ch5/min_sysinfo/min_sysinfo.c
[ ... ]
void llkd_sysinfo(void)
{
    char msg[128];

    memset(msg, 0, strlen(msg));
    snprintf(msg, 47, "%s(): minimal Platform Info:\nCPU: ", __func__);

    /* Strictly speaking, all this #if... is considered ugly and should be
     * isolated as far as is possible */
#ifdef CONFIG_X86
#if(BITS_PER_LONG == 32)
    strncat(msg, "x86-32, ", 9);
#else
    strncat(msg, "x86_64, ", 9);
#endif
#endif
#ifdef CONFIG_ARM
    strncat(msg, "ARM-32, ", 9);
#endif
#ifdef CONFIG_ARM64
    strncat(msg, "Aarch64, ", 10);
#endif
#ifdef CONFIG_MIPS
    strncat(msg, "MIPS, ", 7);
#endif
#ifdef CONFIG_PPC
    strncat(msg, "PowerPC, ", 10);
#endif
#ifdef CONFIG_S390
    strncat(msg, "IBM S390, ", 11);
#endif

#ifdef __BIG_ENDIAN
    strncat(msg, "big-endian; ", 13);
#else
    strncat(msg, "little-endian; ", 16);
#endif

#if(BITS_PER_LONG == 32)
    strncat(msg, "32-bit OS.\n", 12);
#elif(BITS_PER_LONG == 64)
    strncat(msg, "64-bit OS.\n", 12);
#endif
    pr_info("%s", msg);

  show_sizeof();
 /* Word ranges: min & max: defines are in include/linux/limits.h */
 [ ... ]
}
EXPORT_SYMBOL(lkdc_sysinfo);
```

（此 LKM 显示的其他细节 - 如各种原始数据类型的大小和字范围 - 这里没有显示；请参考我们的 GitHub 存储库中的源代码并自行尝试。）前面的内核模块代码是有益的，因为它有助于演示如何编写可移植的代码。请记住，内核模块本身是一个二进制的不可移植的目标文件，但它的源代码可能（也许应该，取决于您的项目）以这样一种方式编写，以便在各种架构上都是可移植的。然后在目标架构上进行简单的构建（或为目标架构构建）将使其准备好部署。

现在，请忽略此处使用的`EXPORT_SYMBOL()`宏。我们将很快介绍其用法。

在我们现在熟悉的 x86_64 Ubuntu 18.04 LTS 客户机上构建并运行它，我们得到了这个输出：

```
$ cd ch5/min_sysinfo
$ make
[...]
$ sudo insmod ./min_sysinfo.ko 
$ dmesg
[...]
[29626.257341] min_sysinfo: inserted
[29626.257352] llkd_sysinfo(): minimal Platform Info:
              CPU: x86_64, little-endian; 64-bit OS.
$ 
```

太棒了！类似地（如前面演示的），我们可以为 ARM-32（树莓派）*交叉编译*这个内核模块，然后将交叉编译的内核模块传输（`scp(1)`）到我们的树莓派目标并在那里运行（以下输出来自运行 32 位 Raspbian OS 的树莓派 3B+）：

```
$ sudo insmod ./min_sysinfo.ko
$ dmesg
[...]
[    80.428363] min_sysinfo: inserted
[    80.428370] llkd_sysinfo(): minimal Platform Info:
               CPU: ARM-32, little-endian; 32-bit OS.
$
```

事实上，这揭示了一些有趣的事情；树莓派 3B+拥有本地*64 位 CPU*，但默认情况下（截至撰写本文时）运行 32 位操作系统，因此出现了前面的输出。我们将留给你在树莓派（或其他设备）上安装 64 位 Linux 操作系统，并重新运行这个内核模块。

强大的*Yocto 项目*（[`www.yoctoproject.org/`](https://www.yoctoproject.org/)）是一种（行业标准）生成树莓派 64 位操作系统的方法。另外（也更容易快速尝试），Ubuntu 为该设备提供了自定义的 Ubuntu 64 位内核和根文件系统（[`wiki.ubuntu.com/ARM/RaspberryPi`](https://wiki.ubuntu.com/ARM/RaspberryPi)）。

## 更加注重安全性

当然，安全性是当今的一个关键问题。专业开发人员被期望编写安全的代码。近年来，针对 Linux 内核已经有许多已知的漏洞利用（有关更多信息，请参阅*进一步阅读*部分）。与此同时，许多工作正在进行中，以改进 Linux 内核的安全性。

在我们之前的内核模块（`ch5/min_sysinfo/min_sysinfo.c`）中，要注意使用旧式的例程（比如`sprintf`、`strlen`等等；是的，在内核中存在这些）！*静态分析器*可以在捕获潜在的与安全相关的和其他错误方面大有裨益；我们强烈建议您使用它们。第一章，*内核工作区设置*，提到了内核的几种有用的静态分析工具。在下面的代码中，我们使用了我们“更好”的`Makefile`中的`sa`目标之一来运行一个相对简单的静态分析器：`flawfinder(1)`（由 David Wheeler 编写）：

```
$ make [tab][tab] all        clean      help       install     sa_cppcheck    sa_gcc    
tarxz-pkg  checkpatch code-style indent      sa             sa_flawfinder sa_sparse $ make sa_flawfinder 
make clean
make[1]: Entering directory '/home/llkd/llkd_book/Linux-Kernel-Programming/ch5/min_sysinfo'

--- cleaning ---

[...]

--- static analysis with flawfinder ---

flawfinder *.c
Flawfinder version 1.31, (C) 2001-2014 David A. Wheeler.
Number of rules (primarily dangerous function names) in C/C++ ruleset: 169
Examining min_sysinfo.c

FINAL RESULTS:

min_sysinfo.c:60: [2] (buffer) char:
  Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues (CWE-119:CWE-120). Perform bounds checking, use functions that limit length, or ensure that the size is larger than the maximum possible length.

[...]

min_sysinfo.c:138: [1] (buffer) strlen:
  Does not handle strings that are not \0-terminated; if given one it may
  perform an over-read (it could cause a crash if unprotected) (CWE-126).
[...]
```

仔细看一下`flawfinder(1)`发出的警告，特别是关于`strlen()`函数的警告（它生成了许多警告！）。在这里我们确实面临这种情况！记住，未初始化的局部变量（比如我们的`msg`缓冲区）在声明时具有*随机内容*。因此，`strlen()`函数可能会产生我们期望的值，也可能不会。

`flawfinder`的输出甚至提到了**CWE**编号（在这里是 CWE-126），表示在这里看到的*一般类*的安全问题；（搜索一下你会看到详细信息。在这种情况下，CWE-126 代表缓冲区过读问题：[`cwe.mitre.org/data/definitions/126.html`](https://cwe.mitre.org/data/definitions/126.html)）。

同样，我们避免使用`strncat()`，并用`strlcat()`函数替换它。因此，考虑到安全性问题，我们将`llkd_sysinfo()`函数的代码重写为`llkd_sysinfo2()`。

我们还添加了一些代码行，以显示平台上无符号和有符号变量的*范围*（最小值、最大值）（以 10 进制和 16 进制表示）。我们留给你来阅读。作为一个简单的任务，运行这个内核模块在你的 Linux 设备上，并验证输出。

现在，让我们继续讨论一下 Linux 内核和内核模块代码的许可问题。

# 许可内核模块

众所周知，Linux 内核代码本身是根据 GNU GPL v2（也称为 GPL-2.0；GPL 代表通用公共许可证）许可的，就大多数人而言，将保持这种状态。如前所述，在第四章中，*编写您的第一个内核模块 - LKMs 第一部分*，许可您的内核代码是必需且重要的。基本上，至少对于我们的目的来说，讨论的核心是：如果您的意图是直接使用内核代码和/或向主线内核贡献您的代码（接下来会有一些说明），您*必须*以与 Linux 内核发布的相同许可证发布代码：GNU GPL-2.0。对于内核模块，情况仍然有点“灵活”，我们可以这么说。无论如何，为了与内核社区合作并得到他们的帮助（这是一个巨大的优势），您应该或者预期将代码发布为 GNU GPL-2.0 许可证（尽管双重许可证当然是可能和可接受的）。

使用`MODULE_LICENSE()`宏来指定许可证。从内核头文件`include/linux/module.h`中复制的以下注释清楚地显示了哪些许可证“标识”是可接受的（请注意双重许可）。显然，内核社区强烈建议将内核模块发布为 GPL-2.0（GPL v2）和/或其他许可证，如 BSD/MIT/MPL。如果您打算向内核主线贡献代码，毫无疑问，单独的 GPL-2.0 就是要发布的许可证：

```
// include/linux/module.h
[...]
/*
 * The following license idents are currently accepted as indicating free
 * software modules
 *
 * "GPL"                       [GNU Public License v2 or later]
 * "GPL v2"                    [GNU Public License v2]
 * "GPL and additional rights" [GNU Public License v2 rights and more]
 * "Dual BSD/GPL"              [GNU Public License v2
 *                              or BSD license choice]
 * "Dual MIT/GPL"              [GNU Public License v2
 *                              or MIT license choice]
 * "Dual MPL/GPL"              [GNU Public License v2
 *                              or Mozilla license choice]
 *
 * The following other idents are available
 *
 * "Proprietary" [Non free products]
 *
 * There are dual licensed components, but when running with Linux it is the GPL that is relevant so this is a non issue. Similarly LGPL linked with GPL is a GPL combined work.
 *
 * This exists for several reasons
 * 1\. So modinfo can show license info for users wanting to vet their setup is free
 * 2\. So the community can ignore bug reports including proprietary modules
 * 3\. So vendors can do likewise based on their own policies
 */
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
[...]
```

顺便说一句，内核源代码树有一个`LICENSES/`目录，在其中您将找到有关许可证的详细信息；在这个文件夹上快速执行`ls`命令会显示其中的子文件夹：

```
$ ls <...>/linux-5.4/LICENSES/
deprecated/ dual/ exceptions/ preferred/
```

我们将留给您去查看，并且将讨论许可证的内容到此为止；现实情况是，这是一个需要法律知识的复杂话题。您最好咨询公司内的专业法律人员（律师）（或者雇佣他们）以确保您的产品或服务的法律角度正确。

在这个话题上，为了保持一致，最近的内核有一个规定：每个单独的源文件的第一行必须是一个 SPDX 许可证标识符（详见[`spdx.org/`](https://spdx.org/)）。当然，脚本需要第一行指定解释器。此外，一些关于 GPL 许可证的常见问题的答案可以在这里找到：[`www.gnu.org/licenses/gpl-faq.html`](https://www.gnu.org/licenses/gpl-faq.html)。

有关许可模型、不滥用`MODULE_LICENSE`宏，特别是多许可证/双许可证的更多信息，请参阅本章“进一步阅读”部分提供的链接。现在，让我们回到技术方面。下一节将解释如何在内核空间有效地模拟类库功能。

# 在内核模块中模拟“类库”功能

用户模式和内核模式编程之间的一个主要区别是后者完全没有熟悉的“库”概念。库本质上是 API 的集合或存档，方便开发人员实现重要目标，通常包括：*不要重复造轮子、软件重用、模块化*等。但在 Linux 内核中，库根本不存在。

然而，好消息是，大体上说，有两种技术可以在内核空间为我们的内核模块实现“类库”功能：

+   第一种技术：显式“链接”多个源文件（包括“库”代码）到您的内核模块对象中。

+   第二个被称为模块堆叠。

请继续阅读，我们将更详细地讨论这些技术。也许有点剧透，但立即了解的话会很有用：前面的技术中的第一种通常优于第二种。不过，这取决于项目。请在下一节中阅读详细信息；我们将在进行时列出一些优缺点。

## 通过多个源文件执行库模拟

到目前为止，我们处理的内核模块都只有一个 C 源文件。那么对于（相当典型的）现实世界中存在*多个 C 源文件的单个内核模块*的情况呢？所有源文件都必须被编译，然后链接在一起成为一个`.ko`二进制对象。

例如，假设我们正在构建一个名为`projx`的内核模块项目。它由三个 C 源文件组成：`prj1.c, prj2.c`和`prj3.c`。我们希望最终的内核模块被称为`projx.ko`。Makefile 是您指定这些关系的地方，如下所示：

```
obj-m      := projx.o
projx-objs := prj1.o prj2.o prj3.o
```

在上述代码中，请注意`projx`标签在`obj-m`指令*之后*和作为前缀使用的情况

`-objs`指令在下一行。当然，您可以使用任何标签。我们之前的示例将使内核构建系统将三个单独的 C 源文件编译为单独的目标（`.o`）文件，然后将它们*链接*在一起，形成最终的二进制内核模块对象文件，`projx.ko`，正如我们所期望的那样。

我们可以利用这种机制在我们书籍的源树中构建一个小的例程“库”（此处的“内核库”源文件位于源树的根目录中：`klib_llkd.h`和`klib_llkd.c`）。其想法是其他内核模块可以通过链接到这里的函数来使用这里的函数！例如，在即将到来的第七章*，内存管理内部 - 基本知识*中，我们的`ch7/lowlevel_mem/lowlevel_mem.c`内核模块代码调用了我们库代码中的一个函数，`../../klib_llkd.c`。所谓的“链接到”我们所谓的“库”代码是通过将以下内容放入`lowlevel_mem`内核模块的 Makefile 中实现的：

```
obj-m                 += lowlevel_mem_lib.o
lowlevel_mem_lib-objs := lowlevel_mem.o ../../klib_llkd.o
```

第二行指定要构建的源文件（成为目标文件）；它们是`lowlevel_mem.c`内核模块的代码和`../../klib_llkd`库代码。然后，将它们链接成一个单一的二进制内核模块，`lowlevel_mem_lib.ko`，实现我们的目标。（为什么不在本章末尾的*问题*部分中处理指定的作业 5.1。）

## 了解内核模块中的函数和变量作用域

在深入研究之前，快速回顾一些基础知识是个好主意。在使用 C 进行编程时，您应该了解以下内容：

+   在函数内声明的变量显然只在函数内部可见，并且仅在该函数内部具有作用域。

+   使用`static`限定符前缀的变量和函数仅在当前“单元”内具有作用域；实际上是在它们被声明的文件内。这很好，因为它有助于减少命名空间污染。静态（和全局）数据变量在该函数内保留其值。

在 2.6 Linux 之前（即<= 2.4.x，现在是古代历史），内核模块的静态和全局变量以及所有函数都会自动在整个内核中可见。回顾起来，这显然不是一个好主意。从 2.5 开始（因此 2.6 及以后的现代 Linux）决定反转：**所有内核模块变量（静态和全局数据）和函数默认范围仅限于其内核模块，并且因此在外部不可见**。因此，如果两个内核模块`lkmA`和`lkmB`有一个名为`maya`的全局变量，它对每个模块都是唯一的；不会发生冲突。

要更改作用域，LKM 框架提供了`EXPORT_SYMBOL()`宏。使用它，您可以声明数据项或函数为*全局*作用域 - 实际上，对所有其他内核模块以及内核核心可见。

让我们举一个简单的例子。我们有一个名为`prj_core`的内核模块，其中包含一个全局变量和一个函数：

```
static int my_glob = 5;
static long my_foo(int key)
{ [...]
}
```

尽管两者都可以在这个内核模块内部使用，但在外部都看不到。这是有意为之的。为了使它们在这个内核模块外部可见，我们可以*导出*它们：

```
int my_glob = 5;
EXPORT_SYMBOL(my_glob);

long my_foo(int key)
{ [...]
}
EXPORT_SYMBOL(my_foo);
```

现在，这两者都在这个内核模块之外具有作用域（请注意，在前面的代码块中，`static`关键字已经被故意删除）。*其他内核模块（以及核心内核）现在可以“看到”并使用它们*。确切地说，这个想法以两种广泛的方式得到了利用：

+   首先，内核导出了一个经过深思熟虑的全局变量和函数的子集，这些变量和函数构成了其核心功能的一部分，也是其他子系统的一部分。现在，这些全局变量和函数是可见的，因此可以从内核模块中使用！我们很快将看到一些示例用法。

+   其次，内核模块作者（通常是设备驱动程序）使用这个概念来导出某些数据和/或功能，以便其他内核模块在更高的抽象级别上可以利用这个设计并使用这些数据和/或功能 - 这个概念被称为*模块堆叠*，我们将很快通过一个例子来深入探讨它。

例如，对于第一个用例，设备驱动程序的作者可能希望处理来自外围设备的硬件中断。通常的做法是通过`request_irq()`API 来实现，实际上，这个 API 只是对这个 API 的一个薄包装（内联）：

```
// kernel/irq/manage.c
int request_threaded_irq(unsigned int irq, irq_handler_t handler,
                         irq_handler_t thread_fn, unsigned long irqflags,
                         const char *devname, void *dev_id)
{
    struct irqaction *action;
[...]
    return retval;
}
EXPORT_SYMBOL(request_threaded_irq);
```

正因为`request_threaded_irq()`函数是*导出的*，它可以从设备驱动程序中调用，而设备驱动程序往往是作为内核模块编写的。同样，开发人员经常需要一些“便利”例程 - 例如，字符串处理例程。Linux 内核在`lib/string.c`中提供了几个常见字符串处理函数的实现（您期望它们存在）：`str[n]casecmp`、`str[n|l|s]cpy`、`str[n|l]cat`、`str[n]cmp`、`strchr[nul]`、`str[n|r]chr`、`str[n]len`等等。当然，这些都是通过`EXPORT_SYMBOL()`宏*导出*的，以使它们可见，从而可供模块作者使用。

在这里，我们使用`str[n|l|s]cpy`表示内核提供了四个函数：`strcpy`、`strncpy`、`strlcpy`和`strscpy`。请注意，一些接口可能已被弃用（`strcpy()`、`strncpy()`和`strlcpy()`）。一般来说，始终避免使用此处记录的弃用内容：*弃用接口、语言特性、属性和约定*（[`www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions`](https://www.kernel.org/doc/html/latest/process/deprecated.html#deprecated-interfaces-language-features-attributes-and-conventions)）。

另一方面，让我们来看一下内核核心深处的**CFS**（**完全公平调度器**）调度代码的一小部分。在这里，当调度代码需要找到另一个任务进行上下文切换时，会调用`pick_next_task_fair()`函数：

```
// kernel/sched/fair.c
static struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
        struct cfs_rq *cfs_rq = &rq->cfs;
[...]
        if (new_tasks > 0)
                goto again;
        return NULL;
}
```

我们这里并不真的想研究调度（第十章，*CPU 调度器 - 第一部分*，和第十一章，*CPU 调度器 - 第二部分*，已经涵盖了它），这里的重点是：由于前面的函数*没有*用`EXPORT_SYMBOL()`宏标记，它永远不能被内核模块调用。它仍然是核心内核的*私有*。

您还可以使用相同的宏将数据结构标记为已导出。此外，显而易见，只有全局范围的数据 - 而不是局部变量 - 可以被标记为已导出。

如果您想了解`EXPORT_SYMBOL()`宏的工作原理，请参考本章的*进一步阅读*部分，其中链接到了本书的 GitHub 存储库。

回想一下我们对内核模块许可的简要讨论。Linux 内核有一个，我们可以说，有趣的命题：还有一个名为`EXPORT_SYMBOL_GPL()`的宏。它就像它的表兄弟`EXPORT_SYMBOL()`宏一样，只是，是的，导出的数据项或函数只对那些在他们的`MODULE_LICENSE()`宏中包含`GPL`一词的内核模块可见！啊，内核社区的甜蜜复仇。它确实在内核代码库的几个地方使用。（我会把这留给你作为一个练习，在代码中找到这个宏的出现；在 5.4.0 内核上，使用`cscope(1)`进行快速搜索，发现“只有”14,000 多个使用实例！）

要查看所有导出的符号，请导航到内核源树的根目录，并发出`make export_report`命令。请注意，这仅适用于已配置和构建的内核树。

现在让我们看一下实现类似库的内核特性的另一个关键方法：模块堆叠。

## 理解模块堆叠

这里的第二个重要想法- *模块堆叠* - 是我们现在将进一步深入研究的。

模块堆叠是一个概念，为内核模块作者提供了类似“库”的功能。在这里，我们通常以这样的方式设计我们的项目或产品，有一个或多个“核心”内核模块，其工作是充当某种库。它将包括数据结构和功能（函数/API），这些将被*导出*到其他内核模块（前面的部分讨论了符号的导出）。

为了更好地理解这一点，让我们看一些真实的例子。首先，在我的主机系统上，一个 Ubuntu 18.04.3 LTS 本机 Linux 系统上，我在*Oracle VirtualBox 6.1*虚拟化应用程序上运行了一个或多个客户 VM。好的，在主机系统上执行快速的`lsmod(8)`，同时过滤字符串`vbox`，会显示如下内容：

```
$ lsmod | grep vbox
vboxnetadp             28672  0
vboxnetflt             28672  1
vboxdrv               479232  3 vboxnetadp,vboxnetflt
$ 
```

回想一下我们之前的讨论，第三列是*使用计数*。在第一行中是`0`，但在第三行中是`3`。不仅如此，`vboxdrv`内核模块右侧列出了两个内核模块。如果任何内核模块出现在第三列之后，它们代表**依赖关系**；这样读：右侧显示的内核模块*依赖于*左侧的内核模块。

因此，在前面的例子中，`vboxnetadp`和`vboxnetflt`内核模块依赖于`vboxdrv`内核模块。以什么方式依赖它？当然是使用`vboxdrv`核心内核模块中的数据结构和/或功能（API）！一般来说，出现在第三列右侧的内核模块意味着它们使用左侧内核模块的一个或多个数据结构和/或功能（导致使用计数的增加；这个使用计数是一个*引用计数器*的很好例子（这里，它实际上是一个 32 位原子变量），这是我们在最后一章中深入讨论的内容）。实际上，`vboxdrv`内核模块类似于一个“库”（在有限的意义上，与用户模式库相关的通常含义除外，除了提供模块化功能）。您可以看到，在这个快照中，它的使用计数是`3`，依赖它的内核模块堆叠在它的上面-字面上！（您可以在`lsmod(1)`输出的前两行中看到它们。）另外，请注意，`vboxnetflt`内核模块有一个正的使用计数（`1`），但在它的右侧没有内核模块显示；这仍然意味着某些东西目前在使用它，通常是一个进程或线程。

FYI，我们在这个示例中看到的**Oracle VirtualBox**内核模块实际上是**VirtualBox Guest Additions**的实现。它们本质上是一种半虚拟化构造，有助于加速客户 VM 的工作。Oracle VirtualBox 也为 Windows 和 macOS 主机提供类似的功能（所有主要的虚拟化供应商也是如此）。

作为承诺的模块堆叠的另一个例子：运行强大的**LTTng**（**Linux Tracing Toolkit next generation**）框架使您能够执行详细的系统分析。LTTng 项目安装和使用了相当多的内核模块（通常是 40 个或更多）。其中一些内核模块是“堆叠”的，允许项目精确利用我们在这里讨论的“类似库”的功能。

在下图中（在 Ubuntu 18.04.4 LTS 系统上安装了 LTTng 后），查看`lsmod | grep --color=auto "^lttng"`输出的部分截图，涉及其内核模块：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/581dd594-9e25-4e31-a8ea-701dec0f1e30.png)

图 5.3 - LTTng 产品中的大量模块堆叠

可以看到，`lttng_tracer`内核模块右侧有 35 个内核模块，表示它们“堆叠”在其上，使用它提供的功能（类似地，`lttng_lib_ring_buffer`内核模块有 23 个内核模块“依赖”它）。

这里有一些快速的脚本魔法，可以查看所有使用计数非零的内核模块（它们通常 - 但并不总是 - 有一些依赖的内核模块显示在它们的右侧）：

```
lsmod | awk '$3 > 0 {print $0}'
```

模块堆叠的一个含义是：只有在使用计数为`0`时，才能成功地`rmmod(8)`一个内核模块；也就是说，它没有在使用中。因此，对于前面的第一个示例，我们只能在移除两个依赖它的内核模块之后（从而将使用计数减少到`0`）才能移除`vboxdrv`内核模块。

### 尝试模块堆叠

让我们为模块堆叠构建一个非常简单的概念验证代码。为此，我们将构建两个内核模块：

+   第一个我们将称为`core_lkm`；它的工作是充当一种“库”，为内核和其他模块提供一些函数（API）。

+   我们的第二个内核模块`user_lkm`是“用户”（或消费者）“库”的使用者；它将简单地调用第一个内核模块中的函数（并使用一些数据）。

为了做到这一点，我们的一对内核模块需要做到以下几点：

+   核心内核模块必须使用`EXPORT_SYMBOL()`宏将一些数据和函数标记为*导出*。

+   用户内核模块必须声明其期望使用的数据和/或函数为外部数据，通过 C 的`extern`关键字（请记住，导出数据或功能只是设置适当的链接；编译器仍然需要知道被调用的数据和/或函数）。

+   使用最近的工具链，允许将导出的函数和数据项标记为`static`。但会产生一个警告；我们不使用`static`关键字来导出符号。

+   编辑自定义 Makefile 以构建两个内核模块。

代码如下；首先是核心或库内核模块。为了（希望）使其更有趣，我们将把之前一个模块的函数代码 - `ch5/min_sysinfo/min_sysinfo.c:llkd_sysinfo2()` - 复制到这个内核模块中，并*导出*它，从而使其对我们的第二个“用户”LKM 可见，后者将调用该函数：

这里我们不显示完整的代码；您可以参考本书的 GitHub 存储库。

```
// ch5/modstacking/core_lkm.c
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
#include <linux/init.h>
#include <linux/module.h>

#define MODNAME     "core_lkm"
#define THE_ONE     0xfedface
MODULE_LICENSE("Dual MIT/GPL");

int exp_int = 200;
EXPORT_SYMBOL_GPL(exp_int);

/* Functions to be called from other LKMs */
void llkd_sysinfo2(void)
{
[...]
}
EXPORT_SYMBOL(llkd_sysinfo2);

#if(BITS_PER_LONG == 32)
u32 get_skey(int p)
#else // 64-bit
u64 get_skey(int p)
#endif
{
#if(BITS_PER_LONG == 32)
    u32 secret = 0x567def;
#else // 64-bit
    u64 secret = 0x123abc567def;
#endif
    if (p == THE_ONE)
        return secret;
    return 0;
}
EXPORT_SYMBOL(get_skey);
[...]
```

接下来是`user_lkm`内核模块，它是“堆叠”在`core_lkm`内核模块之上的一个：

```
// ch5/modstacking/user_lkm.c
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__
#define MODNAME "user_lkm"

#if 1
MODULE_LICENSE("Dual MIT/GPL");
#else
MODULE_LICENSE("MIT");
#endif

extern void llkd_sysinfo2(void);
extern long get_skey(int);
extern int exp_int;

/* Call some functions within the 'core' module */
static int __init user_lkm_init(void)
{
#define THE_ONE 0xfedface
     pr_info("%s: inserted\n", MODNAME);
     u64 sk = get_skey(THE_ONE);
     pr_debug("%s: Called get_skey(), ret = 0x%llx = %llu\n",
             MODNAME, sk, sk);
     pr_debug("%s: exp_int = %d\n", MODNAME, exp_int);
 llkd_sysinfo2();
     return 0;
}

static void __exit user_lkm_exit(void)
{
    pr_info("%s: bids you adieu\n", MODNAME);
}
module_init(user_lkm_init);
module_exit(user_lkm_exit);
```

Makefile 基本上与我们之前的内核模块相同，只是这次我们需要构建两个内核模块对象，如下所示：

```
obj-m     := core_lkm.o
obj-m     += user_lkm.o
```

好的，让我们试一下：

1.  首先，构建内核模块：

```
$ make

--- Building : KDIR=/lib/modules/5.4.0-llkd02-kasan/build ARCH= CROSS_COMPILE= EXTRA_CFLAGS=-DDEBUG ---

make -C /lib/modules/5.4.0-llkd02-kasan/build M=/home/llkd/booksrc/ch5/modstacking modules
make[1]: Entering directory '/home/llkd/kernels/linux-5.4'
  CC [M] /home/llkd/booksrc/ch5/modstacking/core_lkm.o
  CC [M] /home/llkd/booksrc/ch5/modstacking/user_lkm.o
  [...]
  Building modules, stage 2.
  MODPOST 2 modules
  CC [M] /home/llkd/booksrc/ch5/modstacking/core_lkm.mod.o
  LD [M] /home/llkd/booksrc/ch5/modstacking/core_lkm.ko
  CC [M] /home/llkd/booksrc/ch5/modstacking/user_lkm.mod.o
  LD [M] /home/llkd/booksrc/ch5/modstacking/user_lkm.ko
make[1]: Leaving directory '/home/llkd/kernels/linux-5.4'
$ ls *.ko
core_lkm.ko  user_lkm.ko
$ 
```

请注意，我们正在针对我们自定义的 5.4.0 内核构建我们的内核模块。请注意其完整版本是`5.4.0-llkd02-kasan`；这是故意的。这是我构建并用作测试平台的“调试内核”！

1.  现在，让我们进行一系列快速测试，以演示*模块堆叠*概念的证明。让我们首先*错误地*进行：我们将首先尝试在插入`core_lkm`模块之前插入`user_lkm`内核模块。

这将失败-为什么？您将意识到`user_lkm`内核模块依赖的导出功能（和数据）尚未（尚未）在内核中可用。更具体地说，符号将不会位于内核的符号表中，因为具有这些符号的`core_lkm`内核模块尚未插入：

```
$ sudo dmesg -C
$ sudo insmod ./user_lkm.ko 
insmod: ERROR: could not insert module ./user_lkm.ko: Unknown symbol in module
$ dmesg 
[13204.476455] user_lkm: Unknown symbol exp_int (err -2)
[13204.476493] user_lkm: Unknown symbol get_skey (err -2)
[13204.476531] user_lkm: Unknown symbol llkd_sysinfo2 (err -2)
$ 
```

正如预期的那样，由于所需的（要导出的）符号不可用，`insmod（8）`失败（您在内核日志中看到的精确错误消息可能会略有不同，这取决于内核版本和设置的调试配置选项）。

1.  现在，让我们做对：

```
$ sudo insmod ./core_lkm.ko 
$ dmesg 
[...]
[19221.183494] core_lkm: inserted
$ sudo insmod ./user_lkm.ko 
$ dmesg 
[...]
[19221.183494] core_lkm:core_lkm_init(): inserted
[19242.669208] core_lkm:core_lkm_init(): /home/llkd/book_llkd/Linux-Kernel-Programming/ch5/modstacking/core_lkm.c:get_skey():100: I've been called
[19242.669212] user_lkm:user_lkm_init(): inserted
[19242.669217] user_lkm:user_lkm:user_lkm_init(): Called get_skey(), ret = 0x123abc567def = 20043477188079
[19242.669219] user_lkm:user_lkm_init(): exp_int = 200
[19242.669223] core_lkm:llkd_sysinfo2(): minimal Platform Info:
 CPU: x86_64, little-endian; 64-bit OS.
$ 
```

1.  它按预期工作！使用`lsmod（8）`检查模块列表：

```
$ lsmod | egrep "core_lkm|user_lkm"
user_lkm               20480  0
core_lkm               16384  1 user_lkm
$ 
```

请注意，对于`core_lkm`内核模块，使用计数列已增加到`1`*并且*现在我们可以看到`user_lkm`内核模块依赖于`core_lkm`。回想一下，在`lsmod`输出的极右列中显示的内核模块依赖于极左列中的内核模块。

1.  现在，让我们删除内核模块。删除内核模块也有*顺序依赖性*（就像插入一样）。首先尝试删除`core_lkm`失败，因为显然，仍然有另一个模块在内核内存中依赖其代码/数据；换句话说，它仍在使用中：

```
$ sudo rmmod core_lkm 
rmmod: ERROR: Module core_lkm is in use by: user_lkm
$ 
```

请注意，如果模块*安装*到系统上，那么您可以使用`modprobe -r <modules...>`命令来删除所有相关模块；我们将在*系统引导时自动加载模块*部分中介绍这个主题。

1.  前面的`rmmod（8）`失败消息是不言自明的。因此，让我们做对：

```
$ sudo rmmod user_lkm core_lkm 
$ dmesg 
[...]
 CPU: x86_64, little-endian; 64-bit OS.
[19489.717265] user_lkm:user_lkm_exit(): bids you adieu
[19489.732018] core_lkm:core_lkm_exit(): bids you adieu
$ 
```

好了！

您将注意到在`user_lkm`内核模块的代码中，我们发布的许可是在条件`#if`语句中：

```
#if 1
MODULE_LICENSE("Dual MIT/GPL");
#else
MODULE_LICENSE("MIT");
#endif
```

我们可以看到它（默认）以*双 MIT/GPL*许可发布；那又怎样？想一想：在`core_lkm`内核模块的代码中，我们有以下内容：

```
int exp_int = 200;
EXPORT_SYMBOL_GPL(exp_int);
```

`exp_int`整数*仅对在 GPL 许可下运行的内核模块可见。*因此，请尝试更改`core_lkm`中的`#if 1`语句为`#if 0`，从而现在仅在 MIT 许可下发布它。现在，重新构建并重试。它在构建阶段本身*失败*：

```
$ make
[...]
Building for: kver=5.4.0-llkd01 ARCH=x86 CROSS_COMPILE= EXTRA_CFLAGS=-DDEBUG
  Building modules, stage 2.
  MODPOST 2 modules
FATAL: modpost: GPL-incompatible module user_lkm.ko uses GPL-only symbol 'exp_int'
[...]
$ 
```

许可确实很重要！在结束本节之前，这里是模块堆叠可能出错的一些事项的快速清单；也就是说，要检查的事项：

+   插入/删除时内核模块的错误顺序

+   尝试插入已经在内核内存中的导出例程-名称空间冲突问题：

```
$ sudo insmod ./min_sysinfo.ko
[...]
$ cd ../modstacking ; sudo insmod ./core_lkm.ko
insmod: ERROR: could not insert module ./core_lkm.ko: Invalid module format
$ dmesg
[...]
[32077.823472] core_lkm: exports duplicate symbol llkd_sysinfo2 (owned by min_sysinfo)
$ sudo rmmod min_sysinfo
$ sudo insmod ./core_lkm.ko * # now it's ok*
```

+   由于使用`EXPORT_SYMBOL_GPL（）`宏引起的许可问题

始终查看内核日志（使用`dmesg（1）`或`journalctl（1）`）。它经常有助于显示实际出了什么问题。

因此，让我们总结一下：为了在内核模块空间中模拟类似库的功能，我们探索了两种技术：

+   我们使用的第一种技术通过*将多个源文件链接到单个内核模块中*来工作。

+   这与*模块堆叠*技术相反，后者实际上构建了多个内核模块并将它们“堆叠”在一起。

第一种技术不仅效果很好，而且还具有这些优点：

+   我们不必明确标记（通过`EXPORT_SYMBOL（）`）我们使用的每个数据/函数符号作为已导出的。

+   这些功能仅对实际链接到的内核模块可用（而不是*整个*内核，包括其他模块）。这是一件好事！所有这些都是以稍微调整 Makefile 的代价 - 绝对值得。

“链接”方法的一个缺点：在链接多个文件时，内核模块的大小可能会变得很大。

这就是您学习内核编程强大功能的结束——将多个源文件链接在一起形成一个内核模块，和/或利用模块堆叠设计，这两者都允许您开发更复杂的内核项目。

在接下来的部分中，我们将深入探讨如何向内核模块传递参数。

# 向内核模块传递参数

一种常见的调试技术是*instrument*您的代码；也就是说，在适当的位置插入打印，以便您可以跟踪代码的路径。当然，在内核模块中，我们会使用多功能的`printk`函数来实现这一目的。因此，让我们假设我们做了以下操作（伪代码）：

```
#define pr_fmt(fmt) "%s:%s():%d: " fmt, KBUILD_MODNAME, __func__, __LINE__
[ ... ]
func_x() { 
    pr_debug("At 1\n");
    [...]
    while (<cond>) {
        pr_debug("At 2: j=0x%x\n", j); 
        [...] 
 }
 [...]
}
```

好的，很好。但是我们不希望调试打印出现在生产（或发布）版本中。这正是我们使用`pr_debug()`的原因：它只在定义了符号`DEBUG`时才发出一个 printk！确实，但是如果，有趣的是，我们的客户是一个工程客户，并希望*动态打开或关闭这些调试打印*呢？您可能会采取几种方法；其中一种如下伪代码所示：

```
static int debug_level;     /* will be init to zero */
func_x() { 
    if (debug_level >= 1) pr_debug("At 1\n");
    [...]
    while (<cond>) {
        if (debug_level >= 2) 
            pr_debug("At 2: j=0x%x\n", j); 
        [...] 
    }
 [...]
}
```

啊，这很好。那么，我们真正要说的是：*如果我们可以将*`debug_level`*模块变量**作为我们的内核模块的参数*，那将是一个强大的功能，内核模块的用户可以控制哪些调试消息出现或不出现。

## 声明和使用模块参数

模块参数作为*name=value*对在模块插入（`insmod`）时传递给内核模块。例如，假设我们有一个名为`mp_debug_level`的*模块参数*，那么我们可以在`insmod(8)`时传递其值，如下所示：

```
sudo insmod modparams1.ko mp_debug_level=2
```

在这里，`mp`前缀代表模块参数。当然，不一定要这样命名，这有点迂腐，但可能会使其更直观一些。

这将是强大的。现在，最终用户可以决定*verbosity* 他们希望*debug-level* 消息。我们甚至可以轻松安排默认值为`0`。

您可能会想：内核模块没有`main()`函数，因此没有常规的`(argc, argv)`参数列表，那么您究竟如何传递参数呢？事实上，这是一种链接器的技巧；只需这样做：将您打算的模块参数声明为全局（静态）变量，然后通过使用`module_param()`宏指定构建系统将其视为模块参数。

通过我们的第一个模块参数的演示内核模块，这一点很容易看出（通常情况下，完整的源代码和`Makefile`可以在本书的 GitHub 存储库中找到）：

```
// ch5/modparams/modparams1/modparams1.c
[ ... ]
/* Module parameters */
static int mp_debug_level;
module_param(mp_debug_level, int, 0660);
MODULE_PARM_DESC(mp_debug_level,
"Debug level [0-2]; 0 => no debug messages, 2 => high verbosity");

static char *mp_strparam = "My string param";
module_param(mp_strparam, charp, 0660);
MODULE_PARM_DESC(mp_strparam, "A demo string parameter");
```

在`static int mp_debug_level;`语句中，将其更改为`static int mp_debug_level = 0;`是没有害处的，这样明确地将变量初始化为 0，对吗？嗯，不是的：内核的`scripts/checkpatch.pl`脚本输出显示，内核社区并不认为这是良好的编码风格：

`ERROR: do not initialise statics to 0`

`#28: FILE: modparams1.c:28:`

`+static int mp_debug_level = 0;`

在上述代码块中，我们通过`module_param()`宏声明了两个模块参数。`module_param()`宏接受三个参数：

+   第一个参数：变量名（我们希望将其视为模块参数）。这应该使用`static`限定符声明。

+   第二个参数：其数据类型。

+   第三个参数：权限（实际上，它通过`sysfs`的可见性；这将在下文中解释）。

`MODULE_PARM_DESC()`宏允许我们“描述”参数代表什么。想想看，这是如何通知内核模块（或驱动程序）的最终用户以及实际可用的参数。查找是通过`modinfo(8)`实用程序执行的。此外，您可以使用`-p`选项开关，仅将参数信息打印到模块，如下所示：

```
cd <booksrc>/ch5/modparams/modparams1
make
$ modinfo -p ./modparams1.ko 
parm:          mp_debug_level:Debug level [0-2]; 0 => no debug messages, 2 => high verbosity (int)
parm:          mp_strparam:A demo string parameter (charp)
$ 
```

`modinfo(8)`输出显示可用的模块参数（如果有的话）。在这里，我们可以看到我们的`modparams1.ko`内核模块有两个参数，它们的名称、描述和数据类型（在括号内；`charp`是字符指针，一个字符串）都显示出来了。好了，现在让我们快速运行一下我们的演示内核模块：

```
sudo dmesg -C
sudo insmod ./modparams1.ko 
dmesg 
[42724.936349] modparams1: inserted
[42724.936354] module parameters passed: mp_debug_level=0 mp_strparam=My string param
```

在这里，我们从`dmesg(1)`输出中看到，由于我们没有显式传递任何内核模块参数，模块变量显然保留了它们的默认（原始）值。让我们重新做一遍，这次传递显式值给模块参数：

```
sudo rmmod modparams1 
sudo insmod ./modparams1.ko mp_debug_level=2 mp_strparam=\"Hello modparams1\"
$ dmesg 
[...]
[42734.162840] modparams1: removed
[42766.146876] modparams1: inserted
[42766.146880] module parameters passed: mp_debug_level=2 mp_strparam=Hello modparams1
$ 
```

它按预期工作。既然我们已经看到了如何声明和传递一些参数给内核模块，现在让我们来看看如何在运行时检索甚至修改它们。

## 插入后获取/设置模块参数

让我们仔细看一下我们之前的`modparams1.c`源文件中`module_param()`宏的用法：

```
module_param(mp_debug_level, int, 0660);
```

注意第三个参数，*权限*（或*模式*）：它是`0660`（当然，这是一个*八进制*数，意味着所有者和组有读写访问权限，其他人没有访问权限）。这有点令人困惑，直到你意识到如果指定了*permissions*参数为非零，伪文件将在`sysfs`文件系统下创建，表示内核模块参数，这里是：`/sys/module/<module-name>/parameters/`：

`sysfs`通常挂载在`/sys`下。此外，默认情况下，所有伪文件的所有者和组都是 root。

1.  因此，对于我们的`modparams1`内核模块（假设它加载到内核内存中），让我们查找它们：

```
$ ls /sys/module/modparams1/
coresize   holders/    initsize  initstate  notes/  parameters/  refcnt sections/  srcversion  taint     uevent     version
$ ls -l /sys/module/modparams1/parameters/
total 0
-rw-rw---- 1 root root 4096 Jan  1 17:39 mp_debug_level
-rw-rw---- 1 root root 4096 Jan  1 17:39 mp_strparam
$ 
```

确实，它们在那里！不仅如此，它的真正美妙之处在于这些“参数”现在可以随意读取和写入，任何时候（当然只有 root 权限）！

1.  检查一下：

```
$ cat /sys/module/modparams1/parameters/mp_debug_level 
cat: /sys/module/modparams1/parameters/mp_debug_level: Permission denied
$ sudo cat /sys/module/modparams1/parameters/mp_debug_level
[sudo] password for llkd: 
2
```

是的，我们的`mp_debug_level`内核模块参数的当前值确实是`2`。

1.  让我们动态将其更改为`0`，表示`modparams1`内核模块不会发出“调试”消息：

```
$ sudo bash -c "echo 0 > /sys/module/modparams1/parameters/mp_debug_level"
$ sudo cat /sys/module/modparams1/parameters/mp_debug_level 
0
```

完成了。您可以类似地获取和/或设置`mp_strparam`参数；我们将留给您尝试这个作为一个简单的练习。这是强大的东西：您可以编写简单的脚本来通过内核模块参数控制设备（或其他内容）的行为，获取（或切断）调试信息等等；可能性是相当无限的。

实际上，将`module_param()`的第三个参数编码为字面八进制数（例如`0660`）在某些圈子里不被认为是最佳的编程实践。通过适当的宏（在`include/uapi/linux/stat.h`中指定）指定`sysfs`伪文件的权限，例如：

```
module_param(mp_debug_level, int, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
```

然而，话虽如此，我们的“更好”的*Makefile*的*checkpatch*目标（当然，调用内核的`scripts/checkpatch.pl`“编码风格”Perl 脚本检查器）礼貌地告诉我们，简单地使用八进制权限更好：

```
$ make checkpatch
[ ... ]
checkpatch.pl: /lib/modules/<ver>/build//scripts/checkpatch.pl --no-tree -f *.[ch]
[ ... ]
WARNING: Symbolic permissions 'S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP' are not preferred. Consider using octal permissions '0660'.
 #29: FILE: modparams1.c:29:
 +module_param(mp_debug_level, int, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
```

因此，内核社区并不同意。因此，我们将只使用“通常”的八进制数表示法`0660`。

## 内核模块参数数据类型和验证

在我们之前的简单内核模块中，我们设置了整数和字符串数据类型（`charp`）的两个参数。还可以使用哪些数据类型？事实证明有几种，`moduleparam.h`包含文件中都有（在注释中重复显示）：

```
// include/linux/moduleparam.h
[...]
 * Standard types are:
 * byte, short, ushort, int, uint, long, ulong
 * charp: a character pointer
 * bool: a bool, values 0/1, y/n, Y/N.
 * invbool: the above, only sense-reversed (N = true).
```

甚至可以根据需要定义自己的数据类型。通常，标准类型已经足够了。

### 验证内核模块参数

所有内核模块参数默认都是*可选的*；用户可以选择是否显式传递它们。但是如果我们的项目要求用户*必须显式传递*给定内核模块参数的值怎么办？我们在这里解决这个问题：让我们增强我们之前的内核模块，创建另一个（`ch5/modparams/modparams2`），关键区别在于我们设置了一个名为`control_freak`的额外参数。现在，我们*要求*用户在模块插入时*必须*传递这个参数：

1.  在代码中设置新的模块参数：

```
static int control_freak;
module_param(control_freak, int, 0660);
MODULE_PARM_DESC(control_freak, "Set to the project's control level [1-5]. MANDATORY");
```

1.  我们如何实现这种“强制传递”呢？嗯，这实际上有点小聪明：只需在插入时检查值是否为默认值（这里是`0`）。如果是，默认值，那么用适当的消息中止（我们还进行了一个简单的有效性检查，以确保传递的整数在给定范围内）。以下是`ch5/modparams/modparams2/modparams2.c`的初始化代码：

```
static int __init modparams2_init(void)
{
    pr_info("%s: inserted\n", OUR_MODNAME);
    if (mp_debug_level > 0)
        pr_info("module parameters passed: "
                "mp_debug_level=%d mp_strparam=%s\n control_freak=%d\n",
                mp_debug_level, mp_strparam, control_freak);

    /* param 'control_freak': if it hasn't been passed (implicit guess), 
     * or is the same old value, or isn't within the right range,
     * it's Unacceptable!  :-)
     */
    if ((control_freak < 1) || (control_freak > 5)) {
        pr_warn("%s: Must pass along module parameter"
              " 'control_freak', value in the range [1-5]; aborting...\n",
              OUR_MODNAME);
        return -EINVAL;
    }
    return 0; /* success */
}
```

1.  另外，作为一个快速演示，注意我们如何发出一个`printk`，只有当`mp_debug_level`为正数时才显示模块参数值。

1.  最后，在这个话题上，内核框架提供了一种更严格的方式来“获取/设置”内核（模块）参数并对其进行有效性检查，通过`module_parm_cb()`宏（`cb`代表回调）。我们不会在这里深入讨论这个问题；我建议你参考*进一步阅读*文档中提到的博客文章，了解如何使用它的详细信息。

现在，让我们继续讨论如何（以及为什么）覆盖模块参数的名称。

### 覆盖模块参数的名称

为了解释这个特性，让我们以(5.4.0)内核源代码树中的一个例子来说明：直接映射缓冲 I/O 库驱动程序`drivers/md/dm-bufio.c`需要使用`dm_bufio_current_allocated`变量作为模块参数。然而，这个名称实际上是一个*内部变量*，对于这个驱动程序的用户来说并不是非常直观的。这个驱动程序的作者更希望使用另一个名称——`current_allocated_bytes`——作为*别名*或*名称覆盖*。可以通过`module_param_named()`宏来实现这一点，通过覆盖并完全等效于内部变量名称的方式，如下所示：

```
// drivers/md/dm-bufio.c
[...]
module_param_named(current_allocated_bytes, dm_bufio_current_allocated, ulong, S_IRUGO);
MODULE_PARM_DESC(current_allocated_bytes, "Memory currently used by the cache");
```

因此，当用户对这个驱动程序执行`insmod`时，他们可以做如下的事情：

```
sudo insmod <path/to/>dm-bufio.ko current_allocated_bytes=4096 ...
```

在内部，实际变量`dm_bufio_current_allocated`将被赋值为`4096`。

### 与硬件相关的内核参数

出于安全原因，指定硬件特定值的模块或内核参数有一个单独的宏——`module_param_hw[_named|array]()`. David Howells 于 2016 年 12 月 1 日提交了一系列补丁，用于支持这些新的硬件参数内核。补丁邮件[[`lwn.net/Articles/708274/`](https://lwn.net/Articles/708274/)]提到了以下内容：

```
Provided an annotation for module parameters that specify hardware
parameters (such as io ports, iomem addresses, irqs, dma channels, fixed
dma buffers and other types).

This will enable such parameters to be locked down in the core parameter
parser for secure boot support.  [...]
```

这就结束了我们对内核模块参数的讨论。让我们继续讨论一个特殊的方面——内核中的浮点使用。

# 内核中不允许浮点数

多年前，当我在温度传感器设备驱动程序上工作时，我有过一次有趣的经历（尽管当时并不那么有趣）。试图将毫摄氏度作为“常规”摄氏度值来表达温度值时，我做了类似以下的事情：

```
double temp;
[... processing ...]
temp = temp / 1000.0;
printk(KERN_INFO "temperature is %.3f degrees C\n", temp);
```

从那时起一切都变得糟糕了！

备受尊敬的 LDD（*Linux 设备驱动程序*，作者为*Corbet, Rubini, and G-K-Hartman*）书指出了我的错误——**浮点**（FP）算术在内核空间是不允许的！这是一个有意识的设计决定——保存处理器（FP）状态，打开 FP 单元，进行操作，然后关闭和恢复 FP 状态在内核中并不被认为是值得做的事情。内核（或驱动程序）开发人员最好*不要*在内核空间尝试执行 FP 工作。

那么，你会问，那你怎么做（以我的例子为例）温度转换呢？简单：将*整数*毫摄氏度值*传递给用户空间*，然后在那里执行 FP 工作！

话虽如此，显然有一种方法可以强制内核执行 FP：将你的浮点代码放在`kernel_fpu_begin()`和`kernel_fpu_end()`宏之间。在内核代码库中有一些地方确实使用了这种技术（通常是一些涵盖加密/AES、CRC 等的代码路径）。不过，建议是典型的模块（或驱动程序）开发人员*只在内核中执行整数算术*。

尽管如此，为了测试整个场景（永远记住，*实证方法 - 实际尝试事物 - 是唯一现实的前进方式！*），我们编写了一个简单的内核模块，试图执行一些 FP 工作。代码的关键部分在这里显示：

```
// ch5/fp_in_kernel/fp_in_kernel.c
static double num = 22.0, den = 7.0, mypi;
static int __init fp_in_lkm_init(void)
{
    [...]
    kernel_fpu_begin();
    mypi = num/den;
    kernel_fpu_end();
#if 1
    pr_info("%s: PI = %.4f = %.4f\n", OURMODNAME, mypi, num/den);
#endif
    return 0;     /* success */
}
```

它实际上是有效的，*直到* *我们尝试通过* `printk()` *显示 FP 值*！在那一点上，它变得非常疯狂。请看下面的截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/63160f27-b5bc-47f0-9d4d-2b10782e941b.png)

图 5.4 - 当我们尝试在内核空间中打印 FP 数字时，WARN_ONCE()的输出

关键行是`Please remove unsupported %f in format string`。

这告诉我们一个故事。系统实际上并没有崩溃或恐慌，因为这只是一个通过`WARN_ONCE()`宏输出到内核日志的*警告*。但请注意，在生产系统上，`/proc/sys/kernel/panic_on_warn`伪文件很可能被设置为值`1`，导致内核（完全正确地）恐慌。

在前面截图（图 5.3）中的部分，从`Call Trace:`开始，当然是对进程或线程的*内核模式堆栈*的当前状态的一瞥，它是在前面的`WARN_ONCE()`代码路径中“捕获”的（稍等，你将在第六章中学到关于用户模式和内核模式堆栈等关键细节）。通过自下而上地阅读内核堆栈来解释内核堆栈；所以在这里，`do_one_initcall`函数调用了属于方括号中的内核模块的`fp_in_lkm_init`（`[fp_in_lkm_init]`），然后调用了`printk()`，然后试图打印 FP（浮点）数量，结果导致了各种麻烦！

明显的道理是：*避免在内核空间中使用浮点数运算*。现在让我们继续讨论如何在系统启动时安装和自动加载内核模块。

# 在系统启动时自动加载模块

到目前为止，我们编写了简单的“外部”内核模块，它们驻留在自己的私有目录中，并且通常需要通过`insmod(8)`或`modprobe(8)`实用程序手动加载。在大多数真实项目和产品中，你将需要*在启动时自动加载*你的外部内核模块。本节介绍了如何实现这一点。

假设我们有一个名为`foo.ko`的内核模块。我们假设我们可以访问源代码和 Makefile。为了在系统启动时*自动加载*它，你需要首先将内核模块*安装*到系统上已知的位置。为此，我们期望模块的 Makefile 包含一个`install`目标，通常是：

```
install:
 make -C $(KDIR) M=$(PWD) modules_install
```

这并不是什么新鲜事；我们一直在我们的演示内核模块的`Makefile`中放置`install`目标。

为了演示这个“自动加载”过程，我们展示了实际*安装和自动加载*我们的`ch5/min_sysinfo`内核模块的步骤：

1.  首先，切换到模块的源目录：

```
cd <...>/ch5/min_sysinfo
```

1.  接下来，首先重要的是构建内核模块（使用`make`），并且在成功后安装它（很快你会看到，我们的“更好”的 Makefile 通过保证先进行构建，然后进行安装和`depmod`来简化这个过程）：

```
make && sudo make install   
```

假设它构建成功，`sudo make install`命令然后会在`/lib/modules/<kernel-ver>/extra/`安装内核模块，这是预期的（也请看下面的信息框和提示）：

```
$ cd <...>/ch5/min_sysinfo
$ make                *<-- ensure it's first built 'locally'   
               generating the min_sysinfo.ko kernel module object*
[...]
$ sudo make install Building for: KREL= ARCH= CROSS_COMPILE= EXTRA_CFLAGS=-DDEBUG
make -C /lib/modules/5.4.0-llkd01/build M=<...>/ch5/min_sysinfo modules_install
make[1]: Entering directory '/home/llkd/kernels/linux-5.4'
 INSTALL <...>/ch5/min_sysinfo/min_sysinfo.ko
 DEPMOD  5.4.0-llkd01
make[1]: Leaving directory '/home/llkd/kernels/linux-5.4'
$ ls -l /lib/modules/5.4.0-llkd01/extra/
total 228
-rw-r--r-- 1 root root 232513 Dec 30 16:23 min_sysinfo.ko
$ 
```

在`sudo make install`期间，可能会看到关于 SSL 的（非致命的）错误；它们可以安全地忽略。它们表明系统未能“签名”内核模块。关于这一点，稍后会有关于安全性的说明。

另外，如果你发现`sudo make install`失败，也可以尝试以下方法：

a) 切换到 root shell（`sudo -s`）并在其中运行`make ; make install`命令。

b) 一个有用的参考资料：*Makefile: installing external Linux kernel module, StackOverflow, June 2016* ([`unix.stackexchange.com/questions/288540/makefile-installing-external-linux-kernel-module`](https://unix.stackexchange.com/questions/288540/makefile-installing-external-linux-kernel-module))。

1.  然后通常会在`sudo make install`中默认调用另一个模块实用程序`depmod(8)`（可以从前面的输出中看到）。以防万一（无论出于什么原因），这没有发生，您总是可以手动调用`depmod`：它的工作基本上是解决模块依赖关系（有关详细信息，请参阅其手册页）：`sudo depmod`。安装内核模块后，您可以使用其`--dry-run`选项开关查看`depmod(8)`的效果：

```
$ sudo depmod --dry-run | grep min_sysinfo
extra/min_sysinfo.ko:
alias symbol:lkdc_sysinfo2 min_sysinfo
alias symbol:lkdc_sysinfo min_sysinfo
$ 
```

1.  在启动时自动加载内核模块：一种方法是创建`/etc/modules-load.d/<foo>.conf`配置文件（当然，您需要 root 访问权限来创建此文件）；简单情况：只需在其中放入内核模块的`foo`名称，就是这样。任何以`#`字符开头的行都被视为注释并被忽略。对于我们的`min_sysinfo`示例，我们有以下内容：

```
$ cat /etc/modules-load.d/min_sysinfo.conf 
# Auto load kernel module for LLKD book: ch5/min_sysinfo
min_sysinfo
$
```

另外，通知 systemd 加载我们的内核模块的另一种（甚至更简单的）方法是将模块的*名称*输入到（现有的）`/etc/modules-load.d/modules.conf`文件中。

1.  使用`sync; sudo reboot`重新启动系统。

系统启动后，使用`lsmod(8)`并查看内核日志（也许可以用`dmesg(1)`）。您应该会看到与内核模块加载相关的相关信息（在我们的示例中是`min_sysinfo`）。

```
[... system boots up ...]

$ lsmod | grep min_sysinfo
min_sysinfo         16384  0
$ dmesg | grep -C2 min_sysinfo
[...]
[ 2.395649] min_sysinfo: loading out-of-tree module taints kernel.
[ 2.395667] min_sysinfo: module verification failed: signature and/or required key missing - tainting kernel
[ 2.395814] min_sysinfo: inserted
[ 2.395815] lkdc_sysinfo(): minimal Platform Info:
               CPU: x86_64, little-endian; 64-bit OS.
$
```

好了，完成了：我们的`min_sysinfo`内核模块确实已经在启动时自动加载到内核空间中！

正如您刚刚学到的，您必须首先构建您的内核模块，然后执行安装；为了帮助自动化这一过程，我们的“更好”的 Makefile 在其模块安装`install`目标中包含以下内容：

```
// ch5/min_sysinfo/Makefile
[ ... ]
install:
    @echo
    @echo "--- installing ---"
    @echo " [First, invoke the 'make' ]"
    make
    @echo
    @echo " [Now for the 'sudo make install' ]"
    sudo make -C $(KDIR) M=$(PWD) modules_install
 sudo depmod
```

它确保首先进行构建，然后进行安装，（显式地）进行`depmod(8)`。

如果您的自动加载的内核模块在加载时需要传递一些（模块）参数，该怎么办？有两种方法可以确保这种情况发生：通过所谓的 modprobe 配置文件（在`/etc/modprobe.d/`下）或者，如果模块是内核内置的，通过内核命令行。

这里我们展示第一种方法：简单地设置您的 modprobe 配置文件（在这里作为示例，我们使用`mykmod`作为我们 LKM 的名称；同样，您需要 root 访问权限来创建此文件）：`/etc/modprobe.d/mykmod.conf`；在其中，您可以像这样传递参数：

```
options <module-name> <parameter-name>=<value>
```

例如，我的 x86_64 Ubuntu 20.04 LTS 系统上的`/etc/modprobe.d/alsa-base.conf` modprobe 配置文件包含以下行（还有其他几行）：

```
# Ubuntu #62691, enable MPU for snd-cmipci
options snd-cmipci mpu_port=0x330 fm_port=0x388
```

接下来是有关内核模块自动加载相关项目的一些要点。

## 模块自动加载-其他详细信息

一旦内核模块已经通过`sudo make install`安装到系统上（如前所示），您还可以通过一个“更智能”的`insmod(8)`实用程序的版本，称为`modprobe(8)`，将其插入内核交互式地（或通过脚本）。对于我们的示例，我们可以首先`rmmod(8)`模块，然后执行以下操作：

```
sudo modprobe min_sysinfo
```

有趣的是，在有多个内核模块对象要加载的情况下（例如，*模块堆叠*设计），`modprobe`如何知道加载内核模块的*顺序*？在本地进行构建时，构建过程会生成一个名为`modules.order`的文件。它告诉诸如`modprobe`之类的实用程序加载内核模块的顺序，以便解决所有依赖关系。当内核模块被*安装*到内核中（即，到`/lib/modules/$(uname -r)/extra/`或类似位置），`depmod(8)`实用程序会生成一个`/lib/modules/$(uname -r)/modules.dep`文件。其中包含依赖信息 - 它指定一个内核模块是否依赖于另一个。使用这些信息，modprobe 然后按照所需的顺序加载它们。为了充实这一点，让我们安装我们的模块堆叠示例：

```
$ cd <...>/ch5/modstacking
$ make && sudo make install
[...]
$ ls -l /lib/modules/5.4.0-llkd01/extra/
total 668K
-rw-r--r-- 1 root root 218K Jan 31 08:41 core_lkm.ko
-rw-r--r-- 1 root root 228K Dec 30 16:23 min_sysinfo.ko
-rw-r--r-- 1 root root 217K Jan 31 08:41 user_lkm.ko
$ 
```

显然，我们模块堆叠示例中的两个内核模块（`core_lkm.ko`和`user_lkm.ko`）现在安装在预期位置`/lib/modules/$(uname -r)/extra/`下。现在，来看一下这个：

```
$ grep user_lkm /lib/modules/5.4.0-llkd01/* 2>/dev/null
/lib/modules/5.4.0-llkd01/modules.dep:extra/user_lkm.ko: extra/core_lkm.ko
Binary file /lib/modules/5.4.0-llkd01/modules.dep.bin matches
$
```

`grep`后的第一行输出是相关的：`depmod`已经安排`modules.dep`文件显示`extra/user_lkm.ko`内核模块依赖于`extra/core_lkm.ko`内核模块（通过`<k1.ko>: <k2.ko>...`表示，意味着`k1.ko`模块依赖于`k2.ko`模块）。因此，modprobe 看到这一点，按照所需的顺序加载它们，避免任何问题。

（顺便说一句，谈到这个话题，生成的`Module.symvers`文件包含所有导出符号的信息。）

接下来，回想一下 Linux 上的新（ish）`init`框架，*systemd*。事实上，在现代 Linux 系统上，实际上是 systemd 负责在系统启动时自动加载内核模块，通过解析诸如`/etc/modules-load.d/*`之类的文件的内容（负责此操作的 systemd 服务是`systemd-modules-load.service(8)`。有关详细信息，请参阅`modules-load.d(5)`的 man 页面）。

相反，有时您可能会发现某个自动加载的内核模块表现不佳 - 导致死机或延迟，或者根本不起作用 - 因此您肯定想要禁用它的加载。这可以通过*黑名单*模块来实现。您可以在内核命令行上指定这一点（当其他方法都失败时很方便！）或者在（前面提到的）`/etc/modules-load.d/<foo>.conf`配置文件中指定。在内核命令行上，通过`module_blacklist=mod1,mod2,...`，内核文档向我们展示了语法/解释：

```
module_blacklist=  [KNL] Do not load a comma-separated list of
                        modules.  Useful for debugging problem modules.
```

您可以通过执行`cat /proc/cmdline`来查找当前的内核命令行。

谈到内核命令行，还存在一些其他有用的选项，使我们能够使用内核的帮助来调试与内核初始化有关的问题。例如，内核在这方面提供了以下参数之一（来源：[`www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html`](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)）：

```
debug           [KNL] Enable kernel debugging (events log level).
[...]
initcall_debug  [KNL] Trace initcalls as they are executed. Useful
                      for working out where the kernel is dying during
                      startup.
[...]
ignore_loglevel [KNL] Ignore loglevel setting - this will print /all/
                      kernel messages to the console. Useful for  
                      debugging. We also add it as printk module 
                      parameter, so users could change it dynamically, 
                      usually by /sys/module/printk/parameters/ignore_loglevel.
```

顺便说一句，并且正如本章前面提到的，还有一个用于第三方内核模块自动重建的替代框架，称为**动态内核模块支持**（**DKMS**）。

本章的*进一步阅读*文档还提供了一些有用的链接。总之，在系统启动时将内核模块自动加载到内存中是一个有用且经常需要的功能。构建高质量的产品需要对*安全性*有深刻的理解，并具有构建*安全性*的知识；这是下一节的主题。

# 内核模块和安全性 - 概述

讽刺的现实是，过去几年中，花费大量精力改进*用户空间*安全考虑已经取得了相当大的回报。几十年前，恶意用户进行有效的**缓冲区溢出**（**BoF**）攻击是完全可能的，但今天却很难实现。为什么？因为有许多层加强的安全机制来防止许多这些攻击类别。

快速列举一些对策：编译器保护（`-fstack-protector[...]`）

-Wformat-security, -D_FORTIFY_SOURCE=2`, partial/full RELRO, better sanity and security checker tools (`checksec.sh`, the address sanitizers, paxtest, static analysis tools, and so on), secure libraries, hardware-level protection mechanisms (NX, SMEP, SMAP, and so on), [K]ASLR, better testing (fuzzing), and so on.

讽刺的是，过去几年中*内核空间*攻击变得越来越常见！已经证明，即使是透露一个有效的内核（虚拟）地址（及其对应的符号）给一个聪明的攻击者，她也可以找到一些关键的内核结构的位置，从而为进行各种**特权升级**（**privesc**）攻击铺平道路。因此，即使是透露一个看似无害的内核信息（如内核地址及其关联的符号）也可能是一个**信息泄漏**（或信息泄漏）并且必须在生产系统上予以防止。接下来，我们将列举并简要描述 Linux 内核提供的一些安全功能。然而，最终，内核开发人员-也就是您！-在其中扮演了重要角色：首先编写安全的代码！使用我们的“更好”的 Makefile 是一个很好的开始方式-其中的几个目标与安全有关（例如所有的静态分析目标）。

## 影响系统日志的 proc 文件系统可调整参数

我们直接参考`proc(5)`的手册页面-非常有价值！-以获取有关这两个与安全相关的可调整参数的信息：

+   `dmesg_restrict`

+   `kptr_restrict`

首先是`dmesg_restrict`：

```
dmesg_restrict
/proc/sys/kernel/dmesg_restrict (since Linux 2.6.37)
 The value in this file determines who can see kernel syslog contents. A  value of 0 in this file imposes no restrictions. If the value is 1, only privileged users can read the kernel syslog. (See syslog(2) for more details.) Since Linux 3.4, only users with the CAP_SYS_ADMIN capability may change the value in this file.
```

默认值（在我们的 Ubuntu 和 Fedora 平台上）是`0`：

```
$ cat /proc/sys/kernel/dmesg_restrict
0
```

Linux 内核使用强大的细粒度 POSIX *capabilities*模型。`CAP_SYS_ADMIN`能力本质上是传统*root（超级用户/系统管理员）*访问的一个捕捉所有。`CAP_SYSLOG`能力赋予进程（或线程）执行特权`syslog(2)`操作的能力。

如前所述，“泄漏”内核地址及其关联的符号可能导致基于信息泄漏的攻击。为了帮助防止这些情况，建议内核和模块的作者始终使用新的`printf`风格格式来打印内核地址：而不是使用熟悉的`%p`或`%px`来打印内核地址，应该使用新的**`%pK`**格式来打印地址。（使用`%px`格式确保实际地址被打印出来；在生产中应避免使用这种格式）。这有什么帮助呢？请继续阅读...

`kptr_restrict`可调整参数（2.6.38 及以上版本）影响`printk()`输出时打印内核地址；使用`printk("&var = **%pK**\n", &var);`

而不是老旧的`printk("&var = %p\n", &var);`被认为是一种安全最佳实践。了解`kptr_restrict`可调整参数的工作原理对此至关重要：

```
kptr_restrict
/proc/sys/kernel/kptr_restrict (since Linux 2.6.38)
 The value in this file determines whether kernel addresses are exposed via /proc files and other interfaces. A value of 0 in this file imposes no restrictions. If the value is 1, kernel pointers printed using the %pK format specifier will be replaced with zeros unless the user has the CAP_SYSLOG capability. If the value is 2, kernel pointers printed using the %pK format specifier will be replaced with zeros regardless of the user's capabilities. The initial default value for this file was 1, but the default was changed to 0 in Linux 2.6.39\. Since Linux 3.4, only users with the CAP_SYS_ADMIN capability can change the value in this file.
```

默认值（在我们最近的 Ubuntu 和 Fedora 平台上）是`1`：

```
$ cat /proc/sys/kernel/kptr_restrict 
1
```

在生产系统上，您可以-而且*必须*将这些可调整参数更改为安全值（1 或 2）以确保安全。当然，只有开发人员使用这些安全措施时，安全措施才能发挥作用；截至 Linux 内核 5.4.0 版本，整个 Linux 内核代码库中只有（仅有！）14 个使用`%pK`格式指定符，而使用`%p`的使用约为 5200 多次，显式使用`%px`格式指定符的使用约为 230 次。

a）由于`procfs`是一个易失性文件系统，您可以始终使用`sysctl(8)`实用程序和`-w`选项开关（或直接更新`/etc/sysctl.conf`文件）使更改永久生效。

b）为了调试的目的，如果必须打印实际的内核（未修改的）地址，建议您使用`%px`格式说明符；在生产系统上，请删除这些打印！

c）有关`printk`格式说明符的详细内核文档可以在[`www.kernel.org/doc/html/latest/core-api/printk-formats.html#how-to-get-printk-format-specifiers-right`](https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#how-to-get-printk-format-specifiers-right)找到；请浏览一下。

随着 2018 年初硬件级缺陷的出现（现在众所周知的*Meltdown，Spectre*和其他处理器推测安全问题），人们对*检测信息泄漏*产生了一种新的紧迫感，从而使开发人员和管理员能够将其封锁。

一个有用的 Perl 脚本`scripts/leaking_addresses.pl`在 4.14 版中发布（2017 年 11 月；我很高兴能在这项重要工作中提供帮助：[`github.com/torvalds/linux/commit/1410fe4eea22959bd31c05e4c1846f1718300bde`](https://github.com/torvalds/linux/commit/1410fe4eea22959bd31c05e4c1846f1718300bde)），并且正在进行更多的检查以检测泄漏的内核地址。

## 内核模块的加密签名

一旦恶意攻击者在系统上立足，他们通常会尝试某种特权升级向量，以获得 root 访问权限。一旦实现了这一点，典型的下一步是安装*rootkit*：基本上是一组脚本和内核模块，它们几乎会接管系统（通过“劫持”系统调用，设置后门和键盘记录器等）。

当然，这并不容易 - 现代生产质量的 Linux 系统的安全姿态，包括**Linux 安全模块**（**LSMs**）等，意味着这并不是一件微不足道的事情，但对于一个技术娴熟且积极进取的攻击者来说，任何事情都有可能。假设他们安装了足够复杂的 rootkit，系统现在被认为是受到了威胁。

一个有趣的想法是：即使具有 root 访问权限，也不要允许`insmod(8)`（或`modprobe(8)`，甚至底层的`[f]init_module(2)`系统调用）将内核模块插入内核地址空间**除非它们使用安全密钥进行了加密签名**，而该密钥在内核的密钥环中。这一强大的安全功能是在 3.7 内核中引入的（相关提交在这里：[`git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=106a4ee258d14818467829bf0e12aeae14c16cd7`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=106a4ee258d14818467829bf0e12aeae14c16cd7)）。

有关对内核模块进行加密签名的详细信息超出了本书的范围；您可以在这里参考官方内核文档：[`www.kernel.org/doc/html/latest/admin-guide/module-signing.html`](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)。

有关此功能的一些相关内核配置选项是`CONFIG_MODULE_SIG`，`CONFIG_MODULE_SIG_FORCE`，`CONFIG_MODULE_SIG_ALL`等。要了解这究竟意味着什么，请参阅第一个选项的`Kconfig 'help'`部分，如下所示（来自`init/Kconfig`）：

```
config MODULE_SIG
 bool "Module signature verification"
 depends on MODULES
 select SYSTEM_DATA_VERIFICATION
 help
  Check modules for valid signatures upon load: the signature is simply  
  appended to the module. For more information see  
  <file:Documentation/admin-guide/module-signing.rst>. Note that this  
  option adds the OpenSSL development packages as a kernel build   
  dependency so that the signing tool can use its crypto library.

 !!!WARNING!!! If you enable this option, you MUST make sure that the  
 module DOES NOT get stripped after being signed. This includes the
 debuginfo strip done by some packagers (such as rpmbuild) and
 inclusion into an initramfs that wants the module size reduced
```

内核配置`MODULE_SIG_FORCE`是一个布尔值（默认为`n`）。只有在打开`MODULE_SIG`时才会起作用。如果`MODULE_SIG_FORCE`设置为`y`，那么内核模块*必须*具有有效的签名才能加载。如果没有，加载将失败。如果其值保持为`n`，这意味着即使未签名的内核模块也将加载到内核中，但内核将被标记为有瑕疵。这往往是典型现代 Linux 发行版的默认设置。在以下代码块中，我们查找了我们的 x86_64 Ubuntu 20.04.1 LTS 客户 VM 上的这些内核配置：

```
$ grep MODULE_SIG /boot/config-5.4.0-58-generic 
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
[ ... ] 
```

在生产系统上鼓励对内核模块进行加密签名（近年来，随着（I）IoT 边缘设备变得更加普遍，安全性是一个关键问题）。

## 完全禁用内核模块

偏执的人可能希望完全禁用内核模块的加载（和卸载）。这相当激烈，但嘿，这样你就可以完全锁定系统的内核空间（以及使任何 rootkit 基本上无害）。有两种广泛的方法可以实现这一点：

+   首先，通过在构建之前的内核配置期间将`CONFIG_MODULES`内核配置设置为关闭（默认情况下是打开的）。这样做相当激烈 – 它使决定成为永久的！

+   其次，假设`CONFIG_MODULES`已打开，模块加载可以通过`modules_disabled` `sysctl`可调参数在运行时动态关闭；看一下这个：

```
$ cat /proc/sys/kernel/modules_disabled
0 
```

当然，默认情况下是*关闭*（`0`）。像往常一样，`proc(5)`的 man 页面告诉了我们这个故事：

```
/proc/sys/kernel/modules_disabled (since Linux 2.6.31)
 A toggle value indicating if modules are allowed to be loaded in an otherwise modular kernel. This toggle defaults to off (0), but can be set true (1). Once true, modules can be neither loaded nor unloaded, and the toggle cannot be set back to false. The file is present only if the kernel is built with the CONFIG_MODULES option enabled.
```

总之，当然，内核安全加固和恶意攻击是一场猫鼠游戏。例如，（K）ASLR（我们将在接下来的 Linux 内存管理章节中讨论（K）ASLR 的含义）经常被打败。另请参阅这篇文章 – *在 Android 上有效地绕过 kptr_restrict*：[`bits-please.blogspot.com/2015/08/effectively-bypassing-kptrrestrict-on.html`](http://bits-please.blogspot.com/2015/08/effectively-bypassing-kptrrestrict-on.html)。安全并不容易；它总是在不断地进步中。几乎可以说：开发人员 – 无论是用户空间还是内核空间 – *必须*编写具有安全意识的代码，并且持续使用工具和测试*。*

让我们通过关于 Linux 内核编码风格指南、访问内核文档以及如何进行对主线内核的贡献的主题来完成本章。

# 内核开发人员的编码风格指南

许多大型项目都规定了自己的一套编码准则；Linux 内核社区也是如此。遵循 Linux 内核*编码风格*指南是一个非常好的主意。您可以在这里找到官方文档：[`www.kernel.org/doc/html/latest/process/coding-style.html`](https://www.kernel.org/doc/html/latest/process/coding-style.html)（请务必阅读！）。

此外，作为想要上游您的代码的开发人员的（相当详尽的）代码提交检查清单的一部分，您应该通过一个 Perl 脚本运行您的补丁，检查您的代码是否符合 Linux 内核编码风格：`scripts/checkpatch.pl`。

默认情况下，此脚本仅在格式良好的`git`补丁上运行。可以对独立的 C 代码（如您的树外内核模块代码）运行它，方法如下（正如我们的“更好”的 Makefile 确实做到的）：

```
<kernel-src>/scripts/checkpatch.pl --no-tree -f <filename>.c
```

在您的内核代码中养成这样的习惯是有帮助的，可以帮助您发现那些令人讨厌的小问题 – 以及更严重的问题！ – 否则可能会阻碍您的补丁。再次提醒您：我们的“更好”的 Makefile 的`indent`和`checkpatch`目标是为此而设计的。

除了编码风格指南，您会发现，时不时地，您需要深入研究详细且有用的内核文档。温馨提示：我们在第一章 *内核工作区设置*的*查找和使用 Linux 内核文档*部分中介绍了定位和使用内核文档。

我们现在将通过简要介绍如何开始一个崇高的目标来完成本章：为主线 Linux 内核项目贡献代码。

# 为主线内核做贡献

在本书中，我们通常通过 LKM 框架在内核源树之外进行内核开发。如果您正在内核树中编写代码，并明确目标是将您的代码上游到内核主线，该怎么办呢？这确实是一个值得赞扬的目标 - 开源的整个基础源自社区愿意付出努力并将其贡献到项目上游。

## 开始为内核做贡献

当然，最常见的问题是*我该如何开始*？为了帮助您准确地解决这个问题，内核文档中有一个非常详细的答案：*如何进行 Linux 内核开发*：[`www.kernel.org/doc/html/latest/process/howto.html#howto-do-linux-kernel-development`](https://www.kernel.org/doc/html/latest/process/howto.html#howto-do-linux-kernel-development)。

实际上，您可以通过`make pdfdocs`命令在内核源树的根目录生成完整的 Linux 内核文档；一旦成功，您将在此找到 PDF 文档：`<kernel-source-tree>/Documentation/output/latex/development-process.pdf`。

这是 Linux 内核开发过程的非常详细的指南，包括代码提交的指南。此处显示了该文档的裁剪截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/6b621a0c-964d-4b25-8c8b-9a63ad58ae79.png)

图 5.5 - 生成的内核开发文档的（部分）截图

作为内核开发过程的一部分，为了保持质量标准，一个严格且*必须遵循*的清单 - 一种长长的配方！ - 是内核补丁提交过程的重要部分。官方清单位于此处：*Linux 内核补丁提交清单*：[`www.kernel.org/doc/html/latest/process/submit-checklist.html#linux-kernel-patch-submission-checklist`](https://www.kernel.org/doc/html/latest/process/submit-checklist.html#linux-kernel-patch-submission-checklist)。

虽然对于内核新手来说可能看起来是一项繁重的任务，但仔细遵循这个清单会给您的工作带来严谨性和可信度，并最终产生优秀的代码。我强烈鼓励您阅读内核补丁提交清单并尝试其中提到的程序。

有没有一个真正实用的动手提示，一个几乎可以保证成为内核黑客的方法？当然，继续阅读本书！哈哈，是的，此外，参加简直太棒了的**Eudyptula 挑战**（[`www.eudyptula-challenge.org/`](http://www.eudyptula-challenge.org/)）哦，等等，很不幸，截至撰写本文时，它已经关闭了。

不要担心；这里有一个网站，上面发布了所有挑战（以及解决方案，但不要作弊！）。一定要去看看并尝试这些挑战。这将极大地提升您的内核编程技能：[`github.com/agelastic/eudyptula`](https://github.com/agelastic/eudyptula)。

# 总结

在本章中，我们涵盖了使用 LKM 框架编写内核模块的第二个章节，其中包括与这一重要主题相关的几个（剩余的）领域：其中包括使用“更好”的 Makefile 来为您的内核模块进行配置，配置调试内核的提示（这非常重要！），交叉编译内核模块，从内核模块中收集一些最小的平台信息，甚至涉及内核模块的许可证问题。我们还探讨了使用两种不同方法（一种是首选的链接方法，另一种是模块堆叠方法）来模拟类似库的特性，使用模块参数，避免浮点运算，内核模块的自动加载等等。安全问题及其解决方法也很重要。最后，我们通过介绍内核编码风格指南、内核文档以及如何开始为主线内核做出贡献来结束了本章。所以，恭喜！您现在知道如何开发内核模块，甚至可以开始迈向内核上游贡献的旅程。

在下一章中，我们将深入探讨一个有趣且必要的主题。我们将开始深入探讨 Linux 内核及其内存管理子系统的*内部*。

# 问题

最后，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会在书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入研究这个主题并提供有用的材料，我们在这本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接（有时甚至包括书籍）的*进一步阅读*markdown 文档 - 按章节组织。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。
