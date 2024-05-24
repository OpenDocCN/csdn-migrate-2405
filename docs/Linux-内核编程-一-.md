# Linux 内核编程（一）

> 原文：[`zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7`](https://zh.annas-archive.org/md5/86EBDE91266D2750084E0C4C5C494FF7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书明确地旨在帮助你以实际、动手的方式学习 Linux 内核开发，同时提供必要的理论背景，使你对这个广阔而有趣的主题有一个全面的了解。它有意地专注于通过强大的**可加载内核模块**（**LKM**）框架进行内核开发；绝大多数的内核项目和产品，包括设备驱动程序开发，都是以这种方式完成的。

重点放在实际操作和对 Linux 操作系统内部的深入理解上。在这方面，我们涵盖了从源代码构建 Linux 内核到理解和处理内核中的同步等复杂主题的方方面面。

为了指导你进行这激动人心的旅程，我们将这本书分为三个部分。第一部分涵盖了基础知识-设置内核开发所需的工作空间，从源代码构建内核，以及编写你的第一个内核模块。

接下来的一部分，一个关键部分，将帮助你理解重要和必要的内核内部- Linux 内核架构、任务结构以及用户和内核模式堆栈。内存管理是一个重要且有趣的主题-我们专门撰写了三整章来涵盖它（充分涵盖了内部内容，以及如何准确分配任何空闲内核内存）。Linux 上的 CPU 调度的工作和更深入的细节结束了这一部分。

本书的最后一部分涉及更高级的内核同步主题-这是 Linux 内核专业设计和编码的必要内容。我们专门撰写了两整章来涵盖这些关键主题。

本书使用了截至撰写时最新的 5.4 **长期支持**（**LTS**）Linux 内核。这是一个将从 2019 年 11 月一直维护（包括错误修复和安全修复）到 2025 年 12 月的内核！这是一个关键点，确保了本书的内容在未来多年仍然保持最新和有效！

我们非常相信实践：本书的 GitHub 仓库上有超过 20 个内核模块（以及几个用户应用程序和 shell 脚本），使学习变得生动、有趣和有用。

我们强烈建议你也使用本书的配套指南*Linux Kernel Programming (Part 2)*。

这是一本与行业接轨的初学者指南，涵盖了编写`misc`字符驱动程序、在外围芯片内存上执行 I/O 以及处理硬件中断。你可以免费获取这本书，同时也可以在 GitHub 仓库中找到这本电子书：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/Linux-Kernel-Programming-(Part-2)`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/Linux-Kernel-Programming-(Part-2))。

我们真诚地希望你能从这本书中学到东西并且享受阅读。祝阅读愉快！

# 这本书适合谁

这本书主要是为那些刚开始涉足 Linux 内核模块开发以及在一定程度上 Linux 设备驱动程序开发的人而写的。它也非常针对那些已经在 Linux 模块和/或驱动程序上工作的人，他们希望对 Linux 内核架构、内存管理和同步有更深入、结构良好的理解。这种对底层操作系统的了解，以适当的结构方式进行覆盖，将在面对难以调试的现实情况时帮助你无比。

# 本书涵盖的内容

第一章，“内核工作空间设置”，指导您设置一个完整的 Linux 内核开发工作空间（通常作为一个完全虚拟化的客户系统）。您将学习如何在其中安装所有必需的软件包，包括交叉工具链。您还将了解其他几个开源项目，这些项目对您成为专业内核/驱动程序开发人员的旅程将会有用。完成本章后，您将准备好构建 Linux 内核，以及开始编写和测试内核代码（通过可加载内核模块框架）。在我们看来，您实际上使用这本书进行动手操作，尝试和实验代码非常重要。学习某件事情的最好方法是通过经验主义 - 不是完全相信任何人的话，而是通过尝试和亲身体验来学习。

第二章，“从源代码构建 5.x Linux 内核 - 第一部分”，是解释如何从头开始使用源代码构建现代 Linux 内核的第一部分。在这一部分，您将获得必要的背景信息 - 版本命名、不同的源树、内核源代码的布局。接下来，您将详细了解如何将稳定的 vanilla Linux 内核源代码树下载到虚拟机上。然后，我们将学习一些关于内核源代码布局的知识，实际上是对内核代码库的“鸟瞰”。然后是提取和配置 Linux 内核的实际工作。还展示了创建和使用自定义菜单条目进行内核配置。

第三章，“从源代码构建 5.x Linux 内核 - 第二部分”，是关于从源代码执行内核构建的第二部分。在这一部分，您将继续上一章的内容，现在实际上构建内核，安装内核模块，了解`initramfs`（`initrd`）的确切含义以及如何生成它，以及设置引导加载程序（对于 x86）。此外，作为有价值的附加内容，本章还解释了如何为典型的嵌入式 ARM 目标（使用流行的树莓派作为目标设备）交叉编译内核。还提到了一些关于内核构建的技巧和窍门，甚至内核安全（加固）的内容。

第四章，“编写您的第一个内核模块 - LKMs 第一部分”，是涵盖 Linux 内核开发的一个基本方面的两个部分之一 - LKM 框架，以及模块用户（您 - 内核模块或设备驱动程序程序员）如何理解和使用它。它涵盖了 Linux 内核架构的基础知识，然后详细介绍了编写一个简单的“Hello, world”内核模块的每个步骤，包括编译、插入、检查和从内核空间中删除。我们还详细介绍了通过普遍的 printk API 进行内核日志记录。

第五章，“编写您的第一个内核模块 - LKMs 第二部分”，是涵盖 LKM 框架的第二部分。在这里，我们首先要学习如何使用“更好”的 Makefile，这将帮助您生成更健壮的代码（具有多个代码检查、纠正、静态分析目标等）。然后我们详细展示了成功交叉编译内核模块到另一个架构的步骤，以及如何在内核中模拟“类库”代码（通过“链接”和模块堆叠方法），定义和使用传递参数给内核模块。其他主题包括在启动时自动加载模块、重要的安全指南，以及有关内核文档的一些信息以及如何访问它。几个示例内核模块使学习更加有趣。

第六章，*内核内部要点-进程和线程*，深入探讨了一些基本的内核内部主题。我们首先介绍了进程和中断上下文中执行的含义，以及进程用户**虚拟地址空间**（VAS）布局的最小但必需的覆盖范围。这为您铺平了道路；然后您将更深入地了解 Linux 内核架构，重点关注进程/线程任务结构及其相应的堆栈（用户模式和内核模式）。然后我们向您展示了更多关于内核任务结构（一个“根”数据结构），如何从中实际获取信息，甚至遍历各种（任务）列表。几个内核模块使这个主题更加生动。

第七章，*内存管理内部要点-基础知识*，是一个关键章节，深入探讨了 Linux 内存管理子系统的基本内部结构，以满足典型模块作者或驱动程序开发人员所需的详细程度。因此，这种覆盖范围在本质上更加理论化；然而，在这里获得的知识对于您作为内核开发人员来说至关重要，无论是为了深入理解和使用适当的内核内存 API，还是为了在内核层面进行有意义的调试。我们涵盖了 VM 分割（以及它在各种实际架构上的情况），深入了解用户 VAS（我们的 procmap 实用程序将让您大开眼界），以及内核段（或内核 VAS）。然后我们简要地探讨了内存布局随机化（[K]ASLR）的安全技术，并以讨论 Linux 内部的物理内存组织结束了本章。

第八章，*模块作者的内核内存分配第一部分*，让我们亲自动手使用内核内存分配（和显然的释放）API。您将首先了解 Linux 内部的两种分配“层”-位于内核内存分配“引擎”上方的 slab 分配器，以及页面分配器（或 BSA）。我们将简要了解页面分配器算法的基础和其“空闲列表”数据结构；在决定使用哪一层时，这些信息是有价值的。接下来，我们直接投入到学习这些关键 API 的实际工作中。我们将涵盖 slab 分配器（或缓存）的背后思想以及主要的内核分配器 API-`kzalloc`/`kfree`。重要的是，详细介绍了使用这些常见 API 时的大小限制、缺点和注意事项。此外，特别适用于驱动程序作者的是，我们涵盖了内核的现代资源管理内存分配 API（`devm_*()`例程）。

第九章，*模块作者的内核内存分配第二部分*，在逻辑上进一步发展了前一章。在这里，您将学习如何创建自定义 slab 缓存（对于高频（de）分配，例如自定义驱动程序非常有用），以及关于在 slab 层调试内存分配的一些帮助。接下来，您将了解并使用`vmalloc()` API（及其相关内容）。非常重要的是，在涵盖了许多内核内存（de）分配 API 之后，您现在将学习如何根据您所处的实际情况选择适当的 API。本章以对内核的**内存不足**（OOM）“killer”框架的重要覆盖结束。了解它也将导致您对用户空间内存分配的工作原理有更深入的理解，通过需求分页技术。

第十章，“CPU 调度器-第一部分”，是两章中的第一部分，涵盖了关于 Linux 操作系统上 CPU 调度的理论和实践的有用混合内容。首先介绍了关于线程作为 KSE 以及可用的内核调度策略的最低必要理论背景。接下来，介绍了足够的内核 CPU 调度的细节，以便让您了解现代 Linux 操作系统上的调度工作原理。在学习的过程中，您将学习如何使用强大的工具（如 perf）“可视化”PU 调度；还深入探讨了线程调度属性（策略和实时优先级）。

第十一章，“CPU 调度器-第二部分”，是关于 CPU 调度的第二部分，继续更深入地介绍了这个主题。在这里，我们介绍了更多用于 CPU 调度的可视化工具（利用强大的软件，如 LTTng 和 trace-cmd 实用程序）。接下来，深入探讨了 CPU 亲和性掩码以及如何查询/设置它，以及在每个线程基础上控制调度策略和优先级的功能。还概述了控制组（cgroups）的含义和重要性，以及通过 cgroups v2 进行 CPU 带宽分配的有趣示例。您可以将 Linux 作为 RTOS 运行吗？确实可以！然后展示了实际操作的详细信息。最后，我们讨论了（调度）延迟以及如何测量它们。

第十二章，“内核同步-第一部分”，首先介绍了关于临界区、原子性、锁概念的关键概念，以及所有这些的重要性。然后我们介绍了在 Linux 内核中工作时的并发问题；这自然地引出了重要的锁定准则，死锁的含义，以及预防死锁的关键方法。然后深入讨论了两种最流行的内核锁技术——互斥锁和自旋锁——以及几个（驱动程序）代码示例。

第十三章，“内核同步-第二部分”，继续介绍内核同步的内容。在这里，您将了解关键的锁定优化——使用轻量级原子和（更近期的）引用计数运算符来安全地操作整数，使用 RMW 位运算符来安全地执行位操作，以及使用读者-写者自旋锁而不是常规自旋锁。还讨论了缓存“虚假共享”等固有风险。然后概述了无锁编程技术（重点是每 CPU 变量及其用法，并提供示例）。然后介绍了关键主题——锁调试技术，包括使用内核强大的“lockdep”锁验证器。最后简要介绍了内存屏障（并提供了一个示例）。

# 为了充分利用本书

为了充分利用本书，我们希望您具有以下知识和经验：

+   熟悉 Linux 系统的命令行（shell）。

+   C 编程语言。

+   这不是强制性的，但具有 Linux 系统编程概念和技术的经验将大大有助于。

有关硬件和软件要求以及其安装的详细信息在第一章，“内核工作区设置”中完整而深入地介绍。您必须详细阅读并遵循其中的说明。

此外，我们还在这些平台上测试了本书中的所有代码（它还有自己的 GitHub 存储库）：

+   x86_64 Ubuntu 18.04 LTS 客户操作系统（在 Oracle VirtualBox 6.1 上运行）

+   x86_64 Ubuntu 20.04.1 LTS 客户操作系统（在 Oracle VirtualBox 6.1 上运行）

+   x86_64 Ubuntu 20.04.1 LTS 本机操作系统

+   ARM Raspberry Pi 3B+（同时运行其“发行版”内核和我们的自定义 5.4 内核）；轻度测试

+   x86_64 CentOS 8 客户操作系统（在 Oracle VirtualBox 6.1 上运行）；轻度测试

我们假设在作为客户机（VM）运行 Linux 时，主机系统要么是 Windows 10 或更高版本（当然，甚至 Windows 7 也可以），要么是最新的 Linux 发行版（例如 Ubuntu 或 Fedora），甚至是 macOS。

**如果您使用本书的数字版本，我们建议您自己输入代码，或者更好的是通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。

我强烈建议您遵循*经验主义方法：不要轻信任何人的话，而是亲自尝试并体验。*因此，本书为您提供了许多实践实验和内核代码示例，您可以并且必须亲自尝试；这将极大地帮助您取得实质性进展，并深入学习和理解 Linux 内核开发的各个方面。

## 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件，链接为[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

## 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789953435_ColorImages.pdf`。

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“`ioremap()` API 返回`void *`类型的 KVA（因为它是一个地址位置）”

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

任何命令行输入或输出都是按照以下方式编写的：

```
pi@raspberrypi:~ $ sudo cat /proc/iomem
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“从管理面板中选择系统信息”。

警告或重要说明会出现在这样的形式中。

提示和技巧会以这种形式出现。

# 联系我们

我们始终欢迎读者的反馈意见。

**一般反馈**：如果您对本书的任何方面有疑问，请在您的消息主题中提及书名，并通过电子邮件联系我们，邮箱为`customercare@packtpub.com`。

**勘误**：尽管我们已经非常注意确保内容的准确性，但错误是难免的。如果您在本书中发现错误，我们将不胜感激，如果您能向我们报告。请访问[www.packtpub.com/support/errata](https://www.packtpub.com/support/errata)，选择您的书，点击勘误提交表单链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，我们将不胜感激，如果您能向我们提供位置地址或网站名称。请通过`copyright@packt.com`与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

## 评论

请留下评论。在阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问 [packt.com](http://www.packt.com/)。


# 第一部分：基础知识

在这里，您将学习如何执行基本的内核开发任务。您将设置一个内核开发工作空间，从源代码构建 Linux 内核，了解 LKM 框架，并编写一个“Hello, world”内核模块。

本部分包括以下章节：

+   第一章，*内核工作空间设置*

+   第二章，*从源代码构建 5.x Linux 内核，第一部分*

+   第三章，*从源代码构建 5.x Linux 内核，第二部分*

+   第四章，*编写您的第一个内核模块 - LKMs 第一部分*

+   第五章，*编写您的第一个内核模块 - LKMs 第二部分*

我们强烈建议您还使用本书的配套指南，*Linux Kernel Programming (Part 2)*。

这是一本与行业相关的优秀的初学者指南，介绍了编写`misc`字符驱动程序，对外围芯片内存进行 I/O 以及处理硬件中断。这本书主要是为了开始在设备驱动程序开发中找到自己方向的 Linux 程序员而写的。想要克服频繁和常见的内核/驱动程序开发问题，以及了解和学习执行常见驱动程序任务的 Linux 设备驱动程序开发人员 - 现代**Linux 设备模型**（**LDM**）框架，用户-内核接口，执行外围 I/O，处理硬件中断，处理并发等 - 都将从这本书中受益。需要对 Linux 内核内部（和常见 API）、内核模块开发和 C 编程有基本的了解。

您可以免费获取这本书，以及您的副本，或者您也可以在 GitHub 存储库中找到这本电子书：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/Linux-Kernel-Programming-(Part-2)`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/Linux-Kernel-Programming-(Part-2))。


# 第一章：内核工作区设置

你好，欢迎来到这本关于学习 Linux 内核开发的书。为了充分利用本书，非常重要的是您首先设置我们将在整本书中使用的工作区环境。本章将教您如何做到这一点并开始。

我们将安装最新的 Linux 发行版，最好作为**虚拟机**（**VM**），并设置它以包括所有必需的软件包。我们还将在 GitHub 上克隆本书的代码库，并了解一些有用的项目，这些项目将在这个过程中帮助我们。

学习某事的最佳方法是*经验主义*-不要完全相信任何人的话，而是尝试并亲身体验。因此，本书为您提供了许多实践实验和内核代码示例，您可以并且必须自己尝试；这将极大地帮助您取得实质性进展，深入学习和理解 Linux 内核和驱动程序开发的各个方面。所以，让我们开始吧！

本章将带领我们通过以下主题，帮助我们设置我们的环境：

+   作为客户 VM 运行 Linux

+   设置软件-分发和软件包

+   一些额外有用的项目

# 技术要求

您需要一台现代台式机或笔记本电脑。Ubuntu 桌面指定了以下作为“推荐系统要求”的分发安装和使用：

+   2 GHz 双核处理器或更好。

+   内存：

+   在物理主机上运行：2 GB 或更多系统内存（更多肯定会有所帮助）。

+   作为客户 VM 运行：主机系统应至少有 4 GB RAM（内存越多越好，体验越流畅）。

+   25 GB 的可用硬盘空间（我建议更多，至少是这个的两倍）。

+   安装介质的 DVD 驱动器或 USB 端口（在设置 Ubuntu 作为客户 VM 时不需要）。

+   互联网访问绝对是有帮助的，有时是必需的。

由于从源代码构建 Linux 内核等任务是一个非常消耗内存和 CPU 的过程，我强烈建议您在具有充足内存和磁盘空间的强大 Linux 系统上尝试。很明显-主机系统的 RAM 和 CPU 功率越大，越好！

像任何经验丰富的内核贡献者一样，我会说在本地 Linux 系统上工作是最好的。但是，出于本书的目的，我们不能假设您总是有一个专用的本地 Linux 框可供使用。因此，我们将假设您正在使用 Linux 客户端。在客户 VM 中工作还增加了一个额外的隔离层，因此更安全。

**克隆我们的代码库**：本书的完整源代码可以在 GitHub 上免费获取，网址为[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Learn-Linux-Kernel-Development)*.* 您可以通过克隆`git`树来克隆并使用它。

```
git clone https://github.com/PacktPublishing/Linux-Kernel-Programming.git
```

源代码按章节组织。每个章节都表示为一个目录-例如，`ch1/`包含本章的源代码。源树的根目录有一些对所有章节都通用的代码，比如源文件`convenient.h`，`klib_llkd.c`等等。

为了高效地浏览代码，我强烈建议您始终使用`ctags(1)`和/或`cscope(1)`对代码库进行索引。例如，要设置`ctags`索引，只需`cd`到源树的根目录，然后输入`ctags -R`。

除非另有说明，我们在书中展示的代码输出是在 x86-64 *Ubuntu 18.04.3 LTS* 客户 VM 上看到的输出（在 Oracle VirtualBox 6.1 下运行）。您应该意识到，由于（通常是轻微的）分布-甚至在相同的发行版中但是不同的版本-差异，这里显示的输出可能不完全匹配您在 Linux 系统上看到的内容。

# 作为客户 VM 运行 Linux

正如之前讨论的，与使用本机 Linux 系统相比，一个实用和方便的替代方法是在虚拟机上安装和使用 Linux 发行版作为客户端操作系统。重要的是，您安装一个最近的 Linux 发行版，最好作为虚拟机，以确保安全并避免不愉快的数据丢失或其他意外。事实上，当在内核级别工作时，突然崩溃系统（以及由此产生的数据丢失风险）实际上是一个常见的情况。我建议使用**Oracle VirtualBox 6.x**（或最新的稳定版本）或其他虚拟化软件，如**VMware Workstation***.*

这两者都是免费提供的。只是这本书的代码已经在*VirtualBox 6.1*上进行了测试。Oracle VirtualBox 被认为是**开源软件**（**OSS**），并且根据 GPL v2 许可（与 Linux 内核相同）。您可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载它。其文档可以在这里找到：[`www.virtualbox.org/wiki/End-user_documentation`](https://www.virtualbox.org/wiki/End-user_documentation)。

主机系统应该是 MS Windows 10 或更高版本（当然，甚至 Windows 7 也可以），最近的 Linux 发行版（例如 Ubuntu 或 Fedora）或 macOS。因此，让我们通过安装我们的 Linux 客户端来开始。

## 安装 64 位 Linux 客户端

在这里，我不会深入讨论在 Oracle VirtualBox 上安装 Linux 作为客户端的细节，原因是这种安装与 Linux 内核开发*没有*直接关联。有许多设置 Linux 虚拟机的方法；我们真的不想在这里讨论每种方法的细节和利弊。

但如果您对此不熟悉，不用担心。为了您的方便，这里有一些非常好的资源可以帮助您：

+   Abhishek Prakash 撰写的非常清晰的教程，名为*在 VirtualBox 中在 Windows 上安装 Linux*（*It's FOSS！，2019 年 8 月*）：[`itsfoss.com/install-linux-in-virtualbox/`](https://itsfoss.com/install-linux-in-virtualbox/)。

+   另一个同样出色的资源是*在 Oracle VirtualBox 上安装 Ubuntu：*[`brb.nci.nih.gov/seqtools/installUbuntu.html`](https://brb.nci.nih.gov/seqtools/installUbuntu.html)。

此外，您可以在本章末尾的*进一步阅读*部分查找有关在 VirtualBox 上安装 Linux 客户端的有用资源。

在安装 Linux 虚拟机时，请记住以下几点。

### 打开您的 x86 系统的虚拟化扩展支持

安装 64 位 Linux 客户端需要在主机系统的**基本输入/输出系统**（**BIOS**）设置中打开 CPU 虚拟化扩展支持（Intel VT-x 或 AMD-SV）。让我们看看如何做到这一点：

1.  我们的第一步是确保我们的 CPU 支持虚拟化：

1.  **在 Windows 主机上检查这一点有两种广泛的方法**：

+   首先，运行任务管理器应用程序并切换到性能选项卡。在 CPU 图表下，您将看到，除其他几个选项外，有一个名为虚拟化的选项，后面跟着启用或禁用。

+   在 Windows 系统上检查的第二种方法是打开命令窗口（cmd）。在命令提示符中，键入`systeminfo`并按*Enter*。在输出中将看到`固件中启用了虚拟化`一行。它将后面跟着`是`或`否`。

1.  **在 Linux 主机上检查这一点**，从终端，输入以下命令（处理器虚拟化扩展支持：`vmx`是 Intel 处理器的检查，`smv`是 AMD 处理器的检查）：

```
egrep --color "vmx|svm" /proc/cpuinfo 
```

对于 Intel CPU，如果支持虚拟化，`vmx`标志将显示出来（以颜色显示）。对于 AMD CPU，`svm`将显示出来（以颜色显示）。有了这个，我们知道我们的 CPU 支持虚拟化。但是为了使用它，我们需要在计算机 BIOS 中启用它。

1.  通过按*Del*或*F12*进入 BIOS（按键的确切按键因 BIOS 而异）。请参阅系统手册，了解要使用哪个键。搜索诸如`虚拟化`或`虚拟化技术（VT-x）`之类的术语。以下是 Award BIOS 的示例：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/72bfc0d7-0c9b-4ffc-8393-427ca3b78384.png)

图 1.1 - 将 BIOS 虚拟化选项设置为已启用状态

如果您使用的是 Asus EFI-BIOS，则如果默认情况下未设置该条目，则必须将该条目设置为`[Enabled]`。访问[`superuser.com/questions/367290/how-to-enable-hardware-virtualization-on-asus-motherboard/375351#375351`](https://superuser.com/questions/367290/how-to-enable-hardware-virtualization-on-asus-motherboard/375351#375351)。 [](https://superuser.com/questions/367290/how-to-enable-hardware-virtualization-on-asus-motherboard/375351#375351)

1.  现在，选择在 VM 的 VirtualBox 设置菜单中使用硬件虚拟化。要做到这一点，请单击系统，然后加速。之后，检查框，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/e815207f-62a8-4a25-ae0b-b27d80b98be6.png)

图 1.2 - 在 VirtualBox VM 设置中启用硬件虚拟化选项

这就是我们启用主机处理器的硬件虚拟化功能以获得最佳性能的方法。

### 为磁盘分配足够的空间

对于大多数台式机/笔记本系统，为客户 VM 分配 1 GB 的 RAM 和两个 CPU 应该足够了。

但是，在为客户的磁盘分配空间时，请慷慨一些。我强烈建议您将其设置为 50 GB 甚至更多，而不是通常/默认的 8 GB 建议。当然，这意味着主机系统有更多的磁盘空间可用！此外，您可以将此金额指定为*动态分配*或*按需分配*。虚拟机监视程序将以最佳方式“增长”虚拟磁盘，而不是一开始就给它整个空间。

### 安装 Oracle VirtualBox 客户附加组件

为了获得最佳性能，重要的是在客户 VM 中安装 Oracle VirtualBox 客户附加组件。这些本质上是用于优化性能的 para-virtualization 加速软件。让我们看看如何在 Ubuntu 客户会话中执行此操作：

1.  首先，更新您的 Ubuntu 客户操作系统的软件包。您可以使用以下命令来执行此操作：

```
sudo apt update

sudo apt upgrade 
```

1.  完成后，重新启动您的 Ubuntu 客户操作系统，然后使用以下命令安装所需的软件包：

```
sudo apt install build-essential dkms linux-headers-$(uname -r)
```

1.  现在，从 VM 菜单栏，转到设备 | 插入客户附加 CD 映像.... 这将在 VM 内部挂载`客户附加 ISO`文件。以下屏幕截图显示了这样做的样子：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/389c7708-c2c5-4b5b-b039-a454da17fab0.png)

图 1.3 - VirtualBox | 设备 | 插入客户附加 CD 映像

1.  现在，将弹出一个对话框窗口，提示您运行安装程序以启动它。选择运行。

1.  客户添加安装现在将在显示的终端窗口中进行。完成后，按*Enter*键关闭窗口。然后，关闭 Ubuntu 客户操作系统，以便从 VirtualBox 管理器更改一些设置，如下所述。

1.  现在，要在客户机和主机之间启用共享剪贴板和拖放功能，请转到常规 | 高级，并使用下拉菜单启用两个选项（共享剪贴板和拖放）：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/aa611c54-cea4-4676-8abc-c0e5cd159d39.png)

图 1.4 - VirtualBox：启用主机和客户之间的功能

1.  然后，单击 OK 保存设置。现在启动到您的客户系统，登录并测试一切是否正常工作。

截至撰写本文时，Fedora 29 在安装所需的共享文件夹功能的`vboxsf`内核模块时存在问题。我建议您参考以下资源来尝试纠正这种情况：*Bug 1576832* - virtualbox-guest-additions does not mount shared folder (*[`bugzilla.redhat.com/show_bug.cgi?id=1576832`](https://bugzilla.redhat.com/show_bug.cgi?id=1576832))。如果这种方法不起作用，您可以使用`scp(1)`通过 SSH 在主机和来宾 VM 之间传输文件；要这样做，请使用以下命令安装并启动 SSH 守护程序：

`sudo yum install openssh-server`

`sudo systemctl start sshd`

记得定期更新来宾 VM，当提示时。这是一个必要的安全要求。您可以通过以下方式手动执行：

```
sudo /usr/bin/update-manager 
```

最后，请不要在来宾 VM 上保存任何重要数据。我们将进行内核开发。崩溃来宾内核实际上是一个常见的情况。虽然这通常不会导致数据丢失，但你永远无法确定！为了安全起见，请始终备份任何重要数据。这也适用于 Fedora。要了解如何将 Fedora 安装为 VirtualBox 来宾，请访问[`fedoramagazine.org/install-fedora-virtualbox-guest/`](https://fedoramagazine.org/install-fedora-virtualbox-guest/)。

有时，特别是当 X Window 系统（或 Wayland）GUI 的开销太高时，最好只是在控制台模式下工作。您可以通过在引导加载程序中的内核命令行中附加`3`（运行级别）来实现。但是，在 VirtualBox 中以控制台模式工作可能不是那么愉快的体验（例如，剪贴板不可用，屏幕大小和字体不太理想）。因此，只需从主机系统中进行远程登录（通过`ssh`，`putty`或等效工具）到 VM 中，这是一种很好的工作方式。

## 使用树莓派进行实验

树莓派是一种流行的信用卡大小的**单板计算机**（**SBC**），就像一个具有 USB 端口，microSD 卡，HDMI，音频，以太网，GPIO 等的小型 PC。驱动它的**SoC**（**系统芯片**）来自 Broadcom，其中包含 ARM 核心或核心集群。当然，这并非强制要求，但在本书中，我们还努力在树莓派 3 Model B+目标上测试和运行我们的代码。在不同的目标架构上运行代码始终是发现可能缺陷并有助于测试的好方法。我鼓励您也这样做：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/29496127-e03d-4829-b976-47296b7509fe.png)

图 1.5-连接到其 GPIO 引脚的树莓派的 USB 到串行适配器电缆

您可以使用数字监视器/电视通过 HDMI 作为输出设备和传统键盘/鼠标通过其 USB 端口，或者更常见的是通过`ssh(1)`远程 shell 在树莓派目标上工作。但是，在某些情况下，SSH 方法并不适用。在树莓派上有一个*串行控制台*有所帮助，特别是在进行内核调试时。

我建议您查看以下文章，该文章将帮助您建立 USB 到串行连接，从而可以从 PC /笔记本电脑登录到树莓派的控制台：*使用树莓派在控制台上工作，* kaiwanTECH：[`kaiwantech.wordpress.com/2018/12/16/working-on-the-console-with-the-raspberry-pi/`](https://kaiwantech.wordpress.com/2018/12/16/working-on-the-console-with-the-raspberry-pi/)。

要设置您的树莓派，请参阅官方文档：[`www.raspberrypi.org/documentation/`](https://www.raspberrypi.org/documentation/)。我们的树莓派系统运行“官方”Raspbian（树莓派的 Debian）Linux 操作系统，带有最新（写作时）的 4.14 Linux 内核。在树莓派的控制台上，我们运行以下命令：

```
rpi $ lsb_release -a
No LSB modules are available.
Distributor ID: Raspbian
Description:    Raspbian GNU/Linux 9.6 (stretch)
Release:        9.6
Codename:       stretch
rpi $ uname -a
Linux raspberrypi 4.14.79-v7+ #1159 SMP Sun Nov 4 17:50:20 GMT 2018 armv7l GNU/Linux
rpi $ 
```

如果您没有树莓派，或者它不方便使用，那怎么办？嗯，总是有办法——模拟！虽然不如拥有真正的设备好，但用强大的**自由开源软件**（**FOSS**）模拟器**QEMU**或**Quick Emulator**模拟树莓派是一个不错的开始方式，至少是这样。

由于设置通过 QEMU 模拟树莓派的细节超出了本书的范围，我们将不予涵盖。但是，您可以查看以下链接以了解更多信息：*在 Linux 上模拟树莓派*：[`embedonix.com/articles/linux/emulating-raspberry-pi-on-linux/`](http://embedonix.com/articles/linux/emulating-raspberry-pi-on-linux/)和*qemu-rpi-kernel，GitHub*：[`github.com/dhruvvyas90/qemu-rpi-kernel/wiki`](https://github.com/dhruvvyas90/qemu-rpi-kernel/wiki)。

当然，您不必局限于树莓派家族；还有几个其他出色的原型板可供选择。其中一个让人印象深刻的是流行的**BeagleBone Black**（**BBB**）开发板。

实际上，对于专业开发和产品工作来说，树莓派并不是最佳选择，原因有几个……稍微搜索一下就能理解。话虽如此，作为学习和基本原型环境，它很难被超越，因为它拥有强大的社区（和技术爱好者）支持。

在这篇深度文章中，讨论并对比了几种嵌入式 Linux（以及更多）的现代微处理器选择：*SO YOU WANT TO BUILD AN EMBEDDED LINUX SYSTEM?*，Jay Carlson，2020 年 10 月：[`jaycarlson.net/embedded-linux/`](https://jaycarlson.net/embedded-linux/)；请查看。

到目前为止，我希望您已经设置了 Linux 作为虚拟机（或者正在使用本地的“测试”Linux 框）并克隆了本书的 GitHub 代码库。到目前为止，我们已经涵盖了一些关于将 Linux 设置为虚拟机（以及可选地使用树莓派或 BeagleBone 等开发板）的信息。现在让我们继续进行一个关键步骤：在我们的 Linux 虚拟系统上实际安装软件组件，以便我们可以在系统上学习和编写 Linux 内核代码！

# 设置软件——发行版和软件包

建议使用以下或更高版本的稳定版 Linux 发行版。正如前一节中提到的，它们始终可以安装为 Windows 或 Linux 主机系统的虚拟操作系统，首选当然是 Ubuntu Linux 18.04 LTS 桌面。以下截图显示了推荐的版本和用户界面：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/ebd213e7-04ce-4dcd-909e-0977d073f2a8.png)

图 1.6 - Oracle VirtualBox 6.1 运行 Ubuntu 18.04.4 LTS 作为虚拟机

上一个版本——Ubuntu 18.04 LTS 桌面——至少对于本书来说是首选版本。选择这个版本的两个主要原因很简单：

+   Ubuntu Linux 是当今工业中最受欢迎的 Linux（内核）开发工作站环境之一，如果不是*最*受欢迎的话。

+   由于篇幅和清晰度的限制，我们无法在本书中展示多个环境的代码/构建输出。因此，我们选择以 Ubuntu 18.04 LTS 桌面上看到的输出来展示。

Ubuntu 16.04 LTS 桌面也是一个不错的选择（它也有**长期支持**（**LTS**）），一切都应该可以正常工作。要下载它，请访问[`www.ubuntu.com/download/desktop`](https://www.ubuntu.com/download/desktop)。

还可以考虑一些其他 Linux 发行版，包括以下内容：

+   **CentOS 8 Linux（不是 CentOS Stream）**：CentOS Linux 是一个基本上是 RedHat 流行企业服务器发行版（在我们的案例中是 RHEL 8）的克隆。您可以从这里下载：[`www.centos.org/download/`](https://www.centos.org/download/)。

+   **Fedora Workstation**：Fedora 也是一个非常知名的 FOSS Linux 发行版。您可以将其视为 RedHat 企业产品中最终会出现的项目和代码的测试平台。从[`getfedora.org/`](https://getfedora.org/)下载（下载 Fedora Workstation 镜像）。

+   **Raspberry Pi 作为目标**：最好参考官方文档来设置您的 Raspberry Pi（*Raspberry Pi 文档*：[`www.raspberrypi.org/documentation/`](https://www.raspberrypi.org/documentation/)）。也许值得注意的是，广泛提供完全预安装的 Raspberry Pi“套件”，还配备了一些硬件配件。

如果您想学习如何在 SD 卡上安装 Raspberry Pi OS 映像，请访问[`www.raspberrypi.org/documentation/installation/installing-images/`](https://www.raspberrypi.org/documentation/installation/installing-images)。

+   **BeagleBone Black 作为目标**：BBB 与 Raspberry Pi 一样，是业余爱好者和专业人士非常受欢迎的嵌入式 ARM SBC。您可以从这里开始：[`beagleboard.org/black`](https://beagleboard.org/black)。BBB 的系统参考手册可以在这里找到：[`cdn.sparkfun.com/datasheets/Dev/Beagle/BBB_SRM_C.pdf`](https://cdn.sparkfun.com/datasheets/Dev/Beagle/BBB_SRM_C.pdf)。尽管我们没有在 BBB 上运行示例，但它仍然是一个有效的嵌入式 Linux 系统，一旦正确设置，您可以在上面运行本书的代码。

在我们结束对书中软件发行版的选择讨论之前，还有一些要注意的地方：

+   这些发行版在其默认形式下是 FOSS 和非专有的，可以作为最终用户免费使用。

+   尽管我们的目标是成为与 Linux 发行版无关，但代码只在 Ubuntu 18.04 LTS 上进行了测试，并在 CentOS 8 上进行了“轻微”测试，以及在运行基于 Debian 的 Raspbian GNU/Linux 9.9（stretch）的 Raspberry Pi 3 Model B+上进行了测试。

+   我们将尽可能使用最新的（在撰写时）**稳定的 LTS**

**Linux 内核版本 5.4**用于我们的内核构建和代码运行。作为 LTS 内核，5.4 内核是一个非常好的选择来运行和学习。

有趣的是，5.4 LTS 内核的寿命将会很长；从 2019 年 11 月一直到 2025 年 12 月！这是个好消息：本书的内容将在未来几年内保持最新和有效！

+   对于这本书，我们将以名为`llkd`的用户帐户登录。

要最大限度地提高安全性（使用最新的防御和修复），您必须运行最新的**长期支持**（**LTS**）内核，以便用于您的项目或产品。

现在我们已经选择了我们的 Linux 发行版和/或硬件板和 VM，是时候安装必要的软件包了。

## 安装软件包

当您使用典型的 Linux 桌面发行版（如任何最近的 Ubuntu、CentOS 或 Fedora Linux 系统）时，默认安装的软件包将包括系统程序员所需的最小设置：本地工具链，其中包括`gcc`编译器和头文件，以及`make`实用程序/软件包。

在本书中，我们将学习如何使用 VM 和/或在外部处理器（ARM 或 AArch64 是典型情况）上运行的目标系统编写内核空间代码。为了有效地在这些系统上开发内核代码，我们需要安装一些软件包。继续阅读。

### 安装 Oracle VirtualBox 客户附加组件

确保您已安装了客户端 VM（如前所述）。然后，跟着做：

1.  登录到您的 Linux 客户 VM，首先在终端窗口（shell 上）运行以下命令：

```
sudo apt update
sudo apt install gcc make perl
```

1.  现在安装 Oracle VirtualBox 客户附加组件。参考*如何在 Ubuntu 中安装 VirtualBox 客户附加组件：*[`www.tecmint.com/install-virtualbox-guest-additions-in-ubuntu/`](https://www.tecmint.com/install-virtualbox-guest-additions-in-ubuntu/)。

只有当您将 Ubuntu 作为使用 Oracle VirtualBox 作为 hypervisor 应用程序的 VM 运行时才适用。

### 安装所需的软件包

要安装这些软件包，请执行以下步骤：

1.  在 Ubuntu VM 中，首先执行以下操作：

```
sudo apt update
```

1.  现在，在一行中运行以下命令：

```
sudo apt install git fakeroot build-essential tar ncurses-dev tar xz-utils libssl-dev bc stress python3-distutils libelf-dev linux-headers-$(uname -r) bison flex libncurses5-dev util-linux net-tools linux-tools-$(uname -r) exuberant-ctags cscope sysfsutils gnome-system-monitor curl perf-tools-unstable gnuplot rt-tests indent tree pstree smem libnuma-dev numactl hwloc bpfcc-tools sparse flawfinder cppcheck tuna hexdump openjdk-14-jre trace-cmd virt-what
```

首先执行安装`gcc`，`make`和`perl`的命令，以便可以直接安装 Oracle VirtualBox Guest Additions。这些（Guest Additions）本质上是 para-virtualization 加速软件。安装它们对于性能优化很重要。

这本书有时提到在另一个 CPU 架构上运行程序-通常是 ARM-可能是一个有用的练习。如果您想尝试（有趣！）这样的东西，请继续阅读；否则，可以随意跳到*重要的安装注意事项*部分。

### 安装交叉工具链和 QEMU

在 ARM 机器上尝试事物的一种方法是实际在物理 ARM-based SBC 上这样做；例如，树莓派是一个非常受欢迎的选择。在这种情况下，典型的开发工作流程是首先在 x86-64 主机系统上构建 ARM 代码。但为了这样做，我们需要安装一个**交叉工具链**-一组工具，允许您在一个设计为在不同*目标*CPU 上执行的主机 CPU 上构建软件。一个 x86-64 *主机*构建 ARM *目标*的程序是一个非常常见的情况，确实是我们的用例。稍后将详细介绍安装交叉编译器的详细信息。

通常，尝试事物的另一种方法是模拟 ARM/Linux 系统-这样可以减轻对硬件的需求！为此，我们建议使用出色的**QEMU**项目（[`www.qemu.org/`](https://www.qemu.org/)）。

要安装所需的 QEMU 软件包，请执行以下操作：

+   对于 Ubuntu 的安装，请使用以下命令：

```
sudo apt install qemu-system-arm
```

+   对于 Fedora 的安装，请使用以下命令：

```
sudo dnf install qemu-system-arm-<version#>
```

要在 Fedora 上获取版本号，只需输入前面的命令，然后在输入所需的软件包名称（这里是`qemu-system-arm-`）后，按两次*Tab*键。它将自动完成，提供一个选择列表。选择最新版本，然后按*Enter*。

CentOS 8 似乎没有简单的方法来安装我们需要的 QEMU 软件包。（您可以通过源代码安装交叉工具链，但这很具有挑战性；或者，获取一个合适的二进制软件包。）由于这些困难，我们将跳过在 CentOS 上展示交叉编译。

### 安装交叉编译器

如果您打算编写一个在特定主机系统上编译但必须在另一个目标系统上执行的 C 程序，那么您需要使用所谓的交叉编译器或交叉工具链进行编译。例如，在我们的用例中，我们希望在一个 x86-64 主机上工作。甚至可以是 x86-64 虚拟机，没有问题，但在 ARM-32 目标上运行我们的代码：

+   在 Ubuntu 上，您可以使用以下命令安装交叉工具链：

```
sudo apt install crossbuild-essential-armhf 
```

前面的命令安装了适用于 ARM-32“硬浮点”（armhf）系统（例如树莓派）的 x86_64 到 ARM-32 工具链（通常很好）。它会安装`arm-linux-gnueabihf-<foo>`一组工具；其中`<foo>`代表交叉工具，如`addr2line`，`as`，`g++`，`gcc`，`gcov`，`gprof`，`ld`，`nm`，`objcopy`，`objdump`，`readelf`，`size`，`strip`等。 （在这种情况下，交叉编译器前缀是`arm-linux-gnueabihf-`）。此外，虽然不是强制的，您也可以这样安装`arm-linux-gnueabi-<foo>`交叉工具集：

```
sudo apt install gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi
```

+   在 Fedora 上，您可以使用以下命令安装交叉工具链：

```
sudo dnf install arm-none-eabi-binutils-cs-<ver#> arm-none-eabi-gcc-cs-<ver#>
```

对于 Fedora Linux，与之前相同的提示适用-使用*Tab*键来帮助自动完成命令。

安装和使用交叉工具链可能需要一些新手用户的阅读。您可以访问*进一步阅读*部分，我在那里放置了一些有用的链接，这些链接肯定会帮助很大。

## 重要的安装注意事项

我们现在将提到一些剩下的要点，其中大部分涉及软件安装或在特定发行版上工作时的其他问题：

+   在 CentOS 8 上，您可以使用以下命令安装 Python：

```
sudo dnf install python3
```

然而，这实际上并没有创建（必需的）**符号链接**（**symlink**），`/usr/bin/python`；为什么呢？查看此链接获取详细信息：[`developers.redhat.com/blog/2019/05/07/what-no-python-in-red-hat-enterprise-linux-8/`](https://developers.redhat.com/blog/2019/05/07/what-no-python-in-red-hat-enterprise-linux-8/)。

手动创建符号链接，例如 `python3`，请执行以下操作：

```
sudo alternatives --set python /usr/bin/python3
```

+   如果未安装 OpenSSL 头文件，内核构建可能会失败。在 CentOS 8 上使用以下命令修复：

```
sudo dnf install openssl-devel
```

+   在 CentOS 8 上，可以使用以下命令安装 `lsb_release` 实用程序：

```
sudo dnf install redhat-lsb-core
```

+   在 Fedora 上，执行以下操作：

+   安装这两个包，确保在 Fedora 系统上构建内核时满足依赖关系：

`sudo dnf install openssl-devel-1:1.1.1d-2.fc31 elfutils-libelf-devel`（前面的`openssl-devel`包后缀为相关的 Fedora 版本号（这里是`.fc31`；根据您的系统需要进行调整）。

+   为了使用 `lsb_release` 命令，您必须安装 `redhat-lsb-core` 包。

恭喜！软件设置完成，您的内核之旅开始了！现在，让我们看看一些额外的有用项目，以完成本章。强烈建议您也阅读这些。

# 额外有用的项目

本节为您带来了一些额外的杂项项目的详细信息，您可能会发现它们非常有用。在本书的一些适当的地方，我们提到或直接使用了其中一些，因此理解它们非常重要。

让我们开始熟悉并重要的 Linux *man 页面*项目。

## 使用 Linux man 页面

您一定已经注意到了大多数 Linux/Unix 文献中遵循的惯例：

+   *用户命令* 的后缀为 `(1)` – 例如， `gcc(1)` 或 `gcc.1`

+   *系统调用* 带有 `(2)` – 例如， `fork(2)` 或 `fork().2`

+   *库 API* 带有 `(3)` – 例如， `pthread_create(3)` 或 `pthread_create().3`

正如您无疑所知，括号中的数字（或句号后面的数字）表示命令/API 所属的**手册**（**man**页面）的部分。通过 `man(1)` 快速检查，通过 `man man` 命令 （这就是我们喜欢 Unix/Linux 的原因！）可以查看 Unix/Linux 手册的部分：

```
$ man man
[...]
A section, if provided, will direct man to look only in that section of
the manual. [...]

       The table below shows the section numbers of the manual followed by the types of pages they contain.

       1   Executable programs or shell commands
       2   System calls (functions provided by the kernel)
       3   Library calls (functions within program libraries)
       4   Special files (usually found in /dev)
       5   File formats and conventions eg /etc/passwd
       6   Games
       7   Miscellaneous (including macro packages and conventions), e.g. 
           man(7), groff(7)
       8   System administration commands (usually only for root)
       9   Kernel routines [Non standard]
[...]
```

因此，例如，要查找 `stat(2)` 系统调用的 man 页面，您将使用以下命令：

```
man 2 stat # (or: man stat.2)
```

有时（实际上经常），`man`页面太详细了，不值得阅读，只需要一个快速答案。这就是 `tldr` 项目的用途 – 继续阅读！

### tldr 变种

当我们讨论`man`页面时，一个常见的烦恼是命令的`man`页面有时太大了。以 `ps(1)` 实用程序为例。它有一个很大的`man`页面，因为它当然有大量的选项开关。不过，有一个简化和总结的“常见用法”页面会很好，对吧？这正是 `tldr` 页面项目的目标。

**TL;DR** 字面意思是 **太长了；没读***.*

他们提供*“简化和社区驱动的 man 页面。”*因此，一旦安装，`tldr ps` 提供了一个简洁的摘要，介绍了最常用的`ps` 命令选项开关，以便做一些有用的事情：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/a3222a01-e03c-4c9b-842d-d16a5295ee50.png)

图 1.7 – tldr 实用程序的截图：tldr ps

所有 Ubuntu 仓库都有 `tldr` 包。使用 `sudo apt install tldr` 进行安装。

确实值得一看。如果您想了解更多，请访问 [`tldr.sh/`](https://tldr.sh/)。

早些时候，我们提到用户空间系统调用属于 man 页面的第二部分，库子例程属于第三部分，内核 API 属于第九部分。鉴于此，在本书中，为什么我们不将，比如，`printk`内核函数（或 API）指定为`printk(9)` - 因为`man man`向我们展示手册的第九部分是*Kernel routines*？嗯，实际上这是虚构的（至少在今天的 Linux 上）：*内核 API 实际上没有 man 页面！*那么，你如何获取内核 API 的文档等？这正是我们将在下一节中简要探讨的内容。

## 查找和使用 Linux 内核文档

社区经过多年的努力，已经将 Linux 内核文档发展和演变到一个良好的状态。内核文档的*最新版本*以一种漂亮和现代的“web”风格呈现，可以在这里在线访问：[`www.kernel.org/doc/html/latest/`](https://www.kernel.org/doc/html/latest/)。

当然，正如我们将在下一章中提到的那样，内核文档始终可以在内核源树中的该内核版本中找到，位于名为`Documentation/`的目录中。

作为在线内核文档的一个例子，可以查看以下页面的部分截图*Core Kernel Documentation*/*Basic C Library Functions* ([`www.kernel.org/doc/html/latest/core-api/kernel-api.html#basic-c-library-functions`](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html#basic-c-library-functions))：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/89f4c179-15d9-4d6e-a241-9e984e14ebae.png)

图 1.8 - 部分截图显示现代在线 Linux 内核文档的一小部分

从截图中可以看出，现代文档非常全面。

### 从源代码生成内核文档

你可以从内核源树中以各种流行的格式（包括 PDF、HTML、LaTeX、EPUB 或 XML）生成完整的 Linux 内核文档，以*Javadoc*或*Doxygen*风格。内核内部使用的现代文档系统称为**Sphinx**。在内核源树中使用`make help`将显示几个*文档目标*，其中包括`htmldocs`、`pdfdocs`等。因此，例如，你可以`cd`到内核源树并运行`make pdfdocs`来构建完整的 Linux 内核文档作为 PDF 文档（PDF 文档以及其他一些元文档将放在`Documentation/output/latex`中）。至少在第一次，你可能会被提示安装几个软件包和实用程序（我们没有明确显示这一点）。

如果前面的细节还不是很清楚，不要担心。我建议你先阅读第二章，*从源代码构建 5.x Linux 内核-第一部分*，和第三章，*从源代码构建 5.x Linux 内核-第二部分*，然后再回顾这些细节。

## Linux 内核的静态分析工具

静态分析工具是通过检查源代码来尝试识别其中潜在错误的工具。它们对开发人员非常有用，尽管你必须学会如何“驯服”它们 - 因为它们可能会产生误报。

存在一些有用的静态分析工具。其中，对于 Linux 内核代码分析更相关的工具包括以下内容：

+   Sparse: [`sparse.wiki.kernel.org/index.php/Main_Page`](https://sparse.wiki.kernel.org/index.php/Main_Page)

+   Coccinelle: [`coccinelle.lip6.fr/`](http://coccinelle.lip6.fr/)（需要安装`ocaml`包）

+   Smatch: [`smatch.sourceforge.net/`](http://smatch.sourceforge.net/)，[`repo.or.cz/w/smatch.git`](http://repo.or.cz/w/smatch.git)

+   Flawfinder: [`dwheeler.com/flawfinder/`](https://dwheeler.com/flawfinder/)

+   Cppcheck: [`github.com/danmar/cppcheck`](https://github.com/danmar/cppcheck)

例如，要安装并尝试 Sparse，请执行以下操作：

```
sudo apt install sparse
cd <kernel-src-tree>
make C=1 CHECK="/usr/bin/sparse" 
```

还有一些高质量的商业静态分析工具可用。其中包括以下内容：

+   SonarQube: [`www.sonarqube.org/`](https://www.sonarqube.org/)（提供免费的开源社区版）

+   Coverity Scan: [`scan.coverity.com/`](https://scan.coverity.com/)

+   Klocwork: [`www.meteonic.com/klocwork`](https://www.meteonic.com/klocwork)

`clang`是 GCC 的前端，即使用于内核构建也越来越受欢迎。您可以使用`sudo apt install clang clang-tools`在 Ubuntu 上安装它。

静态分析工具可以帮助解决问题。花时间学习如何有效使用它们是值得的！

## Linux Trace Toolkit next generation

用于*跟踪*和*分析*的绝佳工具是功能强大的**Linux Tracing Toolkit next generation**（LTTng）工具集，这是一个 Linux 基金会项目。LTTng 允许您详细跟踪用户空间（应用程序）和/或内核代码路径。这可以极大地帮助您了解性能瓶颈出现在哪里，以及帮助您了解整体代码流程，从而了解代码实际执行任务的方式。

为了学习如何安装和使用它，我建议您参考这里非常好的文档：[`lttng.org/docs`](https://lttng.org/docs)（尝试[`lttng.org/download/`](https://lttng.org/download/) 安装常见的 Linux 发行版）。强烈建议您安装 Trace Compass GUI：[`www.eclipse.org/tracecompass/`](https://www.eclipse.org/tracecompass/)。它提供了一个优秀的 GUI 来检查和解释 LTTng 的输出。

Trace Compass 最低要求安装**Java Runtime Environment**（JRE）。我在我的 Ubuntu 20.04 LTS 系统上安装了一个，使用`sudo apt install openjdk-14-jre`。

举个例子（我忍不住！），这是 LTTng 捕获的截图，由出色的 Trace Compass GUI“可视化”。在这里，我展示了一些硬件中断（IRQ 线 1 和 130，分别是我的本机 x86_64 系统上 i8042 和 Wi-Fi 芯片组的中断线。）

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/3845add2-b5a5-4f1b-a6b2-a2bb787f58e9.png)

图 1.9 - Trace Compass GUI 的示例截图；由 LTTng 记录的显示 IRQ 线 1 和 130 的样本

前面截图上部的粉色表示硬件中断的发生。在下面，在 IRQ vs Time 标签（仅部分可见），可以看到中断分布。（在分布图中，*y*轴是所花费的时间；有趣的是，网络中断处理程序 - 以红色显示 - 似乎花费的时间很少，i8042 键盘/鼠标控制器芯片的处理程序 - 以蓝色显示 - 花费更多时间，甚至超过 200 微秒！）

## procmap 实用程序

`procmap`实用程序的设计目的是可视化内核**虚拟地址空间**（VAS）的完整内存映射，以及任何给定进程的用户 VAS。

其 GitHub 页面上的描述总结如下：

<q>它以垂直平铺的格式输出给定进程的完整内存映射的简单可视化，按降序虚拟地址排序。脚本具有智能功能，可以显示内核和用户空间映射，并计算并显示将出现的稀疏内存区域。此外，每个段或映射都按相对大小进行缩放（并以颜色编码以便阅读）。在 64 位系统上，它还显示所谓的非规范稀疏区域或“空洞”（通常接近 x86_64 上的 16,384 PB）。</q>

该实用程序包括查看仅内核空间或用户空间、详细和调试模式、将输出以便于的 CSV 格式导出到指定文件以及其他选项。它还有一个内核组件，目前可以在 x86_64、AArch32 和 Aarch64 CPU 上**工作**（并自动检测）。

请注意，我仍在开发此实用程序...目前仍有一些注意事项。欢迎反馈和贡献！

从[`github.com/kaiwan/procmap`](https://github.com/kaiwan/procmap)下载/克隆它：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/c6518827-5c73-4216-8c8d-3dfb7675c5c1.png)

图 1.10- procmap 实用程序输出的部分截图，仅显示 x86_64 内核 VAS 的顶部部分

我们在第七章中充分利用了这个实用程序，*内存管理内部-基础*。

## 简单的嵌入式 ARM Linux 系统 FOSS 项目

**SEALS**或**Simple Embedded ARM Linux System**是一个非常简单的“骨架”Linux 基本系统，运行在模拟的 ARM 机器上。它提供了一个主要的 Bash 脚本，通过菜单询问最终用户需要什么功能，然后相应地继续为 ARM 交叉编译 Linux 内核，然后创建和初始化一个简单的根文件系统。然后可以调用 QEMU（`qemu-system-arm`）来模拟和运行 ARM 平台（Versatile Express CA-9 是默认的模拟板）。有用的是，该脚本构建目标内核、根文件系统和根文件系统映像文件，并设置引导。它甚至有一个简单的 GUI（或控制台）前端，以使最终用户的使用变得更简单一些。该项目的 GitHub 页面在这里：[`github.com/kaiwan/seals/`](https://github.com/kaiwan/seals/)。克隆它并试试看...我们强烈建议您查看其 wiki 部分页面以获取帮助。

## 使用[e]BPF 进行现代跟踪和性能分析

作为众所周知的**伯克利数据包过滤器**或**BPF**的扩展，**eBPF**是**扩展 BPF**（顺便说一句，现代用法是简单地将其称为**BPF**，去掉前缀'e'）。简而言之，BPF 用于在内核中提供支持基本上是为了有效地跟踪网络数据包。BPF 是非常近期的内核创新-仅从 Linux 4.0 内核开始可用。它扩展了 BPF 的概念，允许您跟踪的不仅仅是网络堆栈。此外，它适用于跟踪内核空间和用户空间应用程序。*实际上，BPF 及其前端是在 Linux 系统上进行跟踪和性能分析的现代方法*。

要使用 BPF，您需要具有以下系统：

+   Linux 内核 4.0 或更高版本

+   BPF 的内核支持（[`github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration`](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration)）

+   已安装**BCC**或`bpftrace`前端（在流行的 Linux 发行版上安装它们的链接：[`github.com/iovisor/bcc/blob/master/INSTALL.md#installing-bcc`](https://github.com/iovisor/bcc/blob/master/INSTALL.md#installing-bcc)）

+   目标系统上的根访问权限

直接使用 BPF 内核功能非常困难，因此有几个更容易的前端可供使用。其中，BCC 和`bpftrace`被认为是有用的。查看以下链接，了解有多少强大的 BCC 工具可用于帮助跟踪不同的 Linux 子系统和硬件：[`github.com/iovisor/bcc/blob/master/images/bcc_tracing_tools_2019.png`](https://github.com/iovisor/bcc/blob/master/images/bcc_tracing_tools_2019.png)。

重要提示：您可以通过阅读此处的安装说明在您的常规主机 Linux 发行版上安装 BCC 工具：[`github.com/iovisor/bcc/blob/master/INSTALL.md`](https://github.com/iovisor/bcc/blob/master/INSTALL.md)。为什么不能在我们的 Linux VM 上安装？当运行发行版内核（如 Ubuntu 或 Fedora 提供的内核）时，您可以。原因是：BCC 工具集的安装包括（并依赖于）`linux-headers-$(uname -r)`包的安装；这个`linux-headers`包仅适用于发行版内核（而不适用于我们经常在客人上运行的自定义 5.4 内核）。

BCC 的主要网站可以在[`github.com/iovisor/bcc`](https://github.com/iovisor/bcc)找到。

## LDV - Linux 驱动程序验证 - 项目

成立于 2005 年的俄罗斯 Linux 验证中心是一个开源项目；它拥有专家，并因此专门从事复杂软件项目的自动化测试。这包括在核心 Linux 内核以及主要的内核内设备驱动程序上执行的全面测试套件、框架和详细分析（静态和动态）。该项目还非常注重对*内核模块*的测试和验证，而许多类似的项目往往只是粗略地涉及。

我们特别感兴趣的是在线 Linux 驱动程序验证服务页面([`linuxtesting.org/ldv/online?action=rules`](http://linuxtesting.org/ldv/online?action=rules))；它包含了一些经过验证的规则（图 1.11）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/e0e68bf6-a2d9-4bb0-b09e-cc02a2bf32da.png)

图 1.11 - Linux 驱动程序验证（LDV）项目网站的“规则”页面的屏幕截图

通过浏览这些规则，我们不仅能够看到规则，还能看到这些规则在主线内核中被驱动程序/内核代码违反的实际案例，从而引入了错误。LDV 项目已成功发现并修复（通过通常方式发送补丁）了几个驱动程序/内核错误。在接下来的几章中，我们将提到这些 LDV 规则违反的实例（例如，内存泄漏，**使用后释放**（UAF）错误和锁定违规）已经被发现，并（可能）已经修复。

以下是 LDV 网站上一些有用的链接：

+   Linux 验证中心主页；[`linuxtesting.org/`](http://linuxtesting.org/)

+   Linux 内核空间验证；[`linuxtesting.org/kernel`](http://linuxtesting.org/kernel)

+   在线 Linux 驱动程序验证服务页面**具有经过验证的规则**：[`linuxtesting.org/ldv/online?action=rules`](http://linuxtesting.org/ldv/online?action=rules)

+   *Linux 内核中的问题*页面；列出了现有驱动程序中发现的 400 多个问题（大部分也已经修复）；[`linuxtesting.org/results/ldv`](http://linuxtesting.org/results/ldv)

# 总结

在本章中，我们详细介绍了设置适当的开发环境的硬件和软件要求，以便开始进行 Linux 内核开发。此外，我们提到了基础知识，并在适当的地方提供了设置树莓派设备、安装强大工具如 QEMU 和交叉工具链等的链接。我们还介绍了其他一些“杂项”工具和项目，作为一个新手内核和/或设备驱动程序开发人员，您可能会发现这些工具和如何开始查找内核文档的信息很有用。

在本书中，我们强烈建议并期望您以实际操作的方式尝试并开展内核代码的工作。为此，您必须设置一个适当的内核工作空间环境，我们在本章中已经成功完成了这一点。

现在我们的环境已经准备好，让我们继续探索 Linux 内核开发的广阔世界吧！接下来的两章将教您如何从源代码下载、提取、配置和构建 Linux 内核。

# 问题

最后，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会发现一些问题的答案在书的 GitHub 存储库中：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入了解这个主题并提供有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）。*进一步阅读*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。


# 第二章：从源代码构建 5.x Linux 内核 - 第一部分

从源代码构建 Linux 内核是开始内核开发之旅的有趣方式！请放心，这是一个漫长而艰巨的旅程，但这就是其中的乐趣，对吧？内核构建主题本身足够大，值得分成两章，本章和下一章。

本章和下一章的主要目的是详细描述如何从头开始、从源代码构建 Linux 内核。在本章中，您将首先学习如何将稳定的原始 Linux 内核源树下载到一个 Linux**虚拟机**（**VM**）上（通过原始内核，我们指的是 Linux 内核社区在其存储库上发布的普通默认内核源代码，[`www.kernel.org`](https://kernel.org)）。接下来，我们将学习一些关于内核源代码布局的知识 - 实际上是对内核代码库的一个整体概览。然后是实际的内核构建过程。

在继续之前，一个关键信息：任何 Linux 系统，无论是超级计算机还是微型嵌入式设备，都有三个必需的组件：引导加载程序、**操作系统**（**OS**）内核和根文件系统。在本章中，我们只关注从源代码构建 Linux 内核。我们不深入研究根文件系统的细节，并且（在下一章中）学习如何最小化配置（非常特定于 x86 的）GNU GRUB 引导加载程序。

在本章中，我们将涵盖以下主题：

+   内核构建的前提条件

+   构建内核的步骤

+   第 1 步 - 获取 Linux 内核源树

+   第 2 步 - 提取内核源树

+   第 3 步 - 配置 Linux 内核

+   自定义内核菜单 - 添加我们自己的菜单项

# 技术要求

我假设您已经阅读了第一章，*内核工作空间设置*，并已经适当地准备了一个运行 Ubuntu 18.04 LTS（或 CentOS 8，或这些发行版的后续稳定版本）的客户 VM，并安装了所有必需的软件包。如果没有，我强烈建议您首先这样做。

为了充分利用本书，我强烈建议您首先设置工作空间环境，包括克隆本书的 GitHub 存储库（[`github.com/PacktPublishing/Linux-Kernel-Programming`](https://github.com/PacktPublishing/Linux-Kernel-Programming)）以获取代码，并进行实际操作。

# 内核构建的前提条件

从一开始就了解一些事情对我们在构建和使用 Linux 内核的旅程中会有所帮助。首先，Linux 内核及其姊妹项目是完全去中心化的 - 这是一个虚拟的、在线的开源社区！我们最接近办公室的地方是：Linux 内核（以及几十个相关项目）的管理权在 Linux 基金会（[`linuxfoundation.org/`](https://linuxfoundation.org/)）的有力掌握之下；此外，它管理着 Linux 内核组织，这是一个私人基金会，向公众免费分发 Linux 内核（[`www.kernel.org/nonprofit.html`](https://www.kernel.org/nonprofit.html)）。

本节讨论的一些关键点包括以下内容：

+   内核发布，或版本号命名法

+   典型的内核开发工作流程

+   存储库中不同类型的内核源树的存在

有了这些信息，您将更好地了解内核构建过程。好的，让我们逐个讨论前面提到的每一点。

## **内核发布命名法**

要查看内核版本号，只需在 shell 上运行`uname -r`。如何准确解释`uname -r`的输出？在我们的 Ubuntu 18.04 LTS 客户 VM 上，我们运行`uname(1)`，传递`-r`选项开关，只显示当前的内核发布或版本：

```
$ uname -r
5.0.0-36-generic 
```

当然，在您阅读本文时，Ubuntu 18.04 LTS 内核肯定已经升级到了更高的版本；这是完全正常的。在我写这一章节时，5.0.0-36-generic 内核是我在 Ubuntu 18.04.3 LTS 中遇到的版本。

现代 Linux 内核发布号命名规范如下：

```
major#.minor#[.patchlevel][-EXTRAVERSION]
```

这也经常被写成或描述为`w.x[.y][-z]`。

方括号表示`patchlevel`和`EXTRAVERSION`组件是可选的。以下表总结了发布号的各个组件的含义：

| **发布号组件** | **含义** | **示例号码** |
| --- | --- | --- |
| 主要`#`（或`w`） | 主要号码；目前，我们在 5.x 内核系列上，因此主要号码是`5`。 | `2`，`3`，`4`和`5` |
| 次要`#`（或`x`） | 次要号码，在主要号码之下。 | `0`及以上 |
| `[patchlevel]`（或`y`） | 在次要号码之下 - 也称为 ABI 或修订版 - 在需要时应用于稳定内核，以进行重要的错误/安全修复。 | `0`及以上 |
| `[-EXTRAVERSION]`（或`-z`） | 也称为`localversion`；通常由发行版内核用于跟踪其内部更改。 | 变化；Ubuntu 使用`w.x.y-'n'-generic` |

表 2.1 - Linux 内核发布命名规范

因此，我们现在可以解释我们 Ubuntu 18.04 LTS 发行版的内核发布号`5.0.0-36-generic`：

+   **主要#（或 w）**：`5`

+   **次要#（或 x）**：`0`

+   **[patchlevel]（或 y）**：`0`

+   **[-EXTRAVERSION]（或-z）**：`-36-generic`

请注意，发行版内核可能会或可能不会严格遵循这些约定，这取决于他们自己。在[`www.kernel.org/`](https://www.kernel.org/)发布的常规或原始内核确实遵循这些约定（至少在 Linus 决定更改它们之前）。

（a）作为一个有趣的练习配置内核的一部分，我们将稍后更改我们构建的内核的`localversion`（又名`-EXTRAVERSION`）组件。

（b）在 2.6 之前的内核中（也就是说，现在是古老的东西），*次要号*具有特殊的含义；如果是偶数，表示稳定的内核发布，如果是奇数，表示不稳定或测试版发布。现在不再是这样了。

## 内核开发工作流程 - 基础知识

在这里，我们简要概述了典型的内核开发工作流程。任何像您一样对内核开发感兴趣的人，至少应该对这个过程有基本的了解。

可以在内核文档中找到详细描述：[`www.kernel.org/doc/html/latest/process/2.Process.html#how-the-development-process-works`](https://www.kernel.org/doc/html/latest/process/2.Process.html#how-the-development-process-works)。

一个常见的误解，尤其是在它的初期，是 Linux 内核是以一种非常临时的方式开发的。这一点完全不正确！内核开发过程已经发展成为一个（大部分）良好运转的系统，有着详细的文件化流程和对内核贡献者应该了解的期望。我建议您查看前面的链接以获取完整的详细信息。

为了让我们一窥典型的开发周期，让我们假设我们在系统上克隆了最新的主线 Linux Git 内核树。

关于强大的`git(1)`**源代码管理**（**SCM**）工具的使用细节超出了本书的范围。请参阅*进一步阅读*部分，了解如何使用 Git 的有用链接。显然，我强烈建议至少基本了解如何使用`git(1)`。

如前所述，截至撰写本文时，**5.4 内核**是最新的**长期稳定**（**LTS**）版本，因此我们将在接下来的材料中使用它。那么，它是如何产生的呢？显然，它是从**发布候选**（**rc**）内核和之前的稳定内核发布演变而来的，在这种情况下，是*v5.4-rc'n'*内核和之前的稳定*v5.3*。我们使用以下`git log`命令按日期顺序获取内核 Git 树中标签的可读日志。在这里，我们只对导致 5.4 LTS 内核发布的工作感兴趣，因此我们故意截断了以下输出，只显示了那部分内容：

`git log`命令（我们在下面的代码块中使用，实际上任何其他`git`子命令）只能在`git`树上工作。我们纯粹使用以下内容来演示内核的演变。稍后，我们将展示如何克隆 Git 树。

```
$ git log --date-order --graph --tags --simplify-by-decoration --pretty=format:'%ai %h %d'
* 2019-11-24 16:32:01 -0800 219d54332a09  (tag: v5.4)
* 2019-11-17 14:47:30 -0800 af42d3466bdc  (tag: v5.4-rc8)
* 2019-11-10 16:17:15 -0800 31f4f5b495a6  (tag: v5.4-rc7)
* 2019-11-03 14:07:26 -0800 a99d8080aaf3  (tag: v5.4-rc6)
* 2019-10-27 13:19:19 -0400 d6d5df1db6e9  (tag: v5.4-rc5)
* 2019-10-20 15:56:22 -0400 7d194c2100ad  (tag: v5.4-rc4)
* 2019-10-13 16:37:36 -0700 4f5cafb5cb84  (tag: v5.4-rc3)
* 2019-10-06 14:27:30 -0700 da0c9ea146cb  (tag: v5.4-rc2)
* 2019-09-30 10:35:40 -0700 54ecb8f7028c  (tag: v5.4-rc1)
* 2019-09-15 14:19:32 -0700 4d856f72c10e  (tag: v5.3)
* 2019-09-08 13:33:15 -0700 f74c2bb98776  (tag: v5.3-rc8)
* 2019-09-02 09:57:40 -0700 089cf7f6ecb2  (tag: v5.3-rc7)
* 2019-08-25 12:01:23 -0700 a55aa89aab90  (tag: v5.3-rc6)
[...]
```

啊哈！在前面的代码块中，您可以清楚地看到稳定的 5.4 内核于 2019 年 11 月 24 日发布，5.3 树于 2019 年 9 月 15 日发布（您也可以通过查找其他有用的内核资源来验证，例如[`kernelnewbies.org/LinuxVersions`](https://kernelnewbies.org/LinuxVersions)）。

对于最终导致 5.4 内核的开发系列，后一个日期（2019 年 9 月 15 日）标志着所谓的**合并窗口**的开始，为期（大约）两周的下一个稳定内核。在此期间，开发人员被允许向内核树提交新代码（实际上，实际工作早在很早之前就已经进行了；这项工作的成果现在已经在此时合并到主线）。

两周后（2019 年 9 月 30 日），合并窗口关闭，`rc`内核工作开始，`5.4-rc1`是`rc`版本的第一个版本，当然。`-rc`（也称为预补丁）树主要用于合并补丁和修复（回归）错误，最终导致由主要维护者（Linus Torvalds 和 Andrew Morton）确定为“稳定”的内核树。预补丁（`-rc`发布）的数量有所不同。通常，这个“错误修复”窗口需要 6 到 10 周的时间，之后新的稳定内核才会发布。在前面的代码块中，我们可以看到八个发布候选内核最终导致了 2019 年 11 月 24 日发布了 v5.4 树（共计 70 天）。

可以通过[`github.com/torvalds/linux/releases`](https://github.com/torvalds/linux/releases)页面更直观地看到：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/97f30cbb-0926-4115-850d-bc9c6a87679f.png)

图 2.1 - 导致 5.4 LTS 内核的发布（自下而上阅读）

前面的截图是部分截图，显示了各种*v5.4-rc'n'*发布候选内核最终导致了 LTS 5.4 树的发布（2019 年 11 月 25 日，*v5.4-rc8*是最后一个`rc`发布）。工作从未真正停止：到 2019 年 12 月初，*v5.5-rc1*发布候选版本已经发布。

通常情况下，以 5.x 内核系列为例（对于任何其他最近的`major`内核系列也是如此），内核开发工作流程如下：

1.  5.x 稳定版本已经发布。因此，5.x+1（主线）内核的合并窗口已经开始。

1.  合并窗口保持开放约 2 周，新的补丁被合并到主线。

1.  一旦（通常）过去了 2 周，合并窗口就会关闭。

1.  `rc`（也称为主线，预补丁）内核开始。*5.x+1-rc1, 5.x+1-rc2, ..., 5.x+1-rcn*被发布。这个过程需要 6 到 8 周的时间。

1.  稳定版本已经发布：新的*5.x+1*稳定内核已经发布。

1.  发布被移交给“稳定团队”：

+   重大的错误或安全修复导致了*5.x+1.y*的发布：

*5.x+1.1, 5**.x+1.2, ... , 5.x+1.n*。

+   维护直到下一个稳定发布或**生命周期结束**（EOL）日期到达

...整个过程重复。

因此，当您看到 Linux 内核发布时，名称和涉及的过程将变得合乎情理。现在让我们继续看看不同类型的内核源树。

## 内核源树的类型

有几种类型的 Linux 内核源树。关键的是**长期支持**（LTS）内核。好吧，LTS 发布内核到底是什么？它只是一个“特殊”的发布，内核维护者将继续在其上进行重要的错误和安全修复的后移（嗯，安全问题通常只是错误），直到给定的 EOL 日期。

LTS 内核的“寿命”通常至少为 2 年，它可以延长多年（有时会延长）。我们将在本书中使用的**5.4 LTS 内核**是第 20 个 LTS 内核，其**寿命超过 6 年-从 2019 年 11 月到 2025 年 12 月**。

存储库中有几种类型的发布内核。然而，在这里，我们提到一个不完整的列表，按稳定性从低到高排序（因此，它们的生命周期从最短到最长）：

+   **-next 树**：这确实是最前沿的，子系统树中收集了新的补丁进行测试和审查。这是上游内核贡献者将要处理的内容。

+   **预补丁，也称为-rc 或主线**：这些是在发布之前生成的候选版本内核。

+   **稳定内核**：顾名思义，这是业务端。这些内核通常会被发行版和其他项目采用（至少起初是这样）。它们也被称为原始内核。

+   **发行版和 LTS 内核**：发行版内核（显然）是发行版提供的内核。它们通常以基本的原始/稳定内核开始。LTS 内核是专门维护更长时间的内核，使它们特别适用于行业/生产项目和产品。

在本书中，我们将一直使用撰写时的最新 LTS 内核，即 5.4 LTS 内核。正如我在第一章中提到的，*内核工作区设置*，5.4 LTS 内核最初计划的 EOL 是“至少 2021 年 12 月”。最近（2020 年 6 月），它现在被推迟到**2025 年 12 月**，使本书的内容在未来几年仍然有效！

+   **超长期支持（SLTS）内核**：更长时间维护的 LTS 内核（由*民用基础设施平台*（[`www.cip-project.org/`](https://www.cip-project.org/)）提供支持，这是一个 Linux 基金会项目）。

这是相当直观的。尽管如此，我建议您访问 kernel.org 的 Releases 页面获取有关发布内核类型的详细信息：[`www.kernel.org/releases.html`](https://www.kernel.org/releases.html)。同样，要获取更多详细信息，请访问*开发过程如何工作*（[`www.kernel.org/doc/html/latest/process/2.Process.html#how-the-development-process-works`](https://www.kernel.org/doc/html/latest/process/2.Process.html#how-the-development-process-works)）。

有趣的是，某些 LTS 内核是非常长期的发布，称为**SLTS**或**超长期支持**内核。例如，4.4 Linux 内核（第 16 个 LTS 发布）被认为是一个 SLTS 内核。作为 SLTS 选择的第一个内核，民用基础设施平台将提供支持至少到 2026 年，可能一直到 2036 年。

以非交互式可脚本化的方式查询存储库`www.kernel.org`可以使用`curl(1)`（以下输出是截至 2021 年 1 月 5 日的 Linux 状态）：

```
$ curl -L https://www.kernel.org/finger_banner The latest stable version of the Linux kernel is: 5.10.4
The latest mainline version of the Linux kernel is: 5.11-rc2
The latest stable 5.10 version of the Linux kernel is: 5.10.4
The latest stable 5.9 version of the Linux kernel is: 5.9.16 (EOL)
The latest longterm 5.4 version of the Linux kernel is: 5.4.86
The latest longterm 4.19 version of the Linux kernel is: 4.19.164
The latest longterm 4.14 version of the Linux kernel is: 4.14.213
The latest longterm 4.9 version of the Linux kernel is: 4.9.249
The latest longterm 4.4 version of the Linux kernel is: 4.4.249
The latest linux-next version of the Linux kernel is: next-20210105
$ 
```

当然，当您阅读本书时，内核极有可能（事实上是肯定的）已经进化，并且稍后的版本会出现。对于这样一本书，我能做的就是选择撰写时的最新 LTS 内核。

当然，这已经发生了！5.10 内核于 2020 年 12 月 13 日发布，截至撰写时（即将印刷之前），5.11 内核的工作正在进行中……

最后，另一种安全下载给定内核的方法是由内核维护者提供的，他们提供了一个脚本来安全地下载给定的 Linux 内核源树，并验证其 PGP 签名。该脚本在这里可用：[`git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/tree/get-verified-tarball`](https://git.kernel.org/pub/scm/linux/kernel/git/mricon/korg-helpers.git/tree/get-verified-tarball)。

好了，现在我们已经掌握了内核版本命名规则和内核源树类型的知识，是时候开始我们构建内核的旅程了。

# 从源码构建内核的步骤

作为一个方便和快速的参考，以下是构建 Linux 内核源码所需的关键步骤。由于每个步骤的解释都非常详细，您可以参考这个摘要来了解整体情况。步骤如下：

1.  通过以下选项之一获取 Linux 内核源树：

+   下载特定内核源作为压缩文件

+   克隆（内核）Git 树

1.  将内核源树提取到家目录中的某个位置（如果您通过克隆 Git 树获得内核，则跳过此步骤）。

1.  配置：根据新内核的需要选择内核支持选项，

`make [x|g|menu]config`，其中`make menuconfig`是首选方式。

1.  使用`make [-j'n'] all`构建内核的可加载模块和任何**设备树块**（**DTB**）。这将构建压缩的内核映像（`arch/<arch>/boot/[b|z|u]image`）、未压缩的内核映像（`vmlinux`）、`System.map`、内核模块对象和任何已配置的 DTB(s)文件。

1.  使用`sudo make modules_install`安装刚构建的内核模块。

此步骤默认将内核模块安装在`/lib/modules/$(uname -r)/`下。

1.  设置 GRUB 引导加载程序和`initramfs`（之前称为`initrd`）映像（特定于 x86）：

`sudo make install`：

+   这将在`/boot`下创建并安装`initramfs`（或`initrd`）映像。

+   它更新引导加载程序配置文件以启动新内核（第一个条目）。

1.  自定义 GRUB 引导加载程序菜单（可选）。

本章是关于这个主题的两章中的第一章，基本上涵盖了*步骤 1 到 3*，还包括了许多必需的背景材料。下一章将涵盖剩下的步骤，*4 到 7*。所以，让我们从*第 1 步*开始。

# 第 1 步——获取 Linux 内核源树

在这一部分，我们将看到两种获取 Linux 内核源树的广泛方法：

+   通过从 Linux 内核公共存储库（[`www.kernel.org`](https://www.kernel.org)）下载和提取特定的内核源树

+   通过克隆 Linus Torvalds 的源树（或其他人的）——例如，`linux-next` Git 树

但是你如何决定使用哪种方法？对于像您这样在项目或产品上工作的大多数开发人员来说，决定已经做出了——项目使用一个非常特定的 Linux 内核版本。因此，您将下载该特定的内核源树，如果需要，可能会对其应用特定于项目的补丁，并使用它。

对于那些打算向主线内核贡献或"上游"代码的人来说，第二种方法——克隆 Git 树——是您应该选择的方式。（当然，这还有更多内容；我们在*内核源树类型*部分中描述了一些细节）。

在接下来的部分中，我们将演示这两种方法。首先，我们描述了一种从内核存储库下载特定内核源树（而不是 Git 树）的方法。我们选择了截至撰写时的**最新 LTS 5.4 Linux 内核**来进行演示。在第二种方法中，我们克隆了一个 Git 树。

## 下载特定的内核树

首先，内核源代码在哪里？简短的答案是它在[`www.kernel.org`](https://www.kernel.org)上可见的公共内核存储库服务器上。该站点的主页显示了最新的稳定 Linux 内核版本，以及最新的`longterm`和`linux-next`发布（下面的截图显示了 2019 年 11 月 29 日的站点。它显示了以众所周知的`yyyy-mm-dd`格式的日期）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/7e90a555-0632-4d57-8d2a-a0184ec36212.png)

图 2.2 - kernel.org 网站（截至 2019 年 11 月 29 日）

快速提醒：我们还提供了一个 PDF 文件，其中包含本书中使用的截图/图表的全彩图像。您可以在这里下载：`static.packt-cdn.com/downloads/9781789953435_ColorImages.pdf`。

有许多种方法可以下载（压缩的）内核源文件。让我们看看其中的两种：

+   一个交互式，也许是最简单的方法，是访问上述网站，然后简单地点击适当的`tarball`链接。浏览器将会下载图像文件（以`.tar.xz`格式）到您的系统。

+   或者，您可以使用`wget(1)`实用程序（我们也可以使用强大的`curl(1)`实用程序来做到这一点）从命令行（shell 或 CLI）下载它。例如，要下载稳定的 5.4.0 内核源代码压缩文件，我们可以这样做：

```
wget --https-only -O ~/Downloads/linux-5.4.0.tar.xz https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.4.0.tar.xz
```

如果前面的`wget(1)`实用程序不起作用，很可能是因为内核（压缩的）`tarball`链接发生了变化。例如，如果对于`5.4.0.tar.xz`不起作用，尝试相同的`wget`实用程序，但将版本更改为`5.4.1.tar.xz`。

这将安全地下载 5.4.0 压缩的内核源树到您计算机的`~/Downloads`文件夹中。当然，您可能不希望在存储库的主页上显示的内核版本。例如，如果对于我的特定项目，我需要最新的 4.19 稳定（LTS）内核，第 19 个 LTS 版本，怎么办？简单：通过浏览器，只需点击[`www.kernel.org/pub/`](https://www.kernel.org/pub/)（或镜像[`mirrors.edge.kernel.org/pub/`](https://mirrors.edge.kernel.org/pub/)）链接（在前几行显示的“HTTP”链接右侧）并导航到服务器上的`linux/kernel/v4.x/`目录（您可能会被引导到一个镜像站点）。或者，只需将`wget(1)`指向 URL（在撰写时，这里碰巧是[`mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.19.164.tar.xz`](https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.19.164.tar.xz)）。

## 克隆 Git 树

对于像您这样的开发人员，正在研究并寻求向上游贡献代码，您*必须*在 Linux 内核代码库的最新版本上工作。嗯，内核社区内有最新版本的微妙变化。如前所述，`linux-next`树以及其中的某个特定分支或标签，是为此目的而工作的树。

在这本书中，我们并不打算深入探讨建立`linux-next`树的血腥细节。这个过程已经有非常好的文档记录，我们更愿意不仅仅重复指令（详细链接请参见*进一步阅读*部分）。关于如何克隆`linux-next`树的详细页面在这里：*使用 linux-next*，[`www.kernel.org/doc/man-pages/linux-next.html`](https://www.kernel.org/doc/man-pages/linux-next.html)，正如在那里提到的，*linux-next*树*，[`git.kernel.org/cgit/linux/kernel/git/next/linux-next.git`](http://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git)，是用于下一个内核合并窗口的补丁的存储区。如果你正在进行最前沿的内核开发，你可能希望从那个树上工作，而不是 Linus Torvalds 的主线树。

对于我们的目的，克隆*mainline*Linux Git 存储库（Torvalds 的 Git 树）已经足够了。像这样做（在一行上输入）：

```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
```

请注意，克隆完整的 Linux 内核树是一个耗时、耗网络和耗磁盘的操作！确保您有足够的磁盘空间可用（至少几个 GB）。

执行`git clone --depth n <...>`，其中`n`是一个整数值，非常有用，可以限制历史记录（提交）的深度，从而降低下载/磁盘使用量。正如`git-clone(1)`的`man`页面中提到的`--depth`选项：“创建一个浅克隆，其历史记录被截断为指定数量的提交。”

根据前面的提示，为什么不执行以下操作（再次在一行上输入）？

```
git clone --depth=3 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
```

如果您打算在这个主线 Git 树上工作，请跳过*步骤*2 - *提取内核源树*部分（因为`git clone`操作将在任何情况下提取源树），并继续进行下一部分（*步骤 3 - 配置 Linux 内核*）。

# 步骤 2 - 提取内核源树

如前所述，本节适用于那些从存储库[`www.kernel.org`](https://www.kernel.org)下载了特定的 Linux 内核并打算构建它的人。在本书中，我们使用 5.4 LTS 内核版本。另一方面，如果您已经在主线 Linux Git 树上执行了`git clone`，就像在前面的部分中所示的那样，您可以安全地跳过本节，继续进行下一节内核配置。

现在下载已经完成，让我们继续。下一步是提取内核源树 - 记住，它是一个经过 tar 和压缩的（通常是`.tar.xz`）文件。

我们假设，如本章前面详细介绍的那样，您现在已经将 Linux 内核版本 5.4 代码库下载为一个压缩文件（放入`~/Downloads`目录）：

```
$ cd ~/Downloads ; ls -lh linux-5.4.tar.xz
-rw-rw-r-- 1 llkd llkd 105M Nov 26 08:04 linux-5.4.tar.xz
```

提取这个文件的简单方法是使用无处不在的`tar(1)`实用程序来完成：

```
tar xf ~/Downloads/linux-5.4.tar.xz
```

这将把内核源树提取到`~/Downloads`目录中名为`linux-5.4`的目录中。但是，如果我们想要将其提取到另一个文件夹，比如`~/kernels`中，那么可以这样做：

```
mkdir -p ~/kernels
tar xf ~/Downloads/linux-5.4.tar.xz --directory=${HOME}/kernels/
```

这将把内核源提取到`~/kernels/linux-5.4/`文件夹中。为了方便起见，也是一个良好的做法，让我们设置一个*环境变量*，指向我们内核源树根目录的位置：

```
export LLKD_KSRC=${HOME}/kernels/linux-5.4
```

请注意，从现在开始，我们将假设这个变量保存着内核源树的位置。

虽然您可以随时使用 GUI 文件管理器应用程序（如`Nautilus(1)`）来提取压缩文件，但我强烈建议您熟悉使用 Linux CLI 来执行这些操作。

当您需要快速查找常用命令的最常用选项时，不要忘记`tldr(1)`！例如，对于`tar(1)`，只需使用`tldr tar`来查找。

您注意到了吗？我们将内核源树提取到*任何*家目录下的任何目录中（甚至其他地方），不像以前那样总是提取到可写的根目录位置（通常是`/usr/src/`）。现在，只要说不（对于那个）。

如果您现在只想继续进行内核构建操作，请跳过以下部分并继续。如果感兴趣（我们当然希望如此！），下一节是一个简短但重要的偏离，看一下内核源树的结构和布局。

## **内核源树的简要介绍**

内核源代码现在可以在您的系统上使用了！很酷，让我们快速看一下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/7495234c-06e5-47b3-93c8-e8a1e08e0a20.png)

图 2.3 - 5.4 Linux 内核源树的根目录

太好了！它有多大？在内核源树的根目录中快速执行`du -m .`，可以看到这个特定的内核源树（记住，它是版本 5.4）的大小略大于 1,000 MB - 几乎是 1 GB！

值得一提的是，Linux 内核在**代码行数（SLOCs）**方面已经变得很大，并且正在变得越来越大。目前的估计是超过 2000 万行代码。当然，要意识到在构建内核时，并不是所有的代码都会被编译。

我们如何知道这段代码是哪个版本的 Linux 内核呢？很简单，一个快速的方法就是查看项目的 Makefile 的前几行。顺便说一句，内核在很多地方都使用 Makefile；大多数目录都有一个。我们将把这个 Makefile，也就是内核源代码树根目录下的 Makefile，称为*顶层 Makefile*：

```
$ head Makefile
# SPDX-License-Identifier: GPL-2.0
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 0
EXTRAVERSION =
NAME = Kleptomaniac Octopus

# *DOCUMENTATION*
# To see a list of typical targets execute "make help"
# More info can be located in ./README
$
```

显然，这是 5.4.0 内核的源代码。

让我们来看看内核源代码树的整体情况。以下表格总结了 Linux 内核源代码树根目录中（更）重要的文件和目录的广泛分类和目的：

| **文件或目录名称** | **目的** |
| --- | --- |
| **顶层文件** |  |
| `README` | 项目的 `README` 文件。它告诉我们内核文档存放在哪里 - 提示，它在名为 `Documentation` 的目录中 - 以及如何开始使用它。文档非常重要；它是由内核开发人员自己编写的真实内容。 |
| `COPYING` | 内核源代码发布的许可条款。绝大多数都是根据著名的 GNU GPL v2（写作 GPL-2.0）许可证发布的 [1]。 |
| `MAINTAINERS` | *常见问题：* *XYZ 出了问题，我应该联系谁获取支持？* 这正是这个文件提供的 - 所有内核子系统的列表，甚至到个别组件（如特定驱动程序）的级别，它的状态，当前维护者，邮件列表，网站等等。非常有帮助！甚至有一个辅助脚本可以找到需要联系的人或团队：`scripts/get_maintainer.pl` [2]。 |
| Makefile | 这是内核的顶层 Makefile；`kbuild` 内核构建系统以及内核模块最初使用这个 Makefile 进行构建。 |
| **主要子系统目录** |  |
| `kernel/` | 核心内核子系统：这里的代码涉及进程/线程生命周期，CPU 调度，锁定，cgroups，定时器，中断，信号，模块，跟踪等等。 |
| `mm/` | 大部分**内存管理**（**mm**）代码都在这里。我们将在第六章中涵盖一些内容，即*内核内部要点 - 进程和线程*，以及在第七章中涵盖一些相关内容，即*内存管理内部要点*，以及在第八章中涵盖一些内容，即*模块作者的内核内存分配 - 第一部分*。 |
| `fs/` | 这里的代码实现了两个关键的文件系统功能：抽象层 - 内核**虚拟文件系统开关**（**VFS**），以及各个文件系统驱动程序（例如 `ext[2 | 4]`，`btrfs`，`nfs`，`ntfs`，`overlayfs`，`squashfs`，`jffs2`，`fat`，`f2fs` 等）。 |
| `block/` | 底层（对于 VFS/FS）块 I/O 代码路径。它包括实现页面缓存、通用块 I/O 层、I/O 调度器等代码。 |
| `net/` | 完整（按照**请求评论**（**RFC**）的要求 - [`whatis.techtarget.com/definition/Request-for-Comments-RFC`](https://whatis.techtarget.com/definition/Request-for-Comments-RFC)）实现了网络协议栈。包括高质量的 TCP、UDP、IP 等许多网络协议的实现。 |
| `ipc/` | **进程间通信**（**IPC**）子系统代码；涵盖 IPC 机制，如（SysV 和 POSIX）消息队列，共享内存，信号量等。 |
| `sound/` | 音频子系统代码，也称为**高级 Linux 音频架构**（**ALSA**）。 |
| `virt/` | *虚拟化*（hypervisor）代码；流行且强大的**内核虚拟机**（**KVM**）就是在这里实现的。 |
| **基础设施/其他** |  |
| `arch/` | 这里存放着特定架构的代码（在这里，架构指的是 CPU）。Linux 最初是为 i386 架构的一个小型爱好项目。现在可能是最多移植的操作系统（请参见表后面的 *步骤 3* 中的架构移植）。 |
| `crypto/` | 此目录包含密码（加密/解密算法，也称为转换）的内核级实现和内核 API，以为需要加密服务的消费者提供服务。 |
| `include/` | 此目录包含与架构无关的内核头文件（还有一些特定架构的头文件在 `arch/<cpu>/include/...` 下）。 |
| `init/` | 与架构无关的内核初始化代码；也许我们能接近内核的主要功能（记住，内核不是一个应用程序）就在这里：`init/main.c:start_kernel()`，其中的 `start_kernel()` 函数被认为是内核初始化期间的早期 C 入口点。 |
| `lib/` | 这是内核最接近库的等价物。重要的是要理解，内核不支持像用户空间应用程序那样的共享库。这里的代码会自动链接到内核映像文件中，因此在运行时对内核可用（`/lib` 中存在各种有用的组件：[解]压缩、校验和、位图、数学、字符串例程、树算法等）。 |
| `scripts/` | 这里存放着各种脚本，其中一些用于内核构建，许多用于其他目的（如静态/动态分析等），主要是 Bash 和 Perl。 |
| `security/` | 包含内核的 **Linux 安全模块**（**LSM**），这是一个旨在对用户应用程序对内核空间的访问控制施加更严格限制的 **强制访问控制**（**MAC**）框架，比默认内核模型（称为 **自由访问控制**（**DAC**））更严格。目前，Linux 支持几种 LSM；其中一些知名的是 SELinux、AppArmor、Smack、Tomoyo、Integrity 和 Yama（请注意，LSM 默认情况下是“关闭”的）。 |
| `tools/` | 这里存放着各种工具，主要是与内核有“紧密耦合”的用户空间应用程序（或脚本），如现代性能分析工具 *perf* 就是一个很好的例子。 |

表 2.2 – Linux 内核源代码树的布局

表中以下是一些重要的解释：

1.  **内核许可证**：不要陷入法律细节，这里是事物的实质：由于内核是根据 GNU GPL-2.0 许可证发布的（**GNU GPL** 是 **GNU 通用公共许可证**），任何直接使用内核代码库的项目（即使只有一点点！）都自动属于这个许可证（GPL-2.0 的“衍生作品”属性）。这些项目或产品必须按照相同的许可条款发布其内核。实际上，实际情况要复杂得多；许多在 Linux 内核上运行的商业产品确实包含专有的用户空间和/或内核空间代码。它们通常通过重构内核（通常是设备驱动程序）工作为 **可加载内核模块**（**LKM**）格式来实现。可以以 *双重许可* 模式发布内核模块（LKM）（例如，双重 BSD/GPL；LKM 是 第四章 和 第五章 的主题，我们在那里涵盖了一些关于内核模块许可的信息）。一些人更喜欢专有许可证，他们设法发布其内核代码，而不受 GPL-2.0 条款的约束；从技术上讲，这可能是可能的，但（至少）被认为是反社会的（甚至可能违法）。感兴趣的人可以在本章的 *进一步阅读* 文档中找到更多关于许可证的链接。

1.  `MAINTAINERS`：运行`get_maintainer.pl` Perl 脚本的示例（注意：它只能在 Git 树上运行）：

```
$ scripts/get_maintainer.pl -f drivers/android/ Greg Kroah-Hartman <gregkh@linuxfoundation.org> (supporter:ANDROID DRIVERS)
"Arve Hjønnevåg" <arve@android.com> (supporter:ANDROID DRIVERS)
Todd Kjos <tkjos@android.com> (supporter:ANDROID DRIVERS)
Martijn Coenen <maco@android.com> (supporter:ANDROID DRIVERS)
Joel Fernandes <joel@joelfernandes.org> (supporter:ANDROID DRIVERS)
Christian Brauner <christian@brauner.io> (supporter:ANDROID DRIVERS)
devel@driverdev.osuosl.org (open list:ANDROID DRIVERS)
linux-kernel@vger.kernel.org (open list)
$ 
```

1.  Linux `arch`（CPU）端口：

```
$ cd ${LLKD_KSRC} ; ls arch/
alpha/ arm64/ h8300/   Kconfig     mips/  openrisc/ riscv/ sparc/ x86/
arc/   c6x/   hexagon/ m68k/       nds32/ parisc/   s390/  um/    xtensa/
arm/   csky/  ia64/    microblaze/ nios2/ powerpc/  sh/    unicore32/
```

作为内核或驱动程序开发人员，浏览内核源代码树是你必须要习惯（甚至喜欢！）的事情。当代码量接近 2000 万 SLOC 时，搜索特定函数或变量可能是一项艰巨的任务！要使用高效的代码浏览工具。我建议使用`ctags(1)`和`cscope(1)`这些**自由开源软件**（**FOSS**）工具。事实上，内核的顶层`Makefile`有针对这些工具的目标：

`make tags ; make cscope`

我们现在已经完成了*步骤 2*，提取内核源代码树！作为奖励，您还学会了有关内核源代码布局的基础知识。现在让我们继续进行*步骤 3*的过程，并学习如何在构建之前*配置*Linux 内核。

# 第 3 步-配置 Linux 内核

配置新内核可能是内核构建过程中*最*关键的一步。Linux 备受好评的原因之一是其多功能性。普遍的误解是认为（企业级）服务器、数据中心、工作站和微型嵌入式 Linux 设备有各自独立的 Linux 内核代码库-不，*它们都使用同一个统一的 Linux 内核源代码！*因此，仔细*配置*内核以满足特定用例（服务器、桌面、嵌入式或混合/自定义）是一个强大的功能和要求。这正是我们在这里深入研究的内容。

无论如何都要执行内核配置步骤。即使您觉得不需要对现有（或默认）配置进行任何更改，至少在构建过程的一部分中运行此步骤非常重要。否则，这里自动生成的某些标头将丢失并引起问题。至少应执行`make oldconfig`。这将将内核配置设置为现有系统的配置，用户仅对任何新选项进行请求。

首先，让我们了解一下**内核构建**（**kbuild**）系统的一些必要背景。

## 了解 kbuild 构建系统

Linux 内核用于配置和构建内核的基础设施被称为**kbuild**系统。不深入了解复杂的细节，kbuild 系统通过四个关键组件将复杂的内核配置和构建过程联系在一起：

+   `CONFIG_FOO`符号

+   菜单规范文件，称为`Kconfig`

+   Makefile(s)

+   总体内核配置文件

这些组件的目的总结如下：

| **Kbuild 组件** | **简要目的** |
| --- | --- |
| 配置符号：`CONFIG_FOO` | 每个内核可配置的`FOO`都由`CONFIG_FOO`宏表示。根据用户的选择，该宏将解析为`y`、`m`或`n`中的一个：- `y=yes`：表示将该功能构建到内核映像本身中- `m=module`：表示将其构建为一个独立对象，即内核模块- `n=no`：表示不构建该功能请注意，`CONFIG_FOO`是一个字母数字字符串（很快我们将看到，您可以使用`make menuconfig`选项查找精确的配置选项名称，导航到配置选项，并选择`<帮助>`按钮）。 |
| `Kconfig`文件 | 这是`CONFIG_FOO`符号定义的地方。kbuild 语法指定了它的类型（布尔值、三态值、[alpha]数字等）和依赖树。此外，对于基于菜单的配置 UI（通过`make [menu&#124;g&#124;x]config`之一调用），它指定了菜单条目本身。当然，我们稍后将使用此功能。 |
| Makefile(s) | kbuild 系统使用*递归*Makefile 方法。内核源代码树根文件夹下的 Makefile 称为*顶层*Makefile，在每个子文件夹中都有一个 Makefile 来构建那里的源代码。5.4 原始内核源代码中总共有 2500 多个 Makefile！ |
| `.config`文件 | 最终，它的本质-实际的内核配置-以 ASCII 文本文件的形式生成并存储在内核源树根目录中的`.config`文件中。请保管好这个文件，它是产品的关键部分。 |

表 2.3 - Kbuild 构建系统的主要组件

关键是获得一个可用的`.config`文件。我们如何做到这一点？我们进行迭代。我们从“默认”配置开始-下一节的主题-并根据需要仔细地进行自定义配置。

## 到达默认配置

那么，您如何决定初始内核配置从哪里开始？存在几种技术；一些常见的技术如下：

+   不指定任何内容；kbuild 系统将引入默认内核配置。

+   使用现有发行版的内核配置。

+   基于当前加载在内存中的内核模块构建自定义配置。

第一种方法的好处是简单性。内核将处理细节，为您提供默认配置。缺点是默认配置实际上相当大（在这里，我们指的是构建面向 x86 桌面或服务器类型系统的 Linux）-大量选项被打开，以防万一，这可能会使构建时间非常长，内核映像大小非常大。当然，您随后需要手动配置内核以获得所需的设置。

这带来了一个问题，*默认内核配置存储在哪里*？kbuild 系统使用优先级列表回退方案来检索默认配置。优先级列表及其顺序（第一个优先级最高）在`init/Kconfig:DEFCONFIG_LIST`中指定：

```
$ cat init/Kconfig
config DEFCONFIG_LIST
    string
    depends on !UML 
    option defconfig_list
    default "/lib/modules/$(shell,uname -r)/.config"
    default "/etc/kernel-config"
    default "/boot/config-$(shell,uname -r)"
    default ARCH_DEFCONFIG
    default "arch/$(ARCH)/defconfig"
config CC_IS_GCC
[...]
```

顺便说一句，关于`Kconfig`的内核文档（在此处找到：[`www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt`](https://www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt)）记录了`defconfig_list`是什么：

```
"defconfig_list"
    This declares a list of default entries which can be used when
    looking for the default configuration (which is used when the main
    .config doesn't exists yet.)
```

从列表中可以看出，kbuild 系统首先检查`/lib/modules/$(uname -r)`文件夹中是否存在`.config`文件。如果找到，其中的值将被用作默认值。如果未找到，则接下来检查`/etc/kernel-config`文件是否存在。如果找到，其中的值将被用作默认值，如果未找到，则继续检查前面优先级列表中的下一个选项，依此类推。但请注意，内核源树根目录中存在`.config`文件将覆盖所有这些！

## 获取内核配置的良好起点

这带我们来到一个**非常重要的观点**：玩弄内核配置作为学习练习是可以的（就像我们在这里做的那样），但对于生产系统，使用已知、经过测试和工作的内核配置真的非常重要。

在这里，为了帮助您理解选择内核配置的有效起点的微妙之处，我们将看到三种获得内核配置起点的方法（我们希望）是典型的：

+   首先，对于典型的小型嵌入式 Linux 系统要遵循的方法

+   接下来，一种模拟发行版配置的方法

+   最后，一种基于现有（或其他）系统的内核模块的内核配置的方法（`localmodconfig`方法）

让我们更详细地检查每种方法。

### 典型嵌入式 Linux 系统的内核配置

使用此方法的典型目标系统是小型嵌入式 Linux 系统。这里的目标是从已知、经过测试和工作的内核配置开始我们的嵌入式 Linux 项目。那么，我们究竟如何做到这一点呢？

有趣的是，内核代码库本身为各种硬件平台提供了已知、经过测试和工作的内核配置文件。我们只需选择与我们的嵌入式目标板匹配（或最接近匹配）的配置文件。这些内核配置文件位于内核源树中的`arch/<arch>/configs/`目录中。配置文件的格式为`<platform-name>_defconfig`。让我们快速看一下；看一下以下屏幕截图，显示了在 v5.4 Linux 内核代码库上执行`ls arch/arm/configs`命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/06950efa-a78e-4194-a747-2414cddfe329.png)

图 2.4 - 5.4 Linux 内核中 arch/arm/configs 的内容

因此，例如，如果您发现自己为具有三星 Exynos **片上系统**（**SoC**）的硬件平台配置 Linux 内核，请不要从默认的 x86-64 内核配置文件开始（或者尝试使用它）。这样不会起作用。即使您成功了，内核也不会干净地构建/工作。选择适当的内核配置文件：对于我们的示例，`arch/arm/configs/exynos_defconfig`文件将是一个很好的起点。您可以将此文件复制到内核源树的根目录中的`.config`，然后继续对其进行微调以满足项目特定需求。

举个例子，树莓派（[`www.raspberrypi.org/`](https://www.raspberrypi.org/)）是一种流行的业余爱好者平台。内核配置文件 - 在其内核源树中 - 使用（作为基础）的是这个：`arch/arm/configs/bcm2835_defconfig`。文件名反映了树莓派板使用的是基于 Broadcom 2835 的 SoC。您可以在这里找到有关树莓派内核编译的详细信息：[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)。不过，我们将在第三章中至少涵盖其中的一些内容，*从源代码构建 5.x Linux 内核 - 第二部分*，在*树莓派的内核构建*部分。

查看哪个平台的配置文件适合哪个平台的简单方法是在目标平台上执行`make help`。输出的后半部分显示了*特定架构目标*标题下的配置文件（请注意，这是针对外部 CPU 的，不适用于 x86[-64]）。

对产品进行内核配置的仔细调整和设置是*平台*或**板支持包**（**BSP**）团队工程师通常进行的重要工作的一部分。

### 使用发行版配置作为起点的内核配置

使用这种方法的典型目标系统是桌面或服务器 Linux 系统。

接下来，这第二种方法也很快：

```
cp /boot/config-5.0.0-36-generic ${LLKD_KSRC}/.config
```

在这里，我们只需将现有的 Linux 发行版（这里是我们的 Ubuntu 18.04.3 LTS 虚拟机）的配置文件复制到内核源树根目录中的`.config`文件中，从而使发行版配置成为起点，然后可以进一步编辑（更通用的命令：`cp /boot/config-$(uname -r) ${LLKD_KSRC}/.config`）。

### 通过 localmodconfig 方法调整内核配置

使用这种方法的典型目标系统是桌面或服务器 Linux 系统。

我们考虑的第三种方法是一个很好的方法，当目标是从基于现有系统的内核配置开始时，通常相对于桌面或服务器 Linux 系统的典型默认配置来说，它相对较小。在这里，我们通过简单地将`lsmod(8)`的输出重定向到临时文件，然后将该文件提供给构建，向 kbuild 系统提供了系统上当前运行的内核模块的快照。可以通过以下方式实现：

```
lsmod > /tmp/lsmod.now
cd ${LLKD_KSRC}
make LSMOD=/tmp/lsmod.now localmodconfig
```

`lsmod(8)`实用程序简单地列出当前驻留在系统（内核）内存中的所有内核模块。我们将在第四章中详细介绍这个（很多）。我们将其输出保存在一个临时文件中，并将其传递到 Makefile 的`localmodconfig`目标中的`LSMOD`环境变量中。此目标的工作是以一种只包括基本功能以及这些内核模块提供的功能的方式配置内核，并排除其余部分，从而实际上给我们提供了当前内核的合理外观（或`lsmod`输出所代表的任何内核）。我们将使用这种技术来配置我们的 5.4 内核，接下来是*使用 localmodconfig 方法开始*部分。

好了，这就结束了为内核配置设置起点的三种方法。事实上，我们只是触及了表面。许多更多的技术被编码到 kbuild 系统本身中，以明确地生成给定方式的内核配置！如何？通过`make`的配置目标。在`Configuration targets`标题下查看它们：

```
$ cd ${LKDC_KSRC}         *# root of the kernel source tree*
$ make help
Cleaning targets:
 clean             - Remove most generated files but keep the config and
 enough build support to build external modules
 mrproper          - Remove all generated files + config + various backup     
                     files
 distclean         - mrproper + remove editor backup and patch files

Configuration targets:
 config           - Update current config utilising a line-oriented  
                    program
 nconfig          - Update current config utilising a ncurses menu based 
                    program
 menuconfig       - Update current config utilising a menu based program
 xconfig          - Update current config utilising a Qt based front-end
 gconfig          - Update current config utilising a GTK+ based front-end
 oldconfig        - Update current config utilising a provided .config as 
                    base
 localmodconfig   - Update current config disabling modules not loaded
 localyesconfig   - Update current config converting local mods to core
 defconfig        - New config with default from ARCH supplied defconfig
 savedefconfig    - Save current config as ./defconfig (minimal config)
 allnoconfig      - New config where all options are answered with no
 allyesconfig     - New config where all options are accepted with yes
 allmodconfig     - New config selecting modules when possible
 alldefconfig     - New config with all symbols set to default
 randconfig       - New config with random answer to all options
 listnewconfig    - List new options
 olddefconfig     - Same as oldconfig but sets new symbols to their
                    default value without prompting
 kvmconfig        - Enable additional options for kvm guest kernel support
 xenconfig        - Enable additional options for xen dom0 and guest   
                    kernel support
 tinyconfig       - Configure the tiniest possible kernel
 testconfig       - Run Kconfig unit tests (requires python3 and pytest)

Other generic targets:
  all             - Build all targets marked with [*]
[...]
$
```

一个快速但非常有用的要点：为了确保一张干净的纸，首先使用`mrproper`目标。接下来我们将展示所有步骤的摘要，所以现在不要担心。

## 使用 localmodconfig 方法开始

现在，让我们快速开始使用我们之前讨论过的第三种方法 - `localmodconfig`技术为我们的新内核创建一个基本内核配置。如前所述，这种现有的仅内核模块方法是一个很好的方法，当目标是在基于 x86 的系统上获得内核配置的起点时，通过保持相对较小的内核配置，从而使构建速度更快。

不要忘记：当前正在执行的内核配置适用于您典型的基于 x86 的桌面/服务器系统。对于嵌入式目标，方法是不同的（如在*典型嵌入式 Linux 系统的内核配置*部分中所见）。我们将在第三章中进一步介绍这一点，*从源代码构建 5.x Linux 内核 - 第二部分*，在*树莓派的内核构建*部分。

如前所述，首先获取当前加载的内核模块的快照，然后通过指定`localmodconfig`目标让 kbuild 系统对其进行操作，如下所示：

```
lsmod > /tmp/lsmod.now
cd ${LLKD_KSRC} ; make LSMOD=/tmp/lsmod.now localmodconfig
```

现在，要理解的是：当我们执行实际的`make [...] localmodconfig`命令时，当前正在构建的内核（版本 5.4）与当前实际运行构建的内核（`$(uname -r) = 5.0.0-36-generic`）之间的配置选项可能会有差异，甚至很可能会有差异。在这些情况下，kbuild 系统将在控制台（终端）窗口上显示每个新的配置选项以及您可以设置的可用值。然后，它将提示用户选择正在构建的内核中遇到的任何新的配置选项的值。您将看到这是一系列问题，并提示在命令行上回答它们。

提示将以`(NEW)`为后缀，实际上告诉您这是一个*新*的内核配置选项，并希望您回答如何配置它。

在这里，至少，我们将采取简单的方法：只需按`[Enter]`键接受默认选择，如下所示：

```
$ uname -r5.0.0-36-generic $ make LSMOD=/tmp/lsmod.now localmodconfig 
using config: '/boot/config-5.0.0-36-generic'
vboxsf config not found!!
module vboxguest did not have configs CONFIG_VBOXGUEST
*
* Restart config...
*
*
* General setup
*
Compile also drivers which will not load (COMPILE_TEST) [N/y/?] n
Local version - append to kernel release (LOCALVERSION) [] 
Automatically append version information to the version string (LOCALVERSION_AUTO) [N/y/?] n
Build ID Salt (BUILD_SALT) [] (NEW) [Enter] Kernel compression mode
> 1\. Gzip (KERNEL_GZIP)
  2\. Bzip2 (KERNEL_BZIP2)
  3\. LZMA (KERNEL_LZMA)
  4\. XZ (KERNEL_XZ)
  5\. LZO (KERNEL_LZO)
  6\. LZ4 (KERNEL_LZ4)
choice[1-6?]: 1
Default hostname (DEFAULT_HOSTNAME) [(none)] (none)
Support for paging of anonymous memory (swap) (SWAP) [Y/n/?] y
System V IPC (SYSVIPC) [Y/n/?] y
[...]
Enable userfaultfd() system call (USERFAULTFD) [Y/n/?] y
Enable rseq() system call (RSEQ) [Y/n/?] (NEW)
[...]
  Test static keys (TEST_STATIC_KEYS) [N/m/?] n
  kmod stress tester (TEST_KMOD) [N/m/?] n
  Test memcat_p() helper function (TEST_MEMCAT_P) [N/m/y/?] (NEW)
#
# configuration written to .config
#
$ ls -la .config
-rw-r--r-- 1 llkd llkd  140764 Mar  7 17:31 .config
$ 
```

按下`[Enter]`键多次后，询问终于结束，kbuild 系统将新生成的配置写入当前工作目录中的`.config`文件中（我们截断了先前的输出，因为它太庞大，而且没有必要完全重现）。

前面两个步骤负责通过`localmodconfig`方法生成`.config`文件。在结束本节之前，这里有一些要注意的关键点：

+   为了确保完全干净的状态，在内核源代码树的根目录中运行`make mrproper`或`make distclean`（当您想从头开始重新启动时很有用；请放心，总有一天会发生！请注意，这将删除内核配置文件）。

+   在本章中，所有与内核配置步骤和相关截图都是在 Ubuntu 18.04.3 LTS x86-64 虚拟机上执行的，我们将其用作构建全新的 5.4 Linux 内核的主机。菜单项的名称、存在和内容，以及菜单系统（UI）的外观和感觉可能会根据（a）架构（CPU）和（b）内核版本而有所不同。

+   正如前面提到的，在生产系统或项目中，平台或**板支持包**（**BSP**）团队，或者如果您与嵌入式 Linux BSP 供应商合作，他们会提供一个已知的、可工作和经过测试的内核配置文件。请将其用作起点，将其复制到内核源代码树根目录中的`.config`文件中。

随着构建内核的经验增加，您会意识到第一次正确设置内核配置的工作量（至关重要！）更大；当然，第一次构建所需的时间也更长。不过，一旦正确完成，整个过程通常会变得简单得多 - 一个可以一遍又一遍运行的配方。

现在，让我们学习如何使用一个有用且直观的 UI 来调整我们的内核配置。

## 通过 make menuconfig UI 调整我们的内核配置

好的，很好，我们现在有一个通过`localmodconfig` Makefile 目标为我们生成的初始内核配置文件（`.config`），如前一节详细介绍的那样，这是一个很好的起点。现在，我们希望进一步检查和微调我们的内核配置。一种方法是通过`menuconfig` Makefile 目标 - 实际上，是推荐的方法。这个目标让 kbuild 系统生成一个相当复杂的（基于 C 的）程序可执行文件（`scripts/kconfig/mconf`），向最终用户呈现一个整洁的基于菜单的 UI。在下面的代码块中，当我们第一次调用该命令时，kbuild 系统会构建`mconf`可执行文件并调用它：

```
$ make menuconfig
 UPD scripts/kconfig/.mconf-cfg
 HOSTCC scripts/kconfig/mconf.o
 HOSTCC scripts/kconfig/lxdialog/checklist.o
 HOSTCC scripts/kconfig/lxdialog/inputbox.o
 HOSTCC scripts/kconfig/lxdialog/menubox.o
 HOSTCC scripts/kconfig/lxdialog/textbox.o
 HOSTCC scripts/kconfig/lxdialog/util.o
 HOSTCC scripts/kconfig/lxdialog/yesno.o
 HOSTLD scripts/kconfig/mconf
scripts/kconfig/mconf Kconfig
...
```

当然，一张图片无疑价值千言万语，这是`menuconfig`的 UI 外观：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/ddd39591-ff94-4c75-998d-f87fb3b1fa17.png)

图 2.5 - 通过 make menuconfig 进行内核配置的主菜单（在 x86-64 上）

作为经验丰富的开发人员，或者任何足够使用计算机的人都知道，事情可能会出错。例如，以下情景 - 在新安装的 Ubuntu 系统上第一次运行`make menuconfig`：

```
$ make menuconfig
 UPD     scripts/kconfig/.mconf-cfg
 HOSTCC  scripts/kconfig/mconf.o
 YACC    scripts/kconfig/zconf.tab.c
/bin/sh: 1: bison: not found
scripts/Makefile.lib:196: recipe for target 'scripts/kconfig/zconf.tab.c' failed
make[1]: *** [scripts/kconfig/zconf.tab.c] Error 127
Makefile:539: recipe for target 'menuconfig' failed
make: *** [menuconfig] Error 2
$
```

等一下，不要慌（还）。仔细阅读失败消息。`YACC [...]`后的一行提供了线索：`/bin/sh: 1: bison: not found`。啊，所以用以下命令安装`bison(1)`：

`sudo apt install bison`

现在，一切应该都好了。嗯，几乎；同样，在新安装的 Ubuntu 系统上，`make menuconfig`然后抱怨`flex(1)`未安装。所以，我们安装它（你猜对了：通过`sudo apt install flex`）。此外，在 Ubuntu 上，您需要安装`libncurses5-dev`包（在 Fedora 上，执行`sudo dnf install ncurses-devel`）。

如果您已经阅读并遵循了第一章，*内核* *工作空间设置*，那么您应该已经安装了所有这些先决条件包。如果没有，请立即参考并安装所有所需的包。记住，*种瓜得瓜，种豆得豆……*

继续前进，kbuild 开源框架（顺便说一句，它在许多项目中被重复使用）通过其 UI 向用户提供了一些线索。菜单条目前缀的含义如下：

+   `[.]`: 内核功能，布尔选项（要么开启，要么关闭）：

+   `[*]`: 开启，功能已编译并内置到内核镜像中（编译进内核）（y）

+   `[ ]`: 关闭，根本没有构建（n）

+   `<.>`：一个可以处于三种状态之一的特性（三态）：

+   `<*>`：打开，特性已编译并内建（编译进）内核镜像（y）

+   `<M>`：模块，作为内核模块编译和内建（m）

+   `< >`：关闭，完全不构建（n）

+   `{.}`：此配置选项存在依赖关系；因此，它需要被构建（编译）为模块（m）或内建到内核镜像中（y）。

+   `-*-`：一个依赖需要将此项目编译进（y）。

+   `（...）`：提示：需要输入字母数字（在此选项上按`[Enter]`键，然后会出现提示）。

+   `<菜单项>  --->`：后面有一个子菜单（在此项目上按`[Enter]`键导航到子菜单）。

再次，经验法则至关重要。让我们实际尝试使用`make menuconfig` UI 来看看它是如何工作的。这是下一节的主题。

### 使用 make menuconfig UI 的示例用法

通过方便的`menuconfig`目标来感受使用 kbuild 菜单系统的过程，让我们逐步进行导航到名为`内核.config 支持`的三态菜单项。它默认是关闭的，所以让我们打开它；也就是说，让我们把它设为`y`，内建到内核镜像中。我们可以在主屏幕上的`常规设置`主菜单项下找到它。

打开此功能到`y`会实现什么？当打开到`y`（或者当设置为`M`时，一个内核模块将可用，并且一旦加载，当前运行的内核配置设置可以通过两种方式随时查找：

+   通过运行`scripts/extract-ikconfig`脚本

+   直接读取`/proc/config.gz`伪文件的内容（当然，它是`gzip(1)`压缩的；首先解压缩，然后读取）

作为一个学习练习，我们现在将学习如何为 x86-64 架构的 5.4 Linux 内核配置内核配置选项，其值如下表所示。现在，不要担心每个选项的含义；这只是为了练习内核配置系统：

| **特性** | **在 make menuconfig UI 中的效果和位置** | **选择<帮助>按钮**

**查看精确的 CONFIG_<FOO>选项** | **值：原始** **-> 新值** |

| 本地版本 | 设置内核发布/版本的`-EXTRAVERSION`组件（使用`uname -r`查看）；`常规设置 / 附加到内核发布的本地版本` | `CONFIG_LOCALVERSION` | (none) -> `-llkd01` |
| --- | --- | --- | --- |
| 内核配置文件支持 | 允许您查看当前内核配置详细信息；`常规设置 / 内核.config 支持` | `CONFIG_IKCONFIG` |  `n` -> `y` |
| 与前面相同，还可以通过 procfs 访问 | 允许您通过**proc 文件系统**（**procfs**）查看当前内核配置详细信息；`常规设置 / 通过/proc/config.gz 启用对.config 的访问` | `CONFIG_IKCONFIG_PROC` | `n` -> `y` |
| 内核分析 | 内核分析支持；`常规设置 / 分析支持` | `CONFIG_PROFILING` | `y` -> `n` |
| HAM 无线电 | HAM 无线电支持；`网络支持 / 业余无线电支持` | `CONFIG_HAMRADIO` | `y` -> `n` |
| VirtualBox 支持 | VirtualBox 的（Para）虚拟化支持；`设备驱动程序 / 虚拟化驱动程序 / Virtual Box 客户端集成支持` | `CONFIG_VBOXGUEST` | `n` -> `m` |
| **用户空间 IO 驱动程序**（**UIO**） | UIO 支持；`设备驱动程序 / 用户空间 IO 驱动程序` | `CONFIG_UIO` | `n` -> `m` |
| 前面加上具有通用中断处理的 UIO 平台驱动程序 | 具有通用中断处理的 UIO 平台驱动程序；`设备驱动程序 / 用户空间 IO 驱动程序 / 具有通用中断处理的用户空间 IO 平台驱动程序` | `CONFIG_UIO_PDRV_GENIRQ` | `n` -> `m` |
| MS-DOS 文件系统支持 | `文件系统 / DOS/FAT/NT 文件系统 / MSDOS 文件系统支持` | `CONFIG_MSDOS_FS` | `n` -> `m` |
| 安全性：LSMs | 关闭内核 LSMs；`安全选项 / 启用不同的安全模型` *(注意：对于生产系统，通常最好保持此选项打开！)* | `CONFIG_SECURITY` | `y` -> `n` |
| 内核调试：堆栈利用信息 | `内核调试 / 内存调试 / 堆栈利用信息检测` | `CONFIG_DEBUG_STACK_USAGE` | `n` -> `y` |

表 2.4 – 需要配置的项目

您如何解释这个表格？让我们以第一行为例；我们逐列地讨论它：

+   **第一列**指定我们要修改（编辑/启用/禁用）的内核*特性*。在这里，它是内核版本字符串的最后部分（如在`uname -r`的输出中显示）。它被称为发布的`-EXTRAVERSION`组件（详细信息请参阅*内核发布命名规范*部分）。

+   **第二列**指定了两件事：

+   首先，我们要做什么。在这里，我们想要*设置*内核发布字符串的`-EXTRAVERSION`组件。

+   第二，显示了此内核配置选项在`menuconfig` UI 中的位置。在这里，它在`General Setup`子菜单中，在其中是名为`Local version - append to kernel release`的菜单项。我们将其写为`General Setup / Local version - append to kernel release`。

+   **第三列**指定内核配置选项的名称为`CONFIG_<FOO>`。如果需要，您可以在菜单系统中搜索此选项。在这个例子中，它被称为`CONFIG_LOCALVERSION`。

+   **第四列**显示了此内核配置选项的原始*值*以及我们希望您将其更改为的值（“新”值）。它以*原始值 -> 新值*的格式显示。在我们的示例中，它是`(none) -> -llkd01`，意味着`-EXTRAVERSION`字符串组件的原始值为空，我们希望您修改它，将其更改为值`-llkd01`。

另一方面，对于我们展示的几个项目，可能不会立即显而易见——比如`n -> m`；这是什么意思？`n -> m`意味着您应该将原始值从`n`（未选择）更改为`m`（选择为内核模块进行构建）。同样，`y -> n`字符串表示将配置选项从打开更改为关闭。

您可以通过按下/键（就像 vi 一样；我们将在接下来的部分中展示更多内容）在`menuconfig`系统 UI 中*搜索*内核配置选项。

然后（实际上是在接下来的章节中），我们将使用这些新的配置选项构建内核（和模块），从中引导，并验证前面的内核配置选项是否按我们所需设置。

但是现在，您需要做您的部分：启动菜单 UI（通常使用`make menuconfig`），然后导航菜单系统，找到先前描述的相关内核配置选项，并根据需要进行编辑，以符合前表中第四列显示的内容。

请注意，根据您当前运行的 Linux 发行版及其内核模块（我们使用`lsmod(8)`生成了初始配置，记得吗？），在配置内核时看到的实际值和默认值可能与*Ubuntu 18.04.3 LTS*发行版（运行 5.0.0-36-generic 内核）的值不同，正如我们之前使用和展示的那样。

在这里，为了保持讨论的理智和紧凑，我们只会展示设置前表中显示的第二个和第三个内核配置选项的完整详细步骤（`Kernel .config support`）。剩下的编辑由您完成。让我们开始吧：

1.  切换到内核源树的根目录（无论您在磁盘上的哪个位置提取了它）：

```
cd ${LLKD_KSRC}
```

1.  根据先前描述的第三种方法（在*Tuned kernel config via the localmodconfig approach*部分）设置初始内核配置文件：

```
lsmod > /tmp/lsmod.now
make LSMOD=/tmp/lsmod.now localmodconfig
```

1.  运行 UI：

```
make menuconfig
```

1.  一旦`menuconfig` UI 加载完成，转到`General Setup`菜单项。通常，在 x86-64 上，它是第二个项目。使用键盘箭头键导航到它，并按*Enter*键进入。

1.  现在你在`General Setup`菜单项中。按下箭头键几次向下滚动菜单项。我们滚动到我们感兴趣的菜单——`Kernel .config support`——并将其突出显示；屏幕应该看起来（有点）像这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/255d0e1a-ffed-4ada-8417-3c7a437fbcf8.png)

图 2.6 - 通过 make menuconfig 进行内核配置；通用设置/内核.config 支持

对于 x86-64 上的 5.4.0 原始 Linux 内核，`通用设置/内核.config 支持`是从`通用设置`菜单顶部开始的第 20 个菜单项。

1.  一旦在`Kernel .config support`菜单项上，我们可以从其`<M>`前缀（在前面的屏幕截图中）看到，它是一个三态菜单项，最初设置为模块的选择`<M>`。

1.  保持这个项目（`Kernel .config support`）突出显示，使用右箭头键导航到底部工具栏上的`< Help >`按钮上，并在`< Help >`按钮上按*Enter*键。屏幕现在应该看起来（有点）像这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/bc005d7d-6840-4224-b325-471055fb315a.png)

图 2.7 - 通过 make menuconfig 进行内核配置；一个示例帮助屏幕

帮助屏幕非常有信息量。事实上，一些内核配置帮助屏幕非常丰富并且实际上很有帮助。不幸的是，有些则不是。

1.  好的，接下来，按*Enter*在`< Exit >`按钮上，这样我们就回到了上一个屏幕。

1.  然后，通过按空格键切换`Kernel .config support`菜单项（假设初始状态为`<M>`；也就是说，设置为模块）。按一次空格键会使 UI 项目显示如下：

```
<*> Kernel .config support
[ ]   Enable access to .config through /proc/config.gz (NEW)
```

注意它如何变成了`<*>`，这意味着这个功能将被构建到内核镜像本身中（实际上，它将始终处于打开状态）。现在，让我们这样做（当然，再次按空格键会将其切换到关闭状态`< >`，然后再回到原始的`<M>`状态）。

1.  现在，项目处于`<*>`（是）状态，向下滚动到下一个菜单项，`[*] Enable access to .config through /proc/config.gz`，并启用它（再次按空格键）；屏幕现在应该看起来（有点）像这样（我们只放大了相关部分）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/9d2f0a06-cb54-459c-994f-7f2dbeca1af5.png)

图 2.8 - 通过 make menuconfig 进行内核配置：将布尔配置选项切换到打开状态

您可以随时使用右箭头键转到`< Help >`并查看此项目的帮助屏幕。

在这里，我们不会探索剩余的内核配置菜单；我会留给你去找到并按照前面的表格设置。

1.  回到主菜单（主屏幕），使用右箭头键导航到`< Exit >`按钮上并按*Enter*。会弹出一个对话框：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/53fdb7cc-c7d3-44ff-bd7e-b6bef75f611c.png)

图 2.9 - 通过 make menuconfig 进行内核配置：保存对话框

很简单，不是吗？在`< Yes >`按钮上按*Enter*保存并退出。如果选择`< No >`按钮，您将失去所有配置更改（在本次会话期间进行的更改）。或者，您可以按*Esc*键*两次*来摆脱这个对话框并继续处理内核配置。

1.  保存并退出。在`< Yes >`按钮上按*Enter*。菜单系统 UI 现在保存了新的内核配置并退出；我们回到控制台（一个 shell 或终端窗口）提示符。

但是新的内核配置保存在哪里？这很重要：内核配置被写入内核源树根目录中的一个简单的 ASCII 文本文件中，名为**`.config`**。也就是说，它保存在`${LLKD_KSRC}/.config`中。

如前所述，每个内核配置选项都与形式为`CONFIG_<FOO>`的配置变量相关联，其中`<FOO>`当然被适当的名称替换。在内部，这些变量成为构建系统和实际上内核源代码使用的*宏*。例如，考虑一下`Kernel .config support`选项：

```
$ grep IKCONFIG .config
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
$
```

啊哈！配置现在反映了我们已经完成的事实：

+   打开了`CONFIG_IKCONFIG`内核功能（`=y`表示它已经打开，并将构建到内核镜像中）。

+   `/proc/config.gz`（伪）文件现在可用，作为`CONFIG_IKCONFIG_PROC=y`。

注意*：最好不要尝试手动编辑`.config`文件（“手动”）。你可能不知道有几个相互依赖；始终使用 kbuild 菜单系统（我们建议通过`make menuconfig`）来编辑它。

实际上，在我们迄今为止与 kbuild 系统的快速冒险中，底层已经发生了很多事情。下一节将稍微探讨一下这个问题，在菜单系统中搜索以及清晰地可视化原始（或旧）和新的内核配置文件之间的差异。

## 关于 kbuild 的更多信息

通过`make menuconfig`或其他方法在内核源树的根目录中创建或编辑`.config`文件并不是 kbuild 系统处理配置的最后一步。不，它现在会内部调用一个名为`syncconfig`的目标，这个目标之前被（误）命名为`silentoldconfig`。这个目标让 kbuild 生成一些头文件，这些头文件进一步用于构建内核的设置。这些文件包括`include/config`下的一些元头文件，以及`include/generated/autoconf.h`头文件，它将内核配置存储为 C 宏，从而使内核的 Makefile(s)和内核代码能够根据内核功能是否可用来做出决策。

接下来，如果你正在寻找特定的内核配置选项，但很难找到它怎么办？没问题，`menuconfig` UI 系统有一个`Search Configuration Parameter`功能。就像著名的`vi(1)`编辑器一样，按下`/`（正斜杠）键会弹出一个搜索对话框，然后输入你的搜索词，带有或不带有`CONFIG_`前缀，然后选择`< Ok >`按钮让它继续进行。

以下几张截图显示了搜索对话框和结果对话框（例如，我们搜索了术语`vbox`）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/2c56f14c-3dad-4cb4-8931-d4d1cbdc2efc.png)

图 2.10 - 通过`make menuconfig`进行内核配置：搜索配置参数的结果对话框

前面搜索的结果对话框很有趣。它揭示了关于配置选项的几条信息：

+   配置指令（只需在`Symbol:`中加上`CONFIG_`前缀）

+   配置的类型（布尔值、三态值、字母数字等）

+   提示字符串

+   重要的是，它在菜单系统中的位置（这样你就可以找到它）

+   它的内部依赖，如果有的话

+   它自动选择的任何配置选项（如果选择了它本身，则打开）

以下是结果对话框的截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/78b4af6f-1d70-4004-b7b4-91e1de325f23.png)

图 2.11 - 通过`make menuconfig`进行内核配置：前面搜索的结果对话框

所有这些信息都包含在一个 ASCII 文本文件中，该文件由 kbuild 系统用于构建菜单系统 UI - 这个文件称为`Kconfig`（实际上有几个）。它的位置也显示出来了（在`Defined at ...`行）。

### 查找配置中的差异

一旦要写入`.config`内核配置文件，kbuild 系统会检查它是否已经存在，如果存在，它会备份为`.config.old`。知道这一点，我们总是可以区分这两个文件，看到我们所做的更改。然而，使用典型的`diff(1)`实用程序来做这件事使得差异很难解释。内核提供了一个更好的方法，一个专门用于做这件事的基于控制台的脚本。内核源树中的`scripts/diffconfig`脚本对此非常有用。为了看到原因，让我们首先运行它的帮助屏幕：

```
$ scripts/diffconfig --help
Usage: diffconfig [-h] [-m] [<config1> <config2>]

Diffconfig is a simple utility for comparing two .config files.
Using standard diff to compare .config files often includes extraneous and
distracting information. This utility produces sorted output with only the
changes in configuration values between the two files.

Added and removed items are shown with a leading plus or minus, respectively.
Changed items show the old and new values on a single line.
[...]
```

现在，我们来试一下：

```
$ scripts/diffconfig .config.old .config
-AX25 n
-DEFAULT_SECURITY_APPARMOR y
-DEFAULT_SECURITY_SELINUX n
-DEFAULT_SECURITY_SMACK n
[...]
-SIGNATURE y
 DEBUG_STACK_USAGE n -> y
 DEFAULT_SECURITY_DAC n -> y
 FS_DAX y -> n
 HAMRADIO y -> n
 IKCONFIG m -> y
 IKCONFIG_PROC n -> y
 LOCALVERSION "" -> "-llkd01"
 MSDOS_FS n -> m
 PROFILING y -> n
 SECURITY y -> n
 UIO n -> m
+UIO_AEC n
 VBOXGUEST n -> m
[...]
$ 
```

如果您修改了内核配置更改，如前表所示，您应该通过内核的`diffconfig`脚本看到类似于前面代码块中显示的输出。它清楚地向我们展示了我们改变了哪些内核配置选项以及如何改变的。

在我们结束之前，快速注意一些关键的事情：*内核安全*。虽然用户空间安全加固技术已经大大增长，但内核空间安全加固技术实际上正在追赶。仔细配置内核的配置选项在确定给定 Linux 内核的安全姿态方面起着关键作用；问题是，有太多的选项（实际上是意见），往往很难（交叉）检查哪些是从安全角度来看是一个好主意，哪些不是。Alexander Popov 编写了一个非常有用的 Python 脚本，名为`kconfig-hardened-check`；它可以运行以检查和比较给定的内核配置（通过通常的配置文件）与一组预定的加固偏好（来自各种 Linux 内核安全项目：著名的**内核自我保护项目**（**KSPP**），最后一个公共 grsecurity 补丁，CLIP OS 和安全锁定 LSM）。查找`kconfig-hardened-check` GitHub 存储库，尝试一下！

好了！你现在已经完成了 Linux 内核构建的前三个步骤，相当了不起。（当然，我们将在下一章中完成构建过程的其余四个步骤。）我们将以一个关于学习有用技能的最后一节结束本章-如何自定义内核 UI 菜单。

# 自定义内核菜单-添加我们自己的菜单项

所以，假设你开发了一个设备驱动程序，一个实验性的新调度类，一个自定义的`debugfs`（调试文件系统）回调，或者其他一些很酷的内核特性。你将如何让团队中的其他人，或者说，你的客户，知道这个奇妙的新内核特性存在，并允许他们选择它（作为内置或内核模块）并因此构建和使用它？答案是在内核配置菜单的适当位置插入*一个新的菜单项*。

为此，首先了解一下各种`Kconfig*`文件及其所在位置是很有用的。让我们找出来。

## Kconfig*文件

内核源树根目录中的`Kconfig`文件用于填充`menuconfig` UI 的初始屏幕。如果你愿意，可以看一下它。它通过在内核源树的不同文件夹中源化各种其他`Kconfig`文件来工作。以下表总结了更重要的`Kconfig*`文件以及它们在 kbuild UI 中服务的菜单：

| **菜单** | **定义它的 Kconfig 文件位置** |
| --- | --- |
| 主菜单，初始屏幕 | `Kconfig` |
| 通用设置+启用可加载模块支持 | `init/Kconfig` |

| 处理器类型和特性+总线选项+二进制模拟

（特定于架构；上面的菜单标题是为 x86；一般来说，Kconfig 文件在这里：`arch/<arch>/Kconfig`）| `arch/<arch>/Kconfig` |

| 电源管理 | `kernel/power/Kconfig` |
| --- | --- |
| 固件驱动程序 | `drivers/firmware/Kconfig` |
| 虚拟化 | `arch/<arch>/kvm/Kconfig` |
| 通用架构相关选项 | `arch/Kconfig` |
| 启用块层+IO 调度程序 | `block/Kconfig` |
| 可执行文件格式 | `fs/Kconfig.binfmt` |
| 内存管理选项 | `mm/Kconfig` |
| 网络支持 | `net/Kconfig, net/*/Kconfig` |
| 设备驱动程序 | `drivers/Kconfig, drivers/*/Kconfig` |
| 文件系统 | `fs/Kconfig, fs/*/Kconfig` |
| 安全选项 | `security/Kconfig, security/*/Kconfig*` |
| 加密 API | `crypto/Kconfig, crypto/*/Kconfig` |
| 库例程 | `lib/Kconfig, lib/*/Kconfig` |
| 内核黑客 | `lib/Kconfig.debug, lib/Kconfig.*` |

表 2.5-内核配置菜单项及定义它们的相应 Kconfig*文件

通常，一个`Kconfig`文件驱动一个菜单。现在，让我们继续添加菜单项。

## 在 Kconfig 文件中创建一个新的菜单项

作为一个微不足道的例子，让我们在`General Setup`菜单中添加我们自己的布尔`dummy`配置选项。我们希望配置名称为`CONFIG_LLKD_OPTION1`。从前面的表中可以看出，要编辑的相关`Kconfig`文件是`init/Kconfig`，因为这是定义`General Setup`菜单的菜单元文件。

让我们开始吧：

1.  为了安全起见，始终制作备份副本：

```
cp init/Kconfig init/Kconfig.orig
```

1.  现在，编辑`init/Kconfig`文件：

```
vi init/Kconfig
```

在文件中找到适当的位置；在这里，我们选择在`CONFIG_LOCALVERSION_AUTO`之后插入我们的菜单项。以下截图显示了我们的新条目：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/6e083586-fb43-43a6-b1af-f5675e70bb4d.png)

图 2.12 - 编辑 init/Kconfig 并插入我们自己的菜单项

我们已经将前面的文本作为补丁提供给了我们书籍的*GitHub*源代码树中的原始`init/Kconfig`文件。在`ch2/Kconfig.patch`下找到它。

新项目以`config`关键字开头，后跟您的新`CONFIG_LLKD_OPTION1`配置变量的`FOO`部分。现在，只需阅读我们在`Kconfig`文件中关于此条目的陈述。有关`Kconfig`语言/语法的更多细节在接下来的*A few details on the Kconfig language*部分中。

1.  保存文件并退出编辑器。

1.  重新配置内核。导航到我们的新菜单项并打开该功能（请注意，在下面的截图中，默认情况下它是高亮显示的并且*关闭*）：

```
make menuconfig
[...]
```

这是输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/b201c7d0-b928-4192-8c15-99660dcbccac.png)

图 2.13 - 通过 make menuconfig 进行内核配置，显示我们的新菜单项

1.  打开它（使用空格键切换），然后保存并退出菜单系统。

在此期间，尝试按下`< Help >`按钮。您应该看到我们在`Kconfig`文件中提供的“帮助”。

1.  检查我们的功能是否已被选择：

```
$ grep "LLKD_OPTION1" .config
CONFIG_LLKD_OPTION1=y
$ grep "LLKD_OPTION1" include/generated/autoconf.h 
$  
```

我们发现确实已经在我们的`.config`文件中设置为*on*，但是（还没有！）在内核的内部自动生成的头文件中。这将在构建内核时发生。

1.  构建内核（不用担心；有关构建内核的完整细节在下一章中找到。您可以首先阅读第三章，*从源代码构建 5.x Linux 内核-第二部分*，然后再回到这一点，如果您愿意的话...）:

```
make -j4
```

1.  完成后，重新检查`autoconf.h`头文件，查看我们的新配置选项是否存在：

```
$ grep "LLKD_OPTION1" include/generated/autoconf.h 
#define CONFIG_LLKD_OPTION1 1
```

成功了！是的，但是在实际项目（或产品）中工作时，我们通常需要进一步设置，设置我们的配置项在使用此配置选项的代码相关的 Makefile 中。

这是一个快速示例，内核的顶层（或其他位置）Makefile 中，以下行将确保我们自己的代码（以下内容在`llkd_option1.c`源文件中）在构建时编译到内核中。将此行添加到相关的 Makefile 末尾：

```
obj-${CONFIG_LLKD_OPTION1}  +=  llkd_option1.o
```

现在不要担心内核`Makefile`语法相当奇怪。接下来的几章将对此进行一些解释。

此外，您应该意识到，同一个配置也可以作为内核代码片段中的普通 C 宏使用；例如，我们可以这样做：

```
#ifdef CONFIG_LLKD_OPTION1
    do_our_thing();
#endif
```

然而，非常值得注意的是，Linux 内核社区已经制定并严格遵守了某些严格的编码风格指南。在这种情况下，指南规定应尽量避免条件编译，如果需要使用`Kconfig`符号作为条件，则请按照以下方式进行：

```
if (IS_ENABLED(CONFIG_LLKD_OPTION1)) {
    do_our_thing();
}
```

Linux 内核*编码风格指南*可以在这里找到：[`www.kernel.org/doc/html/latest/process/coding-style.html`](https://www.kernel.org/doc/html/latest/process/coding-style.html)。我建议您经常参考它们，并且当然要遵循它们！

## 关于 Kconfig 语言的一些细节

到目前为止，我们对`Kconfig`语言的使用只是冰山一角。事实上，kbuild 系统使用`Kconfig`语言（或语法）来使用简单的 ASCII 文本指令来表达和创建菜单。该语言包括菜单条目、属性、（反向）依赖项、可见性约束、帮助文本等等。

内核文档了`Kconfig`语言的构造和语法：[`www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt`](https://www.kernel.org/doc/Documentation/kbuild/kconfig-language.txt)。请参考此文档以获取完整的详细信息。

以下表格简要介绍了更常见的`Kconfig`构造（并不完整）：

| **构造** | **含义** |
| --- | --- |
| `config <FOO>` | 在这里指定菜单条目名称（格式为`CONFIG_FOO`）；只需放入`FOO`部分。 |
| **菜单属性** |  |
| `  bool ["<description>"]` | 将配置选项指定为*布尔*；在`.config`中的值将是`Y`（内建到内核映像中）或不存在（将显示为已注释的条目）。 |
| `  tristate ["description>"]` | 将配置选项指定为*三态*；在`.config`中的值将是`Y`、`M`（作为内核模块构建）或不存在（将显示为已注释的条目）。 |
| `  int ["<description>"]` | 将配置选项指定为*整数*值。 |
| `     range x-y` | 整数范围从`x`到`y`。 |
| `  default <value>` | 指定默认值；根据需要使用`y`、`m`、`n`或其他值。 |
| ` prompt "<description>"` | 描述内核配置的句子。 |
| `depends on "expr"` | 为菜单项定义一个依赖项；可以使用`depends on FOO1 && FOO2 && (FOO3 &#124;&#124; FOO4)`类型的语法来定义多个依赖项。 |
| `select <config> [if "expr"]` | 定义一个反向依赖项。 |
| `help "help-text"` | 在选择`<帮助>`按钮时显示的文本。 |

表 2.6 - Kconfig，一些构造

为了帮助理解语法，以下是来自`lib/Kconfig.debug`（描述 UI 的`Kernel Hacking`-内核调试，实际上-部分菜单项的文件）的一些示例：

1.  我们将从一个简单的开始（`CONFIG_DEBUG_INFO`选项）：

```
config DEBUG_INFO
    bool "Compile the kernel with debug info"
    depends on DEBUG_KERNEL && !COMPILE_TEST
    help
      If you say Y here the resulting kernel image will include
      debugging info resulting in a larger kernel image. [...]
```

1.  接下来，让我们来看一下`CONFIG_FRAME_WARN`选项。注意`range`和条件默认值语法，如下所示：

```
config FRAME_WARN
    int "Warn for stack frames larger than (needs gcc 4.4)"
    range 0 8192
    default 3072 if KASAN_EXTRA
    default 2048 if GCC_PLUGIN_LATENT_ENTROPY
    default 1280 if (!64BIT && PARISC)
    default 1024 if (!64BIT && !PARISC)
    default 2048 if 64BIT
    help
      Tell gcc to warn at build time for stack frames larger than this.
      Setting this too low will cause a lot of warnings.
      Setting it to 0 disables the warning.
      Requires gcc 4.4
```

1.  接下来，`CONFIG_HAVE_DEBUG_STACKOVERFLOW`选项是一个简单的布尔值；它要么开启，要么关闭。`CONFIG_DEBUG_STACKOVERFLOW`选项也是一个布尔值。请注意它如何依赖于另外两个选项，使用布尔 AND（`&&`）运算符分隔：

```
config HAVE_DEBUG_STACKOVERFLOW
        bool

config DEBUG_STACKOVERFLOW
        bool "Check for stack overflows"
        depends on DEBUG_KERNEL && HAVE_DEBUG_STACKOVERFLOW
        ---help---
          Say Y here if you want to check for overflows of kernel, IRQ
          and exception stacks (if your architecture uses them). This 
          option will show detailed messages if free stack space drops
          below a certain limit. [...]
```

好了！这完成了我们对在内核配置中创建（或编辑）自定义菜单条目的覆盖，也完成了本章。

# 总结

在本章中，您首先学习了如何获取 Linux 内核源代码树。然后，您了解了其发布（或版本）命名法，各种类型的 Linux 内核（`-next`树，`-rc`/主线树，稳定版，LTS，SLTS 和发行版），以及基本的内核开发工作流程。在这个过程中，您甚至快速浏览了内核源代码树，以便更清楚地了解其布局。接下来，您将看到如何将压缩的内核源代码树提取到磁盘上，并且关键的是如何配置内核-这是过程中的关键步骤。此外，您还学会了如何自定义内核菜单，向其中添加自己的条目，以及有关 kbuild 系统和相关的`Kconfig`文件的一些知识。

了解如何获取和配置 Linux 内核是一项有用的技能。我们刚刚开始了这段漫长而激动人心的旅程。您将意识到，随着对内核内部、驱动程序和目标系统硬件的更多经验和知识，您调整内核以适应项目目的的能力将会变得更好。

我们已经走了一半的路；我建议您首先消化这些材料，重要的是-尝试本章中的步骤，解决问题/练习，并浏览*Further reading*部分。然后，在下一章中，让我们实际构建 5.4.0 内核并进行验证！

# 问题

最后，这里有一些问题供您测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。您会在本书的 GitHub 存储库中找到一些问题的答案：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助您深入了解有用的材料，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）的 Further reading 文档。 *Further reading* 文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。


# 第三章：从源代码构建 5.x Linux 内核 - 第二部分

本章继续上一章的内容。在上一章中，在“从源代码构建内核的步骤”部分，我们涵盖了构建内核的前三个步骤。在那里，您学会了如何下载和提取内核源树，甚至是`git clone`（*步骤 1*和*2*）。然后，我们继续了解内核源树布局，以及正确到达配置内核起始点的各种方法（*步骤 3*）。我们甚至在内核配置菜单中添加了自定义菜单项。

在本章中，我们继续我们的内核构建任务，覆盖了剩下的四个步骤来实际构建它。首先，当然，我们要构建它（*步骤 4*）。然后您将看到如何正确安装作为构建的一部分生成的内核模块（*步骤 5*）。接下来，我们运行一个简单的命令来设置 GRUB 引导加载程序并生成`initramfs`（或`initrd`）镜像（*步骤 6*）。还讨论了使用`initramfs`镜像的动机以及它的使用方式。然后介绍了一些有关配置 GRUB 引导加载程序（对于 x86）的细节（*步骤 7*）。

在本章结束时，我们将使用新的内核镜像引导系统，并验证它是否按预期构建。然后，我们将学习如何为外部架构（即 ARM，所讨论的板子是著名的树莓派）*交叉编译* Linux 内核。

简而言之，涵盖的领域如下：

+   第 4 步 - 构建内核镜像和模块

+   第 5 步 - 安装内核模块

+   第 6 步 - 生成 initramfs 镜像和引导加载程序设置

+   了解 initramfs 框架

+   第 7 步 - 自定义 GRUB 引导加载程序

+   验证我们新内核的配置

+   树莓派的内核构建

+   内核构建的其他提示

# 技术要求

在开始之前，我假设您已经下载、提取（如果需要）并配置了内核，因此有一个`.config`文件准备好了。如果您还没有，请参考上一章，了解如何确切地完成这些步骤。现在我们可以继续构建它了。

# 第 4 步 - 构建内核镜像和模块

从最终用户的角度来看，执行构建实际上非常简单。在最简单的形式中，只需确保您在配置的内核源树的根目录中，并键入`make`。就是这样 - 内核镜像和任何内核模块（在嵌入式系统上可能还有**设备树二进制**（**DTB**））将被构建。喝杯咖啡吧！第一次可能需要一段时间。

当然，我们可以向`make`传递各种`Makefile`目标。在命令行上快速发出`make help`命令会显示相当多的信息。请记住，实际上我们之前就用过这个命令，事实上，以查看所有可能的配置目标。在这里，我们用它来查看`all`目标默认构建了什么：

```
$ cd ${LLKD_KSRC}     # the env var LLKD_KSRC holds the 'root' of our 
                      # 5.4 kernel source tree
$ make help
[...]
Other generic targets:
  all - Build all targets marked with [*]
* vmlinux - Build the bare kernel
* modules - Build all modules
[...]
Architecture specific targets (x86):
* bzImage - Compressed kernel image (arch/x86/boot/bzImage)
[...]
$ 
```

好的，执行`make all`将得到前面三个带有`*`前缀的目标；它们代表什么意思呢？

+   `vmlinux`实际上与未压缩的内核镜像的名称相匹配。

+   `modules`目标意味着所有标记为`m`（用于模块）的内核配置选项将作为内核模块（`.ko`文件）构建在内核源树中（有关内核模块的具体内容以及如何编程的细节将在接下来的两章中讨论）。

+   `bzImage`是特定于架构的。在 x86[-64]系统上，这是压缩内核镜像的名称 - 引导加载程序实际加载到 RAM 中并在内存中解压缩并引导的镜像文件。

那么，一个常见问题：如果`bzImage`是我们用来引导和初始化系统的实际内核，那么`vmlinux`是用来做什么的？请注意，`vmlinux`是未压缩的内核映像。它可能很大（甚至在调试构建期间生成的内核符号存在时非常大）。虽然我们从不通过`vmlinux`引导，但它仍然很重要。出于内核调试目的，请保留它（不幸的是，这超出了本书的范围）。

使用 kbuild 系统，只需运行`make`命令就相当于`make all`。

内核代码库非常庞大。目前的估计在 2000 万**源代码行**（**SLOC**）左右，因此，构建内核确实是*一个非常占用内存和 CPU 的工作*。事实上，有些人使用内核构建作为压力测试！现代的`make(1)`实用程序功能强大，能够处理多个进程。我们可以要求它生成多个进程来并行处理构建的不同（无关）部分，从而提高吞吐量，缩短构建时间。相关选项是`-j'n'`，其中`n`是并行运行的任务数量的上限。用于确定这一点的启发式（经验法则）如下：

```
n = num-CPU-cores * factor;
```

在这里，`factor`是 2（或者在具有数百个 CPU 核心的高端系统上为 1.5）。从技术上讲，我们需要内部的核心是“线程化”的或者使用**同时多线程**（**SMT**）-这是英特尔所称的*超线程*，这样启发式才有用。

有关并行化`make`及其工作原理的更多详细信息可以在`make(1)`的 man 页面中找到（使用`man 1 make`调用），在`PARALLEL MAKE AND THE JOBSERVER`部分。

另一个常见问题：您的系统上有多少 CPU 核心？有几种方法可以确定这一点，其中一种简单的方法是使用`nproc(1)`实用程序：

```
$ nproc
2 
```

关于`nproc(1)`和相关实用程序的一点说明：

a) 对`nproc(1)`执行`strace(1)`会发现它基本上是使用`sched_getaffinity(2)`系统调用。我们将在第九章 *CPU 调度器-第一部分*和第十章 *CPU 调度器-第二部分*中提到更多关于这个和相关系统调用的内容。

b) FYI，`lscpu(1)`实用程序提供核心数以及其他有用的 CPU 信息。例如，它显示是否在**虚拟机**（**VM**）上运行（`virt-what`脚本也是如此）。在 Linux 系统上试一下。

显然，我们的客户机虚拟机已配置为具有两个 CPU 核心，因此让`n=2*2=4`。所以，我们开始构建内核。以下输出来自我们可靠的 x86_64 Ubuntu 18.04 LTS 客户机系统，配置为具有 2GB 的 RAM 和两个 CPU 核心。

请记住，内核必须首先*配置。*有关详细信息，请参阅第二章 *从源代码构建 5.x Linux 内核-第一部分*。

再次，当您开始时，内核构建可能会发出警告，尽管在这种情况下不是致命的：

```
$ time make -j4
scripts/kconfig/conf --syncconfig Kconfig
 UPD include/config/kernel.release
warning: Cannot use CONFIG_STACK_VALIDATION=y, please install libelf-dev, libelf-devel or elfutils-libelf-devel
[...]
```

因此，为了解决这个问题，我们中断构建，使用*Ctrl* + *C*，然后按照输出的建议安装`libelf-dev`软件包。在我们的 Ubuntu 系统上，`sudo apt install libelf-dev`就足够了。如果您按照第一章 *内核工作区设置*中的详细设置进行操作，这种情况就不会发生。重试，现在它可以工作了！为了让您感受一下，我们展示了构建输出的一些小片段。但是，最好还是自己尝试一下：

正因为内核构建非常依赖 CPU 和 RAM，因此在虚拟机上进行这项工作要比在本机 Linux 系统上慢得多。通过至少将客户机引导到运行级别 3（多用户网络，无 GUI）来节省 RAM 是有帮助的：[`www.if-not-true-then-false.com/2012/howto-change-runlevel-on-grub2/`](https://www.if-not-true-then-false.com/2012/howto-change-runlevel-on-grub2/)。

```
$ cd ${LLKD_KSRC} $ time make -j4 scripts/kconfig/conf --syncconfig Kconfig SYSHDR arch/x86/include/generated/asm/unistd_32_ia32.h
 SYSTBL arch/x86/include/generated/asm/syscalls_32.h
[...]
  DESCEND objtool
  HOSTCC /home/llkd/kernels/linux-5.4/tools/objtool/fixdep.o
  HOSTLD /home/llkd/kernels/linux-5.4/tools/objtool/fixdep-in.o
  LINK /home/llkd/kernels/linux-5.4/tools/objtool/fixdep
[...]

[...]
  LD      vmlinux.o
  MODPOST vmlinux.o
  MODINFO modules.builtin.modinfo
  LD      .tmp_vmlinux1
  KSYM    .tmp_kallsyms1.o
  LD      .tmp_vmlinux2
  KSYM    .tmp_kallsyms2.o
 LD      vmlinux
  SORTEX  vmlinux
  SYSMAP  System.map
  Building modules, stage 2.
 MODPOST 59 modules
  CC      arch/x86/boot/a20.o
[...]
  LD      arch/x86/boot/setup.elf
  OBJCOPY arch/x86/boot/setup.bin
  BUILD   arch/x86/boot/bzImage
Setup is 17724 bytes (padded to 17920 bytes).
System is 8385 kB
CRC 6f010e63
  CC [M]  drivers/hid/hid.mod.o
Kernel: arch/x86/boot/bzImage is ready  (#1)
```

好的，内核映像（在这里称为`bzImage`）和`vmlinux`文件已经成功地通过拼接生成的各种目标文件构建，正如在先前的输出中所见 - 先前块的最后一行确认了这一事实。但是，请稍等，构建还没有完成。kbuild 系统现在继续完成所有内核模块的构建；输出的最后部分如下所示：

```
[...]
  CC [M]  drivers/hid/usbhid/usbhid.mod.o
  CC [M]  drivers/i2c/algos/i2c-algo-bit.mod.o
[...]
  LD [M] sound/pci/snd-intel8x0.ko
  LD [M] sound/soundcore.ko

real     17m31.980s
user     23m58.451s
sys      3m22.280s
$
```

整个过程似乎总共花了大约 17.5 分钟。`time(1)`实用程序给出了一个（非常）粗略的时间概念，即后面的命令所花费的时间。

如果您想要准确的 CPU 分析，请学会使用强大的`perf(1)`实用程序。在这里，您可以尝试使用`perf stat make -j4`命令。我建议您在发行版内核上尝试此操作，否则，`perf`本身将必须为您的自定义内核手动构建。

此外，在先前的输出中，`Kernel: arch/x86/boot/bzImage is ready (#1)`，`#1`意味着这是内核的第一个构建。此数字将在后续构建中自动递增，并在您引导到新内核然后执行`uname -a`时显示。

由于我们正在进行并行构建（通过`make -j4`，意味着四个进程并行执行构建），所有构建过程仍然写入相同的`stdout`位置 - 终端窗口。因此，输出可能是无序或混乱的。

构建应该干净地运行，没有任何错误或警告。嗯，有时会看到编译器警告，但我们将轻松地忽略它们。如果在此步骤中遇到编译器错误，从而导致构建失败，怎么办？我们怎么委婉地表达这？哦，好吧，我们不能 - 这很可能是您的问题，而不是内核社区的问题。请检查并重新检查每一步，如果一切都失败了，请使用`make mrproper`命令从头开始重做！很多时候，内核构建失败意味着内核配置错误（可能会冲突的随机选择的配置）、工具链的过时版本或不正确的打补丁，等等。

假设一切顺利，正如它应该的那样，在此步骤终止时，kbuild 系统已生成了三个关键文件（其中有许多）。

在内核源树的根目录中，我们有以下内容：

+   未压缩的内核映像文件`vmlinux`（仅用于调试）

+   符号地址映射文件`System.map`

+   压缩的可引导内核映像文件`bzImage`（请参阅以下输出）

让我们来看看它们！通过向`ls(1)`传递`-h`选项，我们使输出（特别是文件大小）更易于阅读：

```
$ ls -lh vmlinux System.map
-rw-rw-r-- 1 llkd llkd 4.1M Jan 17 12:27 System.map
-rwxrwxr-x 1 llkd llkd 591M Jan 17 12:27 vmlinux
$ file ./vmlinux
./vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=<...>, with debug_info, not stripped
```

如您所见，`vmlinux`文件非常庞大。这是因为它包含了所有内核符号以及额外的调试信息编码进去。（顺便说一句，`vmlinux`和`System.map`文件在内核调试上下文中使用；保留它们。）有用的`file(1)`实用程序向我们展示了有关此映像文件的更多细节。引导加载程序加载并引导的实际内核映像文件将始终位于`arch/<arch>/boot/`的通用位置；因此，对于 x86 架构，我们有以下内容：

```
$ ls -l arch/x86/boot/bzImage -rw-rw-r-- 1 llkd llkd 8604032 Jan 17 12:27 arch/x86/boot/bzImage$ file arch/x86/boot/bzImage
arch/x86/boot/bzImage: Linux kernel x86 boot executable bzImage, version 5.4.0-llkd01 (llkd@llkd-vbox) #1 SMP Thu [...], RO-rootFS, swap_dev 0x8, Normal VGA
```

x86_64 架构的压缩内核映像版本`5.4.0-llkd01`大小略大于 8MB。`file(1)`实用程序再次清楚地显示它确实是用于 x86 架构的 Linux 内核引导映像。

内核文档记录了在内核构建过程中可以通过设置各种环境变量执行的几个调整和开关。此文档可以在内核源树中的`Documentation/kbuild/kbuild.rst`找到。实际上，我们将在接下来的材料中使用`INSTALL_MOD_PATH`、`ARCH`和`CROSS_COMPILE`环境变量。

太好了！我们的内核映像和模块已经准备就绪！继续阅读，因为我们将在下一步中安装内核模块。

# 第 5 步 - 安装内核模块

在上一步中，所有标记为`m`的内核配置选项实际上现在都已经构建完成。正如你将了解的那样，这还不够：它们现在必须被安装到系统上已知的位置。本节涵盖了这些细节。

## 在内核源代码中定位内核模块

要查看前一步生成的内核模块 - 内核构建 - 让我们在内核源文件夹中执行一个快速的`find(1)`命令。了解所使用的命名约定，其中内核模块文件名以`.ko`结尾。

```
$ cd ${LLKD_KSRC}
$ find . -name "*.ko"
./arch/x86/events/intel/intel-rapl-perf.ko
./arch/x86/crypto/crc32-pclmul.ko
./arch/x86/crypto/ghash-clmulni-intel.ko
[...]
./net/ipv4/netfilter/ip_tables.ko
./net/sched/sch_fq_codel.ko
$ find . -name "*.ko" | wc -l
59 
```

我们可以从前面的输出中看到，在这个特定的构建中，总共构建了 59 个内核模块（为了简洁起见，实际的`find`输出在前面的块中被截断）。

现在回想一下我在第二章中要求你进行的练习，*从源代码构建 5.x Linux 内核 - 第一部分*，在*使用 make menuconfig UI 的示例*部分。在那里，在*表 2.4*中，最后一列指定了我们所做更改的类型。寻找`n -> m`（或`y -> m`）的更改，这意味着我们正在配置该特定功能以构建为内核模块。在那里，我们可以看到这包括以下功能：

+   VirtualBox 支持，`n -> m`

+   **用户空间 I/O**（**UIO**）驱动程序，`n -> m`；以及具有通用中断处理的 UIO 平台驱动程序，`n -> m`

+   MS-DOS 文件系统支持，`n -> m`

由于这些功能被要求构建为模块，它们不会被编码到`vmlinux`或`bzImage`内核映像文件中。不，它们将作为独立的（嗯，有点）*内核模块*存在。让我们在内核源树中寻找前面功能的内核模块（显示它们的路径名和大小，使用一些脚本技巧）：

```
$ find . -name "*.ko" -ls | egrep -i "vbox|msdos|uio" | awk '{printf "%-40s %9d\n", $11, $7}'
./fs/fat/msdos.ko                           361896
./drivers/virt/vboxguest/vboxguest.ko       948752
./drivers/gpu/drm/vboxvideo/vboxvideo.ko   3279528
./drivers/uio/uio.ko                        408136
./drivers/uio/uio_pdrv_genirq.ko            324568
$ 
```

好的，很好，二进制内核模块确实已经在内核源树中生成。但这还不够。为什么？它们需要被*安装*到根文件系统中的一个众所周知的位置，以便在引导时，系统*实际上可以找到并加载它们*到内核内存中。这就是为什么我们需要*安装*内核模块。根文件系统中的“众所周知的位置”是**`/lib/modules/$(uname -r)/`**，其中`$(uname -r)`产生内核版本号，当然。

## 安装内核模块

执行内核模块安装很简单；（在构建步骤之后）只需调用`modules_install` Makefile 目标。让我们这样做：

```
$ cd ${LLKD_KSRC} $ sudo make modules_install [sudo] password for llkd: 
  INSTALL arch/x86/crypto/aesni-intel.ko
  INSTALL arch/x86/crypto/crc32-pclmul.ko
  INSTALL arch/x86/crypto/crct10dif-pclmul.ko
[...]
  INSTALL sound/pci/snd-intel8x0.ko
  INSTALL sound/soundcore.ko
  DEPMOD 5.4.0-llkd01
$ 
```

请注意，我们使用`sudo(8)`以*root*（超级用户）身份执行安装。这是因为默认的安装位置（在`/lib/modules/`下）只有 root 可写。一旦内核模块准备好并复制过去（在前面的输出块中显示为`INSTALL`的工作），kbuild 系统运行一个名为`depmod(8)`的实用程序。它的工作基本上是解决内核模块之间的依赖关系，并将它们（如果存在）编码到一些元文件中（有关`depmod(8)`的更多详细信息，请参阅[`linux.die.net/man/8/depmod`](https://linux.die.net/man/8/depmod)上的 man 页面）。

现在让我们看看模块安装步骤的结果：

```
$ uname -r
5.0.0-36-generic        # this is the 'distro' kernel (for Ubuntu 18.04.3 LTS) we're running on
$ ls /lib/modules/
5.0.0-23-generic 5.0.0-36-generic 5.4.0-llkd01
$ 
```

在前面的代码中，我们可以看到对于每个（Linux）内核，我们可以将系统引导到的文件夹在`/lib/modules/`下，其名称是内核版本，正如预期的那样。让我们查看感兴趣的文件夹 - 我们新内核的（`5.4.0-llkd01`）。在那里，在`kernel/`子目录下 - 在各种目录中 - 存放着刚安装的内核模块：

```
$ ls /lib/modules/5.4.0-llkd01/kernel/
arch/  crypto/  drivers/  fs/  net/  sound/
```

顺便说一句，`/lib/modules/<kernel-ver>/modules.builtin`文件中列出了所有已安装的内核模块（在`/lib/modules/<kernel-ver>/kernel/`下）。

让我们在这里搜索我们之前提到的内核模块：

```
$ find /lib/modules/5.4.0-llkd01/kernel/ -name "*.ko" | egrep "vboxguest|msdos|uio"
/lib/modules/5.4.0-llkd01/kernel/fs/fat/msdos.ko
/lib/modules/5.4.0-llkd01/kernel/drivers/virt/vboxguest/vboxguest.ko
/lib/modules/5.4.0-llkd01/kernel/drivers/uio/uio.ko
/lib/modules/5.4.0-llkd01/kernel/drivers/uio/uio_pdrv_genirq.ko
$ 
```

它们都显示出来了。太棒了！

最后一个关键点：在内核构建过程中，我们可以将内核模块安装到*我们*指定的位置，覆盖（默认的）`/lib/modules/<kernel-ver>`位置。这是通过将环境变量`INSTALL_MOD_PATH`设置为所需的位置来完成的；例如，执行以下操作：

```
export STG_MYKMODS=../staging/rootfs/my_kernel_modules
make INSTALL_MOD_PATH=${STG_MYKMODS} modules_install
```

有了这个，我们所有的内核模块都安装到了`${STG_MYKMODS}/`文件夹中。请注意，如果`INSTALL_MOD_PATH`指向不需要*root*写入的位置，也许就不需要`sudo`。

这种技术 - 覆盖*内核模块的安装位置* - 在为嵌入式目标构建 Linux 内核和内核模块时特别有用。显然，我们绝对*不*应该用嵌入式目标的内核模块覆盖主机系统的内核模块；那可能是灾难性的！

下一步是生成所谓的`initramfs`（或`initrd`）镜像并设置引导加载程序。我们还需要清楚地了解这个`initramfs`镜像到底是什么，以及使用它的动机。接下来的部分将深入探讨这些细节。

# 第 6 步 - 生成`initramfs`镜像和引导加载程序设置

首先，请注意，这个讨论非常偏向于 x86[_64]架构。对于典型的 x86 桌面或服务器内核构建过程，这一步被内部分成了两个不同的部分：

+   生成`initramfs`（以前称为`initrd`）镜像

+   （GRUB）引导加载程序设置为新的内核镜像

在这里，将它封装成一个单一步骤的原因是，在 x86 架构上，方便的脚本执行这两个任务，看起来就像是一个单一步骤。

想知道这个`initramfs`（或`initrd`）镜像文件到底是什么？请参阅下面的*了解 initramfs 框架*部分以获取详细信息。我们很快就会到那里。

现在，让我们继续并生成**initramfs**（即**初始 RAM 文件系统**）镜像文件，并更新引导加载程序。在 x86[_64] Ubuntu 上执行这个操作非常简单，只需一步即可完成：

```
$ sudo make install sh ./arch/x86/boot/install.sh 5.4.0-llkd01 arch/x86/boot/bzImage \
  System.map "/boot"
run-parts: executing /etc/kernel/postinst.d/apt-auto-removal 5.4.0-llkd01 /boot/vmlinuz-5.4.0-llkd01
run-parts: executing /etc/kernel/postinst.d/initramfs-tools 5.4.0-llkd01 /boot/vmlinuz-5.4.0-llkd01
update-initramfs: Generating /boot/initrd.img-5.4.0-llkd01
[...]
run-parts: executing /etc/kernel/postinst.d/zz-update-grub 5.4.0-llkd01 /boot/vmlinuz-5.4.0-llkd01
Sourcing file `/etc/default/grub'
Generating grub configuration file ...
Found linux image: /boot/vmlinuz-5.4.0-llkd01
Found initrd image: /boot/initrd.img-5.4.0-llkd01
[...]
Found linux image: /boot/vmlinuz-5.0.0-36-generic
Found initrd image: /boot/initrd.img-5.0.0-36-generic
[...]
done
$
```

请注意，再次，我们在`make install`命令前加上了`sudo(8)`。显然，这是因为我们需要*root*权限来写入相关的文件和文件夹。

就是这样，我们完成了：一个全新的 5.4 内核，以及所有请求的内核模块和`initramfs`镜像，都已经生成，并且（GRUB）引导加载程序已经更新。剩下的就是重新启动系统，在引导加载程序菜单屏幕上选择新的内核镜像，启动，登录，并验证一切是否正常。

## 在 Fedora 30 及以上版本上生成`initramfs`镜像

不幸的是，在 Fedora 30 及以上版本中，生成`initramfs`镜像似乎并不像在前面的部分中使用 Ubuntu 那样容易。一些人建议通过`ARCH`环境变量明确指定架构。看一下：

```
$ sudo make ARCH=x86_64 install
sh ./arch/x86/boot/install.sh 5.4.0-llkd01 arch/x86/boot/bzImage \
System.map "/boot"
Cannot find LILO.
$
```

失败了！想知道为什么吗？我不会在这里详细介绍，但这个链接应该会帮到你：[`discussion.fedoraproject.org/t/installing-manually-builded-kernel-in-system-with-grub2/1895`](https://discussion.fedoraproject.org/t/installing-manually-builded-kernel-in-system-with-grub2/1895)。为了解决这个问题，以下是我在我的 Fedora 31 VM 上所做的（是的，它成功了！）：

1.  手动创建`initramfs`镜像：

```
 sudo mkinitrd /boot/initramfs-5.4.0-llkd01.img 5.4.0-llkd01
```

1.  确保安装了`grubby`软件包：

```
sudo dnf install grubby-deprecated-8.40-36.fc31.x86_64
```

在输入`grubby-`后按两次*Tab*键会自动完成完整的软件包名称。

1.  重新运行`make install`命令：

```
$ sudo make ARCH=x86_64 install
 sh ./arch/x86/boot/install.sh 5.4.0-llkd01 arch/x86/boot/bzImage \
 System.map "/boot"
 grubby fatal error: unable to find a suitable template
 grubby fatal error: unable to find a suitable template
 grubby: doing this would leave no kernel entries. Not writing out new config.
 $
```

尽管`make install`命令似乎失败了，但它已经足够成功了。让我们偷看一下`/boot`目录的内容来验证一下：

```
 $ ls -lht /boot
 total 204M
 -rw-------. 1 root root  44M Mar 26 13:08 initramfs-5.4.0-llkd01.img
 lrwxrwxrwx. 1 root root   29 Mar 26 13:07 System.map -> /boot/System.map-5.4.0-llkd01
 lrwxrwxrwx. 1 root root   26 Mar 26 13:07 vmlinuz -> /boot/vmlinuz-5.4.0-llkd01
 -rw-r--r--. 1 root root 4.1M Mar 26 13:07 System.map-5.4.0-llkd01
 -rw-r--r--. 1 root root 9.0M Mar 26 13:07 vmlinuz-5.4.0-llkd01
[...]
```

的确，`initramfs`镜像、`System.map`文件和`vmlinuz`（以及所需的符号链接）似乎已经设置好了！重新启动，从 GRUB 菜单中选择新的内核，并验证它是否正常工作。

在这一步中，我们生成了`initramfs`镜像。问题是，在我们执行此操作时，*kbuild*系统在幕后执行了什么？继续阅读以了解详情。

## 生成 initramfs 镜像-在幕后

请回想一下前一节中，当`sudo make install`命令执行时，您将首先看到什么（以下是为了您的方便而重现的）：

```
$ sudo make install sh ./arch/x86/boot/install.sh 5.4.0-llkd01 arch/x86/boot/bzImage \
 System.map "/boot"
```

显然，(`install.sh`)是一个正在执行的脚本。在其工作的一部分内部，它将以下文件复制到`/boot`文件夹中，名称格式通常为`<filename>-$(uname -r)`：

```
System.map-5.4.0-llkd01, initrd.img-5.4.0-llkd01, vmlinuz-5.4.0-llkd01, config-5.4.0-llkd01
```

`initramfs`镜像也被构建。一个名为`update-initramfs`的 shell 脚本执行此任务（它本身是另一个名为`mkinitramfs(8)`的脚本的方便包装，该脚本执行实际工作）。构建后，`initramfs`镜像也被复制到`/boot`目录中，在前面的输出片段中被视为`initrd.img-5.4.0-llkd01`。

如果要复制到`/boot`的文件已经存在，则将其备份为`<filename>-$(uname -r).old`。名为`vmlinuz-<kernel-ver>`的文件是`arch/x86/boot/bzImage`文件的副本。换句话说，它是压缩的内核镜像-引导加载程序将被配置为将其加载到 RAM 中，解压缩并跳转到其入口点，从而将控制权交给内核！

为什么叫`vmlinux`（回想一下，这是存储在内核源树根目录中的未压缩内核镜像文件）和`vmlinuz`？这是一个古老的 Unix 惯例，Linux OS 非常乐意遵循：在许多 Unix 版本中，内核被称为`vmunix`，因此 Linux 将其称为`vmlinux`，压缩的内核被称为`vmlinuz`；`vmlinuz`中的`z`是为了暗示（默认情况下）`gzip(1)`压缩。

此外，位于`/boot/grub/grub.cfg`的 GRUB 引导加载程序配置文件将被更新，以反映新的内核现在可用于引导。

同样值得强调的是，所有这些都是*非常特定于架构*的。前面的讨论是关于在 Ubuntu Linux x86[-64]系统上构建内核的。虽然在概念上类似，但内核镜像文件名、它们的位置，特别是引导加载程序，在不同的架构上有所不同。

如果您愿意，可以直接跳到*自定义 GRUB 引导加载程序*部分。如果您感兴趣（我希望如此），请继续阅读。在下一节中，我们将更详细地描述`initramfs`*/*`inird`框架的*如何*和*为什么*。

# 理解 initramfs 框架

还有一个谜团！这个`initramfs`或`initrd`镜像到底是干什么的？它为什么存在？

首先，使用此功能是一个选择-配置指令称为`CONFIG_BLK_DEV_INITRD`。默认情况下为`y`。简而言之，对于那些事先不知道某些事情的系统，比如引导磁盘主机适配器或控制器类型（SCSI，RAID 等），根文件系统格式化为确切的文件系统类型（是`ext2`，`ext3`，`ext4`，`btrfs`，`reiserfs`，`f2fs`还是其他？），或者对于那些这些功能总是作为内核模块构建的系统，我们需要`initramfs`功能。为什么确切的原因一会儿就会变得清楚。另外，正如前面提到的，`initrd`现在被认为是一个较旧的术语。如今，我们更经常使用`initramfs`这个术语。

## 为什么要使用 initramfs 框架？

`initramfs`框架本质上是早期内核引导和用户模式之间的一种中间人。它允许我们在实际根文件系统被挂载之前运行用户空间应用程序（或脚本）。这在许多情况下都很有用，以下列表详细说明了其中的一些情况。关键点是，`initramfs`允许我们在内核在引导时通常无法运行的用户模式应用程序。

实际上，在各种用途中，这个框架使我们能够做一些事情，包括以下内容：

+   设置控制台字体。

+   自定义键盘布局设置。

+   在控制台设备上打印自定义欢迎消息。

+   接受密码（用于加密磁盘）。

+   根据需要加载内核模块。

+   如果出现故障，生成“救援”shell。

+   还有更多！

想象一下，你正在从事构建和维护新 Linux 发行版的业务。现在，在安装时，你的发行版的最终用户可能会决定用`reiserfs`文件系统格式化他们的 SCSI 磁盘（FYI，这是内核中最早的通用日志文件系统）。问题是，你无法预先知道最终用户会做出什么选择 - 它可能是任何一种文件系统。因此，你决定预先构建和提供大量的内核模块，几乎可以满足所有可能性。好吧，当安装完成并且用户的系统启动时，在这种情况下，内核将需要`reiserfs.ko`内核模块才能成功挂载根文件系统，从而继续系统启动。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/bafffd2d-09c5-4054-899f-5d44b6e34c76.png)

图 3.1 - 磁盘上的根文件系统尚未挂载，内核映像在 RAM 中

但是，请等一下，想想这个，我们现在有一个经典的*鸡和蛋问题*：为了使内核挂载根文件系统，它需要将`reiserfs.ko`内核模块文件加载到 RAM 中（因为它包含必要的代码，能够与文件系统一起工作）。*但是*，该文件本身嵌入在`reiserfs`根文件系统中；准确地说，在`/lib/modules/<kernel-ver>/kernel/fs/reiserfs/`目录中！（见图 3.1）。`initramfs`框架的主要目的之一是解决这个*鸡和蛋问题*。

`initramfs`镜像文件是一个压缩的`cpio`存档（`cpio`是`tar(1)`使用的平面文件格式）。正如我们在前一节中看到的，`update-initramfs`脚本在内部调用`mkinitramfs`脚本（至少在 Ubuntu 上是这样）。这些脚本构建一个包含内核模块以及支持基础设施（如`/etc`和`/lib`文件夹）的最小根文件系统，以简单的`cpio`文件格式，然后通常进行 gzip 压缩。现在形成了所谓的`initramfs`（或`initrd`）镜像文件，正如我们之前看到的，它将被放置在`/boot/initrd.img-<kernel-ver>`中。那么这有什么帮助呢？

在引导时，如果我们使用`initramfs`功能，引导加载程序将在其工作的一部分中将`initramfs`镜像文件加载到 RAM 中。接下来，当内核本身在系统上运行时，它会检测到`initramfs`镜像的存在，解压缩它，并使用其内容（通过脚本）将所需的内核模块加载到 RAM 中（图 3.2）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/dcdd1dc0-1a4f-443d-bd55-47620fdc281e.png)

图 3.2 - initramfs 镜像充当早期内核和实际根文件系统可用性之间的中间人

关于 x86 引导过程和 initramfs 镜像的更多细节可以在以下部分找到。

## 了解 x86 上的引导过程的基础知识

在下面的列表中，我们提供了关于 x86[_64]桌面（或笔记本电脑）、工作站或服务器上典型引导过程的简要概述：

1.  早期引导，POST，BIOS 初始化 - **BIOS**（即 x86 上的*固件*，简称**基本输入输出系统**）将第一个可引导磁盘的第一个扇区加载到 RAM 中，并跳转到其入口点。这形成了通常被称为*第一阶段*引导加载程序的东西，其主要工作是将*第二阶段（更大）引导加载程序*代码加载到内存并跳转到它。

1.  现在第二阶段引导加载程序代码接管了控制。它的主要工作是将实际（第三阶段）GRUB 引导加载程序*加载到内存并跳转到其入口点（GRUB 通常是 x86[-64]系统上使用的引导加载程序）

1.  引导加载程序将传递压缩的内核图像文件（`/boot/vmlinuz-<kernel-ver>`）以及压缩的`initramfs`图像文件（`/boot/initrd.img-<kernel-ver>`）作为参数。引导加载程序将（简单地）执行以下操作：

+   +   执行低级硬件初始化。

+   将这些图像加载到 RAM 中，对内核图像进行一定程度的解压缩。

+   它将*跳转到内核入口点*。

1.  Linux 内核现在控制着机器，将初始化硬件和软件环境。它不会对引导加载程序之前执行的工作做任何假设。

1.  在完成大部分硬件和软件初始化后，它注意到`initramfs`功能已经打开（`CONFIG_BLK_DEV_INITRD=y`）。因此，它将在 RAM 中定位（并且如果需要，解压缩）`initramfs`（`initrd`）图像（参见图 3.2）。

1.  然后，它将*将其*作为 RAM 中的临时根文件系统*挂载*。

1.  我们现在在内存中设置了一个基本的最小根文件系统。因此，`initrd`启动脚本现在运行，执行加载所需的内核模块到 RAM 中的任务（实际上是加载根文件系统驱动程序，包括在我们的场景中的`reiserfs.ko`内核模块；再次参见图 3.2）。

1.  然后，内核执行*pivot-root*，*卸载*临时的`initrd`根文件系统，释放其内存，并*挂载真正的根文件系统*；现在这是可能的，因为提供该文件系统支持的内核模块确实可用。

1.  一旦（实际的）根文件系统成功挂载，系统初始化就可以继续进行。内核继续，最终调用第一个用户空间进程，通常是`/sbin/init` PID `1`。

1.  *SysV **init*框架现在继续初始化系统，按照配置的方式启动系统服务。

需要注意的几点：

(a) 在现代 Linux 系统上，传统的（即：旧的）SysV *init*框架已经大部分被一个名为**systemd**的现代优化框架所取代。因此，在许多（如果不是大多数）现代 Linux 系统上，包括嵌入式系统，传统的`/sbin/init`已被`systemd`取代（或者是其可执行文件的符号链接）。在本章末尾的*进一步阅读*部分了解更多关于*systemd*的信息。

(b) 顺便说一句，本书不涵盖根文件系统本身的生成；作为一个简单的例子，我建议您查看我在第一章中提到的 SEALS 项目的代码（在[`github.com/kaiwan/seals`](https://github.com/kaiwan/seals)）；它有一个脚本，可以从头开始生成一个非常简单或“骨架”根文件系统。

现在您了解了`initrd`/`initramfs`背后的动机，我们将在下一节中深入了解`initramfs`。请继续阅读！

## 关于 initramfs 框架的更多信息

`initramfs`框架帮助的另一个地方是启动磁盘*加密*的计算机。在引导过程的早期阶段，内核将不得不询问用户密码，如果正确，就会继续挂载磁盘等。但是，请考虑一下：如果没有建立 C 运行时环境，即包含库、加载程序、所需的内核模块（可能是加密支持的内核模块）等的根文件系统，我们如何运行一个请求密码的 C 程序可执行文件？

请记住，内核*本身*尚未完成初始化；用户空间应用程序如何运行？再次，`initramfs`框架通过确实在内存中设置一个临时用户空间运行环境来解决这个问题，其中包含所需的根文件系统，包含库、加载程序、内核模块等。

我们可以验证吗？可以！让我们来看看`initramfs`映像文件。在 Ubuntu 上，`lsinitramfs(8)`脚本正好用于此目的（在 Fedora 上，相当应的脚本称为`lsinitrd`）：

```
$ lsinitramfs /boot/initrd.img-5.4.0-llkd01 | wc -l
334
$ lsinitramfs /boot/initrd.img-5.4.0-llkd01
.
kernel
kernel/x86
[...]
lib
lib/systemd
lib/systemd/network
lib/systemd/network/99-default.link
lib/systemd/systemd-udevd
[...]
lib/modules/5.4.0-llkd01/kernel/drivers/net/ethernet/intel/e1000/e1000.ko
lib/modules/5.4.0-llkd01/modules.dep
[...]
lib/x86_64-linux-gnu/libc-2.27.so
[...]
lib/x86_64-linux-gnu/libaudit.so.1
lib/x86_64-linux-gnu/ld-2.27.so
lib/x86_64-linux-gnu/libpthread.so.0
[...]
etc/udev/udev.conf
etc/fstab
etc/modprobe.d
[...]
bin/dmesg
bin/date
bin/udevadm
bin/reboot
[...]
sbin/fsck.ext4
sbin/dmsetup
sbin/blkid
sbin/modprobe
[...]
scripts/local-premount/resume
scripts/local-premount/ntfs_3g
$
```

里面有相当多的内容：我们截断输出以显示一些精选片段。显然，我们可以看到一个*最小*的根文件系统，支持所需的运行时库、内核模块、`/etc`、`/bin`和`/sbin`目录，以及它们的实用程序。

构建`initramfs`（或`initrd`）映像的细节超出了我们希望在这里涵盖的范围。我建议您查看这些脚本以揭示它们的内部工作（在 Ubuntu 上）：`/usr/sbin/update-initramfs`，这是`/usr/sbin/mkinitramfs` shell 脚本的包装脚本。有关更多信息，请参阅*进一步阅读*部分。

此外，现代系统通常具有所谓的混合`initramfs`：一个由早期`ramfs`映像和常规或主`ramfs`映像组成的`initramfs`映像。事实上，我们需要特殊的工具来解包/打包（解压缩/压缩）这些映像。Ubuntu 分别提供了`unmkinitramfs(8)`和`mkinitramfs(8)`脚本来执行这些操作。

作为一个快速实验，让我们将我们全新的`initramfs`映像（在上一节中生成的映像）解压到一个临时目录中。同样，这是在我们的 Ubuntu 18.04 LTS 虚拟机上执行的。使用`tree(1)`查看其输出以便阅读：

```
$ TMPDIR=$(mktemp -d)
$ unmkinitramfs /boot/initrd.img-5.4.0-llkd01 ${TMPDIR}
$ tree ${TMPDIR} | less
/tmp/tmp.T53zY3gR91
├── early
│   └── kernel
│       └── x86
│           └── microcode
│               └── AuthenticAMD.bin
└── main
    ├── bin
    │   ├── [
    │   ├── [[
    │   ├── acpid
    │   ├── ash
    │   ├── awk
[...]
  ├── etc
    │   ├── console-setup
    │   │   ├── cached_UTF-8_del.kmap.gz
[...]
   ├── init
   ├── lib
[...]
    │   ├── modules
    │   │   └── 5.4.0-llkd01
    │   │   ├── kernel
    │   │   │   └── drivers
[...]
    ├── scripts
    │   ├── functions
    │   ├── init-bottom
[...]
    └── var
        └── lib
            └── dhcp
$ 
```

这结束了我们对 x86 上`initramfs`框架和引导过程基础的（相当冗长的）讨论。好消息是，现在，掌握了这些知识，您可以通过根据需要调整`initramfs`映像来进一步定制产品-这是一项重要的技能！

例如（正如前面提到的），在现代系统中，*安全性*是一个关键因素，能够在块级别对磁盘进行加密是一个强大的安全功能；这在很大程度上涉及调整`initramfs`映像。 （再次强调，由于这超出了本书的范围，请参阅本章末尾的*进一步阅读*部分，以获取有关此内容和其他方面的有用链接。）

现在让我们通过对（x86）GRUB 引导加载程序的引导脚本进行一些简单的定制来完成内核构建。

# 第 7 步-定制 GRUB 引导加载程序

我们现在已经完成了第二章中概述的*步骤 1*至*6*，*从源代码构建 5.x Linux 内核-第一部分*，在*从源代码构建内核的步骤*部分。我们可以重新启动系统；当然，首先关闭所有应用程序和文件。默认情况下，现代**GRUB**（**GRand Unified** **Bootloader**）引导加载程序甚至在重新启动时都不会显示任何菜单；它将默认引导到新构建的内核（请记住，在这里，我们仅描述了 x86[_64]系统运行 Ubuntu 的这个过程）。

在 x86[_64]上，您可以在系统早期启动期间始终进入 GRUB 菜单。只需确保在启动过程中按住*Shift*键。

如果我们希望每次启动系统时都看到并定制 GRUB 菜单，从而可能选择要引导的备用内核/操作系统，该怎么办？在开发过程中，这通常非常有用，因此让我们看看如何做到这一点。

## 定制 GRUB-基础知识

定制 GRUB 非常容易。请注意以下内容：

+   以下步骤是在“目标”系统本身上执行的（而不是在主机上）；在我们的情况下，是 Ubuntu 18.04 虚拟机。

+   这已在我们的 Ubuntu 18.04 LTS 客户系统上进行了测试和验证。

以下是我们定制的一系列快速步骤：

1.  让我们安全起见，保留 GRUB 引导加载程序配置文件的备份副本：

```
sudo cp /etc/default/grub /etc/default/grub.orig

```

`/etc/default/grub`文件是涉及的用户配置文件。在编辑之前，为了安全起见，我们进行备份。这总是一个好主意。

1.  编辑它。您可以使用`vi(1)`或您选择的编辑器：

```
sudo vi /etc/default/grub 
```

1.  要始终在启动时显示 GRUB 提示符，请插入此行：

```
GRUB_HIDDEN_TIMEOUT_QUIET=false
```

在某些 Linux 发行版上，您可能会有`GRUB_TIMEOUT_STYLE=hidden`指令；只需将其更改为`GRUB_TIMEOUT_STYLE=menu`即可实现相同的效果。

1.  根据需要设置启动默认操作系统的超时时间（以秒为单位）；默认为`10`秒；请参阅以下示例：

```
GRUB_TIMEOUT=3
```

将上述超时值设置为以下值将产生以下结果：

+   `0`：立即启动系统，不显示菜单。

+   `-1`：无限等待。

此外，如果存在`GRUB_HIDDEN_TIMEOUT`指令，只需将其注释掉：

```
#GRUB_HIDDEN_TIMEOUT=1
```

1.  最后，以*root*身份运行`update-grub(8)`程序，使您的更改生效：

```
sudo update-grub
```

上述命令通常会导致`initramfs`镜像被刷新（重新生成）。完成后，您可以准备重新启动系统。不过等一下！接下来的部分将向您展示如何修改 GRUB 的配置，以便默认启动您选择的内核。

## 选择默认要启动的内核

GRUB 默认内核预设为数字零（通过`GRUB_DEFAULT=0`指令）。这将确保“第一个内核” - 最近添加的内核 - 默认启动（超时后）。这可能不是我们想要的；例如，在我们的 Ubuntu 18.04.3 LTS 虚拟机上，我们将其设置为默认的 Ubuntu *发行版内核*，就像之前一样，通过编辑`/etc/default/grub`文件（当然是作为 root 用户）：

```
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.0.0-36-generic"
```

当然，这意味着如果您的发行版被更新或升级，您必须再次手动更改上述行，以反映您希望默认启动的新发行版内核，然后运行`sudo update-grub`。

好了，我们新编辑的 GRUB 配置文件如下所示：

```
$ cat /etc/default/grub
[...]
#GRUB_DEFAULT=0
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.0.0-36-generic"
#GRUB_TIMEOUT_STYLE=hidden
GRUB_HIDDEN_TIMEOUT_QUIET=false
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
[...] 
```

与前一部分一样，不要忘记：如果您在这里进行任何更改，请运行`sudo update-grub`命令使更改生效。

需要注意的其他事项：

a) 此外，您可以添加“漂亮”的调整，比如通过`BACKGROUND_IMAGE="<img_file>"`指令来更改背景图片（或颜色）。

b) 在 Fedora 上，GRUB 引导程序配置文件有点不同；运行此命令以在每次启动时显示 GRUB 菜单：

`sudo grub2-editenv - unset menu_auto_hide` 详细信息可以在*Fedora wiki: Changes/HiddenGrubMenu*中找到：[`fedoraproject.org/wiki/Changes/HiddenGrubMenu`](https://fedoraproject.org/wiki/Changes/HiddenGrubMenu)。

c) 不幸的是，GRUB2（最新版本现在是 2）似乎在几乎每个 Linux 发行版上都有不同的实现方式，导致在尝试以一种特定的方式进行调整时出现不兼容性。

现在让我们重新启动虚拟机系统，进入 GRUB 菜单，并启动我们的新内核。

全部完成！让我们（终于！）重新启动系统：

```
$ sudo reboot
[sudo] password for llkd: 
```

一旦系统完成关机程序并重新启动，您应该很快就会看到 GRUB 引导程序菜单（下一部分还显示了几个屏幕截图）。一定要通过按任意键来中断它！

虽然总是可能的，但我建议您不要删除原始的发行版内核镜像（以及相关的`initrd`、`System.map`文件等）。如果您全新的内核无法启动呢？（*如果泰坦尼克号都会发生...*）通过保留我们的原始镜像，我们就有了备用选项：从原始发行版内核启动，解决我们的问题，并重试。

作为最坏的情况，如果所有其他内核/`initrd`镜像都已被删除，您的单个新内核无法成功启动呢？好吧，您总是可以通过 USB 闪存驱动器引导到*恢复模式*的 Linux；关于这方面的一些搜索将产生许多链接和视频教程。

## 通过 GNU GRUB 引导程序引导我们的虚拟机

现在我们的虚拟机客人（使用*Oracle VirtualBox hypervisor*）即将启动； 一旦它（模拟的）BIOS 例程完成，GNU GRUB 引导加载程序屏幕首先显示出来。 这是因为我们故意将`GRUB_HIDDEN_TIMEOUT_QUIET` GRUB 配置指令更改为`false`。 请参阅以下截图（图 3.3）。 截图中看到的特定样式是 Ubuntu 发行版自定义的样式：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/913f5b6d-b473-4b43-a0c7-0ae382644d81.png)

图 3.3 - GRUB2 引导加载程序 - 在系统启动时暂停

现在让我们直接引导我们的虚拟机：

1.  按下任何键盘键（除了*Enter*）以确保默认内核在超时（回想一下，我们将其设置为 3 秒）到期后不会引导。

1.  如果还没有到达那里，请滚动到`Ubuntu 的高级选项`菜单，将其突出显示，然后按*Enter*。

1.  现在你会看到一个类似的菜单，但可能不完全相同，如下截图（图 3.4）。 对于 GRUB 检测到并可以引导的每个内核，都显示了两行 - 一个是内核本身，另一个是进入相同内核的特殊恢复模式引导选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/f422bfa0-21b2-4f03-84d9-7891f9f3a522.png)

图 3.4 - GRUB2 引导加载程序显示可引导的内核

注意默认引导的内核 - 在我们的情况下，默认高亮显示了`5.0.0-36-generic`内核，带有一个星号（`*`）。

前面的截图显示了一些“额外”的行项目。 这是因为在拍摄这张截图时，我已经更新了虚拟机，因此还安装了一些更新的内核。 我们可以看到`5.0.0-37-generic`和`5.3.0-26-generic`内核。 没关系； 我们在这里忽略它们。

1.  无论如何，只需滚动到感兴趣的条目，也就是`5.4.0-llkd01`内核条目。 在这里，它是 GRUB 菜单的第一行（因为它是可引导操作系统的 GRUB 菜单的最新添加）：`Ubuntu, with Linux 5.4.0-llkd01`。

1.  一旦你突出显示了前面的菜单项，按*Enter*，完成！ 引导加载程序将继续执行它的工作，将内核映像和`initrd`映像解压缩并加载到 RAM 中，并跳转到 Linux 内核的入口点，从而将控制权交给 Linux！

好了，如果一切顺利，就像应该的那样，你将成功引导到全新构建的 5.4.0 Linux 内核！ 祝贺你完成了一项出色的任务。 再说一遍，你可以做得更多 - 以下部分将向你展示如何在运行时（引导时）进一步编辑和自定义 GRUB 的配置。 再次，这种技能偶尔会派上用场 - 例如，*忘记了 root 密码？* 是的，确实，你实际上可以使用这种技术*绕过它*！ 继续阅读以了解详情。

## 尝试使用 GRUB 提示

你可以进一步进行实验； 而不仅仅是在`Ubuntu, with Linux 5.4.0-llkd01`内核的菜单条目上按*Enter*，确保突出显示此行并按`e`键（进行编辑）。 现在我们将进入 GRUB 的*编辑屏幕*，在这里我们可以自由更改任何值。 这是按下*e*键后的截图：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/80e582a1-ba49-492a-93b3-b708e8a0cb57.png)

图 3.5 - GRUB2 引导加载程序 - 自定义 5.4.0-llkd01 内核的详细信息

这个截图是在向下滚动几行后拍摄的； 仔细看，你可以在编辑框底部的第三行的开头处看到光标（一个下划线状的， "**`_`**"）。 这是关键的一行； 它以适当缩进的关键字`linux`开头。 它指定通过 GRUB 引导加载程序传递给 Linux 内核的*内核参数*列表。

尝试在这里做一些实验。 举个简单的例子，从这个条目中删除单词`quiet`和`splash`，然后按*Ctrl* + *X*或*F10*进行引导。 这一次，漂亮的 Ubuntu 启动画面不会出现； 你直接在控制台中看到所有内核消息闪过。

一个常见的问题：如果我们忘记了密码，因此无法登录怎么办？有几种方法可以解决这个问题。其中一种是通过引导加载程序：像我们一样进入 GRUB 菜单，转到相关的菜单项，按*e*进行编辑，滚动到以单词`linux`开头的行，并在此条目的末尾添加单词`single`（或只是数字`1`），使其看起来像这样：

```
               linux       /boot/vmlinuz-5.0.0-36-generic \ root=UUID=<...> ro quiet splash single
```

现在，当您启动时，内核将以单用户模式启动，并为您，永远感激的用户，提供具有 root 访问权限的 shell。只需运行`passwd <username>`命令来更改您的密码。

进入单用户模式的确切过程因发行版而异。在 Red Hat/Fedora/CentOS 上编辑 GRUB2 菜单的确切内容与其他发行版有些不同。请参阅*进一步阅读*部分，了解如何为这些系统设置的链接。

这教会了我们一些关于*安全*的东西，不是吗？当可以在没有密码的情况下访问引导加载程序菜单（甚至是 BIOS）时，系统被认为是不安全的！事实上，在高度安全的环境中，甚至必须限制对控制台设备的物理访问。

现在您已经学会了如何自定义 GRUB 引导加载程序，并且我期望您已经启动到了新的 5.4 Linux 内核！让我们不要假设，让我们验证内核是否确实按照我们的计划配置。

# 验证我们新内核的配置

好的，回到我们的讨论：我们现在已经启动到我们新构建的内核中。但是等等，让我们不要盲目地假设，让我们实际验证一下是否一切都按计划进行。*经验主义方法*总是最好的：

```
$ uname -r
5.4.0-llkd01
```

事实上，我们现在正在我们刚构建的**5.4.0** Linux 内核上运行 Ubuntu 18.04.3 LTS！

回想一下我们在第二章中编辑的内核配置表，*从源代码构建 5.x Linux 内核-第一部分*，在*表 2.4*中。我们应该逐行检查我们已经更改的每个配置是否实际生效。让我们列出其中一些，从关注的`CONFIG_'FOO'`名称开始，如下所示：

+   `CONFIG_LOCALVERSION`：`uname -r`的前面输出清楚地显示了内核版本的`localversion`（或`-EXTRAVERSION`）部分已经设置为我们想要的`-llkd01`字符串。

+   `CONFIG_IKCONFIG`：允许我们查看当前内核配置的详细信息。让我们检查一下。请记住，您需要将`LLKD_KSRC`环境变量设置为您的 5.4 内核源代码树目录的根位置：

```
$ ${LLKD_KSRC}/scripts/extract-ikconfig /boot/vmlinuz-5.4.0-llkd01
#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 5.4.0 Kernel Configuration
[...]
CONFIG_IRQ_WORK=y
[...]
```

它奏效了！我们可以通过`scripts/extract-ikconfig`脚本看到整个内核配置。我们将使用这个脚本来`grep(1)`我们在上述*表 2.4*中更改的其余配置指令：

```
$ scripts/extract-ikconfig /boot/vmlinuz-5.4.0-llkd01 | egrep "IKCONFIG|HAMRADIO|PROFILING|VBOXGUEST|UIO|MSDOS_FS|SECURITY|DEBUG_STACK_USAGE"
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
# CONFIG_PROFILING is not set
# CONFIG_HAMRADIO is not set
CONFIG_UIO=m
# CONFIG_UIO_CIF is not set
CONFIG_UIO_PDRV_GENIRQ=m
# CONFIG_UIO_DMEM_GENIRQ is not set
[...]
CONFIG_VBOXGUEST=m
CONFIG_EXT4_FS_SECURITY=y
CONFIG_MSDOS_FS=m
# CONFIG_SECURITY_DMESG_RESTRICT is not set
# CONFIG_SECURITY is not set
CONFIG_SECURITYFS=y
CONFIG_DEFAULT_SECURITY_DAC=y
CONFIG_DEBUG_STACK_USAGE=y
$ 
```

仔细查看前面的输出，我们可以看到我们确实得到了我们想要的结果。我们的新内核配置设置与第二章中*从源代码构建 5.x Linux 内核-第一部分*，*表 2.4*中预期的设置完全匹配；完美。

或者，由于我们启用了`CONFIG_IKCONFIG_PROC`选项，我们可以通过查找（压缩的）`proc`文件系统条目`/proc/config.gz`来实现相同的验证，就像这样：

```
gunzip -c /proc/config.gz | egrep \ "IKCONFIG|HAMRADIO|PROFILING|VBOXGUEST|UIO|MSDOS_FS|SECURITY|DEBUG_STACK_USAGE"
```

所以，内核构建完成了！太棒了。我建议您回到第二章，*从源代码构建 5.x Linux 内核-第一部分*，在*从源代码构建内核的步骤*部分，再次查看整个过程的高级概述。我们将以树莓派设备内核的有趣*交叉编译*和一些剩余的提示结束本章。

# 树莓派的内核构建

一个受欢迎且相对便宜的**单板计算机**（**SBC**）用于实验和原型设计是基于 ARM 的树莓派。爱好者和改装者发现它非常有用，可以尝试并学习如何使用嵌入式 Linux，特别是因为它有强大的社区支持（有许多问答论坛）和良好的支持：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-krn-prog/img/4dbca72e-6589-4a88-98cc-318889ef8367.png)

图 3.6-树莓派 3 型 B+设备（请注意，照片中看到的 USB 转串口电缆不随设备一起提供）

有两种方式可以为目标设备构建内核：

+   在功能强大的主机系统上构建内核，通常是运行 Linux 发行版的 Intel/AMD x86_64（或 Mac）台式机或笔记本电脑。

+   在目标设备本身上进行构建。

我们将遵循第一种方法-它更快，被认为是执行嵌入式 Linux 开发的正确方法。

我们假设（像往常一样）我们正在运行我们的 Ubuntu 18.04 LTS 虚拟机。所以，想想看；现在，主机系统实际上是嵌入式 Linux 虚拟机！此外，我们的目标是为 ARM 32 位架构构建内核，而不是 64 位。

在虚拟机上执行大型下载和内核构建操作并不是理想的。根据主机和客户端的功率和 RAM，这将需要一段时间。它可能会比在本机 Linux 框上构建慢两倍。尽管如此，假设您在客户端设置了足够的磁盘空间（当然主机实际上有这个空间可用），这个过程是有效的。

我们将不得不使用*x86_64 到 ARM（32 位）交叉编译器*来构建内核，或者为树莓派目标构建任何组件。这意味着还需要安装适当的**交叉工具链**来执行构建。

在接下来的几个部分中，我们将工作分为三个离散的步骤：

1.  为设备获取适当的内核源树

1.  学习如何安装适当的交叉工具链

1.  配置和构建内核

那么让我们开始吧！

## 第 1 步-克隆内核源树

我们任意选择一个*暂存文件夹*（构建发生的地方）用于内核源树和交叉工具链，并将其分配给一个环境变量（以避免硬编码）：

1.  设置您的工作空间。我们将一个环境变量设置为`RPI_STG`（不需要使用这个环境变量的确切名称；只需选择一个合理的名称并坚持使用）到暂存文件夹的位置-我们将在那里进行工作。随时使用适合您系统的值：

```
export RPI_STG=~/rpi_work
mkdir -p ${RPI_STG}/kernel_rpi ${RPI_STG}/rpi_tools
```

确保您有足够的磁盘空间可用：内核源树大约占用 900 MB，工具链大约占用 1.5 GB。您至少需要另外一千兆字节的工作空间。

1.  下载树莓派内核源树（我们从官方源克隆，树莓派 GitHub 内核树库，链接：[`github.com/raspberrypi/linux/`](https://github.com/raspberrypi/linux/)）：

```
cd ${RPI_STG}/kernel_rpi
git clone --depth=1 --branch rpi-5.4.y https://github.com/raspberrypi/linux.git
```

内核源树被克隆到一个名为`linux/`的目录下（即`${RPI_WORK}/kernel_rpi/linux`）。请注意，在前面的代码中，我们有以下内容：

+   我们选择的特定树莓派内核树分支*不是*最新的（在撰写本文时，最新的是 5.11 系列），它是 5.4 内核；这完全没问题（它是 LTS 内核，也与我们的 x86 内核匹配！）。

+   我们将`--depth`参数设置为`1`传递给`git clone`以减少下载和解压负载。

现在树莓派内核源已安装。让我们简要验证一下：

```
$ cd ${RPI_STG}/kernel_rpi/linux ; head -n5 Makefile
# SPDX-License-Identifier: GPL-2.0
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 51
EXTRAVERSION =
```

好的，这是 5.4.51 树莓派内核端口（我们在 x86_64 上使用的内核版本是 5.4.0；轻微的变化没问题）。

## 第 2 步-安装交叉工具链

现在是时候在您的主机系统上安装适用于执行实际构建的*交叉工具链*。事实上，有几个可用的工作工具链...在这里，我将展示两种获取和安装工具链的方法。第一种是最简单的，通常足够了，而第二种方法安装了一个更复杂的版本。

### 第一种方法-通过 apt 包安装

这非常简单且效果很好；通常使用这种方法：

```
sudo apt install ​crossbuild-essential-armhf
```

工具通常安装在`/usr/bin/`下，因此已经包含在您的`PATH`中；您可以直接使用它们。例如，检查 ARM-32 `gcc`编译器的位置和版本如下：

```
$ which arm-linux-gnueabihf-gcc
/usr/bin/arm-linux-gnueabihf-gcc
$ arm-linux-gnueabihf-gcc --version |head -n1
arm-linux-gnueabihf-gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

此外，请记住：此工具链适用于构建 ARM 32 位架构的内核，而不适用于 64 位架构。如果您的意图是构建 64 位架构（这里我们不涉及），您将需要安装一个 x86_64 到 ARM64 的工具链，使用`sudo apt install crossbuild-essential-arm64`。

### 第二种方法-通过源代码库安装

这是一种更复杂的方法。在这里，我们从树莓派的 GitHub 存储库克隆工具链：

1.  下载工具链。让我们将其放在名为`rpi_tools`的文件夹中，放在我们的树莓派分期目录中：

```
cd ${RPI_STG}/rpi_tools
git clone https://github.com/raspberrypi/tools
```

1.  更新`PATH`环境变量，使其包含工具链二进制文件：

```
export PATH=${PATH}:${RPI_STG}/rpi_tools/tools/arm-bcm2708/arm-linux-gnueabihf/bin/

```

设置`PATH`环境变量（如前面的代码所示）是必需的。但是，它只对当前的 shell 会话有效。通过将前面的行放入启动脚本（通常是您的`${HOME}/.bashrc`文件或等效文件）使其永久化。

如前所述，也可以使用其他工具链。例如，ARM 开发（A 型处理器）的几个工具链可在 ARM 开发者网站上找到。

## 第 3 步-配置和构建内核

让我们配置内核（适用于树莓派 2、3 和 3[B]+）。在开始之前，*非常重要*要记住以下内容：

+   **`ARCH`**环境变量应设置为要进行交叉编译的 CPU（架构），即编译后的代码将在该 CPU 上运行。要设置`ARCH`的值，是内核源树中`arch/`目录下的目录名称。例如，将`ARCH`设置为`arm`用于 ARM32，`arm64`用于 ARM64，`powerpc`用于 PowerPC，`openrisc`用于 OpenRISC 处理器。

+   **`CROSS_COMPILE`**环境变量应设置为交叉编译器（工具链）的前缀。基本上，它是在工具链中每个实用程序之前的前几个常见字母。在我们的下面的示例中，所有工具链实用程序（C 编译器`gcc`，链接器，C++，`objdump`等）都以`arm-linux-gnueabihf-`开头，因此我们将`CROSS_COMPILE`设置为这个。`Makefile`将始终调用实用程序为`${CROSS_COMPILE}<utility>`，因此调用正确的工具链可执行文件。这意味着工具链目录应该在`PATH`变量中（正如我们在前面的部分中提到的）。

好的，让我们构建内核：

```
cd ${RPI_STG}/kernel_rpi/linux
make mrproper
KERNEL=kernel7
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2709_defconfig
```

关于配置目标`bcm2709_defconfig`的简要说明：这一关键点在第二章中提到，*从源代码构建 5.x Linux 内核-第一部分*。我们必须确保使用适当的特定于板的内核配置文件作为起点。在这里，这是树莓派 2、树莓派 3、树莓派 3+和计算模块 3 设备上 Broadcom SoC 的正确内核配置文件。指定的`bcm2709_defconfig`配置目标会解析`arch/arm/configs/bcm2709_defconfig`文件的内容。（树莓派网站将其文档化为适用于树莓派 2、树莓派 3、树莓派 3+和计算模块 3 默认构建配置的`bcm2709_defconfig`。重要提示：如果您为其他类型的树莓派设备构建内核，请参阅[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)。）

顺便说一句，`kernel7`的值是这样的，因为处理器是基于 ARMv7 的（实际上，从树莓派 3 开始，SoC 是 64 位 ARMv8，兼容在 32 位 ARMv7 模式下运行；在这里，因为我们正在为 ARM32（AArch32）构建 32 位内核，我们指定`KERNEL=kernel7`）。

SoCs 的种类、它们的封装以及它们的命名方式造成了很多混乱；这个链接可能会有所帮助：[`raspberrypi.stackexchange.com/questions/840/why-is-the-cpu-sometimes-referred-to-as-bcm2708-sometimes-bcm2835`](https://raspberrypi.stackexchange.com/questions/840/why-is-the-cpu-sometimes-referred-to-as-bcm2708-sometimes-bcm2835)。

如果需要对内核配置进行任何进一步的定制，您可以使用以下方法：

```
make ARCH=arm menuconfig
```

如果不需要，可以跳过此步骤并继续。使用以下方法构建（交叉编译）内核、内核模块和 DTB：

```
make -j4 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
```

（根据您的构建主机适当调整`-jn`）。一旦构建成功完成，我们可以看到生成了以下文件：

```
$ ls -lh vmlinux System.map arch/arm/boot/zImage
-rwxrwxr-x 1 llkd llkd  5.3M Jul 23 12:58 arch/arm/boot/zImage
-rw-rw-r-- 1 llkd llkd  2.5M Jul 23 12:58 System.map
-rwxrwxr-x 1 llkd llkd   16M Jul 23 12:58 vmlinux
$ 
```

在这里，我们的目的只是展示 Linux 内核如何配置和构建为不同于编译主机的架构，或者换句话说，进行交叉编译。关于将内核映像（和 DTB 文件）放在 microSD 卡上等细节不在此讨论范围内。我建议您查阅树莓派内核构建的完整文档，可以在这里找到：[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)。

尽管如此，这里有一个快速提示，可以在树莓派 3[B+]上尝试新内核：

1.  挂载 microSD 卡。通常会有一个 Raspbian 发行版和两个分区，`boot`和`rootfs`，分别对应`mmcblk0p1`和`mmcblk0p2`分区。

1.  **引导加载程序和相关二进制文件**：关键是将低级启动二进制文件，包括引导加载程序本身，放到 SD 卡的引导分区上；这包括`bootcode.bin`（实际的引导加载程序）、`fixup*.dat`和`start*.elf`二进制文件；`/boot`文件夹的内容在这里解释：[`www.raspberrypi.org/documentation/configuration/boot_folder.md`](https://www.raspberrypi.org/documentation/configuration/boot_folder.md)。（如果您不确定如何获取这些二进制文件，最简单的方法可能是在 SD 卡上安装一个标准版本的树莓派 OS；这些二进制文件将被安装在其引导分区内。标准的树莓派 OS 镜像可以从[`www.raspberrypi.org/downloads/`](https://www.raspberrypi.org/downloads)获取；另外，新的 Raspberry Pi Imager 应用程序（适用于 Windows、macOS、Linux）使得首次安装变得非常容易）。

1.  如果存在，备份并用我们刚刚构建的`zImage`文件替换 microSD 卡上`/boot`分区内的`kernel7.img`文件，命名为`kernel7.img`。

1.  安装刚构建的内核模块；确保您将位置指定为 microSD 卡的根文件系统，使用`INSTALL_MOD_PATH`环境变量！（未这样做可能会覆盖主机的模块，这将是灾难性的！）在这里，我们假设 microSD 卡的第二个分区（其中包含根文件系统）被挂载在`/media/${USER}/rootfs`下；然后，执行以下操作（一行内全部执行）：

```
sudo env PATH=$PATH make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-  INSTALL_MOD_PATH=/media/${USER}/rootfs modules_install
```

1.  在 SD 卡上安装刚生成的 DTB（和叠加）：

```
sudo cp arch/arm/boot/dts/*.dtb /media/${USER}/boot
sudo cp arch/arm/boot/dts/overlays/*.dtb* arch/arm/boot/dts/overlays/README /media/${USER}/boot/overlays
sync 
```

1.  卸载 SD 卡，重新插入设备，然后尝试。

再次，为了确保它能正常工作，请参考官方文档（可在[`www.raspberrypi.org/documentation/linux/kernel/building.md`](https://www.raspberrypi.org/documentation/linux/kernel/building.md)找到）。我们没有涵盖有关生成和复制内核模块和 DTB 到 microSD 卡的详细信息。

另外，值得一提的是，我们在第十一章中再次讨论了树莓派的内核配置和构建，*CPU 调度器-第二部分*。

这完成了我们对树莓派内核交叉编译的简要介绍。我们将以一些杂项但仍然有用的提示结束本章。

# 内核构建的杂项提示

我们以一些提示结束了从源代码构建 Linux 内核的本章。以下各小节都包含了您需要注意的提示。

对于新手来说，经常会感到困惑的一点是：一旦我们配置、构建并从新的 Linux 内核引导，我们会注意到根文件系统和任何其他挂载的文件系统仍然与原始（发行版或自定义）系统上的相同。只有内核本身发生了变化。这是完全有意的，因为 Unix 范式要求内核和根文件系统之间*松散耦合*。由于根文件系统包含所有应用程序、系统工具和实用程序，包括库，实际上，我们可以为相同的基本系统拥有几个内核，以适应不同的产品风格。

## 最低版本要求

要成功构建内核，您必须确保您的构建系统具有工具链（和其他杂项工具和实用程序）的文档化的*最低版本*。这些信息清楚地在内核文档的*编译内核的最低要求*部分中，可在[ ](https://github.com/torvalds/linux/blob/master/Documentation/process/changes.rst#minimal-requirements-to-compile-the-kernel)[`github.com/torvalds/linux/blob/master/Documentation/process/changes.rst#minimal-requirements-to-compile-the-kernel`](https://github.com/torvalds/linux/blob/master/Documentation/process/changes.rst#minimal-requirements-to-compile-the-kernel)找到。

例如，在撰写本文时，推荐的`gcc`最低版本为 4.9，`make`的最低版本为 3.81。

## 为其他站点构建内核

在本书的内核构建步骤中，我们在某个系统上（这里是一个 x86_64 客户机）构建了 Linux 内核，并从同一系统上引导了新构建的内核。如果情况不是这样，比如当您为另一个站点或客户现场构建内核时，经常会发生什么？虽然始终可以在远程系统上手动放置这些部件，但有一种更简单和更正确的方法——将内核和相关的元工作（`initrd`镜像、内核模块集合、内核头文件等）打包成一个众所周知的**软件包格式**（Debian 的`deb`、Red Hat 的`rpm`等）！在内核的顶层`Makefile`上快速输入`help`命令，就会显示这些软件包目标：

```
$ make help
[ ... ]
Kernel packaging:
 rpm-pkg - Build both source and binary RPM kernel packages
 binrpm-pkg - Build only the binary kernel RPM package
 deb-pkg - Build both source and binary deb kernel packages
 bindeb-pkg - Build only the binary kernel deb package
 snap-pkg - Build only the binary kernel snap package (will connect to external hosts)
 tar-pkg - Build the kernel as an uncompressed tarball
 targz-pkg - Build the kernel as a gzip compressed tarball
 tarbz2-pkg - Build the kernel as a bzip2 compressed tarball
 tarxz-pkg - Build the kernel as a xz compressed tarball
[ ... ]
```

因此，例如，要构建内核及其关联文件作为 Debian 软件包，只需执行以下操作：

```
$ make -j8 bindeb-pkg
scripts/kconfig/conf --syncconfig Kconfig
sh ./scripts/package/mkdebian
dpkg-buildpackage -r"fakeroot -u" -a$(cat debian/arch) -b -nc -uc
dpkg-buildpackage: info: source package linux-5.4.0-min1
dpkg-buildpackage: info: source version 5.4.0-min1-1
dpkg-buildpackage: info: source distribution bionic
[ ... ]
```

实际的软件包被写入到紧挨着内核源目录的目录中。例如，从我们刚刚运行的命令中，这里是生成的`deb`软件包：

```
$ ls -l ../*.deb
-rw-r--r-- 1 kaiwan kaiwan 11106860 Feb 19 17:05 ../linux-headers-5.4.0-min1_5.4.0-min1-1_amd64.deb
-rw-r--r-- 1 kaiwan kaiwan 8206880 Feb 19 17:05 ../linux-image-5.4.0-min1_5.4.0-min1-1_amd64.deb
-rw-r--r-- 1 kaiwan kaiwan 1066996 Feb 19 17:05 ../linux-libc-dev_5.4.0-min1-1_amd64.deb
```

这确实非常方便！现在，你可以在任何其他匹配的（在 CPU 和 Linux 版本方面）系统上直接安装软件包，只需使用简单的`dpkg -i <package-name>`命令。

## 观看内核构建运行

在内核构建运行时查看详细信息（`gcc(1)`编译器标志等），将**`V=1`**详细选项开关传递给`make(1)`。以下是在设置为*on*的详细开关下构建 Raspberry Pi 3 内核时的一些示例输出：

```
$ make V=1 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
[...]
make -f ./scripts/Makefile.build obj=kernel/sched
arm-linux-gnueabihf-gcc -Wp,-MD,kernel/sched/.core.o.d 
 -nostdinc 
 -isystem <...>/gcc-linaro-7.3.1-2018.05-x86_64_arm-linux-gnueabihf/bin/../lib/gcc/arm-linux-gnueabihf/7.3.1/include 
 -I./arch/arm/include -I./arch/arm/include/generated/uapi 
 -I./arch/arm/include/generated -I./include 
 -I./arch/arm/include/uapi -I./include/uapi 
 -I./include/generated/uapi -include ./include/linux/kconfig.h 
 -D__KERNEL__ -mlittle-endian -Wall -Wundef -Wstrict-prototypes 
 -Wno-trigraphs -fno-strict-aliasing -fno-common 
 -Werror-implicit-function-declaration -Wno-format-security 
 -std=gnu89 -fno-PIE -fno-dwarf2-cfi-asm -fno-omit-frame-pointer 
 -mapcs -mno-sched-prolog -fno-ipa-sra -mabi=aapcs-linux 
 -mno-thumb-interwork -mfpu=vfp -funwind-tables -marm 
 -D__LINUX_ARM_ARCH__=7 -march=armv7-a -msoft-float -Uarm 
 -fno-delete-null-pointer-checks -Wno-frame-address 
 -Wno-format-truncation -Wno-format-overflow 
 -Wno-int-in-bool-context -O2 --param=allow-store-data-races=0 
 -DCC_HAVE_ASM_GOTO -Wframe-larger-than=1024 -fno-stack-protector 
 -Wno-unused-but-set-variable -Wno-unused-const-variable 
 -fno-omit-frame-pointer -fno-optimize-sibling-calls 
 -fno-var-tracking-assignments -pg -Wdeclaration-after-statement 
 -Wno-pointer-sign -fno-strict-overflow -fno-stack-check 
 -fconserve-stack -Werror=implicit-int -Werror=strict-prototypes 
 -Werror=date-time -Werror=incompatible-pointer-types 
 -fno-omit-frame-pointer -DKBUILD_BASENAME='"core"' 
 -DKBUILD_MODNAME='"core"' -c -o kernel/sched/.tmp_core.o  
 kernel/sched/core.c
[...]
```

请注意，我们通过插入新行和突出显示一些开关，使前面的输出更加易读。这种细节可以帮助调试构建失败的情况。

## 构建过程的快捷 shell 语法

一个快捷的 shell（通常是 Bash）语法到构建过程（假设内核配置步骤已完成）可能是以下示例，用于非交互式构建脚本：

```
time make -j4 [ARCH=<...> CROSS_COMPILE=<...>] all && sudo make modules_install && sudo make install
```

在上面的代码中，**`&&`**和**`||`**元素是 shell（Bash）的便利条件列表语法：

+   `cmd1 && cmd2`意味着：只有在`cmd1`成功运行时才运行`cmd2`。

+   `cmd1 || cmd2`意味着：只有在`cmd1`失败时才运行`cmd2`。

## 处理编译器开关问题

很久以前，2016 年 10 月，当尝试为 x86_64 构建一个（较旧的 3.x）内核时，我遇到了以下错误：

```
$ make
[...]
CC scripts/mod/empty.o
scripts/mod/empty.c:1:0: error: code model kernel does not support PIC mode
/* empty file to figure out endianness / word size */
[...]
```

事实证明，这根本不是内核问题。相反，这是 Ubuntu 16.10 上的编译器开关问题：`gcc(1)`默认坚持使用`-fPIE`（其中**PIE**缩写为**Position Independent Executable**）标志。在较旧的内核的 Makefile 中，我们需要关闭这个选项。这个问题已经解决了。

这个关于*AskUbuntu*网站上的 Q&A，关于*Kernel doesn't support PIC mode for compiling?*，描述了如何做到这一点：[`askubuntu.com/questions/851433/kernel-doesnt-support-pic-mode-for-compiling`](https://askubuntu.com/questions/851433/kernel-doesnt-support-pic-mode-for-compiling)。

（有趣的是，在前面的*Watching the kernel build run*部分，使用最近的内核时，构建确实使用了**`-fno-PIE`**编译器开关。）

## 处理缺少的 OpenSSL 开发头文件

有一次，在 Ubuntu 上的 x86_64 内核构建失败，出现了以下错误：

```
[...] fatal error: openssl/opensslv.h: No such file or directory
```

这只是缺少 OpenSSL 开发头文件的情况；这在这里的*Minimal requirements to compile the kernel*文档中清楚地提到：[`github.com/torvalds/linux/blob/master/Documentation/process/changes.rst#openssl`](https://github.com/torvalds/linux/blob/master/Documentation/process/changes.rst#openssl)。具体来说，它提到从 v4.3 及更高版本开始，需要`openssl`开发包。 

FYI，这个 Q&A 也展示了如何安装`openssl-devel`软件包（或等效的；例如，在 Raspberry Pi 上，需要安装`libssl-dev`软件包）来解决这个问题：*OpenSSL missing during ./configure. How to fix?*，可在[`superuser.com/questions/371901/openssl-missing-during-configure-how-to-fix`](https://superuser.com/questions/371901/openssl-missing-during-configure-how-to-fix)找到。

实际上，在一个纯净的 x86_64 *Fedora 29*发行版上也发生了完全相同的错误：

```
make -j4
[...]
HOSTCC scripts/sign-file
scripts/sign-file.c:25:10: fatal error: openssl/opensslv.h: No such file or directory
 #include <openssl/opensslv.h>
 ^~~~~~~~~~~~~~~~~~~~
compilation terminated.
make[1]: *** [scripts/Makefile.host:90: scripts/sign-file] Error 1
make[1]: *** Waiting for unfinished jobs....
make: *** [Makefile:1067: scripts] Error 2
make: *** Waiting for unfinished jobs....
```

修复方法如下：

```
sudo dnf install openssl-devel-1:1.1.1-3.fc29
```

最后，请记住一个几乎可以保证成功的方法：当你遇到那些你*无法解决*的构建和/或引导错误时：将确切的错误消息复制到剪贴板中，转到 Google（或其他搜索引擎），并输入类似于`linux kernel build <ver ...> fails with <paste-your-error-message-here>`。你可能会惊讶地发现这有多么有帮助。如果没有，要认真地进行研究，如果你真的找不到任何相关/正确的答案，就在适当的论坛上发布你的（深思熟虑的）问题。

存在几个 Linux“构建器”项目，这些项目是用于构建整个 Linux 系统或发行版的复杂框架（通常用于嵌入式 Linux 项目）。截至撰写本文时，***Yocto***（[`www.yoctoproject.org/`](https://www.yoctoproject.org/)）被认为是行业标准的 Linux 构建器项目，而***Buildroot***（[`buildroot.org/`](https://buildroot.org/)）是一个更老但得到很好支持的项目；它们确实值得一看。

# 总结

本章以及前一章详细介绍了如何从源代码构建 Linux 内核。我们从实际的内核（和内核模块）构建过程开始。构建完成后，我们展示了如何将内核模块安装到系统上。然后我们继续讨论了生成`initramfs`（或`initrd`）镜像的实际操作，并解释了背后的动机。内核构建的最后一步是（简单的）自定义引导加载程序（这里，我们只关注 x86 GRUB）。然后我们展示了如何通过新构建的内核引导系统，并验证其配置是否符合预期。作为一个有用的附加功能，我们还展示了如何为另一个处理器（在这种情况下是 ARM）交叉编译 Linux 内核的基础知识。最后，我们分享了一些额外的提示，以帮助你进行内核构建。

再次强调，如果你还没有这样做，我们建议你仔细审查并尝试这里提到的程序，并构建自己的定制 Linux 内核。

因此，恭喜你成功地从头开始构建了一个 Linux 内核！你可能会发现，在实际项目（或产品）中，你可能*不需要*像我们努力地仔细展示的那样执行内核构建过程的每一步。为什么呢？原因之一是可能会有一个单独的 BSP 团队负责这个方面；另一个原因 - 在嵌入式 Linux 项目中尤其可能，是正在使用像*Yocto*（或*Buildroot*）这样的 Linux 构建框架。Yocto 通常会处理构建的机械方面。*然而*，你真的需要能够根据项目要求*配置*内核；这仍然需要在这里获得的知识和理解。

接下来的两章将带你深入了解 Linux 内核开发世界，向你展示如何编写你的第一个内核模块。

# 问题

最后，这里有一些问题供你测试对本章材料的了解：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/questions)。你会发现其中一些问题的答案在本书的 GitHub 存储库中：[`github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn`](https://github.com/PacktPublishing/Linux-Kernel-Programming/tree/master/solutions_to_assgn)。

# 进一步阅读

为了帮助你深入学习这个主题，我们在本书的 GitHub 存储库中提供了一个相当详细的在线参考和链接列表（有时甚至包括书籍）的 Further reading 文档。*Further reading*文档在这里可用：[`github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md`](https://github.com/PacktPublishing/Linux-Kernel-Programming/blob/master/Further_Reading.md)。
