# 精通 Linux 嵌入式编程（一）

> 原文：[`zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814`](https://zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

嵌入式系统是一种内部带有计算机的设备，看起来不像计算机。洗衣机、电视、打印机、汽车、飞机和机器人都由某种类型的计算机控制，在某些情况下甚至不止一个。随着这些设备变得更加复杂，以及我们对它们的期望不断扩大，控制它们的强大操作系统的需求也在增长。越来越多的情况下，Linux 是首选的操作系统。

Linux 的力量来自于其鼓励代码共享的开源模式。这意味着来自许多不同背景的软件工程师，通常是竞争公司的雇员，可以合作创建一个最新的操作系统内核，并跟踪硬件的发展。从这个代码库中，支持从最大的超级计算机到手表的各种设备。Linux 只是操作系统的一个组成部分。还需要许多其他组件来创建一个工作系统，从基本工具，如命令行，到具有网页内容和与云服务通信的图形用户界面。Linux 内核以及其他大量的开源组件允许您构建一个可以在各种角色中发挥作用的系统。

然而，灵活性是一把双刃剑。虽然它为系统设计者提供了多种解决特定问题的选择，但也带来了如何知道哪种选择最佳的问题。本书的目的是详细描述如何使用免费、开源项目构建嵌入式 Linux 系统，以产生稳健、可靠和高效的系统。它基于作者多年作为顾问和培训师的经验，使用示例来说明最佳实践。

# 本书涵盖的内容

《精通嵌入式 Linux 编程》按照典型嵌入式 Linux 项目的生命周期进行组织。前六章告诉您如何设置项目以及 Linux 系统的构建方式，最终选择适当的 Linux 构建系统。接下来是必须就系统架构和设计选择做出某些关键决策的阶段，包括闪存存储器、设备驱动程序和`init`系统。随后是编写应用程序以利用您构建的嵌入式平台的阶段，其中有两章关于进程、线程和内存管理。最后，我们来到了调试和优化平台的阶段，这在第 12 和 13 章中讨论。最后一章描述了如何为实时应用程序配置 Linux。

第一章，“起步”，通过描述项目开始时系统设计者的选择，为整个故事铺垫。

第二章，“了解工具链”，描述了工具链的组件，重点介绍交叉编译。它描述了在哪里获取工具链，并提供了如何从源代码构建工具链的详细信息。

第三章，“关于引导加载程序”，解释了引导加载程序初始化设备硬件的作用，并以 U-Boot 和 Bareboot 为例进行了说明。它还描述了设备树，这是一种编码硬件配置的方法，用于许多嵌入式系统。

第四章，“移植和配置内核”，提供了如何为嵌入式系统选择 Linux 内核并为设备内部的硬件进行配置的信息。它还涵盖了如何将 Linux 移植到新的硬件上。

第五章，“构建根文件系统”，通过逐步指南介绍了嵌入式 Linux 实现中用户空间部分的概念，以及如何配置根文件系统的方法。

第六章，“选择构建系统”，涵盖了两个嵌入式 Linux 构建系统，它们自动化了前四章描述的步骤，并结束了本书的第一部分。

第七章，“创建存储策略”，讨论了管理闪存存储带来的挑战，包括原始闪存芯片和嵌入式 MMC 或 eMMC 封装。它描述了适用于每种技术类型的文件系统，并涵盖了如何在现场更新设备固件的技术。

第八章，“介绍设备驱动程序”，描述了内核设备驱动程序如何与硬件交互，并提供了简单驱动程序的示例。它还描述了从用户空间调用设备驱动程序的各种方法。

第九章，“启动 - init 程序”，展示了第一个用户空间程序`init`如何启动其余系统。它描述了`init`程序的三个版本，每个版本适用于不同的嵌入式系统组，从 BusyBox `init`到 systemd 的复杂性逐渐增加。

第十章，“了解进程和线程”，从应用程序员的角度描述了嵌入式系统。本章介绍了进程和线程、进程间通信和调度策略。

第十一章，“内存管理”，介绍了虚拟内存背后的思想，以及地址空间如何划分为内存映射。它还涵盖了如何检测正在使用的内存和内存泄漏。

第十二章，“使用 GDB 调试”，向您展示如何使用 GNU 调试器 GDB 交互式调试用户空间和内核代码。它还描述了内核调试器`kdb`。

第十三章，“性能分析和跟踪”，介绍了可用于测量系统性能的技术，从整个系统概要开始，然后逐渐聚焦于导致性能不佳的特定领域。它还描述了 Valgrind 作为检查应用程序对线程同步和内存分配正确性的工具。

第十四章，“实时编程”，提供了关于 Linux 上实时编程的详细指南，包括内核和实时内核补丁的配置，还提供了测量实时延迟的工具描述。它还涵盖了如何通过锁定内存来减少页面错误的信息。

# 本书所需内容

本书使用的软件完全是开源的。在大多数情况下，使用的版本是写作时可用的最新稳定版本。虽然我尽力以不特定于特定版本的方式描述主要特性，但其中的命令示例不可避免地包含一些在较新版本中无法使用的细节。我希望随附的描述足够详细，以便您可以将相同的原则应用于软件包的较新版本。

创建嵌入式系统涉及两个系统：用于交叉编译软件的主机系统和运行软件的目标系统。对于主机系统，我使用了 Ubuntu 14.04，但大多数 Linux 发行版都可以进行少量修改后使用。同样，我不得不选择一个目标系统来代表嵌入式系统。我选择了两个：BeagelBone Black 和 QEMU CPU 模拟器，模拟 ARM 目标。后一个目标意味着您可以尝试示例，而无需投资于实际目标设备的硬件。同时，应该可以将示例应用于广泛的目标，只需根据具体情况进行适应，例如设备名称和内存布局。

目标主要软件包的版本为 U-Boot 2015.07、Linux 4.1、Yocto Project 1.8 "Fido"和 Buildroot 2015.08。

# 这本书适合谁

这本书非常适合已经熟悉嵌入式系统并想要了解如何创建最佳设备的 Linux 开发人员和系统程序员。需要基本的 C 编程理解和系统编程经验。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以使用流 I/O 函数`fopen(3)`、`fread(3)`和`fclose(3)`。"

代码块设置如下：

```
static struct mtd_partition omap3beagle_nand_partitions[] = {
  /* All the partition sizes are listed in terms of NAND block size */
  {
    .name        = "X-Loader",
    .offset      = 0,
    .size        = 4 * NAND_BLOCK_SIZE,
    .mask_flags  = MTD_WRITEABLE,  /* force read-only */
  }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
static struct mtd_partition omap3beagle_nand_partitions[] = {
  /* All the partition sizes are listed in terms of NAND block size */
  {
    .name        = "X-Loader",
    .offset      = 0,
    .size         = 4 * NAND_BLOCK_SIZE,
    .mask_flags  = MTD_WRITEABLE,  /* force read-only */
  }
}
```

任何命令行输入或输出都以以下方式编写：

```
# flash_erase -j /dev/mtd6 0 0
# nandwrite /dev/mtd6 rootfs-sum.jffs2

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："第二行在控制台上打印消息**请按 Enter 键激活此控制台**。"

### 注意

警告或重要说明会显示在这样的框中。

### 提示

提示和技巧会显示为这样。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对这本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它可以帮助我们开发出您真正能够充分利用的标题。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，适用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

## 勘误

尽管我们已经尽最大努力确保内容的准确性，但错误确实会发生。如果您在我们的书籍中发现错误——可能是文本或代码中的错误，我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表格**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误部分的任何现有勘误列表中。

要查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将显示在**勘误表**部分下。

## 盗版

互联网上侵犯版权材料的盗版是跨媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并提供涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：起步

你即将开始你的下一个项目，这一次它将运行 Linux。在你动手之前，你应该考虑些什么？让我们从一个高层次来看嵌入式 Linux，看看为什么它如此受欢迎，开源许可证的影响是什么，以及你需要什么样的硬件来运行 Linux。

Linux 在 1999 年左右首次成为嵌入式设备的可行选择。那时 Axis（www.axis.com）发布了他们的第一款 Linux 动力网络摄像头，而 TiVo（www.tivo.com）发布了他们的第一款数字视频录像机（DVR）。自 1999 年以来，Linux 变得越来越受欢迎，以至于今天它是许多产品类别的首选操作系统。在撰写本文时，即 2015 年，有大约 20 亿台设备运行 Linux。其中包括大量运行 Android 的智能手机，Android 使用了 Linux 内核，以及数亿台机顶盒、智能电视和 Wi-Fi 路由器，更不用说一系列体积较小的设备，如车辆诊断、称重秤、工业设备和医疗监测单元。

那么，为什么你的电视运行 Linux？乍一看，电视的功能很简单：它必须在屏幕上显示视频流。为什么像 Linux 这样复杂的类 Unix 操作系统是必要的？

简单的答案是摩尔定律：英特尔的联合创始人戈登·摩尔在 1965 年观察到，芯片上的组件密度大约每两年翻一番。这适用于我们设计和使用的日常生活中的设备，就像它适用于台式机、笔记本电脑和服务器一样。大多数嵌入式设备的核心是一个高度集成的芯片，其中包含一个或多个处理器核心，并与主存储器、大容量存储和多种类型的外围设备进行接口。这被称为片上系统，或 SoC，它们随着摩尔定律的增长而变得越来越复杂。典型的 SoC 有一个技术参考手册，长达数千页。你的电视不仅仅是像旧模拟电视一样显示视频流。

视频流是数字的，可能是加密的，需要处理才能创建图像。你的电视（或很快将会）连接到互联网。它可以接收来自智能手机、平板电脑和家庭媒体服务器的内容。它可以（或很快将会）用于玩游戏。等等。你需要一个完整的操作系统来管理这种复杂程度。

以下是一些推动 Linux 采用的要点：

+   Linux 具有必要的功能。它有一个良好的调度程序，一个良好的网络堆栈，支持 USB、Wi-Fi、蓝牙，许多种存储介质，对多媒体设备的良好支持等等。它满足了所有要求。

+   Linux 已经移植到了各种处理器架构，包括一些在 SoC 设计中非常常见的架构——ARM、MIPS、x86 和 PowerPC。

+   Linux 是开源的，所以你有自由获取源代码并修改以满足你的需求。你或者代表你工作的人可以为你特定的 SoC 板或设备创建一个板支持包。你可以添加可能在主线源代码中缺失的协议、功能和技术。你可以删除你不需要的功能以减少内存和存储需求。Linux 是灵活的。

+   Linux 有一个活跃的社区；在 Linux 内核的情况下，非常活跃。内核每 10 到 12 周发布一个新版本，每个版本都包含来自大约 1000 名开发人员的代码。活跃的社区意味着 Linux 是最新的，并支持当前的硬件、协议和标准。

+   开源许可证保证你可以访问源代码。没有供应商的约束。

因此，Linux 是复杂设备的理想选择。但我在这里应该提到一些注意事项。复杂性使得理解变得更加困难。再加上快速发展的开发过程和开源的分散结构，您必须付出一些努力来学习如何使用它，并随着其变化而不断重新学习。我希望本书能在这个过程中有所帮助。

# 选择合适的操作系统

Linux 是否适合您的项目？Linux 在解决问题的复杂性得到合理解释的情况下效果很好。在需要连接性、稳健性和复杂用户界面的情况下尤其有效。但它无法解决所有问题，因此在您着手之前需要考虑以下一些事项：

+   您的硬件是否能胜任？与传统的实时操作系统（RTOS）如 VxWorks 相比，Linux 需要更多的资源。它至少需要一个 32 位处理器，以及更多的内存。我将在典型硬件要求部分详细介绍。

+   您是否具备正确的技能？项目的早期阶段，即板卡调试，需要对 Linux 及其与硬件的关系有详细的了解。同样，在调试和优化应用程序时，您需要能够解释结果。如果您内部没有这些技能，您可能需要外包一些工作。当然，阅读本书会有所帮助！

+   您的系统是否实时？Linux 可以处理许多实时活动，只要您注意一些细节，我将在《第十四章》中详细介绍，*实时编程*。

仔细考虑这些要点。成功的最佳指标可能是寻找运行 Linux 的类似产品，并看看它们是如何做到的；遵循最佳实践。

# 参与者

开源软件是从哪里来的？谁写的？特别是，这与嵌入式开发的关键组件 - 工具链、引导加载程序、内核和根文件系统中的基本实用程序有何关系？

主要参与者是：

+   开源社区。毕竟，这是生成您将要使用的软件的引擎。社区是一群开发人员的松散联盟，其中许多人以某种方式获得资助，可能是通过非营利组织、学术机构或商业公司。他们共同努力以推进各种项目的目标。其中有许多项目，有些小，有些大。我们在本书的其余部分将使用的一些项目是 Linux 本身、U-Boot、BusyBox、Buildroot、Yocto 项目以及 GNU 组织下的许多项目。

+   CPU 架构师 - 这些是设计我们使用的 CPU 的组织。这里的重要组织包括 ARM/Linaro（基于 ARM 的 SoC）、英特尔（x86 和 x86_64）、想象科技（MIPS）和 Freescale/IBM（PowerPC）。他们实现或者至少影响对基本 CPU 架构的支持。

+   SoC 供应商（Atmel、Broadcom、Freescale、英特尔、高通、TI 等）- 他们从 CPU 架构师那里获取内核和工具链，并对其进行修改以支持他们的芯片。他们还创建参考板：这些设计被下一级用来创建开发板和实际产品。

+   板卖家和 OEM - 这些人从 SoC 供应商那里获取参考设计，并将其构建到特定产品中，例如机顶盒或摄像头，或创建更通用的开发板，例如 Avantech 和 Kontron 的开发板。一个重要的类别是廉价的开发板，如 BeagleBoard/BeagleBone 和 Raspberry Pi，它们已经创建了自己的软件和硬件附加组件生态系统。

这些构成了一个链条，您的项目通常位于末端，这意味着您不能自由选择组件。您不能简单地从[kernel.org](http:// kernel.org)获取最新的内核，除非在极少数情况下，因为它不支持您正在使用的芯片或板。

这是嵌入式开发的一个持续问题。理想情况下，每个环节的开发者都会将他们的变更推送到上游，但他们没有这样做。发现一个内核有成千上万个未合并到上游的补丁并不罕见。此外，SoC 供应商倾向于只为他们最新的芯片积极开发开源组件，这意味着对于任何超过几年的芯片，支持将被冻结，不会收到任何更新。

其结果是，大多数嵌入式设计都基于旧版本的软件。它们不会接收安全修复、性能增强或新版本中的功能。像 Heartbleed（OpenSSL 库中的一个漏洞）和 Shellshock（bash shell 中的一个漏洞）这样的问题得不到修复。我将在本章后面的安全主题下更多地谈论这个问题。

你能做些什么？首先，向你的供应商提问：他们的更新政策是什么，他们多久修订一次内核版本，当前的内核版本是什么，之前的是什么？他们的政策是如何将变更合并到上游的？一些供应商在这方面取得了巨大进展。你应该偏好他们的芯片。

其次，你可以采取措施使自己更加自给自足。本书旨在更详细地解释依赖关系，并向你展示在哪些方面你可以自助。不要盲目接受 SoC 或板卡供应商提供的软件包，而不考虑其他选择。

# 项目生命周期

这本书分为四个部分，反映了项目的各个阶段。这些阶段不一定是顺序的。通常它们会重叠，你需要回头去重新审视之前完成的事情。然而，它们代表了开发者在项目进展过程中的关注点：

+   嵌入式 Linux 的要素（第 1 至 6 章）将帮助你建立开发环境，并为后续阶段创建一个工作平台。它通常被称为“板卡引导”阶段。

+   系统架构和设计选择（第 7 至 9 章）将帮助你审视一些关于程序和数据存储、如何在内核设备驱动程序和应用程序之间划分工作，以及如何初始化系统的设计决策。

+   编写嵌入式应用程序（第 10 和 11 章）展示了如何有效利用 Linux 进程和线程模型，以及如何在资源受限的设备中管理内存。

+   调试和优化性能（第 12 和 13 章）描述了如何在应用程序和内核中跟踪、分析和调试代码。

关于实时（第十四章, *实时编程*）的第五部分有些独立，因为它是嵌入式系统的一个小但重要的类别。为实现实时行为而设计对四个主要阶段都有影响。

## 嵌入式 Linux 的四个要素

每个项目都始于获取、定制和部署这四个要素：工具链、引导加载程序、内核和根文件系统。这是本书第一部分的主题：

+   **工具链**：这包括为目标设备创建代码所需的编译器和其他工具。其他一切都依赖于工具链。

+   **引导加载程序**：这是必要的，用于初始化板卡并加载和启动 Linux 内核。

+   **内核**：这是系统的核心，管理系统资源并与硬件进行接口。

+   **根文件系统**：这包含了在内核完成初始化后运行的库和程序。

当然，这里还有第五个要素，没有在这里提到。那就是专门针对你的嵌入式应用程序的程序集合，使设备能够完成其预定任务，无论是称重杂货、播放电影、控制机器人还是驾驶无人机。

通常情况下，当你购买 SoC 或板卡时，可能会作为一个包的一部分或全部提供这些元素。但是，出于前面段落提到的原因，它们可能不是最好的选择。我将在前六章中为您提供背景，以便做出正确的选择，并向您介绍两个自动化整个过程的工具：Buildroot 和 Yocto Project。

# 开源

嵌入式 Linux 的组件是开源的，所以现在是考虑这意味着什么，为什么开源工作方式以及这如何影响您将从中创建的通常是专有的嵌入式设备的好时机。

## 许可证

谈到开源时，经常使用“免费”这个词。对于这个主题的新手来说，他们通常认为这意味着无需支付任何费用，而开源软件许可确实保证您可以免费使用软件开发和部署系统。然而，这里更重要的意义是自由，因为您可以自由获取源代码并以任何您认为合适的方式进行修改，并在其他系统中重新部署。这些许可证赋予了您这个权利。与允许您免费复制二进制文件但不提供源代码的共享软件许可证，或者允许您在某些情况下免费使用软件（例如个人使用但不允许商业使用）的其他许可证相比，这些都不是开源。

我将提供以下评论，以帮助您了解使用开源许可证的影响，但我想指出，我是一名工程师，而不是律师。以下是我对许可证及其解释方式的理解。

开源许可证大致分为两类：来自自由软件基金会的**GPL**（**General Public License**）和来自**BSD**（**Berkeley Software Distribution**）、Apache 基金会和其他组织的宽松许可证。

宽松许可证基本上表示，您可以修改源代码并在自己选择的系统中使用它，只要您不以任何方式修改许可证条款。换句话说，在这个限制下，您可以按照自己的意愿使用它，包括将其构建到可能是专有系统中。

GPL 许可证相似，但有条款强制您将获取和修改软件的权利传递给最终用户。换句话说，您分享您的源代码。其中一个选项是通过将其放在公共服务器上使其完全公开。另一个选项是通过书面提供代码的要约，仅向最终用户提供。GPL 进一步规定，您不能将 GPL 代码合并到专有程序中。任何尝试这样做的行为都会使 GPL 适用于整个程序。换句话说，您不能在一个程序中将 GPL 和专有代码结合在一起。

那么，图书馆呢？如果它们使用 GPL 许可证，任何与它们链接的程序也会成为 GPL。然而，大多数图书馆都是根据**Lesser General Public License** (**LGPL**)许可。如果是这种情况，你可以允许从专有程序中链接它们。

前面的描述都是针对 GPL v2 和 LGPL v2.1 的。我应该提到最新版本的 GPL v3 和 LGPL v3。这些是有争议的，我承认我并不完全理解其影响。然而，意图是确保系统中的 GPLv3 和 LGPL v3 组件可以被最终用户替换，这符合开源软件的精神。但这确实会带来一些问题。一些 Linux 设备用于根据订阅级别或其他限制获取信息，替换软件的关键部分可能会影响这一点。机顶盒属于这一类。还存在安全问题。如果设备的所有者可以访问系统代码，那么不受欢迎的入侵者也可能会访问。通常的防御措施是拥有由权威（供应商）签名的内核映像，以防止未经授权的更新。这是否侵犯了我修改设备的权利？意见不一。

### 注意

TiVo 机顶盒是这场辩论的重要组成部分。它使用 Linux 内核，该内核根据 GPL v2 许可。TiVo 发布了他们版本的内核源代码，因此符合许可证。TiVo 还有一个只会加载由他们签名的内核二进制文件的引导加载程序。因此，你可以为 TiVo 盒构建修改后的内核，但无法在硬件上加载它。自由软件基金会认为这不符合开源软件的精神，并将此过程称为“Tivoization”。GPL v3 和 LGPL v3 是明确防止这种情况发生的。一些项目，特别是 Linux 内核，一直不愿采用第三版许可证，因为它会对设备制造商施加限制。

# 嵌入式 Linux 的硬件

如果你正在为嵌入式 Linux 项目设计或选择硬件，你需要注意什么？

首先，CPU 架构必须得到内核支持，除非你当然打算自己添加一个新的架构！查看 Linux 4.1 的源代码，有 30 种架构，每种都在`arch/`目录下有一个子目录表示。它们都是 32 位或 64 位架构，大多数带有内存管理单元（MMU），但也有一些没有。在嵌入式设备中最常见的是 ARM、MIPS、PowerPC 和 X86，每种都有 32 位和 64 位变体，并且都有内存管理单元。

本书的大部分内容是针对这类处理器编写的。还有另一类没有 MMU 的处理器，运行一个名为微控制器 Linux 或 uClinux 的 Linux 子集。这些处理器架构包括 ARC、Blackfin、Microblaze 和 Nios。我会不时提到 uClinux，但不会详细介绍，因为这是一个相当专业的话题。

其次，你需要合理数量的 RAM。16 MiB 是一个不错的最低值，尽管使用一半的 RAM 也完全可以运行 Linux。如果你愿意对系统的每个部分进行优化，甚至可以使用 4 MiB 运行 Linux。甚至可能更低，但是有一个临界点，那时它就不再是 Linux 了。

第三，通常是闪存这样的非易失性存储。8 MiB 对于简单设备如网络摄像头或简单路由器已经足够了。与 RAM 一样，如果你真的愿意，你可以使用更少的存储创建一个可行的 Linux 系统，但是越低，就越困难。Linux 对闪存设备有广泛的支持，包括原始 NOR 和 NAND 闪存芯片以及 SD 卡、eMMC 芯片、USB 闪存等形式的受控闪存。

第四，调试端口非常有用，最常见的是 RS-232 串行端口。它不一定要安装在生产板上，但可以使板子的启动、调试和开发更加容易。

第五，您需要一些手段在从头开始时加载软件。几年前，板子会配备 JTAG 接口，但现代 SoC 有能力直接从可移动介质加载引导代码，特别是 SD 和 micro SD 卡，或者串行接口，如 RS-232 或 USB。

除了这些基础知识外，还有与设备需要完成工作的特定硬件位的接口。主线 Linux 配备了成千上万种不同设备的开源驱动程序，SoC 制造商和第三方芯片的 OEM 提供了质量不等的驱动程序，但请记住我对一些制造商的承诺和能力的评论。作为嵌入式设备的开发人员，您会发现自己花费了相当多的时间来评估和调整第三方代码，如果有的话，或者与制造商联系，如果没有的话。最后，您将不得不为设备的任何独特接口编写设备支持，或者找人替您完成。

# 本书中使用的硬件

本书中的示例旨在是通用的，但为了使它们相关且易于遵循，我不得不选择一个特定的设备作为示例。我使用了两个示例设备：BeagleBone Black 和 QEMU。第一个是广泛可用且便宜的开发板，可用于严肃的嵌入式硬件。第二个是一个机器模拟器，可用于创建典型的嵌入式硬件系统。诱人的是只使用 QEMU，但是像所有模拟一样，它与真实情况并不完全相同。使用 BeagleBone，您可以满足与真实硬件交互并看到真正的 LED 闪烁的满足感。诱人的是选择比 BeagleBone Black 更为时尚的板子，但我相信它的流行度使其具有一定的长寿性，并意味着它将在未来几年内继续可用。

无论如何，我鼓励您尝试使用这两个平台中的任何一个或者您手头上可能有的任何嵌入式硬件来尝试尽可能多的示例。

## BeagleBone Black

BeagleBone 和后来的 BeagleBone Black 是由 Circuitco LLC 生产的一款小型信用卡大小的开放硬件设计的开发板。主要信息库位于[www.beagleboard.org](http://www.beagleboard.org)。规格的主要要点是：

+   TI AM335x 1GHz ARM® Cortex-A8 Sitara SoC

+   512 MiB DDR3 RAM

+   2 或 4 GiB 8 位 eMMC 板载闪存

+   用于调试和开发的串行端口

+   可用作引导设备的 MicroSD 连接器

+   迷你 USB OTG 客户端/主机端口，也可用于为板子供电

+   全尺寸 USB 2.0 主机端口

+   10/100 以太网端口

+   HDMI 用于视频和音频输出

此外，还有两个 46 针扩展头，有许多不同的子板，称为披风，可以使板子适应许多不同的功能。但是，在本书的示例中，您不需要安装任何披风。

除了板子本身，您还需要：

+   一根迷你 USB 到全尺寸 USB 电缆（随板子提供）以提供电源，除非您拥有此列表上的最后一项。

+   一个 RS-232 电缆，可以与板子提供的 6 针 3.3 伏 TTL 电平信号进行接口。Beagleboard 网站上有兼容电缆的链接。

+   一个 microSD 卡和一种从开发 PC 或笔记本电脑上写入软件到板子上所需的手段。

+   一根以太网电缆，因为一些示例需要网络连接。

+   可选，但建议使用，能够提供 1A 或更多电流的 5V 电源适配器。

## QEMU

QEMU 是一个机器模拟器。它有许多不同的版本，每个版本都可以模拟处理器架构和使用该架构构建的许多板子。例如，我们有以下内容：

+   **qemu-system-arm**：ARM

+   **qemu-system-mips**：MIPS

+   **qemu-system-ppc**：PowerPC

+   **qemu-system-x86**：x86 和 x86_64

对于每种架构，QEMU 模拟了一系列硬件，您可以通过使用选项`-machine help`来查看。每台机器模拟了通常在该板上找到的大部分硬件。有选项可以将硬件链接到本地资源，例如使用本地文件作为模拟磁盘驱动器。以下是一个具体的例子：

```
$ qemu-system-arm -machine vexpress-a9 -m 256M -drive file=rootfs.ext4,sd -net nic -net use -kernel zImage -dtb vexpress-v2p-ca9.dtb -append "console=ttyAMA0,115200 root=/dev/mmcblk0" -serial stdio -net nic,model=lan9118 -net tap,ifname=tap0

```

前面命令行中使用的选项是：

+   -machine vexpress-a9：创建一个 ARM Versatile Express 开发板的模拟，配备 Cortex A-9 处理器

+   -m 256M：为其分配 256 MiB 的 RAM

+   -drive file=rootfs.ext4,sd：将`sd`接口连接到本地文件`rootfs.ext4`（其中包含文件系统镜像）

+   -kernel zImage：从名为`zImage`的本地文件加载 Linux 内核

+   -dtb vexpress-v2p-ca9.dtb：从本地文件`vexpress-v2p-ca9.dtb`加载设备树

+   -append "..."：将此字符串作为内核命令行提供

+   -serial stdio：将串行端口连接到启动 QEMU 的终端，通常用于通过串行控制台登录到模拟机器

+   -net nic,model=lan9118：创建一个网络接口

+   -net tap,ifname=tap0：将网络接口连接到虚拟网络接口`tap0`

要配置网络的主机端，您需要来自**用户模式 Linux**（**UML**）项目的`tunctl`命令；在 Debian 和 Ubuntu 上，该软件包的名称为`uml-utilities`。您可以使用以下命令创建一个虚拟网络：

```
$ sudo tunctl -u $(whoami) -t tap0

```

这将创建一个名为`tap0`的网络接口，它连接到模拟的 QEMU 机器中的网络控制器。您可以像配置任何其他接口一样配置`tap0`。

所有这些选项在接下来的章节中都有详细描述。我将在大多数示例中使用 Versatile Express，但使用不同的机器或架构应该也很容易。

# 本书中使用的软件

我只使用了开源软件来开发工具和目标操作系统和应用程序。我假设您将在开发系统上使用 Linux。我使用 Ubuntu 14.04 测试了所有主机命令，因此对该特定版本有一些偏见，但任何现代 Linux 发行版都可能运行良好。

# 摘要

嵌入式硬件将继续变得更加复杂，遵循摩尔定律所设定的轨迹。Linux 具有利用硬件的能力和灵活性。

Linux 只是开源软件中的一个组件，您需要创建一个可工作产品所需的许多组件。代码是免费提供的，这意味着许多不同层次的人和组织都可以做出贡献。然而，嵌入式平台的多样性和快速发展的步伐导致了软件的孤立池，它们的共享效率不如预期高。在许多情况下，您将依赖于这些软件，特别是由 SoC 或板卡供应商提供的 Linux 内核，以及较小程度上的工具链。一些 SoC 制造商正在更好地推动他们的变更上游，并且这些变更的维护变得更加容易。

幸运的是，有一些强大的工具可以帮助您创建和维护设备的软件。例如，Buildroot 非常适合小型系统，Yocto Project 适合更大的系统。

在我描述这些构建工具之前，我将描述嵌入式 Linux 的四个元素，您可以将其应用于所有嵌入式 Linux 项目，无论它们是如何创建的。下一章将全面介绍这些元素中的第一个，即工具链，您需要用它来为目标平台编译代码。


# 第二章：了解工具链

工具链是嵌入式 Linux 的第一个元素，也是项目的起点。在这个早期阶段做出的选择将对最终结果产生深远影响。您的工具链应能够有效地利用硬件，使用处理器的最佳指令集，使用浮点单元（如果有的话）等。它应该支持您需要的语言，并且具有对 POSIX 和其他系统接口的稳固实现。此外，发现安全漏洞或错误时，应及时更新。最后，它应该在整个项目中保持不变。换句话说，一旦选择了工具链，坚持使用它是很重要的。在项目进行过程中以不一致的方式更改编译器和开发库将导致隐蔽的错误。

获得工具链就像下载和安装一个软件包一样简单。但是，工具链本身是一个复杂的东西，我将在本章中向您展示。

# 什么是工具链？

工具链是将源代码编译成可在目标设备上运行的可执行文件的一组工具，包括编译器、链接器和运行时库。最初，您需要一个工具链来构建嵌入式 Linux 系统的另外三个元素：引导加载程序、内核和根文件系统。它必须能够编译用汇编、C 和 C++编写的代码，因为这些是基本开源软件包中使用的语言。

通常，Linux 的工具链是基于 GNU 项目（[`www.gnu.org`](http://www.gnu.org)）的组件构建的，这在撰写本文时仍然是大多数情况下的情况。然而，在过去的几年里，Clang 编译器和相关的 LLVM 项目（[`llvm.org`](http://llvm.org)）已经发展到了可以成为 GNU 工具链的可行替代品的地步。LLVM 和基于 GNU 的工具链之间的一个主要区别在于许可证；LLVM 采用 BSD 许可证，而 GNU 采用 GPL。Clang 也有一些技术优势，比如更快的编译速度和更好的诊断，但 GNU GCC 具有与现有代码库的兼容性和对各种体系结构和操作系统的支持。事实上，仍然有一些领域 Clang 无法取代 GNU C 编译器，特别是在编译主流 Linux 内核时。很可能，在未来一年左右的时间里，Clang 将能够编译嵌入式 Linux 所需的所有组件，因此将成为 GNU 的替代品。在[`clang.llvm.org/docs/CrossCompilation.html`](http://clang.llvm.org/docs/CrossCompilation.html)上有一个关于如何使用 Clang 进行交叉编译的很好的描述。如果您想将其作为嵌入式 Linux 构建系统的一部分使用，EmbToolkit（[`www.embtoolkit.org`](https://www.embtoolkit.org)）完全支持 GNU 和 LLVM/Clang 工具链，并且有许多人正在努力使用 Clang 与 Buildroot 和 Yocto Project。我将在第六章中介绍嵌入式构建系统，*选择构建系统*。与此同时，本章将重点介绍 GNU 工具链，因为这是目前唯一的完整选项。

标准的 GNU 工具链由三个主要组件组成：

+   **Binutils**：一组二进制实用程序，包括汇编器和链接器 ld。它可以在[`www.gnu.org/software/binutils/`](http://www.gnu.org/software/binutils/)上获得。

+   **GNU 编译器集合（GCC）**：这些是 C 和其他语言的编译器，根据 GCC 的版本，包括 C++、Objective-C、Objective-C++、Java、Fortran、Ada 和 Go。它们都使用一个通用的后端，生成汇编代码，然后传递给 GNU 汇编器。它可以在[`gcc.gnu.org/`](http://gcc.gnu.org/)上获得。

+   C 库：基于 POSIX 规范的标准化 API，是应用程序与操作系统内核之间的主要接口。有几个 C 库需要考虑，见下一节。

除此之外，您还需要一份 Linux 内核头文件的副本，其中包含在直接访问内核时所需的定义和常量。现在，您需要它们来编译 C 库，但以后在编写程序或编译与特定 Linux 设备交互的库时也会需要它们，例如通过 Linux 帧缓冲驱动程序显示图形。这不仅仅是将头文件复制到内核源代码的 include 目录中的问题。这些头文件仅供内核使用，并包含原始状态下用于编译常规 Linux 应用程序会导致冲突的定义。

相反，您需要生成一组经过清理的内核头文件，我在第五章 *构建根文件系统*中进行了说明。

通常并不重要内核头文件是否是从您将要使用的 Linux 的确切版本生成的。由于内核接口始终向后兼容，只需要头文件来自于与目标上使用的内核相同或更旧的内核即可。

大多数人认为 GNU 调试器 GDB 也是工具链的一部分，并且通常在这一点上构建它。我将在第十二章 *使用 GDB 进行调试*中讨论 GDB。

# 工具链类型 - 本地与交叉工具链

对于我们的目的，有两种类型的工具链：

+   本地：这个工具链在与生成的程序相同类型的系统上运行，有时甚至是同一台实际系统。这是桌面和服务器的常见情况，并且在某些嵌入式设备类别上变得流行。例如，运行 Debian for ARM 的树莓派具有自托管的本地编译器。

+   交叉：这个工具链在与目标不同类型的系统上运行，允许在快速桌面 PC 上进行开发，然后加载到嵌入式目标进行测试。

几乎所有嵌入式 Linux 开发都是使用交叉开发工具链完成的，部分原因是大多数嵌入式设备不适合程序开发，因为它们缺乏计算能力、内存和存储空间，另一部分原因是它保持了主机和目标环境的分离。当主机和目标使用相同的架构，例如 X86_64 时，后一点尤为重要。在这种情况下，诱人的是在主机上进行本地编译，然后简单地将二进制文件复制到目标上。这在一定程度上是有效的，但很可能主机发行版会比目标更频繁地接收更新，为目标构建代码的不同工程师将具有略有不同版本的主机开发库，因此您将违反工具链在项目生命周期内保持恒定的原则。如果确保主机和目标构建环境保持同步，您可以使这种方法奏效，但更好的方法是保持主机和目标分开，交叉工具链是实现这一点的一种方式。

然而，有一个支持本地开发的反对意见。跨平台开发需要跨编译所有你需要的库和工具到你的目标平台上。我们将在本章后面看到，跨编译并不总是简单的，因为大多数开源软件包并不是设计成这种方式构建的。集成构建工具，包括 Buildroot 和 Yocto 项目，通过封装交叉编译一系列 typical 嵌入式系统中需要的软件包的规则来帮助，但是，如果你想编译大量额外的软件包，最好是本地编译它们。例如，使用交叉编译器为树莓派或 BeagleBone 提供 Debian 发行版是不可能的，它们必须本地编译。从头开始创建本地构建环境并不容易，需要首先创建一个交叉编译器来引导目标上的本地构建环境，并使用它来构建软件包。你需要一个充分配置的目标板的构建农场，或者你可以使用 QEMU 来模拟目标。如果你想进一步了解这一点，你可能想看看 Scratchbox 项目，现在已经发展到了第二代 Scratchbox2。它是由诺基亚开发的，用于构建他们的 Maemo Linux 操作系统，今天被 Mer 项目和 Tizen 项目等使用。

与此同时，在本章中，我将专注于更主流的交叉编译器环境，这相对容易设置和管理。

## CPU 架构

工具链必须根据目标 CPU 的能力进行构建，其中包括：

+   **CPU 架构**：arm、mips、x86_64 等

+   **大端或小端操作**：一些 CPU 可以在两种模式下运行，但每种模式的机器码是不同的。

+   **浮点支持**：并非所有版本的嵌入式处理器都实现了硬件浮点单元，如果是这样，工具链可以配置为调用软件浮点库。

+   **应用二进制接口（ABI）**：用于在函数调用之间传递参数的调用约定

对于许多体系结构，ABI 在处理器系列中是恒定的。一个值得注意的例外是 ARM。ARM 架构在 2000 年代后期过渡到了扩展应用二进制接口（EABI），导致以前的 ABI 被命名为旧应用二进制接口（OABI）。虽然 OABI 现在已经过时，但你仍然会看到有关 EABI 的引用。从那时起，EABI 分为两个，基于传递浮点参数的方式。原始的 EABI 使用通用寄存器（整数）寄存器，而新的 EABIHF 使用浮点寄存器。EABIHF 在浮点运算方面显着更快，因为它消除了整数和浮点寄存器之间的复制需求，但它与没有浮点单元的 CPU 不兼容。因此，选择是在两种不兼容的 ABI 之间：你不能混合使用这两种，因此你必须在这个阶段做出决定。

GNU 使用前缀来标识可以生成的各种组合，由三到四个由破折号分隔的组件元组组成，如下所述：

+   **CPU**：CPU 架构，如 arm、mips 或 x86_64。如果 CPU 有两种字节序模式，可以通过添加 el 表示小端，或者 eb 表示大端来区分。很好的例子是小端 MIPS，mipsel 和大端 ARM，armeb。

+   **供应商**：这标识了工具链的提供者。例如 buildroot、poky 或者 unknown。有时会完全省略。

+   **内核**：对于我们的目的，它总是'linux'。

+   **操作系统**：用户空间组件的名称，可能是`gnu`或`uclibcgnu`。ABI 也可以附加在这里，因此对于 ARM 工具链，您可能会看到`gnueabi`，`gnueabihf`，`uclibcgnueabi`或`uclibcgnueabihf`。

您可以使用`gcc`的`-dumpmachine`选项找到构建工具链时使用的元组。例如，您可能会在主机计算机上看到以下内容：

```
$ gcc -dumpmachine
x86_64-linux-gnu

```

### 注意

当在机器上安装本地编译器时，通常会创建到工具链中每个工具的链接，没有前缀，这样你就可以使用命令`gcc`调用编译器。

以下是使用交叉编译器的示例：

```
$ mipsel-unknown-linux-gnu-gcc -dumpmachine
mipsel-unknown-linux-gnu

```

# 选择 C 库

Unix 操作系统的编程接口是用 C 语言定义的，现在由 POSIX 标准定义。C 库是该接口的实现；它是 Linux 程序与内核之间的网关，如下图所示。即使您使用其他语言编写程序，例如 Java 或 Python，相应的运行时支持库最终也必须调用 C 库：

![选择 C 库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_02_01.jpg)

C 库是应用程序与内核之间的网关

每当 C 库需要内核的服务时，它将使用内核`系统调用`接口在用户空间和内核空间之间进行转换。可以通过直接进行内核系统调用来绕过 C 库，但这是很麻烦的，几乎从不需要。

有几个 C 库可供选择。主要选项如下：

+   **glibc**：可在[`www.gnu.org/software/libc`](http://www.gnu.org/software/libc)找到。这是标准的 GNU C 库。它很大，并且直到最近都不太可配置，但它是 POSIX API 的最完整实现。

+   **eglibc**：可在[`www.eglibc.org/home`](http://www.eglibc.org/home)找到。这是嵌入式 GLIBC。它是对 glibc 的一系列补丁，添加了配置选项和对 glibc 未覆盖的架构的支持（特别是 PowerPC e500）。eglibc 和 glibc 之间的分裂总是相当人为的，幸运的是，从版本 2.20 开始，eglibc 的代码库已经合并回 glibc，留下了一个改进的库。eglibc 不再维护。

+   **uClibc**：可在[`www.uclibc.org`](http://www.uclibc.org)找到。 'u'实际上是希腊字母'μ'，表示这是微控制器 C 库。它最初是为了与 uClinux（没有内存管理单元的 CPU 的 Linux）一起工作而开发的，但后来已经适应用于完整的 Linux。有一个配置实用程序，允许您根据需要微调其功能。即使完整配置也比 glibc 小，但它不是 POSIX 标准的完整实现。

+   **musl libc**：可在[`www.musl-libc.org`](http://www.musl-libc.org)找到。这是一个为嵌入式系统设计的新 C 库。

那么，应该选择哪个？我的建议是，如果您使用 uClinux 或存储空间或 RAM 非常有限，因此小尺寸将是一个优势，那么只使用 uClibc。否则，我更喜欢使用最新的 glibc 或 eglibc。我没有 musl libc 的经验，但如果您发现 glibc/eglibc 不合适，尽管尝试一下。这个过程总结在下图中：

![选择 C 库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_02_02.jpg)

选择 C 库

# 查找工具链

对于交叉开发工具链，您有三种选择：您可以找到与您的需求匹配的现成工具链，可以使用嵌入式构建工具生成的工具链，该工具链在第六章中有介绍，或者您可以按照本章后面描述的方式自己创建一个。

预先构建的交叉工具链是一个吸引人的选择，因为你只需要下载和安装它，但你受限于特定工具链的配置，并且依赖于你获取它的个人或组织。最有可能的是以下之一：

+   SoC 或板卡供应商。大多数供应商提供 Linux 工具链。

+   致力于为特定架构提供系统级支持的联盟。例如，Linaro ([`www.linaro.org`](https://www.linaro.org))为 ARM 架构提供了预构建的工具链。

+   第三方 Linux 工具供应商，如 Mentor Graphics、TimeSys 或 MontaVista。

+   桌面 Linux 发行版的交叉工具包，例如，基于 Debian 的发行版有用于 ARM、MIPS 和 PowerPC 目标的交叉编译软件包。

+   由集成嵌入式构建工具之一生成的二进制 SDK，Yocto 项目在[`autobuilder.yoctoproject.org/pub/releases/CURRENT/toolchain`](http://autobuilder.yoctoproject.org/pub/releases/CURRENT/toolchain)上有一些示例，还有 Denx 嵌入式 Linux 开发工具包在 ftp://ftp.denx.de/pub/eldk/上。

+   一个你找不到的论坛链接。

在所有这些情况下，你必须决定提供的预构建工具链是否满足你的要求。它是否使用你喜欢的 C 库？提供商是否会为你提供安全修复和错误修复的更新，考虑到我在第一章中对支持和更新的评论，*起步*。如果你对任何一个问题的答案是否定的，那么你应该考虑创建你自己的工具链。

不幸的是，构建工具链并不是一件容易的事。如果你真的想自己完成所有工作，请看*Cross Linux From Scratch* ([`trac.clfs.org`](http://trac.clfs.org))。在那里，你会找到如何创建每个组件的逐步说明。

一个更简单的选择是使用 crosstool-NG，它将这个过程封装成一组脚本，并有一个菜单驱动的前端。不过，你仍然需要相当多的知识，才能做出正确的选择。

使用构建系统如 Buildroot 或 Yocto 项目更简单，因为它们在构建过程中生成工具链。这是我偏好的解决方案，正如我在第六章中所展示的，*选择构建系统*。

## 使用 crosstool-NG 构建工具链

我将从 crosstool-NG 开始，因为它允许你看到创建工具链的过程，并创建几种不同的工具链。

几年前，Dan Kegel 编写了一组脚本和 makefile 用于生成交叉开发工具链，并称之为 crosstool ([kegel.com/crosstool](http://kegel.com/crosstool))。2007 年，Yann E. Morin 基于这个基础创建了下一代 crosstool，即 crosstool-NG ([crosstool-ng.org](http://crosstool-ng.org))。今天，这无疑是从源代码创建独立交叉工具链的最方便的方法。

## 安装 crosstool-NG

在开始之前，你需要在主机 PC 上安装一个可用的本地工具链和构建工具。要在 Ubuntu 主机上使用 crosstool-NG，你需要使用以下命令安装软件包：

```
$ sudo apt-get install automake bison chrpath flex g++ git gperf gawk libexpat1-dev libncurses5-dev libsdl1.2-dev libtool python2.7-dev texinfo

```

接下来，从 crosstool-NG 下载部分获取当前版本，[`crosstool-ng.org/download/crosstool-ng`](http://crosstool-ng.org/download/crosstool-ng)。在我的示例中，我使用了 1.20.0。解压并创建前端菜单系统 ct-ng，如下所示的命令：

```
$ tar xf crosstool-ng-1.20.0.tar.bz2
$ cd crosstool-ng-1.20.0
$ ./configure --enable-local
$ make
$ make install

```

`--enable-local`选项意味着程序将安装到当前目录，这样可以避免需要 root 权限，如果你要安装到默认位置`/usr/local/bin`，则需要 root 权限。从当前目录输入`./ct-ng`启动 crosstool 菜单。

## 选择工具链

Crosstool-NG 可以构建许多不同的工具链组合。为了使初始配置更容易，它附带了一组样本，涵盖了许多常见用例。使用`./ct-ng list-samples`来生成列表。

例如，假设你的目标是 BeagleBone Black，它有一个 ARM Cortex A8 核心和一个 VFPv3 浮点单元，并且你想使用一个当前版本的 glibc。最接近的样本是`arm-cortex_a8-linux-gnueabi`。你可以通过在名称前加上`show-`来查看默认配置：

```
$ ./ct-ng show-arm-cortex_a8-linux-gnueabi
[L..] arm-cortex_a8-linux-gnueabi
OS             : linux-3.15.4
Companion libs : gmp-5.1.3 mpfr-3.1.2 cloog-ppl-0.18.1 mpc-1.0.2 libelf-0.8.13
binutils       : binutils-2.22
C compiler     : gcc-4.9.1 (C,C++)
C library      : glibc-2.19 (threads: nptl)
Tools          : dmalloc-5.5.2 duma-2_5_15 gdb-7.8 ltrace-0.7.3 strace-4.8

```

要将其选择为目标配置，你需要输入：

```
$ ./ct-ng  arm-cortex_a8-linux-gnueabi

```

在这一点上，你可以通过使用配置菜单命令`menuconfig`来审查配置并进行更改：

```
$ ./ct-ng menuconfig

```

菜单系统基于 Linux 内核的`menuconfig`，所以对于任何配置过内核的人来说，用户界面的导航都是熟悉的。如果不熟悉，请参考第四章，*移植和配置内核*，了解`menuconfig`的描述。

在这一点上，有一些配置更改是我建议你做的：

+   在**路径和杂项**选项中，禁用**使工具链只读** (`CT_INSTALL_DIR_RO`)

+   在**目标选项** | **浮点数**中，选择**硬件 (FPU)** (`CT_ARCH_FLOAT_HW`)

+   在**C 库** | **额外配置**中，添加**--enable-obsolete-rpc** (`CT_LIBC_GLIBC_EXTRA_CONFIG_ARRAY`)

第一个是必要的，如果你想在安装后向工具链添加库，我将在本章后面描述。接下来是为具有硬件浮点单元的处理器选择最佳浮点实现。最后是强制生成一个过时的头文件`rpc.h`的工具链，这个头文件仍然被许多软件包使用（请注意，只有在选择 glibc 时才会出现这个问题）。括号中的名称是存储在配置文件中的配置标签。当你做出更改后，退出`menuconfig`，并在这样做时保存配置。

配置数据保存在一个名为`.config`的文件中。查看文件时，你会看到文本的第一行是*Automatically generated make config: don't edit*，这通常是一个很好的建议，但我建议你在这种情况下忽略它。你还记得关于工具链 ABI 的讨论吗？ARM 有两个变体，一个是将浮点参数传递到整数寄存器中，另一个是使用 VFP 寄存器。你刚刚选择的浮点配置是后者，所以元组的 ABI 部分应该是`eabihf`。有一个配置参数恰好符合你的要求，但它不是默认启用的，也不会出现在菜单中，至少在这个版本的 crosstool 中不会。因此，你需要编辑`.config`并添加如下粗体显示的行：

```
[…]
#
# arm other options
#
CT_ARCH_ARM_MODE="arm"
CT_ARCH_ARM_MODE_ARM=y
# CT_ARCH_ARM_MODE_THUMB is not set
# CT_ARCH_ARM_INTERWORKING is not set
CT_ARCH_ARM_EABI_FORCE=y
CT_ARCH_ARM_EABI=y
CT_ARCH_ARM_TUPLE_USE_EABIHF=y
[...]

```

现在你可以使用 crosstool-NG 来获取、配置和构建组件，根据你的规格输入以下命令：

```
$ ./ct-ng build

```

构建大约需要半个小时，之后你会发现你的工具链出现在`~/x-tools/arm-cortex_a8-linux-gnueabihf/`中。

# 工具链的解剖

为了了解典型工具链中有什么，我想要检查一下你刚刚创建的 crosstool-NG 工具链。

工具链位于目录`~/x-tools/arm-cortex_a8-linux-gnueabihf/bin`中。在那里你会找到交叉编译器`arm-cortex_a8-linux-gnueabihf-gcc`。要使用它，你需要使用以下命令将该目录添加到你的路径中：

```
$ PATH=~/x-tools/arm-cortex_a8-linux-gnueabihf/bin:$PATH

```

现在你可以使用一个简单的`hello world`程序，看起来像这样：

```
#include <stdio.h>
#include <stdlib.h>
int main (int argc, char *argv[])
{
  printf ("Hello, world!\n");
  return 0;
}
```

然后像这样编译它：

```
$ arm-cortex_a8-linux-gnueabihf-gcc helloworld.c -o helloworld

```

你可以使用`file`命令来确认它已经被交叉编译，以打印文件的类型：

```
$ file helloworld
helloworld: ELF 32-bit LSB executable, ARM, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.15.4, not stripped

```

## 了解你的交叉编译器

想象一下，你刚刚收到了一个工具链，你想了解更多关于它是如何配置的。你可以通过查询 gcc 来了解很多信息。例如，要找到版本，你可以使用`--version`：

```
$ arm-cortex_a8-linux-gnueabi-gcc --version
arm-cortex_a8-linux-gnueabi-gcc (crosstool-NG 1.20.0) 4.9.1
Copyright (C) 2014 Free Software Foundation, Inc.
This is free software; see the source for copying conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

```

要查找它是如何配置的，请使用`-v`：

```
$ arm-cortex_a8-linux-gnueabi-gcc -v
Using built-in specs.
COLLECT_GCC=arm-cortex_a8-linux-gnueabihf-gcc
COLLECT_LTO_WRAPPER=/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/libexec/gcc/arm-cortex_a8-linux-gnueabihf/4.9.1/lto-wrapper
Target: arm-cortex_a8-linux-gnueabihf
Configured with: /home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/src/gcc-4.9.1/configure --build=x86_64-build_unknown-linux-gnu --host=x86_64-build_unknown-linux-gnu --target=arm-cortex_a8-linux-gnueabihf --prefix=/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf --with-sysroot=/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot --enable-languages=c,c++ --with-arch=armv7-a --with-cpu=cortex-a8 --with-tune=cortex-a8 --with-float=hard --with-pkgversion='crosstool-NG 1.20.0' --enable-__cxa_atexit --disable-libmudflap --disable-libgomp --disable-libssp --disable-libquadmath --disable-libquadmath-support --disable-libsanitizer --with-gmp=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-mpfr=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-mpc=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-isl=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-cloog=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-libelf=/home/chris/hd/home/chris/build/MELP/build/crosstool-ng-1.20.0/.build/arm-cortex_a8-linux-gnueabihf/buildtools --with-host-libstdcxx='-static-libgcc -Wl,-Bstatic,-lstdc++,-Bdynamic -lm' --enable-threads=posix --enable-target-optspace --enable-plugin --enable-gold --disable-nls --disable-multilib --with-local-prefix=/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot --enable-c99 --enable-long-long
Thread model: posix
gcc version 4.9.1 (crosstool-NG 1.20.0)

```

那里有很多输出，但值得注意的有：

+   `--with-sysroot=/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot`：这是默认的 sysroot 目录，请参阅以下部分以获取解释

+   `--enable-languages=c,c++`：使用此选项，我们启用了 C 和 C++语言

+   `--with-arch=armv7-a`：使用 ARM v7a 指令集生成代码

+   `--with-cpu=cortex-a8 and --with-tune=cortex-a8`：进一步调整代码以适应 Cortex A8 核心

+   `--with-float=hard`：生成浮点单元的操作码，并使用 VFP 寄存器作为参数

+   `--enable-threads=posix`：启用 POSIX 线程

这些是编译器的默认设置。您可以在 gcc 命令行上覆盖大多数设置，因此，例如，如果要为不同的 CPU 编译，可以通过在命令行中添加`-mcpu`来覆盖配置的设置`--with-cpu`，如下所示：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -mcpu=cortex-a5 helloworld.c -o helloworld

```

您可以使用`--target-help`打印出可用的特定于体系结构的选项范围，如下所示：

```
$ arm-cortex_a8-linux-gnueabihf-gcc --target-help

```

你可能会想知道在生成工具链时是否很重要是否得到了精确的配置，如果以后可以更改，答案取决于您预期使用它的方式。如果您计划为每个目标创建一个新的工具链，那么最好在开始时设置所有内容，因为这将减少以后出错的风险。稍微提前到第六章，*选择构建系统*，我称之为 Buildroot 哲学。另一方面，如果您想构建一个通用的工具链，并且准备在为特定目标构建时提供正确的设置，那么您应该使基本工具链通用，这是 Yocto 项目处理事务的方式。前面的例子遵循 Buildroot 哲学。

## sysroot、库和头文件

工具链 sysroot 是一个包含库、头文件和其他配置文件子目录的目录。它可以在配置工具链时通过`--with-sysroot=`设置，也可以在命令行上使用`--sysroot=`设置。您可以使用`-print-sysroot`来查看默认 sysroot 的位置：

```
$ arm-cortex_a8-linux-gnueabi-gcc -print-sysroot
/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot

```

您将在 sysroot 中找到以下内容：

+   `lib`：包含 C 库和动态链接器/加载器`ld-linux`的共享对象

+   `usr/lib`：C 库的静态库存档以及随后可能安装的任何其他库

+   `usr/include`：包含所有库的头文件

+   `usr/bin`：包含在目标上运行的实用程序，例如`ldd`命令

+   `/usr/share`：用于本地化和国际化

+   `sbin`：提供了 ldconfig 实用程序，用于优化库加载路径

明显地，其中一些需要在开发主机上用于编译程序，而其他一些，例如共享库和`ld-linux`，需要在目标运行时使用。

# 工具链中的其他工具

以下表格显示了工具链中的各种其他命令以及简要描述：

| 命令 | 描述 |
| --- | --- |
| `addr2line` | 通过读取可执行文件中的调试符号表，将程序地址转换为文件名和数字。在解码系统崩溃报告中打印的地址时非常有用。 |
| `ar` | 存档实用程序用于创建静态库。 |
| `as` | 这是 GNU 汇编器。 |
| `c++filt` | 用于解开 C++和 Java 符号。 |
| `cpp` | 这是 C 预处理器，用于扩展`#define`、`#include`和其他类似的指令。您很少需要单独使用它。 |
| `elfedit` | 用于更新 ELF 文件的 ELF 头。 |
| `g++` | 这是 GNU C++前端，假设源文件包含 C++代码。 |
| `gcc` | 这是 GNU C 前端，假设源文件包含 C 代码。 |
| `gcov` | 这是一个代码覆盖工具。 |
| `gdb` | 这是 GNU 调试器。 |
| `gprof` | 这是一个程序性能分析工具。 |
| `ld` | 这是 GNU 链接器。 |
| `nm` | 这列出了目标文件中的符号。 |
| `objcopy` | 用于复制和转换目标文件。 |
| `objdump` | 用于显示目标文件的信息。 |
| `ranlib` | 这在静态库中创建或修改索引，使链接阶段更快。 |
| `readelf` | 这显示有关 ELF 对象格式文件的信息。 |
| `size` | 这列出了各个部分的大小和总大小。 |
| `strings` | 这在文件中显示可打印字符的字符串。 |
| `strip` | 用于剥离对象文件的调试符号表，从而使其更小。通常，您会剥离放入目标的所有可执行代码。 |

# 查看 C 库的组件

C 库不是单个库文件。它由四个主要部分组成，共同实现 POSIX 函数 API：

+   `libc`：包含诸如`printf`、`open`、`close`、`read`、`write`等众所周知的 POSIX 函数的主 C 库

+   `libm`：数学函数，如`cos`、`exp`和`log`

+   `libpthread`：所有以`pthread_`开头的 POSIX 线程函数

+   `librt`：POSIX 的实时扩展，包括共享内存和异步 I/O

第一个`libc`总是被链接，但其他的必须使用`-l`选项显式链接。`-l`的参数是去掉`lib`的库名称。因此，例如，通过调用`sin()`计算正弦函数的程序将使用`-lm`链接`libm`：

```
arm-cortex_a8-linux-gnueabihf-gcc myprog.c -o myprog -lm

```

您可以使用`readelf`命令验证已链接到此程序或任何其他程序的库：

```
$ arm-cortex_a8-linux-gnueabihf-readelf -a myprog | grep "Shared library"
0x00000001 (NEEDED)         Shared library: [libm.so.6]
0x00000001 (NEEDED)         Shared library: [libc.so.6]

```

共享库需要运行时链接器，您可以使用以下命令公开它：

```
$ arm-cortex_a8-linux-gnueabihf-readelf -a myprog | grep "program interpreter"
 [Requesting program interpreter: /lib/ld-linux-armhf.so.3]

```

这是如此有用，以至于我有一个包含这些命令的脚本文件：

```
#!/bin/sh
${CROSS_COMPILE}readelf -a $1 | grep "program interpreter"
${CROSS_COMPILE}readelf -a $1 | grep "Shared library"

```

# 链接库：静态和动态链接

您为 Linux 编写的任何应用程序，无论是 C 还是 C++，都将与 C 库 libc 链接。这是如此基本，以至于您甚至不必告诉`gcc`或`g++`去做，因为它总是链接 libc。您可能想要链接的其他库必须通过`-l`选项显式命名。

图书馆代码可以以两种不同的方式链接：静态链接，意味着应用程序调用的所有库函数及其依赖项都从库存档中提取并绑定到可执行文件中；动态链接，意味着代码中生成对库文件和这些文件中的函数的引用，但实际的链接是在运行时动态完成的。

## 静态库

静态链接在一些情况下很有用。例如，如果您正在构建一个仅包含 BusyBox 和一些脚本文件的小型系统，将 BusyBox 静态链接并避免复制运行时库文件和链接器会更简单。它还会更小，因为您只链接应用程序使用的代码，而不是提供整个 C 库。如果您需要在运行时库可用之前运行程序，静态链接也很有用。

通过在命令行中添加`-static`，您可以告诉 gcc 将所有库静态链接起来：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -static helloworld.c -o helloworld-static

```

您会注意到二进制文件的大小大幅增加：

```
$ ls -l
-rwxrwxr-x 1 chris chris   5323 Oct  9 09:01 helloworld
-rwxrwxr-x 1 chris chris 625704 Oct  9 09:01 helloworld-static

```

静态链接从库存档中提取代码，通常命名为`lib[name].a`。在前面的情况下，它是`libc.a`，位于`[sysroot]/usr/lib`中：

```
$ ls -l $(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot)/usr/lib/libc.a
-r--r--r-- 1 chris chris 3434778 Oct  8 14:00 /home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot/usr/lib/libc.a

```

请注意，语法`$(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot)`将程序的输出放在命令行上。我正在使用它作为一种通用方式来引用 sysroot 中的文件。

创建静态库就像使用`ar`命令创建对象文件的存档一样简单。如果我有两个名为`test1.c`和`test2.c`的源文件，并且我想创建一个名为`libtest.a`的静态库，那么我会这样做：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -c test1.c
$ arm-cortex_a8-linux-gnueabihf-gcc -c test2.c
$ arm-cortex_a8-linux-gnueabihf-ar rc libtest.a test1.o test2.o
$ ls -l
total 24
-rw-rw-r-- 1 chris chris 2392 Oct  9 09:28 libtest.a
-rw-rw-r-- 1 chris chris  116 Oct  9 09:26 test1.c
-rw-rw-r-- 1 chris chris 1080 Oct  9 09:27 test1.o
-rw-rw-r-- 1 chris chris  121 Oct  9 09:26 test2.c
-rw-rw-r-- 1 chris chris 1088 Oct  9 09:27 test2.o

```

然后我可以使用以下命令将`libtest`链接到我的`helloworld`程序中：

```
$ arm-cortex_a8-linux-gnueabihf-gcc helloworld.c -ltest -L../libs -I../libs -o helloworld

```

## 共享库

部署库的更常见方式是作为在运行时链接的共享对象，这样可以更有效地使用存储和系统内存，因为只需要加载一份代码副本。这也使得可以轻松更新库文件，而无需重新链接所有使用它们的程序。

共享库的目标代码必须是位置无关的，以便运行时链接器可以自由地将其定位在内存中的下一个空闲地址。为此，使用 gcc 添加`-fPIC`参数，然后使用`-shared`选项进行链接：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -fPIC -c test1.c
$ arm-cortex_a8-linux-gnueabihf-gcc -fPIC -c test2.c
$ arm-cortex_a8-linux-gnueabihf-gcc -shared -o libtest.so test1.o test2.o

```

要将应用程序与此库链接，您需要添加`-ltest`，与前面段落中提到的静态情况完全相同，但是这次代码不包含在可执行文件中，而是有一个对运行时链接器必须解析的库的引用：

```
$ arm-cortex_a8-linux-gnueabihf-gcc helloworld.c -ltest -L../libs -I../libs -o helloworld
$ list-libs helloworld
[Requesting program interpreter: /lib/ld-linux-armhf.so.3]
0x00000001 (NEEDED)                     Shared library: [libtest.so]
0x00000001 (NEEDED)                     Shared library: [libc.so.6]

```

这个程序的运行时链接器是`/lib/ld-linux-armhf.so.3`，必须存在于目标文件系统中。链接器将在默认搜索路径`/lib`和`/usr/lib`中查找`libtest.so`。如果您希望它也在其他目录中查找库，可以在 shell 变量`LD_LIBRARY_PATH`中放置一个以冒号分隔的路径列表：

```
# export LD_LIBRARY_PATH=/opt/lib:/opt/usr/lib

```

### 理解共享库版本号

共享库的一个好处是它们可以独立于使用它们的程序进行更新。库更新有两种类型：修复错误或以向后兼容的方式添加新功能的更新，以及破坏现有应用程序兼容性的更新。GNU/Linux 有一个版本控制方案来处理这两种情况。

每个库都有一个发布版本和一个接口号。发布版本只是一个附加到库名称的字符串，例如 JPEG 图像库 libjpeg 当前发布版本为 8.0.2，因此库的名称为`libjpeg.so.8.0.2`。有一个名为`libjpeg.so`的符号链接指向`libjpeg.so.8.0.2`，因此当您使用`-ljpeg`编译程序时，您将链接到当前版本。如果安装了版本 8.0.3，链接将被更新，您将链接到新版本。

现在，假设出现了版本 9.0.0，并且它破坏了向后兼容性。`libjpeg.so`现在指向`libjpeg.so.9.0.0`，因此任何新程序都将链接到新版本，可能在 libjpeg 接口发生更改时引发编译错误，开发人员可以修复。目标上未重新编译的任何程序都将以某种方式失败，因为它们仍在使用旧接口。这就是`soname`的作用。`soname`在构建库时编码接口号，并在运行时链接器加载库时使用。它的格式为`<库名称>.so.<接口号>`。对于`libjpeg.so.8.0.2`，`soname`是`libjpeg.so.8`：

```
$ readelf -a /usr/lib/libjpeg.so.8.0.2 | grep SONAME
0x000000000000000e (SONAME)             Library soname: [libjpeg.so.8]

```

使用它编译的任何程序都将在运行时请求`libjpeg.so.8`，这将是目标上的一个指向`libjpeg.so.8.0.2`的符号链接。安装 libjpeg 的 9.0.0 版本时，它将具有`soname`为`libjpeg.so.9`，因此可以在同一系统上安装两个不兼容版本的相同库。使用`libjpeg.so.8.*.*`链接的程序将加载`libjpeg.so.8`，而使用`libjpeg.so.9.*.*`链接的程序将加载`libjpeg.so.9`。

这就是为什么当您查看`<sysroot>/usr/lib/libjpeg*`目录列表时，会找到这四个文件：

+   `libjpeg.a`：这是用于静态链接的库存档

+   `libjpeg.so -> libjpeg.so.8.0.2`：这是一个符号链接，用于动态链接

+   `libjpeg.so.8 -> libjpeg.so.8.0.2`：这是在运行时加载库时使用的符号链接

+   `libjpeg.so.8.0.2`：这是实际的共享库，用于编译时和运行时

前两个仅在主机计算机上用于构建，后两个在目标上运行时需要。

# 交叉编译的艺术

拥有可用的交叉工具链只是旅程的起点，而不是终点。在某些时候，您将希望开始交叉编译各种工具、应用程序和库，这些都是您在目标设备上需要的。其中许多是开源软件包，每个软件包都有自己的编译方法和特点。其中一些常见的构建系统包括：

+   纯 makefile，其中工具链由`make`变量`CROSS_COMPILE`控制

+   被称为 Autotools 的 GNU 构建系统

+   CMake ([`cmake.org`](https://cmake.org))

我这里只会涵盖前两个，因为这些是甚至基本嵌入式 Linux 系统所需的。对于 CMake，在前面一点引用的 CMake 网站上有一些很好的资源。

## 简单的 makefile

一些重要的软件包非常容易进行交叉编译，包括 Linux 内核、U-Boot 引导加载程序和 Busybox。对于这些软件包，您只需要将工具链前缀放在`make`变量`CROSS_COMPILE`中，例如`arm-cortex_a8-linux-gnueabi-`。注意末尾的破折号`-`。

因此，要编译 Busybox，您需要键入：

```
$ make CROSS_COMPILE=arm-cortex_a8-linux-gnueabi-

```

或者，您可以将其设置为 shell 变量：

```
$ export CROSS_COMPILE=arm-cortex_a8-linux-gnueabi-
$ make

```

在 U-Boot 和 Linux 的情况下，您还必须将`make`变量`ARCH`设置为它们支持的机器架构之一，我将在第三章和第四章中介绍，*关于引导加载程序*和*移植和配置内核*。

## Autotools

名称 Autotools 指的是一组工具，它们被用作许多开源项目中的构建系统。这些组件以及相应的项目页面是：

+   GNU Autoconf ([`www.gnu.org/software/autoconf/autoconf.html`](http://www.gnu.org/software/autoconf/autoconf.html))

+   GNU Automake ([`www.gnu.org/savannah-checkouts/gnu/automake`](http://www.gnu.org/savannah-checkouts/gnu/automake))

+   GNU Libtool ([`www.gnu.org/software/libtool/libtool.html`](http://www.gnu.org/software/libtool/libtool.html))

+   Gnulib ([`www.gnu.org/software/gnulib`](https://www.gnu.org/software/gnulib))

Autotools 的作用是消除软件包可能编译的许多不同类型系统之间的差异，考虑到不同版本的编译器、不同版本的库、头文件的不同位置以及与其他软件包的依赖关系。使用 Autotools 的软件包附带一个名为`configure`的脚本，该脚本检查依赖关系并根据其发现生成 makefile。配置脚本还可以让您有机会启用或禁用某些功能。您可以通过运行`./configure --help`来查看提供的选项。

要为本机操作系统配置、构建和安装软件包，通常会运行以下三个命令：

```
$ ./configure
$ make
$ sudo make install

```

Autotools 也能够处理交叉开发。您可以通过设置这些 shell 变量来影响配置脚本的行为：

+   `CC`：C 编译器命令

+   `CFLAGS`：额外的 C 编译器标志

+   `LDFLAGS`：额外的链接器标志，例如，如果您在非标准目录`<lib dir>`中有库，则可以通过添加`-L<lib dir>`将其添加到库搜索路径

+   `LIBS`：包含要传递给链接器的额外库的列表，例如数学库`-lm`

+   `CPPFLAGS`：包含 C/C++预处理器标志，例如，您可以添加`-I<include dir>`来在非标准目录`<include dir>`中搜索头文件

+   `CPP`：要使用的 C 预处理器

有时只需设置`CC`变量即可，如下所示：

```
$ CC=arm-cortex_a8-linux-gnueabihf-gcc ./configure

```

在其他时候，这将导致如下错误：

```
[...]
checking whether we are cross compiling... configure: error: in '/home/chris/MELP/build/sqlite-autoconf-3081101':
configure: error: cannot run C compiled programs.
If you meant to cross compile, use '--host'.
See 'config.log' for more details

```

失败的原因是`configure`经常尝试通过编译代码片段并运行它们来发现工具链的功能，以查看发生了什么，如果程序已经进行了交叉编译，这种方法是行不通的。然而，错误消息中有解决问题的提示。Autotools 理解编译软件包时可能涉及的三种不同类型的机器：

+   **构建**：这是用于构建软件包的计算机，默认为当前计算机。

+   **主机**：这是程序将在其上运行的计算机：对于本地编译，这将保持为空白，并且默认为与构建相同的计算机。对于交叉编译，您需要将其设置为您的工具链的元组。

+   **目标**：这是程序将为其生成代码的计算机：例如，构建交叉编译器时会设置这个。

因此，要进行交叉编译，您只需要覆盖主机，如下所示：

```
$ CC=arm-cortex_a8-linux-gnueabihf-gcc \
./configure --host=arm-cortex_a8-linux-gnueabihf

```

最后要注意的一件事是默认安装目录是`<sysroot>/usr/local/*`。通常会将其安装在`<sysroot>/usr/*`中，以便从默认位置获取头文件和库文件。配置典型的 Autotools 软件包的完整命令是：

```
$ CC=arm-cortex_a8-linux-gnueabihf-gcc \
./configure --host=arm-cortex_a8-linux-gnueabihf --prefix=/usr

```

### 例如：SQLite

SQLite 库实现了一个简单的关系型数据库，在嵌入式设备上非常受欢迎。您可以通过获取 SQLite 的副本来开始：

```
$ wget http://www.sqlite.org/2015/sqlite-autoconf-3081101.tar.gz
$ tar xf sqlite-autoconf-3081101.tar.gz
$ cd sqlite-autoconf-3081101

```

接下来，运行配置脚本：

```
$ CC=arm-cortex_a8-linux-gnueabihf-gcc \
./configure --host=arm-cortex_a8-linux-gnueabihf --prefix=/usr

```

看起来好像可以了！如果失败，终端会打印错误消息，并记录在`config.log`中。请注意，已创建了几个 makefile，现在您可以构建它：

```
$ make

```

最后，通过设置`make`变量`DESTDIR`将其安装到工具链目录中。如果不这样做，它将尝试将其安装到主机计算机的`/usr`目录中，这不是您想要的。

```
$ make DESTDIR=$(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot) install

```

您可能会发现最终的命令失败并出现文件权限错误。crosstool-NG 工具链默认为只读，因此在构建时将`CT_INSTALL_DIR_RO`设置为`y`是很有用的。另一个常见问题是工具链安装在系统目录（例如`/opt`或`/usr/local`）中，这种情况下在运行安装时需要 root 权限。

安装后，您应该会发现各种文件已添加到您的工具链中：

+   `<sysroot>/usr/bin`：sqlite3。这是 SQLite 的命令行界面，您可以在目标设备上安装和运行。

+   <`sysroot>/usr/lib`：libsqlite3.so.0.8.6，libsqlite3.so.0，libsqlite3.so，libsqlite3.la，libsqlite3.a。这些是共享和静态库。

+   `<sysroot>/usr/lib/pkgconfig`：`sqlite3.pc`：这是软件包配置文件，如下一节所述。

+   `<sysroot>/usr/lib/include`：`sqlite3.h`，`sqlite3ext.h`：这些是头文件。

+   <`sysroot>/usr/share/man/man1`：sqlite3.1。这是手册页。

现在，您可以在链接阶段添加`-lsqlite3`来编译使用 sqlite3 的程序：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -lsqlite3 sqlite-test.c -o sqlite-test

```

其中，`sqlite-test.c`是一个调用 SQLite 函数的假设程序。由于 sqlite3 已安装到 sysroot 中，编译器将无需任何问题地找到头文件和库文件。如果它们已安装在其他位置，您将需要添加`-L<lib dir>`和`-I<include dir>`。 

当然，还会有运行时依赖关系，您需要将适当的文件安装到目标目录中，如第五章中所述，*构建根文件系统*。

## 软件包配置

跟踪软件包依赖关系非常复杂。软件包配置实用程序`pkg-config`（[`www.freedesktop.org/wiki/Software/pkg-config`](http://www.freedesktop.org/wiki/Software/pkg-config)）通过在`[sysroot]/usr/lib/pkgconfig`中保持 Autotools 软件包的数据库来帮助跟踪已安装的软件包以及每个软件包需要的编译标志。例如，SQLite3 的软件包配置名为`sqlite3.pc`，包含其他需要使用它的软件包所需的基本信息：

```
$ cat $(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot)/usr/lib/pkgconfig/sqlite3.pc
# Package Information for pkg-config
prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include
Name: SQLite
Description: SQL database engine
Version: 3.8.11.1
Libs: -L${libdir} -lsqlite3
Libs.private: -ldl -lpthread
Cflags: -I${includedir}

```

你可以使用`pkg-config`工具来提取信息，以便直接传递给 gcc。对于像 libsqlite3 这样的库，你想要知道库名称(`--libs`)和任何特殊的 C 标志(`--cflags`)：

```
$ pkg-config sqlite3 --libs --cflags
Package sqlite3 was not found in the pkg-config search path.
Perhaps you should add the directory containing `sqlite3.pc'
to the PKG_CONFIG_PATH environment variable
No package 'sqlite3' found

```

哎呀！失败了，因为它在主机的 sysroot 中查找，而主机上没有安装 libsqlite3 的开发包。你需要通过设置 shell 变量`PKG_CONFIG_LIBDIR`将其指向目标工具链的 sysroot：

```
$ PKG_CONFIG_LIBDIR=$(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot)/usr/lib/pkgconfig \
pkg-config sqlite3 --libs --cflags
 -lsqlite3

```

现在输出是`-lsqlite3`。在这种情况下，你已经知道了，但通常情况下你不会知道，所以这是一种有价值的技术。最终的编译命令将是：

```
$ PKG_CONFIG_LIBDIR=$(arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot)/usr/lib/pkgconfig \
arm-cortex_a8-linux-gnueabihf-gcc $(pkg-config sqlite3 --cflags --libs) sqlite-test.c -o sqlite-

```

# 交叉编译的问题

Sqlite3 是一个行为良好的软件包，可以很好地进行交叉编译，但并非所有软件包都如此温顺。典型的痛点包括：

+   自制构建系统，例如 zlib，有一个配置脚本，但它的行为不像前一节中描述的 Autotools 配置。

+   读取`pkg-config`信息、头文件和其他文件的配置脚本，忽略`--host`覆盖

+   坚持尝试运行交叉编译代码的脚本

每种情况都需要仔细分析错误，并向配置脚本提供正确的信息或修补代码以完全避免问题。请记住，一个软件包可能有很多依赖项，特别是对于使用 GTK 或 QT 的图形界面或处理多媒体内容的程序。例如，mplayer 是一个用于播放多媒体内容的流行工具，它依赖于 100 多个库。构建它们将需要数周的努力。

因此，我不建议以这种方式手动交叉编译目标的组件，除非没有其他选择，或者要构建的软件包数量很少。一个更好的方法是使用 Buildroot 或 Yocto Project 等构建工具，或者通过为目标架构设置本地构建环境来完全避免这个问题。现在你可以看到为什么像 Debian 这样的发行版总是本地编译的了。

# 总结

工具链始终是你的起点：从那里开始的一切都依赖于拥有一个工作的、可靠的工具链。

大多数嵌入式构建环境都是基于交叉开发工具链的，它在强大的主机计算机上构建代码，并在运行代码的目标计算机上创建了明确的分离。工具链本身由 GNU binutils、GNU 编译器集合中的 C 编译器，很可能还有 C++编译器，以及我描述过的 C 库之一组成。通常在这一点上会生成 GNU 调试器 gdb，我在第十二章中描述了它，*使用 GDB 进行调试*。此外，要密切关注 Clang 编译器，因为它将在未来几年内发展。

你可能从零开始，只有一个工具链，也许是使用 crosstool-NG 构建的，或者从 Linaro 下载的，并使用它来编译你在目标上需要的所有软件包，接受这将需要大量的辛苦工作。或者，你可以作为一个分发的一部分获得工具链，该分发包括一系列软件包。一个分发可以使用 Buildroot 或 Yocto Project 等构建系统从源代码生成，也可以是来自第三方的二进制分发，也许是像 Mentor Graphics 这样的商业企业，或者是像 Denx ELDK 这样的开源项目。要注意的是，作为硬件包的一部分免费提供给你的工具链或分发通常配置不良且未得到维护。无论如何，你应该根据自己的情况做出选择，然后在整个项目中保持一致。

一旦你有了一个工具链，你就可以用它来构建嵌入式 Linux 系统的其他组件。在下一章中，你将学习关于引导加载程序的知识，它可以让你的设备启动并开始引导过程。


# 第三章：关于引导加载程序的一切

引导加载程序是嵌入式 Linux 的第二个元素。它是启动系统并加载操作系统内核的部分。在本章中，我将研究引导加载程序的作用，特别是它如何使用称为设备树的数据结构将控制权从自身传递给内核，也称为**扁平设备树**或**FDT**。我将介绍设备树的基础知识，以便您能够跟随设备树中描述的连接，并将其与实际硬件联系起来。

我将研究流行的开源引导加载程序 U-Boot，并看看如何使用它来引导目标设备，以及如何定制它以适应新设备。最后，我将简要介绍 Barebox，这是一个与 U-Boot 共享历史的引导加载程序，但可以说它具有更清晰的设计。

# 引导加载程序的作用是什么？

在嵌入式 Linux 系统中，引导加载程序有两个主要任务：基本系统初始化和内核加载。实际上，第一个任务在某种程度上是第二个任务的附属，因为只有在加载内核所需的系统工作正常时才需要。

当执行引导加载程序代码的第一行时，随着通电或复位，系统处于非常基本的状态。DRAM 控制器尚未设置，因此主存储器不可访问，同样，其他接口也尚未配置，因此通过 NAND 闪存控制器、MMC 控制器等访问的存储器也不可用。通常，在开始时仅有一个 CPU 核心和一些芯片上的静态存储器是可操作的。因此，系统引导包括几个代码阶段，每个阶段都将系统的更多部分带入运行。

早期引导阶段在加载内核所需的接口正常工作后停止。这包括主存储器和用于访问内核和其他映像的外围设备，无论是大容量存储还是网络。引导加载程序的最后一步是将内核加载到 RAM 中，并为其创建执行环境。引导加载程序与内核之间的接口细节是特定于体系结构的，但在所有情况下，这意味着传递有关引导加载程序已知的硬件信息的指针，并传递一个内核命令行，这是一个包含 Linux 必要信息的 ASCII 字符串。一旦内核开始执行，引导加载程序就不再需要，并且可以回收它使用的所有内存。

引导加载程序的附属任务是提供维护模式，用于更新引导配置，将新的引导映像加载到内存中，可能运行诊断。这通常由一个简单的命令行用户界面控制，通常通过串行接口。

# 引导序列

在更简单的时代，几年前，只需要将引导加载程序放在处理器的复位向量处的非易失性存储器中。当时 NOR 闪存存储器很常见，由于它可以直接映射到地址空间中，因此是存储的理想方法。以下图表显示了这样的配置，复位向量位于闪存存储器区域的顶端 0xfffffffc 处。引导加载程序被链接，以便在该位置有一个跳转指令，指向引导加载程序代码的开始位置：

![引导序列](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_03_01.jpg)

旧日的引导

从那时起，它可以初始化内存控制器，使主存储器 DRAM 可用，并将自身复制到 DRAM 中。一旦完全运行，引导加载程序可以将内核从闪存加载到 DRAM 中，并将控制权转移给它。

然而，一旦远离像 NOR 闪存这样的简单线性可寻址存储介质，引导序列就变成了一个复杂的多阶段过程。细节对于每个 SoC 都非常具体，但它们通常遵循以下各个阶段。

## 阶段 1：ROM 代码

在没有可靠的外部存储器的情况下，立即在重置或上电后运行的代码必须存储在 SoC 芯片上；这就是所谓的 ROM 代码。它在制造芯片时被编程，因此 ROM 代码是专有的，不能被开源等效物替换。ROM 代码对不在芯片上的任何硬件都可以做出非常少的假设，因为它将与另一个设计不同。这甚至适用于用于主系统内存的 DRAM 芯片。因此，ROM 代码只能访问大多数 SoC 设计中找到的少量静态 RAM（SRAM）。SRAM 的大小从 4 KiB 到几百 KiB 不等：

![第 1 阶段：ROM 代码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_03_02.jpg)

第 1 阶段引导加载程序

ROM 代码能够从几个预编程位置之一加载一小块代码到 SRAM 中。例如，TI OMAP 和 Sitara 芯片将尝试从 NAND 闪存的前几页，或通过 SPI（串行外围接口）连接的闪存，或 MMC 设备的前几个扇区（可能是 eMMC 芯片或 SD 卡），或 MMC 设备的第一个分区上名为`MLO`的文件中加载代码。如果从所有这些存储设备读取失败，那么它将尝试从以太网、USB 或 UART 读取字节流；后者主要用作在生产过程中将代码加载到闪存中，而不是用于正常操作。大多数嵌入式 SoC 都有类似的 ROM 代码工作方式。在 SRAM 不足以加载像 U-Boot 这样的完整引导加载程序的 SoC 中，必须有一个称为二级程序加载器或 SPL 的中间加载器。

在这个阶段结束时，下一阶段的引导加载程序存在于芯片内存中，ROM 代码跳转到该代码的开头。

## 第 2 阶段：SPL

SPL 必须设置内存控制器和系统的其他必要部分，以准备将第三阶段程序加载器（TPL）加载到主内存 DRAM 中。SPL 的功能受其大小限制。它可以从存储设备列表中读取程序，就像 ROM 代码一样，再次使用从闪存设备开始的预编程偏移量，或者像`u-boot.bin`这样的众所周知的文件名。SPL 通常不允许用户交互，但它可以打印版本信息和进度消息，这些消息将显示在控制台上。以下图解释了第 2 阶段的架构：

![第 2 阶段：SPL](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_03_03.jpg)

第二阶段引导

SPL 可能是开源的，就像 TI x-loader 和 Atmel AT91Bootstrap 一样，但它通常包含供应商提供的专有代码，以二进制块的形式提供。

在第二阶段结束时，DRAM 中存在第三阶段加载器，并且 SPL 可以跳转到该区域。

## 第 3 阶段：TPL

现在，最后，我们正在运行像 U-Boot 或 Barebox 这样的完整引导加载程序。通常，有一个简单的命令行用户界面，让您执行维护任务，如将新的引导和内核映像加载到闪存中，加载和引导内核，并且有一种方法可以在没有用户干预的情况下自动加载内核。以下图解释了第 3 阶段的架构：

![第 3 阶段：TPL](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_03_04.jpg)

第三阶段引导

在第三阶段结束时，内存中存在一个等待启动的内核。嵌入式引导加载程序通常在内核运行后从内存中消失，并且在系统操作中不再起任何作用。

# 使用 UEFI 固件引导

大多数嵌入式 PC 设计和一些 ARM 设计都基于通用可扩展固件接口（UEFI）标准的固件，有关更多信息，请参阅官方网站[`www.uefi.org`](http://www.uefi.org)。引导顺序基本上与前一节中描述的相同：

**第一阶段**：处理器从闪存加载 UEFI 引导管理器固件。在某些设计中，它直接从 NOR 闪存加载，而在其他设计中，芯片上有 ROM 代码，它从 SPI 闪存加载引导管理器。引导管理器大致相当于 SPL，但可能允许用户通过基于文本或图形界面进行交互。

**第二阶段**：引导管理器从**EFI 系统分区**（**ESP**）或硬盘或固态硬盘加载引导固件，或通过 PXE 引导从网络服务器加载。如果从本地磁盘驱动器加载，则 EXP 由已知的 GUID 值 C12A7328-F81F-11D2-BA4B-00A0C93EC93B 标识。分区应使用 FAT32 格式进行格式化。第三阶段引导加载程序应该位于名为`<efi_system_partition>/boot/boot<machine_type_short_name>.efi`的文件中。

例如，在 x86_64 系统上加载器的文件路径是：`/efi/boot/bootx64.efi`

**第三阶段**：在这种情况下，TPL 必须是一个能够将 Linux 内核和可选的 RAM 磁盘加载到内存中的引导加载程序。常见选择包括：

+   **GRUB 2**：这是 GNU 统一引导加载程序，第 2 版，是 PC 平台上最常用的 Linux 加载程序。然而，有一个争议，即它根据 GPL v3 许可，这可能使其与安全引导不兼容，因为许可要求提供代码的引导密钥。网站是[`www.gnu.org/software/grub/`](https://www.gnu.org/software/grub/)。

+   **gummiboot**：这是一个简单的与 UEFI 兼容的引导加载程序，已经集成到 systemd 中，并且根据 LGPL v2.1 许可。网站是[`wiki.archlinux.org/index.php/Systemd-boot`](https://wiki.archlinux.org/index.php/Systemd-boot)。

# 从引导加载程序到内核的转移

当引导加载程序将控制权传递给内核时，它必须向内核传递一些基本信息，其中可能包括以下一些内容：

+   在 PowerPC 和 ARM 架构上：一种与 SoC 类型相关的数字

+   迄今为止检测到的硬件的基本细节，包括至少物理 RAM 的大小和位置，以及 CPU 时钟速度

+   内核命令行

+   可选的设备树二进制文件的位置和大小

+   可选的初始 RAM 磁盘的位置和大小

内核命令行是一个纯 ASCII 字符串，用于控制 Linux 的行为，例如设置包含根文件系统的设备。我将在下一章中详细介绍这一点。通常会将根文件系统提供为 RAM 磁盘，在这种情况下，引导加载程序有责任将 RAM 磁盘映像加载到内存中。我将在第五章中介绍创建初始 RAM 磁盘的方法，*构建根文件系统*。

传递这些信息的方式取决于架构，并且近年来发生了变化。例如，对于 PowerPC，引导加载程序过去只是传递一个指向板信息结构的指针，而对于 ARM，它传递了一个指向“A 标签”列表的指针。在`Documentation/arm/Booting`中有关内核源代码格式的良好描述。

在这两种情况下，传递的信息量非常有限，大部分信息需要在运行时发现或硬编码到内核中作为“平台数据”。广泛使用平台数据意味着每个设备都必须有为该平台配置和修改的内核。需要一种更好的方法，这种方法就是设备树。在 ARM 世界中，从 2013 年 2 月发布 Linux 3.8 开始，逐渐摆脱了 A 标签，但仍然有相当多的设备在现场使用，甚至在开发中，仍在使用 A 标签。

# 介绍设备树

你几乎肯定会在某个时候遇到设备树。本节旨在为您快速概述它们是什么以及它们是如何工作的，但有许多细节没有讨论。

设备树是定义计算机系统的硬件组件的灵活方式。通常，设备树由引导加载程序加载并传递给内核，尽管也可以将设备树与内核映像捆绑在一起，以适应不能单独处理它们的引导加载程序。

该格式源自 Sun Microsystems 引导加载程序 OpenBoot，它被正式规范为 Open Firmware 规范，IEEE 标准 IEEE1275-1994。它曾在基于 PowerPC 的 Macintosh 计算机上使用，因此是 PowerPC Linux 端口的一个合乎逻辑的选择。从那时起，它已被许多 ARM Linux 实现大规模采用，并在较小程度上被 MIPS、MicroBlaze、ARC 和其他架构所采用。

我建议访问[`devicetree.org`](http://devicetree.org)获取更多信息。

## 设备树基础

Linux 内核包含大量设备树源文件，位于`arch/$ARCH/boot/dts`，这是学习设备树的良好起点。U-boot 源代码中也有较少数量的源文件，位于`arch/$ARCH/dts`。如果您从第三方获取硬件，则`dts`文件是板支持包的一部分，您应该期望收到其他源文件以及它。

设备树将计算机系统表示为一个层次结构中连接在一起的组件的集合，就像一棵树。设备树以根节点开始，由正斜杠`/`表示，其中包含代表系统硬件的后续节点。每个节点都有一个名称，并包含一些形式为`name = "value"`的属性。这是一个简单的例子：

```
/dts-v1/;
/{
  model = "TI AM335x BeagleBone";
  compatible = "ti,am33xx";
  #address-cells = <1>;
  #size-cells = <1>;
  cpus {
    #address-cells = <1>;
    #size-cells = <0>;
    cpu@0 {
      compatible = "arm,cortex-a8";
      device_type = "cpu";
      reg = <0>;
    };
  };
  memory@0x80000000 {
    device_type = "memory";
    reg = <0x80000000 0x20000000>; /* 512 MB */
  };
};
```

在这里，我们有一个包含`cpus`节点和内存节点的根节点。`cpus`节点包含一个名为`cpu@0`的单个 CPU 节点。通常约定节点的名称包括一个`@`后跟一个地址，用于将其与其他节点区分开。

根节点和 CPU 节点都有一个兼容属性。Linux 内核使用这个属性来将此名称与设备驱动程序中的`struct of_device_id`导出的字符串进行匹配（有关更多信息，请参见第八章，“介绍设备驱动程序”）。这是一个惯例，该值由制造商名称和组件名称组成，以减少不同制造商制造的类似设备之间的混淆，因此`ti,am33xx`和`arm,cortex-a8`。`compatible`通常有多个值，其中有多个驱动程序可以处理此设备。它们按最合适的顺序列出。

CPU 节点和内存节点都有一个`device_type`属性，描述设备的类别。节点名称通常是从`device_type`派生的。

## reg 属性

内存和 CPU 节点都有一个`reg`属性，它指的是寄存器空间中的一系列单元。`reg`属性由两个值组成，表示范围的起始地址和大小（长度）。两者都以零个或多个 32 位整数（称为单元）写下。因此，内存节点指的是从 0x80000000 开始，长度为 0x20000000 字节的单个内存银行。

当地址或大小值无法用 32 位表示时，理解`reg`属性变得更加复杂。例如，在具有 64 位寻址的设备上，每个需要两个单元：

```
/ {
  #address-cells = <2>;
  #size-cells = <2>;
  memory@80000000 {
    device_type = "memory";
    reg = <0x00000000 0x80000000 0 0x80000000>;
  };
}
```

有关所需单元数的信息存储在祖先节点中的`#address-cells`和`#size_cells`声明中。换句话说，要理解`reg`属性，您必须向下查找节点层次结构，直到找到`#address-cells`和`#size_cells`。如果没有，则默认值为每个都是`1` - 但是依赖后备是设备树编写者的不良做法。

现在，让我们回到 cpu 和 cpus 节点。 CPU 也有地址：在四核设备中，它们可能被标记为 0、1、2 和 3。这可以被看作是一个没有深度的一维数组，因此大小为零。因此，你可以看到在 cpus 节点中我们有`#address-cells = <1>`和`#size-cells = <0>`，在子节点`cpu@0`中，我们为`reg`属性分配了一个单一值：节点`reg = <0>`。

## Phandles 和中断

到目前为止，设备树的结构假设存在一个组件的单一层次结构，而实际上存在多个层次结构。除了组件与系统其他部分之间的明显数据连接之外，它还可能连接到中断控制器、时钟源和电压调节器。为了表达这些连接，我们有 phandles。

以一个包含可以生成中断并且中断控制器的串行端口的系统为例：

```
/dts-v1/;
{
  intc: interrupt-controller@48200000 {
    compatible = "ti,am33xx-intc";
    interrupt-controller;
    #interrupt-cells = <1>;
    reg = <0x48200000 0x1000>;
  };
  serial@44e09000 {
    compatible = "ti,omap3-uart";
    ti,hwmods = "uart1";
    clock-frequency = <48000000>;
    reg = <0x44e09000 0x2000>;
    interrupt-parent = <&intc>;
    interrupts = <72>;
  };
};
```

我们有一个中断控制器节点，它有特殊属性`#interrupt-cells`，告诉我们需要多少个 4 字节值来表示一个中断线。在这种情况下，只需要一个给出 IRQ 号码，但通常使用额外的值来描述中断，例如`1 = 低到高边沿触发`，`2 = 高到低边沿触发`，等等。

查看`serial`节点，它有一个`interrupt-parent`属性，引用了它连接到的中断控制器的标签。这就是 phandle。实际的 IRQ 线由`interrupts`属性给出，在这种情况下是`72`。

`serial`节点有其他我们之前没有见过的属性：`clock-frequency`和`ti,hwmods`。这些是特定类型设备的绑定的一部分，换句话说，内核设备驱动程序将读取这些属性来管理设备。这些绑定可以在 Linux 内核源代码的`Documentation/devicetree/bindings/`目录中找到。

## 设备树包含文件

许多硬件在同一系列 SoC 和使用相同 SoC 的板之间是共同的。这在设备树中通过将共同部分拆分为`include`文件来反映，通常使用扩展名`.dtsi`。开放固件标准将`/include/`定义为要使用的机制，就像在`vexpress-v2p-ca9.dts`的这个片段中一样：

```
/include/ "vexpress-v2m.dtsi"
```

在内核的`.dts`文件中查找，你会发现一个借用自 C 的替代`include`语句，例如在`am335x-boneblack.dts`中：

```
#include "am33xx.dtsi"
#include "am335x-bone-common.dtsi"
```

这里是`am33xx.dtsi`的另一个例子：

```
#include <dt-bindings/gpio/gpio.h>
#include <dt-bindings/pinctrl/am33xx.h>
```

最后，`include/dt-bindings/pinctrl/am33xx.h`包含普通的 C 宏：

```
#define PULL_DISABLE (1 << 3)
#define INPUT_EN (1 << 5)
#define SLEWCTRL_SLOW (1 << 6)
#define SLEWCTRL_FAST 0
```

如果设备树源文件使用内核 kbuild 构建，所有这些问题都会得到解决，因为它首先通过 C 预处理器`cpp`运行它们，其中`#include`和`#define`语句被处理成适合设备树编译器的纯文本。先前的示例中显示了这一动机：这意味着设备树源可以使用与内核代码相同的常量定义。

当我们以这种方式包含文件时，节点会叠加在一起，以创建一个复合树，其中外层扩展或修改内层。例如，`am33xx.dtsi`，它适用于所有 am33xx SoC，像这样定义了第一个 MMC 控制器接口：

```
mmc1: mmc@48060000 {
  compatible = "ti,omap4-hsmmc";
  ti,hwmods = "mmc1";
  ti,dual-volt;
  ti,needs-special-reset;
  ti,needs-special-hs-handling;
  dmas = <&edma 24  &edma 25>;
  dma-names = "tx", "rx";
  interrupts = <64>;
  interrupt-parent = <&intc>;
  reg = <0x48060000 0x1000>;
  status = "disabled";
};
```

### 注意

注意，状态是`disabled`，意味着没有设备驱动程序应该绑定到它，而且它有标签`mmc1`。

在`am335x-bone-common.dtsi`中，它被 BeagleBone 和 BeagleBone Black 都包含，相同的节点通过它的 phandle 被引用：

```
&mmc1 {
  status = "okay";
  bus-width = <0x4>;
  pinctrl-names = "default";
  pinctrl-0 = <&mmc1_pins>;
  cd-gpios = <&gpio0 6 GPIO_ACTIVE_HIGH>;
  cd-inverted;
};
```

在这里，`mmc1`被启用（`status="okay"`）因为两个变体都有物理 MMC1 设备，并且`pinctrl`已经建立。然后，在`am335x-boneblack.dts`中，你会看到另一个对`mmc1`的引用，它将其与电压调节器关联起来：

```
&mmc1 {
  vmmc-supply = <&vmmcsd_fixed>;
};
```

因此，像这样分层源文件可以提供灵活性，并减少重复代码的需求。

## 编译设备树

引导加载程序和内核需要设备树的二进制表示，因此必须使用设备树编译器`dtc`进行编译。结果是一个以`.dtb`结尾的文件，称为设备树二进制或设备树 blob。

Linux 源代码中有一个`dtc`的副本，在`scripts/dtc/dtc`中，它也可以作为许多 Linux 发行版的软件包使用。您可以使用它来编译一个简单的设备树（不使用`#include`的设备树）如下：

```
$ dtc simpledts-1.dts -o simpledts-1.dtb
DTC: dts->dts on file "simpledts-1.dts"
```

要注意的是，`dtc`不提供有用的错误消息，它只对语言的基本语法进行检查，这意味着在源文件中调试打字错误可能是一个漫长的过程。

要构建更复杂的示例，您将需要使用内核`kbuild`，如下一章所示。

# 选择引导加载程序

引导加载程序有各种形状和大小。您希望从引导加载程序中获得的特征是它们简单且可定制，并且有许多常见开发板和设备的示例配置。以下表格显示了一些通常使用的引导加载程序：

| 名称 | 架构 |
| --- | --- |
| Das U-Boot | ARM, Blackfin, MIPS, PowerPC, SH |
| Barebox | ARM, Blackfin, MIPS, PowerPC |
| GRUB 2 | X86, X86_64 |
| RedBoot | ARM, MIPS, PowerPC, SH |
| CFE | Broadcom MIPS |
| YAMON | MIPS |

我们将专注于 U-Boot，因为它支持许多处理器架构和大量的个别板和设备。它已经存在很长时间，并且有一个良好的社区支持。

也许您收到了一个与您的 SoC 或板一起的引导加载程序。像往常一样，仔细看看您拥有的东西，并询问您可以从哪里获取源代码，更新政策是什么，如果您想进行更改他们将如何支持您等等。您可能要考虑放弃供应商提供的加载程序，改用开源引导加载程序的当前版本。

# U-Boot

U-Boot，或者以其全名 Das U-Boot，最初是嵌入式 PowerPC 板的开源引导加载程序。然后，它被移植到基于 ARM 的板上，后来又移植到其他架构，包括 MIPS、SH 和 x86。它由 Denx 软件工程托管和维护。有大量的信息可用，一个很好的起点是[www.denx.de/wiki/U-Boot](http://www.denx.de/wiki/U-Boot)。还有一个邮件列表在`<u-boot@lists.denx.de>`。

## 构建 U-Boot

首先要获取源代码。与大多数项目一样，推荐的方法是克隆 git 存档并检出您打算使用的标签，本例中是写作时的当前版本：

```
$ git clone git://git.denx.de/u-boot.git
$ cd u-boot
$ git checkout v2015.07

```

或者，您可以从 ftp://ftp.denx.de/pub/u-boot/获取一个 tarball。

在`configs/`目录中有超过 1,000 个常见开发板和设备的配置文件。在大多数情况下，您可以根据文件名猜出要使用哪个，但您可以通过查看`board/`目录中每个板的`README`文件来获取更详细的信息，或者您可以在适当的网络教程或论坛中找到信息。不过要注意，自 2014.10 版本以来，U-Boot 的配置方式发生了很多变化。请仔细检查您正在遵循的说明是否合适。

以 BeagleBone Black 为例，我们发现在`configs/`中有一个名为`am335x_boneblack_defconfig`的可能配置文件，并且在 am335x 芯片的板`README`文件`board/ti/am335x/README`中找到了文本**该板生成的二进制文件支持...Beaglebone Black**。有了这些知识，为 BeagleBone Black 构建 U-Boot 就很简单了。您需要通过设置`make`变量`CROSS_COMPILE`来告知 U-Boot 交叉编译器的前缀，然后使用`make [board]_defconfig`类型的命令选择配置文件，如下所示：

```
$ make CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- am335x_boneblack_defconfig
$ make CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf-

```

编译的结果是：

+   `u-boot`：这是以 ELF 对象格式的 U-Boot，适合与调试器一起使用

+   `u-boot.map`：这是符号表

+   `u-boot.bin`：这是 U-Boot 的原始二进制格式，适合在设备上运行

+   `u-boot.img`：这是`u-boot.bin`添加了 U-Boot 头的版本，适合上传到正在运行的 U-Boot 副本

+   `u-boot.srec`：这是以 Motorola `srec`格式的 U-Boot，适合通过串行连接传输

BeagleBone Black 还需要一个**Secondary Program Loader**（**SPL**），如前所述。这是同时构建的，命名为`MLO`。

```
$ ls -l MLO u-boot*
-rw-rw-r-- 1 chris chris 76100 Dec 20 11:22 MLO
-rwxrwxr-x 1 chris chris 2548778 Dec 20 11:22 u-boot
-rw-rw-r-- 1 chris chris 449104 Dec 20 11:22 u-boot.bin
-rw-rw-r-- 1 chris chris 449168 Dec 20 11:22 u-boot.img
-rw-rw-r-- 1 chris chris 434276 Dec 20 11:22 u-boot.map
-rw-rw-r-- 1 chris chris 1347442 Dec 20 11:22 u-boot.srec

```

其他目标的过程类似。

## 安装 U-Boot

首次在板上安装引导加载程序需要一些外部帮助。如果板上有硬件调试接口，比如 JTAG，通常可以直接将 U-Boot 的副本加载到 RAM 中并运行。从那时起，您可以使用 U-Boot 命令将其复制到闪存中。这些细节非常依赖于板子，并且超出了本书的范围。

一些 SoC 设计内置了引导 ROM，可以用于从各种外部来源（如 SD 卡、串行接口或 USB）读取引导代码，BeagleBone Black 中的 AM335x 芯片就是这种情况。以下是如何通过 micro-SD 卡加载 U-Boot。

首先，格式化 micro-SD 卡，使第一个分区为 FAT32 格式，并标记为可引导。如果有直接的 SD 卡插槽可用，卡片将显示为`/dev/mmcblk0`，否则，如果使用内存卡读卡器，它将显示为`/dev/sdb`，或`/dev/sdc`等。现在，假设卡片显示为`/dev/mmcblk0`，输入以下命令对 micro-SD 卡进行分区：

```
$ sudo sfdisk -D -H 255 -S 63 /dev/mmcblk0 << EOF 
,9,0x0C,*
,,,-
EOF

```

将第一个分区格式化为`FAT16`：

```
$ sudo mkfs.vfat -F 16 -n boot /dev/mmcblk0p1

```

现在，挂载您刚刚格式化的分区：在某些系统上，只需简单地拔出 micro-SD 卡，然后再插入即可，而在其他系统上，您可能需要单击一个图标。在当前版本的 Ubuntu 上，它应该被挂载为`/media/[user]/boot`，所以我会像这样将 U-Boot 和 SPL 复制到它：

```
cp MLO u-boot.img /media/chris/boot

```

最后，卸载它。

在 BeagleBone 板上没有电源的情况下，插入 micro-SD 卡。

插入串行电缆。串行端口应该出现在您的 PC 上，如`/dev/ttyUSB0`或类似。

启动适当的终端程序，如`gtkterm`、`minicom`或`picocom`，并以 115,200 bps 的速度，无流控制连接到端口：

```
$ gtkterm -p /dev/ttyUSB0 -s 115200

```

按住 Beaglebone 上的**Boot Switch**按钮，使用外部 5V 电源连接器启动板，大约 5 秒后释放按钮。您应该在串行控制台上看到一个 U-Boot 提示：

```
U-Boot#

```

## 使用 U-Boot

在本节中，我将描述一些您可以使用 U-Boot 执行的常见任务。

通常，U-Boot 通过串行端口提供命令行界面。它提供一个为每个板定制的命令提示符。在示例中，我将使用`U-Boot#`。输入`help`会打印出此版本 U-Boot 中配置的所有命令；输入`help <command>`会打印出有关特定命令的更多信息。

默认的命令解释器非常简单。按左右光标键没有命令行编辑；按*Tab*键没有命令完成；按上光标键没有命令历史。按下这些键会中断您当前尝试输入的命令，您将不得不输入`Ctrl`+`C`并重新开始。您唯一可以安全使用的行编辑键是退格键。作为一个选项，您可以配置一个名为 Hush 的不同命令外壳，它具有更复杂的交互式支持。

默认的数字格式是十六进制。例如，如下命令所示：

```
nand read 82000000 400000 200000

```

此命令将从 NAND 闪存的偏移 0x400000 处读取 0x200000 字节，加载到 RAM 地址 0x82000000 处。

### 环境变量

U-Boot 广泛使用环境变量来存储和传递信息，甚至创建脚本。环境变量是简单的`name=value`对，存储在内存的一个区域中。变量的初始填充可以在板配置头文件中编码，如下所示：

```
#define CONFIG_EXTRA_ENV_SETTINGS \
"myvar1=value1\0" \
"myvar2=value2\0"
```

您可以使用`setenv`从 U-Boot 命令行创建和修改变量。例如，`setenv foo bar`会创建变量`foo`，其值为`bar`。请注意，变量名称和值之间没有`=`号。您可以通过将其设置为空字符串`setenv foo`来删除变量。您可以使用`printenv`将所有变量打印到控制台，或者使用`printenv foo`打印单个变量。

通常，可以使用`saveenv`命令将整个环境保存到某种永久存储中。如果有原始 NAND 或 NOR 闪存，则会保留一个擦除块，通常还有另一个用于冗余副本，以防止损坏。如果有 eMMC 或 SD 卡存储，它可以存储在磁盘分区中的文件中。其他选项包括存储在通过 I2C 或 SPI 接口连接的串行 EEPROM 中，或者存储在非易失性 RAM 中。

### 引导映像格式

U-Boot 没有文件系统。相反，它使用 64 字节的标头标记信息块，以便跟踪内容。您可以使用`mkimage`命令为 U-Boot 准备文件。以下是其用法的简要总结：

```
$ mkimage
Usage: mkimage -l image
-l ==> list image header information
mkimage [-x] -A arch -O os -T type -C comp -a addr -e ep -n name -d data_file[:data_file...] image
-A ==> set architecture to 'arch'
-O ==> set operating system to 'os'
-T ==> set image type to 'type'
-C ==> set compression type 'comp'
-a ==> set load address to 'addr' (hex)
-e ==> set entry point to 'ep' (hex)
-n ==> set image name to 'name'
-d ==> use image data from 'datafile'
-x ==> set XIP (execute in place)
mkimage [-D dtc_options] -f fit-image.its fit-image
mkimage -V ==> print version information and exit

```

例如，为 ARM 处理器准备内核映像的命令是：

```
$ mkimage -A arm -O linux -T kernel -C gzip -a 0x80008000 \
-e 0x80008000 -n 'Linux' -d zImage uImage

```

### 加载映像

通常，您将从可移动存储介质（如 SD 卡或网络）加载映像。SD 卡在 U-Boot 中由`mmc`驱动程序处理。将映像加载到内存的典型序列如下：

```
U-Boot# mmc rescan
U-Boot# fatload mmc 0:1 82000000 uimage
reading uimage
4605000 bytes read in 254 ms (17.3 MiB/s)
U-Boot# iminfo 82000000

## Checking Image at 82000000 ...
Legacy image found
Image Name: Linux-3.18.0
Created: 2014-12-23 21:08:07 UTC
Image Type: ARM Linux Kernel Image (uncompressed)
Data Size: 4604936 Bytes = 4.4 MiB
Load Address: 80008000
Entry Point: 80008000
Verifying Checksum ... OK

```

`mmc rescan`命令重新初始化`mmc`驱动程序，也许是为了检测最近插入的 SD 卡。接下来，使用`fatload`从 SD 卡上的 FAT 格式分区中读取文件。格式如下：

`fatload <interface> [<dev[:part]> [<addr> [<filename> [bytes [pos]]]]]`

如果`<interface>`是`mmc`，如我们的情况，`<dev:part>`是从零开始计数的`mmc`接口的设备号，以及从一开始计数的分区号。因此，`<0:1>`是第一个设备上的第一个分区。选择的内存位置`0x82000000`是为了在此时未被使用的 RAM 区域中。如果我们打算引导此内核，我们必须确保在解压缩内核映像并将其定位到运行时位置`0x80008000`时，不会覆盖此 RAM 区域。

要通过网络加载映像文件，您可以使用**Trivial File Transfer Protocol**（**TFTP**）。这需要您在开发系统上安装 TFTP 守护程序 tftpd，并启动它运行。您还必须配置 PC 和目标板之间的任何防火墙，以允许 UDP 端口 69 上的 TFTP 协议通过。tftpd 的默认配置仅允许访问目录`/var/lib/tftpboot`。下一步是将要传输的文件复制到该目录中。然后，假设您使用一对静态 IP 地址，这样就无需进行进一步的网络管理，加载一组内核映像文件的命令序列应如下所示：

```
U-Boot# setenv ipaddr 192.168.159.42
U-Boot# setenv serverip 192.168.159.99
U-Boot# tftp 82000000 uImage
link up on port 0, speed 100, full duplex
Using cpsw device
TFTP from server 192.168.159.99; our IP address is 192.168.159.42
Filename 'uImage'.
Load address: 0x82000000
Loading:
#################################################################
#################################################################
#################################################################
######################################################
3 MiB/s
done
Bytes transferred = 4605000 (464448 hex)

```

最后，让我们看看如何将映像编程到 NAND 闪存中并读取它们，这由`nand`命令处理。此示例通过 TFTP 加载内核映像并将其编程到闪存：

```
U-Boot# fatload mmc 0:1 82000000 uimage
reading uimage
4605000 bytes read in 254 ms (17.3 MiB/s)

U-Boot# nandecc hw
U-Boot# nand erase 280000 400000

NAND erase: device 0 offset 0x280000, size 0x400000
Erasing at 0x660000 -- 100% complete.
OK
U-Boot# nand write 82000000 280000 400000

NAND write: device 0 offset 0x280000, size 0x400000
4194304 bytes written: OK

```

现在您可以使用`nand read`从闪存中加载内核：

```
U-Boot# nand read 82000000 280000 400000

```

## 引导 Linux

`bootm`命令启动内核映像。语法是：

`bootm [内核地址] [ramdisk 地址] [dtb 地址]`。

内核映像的地址是必需的，但如果内核配置不需要 ramdisk 和 dtb，则可以省略 ramdisk 和 dtb 的地址。如果有 dtb 但没有 ramdisk，则第二个地址可以替换为破折号（`-`）。看起来像这样：

```
U-Boot# bootm 82000000 - 83000000

```

### 使用 U-Boot 脚本自动引导

显然，每次打开电源时键入一长串命令来引导板是不可接受的。为了自动化这个过程，U-Boot 将一系列命令存储在环境变量中。如果特殊变量`bootcmd`包含一个脚本，它将在`bootdelay`秒的延迟后在上电时运行。如果你在串行控制台上观看，你会看到延迟倒计时到零。在这段时间内，你可以按任意键终止倒计时，并进入与 U-Boot 的交互会话。

创建脚本的方式很简单，尽管不容易阅读。你只需附加由分号分隔的命令，分号前必须有一个反斜杠转义字符。因此，例如，要从闪存中的偏移加载内核镜像并引导它，你可以使用以下命令：

```
setenv bootcmd nand read 82000000 400000 200000\;bootm 82000000

```

## 将 U-Boot 移植到新板

假设你的硬件部门创建了一个基于 BeagleBone Black 的名为“Nova”的新板，你需要将 U-Boot 移植到它上面。你需要了解 U-Boot 代码的布局以及板配置机制的工作原理。在 2014.10 版本中，U-Boot 采用了与 Linux 内核相同的配置机制，`Kconfig`。在接下来的几个版本中，现有的配置设置将从`include/configs`中的当前位置移动到`Kconfig`文件中。截至 2014.10 版本，每个板都有一个`Kconfig`文件，其中包含从旧的`boards.cfg`文件中提取的最小信息。

你将要处理的主要目录是：

+   `arch`：包含特定于每个支持的架构的代码，位于 arm、mips、powerpc 等目录中。在每个架构中，都有一个家族成员的子目录，例如在`arch/arm/cpu`中，有包括 amt926ejs、armv7 和 armv8 在内的架构变体的目录。

+   `板`: 包含特定于板的代码。如果同一个供应商有多个板，它们可以被收集到一个子目录中，因此基于 BeagelBone 的 am335x evm 板的支持在`board/ti/am335x`中。

+   `公共`: 包含核心功能，包括命令行和可以从中调用的命令，每个命令都在一个名为`cmd_[命令名称].c`的文件中。

+   `doc`：包含几个描述 U-Boot 各个方面的`README`文件。如果你想知道如何进行 U-Boot 移植，这是一个很好的起点。

+   `包括`：除了许多共享的头文件外，这还包括非常重要的子目录`include/configs`，在这里你会找到大部分的板配置设置。随着向`Kconfig`的转变，信息将被移出到`Kconfig`文件中，但在撰写本文时，这个过程才刚刚开始。

## Kconfig 和 U-Boot

`Kconfig`从`Kconfig`文件中提取配置信息，并将总系统配置存储在一个名为`.config`的文件中的方式在第四章中有详细描述，*移植和配置内核*。U-Boot 采用了 kconfig 和 kbuild，并进行了一些更改。一个 U-Boot 构建可以产生最多三个二进制文件：一个`普通的 u-boot.bin`，一个**二级程序加载器**（**SPL**），和一个**三级程序加载器**（**TPL**），每个可能有不同的配置选项。因此，`.config`文件和默认配置文件中的行可以用下表中显示的代码前缀来表示它们适用于哪个目标：

| 无 | 仅普通镜像 |
| --- | --- |
| `S:` | 仅 SPL 镜像 |
| `T:` | 仅 TPL 镜像 |
| `ST:` | SPL 和 TPL 镜像 |
| `+S:` | 普通和 SPL 镜像 |
| `+T:` | 普通和 TPL 镜像 |
| `+ST:` | 普通、SPL 和 TPL 镜像 |

每个板都有一个存储在`configs/[板名称]_defconfig`中的默认配置。对于你的 Nova 板，你需要创建一个名为`nova_defonfig`的文件，并在其中添加这些行：

```
CONFIG_SPL=y
CONFIG_SYS_EXTRA_OPTIONS="SERIAL1,CONS_INDEX=1,EMMC_BOOT"
+S:CONFIG_ARM=y
+S:CONFIG_TARGET_NOVA=y
```

在第一行，`CONFIG_SPL=y`会导致生成 SPL 二进制文件 MLO，`CONFIG_ARM=y`会导致在第三行包含`arch/arm/Kconfig`的内容。在第四行，`CONFIG_TARGET_NOVA=y`选择您的板。请注意，第三行和第四行都以`+S：`为前缀，以便它们适用于 SPL 和普通二进制文件。

您还应该在 ARM 架构的`Kconfig`中添加一个菜单选项，允许人们选择 Nova 作为目标：

```
CONFIG_SPL=y
config TARGET_NOVA
bool "Support Nova!"
```

### 特定于板的文件

每个板都有一个名为`board/[board name]`或`board/[vendor]/[board name]`的子目录，其中应包含：

+   `Kconfig`：包含板的配置选项

+   `MAINTAINERS`：包含有关板当前是否被维护以及如果是的话由谁维护的记录

+   `Makefile`：用于构建特定于板的代码

+   `README`：包含有关 U-Boot 端口的任何有用信息，例如，涵盖了哪些硬件变体

此外，可能还有特定于板的功能的源文件。

您的 Nova 板基于 BeagleBone，而 BeagleBone 又基于 TI AM335x EVM，因此，您可以首先复制 am335x 板文件：

```
$ mkdir board/nova
$ cp -a board/ti/am335x board/nova

```

接下来，更改`Kconfig`文件以反映 Nova 板：

```
if TARGET_NOVA

config SYS_CPU
default "armv7"

config SYS_BOARD
default "nova"

config SYS_SOC
default "am33xx"

config SYS_CONFIG_NAME
default "nova"
endif
```

将`SYS_CPU`设置为`armv7`会导致`arch/arm/cpu/armv7`中的代码被编译和链接。将`SYS_SOC`设置为`am33xx`会导致`arch/arm/cpu/armv7/am33xx`中的代码被包含，将`SYS_BOARD`设置为`nova`会引入`board/nova`，将`SYS_CONFIG_NAME`设置为`nova`意味着头文件`include/configs/nova.h`用于进一步的配置选项。

`board/nova`中还有另一个文件需要更改，即放置在`board/nova/u-boot.lds`的链接器脚本，其中硬编码引用了`board/ti/am335x/built-in.o`。将其更改为使用`nova`本地的副本：

```
diff --git a/board/nova/u-boot.lds b/board/nova/u-boot.lds
index 78f294a..6689b3d 100644
--- a/board/nova/u-boot.lds
+++ b/board/nova/u-boot.lds
@@ -36,7 +36,7 @@ SECTIONS
*(.__image_copy_start)
*(.vectors)
CPUDIR/start.o (.text*)
- board/ti/am335x/built-in.o (.text*)
+ board/nova/built-in.o (.text*)
*(.text*)
}
```

### 配置头文件

每个板在`include/configs`中都有一个头文件，其中包含大部分配置。该文件由板的`Kconfig`中的`SYS_CONFIG_NAME`标识符命名。该文件的格式在 U-Boot 源树顶层的`README`文件中有详细描述。

对于您的 Nova 板，只需将`am335x_evm.h`复制到`nova.h`并进行少量更改：

```
diff --git a/include/configs/nova.h b/include/configs/nova.h
index a3d8a25..8ea1410 100644
--- a/include/configs/nova.h
+++ b/include/configs/nova.h
@@ -1,5 +1,5 @@
/*
- * am335x_evm.h
+ * nova.h, based on am335x_evm.h
*
* Copyright (C) 2011 Texas Instruments Incorporated - http://www.ti.com/
*
@@ -13,8 +13,8 @@
* GNU General Public License for more details.
*/
-#ifndef __CONFIG_AM335X_EVM_H
-#define __CONFIG_AM335X_EVM_H
+#ifndef __CONFIG_NOVA
+#define __CONFIG_NOVA
#include <configs/ti_am335x_common.h>
@@ -39,7 +39,7 @@
#define V_SCLK (V_OSCK)
/* Custom script for NOR */
-#define CONFIG_SYS_LDSCRIPT "board/ti/am335x/u-boot.lds"
+#define CONFIG_SYS_LDSCRIPT "board/nova/u-boot.lds"
/* Always 128 KiB env size */
#define CONFIG_ENV_SIZE (128 << 10)
@@ -50,6 +50,9 @@
#define CONFIG_PARTITION_UUIDS
#define CONFIG_CMD_PART
+#undef CONFIG_SYS_PROMPT
+#define CONFIG_SYS_PROMPT "nova!> "
+
#ifdef CONFIG_NAND
#define NANDARGS \
"mtdids=" MTDIDS_DEFAULT "\0" \
```

## 构建和测试

要为 Nova 板构建，请选择您刚刚创建的配置：

```
$ make CROSS_COMPILE=arm-cortex_a8-linux-gnueabi- nova_defconfig
$ make CROSS_COMPILE=arm-cortex_a8-linux-gnueabi-

```

将`MLO`和`u-boot.img`复制到您之前创建的 micro-SD 卡的 FAT 分区，并启动板。

## 猎鹰模式

我们习惯于现代嵌入式处理器的引导涉及 CPU 引导 ROM 加载 SPL，SPL 加载`u-boot.bin`，然后加载 Linux 内核。您可能想知道是否有办法减少步骤数量，从而简化和加快引导过程。答案是 U-Boot“猎鹰模式”，以游隼命名，据称是所有鸟类中最快的。

这个想法很简单：让 SPL 直接加载内核映像，跳过`u-boot.bin`。没有用户交互，也没有脚本。它只是从 flash 或 eMMC 中的已知位置加载内核到内存中，传递给它一个预先准备好的参数块并启动它运行。配置猎鹰模式的详细信息超出了本书的范围。如果您想了解更多信息，请查看`doc/README.falcon`。

# Barebox

我将以另一个引导加载程序结束这一章，它与 U-Boot 有相同的根源，但对引导加载程序采取了新的方法。它源自 U-Boot，在早期实际上被称为 U-Boot v2。Barebox 的开发人员旨在结合 U-Boot 和 Linux 的最佳部分，包括类似 POSIX 的 API 和可挂载的文件系统。

Barebox 项目网站是[www.barebox.org](http://www.barebox.org)，开发者邮件列表是`<barebox@lists.infradead.org>`。

## 获取 Barebox

要获取 Barebox，克隆 git 存储库并检出您想要使用的版本：

```
$ git clone git://git.pengutronix.de/git/barebox.git
$ cd barebox
$ git checkout v2014.12.0

```

代码的布局类似于 U-Boot：

+   `arch`：包含每个支持的架构的特定代码，其中包括所有主要的嵌入式架构。SoC 支持在`arch/[architecture]/mach-[SoC]`中。对于单独的板支持在`arch/[architecture]/boards`中。

+   `common`：包含核心功能，包括 shell。

+   `commands`：包含可以从 shell 中调用的命令。

+   `Documentation`：包含文档文件的模板。要构建它，输入"`make docs`"。结果放在`Documentation/html`中。

+   `drivers`：包含设备驱动程序的代码。

+   `include`：包含头文件。

## 构建 Barebox

Barebox 长期以来一直使用`kconfig/kbuild`。在`arch/[architecture]/configs`中有默认的配置文件。举个例子，假设你想为 BeagleBoard C4 构建 Barebox。你需要两个配置，一个是 SPL，一个是主二进制文件。首先，构建 MLO：

```
$ make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabi- omap3530_beagle_xload_defconfig
$ make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabi-

```

结果是次级程序加载器 MLO。

接下来，构建 Barebox：

```
$ make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabi- omap3530_beagle_defconfig
$ make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabi-

```

将两者都复制到 SD 卡上：

```
$ cp MLO /media/boot/
$ cp barebox-flash-image /media/boot/barebox.bin

```

然后，启动板子，你应该在控制台上看到这样的消息：

```
barebox 2014.12.0 #1 Wed Dec 31 11:04:39 GMT 2014

Board: Texas Instruments beagle
nand: Trying ONFI probe in 16 bits mode, aborting !
nand: NAND device: Manufacturer ID: 0x2c, Chip ID: 0xba (Micron ), 256MiB, page
size: 2048, OOB size: 64
omap-hsmmc omap3-hsmmc0: registered as omap3-hsmmc0
mci0: detected SD card version 2.0
mci0: registered disk0
malloc space: 0x87bff400 -> 0x87fff3ff (size 4 MiB)
booting from MMC

barebox 2014.12.0 #2 Wed Dec 31 11:08:59 GMT 2014

Board: Texas Instruments beagle
netconsole: registered as netconsole-1
i2c-omap i2c-omap30: bus 0 rev3.3 at 100 kHz
ehci ehci0: USB EHCI 1.00
nand: Trying ONFI probe in 16 bits mode, aborting !
nand: NAND device: Manufacturer ID: 0x2c, Chip ID: 0xba (Micron NAND 256MiB 1,8V
16-bit), 256MiB, page size: 2048, OOB size: 64
omap-hsmmc omap3-hsmmc0: registered as omap3-hsmmc0
mci0: detected SD card version 2.0
mci0: registered disk0
malloc space: 0x85e00000 -> 0x87dfffff (size 32 MiB)
environment load /boot/barebox.env: No such file or directory
Maybe you have to create the partition.
no valid environment found on /boot/barebox.env. Using default environment
running /env/bin/init...

Hit any key to stop autoboot: 0

```

Barebox 正在不断发展。在撰写本文时，它缺乏 U-Boot 所具有的广泛硬件支持，但对于新项目来说是值得考虑的。

# 总结

每个系统都需要一个引导加载程序来启动硬件并加载内核。U-Boot 受到许多开发人员的青睐，因为它支持一系列有用的硬件，并且相对容易移植到新设备上。在过去几年中，嵌入式硬件的复杂性和不断增加的种类导致了设备树的引入，作为描述硬件的一种方式。设备树只是系统的文本表示，编译成**设备树二进制**（**dtb**），并在内核加载时传递给内核。内核需要解释设备树，并加载和初始化设备驱动程序。

在使用中，U-Boot 非常灵活，允许从大容量存储、闪存或网络加载和引导镜像。同样，Barebox 也可以实现相同的功能，但硬件支持的基础较小。尽管其更清晰的设计和受 POSIX 启发的内部 API，但在撰写本文时，它似乎还没有被接受到自己的小而专注的社区之外。

在介绍了一些 Linux 引导的复杂性之后，下一章中你将看到嵌入式项目的第三个元素，内核，进入到过程的下一个阶段。
