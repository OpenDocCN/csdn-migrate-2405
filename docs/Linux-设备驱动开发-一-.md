# Linux 设备驱动开发（一）

> 原文：[`zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E`](https://zh.annas-archive.org/md5/1581478CA24960976F4232EF07514A3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Linux 内核是一款复杂、可移植、模块化且广泛使用的软件，约 80%的服务器和超过一半的全球嵌入式系统都在运行该软件。设备驱动程序在 Linux 系统性能方面起着至关重要的作用。随着 Linux 成为最受欢迎的操作系统之一，对于开发个人设备驱动程序的兴趣也在稳步增长。

设备驱动程序是用户空间和设备之间的链接，通过内核。

本书将从两章开始，帮助您了解驱动程序的基础知识，并为您在 Linux 内核中的漫长旅程做好准备。本书还将涵盖基于 Linux 子系统的驱动程序开发，如内存管理、PWM、RTC、IIO、GPIO、中断请求管理。本书还将涵盖直接内存访问和网络设备驱动程序的实际方法。

本书中的源代码已在 x86 PC 和基于 NXP 的 ARM i.MX6 的 SECO UDOO Quad 上进行了测试，具有足够的功能和连接，可以覆盖本书中讨论的所有测试。还提供了一些驱动程序用于测试廉价组件，如 MCP23016 和 24LC512，它们分别是 I2C GPIO 控制器和 EEPROM 存储器。

通过本书的学习，您将能够熟悉设备驱动程序开发的概念，并能够使用最新的内核版本（写作时为 v4.13）从头开始编写任何设备驱动程序。

# 本书涵盖的内容

第一章，内核开发简介，介绍了 Linux 内核开发过程。本章将讨论下载、配置和编译内核的步骤，适用于 x86 和基于 ARM 的系统。

第二章，设备驱动程序基础，通过内核模块介绍了 Linux 的模块化，并描述了它们的加载/卸载。还描述了驱动程序架构和一些基本概念以及一些内核最佳实践。

第三章，内核设施和辅助函数，介绍了经常使用的内核函数和机制，如工作队列、等待队列、互斥锁、自旋锁，以及其他对于改进驱动程序可靠性有用的设施。

第四章，字符设备驱动程序，侧重于通过字符设备将设备功能导出到用户空间，并使用 IOCTL 接口支持自定义命令。

第五章，平台设备驱动程序，解释了什么是平台设备，并介绍了伪平台总线的概念，以及设备和总线匹配机制。本章以一般方式描述了平台驱动程序架构，以及如何处理平台数据。

第六章，设备树的概念，讨论了向内核提供设备描述的机制。本章解释了设备寻址、资源处理、设备树中支持的每种数据类型及其内核 API。

第七章，I2C 客户端驱动程序，深入探讨了 I2C 设备驱动程序架构、数据结构以及总线上的设备寻址和访问方法。

第八章，SPI 设备驱动程序，描述了基于 SPI 的设备驱动程序架构，以及涉及的数据结构。本章讨论了每个设备的访问方法和具体特性，以及应该避免的陷阱。还讨论了 SPI DT 绑定。

第九章，Regmap API - 寄存器映射抽象，概述了 regmap API 以及它如何抽象底层的 SPI 和 I2C 事务。本章描述了通用 API 以及专用 API。

第十章，IIO 框架，介绍了内核数据采集和测量框架，用于处理数字模拟转换器（DAC）和模拟数字转换器（ADC）。本章介绍了 IIO API，涉及触发缓冲区和连续数据捕获，并介绍了通过 sysfs 接口进行单通道采集。

第十一章，内核内存管理，首先介绍了虚拟内存的概念，以描述整个内核内存布局。本章介绍了内核内存管理子系统，讨论了内存分配和映射，它们的 API 以及涉及这些机制的所有设备，以及内核缓存机制。

第十二章，DMA - 直接内存访问，介绍了 DMA 及其新的内核 API：DMA 引擎 API。本章将讨论不同的 DMA 映射，并描述如何解决缓存一致性问题。此外，本章还总结了基于 NXP 的 i.MX6 SoC 的使用案例中使用的所有概念。

第十三章，Linux 设备模型，概述了 Linux 的核心，描述了内核中对象的表示方式，以及 Linux 是如何设计的，从 kobject 到设备，通过总线、类和设备驱动程序。本章还突出了用户空间中不为人知的一面，即 sysfs 中的内核对象层次结构。

第十四章，引脚控制和 GPIO 子系统，描述了内核引脚控制 API 和 GPIOLIB，这是处理 GPIO 的内核 API。本章还讨论了旧的和已弃用的基于整数的 GPIO 接口，以及基于描述符的接口，这是新的接口，最后讨论了它们如何在设备树中进行配置。

第十五章，GPIO 控制器驱动程序 - gpio_chip，编写此类设备驱动程序所需的必要元素。也就是说，它的主要数据结构是 struct gpio_chip。本章详细解释了这个结构，以及书籍源代码中提供的完整可用的驱动程序。

第十六章，高级中断请求（IRQ）管理，揭开了 Linux IRQ 核心的神秘面纱。本章介绍了 Linux IRQ 管理，从系统中断传播开始，移动到中断控制器驱动程序，因此解释了 IRQ 多路复用的概念，使用 Linux IRQ 域 API。

第十七章，输入设备驱动程序，提供了输入子系统的全局视图，处理基于 IRQ 和轮询的输入设备，并介绍了两种 API。本章解释并展示了用户空间代码如何处理这些设备。

第十八章，RTC 驱动程序，深入讲解了 RTC 子系统及其 API。本章还详细解释了如何在 RTC 驱动程序中处理闹钟。

第十九章，PWM 驱动程序，全面描述了 PWM 框架，讨论了控制器端 API 和消费者端 API。本章最后一节讨论了来自用户空间的 PWM 管理。

第二十章，调节器框架，突出了电源管理的重要性。本章的第一部分涉及电源管理 IC（PMIC），并解释了其驱动程序设计和 API。第二部分侧重于消费者方面，讨论了请求和使用调节器。

第二十一章，帧缓冲驱动程序，解释了帧缓冲的概念及其工作原理。它还展示了如何设计帧缓冲驱动程序，介绍了其 API，并讨论了加速和非加速方法。本章展示了驱动程序如何公开帧缓冲内存，以便用户空间可以在其中写入，而不必担心底层任务。

*第二十二章，网络接口卡驱动程序*，介绍了 NIC 驱动程序的架构及其数据结构，从而向您展示如何处理设备配置、数据传输和套接字缓冲区。

# 本书所需的内容

本书假定读者对 Linux 操作系统有中等水平的理解，对 C 编程有基本的知识（至少要能处理指针）。就是这样。如果某一章需要额外的技能，文档中会提供链接，帮助读者快速学习这些技能。

Linux 内核编译是一个相当长而繁重的任务。最低硬件或虚拟要求如下：

+   CPU：4 核

+   内存：4 GB RAM

+   免费磁盘空间：5 GB（足够大）

在本书中，您将需要以下软件清单：

+   Linux 操作系统：最好是基于 Debian 的发行版，例如本书中使用的 Ubuntu 16.04

+   至少需要 gcc 和 gcc-arm-linux 的 5 版本（在书中使用）

其他必要的软件包在书中的专用章节中有描述。需要互联网连接以下载内核源代码。

# 本书适合对象

为了充分利用本书的内容，需要具备基本的 C 编程和基本的 Linux 命令知识。本书涵盖了广泛使用的嵌入式设备的 Linux 驱动程序开发，使用内核版本 v4.1，并覆盖了撰写本书时的最新版本的更改（v4.13）。本书主要面向嵌入式工程师、Linux 系统管理员、开发人员和内核黑客。无论您是软件开发人员、系统架构师还是愿意深入研究 Linux 驱动程序开发的制造商，本书都适合您。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`.name`字段必须与您在特定文件中注册设备时给出的设备名称相同”。

代码块设置如下：

```
#include <linux/of.h> 
#include <linux/of_device.h> 
```

任何命令行输入或输出都以以下方式编写：

```
 sudo apt-get update

 sudo apt-get install linux-headers-$(uname -r)

```

**新术语**和**重要单词**以粗体显示。

警告或重要说明显示如下。

提示和技巧显示如下。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对本书的看法-您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出您真正能充分利用的标题。要向我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在主题中提及书名。如果您在某个主题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有很多东西可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的“支持”选项卡上。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地方。

1.  单击“代码下载”。

下载文件后，请确保使用最新版本解压文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Linux-Device-Drivers-Development`](https://github.com/PacktPublishing/Linux-Device-Drivers-Development)。我们还有其他丰富的图书和视频代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。彩色图片将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/LinuxDeviceDriversDevelopment_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/LinuxDeviceDriversDevelopment_ColorImages.pdf)下载此文件。

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击勘误提交表单链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误部分下的任何现有勘误列表中。要查看以前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在勘误部分下。

# 盗版

互联网上盗版受版权保护的材料是一个持续存在的问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。感谢您帮助我们保护我们的作者和我们为您提供有价值内容的能力。

# 问题

如果您对本书的任何方面有问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：内核开发简介

Linux 是 1991 年芬兰学生 Linus Torvalds 的一个业余项目。该项目逐渐增长，现在仍在增长，全球大约有 1000 名贡献者。如今，Linux 在嵌入式系统和服务器上都是必不可少的。内核是操作系统的核心部分，它的开发并不那么明显。

Linux 相对于其他操作系统有很多优势：

+   免费

+   有着完善的文档和庞大的社区

+   在不同平台上可移植

+   提供对源代码的访问

+   大量免费开源软件

这本书试图尽可能通用。有一个特殊的主题，设备树，它还不是完全的 x86 特性。这个主题将专门用于 ARM 处理器，以及所有完全支持设备树的处理器。为什么选择这些架构？因为它们在台式机和服务器（对于 x86）以及嵌入式系统（ARM）上最常用。

本章主要涉及以下内容：

+   开发环境设置

+   获取、配置和构建内核源代码

+   内核源代码组织

+   内核编码风格简介

# 环境设置

在开始任何开发之前，你需要设置一个环境。至少在基于 Debian 的系统上，专门用于 Linux 开发的环境是相当简单的：

```
 $ sudo apt-get update

 $ sudo apt-get install gawk wget git diffstat unzip texinfo \

 gcc-multilib build-essential chrpath socat libsdl1.2-dev \

 xterm ncurses-dev lzop

```

本书中的一些代码部分与 ARM**系统芯片**（**SoC**）兼容。你也应该安装`gcc-arm`：

```
 sudo apt-get install gcc-arm-linux-gnueabihf

```

我正在一台 ASUS RoG 上运行 Ubuntu 16.04，配备英特尔 i7 处理器（8 个物理核心），16GB 内存，256GB 固态硬盘和 1TB 磁性硬盘。我的最爱编辑器是 Vim，但你可以自由选择你最熟悉的编辑器。

# 获取源代码

在早期的内核版本（直到 2003 年），使用了奇数-偶数版本样式；奇数版本是稳定的，偶数版本是不稳定的。当 2.6 版本发布时，版本方案切换为 X.Y.Z，其中：

+   `X`：这是实际内核的版本，也称为主要版本，当有不兼容的 API 更改时会增加。

+   `Y`：这是次要修订版本，当以向后兼容的方式添加功能时增加。

+   `Z`：这也被称为 PATCH，表示与错误修复相关的版本

这被称为语义版本控制，一直使用到 2.6.39 版本；当 Linus Torvalds 决定将版本号提升到 3.0 时，这也意味着 2011 年语义版本控制的结束，然后采用了 X.Y 方案。

当到了 3.20 版本时，Linus 认为他不能再增加 Y 了，并决定切换到任意的版本方案，当 Y 变得足够大以至于他数不过来时，就增加 X。这就是为什么版本从 3.20 直接变成了 4.0 的原因。请看：[`plus.google.com/+LinusTorvalds/posts/jmtzzLiiejc`](https://plus.google.com/+LinusTorvalds/posts/jmtzzLiiejc)。

现在内核使用任意的 X.Y 版本方案，与语义版本控制无关。

# 源代码组织

对于本书的需求，你必须使用 Linus Torvald 的 Github 存储库。

```
 git clone https://github.com/torvalds/linux
 git checkout v4.1
 ls

```

+   `arch/`：Linux 内核是一个快速增长的项目，支持越来越多的架构。也就是说，内核希望尽可能地通用。架构特定的代码与其他代码分开，并放在这个目录中。该目录包含处理器特定的子目录，如`alpha/`，`arm/`，`mips/`，`blackfin/`等。

+   `block/`：这个目录包含块存储设备的代码，实际上是调度算法。

+   `crypto/`：这个目录包含加密 API 和加密算法代码。

+   `Documentation/`：这应该是你最喜欢的目录。它包含了用于不同内核框架和子系统的 API 描述。在向论坛提问之前，你应该先在这里查找。

+   `drivers/`：这是最重的目录，随着设备驱动程序的合并而不断增长。它包含各种子目录中组织的每个设备驱动程序。

+   `fs/`：此目录包含内核实际支持的不同文件系统的实现，如 NTFS，FAT，ETX{2,3,4}，sysfs，procfs，NFS 等。

+   `include/`：这包含内核头文件。

+   `init/`：此目录包含初始化和启动代码。

+   `ipc/`：这包含**进程间通信**（**IPC**）机制的实现，如消息队列，信号量和共享内存。

+   `kernel/`：此目录包含基本内核的与体系结构无关的部分。

+   `lib/`：库例程和一些辅助函数位于此处。它们是：通用**内核对象**（**kobject**）处理程序和**循环冗余码**（**CRC**）计算函数等。

+   `mm/`：这包含内存管理代码。

+   `net/`：这包含网络（无论是什么类型的网络）协议代码。

+   `scripts/`：这包含内核开发期间使用的脚本和工具。这里还有其他有用的工具。

+   `security/`：此目录包含安全框架代码。

+   `sound/`：音频子系统代码位于此处。

+   `usr/：`目前包含 initramfs 实现。

内核必须保持可移植性。任何特定于体系结构的代码应位于`arch`目录中。当然，与用户空间 API 相关的内核代码不会改变（系统调用，`/proc`，`/sys`），因为这会破坏现有的程序。

该书涉及内核 4.1 版本。因此，任何更改直到 v4.11 版本都会被覆盖，至少可以这样说关于框架和子系统。

# 内核配置

Linux 内核是一个基于 makefile 的项目，具有数千个选项和驱动程序。要配置内核，可以使用`make menuconfig`进行基于 ncurse 的界面，或者使用`make xconfig`进行基于 X 的界面。一旦选择，选项将存储在源树的根目录中的`.config`文件中。

在大多数情况下，不需要从头开始配置。在每个`arch`目录中都有默认和有用的配置文件，可以用作起点：

```
 ls arch/<you_arch>/configs/ 

```

对于基于 ARM 的 CPU，这些配置文件位于`arch/arm/configs/`中，对于 i.MX6 处理器，默认文件配置为`arch/arm/configs/imx_v6_v7_defconfig`。同样，对于 x86 处理器，我们在`arch/x86/configs/`中找到文件，只有两个默认配置文件，`i386_defconfig`和`x86_64_defconfig`，分别用于 32 位和 64 位版本。对于 x86 系统来说，这是非常简单的：

```
make x86_64_defconfig 
make zImage -j16 
make modules 
makeINSTALL_MOD_PATH </where/to/install> modules_install

```

给定一个基于 i.MX6 的板，可以从`ARCH=arm make imx_v6_v7_defconfig`开始，然后`ARCH=arm make menuconfig`。使用前一个命令，您将把默认选项存储在`.config`文件中，使用后一个命令，您可以根据需要更新添加/删除选项。

在使用`xconfig`时可能会遇到 Qt4 错误。在这种情况下，应该使用以下命令：

```
sudo apt-get install  qt4-dev-tools qt4-qmake

```

# 构建您的内核

构建内核需要您指定为其构建的体系结构，以及编译器。也就是说，对于本地构建并非必需。

```
ARCH=arm make imx_v6_v7_defconfig

ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make zImage -j16

```

之后，将看到类似以下内容：

```
    [...]

      LZO     arch/arm/boot/compressed/piggy_data

      CC      arch/arm/boot/compressed/misc.o

      CC      arch/arm/boot/compressed/decompress.o

      CC      arch/arm/boot/compressed/string.o

      SHIPPED arch/arm/boot/compressed/hyp-stub.S

      SHIPPED arch/arm/boot/compressed/lib1funcs.S

      SHIPPED arch/arm/boot/compressed/ashldi3.S

      SHIPPED arch/arm/boot/compressed/bswapsdi2.S

      AS      arch/arm/boot/compressed/hyp-stub.o

      AS      arch/arm/boot/compressed/lib1funcs.o

      AS      arch/arm/boot/compressed/ashldi3.o

      AS      arch/arm/boot/compressed/bswapsdi2.o

      AS      arch/arm/boot/compressed/piggy.o

      LD      arch/arm/boot/compressed/vmlinux

      OBJCOPY arch/arm/boot/zImage

      Kernel: arch/arm/boot/zImage is ready

```

从内核构建中，结果将是一个单一的二进制映像，位于`arch/arm/boot/`中。模块使用以下命令构建：

```
 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make modules

```

您可以使用以下命令安装它们：

```
ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make modules_install

```

`modules_install`目标需要一个环境变量`INSTALL_MOD_PATH`，指定应该在哪里安装模块。如果未设置，模块将安装在`/lib/modules/$(KERNELRELEASE)/kernel/`中。这在第二章 *设备驱动程序基础*中讨论过。

i.MX6 处理器支持设备树，这是用来描述硬件的文件（这在第六章中详细讨论），但是，要编译每个`ARCH`设备树，可以运行以下命令：

```
ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make dtbs

```

但是，并非所有支持设备树的平台都支持`dtbs`选项。要构建一个独立的 DTB，您应该使用：

```
ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- make imx6d-    sabrelite.dtb

```

# 内核习惯

内核代码试图遵循标准规则。在本章中，我们只是介绍它们。它们都在专门的章节中讨论，从[第三章](http://post)开始，*内核设施和辅助函数*，我们可以更好地了解内核开发过程和技巧，直到[第十三章](http://post1)，*Linux 设备模型*。

# 编码风格

在深入研究本节之前，您应始终参考内核编码风格手册，位于内核源树中的`Documentation/CodingStyle`。这种编码风格是一组规则，您至少应该遵守这些规则，如果需要内核开发人员接受其补丁。其中一些规则涉及缩进、程序流程、命名约定等。

最流行的是：

+   始终使用 8 个字符的制表符缩进，并且每行应为 80 列长。如果缩进阻止您编写函数，那是因为该函数的嵌套级别太多。可以使用内核源代码中的`scripts/cleanfile`脚本调整制表符大小并验证行大小：

```
scripts/cleanfile my_module.c 
```

+   您还可以使用`indent`工具正确缩进代码：

```
      sudo apt-get install indent

 scripts/Lindent my_module.c

```

+   每个未导出的函数/变量都应声明为静态的。

+   在括号表达式（内部）周围不应添加空格。*s = size of (struct file)*；是可以接受的，而*s = size of( struct file )*；是不可以接受的。

+   禁止使用`typdefs`。

+   始终使用`/* this */`注释样式，而不是`// this`

+   +   不好：`// 请不要使用这个`

+   好的：`/* 内核开发人员喜欢这样 */`

+   宏应该大写，但功能宏可以小写。

+   注释不应该替换不可读的代码。最好重写代码，而不是添加注释。

# 内核结构分配/初始化

内核始终为其数据结构和设施提供两种可能的分配机制。

其中一些结构包括：

+   工作队列

+   列表

+   等待队列

+   Tasklet

+   定时器

+   完成

+   互斥锁

+   自旋锁

动态初始化器都是宏，这意味着它们始终大写：`INIT_LIST_HEAD()`，`DECLARE_WAIT_QUEUE_HEAD()`，`DECLARE_TASKLET()`等等。

说到这一点，所有这些都在第三章中讨论，*内核设施和辅助函数*。因此，代表框架设备的数据结构始终是动态分配的，每个数据结构都有自己的分配和释放 API。这些框架设备类型包括：

+   网络

+   输入设备

+   字符设备

+   IIO 设备

+   类

+   帧缓冲

+   调节器

+   PWM 设备

+   RTC

静态对象的作用域在整个驱动程序中可见，并且由此驱动程序管理的每个设备都可见。动态分配的对象仅由实际使用给定模块实例的设备可见。

# 类、对象和 OOP

内核通过设备和类来实现 OOP。内核子系统通过类进行抽象。几乎每个子系统都有一个`/sys/class/`下的目录。`struct kobject`结构是这种实现的核心。它甚至带有一个引用计数器，以便内核可以知道实际使用对象的用户数量。每个对象都有一个父对象，并且在`sysfs`中有一个条目（如果已挂载）。

每个属于特定子系统的设备都有一个指向**操作**（**ops**）结构的指针，该结构公开了可以在此设备上执行的操作。

# 摘要

本章以非常简短和简单的方式解释了如何下载 Linux 源代码并进行第一次构建。它还涉及一些常见概念。也就是说，这一章非常简短，可能不够，但没关系，这只是一个介绍。这就是为什么下一章会更深入地介绍内核构建过程，如何实际编译驱动程序，无论是作为外部模块还是作为内核的一部分，以及在开始内核开发这段漫长旅程之前应该学习的一些基础知识。


# 第二章：设备驱动程序基础

驱动程序是一种旨在控制和管理特定硬件设备的软件。因此得名设备驱动程序。从操作系统的角度来看，它可以在内核空间（以特权模式运行）或用户空间（权限较低）中。本书只涉及内核空间驱动程序，特别是 Linux 内核驱动程序。我们的定义是设备驱动程序向用户程序公开硬件的功能。

这本书的目的不是教你如何成为 Linux 大师——我自己也不是——但在编写设备驱动程序之前，你应该了解一些概念。C 编程技能是必需的；你至少应该熟悉指针。你还应该熟悉一些操作函数。还需要一些硬件技能。因此，本章主要讨论：

+   模块构建过程，以及它们的加载和卸载

+   驱动程序骨架和调试消息管理

+   驱动程序中的错误处理

# 用户空间和内核空间

内核空间和用户空间的概念有点抽象。这一切都与内存和访问权限有关。人们可能认为内核是特权的，而用户应用程序是受限制的。这是现代 CPU 的一个特性，允许它在特权或非特权模式下运行。这个概念在[第十一章](http://post%2011) *内核内存管理*中会更清楚。

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00004.jpg)

用户空间和内核空间

前面的图介绍了内核空间和用户空间之间的分离，并强调了系统调用代表它们之间的桥梁（我们稍后在本章讨论这一点）。可以描述每个空间如下：

+   **内核空间：**这是内核托管和运行的一组地址。内核内存（或内核空间）是一段内存范围，由内核拥有，受到访问标志的保护，防止任何用户应用程序无意中干扰内核。另一方面，内核可以访问整个系统内存，因为它以更高的优先级在系统上运行。在内核模式下，CPU 可以访问整个内存（包括内核空间和用户空间）。

+   **用户空间：**这是正常程序（如 gedit 等）受限制运行的一组地址（位置）。你可以把它看作是一个沙盒或监狱，这样用户程序就不能干扰其他程序拥有的内存或其他资源。在用户模式下，CPU 只能访问带有用户空间访问权限标记的内存。用户应用程序运行的优先级较低。当进程执行系统调用时，会向内核发送软件中断，内核会打开特权模式，以便进程可以在内核空间中运行。当系统调用返回时，内核关闭特权模式，进程再次被限制。

# 模块的概念

模块对于 Linux 内核来说就像插件（Firefox 就是一个例子）对于用户软件一样。它动态扩展了内核的功能，甚至不需要重新启动计算机。大多数情况下，内核模块都是即插即用的。一旦插入，它们就可以被使用。为了支持模块，内核必须已经使用以下选项构建：

```
CONFIG_MODULES=y 
```

# 模块依赖

在 Linux 中，模块可以提供函数或变量，并使用`EXPORT_SYMBOL`宏导出它们，使它们对其他模块可用。这些被称为符号。模块 B 对模块 A 的依赖是，模块 B 使用了模块 A 导出的符号之一。

# depmod 实用程序

`depmod` 是在内核构建过程中运行的工具，用于生成模块依赖文件。它通过读取`/lib/modules/<kernel_release>/`中的每个模块来确定它应该导出哪些符号以及它需要哪些符号。该过程的结果被写入文件`modules.dep`，以及它的二进制版本`modules.dep.bin`。它是一种模块索引。

# 模块加载和卸载

要使模块运行，应该将其加载到内核中，可以使用`insmod`给定模块路径作为参数来实现，这是开发过程中首选的方法，也可以使用`modprobe`，这是一个聪明的命令，但在生产系统中更受欢迎。

# 手动加载

手动加载需要用户的干预，用户应该具有 root 访问权限。实现这一点的两种经典方法如下所述：

# modprobe 和 insmod

在开发过程中，通常使用`insmod`来加载模块，并且应该给出要加载的模块的路径：

```
insmod /path/to/mydrv.ko

```

这是一种低级形式的模块加载，它构成了其他模块加载方法的基础，也是本书中我们将使用的方法。另一方面，有`modprobe`，主要由系统管理员或在生产系统中使用。`modprobe`是一个聪明的命令，它解析文件`modules.dep`以便先加载依赖项，然后再加载给定的模块。它自动处理模块依赖关系，就像软件包管理器一样：

```
modprobe mydrv

```

是否可以使用`modprobe`取决于`depmod`是否知道模块安装。

# /etc/modules-load.d/<filename>.conf

如果您希望某个模块在启动时加载，只需创建文件`/etc/modules-load.d/<filename>.conf`，并添加应该加载的模块名称，每行一个。`<filename>`应该对您有意义，人们通常使用模块：`/etc/modules-load.d/modules.conf`。您可以根据需要创建多个`.conf`文件：

`/etc/modules-load.d/mymodules.conf`的一个例子如下：

```
#this line is a comment 
uio 
iwlwifi 
```

# 自动加载

`depmod`实用程序不仅构建`modules.dep`和`modules.dep.bin`文件。它做的不仅仅是这些。当内核开发人员实际编写驱动程序时，他们确切地知道驱动程序将支持哪些硬件。然后他们负责为驱动程序提供所有受支持设备的产品和供应商 ID。`depmod`还处理模块文件以提取和收集这些信息，并生成一个`modules.alias`文件，位于`/lib/modules/<kernel_release>/modules.alias`，它将设备映射到它们的驱动程序：

`modules.alias`的摘录如下：

```
alias usb:v0403pFF1Cd*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0403pFF18d*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0403pDAFFd*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0403pDAFEd*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0403pDAFDd*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0403pDAFCd*dc*dsc*dp*ic*isc*ip*in* ftdi_sio 
alias usb:v0D8Cp0103d*dc*dsc*dp*ic*isc*ip*in* snd_usb_audio 
alias usb:v*p*d*dc*dsc*dp*ic01isc03ip*in* snd_usb_audio 
alias usb:v200Cp100Bd*dc*dsc*dp*ic*isc*ip*in* snd_usb_au 
```

在这一步，您将需要一个用户空间热插拔代理（或设备管理器），通常是`udev`（或`mdev`），它将向内核注册，以便在新设备出现时得到通知。

内核通过发送设备的描述（pid、vid、class、device class、device subclass、interface 以及可能标识设备的所有其他信息）来通知，这些信息发送到热插拔守护程序，它再调用`modprobe`来处理这些信息。`modprobe`然后解析`modules.alias`文件以匹配与设备关联的驱动程序。在加载模块之前，`modprobe`将在`module.dep`中查找它的依赖项。如果找到任何依赖项，那么在加载相关模块之前将加载依赖项；否则，模块将直接加载。

# 模块卸载

卸载模块的常用命令是`rmmod`。应该优先使用此命令来卸载使用`insmod`命令加载的模块。应该将模块名称作为参数给出。模块卸载是一个内核功能，可以根据`CONFIG_MODULE_UNLOAD`配置选项的值来启用或禁用。如果没有此选项，将无法卸载任何模块。让我们启用模块卸载支持：

```
CONFIG_MODULE_UNLOAD=y 
```

在运行时，内核将阻止卸载可能破坏事物的模块，即使有人要求这样做。这是因为内核保持对模块使用的引用计数，以便它知道模块是否实际上正在使用。如果内核认为移除模块是不安全的，它就不会这样做。显然，人们可以改变这种行为：

```
MODULE_FORCE_UNLOAD=y 
```

为了强制模块卸载，应该在内核配置中设置前述选项：

```
rmmod -f mymodule

```

另一方面，以智能方式卸载模块的更高级命令是`modeprobe -r`，它会自动卸载未使用的依赖项：

```
modeprobe -r mymodule

```

正如你可能已经猜到的，这对开发人员来说是一个非常有帮助的选项。最后，可以使用以下命令检查模块是否已加载：

```
lsmod

```

# 驱动程序骨架

让我们考虑以下`helloworld`模块。它将成为本章其余部分工作的基础：

helloworld.c

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/kernel.h> 

static int __init helloworld_init(void) { 
    pr_info("Hello world!\n"); 
    return 0; 
} 

static void __exit helloworld_exit(void) { 
    pr_info("End of the world\n"); 
} 

module_init(helloworld_init); 
module_exit(helloworld_exit); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

# 模块入口和出口点

内核驱动程序都有入口和出口点：前者对应于模块加载时调用的函数（`modprobe`，`insmod`），后者是在模块卸载时执行的函数（在`rmmod`或`modprobe -r`中）。

我们都记得`main()`函数，它是每个以 C/C++编写的用户空间程序的入口点，当该函数返回时程序退出。对于内核模块，情况有所不同。入口点可以有任何你想要的名称，而不像用户空间程序在`main()`返回时退出，出口点是在另一个函数中定义的。你需要做的就是告诉内核哪些函数应该作为入口或出口点执行。实际的函数`hellowolrd_init`和`hellowolrd_exit`可以被赋予任何名称。实际上，唯一强制的是将它们标识为相应的加载和卸载函数，并将它们作为参数传递给`module_init()`和`module_exit()`宏。

总之，`module_init()`用于声明在加载模块（使用`insmod`或`modprobe`）时应调用的函数。初始化函数中所做的事情将定义模块的行为。`module_exit()`用于声明在卸载模块（使用`rmmod`）时应调用的函数。

无论是`init`函数还是`exit`函数，在模块加载或卸载后都只运行一次。

# `__init`和`__exit`属性

`__init`和`__exit`实际上是内核宏，在`include/linux/init.h`中定义，如下所示：

```
#define __init__section(.init.text) 
#define __exit__section(.exit.text) 
```

`__init`关键字告诉链接器将代码放置在内核对象文件的一个专用部分中。这个部分对内核是预先知道的，并且在模块加载和`init`函数完成后被释放。这仅适用于内置驱动程序，而不适用于可加载模块。内核将在其引导序列期间首次运行驱动程序的初始化函数。

由于驱动程序无法卸载，其初始化函数直到下次重启之前都不会再次被调用。不再需要保留对其初始化函数的引用。对于`__exit`关键字也是一样，当模块被静态编译到内核中时，或者未启用模块卸载支持时，其对应的代码将被省略，因为在这两种情况下，`exit`函数永远不会被调用。`__exit`对可加载模块没有影响。

让我们花更多时间了解这些属性是如何工作的。这一切都关于名为**可执行和可链接格式**（**ELF**）的对象文件。一个 ELF 对象文件由各种命名的部分组成。其中一些是强制性的，并且构成了 ELF 标准的基础，但人们可以创造任何想要的部分，并让特殊程序使用它。这就是内核的做法。可以运行`objdump -h module.ko`来打印出构成给定`module.ko`内核模块的不同部分：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00005.jpg)

helloworld-params.ko 模块的部分列表

在标题中的部分中，只有少数是标准的 ELF 部分：

+   `.text`，也称为代码，其中包含程序代码

+   `.data`，其中包含初始化数据，也称为数据段

+   `.rodata`，用于只读数据

+   `.评论`

+   未初始化数据段，也称为 **由符号开始的块**（**bss**）

其他部分是根据内核目的的需求添加的。对于本章来说，最重要的是 **.modeinfo** 部分，它存储有关模块的信息，以及 **.init.text** 部分，它存储以 `__init` 宏为前缀的代码。

链接器（Linux 系统上的 `ld` ）是 binutils 的一部分，负责将符号（数据、代码等）放置在生成的二进制文件的适当部分，以便在程序执行时由加载器处理。可以通过提供链接器脚本（称为 **链接器定义文件**（**LDF**）或 **链接器定义脚本**（**LDS**））来自定义这些部分，更改它们的默认位置，甚至添加额外的部分。现在，您只需要通过编译器指令通知链接器符号的放置。GNU C 编译器提供了用于此目的的属性。在 Linux 内核的情况下，提供了一个自定义的 LDS 文件，位于 `arch/<arch>/kernel/vmlinux.lds.S` 中。然后使用 `__init` 和 `__exit` 来标记要放置在内核的 LDS 文件中映射的专用部分中的符号。

总之，`__init` 和 `__exit` 是 Linux 指令（实际上是宏），它们包装了用于符号放置的 C 编译器属性。它们指示编译器将它们分别放置在 `.init.text` 和 `.exit.text` 部分，即使内核可以访问不同的对象部分。

# 模块信息

即使不必阅读其代码，人们也应该能够收集有关给定模块的一些信息（例如作者、参数描述、许可证）。内核模块使用其 `.modinfo` 部分来存储有关模块的信息。任何 `MODULE_*` 宏都将使用传递的值更新该部分的内容。其中一些宏是 `MODULE_DESCRIPTION()`、`MODULE_AUTHOR()` 和 `MODULE_LICENSE()`。内核提供的真正底层宏用于在模块信息部分中添加条目是 `MODULE_INFO(tag, info)`，它添加了形式为 tag = info 的通用信息。这意味着驱动程序作者可以添加任何他们想要的自由形式信息，例如：

```
MODULE_INFO(my_field_name, "What eeasy value"); 
```

可以使用 `objdump -d -j .modinfo` 命令在给定模块上转储 `.modeinfo` 部分的内容：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00006.jpg)

helloworld-params.ko 模块的 .modeinfo 部分的内容

modinfo 部分可以被视为模块的数据表。实际上以格式化的方式打印信息的用户空间工具是 `modinfo`：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00007.jpg)

modinfo 输出

除了自定义信息外，还应提供标准信息，内核为此提供了宏；这些是许可证、模块作者、参数描述、模块版本和模块描述。

# 许可

许可在给定模块中由 `MODULE_LICENSE()` 宏定义：

```
MODULE_LICENSE ("GPL"); 
```

许可证将定义您的源代码应如何与其他开发人员共享（或不共享）。`MODULE_LICENSE()`告诉内核我们的模块使用的许可证。它会影响您的模块行为，因为不兼容 GPL 的许可证将导致您的模块无法看到/使用内核通过`EXPORT_SYMBOL_GPL()`宏导出的服务/函数，该宏仅向兼容 GPL 的模块显示符号，这与`EXPORT_SYMBOL()`相反，后者为任何许可证的模块导出函数。加载不兼容 GPL 的模块还将导致内核受到污染；这意味着已加载非开源或不受信任的代码，您可能不会得到社区的支持。请记住，没有`MODULE_LICENSE()`的模块也不被视为开源，并且也会污染内核。以下是`include/linux/module.h`的摘录，描述了内核支持的许可证：

```
/* 
 * The following license idents are currently accepted as indicating free 
 * software modules 
 * 
 * "GPL"                   [GNU Public License v2 or later] 
 * "GPL v2"                [GNU Public License v2] 
 * "GPL and additional rights"   [GNU Public License v2 rights and more] 
 * "Dual BSD/GPL"                [GNU Public License v2 
 *                          or BSD license choice] 
 * "Dual MIT/GPL"                [GNU Public License v2 
 *                          or MIT license choice] 
 * "Dual MPL/GPL"                [GNU Public License v2 
 *                          or Mozilla license choice] 
 * 
 * The following other idents are available 
 * 
 * "Proprietary"                 [Non free products] 
 * 
 * There are dual licensed components, but when running with Linux it is the 
 * GPL that is relevant so this is a non issue. Similarly LGPL linked with GPL 
 * is a GPL combined work. 
 * 
 * This exists for several reasons 
 * 1\.    So modinfo can show license info for users wanting to vet their setup 
 * is free 
 * 2\.    So the community can ignore bug reports including proprietary modules 
 * 3\.    So vendors can do likewise based on their own policies 
 */ 
```

您的模块至少必须与 GPL 兼容，才能享受完整的内核服务。

# 模块作者

`MODULE_AUTHOR()`声明模块的作者：

```
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>");  
```

可能有多个作者。在这种情况下，每个作者都必须用`MODULE_AUTHOR()`声明：

```
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_AUTHOR("Lorem Ipsum <l.ipsum@foobar.com>"); 
```

# 模块描述

`MODULE_DESCRIPTION()`简要描述模块的功能：

```
MODULE_DESCRIPTION("Hello, world! Module"); 
```

# 错误和消息打印

错误代码要么由内核解释，要么由用户空间应用程序（通过`errno`变量）解释。错误处理在软件开发中非常重要，比在内核开发中更重要。幸运的是，内核提供了几个几乎涵盖了你可能遇到的每个错误的错误，并且有时你需要打印它们以帮助你调试。

# 错误处理

返回给定错误的错误代码将导致内核或用户空间应用程序产生不必要的行为并做出错误的决定。为了保持清晰，内核树中有预定义的错误，几乎涵盖了您可能遇到的每种情况。一些错误（及其含义）在`include/uapi/asm-generic/errno-base.h`中定义，其余列表可以在`include/uapi/asm-generic/errno.h`中找到。以下是`include/uapi/asm-generic/errno-base.h`中错误列表的摘录：

```
#define  EPERM        1    /* Operation not permitted */ 
#define  ENOENT             2    /* No such file or directory */ 
#define  ESRCH        3    /* No such process */ 
#define  EINTR        4    /* Interrupted system call */ 
#define  EIO          5    /* I/O error */ 
#define  ENXIO        6    /* No such device or address */ 
#define  E2BIG        7    /* Argument list too long */ 
#define  ENOEXEC            8    /* Exec format error */ 
#define  EBADF        9    /* Bad file number */ 
#define  ECHILD            10    /* No child processes */ 
#define  EAGAIN            11    /* Try again */ 
#define  ENOMEM            12    /* Out of memory */ 
#define  EACCES            13    /* Permission denied */ 
#define  EFAULT            14    /* Bad address */ 
#define  ENOTBLK           15    /* Block device required */ 
#define  EBUSY       16    /* Device or resource busy */ 
#define  EEXIST            17    /* File exists */ 
#define  EXDEV       18    /* Cross-device link */ 
#define  ENODEV            19    /* No such device */ 
#define  ENOTDIR           20    /* Not a directory */ 
#define  EISDIR            21    /* Is a directory */ 
#define  EINVAL            22    /* Invalid argument */ 
#define  ENFILE            23    /* File table overflow */ 
#define  EMFILE            24    /* Too many open files */ 
#define  ENOTTY            25    /* Not a typewriter */ 
#define  ETXTBSY           26    /* Text file busy */ 
#define  EFBIG       27    /* File too large */ 
#define  ENOSPC            28    /* No space left on device */ 
#define  ESPIPE            29    /* Illegal seek */ 
#define  EROFS       30    /* Read-only file system */ 
#define  EMLINK            31    /* Too many links */ 
#define  EPIPE       32    /* Broken pipe */ 
#define  EDOM        33    /* Math argument out of domain of func */ 
#define  ERANGE            34    /* Math result not representable */ 
```

大多数时候，返回错误的经典方法是以`return -ERROR`的形式返回，特别是当涉及到回答系统调用时。例如，对于 I/O 错误，错误代码是`EIO`，应该`return -EIO`：

```
dev = init(&ptr); 
if(!dev) 
return -EIO 
```

错误有时会跨越内核空间并传播到用户空间。如果返回的错误是对系统调用（`open`，`read`，`ioctl`，`mmap`）的回答，则该值将自动分配给用户空间的`errno`全局变量，可以使用`strerror(errno)`将错误转换为可读字符串：

```
#include <errno.h>  /* to access errno global variable */ 
#include <string.h> 
[...] 
if(wite(fd, buf, 1) < 0) { 
    printf("something gone wrong! %s\n", strerror(errno)); 
} 
[...] 
```

当遇到错误时，必须撤消发生错误之前设置的所有操作。通常的做法是使用`goto`语句：

```
ptr = kmalloc(sizeof (device_t)); 
if(!ptr) { 
        ret = -ENOMEM 
        goto err_alloc; 
} 
dev = init(&ptr); 

if(dev) { 
        ret = -EIO 
        goto err_init; 
} 
return 0; 

err_init: 
        free(ptr); 
err_alloc: 
        return ret; 
```

使用`goto`语句的原因很简单。当涉及到处理错误时，比如在第 5 步，必须清理之前的操作（步骤 4、3、2、1）。而不是进行大量的嵌套检查操作，如下所示：

```
if (ops1() != ERR) { 
    if (ops2() != ERR) { 
        if ( ops3() != ERR) { 
            if (ops4() != ERR) { 
```

这可能会令人困惑，并可能导致缩进问题。人们更喜欢使用`goto`以便有一个直接的控制流，如下所示：

```
if (ops1() == ERR) // | 
    goto error1;   // | 
if (ops2() == ERR) // | 
    goto error2;   // | 
if (ops3() == ERR) // | 
    goto error3;   // | 
if (ops4() == ERR) // V 
    goto error4; 
error5: 
[...] 
error4: 
[...] 
error3: 
[...] 
error2: 
[...] 
error1: 
[...] 
```

这意味着，应该只使用 goto 在函数中向前移动。

# 处理空指针错误

当涉及到从应该返回指针的函数返回错误时，函数经常返回`NULL`指针。这是一种有效但相当无意义的方法，因为人们并不确切知道为什么返回了这个空指针。为此，内核提供了三个函数，`ERR_PTR`，`IS_ERR`和`PTR_ERR`：

```
void *ERR_PTR(long error); 
long IS_ERR(const void *ptr); 
long PTR_ERR(const void *ptr); 
```

第一个实际上将错误值作为指针返回。假设一个函数在失败的内存分配后可能会`return -ENOMEM`，我们必须这样做`return ERR_PTR(-ENOMEM);`。第二个用于检查返回的值是否是指针错误，`if (IS_ERR(foo))`。最后返回实际的错误代码`return PTR_ERR(foo);`。以下是一个例子：

如何使用`ERR_PTR`，`IS_ERR`和`PTR_ERR`：

```
static struct iio_dev *indiodev_setup(){ 
    [...] 
    struct iio_dev *indio_dev; 
    indio_dev = devm_iio_device_alloc(&data->client->dev, sizeof(data)); 
    if (!indio_dev) 
        return ERR_PTR(-ENOMEM); 
    [...] 
    return indio_dev; 
} 

static int foo_probe([...]){ 
    [...] 
    struct iio_dev *my_indio_dev = indiodev_setup(); 
    if (IS_ERR(my_indio_dev)) 
        return PTR_ERR(data->acc_indio_dev); 
    [...] 
} 
```

这是错误处理的一个优点，也是内核编码风格的一部分，其中说：如果函数的名称是一个动作或一个命令，函数应该返回一个错误代码整数。如果名称是一个谓词，函数应该返回一个`succeeded`布尔值。例如，`add work`是一个命令，`add_work（）`函数成功返回`0`，失败返回`-EBUSY`。同样，`PCI device present`是一个谓词，`pci_dev_present（）`函数在成功找到匹配设备时返回`1`，如果没有找到则返回`0`。

# 消息打印 - printk（）

`printk（）`对内核来说就像`printf（）`对用户空间一样。由`printk（）`编写的行可以通过`dmesg`命令显示。根据您需要打印的消息的重要性，您可以在`include/linux/kern_levels.h`中定义的八个日志级别消息之间进行选择，以及它们的含义：

以下是内核日志级别的列表。这些级别中的每一个都对应于字符串中的一个数字，其优先级与数字的值成反比。例如，`0`是更高的优先级：

```
#define KERN_SOH     "\001"            /* ASCII Start Of Header */ 
#define KERN_SOH_ASCII     '\001' 

#define KERN_EMERG   KERN_SOH "0"      /* system is unusable */ 
#define KERN_ALERT   KERN_SOH "1"      /* action must be taken immediately */ 
#define KERN_CRIT    KERN_SOH "2"      /* critical conditions */ 
#define KERN_ERR     KERN_SOH "3"      /* error conditions */ 
#define KERN_WARNING KERN_SOH "4"      /* warning conditions */ 
#define KERN_NOTICE  KERN_SOH "5"      /* normal but significant condition */ 
#define KERN_INFO    KERN_SOH "6"      /* informational */ 
#define KERN_DEBUG   KERN_SOH "7"      /* debug-level messages */ 
```

以下代码显示了如何打印内核消息以及日志级别：

```
printk(KERN_ERR "This is an error\n"); 
```

如果省略调试级别（`printk("This is an error\n")`），内核将根据`CONFIG_DEFAULT_MESSAGE_LOGLEVEL`配置选项为函数提供一个调试级别，这是默认的内核日志级别。实际上可以使用以下更有意义的宏之一，它们是对先前定义的宏的包装器：`pr_emerg`，`pr_alert`，`pr_crit`，`pr_err`，`pr_warning`，`pr_notice`，`pr_info`和`pr_debug`：

```
pr_err("This is the same error\n"); 
```

对于新驾驶员，建议使用这些包装器。 `printk（）`的现实是，每当调用它时，内核都会将消息日志级别与当前控制台日志级别进行比较；如果前者较高（值较低）则消息将立即打印到控制台。您可以使用以下命令检查日志级别参数：

```
 cat /proc/sys/kernel/printk

 4 4 1 7

```

在此代码中，第一个值是当前日志级别（4），第二个值是默认值，根据`CONFIG_DEFAULT_MESSAGE_LOGLEVEL`选项。其他值对于本章的目的并不重要，因此让我们忽略这些。

内核日志级别列表如下：

```
/* integer equivalents of KERN_<LEVEL> */ 
#define LOGLEVEL_SCHED           -2    /* Deferred messages from sched code 
                            * are set to this special level */ 
#define LOGLEVEL_DEFAULT   -1    /* default (or last) loglevel */ 
#define LOGLEVEL_EMERG           0     /* system is unusable */ 
#define LOGLEVEL_ALERT           1     /* action must be taken immediately */ 
#define LOGLEVEL_CRIT            2     /* critical conditions */ 
#define LOGLEVEL_ERR       3     /* error conditions */ 
#define LOGLEVEL_WARNING   4     /* warning conditions */ 
#define LOGLEVEL_NOTICE          5     /* normal but significant condition */ 
#define LOGLEVEL_INFO            6     /* informational */ 
#define LOGLEVEL_DEBUG           7     /* debug-level messages */ 
```

当前日志级别可以通过以下更改：

```
 # echo <level> > /proc/sys/kernel/printk

```

`printk（）`永远不会阻塞，并且即使从原子上下文中调用也足够安全。它会尝试锁定控制台并打印消息。如果锁定失败，输出将被写入缓冲区，函数将返回，永远不会阻塞。然后当前控制台持有者将收到有关新消息的通知，并在释放控制台之前打印它们。

内核还支持其他调试方法，可以动态使用`#define DEBUG`或在文件顶部使用`#define DEBUG`。对此类调试风格感兴趣的人可以参考内核文档中的*Documentation/dynamic-debug-howto.txt*文件。

# 模块参数

与用户程序一样，内核模块可以从命令行接受参数。这允许根据给定的参数动态更改模块的行为，并且可以帮助开发人员在测试/调试会话期间不必无限制地更改/编译模块。为了设置这一点，首先应该声明将保存命令行参数值的变量，并对每个变量使用`module_param()`宏。该宏在`include/linux/moduleparam.h`中定义（代码中也应该包括：`#include <linux/moduleparam.h>`），如下所示：

```
module_param(name, type, perm); 
```

该宏包含以下元素：

+   `name`：用作参数的变量的名称

+   `type`：参数的类型（bool、charp、byte、short、ushort、int、uint、long、ulong），其中`charp`代表 char 指针

+   `perm`：这表示`/sys/module/<module>/parameters/<param>`文件的权限。其中一些是`S_IWUSR`，`S_IRUSR`，`S_IXUSR`，`S_IRGRP`，`S_WGRP`和`S_IRUGO`，其中：

+   `S_I`只是一个前缀

+   `R`：读取，`W`：写入，`X`：执行

+   `USR`：用户，`GRP`：组，`UGO`：用户，组，其他人

最终可以使用`|`（或操作）来设置多个权限。如果 perm 为`0`，则`sysfs`中的文件参数将不会被创建。您应该只使用`S_IRUGO`只读参数，我强烈建议；通过与其他属性进行`|`（或）运算，可以获得细粒度的属性。

在使用模块参数时，应该使用`MODULE_PARM_DESC`来描述每个参数。这个宏将在模块信息部分填充每个参数的描述。以下是一个示例，来自书籍的代码库中提供的`helloworld-params.c`源文件：

```
#include <linux/moduleparam.h> 
[...] 

static char *mystr = "hello"; 
static int myint = 1; 
static int myarr[3] = {0, 1, 2}; 

module_param(myint, int, S_IRUGO); 
module_param(mystr, charp, S_IRUGO); 
module_param_array(myarr, int,NULL, S_IWUSR|S_IRUSR); /*  */ 

MODULE_PARM_DESC(myint,"this is my int variable"); 
MODULE_PARM_DESC(mystr,"this is my char pointer variable"); 
MODULE_PARM_DESC(myarr,"this is my array of int"); 

static int foo() 
{ 
    pr_info("mystring is a string: %s\n", mystr); 
    pr_info("Array elements: %d\t%d\t%d", myarr[0], myarr[1], myarr[2]); 
    return myint; 
} 
```

要加载模块并传递我们的参数，我们需要执行以下操作：

```
# insmod hellomodule-params.ko mystring="packtpub" myint=15 myArray=1,2,3

```

在加载模块之前，可以使用`modinfo`来显示模块支持的参数的描述：

```
$ modinfo ./helloworld-params.ko

filename: /home/jma/work/tutos/sources/helloworld/./helloworld-params.ko

license: GPL

author: John Madieu <john.madieu@gmail.com>

srcversion: BBF43E098EAB5D2E2DD78C0

depends:

vermagic: 4.4.0-93-generic SMP mod_unload modversions

parm: myint:this is my int variable (int)

parm: mystr:this is my char pointer variable (charp)

parm: myarr:this is my array of int (array of int)

```

# 构建您的第一个模块

有两个地方可以构建一个模块。这取决于您是否希望人们使用内核配置界面自行启用模块。

# 模块的 makefile

Makefile 是一个特殊的文件，用于执行一系列操作，其中最重要的是编译程序。有一个专门的工具来解析 makefile，叫做`make`。在跳转到整个 make 文件的描述之前，让我们介绍`obj-<X>` kbuild 变量。

在几乎每个内核 makefile 中，都会看到至少一个`obj<-X>`变量的实例。这实际上对应于`obj-<X>`模式，其中`<X>`应该是`y`，`m`，留空，或`n`。这是由内核 makefile 从内核构建系统的头部以一般方式使用的。这些行定义要构建的文件、任何特殊的编译选项以及要递归进入的任何子目录。一个简单的例子是：

```
 obj-y += mymodule.o 
```

这告诉 kbuild 当前目录中有一个名为`mymodule.o`的对象。`mymodule.o`将从`mymodule.c`或`mymodule.S`构建。`mymodule.o`将如何构建或链接取决于`<X>`的值：

+   如果`<X>`设置为`m`，则使用变量`obj-m`，`mymodule.o`将作为一个模块构建。

+   如果`<X>`设置为`y`，则使用变量`obj-y`，`mymodule.o`将作为内核的一部分构建。然后说 foo 是一个内置模块。

+   如果`<X>`设置为`n`，则使用变量`obj-m`，`mymodule.o`将根本不会被构建。

因此，通常使用`obj-$(CONFIG_XXX)`模式，其中`CONFIG_XXX`是内核配置选项，在内核配置过程中设置或不设置。一个例子是：

```
obj-$(CONFIG_MYMODULE) += mymodule.o 
```

`$(CONFIG_MYMODULE)`根据内核配置过程中的值评估为`y`或`m`。如果`CONFIG_MYMODULE`既不是`y`也不是`m`，则文件将不会被编译或链接。`y`表示内置（在内核配置过程中代表是），`m`代表模块。`$(CONFIG_MYMODULE)`从正常配置过程中获取正确的答案。这将在下一节中解释。

最后一个用例是：

```
obj-<X> += somedir/ 
```

这意味着 kbuild 应进入名为`somedir`的目录；查找其中的任何 makefile 并处理它，以决定应构建哪些对象。

回到 makefile，以下是我们将用于构建书中介绍的每个模块的内容 makefile：

```
obj-m := helloworld.o 

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 

all default: modules 
install: modules_install 

modules modules_install help clean: 
$(MAKE) -C $(KERNELDIR) M=$(shell pwd) $@ 
```

+   `obj-m := hellowolrd.o`：`obj-m`列出我们要构建的模块。对于每个`<filename>.o`，构建系统将寻找一个`<filename>.c`进行构建。`obj-m`用于构建模块，而`obj-y`将导致内置对象。

+   `KERNELDIR := /lib/modules/$(shell uname -r)/build`：`KERNELDIR`是预构建内核源的位置。正如我们之前所说，我们需要预构建的内核才能构建任何模块。如果您已经从源代码构建了内核，则应将此变量设置为构建源目录的绝对路径。`-C`指示 make 实用程序在读取 makefile 或执行其他任何操作之前切换到指定的目录。

+   `M=$(shell pwd)`：这与内核构建系统有关。内核 Makefile 使用此变量来定位要构建的外部模块的目录。您的`.c`文件应放置在这里。

+   `all default: modules`：此行指示`make`实用程序执行`modules`目标，无论是`all`还是`default`目标，这些都是在构建用户应用程序时的经典目标。换句话说，`make default`或`make all`或简单地`make`命令将被转换为`make modules`。

+   `modules modules_install help clean：`：此行表示此 Makefile 中有效的列表目标。

+   `$(MAKE) -C $(KERNELDIR ) M=$(shell pwd) $@`：这是要为上述每个目标执行的规则。`$@`将被替换为导致规则运行的目标的名称。换句话说，如果调用 make modules，`$@`将被替换为 modules，规则将变为：`$(MAKE) -C $(KERNELDIR ) M=$(shell pwd) module`。

# 在内核树中

在内核树中构建驱动程序之前，您应首先确定驱动程序应放置在哪个驱动程序目录中的`.c`文件。给定您的文件名`mychardev.c`，其中包含您的特殊字符驱动程序的源代码，它应放置在内核源中的`drivers/char`目录中。驱动程序中的每个子目录都有`Makefile`和`Kconfig`文件。

将以下内容添加到该目录的`Kconfig`中：

```
config PACKT_MYCDEV 
   tristate "Our packtpub special Character driver" 
   default m 
   help 
     Say Y here if you want to support the /dev/mycdev device. 
     The /dev/mycdev device is used to access packtpub. 
```

在同一目录的 makefile 中添加：

```
obj-$(CONFIG_PACKT_MYCDEV)   += mychardev.o 
```

更新`Makefile`时要小心；`.o`文件名必须与您的`.c`文件的确切名称匹配。如果您的源文件是`foobar.c`，则必须在`Makefile`中使用`foobar.o`。为了使您的驱动程序作为模块构建，将以下行添加到`arch/arm/configs`目录中的板 defconfig 中：

```
CONFIG_PACKT_MYCDEV=m 
```

您还可以运行`make menuconfig`从 UI 中选择它，并运行`make`构建内核，然后运行`make modules`构建模块（包括您自己的模块）。要使驱动程序内置构建，只需用`y`替换`m`：

```
CONFIG_PACKT_MYCDEV=m 
```

这里描述的一切都是嵌入式板制造商为了提供带有他们的板的**BSP**（**Board Support Package**）而做的，其中包含已经包含他们自定义驱动程序的内核：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00008.jpg)

内核树中的 packt_dev 模块

配置完成后，您可以使用`make`构建内核，并使用`make modules`构建模块。

包含在内核源树中的模块将安装在`/lib/modules/$(KERNELRELEASE)/kernel/`中。在您的 Linux 系统上，它是`/lib/modules/$(uname -r)/kernel/`。运行以下命令以安装模块：

```
make modules_install

```

# 树外

在构建外部模块之前，您需要拥有完整的预编译内核源代码树。内核源代码树的版本必须与您将加载和使用模块的内核相同。获取预构建内核版本有两种方法：

+   自行构建（之前讨论过）

+   从您的发行版存储库安装`linux-headers-*`软件包

```
 sudo apt-get update

 sudo apt-get install linux-headers-$(uname -r)

```

这将只安装头文件，而不是整个源代码树。然后，头文件将安装在`/usr/src/linux-headers-$(uname -r)`中。在我的计算机上，它是`/usr/src/linux-headers-4.4.0-79-generic/`。将会有一个符号链接，`/lib/modules/$(uname -r)/build`，指向先前安装的头文件。这是您应该在`Makefile`中指定为内核目录的路径。这是您为预构建内核所需做的一切。

# 构建模块

现在，当您完成了您的 makefile，只需切换到您的源目录并运行`make`命令，或者`make modules`：

```
    jma@jma:~/work/tutos/sources/helloworld$ make

    make -C /lib/modules/4.4.0-79-generic/build \

        M=/media/jma/DATA/work/tutos/sources/helloworld modules

    make[1]: Entering directory '/usr/src/linux-headers-4.4.0-79-generic'

      CC [M]  /media/jma/DATA/work/tutos/sources/helloworld/helloworld.o

      Building modules, stage 2.

      MODPOST 1 modules

      CC      /media/jma/DATA/work/tutos/sources/helloworld/helloworld.mod.o

      LD [M]  /media/jma/DATA/work/tutos/sources/helloworld/helloworld.ko

    make[1]: Leaving directory '/usr/src/linux-headers-4.4.0-79-generic'

    jma@jma:~/work/tutos/sources/helloworld$ ls

    helloworld.c  helloworld.ko  helloworld.mod.c  helloworld.mod.o  helloworld.o  Makefile  modules.order  Module.symvers

    jma@jma:~/work/tutos/sources/helloworld$ sudo insmod  helloworld.ko

    jma@jma:~/work/tutos/sources/helloworld$ sudo rmmod helloworld

    jma@jma:~/work/tutos/sources/helloworld$ dmesg

    [...]

    [308342.285157] Hello world!

    [308372.084288] End of the world

```

前面的例子只涉及本地构建，在 x86 机器上为 x86 机器进行编译。那么交叉编译呢？这是指在 A 机器上（称为主机）编译旨在在 B 机器上（称为目标机）运行的代码的过程；主机和目标机具有不同的架构。经典用例是在 x86 机器上构建应在 ARM 架构上运行的代码，这恰好是我们的情况。

当涉及交叉编译内核模块时，内核 makefile 需要了解的基本上有两个变量；这些是：`ARCH`和`CROSS_COMPILE`，分别代表目标架构和编译器前缀名称。因此，本地编译和交叉编译内核模块之间的变化是`make`命令。以下是为 ARM 构建的命令行：

```
make ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- 

```

# 摘要

本章向您展示了驱动程序开发的基础知识，并解释了模块/内置设备的概念，以及它们的加载和卸载。即使您无法与用户空间交互，您也可以准备编写完整的驱动程序，打印格式化消息，并理解`init`/`exit`的概念。下一章将涉及字符设备，您将能够针对增强功能编写代码，编写可从用户空间访问的代码，并对系统产生重大影响。


# 第三章：内核设施和辅助函数

内核是一个独立的软件，正如您将在本章中看到的，它不使用任何 C 库。它实现了您可能在现代库中遇到的任何机制，甚至更多，例如压缩、字符串函数等。我们将逐步介绍这些功能的最重要方面。

在本章中，我们将涵盖以下主题：

+   引入内核容器数据结构

+   处理内核睡眠机制

+   使用定时器

+   深入了解内核锁定机制（互斥锁、自旋锁）

+   使用内核专用 API 推迟工作

+   使用 IRQs

# 理解 container_of 宏

当涉及到在代码中管理多个数据结构时，您几乎总是需要将一个结构嵌入到另一个结构中，并在任何时刻检索它们，而不需要询问有关内存偏移或边界的问题。假设您有一个`struct person`，如此定义：

```
 struct person { 
     int  age; 
     char *name; 
 } p;
```

只需拥有`age`或`name`的指针，就可以检索包含该指针的整个结构。正如其名称所示，`container_of`宏用于查找结构的给定字段的容器。该宏在`include/linux/kernel.h`中定义，如下所示：

```
#define container_of(ptr, type, member) ({               \ 
   const typeof(((type *)0)->member) * __mptr = (ptr);   \ 
   (type *)((char *)__mptr - offsetof(type, member)); }) 
```

不要害怕指针；只需将其视为：

```
container_of(pointer, container_type, container_field); 
```

以下是前面代码片段的元素：

+   `pointer`：这是结构中字段的指针

+   `container_type`：这是包装（包含）指针的结构的类型

+   `container_field`：这是指针在结构内指向的字段的名称

让我们考虑以下容器：

```
struct person { 
     int  age; 
     char *name; 
 }; 
```

现在让我们考虑它的一个实例，以及指向`name`成员的指针：

```
struct person somebody; 
[...] 
char *the_name_ptr = somebody.name; 
```

以及指向`name`成员的指针（`the_name_ptr`），您可以使用`container_of`宏来获取包含此成员的整个结构（容器）的指针，方法如下：

```
struct person *the_person; 
the_person = container_of(the_name_ptr, struct person, name); 
```

`container_of`考虑了`name`在结构的开头的偏移量，以获取正确的指针位置。如果您从指针`the_name_ptr`中减去字段`name`的偏移量，您将得到正确的位置。这就是宏的最后一行所做的事情：

```
(type *)( (char *)__mptr - offsetof(type,member) ); 
```

将其应用于一个真实的例子，得到以下结果：

```
struct family { 
    struct person *father; 
    struct person *mother; 
    int number_of_suns; 
    int salary; 
} f; 

/* 
 * pointer to a field of the structure 
 * (could be any member of any family) 
*/ 
struct *person = family.father; 
struct family *fam_ptr; 

/* now let us retrieve back its family */ 
fam_ptr = container_of(person, struct family, father); 
```

这就是您需要了解的关于`container_of`宏的全部内容，相信我，这已经足够了。在我们将在本书中进一步开发的真实驱动程序中，它看起来像这样：

```
struct mcp23016 { 
    struct i2c_client *client; 
    struct gpio_chip chip; 
} 

/* retrive the mcp23016 struct given a pointer 'chip' field */ 
static inline struct mcp23016 *to_mcp23016(struct gpio_chip *gc) 
{ 
    return container_of(gc, struct mcp23016, chip); 
} 

static int mcp23016_probe(struct i2c_client *client, 
                const struct i2c_device_id *id) 
{ 
    struct mcp23016 *mcp; 
    [...] 
    mcp = devm_kzalloc(&client->dev, sizeof(*mcp), GFP_KERNEL); 
    if (!mcp) 
        return -ENOMEM; 
    [...] 
} 
```

`controller_of`宏主要用于内核中的通用容器。在本书的一些示例中（从第五章开始，*平台设备驱动程序*），您将遇到`container_of`宏。

# 链表

想象一下，您有一个管理多个设备的驱动程序，比如说五个设备。您可能需要在驱动程序中跟踪每个设备。您需要的是一个链表。实际上存在两种类型的链表：

+   简单链表

+   双向链表

因此，内核开发人员只实现循环双向链表，因为这种结构允许您实现 FIFO 和 LIFO，并且内核开发人员会努力维护一组最小的代码。要支持列表，需要在代码中添加的标头是`<linux/list.h>`。内核中列表实现的核心数据结构是`struct list_head`结构，定义如下：

```
struct list_head { 
    struct list_head *next, *prev; 
 }; 
```

`struct list_head`在列表的头部和每个节点中都使用。在内核世界中，要将数据结构表示为链表，该结构必须嵌入一个`struct list_head`字段。例如，让我们创建一个汽车列表：

```
struct car { 
    int door_number; 
    char *color; 
    char *model; 
}; 
```

在我们可以为汽车创建一个列表之前，我们必须改变其结构以嵌入一个`struct list_head`字段。结构变为：

```
struct car { 
    int door_number; 
    char *color; 
    char *model; 
    struct list_head list; /* kernel's list structure */ 
}; 
```

首先，我们需要创建一个`struct list_head`变量，它将始终指向我们列表的头部（第一个元素）。这个`list_head`的实例不与任何汽车相关联，它是特殊的：

```
static LIST_HEAD(carlist) ; 
```

现在我们可以创建汽车并将它们添加到我们的列表`carlist`：

```
#include <linux/list.h> 

struct car *redcar = kmalloc(sizeof(*car), GFP_KERNEL); 
struct car *bluecar = kmalloc(sizeof(*car), GFP_KERNEL); 

/* Initialize each node's list entry */ 
INIT_LIST_HEAD(&bluecar->list); 
INIT_LIST_HEAD(&redcar->list); 

/* allocate memory for color and model field and fill every field */ 
 [...] 
list_add(&redcar->list, &carlist) ; 
list_add(&bluecar->list, &carlist) ; 
```

就是这么简单。现在，`carlist` 包含两个元素。让我们深入了解链表 API。

# 创建和初始化列表

有两种方法可以创建和初始化列表：

# 动态方法

动态方法包括一个 `struct list_head` 并使用 `INIT_LIST_HEAD` 宏进行初始化：

```
struct list_head mylist; 
INIT_LIST_HEAD(&mylist); 
```

以下是 `INIT_LIST_HEAD` 的展开：

```
static inline void INIT_LIST_HEAD(struct list_head *list) 
   { 
       list->next = list; 
       list->prev = list; 
   } 
```

# 静态方法

通过 `LIST_HEAD` 宏进行静态分配：

```
LIST_HEAD(mylist) 
```

`LIST_HEAD` 的定义如下：

```
#define LIST_HEAD(name) \ 
    struct list_head name = LIST_HEAD_INIT(name) 
```

以下是它的展开：

```
#define LIST_HEAD_INIT(name) { &(name), &(name) } 
```

这将把 `name` 字段内的每个指针（`prev` 和 `next`）都指向 `name` 本身（就像 `INIT_LIST_HEAD` 做的那样）。

# 创建列表节点

要创建新节点，只需创建我们的数据结构实例，并初始化它们的嵌入式 `list_head` 字段。使用汽车示例，将得到以下内容：

```
struct car *blackcar = kzalloc(sizeof(struct car), GFP_KERNEL); 

/* non static initialization, since it is the embedded list field*/ 
INIT_LIST_HEAD(&blackcar->list); 
```

如前所述，使用 `INIT_LIST_HEAD`，这是一个动态分配的列表，通常是另一个结构的一部分。

# 添加列表节点

内核提供了 `list_add` 来将新条目添加到列表中，它是对内部函数 `__list_add` 的封装：

```
void list_add(struct list_head *new, struct list_head *head); 
static inline void list_add(struct list_head *new, struct list_head *head) 
{ 
    __list_add(new, head, head->next); 
} 
```

`__list_add` 将接受两个已知的条目作为参数，并在它们之间插入您的元素。它在内核中的实现非常简单：

```
static inline void __list_add(struct list_head *new, 
                  struct list_head *prev, 
                  struct list_head *next) 
{ 
    next->prev = new; 
    new->next = next; 
    new->prev = prev; 
    prev->next = new; 
} 
```

以下是我们列表中添加两辆车的示例：

```
list_add(&redcar->list, &carlist); 
list_add(&blue->list, &carlist); 
```

这种模式可以用来实现栈。另一个将条目添加到列表中的函数是：

```
void list_add_tail(struct list_head *new, struct list_head *head); 
```

这将给定的新条目插入到列表的末尾。根据我们之前的示例，我们可以使用以下内容：

```
list_add_tail(&redcar->list, &carlist); 
list_add_tail(&blue->list, &carlist); 
```

这种模式可以用来实现队列。

# 从列表中删除节点

在内核代码中处理列表是一项简单的任务。删除节点很简单：

```
 void list_del(struct list_head *entry); 
```

按照前面的示例，让我们删除红色的车：

```
list_del(&redcar->list); 
```

`list_del` 断开给定条目的 `prev` 和 `next` 指针，导致条目被移除。节点分配的内存尚未被释放；您需要使用 `kfree` 手动释放。

# 链表遍历

我们有宏 `list_for_each_entry(pos, head, member)` 用于列表遍历。

+   `head` 是列表的头节点。

+   `member` 是我们数据结构中 `struct list_head` 的列表名称（在我们的例子中是 `list`）。

+   `pos` 用于迭代。它是一个循环游标（就像 `for(i=0; i<foo; i++)` 中的 `i`）。`head` 可能是链表的头节点，也可能是任何条目，我们不关心，因为我们处理的是双向链表。

```
struct car *acar; /* loop counter */ 
int blue_car_num = 0; 

/* 'list' is the name of the list_head struct in our data structure */ 
list_for_each_entry(acar, carlist, list){ 
    if(acar->color == "blue") 
        blue_car_num++; 
} 

```

为什么我们需要在数据结构中的 `list_head` 类型字段的名称？看看 `list_for_each_entry` 的定义：

```
#define list_for_each_entry(pos, head, member)      \ 
for (pos = list_entry((head)->next, typeof(*pos), member);   \ 
     &pos->member != (head);        \ 
     pos = list_entry(pos->member.next, typeof(*pos), member)) 

#define list_entry(ptr, type, member) \ 
    container_of(ptr, type, member) 
```

通过这个，我们可以理解这一切都是关于 `container_of` 的力量。还要记住 `list_for_each_entry_safe(pos, n, head, member)`。

# 内核睡眠机制

睡眠是一个进程使处理器放松的机制，有可能处理另一个进程。处理器可以进入睡眠状态的原因可能是为了感知数据的可用性，或者等待资源空闲。

内核调度程序管理要运行的任务列表，称为运行队列。睡眠进程不再被调度，因为它们已从运行队列中移除。除非其状态发生变化（即它被唤醒），否则睡眠进程永远不会被执行。只要有一个进程在等待某些东西（资源或其他任何东西），您就可以放松处理器，并确保某个条件或其他人会唤醒它。也就是说，Linux 内核通过提供一组函数和数据结构来简化睡眠机制的实现。

# 等待队列

等待队列主要用于处理阻塞的 I/O，等待特定条件成立，并感知数据或资源的可用性。为了理解它的工作原理，让我们来看看 `include/linux/wait.h` 中的结构：

```
struct __wait_queue { 
    unsigned int flags; 
#define WQ_FLAG_EXCLUSIVE 0x01 
    void *private; 
    wait_queue_func_t func; 
    struct list_head task_list; 
}; 
```

让我们关注`task_list`字段。如您所见，它是一个列表。您想要让进程进入睡眠状态的每个进程都排队在该列表中（因此称为*等待队列*），并进入睡眠状态，直到条件成为真。等待队列可以被视为一系列进程和一个锁。

处理等待队列时您将经常遇到的函数是：

+   静态声明：

```
DECLARE_WAIT_QUEUE_HEAD(name) 
```

+   动态声明：

```
wait_queue_head_t my_wait_queue; 
init_waitqueue_head(&my_wait_queue); 
```

+   阻塞：

```
/* 
 * block the current task (process) in the wait queue if 
 * CONDITION is false 
 */ 
int wait_event_interruptible(wait_queue_head_t q, CONDITION); 
```

+   解除阻塞：

```
/* 
 * wake up one process sleeping in the wait queue if  
 * CONDITION above has become true 
 */ 
void wake_up_interruptible(wait_queue_head_t *q); 
```

`wait_event_interruptible`不会持续轮询，而只是在调用时评估条件。如果条件为假，则将进程置于`TASK_INTERRUPTIBLE`状态并从运行队列中移除。然后在等待队列中每次调用`wake_up_interruptible`时重新检查条件。如果在`wake_up_interruptible`运行时条件为真，则等待队列中的进程将被唤醒，并且其状态设置为`TASK_RUNNING`。进程按照它们进入睡眠的顺序被唤醒。要唤醒等待队列中的所有进程，您应该使用`wake_up_interruptible_all`。

实际上，主要功能是`wait_event`，`wake_up`和`wake_up_all`。它们与队列中的进程一起使用，处于独占（不可中断）等待状态，因为它们不能被信号中断。它们应该仅用于关键任务。可中断函数只是可选的（但建议使用）。由于它们可以被信号中断，您应该检查它们的返回值。非零值意味着您的睡眠已被某种信号中断，驱动程序应返回`ERESTARTSYS`。

如果有人调用了`wake_up`或`wake_up_interruptible`，并且条件仍然为`FALSE`，那么什么也不会发生。没有`wake_up`（或`wake_up_interuptible`），进程将永远不会被唤醒。以下是等待队列的一个示例：

```
#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/sched.h> 
#include <linux/time.h> 
#include <linux/delay.h> 
#include<linux/workqueue.h> 

static DECLARE_WAIT_QUEUE_HEAD(my_wq); 
static int condition = 0; 

/* declare a work queue*/        
static struct work_struct wrk; 

static void work_handler(struct work_struct *work) 
{  
    printk("Waitqueue module handler %s\n", __FUNCTION__); 
    msleep(5000); 
    printk("Wake up the sleeping module\n"); 
    condition = 1; 
    wake_up_interruptible(&my_wq); 
} 

static int __init my_init(void) 
{ 
    printk("Wait queue example\n"); 

    INIT_WORK(&wrk, work_handler); 
    schedule_work(&wrk); 

    printk("Going to sleep %s\n", __FUNCTION__); 
    wait_event_interruptible(my_wq, condition != 0); 

    pr_info("woken up by the work job\n"); 
    return 0; 
} 

void my_exit(void) 
{ 
    printk("waitqueue example cleanup\n"); 
} 

module_init(my_init); 
module_exit(my_exit); 
MODULE_AUTHOR("John Madieu <john.madieu@foobar.com>"); 
MODULE_LICENSE("GPL"); 
```

在上面的例子中，当前进程（实际上是`insmod`）将被放入等待队列中，等待 5 秒钟后由工作处理程序唤醒。`dmesg`输出如下：

```
    [342081.385491] Wait queue example

    [342081.385505] Going to sleep my_init

    [342081.385515] Waitqueue module handler work_handler

    [342086.387017] Wake up the sleeping module

    [342086.387096] woken up by the work job

    [342092.912033] waitqueue example cleanup

```

# 延迟和定时器管理

时间是最常用的资源之一，仅次于内存。它用于几乎所有事情：延迟工作，睡眠，调度，超时和许多其他任务。

时间有两个类别。内核使用绝对时间来知道现在是什么时间，也就是说，日期和时间，而相对时间则由内核调度程序等使用。对于绝对时间，有一个名为**实时时钟**（**RTC**）的硬件芯片。我们将在本书的第十八章中处理这些设备，*RTC 驱动程序*。另一方面，为了处理相对时间，内核依赖于一个称为定时器的 CPU 特性（外围设备），从内核的角度来看，它被称为*内核定时器*。内核定时器是我们将在本节中讨论的内容。

内核定时器分为两个不同的部分：

+   标准定时器，或系统定时器

+   高分辨率定时器

# 标准定时器

标准定时器是以 jiffies 为粒度运行的内核定时器。

# Jiffies 和 HZ

jiffy 是在`<linux/jiffies.h>`中声明的内核时间单位。要理解 jiffies，我们需要介绍一个新的常数 HZ，它是在一秒钟内递增`jiffies`的次数。每次递增称为*tick*。换句话说，HZ 表示 jiffy 的大小。HZ 取决于硬件和内核版本，并且还确定时钟中断的频率。这在某些架构上是可配置的，在其他架构上是固定的。

这意味着`jiffies`每秒递增 HZ 次。如果 HZ = 1,000，则递增 1,000 次（也就是说，每 1/1,000 秒递增一次）。一旦定义了**可编程中断定时器**（**PIT**），它是一个硬件组件，就会使用该值来对 PIT 进行编程，以便在 PIT 中断时递增 jiffies。

根据平台的不同，jiffies 可能会导致溢出。在 32 位系统上，HZ = 1,000 将导致大约 50 天的持续时间，而在 64 位系统上，持续时间约为 6 亿年。通过将 jiffies 存储在 64 位变量中，问题得到解决。然后引入了第二个变量，并在`<linux/jiffies.h>`中定义：

```
extern u64 jiffies_64; 
```

在 32 位系统上，`jiffies`将指向低位 32 位，而`jiffies_64`将指向高位位。在 64 位平台上，`jiffies = jiffies_64`。

# 定时器 API

定时器在内核中表示为`timer_list`的实例：

```
#include <linux/timer.h> 

struct timer_list { 
    struct list_head entry; 
    unsigned long expires; 
    struct tvec_t_base_s *base; 
    void (*function)(unsigned long); 
    unsigned long data; 
); 
```

`expires`是 jiffies 中的绝对值。`entry`是一个双向链表，`data`是可选的，并传递给回调函数。

# 定时器设置初始化

以下是初始化定时器的步骤：

1.  **设置定时器**：设置定时器，提供用户定义的回调和数据：

```
void setup_timer( struct timer_list *timer, \ 
           void (*function)(unsigned long), \ 
           unsigned long data); 
```

也可以使用以下方法：

```
void init_timer(struct timer_list *timer); 
```

`setup_timer`是`init_timer`的包装器。

1.  **设置到期时间**：当初始化定时器时，需要在回调触发之前设置其到期时间：

```
int mod_timer( struct timer_list *timer, unsigned long expires); 
```

1.  **释放定时器**：当您完成定时器时，需要释放它：

```
void del_timer(struct timer_list *timer); 
int del_timer_sync(struct timer_list *timer); 
```

`del_timer`返回`void`，无论它是否已停用挂起的定时器。其返回值为 0 表示未激活的定时器，1 表示激活的定时器。最后，`del_timer_sync`等待处理程序完成执行，即使可能发生在另一个 CPU 上的处理程序。您不应持有阻止处理程序完成的锁，否则将导致死锁。您应在模块清理例程中释放定时器。您可以独立检查定时器是否正在运行：

```
int timer_pending( const struct timer_list *timer); 
```

此函数检查是否有任何已触发的定时器回调待处理。

# 标准定时器示例

```
#include <linux/init.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/timer.h> 

static struct timer_list my_timer; 

void my_timer_callback(unsigned long data) 
{ 
    printk("%s called (%ld).\n", __FUNCTION__, jiffies); 
} 

static int __init my_init(void) 
{ 
    int retval; 
    printk("Timer module loaded\n"); 

    setup_timer(&my_timer, my_timer_callback, 0); 
    printk("Setup timer to fire in 300ms (%ld)\n", jiffies); 

    retval = mod_timer( &my_timer, jiffies + msecs_to_jiffies(300) ); 
    if (retval) 
        printk("Timer firing failed\n"); 

    return 0; 
} 

static void my_exit(void) 
{ 
    int retval; 
    retval = del_timer(&my_timer); 
    /* Is timer still active (1) or no (0) */ 
    if (retval) 
        printk("The timer is still in use...\n"); 

    pr_info("Timer module unloaded\n"); 
} 

module_init(my_init); 
module_exit(my_exit); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_DESCRIPTION("Standard timer example"); 
MODULE_LICENSE("GPL"); 
```

# 高分辨率定时器（HRTs）

标准定时器精度较低，不适用于实时应用。高分辨率定时器在内核 v2.6.16 中引入（并通过内核配置中的`CONFIG_HIGH_RES_TIMERS`选项启用）具有微秒级（取决于平台，可达纳秒级）的分辨率，而标准定时器依赖于 HZ（因为它们依赖于 jiffies），而 HRT 实现基于`ktime`。

在您的系统上使用 HRT 之前，内核和硬件必须支持 HRT。换句话说，必须实现与体系结构相关的代码以访问您的硬件 HRT。

# HRT API

所需的头文件是：

```
#include <linux/hrtimer.h> 
```

HRT 在内核中表示为`hrtimer`的实例：

```
struct hrtimer { 
   struct timerqueue_node node; 
   ktime_t _softexpires; 
   enum hrtimer_restart (*function)(struct hrtimer *); 
   struct hrtimer_clock_base *base; 
   u8 state; 
   u8 is_rel; 
}; 
```

# HRT 设置初始化

1.  **初始化 hrtimer**：在 hrtimer 初始化之前，您需要设置一个代表时间持续的`ktime`。我们将在以下示例中看到如何实现：

```
 void hrtimer_init( struct hrtimer *time, clockid_t which_clock, 
                    enum hrtimer_mode mode); 
```

1.  **启动 hrtimer**：hrtimer 可以如以下示例所示启动：

```
int hrtimer_start( struct hrtimer *timer, ktime_t time, 
                    const enum hrtimer_mode mode); 
```

`mode`表示到期模式。对于绝对时间值，它应为`HRTIMER_MODE_ABS`，对于相对于现在的时间值，它应为`HRTIMER_MODE_REL`。

1.  **hrtimer 取消**：您可以取消定时器，或者查看是否可能取消它：

```
int hrtimer_cancel( struct hrtimer *timer); 
int hrtimer_try_to_cancel(struct hrtimer *timer); 
```

当定时器未激活时，两者返回`0`，当定时器激活时返回`1`。这两个函数之间的区别在于，如果定时器处于活动状态或其回调正在运行，`hrtimer_try_to_cancel`将失败，返回`-1`，而`hrtimer_cancel`将等待回调完成。

我们可以独立检查 hrtimer 的回调是否仍在运行，如下所示：

```
int hrtimer_callback_running(struct hrtimer *timer); 
```

请记住，`hrtimer_try_to_cancel`内部调用`hrtimer_callback_running`。

为了防止定时器自动重新启动，hrtimer 回调函数必须返回`HRTIMER_NORESTART`。

您可以通过以下方式检查系统是否支持 HRT：

+   通过查看内核配置文件，其中应包含类似`CONFIG_HIGH_RES_TIMERS=y`的内容：`zcat /proc/configs.gz | grep CONFIG_HIGH_RES_TIMERS`。

+   通过查看`cat /proc/timer_list`或`cat /proc/timer_list | grep resolution`的结果。`.resolution`条目必须显示 1 纳秒，事件处理程序必须显示`hrtimer_interrupts`。

+   通过使用`clock_getres`系统调用。

+   从内核代码中，通过使用`#ifdef CONFIG_HIGH_RES_TIMERS`。

在系统上启用 HRT 后，睡眠和定时器系统调用的准确性不再取决于 jiffies，但它们仍然与 HRT 一样准确。这就是为什么有些系统不支持`nanosleep()`的原因，例如。

# 动态滴答/无滴答内核

使用先前的 HZ 选项，内核每秒被中断 HZ 次以重新安排任务，即使在空闲状态下也是如此。如果 HZ 设置为 1,000，则每秒将有 1,000 次内核中断，防止 CPU 长时间处于空闲状态，从而影响 CPU 功耗。

现在让我们看一个没有固定或预定义滴答声的内核，其中滴答声被禁用，直到需要执行某些任务。我们称这样的内核为**无滴答内核**。实际上，滴答激活是根据下一个动作安排的。正确的名称应该是**动态滴答内核**。内核负责任务调度，并在系统中维护可运行任务的列表（运行队列）。当没有任务需要调度时，调度程序切换到空闲线程，通过禁用周期性滴答声来启用动态滴答，直到下一个定时器到期（新任务排队等待处理）。

在底层，内核还维护任务超时的列表（然后知道何时以及需要睡眠多长时间）。在空闲状态下，如果下一个滴答声比任务列表超时中的最低超时时间更长，则内核将使用该超时值对定时器进行编程。当定时器到期时，内核重新启用周期性滴答声并调用调度程序，然后调度与超时相关的任务。这就是无滴答内核在空闲时如何移除周期性滴答声并节省电源的方式。

# 内核中的延迟和睡眠

不深入细节，根据代码运行的上下文，有两种类型的延迟：原子或非原子。内核中处理延迟的强制头文件是`#include <linux/delay>`。

# 原子上下文

在原子上下文中的任务（例如 ISR）无法睡眠，也无法被调度；这就是为什么在原子上下文中用于延迟目的的忙等待循环。内核公开了`Xdelay`函数系列，这些函数将在忙循环中花费时间，足够长（基于 jiffies）以实现所需的延迟：

+   `ndelay(unsigned long nsecs)`

+   `udelay(unsigned long usecs)`

+   `mdelay(unsigned long msecs)`

您应该始终使用`udelay()`，因为`ndelay()`的精度取决于您的硬件定时器的准确性（在嵌入式 SOC 上并非总是如此）。还不鼓励使用`mdelay()`。

定时器处理程序（回调）在原子上下文中执行，这意味着根本不允许睡眠。通过*睡眠*，我的意思是可能导致调用者进入睡眠状态的任何函数，例如分配内存，锁定互斥锁，显式调用`sleep()`函数等。

# 非原子上下文

在非原子上下文中，内核提供了`sleep[_range]`函数系列，使用哪个函数取决于您需要延迟多长时间：

+   `udelay(unsigned long usecs)`：基于忙等待循环。如果您需要睡眠几微秒（<〜10 微秒），则应使用此函数。

+   `usleep_range(unsigned long min, unsigned long max)`：依赖于 hrtimers，并建议让此睡眠几个~微秒或小毫秒（10 微秒-20 毫秒），避免`udelay()`的忙等待循环。

+   `msleep(unsigned long msecs)`：由 jiffies/legacy_timers 支持。您应该用于更大的毫秒睡眠（10 毫秒以上）。

内核源代码中的*Documentation/timers/timers-howto.txt*中很好地解释了睡眠和延迟主题。

# 内核锁定机制

锁定是一种帮助在不同线程或进程之间共享资源的机制。共享资源是可以由至少两个用户同时访问的数据或设备，或者不可以。锁定机制可以防止滥用访问，例如，一个进程在另一个进程读取相同位置时写入数据，或者两个进程访问相同的设备（例如相同的 GPIO）。内核提供了几种锁定机制。最重要的是：

+   互斥锁

+   信号量

+   自旋锁

我们只会学习互斥锁和自旋锁，因为它们在设备驱动程序中被广泛使用。

# 互斥锁

**互斥排他**（**mutex**）是事实上最常用的锁定机制。要了解它的工作原理，让我们看看在`include/linux/mutex.h`中它的结构是什么样的：

```
struct mutex { 
    /* 1: unlocked, 0: locked, negative: locked, possible waiters */ 
    atomic_t count; 
    spinlock_t wait_lock; 
    struct list_head wait_list; 
    [...] 
}; 
```

正如我们在*等待队列*部分中所看到的，结构中还有一个`list`类型的字段：`wait_list`。睡眠的原理是相同的。

竞争者从调度程序运行队列中移除，并放入等待列表（`wait_list`）中的睡眠状态。然后内核调度和执行其他任务。当锁被释放时，等待队列中的等待者被唤醒，移出`wait_list`，并重新调度。

# 互斥锁 API

使用互斥锁只需要几个基本函数：

# 声明

+   静态地：

```
DEFINE_MUTEX(my_mutex); 
```

+   动态地：

```
struct mutex my_mutex; 
mutex_init(&my_mutex); 
```

# 获取和释放

+   锁：

```
void mutex_lock(struct mutex *lock); 
int  mutex_lock_interruptible(struct mutex *lock); 
int  mutex_lock_killable(struct mutex *lock); 
```

+   解锁：

```
void mutex_unlock(struct mutex *lock); 
```

有时，您可能只需要检查互斥锁是否被锁定。为此，您可以使用`int mutex_is_locked(struct mutex *lock)`函数。

```
int mutex_is_locked(struct mutex *lock); 
```

这个函数的作用只是检查互斥锁的所有者是否为空（`NULL`）或不为空。还有`mutex_trylock`，如果互斥锁尚未被锁定，则会获取互斥锁，并返回`1`；否则返回`0`：

```
int mutex_trylock(struct mutex *lock); 
```

与等待队列的可中断系列函数一样，`mutex_lock_interruptible()`是推荐的，将导致驱动程序能够被任何信号中断，而`mutex_lock_killable()`只有杀死进程的信号才能中断驱动程序。

在使用`mutex_lock()`时，应非常小心，并且只有在可以保证无论发生什么都会释放互斥锁时才使用它。在用户上下文中，建议始终使用`mutex_lock_interruptible()`来获取互斥锁，因为如果收到信号（甚至是 c*trl + c*），`mutex_lock()`将不会返回。

以下是互斥锁实现的示例：

```
struct mutex my_mutex; 
mutex_init(&my_mutex); 

/* inside a work or a thread */ 
mutex_lock(&my_mutex); 
access_shared_memory(); 
mutex_unlock(&my_mutex); 
```

请查看内核源码中的`include/linux/mutex.h`，以了解您必须遵守的互斥锁的严格规则。以下是其中一些规则：

+   一次只有一个任务可以持有互斥锁；这实际上不是一条规则，而是一个事实

+   不允许多次解锁

+   它们必须通过 API 进行初始化

+   持有互斥锁的任务可能不会退出，因为互斥锁将保持锁定，并且可能的竞争者将永远等待（将永远睡眠）

+   保存锁定的内存区域不得被释放

+   持有的互斥锁不得被重新初始化

+   由于它们涉及重新调度，因此在原子上下文中可能无法使用互斥锁，例如任务和定时器

与`wait_queue`一样，互斥锁没有轮询机制。每次在互斥锁上调用`mutex_unlock`时，内核都会检查`wait_list`中是否有等待者。如果有，其中一个（仅一个）会被唤醒并调度；它们被唤醒的顺序与它们入睡的顺序相同。

# 自旋锁

与互斥锁类似，自旋锁是一种互斥排他机制；它只有两种状态：

+   已锁定（已获取）

+   未锁定（已释放）

需要获取自旋锁的任何线程都将主动循环，直到获取锁为止，然后才会跳出循环。这是互斥锁和自旋锁的区别所在。由于自旋锁在循环时会大量消耗 CPU，因此应该在非常快速获取锁的情况下使用，特别是当持有自旋锁的时间小于重新调度的时间时。自旋锁应该在关键任务完成后尽快释放。

为了避免通过调度可能旋转的线程来浪费 CPU 时间，尝试获取由另一个线程持有的锁，内核在运行持有自旋锁的代码时禁用了抢占。通过禁用抢占，我们防止自旋锁持有者被移出运行队列，这可能导致等待进程长时间旋转并消耗 CPU。

只要持有自旋锁，其他任务可能会在等待它时旋转。通过使用自旋锁，你断言并保证它不会被长时间持有。你可以说在循环中旋转，浪费 CPU 时间，比睡眠线程、上下文切换到另一个线程或进程的成本，然后被唤醒要好。在处理器上旋转意味着没有其他任务可以在该处理器上运行；因此，在单核机器上使用自旋锁是没有意义的。在最好的情况下，你会减慢系统的速度；在最坏的情况下，你会死锁，就像互斥体一样。因此，内核只会在单处理器上对`spin_lock(spinlock_t *lock)`函数做出响应时禁用抢占。在单处理器（核心）系统上，你应该使用`spin_lock_irqsave()`和`spin_unlock_irqrestore()`，分别禁用 CPU 上的中断，防止中断并发。

由于你事先不知道要为哪个系统编写驱动程序，建议你使用`spin_lock_irqsave(spinlock_t *lock, unsigned long flags)`来获取自旋锁，它会在获取自旋锁之前禁用当前处理器（调用它的处理器）上的中断。`spin_lock_irqsave`内部调用`local_irq_save(flags);`，一个依赖于体系结构的函数来保存 IRQ 状态，并调用`preempt_disable()`来禁用相关 CPU 上的抢占。然后你应该使用`spin_unlock_irqrestore()`释放锁，它会执行我们之前列举的相反操作。这是一个执行锁获取和释放的代码。这是一个 IRQ 处理程序，但让我们只关注锁方面。我们将在下一节讨论更多关于 IRQ 处理程序的内容。

```
/* some where */ 
spinlock_t my_spinlock; 
spin_lock_init(my_spinlock); 

static irqreturn_t my_irq_handler(int irq, void *data) 
{ 
    unsigned long status, flags; 

    spin_lock_irqsave(&my_spinlock, flags); 
    status = access_shared_resources(); 

    spin_unlock_irqrestore(&gpio->slock, flags); 
    return IRQ_HANDLED; 
} 
```

# 自旋锁与互斥体

在内核中用于并发的自旋锁和互斥体各自有各自的目标：

+   互斥体保护进程的关键资源，而自旋锁保护 IRQ 处理程序的关键部分

+   互斥体将竞争者置于睡眠状态，直到获得锁，而自旋锁会无限循环旋转（消耗 CPU），直到获得锁

+   由于前面的观点，你不能长时间持有自旋锁，因为等待者会浪费 CPU 时间等待锁，而互斥体可以持有资源需要受保护的时间，因为竞争者被放置在等待队列中睡眠

在处理自旋锁时，请记住抢占仅对持有自旋锁的线程禁用，而不是对自旋等待者禁用。

# 工作延迟机制

延迟是一种安排将来执行的工作的方法。这是一种以后报告动作的方式。显然，内核提供了实现这种机制的设施；它允许你推迟函数，无论它们的类型，以便以后调用和执行。内核中有三种：

+   **SoftIRQs**：在原子上下文中执行

+   **Tasklets**：在原子上下文中执行

+   **Workqueues**：在进程上下文中执行

# Softirqs 和 ksoftirqd

软件中断（softirq），或软件中断是一种延迟机制，仅用于非常快速的处理，因为它在禁用调度程序的情况下运行（在中断上下文中）。你几乎不会直接处理 softirq。只有网络和块设备子系统使用 softirq。Tasklets 是 softirq 的一个实例，在几乎所有需要使用 softirq 的情况下都足够了。

# ksoftirqd

在大多数情况下，softirqs 在硬件中断中调度，这可能会非常快，比它们能够被服务的速度更快。然后它们被内核排队以便稍后处理。**Ksoftirqds**负责延迟执行（这次是在进程上下文中）。ksoftirqd 是每个 CPU 的内核线程，用于处理未服务的软中断：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-dvc-dvr-dev/img/Image00009.jpg)

在我个人电脑的前面的`top`示例中，您可以看到`ksoftirqd/n`条目，其中`n`是 ksoftirqd 运行的 CPU 编号。消耗 CPU 的 ksoftirqd 可能表明系统负载过重或处于**中断风暴**下，这是不好的。您可以查看`kernel/softirq.c`，了解 ksoftirqd 的设计方式。

# Tasklets

Tasklet 是建立在 softirqs 之上的一种底半部（稍后我们将看到这意味着什么）机制。它们在内核中表示为`tasklet_struct`的实例：

```
struct tasklet_struct 
{ 
    struct tasklet_struct *next; 
    unsigned long state; 
    atomic_t count; 
    void (*func)(unsigned long); 
    unsigned long data; 
}; 
```

tasklet 本质上不是可重入的。如果代码在执行过程中可以在任何地方被中断，然后可以安全地再次调用，则称为可重入代码。tasklet 被设计成只能在一个 CPU 上同时运行（即使在 SMP 系统上也是如此），这是它被计划的 CPU，但不同的 tasklet 可以在不同的 CPU 上同时运行。tasklet API 非常基本和直观。

# 声明一个 tasklet

+   动态地：

```
void tasklet_init(struct tasklet_struct *t, 
          void (*func)(unsigned long), unsigned long data); 
```

+   静态地：

```
DECLARE_TASKLET( tasklet_example, tasklet_function, tasklet_data ); 
DECLARE_TASKLET_DISABLED(name, func, data); 
```

这两个函数之间有一个区别；前者创建一个已经启用并准备好在没有任何其他函数调用的情况下进行调度的 tasklet，通过将`count`字段设置为`0`，而后者创建一个已禁用的 tasklet（通过将`count`设置为`1`），在这种情况下，必须调用`tasklet_enable()`才能使 tasklet 可调度：

```
#define DECLARE_TASKLET(name, func, data) \ 
    struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data } 

#define DECLARE_TASKLET_DISABLED(name, func, data) \ 
    struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1),  func, data } 
```

全局地，将`count`字段设置为`0`意味着 tasklet 被禁用，不能执行，而非零值意味着相反。

# 启用和禁用 tasklet

有一个函数可以启用 tasklet：

```
void tasklet_enable(struct tasklet_struct *); 
```

`tasklet_enable`简单地启用 tasklet。在旧的内核版本中，可能会发现使用`void tasklet_hi_enable(struct tasklet_struct *)`，但这两个函数实际上是一样的。要禁用 tasklet，调用：

```
void tasklet_disable(struct tasklet_struct *); 
```

您还可以调用：

```
void tasklet_disable_nosync(struct tasklet_struct *); 
```

`tasklet_disable`将禁用 tasklet，并且只有在 tasklet 终止执行后才会返回（如果它正在运行），而`tasklet_disable_nosync`会立即返回，即使终止尚未发生。

# Tasklet 调度

有两个用于 tasklet 的调度函数，取决于您的 tasklet 是具有正常优先级还是较高优先级的：

```
void tasklet_schedule(struct tasklet_struct *t); 
void tasklet_hi_schedule(struct tasklet_struct *t);
```

内核在两个不同的列表中维护正常优先级和高优先级的 tasklet。`tasklet_schedule`将 tasklet 添加到正常优先级列表中，并使用`TASKLET_SOFTIRQ`标志调度相关的 softirq。使用`tasklet_hi_schedule`，tasklet 将添加到高优先级列表中，并使用`HI_SOFTIRQ`标志调度相关的 softirq。高优先级 tasklet 用于具有低延迟要求的软中断处理程序。有一些与 tasklet 相关的属性您应该知道：

+   对已经计划的 tasklet 调用`tasklet_schedule`，但其执行尚未开始，将不会产生任何效果，导致 tasklet 只执行一次。

+   `tasklet_schedule`可以在 tasklet 中调用，这意味着 tasklet 可以重新安排自己。

+   高优先级的 tasklet 始终在正常优先级的 tasklet 之前执行。滥用高优先级任务会增加系统的延迟。只能用于非常快速的任务。

您可以使用`tasklet_kill`函数停止 tasklet，这将阻止 tasklet 再次运行，或者在当前计划运行时等待其完成后再杀死它：

```
void tasklet_kill(struct tasklet_struct *t); 
```

让我们来看看。看下面的例子：

```
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/interrupt.h>    /* for tasklets API */ 

char tasklet_data[]="We use a string; but it could be pointer to a structure"; 

/* Tasklet handler, that just print the data */ 
void tasklet_work(unsigned long data) 
{ 
    printk("%s\n", (char *)data); 
} 

DECLARE_TASKLET(my_tasklet, tasklet_function, (unsigned long) tasklet_data); 

static int __init my_init(void) 
{ 
    /* 
     * Schedule the handler. 
     * Tasklet arealso scheduled from interrupt handler 
     */ 
    tasklet_schedule(&my_tasklet); 
    return 0; 
} 

void my_exit(void) 
{ 
    tasklet_kill(&my_tasklet); 
} 

module_init(my_init); 
module_exit(my_exit); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
MODULE_LICENSE("GPL"); 
```

# 工作队列

自 Linux 内核 2.6 以来，最常用和简单的推迟机制是工作队列。这是我们将在本章中讨论的最后一个。作为一个推迟机制，它采用了与我们所见其他机制相反的方法，仅在可抢占的上下文中运行。当您需要在底半部分休眠时，它是唯一的选择（我将在下一节中解释什么是底半部分）。通过休眠，我指的是处理 I/O 数据，持有互斥锁，延迟和所有可能导致休眠或将任务移出运行队列的其他任务。

请记住，工作队列是建立在内核线程之上的，这就是为什么我决定根本不谈论内核线程作为推迟机制的原因。但是，在内核中处理工作队列有两种方法。首先，有一个默认的共享工作队列，由一组内核线程处理，每个线程在一个 CPU 上运行。一旦有要安排的工作，您就将该工作排入全局工作队列，该工作将在适当的时刻执行。另一种方法是在专用内核线程中运行工作队列。这意味着每当需要执行工作队列处理程序时，将唤醒您的内核线程来处理它，而不是默认的预定义线程之一。

根据您选择的是共享工作队列还是专用工作队列，要调用的结构和函数是不同的。

# 内核全局工作队列-共享队列

除非您别无选择，或者需要关键性能，或者需要从工作队列初始化到工作调度的所有控制，并且只偶尔提交任务，否则应该使用内核提供的共享工作队列。由于该队列在整个系统中共享，因此您应该友好，并且不应该长时间垄断队列。

由于在每个 CPU 上对队列中的挂起任务的执行是串行化的，因此您不应该长时间休眠，因为在您醒来之前，队列中的其他任务将不会运行。您甚至不知道与您共享工作队列的是谁，因此如果您的任务需要更长时间才能获得 CPU，也不要感到惊讶。共享工作队列中的工作在由内核创建的每个 CPU 线程中执行。

在这种情况下，工作还必须使用`INIT_WORK`宏进行初始化。由于我们将使用共享工作队列，因此无需创建工作队列结构。我们只需要作为参数传递的`work_struct`结构。有三个函数可以在共享工作队列上安排工作：

+   将工作绑定到当前 CPU 的版本：

```
int schedule_work(struct work_struct *work); 
```

+   相同但带有延迟功能：

```
static inline bool schedule_delayed_work(struct delayed_work *dwork, 
                            unsigned long delay) 
```

+   实际在给定 CPU 上安排工作的函数：

```
int schedule_work_on(int cpu, struct work_struct *work); 
```

+   与之前显示的相同，但带有延迟：

```
int scheduled_delayed_work_on(int cpu, struct delayed_work *dwork, unsigned long delay); 
```

所有这些函数都将作为参数安排到系统的共享工作队列`system_wq`中，该队列在`kernel/workqueue.c`中定义：

```
struct workqueue_struct *system_wq __read_mostly; 
EXPORT_SYMBOL(system_wq); 
```

已经提交到共享队列的工作可以使用`cancel_delayed_work`函数取消。您可以使用以下方法刷新共享工作队列：

```
void flush_scheduled_work(void); 
```

由于队列在整个系统中共享，因此在`flush_scheduled_work()`返回之前，人们无法真正知道它可能持续多长时间：

```
#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/sched.h>    /* for sleep */ 
#include <linux/wait.h>     /* for wait queue */ 
#include <linux/time.h> 
#include <linux/delay.h> 
#include <linux/slab.h>         /* for kmalloc() */ 
#include <linux/workqueue.h> 

//static DECLARE_WAIT_QUEUE_HEAD(my_wq); 
static int sleep = 0; 

struct work_data { 
    struct work_struct my_work; 
    wait_queue_head_t my_wq; 
    int the_data; 
}; 

static void work_handler(struct work_struct *work) 
{ 
    struct work_data *my_data = container_of(work, \ 
                                 struct work_data, my_work);  
    printk("Work queue module handler: %s, data is %d\n", __FUNCTION__, my_data->the_data); 
    msleep(2000); 
    wake_up_interruptible(&my_data->my_wq); 
    kfree(my_data); 
} 

static int __init my_init(void) 
{ 
    struct work_data * my_data; 

    my_data = kmalloc(sizeof(struct work_data), GFP_KERNEL); 
    my_data->the_data = 34; 

    INIT_WORK(&my_data->my_work, work_handler); 
    init_waitqueue_head(&my_data->my_wq); 

    schedule_work(&my_data->my_work); 
    printk("I'm goint to sleep ...\n"); 
    wait_event_interruptible(my_data->my_wq, sleep != 0); 
    printk("I am Waked up...\n"); 
    return 0; 
} 

static void __exit my_exit(void) 
{ 
    printk("Work queue module exit: %s %d\n", __FUNCTION__,  __LINE__); 
} 

module_init(my_init); 
module_exit(my_exit); 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com> "); 
MODULE_DESCRIPTION("Shared workqueue"); 
```

为了将数据传递给我的工作队列处理程序，您可能已经注意到在这两个示例中，我将我的`work_struct`结构嵌入到自定义数据结构中，并使用`container_of`来检索它。这是将数据传递给工作队列处理程序的常用方法。

# 专用工作队列

在这里，工作队列表示为`struct workqueue_struct`的一个实例。要排入工作队列的工作表示为`struct work_struct`的一个实例。在将您的工作安排到自己的内核线程之前，有四个步骤：

1.  声明/初始化一个`struct workqueue_struct`。

1.  创建您的工作函数。

1.  创建一个`struct work_struct`，以便将您的工作函数嵌入其中。

1.  将您的工作函数嵌入`work_struct`。

# 编程语法

以下函数在`include/linux/workqueue.h`中定义：

+   声明工作和工作队列：

```
struct workqueue_struct *myqueue; 
struct work_struct thework; 
```

+   定义工作函数（处理程序）：

```
void dowork(void *data) {  /* Code goes here */ }; 
```

+   初始化我们的工作队列并嵌入我们的工作：

```
myqueue = create_singlethread_workqueue( "mywork" ); 
INIT_WORK( &thework, dowork, <data-pointer> ); 
```

我们也可以通过一个名为 `create_workqueue` 的宏创建我们的工作队列。`create_workqueue` 和 `create_singlethread_workqueue` 之间的区别在于前者将创建一个工作队列，该工作队列将为每个可用的处理器创建一个单独的内核线程。

+   调度工作：

```
queue_work(myqueue, &thework); 
```

在给定的延迟时间后排队到给定的工作线程：

```
    queue_dalayed_work(myqueue, &thework, <delay>); 
```

如果工作已经在队列中，则这些函数返回 `false`，如果不在队列中则返回 `true`。`delay` 表示排队前等待的 jiffies 数。您可以使用辅助函数 `msecs_to_jiffies` 将标准毫秒延迟转换为 jiffies。例如，要在 5 毫秒后排队工作，可以使用 `queue_delayed_work(myqueue, &thework, msecs_to_jiffies(5));`。

+   等待给定工作队列上的所有待处理工作：

```
void flush_workqueue(struct workqueue_struct *wq) 
```

`flush_workqueue` 等待直到所有排队的工作都完成执行。新进入的（排队的）工作不会影响等待。通常可以在驱动程序关闭处理程序中使用这个函数。

+   清理：

使用 `cancel_work_sync()` 或 `cancel_delayed_work_sync` 进行同步取消，如果工作尚未运行，将取消工作，或者阻塞直到工作完成。即使工作重新排队，也将被取消。您还必须确保在处理程序返回之前，最后排队的工作队列不会被销毁。这些函数分别用于非延迟或延迟工作：

```
int cancel_work_sync(struct work_struct *work); 
int cancel_delayed_work_sync(struct delayed_work *dwork); 
```

自 Linux 内核 v4.8 起，可以使用 `cancel_work` 或 `cancel_delayed_work`，这是取消的异步形式。必须检查函数是否返回 true 或 false，并确保工作不会重新排队。然后必须显式刷新工作队列：

```
if ( !cancel_delayed_work( &thework) ){

flush_workqueue(myqueue);

destroy_workqueue(myqueue);

}
```

另一个是相同方法的不同版本，将为所有处理器创建一个线程。如果需要在工作排队之前延迟，请随时使用以下工作初始化宏：

```
INIT_DELAYED_WORK(_work, _func); 
INIT_DELAYED_WORK_DEFERRABLE(_work, _func); 
```

使用上述宏意味着您应该使用以下函数在工作队列中排队或调度工作：

```
int queue_delayed_work(struct workqueue_struct *wq, 
            struct delayed_work *dwork, unsigned long delay) 
```

`queue_work` 将工作绑定到当前 CPU。您可以使用 `queue_work_on` 函数指定处理程序应在哪个 CPU 上运行：

```
int queue_work_on(int cpu, struct workqueue_struct *wq, 
                   struct work_struct *work); 
```

对于延迟工作，您可以使用：

```
int queue_delayed_work_on(int cpu, struct workqueue_struct *wq, 
    struct delayed_work *dwork, unsigned long delay);
```

以下是使用专用工作队列的示例：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/workqueue.h>    /* for work queue */ 
#include <linux/slab.h>         /* for kmalloc() */ 

struct workqueue_struct *wq; 

struct work_data { 
    struct work_struct my_work; 
    int the_data; 
}; 

static void work_handler(struct work_struct *work) 
{ 
    struct work_data * my_data = container_of(work, 
                                   struct work_data, my_work); 
    printk("Work queue module handler: %s, data is %d\n", 
         __FUNCTION__, my_data->the_data); 
    kfree(my_data); 
} 

static int __init my_init(void) 
{ 
    struct work_data * my_data; 

    printk("Work queue module init: %s %d\n", 
           __FUNCTION__, __LINE__); 
    wq = create_singlethread_workqueue("my_single_thread"); 
    my_data = kmalloc(sizeof(struct work_data), GFP_KERNEL); 

    my_data->the_data = 34; 
    INIT_WORK(&my_data->my_work, work_handler); 
    queue_work(wq, &my_data->my_work); 

    return 0; 
} 

static void __exit my_exit(void) 
{ 
    flush_workqueue(wq); 
    destroy_workqueue(wq); 
    printk("Work queue module exit: %s %d\n", 
                   __FUNCTION__, __LINE__); 
} 

module_init(my_init); 
module_exit(my_exit); 
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu <john.madieu@gmail.com>"); 
```

# 预定义（共享）工作队列和标准工作队列函数

预定义的工作队列在 `kernel/workqueue.c` 中定义如下：

```
struct workqueue_struct *system_wq __read_mostly; 
```

它只是一个标准工作，内核为其提供了一个简单包装标准工作的自定义 API。

内核预定义的工作队列函数与标准工作队列函数的比较如下：

| **预定义工作队列函数** | **等效标准工作队列函数** |
| --- | --- |
| `schedule_work(w)` | `queue_work(keventd_wq,w)` |
| `schedule_delayed_work(w,d)` | `queue_delayed_work(keventd_wq,w,d)`（在任何 CPU 上） |
| `schedule_delayed_work_on(cpu,w,d)` | `queue_delayed_work(keventd_wq,w,d)`（在给定的 CPU 上） |
| `flush_scheduled_work()` | `flush_workqueue(keventd_wq)` |

# 内核线程

工作队列运行在内核线程之上。当您使用工作队列时，已经在使用内核线程。这就是为什么我决定不谈论内核线程 API 的原因。

# 内核中断机制

中断是设备停止内核的方式，告诉内核发生了有趣或重要的事情。在 Linux 系统上称为 IRQ。中断提供的主要优势是避免设备轮询。由设备告知其状态是否发生变化；不是由我们轮询它。

为了在中断发生时得到通知，您需要注册到该 IRQ，提供一个称为中断处理程序的函数，每次引发该中断时都会调用它。

# 注册中断处理程序

您可以注册一个回调函数，在您感兴趣的中断（或中断线）被触发时运行。您可以使用`<linux/interrupt.h>`中声明的`request_irq()`函数来实现这一点。

```
int request_irq(unsigned int irq, irq_handler_t handler, 
    unsigned long flags, const char *name, void *dev) 
```

`request_irq()`可能会失败，并在成功时返回`0`。前面代码的其他元素如下所述：

+   `flags`：这些应该是`<linux/interrupt.h>`中定义的掩码的位掩码。最常用的是：

+   `IRQF_TIMER:` 通知内核，此处理程序由系统定时器中断发起。

+   `IRQF_SHARED:` 用于可以被两个或更多设备共享的中断线。共享同一线的每个设备都必须设置此标志。如果省略，只能为指定的 IRQ 线注册一个处理程序。

+   `IRQF_ONESHOT:` 主要用于线程化的 IRQ。它指示内核在硬中断处理程序完成后不要重新启用中断。它将保持禁用状态，直到线程处理程序运行。

+   在旧的内核版本（直到 v2.6.35），有`IRQF_DISABLED`标志，它要求内核在处理程序运行时禁用所有中断。现在不再使用这个标志。

+   `name`：这由内核用于在`/proc/interrupts`和`/proc/irq`中标识您的驱动程序。

+   `dev`：其主要目标是作为处理程序的参数传递。这应该对每个注册的处理程序都是唯一的，因为它用于标识设备。对于非共享的 IRQ，它可以是`NULL`，但对于共享的 IRQ 则不行。通常的使用方式是提供一个`device`结构，因为它既是唯一的，也可能对处理程序有用。也就是说，任何与设备相关的数据结构的指针都是足够的：

```
struct my_data { 
   struct input_dev *idev; 
   struct i2c_client *client; 
   char name[64]; 
   char phys[32]; 
 }; 

 static irqreturn_t my_irq_handler(int irq, void *dev_id) 
 { 
    struct my_data *md = dev_id; 
    unsigned char nextstate = read_state(lp); 
    /* Check whether my device raised the irq or no */ 
    [...] 
    return IRQ_HANDLED; 
 } 

 /* some where in the code, in the probe function */ 
 int ret; 
 struct my_data *md; 
 md = kzalloc(sizeof(*md), GFP_KERNEL); 

 ret = request_irq(client->irq, my_irq_handler, 
                    IRQF_TRIGGER_LOW | IRQF_ONESHOT, 
                    DRV_NAME, md); 

 /* far in the release function */ 
 free_irq(client->irq, md); 
```

+   `handler`：这是当中断触发时将运行的回调函数。中断处理程序的结构如下：

```
static irqreturn_t my_irq_handler(int irq, void *dev) 
```

+   这包含以下代码元素：

+   `irq`：IRQ 的数值（与`request_irq`中使用的相同）。

+   `dev`：与`request_irq`中使用的相同。

这两个参数由内核传递给您的处理程序。处理程序只能返回两个值，取决于您的设备是否引起了 IRQ：

+   `IRQ_NONE`：您的设备不是该中断的发起者（这在共享的 IRQ 线上经常发生）

+   `IRQ_HANDLED`：您的设备引起了中断

根据处理情况，可以使用`IRQ_RETVAL(val)`宏，如果值非零，则返回`IRQ_HANDLED`，否则返回`IRQ_NONE`。

在编写中断处理程序时，您不必担心重入性，因为内核会在所有处理器上禁用服务的 IRQ 线，以避免递归中断。

释放先前注册的处理程序的相关函数是：

```
void free_irq(unsigned int irq, void *dev) 
```

如果指定的 IRQ 不是共享的，`free_irq`不仅会删除处理程序，还会禁用该线路。如果是共享的，只有通过`dev`（应该与`request_irq`中使用的相同）标识的处理程序被删除，但中断线路仍然存在，只有在最后一个处理程序被删除时才会被禁用。`free_irq`将阻塞，直到指定 IRQ 的所有执行中断完成。然后，您必须避免在中断上下文中同时使用`request_irq`和`free_irq`。

# 中断处理程序和锁

不用说，您处于原子上下文中，只能使用自旋锁进行并发。每当全局数据可被用户代码（用户任务；即系统调用）和中断代码访问时，这些共享数据应该在用户代码中由`spin_lock_irqsave()`保护。让我们看看为什么我们不能只使用`spin_lock`。中断处理程序将始终优先于用户任务，即使该任务持有自旋锁。简单地禁用 IRQ 是不够的。中断可能发生在另一个 CPU 上。如果用户任务更新数据时被中断处理程序尝试访问相同的数据，那将是一场灾难。使用`spin_lock_irqsave()`将在本地 CPU 上禁用所有中断，防止系统调用被任何类型的中断中断：

```
ssize_t my_read(struct file *filp, char __user *buf, size_t count,  
   loff_t *f_pos) 
{ 
    unsigned long flags; 
    /* some stuff */ 
    [...] 
    unsigned long flags; 
    spin_lock_irqsave(&my_lock, flags); 
    data++; 
    spin_unlock_irqrestore(&my_lock, flags) 
    [...] 
} 

static irqreturn_t my_interrupt_handler(int irq, void *p) 
{ 
    /* 
     * preemption is disabled when running interrupt handler 
     * also, the serviced irq line is disabled until the handler has completed 
     * no need then to disable all other irq. We just use spin_lock and 
     * spin_unlock 
     */ 
    spin_lock(&my_lock); 
    /* process data */ 
    [...] 
    spin_unlock(&my_lock); 
    return IRQ_HANDLED; 
} 
```

在不同的中断处理程序之间共享数据（即，同一驱动程序管理两个或多个设备，每个设备都有自己的 IRQ 线），应该在这些处理程序中使用`spin_lock_irqsave()`来保护数据，以防止其他 IRQ 被触发并且无用地旋转。

# 底半部分的概念

底半部分是一种将中断处理程序分成两部分的机制。这引入了另一个术语，即顶半部分。在讨论它们各自之前，让我们谈谈它们的起源以及它们解决了什么问题。

# 问题-中断处理程序设计的限制

无论中断处理程序是否持有自旋锁，都会在运行该处理程序的 CPU 上禁用抢占。在处理程序中浪费的时间越多，分配给其他任务的 CPU 就越少，这可能会显着增加其他中断的延迟，从而增加整个系统的延迟。挑战在于尽快确认引发中断的设备，以保持系统的响应性。

在 Linux 系统（实际上在所有操作系统上，根据硬件设计），任何中断处理程序都会在所有处理器上禁用其当前中断线，并且有时您可能需要在实际运行处理程序的 CPU 上禁用所有中断，但绝对不想错过中断。为了满足这个需求，引入了*halves*的概念。

# 解决方案-底半部分

这个想法是将处理程序分成两部分：

+   第一部分称为顶半部分或硬中断，它是使用`request_irq()`注册的函数，最终会掩盖/隐藏中断（在当前 CPU 上，除了正在服务的 CPU，因为内核在运行处理程序之前已经禁用了它），根据需要执行快速操作（基本上是时间敏感的任务，读/写硬件寄存器以及对这些数据的快速处理），安排第二部分和下一个部分，然后确认该线路。所有被禁用的中断必须在退出底半部分之前重新启用。

+   第二部分，称为底半部分，将处理耗时的任务，并在重新启用中断时运行。这样，您就有机会不会错过中断。

底半部分是使用工作推迟机制设计的，我们之前已经看到了。根据您选择的是哪一个，它可能在（软件）中断上下文中运行，或者在进程上下文中运行。底半部分的机制有：

+   软中断

+   任务 let

+   工作队列

+   线程中断

软中断和任务 let 在（软件）中断上下文中执行（意味着抢占被禁用），工作队列和线程中断在进程（或简单任务）上下文中执行，并且可以被抢占，但没有什么可以阻止我们改变它们的实时属性以适应您的需求并改变它们的抢占行为（参见`CONFIG_PREEMPT`或`CONFIG_PREEMPT_VOLUNTARY`。这也会影响整个系统）。底半部分并不总是可能的。但当可能时，这绝对是最好的选择。

# 任务 let 作为底半部分

任务延迟机制在 DMA、网络和块设备驱动程序中最常用。只需在内核源代码中尝试以下命令：

```
 grep -rn tasklet_schedule

```

现在让我们看看如何在我们的中断处理程序中实现这样的机制：

```
struct my_data { 
    int my_int_var; 
    struct tasklet_struct the_tasklet; 
    int dma_request; 
}; 

static void my_tasklet_work(unsigned long data) 
{ 
    /* Do what ever you want here */ 
} 

struct my_data *md = init_my_data; 

/* somewhere in the probe or init function */ 
[...] 
   tasklet_init(&md->the_tasklet, my_tasklet_work, 
                 (unsigned long)md); 
[...] 

static irqreturn_t my_irq_handler(int irq, void *dev_id) 
{ 
    struct my_data *md = dev_id; 

    /* Let's schedule our tasklet */ 
    tasklet_schedule(&md.dma_tasklet); 

    return IRQ_HANDLED; 
} 
```

在上面的示例中，我们的 tasklet 将执行函数`my_tasklet_work()`。

# 工作队列作为底半部分。

让我们从一个示例开始：

```
static DECLARE_WAIT_QUEUE_HEAD(my_wq);  /* declare and init the wait queue */ 
static struct work_struct my_work; 

/* some where in the probe function */ 
/* 
 * work queue initialization. "work_handler" is the call back that will be 
 * executed when our work is scheduled. 
 */ 
INIT_WORK(my_work, work_handler); 

static irqreturn_t my_interrupt_handler(int irq, void *dev_id) 
{ 
    uint32_t val; 
    struct my_data = dev_id; 

    val = readl(my_data->reg_base + REG_OFFSET); 
   if (val == 0xFFCD45EE)) { 
       my_data->done = true; 
         wake_up_interruptible(&my_wq); 
   } else { 
         schedule_work(&my_work); 
   } 

   return IRQ_HANDLED; 
}; 
```

在上面的示例中，我们使用等待队列或工作队列来唤醒可能正在等待我们的进程，或者根据寄存器的值安排工作。我们没有共享的数据或资源，因此不需要禁用所有其他 IRQs（`spin_lock_irq_disable`）。

# Softirqs 作为底半部分

正如本章开头所说，我们不会讨论 softirq。在你感觉需要使用 softirqs 的任何地方，tasklets 都足够了。无论如何，让我们谈谈它们的默认值。

Softirq 在软件中断上下文中运行，禁用了抢占，保持 CPU 直到它们完成。Softirq 应该很快；否则它们可能会减慢系统。当由于任何原因 softirq 阻止内核调度其他任务时，任何新进入的 softirq 将由**ksoftirqd**线程处理，运行在进程上下文中。

# 线程化的 IRQs

线程化的 IRQs 的主要目标是将中断禁用的时间减少到最低限度。使用线程化的 IRQs，注册中断处理程序的方式有些简化。你甚至不需要自己安排底半部分。核心会为我们做这件事。然后底半部分将在一个专用的内核线程中执行。我们不再使用`request_irq()`，而是使用`request_threaded_irq()`：

```
int request_threaded_irq(unsigned int irq, irq_handler_t handler,\ 
                            irq_handler_t thread_fn, \ 
                            unsigned long irqflags, \ 
                            const char *devname, void *dev_id) 

```

`request_threaded_irq()`函数在其参数中接受两个函数：

+   **@handler 函数**：这与使用`request_irq()`注册的函数相同。它代表顶半部分函数，运行在原子上下文（或硬中断）中。如果它可以更快地处理中断，以至于你可以完全摆脱底半部分，它应该返回`IRQ_HANDLED`。但是，如果中断处理需要超过 100 微秒，如前面讨论的那样，你应该使用底半部分。在这种情况下，它应该返回`IRQ_WAKE_THREAD`，这将导致调度必须已经提供的`thread_fn`函数。

+   **@thread_fn 函数**：这代表了底半部分，就像你在顶半部分中安排的那样。当硬中断处理程序（处理函数）返回`IRQ_WAKE_THREAD`时，与该底半部分相关联的 kthread 将被调度，在运行 ktread 时调用`thread_fn`函数。`thread_fn`函数在完成时必须返回`IRQ_HANDLED`。执行完毕后，kthread 将不会再次被调度，直到再次触发 IRQ 并且硬中断返回`IRQ_WAKE_THREAD`。

在任何你会使用工作队列来安排底半部分的地方，都可以使用线程化的 IRQs。必须定义`handler`和`thread_fn`以正确使用线程化的 IRQ。如果`handler`为`NULL`且`thread_fn != NULL`（见下文），内核将安装默认的硬中断处理程序，它将简单地返回`IRQ_WAKE_THREAD`以安排底半部分。`handler`总是在中断上下文中调用，无论是由你自己提供还是默认情况下由内核提供的。

```
/* 
 * Default primary interrupt handler for threaded interrupts. Is 
 * assigned as primary handler when request_threaded_irq is called 
 * with handler == NULL. Useful for oneshot interrupts. 
 */ 
static irqreturn_t irq_default_primary_handler(int irq, void *dev_id) 
{ 
    return IRQ_WAKE_THREAD; 
} 

request_threaded_irq(unsigned int irq, irq_handler_t handler, 
                         irq_handler_t thread_fn, unsigned long irqflags, 
                         const char *devname, void *dev_id) 
{ 
        [...] 
        if (!handler) { 
                if (!thread_fn) 
                        return -EINVAL; 
                handler = irq_default_primary_handler; 
        } 
        [...] 
} 
EXPORT_SYMBOL(request_threaded_irq); 

```

使用线程化的 IRQs，处理程序的定义不会改变，但它的注册方式会有一点变化。

```
request_irq(unsigned int irq, irq_handler_t handler, \ 
            unsigned long flags, const char *name, void *dev) 
{ 
    return request_threaded_irq(irq, handler, NULL, flags, \ 
                                name, dev); 
} 
```

# 线程化的底半部分

以下简单的摘录演示了如何实现线程化的底半部分机制：

```
static irqreturn_t pcf8574_kp_irq_handler(int irq, void *dev_id) 
{ 
    struct custom_data *lp = dev_id; 
    unsigned char nextstate = read_state(lp); 

    if (lp->laststate != nextstate) { 
        int key_down = nextstate < ARRAY_SIZE(lp->btncode); 
        unsigned short keycode = key_down ?  
            p->btncode[nextstate] : lp->btncode[lp->laststate]; 

        input_report_key(lp->idev, keycode, key_down); 
        input_sync(lp->idev); 
        lp->laststate = nextstate; 
    } 
    return IRQ_HANDLED; 
} 

static int pcf8574_kp_probe(struct i2c_client *client, \ 
                          const struct i2c_device_id *id) 
{ 
    struct custom_data *lp = init_custom_data(); 
    [...] 
    /* 
     * @handler is NULL and @thread_fn != NULL 
     * the default primary handler is installed, which will  
     * return IRQ_WAKE_THREAD, that will schedule the thread  
     * asociated to the bottom half. the bottom half must then  
     * return IRQ_HANDLED when finished 
     */ 
    ret = request_threaded_irq(client->irq, NULL, \ 
                            pcf8574_kp_irq_handler, \ 
                            IRQF_TRIGGER_LOW | IRQF_ONESHOT, \ 
                            DRV_NAME, lp); 
    if (ret) { 
        dev_err(&client->dev, "IRQ %d is not free\n", \ 
                 client->irq); 
        goto fail_free_device; 
    } 
    ret = input_register_device(idev); 
    [...] 
} 
```

当中断处理程序被执行时，所有 CPU 上的服务 IRQ 始终被禁用，并在硬件 IRQ（顶半部）完成时重新启用。但是，如果出于任何原因，您需要在顶半部完成后不重新启用 IRQ 线，并且保持禁用直到线程处理程序运行完毕，您应该使用启用了 `IRQF_ONESHOT` 标志的线程 IRQ（只需像之前显示的那样执行 OR 操作）。然后 IRQ 线将在底半部完成后重新启用。

# 从内核调用用户空间应用程序

用户空间应用程序大多数情况下是由其他应用程序从用户空间调用的。不深入细节，让我们看一个例子：

```
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/workqueue.h>    /* for work queue */ 
#include <linux/kmod.h> 

static struct delayed_work initiate_shutdown_work; 
static void delayed_shutdown( void ) 
{ 
   char *cmd = "/sbin/shutdown"; 
   char *argv[] = { 
         cmd, 
         "-h", 
         "now", 
         NULL, 
   }; 
   char *envp[] = { 
         "HOME=/", 
         "PATH=/sbin:/bin:/usr/sbin:/usr/bin", 
         NULL, 
   }; 

   call_usermodehelper(cmd, argv, envp, 0); 
} 

static int __init my_shutdown_init( void ) 
{ 
    schedule_delayed_work(&delayed_shutdown, msecs_to_jiffies(200)); 
    return 0; 
} 

static void __exit my_shutdown_exit( void ) 
{ 
  return; 
} 

module_init( my_shutdown_init ); 
module_exit( my_shutdown_exit ); 

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("John Madieu", <john.madieu@gmail.com>); 
MODULE_DESCRIPTION("Simple module that trigger a delayed shut down"); 
```

在前面的例子中，使用的 API（`call_usermodehelper`）是 Usermode-helper API 的一部分，所有函数都在 `kernel/kmod.c` 中定义。它的使用非常简单；只需查看 `kmod.c` 就能给你一个想法。您可能想知道这个 API 是为什么定义的。例如，内核使用它进行模块（卸载）和 cgroups 管理。

# 总结

在本章中，我们讨论了开始驱动程序开发的基本元素，介绍了驱动程序中经常使用的每种机制。本章非常重要，因为它涉及到本书其他章节依赖的主题。例如，下一章将处理字符设备，将使用本章讨论的一些元素。
