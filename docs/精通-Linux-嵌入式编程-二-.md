# 精通 Linux 嵌入式编程（二）

> 原文：[`zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814`](https://zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：移植和配置内核

内核是嵌入式 Linux 的第三个元素。它是负责管理资源和与硬件接口的组件，因此几乎影响到最终软件构建的每个方面。它通常根据您的特定硬件配置进行定制，尽管正如我们在第三章中看到的，设备树允许您通过设备树的内容创建一个通用内核，以适应特定硬件。

在本章中，我们将看看如何为板载获取内核，以及如何配置和编译它。我们将再次看看引导加载程序，这次重点放在内核所扮演的角色上。我们还将看看设备驱动程序以及它们如何从设备树中获取信息。

# 内核的主要作用是什么？

Linux 始于 1991 年，当时 Linus Torvalds 开始为基于 Intel 386 和 486 的个人计算机编写操作系统。他受到了四年前 Andrew S. Tanenbaum 编写的 Minix 操作系统的启发。Linux 在许多方面与 Minix 不同，主要区别在于它是一个 32 位虚拟内存内核，代码是开源的，后来发布在 GPL 2 许可下。

1991 年 8 月 25 日，他在*comp.os.minix*新闻组上宣布了这一消息，这是一篇著名的帖子，开头是*大家好，所有使用 minix 的人 - 我正在为 386(486) AT 克隆机做一个(免费)操作系统(只是一项爱好，不会像 gnu 那样大而专业)。这个想法从四月份开始酝酿，现在已经开始准备。我想听听大家对 minix 中喜欢/不喜欢的东西的反馈，因为我的操作系统在某种程度上类似(minix)（由于实际原因，文件系统的物理布局相同，等等）*。

严格来说，Linus 并没有编写操作系统，而是编写了一个内核，这是操作系统的一个组成部分。为了创建一个工作系统，他使用了 GNU 项目的组件，特别是工具链、C 库和基本命令行工具。这种区别至今仍然存在，并且使 Linux 在使用方式上具有很大的灵活性。它可以与 GNU 用户空间结合，创建一个在台式机和服务器上运行的完整 Linux 发行版，有时被称为 GNU/Linux；它可以与 Android 用户空间结合，创建著名的移动操作系统；或者它可以与基于 Busybox 的小型用户空间结合，创建一个紧凑的嵌入式系统。与 BSD 操作系统（FreeBSD、OpenBSD 和 NetBSD）形成对比，其中内核、工具链和用户空间组合成一个单一的代码库。

内核有三个主要任务：管理资源、与硬件接口和提供 API，为用户空间程序提供有用的抽象级别，如下图所示：

![内核的主要作用是什么？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_04_01.jpg)

在用户空间运行的应用程序以较低的 CPU 特权级别运行。除了进行库调用之外，它们几乎无法做任何事情。用户空间和内核空间之间的主要接口是 C 库，它将用户级函数（如 POSIX 定义的函数）转换为内核系统调用。系统调用接口使用特定于体系结构的方法，如陷阱或软件中断，将 CPU 从低特权用户模式切换到高特权内核模式，从而允许访问所有内存地址和 CPU 寄存器。

系统调用处理程序将调用分派到适当的内核子系统：调度调用调度程序，文件系统调用文件系统代码等。其中一些调用需要来自底层硬件的输入，并将被传递给设备驱动程序。在某些情况下，硬件本身通过引发中断来调用内核函数。中断只能由设备驱动程序处理，而不能由用户空间应用程序处理。

换句话说，您的应用程序执行的所有有用的功能都是通过内核完成的。因此，内核是系统中最重要的元素之一。

# 选择内核

下一步是选择适合您项目的内核，平衡了始终使用最新软件版本的愿望和对特定供应商添加的需求。

## 内核开发周期

Linux 已经以快速的速度发展，每 8 到 12 周发布一个新版本。近年来，版本号的构造方式有所改变。2011 年 7 月之前，版本号采用了三位数的版本方案，版本号看起来像 2.6.39。中间的数字表示它是开发人员还是稳定版本，奇数（2.1.x、2.3.x、2.5.x）是给开发人员的，偶数是给最终用户的。从 2.6 版本开始，长期的开发分支（奇数）的概念被放弃了，因为它减缓了新功能向用户提供的速度。从 2.6.39 到 2011 年 7 月的 3.0 的编号变化纯粹是因为 Linus 觉得数字变得太大了：在这两个版本之间，Linux 的功能或架构没有发生巨大的飞跃。他还趁机去掉了中间的数字。从那时起，2015 年 4 月，他将主要版本从 3 提升到 4，也纯粹是为了整洁，而不是因为有任何重大的架构变化。

Linus 管理开发内核树。您可以通过克隆他的 git 树来关注他：

```
$ git clone \ git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

```

这将检出到子目录`linux`。您可以通过在该目录中不时运行`git pull`命令来保持最新。

目前，内核开发的完整周期始于两周的合并窗口期，在此期间 Linus 将接受新功能的补丁。合并窗口结束后，稳定化阶段开始，Linus 将发布版本号以-rc1、-rc2 等结尾的候选版本，通常会发布到-rc7 或-rc8。在此期间，人们测试候选版本并提交错误报告和修复。当所有重要的错误都被修复后，内核就会发布。

合并窗口期间合并的代码必须已经相当成熟。通常，它是从内核的许多子系统和架构维护者的存储库中提取的。通过保持短的开发周期，可以在功能准备就绪时合并功能。如果内核维护人员认为某个功能不够稳定或发展不够完善，它可以简单地延迟到下一个发布版本。

跟踪每个版本之间的变化并不容易。您可以阅读 Linus 的 git 存储库中的提交日志，但是每个发布版本大约有 10,000 个或更多的条目，很难得到一个概述。幸运的是，有*Linux Kernel Newbies*网站，[`kernelnewbies.org`](http://kernelnewbies.org)，您可以在[`kernelnewbies.org/LinuxVersions`](http://kernelnewbies.org/LinuxVersions)找到每个版本的简要概述。

## 稳定和长期支持版本

Linux 的快速变化速度是一件好事，因为它将新功能引入了主线代码库，但它并不太适合嵌入式项目的较长生命周期。内核开发人员以两种方式解决了这个问题。首先，他们承认一个发布版本可能包含需要在下一个内核发布版本之前修复的错误。这就是由 Greg Kroah-Hartman 维护的稳定 Linux 内核的作用。发布后，内核从“主线”（由 Linus 维护）转变为“稳定”（由 Greg 维护）。稳定内核的错误修复版本由第三个数字标记，如 3.18.1、3.18.2 等。在 3 版本之前，有四个发布数字，如 2.6.29.1、2.6.39.2 等。

您可以使用以下命令获取稳定树：

```
$ git clone \
git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git

```

您可以使用`git chckout`获取特定版本，例如版本 4.1.10：

```
$ cd linux-stable
$ git checkout v4.1.10

```

通常，稳定的内核只维护到下一个主线发布，通常是 8 到 12 周后，因此您会发现在[kernel.org](http://kernel.org)上只有一个或两个稳定的内核。为了满足那些希望在更长时间内获得更新并确保任何错误都将被发现和修复的用户，一些内核被标记为**长期**，并维护两年或更长时间。每年至少有一个长期内核。在撰写本文时，[kernel.org](http://kernel.org)上总共有八个长期内核：4.1、3.18、3.14、3.12、3.10、3.4、3.2 和 2.6.32。后者已经维护了五年，目前版本为 2.6.32.68。如果您正在构建一个需要维护这么长时间的产品，最新的长期内核可能是一个不错的选择。

## 供应商支持

在理想的世界中，您可以从[kernel.org](http://kernel.org)下载内核，并为任何声称支持 Linux 的设备进行配置。然而，这并不总是可能的：事实上，主线 Linux 只对可以运行 Linux 的许多设备中的一小部分具有坚实的支持。您可能会从独立的开源项目、Linaro 或 Yocto 项目等地方找到对您的板子或 SoC 的支持，或者从提供嵌入式 Linux 第三方支持的公司那里找到支持，但在许多情况下，您将被迫寻求您的 SoC 或板子的供应商提供一个可用的内核。正如我们所知，有些供应商比其他供应商更好。

### 提示

我在这一点上唯一的建议是选择给予良好支持的供应商，或者更好的是，让他们的内核更改进入主线。

## 许可

Linux 源代码根据 GPL v2 许可，这意味着您必须以许可中指定的一种方式提供内核的源代码。

内核许可的实际文本在`COPYING`文件中。它以 Linus 撰写的附录开头，附录指出通过系统调用接口从用户空间调用内核的代码不被视为内核的衍生作品，因此不受许可的约束。因此，在 Linux 上运行专有应用程序没有问题。

然而，有一个 Linux 许可的领域引起了无休止的混乱和争论：内核模块。内核模块只是在运行时与内核动态链接的一段代码，从而扩展了内核的功能。GPL 对静态链接和动态链接没有区别，因此内核模块的源代码似乎受到 GPL 的约束。但是，在 Linux 的早期，关于这一规则的例外情况进行了辩论，例如与 Andrew 文件系统有关。这段代码早于 Linux，因此（有人认为）不是衍生作品，因此许可不适用。多年来，关于其他代码的类似讨论也进行了讨论，结果是现在普遍认为 GPL 不一定适用于内核模块。这由内核`MODULE_LICENSE`宏所规定，该宏可以取值`Proprietary`，表示它不是根据 GPL 发布的。如果您打算自己使用相同的论点，您可能需要阅读一篇经常引用的电子邮件主题，标题为*Linux GPL 和二进制模块例外条款？*（[`yarchive.net/comp/linux/gpl_modules.html`](http://yarchive.net/comp/linux/gpl_modules.html)）。

GPL 应该被视为一件好事，因为它保证了当你和我在嵌入式项目上工作时，我们总是可以获得内核的源代码。没有它，嵌入式 Linux 将会更难使用，更加分散。

# 构建内核

在决定基于哪个内核构建您的构建之后，下一步是构建它。

## 获取源代码

假设您有一个在主线上受支持的板子。您可以通过 git 获取源代码，也可以通过下载 tarball 获取。使用 git 更好，因为您可以查看提交历史，轻松查看您可能进行的任何更改，并且可以在分支和版本之间切换。在此示例中，我们正在克隆稳定树并检出版本标签 4.1.10：

```
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux
$ cd linux
$ git checkout v4.1.10

```

或者，您可以从[`cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.1.10.tar.xz`](https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.1.10.tar.xz)下载 tarball。

这里有很多代码。在 4.1 内核中有超过 38,000 个文件，包含 C 源代码、头文件和汇编代码，总共超过 1250 万行代码（由 cloc 实用程序测量）。尽管如此，了解代码的基本布局并大致知道在哪里寻找特定组件是值得的。感兴趣的主要目录有：

+   `arch`: 这包含特定于体系结构的文件。每个体系结构都有一个子目录。

+   `Documentation`: 这包含内核文档。如果您想要找到有关 Linux 某个方面的更多信息，首先请查看这里。

+   `drivers`: 这包含设备驱动程序，成千上万个。每种类型的驱动程序都有一个子目录。

+   `fs`: 这包含文件系统代码。

+   `include`: 这包含内核头文件，包括构建工具链时所需的头文件。

+   `init`: 这包含内核启动代码。

+   `kernel`: 这包含核心功能，包括调度、锁定、定时器、电源管理和调试/跟踪代码。

+   `mm`: 这包含内存管理。

+   `net`: 这包含网络协议。

+   `scripts`: 这包含许多有用的脚本，包括设备树编译器 dtc，我在第三章中描述了*关于引导加载程序的一切*。

+   `工具`: 这包含许多有用的工具，包括 Linux 性能计数器工具 perf，在第十三章中我会描述*性能分析和跟踪*。

随着时间的推移，您将熟悉这种结构，并意识到，如果您正在寻找特定 SoC 的串行端口代码，您将在`drivers/tty/serial`中找到它，而不是在`arch/$ARCH/mach-foo`中找到，因为它是设备驱动程序，而不是 Linux 在该 SoC 上运行的核心部分。

## 了解内核配置

Linux 的一个优点是您可以根据不同的工作需求配置内核，从小型专用设备（如智能恒温器）到复杂的移动手持设备。在当前版本中有成千上万的配置选项。正确配置配置本身就是一项任务，但在此之前，我想向您展示它是如何工作的，以便您更好地理解正在发生的事情。

配置机制称为`Kconfig`，与之集成的构建系统称为`Kbuild`。两者都在`Documentation/kbuild/`中有文档。`Kconfig/Kbuild`在内核以及其他项目中都有使用，包括 crosstool-NG、U-Boot、Barebox 和 BusyBox。

配置选项在名为`Kconfig`的文件层次结构中声明，使用`Documentation/kbuild/kconfig-language.txt`中描述的语法。在 Linux 中，顶层`Kconfig`看起来像这样：

```
mainmenu "Linux/$ARCH $KERNELVERSION Kernel Configuration"
config SRCARCH
  string
  option env="SRCARCH"
  source "arch/$SRCARCH/Kconfig"
```

最后一行包括与体系结构相关的配置文件，该文件根据启用的选项源自其他`Kconfig`文件。体系结构发挥如此重要的作用有两个含义：首先，在配置 Linux 时必须通过设置`ARCH=[architecture]`指定体系结构，否则它将默认为本地机器体系结构；其次，每个体系结构的顶级菜单布局都不同。

您放入`ARCH`的值是您在`arch`目录中找到的子目录之一，其中有一个奇怪之处，即`ARCH=i386`和`ARCH=x86_64`都具有源`arch/x86/Kconfig`。

`Kconfig`文件主要由菜单组成，由`menu`、`menu title`和`endmenu`关键字界定，菜单项由`config`标记。以下是一个例子，取自`drivers/char/Kconfig`：

```
menu "Character devices"
[...]
config DEVMEM
  bool "/dev/mem virtual device support"
  default y
    help
    Say Y here if you want to support the /dev/mem device.
    The /dev/mem device is used to access areas of physical
    memory.
    When in doubt, say "Y".
```

`config`后面的参数命名了一个变量，在这种情况下是`DEVMEM`。由于这个选项是一个布尔值，它只能有两个值：如果启用了，它被赋值为`y`，如果没有，这个变量根本就没有定义。在屏幕上显示的菜单项的名称是在`bool`关键字后面的字符串。

这个配置项，以及所有其他配置项，都存储在一个名为`.config`的文件中（注意，前导点'`.`'表示它是一个隐藏文件，不会被`ls`命令显示，除非你输入`ls -a`来显示所有文件）。存储在`.config`中的变量名都以`CONFIG_`为前缀，所以如果`DEVMEM`被启用，那么这一行就是：

```
CONFIG_DEVMEM=y
```

除了`bool`之外，还有几种其他数据类型。以下是列表：

+   `bool`: 这要么是`y`，要么未定义。

+   `tristate`: 这用于一个功能可以作为内核模块构建，也可以构建到主内核映像中。值为`m`表示模块，`y`表示构建，如果未启用该功能，则未定义。

+   `int`: 这是使用十进制表示的整数值。

+   `hex`: 这是使用十六进制表示的无符号整数值。

+   `string`: 这是一个字符串值。

项目之间可能存在依赖关系，通过`depends on`短语表示，如下所示：

```
config MTD_CMDLINE_PARTS
  tristate "Command line partition table parsing"
  depends on MTD
```

如果`CONFIG_MTD`在其他地方没有被启用，这个菜单选项就不会显示，因此也无法选择。

还有反向依赖关系：`select`关键字如果启用了其他选项，则启用了这个选项。`arch/$ARCH`中的`Kconfig`文件有大量的`select`语句，启用了特定于架构的功能，如 arm 中所示：

```
config ARM
  bool
default y
  select ARCH_HAS_ATOMIC64_DEC_IF_POSITIVE
  select ARCH_HAS_ELF_RANDOMIZE
[...]
```

有几个配置实用程序可以读取`Kconfig`文件并生成一个`.config`文件。其中一些在屏幕上显示菜单，并允许你进行交互式选择。`Menuconfig`可能是大多数人熟悉的一个，但还有`xconfig`和`gconfig`。

你可以通过`make`启动每一个，记住，在内核的情况下，你必须提供一个架构，就像这里所示的那样：

```
$ make ARCH=arm menuconfig

```

在这里，你可以看到在前一段中突出显示了`DEVMEM` `config`选项的`menuconfig`：

![理解内核配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_04_02.jpg)

使用 menuconfig 进行内核配置

星号(`*`)在项目的左侧表示它被选中(`="y"`)，或者如果是`M`，表示它已被选中以构建为内核模块。

### 提示

通常你会看到像`enable CONFIG_BLK_DEV_INITRD,`这样的指令，但是要浏览这么多菜单，找到设置这个配置的地方可能需要一段时间。所有的配置编辑器都有一个`search`功能。你可以在`menuconfig`中按下斜杠键`/`来访问它。在 xconfig 中，它在编辑菜单中，但是在这种情况下，确保你省略了你要搜索的变量的`CONFIG_`部分。

有这么多东西要配置，每次构建内核时都从零开始是不合理的，所以在`arch/$ARCH/configs`中有一组已知的工作配置文件，每个文件包含了单个 SoC 或一组 SoC 的合适配置值。你可以用`make [配置文件名]`来选择其中一个。例如，要配置 Linux 在使用 armv7-a 架构的各种 SoC 上运行，其中包括 BeagleBone Black AM335x，你可以输入：

```
$ make ARCH=arm multi_v7_defconfig

```

这是一个通用的内核，可以在不同的板上运行。对于更专业的应用，例如使用供应商提供的内核时，默认的配置文件是板支持包的一部分；在构建内核之前，你需要找出要使用哪一个。

还有另一个有用的配置目标名为`oldconfig`。这需要一个现有的`.config`文件，并要求您为任何没有配置值的选项提供配置值。当将配置移动到更新的内核版本时，您将使用它：将`.config`从旧内核复制到新的源目录，并运行`make ARCH=arm oldconfig`来使其保持最新。它还可以用于验证您手动编辑的`.config`文件（忽略顶部出现的文本`自动生成的文件；请勿编辑`：有时可以忽略警告）。

如果您对配置进行更改，修改后的`.config`文件将成为设备的一部分，并需要放置在源代码控制下。

当您启动内核构建时，将生成一个头文件`include/generated/autoconf.h`，其中包含每个配置值的`#define`，以便它可以像 U-Boot 一样包含在内核源中。

## 使用 LOCALVERSION 标识您的内核

您可以使用`make kernelversion`目标来查找您构建的内核版本：

```
$ make kernelversion
4.1.10

```

这在运行时通过`uname`命令报告，并且还用于命名存储内核模块的目录。

如果您从默认配置更改，建议附加您自己的版本信息，您可以通过设置`CONFIG_LOCALVERSION`来配置，您将在**常规设置配置**菜单中找到它。也可以（但不建议）通过编辑顶层 makefile 并将其附加到以`EXTRAVERSION`开头的行来执行相同的操作。例如，如果我想要使用标识符`melp`和版本 1.0 标记我正在构建的内核，我会在`.config`文件中定义本地版本如下：

```
CONFIG_LOCALVERSION="-melp-v1.0"

```

运行`make kernelversion`会产生与以前相同的输出，但现在，如果我运行`make kernelrelease`，我会看到：

```
$ make kernelrelease
4.1.10-melp-v1.0

```

它还会在内核日志的开头打印：

```
Starting kernel ...
[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Linux version 4.1.10-melp-v1.0 (chris@builder) (gcc version 4.9.1 (crosstool-NG 1.20.0) ) #3 SMP Thu Oct 15 21:29:35 BST 2015

```

现在我可以识别和跟踪我的自定义内核。

## 内核模块

我已经多次提到内核模块。桌面 Linux 发行版广泛使用它们，以便根据检测到的硬件和所需的功能在运行时加载正确的设备和内核功能。没有它们，每个驱动程序和功能都必须静态链接到内核中，使其变得不可行大。

另一方面，对于嵌入式设备来说，硬件和内核配置通常在构建内核时就已知，因此模块并不那么有用。实际上，它们会造成问题，因为它们在内核和根文件系统之间创建了版本依赖关系，如果一个更新了而另一个没有更新，可能会导致启动失败。因此，嵌入式内核通常会构建为完全没有任何模块。以下是一些适合使用内核模块的情况：

+   当您有专有模块时，出于前一节中给出的许可原因。

+   通过推迟加载非必要驱动程序来减少启动时间。

+   当有多个驱动程序可以加载并且将占用太多内存以静态编译它们时。例如，您有一个 USB 接口来支持一系列设备。这与桌面发行版中使用的论点基本相同。

# 编译

内核构建系统`kbuild`是一组`make`脚本，它从`.config`文件中获取配置信息，计算出依赖关系，并编译所有必要的内容，以生成包含所有静态链接组件的内核映像，可能还包括设备树二进制文件和一个或多个内核模块。这些依赖关系在每个可构建组件的目录中的 makefile 中表示。例如，以下两行摘自`drivers/char/Makefile`：

```
obj-y                    += mem.o random.o
obj-$(CONFIG_TTY_PRINTK) += ttyprintk.o
```

`obj-y`规则无条件地编译文件以生成目标，因此`mem.c`和`random.c`始终是内核的一部分。在第二行中，`ttyprintk.c`取决于配置参数。如果`CONFIG_TTY_PRINTK`是`y`，它将被编译为内置模块，如果是`m`，它将作为模块构建，如果参数未定义，则根本不会被编译。

对于大多数目标，只需键入`make`（带有适当的`ARCH`和`CROSS_COMPILE`）即可完成工作，但逐步进行也是有益的。

## 编译内核映像

要构建内核映像，您需要知道您的引导加载程序期望什么。这是一个粗略的指南：

+   **U-Boot**：传统上，U-Boot 需要一个 uImage，但较新版本可以使用`bootz`命令加载`zImage`文件

+   x86 目标：它需要一个`bzImage`文件

+   **大多数其他引导加载程序**：它需要一个`zImage`文件

以下是构建`zImage`文件的示例：

```
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- zImage

```

### 提示

`-j 4`选项告诉`make`并行运行多少个作业，从而减少构建所需的时间。一个粗略的指南是运行与 CPU 核心数量相同的作业。

构建`bzImage`和`uImage`目标时也是一样的。

构建具有多平台支持的 ARM 的`uImage`文件存在一个小问题，这是当前一代 ARM SoC 内核的常态。 ARM 的多平台支持是在 Linux 3.7 中引入的。它允许单个内核二进制文件在多个平台上运行，并且是朝着为所有 ARM 设备拥有少量内核的道路上的一步。内核通过读取引导加载程序传递给它的机器号或设备树来选择正确的平台。问题出在因为每个平台的物理内存位置可能不同，因此内核的重定位地址（通常是从物理 RAM 的起始位置偏移 0x8000 字节）也可能不同。当内核构建时，重定位地址由`mkimage`命令编码到`uImage`头中，但如果有多个重定位地址可供选择，则会失败。换句话说，`uImage`格式与多平台映像不兼容。您仍然可以从多平台构建创建一个 uImage 二进制文件，只要您为希望在其上引导此内核的特定 SoC 提供`LOADADDR`。您可以通过查看`mach-[your SoC]/Makefile.boot`并注意`zreladdr-y`的值来找到加载地址。

对于 BeagleBone Black，完整的命令如下：

```
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- LOADADDR=0x80008000 uImage

```

内核构建在顶层目录中生成两个文件：`vmlinux`和`System.map`。第一个`vmlinux`是内核的 ELF 二进制文件。如果您已启用调试编译内核（`CONFIG_DEBUG_INFO=y`），它将包含可用于像`kgdb`这样的调试器的调试符号。您还可以使用其他 ELF 二进制工具，如`size`：

```
$ arm-cortex_a8-linux-gnueabihf-size vmlinux
 text     data      bss        dec       hex    filename
8812564   790692   8423536   18026792   1131128   vmlinux

```

`System.map`以人类可读的形式包含符号表。

大多数引导加载程序不能直接处理 ELF 代码。还有一个进一步的处理阶段，它将`vmlinux`放置在`arch/$ARCH/boot`中，这些二进制文件适用于各种引导加载程序：

+   `Image`：将`vmlinux`转换为原始二进制文件。

+   `zImage`：对于 PowerPC 架构，这只是`Image`的压缩版本，这意味着引导加载程序必须进行解压缩。对于所有其他架构，压缩的`Image`被附加到一个解压缩和重定位它的代码存根上。

+   `uImage`：`zImage`加上 64 字节的 U-Boot 头。

在构建过程中，您将看到正在执行的命令的摘要：

```
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf-zImage
CC     init/main.o
CHK    include/generated/compile.h
CC     init/version.o
CC     init/do_mounts.o
CC     init/do_mounts_rd.o
CC     init/do_mounts_initrd.o
LD     init/mounts.o
[...]
```

有时，当内核构建失败时，查看实际执行的命令很有用。要做到这一点，请在命令行中添加`V=1`：

```
$ make ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- V=1 zImage
[...]
arm-cortex_a8-linux-gnueabihf-gcc -Wp,-MD,init/.do_mounts_initrd.o.d  -nostdinc -isystem /home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/lib/gcc/arm-cortex_a8-linux-gnueabihf/4.9.1/include -I./arch/arm/include -Iarch/arm/include/generated/uapi -Iarch/arm/include/generated  -Iinclude -I./arch/arm/include/uapi -Iarch/arm/include/generated/uapi -I./include/uapi -Iinclude/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -mlittle-endian -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -std=gnu89 -fno-dwarf2-cfi-asm -mabi=aapcs-linux -mno-thumb-interwork -mfpu=vfp -funwind-tables -marm -D__LINUX_ARM_ARCH__=7 -march=armv7-a -msoft-float -Uarm -fno-delete-null-pointer-checks -O2 --param=allow-store-data-races=0 -Wframe-larger-than=1024 -fno-stack-protector -Wno-unused-but-set-variable -fomit-frame-pointer -fno-var-tracking-assignments -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -Werror=implicit-int -Werror=strict-prototypes -Werror=date-time -DCC_HAVE_ASM_GOTO    -D"KBUILD_STR(s)=#s" -D"KBUILD_BASENAME=KBUILD_STR(do_mounts_initrd)"  -D"KBUILD_MODNAME=KBUILD_STR(mounts)" -c -o init/do_mounts_initrd.o init/do_mounts_initrd.c
[...]
```

## 编译设备树

下一步是构建设备树，或者如果您有多平台构建，则构建多个设备树。dtbs 目标根据`arch/$ARCH/boot/dts/Makefile`中的规则使用该目录中的设备树源文件构建设备树：

```
$ make ARCH=arm dtbs
...
DTC     arch/arm/boot/dts/omap2420-h4.dtb
DTC     arch/arm/boot/dts/omap2420-n800.dtb
DTC     arch/arm/boot/dts/omap2420-n810.dtb
DTC     arch/arm/boot/dts/omap2420-n810-wimax.dtb
DTC     arch/arm/boot/dts/omap2430-sdp.dtb
...

```

`.dtb`文件生成在与源文件相同的目录中。

## 编译模块

如果您已经配置了一些功能作为模块构建，可以使用`modules`目标单独构建它们：

```
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- modules

```

编译的模块具有`.ko`后缀，并且生成在与源代码相同的目录中，这意味着它们散布在整个内核源代码树中。找到它们有点棘手，但您可以使用`modules_install` make 目标将它们安装到正确的位置。默认位置是开发系统中的`/lib/modules`，这几乎肯定不是您想要的位置。要将它们安装到根文件系统的暂存区域（我们将在下一章讨论根文件系统），请使用`INSTALL_MOD_PATH`提供路径：

```
$ make -j4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf- INSTALL_MOD_PATH=$HOME/rootfs modules_install

```

内核模块被放置在相对于文件系统根目录的目录`/lib/modules/[kernel version]`中。

# 清理内核源代码

有三个用于清理内核源代码树的 make 目标：

+   清理：删除对象文件和大部分中间文件。

+   `mrproper`：删除所有中间文件，包括`.config`文件。使用此目标将源树恢复到克隆或提取源代码后的状态。如果您对名称感到好奇，Mr Proper 是一种在世界某些地区常见的清洁产品。`make mrproper`的含义是给内核源代码进行彻底的清洁。

+   `distclean`：这与 mrproper 相同，但还会删除编辑器备份文件、补丁剩余文件和软件开发的其他工件。

# 引导您的内核

引导高度依赖于设备，但以下是在 BeagleBone Black 和 QEMU 上使用 U-Boot 的一个示例：。

## BeagleBone Black

以下 U-Boot 命令显示了如何在 BeagleBone Black 上启动 Linux：

```
U-Boot# fatload mmc 0:1 0x80200000 zImage
reading zImage
4606360 bytes read in 254 ms (17.3 MiB/s)
U-Boot# fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
reading am335x-boneblack.dtb
29478 bytes read in 9 ms (3.1 MiB/s)
U-Boot# setenv bootargs console=ttyO0,115200
U-Boot# bootz 0x80200000 - 0x80f00000
Kernel image @ 0x80200000 [ 0x000000 - 0x464998 ]
## Flattened Device Tree blob at 80f00000
   Booting using the fdt blob at 0x80f00000
   Loading Device Tree to 8fff5000, end 8ffff325 ... OK
Starting kernel ...
[   0.000000] Booting Linux on physical CPU 0x0
...
```

请注意，我们将内核命令行设置为`console=ttyO0,115200`。这告诉 Linux 要使用哪个设备进行控制台输出，在本例中是板上的第一个 UART 设备`ttyO0`，速度为每秒 115,200 位。如果没有这个设置，我们将在`Starting the kernel ...`后看不到任何消息，因此将不知道它是否工作。

## QEMU

假设您已经安装了`qemu-system-arm`，您可以使用 multi_v7 内核和 ARM Versatile Express 的`.dtb`文件启动它，如下所示：

```
$ QEMU_AUDIO_DRV=none \
qemu-system-arm -m 256M -nographic -M vexpress-a9 -kernel zImage -dtb vexpress-v2p-ca9.dtb -append "console=ttyAMA0"

```

请注意，将`QEMU_AUDIO_DRV`设置为`none`只是为了抑制关于音频驱动程序缺少配置的 QEMU 的错误消息，我们不使用音频驱动程序。

要退出 QEMU，请键入`Ctrl-A`，然后键入`x`（两个单独的按键）。

## 内核恐慌

虽然一切开始得很顺利，但最终却以失败告终：

```
[    1.886379] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    1.895105] ---[ end Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0, 0)
```

这是内核恐慌的一个很好的例子。当内核遇到不可恢复的错误时，就会发生恐慌。默认情况下，它会在控制台上打印一条消息，然后停止。您可以设置`panic`命令行参数，以允许在恐慌后重新启动之前等待几秒钟。

在这种情况下，不可恢复的错误是因为没有根文件系统，说明内核没有用户空间来控制它是无用的。您可以通过提供根文件系统作为 ramdisk 或可挂载的大容量存储设备来提供用户空间。我们将在下一章讨论如何创建根文件系统，但是为了让事情正常运行，假设我们有一个名为`uRamdisk`的 ramdisk 文件，然后您可以通过在 U-Boot 中输入以下命令来引导到 shell 提示符：

```
fatload mmc 0:1 0x80200000 zImage
fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
fatload mmc 0:1 0x81000000 uRamdisk
setenv bootargs console=ttyO0,115200 rdinit=/bin/sh
bootz 0x80200000 0x81000000 0x80f00000

```

在这里，我已经在命令行中添加了`rdinit=/bin/sh`，这样内核将运行一个 shell 并给我们一个 shell 提示符。现在，控制台上的输出看起来像这样：

```
...
[    1.930923] sr_init: No PMIC hook to init smartreflex
[    1.936424] sr_init: platform driver register failed for SR
[    1.964858] Freeing unused kernel memory: 408K (c0824000 - c088a000)
/ # uname -a
Linux (none) 3.18.3 #1 SMP Wed Jan 21 08:34:58 GMT 2015 armv7l GNU/Linux
/ #

```

最后，我们有了一个提示符，可以与我们的设备交互。

## 早期用户空间

为了从内核初始化到用户空间的过渡，内核必须挂载一个根文件系统并在该根文件系统中执行一个程序。这可以通过 ramdisk 来实现，就像前一节中所示的那样，也可以通过在块设备上挂载一个真实的文件系统来实现。所有这些代码都在`init/main.c`中，从`rest_init()`函数开始，该函数创建了 PID 为 1 的第一个线程，并运行`kernel_init()`中的代码。如果有一个 ramdisk，它将尝试执行`program /init`，这将承担设置用户空间的任务。

如果找不到并运行`/init`，它将尝试通过在`init/do_mounts.c`中调用`prepare_namespace()`函数来挂载文件系统。这需要一个`root=`命令行来指定用于挂载的块设备的名称，通常的形式是：

+   `root=/dev/<disk name><partition number>`

+   `root=/dev/<disk name>p<partition number>`

例如，对于 SD 卡上的第一个分区，应该是`root=/dev/mmcblk0p1`。如果挂载成功，它将尝试执行`/sbin/init`，然后是`/etc/init`，`/bin/init`，然后是`/bin/sh`，在第一个有效的停止。

`init`程序可以在命令行上被覆盖。对于 ramdisk，使用`rdinit=`（我之前使用`rdinit=/bin/sh`来执行 shell），对于文件系统，使用`init=`。

## 内核消息

内核开发人员喜欢通过大量使用`printk()`和类似的函数来打印有用的信息。消息根据重要性进行分类，0 是最高级别：

| Level | Value | 含义 |
| --- | --- | --- |
| `KERN_EMERG` | 0 | 系统无法使用 |
| `KERN_ALERT` | 1 | 必须立即采取行动 |
| `KERN_CRIT` | 2 | 临界条件 |
| `KERN_ERR` | 3 | 错误条件 |
| `KERN_WARNING` | 4 | 警告条件 |
| `KERN_NOTICE` | 5 | 正常但重要的条件 |
| `KERN_INFO` | 6 | 信息 |
| `KERN_DEBUG` | 7 | 调试级别的消息 |

它们首先被写入一个缓冲区`__log_buf`，其大小为`CONFIG_LOG_BUF_SHIFT`的 2 次幂。例如，如果是 16，那么`__log_buf`就是 64 KiB。您可以使用命令`dmesg`来转储整个缓冲区。

如果消息的级别低于控制台日志级别，则会在控制台上显示该消息，并放置在`__log_buf`中。默认控制台日志级别为 7，这意味着级别为 6 及以下的消息会被显示，过滤掉级别为 7 的`KERN_DEBUG`。您可以通过多种方式更改控制台日志级别，包括使用内核参数`loglevel=<level>`或命令`dmesg -n <level>`。

## 内核命令行

内核命令行是一个字符串，由引导加载程序通过`bootargs`变量传递给内核，在 U-Boot 的情况下；它也可以在设备树中定义，或作为内核配置的一部分在`CONFIG_CMDLINE`中设置。

我们已经看到了一些内核命令行的示例，但还有许多其他的。在`Documentation/kernel-parameters.txt`中有一个完整的列表。这里是一个更小的最有用的列表：

| 名称 | 描述 |
| --- | --- |
| `debug` | 将控制台日志级别设置为最高级别 8，以确保您在控制台上看到所有内核消息。 |
| `init=` | 从挂载的根文件系统中运行的`init`程序，默认为`/sbin/init`。 |
| `lpj=` | 将`loops_per_jiffy`设置为给定的常数，参见下一段。 |
| `panic=` | 内核发生 panic 时的行为：如果大于零，则在重新启动之前等待的秒数；如果为零，则永远等待（这是默认值）；如果小于零，则立即重新启动。 |
| `quiet` | 将控制台日志级别设置为 1，抑制除紧急消息之外的所有消息。由于大多数设备都有串行控制台，输出所有这些字符串需要时间。因此，使用此选项减少消息数量可以减少启动时间。 |
| `rdinit=` | 从 ramdisk 运行的`init`程序，默认为`/init`。 |
| `ro` | 将根设备挂载为只读。对于始终是读/写的 ramdisk 没有影响。 |
| `root=` | 要挂载根文件系统的设备。 |
| `rootdelay=` | 在尝试挂载根设备之前等待的秒数，默认为零。如果设备需要时间来探测硬件，则此参数很有用，但也请参阅`rootwait`。 |
| `rootfstype=` | 根设备的文件系统类型。在许多情况下，在挂载期间会自动检测到，但对于`jffs2`文件系统是必需的。 |
| `rootwait` | 无限期等待根设备被检测到。通常在使用`mmc`设备时是必需的。 |
| `rw` | 将根设备挂载为读/写（默认）。 |

`lpj`参数经常在减少内核启动时间方面提到。在初始化期间，内核循环大约 250 毫秒来校准延迟循环。该值存储在变量`loops_per_jiffy`中，并且报告如下：

```
Calibrating delay loop... 996.14 BogoMIPS (lpj=4980736)

```

如果内核始终在相同的硬件上运行，它将始终计算相同的值。通过在命令行中添加`lpj=4980736`，可以缩短 250 毫秒的启动时间。

# 将 Linux 移植到新板子

任务的范围取决于您的板子与现有开发板有多相似。在第三章中，*关于引导加载程序*，我们将 U-Boot 移植到了一个名为 Nova 的新板子上，该板子基于 BeagleBone Black（实际上就是基于它），因此在这种情况下，需要对内核代码进行的更改很少。如果要移植到全新和创新的硬件上，则需要做更多工作。我只会考虑简单的情况。

`arch/$ARCH`中的特定于体系结构的代码组织因系统而异。x86 体系结构非常干净，因为硬件细节在运行时被检测到。PowerPC 体系结构将 SoC 和特定于板子的文件放在子目录平台中。ARM 体系结构具有所有 ARM 板子和 SoC 中最多的特定于板子和 SoC 的文件。特定于平台的代码位于`arch/arm`中名为`mach-*`的目录中，大约每个 SoC 一个。还有其他名为`plat-*`的目录，其中包含适用于某个 SoC 的几个版本的通用代码。在 Nova 板的情况下，相关目录是`mach-omap2`。不过，不要被名称所迷惑，它包含对 OMAP2、3 和 4 芯片的支持。

在接下来的章节中，我将以两种不同的方式对 Nova 板进行移植。首先，我将向您展示如何使用设备树进行移植，然后再进行移植，因为现场有很多符合此类别的设备。您会发现，当您有设备树时，这将更加简单。

## 有设备树

首先要做的是为板子创建一个设备树，并修改它以描述板子上的附加或更改的硬件。在这种简单情况下，我们将只是将`am335x-boneblack.dts`复制到`nova.dts`，并更改板子名称：

```
/dts-v1/;
#include "am33xx.dtsi"
#include "am335x-bone-common.dtsi"
/ {
     model = "Nova";
     compatible = "ti,am335x-bone-black", "ti,am335x-bone", "ti,am33xx";
  };
...
```

我们可以显式构建`nova.dtb`：

```
$ make  ARCH=arm nova.dtb

```

或者，如果我们希望`nova.dtb`在 OMAP2 平台上默认生成，可以使用`make ARCH=arm dtbs`，然后我们可以将以下行添加到`arch/arm/boot/dts/Makefile`中：

```
dtb-$(CONFIG_SOC_AM33XX) += \
[...]
nova.dtb \
[...]
```

现在我们可以像以前一样启动相同的`zImage`文件，使用`multi_v7_defconfig`进行配置，但是加载`nova.dtb`，如下所示：

```
Starting kernel ...

[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Initializing cgroup subsys cpuset
[    0.000000] Initializing cgroup subsys cpu
[    0.000000] Initializing cgroup subsys cpuacct
[    0.000000] Linux version 3.18.3-dirty (chris@builder) (gcc version 4.9.1 (crosstool-N
G 1.20.0) ) #1 SMP Wed Jan 28 07:50:50 GMT 2015
[    0.000000] CPU: ARMv7 Processor [413fc082] revision 2 (ARMv7), cr=10c5387d
[    0.000000] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000] Machine model: Nova
...
```

我们可以通过复制`multi_v7_defconfig`来创建自定义配置，并添加我们需要的功能，并通过留出不需要的功能来减小代码大小。

## 没有设备树

首先，我们需要为板子创建一个配置名称，本例中为`NOVABOARD`。我们需要将其添加到您的 SoC 的`mach-`目录的`Kconfig`文件中，并且需要为 SoC 支持本身添加一个依赖项，即`OMAPAM33XX`。

这些行添加到`arch/arm/mach-omap2/Kconfig`中：

```
config MACH_NOVA BOARD
bool "Nova board"
depends on SOC_OMAPAM33XX
default n
```

对于每个板卡都有一个名为`board-*.c`的源文件，其中包含特定于目标的代码和配置。在我们的情况下，它是基于`board-am335xevm.c`的`board-nova.c`。必须有一个规则来编译它，条件是`CONFIG_MACH_NOVABOARD`，这个添加到`arch/arm/mach-omap2/Makefile`中的内容会处理：

```
obj-$(CONFIG_MACH_NOVABOARD) += board-nova.o
```

由于我们不使用设备树来识别板卡，我们将不得不使用较旧的机器编号机制。这是由引导加载程序传递给寄存器 r1 的每个板卡的唯一编号，ARM 启动代码将使用它来选择正确的板卡支持。ARM 机器编号的权威列表保存在：[www.arm.linux.org.uk/developer/machines/download.php](http://www.arm.linux.org.uk/developer/machines/download.php)。您可以从[www.arm.linux.org.uk/developer/machines/?action=new#](http://www.arm.linux.org.uk/developer/machines/?action=new#)请求一个新的机器编号。

如果我们劫持机器编号`4242`，我们可以将其添加到`arch/arm/tools/mach-types`中，如下所示：

```
machine_is_xxx   CONFIG_xxxx        MACH_TYPE_xxx      number
...
nova_board       MACH_NOVABOARD     NOVABOARD          4242
```

当我们构建内核时，它将用于创建`include/generated/`中存在的`mach-types.h`头文件。

机器编号和板卡支持是通过一个结构绑定在一起的，该结构定义如下：

```
MACHINE_START(NOVABOARD, "nova_board")
/* Maintainer: Chris Simmonds */
.atag_offset    = 0x100,
.map_io         = am335x_evm_map_io,
.init_early     = am33xx_init_early,
.init_irq       = ti81xx_init_irq,
.handle_irq     = omap3_intc_handle_irq,
.timer          = &omap3_am33xx_timer,
.init_machine   = am335x_evm_init,
MACHINE_END
```

请注意，一个板卡文件中可能有多个机器结构，允许我们创建一个可以在多个不同板卡上运行的内核。引导加载程序传递的机器编号将选择正确的机器结构。

最后，我们需要为我们的板卡选择一个新的默认配置，该配置选择`CONFIG_MACH_NOVABOARD`和其他特定于它的配置选项。在下面的示例中，它将位于`arch/arm/configs/novaboard_defconfig`。现在您可以像往常一样构建内核映像：

```
$ make ARCH=arm novaboard_defconfig
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabi- zImage

```

工作完成之前还有一步。引导加载程序需要修改以传递正确的机器编号。假设您正在使用 U-Boot，您需要将 Linux 生成的机器编号复制到 U-Boot 文件`arch/arm/include/asm/mach-types.h`中。然后，您需要更新 Nova 的配置头文件`include/configs/nova.h`，并添加以下行：

```
#define CONFIG_MACH_TYPE          MACH_TYPE_NOVABOARD
```

现在，最后，您可以构建 U-Boot 并使用它来引导 Nova 板上的新内核：

```
Starting kernel ...

[    0.000000] Linux version 3.2.0-00246-g0c74d7a-dirty (chris@builder) (gcc version 4.9.
1 (crosstool-NG 1.20.0) ) #3 Wed Jan 28 11:45:10 GMT 2015
[    0.000000] CPU: ARMv7 Processor [413fc082] revision 2 (ARMv7), cr=10c53c7d
[    0.000000] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000] Machine: nova_board
```

# 额外阅读

以下资源提供了有关本章介绍的主题的更多信息：

+   *Linux 内核新手*，[kernelnewbies.org](http://kernelnewbies.org)

+   *Linux 每周新闻*，[www.lwn.net](http://www.lwn.net)

# 总结

Linux 是一个非常强大和复杂的操作系统内核，可以与各种类型的用户空间结合，从简单的嵌入式设备到使用 Android 的日益复杂的移动设备，再到完整的服务器操作系统。其优势之一是可配置性。获取源代码的权威位置是[www.kerenl.org](http://www.kerenl.org)，但您可能需要从该设备的供应商或支持该设备的第三方获取特定 SoC 或板卡的源代码。为特定目标定制内核可能包括对核心内核代码的更改，为不在主线 Linux 中的设备添加额外的驱动程序，一个默认的内核配置文件和一个设备树源文件。

通常情况下，您会从目标板的默认配置开始，然后通过运行诸如`menuconfig`之类的配置工具进行调整。在这一点上，您应该考虑的一件事是内核功能和驱动程序是否应该编译为模块或内置。内核模块通常对嵌入式系统没有太大优势，因为功能集和硬件通常是明确定义的。然而，模块通常被用作将专有代码导入内核的一种方式，还可以通过在引导后加载非必要驱动程序来减少启动时间。构建内核会生成一个压缩的内核映像文件，根据您将要使用的引导加载程序和目标架构的不同，它的名称可能是`zImage`、`bzImage`或`uImage`。内核构建还会生成您配置的任何内核模块（作为`.ko`文件），以及设备树二进制文件（作为`.dtb`文件），如果您的目标需要的话。

将 Linux 移植到新的目标板可能非常简单，也可能非常困难，这取决于硬件与主线或供应商提供的内核有多大不同。如果您的硬件是基于一个众所周知的参考设计，那么可能只需要对设备树或平台数据进行更改。您可能需要添加设备驱动程序，这在第八章中有讨论，*介绍设备驱动程序*。然而，如果硬件与参考设计有根本的不同，您可能需要额外的核心支持，这超出了本书的范围。

内核是基于 Linux 的系统的核心，但它不能单独工作。它需要一个包含用户空间的根文件系统。根文件系统可以是一个 ramdisk 或通过块设备访问的文件系统，这将是下一章的主题。正如我们所看到的，没有根文件系统启动内核会导致内核恐慌。


# 第五章：构建根文件系统

根文件系统是嵌入式 Linux 的第四个也是最后一个元素。阅读完本章后，您将能够构建、引导和运行一个简单的嵌入式 Linux 系统。

本章探讨了通过从头开始构建根文件系统来探索根文件系统背后的基本概念。主要目的是提供您理解和充分利用 Buildroot 和 Yocto Project 等构建系统所需的背景信息，我将在第六章*选择构建系统*中进行介绍。

我将在这里描述的技术通常被称为**自定义**或**RYO**。在嵌入式 Linux 的早期，这是创建根文件系统的唯一方法。仍然有一些用例适用于 RYO 根文件系统，例如当 RAM 或存储量非常有限时，用于快速演示，或者用于任何标准构建系统工具（容易）无法满足您的要求的情况。然而，这些情况非常罕见。让我强调一下，本章的目的是教育性的，而不是为了构建日常嵌入式系统的配方：请使用下一章中描述的工具。

第一个目标是创建一个最小的根文件系统，以便给我们一个 shell 提示符。然后，以此为基础，我们将添加脚本来启动其他程序，并配置网络接口和用户权限。了解如何从头开始构建根文件系统是一项有用的技能，它将帮助您理解我们在后面章节中看到的更复杂的示例时发生了什么。

# 根文件系统中应该包含什么？

内核将获得一个根文件系统，可以是 ramdisk，从引导加载程序传递的指针，或者通过`root=`参数在内核命令行上挂载的块设备。一旦有了根文件系统，内核将执行第一个程序，默认情况下命名为`init`，如第四章*移植和配置内核*中的*早期用户空间*部分所述。然后，就内核而言，它的工作就完成了。由`init`程序开始处理脚本，启动其他程序等，调用 C 库中的系统函数，这些函数转换为内核系统调用。

要创建一个有用的系统，您至少需要以下组件：

+   **init**:通常通过运行一系列脚本来启动一切的程序。

+   **shell**:需要为您提供命令提示符，但更重要的是运行`init`和其他程序调用的 shell 脚本。

+   **守护进程**:由`init`启动的各种服务器程序。

+   **库**:通常，到目前为止提到的程序都链接到必须存在于根文件系统中的共享库。

+   **配置文件**: `init`和其他守护程序的配置存储在一系列 ASCII 文本文件中，通常位于`/etc`目录中。

+   **设备节点**:特殊文件，提供对各种设备驱动程序的访问。

+   **/proc 和/sys**:代表内核数据结构的两个伪文件系统，以目录和文件的层次结构表示。许多程序和库函数读取这些文件。

+   **内核模块**:如果您已经配置了内核的某些部分为模块，它们通常会在`/lib/modules/[kernel version]`中。

此外，还有系统应用程序或应用程序，使设备能够完成其预期工作，并收集它们所收集的运行时最终用户数据。

另外，也有可能将上述所有内容压缩成一个单独的程序。您可以创建一个静态链接的程序，它会在`init`之外启动并且不运行其他程序。我只遇到过这样的配置一次。例如，如果您的程序命名为`/myprog`，您可以将以下命令放在内核命令行中：

```
init=/myprog

```

或者，如果根文件系统被加载为 ramdisk，你可以输入以下命令：

```
rdinit=/myprog

```

这种方法的缺点是你无法使用通常用于嵌入式系统的许多工具；你必须自己做一切。

## 目录布局

有趣的是，Linux 并不关心文件和目录的布局，只要存在由`init=`或`rdinit=`命名的程序，你可以自由地将东西放在任何你喜欢的地方。例如，比较运行安卓的设备的文件布局和桌面 Linux 发行版的文件布局：它们几乎完全不同。

然而，许多程序希望某些文件在特定位置，如果设备使用类似的布局，对开发人员有所帮助，除了安卓。Linux 系统的基本布局在**文件系统层次结构标准**（**FHS**）中定义，参见本章末尾的参考资料。FHS 涵盖了从最大到最小的所有 Linux 操作系统的实现。嵌入式设备根据需要有一个子集，但通常包括以下内容：

+   `/bin`：所有用户必需的程序

+   `/dev`：设备节点和其他特殊文件

+   `/etc`：系统配置

+   `/lib`：必需的共享库，例如组成 C 库的那些库

+   `/proc`：`proc`文件系统

+   `/sbin`：对系统管理员至关重要的程序

+   `/sys`：`sysfs`文件系统

+   `/tmp`：放置临时或易失性文件的地方

+   `/usr`：至少应包含目录`/usr/bin`、`/usr/lib`和`/usr/sbin`，其中包含额外的程序、库和系统管理员实用程序

+   `/var`：可能在运行时被修改的文件和目录的层次结构，例如日志消息，其中一些必须在引导后保留

这里有一些微妙的区别。`/bin`和`/sbin`之间的区别仅仅是`/sbin`不需要包含在非 root 用户的搜索路径中。使用 Red Hat 衍生的发行版的用户会熟悉这一点。`/usr`的重要性在于它可能在与根文件系统不同的分区中，因此它不能包含任何引导系统所需的内容。这就是前面描述中所说的“必需”的含义：它包含了在引导时需要的文件，因此必须是根文件系统的一部分。

### 提示

虽然似乎在四个目录中存储程序有些多余，但反驳的观点是这并没有什么坏处，甚至可能有些好处，因为它允许你将`/usr`存储在不同的文件系统中。

## 暂存目录

你应该首先在主机计算机上创建一个暂存目录，在那里你可以组装最终将传输到目标设备的文件。在下面的示例中，我使用了`~/rootfs`。你需要在其中创建一个骨架目录结构，例如：

```
$ mkdir ~/rootfs
$ cd ~/rootfs
$ mkdir bin dev etc home lib proc sbin sys tmp usr var
$ mkdir usr/bin usr/lib usr/sbin
$ mkdir var/log

```

为了更清晰地看到目录层次结构，你可以使用方便的`tree`命令，下面的示例中使用了`-d`选项只显示目录：

```
$ tree -d

├── bin
├── dev
├── etc
├── home
├── lib
├── proc
├── sbin
├── sys
├── tmp
├── usr
│   ├── bin
│   ├── lib
│   └── sbin
└── var
 └── log

```

### POSIX 文件访问权限

在这里讨论的上下文中，每个进程，也就是每个正在运行的程序，都属于一个用户和一个或多个组。用户由一个称为**用户 ID**或**UID**的 32 位数字表示。关于用户的信息，包括从 UID 到名称的映射，保存在`/etc/passwd`中。同样，组由**组 ID**或**GID**表示，信息保存在`/etc/group`中。始终存在一个 UID 为 0 的 root 用户和一个 GID 为 0 的 root 组。root 用户也被称为超级用户，因为在默认配置中，它可以绕过大多数权限检查，并且可以访问系统中的所有资源。基于 Linux 的系统中的安全性主要是关于限制对 root 账户的访问。

每个文件和目录也都有一个所有者，并且属于一个组。进程对文件或目录的访问级别由一组访问权限标志控制，称为文件的模式。有三组三个位：第一组适用于文件的所有者，第二组适用于与文件相同组的成员，最后一组适用于其他人，即世界其他地方的人。位用于文件的读取（r）、写入（w）和执行（x）权限。由于三个位恰好适合八进制数字，它们通常以八进制表示，如下图所示：

![POSIX 文件访问权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_05_01.jpg)

还有一组特殊含义的三个位：

+   **SUID (4)**：如果文件是可执行文件，则将进程的有效 UID 更改为文件的所有者的 UID。

+   **SGID (2)**：如果文件是可执行文件，则将进程的有效 GID 更改为文件的组的 GID。

+   **Sticky (1)**：在目录中，限制删除，以便一个用户不能删除属于另一个用户的文件。这通常设置在`/tmp`和`/var/tmp`上。

SUID 位可能是最常用的。它为非 root 用户提供了临时特权升级到超级用户以执行任务。一个很好的例子是`ping`程序：`ping`打开一个原始套接字，这是一个特权操作。为了让普通用户使用`ping`，通常由 root 拥有并设置了 SUID 位，这样当您运行`ping`时，它将以 UID 0 执行，而不管您的 UID 是多少。

要设置这些位，请使用八进制数字 4、2、1 和`chmod`命令。例如，要在您的暂存根目录中设置`/bin/ping`的 SUID，您可以使用以下命令：

```
$ cd ~/rootfs
$ ls -l bin/ping
-rwxr-xr-x 1 root root 35712 Feb  6 09:15 bin/ping
$ sudo chmod 4755 bin/ping
$ ls -l bin/ping
-rwsr-xr-x 1 root root 35712 Feb  6 09:15 bin/ping

```

### 注意

请注意最后一个文件列表中的`s`：这表明设置了 SUID。

### 暂存目录中的文件所有权权限

出于安全和稳定性原因，非常重要的是要注意将要放置在目标设备上的文件的所有权和权限。一般来说，您希望将敏感资源限制为只能由 root 访问，并尽可能多地使用非 root 用户运行程序，以便如果它们受到外部攻击，它们尽可能少地向攻击者提供系统资源。例如，设备节点`/dev/mem`提供对系统内存的访问，这在某些程序中是必要的。但是，如果它可以被所有人读取和写入，那么就没有安全性，因为每个人都可以访问一切。因此，`/dev/mem`应该由 root 拥有，属于 root 组，并且具有 600 的模式，这样除了所有者之外，其他人都无法读取和写入。

然而，暂存目录存在问题。您在那里创建的文件将归您所有，但是，当它们安装到设备上时，它们应该属于特定的所有者和组，主要是 root 用户。一个明显的修复方法是使用以下命令在此阶段更改所有权：

```
$ cd ~/rootfs
$ sudo chown -R root:root *

```

问题是您需要 root 权限来运行该命令，并且从那时起，您将需要 root 权限来修改暂存目录中的任何文件。在您知道之前，您将以 root 身份进行所有开发，这不是一个好主意。这是我们稍后将回头解决的问题。

# 根文件系统的程序

现在，是时候开始用必要的程序和支持库、配置和数据文件填充根文件系统了，首先概述您将需要的程序类型。

## init 程序

您在上一章中已经看到`init`是第一个要运行的程序，因此具有 PID 1。它以 root 用户身份运行，因此对系统资源具有最大访问权限。通常，它运行启动守护程序的 shell 脚本：守护程序是在后台运行且与终端没有连接的程序，在其他地方可能被称为服务器程序。

## Shell

我们需要一个 shell 来运行脚本，并给我们一个命令行提示符，以便我们可以与系统交互。在生产设备中可能不需要交互式 shell，但它对开发、调试和维护非常有用。嵌入式系统中常用的各种 shell 有：

+   `bash`：是我们从桌面 Linux 中熟悉和喜爱的大型工具。它是 Unix Bourne shell 的超集，具有许多扩展或*bashisms*。

+   `ash`：也基于 Bourne shell，并且在 Unix 的 BSD 变体中有着悠久的历史。Busybox 有一个 ash 的版本，已经扩展以使其与`bash`更兼容。它比`bash`小得多，因此是嵌入式系统的非常受欢迎的选择。

+   `hush`：是一个非常小的 shell，在引导加载程序章节中我们简要介绍过。它在内存非常少的设备上非常有用。BusyBox 中有一个版本。

### 提示

如果您在目标上使用`ash`或`hush`作为 shell，请确保在目标上测试您的 shell 脚本。很容易只在主机上测试它们，使用`bash`，然后当您将它们复制到目标时发现它们无法工作。

## 实用程序

shell 只是启动其他程序的一种方式，shell 脚本只不过是要运行的程序列表，带有一些流程控制和在程序之间传递信息的手段。要使 shell 有用，您需要基于 Unix 命令行的实用程序。即使对于基本的根文件系统，也有大约 50 个实用程序，这带来了两个问题。首先，追踪每个程序的源代码并进行交叉编译将是一项相当大的工作。其次，由此产生的程序集将占用数十兆字节的空间，在嵌入式 Linux 的早期阶段，几兆字节就是一个真正的问题。为了解决这个问题，BusyBox 诞生了。

## BusyBox 来拯救！

BusyBox 的起源与嵌入式 Linux 无关。该项目是由 Bruce Perens 于 1996 年发起的，用于 Debian 安装程序，以便他可以从 1.44 MB 软盘启动 Linux。巧合的是，当时的设备存储容量大约是这个大小，因此嵌入式 Linux 社区迅速接受了它。从那时起，BusyBox 一直是嵌入式 Linux 的核心。

BusyBox 是从头开始编写的，以执行这些基本 Linux 实用程序的基本功能。开发人员利用了 80:20 规则：程序最有用的 80%在代码的 20%中实现。因此，BusyBox 工具实现了桌面等效工具功能的子集，但它们足够在大多数情况下使用。

BusyBox 采用的另一个技巧是将所有工具合并到一个单一的二进制文件中，这样可以很容易地在它们之间共享代码。它的工作原理是这样的：BusyBox 是一组小工具，每个小工具都以`[applet]_main`的形式导出其主要函数。例如，`cat`命令是在`coreutils/cat.c`中实现的，并导出`cat_main`。BusyBox 本身的主函数根据命令行参数将调用分派到正确的小工具。

因此，要读取文件，您可以启动`busybox`，后面跟上您想要运行的小工具的名称，以及小工具期望的任何参数，如下所示：

```
$ busybox cat my_file.txt

```

您还可以运行`busybox`而不带任何参数，以获取已编译的所有小工具的列表。

以这种方式使用 BusyBox 相当笨拙。让 BusyBox 运行`cat`小工具的更好方法是创建一个从`/bin/cat`到`/bin/busybox`的符号链接。

```
$ ls -l bin/cat bin/busybox
-rwxr-xr-x 1 chris chris 892868 Feb  2 11:01 bin/busybox
lrwxrwxrwx 1 chris chris      7 Feb  2 11:01 bin/cat -> busybox

```

当您在命令行输入`cat`时，实际运行的程序是`busybox`。BusyBox 只需要检查传递给`argv[0]`的命令尾部，它将是`/bin/cat`，提取应用程序名称`cat`，并进行表查找以匹配`cat`与`cat_main`。所有这些都在`libbb/appletlib.c`中的这段代码中（稍微简化）：

```
applet_name = argv[0];
applet_name = bb_basename(applet_name);
run_applet_and_exit(applet_name, argv);
```

BusyBox 有 300 多个小程序，包括一个`init`程序，几个不同复杂级别的 shell，以及大多数管理任务的实用程序。甚至还有一个简化版的`vi`编辑器，这样你就可以在设备上更改文本文件。

总之，BusyBox 的典型安装包括一个程序和每个小程序的符号链接，但它的行为就像是一个独立应用程序的集合。

### 构建 BusyBox

BusyBox 使用与内核相同的`Kconfig`和`Kbuild`系统，因此交叉编译很简单。你可以通过克隆 git 存档并检出你想要的版本（写作时最新的是 1_24_1）来获取源代码，就像这样：

```
$ git clone git://busybox.net/busybox.git
$ cd busybox
$ git checkout 1_24_1

```

你也可以从[`busybox.net/downloads`](http://busybox.net/downloads)下载相应的`tarball`文件。然后，配置 BusyBox，从默认配置开始，这样可以启用几乎所有 BusyBox 的功能：

```
$ make distclean
$ make defconfig

```

在这一点上，你可能想要运行`make menuconfig`来微调配置。你几乎肯定想要在**Busybox Settings** | **Installation Options** (`CONFIG_PREFIX`)中设置安装路径，指向暂存目录。然后，你可以像通常一样进行交叉编译：

```
$ make -j 4 ARCH=arm CROSS_COMPILE=arm-cortex_a8-linux-gnueabihf-

```

结果是可执行文件`busybox`。对于 ARM v7a 的`defconfig`构建，它的大小约为 900 KiB。如果这对你来说太大了，你可以通过配置掉你不需要的实用程序来减小它。

要安装 BusyBox，请使用以下命令：

```
$ make install

```

这将把二进制文件复制到`CONFIG_PREFIX`配置的目录，并创建所有的符号链接。

## ToyBox - BusyBox 的替代品

BusyBox 并不是唯一的选择。例如，Android 有一个名为 Toolbox 的等效工具，但它更适合 Android 的需求，对于一般嵌入式环境没有用。一个更有用的选择是 ToyBox，这是一个由 Rob Landley 发起和维护的项目，他以前是 BusyBox 的维护者。ToyBox 的目标与 BusyBox 相同，但更注重遵守标准，特别是 POSIX-2008 和 LSB 4.1，而不是与 GNU 对这些标准的扩展的兼容性。ToyBox 比 BusyBox 小，部分原因是它实现的小程序更少。

然而，主要的区别是许可证，是 BSD 而不是 GPL v2，这使它与具有 BSD 许可的用户空间的操作系统兼容，比如 Android 本身。

# 根文件系统的库

程序与库链接。你可以将它们全部静态链接，这样目标设备上就不会有库了。但是，如果你有两三个以上的程序，这将占用不必要的大量存储空间。所以，你需要将共享库从工具链复制到暂存目录。你怎么知道哪些库？

一个选择是将它们全部复制，因为它们肯定有些用处，否则它们就不会存在！这当然是合乎逻辑的，如果你正在为他人用于各种应用程序的平台创建一个平台，那么这将是正确的方法。但要注意，一个完整的`glibc`相当大。在 CrossTool-NG 构建的`glibc` 2.19 的情况下，`/lib`和`/usr/lib`占用的空间为 33 MiB。当然，你可以通过使用 uClibc 或 Musel `libc`库大大减少这个空间。

另一个选择是只挑选你需要的那些库，为此你需要一种发现库依赖关系的方法。使用我们从第二章中的一些知识，*了解工具链*库，你可以使用`readelf`来完成这个任务：

```
$ cd ~/rootfs
$ arm-cortex_a8-linux-gnueabihf-readelf -a bin/busybox | grep "program interpreter"
 [Requesting program interpreter: /lib/ld-linux-armhf.so.3]
$ arm-cortex_a8-linux-gnueabihf-readelf -a bin/busybox | grep "Shared library"
0x00000001 (NEEDED)              Shared library: [libm.so.6]
0x00000001 (NEEDED)              Shared library: [libc.so.6]

```

现在你需要在工具链中找到这些文件，并将它们复制到暂存目录。记住你可以这样找到`sysroot`：

```
$ arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot
/home/chris/x-tools/arm-cortex_a8-linux-gnueabihf/arm-cortex_a8-linux-gnueabihf/sysroot

```

为了减少输入量，我将把它保存在一个 shell 变量中：

```
$ export SYSROOT=`arm-cortex_a8-linux-gnueabihf-gcc -print-sysroot`

```

如果你在`sysroot`中查看`/lib/ld-linux-armhf.so.3`，你会发现，它实际上是一个符号链接：

```
$ ls -l $SYSROOT/lib/ld-linux-armhf.so.3
[...]/sysroot/lib/ld-linux-armhf.so.3 -> ld-2.19.so

```

对`libc.so.6`和`libm.so.6`重复此操作，您将得到三个文件和三个符号链接的列表。使用`cp -a`进行复制，这将保留符号链接：

```
$ cd ~/rootfs
$ cp -a $SYSROOT/lib/ld-linux-armhf.so.3 lib
$ cp -a $SYSROOT/lib/ld-2.19.so lib
$ cp -a $SYSROOT/lib/libc.so.6 lib
$ cp -a $SYSROOT/lib/libc-2.19.so lib
$ cp -a $SYSROOT/lib/libm.so.6 lib
$ cp -a $SYSROOT/lib/libm-2.19.so lib

```

对每个程序重复此过程。

### 提示

这样做只有在获取最小的嵌入式占用空间时才值得。有可能会错过通过`dlopen(3)`调用加载的库，主要是插件。我们将在本章后面配置网络接口时，通过 NSS 库的示例来说明。

## 通过剥离来减小尺寸

通常情况下，库和程序都会编译时内置符号表信息，如果使用了调试开关`-g`，则更多。您很少需要这些信息。节省空间的一种快速简单的方法是剥离它们。此示例显示了剥离前后的`libc`：

```
$ file rootfs/lib/libc-2.19.so
rootfs/lib/libc-2.19.so: ELF 32-bit LSB shared object, ARM, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.15.4, not stripped
$ ls -og rootfs/lib/libc-2.19.so
-rwxrwxr-x 1 1547371 Feb  5 10:18 rootfs/lib/libc-2.19.so
$ arm-cortex_a8-linux-gnueabi-strip rootfs/lib/libc-2.19.so
$ file rootfs/lib/libc-2.19.so
rootfs/lib/libc-2.19.so: ELF 32-bit LSB shared object, ARM, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.15.4, stripped
$ ls -l rootfs/lib/libc-2.19.so
-rwxrwxr-x 1 chris chris 1226024 Feb  5 10:19 rootfs/lib/libc-2.19.so
$ ls -og rootfs/lib/libc-2.19.so
-rwxrwxr-x 1 1226024 Feb  5 10:19 rootfs/lib/libc-2.19.so

```

在这种情况下，我们节省了 321,347 字节，大约为 20%。

在剥离内核模块时，使用以下命令：

```
strip --strip-unneeded <module name>

```

否则，您将剥离重定位模块代码所需的符号，导致加载失败。

# 设备节点

Linux 中的大多数设备都由设备节点表示，符合 Unix 哲学的*一切皆文件*（除了网络接口，它们是套接字）。设备节点可能是块设备或字符设备。块设备是诸如 SD 卡或硬盘等大容量存储设备。字符设备基本上是其他任何东西，再次除了网络接口。设备节点的传统位置是目录`/dev`。例如，串行端口可以由设备节点`/dev/ttyS0`表示。

使用程序`mknod`（缩写为 make node）创建设备节点：

```
mknod <name> <type> <major> <minor>
```

`name`是您要创建的设备节点的名称，`type`可以是`c`表示字符设备，`b`表示块设备。它们各自有一个主要号和次要号，内核使用这些号码将文件请求路由到适当的设备驱动程序代码。内核源代码中有一个标准主要和次要号的列表，位于`Documentation/devices.txt`中。

您需要为系统上要访问的所有设备创建设备节点。您可以手动使用`mknod`命令来执行此操作，就像我在这里所示的那样，或者您可以使用稍后提到的设备管理器之一来在运行时自动创建它们。

使用 BusyBox 启动只需要两个节点：`console`和`null`。控制台只需要对 root 可访问，设备节点的所有者，因此访问权限为 600。空设备应该对所有人可读可写，因此模式为 666。您可以使用`mknod`的`-m`选项在创建节点时设置模式。您需要是 root 才能创建设备节点：

```
$ cd ~/rootfs
$ sudo mknod -m 666 dev/null c 1 3
$ sudo mknod -m 600 dev/console c 5 1
$ ls -l dev
total 0
crw------- 1 root root 5, 1 Oct 28 11:37 console
crw-rw-rw- 1 root root 1, 3 Oct 28 11:37 null

```

您可以使用标准的`rm`命令删除设备节点：没有`rmnod`命令，因为一旦创建，它们就是普通文件。

# proc 和 sysfs 文件系统

`proc`和`sysfs`是两个伪文件系统，它们提供了内核内部工作的窗口。它们都将内核数据表示为目录层次结构中的文件：当您读取其中一个文件时，您看到的内容并不来自磁盘存储，而是由内核中的一个函数即时格式化的。一些文件也是可写的，这意味着将调用内核函数并使用您写入的新数据，如果格式正确且您有足够的权限，它将修改内核内存中存储的值。换句话说，`proc`和`sysfs`提供了另一种与设备驱动程序和其他内核代码交互的方式。

`proc`和`sysfs`应该挂载在目录`/proc`和`/sys`上：

```
mount -t proc proc /proc
mount -t sysfs sysfs /sys

```

尽管它们在概念上非常相似，但它们执行不同的功能。`proc`从 Linux 的早期就存在。它的最初目的是向用户空间公开有关进程的信息，因此得名。为此，有一个名为`/proc/<PID>`的目录，其中包含有关其状态的信息。进程列表命令`ps`读取这些文件以生成其输出。此外，还有一些文件提供有关内核其他部分的信息，例如`/proc/cpuinfo`告诉您有关 CPU 的信息，`/proc/interrupts`包含有关中断的信息，等等。最后，在`/proc/sys`中，有一些文件显示和控制内核子系统的状态和行为，特别是调度、内存管理和网络。有关您将在`proc`中找到的文件的最佳参考是`proc(5)`手册页。

实际上，随着时间的推移，`proc`中的文件数量及其布局变得相当混乱。在 Linux 2.6 中，`sysfs`被引入以有序方式导出数据的子集。

相比之下，`sysfs`导出了一个与设备及其相互连接方式相关的文件的有序层次结构。

## 挂载文件系统

`mount`命令允许我们将一个文件系统附加到另一个文件系统中的目录，形成文件系统的层次结构。在顶部被内核挂载时，称为根文件系统。`mount`命令的格式如下：

```
mount [-t vfstype] [-o options] device directory

```

您需要指定文件系统的类型`vfstype`，它所在的块设备节点，以及您要将其挂载到的目录。在`-o`之后，您可以给出各种选项，更多信息请参阅手册。例如，如果您想要将包含`ext4`文件系统的 SD 卡的第一个分区挂载到目录`/mnt`，您可以输入以下内容：

```
mount -t ext4 /dev/mmcblk0p1 /mnt

```

假设挂载成功，您将能够在目录`/mnt`中看到存储在 SD 卡上的文件。在某些情况下，您可以省略文件系统类型，让内核探测设备以找出存储的内容。

看看挂载`proc`文件系统的例子，有一些奇怪的地方：没有设备节点`/dev/proc`，因为它是一个伪文件系统，而不是一个真正的文件系统。但`mount`命令需要一个设备作为参数。因此，我们必须提供一个字符串来代替设备，但这个字符串是什么并不重要。这两个命令实现了完全相同的结果：

```
mount -t proc proc /proc
mount -t proc nodevice /proc

```

在挂载伪文件系统时，通常在设备的位置使用文件系统类型。

# 内核模块

如果您有内核模块，它们需要安装到根文件系统中，使用内核`make modules_install`目标，就像我们在上一章中看到的那样。这将把它们复制到目录`/lib/modules/<kernel version>`中，以及`modprobe`命令所需的配置文件。

请注意，您刚刚在内核和根文件系统之间创建了一个依赖关系。如果您更新其中一个，您将不得不更新另一个。

# 将根文件系统传输到目标位置

在暂存目录中创建了一个骨架根文件系统后，下一个任务是将其传输到目标位置。在接下来的章节中，我将描述三种可能性：

+   **ramdisk**：由引导加载到 RAM 中的文件系统映像。Ramdisks 易于创建，并且不依赖于大容量存储驱动程序。当主根文件系统需要更新时，它们可以用于后备维护模式。它们甚至可以用作小型嵌入式设备的主根文件系统，当然也可以用作主流 Linux 发行版中的早期用户空间。压缩的 ramdisk 使用最少的存储空间，但仍然消耗 RAM。内容是易失性的，因此您需要另一种存储类型来存储永久数据，例如配置参数。

+   **磁盘映像**：根文件系统的副本，格式化并准备好加载到目标设备的大容量存储设备上。例如，它可以是一个`ext4`格式的映像，准备好复制到 SD 卡上，或者它可以是一个`jffs2`格式的映像，准备好通过引导加载到闪存中。创建磁盘映像可能是最常见的选项。有关不同类型的大容量存储的更多信息，请参阅第七章，“创建存储策略”。

+   **网络文件系统**：暂存目录可以通过 NFS 服务器导出到网络，并在启动时由目标设备挂载。在开发阶段通常会这样做，而不是重复创建磁盘映像并重新加载到大容量存储设备上，这是一个相当慢的过程。

我将从 ramdisk 开始，并用它来说明对根文件系统的一些改进，比如添加用户名和设备管理器以自动创建设备节点。然后，我将向您展示如何创建磁盘映像，最后，如何使用 NFS 在网络上挂载根文件系统。

# 创建引导 ramdisk

Linux 引导 ramdisk，严格来说，是一个**初始 RAM 文件系统**或**initramfs**，是一个压缩的`cpio`存档。`cpio`是一个古老的 Unix 存档格式，类似于 TAR 和 ZIP，但更容易解码，因此在内核中需要更少的代码。您需要配置内核以支持`initramfs`的`CONFIG_BLK_DEV_INITRD`。

实际上，有三种不同的方法可以创建引导 ramdisk：作为一个独立的`cpio`存档，作为嵌入在内核映像中的`cpio`存档，以及作为内核构建系统在构建过程中处理的设备表。第一种选项提供了最大的灵活性，因为我们可以随心所欲地混合和匹配内核和 ramdisk。但是，这意味着您需要处理两个文件而不是一个，并且并非所有的引导加载程序都具有加载单独 ramdisk 的功能。稍后我将向您展示如何将其构建到内核中。

## 独立的 ramdisk

以下一系列指令创建存档，对其进行压缩，并添加一个 U-Boot 标头，以便加载到目标设备上：

```
$ cd ~/rootfs
$ find . | cpio -H newc -ov --owner root:root > ../initramfs.cpio
$ cd ..
$ gzip initramfs.cpio
$ mkimage -A arm -O linux -T ramdisk -d initramfs.cpio.gz uRamdisk

```

请注意，我们使用了`cpio`选项`--owner root:root`。这是对前面提到的文件所有权问题的一个快速修复，使`cpio`文件中的所有内容的 UID 和 GID 都为 0。

`uRamdisk`文件的最终大小约为 2.9 MiB，没有内核模块。再加上内核`zImage`文件的 4.4 MiB，以及 U-Boot 的 440 KiB，总共需要 7.7 MiB 的存储空间来引导此板。我们离最初的 1.44 MiB 软盘还有一段距离。如果大小是一个真正的问题，您可以使用以下选项之一：

+   通过留出您不需要的驱动程序和功能，使内核变得更小

+   通过留出您不需要的实用程序，使 BusyBox 变得更小

+   使用 uClibc 或 musl libc 代替 glibc

+   静态编译 BusyBox

## 引导 ramdisk

我们可以做的最简单的事情是在控制台上运行一个 shell，以便与设备进行交互。我们可以通过将`rdinit=/bin/sh`添加到内核命令行来实现这一点。现在，您可以引导设备。

### 使用 QEMU 引导

QEMU 有`-initrd`选项，可以将`initframfs`加载到内存中，因此完整的命令现在如下所示：

```
$ cd ~/rootfs
$ QEMU_AUDIO_DRV=none \
qemu-system-arm -m 256M -nographic -M vexpress-a9 -kernel zImage -append "console=ttyAMA0 rdinit=/bin/sh" -dtb vexpress-v2p-ca9.dtb -initrd initramfs.cpio.gz

```

### 引导 BeagleBone Black

要启动 BeagleBone Black，请引导到 U-Boot 提示符，并输入以下命令：

```
fatload mmc 0:1 0x80200000 zImage
fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
fatload mmc 0:1 0x81000000 uRamdisk
setenv bootargs console=ttyO0,115200 rdinit=/bin/sh
bootz 0x80200000 0x81000000 0x80f00000

```

如果一切顺利，您将在控制台上获得一个根 shell 提示符。

### 挂载 proc

请注意，`ps`命令不起作用：这是因为`proc`文件系统尚未被挂载。尝试挂载它，然后再次运行`ps`。

对此设置的一个改进是编写一个包含需要在启动时执行的内容的 shell 脚本，并将其作为`rdinit=`的参数。脚本将类似于以下代码片段：

```
#!/bin/sh
/bin/mount -t proc proc /proc
/bin/sh

```

以这种方式使用 shell 作为`init`对于快速修补非常方便，例如，当您想要修复带有损坏`init`程序的系统时。但是，在大多数情况下，您将使用一个`init`程序，我们将在后面进一步介绍。

## 将 ramdisk cpio 构建到内核映像中

在某些情况下，最好将 ramdisk 构建到内核映像中，例如，如果引导加载程序无法处理 ramdisk 文件。要做到这一点，更改内核配置并将`CONFIG_INITRAMFS_SOURCE`设置为您之前创建的`cpio`存档的完整路径。如果您使用`menuconfig`，它在**常规设置** | **Initramfs 源文件**中。请注意，它必须是以`.cpio`结尾的未压缩`cpio`文件；而不是经过 gzip 压缩的版本。然后，构建内核。您应该看到它比以前大。

引导与以前相同，只是没有 ramdisk 文件。对于 QEMU，命令如下：

```
$ cd ~/rootfs
$ QEMU_AUDIO_DRV=none \
qemu-system-arm -m 256M -nographic -M vexpress-a9 -kernel zImage -append "console=ttyAMA0 rdinit=/bin/sh" -dtb vexpress-v2p-ca9.dtb

```

对于 BeagleBone Black，将这些命令输入 U-Boot：

```
fatload mmc 0:1 0x80200000 zImage
fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
setenv bootargs console=ttyO0,115200 rdinit=/bin/sh
bootz 0x80200000 – 0x80f00000

```

当然，您必须记住每次更改 ramdisk 的内容并重新生成`.cpio`文件时都要重新构建内核。

### 另一种构建带有 ramdisk 的内核的方法

将 ramdisk 构建到内核映像中的一个有趣的方法是使用**设备表**生成`cpio`存档。`设备表`是一个文本文件，列出了存档中包含的文件、目录、设备节点和链接。压倒性的优势在于，您可以在`cpio`文件中创建属于 root 或任何其他 UID 的条目，而无需自己拥有 root 权限。您甚至可以创建设备节点。所有这些都是可能的，因为存档只是一个数据文件。只有在 Linux 在引导时扩展它时，才会使用您指定的属性创建真实的文件和目录。

这是我们简单的`rootfs`的设备表，但缺少大部分到`busybox`的符号链接，以便更易管理：

```
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
nod /dev/null 0666 0 0 c 1 3
nod /dev/ttyO0 0600 0 0 c 252 0
dir /bin 0755 0 0
file /bin/busybox /home/chris/rootfs/bin/busybox 0755 0 0
slink /bin/sh /bin/busybox 0777 0 0
dir /lib 0755 0 0
file /lib/ld-2.19.so /home/chris/rootfs/lib/ld-2.19.so 0755 0 0
slink /lib/ld-linux.so.3 /lib/ld-2.19.so 0777 0 0
file /lib/libc-2.19.so /home/chris/rootfs/lib/libc-2.19.so 0755 0 0
slink /lib/libc.so.6 /lib/libc-2.19.so 0777 0 0
file /lib/libm-2.19.so /home/chris/rootfs/lib/libm-2.19.so 0755 0 0
slink /lib/libm.so.6 /lib/libm-2.19.so 0777 0 0

```

语法相当明显：

+   `dir <name> <mode> <uid> <gid>`

+   `file <name> <location> <mode> <uid> <gid>`

+   `nod <name> <mode> <uid> <gid> <dev_type> <maj> <min>`

+   `slink <name> <target> <mode> <uid> <gid>`

内核提供了一个工具，读取此文件并创建`cpio`存档。源代码在`usr/gen_init_cpio.c`中。`scripts/gen_initramfs_list.sh`中有一个方便的脚本，它从给定目录创建设备表，这样可以节省很多输入。

要完成任务，您需要将`CONFIG_INITRAMFS_SOURCE`设置为指向设备表文件，然后构建内核。其他一切都和以前一样。

## 旧的 initrd 格式

Linux ramdisk 的旧格式称为`initrd`。在 Linux 2.6 之前，这是唯一可用的格式，并且如果您使用 Linux 的无 mmu 变体 uCLinux，则仍然需要它。它相当晦涩，我在这里不会涉及。内核源代码中有更多信息，在`Documentation/initrd.txt`中。

# init 程序

在引导时运行 shell，甚至是 shell 脚本，对于简单情况来说是可以的，但实际上您需要更灵活的东西。通常，Unix 系统运行一个名为`init`的程序，它启动并监视其他程序。多年来，已经有许多`init`程序，其中一些我将在第九章中描述，*启动 - init 程序*。现在，我将简要介绍 BusyBox 中的`init`。

`init`开始读取配置文件`/etc/inittab`。这是一个对我们的需求足够简单的示例：

```
::sysinit:/etc/init.d/rcS
::askfirst:-/bin/ash
```

第一行在启动`init`时运行一个 shell 脚本`rcS`。第二行将消息**请按 Enter 键激活此控制台**打印到控制台，并在按下*Enter*时启动一个 shell。`/bin/ash`前面的`-`表示它将是一个登录 shell，在给出 shell 提示之前会源自`/etc/profile`和`$HOME/.profile`。以这种方式启动 shell 的一个优点是启用了作业控制。最直接的影响是您可以使用*Ctrl* + *C*来终止当前程序。也许您之前没有注意到，但是等到您运行`ping`程序并发现无法停止它时！

BusyBox `init`在根文件系统中没有`inittab`时提供默认的`inittab`。它比前面的更加广泛。

脚本`/etc/init.d/rcS`是放置需要在启动时执行的初始化命令的地方，例如挂载`proc`和`sysfs`文件系统：

```
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
```

确保使`rcS`可执行，就像这样：

```
$ cd ~/rootfs
$ chmod +x etc/init.d/rcS

```

您可以通过更改`-append`参数在 QEMU 上尝试它，就像这样：

```
-append "console=ttyAMA0 rdinit=/sbin/init"
```

要在 BeagelBone Black 上实现相同的效果，需要更改 U-Boot 中的`bootargs`变量，如下所示：

```
setenv bootargs console=ttyO0,115200 rdinit=/sbin/init
```

# 配置用户帐户

正如我已经暗示的，以 root 身份运行所有程序并不是一个好的做法，因为如果一个程序受到外部攻击，那么整个系统都处于风险之中，而且如果作为 root 运行的程序行为不端，它可能会造成更大的破坏。最好创建非特权用户帐户，并在不需要完全 root 权限的地方使用它们。

用户名称配置在`/etc/passwd`中。每个用户一行，由冒号分隔的七个信息字段：

+   登录名

+   用于验证密码的哈希码，或者更通常地是一个`x`，表示密码存储在`/etc/shadow`中

+   UID

+   GID

+   一个注释字段，通常留空

+   用户的主目录

+   （可选）此用户将使用的 shell

例如，这将创建用户`root`，UID 为 0，和`daemon`，UID 为 1：

```
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
```

将用户 daemon 的 shell 设置为`/bin/false`可以确保使用该名称登录的任何尝试都会失败。

### 注意

各种程序必须读取`/etc/passwd`以便能够查找 UID 和名称，因此它必须是可读的。如果密码哈希存储在其中，那就是一个问题，因为恶意程序将能够复制并使用各种破解程序发现实际密码。因此，为了减少这些敏感信息的暴露，密码存储在`/etc/shadow`中，并在密码字段中放置一个`x`以指示这种情况。`/etc/shadow`只能由`root`访问，只要`root`用户受限，密码就是安全的。

影子密码文件由每个用户的一个条目组成，由九个字段组成。这是一个与前一段中显示的`passwd`文件相似的例子：

```
root::10933:0:99999:7:::
daemon:*:10933:0:99999:7:::
```

前两个字段是用户名和密码哈希。剩下的七个与密码老化有关，这在嵌入式设备上通常不是问题。如果您对完整的细节感兴趣，请参阅手册页*shadow(5)*。

在这个例子中，`root`的密码是空的，这意味着`root`可以在不输入密码的情况下登录，这在开发过程中很有用，但在生产中不适用！您可以使用`mkpasswd`命令生成密码哈希，或者在目标上运行`passwd`命令，并将目标上的`/etc/shadow`中的哈希字段复制并粘贴到分段目录中的默认 shadow 文件中。

daemon 的密码是`*`，这不会匹配任何登录密码，再次确保 daemon 不能用作常规用户帐户。

组名以类似的方式存储在`/etc/group`中。格式如下：

+   组的名称

+   组密码，通常是一个`x`字符，表示没有组密码

+   GID

+   属于该组的用户的可选列表，用逗号分隔。

这是一个例子：

```
root:x:0:
daemon:x:1:
```

## 向根文件系统添加用户帐户

首先，你必须向你的暂存目录添加`etc/passwd`、`etc/shadow`和`etc/group`，就像前面的部分所示的那样。确保`shadow`的权限为 0600。

登录过程由一个名为`getty`的程序启动，它是 BusyBox 的一部分。你可以使用`inittab`中的`respawn`关键字启动它，当登录 shell 终止时，`getty`将被重新启动，因此`inittab`应该如下所示：

```
::sysinit:/etc/init.d/rcS
::respawn:/sbin/getty 115200 console
```

然后重新构建 ramdisk，并像之前一样使用 QEMU 或 BeagelBone Black 进行尝试。

# 启动守护进程

通常，你会希望在启动时运行某些后台进程。让我们以日志守护程序`syslogd`为例。`syslogd`的目的是积累来自其他程序（大多数是其他守护程序）的日志消息。当然，BusyBox 有一个适用于此的小工具！

启动守护进程就像在`etc/inittab`中添加这样一行那样简单：

```
::respawn:syslogd -n
```

`respawn`表示，如果程序终止，它将自动重新启动；`-n`表示它应该作为前台进程运行。日志将被写入`/var/log/messages`。

### 提示

你可能也想以同样的方式启动`klogd`：`klogd`将内核日志消息发送到`syslogd`，以便将其记录到永久存储中。

顺便提一下，在典型的嵌入式 Linux 系统中，将日志文件写入闪存并不是一个好主意，因为这样会使其磨损。我将在第七章中介绍日志记录的选项，*创建存储策略*。

# 更好地管理设备节点

使用`mknod`静态创建设备节点非常费力且不灵活。还有其他方法可以根据需要自动创建设备节点：

+   `devtmpfs`：这是一个伪文件系统，在引导时挂载到`/dev`上。内核会为内核当前已知的所有设备填充它，并在运行时检测到新设备时创建节点。这些节点由`root`拥有，并具有默认权限 0600。一些众所周知的设备节点，如`/dev/null`和`/dev/random`，覆盖默认值为 0666（请参阅`drivers/char/mem.c`中的`struct` `memdev`）。

+   `mdev`：这是一个 BusyBox 小工具，用于向目录填充设备节点，并根据需要创建新节点。有一个配置文件`/etc/mdev.conf`，其中包含节点所有权和模式的规则。

+   `udev`：现在是`systemd`的一部分，是桌面 Linux 和一些嵌入式设备上的解决方案。它非常灵活，是高端嵌入式设备的不错选择。

### 提示

虽然`mdev`和`udev`都可以自行创建设备节点，但更常见的做法是让`devtmpfs`来完成这项工作，并使用`mdev/udev`作为实施设置所有权和权限策略的一层。

## 使用 devtmpfs 的示例

如果你已经启动了之前的 ramdisk 示例之一，尝试`devtmpfs`就像输入这个命令一样简单：

```
# mount -t devtmpfs devtmpfs /dev

```

你应该看到`/dev`里面充满了设备节点。要进行永久修复，将这个添加到`/etc/init.d/rcS`中：

```
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

```

事实上，内核初始化会自动执行这一操作，除非你提供了`initramfs` ramdisk，就像我们所做的那样！要查看代码，请查看`init/do_mounts.c`，函数`prepare_namespace()`。

## 使用 mdev 的示例

虽然设置`mdev`有点复杂，但它允许你在创建设备节点时修改权限。首先，有一个启动阶段，通过`-s`选项选择，当`mdev`扫描`/sys`目录查找有关当前设备的信息并用相应的节点填充`/dev`目录。

如果你想跟踪新设备的上线并为它们创建节点，你需要将`mdev`作为热插拔客户端写入`/proc/sys/kernel/hotplug`。将这些添加到`/etc/init.d/rcS`将实现所有这些：

```
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo /sbin/mdev > /proc/sys/kernel/hotplug
mdev -s

```

默认模式为 660，所有权为`root:root`。您可以通过在`/etc/mdev.conf`中添加规则来更改。例如，要为`null`，`random`和`urandom`设备提供正确的模式，您需要将其添加到`/etc/mdev.conf`中：

```
null     root:root 666
random   root:root 444
urandom  root:root 444

```

该格式在 BusyBox 源代码中的`docs/mdev.txt`中有记录，并且在名为`examples`的目录中有更多示例。

## 静态设备节点到底有多糟糕？

静态创建的设备节点确实有一个优点：它们在引导过程中不需要花费任何时间来创建，而其他方法则需要。如果最小化引导时间是一个优先考虑的问题，使用静态创建的设备节点将节省可测量的时间。

# 配置网络

接下来，让我们看一些基本的网络配置，以便我们可以与外部世界通信。我假设有一个以太网接口`eth0`，我们只需要一个简单的 IP v4 配置。

这些示例使用了 BusyBox 的网络实用程序，并且对于简单的用例来说足够了，使用`old-but-reliable ifup`和`ifdown`程序。您可以阅读这两者的 man 页面以获取更多细节。主要的网络配置存储在`/etc/network/interfaces`中。您需要在暂存目录中创建这些目录：

```
etc/network
etc/network/if-pre-up.d
etc/network/if-up.d
var/run
```

对于静态 IP 地址，`etc/network/interfaces`看起来像这样：

```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
  address 10.0.0.42
  netmask 255.255.255.0
  network 10.0.0.0
```

对于使用 DHCP 分配的动态 IP 地址，`etc/network/interfaces`看起来像这样：

```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet dhcp
```

您还需要配置一个 DHCP 客户端程序。BusyBox 有一个名为`udchpcd`的程序。它需要一个应该放在`/usr/share/udhcpc/default.script`中的 shell 脚本。在 BusyBox 源代码的`examples//udhcp/simple.script`目录中有一个合适的默认值。

## glibc 的网络组件

`glibc`使用一种称为**名称服务开关**（**NSS**）的机制来控制名称解析为网络和用户的数字的方式。例如，用户名可以通过文件`/etc/passwd`解析为 UID；网络服务（如 HTTP）可以通过`/etc/services`解析为服务端口号，等等。所有这些都由`/etc/nsswitch.conf`配置，有关详细信息，请参阅手册页*nss(5)*。以下是一个对大多数嵌入式 Linux 实现足够的简单示例：

```
passwd:      files
group:       files
shadow:      files
hosts:       files dns
networks:    files
protocols:   files
services:    files
```

一切都由`/etc`中同名的文件解决，除了主机名，它可能还会通过 DNS 查找来解决。

要使其工作，您需要使用这些文件填充`/etc`。网络、协议和服务在所有 Linux 系统中都是相同的，因此可以从开发 PC 中的`/etc`中复制。`/etc/hosts`至少应包含环回地址：

```
127.0.0.1 localhost
```

我们将在稍后讨论其他的`passwd`，`group`和`shadow`。

拼图的最后一块是执行名称解析的库。它们是根据`nsswitch.conf`的内容按需加载的插件，这意味着如果您使用`readelf`或类似工具，它们不会显示为依赖项。您只需从工具链的`sysroot`中复制它们：

```
$ cd ~/rootfs
$ cp -a $TOOLCHAIN_SYSROOT/lib/libnss* lib
$ cp -a $TOOLCHAIN_SYSROOT/lib/libresolv* lib

```

# 使用设备表创建文件系统映像

内核有一个实用程序`gen_init_cpio`，它根据文本文件中设置的格式指令创建一个`cpio`文件，称为`设备表`，允许非根用户创建设备节点，并为任何文件或目录分配任意 UID 和 GID 值。

相同的概念已应用于创建其他文件系统映像格式的工具：

+   `jffs2`：`mkfs.jffs2`

+   `ubifs`：`mkfs.ubifs`

+   `ext2`：`genext2fs`

我们将在第七章中讨论`jffs2`和`ubifs`，*创建存储策略*，当我们研究用于闪存的文件系统时。第三个`ext2`是一个相当古老的硬盘格式。

它们都需要一个设备表文件，格式为`<name> <type> <mode> <uid> <gid> <major> <minor> <start> <inc> <count>`，其中以下内容适用：

+   `name`：文件名

+   `type`：以下之一：

+   `f`：一个常规文件

+   `d`：一个目录

+   `c`：字符特殊设备文件

+   `b`：块特殊设备文件

+   `p`：FIFO（命名管道）

+   `uid`：文件的 UID

+   `gid`：文件的 GID

+   `major`和`minor`：设备号（仅设备节点）

+   `start`，`inc`和`count`：（仅设备节点）允许您从`start`中的`minor`号开始创建一组设备节点

您不必像使用`gen_init_cpio`那样指定每个文件：您只需将它们指向一个目录-暂存目录-并列出您需要在最终文件系统映像中进行的更改和异常。

一个简单的示例，为我们填充静态设备节点如下：

```
/dev         d  755  0    0  -    -    -    -    -
/dev/null    c  666  0    0    1    3    0    0  -
/dev/console c  600  0    0    5    1    0    0  -
/dev/ttyO0   c  600  0    0   252   0    0    0  -
```

然后，使用`genext2fs`生成一个 4 MiB（即默认大小的 4,096 个块，每个块 1,024 字节）的文件系统映像：

```
$ genext2fs -b 4096 -d rootfs -D device-table.txt -U rootfs.ext2

```

现在，您可以将生成的映像`rootfs.ext`复制到 SD 卡或类似的设备。

## 将根文件系统放入 SD 卡中

这是一个从普通块设备（如 SD 卡）挂载文件系统的示例。相同的原则适用于其他文件系统类型，我们将在第七章*创建存储策略*中更详细地讨论它们。

假设您有一个带有 SD 卡的设备，并且第一个分区用于引导文件，`MLO`和`u-boot.img`-就像 BeagleBone Black 上一样。还假设您已经使用`genext2fs`创建了一个文件系统映像。要将其复制到 SD 卡，请插入卡并识别其被分配的块设备：通常为`/dev/sd`或`/dev/mmcblk0`。如果是后者，请将文件系统映像复制到第二个分区：

```
$ sudo dd if=rootfs.ext2 of=/dev/mmcblk0p2

```

然后，将 SD 卡插入设备，并将内核命令行设置为`root=/dev/mmcblk0p2`。完整的引导顺序如下：

```
fatload mmc 0:1 0x80200000 zImage
fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
setenv bootargs console=ttyO0,115200 root=/dev/mmcblk0p2
bootz 0x80200000 – 0x80f00000
```

# 使用 NFS 挂载根文件系统

如果您的设备有网络接口，最好在开发过程中通过网络挂载根文件系统。这样可以访问几乎无限的存储空间，因此您可以添加具有大型符号表的调试工具和可执行文件。作为额外的奖励，对于开发机上托管的根文件系统所做的更新将立即在目标上生效。您还有日志文件的副本。

为了使其工作，您的内核必须配置为`CONFIG_ROOT_NFS`。然后，您可以通过将以下内容添加到内核命令行来配置 Linux 在引导时进行挂载：

```
root=/dev/nfs

```

给出 NFS 导出的详细信息如下：

```
nfsroot=<host-ip>:<root-dir>

```

配置连接到 NFS 服务器的网络接口，以便在引导时，在`init`程序运行之前使用此命令：

```
ip=<target-ip>

```

有关 NFS 根挂载的更多信息，请参阅内核源中的`Documentation/filesystems/nfs/nfsroot.txt`。

您还需要在主机上安装和配置 NFS 服务器，对于 Ubuntu，您可以使用以下命令完成：

```
$ sudo apt-get install nfs-kernel-server

```

NFS 服务器需要告知哪些目录正在导出到网络，这由`/etc/exports`控制。向该文件添加类似以下行：

```
/<path to staging> *(rw,sync,no_subtree_check,no_root_squash)
```

然后，重新启动服务器以应用更改，对于 Ubuntu 来说是：

```
$ sudo /etc/init.d/nfs-kernel-server restart

```

## 使用 QEMU 进行测试

以下脚本创建了一个虚拟网络，将主机上的网络设备`tap0`与目标上的`eth0`使用一对静态 IPv4 地址连接起来，然后使用参数启动 QEMU，以使用`tap0`作为模拟接口。您需要更改根文件系统的路径为您的暂存目录的完整路径，如果它们与您的网络配置冲突，可能还需要更改 IP 地址：

```
#!/bin/bash

KERNEL=zImage
DTB=vexpress-v2p-ca9.dtb
ROOTDIR=/home/chris/rootfs

HOST_IP=192.168.1.1
TARGET_IP=192.168.1.101
NET_NUMBER=192.168.1.0
NET_MASK=255.255.255.0

sudo tunctl -u $(whoami) -t tap0
sudo ifconfig tap0 ${HOST_IP}
sudo route add -net ${NET_NUMBER} netmask ${NET_MASK} dev tap0
sudo sh -c "echo  1 > /proc/sys/net/ipv4/ip_forward"

QEMU_AUDIO_DRV=none \
qemu-system-arm -m 256M -nographic -M vexpress-a9 -kernel $KERNEL -append "console=ttyAMA0 root=/dev/nfs rw nfsroot=${HOST_IP}:${ROOTDIR} ip=${TARGET_IP}" -dtb ${DTB} -net nic -net tap,ifname=tap0,script=no
```

该脚本可用作`run-qemu-nfs.sh`。

它应该像以前一样启动，但现在直接通过 NFS 导出使用暂存目录。您在该目录中创建的任何文件将立即对目标设备可见，而在设备上创建的文件将对开发 PC 可见。

## 使用 BeagleBone Black 进行测试

类似地，您可以在 BeagleBone Black 的 U-Boot 提示符下输入这些命令：

```
setenv serverip 192.168.1.1
setenv ipaddr 192.168.1.101
setenv npath [path to staging directory]
setenv bootargs console=ttyO0,115200 root=/dev/nfs rw nfsroot=${serverip}:${npath} ip=${ipaddr}

```

然后，要引导它，从`sdcard`中加载内核和`dtb`，就像以前一样：

```
fatload mmc 0:1 0x80200000 zImage
fatload mmc 0:1 0x80f00000 am335x-boneblack.dtb
bootz 0x80200000 - 0x80f00000

```

## 文件权限问题

已经在暂存目录中的文件由您拥有，并且在运行`ls -l`时会显示在目标上，无论您的 UID 是什么，通常为 1,000。由目标设备创建的任何文件都将由 root 拥有。整个情况一团糟。

不幸的是，没有简单的方法。最好的建议是复制暂存目录并将所有权更改为`root:root`（使用`sudo chown -R 0:0 *`），并将此目录导出为 NFS 挂载。这样可以减少在开发和目标系统之间共享根文件系统的不便。

# 使用 TFTP 加载内核

当使用诸如 BeagleBone Black 之类的真实硬件时，最好通过网络加载内核，特别是当根文件系统通过 NFS 挂载时。这样，您就不会使用设备上的任何本地存储。如果不必一直重新刷新内存，可以节省时间，并且意味着您可以在闪存存储驱动程序仍在开发中时完成工作（这种情况经常发生）。

U-Boot 多年来一直支持**简单文件传输协议**（**TFTP**）。首先，您需要在开发机器上安装`tftp`守护程序。在 Ubuntu 上，您将安装`tftpd-hpa`软件包，该软件包授予`/var/lib/tftpboot`目录中的文件对`U-Boot`等`tftp`客户端的读取访问权限。

假设您已将`zImage`和`am335x-boneblack.dtb`复制到`/var/lib/tftpboot`，请在 U-Boot 中输入以下命令以加载和启动：

```
setenv serverip 192.168.1.1
setenv ipaddr 192.168.1.101
tftpboot 0x80200000 zImage
tftpboot 0x80f00000 am335x-boneblack.dtb
setenv npath [path to staging]
setenv bootargs console=ttyO0,115200 root=/dev/nfs rw nfsroot=${serverip}:${npath} ip=${ipaddr}
bootz 0x80200000 - 0x80f00000

```

对于`tftpboot`的响应通常是这样的：

```
setenv ipaddr 192.168.1.101
nova!> setenv serverip 192.168.1.1
nova!> tftpboot 0x80200000 zImage
link up on port 0, speed 100, full duplex
Using cpsw device
TFTP from server 192.168.1.1; our IP address is 192.168.1.101
Filename 'zImage'.
Load address: 0x80200000
Loading: T T T T

```

最后一行的`T`字符行表示有些问题，TFTP 请求超时。最常见的原因如下：

+   服务器的 IP 地址不正确。

+   服务器上没有运行 TFTP 守护程序。

+   服务器上的防火墙阻止了 TFTP 协议。大多数防火墙默认确实会阻止 TFTP 端口 69。

在这种情况下，tftp 守护程序没有运行，所以我用以下命令启动了它：

```
$ sudo service tftpd-hpa restart

```

# 额外阅读

+   *文件系统层次结构标准*，目前版本为 3.0，可在[`refspecs.linuxfoundation.org/fhs.shtml`](http://refspecs.linuxfoundation.org/fhs.shtml)上找到。

+   *ramfs, rootfs and initramfs , Rob Landley*，2005 年 10 月 17 日，这是 Linux 源代码中的一部分，可在`Documentation/filesystems/ramfs-rootfs-initramfs.txt`上找到。

# 总结

Linux 的一个优点是它可以支持各种根文件系统，从而使其能够满足各种需求。我们已经看到可以手动使用少量组件构建简单的根文件系统，并且 BusyBox 在这方面特别有用。通过一步一步地进行这个过程，我们对 Linux 系统的一些基本工作原理有了了解，包括网络配置和用户帐户。然而，随着设备变得更加复杂，任务很快变得难以管理。而且，我们始终担心可能存在我们没有注意到的实现中的安全漏洞。在下一章中，我们将研究使用嵌入式构建系统来帮助我们。


# 第六章：选择构建系统

前几章涵盖了嵌入式 Linux 的四个元素，并逐步向您展示了如何构建工具链、引导加载程序、内核和根文件系统，然后将它们组合成基本的嵌入式 Linux 系统。而且有很多步骤！现在是时候看看如何通过尽可能自动化来简化这个过程。我将介绍嵌入式构建系统如何帮助，并特别介绍两种构建系统：Buildroot 和 Yocto Project。这两种都是复杂而灵活的工具，需要整本书来充分描述它们的工作原理。在本章中，我只想向您展示构建系统背后的一般思想。我将向您展示如何构建一个简单的设备镜像，以便对系统有一个整体感觉，然后如何进行一些有用的更改，使用前几章中的 Nova 板示例。

# 不再自己制作嵌入式 Linux

手动创建系统的过程，如第五章中所述的*构建根文件系统*，称为**roll your own**（**RYO**）过程。它的优点是您完全控制软件，可以根据自己的喜好进行定制。如果您希望它执行一些非常奇特但创新的操作，或者如果您希望将内存占用减少到最小，RYO 是一种方法。但是，在绝大多数情况下，手动构建是浪费时间并产生质量较差、难以维护的系统。

它们通常在几个月的时间内逐步构建，通常没有记录，很少从头开始重新创建，因为没有人知道每个部分来自哪里。

# 构建系统

构建系统的理念是自动化我到目前为止描述的所有步骤。构建系统应该能够从上游源代码构建一些或所有以下内容：

+   工具链

+   引导加载程序

+   内核

+   根文件系统

从上游源代码构建对于许多原因都很重要。这意味着您可以放心，随时可以重新构建，而无需外部依赖。这还意味着您拥有用于调试的源代码，并且可以满足分发给用户的许可要求。

因此，为了完成其工作，构建系统必须能够执行以下操作：

+   从上游下载源代码，可以直接从源代码控制系统或作为存档文件，并将其缓存在本地

+   应用补丁以启用交叉编译，修复与体系结构相关的错误，应用本地配置策略等

+   构建各种组件

+   创建一个暂存区并组装一个根文件系统

+   创建各种格式的镜像文件，准备加载到目标设备上

其他有用的东西如下：

+   添加您自己的软件包，例如应用程序或内核更改

+   选择各种根文件系统配置文件：大或小，带有或不带有图形或其他功能

+   创建一个独立的 SDK，您可以将其分发给其他开发人员，以便他们不必安装完整的构建系统

+   跟踪所选软件包使用的各种开源许可证

+   允许您为现场更新创建更新

+   具有用户友好的用户界面

在所有情况下，它们将系统的组件封装成包，一些用于主机，一些用于目标。每个软件包由一组规则定义，以获取源代码，构建它，并将结果安装在正确的位置。软件包之间存在依赖关系和构建机制来解决依赖关系并构建所需的软件包集。

开源构建系统在过去几年中已经显著成熟。有许多构建系统，包括：

+   **Buildroot**：使用 GNU `make`和`Kconfig`的易于使用的系统（[`buildroot.org`](http://buildroot.org)）

+   **EmbToolkit**：用于生成根文件系统的简单系统；在撰写本文时，是唯一支持 LLVM/Clang 的系统（[`www.embtoolkit.org`](https://www.embtoolkit.org)）

+   **OpenEmbedded**：一个强大的系统，也是 Yocto 项目和其他项目的核心组件（[`openembedded.org`](http://openembedded.org)）

+   **OpenWrt**：一个面向无线路由器固件构建的构建工具（[`openwrt.org`](https://openwrt.org)）

+   **PTXdist**：由 Pengutronix 赞助的开源构建系统（[`www.pengutronix.de/software/ptxdist/index_en.html`](http://www.pengutronix.de/software/ptxdist/index_en.html)）

+   **Tizen**：一个全面的系统，重点放在移动、媒体和车载设备上（[`www.tizen.org`](https://www.tizen.org)）

+   **Yocto 项目**：这扩展了 OpenEmbedded 核心的配置、层、工具和文档：可能是最受欢迎的系统（[`www.yoctoproject.org`](http://www.yoctoproject.org)）

我将专注于其中两个：Buildroot 和 Yocto 项目。它们以不同的方式和不同的目标解决问题。

Buildroot 的主要目标是构建根文件系统映像，因此得名，尽管它也可以构建引导加载程序和内核映像。它易于安装和配置，并且可以快速生成目标映像。

另一方面，Yocto 项目在定义目标系统的方式上更加通用，因此可以构建相当复杂的嵌入式设备。每个组件都以 RPM、`.dpkg`或`.ipk`格式的软件包生成（见下一节），然后将这些软件包组合在一起以制作文件系统映像。此外，您可以在文件系统映像中安装软件包管理器，这允许您在运行时更新软件包。换句话说，当您使用 Yocto 项目构建时，实际上是在创建自己的定制 Linux 发行版。

# 软件包格式和软件包管理器

主流 Linux 发行版在大多数情况下是由 RPM 或 deb 格式的二进制（预编译）软件包集合构建而成。**RPM**代表**Red Hat 软件包管理器**，在 Red Hat、Suse、Fedora 和其他基于它们的发行版中使用。基于 Debian 的发行版，包括 Ubuntu 和 Mint，使用 Debian 软件包管理器格式`deb`。此外，还有一种轻量级格式专门用于嵌入式设备，称为**Itsy PacKage**格式，或**ipk**，它基于`deb`。

在设备上包含软件包管理器的能力是构建系统之间的重要区别之一。一旦在目标设备上安装了软件包管理器，您就可以轻松地部署新软件包并更新现有软件包。我将在下一章讨论这一点的影响。

# Buildroot

Buildroot 项目网站位于[`buildroot.org`](http://buildroot.org)。

当前版本的 Buildroot 能够构建工具链、引导加载程序（U-Boot、Barebox、GRUB2 或 Gummiboot）、内核和根文件系统。它使用 GNU `make`作为主要构建工具。

[`buildroot.org/docs.html`](http://buildroot.org/docs.html)上有很好的在线文档，包括*Buildroot 用户手册*。

## 背景

Buildroot 是最早的构建系统之一。它始于 uClinux 和 uClibc 项目的一部分，作为生成用于测试的小型根文件系统的一种方式。它于 2001 年末成为一个独立项目，并持续发展到 2006 年，之后进入了一个相当休眠的阶段。然而，自 2009 年 Peter Korsgaard 接管以来，它一直在快速发展，增加了对基于`glibc`的工具链的支持以及构建引导加载程序和内核的能力。

Buildroot 也是另一个流行的构建系统 OpenWrt（[`wiki.openwrt.org`](http://wiki.openwrt.org)）的基础，它在 2004 年左右从 Buildroot 分叉出来。OpenWrt 的主要重点是为无线路由器生产软件，因此软件包混合物是面向网络基础设施的。它还具有使用`.ipk`格式的运行时软件包管理器，因此可以在不完全重新刷写镜像的情况下更新或升级设备。

## 稳定版本和支持

Buildroot 开发人员每年发布四次稳定版本，分别在 2 月、5 月、8 月和 11 月。它们以`git`标签的形式标记为`<year>.02`、`<year>.05`、`<year>.08`和`<year>.11`。通常，当您启动项目时，您将使用最新的稳定版本。但是，稳定版本发布后很少更新。要获得安全修复和其他错误修复，您将不得不在可用时不断更新到下一个稳定版本，或者将修复程序回溯到您的版本中。

## 安装

通常情况下，您可以通过克隆存储库或下载存档来安装 Buildroot。以下是获取 2015.08.1 版本的示例，这是我写作时的最新稳定版本：

```
$ git clone git://git.buildroot.net/buildroot
$ cd buildroot
$ git checkout 2015.08.1

```

等效的 TAR 存档可从[`buildroot.org/downloads`](http://buildroot.org/downloads)获取。

接下来，您应该阅读*Buildroot 用户手册*中的*系统要求*部分，网址为[`buildroot.org/downloads/manual/manual.html`](http://buildroot.org/downloads/manual/manual.html)，并确保您已安装了那里列出的所有软件包。

## 配置

Buildroot 使用`Kconfig`和`Kbuild`机制，就像内核一样，我在第四章的*理解内核配置*部分中描述的那样，*移植和配置内核*。您可以直接使用`make menuconfig`（或`xconfig`或`gconfig`）从头开始配置它，或者您可以选择存储在`configs/`目录中的大约 90 个各种开发板和 QEMU 模拟器的配置之一。键入`make help`列出所有目标，包括默认配置。

让我们从构建一个默认配置开始，您可以在 ARM QEMU 模拟器上运行：

```
$ cd buildroot
$ make qemu_arm_versatile_defconfig
$ make

```

### 提示

请注意，您不需要使用`-j`选项告诉`make`要运行多少个并行作业：Buildroot 将自行充分利用您的 CPU。如果您想限制作业的数量，可以运行`make menuconfig`并查看**Build**选项下的内容。

构建将花费半小时到一小时的时间，这取决于您的主机系统的能力和与互联网的连接速度。完成后，您会发现已创建了两个新目录：

+   `dl/`：这包含了 Buildroot 构建的上游项目的存档

+   `output/`：这包含了所有中间和最终编译的资源

您将在`output/`中看到以下内容：

+   `build/`：这是每个组件的构建目录。

+   `host/`：这包含 Buildroot 所需的在主机上运行的各种工具，包括工具链的可执行文件（在`output/host/usr/bin`中）。

+   `images/`：这是最重要的，包含构建的结果。根据您的配置选择，您将找到引导加载程序、内核和一个或多个根文件系统镜像。

+   `staging/`：这是指向工具链的`sysroot`的符号链接。链接的名称有点令人困惑，因为它并不指向我在第五章中定义的暂存区。

+   `target/`：这是根目录的暂存区。请注意，您不能将其作为根文件系统使用，因为文件所有权和权限未正确设置。Buildroot 在创建文件系统映像时使用设备表来设置所有权和权限，如前一章所述。

## 运行

一些示例配置在`boards/`目录中有相应的条目，其中包含自定义配置文件和有关在目标上安装结果的信息。对于您刚刚构建的系统，相关文件是`board/qemu/arm-vexpress/readme.txt`，其中告诉您如何使用此目标启动 QEMU。

假设您已经按照第一章中描述的方式安装了`qemu-system-arm`，*起步*，您可以使用以下命令运行它：

```
$ qemu-system-arm -M vexpress-a9 -m 256 \
-kernel output/images/zImage \
-dtb output/images/vexpress-v2p-ca9.dtb \
-drive file=output/images/rootfs.ext2,if=sd \
-append "console=ttyAMA0,115200 root=/dev/mmcblk0" \
-serial stdio -net nic,model=lan9118 -net user

```

您应该在启动 QEMU 的同一终端窗口中看到内核引导消息，然后是登录提示符：

```
Booting Linux on physical CPU 0x0
Initializing cgroup subsys cpuset

Linux version 4.1.0 (chris@builder) (gcc version 4.9.3 (Buildroot 2015.08) ) #1 SMP Fri Oct 30 13:55:50 GMT 2015

CPU: ARMv7 Processor [410fc090] revision 0 (ARMv7), cr=10c5387d

CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
Machine model: V2P-CA9
[...]
VFS: Mounted root (ext2 filesystem) readonly on device 179:0.
devtmpfs: mounted
Freeing unused kernel memory: 264K (8061e000 - 80660000)
random: nonblocking pool is initialized
Starting logging: OK
Starting mdev...
Initializing random number generator... done.
Starting network...

Welcome to Buildroot
buildroot login:

```

以`root`身份登录，无需密码。

您会看到 QEMU 启动一个黑色窗口，除了具有内核引导消息的窗口。它用于显示目标的图形帧缓冲区。在这种情况下，目标从不写入`framebuffer`，这就是为什么它是黑色的原因。要关闭 QEMU，可以在 root 提示符处键入`poweroff`，或者只需关闭`framebuffer`窗口。这适用于 QEMU 2.0（Ubuntu 14.04 上的默认版本），但在包括 QEMU 1.0.50（Ubuntu 12.04 上的默认版本）在内的早期版本中失败，因为存在 SCSI 仿真问题。

## 创建自定义 BSP

接下来，让我们使用 Buildroot 为我们的 Nova 板创建 BSP，使用前几章中相同版本的 U-Boot 和 Linux。建议存储更改的位置是：

+   `board/<organization>/<device>`：包含 Linux、U-Boot 和其他组件的补丁、二进制文件、额外的构建步骤、配置文件

+   `configs/<device>_defconfig`：包含板的默认配置

+   `packages/<organization>/<package_name>`：是放置此板的任何额外软件包的位置

我们可以使用 BeagleBone 配置文件作为基础，因为 Nova 是近亲：

```
$ make clean  #  Always do a clean when changing targets
$ make beaglebone_defconfig

```

现在`.config`文件已设置为 BeagleBone。接下来，为板配置创建一个目录：

```
$ mkdir -p board/melp/nova

```

### U-Boot

在第三章中，*引导程序全解*，我们为 Nova 创建了一个基于 U-Boot 2015.07 版本的自定义引导程序，并为其创建了一个补丁文件。我们可以配置 Buildroot 选择相同的版本，并应用我们的补丁。首先将补丁文件复制到`board/melp/nova`，然后使用`make menuconfig`将 U-Boot 版本设置为 2015.07，补丁目录设置为`board/melp/nova`，并将板名称设置为 nova，如此屏幕截图所示：

![U-Boot](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_06_01.jpg)

### Linux

在第四章中，*移植和配置内核*，我们基于 Linux 4.1.10 构建了内核，并提供了一个名为`nova.dts`的新设备树。将设备树复制到`board/melp/nova`，并更改 Buildroot 内核配置以使用此版本和 nova 设备树，如此屏幕截图所示：

![Linux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_06_02.jpg)

### 构建

现在，您可以通过键入`make`为 Nova 板构建系统，这将在目录`output/images`中生成这些文件：

```
MLO  nova.dtb  rootfs.ext2  u-boot.img  uEnv.txt  zImage

```

最后一步是保存配置的副本，以便您和其他人可以再次使用它：

```
$ make savedefconfig BR2_DEFCONFIG=configs/nova_defconfig

```

现在，您已经为 Nova 板创建了 Buildroot 配置。

## 添加您自己的代码

假设您开发了一些程序，并希望将其包含在构建中。您有两个选择：首先，使用它们自己的构建系统单独构建它们，然后将二进制文件作为叠加卷入最终构建中。其次，您可以创建一个 Buildroot 软件包，可以从菜单中选择并像其他软件包一样构建。

### 叠加

覆盖只是在构建过程的后期阶段复制到 Buildroot 根文件系统顶部的目录结构。它可以包含可执行文件、库和任何您想要包含的其他内容。请注意，任何编译的代码必须与运行时部署的库兼容，这意味着它必须使用 Buildroot 使用的相同工具链进行编译。使用 Buildroot 工具链非常容易：只需将其添加到路径中：

```
$ PATH=<path_to_buildroot>/output/host/usr/bin:$PATH

```

工具的前缀是`<ARCH>-linux-`。

覆盖目录由`BR2_ROOTFS_OVERLAY`设置，其中包含一个由空格分隔的目录列表，您应该在 Buildroot 根文件系统上覆盖它。它可以在`menuconfig`中配置，选项为**系统配置** | **根文件系统覆盖目录**。

例如，如果将`helloworld`程序添加到`bin`目录，并在启动时添加一个脚本，您将创建一个包含以下内容的覆盖目录：

![覆盖](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_06_04.jpg)

然后，您将`board/melp/nova/overlay`添加到覆盖选项中。

根文件系统的布局由`system/skeleton`目录控制，权限在`device_table_dev.txt`和`device_table.txt`中设置。

### 添加软件包

Buildroot 软件包存储在`package`目录中，有 1000 多个软件包，每个软件包都有自己的子目录。软件包至少包含两个文件：`Config.in`，其中包含使软件包在**配置**菜单中可见所需的`Kconfig`代码片段，以及名为`<package_name>.mk`的`makefile`。请注意，软件包不包含代码，只包含获取代码的指令，如下载 tarball、执行 git pull 等。

`makefile`以 Buildroot 期望的格式编写，并包含指令，允许 Buildroot 下载、配置、编译和安装程序。编写新软件包`makefile`是一个复杂的操作，在*Buildroot 用户手册*中有详细介绍。以下是一个示例，演示了如何为存储在本地的简单程序（如我们的`helloworld`程序）创建软件包。

首先创建子目录`package/helloworld`，其中包含一个名为`Config.in`的配置文件，内容如下：

```
config BR2_PACKAGE_HELLOWORLD
bool "helloworld"
help
  A friendly program that prints Hello World! every 10s
```

第一行必须是`BR2_PACKAGE_<大写软件包名称>`的格式。然后是一个布尔值和软件包名称，它将出现在**配置**菜单中，并允许用户选择此软件包。*帮助*部分是可选的（但希望有用）。

接下来，通过编辑`package/Config.in`并在前面的部分提到的源配置文件，将新软件包链接到**目标软件包**菜单中。您可以将其附加到现有子菜单中，但在这种情况下，创建一个仅包含我们软件包的新子菜单似乎更整洁：

```
menu "My programs"
  source "package/helloworld/Config.in"
endmenu
```

然后，创建一个 makefile，`package/helloworld/helloworld.mk`，以提供 Buildroot 所需的数据：

```
HELLOWORLD_VERSION:= 1.0.0
HELLOWORLD_SITE:= /home/chris/MELP/helloworld/
HELLOWORLD_SITE_METHOD:=local
HELLOWORLD_INSTALL_TARGET:=YES

define HELLOWORLD_BUILD_CMDS
  $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D) all
endef

define HELLOWORLD_INSTALL_TARGET_CMDS
  $(INSTALL) -D -m 0755 $(@D)/helloworld $(TARGET_DIR)/bin
endef

$(eval $(generic-package))
```

代码的位置被硬编码为本地路径名。在更现实的情况下，您将从源代码系统或某种中央服务器获取代码：*Buildroot 用户指南*中有如何执行此操作的详细信息，其他软件包中也有大量示例。

## 许可合规性

Buildroot 基于开源软件，它编译的软件包也是开源的。在项目的某个阶段，您应该检查许可证，可以通过运行以下命令来执行：

```
$ make legal-info

```

信息被收集到`output/legal-info`中。在`host-manifest.csv`中有用于编译主机工具的许可证摘要，在目标中有`manifest.csv`。在*Buildroot 用户手册*和`README`文件中有更多信息。

# Yocto 项目

Yocto 项目比 Buildroot 更复杂。它不仅可以像 Buildroot 一样构建工具链、引导加载程序、内核和根文件系统，还可以为您生成整个 Linux 发行版，其中包含可以在运行时安装的二进制软件包。

Yocto 项目主要是一组类似于 Buildroot 包的配方，但是使用 Python 和 shell 脚本的组合编写，并使用名为 BitBake 的任务调度程序生成你配置的任何内容。

在 [`www.yoctoproject.org/`](https://www.yoctoproject.org/) 有大量在线文档。

## 背景

Yocto 项目的结构如果你先看一下背景会更有意义。它的根源在于 OpenEmbedded，[`openembedded.org/`](http://openembedded.org/)，而 OpenEmbedded 又源自于一些项目，用于将 Linux 移植到各种手持计算机上，包括 Sharp Zaurus 和 Compaq iPaq。OpenEmbedded 于 2003 年诞生，作为这些手持计算机的构建系统，但很快扩展到包括其他嵌入式板。它是由一群热情的程序员开发并继续开发的。

OpenEmbedded 项目旨在使用紧凑的 `.ipk` 格式创建一组二进制软件包，然后可以以各种方式组合这些软件包，创建目标系统，并在运行时安装在目标上。它通过为每个软件创建配方并使用 BitBake 作为任务调度程序来实现这一点。它非常灵活。通过提供正确的元数据，你可以根据自己的规格创建整个 Linux 发行版。一个相当知名的是 *The Ångström Distribution*，[`www.angstrom-distribution.org`](http://www.angstrom-distribution.org)，但还有许多其他发行版。

在 2005 年的某个时候，当时是 OpenedHand 的开发人员 Richard Purdie 创建了 OpenEmbedded 的一个分支，选择了更保守的软件包，并创建了一段时间稳定的发布。他将其命名为 Poky，以日本小吃命名（如果你担心这些事情，Poky 的发音与 hockey 押韵）。尽管 Poky 是一个分支，但 OpenEmbedded 和 Poky 仍然并行运行，共享更新，并保持体系结构大致同步。英特尔在 2008 年收购了 OpenedHand，并在 2010 年他们成立 Yocto 项目时将 Poky Linux 转移到了 Linux 基金会。

自 2010 年以来，OpenEmbedded 和 Poky 的共同组件已经合并为一个名为 OpenEmbedded core 的独立项目，或者简称 oe-core。

因此，Yocto 项目汇集了几个组件，其中最重要的是以下内容：

+   **Poky**：参考发行版

+   **oe-core**：与 OpenEmbedded 共享的核心元数据

+   **BitBake**：任务调度程序，与 OpenEmbedded 和其他项目共享

+   **文档**：每个组件的用户手册和开发人员指南

+   **Hob**：OpenEmbedded 和 BitBake 的图形用户界面

+   **Toaster**：OpenEmbedded 和 BitBake 的基于 Web 的界面

+   **ADT Eclipse**：Eclipse 的插件，使使用 Yocto 项目 SDK 更容易构建项目

严格来说，Yocto 项目是这些子项目的总称。它使用 OpenEmbedded 作为其构建系统，并使用 Poky 作为其默认配置和参考环境。然而，人们经常使用术语“Yocto 项目”来指代仅构建系统。我觉得现在已经为时已晚，所以为了简洁起见，我也会这样做。我提前向 OpenEmbedded 的开发人员道歉。

Yocto 项目提供了一个稳定的基础，可以直接使用，也可以使用元层进行扩展，我将在本章后面讨论。许多 SoC 供应商以这种方式为其设备提供了板支持包。元层也可以用于创建扩展的或不同的构建系统。有些是开源的，比如 Angstrom 项目，另一些是商业的，比如 MontaVista Carrier Grade Edition、Mentor Embedded Linux 和 Wind River Linux。Yocto 项目有一个品牌和兼容性测试方案，以确保组件之间的互操作性。您会在各种网页上看到类似“Yocto 项目兼容 1.7”的声明。

因此，您应该将 Yocto 项目视为嵌入式 Linux 整个领域的基础，同时也是一个完整的构建系统。您可能会对*yocto*这个名字感到好奇。Yocto 是 10-24 的国际单位制前缀，就像微是 10-6 一样。为什么要给项目取名为 yocto 呢？部分原因是为了表明它可以构建非常小的 Linux 系统（尽管公平地说，其他构建系统也可以），但也可能是为了在基于 OpenEmbedded 的Ångström 发行版上取得优势。Ångström 是 10-10。与 yocto 相比，那太大了！

## 稳定版本和支持

通常，Yocto 项目每六个月发布一次，分别在 4 月和 10 月。它们主要以代号而闻名，但了解 Yocto 项目和 Poky 的版本号也是有用的。以下是我写作时最近的四个版本的表格：

| 代号 | 发布日期 | Yocto 版本 | Poky 版本 |
| --- | --- | --- | --- |
| `Fido` | 2015 年 4 月 | 1.8 | 13 |
| `Dizzy` | 2014 年 10 月 | 1.7 | 12 |
| `Daisy` | 2014 年 4 月 | 1.6 | 11 |
| `Dora` | 2013 年 10 月 | 1.5 | 10 |

稳定版本在当前发布周期和下一个周期内受到安全和关键错误修复的支持，即发布后大约 12 个月。这些更新不允许进行工具链或内核版本更改。与 Buildroot 一样，如果您希望获得持续支持，可以升级到下一个稳定版本，或者可以将更改移植到您的版本。您还可以选择从操作系统供应商（如 Mentor Graphics、Wind River 等）获得长达数年的商业支持。

## 安装 Yocto 项目

要获取 Yocto 项目的副本，您可以克隆存储库，选择代码名称作为分支，本例中为`fido`：

```
$ git clone -b fido git://git.yoctoproject.org/poky.git

```

您还可以从[`downloads.yoctoproject.org/releases/yocto/yocto-1.8/poky-fido-13.0.0.tar.bz2`](http://downloads.yoctoproject.org/releases/yocto/yocto-1.8/poky-fido-13.0.0.tar.bz2)下载存档。

在第一种情况下，您会在`poky`目录中找到所有内容，在第二种情况下，是`poky-fido-13.0.0/`。

此外，您应该阅读《Yocto 项目参考手册》（[`www.yoctoproject.org/docs/current/ref-manual/ref-manual.html#detailed-supported-distros`](http://www.yoctoproject.org/docs/current/ref-manual/ref-manual.html#detailed-supported-distros)）中标题为“系统要求”的部分，并特别确保其中列出的软件包已安装在您的主机计算机上。

## 配置

与 Buildroot 一样，让我们从 ARM QEMU 模拟器的构建开始。首先要源化一个脚本来设置环境：

```
$ cd poky
$ source oe-init-build-env

```

这将为您创建一个名为`build`的工作目录，并将其设置为当前目录。所有的配置、中间和可部署文件都将放在这个目录中。每次您想要处理这个项目时，都必须源化这个脚本。

您可以通过将其作为参数添加到`oe-init-build-env`来选择不同的工作目录，例如：

```
$ source oe-init-build-env build-qemuarm

```

这将使您进入`build-qemuarm`目录。然后，您可以同时进行几个项目：通过`oe-init-build-env`的参数选择要使用的项目。

最初，`build`目录只包含一个名为`conf`的子目录，其中包含此项目的配置文件：

+   `local.conf`：包含要构建的设备和构建环境的规范。

+   `bblayers.conf`：包含要使用的层的目录列表。稍后将会有更多关于层的内容。

+   `templateconf.cfg`：包含一个包含各种`conf`文件的目录的名称。默认情况下，它指向`meta-yocto/conf`。

现在，我们只需要在`local.conf`中将`MACHINE`变量设置为`qemuarm`，方法是删除此行开头的注释字符：

```
MACHINE ?= "qemuarm"
```

## 构建

要实际执行构建，需要运行`bitbake`，告诉它要创建哪个根文件系统镜像。一些常见的图像如下：

+   核心图像-最小：一个小型的基于控制台的系统，对于测试和作为自定义图像的基础很有用。

+   核心图像-最小 initramfs：类似于核心图像-最小，但构建为 ramdisk。

+   核心图像-x11：通过 X11 服务器和 xterminal 终端应用程序支持图形的基本图像。

+   核心图像-sato：基于 Sato 的完整图形系统，Sato 是基于 X11 和 GNOME 构建的移动图形环境。图像包括几个应用程序，包括终端、编辑器和文件管理器。

通过给 BitBake 最终目标，它将向后工作，并首先构建所有依赖项，从工具链开始。现在，我们只想创建一个最小的图像来查看它是否有效：

```
$ bitbake core-image-minimal

```

构建可能需要一些时间，可能超过一个小时。完成后，您将在构建目录中找到几个新目录，包括`build/downloads`，其中包含构建所需的所有源文件，以及`build/tmp`，其中包含大部分构建产物。您应该在`tmp`中看到以下内容：

+   `work`：包含构建目录和所有组件的分段区域，包括根文件系统

+   `deploy`：包含要部署到目标上的最终二进制文件：

+   `deploy/images/[机器名称]`：包含引导加载程序、内核和根文件系统镜像，准备在目标上运行

+   `deploy/rpm`：包含组成图像的 RPM 软件包

+   `deploy/licenses`：包含从每个软件包中提取的许可文件

## 运行

当构建 QEMU 目标时，将生成一个内部版本的 QEMU，从而无需安装 QEMU 软件包以避免版本依赖。有一个名为`runqemu`的包装脚本用于这个内部 QEMU。

要运行 QEMU 仿真，请确保已经源自`oe-init-build-env`，然后只需键入：

```
$ runqemu qemuarm

```

在这种情况下，QEMU 已配置为具有图形控制台，因此启动消息和登录提示将显示在黑色帧缓冲屏幕上：

![运行中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_06_03.jpg)

您可以以`root`身份登录，无需密码。您可以通过关闭帧缓冲窗口关闭 QEMU。您可以通过在命令行中添加`nographic`来启动不带图形窗口的 QEMU：

```
$ runqemu qemuarm nographic

```

在这种情况下，使用键序*Ctrl* + *A* + *X*关闭 QEMU。

`runqemu`脚本有许多其他选项，键入`runqemu help`以获取更多信息。

## 层

Yocto 项目的元数据按层结构化，按照惯例，每个层的名称都以`meta`开头。Yocto 项目的核心层如下：

+   元：这是 OpenEmbedded 核心

+   meta-yocto：特定于 Yocto 项目的元数据，包括 Poky 发行版

+   meta-yocto-bsp：包含 Yocto 项目支持的参考机器的板支持软件包

BitBake 搜索配方的层列表存储在`<your build directory>/conf/bblayers.conf`中，并且默认情况下包括前面列表中提到的所有三个层。

通过以这种方式构建配方和其他配置数据，很容易通过添加新的层来扩展 Yocto 项目。额外的层可以从 SoC 制造商、Yocto 项目本身以及希望为 Yocto 项目和 OpenEmbedded 增加价值的广泛人员那里获得。在[`layers.openembedded.org`](http://layers.openembedded.org)上有一个有用的层列表。以下是一些示例：

+   **meta-angstrom**：Ångström 发行版

+   **meta-qt5**：Qt5 库和实用程序

+   **meta-fsl-arm**：Freescale 基于 ARM 的 SoC 的 BSP

+   **meta-fsl-ppc**：Freescale 基于 PowerPC 的 SoC 的 BSP

+   **meta-intel**：Intel CPU 和 SoC 的 BSP

+   **meta-ti**：TI 基于 ARM 的 SoC 的 BSP

添加一个层就像将 meta 目录复制到合适的位置一样简单，通常是在默认的 meta 层旁边，并将其添加到`bblayers.conf`中。只需确保它与您正在使用的 Yocto 项目版本兼容即可。

为了说明层的工作原理，让我们为我们的 Nova 板创建一个层，我们可以在本章的其余部分中使用它来添加功能。每个元层必须至少有一个配置文件`conf/layer.conf`，还应该有一个`README`文件和一个许可证。有一个方便的辅助脚本可以为我们完成基本工作：

```
$ cd poky
$ scripts/yocto-layer create nova

```

脚本会要求设置优先级，以及是否要创建示例配方。在这个示例中，我只接受了默认值：

```
Please enter the layer priority you'd like to use for the layer: [default: 6]
Would you like to have an example recipe created? (y/n) [default: n]
Would you like to have an example bbappend file created? (y/n) [default: n]
New layer created in meta-nova.
Don't forget to add it to your BBLAYERS (for details see meta-nova\README).

```

这将创建一个名为`meta-nova`的层，其中包含`conf/layer.conf`、概要`README`和`COPYING.MIT`中的 MIT 许可证。`layer.conf`文件如下所示：

```
# We have a conf and classes directory, add to BBPATH
BBPATH .= ":${LAYERDIR}"

# We have recipes-* directories, add to BBFILES
BBFILES += "${LAYERDIR}/recipes-*/*/*.bb \
${LAYERDIR}/recipes-*/*/*.bbappend"

BBFILE_COLLECTIONS += "nova"
BBFILE_PATTERN_nova = "^${LAYERDIR}/"
BBFILE_PRIORITY_nova = "6"
```

它将自己添加到`BBPATH`，并将其包含的配方添加到`BBFILES`。通过查看代码，您可以看到配方位于以`recipes-`开头的目录中，并且文件名以`.bb`结尾（用于普通 BitBake 配方），或以`.bbappend`结尾（用于通过添加和覆盖指令扩展现有普通配方的配方）。此层的名称为`nova`，它被添加到`BBFILE_COLLECTIONS`中的层列表中，并且具有优先级`6`。如果相同的配方出现在几个层中，则具有最高优先级的层中的配方获胜。

由于您即将构建一个新的配置，最好从创建一个名为`build-nova`的新构建目录开始：

```
$ cd ~/poky
$ . oe-init-build-env build-nova

```

现在，您需要将此层添加到您的构建配置中，`conf/bblayers.conf`：

```
LCONF_VERSION = "6"

BBPATH = "${TOPDIR}"
BBFILES ?= ""

BBLAYERS ?= " \
  /home/chris/poky/meta \
  /home/chris/poky/meta-yocto \
  /home/chris/poky/meta-yocto-bsp \
 /home/chris/poky/meta-nova \
  "
BBLAYERS_NON_REMOVABLE ?= " \
  /home/chris/poky/meta \
  /home/chris/poky/meta-yocto \"
```

您可以使用另一个辅助脚本确认它是否设置正确：

```
$ bitbake-layers show-layers
layer                 path                     priority
==========================================================
meta              /home/chris/poky/meta            5
meta-yocto        /home/chris/poky/meta-yocto      5
meta-yocto-bsp    /home/chris/poky/meta-yocto-bsp  5
meta-nova         /home/chris/poky/meta-nova       6

```

在那里，您可以看到新的层。它的优先级为`6`，这意味着我们可以覆盖具有较低优先级的其他层中的配方。

此时运行一个构建，使用这个空层是一个好主意。最终目标将是 Nova 板，但是现在，通过在`conf/local.conf`中的`MACHINE ?= "beaglebone"`之前去掉注释，为 BeagelBone Black 构建一个小型镜像。然后，使用`bitbake core-image-minimal`构建一个小型镜像。

除了配方，层还可以包含 BitBake 类、机器的配置文件、发行版等。接下来我将看一下配方，并向您展示如何创建自定义镜像以及如何创建软件包。

### BitBake 和配方

BitBake 处理几种不同类型的元数据，包括以下内容：

+   **recipes**：以`.bb`结尾的文件。这些文件包含有关构建软件单元的信息，包括如何获取源代码副本、对其他组件的依赖关系以及如何构建和安装它。

+   **append**：以`.bbappend`结尾的文件。这些文件允许覆盖或扩展配方的一些细节。`A.bbappend`文件只是将其指令附加到具有相同根名称的配方（`.bb`）文件的末尾。

+   **包括**：以`.inc`结尾的文件。这些文件包含多个食谱共有的信息，允许信息在它们之间共享。可以使用`include`或`require`关键字来包含这些文件。不同之处在于，如果文件不存在，`require`会产生错误，而`include`不会。

+   **类**：以`.bbclass`结尾的文件。这些文件包含常见的构建信息，例如如何构建内核或如何构建`autotools`项目。这些类在食谱和其他类中使用`inherit`关键字进行继承和扩展。`classes/base.bbclass`类在每个食谱中都会被隐式继承。

+   **配置**：以`.conf`结尾的文件。它们定义了管理项目构建过程的各种配置变量。

食谱是一组以 Python 和 shell 代码的组合编写的任务。任务的名称如`do_fetch`、`do_unpack`、`do_patch`、`do_configure`、`do_compile`、`do_install`等。您可以使用 BitBake 来执行这些任务。

默认任务是`do_build`，因此您正在运行该食谱的构建任务。您可以通过像这样运行`bitbake core-image-minimal`来列出食谱中可用的任务：

```
$ bitbake -c listtasks core-image-minimal

```

`-c`选项允许您指定任务，省略`do_`部分。一个常见的用法是`-c fetch`来获取一个食谱所需的代码：

```
$ bitbake -c fetch busybox

```

您还可以使用`fetchall`来获取目标代码和所有依赖项的代码：

```
$ bitbake -c fetchall core-image-minimal

```

食谱文件通常被命名为`<package-name>_version.bb`。它们可能依赖于其他食谱，这将允许 BitBake 计算出需要执行的所有子任务，以完成顶层作业。不幸的是，我在这本书中没有空间来描述依赖机制，但您将在 Yocto Project 文档中找到完整的描述。

例如，要在`meta-nova`中为我们的`helloworld`程序创建一个食谱，您可以创建以下目录结构：

```
meta-nova/recipes-local/helloworld
├── files
│   └── helloworld.c
└── helloworld_1.0.bb
```

食谱是`helloworld_1.0.bb`，源代码是食谱目录中子目录文件的本地文件。食谱包含这些说明：

```
DESCRIPTION = "A friendly program that prints Hello World!"
PRIORITY = "optional"
SECTION = "examples"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0;md5=801f80980d171dd6425610833a22dbe6"

SRC_URI = "file://helloworld.c"
S = "${WORKDIR}"

do_compile() {
  ${CC} ${CFLAGS} -o helloworld helloworld.c
}

do_install() {
  install -d ${D}${bindir}
  install -m 0755 helloworld ${D}${bindir}
}
```

源代码的位置由`SRC_URI`设置：在这种情况下，它将在食谱目录中搜索目录、文件、`helloworld`和`helloworld-1.0`。唯一需要定义的任务是`do_compile`和`do_install`，它们简单地编译一个源文件并将其安装到目标根文件系统中：`${D}`扩展到目标设备的分段区域，`${bindir}`扩展到默认的二进制目录`/usr/bin`。

每个食谱都有一个许可证，由`LICENSE`定义，这里设置为`GPLv2`。包含许可证文本和校验和的文件由`LIC_FILES_CHKSUM`定义。如果校验和不匹配，BitBake 将终止构建，表示许可证以某种方式发生了变化。许可证文件可能是软件包的一部分，也可能指向`meta/files/common-licenses`中的标准许可证文本之一，就像这里一样。

默认情况下，商业许可证是不允许的，但很容易启用它们。您需要在食谱中指定许可证，如下所示：

```
LICENSE_FLAGS = "commercial"
```

然后，在您的`conf/local.conf`中，您可以明确允许此许可证，如下所示：

```
LICENSE_FLAGS_WHITELIST = "commercial"
```

为了确保它编译正确，您可以要求 BitBake 构建它，如下所示：

```
$ bitbake  helloworld

```

如果一切顺利，您应该看到它已经在`tmp/work/cortexa8hf-vfp-neon-poky-linux-gnueabi/helloworld/`中为其创建了一个工作目录。

您还应该看到`tmp/deploy/rpm/cortexa8hf_vfp_neon/helloworld-1.0-r0.cortexa8hf_vfp_neon.rpm`中有一个 RPM 软件包。

尽管如此，它还不是目标镜像的一部分。要安装的软件包列表保存在名为`IMAGE_INSTALL`的变量中。您可以通过将此行添加到您的`conf/local.conf`中的列表末尾来追加到该列表：

```
IMAGE_INSTALL_append = " helloworld"
```

请注意，第一个双引号和第一个软件包名称之间必须有一个空格。现在，该软件包将被添加到您 bitbake 的任何镜像中：

```
$ bitbake core-image-minimal

```

如果您查看`tmp/deploy/images/beaglebone/core-image-minimal-beaglebone.tar.bz2`，您将看到确实已安装`/usr/bin/helloworld`。

## 通过 local.conf 自定义图像

您可能经常希望在开发过程中向图像添加软件包或以其他方式进行微调。如前所示，您可以通过添加类似以下语句来简单地追加要安装的软件包列表：

```
IMAGE_INSTALL_append = " strace helloworld"
```

毫无疑问，您也可以做相反的事情：可以使用以下语法删除软件包：

```
IMAGE_INSTALL_remove = "someapp"
```

您可以通过`EXTRA_IMAGE_FEATURES`进行更广泛的更改。这里列不完，我建议您查看*Yocto Project 参考手册*的*图像功能*部分和`meta/classes/core-image.bbclass`中的代码。以下是一个简短的列表，应该可以让您了解可以启用的功能：

+   `dbg-pkgs`：为图像中安装的所有软件包安装调试符号包。

+   `debug-tweaks`：允许无密码进行 root 登录和其他使开发更容易的更改。

+   `package-management`：安装软件包管理工具并保留软件包管理器数据库。

+   `read-only-rootfs`：使根文件系统只读。我们将在第七章中详细介绍这一点，*创建存储策略*。

+   `x11`：安装 X 服务器。

+   `x11-base`：安装带有最小环境的 X 服务器。

+   `x11-sato`：安装 OpenedHand Sato 环境。

## 编写图像配方

对`local.conf`进行更改的问题在于它们是本地的。如果您想创建一个要与其他开发人员共享或加载到生产系统的图像，那么您应该将更改放入图像配方中。

图像配方包含有关如何为目标创建图像文件的指令，包括引导加载程序、内核和根文件系统映像。您可以使用此命令获取可用图像的列表：

```
$ ls meta*/recipes*/images/*.bb

```

`core-image-minimal`的配方位于`meta/recipes-core/images/core-image-minimal.bb`中。

一个简单的方法是使用类似于在`local.conf`中使用的语句来获取现有的图像配方并进行修改。

例如，假设您想要一个与`core-image-minimal`相同的图像，但包括您的`helloworld`程序和`strace`实用程序。您可以使用一个两行的配方文件来实现这一点，该文件包括（使用`require`关键字）基本图像并添加您想要的软件包。将图像放在名为`images`的目录中是传统的做法，因此在`meta-nova/recipes-local/images`中添加具有以下内容的配方`nova-image.bb`：

```
require recipes-core/images/core-image-minimal.bb
IMAGE_INSTALL += "helloworld strace"
```

现在，您可以从`local.conf`中删除`IMAGE_INSTALL_append`行，并使用以下命令构建它：

```
$ bitbake nova-image

```

如果您想进一步控制根文件系统的内容，可以从空的`IMAGE_INSTALL`变量开始，并像这样填充它：

```
SUMMARY = "A small image with helloworld and strace packages" IMAGE_INSTALL = "packagegroup-core-boot helloworld strace"
IMAGE_LINGUAS = " "
LICENSE = "MIT"
IMAGE_ROOTFS_SIZE ?= "8192"
inherit core-image
```

`IMAGE_LINGUAS`包含要在目标图像中安装的`glibc`区域设置的列表。它们可能占用大量空间，因此在这种情况下，我们将列表设置为空，只要我们不需要区域设置相关的库函数就可以了。`IMAGE_ROOTFS_SIZE`是生成的磁盘映像的大小，以 KiB 为单位。大部分工作由我们在最后继承的`core-image`类完成。

## 创建 SDK

能够创建一个其他开发人员可以安装的独立工具链非常有用，避免了团队中每个人都需要完整安装 Yocto Project 的需求。理想情况下，您希望工具链包括目标上安装的所有库的开发库和头文件。您可以使用`populate_sdk`任务为任何图像执行此操作，如下所示：

```
$ bitbake nova-image -c populate_sdk

```

结果是一个名为`tmp/deploy/sdk`中的自安装 shell 脚本：

```
poky-<c_library>-<host_machine>-<target_image><target_machine>-toolchain-<version>.sh
```

这是一个例子：

```
poky-glibc-x86_64-nova-image-cortexa8hf-vfp-neon-toolchain-1.8.1.sh
```

请注意，默认情况下，工具链不包括静态库。您可以通过向`local.conf`或图像配方添加类似以下行来单独启用它们：

```
TOOLCHAIN_TARGET_TASK_append = " glibc-staticdev"
```

您也可以像下面这样全局启用它们：

```
SDKIMAGE_FEATURES_append = " staticdev-pkgs"
```

如果您只想要一个基本的工具链，只需 C 和 C++交叉编译器，C 库和头文件，您可以运行：

```
$ bitbake meta-toolchain

```

要安装 SDK，只需运行 shell 脚本。默认安装目录是`/opt/poky`，但安装脚本允许您更改：

```
$ tmp/deploy/sdk/poky-glibc-x86_64-nova-image-cortexa8hf-vfp-neon-toolchain-1.8.1.sh

Enter target directory for SDK (default: /opt/poky/1.8.1):

You are about to install the SDK to "/opt/poky/1.8.1". Proceed[Y/n]?

[sudo] password for chris:

Extracting SDK...done

Setting it up...done

SDK has been successfully set up and is ready to be used.

```

要使用工具链，首先要源环境设置脚本：

```
. /opt/poky/1.8.1/environment-setup-cortexa8hf-vfp-neon-poky-linux-gnueabi

```

以这种方式生成的工具链未配置有效的`sysroot`：

```
$ arm-poky-linux-gnueabi-gcc -print-sysroot

/not/exist

```

因此，如果您尝试像我在之前的章节中所示的那样进行交叉编译，它将失败，如下所示：

```
$ arm-poky-linux-gnueabi-gcc helloworld.c -o helloworld

helloworld.c:1:19: fatal error: stdio.h: No such file or directory

#include <stdio.h>

 ^

compilation terminated.

```

这是因为编译器已配置为通用于广泛范围的 ARM 处理器，当您使用正确的一组`gcc`标志启动它时，微调就完成了。只要使用`$CC`进行编译，一切都应该正常工作：

```
$ $CC helloworld.c -o helloworld

```

## 许可审计

Yocto Project 要求每个软件包都有许可证。每个软件包构建时，许可证的副本位于`tmp/deploy/licenses/[packagenam.e]`中。此外，图像中使用的软件包和许可证的摘要位于`<image name>-<machine name>-<date stamp>`目录中。如下所示：

```
$ ls tmp/deploy/licenses/nova-image-beaglebone-20151104150124
license.manifest  package.manifest

```

第一个文件列出了每个软件包使用的许可证，第二个文件只列出了软件包名称。

# 进一步阅读

您可以查看以下文档以获取更多信息：

+   《Buildroot 用户手册》，[`buildroot.org/downloads/manual/manual.html`](http://buildroot.org/downloads/manual/manual.html)

+   Yocto Project 文档：有九个参考指南，还有一个由其他指南组合而成的第十个（所谓的“Mega-manual”），网址为[`www.yoctoproject.org/documentation`](https://www.yoctoproject.org/documentation)

+   《即时 Buildroot》，作者 Daniel Manchón Vizuete，Packt Publishing，2013

+   《使用 Yocto Project 进行嵌入式 Linux 开发》，作者 Otavio Salvador 和 Daianne Angolini，Packt Publishing，2014

# 摘要

使用构建系统可以减轻创建嵌入式 Linux 系统的工作量，通常比手工打造自己的系统要好得多。如今有一系列开源构建系统可用：Buildroot 和 Yocto Project 代表了两种不同的方法。Buildroot 简单快速，适用于相当简单的单用途设备：我喜欢称之为传统嵌入式 Linux。

Yocto Project 更加复杂和灵活。它是基于软件包的，这意味着您可以选择安装软件包管理器，并在现场对单个软件包进行更新。元层结构使得扩展元数据变得容易，社区和行业对 Yocto Project 的支持非常好。缺点是学习曲线非常陡峭：您应该期望需要几个月的时间才能熟练掌握它，即使那样，它有时也会做出您意想不到的事情，至少这是我的经验。

不要忘记，使用这些工具创建的任何设备都需要在现场维护一段时间，通常是多年。Yocto Project 将在发布后约一年提供点发布，Buildroot 通常不提供任何点发布。在任何情况下，您都会发现自己必须自行维护您的发布，否则需要支付商业支持费用。第三种可能性，忽视这个问题，不应被视为一个选择！

在下一章中，我将讨论文件存储和文件系统，以及您在那里做出的选择将如何影响嵌入式 Linux 的稳定性和可维护性。
