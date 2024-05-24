# 使用 Yocto 项目学习 Linux 嵌入式编程（一）

> 原文：[`zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910`](https://zh.annas-archive.org/md5/6A5B9E508EC2401ECE20C211D2D71910)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

关于当今的 Linux 环境，本书中解释的大多数主题已经可用并且有详细的介绍。本书还涵盖了大量信息，并帮助创建许多观点。当然，本书中还介绍了一些关于各种主题的很好的书籍，并在这里，您将找到对它们的引用。然而，本书的范围并不是再次呈现这些信息，而是在传统的嵌入式开发过程中与 Yocto 项目使用的方法之间进行对比。

本书还介绍了您在嵌入式 Linux 中可能遇到的各种挑战，并为其提出了解决方案。尽管本书旨在面向对其基本 Yocto 和 Linux 技能相当自信并试图改进它们的开发人员，但我相信那些在这个领域没有真正经验的人也可以在这里找到一些有用的信息。

本书围绕您在嵌入式 Linux 之旅中会遇到的各种重要主题构建而成。除此之外，还向您提供了技术信息和许多练习，以确保尽可能多地向您传递信息。在本书结束时，您应该对 Linux 生态系统有一个清晰的认识。

# 本书涵盖的内容

第一章，“介绍”，试图呈现嵌入式 Linux 软件和硬件架构的样子。它还向您介绍了 Linux 和 Yocto 的好处，并提供了示例。它解释了 Yocto 项目的架构以及它是如何集成到 Linux 环境中的。

第二章，“交叉编译”，为您提供了工具链的定义、其组件以及获取方式。之后，向您提供了有关 Poky 存储库的信息，并与组件进行了比较。

第三章，“引导加载程序”，为您提供了引导顺序、U-Boot 引导加载程序以及如何为特定板构建它的信息。之后，它提供了从 Poky 获取 U-Boot 配方的访问权限，并展示了它的使用方法。

第四章，“Linux 内核”，解释了 Linux 内核和源代码的特性。它为您提供了构建内核源代码和模块的信息，然后继续解释 Yocto 内核的配方，并展示了内核引导后发生的相同事情。

第五章，“Linux 根文件系统”，为您提供了有关根文件系统目录和设备驱动程序的组织的信息。它解释了各种文件系统、BusyBox 以及最小文件系统应包含的内容。它将向您展示如何在 Yocto 项目内外编译 BusyBox，以及如何使用 Poky 获取根文件系统。

第六章，“Yocto 项目的组件”，概述了 Yocto 项目的可用组件，其中大部分在 Poky 之外。它提供了每个组件的简介和简要介绍。在本章之后，这些组件中的一些将被更详细地解释。

第七章，“ADT Eclipse 插件”，展示了如何设置 Yocto 项目 Eclipse IDE，为交叉开发和使用 Qemu 进行调试进行设置，并自定义图像并与不同工具进行交互。

第八章，“Hob，Toaster 和 Autobuilder”，介绍了这些工具的每一个，并解释了它们各自的用途，提到了它们的好处。

第九章, *Wic 和其他工具*，解释了如何使用另一组工具，这些工具与前一章提到的工具非常不同。

第十章, *实时*，展示了 Yocto Project 的实时层，它们的目的和附加值。还提供了有关 Preempt-RT、NoHz、用户空间 RTOS、基准测试和其他实时相关功能的文档信息。

第十一章, *安全*，解释了 Yocto Project 的安全相关层，它们的目的以及它们如何为 Poky 增加价值。在这里，您还将获得有关 SELinux 和其他应用程序的信息，例如 bastille、buck-security、nmap 等。

第十二章, *虚拟化*，解释了 Yocto Project 的虚拟化层，它们的目的以及它们如何为 Poky 增加价值。您还将获得有关虚拟化相关软件包和倡议的信息。

第十三章, *CGL 和 LSB*，为您提供了 Carrier Graded Linux (CGL)的规范和要求的信息，以及 Linux Standard Base (LSB)的规范、要求和测试。最后，将与 Yocto Project 提供的支持进行对比。

# 阅读本书需要什么

在阅读本书之前，对嵌入式 Linux 和 Yocto 的先验知识将会有所帮助，尽管不是强制性的。在本书中，有许多练习可供选择，为了完成这些练习，对 GNU/Linux 环境的基本理解将会很有用。此外，一些练习是针对特定的开发板，另一些涉及使用 Qemu。拥有这样的开发板和对 Qemu 的先验知识是一个加分项，但不是强制性的。

在整本书中，有一些章节包含各种练习，需要读者已经具备 C 语言、Python 和 Shell 脚本的知识。如果读者在这些领域有经验，那将会很有帮助，因为它们是当今大多数 Linux 项目中使用的核心技术。我希望这些信息不会在阅读本书内容时让您感到沮丧，希望您会喜欢它。

# 这本书是为谁准备的

这本书是针对 Yocto 和 Linux 爱好者的，他们想要构建嵌入式 Linux 系统，也许还想为社区做出贡献。背景知识应该包括 C 编程技能，以及将 Linux 作为开发平台的经验，对软件开发流程有基本的了解。如果您之前阅读过《使用 Yocto Project 进行嵌入式 Linux 开发》，那也是一个加分项。

看一下技术趋势，Linux 是下一个大事件。它提供了访问尖端开源产品的机会，每天都有更多的嵌入式系统投入使用。Yocto Project 是与嵌入式设备交互的任何项目的最佳选择，因为它提供了丰富的工具集，帮助您将大部分精力和资源投入到产品开发中，而不是重新发明。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下: "一个`maintainers`文件提供了特定板支持的贡献者列表。"

代码块设置如下:

```
sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
sudo apt-get update
sudo add-apt-repository "deb http://people.linaro.org/~neil.williams/lava jessie main"
sudo apt-get update

sudo apt-get install postgresql
sudo apt-get install lava
sudo a2dissite 000-default
sudo a2ensite lava-server.conf
sudo service apache2 restart
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示:

```
sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
sudo apt-get update
sudo add-apt-repository "deb http://people.linaro.org/~neil.williams/lava jessie main"
sudo apt-get update

sudo apt-get install postgresql
sudo apt-get install lava
sudo a2dissite 000-default
sudo a2ensite lava-server.conf
sudo service apache2 restart
```

任何命令行输入或输出都将按照以下格式编写：

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如在菜单或对话框中，会以这种方式出现在文本中："如果出现此警告消息，请按**确定**并继续"

### 注意

警告或重要说明会以这种方式出现在框中。

### 提示

技巧和窍门会以这种方式出现。

# 读者反馈

我们的读者的反馈总是受欢迎的。让我们知道您对本书的看法——您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发您真正能够充分利用的标题。

要向我们发送一般反馈，只需简单地发送电子邮件`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误部分下的任何现有勘误列表中。

要查看先前提交的勘误，请转到[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索字段中输入书名。所需信息将出现在**勘误**部分下。

## 盗版

在互联网上盗版受版权保护的材料是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们为您提供有价值的内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：介绍

在本章中，您将了解 Linux 和开源开发的优势。将介绍运行嵌入式 Linux 的系统的示例，许多嵌入式硬件平台都支持。之后，您将介绍嵌入式 Linux 系统的架构和开发环境，最后介绍 Yocto 项目，总结其 Poky 构建系统的属性和目的。

# Linux 和开源系统的优势

本书中大部分可获得的信息和作为练习呈现的示例有一个共同点：它们都是任何人都可以自由访问的。本书试图为您提供如何与现有的和免费可用的软件包进行交互的指导，这些软件包可以帮助像您这样的嵌入式工程师，并且同时也试图激发您的好奇心，让您学到更多。

### 注

有关开源的更多信息可以从**开源倡议**（**OSI**）[`opensource.org/`](http://opensource.org/)获取。

开源的主要优势在于它允许开发人员更专注于他们的产品和附加值。拥有开源产品可以获得各种新的可能性和机会，比如减少许可成本、增加公司的技能和知识。使用大多数人都可以访问并理解其工作原理的开源产品意味着预算节省。节省下来的资金可以用于其他部门，比如硬件或收购。

通常，人们对开源产品有很少或没有控制权的误解。然而，事实恰恰相反。开源系统一般来说提供了对软件的完全控制，我们将证明这一点。对于任何软件，您的开源项目都驻留在一个允许每个人查看的存储库中。由于您是项目的负责人，也是其管理员，您有权接受他人的贡献，这使他们和您拥有同样的权利，基本上给了您想做任何事情的自由。当然，可能会有人受到您的项目的启发，做出了开源社区更受欢迎的事情。然而，这就是进步的方式，坦率地说，如果您是一家公司，这种情况几乎是无效的。即使在这种情况下，这种情况也并不意味着您的项目的失败，而是一个机会。在这里，我想引用以下引用：

|   | *"如果你想建立一个开源项目，你不能让自己的自尊挡住你的路。你不能重写每个人的补丁，你不能对每个人进行第二次猜测，你必须给人们平等的控制权。"* |   |
| --- | --- | --- |
|   | --*– Rasmus Lerdorf* |

允许他人访问、获得外部帮助、对您的开源软件进行修改、调试和优化意味着产品的寿命更长，随着时间的推移，质量也得到了提高。同时，开源环境提供了各种组件的访问，如果需要，这些组件可以轻松地集成到您的产品中。这可以实现快速的开发过程，降低成本，并且还可以将大部分的维护和开发工作从您的产品中转移出去。此外，它还提供了支持特定组件的可能性，以确保它继续满足您的需求。然而，在大多数情况下，您需要花一些时间从零开始为您的产品构建这个组件。

这将我们带到开源的下一个好处，涉及我们产品的测试和质量保证。除了测试所需的工作量较少之外，还可以在决定哪个组件最适合我们的产品之前从多个选项中进行选择。此外，使用开源软件比购买和评估专有产品更便宜。这种接受和回馈的过程，在开源社区中可见，是产生更高质量和更成熟产品的过程。这种质量甚至比其他专有或闭源类似产品的质量更高。当然，这并不是一个普遍有效的断言，只发生在成熟和广泛使用的产品上，但在这里出现了社区和基金会这个术语。

一般来说，开源软件是由开发人员和用户社区共同开发的。这个系统提供了直接从开发人员那里获得更大支持的机会——这在使用闭源工具时是不会发生的。此外，无论您是为公司工作与否，寻找问题答案时都没有限制。成为开源社区的一部分意味着不仅仅是修复错误、报告错误或开发功能。它是开发人员所做的贡献，但同时也为工程师提供了在工作环境之外获得认可的可能性，面对新挑战并尝试新事物。它也可以被视为一个巨大的激励因素和所有参与过程的灵感来源。

作为结论，我还想引用这个过程的核心人物的一句话，他给了我们 Linux 并使其保持开源：

|   | *"我认为，从根本上讲，开源软件确实更稳定。这是正确的做事方式。"* |   |
| --- | --- | --- |
|   | --*– Linus Torvalds* |

# 嵌入式系统

既然开源的好处已经向您介绍了，我相信我们可以通过一些嵌入式系统、硬件、软件及其组件的例子。首先，嵌入式设备随处可见：看看您的智能手机、汽车信息娱乐系统、微波炉甚至您的 MP3 播放器。当然，并非所有这些都符合 Linux 操作系统的要求，但它们都有嵌入式组件，使它们能够实现其设计功能。

## 一般描述

要在任何设备硬件上运行 Linux，您将需要一些能够将硬件相关组件抽象为硬件无关组件的硬件相关组件。引导加载程序、内核和工具链包含使所有其他组件的工作更容易的硬件相关组件。例如，BusyBox 开发人员只会专注于为他的应用程序开发所需的功能，而不会专注于硬件兼容性。所有这些硬件相关组件都支持 32 位和 64 位的各种硬件架构。例如，U-Boot 实现是最容易作为源代码检查的例子。从中，我们可以很容易地想象如何添加对新设备的支持。

我们现在将尝试做一些之前介绍的小练习，但在继续之前，我必须介绍我将继续进行练习的计算机配置，以确保您尽可能少遇到问题。我正在使用 Ubuntu 14.04，并已从 Ubuntu 网站[`www.ubuntu.com/download/desktop`](http://www.ubuntu.com/download/desktop)下载了 64 位镜像。

使用此命令可以收集有关在计算机上运行的 Linux 操作的信息：

```
uname –srmpio

```

前面的命令生成了这个输出：

```
Linux 3.13.0-36-generic x86_64 x86_64 x86_64 GNU/Linux

```

收集与 Linux 操作相关的信息的下一个命令如下：

```
cat /etc/lsb-release

```

前面的命令生成了这个输出：

```
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"

```

## 例子

现在，转到练习，第一个要求您获取 U-Boot 软件包的`git`存储库源代码：

```
sudo apt-get install git-core
git clone http://git.denx.de/u-boot.git

```

在您的机器上可用源代码之后，您可以尝试查看`board`目录内部；在这里，将出现许多开发板制造商。让我们看看`board/atmel/sama5d3_xplained`，`board/faraday/a320evb`，`board/freescale/imx`和`board/freescale/b4860qds`。通过观察这些目录，可以看到一种模式。几乎所有的板都包含一个`Kconfig`文件，主要受到内核源的启发，因为它们以更清晰的方式呈现配置依赖关系。一个`maintainers`文件提供了对特定板支持的贡献者列表。基本的`Makefile`文件从更高级别的 makefiles 中获取必要的对象文件，这些对象文件是在构建特定板支持后获得的。与`board/freescale/imx`的区别在于，它只提供了一个配置数据列表，这些数据将在高级别 makefiles 中使用。

在内核级别，硬件相关的支持添加到`arch`文件中。在这里，除了`Makefile`和`Kconfig`之外，还可以添加各种数量的子目录。这些子目录为内核的不同方面提供支持，例如引导、内核、内存管理或特定应用程序。

通过克隆内核源代码，可以使用以下代码轻松可视化前面的信息：

```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

```

一些可以可视化的目录是`arch`/`arc`和`arch`/`metag`。

从工具链的角度来看，硬件相关的组件由 GNU C 库表示，通常由`glibc`表示。这提供了系统调用接口，连接到内核架构相关的代码，并进一步为用户应用程序提供这两个实体之间的通信机制。如果克隆了`glibc`源代码，系统调用将显示在`glibc`源代码的`sysdeps`目录中，如下所示：

```
git clone http://sourceware.org/git/glibc.git

```

可以使用两种方法验证前面的信息：第一种方法涉及打开`sysdeps/arm`目录，例如，或者阅读`ChangeLog.old-ports-arm`库。尽管它已经过时，且存在不存在的链接，比如从存储库的新版本中消失的 ports 目录，但后者仍然可以用作参考点。

这些软件包也可以通过 Yocto 项目的`poky`存储库非常容易地访问。如[`www.yoctoproject.org/about`](https://www.yoctoproject.org/about)所述：

> “Yocto 项目是一个开源协作项目，提供模板、工具和方法，帮助您创建嵌入式产品的自定义 Linux 系统，无论硬件架构如何。它成立于 2010 年，是许多硬件制造商、开源操作系统供应商和电子公司之间的合作，旨在为嵌入式 Linux 开发的混乱带来一些秩序。”

与 Yocto 项目的大多数交互都是通过 Poky 构建系统完成的，这是其核心组件之一，提供了生成完全可定制的 Linux 软件堆栈所需的功能和功能。确保与存储库源进行交互的第一步是克隆它们：

```
git clone -b dizzy http://git.yoctoproject.org/git/poky

```

在您的计算机上存在源代码之后，需要检查一组配方和配置文件。可以检查的第一个位置是 U-Boot 配方，位于`meta/recipes-bsp/u-boot/u-boot_2013.07.bb`。它包含构建相应选定机器的 U-Boot 软件包所需的指令。下一个要检查的地方是内核中可用的配方。在这里，工作是稀疏的，有更多的软件包版本可用。它还为可用的配方提供了一些`bbappends`，例如`meta/recipes-kernel/linux/linux-yocto_3.14.bb`和`meta-yocto-bsp/recipes-kernel/linux/linux-yocto_3.10.bbappend`。这构成了使用 BitBake 开始新构建时可用的内核软件包版本的一个很好的例子。

工具链的构建对于主机生成的软件包来说是一个重要的步骤。为此，需要一组软件包，如`gcc`、`binutils`、`glibc`库和`内核头文件`，它们起着重要的作用。对应于这些软件包的配方可在`meta/recipes-devtools/gcc/`、`meta/recipes-devtools/binutils`和`meta/recipes-core/glibc`路径中找到。在所有可用的位置，都可以找到大量的配方，每个配方都有特定的目的。这些信息将在下一章中详细介绍。

选择一个软件包版本而不是另一个的配置和选项主要添加在机器配置中。一个这样的例子是 Yocto 1.6 支持的 Freescale `MPC8315E-rdb`低功耗型号，其机器配置可在`meta-yocto-bsp/conf/machine/mpc8315e-rdb.conf`文件中找到。

### 注意

有关此开发板的更多信息，请访问[`www.freescale.com/webapp/sps/site/prod_summary.jsp?code=MPC8315E`](http://www.freescale.com/webapp/sps/site/prod_summary.jsp?code=MPC8315E)。

# 介绍 GNU/Linux

GNU/Linux，或者通常所说的 Linux，代表着一个悠久的传统，是开源软件中最重要的联盟之一。不久，您将会了解到今天为全世界人们提供的历史以及在选择个人计算机操作系统方面的选择。最重要的是，我们将看看硬件开发人员提供的内容以及可用于平台开发的共同基础。

GNU/Linux 由 Linux 内核和一系列用户空间应用程序组成，这些应用程序放在 GNU C 库之上；这充当了计算机操作系统。它可以被认为是最多产的开源和免费软件之一，仍在发展中。它的历史始于 1983 年，当时 Richard Stallman 创立了 GNU 项目，旨在开发一个完整的类 Unix 操作系统，只能使用免费软件组装。到了 1990 年代初，GNU 已经提供了一系列库、类 Unix shell、编译器和文本编辑器。然而，它缺少一个内核。他们在 1990 年开始开发自己的内核 Hurd。该内核基于 Mach 微内核设计，但证明难以使用，并且开发过程缓慢。

与此同时，1991 年，一位芬兰学生在赫尔辛基大学上学时开始了另一个内核的业余工作。他还得到了来自互联网上各种程序员的帮助。那位学生的名字叫 Linus Torvalds，在 1992 年，他的内核与 GNU 系统结合在一起。结果是一个名为 GNU/Linux 的完全功能的操作系统，它是免费和开源的。GNU 系统的最常见形式通常被称为*GNU/Linux 系统*，甚至是*Linux 发行版*，是 GNU 的最流行的变体。今天，有许多基于 GNU 和 Linux 内核的发行版，其中最广泛使用的有：Debian、Ubuntu、Red Hat Linux、SuSE、Gentoo、Mandriva 和 Slackware。这张图片向我们展示了 Linux 的两个组件是如何一起工作的：

![介绍 GNU/Linux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00299.jpeg)

尽管最初并不是为了在 x86 PC 之外的其他设备上运行，但今天，Linux 操作系统是最广泛和可移植的操作系统。它可以在嵌入式设备或超级计算机上找到，因为它为用户和开发人员提供了自由。拥有生成可定制 Linux 系统的工具是这个工具发展的又一个重大进步。它为新类别的人提供了访问 GNU/Linux 生态系统的途径，通过使用 BitBake 等工具，他们最终会了解更多关于 Linux、其架构差异、根文件系统的构建和配置、工具链以及 Linux 世界中的许多其他内容。

Linux 并不是设计用于微控制器。如果 RAM 小于 32MB，它将无法正常工作，并且至少需要 4MB 的存储空间。然而，如果你看一下这个要求，你会发现它非常宽松。另外，它还支持各种通信外围设备和硬件平台，这清楚地说明了为什么它如此广泛地被采用。

### 注意

嗯，它可能在 8MB 的 RAM 上运行，但这取决于应用程序的大小。

在嵌入式环境中使用 Linux 架构需要遵循一定的标准。这是一个图形化表示的环境，它是在 free-electrons Linux 课程中提供的：

![介绍 GNU/Linux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00300.jpeg)

前面的图像展示了在嵌入式设备世界中使用 Linux 进行开发过程中涉及的两个主要组件：

+   **主机**：这是所有开发工具所在的机器。在 Yocto 世界之外，这些工具由为特定目标交叉编译的相应工具链以及其必要的应用程序源代码和补丁表示。然而，对于 Yocto 用户，所有这些软件包和所涉及的准备工作都被简化为在实际工作之前执行的自动化任务。当然，这必须得到适当的优先考虑。

+   **目标机器**：这是嵌入式系统，用于进行工作和测试。目标上可用的所有软件通常都是在主机上进行交叉编译的，主机是一个更强大、更高效的环境。通常需要用于嵌入式设备引导 Linux 并运行各种应用程序的组件，包括使用引导加载程序进行基本初始化和加载 Linux 内核。这反过来初始化驱动程序和内存，并通过可用的 C 库的功能为应用程序提供服务。

### 注意

还有其他与嵌入式设备一起工作的方法，比如交叉加拿大和本地开发，但这里介绍的方法是最常用的，对于开发人员和公司在嵌入式设备的软件开发方面都能够取得最好的结果。

在开发板上拥有一个功能完整的 Linux 操作系统之前，开发人员首先需要确保内核、引导程序和板对应的驱动程序正常工作，然后才能开始开发和集成其他应用程序和库。

# Yocto 项目简介

在前一节中，介绍了拥有开源环境的好处。回顾 Yocto 项目出现之前嵌入式开发是如何进行的，可以完整地展现这个项目的好处。它也解释了为什么它被如此迅速地和如此大量地采用。

使用 Yocto 项目，整个过程变得更加自动化，主要是因为工作流程允许这样做。手动操作需要开发人员执行一系列步骤：

1.  选择并下载必要的软件包和组件。

1.  配置下载的软件包。

1.  编译配置好的软件包。

1.  在开发机上安装生成的二进制文件、库等到`rootfs`上。

1.  生成最终可部署的格式。

所有这些步骤在需要引入最终可部署状态的软件包数量增加时会变得更加复杂。考虑到这一点，可以明确地说，手动工作只适用于少量组件；自动化工具通常更适用于大型和复杂的系统。

在过去的十年里，有许多自动化工具可以用来生成嵌入式 Linux 发行版。它们都基于之前描述的相同策略，但它们还需要一些额外的信息来解决依赖性相关的问题。这些工具都建立在一个用于执行任务的引擎周围，并包含描述操作、依赖关系、异常和规则的元数据。

最值得注意的解决方案是 Buildroot、Linux 目标镜像生成器（LTIB）、Scratchbox、OpenEmbedded、Yocto 和 Angstrom。然而，Scratchbox 似乎不再活跃，最后一次提交是在 2012 年 4 月。LTIB 曾是 Freescale 的首选构建工具，最近更多地转向 Yocto；在短时间内，LTIB 也可能被淘汰。

## Buildroot

Buildroot 作为一个工具，试图简化使用交叉编译器生成 Linux 系统的方式。Buildroot 能够生成引导程序、内核映像、根文件系统，甚至交叉编译器。它可以独立生成每一个组件，因此它的主要用途被限制在生成相应的自定义根文件系统的交叉编译工具链上。它主要用于嵌入式设备，很少用于 x86 架构；它的主要关注点是 ARM、PowerPC 或 MIPS 等架构。与本书中介绍的每个工具一样，它都是为 Linux 设计的，并且期望主机系统上有一些特定的软件包以便正确使用。有一些强制性的软件包和一些可选的软件包。

在 Buildroot 手册中有一份包含特定软件包的强制性软件包列表，可以在[`buildroot.org/downloads/manual/manual.html`](http://buildroot.org/downloads/manual/manual.html)找到。这些软件包如下：

+   `which`

+   `sed`

+   `make`（3.81 版本或更高版本）

+   `binutils`

+   `build-essential`（仅适用于基于 Debian 的系统）

+   `gcc`（2.95 版本或更高版本）

+   `g++`（2.95 版本或更高版本）

+   `bash`

+   `patch`

+   `gzip`

+   `bzip2`

+   `perl`（5.8.7 版本或更高版本）

+   `tar`

+   `cpio`

+   `python`（2.6 或 2.7 版本）

+   `unzip`

+   `rsync`

+   `wget`

除了这些强制性软件包外，还有一些可选的软件包。它们对以下方面非常有用：

+   **源获取工具**：在官方树中，大多数软件包的检索都是使用`wget`从`http`、`https`甚至`ftp`链接进行的，但也有一些链接需要使用版本控制系统或其他类型的工具。为了确保用户没有获取软件包的限制，可以使用以下工具：

+   `bazaar`

+   `cvs`

+   `git`

+   `mercurial`

+   `rsync`

+   `scp`

+   `subversion`

+   **接口配置依赖**：它们由需要确保内核、BusyBox 和 U-Boot 配置等任务能够顺利执行的软件包表示：

+   `ncurses5`用于 menuconfig 界面

+   `qt4`用于`xconfig`界面

+   `glib2`，`gtk2`和`glade2`用于`gconfig`界面

+   **与 Java 相关的软件包交互**：这用于确保当用户想要与 Java 类路径组件进行交互时，可以顺利进行：

+   `javac`：这是指 Java 编译器

+   `jar`：这是指 Java 存档工具

+   **图形生成工具**：以下是图形生成工具：

+   `graphviz`用于使用`graph-depends`和`<pkg>-graph-depends`

+   `python-matplotlib`用于使用`graph-build`

+   **文档生成工具**：以下是文档生成过程中所需的工具：

+   `asciidoc`，版本 8.6.3 或更高版本

+   `w3m`

+   `python`与`argparse`模块（在 2.7+和 3.2+版本中自动可用）

+   `dblatex`（仅用于 pdf 手册生成）

Buildroot 发布每三个月一次，具体在 2 月、5 月、8 月和 11 月，并且发布名称采用`buildroot-yyyy-mm`格式。对于有兴趣尝试 Buildroot 的人来说，前一节中描述的手册应该是安装和配置的起点。对于有兴趣查看 Buildroot 源代码的开发人员，可以参考[`git.buildroot.net/buildroot/`](http://git.buildroot.net/buildroot/)。

### 注意

在克隆 Buildroot 源代码之前，建议快速查看[`buildroot.org/download`](http://buildroot.org/download)。这可能会帮助那些使用代理服务器的人。

接下来，将介绍一组新的工具，它们为这一领域做出了贡献，并将 Buildroot 项目放在了较低的支持级别上。我相信有必要快速回顾一下这些工具的优势和劣势。我们将从 Scratchbox 开始，考虑到它已经被弃用，关于它的内容并不多；它之所以被提及纯粹是出于历史原因。接下来是 LTIB，它构成了 Freescale 硬件的标准，直到采用 Yocto 为止。它在**板支持包**（**BSPs**）方面得到了 Freescale 的良好支持，并包含了大量的组件数据库。另一方面，它相当古老，已经被 Yocto 取代。它不包含对新发行版的支持，也不被许多硬件供应商使用，在短时间内，它很可能会像 Scratchbox 一样被弃用。Buildroot 是它们中的最后一个，它易于使用，采用`Makefile`基本格式，并有一个活跃的社区支持。然而，它仅限于较小和较简单的镜像或设备，并不支持部分构建或软件包。

## OpenEmbedded

接下来要介绍的工具非常相关，并且实际上具有相同的灵感和共同的祖先，即 OpenEmbedded 项目。这三个项目都由一个称为 Bitbake 的共同引擎连接，并受到 Gentoo Portage 构建工具的启发。OpenEmbedded 最初是在 2001 年开发的，当时夏普公司推出了基于 ARM 的 PDA 和 SL-5000 Zaurus，运行 Lineo，一个嵌入式 Linux 发行版。在夏普 Zaurus 推出后不久，Chris Larson 发起了 OpenZaurus 项目，旨在取代基于 Buildroot 的 SharpROM。之后，人们开始贡献更多的软件包，甚至支持新设备，最终系统开始显示其局限性。2003 年，开始讨论一个新的构建系统，可以提供一个通用的构建环境，并结合开源社区所需的使用模型；这是用于嵌入式 Linux 发行版的系统。这些讨论在 2003 年开始显示结果，今天出现的就是 Openembedded 项目。它有从 OpenZaurus 移植过来的软件包，如 Chris Larson、Michael Lauer 和 Holger Schurig 等人，根据新构建系统的能力。

Yocto 项目是同一项目的下一个演进阶段，其核心部分是 Poky 构建系统，由 Richard Purdie 创建。该项目最初是 OpenEmbedded 项目的一个稳定分支，只包括 OpenEmbedded 上可用的众多 recipes 的子集；它还具有有限的设备和架构支持。随着时间的推移，它变得更多：它变成了一个软件开发平台，集成了 fakeroot 替代品、Eclipse 插件和基于 QEMU 的镜像。现在 Yocto 项目和 OpenEmbedded 围绕一个称为**OpenEmbedded-Core**（**OE-Core**）的核心元数据进行协调。

Yocto 项目由 Linux 基金会赞助，为对开发定制嵌入式产品的 Linux 开发人员提供了一个**硬件无关环境**的起点。Poky 构建系统代表了其核心组件之一，也非常复杂。在所有这些中心是 Bitbake，它驱动一切的引擎，处理元数据的工具，下载相应的源代码，解决依赖关系，并相应地存储所有必要的库和可执行文件在构建目录中。Poky 结合了 OpenEmbedded 的优点，以分层的方式添加或删除构建环境配置中的额外软件组件，具体取决于开发人员的需求。

Poky 是一个以简单性为理念开发的构建系统。默认情况下，测试构建的配置需要用户很少的交互。基于之前练习中的克隆，我们可以进行一个新的练习来强调这个理念：

```
cd poky
source oe-init-build-env ../build-test
bitbake core-image-minimal

```

正如本例所示，很容易获得一个 Linux 镜像，以便在 QEMU 环境中进行测试。有许多可用的镜像足迹，从可以通过 shell 访问的最小镜像到具有 GNOME Mobile 用户界面支持的 LSB 兼容镜像都有。当然，这些基本镜像可以导入到新的镜像中以获得额外的功能。Poky 具有分层结构是一个巨大的优势，因为它增加了扩展功能的可能性，并且包含了错误的影响。层可以用于各种功能，从为新的硬件平台添加支持到扩展工具的支持，从新的软件堆栈到扩展的镜像功能。这里的可能性是无限的，因为几乎任何 recipe 都可以与另一个组合。

所有这些都是可能的，因为 Bitbake 引擎，它在环境设置和满足最小系统要求的测试之后，根据配置文件和接收到的输入，识别任务之间的相互依赖关系，任务的执行顺序，生成一个完全功能的交叉编译环境，并开始构建必要的本地和目标特定的软件包任务，就像它们被开发人员定义的那样。这里有一个示例，列出了一个软件包的可用任务列表：

![OpenEmbedded](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00301.jpeg)

### 注意

有关 Bitbake 及其烘烤过程的更多信息，请参阅《使用 Yocto 项目进行嵌入式 Linux 开发》，作者是 Otavio Salvador 和 Daiane Angolini。

元数据模块化基于两个想法——第一个是关于优先考虑层的结构的可能性，第二个是关于当一个配方需要更改时不需要重复工作的可能性。这些层是重叠的。最一般的层是 meta，所有其他层通常都堆叠在其上，比如`meta-yocto`与 Yocto 特定的配方、机器特定的板支持包，以及其他可选层，取决于开发人员的需求和需求。应该使用位于上层的`bbappend`来定制配方。这种方法更受青睐，以确保不会重复配方，并且还有助于支持更新和旧版本。

在前面指定软件包的可用任务列表的示例中，可以找到层的组织示例。如果用户有兴趣识别在前面的练习中指定软件包的可用任务列表的`test`构建设置使用的层，`bblayers.conf`文件是一个很好的灵感来源。如果在此文件上执行`cat`命令，将看到以下输出：

```
# LAYER_CONF_VERSION is increased each time build/conf/bblayers.conf
# changes incompatibly
LCONF_VERSION = "6"

BBPATH = "${TOPDIR}"
BBFILES ?= ""

BBLAYERS ?= " \
  /home/alex/workspace/book/poky/meta \
  /home/alex/workspace/book/poky/meta-yocto \
  /home/alex/workspace/book/poky/meta-yocto-bsp \
  "
BBLAYERS_NON_REMOVABLE ?= " \
  /home/alex/workspace/book/poky/meta \
  /home/alex/workspace/book/poky/meta-yocto \
  "
```

执行此操作的完整命令是：

```
cat build-test/conf/bblayers.conf

```

这是一个更通用的构建目录的分层结构的可视模式：

![OpenEmbedded](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00302.jpeg)

Yocto 作为一个项目提供了另一个重要的功能：无论主机机器上发生了什么变化，都可以以相同的方式重新生成镜像。这是一个非常重要的功能，不仅考虑到在开发过程中，一些工具的更改，如`autotools`、`交叉编译器`、`Makefile`、`perl`、`bison`、`pkgconfig`等，可能会发生，还考虑到与仓库的交互过程中参数可能会发生变化。简单地克隆一个仓库分支并应用相应的补丁可能无法解决所有问题。Yocto 项目对这些问题的解决方案非常简单。通过在任何安装步骤之前定义变量和配置参数，并确保配置过程也是自动化的，将最小化手动交互的风险。这个过程确保了镜像生成总是像第一次那样进行。

由于主机上的开发工具容易发生变化，Yocto 通常会编译用于软件包和镜像开发过程的必要工具，只有在它们的构建过程完成后，Bitbake 构建引擎才开始构建所请求的软件包。这种与开发人员机器的隔离有助于开发过程，保证了主机机器的更新不会影响或影响生成嵌入式 Linux 发行版的过程。

Yocto 项目优雅解决的另一个关键问题是工具链处理头文件和库的方式；因为这可能不仅会带来编译错误，还会带来非常难以预测的执行错误。 Yocto 通过将所有头文件和库移动到相应的`sysroots`目录中，并使用`sysroot`选项，构建过程确保不会与本地组件发生污染来解决这些问题。一个例子将更好地强调这一信息：

```
ls -l build-test/tmp/sysroots/
total 12K
drwxr-xr-x 8 alex alex 4,0K sep 28 04:17 qemux86/
drwxr-xr-x 5 alex alex 4,0K sep 28 00:48 qemux86-tcbootstrap/
drwxr-xr-x 9 alex alex 4,0K sep 28 04:21 x86_64-linux/

ls -l build-test/tmp/sysroots/qemux86/ 
total 24K
drwxr-xr-x 2 alex alex 4,0K sep 28 01:52 etc/
drwxr-xr-x 5 alex alex 4,0K sep 28 04:15 lib/
drwxr-xr-x 6 alex alex 4,0K sep 28 03:51 pkgdata/
drwxr-xr-x 2 alex alex 4,0K sep 28 04:17 sysroot-providers/
drwxr-xr-x 7 alex alex 4,0K sep 28 04:16 usr/
drwxr-xr-x 3 alex alex 4,0K sep 28 01:52 var/

```

Yocto 项目有助于实现可靠的嵌入式 Linux 开发，由于其规模，它被用于许多事情，从硬件公司的板支持包到软件开发公司的新软件解决方案。 Yocto 并不是一个完美的工具，它有一定的缺点：

+   磁盘空间和机器使用要求相当高

+   缺乏高级用法的文档

+   工具，如 Autobuilder 和 Eclipse 插件，现在存在功能问题

还有其他一些困扰开发人员的事情，比如`ptest`集成和 SDK sysroot 的缺乏可扩展性，但其中一部分问题已经被项目背后的大社区解决，直到项目显示出其局限性，新的问题仍然需要等待来取代它。在此之前，Yocto 是开发基于 Linux 的自定义嵌入式 Linux 发行版或产品的框架。

# 总结

在本章中，您将了解开源的优势，以及开源如何帮助 Linux 内核、Yocto 项目、OpenEmbedded 和 Buildroot 等项目的发展和增长，例如 LTIB 和 Scratchbox；缺乏开源贡献意味着它们随着时间的推移被淘汰和消失。向您呈现的信息将以示例的形式呈现，这将让您更清楚地了解本书中的概念。

在下一章中，将会有更多关于工具链及其组成部分的信息。使用手动和自动方法生成让您更好地了解工具链的练习。


# 第二章：交叉编译

在本章中，您将了解工具链，如何使用和自定义它们，以及代码标准如何适用于它们。工具链包含了许多工具，如编译器、链接器、汇编器、调试器和各种杂项实用程序，帮助操纵生成的应用程序二进制文件。在本章中，您将学习如何使用 GNU 工具链，并熟悉其特性。您将看到涉及手动配置的示例，并同时将这些示例移至 Yocto 项目环境。在本章结束时，将进行分析，以确定手动部署工具链和自动部署工具链之间的相似性和差异，以及可用于它的各种使用场景。

# 介绍工具链

工具链代表了一个编译器及其相关实用程序，用于生成特定目标所需的内核、驱动程序和应用程序。工具链通常包含一组通常相互链接的工具。它包括`gcc`、`glibc`、`binutils`或其他可选工具，如用于特定编程语言（如 C++、Ada、Java、Fortran 或 Objective-C）的调试器可选编译器。

通常，一个可用于传统桌面或服务器的工具链在这些机器上执行，并生成可在同一系统上运行的可执行文件和库。通常用于嵌入式开发环境的工具链称为交叉工具链。在这种情况下，诸如 gcc 之类的程序在主机系统上运行，用于特定目标架构生成二进制代码。整个过程称为交叉编译，这是构建嵌入式开发源代码的最常见方式。

![介绍工具链](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00303.jpeg)

在工具链环境中，有三台不同的机器：

+   代表创建工具链的机器的构建机器

+   代表执行工具链的主机机器

+   代表工具链生成二进制代码的目标机器

这三台机器用于生成四种不同的工具链构建过程：

+   **本地工具链**：这通常在普通 Linux 发行版或您的普通桌面系统上可用。通常编译和运行，并为相同的架构生成代码。

+   **交叉本地工具链**：这代表了在一个系统上构建的工具链，尽管在目标系统上运行并生成二进制代码。一个常见的用例是在目标平台上需要本地`gcc`而无需在目标平台上构建它。

+   **交叉编译工具链**：这是用于嵌入式开发的最常见的工具链类型。它在一个架构类型上编译和运行，通常是 x86，并为目标架构生成二进制代码。

+   **交叉加拿大构建**：这代表了一个涉及在系统 A 上构建工具链的过程。然后在另一个系统上运行该工具链，例如 B，生成第三个系统 C 的二进制代码。这是最不常用的构建过程之一。

生成四种不同的工具链构建过程的三台机器在下图中描述：

![介绍工具链](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00304.jpeg)

工具链代表了使今天大多数伟大项目的存在成为可能的工具列表。这包括开源项目。没有相应的工具链，这种多样性是不可能的。这也发生在嵌入式世界中，新的可用硬件需要相应工具链的组件和支持**板支持包**（**BSP**）。

工具链配置并不是一个简单的过程。在寻找预构建的工具链，甚至自己构建工具链之前，最好的解决方案是检查特定目标 BSP；每个开发平台通常都提供一个。

# 工具链的组成部分

GNU 工具链是 GNU 项目下的一组编程工具的术语。这套工具通常被称为**工具链**，用于应用程序和操作系统的开发。它在嵌入式系统和 Linux 系统的开发中起着重要作用。

以下项目包含在 GNU 工具链中：

+   GNU make：这代表了用于编译和构建的自动化工具

+   GNU 编译器套件（GCC）：这代表了用于多种可用编程语言的编译器套件

+   GNU Binutils：这包含了链接器、汇编器等工具 - 这些工具能够操作二进制文件

+   GNU Bison：这是一个解析器生成器

+   GNU 调试器（GDB）：这是一个代码调试工具

+   GNU m4：这是一个 m4 宏处理器

+   GNU 构建系统（autotools）：包括以下内容：

+   Autoconf

+   Autoheaders

+   Automake

+   Libtool

工具链中包含的项目如下图所示：

![工具链的组成部分](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00305.jpeg)

嵌入式开发环境需要的不仅仅是交叉编译工具链。它还需要库，并且应该针对特定系统的软件包，如程序、库和实用程序，以及特定主机的调试器、编辑器和实用程序。在某些情况下，通常是在谈论公司的环境时，一些服务器托管目标设备，并且某些硬件探针通过以太网或其他方法连接到主机。这强调了嵌入式发行版包括大量工具的事实，通常情况下，其中一些工具需要定制。介绍这些工具中的每一个将占用书中的一个章节以上。

然而，在本书中，我们只会涵盖工具链构建组件。这些包括以下内容：

+   `binutils`

+   `gcc`

+   `glibc`（C 库）

+   内核头文件

我将从介绍列表中的第一项开始，即**GNU Binutils 软件包**。根据 GNU GPL 许可证开发，它代表了一组工具，用于创建和管理给定架构的二进制文件、目标代码、汇编文件和配置数据。以下是 GNU Binutils 软件包可用工具的功能和名称列表：

+   GNU 链接器，即`ld`

+   GNU 汇编器，即`as`

+   将地址转换为文件名和行号的实用程序，即`addr2line`

+   创建、提取和修改存档的实用程序，即`ar`

+   用于列出对象文件中可用符号的工具，即`nm`

+   复制和翻译对象文件，即`objcopy`

+   显示来自对象文件的信息，即`objdump`

+   为存档内容生成索引的工具，即`ranlib`

+   显示任何 ELF 格式对象文件的信息，即`readelf`

+   列出对象或存档文件的段大小，即`size`

+   从文件中列出可打印的字符串，即`strings`

+   丢弃符号实用程序，即`strip`

+   过滤或解码编码的 C++符号，即`c++filt`

+   创建使用 DLL 的文件，即`dlltool`

+   一种新的、更快的、仅支持 ELF 的链接器，目前仍处于测试阶段，即`gold`

+   显示分析信息工具，即`gprof`

+   将目标代码转换为 NLM 的实用程序，即`nlmconv`

+   一个兼容 Windows 的消息编译器，即`windmc`

+   用于 Windows 资源文件的编译器，即`windres`

这些工具中的大多数使用**二进制文件描述符**（**BFD**）库进行低级数据操作，而且其中许多使用`opcode`库来组装和反汇编操作。

### 注意

有关`binutils`的有用信息可以在[`www.gnu.org/software/binutils/`](http://www.gnu.org/software/binutils/)找到。

在工具链生成过程中，列表上的下一项是内核头文件，它们被 C 库所需，用于与内核交互。在编译相应的 C 库之前，需要提供内核头文件，以便它们可以访问可用的系统调用、数据结构和常量定义。当然，任何 C 库都定义了针对每个硬件架构特定的规范集；在这里，我指的是**应用二进制接口**（**ABI**）。

应用二进制接口（ABI）代表两个模块之间的接口。它提供了有关函数调用方式以及应该在组件之间或操作系统之间传递的信息的信息。参考一本书，比如*The Linux Kernel Primer*，会对你有好处，而且在我看来，它是 ABI 提供的完整指南。我将尝试为你复制这个定义。

ABI 可以被视为类似于协议或协议的一组规则，它提供了链接器将编译模块组合成一个组件的可能性，而无需重新编译的可能性。同时，ABI 描述了这些组件之间的二进制接口。遵守 ABI 的这种约定并符合 ABI 的好处是可以链接使用不同编译器编译的目标文件。

很容易从这两个定义中看出，ABI 取决于平台的类型，这可能包括物理硬件、某种虚拟机等。它也可能取决于所使用的编程语言和编译器，但大部分取决于平台。

ABI 展示了生成的代码如何运行。代码生成过程也必须了解 ABI，但在高级语言中编码时，对 ABI 的关注很少是一个问题。这些信息可以被视为指定一些与 ABI 相关选项的必要知识。

一般规则是，ABI 必须尊重其与外部组件的交互。但是，就其与内部模块的交互而言，用户可以自由做任何他或她想做的事情。基本上，他们能够重新发明 ABI，并形成自己对机器限制的依赖。这里的简单例子与属于自己国家或地区的各种公民有关，因为他们从出生开始就学会并了解该地区的语言。因此，他们能够互相理解并无障碍地交流。对于外部公民来说，要能够交流，他或她需要了解一个地区的语言，并且在这个社区中似乎是很自然的，因此这不会构成问题。编译器也能够设计自己的自定义调用约定，其中他们了解在模块内调用的函数的限制。这通常是出于优化的原因而进行的。然而，这可能被视为 ABI 术语的滥用。

与用户空间 ABI 相关的内核是向后兼容的，并确保使用旧内核头版本生成的二进制文件比在运行内核上可用的版本更好地工作。这样做的缺点在于，使用较新内核头的工具链生成的新系统调用、数据结构和二进制文件可能无法使用较新功能。需要最新内核头的原因可以通过需要访问最新内核功能来证明。

GNU 编译器集合，也称为 GCC，代表了 GNU 工具链的关键组件。尽管最初被命名为 GNU C 编译器，因为它只处理 C 编程语言，但很快开始代表一系列语言，如 C、C++、Objective C、Fortran、Java、Ada 和 Go，以及其他语言的库（如`libstdc++`、`libgcj`等）。

它最初是作为 GNU 操作系统的编译器编写的，并作为 100％自由软件开发。它在 GNU GPL 下分发。这有助于它在各种体系结构上扩展其功能，并在开源软件的增长中发挥了重要作用。

GCC 的开发始于 Richard Stallman 为引导 GNU 操作系统所付出的努力。这个任务导致 Stallman 从头开始编写自己的编译器。它于 1987 年发布，Stallman 是作者，其他人是贡献者。到 1991 年，它已经达到了稳定阶段，但由于其架构限制，无法包含改进。这意味着开始了对 GCC 版本 2 的工作，但不久之后，对它进行新语言接口开发的需求也开始出现，并且开发人员开始对编译器源代码进行自己的分支。这种分支倡议被证明是非常低效的，由于接受代码程序的困难，对它的工作变得非常沮丧。

这在 1997 年发生了变化，当时一群开发人员聚集在**实验/增强 GNU 编译系统**（**EGCS**）工作组，开始将几个分支合并为一个项目。他们在这个冒险中取得了巨大成功，并收集了许多功能，以至于他们使**自由软件基金会**（**FSF**）停止了他们对 GCC 版本 2 的开发，并于 1999 年 4 月任命 EGCS 为官方 GCC 版本和维护者。他们在发布 GCC 2.95 时合并在一起。有关 GNU 编译器集合的历史和发布历史的更多信息，请访问[`www.gnu.org/software/gcc/releases.html`](https://www.gnu.org/software/gcc/releases.html)和[`en.wikipedia.org/wiki/GNU_Compiler_Collection#Revision_history`](http://en.wikipedia.org/wiki/GNU_Compiler_Collection#Revision_history)。

GCC 接口类似于 Unix 约定，用户调用特定于语言的驱动程序，解释参数并调用编译器。然后运行汇编程序生成输出，必要时运行链接器以获得最终可执行文件。对于每种语言编译器，都有一个执行源代码读取的单独程序。

从源代码获取可执行文件的过程有一些执行步骤。在第一步之后，生成抽象语法树，在这个阶段，可以应用编译器优化和静态代码分析。优化和静态代码分析可以同时应用于与体系结构无关的**GIMPLE**或其超集 GENERIC 表示，也可以应用于与体系结构相关的**寄存器传输语言**（**RTL**）表示，它类似于 LISP 语言。使用由 Jack Davidson 和 Christopher Fraser 编写的模式匹配算法生成机器代码。

GCC 最初几乎完全用 C 语言编写，尽管 Ada 前端主要用 Ada 语言编写。然而，2012 年，GCC 委员会宣布采用 C++作为实现语言。尽管 GCC 库的主要活动包括添加新语言支持、优化、改进的运行时库和增加调试应用程序的速度，但它不能被认为是一个完成的实现语言。

每个可用的前端都从给定的源代码生成一个树。使用这种抽象树形式，不同的语言可以共享相同的后端。最初，GCC 使用由 Bison 生成的**Look-Ahead LR**（**LALR**）解析器，但随着时间的推移，它在 2006 年转向了递归下降解析器，用于 C、C++和 Objective-C。今天，所有可用的前端都使用手写的递归下降解析器。

直到最近，程序的语法树抽象与目标处理器不独立，因为树的含义在不同的语言前端之间是不同的，每个前端都提供自己的树语法。所有这些都随着 GCC 4.0 版本引入的 GENERIC 和 GIMPLE 架构无关表示的引入而发生了变化。

GENERIC 是一个更复杂的中间表示，而 GIMPLE 是一个简化的 GENERIC，目标是 GCC 的所有前端。诸如 C、C++或 Java 前端的语言直接在前端生成 GENERIC 树表示。其他使用不同的中间表示，然后被解析和转换为 GENERIC 表示。

GIMPLE 转换表示复杂表达式，这些表达式使用临时变量分割成三地址代码。GIMPLE 表示受到了 McCAT 编译器上使用的 SIMPLE 表示的启发，用于简化程序的分析和优化。

GCC 的中间阶段表示涉及代码分析和优化，并且在编译语言和目标架构方面是独立的。它从 GENERIC 表示开始，继续到**寄存器传输语言**（**RTL**）表示。优化主要涉及跳转线程、指令调度、循环优化、子表达式消除等。RTL 优化不如通过 GIMPLE 表示进行的优化重要。但是，它们包括死代码消除、全局值编号、部分冗余消除、稀疏条件常量传播、聚合标量替换，甚至自动矢量化或自动并行化。

GCC 后端主要由预处理宏和特定目标架构函数表示，例如大小端定义，调用约定或字大小。后端的初始阶段使用这些表示来生成 RTL；这表明，尽管 GCC 的 RTL 表示在名义上是处理器无关的，但抽象指令的初始处理是针对每个特定目标进行调整的。

机器特定的描述文件包含 RTL 模式，还包括最终汇编的代码片段或操作数约束。在 RTL 生成过程中，验证目标架构的约束。要生成一个 RTL 片段，它必须与机器描述文件中的一个或多个 RTL 模式匹配，并且同时满足这些模式的限制。如果不这样做，最终 RTL 转换为机器代码的过程将是不可能的。在编译的最后阶段，RTL 表示变得严格。它的表示包含了真实的机器寄存器对应关系，以及每个指令引用的目标机器描述文件的模板。

因此，通过调用与相应模式相关联的小代码片段来获得机器代码。这样，指令就从目标指令集生成。这个过程涉及从重新加载阶段使用寄存器、偏移和地址。

### 注意

有关 GCC 编译器的更多信息，请访问[`gcc.gnu.org/`](http://gcc.gnu.org/)或[`en.wikipedia.org/wiki/GNU_Compiler_Collection`](http://en.wikipedia.org/wiki/GNU_Compiler_Collection)。

需要在这里介绍的最后一个元素是 C 库。它代表了 Linux 内核和 Linux 系统上使用的应用程序之间的接口。同时，它还为应用程序的更轻松开发提供了帮助。在这个社区中有几个 C 库可用：

+   `glibc`

+   `eglibc`

+   `Newlib`

+   `bionic`

+   `musl`

+   `uClibc`

+   `dietlibc`

+   `Klibc`

GCC 编译器使用的 C 库的选择将在工具链生成阶段执行，并且不仅受到库提供的大小和应用程序支持的影响，还受到标准的符合性、完整性和个人偏好的影响。

# 深入研究 C 库

我们将在这里讨论的第一个库是`glibc`库，它旨在提高性能、符合标准和可移植性。它是由自由软件基金会为 GNU/Linux 操作系统开发的，至今仍然存在于所有积极维护的 GNU/Linux 主机系统上。它是根据 GNU Lesser General Public License 发布的。

`glibc`库最初是由 Roland McGrath 在 20 世纪 80 年代编写的，直到 20 世纪 90 年代才继续发展，当时 Linux 内核分叉了`glibc`，称其为`Linux libc`。它在 1997 年 1 月之前是分开维护的，当时自由软件基金会发布了`glibc 2.0`。`glibc 2.0`包含了很多功能，使得继续开发`Linux libc`毫无意义，因此他们停止了分支并回到了使用`glibc`。在`Linux libc`中进行的更改没有合并到`glibc`中，因为代码的作者身份存在问题。

`glibc`库在尺寸上相当大，不适合小型嵌入式系统，但它提供了**单一 UNIX 规范**（**SUS**）、POSIX、ISO C11、ISO C99、伯克利 Unix 接口、System V 接口定义和 X/Open 可移植性指南 4.2 版的功能，以及与 X/Open 系统接口兼容系统以及 X/Open UNIX 扩展的所有扩展。此外，GLIBC 还提供了在开发 GNU 时被认为有用或必要的扩展。

我将在这里讨论的下一个 C 库是 Yocto 项目在 1.7 版本之前使用的主要 C 库。这里，我指的是`eglibc`库。这是`glibc`的一个版本，经过优化，用于嵌入式设备的使用，并且同时能够保持兼容性标准。

自 2009 年以来，Debian 及其一些派生版本选择从 GNU C 库转移到`eglibc`。这可能是因为 GNU LGPL 和`eglibc`之间的许可证存在差异，这使他们能够接受`glibc`开发人员可能拒绝的补丁。自 2014 年以来，官方`eglibc`主页声明`eglibc`的开发已经停止，因为`glibc`也已经转移到相同的许可证，而且 Debian Jessie 的发布意味着它已经回到了`glibc`。在 Yocto 支持的情况下，他们也决定将`glibc`作为他们的主要库支持选项。

`newlib`库是另一个旨在用于嵌入式系统的 C 库。它是由 Cygnus Support 开发并由 Red Hat 维护的一组自由软件许可证下的库组件。它是用于非 Linux 嵌入式系统的首选 C 库版本之一。

`newlib`系统调用描述了 C 库在多个操作系统上的使用，以及在不需要操作系统的嵌入式系统上的使用。它包含在商业 GCC 发行版中，如 Red Hat、CodeSourcery、Attolic、KPIT 等。它还受到包括 ARM、Renesas 在内的架构供应商的支持，或者类 Unix 环境，如 Cygwin，甚至 Amiga 个人电脑的专有操作系统的支持。

到 2007 年，它还得到了任天堂 DS、PlayStation、便携式 SDK Game Boy Advance 系统、Wii 和 GameCube 开发平台的工具链维护者的支持。2013 年，谷歌原生客户端 SDK 将`newlib`作为其主要 C 库包含在此列表中。

Bionic 是由 Google 为基于 Linux 内核的 Android 开发的 BSD C 库的派生版本。它的开发独立于 Android 代码开发。它的许可证是 3 条款 BSD 许可证，其目标是公开可用的。这些目标包括：

+   **小尺寸**：与`glibc`相比，Bionic 尺寸更小

+   **速度**：这些 CPU 设计为在低频率下工作

+   **BSD 许可证**：谷歌希望将 Android 应用程序与 GPL 和 LGPL 许可证隔离开来，这就是它转向非版权许可证的原因，具体如下：

+   Android 基于 GPLv2 许可证的 Linux 内核

+   `glibc`基于 LGPL，允许链接动态专有库，但不允许静态链接

与`glibc`相比，它还有一系列限制，如下：

+   它不包括 C++异常处理，主要是因为 Android 大多数代码都是用 Java 编写的。

+   它不支持宽字符。

+   它不包括标准模板库，尽管可以手动包含。

+   它在 Bionic POSIX 中运行，甚至系统调用头文件都是 Android 特定函数的包装器或存根。这有时可能会导致奇怪的行为。

+   当 Android 4.2 发布时，它包括对`glibc``FORTIFY_SOURCE`功能的支持。这些功能在 Yocto 和嵌入式系统中经常使用，但只存在于带有 ARM 处理器的 Android 设备的`gcc`版本中。

接下来要讨论的 C 库是`musl`。它是一个用于嵌入式和移动系统的 Linux 操作系统的 C 库。它具有 MIT 许可证，并且是根据从头开始开发的干净、符合标准的`libc`的想法而开发的。作为一个 C 库，它被优化用于静态库的链接。它与 C99 标准和 POSIX 2008 兼容，并实现了 Linux、`glibc`和 BSD 非标准函数。

接下来，我们将讨论`uClibc`，这是为 Linux 嵌入式系统和移动设备设计的 C 标准库。尽管最初是为μClinux 开发并设计用于微控制器，但它获得了追踪，并成为任何在设备上有限空间的人的首选。这是因为它变得受欢迎的原因：

+   它侧重于尺寸而不是性能

+   它具有 GNU Lesser General Public License（LGPL）免费许可证

+   它比 glibc 小得多，减少了编译时间

+   由于许多功能可以使用类似于 Linux 内核、U-Boot 甚至 BusyBox 等软件包上可用的`menuconfig`界面进行启用，因此它具有很高的可配置性。

`uClibc`库还具有另一个使其非常有用的特性。它引入了一种新的思想，因此 C 库不试图支持尽可能多的标准。然而，它专注于嵌入式 Linux，并包括对面临可用空间限制的开发人员必要的功能。出于这个原因，这个库是从头开始编写的，尽管它有其自身的局限性，但`uClibc`是`glibc`的一个重要替代品。如果我们考虑到大多数 C 库使用的功能都包含在其中，最终尺寸要小四倍，WindRiver、MontaVista 和 TimeSys 都是其活跃的维护者。

`dietlibc`库是由 Felix von Leitner 开发的标准 C 库，并在 GNU GPL v2 许可下发布。尽管它也包含一些商业许可的组件，但其设计基于与`uClibc`相同的思想：在尽可能小的尺寸下编译和链接软件。它与`uClibc`还有另一个相似之处；它是从头开始开发的，并且只实现了最常用和已知的标准函数。它的主要用途主要是在嵌入式设备市场。

C 库列表中的最后一个是`klibc`标准 C 库。它是由 H. Peter Anvin 开发的，并且被开发用作 Linux 启动过程中早期用户空间的一部分。它被用于运行内核启动过程的组件，但不用于内核模式，因此它们无法访问标准 C 库。

`klibc`的开发始于 2002 年，旨在将 Linux 初始化代码移出内核。其设计使其适用于嵌入式设备。它还有另一个优势：它针对小尺寸和数据正确性进行了优化。`klibc`库在 Linux 启动过程中从**initramfs**（临时 Ram 文件系统）中加载，并且默认情况下使用`mkinitramfs`脚本将其合并到基于 Debian 和 Ubuntu 的文件系统中。它还可以访问一小组实用程序，如`mount`，`mkdir`，`dash`，`mknod`，`fstype`，`nfsmount`，`run-init`等，在早期初始化阶段非常有用。

### 注意

有关 initramfs 的更多信息可以在内核文档中找到：[`www.kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt`](https://www.kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt)。

`klibc`库根据 GNU GPL 许可，因为它使用了一些来自 Linux 内核的组件，因此作为整体，它被视为 GPL 许可的软件，限制了其在商业嵌入式软件中的适用性。然而，大多数库的源代码都是根据 BSD 许可编写的。

# 使用工具链

在生成工具链时，需要做的第一件事是建立用于生成二进制文件的 ABI。这意味着内核需要理解这个 ABI，同时系统中的所有二进制文件都需要使用相同的 ABI 进行编译。

在使用 GNU 工具链时，收集信息并了解使用这些工具的方式的一个很好的来源是查阅 GNU 编码标准。编码标准的目的非常简单：确保在 GNU 生态系统中以清晰、简单和一致的方式执行工作。这是一个需要被有兴趣使用 GNU 工具编写可靠、稳固和可移植软件的人使用的指南。GNU 工具链的主要重点是 C 语言，但这里应用的规则对于任何编程语言也非常有用。通过确保将给定信息背后的逻辑传递给读者来解释每条规则的目的。

我们将主要关注的语言也将是 C 编程语言。关于 GNU 编码标准与 GNU 库、异常或实用程序的兼容性，以及它们与 Berkeley Unix、标准 C 或 POSIX 等标准的比较应该非常好。在兼容性冲突的情况下，为该编程语言拥有兼容模式非常有用。

标准，如 POSIX 和 C，对于支持扩展有许多限制 - 然而，这些扩展仍然可以通过包括`—posix`，`—ansi`或`—compatible`选项来禁用它们。如果扩展提供了破坏程序或脚本的高概率，因为不兼容，应重新设计其接口以确保兼容性。

大量的 GNU 程序抑制了已知会与 POSIX 冲突的扩展，如果定义了`POSIXLY_CORRECT`环境变量。用户定义功能的使用为交换 GNU 功能与其他完全不同、更好甚至兼容功能提供了可能性。额外的有用功能总是受欢迎的。

如果我们快速浏览 GNU 标准文档，可以从中学到一些有用的信息：

最好使用`int`类型，尽管您可能考虑定义一个更窄的数据类型。当然，也有一些特殊情况可能很难使用。一个例子是`dev_t`系统类型，因为在某些机器上它比`int`短，在其他机器上则更宽。支持非标准 C 类型的唯一方法是使用`Autoconf`检查`dev_t`的宽度，然后相应地选择参数类型。然而，这可能不值得麻烦。

对于 GNU 项目来说，实施组织标准规范是可选的，只有在帮助系统整体变得更好的情况下才能实现。在大多数情况下，遵循已发布的标准符合用户需求，因为他们的程序或脚本可能被认为更具可移植性。一个例子是 GCC，它几乎实现了标准 C 的所有特性，正如标准要求的那样。这为 C 程序的开发人员提供了巨大的优势。这也适用于遵循 POSIX.2 规范的 GNU 实用程序。

还有一些规范中没有遵循的具体要点，但这是为了使 GNU 系统更好地为用户服务。一个例子是标准 C 程序不允许对 C 进行扩展，但是 GCC 实现了其中的许多扩展，其中一些后来被标准所采纳。对于希望按照标准输出错误消息的开发人员，可以使用`--pedantic`参数。这是为了确保 GCC 完全实现了标准。

POSIX.2 标准提到，诸如`du`和`df`之类的命令应该以 512 字节为单位输出大小。然而，用户希望以 1KB 为单位，因此实现了这种默认行为。如果有人希望具有 POSIX 标准要求的行为，他们需要设置`POSIXLY_CORRECT`环境变量。

另一个例子是 GNU 实用程序，当涉及到长命令行选项的支持或选项与参数的混合时，并不总是遵循 POSIX.2 标准规范。这种与 POSIX 标准的不兼容在实践中对开发人员非常有用。这里的主要思想不是拒绝任何新功能或删除旧功能，尽管某个标准将其视为已弃用或禁止。

### 注意

有关 GNU 编码标准的更多信息，请参阅[`www.gnu.org/prep/standards/html_node/`](https://www.gnu.org/prep/standards/html_node/)。

## 健壮编程的建议

为了确保编写健壮的代码，应该提到一些指导方针。第一个指导方针是不应该对任何数据结构使用限制，包括文件、文件名、行和符号，尤其是任意限制。所有数据结构都应该是动态分配的。其中一个原因是大多数 Unix 实用程序会悄悄地截断长行；GNU 实用程序不会这样做。

用于读取文件的实用程序应避免删除`null`字符或不可打印字符。这里的例外是，当这些旨在与某些类型的打印机或终端进行接口的实用程序无法处理先前提到的字符时。在这种情况下，我会建议尝试使用 UTF-8 字符集或其他用于表示多字节字符的字节序列使程序正常工作。

确保检查系统调用的错误返回值；例外情况是开发人员希望忽略错误。最好在由系统调用崩溃导致的错误消息中包括`strerror`、`perror`或等效错误处理函数的系统错误文本，还要添加源代码文件的名称和实用程序的名称。这样做是为了确保错误消息易于被与源代码或程序交互的任何人阅读和理解。

检查`malloc`或`realloc`的返回值，以验证它们是否返回了零。如果在系统中使用`realloc`使块变小，系统将近似块尺寸为 2 的幂，则`realloc`可能会有不同的行为并获得不同的块。在 Unix 中，当`realloc`存在错误时，它会破坏零返回值的存储块。对于 GNU，这个错误不会发生，当它失败时，原始块保持不变。如果要在 Unix 上运行相同的程序并且不想丢失数据，可以检查 Unix 系统上的错误是否已解决，或者使用 GNU 的`malloc`。

释放的块的内容不可访问以进行更改或进行任何其他用户交互。这可以在调用 free 之前完成。

当`malloc`命令在非交互式程序中失败时，我们面临致命错误。如果发生相同的情况，但这次涉及交互式程序，最好中止命令并返回读取循环。这提供了释放虚拟内存、终止其他进程并重试命令的可能性。

要解码参数，可以使用`getopt_long`选项。

在程序执行期间写入静态存储时，使用 C 代码进行初始化。但是，对于不会更改的数据，请保留 C 初始化声明。

尽量远离对未知 Unix 数据结构的低级接口——当数据结构无法以兼容的方式工作时，可能会发生这种情况。例如，要查找目录中的所有文件，开发人员可以使用`readdir`函数或任何高级接口可用函数，因为这些函数没有兼容性问题。

对于信号处理，使用 BSD 变体的`signal`和 POSIX 的`sigaction`函数。在这种情况下，USG 的`signal`接口不是最佳选择。如今，使用 POSIX 信号函数被认为是开发可移植程序的最简单方法。但是，使用一个函数而不是另一个完全取决于开发人员。

对于识别不可能情况的错误检查，只需中止程序，因为无需打印任何消息。这种类型的检查证明了错误的存在。要修复这些错误，开发人员将不得不检查可用的源代码，甚至启动调试器。解决这个问题的最佳方法是在源代码中使用注释描述错误和问题。在使用调试器相应地检查变量后，可以找到相关信息。

不要将程序中遇到的错误数量作为退出状态。这种做法并不是最佳的，主要是因为退出状态的值仅限于 8 位，可执行文件的执行可能有超过 255 个错误。例如，如果尝试返回进程的退出状态 256，父进程将看到状态为零，并认为程序成功完成。

如果创建了临时文件，请检查`TMPDIR`环境变量是个好主意。如果定义了该变量，最好使用`/tmp`目录。应谨慎使用临时文件，因为在可写入世界的目录中创建它们可能会导致安全漏洞。对于 C 语言，可以通过以下方式避免在临时文件中创建临时文件：

```
fd = open (filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
```

这也可以使用`mkstemps`函数来完成，该函数由`Gnulib`提供。

对于 bash 环境，使用`noclobber`环境变量，或`set -C`的简短版本，以避免前面提到的问题。此外，`mktemp`可用实用程序是在 GNU Coreutils 软件包中的制作临时文件的更好解决方案。

### 注意

有关 GNU C 标准的更多信息，请访问[`www.gnu.org/prep/standards/standards.html`](https://www.gnu.org/prep/standards/standards.html)。

## 生成工具链

在介绍组成工具链的软件包之后，本节将介绍获取自定义工具链所需的步骤。将生成的工具链包含与 Poky dizzy 分支中可用的相同源。在这里，我指的是`gcc`版本 4.9，`binutils`版本 2.24 和`glibc`版本 2.20。对于 Ubuntu 系统，也有快捷方式可用。可以使用可用的软件包管理器安装通用工具链，还有其他选择，例如从 Board Support Packages 中下载可用的自定义工具链，甚至从 CodeSourcery 和 Linaro 等第三方下载。有关工具链的更多信息，请访问[`elinux.org/Toolchains`](http://elinux.org/Toolchains)。将用作演示的架构是 ARM 架构。

工具链构建过程有八个步骤。我只会概述每个步骤所需的活动，但必须提到它们都在 Yocto 项目配方中自动化。在 Yocto 项目部分，工具链是在不知不觉中生成的。与生成的工具链交互的最简单任务是调用**meta-ide-support**，但这将在适当的部分中介绍如下：

+   **设置**：这代表了创建顶级构建目录和源子目录的步骤。在此步骤中，定义了诸如`TARGET`，`SYSROOT`，`ARCH`，`COMPILER`，`PATH`等变量。

+   **获取源代码**：这代表了在后续步骤中可用的软件包，如`binutils`，`gcc`，`glibc`，`Linux 内核`头文件和各种补丁。

+   **GNU Binutils 设置** - 这代表了与`binutils`软件包交互的步骤，如下所示：

+   解压相应版本的源代码

+   如果适用，相应地对源代码进行打补丁

+   相应地配置软件包

+   编译源代码

+   将源代码安装在相应的位置

+   **Linux 内核头文件设置**：这代表了与 Linux 内核源交互的步骤，如下所示：

+   解压内核源代码。

+   如果适用，对内核源代码进行打补丁。

+   为所选的架构配置内核。在此步骤中，将生成相应的内核配置文件。有关 Linux 内核的更多信息将在第四章中介绍，*Linux Kernel*。

+   编译 Linux 内核头文件并将其复制到相应的位置。

+   将头文件安装在相应的位置。

+   **Glibc 头文件设置**：这代表了设置`glibc`构建区域和安装头文件的步骤，如下所示：

+   解压 glibc 存档和头文件

+   如果适用，对源代码进行打补丁

+   配置源代码，启用`-with-headers`变量以将库链接到相应的 Linux 内核头文件

+   编译`glibc`头文件

+   相应地安装头文件

+   **GCC 第一阶段设置**：这代表了生成 C 运行时文件（如`crti.o`和`crtn.o`）的步骤：

+   解压 gcc 存档

+   如有必要，对`gcc`源代码进行修补

+   配置源代码，启用所需的功能

+   编译 C 运行时组件

+   相应地安装源代码

+   **构建`glibc`源代码**：这代表了构建`glibc`源代码并进行必要的 ABI 设置的步骤，如下所示：

+   通过相应地设置`mabi`和`march`变量来配置`glibc`库

+   编译源代码

+   相应地安装`glibc`

+   **GCC 第二阶段设置**：这代表了工具链配置完成的最终设置阶段，如下所示：

+   配置`gcc`源代码

+   编译源代码

+   在相应位置安装二进制文件

执行这些步骤后，开发人员将可以使用工具链。在 Yocto 项目中遵循相同的策略和构建过程步骤。

# Yocto 项目参考

正如我所提到的，Yocto 项目环境的主要优势和可用功能在于 Yocto 项目构建不使用主机可用的软件包，而是构建和使用自己的软件包。这是为了确保主机环境的更改不会影响其可用的软件包，并且构建是为了生成自定义 Linux 系统。工具链是其中的一个组件，因为几乎所有构成 Linux 发行版的软件包都需要使用工具链组件。

Yocto 项目的第一步是确定将组合生成工具链的确切源和软件包，该工具链将被后续构建的软件包使用，如 U-Boot 引导程序、内核、BusyBox 等。在本书中，将讨论的源代码位于 dizzy 分支、最新的 poky 12.0 版本和 Yocto 项目版本 1.7 中。可以使用以下命令收集源代码：

```
git clone -b dizzy http://git.yoctoproject.org/git/poky

```

收集源代码并调查源代码，我们确定了前面标题中提到的部分软件包，并按照以下方式呈现：

```
cd poky
find ./ -name "gcc"
./meta/recipes-devtools/gcc
find ./ -name "binutils" 
./meta/recipes-devtools/binutils
./meta/recipes-devtools/binutils/binutils
find ./ -name "glibc"
./meta/recipes-core/glibc
./meta/recipes-core/glibc/glibc
$ find ./ -name "uclibc"
./meta-yocto-bsp/recipes-core/uclibc
./meta-yocto-bsp/recipes-core/uclibc/uclibc
./meta/recipes-core/uclibc 

```

GNU CC 和 GCC C 编译器软件包包括所有前面的软件包，分为多个部分，每个部分都有其目的。这主要是因为每个部分都有其目的，并且用于不同的范围，如`sdk`组件。然而，正如我在本章开头提到的，有多个需要确保并使用相同源代码自动化的工具链构建过程。Yocto 中支持 gcc 4.8 和 4.9 版本。快速查看`gcc`可用的配方显示了可用的信息：

```
meta/recipes-devtools/gcc/
├── gcc-4.8
├── gcc_4.8.bb
├── gcc-4.8.inc
├── gcc-4.9
├── gcc_4.9.bb
├── gcc-4.9.inc
├── gcc-common.inc
├── gcc-configure-common.inc
├── gcc-cross_4.8.bb
├── gcc-cross_4.9.bb
├── gcc-cross-canadian_4.8.bb
├── gcc-cross-canadian_4.9.bb
├── gcc-cross-canadian.inc
├── gcc-cross.inc
├── gcc-cross-initial_4.8.bb
├── gcc-cross-initial_4.9.bb
├── gcc-cross-initial.inc
├── gcc-crosssdk_4.8.bb
├── gcc-crosssdk_4.9.bb
├── gcc-crosssdk.inc
├── gcc-crosssdk-initial_4.8.bb
├── gcc-crosssdk-initial_4.9.bb
├── gcc-crosssdk-initial.inc
├── gcc-multilib-config.inc
├── gcc-runtime_4.8.bb
├── gcc-runtime_4.9.bb
├── gcc-runtime.inc
├── gcc-target.inc
├── libgcc_4.8.bb
├── libgcc_4.9.bb
├── libgcc-common.inc
├── libgcc.inc
├── libgcc-initial_4.8.bb
├── libgcc-initial_4.9.bb
├── libgcc-initial.inc
├── libgfortran_4.8.bb
├── libgfortran_4.9.bb
└── libgfortran.inc

```

GNU Binutils 软件包代表了二进制工具集合，如 GNU 链接器、GNU 汇编器、`addr2line`、`ar`、`nm`、`objcopy`、`objdump`和其他工具及相关库。Yocto 项目支持 Binutils 版本 2.24，并且还依赖于可用的工具链构建过程，可以从源代码检查中看到：

```
meta/recipes-devtools/binutils/
├── binutils
├── binutils_2.24.bb
├── binutils-2.24.inc
├── binutils-cross_2.24.bb
├── binutils-cross-canadian_2.24.bb
├── binutils-cross-canadian.inc
├── binutils-cross.inc
├── binutils-crosssdk_2.24.bb
└── binutils.inc

```

最后的组件由 C 库组成，这些库作为 Poky dizzy 分支中的组件存在。有两个可供开发人员使用的 C 库。第一个是 GNU C 库，也称为`glibc`，是 Linux 系统中最常用的 C 库。`glibc`软件包的源代码可以在这里查看：

```
meta/recipes-core/glibc/
├── cross-localedef-native
├── cross-localedef-native_2.20.bb
├── glibc
├── glibc_2.20.bb
├── glibc-collateral.inc
├── glibc-common.inc
├── glibc.inc
├── glibc-initial_2.20.bb
├── glibc-initial.inc
├── glibc-ld.inc
├── glibc-locale_2.20.bb
├── glibc-locale.inc
├── glibc-mtrace_2.20.bb
├── glibc-mtrace.inc
├── glibc-options.inc
├── glibc-package.inc
├── glibc-scripts_2.20.bb
├── glibc-scripts.inc
├── glibc-testing.inc
├── ldconfig-native-2.12.1
├── ldconfig-native_2.12.1.bb
└── site_config

```

从这些源中，相同的位置还包括工具，如`ldconfig`，用于运行时依赖关系的独立本地动态链接器和绑定和交叉语言环境生成工具。在另一个名为`uClibc`的 C 库中，如前所述，这是为嵌入式系统设计的库，具有较少的配方，可以从 Poky 源代码中查看：

```
meta/recipes-core/uclibc/
├── site_config
├── uclibc-config.inc
├── uclibc-git
├── uclibc_git.bb
├── uclibc-git.inc
├── uclibc.inc
├── uclibc-initial_git.bb
└── uclibc-package.inc

```

uClibc 被用作`glibc` C 库的替代方案，因为它生成较小的可执行文件占用空间。同时，`uClibc`是前面列表中所呈现的唯一一个应用了`bbappend`的软件包，因为它扩展了对两台机器`genericx86-64`和`genericx86`的支持。可以通过将`TCLIBC`变量更改为相应的变量来在`glibc`和`uClibc`之间进行更改：`TCLIBC = "uclibc"`。

如前所述，Yocto Project 的工具链生成过程更简单。这是在使用 Yocto Project 构建任何配方之前执行的第一个任务。要在 Bitbake 中生成交叉工具链，首先执行`bitbake meta-ide-support`任务。例如，可以为`qemuarm`架构执行该任务，但当然也可以以类似的方法为任何给定的硬件架构生成。任务完成执行过程后，工具链将生成并填充构建目录。在此之后，可以通过在`tmp`目录中使用`environment-setup`脚本来使用它：

```
cd poky
source oe-init-build-env ../build-test

```

相应地在`conf/local.conf`文件中将`MACHINE`变量设置为值`qemuarm`：

```
bitbake meta-ide-support
source tmp/environment-setup

```

用于生成工具链的默认 C 库是`glibc`，但可以根据开发人员的需要进行更改。从前一节的介绍中可以看出，Yocto Project 中的工具链生成过程非常简单直接。它还避免了手动工具链生成过程中涉及的所有麻烦和问题，使得重新配置也非常容易。

# 摘要

在本章中，您将获得理解 Linux 工具链组成部分所需的必要信息，以及开发人员为工作或配置特定于板或架构的 Linux 工具链所采取的步骤。您还将获得有关 Yocto Project 源中可用软件包的信息，以及 Yocto Project 中定义的过程与 Yocto Project 上下文之外已经使用的过程非常相似。

在下一章中，我们将快速浏览有关引导加载程序的信息，特别强调 U-Boot 引导加载程序。您还将获得有关引导顺序和 U-Boot 源中板的配置的信息。


# 第三章：引导加载程序

在本章中，将介绍在嵌入式环境中使用 Linux 系统所必需的最重要的组件之一。我指的是引导加载程序，它是一种软件，可以初始化平台并使其准备好引导 Linux 操作系统。本章将介绍引导加载程序的好处和作用。本章主要关注 U-Boot 引导加载程序，但鼓励读者也了解其他引导加载程序，如 Barebox、RedBoot 等。所有这些引导加载程序都有各自的特点，没有一种特别适合所有需求；因此，在本章中欢迎进行实验和探索。

本章的主要目的是介绍嵌入式引导加载程序和固件的主要属性，它们的引导机制，以及在固件更新或修改时出现的问题。我们还将讨论与安全、安装或容错相关的问题。关于引导加载程序和固件的概念，我们有多个定义可用，其中一些是指传统的桌面系统，而我们对此不感兴趣。

固件通常代表一个固定且小型的程序，用于控制硬件系统。它执行低级操作，通常存储在闪存、只读存储器、可擦写只读存储器等上。它不经常更改。由于有时会有人对这个术语感到困惑，并且有时仅用于定义硬件设备或表示数据及其指令，因此完全避免使用。它代表两者的结合：计算机数据和信息，以及与硬件设备结合在一起的只读软件，可用于设备上。

引导加载程序代表系统初始化时首先执行的软件部分。它用于加载、解压缩和执行一个或多个二进制应用程序，比如 Linux 内核或根文件系统。它的作用是将系统添加到可以执行其主要功能的状态。这是在加载和启动它接收到的或已经保存在内部存储器上的正确二进制应用程序之后完成的。在初始化时，硬件引导加载程序可能需要初始化锁相环（PLL）、设置时钟，或者启用对 RAM 存储器和其他外围设备的访问。然而，这些初始化是在基本级别上完成的；其余的由内核驱动程序和其他应用程序完成。

今天有许多引导加载程序可用。由于本主题的空间有限，而且它们的数量很多，我们只讨论最流行的几种。U-Boot 是 PowerPC、ARM、MIPS 等架构中最流行的引导加载程序之一，它将成为本章的主要焦点。

# 引导加载程序的作用

第一次电流进入开发板处理器时，运行程序之前需要准备大量的硬件组件。对于每种架构、硬件制造商，甚至处理器来说，初始化过程都是不同的。在大多数情况下，它涉及一组配置和操作，对于各种处理器来说都是不同的，并最终从处理器附近的存储设备中获取引导代码。这个存储设备通常是闪存存储器，引导代码是引导加载程序的第一阶段，它初始化处理器和相关硬件外围设备。

大多数可用的处理器在通电时会转到默认地址位置，并在找到二进制数据的第一个字节后开始执行它们。基于这些信息，硬件设计师定义了闪存内存的布局和后续可以用于从可预测地址加载和引导 Linux 操作系统的地址范围。

在初始化的第一阶段，通常使用特定于处理器的汇编语言进行板子初始化，完成后，整个生态系统就准备好进行操作系统引导过程。引导程序负责这一切；它是提供加载、定位和执行操作系统的主要组件的可能性。此外，它还可以包含其他高级功能，比如升级 OS 映像、验证 OS 映像、在几个 OS 映像之间进行选择，甚至升级自身的可能性。传统 PC BIOS 和嵌入式引导程序之间的区别在于，在嵌入式环境中，引导程序在 Linux 内核开始执行后被覆盖。事实上，在它将控制权交给 OS 映像后，它就不复存在了。

在使用外围设备之前，引导程序需要仔细初始化外围设备，比如闪存或 DRAM。这并不是一件容易的事情。例如，DRAM 芯片不能以直接的方式读取或写入 - 每个芯片都有一个需要启用读写操作的控制器。同时，DRAM 需要不断刷新，否则数据将丢失。事实上，刷新操作代表了在硬件制造商规定的时间范围内读取每个 DRAM 位置。所有这些操作都是 DRAM 控制器的责任，它可能会给嵌入式开发人员带来很多挫折，因为它需要对架构设计和 DRAM 芯片有特定的了解。

引导程序没有普通应用程序的基础设施。它没有只能通过名称调用并开始执行的可能性。在获得控制权后，它通过初始化处理器和必要的硬件（如 DRAM）创建自己的上下文，如果需要，将自己移动到 DRAM 中以加快执行速度，最后开始实际的代码执行。

第一个复杂性因素是启动代码与处理器的引导顺序的兼容性。第一个可执行指令需要位于闪存内存中的预定义位置，这取决于处理器甚至硬件架构。此外，有可能有多个处理器根据接收到的硬件信号在几个位置寻找这些第一个可执行指令。

另一种可能性是在许多新的开发板上具有相同的结构，比如 Atmel SAMA5D3-Xplained：

![引导程序的作用](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00306.jpeg)

对于 Atmel SAMA5D3-Xplained 板和其他类似的板，引导过程是从 ROM 内存中的集成引导代码 BootROM 开始的，该代码在 AT91 CPU 上加载第一阶段引导程序 AT91Bootstrap 到 SRAM 并启动它。第一阶段引导程序初始化 DRAM 内存并启动第二阶段引导程序，这种情况下是 U-Boot。有关引导序列可能性的更多信息可以在即将介绍的引导序列头部中找到。

缺乏执行上下文代表另一个复杂性。即使在一个没有内存，因此没有堆栈来分配信息的系统中编写一个简单的`"Hello World"`也会与众不同，这就是引导程序初始化 RAM 内存以便有一个可用的堆栈，并能够运行更高级的程序或语言，比如 C 的原因。

# 比较各种引导加载程序

正如前面所读到的，嵌入式系统有许多引导加载程序可用。这里将介绍以下引导加载程序：

+   U-Boot：也称为通用引导加载程序，主要适用于嵌入式 Linux 系统的 PowerPC 和 ARM 架构

+   Barebox：最初被称为 U-Boot v2，于 2007 年开始，旨在解决 U-Boot 的局限性；随着设计目标和社区的变化，它随时间改变了名称

+   RedBoot：这是一个源自 eCos 的 RedHat 引导加载程序，eCos 是一种便携式的开源实时操作系统，专为嵌入式系统设计

+   rrload：这是一个基于嵌入式 Linux 系统的 ARM 引导加载程序

+   PPCBOOT：这是用于 PowerPC 的引导加载程序，基于嵌入式 Linux 系统

+   CLR/OHH：这代表基于 ARM 架构的嵌入式 Linux 系统的闪存引导加载程序

+   Alios：这是一个主要用汇编语言编写的引导加载程序，进行 ROM 和 RAM 初始化，并试图完全消除嵌入式系统上固件的需求

有许多可用的引导加载程序，这是因为存在大量不同的架构和设备，实际上有很多，几乎不可能有一个适用于所有系统的引导加载程序。引导加载程序的种类很多；区分因素包括板类型和结构、SOC 差异甚至 CPU。 

# 深入研究引导加载程序循环

如前所述，引导加载程序是在初始化系统后首先运行的组件，并为操作系统引导过程准备整个生态系统。这个过程因架构而异。例如，对于 x86 架构，处理器可以访问 BIOS，这是一个可用于非易失性存储器的软件，通常是 ROM。它的作用是在系统重置后开始执行并初始化硬件组件，这些组件稍后将被第一阶段引导加载程序使用。它还执行引导加载程序的第一阶段。

第一阶段引导加载程序在尺寸上非常小 - 通常只有 512 字节，并驻留在易失性存储器中。它在第二阶段执行完整的引导加载程序初始化。第二阶段引导加载程序通常驻留在第一阶段引导加载程序旁边，它们包含最多的功能并完成大部分工作。它们还知道如何解释各种文件系统格式，主要是因为内核是从文件系统加载的。

对于 x86 处理器，还有更多可用的引导加载程序解决方案：

+   GRUB：Grand Unified Bootloader 是 Linux 系统中最常用和功能强大的引导加载程序，适用于台式 PC 平台。它是 GNU 项目的一部分，也是 x86 架构系统中最强大的引导加载程序之一。这是因为它能够理解各种文件系统和内核映像格式。它能够在引导时更改引导配置。GRUB 还支持网络引导和命令行界面。它有一个在引导时处理并可修改的配置文件。有关更多信息，请访问[`www.gnu.org/software/grub/`](http://www.gnu.org/software/grub/)。

+   **Lilo**：Linux Loader 是商业 Linux 发行版中经常使用的引导加载程序。与前面的情况类似，它适用于台式 PC 平台。它有多个组件，第一个组件出于历史原因位于磁盘驱动器的第一个扇区上；它是引导组件。出于同样的历史原因，它受限于 512 字节的尺寸，并且加载并提供控制给第二阶段引导加载程序，后者完成大部分引导加载程序的工作。Lilo 有一个配置实用程序，主要用作 Linux 内核引导过程的信息来源。有关更多信息，请访问[`www.tldp.org/HOWTO/LILO.html`](http://www.tldp.org/HOWTO/LILO.html)。

+   **Syslinux**：用于可移动媒体或网络引导。Syslinux 是一个在 MS-DOS 或 Windows FAT 文件系统上运行的 Linux 操作系统引导加载程序，主要用于 Linux 的救援和首次安装。有关更多信息，请访问[`www.kernel.org/pub/linux/utils/boot/syslinux/`](http://www.kernel.org/pub/linux/utils/boot/syslinux/)。

对于大多数嵌入式系统，这种引导过程并不适用，尽管有一些系统会复制这种行为。接下来将介绍两种情况。第一种情况是代码执行从固定地址位置开始，第二种情况是 CPU 在 ROM 存储器中有可调用的代码。

![深入了解引导加载程序周期](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00307.jpeg)

图像的右侧呈现为先前提到的引导机制。在这种情况下，硬件需要一个 NOR 闪存存储器芯片，该芯片位于起始地址，以确保代码执行的开始。

NOR 存储器优于 NAND 存储器，因为它允许随机地址访问。这是第一阶段引导加载程序编程开始执行的地方，这并不使它成为最实用的引导机制。

尽管它并不是用于引导加载程序引导过程的最实用方法，但它仍然可用。然而，它在只适用于不适合更强大引导选项的板卡上才能使用。

# U-Boot 引导加载程序

今天有许多开源引导加载程序可用。几乎所有这些引导加载程序都具有加载和执行程序的功能，通常涉及操作系统，并且它们的功能用于串行接口通信。然而，并非所有引导加载程序都具有通过以太网通信或自我更新的可能性。另一个重要因素是引导加载程序的广泛使用。组织和公司通常会选择一种引导加载程序，以支持它们所支持的多样化的板卡、处理器和架构。类似的情况也发生在 Yocto 项目中，当选择一个引导加载程序来代表官方支持的引导加载程序时。他们和其他类似的公司选择了 U-Boot 引导加载程序，在 Linux 社区中相当知名。

U-Boot 引导加载程序，或其官方名称 Das U-Boot，由 Wolfgang Denx 开发和维护，得到社区的支持。它在 GPLv2 许可下，其源代码在`git`存储库中免费提供，如第一章所示，每两个月发布一次。发布版本名称显示为`U-boot vYYYY.MM`。有关 U-Boot 加载程序的信息可在[`www.denx.de/wiki/U-Boot/ReleaseCycle`](http://www.denx.de/wiki/U-Boot/ReleaseCycle)找到。

U-Boot 源代码具有非常明确定义的目录结构。可以通过以下控制台命令轻松看到这一点：

```
tree -d -L 1
.
├── api
├── arch
├── board
├── common
├── configs
├── disk
├── doc
├── drivers
├── dts
├── examples
├── fs
├── include
├── lib
├── Licenses
├── net
├── post
├── scripts
├── test
└── tools
19 directories

```

`arch`目录包含特定架构文件和每个架构、CPU 或开发板特定目录。`api`包含独立于机器或架构类型的外部应用程序。`board`包含具有特定目录名称的所有特定板卡文件。`common`是`misc`函数的位置。`disk`包含磁盘驱动处理函数，文档可在`doc`目录中找到。驱动程序位于`drivers`目录中。文件系统特定功能位于`fs`目录中。还有一些目录需要在这里提到，比如`include`目录，其中包含头文件；`lib`目录包含对各种实用程序的通用库支持，例如扁平设备树、各种解压缩、`post`（自检）等，但我会让读者的好奇心去发现它们，一个小提示是检查`Directory Hierachy`部分的`README`文件。

在 U-Boot 源代码中，可以找到每个支持的板卡的配置文件，这些文件在前一章节中下载到`./include/configs`文件夹中。这些配置文件是`.h`文件，包含了一些`CONFIG_`文件和有关内存映射、外围设备及其设置、命令行输出等信息，例如用于引导 Linux 系统的默认引导地址等。有关配置文件的更多信息可以在*Configuration Options*部分的`README`文件中或特定板卡配置文件中找到。对于 Atmel SAMA5D3-Xplained，配置文件是`include/configs/sama5d3_xplained.h`。此外，在`configs`目录中为该板卡提供了两种配置，分别是：

+   `configs/sama5d3_xplained_mmc_defconfig`

+   `configs/sama5d3_xplained_nandflash_defconfig`

这些配置用于定义板卡**Secondary Program Loader**（**SPL**）初始化方法。SPL 代表从 U-Boot 源代码构建的一个小型二进制文件，放置在 SRAM 内存中，用于将 U-Boot 加载到 RAM 内存中。通常，它的内存小于 4KB，这就是引导序列的样子：

![U-Boot 引导程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00308.jpeg)

在实际开始为特定板卡构建 U-Boot 源代码之前，必须指定板卡配置。对于 Atmel SAMA5_Xplained 开发板，如前图所示，有两种可用的配置。配置是通过使用`make ARCH=arm CROSS_COMPILE=${CC} sama5d3_xplained_nandflash_defconfig`命令完成的。在这个命令后面，将创建`include/config.h`文件。这个头文件包含了针对所选板卡、架构、CPU 以及特定板卡头文件的定义。从`include/config.h`文件中读取的`CONFIG_*`变量包括了编译过程的确定。配置完成后，可以开始为 U-Boot 进行构建。

另一个可能非常有用的示例涉及引导嵌入式系统的另一种情况，即需要使用 NOR 存储器。在这种情况下，我们可以看一个特定的示例。这也在 Christopher Hallinan 的《嵌入式 Linux 入门》中有很好的描述，其中讨论了 AMCC PowerPC 405GP 的处理器。该处理器的硬编码地址为 0xFFFFFFFC，并且可以使用`.resetvec`，重置向量位置来查看。还指定了这一部分的其余部分只有值`1`直到 0xFFFFFFFF 堆栈的末尾；这意味着空的闪存存储器数组只包含值`1`。有关此部分的信息可在`resetvec.S`文件中找到，该文件位于`arch/powerpc/cpu/ppc4xx/resetvec.S`。`resetvec.S`文件的内容如下：

```
 /* Copyright MontaVista Software Incorporated, 2000 */
#include <config.h>
  .section .resetvec,"ax"
#if defined(CONFIG_440)
  b _start_440
#else
#if defined(CONFIG_BOOT_PCI) && defined(CONFIG_MIP405)
  b _start_pci
#else
  b _start
#endif
#endif
```

检查此文件的源代码，可以看到在这一部分中只定义了一条指令，而不管可用的配置选项如何。

U-Boot 的配置通过两种类型的配置变量完成。第一种是`CONFIG_*`，它引用了用户可以配置以启用各种操作功能的配置选项。另一个选项称为`CFG_*`，用于配置设置和引用硬件特定的细节。`CFG_*`变量通常需要对硬件平台、外围设备和处理器有很好的了解。SAMA5D3 Xplained 硬件平台的配置文件位于`include/config.h`头文件中，如下所示：

```
/* Automatically generated - do not edit */
#define CONFIG_SAMA5D3  1
#define CONFIG_SYS_USE_NANDFLASH        1
#define CONFIG_SYS_ARCH  "arm"
#define CONFIG_SYS_CPU   "armv7"
#define CONFIG_SYS_BOARD "sama5d3_xplained"
#define CONFIG_SYS_VENDOR "atmel"
#define CONFIG_SYS_SOC    "at91"
#define CONFIG_BOARDDIR board/atmel/sama5d3_xplained
#include <config_cmd_defaults.h>
#include <config_defaults.h>
#include <configs/sama5d3_xplained.h>
#include <asm/config.h>
#include <config_fallbacks.h>
#include <config_uncmd_spl.h>
```

此处提供的配置变量代表 SAMA5D3 Xplained 板的相应配置。这些配置的一部分涉及用户与引导加载程序的交互的一些标准命令。这些命令可以根据需要添加或删除，以扩展或减少可用命令行界面的命令。

有关 U-Boot 可配置命令界面的更多信息，请参阅[`www.denx.de/wiki/view/DULG/UBootCommandLineInterface`](http://www.denx.de/wiki/view/DULG/UBootCommandLineInterface)。

## 引导 U-Boot 选项

在工业环境中，与 U-Boot 的交互主要通过以太网接口完成。以太网接口不仅能够更快地传输操作系统映像，而且比串行连接更不容易出错。

引导加载程序内部的一个最重要的功能与对动态主机控制协议（DHCP）、简单文件传输协议（TFTP）甚至引导协议（BOOTP）的支持有关。BOOTP 和 DHPC 使以太网连接能够自行配置并从专用服务器获取 IP 地址。TFTP 使得通过 TFTP 服务器下载文件成为可能。目标设备与 DHCP/BOOTP 服务器之间传递的消息在下图中以更通用的方式表示。最初，硬件平台发送一个广播消息，到达所有可用的 DHCP/BOOTP 服务器。每个服务器都会发送其提供的 IP 地址，客户端接受最适合其目的的那个，并拒绝其他的。

![引导 U-Boot 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00309.jpeg)

目标设备与 DHCP/BOOTP 通信完成后，它将保留一个特定于目标的配置，其中包含主机名、目标 IP 和硬件以太网地址（MAC 地址）、子网掩码、tftp 服务器 IP 地址甚至是 TFTP 文件名。这些信息绑定到以太网端口，并在引导过程中后续使用。

对于引导映像，U-Boot 提供了许多与存储子系统支持相关的功能。这些选项包括 RAM 引导、MMC 引导、NAND 引导、NFS 引导等等。对这些选项的支持并不总是容易的，可能涉及硬件和软件的复杂性。

## 移植 U-Boot

我之前提到过，U-Boot 是最常用和知名的引导加载程序之一。这也是因为它的架构使得在新的开发平台和处理器上进行移植变得非常容易。同时，还有大量可用的开发平台可以作为参考。任何有兴趣移植新平台的开发人员首先应该做的事情是检查`board`和`arch`目录，以建立它们的基线，并同时识别它们与其他 CPU 和可用板子的相似之处。

`board.cfg`文件是注册新平台的起点。在这里，应该添加以下信息作为表格行：

+   状态

+   架构

+   CPU

+   SOC

+   供应商

+   板子名称

+   目标

+   选项

+   维护者

要移植类似于 SAMA5D3 Xplained 的机器，可以查阅的目录之一是`arch`目录。它包含了一些文件，比如`board.c`，其中包含了与板子和 SOC 的初始化过程相关的信息。最值得注意的过程是`board_init_r()`，它在 RAM 中重新定位后对板子和外设进行设置和探测，`board_init_f()`，它在 RAM 中重新定位之前识别堆栈大小和保留地址，以及`init_sequence[]`，它在`board_init_f`内部用于外设的设置。在相同位置内的其他重要文件还有`bootm.c`和`interrupts.c`文件。前者主要负责从内存中引导操作系统，后者负责实现通用中断。

`board`目录还有一些有趣的文件和函数需要在这里提到，比如`board/atmel/sama5d3_xplained/sama5d3_xplained.c`文件。它包含了一些函数，比如`board_init()`、`dram_init()`、`board_eth_init()`、`board_mmc_init()`、`spl_board_init()`和`mem_init()`，用于初始化，其中一些被`arch/arm/lib/board.c`文件调用。

以下是一些其他相关的目录：

+   `common`：这包含了用户命令、中间件、用于中间件和用户命令之间的接口的 API，以及所有可用板子使用的其他函数和功能。

+   `drivers`：这包含了各种设备驱动程序和中间件 API 的驱动程序，比如`drivers/mmc/mmc.c`、`drivers/pci/pci.c`、`drivers/watchdog/at91sam9_wdt.c`等。

+   `fs`：各种支持的文件系统，如 USB、SD 卡、Ext2 FAT 等都可以在这里找到。

+   `include`：这代表了大多数板子所需的所有头文件的位置。SOC 和其他软件也可用。在 include/configs 中，可以找到特定于板子的配置，并包括从 Linux 导入的头文件；这些可以用于各种设备驱动程序、移植或其他字节操作。

+   `tools`：这是工具的位置，比如`checkpatch.pl`，这是一个用于发送到邮件列表之前用作编码风格检查的补丁检查工具，或者`mkimage.c`工具。这也用于 U-Boot 通用头文件的生成，以便制作 Linux 二进制文件，并确保它们能够使用 U-Boot 引导。

有关 SAMA5D3 Xplained 板的更多信息可以在相应的 doc 目录和`README`文件中找到，例如`README.at91`、`README.at91-soc`、`README.atmel_mci`、`README.atmel_pmecc`、`README.ARM-memory-map`等。

对于有兴趣提交对 U-Boot 进行新开发板、CPU 或 SOC 移植时所做的更改的人，应遵循一些规则。所有这些都与`git`交互有关，并帮助您确保正确维护您的分支。

开发人员应该做的第一件事是跟踪对应于本地分支的上游分支。另一个建议是忘记`git` `merge`，而是使用`git` `rebase`。使用`git fetch`命令可以与上游存储库保持联系。要使用补丁，需要遵循一些一般规则，并且补丁只能有一个逻辑更改，可以是以下任何一个：

+   更改不应包含无关或不同的修改；每个更改集只有一个补丁可用和可接受

+   提交应尽可能使用`git-bisect`来检测源代码中的错误时进行调试

+   如果一组修改影响了多个文件，则所有这些文件都应在同一个补丁中提交

+   补丁需要进行审查，而且非常彻底

让我们看一下下面的图表，它说明了 git rebase 操作：

![移植 U-Boot](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00310.jpeg)

如前面和后面的图表所示，**git rebase**操作已将工作从一个分支重新创建到另一个分支。来自一个分支的每个提交都可以在后续的一个分支上使用，就在它的最后一个提交之后。

![移植 U-Boot](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00311.jpeg)

另一方面，`git merge`操作是一个具有两个父级的新提交：从中进行移植的分支和进行合并的新分支。实际上，它将一系列提交收集到一个具有不同提交 ID 的分支中，这就是为什么它们难以管理。

![移植 U-Boot](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00312.jpeg)

有关`git`交互的更多信息可以在[`git-scm.com/documentation`](http://git-scm.com/documentation)或[`www.denx.de/wiki/U-Boot/Patches`](http://www.denx.de/wiki/U-Boot/Patches)找到。

几乎总是在 U-Boot 中移植新功能时，都涉及调试。对于 U-Boot 调试器，可能会出现两种不同的情况：

+   第一种情况是`lowlevel_init`未被执行

+   第二种情况是`lowlevel_init`被执行；这是最为人所知的情况。

在接下来的几行中，将考虑第二种情况：为 U-Boot 启用调试会话的基线。为了确保可以进行调试，需要执行`elf`文件。此外，它不能直接操作，因为链接地址将被重定位。为此，应该使用一些技巧：

+   第一步是确保环境干净，旧对象不再可用：`make clean`

+   下一步是确保依赖项已清理：`find ./ | grep depend | xargs rm`

+   清理完成后，目标构建可以开始，并且输出可以重定向到日志文件中：`make sama5d3_xplained 2>&1 > make.log`

+   生成的输出应重命名以避免多个板的调试问题：`mv u-boot.bin u-boot_sama5d3_xplained.bin`

+   在板配置文件中启用 DEBUG 很重要；在`include/configs/ sama5d3_xplained.h`中，添加`#define` DEBUG 行

重定位发生后可以设置早期开发平台，并且应在重定位结束后设置适当的断点。需要重新加载 U-Boot 的符号，因为重定位将移动链接地址。对于所有这些任务，`gdb`脚本被指定为`gdb gdb-script.sh`：

```
#!/bin/sh
${CROSS_COMPILE}-gdb u-boot –command=gdb-command-script.txt

vim gdb-command-script.txt
target remote ${ip}:${port}
load
set symbol-reloading
# break the process before calling board_init_r() function
b start.S:79
c
…
# the symbol-file need to be align to the address available after relocation
add-symbol-file u-boot ${addr}
# break the process at board_init_r() function for single stepping b board.c:494
```

### 注意

有关重定位的更多信息可以在`doc/README.arm-relocation`中找到。

# Yocto 项目

Yocto Project 使用各种配方来定义与每个支持的引导加载程序的交互。由于引导启动有多个阶段，BSP 内也需要多个配方和包。用于各种引导加载程序的配方与 Yocto 世界中的任何其他配方并无不同。然而，它们有一些使它们独特的细节。

我们将在这里关注的板子是`sama5d3_xplained`开发板，它位于`meta-atmel`层内。在这个层内，第一阶段和第二阶段引导加载程序的相应配方可以在`recipes-bsp`目录中找到。在这里，我指的是`at91bootstrap`和`u-boot`配方。关于第一阶段和第二阶段引导加载程序有一些误解。它们可能被称为第二级和第三级引导加载程序，因为在讨论中可能会考虑引导 ROM 代码。在本书中，我们更愿意称它们为第一阶段和第二阶段引导加载程序。

`AT91bootstrap`包代表了 Atmel 公司为其 SOC 提供的第一阶段引导加载程序。它管理硬件初始化，并执行从内存中的引导介质下载第二阶段引导加载程序；它在最后启动它。在`meta-atmel`层中，第二阶段引导加载程序是`u-boot`，它稍后用于 Linux 操作系统的引导。

通常，在 BSP 层内，支持多个开发板，这意味着也提供了多个版本和引导加载程序包。然而，它们之间的区别在于机器配置。对于 SAMA5D3 Xplained 开发板，机器配置可在`conf/machine/sama5d3_xplained`文件中找到。在这个文件中，定义了首选的引导加载程序版本、提供者和配置。如果这些配置不是`MACHINE`特定的，它们也可以在`package`配方中执行。

这是`sama5d3_xplained`开发板可用的配置之一：

```
PREFERRED_PROVIDER_virtual/bootloader = "u-boot-at91"
UBOOT_MACHINE ?= "sama5d3_xplained_nandflash_config"
UBOOT_ENTRYPOINT = "0x20008000"
UBOOT_LOADADDRESS = "0x20008000"

AT91BOOTSTRAP_MACHINE ?= "sama5d3_xplained"
```

# 摘要

在本章中，您将了解引导加载程序的信息，特别关注 U-Boot 引导加载程序。我们还讨论了与 U-Boot 交互、移植、调试、引导加载程序的一般信息、U-Boot 替代方案以及嵌入式环境中的引导序列相关的主题。还有一个与 Yocto Project 相关的部分，介绍了用于支持 BSP 内各种引导加载程序的机制。本章中提出了一些练习，它们为这个主题提供了更多的清晰度。

在下一章中，我们将讨论 Linux 内核，其特性和源代码、模块和驱动程序，以及一般来说，与 Linux 内核交互所需的大部分信息。由于您已经对此有所了解，我们还将集中讨论 Yocto Project 以及它如何能够与多个板子和练习的各种内核版本一起工作。这应该有助于您理解所呈现的信息。


# 第四章：Linux 内核

在本章中，您不仅将了解有关 Linux 内核的一般信息，还将了解有关它的具体信息。本章将从 Linux 的历史和作用的简要介绍开始，然后继续解释其各种特性。不会省略与 Linux 内核源代码交互的步骤。您将了解到获取 Linux 内核映像的步骤，以及新**ARM 机器**的移植意味着什么，以及在一般情况下使用调试各种问题的方法。最后，将切换到 Yocto 项目，展示如何为给定的机器构建 Linux 内核，以及如何集成和稍后从根文件系统映像中使用外部模块。

本章将让您了解 Linux 内核和 Linux 操作系统。没有历史组成部分，这个演示是不可能的。Linux 和 UNIX 通常被放在同一历史背景下，但尽管 Linux 内核出现在 1991 年，Linux 操作系统很快成为 UNIX 操作系统的替代品，但这两个操作系统是同一个家族的成员。考虑到这一点，UNIX 操作系统的历史不能从其他地方开始。这意味着我们需要回到 40 多年前，更准确地说，大约 45 年前的 1969 年，当丹尼斯·里奇和肯·汤普森开始开发 UNIX 时。

UNIX 的前身是**多路信息和计算服务**（**Multics**），这是一个多用户操作系统项目，当时并不是最佳状态。自从 Multics 在 1969 年夏天成为贝尔实验室计算机科学研究中心无法实现的解决方案后，一个文件系统设计诞生了，后来成为今天所知的 UNIX。随着时间的推移，由于其设计和源代码随之分发，它被移植到了多台机器上。UNIX 最多产的贡献者是加州大学伯克利分校。他们还开发了自己的 UNIX 版本，名为**伯克利软件发行**（**BSD**），首次发布于 1977 年。直到 1990 年代，多家公司开发并提供了自己的 UNIX 发行版，它们的主要灵感来自伯克利或 AT&T。所有这些都帮助 UNIX 成为一个稳定、健壮和强大的操作系统。UNIX 作为操作系统强大的特点包括：

+   UNIX 很简单。它使用的系统调用数量减少到只有几百个，它们的设计是基本的

+   在 UNIX 中，一切都被视为文件，这使得数据和设备的操作更简单，并且最小化了用于交互的系统调用。

+   更快的进程创建时间和`fork()`系统调用。

+   UNIX 内核和实用程序都是用 C 语言编写的，这使得它易于移植和访问。

+   简单而健壮的**进程间通信**（**IPC**）原语有助于创建快速和简单的程序，以最佳方式完成一件事。

如今，UNIX 是一个成熟的操作系统，支持虚拟内存、TCP/IP 网络、需求分页、抢占式多任务处理和多线程等功能。其功能覆盖范围广泛，从小型嵌入式设备到拥有数百个处理器的系统。它的发展已经超越了 UNIX 是一个研究项目的想法，它已经成为一个通用的操作系统，几乎适用于任何需求。所有这些都是由于其优雅的设计和经过验证的简单性。它能够在不失去简单性的能力的情况下发展。

Linux 是 UNIX 变体**Minix**的替代解决方案，Minix 是一个为教学目的而创建的操作系统，但它缺乏与系统源代码的简单交互。由于 Minix 的许可证，对源代码的任何更改都不容易集成和分发。Linus Torvalds 最初在终端仿真器上开始工作，以连接到他的大学的其他 UNIX 系统。在同一个学年内，仿真器演变成了一个完整的 UNIX 系统。他在 1991 年发布了供所有人使用的版本。

Linux 最吸引人的特点之一是它是一个开源操作系统，其源代码在 GNU GPL 许可证下可用。在编写 Linux 内核时，Linus Torvalds 从可用的 UNIX 变体中选择了最佳的设计选择和功能作为灵感的来源。它的许可证是推动它成为今天强大力量的原因。它吸引了大量的开发人员，他们帮助改进了代码，修复了错误等等。

今天，Linux 是一个经验丰富的操作系统，能够在多种架构上运行。它能够在比手表还小的设备上运行，也能在超级计算机集群上运行。它是我们这个时代的新感觉，并且正在以越来越多样化的方式被公司和开发人员采用。对 Linux 操作系统的兴趣非常强烈，这不仅意味着多样性，还提供了大量的好处，从安全性、新功能、嵌入式解决方案到服务器解决方案等等。

Linux 已经成为一个真正的由互联网上的庞大社区开发的协作项目。尽管在这个项目内部进行了大量的变化，但 Linus 仍然是它的创造者和维护者。变化是我们周围一切的不断因素，这也适用于 Linux 及其维护者，现在被称为 Greg Kroah-Hartman，已经担任内核维护者两年了。在 Linus 在场的时期，Linux 内核似乎是一个松散的开发者社区。这可能是因为 Linus 全球知名的严厉评论。自从 Greg 被任命为内核维护者以来，这种形象逐渐消失。我期待未来的岁月。

# Linux 内核的作用

具有令人印象深刻的代码行数，Linux 内核是最重要的开源项目之一，同时也是最大的开源项目之一。Linux 内核构成了一个软件部分，帮助硬件接口，是在每个人的 Linux 操作系统中运行的最低级别代码。它被用作其他用户空间应用程序的接口，如下图所示：

![Linux 内核的作用](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00313.jpeg)

Linux 内核的主要作用如下：

+   它提供一组可移植的硬件和架构 API，为用户空间应用程序提供使用必要硬件资源的可能性。

+   它有助于管理硬件资源，如 CPU、输入/输出外设和内存。

+   它用于管理不同应用程序对必要硬件资源的并发访问和使用。

为了确保前述角色被充分理解，一个例子将非常有用。让我们假设在给定的 Linux 操作系统中，一些应用程序需要访问相同的资源，如网络接口或设备。对于这些元素，内核需要复用资源，以确保所有应用程序都可以访问它。

# 深入了解 Linux 内核的特性

本节将介绍 Linux 内核中的一些可用功能。它还将涵盖关于每个功能的信息，它们如何使用，代表什么，以及有关每个特定功能的任何其他相关信息。每个功能的介绍使您熟悉 Linux 内核中一些可用功能的主要作用，以及 Linux 内核和其源代码的一般情况。

更一般地说，Linux 内核具有一些最有价值的功能，如下所示：

+   稳定性和可靠性

+   可扩展性

+   可移植性和硬件支持

+   符合标准

+   各种标准之间的互操作性

+   模块化

+   编程的便利性

+   社区的全面支持

+   安全性

前述功能并不构成实际功能，但它们在项目的开发过程中有所帮助，今天仍在帮助着它。话虽如此，有很多功能已经实现，例如快速用户空间互斥（futex）、netfileters、简化强制访问控制内核（smack）等。完整的列表可以在[`en.wikipedia.org/wiki/Category:Linux_kernel_features`](http://en.wikipedia.org/wiki/Category:Linux_kernel_features)上访问和学习。

## 内存映射和管理

在讨论 Linux 中的内存时，我们可以将其称为物理内存和虚拟内存。RAM 内存的隔间用于包含 Linux 内核变量和数据结构，其余内存用于动态分配，如下所述：

![内存映射和管理](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00314.jpeg)

物理内存定义了能够维护内存的算法和数据结构，它是在页面级别相对独立地由虚拟内存完成的。在这里，每个物理页面都有一个与之关联的`struct page`描述符，用于包含有关物理页面的信息。每个页面都有一个定义的`struct page`描述符。该结构的一些字段如下：

+   `_count`：这代表页面计数器。当它达到`0`值时，页面将被添加到空闲页面列表中。

+   `虚拟`：这代表与物理页面关联的虚拟地址。**ZONE_DMA**和**ZONE_NORMAL**页面始终被映射，而**ZONE_HIGHMEN**不总是被映射。

+   `标志`：这代表了描述页面属性的一组标志。

物理内存的区域以前已经被划分。物理内存被分割成多个节点，这些节点具有共同的物理地址空间和快速的本地内存访问。其中最小的是**ZONE_DMA**，介于 0 到 16Mb 之间。接下来是**ZONE_NORMAL**，它是介于 16Mb 到 896Mb 之间的 LowMem 区域，最大的是**ZONE_HIGHMEM**，介于 900Mb 到 4GB/64Gb 之间。这些信息可以在前面和后面的图像中都可见：

![内存映射和管理](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00315.jpeg)

虚拟内存既用于用户空间，也用于内核空间。为内存区域分配意味着分配物理页面以及地址空间区域的分配；这既在页表中，也在操作系统内部可用的内部结构中完成。页表的使用因架构类型而异。对于**复杂指令集计算**（CISC）架构，页表由处理器使用，但对于**精简指令集计算**（RISC）架构，页表由核心用于页查找和**转换查找缓冲器**（TLB）添加操作。每个区域描述符用于区域映射。它指定了区域是否被映射以供文件使用，如果区域是只读的，写时复制的等等。地址空间描述符由操作系统用于维护高级信息。

用户空间和内核空间上下文之间的内存分配是不同的，因为内核空间内存分配无法以简单的方式分配内存。这种差异主要是因为内核上下文中的错误管理不容易完成，或者至少不是以与用户空间上下文相同的方式完成。这是本节将介绍的问题之一，以及解决方案，因为它有助于读者了解在 Linux 内核上下文中如何进行内存管理。

内核用于内存处理的方法是本节将讨论的第一个主题。这是为了确保您了解内核用于获取内存的方法。虽然处理器的最小可寻址单元是字节，但负责虚拟到物理转换的**内存管理单元**（**MMU**）的最小可寻址单元是页面。页面的大小因架构而异。它负责维护系统的页表。大多数 32 位架构使用 4KB 页面，而 64 位架构通常使用 8KB 页面。对于 Atmel SAMA5D3-Xplained 板，`struct page`结构的定义如下：

```
struct page {
        unsigned long 	flags;
        atomic_t        _count;
        atomic_t        _mapcount;
        struct address_space *mapping;
        void        *virtual;
        unsigned long 	debug_flags;
        void        *shadow;
        int        _last_nid;

};
```

这是页面结构中最重要的字段之一。例如，`flags`字段表示页面的状态；这包含信息，例如页面是否脏了，是否被锁定，或者处于另一个有效状态。与此标志相关的值在`include/linux/page-flags-layout.h`头文件中定义。`virtual`字段表示与页面关联的虚拟地址，`count`表示页面的计数值，通常可以通过`page_count()`函数间接访问。所有其他字段都可以在`include/linux/mm_types.h`头文件中找到。

内核将硬件划分为各种内存区域，主要是因为物理内存中有一些页面对于一些任务是不可访问的。例如，有些硬件设备可以执行 DMA。这些操作只与物理内存的一个区域进行交互，简称为`ZONE_DMA`。对于 x86 架构，它在 0-16 Mb 之间可访问。

内核源代码中定义了四个主要的内存区域和另外两个不太显著的内存区域，这些定义在`include/linux/mmzone.h`头文件中。区域映射也与 Atmel SAMA5D3-Xplained 板的体系结构有关。我们有以下区域定义：

```
enum zone_type {
#ifdef CONFIG_ZONE_DMA
        /*
         * ZONE_DMA is used when there are devices that are not able
         * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
         * carve out the portion of memory that is needed for these devices.
         * The range is arch specific.
         *
         * Some examples
         *
         * Architecture         Limit
         * ---------------------------
         * parisc, ia64, sparc  <4G
         * s390                 <2G
         * arm                  Various
         * alpha                Unlimited or 0-16MB.
         *
         * i386, x86_64 and multiple other arches
         *                      <16M.
         */
        ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
        /*
         * x86_64 needs two ZONE_DMAs because it supports devices that are
         * only able to do DMA to the lower 16M but also 32 bit devices that
         * can only do DMA areas below 4G.
         */
        ZONE_DMA32,
#endif
        /*
         * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
         * performed on pages in ZONE_NORMAL if the DMA devices support
         * transfers to all addressable memory.
         */
        ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
        /*
         * A memory area that is only addressable by the kernel through
         * mapping portions into its own address space. This is for example
         * used by i386 to allow the kernel to address the memory beyond
         * 900MB. The kernel will set up special mappings (page
         * table entries on i386) for each page that the kernel needs to
         * access.
         */
        ZONE_HIGHMEM,
#endif
        ZONE_MOVABLE,
        __MAX_NR_ZONES
};
```

有一些分配需要与多个区域进行交互。一个例子是普通分配，可以使用`ZONE_DMA`或`ZONE_NORMAL`。`ZONE_NORMAL`更受青睐，因为它不会干扰直接内存访问，尽管当内存使用完全时，内核可能会使用除正常情况下使用的区域之外的其他可用区域。可用的内核是一个**struct zone**结构，定义了每个区域的相关信息。对于 Atmel SAMA5D3-Xplained 板，该结构如下所示：

```
struct zone {
        unsigned long 	watermark[NR_WMARK];
        unsigned long 	percpu_drift_mark;
        unsigned long 	lowmem_reserve[MAX_NR_ZONES];
        unsigned long 	dirty_balance_reserve;
        struct per_cpu_pageset __percpu *pageset;
        spinlock_t        lock;
        int        all_unreclaimable;
        struct free_area        free_area[MAX_ORDER];
        unsigned int            compact_considered;
        unsigned int            compact_defer_shift;
        int                     compact_order_failed;
        spinlock_t              lru_lock;
        struct lruvec           lruvec;
        unsigned long         pages_scanned;
        unsigned long         flags;
        unsigned int        inactive_ratio;
        wait_queue_head_t       * wait_table;
        unsigned long         wait_table_hash_nr_entries;
        unsigned long         wait_table_bits;
        struct pglist_data    *zone_pgdat;
        unsigned long         zone_start_pfn;
        unsigned long         spanned_pages;
        unsigned long         present_pages;
        unsigned long         managed_pages;
        const char              *name;
};
```

如您所见，定义结构的区域是一个令人印象深刻的区域。一些最有趣的字段由`watermark`变量表示，其中包含所定义区域的高、中和低水印。`present_pages`属性表示区域内的可用页面。`name`字段表示区域的名称，还有其他字段，例如`lock`字段，一个用于保护区域结构免受同时访问的自旋锁。所有其他字段都可以在 Atmel SAMA5D3 Xplained 板的相应`include/linux/mmzone.h`头文件中找到。

有了这些信息，我们可以继续并了解内核如何实现内存分配。所有必要的内存分配和内存交互的可用函数都在`linux/gfp.h`头文件中。其中一些函数是：

```
struct page * alloc_pages(gfp_t gfp_mask, unsigned int order)
```

这个函数用于在连续位置分配物理页面。最后，如果分配成功，则返回值由第一个页面结构的指针表示，如果发生错误，则返回`NULL`：

```
void * page_address(struct page *page)
```

这个函数用于获取相应内存页面的逻辑地址：

```
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
```

这个函数类似于`alloc_pages()`函数，但不同之处在于返回变量是在`struct page * alloc_page(gfp_t gfp_mask)`返回参数中提供的：

```
unsigned long __get_free_page(gfp_t gfp_mask)
struct page * alloc_page(gfp_t gfp_mask)
```

前两个函数是类似的函数的包装器，不同之处在于这个函数只返回一个页面信息。这个函数的顺序具有`zero`值：

```
unsigned long get_zeroed_page(unsigned int gfp_mask)
```

前面的函数就像其名称所示。它返回一个充满`zero`值的页面。这个函数与`__get_free_page()`函数的区别在于，在被释放后，页面被填充为`zero`值：

```
void __free_pages(struct page *page, unsigned int order)
void free_pages(unsigned long addr, unsigned int order)
void free_page(unsigned long addr)
```

前面的函数用于释放给定的分配页面。传递页面时应谨慎，因为内核无法检查所提供的信息。

### 页面缓存和页面写回

通常磁盘比物理内存慢，所以这是内存优于磁盘存储的原因之一。对于处理器的缓存级别也是一样：它离处理器越近，对 I/O 访问就越快。将数据从磁盘移动到物理内存的过程称为**页面缓存**。相反的过程被定义为**页面写回**。这两个概念将在本小节中介绍，但主要是关于内核上下文。

内核第一次调用`read()`系统调用时，会验证数据是否存在于页面缓存中。在 RAM 中找到页面的过程称为**缓存命中**。如果数据不在那里，则需要从磁盘读取数据，这个过程称为**缓存未命中**。

当内核发出**write()**系统调用时，关于这个系统调用的缓存交互有多种可能性。最简单的一种是不缓存写系统调用操作，只将数据保留在磁盘中。这种情况称为**无写缓存**。当写操作同时更新物理内存和磁盘数据时，该操作称为**写透缓存**。第三个选项由**写回缓存**表示，其中页面被标记为脏。它被添加到脏列表中，随着时间的推移，它被放在磁盘上并标记为非脏。脏关键字的最佳同义词由同步关键字表示。

### 进程地址空间

除了自己的物理内存外，内核还负责用户空间进程和内存管理。为每个用户空间进程分配的内存称为**进程地址空间**，它包含给定进程可寻址的虚拟内存地址。它还包含进程在与虚拟内存交互时使用的相关地址。

通常，进程接收一个平面的 32 位或 64 位地址空间，其大小取决于体系结构类型。然而，有些操作系统分配了**分段地址空间**。在线程之间提供了共享地址空间的可能性。虽然进程可以访问大量的内存空间，但通常只有权限访问内存的一部分。这被称为**内存区域**，意味着进程只能访问位于可行内存区域内的内存地址。如果它尝试管理位于其有效内存区域之外的内存地址，内核将使用*段错误*通知终止进程。

内存区域包含以下内容：

+   `text`部分映射源代码

+   `数据`部分映射已初始化的全局变量

+   `bss`部分映射未初始化的全局变量

+   `零页`部分用于处理用户空间堆栈

+   `共享库文本`，`bss`和数据特定部分

+   映射文件

+   匿名内存映射通常与`malloc()`等函数相关联

+   共享内存段

进程地址空间在 Linux 内核源代码中通过**内存描述符**进行定义。这个结构被称为`struct mm_struct`，它在`include/linux/mm_types.h`头文件中定义，并包含与进程地址空间相关的信息，如使用地址空间的进程数量、内存区域列表、最后使用的内存区域、可用的内存区域数量、代码、数据、堆和栈部分的起始和结束地址。

对于内核线程，没有与之关联的进程地址空间；对于内核来说，进程描述符结构被定义为`NULL`。这样，内核表明内核线程没有用户上下文。内核线程只能访问与所有其他进程相同的内存。内核线程没有用户空间中的任何页面或对用户空间内存的访问权限。

由于处理器只能使用物理地址，因此需要进行物理和虚拟内存之间的转换。这些操作由页表完成，页表将虚拟地址分割为较小的组件，并具有用于指向目的的关联索引。在大多数可用的板和体系结构中，页表查找由硬件处理；内核负责设置它。

## 进程管理

进程是 Linux 操作系统中的基本单元，同时也是一种抽象形式。实际上，它是一个正在执行的程序，但程序本身不是一个进程。它需要处于活动状态并具有相关联的资源。通过使用`fork()`函数，进程能够成为父进程，从而生成一个子进程。父进程和子进程都驻留在单独的地址空间中，但它们都具有相同的内容。`exec()`函数族能够执行不同的程序，创建一个地址空间，并将其加载到该地址空间中。

使用`fork()`时，父进程的资源会被复制给子进程。这个函数的实现方式非常有趣；它使用`clone()`系统调用，其基础包含`copy_process()`函数。这个函数执行以下操作：

+   调用`dup_task_struct()`函数创建一个新的内核栈。为新进程创建`task_struct`和`thread_info`结构。

+   检查子进程是否超出内存区域的限制。

+   子进程与父进程有所不同。

+   将其设置为`TASK_UNINTERRUPTIBLE`以确保它不运行。

+   更新标志。

+   `PID`与子进程相关联。

+   检查已设置的标志，并根据它们的值执行适当的操作。

+   在获取子进程指针时执行清理过程。

Linux 中的线程与进程非常相似。它们被视为共享各种资源（如内存地址空间、打开文件等）的进程。线程的创建类似于普通任务，唯一的例外是`clone()`函数，它传递了提到共享资源的标志。例如，clone 函数调用一个线程，即`clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND, 0)`，而对于正常的 fork 看起来类似于`clone(SIGCHLD, 0)`。

内核线程的概念出现是为了解决在内核上下文的后台运行任务所涉及的问题。内核线程没有地址空间，只能在内核上下文中使用。它具有与普通进程相同的属性，但仅用于特殊任务，如`ksoftirqd`、`flush`等。

在执行结束时，需要终止进程以释放资源，并通知执行进程的父进程。最常用于终止进程的方法是调用`exit()`系统调用。此过程需要一些步骤：

1.  设置`PF_EXITING`标志。

1.  调用`del_timer_sync()`函数来删除内核定时器。

1.  在编写会计和日志信息时调用`acct_update_integrals()`函数。

1.  调用`exit_mm()`来释放进程的`mm_struct`结构。

1.  调用`exit_sem()`来从 IPC 信号量中出队进程。

1.  调用`exit_files()`和`exit_fs()`函数来删除与各种文件描述符的链接。

1.  应设置任务退出代码。

1.  调用`exit_notify()`通知父进程，并将任务退出状态设置为`EXIT_ZOMBIE`。

1.  调用`schedule()`切换到新进程。

在执行了前述步骤之后，与该任务关联的对象被释放，并且变得不可运行。它的内存仅作为其父进程的信息存在。在其父进程宣布此信息对其无用后，此内存将被系统释放使用。

## 进程调度

进程调度程序决定为可运行的进程分配哪些资源。它是一种负责多任务处理、资源分配给各种进程，并决定如何最佳设置资源和处理器时间的软件。它还决定哪些进程应该接下来运行。

Linux 调度程序的第一个设计非常简单。当进程数量增加时，它无法很好地扩展，因此从 2.5 内核版本开始，开发了一个新的调度程序。它被称为**O(1)调度程序**，为时间切片计算提供了常数时间算法，并且在每个处理器基础上定义了运行队列。虽然它非常适合大型服务器，但并不是普通桌面系统的最佳解决方案。从 2.6 内核版本开始，对 O(1)调度程序进行了改进，例如公平调度概念，后来从内核版本 2.6.23 实现为**完全公平调度程序**（**CFS**），成为事实上的调度程序。

CFS 背后有一个简单的想法。它表现得好像我们有一个完美的多任务处理器，每个进程都获得处理器时间的`1/n`切片，而这个时间切片非常小。`n`值代表正在运行的进程数。Con Kolivas 是澳大利亚程序员，他为公平调度实现做出了贡献，也被称为**旋转楼梯截止时间调度器**（**RSDL**）。它的实现需要一个红黑树来平衡自身的优先级，还需要在纳秒级别计算的时间切片。与 O(1)调度程序类似，CFS 应用了权重的概念，这意味着一些进程等待的时间比其他进程长。这是基于加权公平排队算法的。

进程调度程序构成了 Linux 内核中最重要的组件之一，因为它定义了用户与操作系统的一般交互。Linux 内核 CFS 是调度程序，吸引开发人员和用户的原因是它以最合理的方式提供了可伸缩性和性能。

## 系统调用

为了使进程与系统交互，应该提供一个接口，使用户空间应用程序能够与硬件和其他进程进行交互。这些被用作硬件和用户空间之间的接口。它们也被用于确保稳定性、安全性和抽象性。这些是构成内核入口点的常见层，以及陷阱和异常，如下所述：

![系统调用](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00316.jpeg)

与 Linux 系统内大多数系统调用的交互是通过 C 库完成的。它们能够定义一些参数并返回一个值，以显示它们是否成功。通常，值为`零`表示执行成功，如果出现错误，则`errno`变量中将可用错误代码。进行系统调用时，遵循以下步骤：

1.  切换到内核模式。

1.  对内核空间访问的任何限制都被消除。

1.  用户空间的堆栈被传递到内核空间。

1.  来自用户空间的任何参数都会被检查并复制到内核空间。

1.  识别并运行与系统调用相关的例程。

1.  切换到用户空间并继续执行应用程序。

系统调用有与之关联的`syscall`号码，这是一个唯一的数字，用作系统调用的参考，不能更改（无法实现系统调用）。每个系统调用号码的符号常量都在`<sys/syscall.h>`头文件中可用。要检查系统调用的存在，使用`sys_ni_syscall()`，它对于无效的系统调用返回`ENOSYS`错误。

## 虚拟文件系统

Linux 操作系统能够支持多种文件系统选项。这是由于存在**虚拟文件系统**（**VFS**），它能够为大量文件系统类型提供一个通用接口，并处理与它们相关的系统调用。

VFS 支持的文件系统类型可以分为以下三类：

+   **基于磁盘的文件系统**：这些管理本地磁盘或用于磁盘仿真的设备上的内存。其中一些最著名的是：

+   Linux 文件系统，如第二扩展文件系统（Ext2），第三扩展文件系统（Ext3）和第四扩展文件系统（Ext4）

+   UNIX 文件系统，如 sysv 文件系统，UFS，Minix 文件系统等

+   微软文件系统，如 MS-DOS，NTFS（自 Windows NT 起可用）和 VFAT（自 Windows 95 起可用）

+   ISO966 CD-ROM 文件系统和磁盘格式 DVD 文件系统

+   专有文件系统，如来自苹果、IBM 和其他公司的文件系统

+   **网络文件系统**：它们允许在其他计算机上通过网络访问各种文件系统类型。其中最著名的之一是 NFS。当然，还有其他一些，但它们不那么出名。这些包括**Andrew 文件系统**（**AFS**），**Novel 的 NetWare Core Protocol**（**NCP**），**Constant Data Availability**（**Coda**）等。

+   **特殊文件系统**：`/proc`文件系统是这类文件系统的完美例子。这类文件系统使系统应用程序更容易地访问内核的数据结构并实现各种功能。

虚拟文件系统系统调用的实现在这张图片中得到了很好的总结：

![虚拟文件系统](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00317.jpeg)

在前面的图像中，可以看到如何轻松地从一种文件系统类型复制到另一种文件系统类型。它只使用基本的`open()`、`close()`、`read()`、`write()`函数，这些函数对所有其他文件系统交互都可用。然而，它们都在所选文件系统下实现了特定的功能。例如，`open()`系统调用`sys_open()`，它接受与`open()`相同的参数并返回相同的结果。`sys_open()`和`open()`之间的区别在于`sys_open()`是一个更宽松的函数。

其他三个系统调用都有相应的`sys_read()`、`sys_write()`和`sys_close()`函数在内部调用。

# 中断

中断是表示改变处理器执行指令顺序的事件的表示。中断意味着硬件生成的电信号，用于表示已发生的事件，例如按键、复位等。根据其参考系统，中断分为更多类别，如下所示：

+   软件中断：这些通常是从外部设备和用户空间程序触发的异常

+   硬件中断：这些是系统发出的信号，通常表示处理器特定的指令

Linux 中断处理层通过全面的 API 函数为各种设备驱动程序提供了中断处理的抽象。它用于请求、启用、禁用和释放中断，确保在多个平台上保证可移植性。它处理所有可用的中断控制器硬件。

通用中断处理使用`__do_IRQ()`处理程序，能够处理所有可用类型的中断逻辑。处理层分为两个组件：

+   顶部组件用于响应中断

+   顶部组件安排底部在稍后运行

它们之间的区别在于所有可用的中断都被允许在底部上下文中执行。这有助于顶部在底部工作时响应另一个中断，这意味着它能够将其数据保存在特定的缓冲区中，并允许底部在安全环境中运行。

对于底部处理，有四种定义好的机制可用：

+   **软中断**

+   **Tasklets**

+   **工作队列**

+   **内核线程**

这里展示了可用的机制：

![中断](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00318.jpeg)

尽管顶部和底部中断机制的模型看起来很简单，但它具有非常复杂的函数调用机制模型。这个例子展示了 ARM 架构的这一事实：

![中断](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00319.jpeg)

对于中断的顶部组件，在中断源代码中有三个抽象级别。第一个是高级驱动程序 API，具有函数，如`request_irq()`、`free_irq`、`disable_irq()`、`enable_irq()`等。第二个由高级 IRQ 流处理程序表示，这是一个通用层，具有预定义或特定架构的中断流处理程序，用于在设备初始化或引导时响应各种中断。它定义了一些预定义函数，如`handle_level_irq()`、`handle_simple_irq()`、`handle_percpu_irq()`等。第三个由芯片级硬件封装表示。它定义了`struct irq_chip`结构，其中包含在 IRQ 流实现中使用的与芯片相关的函数。其中一些函数是`irq_ack()`、`irq_mask()`和`irq_unmask()`。

模块需要注册中断通道并在之后释放它。支持的请求总数从`0`值计数到 IRQs 的数量-1。这些信息在`<asm/irq.h>`头文件中可用。注册完成后，将处理程序标志传递给`request_irq()`函数，以指定中断处理程序的类型，如下所示：

+   `SA_SAMPLE_RANDOM`：这表明中断可以为熵池做出贡献，即具有强随机属性的位的池，通过对不可预测事件进行采样，例如鼠标移动、按键间的时间、磁盘中断等

+   `SA_SHIRQ`：这表明中断可以在设备之间共享。

+   `SA_INTERRUPT`：这表示快速中断处理程序，因此在当前处理器上禁用中断-这并不是一个非常理想的情况

## 底半部

关于底半部中断处理的第一个机制是由`softirqs`代表的。它们很少使用，但可以在 Linux 内核源代码中的`kernel/softirq.c`文件中找到。在实现方面，它们在编译步骤时静态分配。当在`include/linux/interrupt.h`头文件中添加条目时，它们被创建，并且它们提供的系统信息可以在`/proc/softirqs`文件中找到。虽然不经常使用，但它们可以在异常、中断、系统调用以及由调度程序运行`ksoftirkd`守护程序后执行。

列表中的下一个是任务 let。虽然它们建立在`softirqs`之上，但它们更常用于底半部中断处理。以下是这样做的一些原因：

+   它们非常快

+   它们可以动态创建和销毁

+   它们具有原子和非阻塞代码

+   它们在软中断上下文中运行

+   它们在被调度的同一处理器上运行

任务 let 有一个**struct tasklet_struct**结构可用。这些也可以在`include/linux/interrupt.h`头文件中找到，与`softirqs`不同，任务 let 是不可重入的。

列表中的第三个是工作队列，它代表了与先前介绍的机制相比进行工作分配的不同形式。主要区别如下：

+   它们能够同时在多个 CPU 上运行

+   它们可以进入睡眠状态

+   它们在进程上下文中运行

+   它们可以被调度或抢占

虽然它们可能具有比任务 let 稍大的延迟，但前述特性确实非常有用。任务 let 是围绕`struct workqueue_struct`结构构建的，该结构位于`kernel/workqueue.c`文件中。

底半部机制选项中的最后一个和最新的添加是由内核线程代表的，它们完全在内核模式下操作，因为它们是由内核创建/销毁的。它们出现在 2.6.30 内核发布中，并且具有与工作队列相同的优势，以及一些额外的功能，例如拥有自己的上下文的可能性。预计内核线程最终将取代工作队列和任务 let，因为它们类似于用户空间线程。驱动程序可能希望请求线程化的中断处理程序。在这种情况下，它只需要类似于`request_irq()`的方式使用`request_threaded_irq()`。`request_threaded_irq()`函数提供了将中断处理代码分成两部分的处理程序和`thread_fn`的可能性。除此之外，还调用`quick_check_handler`来检查中断是否来自设备；如果是这种情况，它将需要调用`IRQ_WAKE_THREAD`来唤醒处理程序线程并执行`thread_fn`。

## 执行内核同步的方法

内核正在处理的请求数量类似于服务器必须接收的请求数量。这种情况可能会导致竞争条件，因此需要一个良好的同步方法。有多种策略可用于定义内核控制路径的方式。以下是一个内核控制路径的示例：

![执行内核同步的方法](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00320.jpeg)

前面的图像清楚地说明了为什么同步是必要的。例如，当多个内核控制路径相互关联时，可能会出现竞争条件。为了保护这些关键区域，应采取一些措施。还应考虑到中断处理程序不能被中断，`softirqs`不应该交错。

已经诞生了许多同步原语：

+   **每 CPU 变量**：这是最简单和有效的同步方法之一。它将数据结构乘以每个 CPU 可用。

+   **原子操作**：这指的是原子读-修改-写指令。

+   **内存屏障**：这保证了在屏障之前完成的操作在开始屏障之后的操作之前全部完成。

+   **自旋锁**：这代表一种实现忙等待的锁类型。

+   **信号量**：这是一种实现休眠或阻塞等待的锁形式。

+   **Seqlocks**：这类似于自旋锁，但基于访问计数器。

+   **本地中断禁用**：这禁止了可以在单个 CPU 上延迟使用的功能。

+   **读-拷贝-更新（RCU）**：这是一种旨在保护用于读取的最常用数据结构的方法。它使用指针为共享数据结构提供无锁访问。

通过上述方法，竞争条件情况试图得到解决。开发人员的工作是识别和解决可能出现的所有同步问题。

# 定时器

在 Linux 内核周围，有许多受时间影响的函数。从调度程序到系统正常运行时间，它们都需要一个时间参考，包括绝对时间和相对时间。例如，需要安排在未来进行的事件代表相对时间，实际上意味着有一种方法用于计算时间。

定时器的实现可以根据事件类型而变化。周期性实现由系统定时器定义，它以固定时间间隔发出中断。系统定时器是一个硬件组件，以给定频率发出定时器中断，以更新系统时间并执行必要的任务。还可以使用实时时钟，它是一个带有电池的芯片，即使在系统关闭后也能继续计时。除了系统时间，内核动态管理的动态定时器也可用于计划在特定时间后运行的事件。

定时器中断具有发生窗口，对于 ARM 来说，每秒发生 100 次。这称为**系统定时器频率**或**滴答率**，其单位是**赫兹**（**Hz**）。滴答率因架构而异。对于大多数架构，我们有 100 Hz 的值，还有其他架构的值为 1024 Hz，例如 Alpha 和 Itanium（IA-64）架构。当然，默认值可以更改和增加，但这种操作有其优点和缺点。

更高频率的一些优点包括：

+   定时器将更准确地执行，并且数量更多。

+   使用超时的系统调用以更精确的方式执行

+   正常运行时间测量和其他类似测量变得更加精确

+   进程抢占更准确

另一方面，更高频率的缺点意味着更高的开销。处理器在定时器中断上花费更多时间；此外，由于进行了更多的计算，将会发生功耗的增加。

Linux 操作系统上的总 ticks 数，从启动开始计时，存储在`include/linux/jiffies.h`头文件中的一个名为**jiffies**的变量中。在启动时，这个变量被初始化为零，并且每次发生中断时都会将其值加一。因此，系统正常运行时间的实际值可以以 jiffies/Hz 的形式计算出来。

# Linux 内核交互

到目前为止，您已经了解了 Linux 内核的一些特性。现在，是时候介绍更多关于开发过程、版本控制方案、社区贡献以及与 Linux 内核的交互的信息了。

## 开发过程

Linux 内核是一个众所周知的开源项目。为了确保开发人员知道如何与其交互，将介绍如何使用`git`与该项目进行交互的信息，同时还将介绍一些关于其开发和发布程序的信息。该项目已经发展，其开发流程和发布程序也随之发展。

在介绍实际的开发过程之前，需要了解一些历史。在 Linux 内核项目的 2.6 版本之前，每两三年发布一次版本，并且每个版本都以偶数中间数字标识，如 1.0.x、2.0.x 和 2.6.x。相反，开发分支使用偶数号来定义，如 1.1.x、2.1.x 和 2.5.x，并且它们用于集成各种功能，直到准备好进行主要发布并准备好进行发布。所有次要发布都有名称，如 2.6.32 和 2.2.23，并且它们是在主要发布周期之间发布的。

![开发过程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00321.jpeg)

这种工作方式一直持续到 2.6.0 版本，当时在每个次要版本发布期间在内核中添加了大量功能，并且所有这些功能都非常好地组合在一起，以免引起需要分支出一个新的开发分支的需求。这意味着发布速度更快，可用功能更多。因此，自 2.6.14 内核发布以来，出现了以下变化：

+   所有新的次要发布版本，如 2.6.x，都包含一个两周的合并窗口，在这个窗口中可以引入下一个发布中的一些功能。

+   这个合并窗口将在一个名为 2.6.(x+1)-rc1 的发布测试版本关闭

+   然后是一个 6-8 周的错误修复期，期间应该修复由新增功能引入的所有错误

+   在错误修复间隔期间，对发布候选版本进行了测试，并发布了 2.6.(x+1)-rcY 测试版本

+   在最终测试完成并且最后一个发布候选版本被认为足够稳定之后，将发布一个名为 2.6.(x+1)的新版本，然后这个过程将再次继续

这个过程运行得很好，但唯一的问题是，错误修复只发布给最新的稳定版本的 Linux 内核。人们需要长期支持版本和旧版本的安全更新，以及关于这些长期支持版本的一般信息等。

这个过程随着时间的推移而改变，在 2011 年 7 月，出现了 3.0 Linux 内核版本。它出现了一些小的变化，旨在改变解决先前提到的请求的交互方式。更改是针对编号方案进行的，如下所示：

+   内核官方版本将被命名为 3.x（3.0, 3.1, 3.2 等）

+   稳定版本将被命名为 3.x.y（3.0.1, 3.1.3 等）

尽管这个变化只是从编号方案中删除了一个数字，但这个变化是必要的，因为它标志着 Linux 内核的 20 周年。

由于 Linux 内核每天包含大量的补丁和功能，很难跟踪所有的变化和整体的大局。随着时间的推移，出现了一些网站，如[`kernelnewbies.org/LinuxChanges`](http://kernelnewbies.org/LinuxChanges)和[`lwn.net/`](http://lwn.net/)，帮助开发人员与 Linux 内核的世界保持联系。

除了这些链接，`git`版本控制系统可以提供非常需要的信息。当然，这需要工作站上存在 Linux 内核源克隆。一些提供大量信息的命令包括：

+   `git log`: 这列出了最新的所有提交

+   `git log –p`: 这列出了所有提交及其相应的`diffs`

+   `git tag –l`: 这列出了所有可用的标签

+   `git checkout <tagname>`: 这从工作库中检出一个分支或标签

+   `git log v2.6.32..master`: 这列出了给定标签和最新版本之间的所有更改

+   `git log –p V2.6.32..master MAINTAINERS`: 这列出了`MAINTAINERS`文件中两个给定分支之间的所有差异

当然，这只是一个有用命令的小列表。所有其他命令都可以在[`git-scm.com/docs/`](http://git-scm.com/docs/)上找到。

## 内核移植

Linux 内核支持多种 CPU 架构。每个架构和单独的板都有自己的维护者，这些信息可以在`MAINTAINERS`文件中找到。此外，板的移植差异主要由架构决定，PowerPC 与 ARM 或 x86 非常不同。由于本书关注的开发板是一款搭载 ARM Cortex-A5 核心的 Atmel，本节将尝试关注 ARM 架构。

在我们的情况下，主要关注的是`arch/arm`目录，其中包含诸如`boot`、`common`、`configs`、`crypto`、`firmware`、`kernel`、`kvm`、`lib`、`mm`、`net`、`nwfpe`、`oprofile`、`tools`、`vfp`和`xen`等子目录。它还包含了许多针对不同 CPU 系列特定的目录，例如`mach-*`目录或`plat-*`目录。第一个`mach-*`类别包含了 CPU 和使用该 CPU 的几个板，第二个`plat-*`类别包含特定于平台的代码。一个例子是`plat-omap`，其中包含了`mach-omap1`和`mach-omap2`的通用代码。

自 2011 年以来，ARM 架构的开发发生了很大变化。如果直到那时 ARM 没有使用设备树，那是因为它需要将大部分代码保留在`mach-*`特定目录中，对于每个在 Linux 内核中有支持的板，都会关联一个唯一的机器 ID，并且一个机器结构与包含特定信息和一组回调的每个板相关联。引导加载程序将这个机器 ID 传递给特定的 ARM 注册表，这样内核就知道了板子。

ARM 架构的流行增加是因为工作重构和**设备树**的引入，这大大减少了`mach-*`目录中可用的代码量。如果 SoC 受到 Linux 内核的支持，那么为板添加支持就像在`/arch/arm/boot/dts`目录中定义一个设备树一样简单，例如，对于`<soc-name>-<board-name>.d`，如果需要，包含相关的`dtsi`文件。确保通过将设备树包含到**arch/arm/boot/dts/Makefile**中并为板添加缺失的设备驱动程序来构建**设备树 blob**（**DTB**）。

如果板上没有在 Linux 内核中的支持，需要在`mach-*`目录中进行适当的添加。在每个`mach-*`目录中，有三种类型的文件可用：

+   **通用代码文件**：这些通常只有一个单词的名称，比如`clock.c`，`led.c`等

+   **特定于 CPU 的代码**：这是用于机器 ID 的，通常采用`<machine-ID>*.c`的形式 - 例如，`at91sam9263.c`，`at91sam9263_devices.c`，`sama5d3.c`等

+   **特定于板子的代码**：这通常被定义为 board-*.c，比如`board-carmeva.c`，`board-pcontrol-g20.c`等

对于给定的板子，应首先在`arch/arm/mach-*/Kconfig`文件中进行适当的配置；为此，应该为板子 CPU 确定机器 ID。配置完成后，可以开始编译，因此应该更新`arch/arm/mach-*/Makefile`以确保板子支持所需的文件。另一步是由定义板子和需要在`board-<machine>.c`文件中定义的机器类型号的机器结构表示。

机器结构使用两个宏：`MACHINE_START`和`MACHINE_END`。它们都在`arch/arm/include/asm/march/arch.h`中定义，并用于定义`machine_desc`结构。机器类型号可在`arch/arm/tools/mach_types`文件中找到。该文件用于为板子生成`include/asm-arm/mach-types.h`文件。

### 注意

机器类型的更新编号列表可在[`www.arm.linux.org.uk/developer/machines/download.php`](http://www.arm.linux.org.uk/developer/machines/download.php)上找到。

在第一种情况下，当启动过程开始时，只需要将`dtb`传递给引导加载程序并加载以初始化 Linux 内核，而在第二种情况下，需要将机器类型号加载到`R1`寄存器中。在早期的启动过程中，`__lookup_machine_type`寻找`machine_desc`结构并加载它以初始化板子。

## 社区互动

在向您呈现了这些信息之后，如果你渴望为 Linux 内核做出贡献，那么接下来应该阅读这一部分。如果你真的想为 Linux 内核项目做出贡献，那么在开始这项工作之前应该执行一些步骤。这主要涉及文档和调查。没有人想要发送重复的补丁或徒劳地复制别人的工作，因此在互联网上搜索你感兴趣的主题可以节省大量时间。另一个有用的建议是，在熟悉了主题之后，避免发送权宜之计。尝试解决问题并提供解决方案。如果不能，报告问题并进行彻底描述。如果找到解决方案，那么在补丁中同时提供问题和解决方案。

在开源社区中最有价值的事情之一是你可以从他人那里得到帮助。分享你的问题和困难，但不要忘记提到解决方案。在适当的邮件列表中提出问题，并尽量避免联系维护者。他们通常非常忙，有数百甚至数千封邮件需要阅读和回复。在寻求帮助之前，尽量研究你想提出的问题，这将有助于表达问题，也可能提供答案。如果可能的话，使用 IRC 来提出较小的问题，最重要的是，尽量不要过度使用。

当你准备好补丁时，确保它是在相应的分支上完成的，并且你首先阅读`Documentation/BUG-HUNTING`文件。如果有的话，识别 bug 报告，并确保将你的补丁链接到它们。在发送之前不要犹豫阅读`Documentation/SubmittingPatches`指南。在发送补丁之前一定要进行适当的测试。始终签署你的补丁，并尽可能使第一行描述具有指导性。在发送补丁时，找到适当的邮件列表和维护者，并等待回复。解决评论并重新提交，直到补丁被认为是可以接受的。

# 内核源码

Linux 内核的官方位置位于[`www.kernel.org`](http://www.kernel.org)，但有许多较小的社区为 Linux 内核贡献其特性，甚至维护自己的版本。

尽管 Linux 核心包含调度程序、内存管理和其他功能，但其大小相当小。大量的设备驱动程序、架构和板支持以及文件系统、网络协议和所有其他组件使得 Linux 内核的大小真正庞大。这可以通过查看 Linux 目录的大小来看出。

Linux 源代码结构包含以下目录：

+   `arch`：这包含了与架构相关的代码

+   `block`：这包含了块层核心

+   `crypto`：这包含了加密库

+   `drivers`：这收集了除声音驱动程序之外的所有设备驱动程序的实现

+   `fs`：这收集了所有可用的文件系统实现

+   `include`：这包含了内核头文件

+   `init`：这包含了 Linux 初始化代码

+   `ipc`：这包含了进程间通信实现代码

+   `kernel`：这是 Linux 内核的核心

+   `lib`：这包含了各种库，如`zlibc`，`crc`等

+   `mm`：这包含了内存管理的源代码

+   `net`：这提供了对 Linux 内部支持的所有网络协议实现的访问

+   `samples`：这提供了许多示例实现，如`kfifo`，`kobject`等

+   `scripts`：这既在内部又在外部使用

+   `security`：这包含了许多安全实现，如`apparmor`，`selinux`，`smack`等

+   `sound`：这包含了声音驱动程序和支持代码

+   `usr`：这是生成源代码的`initramfs cpio`存档

+   `virt`：这包含了虚拟化支持的源代码

+   `COPYING`：这代表了 Linux 许可证和定义复制条件

+   `CREDITS`：这代表了 Linux 的主要贡献者的集合

+   `Documentation`：这包含了内核源代码的相应文档

+   `Kbuild`：这代表了顶层的内核构建系统

+   `Kconfig`：这是配置参数的顶层描述符

+   `MAINTAINERS`：这是每个内核组件的维护者列表

+   `Makefile`：这代表了顶层的 makefile

+   `README`：这个文件描述了 Linux 是什么，是理解项目的起点

+   `REPORTING-BUGS`：这提供了关于错误报告程序的信息

正如所见，Linux 内核的源代码非常庞大，因此需要一个浏览工具。有许多可以使用的工具，如**Cscope**，**Kscope**，或者 Web 浏览器**Linux Cross Reference**（**LXR**）。Cscope 是一个庞大的项目，也可以通过`vim`和`emacs`的扩展来使用。

## 配置内核

在构建 Linux 内核映像之前，需要进行适当的配置。考虑到我们可以访问数百甚至数千个组件，如驱动程序、文件系统和其他项目，这是困难的。在配置阶段内进行选择过程，并且这是可能的依赖关系的帮助下。用户有机会使用和定义一些选项，以便定义将用于为特定板构建 Linux 内核映像的组件。

所有支持板的特定配置都位于一个名为`.config`的配置文件中，它位于先前介绍的文件和目录位置的同一级别。它们的形式通常表示为`configuration_key=value`。当然，这些配置之间存在依赖关系，因此它们在`Kconfig`文件中定义。

以下是一些可用于配置键的变量选项：

+   `bool`：这些选项可以有真或假的值

+   三态：除了真和假选项之外，也可以作为模块选项出现

+   `int`：这些值并不是那么常见，但它们通常具有一个很好的值范围

+   `string`：这些值也不是最常见的，但通常包含一些非常基本的信息。

关于`Kconfig`文件，有两个选项可用。第一个选项只有在启用选项 B 时才会显示选项 A，并被定义为*取决于*，第二个选项提供了启用选项 A 的可能性。当选项被自动启用并被定义为*选择*时，就会执行此操作。

除了手动配置`.config`文件之外，配置对于开发人员来说是最糟糕的选择，主要是因为它可能会忽略一些配置之间的依赖关系。我想建议开发人员使用`menuconfig`命令，它将启动一个文本控制台工具，用于配置内核映像。

## 编译和安装内核

配置完成后，可以开始编译过程。我想给出的建议是，如果主机机器提供了这种可能性，尽可能使用多个线程，因为这将有助于构建过程。构建过程的启动命令示例是`make -j 8`。

在构建过程结束时，将提供一个`vmlinux`映像，以及一些特定于体系结构的映像，可在 ARM 体系结构的特定文件中使用。其结果可在`arch/arm/boot/*Image`中找到。此外，Atmel SAMA5D3-Xplained 板将提供一个特定的设备树文件，可在`arch/arm/boot/dts/*.dtb`中找到。如果`vmlinux`映像文件是带有调试信息的 ELF 文件，除了调试目的外不能用于引导，那么`arch/arm/boot/*Image`文件就是解决此目的的方法。

安装是开发完成后的下一步。对于 Linux 内核也是如此，但在嵌入式环境中，这一步似乎有点不必要。对于 Yocto 爱好者，这一步也是可用的。然而，在这一步中，为内核源代码进行适当的配置，并且要使用由存储部署步骤的依赖项使用的头文件。

内核模块，如交叉编译章节中所述，需要稍后用于编译器构建。可以使用 make `modules_install`命令进行内核模块的安装，这提供了在`/lib/modules/<linux-kernel-version>`目录中安装可用源的可能性，包括所有模块依赖项、符号和别名。

## 交叉编译 Linux 内核

在嵌入式开发中，编译过程意味着交叉编译，与本地编译过程最明显的区别是它具有一个以目标架构为前缀的命名。前缀设置可以使用`ARCH`变量来定义目标板的架构名称，以及`CROSS_COMPILE`变量来定义交叉编译工具链的前缀。它们都在顶层`Makefile`中定义。

最好的选择是将这些变量设置为环境变量，以确保不会为主机机器运行 make 过程。虽然它只在当前终端中有效，但在没有自动化工具可用的情况下，比如 Yocto 项目，这将是最好的解决方案。不过，如果您计划在主机机器上使用多个工具链，不建议更新`.bashrc` shell 变量。

# 设备和模块

如我之前提到的，Linux 内核有许多内核模块和驱动程序，这些模块和驱动程序已经在 Linux 内核的源代码中实现并可用。其中许多模块也可以在 Linux 内核源代码之外找到。将它们放在外面不仅可以减少启动时间，而且可以根据用户的请求和需求进行初始化。唯一的区别是，加载和卸载模块需要 root 访问权限。

加载和与 Linux 内核模块交互需要提供日志信息。对于任何内核模块依赖项也是如此。日志信息可通过`dmesg`命令获得，并且日志级别可以使用`loglevel`参数手动配置，也可以使用`quite`参数禁用。对于内核依赖项，有关它们的信息可在`/lib/modules/<kernel-version>/modules.dep`文件中找到。

对于模块交互，有多个用于多个操作的实用程序可用，例如`modinfo`用于收集有关模块的信息；`insmod`用于在给定内核模块的完整路径时加载模块。类似的实用程序也可用于模块。其中一个称为`modprobe`，`modprobe`的区别在于不需要完整路径，因为它负责在加载自身之前加载所选内核对象的依赖模块。`modprobe`提供的另一个功能是`-r`选项。这是删除功能，它支持删除模块及其所有依赖项。这方面的替代方法是`rmmod`实用程序，它删除不再使用的模块。最后一个可用的实用程序是`lsmod`，它列出加载的模块。

可以编写的最简单的内核模块示例看起来类似于这样：

```
#define MODULE
#define LINUX
#define __KERNEL__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int hello_world_init(void)
{
   printk(KERN_ALERT "Hello world!\n");
   return 0;
}

static void hello_world_exit(void)
{
   printk(KERN_ALERT "Goodbye!\n");
}

module_init(hello_world_init);
module_exit(hello_world_exit);

MODULE_LICENSE("GPL");
```

这是一个简单的“hello world 内核”模块。可以从上面的示例中获得的有用信息是，每个内核模块都需要在上面的示例中定义为`hello_world_init()`的启动函数。当模块被插入时，它被调用，当模块被移除时，被调用的清理函数称为`hello_world_exit()`。

自 Linux 内核版本 2.2 以来，可以以这种方式使用`_init`和`__exit`宏：

```
static int __init hello_world_init (void)
static void __exit hello_world_exit (void)
```

前面的宏被移除，第一个在初始化后被移除，第二个在模块内置在 Linux 内核源代码中时被移除。

### 注意

有关 Linux 内核模块的更多信息可以在 Linux**内核模块编程指南**中找到，网址为[`www.tldp.org/LDP/lkmpg/2.6/html/index.html`](http://www.tldp.org/LDP/lkmpg/2.6/html/index.html)。

如前所述，内核模块不仅可以在 Linux 内核内部使用，还可以在 Linux 内核树之外使用。对于内置的内核模块，编译过程类似于其他可用的内核模块的编译过程，开发人员可以从中汲取灵感。在 Linux 内核驱动程序之外可用的内核模块和构建过程需要访问 Linux 内核源代码或内核头文件。

对于在 Linux 内核源代码之外可用的内核模块，有一个`Makefile`示例，如下：

```
KDIR := <path/to/linux/kernel/sources>
PWD := $(shell pwd)
obj-m := hello_world.o
all:
$(MAKE) ARCH=arm CROSS_COMPILE=<arm-cross-compiler-prefix> -C
$(KDIR) M=$(PWD)

```

对于在 Linux 内核内实现的模块，需要在相应的`Kconfig`文件中提供模块的配置，并进行正确的配置。此外，需要更新`Kconfig`文件附近的`Makefile`，以便让`Makefile`系统知道何时更新模块的配置并构建源代码。我们将在这里看到一个这种类型的内核设备驱动程序的示例。

`Kconfig`文件的示例如下：

```
config HELLO_WORLD_TEST 
 tristate "Hello world module test"
 help
 To compile this driver as a module chose the M option.
 otherwise chose Y option.

```

`Makefile`的示例如下：

```
obj-$(CONFIG_ HELLO_WORLD_TEST)  += hello_world.c

```

在这两个示例中，源代码文件是`hello_world.c`，如果没有内置，生成的内核模块称为`hello_world.ko`。

驱动程序通常用作与公开多种硬件特性的框架的接口，或者与用于检测和与硬件通信的总线接口一起使用。最好的例子在这里展示：

![设备和模块](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/lrn-emb-linux-yocto-pj/img/image00322.jpeg)

由于使用设备驱动程序的多种情况以及可用的三种设备模式结构：

+   `struct bus_type`：表示总线类型，如 I2C、SPI、USB、PCI、MMC 等

+   `struct device_driver`：这代表了用于处理总线上特定设备的驱动程序

+   `struct device`：用于表示连接到总线的设备

继承机制用于从更通用的结构（例如`struct device_driver`和`struct device`）创建专门的结构，用于每个总线子系统。总线驱动程序负责表示每种类型的总线，并将相应的设备驱动程序与检测到的设备匹配，检测是通过适配器驱动程序完成的。对于不可发现的设备，在设备树或 Linux 内核源代码中进行描述。它们由支持平台驱动程序并处理平台设备的平台总线处理。

# 调试内核

不得不调试 Linux 内核并不是一项容易的任务，但必须完成以确保开发过程向前推进。当然，理解 Linux 内核是其中的先决条件之一。一些可用的错误非常难以解决，并且可能在 Linux 内核中存在很长一段时间。

对于大多数简单的问题，应该采取以下一些步骤。首先，正确地识别错误；这不仅在定义问题时有用，而且在重现问题时也有帮助。第二步涉及找到问题的源头。这里，我指的是首次报告错误的内核版本。对于错误或 Linux 内核源代码的良好了解总是有用的，因此在开始工作之前，请确保您理解代码。

Linux 内核中的错误有着广泛的传播。它们从变量未正确存储到竞争条件或硬件管理问题，表现出各种各样的表现形式和一系列事件。然而，调试它们并不像听起来那么困难。除了一些特定的问题，如竞争条件和时间限制，调试与调试任何大型用户空间应用程序非常相似。

调试内核的第一种、最简单、最方便的方法是使用`printk()`函数。它非常类似于`printf()`C 库函数，虽然有些过时并且不被一些人推荐，但它确实有效。新的首选方法涉及使用`pr_*()`函数，比如`pr_emerg()`、`pr_alert()`、`pr_crit()`、`pr_debug()`等。另一种方法涉及使用`dev_*()`函数，比如`dev_emerg()`、`dev_alert()`、`dev_crit()`、`dev_dbg()`等。它们对应于每个日志级别，并且还有一些额外的函数，用于调试目的，并且在启用`CONFIG_DEBUG`时进行编译。

### 注意

有关`pr_*()`和`dev_*()`函数族的更多信息可以在 Linux 内核源代码的`Documentation/dynamic-debug-howto.txt`中找到。您还可以在`Documentation/kernel-parameters.txt`中找到有关`loglevel`的更多信息。

当内核发生**oops**崩溃时，表示内核犯了一个错误。无法修复或自杀，它提供了一堆信息，如有用的错误消息、寄存器内容和回溯信息。

`Magic SysRq`键是调试中使用的另一种方法。它由`CONFIG_MAGIC_SYSRQ config`启用，并可用于调试和救援内核信息，而不管其活动性。它提供了一系列命令行选项，可用于各种操作，从更改优先级到重新启动系统。此外，可以通过更改`/proc/sys/kernel/sysrq`文件中的值来切换开关。有关系统请求键的更多信息，请参阅`Documentation/sysrq.txt`。

尽管 Linus Torvalds 和 Linux 社区并不认为内核调试器的存在对项目有多大好处，但对代码的更好理解是任何项目的最佳方法。仍然有一些调试器解决方案可供使用。GNU 调试器（`gdb`）是第一个，它可以像其他任何进程一样使用。另一个是`kgdb`，它是`gdb`的一个补丁，允许调试串行连接。

如果前面的方法都无法解决问题，并且您已经尝试了一切但似乎无法得出解决方案，那么您可以联系开源社区寻求帮助。总会有开发人员愿意帮助您。

### 注意

要获取与 Linux 内核相关的更多信息，可以查阅一些书籍。我将在这里列出一些书名：Christopher Hallinan 的*嵌入式 Linux 入门*，Robert Love 的*Linux 内核开发*，Greg Kroah-Hartman 的*Linux 内核要点*，最后但同样重要的是，Daniel P. Bovet 和 Marco Cesati 的*理解 Linux 内核*。

# Yocto 项目参考

转向 Yocto 项目，我们为每个支持的板上的 BSP 支持内核版本提供了配方，并为在 Linux 内核源树之外构建的内核模块提供了配方。

Atmel SAMA5D3-Xplained 板使用`linux-yocto-custom`内核。这是通过`conf/machine/sama5d3-xplained.conf`机器配置文件使用`PREFERRED_PROVIDER_virtual/kernel`变量进行定义的。没有提到`PREFERRED_VERSION`，因此首选最新版本；在这种情况下，我们谈论的是`linux-yocto-custom_3.10.bb`配方。

`linux-yocto-custom_3.10.bb`配方从 Linux Torvalds 的`git`存储库中提取可用的内核源代码。在`do_fetch`任务完成后快速查看源代码后，可以观察到实际上已经提取了 Atmel 存储库。答案可以在`linux-yocto-custom_3.10.bbappend`文件中找到，该文件提供了另一个`SR_URI`位置。您可以从这里收集到的其他有用信息是在 bbappend 文件中可用的，其中非常清楚地说明了 SAMA5D3 Xplained 机器是`COMPATIBLE_MACHINE`：

```
KBRANCH = "linux-3.10-at91"
SRCREV = "35158dd80a94df2b71484b9ffa6e642378209156"
PV = "${LINUX_VERSION}+${SRCPV}"

PR = "r5"

FILESEXTRAPATHS_prepend := "${THISDIR}/files/${MACHINE}:"

SRC_URI = "git://github.com/linux4sam/linux-at91.git;protocol=git;branch=${KBRANCH};nocheckout=1"
SRC_URI += "file://defconfig"

SRCREV_sama5d4-xplained = "46f4253693b0ee8d25214e7ca0dde52e788ffe95"

do_deploy_append() {
  if [ ${UBOOT_FIT_IMAGE} = "xyes" ]; then
    DTB_PATH="${B}/arch/${ARCH}/boot/dts/"
    if [ ! -e "${DTB_PATH}" ]; then
      DTB_PATH="${B}/arch/${ARCH}/boot/"
    fi

    cp ${S}/arch/${ARCH}/boot/dts/${MACHINE}*.its ${DTB_PATH}
    cd ${DTB_PATH}
    mkimage -f ${MACHINE}.its ${MACHINE}.itb
    install -m 0644 ${MACHINE}.itb ${DEPLOYDIR}/${MACHINE}.itb
    cd -
  fi
}

COMPATIBLE_MACHINE = "(sama5d4ek|sama5d4-xplained|sama5d3xek|sama5d3-xplained|at91sam9x5ek|at91sam9rlek|at91sam9m10g45ek)"
```

配方首先定义了与存储库相关的信息。它通过变量（如`SRC_URI`和`SRCREV`）进行定义。它还通过`KBRANCH`变量指示存储库的分支，并且还指示`defconfig`需要放入源代码中以定义`.config`文件的位置。正如在配方中所看到的，对内核配方的`do_deploy`任务进行了更新，以将设备驱动程序添加到`tmp/deploy/image/sama5d3-xplained`目录中，与内核映像和其他二进制文件一起。

内核配方继承了`kernel.bbclass`和`kernel-yocto.bbclass`文件，这些文件定义了大部分任务操作。由于它还生成设备树，因此需要访问`linux-dtb.inc`，该文件位于`meta/recipes-kernel/linux`目录中。`linux-yocto-custom_3.10.bb`配方中提供的信息相当通用，并且被`bbappend`文件覆盖，如下所示：

```
SRC_URI = "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git;protocol=git;nocheckout=1"

LINUX_VERSION ?= "3.10"
LINUX_VERSION_EXTENSION ?= "-custom"

inherit kernel
require recipes-kernel/linux/linux-yocto.inc

# Override SRCREV to point to a different commit in a bbappend file to
# build a different release of the Linux kernel.
# tag: v3.10 8bb495e3f02401ee6f76d1b1d77f3ac9f079e376"
SRCREV = "8bb495e3f02401ee6f76d1b1d77f3ac9f079e376"

PR = "r1"
PV = "${LINUX_VERSION}+git${SRCPV}"

# Override COMPATIBLE_MACHINE to include your machine in a bbappend
# file. Leaving it empty here ensures an early explicit build failure.
COMPATIBLE_MACHINE = "(^$)"

# module_autoload is used by the kernel packaging bbclass
module_autoload_atmel_usba_udc = "atmel_usba_udc"
module_autoload_g_serial = "g_serial"
```

通过运行`bitbake virtual/kernel`命令构建内核后，内核映像将在`tmp/deploy/image/sama5d3-xplained`目录下以`zImage-sama5d3-xplained.bin`名称可用，这是一个符号链接到完整名称文件，并具有更大的名称标识符。内核映像是从执行 Linux 内核任务的地方部署到这里的。发现该位置的最简单方法是运行`bitbake –c devshell virtual/kernel`。开发 shell 将可供用户直接与 Linux 内核源代码进行交互，并访问任务脚本。这种方法是首选的，因为开发人员可以访问与`bitbake`相同的环境。

另一方面，如果内核模块不是内置在 Linux 内核源树中，则具有不同类型行为。对于在源树之外构建的模块，需要编写一个新的配方，即继承另一个名为`module.bbclass`的`bitbake`类的配方。一个外部 Linux 内核模块的示例可在`meta-skeleton`层的`recipes-kernel/hello-mod`目录中找到。

```
SUMMARY = "Example of how to build an external Linux kernel module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=12f884d2ae1ff87c09e5b7ccc2c4ca7e"

inherit module

PR = "r0"
PV = "0.1"

SRC_URI = "file://Makefile \
           file://hello.c \
           file://COPYING \
          "

S = "${WORKDIR}"

# The inherit of module.bbclass will automatically name module packages with
# "kernel-module-" prefix as required by the oe-core build environment.
```

在 Linux 内核外部模块的示例中提到，每个外部或内部内核模块的最后两行都使用`kernel-module-`前缀打包，以确保当`IMAGE_INSTALL`变量可用时，值 kernel-modules 将添加到`/lib/modules/<kernel-version>`目录中所有可用的内核模块。内核模块配方与任何可用配方非常相似，主要区别在于继承的模块形式，如继承模块一行所示。

在 Yocto Project 中，有多个可用命令与内核和内核模块配方进行交互。最简单的命令当然是`bitbake` `<recipe-name>`，但对于 Linux 内核，有许多可用命令可以使交互更容易。最常用的是`bitbake -c menuconfig virtual/kernel`操作，它提供了对内核配置菜单的访问。

除了已知的任务，如`configure`、`compile`和`devshell`，主要用于开发过程，还有其他任务，如`diffconfig`，它使用 Linux 内核`scripts`目录中可用的`diffconfig`脚本。 Yocto Project 的实现与 Linux 内核的可用脚本之间的区别在于前者添加了内核`config`创建阶段。这些`config`片段用于将内核配置添加到`.config`文件中，作为自动化过程的一部分。

# 摘要

在本章中，您了解了 Linux 内核的一般情况，以及与其交互的特性和方法。还有关于调试和移植特性的信息。所有这些都是为了确保在与其交互之前，您能够获得足够的信息。我认为，如果您首先了解整个情况，将更容易专注于更具体的事物。这也是 Yocto Project 参考资料被保留到最后的原因之一。您将了解如何定义 Linux 内核配方和 Linux 内核外部模块，并在稍后由特定机器使用。有关 Linux 内核的更多信息也将在下一章中提供，该章将汇总先前提供的所有信息，并向您展示开发人员如何与 Linux 操作系统映像进行交互。

除了这些信息之外，在下一章中，将会对根文件系统的组织及其背后的原理、内容和设备驱动程序进行解释。Busybox 是另一个有趣的主题，将进行讨论，还有各种可用的文件系统支持。由于它倾向于变得更大，关于最小文件系统应该是什么样子的信息也将被呈现。说到这里，我们将继续下一章。
