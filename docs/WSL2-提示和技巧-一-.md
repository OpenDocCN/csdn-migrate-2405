# WSL2 提示和技巧（一）

> 原文：[`zh.annas-archive.org/md5/5EBC4B193F90421D3484B13463D11C33`](https://zh.annas-archive.org/md5/5EBC4B193F90421D3484B13463D11C33)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Windows 子系统 Linux（WSL）是微软的一项令人兴奋的技术，它将 Linux 与 Windows 并列，并允许您在 Windows 上运行未经修改的 Linux 二进制文件。与在隔离的虚拟机中运行 Linux 的体验不同，WSL 带来了丰富的互操作能力，使您可以将每个操作系统的工具结合在一起，让您可以使用最适合工作的工具。

通过改进性能并提供完整的系统调用兼容性，WSL 2 使 WSL 得到了进一步的发展，为您提供了更多的功能。此外，其他技术，如 Docker Desktop 和 Visual Studio Code，已经添加了对 WSL 的支持，为您提供了更多利用它的方式。

通过 Docker Desktop 的 WSL 集成，您可以在 WSL 中运行 Docker 守护程序，从而提供一系列好处，包括在从 WSL 挂载卷时提高性能。

Visual Studio Code 中的 WSL 集成使您能够在 WSL 中安装项目工具和依赖项，以及源代码，并使 Windows 用户界面连接到 WSL 以加载代码并在 WSL 中运行和调试应用程序。

总的来说，WSL 是一项令人兴奋的技术，它极大地改善了我的日常工作流程，我希望在您阅读本书时能与您分享这种兴奋！

# 本书适合谁？

本书适用于希望在 Windows 上使用 Linux 工具的开发人员，包括根据项目要求希望逐渐适应 Linux 环境的本地 Windows 程序员，或最近切换到 Windows 的 Linux 开发人员。本书还适用于使用以 Ruby 或 Python 为首选的 Linux 工具进行开源项目的 Web 开发人员，或者希望在测试应用程序时在容器和开发机之间切换的开发人员。

# 本书涵盖了什么内容？

[*第一章*]（B16412_01_Final_JC_ePub.xhtml#_idTextAnchor017），*介绍 Windows 子系统 Linux*，概述了 WSL 是什么，并探讨了 WSL 1 和 WSL 2 之间的区别。

[*第二章*]（B16412_02_Final_JC_ePub.xhtml#_idTextAnchor023），*安装和配置 Windows 子系统 Linux*，带您了解安装 WSL 2 的过程，如何使用 WSL 安装 Linux 发行版，以及如何控制和配置 WSL。

[*第三章*]（B16412_03_Final_JC_ePub.xhtml#_idTextAnchor037），*开始使用 Windows 终端*，介绍了新的 Windows 终端。这个来自微软的新的开源终端正在快速发展，并为在 WSL 2 中使用 shell 提供了很好的体验。您将了解如何安装 Windows 终端，如何使用它，并自定义其外观。

[*第四章*]（B16412_04_Final_JC_ePub.xhtml#_idTextAnchor047），*Windows 与 Linux 的互操作性*，开始深入研究 WSL 提供的互操作性功能，看看如何从 Windows 访问 Linux 发行版中的文件和应用程序。

[*第五章*]（B16412_05_Final_JC_ePub.xhtml#_idTextAnchor054），*Linux 与 Windows 的互操作性*，继续探索 WSL 的互操作性功能，展示如何从 Linux 访问 Windows 文件和应用程序，以及一些互操作性技巧和技巧。

[*第六章*]（B16412_06_Final_JC_ePub.xhtml#_idTextAnchor069），*获取更多 Windows 终端*，探索了 Windows 终端的更多深入方面，例如自定义选项卡标题和将选项卡分割成多个窗格。您将看到各种选项，包括如何从命令行控制 Windows 终端（以及如何重用命令行选项与正在运行的 Windows 终端一起工作）。您还将了解如何添加自定义配置文件以提高日常工作流程。

*第七章*，*在 WSL 中使用容器*，介绍了使用 Docker Desktop 在 WSL 2 中运行 Docker 守护程序的方法。您将了解如何构建和运行用于示例 Web 应用程序的容器。本章还展示了如何启用并使用 Docker Desktop 中的 Kubernetes 集成，在 WSL 中运行示例 Web 应用程序。

*第八章*，*使用 WSL 发行版*，指导您完成导出和导入 WSL 发行版的过程。这种技术可用于将发行版复制到另一台计算机或在本地计算机上创建副本。您还将了解如何使用容器映像快速创建新的 WSL 发行版。

*第九章*，*Visual Studio Code 和 WSL*，在探索 Remote-WSL 扩展之前，对 Visual Studio Code 进行了简要介绍，该扩展可用于在 WSL 发行版文件系统中使用代码。通过这种方法，您可以在 WSL 中保留 Visual Studio Code 的丰富 GUI 体验，同时运行代码文件、工具和应用程序。

*第十章*，*Visual Studio Code 和容器*，通过查看 Remote-Containers 扩展继续探索 Visual Studio Code，该扩展允许您将所有项目依赖项打包到容器中。这种方法可以使项目之间的依赖项隔离，以避免冲突，并且还可以让新团队成员快速入门。

*第十一章*，*使用命令行工具提高生产力*，介绍了一些在命令行中使用 Git 的技巧，然后介绍了处理 JSON 数据的一些方法。之后，它探索了 Azure 和 Kubernetes 命令行实用程序以及它们各自用于查询信息的方法，包括进一步探索处理 JSON 数据。

# 为了充分利用本书的内容

要按照本书中的示例进行操作，您需要使用与 WSL 版本 2 兼容的 Windows 10 版本（请参阅下表）。您还需要 Docker Desktop 和 Visual Studio Code。

需要具备先前的编程或开发经验以及对在 PowerShell、Bash 或 Windows 命令提示符中运行任务的基本理解：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_Preface_Table.jpg)

如果您使用的是电子版的本书，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做可以帮助您避免与复制和粘贴代码相关的潜在错误。

微软还宣布了 WSL 的其他功能（例如对 GPU 和 GUI 应用程序的支持），但在撰写本书时，这些功能尚不稳定，仅以早期预览形式提供。本书选择关注 WSL 的稳定发布功能，因此目前专注于 WSL 的当前、以命令行为中心的视图。

# 下载示例代码文件

您可以从 GitHub 上的以下链接下载本书的示例代码文件：[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还提供了来自我们丰富的图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上获取。请查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在此处下载：[`static.packt-cdn.com/downloads/9781800562448_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781800562448_ColorImages.pdf)。

# 使用的约定

本书中使用了一些文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“要更改 UI 中配置文件的顺序，我们可以更改`settings`文件中`profiles`下的`list`中的条目顺序。”

代码块设置如下：

```
"profiles": {
    "defaults": {
        "fontFace": "Cascadia Mono PL"
    },
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```
"profiles": {
    "defaults": {
        "fontFace": "Cascadia Mono PL"
    },
```

任何命令行输入或输出都按以下方式编写：

```
git clone https://github.com/magicmonty/bash-git-prompt.git ~/.bash-git-prompt --depth=1
```

**粗体**：表示新术语、重要单词或屏幕上显示的单词。例如，菜单或对话框中的单词会以这样的方式出现在文本中。这是一个例子：“当您在处理复杂查询时，游乐场可以是一个有帮助的环境，底部的**命令行**部分甚至提供了您可以复制和在脚本中使用的命令行。”

提示或重要说明

显示如下。

# 联系我们

我们非常欢迎读者的反馈。

`customercare@packtpub.com`。

**勘误表**：尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在本书中发现错误，我们将非常感激您向我们报告。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata)，选择您的书籍，点击“勘误提交表”链接，并输入详细信息。

`copyright@packt.com`，附带材料的链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com)。

# 评论

请留下评论。在阅读并使用本书后，为什么不在您购买它的网站上留下评论呢？潜在读者可以看到并使用您的公正意见来做出购买决策，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://packt.com)。


# 第一部分：介绍、安装和配置

通过本部分的学习，您将了解 Windows 子系统是什么，以及它与传统虚拟机的区别。您将能够安装 Windows 子系统并进行配置以满足您的需求。您还将能够安装新的 Windows 终端。

本节包括以下章节：

*第一章*，*Windows 子系统介绍*

*第二章*，*安装和配置 Windows 子系统*

*第三章*，*使用 Windows 终端入门*


# 第一章：Windows 子系统介绍 Linux

在本章中，您将了解到**Windows 子系统 Linux**（**WSL**）的一些用例，并开始对 WSL 的实际情况以及与仅运行 Linux 虚拟机相比的优劣有所了解。这将帮助我们理解本书的其余部分，我们将学习有关 WSL 的所有内容，以及如何安装和配置它，并获取有关如何在开发者工作流中充分利用它的技巧。

通过 WSL，您可以在 Windows 上运行 Linux 实用工具来帮助您完成工作。您可以使用原生 Linux 工具（如**调试器**）构建 Linux 应用程序，从而打开了一系列仅具有基于 Linux 的构建系统的项目。其中许多项目还会生成 Windows 二进制文件作为输出，但对于 Windows 开发人员来说，访问和贡献这些项目通常很困难。但由于 WSL 为您提供了 Windows 和 Linux 的综合功能，您可以做到这一切，并且仍然可以使用您喜爱的 Windows 实用工具作为工作流的一部分。

本书重点介绍 WSL 的第 2 版，这是一个重大改进的功能，本章将为您概述此版本的工作原理以及与第 1 版的比较。

在本章中，我们将特别涵盖以下主题：

+   什么是 WSL？

+   探索 WSL 1 和 2 之间的区别

所以，让我们从定义 WSL 开始！

# 什么是 WSL？

从高层次来看，WSL 提供了在 Windows 上运行 Linux 二进制文件的能力。多年来，人们一直希望能够运行 Linux 二进制文件，至少可以从**Cygwin**（[`cygwin.com`](https://cygwin.com)）等项目的存在来看。根据其主页的介绍，Cygwin 是“一个大型的 GNU 和开源工具集，提供类似于 Linux 发行版的功能”。在 Cygwin 上运行 Linux 应用程序需要重新构建源代码。WSL 提供了在 Windows 上运行 Linux 二进制文件的能力，无需修改。这意味着您可以立即获取您喜爱的应用程序的最新版本并与之一起工作。

希望在 Windows 上运行 Linux 应用程序的原因有很多，包括以下几点：

+   您目前正在使用 Windows，但对 Linux 应用程序和实用工具有经验和熟悉。

+   您在 Windows 上进行开发，但针对应用程序的部署目标是 Linux（直接或在容器中）。

+   您正在使用开发堆栈，其中生态系统在 Linux 上具有更强的存在，例如 Python，其中一些库是特定于 Linux 的。

无论您希望在 Windows 上运行 Linux 应用程序的原因是什么，WSL 都可以以一种新的、高效的方式为您提供这种能力。虽然在 Hyper-V 中运行 Linux**虚拟机**（**VM**）一直是可能的，但运行虚拟机会对您的工作流程产生一些障碍。

例如，启动虚拟机需要足够的时间，以至于您会中断思路，并且需要从主机机器中分配一定的内存。此外，虚拟机中的文件系统专用于该虚拟机，并与主机隔离。这意味着在 Windows 主机和 Linux 虚拟机之间访问文件需要设置 Hyper-V 功能的客户机集成服务或设置传统的网络文件共享。虚拟机的隔离还意味着虚拟机内部和外部的进程之间没有简单的通信方式。基本上，在任何时候，您要么在虚拟机中工作，要么在虚拟机外工作。

当您首次使用 WSL 启动终端时，您将在 Windows 上运行 Linux shell 的终端应用程序。与虚拟机体验相比，这个看似简单的差异已经更好地融入了工作流程，因为在同一台机器上的窗口之间切换比在 Windows 上的应用程序和虚拟机会话之间切换更容易。

然而，WSL 在集成 Windows 和 Linux 环境方面的工作还不止于此。虽然在虚拟机中，文件系统是被设计为隔离的，但在 WSL 中，默认情况下为你配置了文件系统访问。从 Windows 中，你可以访问一个名为`\\wsl$\`的网络文件共享，当 WSL 运行时，它会自动为你提供访问你的 Linux 文件系统的权限。从 Linux 中，默认情况下会自动挂载你的本地 Windows 驱动器。例如，Windows 的`C:`驱动器会被挂载为`/mnt/c`。

更令人印象深刻的是，你可以在 Windows 中调用 Linux 中的进程，反之亦然。例如，在 WSL 的 Bash 脚本中，你可以调用一个 Windows 应用程序，并通过将其输出导入到另一个命令中在 Linux 中处理该应用程序的输出，就像你使用本地 Linux 应用程序一样。

这种集成超越了传统虚拟机所能实现的范围，并为将 Windows 和 Linux 的能力整合到一个单一的、高效的环境中创造了一些令人惊叹的机会，让你兼具两者的优势！

WSL 在 Windows 主机和 Linux 虚拟机环境之间实现的集成令人印象深刻。然而，如果你使用过 WSL 1 或熟悉它的工作原理，你可能已经阅读了前面的段落，并想知道为什么 WSL 2 放弃了之前的不使用虚拟机的架构。在接下来的部分中，我们将简要介绍 WSL 1 和 WSL 2 之间的不同架构，以及使用虚拟机带来的额外挑战，尽管 WSL 团队面临了创建我们刚刚看到的集成水平的难题。

# 探索 WSL 1 和 2 之间的差异

虽然本书讨论的是**Windows 子系统 Linux**（**WSL 2**）的第二个版本，但简要了解第一版（WSL 1）的工作原理是有帮助的。这将帮助你了解 WSL 1 的限制，并为 WSL 2 中的架构变化和新功能提供背景。本节将介绍这些内容，之后本书的其余部分将重点介绍 WSL 2。

## WSL 1 概述

在 WSL 的第一个版本中，WSL 团队在 Linux 和 Windows 之间创建了一个翻译层。这个层在 Windows 内核之上实现了 Linux 系统调用，使得 Linux 二进制文件可以无需修改地运行；当 Linux 二进制文件运行并进行系统调用时，它调用的是 WSL 翻译层，并将其转换为对 Windows 内核的调用。如下图所示：

![图 1.1 - 显示 WSL 1 翻译层的概述](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_1.1_B16412.jpg)

图 1.1 - 显示 WSL 1 翻译层的概述

除了翻译层之外，还进行了其他投资，以实现 Windows 和 WSL 之间的文件访问以及在两个系统之间调用二进制文件（包括捕获输出）的能力。这些能力有助于构建整体功能的丰富性。

在 WSL 1 中创建翻译层是一个大胆的举动，为 Windows 开辟了新的可能性，然而，并非所有的 Linux 系统调用都被实现，只有当所需的所有系统调用都被实现时，Linux 二进制文件才能运行。幸运的是，已经实现的系统调用可以让各种应用程序运行，例如 Python 和 Node.js。

翻译层负责弥合 Linux 和 Windows 内核之间的差距，这带来了一些挑战。在某些情况下，弥合这些差异会增加性能开销。在 WSL 1 上运行大量文件访问的应用程序明显较慢；例如，由于在 Linux 和 Windows 之间进行翻译的开销。

在其他情况下，Linux 和 Windows 之间的差异更深，很难看到如何调和它们。例如，在 Windows 上，当打开一个目录中包含的文件时尝试重命名该目录会导致错误，而在 Linux 上可以成功执行重命名操作。在这种情况下，很难看到翻译层如何解决差异。这导致一些系统调用未被实现，结果是一些 Linux 应用程序无法在 WSL 1 上运行。下一节将介绍 WSL 2 中所做的更改以及它们如何解决这个挑战。

## WSL 2 概述

WSL 1 翻译层面虽然令人印象深刻，但它总是会面临性能挑战和难以正确实现的系统调用。通过 WSL 2，WSL 团队重新审视了问题，并提出了一个新的解决方案：一个**虚拟机**！这种方法通过运行 Linux 内核避免了 WSL 1 的翻译层：

![图 1.2 - 显示 WSL 2 架构的概要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_1.2_B16412.jpg)

图 1.2 - 显示 WSL 2 架构的概要

当你想到虚拟机时，你可能会想到启动速度慢（至少与启动 shell 提示符相比），启动时占用大量内存，并且与主机机器隔离运行的东西。从表面上看，使用虚拟化来运行 WSL 2 可能似乎出乎意料，因为在 WSL 1 中将这两个环境整合在一起的工作已经完成。实际上，在 Windows 上运行 Linux 虚拟机的能力早已存在。那么，WSL 2 与运行虚拟机有何不同？

使用文档中所称的**轻量级实用虚拟机**（参见[`docs.microsoft.com/en-us/windows/wsl/wsl2-about`](https://docs.microsoft.com/en-us/windows/wsl/wsl2-about)），带来了很大的差异。这个虚拟机具有快速启动，只消耗少量内存。当运行需要内存的进程时，虚拟机会动态增加其内存使用量。更好的是，当虚拟机内的内存被释放时，它会返回给主机！

运行 WSL 2 的虚拟机意味着它现在正在运行 Linux 内核（其源代码可在[`github.com/microsoft/WSL2-Linux-Kernel`](https://github.com/microsoft/WSL2-Linux-Kernel)上获得）。这反过来意味着 WSL 1 翻译层面临的挑战被消除了：在 WSL 2 中，性能和系统调用兼容性都得到了极大改善。

WSL 2 对于大多数情况来说是向前迈出的积极一步，同时也保留了 WSL 1（Windows 和 Linux 之间的互操作性）的整体体验。

对于大多数用例来说，由于兼容性和性能，WSL 2 将是首选版本，但有几个值得注意的事项。其中之一是（在撰写本文时）WSL 2 的普遍可用版本不支持 GPU 或 USB 访问（详细信息请参见[`docs.microsoft.com/en-us/windows/wsl/wsl2-faq#can-i-access-the-gpu-in-wsl-2-are-there-plans-to-increase-hardware-support`](https://docs.microsoft.com/en-us/windows/wsl/wsl2-faq#can-i-access-the-gpu-in-wsl-2-are-there-plans-to-increase-hardware-support)）。GPU 支持在 2020 年 5 月的*Build*会议上宣布，并且在撰写本文时可通过 Windows Insiders 计划获得（[`insider.windows.com/en-us/`](https://insider.windows.com/en-us/)）。

另一个考虑因素是，由于 WSL 2 使用虚拟机，运行在 WSL 2 中的应用程序将通过与主机不同的网络适配器连接到网络（具有单独的 IP 地址）。正如我们将在*第五章*中看到的那样，WSL 团队在网络互操作性方面进行了投资，以帮助减少这种影响。

幸运的是，WSL 1 和 WSL 2 可以并行运行，因此如果您有特定的情况需要使用 WSL 1，您可以在那种情况下使用它，并且仍然可以在其他情况下使用 WSL 2。

# 总结

在本章中，您了解了 WSL 是什么以及它如何通过允许在 Windows 和 Linux 环境之间进行文件系统和进程集成来与传统虚拟机的体验有所不同。您还了解了 WSL 1 和 WSL 2 之间的区别概述以及为什么在大多数情况下，改进的性能和兼容性使得 WSL 2 成为首选选项。

在下一章中，您将学习如何安装和配置 WSL 和 Linux 发行版。


# 第二章：安装和配置 Windows 子系统 Linux

**Windows 子系统 Linux**（**WSL**）不是默认安装的，因此开始使用它的第一步将是安装它以及您选择的 Linux **发行版**（**distro**）。通过本章的学习，您将了解如何安装 WSL 以及如何安装 Linux 发行版以供使用。您还将了解如何检查和控制 Linux 发行版，以及如何配置 WSL 中的其他属性。

在本章中，我们将特别介绍以下主要主题：

+   启用 WSL

+   在 WSL 中安装 Linux 发行版

+   配置和控制 WSL

# 启用 WSL

要准备好运行 WSL 的计算机，您需要确保您使用的是支持 WSL 的 Windows 版本。然后，您可以启用运行 WSL 所需的 Windows 功能，并安装 Linux 内核以准备安装 Linux 发行版。最后，您将能够安装一个或多个 Linux 发行版来运行。

让我们首先确保您正在使用最新版本的 Windows。

## 检查所需的 Windows 版本

要安装 WSL 2，您需要在运行的 Windows 10 版本上安装最新的版本。要检查您正在运行的 Windows 10 版本（以及是否需要更新），请按下*Windows 键* + *R*，然后键入`winver`：

![图 2.1 - 显示 2004 更新的 Windows 版本对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_2.1_B16412.jpg)

图 2.1 - 显示 2004 更新的 Windows 版本对话框

在此屏幕截图中，您可以看到**版本 2004**表示系统正在运行 2004 版本。之后，您可以看到**OS 构建**为**19041.208**。

要运行 WSL 2，您需要使用版本 1903 或更高版本和 OS 构建 18362 或更高版本。（请注意，ARM64 系统需要使用版本 2004 或更高版本和 OS 构建 19041 或更高版本。）更多详细信息请参见[`docs.microsoft.com/en-us/windows/wsl/install-win10#requirements`](https://docs.microsoft.com/en-us/windows/wsl/install-win10#requirements)。

如果您使用的是较低的版本号，请在计算机上转到**Windows 更新**并应用任何待处理的更新。

重要提示

Windows 10 更新的命名可能有点令人困惑，版本号如 1903 和 1909（或更糟糕的是，看起来像年份的 2004）的含义并不立即显而易见。命名是以**yymm**形式的年份和月份的组合，其中**yy**是年份的最后两位数字，**mm**是月份的两位数字形式。例如，1909 更新计划于 2019 年 9 月发布。同样，2004 版本计划于 2020 年 4 月发布。

现在您知道您使用的是所需的 Windows 版本，让我们开始启用 WSL。

## 检查是否有简易安装选项

在 2020 年 5 月的**BUILD**大会上，微软宣布了一种新的、简化的 WSL 安装方式，但在撰写本文时，这种新方法尚不可用。然而，由于这是一种快速简便的方法，您可能希望在使用较长的安装步骤之前尝试一下，以防在您阅读本文时已经可用！

要尝试一下，请打开您选择的提升的提示符（例如，**命令提示符**）并输入以下命令：

```
Wsl.exe --install
```

如果此命令运行，则表示您具有简易安装选项，并且它将为您安装 WSL。在这种情况下，您可以跳到*配置和控制 WSL 部分（或者如果您想安装其他 Linux 发行版，则跳到安装 Linux 发行版在 WSL 中*部分）。

如果找不到该命令，则继续下一节使用原始方法安装 WSL。

## 启用所需的 Windows 功能

正如在介绍章节中讨论的那样，WSL 的第二版使用了一种新的轻量级实用虚拟机功能。要启用轻量级虚拟机和 WSL，您需要启用两个 Windows 功能：**虚拟机平台**和**Windows 子系统 Linux**。

要通过“Windows 功能”启用这些功能，请单击如下图所示的**打开或关闭 Windows 功能**：

![图 2.2-启动 Windows 功能选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_2.2_B16412.jpg)

图 2.2-启动 Windows 功能选项

当 Windows 功能对话框出现时，请勾选**虚拟机平台**和**Windows 子系统 Linux**的复选框，如下图所示：

![图 2.3-WSL 版本 2 所需的 Windows 功能](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_2.3_B16412.jpg)

图 2.3-WSL 版本 2 所需的 Windows 功能

单击**确定**后，Windows 将下载并安装组件，并可能提示您重新启动计算机。

如果您喜欢通过命令行启用这些功能，请启动您选择的提升的提示符（例如，命令提示符）并输入以下命令：

```
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

完成这些命令后，重新启动计算机，您将准备好安装 Linux 内核。

## 安装 Linux 内核

在安装您喜欢的 Linux 发行版之前的最后一步是安装内核以便运行。在撰写本文时，这是一个手动步骤；将来计划通过 Windows 更新进行自动更新！

现在，访问[`aka.ms/wsl2kernel`](http://aka.ms/wsl2kernel)获取下载和安装内核的链接。完成后，您可以选择要安装的**Linux 发行版**。

# 在 WSL 中安装 Linux 发行版

安装 WSL 的 Linux 发行版的标准方法是通过 Microsoft Store 进行。当前可用的 Linux 发行版的完整列表可以在官方文档中找到（[`docs.microsoft.com/windows/wsl/install-win10#install-your-linux-distribution-of-choice`](https://docs.microsoft.com/windows/wsl/install-win10#install-your-linux-distribution-of-choice)）。在撰写本文时，这包括各种版本的 Ubuntu、OpenSUSE Leap、SUSE Linux Enterprise Server、Kali、Debian、Fedora Remix、Pengwin 和 Alpine。由于我们无法为本书中的每个 Linux 版本都提供示例，我们将重点介绍如何使用*Ubuntu*进行示例。

提示

前一章的步骤已经安装了运行版本 2 发行版所需的所有部分，但版本 1 仍然是默认设置！

这些命令将在本章的下一节中介绍，但如果您想将版本 2 设置为您安装的任何 Linux 发行版的默认设置，则运行以下命令：

`wsl --set-default-version 2`

如果您从 Windows 启动 Microsoft Store，可以搜索您选择的 Linux 发行版。例如，以下图显示了在 Microsoft Store 中搜索`Ubuntu`的结果：

![图 2.4-在 Microsoft Store 中搜索 Linux 发行版](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_2.4_B16412.jpg)

图 2.4-在 Microsoft Store 中搜索 Linux 发行版

当您找到想要的发行版时，请按照以下步骤进行操作：

1.  单击它，然后单击**安装**。然后，商店应用程序将为您下载和安装发行版。

1.  安装完成后，您可以点击**启动**按钮来运行。这将开始您选择的发行版的设置过程，如图所示（以 Ubuntu 为例）。

1.  在设置过程中，您将被要求输入 UNIX 用户名（不必与 Windows 用户名匹配）和 UNIX 密码。

此时，您安装的发行版将运行 WSL 的版本 1（除非您之前运行过`wsl --set-default-version 2`命令）。不用担心-下一节将介绍`wsl`命令，包括在版本 1 和版本 2 之间转换已安装的 Linux 发行版！

现在您已经安装了 Linux 发行版，让我们来看看如何配置和控制它。

# 配置和控制 WSL

前面的部分简要提到了`wsl`命令，这是与 WSL 交互和控制的最常见方式。在本节中，您将学习如何使用`wsl`命令交互地控制 WSL，以及如何通过修改`wsl.conf`配置文件中的设置来更改 WSL 的行为。

重要提示

早期版本的 WSL 提供了一个`wslconfig.exe`实用程序。如果您在文档或文章中看到任何对此的引用，请不用担心-`wslconfig.exe`的所有功能（以及更多）都可以在接下来的部分中看到的`wsl`命令中使用。

以下部分中的命令和配置将为您提供控制 WSL 中运行的发行版以及配置发行版（以及整个 WSL）行为以满足您的要求所需的工具。

## 介绍 wsl 命令

`wsl`命令提供了一种控制和与 WSL 及已安装的 Linux 发行版交互的方式，例如在发行版中运行命令或停止运行的发行版。在本节中，您将通过`wsl`命令的最常用选项进行一次浏览。如果您感兴趣，可以通过运行`wsl --help`找到完整的选项集。

### 列出发行版

`wsl`命令是一个多功能命令行实用程序，既可以用于控制 WSL 中的 Linux 发行版，也可以用于在这些发行版中运行命令。

要开始，请运行`wsl --list`以获取您已安装的 Linux 发行版的列表：

```
PS C:\> wsl --list
Windows Subsystem for Linux Distributions:
Ubuntu-20.04 (Default)
Legacy
docker-desktop
docker-desktop-data
WLinux
Alpine
Ubuntu
PS C:\>
```

前面的输出显示了已安装发行版的完整`列表`，但还有一些其他开关可以应用于自定义此命令的行为。例如，如果您只想查看正在运行的发行版，则可以使用`wsl --list --running`，如下面的片段所示：

```
PS C:\> wsl --list --running
Windows Subsystem for Linux Distributions:
Ubuntu-20.04 (Default)
Ubuntu
PS C:\>
```

列表命令的另一个有用变体是详细输出选项，使用`wsl --list –verbose`来实现，如下所示：

```
PS C:\> wsl --list --verbose
  NAME                   STATE           VERSION
* Ubuntu-20.04           Running         2
  Legacy                 Stopped         1
  docker-desktop         Stopped         2
  docker-desktop-data    Stopped         2
  WLinux                 Stopped         1
  Alpine                 Stopped         2
  Ubuntu                 Running         2
PS C:\>
```

如前面的输出所示，详细选项显示了每个发行版使用的 WSL 版本；您可以看到同时支持`1`和`2`。详细输出还显示了每个发行版是否正在运行。它还在默认发行版旁边包含了一个星号（`*`）。

除了获取有关 WSL 的信息外，我们还可以使用`wsl`命令来控制发行版。

### 控制 WSL 发行版

如`wsl --list --verbose`的输出所示，可以同时安装多个并且它们可以使用不同版本的 WSL。除了具有并行版本之外，安装后还可以在 WSL 版本之间转换发行版。要实现这一点，您可以使用`wsl --set-version`命令。

此命令接受两个参数：

+   要更新的发行版的名称

+   要转换的版本

这里显示了将`Ubuntu`发行版转换为版本 2 的示例：

```
PS C:\> wsl --set-version Ubuntu 2
Conversion in progress, this may take a few minutes...
For information on key differences with WSL 2 please visit https://aka.ms/wsl2
Conversion complete.
PS C:\>
```

默认情况下，为 WSL 安装 Linux 发行版将其安装为版本 1。但是，可以使用`wsl --set-default-version`命令将其更改为默认版本，该命令接受一个版本参数作为默认版本。

例如，`wsl --set-default-version 2`将使 WSL 的版本 2 成为您安装的任何新发行版的默认版本。

接下来，让我们来看看在 Linux 发行版中运行命令的方法。

### 使用 wsl 命令运行 Linux 命令

`wsl`命令的另一个功能是在 Linux 中运行命令。实际上，如果不带任何参数运行`wsl`，它将在默认发行版中启动一个 shell！

如果将命令字符串传递给`wsl`，它将在默认发行版中运行该命令。例如，下面的片段显示了运行`wsl ls ~`和`wsl cat /etc/issue`的输出：

```
PS C:\> wsl ls ~
Desktop    Downloads  Pictures  Templates  source    tmp
Documents  Music      Public    Videos     go        ssh-test  
PS C:\> wsl cat /etc/issue
Ubuntu 20.04 LTS \n \l
PS C:\>
```

从前面的 `wsl cat /etc/issue` 输出可以看出，命令是在 Ubuntu-20.04 发行版中运行的。如果您安装了多个发行版并且想要在特定的发行版中运行命令，则可以使用 `-d` 开关来指定要在其中运行命令的发行版。您可以使用 `wsl --list` 命令获取发行版名称。下面是一些 `wsl -d` 的示例：

```
PS C:\> wsl -d Ubuntu-20.04 cat /etc/issue
Ubuntu 20.04 LTS \n \l
PS C:\> wsl -d Alpine cat /etc/issue
Welcome to Alpine Linux 3.11
Kernel \r on an \m (\l)
PS C:\>
```

前面的示例显示了在多个发行版中运行 `cat /etc/issue` 命令，并且输出确认了命令所针对的发行版。

除了允许您选择在哪个 Linux 发行版中运行命令外，`wsl` 命令还允许您通过 `-u` 开关指定要以哪个用户身份运行命令。我发现最常用的用途是以 root 身份运行命令，这允许使用 `sudo` 在不提示输入密码的情况下运行命令。`-u` 开关在以下输出中进行了演示：

```
PS C:\> wsl whoami
stuart
PS C:\> wsl -u stuart whoami
stuart
PS C:\> wsl -u root whoami
root
PS C:\>
```

前面的输出显示了 `whoami` 命令（输出当前用户）。如果不传递 `-u` 开关，您可以看到命令是以在安装发行版时创建的 `stuart` 用户身份运行的，但是这可以被覆盖。

我们将看一个关于 `wsl` 命令停止运行发行版的最后一个示例。

### 使用 WSL 停止发行版

如果您一直在运行 WSL 并且想要出于任何原因停止它，也可以使用 `wsl` 命令来完成。

如果您运行了多个发行版，并且只想停止特定的一个，可以运行 `wsl --terminate <distro>`，例如 `wsl --terminate Ubuntu-20.04`。

提示

请记住，您可以使用 `wsl --list --running` 命令获取当前正在运行的发行版，就像我们之前看到的那样。

如果您想关闭 WSL 和所有正在运行的发行版，可以运行 `wsl --shutdown`。

现在我们已经看到了如何使用 `wsl` 命令来控制 WSL，让我们来看看 WSL 的配置文件。

## 介绍 wsl.conf 和 .wslconfig

WSL 提供了几个可以配置其行为的位置。其中之一是 `wsl.conf`，它提供了每个发行版的配置，另一个是 `.wslconfig`，它提供了全局配置选项。这两个文件允许您启用 WSL 的不同功能，例如在发行版中挂载主机驱动器的位置，或者控制整体的 WSL 行为，例如它可以消耗多少系统内存。

### 使用 wsl.conf 进行工作

`wsl.conf` 文件位于每个发行版的 `/etc/wsl.conf` 文件中。如果该文件不存在，并且您想要对某个发行版应用一些设置，则在该发行版中创建带有所需配置的文件，并重新启动该发行版（参见“使用 WSL 停止发行版”部分中的 `wsl --terminate`）。

默认选项通常工作良好，但本节将带您浏览 `wsl.conf`，以便您了解如果需要，可以自定义哪些类型的设置。

`wsl.conf` 文件遵循 `ini` 文件结构，其中的名称/值对按部分组织。请参阅以下示例：

```
[section]
value1 = true
value2 = "some content"
# This is just a comment
[section2]
value1 = true
```

以下示例显示了 `wsl.conf` 文件的一些主要部分和值以及它们的默认选项：

```
[automount]
enabled = true # control host drive mounting (e.g. /mnt/c)
mountFsTab = true # process /etc/fstab for additional mounts
root = /mnt/ # control where drives are mounted
[interop]
enabled = true # allow WSl to launch Windows processes
appendWindowsPath = true # add Windows PATH to $PATH in WSL
```

`automount` 部分提供了控制 WSL 在发行版内部挂载 Windows 驱动器的选项。`enabled` 选项允许您完全启用或禁用此行为，而 `root` 选项允许您控制驱动器挂载应在发行版文件系统的哪个位置创建，如果您有理由或偏好将其放在不同的位置。

`interop` 部分控制着允许 Linux 发行版与 Windows 交互的功能。您可以通过将 `enabled` 属性设置为 `false` 来完全禁用该功能。默认情况下，Windows 的 `PATH` 会附加到发行版的 `PATH` 中，但如果您需要更精细地控制发现哪些 Windows 应用程序，则可以使用 `appendWindowsPath` 设置来禁用此功能。

有关`wsl.conf`的完整文档可以在[`docs.microsoft.com/en-us/windows/wsl/wsl-config#configure-per-distro-launch-settings-with-wslconf`](https://docs.microsoft.com/en-us/windows/wsl/wsl-config#configure-per-distro-launch-settings-with-wslconf)找到。您将在*第五章*中了解有关从 WSL 内部访问 Windows 文件和应用程序的更多信息，*Linux 到 Windows 的互操作性*。

在这里，我们已经看到了如何更改每个发行版的配置，接下来我们将看一下系统范围的 WSL 配置选项。

### 使用.wslconfig 文件

除了每个发行版的`wsl.conf`配置外，WSL 的第 2 版还添加了一个全局的`.wslconfig`文件，可以在您的`Windows 用户`文件夹中找到，例如`C:\Users\<您的用户名>\.wslconfig`。

与`wsl.conf`文件一样，`.wslconfig`使用`ini`文件结构。以下示例显示了`[wsl2]`部分的主要值，它允许您更改 WSL 版本 2 的行为：

```
[wsl2]
memory=4GB
processors=2
localhostForwarding=true
swap=6GB
swapFile=D:\\Temp\\WslSwap.vhdx
```

`memory`值配置了用于 WSL 第 2 版的轻量级实用虚拟机消耗的内存限制。默认情况下，这是系统内存的 80%。

同样，`processors`允许您限制虚拟机使用的处理器数量（默认情况下没有限制）。这两个值可以帮助您平衡在 Windows 和 Linux 上运行的工作负载。

另一个需要注意的是路径（例如`swapFile`）需要是绝对路径，并且反斜杠（`\\`）需要转义显示。

还有其他选项（例如`kernel`和`kernelCommandLine`），允许您指定自定义内核或其他内核参数，这超出了本书的范围，但可以在文档中找到：[`docs.microsoft.com/en-us/windows/wsl/wsl-config#configure-global-options-with-wslconfig`](https://docs.microsoft.com/en-us/windows/wsl/wsl-config#configure-global-options-with-wslconfig)。

在本节中，您已经了解了如何通过在发行版的`wsl.conf`文件中更改设置来控制 WSL 集成功能，例如驱动器挂载和调用 Windows 进程的能力。您还了解了如何控制整个 WSL 系统的行为，例如限制内存使用量或处理器数量。这些选项可以确保 WSL 以适合您的系统和工作流程的方式运行。

# 总结

在本章中，您已经了解了如何启用 WSL，安装 Linux 发行版，并确保它们在 WSL 的第 2 版下运行。您还学习了如何使用`wsl`命令来控制 WSL，以及如何使用`wsl.conf`和`.wslconfig`配置文件进一步控制 WSL 和其中运行的发行版的行为。有了这些工具，您可以控制 WSL 及其与系统的交互方式。

在下一章中，我们将介绍新的 Windows 终端，它是与 WSL 自然配对的。我们将介绍如何安装它并使其运行起来。


# 第三章：开始使用 Windows 终端

微软已经宣布在即将发布的 Windows 子系统中支持 GUI 应用程序，但在撰写本书时，即使是早期预览形式也不可用。在本书中，我们选择关注 WSL 的稳定发布功能，因此它涵盖了 WSL 的当前以命令行为中心的视图。因此，装备一个良好的终端体验是有意义的。Windows 中的默认控制台体验（由`cmd.exe`使用）在许多方面都有所欠缺，而新的 Windows 终端提供了许多好处。在本章中，我们将介绍其中一些好处，以及如何安装和开始使用 Windows 终端。

在本章中，我们将涵盖以下主要主题：

+   介绍 Windows 终端

+   安装 Windows 终端

+   使用 Windows 终端

+   配置 Windows 终端

# 介绍 Windows 终端

Windows 终端是 Windows 的替代终端体验。如果您习惯在 Windows 上运行命令行应用程序，您可能熟悉在运行 PowerShell 或`cmd.exe`时看到的以前的 Windows 控制台体验（如下图所示）：

![图 3.1 - 显示 cmd.exe 用户体验的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.1_B16412.jpg)

图 3.1 - 显示 cmd.exe 用户体验的屏幕截图

Windows 控制台有着悠久的历史，可以追溯到 Windows NT 和 Windows 2000 时代，甚至可以追溯到 Windows 3.x 和 95/98 时代！在此期间，许多 Windows 用户创建了依赖于 Windows 控制台行为的脚本和工具。Windows 控制台团队设法改进了体验（例如，*Ctrl* +鼠标滚轮滚动以缩放文本，并改进了许多 Linux 和 UNIX 命令行应用程序和 shell 发出的 ANSI/VT 控制序列的处理），但在不破坏向后兼容性的情况下，他们最终受到了一些限制。

Windows 控制台团队花费了时间重构控制台的代码，以使其他终端体验（如新的 Windows 终端）能够在其之上构建。

新的 Windows 终端提供了许多改进，使其成为 Windows 控制台应用程序和 Linux shell 应用程序的终端体验更好。通过 Windows 终端，您可以更丰富地支持自定义终端的外观和感觉，并控制键绑定的配置。您还可以在终端中拥有多个选项卡，就像在 Web 浏览器中拥有多个选项卡一样，如下图所示：

![图 3.2 - 显示 Windows 终端中多个选项卡的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.2_B16412.jpg)

图 3.2 - 显示 Windows 终端中多个选项卡的屏幕截图

除了每个窗口有多个选项卡外，Windows 终端还支持将选项卡分割为多个窗格。与选项卡不同，只有一个选项卡可见，而窗格可以将选项卡细分为多个部分。*图 3.3*显示了 Windows 终端中具有多个窗格的情况，其中混合了在 WSL2 中运行的 Bash 和在 Windows 中运行的 PowerShell：

![图 3.3 - 显示 Windows 终端中多个窗格的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.3_B16412.jpg)

图 3.3 - 显示 Windows 终端中多个窗格的屏幕截图

从上述屏幕截图中可以看出，与默认控制台体验相比，Windows 终端体验有了很大的改进。

您将学习如何利用其更丰富的功能，例如*第六章*中的窗格，*从 Windows 终端获取更多信息*，但现在您已经了解了 Windows 终端的特点，让我们开始安装吧！

# 安装 Windows 终端

Windows 终端（截至撰写本文时）仍在积极开发中，它位于 GitHub 上的[`github.com/microsoft/terminal`](https://github.com/microsoft/terminal)。如果您想运行最新的代码（或有兴趣贡献功能），那么 GitHub 上的文档将引导您完成构建代码所需的步骤。（GitHub 存储库也是提出问题和功能请求的好地方。）

安装 Windows 终端的更常见的方法是通过 Windows Store，它将安装应用程序并为您提供一种轻松的方式来保持更新。您可以在商店应用程序中搜索“Windows 终端”（如下图所示），或使用快速链接[`aka.ms/terminal`](https://aka.ms/terminal)：

![图 3.4-显示 Windows Store 应用程序的屏幕截图，显示 Windows 终端](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.4_B16412.jpg)

图 3.4-显示 Windows Store 应用程序的屏幕截图，显示 Windows 终端

如果您有兴趣提前测试功能（并且不介意潜在的偶尔不稳定），那么您可能会对 Windows 终端预览感兴趣。这也可以在商店应用程序中找到（您可能已经注意到它在前面的图中显示），或通过快速链接[`aka.ms/terminal-preview`](https://aka.ms/terminal-preview)获得。预览版本和主版本可以并行安装和运行。如果您对 Windows 终端的路线图感兴趣，可以在 GitHub 上的文档中找到[`github.com/microsoft/terminal/blob/master/doc/terminal-v2-roadmap.md`](https://github.com/microsoft/terminal/blob/master/doc/terminal-v2-roadmap.md)。

现在您已经安装了 Windows 终端，让我们来了解一些功能。

# 使用 Windows 终端

当您运行 Windows 终端时，它将启动您的默认配置文件。配置文件是指定在终端实例中运行哪个 shell 的一种方式，例如 PowerShell 或 Bash。单击标题栏中的**+**以使用默认配置文件创建一个新选项卡的另一个实例，或者您可以单击向下箭头选择要运行的配置文件，如下图所示：

![图 3.5-显示用于创建新选项卡的配置文件下拉菜单的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.5_B16412.jpg)

图 3.5-显示用于创建新选项卡的配置文件下拉菜单的屏幕截图

前面的图显示了启动新终端选项卡的一系列选项，每个选项都被称为一个配置文件。显示的配置文件是由 Windows 终端自动生成的-它检测到我机器上安装了什么，并创建了动态配置文件列表。更好的是，如果我在安装 Windows 终端之后安装了新的 WSL 发行版，它将自动添加到可用配置文件列表中！我们稍后将快速查看如何配置您的配置文件，但首先，让我们看一些 Windows 终端的方便键盘快捷键。

## 学习方便的键盘快捷键

无论您是键盘快捷键的粉丝还是主要使用鼠标的用户，了解一些键盘快捷键都是有益的，尤其是对于 Windows 终端中的常见场景，因此本节列出了最常见的键盘快捷键。

您刚刚看到了如何使用 Windows 终端标题栏中的**+**和向下箭头启动具有默认配置文件的新选项卡或选择要启动的配置文件。使用键盘，可以使用*Ctrl* + *Shift* + *T*启动默认配置文件的新实例。要显示配置文件选择器，可以使用*Ctrl* + *Shift* +空格键，但是如果您查看*图 3.5*中的屏幕截图，您会看到前九个配置文件实际上有自己的快捷键：*Ctrl* + *Shift* + *1*启动第一个配置文件，*Ctrl* + *Shift* + *2*启动第二个配置文件，依此类推。

当您在 Windows 终端中打开多个标签页时，您可以使用*Ctrl* + *Tab*向前导航标签页，使用*Ctrl* + *Shift* + *Tab*向后导航（这与大多数带有标签的浏览器相同）。如果您想导航到特定的标签页，可以使用*Ctrl* + *Alt* + *<n>*，其中*<n>*是您要导航到的标签页的位置，例如，*Ctrl* + *Alt* + *3*导航到第三个标签页。最后，您可以使用*Ctrl* + *Shift* + *W*关闭标签页。

使用键盘可以快速管理 Windows 终端中的标签页。如果 Windows 终端检测到很多配置文件，您可能希望控制它们的顺序，以便将您最常使用的配置文件放在顶部以便轻松访问（并确保它们获取快捷键）。我们将在下一节中看看这个以及其他一些配置选项。

# 配置 Windows 终端

Windows 终端的所有设置都存储在您的 Windows 配置文件中的一个`JSON`文件中。要访问设置，您可以单击向下箭头选择要启动的配置文件，然后选择系统中`JSON`文件的默认编辑器中的`settings.json`。

`settings`文件分为几个部分：

+   `JSON`文件

+   **每个配置文件的设置**，独立定义和配置每个配置文件

+   指定配置文件可以使用的颜色方案的**方案**

+   **键绑定**，允许您自定义在 Windows 终端中执行任务的键盘快捷键

在 Windows 终端的设置中，有很多可以调整的选项，并且随着不断更新，会出现新的选项！所有设置的完整描述留给文档（[`docs.microsoft.com/en-us/windows/terminal/customize-settings/global-settings`](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/global-settings)），我们将重点关注一些可能要进行的自定义以及如何使用`settings`文件实现它们。

让我们开始看一些您可能想要对 Windows 终端中的配置文件进行的自定义。

## 自定义配置文件

`settings`文件的`profiles`部分控制 Windows 终端在单击新标签下拉菜单时显示的配置文件，并允许您配置配置文件的各种显示选项。您还可以选择默认启动的配置文件，如下所示。

### 更改默认配置文件

您可能希望首先进行的更改之一是控制在启动 Windows 终端时默认启动哪个配置文件，以便自动启动您最常使用的配置文件。

此设置在全局设置中的`defaultProfile`值中设置，如下例所示（全局设置是`settings`文件顶层的值）：

```
{
    "$schema": "https://aka.ms/terminal-profiles-schema",
    "defaultProfile": "Ubuntu-20.04",
```

`defaultProfile`设置的值允许您使用要设置为默认配置文件的配置文件的`name`（或关联的`guid`）属性。请确保输入与`profiles`部分中指定的名称完全相同。

接下来，您将查看如何更改 Windows 终端配置文件的顺序。

### 更改配置文件的顺序

您可能希望进行的另一个提高生产力的更改是按照最常用的配置文件顺序排列，以便轻松访问顶部。如果您使用键盘快捷键启动新标签页，则顺序决定了快捷键是什么，因此在这里顺序具有额外的重要性。以下图显示了在我的机器上的初始顺序，如前一节中的设置所示：

![图 3.6 - 显示初始配置文件顺序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.6_B16412.jpg)

图 3.6 - 显示初始配置文件顺序的屏幕截图

在屏幕截图中，您可以看到 PowerShell 是第一个列出的配置文件（您还可以注意到 PowerShell 以粗体显示，表示它是默认配置文件）。

要更改 UI 中配置文件的顺序，我们可以更改`settings`文件中`profiles`下的`list`中的条目顺序。以下代码片段显示了上一节中的设置更新，使**Ubuntu-20.04**成为列表中的第一项：

```
    "profiles":
    {
        "defaults":
        {
            // Put settings here that you want to apply to all profiles.
        },
        "list":
        
            {
                "guid": "{07b52e3e-de2c-5db4-bd2d-ba144ed6c273}",
                "hidden": false,
                "name": "Ubuntu-20.04",
                "source": "Windows.Terminal.Wsl"
            },
            {
                "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
                "hidden": false,
                "name": "PowerShell",
                "source": "Windows.Terminal.PowershellCore"
            },
            {
                "guid": "{6e9fa4d2-a4aa-562d-b1fa-0789dc1f83d7}",
                "hidden": false,
                "name": "Legacy",
                "source": "Windows.Terminal.Wsl"
            },
// ... more settings omitted
```

保存`settings`文件后，您可以返回到 Windows 终端的下拉菜单中查看顺序的更改：

![图 3.7 - 显示更新后的配置文件顺序的屏幕截图图 3.7 - 显示更新后的配置文件顺序的屏幕截图在上述屏幕截图中，请注意**Ubuntu-20.04**位于列表顶部，现在具有**Ctrl+Shift+1**的快捷键。值得注意的是，**PowerShell**仍然以粗体显示，表示它仍然是默认配置文件，即使它不再是列表中的第一个。需要注意的一点是，列表中的每个项目都需要用逗号分隔，并且最后一个列表项后面不能有逗号。如果您更改列表末尾的项目，这可能会让您感到困惑。然而，Windows 终端可能会显示警告，如下图所示：![图 3.8 - 显示加载设置时出现错误的示例屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.8_B16412.jpg)

图 3.8 - 显示加载设置时出现错误的示例屏幕截图

如果您在上述屏幕截图中看到错误，请不要担心。当 Windows 终端运行时，它会在文件更改时重新加载设置。错误指出了`settings`文件中有错误的部分。当您关闭错误时，Windows 终端仍会重新加载您的设置。

除了控制配置文件在列表中显示的顺序，您还可以更改它们在列表中的显示方式，如下所示。

### 重命名配置文件和更改图标

Windows 终端在预填充配置文件方面做得很好，但您可能希望重命名配置文件。要做到这一点，请根据以下代码片段所示，更改相关配置文件的`name`属性的值。与之前一样，一旦保存文件，Windows 终端将重新加载它并应用更改：

```
{
    "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
    "hidden": false,
    "name": "** PowerShell **",
    "source": "Windows.Terminal.PowershellCore"
},
```

您甚至可以通过 Windows 表情符号支持进一步操作。当您更改配置文件的名称时，按下*Win* + *.*以打开表情符号选择器，然后继续输入以过滤表情符号列表。例如，下图显示了筛选到猫的情况：

![图 3.9 - 显示使用表情选择器的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.9_B16412.jpg)

图 3.9 - 显示使用表情选择器的屏幕截图

从列表中选择一个表情符号将其插入到编辑器中，如下图所示：

![图 3.10 - 显示已完成的 PowerShell 配置文件的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.10_B16412.jpg)

图 3.10 - 显示已完成的 PowerShell 配置文件的屏幕截图

在此屏幕截图中，您可以看到在`name`属性中使用了一个表情符号。除了更改名称外，设置还允许您自定义列表中配置文件旁边显示的图标。通过向配置文件添加一个图标属性来实现，该属性给出了您希望使用的图标的路径，如上一个屏幕截图所示。该图标可以是`PNG`，`JPG`，`ICO`或其他文件类型 - 我倾向于使用`PNG`，因为它在各种编辑器中易于使用，并允许图像的透明部分。

值得注意的是，路径需要将反斜杠（`\`）转义为双反斜杠（`\\`）。方便的是，您还可以在路径中使用环境变量。这使您可以将图标放在 OneDrive（或其他文件同步平台）中，并在多台机器上共享它们（或仅备份以供将来使用）。要使用环境变量，请将其用百分号括起来，如上面的代码片段中所示的`%OneDrive%`。

这些自定义（图标和文本）的结果如下图所示：

![图 3.11 - 显示自定义图标和文本（包括表情符号！）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_3.11_B16412.jpg)

图 3.11 - 显示自定义图标和文本（包括表情符号！）的屏幕截图

到目前为止，您已经了解了如何控制配置文件列表中的项目以及它们的显示方式。最后要看的是如何从列表中删除项目。

### 删除配置文件

如果您已经阅读了前面的部分，您可能会认为删除配置文件只需从列表中删除条目即可。然而，如果配置文件是动态生成的，则在下次加载设置时，Windows Terminal 将重新添加该配置文件（在列表底部）！虽然这可能看起来有点奇怪，但这是 Windows Terminal 自动检测新配置文件（例如新的 WSL Distros）的副作用，即使您在安装 Windows Terminal 之后安装它们。相反，要防止配置文件显示在列表中，您可以设置隐藏属性，如下面的代码片段所示：

```
{
    "guid": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
    "name": "Command Prompt",
    "commandline": "cmd.exe",
    "hidden": true
}
```

现在我们已经探索了如何控制 Windows Terminal 中的配置文件，让我们来看看如何自定义其外观。

## 更改 Windows Terminal 的外观

Windows Terminal 提供了多种方式来自定义其外观，您进行这些操作的动机可能纯粹是为了美观，也可能是为了通过增大字体大小、增加对比度或使用特定字体使内容更易读（例如，在[`www.opendyslexic.org/`](https://www.opendyslexic.org/)上提供的**OpenDyslexic**字体）来使终端更易于使用。

### 更改字体

Windows Terminal 的默认字体是一种名为`!=`的新字体，当呈现为`≠`时，这两个字符会合并在一起。如果您不想使用连字，则**Cascadia Mono**是相同的字体，但不包含连字。

可以通过在配置文件中设置`fontFace`和`fontSize`属性来独立更改每个配置文件的字体，如下面的示例所示：

```
{
    "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
    "hidden": false,
    "name": "PowerShell",
    "source": "Windows.Terminal.PowershellCore",
    "fontFace": "OpenDyslexicMono",
    "fontSize": 16
},
```

如果您想为所有配置文件自定义字体设置，可以在`defaults`部分中添加`fontFace`和`fontSize`属性，如下面的代码片段所示：

```
"profiles": {
    "defaults": {
        // Put settings here that you want to apply to all profiles.
        "fontFace": "OpenDyslexicMono",
        "fontSize": 16
    },
```

在`defaults`部分指定的设置适用于所有配置文件，除非配置文件覆盖它。现在我们已经了解了如何更改字体，让我们来看看如何控制颜色方案。

### 更改颜色

Windows Terminal 允许您以几种方式自定义配置文件的颜色方案。

最简单的自定义是在配置文件中使用`foreground`、`background`和`cursorColor`属性。这些值以`#rgb`或`#rrggbb`的形式指定为 RGB 值（例如，`#FF0000`表示亮红色）。以下是示例代码片段：

```
{
    "guid": "{07b52e3e-de2c-5db4-bd2d-ba144ed6c273}",
    "name": "Ubuntu-20.04",
    "source": "Windows.Terminal.Wsl",
    "background": "#300A24",
    "foreground": "#FFFFFF",
    "cursorColor": "#FFFFFF"
},
```

要更精细地控制颜色，您可以在`settings`文件的`schemes`部分下创建一个颜色方案。有关详细信息，请参阅[`docs.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes`](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes)，其中包括内置颜色方案的列表。如下面的示例所示，方案具有名称和一组以`#rgb`或`#rrggbb`形式的颜色规范：

```
"schemes": [
    {
        "name" : "Ubuntu-inspired",
        "background" : "#300A24",
        "foreground" : "#FFFFFF",
        "black" : "#2E3436",
        "blue" : "#0037DA",
        "brightBlack" : "#767676",
        "brightBlue" : "#3B78FF",
        "brightCyan" : "#61D6D6",
        "brightGreen" : "#16C60C",
        "brightPurple" : "#B4009E",
        "brightRed" : "#E74856",
        "brightWhite" : "#F2F2F2",
        "brightYellow" : "#F9F1A5",
        "cyan" : "#3A96DD",
        "green" : "#13A10E",
        "purple" : "#881798",
        "red" : "#C50F1F",
        "white" : "#CCCCCC",
        "yellow" : "#C19C00"
    }
],
```

定义颜色方案后，您需要更新配置文件设置以使用它。您可以使用`colorScheme`属性指定这一点，并将其应用于单个配置文件级别，或者使用前面在本章中看到的`default`部分将其应用于所有配置文件。以下是将其应用于单个配置文件的示例：

```
{
    "guid": "{07b52e3e-de2c-5db4-bd2d-ba144ed6c273}",
    "name": "Ubuntu-20.04",
    "source": "Windows.Terminal.Wsl",
    "colorScheme": "Ubuntu-inspired"
},
```

保存这些更改后，Windows Terminal 将将您定义的颜色方案应用于使用该配置文件的任何选项卡。

通过这里展示的选项，您可以自定义默认启动的配置文件以及配置文件在配置文件列表中的显示顺序和方式。您已经看到了各种选项，可以让您自定义配置文件在运行时的显示方式，这将使您能够轻松应用其他设置，如设置背景图像或更改终端配置文件的透明度。完整的详细信息可以在 Windows 终端文档中找到：[`docs.microsoft.com/en-us/windows/terminal/customize-settings/profile-settings`](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/profile-settings)。

# 总结

在本章中，您已经了解了 Windows 终端以及它如何通过更好地控制显示和支持多个选项卡等功能来改进以前的终端体验。在使用 WSL 时，自动检测您安装的新 Linux 发行版的终端也是一个不错的好处！

您已经了解了如何安装和使用 Windows 终端，以及如何根据自己的喜好进行自定义，以便您可以轻松阅读文本，并定义颜色方案以便轻松知道哪些终端配置文件正在运行。通过自定义默认配置文件和配置文件顺序，您可以确保轻松访问您最常使用的配置文件，帮助您保持高效。在下一章中，我们将开始使用 Windows 终端，探索如何在 Windows 上与 Linux 发行版进行交互。


# 第二部分：Windows 和 Linux - 一个胜利的组合

本节深入探讨了在 Windows 和 Windows 子系统之间进行工作的一些奇妙之处，展示了这两个操作系统如何协同工作。您还将了解更多关于有效使用 Windows 终端的技巧。最后，您还将了解如何在 WSL 中使用容器以及如何复制和管理您的 WSL 发行版。

本节包括以下章节：

【第四章】，*Windows 与 Linux 的互操作性*

【第五章】，*Linux 到 Windows 的互操作性*

【第六章】，*从 Windows 终端获取更多功能*

【第七章】，*在 WSL 中使用容器*

【第八章】，*使用 WSL 发行版进行工作*


# 第四章：Windows 与 Linux 的互操作性

在*第一章*中，我们将 WSL 体验与在虚拟机中运行 Linux 进行了比较；虚拟机专注于隔离，而 WSL 在 Windows 和 Linux 之间具有强大的互操作性。在本章中，您将开始了解这些功能，从与在 WSL 下运行的文件和应用程序进行交互开始，以及从 Windows 主机环境访问文件。这将包括查看如何在 Windows 和 WSL 中的脚本之间传递输出。之后，我们将看看 WSL 如何使 Linux 中的 Web 应用程序可以从 Windows 访问。

在本章中，我们将介绍以下主要内容：

+   从 Windows 访问 Linux 文件

+   从 Windows 运行 Linux 应用程序

+   从 Windows 访问 Linux Web 应用程序

让我们开始吧！

# 从 Windows 访问 Linux 文件

当您安装了 WSL 后，您会得到一个新的`\\wsl$`路径，您可以在 Windows 资源管理器和其他程序中使用它。如果您在 Windows 资源管理器的地址栏中键入`\\wsl$`，它将列出任何正在运行的 Linux 发行版（distros），如下面的截图所示：

图 4.1 - 在 Windows 资源管理器中显示\\wls$的截图

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_04_01.jpg)

图 4.1 - 在 Windows 资源管理器中显示的\\wls$的截图

如前面的截图所示，每个正在运行的发行版都显示为`\\wsl$`下的路径。每个`\\wsl$\<distroname>`都是访问`<distroname>`文件系统根目录的 Windows 路径。例如，`\\wsl$\Ubuntu-20.04`是从 Windows 访问`Ubuntu-20.04`发行版文件系统根目录的路径。这是一种非常灵活和强大的功能，使您可以完全访问 Windows 上的 Linux 发行版的文件系统。

下面的截图显示了 Windows 资源管理器中的`\\wsl$\Ubuntu-20.04\home\stuart\tmp`路径。这对应于`Ubuntu-20.04`发行版中的`~/tmp`文件夹：

图 4.2 - 在 Windows 资源管理器中显示 Linux 发行版内容的截图

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_04_02.jpg)

图 4.2 - 在 Windows 资源管理器中显示 Linux 发行版内容的截图

在这些截图中，您可以在 Windows 资源管理器中看到 Linux 文件系统，但是任何可以接受 UNC 路径（即以`\\`开头的路径）的应用程序都可以使用这些路径。例如，从 PowerShell 中，您可以像在 Windows 中一样读取和写入 Linux 文件系统：

```
C:\ > Get-Content '\\wsl$\ubuntu-20.04\home\stuart\tmp\hello-wsl.txt'
Hello from WSL!
C:\ >
```

在此示例中，在 Ubuntu 20.04 发行版中创建了一个名为`~/tmp/hello-wsl.txt`的文本文件，内容为`Hello from WSL!`，并使用`Get-Content` PowerShell cmdlet 使用我们之前看到的`\\wsl$\...`路径读取文件的内容。

在 Windows 资源管理器中浏览文件系统时，双击文件将尝试在 Windows 中打开它。例如，双击我们在*图 4.2*中查看的文本文件将在您的默认文本编辑器（在我的情况下是记事本）中打开，如下面的截图所示：

图 4.3 - 在记事本中打开的 Linux 文件的截图

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_04_03.jpg)

图 4.3 - 在记事本中打开的 Linux 文件的截图

此截图显示了与之前通过 PowerShell 获取文件内容的示例相同的内容，但在记事本中打开。使用`\\wsl$\...`路径。

提示

如果您浏览到`\\wsl$`并且看不到您安装的发行版之一，则表示该发行版未运行。

启动发行版的简单方法是使用 Windows 终端在其中启动一个 shell。或者，如果您知道发行版的名称，您可以在 Windows 资源管理器的地址栏（或您正在使用的任何应用程序）中键入`\\wsl$\<distroname>`，WSL 将自动启动发行版，以允许您浏览文件系统！

正如您在本节中所看到的，`\\wsl$\`共享提供了从 Windows 应用程序访问 WSL 发行版文件系统内文件的能力。这是在 WSL 中桥接 Windows 和 Linux 的有用步骤，因为它允许您使用 Windows 工具和应用程序来处理 Linux 文件系统中的文件。

接下来，我们将看一下如何从 Windows 中运行 WSL 中的应用程序。

# 从 Windows 中运行 Linux 应用程序

在*第二章*中，*安装和配置 Windows 子系统*，我们简要介绍了`wsl`命令，并且您看到了它如何用于控制运行的发行版和在发行版内执行应用程序。在本节中，我们将深入探讨使用`wsl`命令在发行版中运行应用程序。

正如我们在上一节中看到的，能够在 Windows 和 Linux 之间访问文件非常有用，而能够调用应用程序进一步增强了这一功能。WSL 不仅可以从 Windows 中的发行版运行应用程序，还可以在应用程序之间进行输出导入。在 Windows 或 Linux 中构建脚本时，通过应用程序之间的输出导入来构建脚本功能是一种非常常见的方式。能够在 Windows 和 Linux 命令之间进行输出导入，使您能够构建在 Windows 和 Linux 上运行的脚本，这真的有助于建立这两个环境的统一感。我们将开始看一下它是如何工作的。

## 导入到 Linux 中

在本节中，我们将探讨将数据从 Linux 传输到 Windows 的方法。我遇到过很多次的一种情况是有一些数据，比如日志输出，我想对其进行一些处理。一个例子是处理每一行以提取 HTTP 状态码，然后进行分组和计数，以计算记录了多少个成功和失败。我们将使用一个代表这种情况的示例，但不需要任何真实的设置：我们将检查 Windows 目录中以每个字母开头的文件数量。

让我们从一些 PowerShell 开始（我们将逐步构建脚本，所以如果您对 PowerShell 不太熟悉，不用担心）：

1.  首先，我们将使用`Get-ChildItem`获取`Windows`文件夹的内容，如下所示：

```
SystemRoot environment variable to refer to the Windows folder (typically C:\Windows) in case you have customized the install location. The output shows some of the files and folders from the Windows folder, and you can see various properties for each item, such as LastWriteTime, Length, and Name.
```

1.  接下来，我们可以执行提取操作，例如提取文件名的第一个字母。我们可以通过将`Get-ChildItem`的输出导入到`ForEach-Object` cmdlet 中来扩展我们之前的命令，如下所示：

```
ForEach-Object, which takes the input ($_) and gets the first character using Substring, which lets you take part of a string. The first argument to Substring specifies where to start (0 indicates the start of the string) and the second argument is how many characters to take. The previous output shows that some of the files and folders start with lowercase and others start with uppercase, so we call ToUpper to standardize using uppercase.
```

1.  下一步是对项目进行分组和计数。由于目标是演示在 Windows 和 Linux 之间进行输出导入，我们暂时忽略 PowerShell 的`Group-Object` cmdlet，而是使用一些常见的 Linux 实用工具：`sort`和`uniq`。如果您在 Linux 中使用这些命令与其他输出一起使用，可以将其作为`other-command | sort | uniq -c`进行管道传输。然而，由于`sort`和`uniq`是 Linux 命令，我们在 Windows 上运行此命令，需要使用`wsl`命令来运行它们，如下面的输出所示：

```
PS C:\> Get-Childitem $env:SystemRoot | ForEach-Object { $_.Name.Substring(0,1).ToUpper() } | wsl sort | wsl uniq -c                                                                                                              
      5 A
      5 B
      5 C
      9 D
      3 E
      2 F
...
```

前面的输出显示了我们的目标结果：每个字母开头的文件和文件夹的数量。但更重要的是，它显示了将 Windows 命令的输出导入 Linux 命令的管道工作正常！

在此示例中，我们调用了两次`wsl`：一次用于`sort`，一次用于`uniq`，这将导致输出在管道中的每个阶段在 Windows 和 Linux 之间进行传输。如果我们稍微改变命令的结构，我们可以使用单个`wsl`调用。尝试将输入管道到`wsl sort | uniq -c`可能会很诱人，但这会尝试将`wsl sort`的输出管道到 Windows 的`uniq`命令中。您还可以考虑`wsl "sort | uniq -c"`，但会出现错误`/bin/bash: sort | uniq -c: command not found`。相反，我们可以使用`wsl`运行`bash`和我们的命令`wsl bash -c "sort | uniq -c"`。完整的命令如下：

```
PS C:\> Get-Childitem $env:SystemRoot | ForEach-Object { $_.Name.Substring(0,1).ToUpper() } | wsl bash -c "sort | uniq -c"

      5 A
      5 B
      5 C
      9 D
      3 E
      2 F
...
```

正如您所看到的，这与先前版本的输出相同，但只执行了一次`wsl`。虽然这可能不是运行复杂命令的最明显的方法，但它是一种有用的技术。

在这个例子中，我们一直关注将数据导入 Linux，但当从 Linux 命令导出输出时，它同样有效，我们将在下一节中看到。

## 从 Linux 进行管道传输

在前一节中，我们看了如何将 Windows 命令的输出导入 Linux，并通过使用 PowerShell 检索`Windows`文件夹中的项目并获取它们的首字母，然后将字母传递给 Linux 实用程序进行排序、分组和计数来探索这一点。在本节中，我们将看看如何将 Linux 实用程序的输出导入 Windows。我们将使用反向示例，通过 Bash 列出文件并使用 Windows 实用程序处理输出。

首先，让我们从默认的发行版中获取`/usr/bin`文件夹中的文件和文件夹：

```
PS C:\> wsl ls /usr/bin
 2to3-2.7                             padsp
 GET                                  pager
 HEAD                                 pamon
 JSONStream                           paperconf
 NF                                   paplay
 POST                                 parec
 Thunar                               parecord
...
```

此输出显示了`/usr/bin`文件夹的内容，下一步是获取名称的第一个字符。为此，我们可以使用`cut`命令。我们可以运行`wsl ls /usr/bin | wsl cut -c1`，但我们可以重用我们在上一节中看到的技术将其组合成一个单独的`wsl`命令：

```
PS C:\> wsl bash -c "ls /usr/bin | cut -c1"
2
G
H
J
N
P
T
```

从前面的输出中可以看到，我们现在只有第一个字符，并且我们已经准备好对它们进行排序和分组。为了进行这个练习，我们假装`sort`和`uniq`命令不存在，而是使用 PowerShell 的`Group-Object` cmdlet：

```
PS C:\> wsl bash -c "ls /usr/bin | cut -c1-1" | Group-Object
Count Name                      Group
----- ----                      -----
    1 [                         {[}
    1 2                         {2}
   46 a                         {a, a, a, a…}
   79 b                         {b, b, b, b…}
   82 c                         {c, c, c, c…}
   79 d                         {d, d, d, d…}
   28 e                         {e, e, e, e…}
   49 f                         {f, f, f, f…}
  122 G                         {G, g, g, g…}
```

在这里，我们可以看到从在 WSL 中运行的 Bash 命令成功地通过管道传输到 PowerShell 的`Group-Object` cmdlet。在前一节中，我们强制将字符转换为大写，但在这里我们不需要这样做，因为`Group-Object`默认执行不区分大小写的匹配（尽管可以使用`-CaseSensitive`开关覆盖这一点）。

通过这些示例，您可以通过 WSL 调用 Linux 发行版来执行 Linux 应用程序和实用程序。这些示例只使用了默认的 WSL 发行版，但在上面的所有示例中，您可以在`wsl`命令上添加`-d`开关以指定要在其中运行 Linux 命令的发行版。如果您有多个发行版，并且您需要的特定应用程序仅在其中一个发行版中可用，这将非常有用。

能够在 Windows 和 Linux 应用程序之间双向传输输出允许在组合应用程序时具有很大的灵活性。如果您更熟悉 Windows 实用程序，您可以执行 Linux 应用程序，然后使用 Windows 实用程序处理结果。或者，如果 Linux 是您更熟悉的地方，但您需要在 Windows 机器上工作，那么能够调用熟悉的 Linux 实用程序来处理 Windows 输出将帮助您提高工作效率。

您已经看到如何从 Windows 访问 Linux 文件并从 Windows 调用 Linux 应用程序。在下一节中，您将看到如何从 Windows 访问在 WSL 中运行的 Web 应用程序。

# 从 Windows 访问 Linux Web 应用程序

如果您正在开发 Web 应用程序，那么在您工作时，通常会在 Web 浏览器中打开应用程序，地址为`http://localhost`。使用 WSL，您的 Web 应用程序在 WSL 轻量级虚拟机内运行，该虚拟机具有单独的 IP 地址（您可以使用 Linux 的`ip addr`命令找到此地址）。幸运的是，WSL 将 localhost 地址转发到 Linux 发行版以保持自然的工作流程。您将在本节中了解到这一点。

要跟随本章的内容，请确保您已经在 Linux 发行版中克隆了本书的代码，在终端中打开，并导航到`chapter-04/web-app`文件夹，网址为[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques/tree/main/chapter-04`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques/tree/main/chapter-04)。

示例代码使用 Python 3，如果您使用的是最新版本的 Ubuntu，则应该已经安装了 Python 3。您可以通过在 Linux 发行版中运行`python3 -c 'print("hello")'`来测试是否安装了 Python 3。如果命令成功完成，则说明已经准备就绪。如果没有，请参考 Python 文档以获取安装说明：[`wiki.python.org/moin/BeginnersGuide/Download`](https://wiki.python.org/moin/BeginnersGuide/Download)。

在`chapter-04/web-app`文件夹中，您应该看到`index.html`和`run.sh`。在终端中运行`./run.sh`来运行 Web 服务器：

```
$ ./run.sh
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ... 
```

您应该看到类似于前面输出的输出，以指示 Web 服务器正在运行。

您可以通过在 Linux 发行版中启动新的终端并运行`curl`来验证 Web 服务器是否正在运行：

```
$ curl localhost:8080
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chapter 4</title>
</head>
<body>
    <h1>Hello from WSL</h1>
    <p>This content is brought to you by python <a href="https://docs.python.org/3/library/http.server.html">http.server</a> from WSL.</p>
</body>
</html>
$
```

此输出显示了 Web 服务器对`curl`请求的响应返回的 HTML。

接下来，在 Windows 中打开您的 Web 浏览器，并导航到`http://localhost:8080`。

![图 4.4 - 显示 WSL Web 应用程序在 Windows 浏览器中的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_04_04.jpg)

图 4.4 - 显示 WSL Web 应用程序在 Windows 浏览器中的屏幕截图

正如前面的屏幕截图所示，WSL 将 Windows 中的**localhost**流量转发到 Linux 发行版。当您使用 WSL 开发 Web 应用程序或运行具有 Web 用户界面的应用程序时，您可以使用**localhost**访问 Web 应用程序，就像它在 Windows 本地运行一样；这是另一种真正平滑用户体验的集成。

# 总结

在本章中，您已经看到了 WSL 允许我们如何与 Linux 发行版在 Windows 中进行互操作的方式，从通过`\\wsl$\...`路径访问 Linux 文件系统开始。您还看到了如何从 Windows 调用 Linux 应用程序，并且可以通过在它们之间传递输出来链接 Windows 和 Linux 命令，就像在任一系统中一样。最后，您看到了 WSL 将**localhost**请求转发到在 WSL 发行版内部运行的 Web 服务器。这使您可以轻松地在 WSL 中开发和运行 Web 应用程序，并从 Windows 浏览器中进行测试。

能够从 Windows 访问 WSL 发行版的文件系统并在其中执行命令，真正有助于将这两个系统结合在一起，并帮助您选择您喜欢的工具来完成您正在进行的任务，而不管它们在哪个操作系统中。在下一章中，我们将探索从 WSL 发行版内部与 Windows 交互的能力。


# 第五章：Linux 到 Windows 的互操作性

在*第一章*中，*介绍 Windows 子系统 Linux*，我们将 WSL 体验与在虚拟机中运行 Linux 进行了比较，并提到了 WSL 的互操作性能力。在*第四章*中，*Windows 到 Linux 的互操作性*，我们看到了如何开始利用这些互操作性功能。在本章中，我们将继续探索互操作性功能，但这次是从 Linux 端进行。这将使您能够将 Windows 命令和工具的功能带入 WSL 环境中。

我们将首先看一下如何在 WSL 环境中与 Windows 应用程序和文件进行交互。接下来，我们将介绍如何在 Linux 和 Windows 之间处理脚本，包括如何在它们之间传递输入。最后，我们将提供一些互操作性技巧和窍门，以提高您的生产力，从通过别名使 Windows 命令更加自然，到在 Windows 和 Linux 之间共享**安全外壳**（**SSH**）密钥以便于使用和维护。

在本章中，我们将涵盖以下主要主题：

+   从 Linux 访问 Windows 文件

+   从 Linux 调用 Windows 应用程序

+   从 Linux 调用 Windows 脚本

+   互操作性技巧和窍门

让我们从第一个主题开始！

# 从 Linux 访问 Windows 文件

默认情况下，WSL 会自动将 Windows 驱动器挂载到 WSL 的`/mnt`目录下；例如，您的`C:`驱动器会被挂载为`/mnt/c`。要尝试这个功能，请在`C:`驱动器上创建一个名为`wsl-book`的文件夹，并在其中放置一个`example.txt`文件（文本文件的内容并不重要）。现在，在 WSL 中打开一个终端并运行`ls /mnt/c/wsl-book`，您将在 Bash 输出中看到您创建的文件：

![图 5.1 - 屏幕截图显示了从 Windows 和 WSL 列出文件夹内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_5.1_B16412.jpg)

图 5.1 - 屏幕截图显示了从 Windows 和 WSL 列出文件夹内容

此屏幕截图显示了 Windows 中的目录列表，右侧是 WSL 发行版中`/mnt/c`路径下的`example.txt`。

您可以像与任何其他文件一样与挂载的文件进行交互；例如，您可以使用`cat`命令查看文件的内容：

```
$ cat /mnt/c/wsl-book/example.txt
Hello from a Windows file!
```

或者，您可以将内容重定向到 Windows 文件系统中的文件：

```
$ echo "Hello from WSL" > /mnt/c/wsl-book/wsl.txt
$ cat /mnt/c/wsl-book/wsl.txt
Hello from WSL
```

或者，您可以在`vi`（或您喜欢的其他终端文本编辑器）中编辑文件：

![图 5.2 - 屏幕截图显示了在 WSL 下使用 vi 编辑 Windows 文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_5.2_B16413.jpg)

图 5.2 - 屏幕截图显示了在 WSL 下使用 vi 编辑 Windows 文件

在此屏幕截图中，您可以看到从 Windows 文件系统中的文件在 WSL 发行版中的`vi`中进行编辑，之前运行了`vi /mnt/c/wsl-book/wsl.txt`命令。

重要提示

在 Windows 下，文件系统通常是不区分大小写的；也就是说，Windows 将`SomeFile`视为与`somefile`相同。在 Linux 下，文件系统是区分大小写的，因此它们将被视为两个不同的文件。

当从 WSL 挂载访问 Windows 文件系统时，Linux 端对文件进行区分大小写处理，因此尝试从`/mnt/c/wsl-book/EXAMPLE.txt`读取将失败。

尽管 Linux 端将文件系统视为区分大小写，但底层的 Windows 文件系统仍然是不区分大小写的，这一点很重要。例如，虽然 Linux 会将`/mnt/c/wsl-book/wsl.txt`和`/mnt/c/wsl-book/WSL.txt`视为不同的文件，但从 Linux 写入`/mnt/c/wsl-book/WSL.txt`实际上会覆盖先前创建的`wsl.txt`文件的内容，因为 Windows 将名称视为不区分大小写。

正如您在本节中所看到的，自动创建的挂载点（`/mnt/...`）使得通过 WSL 非常容易访问 Windows 文件（如果您想禁用此挂载或更改挂载点的位置，可以使用`wsl.conf`，如*第二章*所示，*安装和配置 Windows 子系统用于 Linux*）。下一节将介绍如何从 Linux 调用 Windows 应用程序。

# 从 Linux 调用 Windows 应用程序

在*第四章*中，我们看到了如何使用`wsl`命令从 Windows 调用 Linux 应用程序。而从 Linux 调用 Windows 应用程序则更加简单！为了看到这一点，启动 WSL 发行版中的终端，并运行`/mnt/c/Windows/System32/calc.exe`来直接从 Linux 启动 Windows 计算器应用程序。如果 Windows 没有安装在`C:\Windows`中，则更新路径以匹配。通过这种方式，您可以从 WSL 发行版的终端启动任何 Windows 应用程序。

在 Windows 计算器（以及许多其他应用程序）的情况下，WSL 实际上使得这更容易。这次，在终端中键入`calc.exe`，Windows 计算器仍然会运行。之所以能够运行，是因为`calc.exe`在 Windows 路径中，并且（默认情况下）WSL 将映射 Windows 路径到 WSL 发行版中的 Linux 路径。为了证明这一点，在终端中运行`echo $PATH`：

```
$ echo $PATH
/home/stuart/.local/bin:/home/stuart/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/mnt/c/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin:/mnt/c/WINDOWS/system32:/mnt/c/WINDOWS:/mnt/c/WINDOWS/System32/Wbem:/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/:/mnt/c/Program Files/dotnet/:/mnt/c/Go/bin:/mnt/c/Program Files (x86)/nodejs/:/mnt/c/WINDOWS/System32/OpenSSH/:/mnt/c/Program Files/Git/cmd:/mnt/c/Program Files (x86)/Microsoft VS Code/bin:/mnt/c/Program Files/Azure Data Studio/bin:/mnt/c/Program Files/Microsoft VS Code Insiders/bin:/mnt/c/Program Files/PowerShell/7/:/mnt/c/Program Files/Docker/Docker/resources/bin:/mnt/c/ProgramData/DockerDesktop/version-bin:/mnt/c/Program Files/Docker/Docker/Resources/bin:… <truncated>
```

从这个例子中可以看出，Linux 中的`PATH`变量不仅包含常见的路径，如`/home/stuart/bin`，还包含已经转换为使用 WSL 挂载的 Windows `PATH`变量的值，例如`/mnt/c/WINDOWS/System32`。由此产生的结果是，您习惯于在 Windows 中无需指定路径即可运行的任何应用程序也可以在 WSL 中无需指定路径运行。一个区别是在 Windows 中，我们不需要指定文件扩展名（例如，我们可以在 PowerShell 中运行`calc`），但在 WSL 中我们需要。

在上一节中，我们在 Windows 中创建了一个文本文件（`c:\wsl-book\wsl.txt`），并使用`vi`在 Linux 中打开了它，但是如果我们想在 Windows 应用程序中打开该文件怎么办？如果您尝试从 Linux 运行`notepad.exe c:\wsl-book\wsl.txt`，记事本将显示找不到该文件的错误。要解决此问题，您可以将路径放在引号中（`notepad.exe "c:\wsl-book\wsl.txt"`）或转义反斜杠（`notepad.exe c:\\wsl-book\\wsl.txt`）。使用这两种修复方法之一，该命令将启动记事本并打开指定的文件。

实际上，当您在 WSL 发行版的终端中工作时，您将花费大量时间在 Linux 文件系统中处理文件，并且您将希望在编辑器中打开*这些*文件。如果您有本书的示例代码（您可以在[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)找到它），请在终端中导航到`chapter-05`文件夹，其中有一个`example.txt`文件（如果您没有示例，请运行`echo "Hello from WSL!" > example.txt`创建一个测试文件）。在终端中，尝试运行`notepad.exe example.txt` - 这将使用 WSL 文件系统加载`example.txt`文件启动记事本。这非常方便，因为它允许您轻松启动 Windows GUI 编辑器来处理 WSL 发行版中的文件。

在本节中，我们已经看到了如何轻松地从 WSL 调用 Windows GUI 应用程序并将路径作为参数传递。在下一节中，我们将看看如何从 WSL 调用 Windows 脚本，以及在需要时如何明确转换路径。

# 从 Linux 调用 Windows 脚本

如果你习惯在 Windows 中运行 PowerShell，那么你也习惯于能够直接调用 PowerShell cmdlet 和脚本。当你在 WSL 中运行 PowerShell 脚本时，有两个选择：在 Linux 上安装 PowerShell 或调用 Windows 上的 PowerShell 运行脚本。如果你对 Linux 上的 PowerShell 感兴趣，安装文档可以在[`docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7`](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7)找到。然而，由于本章重点是从 WSL 调用 Windows，我们将看看后者选项。

PowerShell 是一个 Windows 应用程序，并且在 Windows 路径中，所以我们可以在 Linux 中使用`powershell.exe`来调用它，就像我们在上一节中看到的那样。要使用 PowerShell 运行命令，我们可以使用`-C`开关（缩写为`-Command`）：

```
$ powershell.exe -C "Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System"
Component Information : {0, 0, 0, 0...}
Identifier            : AT/AT COMPATIBLE
Configuration Data    :
SystemBiosVersion     : {OEMC - 300, 3.11.2650,
                        American Megatrends - 50008}
BootArchitecture      : 3
PreferredProfile      : 8
Capabilities          : 2327733
...
```

正如你所看到的，在这里我们使用了`-C`开关来运行 PowerShell 的`Get-ItemProperty` cmdlet 来从 Windows 注册表中检索值。

除了能够调用 PowerShell cmdlet 外，你还可以从 Linux 调用 PowerShell 脚本。本书的附带代码包含一个名为`wsl.ps1`的示例脚本。该脚本向用户打印问候语（使用传入的`Name`参数），打印出当前工作目录，然后输出一些来自 Windows 事件日志的条目。从 Bash 提示符下，将工作文件夹设置为`chapter-05`文件夹，我们可以运行该脚本：

```
$ powershell.exe -C ./wsl.ps1 -Name Stuart
Hello from WSL: Stuart
Current directory: Microsoft.PowerShell.Core\FileSystem
::\\wsl$\Ubuntu-20.04\home\stuart\wsl-book\chapter-05
Index Source      Message
----- ------      -------
14954 edgeupdatem The description for Event ID '0'...
14953 edgeupdate  The description for Event ID '0'...
14952 ESENT       svchost (15664,D,50) DS_Token_DB...
14951 ESENT       svchost (15664,D,0) DS_Token_DB:...
14950 ESENT       svchost (15664,U,98) DS_Token_DB...
14949 ESENT       svchost (15664,R,98) DS_Token_DB...
14948 ESENT       svchost (15664,R,98) DS_Token_DB...
14947 ESENT       svchost (15664,R,98) DS_Token_DB...
14946 ESENT       svchost (15664,R,98) DS_Token_DB...
14945 ESENT       svchost (15664,P,98) DS_Token_DB...
```

前面的输出显示了运行我们刚刚描述的脚本的结果：

+   我们可以看到`Hello from WSL: Stuart`的输出，其中包括`Stuart`（我们作为`Name`参数传递的值）。

+   当前目录的输出为（`Microsoft.PowerShell.Core\FileSystem::\\wsl$\Ubuntu-20.04\home\stuart\wsl-book\chapter-05`）。

+   调用`Get-EventLog` PowerShell cmdlet 时的 Windows 事件日志条目。

这个例子展示了获取 Windows 事件日志条目，但由于它在 Windows 中运行 PowerShell，你可以访问任何 Windows PowerShell cmdlet 来检索 Windows 数据或操作 Windows。

正如你在这里看到的，能够像这里展示的那样调用 PowerShell 命令和脚本提供了一种从 Windows 获取信息的简单方法。这个例子还展示了从 WSL 传递参数（`Name`）到 PowerShell 脚本，接下来，我们将进一步探讨如何结合使用 PowerShell 和 Bash 命令。

## 在 PowerShell 和 Bash 之间传递数据

有时，调用 PowerShell 命令或脚本就足够了，但有时你会希望在 Bash 中处理该命令的输出。在 WSL 中处理 PowerShell 脚本的输出的方式很自然：

```
$ powershell.exe -C "Get-Content ./wsl.ps1" | wc -l
10
```

正如你所看到的，这个命令演示了将执行一些 PowerShell 的输出通过管道传递到`wc -l`中，它计算输入中的行数（在这个例子中为`10`）。

在编写脚本时，你可能还希望将值传递给 PowerShell 脚本。在简单的情况下，我们可以使用 Bash 变量，如下所示：

```
$ MESSAGE="Hello"; powershell.exe -noprofile -C "Write-Host $MESSAGE"
Hello
```

在这里，我们在 Bash 中创建了一个`MESSAGE`变量，然后在传递给 PowerShell 的命令中使用它。这种方法使用了 Bash 中的变量替换-传递给 PowerShell 的实际命令是`Write-Host Hello`。这种技术适用于某些场景，但有时你实际上需要将输入传递给 PowerShell。这种方法不太直观，使用了 PowerShell 中的特殊`$input`变量：

```
$ echo "Stuart" | powershell.exe -noprofile -c 'Write-Host "Hello $input"'
Hello Stuart
```

在这个例子中，你可以看到从`echo "Stuart"`输出的结果被传递到 PowerShell 中，PowerShell 使用`$input`变量来检索输入。这个例子被故意保持简单，以帮助展示传递输入的技巧。更常见的情况是，输入可以是文件的内容或另一个 Bash 命令的输出，而 PowerShell 命令可以是执行更丰富处理的脚本。

在本节中，您已经了解了如何从 WSL 调用 Windows 应用程序，包括如何在 GUI 应用程序中打开 WSL 文件。您还了解了如何调用 PowerShell 脚本，以及如何在 PowerShell 和 Bash 之间传递数据，以创建跨两个环境的脚本，为您提供更多编写脚本的选项。在下一节中，我们将探索一些技巧和诀窍，使集成更加紧密，进一步提高您的生产力。

# 互操作性技巧和诀窍

在本节中，我们将介绍一些技巧，可以在 Windows 和 WSL 之间工作时提高您的生产力。我们将看到如何使用别名来避免在执行 Windows 命令时指定扩展名，使其更加自然。我们还将看到如何将文本从 Linux 复制到 Windows 剪贴板，以及如何使 Windows 文件夹在 WSL 发行版中更加自然。之后，我们将看到如何从 Linux 中的默认 Windows 应用程序打开文件。从那里开始，我们将看到当我们将 WSL 路径作为参数传递给它们时，Windows 应用程序如何能够与 WSL 路径一起工作，以及在默认行为不起作用时如何控制映射路径。最后，我们将看到如何将 Windows 中的 SSH 密钥共享到 WSL 发行版中，以便轻松进行密钥维护。

让我们开始使用别名。

## 创建 Windows 应用程序的别名

正如本章前面提到的，当从 WSL 调用 Windows 应用程序时，我们需要包括文件扩展名。例如，我们需要使用`notepad.exe`来启动记事本，而在 Windows 中，我们只需使用`notepad`。如果您习惯于不包括文件扩展名，那么包括它可能需要一点时间来适应。

作为重新训练自己的替代方法，您可以重新训练 Bash！Bash 中的别名允许您为命令创建别名或替代名称。例如，运行`alias notepad=notepad.exe`将为`notepad.exe`创建一个名为`notepad`的别名。这意味着当您运行`notepad hello.txt`时，Bash 将将其解释为`notepad.exe hello.txt`。

在终端中以交互方式运行`alias`命令只会为当前 shell 实例设置别名。要永久添加别名，请将`alias`命令复制到您的`.bashrc`（或`.bash_aliases`）文件中，以便每次启动 shell 时自动设置它。

接下来，我们将看一下一个方便的 Windows 实用程序，它是一个很好的别名候选者。

## 将输出复制到 Windows 剪贴板

Windows 已经有了`clip.exe`实用程序很长时间了。`clip.exe`的帮助文本指出它*将命令行工具的输出重定向到 Windows 剪贴板*，这是一个很好的描述。正如我们在本章前面看到的，我们可以将 WSL 的输出导入到 Windows 应用程序中，并且我们可以使用`clip.exe`将其放入 Windows 剪贴板中。

例如，运行`echo $PWD > clip.exe`将当前工作目录在终端中（即`$PWD`的值）传输到`clip.exe`。换句话说，您可以将当前工作目录从 WSL 复制到 Windows 剪贴板中。

您还可以将其与别名（`alias clip=clip.exe`）结合使用，简化为`echo $PWD > clip`。

我经常使用`clip.exe` - 例如，将命令的输出复制到我的代码编辑器或电子邮件中 - 这样可以避免在终端中选择和复制文本。

让我们继续使用一些技巧，看看如何使 Windows 路径在 WSL 中更加自然。

## 使用符号链接使 Windows 路径更易访问

正如我们之前看到的，我们可以通过`/mnt/c/…`映射访问 Windows 路径。但是，您可能会发现有一些路径您经常访问，并且希望更方便地访问它们。对我来说，其中一个路径是我的 Windows `Downloads`文件夹 - 每当我发现一个我想要在 WSL 中安装的 Linux 工具并需要下载一个安装包时，我的浏览器默认将其下载到 Windows 的`Downloads`文件夹中。虽然我可以通过`/mnt/c/Users/stuart/Downloads`访问它，但我更喜欢在 WSL 中将其访问为`~/Downloads`。

为了实现这一点，我们可以使用`ln`实用程序创建一个以 Windows `Downloads`文件夹为目标的`~/Downloads`：

```
$ ln -s /mnt/c/Users/stuart/Downloads/ ~/Downloads
$ ls ~/Downloads
browsh_1.6.4_linux_amd64.deb
devcontainer-cli_linux_amd64.tar.gz
powershell_7.0.0-1.ubuntu.18.04_amd64.deb
windirstat1_1_2_setup.exe
wsl_update_x64.msi
```

在此输出中，您可以看到使用`ln -s /mnt/c/Users/stuart/Downloads/ ~/Downloads`命令创建符号链接（您需要更改第一个路径以匹配您的 Windows `Downloads`文件夹）。之后，您可以看到在 WSL 中列出新的符号链接位置的内容输出。

虽然在 WSL 中没有特殊的符号链接功能，但能够创建指向 Windows 文件夹的符号链接使您能够进一步自定义 WSL 环境。当您使用 WSL 时，您可能会发现自己想要创建符号链接的文件夹。

接下来，我们将看一下如何在默认的 Windows 编辑器中打开 WSL 文件。

## 使用 wslview 启动默认的 Windows 应用程序

在本章中，我们已经看到了如何从 WSL 调用特定的 Windows 应用程序。Windows 还具有另一个功能，即能够启动*一个文件*并让 Windows 确定应该启动哪个应用程序来打开它。例如，在 PowerShell 提示符下执行`example.txt`将打开默认的文本编辑器（通常是记事本），而执行`example.jpg`将打开默认的图像查看器。

幸运的是，有帮助可得，`wslutilities`中的`wslview`允许我们从 Linux 中执行相同的操作。在 Microsoft Store 中的最新版本的 Ubuntu 预装了`wslutilities`，但其他发行版的安装说明可以在[`github.com/wslutilities/wslu`](https://github.com/wslutilities/wslu)找到。

安装了`wslutilities`后，您可以在 WSL 终端中运行`wslview`：

```
# Launch the default Windows test editor
$ wslview my-text-file.txt
# Launch the default Windows image viewer
wslview my-image.jpg
# Launch the default browser
wslview https://wsl.tips
```

这些命令展示了使用`wslview`的几个示例。前两个示例展示了根据文件扩展名启动默认的 Windows 应用程序。第一个示例启动默认的 Windows 文本编辑器（通常是记事本），第二个示例启动与 JPEG 文件关联的 Windows 应用程序。在第三个示例中，我们传递了一个 URL，这将在默认的 Windows 浏览器中打开该 URL。

这个实用程序是从 WSL 控制台到 Windows 图形应用程序的一种非常方便的桥梁。

在撰写本文时，`wslview`可以使用的路径存在一些限制；例如，`wslview ~/my-text-file.txt`将失败并显示错误`系统找不到指定的文件`。在下一节中，我们将介绍如何在 Windows 和 Linux 之间转换路径以解决这个问题。

## 在 Windows 和 WSL 之间映射路径

在本章的前面部分，我们在 WSL 中运行了诸如`notepad.exe example.txt`之类的命令，结果记事本打开了我们指定的文本文件。乍一看，似乎 WSL 在我们运行命令时为我们转换了路径，但下面的屏幕截图显示了任务管理器中的记事本（添加了**命令行**列）：

![图 5.3 - 显示任务管理器中运行的 notepad.exe 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_5.3_B16412.jpg)

图 5.3 - 显示任务管理器中运行的 notepad.exe 的屏幕截图

在此屏幕截图中，您可以看到记事本使用了三个不同的参数：

+   `notepad.exe example.txt`

+   `notepad.exe ../chapter-05/example.txt`

+   `notepad.exe /home/stuart/wsl-book/chapter-05/example.txt`

对于列出的每个示例，我确保我在一个目录中，该目录解析为 WSL 中的一个文件，并且每次 Notepad 启动时，示例文件都会被打开，即使参数直接传递给 Notepad 而不进行转换（如*图 5.3*中的截图所示）。

这个工作方式对于我们作为 WSL 用户非常有帮助，但是虽然在这种情况下它可以正常工作，以及大多数其他情况下，了解它为什么可以正常工作对于它无法正常工作的情况也是有用的。这样，您就知道何时可能需要更改行为，例如在从 WSL 调用 Windows 脚本时。那么，如果在调用命令时路径没有被转换，记事本是如何在 WSL 中找到`example.txt`的呢？答案的第一部分是，当 WSL 启动记事本时，它的工作目录被设置为与 WSL 终端的当前工作目录相对应的`\\wsl$\...`路径。我们可以通过运行`powershell.exe ls`来确认这种行为：

```
$ powershell.exe ls
Directory: \\wsl$\Ubuntu-20.04\home\stuart\wsl-book\chapter-05
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        01/07/2020     07:57             16 example.txt
$
```

在这个输出中，您可以看到从 WSL 启动的 PowerShell 列出了其当前工作目录的内容。WSL shell 的工作目录是`/home/stuart/wsl-book/chapter-05`，当启动 PowerShell 时，它会得到 Windows 的等效路径，即`\\wsl$\Ubuntu-20.04\home\stuart\wsl-book\chapter-05`。

现在我们知道记事本的工作目录是基于 WSL 工作目录的，我们可以看到在我们的前两个示例（`notepad.exe example.txt`和`notepad.exe ../chapter-05/example.txt`）中，记事本将路径视为相对路径，并根据其工作目录解析它们以找到文件。

最后一个示例（`notepad.exe /home/stuart/wsl-book/chapter-05/example.txt`）略有不同。在这种情况下，记事本将路径解析为根相对路径。如果记事本的工作目录是`C:\some\folder`，那么它将将路径解析为相对于其工作目录的根目录（`C:\`），并生成路径`C:\home\stuart\wsl-book\chapter-05\example.txt`。然而，由于我们是从 WSL 启动记事本的，它的工作目录是`\\wsl$\Ubuntu-20.04\home\stuart\wsl-book\chapter-05`，这是一个 UNC 路径，因此根被认为是`\\wsl$\Ubuntu-20.04`。这非常好，因为它映射到`Ubuntu-20.04`发行版文件系统的根目录，所以将 Linux 绝对路径添加到它上面生成了预期的路径！

这种映射非常高效，大部分情况下都能正常工作，但在前面的部分中，我们看到`wslview ~/my-text-file.txt`无法正常工作。当我们需要自己控制路径映射时，我们有另一个工具可以使用，接下来我们将看看它。

### 介绍 wslpath

`wslpath`实用程序可用于在 Windows 路径和 Linux 路径之间进行转换。例如，要将 WSL 路径转换为 Windows 路径，我们可以运行以下命令：

```
$ wslpath -w ~/my-text-file.txt
\\wsl$\Ubuntu-20.04\home\stuart\my-text-file.txt
```

这个输出显示`wslpath`返回了我们作为参数传递的 WSL 路径的`\\wsl$\...`路径。

我们还可以使用`wslpath`将路径转换为相反的方向：

```
$ wslpath -u '\\wsl$\Ubuntu-20.04\home\stuart\my-text-file.txt'
/home/stuart/my-text-file.txt
```

在这里，我们可以看到`\\wsl$\...`路径已经被转换回 WSL 路径。

重要提示

在 Bash 中指定 Windows 路径时，您必须对它们进行转义或用单引号括起来，以避免需要转义。对于`\\wsl$\...`路径中的美元符号也是如此。

在前面的示例中，我们使用的是 WSL 文件系统中的文件路径，但`wslpath`同样适用于 Windows 文件系统中的路径：

```
$ wslpath -u 'C:\Windows'
/mnt/c/Windows
$ wslpath -w /mnt/c/Windows
C:\Windows
```

在这个输出中，您可以看到`wslpath`将 Windows 文件系统中的路径转换为`/mnt/...`路径，然后再转换回来。

现在我们已经看到了`wslpath`的工作原理，让我们来看几个使用它的示例。

### wslpath 的使用

在本章的早些时候，我们看到了方便的`wslview`实用程序，但观察到它只处理相对的 WSL 路径，因此我们不能使用`wslview /home/stuart/my-text-file.txt`。但是`wslview`可以使用 Windows 路径，并且我们可以利用`wslpath`来实现这一点。例如，`wslview $(wslpath -w /home/stuart/my-text-file.txt)`将使用`wslpath`将路径转换为相应的 Windows 路径，然后使用该值调用`wslview`。我们可以将所有这些封装到一个函数中以便使用：

```
# Create a 'wslvieww' function
wslvieww() { wslview $(wslpath -w "$1"); };
# Use the function 
wslvieww /home/stuart/my-text-file.txt
```

在此示例中，使用 Bash 创建了一个名为`wslvieww`的函数（额外的`w`是为了 Windows），但如果您愿意，可以选择其他名称。然后，以与`wslview`相同的方式调用新函数，但这次执行路径映射，Windows 能够解析映射的路径并在文本编辑器中加载它。

我们之前看到的另一个可以使用`wslpath`的示例是在 Linux 的`home`文件夹中创建指向 Windows 的`Downloads`文件夹的符号链接。本章前面给出的命令要求您编辑命令以将适当的路径放入 Windows 用户配置文件中。以下一组命令将在不修改的情况下执行此操作：

```
WIN_PROFILE=$(cmd.exe /C echo %USERPROFILE% 2>/dev/null)
WIN_PROFILE_MNT=$(wslpath -u ${WIN_PROFILE/[$'\r\n']})
ln -s $WIN_PROFILE_MNT/Downloads ~/Downloads
```

这些命令显示了调用 Windows 以获取`USERPROFILE`环境变量，然后使用`wslpath`将其转换为`/mnt/…`路径。最后，将其与`Downloads`文件夹组合，并传递给`ln`以创建符号链接。

这些只是`wslpath`用于在 Windows 和 WSL 文件系统之间转换路径时的一些示例。大多数情况下，这是不需要的，但了解它的存在（以及如何使用它）可以帮助您在 WSL 中高效地处理文件。

我们将看一下如何在 Windows 和 WSL 发行版之间共享 SSH 密钥的最后一个提示。

## SSH 代理转发

在使用 SSH 连接远程机器时，通常会使用 SSH 身份验证密钥。SSH 密钥也可以用于身份验证其他服务，例如通过`git`将源代码更改推送到 GitHub。

本节将指导您配置用于 WSL 发行版的 OpenSSH 身份验证代理。假设您已经拥有 SSH 密钥和一台要连接的机器。

提示

如果您没有 SSH 密钥，可以参考 OpenSSH 文档中的创建方法：[`docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement`](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)。

如果您没有要连接的机器，Azure 文档将帮助您创建具有 SSH 访问权限的虚拟机（您可以使用免费试用版进行操作）：[`docs.microsoft.com/en-us/azure/virtual-machines/linux/ssh-from-windows#provide-an-ssh-public-key-when-deploying-a-vm`](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/ssh-from-windows#provide-an-ssh-public-key-when-deploying-a-vm)。

如果您在 Windows 和一个或多个 WSL 发行版中使用 SSH 密钥，您可以每次复制 SSH 密钥。另一种选择是在 Windows 中设置**OpenSSH 身份验证代理**，然后配置 WSL 发行版以使用该代理获取密钥。这意味着您只需要管理一个地方的 SSH 密钥，并且只需要在一个地方输入 SSH 密钥的密码（假设您正在使用密码）。

让我们开始使用 Windows 的 OpenSSH 身份验证代理。

### 确保 Windows 的 OpenSSH 身份验证代理正在运行

设置的第一步是确保 Windows 的 OpenSSH 身份验证代理正在运行。为此，请在 Windows 中打开**服务**应用程序，并向下滚动到**OpenSSH 身份验证代理**。如果它显示为**正在运行**，则右键单击并选择**属性**。在打开的对话框中，确保具有以下设置：

+   **启动类型**为**自动**。

+   **服务状态**为**正在运行**（如果没有，请点击**启动**按钮）。

现在，您可以使用`ssh-add`将您的密钥添加到代理中 - 例如，`ssh-add ~/.ssh/id_rsa`。如果您的 SSH 密钥有密码短语，您将被提示输入密码。如果出现找不到`ssh-add`的错误，则使用以下说明安装 OpenSSH 客户端：[`docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse`](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)。

要检查密钥是否已正确添加，请尝试从 Windows 运行`ssh`以连接到远程机器：

```
C:\ > ssh stuart@sshtest.wsl.tips
key_load_public: invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-1028-azure x86_64)                                                                           
Last login: Tue Jul  7 21:24:59 2020 from 143.159.224.70
stuart@slsshtest:~$ 
```

在此输出中，您可以看到`ssh`正在运行并成功连接到远程机器。

提示

如果您已经配置了 SSH 密钥用于与 GitHub 进行身份验证，您可以使用`ssh -T git@github.com`来测试您的连接。有关在 GitHub 上使用 SSH 密钥的完整详细信息，请访问[`docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh`](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh)。

告诉 Git 使用`GIT_SSH`环境变量为`C:\Windows\System32\OpenSSH\ssh.exe`（或者如果您的 Windows 文件夹不同，则为安装路径）。

到目前为止，我们已经在 Windows 中配置了 OpenSSH 身份验证代理，并使用了我们的 SSH 密钥。如果我们的密钥有密码短语，这将避免我们每次使用它们时都被提示输入密码。接下来，我们将设置从 WSL 访问这些密钥。

### 从 WSL 配置访问 Windows SSH 密钥

现在我们已经在 Windows 中使密钥工作，我们希望在 WSL 中设置我们的 Linux 发行版以连接到 Windows 的 OpenSSH 身份验证代理。Linux `ssh`客户端具有`SSH_AUTH_SOCK`环境变量，允许您在检索 SSH 密钥时提供一个套接字供`ssh`连接。挑战在于 OpenSSH 身份验证代理允许通过 Windows 命名管道进行连接，而不是套接字（更不用说是一个单独的机器了）。

为了将 Linux 套接字连接到 Windows 命名管道，我们将使用两个实用程序：`socat`和`npiperelay`。`socat`实用程序是一个强大的 Linux 工具，可以在不同位置之间中继流。我们将使用它来监听`SSH_AUTH_SOCK`套接字并转发到一个它执行的命令。该命令将是`npiperelay`实用程序（由 Windows 团队的开发人员 John Starks 编写，他在 Linux 和容器方面做了很酷的工作），它将将其输入转发到一个命名管道。

要安装`npiperelay`，请从 GitHub 获取最新版本（[`github.com/jstarks/npiperelay/releases/latest`](https://github.com/jstarks/npiperelay/releases/latest)）并将`npiperelay.exe`提取到您的路径中的位置。要安装`socat`，请运行`sudo apt install socat`。

要开始转发 SSH 密钥请求，请在 WSL 中运行以下命令：

```
export SSH_AUTH_SOCK=$HOME/.ssh/agent.sock
socat UNIX-LISTEN:$SSH_AUTH_SOCK,fork EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent",nofork &
```

第一行设置了`SSH_AUTH_SOCK`环境变量。第二行运行`socat`并告诉它监听`SSH_AUTH_SOCK`套接字并将其中继到`npiperelay`。`npiperelay`命令行告诉它监听并将其输入转发到`//./pipe/openssh-ssh-agent`命名管道。

有了这个设置，您现在可以在 WSL 发行版中运行`ssh`：

```
$ ssh stuart@sshtest.wsl.tips
agent key RSA SHA256:WEsyjMl1hZY/xahE3XSBTzURnj5443sg5wfuFQ+bGLY returned incorrect signature type
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-1028-azure x86_64)
Last login: Wed Jul  8 05:45:15 2020 from 143.159.224.70
stuart@slsshtest:~$
```

此输出显示在 WSL 发行版中成功运行`ssh`。我们可以通过使用`-v`（详细）开关运行`ssh`来验证密钥是否已从 Windows 加载：

```
$ ssh -v stuart@sshtest.wsl.tips
...
debug1: Offering public key: C:\\Users\\stuart\\.ssh\\id_rsa RSA SHA256:WEsyjMl1hZY/xahE3XSBTzURnj5443sg5wfuFQ+bGLY agent
debug1: Server accepts key: C:\\Users\\stuart\\.ssh\\id_rsa RSA SHA256:WEsyjMl1hZY/xahE3XSBTzURnj5443sg5wfuFQ+bGLY agent
...
```

完整的详细输出非常长，但在其中的这个片段中，我们可以看到`ssh`用于建立连接的密钥。请注意，路径是 Windows 路径，显示密钥是通过 Windows OpenSSH 代理加载的。

我们之前运行的命令启动了`socat`，使我们能够测试这种情况，但您可能希望自动转发 SSH 密钥请求，而不需要在每个新的终端会话中运行这些命令。为了实现这一点，请将以下行添加到您的`.bash_profile`文件中：

```
export SSH_AUTH_SOCK=$HOME/.ssh/agent.sock
ALREADY_RUNNING=$(ps -auxww | grep -q "[n]piperelay.exe -ei -s //./pipe/openssh-ssh-agent"; echo $?)
if [[ $ALREADY_RUNNING != "0" ]]; then
    if [[ -S $SSH_AUTH_SOCK ]]; then
 (http://www.tldp.org/LDP/abs/html/fto.html)
        echo "removing previous socket..."
        rm $SSH_AUTH_SOCK
    fi
    echo "Starting SSH-Agent relay..."
    (setsid socat UNIX-LISTEN:$SSH_AUTH_SOCK,fork EXEC:"npiperelay.exe -ei -s //./pipe/openssh-ssh-agent",nofork &) /dev/null 2>&1
fi
```

这些命令的本质与原始的`socat`命令相同，但增加了错误检查，在启动之前测试`socat`命令是否已经运行，并允许它在终端会话之间持久存在。

有了这个设置，您可以有一个地方来管理您的 SSH 密钥和密码短语（Windows 的 OpenSSH 身份验证代理），并无缝共享您的 SSH 密钥与您的 WSL 发行版。

此外，将 Linux 套接字转发到 Windows 命名管道的技术可以在其他情况下使用。请查看`npiperelay`文档以获取更多示例，包括从 Linux 连接到 Windows 中的 MySQL 服务：[`github.com/jstarks/npiperelay`](https://github.com/jstarks/npiperelay)。

在这个技巧和窍门的部分，您已经看到了一系列示例，说明了在 WSL 和 Windows 之间桥接的技术，从创建命令别名到共享 SSH 密钥。虽然这些示例的目的是直接使用，但它们背后的技术是可推广的。例如，SSH 密钥共享示例展示了如何使用一些工具来实现 Linux 套接字和 Windows 命名管道之间的桥接，并可以在其他场景中使用。

# 总结

在本章中，您已经学会了如何从 WSL 发行版访问 Windows 文件系统中的文件，以及如何从 Linux 启动 Windows 应用程序，包括使用`wlsview`实用程序轻松启动文件的默认 Windows 应用程序。您已经学会了如何在 Windows 和 Linux 脚本之间传递输入，包括在需要时如何使用`wslpath`映射两个文件系统方案之间的路径。

在本章的结尾，您了解了如何将 Linux 套接字映射到 Windows 命名管道，并使用此技术使您的 Windows SSH 密钥在 WSL 中可用。这使您可以避免将 SSH 密钥复制到每个 WSL 发行版中，而是在一个共享的地方管理您的 SSH 密钥和密码短语，从而更容易控制和备份您的 SSH 密钥。

所有这些都有助于通过 WSL 将 Windows 和 Linux 更紧密地联系在一起，并在您的日常工作流程中提高生产力。

在本章中，我们在终端上花了相当多的时间。在下一章中，我们将重新访问 Windows 终端，并探索一些更高级的方法来自定义它以满足您的需求。


# 第六章：从 Windows 终端获取更多信息

新的 Windows 终端在*第三章*，*开始使用 Windows 终端*中介绍过，您已经了解了如何安装它以及如何自定义配置文件的顺序和它们在该章节中使用的颜色方案。在本章中，我们将进一步探索 Windows 终端，并介绍一些在 Windows 终端中运行多个不同 shell 的方法。之后，我们将介绍如何添加自定义配置文件，以简化常见任务的流程。

在本章中，我们将涵盖以下主要内容：

+   自定义选项卡标题

+   使用多个窗格

+   添加自定义配置文件

我们将从查看如何使用选项卡标题来帮助您管理多个选项卡开始本章。

# 自定义选项卡标题

**选项卡式用户界面**很棒；浏览器有它们，编辑器有它们，Windows 终端也有它们。对于某些人，包括我自己在内，选项卡式用户界面也带来了一些挑战 - 我打开了很多选项卡：

![图 6.1 - Windows 终端的屏幕截图，打开了许多选项卡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.1_B16412.jpg)

图 6.1 - Windows 终端的屏幕截图，打开了许多选项卡

正如前面的屏幕截图所示，打开多个选项卡时，很难确定每个选项卡正在运行的内容以及您使用它的目的。当我编码时，我经常打开一个选项卡用于执行 Git 操作，另一个用于构建和运行代码，另一个用于在代码运行时与代码进行交互。除此之外，还有一个额外的选项卡用于一些常规系统交互，以及一个或两个选项卡用于查看其他项目中的问题。这样，选项卡的数量很快就增加了。

前面的屏幕截图显示，根据选项卡中运行的 shell，您可能会获得一些路径信息，但是如果在相同路径下有多个选项卡，即使这样也没有太大帮助，因为它们都显示相同的值。幸运的是，使用 Windows 终端，您可以设置选项卡标题以帮助您跟踪。我们将介绍几种不同的方法，以便您可以选择最适合您的方法。

## 从上下文菜单设置选项卡标题

设置标题的简单方法是右键单击选项卡标题，弹出上下文菜单，然后选择**重命名选项卡**：

![图 6.2 - 显示重命名选项卡的选项卡上下文菜单的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.2_B16412.jpg)

图 6.2 - 显示重命名选项卡的选项卡上下文菜单的屏幕截图

正如前面的屏幕截图所示，右键单击选项卡会弹出上下文菜单，允许您重命名选项卡或设置选项卡颜色以帮助组织您的选项卡：

![图 6.3 - Windows 终端的屏幕截图，显示已重命名和带颜色的选项卡](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.3_B16412.jpg)

图 6.3 - Windows 终端的屏幕截图，显示已重命名和带颜色的选项卡

此屏幕截图显示了按照选项卡标题中的颜色进行分组的选项卡标题集合。每个选项卡还有一个描述性标题，例如**git**，表示该选项卡的用途。当然，您可以选择适合您工作流程的标题。

当您在终端中工作时，您可能更喜欢使用键盘来设置标题，因此我们将在下一节中介绍这一点。

## 使用函数从 shell 设置选项卡标题

如果您喜欢保持双手在键盘上，可以从选项卡中运行的 shell 中设置选项卡标题。这取决于您使用的 shell 的方法，因此我们将在这里介绍一些不同的 shell。让我们从**Bash**开始。

为了方便设置提示符，我们可以创建以下函数：

```
function set-prompt() { echo -ne '\033]0;' $@ '\a'; }
```

从此代码片段中可以看出，这创建了一个名为`set-prompt`的函数。该函数使用控制终端标题的转义序列，允许我们运行诸如`set-prompt "A new title"`的命令来更改选项卡标题，在此示例中将其更改为`A new title`。

对于 PowerShell，我们可以创建一个类似的函数：

```
function Set-Prompt {
    param (
        # Specifies a path to one or more locations.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        $PromptText
    )
    $Host.UI.RawUI.WindowTitle = $PromptText
}
```

这段代码显示了一个`Set-Prompt`函数，它访问 PowerShell 的`$Host`对象来控制标题，允许我们运行诸如`Set-Prompt "A new title"`之类的命令以类似于 Bash 的方式更改选项卡标题。

对于 Windows 命令提示符（`cmd.exe`），我们可以运行`TITLE A new title`来控制选项卡标题。

提示

一些实用程序和 shell 配置会覆盖默认的提示设置，以控制 shell 标题以及提示。在这些情况下，本节中的函数将不会有任何明显的效果，因为提示将立即覆盖指定的标题。如果您在使用这些函数时遇到问题，请检查您的提示配置。

对于 Bash，运行 echo `$PROMPT_COMMAND`来检查您的提示配置。对于 PowerShell，运行`Get-Content function:prompt`。

这里显示了使用刚才看到的函数的示例：

![图 6.4 - 显示使用 set-prompt 函数的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.4_B16412.jpg)

图 6.4 - 显示使用 set-prompt 函数的屏幕截图

在此屏幕截图中，您可以看到在 Bash 中使用`set-prompt`函数来控制选项卡标题。其他选项卡（PowerShell 和命令提示符）的标题也是使用本节中显示的函数设置的。

在终端中工作时，使用这些函数可以方便地更新选项卡标题，而无需中断您的工作流程以使用鼠标。您还可以使用这些函数作为脚本的一部分来更新标题，例如，通过选项卡标题以一目了然的方式查看长时间运行脚本的状态，即使不同的选项卡具有焦点。

我们将要看的最后一种更新选项卡标题的方法是在启动 Windows 终端时通过命令行进行。

## 从命令行设置选项卡标题

前一节介绍了如何从运行的 shell 中设置选项卡标题；在本节中，我们将启动 Windows 终端并传递命令行参数来指定要加载的配置文件和设置选项卡标题。

可以使用`wt.exe`命令从命令行或运行对话框（*Windows* + *R*）启动 Windows 终端。仅运行`wt.exe`将使用默认配置文件启动 Windows 终端。可以使用`--title`开关来控制选项卡标题，例如，`wt.exe --title "Put a title here"`。此外，`--profile`（或`-p`）开关允许我们指定要加载的配置文件，因此`wt.exe -p Ubuntu-20.04 --title "This is Ubuntu"`将加载`Ubuntu-20.04`配置文件并设置选项卡标题。

控制选项卡标题的一个动机是在使用多个选项卡时进行跟踪。Windows 终端具有一组强大的命令行参数（我们将在下一节中看到更多），允许我们使用一个或多个特定的选项卡/配置文件启动终端。我们可以在前面的命令后面添加`；new-tab`（注意分号），以指定要加载的新选项卡，包括任何其他参数，如`title`和`profile`：

```
wt.exe -p "PowerShell" --title "This one is PowerShell"; new-tab -p "Ubuntu-20.04" --title "WSL here!"
```

在此示例中，我们将第一个选项卡指定为`PowerShell`配置文件，并将其标题设置为`This one is PowerShell`，第二个选项卡指定为`Ubuntu-20.04`配置文件，并将其标题设置为`WSL here!`。

注意

`new-tab`参数需要一个分号在其前面，但许多 shell（包括 Bash 和 PowerShell）将分号视为命令分隔符。为了成功使用前面的命令，任何分号都需要在 PowerShell 中使用反引号进行转义（``;`）。

正如在*第五章*中所见，*Linux 与 Windows 的互操作性*，在*从 Linux 调用 Windows 应用程序*部分，我们可以从 WSL 启动 Windows 应用程序。通常情况下，我们可以直接执行 Windows 应用程序，但由于 Windows 终端使用了一个称为执行别名的功能，我们需要通过`cmd.exe`来启动它。

此外，由于`wt.exe`的工作方式，当从 Bash 启动时，需要使用`cmd.exe`运行：

`cmd.exe /C wt.exe -p "PowerShell" --title "这是 PowerShell"\; new-tab -p "Ubuntu-20.04" --title "在这里运行 WSL！"`

这个示例展示了如何使用`cmd.exe`启动 Windows 终端并打开多个选项卡（注意反斜杠用于转义分号），设置配置文件和标题。

使用 Windows 终端的`new-tab`命令可以重复多次，通过这种方式，你可以创建命令或脚本来以可重复的方式设置复杂的 Windows 终端选项卡布局。

本节介绍的技巧提供了多种方法来设置 Windows 终端会话中选项卡的标题，帮助你在不同选项卡中打开多个 Shell 时保持组织。在下一节中，我们将介绍 Windows 终端的另一个用于处理多个 Shell 的功能。

# 使用多个窗格

在前一节中，我们看到了在同时打开多个 Shell 时使用选项卡的情况，但有时候希望能够同时看到多个 Shell。在本节中，我们将介绍如何在 Windows 终端中使用多个窗格来实现这样的效果：

![图 6.5 - 展示 Windows 终端中多个窗格的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.5_B16412.jpg)

图 6.5 - 展示 Windows 终端中多个窗格的屏幕截图

上面的屏幕截图显示了在同一个选项卡中运行多个配置文件的窗格：左侧是一个已经发出了网络请求的 PowerShell 窗口，右上角的窗格正在运行一个 Web 服务器，右下角的窗格正在运行`htop`以跟踪 WSL 中正在运行的 Linux 进程。

提示

如果你熟悉`tmux`实用程序（[`github.com/tmux/tmux/wiki`](https://github.com/tmux/tmux/wiki)），那么这可能看起来很熟悉，因为`tmux`也允许将窗口分割成多个面板。但是有一些区别。`tmux`的一个特性是允许你断开和重新连接终端会话，这在使用`ssh`时非常方便，因为它可以保留你的会话，而`tmux`则不会。

在上面的屏幕截图中，你可以看到 PowerShell 和 Bash（在 WSL 中）在同一个选项卡的不同窗格中运行。了解`tmux`和 Windows 终端的功能，并选择适合工作的正确工具是很重要的 - 你始终可以在 Windows 终端的 Bash shell 中运行 tmux，以获得最佳的体验！

现在你对窗格有了一定的了解，让我们看看如何设置它们。

## 交互式创建窗格

创建窗格的最简单方法是按需交互式创建。有一些默认的快捷键可以帮助你入门，但如果你有特定的需求，你可以根据这里的描述配置自己的按键绑定：[`docs.microsoft.com/en-us/windows/terminal/customize-settings/key-bindings#pane-management-commands`](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/key-bindings#pane-management-commands)。

首先是*Alt* + *Shift* + *-*, 这将把当前窗格水平分割成两半，然后是*Alt* + *Shift* + *+*, 这将把窗格垂直分割。这两个命令都会在新创建的窗格中启动默认配置文件的新实例。

默认配置文件可能不是你想要运行的配置文件，但通常情况下，你可能希望在同一个配置文件中运行另一个终端。按下*Alt* + *Shift* + *D*将在当前窗格中创建一个新的配置文件实例的窗格。该命令会根据可用空间自动确定是水平分割还是垂直分割。

如果你想选择在新窗格中打开哪个配置文件，你可以打开启动配置文件下拉菜单：

![图 6.6 - 展示启动配置文件下拉菜单的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.6_B16412.jpg)

图 6.6 - 展示启动配置文件下拉菜单的屏幕截图

此屏幕截图显示了用于选择要运行的配置文件的标准下拉菜单。与正常点击不同，按住*Alt*键并单击将在新窗格中启动所选配置文件。与*Alt* + *Shift* + *D*一样，Windows 终端将确定是水平拆分还是垂直拆分当前窗格。

另一个选项是使用 Windows 终端命令面板，使用*Ctrl* + *Shift* + *P*：

![图 6.7-屏幕截图显示命令面板中的拆分选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.7_B16412.jpg)

图 6.7-屏幕截图显示命令面板中的拆分选项

命令面板允许您输入以过滤命令列表，并且此屏幕截图显示与`split`匹配的命令。底部的两个命令与我们已经看到的两个命令以及它们对应的快捷键匹配。顶部的命令在命令面板中提供了一个菜单系统，允许您选择要用于新窗格的配置文件，然后选择如何拆分现有窗格。

现在我们已经看过如何创建窗格，让我们看一下如何使用它们。

## 管理窗格

在窗格之间切换焦点最明显的方法是使用鼠标在窗格中单击-这样做会更改焦点所在的窗格（窗格边框上会显示突出显示的颜色）。要使用键盘更改窗格，可以使用*Alt* + 光标键，即*Alt* + *光标向上*将焦点移动到当前窗格上方的窗格。

要更改窗格的大小，我们使用类似的键组合，即*Alt* + *Shift* + 光标键。*Alt* + *Shift* + *光标向上*和*Alt* + *Shift* + *光标向下*组合调整当前窗格的高度，*Alt* + *Shift* + *光标向左*和*Alt* + *Shift* + *光标向右*组合调整当前窗格的宽度。

如果任何在窗格中运行的 shell 退出，则该窗格将关闭，并且其他窗格将调整大小以填充其空间。您还可以通过按下*Ctrl* + *Shift* + *W*关闭当前窗格（此快捷键在*第三章*中引入，*使用 Windows 终端*部分，作为关闭选项卡的快捷键，但在那时，选项卡中只有一个窗格！）。

最后，让我们看一下如何在从命令行启动 Windows 终端时配置窗格。

## 从命令行创建窗格

在本章的前面部分，我们看到了如何使用 Windows 终端命令行（`wt.exe`）加载多个选项卡启动 Windows 终端。在本节中，我们将看到如何使用窗格执行相同操作。当您在项目上工作并且有一组常用的窗格设置时，这非常有用，因为您可以对其进行脚本处理，并且可以轻松启动一致的布局。

在使用多个选项卡启动时，我们使用`wt.exe`的`new-tab`命令。启动多个窗格的方法类似，但使用`split-pane`命令（请注意，分号的转义规则仍适用于“从命令行设置选项卡标题”部分）。

以下是使用`split-pane`的示例：

```
wt.exe -p PowerShell; split-pane -p Ubuntu-20.04 -V --title "web server"; split-pane -H -p Ubuntu-20.04 --title htop bash -c htop
```

如您所见，在此示例中，`split-pane`用于指定新窗格，我们可以使用`-p`开关指定该窗格应使用的配置文件。我们可以让 Windows 终端自动选择如何拆分，或者我们可以使用`-H`进行水平拆分，或者使用`-V`进行垂直拆分。您可能还注意到已指定了`--title`。Windows 终端允许每个窗格都有一个标题，并将当前焦点窗格的标题显示为选项卡标题。最后，您可能会注意到最后一个窗格具有附加参数`bash -c htop`。这些参数被视为在启动的配置文件中执行的命令。此命令的最终结果与*图 6.5*中显示的屏幕截图非常相似。

作为一个额外的功能，Windows Terminal 中的命令面板还允许我们使用命令行选项。按下*Ctrl* + *Shift* + *P*来打开命令面板，然后输入`>`（右尖括号）：

![图 6.8 - 屏幕截图显示带有命令行选项的命令面板](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.8_B16412.jpg)

图 6.8 - 屏幕截图显示带有命令行选项的命令面板

正如您在这个屏幕截图中所看到的，我们可以使用`split-pane`命令使用命令行选项来拆分现有的窗格。

到目前为止，在本章中，我们已经介绍了一些使用选项卡和窗格来帮助管理多个配置文件的方法。在本章的最后一节中，我们将看一些其他的配置文件创意想法。

# 添加自定义配置文件

Windows Terminal 非常好地自动发现 PowerShell 安装和 WSL 分发，以填充您的配置文件列表（并在安装新分发时更新）。这是一个很好的开始，但除了启动交互式 shell 之外，配置文件还可以在配置文件中启动特定的应用程序（就像上一节中显示的`htop`）。在本节中，我们将看一些示例，但它们的主要目的是展示除了仅仅启动 shell 之外的想法，以激发您如何自定义 Windows Terminal 配置的灵感。

如果您经常通过 SSH 连接到一台机器，那么您可以通过创建一个直接启动 SSH 的 Windows Terminal 配置文件来简化工作流程。从配置文件下拉菜单中打开您的设置（或按*Ctrl* + *,*），并在`profiles`下的`list`部分中添加一个配置文件：

```
{
    "guid": "{9b0583cb-f2ef-4c16-bcb5-9111cdd626f3}",
    "hidden": false,
    "name": "slsshtest",
    "commandline": "wsl bash -c \"ssh stuart@slsshtest.uksouth.cloudapp.azure.com\"",
    "colorScheme": "Ubuntu-sl",
    "background": "#801720",
    "fontFace": "Cascadia Mono PL"
},
```

Windows Terminal 设置文件在*第三章*中介绍过，*开始使用 Windows Terminal*，在这个示例配置文件中，您可以看到来自该章节的熟悉属性，如`name`和`colorScheme`。`commandline`属性是我们配置要运行的内容的地方，我们使用它来启动`wsl`命令以运行带有运行`ssh`命令行的`bash`。您应该确保`guid`值与设置中的其他配置文件不同。这个示例展示了如何创建一个在 WSL 中执行命令的配置文件 - 对于 SSH，您还可以选择在`commandline`属性中直接使用`ssh`，因为 Windows 现在包含了一个 SSH 客户端。

启动这个新配置文件会自动启动`ssh`并连接到指定的远程机器。作为一个额外的功能，`background`属性可以用来设置背景颜色，以指示您所连接的环境，例如，方便地区分开发和测试环境。

如果您有多台通过 SSH 连接的机器，那么您可以启动一个脚本来允许您选择要连接的机器：

```
#!/bin/bash
# This is an example script showing how to set up a prompt for connecting to a remote machine over SSH
PS3="Select the SSH remote to connect to: "
# TODO Put your SSH remotes here (with username if required)
vals=(
    stuart@sshtest.wsl.tips
    stuart@slsshtest.uksouth.cloudapp.azure.com
)
IFS="\n"
select option in "${vals[@]}"
do
if [[ $option == "" ]]; then
    echo "unrecognised option"
    exit 1
fi
echo "Connecting to $option..."
ssh $option
break
done
```

该脚本包含一个选项列表（`vals`），当执行脚本时，这些选项将呈现给用户。当用户选择一个选项时，脚本会运行`ssh`来连接到该机器。

如果您将此脚本保存为`ssh-launcher.sh`并放在您的主文件夹中，您可以在 Windows Terminal 设置中添加一个配置文件来执行它：

```
{
    "guid": "{0b669d9f-7001-4387-9a91-b8b3abb4s7de8}",
    "hidden": false,
    "name": "ssh picker",
    "commandline": "wsl bash $HOME/ssh-launcher.sh,
    "colorScheme": "Ubuntu-sl",
    "fontFace": "Cascadia Mono PL"
},
```

在上述配置文件中，您可以看到`commandline`已被替换为运行先前的`ssh-launcher.sh`脚本的命令。当启动此配置文件时，它使用`wsl`通过`bash`来启动脚本：

![图 6.9 - 屏幕截图显示 ssh 启动脚本运行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_6.9_B16412.jpg)

图 6.9 - 屏幕截图显示 ssh 启动脚本运行

您可以在上述屏幕截图中看到此脚本的运行情况。该脚本提示用户从机器列表中选择，并运行`ssh`以连接到所选的机器。这为设置到经常使用的机器的连接提供了一种方便的方式。

当您使用 WSL 时，您可能会发现一组您经常运行的应用程序或者您经常执行的步骤，这些都是添加到 Windows 终端配置文件的好选择！

注意

这里还有其他一些选项，我们没有机会在这里看到，例如为配置文件设置背景图像，您可以在 Windows 终端文档中找到这些选项的详细信息，网址为[`docs.microsoft.com/en-us/windows/terminal/`](https://docs.microsoft.com/en-us/windows/terminal/)。Windows 终端还在快速添加新功能-要了解即将推出的功能，请查看 GitHub 上的路线图文档，网址为[`github.com/microsoft/terminal/blob/master/doc/terminal-v2-roadmap.md`](https://github.com/microsoft/terminal/blob/master/doc/terminal-v2-roadmap.md)。

# 总结

在本章中，您已经了解了如何使用多个 Windows 终端配置文件的方法。首先，您了解了如何通过控制选项卡标题（和颜色）来处理多个选项卡，以帮助跟踪每个选项卡的上下文。然后，您了解了如何使用窗格来允许在同一个选项卡中运行多个（可能不同的）配置文件。您可能会发现您更喜欢一种工作方式，或者将选项卡和配置文件结合起来。无论哪种方式，您还学会了如何使用 Windows 终端命令行来脚本化选项卡和窗格的创建，以便为您的项目轻松快速地创建一致且高效的工作环境。

本章最后介绍了如何使用 Windows 终端配置文件来运行不仅仅是 shell 的功能，通过设置一个启动 SSH 连接到远程机器的配置文件。然后，您了解了如何进一步选择要连接的机器列表，并使用*Bash*脚本提示您选择。如果您经常通过 SSH 连接到机器，那么这些示例将希望对您有用，但目标是展示如何进一步利用 Windows 终端中的配置文件。当您在工作流程中找到常见任务和应用程序时，请考虑是否值得花费几分钟创建一个 Windows 终端配置文件，以使这些重复的任务更快、更容易完成。所有这些技术都可以让您优化 Windows 终端的工作流程，提高您的日常工作效率。

在下一章中，我们将介绍一个新的主题：如何在 WSL 中使用容器。


# 第七章：在 WSL 中使用容器

容器作为一种打包和管理应用程序的方式是一个热门话题。虽然有 Windows 和 Linux 版本的容器，但由于本书是关于 WSL 的，我们将重点介绍 Linux 容器和 Docker 容器。如果您想了解 Windows 容器，可以从这个链接开始：[`docs.microsoft.com/virtualization/windowscontainers/`](https://docs.microsoft.com/virtualization/windowscontainers/)

在介绍了容器的概念并安装了 Docker 之后，本章将指导您运行一个预构建的 Docker 容器，然后通过使用 Python Web 应用程序作为示例，教您如何构建自己应用程序的容器镜像。创建容器镜像后，您将快速了解 Kubernetes 的一些关键组件，然后看看如何使用这些组件在 WSL 中托管容器化应用程序。

在本章中，我们将涵盖以下主要内容：

+   容器概述

+   在 WSL 中安装和使用 Docker

+   使用 Docker 运行容器

+   构建和运行 Docker 中的 Web 应用程序

+   介绍编排器

+   在 WSL 中设置 Kubernetes

+   在 Kubernetes 中运行 Web 应用程序

我们将从探索容器的概念开始本章。

# 容器概述

容器提供了一种打包应用程序及其依赖项的方式。这个描述可能有点像一个虚拟机（VM），在虚拟机中，你可以在文件系统中安装应用程序二进制文件，然后稍后运行。然而，当你运行一个容器时，它更像一个进程，无论是启动速度还是内存消耗量。在底层，容器是一组通过使用诸如 Linux 命名空间和控制组（cgroups）等特性进行隔离的进程，使得这些进程看起来像在它们自己的环境中运行（包括有自己的文件系统）。容器与主机操作系统共享内核，因此与虚拟机相比，它们的隔离性较低，但对于许多目的来说，这种隔离已经足够了，而且主机资源的共享使得容器可以实现低内存消耗和快速启动时间。

除了容器执行外，Docker 还可以轻松定义容器的组成部分（称为容器镜像）并在注册表中发布容器镜像，供其他用户使用。

我们将在本章稍后的部分中看到这一点，但首先让我们安装 Docker。

# 在 WSL 中安装和使用 Docker

在 Windows 机器上运行 Docker 的传统方法是使用 Docker Desktop（https://www.docker.com/products/docker-desktop），它将为您创建和管理一个 Linux 虚拟机，并在该虚拟机中作为守护程序运行 Docker 服务。这样做的缺点是虚拟机需要时间启动，并且必须预先分配足够的内存来容纳运行各种容器。

通过 WSL2，可以在 WSL 发行版中安装和运行标准的 Linux Docker 守护程序。这样做的好处是在启动时更快，占用的内存更少，并且只在运行容器时增加内存消耗。缺点是你必须自己安装和管理守护程序。

幸运的是，现在有第三种选择，即安装 Docker Desktop 并启用 WSL 后端。通过这种方法，您可以保留 Docker Desktop 在安装和管理方面的便利性。不同之处在于，Docker Desktop 会在 WSL 中为您运行守护程序，从而使您在不失便利性的情况下获得启动时间和内存使用方面的改进。

要开始使用，请从 https://www.docker.com/products/docker-desktop 下载并安装 Docker Desktop。安装完成后，在系统图标托盘中右键单击 Docker 图标，选择“设置”。您将看到以下屏幕：

![图 7.1 - Docker 设置的屏幕截图显示 WSL 2 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.1_B16412.jpg)

图 7.1 - Docker 设置的屏幕截图显示 WSL 2 选项

上面的截图显示了“使用基于 WSL 2 的引擎”选项。确保选中此选项以配置 Docker Desktop 在 WSL 2 下运行，而不是传统的虚拟机。

您可以从“资源”部分选择 Docker Desktop 与哪些发行版集成：

![图 7.2 - WSL 集成的 Docker 设置的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.2_B16412.jpg)

图 7.2 - WSL 集成的 Docker 设置的屏幕截图

正如您在上面的截图中看到的，您可以控制 Docker Desktop 与哪些发行版集成。当您选择与 WSL 发行版集成时，Docker 守护程序的套接字将对该发行版可用，并为您添加 docker 命令行界面（CLI）。选择您想要能够从中使用 Docker 的所有发行版，并单击“应用并重新启动”。

Docker 重新启动后，您将能够使用`docker`命令行界面（CLI）与任何选定的 WSL 发行版交互，例如`docker info`：

```
$ docker info
Client:
 Debug Mode: false
Server:
...
Server Version: 19.03.12
...
Kernel Version: 4.19.104-microsoft-standard
 Operating System: Docker Desktop
 OSType: linux
...
```

这个片段显示了运行`docker info`的一些输出，您可以看到服务器正在`linux`上运行，内核版本为`4.19.104-microsoft-standard`，这与我的机器上的 WSL 内核版本相同（您可以通过在 WSL 发行版中运行`uname -r`来检查您的机器上的版本）。

有关使用 WSL 安装和配置 Docker Desktop 的更多信息，请参阅 Docker 文档 https://docs.docker.com/docker-for-windows/wsl/。

现在我们已经安装了 Docker，让我们通过运行一个容器来开始。

# 使用 Docker 运行容器

正如前面提到的，Docker 为我们提供了一种标准化的方式来打包容器镜像。这些容器镜像可以通过 Docker 注册表共享，Docker Hub（https://hub.docker.com/）是一个常用的公共镜像注册表。在本节中，我们将使用以下命令运行一个带有`nginx` Web 服务器的容器：`docker run -d --name docker-nginx -p 8080:80 nginx`。

```
$ docker run -d --name docker-nginx -p 8080:80 nginx
Unable to find image 'nginx:latest' locally
latest: Pulling from library/nginx
8559a31e96f4: Already exists
1cf27aa8120b: Downloading [======================>                            ]  11.62MB/26.34MB
...
```

我们刚刚运行的命令的最后一部分告诉 Docker 我们要运行哪个容器镜像（`nginx`）。这个输出片段显示 Docker 在本地没有找到`nginx`镜像，所以它开始拉取（即下载）来自 Docker Hub 的镜像。容器镜像由多个层组成（我们将在本章后面讨论这个问题），在输出中，已经存在一个层并且正在下载另一个层。`docker`命令行界面（CLI）会随着下载的进行不断更新输出，如下所示：

```
$ docker run -d --name docker-nginx -p 8080:80 nginx
Unable to find image 'nginx:latest' locally
latest: Pulling from library/nginx
8559a31e96f4: Already exists
1cf27aa8120b: Pull complete
67d252a8c1e1: Pull complete
9c2b660fcff6: Pull complete
4584011f2cd1: Pull complete
Digest: sha256:a93c8a0b0974c967aebe868a186 e5c205f4d3bcb5423a56559f2f9599074bbcd
Status: Downloaded newer image for nginx:latest
336ab5bed2d5f547b8ab56ff39d1db08d26481215d9836a1b275e0c7dfc490d5
```

当 Docker 完成拉取镜像时，您将看到类似于上面输出的内容，确认 Docker 已经拉取了镜像并打印了创建的容器的 ID（`336ab5bed2d5…`）。此时，我们可以运行`docker ps`来列出正在运行的容器：

```
$ docker ps
CONTAINER ID        IMAGE              COMMAND                CREATED              STATUS              PORTS                 NAMES
336ab5bed2d5        nginx              "/docker-entrypoint.…"   About a minute ago   Up About a minute   0.0.0.0:8080->80/tcp|     docker-nginx
```

这个输出显示了一个正在运行的容器，我们可以看到容器 ID `336ab5bed2d5`的值与`docker run`命令输出的容器 ID 的开头匹配。默认情况下，`docker ps`输出容器 ID 的短格式，而`docker run`输出完整的容器 ID 值。

让我们回到我们用来运行容器的命令：`docker run -d --name docker-nginx -p 8080:80 nginx`。这个命令有几个部分：

+   `-d`告诉 Docker 在后台运行这个容器，即以分离模式运行。

+   `--name`告诉 Docker 使用一个特定的名称`docker-nginx`来命名容器，而不是生成一个随机的名称。这个名称也可以在`docker ps`的输出中看到，并且可以使用。

+   `-p`允许我们将主机上的端口映射到正在运行的容器内部的端口。格式为`<主机端口>:<容器端口>`，因此在`8080:80`的情况下，我们将主机上的端口`8080`映射到容器内部的端口`80`。

+   最后一个参数是要运行的镜像的名称：`nginx`。

由于端口`80`是`nginx`默认提供内容的端口，并且我们已将端口`8080`映射到该容器端口，因此我们可以在 Web 浏览器中打开`http://localhost:8080`，如下图所示：

![图 7.3-浏览器显示 nginx 输出的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.3_B16412.jpg)

图 7.3-浏览器显示 nginx 输出的屏幕截图

前面的屏幕截图显示了 Web 浏览器中 nginx 的输出。此时，我们使用了一个命令（`docker run`）在 Docker 容器中下载和运行 nginx。容器资源具有一定的隔离级别，这意味着容器内部提供流量的端口`80`在外部不可见，因此我们将其映射到容器外部的端口`8080`。由于我们正在使用 WSL 2 后端的 Docker Desktop，因此端口`8080`实际上在 WSL 2 虚拟机上公开，但由于我们在*第四章*中看到的魔法，即*Windows 与 Linux 的互操作性*，在*从 Windows 访问 Linux Web 应用程序*部分，我们可以从 Windows 访问`http://localhost:8080`。

如果我们让容器继续运行，它将继续消耗资源，因此在继续之前让我们停止并删除它，如下所示：

```
$ docker stop docker-nginx
docker-nginx
$ docker rm docker-nginx
docker-nginx
```

在此输出中，您可以看到`docker stop docker-nginx`，它停止了正在运行的容器。此时，它不再消耗内存或 CPU，但它仍然存在并引用了用于创建它的镜像，这会阻止删除该镜像。因此，在停止容器后，我们使用`docker rm docker-nginx`来删除它。为了释放磁盘空间，我们还可以通过运行`docker image rm nginx:latest`来清理`nginx`镜像。

现在我们已经看到了如何运行容器，让我们构建自己的容器镜像来运行。

# 在 Docker 中构建和运行 Web 应用程序

在本节中，我们将构建一个 Docker 容器镜像，该镜像打包了一个 Python Web 应用程序。该容器镜像将包含 Web 应用程序及其所有依赖项，以便在安装了 Docker 守护程序的机器上运行。

要按照此示例进行操作，请确保您已经在 Linux 发行版中克隆了本书的代码（来自[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)），然后打开终端并导航到`chapter-07/01-docker-web-app`文件夹，其中包含我们将在此处使用的示例应用程序。请查看`README.md`文件以获取运行应用程序所需的依赖项的安装说明。

示例应用程序基于 Python 的**Flask** Web 框架构建（https://github.com/pallets/flask），并使用**Gunicorn HTTP 服务器**托管应用程序（https://gunicorn.org/）。

为了使本章重点放在 Docker 容器上，该应用程序只有一个代码文件`app.py`：

```
from os import uname
from flask import Flask
app = Flask(__name__)
def gethostname():
    return uname()[1]
@app.route("/")
def home():
    return f"<html><body><h1>Hello from {gethostname()}</h1></body></html>"
```

如代码所示，定义了一个用于主页的单个端点，该端点返回一个显示 Web 服务器所在机器的主机名的消息。

可以使用`gunicorn --bind 0.0.0.0:5000 app:app`运行该应用程序，并在 Web 浏览器中打开`http://localhost:5000`：

![图 7.4-浏览器中显示示例应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.4_B16412.jpg)

图 7.4-浏览器中显示示例应用程序的屏幕截图

在此屏幕截图中，您可以看到示例应用程序的响应，显示应用程序正在运行的主机名（`wfhome`）。

现在您已经看到了示例应用程序的运行情况，我们将开始看如何将其打包为容器镜像。

## 介绍 Dockerfile

要构建一个镜像，我们需要能够向 Docker 描述镜像应该包含什么内容，为此，我们将使用一个 `Dockerfile`。`Dockerfile` 包含了一系列命令，供 Docker 执行以构建容器镜像：

```
FROM python:3.8-slim-buster
EXPOSE 5000
ADD requirements.txt .
RUN python -m pip install -r requirements.txt
WORKDIR /app
ADD . /app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

这个 Dockerfile 包含了一系列命令。让我们来看看它们：

+   `FROM` 命令指定 Docker 应该使用的基础镜像，换句话说，是我们容器镜像的起始内容。在基础镜像中安装的任何应用程序和软件包都成为我们在其之上构建的镜像的一部分。在这里，我们指定了 `python:3.8-slim-buster` 镜像，它提供了一个基于 `python:3.8-buster` 镜像的镜像，该镜像包含了一些常见的软件包，但这使得基础镜像变得更大。由于此应用程序只使用了几个软件包，我们使用了 `slim` 变体。

+   `EXPOSE` 表示我们要暴露一个端口（在本例中为 `5000`，因为这是 Web 应用程序将监听的端口）。

+   我们使用 `ADD` 命令将内容添加到容器镜像中。`ADD` 的第一个参数指定要从 `host` 文件夹添加的内容，第二个参数指定要将其放置在容器镜像中的位置。在这里，我们正在添加 `requirements.txt`。

+   `RUN` 命令用于使用刚刚通过 `ADD` 命令添加到镜像中的 `requirements.txt` 文件执行 `pip install` 操作。

+   `WORKDIR` 用于将容器中的工作目录设置为 `/app`。

+   `ADD` 再次用于将完整的应用程序内容复制到 `/app` 目录中。我们将在下一节中讨论为什么使用两个单独的 `ADD` 命令将应用程序文件复制进去。

+   最后，`CMD` 命令指定当从此镜像运行容器时将执行的命令。在这里，我们指定与刚刚在本地运行 Web 应用程序时使用的相同的 `gunicorn` 命令。

现在我们有了一个 `Dockerfile`，让我们来看看如何使用它来构建一个镜像。

## 构建镜像

要构建一个容器镜像，我们将使用 `docker build` 命令：

```
docker build -t simple-python-app  .
```

在这里，我们使用了 `-t` 开关来指定生成的镜像应该被标记为 `simple-python-app`。这是我们以后可以使用的镜像名称来运行容器。最后，我们告诉 Docker 使用哪个目录作为构建上下文，这里我们使用 `.` 表示当前目录。构建上下文指定要打包并传递给 Docker 守护进程用于构建镜像的内容 - 当您将文件 `ADD` 到 `Dockerfile` 时，它会从构建上下文中复制。

这个命令的输出非常长，所以我们不会完整地包含它，我们只会看一些关键部分。

这个命令的初始输出来自 `FROM` 命令：

```
Step 1/7 : FROM python:3.8-slim-buster
3.8-slim-buster: Pulling from library/python
8559a31e96f4: Already exists
62e60f3ef11e: Pull complete
...
Status: Downloaded newer image for python:3.8-slim-buster
```

在这里，您可以看到 Docker 已经确定它在本地没有基础镜像，所以从 Docker Hub 上拉取了它，就像我们之前运行 `nginx` 镜像一样。

在输出的稍后部分，我们可以看到 `pip install` 已经执行了安装应用程序要求的操作：

```
Step 4/7 : RUN python -m pip install -r requirements.txt
 ---> Running in 1515482d6808
Requirement already satisfied: wheel in /usr/local/lib/python3.8/site-packages (from -r requirements.txt (line 1)) (0.34.2)
Collecting flask
  Downloading Flask-1.1.2-py2.py3-none-any.whl (94 kB)
Collecting gunicorn
  Downloading gunicorn-20.0.4-py2.py3-none-any.whl (77 kB)
...
```

在上面的代码片段中，您可以看到 `pip install` 的输出，它正在安装 `flask` 和 `gunicorn`。

在输出的末尾，我们看到了一些成功的消息：

```
Successfully built 747c4a9481d8
Successfully tagged simple-python-app:latest
```

这些成功消息中的第一个给出了我们刚刚创建的镜像的 ID (`747c4a9481d8`)，第二个显示它已经使用我们指定的标签进行了标记 (`simple-python-app`)。要查看本地机器上的 Docker 镜像，可以运行 `docker image ls`：

```
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
simple-python-app   latest              7383e489dd38        16 seconds ago      123MB
python              3.8-slim-buster     ec75d34adff9        22 hours ago        113MB
nginx               latest              4bb46517cac3        3 weeks ago         133MB
```

在此输出中，我们可以看到我们刚刚构建的 `simple-python-app` 镜像。现在我们已经构建了一个容器镜像，可以准备运行它了！

## 运行镜像

正如我们之前看到的，我们可以使用 `docker run` 命令运行容器：

```
$ docker run -d -p 5000:5000 --name chapter-07-example simple-python-app
6082241b112f66f2bb340876864fa1ccf170a 519b983cf539e2d37e4f5d7e4df
```

在这里，您可以看到我们正在将 `simple-python-app` 镜像作为名为 `chapter-07-example` 的容器运行，并且已经暴露了端口 `5000`。命令输出显示了我们刚刚启动的容器的 ID。

容器运行时，我们可以在 Web 浏览器中打开`http://localhost:5000`：

![图 7.5 - 展示在 Web 浏览器中的容器化示例应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.5_B16412.jpg)

图 7.5 - 展示在 Web 浏览器中的容器化示例应用程序的屏幕截图

在这个屏幕截图中，我们可以看到示例应用程序的输出。请注意，它输出的主机名与`docker run`命令的输出中容器 ID 的开头匹配。当创建容器的隔离环境时，主机名设置为容器 ID 的短格式。

现在我们已经构建和运行了容器的初始版本，让我们来看看如何修改应用程序并重新构建镜像。

## 使用更改重新构建镜像

在开发应用程序时，我们会对源代码进行更改。为了模拟这个过程，在`app.py`中对消息进行简单更改（例如，将`Hello from`更改为`Coming to you from`）。一旦我们进行了这个更改，我们可以使用与之前相同的`docker build`命令重新构建容器镜像：

```
$ docker build -t simple-python-app -f Dockerfile .
Sending build context to Docker daemon   5.12kB
Step 1/7 : FROM python:3.8-slim-buster
 ---> 772edcebc686
Step 2/7 : EXPOSE 5000
 ---> Using cache
 ---> 3e0273f9830d
Step 3/7 : ADD requirements.txt .
 ---> Using cache
 ---> 71180e54daa0
Step 4/7 : RUN python -m pip install -r requirements.txt
 ---> Using cache
 ---> c5ab90bcfe94
Step 5/7 : WORKDIR /app
 ---> Using cache
 ---> f4a62a82db1a
Step 6/7 : ADD . /app
 ---> 612bba79f590
Step 7/7 : CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
 ---> Running in fbc6af76acbf
Removing intermediate container fbc6af76acbf
 ---> 0dc3b05b193f
Successfully built 0dc3b05b193f
Successfully tagged simple-python-app:latest
```

这次的输出有点不同。除了基本镜像不被拉取（因为我们已经下载了基本镜像）之外，您还可能注意到一些带有`---> Using cache`的行。当 Docker 运行`Dockerfile`中的命令时，每一行（有几个例外）都会创建一个新的容器镜像，后续的命令就像我们在基本镜像上构建一样。由于它们相互构建，这些镜像通常被称为层。在构建镜像时，如果 Docker 确定命令中使用的文件与先前构建的层匹配，则它将重用该层，并通过`---> Using cache`输出指示此情况。如果文件不匹配，则 Docker 运行该命令并使任何后续层的缓存无效。

这种层缓存是为什么我们将`requirements.txt`从应用程序的主要内容中拆分出来放在`Dockerfile`中的原因：安装依赖通常是一个耗时的操作，并且通常应用程序的其他文件更频繁地发生变化。将依赖拆分出来，并在复制应用程序代码之前执行`pip install`，可以确保层缓存在我们开发应用程序时与我们一起工作。

我们在这里看到了一系列 Docker 命令；如果您想进一步探索（包括如何将镜像推送到注册表），请查看 https://www.docker.com/101-tutorial 上的*Docker 101 教程*。

在本节中，我们已经看到了如何构建容器镜像以及如何运行容器，无论是我们自己的镜像还是来自 Docker Hub 的镜像。我们还看到了层缓存如何加速开发周期。这些都是基础步骤，在下一节中，我们将开始研究编排器，这是使用容器构建系统的上一层。

# 介绍编排器

在前一节中，我们看到了如何使用 Docker 的功能将我们的应用程序打包成容器镜像并运行。如果我们将镜像推送到 Docker 注册表，那么从安装了 Docker 的任何机器上都可以简单地拉取和运行该应用程序。然而，较大的系统由许多这样的组件组成，我们可能希望将它们分布在多个 Docker 主机上。这样可以通过增加或减少运行的组件容器实例的数量来适应系统上的负载变化。使用容器化系统获得这些功能的方法是使用编排器。编排器提供其他功能，例如自动重新启动失败的容器，在主机故障时在不同的主机上运行容器，以及与容器进行稳定通信，因为它们可能会重新启动并在主机之间移动。

有许多容器编排器，如 Kubernetes、Docker Swarm 和基于 Apache Mesos 和 Marathon 的 Mesosphere DC/OS。这些编排器都提供了稍微不同的功能和实现我们刚才描述的要求的方式。Kubernetes 已经成为一个非常流行的编排器，所有主要的云供应商都提供了 Kubernetes 的支持（它甚至在 Docker Enterprise 和 Mesosphere DC/OS 中都有支持）。本章的其余部分将介绍如何在 WSL 中创建一个 Kubernetes 开发环境并在其上运行应用程序。

# 在 WSL 中设置 Kubernetes

安装 Kubernetes 有很多选择，包括以下几种：

+   Kind（[`kind.sigs.k8s.io/`](https://kind.sigs.k8s.io/)）

+   Minikube（[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)）

+   MicroK8s（https://microk8s.io/）

+   k3s（[`k3s.io/`](https://k3s.io/)）

首先是 Kind，它代表 Kubernetes in Docker，专为测试 Kubernetes 而设计。只要您的构建工具可以运行 Docker 容器，它就可以作为在自动化构建中运行 Kubernetes 的一种好选择，用于集成测试的一部分。默认情况下，Kind 将创建一个单节点 Kubernetes 集群，但您可以配置它以运行多节点集群，其中每个节点都作为一个单独的容器运行（*我们将在第十章“使用 Visual Studio Code 和容器”中看到如何使用 Kind 在开发容器中使用 Kubernetes*）。

然而，在本章中，我们将使用 Docker Desktop 中内置的 Kubernetes 功能，它提供了一种方便的方式来启用由您管理的 Kubernetes 集群。

![图 7.6 - 显示在 Docker Desktop 中启用 Kubernetes 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.6_B16412.jpg)

图 7.6 - 显示在 Docker Desktop 中启用 Kubernetes 的屏幕截图

在这个屏幕截图中，您可以看到 Docker Desktop 设置的 Kubernetes 页面，其中包含“启用 Kubernetes”选项。勾选此选项并点击“应用并重启”，Docker Desktop 将为您安装一个 Kubernetes 集群。

就像我们一直使用`docker` CLI 与 Docker 进行交互一样，Kubernetes 也有自己的 CLI，即`kubectl`。我们可以使用`kubectl cluster-info`命令来检查我们是否能够连接到 Docker Desktop 为我们创建的 Kubernetes 集群：

```
$ kubectl cluster-info
Kubernetes master is running at https://kubernetes.docker.internal:6443
KubeDNS is running at https://kubernetes.docker.internal:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

这个输出显示`kubectl`已成功连接到`kubernetes.docker.internal`上的 Kubernetes 集群，表示我们正在使用*Docker Desktop Kubernetes 集成*。

现在我们有一个运行的 Kubernetes 集群，让我们来看看如何在其中运行一个应用程序。

# 在 Kubernetes 中运行 Web 应用程序

Kubernetes 引入了一些新的术语，其中第一个是 Pod。Pod 是在 Kubernetes 中运行容器的方式。当我们要求 Kubernetes 运行一个 Pod 时，我们会指定一些细节，比如我们希望它运行的镜像。像 Kubernetes 这样的编排器旨在使我们能够作为系统的一部分运行多个组件，包括能够扩展组件实例的数量。为了帮助实现这个目标，Kubernetes 添加了另一个概念，称为 Deployments。Deployments 是基于 Pod 构建的，允许我们指定我们希望 Kubernetes 运行的相应 Pod 的实例数量，并且这个值可以动态更改，使我们能够扩展（和缩小）我们的应用程序。

我们将稍后查看如何创建部署，但首先，我们需要为我们的示例应用程序创建一个新的标签。在之前构建 Docker 镜像时，我们使用了`simple-python-app`标签。每个标签都有一个或多个关联的版本，由于我们没有指定版本，它被假定为`simple-python-app:latest`。在使用 Kubernetes 时，使用*latest*镜像版本意味着 Kubernetes 将尝试从注册表中拉取镜像，即使它已经在本地存在。由于我们还没有将镜像推送到注册表，这将失败。我们可以重新构建镜像，指定`simple-python-app:v1`作为镜像名称，但由于我们已经构建了镜像，我们也可以通过运行`docker tag simple-python-app:latest simple-python-app:v1`来创建一个新的带标签的版本。现在我们有两个引用同一镜像的标签，但是通过使用`simple-python-app:v1`标签，只有在本地不存在镜像时，Kubernetes 才会尝试拉取镜像。有了我们的新标签，让我们开始将应用程序部署到 Kubernetes。

## 创建一个部署

将我们的示例应用程序部署到 Kubernetes 的第一步是在 Kubernetes 中创建一个部署对象。使用我们容器镜像的版本标签，我们可以使用`kubectl`创建一个部署：

```
$ kubectl create deployment chapter-07-example --image=simple-python-app:v1
deployment.apps/chapter-07-example created
$ kubectl get deployments
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
chapter-07-example   1/1     1            1           10s
```

此输出显示创建了一个名为`chapter-07-example`的部署，运行着`simple-python-app:v1`镜像。创建部署后，它显示了使用`kubectl get deployments`列出部署并获取关于部署状态的摘要信息。在这里，`READY`列中的`1/1`表示部署配置为运行一个实例的 pod，并且该实例可用。如果我们 pod 中运行的应用程序崩溃，Kubernetes 将（默认情况下）自动重新启动它。我们可以运行`kubectl get pods`来查看部署创建的 pod：

```
$ kubectl get pods
NAME                                  READY   STATUS    RESTARTS   AGE
chapter-07-example-7dc44b8d94-4lsbr   1/1     Running   0          1m
```

在这个输出中，我们可以看到 pod 的名称以部署名称开头，后面跟着一个随机后缀。

正如我们之前提到的，使用部署而不是 pod 的一个好处是可以对其进行扩展：

```
$ kubectl scale deployment chapter-07-example --replicas=2
deployment.apps/chapter-07-example scaled
$ kubectl get pods
NAME                                  READY   STATUS    RESTARTS   AGE
chapter-07-example-7dc44b8d94-4lsbr   1/1     Running   0       2m
chapter-07-example-7dc44b8d94-7nv7j   1/1     Running   0      15s
```

在这里，我们看到`kubectl scale`命令在`chapter-07-example`部署上使用，将副本数设置为 2，换句话说，将部署扩展到两个 pod。扩展后，我们再次运行`kubectl get pods`，可以看到我们创建了第二个 pod。

提示

在使用 kubectl 时，您可以通过启用 bash 自动补全来提高生产力。要配置这个，请运行：

`echo 'source <(kubectl completion bash)' >>~/.bashrc`

这将将 kubectl bash 自动补全添加到您的`.bashrc`文件中，因此您需要重新启动 Bash 以启用它（有关详细信息，请参阅[`kubernetes.io/docs/tasks/tools/install-kubectl/#optional-kubectl-configurations`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#optional-kubectl-configurations)），

通过这个更改，您现在可以键入以下内容（在<TAB>的位置按下*Tab*键）：

`kubectl sc<TAB> dep<TAB> chap<TAB> --re<TAB>2`

使用 bash 自动补全的最终结果是：

`kubectl scale deployment chapter-07-example --replicas=2`

正如您所看到的，这样可以节省输入命令的时间，并支持命令（如`scale`）和资源名称（`chapter-07-example`）的自动补全。

现在我们已经部署了应用程序，让我们看看如何访问它。

创建一个服务

接下来，我们希望能够访问作为`chapter-07-example`部署运行的 Web 应用程序。由于我们可以在多个 pod 上运行 Web 应用程序的实例，我们需要一种访问一组 pod 的方法。为此，Kubernetes 有一个称为`kubectl expose`的概念来创建服务：

```
$ kubectl expose deployment chapter-07-example --type="NodePort" --port 5000
service/chapter-07-example exposed
$ kubectl get services
NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP    PORT(S)          AGE
chapter-07-example   NodePort    10.107.73.156   <none>        5000:30123/TCP   7s
kubernetes           ClusterIP   10.96.0.1       <none>        443/TCP          16m
```

在这里，我们运行`kubectl expose`命令，指示 Kubernetes 为我们的`chapter-07-example`部署创建一个服务。我们将服务类型指定为`NodePort`，这使得服务在集群中的任何节点上都可用，并将`5000`作为服务目标端口，以匹配我们的 Web 应用程序正在侦听的端口。接下来，我们运行`kubectl get services`命令，显示新创建的`chapter-07-example`服务。在`PORT(S)`列下，我们可以看到`5000:30123/TCP`，表示该服务正在端口`30123`上侦听，并将流量转发到部署中的端口`5000`。

由于 Docker Desktop 为 Kubernetes 集群设置了网络（以及从 Windows 到 WSL 的`localhost`的 WSL 转发），我们可以在 Web 浏览器中打开`http://localhost:30123`。

![图 7.7 - 展示在浏览器中加载的 Kubernetes Web 应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_7.7_B16412.jpg)

图 7.7 - 展示在浏览器中加载的 Kubernetes Web 应用程序的屏幕截图

此屏幕截图显示了在浏览器中加载的 Web 应用程序和显示的主机名与我们在缩放部署后列出的 Pod 名称之一相匹配。如果您刷新页面几次，您将看到名称在我们缩放部署后创建的 Pod 名称之间更改，这表明我们创建的 Kubernetes 服务正在在 Pod 之间分发流量。

我们一直在交互式地运行`kubectl`命令来创建部署和服务，但 Kubernetes 的一个强大之处是它支持声明式部署。Kubernetes 允许您在`YAML`格式的文件中定义部署和服务等对象。通过这种方式，您可以指定系统的多个方面，然后一次性将一组`YAML`文件传递给 Kubernetes，Kubernetes 将创建它们。您以后可以更新*YAML*规范并将其传递给 Kubernetes，它将协调规范中的差异以应用您的更改。本书附带的代码示例位于`chapter-07/02-deploy-to-kubernetes`文件夹中（请参阅文件夹中的`README.md`文件以获取部署说明）。

在本节中，我们介绍了如何使用 Kubernetes 部署我们打包为容器镜像的 Web 应用程序。我们看到这将为我们创建 Pod，并允许我们动态扩展正在运行的 Pod 的数量。我们还看到如何使用 Kubernetes 创建一个服务，该服务在部署中的 Pod 之间分发流量。该服务为部署中的 Pod 提供了逻辑抽象，并处理部署的扩展以及已重新启动的 Pod（例如，如果它已崩溃）。这为使用 Kubernetes 工作提供了一个很好的起点，如果您想进一步了解，Kubernetes 在[`kubernetes.io/docs/tutorials/kubernetes-basics/`](https://kubernetes.io/docs/tutorials/kubernetes-basics/)上有一个很棒的交互式教程。

注意

如果您有兴趣深入了解使用*Docker*或*Kubernetes*构建应用程序，以下链接是一个很好的起点（还有其他内容的进一步链接）：

[`docs.docker.com/develop/`](https://docs.docker.com/develop/)

[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)

# 总结

在本章中，我们介绍了容器，并看到它们如何使应用程序及其依赖项打包在一起，以便在运行 Docker 守护程序的机器上简单运行。我们讨论了 Docker 注册表作为共享镜像的一种方式，包括常用的公共注册表：`docker` CLI，并使用它来运行来自 Docker Hub 的`nginx`镜像，Docker 会自动从 Docker Hub 将镜像拉取到本地机器上。

在运行了`nginx`镜像之后，你学会了如何使用在`Dockerfile`中定义的步骤来构建自定义 Web 应用程序的镜像。你了解到 Docker 会为`Dockerfile`中的步骤构建镜像层，并在后续构建中重用它们，如果文件没有更改的话。你还了解到可以通过精心构建`Dockerfile`，将最常变化的内容添加到后续步骤中，从而提高后续构建的时间。

在学习如何使用 Docker 之后，你了解了容器编排器的概念，然后开始学习 Kubernetes。通过 Kubernetes，你了解到可以使用不同类型的资源，如 pod、deployment 和 service 来部署应用程序。你了解到 Kubernetes 的部署是基于 pod 构建的，可以通过一个命令轻松地扩展 pod 实例的数量，并且可以使用 Kubernetes 的 service 来提供一种简单且一致的方式来访问部署中的 pod，而不受扩展的影响。

在下一章中，我们将更直接地关注 WSL，掌握构建和使用容器的知识将会很有用。
