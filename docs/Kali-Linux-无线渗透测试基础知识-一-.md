# Kali Linux 无线渗透测试基础知识（一）

> 原文：[`annas-archive.org/md5/021485514156F327797F187A748A3494`](https://annas-archive.org/md5/021485514156F327797F187A748A3494)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自不到 20 年前进入市场以来，无线网络已经呈指数级增长，并变得无处不在，不仅在企业中，而且在所有其他地方——各种公共场所（咖啡店、餐厅、购物中心、车站和机场）、露天免费 Wi-Fi 区域和私人住宅。

与所有其他技术一样，它们的传播导致了对其安全性的不断评估和改进的需求，因为一个容易受攻击的无线网络为攻击者提供了访问和攻击整个网络的简单途径，正如我们将在本书中看到的那样。

出于这些原因，对无线网络进行安全评估的过程，也称为无线渗透测试，已成为更一般的网络渗透测试的重要组成部分。

在本书中，我们探讨了使用著名的 Kali Linux 安全发行版执行无线渗透测试的整个过程，分析了从初始规划到最终报告的每个阶段。我们涵盖了无线安全的基本理论（协议、漏洞和攻击），但主要关注实际方面，使用 Kali Linux 提供的宝贵、免费和开源工具进行无线渗透测试。

# 本书涵盖内容

第一章，*无线渗透测试简介*，介绍了渗透测试的一般概念，并重点介绍了无线网络的四个主要阶段。

本章解释了如何与客户达成一致并计划渗透测试，并对过程的信息收集、攻击执行和报告撰写阶段进行了高层次的概述。

第二章，*使用 Kali Linux 设置您的机器*，介绍了 Kali Linux 发行版和专门设计用于无线渗透测试的包含工具。然后我们看到了其安装的硬件要求，不同的安装方法，并逐步介绍了在 VirtualBox 机器中的安装，为每个步骤提供了相关的截图。

安装 Kali Linux 后，本章介绍了无线适配器必须满足的特性，以及如何实际测试这些要求。

第三章，*WLAN 侦察*，讨论了无线渗透测试的发现或信息收集阶段。它从 802.11 标准和无线局域网（WLAN）的基本理论开始，然后涵盖了无线扫描的概念，即识别和收集关于无线网络的信息的过程。

然后我们学习如何使用 Kali Linux 中包含的工具执行无线网络扫描，展示了实际的例子。

第四章，*WEP 破解*，讨论了 WEP 安全协议，分析了其设计、漏洞和针对它开发的各种攻击。

本章说明了如何使用命令行工具和自动化工具来执行这些攻击的不同变体，以破解 WEP 密钥，证明了 WEP 是一种不安全的协议，不应该被使用！

第五章，*WPA/WPA2 破解*，从 WPA/WPA2 破解的描述、设计和特性开始，并展示了其安全性。我们看到，只有在使用弱密钥时，WPA 才容易受到攻击。在本章中，我们涵盖了各种工具来运行暴力和字典攻击以破解 WPA 密钥。还介绍了最近和有效的 WPA 破解技术，如 GPU 和云计算。

第六章，*攻击接入点和基础设施*，涵盖了针对 WPA-Enterprise、接入点和有线网络基础设施的攻击。它介绍了 WPA-Enterprise，它使用的不同认证协议，并解释了如何使用数据包分析器识别它们。然后，它涵盖了破解 WPA-Enterprise 密钥的工具和技术。

本章还涵盖了其他攻击，包括针对接入点的拒绝服务攻击，强制断开连接的客户端，恶意接入点攻击以及针对接入点默认认证凭据的攻击。

第七章，*无线客户端攻击*，涵盖了针对孤立无线客户端的攻击，以恢复 WEP 和 WPA 密钥，并说明如何设置一个虚假接入点来冒充合法接入点，并诱使客户端连接到它（恶意双胞胎攻击）。一旦客户端连接到虚假接入点，我们将展示如何使用 Kali Linux 提供的工具进行所谓的中间人攻击。

第八章，*报告和结论*，讨论了渗透测试的最后阶段，即报告阶段，解释了其基本概念，并特别关注了专业和精心撰写报告的原因和目的。

本章描述了报告编写过程的各个阶段，从规划到修订，以及典型的专业报告格式。

附录，*参考资料*，以章节格式列出了所有的参考资料。我们还介绍了 Kali Linux 中包含的主要工具，以记录渗透测试的发现。

# 您需要为这本书做些什么

这本书需要一台具有足够硬盘空间和 RAM 内存来安装和执行 Kali Linux 操作系统的笔记本电脑，以及一个适用于无线渗透测试的无线适配器，最好是外置 USB 适配器。有关这些要求的更详细信息在第二章中有介绍，*使用 Kali Linux 设置您的机器*。

不需要有 Kali Linux 和无线渗透测试的先前经验，但建议熟悉 Linux 和基本的网络概念。

# 这本书是为谁写的

这本书适用于渗透测试人员、信息安全专业人员、系统和网络管理员，以及想要开始或提高无线渗透测试知识和实际技能的 Linux 和 IT 安全爱好者，使用 Kali Linux 及其工具。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“首先我们执行`airmon-ng start wlan0`将接口置于监视模式”

任何命令行输入或输出都以以下方式书写：

```
# aireplay-ng --chopchop -b 08:7A:4C:83:0C:E0 -h 1C:4B:D6:BB:14:06 mon0

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击工具栏菜单上的**新建**按钮，向导就会启动。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：无线渗透测试简介

在本章中，我们将介绍渗透测试过程的关键概念，特别是无线渗透测试。

渗透测试是模拟对系统或网络的攻击过程，以指出其错误配置、弱点或安全漏洞及其相关的利用方式，这些方式可能被真正的攻击者用来获取对系统或网络的访问权限。

识别和评估漏洞的过程称为**漏洞评估**，有时被用作渗透测试的同义词，但它们实际上是不同的过程；事实上，渗透测试通常包括漏洞评估以及随后的攻击阶段，以实际利用发现的漏洞。在某些情况下，根据渗透测试的范围，可能不需要进行完整的漏洞评估，因为渗透测试可能只专注于特定的漏洞进行攻击。

渗透测试可以是外部的或内部的。外部渗透测试（有时也称为“黑盒”渗透测试）试图模拟真实的外部攻击，渗透测试人员对目标系统和网络没有先前的信息，而内部渗透测试（也称为“白盒”）是由获得内部权限的渗透测试人员执行的，他们试图利用网络漏洞来增加权限并做一些未经授权的事情，例如发动中间人攻击，正如我们将在第七章“无线客户端攻击”中看到的。

在本书中，我们主要将专注于外部渗透测试。

# 渗透测试的阶段

渗透测试过程可以分为四个主要阶段，即：

+   规划

+   发现

+   攻击

+   报告

描述这些阶段的渗透测试过程和方法的有用指南是 NIST CSRC SP800-115《信息安全测试和评估技术指南》（请参见附录 1.1 的参考部分），网址为[`csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf`](http://csrc.nist.gov/publications/nistpubs/800-115/SP800-115.pdf)。

渗透测试方法的四个阶段的方案如下图所示，取自前述出版物：

![渗透测试的阶段](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_01_01.jpg)

我们现在将探讨这四个阶段中的每一个。

## 规划阶段

规划阶段是渗透测试的关键部分，尽管它并不总是被赋予应有的重要性。在这个阶段，我们定义了渗透测试的范围和所谓的“参与规则”，这是渗透测试人员和客户之间达成的协议的结果，将在双方之间的合同中正式规定。必须明确的是，渗透测试人员绝不能在没有合同或超出合同规定的范围和参与规则的情况下进行操作，否则他/她可能会陷入严重的法律纠纷。范围涉及要测试的网络、客户希望通过渗透测试实现的目标和目标。

在这一阶段，我们需要考虑的是，例如，要扫描无线网络的区域、网络信号的覆盖范围以及预计连接的客户数量。我们还定义了测试的目标，例如应该评估的特定漏洞及其优先级；是否应该列举伪装和隐藏的接入点，以及是否应该对客户进行无线攻击。

参与规则包括，但不限于，预计时间表以及何时进行测试的日期和时间，客户的合法授权，要生成的报告格式，付款条款以及保密协议条款，根据该条款，测试结果由测试人员保密。

### 注意

在附录中提供的参考文献 1.4 和 1.5 的链接中提供了定义范围和参与规则的工作表（需要注册 SANS Institute 网站）。

一旦确定了范围和参与规则，渗透测试团队就会定义要用于测试执行的资源和工具。

## 发现阶段

在发现阶段，我们收集尽可能多关于渗透测试范围内的网络的信息。这个阶段也被称为信息收集阶段，非常重要，因为它精确定义了我们测试的目标，并允许收集关于它们的详细信息并暴露它们的潜在漏洞。

特别是对于我们的范围，我们将收集诸如：

+   隐藏网络和伪造接入点

+   连接到网络的客户端

+   网络使用的认证类型；我们想要找出开放或使用 WEP 的网络，因此易受攻击

+   组织外部通过无线信号可达的区域

发现阶段可以通过两种主要类型的无线网络扫描来实现，**主动**和**被动**。主动扫描意味着发送探测请求数据包以识别*可见*接入点，而被动扫描意味着捕获和分析所有无线流量，并且还允许发现隐藏的接入点。

我们将在第三章 *WLAN 侦察*中了解更多关于无线扫描以及如何使用 Kali Linux 中包含的无线扫描器，如 airmon、airodump 和 Kismet，来执行无线渗透测试的发现阶段。

## 攻击阶段

攻击阶段是渗透测试过程中最实际的部分，我们试图利用发现阶段确定的漏洞来访问目标网络。

这被称为*利用*子阶段，在我们的情况下可能涉及尝试破解认证密钥以连接到网络，设置伪造和蜜罐接入点并直接攻击客户端以恢复密钥。下一个阶段（如果合同需要）被称为*后利用*，在我们获得对其的访问权限后，涉及攻击网络和基础设施，例如控制访问点并对客户端执行中间人攻击。

值得重申的是，我们不应进行未在合同中明确要求的攻击。此外，攻击阶段应根据与客户建立的规则和方式进行，定义在参与规则中。例如，如果目标是生产系统或网络，我们可以与客户协商在工作时间之外进行此类攻击，因为无线连接和提供的服务可能会受到干扰。

我们将覆盖攻击阶段从第四章 *WEP 破解*到第七章 *无线客户端攻击*。

## 报告阶段

报告是渗透测试的最终阶段。之前的阶段非常重要，因为它们是我们计划和执行测试的地方，但有效地向客户传达其结果和发现仍然很重要。报告对于定义应对已识别的漏洞的对策和缓解活动是有用的。它通常由两个主要部分组成，执行摘要和技术报告。

### 执行摘要

执行摘要是对测试的目标、方法和发现的高层次总结，主要面向非技术管理层。因此，摘要应以清晰的语言和可理解的术语编写，避免使用过多的技术术语和表达。

执行摘要应包括：

+   测试目标的描述

+   发现问题的概述和描述

+   客户组织的安全风险概况定义

+   发现漏洞并减轻风险的纠正计划

+   改进组织安全姿态的建议

### 技术报告

技术报告包括对渗透测试的深入描述，以及有关发现和攻击阶段的详细信息，以及对客户所面临的已识别漏洞所带来的风险的评估和风险缓解计划。因此，技术报告涵盖了执行摘要的内容，但是从技术角度来看，主要是针对 IT 高管，他们应该根据报告中提供的纠正活动进行应用。

我们将在第八章*报告和结论*中涵盖报告阶段。

# 摘要

在本章中，我们介绍了无线渗透测试，并简要描述了其分为四个主要阶段：规划、发现、攻击和报告。

在下一章中，我们将看到如何在您的计算机上安装 Kali Linux，并检查您的无线适配器必须满足的要求，以开始进行无线渗透测试。


# 第二章：使用 Kali Linux 设置您的机器

在本章中，我们将涵盖以下主题，为您的笔记本电脑设置无线渗透测试：

+   介绍 Kali Linux 发行版

+   安装 Kali Linux

+   无线适配器设置和配置

# 介绍 Kali Linux 发行版

Kali Linux 是最受欢迎和使用最广泛的渗透测试和安全审计发行版。它由 Offensive Security 开发和维护，取代了 Backtrack Linux 成为 Kali Linux 的第一个版本，是 Backtrack 5 版本 3 的继任者。

Kali Linux 已经完全重建，现在它基于 Debian。它包括广泛的用于侦察和信息收集、嗅探和欺骗、漏洞评估、密码破解、利用、逆向工程、硬件黑客、取证调查、事件处理和报告的工具。对于无线渗透测试，有一个专门的集合（`kali-linux-wireless`元包），包括最知名的开源工具，如 Aircrack-ng 套件、Kismet、Fern Wifi Cracker、Wifite 和 Reaver 等。

在本书中，我们将主要使用 Aircrack-ng 套件，由 Thomas d'Otreppe 开发，因为它是用于审计无线网络的最完整和最受欢迎的工具集。有关 Aircrack-ng 项目的更多信息，请访问其网站[`www.aircrack-ng.org/`](http://www.aircrack-ng.org/)，本书中经常引用。此外，Kali Linux 支持各种无线适配器，并且其内核会不断更新以获取最新的无线注入补丁。

出于所有这些原因，Kali Linux 是我们目的的最佳选择。下一节演示了如何在我们的笔记本电脑上安装它。

# 安装 Kali Linux

有三种方法可以安装 Kali Linux，可以安装在硬盘上（单引导或多引导），可以安装在 USB 闪存驱动器上以用作实时系统，也可以使用软件（如 Oracle VirtualBox 和 VMware Workstation 或 Player）在虚拟机上安装。

安装至少需要 10GB 的硬盘空间，建议至少 1,024MB 的 RAM，尽管 Kali Linux 可以在只有 512MB 的 RAM 上运行。

在硬盘上安装 Kali Linux 在性能上更好，但缺点是要将所有硬盘空间都分配给它，或者对硬盘进行分区并使用一个分区来安装它，而在虚拟机上安装则提供了一个轻微较慢的系统，但也更加灵活，我们不必修改硬盘的配置。

我们可以使用可下载的 ISO 在虚拟机上安装 Kali Linux，也可以直接使用 VMware 或 VirtualBox 预构建的映像。32 位或 64 位的 ISO 可以从[`www.kali.org/downloads/`](https://www.kali.org/downloads/)下载，VMware 和 VirtualBox 映像可以从[`www.offensive-security.com/kali-linux-vmware-arm-image-download/`](https://www.offensive-security.com/kali-linux-vmware-arm-image-download/)下载。有趣的是，Kali Linux 也可以安装在树莓派等 ARM 设备上。

本章的其余部分涉及在虚拟机上安装和配置 Kali Linux，这个过程与直接在硬盘上安装非常相似。

## 在虚拟机上安装

要创建新的虚拟机并在其上安装 Kali Linux，我们需要使用虚拟化软件。

在本书中，我们将使用 Oracle VirtualBox，这是一款免费的开源虚拟化软件，适用于各种平台，如 Windows、Linux、Mac OS X 和 Solaris。要下载并获取有关如何安装它的信息，请参阅附录中的*参考资料*。

### 创建新的虚拟机

要创建新的虚拟机（VM），请按照以下步骤进行：

1.  在工具栏菜单上点击**新建**按钮，向导将开始。我们为虚拟机分配一个名称，并选择操作系统类型和版本，在我们的情况下分别为 Linux 和 Debian（架构，32 位或 64 位，取决于您的机器）：![创建新虚拟机](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_01.jpg)

1.  我们分配给虚拟机的 RAM 数量；这里推荐的大小是 512 MB，但对于我们的目的，至少 1,024 MB 会是更好的选择：![创建新虚拟机](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_02.jpg)

1.  然后，我们必须为我们的安装创建一个新的虚拟硬盘：![创建新虚拟机](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_03.jpg)

1.  我们选择**VDI（VirtualBox 磁盘映像）**作为虚拟磁盘格式：![创建新虚拟机](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_04.jpg)

1.  我们选择**动态分配**选项，这只会在虚拟磁盘文件增长时使用物理驱动器上的空间，直到达到固定的最大大小：![创建新虚拟机](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_05.jpg)

1.  我们设置虚拟磁盘文件位置和最大大小；然后点击**创建**按钮，虚拟机就准备好了！创建新虚拟机

### 安装步骤

此时，虚拟机已创建，我们准备在其上安装 Kali Linux 操作系统。为此，我们按照以下步骤进行：

1.  我们在 Oracle VM VirtualBox Manager 的左窗格中选择新创建的 Kali Linux VM，然后点击工具栏菜单上的**设置**，然后点击**存储**。我们选择与**CD/DVD 驱动器**字段关联的**控制器：IDE**条目，并在**属性**部分选择硬盘上的 Kali Linux ISO。这类似于在直接在硬盘上安装 Kali Linux 时在物理驱动器上插入 Kali Linux 安装 DVD，以便机器可以从中引导：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_07.jpg)

1.  现在，我们点击工具栏菜单上的**启动**按钮启动虚拟机。虚拟机从 ISO 引导，并在以下截图中显示安装引导菜单：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_08.jpg)

1.  我们按照安装向导的步骤，依次选择语言（默认为英语）、国家、区域设置、键盘布局、主机名和域名。然后，我们需要设置 root 帐户的密码。Root 是系统中默认和最高特权的帐户，具有完全的管理权限：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_09.jpg)

1.  我们选择时区，然后需要选择磁盘分区方法。我们可以选择引导方法（使用三种不同的方案）或手动方法，如果我们希望对磁盘进行分区。在我们的情况下，我们将选择第一种方法，并使用与虚拟机关联的整个虚拟磁盘：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_10.jpg)

1.  然后，安装程序询问要使用哪个磁盘来安装系统（在我们的情况下，是唯一的），在接下来的窗口中，询问我们是否要使用单个分区或为不同的挂载点创建单独的分区（例如，`/home`，`/usr/local`，`/opt`等）：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_11.jpg)

1.  安装程序创建根（`/`）和交换分区，并要求确认，将更改写入虚拟磁盘：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_12.jpg)

1.  在所有数据复制到磁盘后，安装程序询问我们是否要使用网络镜像来安装未包含在安装 ISO 中的软件或更新已安装的软件。然后，我们需要选择是否要在虚拟磁盘的**主引导记录**（**MBR**）上安装 GRUB 引导加载程序。我们将安装它：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_13.jpg)

1.  再走一步，安装就完成了。现在我们在虚拟机上有了一个全新的 Kali Linux 系统！我们可以重新启动虚拟机来启动它，然后从虚拟 CD/DVD 驱动器中删除安装 ISO：![安装步骤](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_14.jpg)

# 无线适配器的设置和配置

现在我们已经在虚拟机上安装了 Kali Linux，是时候谈谈无线适配器的配置了。但是，首先让我们看看它的要求。

## 无线适配器的要求

无线适配器必须满足进行无线渗透测试的主要要求是：

+   与 IEEE 802.11b/g/n Wi-Fi 标准兼容，可能还与在 5 GHz 频段上运行的 802.11a 兼容（双频支持）。

+   能够将卡放入所谓的*监控模式*，这允许对所有无线流量进行嗅探。监控模式相当于有线网络中的混杂模式。

+   支持*数据包注入*的能力，以主动向网络中注入流量。

要验证我们的 Wi-Fi 适配器是否满足这些要求，我们首先需要确定其芯片组，并验证其 Linux 驱动程序是否支持监控模式和数据包注入。我们将在本章后面看到如何实际测试我们的适配器是否满足这些要求。

### 注意

**验证适配器芯片组的兼容性**

确定芯片组并验证其兼容性的绝佳资源是 Aircrack-ng 文档 wiki 上的*Tutorial: Is My Wireless Card Compatible?*和*Compatibility_drivers*部分（请参阅附录中*第二章*，*使用 Kali Linux 设置您的机器*，*参考资料*）。

它们提供了一个详细的芯片组列表，以及它们在无线渗透测试中的支持级别。

如果我们的笔记本电脑不是很旧，几乎肯定配备了内置 Wi-Fi 卡。内置卡通常不是进行无线渗透测试的最佳选择，因为它们的大多数芯片组在 Kali Linux 上不支持此目的。此外，我们无法在虚拟机中使用内置卡，因为我们需要直接访问设备才能使其工作，而虚拟机只允许对 USB 设备进行直接访问。因此，如果 Kali Linux 在虚拟机上运行，我们只能使用 USB 无线适配器。

因此，推荐的选择是使用带有外置高增益天线的 USB 无线适配器，它比集成天线具有更多的发射功率和灵敏度，从而允许长距离信号接收和发送。

具有这些功能的适配器在 Kali Linux 中得到了很好的支持，价格便宜，因此在无线渗透测试人员中非常受欢迎的是 Alfa Networks AWUS036NH USB 卡。该卡具有 Ralink 芯片组。在 Linux 下得到很好支持的其他芯片组是 Atheros 和 Realtek RTL8187L 芯片组。

在本书的其余部分，我们将假设您正在使用 USB 无线适配器。

## 无线卡配置

将适配器连接到 USB 端口后，我们必须配置它以在安装了 Kali Linux 的虚拟机中使用。

1.  我们启动 VirtualBox VM Manager，在左窗格中选择我们的 Kali Linux VM，然后导航到**设置** | **USB**。首先，如果我们还没有启用 USB 2.0 控制器，我们应该启用它。这需要安装 VirtualBox 扩展包（有关更多信息，请参阅*安装 VirtualBox 扩展包*信息框）。

1.  我们点击右侧的添加新 USB 设备过滤器（绿色加号图标），然后选择与我们的无线适配器对应的设备：![无线卡配置](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_15.jpg)

### 注意

**安装 VirtualBox 扩展包**

我们可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载扩展包，根据安装的 VirtualBox 版本选择适当的文件。

有关 VirtualBox 扩展包及其安装方法的信息，请访问[`www.virtualbox.org/manual/ch01.html#intro-installing`](https://www.virtualbox.org/manual/ch01.html#intro-installing)。

1.  我们启动我们的虚拟机，现在应该能够通过 USB 直通功能使用我们的无线适配器。在虚拟机中启动 Kali Linux 后，我们以 root 用户登录系统并打开终端仿真器。我们输入`iwconfig`命令来列出系统上所有可用的无线接口：![无线网卡配置](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_16.jpg)

系统已分配`wlan0`接口给我们的适配器，但它仍未激活，如`ifconfig`输出所示：

![无线网卡配置](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_17.jpg)

1.  为了启用`wlan0`接口，我们执行`ifconfig wlan0 up`命令，然后使用`ifconfig`来验证它是否已被激活。现在，我们的无线接口已经启动运行，如下截图所示：![无线网卡配置](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_18.jpg)

### 测试适配器进行无线渗透测试

现在我们已经设置好了适配器，我们可以进行一个小测试，以验证它是否真的适合进行无线渗透测试，即它是否可以被置于监视模式并支持数据包注入。为此，我们将使用 Aircrack-ng 套件中的两个程序，这些程序在本书的其余部分中也将被广泛使用。

首先，我们执行`airmon-ng start wlan0`将接口置于监视模式。

如果命令成功完成，并且新创建的接口`mon0`启用了监视模式，那么它已通过了这个测试！

![测试适配器进行无线渗透测试](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_19.jpg)

接下来，我们运行`aireplay-ng -9 wlan0`命令，其中`-9`选项表示这是一个注入测试（完整形式为`--test`）：

![测试适配器进行无线渗透测试](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_02_20.jpg)

Aireplay-ng 是一个用于生成和注入帧的工具，我们将使用它来进行本书中涵盖的许多攻击。

如果输出中出现`Injection is working!`字符串，则测试成功，我们的适配器支持数据包注入！

测试还提供其他有价值的信息；它告诉我们无线接口使用的信道以及通过响应广播探测或接收的信标找到的接入点，以及相关的连接质量（我们将在第三章中讨论这些主题，*WLAN Reconnaissance*）。

有关注入测试的更多信息，请访问[`www.aircrack-ng.org/doku.php?id=injection_test`](http://www.aircrack-ng.org/doku.php?id=injection_test)。

### 故障排除

正如我们所看到的，Kali Linux 发行版支持各种无线适配器，我们不应该在配置无线适配器时遇到任何问题。

然而，有时我们的适配器在`iwconfig`输出中没有显示。在这种情况下，我们可以使用`lsusb`或`lspci`工具（取决于接口类型）来检查操作系统是否已检测到设备，并使用`dmesg`来检查相关驱动程序是否已正确加载。

有时，无线适配器可能被识别，但`ifconfig wlan0 up`命令无法启用接口，出现错误消息`'SIOCSIFFLAGS : No such file or directory'`。这个错误通常表示驱动程序无法加载适配器固件，因为固件丢失或未正确安装。

我们可以通过安装正确的固件来解决这个问题，这些固件可以在适配器驱动的文档中找到。

例如，要为 Ralink 芯片组适配器安装固件包，我们执行以下命令：

```
apt-get install firmware-ralink

```

有关无线适配器配置故障排除的更详细信息，可以在附录中找到一些有用的参考资料。

# 总结

在本章中，我们看到了如何使用 Virtual Box 创建虚拟机以及如何在其中安装 Kali Linux。在涵盖了无线适配器对无线渗透测试的要求之后，我们已经配置了 USB 无线适配器以在 Kali Linux 上工作，并对我们之前分析的要求进行了测试。

在下一章中，我们将涵盖无线渗透测试的发现和信息收集阶段。


# 第三章：无线局域网侦察

在本章中，我们将介绍无线局域网（**LANs**）的基本概念，并了解如何进行渗透测试的侦察和信息收集阶段。

本章涉及无线网络扫描和信息收集，列举可见和隐藏的网络，识别使用的安全协议、可能的漏洞以及连接的客户端。涵盖的主题如下：

+   802.11 标准和无线局域网简介

+   无线扫描简介

+   使用`airodump-ng`进行无线扫描

+   使用 Kismet 进行无线扫描

# 802.11 标准和无线局域网简介

在进行实际操作之前，值得回顾一下 802.11 标准的基本概念，无线局域网就是基于这些概念的。

802.11 是由 IEEE 制定的用于实现无线局域网的第二层（链路层）标准。使用 802.11 标准的设备和网络通常被称为**Wi-Fi**，这是**Wi-Fi 联盟**的商标。

随着时间的推移，标准还有后续的规范，主要的有 802.11a、802.11b、802.11g 和 802.11n。

802.11a 在 5 GHz 频段上运行，而 802.11b/g 在 2.4 GHz 频段上运行，这是目前 Wi-Fi 网络中最常用的频段。802.11n 支持这两个频段，并且向后兼容其他 802.11 规范。

Wi-Fi 信号的范围取决于使用的标准、传输设备的功率以及物理障碍和无线干扰的存在。

对于普通的 Wi-Fi 设备，室内的最大覆盖范围通常从 20-25 米不等，而室外则可达 100 米甚至更远。

802.11 标准的最大吞吐量，即最大数据速率，从 802.11a/b 标准的 11 Mbps 到 802.11n 标准的 600 Mbps 不等。

每个频段被细分为多个信道，这些信道是包含较小频率范围的子集。2.4 GHz 频段被细分为 14 个不同的信道，但并非所有信道都总是被使用。大多数国家通常只允许使用这些信道的一个子集，而一些国家则允许使用所有信道。

例如，美国允许使用 1 到 11 号信道，而日本允许使用所有 14 个信道。事实上，每个国家都建立了自己的*监管领域*（*regdomain*），这是一套定义无线传输的无线电频谱分配规则。监管领域还定义了允许的最大发射功率。

### 注意

**关于 Wi-Fi 信道**

要获取有关 Wi-Fi 信道和监管领域的更多信息，请参考维基百科上的资源[`en.wikipedia.org/wiki/List_of_WLAN_channels`](https://en.wikipedia.org/wiki/List_of_WLAN_channels)。

## 802.11 帧、类型和子类型

802.11 帧由**MAC 头部**、**有效载荷**和**帧检查序列**（**FCS**）部分组成，如下图所示：

![802.11 帧、类型和子类型](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_01.jpg)

MAC 头部部分被分成各种字段，其中包括**类型**和**子类型**字段。802.11 标准定义了三种不同类型的帧：

+   管理帧：这些帧协调无线局域网上的接入点和客户端之间的通信。管理帧包括以下子类型：

+   **信标帧**：用于宣布接入点（AP）的存在和基本配置。

+   **探测请求帧**：这些是由客户端发送的，用于测试接入点的存在或特定接入点的连接。

+   **探测响应帧**：这些是由接入点响应探测请求发送的，包含有关网络的信息。

+   认证请求帧：这些是由客户端发送的，用于在连接到接入点之前开始认证阶段。

+   认证响应帧：这些是由接入点发送的，用于接受或拒绝客户端的认证。

+   **关联请求帧**：客户端用于与 AP 关联的帧。它必须包含 SSID。

+   **关联响应帧**：这些由 AP 发送以接受或拒绝与客户端的关联。

+   **控制帧**：它们用于控制网络上的数据流量。控制帧的子类型包括**请求发送**（**RTS**）帧和**清除发送**（**CTS**）帧，它们提供了一个可选的机制来减少帧碰撞，以及由接收站发送的**确认**（**ACK**）帧，用于确认数据帧的正确接收。

+   **数据帧**：这些包含在网络上传输的数据，其中包含高层协议的数据包封装在 802.11 帧中。

在下一节中，我们将回顾无线网络的结构和构建模块。

## 基础设施模式和无线接入点

Wi-Fi 网络在基础设施模式下使用 802.11 标准。在这种模式下，称为**接入点**（**APs**）的设备用于将无线客户端站与有线局域网或互联网连接起来。接入点可以被视为有线网络的交换机的类比，但它们提供更多功能，如网络层路由、DHCP、NAT 以及通过远程控制台或 Web 管理面板的高级管理功能。

由单个 AP 组成的无线网络称为**基本服务集**（**BSS**），而具有多个 AP 的网络称为**扩展服务集**（**ESS**）。每个 AP 由**基本服务集 ID**（**BSSID**）标识，通常对应于 AP 上的无线接口的 MAC 地址。相反，无线局域网由**服务集 ID**（**SSID**）或**扩展服务集 ID**（**ESSID**）标识，通常是一个可读的字符串，用作网络的名称。

![基础设施模式和无线接入点](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_02.jpg)

接入点定期发送广播信标帧来宣布它们的存在。通常，信标还包含 AP 的 SSID，以便客户端可以轻松识别，并向 AP 发送认证和关联请求，以连接到无线网络。

## 无线安全

与有线网络相比，无线网络上的数据传输在物理媒介方面本质上不太安全，因为附近的任何人都可以轻松地嗅探到流量。无线局域网可以使用开放式认证，例如免费的 Wi-Fi 热点，此时客户端不需要进行认证，流量也不加密，使得开放网络完全不安全。

随着时间的推移，已经开发了两种为无线局域网提供认证和加密的安全协议：**有线等效隐私**（**WEP**）和**Wi-Fi 保护访问**（**WPA**/**WPA2**）。

WEP 和 WPA/WPA2 认证协议及其相关破解技术将在第四章 *WEP 破解*和第五章 *WPA/WPA2 破解*中进行讨论。

# 无线局域网扫描

彻底检查无线电波以找到无线网络的过程称为*无线扫描*。

无线网络扫描已经变得非常流行，即使在非技术人员中也是如此，这也部分归因于所谓的*wardriving*现象。Wardriving 是在户外定位无线网络的活动，通常是驾驶汽车并配备笔记本电脑、高增益天线和 GPS 接收器。

扫描有两种主要类型：**主动**和**被动**。

+   主动扫描涉及发送广播探测请求数据包，并等待来自接入点的探测响应数据包，记录已发现的接入点。这是客户端用来识别附近可用无线网络的标准方法。这种方法的缺点是，接入点可以配置为忽略广播探测请求数据包，并从发送的信标中排除其 SSID（**隐藏 AP**），因此在这种情况下，主动扫描无法识别网络。

+   被动扫描在无线侦察方面提供了更好的结果，并且是无线扫描器采用的方法。在被动扫描中，我们不发送广播探测请求。相反，无线适配器被置于监视模式，以便它可以嗅探 Wi-Fi 频率范围内特定信道上的所有流量。捕获的数据包被分析，以确定哪些接入点正在传输，从信标中包含的 BSSID，以及哪些客户端已连接。这样，即使在主动扫描中隐藏的接入点也可以被揭示。

Kali Linux 中包含的用于扫描无线网络的工具属于被动扫描器的范畴。在本章中，我们将介绍其中两种最流行的工具，`airodump-ng`和`Kismet`，但也可以使用 Fern Wi-Fi Cracker 和 Wifite 等工具来实现这一目的。在接下来的小节中，我们将看到如何将无线适配器配置为监视模式。

## 配置无线适配器为监视模式

在上一章中，我们已经看到了如何将无线接口置于监视模式，以验证其是否与数据包嗅探兼容。现在，我们来分析这个过程的细节。

回想一下，我们发出了`airmon-ng start wlan0`命令，如下面的截图所示：

![配置无线适配器为监视模式](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_03.jpg)

`airmon-ng`工具还会指示我们适配器使用的芯片组和驱动程序。请注意，`mon0`接口是以监视模式创建的，而`wlan0`接口处于托管模式（这是无线适配器的默认模式），如`iwconfig`命令的以下输出所示：

![配置无线适配器为监视模式](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_04.jpg)

`mon0`接口正在监听所有信道。如果我们想监听特定信道，我们可以发出`airmon-ng start wlan0 <channel>`命令：

![配置无线适配器为监视模式](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_05.jpg)

我们看到另一个名为`mon1`的接口已经以监视模式创建。我们可以为一个物理无线接口创建多个监视模式接口。在运行`airmon-ng`时，我们注意到一个警告，告诉我们一些进程可能会干扰`Aircrack-ng`套件的其他工具。要停止这些进程，我们可以执行`airmon-ng check kill`。

如果我们想要停止`mon0`接口，我们运行`airmon-ng stop mon0`命令：

![配置无线适配器为监视模式](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_06.jpg)

现在接口已经处于监视模式，我们可以进行无线扫描了。

## 使用 airodump-ng 进行无线扫描

`airodump-ng`工具是`Aircrack-ng`套件中包含的众多工具之一。除了记录有关发现的接入点和客户端的信息外，它还能够嗅探和捕获 802.11 帧。`Airodump-ng`扫描 Wi-Fi 频段，从一个信道跳到另一个信道。要使用它，我们需要先将无线接口置于监视模式，就像我们之前看到的那样，然后运行`airodump-ng mon0`命令。下面的截图显示了它的输出：

![使用 airodump-ng 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_07.jpg)

第一行显示了 AP 和客户端之间的最后一次关联，当前信道，经过的运行时间以及使用的安全协议。正如我们在前面的截图中所注意到的，屏幕的上半部分显示了 AP，而下半部分显示了客户端。

对于找到的每个 AP，显示以下信息：

+   BSSID（MAC 地址）

+   信号的功率级别（PWR）和接收质量（RXQ）

+   发送的信标数量和捕获的数据包数量

+   信道（CH）

+   支持的最大速度（MB）

+   加密算法（ENC）、密码（CIPHER）和使用的认证协议（AUTH）

+   无线网络名称或 SSID（ESSID）

如果 ESSID 字段中出现`<length: number>`，这意味着 SSID 是隐藏的，AP 只会透露其长度（字符数）。如果数字是 0 或 1，则意味着 AP 不会透露 SSID 的实际长度。

在底部的`STATION`字段是关于客户端的 MAC 地址，它可以与 AP 关联。如果关联，则 AP 的 BSSID 显示在相关字段中；否则，显示`not associated`状态。

`Probes`字段指示客户端正在尝试连接的 AP 的 SSID，如果它当前没有关联。当它对来自客户端的探测请求或关联请求做出响应时，这可以揭示一个隐藏的 AP。

有其他方法可以获取隐藏的 SSID。我们可以通过向连接的客户端发送去认证数据包来强制它们重新关联到 AP，就像我们将在第七章中看到的那样，*无线客户端攻击*。我们还可以使用 Wireshark 分析捕获的关联和探测请求/响应数据包来恢复 SSID。我们将在第四章和第五章中涵盖数据包转储和分析，关于 WEP 和 WPA/WPA2 的破解。

我们可以使用`-w`或`--write`选项后跟文件名将输出写入文件。`Airodump-ng`可以以各种格式（`pcap`、`ivs`、`csv`、`gps`、`kismet`和`netxml`）保存输出，与 Kismet 和 Wireshark 等数据包分析工具兼容。

`Airodump-ng`还允许通过`--channel`或`-c <ch_nr1,ch_nr2…..ch_nrN>`选项选择特定的信道：

```
airodump-ng -c 1 -w output mon0

```

![使用 airodump-ng 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_08.jpg)

# 使用 Kismet 进行无线扫描

Kismet 是一个功能强大的被动扫描程序，可用于不同的平台，并且默认安装在 Kali 上。它不仅仅是一个扫描程序，还是一个无线帧分析和入侵检测工具。

Kismet 由两个主要进程组成：`kismet_server`和`kismet_client`。`kismet_server`组件负责捕获、记录和解码无线帧。它的配置文件是`kismet.conf`，位于 Kali Linux 的`/etc/kismet/`目录下。`kismet_client`前端是一个基于 ncurses 的界面，显示检测到的 AP、统计信息和网络详细信息。要运行它，我们在命令行上键入`kismet`，或者从**应用程序**菜单中导航到**Kali Linux** | **无线攻击** | **802.11 无线工具** | **Kismet**：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_09.jpg)

正如我们所看到的，Kismet 提示我们启动服务器，我们选择`Yes`，然后在随后的提示中选择`Start`。然后可能会出现一条消息，说没有定义数据包源，并要求我们添加一个数据包源：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_10.jpg)

数据包源是我们的监视模式接口`mon0`，我们将其插入到随后的提示中的`Intf`字段中：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_11.jpg)

数据包源也可以在`kismet.conf`文件中的`ncsource`指令中设置，如下截图所示：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_12.jpg)

这是配置数据包源的推荐方法，避免每次启动 Kismet 时手动配置。

我们关闭服务器控制台，客户端界面显示出来。要访问窗口顶部的菜单，我们按下*~*键，并用箭头键移动到条目上。可以通过导航到**Kismet** | **Preferences**来自定义 Kismet 界面和行为：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_13.jpg)

屏幕从上到下分为以下主要部分：网络列表、客户端列表、数据包图、状态以及右侧的一般信息侧栏。您可以在**View**菜单中选择要可视化的部分：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_14.jpg)

网络列表以默认的自适应模式显示检测到的网络。

要选择一个网络并查看其详细信息以及连接的客户端，我们需要将排序方法更改为另一个，例如在**Sort**菜单中使用**Type**或**Channel**。然后我们可以通过鼠标点击列表中的网络来选择一个网络：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_15.jpg)

转到**Windows** | **网络详细信息**以获取更详细的信息，例如 BSSID、信道、制造商、信号级别、数据包速率等：

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_16.jpg)

如果选择**Clients**选项，我们可以看到连接到网络的客户端，以及有用的信息，如 MAC 地址、交换的数据包和客户端设备制造商。

![使用 Kismet 进行无线扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_03_17.jpg)

对于隐藏 SSID 的网络，Kismet 在网络名称的位置显示字符串`<Hidden SSID>`。当客户端尝试连接到网络时，AP 会在响应数据包中清楚地发送 SSID，允许 Kismet 揭示它，就像我们已经在`Airodump-ng`中看到的那样。

Kismet 默认在启动的目录中生成以下日志文件（但我们可以在`kismet.conf`中的`logtemplate`指令中更改这一点）：

+   数据包捕获文件

+   以文本格式（`.nettxt`）的网络

+   以 XML 格式（`.netxml`）的网络

+   以 XML 格式（`.gpsxml`）的 GPS 数据

然后可以使用 Wireshark 检查数据包捕获文件，其中可能包含频谱数据、信号和噪声水平以及 GPS 数据。

实际上，Kismet 以及`Airodump-ng`可以通过`gpsd`守护进程与 GPS 接收器集成，以确定网络的坐标，这也可以用于使用适当的工具（如 GISKismet）实现图形地图。

### 注意

**GISKismet**

GISKismet 是 Kismet 的可视化工具，它默认包含在 Kali Linux 中，允许将`.netxml`文件导入 SQLite 数据库，以便我们可以对其执行 SQL 查询，并构建网络的图表和地图。当扫描具有许多接入点的大型网络时，此工具可能非常有用。有关更多信息，请参阅 GISKismet 网站[`trac.assembla.com/giskismet/wiki`](http://trac.assembla.com/giskismet/wiki)。

# 总结

在本章中，我们介绍了 IEEE 802.11 标准和基础设施模式下的典型无线局域网部署。然后我们介绍了无线扫描的基本概念，并看到如何使用 Kali Linux 中包含的两种最有效的工具`airodump-ng`和 Kismet 来实际发现和收集关于无线网络的信息。

在下一章中，我们将介绍 WEP 协议，解释为什么它是不安全的，并看看如何使用 Kali Linux 提供的工具来破解它。


# 第四章：WEP 破解

在本章中，我们将介绍**有线等效隐私**（**WEP**）协议及其漏洞，展示如何使用 Kali Linux 中包含的一些工具，即 Aircrack-ng 套件和 Fern WiFi Cracker 来破解 WEP 密钥。

我们将涵盖以下主题：

+   WEP 介绍

+   使用 Aircrack-ng 破解 WEP

+   使用自动化工具破解 WEP

# WEP 简介

WEP 协议是在最初的 802.11 标准中引入的，作为为无线局域网实现提供身份验证和加密的手段。它基于**RC4**（**Rivest Cipher 4**）流密码，使用 40 位或 104 位的**预共享密钥**（**PSK**），具体取决于实现。24 位伪随机**初始化向量**（**IV**）与预共享密钥连接在一起，用于生成 RC4 用于实际加密和解密过程的每个数据包密钥流。因此，生成的密钥流可能是 64 位或 128 位长。

在加密阶段，密钥流与明文数据进行异或运算，以获得加密数据，而在解密阶段，加密数据与密钥流进行异或运算，以获得明文数据。加密过程如下图所示：

![WEP 简介](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_01.jpg)

## 针对 WEP 的攻击

首先，我们必须说 WEP 是一个不安全的协议，并已被 Wi-Fi 联盟弃用。它存在与密钥流的生成、IV 的使用和密钥长度相关的各种漏洞。

IV 用于向密钥流添加随机性，试图避免重用相同的密钥流来加密不同的数据包。WEP 的设计并未实现这一目的，因为 IV 只有 24 位长（具有 2²⁴ = 16,777,216 个可能的值），并且在每个帧中以明文形式传输。因此，在一定时间后（取决于网络流量），将重用相同的 IV，因此也将重用相同的密钥流，使攻击者能够收集相关的密文并执行统计攻击以恢复明文和密钥。

针对 WEP 的第一个著名攻击是 2001 年的**Fluhrer, Mantin and Shamir**（**FMS**）攻击。FMS 攻击依赖于 WEP 生成密钥流的方式，以及它还使用*weak* IV 来生成弱密钥流，使得攻击者能够收集足够数量的使用这些密钥流加密的数据包，对其进行分析，并恢复密钥。

完成 FMS 攻击所需收集的 IV 数量约为 40 位密钥为 250,000 个，104 位密钥为 1,500,000 个。

FMS 攻击已经被 Korek 改进，提高了其性能。

Andreas Klein 发现了 RC4 密钥流与密钥之间的更多相关性，这些相关性可以用来破解 WEP 密钥。

2007 年，**Pyshkin, Tews, and Weinmann**（**PTW**）扩展了 Andreas Klein 的研究，并改进了 FMS 攻击，显著减少了成功恢复 WEP 密钥所需的 IV 数量。

事实上，PTW 攻击不像 FMS 攻击那样依赖于弱 IV，并且非常快速和有效。它能够在不到 40,000 帧的情况下以 50%的成功概率恢复 104 位 WEP 密钥，并且在 85,000 帧的情况下以 95%的概率成功。

PTW 攻击是 Aircrack-ng 用来破解 WEP 密钥的默认方法。

FMS 和 PTW 攻击都需要收集相当多的帧才能成功，并且可以被动地进行，嗅探目标 AP 的同一信道上的无线流量并捕获帧。问题在于，在正常情况下，我们将不得不花费相当长的时间 passively 收集攻击所需的所有必要数据包，特别是 FMS 攻击。

为了加快这个过程，想法是重新向网络中注入帧以产生响应流量，以便更快地收集所需的 IV。适合这一目的的一种帧类型是 ARP 请求，因为 AP 会广播它，并且每次都会有一个新的 IV。由于我们没有与 AP 关联，如果我们直接向其发送帧，它们将被丢弃并发送去认证帧。相反，我们可以捕获关联客户端的 ARP 请求并将其重发到 AP。

这种技术被称为**ARP 请求重放**攻击，也被 Aircrack-ng 采用用于实施 PTW 攻击。

### 注意

**深入破解 WEP**

这些攻击背后的数学和密码学超出了本书的范围。对于那些有兴趣了解攻击的细节和技术的人来说，一个有价值的资源是 Aircrack-ng 链接和参考页面上的*技术论文*部分，网址为[`www.aircrack-ng.org/doku.php?id=links#technique_papers`](http://www.aircrack-ng.org/doku.php?id=links#technique_papers)。

# 使用 Aircrack-ng 破解 WEP

现在我们已经探讨了 WEP 的漏洞及其相关攻击，我们准备开始实际操作部分。在本节中，我们将看到如何使用 Aircrack-ng 套件破解 WEP 密钥。

在侦察阶段，我们已经收集了关于每个要测试的网络的信息，例如 BSSID、操作频道和使用的安全协议。在这里，我们专注于一个受 WEP 保护的网络，并开始捕获在相关频道上 AP 和关联客户端之间交换的帧。

我们可以通过将我们的 WiFi 路由器设置为使用 WEP 来尝试这种攻击。我们假设 AP 的 BSSID 是 08:7A:4C:83:0C:E0，频道是 1。第一步是在频道 1 上启动监视模式，就像我们在前一章中看到的那样：

```
airmon-ng start wlan0 1

```

为了捕获我们目标网络的流量，我们将执行以下命令：

```
airodump-ng --channel 1 --bssid 08:7A:4C:83:0C:E0 --write wep_crack mon0

```

![使用 Aircrack-ng 破解 WEP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_02.jpg)

这个命令将所有捕获的帧保存到`wep_crack` pcap 文件中。我们将看到如何在有客户端连接到 AP 和没有客户端连接到 AP 时破解 WEP 密钥。

## 使用连接的客户端破解 WEP 密钥

从前面的截图中，我们看到有一个客户端（其 MAC 地址为 98:52:B1:3B:32:58）连接到我们的目标 AP。

由于我们没有与 AP 关联，也无法自己发送 ARP 请求，我们捕获并重发由此客户端发送的请求。

为此，我们使用 aireplay-ng，这是一个旨在注入帧的工具，它有各种选项可以执行不同的攻击，我们将在本书中看到。我们已经在第二章中使用它来测试无线适配器的注入，*使用 Kali Linux 设置您的机器*。

为了破解 WEP 密钥，我们将执行以下步骤：

1.  我们在终端模拟器中打开一个新标签并运行以下命令：

```
aireplay-ng --arpreplay -h 98:52:B1:3B:32:58 -b 08:7A:4C:83:0C:E0 mon0

```

这里，`-b`是 BSSID，`-h`是客户端 MAC 地址，`-arpreplay`（或-3）是 ARP 请求重放攻击选项。

![使用连接的客户端破解 WEP 密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_03.jpg)

我们切换到终端并输出`airodump-ng`，我们应该注意到捕获的帧数（#Data）迅速增加。

1.  在收集了足够数量的数据包后（即，如我们所见，Aircrack-ng 实施的 PTW 攻击需要约 40,000 个数据包），我们可以开始尝试破解 WEP 密钥，启动一个新的控制台标签中的`aircrack-ng`。

Aircrack-ng 是一个工具，可以使用 PTW 攻击从保存在`.cap`文件中的帧中恢复密钥。我们运行以下命令：

```
aircrack-ng -b 08:7A:4C:83:0C:E0 wep_crack-01.cap

```

这里`-b`是（通常）BSSID。如果`aircrack-ng`无法破解 WEP 密钥，它会等待`airodump-ng`收集更多的 IV 并重试该过程（默认情况下，每收集 5000 个 IV）：

![有连接客户端的 WEP 密钥破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_04.jpg)

在下面的屏幕截图中，我们可以看到`aircrack-ng`尝试破解密钥，但捕获的 IV 数量仍然很少：

![有连接客户端的 WEP 密钥破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_05.jpg)

最后，它以十六进制和 ASCII 显示破解的密钥：

![有连接客户端的 WEP 密钥破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_06.jpg)

## 无连接客户端的 WEP 密钥破解

在本节中，我们涵盖了在没有与 AP 关联的客户端的更复杂情况下恢复密钥的情况。

由于我们无法回复 ARP 请求帧，我们需要以某种方式模拟与 AP 的认证（虚假认证）。为此，我们执行以下命令：

```
aireplay-ng --fakeauth 0 -o 1 -e InfostradaWiFi-201198 -a 08:7A:4C:83:0C:E0 -h 1C:4B:D6:BB:14:06 mon0

```

这里，`--fakeauth`（或-1）是虚假认证选项，`0`是重新关联的时间间隔（无延迟），`-o`是每次发送的数据包数，`-e`是网络 SSID，`-a`是 BSSID，`-h`是`mon0`接口的 MAC 地址：

![无连接客户端的 WEP 密钥破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_07.jpg)

我们应该看到消息说虚假认证已成功。如果我们收到`Got a deauthentication packet!`的消息，可能 AP 应用了 MAC 过滤，只允许特定的 MAC 地址访问。

### 分段和 ChopChop 攻击

接下来，我们需要找到一种方法来生成使用 AP 使用的 WEP 密钥加密的 ARP 请求帧，但我们没有它，我们正在寻找恢复它的方法！

这时两种攻击可以帮助我们：**分段**和**ChopChop**攻击。并非所有无线设备驱动程序都支持它们，也并非所有 AP 都能成功受到攻击，因此这些攻击可以交替进行。

即使没有客户端连接，接入点也会传输帧。分段攻击允许从 AP 传输的单个帧开始恢复用于加密帧的密钥流（而不是实际密钥）。密钥流的最大大小可能等于**MTU**（**最大传输单元**），即 1500 字节。

要执行攻击，我们运行以下命令：

```
aireplay-ng --fragment -b 08:7A:4C:83:0C:E0 -h 1C:4B:D6:BB:14:06 mon0

```

![分段和 ChopChop 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_08.jpg)

该程序捕获了一个来自 AP 的帧，并询问我们是否要使用这个数据包。我们确认后，程序会尝试恢复高达 1500 字节的密钥流。当它达到足够的字节数（384）时，它会要求退出并保存恢复的密钥流。如果我们接受，输出中会出现`Saving keystream in fragment...`的消息，攻击将成功终止：

![分段和 ChopChop 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_09.jpg)

然后我们可以继续伪造一个 ARP 请求注入到网络中，接下来我们会看到。否则，我们可以尝试 ChopChop 攻击。

ChopChop 攻击也可以像分段攻击一样从单个 WEP 加密帧中恢复密钥流，但它更复杂，通常速度较慢，因为它仅依赖于密文，而不依赖于任何已知的明文。

要执行它，我们执行以下命令：

```
aireplay-ng --chopchop -b 08:7A:4C:83:0C:E0 -h 1C:4B:D6:BB:14:06 mon0

```

输出将类似于以下屏幕截图：

![分段和 ChopChop 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_10.jpg)

如果攻击成功，我们会注意到密钥流和明文已保存。

### 伪造和注入 ARP 请求帧

恢复了密钥流后，现在可以使用`packetforge-ng`工具伪造加密的 ARP 请求：

```
packetforge-ng --arp -a 08:7A:4C:83:0C:E0 -h 1C:4B:D6:BB:14:06 -k 192.168.1.100 -l 192.168.1.1 -y fragment-0325-172339.xor -w arp- request

```

这里，`--arp`（或-0）是用于 ARP 数据包的选项，`-a`是 AP 的 MAC 地址，`-h`是源 MAC 地址，`-k`是目标 IP 地址，`-l`是源 IP 地址，`-y`指定密钥流文件（使用先前看到的攻击获得），`-w`是我们需要保存生成的 ARP 请求的文件：

伪造和注入 ARP 请求帧

一旦我们伪造了 ARP 请求，我们就可以用`aireplay-ng`注入它：

```
aireplay-ng --interactive -r arp-request mon0

```

在下面的屏幕截图中，我们可以注意到正在注入的 ARP 请求的详细信息：

![伪造和注入 ARP 请求帧](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_12.jpg)

`--interactive`选项允许我们注入我们选择的帧，使用`-r`选项指定。

我们切换回`airodump-ng`终端，应该观察到捕获的帧数（#Data）在增加：

当我们有足够数量的帧时，我们可以开始使用`aircrack-ng`来处理生成的`pcap`文件并恢复密钥：

```
aircrack-ng -b 08:7A:4C:83:0C:E0 wep_crack-10.cap

```

![伪造和注入 ARP 请求帧](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_14.jpg)

## 使用自动化工具进行 WEP 破解

在前面的部分中，我们介绍了使用 Aircrack-ng 套件中包含的工具进行 WEP 密钥破解，该套件提供了广泛的选项和很高的控制和细粒度。对于无线渗透测试人员来说，学会使用这些工具并理解实施攻击的逻辑是至关重要的。

Kali Linux 中还有其他工具可以自动化 WEP 破解过程，因此更容易和立即使用。

其中一个是名为 Wifite 的 Python 脚本，它使用 Aircrack-ng 工具进行密钥破解。我们可以在 Wifite 网站[https://code.google.com/p/wifite/]下载程序并阅读文档和使用示例。程序的最新版本可在[https://github.com/derv82/wifite]找到。我们将在第五章中介绍 Wifite，*WPA/WPA2 破解*。

另一个简单的自动化程序是 Fern WiFi Cracker，我们将在下一节中探讨。

## 使用 Fern WiFi Cracker 进行 WEP 破解

Fern WiFi Cracker 是一个用 Python 编写的 GUI 工具，基于 Qt 库，并依赖于 Aircrack-ng 工具来执行底层工作。

它不仅设计用于仅需点击几下鼠标即可破解 WEP 和 WPA/WPA2 密钥，还可以对 AP 和客户端执行各种其他无线攻击。

要运行该程序，我们导航至**应用程序菜单** | **Kali Linux** | **无线攻击** | **802.11 无线工具** | **fern-wifi-cracker**。

GUI 界面简单直观。窗口顶部有一个下拉菜单，列出了可用的无线接口。我们选择我们的接口，程序将其置于监视模式：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_15.jpg)

要扫描无线网络，我们点击**扫描接入点**按钮，应该看到检测到的带有 WEP 或 WPA 加密的网络数量，以及相关的按钮：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_16.jpg)

我们点击**Wi-Fi WEP**按钮，打开一个窗口，顶部显示检测到的 WEP 网络。

我们选择目标网络并在下方的窗格中查看其详细信息。在底部是攻击面板，我们可以选择针对网络执行哪种攻击。在本例中，我们在左侧选择**分段攻击**选项，然后在右上角点击**Wi-Fi 攻击**：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_17.jpg)

攻击面板显示攻击的进展，捕获的 IVs 数量在增加：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_18.jpg)

最后，程序会在窗口底部返回破解的密钥（十六进制）。我们可以右键单击它并复制密钥或转换为 ASCII 文本：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_20.jpg)

完成后，攻击面板将显示 ASCII 密钥如下：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_21.jpg)

在主窗口中，我们可以看到**密钥数据库**条目已填充了我们恢复的密钥：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_22.jpg)

确实，在完成攻击后，破解的密钥将保存在 SQLite 数据库中，我们可以通过点击**密钥数据库**按钮查看其详细信息：

![使用 Fern WiFi Cracker 进行 WEP 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_04_23.jpg)

# 总结

在本章中，我们介绍了 WEP 协议、已经开发出来用于破解密钥的攻击、Aircrack-ng 套件以及 Kali Linux 中包含的其他自动化工具来实施这些攻击。

在下一章中，我们将介绍 WPA/WPA2 协议以及用于攻击它的工具。


# 第五章：WPA/WPA2 破解

在这一章中，我们将研究**Wi-Fi 保护访问**（**WPA/WPA2**）协议，并了解恢复加密密钥的技术和工具。

涵盖的主题如下：

+   WPA/WPA2 简介

+   使用 Aircrack-ng 破解 WPA

+   使用 Cowpatty 破解 WPA

+   使用 GPU 破解 WPA

+   使用自动化工具破解 WPA

# WPA/WPA2 简介

WPA/WPA2 是由 Wi-Fi 联盟开发的安全协议的两个不同版本，用于替代 WEP 作为 802.11 协议的安全标准。WPA 协议首次发布于 2003 年，随后在 2004 年作为 IEEE 802.11i 标准的一部分被其后继者 WPA2 取代。WPA 和 WPA2 都支持两种认证模式：**WPA-Personal**和**WPA-Enterprise**。在 WPA-Personal 模式中，使用**预共享密钥**（**PSK**）进行认证，无需认证服务器。PSK 可以是 8 到 63 个可打印 ASCII 字符的密码。而 WPA-Enterprise 模式需要一个认证服务器，该服务器使用 RADIUS 协议与接入点（AP）通信，并使用**可扩展认证协议**（**EAP**）对客户端进行认证。我们将在第六章中详细介绍对 WPA-Enterprise 的攻击，*攻击接入点和基础设施*。

在这一章中，我们将专注于攻击 WPA-Personal 认证。WPA-Personal 和 WPA-Enterprise 在 AP 和客户端（下图中的 STA）之间共享认证过程，这被称为**四路握手**。

![WPA/WPA2 简介](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_01.jpg)

认证过程的四个阶段如下：

+   在第一阶段，双方独立建立了一个 256 位的**对等主密钥**（**PMK**）。它是从 PSK 和网络 SSID 生成的。然后 AP 向客户端发送一个随机数，**A-Nonce**。

+   客户端向 AP 发送一个随机的**S-Nonce**，加上一个**消息完整性代码**（**MIC**）。同时，客户端计算一个将用于加密流量的**对等瞬态密钥**（**PTK**）。 PTK 是从 PMK、A-Nonce、S-Nonce 以及客户端和 AP 的 MAC 地址派生出来的。

+   AP 自己派生 PTK，然后发送**组临时密钥**（**GTK**）给客户端，用于解密多播和广播流量，以及一个 MIC。

+   客户端向 AP 发送确认。

分析四路握手，我们可以注意到，与 WEP 不同，加密密钥（PTK）是唯一的，因为它是与握手过程相关的参数的函数，从不在 AP 和客户端之间交换。WPA 使用由 Wi-Fi 联盟开发的**临时密钥完整性协议**（**TKIP**）加密协议，用于临时替代 WEP 加密，但也发现了一些漏洞，并在 802.11 标准的最新版本中已被弃用。

WPA2 默认使用**CCMP**（**计数器密码模式协议**），这是一种基于**高级加密标准**（**AES**）的协议，AES 是事实上的标准对称加密算法。

要了解 WPA/WPA2 实施的细节和我们将在下一节中涵盖的攻击，请参考附录中的链接，*参考资料*。

## 攻击 WPA

WPA/WPA2 协议（以下简称 WPA）被认为是安全的，因为它依赖于强大的认证和加密协议，特别是使用 AES-CCMP 的 WPA2。接下来，我们将展示只有在使用弱 PSK 时才会有漏洞。

TKIP 已被证明容易受到攻击，可能导致数据包解密和注入，但不能恢复 PSK。对于 PSK 破解，我们需要捕获四次握手帧，这些帧给出了计算 PTK 所需的所有参数，包括用于检查我们的候选密钥是否正确的 MIC。

一旦我们有了捕获的数据包文件，我们可以尝试通过对其进行离线*暴力破解攻击*或*字典攻击*来破解密钥。暴力破解攻击意味着检查整个密钥空间，即可能形成密钥的所有可能字符组合。要可行，PSK 必须很短。否则，一个强大的 PSK 将需要很长时间才能被破解。

要有一个大致的时间估计，我们需要通过在线可用的暴力破解计算器之一来估算，例如[`calc.opensecurityresearch.com/`](http://calc.opensecurityresearch.com/)上的计算器。假设我们可以每秒测试 100,000 个密钥，这是一个相当高的速率，密钥的字符集是字母数字组合，我们可能会惊讶地发现破解一个 8 个字符长的密钥所需的时间：

![攻击 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_02.jpg)

对于一个 63 个字符长的密钥，这是相当令人泄气的：

![攻击 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_03.jpg)

在字典攻击中，我们需要测试字典文件或单词列表中包含的所有单词。要成功，密钥必须包含在使用的单词列表中。

有一些技术可以加快破解过程。对于字典攻击，一种技术是使用预先计算的哈希列表（或表），也称为*彩虹表*，而不是使用单词列表。通过这种方式，我们可以从字典文件的单词预先计算 PMK 并将其存储在彩虹表中。缺点是每个网络 ESSID 都需要其彩虹表，因为 PMK 也取决于 ESSID，并且需要大量的磁盘空间。

加速这个过程的另一种技术是利用最近视频卡的**图形处理单元**（**GPU**）的计算能力。

我们将在本章后面看到如何利用 GPU 破解 WPA 密钥。

### 注意

**使用 Amazon Linux AMI 破解 WPA**

破解 WPA 密钥的一个有趣且相对新的方法是使用启用了 NVIDIA GRID GPU 驱动程序的 Amazon Linux AMI，由 Amazon EC2 提供。AMI（Amazon Machine Image）允许利用 NVIDIA GPU 的处理能力，具有 1,536 个 CUDA 核心和 4GB 视频内存。有关更多信息，请阅读[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/using_cluster_computing.html`](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using_cluster_computing.html)上提供的指南。

还有在线的基于云的服务，可以在支付费用后，只需提供四次握手文件和网络 SSID 即可破解 WPA/WPA2 密钥。

这种服务的一个例子是 CloudCracker - [`www.cloudcracker.com/`](https://www.cloudcracker.com/)。

在接下来的章节中，我们将介绍使用 Aircrack-ng 套件和 Cowpatty 破解 WPA PSK 的过程。

## 使用 Aircrack-ng 破解 WPA

在前一节中，我们提到要破解 WPA 密钥，我们必须首先捕获与目标 AP 和客户端之间的 WPA 握手相关的四个帧。为此，我们可以被动地等待客户端成功进行身份验证，完成握手，并捕获相关的帧。在某些情况下，我们需要等待更长的时间，因此我们可以通过对已连接的客户端进行去认证，诱使其重新与 AP 进行身份验证（*去认证攻击*）来加快这个过程。

我们首先使用`airmon-ng start wlan0`命令将无线接口设置为监视模式，然后使用目标 AP 的 BSSID 和信道作为参数运行`airodump-ng`：

```
airodump-ng --channel 1 --bssid 08:7A:4C:83:0C:E0 --write wpa_crack mon0

```

![使用 Aircrack-ng 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_04.jpg)

当客户端向 AP 进行身份验证时，airodump-ng 输出的第一行显示发生的 WPA 握手。在这种情况下，airodump-ng 将捕获的握手保存在`wpa_crack`文件中。

如果没有发生握手，但是客户端已经连接，并且我们离它不太远，我们可以使用以下命令从 AP 中去认证它： 

```
aireplay-ng --deauth 1 -c 98:52:B1:3B:32:58 -a 08:7A:4C:83:0C:E0 mon0

```

在这里，`--deauth`（或-0）是用于去认证攻击的，`1`代表要发送的一组帧，`-c`是客户端的 MAC 地址，`-a`是 AP 的 MAC 地址。

![使用 Aircrack-ng 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_05.jpg)

如果攻击成功，我们应该在短时间内看到客户端重新连接，然后我们可以捕获 WPA 握手。

一旦我们捕获了握手，我们就可以使用 aircrack-ng 来破解密钥，指定要使用的字典文件或单词列表。只有在字典文件中存在时，aircrack-ng 才能找到 WPA PSK。

在网上有很多单词列表可用，其中一些列在[`www.aircrack-ng.org/doku.php?id=faq#where_can_i_find_good_wordlists`](http://www.aircrack-ng.org/doku.php?id=faq#where_can_i_find_good_wordlists)上。

Wordlists 也默认包含在 Kali Linux 中，位于`/usr/share/wordlists`下，`rockyou.txt.gz`文件提供了一个大型压缩的单词列表供使用。

可以使用**crunch**工具创建自定义单词列表（键入`man crunch`查看手册页）。

对于我们的示例，我们使用`rockyou.txt.gz`单词列表，因此我们首先解压缩它：

```
gunzip rockyou.txt.gz

```

为了减少尝试的单词数量，我们必须考虑 PSK 由最少 8 个字符和最多 63 个字符组成。因此，我们可以从`rockyou.txt`中创建一个符合这些要求的新单词列表。一个允许您过滤和减少单词列表的工具是**pw-inspector**。

我们通过将`rockyou.txt`作为输入传递给 pw-inspector 来创建新的单词列表`wparockyou.txt`：

```
cat rockyou.txt | sort | uniq | pw-inspector -m 8 -M 63 > wparockyou.txt

```

然后我们执行使用`aircrack-ng`的字典攻击：

```
aircrack-ng -w wparockyou.txt wpa_crack-01.cap

```

![使用 Aircrack-ng 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_06.jpg)

经过一段时间后，如果在使用的单词列表中找到了密钥，aircrack-ng 会在输出中返回它，以及经过的时间，测试的密钥数量和测试速度，如我们在下面的截图中所看到的：

![使用 Aircrack-ng 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_07.jpg)

如果我们想使用彩虹表进行字典攻击，我们可以使用`airolib-ng`工具创建网络 ESSIDs 的数据库和相关的预先计算的 PMKs。

为了创建我们目标网络的数据库`wpa_db`，我们运行以下命令：

```
airolib-ng wpa_db --import essid InfostradaWiFi-201198

```

然后导入我们之前使用的字典文件：

```
airolib-ng wpa_db --import passwd wparockyou.txt

```

在继续计算 PMK 之前，建议清理和优化数据库：

```
airolib-ng wpa_db --clean all

```

![使用 Aircrack-ng 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_08.jpg)

接下来，我们使用以下命令计算 PMKs：

```
airolib-ng wpa_db -batch

```

最后，我们可以在数据库上执行`aircrack-ng`：

```
aircrack-ng -r wpa_db wpa_crack-01.cap

```

## 使用 Cowpatty 破解 WPA

作为 aircrack-ng 的替代品，Cowpatty 是一种易于使用且有效的 WPA PSK 破解工具，由**Joshua Wright**开发。

它的使用方式与 aircrack-ng 非常相似，因为它接受包含四次握手和单词列表的数据包捕获，以及网络 ESSID：

```
cowpatty -f wparockyou.txt -r wpa_crack-01.cap -s InfostradaWiFi-201198

```

![使用 Cowpatty 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_09.jpg)

正如我们在下面的截图中所看到的，破解的 PSK 显示在输出中。Cowpatty 像 aircrack-ng 一样，还显示了经过的时间，测试的密码数量和速率：

![使用 Cowpatty 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_10.jpg)

Cowpatty 也可以将彩虹表作为输入。要从我们的单词列表中构建它，我们使用`genpmk`工具，执行以下命令：

```
genpmk -f wparockyou.txt -d hash_table -s InfostradaWiFi-201198

```

![使用 Cowpatty 破解 WPA](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_11.jpg)

然后，我们启动程序，指定彩虹表而不是单词列表的`-d`选项：

```
cowpatty -d hash_table -r wpa_crack-01.cap -s InfostradaWiFi-201198

```

# 使用 GPU 破解 WPA

最近视频卡的 GPU 通常包括大量的核心，可以同时执行线程，从而比 CPU 更快地执行复杂的计算。

要适用于**通用目的计算**（**GPGPU**），GPU 必须支持 NVIDIA **Compute Unified Device Architecture**（**CUDA**）或**Open Computing Language**（**OpenCL**）平台，这允许普通程序在执行指定代码部分时访问和利用 GPU 的硬件。

Kali Linux 中包含的两个最受欢迎的程序，可以利用 GPU 来破解密码，分别是**Pyrit**和**oclHashcat**。

### 注意

**准备进行 GPU 破解**

首先值得指出的是，基于 GPU 的破解工具无法在虚拟机中运行，因为它们需要直接访问物理视频卡。因此，我们需要在 Kali Linux 的本机安装中运行它们。

要进行 GPU 破解，我们首先需要检查视频卡的正确驱动程序是否已安装。如果要使用 CUDA 或 OpenCL，我们必须安装相应的专有驱动程序（NVIDIA 或 AMD/ATI）。

NVIDIA 卡的有用参考资料是[`docs.kali.org/general-use/install-nvidia-drivers-on-kali-linux`](http://docs.kali.org/general-use/install-nvidia-drivers-on-kali-linux)，而对于 AMD/ATI 卡，以下帖子可能有所帮助[`forums.kali.org/showthread.php?17681-Install-AMD-ATI-Driver-in-Kali-Linux-1-x`](https://forums.kali.org/showthread.php?17681-Install-AMD-ATI-Driver-in-Kali-Linux-1-x)。

我们还需要安装 NVIDIA CUDA 工具包或 AMD APP SDK（参见附录，*参考资料*）。

## Pyrit

Pyrit 是用 Python 编写的工具，支持 CPU 和 GPU 破解，后者通过 CUDA 和 OpenCL 模块。使用最新的视频卡，Pyrit 能够每秒计算高达 100,000 个**PMKs**（**Pairwise Master Keys**），与仅依靠 CPU 相比，大大加快了破解过程。

Pyrit 的工作方式是通过使用字典文件作为输入，就像 aircrack-ng 一样，或者使用预先计算的 PMKs 数据库来破解我们目标 ESSID 的密码。

后一种方法速度更快，但需要您事先创建数据库或使用预先构建的数据库。

在第一种情况下，启动的命令如下：

```
pyrit -r wpa_crack-01.cap -i wparockyou.txt attack_passthrough

```

![Pyrit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_12.jpg)

这里，`attack_passthrough`指定了使用字典文件的攻击，`-r`指定了数据包捕获，`-i`指定了要使用的单词列表。

在第二种情况下，当使用数据库时，我们首先将 ESSID 添加到数据库中：

```
pyrit -e InfostradaWiFi-201198 create_essid

```

现在，我们将字典文件导入数据库：

```
pyrit -i wparockyou.txt import_passwords

```

![Pyrit](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_13.jpg)

然后，我们使用以下命令从相关密码计算 PMKs：

```
pyrit batch

```

最后，我们可以运行破解过程：

```
pyrit -r wpa_crack-01.cap attack_db

```

## oclHashcat

oclHashcat 工具是一个强大的基于 GPGPU 的多哈希破解工具，支持 CUDA 和 OpenCL API。

OclHashcat 是流行的**Hashcat**工具的 GPGPU 版本，它是以前版本*oclHashcat-plus*和*oclHashcat-lite*的融合。它支持许多哈希算法攻击，其中包括字典和暴力攻击。

OclHashcat 不接受以`.cap`格式的数据包捕获，而必须将其转换为自己的格式`.hccap`。为此，我们可以使用 aircrack-ng：

```
aircrack-ng wpa_crack-01.cap -J wpa_crack-01.hccap

```

要对捕获的握手进行字典攻击，使用以下命令：

```
oclHashcat -m 2500 wpa_crack-01.hccap wparockyou.txt

```

这里，`-m 2500`指定了 WPA 攻击模式。

例如，要对由四个小写字母和四个数字组成的八个字符 PSK 进行暴力破解攻击，我们需要运行以下命令：

```
oclHashcat -m 2500 -a 3 wpa_crack-01.hccap ?l?l?l?l?d?d?d?d

```

实际上，oclHashcat 有自己内置的字符集，我们可以用它来定义掩码，即配置我们想要破解的密码的密钥空间的字符串。

# 使用自动化工具进行 WPA 破解

在最后一章中，我们介绍了两个自动化工具来破解 WEP（以及 WPA）密钥：Wifite 和 Fern WiFi Cracker。

在上一章中，我们展示了使用 Fern WiFi Cracker 进行 WEP 破解的实际示例；在本章中，我们将看到如何使用 Wifite 破解 WPA 密钥。

## Wifite

正如我们已经看到的，Wifite 是基于 Aircrack-ng 套件的工具。默认情况下，它依赖于 aircrack-ng 进行 WPA 破解，但也支持 Cowpatty、Pyrit 和 oclHashcat。

要破解 WPA 密钥，我们将运行以下命令：

```
wifite -wpa -dict wparockyou.txt

```

![Wifite](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_14.jpg)

程序扫描 WPA 无线网络并显示结果：

![Wifite](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_15.jpg)

当我们确定了目标网络后，我们按下*Ctrl* + *C*并选择网络（在本例中是数字`1`）：

![Wifite](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_16.jpg)

Wifite 开始监听以捕获 WPA 握手。

之后，程序开始使用先前提供的字典文件进行破解过程：

![Wifite](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_17.jpg)

最后，它返回破解的密钥并显示其他相关信息，就像 aircrack-ng 一样（经过的时间，测试的密钥数量和速率）：

![Wifite](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_05_18.jpg)

如果没有捕获到握手，Wifite 会尝试取消连接的客户端，自动执行 aireplay-ng 执行的取消认证攻击。

我们还可以选择使用其他工具来破解密钥，而不是 aircrack-ng，指定相关选项（例如，Pyrit 或 Cowpatty）。

# 摘要

在本章中，我们已经介绍了 WPA/WPA2 安全协议，并分析了如何捕获 WPA 四路握手并使用 Kali Linux 上可用的许多工具来破解 PSK。

还有一种针对**Wi-Fi Protected Setup**（**WPS**）部署的攻击，可以在相对较短的时间内导致 WPA PSK 恢复。我们将在第六章中涵盖这种攻击和其他针对接入点的攻击，*攻击接入点和基础设施*。


# 第六章：攻击接入点和基础设施

在第五章中，*WPA/WPA2 破解*，我们学习了如何在 WPA-Personal 模式下破解 WPA 预共享密钥。还有另一种恢复 PSK 的方法；攻击 AP 以利用**Wi-Fi Protected Setup**（**WPS**）中的缺陷。在本章中，我们将介绍这种攻击，针对 WPA-Enterprise 的攻击以及针对接入点和网络基础设施的其他攻击，解释 Kali Linux 中用于进行此类攻击的技术和工具。

我们将要涵盖的主题是：

+   针对 Wi-Fi Protected Setup 的攻击

+   攻击 WPA-Enterprise

+   拒绝服务攻击

+   Rogue 接入点

+   攻击 AP 认证凭据

# 针对 Wi-Fi Protected Setup 的攻击

WPS 是由 Wi-Fi 联盟于 2006 年引入的用于接入点的安全机制，允许客户端通过提供八位数字 PIN 而不是预共享密钥更轻松地连接到无线网络。如果 PIN 正确，AP 将向客户端提供 WPA PSK 以进行网络认证。

WPS 规范还支持**Push-Button-Connect**（**PBC**）方法，其中在 AP 和客户端设备上都按下按钮以开始连接。

2011 年，两位研究人员 Stefan Viehböck 和 Craig Heffner 分别发现了 WPS 中的一个漏洞，可以允许攻击者通过暴力攻击在几小时内恢复 PIN 并访问网络。Heffner 还开发并发布了一个实现此攻击的工具**Reaver**。

漏洞存在于 AP 检查 PIN 的方式中。事实上，八位数字 PIN 并没有完整地发送到 AP，而是只发送和检查前半部分，然后，如果正确，发送和验证后半部分。如果前半部分不正确，AP 会向客户端发送负面响应。因此，AP 独立地检查 PIN 的两个部分。

此外，PIN 的最后一位是其他七位数字的校验和，因此可以从中推导出来。

以这种方式，攻击者可以尝试猜测 PIN 的前四位数字，最多尝试*10⁴ = 10,000*个值，然后再尝试后半部分，最多*10³ = 1,000*个可能性，总共有 11,000 个可能值，而整个 PIN 有*10⁷ = 10,000,000*个可能的组合。这在暴力攻击中产生了很大的差异，大大减少了执行所需的时间。

WPS 可以在接入点的管理面板中禁用。在这种情况下，我们启用它，保留 AP 的预配置 PIN，以演示攻击的工作原理，如下面的屏幕截图所示：

![针对 Wi-Fi Protected Setup 的攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_01.jpg)

最近的 AP 型号在尝试猜测 PIN 的次数达到一定数量后会实施锁定机制。

另一种针对 WPS 的攻击，**Pixie Dust**攻击，是由 Dominique Bongard 在 2014 年引入的。这是一种*离线*暴力攻击，用于恢复 PIN，而之前由 Reaver 实施的攻击是一种不断与 AP 交互的在线攻击。

Pixie Dust 攻击极大地提高了 WPS PIN 恢复过程的速度，在最坏的情况下将所需的时间减少到几秒或几分钟。

攻击的技术细节可以在[`archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf`](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf)找到。

一种名为**Pixiewps**的用 C 编写的工具已经开发出来，作为演示 Pixie Dust 攻击的概念验证代码。这个工具已经集成到 Reaver 的社区分支版本 reaver-wps-fork-t6x 中，以支持这种新的攻击。

并非所有 AP 都容易受到攻击；易受攻击的 AP 型号数据库可在[`docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit#gid=2048815923`](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit#gid=2048815923)找到。

在下一小节中，我们将看到如何使用 Reaver 来恢复 WPS PIN，包括在线和离线两种暴力破解攻击。

## Reaver

Reaver 是一个可以暴力破解 WPS PIN 的命令行工具。在启动程序之前，我们必须确定我们的目标，即启用了 WPS 并且没有针对暴力破解攻击进行锁定的接入点。这就是一个名为**Wash**的工具派上用场的地方，它是 Reaver 捆绑的 WPS 扫描程序。

执行在线暴力破解攻击的步骤是：

1.  首先，我们需要将无线接口置于监视模式，使用以下命令：

```
airmon-ng start wlan0

```

1.  要扫描启用了 WPS 的 AP，我们执行以下命令：

```
wash -i mon0 -C

```

![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_02.jpg)

Wash 显示了有关检测到的 AP 的信息，如 BSSID、信道、使用的 WPS 版本、WPS 是否被锁定以及 ESSID。

1.  我们选择目标 AP 并运行 Reaver 来恢复 WPS PIN：

```
reaver -i mon0 -b 08:7A:4C:83:0C:E0

```

这里，`-b`选项指定了 AP 的 MAC 地址。

![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_03.jpg)

Reaver 尝试每个 PIN 的可能组合并等待响应，因此通常需要几个小时才能完成攻击，即使 PIN 的可能组合并不多。

要执行离线 Pixie Dust 攻击，我们必须使用 reaver-wps-fork-t6x 版本，对应于 Reaver 的 1.5.2 版本。这个版本需要 Pixiewps，建议升级到最新版本（写作时）的 Aircrack-ng，即 1.2 RC2。更新的 Reaver、pixiewps 和更新的 Aircrack-ng 都可以在 Kali Linux 存储库中找到。

我们按照以下步骤进行：

1.  我们使用以下命令升级软件：

```
apt-get install aircrack-ng reaver

```

注意，pixiewps 也作为一个依赖项安装。

![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_04.jpg)

1.  然后我们使用`airmon-ng start wlan0`将无线接口置于监视模式：![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_05.jpg)

我们可以观察到虚拟监视接口的名称是`wlanXmon`，而不是新版本的 Aircrack-ng 中的`monX`。

1.  要执行攻击，我们运行以下命令：

```
reaver -i wlan0mon -b 08:7A:4C:83:0C:E0 -vvv -K 1

```

这里的`-i`选项指定了我们的监视接口，`-b`指定了 AP 的 MAC 地址，`-vvv`是最详细的输出模式，`-K 1`指定了 Pixie Dust 攻击。

![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_06.jpg)

在下面的截图中，我们注意到 pixiewps 被调用并立即发现 PIN：

![Reaver](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_07.jpg)

Pixie Dust 攻击展示了如何轻松快速地恢复 WPS PIN，因此强烈建议禁用 WPS。

# 攻击 WPA-Enterprise

WPA-Enterprise，顾名思义，是企业网络中使用的认证模式。

在 WPA-Enterprise 中，AP 不像 WPA-Personal 模式那样对客户端进行认证，而是委托给一个通过 RADIUS 协议与 AP 通信的**认证服务器**（**AS**）。

AP 和 AS 之间交换的认证数据包使用**可扩展认证协议**（**EAP**）和特别是**EAP Over LAN**（**EAPOL**）进行传输，EAPOL 是 802.1x 标准中定义的用于有线局域网认证的协议。AP（认证器）充当中继，转发两方之间的认证数据包，即客户端（请求者）和 AS。

EAP 是一个认证框架，而不是单一协议，有许多类型，其中最重要的是：

+   **轻量级 EAP**（**LEAP**）

+   EAP-MD5

+   EAP-TLS

+   EAP-FAST

+   EAP-TTLS

+   PEAP

最后三个是企业网络中使用的最常见的 EAP 类型。认证过程通过 EAP 握手进行，如下图所示的 EAP-TLS：

![攻击 WPA-Enterprise](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_08.jpg)

LEAP 和 EAP-MD5 已经被弃用，因为它们容易受到暴力和字典攻击的影响，并且不验证认证服务器的证书。

LEAP 基于 MS-CHAPv2，这是一种挑战-响应协议，以明文形式传输认证数据，允许攻击者检索并发动暴力攻击以获取凭据。

EAP-MD5 也容易受到离线字典和暴力攻击的影响。

EAP-TLS 是最初的 WPA-Enterprise 标准认证协议，因为它依赖于**传输层安全性**（**TLS**），所以它是安全的。除了服务器端证书外，TLS 还需要客户端证书验证，因此组织需要部署**公钥基础设施**（**PKI**）来管理用户的证书。

这阻止了 EAP-TLS 在 WPA-Enterprise 实现中变得普遍，为 EAP-FAST、EAP-TTLS 和尤其是 PEAP 的采用留下了空间，这些协议不需要验证客户端的证书，但仍然安全，因为它们基于 TLS。

事实上，这些协议使用 TLS 隧道封装内部认证协议。例如，在 Microsoft Windows 实现中，PEAP 使用 MS-CHAPv2，如 LEAP，但封装在 TLS 隧道中。

以下表总结了 EAP 认证类型及其主要特点：

![攻击 WPA-Enterprise](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_09.jpg)

在接下来的章节中，我们将看到对 WPA-Enterprise 的攻击的实际示例。

## 设置 WPA-Enterprise 网络

为了看到攻击是如何在实践中工作的，我们将不得不配置我们的接入点使用 WPA-Enterprise 并设置 RADIUS 服务器。

由于许多消费者 AP 不支持 WPA-Enterprise，并且设置 RADIUS 服务器是一项繁琐的操作，一个实际的解决方案是安装**hostapd-wpe**（**hostapd Wireless Pwnage Edition**），这是**hostapd**工具的补丁版本，允许我们在无线接口上创建虚拟 AP。

Hostapd-wpe 由 Joshua Wright（Cowpatty 的作者和其他无线安全工具）和 Brad Antoniewicz 开发，配备了捆绑的 FreeRADIUS-WPE 服务器，这是 FreeRADIUS 服务器的补丁，大大简化了其配置。

Hostapd-wpe 最近取代了 FreeRADIUS-WPE 项目本身。它没有预装在 Kali Linux 上，所以我们需要下载并安装它。

为了设置一个虚拟的 WPA-Enterprise 启用的 AP，我们将执行以下步骤：

1.  我们首先安装必要的库：

```
apt-get update; apt-get install libssl-dev libnl-dev

```

hostapd 的最新版本是 2.4，但我们必须下载并安装 2.2 版本，因为`hostapd-wpe`补丁只支持这个版本（在撰写本书时）。我们使用以下命令下载 hostapd：

```
wget http://w1.fi/releases/hostapd-2.2.tar.gz

```

1.  接下来，我们从其 Git 存储库下载`hostapd-wpe`补丁：

```
git clone https://github.com/OpenSecurityResearch/hostapd-wpe

```

1.  我们解压 hostapd tar 存档并进入提取的目录：

```
tar -xzf hostapd-2.2.tar.gz; cd hostapd-2.2

```

1.  现在，我们必须应用`hostapd-wpe`补丁：

```
patch -p1 < ../hostapd-wpe/hostapd-wpe.patch

```

1.  我们进入`hostapd`目录并编译：

```
cd hostapd; make

```

1.  编译完成后，我们进入`certificate`目录并运行引导脚本以生成自签名证书：

```
cd ../../hostapd-wpe/certs; ./bootstrap

```

1.  在执行`hostapd-wpe`之前，我们必须编辑其配置文件`hostapd-wpe.conf`，位于`hostapd-2.2/hostapd`目录中。我们必须在`# Interface`部分中设置`interface=wlan0`，在`#Driver`部分中注释掉`driver=wired`行，并取消注释`802.11 Options`，指定我们想要 AP 使用的 SSID。![设置 WPA-企业网络](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_10.jpg)

1.  一旦我们保存了配置文件，我们可以使用以下命令运行程序：

```
./hostapd-wpe hostapd-wpe.conf

```

![设置 WPA-企业网络](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_11.jpg)

现在我们已经设置好了我们的 WPA-企业网络，我们准备攻击 EAP。

## 针对 EAP 的攻击

要执行对 EAP 的攻击，我们执行以下步骤：

1.  首先，我们需要使用`airodump-ng`来捕获 EAP 握手，这与我们在上一章中捕获 WPA 四路握手的方式相同：

```
airodump-ng --channel <nr> --bssid <AP_MAC_ADDR> --write eap_crack mon0

```

1.  要攻击特定的 EAP 实现，我们必须确定正在使用的 EAP 类型。Airodump-ng 不会告诉我们 EAP 类型，因此我们必须使用 Wireshark 等数据包分析工具分析捕获的 EAP 握手数据包。

要运行它，我们导航到应用程序菜单，**Kali Linux** | **嗅探/欺骗** | **网络嗅探器** | **Wireshark**。

1.  我们打开我们的捕获文件，应该看到一个如下截图所示的窗口：![针对 EAP 的攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_12.jpg)

1.  我们使用表达式`eap`过滤数据包，只显示我们感兴趣的数据包：![针对 EAP 的攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_13.jpg)

1.  在数据包列表面板中向下滚动，我们会注意到**信息**列中的 EAP 握手数据包，如下截图所示：![针对 EAP 的攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_14.jpg)

1.  现在我们已经发现了 EAP 类型，接下来我们可以进行攻击。如果认证服务器使用 LEAP 或 EAP-MD5，那么我们可以使用两个分别实现这些攻击的工具：`asleap`和`eapmd5pass`，这两个工具都是由 Joshua Wright 开发的。

要使用 asleap，我们必须使用`genkeys`工具从字典文件生成哈希表：

```
genkeys -r wordlist.txt -f wordlist.hash -n wordlist.idx

```

然后，将哈希表和捕获文件一起传递给`asleap`：

```
asleap -r eap_crack-01.cap -f wordlist.hash -n wordlist.idx

```

`Eapmd5pass`的工作方式类似，它将捕获文件和字典文件作为输入参数。

只有当攻击者拥有客户端的私钥并且因此冒充客户端向认证服务器时，EAP-TLS 才会有漏洞。

如果客户端不验证认证服务器的证书，PEAP 和 EAP-TTLS 可能会受到攻击。攻击者可以建立一个假的 AP 并冒充合法的 AP，从而破坏 TLS 加密隧道，让他攻击内部认证协议。

在下一小节中，我们将以 PEAP 为例进行介绍，因为它是部署最广泛的 EAP 类型。

### 攻击 PEAP

在这个例子中，我们使用一个默认支持 PEAP 和 MS-CHAPv2 的 Windows 客户端机器。

1.  要连接到我们之前创建的虚拟 AP，我们必须在**控制面板** | **网络和互联网** | **网络和共享中心** | **管理无线网络**中手动添加一个无线连接。

我们选择**手动创建网络配置文件**，然后输入我们 AP 的 SSID（`hostapd-wpe`）作为网络名称，并选择**WPA-Enterprise**作为安全类型：

![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_15.jpg)

1.  在随后的窗口中，我们点击**更改连接**设置，然后点击**安全**选项卡和**设置…**：![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_16.jpg)

1.  我们取消选中**验证服务器证书**选项，以禁用客户端对服务器证书的验证：![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_17.jpg)

1.  我们将 EAP-MSCHAPv2 作为认证方法，点击**配置…**按钮，然后取消选中**Windows 域登录认证**选项。

1.  接下来，我们使用以下命令在 Kali Linux 机器上启动`hostapd-wpe`：

```
hostapd-wpe hostapd-wpe.conf

```

正如我们所见，这个命令启动了一个以`hostapd-wpe`作为 SSID 的 AP。

1.  我们将 Windows 客户端连接到`hostapd-wpe`网络，然后提示我们输入用户名和密码。在这种情况下，我们可以输入任何我们想要的凭据，只是为了演示攻击。这里的密码是`my_eap_password`：![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_18.jpg)

1.  在`hostapd-wpe`终端窗口日志中，我们可以观察到这个认证尝试，包括 MSCHAPv2 协议的挑战和响应：![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_19.jpg)

1.  这就是我们启动使用`asleap`进行离线字典攻击所需要的一切，通过使用`-C`和`-R`选项将挑战和响应传递给程序：

```
asleap -C 1d:cc:5d:7c:ba:7f:c3:dc -R f0:4d:32:1a:8e:c0:44:1e:e1:fa:07:e0:c0:6c:a3:23:8d:3b:96:52:55 :b2:5d:73 -W wordlist.txt

```

![攻击 PEAP](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_20.jpg)

# 拒绝服务攻击

无线网络可能会受到针对客户端和 AP 的**拒绝服务**（**DoS**）攻击。

通过不断发送广播去认证数据包来强制断开连接并阻止客户端重新连接，从而执行这种攻击。

使用`aireplay-ng`工具来完成这个任务，命令如下：

```
aireplay-ng --deauth 0 -a 08:7A:4C:83:0C:E0 mon0

```

![服务拒绝攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_21.jpg)

在这个命令中，`0`选项表示持续发送去认证数据包，只指定了 AP 的 MAC 地址，使用了`-a`选项。我们也可以针对单个无线客户端进行攻击，就像我们将在第七章中看到的那样，*无线客户端攻击*。

在下一小节中，我们将介绍另一个工具来对无线网络执行 DoS 攻击，MDK3。

## 使用 MDK3 进行 DoS 攻击

MDK3 支持以下模式来执行针对无线网络的 DoS 攻击：

+   信标（SSID）洪泛模式

+   认证 DoS

+   去认证/去关联（Amok）模式

在这里，`b`选项是信标洪泛模式，`-f`指定一个包含要用于 AP 的 SSID 名称列表的文件。如果未指定`-f`选项，则使用随机的 SSID。如果我们想使用特定的信道，我们需要使用`-c`选项：

要使用 MDK3，我们首先需要使用`airmon-ng start wlan0`命令将无线接口置于监视模式。

要运行信标洪泛攻击，我们执行以下命令：

```
mdk3 mon0 b -f SSIDs

```

在信标洪泛模式中，MDK3 发送一系列信标帧，广告虚假的 AP。这种方法主要不是为了 DoS 攻击而设计的，但有时可能会导致网络扫描程序和无线适配器的驱动程序崩溃，从而阻止客户端连接到网络。此外，它可以将合法的 AP 隐藏在众多的虚假 AP 中，最终具有非常相似的 SSID，使客户端难以识别他们想要连接的合法网络。

![使用 MDK3 进行 DoS 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_22.jpg)

认证洪泛模式意味着向 AP 发送许多认证请求，这可能会导致 AP 无法处理这些请求并因此冻结。这并不总是有效，可能需要多个 MDK3 实例才能成功执行此攻击。

在这种情况下，命令的语法很简单：

```
mdk3 mon0 a -a 08:7A:4C:83:0C:E0

```

这里`a`代表认证洪泛模式，`-a`指定目标 AP 的 MAC 地址：

![使用 MDK3 进行 DoS 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_23.jpg)

我们注意到目标 AP 似乎不容易受到这种攻击方法的影响。

DoS 攻击最有效的方法是去认证/去关联（Amok）模式，它发送去认证帧以断开客户端与 AP 的连接。要使用`mdk3`执行此攻击，我们首先将我们的目标 AP 的 MAC 地址保存在黑名单文件中。然后，我们运行以下命令：

```
mdk3 mon0 d -b blacklist_file

```

在这里，`d`显然是去认证/去关联模式，`-b`选项指定要使用的黑名单文件，这里只包含一个目标 AP：

![使用 MDK3 进行 DoS 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_24.jpg)

# Rogue 访问点

到目前为止，我们已经介绍了针对无线网络的未经身份验证的攻击，以破解 WEP 或 WPA 密钥，攻击 WPA-Enterprise，恢复 WPS PIN，并获得对这些网络的访问权限。

在这一部分，我们将介绍一种攻击，假设攻击者（内部人员或外部人员）正在控制已连接到有线 LAN 的机器：Rogue 访问点。

事实上，Rogue AP 是未经授权安装在 LAN 上的接入点，可以被攻击者用作网络的后门。

Rogue AP 可以通过物理方式或软件（软 AP）安装。物理 AP 的安装涉及违反网络的物理安全策略，更容易被识别。我们将看到如何安装一个 Rogue 软 AP 并将其桥接到有线 LAN。

我们可以使用`hostapd-wpe`来完成这个任务，但是这里我们使用 Aircrack-ng 套件中的一个工具`airbase-ng`。

我们使用 airmon-ng 将无线接口设置为监视模式，并运行以下命令：

```
airbase-ng --essid Rogue-AP -c 1 mon0

```

![恶意接入点](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_25.jpg)

我们注意到创建了一个 tap 接口`at0`。为了能够通信，我们必须在恶意 AP 和有线网络之间创建一个桥接，因此在`at0`和以太网（`eth0`）接口之间。

为此，我们安装`bridge-utils`实用程序：

```
apt-get install bridge-utils

```

我们使用名称`bridge-if`创建桥接接口：

```
brctl addbr bridge-if

```

然后，我们将`at0`和`eth0`接口连接到`bridge-if`：

```
brctl addif bridge-if eth0; brctl addif bridge-if at0

```

我们使用以下命令启动接口：

```
ifconfig eth0 0.0.0.0 up; ifconfig at0 0.0.0.0 up

```

我们还需要启用内核级 IP 转发，因为恶意 AP 充当无线和有线网络之间的路由器：

```
sysctl -w net.ipv4.ip_forward=1

```

否则，我们执行以下命令，具有相同的效果：

```
echo 1 > /proc/sys/net/ipv4/ip_forward

```

当客户端连接到恶意 AP 时，`airbase-ng`会在其日志中显示。

![恶意接入点](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_26.jpg)

运行`airodump-ng`，我们可以看到我们的恶意 AP 的详细信息：

![恶意接入点](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_27.jpg)

认证类型是开放的，因此没有认证和加密，通常恶意 AP 默认设置。这可以使 AP 很容易被检测到，因为开放的无线网络立即引起渗透测试人员或网络管理员的注意。

恶意 AP 也可以设置为使用 WEP 或 WPA/WPA2。例如，要使用 WPA2-CCMP 运行 AP，我们将执行以下命令：

```
airbase-ng --essid Rogue-AP -c 1 -Z 4 mon0

```

这里，`-Z`选项是用于 WPA2（`-z`用于 WPA），值`4`是用于 CCMP。

在下面的截图中，我们可以看到`airodump-ng`的输出：

![恶意接入点](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_06_28.jpg)

我们还可以通过使用`-X`选项而不是`–essid`选项来启动隐藏的恶意 AP，运行`airbase-ng`：

```
airbase-ng -X -c 1 mon0

```

恶意 AP 对网络安全构成严重威胁，因为它们允许未经授权访问网络，绕过防火墙和 IDS 等安全系统。事实上，连接到恶意 AP 的攻击者可以对本地网络、服务器和连接的客户端发动攻击。攻击者还可以创建一个恶意 AP 来冒充合法 AP，并对无线客户端进行中间人攻击，我们将在下一章中看到。

# 攻击 AP 身份验证凭据

家用路由器和 AP 提供了一个 Web 管理面板，用于配置通常无法从互联网访问但只能从本地网络访问的设备。

一个可能看起来是原子的安全方面，但通常不被认为足够重要的是默认的身份验证凭据。

通常的做法是不更改访问 AP 管理界面的默认用户名和密码，许多型号预先配置了诸如 admin/admin 之类的弱凭据。在网络上，可以找到带有相关默认凭据的 AP 和路由器型号列表。即使默认凭据被修改，通常也会选择弱密码。

这是一个严重的安全问题，因为如果攻击者控制了 AP，他/她可以通过在网络上执行中间人攻击、嗅探流量、更改 DNS 设置和发动药物和钓鱼攻击来危害整个网络。

可以用于破解 HTTP 身份验证凭据的工具是**hydra**，这是一个支持各种协议的在线密码破解工具。该程序还有一个 GUI 版本，名为 hydra-gtk。这两者都已安装在 Kali Linux 上。

Hydra 接受用户名或用户名列表和密码列表作为输入，并尝试所有可能的组合来攻击指定的目标。

要了解有关 Hydra 及其如何使用它来破解密码的更多信息，请参阅手册页面和项目网站[`www.thc.org/thc-hydra/`](https://www.thc.org/thc-hydra/)。

近年来，已经开发出了一些攻击，允许甚至从互联网访问路由器/AP 的管理面板。其中一个例子是**DNS 重绑定**攻击，攻击者滥用 DNS 向受害者的浏览器提供恶意的客户端脚本，针对内部网络。因此，浏览器对攻击者来说就像是内部代理，用来攻击和控制路由器/AP。这种类型的攻击在近年来变得广泛。

一个实施 DNS 重绑定攻击的工具被称为**rebind**，由 Craig Heffner 编写并包含在 Kali Linux 中。关于它的更多信息可以在程序网页[`code.google.com/p/rebind/`](https://code.google.com/p/rebind/)上找到。要了解攻击的细节，请阅读 Heffner 的白皮书*远程攻击 SOHO 路由器*[`media.blackhat.com/bh-us-10/whitepapers/Heffner/BlackHat-USA-2010-Heffner-How-to-Hack-Millions-of-Routers-wp.pdf`](https://media.blackhat.com/bh-us-10/whitepapers/Heffner/BlackHat-USA-2010-Heffner-How-to-Hack-Millions-of-Routers-wp.pdf)。

# 总结

在本章中，我们已经涵盖了针对接入点和网络的攻击，特别是针对 WPS 和 WPA-Enterprise 的攻击，以及如何设置一个伪造的 AP，DoS 攻击和 AP 认证攻击。

在第七章*无线客户端攻击*中，我们将看到针对无线客户端的攻击，比如蜜罐和恶意双子 AP，Caffe Latte 和 Hirte 攻击，中间人攻击和客户端去认证。


# 第七章：无线客户端攻击

到目前为止，我们已经涵盖了针对 WEP 和 WPA/WPA2 协议、接入点和网络基础设施的攻击。在本章中，我们将讨论针对客户端的攻击，无论它们是否连接到 Wi-Fi 网络。本章将涵盖以下主题：

+   蜜罐接入点和 Evil Twin 攻击

+   中间人攻击

+   Caffe Latte 和 Hirte 攻击

+   无需 AP 即可破解 WPA 密钥

# 蜜罐接入点和 Evil Twin 攻击

在上一章中，我们已经看到了如何设置一个属于本地有线网络的恶意接入点。攻击者还可以设置一个看似合法但未连接到本地网络的假 AP。这种 AP 被称为**蜜罐**AP，因为它诱使客户端与其关联。模拟真实 AP 的蜜罐 AP，站在其附近，可用于进行所谓的**Evil Twin**攻击。事实上，蜜罐 AP 伪造了真实 AP 的 SSID（以及可能的 MAC 地址），在发送的信标帧中进行广告。无线客户端的操作系统通常会跟踪客户端过去连接过的网络。当客户端在这些网络的范围内且信号足够强时，客户端可以配置为自动连接到这些网络。因此，如果假 AP 比合法 AP 更接近客户端，因此其信号更强，那么前者就会胜过后者，客户端会连接到前者。

客户端无法对 AP 进行身份验证，因为 802.11 管理帧没有加密签名。使用 WEP 或 WPA-PSK 用于对客户端进行身份验证，并在关联发生后加密交换的数据，但不对服务器进行客户端身份验证。

即使启用了 WPA-Enterprise 的 AP 也可能受到这种攻击的影响，因为客户端通常配置为不检查认证服务器证书，正如我们在上一章中所看到的。

此外，这些证书与网络 SSID 没有紧密绑定，攻击者可以设置其认证服务器并向客户端呈现看似合法的证书。为此，攻击者可以注册一个类似于目标网络的域名，并从认证机构获取有效证书。

这种技术也被用于针对 WPA-Enterprise 网络的 Evil Twin 攻击的变种，该攻击在研究论文中有描述，可在[`seclab.ccs.neu.edu/static/publications/ndss2013wpa.pdf`](http://seclab.ccs.neu.edu/static/publications/ndss2013wpa.pdf)找到。

### 注意

**Multipot 攻击**

另一个有趣的 Evil Twin 攻击变种是所谓的 Multipot 攻击，由 K.N. Gopinath 在 2007 年的 Defcon 15 会议上提出，其中使用多个蜜罐 AP 来进行攻击。演示的相关白皮书和演示文稿（以及音频和视频）可在[`www.defcon.org/html/links/dc-archives/dc-15-archive.html#Gopinath`](https://www.defcon.org/html/links/dc-archives/dc-15-archive.html#Gopinath)上找到。

在下一小节中，我们将看到如何设置蜜罐 AP 并使用 aircrack-ng 套件进行 Evil Twin 攻击。

## 实践中的 Evil Twin 攻击

在创建蜜罐 AP 之前，我们假设已经进行了侦察阶段，并识别了连接的 AP 和客户端，遵循第三章中介绍的方法，*WLAN 侦察*。

一旦我们选择了要模拟的目标 AP，我们就在新的终端模拟器窗口中使用相同的 SSID 设置我们的蜜罐 AP，运行 airbase-ng：

```
airbase-ng --essid InfostradaWiFi-201198 -c 1 mon0

```

请注意，`--essid`选项定义了我们 AP 的 SSID，`-c`选项定义了它使用的信道。

![实践中的 Evil Twin 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_01.jpg)

在`airodump-ng`输出窗口中，我们可以看到我们的两个双胞胎 AP，具有相同的 SSID：

![实践中的恶意双胞胎攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_02.jpg)

我们可以通过使用的加密类型（虚假 AP 使用开放认证）、信道和其他字段（如信标和数据包传输）以及信号功率水平（`Pwr`）来区分它们。`Pwr`字段的较低负值意味着更高的信号水平。蜜罐 AP 的信号水平应该高于真实 AP 的信号水平，以吸引客户端连接。

如果当前没有客户端连接到合法的 AP，我们需要等待客户端连接到虚假 AP，同时相信连接到真实 AP。

如果客户端已经连接，我们可以使用`aireplay-ng`工具强制其从网络中注销：

```
aireplay-ng --deauth 0 -a 08:7A:4C:83:0C:E0 -c 00:17:C4:19:85:46 -- ignore-negative-one mon0

```

这个命令也可以用来对目标客户端进行 DoS 攻击：

![实践中的恶意双胞胎攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_03.jpg)

如果有更多的客户端连接，我们可以发送广播去认证数据包，将所有客户端从网络中断开：

```
aireplay-ng --deauth 0 -a 08:7A:4C:83:0C:E0 mon0

```

![实践中的恶意双胞胎攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_04.jpg)

在下面的屏幕截图中，我们可以看到客户端再次重新连接到蜜罐 AP，这意味着我们成功了：

![实践中的恶意双胞胎攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_05.jpg)

在接下来的部分，我们将看到如何对连接到蜜罐 AP 的客户端进行中间人攻击。

# 中间人攻击

**中间人**（**MITM**）攻击是一种攻击，攻击者在两个通信方之间插入自己，通常（但不一定）是客户端和服务器，并透明地中继交换的消息，使双方相信他们直接在交谈。

在我们的情况下，中间人攻击是一个蜜罐软件 AP，诱使客户端连接到它，相信它是合法的。这样，客户端发送和接收的所有网络流量都通过虚假 AP，并且攻击者可以窃听和操纵它，获取密码和敏感信息，更改数据，并劫持会话。

例如，攻击者可以使用网络嗅探器如 tcpdump、Wireshark 和**Ettercap**来窃听和嗅探流量。Ettercap 不仅是一个嗅探器，还是一个用于发动中间人攻击的工具，提供了 GUI 并支持许多网络协议。有关更多信息，请参阅附录，*参考资料*或手册页（`man ettercap`）。

典型的中间人攻击是通过 ARP 缓存投毒、DNS 欺骗和会话劫持进行的。例如，通过 DNS 欺骗，攻击者可以将用户重定向到一个克隆的网站，并欺骗他们输入他们的凭据。

此外，如果攻击者利用类似于 OpenSSL 中的 CVE-2014-0224 的漏洞或向客户端呈现一个虚假证书，即使客户端浏览器显示警告，也可以攻击 TLS 加密会话。

为了使蜜罐 AP 充当无线客户端和有线网络和/或互联网之间的路由器，我们必须创建一个桥接接口并启用 IP 转发，按照第六章中描述的相同过程，*攻击访问点和基础设施*，来设置一个恶意 AP。

Kali Linux 提供了许多用于进行中间人攻击的工具，如`arpspoof`、`dnsspoof`、`ettercap`、`burp suite`、`urlsnarf`、`driftnet`和`webmitm`。

Kali Linux 还提供了一个用于中间人攻击的全功能图形程序，名为**Ghost-phisher**。

## Ghost phisher

Ghost phisher 是一个用 Python 编写的 GUI 程序，提供各种功能来执行中间人攻击，包括设置蜜罐 AP 和虚假网络服务（HTTP、DNS 和 DHCP）、会话劫持、ARP 欺骗和密码收集。

该程序易于使用且直观。要启动它，我们在终端中执行 ghost-phisher 命令。程序窗口分为不同的选项卡，每个选项卡用于不同的功能，并且每个选项卡包括顶部的配置部分和底部的状态部分。

要执行中间人攻击，我们可以执行以下步骤：

1.  第一个选项卡窗口与虚假 AP 设置有关。在**无线接口**部分，我们可以选择要使用的接口，然后通过单击下面的**设置监视器**按钮将其置于监视模式：![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_06.jpg)

1.  在**访问点设置**中，我们为诱饵 AP 分配 SSID、有效的私有 IP 地址（例如 192.168.0.1）、信道和加密类型。

然后，我们单击**开始**按钮，AP 正在运行，因为**状态**窗格向我们显示：

![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_07.jpg)

1.  然后，我们使用类 C 网络 IP 分配范围（在我们的情况下为 192.168.0.2 到 192.168.0.254）启动虚假 DHCP 服务器，将 AP（`192.168.0.1`）的 IP 设置为网关和虚假 DNS 服务器。因此，当客户端连接到 AP 时，它将被分配在此范围内的 IP 地址。![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_08.jpg)

1.  我们设置了一个虚假的 HTTP 服务器，用于托管合法网站的克隆页面，客户端打算登录，例如，访问他/她的在线银行账户。在这种情况下，我们可以指定客户端访问虚构网站`www.exampleonlinebank.com`时要显示的网页：![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_09.jpg)

1.  然后，是虚假 DNS 服务器的时间，它将此特定域的客户端查询解析为我们 AP 的 IP 地址。![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_10.jpg)

1.  点击**添加**按钮，使用虚假 AP（`192.168.0.1`）的 IP 地址来解析目标域`www.exampleonlinebank.com`。我们还可以将其他目标域名添加到此 IP 地址以及攻击者控制的主机的 IP 地址进行解析。![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_11.jpg)

1.  当客户端连接到上述网站时，它会看到一个伪造的登录页面，类似于合法网站上的页面：![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_12.jpg)

1.  用户输入的凭证被虚假 HTTP 服务器抓取，并显示在**收集的凭证**选项卡窗口中，如下面的屏幕截图所示：![Ghost phisher](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_13.jpg)

收集的凭证存储在 SQLite 数据库中，位于`/usr/share/ghost-phisher/Ghost-Phisher-Database`下。

这种攻击的另一个例子可能是为真实 AP 的 Web 管理面板设置一个虚假的身份验证页面，以便连接到虚假 AP 的网络管理员被重定向到此页面并透露身份验证凭据。

值得强调的是，这些攻击以及书中描述的所有攻击，如果未经网络所有者的书面和明确许可，都是非法的！

# Caffe Latte 攻击

在第四章中，*WEP 破解*，我们介绍了当客户端连接到 AP 时如何破解 WEP 密钥，注入 ARP 请求数据包并捕获生成的流量以收集一致数量的 IV，然后发起统计攻击来破解密钥。

两位无线安全研究人员 Vivek Ramachandran 和 MD Sohail Ahmad 在 Toorcon 2007 会议上提出了一种名为**Caffe Latte**的新攻击，允许您即使客户端未连接并且远离网络，也可以检索 WEP 密钥。

这种攻击被命名为 Caffe Latte，因为作者证明完成它所需的时间（几乎）与在咖啡店或餐厅喝一杯咖啡的时间一样短（这两个地方是这种攻击的经典场所）！

要执行攻击，我们必须诱使孤立的客户端生成足够的加密 WEP 数据包。诸如 Windows 之类的操作系统会将 WEP 共享密钥与相关网络详细信息一起缓存到**首选网络列表**（**PNL**）中，以便自动连接到这些网络。

客户端发送对其 PNL 中网络的探测请求。如果我们嗅探这些探测请求，我们可以确定网络的 SSID，并设置一个具有相同 SSID 的虚假 AP，向客户端发送探测响应。即使后者不知道密钥，客户端也会与此 AP 关联，因为 WEP 协议不要求 AP 对客户端进行身份验证。

一旦客户端关联，它将被分配一个 IP 地址，可以是静态分配或通过 DHCP 动态分配。如果没有 DHCP 服务器或者服务器未能响应，Windows 会为客户端分配一个来自 169.254.0.0/16 子网范围的 IP 地址。客户端开始发送一些伪造的 ARP 数据包，显然是使用 WEP 密钥加密的。为了破解密钥，我们需要强制客户端持续发送这些数据包，直到我们收集到足够数量的数据包（对于 PTW 攻击大约为 80,000 个）。一种做法是反复取消客户端的认证，但这需要相当长的时间。

Caffe Latte 攻击提供了一个更有效的解决方案，捕获这些伪造的 ARP 数据包，并翻转适当的位以修改数据包中固定位置的发送者 MAC 和 IP 地址。

这些伪造的 ARP 数据包被转换为 ARP 请求，不断地发送回客户端。这是可能的，因为 WEP 数据包的完整性没有得到加密保护，攻击者可以修改有效载荷和 CRC，从而创建一个仍然有效的加密数据包。

这样，客户端将响应这些 ARP 请求并快速生成流量，加快密钥破解过程。有关 Caffe Latte 攻击的更多细节，请参考附录中提供的链接，*参考资料*。

现在我们已经了解了攻击的理论，我们可以看看如何使用 aircrack-ng 套件来实现它，特别是使用 airbase-ng。

我们将接口设置为监视模式，并运行`airodump-ng mon0`来检测不在范围内的网络的探测请求。我们可以在 airodump-ng 输出的右下部分看到这些探测请求：

![Caffe Latte 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_14.jpg)

一旦目标网络的 SSID 被识别出来，我们就使用以下命令设置一个具有相同 SSID 的虚假 AP：

```
airbase-ng -c 1 -e Target_Network -F coffee -L -W 1 mon0

```

这里，`-L`选项是用于 Caffe Latte 攻击，`-W 1`允许我们在信标帧中指定 WEP 协议，`-F`将捕获的数据包写入指定的文件。

当客户端连接到虚假 AP 并开始发送伪造的 ARP 请求时，airbase-ng 启动 Caffe Latte 攻击。

![Caffe Latte 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_15.jpg)

当我们收集到足够数量的数据包时，我们可以运行 aircrack-ng 来破解 WEP 密钥：

```
aircrack-ng -e Target_Network coffee-01.cap

```

Caffe Latte 攻击的一个优化方案已经开发出来，即 Hirte 攻击。

# Hirte 攻击

Hirte 攻击扩展了 Caffe Latte 攻击，因为它还允许使用任何 IP 数据包，而不仅仅是从客户端收到的伪造 ARP 数据包。

通过位翻转这些数据包，我们生成 ARP 请求发送回客户端，然后执行攻击。与 Caffe Latte 的另一个不同之处在于，Hirte 还使用数据包分片将 ARP 请求发送到客户端。

关于这次攻击的更多技术细节可以在 Aircrack-ng Wiki 上找到，网址为[`www.aircrack-ng.org/doku.php?id=hirte`](http://www.aircrack-ng.org/doku.php?id=hirte)。

实际上，启动 Hirte 攻击几乎与启动 Caffe Latte 攻击相同；唯一的区别是使用特定于此攻击的`-N`选项，而不是`-L`选项：

```
airbase-ng -c 1 -e Target_Network -F hirte -N -W 1 mon0

```

![Hirte 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_16.jpg)

对于那些更喜欢使用图形化、自动化工具的人，Caffe Latte 和 Hirte 攻击都可以使用 Fern WiFi Cracker 来执行，我们在第四章中已经介绍过了。

这些攻击代表了停止使用 WEP 协议并采用 WPA2 的另一个理由（如果需要的话），尽管后者可能会受到类似的攻击。

# 在没有 AP 的情况下破解 WPA 密钥

Caffe Latte 和 Hirte 攻击允许我们在没有目标 AP 的情况下破解 WEP 密钥，攻击断开连接的客户端。

在本节中，我们将看到即使在这种情况下，破解 WPA 密钥也是可能的。

回想一下第五章中提到，要破解 WPA 密钥，我们必须捕获 WPA 四路握手以检索运行破解过程所需的所有参数：A-nonce、S-nonce、客户端、AP MAC 地址和 MIC（消息完整性检查）。

值得注意的是，不需要完成四路握手，因为所有这些参数在前两个数据包中交换，AP 不需要知道预共享密钥，如下图所示：

![在没有 AP 的情况下破解 WPA 密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_07_17.jpg)

因此，我们可以使用以下命令设置一个带有 WPA 协议和目标网络相同 SSID 的蜜罐 AP：

```
airbase-ng -c 1 -e Target_Network -F wpa -z 2 -W 1 mon0

```

这里，`-z`选项代表 WPA，值`2`代表 TKIP 加密。

如果我们想设置一个 WPA2-CCMP AP，命令将如下所示：

```
airbase-ng -c 1 -e Target_Network -F wpa -Z 4 -W 1 mon0

```

实际上，`-Z`选项表示 WPA2，`4`表示 CCMP 加密。

收集了握手参数后，我们按照第五章中描述的相同步骤，使用 aircrack-ng 来破解密钥。

显然，这种攻击提供了另一种破解 WPA 密钥的机会，因为它针对孤立的客户端，并且不需要捕获与 AP 的真实四路握手。

破解 WPA 密钥通常不像破解 WEP 密钥那么容易，但如果使用弱预共享密钥，可能会变得简单；因此，有必要使用强大的 WPA 密钥！

# 总结

在本章中，我们分析了针对无线客户端的最常见攻击，介绍了如何设置一个冒充合法 AP 并诱使客户端连接的蜜罐 AP（恶意双胞胎攻击）。我们还介绍了针对连接的客户端的 MITM 攻击以及在客户端与网络隔离时恢复 WPA 和 WEP 密钥的攻击（Caffe Latte 和 Hirte 攻击）。

下一章将涵盖报告阶段，展示如何撰写智能有效的渗透测试报告。


# 第八章：报告和结论

到目前为止，我们已经分析了无线渗透测试的规划、发现和攻击阶段。所有这些阶段同样重要，以实现准确可靠的结果，但需要完成最终阶段，即报告阶段。

在这个阶段，从渗透测试中出现的所有信息和发现都被收集并描述在一份报告中提交给客户。

本章涵盖的主题如下：

+   报告撰写的四个阶段

+   报告格式

在下一节中，我们将分析规划和撰写专业报告的过程。

# 报告撰写的四个阶段

报告阶段经常被低估其重要性，并被认为是渗透测试中沉闷但必要的部分。当然，发现和攻击阶段是核心和最激动人心的部分，因为在这个阶段，渗透测试人员的技术技能得以实践。渗透测试人员可能非常有技术，并且可能做得很出色，但如果他们在某种程度上未能有效地向客户传达他们的成就，那么他们的工作就是徒劳的。

撰写良好的报告是渗透测试人员必备的能力，几乎是一种艺术，就像所有技能一样，可以通过实践来提高。

撰写专业渗透测试报告的过程包括四个阶段：

+   报告规划

+   信息收集

+   撰写初稿

+   审查和最终确定

## 报告规划

在第一个阶段，即报告规划阶段，我们定义报告的目标、目标受众和内容，以及我们将花费在撰写报告上的预计时间。定义目标意味着解释为什么进行测试以及将从中获得的好处，帮助渗透测试人员和客户都专注于最重要的要点。报告的目标受众通常由组织/公司的管理层和高管以及 IT 经理和员工组成，特别是如果组织中有信息安全团队。根据受众类型，报告的布局和内容可以分为两个主要部分：**执行摘要**和**技术报告**。我们稍后将在相关专门部分中涵盖这两个部分。定义受众还意味着定义报告的分类和分发。一份文件的分类通常确定其机密级别，因此允许阅读它的人员。

分发是关于如何以安全的方式将其交付给正确的人员。例如，如果我们必须通过电子邮件发送报告，最好在加密消息中发送，使用公共加密工具，如 GnuPGP。事实上，渗透测试报告包含可能被用于攻击网络和组织系统的关键信息，如果落入错误的手中！

## 信息收集

在信息收集阶段，我们收集从先前的渗透测试阶段得出的所有结果和发现。

在渗透测试期间，记录和记录网络扫描和漏洞评估的结果、使用的工具和程序以及实施活动的有意义的截图是至关重要的。

在使用命令行工具时，将输出保存在文件中是一个好习惯。例如，发现阶段中使用的 airodump-ng 和 Kismet 都有选项将输出保存为文本可读格式，如 CSV 和 XML。

事实上，记录所有步骤也很重要，因为其他渗透测试人员或最终客户的 IT 人员必须能够重复这些步骤。

## 文档工具

Kali Linux 中有一些工具可帮助我们记笔记和记录渗透测试步骤。

其中一个是**KeepNote**，这是一个跨平台程序，用 Python 编写，支持笔记的分层组织，富文本格式和文件附件。以下是该程序的屏幕截图：

![文档工具](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_08_01.jpg)

另一个有用的文档工具是**Dradis**，这是一个专门用于安全评估的协作和信息共享的开源框架。Dradis 是一个独立的 Web 应用程序，提供了一个集中的信息存储库，在团队执行渗透测试时特别有用。

要执行 Dradis，从应用程序菜单中，导航到**Kali Linux** | **报告工具** | **文档** | **Dradis**。

相关服务已启动，并打开了一个浏览器窗口，连接到 URL `https://localhost:3004`，其中`3004`是 Dradis Web 服务器监听的默认端口。第一次运行程序时，需要设置我们将用于后续登录的密码：

![文档工具](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_08_02.jpg)

登录应用程序后，会显示以下界面：

![文档工具](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-wrls-pentest-ess/img/B04527_08_03.jpg)

Dradis 还可以生成 HTML 和 Word 格式的简单报告，可用于撰写完整报告。

更高级的报告功能，可以使用 Dradis 的专业版本。

通常用于终端工具的 Linux 用户可能会发现使用 Vim 或 Emacs 等编辑器以及使用 Markdown 或 reStructuredText 等纯文本标记语言编写文档更加方便。这些标记语言提供了一种易于使用、清晰且与格式无关的方式来生成文档，可以轻松导出为不同的格式，例如 PDF 和 HTML。

## 编写第一稿

在收集了发现和攻击阶段的信息后，下一步是撰写报告的第一稿。在这个阶段，我们以结构化的方式组织所有收集到的信息，并描述渗透测试期间执行的所有步骤。报告的撰写应该遵循一定的格式，我们将在本章后面看到。第一稿通常需要花费报告撰写时间的 60%。

## 审查和最终确定

最终阶段，审查和最终确定，是检查报告以纠正可能的错误和/或不准确之处，并进行专业编辑以满足客户的要求和标准。

如果报告是由单个渗透测试人员编写的，建议进行同行评审；而如果是由渗透测试团队编写的，所有团队成员都应该进行审查。

# 报告格式

在这一部分，我们描述了用于生成专业渗透测试报告的典型格式。

在撰写报告之前，我们必须选择文档的外观；标题和文本的字体和颜色，页边距，页眉和页脚内容等等。

报告通常以封面页开始，包含报告名称和版本、日期、服务提供商和组织名称。服务提供商是渗透测试人员或渗透测试团队。在后一种情况下，包括所有团队成员的姓名是一个良好的做法。

在封面页之后，如果报告超过几页，我们应该包括目录，列出报告的所有部分及其页码。

报告的内容可以分为两个主要部分：执行摘要和技术报告，正如我们之前所见。

## 执行摘要

执行摘要，顾名思义，是为客户组织的管理/高管而设计的，面向非技术人员。

摘要应该是对渗透测试的范围、目标和结果的高层次简洁概述，用清晰的语言表达，避免使用技术术语。

我们不需要提及使用的工具和技术，而应该专注于结果和状态，以查看被测试网络是否安全；我们应该描述安全性，即信息的保密性、完整性和可用性如何受到发现的问题的影响，以及应该采取什么措施来解决这些问题。

事实上，高管们对漏洞可能对他们业务的影响更感兴趣，而不是了解它们的技术细节。

## 技术报告

技术报告是针对 IT 经理和员工（通常是网络和系统管理员）以及信息安全经理和分析师（如果组织中有的话）。

技术报告部分通常以描述所采用的测试方法论开始，其中可能包括渗透测试人员拥有的认证、使用的软件类型（商业或开源）以及如何计算漏洞的风险评级。例如，评估漏洞严重程度的一个免费和开放的标准是**通用漏洞评分系统**（**CVSS**）。

在方法论部分之后，无线渗透测试报告通常包括检测到的网络和客户端的全面列表，按严重程度分组的检测到的漏洞摘要，以及每个漏洞的详细描述。

这个描述必须说明漏洞的来源、威胁级别、相关风险和被攻击者利用的可能性（概率）。描述使用的工具和命令也很重要。

描述应该以必须采取的对策结束，以纠正漏洞。

在我们的情况下，最常见的漏洞可能是配置为开放认证、WEP 或 WPA 弱密钥和启用 WPS、蜜罐和伪装接入点的无线网络。

建议按照严重程度递减的顺序呈现漏洞，即首先暴露最关键的漏洞，以更好地引起客户对必须紧急解决的问题的注意。

在描述渗透测试的发现时，可以适当地使用表格、图表和图表来使信息更清晰、更直观。例如，可以包括由 giskismet 生成的无线网络的图形地图，正如我们在第三章中所见的那样，*WLAN 侦察*。

技术报告可以以附录结束，包括一个参考部分，在那里作者引用外部来源（出版物、书籍、网站等），这些来源可能对观众更好地理解报告的内容有用。

报告阶段并不总是以报告的撰写结束，还包括向客户展示和解释报告。事实上，即使 IT 人员可能也没有充分理解报告内容的技术技能、背景和/或专业知识，因此可能需要渗透测试人员的一些解释。

在向高管呈现报告时，使用幻灯片或动画演示可能非常有用，也可以使用 Prezi 等基于云的软件制作。

在附录中，*参考资料*，有一些样本报告的参考资料，特别是关于无线渗透测试的（参见参考文献 8.4）。

# 总结

在本章中，我们已经涵盖了无线渗透测试的报告阶段，从报告规划到审查和最终确定，描述了专业报告的典型格式。

本章还强调了有效地向客户传达渗透测试工作的重要性，而一份写得好、呈现得好的报告无疑是最好的方式！

# 结论

我们已经到达了我们对无线渗透测试的旅程的结尾。这是一个非常令人兴奋的渗透测试领域，它正在迅速发展，并且由于无线网络的无处不在和移动设备的广泛增长，将来肯定会变得越来越重要。

学习和掌握 Kali Linux 用于无线渗透测试不仅为我们提供了一套很棒的工具，而且由于它们都是开源的，也给了我们理解它们实施逻辑和深入攻击的机会。
