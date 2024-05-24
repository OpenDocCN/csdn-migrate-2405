# Kali Linux 2018：通过渗透测试确保安全（一）

> 原文：[`annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A`](https://annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书现已出版第四版，使用了更新的 Kali Linux 2018 以及行业内专业渗透测试人员和安全专家使用的许多新工具。多年来，Kali Linux 已被证明是每个渗透测试人员的首选工具，本书通过实践实验室为读者提供深入的知识，让他们能够在一个安全的环境中深入了解渗透测试的领域。

# 这本书适合谁

本书面向渗透测试人员、道德黑客和具有 Unix/Linux 操作系统基础知识的 IT 安全专业人员。预期具备一定的信息安全概念的认识和知识。

# 要充分利用这本书

这本书涵盖了许多主题，尽管作者已经尽力解释这些主题，但读者可能希望复习一些关于网络和安全的基本主题，以更好地理解本书中教授的概念。

其中一些主题包括以下内容：

+   OSI 模型的七层

+   TCP/IP 套件

+   TCP 三次握手

+   协议和端口号

+   无线基础知识（802.11 a、b、g、n、ac）、WEP 和 WPA2

+   基本的 Linux 命令（包括`ls`、`cd`和`clear`）

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

任何命令行输入或输出都以以下形式书写：

```
Nmap 172.16.54.144 –sV 
```

**粗体**：表示一个新术语、一个重要词或者屏幕上显示的词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如：“从管理面板中选择系统信息。”

警告或重要说明会以这种形式出现。

技巧和窍门会以这种形式出现。


# 第一章：安装和配置 Kali Linux

本章将指导您了解专门用于渗透测试目的的 Kali Linux 2018.2 的精彩世界。在本章中，我们将涵盖以下主题：

+   Kali 的简要历史

+   Kali 的几个常见用途

+   下载和安装 Kali

+   配置和更新 Kali

# 技术要求

在本章和整本书中，读者将需要一台配备 6GB 或更多 RAM 的笔记本电脑或台式机，以及 100GB 硬盘空间，如果要将 Kali Linux 和测试实验室环境安装为虚拟机。如果要在闪存驱动器或 SD/micro-SD 卡上安装 Kali，最小存储空间应为 8GB（建议为 16GB 或更多）。读者还需要下载以下内容：

+   VirtualBox ([`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads))

+   Vmware Player ([`my.vmware.com/en/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/14_0`](https://my.vmware.com/en/web/vmware/free#desktop_end_user_computing/vmware_workstation_player/14_0))

+   Kali Linux ([`www.kali.org/downloads/`](https://www.kali.org/downloads/))

# Kali Linux 工具类别

截至目前，Kali Linux 的最新版本是 2018.2 版，发布于。正如官方网站[`bugs.kali.org/changelog_page.php`](https://bugs.kali.org/changelog_page.php)上所列出的，这个版本包括：

+   对 AMD GPU 的更好支持

+   针对 Spectre 和 Meltdown 漏洞的 x86 和 x64 架构修复

+   更容易访问 Metasploit，使用`metasploit-framework-4.16.34-0Kali2`和更新版本

+   更新工具，包括 Bloodhound v1.51、Reaver 1.6.4、PixieWPS 1.42、BurpSuite 1.7.32、Hashcat 4.0 等

+   Wpscan、Openvas、Xplico、Responder 和 Dradis 的改进

Kali Linux 包含许多工具，可在渗透测试过程中使用。Kali Linux 中包含的渗透测试工具可以分为以下几类：

+   信息收集：这个类别包含几个工具，可用于收集有关 DNS、IDS/IPS、网络扫描、操作系统、路由、SSL、SMB、VPN、VoIP、SNMP、电子邮件地址和 VPN 的信息。

+   漏洞评估：在这个类别中，您可以找到用于一般漏洞扫描的工具。它还包含用于评估 Cisco 网络的工具，以及用于评估几个数据库服务器中的漏洞的工具。这个类别还包括几个模糊测试工具。

+   Web 应用程序：这个类别包含与 Web 应用程序相关的工具，如内容管理系统扫描器、数据库利用、Web 应用程序模糊器、Web 应用程序代理、Web 爬虫和 Web 漏洞扫描器。

+   数据库评估：这个类别中的工具测试各种数据库的安全性。有许多专门设计用于测试 SQL 数据库的工具。

+   密码攻击：在这个类别中，您将找到几个工具，可以用来执行在线或离线密码攻击。

+   无线攻击：测试无线安全性变得越来越普遍。这个类别包括攻击蓝牙、RFID/NFC 和无线设备的工具。

+   利用工具：这个类别包含可以用来利用目标环境中发现的漏洞的工具。您可以找到用于网络、Web 和数据库的利用工具。还有用于进行社会工程攻击和查找利用信息的工具。

+   嗅探和欺骗：这个类别中的工具可用于嗅探网络和 Web 流量。这个类别还包括网络欺骗工具，如 Ettercap 和 Yersinia。

+   **后期利用**：这个类别中的工具将能够帮助您保持对目标机器的访问。在安装这个类别中的工具之前，您可能需要在机器中获得最高的特权级别。在这里，您可以找到用于在操作系统和 Web 应用程序中设置后门的工具。您还可以找到用于隧道的工具。

+   **取证**：这个类别包含执行数字取证获取、数据恢复、事件响应和文件切割的工具。

+   **报告工具**：在这个类别中，您将找到帮助您记录渗透测试过程和结果的工具。

+   **社会工程工具**：这个类别包含非常强大的 Maltego 和**社会工程工具包**（**SET**），等等，这些在渗透测试的侦察和利用阶段非常有用。

+   **系统服务**：这个类别包含在渗透测试任务中可能有用的几个服务，比如 Apache 服务、MySQL 服务、SSH 服务和 Metasploit 服务。

为了简化渗透测试人员的生活，Kali Linux 为我们提供了一个名为**前 10 安全工具**的类别。顾名思义，这些是渗透测试人员最常用的前 10 个安全工具。这个类别中包含的工具有`aircrack-ng`、`burp-suite`、`hydra`、`john`、`maltego`、`metasploit`、`nmap`、`sqlmap`、`wireshark`和`zaproxy`。

除了包含用于渗透测试任务的工具之外，Kali Linux 还提供了一些工具，您可以用于以下目的：

+   **逆向工程**：这个类别包含可以用来调试程序或反汇编可执行文件的工具。

+   **压力测试**：这个类别包含可以用于帮助您对网络、无线、Web 和 VOIP 环境进行压力测试的工具。

+   **硬件黑客**：这个类别中的工具可以用于处理 Android 和 Arduino 应用程序。

+   **取证**：这个类别中的工具可以用于各种数字取证任务。这包括对磁盘进行成像、分析内存映像和文件切割。Kali Linux 提供的最好的取证工具之一是 Volatility。这个命令行工具有许多功能用于分析内存映像。还有一些可用的 GUI 工具，比如 Autopsy 和 Guymager，还有已经修复的 Xplico。

为了本书的目的，我们只关注 Kali Linux 的渗透测试工具。

# 下载 Kali Linux

在安装和使用 Kali Linux 之前，首先要做的事情是下载它。您可以从 Kali Linux 网站([`www.kali.org/downloads/`](http://www.kali.org/downloads/))获取 Kali Linux。

在下载页面上，您可以根据以下项目选择官方的 Kali Linux 镜像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e35ce4e3-7289-4906-a51e-ca07a678269d.png)

机器架构：i386、x64 和 armhf

VMware、VirtualBox 和 Hyper-V 的镜像也可以从 Offensive Security 下载页面[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/)下载，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3bc54846-af68-4f0e-a6d3-579e1ac24f91.png)

这些镜像文件可以直接下载或者通过种子作为 OVA、ZIP 和 7-Zip 文件下载

Kali Linux 自定义 ARM 下载可以从[`www.offensive-security.com/kali-linux-arm-images/`](https://www.offensive-security.com/kali-linux-arm-images/)下载。可以通过点击设备名称右侧的箭头下载 Chromebook、Raspberry Pi 等设备的镜像。

Kali NetHunter v3.o 可以从 Offensive Security 网站[`www.offensive-security.com/kali-linux-nethunter-download/`](https://www.offensive-security.com/kali-linux-nethunter-download/)下载。

有关选择、安装和使用适当版本的 NetHunter 的更多信息将在后面的章节中讨论：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a9edb846-4ee0-4f11-a3c9-957decdbe97d.jpg)

Kali Linux Nethunter 下载页面

如果您想要将图像刻录到 DVD 上或在您的机器上安装 Kali Linux，您可能需要下载 ISO 图像版本。但是，如果您想要在虚拟环境中使用 Kali Linux，如 VirtualBox、VMWare 或 Hyper-V，您可以使用相关的图像文件来加快虚拟环境的安装和配置，可在[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-hyperv-image-download/.)上找到。

成功下载图像文件后，您需要将下载的图像的 SHA 哈希值与下载页面上提供的`sha256sum`哈希值进行比较。检查 SHA-256 值的目的是确保下载的图像的完整性得到保留。这可以防止用户安装损坏的图像或被恶意篡改的图像文件。

在 UNIX/Linux/BSD 操作系统中，您可以使用`sha256sum`命令来检查已下载图像文件的 SHA-256 哈希值。请记住，由于其大小，计算 Kali Linux 图像文件的哈希值可能需要一些时间。例如，要生成`kali-linux-2018.2-amd64.iso`文件的哈希值，使用以下命令：

```
sha256sum kali-linux-2018.2-amd64.iso
```

对于 Windows 用户，Raymond Lin 创建的一个小型免费工具，称为 MD5 和 SHA 校验工具，可以使用。此工具计算文件的 MD5、SHA-1、SHA-256 甚至 SHA-512 哈希，并允许比较和验证哈希。

MD5 和 SHA 校验工具可在以下网址下载：[`download.cnet.com/MD5-SHA-Checksum-Utility/3000-2092_4-10911445.html`](https://download.cnet.com/MD5-SHA-Checksum-Utility/3000-2092_4-10911445.html)。下载并运行后，单击“浏览”按钮，浏览到下载文件的路径。在这种情况下，我将使用我的`kali-linux-2018.2-amd64.iso`文件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/84bfd4ad-f504-4b58-bc4c-f27572f58d36.jpg)

在上述截图中，`kali-linux-2018.2-amd64.iso`文件的哈希也是从 Kali Linux 下载页面复制并粘贴到哈希字段进行验证。单击“验证”按钮以比较和验证 SHA-256 哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a6fbb566-7916-46a2-93a3-1dbb45d73e0d.png)

SHA-256 哈希匹配

如果两个值匹配，您可以直接转到*使用 Kali Linux*部分。但是，如果它们不匹配，这意味着您的图像文件损坏了；您可能需要从官方下载镜像再次下载文件。当我们运行我们下载的文件的哈希并将其与网站上的哈希进行比较时，我们看到它们匹配，表明软件包已完全下载并且完整。

# 使用 Kali Linux

您可以以以下方式之一使用 Kali Linux：

+   您可以直接从 Live DVD 上运行 Kali Linux

+   您可以在硬盘上安装 Kali Linux，然后运行它

+   您可以在 USB 磁盘上安装 Kali Linux（作为便携式 Kali Linux）

在接下来的章节中，我们将简要描述每种方法。

# 使用 Live DVD 运行 Kali

如果您想要在不先安装的情况下使用 Kali Linux，可以将 ISO 图像文件刻录到 DVD 上。刻录过程成功完成后，使用该 DVD 启动您的机器。您需要确保已将机器设置为从 DVD 启动。

使用 Kali Linux 作为 Live DVD 的优势在于设置非常快速，使用非常简单。

不幸的是，Live DVD 有一些缺点；例如，任何文件或配置更改在重新启动后将不会被保存。此外，与从硬盘上运行 Kali Linux 相比，从 DVD 上运行 Kali Linux 速度较慢，因为 DVD 的读取速度比硬盘的读取速度慢。

这种运行 Kali 的方法只建议用于测试 Kali。但是，如果您想广泛使用 Kali Linux，我们建议您安装 Kali Linux。

# 在硬盘上安装

要在硬盘上安装 Kali Linux，您可以选择以下方法之一：

+   在物理/真实机器上安装（常规安装）

+   在虚拟机上安装

您可以选择适合您的任何方法，但我们个人更喜欢在虚拟机上安装 Kali Linux。

# 在物理机器上安装 Kali

在您在物理/真实机器上安装 Kali Linux 之前，请确保您将其安装在空的硬盘上。如果您的硬盘上已经有一些数据，那么在安装过程中这些数据将会丢失，因为安装程序将格式化硬盘。为了最简单的安装，建议您使用整个硬盘。对于更高级的设置，有在单个逻辑驱动器的分区上安装 Kali Linux 的选项。要做到这一点，您将需要一个引导操作系统的主分区和另一个用于 Kali Linux 的分区。在这样做时要小心，因为引导操作系统很容易变得损坏。

有关如何在 Windows 操作系统上安装 Kali Linux 的官方 Kali Linux 文档可以在[`docs.kali.org/installation/dual-boot-kali-with-windows`](https://docs.kali.org/installation/dual-boot-kali-with-windows)找到。

有几种工具可用于帮助您执行磁盘分区。在开源领域，以下 Linux Live CD 可用：

+   SystemRescueCD ([`www.sysresccd.org/`](http://www.system-rescue-cd.org/))

+   GParted Live ([`gparted.sourceforge.net/livecd.php`](https://gparted.sourceforge.io/livecd.php))

+   Kali Linux ([`www.kali.org`](https://www.kali.org/))

要使用 Linux Live CD，您只需要启动它，然后您就可以进行磁盘分区了。在使用 Linux Live CD 磁盘分区工具之前，请确保备份您的数据。尽管根据我们的经验它们是安全的，但谨慎起见也没什么不对，特别是如果您的硬盘上有重要数据。

在完成磁盘分区后（或者您只想使用整个硬盘空间），您可以使用 Kali Linux Live DVD 启动您的机器，并在 Kali Linux Live CD 菜单提示您选择安装或图形安装选项时选择它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/693a27ef-bdfd-469d-b40a-f8c824926139.jpg)

Kali Linux 启动画面-选择图形安装

之后，您将看到一个安装窗口。在安装过程中，您需要设置几个事项：

1.  设置语言：默认是英语。

1.  选择位置：使用下拉菜单选择您的国家。

1.  配置键盘：选择最适合您需求的键盘。

1.  系统的主机名：默认是 Kali。对于初学者，您可以保留默认设置。主机名通常在企业环境中使用，需要对连接到网络的所有系统进行核算。

1.  设置域：对于初学者，这应该留空。只有在安装要成为网络域的一部分时才会使用。

1.  设置密码：这将是 ROOT 帐户的密码。选择一个强密码，不要分享它，也不要忘记它。

1.  配置时钟：选择您的时区。

1.  分区磁盘：安装程序将指导您完成磁盘分区过程。如果您使用空的硬盘，只需选择默认的 Guided - use entire disk 选项以方便起见。如果您的机器上已安装了其他操作系统，您可能首先想为 Kali Linux 创建一个单独的分区，然后在此菜单中选择手动。选择适当的菜单后，安装程序将创建分区。

1.  安装程序将询问您有关分区方案；默认方案是所有文件在一个分区中。请记住，如果要将文件存储在主目录中，应选择单独的/home 分区，以便在重新安装系统时不会删除这些文件。/home 分区的大小确实取决于您的需求。如果要将所有数据放在该目录中，可能需要一个较大的分区大小（超过 50GB）。对于一般使用，您可以选择 10 到 20GB。

1.  对于初学者，建议选择“引导-使用整个磁盘”选项。然后，选择要安装 Kali Linux 的磁盘。选择所有文件在一个分区。 

1.  安装程序将显示当前配置的分区概述，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/278b961e-1d75-49d8-8be3-71a4a31a9ca2.jpg)

1.  确保选择“完成分区并将更改写入磁盘”，然后单击“继续”。最后，单击“是”单选按钮，然后单击“继续”以将更改写入磁盘。

1.  网络镜像：对于初学者，选择否。我们将介绍如何更新 Kali Linux。

1.  接下来，安装程序将安装 Kali Linux 系统。安装将在几分钟内完成，然后您将在硬盘上安装了 Kali Linux。在我们的测试机器上，安装大约需要 20 分钟。

1.  安装完成后，安装程序将要求您配置软件包管理器。接下来，它将要求您将 GRUB 安装到主引导记录（MBR）。您可以只选择这两个问题的默认值。注意：如果在同一台机器上有其他操作系统，则不应选择将 GRUB 安装到 MBR。

1.  如果看到以下消息，表示您的 Kali 安装已完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/11f427fe-fa96-4c68-8bf2-362035bebe5c.jpg)

1.  您可以通过选择“继续”按钮重新启动机器以测试新的 Kali 安装。重新启动后，您将看到以下 Kali 登录屏幕。您可以使用在安装过程中配置的凭据登录。默认用户名是`root`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/25b301b8-afbc-47c5-be34-4a34e0cea299.jpg)

默认密码是`toor`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/70e93632-6191-4732-9918-5359d09f703d.jpg)

# 在虚拟机上安装 Kali

您还可以将 Kali Linux 安装在虚拟机环境中作为客户操作系统。这种安装类型的优点是您无需为 Kali Linux 镜像准备单独的物理硬盘分区，并且可以直接使用现有的操作系统。

我们将使用**VirtualBox**（[`www.virtualbox.org`](http://www.virtualbox.org)）作为虚拟机软件。VirtualBox 是一款开源虚拟化软件，适用于 Windows、Linux、OS X 和 Solaris 操作系统。

不幸的是，在虚拟机上运行 Kali Linux 也有一个缺点；它比在物理机器上运行 Kali Linux 要慢。

有两种选项可用于在虚拟机上安装 Kali Linux。第一种选项是将 Kali Linux ISO 镜像安装到虚拟机中。与 VMware 镜像安装相比，这种选项需要更多时间。这种方法的优点是可以自定义 Kali 的安装。

# 从 ISO 镜像在虚拟机上安装 Kali

要在虚拟机上安装 Kali Linux ISO 镜像，可以按照以下步骤进行：

1.  通过从 VirtualBox 工具栏菜单中选择“新建”来创建新的虚拟机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/33dd22a4-317b-469e-8b2c-91b8dda51f71.png)

1.  之后，您需要定义虚拟机的名称和操作系统类型。在这里，我们将 VM 的名称设置为`Kali Linux`，并选择 Linux 作为操作系统类型，Debian 作为版本。

1.  然后，您需要定义 VM 的基本内存大小。您提供的内存越多，虚拟机就越好。在这里，我们为 Kali Linux 虚拟机分配了 2,048 MB 的内存。请记住，您不能将所有物理内存都分配给 VM，因为您仍然需要内存来运行主机操作系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8cdfeb5c-f572-4399-83e7-2491c011509e.png)

1.  接下来，您将被要求创建一个虚拟硬盘。您可以选择 VDI 作为硬盘类型，以及一个动态分配的虚拟磁盘文件。我们建议至少创建一个 32 GB 的虚拟硬盘。如果您想以后安装一些软件包，您可能需要创建一个更大的虚拟硬盘。选择现在创建虚拟硬盘并点击创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/bd469b4d-4e5f-4f83-80cf-80f64c526fd3.png)

1.  现在选择文件位置和大小。点击创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9977ba0b-0bb4-4af9-8a0c-6927d651af40.png)

1.  阅读对话框，然后点击继续。

1.  之后，您新创建的 VM 将在 VirtualBox 菜单中列出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0a18ae04-96fe-463f-93d4-8b434ccb99c6.png)

1.  双击新的 Kali Linux VM：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ba792c3f-00ac-456b-b889-819f9c7718dd.png)

1.  使用文件图标，导航到您选择的 Kali Linux 2018.2 ISO 的位置。选择后，点击开始。

1.  一旦安装开始，请按照之前安装 Kali Linux 2.0 的部分中定义的指示进行操作。

# 使用提供的 Kali Linux VM 镜像在虚拟机上安装 Kali Linux

第二个选项是使用 Kali Linux 提供的 VMware 镜像。

通过这个选项，您可以轻松地在虚拟机上安装 Kali Linux；它位于 Kali Linux 下载页面上：[`www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/`](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a7fdb48d-2be9-4a2d-9c87-afc3759c19ba.png)

虚拟平台上可用的 Kali 镜像列表

点击 Kali 虚拟镜像后，我们将被带到另一页，列出了 Offensive Security 页面上软件包及其相关的`sha256sum`值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/755f0d6b-d7a0-44b6-9e3d-0629aad9f023.png)

下载 Kali Linux VMware 镜像（`kali-linux-2018.2-vm-amd64.zip`）后，您需要验证已下载文件的 SHA256 哈希值与下载页面上提供的哈希值是否相同。如果哈希值相同，您可以将镜像文件提取到适当的文件夹中。

由于 VMware 镜像以 ZIP 格式压缩，您可以使用任何可以提取`.gz`文件的软件，如`gzip`，或者如果您使用 Windows 操作系统，可以使用`7-Zip`。如果您成功提取，您将在目录中找到 13 个文件：

1.  要使用此 VM 镜像文件创建新的虚拟机，请从 VirtualBox 图标工具栏中选择新建。

1.  我们将使用 Kali Linux VM 作为 VM 名称，并选择 Linux 作为操作系统，Debian 作为版本。

1.  我们将 Kali Linux 虚拟机的内存大小配置为 2,048 MB。

1.  接下来，我们定义虚拟硬盘为使用现有的虚拟硬盘文件。然后，我们选择`kali-linux-2018.2-vm-amd64.vmdk`文件作为硬盘。之后，我们选择创建以创建虚拟机，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8ccded4a-24b3-4399-9887-ac92bc4dc611.png)

以下是 Kali Linux VMware 镜像的默认配置：

+   硬盘大小：30 GB

+   网络类型：NAT

+   用户名：`root`

+   密码：`toor`

为了渗透的目的，我们应该避免使用 NAT 作为网络类型。推荐的网络类型是桥接。在配置 Kali VM 时更改 Kali 的默认密码。

如果成功，您将在 Virtual Box 的虚拟管理器列表中看到新的虚拟机。

要运行 Kali Linux 虚拟机，请点击 VirtualBox 菜单栏顶部的启动图标。启动过程后，Kali Linux 将显示其登录提示。

如果有任何错误消息，请安装 VirtualBox 扩展包。您可以从[`www.virtualbox.org/wiki/Downloads.`](http://www.virtualbox.org/wiki/Downloads)获取。

单击“确定”将带您到以下对话框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/764313c9-158b-42f1-b070-c15b9ef40bcc.png)

请继续点击“安装”，然后点击“确定”。

# 保存或移动虚拟机

使用 Kali Linux 作为虚拟机的另外两个优点是，首先是虚拟机可以被暂停的便利性。暂停虚拟机允许您暂停活动而不会丢失任何工作。例如，如果您必须关闭主机系统而虚拟机仍在处理某个操作，暂停它将允许您在离开的地方继续。要暂停虚拟机，请单击位于虚拟机窗口左上角的“暂停”按钮。

虚拟机的另一个功能是能够将其从一个主机移动到另一个主机。如果您需要更改主机系统，例如从笔记本电脑运行然后移动到更新更强大的笔记本电脑，这将非常方便。这可以确保您所做的任何配置或修改保持不变，这样您就不必再次进行整个过程。

要导出虚拟机，转到“文件”并单击“导出虚拟机”。然后将引导您导出 Kali Linux 虚拟机。选择要导出的位置并保持应用程序设置不变。最后，单击“导出”，虚拟机将被导出到该位置。这可能需要一些时间，具体取决于虚拟机的大小。

导出完成后，您可以使用任何存储设备并将虚拟机转移到另一个主机系统。请记住，如果您使用 Oracle VirtualBox 创建虚拟机，请在新主机计算机上使用相同的版本。转移后，您可以通过转到“文件”、“导入虚拟机”并按照说明操作来导入虚拟机。

# 在 USB 磁盘上安装 Kali

使用 Kali Linux 的第三种选择是将其安装在 USB 闪存盘上；我们称这种方法为**便携式 Kali Linux**。根据官方 Kali 文档，这是 Kali 开发人员最喜欢和最快的引导和安装 Kali 的方法。与硬盘安装相比，使用此方法可以在支持从 USB 闪存盘引导的任何计算机上运行 Kali Linux。

USB 闪存盘的安装过程也适用于安装存储卡（SSD、SDHC、SDXC 等）。

有几种工具可用于创建便携式 Kali Linux。其中之一是**Rufus** ([`rufus.akeo.ie/`](http://rufus.akeo.ie/))。此工具仅可在 Windows 操作系统上运行。

您可以使用其他工具从 ISO 镜像创建可引导磁盘，例如：

+   Win32DiskImager ([`launchpad.net/win32-image-writer`](https://launchpad.net/win32-image-writer))

+   Universal USB Installer ([`www.pendrivelinux.com/universal-usb-installer-easy-as-1-2-3/`](http://www.pendrivelinux.com/universal-usb-installer-easy-as-1-2-3/))

+   LinuxLive USB Creator ([`www.linuxliveusb.com`](http://www.linuxliveusb.com/))

在创建便携式 Kali Linux 之前，您需要准备一些东西：

+   **Kali Linux ISO 镜像**：尽管您可以使用便携式创建工具在制作 Kali Linux 便携式时直接下载镜像，但我们认为最好先下载 ISO，然后配置 Rufus 使用镜像文件。

+   **USB 闪存盘**：您需要一个空的 USB 闪存盘，并且有足够的空间。我们建议使用至少 16GB 的 USB 闪存盘。

下载 Rufus 后，您可以通过双击`rufus.exe`文件在 Windows 计算机上运行它。然后您会看到 Rufus 窗口。

如果您使用基于 UNIX 的操作系统，可以使用`dd`命令创建镜像。以下是一个成像的例子：

```
    dd if=kali-linux-2.0-i386.iso of=/dev/sdb bs=512k

```

在这里，`/dev/sdb`是您的 USB 闪存盘。

要创建可引导的 Kali USB 闪存盘，我们需要填写以下选项：

1.  对于**设备**，我们选择 USB 闪存盘的位置。在我的情况下，这是我 Windows 系统中的 E 驱动器。

1.  对于分区方案和目标系统类型，请将其设置为 MBR 分区方案，适用于 BIOS 或 UEFI 计算机。

1.  在“使用 ISO 映像创建可引导磁盘”选项中，将值设置为 ISO 映像，并使用磁盘图标选择 ISO 映像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/7fb4a236-504d-4517-b199-f4aef5253c0c.png)

1.  单击“开始”创建可引导映像。

进程完成后，首先保存所有工作，然后重新启动系统，如果要立即尝试 USB 闪存盘。您可能需要配置您的**基本输入输出系统**（**BIOS**）以从 USB 磁盘引导。如果没有错误，您可以从 USB 闪存盘启动 Kali Linux。

Rufus 也可以用于在 SD 卡上安装 Kali Linux。请务必使用 Class 10 SD 卡以获得最佳效果。

如果您想要为 USB 闪存盘添加持久性功能，可以按照文档部分*向您的 Kali Live USB 添加持久性*中描述的步骤进行操作，位于[`docs.kali.org/installation/kali-linux-live-usb-install`](http://docs.kali.org/installation/kali-linux-live-usb-install)。

# 配置虚拟机

安装后，Kali Linux 虚拟机需要进行几个配置步骤。这些步骤可以提供更大的功能和可用性。

# VirtualBox 增强功能

建议在使用 VirtualBox 成功创建 Kali Linux 虚拟机后，安装`VirtualBox 增强功能`。此附加组件将为您提供以下附加功能：

+   它将使虚拟机可以全屏查看

+   这将使鼠标在虚拟机中移动更快

+   它将使您能够在主机和客户机之间复制和粘贴文本

+   它将使客户机和主机机器可以共享文件夹

要安装增强功能，执行以下步骤：

1.  从 VirtualBox 菜单导航到设备|安装增强功能。然后，您将看到 VirtualBox 增强功能文件被挂载为磁盘。

1.  VirtualBox 随后将显示以下消息。单击“取消”关闭窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fd439358-c6e4-4662-95e0-0d25adca61ff.png)

1.  打开终端控制台并更改 VirtualBox 增强功能 CD ROM 挂载点（`/media/cdrom0`）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5fc8c834-94f5-4822-8ef5-57bb10407469.png)

1.  执行`VBoxLinuxAdditions.run`来运行 VirtualBox 增强功能安装程序，输入`sh ./VBoxLinuxAdditions.run`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c2d483ae-b55f-432f-82ec-25a73470282e.png)

您可能需要等待几分钟，直到所有所需的模块都成功构建和安装。按照以下步骤将 VM 切换到全屏模式：

1.  切换到`root`主目录。

1.  通过右键单击图标并从菜单中选择“弹出”来弹出 VBoxAdditions CD 映像。如果成功，VBoxAdditions 图标将从桌面消失。

1.  在终端控制台中键入`reboot`命令重新启动虚拟机。

1.  重新启动后，您可以从 VirtualBox 菜单中切换到全屏（查看|切换到全屏）。

# 设置网络

在接下来的部分中，我们将讨论如何为 Kali Linux 设置有线和无线网络。

# 设置有线连接

在默认的 Kali Linux VMware 映像或 ISO 配置中，Kali Linux 使用**网络地址转换**（**NAT**）作为网络连接类型。在此连接模式下，Kali Linux 机器将能够通过主机操作系统连接到外部世界，而外部世界，包括主机操作系统，将无法连接到 Kali Linux 虚拟机。

对于渗透测试任务，您可能需要将此网络方法更改为**桥接适配器**。以下是更改它的步骤：

1.  首先确保您已经关闭了虚拟机。

1.  然后，打开 VirtualBox 管理器，选择适当的虚拟机——在本例中我们使用 Kali Linux 虚拟机——然后单击右侧的网络图标，并在适配器 1 中的附加到下拉框中从 NAT 更改为桥接适配器。在名称字段中，您可以选择连接到要测试的网络的网络接口，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5cfaaf55-cfbe-40fc-96ce-92d0cc423292.png)

要能够使用桥接网络连接，主机机器需要连接到可以通过 DHCP 为您提供 IP 地址的网络设备，例如路由器或交换机。

正如您可能知道的那样，DHCP IP 地址不是永久 IP 地址；它只是一个租约 IP 地址。在几次之后（在 DHCP 租约时间中定义），Kali Linux 虚拟机将需要再次获取租约 IP 地址。此 IP 地址可能与以前的相同，也可能是不同的。

如果要使 IP 地址永久，可以将 IP 地址保存在`/etc/network/interfaces`文件中。

以下是 Kali Linux 中此文件的默认内容：

+   `auto lo`

+   `iface lo inet loopback`

在默认配置中，所有网络卡都设置为使用 DHCP 获取 IP 地址。要使网络卡永久绑定到 IP 地址，我们必须编辑该文件并更改内容如下：

+   `auto eth0`

+   `iface eth0 inet static`

+   `address 10.0.2.15`

+   `netmask 255.255.255.0`

+   `network 10.0.2.0`

+   `broadcast 10.0.2.255`

+   `gateway 10.0.2.2`

在这里，我们将第一个网络卡（`eth0`）设置为绑定到`10.0.2.15`的 IP 地址。您可能需要根据要测试的网络环境调整此配置。

# 建立无线连接

通过将 Kali Linux 作为虚拟机运行，您无法使用嵌入在主机操作系统中的无线网卡。幸运的是，您可以使用外部基于 USB 的无线网卡。

在此演示中，我们使用 USB Ralink 无线网卡/外置天线（稍后将在关于无线渗透测试的部分进行无线天线选择的深入讨论）：

1.  要在 Kali 虚拟机中激活您的基于 USB 的无线网卡，将无线网卡插入 USB 端口，导航到设备| USB 设备，并从 VirtualBox 菜单中选择您的无线网卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3fafe61f-fabd-4fc9-b42e-a5f293151c19.png)

在此截图中，我们可以看到列出的 USB 设备。

1.  如果您的 USB 无线网卡已成功被 Kali 识别，您可以使用`dmesg`程序查看无线网卡的信息。确定您的无线设备是否正确连接的另一种选择是打开终端并运行以下命令：

```
 ifconfig
```

如果无线连接已正确配置，您应该在输出下看到`WLAN0`或`WLAN1`的列表：

1.  输出应包括 WLAN 的列表。这是无线网络连接。

1.  在 Kali 菜单的右上部分，您将看到网络连接图标。您可以单击它以显示您的网络信息。

1.  您将看到几个网络的名称，有线或无线，可供您的设备使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b4197dc5-e3d8-4aab-b0f4-a7545f9363e4.png)

1.  要连接到无线网络，只需通过双击其名称选择要连接的特定 SSID。如果无线网络需要身份验证，您将被提示输入密码。只有在您输入正确的密码后，才能连接到该无线网络。

# 更新 Kali Linux

Kali Linux 由数百个应用软件和操作系统内核组成。如果要获取最新功能，可能需要更新软件。我们建议您只从 Kali Linux 软件包存储库更新软件和内核。

成功安装和配置 Kali Linux 后，首先要做的是更新它。由于 Kali 基于 Debian，您可以使用 Debian 命令（`apt-get`）进行更新。

`apt-get`命令将查阅`/etc/apt/sources.list`文件以获取更新服务器。您需要确保已在该文件中放入正确的服务器。

要更新`sources.list`文件，请打开终端并键入以下命令：

```
leafpad /etc/apt/sources.list
```

从官方网站[`docs.kali.org/general-use/kali-linux-sources-list-repositories`](https://docs.kali.org/general-use/kali-linux-sources-list-repositories)复制存储库，粘贴到 leafpad 中，并保存：

```
 deb http://http.kali.org/kali kali-rolling main contrib non-free
 # For source package access, uncomment the following line
 # deb-src http://http.kali.org/kali kali-rolling main contrib non-free 
```

在执行更新过程之前，您需要从`/etc/apt/sources.list`文件中指定的存储库同步软件包的索引文件。以下是此同步的命令：

```
    apt-get update  
```

确保在 Kali 中执行软件更新或安装之前始终运行`apt-get`更新。在软件包索引已同步后，您可以执行软件更新。

有两个命令选项可用于执行升级：

+   `apt-get upgrade`：此命令将把机器上当前安装的所有软件包升级到最新版本。如果在升级软件包时出现问题，该软件包将保持当前版本不变。

+   `apt-get dist-upgrade`：此命令将升级整个 Kali Linux 发行版；例如，如果要从 Kali Linux 1.0.2 升级到 Kali Linux 2.0，可以使用此命令。此命令将升级当前安装的所有软件包，并在升级过程中处理任何冲突；但是，可能需要执行一些特定操作才能执行升级。

在选择适当的命令选项以更新 Kali Linux 之后，`apt-get`程序将列出将要安装、升级或删除的所有软件包。`apt-get`命令将等待您的确认。

如果您确认，升级过程将开始。注意：升级过程可能需要很长时间才能完成，这取决于您的互联网连接速度。

# 在亚马逊 AWS 云上设置 Kali Linux AMI

Kali Linux 也可以作为亚马逊网络服务平台上的**亚马逊机器映像**（**AMI**）在云中设置，作为云计算服务。尽管列为每小时 0.046 美元的费用，但如果特别配置为基本服务且用户未超出某些设定限制，则可以免费使用。虽然注册和配置需要信用卡，但如果超出设定限制，您将在被收费之前收到通知。

在开始在云中设置 Kali Linux 之前，您可以首先访问亚马逊市场，查看此链接中 AMI 的详细信息：[`aws.amazon.com/marketplace/pp/B01M26MMTT`](https://aws.amazon.com/marketplace/pp/B01M26MMTT)。请注意，它被列为免费使用。

要开始设置和配置云中的 Kali Linux，我们必须执行以下步骤：

1.  首先，在亚马逊的 AWS 门户网站上创建一个帐户。访问[`aws.amazon.com/`](https://aws.amazon.com/)，然后单击“创建新帐户”。一定要记住使用的凭据以及您创建的 AWA 名称，如屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/45ef877b-6342-4a7b-81d2-390e0dea670e.png)

1.  单击“继续”后，完成其他所需的详细信息。在输入信用卡详细信息时，您可能会提示亚马逊给您打电话，并要求您输入验证码以进行验证和安全目的。完成后，您将进入 AWS 控制台。

1.  您还应该收到一封电子邮件通知，告知您的帐户已成功创建。您现在可以登录到 AWS 控制台，在那里您将能够完成配置。在“构建解决方案”部分，单击“启动虚拟机”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cb7bb384-c845-4d45-a47b-14d01f9675d9.png)

1.  在 AWS 控制台的 EC2 仪表板中，在左侧窗格中，点击网络和安全类别下的密钥对：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0c19732d-9861-4936-bafa-531cc83a43a9.png)

接下来，点击创建密钥对。

当提示时，输入密钥对的名称。建议您选择一个易于记住的名称和位置，因为您将需要此密钥对进行身份验证和验证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1d5d9103-ce82-44e2-9bdf-304f6880ca4f.png)

将密钥对保存到您选择的目的地。请注意，密钥对扩展名列为`.pem`，并且还以十六进制格式显示数字指纹，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d6845c31-7385-4fd1-85dc-583e1758a3a4.png)

保存密钥对后，返回 AWS 控制台，点击控制台顶部的资源组，然后选择启动虚拟机。在控制台左侧的菜单中，点击 AWS Marketplace，并在搜索栏中输入 Kali Linux，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ca7862e2-5931-4b60-a42a-1e14efa983a1.jpg)

目前市场上只有一个 Kali Linux AMI 实例。请注意，它在 Kali 标志下列为免费使用资格。点击选择以使用此 AMI：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d426b5fb-43cd-4953-9b47-4a20ba63b66b.png)

这将带我们进入 AMI 的各种实例类型的定价细节，这些实例类型包括 AMI 可用的内存和处理器使用等规格，T2 Nano 的每小时费率最低为$0.006/小时。查看完实例类型后，滚动到页面底部，然后点击继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/10d270a0-19e1-4030-ba20-5e3a49acab75.png)

对于免费版本，请选择**t2 微型**类型，因为这是用于一般用途，并且符合免费使用范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fd8c2a27-dddd-4224-82f9-0139bdb985b8.png)

点击“审阅并启动”按钮。确认所选择的实例类型为**t2.micro**，然后点击启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2a99cf3b-4042-461f-ae30-b01fe58633af.png)

现在应提示您使用之前保存的密钥对。在第一个下拉菜单中，选择选择现有的密钥对。在选择密钥对的菜单中，浏览到保存的密钥对的位置。点击复选框以确认条款，然后最后点击启动实例。

现在您将收到 Kali Linux AMI 的启动状态通知。如果您超出了 AWS 的免费使用范围，您还可以创建计费警报：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/544ee842-7f2e-4b61-9124-5d973252e6d8.png)

向下滚动并点击查看使用说明：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c448cb01-33ae-486c-8c27-9757c3774b26.png)

返回启动状态页面，点击在 AWS Marketplace 上打开您的软件。在软件订阅和 AMI 选项卡中，点击查看实例。

这将弹出一个框，显示实例的详细信息，包括 ID、操作系统信息和状态。在 AWS 控制台中点击管理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/dc5670e0-c1cc-4092-84b2-cb46211de738.png)

点击连接按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/016cf0b7-34e2-4e16-92bb-d3aec5cc9260.png)

然后我们将看到连接到我们实例的可用选项，以及如何使用 SSH 客户端（如 PuTTY）进行连接的说明。请注意，在列出的示例中，密钥对的名称是`Kali_AWS.pem`。在通过 SSH 客户端连接时，请确保使用您在之前步骤中选择的密钥对名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/7a88090b-0c09-41f2-ab0f-315bf2296b23.png)

现在我们需要一个独立的**安全外壳**（**SSH**）客户端，以便能够连接到我们在云中的 Kali Linux 实例。我们将使用 Putty 作为我们的独立客户端，我们还需要 Puttygen，以便能够使用之前下载的密钥对对我们的云实例进行身份验证。Putty 和 Puttygen 都有 32 位和 64 位版本，可以从以下链接下载：[`www.chiark.greenend.org.uk/~sgtatham/putty/latest.html?`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html?)。

确保下载`putty.exe`和`puttygen.exe`，它们是 Windows 可执行文件。我使用的机器是 64 位架构，因此我将使用 64 位版本。

下载完成后，首先运行`puttygen.exe`。单击“文件”，然后单击“加载私钥”。现在，浏览到您之前下载的密钥对文件。您可能需要将文件类型从**PFF**更改为**所有文件**，因为密钥文件是以较旧的`.pem`格式。

选择后，应提示您保存私钥以便以 Putty 的格式保存它。

定位到密钥后，单击“保存私钥”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1dc6ed52-ea98-4cb7-b68e-c810b116cfe1.png)

现在，我们可以运行和配置`Putty.exe`，以便使用必要的设置连接到 AWS 云中的 Kali 实例。

在 Putty 的左窗格中的“会话”类别中，输入仪表板中“实例”类别中显示的公共 DNS URL。它应该看起来像屏幕截图中的 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/63ab28b9-2414-400d-829d-62abf5ec12fd.png)

在 Putty 中的主机名区域输入公共 DNS 地址，如屏幕截图中所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/48109c94-38cd-4093-8de7-c2f77083e5d7.png)

接下来，向下滚动到 Putty 的左窗格中的**SSH**类别，并单击**Auth**子类别。单击右窗格上的**浏览**按钮，浏览到保存的`.ppk`私钥。

对于用户名，我们将使用**Ec2-user**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4ca115a8-7c6d-4679-b931-368cd9166469.png)

单击“打开”按钮，现在您应该能够登录到云中的 Kali 实例。连接后，请记得更新 Kali。

# 摘要

当查看最新版本的 Kali Linux 中的各种工具时，我们可以看到有各种安全任务的功能。这些包括数字取证、无线安全评估、软件逆向工程、黑客硬件和渗透测试。

还讨论了 Kali Linux 可以部署的各种方式。可以使用光盘、USB 或 SD 卡部署 Kali Linux，将其安装为虚拟机，也可以将其用作独立系统或云中的主操作系统。

与任何其他软件一样，Kali Linux 也需要更新，无论是仅更新软件应用程序还是更新发行版中包含的 Linux 内核。

在下一章中，我们将介绍如何设置我们的渗透测试实验室。

# 问题

1.  Kali Linux 的移动版本的名称是什么？

1.  可以用什么 Windows 工具来验证已下载的 Kali Linux 镜像文件的完整性？

1.  验证已下载的 Kali Linux 镜像文件的 Linux 命令是什么？

1.  可以用什么工具在闪存驱动器或 SD/micro-SD 卡上安装 Kali Linux 和其他 Linux 发行版的名称是什么？

1.  使用 Kali Linux 的各种实时模式是什么？

1.  用于更新 Kali Linux 的命令是什么？

1.  在亚马逊云中安装 Kali Linux 时，哪种通用实例符合免费套餐的使用条件？

# 进一步阅读

有关 Kali Linux 安装的其他信息，请访问：[`docs.kali.org/category/installation`](https://docs.kali.org/category/installation)。 [](https://docs.kali.org/category/installation)

有关在 Windows 上双启动 Kali Linux 的其他信息，请访问：[`docs.kali.org/installation/dual-boot-kali-with-windows`](https://docs.kali.org/installation/dual-boot-kali-with-windows)。


# 第二章：建立您的测试实验室

在这一章中，我们将看看为我们的渗透测试建立实验室环境。在尝试在生产环境中进行测试之前，许多测试应该首先在这个有限的实验室环境中进行。请记住，在进行网络渗透测试的任何阶段时，您必须在实时环境中获得书面许可，并遵守所有当地法律。在开始之前，最好让律师审查任何合同和参与细节，以避免在练习期间或之后可能出现的任何问题。一些保险公司也会为渗透测试人员提供意外损害的保险。

为了避免由于渗透测试而遇到法律问题和不必要的支出，强烈建议您建立一个测试环境，无论是物理的还是虚拟的，以便熟悉测试及其结果，并了解测试对硬件、软件和带宽的影响，因为这些测试对设备和组织都具有破坏性。

我们将详细介绍以下主题：

+   在虚拟机中设置 Windows 环境

+   安装易受攻击的服务器

+   在 Kali Linux 中安装额外的工具

+   Kali Linux 中的网络服务

+   额外的实验室和资源

# 技术要求

+   最低硬件要求：6 GB RAM，四核 2.4 GHz 处理器，500 GB 硬盘

+   VirtualBox：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

+   Metasploitable 2: [`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/)

+   Packer：[`www.packer.io/downloads.html`](https://www.packer.io/downloads.html)

+   Vagrant：[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)

+   Metasploitble 3（300 MB 文件）

+   Metasploitable 3（适用于 VirtualBox 的 6 GB`.ova`文件）：[`mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI`](https://mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI)

+   BadStore 易受攻击的 Web 服务器：[`d396qusza40orc.cloudfront.net/softwaresec/virtual_machine/BadStore_212.iso`](https://d396qusza40orc.cloudfront.net/softwaresec/virtual_machine/BadStore_212.iso.)

# 物理还是虚拟？

决定是建立物理实验室还是虚拟实验室（或两者兼而有之）取决于您的预算和可用资源。渗透测试可以根据所使用的工具而变得非常昂贵，特别是如果选择商业工具，但考虑到 Kali Linux 中许多可用的开源工具以及 GitHub 和 GitLab 上可用的工具，它并不一定非常昂贵。

作为专业的渗透测试人员，我使用两台物理机器。一台是配备 1 TB 硬盘、16 GB DDR4 RAM、i7 处理器和 NVIDIA GeForce GTX 1050 显卡的笔记本电脑，配备了三台虚拟机，包括主操作系统（Kali Linux 2018.2）。第二台机器是一台较旧的塔式工作站，配备 2 TB 硬盘、24 GB DDR3 RAM 和 Intel Xeon 3500 处理器，带有几个虚拟机，包括作为我的虚拟实验室环境的一部分使用的虚拟机。

在创建实验室环境时，至关重要的是您了解每个操作系统所需的最低和推荐资源，包括主机和所有虚拟机。虽然许多基于 Linux 的操作系统只需要 2 GB 的 RAM，但将超过指定的推荐 RAM 分配给您的工具总是一个明智的选择，以确保您的工具能够运行而不会出现延迟或内存不足的错误。不过，这将取决于您手头的预算或资源。

# 在虚拟机中设置 Windows 环境

对于 Windows 环境测试实验室，我选择安装微软 Windows 10，因为它目前是微软的最新版本。许多拥有更新 PC 和笔记本电脑的用户可能已经在运行 Windows 10，但是为了测试目的，Windows 10 也应该安装为虚拟机，从而保持主机操作系统不受影响。这也建议给那些使用较旧版本 Windows 的读者，以及 Mac 和 Linux 用户，这样他们就能够在实验室环境中使用最新版本的 Windows 进行渗透测试。在现实世界中，我们将看到更少的 Windows 7 机器，因为它的支持已经结束（使这些系统极易受到攻击），尽管也会有一些忠实的用户暂时不愿意升级。

在这次安装中，我们将使用微软网站上直接下载的 Windows 10 企业版评估副本。您可以通过访问[`www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise`](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)来下载 Windows 10 企业版的评估副本。请记住，除非您有或购买了许可证，否则此版本有 90 天的评估期。

一旦到达下载页面，您应该注意到有两个可用版本，ISO 和**长期服务分支**（**LSTB**）。选择 ISO-企业版，然后点击继续。

填写评估表格的详细信息，然后点击继续。请记住输入的详细信息，因为在安装过程中稍后您将需要通过电话或短信进行身份验证。

选择您的平台（32 位或 64 位）以及您的语言，然后点击下载以继续。

现在您可以开始创建 Windows 10 虚拟机。可以使用 VirtualBox 或 VMware 进行此操作，但在这种情况下，我将使用 VirtualBox。

打开 VirtualBox，然后点击左上角的新建图标。为您的 VM 命名，并根据您之前下载的版本选择适当的版本（32 位或 64 位）。点击下一步继续。

为虚拟机分配可用的 RAM。推荐的内存为 2 GB，但是我分配了略多于 6 GB，因为我的机器上有 24 GB 的 RAM。记得考虑主机的使用情况，以及其他可能同时运行的 VM，比如 Kali Linux：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/241ca8c8-b65e-4c11-804c-178357b2830e.jpg)

通过单击立即创建虚拟硬盘，然后单击创建来添加新的虚拟硬盘。

对于硬盘文件类型，选择**VirtualBox 磁盘映像**（**VDI**），然后点击下一步。

在物理磁盘的存储选项下选择动态分配。这个选项通过仅在使用时使用物理磁盘上的空间来节省硬盘空间，而不是创建一个可能不会被使用的固定大小空间。点击下一步继续。

在选择虚拟磁盘大小时，考虑推荐的硬盘空间以及您可能希望在 VM 中安装的应用程序的空间（如 Metasploitable）。在这种情况下，我分配了 64 GB 的硬盘空间。点击创建继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/96f5b4c7-2ea6-4e41-b55d-2a7670c3ec47.jpg)

此时，我们现在必须将 ISO 映像指向 VM。在 VirtualBox 管理器中，点击您新创建的 Windows 10 VM 实例，然后点击启动箭头。在选择启动磁盘框中，点击文件夹图标，浏览下载的 Windows 10 评估副本。点击开始继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/880ea3cb-1f2c-4ace-bb87-bc02ac42e86a.jpg)

这将带我们到 Windows 设置启动画面。输入您设置的相关信息，然后点击下一步继续。

点击立即安装以开始安装过程。

接受微软的许可条款，然后点击下一步继续。选择自定义安装选项，然后点击新建，然后点击应用以格式化 VM 硬盘：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8f2c3138-cac9-4272-ba7b-ff4d1bcb2714.jpg)

格式化后，确保选择了之前指定大小的分区，然后单击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a22d262d-b6d2-4a81-b203-df9b19f37827.jpg)

安装过程将开始，并且也需要一些时间来完成。与此同时，您可以查看一些关于渗透测试的其他精彩标题，网址为[`www.packtpub.com/tech/Penetration-Testing`](https://www.packtpub.com/tech/Penetration-Testing)。

安装完成后，如下截图所示，允许操作系统自动重新启动。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6a064124-13c9-4460-9b48-1d6ef9722746.jpg)

然后，您将被提示选择语言和键盘布局，然后继续设置，在此之后，您将被提示输入工作或学生电子邮件，然后选择隐私设置。

要设置安全登录，点击“设置 PIN”。您可能首先需要通过电话或短信验证您的身份。验证完成后，您将能够设置 PIN。请务必记住此 PIN（至少六位数），因为您将需要使用 PIN 进行登录。

设置完成后，您现在可以配置网络并安装应用程序。在屏幕右下角，您应该看到评估副本的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3e02e2c7-f684-4497-a4cd-608d03be818f.jpg)

如果需要快速恢复虚拟机到工作状态，您可能需要保存虚拟机状态。

# 安装易受攻击的服务器

在本节中，我们将安装一个易受攻击的虚拟机作为目标虚拟机。在书的几个章节中，我们将使用此目标，解释特定主题。我们选择在我们的机器上设置易受攻击的服务器，而不是使用互联网上可用的易受攻击的服务器的原因是因为我们不希望您违反任何法律。我们应强调，您绝不应在没有书面许可的情况下对其他服务器进行渗透测试。安装另一个虚拟机的另一个目的是以受控的方式提高您的技能。这样，很容易修复问题，并了解在攻击不起作用时目标机器上发生了什么。

在一些国家，甚至对不是您拥有的机器进行端口扫描都可能被视为犯罪行为。此外，如果使用虚拟机的操作系统出现问题，我们可以很容易地修复它。

在接下来的章节中，我们将设置 Metasploitable 2 和 Metasploitable 3 虚拟机作为易受攻击的服务器。Metasploitable 2 较旧，但更容易安装和配置。Metasploitable 3 更新一些漏洞，但安装方式有些不同，对新用户来说有时会有问题。因此，我们为读者提供了 Metasploitable 2 和 3 的选择，尽管我们建议您尝试两者，如果您有可用资源的话。

# 在虚拟机中设置 Metasploitable 2

我们将要使用的易受攻击的虚拟机是 Metasploitable 2。Rapid7 的著名 H.D. Moore 创建了这个易受攻击的系统。

除了 Metasploitable 2 之外，还有其他故意易受攻击的系统，您可以用于渗透测试学习过程，可以在以下网站找到：[`www.vulnhub.com`](https://www.vulnhub.com)。

Metasploitable 2 在操作系统、网络和 Web 应用程序层面有许多漏洞。

有关 Metasploitable 2 中包含的漏洞的信息可以在 Rapid7 网站上找到，网址为[`community.rapid7.com/docs/DOC-1875`](https://community.rapid7.com/docs/DOC-1875)。

要在 VirtualBox 中安装 Metasploitable 2，您可以执行以下步骤：

1.  从[`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](http://sourceforge.net/projects/metasploitable/files/Metasploitable2/)下载 Metasploitable 2 文件。

1.  解压 Metasploitable 2 ZIP 文件。成功完成解压过程后，您将找到五个文件：

```
Metasploitable.nvram 
Metasploitable.vmdk 
Metasploitable.vmsd 
Metasploitable.vmx 
Metasploitable.vmxf 
```

1.  在 VirtualBox 中创建一个新的虚拟机。将名称设置为`Metasploitable2`，操作系统设置为`Linux`，版本设置为`Ubuntu`。

1.  将内存设置为`1024MB`。

1.  在虚拟硬盘设置中，选择使用现有的硬盘。选择我们在上一步中已经提取的`Metasploitable`文件。

1.  将网络设置更改为仅主机适配器，以确保此服务器仅从主机机器和 Kali Linux 虚拟机访问。Kali Linux 虚拟机的网络设置也应设置为仅主机适配器，以便对本地 VM 进行渗透测试。

1.  启动`Metasploitable2`虚拟机。启动过程完成后，你可以使用以下凭据登录`Metasploitable2`控制台：

+   用户名：`msfadmin`

+   密码：`msfadmin`

在你成功登录后，以下是 Metasploitable 2 控制台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/736d2a8f-fec1-461d-a6b9-472b928f51e5.png)

# 在 VM 中设置 Metasploitable 3

由 Rapid7 于 2016 年发布，Metasploitable 3 是最新更新的版本，比其前身具有更多的漏洞。然而，Metasploitable 3 并不是作为可下载的虚拟机提供的，而是需要安装和配置多个组件，用户需要自己构建虚拟机。

在这个例子中，我将在 Windows 10 主机上构建 Metasploitable 3 VM。为此，我们首先需要下载以下内容：

+   VirtualBox 或 VMware（VirtualBox 用户报告了版本 5.2 的问题，但使用版本 5.1.14 则取得了良好的结果，该版本可在 VirtualBox 页面上找到）

+   Packer

+   Vagrant

# 安装 Packer

Hashicorp 的 Packer 用于轻松构建自动化镜像，如 Metasploitable 3。访问[`www.packer.io/downloads.html`](https://www.packer.io/downloads.html)并下载适用于你的操作系统的 Packer 版本。在这个例子中，我下载了 Windows 64 位版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b1b4fb03-0450-4b5f-a1dd-6ee358656201.png)

下载完成后，提取文件的内容。应该有一个文件，这里是`packer.exe`。

然后，在任何你喜欢的地方创建一个文件夹，并将其命名为 packer。我把它放在了我的系统的`C:`驱动器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/bfb437ae-5348-4971-aa9c-bed7e7ca6187.png)

在这一点上，你需要添加此文件夹的路径，以便在命令提示符中调用 Packer 应用程序。只需编辑你的环境变量并将其粘贴到`packer.exe`的路径中。

打开控制面板，点击高级系统设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/82137962-71c6-448b-885e-74ed656aefa9.png)

在系统属性窗口中，在高级选项卡下，点击环境变量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/897ad4af-66f9-4230-8596-63eb30e00cea.png)

你应该在用户变量中看到路径条目。在系统变量框中，你还应该看到路径变量，其中包含一个条目`C:\Program Files (x86)\Common Files\Oracle|Java\javapath:..`

点击“编辑”按钮继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/85399e59-d3e2-43db-8503-7acf0a67ef8e.png)

在编辑环境变量中，点击右上角的“新建”按钮，并从主窗口的列表中选择`C:\packer`。然后点击“确定”。

为了测试更改是否成功，启动命令提示符并输入`packer`。如果一切顺利，你应该返回使用参数和可用命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6ded105f-d008-4697-9159-d519e9db6993.png)

# 安装 Vagrant

Hashicorp 的 Vagrant 也是开源的，用于简化虚拟环境中的工作流程和配置。访问[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)并下载 Windows 版本。

一旦相关的下载程序安装完成（在这种情况下是 Windows），安装 Vagrant。

假设你已经安装了 VirtualBox，从 GitHub 存储库[`github.com/rapid7/metasploitable3`](https://github.com/rapid7/metasploitable3)下载 Metasploitable 3 源文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9757e913-797f-411b-ad2f-6c3370476ded.png)

一旦源文件已下载，将文件提取到您选择的位置。在 Windows 10 中启动 PowerShell，更改目录直到到达包含下载的 Metasploitable 文件的文件夹，并输入`./build_win2008`命令。

这应该足以让您开始构建您的 Metasploit 3 服务器。对于初学者来说，这是一个非常复杂的构建，但绝对值得一试。

# 预构建的 Metasploit 3

对于那些在构建自己的 Metasploitable 3 服务器时遇到困难的人，可以在 GitHub 上找到并下载预构建版本：[`github.com/brimstone/metasploitable3/releases`](https://github.com/brimstone/metasploitable3/releases)。

这个版本的 Metasploitable 3 是由 Brimstone（Matt Robinson）构建的，可以作为`.ova`文件（Metasploitable3-0.1.4.ova）下载，大小仅为 211 MB。下载后，可以通过单击“文件”和“导入虚拟设备”在 VirtualBox 中打开.ova 文件。如果可用，您可能希望将预设的 RAM 量更改为 1 GB 以上。

尽管设置过程很长，但安装程序会自动完成所有操作，并最终为您呈现完整版本的 Metasploitable 3 Windows 2008 服务器。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fe741713-0db6-44ab-895d-e342c12d2a57.jpg)

另外，还可以在此处下载另一个完全配置好的预构建 Metasploitable 3 服务器：[`mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI`](https://mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI)。

# 在 VM 中设置 BadStore

与 Metasploitable 3 相比，BadStore ISO 已经过时；但是，与 Metasploitable 3 不同，它非常容易安装和使用。知识和资源非常有限的读者可以使用此 ISO 镜像作为起点，因为它包含众所周知的漏洞，并且大小不到 15 MB。

截至撰写本书时，BadStore ISO 镜像不再在官方商店中提供，但可以使用几个信誉良好的链接。如 GitHub 文章所述，BadStore ISO 可以从此处下载：[`d396qusza40orc.cloudfront.net/softwaresec/virtual_machine/BadStore_212.iso`](https://d396qusza40orc.cloudfront.net/softwaresec/virtual_machine/BadStore_212.iso)。

BadStore ISO 的手册也应下载，因为它包含有关 IP 连接和操作系统中的漏洞的重要信息。

从上述链接下载文件后，打开 VirtualBox，单击“文件”和“新建”。输入屏幕截图中显示的详细信息。完成后，单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2e516748-d319-49f3-aa63-e4648b9f80c4.png)

BadStore 使用的 RAM 很少。可以使用默认分配，但我已分配了 640 MB 的 RAM。单击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d6ef949b-daca-417f-9d39-540cf852444e.png)

完成以下步骤：

+   单击“现在创建虚拟硬盘”，然后单击“创建”按钮

+   选择**VirtualBox 磁盘映像**（**VDI**）作为硬盘文件类型，然后单击“下一步”

+   在提示选择物理存储选项时选择动态分配，并单击“下一步”

+   对于文件位置和大小，保留默认的 4 GB 文件大小，因为 BadStore 也需要非常少的磁盘空间

在启动 BadStore VM 之前，单击 Oracle VM VirtualBox Manager 中的“设置”按钮。单击左窗格中的“网络”类别，将适配器设置更改为“桥接适配器”，然后单击“确定”。这将使 VM 能够通过 DHCP 接收 IP 地址（如果在您的网络上启用了 DHCP），从而简化后续步骤中的连接过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/43ae07f6-721c-40b7-a382-8c5c68a67c38.png)

在 Oracle VM VirtualBox Manager 中，单击 BadStore 条目，然后单击“启动”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8cf744c8-6759-46a9-a669-b25b30294b2c.png)

在提示选择启动磁盘时，单击打开文件夹图标，浏览到之前下载的`BadStore.iso`文件。单击“启动”以运行 VM。

加载 BadStore 后，按 Enter 键激活控制台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/50fbdda1-7b73-4f5a-aedb-7dd6a866744f.png)

按下*Enter*后，输入`ifconfig`命令并按*Enter*查看你的接口配置。请注意，在下面的屏幕截图中，在`eth0`接口中，IP 地址（`inet addr`）设置为`192.168.3.136`。在你的机器上，根据你使用的 IP 方案，它应该是不同的。记下这个 IP，因为连接到 BadStore VM 需要用到它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6e4b7884-00c7-41c4-b5e7-20f3d78ee18d.png)

打开你选择的浏览器，在地址栏中输入 BadStore VM 的 IP 地址，然后输入以下语法：`cgi-bin/badstore.cgi`。

在这种情况下，我已经在浏览器的地址栏中输入了以下 URL，以访问 BadStore VM：`http://192.168.3.136/cgi-bin/badstore.cgi`。

一旦你输入了 BadStore VM 的 IP 并附加了前面的路径，按 Enter 键，你将看到 BadStore 前端，就像在这个屏幕截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/eadbe524-69a5-4de1-bfd8-3d789bf01bf8.png)

如前所述，BadStore VM 在界面设计上非常古老；然而，对于初学者来说，它包含了 Kali Linux 中在后续章节中介绍的各种常见漏洞，可以很容易地找到并利用。

你可以尝试的另一个类似且易于设置的 VM 是**Damn Vulnerable Linux**（**DVL**）ISO。它可以从以下网址下载：[`sourceforge.net/projects/virtualhacking/files/os/dvl/DVL_1.5_Infectious_Disease.iso/download`](https://sourceforge.net/projects/virtualhacking/files/os/dvl/DVL_1.5_Infectious_Disease.iso/download)。

# 在 Kali Linux 中安装额外的工具

在渗透测试之前或期间，可能需要包含 Kali Linux 中常见的其他工具。渗透测试的艺术有很多人不断创造可以包含的工具。因此，在你的 Kali Linux 设置中安装这些工具可能是必要的。在其他情况下，通常最好在开始任何渗透测试之前确保你的工具是最新的。

在包含额外的渗透测试工具时，建议首先查看 Kali Linux 存储库。如果软件包在那里可用，你可以使用该软件包，并使用下面详细说明的命令进行安装。另一个选择是，如果该工具在存储库中不可用，创建者通常会在他们的网站上或通过软件共享和聚合站点[`github.com/`](https://github.com/)上提供下载选项。

虽然 Kali Linux 存储库外有许多可用工具，但你不应该依赖它们，因为很容易将它们添加到你的 Kali Linux 安装中。此外，许多不在存储库中的软件包有其他软件的依赖关系，可能会导致稳定性问题。

有几种软件包管理工具可用于帮助你管理系统中的软件包，如`dpkg`、`apt`和`aptitude`。Kali Linux 默认安装了`dpkg`和`apt`。

如果你想了解更多关于 apt 和`dpkg`命令的信息，你可以查看以下参考资料：[`help.ubuntu.com/community/AptGet/Howto/`](https://help.ubuntu.com/community/AptGet/Howto/)和[`www.debian.org/doc/manuals/debian-reference/ch02.en.html`](http://www.debian.org/doc/manuals/debian-reference/ch02.en.html)。

在本节中，我们将简要讨论 apt 命令，这与软件包安装过程有关。

要在存储库中搜索软件包名称，你可以使用以下命令：

```
    apt-cache search <package_name>
```

这个命令将显示整个软件包，其名称为`package_name`。要搜索特定软件包，请使用以下命令：

```
    apt-cache search <package_name>
```

如果您已经找到软件包但想要更详细的信息，请使用以下命令：

```
    apt-cache show <package_name>
```

要安装新软件包或更新现有软件包，请使用`apt-get`命令。以下是命令：

```
    apt-get install <package_name>
```

如果软件包在存储库中不可用，您可以从开发者网站或通过[www.github.com](http://www.github.com)搜索并下载。请务必只包括来自可信来源的软件。对于需要 Debian 软件包格式（软件包将具有文件扩展名`.deb`）的开发人员，可以使用`dpkg`命令。对于其他软件包，您通常会发现它们使用诸如 7-Zip 之类的压缩程序进行压缩，并且通常具有扩展名`.zip`或`.tar`。

# Kali Linux 中的网络服务

Kali Linux 中有几种网络服务；在本节中，我们只描述其中一些：HTTP、MySQL 和 SSH 服务。您可以通过导航到 Kali Linux | 系统服务来找到其他服务。

# HTTP

如果您的渗透测试有效，您可能希望有一个 Web 服务器，出于各种原因，例如提供恶意 Web 应用程序脚本。在 Kali Linux 中，已经安装了 Apache Web 服务器；您只需要启动服务。

以下是在 Kali Linux 中激活 HTTP 服务器所需的步骤：

1.  要启动 Apache HTTP 服务，请打开命令行终端并输入以下命令以启动 Apache 服务器：

```
   service apache2 start
```

1.  之后，您可以浏览到`127.0.0.1`的网页；默认情况下，它将显示 It works!页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a3d1dc34-82c0-4496-b411-9c2d1f913674.png)

要停止 Apache HTTP 服务，请执行以下步骤：

1.  打开命令行终端并输入以下命令以停止 Apache 服务器：

```
    service apache2 stop
```

请记住，上一个命令不会在启动后生效。启动后，您需要再次输入命令。幸运的是，可以通过提供`update-rc.d apache2 defaults`命令在 Kali Linux 启动后自动启动 Apache HTTP 服务。

1.  该命令将添加`apache2`服务以在启动时启动。

# MySQL

我们将讨论的第二个服务是 MySQL。它是一个关系型数据库系统。MySQL 通常与 PHP 编程语言和 Apache Web 服务器一起使用，以创建动态的基于 Web 的应用程序。对于渗透测试过程，您可以使用 MySQL 来存储您的渗透测试结果，例如漏洞信息和网络映射结果。当然，您需要使用应用程序来存储这些结果。

要在 Kali Linux 中启动 MySQL 服务，可以执行以下步骤：

1.  在终端窗口中，输入以下内容：

```
    service mysql start
```

1.  要测试您的 MySQL 是否已经启动，您可以使用 MySQL 客户端连接到服务器。我们定义用户名（`root`）和密码以登录到 MySQL 服务器：

```
    mysql -u root
```

系统将回复以下内容：

```
    Enter password:
    Welcome to the MySQL monitor. Commands end with ; or g.
    Your MySQL connection id is 39
    Server version: 5.5.44-1 (Debian)
    Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.

    Oracle is a registered trademark of Oracle Corporation and/or its
    affiliates. Other names may be trademarks of their respective
    owners.

    Type ''help;'' or ''h'' for help. Type ''c'' to clear the current input statement.
    mysql>

```

1.  在此 MySQL 提示之后，您可以提供任何 SQL 命令。要退出 MySQL，只需输入`quit`。

出于安全原因，默认情况下，Kali Linux 中的 MySQL 服务只能从本地机器访问。您可以通过编辑位于`/etc/mysql/my.cnf`中的 MySQL 配置文件中的 bind-address 段来更改此配置。我们不建议您更改此行为，除非您希望从其他地方访问您的 MySQL。

要停止 MySQL 服务，您可以执行以下步骤：

1.  在终端窗口中，输入以下内容：

```
    service mysql stop
```

1.  要在 Kali Linux 启动后自动启动 MySQL 服务，可以使用以下命令：

```
    update-rc.d mysql defaults
```

此命令将使 MySQL 服务在启动后启动。

# SSH

在下一个服务中，我们将研究**安全外壳**（**SSH**）。SSH 可用于安全地登录到远程计算机；除此之外，SSH 还有其他几种用途，如在两台计算机之间安全传输文件，执行远程计算机中的命令以及 X11 会话转发。

要在 Kali Linux 中管理您的 SSH 服务，请执行以下步骤：

1.  要从命令行启动 SSHD 服务，请输入以下内容：

```
    service ssh start
```

1.  要测试您的 SSH，您可以使用 SSH 客户端（如 Putty ([`www.chiark.greenend.org.uk/~sgtatham/putty/`](http://www.chiark.greenend.org.uk/~sgtatham/putty/)））从另一台服务器登录到 Kali Linux 服务器，如果您使用的是 Microsoft Windows 操作系统。

1.  要停止 SSHD 服务，请从命令行输入以下内容：

```
    service ssh stop
```

1.  要在 Kali Linux 启动后自动启动 SSH 服务，可以使用以下命令：

```
    update-rc.d ssh defaults
```

此命令将添加 SSH 服务以在启动时启动。

# 其他实验室和资源

虽然我们的主要重点是 Windows 10、Metasploitable 2 和 Metasploitable 3，但还有其他几个类似的项目可用于探索漏洞并测试您的技能。经验丰富的安全专家和渗透测试人员可能还记得一个名为 BadStore 的微小易受攻击的 Web 服务器。这个易受攻击的服务器不超过 15MB（是的，兆字节），包含了从跨站脚本到 SQL 注入的几个漏洞。虽然官方网站上不再提供直接下载，但仍然可以在网络上找到。

[`www.vulnhub.com/`](https://www.vulnhub.com/) 正是其域名所指示的：一个漏洞项目的中心。该网站列出了几个易受攻击的虚拟机供下载，可用于练习和**夺旗赛**（**CTF**）场景和比赛，包括 Damn Vulnerable Linux，Kioptrix 等。

还有一些网站专门为那些有兴趣在受控环境中练习技能或学习的人而存在：

+   **战争游戏**：位于[`overthewire.org/wargames/`](http://overthewire.org/wargames/)，有基本到高级级别，可免费练习：

****![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e7537e08-41f5-4aeb-8d1a-c5d0b9abcdf7.png)****

+   **Hack this site**：[Hackthissite.org](http://www.hackthissite.org)也有许多挑战（左下角），并为初学者和程序员提供任务。这些挑战是免费的，但需要注册：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0f6976b9-2dff-4fdd-8a70-b9455cb133f7.png)

+   **Hellbound Hackers**：与 Hack This Site 一样，Hellbound Hackers ([`www.hellboundhackers.org/`](https://www.hellboundhackers.org/))也提供许多免费挑战，包括渗透测试挑战。还需要注册才能访问这些挑战：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/701f5082-517c-4a3e-a6ce-89e5840bd5f8.png)

# 总结

在本章中，我们讨论了为渗透测试创建实验室环境。正如所解释的，您的实验室设置将完全取决于您可用的资源，如 CPU、RAM 和 HDD 空间。最好尝试尽可能多地使用不同的操作系统，包括 Windows、Linux、Mac、Android，甚至 ARM 操作系统（可在[`www.vulnhub.com/`](https://www.vulnhub.com/)上找到），以便在一个受控环境中获得一些经验，您可以在其中合法地进行测试。

如果使用 Metasploitable 服务器，我们建议初学者，包括时间有限的专业人士，使用 Metasploitable 2 OS，因为 Metasploitable 3 OS 的设置非常复杂——构建可以针对特定的主机操作系统。

资源有限的用户也可以使用较小的易受攻击的操作系统，如 BadStore 和 DVL，这些操作系统与 Metasploitable 2 一样，以 ISO 格式提供，并且只需进行少量设置即可安装。

建议您的实验室至少有一个 Windows 和一个 Linux 操作系统用于测试和学习。接下来，我们将看看渗透测试可用的各种方法。

# 问题

让我们尝试根据你从本章中获取的知识来回答一些问题：

1.  有哪两个虚拟化平台可以用来创建和托管虚拟机？

1.  `.vmdk`代表什么？

1.  Metasploitable 2 的默认登录凭据是什么？

1.  如果从头开始构建 Metasploitable 3 服务器，还需要哪些额外的软件？

1.  在 Kali Linux 中用于安装新软件包或更新现有软件包的命令是什么？

1.  用于启动 MySQL 服务的命令是什么？

1.  用于启动 SSH 服务的命令是什么？

# 进一步阅读

+   **安装 Metasploitable 2**：[`metasploit.help.rapid7.com/docs/metasploitable-2`](https://metasploit.help.rapid7.com/docs/metasploitable-2)

+   **构建 Metasploitable 3**：[`github.com/rapid7/metasploitable3`](https://github.com/rapid7/metasploitable3)

+   **完整的 Metasploitable 3 下载（6 GB 文件）**：[`mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI`](https://mega.nz/#!XQxEAABQ!frdh5DgZE-tSb_1ajPwLZrV4EZuj1lsS3WlWoLPvBjI)


# 第三章：渗透测试方法论

进行成功的渗透测试的一个最关键因素是基本方法。缺乏正式的方法意味着缺乏统一性，我相信你不想成为资助渗透测试并看着测试人员毫无头绪地探索的人。

方法论定义了在任何信息安全审计程序过程中追求和实施的一组规则、实践和程序。渗透测试方法论定义了一个具有实用想法和经过验证实践的路线图，可以用来评估网络、应用程序、系统或任何组合的真实安全状况。

虽然渗透测试人员的技能需要针对工作具体要求，但进行测试的方式不应该是固定的。也就是说，适当的方法应该为进行完整和真实的渗透测试提供一个细致的框架，但不应该是障碍性的——它应该允许测试人员充分探索他们的直觉。

# 技术要求

你必须在系统中安装 Kali Linux 和 Nmap，因为我们将在本章中使用它们。

# 渗透测试方法论

在确定测试类型时，了解不同类型的测试及其组成是很重要的；这可以分为三组：

+   **白盒渗透测试**：在这种情况下，测试人员完全可以访问并深入了解正在测试的系统。测试人员与客户合作，并可以访问内部信息、服务器、正在运行的软件、网络图表，有时甚至可以获得凭据。这种测试类型通常用于在应用投入生产之前测试新应用程序，并作为**系统开发生命周期**（**SDLC**）的一部分进行常规测试；这有助于在投入生产之前识别漏洞并加以修复。

+   **黑盒渗透测试**：在黑盒渗透测试方法中，只向测试人员提供高层次的信息。测试人员对系统/网络完全不了解，使得这种测试类型尽可能接近真实世界。测试人员必须在客户的同意下使用创造性方法获取所有信息。虽然这种方法模仿了真实世界，但有时在测试时可能会错过一些领域。如果范围没有正确确定，这对客户来说可能会非常昂贵，也会耗费时间。测试人员将探索所有攻击向量并报告他们的发现。测试人员必须小心，因为在这种类型的测试中可能会出现问题。

+   **灰盒渗透测试**：在两个极端之间是灰盒渗透测试；测试人员只能获得有限的信息来从外部攻击系统。这些测试通常在有限的范围内进行，并且测试人员对系统有一些了解。

无论选择哪种测试，遵循标准或指南以确保最佳实践也是很重要的。我们将更详细地讨论一些最流行的标准。

+   OWASP 测试指南

+   PCI 渗透测试指南

+   渗透测试执行标准

+   NIST 800-115

+   **开放源安全测试方法手册**（**OSSTMM**）

# OWASP 测试指南

**开放式 Web 应用程序安全项目**（**OWASP**）是一个开源社区项目，开发软件工具和基于知识的文档，帮助人们保护 Web 应用程序和 Web 服务的安全。OWASP 是系统架构师、开发人员、供应商、消费者和参与设计、开发、部署和测试 Web 应用程序和 Web 服务安全的安全专业人员的开源参考点。简而言之，OWASP 旨在帮助每个人构建更安全的 Web 应用程序和 Web 服务。OWASP 测试指南最好的方面之一是对发现的业务风险进行全面描述。OWASP 测试指南根据其对业务可能产生的影响和发生的机会对风险进行评级。通过 OWASP 测试指南描述的这些方面，可以找出给定发现的整体风险评级，从而根据其发现结果为组织提供适当的指导。

OWASP 测试指南主要关注以下内容：

+   Web 应用程序测试中的技术和工具

+   信息收集

+   身份验证测试

+   业务逻辑测试

+   数据验证测试

+   拒绝服务攻击测试

+   会话管理测试

+   Web 服务测试

+   AJAX 测试

+   风险严重性

+   风险可能性

# PCI 渗透测试指南

对于需要遵守 PCI 要求的公司来说，情况变得更加现实。不仅要求使用 PCI v3.2，PCI 标准安全委员会还发布了关于将渗透测试作为漏洞管理计划的一部分的指导。

2016 年 4 月，**支付卡行业安全标准委员会**（**PCI SSC**）发布了**PCI 数据安全标准**（**PCI DSS**）版本 3.2。更新内容包括对要求的澄清、额外指导和七个新要求。

为了解决与持卡人数据泄露相关的问题并防止现有的利用，PCI DSS v.3.2 包括各种变化，其中大部分是针对服务提供商的。这包括新的渗透测试要求，现在要求服务提供商至少每六个月或在分割控制/方法发生重大变化后进行分割测试。此外，还有几项要求，以确保服务提供商在整年内持续监控和维护关键的安全控制。

# 渗透测试执行标准

渗透测试执行标准包括七个主要部分。它们涵盖了渗透测试的一切内容 - 从渗透测试背后的初步沟通和努力；通过信息收集和威胁建模阶段，测试人员在幕后工作，以更好地了解被测试的公司；通过漏洞研究、利用和后利用，测试人员的实际安全知识发挥作用并与业务智能结合；最后是报告，它以客户能够理解的格式概述了整个过程。

这个版本可以被视为 v1.0，因为标准的核心元素已经巩固，并且已经通过行业进行了一年的现场测试。v2.0 正在制作中，将在各个级别提供更细粒度的工作，即渗透测试的每个元素可以进行的强度级别。由于没有两次渗透测试是相同的，测试将从 Web 应用程序或网络测试到全面的红队黑盒参与，这些级别将使组织能够概述他们期望测试人员揭示的复杂程度，并使测试人员在组织认为必要的领域加强强度。级别的一些初始工作可以在情报收集部分中看到。

以下是标准定义的执行渗透测试的主要部分：

+   预先交互

+   情报收集

+   威胁建模

+   漏洞分析

+   利用

+   后期利用

+   报告

# NIST 800-115

**国家标准与技术研究所特别出版物**（**NIST-SP-800-115**）是信息安全测试和评估的技术指南。该出版物由 NIST 的**信息技术实验室**（**ITL**）制作。

该指南将安全评估定义为确定被评估实体如何满足特定安全要求的过程。当你审查该指南时，你会发现它包含了大量测试信息。虽然该文件的更新频率不如我们希望的那样频繁，但它是我们在构建测试方法论时的一个可行资源。

它们提供了设计、实施和维护技术信息、安全测试和审查过程和程序的实用指南，涵盖了技术安全测试和审查的关键元素。

这些可以用于多种原因，比如发现系统或网络中的漏洞，验证合规性或其他要求。该指南并不旨在提供全面的信息安全测试和审查程序，而是概述了技术安全测试和审查的关键要素，重点是特定的技术技巧，每种技巧的优缺点以及对其使用的建议。

NIST 800-115 标准为渗透测试人员提供了一个被接受的行业标准的地图。这个模型是确保你的渗透测试程序符合最佳实践的好方法。

# 开放源安全测试方法手册

OSSTMM 并不是最容易或最有趣的文件，但它充满了实用和相关的高级安全信息。它也是全球最知名的操作安全手册，每个月约有 50 万次下载，原因是：那些搞清楚它的人在安全方面具有明显的优势，因为它的指导比安全行业当前的热点大约领先了十年。

OSSTMM 的目标是提出一个互联网安全测试的标准。它旨在形成一个完整的测试基线，遵循该基线可以确保进行了彻底和全面的渗透测试。这应该使客户相信技术评估的水平，而不受其他组织关注的影响，比如渗透测试提供商的企业概况。

# 一般渗透测试框架

虽然这些标准在要求数量上有所不同，但它们可以大致分为以下阶段：

+   侦察

+   扫描和枚举

+   获取访问

+   权限升级

+   保持访问

+   掩盖你的踪迹

+   报告

让我们更详细地看看每个阶段。

# 侦察

你的渗透测试时间的大部分将花在测试的这个关键部分。虽然有些人将这个阶段分为主动和被动，但我更喜欢将它们合并在一起，因为获取的数据会说明一切。

侦察是一种系统化的方法，你试图定位并收集有关目标的尽可能多的信息，这也被称为足迹技术。

足迹技术涉及的技术包括但不限于以下内容：

+   社会工程学（这很有趣）

+   互联网研究（谷歌、必应、LinkedIn 等）

+   垃圾箱搜寻（弄脏你的手）

+   冷调

基本上任何你可以获取目标信息的方式，所以要有创造力。那么，我们在寻找什么呢？

每一点信息都是有用的，但需要优先考虑，并记住一开始可能认为无用的东西可能在其他地方派上用场。但首先重要的事情将是以下内容：

+   组织内的联系人姓名

+   组织的其他位置（如果有的话）

+   电子邮件地址（以后可以用于钓鱼、鲸鱼或鱼叉式钓鱼）

+   公司内重要人物的电话号码（这些可以用于钓鱼）

+   公司使用的系统，如 Windows 或 Linux

+   招聘启事

+   员工简历（过去/现在）

虽然所有这些可能都是不言自明的，但招聘启事似乎有点奇怪；然而，假设您遇到了一个系统管理员的招聘启事，并且根据他们要求的职位要求，这将为您提供有关他们内部系统的大量信息。然后可以用来制定攻击向量或找到漏洞。

员工简历以类似的方式工作；通过了解员工的技能，您可以确定他们可能正在运行的系统类型。

虽然这可能看起来很繁琐，但请记住，拥有的信息越多，以后做决定时就会更有能力。我个人发现自己在整个过程中都会回到这个阶段。

# 扫描和枚举

毫无疑问，几乎每个安全专业人员都想立即开始利用漏洞，但没有理解基础知识、漏洞，最重要的是他们所处的环境。这可能会导致错误，或者更糟糕的是，在实时环境中出现问题。

扫描和枚举允许渗透测试人员了解他们的环境。从这些扫描中得到的结果为红队提供了一个利用不同系统漏洞的起点。扫描是找到目标主机上运行的所有可用网络服务（TCP 和 UDP）。这可以帮助红队发现 SSH/Telnet 是否开放以尝试暴力登录，发现文件共享以下载数据，可能存在漏洞的网站，或者可能保存用户名和密码的打印机。枚举是发现网络上的服务，以获得网络服务提供的更多信息。

# 扫描

当怀疑缓解控制措施，如防火墙、入侵检测系统和文件完整性监控时，进行全面渗透测试是理想的。扫描将找到单个漏洞；然而，渗透测试将尝试验证这些漏洞在目标环境中是否可利用。让我们来看看每种类型。

# ARP 扫描

通过使用 ARP 广播，我们可以利用获取 IP 信息。每个 ARP 广播帧都会请求谁拥有哪个 IP 地址——每次增加一个 IP 地址。一旦主机拥有该 IP 地址，它将以所请求的 IP 地址和其 MAC 地址回应请求。

ARP 扫描是一种有效快速的方法，通常不会引起任何警报；但问题在于 ARP 是一个第二层协议，所以它不能跨越网络边界。这意味着如果红队在网络`192.100.0.0/24`上，而您的目标在网络`10.16.X.0/24`上，您无法向`10.16.X.0/24`发送 ARP 请求。

# 网络映射器（Nmap）

Nmap 是端口扫描和枚举中的佼佼者。在本指南中涵盖 Nmap 的所有选项和模块超出了本书的范围；相反，我们将介绍我在测试时主要使用的扫描。但首先，这里有一些关于端口状态的信息：

+   **开放**：目标机器上的应用正在监听该端口的连接/数据包

+   **关闭**：端口上没有应用程序在监听，但随时可能打开

+   **过滤**：防火墙、过滤器或其他网络障碍正在阻止端口，因此 Nmap 无法确定它是开放还是关闭的

以下是 Nmap 可用的选项：

+   `O`：操作系统检测

+   `p`：端口扫描

+   `p-`：扫描所有端口（`1-65535`）

+   `p 80,443`：扫描端口`80`和`443`

+   `p 22-1024`：扫描端口`22`到`1024`

+   `top-ports X`：`X`是一个数字，它将扫描`X`个最受欢迎的端口；我通常用 100 进行快速扫描。

+   `sV`：服务检测

+   `Tx`：设置扫描速度

+   `T1`：非常慢的端口扫描

+   `T5`：非常快的端口扫描（非常吵闹）

+   `sS`：隐秘扫描

+   `sU`：UDP 扫描

+   `A`：操作系统检测，版本检测，脚本扫描和路由跟踪

# Nmap 端口扫描器/TCP 扫描

这项服务将通过在目标主机的每个端口上发起（SYN）连接来开始。如果端口是开放的，主机将用（SYN`，`ACK`）回应。连接将由发起方发送的复位（`RST`）关闭：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e7b85063-c1d9-4dd4-b6c6-cd7bf039fe9b.jpg)

# Nmap 半开放/隐秘扫描

这个选项将通过在目标主机的每个端口上发送（`SYN`）连接来开始。如果端口是开放的，主机将用（`SYN`，`ACK`）回复请求。

如果端口没有打开（即关闭），主机将用连接复位（`RST`）回答。

如果没有收到响应，就假定端口被过滤了。TCP 扫描和隐秘扫描的区别在于连接发起方不会用确认（`ACK`）数据包来回应。这种扫描的有效之处在于，由于没有建立完整的连接，所以不会被记录日志。

# Nmap 操作系统检测

这个选项将使用各种技术来尝试识别操作系统类型和版本。这对于漏洞检测非常有用。快速搜索操作系统版本将显示已知的漏洞和操作系统的利用，以便更好地了解网络情况，使用以下命令：

```
nmap 172.16.54.144 –O
```

# Nmap 服务检测

与操作系统检测类似，这个选项试图确定服务和版本，如下图所示：

```
nmap 172.16.54.144 –sV 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8793c2c4-5088-43c1-ae9e-c59c7214c887.png)

# Nmap ping 扫描

这个选项将向给定范围内的每个 IP 地址发送一个 ICMP 请求。如果主机处于启动状态并且配置为响应 ping 请求，它将用 ICMP 回复回应，如下图所示：

```
nmap 172.16.54.0/24 –sP
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8a7a6fc0-b8f7-4ced-97eb-0c6fa195f82d.png)

# 枚举

枚举作为发现 Web 应用程序中的所有攻击和弱点的基础。开发视图将这些攻击和弱点合并为漏洞，并根据它们在相关开发阶段的发生进行分类。这可能是设计、实施或部署阶段。有几种枚举技术；我们将看一些。

# SMB 共享

**SMB**代表**服务器消息块**。这是一种由 IBM 发明的文件共享协议，自 20 世纪 80 年代中期以来一直存在。SMB 协议旨在允许计算机通过**局域网**（**LAN**）读取和写入远程主机上的文件。通过 SMB 提供的远程主机上的目录称为共享。

这种技术有几个好处，我们将讨论。

# DNS 区域传输

DNS 是我最喜欢的协议，因为它是信息的宝库。如果可以请求区域传输，测试人员可以获得特定区域的所有 DNS 记录。这将确定网络中所有主机的主机名到 IP 地址的关系。如果攻击者对网络方案有任何了解，这可能是发现网络上所有主机的最快方法。DNS 还可以显示运行在网络上的服务，如邮件服务器。

# DNSRecon

DNSRecon 是我用于 DNS 侦察和枚举的首选工具。在这个例子中，我们将从`domain.foo`请求区域传输。运行在`domain.foo`上的 DNS 服务器将返回它所知道的所有`domain.foo`和与之相关的任何子域的记录。这为我们提供了服务器名称及其相应的主机名和 IP 地址。它返回了所有 DNS 记录，其中包括`TXT 记录（4）`，`PTR 记录（1）`，`邮件服务器的 MX 记录（10）`，`IPv6 A 记录（2）`和`IPv4 A 记录（12）`。这些记录提供了关于网络的一些非常有价值的信息。其中一条记录显示了他们 DC 办公室的 IP 地址，另一条显示了他们防火墙设备的 IP 地址，另一条显示了他们有 VPN 及其 IP 地址，另一条记录显示了邮件服务器登录门户的 IP 地址，如下图所示：

```
 dnsrecon -d zonetranfer.zone -a
 -d: domain
 -a: perform zone transfer
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ccd1dbba-cc78-45ea-8235-53a5ac4a116b.png)

# SNMP 设备

**简单网络管理协议**，简称**SNMP**，用于记录和管理网络设备和应用程序。SNMP 可用于远程配置设备和应用程序，但如果未经安全配置，也可以用于获取有关所述应用程序和设备的信息。这些信息可以用于更好地了解网络：

```
snmpwalk 192.16.1.1 -c PUBLIC
```

`-c`：这是用于对设备进行身份验证的社区字符串。

# 数据包捕获

在诊断网络问题、嗅探凭据或者如果你喜欢查看流量的话，捕获两个主机之间的数据包可能非常有帮助。

# tcpdump

这是一个用于从网络上嗅探特定类型的流量和数据的命令行实用程序：

+   `-i eth0`：选择要监听的接口

+   `端口 80`：选择要监听的端口

+   `host 172.16.1.1`：仅收集发送至/来自主机的流量。

+   `src`：数据来源

+   `dst`：数据发送至

+   `-w output.pcap`：将流量捕获到磁盘文件上

# Wireshark

这是一个用于从网络上嗅探流量的图形化实用程序，如下图所示：

+   `ip.addr/ip.dst/ip.src == 172.16.1.1`

+   `tcp.port/tcp.dstport/tcp.srcport == 80`

+   `udp.port/udp.dstport/udp.srcport == 53`

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/04021e39-e0bc-475e-ab75-f0b2fdfad2ec.png)

# 获取访问权限

在这个阶段，渗透测试人员试图在公司的内部网络中立足。如今，针对特定目标的网络钓鱼似乎是一种非常常见和有效的方法。一个精心制作的网络钓鱼活动可以针对公司发起，并根据侦察阶段收集的信息创建一个令人信服的场景。

获取访问权限也可以包括使用远程服务上的漏洞/凭据登录系统，然后执行有效负载。

Metasploit 和 PowerShell Empire 可以帮助实现这一点，因为它们都创建有效负载，也称为分段器。一旦分段器在目标上执行，它就在内存中运行。这种方式几乎不留下任何取证证据。另一种情况是将二进制文件推送到远程系统并通过命令行执行该二进制文件，这种方法同样有效。这种方法更快，不依赖于互联网下载的成功。

# 漏洞利用

有时测试人员可能会遇到可以利用的服务。利用可能是初始访问的手段；只要确保利用是 100%可靠的。此外，多次运行利用可能会导致系统崩溃。这种初始访问选项通常需要极度小心使用，除非你已经测试过并知道自己在做什么。

总是 SSH！也许不总是，但我从来没有见过/记得其他服务被使用，除了 telnet，而 telnet 本来就不应该被使用。SSH 和 Linux 就像花生酱和果冻一样搭配。

# 针对 Linux 的漏洞利用

Linux 漏洞通常不是针对操作系统本身，而是针对正在运行的服务。在这里，你会找到一些常见的针对 Linux 系统的漏洞利用。请记住，漏洞利用会因发行版和服务版本而异：

+   CVE-2018-1111

+   发现 Red Hat Linux DHCP 客户端易受命令注入攻击

+   CVE-2017-7494

# Windows 的漏洞利用

Windows 漏洞利用通常针对操作系统的监听服务。以下是针对运行在 Windows 端口`445`上的 SMB 服务的列表：

+   Eternalblue – MS17-010

+   MS08-67

+   MS03-026

以下是一些渗透测试人员经常使用的工具：

+   PsExec：

PsExec 是 Sysinternals 工具包中包含的工具；它用于远程管理，是渗透测试人员、系统管理员和黑客中的常用工具。 PsExec 二进制文件通常被复制到机器上的`$admin`共享中，然后它使用远程管理在远程机器上创建服务。请记住，PsExec 需要远程机器上的管理员权限：

1.  下载 Sysinternals

1.  打开 PowerShell 提示符

1.  输入`cd <Sysinternals directory>`

1.  输入`.\PSexec \\<IP addr of remote machine> -u <user> -p <password> <cmd>`

以下截图显示了获得的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/dae8e366-79c3-4495-b2e7-d7480040a970.png)

+   **Impacket**：用于处理网络协议的 Python 类的集合。

初始设置如下：

1.  打开终端

1.  输入`cd /tmp`

1.  输入`git clone https://github.com/CoreSecurity/impacket.git`

1.  输入``pip install ``

使用以下命令在 Impacket 上启用 PSexec、WMI 和 SMBexec：

+   **PSexec**：

```
psexec.py <username>:<password>@<ip addr> powershell 
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c003864d-8685-4e44-958b-99db69f08480.png)

+   **WMI**：

```
wmiexec.py <username>:<password>@<ip addr> powershell
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f2e5b4ed-0d69-47a3-a4b4-89a06785013c.png)

+   **SMBexec**：

```
wmiexec.py <username>:<password>@<ip addr>
```

上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c8fb7f96-8772-48ee-8415-ee87b72b1662.png)

+   **PS-Remoting**：

要在目标机器上启用 PS-Remoting，请执行以下步骤：

1.  在目标机器上以管理员身份打开 PowerShell

1.  输入以下内容：``powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((new-object net.webclient).DownloadString('https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1'))"``

1.  启用 PS-Remoting

1.  输入`winrm set winrm/config/client/auth '@{Basic="true"}'`

1.  输入`winrm set winrm/config/service/auth '@{Basic="true"}'`

1.  输入`winrm set winrm/config/service '@{AllowUnencrypted="true"}'`

要在目标机器上启用 PS-Remoting，请执行以下步骤：

1.  打开 PowerShell。

1.  输入`$options=New-PSSessionOption -SkipCACheck -SkipCNCheck`

1.  输入`$cred = Get-Credential`。这将提示您输入凭据。

1.  输入`Enter-PSSession -ComputerName <hostname> -UseSSL -SessionOption $options -Credential $cred`。

您将看到配置详细信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/75e0a572-9ac1-45f7-bfd7-b6f83bfc2ee6.png)

类似地，我们还将看到如何在远程目标上启用 WMI 并使用 WMI 访问远程目标

+   **WMI**：在远程目标上启用 WMI 可以通过以管理员身份打开 PowerShell 并运行以下命令来完成：

```
netsh firewall set service RemoteAdmin enable
```

要使用 WMI 访问远程目标，可以通过打开 PowerShell，输入以下命令并观察输出，如下截图所示：

`wmic /node:<target IP addr> /user:<username> process call create "cmd.exe /c <command>"`

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d06895ad-278a-4745-96eb-05fe23feaaa5.png)

# 提升权限

一旦机器被入侵，通常获得的任何访问都是低权限的。由于任何渗透测试的想法都是模拟真实世界的攻击，这包括寻找通常保存在受限制服务器上的敏感信息；测试人员需要找到提升权限的方法。在 Windows **Active Directory** (**AD**)环境中，这意味着获得对域管理员帐户的访问。

# 保持访问

一旦建立了立足点（即远程访问），就可以很快地删除它，因为系统可以重新启动，用户可以注销。这就是持久访问的地方；可以通过多种方式实现。持久访问的最佳策略是同时使用多种技术。

例如，可以在网络中种植一个物理后门（Dropbox），以后可以在其无线范围内访问。更有创意的方法是在受损的机器上设置一个定时任务，在启动时定期执行，例如每天一次：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0ae73856-6260-4e95-8b96-aea0dfb0caf3.png)

# 掩盖你的踪迹

所有的参与都应该得到客户的授权，无论如何。这并不是说在所有的扫描和利用结束后就收拾包袱回家；仍然有人必须以客户能理解的方式向客户呈现发现的结果。但在此之前，我们必须清理环境中留下的漏洞或工具。有时这可能意味着删除二进制文件或编辑日志，我说编辑是因为任何看不到日志的系统管理员都应该非常快速地感到担忧。由于 Windows 和 Linux 都有各自的日志机制，并且它们都有很好的文档记录，所以这里不需要涵盖它们。我建议你跟踪你在系统上所做的更改，并在需要隐藏东西时要有创意；使用系统服务名称或用户名来适应账户，例如，不要将账户命名为`EliteHAK3R`。

# 报告

这将我们带到测试的最后一部分，有些人会说这是最无聊的部分；然而，如果你遵循了前面的阶段，报告不应该是乏味或困难的。我会在进行过程中做笔记，无论是在纸上还是使用 Dradis，这是一个内置的 Kali 工具，可以通过`service dradis start`来召唤。请记住它是一个 Web 服务，所以局域网上的任何人都可以使用`https://kali 机器的 IP:3004`URL 来访问它 - 在第一次运行时，它会提示您设置密码。

Dradis 允许您从 Nmap、NESSUS、NEXPOSE 等导入文件，这使得与队友一起工作时记笔记变得轻松；您可以轻松共享信息并随时了解最新的扫描结果。

# 总结

本章向您介绍了渗透测试中的各种方法，目的是规划和范围渗透测试。下一章将带您了解使用被动和主动技术来发现和收集有关目标和环境的信息和数据。


# 第四章：足迹和信息收集

在本章中，我们将讨论渗透测试的信息收集阶段。我们将描述信息收集的定义和目的。我们还将描述 Kali Linux 中可以用于信息收集的几种工具。阅读完本章后，我们希望读者能更好地理解信息收集阶段，并能够在渗透测试期间进行信息收集。

信息收集是我们渗透测试过程（Kali Linux 测试过程）中的第二阶段，如第三章中的 Kali Linux 测试方法论部分所述，*渗透测试方法论*。在这个阶段，我们试图收集尽可能多的关于目标的信息，例如**域名系统**（**DNS**）主机名、IP 地址、使用的技术和配置、用户名的组织、文档、应用程序代码、密码重置信息、联系信息等等。在信息收集期间，收集到的每一条信息都被认为是重要的。

根据使用的方法，信息收集可以分为两种方式：主动信息收集和被动信息收集。在主动信息收集方法中，我们通过向目标网络引入网络流量来收集信息，而在被动信息收集方法中，我们通过利用第三方服务（如谷歌搜索引擎）来收集有关目标网络的信息。我们将在后面进行介绍。

请记住，这两种方法都没有比另一种更好；每种方法都有其自身的优势。在被动扫描中，您收集的信息较少，但您的行动将是隐秘的，而在主动扫描中，您可以获得更多信息，但某些设备可能会察觉到您的行动。在渗透测试项目中，这个阶段可能会多次进行，以确保收集到的信息完整。您还可以与您的渗透测试客户讨论他们想要哪种方法。

在本章中，我们将利用被动和主动的信息收集方法来更好地了解目标。

在本章中，我们将讨论以下主题：

+   可用于收集有关目标域的信息的公共网站

+   域名注册信息

+   DNS 分析

+   路线信息

+   搜索引擎利用

# 开源情报

与信息收集经常相关的一个关键术语是**开源情报**（**OSINT**）。军事和情报组织将他们的情报来源分为各种类型。真正的间谍活动，涉及间谍之间的互动，通常被称为**人类情报**（**HUMINT**）。以破解加密为目的捕获无线电信号被称为**信号情报**（**SIGINT**）。虽然渗透测试人员不太可能与这两者中的任何一种进行接触，但信息收集阶段是 OSINT。OSINT 是从没有安全控制阻止其披露的来源获取的信息。它们通常是公共记录或目标组织作为其日常运营的一部分分享的信息。

对于渗透测试人员来说，要利用这些信息，他们需要特定的知识和工具来找到这些信息。信息收集阶段在很大程度上依赖于这些信息。此外，简单地向组织展示他们泄露的 OSINT 信息可能会让他们了解到需要增加安全性的领域。正如我们将在本章中看到的，对于那些知道在哪里寻找的人来说，有大量信息是可见的。

# 使用公共资源

在互联网上，有几个可以用于收集有关目标域的信息的公共资源。使用这些资源的好处是，您的网络流量不会直接发送到目标域，因此您的活动不会记录在目标域日志文件中。

以下是可以使用的资源：

| No. | 资源 URL | 描述 |
| --- | --- | --- |
| 1 | [`www.archive.org`](http://www.archive.org) | 这包含网站的存档。 |
| 2 | [`www.domaintools.com/`](http://www.domaintools.com/) | 这包含域名情报。 |
| 3 | [`www.alexa.com/`](http://www.alexa.com/) | 这包含有关网站的信息数据库。 |
| 4 | [`serversniff.net/`](http://serversniff.net/) | 这是用于网络、服务器检查和路由的免费**瑞士军刀**。 |
| 5 | [`centralops.net/`](http://centralops.net/) | 这包含免费的在线网络实用工具，如域名、电子邮件、浏览器、ping、traceroute 和 Whois。 |
| 6 | [`www.robtex.com`](http://www.robtex.com) | 这允许您搜索域和网络信息。 |
| 7 | [`www.pipl.com/`](http://www.pipl.com/) | 这允许您通过他们的名字、姓氏、城市、州和国家在互联网上搜索人。 |
| 8 | [`wink.com/`](http://wink.com/) | 这是一个免费的搜索引擎，允许您通过姓名、电话号码、电子邮件、网站、照片等查找人。 |
| 9 | [`www.isearch.com/`](http://www.isearch.com/) | 这是一个免费的搜索引擎，允许您通过姓名、电话号码和电子邮件地址查找人。 |
| 10 | [`www.tineye.com`](http://www.tineye.com) | TinEye 是一个反向图像搜索引擎。我们可以使用 TinEye 找出图像来自何处，如何使用它，是否存在修改版本的图像，或者找到更高分辨率的版本。 |
| 11 | [`www.sec.gov/edgar.shtml`](http://www.sec.gov/edgar.shtml) | 这可用于搜索证券交易委员会中公开上市公司的信息。 |

由于易于使用——您只需要互联网连接和网络浏览器——我们建议您在使用 Kali Linux 提供的工具之前首先使用这些公共资源。

为了保护域名不被滥用，我们已经更改了我们在示例中使用的域名。我们将使用一些域名，例如来自 IANA 的`example.com`和免费的黑客测试网站[`www.hackthissite.org/`](https://www.hackthissite.org/)，以进行说明。

# 查询域名注册信息

在了解目标域名后，您首先要做的是查询`Whois`数据库有关该域名的信息，以查找域名注册信息。`Whois`数据库将提供有关域名的 DNS 服务器和联系信息的信息。

`Whois`是一种用于搜索互联网注册、已注册域名、IP 和自治系统的协议。该协议在 RFC 3912 中指定（[`www.ietf.org/rfc/rfc3912.txt`](https://www.ietf.org/rfc/rfc3912.txt)）。

默认情况下，Kali Linux 已经配备了`whois`客户端。要查找域的`Whois`信息，只需输入以下命令：

```
    # whois example.com

```

以下是`Whois`信息的结果：

```
    Domain Name: EXAMPLE.COM
       Registrar: RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY
    Sponsoring Registrar IANA ID: 376
       Whois Server: whois.iana.org
       Referral URL: http://res-dom.iana.org
       Name Server: A.IANA-SERVERS.NET
       Name Server: B.IANA-SERVERS.NET
       Updated Date: 14-aug-2015
       Creation Date: 14-aug-1995
       Expiration Date: 13-aug-2016
    >>> Last update of whois database: Wed, 03 Feb 2016 01:29:37 GMT <<<

```

从前面的`Whois`结果中，我们可以获得域名的 DNS 服务器和联系人的信息。这些信息将在渗透测试的后期阶段非常有用。

除了使用命令行`Whois`客户端，`Whois`信息也可以通过以下网站收集，这些网站提供了`whois`客户端：

+   [www.whois.net](http://www.whois.net)

+   [www.internic.net/whois.html](http://www.internic.net/whois.html)

您还可以转到相应域名的顶级域名注册商：

+   **美国**：[www.arin.net/whois/](http://www.arin.net/whois/)

+   **欧洲**：[www.db.ripe.net/whois](http://www.db.ripe.net/whois)

+   **亚太地区**：[www.apnic.net/apnic-info/whois_search2](http://www.apnic.net/apnic-info/whois_search2)

注意：要使用顶级域名注册商的`whois`，域名需要通过其自己的系统注册。例如，如果您使用`ARIN WHOIS`，它只在`ARIN WHOIS`数据库中搜索，而不会在`RIPE`和`APNIC Whois`数据库中搜索。

从`Whois`数据库获取信息后，接下来我们想收集有关目标域的 DNS 条目的信息。

# 分析 DNS 记录

使用 DNS 记录类别中的工具的目标是收集有关目标域的 DNS 服务器和相应记录的信息。

以下是几种常见的 DNS 记录类型：

| No. | 记录类型 | 描述 |
| --- | --- | --- |
| 1 | SOA | 这是权威记录的开始。 |
| 2 | NS | 这是名称服务器记录。 |
| 3 | A | 这是 IPv4 地址记录。 |
| 4 | MX | 这是邮件交换记录。 |
| 5 | PTR | 这是指针记录。 |
| 6 | AAAA | 这是 IPv6 地址记录。 |
| 7 | CNAME | 这是规范名称的缩写。它用作另一个规范域名的别名。 |

例如，在渗透测试中，客户可能会要求您查找其域名下所有可用的主机和 IP 地址。您唯一拥有的信息是组织的域名。我们将看一些常见的工具，如果您遇到这种情况，可以帮助您。

# 主机

在获取 DNS 服务器信息之后，下一步是查找主机名的 IP 地址。为了帮助我们解决这个问题，我们可以使用以下主机命令行工具来从 DNS 服务器查找主机的 IP 地址：

```
    # host hackthissite.org 
```

默认情况下，`host`命令将查找域的`A`、`AAAA`和`MX`记录。要查询任何记录，只需将`-a`选项提供给命令：

```
    # host -a hackthissite.org
    Trying "hackthissite.org"
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32115
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 12, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;hackthissite.org.    IN  ANY
    ;; ANSWER SECTION:
    hackthissite.org.  5  IN  A  198.148.81.135
    hackthissite.org.  5  IN  A  198.148.81.139
    hackthissite.org.  5  IN  A  198.148.81.137
    hackthissite.org.  5  IN  A  198.148.81.136
    hackthissite.org.  5  IN  A  198.148.81.138
    hackthissite.org.  5  IN  NS  ns1.hackthissite.org.
    hackthissite.org.  5  IN  NS  c.ns.buddyns.com.
    hackthissite.org.  5  IN  NS  f.ns.buddyns.com.
    hackthissite.org.  5  IN  NS  e.ns.buddyns.com.
    hackthissite.org.  5  IN  NS  ns2.hackthissite.org.
    hackthissite.org.  5  IN  NS  b.ns.buddyns.com.
    hackthissite.org.  5  IN  NS  d.ns.buddyns.com.
    Received 244 bytes from 172.16.43.2#53 in 34 ms  
```

`host`命令通过查询 Kali Linux 系统的`/etc/resolv.conf`文件中列出的 DNS 服务器来查找这些记录。如果要使用其他 DNS 服务器，只需将 DNS 服务器地址提供为最后一个命令行选项。

如果您将域名作为`host`命令行选项，该方法称为正向查找，但如果您将 IP 地址作为`host`命令的命令行选项，则该方法称为反向查找。

尝试对以下 IP 地址进行反向查找：

```
    host 23.23.144.81 
```

您可以从这个命令中获得什么信息？

`host`工具也可以用于进行 DNS 区域传输。通过这种机制，我们可以收集有关域中可用主机名的信息。

DNS 区域传输是一种机制，用于将主 DNS 服务器上的 DNS 数据库复制到另一个 DNS 服务器，通常称为从属 DNS 服务器。如果没有这种机制，管理员必须单独更新每个 DNS 服务器。必须向域的权威 DNS 服务器发出 DNS 区域传输查询。

由于 DNS 区域传输可以收集的信息的性质，现在很少能找到允许向任意区域传输请求的 DNS 服务器。

如果您找到一个允许区域传输而不限制谁能够执行它的 DNS 服务器，这意味着 DNS 服务器配置不正确。

# dig

除了`host`命令，您还可以使用`dig`命令进行 DNS 查询。与`host`相比，`dig`的优势在于其灵活性和输出的清晰度。使用`dig`，您可以要求系统从文件中处理一系列查找请求。

让我们使用`dig`来查询[`hackthissite.org`](http://hackthissite.org)域。

除了域名之外，如果没有提供任何选项，`dig`命令将只返回域的 A 记录。要请求任何其他 DNS 记录类型，可以在命令行中提供类型选项：

```
    # dig hackthissite.org
    ; <<>> DiG 9.9.5-9+deb8u5-Debian <<>> hackthissite.org
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44321
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1
    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; MBZ: 0005 , udp: 4096
    ;; QUESTION SECTION:
    ;hackthissite.org.    IN  A
    ;; ANSWER SECTION:
    hackthissite.org.  5  IN  A  198.148.81.139
    hackthissite.org.  5  IN  A  198.148.81.137
    hackthissite.org.  5  IN  A  198.148.81.138
    hackthissite.org.  5  IN  A  198.148.81.135
    hackthissite.org.  5  IN  A  198.148.81.136
    ;; Query time: 80 msec
    ;; SERVER: 172.16.43.2#53(172.16.43.2)
    ;; WHEN: Tue Feb 02 18:16:06 PST 2016
    ;; MSG SIZE  rcvd: 125

```

从结果中，我们可以看到`dig`输出现在返回了`A`的 DNS 记录。

# DMitry

**Deepmagic 信息收集工具**（**DMitry**）是一款多合一信息收集工具。它可用于收集以下信息：

+   使用 IP 地址或域名查询主机的`Whois`记录

+   从[`www.netcraft.com/`](https://www.netcraft.com/)获取主机信息

+   目标域中的子域

+   目标域的电子邮件地址

+   在目标机器上执行端口扫描，打开、过滤或关闭端口列表

尽管可以使用几个 Kali Linux 工具获取这些信息，但使用单个工具收集所有信息并将报告保存到一个文件非常方便。

我们认为这个工具更适合归类为 DNS 分析，而不是*路由分析*部分，因为其功能更多地涉及 DNS 分析而不是路由分析。

要从 Kali Linux 菜单访问`DMitry`，请导航到应用程序|信息收集|dmitry，或者您可以使用控制台并输入以下命令：

```
    # dmitry
```

例如，让我们对目标主机执行以下操作：

+   执行`Whois`查找

+   从[`www.netcraft.com/`](https://www.netcraft.com/)获取信息

+   搜索所有可能的子域

+   搜索所有可能的电子邮件地址

执行上述操作的命令如下：

```
    # dmitry -iwnse hackthissite.org 
```

前述命令的结果摘要如下：

```
    Deepmagic Information Gathering Tool
    "There be some deep magic going on"
    HostIP:198.148.81.138
    HostName:hackthissite.org
    Gathered Inet-whois information for 198.148.81.138
    ---------------------------------
    inetnum:        198.147.161.0 - 198.148.176.255
    netname:        NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK
    descr:          IPv4 address block not managed by the RIPE NCC

    remarks:        http://www.iana.org/assignments/ipv4-recovered-address-space/ipv4-recovered-address-space.xhtml
    remarks:
    remarks:        -----------------------------------------------------
    country:        EU # Country is really world wide
    admin-c:        IANA1-RIPE
    tech-c:         IANA1-RIPE
    status:         ALLOCATED UNSPECIFIED
    mnt-by:         RIPE-NCC-HM-MNT
    mnt-lower:      RIPE-NCC-HM-MNT
    mnt-routes:     RIPE-NCC-RPSL-MNT
    created:        2011-07-11T12:36:59Z
    last-modified:  2015-10-29T15:18:41Z
    source:         RIPE
    role:           Internet Assigned Numbers Authority
    address:        see http://www.iana.org.
    admin-c:        IANA1-RIPE
    tech-c:         IANA1-RIPE
    nic-hdl:        IANA1-RIPE
    remarks:        For more information on IANA services
    remarks:        go to IANA web site at http://www.iana.org.
    mnt-by:         RIPE-NCC-MNT
    created:        1970-01-01T00:00:00Z
    last-modified:  2001-09-22T09:31:27Z
    source:         RIPE # Filtered
    % This query was served by the RIPE Database Query Service version 1.85.1 (DB-2)

```

我们还可以使用`dmitry`通过提供以下命令执行简单的端口扫描：

```
    # dmitry -p hackthissite.org -f -b
```

前述命令的结果如下：

```
    Deepmagic Information Gathering Tool
    "There be some deep magic going on"
    HostIP:198.148.81.135
    HostName:hackthissite.org
    Gathered TCP Port information for 198.148.81.135
    ---------------------------------
     Port    State
    ...
    14/tcp    filtered
    15/tcp    filtered
    16/tcp    filtered
    17/tcp    filtered
    18/tcp    filtered
    19/tcp    filtered
    20/tcp    filtered
    21/tcp    filtered
    22/tcp    open
    >> SSH-2.0-OpenSSH_5.8p1_hpn13v10 FreeBSD-20110102
    23/tcp    filtered
    24/tcp    filtered
    25/tcp    filtered
    26/tcp    filtered
    ...
    79/tcp    filtered
    80/tcp    open
    Portscan Finished: Scanned 150 ports, 69 ports were in state closed
    All scans completed, exiting

```

从前述命令中，我们发现目标主机正在使用设备进行数据包过滤。它只允许端口`22`用于 SSH 的传入连接和端口`80`，这通常用于 Web 服务器。有趣的是，SSH 安装的类型被指出，允许进一步研究对 OpenSSH 安装的可能漏洞。

# Maltego

Maltego 是一款开源情报和取证应用程序。它允许您挖掘和收集信息，并以有意义的方式表示信息。Maltego 中的开源短语意味着它从开源资源中收集信息。在收集信息后，Maltego 允许您确定所收集信息之间的关键关系。

Maltego 是一种可以以图形方式显示数据之间联系的工具，因此将更容易看到信息之间的共同点。

Maltego 允许您枚举以下互联网基础设施信息：

+   域名

+   DNS 名称

+   `Whois`信息

+   网络块

+   IP 地址

它还可以用于收集有关人的以下信息：

+   与该人相关的公司和组织

+   与该人相关的电子邮件地址

+   与该人相关的网站

+   与该人相关的社交网络

+   与该人相关的电话号码

+   社交媒体信息

Kali Linux 默认配备了 Maltego 3.6.1 Kali Linux 版。社区版的限制如下：

+   不得用于商业用途

+   每个变换最多 12 个结果

+   您需要在我们的网站上注册才能使用客户端

+   API 密钥每隔几天就会过期

+   在与所有社区用户共享的（较慢的）服务器上运行

+   客户端和服务器之间的通信未加密

+   直到下一个主要版本才会更新

+   没有最终用户支持

+   服务器端的变换不会更新

Maltego 中有 70 多种变换可用。变换一词指的是 Maltego 的信息收集阶段。一个变换意味着 Maltego 只会执行一个信息收集阶段。

要从 Kali Linux 菜单访问 Maltego，请导航到应用程序|信息收集|Maltego。桌面上也有一个启动图标，或者您可以使用控制台并输入以下命令：

```
    # maltego
```

您将看到 Maltego 欢迎屏幕。几秒钟后，您将看到以下 Maltego 启动向导，它将帮助您首次设置 Maltego 客户端。

单击“下一步”继续到下一个窗口，并输入您的登录详细信息。（如果您没有登录详细信息，请单击此处注册以创建帐户。）

登录后，输入您的个人详细信息（姓名和电子邮件地址）。

然后，您需要选择转换种子，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/642e2c0d-2fc1-42fc-b4bf-71e357116b1b.png)

Maltego 客户端将连接到 Maltego 服务器以获取转换。如果 Maltego 已成功初始化，您将看到以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/31aeda01-9710-4c5f-abe6-55c2afef7f9d.png)

这意味着您的 Maltego 客户端初始化已成功完成。现在您可以使用 Maltego 客户端了。

在使用 Maltego 客户端之前，让我们先看一下 Maltego 界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/517bb8de-040d-48d1-9b73-92217ad169a7.png)

Maltego 界面

在前面截图的左上方，您将看到 Palette 窗口。在**Palette**窗口中，您可以选择要收集信息的实体类型。Maltego 将实体分为六组，如下所示：

+   **设备**，如手机或相机

+   **基础设施**，如 AS、DNS 名称、域、IPv4 地址、MX 记录、NS 记录、网络块、URL 和网站

+   地球上的**位置**

+   **渗透测试**

+   个人信息，如别名、文件、电子邮件地址、图像、人员、电话号码和短语

+   社交网络，如 Facebook 对象、Twitter 实体、Facebook 从属关系和 Twitter 从属关系

在前面截图的中上部，您将看到不同的视图：

+   主视图

+   气泡视图

+   实体列表

视图用于提取大型图中不明显的信息，分析师无法通过手动检查数据来清晰地看到关系。主视图是您大部分时间工作的地方。在气泡视图中，节点显示为气泡，而在实体列表选项卡中，节点以纯文本格式列出。

在视图旁边，您将看到不同的布局算法。Maltego 支持以下四种布局算法：

+   块布局：这是默认布局，在挖掘过程中使用。

+   层次布局：层次布局与根和后续主机分支一起工作。这提供了一个分支结构，以便可视化父/子关系。

+   中心布局：中心布局获取最中心的节点，然后以图形方式表示节点周围的传入链接。在检查与一个中心节点相连的多个节点时，这是很有用的。

+   有机布局：有机布局以最小化距离的方式显示节点，使查看者能够更好地了解节点及其关系的整体情况。

对 Maltego 客户端用户界面进行简要描述后，现在是行动的时候了。

假设您想收集有关域的信息。我们将使用`example.com`域作为示例。我们将在以下部分中探讨如何做到这一点：

1.  创建一个新图形（*Ctrl* + *T*）并转到 Palette 选项卡。

1.  选择基础设施，然后单击域。

1.  将其拖到主窗口。如果成功，您将在主窗口中看到一个名为`paterva.com`的域。

1.  双击名称并将其更改为您的目标域，例如`example.com`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/45ba5d80-b8ff-4307-9b8d-816d9677a82f.png)

Maltego Kali Linux

1.  如果您右键单击“域”名称，您将看到可以对域名执行的所有转换：

+   来自域的 DNS

+   域所有者的详细信息

+   来自域的电子邮件地址

+   来自域的文件和文档

+   其他转换，如转换为个人、电话号码和网站

+   所有转换

1.  让我们从域转换中选择 DomainToDNSNameSchema（运行转换|其他转换|DomainToDNSNameSchema）。以下截图显示了结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ce5adbf3-ab12-4aca-953a-4ef0b0c2f481.png)

Maltego Kali Linux

在域转换的 DNS 之后，我们得到了与`example.com`域相关的网站地址（[www.example.com](http://www.example.com)）的信息。

您可以对目标域运行其他转换。

如果要更改域，需要先保存当前图。要保存图，请按照以下步骤操作：

1.  单击 Maltego 图标，然后选择保存。

1.  图将以 Maltego 图文件格式（`.mtgx`）保存。要更改域，只需双击现有域并更改域名。

接下来，我们将描述几种可用于获取路由信息的工具。

# 获取网络路由信息

网络路由信息对于渗透测试人员有多种用途。首先，他们可以识别渗透测试人员的机器和目标之间的不同设备。渗透测试人员还可以获取有关网络操作方式以及流量在目标和测试人员机器之间的路由方式的信息。最后，渗透测试人员还可以确定是否有中间障碍物，如防火墙或代理服务器，位于测试人员和目标之间。

Kali Linux 有许多提供网络路由信息的工具。

# tcptraceroute

在 Linux 发行版中找到的`traceroute`命令的补充是`tcptraceroute`工具。普通的`traceroute`命令向目标主机发送 UDP 或 ICMP 回显请求数据包，**生存时间**（**TTL**）设置为一。该 TTL 每到达一个主机就增加一，直到数据包到达目标主机。`traceroute`和`tcptraceroute`工具之间的主要区别在于`tcptraceroute`工具使用 TCP SYN 数据包到目标主机。

使用`tcptraceroute`的主要优势在于当您有可能在测试机器和目标之间遇到防火墙时。防火墙通常配置为过滤与`traceroute`命令相关的 ICMP 和 UDP 流量。因此，`traceroute`信息对您将没有用处。使用`tcptraceroute`可以使用特定端口上的 TCP 连接，防火墙将允许您通过，从而允许您枚举通过防火墙的网络路由路径。

`tcptraceroute`命令利用 TCP 三次握手来确定防火墙是否允许通过。如果端口打开，您将收到一个 SYN/ACK 数据包。如果端口关闭，您将收到一个 RST 数据包。要启动`tcptraceroute`，在命令行中输入以下内容：

```
    # tcptraceroute
```

该命令将显示与该命令相关的不同功能。

最简单的用法是针对一个域运行该命令。在本演示中，我们将运行`traceroute`命令以跟踪到达域`example.com`的网络路由：

```
    # traceroute www.example.com  
```

`traceroute`的已编辑输出如下：

```
    traceroute to www.example.com (192.168.10.100), 30 hops max, 40 byte packets
     1  192.168.1.1 (192.168.1.1)  8.382 ms  12.681 ms  24.169 ms
     2  1.static.192.168.xx.xx.isp (192.168.2.1)  47.276 ms  61.215 ms  61.057 ms
     3  * * *
     4  74.subnet192.168.xx.xx.isp (192.168.4.1)  68.794 ms  76.895 ms  94.154 ms
     5  isp2 (192.168.5.1)  122.919 ms  124.968 ms  132.380 ms
    ...
    15  * * *
    ...
    30  * * *

```

如您所见，有几个步骤被指示，其他步骤显示为`***`。如果我们查看输出，到第 15 跳，我们看到没有可用的信息。这表明测试机器和主机之间有一个过滤设备，即`example.com`域。

为了对抗这种过滤，我们将尝试使用`tcptraceroute`命令确定路由。由于我们知道`example.com`有一个 Web 服务器，我们将设置命令尝试 TCP 端口`80`，即 HTTP 端口。以下是命令：

```
    # tcptraceroute www.example.com  
```

输出如下：

```
    Selected device eth0, address 192.168.1.107, port 41884 for outgoing packets
    Tracing the path to www.example.com (192.168.10.100) on TCP port 80 (www),                 30 hops max
     1  192.168.1.1  55.332 ms  6.087 ms  3.256 ms
     2  1.static.192.168.xx.xx.isp (192.168.2.1)    66.497 ms  50.436                 ms  85.326 ms
     3  * * *
     4  74.subnet192.168.xx.xx.isp (192.168.4.1)  56.252 ms  28.041 ms  34.607 ms
     5  isp2 (192.168.5.1)  51.160 ms  54.382 ms  150.168 ms
     6  192.168.6.1  106.216 ms  105.319 ms  130.462 ms
     7  192.168.7.1  140.752 ms  254.555 ms  106.610 ms
    ...
    14  192.168.14.1  453.829 ms  404.907 ms  420.745 ms
    15  192.168.15.1 615.886 ms  474.649 ms  432.609 ms
    16  192.168.16.1 [open]  521.673 ms  474.778 ms  820.607 ms

```

从`tcptraceroute`输出中可以看出，请求已到达我们的目标系统，并为我们提供了请求到达目标的跳数。

# tctrace

另一个利用 TCP 握手的工具是`tctrace`。与`tcptraceroute`类似，`tctrace`向特定主机发送一个 SYN 数据包，如果回复是一个 SYN/ACK，端口是打开的。一个 RST 数据包表示一个关闭的端口。

要启动`tctrace`，请输入以下命令：

```
    # tctrace -i<device> -d<targethost> 
```

`-i <device>`是目标上的网络接口，`-d <target host>`是目标。

在本例中，我们将对`www.example.com`域运行`tctrace`：

```
    # tctrace -i eth0 -d www.example.com

```

获得以下输出：

```
     1(1)   [172.16.43.1]
     2(1)   [172.16.44.1]
     3(all)  Timeout
     4(3)   [172.16.46.1]
     5(1)   [172.16.47.1]
     6(1)   [172.16.48.1]
     7(1)   []
    ...
    14(1)   [172.16.56.1]
    15(1)   [172.16.57.1]
    16(1)   [198.148.81.137] (reached; open)

```

# 利用搜索引擎

除了路由和域信息外，Kali Linux 还有其他工具，可以为渗透测试员提供大量的 OSINT。这些工具充当搜索引擎，可以从 Google 或社交网络站点等各种资源中获取电子邮件地址、文档和域信息。使用这些工具的优势之一是它们不直接搜索网站，而是使用其他搜索引擎提供 OSINT。这限制了渗透测试员对目标系统的指纹。

这些工具中有一些是内置在 Kali Linux 中的，而其他一些则需要安装。以下部分介绍了一些工具的子集，这些工具将帮助您在绝大多数信息收集中。

# SimplyEmail

`SimplyEmail`不仅可以获取电子邮件地址和其他信息，还可以清理文档，如文本、Word 或 Excel 电子表格的域。此外，还有各种不同的网站和搜索引擎可供使用。这些包括 Reddit、Pastebin 和 CanaryBin。其中最好的功能之一是该工具可以生成 HTML 格式的报告，在您准备报告时非常方便。

`theharvester`也是一个方便的工具，可以聚合目标可能泄漏的电子邮件地址和其他信息。

`SimplyEmail`是一个具有多个模块的 Python 脚本。安装它相当容易。

使用以下步骤安装`SimplyEmail`：

1.  转到 GitHub 网站[`github.com/killswitch-GUI/SimplyEmail`](https://github.com/killswitch-GUI/SimplyEmail)

1.  输入以下代码：

```
curl -s https://raw.githubusercontent.com/killswitch-GUI/SimplyEmail/master/setup/oneline-setup.sh | bash
```

1.  启动脚本完成后，您可以执行脚本。

通过输入以下内容可以访问帮助菜单：

```
      #./SimplyEmail.py -h

    Current Version: v1.0 | Website: CyberSyndicates.com
     ============================================================
     Twitter: @real_slacker007 |  Twitter: @Killswitch_gui
     ============================================================
    [-s] [-v] 

```

电子邮件枚举是渗透测试员或红队成员进行的许多操作中的重要阶段。有大量的应用程序可以进行电子邮件枚举，但我想要一种简单而有效的方式来获取`Recon-Ng`和`theharvester`提供的内容（您可能想要运行`-h`）：

```
    optional arguments:
      -all                 Use all non API methods to obtain Emails
      -e company.com       Set required email addr user, ex ale@email.com
      -l                   List the current Modules Loaded
      -t           html / flickr / google
                           Test individual module (For Linting)
      -s                   Set this to enable 'No-Scope' of the email parsing
      -v                    Set this switch for verbose output of modules

```

要开始搜索，请输入以下内容：

```
    #./SimplyEmail -all -e example.com

```

然后运行脚本。请注意，如果没有信息，返回将会出现错误。这并不意味着您犯了错误，而是表示搜索没有结果。在工具运行时，您将在屏幕上看到以下输出：

```
    [*] Starting: PasteBin Search for Emails
    [*] Starting: Google PDF Search for Emails
    [*] Starting: Exalead DOCX Search for Emails
    [*] Starting: Exalead XLSX Search for Emails
    [*] Starting: HTML Scrape of Taget Website
    [*] Starting: Exalead Search for Emails
    [*] Starting: Searching PGP
    [*] Starting: OnionStagram Search For Instagram Users
    [*] HTML Scrape of Taget Website has completed with no Email(s)
    [*] Starting: RedditPost Search for Emails
    [*] OnionStagram Search For Instagram Users: Gathered 23 Email(s)!
    [*] Starting: Ask Search for Emails

```

在进行搜索后，您将收到验证电子邮件地址的请求。这个验证过程可能需要一些时间，但在您想要社会工程或钓鱼特定个人的有针对性攻击中，这可能是明智的。一个简单的`Y/N`就足够了：

```
    [*] Email reconnaissance has been completed:
        Email verification will allow you to use common methods
        to attempt to enumerate if the email is valid.
        This grabs the MX records, sorts and attempts to check
        if the SMTP server sends a code other than 250 for known bad addresses

     [>] Would you like to verify email(s)?:

```

在验证问题之后，最后一个问题是报告生成阶段：

```
    [*] Email reconnaissance has been completed:
       File Location:     /root/Desktop/SimplyEmail
       Unique Emails Found:    246
       Raw Email File:    Email_List.txt
       HTML Email File:    Email_List.html
       Domain Performed:    example.com
    [>] Would you like to launch the HTML report?: 

```

报告输出是一个 HTML 文件，其中包含已进行的搜索类型和已找到的数据。如果您擅长 HTML，甚至可以在最终的渗透测试报告中加入您自己的标志。

# Google Hacking Database（GHDB）

**Google Hacking Database**（**GHDB**）可以在[`www.exploit-db.com/google-hacking-database/`](https://www.exploit-db.com/google-hacking-database/)找到，允许用户使用定制的高级查询，可能会显示不寻常的信息，否则这些信息将不会显示在[`www.google.com/`](https://www.google.com/)的典型结果列表中。

GHDB 最初是由 Hackers for Charity 的创始人 Johnny Long 开发的，但现在由 Kali Linux 的制造商 Offensive Security 维护和托管。 GHDB 使用 Googledorks，这是谷歌操作符，用于搜索字符串，例如 inurl，filetype，allintext，site，cache，以及`+`，`-`，`*`等操作符。当正确使用时，Googledorks 有时会显示有趣甚至敏感的信息，例如错误消息，易受攻击的服务器和网站，敏感文件和登录页面。当然，大多数这些信息无法通过普通的谷歌搜索直接获得，这导致了将谷歌用作信息收集和黑客数据库工具。

GHDB 的使用非常简单。它允许用户从各种类别中进行选择，而不是输入短语和 Googledorks。在页面下方，它列出了许多类别和搜索查询，以及指向谷歌搜索的链接，因此即使对于初学者来说也非常容易使用。

作为一个例子，我选择了类别列表中的易受攻击的服务器，只需在搜索框中输入`apache`，然后点击搜索：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c4e66c07-1aeb-4e99-9d59-ea6465e16acc.png)

列出的结果可以单击或复制并粘贴到谷歌中，以尝试收集更多信息。

以下屏幕截图显示了在谷歌中的搜索结果。请注意，有 16,600 个结果，但并非所有结果都会提供有关易受攻击的服务器的有趣信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cb74ec04-4ed9-4b2f-9ee1-3792b95cfb32.png)

出于道德和法律目的，您应该只在符合您所在州和国家法律的情况下使用 GHDB 进行信息收集。

# Metagoofil

`Metagoogil`是一种利用谷歌搜索引擎从目标域中的文档中获取元数据的工具。目前，它支持以下文档类型：

+   Word 文档（`.docx`，`.doc`）

+   电子表格文档（`.xlsx`，`.xls`，`.ods`）

+   演示文件（`.pptx`，`.ppt`，`.odp`）

+   PDF 文件（`.pdf`）

`Metagoogil`通过执行以下操作来工作：

+   使用谷歌搜索引擎在目标域中搜索所有上述文件类型

+   下载找到的所有文档并将它们保存到本地磁盘

+   从下载的文档中提取元数据

+   将结果保存在 HTML 文件中

可以找到的元数据包括以下内容：

+   用户名

+   软件版本

+   服务器或机器名称

此信息可以在后期用于帮助渗透测试阶段。`Metagoogil`不是标准 Kali Linux v 2.0 发行版的一部分。要安装，您只需要使用`apt-get`命令：

```
    # apt-get install metagoofil
```

安装程序包完成后，您可以从命令行访问 Metagoofil：

```
    # metagoofil
```

这将在您的屏幕上显示简单的使用说明和示例。作为`Metagoogil`使用的示例，我们将从目标域（`-d hackthissite.org`）收集所有 DOC 和 PDF 文档（`-t`，`.doc`，`.pdf`）并将它们保存到名为`test`的目录中（`-o test`）。我们将每种文件类型的搜索限制为`20`个文件（`-l 20`），并且只下载五个文件（`-n 5`）。生成的报告将保存在`test.html`中（`-f test.html`）。我们给出以下命令：

```
    # metagoofil -d example.com -l 20 -t doc,pdf -n 5 -f test.html -o test  
```

此命令的编辑结果如下：

```
    [-] Starting online search...

    [-] Searching for doc files, with a limit of 20
      Searching 100 results...
    Results: 5 files found
    Starting to download 5 of them:
    ----------------------------------------

    [1/5] /webhp?hl=en [x] Error downloading /webhp?hl=en
    [2/5] /intl/en/ads [x] Error downloading /intl/en/ads
    [3/5] /services [x] Error downloading /services
    [4/5] /intl/en/policies/privacy/
    [5/5] /intl/en/policies/terms/

    [-] Searching for pdf files, with a limit of 20
      Searching 100 results...
    Results: 25 files found
    Starting to download 5 of them:
    ----------------------------------------

    [1/5] /webhp?hl=en [x] Error downloading /webhp?hl=en
    [2/5] https://mirror.hackthissite.org/hackthiszine/hackthiszine3.pdf
    [3/5] https://mirror.hackthissite.org/hackthiszine/hackthiszine12_print.pdf
    [4/5] https://mirror.hackthissite.org/hackthiszine/hackthiszine12.pdf
    [5/5] https://mirror.hackthissite.org/hackthiszine/hackthiszine4.pdf
    processing

    [+] List of users found:
    --------------------------
    emadison

    [+] List of software found:
    -----------------------------
    Adobe PDF Library 7.0
    Adobe InDesign CS2 (4.0)
    Acrobat Distiller 8.0.0 (Windows)
    PScript5.dll Version 5.2.2

    [+] List of paths and servers found:
    ---------------------------------------

    [+] List of e-mails found:
    ----------------------------
    whooka@gmail.com
    htsdevs@gmail.com
    never@guess
    narc@narc.net
    kfiralfia@hotmail.com
    user@localhost
    user@remotehost.
    user@remotehost.com
    security@lists.
    recipient@provider.com
    subscribe@lists.hackbloc.org
    staff@hackbloc.org
    johndoe@yahoo.com
    staff@hackbloc.org
    johndoe@yahoo.com
    subscribe@lists.hackbloc.org
    htsdevs@gmail.com
    hackbloc@gmail.com
    webmaster@www.ndcp.edu.phpass
    webmaster@www.ndcp.edu.phwebmaster@www.ndcp.edu.ph
    webmaster@ndcp
    [root@ndcp
    D[root@ndcp
    window...[root@ndcp
    .[root@ndcp
    goods[root@ndcp
    liberation_asusual@ya-
    pjames_e@yahoo.com.au

```

您可以从上述结果中看到，我们从收集的文档中获得了大量信息，例如用户名和路径信息。我们可以使用获得的用户名来查找用户名中的模式，并对其进行暴力密码攻击。但是，请注意，对帐户进行暴力密码攻击可能会有锁定用户帐户的风险。路径信息可用于猜测目标使用的操作系统。我们获得了所有这些信息，而无需访问域网站。

`Metagoogil`也能够以报告格式生成信息。以下屏幕截图显示了 HTML 中生成的报告：

![

在生成的报告中，我们可以从目标域中获取有关用户名、软件版本、电子邮件地址和服务器信息的信息。

# 自动足迹和信息收集工具

在本节中，我们将介绍完全自动化的工具，特别是两种，它们包含了许多个别工具中涵盖的任务的几个功能。这些工具可通过[`github.com/`](https://github.com/)免费使用，并在 Kali Linux 2018.2（可能还有早期版本）中使用。

# Devploit

Devploit 3.6 被列为一个信息收集工具，由 Joker25000 开发，可在[`github.com/joker25000/Devploit`](https://github.com/joker25000/Devploit)上获得。

要使用 Devsploit，我们首先将其克隆到我们的 Kali Linux 机器上，然后在提供选项时运行所选的工具。克隆只需做一次；以后每次使用 Devploit 时，只需浏览到 Devploit 目录。

打开一个新的终端，并使用`cd`命令更改到您选择的目录。 （您还可以使用`ls`命令列出目录的内容，并确保您在正确的目录中。）

使用`git clone`命令将 Devploit 克隆到您的机器上，输入以下内容：

```
git clone https://github.com/joker25000/Devploit.git
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/25c29e7e-23a2-4edd-ac16-f897d63547d8.png)

如果从 GitHub 网页复制 URL，请确保在终端中包括`.git`。

按*Enter*克隆 Devploit 到 Kali：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e499109c-30cf-4628-99bd-03fbcd7f72c7.png)

在终端中，通过输入`cd` Devploit 来更改桌面上的 Devploit 目录，然后使用`ls`命令查看目录内容。您应该看到`Devploit.py`和`README.me`文件等。

通过输入`chmod +x install`为文件授予可执行权限以安装，然后通过输入`./install`启动 Devploit。

请确保您是在 Devploit 目录中运行前面的命令。

安装 Devploit 后，打开一个新的终端，输入 Devploit，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6751cf62-d306-44ce-886f-638acfc65a39.png)

Devploit 提供了 19 个自动信息收集选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/bd850307-d386-4c05-9fc1-7361871ea44b.png)

要执行 DNS 查找，请输入`1`，然后输入域的名称，例如[www.google.com](http://www.google.com)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f645bd5a-304f-4221-9c12-0dc1c91b19e0.png)

要查找有关域或 IP 的基本地理信息，请选择选项 3 并按 Enter，然后输入 IP 或域名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e3e2c463-a3bf-4e65-bdd7-1cecac3d96ef.png)

务必熟悉可用的选项。

# Red Hawk v2

Red Hawk 版本 2 是另一个深入的、多合一的信息收集套件，用于侦察和数据收集。

在新的终端中，更改到桌面（或您选择的目录）并通过输入[`github.com/th3justhacker/RED_HAWK`](https://github.com/th3justhacker/RED_HAWK)来克隆 Red Hawk v2：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1a976351-a069-4e1f-9ea1-be961eb87ed5.jpg)

一旦所有对象成功解压缩，通过输入`cd RED_HAWK`更改目录到`RED_HAWK`目录。使用`ls`命令验证`rhawk.php`是否存在：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5139a1d7-e73a-4b0f-8ae0-9fe9484f7c3d.png)

要启动 Red Hawk，请输入`php rhawk.php`并按*Enter*。如果成功，应显示以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/562012a5-2487-4834-93c9-6618d3284471.jpg)

输入您的网站，然后选择 HTTP 或 HTTPS。然后，从可用的选项中进行选择。例如，键入一个进行 Whois 查找：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5d45f3a3-6f26-47bc-af7f-436016d40082.jpg)

`https://www.google.com/`的 Whois 查找信息显示如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8d50f844-dbf3-427d-a5d4-199de8835987.jpg)

选项`[3]抓取横幅`的[`www.google.com/`](https://www.google.com/)的结果如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f692c408-722d-40b0-bc2f-819f075fafd9.jpg)

对[Google.com](https://www.google.com/?gws_rd=ssl)进行 MX 查找（选项`13`）得到以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/16ebd101-7031-4f1c-bd97-a62eae854687.jpg)

用户可以选择多种选项，包括选项`[A]`，该选项可以扫描所有内容。

# 使用 Shodan 查找连接到互联网的设备

位于[shodan.io](http://shodan.io)的 Shodan 搜索引擎并不是您平常的搜索引擎。Shodan 可以通过基本和特定的查询字符串返回连接到互联网的易受攻击系统的搜索结果。

该网站是由 John Matherly 开发的，已经可用将近十年，现在已成为一个在互联网上指纹识别的宝贵工具。考虑到我们生活在**物联网**（**IoT**）时代，越来越多的设备现在可以通过互联网访问，然而其中许多设备的安全性不如他们应该的那样，有时会使它们不仅容易受到黑客的攻击，还容易受到任何好奇的人的攻击。

Shodan 扫描常见端口并执行横幅抓取作为其足迹过程的一部分，然后显示可以通过网络访问的设备，包括路由器和网络设备、网络摄像头和监控设备、交通摄像头、服务器和 SCADA 系统等等有趣的设备。

在结果列表中，单击单个结果通常会返回设备上的开放端口和服务列表，并且还允许生成报告。

出于隐私和法律目的，我选择不使用 Shodan 结果的截图。

要使用 Shodan，请首先访问网站[www.shodan.io](https://www.shodan.io/)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/eaf16620-8c32-4e2d-b20a-55412c3a2ef7.png)

您会注意到您可以免费使用该服务，但如果您不注册，您将被限制查看一页返回的结果。注册是免费的，可以让您查看搜索引擎显示的返回结果的前两页。还有一个付费订阅可以订阅，以便访问所有结果。

# Shodan 中的搜索查询

以下是 Shodan 中的搜索查询：

+   在搜索字段中可以指定诸如网络摄像头、CCTV、思科、Fortinet、交通信号、冰箱等**关键词**。

+   **端口号**也可以根据服务进行指定，比如`3389`（远程桌面）。

+   **操作系统版本：**操作系统和版本也可以与国家代码一起指定

+   **国家名称**也可以与关键词和端口号一起指定

+   **短语**和**组合关键词**也可以使用，包括默认密码、登录失败等热门搜索短语。

在 Shodan 网站的顶部菜单中，有一个“探索”选项。该选项显示了各种类别和热门搜索的链接。工业控制系统和数据库是特色类别之一，而排名靠前的搜索条目包括网络摄像头、Cams、Netcam 和默认密码。

单击 Webcams 类别，甚至在搜索字段中输入 server: SQ-WEBCAM，可以得到不同国家的网络摄像头的多个结果。例如，常见的搜索查询 WebcanXPm 也会返回许多通过互联网访问的摄像头的结果，其中许多允许远程用户进行平移、倾斜和缩放。

由于法律限制，请确保您不要访问受限制的设备，并根据您所在州或国家的法律使用 Shodan。

# 开始目标发现

在我们从第三方来源（如搜索引擎）收集了关于目标网络的信息之后，下一步是发现我们的目标机器。这个过程的目的如下：

+   查找目标网络中哪台机器是可用的。如果目标机器不可用，我们将不会继续对该机器进行渗透测试，并将移动到下一台机器。

+   查找目标机器使用的基础操作系统。

收集先前提到的信息将有助于我们进行漏洞映射过程。

我们可以利用 Kali Linux 提供的工具进行目标发现过程。这些工具中的一些可以在信息收集菜单中找到。其他工具将必须从命令行中使用。对于这些工具，提供了命令。

在本章中，我们将只描述每个类别中的一些重要工具。这些工具是基于它们的功能、流行度和工具开发活动进行选择的。

为了本章的目的，Metasploitable 2 的安装被用作目标系统。可以尝试在该操作系统上使用这些命令。

# Blue-Thunder-IP-Locator

打开一个新的终端并切换到您选择的目录。在本例中，我使用了桌面。

通过键入`git clone https://github.com/th3sha10wbr04rs/Blue-Thunder-IP-Locator-.git`从 GitHub 克隆 Blue-Thunder-IP-Locator：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a8ba6279-0a72-4cbb-81c5-d0802ac45c3b.jpg)

成功克隆后，更改目录到 Blue-Thunder-IP-Locator 目录。

如 GitHub 页面所述，[`github.com/th3sha10wbr04rs/Blue-Thunder-IP-Locator-`](https://github.com/th3sha10wbr04rs/Blue-Thunder-IP-Locator-)，通过输入以下内容安装和更新`perl libs`：`apt-get install liblocal-lib-perl`。

如果在运行上述命令时遇到错误，请输入`Dpkg –-configure –a`命令，然后再次尝试上一个命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c9b8eea5-1028-4afe-b632-3e1295e965fe.jpg)

在整个过程中可能会提示您选择各种选项。在提示时按`Y`（是）。

接下来，键入`apt-get install libjson-perl`，然后键入`apt-get upgrade libjson-perl`。

我们还需要确保 Blue-Thunder 具有适当的可执行权限，方法是键入`chmod +x blue_thunder.pl`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0e81df44-e501-4c0d-b4a7-c9eab987dab7.png)

Blue-Thunder-IP-Locator 需要来自 Mechanize 的某些 Perl 依赖项才能运行。特别需要`Ruby-mechanize`库来自动化与网站的交互。

建议在运行 Blur-Thunder 之前运行下面列出的命令。（确保导航回根目录。）

键入`apt-get install libhttp-daemon-ssl perl`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/877e4cfb-357e-4e21-91a4-1a0438fb5033.jpg)

如果找不到`libhttp-daemon-ssl`包，继续下一个命令也是可以的。

键入`Apt-cache search WWW::Mechanize`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d0aeb1da-b4b0-470c-bad9-57ef78471508.jpg)

最后，运行以下命令，`apt-get install libwww-mechanize-perl`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c234fdfd-b24f-40e5-8fd7-7d1df0ee53b7.png)

现在，所有依赖项都已安装和/或更新，我们可以运行 Blue-Thunder-IP-Locator。

在终端中，导航到 Blue-Thunder-IP-Locator 目录，输入`perl blue_thunder.pl`命令，然后按*Enter*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/61444cb2-747e-43d9-a6e6-f231908913f6.png)

要查找详细的地理位置信息，请键入`perl iplocation.pl`，然后输入主机、IP 或域名的名称（在 Blue-Thunder-IP-Locator 目录中）。

例如，要查找有关[Google.com](https://www.google.com/?gws_rd=ssl)的地理位置信息，请键入`perl blue-thunder.pl www.google.com`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ed53e167-098a-44d2-b345-8994ecc19165.jpg)

请注意，输出包括有关目标`ISP`、`国家`、`纬度`、`经度`等信息，如前面的屏幕截图所示。`纬度`和`经度`坐标也可以输入到 Google 地图中以获取方向和位置具体信息。

# 摘要

本章介绍了信息收集阶段。通常是在渗透测试过程中首先进行的阶段。在这个阶段，您尽可能收集有关目标组织的信息。了解目标组织之后，当我们想要攻击目标时会更容易。伟大的中国战略家孙子非常简洁地阐述了 OSINT 和信息收集的总体意图：

“知己知彼，百战不殆。”

这句话在渗透测试中再合适不过了。

我们描述了 Kali Linux 中包含的几种可用于信息收集的工具。我们首先列出了几个可用于收集有关目标组织信息的公共网站。接下来，我们描述了如何使用工具收集域名注册信息。然后，我们描述了可用于获取 DNS 信息的工具。之后，我们探讨了用于收集路由信息的工具。在本章的最后部分，我们描述了包括令人印象深刻的黑客搜索引擎 Shodan 在内的自动化工具。

在下一章中，我们将讨论如何通过扫描发现目标，以及如何规避检测。

# 问题

让我们现在尝试回答一些问题：

1.  OSINT 的缩写是什么？

1.  有哪些工具可以用来查询域名注册信息？

1.  A 记录代表什么？

1.  什么工具利用 Google 搜索引擎收集目标域中文档的元数据？

1.  有哪两种自动信息收集工具？

1.  有什么工具可以用来查找互联网上的设备信息？

# 进一步阅读

您还可以在以下参考链接中找到有关讨论主题的更多信息：

+   OSINT 资源：[`osintframework.com/`](http://osintframework.com/)

+   Maltego 用户指南和文档：[`www.paterva.com/web7/docs.php`](https://www.paterva.com/web7/docs.php)

+   Google 备忘单：[`www.googleguide.com/print/adv_op_ref.pdf`](http://www.googleguide.com/print/adv_op_ref.pdf)

+   Shodan 用于渗透测试人员：[`www.defcon.org/images/defcon-18/dc-18-presentations/Schearer/DEFCON-18-Schearer-SHODAN.pdf`](https://www.defcon.org/images/defcon-18/dc-18-presentations/Schearer/DEFCON-18-Schearer-SHODAN.pdf)
