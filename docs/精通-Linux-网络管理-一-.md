# 精通 Linux 网络管理（一）

> 原文：[`zh.annas-archive.org/md5/BC997E7C6B3B022A741EFE162560B1CA`](https://zh.annas-archive.org/md5/BC997E7C6B3B022A741EFE162560B1CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在本书中，我们将学习管理真实基于 Linux 的网络所需的概念。目标是帮助读者从初学者或中级水平的 Linux 用户成长为能够管理和支持真实基于 Linux 的网络的人。本书以一些介绍性章节开始，读者将在其中设置他们的环境，然后刷新一些基础知识，这将成为本书其余部分的基础。从那里开始，将涵盖更高级的主题，并提供有用的示例，读者将能够跟随并获得宝贵的实践经验。

在这个旅程中，我们将涵盖网络管理员通常会在工作中执行的任务，如安装 Linux、设置 DHCP、共享文件、IP 地址分配、监控资源等。这些示例不仅涵盖了两种流行的发行版，Debian 和 CentOS。由于这两种发行版在企业中非常流行，读者将能够很好地准备管理基于其中一种或另一种（以及基于它们的无数其他发行版）的网络。

最后几章将涵盖防止入侵和攻击的最佳实践，以及在出现问题时为您提供帮助的故障排除。

# 本书涵盖了什么

第一章，“设置您的环境”，涵盖了为本书使用设置实验室环境的过程。涵盖了安装 Debian 和 CentOS，以及使用虚拟机的利弊。

第二章，“重新审视 Linux 网络基础”，为读者刷新了提供本书其余部分基础的核心 Linux 概念，如 TCP/IP、主机名解析和 IP 和 net 工具套件。

第三章，“通过 SSH 在节点之间通信”，涵盖了所有与 SSH 有关的内容。在本章中，我们将看看如何使用 SSH 以及如何设置 OpenSSH 服务器以允许其他节点连接。还介绍了`scp`命令，允许我们将文件从一台机器传输到另一台机器。

第四章，“设置文件服务器”，涵盖了 Samba 和 NFS。在这里，我们将讨论何时适合使用其中一个，以及配置和挂载这些共享文件。

第五章，“监控系统资源”，涉及监控我们 Linux 系统上的资源，如检查可用磁盘空间、检查可用内存、日志轮转和查看日志。

第六章，“配置网络服务”，涵盖了使我们的网络运行的服务。这里涵盖了 DHCP 和 DNS 服务器等主题。还介绍了 NTP。

第七章，“通过 Apache 托管 HTTP 内容”，涵盖了 Apache，目前是世界上使用最多的 Web 服务器软件。在这里，我们不仅会安装 Apache，还会配置和管理模块。还涵盖了虚拟主机。

第八章，“理解高级网络概念”，将读者带入下一个层次，讨论更高级的主题，如子网划分、服务质量、DHCP 和 DNS 中的冗余等。

第九章，“保护您的网络”，涉及加固系统以防止未经授权访问。在这里，我们将涵盖 iptables、fail2ban、SELinux 等内容。

第十章，“故障排除网络问题”，通过一些故障排除技巧来总结我们的旅程，如果遇到问题，您可以使用这些技巧。

# 您需要为本书准备什么

这本书要求你至少有一台能够运行 Debian 或 CentOS 的计算机，最好是两者都能运行。你可以在虚拟机或物理硬件上运行它们都没关系，唯一的要求是你应该能够安装这两个发行版并通过终端访问它们。这些安装需要 root 级别的访问权限。

虽然你肯定可以使用你已经拥有的任何 Linux 安装，但强烈建议你有单独的、全新的安装来使用，因为我们的一些主题如果在生产网络上运行可能会有破坏性。如果你有疑问，VirtualBox 或者你可能有闲置的旧机器都可以。需要网络访问，但这是不言而喻的，考虑到本书的主题。

需要一些基本的 Linux 知识。用户不需要是高级用户，因为本书的目的是升级你现有的知识。话虽如此，为了获得最顺利的体验，你应该已经熟悉一些东西。首先，你应该已经知道如何使用文本编辑器修改配置文件。本书不假设你使用哪种文本编辑器，这完全取决于你。只要你了解任何文本编辑器，无论是 nano、vim，甚至 gedit——你都处于良好状态。如果你能打开一个属于 root 的配置文件，然后进行更改并保存它——你就已经准备好了。如果有疑问，nano 是初学者的好文本编辑器，只需要几分钟就能学会。对于更高级的用户，vim 是一个不错的选择。说到 root，你还应该了解以 root 用户或普通用户身份运行命令的区别。此外，你应该能够浏览文件系统并四处浏览。

然而，即使你需要复习文本文件的编辑或切换到 root 用户，也不要让这成为阻碍。在线上有很多知识可以帮助你复习，Linux 可用的大多数文本编辑器都提供了非常好的文档。

# 这本书是为谁准备的

这本书的目标读者是那些已经了解 Linux 基础知识，想要学习如何管理基于 Linux 的网络或将自己的技能提升到更高水平的用户。这可以是为了支持全 Linux 网络，甚至是混合环境。本书将读者带入从安装 Debian 等较为简单的主题，到子网划分等更为高级的概念。通过本书，你应该有足够的知识来建立一个完全网络化的环境，包括这样一个网络应该具备的所有组件。如果这激发了你的兴趣，那么这本书绝对适合你！

然而，在本书中，我们专注于与 Linux 相关的真实世界例子。如果你的目标是获得思科认证或其他高级认证，那么这可能不是最适合你的地方。在这里，一切都是关于实际例子，而不是过多关注理论。虽然认证复习书很好，但在本书中，我们做的是真实的事情——如果你的老板或客户要求你实施 Linux 网络，那么这些就是你需要做的事情。如果这是你的目标，那么你肯定来对地方了。

# 惯例

在本书中，你会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的例子及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“在大多数情况下，这将是`/dev/sda`。”

代码块设置如下：

```
default-lease-time 86400;
max-lease-time 86400;
option subnet-mask 255.255.252.0;
option broadcast-address 10.10.99.255;
option domain-name "local.lan";
authoritative;
subnet 10.10.96.0 netmask 255.255.252.0 {
  range 10.10.99.100 10.10.99.254;
  option routers 10.10.96.1;
  option domain-name-servers 10.10.96.1;
}
```

任何命令行输入或输出都以如下形式书写：

```
systemctl status httpd

```

需要以 root 权限运行的任何命令都将以`#`字符为前缀，如下所示：

```
# yum install httpd

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："完成后，您可以通过单击**扫描**，然后**保存扫描**来保存结果。"

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这种方式出现。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它帮助我们开发您真正能够从中获益的标题。

要向我们发送一般反馈，只需发送电子邮件`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载所有您购买的 Packt Publishing 书籍的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接发送到您的电子邮件。

## 下载本书的彩色图像

我们还为您提供了一个包含本书中使用的屏幕截图/图表的彩色图像的 PDF 文件。彩色图像将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/9597OS_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9597OS_ColorImages.pdf)下载此文件。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误部分下的任何现有勘误列表中。

要查看先前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将出现在**勘误**部分下。

## 盗版

互联网上的版权盗版是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助我们保护我们的作者和我们提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：设置您的环境

欢迎来到 Linux 网络世界！本书将指导您完善 Linux 网络管理技能。在本章中，我们将讨论启动和运行环境所需的内容。我们将讨论一些对企业网络感兴趣的 Linux 发行版，设置家庭或办公环境时需要注意的事项，以便您可以跟着本书进行学习，并设置一些我们将在本书中使用的 Linux 安装的最佳实践。基本上，我们将奠定您用来发展技能的基础。

在本章中，我们将涵盖：

+   入门

+   要考虑的发行版

+   物理机与虚拟机

+   设置和配置 VirtualBox

+   获取和安装 Debian 8

+   CentOS 7 的获取和安装

# 入门

在 Linux 中进行网络管理是一个有趣、多样化且不断变化的领域。虽然核心组件通常在多年间保持不变（如**TCP/IP**协议），但这些服务的管理方式在每一代中都有所发展，比如**systemd**的兴起。Linux 绝对令人兴奋。

在本章中，我们将看到如何设置您的环境。根据您的经验水平，您可以直接跳转到第二章，*重新审视 Linux 网络基础*。如果您已经熟悉在物理或虚拟机上安装一个或两个发行版，那么您已经具备了开始的知识。在这里，我们将讨论如何安装本书中练习所需的一些发行版以及一些一般指导。

简而言之，您拥有的 Linux 安装越多，越好。在练习网络概念时，最好尽可能多地拥有节点，这样您可以测试您的配置更改将如何影响您的环境。如果您已经熟悉安装 Linux，可以随意设置一些节点，然后我会在下一章与您见面。

# 要考虑的发行版

今天存在着一百多个 Linux 发行版。这些包括专门面向工作站或服务器（甚至两者兼顾）的发行版，以及解决特定任务的专业发行版，比如 Kali、Mythbuntu 和 Clonezilla。当学习诸如网络管理之类的概念时，人们可能会首先想到从哪些发行版开始。

让我们不要专注于任何一个发行版。在企业中，没有两个数据中心是相同的。一些利用 Linux 的组织可能会将特定的发行版集（例如 Ubuntu 和 Ubuntu Server）标准化，尽管更常见的情况是看到一种或多种发行版的混合使用。在基于 Linux 的网络中，**SUSE Enterprise Linux**、**Red Hat Enterprise Linux**、**Ubuntu Server**、**CentOS**和**Debian**等发行版在服务器中非常常见。根据我的经验，我经常看到使用 Debian（以及其衍生版）和基于 Red Hat 的发行版。

鼓励你尝试并混合你可能喜欢的任何发行版。有很多候选者，像[www.distrowatch.com](http://www.distrowatch.com)这样的网站会给你列出可能性。特别是为了这本书中的例子，推荐你使用 CentOS 和 Debian。事实上，这两个发行版是一个很好的起点。你将品尝到两种不同形式的软件包管理（**rpm**和**deb**软件包），并熟悉两种最流行的发行版。关于 Debian，有很多发行版都是基于它的（**Ubuntu**，**Linux Mint**等）。通过学习如何管理 Debian 安装，很多知识都可以转移到其他发行版，如果你考虑切换的话。同样的情况也适用于基于 Red Hat 的 CentOS。Red Hat 是一个非常流行的发行版，而 CentOS 是从其源代码创建的，你基本上也在学习它。虽然**Fedora**比 Red Hat 或 CentOS 更前沿，但很多知识在那里也会有用；Fedora 作为工作站发行版也很受欢迎。

本书中的示例在 CentOS 和 Debian 中进行了测试。每当指令特定于某个发行版时，我会告诉你。在本书的目的上，拥有 CentOS 和 Debian 的安装将适合你，但请随意尝试。就这些发行版的个别版本而言，都使用了 CentOS 7 和 Debian 8。在你的环境或家庭实验室中安装这些。

# 物理机器与虚拟机器

在一本网络书中看到虚拟机的部分可能会有些意外。公平地说，这确实有些不合适。除了作为一个重要的企业平台外，**虚拟化**也可以是一个宝贵的学习工具。在真实的网络中，技术人员可能会在虚拟机中测试服务，然后再将其部署到环境中。例如，一个新的**DNS**服务器可能首先作为一个**VM**启动，然后一旦经过测试和验证，就可以移入组织中供使用。这种方法的一个好处是你可以在开发解决方案时拍摄多个快照，如果出错破坏了，你可以恢复快照，从已知工作状态开始。

就我们掌握 Linux 网络技能而言，虚拟机允许你测试不同发行版之间的过程差异。启动虚拟机很容易，而且更容易销毁它。如果你受到物理硬件的限制，那么虚拟机可能为你提供一个机会来构建一个小型虚拟网络进行练习。当然，虚拟机的折衷是它们使用了多少内存。然而，没有图形界面，大多数 Linux 发行版只需 512MB 内存就可以运行得相当舒适。如今，有相当多的计算机配备了 8GB 甚至 16GB 的内存，所以即使是当今可用的预算计算机上也应该能够运行几个虚拟机。

公平地说，使用虚拟机进行练习和学习并不总是理想的。事实上，在学习网络时，通常更喜欢使用物理设备。虽然你当然可以通过在虚拟机中运行 Apache 来练习设置和提供网页，但在这样的环境中你无法练习安装和配置交换机和路由器。在可能的情况下，尽量使用物理设备。然而，虚拟机为你提供了一个独特的机会，可以在你的网络上创建一个小型节点的军队来维护。

当然，并非每个人都有一堆戴尔塔在壁橱里等着安装全新 Linux 的机会。根据你手头的资源，你可以使用所有物理机器或物理和虚拟机器的混合。在这本书中，我们不会对你的库存做任何假设。游戏的关键是管理节点，所以尽可能设置多个节点。

在本书中，讨论了**VirtualBox**。但这绝不是创建虚拟机的唯一解决方案。还有其他解决方案，如**KVM**、**Xen**、**VMware**等。VirtualBox 的好处是免费、开源和跨平台（适用于 Linux、Mac OS X 和 Windows），因此它很可能在您的环境中运行。在大多数情况下，它甚至比 KVM 或 Xen 更容易设置（但可能没有那么酷）。您不必使用 VirtualBox（或者根本不使用虚拟机）来跟随本书。使用您喜欢的任何解决方案。在本书中，我尽量不限制说明到任何一个特定的解决方案，因此内容适用于尽可能多的人。

# 设置和配置 VirtualBox

如果您决定在您的环境中使用 VirtualBox（无论是用于学习、测试发行版，还是在实施网络服务之前评估），我们将在本活动中设置我们的 VirtualBox 主机。

## 获取 VirtualBox

实际上，下载和安装 VirtualBox 相当简单，但每个平台都有其独特的怪癖。在 Windows 中，初始安装只是导航到以下网站，下载安装程序并运行安装向导：

[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

安装后，您只需要跳转到本章的*下载和安装扩展包*部分。在 Mac OS X 上安装也很简单。

对于 Linux，有几种安装 VirtualBox 的方法。一种方法是使用您的**软件包管理器**，如果您的发行版已经在其存储库中提供了它。不幸的是，根据您的发行版版本，可能包含的 VirtualBox 版本很可能已经过时。例如，Debian 通常在其存储库中包含较旧的软件包，但像 Arch 这样的最新发行版更有可能包含最新和最好的软件包。

也许更好的获取 VirtualBox 的方法是将 VirtualBox 本身提供的存储库导入到您的系统中。以下 URL 列出了 Debian 存储库的列表，甚至提供了一种为基于 RPM 的发行版（如 Fedora、Red Hat 等）添加存储库的方法：

[`www.virtualbox.org/wiki/Linux_Downloads`](https://www.virtualbox.org/wiki/Linux_Downloads)

例如，使用页面上的说明作为指南，我们可以在基于 Debian 的系统上运行以下过程。但是，Oracle 可能随时更改他们的说明和存储库列表；在安装之前始终查阅之前的 URL，以查看过程是否已更改。

为了验证我们将添加正确的版本，我们需要确定要使用哪个存储库。这取决于您正在运行的发行版，因此一定要查阅 VirtualBox 网站上的文档，以确保您导入了正确的存储库。

对于 Debian 8 "Jessie"，我们将使用以下命令：

```
deb http://download.virtualbox.org/virtualbox/debian jessie contrib

```

要将此存储库添加到我们的 Debian 系统中，我们将使用以下命令：

```
# echo "deb http://download.virtualbox.org/virtualbox/debian jessie contrib" > /etc/apt/sources.list.d/virtualbox.list

```

然后，我们可以使用以下命令为存储库添加公钥：

```
# wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | apt-key add -

```

从现在开始，我们可以在我们的存储库中找到 Oracle 的 VirtualBox 软件包并安装它。为此，让我们首先使用以下命令更新我们的软件包列表（作为 root 用户）：

```
# apt-get update

```

然后使用以下命令安装 VirtualBox：

```
# apt-get install dkms virtualbox-4.3

```

### 注意

只要选择适当的匹配存储库，这种安装方法对于 Ubuntu 也适用。

对于 Fedora、**Red Hat Enterprise Linux**（**RHEL**）和 openSUSE 等发行版，Oracle 提供了类似的说明。

可以通过以下命令下载公钥：

```
# wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | rpm --import -

```

为了将存储库添加到 Fedora 系统中，执行以下命令：

```
# wget -P /etc/yum/repos.d/ http://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo

```

添加存储库后，可以使用以下命令安装 VirtualBox：

```
# yum install VirtualBox-4.3

```

此外，OpenSUSE 和 RHEL 的说明也可以在 VirtualBox 网站上找到。有关更多详细信息，请参阅 VirtualBox 网站[`www.virtualbox.org`](https://www.virtualbox.org)。

## 下载和安装扩展包

Oracle 提供了一个**扩展包**，它可以启用 USB 支持以及**预引导执行环境**（**PXE**）引导支持。您可能需要也可能不需要这些功能。如果您认为您可以从主机 PC 插入闪存驱动器并在虚拟机内访问它会有所帮助，那么安装这个扩展包可能是个好主意。

### 注意

由于许可问题，扩展包并未内置到 VirtualBox 中。如果您希望了解更多信息，请随时查阅 VirtualBox 许可协议。

扩展包的安装过程基本相同，无论您的主机计算机运行的是 Linux、Windows 还是 Mac OS X。但是，如果您的主机运行的是 Linux，则还有一个额外的步骤，即将您的用户帐户添加到`vboxusers`组中。

1.  当您首次安装 VirtualBox 时，应该已经创建了这个组。要验证，请执行以下命令：

```
cat /etc/group |grep vboxusers

```

1.  您应该看到类似以下的输出：

```
vboxusers:x:1000:username

```

1.  如果您看不到输出，请使用以下命令创建组：

```
# groupadd vboxusers

```

1.  然后，将自己添加到该组：

```
# usermod -aG vboxusers yourusername

```

### 注意

您需要注销然后登录，才能将自己添加到`vboxusers`组中。

现在，您可以安装扩展包了。无论您的基础操作系统如何，此过程应该是相同的。首先，从以下 URL 下载扩展包并将其保存在本地：

[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

下载后，按照以下步骤进行：

1.  打开 VirtualBox 并转到**文件** | **首选项...**。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_01.jpg)

在 VirtualBox 中访问文件菜单

1.  接下来，点击**扩展**，然后点击右侧的绿色三角形图标。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_02.jpg)

VirtualBox 设置

1.  选择您之前下载的扩展包，然后点击**打开**。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_03.jpg)

扩展包选择

1.  然后，您将被要求确认安装。点击**安装**。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_04.jpg)

扩展包安装的确认

1.  将显示 VirtualBox 许可协议。请随意查看。然后，滚动到底部，点击**我同意**进行确认。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_05.jpg)

VirtualBox 许可协议

1.  如果您运行的是 Linux，可能会要求您输入 root 或 sudo 密码。如果是这样，请输入并继续。经过身份验证后，您应该会看到成功安装扩展包的确认。![下载和安装扩展包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_06.jpg)

成功安装 VirtualBox 扩展包的确认

完成此过程后，VirtualBox 将在您的计算机上运行。

### 注意

在某些发行版中，密码提示可能不会出现，导致扩展包的安装失败。如果发生这种情况，请使用以下命令以 root 权限运行 VirtualBox：

```
sudo VirtualBox

```

然后，尝试重新安装扩展包。完成后，关闭 VirtualBox，然后以普通用户身份重新打开。

# 获取并安装 Debian 8

为了安装 Debian，我们首先需要获取一个**ISO** **镜像**文件。要做到这一点，请转到以下 URL：

[`www.debian.org/distrib/netinst`](http://www.debian.org/distrib/netinst)

有几个下载选项，但**netinst** ISO 将是我们的目标。对于大多数计算机来说，64 位（amd64）版本应该足够了——除非你确定你的计算机不支持 64 位。netinst 和完整安装镜像的主要区别在于 netinst 版本将从 Debian 的服务器上通过互联网下载所需的内容。只要你不在带宽受限的地区，这应该不是问题。

当然，ISO 文件本身是没有用的，除非你将它附加到虚拟机上。如果是的话，那么你就准备好了。如果你要设置一个物理机器，你需要使用你选择的光盘制作工具创建一个可引导的光盘，或者创建一个可引导的闪存驱动器。

### 注意

由于有大量不同的光盘制作工具可用，不可能完全介绍如何在你的环境中创建可引导光盘。在大多数情况下，你的工具应该有一个选项在菜单中烧录 ISO 镜像。如果你只是创建了一个数据光盘，那么光盘将无法作为 Debian 安装媒体使用。

安装 Debian 8 的步骤如下：

1.  在 Linux 系统中，你可以使用以下命令创建一个可引导的 Debian 闪存驱动器：

```
# cp name-of-debian.iso /dev/sd? && sync

```

1.  基本上，我们是直接将下载的 ISO 镜像复制到闪存驱动器上。当然，根据你的系统更改文件名和目标。要确定要使用的设备节点，执行以下命令：

```
# fdisk -l

```

1.  在输出中，你应该看到你的闪存驱动器的节点指定。该命令的输出将如下所示：

```
Device     Boot Start      End  Sectors  Size Id Type
/dev/sdb1        2048 60563455 60561408 28.9G 83 Linux

```

1.  然后，`/dev/sdb`将是用来创建闪存驱动器的设备。将所有内容放在一起，我们将使用以下命令创建闪存驱动器：

```
# cp name-of-debian.iso /dev/sdb && sync

```

### 提示

**下载示例代码**

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的帐户中为你购买的所有 Packt Publishing 图书下载示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给你。

1.  创建了可引导媒体后，将其插入计算机，按照计算机的具体指示访问引导菜单并选择你的 Debian 媒体。加载完成后，第一个屏幕会要求你选择语言。选择你的语言，然后点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_07.jpg)

Debian 安装程序的语言选择屏幕

1.  选择语言后，下一个屏幕将让你选择你的位置。选择它，然后点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_08.jpg)

Debian 安装程序中的语言选择

1.  同样，选择适合你键盘的键盘映射，然后点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_09.jpg)

Debian 安装程序的键盘选择屏幕

1.  此时，Debian 安装程序将检测你的硬件，然后允许你配置主机名。对于这个选项，选择一个在网络上能识别你的设备的唯一主机名。完成后，点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_10.jpg)

在 Debian 安装过程中选择主机名

1.  然后安装程序将要求你输入你的域名。如果你有域名，请在此处输入；否则，留空。点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_11.jpg)

在安装 Debian 时配置域名

1.  接下来，你将被要求为**root**账户设置密码。为此，你应该创建一个唯一的（最好是随机生成的）密码。你可能知道，root 账户对系统有完全访问权限。设置密码后，点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_12.jpg)

在 Debian 安装过程中输入 root 密码

1.  在接下来的三个屏幕中，您将设置您的用户帐户。首先，输入您的名字和姓氏，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_13.jpg)

设置主要用户帐户的第一个屏幕

1.  然后，输入用户名，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_14.jpg)

创建用户名

1.  用户设置部分的最后一部分将要求您创建一个密码。完成后，再次单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_15.jpg)

为主要用户设置密码

1.  接下来，Debian 将尝试使用**网络时间协议**（**NTP**），如果可用，来配置您的时钟。然后，您将看到一个屏幕，以选择您的时区。确保您的时区被突出显示，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_16.jpg)

配置您的位置，用于时区

1.  现在，我们将对磁盘进行分区。随意对磁盘进行分区，因为就本书而言，没有分区要求。为了本说明，选择了 Debian 的默认选项**引导-使用整个磁盘**。如果您有首选的分区方案，请随意使用。完成后，单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_17.jpg)

Debian 安装的分区部分的第一个屏幕

1.  接下来，您将不得不选择要安装 Debian 的硬盘。在本例中，虚拟机中只有一个可用的硬盘，用于捕获该过程。如果您有多个硬盘，请选择适当的硬盘进行安装，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_18.jpg)

选择 Debian 的目标磁盘

1.  在接下来的部分，Debian 安装程序将询问您是否想要有一个单独的`/home`分区（如果您希望在安装之间保留文件，则建议使用），单独的`/home`，`/var`和`/tmp`分区，或者所有文件在一个分区中。本书没有分区要求，因此选择最符合您偏好的选项。选择完毕后，单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_19.jpg)

磁盘分区选择

1.  接下来，Debian 将显示即将进行的更改摘要。如果这些更改对您来说看起来不错，请确保**完成分区并将更改写入磁盘**被突出显示，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_20.jpg)

分区概述

1.  然后，您将不得不再次确认详细信息。选择**是**，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_21.jpg)

确认分区更改

1.  接下来将安装基本系统；这可能需要一些时间，具体取决于您的计算机和硬盘的速度。之后，您将看到一个屏幕，您将在其中选择最接近您的国家，以设置 Debian 的软件包管理器。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_22.jpg)

选择软件包管理器的位置

1.  接下来，您将为 Debian 的软件包存档选择一个镜像。在大多数情况下，默认选择通常是准确的。因此，除非它猜错了，否则保持默认选择不变，然后单击“**继续**”。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_23.jpg)

选择 Debian 软件包存档的镜像

1.  在下一个屏幕上，Debian 将给您一个机会来配置 HTTP 代理，如果有的话。如果没有，就留空。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_24.jpg)

HTTP 代理配置

1.  接下来，Debian 将配置您的软件包管理器并更新您的源。几个进度条滚动后，您将看到一个新屏幕，询问您是否愿意向 Debian 提交使用统计信息。这些信息对 Debian 的开发人员很有帮助，但并非必需。做出您的选择，然后点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_25.jpg)

选择是否向 Debian 开发人员提供匿名统计信息

下一个屏幕将为我们提供可以添加到系统中的附加软件包，但这些并不是必需的（尽管保留标准系统实用程序是个好主意）。所提供的大多数选项允许我们选择**桌面环境**，但您并不需要安装一个。通常，服务器不会安装桌面环境。但是，如果您正在设置工作站 PC，这可能会有所帮助。

+   **GNOME**：这是 Debian 的默认桌面环境。GNOME 是最先进的，提供了一种独特的与计算机交互的范式。GNOME 大量使用虚拟工作区，这使您可以在几个桌面之间分割您的工作流程。不幸的是，GNOME 对硬件加速的要求相对较低；这意味着如果您没有现代的显卡，它将无法正常运行。

+   **Xfce**：它是 GNOME 的一个非常轻量级的替代品，已经存在很长时间了。Xfce 非常适合处理能力较低的计算机。如今，Xfce 的活跃开发不多，因此它在很多情况下更加稳定，尽管可能不会吸引那些喜欢现代功能的人。

+   **KDE**：它是一个现代的桌面环境，类似于 GNOME，但它更像 Windows 的用户界面。与 GNOME 一样，KDE 的硬件要求相对较低，尽管不像 GNOME 那么严格。KDE 具有备受 Linux 用户尊敬的**Dolphin**文件管理器。

+   **Cinnamon**：最初是作为 GNOME 的一个分支创建的，但它已经发展成为一个独立的桌面环境，几乎没有 GNOME 的依赖。Cinnamon 提供了更传统的桌面风格，同时又具有现代感。

+   **MATE**：它是对较旧的 GNOME 2.x 版本的延续。因此，MATE 在较旧的计算机上运行良好，并且得到比 Xfce 更多的开发。它可能不像 Xfce 那样稳定，但它很接近。

+   **LXDEL**：它也是较老的计算机的一个不错的选择，类似于 Xfce 但不那么受欢迎。

除了桌面环境的选择之外，建议从此列表中选择**SSH 服务器**。也可以选择**Web 服务器**，但最好等到我们讨论 Apache 的部分时再进行安装。

![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_26.jpg)

Debian 软件选择

1.  进行您的选择，然后等待安装程序的其余部分完成，因为 Debian 会安装您在上一步中选择的软件。然后，是时候配置 GRUB 了。**GRUB**是**Grand Unified Bootloader**的缩写，是我们启动系统所必需的。您将被问及是否要将 GRUB 安装到主引导记录中（您很可能会想这样做），因此确保**是**单选框被选中，然后点击**继续**。![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_27.jpg)

GRUB 配置

1.  接下来，选择要安装 GRUB 的目标。在大多数情况下，这将是`/dev/sda`。

GRUB 目标选择

1.  哇！我们终于准备好重启进入新的 Debian 环境了。点击**继续**最后一次，我们就可以开始了！![获取和安装 Debian 8](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_29.jpg)

Debian 安装过程的最后一个屏幕

# 获取和安装 CentOS 7

在这个活动中，我们安装 CentOS 7（比 Debian 的步骤要少得多）。要下载 ISO，请转到以下 URL：

[`www.centos.org/download/`](https://www.centos.org/download/)

DVD ISO 链接应该满足我们的需求。

就像 Debian 的演练一样，我们需要创建一个可引导的光盘或闪存驱动器来开始安装。与 Debian 安装程序不同，现在我们需要一个 DVD-R 光盘，因为镜像太大而无法放入 CD-R 中。

如果您通过闪存驱动器安装，CentOS 维基百科中的以下 URL 描述了该过程：

[`wiki.centos.org/HowTos/InstallFromUSBkey`](http://wiki.centos.org/HowTos/InstallFromUSBkey)

从安装媒体引导后，执行以下步骤：

1.  您将首先看到一个屏幕，要求您在安装过程中选择要使用的语言。选择您的语言，然后单击**继续**。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_30.jpg)

CentOS 安装期间的语言选择

1.  接下来出现的屏幕是安装的两个主要部分之一。这里显示的项目（**日期和时间**，**键盘，语言支持**，**安装源**，**软件选择**，**安装目标**和**网络和主机名**）可以按任何顺序完成。正如您在屏幕截图中所看到的，实际上只有一个部分（**安装目标**）是必需的。基本上，您可以浏览列出的每个部分并完成其任务，然后在完成时单击**开始安装**。如果选择不完成某个部分，将使用其默认值。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_31.jpg)

CentOS 安装过程的第一个主要部分

1.  对于**语言支持**，您将选择您的语言。完成后，单击左上角标有**完成**标签的图标。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_32.jpg)

语言选择

1.  不要跳过**网络和主机名**部分。默认情况下，网络甚至根本没有启用，所以您可以通过单击接口旁边的切换开关来启用它。在底部附近，您可以输入计算机的所需主机名。完成后，单击**完成**。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_33.jpg)

CentOS 安装期间的网络配置

1.  在**日期和时间**部分，您可以设置时钟和位置。请记住，如果您没有在**网络和主机名**部分启用网络接口，则将无法使用 NTP。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_34.jpg)

日期和时间配置

1.  完成**安装目标**部分是强制性的。在这里，您将选择要将 CentOS 安装到哪个磁盘，以及您的分区方案。在本演练中，我们将选择一个磁盘并保留默认分区，但如果愿意，可以自定义分区方案。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_35.jpg)

CentOS 安装程序的磁盘配置部分

1.  默认情况下，CentOS 将是**最小安装**。这意味着没有图形用户界面，只有默认的软件包。如果愿意，您可以选择桌面环境，如 GNOME 或 KDE，选择相应的选项。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_36.jpg)

CentOS 软件选择

1.  单击**开始安装**后，您将被带到安装过程的第二个主要部分，而 CentOS 将在后台安装到您的系统上。这个部分要小得多，只有两个步骤。我们将设置 root 密码并创建一个标准用户帐户。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_37.jpg)

CentOS 用户配置

1.  对于 root 密码，请选择安全的密码。密码强度计会显示密码的预计强度。完成后单击**完成**。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_38.jpg)

输入 root 密码

1.  最后，我们将创建一个标准用户。在这个屏幕上，我们将输入**全名**和**用户名**字段中的值，并为**密码**选择一个强密码。如果需要，您还可以选中标记为**使此用户成为管理员**的复选框。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_39.jpg)

CentOS 用户创建

1.  最后，当安装完成时，点击**重新启动**，我们就完成了。![获取和安装 CentOS 7](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_01_40.jpg)

确认完成 CentOS 安装

完成这些步骤后，可以随意设置所需的 Linux 安装。在未来的章节中，我们将使用这些安装来配置网络并提高我们的知识。

# 总结

在本章中，我们通过设置环境进行了工作。我们讨论了虚拟机和物理机作为网络节点，甚至设置了一个或两个 Debian 和 CentOS 安装。

既然我们已经设置好了环境，现在是时候开始了。在第二章中，*重新审视 Linux 网络基础*，我们将涵盖我们旅程中所需的所有命令，例如配置网络接口，手动连接到网络以及设置网络管理器。敬请关注！


# 第二章：重新审视 Linux 网络基础知识

无论您对 Linux 网络有很多了解，还是刚刚开始，我们将在本章中总结 Linux 网络的基础知识。虽然 Linux 中的 TCP/IP 堆栈实现了与其他平台相同的功能，但使用特定工具来管理这样的网络。在这里，我们将讨论 Linux 如何处理 IP 地址分配、网络设备命名，以及启用和禁用接口。此外，我们还将讨论用于管理接口的图形和非图形工具。

在本章中，我们将涵盖：

+   理解 TCP/IP 协议套件

+   命名网络设备

+   理解 Linux 主机名解析

+   理解 iproute2 和 net-tools 套件

+   手动管理网络接口

+   使用网络管理器管理连接

# 理解 TCP/IP 协议套件

TCP/IP 是存在最流行的网络协议。它不仅是互联网的主要协议套件，而且几乎可以在任何支持网络连接的设备上找到。您的计算机非常了解这个套件，但现在您的手机、电视，甚至一两个厨房电器也支持这项技术。它真的无处不在。尽管 TCP/IP 通常被称为协议，但实际上它是由几个单独的协议组成的**协议套件**。从名称上看，我相信您可以知道其中两个是 TCP 和 IP 协议。此外，还有第三个 UDP，也是这个协议套件的一部分。

**TCP**是**传输控制协议**的缩写。它负责将网络传输分解成序列（也称为数据包或段），然后将它们发送到目标节点，并由 TCP 在另一端重新组装成原始消息。除了管理数据包，TCP 还确保它们被正确接收（尽其所能）。它通过**错误校正**来实现这一点。如果目标节点未收到数据包，TCP 将重新发送。它之所以知道这一点，是因为有**重传时间**。

在讨论错误校正和重传之前，让我们先看一下 TCP 发送数据时实际使用的过程。在建立连接时，TCP 执行**三次握手**，这包括在通信节点之间发送的三个特殊数据包。第一个数据包**SYN**（同步）由发送方发送给接收方。基本上，这是节点宣布它想要开始通信的方式。在接收端，一旦（如果）接收到数据包，就会向发送方发送**SYN/ACK**（同步确认）数据包。最后，发送方向接收方发送一个**ACK**（确认）数据包，这是对传输准备就绪的总体验证。从那时起，连接建立，两个节点能够相互发送信息。然后发送更多数据包，这构成了通信的其余部分。

如果我们生活在一个完美的世界，这就是所需要的一切。数据包永远不会在传输中丢失，带宽是无限的，数据包在传输过程中永远不会损坏。不幸的是，我们并不生活在一个完美的世界，数据包经常丢失和/或损坏。TCP 具有内置功能来处理这些问题。错误校正有助于确保接收到的数据包与发送的数据包相同。TCP 数据包包含一个校验和，并使用算法进行验证。如果验证失败，数据包被视为不正确，然后被丢弃。这种验证并不完美，所以您刚刚下载的文件仍然可能有一两个错误，但总比没有好。大多数时候，它运行得很好。

TCP 的流量控制功能处理数据传输的速度。虽然我们大多数极客拥有一套非常好的网络硬件，能够处理大量带宽，但互联网并不是一个一致的地方。您的高端交换机可能能够处理任何您投入其中的东西，但如果连接的上游某个地方存在薄弱环节，那就无关紧要了。网络传输的速度取决于最慢的点。当您向另一个节点发送传输时，您只能发送与其缓冲区能够容纳的数据量相同的数据。在某个时刻，其缓冲区将填满，然后无法接收任何额外的数据包，直到处理已有的数据包。此时发送到接收方的任何额外数据包都将被丢弃。发送方看到它不再收到 ACK 回复，然后减速并减慢传输速度。这是 TCP 用来根据接收节点能够处理的情况调整传输速度的方法。

流量控制通过利用所谓的**滑动窗口**来实现。接收节点指定了所谓的**接收窗口**，它告诉发送方在变得不堪重负之前能够接收多少数据。一旦接收窗口用尽，发送方就等待接收方澄清它再次准备好接收数据。当然，如果接收端向发送方发送了一个准备好接收数据的更新，而发送方却没有收到备忘录，如果发送方永远等待在传输中丢失的全清消息，我们可能会遇到真正的问题。幸运的是，我们有一个**持续计时器**来帮助处理这个问题。基本上，持续计时器表示发送方愿意等待多长时间，然后需要验证连接是否仍然活动。一旦持续计时器到期，发送方向接收方发送另一个数据包，以查看它是否能够处理。如果发送了回复，回复数据包将包含另一个接收窗口，表明它确实准备好继续对话。

**IP**（即**Internet Protocol**）处理 TCP 想要发送或接收的数据包的实际发送和接收。在每个数据包中，有一个称为**IP 地址**的目的地（我们将在本章中进一步讨论）。每个连接的网络接口都将有自己的 IP 地址，IP 协议将使用它来确定数据包需要去哪里，或者它来自哪个设备。TCP 和 IP 共同组成一个强大的团队。TCP 将通信分成数据包，而 IP 负责将它们路由到它们的目的地。

当然，还有**UDP**（即**User Datagram Protocol**），它也是套件的一部分。它与 TCP 非常相似，因为它将传输分成数据包。然而，主要区别在于 UDP 是**无连接**的。这意味着 UDP 不验证任何内容。它发送数据包，但不保证传递。如果目标没有收到数据包，它将不会被重新发送。

初次了解 UDP 的人可能会质疑为什么会考虑使用这样一个不可靠的协议。事实上，在某些情况下，诸如 TCP 这样的面向连接的协议可能会给某些类型的传输增加不必要的开销。Skype 是一个例子，它提供互联网上的音频通话和视频通话。在通信过程中，如果任一端丢失了一个数据包，重新发送它就没有多大意义。您只会听到一两秒钟的杂音，重新发送数据包肯定不会改变您难以听到一两个字的事实。对这样的传输添加错误校正将是毫无意义的，而且会增加开销。

讨论 TCP/IP 的全部内容本身就是一本书。在 Linux 中，这个协议的处理方式与其他平台基本相同，真正的区别在于协议的管理方式。在本书中，我们将讨论我们可以管理这个协议并调整我们的网络的方法。

# 命名网络设备

如今，一台计算机拥有多个网络接口并不罕见。例如，如果你使用的是笔记本电脑（而不是超极本），很可能你有一个有线和一个无线网络接口。每个网络接口都有自己的 IP 地址，并且它们彼此独立运行。事实上，你甚至可以在多个接口之间路由流量，尽管这在大多数 Linux 发行版中通常默认情况下是禁用的。就像每个接口都有自己的 IP 地址一样，每个接口也会被系统通过自己的设备名称来识别。在我们进一步讨论之前，打开终端并输入以下命令来查看你系统上的设备名称：

```
ip addr show

```

你的输出将如下所示：

![命名网络设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_01.jpg)

ip 命令的输出，显示网络接口和地址分配

在这个例子中，我们看到列出了三个网络接口。第一个`lo`是本地环回适配器。第二个`eth0`是有线接口。最后，`wlan0`代表无线接口。根据这个输出，你可以推断出有一个网络电缆插入了（`eth0`有一个 IP 地址），并且它目前没有使用无线接口（`wlan0`没有列出 IP 地址）。

先前显示的输出来自运行 Debian 系统的系统。现在，让我们来看看在 CentOS 系统上运行相同命令时的输出：

![命名网络设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_02.jpg)

ip 命令的输出，这次是从 CentOS 系统运行的

你看到了区别吗？如果你看有线连接，你会发现它的命名方式与 Debian 示例中的有线连接有很大不同。在 Debian 中，它的名称是`eth0`。但在 CentOS 中，它的名称是`enp0s3`。这就引出了本节的重点：CentOS 和 Debian 中的网络设备命名方式不同。

过去，有线以太网设备的名称以`eth`为前缀，无线设备以`wlan`为前缀。例如，第一个有线以太网适配器将被标记为`eth0`；第二个将是`eth1`，依此类推。无线设备也是类似处理的，第一个设备是`wlan0`，第二个将是`wlan1`，依此类推。在 Debian 中，这仍然是这种情况（即使在较新的版本中也是如此）。然而，一些使用**systemd**的发行版为网络设备采用了不同的命名方案。事实上，Debian 9 将在发布时更改其接口的命名方案。

这种更改的原因是因为以前的命名方案有时是不可预测的。当机器重新启动时，可能会出现网络设备名称交叉，导致对接口的混淆。各种发行版以自己的方式处理这个问题，但 systemd 具有内置的命名方案，该方案基于系统总线中卡的位置，而不仅仅使用`eth0`、`eth1`等名称，因为设备被探测。如前所述，尽管 Debian 8 也使用 systemd，但 Debian 仍然使用较旧的命名方案。在本书中，我们将练习 systemd 命令；但是，在第五章*监视系统资源*中，我们将更详细地解释 systemd，所以如果你还不知道它是如何工作的，也不用太担心。

在第二个示例中使用的 CentOS 机器上，有线网络卡被指定为`enp0s3`。那么，这到底意味着什么呢？首先，我们知道`en`代表以太网，这部分指定是给有线网络卡的。给定名称的其余部分代表系统总线上网络卡的位置。由于每个有线卡（如果您有多个）都会驻留在自己的物理位置，因此给定设备的名称是可预测的。如果您要为特定网络接口编写启动脚本，您可以相当肯定地知道您将编写脚本来引用适当的设备。

# 理解 Linux 主机名解析

在网络上，通过名称查找其他资源要比记住我们连接到的每个资源的 IP 地址方便得多。默认情况下，通过名称查找主机可能需要一些配置才能正常工作。例如，您可以尝试使用`ping`命令针对您的 Linux 机器之一的名称，可能会得到响应，也可能不会。这是因为您连接的资源的 DNS 条目可能不存在。如果不存在，您将看到类似以下的错误：

```
ping: unknown host potato

```

但是，如果您通过 IP 地址 ping 设备，很可能会得到响应：

```
64 bytes from 10.10.96.10: icmp_seq=2 ttl=64 time=0.356 ms

```

### 注意

按下键盘上的*Ctrl* + *C*来中断您的`ping`命令，因为如果找到连接，它将永远 ping 下去。

这样做的原因是为了使网络主机能够联系另一个主机，它需要知道其 IP 地址。如果您输入的是名称而不是 IP 地址，机器将尝试主机名解析，如果**域名系统**（**DNS**）中有机器的有效条目，您将能够收到回复。在具有基于 Windows 的**动态主机配置协议**（**DHCP**）和 DNS 服务器的 Microsoft 网络中，每当服务器分配 IP 地址给主机时，它通常会注册一个**动态 DNS**条目。Linux 基于的 DHCP 和 DNS 服务器也能够进行动态 DNS，但默认情况下不会配置，管理员也很少启用。在全 Linux 网络或任何不动态分配 DNS 的网络中，此 ping 很可能会失败。我们将在第第六章*配置网络服务*中更详细地讨论 DNS。

在大多数情况下，DNS 不是 Linux 主机解析主机名的第一个地方。系统上也保存有一个本地文件（`/etc/hosts`），您的机器将首先检查该文件。如果您要联系的主机的条目未包含在其中，您的机器将联系其配置的主 DNS 服务器，以查找您输入的名称的 IP 地址。以下是`host`文件的示例：

```
127.0.0.1    localhost
127.0.1.1    trinity-debian

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

在呈现的`hosts`文件中，我们可以看到`localhost`和`trinity-debian`的条目。这两个条目以`127.0.x.x` IP 地址开头，代表了机器本身。要测试这一点，请尝试 ping`localhost`以及您的机器的名称（在本例中为`trinity-debian`）。无论哪种方式，您都会得到回复。这是因为机器知道自己的主机名，而`localhost`使用环回适配器来访问自己。如果您愿意，您可以在此文件中创建额外的名称到 IP 地址的匹配。例如，如果您有一个名为`potato`的计算机，IP 地址为`10.10.96.10`，您可以将其添加到`hosts`文件的末尾，如下所示：

```
10.10.96.10 potato

```

从现在开始，你可以通过输入`potato`来访问 IP 地址`10.10.96.10`。你可以 ping 它，甚至在浏览器的地址栏中输入它（如果机器正在提供 web 内容）。事实上，主机条目甚至不需要是你网络中的本地资源。你甚至可以输入外部网站的 IP 地址，并通过不同的名称访问它。然而，这只是在理论上有效——一个设计良好的网站可能不会在这种情况下运行。

虽然首先检查`/etc/hosts`，但你的 Linux 安装包括一个文件`/etc/nsswitch.conf`，它用于确定主机解析的顺序。相关行以`hosts`开头，你可以使用以下命令轻松检查你的机器上的主机解析顺序：

```
cat /etc/nsswitch.conf |grep hosts

```

你将得到以下输出：

```
hosts:          files mdns4_minimal [NOTFOUND=return] dns

```

在这里，我们可以看到系统设置为首先检查`files`，这代表本地文件，包括`/etc/hosts`。如果搜索的是本地域名并且没有找到，`NOTFOUND=return`条目会导致搜索的其余部分中止。如果你搜索其他内容，下一个将被使用的资源是 DNS，如最后一个条目所示。除非你改变了这个文件，你的发行版也很可能设置为首先在本地主机文件中查找，如果资源在本地找不到，然后再查找 DNS。

# 理解 net-tools 和 iproute2 套件

相当长的一段时间以来，**net-tools**一直是在 Linux 系统上管理网络连接的工具套件。net-tools 套件包括诸如`ifconfig`、`route`、`netstat`等命令（我们将很快讨论）。net-tools 的问题在于，它的开发者已经十多年没有更新了，这使得许多发行版选择放弃它，转而选择**iproute2**套件，它提供了相同的功能（但使用不同的命令来实现相同的目标）。尽管 net-tools 正在被弃用，仍然有很多发行版包括它。例如，Debian 包括 iproute2 和 net-tools，因此你可以使用任一套件的命令。在 CentOS 中，iproute2 是默认安装的，而 net-tools 则不是。如果你想使用旧的 net-tools，你可以使用以下命令在 CentOS 中安装它：

```
# yum install net-tools

```

那么，为什么你要安装`net-tools`，如果它正在被弃用？许多系统仍然使用 net-tools 套件的命令，因此它不会很快从 Linux 社区消失。学习 net-tools 以及更新的 iproute2，将使你能够轻松适应任何环境。特别是对于使用旧发行版的旧数据中心来说，情况尤其如此。

让我们看看这些套件的实际操作。首先，要报告有关你的网络连接的基本信息，请输入以下命令：

```
/sbin/ifconfig

```

你应该看到以下输出：

![理解 net-tools 和 iproute2 套件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_03.jpg)

ifconfig 命令的输出

在这里，我们可以看到来自内部有线连接（`eth0`）和环回适配器（`lo`）的统计信息。我们看到`HWaddr`，这是网络卡的**MAC 地址**。我们还有`inet addr`，这是网络卡由**DHCP 服务器**提供的 IP 地址。此外，我们可以看到子网掩码`Mask`，在这种情况下是`255.255.252.0`。在解决网络问题时，我们会使用这个工具来检查这些基本信息，比如确保我们有一个 IP 地址并且在适当的子网上。此外，我们还可以看到在接口上发送和接收的数据包数量，以及错误的数量。

使用 iproute2 套件，我们可以使用以下命令找到大部分相同的信息：

```
ip addr show

```

这是一个参考机器的输出：

![理解 net-tools 和 iproute2 套件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_04.jpg)

ip addr show 命令的输出

正如你所看到的，报告的信息大部分是相同的，尽管布局有些不同。例如，一个区别是你看不到发送和接收的数据包数量，也没有错误计数（默认情况下）。过去，以下命令将显示正在使用的 IP 地址以及发送和接收的数据包：

```
ip -s addr show

```

![理解 net-tools 和 iproute2 套件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_05.jpg)

使用添加了-s 标志的 ip addr show 命令的输出

不幸的是，最近版本的 iproute2 套件似乎不再显示这些信息（尽管添加了`-s`开关），但我们将在本书的后面看到更多的工具。

### 注意

在前面的命令中，你也可以输入整个字符串（地址）而不是`addr`。

```
ip address show

```

输出将是相同的。这些示例中显示的命令是压缩过的，这样可以节省输入时间。

iproute2 套件中有许多其他命令，我们将在本书继续讨论。现在，重要的是要理解这两个命令套件之间的区别，并注意 net-tools 不会永远可用。在本书编写的时间段内，两者都很常见。然而，iproute2 是未来的主流。

在结束本节之前，iproute2 套件中有一个非常简单的命令可能会很有用：

```
hostname

```

这个简单的命令只是打印出你的 shell 所连接的机器的主机名。如果你使用默认的 bash 提示符，很可能你已经知道你的机器的主机名。然而，hostname 命令至少可以帮助你验证你的设备是否报告了你认为它应该报告的主机名；当你处理名称解析问题时，这可能是有用的。

# 手动管理网络接口

在大多数情况下，在安装所需的 Linux 发行版后，它会通过 DHCP 接收一个 IP 地址，然后就可以使用了。无论你是使用图形桌面环境还是没有图形界面的 shell 环境，大部分魔术都是在后台发生的。虽然有图形工具来管理你的网络连接，但任何你可以通过图形工具做的事情，你也可以通过 shell 来做。在服务器的情况下，可能根本没有图形环境，所以学会如何通过 shell 管理你的网络连接非常重要。在本节中，我们将讨论在 Debian 中手动配置接口的方法，然后讨论如何在 CentOS 中做同样的事情。

在上一节中，讨论了两种查找当前 IP 地址的方法。根据你的发行版是否提供了 net-tools 或 iproute2，你可以使用其中一种方法或两种方法（或两者）。当然，这是第一步。你有连接吗？检查你是否有 IP 地址是一个合乎逻辑的起点。你也可以利用一个简单的 ping 测试：

```
ping www.yahoo.com

```

如果你得到了回应，很可能你有网络连接。然而，如果你没有得到回应，并不一定意味着你的网络有问题。有些站点配置为不响应 ping 测试。在可能的情况下，最好针对本地资源进行 ping 测试（比如你的本地 DNS 或 DHCP 服务器）。

在 Linux 中，ping 的工作方式与 Windows 有些不同。首先，在 Linux 中，`ping`命令默认会一直运行下去。要退出它，按键盘上的*Ctrl* + *C*。如果你希望`ping`在尝试一定次数后停止，添加`-c`标志并附上你希望它尝试的次数。在这种情况下，我们的`ping`命令将是这样的：

```
ping -c 4 www.yahoo.com

```

在这种情况下，`ping`将尝试四次，然后停止，并向你报告一些基本统计信息。

知道如何检查你是否连接是一回事，但当你没有连接时该怎么办呢？或者如果你的网络连接是活跃的，但报告无效信息，你需要重新配置它呢？

首先，让我们探讨如何检查我们当前的配置。在 Debian 中，默认控制网络设备的文件是以下文件：

```
/etc/network/interfaces

```

根据几个变量，包括您如何配置 Debian 安装，这个文件可能会有不同的创建方式。首先，您可能会看到列出了几个接口，比如回环适配器、有线以太网和无线。如果您有多个有线接口，您也会在这里看到任何额外的适配器。简单地说，这个文件是一个**配置文件**。它是一个文本文件，包含了底层 Linux 系统理解的信息，并导致设备按照文件中指定的方式进行配置。

要编辑这样的文件，有许多 Linux 文本编辑器可用，包括 GUI 和基于终端的。我个人最喜欢的是**vim**，尽管许多管理员通常从**nano**开始。nano 文本编辑器非常容易使用，但功能很少。另外，vim 比 nano 有更多的功能，但使用起来有点难。你可以自己选择。要在 nano 中打开一个文件，你只需要输入`nano`，然后加上你想编辑的文本文件的名称。如果文件不存在，命令会在你保存文件时创建它。对于我们的`/etc/network/interfaces`文件，命令将类似于这样：

```
# nano /etc/network/interfaces

```

使用 nano 只是简单地打开一个文件，使用键盘上的箭头键将插入点移动到您想要输入的位置，按下*Ctrl* + *O*保存文件，然后按下*Ctrl* + *X*退出。还有更多功能，但就目前来说，这就是我们需要的。本书不涵盖 vim 的教程，但如果你愿意，可以随意尝试。

现在，回到我们的`/etc/network/interfaces`文件的主题。重要的是要注意，这个文件对于以太网和无线适配器并不是必需的。如果在这个文件中除了回环设备之外什么都没有，那就意味着网络连接是由**网络管理器**来管理的。网络管理器是一个用于管理客户端网络连接的图形工具（我们将在本章后面讨论）。对于本节中的目的，当您第一次设置 Debian 时，通常会安装网络管理器，特别是当您决定包括图形桌面环境时（如 GNOME、Xfce 等）。如果您选择了图形环境，那么网络管理器很可能已经为您设置好，并且正在处理配置您的接口的工作。如果您的`interfaces`文件除了回环适配器的条目之外是空白的，那就意味着网络管理器正在处理这个任务。

在 Debian 中，非常常见的是在野外看到没有安装图形环境的安装。对于服务器来说，通常不需要 GUI 来实现其目的。典型的 Linux 管理员会为服务器配置最少的必需软件包，以便它完成其工作，这通常不包括桌面环境。在这种情况下，可能根本没有安装网络管理器。如果没有安装，那么`/etc/network/interfaces`文件将负责设置连接。在其他情况下，也许网络管理器已经安装，但是被管理员禁用了，而是在这个文件中配置了网络连接。

那么，什么时候应该使用网络管理器，什么时候应该只在`interfaces`文件中配置连接？对于最终用户工作站（台式机和笔记本电脑），几乎总是首选网络管理器。对于服务器，特别是在设置静态 IP 地址时，首选在`/etc/network/interfaces`中设置配置。

我们已经讨论了`interfaces`文件是什么，以及何时使用它。现在，让我们看一下你可能会看到的`一些`各种类型的配置。首先，让我们看一下只列出本地回环适配器时的`interfaces`文件：

```
cat /etc/network/interfaces

# The loopback network interface
auto lo
iface lo inet loopback

```

### 注意

注释以第一个字符`#`声明，在解析配置文件时会被忽略。在前面的例子中，第一行被忽略，只是作为信息。

在这个例子中，这台机器很可能正在使用网络管理器，因为有线（通常是`eth0`）或无线（通常是`wlan0`）接口都没有显示。为了验证这一点，我们可以通过以下命令检查网络管理器是否正在运行：

```
ps ax |grep NetworkManager

```

如果网络管理器正在运行，你可能会看到这样的输出：

```
446 ?        Ssl    0:00 /usr/sbin/NetworkManager --no-daemon

```

这个谜团已经解开了；这台机器使用了网络管理器，所以在`/etc/network/interfaces`中没有存储`eth0`或`wlan0`的配置。现在，让我们看一个网络管理器没有使用的机器的示例。要在这样的安装中配置`eth0`，`interfaces`文件看起来会类似于这样：

```
# The loopback network interface
auto lo
iface lo inet loopback

# Wired connection eth0
auto eth0
iface eth0 inet dhcp

```

正如我们之前所做的那样，我们仍然有回环条目，但在文件的末尾，包括了`eth0`的配置细节。就像我们的回环条目一样，我们声明`auto`，然后是一个接口名`eth0`，这意味着我们希望接口`eth0`自动启动。在下一行中，我们澄清了我们希望为接口`eth0`使用`dhcp`，以便它将从 DHCP 服务器自动获取 IP 地址。

在现实世界中，没有理由放弃网络管理器，而选择手动配置连接，当我们要做的只是使用 DHCP 时。然而，这个例子被包含在这里，因为在服务器从 DHCP 服务器接收**静态租约**而不是动态租约的情况下，这实际上是相当常见的。使用静态租约，DHCP 服务器将为特定 MAC 地址提供相同的 IP 地址。因此，在这种情况下，服务器可以为其指定 IP 地址，但 IP 地址仍然是由 DHCP 服务器提供的。这也被称为**DHCP 保留**。

当然，也有可能（也许更常见）只在 interfaces 文件中声明静态 IP。我们将在下面探讨这种方法。但是，值得指出的是，静态租约具有额外的好处。使用静态租约，节点的 IP 配置不会与其安装的发行版的配置绑定。如果从活动媒体引导，甚至重新安装发行版，节点每次接口启动时都会收到相同的 IP 地址。静态租约的另一个好处是，您可以在一个中心位置（在 DHCP 服务器上）配置所有节点的静态 IP，而不必跟踪每台机器的单独配置文件。

### 注意

重要的是要注意，在`interfaces`文件中看到接口列出`dhcp`并不总是意味着正在使用静态租约。对于 Debian 来说，管理员通常只是不安装网络管理器，然后在启动服务器时手动输入`interfaces`文件。

现在，让我们看一个示例`interfaces`文件，其中手动配置了静态 IP：

```
# The loopback network interface
auto lo
iface lo inet loopback

# Wired connection eth0
auto eth0
iface eth0 inet static
 address 10.10.10.12
 netmask 255.255.248.0
 network 10.10.10.0
 broadcast 10.10.10.255
 gateway 10.10.10.1

```

首先，注意以下一行的变化：

```
iface eth0 inet static

```

最后，我们声明了`static`而不是`dhcp`。如果我们忘记更改这个，那么配置文件的所有剩余行将被忽略。

然后，我们声明了接口`eth0`的统计信息。我们将 IP 地址设置为`10.10.10.12`，子网掩码设置为`255.255.248.0`，我们加入的网络设置为`10.10.10.0`，广播 ID 为`10.10.10.255`，网关为`10.10.10.1`。我们将在本书的后面讨论这些值实际上是什么意思，但现在需要注意的重要事情是这个文件的语法。

现在您可能想知道我们如何使这些更改生效，既然我们费力地配置了我们的接口。要这样做，您将使用以下命令：

```
# systemctl restart networking.service

```

在 CentOS 中，手动配置网络接口的过程与 Debian 系统有些不同。首先，我们需要知道机器上安装了哪些接口。运行以下命令将列出它们以及当前分配的任何 IP 地址：

```
ip addr show

```

在本节中，我将使用`enp0s3`，这是本书用于测试的测试机器上的默认设置。如果您的设置不同，请相应更改这些示例命令。无论如何，既然我们知道我们正在使用哪个接口，让我们配置它。接下来，导航到以下目录：

```
cd /etc/sysconfig/network-scripts

```

如果列出该目录中的文件存储（`ls`命令），您应该看到一个与接口名称匹配的配置文件。在我们的示例中，`enp0s3`，您应该看到一个名为`ifcfg-enp0s3`的文件。

用您选择的文本编辑器打开此文件，您将看到配置类似于以下内容：

```
HWADDR="08:00:27:97:FE:8A"
TYPE="Ethernet"
BOOTPROTO="dhcp"
DEFROUTE="yes"
PEERDNS="yes"
PEERROUTES="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_PEERDNS="yes"
IPV6_PEERROUTES="yes"
IPV6_FAILURE_FATAL="no"
NAME="enp0s3"
UUID="a5e581c4-7843-46d3-b8d5-157dfb2e32a2"
ONBOOT="yes"

```

如您所见，此默认文件使用`dhcp`，列在第三行。要配置此连接以利用静态地址，我们需要相应地更改文件。文件的更改部分已用粗体标记：

```
HWADDR="08:00:27:97:FE:8A"
TYPE="Ethernet"
BOOTPROTO="static"
IPADDR=10.10.10.52
NETMASK=255.255.255.0
NM_CONTROLLED=no
DEFROUTE="yes"
PEERDNS="yes"
PEERROUTES="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_PEERDNS="yes"
IPV6_PEERROUTES="yes"
IPV6_FAILURE_FATAL="no"
NAME="enp0s3"
UUID="a5e581c4-7843-46d3-b8d5-157dfb2e32a2"
ONBOOT="yes"

```

在这里，我们对文件进行了四处更改。首先，我们将`BOOTPROTO`更改为`static`。然后，在其下面添加了以下全新的行：

```
IPADDR=10.10.10.52
NETMASK=255.255.255.0
NM_CONTROLLED=no

```

我相信您可以理解前两行的作用。我们添加的第四行可能也很明显，但以防万一，我们基本上告诉系统，我们宁愿不通过网络管理器管理连接，并且希望自己通过此配置文件处理。

当然，我们需要重新启动网络以使这些更改生效。由于 CentOS 使用 systemd（就像 Debian 8 一样），命令非常相似：

```
# systemctl restart network.service

```

就是这样。我们已经在 Debian 和 CentOS 中手动设置了网络接口。

# 使用网络管理器管理连接

虽然我们刚刚费力地手动配置了网络接口，但并不总是需要这样做。例如，最终用户的工作站将受益于网络管理器为我们处理这项工作。对于笔记本电脑及其无线接口，网络管理器比大多数人做得更好。

网络管理器通常默认安装在大多数 Linux 发行版中。对于 Debian 来说，通常在选择图形桌面环境时安装。如果您选择了仅安装 shell（在安装过程中取消了桌面环境的选项），那么您可能没有安装它。要确定，请执行以下命令（在 Debian 和 CentOS 上都适用）：

```
ps ax |grep NetworkManager

```

如果您看到网络管理器正在运行，则已安装。但为了确保，您可以在 Debian 中执行以下命令：

```
aptitude search network-manager

```

如果安装了网络管理器，您将看到它列在以下位置（左侧将有一个`i`标记）：

在 CentOS 中，您可以使用以下命令检查网络管理器是否已安装：

```
yum list installed |grep NetworkManager

```

如果您正在运行图形桌面环境，您可能在系统托盘中运行了网络管理器的实现。如果是这样，请随时使用可用的 GUI 工具管理您的连接。根据您使用的图形桌面环境，执行此操作的说明将有所不同。在本节中，我们讨论了一种更通用的方法来利用网络管理器配置连接。这种方法是使用以下命令：

```
nmtui

```

`nmtui`命令允许您在 shell 环境中配置网络管理器，但具有类似 GUI 的控件。

![使用网络管理器管理连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_06.jpg)

通过 nmtui 配置系统的网络连接

如果我们点击**编辑连接**，我们将看到机器上可用的接口列表：

![使用网络管理器管理连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_07.jpg)

nmtui 接口选择

当我们选择一个接口时，我们首先会看到一些基本信息。

![使用网络管理器管理连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_08.jpg)

在 nmtui 中编辑连接的第一个屏幕

编辑此接口的 IP 地址，请按下箭头键选择**<自动>**在**IPv4 配置**左侧，并按*Enter*。然后，按右箭头键选择**<显示>**选项并展开其余字段。

![使用网络管理器管理连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_09.jpg)

使用 nmtui 编辑连接

要编辑项目，请按下箭头键到字段旁边的**<添加...>**选项。它会展开一个文本框，允许您编辑该项目。

![使用网络管理器管理连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_02_10.jpg)

使用 nmtui 编辑连接

完成后，滚动到底部并按*Enter*在**<确定>**上保存您的更改。您应该能够选择通过网络管理器管理您的连接。

# 摘要

在本章中，我们讨论了 Linux 中 TCP/IP 网络的基础知识，甚至手动配置了我们的接口。我们探讨了如何编辑与 Debian 和 CentOS 相关的配置文件，以及如何在两个平台上重新启动网络。我们简要讨论了 systemd 方法，尽管我们将在第五章中更深入地探讨 systemd，*监视系统资源*。我们通过使用`nmtui`工具为我们的系统配置网络管理器来结束本章。

在下一章中，我们将看看如何使用**安全外壳**（**SSH**）远程管理我们的系统。


# 第三章：通过 SSH 在节点之间通信

SSH 是 Linux 网络管理员最重要的工具之一。它允许您远程连接到服务器和其他工作站，并在您喜爱的终端仿真器中进行工作，所有这些都可以在您的办公桌上完成。虽然 SSH 可能不是每种情况下的完美工具，但一旦开始使用，您就无法想象没有它的生活。

在本章中，我们探讨 SSH 并涵盖以下主题：

+   使用 OpenSSH

+   安装和配置 OpenSSH

+   通过 openssh-client 连接到网络主机

+   OpenSSH 配置文件

+   理解和使用`scp`

+   通过`scp`将文件传输到另一个节点

+   通过 SSH 进行流量隧道

+   生成公钥

+   保持 SSH 连接活动

+   探索 SSH 的替代方案-使用 Mosh（移动 shell）

# 使用 OpenSSH

**SSH**，或**安全外壳**，是一个非常方便的实用程序。SSH 并非在服务器室执行任务的绝对要求，但它是使您的生活变得更加轻松的工具之一。通过 SSH，您可以在不同的 Linux 机器上执行命令，就好像您就坐在它的面前一样。当然，您可以随时走进服务器室，拿起键盘开始工作，但现在远程管理才是最重要的。特别是如果轮到您值班并且办公室出现问题。根据问题的性质，SSH 可能允许您在家中（甚至在智能手机上）解决问题，而无需一直走到公司的服务器室。这还不是全部；SSH 还允许您将文件从一台机器复制到另一台机器，并在服务器上的目录上设置一个实际的存储挂载，可以在您的工作站上像本地文件系统的一部分一样处理。

连接到远程主机并打开命令 shell 的概念并不新鲜，SSH 也不是第一个这样做的工具。其他解决方案，如 telnet 或 rlogin，已经存在了相当长的时间。使 SSH 令人向往的是它比早期技术更加安全，因为通信是加密的。SSH 有两种协议，协议 1 和协议 2。协议 1 绝对不应该在任何情况下使用，因为它不再安全。使用协议 1 发送的流量可能会被攻击者拦截。我们将在第九章*保护您的网络*中讨论 SSH 的这一方面，但现在我想确保您了解，您不应该使用协议 1 的 SSH 连接。您不应该向任何主机提供协议 1。如今，协议 2 是默认的。

默认情况下，SSH 使用端口 22 进行通信。如果防火墙阻止了这个端口，您将无法连接。这在以 Windows 为中心的企业中非常常见，因为 SSH 在 Linux/UNIX 世界中更为常见。通过更改 SSH 服务器的配置，您可以将其配置为监听任何您喜欢的端口。虽然我们暂时不会讨论如何配置这一点（我们将在第九章*保护您的网络*中讨论这一点），但这里提到是因为重要的是您可能会遇到一种情况，即无法连接到 SSH 服务器，例如当端口关闭或已更改为其他端口时。

尽管我提到学习 SSH 实际上并不是在服务器或工作站上执行任务的必需条件，但强烈建议您花时间学习它。不仅是使用 Linux 服务器的公司希望您了解它，您也不想错过它的优势。值得庆幸的是，尽管 SSH 非常有用，但学习它并不难。您可以在五分钟内轻松学会最基本的功能，或者在一周内学会高级用法。

# 安装和配置 OpenSSH

OpenSSH 有两个部分，客户端应用程序和服务器应用程序。在您的发行版中，默认情况下可能已安装了客户端应用程序。客户端允许您通过 SSH 连接到其他节点，但仅具有客户端不允许其他人连接到您。如果要通过 SSH 访问某台机器，则该机器还必须安装 SSH 服务器应用程序。您选择的发行版可能默认安装了服务器应用程序，但大多数不会。这是出于安全考虑-除非您绝对需要运行并侦听连接的应用程序，否则应该不存在。应用程序越少，攻击面就越小。

在 Debian 中，SSH 服务器是安装过程中的一个选项。如果选择了，SSH 的服务器应用程序将存在并默认启动。要检查 Debian 系统上是否安装了 SSH 服务器包，请执行以下命令：

```
aptitude search openssh-server

```

在输出中，如果第一个字符是`i`，则表示已安装该软件包。您可以使用以下命令检查**sshd**服务是否正在运行：

```
ps ax | grep sshd

```

如果服务未运行，可以通过在 Debian 上执行以下命令来启动它：

```
# systemctl start ssh.service

```

在 Debian 上，您可以通过执行以下命令来检查 SSH 服务的状态：

```
# systemctl status ssh.service

```

如果正在运行，则输出应包括`active (running)`：

如果您的系统没有安装 SSH 服务器包，可以使用以下命令安装它：

```
# apt-get install openssh-server

```

安装软件包后，使用以下命令检查服务的状态以查看是否已启用：

```
systemctl status ssh.service

```

否则，下次启动机器时它将不会自动启动。

在 CentOS 中，您还可以使用`systemctl`命令来检查 SSH 服务的状态，尽管守护程序的名称有点不同：

```
systemctl status sshd.service

```

在 Debian 中的上一个命令中，服务的名称是`ssh.service`。在 CentOS 中，它的名称是`sshd.service`。在 CentOS 中，SSH 的客户端和服务器包都是默认安装的，因此在 CentOS 系统完成安装后，您应该已经拥有它们。如果由于某种原因未安装该软件包，可以通过`yum`安装：

```
# yum install openssh-server

```

安装后，请通过检查状态来确保服务已启用：

```
systemctl status sshd.service

```

如果 SSH 服务未处于启用状态（启动时启用），请执行以下命令：

```
# systemctl enable sshd.service

```

现在，SSH 已安装在您的机器上，我们准备开始使用它。

## 通过 openssh-client 连接到网络主机

对于此实验，您至少需要一个具有活动 SSH 服务器的 Linux 安装，以及另一个至少安装了 SSH 客户端的安装。对于客户端，您需要在 CentOS 中安装`openssh-clients`软件包，或在 Debian 中安装`openssh-client`软件包。SSH 的客户端软件包在两者上默认安装，因此除非软件包已被删除，否则您不需要安装它。对于此活动，服务器端或客户端端的连接使用哪种发行版并不重要。随意混合使用。

接下来，我们需要记录我们希望连接到的节点的 IP 地址。无论发行版如何，您都应该能够通过执行以下命令来发现 IP 地址：

```
ip addr show

```

要通过 SSH 连接到该机器，请执行针对主机的 IP 地址的`ssh`命令。例如，如果要连接的主机具有 IP 地址`192.168.1.201`，请执行以下命令：

```
ssh 192.168.1.201

```

只要您的用户名在两端相同，该命令应该会要求您输入密码，然后让您进入。如果您要连接的主机上的用户名与您的用户名不同，请像这样将适当的用户名添加到命令中：

```
ssh jdoe@192.168.1.201

```

使用 SSH，你可以使用任何在那里存在的用户名连接到另一个 Linux 安装，只要你知道它的密码。事实上，根据供应商如何配置发行版，你甚至可以直接以 root 身份登录。在 CentOS 中，默认情况下启用了 root 登录。在 Debian 中，除非你使用 RSA 密钥（我们将在第九章 *保护你的网络*中讨论这个问题），否则不允许通过 SSH 登录 root。尽管我们将在那一章讨论更多关于安全性的内容（包括如何允许/禁止用户），但现在重要的是要理解通过 SSH 允许 root 访问系统是一个非常糟糕的主意；我希望你会在生产服务器和工作站上禁用这个功能。如果你希望现在禁用 root 访问，请转到第九章 *保护你的网络*的相关部分，然后再回到这里。

SSH 还允许你指定主机名而不是 IP 地址。事实上，主机名是首选的方法，因为如果你的网络中有大量的机器，很难记住 IP 地址。SSH 本身不解析主机名；它依赖 DNS 来完成。如果你的网络上的 DNS 服务器有你想要连接的机器的 A（地址）记录，你应该能够使用主机名而不是 IP 地址：

```
ssh jdoe@chupacabra

```

### 注意

如果机器在你的网络中没有 DNS 条目，或者你还没有设置 DNS 服务器，不用担心。我们将在第六章 *配置网络服务*中讨论设置我们自己的 DNS(bind)服务器。

连接到主机的另一个重要方面是指定端口。如前所述，默认端口是 22。如果你不指定端口，那么假定端口是 22。如果你需要指定一个不同的端口，你可以使用`-p`标志，如下所示：

```
ssh -p 6022 jdoe@chupacabra

```

成功连接后，你应该可以在目标机器上获得一个命令提示符。从这里，你可以安装软件包，管理用户，配置网络，或者做任何你能亲自登录到机器上做的事情。你的唯一限制是你的用户对系统的权限。如果这是你自己的机器，或者是你自己设置并知道 root 密码的机器，你可以做任何你想做的事情。如果这台机器属于别人，你可能只有权限修改你的本地主目录。无论如何，你成功使用 SSH 连接到了一台机器。本章的其余部分，以及第九章 *保护你的网络*，将扩展这些基本知识。

# OpenSSH 配置文件

当第一次使用 SSH 时，`.ssh`目录将在你的主目录中创建。这个目录包含了 SSH 客户端的有用文件，包括`known_hosts`、`id_rsa`和`id_rsa.pub`，一旦你生成了你的密钥（我们稍后会讨论）。虽然我们稍后会在本章讨论这些文件，但 SSH 客户端还识别另一个文件：`config`。这个文件不是默认创建的。如果你自己创建它（遵循正确的语法），那么 SSH 将识别它。那么，这个`config`文件是做什么的呢？如果你有一个或多个经常连接的主机，你可以在这个文件中填写每个主机的具体信息，而不必每次都输入详细信息。让我们看一个示例`~/.ssh/config`文件。

```
Host icarus
Hostname 10.10.10.76
Port 22
User jdoe

Host daedalus
Hostname 10.10.10.88
Port 65000
User duser

Host dragon
Hostname 10.10.10.99
Port 22
User jdoe

```

对于这个文件，SSH 将立即识别三个主机：`伊卡洛斯`、`代达罗斯`和`龙`。这与这些机器是否在 DNS 中列出无关。如果我们输入`ssh icarus`并且之前使用了`config`文件，SSH 不仅会知道如何到达它（文件中给出了 IP 地址），而且 SSH 还会知道要使用哪个用户和端口。即使我们的用户名不是`jdoe`，它也会用于这个连接（因为它在文件中列出了）—除非我们在命令字符串中为`ssh`命令提供了不同的用户。

在我们示例文件的第二个条目（`daedalus`）中，你会注意到它与其他条目有些不同。首先，端口是不同的。对于文件中的所有其他主机，都使用默认的 22 端口。但对于`daedalus`，我们使用了不同的端口。如果我们通过 SSH 连接到`daedalus`，它将自动尝试引用的端口。接下来，你还会注意到这个主机的用户名也是不同的。即使我们的本地用户是`jdoe`，并且我们没有提供不同的用户名，用户`duser`也会被自动使用。如果我们希望，我们可以通过在主机名之前提供`user@`来覆盖这一点。

由于这个文件默认不存在，我们只需要使用任何文本编辑器创建它并保存到以下位置：

```
~/.ssh/config

```

只要我们输入正确，SSH 就应该能看到文件并允许我们使用它。然后，我们可以在这个文件中创建我们自己的主机列表，以便为每个主机提供所需的参数，并且更容易地访问。在你的实验室里试一试吧。

# 理解和利用 scp

SSH 实际上有几种用途；它不仅仅是用于连接一台机器到另一台机器，尽管这是最常见的用例。SSH 还允许你将文件传输到另一台机器，甚至从远程机器传输文件到你的本地机器。允许你这样做的实用程序是`scp`（**安全复制**）命令，它是 SSH 工具套件的一部分。当然，你也可以通过网络共享传输文件，但`scp`的美妙之处在于它提供了即时的文件传输，而不需要进行共享配置。`scp`命令简单而快速。你可以将文件从你的机器传输到你有权限访问的目标机器的文件系统的任何位置。

`scp`实用程序主要是为那些需要快速传输文件的人准备的，因为它不是文件访问和存储的长期解决方案。在需要创建其他人需要访问的存储库的情况下，你通常会设置一个**NFS**或**Samba**共享来实现目标。然而，`scp`是一个很棒的实用程序，无论何时你想要简单地将文件发送到另一台机器而不需要配置任何东西，它都会对你非常有用。

## 通过 scp 将文件传输到另一个节点

让我们试一试`scp`。与之前的 SSH 活动一样，你至少需要两台机器：一台安装并运行 SSH 服务器的机器，另一台至少安装了客户端的机器。在这种情况下，发行版并不重要，只要你满足这个简单的要求。此外，我们需要一个测试文件。文件可以是一些小东西（比如文本文件或图像）或大东西（比如 Linux 发行版的 ISO 文件）。目标是使用`scp`将这个文件传输到另一台机器。让我们看看如何做到这一点。

为了本教程的目的，我将概述一个名为 foo 的机器向一个名为 bar 的机器传输文件的过程。

首先，让我们看一个`scp`的简单例子：

```
scp my-image.jpg 192.168.1.200:/home/jdoe/

```

在这个例子中，我们执行了针对名为`my-image.jpg`的文件的`scp`命令。接下来，我们概述目标。在这种情况下，是一个具有 IP 地址`192.168.1.200`的机器。然后，我们输入一个冒号和我们想要存储文件的路径。在这种情况下，我们将文件复制到`jdoe`的主目录中。

由于我们知道目标机器的名称（`bar`），我们可以使用机器的名称而不是 IP 地址，假设它被 DNS 服务器识别。它在`~/.ssh/config`中配置，或者是 foo 的`/etc/hosts`文件中的一个条目。命令如下：

```
scp my-image.jpg bar:/home/jdoe

```

我们稍微简化了命令，因为我们知道机器的名称。此外，如果我们打算复制到用户的主目录，我们不必输入目录的名称。我们可以将命令简化为以下形式：

```
scp my-image.jpg bar:.

```

在这个例子中，我们用一个句号代替了`/home/jdoe`的路径。这是因为默认会使用主目录，除非你给命令一个单独的路径。如果我们用波浪号(`~`)代替也会得到同样的结果：

```
scp my-image.jpg bar:~

```

如果我们希望复制的数据是一个整个目录，而不仅仅是一个单个文件呢？如果我们尝试使用`scp`命令来复制一个目录，它将失败。为了复制整个目录，我们需要添加`-r`标志来执行递归复制：

```
scp -r my_dir bar:~

```

现在，`my_dir`目录及其内容将被传输。在复制文件时，另一个有用的标志是`-p`，它在复制文件时保留修改时间。如果我们将其与前面的命令结合起来，我们得到：

```
scp -rp my_dir bar:~

```

然而，如果两台机器上的用户名不同，每个命令都会失败。例如，如果 foo 上的登录用户是`dlong`，而在`bar`上用户不存在，命令会失败，因为发送计算机会默认使用`dlong`，当前登录的用户。在这种情况下，另一台计算机会要求你输入密码三次，然后给出一个拒绝访问的消息。这是因为你实际上在为一个不存在的用户输入密码。如果我们需要为目标指定用户名，命令会变成类似以下的形式：

```
scp my-image.jpg jdoe@bar:~

```

使用新版本的命令，你将被提示输入`jdoe`的密码，然后文件将被复制到接收端的`/home/jdoe`。

正如本章前面提到的，SSH 的默认端口（端口 22）可能在目标上没有打开，也许它正在监听不同的端口。使用`scp`，我们可以指定一个不同的端口。为此，使用`-P`标志。请注意，这是一个大写的`P`，不像`ssh`命令使用小写的`-p`来指定端口（在切换`ssh`和`scp`时，这可能有点令人困惑）。例如，这个标志被添加到前面的命令中：

```
scp -P 6022 my-image.jpg jdoe@bar:~

```

在你的实验室里试一试。找到任何类型的文件，尝试将其传输到另一台 Linux 机器上。如果你这样做几次，你应该能够很快掌握它。关于`scp`的另一个有趣的地方是，如果你已经知道要下载的文件的路径，你可以使用它将文件或目录从远程机器复制到本地机器。在本节的最后一个例子中，我正在将`myimage.jpg`从远程主机`bar`复制到我的当前工作目录（我用一个句号来指定）：

```
scp jdoe@bar:~/myimage.jpg .

```

## 通过 SSH 进行隧道流量

SSH 最有用的功能之一是创建**SSH 隧道**。SSH 隧道允许你在本地访问来自另一台计算机或服务器的服务。这使你可以做一些事情，比如绕过本地 DNS 过滤，或者甚至从家里访问公司内部隔离的 IRC 服务器。

### 注意

在使用 SSH 隧道时要非常小心。如果你在工作时无法访问资源，或者工作资源被阻止在网络外部访问，很可能是网络管理员（如果不是你）出于某种原因设置了这样的方式。当绕过限制或从网络外部访问工作资源时，一定要确保你有权限这样做。

为了使 SSH 隧道有效，您首先需要能够访问 SSH，其中您想要访问的服务托管。如果您能够启动到包含该服务的网络的普通 SSH 连接，那么您很可能不会在创建隧道时遇到问题。

在使用 SSH 创建隧道时，命令会有所变化。我们不仅仅是针对主机名或 IP 地址执行`ssh`命令，还添加了一些标志。首先，我们添加了`-L`标志。这设置了所谓的绑定地址，基本上意味着我们正在将本地端口转发到另一端的特定端口。

这样一个命令字符串的语法将是这样的：

```
ssh -L <local-port>:localhost:<remote-port> <username>@10.10.10.101

```

基本上，我们使用`-L`标志执行 SSH，并使用`localhost`，因为我们打算将本地服务转发到远程服务。但是，我们在命令中夹在一个端口和一个冒号。左侧的端口是我们的本地端口，右侧的 IP 地址上有一个冒号，然后是远程端口。然后我们用我们通常的语法结束命令，也就是我们输入我们的用户名，然后是我们将用于连接的网关的 IP 地址。

还是感到困惑吗？让我们进一步分解并举例说明。

默认情况下，VNC（图形远程访问程序）使用端口 5900-5902。如果您想要访问具有 IP 地址`10.10.10.101`的远程主机上的桌面环境，请使用以下命令：

```
ssh -L 5900:localhost:5901 jdoe@10.10.10.101

```

在这里，我们将本地机器上的端口`5900`转发到`10.10.10.101`上的端口`5901`。会话连接并建立后，我们可以在本地机器上的 VNC 查看应用程序中使用以下内容连接到远程端上的 VNC 服务：

```
localhost:5900

```

每当使用`localhost:5900`时，我们将被转发到我们的远程机器。要结束会话，请退出 SSH 连接。对于 VNC，我们需要指定要使用的 VNC 会话。为了使用 VNC Viewer 应用程序打开到`10.10.10.101`的 VNC 会话，我们将执行以下命令：

```
vncviewer localhost:1

```

然而，如果我们希望连接的机器或服务位于不同的网关后面怎么办？前面的例子只有在 IP 地址`10.10.10.101`可以通过互联网路由，或者我们实际上在要连接的资源相同的网络上时才有效。这并不总是情况，通常有用的服务并不直接暴露在互联网上。例如，如果您在家里，希望连接到工作网络中计算机上的远程桌面协议，前面的例子就行不通了。

在这个例子中，在办公室，我们有一台计算机，其远程桌面暴露了一个 IP 地址`10.10.10.60`。我们无法直接从家里访问这台机器，因为它不能通过互联网路由。然而，我们碰巧在工作中有一台服务器，实际上是暴露在互联网上的，具有外部 IP 地址`66.238.170.50`。我们能够直接从家里 SSH 进入那台机器，但主机`10.10.10.60`在那个网络中更进一步。

在这里，我们可以利用主机`66.238.170.50`来促进我们与工作网络内`10.10.10.60`的连接。让我们看一个命令：

```
ssh -L 3388:10.10.10.60:3389 jdoe@66.238.170.50

```

在这个例子中，`jdoe`在主机`66.238.170.50`上有一个用户帐户，并希望连接到主机`10.10.10.60`，这是在她的公司网络内的。在这个例子中，`jdoe`正在将`localhost`上的本地端口`3388`转发到主机`10.10.10.60`上的端口`3389`，但是通过主机`66.238.170.50`建立连接。现在，用户`jdoe`可以打开远程桌面客户端，并使用以下命令进行连接：

```
localhost:3388

```

只要 SSH 连接保持打开状态，`jdoe`就能够从她的本地计算机上的服务器上使用远程桌面。如果关闭 shell，则连接将终止。

使用 SSH 隧道可能非常有用。随时尝试并查看您可以通过网络转发哪些服务。

# 生成公钥

SSH 还支持**公钥认证**，除了传统密码之外，这更加安全。虽然 SSH 使用协议 2 的加密很强大，但即使世界上最强大的加密也无法保护你的密码泄露或被暴力破解。这在关键任务的服务器上尤为灾难性。

使用公钥认证允许你使用私钥和公钥的关系连接到主机，而不是使用密码。默认情况下，SSH 允许用户通过用户名/密码组合或用户名/密钥对组合登录。第一种方法的安全性取决于密码。通过使用公钥认证，你可以完全绕过密码的需求，并连接到服务器而不需要提示。但是，如果服务器仍然接受你的密码作为认证手段，那么公钥认证并不是最强大的。

在 SSH 连接的服务器端，可以配置它只接受公钥认证，而不是密码。如果禁用了密码认证，那么没有人能够暴力破解密码进入服务器，因为密码会被忽略。如果攻击者没有私钥，那么他或她将无法连接。

使用`ssh-keygen`命令生成密钥对非常简单，它会引导你完成密钥设置的过程。在这个过程中，你会被要求创建一个密码。如果你愿意的话，可以忽略这个提示，直接按*Enter*键创建一个没有密码的密钥。然而，这样做会大大降低密钥的安全性。虽然通过 SSH 连接到主机时不需要输入任何内容肯定更方便，但强烈建议使用密码，并从增加的安全性中受益。

使用公钥认证时，在用户的主目录中会创建两个文件：`id_rsa`和`id_rsa.pub`。这些文件是在执行`ssh-keygen`过程中创建的。命令完成后，这两个文件应该位于你主目录的`.ssh`目录中。`id_rsa`文件是你的私钥。你应该将它保留在本地，不要传输或在公共场所共享。`id_rsa.pub`文件是你的公钥，你可以安全地复制到其他你连接的主机上。从那时起，你将能够使用公钥认证连接到另一个主机。

让我们总结整个过程。首先，在本地或主机上登录后，执行`ssh-keygen`并按照步骤进行。确保创建一个密码以增加安全性。

![生成公钥](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_03_01.jpg)

使用 ssh-keygen 为 SSH 创建密钥对

接下来，使用`ssh-copy-id`命令将你的密钥复制到你希望连接的远程服务器上。命令语法如下。

```
ssh-copy-id -i ~/.ssh/id_rsa.pub <remote host IP or name>

```

这个命令将把你的公钥复制到目标机器的`~/.ssh`文件夹下的`authorized_keys`文件中。这个文件存储了机器知道的所有密钥。如果你在运行`ssh-copy-id`过程之前和之后进行检查，你会注意到目标机器上的`authorized_keys`文件要么不存在，要么在执行命令之后才包含你的密钥。

![生成公钥](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_03_02.jpg)

使用 ssh-copy-id 将公钥复制到远程主机

如前所述，可以配置你的计算机或服务器禁止通过密码进行认证，只允许使用公钥认证。这部分将在第九章*保护您的网络*中进一步讨论。现在，重要的是养成生成、复制和使用密钥的习惯。随时可以在本地机器上创建密钥对，并将公钥复制到你经常连接的服务器上。

# 保持 SSH 连接活动

根据您的 SSH 服务器或内部防火墙的配置方式，您的 SSH 会话可能会在一段时间后自动断开连接。可以配置 SSH 每隔一定时间发送一个特殊数据包，以保持连接不处于空闲状态并成为断开连接的候选。如果您有一个利用 SSH 的服务，您不希望它被断开连接，这将非常有用。要使用此调整，我们必须配置`ServerAliveInterval`设置。

有两种配置方式，一种影响您的用户帐户，另一种将系统范围的设置部署。首先，让我们看看如何为您的用户帐户配置这个。

记得我们在本章前面配置的`~/.ssh/config`文件吗？再次在文本编辑器中打开它。以下是这个文件的一个示例，以方便您参考：

```
Host icarus
Hostname 10.10.10.76
Port 22
User jdoe

Host daedalus
Hostname 10.10.10.88
Port 65000
User duser

Host dragon
Hostname 10.10.10.99
Port 22
User jdoe

```

与之前一样，我们有三个系统。如果我们希望为主机（例如`icarus`）配置一个设置，使其每 60 秒发送一个活动数据包，我们可以向其添加以下设置：

```
Host icarus
ServerAliveInterval 60
Hostname 10.10.10.76
Port 22
User jdoe

```

如果我们希望为我们连接的所有主机设置`ServerAliveInterval`设置，我们可以将此选项作为通配符添加到文件顶部：

```
Host *
ServerAliveInterval 60

```

有了这个设置，该设置将对我们发起连接的所有系统生效。虽然我们还没有讨论它们（但是），SSH 有两个系统范围（全局）的配置文件。我们将在本书的后面讨论这些文件，但本节的主题是为您提供一个快速介绍：

+   `/etc/ssh/ssh_config`：此文件将影响所有进行出站连接的用户。将其视为客户端配置文件。

+   `/etc/ssh/sshd_config`：这是服务器的全局配置文件。

您在这两个文件中配置的任何内容都会影响任何人。`ssh_config`文件影响所有出站连接，而`sshd_config`影响所有入站连接。对于本节，我们感兴趣的文件是`ssh_config`文件，因为我们可以在那里设置所有用户的`ServerAliveInterval`设置。实际上，无论我们是在配置`/etc/ssh/ssh_config`还是本地的`~/.ssh/config`文件，选项都是相同的。只需将其添加到文件末尾：

```
ServerAliveInterval 60

```

当然，我们将在本书的后面进一步探讨配置这些选项。现在，只需记住这两个文件的目的和它们的位置。

# 探索 SSH 的替代方案-使用 Mosh（移动 shell）

在开始使用 SSH 时，您可能会立即注意到一个怪癖：如果您的网络连接中断，重新获得对您连接到的计算机的控制可能会很困难。这在笔记本电脑上特别常见，因为这种设备上的连接状态会根据您所在的位置或所连接的网络而改变。在终端复用器（如 tmux 或 screen）中运行命令可以使您的工作流在断开连接后保持活动状态，但是 SSH 的替代方案可能适合您。**Mosh**（**移动 shell**）是 SSH 的替代方案，即使您断开了资源所在的网络，也会保持远程会话的活动状态。当您重新连接到网络时，Mosh 将允许您从上次离开的地方继续进行。

在 Debian 中安装 Mosh 非常容易。只需安装`mosh`包，因为它可以从默认存储库中获得：

```
# apt-get install mosh

```

在 CentOS 中，Mosh 无法从该发行版的默认存储库中获得，因此您首先需要添加一个额外的存储库才能使其可用。首先，使用以下命令启用 EPEL 存储库：

```
# yum install epel-release

```

然后，您应该能够安装`mosh`包：

```
# yum install mosh

```

为了使 Mosh 有效，您不仅需要在本地计算机上安装它，还需要在您希望连接的任何计算机上安装它。语法与 SSH 类似：

```
mosh jdoe@10.10.10.101

```

与 SSH 一样，我们可以使用`-p`标志来指定要使用的不同端口：

```
mosh -p 2222 jdoe@10.10.10.101

```

事实上，Mosh 实际上利用 SSH 来建立连接，然后 mosh 程序接管连接。连接后，您可以通过拔掉网络电缆或断开无线接入点来模拟断开连接。您会注意到，下次使用 mosh 连接时，您的会话应该和您离开时一样。要看到所有这些魔法，可以考虑在断开连接之前启动一个进程（比如运行`top`命令）。

虽然有许多方法可以在会话断开时保持远程服务器上的进程运行，但 Mosh 是较新和更独特的解决方案之一。试一试吧！

# 总结

在本章中，我们讨论了 SSH 的所有优点。我们首先讨论了 SSH 是什么以及它的用途，然后确保它已安装在我们的系统上。使用 SSH，我们能够连接到其他 Linux 机器并执行命令。我们还研究了在`~/.ssh/config`文件中配置主机以及使用`scp`在一个主机和另一个主机之间传输文件。此外，我们还讨论了 SSH 隧道，以及公钥认证的介绍。我们最后介绍了 Mosh，这是 SSH 的一个不错的替代品。

在下一章中，我们将通过建立自己的文件服务器来解决文件共享的问题。我们将通过 Samba 和 NFS 设置文件共享，以及每种解决方案的个别特点。到时见！


# 第四章：设置文件服务器

在上一章中，我们介绍了 SSH 并讨论了 SCP。虽然 SCP 是手动将单个文件从一个地方传输到另一个地方的好方法，但在网络上有一个或多个中心位置来存储共享文件对于网络增加了很多价值。无论您是在商业网络上共享重要文件，还是在家庭网络上共享家庭相册，网络上的中央文件存储位置都是一个方便的资产。在本章中，我们将讨论三种实现这一目标的方法。我们首先将讨论设计文件服务器时的一些考虑事项，然后我们将介绍 NFS、Samba 和 SSHFS。

在本章中，我们将涵盖：

+   文件服务器的考虑事项

+   NFS v3 与 NFS v4

+   设置 NFS 服务器

+   学习 Samba 的基础知识

+   设置 Samba 服务器

+   挂载网络共享

+   通过 fstab 和 systemd 自动挂载网络共享

+   使用 SSHFS 创建网络文件系统

# 文件服务器的考虑事项

与 Linux 世界中的大多数事物一样，实现任何目标的方法不止一种。对于每种方法，都有许多最佳实践和注意事项需要在实施解决方案之前了解。正如前面提到的，从一个 Linux 系统向另一个 Linux 系统共享文件的三种最常见方法是**网络文件系统**（**NFS**）、**Samba**和**安全外壳文件** **系统**（**SSHFS**）。这三种方法主要满足不同的需求，您的网络布局将决定您应该使用哪种方法。

设计网络文件服务器时的第一个考虑事项是需要访问其文件的平台类型。NFS 通常是 Linux 环境中的一个很好的选择；然而，它在处理混合环境时表现不佳，因此如果您的网络中有需要与 Windows 机器共享文件的情况，您可能不希望选择它。并不是说您不能在 Windows 系统上访问 NFS 共享（您当然可以），但微软限制了 NFS 的可用性（称为**NFS 服务**）到每个 Windows 版本的最昂贵的版本。如果您使用支持它的 Windows 版本，NFS 服务是可以的，但由于需要克服额外的许可障碍，避开它可能更有意义。一般来说，只有当您的网络主要由 UNIX 和 Linux 节点组成时，NFS 才是一个很好的选择。

接下来要考虑的是 Samba。Samba 允许在所有三个主要平台（Windows、Linux 和 Mac OSX）之间共享文件，并且在混合环境中是一个很好的选择。由于 Samba 使用**SMB**协议，Windows 系统可以访问您的 Samba 共享，而不管您安装的版本如何，因此许可证并不是那么重要。事实上，即使是 Windows 的标准版或家庭版也能够本地访问这些共享，无需安装额外的插件。Samba 的缺点在于它处理权限的方式。在 Windows 和 Linux 节点之间保存文件时，需要一些额外的工作来处理权限，因此在处理需要保留特定权限的 UNIX 或 Linux 节点时，它并不总是最佳选择。

最后，SSHFS 是另一种主要用于在 Linux 节点之间共享文件的方法。当然，可以从 Windows 连接和访问 SSHFS，但只能使用第三方实用程序，因为 Windows 中没有内置的方法（至少在撰写本章时）。SSHFS 的优点在于其易用性和文件传输的加密。虽然加密确实有助于避免窃听，但请记住，SSHFS（就像任何其他解决方案一样）只有在您制定的政策下才是安全的。但是在得心应手的情况下，SSH（和 SSHFS）是从一个节点传输文件到另一个节点的安全方法。此外，SSHFS 是这里列出的三种方法中最容易运行的。您只需要访问另一个节点和访问一个或多个目录的权限。这就是您需要的一切，然后您就可以自动连接到您有权限访问的任何目录。SSHFS 的另一个好处是除了 SSH 本身之外，服务器上没有其他需要配置的东西，而大多数服务器都可以使用 SSH。SSHFS 连接也可以快速按需创建和断开。我们将在本章后面讨论 SSHFS。

# NFS v3 与 NFS v4

关于 NFS 的另一个考虑是您将使用的版本。如今，大多数（如果不是全部）Linux 发行版默认使用 NFS v4。但是，有些情况下，您可能在网络上有较旧的服务器，需要能够连接到它们的共享。虽然 NFS v4 绝对是未来的首选版本，但您可能需要使用旧协议连接到节点。

在这两种情况下，可以通过编辑`/etc/exports`文件共享文件服务器上的目录，您将在其中列出您的共享（exports），每行一个。我们将在下一节详细讨论这个文件。但现在，请记住`/etc/exports`文件是您声明文件系统上哪些目录可用于 NFS 使用的地方。不同版本的 NFS 有不同的处理文件锁定的技术，它们在引入**idmapd**、性能和安全性方面有所不同。此外，还有其他差异，比如 NFS v4 转移到仅支持 TCP（协议的早期版本允许 UDP 或 TCP），以及它是**有状态**的，而早期版本是**无状态**的。

NFS v4 是有状态的，它将文件锁定作为协议的一部分，而不像 NFS v3 那样依赖于**网络锁管理器**（**NLM**）来提供该功能。如果 NFS 服务器崩溃或不可用，连接到它的一个或多个节点可能会有打开的文件，这些文件将被锁定到这些节点。当 NFS 服务器开始备份时，它会重新建立这些锁，并尝试从崩溃中恢复。尽管 NFS 服务器在恢复方面做得相当不错，但它们并不完美，有时文件锁定可能成为管理员处理的噩梦。使用 NFS v4，NLM 被废弃，文件锁定成为协议的一部分，因此锁定处理更加高效。然而，它仍然不完美。

那么，您应该使用哪个版本？建议在所有节点和服务器上始终使用 NFS v4，除非您需要支持旧协议的较旧服务器。

## 设置 NFS 服务器

配置 NFS 服务器相对简单。基本上，您只需要安装所需的软件包，创建您的`/etc/exports`文件，并确保所需的守护程序（服务）正在运行。在这个活动中，我们将设置一个 NFS 服务器，并从不同的节点连接到它。为了这样做，建议您至少有两台 Linux 机器可以使用。这些机器是物理机器还是虚拟机器，或者两者的组合并不重要。如果您已经按照第一章*设置您的环境*进行了操作，您应该已经有了几个节点可以使用；希望是 Debian 和 CentOS 的混合，因为这个过程在它们之间有些不同。

首先，让我们设置我们的 NFS 服务器。选择一台机器作为 NFS 服务器并安装所需的软件包。您选择哪个发行版作为服务器，哪个作为客户端并不重要，我将介绍 CentOS 和 Debian 的配置过程。由于相当多的发行版要么基于 Debian，要么使用与 CentOS 相同的配置，这对大多数发行版都适用。如果您使用的发行版不遵循任何软件包命名约定，您只需查找在您的特定发行版上安装的软件包或元软件包。其余的配置应该是相同的，因为 NFS 是相当标准的。

要在 CentOS 系统上安装所需的软件包，我们将执行以下命令：

```
# yum install nfs-utils

```

对于 Debian，我们安装`nfs-kernel-server`：

```
# apt-get install nfs-kernel-server

```

### 注意

在安装这些软件包时，您可能会收到一个错误，即 NFS 尚未启动，因为文件系统上不存在`/etc/exports`。在某些发行版上安装所需的 NFS 软件包时，可能不会自动创建此文件。即使它确实自动创建，该文件也只是一个框架。如果您收到这样的错误，请忽略它。我们将很快创建此文件。

接下来，我们将确保与 NFS 相关的服务已启用，以便它们在服务器启动时启动。对于 CentOS 系统，我们将使用以下命令：

```
# systemctl enable nfs-server

```

对于 Debian，我们可以通过以下方式启用 NFS：

```
# systemctl enable nfs-kernel-server

```

请记住，我们只是在服务器上启用了 NFS 守护程序，这意味着当系统重新启动时，NFS 也将启动（如果我们正确配置了它）。但是，我们不必重新启动整个服务器才能启动 NFS；我们可以在创建配置文件后的任何时间启动它。实际上，直到我们实际创建配置之前，您的发行版可能根本不会让您启动 NFS。

下一步是确定我们希望在网络上提供哪些服务器目录。您分享哪些目录基本上取决于您。Linux 文件系统上的任何内容都可以作为 NFS 导出的候选项。但是，一些目录，比如`/etc`（其中包含系统配置）或任何其他系统目录，可能最好保持私有。虽然您可以共享系统上的任何目录，但实际上，常见做法是创建一个单独的目录来存放所有共享的内容，然后在其下创建子目录，然后共享给客户端。

例如，也许您会在文件系统的根目录（`mkdir /exports`）下创建一个名为`exports`的目录，然后创建诸如`docs`和`images`之类的目录，以便他人可以访问。这样做的好处是，您的共享可以从一个地方（`/exports`目录）进行管理，并且 NFS 本身具有将此目录分类为您的导出根目录的能力（我们将在后面讨论）。在继续之前，在文件系统上创建一些目录，以便在下一节中将这些目录放入配置文件中。

一旦确定了文件系统中想要共享的目录并创建了它们，你就可以开始实际的配置了。每个 NFS 共享，也称为 export，在`/etc/exports`文件中添加每个我们希望共享的目录的一行来配置。由于你已经安装了所需的软件包以在系统上使用 NFS，这个文件可能已经存在，也可能不存在。根据我的经验，CentOS 在安装过程中不会创建这个文件，而 Debian 会。但即使你得到了一个默认的`exports`文件，它只会包含已注释掉的代码行，没有任何实际用途。实际上，你甚至可能在安装过程中收到警告或错误，说 NFS 守护进程没有启动，因为找不到`/etc/exports`。没关系，因为我们很快就会创建这个文件。

默认的`exports`文件在不同的发行版之间可能不同（如果默认情况下根本不创建），但是创建新的 exports 的格式是相同的，不管你选择的发行版是什么，因为 NFS 是相当标准的。添加一个 export 的过程是打开你喜欢的文本编辑器中的`/etc/exports`文件，并将每个 export 添加到自己的一行中。任何实际的文本编辑器都可以，只要它是文本编辑器而不是文字处理器。例如，如果你喜欢 vim，你可以执行以下命令：

```
# vim /etc/exports

```

如果你喜欢`nano`，你可以执行以下命令：

```
# nano /etc/exports

```

实际上，你甚至可以使用图形文本编辑器，比如 Gedit、Kate、Pluma 或 Geany，如果你更喜欢使用 GUI 工具。这些软件包都可以在大多数发行版的存储库中找到。

### 注意

可能不用说，但是要编辑`/etc`目录中或任何其他由 root 拥有的文件，你需要在这样的命令前加上`sudo`前缀，以便在没有以 root 身份登录时编辑它们。作为最佳实践，建议除非你绝对必须，否则不要以 root 身份登录。如果你以普通用户身份登录，执行以下命令：

```
sudo vim /etc/exports

```

在 Debian 中，你会看到默认的`/etc/exports`文件包含一系列注释，这可能对你有所帮助，以便查看 exports 的格式。我们可以通过简单地将它们添加到文件的末尾来创建新的 exports，保留内容。如果你更喜欢从一个空白文件开始，你可能想要备份原始文件，以防以后需要参考它。

```
# mv /etc/exports /etc/exports.default

```

一旦你在你喜欢的文本编辑器中打开了文件，你就可以开始了。你希望共享或*导出*的所有目录都应该放在这个文件中，每个目录占据一行。然后，你可以附加参数到共享中，以控制它如何被访问以及由谁访问。以下是一个示例 exports 文件，其中包含一些示例目录和每个目录的一些基本配置参数：

```
/exports/docs 10.10.10.0/24(ro,no_subtree_check)
/exports/images 10.10.10.0/24(rw,no_subtree_check)
/exports/downloads 10.10.10.0/24(rw,no_subtree_check)

```

正如你在这些示例 exports 中所看到的，每个的格式基本上包括我们想要导出的目录，我们想要允许访问的网络地址，然后是括号中的一些附加选项。你可以在这里附加许多选项，我们将在本章后面讨论其中一些。但如果你想查看你可以在这里设置的所有选项，可以参考以下`man`命令：

```
man exports

```

让我们讨论一下之前使用的示例`exports`文件的每个部分：

+   `/exports/docs`：第一部分包含我们要向网络上的其他节点导出的目录。如前所述，你几乎可以共享任何你想要的目录。但只是因为你*可以*共享一个目录，并不意味着你*应该*。只共享你不介意其他人访问的目录。

+   `10.10.10.0/24`：在这里，我们限制了对`10.10.10.0/24`网络内的节点的访问。该网络之外的节点将无法挂载任何这些导出。在此示例中，我们可以使用`10.10.10.0/255.255.255.0`，结果将是相同的。在我们的示例中，使用了`/24`，这被称为**无类域间路由**（**CIDR**）表示法，它是用于输入子网掩码的简写。当然，CIDR 还有更多内容，但现在只需记住，与子网掩码相比，CIDR 表示法用于使示例更短（而且看起来更酷）。

+   `ro`：在第一个导出（docs）中，我将其设置为只读，没有其他原因，只是为了向您展示您可以这样做。这可能是不言自明的，但导出为只读的目录将允许其他人挂载导出并访问其中的文件，但不会对任何内容进行更改。

+   `rw`：读写导出允许挂载它的节点创建新文件并修改现有文件（只要用户在文件本身上设置了所需的权限）。

+   `no_subtree_check`：虽然此选项是默认的，我们实际上不需要显式发出请求，但不包括它可能会导致 NFS 在重新启动时抱怨。这个选项是`subtree_check`的相反，后者现在基本上是被避免的。特别是，此选项控制服务器在处理导出中的操作时是否扫描底层文件系统，这可能会增加一些安全性但降低可靠性。由于禁用此选项已知可以增加可靠性，因此在最近的 NFS 版本中已将其设置为默认值。

尽管我在我的任何示例中都没有使用它，但您将在`/etc/exports`中看到的常见导出选项是`no_root_squash`。设置此选项允许终端用户设备上的 root 用户对导出中包含的文件具有 root 访问权限。在大多数情况下，这是一个坏主意，但您会在野外偶尔看到这种情况。这与`root_squash`相反，后者将 root 用户映射到 nobody。除非您有非常充分的理由做出不同的选择，否则`no_root_squash`是您想要的。

除了为单个网络分类选项外，您还可以通过在同一行中为它们添加配置来使您的导出可用于其他网络。以下是我们的`docs`挂载与其他网络共享的示例：

```
/exports/docs 10.10.10.0/24(ro,no_subtree_check),192.168.1.0/24(ro,no_subtree_check)

```

通过此示例，我们正在导出`/exports/docs`，以便`10.10.10.0/24`网络和`192.168.1.0/24`网络内的节点可以访问。虽然我为两者使用了相同的选项，但您不必这样做。如果您愿意，甚至可以为一个网络配置导出为只读，而为另一个网络配置为读写。

到目前为止，我们一直在与整个网络共享我们的导出。这是通过将允许的 IP 地址的最后一个八位设置为`0`来完成的。通过上一个示例，任何具有 IP 地址为`10.10.10.x`或`192.168.1.x`且子网掩码为`255.255.255.0`的节点都有资格访问导出。然而，您可能并不总是想要给整个网络访问权限。也许您只想允许单个节点访问。您可以同样轻松地对单个节点进行分类：

```
/exports/docs 10.10.10.191/24(ro,no_subtree_check)

```

在上一个示例中，我们允许具有 IP 地址`10.10.10.191`的节点访问我们的导出。指定 IP 地址或网络可以增强安全性，尽管这并非百分之百的通用方法。然而，仅限于绝对需要访问的主机是构建安全策略的一个非常好的起点。我们将在第九章*保护您的网络*中更详细地介绍安全性。但现在，请记住，您可以通过特定网络或个别 IP 限制对导出的访问。

早些时候，我们提到从版本 4 开始，NFS 可以使用一个目录作为其导出根，也称为 NFS 伪文件系统。在`/etc/exports`文件中，通过在导出此目录时放置`fsid=0`或`fsid=root`来标识这一点。在本章中，我们一直在使用`/exports`作为我们的 NFS 导出的基础。如果我们想要将此目录标识为我们的导出根，我们将像这样更改`/etc/exports`文件：

```
/exports *(ro,fsid=0)
/exports/docs 10.10.10.0/24(ro,no_subtree_check)
/exports/images 10.10.10.0/24(rw,no_subtree_check)
/exports/downloads 10.10.10.0/24(rw,no_subtree_check)

```

起初，这个概念可能有点令人困惑，所以让我们把它分解一下。在第一行中，我们确定了我们的导出根：

```
/exports *(ro,fsid=0)

```

在这里，我们声明`/exports`为我们的导出根。这现在是 NFS 文件系统的根。当然，就 Linux 本身而言，您有一个以`/`开头的完整文件系统，但就 NFS 而言，它的文件系统现在从这里开始，即`/exports`。在这一行中，我们还将`/exports`声明为只读。我们不希望任何人对这个目录进行更改，因为它是 NFS 根。它也与所有人共享（注意`*`），但这不应该有关系，因为我们为每个单独的导出设置了更细粒度的权限。有了 NFS 根，客户端现在可以挂载这些导出，而无需知道如何到达它的完整路径。

例如，用户可能会输入以下内容，将我们的`downloads`导出挂载到他或她的本地文件系统：

```
# mount 10.10.10.100:/exports/downloads /mnt/downloads

```

这是如何从本地文件服务器（在这种情况下为`10.10.10.100`）挂载 NFS 导出的方式，该服务器*不*使用 NFS 根。这需要用户知道该目录位于该服务器上的`/exports/downloads`。但是有了 NFS 根，我们可以让用户简化`mount`命令如下：

```
# mount 10.10.10.100:/downloads /mnt/downloads

```

请注意，我们在上一个命令中省略了/exports。虽然这可能看起来不是很重要，但我们基本上是在要求服务器给我们`downloads`导出，无论它在文件系统的哪个位置。`downloads`目录位于`/exports/downloads`，`/srv/nfs/downloads`或其他任何地方都无所谓。我们只是要求`downloads`导出，服务器知道它在哪里，因为我们设置了 NFS 根。

现在我们已经配置了我们的`/etc/exports`文件，很好的建议我们编辑`/etc/idmapd.conf`配置文件以配置一些额外的选项。这并不是绝对必需的，但绝对是建议的。默认的`idmapd.conf`文件因发行版而异，但每个都包含我们需要在此部分配置的选项。首先，查找以下行（或非常相似的行）：

```
# Domain = local.domain

```

首先，我们需要取消注释该行。删除`#`符号和尾随空格，使该行以`Domain`开头。然后，设置您的域，使其与网络上的其他节点相同。这个域很可能在安装过程中已经选择过了。如果您不记得您的域是什么，运行`hostname`命令应该会给您您的域名，这个域名紧跟在您的主机名后面。对于您想要能够访问 NFS 导出的每个节点都要这样做。

您可能想知道为什么这是必要的。当在 Linux 系统上创建用户和组帐户时，它们被分配了**UID**（**用户 ID**）和**GID**（**组 ID**）。除非您在所有系统上以完全相同的顺序创建了用户帐户，否则 UID 和 GID 在每个节点上很可能是不同的。即使您按照相同的顺序创建了用户和组帐户，它们仍然可能是不同的。`idmapd`文件通过将这些 UID 从一个系统映射到另一个系统来帮助我们。为了使`idmapd`工作，`idmapd`守护程序必须在每个节点上运行，并且该文件还应配置相同的域名。在 CentOS 和 Debian 上，该守护程序在`/usr/sbin/rpc.idmapd`下运行，并且随 NFS 服务器一起启动。

那么，你可能会想，`Nobody-User`和`Nobody-Group`的目的是什么？`nobody`用户运行的脚本或命令如果由特权用户运行可能会很危险。通常，`nobody`用户无法登录系统，也没有家目录。如果您将进程作为`nobody`运行，那么如果该帐户被破坏，其范围将受到限制。在 NFS 的情况下，`nobody`用户和`nobody`组具有特殊目的。如果文件由一个系统上不存在的特定用户拥有，那么文件的权限将显示为由`nobody`用户和组拥有。当未设置`no_root_squash`时，通过 root 用户访问文件也是如此。根据您使用的发行版，这些帐户可能具有不同的名称。在 Debian 中，`Nobody-User`和`Nobody-Group`默认为`nobody`。在 CentOS 中，这两者都是`nobody`。您可以在`idmapd.conf`文件中看到`nobody`用户和`nobody`组使用的帐户。您不应该需要重命名这些帐户，但如果出于某种原因您需要这样做，您需要确保`idmapd.conf`文件为它们具有正确的名称。

现在我们已经配置好并准备好使用 NFS 了，我们该如何开始使用它呢？如果您一直在跟进，您可能已经注意到我们启用了 NFS 守护程序，但尚未启动它。既然配置已经就位，没有什么能阻止我们这样做了。

在 Debian 上，我们可以通过执行以下命令来启动 NFS 守护程序：

```
# systemctl start nfs-kernel-server

```

在 CentOS 上，我们可以执行以下命令：

```
# systemctl start nfs-server

```

从这一点开始，我们的 NFS 导出应该已经共享并准备就绪。在本章的后面，我将解释如何在其他系统上挂载这些导出（以及 Samba 共享）。

NFS 中还有一件值得一提的事情。每当 NFS 守护程序启动时，都会读取`/etc/exports`文件，这意味着您可以通过重新启动服务器或 NFS 守护程序来激活新的导出。但是，在生产中，重新启动 NFS 或服务器本身是不切实际的。这将中断当前正在使用它的用户，并可能导致过时的挂载，这是对网络共享的无效连接（这不是一个好的情况）。幸运的是，激活新的导出而无需重新启动 NFS 本身是很容易的。只需执行以下命令，您就可以开始了：

```
# exportfs -a

```

# 学习 Samba 的基础知识

与 NFS 一样，Samba 允许您与网络中的其他计算机共享服务器上的目录。尽管两者都有相同的目的，但它们适用于不同的环境和用例。

NFS 是最古老的方法，在 Linux 和 UNIX 世界中被广泛使用。虽然我们当然有更新的解决方案（如 SSHFS），NFS 是经过验证的。但在混合环境中，它可能不是最佳解决方案。如今，您的网络上可能并非每台计算机都运行特定的操作系统，因此可能存在 NFS 访问不可用或不切实际的节点。

正如前面提到的，只有更昂贵的 Windows 版本才支持 NFS。如果你有一个庞大的 Windows 机器网络，要想将它们全部升级到更高版本将会非常昂贵，如果你本来不需要的话。这是 Samba 最擅长的领域。Windows、Linux 和 Mac 计算机都可以通过 Samba 访问共享目录。在 Windows 的情况下，即使是较低端的版本也可以访问 Samba 共享（例如 Windows 7 家庭专业版或 Windows 10 核心），而无需进行任何新的安装或购买。

Samba 的缺点是它处理权限的能力不如 NFS，因此您需要以特殊的方式管理配置文件以尊重权限。然而，它并非百分之百可靠。例如，Windows 和 Linux/UNIX 系统采用非常不同的权限方案，因此它们并不是本质上兼容的。在 Samba 的配置文件中，您可以告诉它在新创建的文件上使用特定的用户和组权限，甚至可以强制 Samba 将所有权视为与实际存储的文件不同的东西。因此，确实有方法可以使 Samba 处理权限更好，但本质上不如 NFS 这样的 Linux 或 UNIX 本地解决方案好。

就 Samba 服务器如何适应您的网络而言，基本的经验法则是在混合环境中使用 Samba，在不需要跨平台兼容性时使用 NFS。

## 设置 Samba 服务器

在本节中，我们将继续设置 Samba 服务器。在下一节中，我将解释如何挂载 Samba 共享。首先，我们需要安装 Samba。在 CentOS 和 Debian 系统上，该软件包简单地被称为`samba`。因此，通过`apt-get`或`yum`安装该软件包，您应该拥有所需的一切：

```
# yum install samba

```

使用`apt-get`的命令如下：

```
# apt-get install samba

```

在 Debian 系统上，Samba 在安装后立即启动。实际上，它也已启用，因此每次启动系统时都会自动启动。但在 CentOS 的情况下，安装后它既没有启用也没有启动。如果您选择 CentOS 作为 Samba 服务器，您需要启用并启动守护进程：

```
# systemctl start smb
# systemctl enable smb

```

现在，Samba 已安装、启用，但尚未配置。要配置 Samba，我们需要编辑`/etc/samba/smb.conf`文件。默认情况下，安装所需软件包后会立即创建此文件。但是，默认文件主要是为您提供配置示例而存在的。它非常庞大，但您可能希望查看它以查看以后可能要使用的一些语法示例。您可以在文本编辑器中打开文件，也可以在终端上使用`cat`命令查看文件：

```
cat /etc/samba/smb.conf

```

为了简化事情，我建议您从一个新文件开始。虽然配置示例绝对不错，但我们可能应该为生产目的使用一个更短的文件。由于原始文件以后可能有用，创建一个备份：

```
# mv /etc/samba/smb.conf /etc/samba/smb.conf.default

```

接下来，只需在文本编辑器中打开`smb.conf`文件，这将创建一个新的/空的文件，因为我们已经将原始文件移动到备份中：

```
# vim /etc/samba/smb.conf

```

我们可以从以下基本配置开始：

```
[global]
server string = File Server
workgroup = HOME-NET
security = user
map to guest = Bad User
name resolve order = bcast hosts wins
include = /etc/samba/smbshared.conf

```

让我们逐行浏览这个配置文件。首先，我们从`[global]`部分开始，这是我们为整个服务器配置选项的地方。实际上，这是这个特定文件中唯一的部分。

接下来是`server string`。`server string`是您在 Windows 系统上浏览网络共享时会看到的描述。例如，您可能会看到一个名为`Documents`的共享，并在其下方看到一个描述; `文件服务器`。这个部分不是必需的，但拥有它是很好的。在企业网络中，这对于概述有关系统的注释，比如它在哪里，或者它用于什么，是很有用的。

接下来，我们设置了我们的“工作组”。那些曾经是 Windows 系统管理员的人可能非常了解这一点。工作组用作包含特定目的所有系统的命名空间。在实践中，这通常是您的局域网的名称。您的局域网中的每台计算机都将具有相同的工作组名称，因此它们将显示为存在于同一网络中。在 Windows 系统上浏览共享时，您可能会看到工作组列表，双击其中一个将带您到共享资源的系统列表。在大多数情况下，您可能希望每个系统具有相同的工作组名称，除非您希望分开资源。要查看现有系统的工作组名称，请右键单击**我的电脑**或**此电脑**（取决于您的版本），然后单击**属性**。您的工作组名称应在出现的窗口中列出。

![设置 Samba 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_04_01.jpg)

查看 Windows 系统的属性以获取工作组名称，在这种情况下是 LOCALNET

设置`security = user`告诉 Samba 使用用户的用户名和密码进行身份验证。如果匹配，用户将不会被提示输入密码来访问资源。

`map to` `guest = Bad User`告诉 Samba，如果提供的用户名和密码与本地用户帐户不匹配，将连接的用户视为通过访客帐户连接。如果您不希望进行这样的映射，可以删除此部分。

接下来，`name resolve order = bcast hosts wins`确定名称解析的顺序。在这里，我们首先使用广播的名称，然后是我们`/etc/hosts`文件中的任何主机名映射，最后是`wins`（`wins`已大部分被 DNS 取代，这里仅用于兼容性）。在大多数网络中，这个顺序应该可以正常工作。

最后，我们在配置文件的末尾添加了`include = /etc/samba/smbshared.conf`。基本上，这允许我们像包含现有文件一样包含另一个配置文件。在这种情况下，我们包含了`/etc/samba/smbshared.conf`的内容，Samba 一旦读取了这一行，就会读取它。接下来我们将创建这个文件。基本上，这允许我们在单独的配置文件中指定我们的共享。这不是必需的，但我认为这样做会使事情更容易管理。如果您愿意，您可以在`smb.conf`文件中包含`smbshared.conf`文件的内容，以便一切都在一个文件中。

这是我为此活动创建的一个`smbshared.conf`示例。在您的情况下，您只需要确保值与您的系统和您选择共享的目录匹配即可：

```
[Music]
## My music collection
 path = /share/music
 public = yes
 writable = no

[Public]
## Public files
 path = /share/public 
 create mask = 0664
 force create mode = 0664
 directory mask = 0777
 force directory mode = 0777
 public = yes
 writable = yes

```

在这里，我创建了两个共享。每个共享都以方括号中的名称开头（在浏览此计算机上的共享时将显示），然后是该共享的配置。正如您所看到的，我有一个名为“音乐”的共享目录，另一个名为“公共”。

要声明共享的路径，请使用`path =`，然后是共享对应的目录路径。在我的示例中，您可以看到我共享了以下目录：

```
/share/music
/share/public

```

接下来，我还通过添加`public = yes`将共享声明为公共。这意味着允许访客访问此共享。如果我希望访客无法访问它，我可以将其设置为`no`。

在我的音乐共享中，我设置了`writable = no`。顾名思义，这禁用了其他计算机更改此共享中的文件的能力。在我的情况下，我与网络上的其他计算机共享我的音乐收藏，但我不希望意外删除音乐文件。

在我的公共共享中，我添加了一些额外选项：

```
 create mask = 0664
 force create mode = 0664
 directory mask = 0777
 force directory mode = 0777

```

这些选项都对应于在该共享中创建新文件时默认的权限。例如，如果我挂载了我的公共共享，然后在那里创建一个目录，它将获得`777`的权限。如果我创建一个文件，它的权限将是`664`。当然，你可能不想让你的文件完全开放，所以你可以根据自己的需要更改这些权限。这个选项确保了在新创建的目录和文件上的权限的一致性。这在一个可能有自动化进程运行需要访问这些文件的网络上是至关重要的，你希望确保每次运行这样的进程时不需要手动更正权限。

现在你已经创建了自己的 Samba 配置，测试你的配置是一个好主意。幸运的是，Samba 本身包含一个特殊的命令，允许你这样做。如果你在系统上运行`testparm`，它将显示你文件中可能存在的语法错误。然后，它将显示你的配置。继续在你的系统上运行`testparm`。如果有任何错误，请返回并确保你输入的内容没有问题。如果一切正常进行，你将看不到错误，然后你将得到你配置的摘要。一旦验证了你的配置，重新启动 Samba 守护进程以使更改生效。要做到这一点，只需在你的 Debian 系统上运行以下命令：

```
# systemctl restart smbd

```

对于 CentOS，请使用以下命令：

```
# systemctl restart smb

```

现在，你应该能够在 Windows 或 Linux 系统上访问你的 Samba 共享。在 Linux 上，大多数图形界面文件管理器应该允许你浏览 Samba 共享的网络。在 Windows 上，你应该能够打开**我的电脑**或**此电脑**，然后点击**网络**来浏览本地网络上有活动共享的计算机。也许在 Windows 机器上访问共享的一个更简单的方法是按下键盘上的 Windows 键，然后按*R*打开运行对话框，然后简单地输入你的 Samba 服务器的名称，以两个反斜杠开头。例如，要从 Windows 系统访问我的基于 Debian 的文件服务器（Pluto），我会在运行对话框中输入以下内容，然后按*Enter*：

```
\\pluto

```

我从该系统中得到了一个共享列表，如下面的屏幕截图所示：

![设置 Samba 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_04_02.jpg)

从 Windows 7 PC 查看 Samba 共享（从 Linux 系统提供）

# 挂载网络共享

本章中，我们已经创建了 NFS 和 Samba 共享。但是我们还没有挂载任何这些共享。在本节中，我们将处理这个问题。

在 Linux 中，`mount`命令可以用于挂载几乎所有东西。无论是连接外部硬盘，插入光盘，还是希望挂载网络共享，`mount`命令都可以作为瑞士军刀来允许你将这些资源挂载到你的系统上。`mount`命令允许你挂载一个资源并将其附加到你系统上的一个本地目录。在大多数情况下，在使用图形桌面环境的大多数 Linux 系统上，`mount`会自动运行。如果你插入了闪存驱动器或某种光学介质，你可能已经看到了这一点。在网络共享中，这些不会自动挂载，但可以配置为自动挂载。

也许挂载网络共享的最简单方法是在安装了桌面环境的系统上使用图形文件管理器。如果你点击一个文件共享，它很可能会被挂载，并且你将被允许访问它，前提是你在该系统上有必要的权限。**Nautilus**、**Caja**、**Pcmanfm**和**Dolphin**都是流行的 Linux 文件管理器。

![挂载网络共享](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-net-adm/img/B03919_04_03.jpg)

pcmanfm 文件管理器，查看来自 Samba 文件服务器的共享

`mount`命令在没有图形环境的系统上或者当您希望将资源挂载到除默认位置之外的地方时最有用。要使用`mount`命令，给出您希望挂载的资源类型，它可以找到资源的位置，然后是用于挂载的本地目录。例如，要挂载 NFS 导出，我们可能会执行类似以下的操作：

```
# mount -t nfs 10.10.10.101:/exports/docs /mnt/docs

```

或者，如果我们设置了 NFS 根目录，可以使用以下命令：

```
# mount -t nfs 10.10.10.101:/docs /mnt/docs

```

在该示例中，我们告诉挂载命令，我们希望通过提供`-t`参数后跟`nfs`来挂载 NFS 导出。在我的实验室中，此共享存在于具有 IP 地址`10.10.10.101`的计算机上，我随后提供了该计算机上我正在访问的目录。在这种情况下，正在访问`10.10.10.101`上的`/exports/docs`。最后，我有一个本地目录`/mnt/docs`，它存在于我本地计算机上，我希望将此共享挂载到该目录。执行此命令后，每次我在本地计算机上访问`/mnt/docs`时，实际上是在我的文件服务器上访问`/exports/docs`。在使用此导出后，我只需卸载它：

```
# umount /mnt/docs

```

在 Linux 机器上挂载 Samba 共享需要更多操作。我将包括一个示例命令，该命令可用于从同一服务器挂载 Samba 共享。但在执行此操作之前，您首先需要在系统上安装必要的软件包，以便能够挂载 Samba 共享。在 CentOS 上，安装`samba-client`。在 Debian 上，软件包是`smbclient`。安装所需软件包后，您应该能够通过执行以下命令来挂载 Samba 共享：

```
# mount -t cifs //10.10.10.101/Videos -o username=jay /mnt/samba/videos

```

如果您需要通过密码访问资源，请使用以下命令：

```
# mount -t cifs //10.10.10.101/Videos -o username=jay, password=mypassword /mnt/samba/videos

```

如您所见，挂载 Samba 共享使用了相同的基本思想。但在这种情况下，我们以不同的方式格式化我们的目标路径，我们使用`cifs`作为文件系统类型，并且我们还包括用户名（以及密码，如果您的 Samba 服务器需要）。与以前的示例一样，我们以希望将挂载附加到的本地目录结束命令。在这种情况下，我为此共享创建了一个`/mnt/samba/Videos`目录。

# 通过 fstab 和 systemd 自动挂载网络共享

尽管通过`mount`命令挂载网络共享非常方便，但您可能不希望每次使用时都手动挂载共享。在具有中央文件服务器的网络中，配置工作站自动挂载网络共享是有意义的，这样每次启动系统时，共享将自动挂载并准备就绪。

自动挂载资源的经过验证的方法是`/etc/fstab`文件。每个 Linux 系统都有一个`/etc/fstab`文件，所以请查看您的文件。默认情况下，此文件仅包含用于挂载本地资源的配置，例如硬盘上的分区。向此文件添加额外的配置行以挂载从额外硬盘到网络共享的任何内容是标准做法。

### 注意

在编辑您的`/etc/fstab`文件时要小心。如果意外更改了本地硬盘的配置，下次启动系统时系统将无法启动。在编辑此文件时请务必小心。

以下是一个`/etc/fstab`文件示例：

```
# root filesystem
UUID=4f60d247-2a46-4e72-a28a-52e3a044cebf       /                   ext4            errors=remount-ro           0 1
# swap
UUID=c9149e0a-26b0-4171-a86e-a5d0ee4f87a7       none                swap            sw                          0 0

```

在我的文件中，**通用唯一标识符**（**UUID**）引用了我的本地硬盘分区。这些在每个系统上都会有所不同。接下来，列出了每个挂载点。`/`符号代表文件系统的根，交换分区不需要挂载点，因此设置为`none`。

在`/etc/fstab`文件的末尾，我们可以添加希望在每次启动系统时可用的额外挂载。如果我们希望添加 NFS 共享，可以执行以下操作：

```
10.10.10.101:/share/music/mnt/music  nfs  users,rw,auto,nolock,x-systemd.automount,x-systemd.device-timeout=10 0 0

```

在第一部分中，我们声明服务器的 IP 地址，后面跟着一个冒号和导出目录的路径。在这种情况下，我正在访问`10.10.10.101`上的`/share/music`。下一部分是挂载点，所以我将这个导出附加到本地系统上的`/home/jay/music`。接下来，我们指定我们正在访问的共享是`nfs`。最后，我们以一些选项结束配置，说明我们希望如何挂载这个共享。一个简单的挂载选项是`rw`，表示读写。如果我们想要防止其中的文件被更改，我们可以在这里使用`ro`。

在上一个示例中的选项中，有`x-systemd.automount`。基本上，这告诉 systemd（Debian 和 CentOS 的默认`init`系统，分别自版本 8 和 7 起）我们希望尽可能保持这个挂载。有了这个选项，systemd 会尽最大努力重新挂载这个共享，如果由于某种原因它断开连接。另外，可以添加`x-systemd.device-timeout=10`，告诉系统如果共享在网络上不可用，不要等待超过 10 秒。我们以`0 0`结束这一行，因为这不是一个本地文件系统，在启动时不需要一致性检查。

### 注意

如果你不使用带有 systemd 的发行版（如 CentOS 7 和 Debian 8），不要包括`x-systemd`选项，因为它们不会被使用不同`init`系统的发行版理解。

同样，Samba 共享也可以添加到你的`/etc/fstab`文件中。这是一个例子：

```
//10.10.10.9/Videos  /samba  cifs  username=jay  0  0

```

在我们继续之前，关于`/etc/fstab`文件的最后一点说明。本节中的示例都假定你希望网络共享在启动时自动可用。然而，这并不总是情况。如果在`fstab`中的配置行中添加了`noauto`挂载选项，共享将不会在启动时自动挂载。通过将`noauto`添加到我们的 Samba 示例中，`fstab`行将更改如下：

```
//10.10.10.101/Videos  /samba  cifs  noauto,username=jay  0  0 

```

NFS 示例如下：

```
10.10.10.101:/share/music
/mnt/music    nfs    users,rw,noauto,nolock,x-systemd.device-timeout=10 0 0

```

有几种情况下这可能会有用。一个例子可能是使用笔记本电脑，你不会总是连接到同一个网络。如果是这种情况，你不希望你的机器在你实际连接到该网络时自动挂载某些东西。通过将`noauto`添加为挂载选项，你可以在需要时手动挂载资源，而无需记住一个长长的`mount`命令。例如，要挂载包含在你的`fstab`文件中的 NFS 导出，你将执行以下操作：

```
# mount /mnt/music

```

相比之下，这比每次想要挂载该导出时输入以下内容要容易得多：

```
# mount -t nfs 10.10.10.101:/exports/music/ mnt/music

```

由于我们将导出添加到了`fstab`文件中，当我们输入一个简化的`mount`命令时，`mount`命令会查找相关行。如果它找到了你要访问的挂载点的配置，它将允许你访问它，而无需输入整个命令。即使你不想自动访问远程共享，将它们添加到你的`fstab`文件中仍然非常方便。

# 使用 SSHFS 创建网络文件系统

在上一章中，我们通过 SSH 工作，这是大多数 Linux 管理员每天多次使用的关键实用程序。但是，虽然它非常适合访问网络上的其他 Linux 系统，但它也允许你访问远程文件系统，就好像它们是本地挂载的一样。这就是**SSHFS**。关于 SSHFS 的一大好处是，无需事先澄清任何导出的目录。如果你能够连接到远程 Linux 服务器并通过 SSH 访问目录，那么你就能够自动将其本地挂载，就好像它是一个网络共享一样。

在 Debian 系统上，您可以简单地安装`sshfs`软件包。在 CentOS 上，默认情况下不提供`sshfs`软件包。在 CentOS 系统上安装`sshfs`之前，您需要添加一个全新的存储库，称为**企业 Linux 的额外软件包**（**EPEL**）。要做到这一点，只需安装`epel-release`软件包：

```
# yum install epel-release

```

安装`epel`存储库后，您应该能够安装`sshfs`：

```
# yum install sshfs

```

安装后，您可以轻松地在本地文件系统上挂载目录：

```
sshfs jay@10.10.10.101:/home/jay/docs /home/jay/mnt/docs

```

为了工作，您的用户帐户必须不仅访问远程系统，还要访问本地挂载点。一旦启动命令，您将看到类似于通过 SSH 连接到服务器时通常看到的提示。基本上，这就是您正在做的事情。不同之处在于连接保持在后台打开，保持远程目录和本地目录之间的关系。

在需要在远程文件系统上挂载某些内容，但您可能不需要再次访问或频繁访问时，使用`sshfs`是一个很好的主意。但与 NFS 和 Samba 共享类似，您实际上可以使用`/etc/fstab`通过 SSHFS 挂载资源。考虑以下`fstab`示例：

```
jay@10.10.10.101:/home/jay/docs                /home/jay/mnt/docs    fuse.sshfs      defaults,noauto,users,_netdev   0 0

```

与以前一样，我们设置了`noauto`，这样我们只需键入即可建立此连接：

```
mount /home/jay/docs

```

# 总结

在这个充满活力的章节中，我们通过几种方式访问和共享 Linux 网络中的文件。我们首先讨论了 NFS，这是在 Linux 和 UNIX 网络中共享文件的一种古老但可靠的方法。我们还涵盖了 Samba，这是在混合操作系统环境中共享资源的一种方法。我们还讨论了如何手动以及自动地挂载这些共享。我们最后讨论了 SSHFS，这是 SSH 的一个非常方便（但不太知名）的功能，它允许我们根据需要从其他系统挂载目录。

当然，依赖于我们网络中的资源，保持每个节点的良好运行状态非常重要。在下一章中，我们将通过监视系统资源并保持节点的良好状态来工作。
