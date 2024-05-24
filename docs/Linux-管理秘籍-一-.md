# Linux 管理秘籍（一）

> 原文：[`zh.annas-archive.org/md5/d1276a108c48d7de17a374836db89ea5`](https://zh.annas-archive.org/md5/d1276a108c48d7de17a374836db89ea5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在服务器方面，没有比 Linux 及其发行版系列更受欢迎的操作系统了。无论你现在为哪家公司工作，他们的基础设施中至少有一部分很可能是在运行某种 Linux 系统。

正因为如此，现在是进入 Linux 系统管理和工程（以及相关学科）的最佳时机，尽管我当然会这么说……作为一名 Linux 系统管理员。

这本书旨在成为你在 Linux 世界中某些常见任务的参考和指南，从平凡和基础的任务到有趣和复杂的任务，尽管任何任务都可能变得复杂，只要你努力。我希望在阅读时，你能发现一些新的东西（最好是很多新的东西），也许会遇到一些你以前没有遇到过的建议。

我们还将在工作中变得更加实用（因为仅仅阅读东西是无聊的），在整个过程中使用虚拟机来实现我们的目标。

# 这本书是为谁准备的

这本书适合各种人，从新手到老手（就像我一样）。

它旨在教会你入门所需的基础知识，同时介绍一些真实世界的例子，并提出一些你可能不知道的各种技巧和窍门。

即使你已经使用 Linux 几十年了，我希望你在这本书中能找到一些你不知道的东西，或者有所启发。

# 这本书涵盖了什么

第一章《介绍和环境设置》解释了如何设置一个原始环境，以便你了解 Vagrant 在幕后的操作，以及我们在安装方面的做法。

第二章《使用 SSH 进行远程管理》帮助你理解 SSH 的奇迹，以及它如何不仅可以让你的生活更加轻松，而且显著改善。

第三章《网络和防火墙》涵盖了我认为比其他任何主题都更痛苦的一个主题，即网络和防火墙。我们将探讨它们的重要性。

第四章《服务和守护进程》检查了守护进程的本质，追踪它们，并在它们变得过于贪婪时将其终结。本章还涵盖了服务。

第五章《硬件和磁盘》涵盖了任何系统中最险恶的部分，即硬件。在这里，我们将讨论磁盘的问题以及如何解决物理系统的故障。

第六章《安全、更新和软件包管理》涵盖了使服务器有用的内容。软件包必须以某种方式进入系统，我们将调查它们是如何做到的！

第七章《监控和日志记录》探讨了大多数系统管理员都觉得重要但又让人叹息的两个主题。我们将探讨为什么你需要合理的监控和健壮的日志记录。

第八章《权限、SELinux 和 AppArmor》涵盖了许多服务器上已经存在的内在安全系统，无论它们使用和配置起来有多么痛苦。在这里，我们将讨论它们的重要性。

第九章《容器和虚拟化》探讨了我喜欢的一个主题，即操作系统的分割以及你可能如何完成这样一项神秘的任务。

第十章《Git、配置管理和基础设施即代码》讨论了当你的计算机突然死机时不丢失配置的重要性，以及解决方案可以轻松启动和关闭的便利性。

第十一章，*Web 服务器、数据库和邮件服务器*，探讨了服务器可以提供的一些核心功能，支撑了互联网的大部分发明目标：通信。

第十二章，*故障排除和职场外交*，阐述了一些基本的故障排除技术，并包含了关于在压力情况下保持冷静的哲学讨论。作者在这方面有一定的权威。

第十三章，*BSDs、Solaris、Windows、IaaS 和 PaaS 以及 DevOps*，是关于 Linux 世界中一些半相关系统的有趣的最后一章，其中一些你肯定会遇到，一些本应该比它们现在的情况更好。

# 为了充分利用本书

你需要一台电脑。如果你打算跟着示例一起工作，最简单的方法是使用 Vagrant，这是一种用于通过编程构建便携式开发环境的软件。

在每个具有可运行代码的章节开头，你会找到一个 Vagrantfile 条目。这可以从前言后面提供的链接中下载，但如果你愿意的话也可以手动输入。

为了获得最佳体验，我建议使用至少四个内核和最好是 8GB RAM 的电脑，尽管你可能需要根据自己的目的进行调整。

本书假设您具有使用命令行在 Linux 文件系统中移动的基本知识。

# 下载示例代码文件

你可以从[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果你在其他地方购买了本书，你可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接发送到你的邮箱。

你可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址是[`github.com/PacktPublishing/Linux-Administration-Cookbook`](https://github.com/PacktPublishing/Linux-Administration-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。你可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789342529_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789342529_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“我已经为本章准备了以下`Vagrantfile`。”

代码块设置如下：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

$provisionScript = <<-SCRIPT
sed -i 's#PasswordAuthentication no#PasswordAuthentication yes#g' /etc/ssh/sshd_config
systemctl restart sshd
SCRIPT
```

当我们希望引起你对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```
[vagrant@centos2 ~]$ ip a
<SNIP>
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:56:c5:a7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.33.11/24 brd 192.168.33.255 scope global noprefixroute eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe56:c5a7/64 scope link 
       valid_lft forever preferred_lft forever
```

任何命令行输入或输出都以以下形式书写：

```
[vagrant@centos1 ~]$ ssh centos2 -X
```

**粗体**：表示一个新术语、一个重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“从主屏幕上做的最后一件事是设置我们的安装目的地。”

警告或重要说明会以这种形式出现。

技巧和窍门会以这种形式出现。

# 章节

在本书中，您会发现一些经常出现的标题（*准备工作*、*如何操作*、*它是如何工作的*、*还有更多*和*另请参阅*）。

为了清晰地说明如何完成一道菜谱，使用这些部分如下：

# 准备工作

本节告诉您可以在配方中期望什么，并描述了如何设置任何软件或配方所需的任何初步设置。

# 如何操作

本节包含了遵循配方所需的步骤。

# 它是如何工作的

本节通常包括对前一节发生的事情的详细解释。

# 还有更多

本节包含了有关配方的额外信息，以使您对配方更加了解。

# 另请参阅

本节提供了有用的链接，指向其他有关该配方的信息。


# 第一章：介绍和环境设置

在本章中，我们将涵盖以下内容：

+   理解和选择发行版

+   安装 VirtualBox

+   手动安装我们选择的发行版

+   连接到我们的**虚拟机**（**VM**）

+   访问和更新我们的虚拟机

+   了解 VM 的不同之处

+   快速的`sudo`解释

+   使用 Vagrant 自动配置 VM

+   轶事（尝试，尝试，再尝试）

# 介绍

在我们深入讨论我们将使用哪种发行版（有时缩写为“distro”）之前，我们必须首先迈出一大步，以一种略带哲学色彩的方式考虑**Linux**的概念。

对“Linux 是什么”进行一个良好的描述可能很难确定，这在很大程度上是由 IT 专业人员故意传播的混乱造成的，因为当他们来解释时，这让他们听起来比实际上更聪明。

因为你正在阅读这本书，我会假设你对 Linux 有一个较高层次的了解；你知道它是一个**操作系统**（**OS**），就像 Windows 或 macOS 一样，它并没有受到太多关注，并且通常不在桌面上使用。

这个评估是对也是错的，这取决于你和谁在说话。

悠闲的**系统管理员**（**sysadmins**）会更加放松，点点他们 80 年代的摩西头，同意 Linux 是一个操作系统，而且是一个不错的操作系统。然后他们会回去玩他们这周正在学习的时髦软件，以便下周可以尝试将其塞入基础设施中。

自称为灰发老者的人会停下手头的工作，大声叹息，拿起他们的第四杯咖啡，然后转身给你讲解 GNU/Linux（或 GNU+Linux）和 Linux 内核之间的区别。

内核是任何完整操作系统的重要组成部分。它是软件的一部分，位于硬件和软件之间，执行在两者之间进行翻译的繁重工作。所有操作系统都会有某种类型的内核，例如，macOS 的内核被称为**XNU**。

你将收到的讲座将会很乏味，会涉及到 Richard Stallman、Linus Torvalds，甚至可能还有 Andrew Tanenbaum 等人的名字，甚至可能会持续一个多小时，但主要的收获是 Linux 是你正在学习的操作系统的公认名称，同时也在技术上是不正确的。他们会说 Linux 实际上只是内核，所有其他东西都是包裹在 GNU 工具套件之上的发行版。

被认为是明智的避免这场辩论

在本书中，当我提到 Linux 时，我指的是整个操作系统，当我提到**内核**时，我实际上是在谈论 Linux 内核，其开发由 Linus Torvalds 领导。

# 理解和选择发行版

如前一节所示，Linux 是分散的。由于可以从众多不同供应商那里下载不同的**发行版**，这是描述这一点的最好方式。其中一些供应商是营利性的，提供支持合同和购买他们的操作系统时的服务级别协议（SLA），而另一些则完全是自愿的，由一个人在他们的车库里管理。

有成百上千种发行版可供选择，每种发行版都有自己的拥护者军团，告诉你为什么他们的发行版是“唯一真正的发行版”，“真的没有理由去寻找其他的”。

也有为特定目的创建的 Linux 发行版，例如据称是朝鲜 Linux 发行版的 Red Star OS。

事实上，大多数企业使用他们使用的 Linux 发行版是因为它：

+   当所有者谷歌搜索**免费操作系统**时，第一个弹出来的

+   第一个 IT 管理员喜欢的

+   提供可以在出现故障时调用的合同

逐个介绍当前存在的每个发行版是徒劳的，因为它们几乎每周都在被创建或被放弃。相反，我将介绍一些受欢迎的选择（在服务器空间而不是桌面上），解释一些关键区别，然后谈论我将在本书的其余部分中使用的发行版。

如果你的企业使用的发行版不是我们在这里讨论的，不要灰心 - 大多数工具在各种发行版上都是一致的，而在有差异的地方，都有文档可以帮助你。

如果你想了解更多关于可用发行版的信息，一个名为 DistroWatch 的网站（[`distrowatch.com/`](https://distrowatch.com/)）已经存在多年，提供一个定期更新的 Linux 发行版列表，按页面点击排名组织。

# Ubuntu

Ubuntu 是我安装的第一个 Linux 发行版，我敢打赌，对于很多在 2000 年代中期开始使用 Linux 的人来说也是如此。这也是我用来写这本书的发行版。

由于其良好的营销尝试（包括在搜索`Linux`时在谷歌排名中的位置）、被视为“人类的 Linux”以及用户友好性，它在桌面上一直享有一致的关注。

在 Debian 的下游，Ubuntu 的开发由 Canonical 负责，虽然他们最初强调制作坚固的桌面操作系统，但他们后来进入了试图主导服务器空间的高尚领域，并且也进入了物联网设备市场。

当我们在这方面说“下游”时，我们的意思是 Ubuntu 与 Debian 共享许多基础，只是它添加了一些额外的部分并去掉了一些部分。在 Linux 世界中，很少有从头开始的发行版，大多数使用其他发行版作为基础。

Ubuntu 以其可爱的命名惯例（18.04 被称为 Bionic Beaver）而闻名，事实上 Ubuntu 在桌面上如此受欢迎，这意味着它是系统管理员在服务器上安装的明显选择，因为他们已经熟悉它。

最近，处理继承系统时越来越常见的是找到 Ubuntu 安装，通常是一个长期支持（LTS）版本（这样可以避免在合理的时间内升级操作系统时的混乱和头痛）。

Ubuntu 每六个月发布一次版本，每两年发布一个 LTS 版本（最近的是 14.04、16.04 和 18.04）。它们的编号惯例是发布年份，后跟月份（所以 2018 年 4 月是 18.04）。可以从一个版本升级到另一个版本的 Ubuntu。

Canonical 在 Ubuntu 中引入新技术和软件时也毫不犹豫，即使它与他们的 Debian 基础有所偏离。最近的例子包括以下内容：

+   Snaps：一种分发与发行无关的软件的方式

+   Upstart：一种替代初始化系统，后来也被`systemd`替换

+   Mir：一种显示服务器，最初构想为取代老化的 X Window 系统

Ubuntu 可以从[`ubuntu.com`](https://ubuntu.com)下载。

# Debian

如前所述，Debian（通用操作系统）是许多后来的其他发行版的基础，但它一直是最受欢迎的发行版之一，无论是在桌面上还是在服务器上。很可能你会选择自己安装 Debian，或者继承一个运行这个发行版的系统，因为它以稳定性而闻名。

传统上，服务器空间的争夺是在两个阵营之间进行的，即 Debian Druids 和 CentOS Cardinals。近年来，新手已经加入了这场争夺（比如 Ubuntu），但这两个仍然控制着相当多的硬件。

每两三年发布一次，Debian 版本以《玩具总动员》角色命名（7—Wheezy，8—Jessie，9—Stretch）。它以稳定性而闻名，具有经过试验和测试的软件版本，以及合理的回溯修复。

回溯是指从最近的软件版本（例如内核本身）中获取修复，并将这些修复合并到您正在运行的版本中，将其重新编译为新的软件。由于功能可能会引入更多破坏性变化到长期支持的发行版中，功能很少会被回溯。

有时会对 Debian 提出一些批评，因为它通常在发布版本中提供较旧版本的软件包，这可能不包括系统管理员想要的所有时髦和酷功能，或者开发人员想要的。鉴于人们通常在服务器世界中寻求稳定性和安全性，而不是最新和最伟大的 Node.js 版本，这是不公平的。

Debian 有坚定的捍卫者，并且在许多人心中占有特殊地位，尽管在一些企业环境中看到它是不寻常的，因为它是由 Debian 项目开发的，而不是传统公司可以提供支持合同。根据我的个人经验，我更经常在需要快速解决方案的小公司和仍在运行一些传统系统的稍大公司中看到 Debian。

Debian 可以从[`www.debian.org`](https://www.debian.org)下载。

# CentOS - 我们将主要使用的一个

在传统的服务器领域战争的另一部分，CentOS 拥有自己的士兵和烈士。它仍然被广泛使用，并以稳定和无聊的声誉与 Debian 相媲美。

**社区企业操作系统**（**CentOS**）是红帽企业 Linux 发行版的免费可用和编译版本，旨在提供功能兼容性，通常用 CentOS 标志取代红帽标志，以避免侵犯商标。 （2014 年 1 月宣布红帽将与 CentOS 合作，以帮助推动和投资于 CentOS 的发展。）

因为它的性质，许多系统管理员安装了 CentOS 来更好地了解红帽世界，因为（如前所述）红帽在企业公司中有很好的声誉，所以安装一些如此相似的东西是有道理的。

这种安装趋势是双向的。我见过一些公司最初安装 CentOS，因为它很容易获得，并允许他们轻松设计基础架构，利用公开可用的免费仓库，然后转移到 RHEL 部署成品。

**仓库**是指软件安装在 Linux 系统上的常见位置的简称。Windows 通常从网站下载，macOS 有应用商店，Linux 在大部分时间里使用软件仓库，并且在命令行上很容易搜索。

我还见过一些公司在所有地方部署了 RHEL，只是意识到他们花了很多钱，却从未使用他们购买的支持，因为他们的运营团队实在太优秀了！然后他们逐渐淘汰了他们的红帽部署，并转移到了 CentOS，在这个过程中几乎没有改变。

每隔几年发布一次版本，版本 7 于 2014 年发布，并自那时起持续更新。然而，应该注意的是，2011 年发布的版本 6 将在 2020 年之前获得维护更新。

CentOS 可以从[`centos.org`](https://centos.org)下载。我们将在安装部分进行介绍。

# 红帽企业 Linux

红帽企业 Linux，或者更常见的 RHEL（因为它的名字很长），在企业中有着非常牢固的基础。它非常适合商业领域，因此很常见的情况是你发现自己在一个 RHEL 的系统上，而你最初以为它是一个 CentOS 的安装。

RHEL 的不同之处在于红帽公司提供的支持，以及如果你购买了官方软件包，你可以利用的各种服务。

尽管红帽仍然毫不犹豫地提供他们发行版的源代码（因此有了 CentOS），但他们为从桌面到数据中心安装的各种版本和软件包销售。

有一句谚语说“没有人因为购买 IBM 而被解雇”，这在今天有点过时，但我听说人们在多次场合上引用这个哲学来描述红帽。没有人会因为购买红帽而被解雇（但你可能会被问到为什么要为另一个名字下免费提供的东西付费的好处是什么）。

美妙的是，在我编辑这本书的过程中，IBM 宣布收购了红帽，这使我上面的评论变得完整。宇宙有时候真是伟大。

除了支持外，其他企业喜欢的商业态度，以及对整个社区的贡献，红帽还提供了一些被描述为“浪费时间”和“对这个角色至关重要”的东西。

考试在 Linux 社区中备受喜爱和嘲笑，这取决于你和 Linux 社区中的谁说话（就像许多事情一样，关于它们有一些圣战）。红帽提供了两个最受欢迎的考试，还有更多。你可以学习并成为红帽认证系统管理员，然后是红帽认证工程师，这被广泛认为是非常可接受的资格。

作为一名大学辍学生，我很高兴拥有 RHCE 资格。

有些人认为这些考试是为了通过那些招聘者的第一道关卡（就像那些扫描你的简历并寻找他们认识的徽章的人）。其他人认为这些考试证明了你对 Linux 系统的了解，因为这些考试是实际的（意味着他们让你坐在电脑前，给你一组完成的步骤）。有些人完全不理会考试，尽管他们通常是那些从未尝试过考试的人。

查看[`www.redhat.com`](https://www.redhat.com)，特别注意提供的各种软件包。他们也有开发者账户，可以让你访问你本来需要付费的服务（只要你不试图将它们悄悄地引入生产环境！）。

# 安装 VirtualBox

正如我在前一节中所说，我选择在这本书中大多数情况下使用 CentOS。希望这为你提供了一个很好的基础来学习 Linux 管理，同时也为你提供了一些优势，如果你打算参加任何红帽的考试。

我不会要求你有一台备用的笔记本电脑，或者在某个地方租用服务器，我会主张使用虚拟机来测试和运行给出的示例。

虚拟机正如它们的名字所示 - 是一种在一个或一组物理机上虚拟化计算机硬件的方式，因此允许你进行测试、破坏和尽情玩耍，而不会冒着使自己的计算机无法启动的风险。

创建虚拟机有很多种方式：macOS 有 xhyve，Windows 有 Hyper-V，Linux 有一个称为 Kernel Virtual Machine（KVM）的本地实现。

KVM（连同 libvirt）是你在 Linux 虚拟化领域经常遇到的技术。它构成了流行技术的基础，比如 Proxmox 和 OpenStack，同时提供接近本机速度。

另一种创建和管理虚拟机的方法是一个名为 VirtualBox 的程序，现在由 Oracle 开发。这个软件的好处，也是我在这里使用它的原因，是它是跨平台的，适用于 macOS、Windows 和 Linux。

# 在 Ubuntu 上安装 VirtualBox

我正在使用 Ubuntu 来撰写这本书，所以我将介绍在 Ubuntu 桌面上安装 VirtualBox 的基本方法。

这与在其他发行版上安装有些不同，但其中有很多都为其提供了安装包，并应该提供安装指南。

# 命令行安装

打开您的终端并运行以下命令：

```
$ sudo apt install virtualbox 
```

使用 sudo 通常会提示您输入密码，当您输入时，屏幕上不会显示任何内容。

您可能会被提示确认安装 VirtualBox 及其依赖项（可能有很多-这是一个复杂的程序，如果您有一段时间没有更新，您可能也会得到一些依赖项更新）。

按*Y*和*Enter*继续。以下屏幕截图显示了从命令行启动安装的示例：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/544d0efc-3187-468b-8526-6401b6e1f151.png)

完成后，您应该已经安装了一个可用的 VirtualBox。

# 图形安装

如果愿意，您也可以通过 Ubuntu 软件安装 VirtualBox。

只需搜索您想要的软件，在本例中是 VirtualBox，并转到其商店页面。

然后，点击安装，软件包将被安装，无需终端！

安装后，您的屏幕将更改以显示启动和删除选项。

# 在 macOS 上安装 VirtualBox

虽然我正在使用 Ubuntu，但如果您不是，也不是世界末日。macOS 也是一个很好的操作系统，并且方便的是它支持 VirtualBox。

在本教程中，我们将介绍在 macOS 中安装 VirtualBox 的几种方法。您会发现，无论您使用的操作系统是什么，布局都非常相似。

# 命令行安装

如果您已经安装了命令行程序`brew`，那么获取 VirtualBox 就像运行以下命令一样简单：

```
$ brew cask install virtualbox
```

您可能会被提示输入超级用户密码以完成安装。

Homebrew 可以从[`brew.sh/`](https://brew.sh/)获得，并且实际上是 macOS 需要但默认没有的软件包管理器。我不建议盲目地从神秘的网站运行脚本，所以在您决定冒险安装 brew 之前，请确保您了解正在执行的操作（阅读代码）。

# 图形安装

Oracle 还为 macOS 提供了安装镜像，如果您愿意以更传统的方式安装。

只需转到[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)并选择 OS X hosts 选项。

这将提示您将安装程序下载到本地系统，然后您可以解压并安装。

在安装过程中，您可能会被提示输入超级用户密码。

# 在 Windows 上安装 VirtualBox

如果您的计算机上没有使用 Linux 版本，也没有使用 macOS，那么您很可能在运行 Windows（除非您已经在桌面上深入研究了 FreeBSD 或类似的操作系统，在这种情况下我无法帮助您-我们需要整整一个下午）。

如果使用 Windows，我可以再次建议 VirtualBox，因为它具有跨操作系统的特性，并且可以再次从 Oracle 的网站上安装。

# 图形安装

像 macOS 安装一样，转到[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)并选择 Windows hosts 选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/7a4e580a-3f97-4ff6-873f-9e9a712d3e77.png)

这将下载一个可执行文件。

值得注意的是，如果您尝试同时运行多个虚拟化解决方案，Windows 可能会抱怨。如果您之前运行过 Hyper-V 或 Docker，并且在尝试启动 VirtualBox 虚拟机时遇到问题，请先尝试禁用其他解决方案。

# 手动安装我们选择的发行版

哦，这是一次旅程，我们甚至还没有正式开始！

接下来，我们将手动设置一个虚拟机。但不要担心！我们还将研究使用 Vagrant 自动化此过程，以避免在本书的其余部分中执行重复的步骤。

如果您已经熟悉安装 CentOS，可以完全跳过本节。我已经在本书的其余部分提供了 Vagrantfiles，用于自动化我们将要使用的虚拟机。

# 获取我们的 CentOS 安装媒体

Linux 发行版的主要分发方式是 ISO 镜像。然后可以将这些镜像刻录到 DVD 上，或者挂载到虚拟机以引导。

前往[`centos.org/download/`](https://centos.org/download/)，看看提供的选项。

我将下载最小 ISO，原因很快就会变得清楚。

点击后应该会带您到一个镜像页面：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/36bc9a7e-cc61-4b4f-b6a8-aa6b8d836e9c.png)

这是 CentOS 项目为节省带宽而采取的措施，通过提示最终用户从任意数量的不同主机下载。他们可以将带宽成本分摊给志愿者。

你会发现这些提供者通常分为两类，但也有例外。通常，这些镜像是由大学或托管提供商提供的。我内心的怀疑者认为，托管提供商提供镜像服务是一种易于营销的方式，而不是一种慈善举动。

选择一个靠近您的下载位置，并等待下载完成。

您可能会注意到其中一个下载选项是通过 Torrent。通过 Torrent 下载是一种将带宽成本分摊给多个人的好方法，并且允许从多个位置下载软件的小部分大大减少了任何一个来源的负载。但应该注意，一些工作场所会注意他们的网络上是否有这种类型的流量，因为 Torrent 下载的声誉。

# 检查校验和

一旦下载完成（可能需要一段时间，因为即使是最小的也很大），您将面对一个 ISO 镜像。

在我的 Ubuntu 安装中，我可以在我的`Downloads`文件夹中看到它：

```
$ ls ~/Downloads/
CentOS-7-x86_64-Minimal-1804.iso
```

确认我们的安装媒体并确保我们已经下载了我们期望的内容的一种方法是比较已下载文件的`Sha256`总和与已知良好值。这既证明了它是我们期望的下载，也检查了文件下载过程中是否发生了损坏。

CentOS 提供了一个发布说明页面，我们可以访问以找到我们要比较的`Sha256`总和：[`wiki.centos.org/Manuals/ReleaseNotes`](https://wiki.centos.org/Manuals/ReleaseNotes)。

点击进入 CentOS 7 的发布说明，这应该会带您到最新版本的发布说明。

在这个页面上，我们可以滚动到验证已下载安装镜像，其中将列出下载镜像的当前`Sha256`总和。

始终确保您获取已知良好的`Sha256`值的网站本身是合法的。

在我的情况下，我可以看到我刚下载的文件的`Sha256`值如下：

```
714acc0aefb32b7d51b515e25546835e55a90da9fb00417fbee2d03a62801efd  CentOS-7-x86_64-Minimal-1804.iso
```

有了这个，我可以回到终端中列出文件的地方，并运行一个基本命令来检查已下载镜像的`Sha256`值：

```
$ sha256sum CentOS-7-x86_64-Minimal-1804.iso 
714acc0aefb32b7d51b515e25546835e55a90da9fb00417fbee2d03a62801efd  CentOS-7-x86_64-Minimal-1804.iso
```

将 CentOS 网站上的值与我下载的镜像的值进行比较，确认它们是相同的。

媒体与我们预期的一样！

`Sha256`检查也可以在 Windows 和 macOS 上进行。在 macOS 上，可以使用内置工具来完成，但 Windows 可能需要其他软件。

# 设置我们的虚拟机

现在我们有了媒体并且 VirtualBox 已安装，是时候手动进行机器配置（技术术语）并安装 CentOS 了。

在这一部分，我们将配置一个小型虚拟机，但即使这样也会消耗处理能力、内存和磁盘空间。始终确保您有适当的资源可用于您要创建的机器。在这种情况下，至少需要 50GB 的可用磁盘空间和至少 8GB 的内存。

# VirtualBox 主窗口

启动后，您将看到 VirtualBox 主窗口。目前，我们只对左上角的“新建”按钮感兴趣。您需要点击“新建”按钮。

接下来，您将被提示为您的虚拟机命名。

将您的第一台机器命名为`CentOS-1`。

注意当您为机器命名时，类型和版本会自动检测您输入的内容，并根据需要重新配置选择。

在这种情况下，它给我们提供了 Linux 类型和 Red Hat 版本（64 位）。这没问题，因为我们之前说过 CentOS 和 Red Hat Enterprise Linux 非常接近。

点击下一步。

64 位是操作系统的架构，尽管您安装的操作系统必须受到您的 CPU 支持（大多数 CPU 现在都是 x86_64）。常见的架构一直是 x86（32 位）和 x86_64（64 位），但最近 x86 变种已经逐渐消失。如今最常见的安装是 x86_64，尽管 ARM 和 aarch64 机器变得越来越普遍。在本书中，我们只会使用 x86_64 机器。

现在，我们必须配置要为我们的机器提供的内存量。如果受到限制，您可以将其设置为低于默认值`1024`MB（1GB），但 1,024MB 是一个合理的起点，如果需要，我们随时可以调整它。

现在，我们将被提示为我们的虚拟系统配置硬盘。

保留默认选项“现在创建虚拟硬盘”，并点击创建。

您将被提示选择类型。保留默认选择，即 VDI（VirtualBox 磁盘映像）。

您将有选择随时间分配磁盘空间（动态分配）或一次性分配所有空间（固定大小）的选项。我倾向于将其保留为动态分配。

接下来，您将被提示选择磁盘的位置和大小。我建议将磁盘保留在默认位置，并且暂时默认大小的`8`GB 应该足够开始使用。

点击创建。

如果一切顺利，您将返回主窗口，并且新的虚拟机应该会显示在左侧处于“已关闭”状态。

# CentOS 安装

现在我们有了虚拟机，是时候在上面安装我们的操作系统了。

在主 VirtualBox 窗口顶部点击“启动”，选择您的虚拟机，应该会提示您首先选择启动盘。

我已经导航到我的“下载”文件夹，并选择了之前下载的镜像。

按下“启动”将从我们的媒体引导机器。

您将在虚拟机中看到选项屏幕，默认选择了“测试此媒体并安装 CentOS 7”。

我通常按下箭头键（在虚拟机窗口内）只选择安装 CentOS 7 并跳过媒体检查，尽管您可能希望进行测试。

如果您使用物理媒体来安装机器（DVD 或 CD），在安装之前进行媒体测试可能是个好主意。

按下*Enter*将继续安装。

您将被提示选择您的语言。我选择英语，因为我只会一种语言。

完成后，您将会发现自己在最新的 CentOS 安装程序的起始页面上：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/c216e71b-0a2b-4123-b31e-3dad56fa2dd0.png)

注意底部的消息，建议需要完成标有黄色图标的项目。

因为我们的日期/时间、键盘和语言都是正确的，我们将继续进行下一步，但如果对您来说有错，可以随时更正。

注意，在“安装源”下我们选择了“本地媒体”，在“软件选择”下我们选择了“最小安装”。这是我们之前选择最小镜像的结果，并给了我们一个很好的机会来谈论通过互联网进行安装。

首先，我们需要配置我们的网络。点击“网络和主机名”来做这个。

你应该有一个以太网设备，作为制作 VM 时默认配置的一部分。

切换设备名称右侧的开/关切换，并检查网络值是否与我的类似：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/cfad055f-aa52-469d-862f-8b0d00376cda.png)

VirtualBox 默认创建一个 NAT 网络，这意味着你的 VM 不在与主机计算机完全相同的网络上。相反，VM 存在于一个独立的网络中，但通过主机机器有通往外部世界的路径。

在左上角按“完成”来完成我们的网络设置（暂时）！

回到主屏幕，点击“安装源”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/b021f44a-a3f4-4114-b327-46d3fec2f187.png)

在这个屏幕上，你可以看到自动检测到的媒体实际上是我们的磁盘映像（`sr0`是 Linux 对光驱的表示）。

将选中的单选按钮更改为“在网络上”。

在 URL 栏中填入以下内容：

```
mirror.centos.org/centos/7/os/x86_64/
```

你最终会看到以下截图：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/901711d3-0acd-4807-a9fa-6a383558659f.png)

在左上角按“完成”。

一旦你回到主屏幕，会显示你的软件源已经改变，你需要通过进入“软件选择”窗口来验证这一点。继续进行。

浏览不同的选项，但现在保留“最小安装”选中并点击“完成”：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/afea01e8-6057-4d62-87c5-1022d55eefda.png)

从主屏幕上做的最后一件事是设置我们的“安装目的地”。点击进入这个屏幕。

看看选项，但现在我们不打算改变默认的分区布局，或者加密我们的磁盘。你还应该看到默认选择的磁盘是我们的 8GB VirtualBox 磁盘。

点击“完成”（你不需要做任何更改，但安装程序至少让你进入这个屏幕）：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/374bb271-1b2f-4455-a4db-2e0798dd305e.png)

我们终于完成了我们（相当基本的）配置。在主屏幕底部点击“开始安装”按钮。

你会看到安装开始，并在等待时会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/3aab7464-a2be-4122-b5f4-5e80ea64ca0f.png)

依次点击顶部的选项，设置`root`密码并创建一个用户。

`root`用户类似于 Windows 系统上的管理员；它是全能的，在错误的手中可能会很危险。有些发行版甚至在安装时都不提示你设置 root 密码，而是让你使用自己的用户和`su`或`sudo`。

在创建用户时，也将其标记为管理员：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/f7f408f0-9da3-48a0-adec-098a9b8860aa.png)

点击“完成”将带你回到安装进度屏幕，你可能会被提示完成安装的其余部分，并最终被要求重新启动到你新安装的系统中。

没有理智的人应该产生那么多的截图。

# 访问和更新我们的 VM

现在我们已经安装了 VM，我们将登录并快速查看一下。

# 从 VirtualBox 窗口登录

点击进入我们的 VM，就像我们在安装时所做的那样，允许我们在登录提示符处输入：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/fffbf2d8-5938-46fe-b6a4-734366bf27e6.png)

我们将使用安装时创建的用户，而不是 root。

注意，你还会得到有关自上次登录以来的登录尝试的一些信息。在这种情况下，我第一次尝试登录失败了，它告诉我这一点：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/5fa84258-fb53-4a5c-bd70-a4f1154c4afd.png)

恭喜-你已经安装了 CentOS！

很少见到安装了**图形用户界面**（**GUI**）的 Linux 服务器，尽管确实会发生。在我使用过的成千上万台服务器中，我只能用一只手数出安装了 GUI 的次数。通常会导致短暂的困惑和苦恼，然后得出结论，即肯定是有人不小心安装了 GUI - 没有其他解释。

在我们继续之前，我们将运行一个快速命令来查找我们机器的 IP 地址：

```
$ ip a
```

`ip a`是输入`ip address`的一种简写方式，我们稍后会更详细地介绍。

这给了我们很多网络信息，但至关重要的是它给了我们网络接口的`inet`地址，即`10.0.2.15`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/24e3007d-88b0-4d93-91ce-faabf858a0f6.png)

# 从主机终端登录

因为使用 VirtualBox 界面有点麻烦（使得复制和粘贴之类的事情变得棘手），所以有一个更优雅的连接和与我们的机器交互的方法是有意义的。

**安全外壳**（**SSH**）是我们将要使用的工具，因为它提供了一种快速和安全的连接远程机器的方式。

原生 SSH 客户端适用于 macOS 和所有 Linux 发行版。Windows 在这方面也取得了一些进展，尽管我知道在 Windows 上使用 SSH 的最简单方法仍然是下载一个名为 PuTTY 的程序。

把 SSH 想象成 Windows 远程桌面协议。如果你是这个领域的新手，它通常更快，因为它不需要向你传输图形连接。SSH 完全是基于文本的。

使用我们刚才的 IP 地址，我们将尝试从主机（你在 VirtualBox 上运行的机器）SSH 到我们的虚拟机：

```
$ ssh adam@10.0.2.15
ssh: connect to host 10.0.2.15 port 22: Connection refused
```

哦，不！有些不对劲！

我们还没有连接，连接显然被拒绝了！

# 确保 sshd 正在运行

首先，我们要确保`sshd`的服务器组件正在运行，方法是登录到 VirtualBox 中的虚拟机并运行以下命令：

```
$ sudo systemctl enable sshd
$ sudo systemctl start sshd
```

你应该被提示（至少一次）输入之前设置的用户密码。

我们正在启用`sshd`服务，使其在服务器启动时启动第一个命令，并立即启动它（这样我们就不必重新启动虚拟机）。

# 确保 VirtualBox 让我们通过

仅仅启动`sshd`还不足以让我们从主机连接到虚拟机，我们还必须为 VirtualBox NAT 网络设置一些端口转发。

端口转发是手动指定流量如何穿越 NAT 网络的方法。如果你在 2000 年代中期玩 Diablo 2 或魔兽争霸 III，你可能会很有趣地尝试让端口转发与你家里的路由器一起工作。

从主 VirtualBox 窗口，突出显示你的虚拟机并点击顶部的设置。转到网络部分并点击高级旁边的箭头以展开更大的部分。点击端口转发：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/e611068c-e618-4953-84aa-90a23759b082.png)

在弹出的新窗口中，点击右侧添加新规则，并使用以下截图中的设置填充它，如果你的 Guest IP 不同，就替换它：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/11ee068c-ed4c-4ab1-a961-73ed0d7b2295.png)

请注意，我们实际上是将我们主机上的`127.0.0.1:2222`映射到我们虚拟机上的`10.0.2.15:22`。我们设置了这样的连接尝试，使得任何连接尝试都会被转发到端口`22`的虚拟机，从而连接到我们主机机器的`localhost`地址上的端口`2222`。

在给出的示例中，`2222`是完全随机的 - 它可以是`8222`，`5123`，`2020`等等。我选择`2222`是为了方便。你不应该尝试使用低于`1024`的端口进行这种操作，因为这些端口只允许 root 访问。

我们现在可以尝试我们刚刚设置的 SSH 命令：

```
$ ssh adam@127.0.0.1 -p2222
The authenticity of host '[127.0.0.1]:2222 ([127.0.0.1]:2222)' can't be established.
ECDSA key fingerprint is SHA256:M2mQKN54oJg3B1lsjJGmbfF/G69MN/Jz/koKHSaWAuU.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[127.0.0.1]:2222' (ECDSA) to the list of known hosts.
adam@127.0.0.1's password: 
```

关于这个命令有一些要解释的事情。

我通过使用`adam@`指定了用户名，并告诉 SSH 尝试连接到本地地址`127.0.0.1`，以及我们选择的端口，即`2222`。

我们会看到主机的指纹，稍后我们会更详细地讨论，并且我们会接受它。

然后，我们将使用在 VM 中设置的密码登录我们的用户：

```
Last login: Mon Aug  6 15:04:26 2018
[adam@localhost ~]$ 
```

成功！

现在我们可以像处理真实服务器一样处理我们的 VM - 只需确保在运行任何命令时您在 VM 上。

# 更新我们的 VM

现在我们已经可以访问我们的机器，我们将运行一个命令，以确保我们拥有所有安装软件的最新版本：

```
$ sudo yum update
```

运行时，您可能会看到一个需要更新的软件的长列表。输入*Y*进行确认并按*Enter*将处理此软件的升级，以及任何需要的依赖软件。您可能还会被提示接受新的或更新的 GPG 密钥。

GPG 是一本书的内容 - 不是一本令人兴奋的书，但肯定是一本书。

如果您升级了不断运行的软件，比如 Apache web 服务器，最好安排重新启动该服务，以确保使用新版本。

一般来说，只有内核和 init（初始化）系统在更新后才需要完全系统重启。这与 Windows 有着明显的不同，Windows 似乎设计用于重启，而实际工作只是副产品。

在我的情况下，我的内核得到了更新。我可以通过以下方式确认这一点。

首先，我们列出已安装的`kernel`包的版本：

```
$ yum info kernel
Loaded plugins: fastestmirror
Loading mirror speeds from cached hostfile
 * base: repo.uk.bigstepcloud.com
 * extras: mirror.sov.uk.goscomb.net
 * updates: mirrors.melbourne.co.uk
Installed Packages
Name        : kernel
Arch        : x86_64
Version     : 3.10.0
Release     : 862.el7
Size        : 62 M
Repo        : installed
From repo   : anaconda
Summary     : The Linux kernel
URL         : http://www.kernel.org/
Licence     : GPLv2
Description : The kernel package contains the Linux kernel (vmlinuz), the core of any
 : Linux operating system.  The kernel handles the basic functions
 : of the operating system: memory allocation, process allocation, device
 : input and output, etc.

Name        : kernel
Arch        : x86_64
Version     : 3.10.0
Release     : 862.9.1.el7
Size        : 62 M
Repo        : installed
From repo   : updates
Summary     : The Linux kernel
URL         : http://www.kernel.org/
Licence     : GPLv2
Description : The kernel package contains the Linux kernel (vmlinuz), the core of any
 : Linux operating system.  The kernel handles the basic functions
 : of the operating system: memory allocation, process allocation, device
 : input and output, etc.
```

然后，我们使用`uname`检查当前正在使用的内核的版本：

```
$ uname -a
Linux localhost.localdomain 3.10.0-862.el7.x86_64 #1 SMP Fri Apr 20 16:44:24 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

从中我们可以看到我们正在运行版本`3.10.0-862.el7`，但我们也有`3.10.0-862.9.1.el7`。

重新启动系统会导致在启动时选择新的内核，再次运行`uname`会显示不同的结果：

```
$ uname -a
Linux localhost.localdomain 3.10.0-862.9.1.el7.x86_64 #1 SMP Mon Jul 16 16:29:36 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

万岁 - 我们正在运行更新的内核！

# 了解 VM 的不同之处

早些时候，我们开始谈论 VM 和它们是什么。现在我们将从机器内部看一下几种确定我们是否在 VM 中的方法。

如果我从托管提供商那里获得了一个新的**虚拟专用服务器**（**VPS**），并想知道用于虚拟化我的新机器的软件是什么，我通常会这样做。

# dmidecode

我最喜欢的工具之一，dmidecode，可以用来转储计算机的**桌面管理接口**（**DMI**）表。在实践中，这意味着它可以用来查找在机器中运行的硬件类型。

此命令需要 root 访问权限，因此在这些示例中我们将一直使用`sudo`。

首先，我们将列出可以传递给 dmidecode 的有效`types`：

```
$ dmidecode --type
dmidecode: option '--type' requires an argument
Type number or keyword expected
Valid type keywords are:
 bios
 system
 baseboard
 chassis
 processor
 memory
 cache
 connector
 slot
```

从顶部开始，我们将使用`bios`，看看它是否给我们一些有用的东西：

```
$ sudo dmidecode --type bios
# dmidecode 3.0
Getting SMBIOS data from sysfs.
SMBIOS 2.5 present.

Handle 0x0000, DMI type 0, 20 bytes
BIOS Information
 Vendor: innotek `GmbH`
 Version: VirtualBox
 Release Date: 12/01/2006
 Address: 0xE0000
 Runtime Size: 128 kB
 ROM Size: 128 kB
 Characteristics:
 ISA is supported
 PCI is supported
 Boot from CD is supported
 Selectable boot is supported
 8042 keyboard services are supported (int 9h)
 CGA/mono video services are supported (int 10h)
 ACPI is supported
```

立即，我们可以在`Version`旁边看到`VirtualBox`，这是一个相当明显的暗示，表明我们正在处理一个 VM。

接下来，我们将选择其他内容，`system`：

```
$ sudo dmidecode --type system
# dmidecode 3.0
Getting SMBIOS data from sysfs.
SMBIOS 2.5 present.

Handle 0x0001, DMI type 1, 27 bytes
System Information
 Manufacturer: innotek GmbH
 Product Name: VirtualBox
 Version: 1.2
 Serial Number: 0
 UUID: BDC643B8-8D4D-4288-BDA4-A72F606CD0EA
 Wake-up Type: Power Switch
 SKU Number: Not Specified
 Family: Virtual Machine
```

再次看到这里的`Product Name`是`VirtualBox`，`Family`是`Virtual Machine`，这两者都是相当有力的证据。

最后，我们将查看`Chassis Information`：

```
$ sudo dmidecode --type chassis
# dmidecode 3.0
Getting SMBIOS data from sysfs.
SMBIOS 2.5 present.

Handle 0x0003, DMI type 3, 13 bytes
Chassis Information
 Manufacturer: Oracle Corporation
 Type: Other
 Lock: Not Present
 Version: Not Specified
 Serial Number: Not Specified
 Asset Tag: Not Specified
 Boot-up State: Safe
 Power Supply State: Safe
 Thermal State: Safe
 Security Status: None
```

甲骨文公司再次是一个重要的信息，让我们相信我们处于一个虚拟化的环境中。

如果我们不想要很多其他信息，我们可以使用 dmidecode 的`-s`选项来微调我们的搜索。

运行此选项而不带参数会输出一个我们可以使用的潜在参数列表：

```
$ sudo dmidecode -s
dmidecode: option requires an argument -- 's'
String keyword expected
Valid string keywords are:
 bios-vendor
 bios-version
 bios-release-date
 system-manufacturer
 system-product-name
 system-version
 system-serial-number
 system-uuid
 baseboard-manufacturer
 baseboard-product-name
 baseboard-version
 baseboard-serial-number
 baseboard-asset-tag
 chassis-manufacturer
 chassis-type
 chassis-version
 chassis-serial-number
 chassis-asset-tag
 processor-family
 processor-manufacturer
 processor-version
 processor-frequency
```

在这里，我们可以立即看到`bios-version`，正如我们之前所知道的，它应该是`VirtualBox`：

```
$ sudo dmidecode -s bios-version
VirtualBox
```

这些类型的短输出命令对于脚本编写非常有用，有时简洁是可取的。

dmidecode 通常默认安装，至少在 Ubuntu 和 CentOS 安装中是这样。

# lshw

如果 dmidecode 不可用，您也可以使用`lshw`，这是一个列出硬件的命令。同样，它利用设备上的 DMI 表。

我们可以很快地使用`lshw`的格式选项来显示系统的总线信息：

```
$ sudo lshw -businfo
Bus info Device Class Description
=====================================================
 system VirtualBox
 bus VirtualBox
 memory 128KiB BIOS
 memory 1GiB System memory
cpu@0 processor Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
pci@0000:00:00.0 bridge 440FX - 82441FX PMC [Natoma]
pci@0000:00:01.0 bridge 82371SB PIIX3 ISA [Natoma/Triton II]
pci@0000:00:01.1 scsi1 storage 82371AB/EB/MB PIIX4 IDE
scsi@1:0.0.0 /dev/cdrom disk CD-ROM
pci@0000:00:02.0 display VirtualBox Graphics Adapter
pci@0000:00:03.0 enp0s3 network 82540EM Gigabit Ethernet Controller
pci@0000:00:04.0 generic VirtualBox Guest Service
pci@0000:00:05.0 multimedia 82801AA AC'97 Audio Controller
pci@0000:00:06.0 bus KeyLargo/Intrepid USB
usb@1 usb1 bus OHCI PCI host controller
pci@0000:00:07.0 bridge 82371AB/EB/MB PIIX4 ACPI
pci@0000:00:0d.0 scsi2 storage 82801HM/HEM (ICH8M/ICH8M-E) SATA Controller [AHCI mode]
scsi@2:0.0.0 /dev/sda disk 8589MB VBOX HARDDISK
scsi@2:0.0.0,1 /dev/sda1 volume 1GiB Linux filesystem partition
scsi@2:0.0.0,2 /dev/sda2 volume 7167MiB Linux LVM Physical Volume partition
 input PnP device PNP0303
 input PnP device PNP0f03
```

这给了我们一些关于虚拟机的信息，比如系统、总线和显示条目。

我们还有一个易于阅读的类别可用的详细信息，这意味着我们可以直接查询这些信息，从这个例子开始，首先是`disk`：

```
$ sudo lshw -c disk
 *-cdrom 
 description: DVD reader
 product: CD-ROM
 vendor: VBOX
 physical id: 0.0.0
 bus info: scsi@1:0.0.0
 logical name: /dev/cdrom
 logical name: /dev/sr0
 version: 1.0
 capabilities: removable audio dvd
 configuration: ansiversion=5 status=nodisc
 *-disk
 description: ATA Disk
 product: VBOX HARDDISK
 vendor: VirtualBox
 physical id: 0.0.0
 bus info: scsi@2:0.0.0
 logical name: /dev/sda
 version: 1.0
 serial: VB5cbf266c-3015878d
 size: 8GiB (8589MB)
 capabilities: partitioned partitioned:dos
 configuration: ansiversion=5 logicalsectorsize=512 sectorsize=512 signature=000b6a88
```

或者，如果我们认为这是太多的信息，我们可以查询系统类：

```
$ sudo lshw -c system
localhost.localdomain 
 description: Computer
 product: VirtualBox
 vendor: innotek GmbH
 version: 1.2
 serial: 0
 width: 64 bits
 capabilities: smbios-2.5 dmi-2.5 vsyscall32
 configuration: family=Virtual Machine uuid=BDC643B8-8D4D-4288-BDA4-A72F606CD0EA
```

# 快速 sudo 解释

在前面的配方中给出的各种命令中，我们反复使用了`sudo`。这是为了我们不必以`root`用户登录来执行各种受限制的操作。

`sudo`是'superuser do'的缩写，因为`sudo`过去只用于以"超级用户"身份运行命令，现在你可以用它以各种用户的身份运行命令。

通常，如果你尝试运行一个你没有权限成功完成的命令，你会收到一个错误提示：

```
$ less /etc/sudoers 
/etc/sudoers: Permission denied
```

在这里，我试图查看`/etc/sudoers`文件，这也恰好是决定用户`sudo`权限的文件。

用`sudo`运行这个命令就是另一回事了。它会为我打开文件，将我放入`less`分页器。

在这个文件的底部，我们找到以下的代码块：

```
## Allows people in group wheel to run all commands
%wheel  ALL=(ALL)       ALL
```

这个代码块中的`wheel`部分是没有被注释的，上面的文本告诉我们这意味着什么。

因此，显而易见的下一个问题是，我是否在`wheel`组中？

术语`wheel`在古老的 UNIX 安装中有着悠久的历史。这些天，它可能被称为`admin`或其他。CentOS 通过使用`wheel`保持了经典。

幸运的是，这很容易检查 - 问题文件总是在同一个地方：`/etc/group`。

在这里，我们将`group`文件的内容打印到屏幕上，并特别查找`wheel`。

我们看到以下的布局：

```
group_name:password:GID:user_list
```

我们可以看到`group_name`是`wheel`，`password`是一个小写的`x`，这意味着正在使用影子密码，组 ID 是`10`，而这个组中唯一的用户就是我自己：

```
$ sudo cat /etc/group | grep wheel
wheel:x:10:adam
```

我们甚至可以用一个单词来做到这一点，那就是`groups`命令，它会打印出你当前用户所属的组：

```
$ groups
adam wheel
```

被授予使用`sudo`运行超级用户命令的能力并不是每个系统上的每个人的直接权利，这取决于个别公司和管理团队决定如何分配这种权力。

有些地方的运维人员都有`sudo`的权限，而有些地方只有一个人有这个权限。

# 使用 Vagrant 自动配置虚拟机

每次想要测试新东西或创建一个沙盒来工作时，都要重复安装新的虚拟机会很快变得乏味。

因此，各种管理员和开发人员想出了解决方案，使得配置虚拟机（或多个虚拟机）变得轻而易举。

如果我们花点时间考虑一下这种方法的优势，很容易就能突出自动化虚拟机配置的一些好处：

+   它消除了手动输入答案到虚拟机窗口中所需的时间。

+   它允许在开发环境中自动运行软件测试。

+   它允许共享文本文件，作为构建虚拟机的配方，而不是在各个站点之间传输大型虚拟机镜像。这是一种**基础设施即代码**（**IaC**）的形式。

# Kickstart

自动部署盒子的一种方法是 kickstart 文件，它经常用于大型部署中自动回答安装程序向用户提出的问题。

如果你在 CentOS 虚拟机的`/root/`文件夹中查看，很有可能会找到一个名为`anaconda-ks.cfg`的文件，这实际上是你在安装机器时执行手动步骤的 kickstart 文件（anaconda 是安装程序的名称）。

这些文件被调整或从头开始编写，然后托管在 Web 服务器上，放在一个未配置的机器上，准备好被拾取。

# Vagrant

在本地，kickstart 文件并不是很实用，而且使用起来也不太快。我们需要一些可以快速轻松设置的东西，但又非常强大。

输入`Vagrant`。

Vagrant 由 Hashicorp 开发为开源软件，可用于自动配置 VM 甚至整个开发环境。

通常，您可能会在某个内部应用程序的存储库中找到一个`Vagrantfile`（核心 Vagrant...文件...）的名称。

开发人员将应用程序的存储库下载到他们的本地计算机，并使用 Vagrant 配置文件启动本地开发环境，然后他们可以使用该环境测试代码更改或功能添加，而不需要使用昂贵的开发环境。

Vagrant 适用于 macOS、Linux 和 Windows。

在我的 Ubuntu 主机上，我安装 Vagrant 如下：

```
$ sudo apt install vagrant
```

之后会有相当多的依赖项，总共使用了大约 200MB 的磁盘空间。

Ubuntu 的软件包相当新，所以我们得到了一个最新版本：

```
$ vagrant --version
Vagrant 2.0.2
```

我对文件存放的位置非常挑剔，所以我将在我的主目录中创建一个名为`Vagrant`的专用文件夹，用于处理我的 Vagrant VM：

```
$ ls
 Desktop     Downloads   Pictures   snap        Videos
 Documents   Music       Public     Templates  'VirtualBox VMs'
$ mkdir Vagrant
$ cd Vagrant/
```

接下来，我们将初始化一个新的`Vagrantfile`。以下命令将自动执行此操作：

```
$ vagrant init
$ ls
Vagrantfile
```

查看`Vagrantfile`，但暂时不要进行任何更改。您会看到许多选项都已列出，但默认情况下都已注释掉。这是一个很好的介绍，让您了解 Vagrant 的功能。

请注意，默认情况下，Vagrant 将尝试使用一个名为`base`的盒子，但也会提示您查看[`vagrantcloud.com/search`](https://vagrantcloud.com/search)以获取其他盒子：

```
 # Every Vagrant development environment requires a box. You can search for
 # boxes at https://vagrantcloud.com/search.
 config.vm.box = "base"
```

在`vagrantcloud`上搜索 CentOS 会发现一个很好的默认盒子可供使用：[`app.vagrantup.com/centos/boxes/7`](https://app.vagrantup.com/centos/boxes/7)。

它还列出了可以在其下进行配置的提供者。VirtualBox 是其中之一，这意味着它将在我们的安装中工作。

我们需要修改我们的`Vagrantfile`指向这个盒子。从包含您的`Vagrantfile`的文件夹中运行以下命令：

```
$ sed -i 's#config.vm.box = "base"#config.vm.box = "centos/7"#g' Vagrantfile
```

我们刚刚使用了`sed`（一个常用的命令行文本编辑工具，可以在文件中或标准输出中编辑文本）和`-i`选项，以原地修改我们的`Vagrantfile`。现在打开文件将会显示`base`行已更改为指向`centos/7`。

现在，我们可以使用另一个简单的命令配置我们的 VM：

```
$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==> default: Box 'centos/7' could not be found. Attempting to find and install...
 default: Box Provider: virtualbox
 default: Box Version: >= 0
==> default: Loading metadata for box 'centos/7'
 default: URL: https://vagrantcloud.com/centos/7
==> default: Adding box 'centos/7' (v1804.02) for provider: virtualbox
 default: Downloading: https://vagrantcloud.com/centos/boxes/7/versions/1804.02/providers/virtualbox.box
==> default: Successfully added box 'centos/7' (v1804.02) for 'virtualbox'!
<SNIP>
 default: No guest additions were detected on the base box for this VM! Guest
 default: additions are required for forwarded ports, shared folders, host only
 default: networking, and more. If SSH fails on this machine, please install
 default: the guest additions and repackage the box to continue.
 default: 
 default: This is not an error message; everything may continue to work properly,
 default: in which case you may ignore this message.
==> default: Rsyncing folder: /home/adam/Vagrant/ => /vagrant
```

一切顺利的话，您的 VM 镜像将开始从`vagrantcloud`下载，并且您的虚拟机将在 VirtualBox 中启动。

我们甚至可以在 VirtualBox 的主窗口中看到我们的 VM：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/1ba8e1b1-413e-44a9-8c79-18d982f8019d.png)

在设置|网络和端口转发下查看，Vagrant 还自动设置了对 NAT 网络的访问，这与我们手动设置的方式非常相似。

我们还可以使用内置的 Vagrant 快捷方式连接到我们的新 VM：

```
$ vagrant ssh
Last login: Tue Aug  7 09:16:42 2018 from 10.0.2.2
[vagrant@localhost ~]$
```

这意味着我们已经通过四个命令配置和连接到了一个 VM，总结如下：

```
$ vagrant init
$ sed -i 's#config.vm.box = "base"#config.vm.box = "centos/7"#g' Vagrantfile
$ vagrant up
$ vagrant ssh
[vagrant@localhost ~]$
```

我们还可以销毁我们在同一个文件夹中创建的任何 VM，只需使用一个命令运行到我们的`Vagrantfile`：

```
$ vagrant destroy
```

我首先写了关于使用 VirtualBox 手动设置 VM（并且拍摄了所有这些截图），因为习惯于在自动化繁琐的部分之前学习如何手动操作是很好的。这个规则也适用于大多数软件，因为即使花费更长的时间，了解底层工作原理会使以后的故障排除更容易。

# 轶事 - 尝试，尝试，再尝试

在你的职业生涯中，你会发现圣战的概念占主导地位，每一代新技术都有其辩护者和反对者。这在发行版之争中尤为明显，部落派系坚定地捍卫他们选择的操作系统。如果你发现自己需要为公司或项目选择要安装的发行版，考虑一下你在这里读到的一切，并在盲目接受一个人的意见之前自己做些调查。

这并不是说你应该成为一个部落人——我曾经安装过所有前面提到的发行版，其中第一个是 Ubuntu。

回到 2005 年，我了解到了一个叫做 Linux 的东西。

在那之前，我一直都在用 Mac，因为那是我爸爸决定的品牌。我还拼凑了一台 Windows 机器，专门用来玩暗黑破坏神，尽管我不能说我喜欢使用这个操作系统本身。

一切都改变了，当我在度假时看到一本计算机杂志，翻阅各种页面，直到我看到一篇关于 Linux 的文章，这立刻吸引了我的想象力。不同和古怪的东西吸引了我叛逆的态度，结果我最终刻录了一个叫做 Ubuntu 的东西到一张 CD 上（或者说是几张）。

当时，Canonical 会免费向你发送 Ubuntu 的 CD，但我很不耐烦，刻录光盘更快。

我在电脑上备份了我关心的一切，然后开始逐步完成我的第一次安装，一旦我弄清楚了如何从 CD 启动。据说一切都进行得很顺利，尽管我不得不偶尔跑到另一台电脑上（记住没有智能手机）查找某些选项的含义，但最终我安装了一个全新的桌面操作系统。

麻烦是从那时开始的。

我的无线网卡不工作，图形看起来很卡，我只运行了一个更新，然后重启，结果我不是进入了桌面，而是进入了一个命令行界面。

我以前从未见过命令行界面。

直到今天，我仍然不知道我是如何设法在那台电脑上安装了一个功能正常的操作系统的，我一直在与一个叫做`NdisWrapper`的程序作斗争，以使我的无线网卡工作，或者安装专有（尽管当时我不知道这个词）的图形驱动程序，但只要你升级了内核，它们就会崩溃（尽管当时我不知道发生了什么）。

我以某种方式艰难前行，很快对 Ubuntu 感到厌倦，当我发现了不同的发行版，并在接下来的几个月里每周尝试不同的桌面。我清楚地记得在 Ubuntu、Debian、Fedora、OpenSUSE 以及一个非常早期的尝试安装 Gentoo 之间切换，大约五分钟后我放弃了。

我经常上论坛，费力地将错误复制到谷歌上，试图找到其他遇到我所经历问题的人，经常发现一个帖子，帖子的作者不情愿地宣布他们已经**解决了！**，却没有提供他们使用的解决方案。

尽管当时对我来说很烦人，但这一切都是一次学习经历，我认为我对 Linux 和计算机的热爱可以追溯到我第一次安装 Ubuntu 的时候。在那之前，计算机只是游戏机而已。

很快，我开始使用 Linux Mint 绕过学校的防火墙，启动一个 Live USB 驱动器，并无视学校 IT 部门启用的所有微弱尝试阻止（出于某种原因，他们认为 Windows 是唯一存在的操作系统）。我仍然不太明白这是如何运作的，但重点是它确实运作了。

在玩魔兽世界的空隙中，Linux 是我多年来摆弄的东西，我一直关注最新的发行版并安装其他发行版进行尝试（经常“跳槽”）。我破坏了东西，修复了它们，对 Linux 感到愤怒，对计算机感到愤怒，但总的来说，我慢慢地进步了。

再往前走一小段时间，由于学校成绩普遍不好，我没有完成大学，也没有上大学。我几乎没有什么资格，但在计算机方面还是有一些天赋。我找到了一个持续几个月的课程，获得了一些微软的认证，但最终意味着我有了一个简陋的简历，可以开始向公司提交申请。

我接到了曼彻斯特一家托管提供商的电话，去参加了一次面试，见到了现在的首席技术官。面试很奇怪，我们讨论了拆解计算机、一点 Linux，还有很多《反恐精英》，结果他过去玩过很多。我离开时感到紧张，但对面试的进展感到相当好笑。

回来后，被召回参加面试，我非常惊讶地被提供了数据中心工程师的工作，虽然不是一个以 Linux 为重点的职位，但考虑到我的教育水平，这已经超出了我的期望。能够就业让我感到非常幸福，我永远感激那家公司和面试官给了我一个机会。

我想要传达的观点是，Linux 相当不错 - 即使我们中最没有学术素养的人也可以在这个领域有一个体面的职业，而且它是如此充满活力和不断发展，总是有新东西可以学习。在我的旅程中，我遇到了一些很棒的人，学到了一些很有趣的东西，其中很多我希望在这些页面中传递下去。

希望你会发现这本书的其余部分有益，无论你是 Linux 管理的新手，还是有经验的人只是在寻找你可能不知道的技巧和窍门。


# 第二章：使用 SSH 进行远程管理

本章将涵盖以下配方：

+   使用 ssh-keygen 生成和使用密钥对

+   SSH 客户端参数和选项

+   使用客户端端 SSH 配置文件

+   修改服务器端 SSH 配置文件

+   旋转主机密钥和更新`known_hosts`

+   使用本地转发

+   使用远程转发

+   ProxyJump 和堡垒主机

+   使用 SSH 创建 SOCKS 代理

+   理解和使用 SSH 代理

+   在一台主机上运行多个 SSH 服务器

# 介绍

在第一章中，我们使用了一个命令连接到我们的虚拟机：

```
$ ssh adam@127.0.0.1 -p2222
adam@127.0.0.1's password: 
Last login: Mon Aug 6 17:04:31 2018 from gateway
[adam@localhost ~]$
```

在本章中，我们将扩展这一点，探讨使用 SSH 密钥对使连接更容易；介绍 SSH 的安全优势；对客户端和服务器端配置进行更改；设置端口转发和反向端口转发连接；学习 ProxyJump 和堡垒主机的设置，以及使用 SSH 设置临时代理；最后，我们将研究 SSH 代理并在我们的虚拟机上设置额外的 SSH 服务器。

本章假定您对 SSH 有基本的了解。

# 技术要求

正如在第一章中介绍的，我们将在本章和以后的所有工作中使用 Vagrant 和 VirtualBox。这使我们能够快速配置基础设施进行测试，并节省了您每次创建多个虚拟机的手动工作。

如果您真的不想使用 VirtualBox 或 Vagrant，那么您不必使用，我已经尽量使示例尽可能通用，但如果您使用它会更容易一些。

我已经准备了以下`Vagrantfile`供本章使用：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

$provisionScript = <<-SCRIPT
sed -i 's#PasswordAuthentication no#PasswordAuthentication yes#g' /etc/ssh/sshd_config
systemctl restart sshd
SCRIPT

Vagrant.configure("2") do |config|
 config.vm.provision "shell",
 inline: $provisionScript

 config.vm.define "centos1" do |centos1|
   centos1.vm.box = "centos/7"
   centos1.vm.network "private_network", ip: "192.168.33.10"
   centos1.vm.hostname = "centos1"
   centos1.vm.box_version = "1804.02"
 end

 config.vm.define "centos2" do |centos2|
   centos2.vm.box = "centos/7"
   centos2.vm.network "private_network", ip: "192.168.33.11"
   centos2.vm.hostname = "centos2"
   centos2.vm.box_version = "1804.02"
 end

 config.vm.define "centos3" do |centos3|
   centos3.vm.box = "centos/7"
   centos3.vm.network "private_network", ip: "192.168.33.12"
   centos3.vm.hostname = "centos3"
   centos3.vm.box_version = "1804.02"
 end
end
```

关于这个`Vagrantfile`有一些新的东西。我们在文件顶部包含了一个 provision 步骤，该步骤运行分配给变量的代码。在这种情况下，我们对默认的 CentOS 镜像的 SSH 配置进行了一些更改，以便我们的示例按照我们的期望工作。我们将所有三个虚拟机放在它们自己的私有网络上。

建议创建一个名为`第二章`的文件夹，并将此代码复制到名为`Vagrantfile`的文件中，或者如果您正在使用 GitHub 上的代码，则导航到正确的文件夹。

从包含您的`Vagrantfile`的文件夹中运行`vagrant up`应该配置两个虚拟机进行测试。

一旦配置完成，请确保您可以通过运行以下命令连接到第一个：

```
$ vagrant ssh centos1
```

Vagrant 非常适合测试，但不应在生产环境中用于部署机器。一些决定是为了方便使用（比如我们镜像中的默认`vagrant`用户），因此并不是安全部署的最佳实践。

# 使用 ssh-keygen 生成和使用密钥对

密码很棒，但也很糟糕。

大多数人使用弱密码，虽然我希望您不是其中之一，但是您团队中总有可能有人没有您的纪律，而是使用类似`football99`的密码连接到您共享的远程主机。

启用密码访问后，任何人都可能通过暴力破解的方式从任何国家连接到您的服务器，只要有足够的时间和足够的处理能力。

我说“可能”是因为只要您使用安全密码并且长度足够长，即使在太阳的力量下，密码也很难被猜到。在决定这些事情时，请参考您公司的安全政策，或者在编写自己的政策时了解最佳实践。

这就是密钥的用武之地。

SSH 密钥基于公钥加密的概念。它们由两部分组成：`公共`部分和`私有`部分，其中的公共部分可以放在服务器上，而私有部分则由您保管，可以放在您的笔记本电脑上，或者可能是一个安全的 USB 存储设备（本身已加密并受密码保护）。

尽管公共和私有一半的概念很明显，但我经常看到人们误解这个概念，分享他们的私有一半而不是公共一半。这通常会导致密钥被标记为受损，并要求相关人员生成一个新的密钥对，并在此期间简要讨论“私有”和“公共”的定义。

一旦您的密钥的公共一半在服务器上，您就可以使用密钥的本地私有一半进行身份验证，从而 SSH 到远程主机。

SSH 密钥甚至可以提供一定程度的便利，因为大多数操作系统都配备了某种类型的钥匙链，可以在用户登录时自动解锁，并且安全地存储了密钥的私有部分。然后，通过 SSH 连接到一台机器变得非常简单，您可以在不被提示的情况下安全连接！

我们将生成一个 SSH 密钥对，并使用该对在我们的机器之间进行 SSH。

# 准备工作

首先确保您已经配置了两个 VM，并在它们之间建立了一个私有网络。

您可以使用*技术要求*部分的`Vagrantfile`来完成此操作。

连接到您的第一台机器：

```
$ vagrant ssh centos1
```

使用`ip a`命令从第一章 *介绍和环境设置*检查`centos1`的 IP 地址是否正确配置。

我们期望它是`192.168.33.10`，在`eth1`设备下：

```
[vagrant@centos1 ~]$ ip a
<SNIP>
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
 link/ether 08:00:27:ac:f2:12 brd ff:ff:ff:ff:ff:ff
 inet 192.168.33.10/24 brd 192.168.33.255 scope global noprefixroute eth1
 valid_lft forever preferred_lft forever
 inet6 fe80::a00:27ff:feac:f212/64 scope link 
 valid_lft forever preferred_lft forever
```

您还可以使用`hostname -I`来获取框的 IP 地址，如下所示，但是您应该注意到您不会得到一个明显的接口标识：

```
$ hostname -I
10.0.2.15 192.168.33.10
```

检查您是否可以从`centos1`内部 ping 通`centos2`的 IP 地址。

我们将第二个 IP 设置为`192.168.33.11`：

```
$ ping 192.168.33.11
PING 192.168.33.11 (192.168.33.11) 56(84) bytes of data.
64 bytes from 192.168.33.11: icmp_seq=1 ttl=64 time=1.17 ms
64 bytes from 192.168.33.11: icmp_seq=2 ttl=64 time=0.997 ms
64 bytes from 192.168.33.11: icmp_seq=3 ttl=64 time=1.18 ms
```

我们的 VM 之间有网络连接！

如果您无法在机器之间进行 ping，请首先检查 VirtualBox 中的网络设置，并使用`vagrant ssh`命令连接到每台机器，以检查分配的 IP 地址。

# 如何做...

我们将逐步介绍如何生成并复制密钥到远程主机，使用两种类型的密钥。

首先，我们将生成一个更传统的**Rivest-Shamir-Adleman**（**RSA**）密钥，然后我们将生成一个更新类型的密钥，即`Ed25519`密钥。

# RSA 示例

首先，我们将生成我们的密钥，确认保存密钥的默认位置，并在提示时提供一个密码：

```
$ ssh-keygen -b 4096 -C "Example RSA Key"
Generating public/private rsa key pair.
Enter file in which to save the key (/home/vagrant/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/vagrant/.ssh/id_rsa.
Your public key has been saved in /home/vagrant/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:hAUNhTqXtfnBOkXMuIpxkvtTkM6NYRYxRbT5QWSVbOk Example RSA Key
The key's randomart image is:
+---[RSA 4096]----+
|      =@*=+o.o   |
|      o++=+ =    |
|     o.=+*.o     |
|    * X.+.+.E    |
|     & *S+..     |
|    o = = .      |
|     . . .       |
|      o          |
|       .         |
+----[SHA256]-----+
```

前面代码中的随机艺术图主要是为了让人们可以通过视觉验证密钥。就我个人而言，我从来没有使用过它（除了在本章稍后的一点，）但您可能会用到。

接下来，我们将把新生成的 RSA 密钥复制到`centos2`，在提示时提供`centos2`的密码：

这些框上`vagrant`用户的默认密码是`vagrant`。

```
$ ssh-copy-id 192.168.33.11
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/vagrant/.ssh/id_rsa.pub"
The authenticity of host '192.168.33.11 (192.168.33.11)' can't be established.
ECDSA key fingerprint is SHA256:LKhW+WOnW2nxKO/PY5UO/ny3GP6hIs3m/ui6uy+Sj2E.
ECDSA key fingerprint is MD5:d5:77:4f:38:88:13:e7:f0:27:01:e2:dc:17:66:ed:46.
Are you sure you want to continue connecting (yes/no)? yes
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
vagrant@192.168.33.11's password: 

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh '192.168.33.11'"
and check to make sure that only the key(s) you wanted were added.
```

最后，我们将检查我们是否可以通过刚刚生成的密钥访问`centos2`。

在需要时，我们将输入生成密钥时设置的密码。

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
[vagrant@centos2 ~]$
```

# Ed25519 示例

与 RSA 示例一样，我们将首先生成一个新的密钥，这次指定类型为'ed25519'。

Ed25519 密钥是基于椭圆曲线的，许多非常聪明的人认为它们比 RSA 提供更高级的安全性。这些密钥本身也要短得多（我们稍后会提到），这意味着如果您必须输入一个密钥，那么工作量要少得多。令人讨厌的是，您不能像 RSA 公钥那样使用 Ed25519 公钥的一半来加密文件，因此存在一些权衡，但这取决于您的需求。

我们将再次接受保存密钥的默认位置，并提供一个密码：

```
[vagrant@centos1 ~]$ ssh-keygen -t ed25519 -C "Example Ed25519 key"
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/vagrant/.ssh/id_ed25519): 
/home/vagrant/.ssh/id_ed25519 already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/vagrant/.ssh/id_ed25519.
Your public key has been saved in /home/vagrant/.ssh/id_ed25519.pub.
The key fingerprint is:
SHA256:nQVR7ZVJMjph093KHB6qLg9Ve87PF4fNnFw8Y5X0kN4 Example Ed25519 key
The key's randomart image is:
+--[ED25519 256]--+
|          o*o+=+=|
|          ..+.B*=|
|           ooB Bo|
|         . +o.B+E|
|        S +.. +==|
|         ..  +.+=|
|        ..    o o|
|        ...    o.|
|         o.     +|
+----[SHA256]-----+
```

我们将复制我们的新密钥到`centos2`。请注意，我们还指定了要复制的文件为`id_ed25519.pub`：

同样，这些框上的默认密码是`vagrant`。

```
[vagrant@centos1 ~]$ ssh-copy-id -i .ssh/id_ed25519.pub 192.168.33.11
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: ".ssh/id_ed25519.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
vagrant@192.168.33.11's password: 

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh '192.168.33.11'"
and check to make sure that only the key(s) you wanted were added
```

如果您在之前的示例之后立即运行此示例，则可能会要求输入 RSA 密钥的密码短语，而不是密码本身。这没问题，这突显了首先尝试基于密钥的身份验证。如果是这种情况，请简单地提供 RSA 密钥的密码短语。

安装完成后，尝试使用私有部分的`Ed25519`密钥连接到`centos2`。

```
[vagrant@centos1 ~]$ ssh 192.168.33.11 -i .ssh/id_ed25519
Enter passphrase for key '.ssh/id_ed25519': 
Last login: Wed Aug  8 10:06:33 2018 from 192.168.33.10
[vagrant@centos2 ~]$
```

# 它是如何工作的...

异步密钥和公钥加密的原则可能让人们难以理解。在大多数情况下，您不需要担心密钥生成的数学问题——您只需要知道您最终会得到两个密钥，一个公钥和一个私钥。

Dimble 是一个完全虚构的工程师，他认为在名为`my stuff`的存储库中将他的`私有`SSH 密钥存储在公共`GitLab`服务器上是一个安全风险，因为他从未拥有过字典，并且认为私有一词意味着“与世界分享”，实际上并非如此。他还禁用了`私有`密钥上的密码短语，因为他不喜欢在他和服务器之间多出一步。不要像 Dimble 一样——保护好您的`私有`密钥。

# 公钥和私钥文件

正如之前暗示的，我们在这里创建了两个文件，其中一个可以自由传递（公共部分），另一个我们在其他地方安全保管（私有部分）。

默认情况下，这些文件位于用户的主目录中，即隐藏的`.ssh`文件夹中：

```
[vagrant@centos1 ~]$ pwd
/home/vagrant
[vagrant@centos1 ~]$ ls -a
.  ..  .bash_history  .bash_logout  .bash_profile  .bashrc  .ssh
[vagrant@centos1 ~]$ ls .ssh
authorized_keys  id_ed25519  id_ed25519.pub  id_rsa  id_rsa.pub  known_host
```

我们的密钥的公共部分以`.pub`结尾，而私有部分没有文件扩展名。

让我们来看看这四个文件：

```
[vagrant@centos1 ~]$ cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9AFF0BD949B955DA3595262BB18E5BF7

n1K6zUfhIynq9dwRMAGlMuTU/7Ht3KgBuelsWy3mxJM+NxprFkhAV2cyEVhnJI+5
xgDkx7+6PcGVv/oQAH3pSICefZSJvHvnFLO+M7HKkcmdz9IYXlQC1gkeZwhS6708
<SNIP>
wTXVajpn0anc3TWDw78sZkLmoP5MEs14gJvyegmyLd8qAGvSmfXYNFgYh49hnX9E
vdAmtTJPqglcw0F1JVCOEevIWA/WoIkkTAgLuKvka5ZepKKnScwnRiAhKTVXCN3W
-----END RSA PRIVATE KEY-----
```

我们的 RSA 密钥的私有部分是一个敏感的文件，当我们生成它时，我们将其设为`4096`位，因此这个文件会非常长（因此我剪辑了一部分）。

我们的 RSA 密钥的公共部分是放在远程机器上的文件。尽管受到我们指定的位长度的影响，但它远没有私有部分那么长。

```
[vagrant@centos1 ~]$ cat .ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCwR6+SAohzU9f1SAha634StlJaBGIZ+k5Rb6T6L4VqxHIfRwCV+uciXbkTg8+lxiP8whGYEiDxfPveqW1xf87JYlWTT3ZT3gd3pfxY1+IgRB7j5Ttd2RBCMeMYB9VJWLqib6K9oeHJyGzM39aJqE2AzxKxc+rXeXT16RlFxs7nDZwS9xV7Dai9LB/Jez0pT8pLFVD/QRsGw0uMjMMSjmKqxPrDpHzZ3OUymB5AdyVfts4JTZINSrWdejPR8G93pzH4S8ZYijhgpOnSuoyGhMnwAjwOJyNkkFOT1rKCuzpW33hr2c1pJSBPZTAx2/ZvB1He2/UweBF2VeQpSruQB7tXkQMeXSQBpe+/zMqOLD82vake3M8mqNpFJoVG3afr9RcCXtqn7cF3fDEqj7nNk0Em6/9akO2/tK5KInWhyOjKdV41ntB6IVPGJWOUBmnvf9HVpOMa8rxeb3KpBqnn6z70rjMTKqHmAQ5BeCuVSezTl4xAUP940PbkHSm0mDeWYMi2AgbofKDGBmH/GGUn3QeahhiLTXGzbIHszbXJdJ5dn30oWAPovW/gc0CeeHgUV7IwJ6wxVIz8jYKpjtDtIPYDs+RJMrWo8qPnhHWxA6HVp42eUylh7eazPUzitfZ2SBQHe3ShbBHTh2wHcLcRoVgSMrMJmfQ7Ibad5ZiWepobJw== Example RSA Key
```

请注意，我们在末尾还有一个注释，`示例 RSA 密钥`，这是我们在生成时指定的。当没有显式传递注释时，这通常是生成它的用户和机器主机名。

```
[vagrant@centos1 ~]$ cat .ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABCV2EFqnw
9/2J52LIVBzp50AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEGnqP8zTx50SwjP
+Fe26RdDx2W3/TQ+0ET8ylxfFB+aAAAAoJUzLk7IAaszO2npeAJIgfYmsqWCcgTM+EfF15
3A1iw4PruO+q8b3BxAjFZGK0tjFTSm3rkKtM9+JYTxOI+CSnEyqPnjnCjPODa7aF/X8GBt
RNkSKBlM7aROwpon0Z8UXH+Js8uyNOsKto+DS+BfVSKvshkQ6bNF/5DlU0fQcnRaYnVdyl
mIJUaPLdl/vKLwF+S4OyU87n8rac0ezjfAOhk=
-----END OPENSSH PRIVATE KEY-----
```

然后，我们有我们的私有（敏感的）`Ed25519`密钥。请注意，这个文件比其 RSA 对应文件要短得多，这是因为`Ed25519`密钥具有固定长度（这也意味着在生成时忽略了`-b`标志）。

```
[vagrant@centos1 ~]$ cat .ssh/id_ed25519.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGnqP8zTx50SwjP+Fe26RdDx2W3/TQ+0ET8ylxfFB+a Example Ed25519 key
```

在这里，我们有我们的公共`Ed25519`文件，它非常短，您可以想象将其写在一张纸上，然后递给您的同事复制到服务器上（尽管他们真的不会感谢您，并且很可能不会很快为您泡一杯茶）。

我们还有我们的注释，`示例 Ed25519 密钥`。

显然，打印我刚刚生成的密钥的私有部分与我关于传递私有密钥的说法相矛盾，尽管这是为了文档目的，我将在完成后销毁这些虚拟机，所以我觉得在这里添加它们是很重要的。请不要使用这些密钥。

# authorized_keys 文件

当您连接到远程主机时，SSH 会验证您提供的密钥 ID 是否在`authorized_keys`列表中。

在我们的示例中，我们使用`ssh-copy-id`命令将我们的密钥放在远程服务器上。实际上，这是将其放在您要连接的主目录用户的特定文件中。

在我们的`centos2`主机上，我们可以在用户的主目录下的`.ssh`文件夹中找到这个文件：

```
[vagrant@centos2 ~]$ pwd
/home/vagrant
[vagrant@centos2 ~]$ ls .ssh/
authorized_keys
```

查看此文件的内容会显示如下内容：

```
[vagrant@centos2 ~]$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNkm9JCaRa/5gunzDZ8xO2/xwRvUx03pITH6f4aYziY/j+7o39XnmNyLRVpvh16u9W75ANJeFpBD7lkevluvaFVRQnZGAhuIdGqLHBlGDnVzkzcQGUFc/fcAc9rDAFGa0h7+BF18P0jpOMXfHQu8+7+cBjJ6cW+ztKerG2ali/JLtSHFirXaVTkOKYkwYVfK7z7nmdMsSzgEOsfg5XrylI+ufhGdgWCKtweHsBeAVWjBBbvNaIwgdRVpB1YmLkLgLN7NxRs53OuejwArLS6tvNS+ZBDiSX+was9gErrhGhZ1mdiOMbd3/oTfFEcOiRNOv/+7Tk4P8fJbnO1dzM8Gid vagrant
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCwR6+SAohzU9f1SAha634StlJaBGIZ+k5Rb6T6L4VqxHIfRwCV+uciXbkTg8+lxiP8whGYEiDxfPveqW1xf87JYlWTT3ZT3gd3pfxY1+IgRB7j5Ttd2RBCMeMYB9VJWLqib6K9oeHJyGzM39aJqE2AzxKxc+rXeXT16RlFxs7nDZwS9xV7Dai9LB/Jez0pT8pLFVD/QRsGw0uMjMMSjmKqxPrDpHzZ3OUymB5AdyVfts4JTZINSrWdejPR8G93pzH4S8ZYijhgpOnSuoyGhMnwAjwOJyNkkFOT1rKCuzpW33hr2c1pJSBPZTAx2/ZvB1He2/UweBF2VeQpSruQB7tXkQMeXSQBpe+/zMqOLD82vake3M8mqNpFJoVG3afr9RcCXtqn7cF3fDEqj7nNk0Em6/9akO2/tK5KInWhyOjKdV41ntB6IVPGJWOUBmnvf9HVpOMa8rxeb3KpBqnn6z70rjMTKqHmAQ5BeCuVSezTl4xAUP940PbkHSm0mDeWYMi2AgbofKDGBmH/GGUn3QeahhiLTXGzbIHszbXJdJ5dn30oWAPovW/gc0CeeHgUV7IwJ6wxVIz8jYKpjtDtIPYDs+RJMrWo8qPnhHWxA6HVp42eUylh7eazPUzitfZ2SBQHe3ShbBHTh2wHcLcRoVgSMrMJmfQ7Ibad5ZiWepobJw== Example RSA Key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGnqP8zTx50SwjP+Fe26RdDx2W3/TQ+0ET8ylxfFB+a Example Ed25519 key
```

在这里，我们可以看到三个密钥，分布在三行上。

第一个密钥如下：

```
[vagrant@centos2 ~]$ cat .ssh/authorized_keys | head -n1
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNkm9JCaRa/5gunzDZ8xO2/xwRvUx03pITH6f4aYziY/j+7o39XnmNyLRVpvh16u9W75ANJeFpBD7lkevluvaFVRQnZGAhuIdGqLHBlGDnVzkzcQGUFc/fcAc9rDAFGa0h7+BF18P0jpOMXfHQu8+7+cBjJ6cW+ztKerG2ali/JLtSHFirXaVTkOKYkwYVfK7z7nmdMsSzgEOsfg5XrylI+ufhGdgWCKtweHsBeAVWjBBbvNaIwgdRVpB1YmLkLgLN7NxRs53OuejwArLS6tvNS+ZBDiSX+was9gErrhGhZ1mdiOMbd3/oTfFEcOiRNOv/+7Tk4P8fJbnO1dzM8Gid vagrant
```

这是 Vagrant 用来连接虚拟机的密钥。这不是我们创建的密钥。

第二个密钥如下：

```
[vagrant@centos2 ~]$ cat .ssh/authorized_keys | head -n2 | tail -n1
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCwR6+SAohzU9f1SAha634StlJaBGIZ+k5Rb6T6L4VqxHIfRwCV+uciXbkTg8+lxiP8whGYEiDxfPveqW1xf87JYlWTT3ZT3gd3pfxY1+IgRB7j5Ttd2RBCMeMYB9VJWLqib6K9oeHJyGzM39aJqE2AzxKxc+rXeXT16RlFxs7nDZwS9xV7Dai9LB/Jez0pT8pLFVD/QRsGw0uMjMMSjmKqxPrDpHzZ3OUymB5AdyVfts4JTZINSrWdejPR8G93pzH4S8ZYijhgpOnSuoyGhMnwAjwOJyNkkFOT1rKCuzpW33hr2c1pJSBPZTAx2/ZvB1He2/UweBF2VeQpSruQB7tXkQMeXSQBpe+/zMqOLD82vake3M8mqNpFJoVG3afr9RcCXtqn7cF3fDEqj7nNk0Em6/9akO2/tK5KInWhyOjKdV41ntB6IVPGJWOUBmnvf9HVpOMa8rxeb3KpBqnn6z70rjMTKqHmAQ5BeCuVSezTl4xAUP940PbkHSm0mDeWYMi2AgbofKDGBmH/GGUn3QeahhiLTXGzbIHszbXJdJ5dn30oWAPovW/gc0CeeHgUV7IwJ6wxVIz8jYKpjtDtIPYDs+RJMrWo8qPnhHWxA6HVp42eUylh7eazPUzitfZ2SBQHe3ShbBHTh2wHcLcRoVgSMrMJmfQ7Ibad5ZiWepobJw== Example RSA Key
```

这是我们生成的 RSA 密钥。请注意，由于我们指定了自定义的`4096`位长度，它比 Vagrant 默认值要长。

我们的第三个密钥如下：

```
[vagrant@centos2 ~]$ cat .ssh/authorized_keys | tail -n1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEGnqP8zTx50SwjP+Fe26RdDx2W3/TQ+0ET8ylxfFB+a Example Ed25519 key
```

这是我们的`Ed25519`密钥。

如果你愿意的话，你可以手动将公钥复制到你要连接的主机上的`authorized_keys`文件中。我们使用的`ssh-copy-id`命令只是一种方便的方式，可以省略一些额外的步骤。

# 还有更多...

SSH 对其文件的**权限**非常敏感。

你不希望你的私钥可以被任何可能在你的系统上的随机用户读取，因此，如果它认为你设置了错误的权限，普通的 SSH 就不会起作用。

一般来说，如果你刚刚生成了你的密钥，这不会是一个问题，但是如果你以后将它们移动到其他计算机上，你可能会发现你稍微破坏了权限。

一个很好的经验法则是假设设置是锁定的：

```
[vagrant@centos1 ~]$ ls -lha .ssh/
total 28K
drwx------. 2 vagrant vagrant  134 Aug  8 14:05 .
drwx------. 3 vagrant vagrant   95 Aug  8 10:29 ..
-rw-------. 1 vagrant vagrant  389 Aug  7 16:40 authorized_keys
-rw-------. 1 vagrant vagrant  464 Aug  8 10:04 id_ed25519
-rw-r--r--. 1 vagrant vagrant  101 Aug  8 10:04 id_ed25519.pub
-rw-------. 1 vagrant vagrant 3.3K Aug  8 11:15 id_rsa
-rw-r--r--. 1 vagrant vagrant  741 Aug  7 16:43 id_rsa.pub
-rw-r--r--. 1 vagrant vagrant  535 Aug  8 11:39 known_hosts
```

在上面的命令中，我们可以看到密钥的公共部分和私有部分（id_rsa 密钥和 id_ed25519 密钥）具有不同的值。

密钥的公共部分（`*.pub`）的值为`644`（读/写，读，读）：

```
-rw-r--r--.
```

密钥的私有部分的值为 600（读/写，无，无）：

```
-rw-------.
```

# 是否需要密码

虽然你可以生成一个没有密码的密钥，并且有一些有效的用例（例如，在自动部署的情况下），但是最好的做法是生成一个带有密码的密钥。

这意味着如果你的密钥没有在你的钥匙链中解锁（当你登录到你的机器时，它本身可能已经解锁），你将被提示输入密码来解锁密钥。你可能认为这很麻烦，但从安全的角度来看（多层安全...这不是一个很好的类比，除非安全让你哭泣。）如果你丢失了你的私钥，那么捡起它的恶意人士将无法使用它来访问你的东西。

如果你丢失了私钥，或者把它留在了公共汽车上的 U 盘上，你应该立即通过撤销安装了公钥的任何位置来旋转你的密钥，并生成一个新的密钥对来使用。

# 附加标志

当我们生成我们的密钥时，我们还添加了一些标志。

与任何软件一样，查看你运行的命令的手册页面可能会提供一些额外的细节，有时可能会有点压倒性：

```
$ man ssh-keygen
```

为了节省一点麻烦，我将重点介绍一些可能对你有兴趣的选项，首先是`-b`：

```
-b bits
```

我们使用`-b`标志在生成 RSA 密钥时指定了大量的位数。最小值是`1024`，默认值是`2048`。你的公司可能对 RSA 密钥的长度有要求。

接下来，我们有评论标志：

```
-C comment
```

我们用这个来为我们的密钥添加一些描述。如果你为不同的事情使用不同的密钥（这是我的`GitLab`密钥，这是我的个人服务器密钥，这是我的公司服务器密钥，等等），这可能会很有用。

如果你需要多个密钥，你可能希望在生成命令中传递你的新密钥的名称（而不是在提示时输入）：

```
-f filename
```

我们还有`-l`来打印密钥的指纹，或者如果你愿意的话，打印 ASCII 艺术。这对于验证密钥对非常有用：

```
-l (or -lv for a pretty picture)
```

如果你想要更改私钥的密码，但又不想生成新的密钥，你可以使用`-p`选项：

```
-p
```

要指定要生成的密钥类型，可以使用`-t`选项：

```
-t dsa | ecdsa | ed25519 | rsa
```

在选择要生成的密钥类型时，请考虑你的要求。RSA 通常是最兼容的，但你的公司可能有其他政策，或者你可能有个人偏好。

我遇到过两种情况，`Ed25519`密钥无法使用——一种是需要 RSA 加密文件的内部脚本，另一种是当时的 OpenStack。

最后，还有老式的`-v`，自从早期就提供详细的输出：

```
-v
```

这可以多次传递，也就是说，`-vvv`也是有效的，每个`v`都会增加调试级别。

# 另请参阅

本节故意不涉及 SSH 密钥交换的细节或密钥的不同类型（例外是我们示例中使用的两种类型）。有关 SSH 的优秀书籍可以提供丰富的信息，OpenSSH 开发人员自己也在不断改进软件。OpenSSH 只是 SSH 的一个实现，但它是迄今为止最受欢迎的。它是我使用的每个 Linux 发行版的默认值，在 macOS 上使用，并且是 BSD（特别是 OpenBSD，在那里开发它）的标准。

# SSH 客户端参数和选项

正如我们已经讨论过的那样，SSH 是一款功能强大的软件，虽然它可以以非常简单的方式用于启用对服务器的访问，但它也非常灵活。

在本节中，我们将看一下在可能具有不同要求的环境中与 SSH 一起使用的常见标志。

我们将使用与之前相同的 Vagrant 框。

# 准备就绪

与前一节一样，确认您的两个 Vagrant 框都已启用，并使用`vagrant`命令连接到第一个：

```
$ vagrant ssh centos1
```

# 如何做到这一点...

我们首先要了解 SSH 的基础知识。

# 使用主机名而不是 IP 的 SSH

到目前为止，我们一直在使用 IP 地址连接到远程主机。

SSH 还能够连接到主机名。

首先，我们必须创建一个快速的主机条目，以便我们可以将我们的名称解析为 IP 地址：

```
[vagrant@centos1 ~]$ echo "192.168.33.11 centos2" | sudo tee -a /etc/hosts
```

上面的代码是使远程主机可解析为名称的快速方法。不能保证它会在某些系统上保持，特别是在第三方控制`hosts`文件的系统上。在实际情况下，您很可能会有某种 DNS 设置，使连接到主机名更容易。

现在我们应该能够使用主机名进行 SSH：

```
[vagrant@centos1 ~]$ ssh centos2
The authenticity of host 'centos2 (192.168.33.11)' can't be established.
ECDSA key fingerprint is SHA256:LKhW+WOnW2nxKO/PY5UO/ny3GP6hIs3m/ui6uy+Sj2E.
ECDSA key fingerprint is MD5:d5:77:4f:38:88:13:e7:f0:27:01:e2:dc:17:66:ed:46.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'centos2' (ECDSA) to the list of known hosts.
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
Last login: Wed Aug 8 11:28:59 2018 from fe80::a00:27ff:fe2a:1652%eth1
[vagrant@centos2 ~]$
```

请注意，我们再次不得不接受我们要连接的主机的指纹。

# SSH 到不同的用户

如果您要连接的用户与您在本地使用的用户不同（在我们的示例中，它总是`vagrant`和`vagrant`），那么您可以在命令行上手动指定用户名。

这样做的第一种方法是使用以下语法：

```
[vagrant@centos1 ~]$ ssh vagrant@centos2
```

第二种方法是使用一个标志：

```
[vagrant@centos1 ~]$ ssh centos2 -l vagrant
```

# SSH 到不同的端口

如果您要连接的 SSH 服务器正在侦听不同的端口（这是相当常见的），那么您可能需要指定相关端口。

默认值是`22`，但是如果出于某种原因更改了这个值，您也可以指定新端口，例如`2020`：

```
[vagrant@centos1 ~]$ ssh centos2 -p2020
```

请注意，此示例现在无法正常工作，因为我们尚未更改服务器正在侦听的端口。

# SSH 到 IPv6 地址

IPv6 地址看起来比它们实际上更为严峻，建议您尽早熟悉它们（即使人们已经预测了 IPv6 的主导地位已经超过十年了）。

对于此示例，我们将查找`centos2`的 IPv6 地址并连接到该地址。

首先，连接到`centos2`并运行`ip a`命令：

```
[vagrant@centos2 ~]$ ip a
<SNIP>
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:56:c5:a7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.33.11/24 brd 192.168.33.255 scope global noprefixroute eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe56:c5a7/64 scope link 
       valid_lft forever preferred_lft forever
```

我在上面的代码中突出显示了 IPv6 地址。

回到`centos1`，让我们使用 IPv6 连接：

```
[vagrant@centos1 ~]$ ssh fe80::a00:27ff:fe56:c5a7%eth1
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
Last login: Wed Aug  8 11:44:34 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

请注意，我们不得不在命令的末尾指定网络接口。这只在链路本地地址的情况下才是必要的，对于全局 IPv6 地址则不必要。

在 IPv6 世界中与链路本地地址进行比较的是 IPv4 世界中的子网，也就是说，链路本地设备是可以通过它们的链路本地地址在本地网络上看到彼此的设备（这些地址本身是基于诸如地址所在接口的 MAC 地址等因素生成的）。它们应该始终具有链路本地前缀（`FE80::/10`）。

# 在运行命令之前进行 SSH

虽然您大多数时候会使用 SSH 连接到远程框，但也可以在远程主机上运行命令，而无需在那里逗留。

在这里，我们正在运行一个命令来打印远程主机上的主机名文件，同时保持在`centos1`上：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11 "cat /etc/hostname"
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
centos2
[vagrant@centos1 ~]$ 
```

这对于自动化软件或您想在本地运行但与远程机器交互的脚本特别有用。

# SSH 和 X11 转发

现在一般不再使用，但在某些特定情况下仍然有用，`X11`转发是在远程主机上运行程序，并在本地机器上显示该程序的行为。

您可以使用以下命令设置您的会话：

```
[vagrant@centos1 ~]$ ssh centos2 -X
```

使用`X11`转发存在安全隐患。请查阅您发行版的手册页面，了解相关信息，因为默认行为可能因发行版而异。

目前，这只有在`X`窗口管理器设置中才可能，并且更现代的 Wayland 显示服务器协议没有类似的功能，部分原因是希望保持简单。

# 工作原理...

SSH 是一个庞大且功能丰富的程序。当您使用标志来操纵它的行为时，您正在修改默认行为以符合您自己的目的。

与任何命令一样，它们可能很简单：

```
$ ssh 192.168.33.11
```

但它们也可能很复杂：

```
$ ssh -Y -D9999 -J buser@BASTION:22 -L 8888:127.0.0.1:80 myself@centos2 -p4433
```

作为练习，使用 SSH 手册页面，如果需要，看看您能否弄清楚这个命令将实现什么目的。

# 更多信息...

SSH 转义字符是一个重要的额外元素需要注意。

偶尔，您可能连接到一个系统，然后连接超时，导致会话被锁定。

这通常表现为一个不眨眼且无响应的终端。通常无法按下*Ctrl* + *D*退出登录，也无法输入。

您应该按下以下按键：

```
~. 
```

虽然这个键组合官方上标为`~.`，但实际上需要先按下*Enter*键（即换行），所以它经常被写成`\n~`。

这个提示是由一个敏锐的技术编辑提供的！

这是一个波浪符号（在键盘上找到它，通常使用 S*hift*键），后面跟着一个点。

您的会话应该立即断开。

查看 SSH 手册页面以获取更多转义字符。

# 另请参阅

与前一节一样，SSH 选项比我在本章节中列出的要多得多，而且我们还没有涵盖一些在本章节其余部分有自己章节的选项，但在这里我们不会使用很多。

在一个无聊的星期二看一下 SSH 的手册页面。我看过了。

# 使用客户端 SSH 配置文件

虽然能够使用命令行参数来操作 SSH 很好，但也很好不必费心。

如果您每天都在一个系统上工作，将您的典型参数配置到永久基础上可能会有益。这就是客户端 SSH 配置文件的用武之地。

在我们的示例框中，默认的`ssh_config`文件位于`/etc/ssh/`目录中。如果您愿意，可以打开此文件查看，但暂时不要进行任何更改。

# 准备工作

与前一节一样，请确认您的两个 Vagrant 框已启用，并使用`vagrant`命令连接到第一个框：

```
$ vagrant ssh centos1
```

为了为我们的用户配置不同的选项，我们将在我们的主目录中创建一个 SSH 配置文件。

这与我们大多数 SSH 文件放置在同一个位置，`~/.ssh/`。

每当您看到一个`~`字符时，把它想象成**我的主目录**。扩展开来，这个位置是`/home/vagrant/.ssh/`。

创建文件，锁定权限，并在你选择的编辑器中打开它——我将使用`vi`。

一定要称它为`config`：

```
[vagrant@centos1 ~]$ touch ~/.ssh/config
[vagrant@centos1 ~]$ chmod 600 ~/.ssh/config
[vagrant@centos1 ~]$ vi ~/.ssh/config
```

# 操作方法...

在你的`config`文件中，创建四个块的开头。

一个应该是通配符块（使用`*`），另一个应该是`CentOS2`名称的变体（注意大写）：

```
Host * !CentOS2-V6
 IdentityFile ~/.ssh/id_ed25519
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant

Host CentOS2-V6
 Hostname fe80::a00:27ff:fe56:c5a7%%eth1
 IdentityFile ~/.ssh/id_rsa
 Port 22
 User vagrant

Host CentOS2-Hostname
 Hostname centos2
 User vagrant
```

请注意，在 V6 条目中，我们实际上使用了两个百分号，而不是我们在命令行上使用的单个百分号。这是为了避免 SSH 误解我们的意思，并尝试用`%e`值读取该条目。

在这些块中，我们根据之前在命令行上所做的事情设置了一些基本选项。

有了这些设置，我们可以保存并退出我们的配置文件，并尝试连接到我们指定的主机。

首先，我们将连接到我们的另一个 VM 的 IPv4 地址：

```
[vagrant@centos1 ~]$ ssh CentOS2-V4 
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
Last login: Wed Aug  8 13:31:41 2018 from fe80::a00:27ff:fe2a:1652%eth1
[vagrant@centos2 ~]$ 
```

接下来，我们将使用我们的 IPv6 地址：

```
[vagrant@centos1 ~]$ ssh CentOS2-V6
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
Last login: Wed Aug  8 13:34:26 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

最后，我们将解析主机的主机名：

```
[vagrant@centos1 ~]$ ssh CentOS2-Hostname 
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
Last login: Wed Aug  8 13:34:04 2018 from fe80::a00:27ff:fe2a:1652%eth1
[vagrant@centos2 ~]$ 
```

大多数系统还将自动完成 SSH 配置文件中的条目。通过键入`ssh C`并连续按*Tab*三次来自行尝试。

# 它是如何工作的...

从通配符主机条目（`Host *`）开始，这是一个全局条目。此块中的设置将适用于所有主机（除了`CentOS2-V6`，我们很快就会谈到）：

```
Host * !CentOS2-V6
 IdentityFile ~/.ssh/id_ed25519
 Port 22
```

在这里，我们说这个文件中的每个主机都将使用我们的`Ed25519`密钥进行连接，我们将始终在端口`22`上进行连接。这个块应该用于一般的全局设置。如果您愿意，也可以完全省略它：

```
Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant
```

在我们的第一个特定主机块中，我们称之为`CentOS2-V4`，我们指定了主机的 IPv4 地址和要使用的用户。

以详细模式连接到这个条目看起来像这样：

```
[vagrant@centos1 ~]$ ssh -v CentOS2-V4 
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 5: Applying options for CentOS2-V4
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug1: Connecting to 192.168.33.11 [192.168.33.11] port 22.
debug1: Connection established.
debug1: identity file /home/vagrant/.ssh/id_ed25519 type 4
<SNIP>
debug1: rekey after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey after 134217728 blocks
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<rsa-sha2-256,rsa-sha2-512>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-keyex
debug1: No valid Key exchange context
debug1: Next authentication method: gssapi-with-mic
debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: KEYRING:persistent:1000)

debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: KEYRING:persistent:1000)

debug1: Next authentication method: publickey
debug1: Offering ED25519 public key: /home/vagrant/.ssh/id_ed25519
debug1: Server accepts key: pkalg ssh-ed25519 blen 51
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
debug1: Authentication succeeded (publickey).
Authenticated to 192.168.33.11 ([192.168.33.11]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending environment.
debug1: Sending env LANG = en_GB.UTF-8
Last login: Wed Aug  8 13:46:27 2018 from 192.168.33.10
```

在这一堆噪音中，我们可以看到一些关键的东西，为了您的方便而加粗。

首先，我们可以看到 SSH 从我们的配置文件中开始读取配置数据的地方。它应用通配符条目的设置，然后是特定主机的设置。

稍后，我们可以看到在主机通配符块中指定的`Ed25519`密钥的提示。

最后，我们可以看到我们的会话已经经过身份验证，连接到了`192.168.33.11`（或 IPv4 地址）。

如果我们现在看一下`CentOS-V6`块，我们开始看到不同之处：

```
Host CentOS2-V6
 Hostname fe80::a00:27ff:fe56:c5a7%%eth1
 IdentityFile ~/.ssh/id_rsa
 Port 22
 User vagrant
```

再次注意双百分号。

首先，您会注意到我们已经指定了端口和不同的`IdentityFile`条目。这是因为`Host *`块不适用于`CentOS2-V6`，如下所示：

```
Host * !CentOS2-V6
```

这意味着通配符块中的任何设置都不会应用于`CentOS2-V6`。

如果我们以详细模式连接到我们的主机，我们会看到以下内容：

```
[vagrant@centos1 ~]$ ssh -v CentOS2-V6
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Skipping Host block because of negated match for CentOS2-V6
debug1: /home/vagrant/.ssh/config line 9: Applying options for CentOS2-V6
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug1: Connecting to fe80::a00:27ff:fe56:c5a7%eth1 [fe80::a00:27ff:fe56:c5a7%eth1] port 22.
debug1: Connection established.
debug1: identity file /home/vagrant/.ssh/id_rsa type 1
debug1: key_load_public: No such file or directory
<SNIP>
debug1: Next authentication method: publickey
debug1: Offering RSA public key: /home/vagrant/.ssh/id_rsa
debug1: Server accepts key: pkalg rsa-sha2-512 blen 535
Enter passphrase for key '/home/vagrant/.ssh/id_rsa': 
debug1: Authentication succeeded (publickey).
Authenticated to fe80::a00:27ff:fe56:c5a7%eth1 ([fe80::a00:27ff:fe56:c5a7%eth1]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending environment.
debug1: Sending env LANG = en_GB.UTF-8
Last login: Wed Aug  8 13:50:39 2018 from fe80::a00:27ff:fe2a:1652%eth1
```

具体不同的是关于匹配配置的行，这次通知我们通配符块不会应用，因为对`CentOS2-V6`的否定匹配。

我们还可以看到这次使用的是`id_rsa`，而且我们已经明确连接到了主机的 IPv6 地址。

最后，让我们看看`CentOS2-Hostname`：

```
[vagrant@centos1 ~]$ ssh -v CentOS2-Hostname 
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 15: Applying options for CentOS2-Hostname
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug1: Connecting to centos2 [192.168.33.11] port 22.
debug1: Connection established.
debug1: identity file /home/vagrant/.ssh/id_ed25519 type 4
debug1: key_load_public: No such file or directory
debug1: identity file /home/vagrant/.ssh/id_ed25519-cert type -1
debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_7.4
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.4
debug1: match: OpenSSH_7.4 pat OpenSSH* compat 0x04000000
debug1: Authenticating to centos2:22 as 'vagrant'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256
<SNIP>
debug1: Next authentication method: publickey
debug1: Offering ED25519 public key: /home/vagrant/.ssh/id_ed25519
debug1: Server accepts key: pkalg ssh-ed25519 blen 51
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
debug1: Authentication succeeded (publickey).
Authenticated to centos2 ([192.168.33.11]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending environment.
debug1: Sending env LANG = en_GB.UTF-8
Last login: Wed Aug  8 13:55:20 2018 from fe80::a00:27ff:fe2a:1652%eth1
```

再次注意配置的匹配，以及我们连接到 IPv4 地址的事实。

我们可以用这个做更多的事情，即增加我们连接的详细程度，达到下一个调试级别，并希望看到其他值得注意的东西：

```
[vagrant@centos1 ~]$ ssh -vv CentOS2-Hostname 
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 15: Applying options for CentOS2-Hostname
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug2: resolving "centos2" port 22
debug2: ssh_connect_direct: needpriv 0
debug1: Connecting to centos2 [192.168.33.11] port 22.
debug1: Connection established.
```

在这里，我们可以看到第二个调试级别（`debug2`），并且特别地，我们可以看到`centos2`在块中被给出并解析为一个地址的时刻。

# 还有更多...

您可能已经注意到，在我的示例中，我对我的名称使用了大写和小写字符的混合（例如`CentOS2-V4`）。我这样做是因为这意味着我知道我何时在使用我的 SSH 配置文件，并且可以一眼就确定我正在使用我配置的设置。

没有什么能阻止您创建这样的块：

```
Host centos2
 Hostname 192.168.33.11
 User vagrant
```

这是完全有效的，设置将被正常读取。

您还可以做一些聪明的事情，比如特定的域匹配。如果您必须管理通过其域区分的两组不同的服务器，您可以这样做：

```
Host *.examplecake.com
  Port 2222
  User Alie

Host *.examplebiscuit.co.uk
  Port 5252
  User Gingerbread
```

尝试连接到这两个域中的主机将导致使用特定的配置选项：

```
[vagrant@centos1 ~]$ ssh -v potato.examplecake.com
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips 26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 19: Applying options for *.examplecake.com
debug1: Reading configuration data /etc/ssh/ssh_config
```

# 另请参阅

`ssh_config`手册页值得一看，即使您只是用它来入睡。

# 修改服务器端的 SSH 配置文件

在过去的几个部分中，我们一直在关注客户端配置。我们已经在命令行上调整了我们的连接字符串，并且我们已经编写了一个配置文件，当连接到我们的第二个主机时，SSH 会自动读取它。

在这一部分，我们将看一下`sshd_config`文件，或者说是配置探戈的服务器端，我们的第二个主机。

我们将进行一些示例和例行更改，以使您熟悉这个概念。

# 做好准备

连接到`centos1`和`centos2`。最好在外部执行此操作（在单独的窗口中，并使用`vagrant ssh`）：

```
$ vagrant ssh centos1
$ vagrant ssh centos2
```

将您的终端窗口并排放置以便查看。

在本节中，有可能会破坏对服务器的 SSH 访问，这就是为什么我建议您使用 Vagrant 进行测试。如果您犯了一个错误，不要担心-只需销毁您的虚拟机并重新开始。

# 如何做...

在您的`centos2`机器上，用您喜欢的编辑器打开`/etc/ssh/sshd_config`。

这个文件很大，第一次打开它可能会有点令人生畏。

列出的选项是 SSH 服务器（`sshd`）在启动时将读取的大部分设置，并适用于您正在运行的守护程序。

# 更改默认端口

我们将从一个简单的开始，也就是更改 SSH 守护程序运行的默认端口：

```
# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
```

更改前面的代码，使`Port`行取消注释，并且现在读取`2222`：

```
#
Port 2222
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
```

正如这个块之前的便利说明所告诉我们的那样，我们还必须修改 SELinux，以便它知道 SSH 守护程序将尝试使用不同的端口。

这个文件建议我们使用`semanage`，所以让我们这样做。

首先，我们将找到提供 semanage 的软件包：

```
[vagrant@centos2 ~]$ sudo yum whatprovides semanage
Loaded plugins: fastestmirror
Loading mirror speeds from cached hostfile
 * base: mirror.vorboss.net
 * extras: mozart.ee.ic.ac.uk
 * updates: mozart.ee.ic.ac.uk
base/7/x86_64/filelists_db                                                    | 6.9 MB  00:00:01 
extras/7/x86_64/filelists_db                                                  | 588 kB  00:00:00 
updates/7/x86_64/filelists_db                                                 | 2.4 MB  00:00:00 
policycoreutils-python-2.5-22.el7.x86_64 : SELinux policy core python utilities
Repo        : base
Matched from:
Filename    : /usr/sbin/semanage
```

然后，我们将安装它：

```
[vagrant@centos2 ~]$ sudo yum install -y policycoreutils-python
```

最后，我们将使用新端口运行推荐的命令：

```
[vagrant@centos2 ~]$ sudo semanage port -a -t ssh_port_t -p tcp 2222
```

完成后，我们可以安全地重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

这不应该将您从虚拟机中踢出来，因为`sshd`是设计成这样的，即使这些更改会阻止您再次登录（一旦您自愿断开连接）。

现在尝试注销，然后再次登录。

一个预警：这应该失败！

不要害怕！相反，连接到您的第二个终端上的`centos1`（此时您应该已经打开了两个连接到`centos1`），然后像这样重新登录到`centos2`：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11 -p2222
```

恭喜！SSH 现在在不同的端口上运行！

您可以使用以下命令从操作系统内部确认这一点（我们稍后将更详细地介绍）：

```
[vagrant@centos2 ~]$ ss -nl sport = :2222
Netid State      Recv-Q Send-Q   Local Address:Port                  Peer Address:Port 
tcp   LISTEN     0      128                  *:2222                             *:* 
tcp   LISTEN     0      128                 :::2222                            :::*  
```

请注意，在前面的代码中，我们打印了 IPv4 和 IPv6 的值。

# 更改监听地址

默认情况下，SSH 将监听所有地址和接口：

```
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
```

我们将更改这样，它只监听 IPv4 和我们的`eth1`地址。

将前面的选项更改为以下内容：

```
AddressFamily inet
ListenAddress 192.168.33.11
#ListenAddress ::
```

我们已经取消注释了两个选项并更改了它们的值。

在前面的块中，您可能已经注意到`ListenAddress ::`也被列出。在这里，`::`是 IPv6 中`0.0.0.0`的等价物。

重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

运行我们之前的`ss`命令，您可能会注意到 IPv6 选项已经消失：

```
[vagrant@centos2 ~]$ ss -nl sport = :2222
Netid State      Recv-Q Send-Q   Local Address:Port                  Peer Address:Port 
tcp   LISTEN     0      128      192.168.33.11:2222                             *:*      
```

如果我们现在退出到`centos2`的会话（使用*Ctrl* + *D*），然后尝试 SSH 到 IPv6 链路本地地址，它将失败：

```
[vagrant@centos1 ~]$ ssh fe80::a00:27ff:fe56:c5a7%eth1 -p2222
ssh: connect to host fe80::a00:27ff:fe56:c5a7%eth1 port 2222: Connection refused
```

一个巨大的成功-我们已经消除了任何趋势设置者登录到我们的 IPv6 服务器的可能性！

现在，让我们认真地谈一分钟，我听说 IPv4 的消亡和 IPv6 的崛起已经有好几年了，基本上是自从我开始从事计算机工作以来。在这段时间里，几乎没有什么改变，运营商和服务提供商都继续从 IPv4 中获取尽可能多的东西，甚至引入了可怕的事情，比如 Carrier-grade NAT。我真心希望 IPv6 能够蓬勃发展，至少因为我们已经基本用完了 IPv4 地址。

# 更改守护程序日志级别

SSH 可以记录多个级别，由`LogLevel`设置决定：

```
# Logging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
#LogLevel INFO
```

可能性有`QUIET`、`FATAL`、`ERROR`、`INFO`、`VERBOSE`、`DEBUG`、`DEBUG1`、`DEBUG2`和`DEBUG3`。

SSH 守护程序手册将`DEBUG`选项列为违反用户隐私的所有选项，因此不建议您使用它们。

我们将把它提升到`VERBOSE`：

```
# Logging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
LogLevel VERBOSE
```

重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

现在，让我们看看这个改变带来了什么不同。

这是我们在`INFO`级别的`secure`日志：

```
[vagrant@centos2 ~]$ sudo grep "1137" /var/log/secure
Aug  7 16:40:44 localhost sshd[1137]: Accepted publickey for vagrant from 10.0.2.2 port 53114 ssh2: RSA SHA256:1M4RzhMyWuFS/86uPY/ce2prh/dVTHW7iD2RhpquOZA
Aug  7 16:40:45 localhost sshd[1137]: pam_unix(sshd:session): session opened for user vagrant by (uid=0)
```

这是我们在`VERBOSE`级别的`secure`日志：

```
[vagrant@centos2 ~]$ sudo grep "5796" /var/log/secure
Aug  8 15:00:00 localhost sshd[5796]: Connection from 192.168.33.10 port 39258 on 192.168.33.11 port 2222
Aug  8 15:00:00 localhost sshd[5796]: Postponed publickey for vagrant from 192.168.33.10 port 39258 ssh2 [preauth]
Aug  8 15:00:02 localhost sshd[5796]: Accepted publickey for vagrant from 192.168.33.10 port 39258 ssh2: ED25519 SHA256:nQVR7ZVJMjph093KHB6qLg9Ve87PF4fNnFw8Y5X0kN4
Aug  8 15:00:03 localhost sshd[5796]: pam_unix(sshd:session): session opened for user vagrant by (uid=0)
Aug  8 15:00:03 localhost sshd[5796]: User child is on pid 5799
```

# 禁止 root 登录

一些发行版默认禁止 root 登录，这被广泛认为是一个好主意。在这里，我们有一个用户（vagrant），我们可以用来绕过，这样我们就不需要以 root 身份登录。

找到带有`PermitRootLogin`的行：

```
#LoginGraceTime 2m
#PermitRootLogin yes
#StrictModes yes
```

将其更改为`no`：

```
#LoginGraceTime 2m
PermitRootLogin no
#StrictModes yes
```

重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

这并不禁止`local` root 登录，所以在紧急情况下，您仍然可以连接到控制台（或将键盘和鼠标插入物理机器）并在本地使用 root 用户登录。

# 禁用密码（强制使用密钥）

因为我们在这台主机上有公钥，所以不再需要允许基于密码的访问。

找到`PasswordAuthentication`行：

```
#PermitEmptyPasswords no
PasswordAuthentication yes
```

将此行更改为`no`：

```
#PermitEmptyPasswords no
PasswordAuthentication no
```

重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

你们中的敏锐者可能已经注意到，我在本章开头的`Vagrantfile`中已经翻转了这个设置一次。这是为了让我们能够将 Vagrant 用作学习经验，我们现在正在有效地扭转这种逆转。

# 设置每日消息（motd）

只要您的`PrintMotd`设置为`yes`，您就可以让用户在登录时看到`/etc/motd`的内容。

首先，确保在 SSH 守护程序配置中将其设置为`yes`：

```
#PermitTTY yes
PrintMotd yes
#PrintLastLog yes
```

接下来，重新启动 SSH 守护程序，然后修改`/etc/motd`文件为合理的内容。或者，您可以使用以下命令：

```
sudo sh -c 'echo "This is a testing system, how did you get here?" > /etc/motd'
```

现在每次您登录时都会打印此消息。

这个功能通常被公司用来警告试图访问他们系统的不良分子。偶尔，无聊的系统管理员也会用它来引用《飞出个未来》。

# UseDNS 设置

我要讲解的最后一个选项是`UseDNS`条目，因为它是一些人的痛点：

```
#UseDNS yes
UseDNS no
```

在这里，我们可以看到`UseDNS`在我们的配置文件中已被明确设置为`no`。这是默认设置。

当设置为`no`时，SSH 守护程序将不会查找远程主机名，并检查远程 IP 是否映射回预期的 IP，基于该主机名。

为了让您更加困惑，这是`UseDNS`的手动输入：

“指定 sshd(8)是否应查找远程主机名，并检查解析的远程主机名是否映射回到相同的 IP 地址。

如果此选项设置为 no（默认值），则只能在~/.ssh/authorized_keys 和 sshd_config Match Host 指令中使用地址而不是主机名。

这意味着当`UseDNS`设置为`yes`时，您正在连接的机器没有设置反向 DNS 条目，SSH 将尝试将其期望的 IP 与其所看到的 IP 进行匹配，并可能无法这样做。

实际上，这意味着如果您要连接的计算机上的 DNS 出现问题，您必须像柠檬一样等待一段时间，直到 DNS 请求超时，并最终让您进入。更让事情变得更加令人沮丧的是，这个功能在开箱即用时几乎没有用处，正如这封邮件列表邮件中所强调的那样：[`lists.centos.org/pipermail/centos-devel/2016-July/014981.html`](https://lists.centos.org/pipermail/centos-devel/2016-July/014981.html)。

# AllowUsers

我们已经拒绝了 root 用户访问我们的系统，但是如果我们想进一步指定要授予访问权限的用户呢？

为此，我们需要`AllowUsers`设置。

这通常不是默认设置，甚至在`sshd_config`文件中也没有被注释掉，所以我们要将其添加到底部：

```
#       PermitTTY no
#       ForceCommand cvs server
AllowUsers vagrant
```

重新启动 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo systemctl restart sshd
```

现在，您有一个只有`vagrant`用户才能 SSH 到的系统。您还可以将多个名称添加到此列表，甚至用`DenyUsers`替换此白名单为黑名单。

如果我们愿意，我们可以使用`AllowGroups`和`DenyGroups`以组为基础（而不是个人用户名）进行工作。

# 工作原理...

现在，我们已经浏览并更改了一些常见设置，我们将快速查看重新启动 SSH 守护程序时会发生什么。

SSH 的`systemd`单元文件看起来类似于这样，尽管您的系统可能有所不同：

```
[vagrant@centos2 ~]$ cat /etc/systemd/system/multi-user.target.wants/sshd.service 
[Unit]
Description=OpenSSH server daemon
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target sshd-keygen.service
Wants=sshd-keygen.service

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/sshd
ExecStart=/usr/sbin/sshd -D $OPTIONS
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
```

默认情况下，我们可以看到使用的二进制文件是`/usr/sbin/sshd`，并且从其他地方传递了`$OPTIONS`（在这种情况下是`EnvironmentFile`值，如前面所列）。

阅读`sshd`的手册，我们找到了以下部分：

`-f config_file`选项（[`man.openbsd.org/sshd`](https://man.openbsd.org/sshd)）的描述如下：

“指定配置文件的名称。默认值为/etc/ssh/sshd_config。如果没有配置文件，sshd 将拒绝启动。”

在这里，我们得到了为什么`sshd_config`默认被读取的答案——它是内置的。

# 还有更多...

我们只涵盖了一些人们在配置 SSH 守护程序时倾向于更改的基本选项，但大多数管理员根本不费心进行任何更改，而是保留配置的默认值。

# 另请参阅

要更好地了解可用于您的所有守护程序选项，请阅读`sshd_config`手册页面，并查看`sshd`可执行文件的页面。

# 旋转主机密钥和更新 known_hosts

我们还没有提到的一件事是主机密钥和`known_hosts`文件。

这是一个经常被忽视的事情，所以我想花几分钟时间来讨论这些被忽视的宝藏。

在本节中，我们将检查第一次 SSH 到新机器时会发生什么，然后我们将更改该机器的密钥，看看这会给我们带来什么问题。

# 做好准备

在不同的会话中连接到`centos1`和`centos2`：

```
$ vagrant ssh centos1 $ vagrant ssh centos2
```

如果您正在进行新安装，从`centos1` SSH 到`centos2`并在出现时接受主机密钥。

从`centos2`注销：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
The authenticity of host '192.168.33.11 (192.168.33.11)' can't be established.
ECDSA key fingerprint is SHA256:D4Tu/OykM/iPayCZ2okG0D2F6J9H5PzTNUuFzhzl/xw.
ECDSA key fingerprint is MD5:4b:2a:42:77:0e:24:b4:9c:6e:65:69:63:1a:57:e9:4e.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.33.11' (ECDSA) to the list of known hosts.
vagrant@192.168.33.11's password: 
[vagrant@centos2 ~]$ logout
Connection to 192.168.33.11 closed.
[vagrant@centos1 ~]$ 
```

我们现在在我们的`known_hosts`文件中有一个条目，如下所示：

```
[vagrant@centos1 ~]$ cat .ssh/known_hosts 
192.168.33.11 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOK52r7ZJ8hwU34RzaY3AD7HitT6UP2qBv3WK8lWEELSoeTsmJ4+zO8QiuULp3cCQBKYqi55Z60Vf/hsEMBoULg=
```

请注意，在`centos2`上找到了此 IP 和密钥：

```
[vagrant@centos2 ~]$ cat /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOK52r7ZJ8hwU34RzaY3AD7HitT6UP2qBv3WK8lWEELSoeTsmJ4+zO8QiuULp3cCQBKYqi55Z60Vf/hsEMBoULg=
```

我们可以通过在两台机器上查看密钥的指纹并比较 ASCII 图来轻松证明这一点。

在`centos2`上，操作如下：

```
[vagrant@centos2 ~]$ ssh-keygen -lv -f /etc/ssh/ssh_host_ecdsa_key.pub 
256 SHA256:D4Tu/OykM/iPayCZ2okG0D2F6J9H5PzTNUuFzhzl/xw no comment (ECDSA)
+---[ECDSA 256]---+
|   . .       o.  |
|  . . o.    o..  |
| o . =. .  + o.  |
|. o o.+.    B  . |
|.  + +..S. o o E.|
|. + +o. oo. .  .o|
|.+ o +o ...     o|
|o.o . +*         |
|.    o=*=        |
+----[SHA256]-----+
```

从`centos1`的`known_hosts`文件中如下：

```
[vagrant@centos1 ~]$ ssh-keygen -lv -f .ssh/known_hosts 
256 SHA256:D4Tu/OykM/iPayCZ2okG0D2F6J9H5PzTNUuFzhzl/xw 192.168.33.11 (ECDSA)
+---[ECDSA 256]---+
|   . .       o.  |
|  . . o.    o..  |
| o . =. .  + o.  |
|. o o.+.    B  . |
|.  + +..S. o o E.|
|. + +o. oo. .  .o|
|.+ o +o ...     o|
|o.o . +*         |
|.    o=*=        |
+----[SHA256]-----+
```

这真的是我第一次使用`-v`选项来获取密钥的 ASCII 图进行比较。

# 如何操作...

现在我们已经确认了我们的设置，我们将在`centos2`上更改主机密钥，看看会发生什么。

在`centos2`上，运行以下命令：

```
[vagrant@centos2 ~]$ sudo mv /etc/ssh/ssh_host_ecdsa_key* /home/vagrant/
[vagrant@centos2 ~]$ ls
ssh_host_ecdsa_key  ssh_host_ecdsa_key.pub
```

我们刚刚将我们在`centos1`上接受为真理的密钥移动了。

我们的会话保持连接，因为我们已经经过身份验证并连接。如果此时断开连接，我们将不得不接受不同的密钥（我们移动了 ECDSA 密钥，但仍然有`Ed25519`主机密钥可用，SSH 将选择使用它们）。

现在，我们将使用通用的`-A`标志生成一组新的密钥：

```
[vagrant@centos2 ~]$ sudo ssh-keygen -A
ssh-keygen: generating new host keys: RSA1 DSA ECDSA
```

我们可以通过检查目录来确认这些存在：

```
[vagrant@centos2 ~]$ ls -l /etc/ssh/ssh_host_ecdsa_key*
-rw-------. 1 root root 227 Aug  8 16:30 /etc/ssh/ssh_host_ecdsa_key
-rw-r--r--. 1 root root 174 Aug  8 16:30 /etc/ssh/ssh_host_ecdsa_key.pub
```

从`centos2`注销并尝试重新登录：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:vdJTJW4ewGtOAdQXCXJ+cbjvrNm9787/CQQnCeM9fjc.
Please contact your system administrator.
Add correct host key in /home/vagrant/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/vagrant/.ssh/known_hosts:1
ECDSA host key for 192.168.33.11 has changed and you have requested strict checking.
Host key verification failed.
[vagrant@centos1 ~]$
```

SSH 试图阻止您做一些坏事。因为它已经知道您要连接的 IP，并且有一个`known_hosts`条目，它将文件中的已知密钥与盒子上的密钥进行比较。

由于我们刚刚在盒子上重新生成了密钥，我们被呈现了一个看起来很糟糕的错误。

值得克服心理障碍，不要只是嘲笑并绕过这个错误。试着花五秒钟的时间来确认错误是否符合预期。我经常看到人们一遇到这个消息就立刻抱怨并立即绕过它。如果您已经在某个盒子上接受了密钥，那么您不应该再看到有关它的警告，这可能意味着该盒子已被篡改，或者您的连接被“中间人”攻击。要保持警惕！

从我们的`known_hosts`文件中清除旧密钥（在前面的代码中加粗显示了行位置）：

```
[vagrant@centos1 ~]$ ssh-keygen -R 192.168.33.11
# Host 192.168.33.11 found: line 1
/home/vagrant/.ssh/known_hosts updated.
Original contents retained as /home/vagrant/.ssh/known_hosts.olds 
```

现在您应该能够再次 SSH 到`centos2`并接受新密钥：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
The authenticity of host '192.168.33.11 (192.168.33.11)' can't be established.
ECDSA key fingerprint is SHA256:vdJTJW4ewGtOAdQXCXJ+cbjvrNm9787/CQQnCeM9fjc.
ECDSA key fingerprint is MD5:c3:be:16:5b:62:7f:4d:9c:0b:15:c0:cd:d6:87:d6:d6.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.33.11' (ECDSA) to the list of known hosts.
vagrant@192.168.33.11's password: 
Last login: Wed Aug  8 16:26:50 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

# 工作原理...

我们使用的`ssh-keygen`命令是在默认位置放置预期主机密钥的快速方法。因为我们删除了我们期望在那里的密钥，所以我们将无法连接到我们的主机，并且会被提示我们之前看到的可怕错误：

```
<SNIP>
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:zW4PXt4o3VRA/OiePUc4VoxBY50us9vl2vemgcrLduA
debug3: hostkeys_foreach: reading file "/home/vagrant/.ssh/known_hosts"
debug3: record_hostkey: found key type ECDSA in file /home/vagrant/.ssh/known_hosts:1
debug3: load_hostkeys: loaded 1 keys from 192.168.33.11
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
<SNIP>
```

在前面的片段中，我们可以看到 SSH 检查我们的`known_hosts`文件，然后从远程主机获取密钥，最后引发了一场骚动。

要重新连接到主机，我们只需从客户端的`known_hosts`文件中删除有问题的条目，然后再次尝试我们的连接。

我们使用了`-R`来删除有问题的密钥，但您可以使用任何方法来这样做，因为它只是一个文本文件。如果您愿意，甚至可以清空整个`known_hosts`文件，但这也意味着您将不得不再次接受您曾经连接过的每个盒子的密钥。

# 还有更多...

那么，如果您从服务器中删除所有主机密钥会发生什么？

这就是你会得到的：

```
[vagrant@centos2 ~]$ sudo rm /etc/ssh/ssh_host_*
[vagrant@centos2 ~]$ logout
Connection to 192.168.33.11 closed.
[vagrant@centos1 ~]$ ssh  192.168.33.11 
ssh_exchange_identification: read: Connection reset by peer
```

此时，您可以重新配置您的 VM，或者通过控制台登录并生成新的密钥。

# 技术要求

确认您的两个 Vagrant 盒子都已启用，并使用`vagrant`命令连接到两个盒子。

如果您之前更改了 SSH 配置文件，最好先销毁您的盒子并重新配置它们：

```
$ vagrant ssh centos1
$ vagrant ssh centos2
```

# 使用本地转发

本地转发是将本地 TCP 端口或 Unix 套接字映射到远程端口或套接字的行为。当要么安全地访问系统（要求用户首先 SSH 到盒子，从而加密他们的连接），要么用于解决问题时，它通常被使用。

在本节中，我们将在`centos2`上启动一个小的`webserver`，我们将首先通过直接连接到 IP 和端口，然后通过连接到映射的本地端口来从`centos1`连接到它，利用端口转发。

# 做好准备

在`centos2`上运行以下命令：

```
[vagrant@centos2 ~]$ python -m SimpleHTTPServer 8888
Serving HTTP on 0.0.0.0 port 8888 ...
```

您刚刚创建了一个小型的基于 Python 的 Web 服务器，监听端口`8888`上的每个地址。

您可以通过从`centos1`运行`curl`命令来确认这一点：

```
[vagrant@centos1 ~]$ curl 192.168.33.11:8888
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
```

注意从`centos2`列出的主目录内容。

在`centos2`上，您应该看到您的连接（`200`响应）：

```
[vagrant@centos2 ~]$ python -m SimpleHTTPServer 8888
Serving HTTP on 0.0.0.0 port 8888 ...
192.168.33.10 - - [09/Aug/2018 10:47:13] "GET / HTTP/1.1" 200 -
```

Python 的内置 Web 服务器模块非常适用于测试。我在这里使用它是因为它在我们的安装中是开箱即用的，但我不会在生产环境中使用它，因为有更好（更快）的替代品。

要确认我们尚未在端口`9999`上本地监听任何内容，请从`centos1`执行另一个`curl`命令：

```
[vagrant@centos1 ~]$ curl 127.0.0.1:9999
curl: (7) Failed connect to 127.0.0.1:9999; Connection refused
```

# 如何做...

我们将本地转发连接到本地端口`9999`到远程端口`8888`。

# 在命令行上

从`centos1`运行以下命令：

```
[vagrant@centos1 ~]$ ssh -f -L 9999:127.0.0.1:8888 192.168.33.11 sleep 120
```

您可能会被提示输入密码（取决于您在密钥设置方面做了什么），然后被放回到`centos1`提示符。

我们的 SSH 连接将保持两分钟。

现在，我们运行一个`curl`，检查我们的转发是否正常工作：

```
[vagrant@centos1 ~]$ curl 127.0.0.1:9999
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
```

成功！在这里，我们正在从我们转发的端口上的`centos1`的本地主机 IP 地址进行 curl，并且我们正在从`centos2`获取目录列表！

# 使用 SSH 配置文件

如果我们想要每次连接到`centos2`时创建这种转发设置，我们可以将选项添加到我们的 SSH 配置文件中。

在以下代码中添加加粗的行：

```
Host * !CentOS2-V6
 IdentityFile ~/.ssh/id_ed25519
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 LocalForward 9999 127.0.0.1:8888
 User vagrant

Host CentOS2-V6
 Hostname fe80::a00:27ff:fe56:c5a7%%eth1
 IdentityFile ~/.ssh/id_rsa
 Port 22
 User vagrant

Host CentOS2-Hostname
 Hostname centos2
 User vagrant
```

现在，如果您 SSH 到指定的主机，您将创建一个转发连接，而无需指定它：

```
[vagrant@centos1 ~]$ ssh -f CentOS2-V4 sleep 120
[vagrant@centos1 ~]$ curl 127.0.0.1:9999
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
```

您不限于每个主机一条`LocalForward`条目 - 您可以有多个。

# 它是如何工作的...

当您使用 SSH 的`-L`标志时，您正在指定任何连接尝试都将转发到远程主机和端口的本地机器上列出的第一个端口。

让我们分解一下这个命令：

```
[vagrant@centos1 ~]$ ssh -f -L 9999:127.0.0.1:8888 192.168.33.11 sleep 120
```

首先，命令末尾的`-f`和`sleep 120`是一种快速创建会话并在我们进行测试时将其后台化的方法：

```
-f ... sleep 120
```

在现实世界中，您不仅限于一个终端窗口，通常情况下，您会发现自己在一个窗口中连接到远程主机，而在另一个窗口中进行工作。

第二部分是有趣的部分：

```
-L 9999:127.0.0.1:8888
```

在这里，我们说本地端口`9999`应将任何连接请求转发到远程主机的`127.0.0.1:8888`。

由于我们创建 Web 服务器的方式，以下语法也是有效的：

```
-L 9999:192.168.33.11:8888
```

这是因为我们的远程 Web 服务器正在监听所有地址，因此我们不是将请求发送到远程本地主机地址，而是使用`eth1`地址。

我经常看到设置，其中不太安全的程序仅在本地主机地址上运行，这意味着如果要访问该程序，必须先 SSH 到远程主机。

您不仅限于 cURL 和命令行 - 您可以在 Web 浏览器中导航到`http://127.0.0.1:9999`，它仍然可以工作。

# 还有更多...

SSH 的技巧和窍门有点无穷无尽，但以下内容可能是很好的练习。

# 观察我们的 SSH 会话

如果要查看 SSH 隧道何时关闭，请运行以下命令：

```
[vagrant@centos1 ~]$ ps aux | grep "ssh -f" | grep -v grep
vagrant   3525  0.0  0.2  82796  1196 ?        Ss   11:03   0:00 ssh -f -L 9999:127.0.0.1:8888 192.168.33.11 sleep 120
```

在断开连接时，此过程将结束：

```
[vagrant@centos1 ~]$ ps aux | grep "ssh -f" | grep -v grep
[vagrant@centos1 ~]$ 
```

# 连接到远程主机之外的系统

`LocalForwarding`甚至可以用于访问远程机器可以看到但本地机器看不到的主机。

考虑以下配置条目：

```
Host *
 IdentityFile ~/.ssh/id_ed25519
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 LocalForward 7777 192.168.33.12:6666
 User vagrant
```

在此示例中，`centos2`可以看到具有 IP`192.168.33.12`的主机，以及在端口`6666`上监听的服务器。

当我们连接到`centos2`并创建我们的隧道时，我们可以在本地连接到`127.0.0.1:7777`，查看`192.168.33.12:6666`上的 Web 服务器。

这通常与堡垒主机一起使用，我们很快将会看到。

# 另请参阅

将本地连接尝试转发到远程主机可能是一种非常有用的故障排除和访问控制方法。

查看 SSH 手册页面，以获取有关此处列出的选项的更多详细信息和扩展。

可以使用以下命令在大多数 Linux 系统上打开 SSH 手册页面：

```
$ man ssh
```

# 使用远程转发

在上一节中，我们看到了将本地连接尝试转发到远程机器的能力。

在本节中，我们将看到非常相似的内容：远程转发。

通过远程转发，对远程机器上指定地址和端口的连接尝试将通过您设置的 SSH 隧道传回，并在本地机器（客户端）上进行处理。

从`centos1`开始。

在开始之前值得注意的是，远程转发是打开网络的一种很好的方法，这意味着它也可能是网络维护的安全专业人员的噩梦。伴随着巨大的力量而来的是巨大的责任等等。

# 准备工作

确认您的 Vagrant 框都已启用，并连接到两者：

```
$ vagrant ssh centos1
$ vagrant ssh centos2
```

# 如何做...

首先，我们将从我们的提示符处使用我们的单个命令开始，然后我们将看看如何使用 SSH 配置文件每次 SSH 到一台机器时设置连接。

# 在命令行上

在`centos1`上运行以下命令：

```
[vagrant@centos1 ~]$ ssh -R 5353:127.0.0.1:22 192.168.33.11
```

连接到`centos2`后，运行以下命令：

```
[vagrant@centos2 ~]$ ssh 127.0.0.1 -p5353
```

您可能会提示添加主机密钥，然后提示输入密码。我们正在连接回`centos1`，因此提供默认的 Vagrant 密码。

您应该留在`centos1`命令行提示符处：

```
vagrant@127.0.0.1's password: 
Last login: Thu Aug  9 12:29:56 2018 from 127.0.0.1
[vagrant@centos1 ~]$ 
```

# 使用 SSH 配置文件

与`LocalForward`一样，我们也可以使用 SSH 配置文件进行`RemoteForward`连接：

```
Host *
 IdentityFile ~/.ssh/id_ed25519
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 LocalForward 9999 127.0.0.1:8888
 RemoteForward 5353 127.0.0.1:22
 User vagrant
```

在这里，您可以看到我们在命令行部分中使用的确切设置，只是在配置文件中指定，因此它始终可用，而无需每次键入标志：

```
[vagrant@centos1 ~]$ ssh CentOS2-V4
[vagrant@centos2 ~]$ ssh 127.0.0.1 -p5353
[vagrant@centos1 ~]$ 
```

# 工作原理...

我们实际上在这里做的是...奇怪的：

1.  我们 SSH 到`centos2`，同时指定在远程机器（`centos2`）上对端口`5353`进行的任何连接尝试都将通过 SSH 会话传回到我们的客户端（`centos1`）。

1.  然后我们在我们的远程机器（`centos2`）上运行 SSH，指定本地地址和我们传递回`centos1`的端口，`127.0.0.1:5353`。

1.  连接尝试被传递回我们已建立的 SSH 会话到`centos1`，SSH 服务器接受连接请求。

1.  结果是，我们通过在`centos2`上指定本地地址和远程转发端口来本地 SSH 到`centos1`。

困惑吗？有人第一次向我解释这个时我也感到困惑。

为了更好地理解这一点，我们可以使用`w`命令。

在`centos1`上，这给我们以下结果：

```
[vagrant@centos1 ~]$ w
 12:47:50 up  2:10,  2 users,  load average: 0.00, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         10:38    6.00s  1.07s  0.08s ssh -R 5353:127.0.0.1:22 192.168.33.
vagrant  pts/1    127.0.0.1        12:44    6.00s  0.07s  0.05s w
```

在这里，我们可以看到我们的默认 Vagrant 连接（来自`10.0.2.2`），但我们也可以看到一个本地连接。

显然，我们已经从本地地址（`127.0.0.1`）SSH 到我们的机器。这实际上是我们在`centos2`上使用以下命令建立的 SSH 会话：

```
[vagrant@centos2 ~]$ ssh 127.0.0.1 -p5353
```

在`centos2`上，`w`命令给出以下结果：

```
[vagrant@centos2 ~]$ w
 12:48:08 up  2:09,  2 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         10:43    0.00s  0.92s  0.04s w
vagrant  pts/1    192.168.33.10    12:44   24.00s  0.07s  0.04s ssh 127.0.0.1 -p5353
```

在这里，我们可以看到我们的默认 Vagrant 连接（来自`10.0.2.2`），但我们也可以看到从`centos1`（`192.168.33.10`）的远程连接。

# 还有更多...

不仅仅是 SSH 可以使用这个。同样，我们可以将远程会话的端口转发到我们的本地机器上 - 我们有许多可用的选项。

让我们在`centos1`上启动并在后台运行一个简单的 Web 服务器：

```
[vagrant@centos1 ~]$ python -m SimpleHTTPServer 8888 &
[1] 6010
```

现在，让我们 SSH 到`centos2`，同时声明在远程机器上对`127.0.0.1:7777`的任何请求都会沿着已建立的 SSH 会话传递回`centos1`：

```
[vagrant@centos1 ~]$ ssh -R 7777:127.0.0.1:8888 192.168.33.11
```

在`centos2`上，我们现在应该能够`curl 127.0.0.1:7777`并查看`centos1`上 Vagrant 主目录的内容：

```
[vagrant@centos2 ~]$ curl 127.0.0.1:7777
127.0.0.1 - - [09/Aug/2018 12:56:43] "GET / HTTP/1.1" 200 -
 <!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
```

成功！

# 另请参阅

虽然看起来似乎用途有限，但就巧妙的技巧而言，您可能会在职业生涯中找到一些奇特的用例。

我曾在一两个场合使用过这个方法，当远程机器的 DNS 出现故障时，我反而通过已建立的 SSH 连接转发 DNS 请求。

# 代理跳转和堡垒主机

在这个教程中，我们将看一看一个非常新的 SSH 选项，一个稍老的 SSH 选项，以及堡垒主机（或跳板机）的概念。

我们需要三台机器，因为我们将使用一台机器作为到另一台机器的“网关”。

# 准备好了

设置好您的三个 VM，最好使用本章开头的`Vagrantfile`。

连接到每个框，然后检查从`centos1`是否可以 ping 通`centos2`和`centos3`：

```
[vagrant@centos1 ~]$ ping 192.168.33.11
PING 192.168.33.11 (192.168.33.11) 56(84) bytes of data.
64 bytes from 192.168.33.11: icmp_seq=1 ttl=64 time=2.54 ms
64 bytes from 192.168.33.11: icmp_seq=2 ttl=64 time=1.09 ms
64 bytes from 192.168.33.11: icmp_seq=3 ttl=64 time=0.929 ms
^C
--- 192.168.33.11 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2009ms
rtt min/avg/max/mdev = 0.929/1.524/2.548/0.728 ms
[vagrant@centos1 ~]$ ping 192.168.33.12
PING 192.168.33.12 (192.168.33.12) 56(84) bytes of data.
64 bytes from 192.168.33.12: icmp_seq=1 ttl=64 time=0.743 ms
64 bytes from 192.168.33.12: icmp_seq=2 ttl=64 time=1.15 ms
64 bytes from 192.168.33.12: icmp_seq=3 ttl=64 time=1.12 ms
^C
--- 192.168.33.12 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2015ms
rtt min/avg/max/mdev = 0.743/1.008/1.157/0.187 ms
```

如果您使用提供的`Vagrantfile`，这些地址是`192.168.33.11`和`192.168.33.12`。

# 如何做...

从`centos1`，运行以下命令：

```
[vagrant@centos1 ~]$ ssh -J vagrant@192.168.33.11:22 192.168.33.12
```

您可能会被提示接受密钥，并被要求输入密码。

您将发现自己在`centos3`上，已经跳转到`centos2`：

```
[vagrant@centos3 ~]$ 
```

# 使用 SSH 配置文件

通过在 SSH 配置文件中指定`ProxyJump`选项，可以使用相同的技巧：

```
Host *
 IdentityFile ~/.ssh/id_ed25519
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant

Host CentOS3-V4
 Hostname 192.168.33.12
 User vagrant
 ProxyJump CentOS2-V4
```

现在您可以通过`centos2` SSH 到`centos3`：

```
[vagrant@centos1 ~]$ ssh CentOS3-V4
vagrant@192.168.33.11's password: 
vagrant@192.168.33.12's password: 
Last login: Thu Aug  9 14:15:03 2018 from 192.168.33.11
[vagrant@centos3 ~]$ 
```

# 工作原理...

`-J`和`ProxyJump`选项是通过指定的主机连接到更远主机的一种方法。

官方手册页面（[`man.openbsd.org/ssh`](https://man.openbsd.org/ssh)）中`-J [user@]host[:port]`的手动输入如下：

首先通过 SSH 连接到由目标描述的跳转主机，然后从那里建立到最终目的地的 TCP 转发，连接到目标主机。可以指定多个跳转跳数，用逗号字符分隔。这是指定 ProxyJump 配置指令的快捷方式。

`ProxyJump`的手动输入来自[`man.openbsd.org/ssh_config`](https://man.openbsd.org/ssh_config)，如下所示：

指定一个或多个跳转代理，格式为[user@]host[:port]或 ssh URI。多个代理可以用逗号字符分隔，并将按顺序访问。设置此选项将导致 ssh(1)首先通过与指定的 ProxyJump 主机建立 ssh(1)连接，然后从那里建立到最终目标的 TCP 转发。

如果我们使用 SSH 的`-v`标志，我们可以更详细地看到发生了什么：

```
[vagrant@centos1 ~]$ ssh -v CentOS3-V4
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 8: Applying options for CentOS3-V4
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug1: Setting implicit ProxyCommand from ProxyJump: ssh -v -W %h:%p CentOS2-V4
debug1: Executing proxy command: exec ssh -v -W 192.168.33.12:22 CentOS2-V4
<SNIP>
debug1: permanently_drop_suid: 1000
OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017
debug1: Reading configuration data /home/vagrant/.ssh/config
debug1: /home/vagrant/.ssh/config line 1: Applying options for *
debug1: /home/vagrant/.ssh/config line 4: Applying options for CentOS2-V4
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 58: Applying options for *
debug1: Connecting to 192.168.33.11 [192.168.33.11] port 22.
debug1: Connection established.
debug1: key_load_public: No such file or directory
<SNIP>
debug1: kex_input_ext_info: server-sig-algs=<rsa-sha2-256,rsa-sha2-512>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-keyex
debug1: No valid Key exchange context
debug1: Next authentication method: gssapi-with-mic
debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: KEYRING:persistent:1000)

debug1: Unspecified GSS failure.  Minor code may provide more information
No Kerberos credentials available (default cache: KEYRING:persistent:1000)

debug1: Next authentication method: publickey
debug1: Trying private key: /home/vagrant/.ssh/id_rsa
debug1: Trying private key: /home/vagrant/.ssh/id_dsa
debug1: Trying private key: /home/vagrant/.ssh/id_ecdsa
debug1: Trying private key: /home/vagrant/.ssh/id_ed25519
debug1: Next authentication method: password
vagrant@192.168.33.11's password: 
debug1: Authentication succeeded (password).
Authenticated to 192.168.33.11 ([192.168.33.11]:22).
debug1: channel_connect_stdio_fwd 192.168.33.12:22
debug1: channel 0: new [stdio-forward]
debug1: getpeername failed: Bad file descriptor
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.4
debug1: match: OpenSSH_7.4 pat OpenSSH* compat 0x04000000
debug1: Authenticating to 192.168.33.12:22 as 'vagrant'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: curve25519-sha256 need=64 dh_need=64
debug1: kex: curve25519-sha256 need=64 dh_need=64
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
<SNIP>
vagrant@192.168.33.12's password: 
debug1: Authentication succeeded (password).
Authenticated to 192.168.33.12 (via proxy).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: proc
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending environment.
debug1: Sending env LANG = en_GB.UTF-8
Last login: Thu Aug  9 14:22:08 2018 from 192.168.33.11
[vagrant@centos3 ~]$
```

在前面的输出中加粗显示，我们可以看到连接序列中发生的关键步骤：

1.  SSH 读取我们要连接的主机的配置。

1.  SSH 意识到它必须使用`ProxyJump`主机来访问指定的主机。

1.  SSH 将`ProxyJump`选项转换为等效的`ProxyCommand`条目。

1.  SSH 读取`ProxyJump`主机的配置。

1.  SSH 连接并对`ProxyJump`主机进行身份验证。

1.  SSH 使用其已建立的连接到`ProxyJump`来连接目标主机。

1.  SSH 注意到它已经通过代理对目标主机进行了身份验证。

# 还有更多...

现在你已经了解了`ProxyJump`的基础知识，让我们看看一些你可能会发现有用的场景。

不止一次，以以下列出的方式使用`ProxyJump`为我节省了几毫秒的时间！

# 多个主机

虽然先前给出的示例相对简单，但值得注意的是，你可以用`ProxyJump`做一些相当复杂的事情。

你可以像手册页建议的那样列出主机，也可以像下面这样链接主机：

```
Host *
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant

Host CentOS3-V4
 Hostname 192.168.33.12
 User vagrant
 ProxyJump CentOS2-V4

Host CentOS4-V4
 Hostname 192.168.33.14
 User vagrant
 ProxyJump CentOS3-V4
```

`ProxyJump`本身的优势应该是显而易见的：使用这种技术，你可以创建一个只需要从本地机器输入一个命令就能访问远程且其他情况下无法访问的主机的设置。

通常，你可能会在只有一个入口服务器的环境中使用`ProxyJump`。

`ProxyJump`还使转发端口变得更容易。如果你在前面的代码中的`CentOS4-V4`中添加了一个`LocalForward`行，SSH 也会通过`ProxyJump`主机处理流量！这可能特别方便，因为它可以阻止你手动转发端口，可能需要通过几个主机。

# ProxyCommand

在我们的调试消息中看到的是 SSH 将相当简单的`ProxyJump`条目转换为`ProxyCommand`行。

`ProxyCommand`是设置这种转发的更传统的方式，但它不仅在语法上更加恼人，而且也很混乱。

考虑以下示例：

```
Host *
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant

Host CentOS3-V4
 Hostname 192.168.33.12
 User vagrant
 ProxyCommand ssh -v -W %h:%p CentOS2-V4
```

看起来更笨拙，不是吗？但它的工作方式是一样的。

这在较旧的发行版上可能很有用，这些发行版可能尚未收到`ProxyJump`功能。

如果你忘记了`ProxyCommand`的语法，并且你有一个支持`ProxyJump`的主机，记住我们之前创建的`SSH -v`调试中已经为你打印了`ProxyCommand`的语法。

# 堡垒主机

所有这些都很棒，但是如果你正在管理服务器，为什么你需要这个呢？尤其是你控制的服务器...

考虑你的环境。

在办公室，你可能可以访问公司在其支配下的每台机器，因为你坐在一个可以无限制访问每个其他网络段的 LAN 段上。

远程，你可能有一个 VPN 机器位于你的网络边界上，你需要最初建立连接，然后才能 SSH 到其他机器。

堡垒主机是你可能考虑的东西，它们可以与 VPN 一起使用。

作为系统管理员，你可以决定你想要一个单一的入口点，让人们轻松地通过 SSH 连接到机器来记录流量，也许管理密钥——也许是因为你只是恶毒的，想让每个人的配置文件变得更长一些？

与你的网络团队合作，咨询你公司的政策，并设计一个你可以轻松维护的网络，而其他人也不会介意使用的网络。

你的公司可能有特定的安全政策限制你可以做什么。记住，问题不在于你*能*做什么，而在于你应该做什么。当你因为绕过安全措施而被赶出办公室时，没有人会因为你聪明而向你祝贺。尽管在发现安全问题时可以指出，但不要利用它们。

# 使用 SSH 创建 SOCKS 代理

SSH 很棒。

我永远不会厌倦谈论它有多么棒，而且我不提到它最好的功能之一会是我的疏忽：快速轻松地设置一个 SOCKS 代理的能力。

在以前的部分中，我们转发了单个端口，但是如果我们使用跳板主机连接网络中的大量不同网站怎么办？您想要在 SSH 配置文件中添加数十行吗？还是每次手动输入每个端口和映射？

我不这么认为。

这就是`-D`标志的作用。

请参阅 SSH 手册页中的`-D [bind_address:]port`（[`man.openbsd.org/ssh`](https://man.openbsd.org/ssh)）：

指定本地“动态”应用级端口转发。这通过分配一个套接字来监听本地端口，可选地绑定到指定的 bind_address。每当有连接到该端口时，连接将通过安全通道转发，并且然后使用应用程序协议确定从远程计算机连接到何处。当前支持 SOCKS4 和 SOCKS5 协议，并且 ssh 将充当 SOCKS 服务器。只有 root 可以转发特权端口。动态端口转发也可以在配置文件中指定。

IPv6 地址可以通过用方括号括起来指定。只有超级用户才能转发特权端口。默认情况下，本地端口将根据 GatewayPorts 设置进行绑定。但是，可以使用显式的 bind_address 将连接绑定到特定地址。 "localhost"的 bind_address 表示监听端口仅绑定供本地使用，而空地址或'*'表示该端口应该从所有接口可用。

这意味着通过一个命令，您可以建立一个连接，然后可以通过该连接转发流量（从 Web 浏览器或其他支持`SOCKS`代理的应用程序）。您不必穿透防火墙，也不必手动映射端口。

`SOCKS`本身是一种互联网协议，而且是相当古老的协议，尽管我们仍然积极使用`SOCKS5`，这是由互联网工程任务组在 1996 年批准的！它就像任何其他代理服务器一样，允许您通过连接交换数据包；在这种情况下，是我们的 SSH 隧道。应用程序可以选择本机支持 SOCKS 代理或不支持，但很多常见的应用程序会支持（例如 Firefox）。

让我们开始吧。

# 准备工作

在本节中，我们将使用`centos1`和`centos2`。

确保您同时连接到两台机器：

```
$ vagrant ssh centos1
$ vagrant ssh centos2
```

在`centos2`上，让我们再次设置我们的小型 Web 服务器：

```
[vagrant@centos2 ~]$ python -m SimpleHTTPServer 8888 &
[1] 7687
```

# 如何做...

首先连接到`centos1`，我们将首先使用一个命令设置我们的 SOCKS 代理，然后看看如何在每次 SSH 到该服务器时启动代理。

# 在命令行上

让我们建立我们的 SSH 会话并同时断开已建立的会话：

```
[vagrant@centos1 ~]$ ssh -f -D9999 192.168.33.11 sleep 120
vagrant@192.168.33.11's password: 
[vagrant@centos1 ~]$ 
```

一旦建立（直到休眠结束），我们可以使用我们的代理通过 SSH 会话查询`centos2`可以看到的任何东西。

让我们从`centos1`上检查我们的 Web 服务器，到`centos2`上：

```
[vagrant@centos1 ~]$ all_proxy="socks5://127.0.0.1:9999" curl 127.0.0.1:8888
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".lesshst">.lesshst</a>
<li><a href=".mysql_history">.mysql_history</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
[vagrant@centos1 ~]$
```

太棒了！我们对本地主机地址运行了一个 cURL，但是通过代理传递，我们的请求已经在`centos2`上运行了！

# 使用 SSH 配置文件

如以前所示，可以使用 SSH 配置文件来完成相同的操作：

```
Host *
 Port 22

Host CentOS2-V4
 Hostname 192.168.33.11
 User vagrant
 DynamicForward 9999
```

现在我们可以确信我们的代理每次连接时都可用：

```
[vagrant@centos1 ~]$ ssh -f CentOS2-V4 sleep 120
```

再次，查看 Web 服务器的内容：

```
[vagrant@centos1 ~]$ all_proxy="socks5://127.0.0.1:9999" curl 127.0.0.1:8888
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href=".bash_history">.bash_history</a>
<li><a href=".bash_logout">.bash_logout</a>
<li><a href=".bash_profile">.bash_profile</a>
<li><a href=".bashrc">.bashrc</a>
<li><a href=".lesshst">.lesshst</a>
<li><a href=".mysql_history">.mysql_history</a>
<li><a href=".ssh/">.ssh/</a>
</ul>
<hr>
</body>
</html>
```

为了证明我们真的在使用我们的代理，让我们尝试`curl`命令而不建立会话（您将不得不等待 SSH 超时，或者如果进程尚未死亡，则终止该进程）：

```
[vagrant@centos1 ~]$ all_proxy="socks5://127.0.0.1:9999" curl 127.0.0.1:8888
curl: (7) Failed connect to 127.0.0.1:9999; Connection refused
```

# 它是如何工作的...

当您在 SSH 中添加`-D`选项，或者在 SSH 配置文件中添加`DynamicForward`选项时，您告诉 SSH 您要在本地端口上指定一个端口，该端口将通过 SSH 连接转发收到的任何请求。

让我们分解我们的命令：

```
[vagrant@centos1 ~]$ ssh -f -D9999 192.168.33.11 sleep 120
```

首先，就像以前一样，我们使用了`-f`和 sleep 来保持连接打开，一旦建立连接，我们就会回到`centos1`提示符：

```
-f ... sleep 120
```

我们还指定了我们的`-D`选项，并选择了一个随机选择的端口：

```
-D9999
```

我习惯使用`9999`，但偶尔也会使用`7777`，甚至在感觉非常疯狂时使用`6666`。您可以使用任何您希望的端口（在`1024`以上，因为低于此值的端口只能由 root 使用）。

一旦我们建立，我们使用以下命令来检查我们的代理是否可用：

```
[vagrant@centos1 ~]$ all_proxy="socks5://127.0.0.1:9999" curl 127.0.0.1:8888
```

将此分解为两部分，我们从设置为此运行的变量开始：

```
all_proxy="socks5://127.0.0.1:9999"
```

cURL 使用`all_proxy`来设置其运行的 SOCKS 代理。

在浏览器中，您可能会在设置下找到设置`SOCKS`服务器的选项，并且在某些其他应用程序中，可以在需要时配置`SOCKS`代理。Gnome 的网络管理器如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/5dcbe70c-ae11-4f6b-a090-19800aa7a1a0.png)

我们命令的另一部分是`curl`：

```
curl 127.0.0.1:8888
```

通过我们的`all_proxy`设置，cURL 知道要在其连接中使用端口`9999`上的 SOCKS 代理，这意味着当我们查询`127.0.0.1:8888`时，我们将通过我们的 SSH 会话发送该请求以在`centos2`上解析。

整洁！

# 还有更多...

如果您想进一步进行，可以在远程端使用`tcpdump`来检查穿过您的网络的流量：

```
[vagrant@centos2 ~]$ sudo tcpdump port 8888 -ilo -n
```

您应该看到流量通过：

```
<SNIP>
15:18:48.991652 IP 127.0.0.1.54454 > 127.0.0.1.ddi-tcp-1: Flags [F.], seq 79, ack 618, win 700, options [nop,nop,TS val 16534669 ecr 16534658], length 0
15:18:48.991677 IP 127.0.0.1.ddi-tcp-1 > 127.0.0.1.54454: Flags [.], ack 80, win 683, options [nop,nop,TS val 16534669 ecr 16534669], length 0
<SNIP>
```

# 理解和使用 SSH 代理

我们简要提到的一件事是 SSH 代理的概念。

当您 SSH 到服务器（设置密钥后）并提示输入密码时，您实际上正在解密公私钥对的私钥部分（默认情况下为`id_rsa`文件），以便用于验证您对远程主机的身份。如果您管理数百或数千个不断变化的服务器，每次 SSH 到服务器时都这样做可能会变得乏味。

这就是 SSH 代理的作用。一旦您给出了密码，它就是您现在解密的私钥的所在地，直到您的会话结束。

一旦您将私钥加载到代理中，代理就负责向您连接的任何服务器呈现密钥，而无需再次输入密码，节省宝贵的时间和手指压力。

大多数桌面 Linux 发行版都会在用户会话中启动某种 SSH 代理，有时在您登录到用户帐户时解锁您的私钥。

macOS 有一个特定的 SSH 配置文件选项`UseKeychain`（[`developer.apple.com/library/archive/technotes/tn2449/_index.html`](https://developer.apple.com/library/archive/technotes/tn2449/_index.html)）：

“在 macOS 上，指定系统在尝试使用特定密钥时是否应在用户的钥匙串中搜索密码。当用户提供密码时，此选项还指定密码一经验证正确后是否应存储到钥匙串中。参数必须是“yes”或“no”。默认值为“no”。”

如果您在桌面上运行 macOS，您可能会考虑此选项。

在我的 Ubuntu 笔记本安装中，查找正在运行的代理会显示如下内容：

```
$ env | grep SSH
SSH_AUTH_SOCK=/run/user/1000/keyring/ssh
SSH_AGENT_PID=1542
```

查找此进程 ID 会显示我正在运行的`ssh-agent`：

```
adam 1542 0.0 0.0 11304 320 ? Ss Aug04 0:02 /usr/bin/ssh-agent /usr/bin/im-launch env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
```

在本节中，我们将在`centos1`上启动一个 SSH 代理并将密钥加载到其中。

# 做好准备

与上一节一样，请确认您的两个 Vagrant 框都已启用，并使用`vagrant`命令连接到第一个：

```
$ vagrant ssh centos1
```

确保在`centos1`上有一个可用的 SSH 密钥。如果需要，请重新阅读上一节有关生成 SSH 密钥的内容：

```
[vagrant@centos1 ~]$ ls .ssh/
authorized_keys  config  id_ed25519  id_ed25519.pub  known_hosts
```

如果您尚未将密钥复制到`centos2`，则需要接受主机密钥：

```
[vagrant@centos1 ~]$ ssh-copy-id 192.168.33.11
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/vagrant/.ssh/id_ed25519.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
vagrant@192.168.33.11's password: 

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh '192.168.33.11'"
and check to make sure that only the key(s) you wanted were added.

[vagrant@centos1 ~]$ 
```

检查尝试登录到`centos2`是否提示您输入密钥密码：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
```

确保您在`centos1`上开始。

# 如何做...

首先运行`ssh-agent`命令：

```
[vagrant@centos1 ~]$ ssh-agent
SSH_AUTH_SOCK=/tmp/ssh-9On2mDhHTL8T/agent.6693; export SSH_AUTH_SOCK;
SSH_AGENT_PID=6694; export SSH_AGENT_PID;
echo Agent pid 6694;
```

您可以看到它打印了几个环境变量和它正在运行的进程 ID。

我们可以确认这是事实：

```
[vagrant@centos1 ~]$ pidof ssh-agent
6694
```

复制为你提供的各种变量，并将它们粘贴到同一个窗口中：

```
[vagrant@centos1 ~]$ SSH_AUTH_SOCK=/tmp/ssh-9On2mDhHTL8T/agent.6693; export SSH_AUTH_SOCK;
[vagrant@centos1 ~]$ SSH_AGENT_PID=6694; export SSH_AGENT_PID;
[vagrant@centos1 ~]$
```

现在，运行`ssh-add`命令，并在提示时填写你的密钥密码：

```
[vagrant@centos1 ~]$ ssh-add
Enter passphrase for /home/vagrant/.ssh/id_ed25519: 
Identity added: /home/vagrant/.ssh/id_ed25519 (vagrant@centos1)
[vagrant@centos1 ~]$ 
```

你可以看到它通知你已经添加了你的身份。

SSH 到`centos2`，准备好惊讶，当你不被提示输入你的密码时：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11 
Last login: Thu Aug 9 15:36:02 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

你可能认为每天输入一两次密码并不介意，你可能会认为没问题，但如果你很少登录到一台机器，你可能是一个非常幸运的系统管理员。 SSH 代理的优势在于当你想要登录到数十甚至数百台机器时，甚至如果你使用`ProxyJump`框，并且不想比必要的次数输入你的密码。

要终止运行的代理，使用`-k`：

```
[vagrant@centos1 ~]$ ssh-agent -k
unset SSH_AUTH_SOCK;
unset SSH_AGENT_PID;
echo Agent pid 6694 killed;
```

我曾见过一些公司不喜欢使用 SSH 代理，并且要求每次输入密码或密码。检查一下，确保你没有违反某些晦涩的安全策略以便让你的生活更轻松。

然后，运行建议的取消设置命令来删除我们之前设置的变量：

```
[vagrant@centos1 ~]$ unset SSH_AUTH_SOCK;
[vagrant@centos1 ~]$ unset SSH_AGENT_PID;
```

简单地注销你的会话不会停止`ssh-agent`程序的运行。如果你选择使用它，要注意这一点。同样，你不应该在多人共享的远程主机上运行代理-最好保留在你的个人机器上。如果你打算使用 SSH 代理，请阅读当前的安全实践。

# 它是如何工作的...

当我们最初运行`ssh-agent`时，代理本身在后台启动，并且我们得到了 SSH 所需的环境变量。设置后，运行 SSH 将导致它读取这些变量。

如果我们在 SSH 中添加了一些`-vv`标志，我们可以看到它在代理中找到我们的密钥：

```
debug2: key: /home/vagrant/.ssh/id_ed25519 (0x55b11351c410), agent
```

没有加载代理，但有密钥存在时，看起来是这样的：

```
debug2: key: /home/vagrant/.ssh/id_ed25519 (0x55dea5015410)
```

`ssh-add`也会读取 SSH 环境变量，我们用它将我们的密钥添加到代理中。引用手册页：

"认证代理必须正在运行，并且 SSH_AUTH_SOCK 环境变量必须包含其套接字的名称，以便 ssh-add 正常工作。"

当你的代理中有一个或多个密钥时，SSH 将尝试使用这些密钥对远程主机进行身份验证，从而无需每次输入密码。

# 还有更多...

如果你想将代理启动命令添加到脚本（比如`.bashrc`），你可能希望自动评估给你的环境变量。 `ssh-agent`假设你是以这种方式启动它的。

在`ssh-agent`的手册页中，你甚至会得到这个提示。

"有两种主要的设置代理的方法：第一种是代理启动一个新的子命令，其中一些环境变量被导出，例如 ssh-agent xterm &。第二种是代理打印所需的 shell 命令（可以生成 sh(1)或 csh(1)语法），可以在调用 shell 中进行评估，例如对于 Bourne 类型的 shell，如 sh(1)或 ksh(1)，可以使用 eval 'ssh-agent -s'，对于 csh(1)和衍生版本，可以使用 eval 'ssh-agent -c'。"

实际上，这意味着最容易这样启动代理：

```
[vagrant@centos1 ~]$ eval $(ssh-agent)
Agent pid 6896
```

在这里，我们使用 Bash 子 shell 来启动和读取代理的输出。

# ssh-add

`ssh-add`有一些不错的选项可用，其中一些是很方便知道的。

`-l`将允许你查看已加载的身份，以及它们的指纹：

```
[vagrant@centos1 ~]$ ssh-add -l
256 SHA256:P7FdkmbQQFoy37avbKBfzMpEhVUaBY0TljwYJyNxzUI vagrant@centos1 (ED25519)
```

`-D`将允许你删除所有身份（`-d`可用于删除特定身份）：

```
[vagrant@centos1 ~]$ ssh-add -D
All identities removed.
```

`-x`将锁定代理，而`-X`将解锁代理：

```
[vagrant@centos1 ~]$ ssh-add -l
256 SHA256:P7FdkmbQQFoy37avbKBfzMpEhVUaBY0TljwYJyNxzUI vagrant@centos1 (ED25519)
[vagrant@centos1 ~]$ ssh-add -x
Enter lock password: 
Again: 
Agent locked.
[vagrant@centos1 ~]$ ssh-add -l
The agent has no identities.
[vagrant@centos1 ~]$ ssh-add -X
Enter lock password: 
Agent unlocked.
[vagrant@centos1 ~]$ ssh-add -l
256 SHA256:P7FdkmbQQFoy37avbKBfzMpEhVUaBY0TljwYJyNxzUI vagrant@centos1 (ED25519)
```

# AddKeysToAgent

当使用代理时，你可能会喜欢 SSH 配置文件选项`AddKeysToAgent`，它将自动将使用的密钥添加到你的`ssh-agent`中以供将来使用。

考虑以下；我们从没有密钥的代理开始：

```
[vagrant@centos1 ~]$ ssh CentOS2-V4
Enter passphrase for key '/home/vagrant/.ssh/id_ed25519': 
Last login: Thu Aug  9 15:58:01 2018 from 192.168.33.10
[vagrant@centos2 ~]$ logout
Connection to 192.168.33.11 closed.
[vagrant@centos1 ~]$ ssh CentOS2-V4
Last login: Thu Aug  9 16:12:04 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

请注意，第一次，我们被提示输入我们的密钥密码。第二次，我们没有被提示。

现在它已经加载到我们的代理中：

```
[vagrant@centos1 ~]$ ssh-add -l
256 SHA256:P7FdkmbQQFoy37avbKBfzMpEhVUaBY0TljwYJyNxzUI vagrant@centos1 (ED25519)
```

这一切都由一个配置选项处理：

```
[vagrant@centos1 ~]$ cat .ssh/config 
Host *
 Port 22
 AddKeysToAgent yes
```

# 另请参阅

除了 OpenSSH 提供的默认 SSH 代理之外，还有其他 SSH 代理（我们在这里使用了）。还有一些系统使用更多的组件（例如大多数桌面发行版上的 PAM）。四处阅读，看看你是否能弄清楚你选择的发行版是如何做事的。

# 在一台主机上运行多个 SSH 服务器

有时，在一台主机上运行多个 SSH 服务器是一个要求。您可能希望使用一个进行常规的日常活动，另一个用于备份或自动化。

在这种情况下，同时运行两个不同版本的 SSH 服务器是完全可能的。

我们将使用`centos2`，在端口`2020`上设置一个辅助 SSH 服务器。

# 准备工作

如果您还没有这样做，我建议销毁之前的 Vagrant 盒子，并为此部署新的盒子。

创建新的盒子后，连接到两个：

```
$ vagrant ssh centos1
$ vagrant ssh centos2
```

在`centos2`上安装`policycoreutils-python`，以备稍后使用`semanage`：

```
[vagrant@centos2 ~]$ sudo yum -y install policycoreutils-python
```

# 如何做...

首先，我们要复制我们的初始配置文件：

```
[vagrant@centos2 ~]$ sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_2020
```

然后，我们要做一些改变：

```
[vagrant@centos2 ~]$ sudo sed -i 's#\#Port 22#Port 2020#g' /etc/ssh/sshd_config_2020
[vagrant@centos2 ~]$ sudo sed -i 's#\#PidFile /var/run/sshd.pid#PidFile /var/run/sshd_2020.pid#g' /etc/ssh/sshd_config_2020
```

现在，我们要复制我们的`systemd`单元文件：

```
[vagrant@centos2 ~]$ sudo cp /usr/lib/systemd/system/sshd.service  /etc/systemd/system/sshd_2020.service
```

然后，我们要在这里做一些更改：

```
[vagrant@centos2 ~]$ sudo sed -i 's#OpenSSH server daemon#OpenSSH server daemon on port 2020#g' /etc/systemd/system/sshd_2020.service
[vagrant@centos2 ~]$ sudo sed -i 's#EnvironmentFile=/etc/sysconfig/sshd#EnvironmentFile=/etc/sysconfig/sshd_2020#g' /etc/systemd/system/sshd_2020.service
```

将旧的环境文件复制到新文件：

```
[vagrant@centos2 ~]$ sudo cp /etc/sysconfig/sshd /etc/sysconfig/sshd_2020
```

然后，将这个环境文件指向我们的新配置文件：

```
[vagrant@centos2 ~]$ sudo sed -i 's#OPTIONS="-u0"#OPTIONS="-u0 -f /etc/ssh/sshd_config_2020"#g' /etc/sysconfig/sshd_2020
```

告诉 SELinux 我们将在`2020`上运行 SSH 守护程序：

```
[vagrant@centos2 ~]$ sudo semanage port -a -t ssh_port_t -p tcp 2020
```

告诉`systemd`我们已经做出了更改：

```
[vagrant@centos2 ~]$ sudo systemctl daemon-reload 
```

启动并启用我们的第二个服务器：

```
[vagrant@centos2 ~]$ sudo systemctl enable sshd_2020
Created symlink from /etc/systemd/system/multi-user.target.wants/sshd_2020.service to /etc/systemd/system/sshd_2020.service.
[vagrant@centos2 ~]$ sudo systemctl start sshd_2020
```

通过从`centos1`进行 SSH 连接来检查它是否正在运行：

```
[vagrant@centos1 ~]$ ssh 192.168.33.11
The authenticity of host '192.168.33.11 (192.168.33.11)' can't be established.
ECDSA key fingerprint is SHA256:I67oI3+08lhdO2ibnoC+z2hzYtvfi9NQAmGxyzxjsI8.
ECDSA key fingerprint is MD5:03:68:ed:a2:b5:5d:57:88:61:4e:86:28:c3:75:28:fa.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.33.11' (ECDSA) to the list of known hosts.
vagrant@192.168.33.11's password: 
Last login: Thu Aug  9 16:24:50 2018 from 10.0.2.2
[vagrant@centos2 ~]$ logout
Connection to 192.168.33.11 closed.
[vagrant@centos1 ~]$ ssh 192.168.33.11 -p2020
vagrant@192.168.33.11's password: 
Last login: Thu Aug  9 16:40:55 2018 from 192.168.33.10
[vagrant@centos2 ~]$ 
```

还记得我们之前看主机密钥时吗？在前面的代码中，我们可以看到端口`22`服务器和`2020`服务器共享主机密钥，因为我们只被要求接受一次。

# 它是如何工作的...

我们所做的一切只是复制了一些文件，并做了一些明智的更改，以确保这两个进程之间的交互不会太多。

首先，我们创建了以下文件：

```
/etc/ssh/sshd_config_2020
```

然后，我们运行了一些`sed`命令来更改一些值。具体来说，我们修改了服务器监听的端口，以及它将使用的进程 ID 文件（PID 修改经常被忽视）。

接下来，我们复制了 CentOS OpenSSH 服务器软件包中提供的`systemd`单元文件，并稍微调整了它，改变了描述并将其指向不同的环境文件。

我们将生成的单元文件（`sshd_2020.service`）放在与原始文件不同的位置，以使其与提供的默认文件区分开来。

我们复制了环境文件，并对其进行了修改，以便在启动 SSH 守护程序时传递一个新选项。这个新选项是一个不同的配置文件（我们开始制作的那个）：

```
OPTIONS="-u0 -f /etc/ssh/sshd_config_2020"
```

然后，我们更新了 SELinux 策略，使其了解新服务器的意图，重新加载了 systemd 的运行配置，并启用并启动了我们的服务器。

在配置和环境文件的标准位置方面，可能会有所不同。这可能会在主要的发行版发布之间发生变化，并且一些设置在不同的发行版之间经常不同。

# 还有更多...

如果您有兴趣看到两个服务器在运行，有几种方法可以做到这一点。

在`centos2`上，从`ss`开始：

```
[vagrant@centos2 ~]$ sudo ss -tna -4
State       Recv-Q Send-Q     Local Address:Port                    Peer Address:Port 
LISTEN      0      128                    *:2020                               *:* 
LISTEN      0      128                    *:111                                *:* 
LISTEN      0      128                    *:22                                 *:* 
LISTEN      0      100            127.0.0.1:25                                 *:* 
ESTAB       0      0              10.0.2.15:22                          10.0.2.2:59594 
```

我们还可以使用 systemd 的内置命令：

```
[vagrant@centos2 ~]$ PAGER= systemctl | grep sshd
 sshd.service                                                                             loaded active running   OpenSSH server daemon
 sshd_2020.service                                                                        loaded active running   OpenSSH server daemon on port 2020
```

最后，我们可以使用老式的`ps`：

```
[vagrant@centos2 ~]$ ps aux | grep sshd
root       856  0.0  0.8 112796  4288 ?        Ss   16:52   0:00 /usr/sbin/sshd -D -u0 -f /etc/ssh/sshd_config_2020
root       858  0.0  0.8 112796  4292 ?        Ss   16:52   0:00 /usr/sbin/sshd -D -u0
```

# 总结

虽然我在本章中描述了 SSH 的一些出色功能，并一直在赞扬它，但值得注意的是，它仍然是软件，并且不断在发展。因为它是软件，它可能会有错误和意外行为，尽管背后的开发人员是最好的，因为它是 OpenBSD 软件套件的一部分。

如果你从本章中学到了什么，那就是：

+   使用基于密钥的身份验证

+   禁用 SSH 上的 root 登录

+   使用本地 SSH 配置文件连接到远程机器

如果你像我一样有点悲伤，我强烈建议你注册各种 SSH 邮件列表，并密切关注可能吸引你注意的新功能。`ProxyJump`还没有出现很久，但非常方便。

我确实记得有时 SSH 以某种形式或其他让我困扰，比如有一次我花了很长时间在桌子上砸头，试图弄清楚为什么 SSH 就是无法读取私有 RSA 文件，最后才发现它需要公钥也在本地机器的同一个文件夹中。这是我不会再浪费的相当长的一段时间，但这是一个我不会再犯的错误。

也就是说，我还可以分享更多 SSH 让我印象深刻，让我的生活更轻松的例子。它基本上是系统管理的瑞士军刀，不仅仅是因为它通常是连接到设备的方式。

人们使用 SSH 进行管理，传输备份，在不同设备之间移动文件，使用诸如 Ansible 之类的工具进行自动化，将其他连接包装在其中，以及更多其他用途。

我曾经看到过在 Windows 上实现 OpenSSH，因为运行 Windows 服务器的人是 Unix 人，不信任远程桌面协议（RDP）。他们习惯于通过 SSH 连接到设备，本地转发 RDP 会话到`127.0.0.1:3389`，然后通过 SSH 会话连接到 RDP……速度很慢……

它稳固、安全，使用起来很愉快。它适用于 Linux、macOS、BSD、Solaris，甚至 Windows！

在此向 SSH 和特别是 OpenSSH 表示衷心的感谢。

本章中我们没有讨论的一些事情包括密码、消息完整性代码、密钥交换算法等。主要是因为这些主题本身几乎就是一本书，而且绝对超出了我们在这里所做的范围。我通常相信各种软件包的维护者会选择明智的默认设置，但如果你感到有必要，独立阅读有关安全性的内容也无妨。
