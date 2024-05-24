# Ansible 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Ansible 已经迅速从一个小型的开源编排工具发展成为一款完整的编排和配置管理工具，由红帽公司拥有。在本书中，您将学习如何使用核心 Ansible 模块编写 playbook，部署从基本的 LAMP 堆栈到完整的高可用公共云基础架构。

通过本书，您将学会以下内容：

+   编写自己的 playbook 来配置运行 CentOS 7、Ubuntu 17.04 和 Windows Server 的服务器

+   定义了一个高可用的云基础架构代码，使得很容易将您的基础架构配置与您自己的代码一起分发

+   部署和配置 Ansible Tower 和 Ansible AWX

+   使用社区贡献的角色，并学习如何贡献自己的角色

+   通过几个用例，了解如何在日常角色和项目中使用 Ansible

通过本书，您应该对如何将 Ansible 集成到日常角色中有一个很好的想法，比如系统管理员、开发人员和 DevOps 从业者。

# 这本书适合谁

这本书非常适合想要将他们当前的工作流程转变为可重复使用的 playbook 的系统管理员、开发人员和 DevOps 从业者。不需要先前对 Ansible 的了解。

# 本书涵盖的内容

第一章，*Ansible 简介*，讨论了 Ansible 开发的问题，作者是谁，并谈到了红帽公司在收购 Ansible 后的参与情况。

第二章，*安装和运行 Ansible*，讨论了我们将如何在 macOS 和 Linux 上安装 Ansible，然后介绍其背景。我们还将讨论为什么没有本地的 Windows 安装程序，并介绍在 Windows 10 专业版的 Ubuntu shell 上安装 Ansible。

第三章，*Ansible 命令*，解释了在开始编写和执行更高级的 playbook 之前，我们将先了解 Ansible 命令。在这里，我们将介绍组成 Ansible 的一组命令的用法。

第四章，*部署 LAMP 堆栈*，讨论了使用随 Ansible 提供的各种核心模块部署完整的 LAMP 堆栈。我们将针对本地运行的 CentOS 7 虚拟机进行操作。

第五章，*部署 WordPress*，解释了我们在上一章部署的 LAMP 堆栈作为基础。我们将使用 Ansible 来下载、安装和配置 WordPress。

第六章，*面向多个发行版*，解释了我们将如何调整 playbook，使其可以针对 Ubuntu 17.04 和 CentOS 7 服务器运行。前两章的最终 playbook 已经编写成针对 CentOS 7 虚拟机。

第七章，*核心网络模块*，解释了我们将如何查看随 Ansible 一起提供的核心网络模块。由于这些模块的要求，我们只会涉及这些模块提供的功能。

第八章，*迁移到云*，讨论了我们将如何从使用本地虚拟机转移到使用 Ansible 在 DigitalOcean 中启动 Droplet，然后我们将使用前几章的 playbook 来安装和配置 LAMP 堆栈和 WordPress。

第九章，*构建云网络*，讨论了在 DigitalOcean 中启动服务器后。我们将转移到 Amazon Web Services，然后启动实例。我们需要为它们创建一个网络来进行托管。

第十章，*高可用云部署*，继续我们的 Amazon Web Services 部署。我们将开始将服务部署到上一章中创建的网络中，到本章结束时，我们将留下一个高可用的 WordPress 安装。

第十一章，*构建 VMware 部署*，讨论了允许您与构成典型 VMware 安装的各种组件进行交互的核心模块。

第十二章，*Ansible Windows 模块*，介绍了不断增长的核心 Ansible 模块集，支持并与基于 Windows 的服务器交互。

第十三章，*使用 Ansible 和 OpenSCAP 加固您的服务器*，解释了如何使用 Ansible 安装和执行 OpenSCAP。我们还将研究如何使用 Ansible 解决在 OpenSCAP 扫描期间发现的任何问题。

第十四章，*部署 WPScan 和 OWASP ZAP*，解释了创建一个部署和运行两个安全工具 OWASP ZAP 和 WPScan 的 playbook。然后，使用前几章的 playbook 启动 WordPress 安装以运行它们。

第十五章，*介绍 Ansible Tower 和 Ansible AWX*，介绍了两个与 Ansible 相关的图形界面，商业版的 Ansible Tower 和开源版的 Ansible AWX。

第十六章，*Ansible Galaxy*，讨论了 Ansible Galaxy，这是一个社区贡献角色的在线存储库。在本章中，我们将发现一些最好的可用角色，如何使用它们，以及如何创建自己的角色并将其托管在 Ansible Galaxy 上。

第十七章，*使用 Ansible 的下一步*，教我们如何将 Ansible 集成到我们的日常工作流程中，从与协作服务的交互到使用内置调试器解决 playbook 的故障。我们还将看一些我如何使用 Ansible 的真实例子。

# 为了充分利用本书

为了充分利用本书，我假设你：

+   有一些在 Linux 和 macOS 上使用命令行的经验

+   对如何在 Linux 服务器上安装和配置服务有基本的了解

+   对服务和语言（如 Git、YAML 和虚拟化）有工作知识

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的说明操作。

一旦文件下载完成，请确保您使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learn-Ansible`](https://github.com/PacktPublishing/Learn-Ansible)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到！看看它们！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/LearnAnsible_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/LearnAnsible_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“这将创建一个密钥并将其存储在您的`user`目录中的`.ssh`文件夹中。”

代码块设置如下：

```
  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end
```

任何命令行输入或输出都将按如下方式编写：

```
$ sudo -H apt-get install python-pip
$ sudo -H pip install ansible
```

**Bold**：表示一个新术语、一个重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“要做到这一点，打开控制面板，然后点击程序和功能，然后点击打开或关闭 Windows 功能。”

警告或重要说明会出现在这样的形式中。提示和技巧会出现在这样的形式中。


# 第一章：Ansible 简介

在我们的第一章中，我们将研究 Ansible 出现之前的技术世界，以便了解为什么需要 Ansible。

在我们开始讨论 Ansible 之前，让我们快速讨论一下旧世界。我从 90 年代末开始就一直在使用服务器，大多数是用来提供网页服务的，而当时的情况已经完全不同了。为了让你了解我是如何操作我的早期服务器的，这里是我运行服务器的前几年的简要概述。

和当时的大多数人一样，我最初使用的是共享托管账户，在那时，我对服务器端的任何事情都几乎没有控制权。当时运行的网站已经超出了共享托管的范围。我转移到了专用服务器——我以为我可以在这里展示未来的系统管理员能力，但我错了。

我得到的服务器是 Cobalt RaQ 3，一个 1U 服务器设备，我认为它领先于当时的技术。然而，我没有 root 级别的访问权限，对于我需要做的一切，我都必须使用基于 Web 的控制面板。最终，我获得了一定级别的访问权限，可以使用 SSH 或 Telnet 访问服务器（我知道，那是早期），并开始通过在 Web 控制面板中进行更改并查看服务器上的配置文件来自学成为系统管理员。

过了一段时间，我换了服务器，这次我选择放弃任何基于 Web 的控制面板，只使用我在 Cobalt RaQ 上学到的知识来配置我的第一个真正的**Linux, Apache, MySQL, PHP** (**LAMP**)服务器，使用我做的笔记。我创建了自己的运行手册，包括一行命令来安装和配置我需要的软件，以及大量的涂鸦来帮助我解决问题并保持服务器运行。

当我为另一个项目获得了第二台服务器后，我意识到这可能是一个好时机，可以打字记录我的笔记，这样在需要部署服务器时就可以复制粘贴，我很高兴我这样做了，因为就在我的第一台服务器失败后不久，我的主机道歉并用一台更新的操作系统替换了它，配置也更高。

于是，我打开了我的 Microsoft Word 文件，里面有我做的笔记，然后逐条复制粘贴每条指令，根据我需要安装的内容和升级后的操作系统进行调整。几个小时后，我的服务器恢复正常运行，我的数据也被恢复了。

我学到的一个重要教训之一是，备份永远不嫌多，另一个是不要使用 Microsoft Word 来存储这些类型的笔记；命令并不在乎你的笔记是否都是用漂亮的格式和 Courier 字体编写的。它在乎的是使用正确的语法，而 Word 已经自动更正和格式化为打印格式。

所以，我在服务器上复制了历史文件，并将我的笔记转录成纯文本。这些笔记成为了接下来几年的基础，因为我开始对其中的部分内容进行脚本化，主要是那些不需要用户输入的部分。

这些命令片段、一行命令和脚本都是通过 Red Hat Linux 6 进行调整的，一直到 CentOS 3 和 4。

当我改变了角色，停止了从 Web 主机那里获取服务，并开始为 Web 主机工作时，事情变得复杂起来。突然间，我开始为可能有不同需求的客户构建服务器——没有一个服务器是相同的。

从这里开始，我开始使用 Kickstart 脚本、PXE 引导服务器、镜像服务器上的 gold master、虚拟机和开始提示正在构建的系统的信息的 bash 脚本。我也从只需要担心维护自己的服务器转变为需要登录数百个不同的物理和虚拟服务器，从属于我工作的公司的服务器到客户机器。

在接下来的几年里，我的单个文本文件迅速变成了一个复杂的笔记、脚本、预编译二进制文件和信息电子表格的集合，如果我诚实地说，这些东西只有我自己能理解。

虽然我已经开始使用 bash 脚本和串联命令来自动化我的日常工作的很多部分，但我发现我的日子仍然充满了手动运行所有这些任务，以及处理客户报告的问题和查询的服务台工作。

我的故事可能是许多人的典型，而使用的操作系统可能被认为是相当古老的。现在，使用 GUI 作为入口并转向命令行，同时保留常用命令的草稿本，是我听说过的一个很常见的过程。

我们将涵盖以下主题：

+   谁在背后支持 Ansible

+   Ansible 与其他工具的区别

+   Ansible 解决的问题

# Ansible 的故事

让我们快速看一下谁写了 Ansible，以及 Ansible 的含义。

# 这个术语

在讨论 Ansible 的起源之前，我们应该快速讨论一下名称的起源。术语 Ansible 是由科幻小说作家乌苏拉·勒·格恩创造的；它首次出现在她 1966 年首次出版的小说《洛坎农的世界》中。在故事的背景下，**Ansible**是一个虚构的设备，能够比光速更快地发送和接收消息。

1974 年，乌苏拉·勒·格恩的小说《被放逐者：一个模棱两可的乌托邦》出版；这本书通过探索（虚构的）数学理论的细节，展示了 Ansible 技术的发展，使得这样的设备成为可能。

这个术语后来被这个类型的其他一些著名作者使用，用来描述能够在星际距离上传递消息的通信设备。

# 这个软件

Ansible 软件最初是由 Michael DeHaan 开发的，他也是《Cobbler》的作者，该软件是在 DeHaan 为红帽公司工作时开发的。

Cobbler 是一个 Linux 安装服务器，允许您在网络中快速部署服务器；它可以帮助进行 DNS、DHCP、软件包更新和分发、虚拟机部署、物理主机的电源管理，以及新部署的服务器（无论是物理的还是虚拟的）交接给配置管理系统。

DeHaan 离开了红帽公司，为 Puppet 等公司工作，这是一个很好的选择，因为 Cobbler 的许多用户使用它来交给 Puppet 服务器管理一旦它们被配置。

离开 Puppet 几年后，DeHaan 在 2012 年 2 月 23 日对 Ansible 项目进行了第一次公开提交。最初的 README 文件给出了一个非常简单的描述，为 Ansible 最终将成为的基础奠定了基础：

"Ansible 是一个超级简单的 Python API，用于通过 SSH 执行'远程任务'。与我共同编写的 Func 一样，它希望避免使用 SSH 并拥有自己的守护程序基础设施，Ansible 希望成为完全不同和更简化，但仍然能够随着时间的推移更加模块化地增长。"

自第一次提交以来，在撰写本文时，已经有 3000 名贡献者在 38 个分支和 195 个发布中进行了超过 35,000 次提交。

2013 年，该项目发展壮大，Ansible, Inc.成立，为依赖该项目管理他们的教练和服务器的 Ansible 用户提供商业支持，无论是物理的、虚拟的还是托管在公共云上的。

Ansible, Inc.的成立，获得了 600 万美元的 A 轮融资，推出了商业版的 Ansible Tower，作为一个基于 Web 的前端，最终用户可以在那里消费基于角色的 Ansible 服务。

然后，在 2015 年 10 月，红帽宣布他们将以 1.5 亿美元收购 Ansible。在宣布中，当时担任红帽管理副总裁的 Joe Fitzgerald 被引述说：

“Ansible 是 IT 自动化和 DevOps 领域的领军者，有助于红帽在创造无摩擦的 IT 目标上迈出重要一步。”

在本书的过程中，您会发现原始 README 文件中的声明和 Red Hat 在收购 Ansible 时的声明仍然成立。

在我们开始动手安装 Ansible 之前，我们应该先了解一些围绕它的核心概念。

# Ansible 与其他工具

如果您比较第一个提交中的设计原则和当前版本，您会注意到虽然有一些增加和调整，但核心原则基本保持不变：

+   **无代理**：一切都应该由 SSH 守护程序、Windows 机器的 WinRM 协议或 API 调用来管理——不应该依赖于自定义代理或需要在目标主机上打开或交互的其他端口

+   **最小化**：您应该能够管理新的远程机器，而无需安装任何新软件，因为每台 Linux 主机通常都会在最小安装的一部分中安装至少 SSH 和 Python

+   **描述性**：您应该能够用机器和人都能读懂的语言描述您的基础架构、堆栈或任务

+   **简单**：设置过程和学习曲线应该简单且直观

+   **易于使用**：这应该是最容易使用的 IT 自动化系统

其中一些原则使 Ansible 与其他工具有很大不同。让我们来看看 Ansible 和 Puppet、Chef 等其他工具之间最基本的区别。

# 声明式与命令式

当我开始使用 Ansible 时，我已经实施了 Puppet 来帮助管理我管理的机器上的堆栈。随着配置变得越来越复杂，Puppet 代码变得非常复杂。这时我开始寻找一些解决我面临问题的替代方案。

Puppet 使用自定义的声明性语言来描述配置。然后，Puppet 将这个配置打包成一个清单，然后运行在每台服务器上的代理程序应用这个清单。

使用声明性语言意味着 Puppet、Chef 和其他配置工具（如 CFEngine）都使用最终一致性的原则运行，这意味着最终，在代理程序运行几次后，您的期望配置将就位。

另一方面，Ansible 是一种命令式语言，这意味着你不仅要定义所需结果的最终状态，并让工具决定如何达到这个状态，还要定义任务执行的顺序，以达到你所定义的状态。

我倾向于使用的例子如下。我们有一个配置，需要将以下状态应用到服务器上：

1.  创建一个名为`Team`的组

1.  创建一个名为`Alice`的用户并将她添加到`Team`组

1.  创建一个名为`Bob`的用户并将他添加到`Team`组

1.  给用户`Alice`提升的特权

这可能看起来很简单；然而，当你使用声明性语言执行这些任务时，你可能会发现，例如，以下情况发生：

+   **运行 1**：任务按以下顺序执行：2、1、3 和 4。这意味着在第一次运行时，由于名为`Team`的组不存在，添加用户`Alice`失败，这意味着`Alice`从未获得提升的特权。然而，组`Team`被添加，用户`Bob`被添加。

+   **运行 2**：同样，任务按照以下顺序执行：2、1、3 和 4。因为在运行 1 期间创建了`Team`组，所以现在创建了用户`Alice`，并且她也被赋予了提升的特权。由于`Team`组和用户`Bob`已经存在，它们保持不变。

+   **运行 3**：任务按照运行 1 和 2 的相同顺序执行；然而，由于已经达到了期望的配置，因此没有进行任何更改。

每次运行都会继续，直到配置或主机本身发生变化，例如，如果`Bob`真的惹恼了`Alice`，她使用她的提升的特权从主机中删除用户`Bob`。当代理下次运行时，`Bob`将被重新创建，因为这仍然是我们期望的配置，不管`Alice`认为`Bob`应该有什么访问权限。

如果我们使用命令式语言运行相同的任务，那么应该发生以下情况：

+   **运行 1**：任务按照我们定义的顺序执行，这意味着首先创建组，然后创建两个用户，最后应用`Alice`的提升特权

+   **运行 2**：同样，任务按照顺序执行，并进行检查以确保我们的期望配置已经就位

正如您所看到的，这两种方式都可以达到我们的最终配置，并且它们也强制执行我们的期望状态。使用声明性语言的工具可以声明依赖关系，这意味着我们可以简单地消除运行任务时遇到的问题。

然而，这个例子只有四个步骤；当您有几百个步骤在公共云平台上启动服务器，然后安装需要几个先决条件的软件时会发生什么？

这是我在开始使用 Ansible 之前发现自己处于的位置。Puppet 在强制执行我期望的最终配置方面做得很好；然而，在达到那里时，我发现自己不得不担心将大量逻辑构建到我的清单中，以达到我期望的状态。

令人讨厌的是，每次成功运行都需要大约 40 分钟才能完成。但由于我遇到了依赖问题，我不得不从头开始处理每次失败和更改，以确保我实际上是在解决问题，而不是因为事情开始变得一致而不得不重新开始——这不是在截止日期时想要的。

# 配置与编排

Ansible 与其他常常被比较的工具之间的另一个关键区别是，这些工具的大部分起源于被设计为部署和监控配置状态的系统。

它们通常需要在每个主机上安装代理，该代理会发现有关其安装主机的一些信息，然后回调到一个中央服务器，基本上说“嗨，我是服务器 XYZ，我可以请你给我配置吗？”然后服务器决定服务器的配置是什么样的，并将其发送给代理，然后代理应用它。通常，这种交换每 15 到 30 分钟发生一次——如果您需要强制执行服务器上的配置，这是很好的。

然而，Ansible 的设计方式使其能够充当编排工具；例如，您可以运行它在 VMware 环境中启动服务器，一旦服务器启动，它就可以连接到您新启动的机器并安装 LAMP 堆栈。然后，它永远不必再次连接到该主机，这意味着我们剩下的只是服务器、LAMP 堆栈，除了可能在文件中添加一些注释以表明 Ansible 添加了一些配置行之外，没有其他东西，但这应该是 Ansible 用于配置主机的唯一迹象。

# 基础设施即代码

在我们完成本章并继续安装 Ansible 之前，让我们快速讨论基础设施即代码，首先通过查看一些实际的代码来了解。以下 bash 脚本使用`yum`软件包管理器安装了几个 RPM 包：

```
#!/bin/sh
LIST_OF_APPS="dstat lsof mailx rsync tree vim-enhanced git whois iptables-services"
yum install -y $LIST_OF_APPS
```

以下是一个 Puppet 类，执行与之前的 bash 脚本相同的任务：

```
class common::apps {
  package{
    [
      'dstat',
      'lsof',
      'mailx',
      'rsync',
      'tree',
      'vim-enhanced',
      'git',
      'whois',
      'iptables-services',
    ]:
    ensure => installed,
  }
}
```

接下来，我们使用 SaltStack 执行相同的任务：

```
common.packages:
  pkg.installed:
    - pkgs:
      - dstat
      - lsof
      - mailx
      - rsync
      - tree
      - vim-enhanced
      - git
      - whois
      - iptables-services
```

最后，我们再次执行相同的任务，这次使用 Ansible：

```
- name: install packages we need
  yum:
    name: "{{ item }}"
    state: "latest"
  with_items:
    - dstat
    - lsof
    - mailx
    - rsync
    - tree
    - vim-enhanced
    - git
    - whois
    - iptables-services
```

即使不详细介绍，您也应该能够了解这三个示例各自在做什么。这三个示例虽然不严格属于基础设施，但都是基础设施即代码的有效示例。

在这里，您以与开发人员管理其应用程序源代码完全相同的方式管理管理基础设施的代码。您使用源代码控制，在一个中心可用的存储库中存储它，与同行合作，分支并使用拉取请求检查您的更改，并在可能的情况下编写和执行单元测试，以确保对基础设施的更改在部署到生产环境之前是成功的和无错误的。这应尽可能自动化。在提到的任务中的任何手动干预都应被视为潜在的故障点，您应该努力自动化任务。

这种基础设施管理方法有一些优势，其中之一是作为系统管理员，您正在使用与开发人员同样的流程和工具，这意味着适用于他们的任何程序也适用于您。这使工作体验更加一致，同时让您接触到以前可能没有接触或使用过的工具。

其次，更重要的是，它允许您分享您的工作。在采用这种方法之前，这种工作似乎对其他人来说是系统管理员专有的黑暗艺术。在公开进行这项工作可以让您的同行审查和评论您的配置，同时也可以让您做同样的事情来审查他们的配置。此外，您可以分享您的工作，以便其他人可以将其中的元素纳入他们自己的项目中。

# 摘要

在完成本章之前，我想结束一下我的个人经历。正如本章其他地方提到的，我从我的脚本和运行簿集合转移到了 Puppet，这很棒，直到我的需求不再局限于管理服务器配置和维护我管理的服务器的状态。

我需要开始在公共云中管理基础设施。当使用 Puppet 时，这个要求很快开始让我感到沮丧。当时，Puppet 对我需要用于基础设施的 API 的覆盖范围不足。我相信现在它的覆盖范围要好得多，但我也发现自己不得不在我的清单中构建太多的逻辑，涉及每个任务执行的顺序。

大约在 2014 年 12 月左右，我决定看看 Ansible。我知道这是因为我写了一篇名为*First Steps With Ansible*的博客文章，从那时起，我想我再也没有回头看过。自那时起，我已经向我的同事和客户介绍了 Ansible，并为 Packt 写了之前的书籍。

在本章中，我们回顾了我个人与 Ansible 以及与之相比的其他工具的历史，并讨论了这些工具之间的区别以及 Ansible 的起源。

在下一章中，我们将介绍如何安装 Ansible 并针对本地虚拟机运行我们的第一个 playbook。

# 进一步阅读

在本章中，我们提到了 Puppet 和 SaltStack：

+   Puppet 是一个运行服务器/代理配置的配置管理工具。它有两种版本——开源版本和由 Puppet 公司支持的企业版本。它是一个声明性系统，与 Ruby 密切相关。有关 Puppet 的更多信息，请参见[`puppet.com/`](https://puppet.com/)。

+   SaltStack 是另一个配置管理工具。它具有极高的可扩展性，虽然与 Ansible 共享设计方法，但它的工作方式类似于 Puppet，采用了服务器/代理的方式。您可以在[`saltstack.com/`](https://saltstack.com/)找到更多关于 SaltStack 的信息。

+   我还提到了我的博客，您可以在[`media-glass.es/`](https://media-glass.es/)找到。


# 第二章：安装和运行 Ansible

现在我们对 Ansible 的背景有了一些了解，我们将开始安装它，并且一旦安装完成，我们将对运行 CentOS 7 的测试虚拟机运行我们的第一组 playbooks。

本章将涵盖以下主题：

+   如何在 macOS 和 Linux 上安装 Ansible

+   在 Windows 10 专业版上使用 Linux 子系统运行 Ansible

+   启动一个测试虚拟机

+   playbooks 简介

# 技术要求

在本章中，我们将安装 Ansible，因此您需要一台能够运行它的机器。我将在本章的下一部分详细介绍这些要求。我们还将使用 Vagrant 在本地启动一个虚拟机。有一节介绍了安装 Vagrant 以及下载一个大小约为 400 MB 的 CentOS 7 Vagrant box。

您可以在本书附带的 GitHub 存储库中找到所有 playbooks 的完整版本[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter02`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter02)。

您还可以在作者的存储库中找到代码包：[`github.com/russmckendrick/learn-ansible-fundamentals-of-ansible-2x`](https://github.com/russmckendrick/learn-ansible-fundamentals-of-ansible-2x)。

# 安装 Ansible

让我们直接开始安装 Ansible。在本书中，我将假设您正在运行 macOS High Sierra 的 macOS 主机机器，或者安装了 Ubuntu 18.04 LTS 的 Linux 机器。虽然我们将涵盖在 Windows 10 专业版上使用 Linux 子系统运行 Ansible，但本书不支持使用 Windows 作为主机机器。

# 在 macOS 上安装

您可以在 macOS High Sierra 主机上以几种不同的方式安装 Ansible。我将涵盖它们两种。

由于我们正在讨论两种不同的安装方式，我建议在选择自己机器上的安装方法之前，先阅读本节以及最后的*优缺点*部分。

# Homebrew

第一种安装方法是使用一个叫做 Homebrew 的软件包。

Homebrew 是 macOS 的软件包管理器。它可以用来安装命令行工具和桌面软件包。它自称为*macOS 的缺失软件包管理器*，通常是我在干净安装或获得新电脑后安装的第一个工具之一。您可以在[`brew.sh/`](https://brew.sh/)找到更多关于该项目的信息。

要使用 Homebrew 安装 Ansible，您首先需要安装 Homebrew。要做到这一点，请运行以下命令：

```
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

在安装过程的每个步骤，安装程序都会告诉您它将要做什么，并提示您提供任何它需要的额外信息，以便完成安装。

安装完成后，或者如果您已经安装了 Homebrew，请运行以下命令来更新软件包列表，并检查您的 Homebrew 安装是否最佳：

```
$ brew update
$ brew doctor
```

根据您的安装时间或上次使用的时间，您可能会看到与以下截图不同的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e7098ac5-a5b9-4284-a9c4-0f78833b94a4.png)

接下来，我们可以通过运行以下命令来检查 Homebrew 为 Ansible 提供了哪些软件包：

```
$ brew search ansible
```

如您在以下截图中看到的结果，搜索返回了几个软件包：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/4f75c86c-ed03-493a-ab3a-d81ceb483151.png)

我们只需要 Ansible 软件包。您可以通过运行以下命令了解更多关于该软件包的信息：

```
$ brew info ansible
```

您可以在以下截图中看到命令的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/f2f7ce93-575f-4e4b-bafc-6d183b63b066.png)

如您所见，该命令返回将要安装的软件包的版本信息，以及有关在哪里可以查看安装软件包的公式代码的详细信息。在我们的情况下，您可以在[`github.com/Homebrew/homebrew-core/blob/master/Formula/ansible.rb`](https://github.com/Homebrew/homebrew-core/blob/master/Formula/ansible.rb)上查看公式的详细信息。

要使用 Homebrew 安装 Ansible，我们只需运行以下命令：

```
$ brew install ansible
```

这将下载并安装所有依赖项，然后安装 Ansible 软件包本身。根据您的计算机上已安装的依赖项数量，这可能需要几分钟。安装完成后，您应该看到类似以下屏幕截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/20eedb32-0c65-4c4a-aca8-739c34af7c30.png)

如您从前面的屏幕截图中所见，Homebrew 在输出中非常详细，为您提供了它正在做什么以及如何使用它安装的软件包的详细信息。

# pip 方法

第二种方法`pip`是一种更传统的安装和配置 Python 软件包的方法。

`pip`是 Python 软件的软件包管理器。这是**pip install packages**的递归缩写。这是从**Python Package Index** (**PyPI**)安装软件包的良好前端。您可以在[`pypi.python.org/pypi/`](https://pypi.python.org/pypi/)上找到索引。

根据您在计算机上安装了什么，您可能需要安装`pip`。要做到这一点，请运行以下命令：

```
$ easy_install pip
```

这将使用 macOS 默认附带的`easy_install`安装程序安装`pip`。安装完成后，您可以通过运行以下命令安装 Ansible：

```
$ sudo -H pip install ansible
```

由于我们使用了`sudo`命令，因此系统会提示您输入密码，就像 Homebrew 一样。此命令将下载并安装运行 Ansible 所需的所有先决条件。虽然它与 Homebrew 一样详细，但其输出包含有关其所做的工作的信息，而不是下一步该做什么的提示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/18f6320e-0289-407a-a27f-61c8b0f0ed55.png)

正如您所看到的，许多要求已经得到满足。

# 优缺点

因此，现在我们已经介绍了在 macOS 上安装 Ansible 的一些不同方法，哪种方法最好？嗯，这没有真正的答案，因为这取决于个人偏好。这两种方法都将安装最新版本的 Ansible。但是，Homebrew 往往会比当前版本晚一两周。

如果您已经使用 Homebrew 安装了许多软件包，那么您已经习惯于运行以下命令：

```
$ brew update
$ brew upgrade
```

偶尔更新已安装的软件包到最新版本。如果您已经这样做了，那么使用 Homebrew 来管理您的 Ansible 安装就是有意义的。

如果您不是 Homebrew 用户，并且想要确保立即安装最新版本，则使用`pip`命令安装 Ansible。升级到最新版本的 Ansible 就像运行以下命令一样简单：

```
$ sudo -H pip install ansible --upgrade --ignore-installed setuptools
```

我发现我需要使用`--ignore-installed setuptools`标志，因为 macOS 管理的版本与 Ansible 更新的版本存在问题和冲突。我没有发现这会引起任何问题。

如果需要的话，您可以使用 Homebrew 和`pip`安装旧版本的 Ansible。要使用 Homebrew 进行此操作，只需运行以下命令来删除当前版本：

```
$ brew uninstall ansible
```

然后，您可以通过运行以下命令安装软件包的早期版本：

```
$ brew install ansible@2.0
```

或者，要安装更早的版本，您可以使用以下命令：

```
$ brew install ansible@1.9
```

要了解要安装的软件包的确切版本的详细信息，您可以运行以下两个命令中的一个：

```
$ brew info ansible@2.0
$ brew info ansible@1.9
```

虽然这将安装一个早期版本，但您在安装哪个版本方面没有太多选择。如果您确实需要一个确切的版本，可以使用`pip`命令进行安装。例如，要安装 Ansible 2.3.1.0，您需要运行：

```
$ sudo -H pip install ansible==2.3.1.0 --ignore-installed setuptools
```

你永远不应该需要这样做。但是，我发现在某些情况下，我不得不降级来帮助调试由升级到较新版本引入的*怪癖*。

正如前面提到的，我大部分时间都是在 macOS 机器前度过的，所以我使用哪种方法呢？主要是使用 Homebrew，因为我安装了几个其他工具。但是，如果我需要回滚到以前的版本，我会使用`pip`，然后问题解决后再返回到 Homebrew。

# 在 Linux 上安装

在 Ubuntu 18.04 上安装 Ansible 有几种不同的方法。然而，我这里只会介绍其中一种。虽然 Ubuntu 有可用的软件包可以使用`apt`安装，但它们往往很快就会过时，并且通常落后于当前版本。

**高级打包工具**（**APT**）是 Debian 系统的软件包管理器，包括 Ubuntu。它用于管理`.deb`文件。

因此，我们将使用`pip`。首先要做的是安装`pip`，可以通过运行以下命令来完成：

```
$ sudo -H apt-get install python-pip
```

一旦安装了`pip`，安装 Ansible 的说明与在 macOS 上安装相同。只需运行以下命令：

```
$ sudo -H pip install ansible
```

这将下载并安装 Ansible 及其要求，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/80c75687-b413-4b5d-8198-80961d084820.png)

安装完成后，您可以使用以下命令升级它：

```
$ sudo -H pip install ansible --upgrade
```

请注意，这一次我们不需要忽略任何内容，因为默认安装不应该有任何问题。此外，降级 Ansible 是相同的命令：

```
$ sudo -H pip install ansible==2.3.1.0 --ignore-installed setuptools
```

上述命令应该适用于大多数 Linux 发行版，如 CentOS、Red Hat Enterprise Linux、Debian 和 Linux Mint。

# 在 Windows 10 专业版上安装

我们要介绍的最后一个平台是 Windows 10 专业版；嗯，有点像。没有支持的方法可以在 Windows 机器上本地运行 Ansible 控制器。因此，我们将使用 Windows 的 Linux 子系统。

这是一个功能，在撰写本文时，它处于测试版，只适用于 Windows 10 专业版用户。要启用它，首先需要启用开发人员模式。要做到这一点，打开 Windows 10 设置应用，然后切换到开发人员模式，可以在更新和安全下找到，然后点击开发人员。

启用开发人员模式后，您将能够启用 shell。要做到这一点，打开控制面板，然后点击程序和功能，然后点击打开或关闭 Windows 功能。在功能列表中，您应该看到列出了 Windows 子系统的 Linux（Beta）。选中它旁边的框，然后点击确定。您将被提示重新启动计算机。重新启动后，点击开始菜单，然后键入`bash`。这将触发安装过程。您应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/948c2393-4d7e-4297-b4eb-9b0aecb6b589.png)

下载后，它将提取并安装子系统。您将被问到一些问题。根据需要，整个过程将需要 5 到 10 分钟。安装完成后，您现在应该在 Windows 机器上运行一个完整的 Ubuntu 16.04 系统。您可以通过运行以下命令来检查：

```
$ cat /etc/*release
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/375eaa66-603d-42ec-bf86-2c3a6f7bd8ad.png)

从这里，您可以运行以下命令来安装 Ansible：

```
$ sudo -H apt-get install python-pip
$ sudo -H pip install ansible
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d8aef965-0e43-4577-80f1-cb3e6de99982.png)

如您所见，一切都像在运行 Ubuntu 机器一样工作，使您能够以完全相同的方式运行和维护您的 Ansible 安装。

**Windows 子系统 Linux**（**WSL**）并不是在虚拟机上运行。它是完全嵌入到 Windows 10 专业版中的本机 Linux 体验。它针对需要作为工具链一部分运行 Linux 工具的开发人员。虽然对 Linux 命令的整体支持非常出色，但我建议阅读由微软撰写和维护的 FAQ，以了解子系统的限制和任何怪癖。FAQ 可以在[`docs.microsoft.com/en-us/windows/wsl/faq/`](https://docs.microsoft.com/en-us/windows/wsl/faq/)找到。

正如前面提到的，虽然这是在 Windows 机器上运行 Ansible 控制节点的一种可行方式，但我们将在未来的章节中涵盖的一些其他工具可能无法在 Windows 上运行。因此，虽然您可以按照 Ubuntu 的说明进行操作，但某些部分可能无法正常工作。在可能的情况下，我会添加一条说明，说明它可能无法在基于 Windows 的系统上运行。

# 启动虚拟机

为了启动一个虚拟机来运行我们的第一组 Ansible 命令，我们将使用 Vagrant。

请注意，如果您正在运行 WSL，这些说明可能不起作用。

Vagrant 是由 HashiCorp 开发的虚拟机管理器。它可以管理本地和远程虚拟机，并支持诸如 VirtualBox、VMware 和 Hyper-V 之类的 hypervisors。

要在 macOS 上安装 Vagrant，我们可以使用 Homebrew 和 cask。要安装 cask，运行以下命令：

```
$ brew install cask
```

VirtualBox 是面向基于 x86 的计算机的开源 hypervisor。它目前由 Oracle 开发，并支持软件和硬件虚拟化。

默认情况下，Vagrant 使用 VirtualBox。安装了 cask 后，您可以通过运行以下命令来使用 VirtualBox 和 Vagrant：

```
$ brew cask install virtualbox vagrant
```

要在 Ubuntu 上安装，可以运行以下命令：

```
$ sudo apt-get install virtualbox vagrant
```

接下来，如果您还没有，我们需要为您的用户生成一个私钥和公钥。要做到这一点，运行以下命令，但如果您已经有一个密钥，可以跳过这部分：

```
$ ssh-keygen -t rsa -C "youremail@example.com"
```

这将创建一个密钥并将其存储在您的用户目录中的`.ssh`文件夹中。我们将使用此密钥注入到我们的 Vagrant 管理的 CentOS 7 虚拟机中。要启动虚拟机或 box（正如 Vagrant 所称），我们需要一个`Vagrantfile`。这是 Vagrant 用来创建和启动 box 的配置。

我们将使用的`Vagrantfile`如下所示。您还可以在本书附带的代码示例的`Chapter02`文件夹中找到副本，也可以在 GitHub 存储库中找到，地址为[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter02`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter02)：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME    = "centos/7"
BOX_IP      = "192.168.50.4"
DOMAIN      = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY  = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY,
  "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY, destination:
  "~/.ssh/authorized_keys"

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

从上面的文件中可以看出，有一些事情正在进行。首先，在顶部部分，我们正在为以下内容定义一些变量：

+   `API_VERSION`：这是要使用的 Vagrant API 版本。这应该保持为`2`。

+   `BOX_NAME`：这是我们想要使用的基本镜像。在我们的情况下，这是官方的 CentOS 7 Vagrant box 镜像，可以在[`app.vagrantup.com/centos/boxes/7`](https://app.vagrantup.com/centos/boxes/7)找到。

+   `BOX_IP`：这是我们要启动的机器的私有 IP 地址。通常情况下，您不应该需要硬编码 IP 地址，但在我们的情况下，我们将需要一个可解析的主机名和一个固定的 IP 地址，以便在本章的下一节中的示例中使用。

+   `DOMAIN`：这是用于配置机器主机名的域名。我们使用[`nip.io/`](http://nip.io/)服务。这提供了免费的通配符 DNS 条目。这意味着我们的域名`192.168.50.4.nip.io`将解析为`192.168.50.4`。

+   `PRIVATE_KEY`：这是您的私钥的路径。一旦启动虚拟机，将用它来 SSH 进入虚拟机。

+   `PUBLIC_KEY`：这是你的公钥的路径。当机器正在启动时，这将被注入到主机中，这意味着我们可以使用我们的私钥访问它。

下一节将采用前面的值并配置 Vagrant 框。然后我们定义了仅适用于`Vagrantfile`支持的两个提供者的设置。正如你所看到的，该文件将使用 VirtualBox 或者，如果你已经安装了它，VMware Fusion 来启动一个框。

有关 Vagrant 的 VMware 提供者插件的更多信息，请访问[`www.vagrantup.com/vmware/`](https://www.vagrantup.com/vmware/)。请注意，Vagrant 的这一部分需要许可证，需要收费，并且需要在主机机器上安装 VMware Fusion 或 Workstation。

现在我们有了`Vagrantfile`，我们只需要运行以下命令来启动 Vagrant 框：

```
$ vagrant up
```

如果你没有传递提供者，它将默认使用 VirtualBox。如果你像我一样有 VMware 插件，你可以运行以下命令：

```
$ vagrant up --provider=vmware_fusion
```

下载适当的框文件并配置虚拟机需要几分钟的时间：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/9749465b-0285-464c-a1d9-405f1a4dbb69.png)

正如你从终端输出中所看到的，启动过程非常详细，并且在每个阶段都会收到有用的反馈。

一旦 Vagrant 框被启动，你可以通过运行以下命令来检查与它的连接。这将以 Vagrant 用户的身份登录到 Vagrant 框，并检查主机名和内核的详细信息：

```
$ vagrant ssh
$ hostname
$ uname -a
$ exit
```

你的终端应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e847bd68-9500-4410-9e25-7b6cf0c52211.png)

正如你所看到的，因为我们已经告诉 Vagrant 在访问该框时使用哪个私钥，我们已经直接进入了该框，并且可以运行命令而没有问题。然而，在下一节中，我们将不会使用`vagrant ssh`命令，这就是为什么我们需要将我们的公钥注入到主机中。相反，我们将直接从我们的主机机器通过 SSH 连接到该机器。为了测试这一点，你应该能够运行以下命令：

```
$ ssh vagrant@192.168.50.4.nip.io
```

你应该被要求通过输入`yes`来建立主机的真实性。一旦你登录，你就可以运行以下命令：

```
$ hostname
$ uname -a
$ exit
```

你的终端应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/690c1845-96f9-4f30-b298-193c874fe3b1.png)

正如你所看到的，我们已经使用 Vagrant 用户解析并连接到`192.168.50.4.nip.io`，并且已经使用我们的私钥进行了身份验证。在我们进入下一节并尝试第一次运行 Ansible 之前，我们应该讨论一下 Vagrant provisioners。

毫无疑问，你可能已经查看了 Vagrant 网站，网址是[`vagrantup.com/`](http://vagrantup.com/)，并且可能已经注意到 Vagrant 实际上支持 Ansible。如果我们使用 Ansible provisioner，那么 Vagrant 将动态创建一个主机清单，并在启动过程中针对该框运行我们的 playbook。在我们看这个之前，我认为我们理解主机清单的工作方式是很重要的，所以我们将在下一章中看一下 Ansible provisioner。

然而，在那之前，让我们来看一些基本的 playbook 以及我们如何使用 Ansible 与我们的 Vagrant 框进行交互。

# playbook 简介

在 IT 中，playbook 通常是发生某事时由某人运行的一组指令；有点模糊，我知道，但请跟着我。这些范围从构建和配置新的服务器实例，到如何部署代码更新以及如何在出现问题时处理问题。

在传统意义上，playbook 通常是用户遵循的一组脚本或指令，虽然它们旨在引入系统的一致性和一致性，但即使怀着最好的意图，这几乎从来没有发生过。

这就是 Ansible 的用武之地。使用 Ansible playbook，您基本上是在说应用这些更改和命令对这些主机集合，而不是让某人登录并手动开始运行操作手册。

在运行 playbook 之前，让我们讨论如何向 Ansible 提供要定位的主机列表。为此，我们将使用`setup`命令。这只是简单地连接到一个主机，然后尽可能多地获取有关主机的信息。

# 主机清单

要提供主机列表，我们需要提供一个清单列表。这是以 hosts 文件的形式。

在其最简单的形式中，我们的 hosts 文件可以包含一行：

```
192.168.50.4.nip.io ansible_user=vagrant
```

这告诉 Ansible 的是，我们要联系的主机是`192.168.50.4.nip.io`，并且要使用用户名`vagrant`。如果我们没有提供用户名，它将退回到您作为 Ansible 控制主机登录的用户，就像在我的情况下一样——用户`russ`，这个用户在 Vagrant 框中不存在。在存储库的`Chapter02`文件夹中有一个名为`hosts-simple`的 hosts 文件的副本，与我们用来启动 Vagrant 框的`Vagrantfile`一起。

运行`setup`命令，我们需要从存储`hosts-simple`的相同文件夹中运行以下命令：

```
$ ansible -i hosts-simple 192.168.50.4.nip.io -m setup
```

您应该看到一些类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/8cf0984f-f09a-49ba-a141-12e7bad49015.png)

正如您从前面的屏幕截图中所看到的，Ansible 很快就找到了我们的 Vagrant 框的大量信息。从屏幕截图中，您可以看到机器上配置的两个 IP 地址，以及 IPv6 地址。它记录了时间和日期，如果您滚动查看自己的输出，您将看到返回了大量详细的主机信息。

回到我们运行的命令：

```
$ ansible -i hosts-simple 192.168.50.4.nip.io -m setup
```

正如您所看到的，我们正在使用`-i`标志加载`hosts-simple`文件。我们也可以使用`--inventory=hosts-simple`，这样就加载了我们的清单文件。命令的下一部分是要目标主机。在我们的情况下，这是`192.168.50.4.nip.io`。命令的最后一部分`-m`告诉 Ansible 使用`setup`模块。我们也可以使用`--module-name=setup`。

这意味着，如果我们没有使用简写，完整的命令将是：

```
$ ansible --inventory=hosts-simple 192.168.50.4.nip.io --module-name=setup
```

如前所述，`hosts-simple`文件是我们可以得到的最基本的。以下是一个更常见的主机清单文件：

```
box ansible_host=192.168.50.4.nip.io

[boxes]
box

[boxes:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

在与`hosts-simple`文件相同的文件夹中有一个名为`hosts`的文件的副本。正如您所看到的，有很多事情要做，所以让我们快速地从上到下地进行一下工作。

第一行定义了我们的单个主机。与简单示例不同，我们将称呼我们的`hosts box`并使用`ansible_host`，因此我们正在向 Ansible 提供它可以 SSH 到的详细信息。这意味着我们现在可以在引用`192.168.50.4.nip.io`时使用名称 box。这意味着我们的命令现在看起来像这样：

```
$ ansible -i hosts box -m setup
```

文件中的下一步是创建一个名为`boxes`的主机组，在该组中，我们添加了我们的单个主机`box`。这意味着我们也可以运行：

```
$ ansible -i hosts boxes -m setup
```

如果我们的组中有不止一个主机，那么前面的命令将循环遍历所有这些主机。`hosts`文件的最后一部分为`boxes`组中的所有主机设置了一些常见的配置选项。在这种情况下，我们告诉 Ansible 该组中的所有主机都在使用 SSH，用户是`vagrant`，应该使用`~/.ssh/id_rsa`的私钥，还告诉不要在连接时检查主机密钥。

我们将在后面的章节中重新访问清单主机文件。从现在开始，我们将使用`hosts`文件来定位`boxes`组。

# Playbooks

在上一节中，运行`ansible`命令允许我们调用单个模块。在本节中，我们将看看如何调用多个模块。以下 playbook 称为`playbook.yml`。它调用了我们在上一节中调用的`setup`模块，然后使用`debug`模块将消息打印到屏幕上：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  tasks:
    - debug:
        msg: "I am connecting to {{ ansible_nodename }} which is running {{ ansible_distribution }} {{ ansible_distribution_version }}"
```

在我们开始分解配置之前，让我们看一下运行 playbook 的结果。为此，请使用以下命令：

```
$ ansible-playbook -i hosts playbook01.yml
```

这将连接到我们的 Vagrant box，在系统上收集信息，然后以消息的形式返回我们想要的信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/3d8e67b7-be81-44c0-9ba5-0083ee8f84fb.png)

您将注意到 playbook 的第一件事是它是用**YAML**编写的，这是一个递归缩写，代表**YAML 不是标记语言**。YAML 旨在成为一个可供所有编程语言使用的人类可读的数据序列化标准。它通常用于帮助定义配置。

在 YAML 中缩进非常重要，因为它用于嵌套和定义文件的区域。让我们更详细地看一下我们的 playbook：

```
---
```

尽管这些行看起来可能不多，但它们被用作文档分隔符，因为 Ansible 将所有 YAML 文件编译成单个文件；稍后会详细介绍。对于 Ansible 来说，知道一个文档何时结束，另一个文档何时开始是很重要的。

接下来，我们有 playbook 的配置。正如您所看到的，这是缩进开始发挥作用的地方：

```
- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo
  tasks:
```

`-`告诉 Ansible 这是一个部分的开始。然后使用键值对。这些是：

+   `hosts`: 这告诉 Ansible 在 playbook 中目标主机或主机组。这必须在主机清单中定义，就像我们在上一节中介绍的那样。

+   `gather_facts`: 这告诉 Ansible 在首次连接到主机时运行`setup`模块。然后在运行的其余时间内，此信息对 playbook 可用。

+   `become`: 这是因为我们连接到主机时作为基本用户存在的。在这种情况下，Vagrant 用户。Ansible 可能没有足够的访问权限来执行我们告诉它的一些命令，因此这指示 Ansible 以 root 用户的身份执行其所有命令。

+   `become_method`: 这告诉 Ansible 如何成为 root 用户；在我们的情况下，Vagrant 配置了无密码的`sudo`，所以我们使用`sudo`。

+   `tasks`: 这些是我们可以告诉 Ansible 在连接到目标主机时运行的任务。

从这里开始，您会注意到我们再次移动了缩进。这定义了配置的另一部分。这次是为了任务：

```
    - debug:
        msg: "I am connecting to {{ ansible_nodename }} which is running {{ ansible_distribution }} {{ ansible_distribution_version }}"
```

正如我们已经看到的，我们正在运行的唯一任务是`debug`模块。此模块允许我们在运行 playbook 时显示输出。

您可能已经注意到花括号之间的信息是来自`setup`模块的键。在这里，我们告诉 Ansible 在使用键的任何地方替换每个键的值——我们将在我们的 playbook 中经常使用这个。我们还将定义自己的键值，以便在 playbook 运行中使用。

让我们通过添加另一个任务来扩展我们的 playbook。以下内容可以在`playbook02.yml`中找到：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  tasks:
    - debug:
        msg: "I am connecting to {{ ansible_nodename }} which is running {{ ansible_distribution }} {{ ansible_distribution_version }}"
    - yum:
        name: "*"
        state: "latest"
```

正如您所看到的，我们添加了第二个调用`yum`模块的任务。该模块旨在帮助我们与 CentOS 和其他基于 Red Hat 的操作系统使用的软件包管理器`yum`进行交互。我们在这里设置了两个关键值：

+   `name`: 这是一个通配符。它告诉 Ansible 使用所有安装的软件包，而不仅仅是单个命名的软件包。例如，我们可以在这里只使用 HTTPD 来仅针对 Apache。

+   `state`: 在这里，我们告诉 Ansible 确保我们在名称键中定义的软件包是`latest`版本。由于我们已经命名了所有安装的软件包，这将更新我们安装的所有内容。

使用以下命令运行 playbook：

```
$ ansible-playbook -i hosts playbook02.yml
```

这将给我们以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/8b59dcc9-f7f7-4c0f-b30f-21e34df5e69e.png)

`yum`任务在主机`box`上被标记为`changed`。这意味着软件包已经更新。再次运行相同的命令会显示以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/07d0d0b9-b6f0-40aa-8e1c-5f867cb1418a.png)

正如你所看到的，`yum`任务现在在我们的主机上显示为`ok`。这是因为当前没有需要更新的软件包。

在我们完成对 playbooks 的快速查看之前，让我们做一些更有趣的事情。下面的 playbook，名为`playbook03.yml`，将安装、配置和启动 NTP 服务到我们的 Vagrant box。它还向我们的 playbook 添加了一些新的部分，并使用了一个模板：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  vars:
    ntp_servers:
      - "0.centos.pool.ntp.org"
      - "1.centos.pool.ntp.org"
      - "2.centos.pool.ntp.org"
      - "3.centos.pool.ntp.org"

  handlers:
    - name: "restart ntp"
      service:
        name: "ntpd"
        state: "restarted"

  tasks:
    - debug:
        msg: "I am connecting to {{ ansible_nodename }} which is
        running {{ ansible_distribution }}
        {{ ansible_distribution_version }}"
    - yum:
        name: "*"
        state: "latest"
    - yum:
        name: "{{ item }}"
        state: "installed"
      with_items:
        - "ntp"
        - "ntpdate"
    - template:
        src: "./ntp.conf.j2"
        dest: "/etc/ntp.conf"
      notify: "restart ntp"
```

在我们通过 playbook 的添加之前，让我们运行它，以了解你从 Ansible 那里得到的反馈：

```
$ ansible-playbook -i hosts playbook03.yml
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/db4b6a60-68a5-4f4f-8fea-3d589806a565.png)

这一次，我们有三个`changed`任务。再次运行 playbook 会显示以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/92319ee8-6dec-4398-a651-359b21420272.png)

正如预期的那样，因为我们没有改变 playbook 或 Vagrant box 上的任何东西，所以没有任何变化，Ansible 报告一切都是`ok`。

让我们回到我们的 playbook 并讨论这些添加。你会注意到我们添加了两个新的部分，`vars`和`handlers`，以及两个新的任务，第二个任务使用了`yum`模块，最后一个任务使用了`template`模块。

`vars`部分允许我们配置自己的键值对。在这种情况下，我们提供了一个 NTP 服务器列表，稍后将在 playbook 中使用：

```
  vars:
    ntp_servers:
      - "0.centos.pool.ntp.org"
      - "1.centos.pool.ntp.org"
      - "2.centos.pool.ntp.org"
      - "3.centos.pool.ntp.org"
```

正如你所看到的，我们实际上为相同的键提供了四个不同的值。这些将用于`template`任务。我们也可以这样写：

```
  vars:
    ntp_servers: [ "0.centos.pool.ntp.org", "1.centos.pool.ntp.org",
    "2.centos.pool.ntp.org", "3.centos.pool.ntp.org" ]
```

然而，这有点难以阅读。新的下一部分是`handlers`。处理程序是分配了一个名称的任务，并且根据任务的变化在 playbook 运行结束时调用：

```
  handlers:
    - name: "restart ntp"
      service:
        name: "ntpd"
        state: "restarted"
```

在我们的情况下，`restart ntp`处理程序使用`service`模块来重新启动`ntpd`。接下来，我们有两个新任务，首先是一个安装 NTP 服务和`ntpdate`软件包的任务，使用`yum`：

```
   - yum:
      name: "{{ item }}"
      state: "installed"
     with_items:
      - "ntp"
      - "ntpdate"
```

因为我们正在安装两个软件包，我们需要一种方法来为`yum`模块提供两个不同的软件包名称，这样我们就不必为每个软件包安装编写两个不同的任务。为了实现这一点，我们使用了`with_items`命令，作为任务部分的一部分。请注意，这是`yum`模块的附加部分，并不是模块的一部分——你可以通过缩进来判断。

`with_items`命令允许你为任务提供一个变量或项目列表。无论`{{ item }}`在哪里使用，它都将被`with_items`值的内容替换。

playbook 的最后一个添加是以下任务：

```
   - template:
      src: "./ntp.conf.j2"
      dest: "/etc/ntp.conf"
     notify: "restart ntp"
```

这个任务使用了`template`模块。从我们的 Ansible 控制器读取一个模板文件，处理它并上传处理后的模板到主机。一旦上传，我们告诉 Ansible，如果配置文件有任何更改，就通知`restart ntp`处理程序。

在这种情况下，模板文件是与 playbooks 相同文件夹中的`ntp.conf.j2`文件，如`src`选项中定义的。这个文件看起来是这样的：

```
# {{ ansible_managed }}
driftfile /var/lib/ntp/drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1 
restrict ::1
{% for item in ntp_servers %}
server {{ item }} iburst
{% endfor %}
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
```

文件的大部分是标准的 NTP 配置文件，还添加了一些 Ansible 部分。第一个添加是第一行：

```
# {{ ansible_managed }}
```

如果没有这一行，每次我们运行 Ansible 时，文件都会被上传，这将被视为一次变更，并且`restart ntp`处理程序将被调用，这意味着即使没有任何变化，NTP 也会被重新启动。

接下来的部分循环遍历了我们在 playbook 的`vars`部分中定义的`ntp_servers`值：

```
{% for item in ntp_servers %}
server {{ item }} iburst
{% endfor %}
```

对于每个值，添加一行包含服务器、然后是值，然后是`iburst`。您可以通过 SSH 连接到 Vagrant 机器并打开`/etc/ntp.conf`来查看此输出：

```
$ vagrant ssh
$ cat /etc/ntp.conf
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/1b5665fd-615b-479b-9087-f1652aa728ec.png)

从完全呈现的文件的前述截图中可以看出，我们在第一行上有注释，指出该文件由 Ansible 管理，还有四行包含要使用的 NTP 服务器的内容。

最后，您可以通过运行以下命令检查 NTP 是否按预期运行： 

```
$ vagrant ssh
$ sudo systemctl status ntpd
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/bf97de68-1d85-49c9-9183-50853e18938f.png)

从前述输出中可以看出，NTP 已加载并按预期运行。让我们通过运行以下命令删除 Vagrant 框架并启动一个新的框架：

```
$ vagrant destroy
```

然后通过运行以下两个命令之一再次启动该框：

```
$ vagrant up $ vagrant up --provider=vmware_fusion
```

一旦框架启动运行，我们可以使用以下命令运行最终的 playbook：

```
$ ansible-playbook -i hosts playbook03.yml
```

一两分钟后，您应该会收到 playbook 运行的结果。您应该会看到五个`changed`和六个`ok`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/375b83d8-6fe7-48c7-aece-748000af3802.png)

第二次运行只会显示五个`ok`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/eb40006e-dc8a-43bc-832a-bf17a0dec629.png)

我们第一次运行时得到六个`ok`，第二次运行时得到五个`ok`的原因是自第一次运行以来没有发生任何变化。因此，重启 NTP 的处理程序从未被通知，因此重新启动服务的任务从未执行。

完成示例 playbook 后，您可以使用以下命令终止正在运行的框架：

```
$ vagrant destroy
```

我们将在下一章中再次使用该框。

# 总结

在本章中，我们通过本地安装 Ansible，然后使用 Vagrant 启动虚拟机进行了第一步。我们了解了基本的主机清单文件，并使用 Ansible 命令针对我们的虚拟机执行了单个任务。

然后，我们查看了 playbooks，首先是一个基本的 playbook，返回了有关我们目标的一些信息，然后进展到一个更新所有已安装的操作系统包并安装和配置 NTP 服务的 playbook。

在下一章中，我们将看看其他可以使用的 Ansible 命令。

# 问题

1.  使用`pip`安装 Ansible 的命令是什么？

1.  真或假：在使用 Homebrew 时，您可以选择要安装或回滚到哪个版本的 Ansible。

1.  真或假：Windows 子系统运行在虚拟机中。

1.  列出三个 Vagrant 支持的 hypervisors。

1.  说明主机清单是什么。

1.  真或假：YAML 文件中的缩进对于它们的执行非常重要，而不仅仅是装饰性的。

1.  更新最终的 playbook 以安装您选择的服务，并通知处理程序以其默认配置启动服务。

# 进一步阅读

在这一章中，我们使用了以下 Ansible 模块，你可以在以下链接中找到每个模块的更多信息：

+   `setup`: [`docs.ansible.com/ansible/latest/setup_module.html`](http://docs.ansible.com/ansible/latest/setup_module.html)

+   `debug`[:](http://docs.ansible.com/ansible/latest/setup_module.html) [`docs.ansible.com/ansible/latest/debug_module.html`](http://docs.ansible.com/ansible/latest/debug_module.html)

+   `yum`: [`docs.ansible.com/ansible/latest/yum_module.html`](http://docs.ansible.com/ansible/latest/yum_module.html)

+   `service`: [`docs.ansible.com/ansible/latest/service_module.html`](http://docs.ansible.com/ansible/latest/service_module.html)


# 第三章：Ansible 命令

在继续编写和执行更高级的 playbook 之前，我们将看一下内置的 Ansible 命令。在这里，我们将介绍组成 Ansible 的一组命令的用法。在本章末尾，我们还将安装一些第三方工具，其中一个是清单图形化工具，它可以让我们可视化我们的主机，另一个允许你记录你的 playbook 运行。

本章将涵盖以下主题：

+   内置命令：

+   `ansible`

+   `ansible-config`

+   `ansible-console`

+   `ansible-doc`

+   `ansible-inventory`

+   `ansible-vault`

+   第三方命令：

+   `ansible-inventory-grapher`

+   `ara`

# 技术要求

我们将重复使用上一章中启动的 Vagrant box；如果你没有跟着做，请参考上一章关于如何安装 Ansible 和 Vagrant 的说明。本章中有一些 playbook 示例；你可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter03`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter03)找到完整的示例。

# 内置命令

当我们安装 Ansible 时，安装了几个不同的命令。这些是：

+   `ansible`

+   `ansible-config`

+   `ansible-console`

+   `ansible-doc`

+   `ansible-inventory`

+   `ansible-vault`

在后续章节中，我们将涵盖一些命令，比如`ansible-galaxy`、`ansible-playbook`和`ansible-pull`，所以在本章中我不会详细介绍这些命令。让我们从列表顶部开始，使用一个我们已经使用过的命令。

# Ansible

现在，你可能会认为`ansible`是我们在整本书中将经常使用的最常见的命令，但事实并非如此。

`ansible`命令实际上只用于针对单个或一组主机运行临时命令。在上一章中，我们创建了一个目标为单个本地虚拟机的主机清单文件。在本章中，让我们来看看如何针对在 DigitalOcean 上运行的四个不同主机进行操作；我的主机文件如下所示：

```
ansible01 ansible_host=46.101.92.240
ansible02 ansible_host=159.65.63.218
ansible03 ansible_host=159.65.63.217
ansible04 ansible_host=138.68.145.116

[london]
ansible01
ansible02

```

```
[nyc]
ansible03
ansible04

[digitalocean:children]
london
nyc

[digitalocean:vars]
ansible_connection=ssh
ansible_user=root
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

正如你所看到的，我有四个主机，`ansible01` > `ansible04`。我的前两个主机在一个名为`london`的组中，我的后两个主机在一个名为`nyc`的组中。然后我将这两个组合并创建了一个名为`digitalocean`的组，并且我使用这个组来应用一些基本配置，基于我启动的主机。

使用`ping`模块，我可以通过运行以下命令检查与主机的连接：

```
$ ansible -i hosts london -m ping
$ ansible -i hosts nyc -m ping
```

从这些结果中可以看出，所有四个主机都返回了`pong`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/eacb9b7b-708c-4dba-b865-95e45fd84d8f.png)

我也可以通过以下方式一次性针对所有四个主机进行操作：

```
$ ansible -i hosts all -m ping
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/1585a18f-2fa3-421b-92aa-75c03d3a3af2.png)

现在我们可以通过 Ansible 访问我们的主机，可以使用一些临时命令来操作它们；让我们从一些基本的开始：

```
$ ansible -i hosts london -a "ping -c 3 google.com"
```

这个命令将连接到`london`主机并运行`ping -c 3 google.com`命令；这将从主机 ping `google.com`并返回结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/84b9aeb6-8592-4fb9-b7b7-969f9bfcd970.png)

我们也可以使用`ansible`命令运行单个模块；我们在上一章中使用`setup`模块做过这个。不过，一个更好的例子是更新所有已安装的软件包：

```
$ ansible -i hosts nyc -m yum -a "name=* state=latest"
```

在上一个示例中，我们使用`yum`模块来更新`nyc`组中所有已安装的软件包：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/acddf1cd-05d0-4233-aa9c-9fb9fb3f38a7.png)

从屏幕截图中可以看出，运行 Ansible 时的输出非常详细，并且有反馈告诉我们在临时执行期间它做了什么。让我们再次针对我们的所有主机运行命令，但这次只针对一个单独的软件包，比如`kpartx`：

```
$ ansible -i hosts all -m yum -a "name=kpartx state=latest"
```

终端输出可以让你更好地了解每个主机在执行命令时返回的信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/73ef6999-a100-4841-9e37-adf188407f21.png)

如您所见，`nyc`组中的两个主机虽然返回了`SUCCESS`状态，但没有显示任何更改；`london`组中的两个主机再次显示了`SUCCESS`状态，但显示了更改。

那么为什么要这样做，以及我们运行的两个命令之间有什么区别呢？

首先，让我们看看两个命令：

```
$ ansible -i hosts london -a "ping -c 3 google.com"
$ ansible -i hosts london -m yum -a "name=* state=latest"
```

虽然第一个命令似乎没有运行模块，但实际上是有的。`ansible`命令的默认模块称为`raw`，它只是在每个目标主机上运行原始命令。命令的`-a`部分是将参数传递给模块。`raw`模块碰巧接受原始命令，这正是我们在第二个命令中所做的。

您可能已经注意到，语法与我们向`ansible`命令传递命令以及在 YAML playbook 中使用时略有不同。我们在这里所做的就是直接向模块传递键值对。

那么为什么要这样使用 Ansible 呢？嗯，它非常适合以极其受控的方式直接针对非 Ansible 管理的主机运行命令。Ansible 只是通过 SSH 连接，运行命令，并告诉您结果。只是要小心，因为很容易变得过于自信，运行以下命令：

```
$ ansible -i hosts all -a "reboot now"
```

如果 Ansible 有权限执行该命令，那么它会执行。运行上一个命令将重新启动主机清单文件中的所有服务器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/11b8a321-1a1b-4733-902d-8b85bc55bddb.png)

请注意，所有主机的状态都是`UNREACHABLE`，因为`reboot`命令在`SUCCESS`状态返回之前终止了我们的 SSH 会话。但是，您可以看到每个主机都已通过运行`uptime`命令进行了重启：

```
$ ansible -i hosts all -a "uptime" 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/cc1a54f6-64e2-4207-9110-3d3aeeb56a4e.png)正如前面提到的，使用 Ansible 管理主机时要非常小心使用临时命令。

# ansible-config 命令

`ansible-config`命令用于管理 Ansible 配置文件。老实说，Ansible 默认提供了一些相当合理的默认值，因此在这些默认值之外没有太多需要配置的地方。您可以通过运行以下命令查看当前配置：

```
$ ansible-config dump
```

如您从以下输出中所见，所有绿色文本都是默认配置，橙色文本中的任何配置都是更改后的值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/5b0142ec-a78c-47c1-9437-42f4bd1b37f3.png)

运行以下命令将列出 Ansible 中的每个配置选项的详细信息，包括选项的功能、当前状态、引入时间、类型等等：

```
$ ansible-config list
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/4a64b4c9-a333-4d20-8c45-3372b7fbbcfc.png)

如果您有一个配置文件，比如在`~/.ansible.cfg`，那么您可以使用`-c`或`--config`标志加载它：

```
$ ansible-config --config="~/.ansible.cfg" view
```

上一个命令将显示配置文件。

# ansible-console 命令

Ansible 有自己的内置控制台。就个人而言，我几乎没有使用过。要启动控制台，我们只需要运行以下命令之一：

```
$ ansible-console -i hosts
$ ansible-console -i hosts london
$ ansible-console -i hosts nyc
```

前三个命令中的第一个命令针对所有主机，而接下来的两个命令只针对指定的组：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/761e4018-c266-461b-898c-31e58648ad36.png)

从终端输出中可以看出，您被要求输入 Ansible Vault 密码。在这里只需输入任何内容，因为我们没有任何受 Ansible Vault 保护的内容；稍后在本章中会详细介绍。连接后，您可以看到我连接到了`london`组，其中有两个主机。从这里，您只需输入模块名称，比如`ping`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ad3f6376-f3b6-46ab-974f-33c1ed1d63ef.png)

或者使用`raw`模块，输入`raw uptime`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e775b6e1-a1a1-480d-80a5-fb6aeac1d6c2.png)

您还可以使用与运行`ansible`命令时相同的语法来传递键值对，例如`yum name=kpartx state=latest`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c987bdea-05b6-49ed-880d-f44cc43833c4.png)

要离开控制台，只需输入`exit`即可返回到常规 shell。

# ansible-doc 命令

`ansible-doc`命令有一个功能——为 Ansible 提供文档。它主要涵盖了核心 Ansible 模块，您可以通过运行以下命令找到完整的列表：

```
$ ansible-doc --list
```

要获取有关模块的信息，只需运行命令，然后是模块名称，例如：

```
$ ansible-doc raw
```

如您从以下输出所见，文档非常详细：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/7979b3a7-74f1-4246-b27c-cb7d353bbb58.png)

如果您只想查看如何在 playbook 中使用示例，那么可以使用以下命令：

```
$ ansible-doc --snippet raw
```

这将让您了解 playbook 应该包含的内容，如您从`raw`模块的以下输出所见：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2242373d-80fe-4a41-bdcf-bd411c2462d1.png)

`ansible-doc`命令的内容与可以在 Ansible 网站上找到的文档相同，但如果您想快速检查模块所需的语法，它就很有用。

# `ansible-inventory`命令

使用`ansible-inventory`命令可以提供主机清单文件的详细信息。如果您想了解主机是如何分组的，这可能会很有用。例如，运行以下命令：

```
$ ansible-inventory -i hosts --graph
```

这为您提供了对主机组的逻辑概述。以下是我们在本章开头使用`ansible`命令的主机清单文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/80c4cbb7-993f-4828-b997-d45a718a79f7.png)

如您所见，它显示了分组，从 all 开始，然后是主机主分组，然后是子分组，最后是主机本身。

如果要查看单个主机的配置，可以使用：

```
$ ansible-inventory -i hosts --host=ansible01 
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/a5f935dc-bcae-426c-abf3-dfd9d3e2de5f.png)

您可能已经注意到，它显示了主机从我们为所有 DigitalOcean 主机设置的配置中继承的配置信息。您可以通过运行以下命令查看每个主机和组的所有信息：

```
$ ansible-inventory -i hosts --list
```

如果您有一个庞大或复杂的主机清单文件，并且只想获取有关单个主机的信息，或者如果您已经接管了主机清单并想更好地了解清单的结构，那么这个命令就很有用。我们将在本章后面看一下一个第三方工具，它提供更多的显示选项。

# Ansible Vault

在 Ansible 中，可以从文件中加载变量。我们将在下一章中更详细地讨论这个问题。这些文件可以包含诸如密码和 API 密钥之类的敏感信息。例如：

```
secret: "mypassword"
secret-api-key: "myprivateapikey" 
```

如您所见，我们有两个敏感的信息片段以明文形式可见。这在文件在我们本地机器上时是可以的，但是如果我们想要将文件检入源代码控制以与同事共享呢？即使存储库是私有的，我们也不应该以明文形式存储这种类型的信息。

Ansible 引入了 Vault 来帮助解决这个问题。使用 Vault，我们可以加密文件，然后在执行 Ansible 时，可以在内存中解密文件并读取内容。

要加密文件，我们需要运行以下命令，提供一个密码，以便在提示时用于解密文件：

```
$ ansible-vault encrypt secrets.yml
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/a15d1b91-d18e-4b3d-be6f-5bba0a54eb64.png)

如您从输出中所见，将要求您确认密码。一旦加密，您的文件将如下所示：

```
$ANSIBLE_VAULT;1.1;AES256
32643164646266353962363635363831366431316264366261616238333237383063313035343062
6431336434356661646336393061626130373233373161660a363532316138633061643430353235
32343466613038663333383835633831363436343363613933626332383565663562366163393866
6532393661633762310a393935373533666230383063376639373831383965303461636433356365
64326162613637336630363733303732343065373233333263613538656361396163376165353237
30393265616630366134383830626335646338343739353638313264336638363338356136636637
623236653139386534613236623434626131
```

如您所见，详细信息使用文本进行编码。这确保我们的`secrets.yml`文件在源代码控制中仍然可以正常工作。您可以通过运行以下命令查看文件的内容：

```
$ ansible-vault view secrets.yml
```

这将要求您输入密码并将文件内容打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/64214a87-fcc9-496e-9a84-701197d71584.png)

您可以通过运行以下命令在磁盘上解密文件：

```
$ ansible-vault decrypt secrets.yml
```

在使用此命令时，请记住不要将解密后的文件检入您的源代码控制系统！

自 Ansible 2.4 以来，现在可以加密文件中的单个变量。让我们向我们的文件添加更多变量：

```
username: russmckendrick
password: "mypassword"
secretapikey: "myprivateapikey" 
packages:
   - httpd
   - php
   - mariadb
```

如果我们不必一直查看或解密文件来检查变量名和文件的整体内容，那将是很好的。

通过运行以下命令来加密密码内容：

```
$ ansible-vault encrypt_string 'mypassword' --name 'password'
```

这将加密`mypassword`字符串并给它一个名为`password`的变量名：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/df83ad87-808d-40ed-be7e-40dcedf39f06.png)

然后我们可以复制并粘贴输出到我们的文件中，再次为`secret-api-key`重复这个过程，最终得到以下结果：

```
username: "russmckendrick"
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          30646136653066633833363837613162623765386561356334386463366338313164633737386534
          6536663537383830323636653235633662353933616331660a313962626530303961383234323736
          36393433313530343266383239663738626235393164356135336564626661303564343039303436
          6662653961303764630a346639663964373137366666383630323535663536623763303339323062
          3662
secretapikey: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63613932313933336532303237373732386337663662656337623962313638313338333763396232
          3463303765303530323133323064346539653234343933330a656537646262633765353766323737
          32303633323166643664323133303336393161663838386632346336626535303466303863346239
          3764633164613862350a363830336633356233626631636266303632663335346234373034376235
          3836
packages:
  - "httpd"
  - "php"
  - "mariadb"
```

如您所见，这样阅读起来更容易，而且与整个文件加密一样安全。还有一个关于 Ansible Vault 的最后一件事，那就是您也可以从文件中读取密码；例如，我一直在使用`password`作为密码对我的 Vault 进行编码。让我们把它放在一个文件中，然后用它来解锁我们的 Vault：

```
$ echo "password" > /tmp/vault-file
```

如您在以下的`playbook.yml`文件中所见，我们正在读取`secrets.yml`文件，然后使用`debug`模块输出内容：

```
---

- hosts: localhost

  vars_files:
    - secrets.yml

  tasks:
    - debug:
        msg: "The username is {{ username }} and password is {{ password }}, also the API key is {{ secretapikey }}"
    - debug:
        msg: "I am going to install {{ packages }}"
```

使用以下命令运行`playbook.yml`文件：

```
$ ansible-playbook playbook.yml
```

这导致终端输出中显示的错误消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e74b642b-41cb-4d79-9d05-d81bc5372e8f.png)

如您所见，它抱怨在我们的文件中发现了 Vault 加密数据，但我们没有提供解锁它的密码。运行以下命令将读取`/tmp/vault-file`的内容并解密数据：

```
$ ansible-playbook --vault-id /tmp/vault-file playbook.yml
```

从以下的 playbook 运行中可以看到，输出现在是我们所期望的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/119c603a-0f96-419a-9163-b71cdbd11b5b.png)

如果您更喜欢被提示输入密码，您也可以使用：

```
$ ansible-playbook --vault-id @prompt playbook.yml
```

您可以在附带存储库的`Chapter03`文件夹中找到`playbook.yml`和`secrets.yml`的副本。

# 第三方命令

在结束查看 Ansible 命令之前，有几个不同的第三方命令我想要介绍，其中第一个是`ansible-inventory-grapher`。

# ansible-inventory-grapher 命令

`ansible-inventory-grapher`命令由 Will Thames 使用 Graphviz 库来可视化您的主机清单。我们需要做的第一件事就是安装 Graphviz。要在 macOS 上使用 Homebrew 安装它，运行以下命令：

```
$ brew install graphviz
```

或者，在 Ubuntu 上安装 Graphviz，使用：

```
$ sudo apt-get install graphviz
```

安装完成后，您可以使用`pip`安装`ansible-inventory-grapher`：

```
$ sudo install ansible-inventory-grapher
```

现在我们已经安装了所有内容，可以使用本章早些时候使用的`hosts`文件生成图形：

```
ansible01 ansible_host=46.101.92.240
ansible02 ansible_host=159.65.63.218
ansible03 ansible_host=159.65.63.217
ansible04 ansible_host=138.68.145.116

[london]
ansible01
ansible02

[nyc]
ansible03
ansible04

[digitalocean:children]
london
nyc

[digitalocean:vars]
ansible_connection=ssh
ansible_user=root
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

我们可以运行以下命令来生成原始图形文件：

```
$ ansible-inventory-grapher -i hosts digitalocean
```

这将生成以下输出：

```
digraph "digitalocean" {
 rankdir=TB;

 "all" [shape=record label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       all</font></b></td></tr>
 </table>
 >]
 "ansible01" [shape=record style=rounded label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       ansible01</font></b></td></tr>
 <hr/><tr><td><font face="Times New Roman, Bold"
      point-size="14">ansible_connection<br/>ansible_host<br/>
      ansible_private_key_file<br/>ansible_user<br/>
      host_key_checking<br/></font></td></tr></table>
 >]
 "ansible02" [shape=record style=rounded label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       ansible02</font></b></td></tr>
 <hr/><tr><td><font face="Times New Roman, Bold"
      point-size="14">ansible_connection<br/>ansible_host<br/>
      ansible_private_key_file<br/>ansible_user<br/>
      host_key_checking<br/></font></td></tr></table>
 >]
 "ansible03" [shape=record style=rounded label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       ansible03</font></b></td></tr>
 <hr/><tr><td><font face="Times New Roman, Bold"
      point-size="14">ansible_connection<br/>ansible_host<br/>
      ansible_private_key_file<br/>ansible_user<br/>
      host_key_checking<br/></font></td></tr></table>
 >]
 "ansible04" [shape=record style=rounded label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
        ansible04</font></b></td></tr>
 <hr/><tr><td><font face="Times New Roman, Bold"
      point-size="14">ansible_connection<br/>ansible_host<br/>
      ansible_private_key_file<br/>ansible_user<br/>
      host_key_checking<br/></font></td></tr></table>
 >]
 "digitalocean" [shape=record label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       digitalocean</font></b></td></tr>
 </table>
 >]
 "london" [shape=record label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
        london</font></b></td></tr>
 </table>
 >]
 "nyc" [shape=record label=<
 <table border="0" cellborder="0">
 <tr><td><b><font face="Times New Roman, Bold" point-size="16">
       nyc</font></b></td></tr>
 </table>
 >]

 "all" -> "digitalocean";
 "digitalocean" -> "london";
 "digitalocean" -> "nyc";
 "london" -> "ansible01";
 "london" -> "ansible02";
 "nyc" -> "ansible03";
 "nyc" -> "ansible04";
}
```

这是图形的原始输出。如您所见，它类似于 HTML。我们可以使用作为 Graphviz 的一部分的`dot`命令来渲染它。`dot`命令从图形中创建分层图。要做到这一点，运行：

```
$ ansible-inventory-grapher -i hosts digitalocean | dot -Tpng > hosts.png
```

这将生成一个名为`hosts.png`的 PNG 文件，其中包含您可以在这里看到的主机清单文件的可视化：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/dca6621b-227a-423c-b3e5-f296cc2c6765.png)

我们将在后面的章节中使用这个工具，以了解我们的清单文件在生成时是什么样子的。

# Ansible Run Analysis

**ARA**是一个递归缩写，代表**Ansible Run Analysis**，记录 Ansible。这是一个用 Python 编写的工具，记录您的 playbook 运行并在直观的 web 界面中显示结果。在 macOS 上安装它，我不得不使用以下命令：

```
$ sudo pip install ara --ignore-installed pyparsing
```

要在 Ubuntu 上安装，我可以只使用这个：

```
$ sudo pip install ara
```

安装完成后，您应该能够运行以下命令来配置您的环境以记录您的 Ansible playbook 运行：

```
$ export ara_location=$(python -c "import os,ara; print(os.path.dirname(ara.__file__))")
$ export ANSIBLE_CALLBACK_PLUGINS=$ara_location/plugins/callbacks
$ export ANSIBLE_ACTION_PLUGINS=$ara_location/plugins/actions
$ export ANSIBLE_LIBRARY=$ara_location/plugins/modules
```

当您配置好环境后，可以运行 playbook。例如，让我们使用本章中 Ansible Vault 部分的 playbook 重新运行：

```
$ ansible-playbook --vault-id @prompt playbook.yml
```

一旦 playbook 被执行，运行以下命令将启动 ARA web 服务器：

```
$ ara-manage runserver
```

打开浏览器并转到前一个命令输出中提到的 URL，`http://127.0.0.1:9191/`，将给您显示 playbook 运行的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c16d88ee-f914-49ad-9933-18ff7fbeca6d.png)

正如您所看到的，我已经运行了四次 playbook，其中一次执行失败。单击元素将显示更多详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d972cbd2-f777-4348-994e-32f6c63ca83a.png)

同样，我们将在以后的章节中更详细地使用 ARA；我们在这里只是简单介绍了基础知识。

# 摘要

在本章中，我们简要介绍了一些作为标准 Ansible 安装的一部分提供的支持工具，以及一些有用的第三方工具，这些工具旨在与 Ansible 一起使用。我们将在以后的章节中使用这些命令，以及我们故意忽略的一些命令。

在我们的下一章中，我们将开始编写一个更复杂的 playbook，在我们的本地 Vagrant 框中安装一个基本的 LAMP 堆栈。

# 问题

1.  在本章中，我们介绍的提供有关主机清单信息的命令中，哪些是默认与 Ansible 一起提供的？

1.  真或假：使用 Ansible Vault 加密字符串的变量文件将在低于 2.4 版本的 Ansible 中起作用。

1.  您将运行哪个命令来获取如何调用`yum`模块作为任务的示例？

1.  解释为什么您希望针对清单中的主机运行单个模块。

1.  使用您自己的主机清单文件，生成显示内容的图表。

# 进一步阅读

您可以在本章末尾涵盖的两个第三方工具的项目页面中找到以下 URL：

+   `ansible-inventory-grapher`: [`github.com/willthames/ansible-inventory-grapher`](https://github.com/willthames/ansible-inventory-grapher)

+   `ara`: [`github.com/openstack/ara`](https://github.com/openstack/ara)


# 第四章：部署 LAMP Stack

在本章中，我们将使用 Ansible 随附的各种核心模块来部署完整的 LAMP stack。我们将针对我们在 第二章 部署的 CentOS 7 Vagrant box 进行操作，*安装和运行 Ansible*。

我们将讨论以下内容：

+   Playbook 布局—Playbook 应该如何结构化

+   Linux—准备 Linux 服务器

+   Apache—安装和配置 Apache

+   MariaDB—安装和配置 MariaDB

+   PHP—安装和配置 PHP

在我们开始编写 Playbook 之前，我们应该讨论一下我们将在本章中使用的结构，然后快速讨论一下我们需要的内容。

# 技术要求

我们将再次使用在之前章节中启动的 CentOS 7 Vagrant box。由于我们将在虚拟机上安装 LAMP stack 的所有元素，您的 Vagrant box 需要能够从互联网下载软件包；总共需要下载大约 500 MB 的软件包和配置。

您可以在 [`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter04/lamp`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter04/lamp) 找到完整的 Playbook 副本。

# Playbook 结构

在之前的章节中，我们运行的 Playbook 通常尽可能基本。它们都在一个单独的文件中，伴随着一个主机清单文件。在本章中，由于我们将大大扩展 Playbook 的工作量，因此我们将使用 Ansible 建议的目录结构。

如您从以下布局中所见，有几个文件夹和文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e8ae9103-54aa-4970-8299-c91760c899e5.png)

让我们开始创建结构并在创建时讨论每个项目。我们需要创建的第一个文件夹是我们的顶层文件夹。这个文件夹将包含我们的 Playbook 文件夹和文件：

```
$ mkdir lamp
$ cd lamp
```

我们要创建的下一个文件夹叫做 `group_vars`。这将包含我们的 Playbook 中使用的变量文件。现在，我们将创建一个名为 `common.yml` 的单个变量文件：

```
$ mkdir group_vars
$ touch group_vars/common.yml
```

接下来，我们将创建两个文件：我们的主机清单文件，我们将命名为 `production`，以及我们的主 Playbook，通常称为 `site.yml`：

```
$ touch production
**$ touch site.yml** 
```

我们要手动创建的最后一个文件夹叫做 `roles`。在这里，我们将使用 `ansible-galaxy` 命令创建一个名为 `common` 的角色。为此，我们使用以下命令：

```
$ mkdir roles $ ansible-galaxy init roles/common
```

正如您可能已经从本节开头的初始结构中注意到的那样，common 角色本身有几个文件和文件夹；当我们运行 `ansible-galaxy init` 命令时，所有这些都会为我们创建。我们将在下一节讨论这些文件的作用，届时我们将使用 common 角色来配置我们的基本 Linux 服务器。

除了默认的 Ansible 结构之外，唯一的其他文件是我们的 `Vagrantfile`。它包含以下内容：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME    = "centos/7"
BOX_IP      = "192.168.50.4"
DOMAIN      = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY  = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY,
  "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY,
  destination: "~/.ssh/authorized_keys"

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

虽然我们将在本节和接下来的几节中逐个处理每个文件，但完整的 Playbook 副本可在附带的 GitHub 存储库中找到。

# LAMP stack

LAMP stack 是用来描述一体化的网站和数据库服务器的术语。通常，组件包括：

+   **Linux**：底层操作系统；在我们的情况下，我们将使用 CentOS 7。

+   **Apache**：该堆栈的网站服务器元素。

+   **MariaDB**：该堆栈的数据库组件；通常是基于 MySQL 的。由于 CentOS 7 预装了 MariaDB，我们将使用它而不是 PHP。

+   **PHP**：网站服务器用于生成内容的动态语言。

还有一个常见的 LAMP stack 变体叫做 **LEMP**；它用 *NGINX* 替换 *Apache*，*NGINX* 的发音是 *engine-x*，因此用 *E* 而不是 *N*。

我们将着手创建角色来处理这些组件；它们是：

+   `common`：这个角色将准备我们的 CentOS 服务器，安装我们需要的任何支持软件包和服务

+   `apache`：这个角色将安装 Apache web 服务器，并配置一个默认的虚拟主机

+   `mariadb`：这个角色不仅会安装 MariaDB，还会保护安装并创建一个默认的数据库和用户

+   `php`：这个角色将安装 PHP，一组常见的 PHP 模块，还有 Composer，这是一个用于 PHP 的包管理器

让我们开始编写 common 角色，准备好基础知识。

# 常见

在本章的前一部分中，我们使用`ansible-galaxy init`命令创建了`common`角色。这将创建几个文件夹和文件；在我们开始编辑它们之前，让我们快速讨论一下它们各自的用途：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/501dbfad-ccb2-4abb-bd73-6f7fd45ecb96.png)

我们只关心顶层；`main.yml`文件只是每个角色部分调用的默认 YAML 文件：

+   `README.md`：这是用于在像 GitHub 这样的服务中检入角色时创建有关角色的任何文档的文件。每当有人浏览 common 文件夹时，该文件将与文件夹列表一起显示。

+   `default`：这是角色的默认变量存储位置。这些变量可以被`vars`文件夹中具有相同名称的任何变量覆盖。

+   `files`：这个文件夹包含我们可能希望使用`copy`模块复制到目标主机的任何静态文件。

+   `handlers`：处理程序是在执行 playbook 后执行的任务；通常，`handlers`用于在配置文件更改时重新启动服务。

+   `meta`：这包含有关角色的信息，如果角色要发布到 Ansible Galaxy，则会使用。

+   `tasks`：这是大部分工作发生的地方。

+   `templates`：这个文件夹包含`template`模块使用的 Jinja2 模板。

+   `tests`：用于存储模块的任何测试。

+   `vars`：您可以使用此处定义的变量覆盖`default`文件夹中定义的任何变量；此处定义的变量也可以被从`group_vars`文件夹和 playbook 的顶层加载的任何变量覆盖。

让我们开始添加一些任务。

# 更新软件包

首先，让我们通过在`roles/common/tasks/main.yml`文件的开头添加以下内容来更新我们的服务器：

```
- name: update all of the installed packages
  yum:
    name: "*"
    state: "latest"
    update_cache: "yes"
```

您会注意到，与我们上次运行`yum`更新所有已安装软件包时有所不同，我们现在正在使用`name`键开始任务，这将在 playbook 运行时打印出我们分配给名称键的值的内容，这将让我们更好地了解 playbook 运行过程中发生了什么。

# 安装常用软件包

现在我们已经更新了安装的软件包，让我们安装我们想要在所有我们将启动的 Linux 服务器上安装的软件包：

```
- name: install the common packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ common_packages }}"
```

正如你所看到的，我们再次使用`yum`模块，并为任务添加了一个描述性名称。我们不是在任务中提供软件包的列表，而是使用一个名为`common_packages`的变量，在`roles/common/defaults/main.yml`文件中定义如下：

```
common_packages:
  - "ntp"
  - "ntpdate"
  - "vim-enhanced"
  - "git"
  - "unzip"
  - "policycoreutils-python"
  - "epel-release"
  - "https://centos7.iuscommunity.org/ius-release.rpm"
```

正如你所看到的，我们正在安装`ntp`和`ntpdate`；我们很快将配置`ntp`。接下来，我们安装`vim-enhanced`和`git`，因为它们在服务器上安装后总是有用。然后，我们安装`policycoreutils-python`包，稍后会详细介绍，最后安装并启用两个额外的`yum`仓库，EPEL 和 IUS。

**企业 Linux 的额外软件包**（**EPEL**）是一个特别感兴趣的小组，他们维护了一系列不属于 Red Hat Enterprise Linux 核心的软件包。EPEL 软件包通常基于它们的 Fedora 对应软件包，并且已经打包，因此它们永远不会与核心 Enterprise Linux 发行版中的软件包发生冲突或替换。

CentOS 7 附带一个名为`epel-release`的软件包，它启用了 EPEL 存储库。但是，IUS 没有发布包，因此在这里，我们不是使用核心 CentOS 存储库的软件包，而是提供了启用了 IUS 存储库的 RPM 文件的完整 URL，该文件适用于 CentOS 7。

IUS 社区项目是为红帽企业 Linux 和兼容操作系统（如 CentOS）提供 RPM 的集合，旨在提供与上游稳定**一致**的软件包，因此**IUS**。他们提供 Apache、PHP 和 MariaDB 的软件包，这些都是最新版本。IUS 提供的软件包遵循*SafeRepo 计划*中制定的规则，这意味着它们是可信的。

# 配置 NTP

接下来，我们从`templates`文件夹中复制`ntp.conf`文件，添加 NTP 服务器列表，然后告诉 Ansible 每当配置文件更改时重新启动 NTP：

```
- name: copy the ntp.conf to /etc/ntp.conf
  template:
    src: "ntp.conf.j2"
    dest: "/etc/ntp.conf"
  notify: "restart ntp"
```

模板文件可以在`roles/common/templates/ntp.conf.j2`中找到：

```
# {{ ansible_managed }}
driftfile /var/lib/ntp/drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1 
restrict ::1
{% for item in ntp_servers %}
server {{ item }} iburst
{% endfor %}
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
```

如您所见，我们正在使用`ntp_servers`变量；这个变量存储在`roles/common/defaults/main.yml`文件中：

```
ntp_servers:
  - "0.centos.pool.ntp.org"
  - "1.centos.pool.ntp.org"
  - "2.centos.pool.ntp.org"
  - "3.centos.pool.ntp.org"
```

最后，以下任务已添加到`roles/common/handlers/main.yml`中：

```
- name: "restart ntp"
  service:
    name: "ntpd"
    state: "restarted"
```

虽然我们在这里通知了处理程序，但 NTP 将不会在 playbook 运行的最后重新启动，以及我们通知的任何其他任务。

# 创建用户

常见角色的最后一部分是添加一个名为`lamp`的用户，并将我们的公钥添加到该用户。在我们查看任务之前，让我们先看一下我们将要使用的变量，这些变量在`roles/common/defaults/main.yml`中定义：

```
users:
  - { name: "lamp", group: "lamp", state: "present", key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}" }
```

如您所见，我们提供了三条信息：

+   `name`：这是我们要创建的用户的名称

+   `group`：这是我们要将用户添加到的组

+   `state`：如果我们希望用户存在或不存在

+   `key`：在这里，我们使用 Ansible 查找任务来读取`~/.ssh/id_rsa.pub`文件的内容，并将其用作值

用于创建用户的`roles/common/tasks/main.yml`文件中的任务分为三部分；第一部分使用`group`模块创建组：

```
- name: add group for our users
  group:
    name: "{{ item.group }}"
    state: "{{ item.state }}"
  with_items: "{{ users }}"
```

如您所见，我们使用`with_items`加载`users`变量，因为该变量包含三个不同的项目，这里只使用了两个。我们可以只命名它们，所以这里我们使用`item.group`和`item.state`。

任务的第二部分使用`user`模块创建用户，如您所见：

```
- name: add users to our group
  user: 
    name: "{{ item.name }}"
    group: "{{ item.group }}"
    comment: "{{ item.name }}"
    state: "{{ item.state }}"
  with_items: "{{ users }}"
```

任务的最后一部分使用`authorized_key`模块将用户的公钥添加到授权密钥文件中：

```
- name: add keys to our users
  authorized_key:
    user: "{{ item.name }}"
    key: "{{ item.key }}"
  with_items: "{{ users }}"
```

如您所见，这次我们使用了`item.name`和`item.key`变量。该模块在用户的主目录中创建一个名为`.ssh/authorized_keys`的文件，该目录由`item.name`定义，然后将`item.key`的内容放在其中，使私钥的持有者可以访问我们刚刚创建的用户。

# 运行角色

首先，让我们通过运行以下命令之一来启动 CentOS 7 Vagrant box：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

现在我们有了服务器，我们需要更新主机清单；在`production`文件中输入以下内容：

```
box ansible_host=192.168.50.4.nip.io

[boxes]
box

[boxes:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

最后，我们需要一个执行我们角色的东西。将以下内容添加到`site.yml`文件中：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/common
```

现在我们的 playbook 文件准备好了，我们可以通过运行以下命令来针对我们的 Vagrant box 运行它：

```
$ ansible-playbook -i production site.yml
```

几分钟后，您应该看到类似以下输出：

```
PLAY [boxes] ***************************************************************************************

TASK [Gathering Facts] *****************************************************************************
ok: [box]

TASK [roles/common : update all of the installed packages] *****************************************
changed: [box]

TASK [roles/common : install the common packages] **************************************************
changed: [box] => (item=[u'ntp', u'ntpdate', u'vim-enhanced', u'git', u'unzip', u'policycoreutils-python', u'epel-release', u'https://centos7.iuscommunity.org/ius-release.rpm'])

TASK [roles/common : copy the ntp.conf to /etc/ntp.conf] *******************************************
changed: [box]

TASK [roles/common : add group for our users] ******************************************************
changed: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

TASK [roles/common : add users to our group] *******************************************************
changed: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

TASK [roles/common : add keys to our users] ********************************************************
changed: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

RUNNING HANDLER [roles/common : restart ntp] *******************************************************
changed: [box]

PLAY RECAP *****************************************************************************************
box : ok=8 changed=7 unreachable=0 failed=0
```

如您所见，一切都已按预期安装和配置。重新运行 playbook 会得到以下结果：

```
PLAY [boxes] ***************************************************************************************

TASK [Gathering Facts] *****************************************************************************
ok: [box]

TASK [roles/common : update all of the installed packages] *****************************************
ok: [box]

TASK [roles/common : install the common packages] **************************************************
ok: [box] => (item=[u'ntp', u'ntpdate', u'vim-enhanced', u'git', u'unzip', u'policycoreutils-python', u'epel-release', u'https://centos7.iuscommunity.org/ius-release.rpm'])

TASK [roles/common : copy the ntp.conf to /etc/ntp.conf] *******************************************
ok: [box]

TASK [roles/common : add group for our users] ******************************************************
ok: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

TASK [roles/common : add users to our group] *******************************************************
ok: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

TASK [roles/common : add keys to our users] ********************************************************
ok: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

PLAY RECAP *****************************************************************************************
box : ok=7    changed=0    unreachable=0    failed=0
```

如您所见，我们跳过了重新启动 NTP 的任务，也没有其他要安装的附加软件包或更新，也没有对我们创建的用户或组的任何更改。现在我们已经更新和安装了基本软件包，并配置了基本操作系统，我们准备安装 Apache。

# Apache

目前，我们没有 Apache 的角色，所以让我们使用以下命令创建一个：

```
$ ansible-galaxy init roles/apache
```

与以前一样，这将为我们的 Apache 角色创建基本的框架。

# 安装 Apache

我们要添加的第一个任务是安装基本的 Apache 软件包。在`roles/apache/tasks/main.yml`中，添加以下内容：

```
- name: install the apache packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ apache_packages }}"
```

正如你可能已经猜到的那样，`apache_packages`的默认值可以在`roles/apache/defaults/main.yml`中找到：

```
apache_packages:
  - "httpd24u"
  - "httpd24u-filesystem"
  - "httpd24u-tools"
  - "httpd24u-mod_ssl"
  - "openssl"
  - "openssl-libs"
```

这将从 IUS 安装最新的 Apache 2.4 软件包，以及我们需要的一些支持工具。安装完成后，我们现在需要配置 Apache。

# 配置 Apache

也许你已经想知道为什么我们在上一节创建了一个名为`lamp`的用户；我们将为这个用户托管我们的网站。准备好用户托管我们网站的第一步是将用户添加到`apache_group`中。为此，我们需要运行以下任务：

```
- name: Add user to apache group
  user:
    name: "{{ item.name }}"
    groups: "{{ apache_group }}"
    append: yes
  with_items: "{{ users }}"
```

这里有两件事需要指出。第一是我们正在使用上一个角色中的`users`变量，在 playbook 运行中仍然可以使用，第二是我们在`roles/apache/defaults/main.yml`中添加了一个名为`apache_group`的变量：

```
apache_group: "apache"
```

既然我们的用户在`apache_group`中，让我们创建将成为我们网站文档根目录的内容：

```
- name: create the document root for our website
  file:
    dest: "{{ document_root }}"
    state: "directory"
    mode: "0755"
    owner: "{{ users.0.name }}"
    group: "{{ apache_group }}"
```

正如你所看到的，这使用了一些新变量，以及访问旧变量的新方法。让我们先解决`users.0.name`，因为我们已经将用户定义为列表。在 playbook 运行期间可能会添加多个用户，因为我们只想创建一个文档根目录并将其分配给一个虚拟主机，我们使用列表中的第一个用户，该用户在**user**变量下注册，这就是`0`的用处。

`document_root`变量也是使用这个原则构建的；这是`roles/apache/defaults/main.yml`文件中的两个变量，将帮助构成完整的文档根目录：

```
web_root: "web"
document_root: "/home/{{ users.0.name }}/{{ web_root }}"
```

这将使我们的文档根目录在 Vagrant box 上的路径为`/home/lamp/web/`，假设我们没有覆盖主要 playbook 中的任何变量名。

我们还需要更改 lamp 用户的主目录权限，以允许我们执行脚本；为此，调用以下任务：

```
- name: set the permissions on the user folder
  file:
    dest: "/home/{{ users.0.name }}/"
    state: "directory"
    mode: "0755"
    owner: "{{ users.0.name }}"
```

接下来，我们需要放置我们的 Apache 虚拟主机；这将在我们在浏览器中输入主机名时提供我们的网页。为此，我们将使用存储在`roles/apache/templates/vhost.conf.j2`中的模板文件，该文件使用我们已经定义的变量以及另外两个变量：

```
# {{ ansible_managed }}
<VirtualHost *:80>
  ServerName {{ ansible_nodename }}
  DocumentRoot {{ document_root }}
  DirectoryIndex {{ index_file }}
  <Directory {{ document_root }}>
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
```

`roles/apache/defaults/main.yml`中的`index_file`变量如下所示：

```
index_file: index.html
```

还有`ansible_nodename`变量；这是从主机机器收集的变量之一，当`setup`模块首次运行时。部署模板的任务如下：

```
- name: copy the vhost.conf to /etc/httpd/conf.d/
  template:
    src: "vhost.conf.j2"
    dest: "/etc/httpd/conf.d/vhost.conf"
  notify: "restart httpd"
```

重启 Apache 的任务可以在`roles/apache/handlers/main.yml`中找到，如下所示：

```
- name: "restart httpd"
  service:
    name: "httpd"
    state: "restarted"
```

既然我们已经安装和配置了 Apache，我们需要允许 Apache 使用存储在`/home/`中的网站根目录。为此，我们需要调整 SELinux 权限。

# 配置 SELinux

在上一节安装的软件包之一是`policycoreutils-python`。这允许我们使用 Python 配置 SELinux，因此也可以使用 Ansible。

**安全增强型 Linux**（**SELinux**）是由红帽和美国国家安全局开发的。它提供了在内核级别支持访问控制安全策略的机制。这些包括美国国防部使用的强制访问控制。

默认情况下，我们使用的 Vagrant box 启用了 SELinux。我们可以不简单地停止 SELinux，而是允许 Apache 在其默认的`/var/www/`之外运行。为此，我们需要将以下内容添加到我们的角色中：

```
- name: set the selinux allowing httpd_t to be permissive
  selinux_permissive:
    name: httpd_t
    permissive: true
```

现在 Apache 被允许从我们的用户目录中提供内容，我们可以添加一个`index.html`文件，这样我们就有了除了默认的 Apache 页面之外的东西来提供。

# 复制 HTML 文件

最后一个任务是将`index.html`文件复制到我们的网站根目录，这样我们就有了新安装的 Apache 服务器可以提供的内容。执行此任务使用`template`模块：

```
- name: copy the test HTML page to the document root
  template:
    src: "index.html.j2"
    dest: "{{ document_root }}/index.html"
    mode: "0644"
    owner: "{{ users.0.name }}"
    group: "{{ apache_group }}"
  when: html_deploy == true
```

如你所见，我们正在加载一个名为 `index.html.j2` 的模板，其中包含以下内容：

```
<!--{{ ansible_managed }}-->
<!doctype html>
<title>{{ html_heading }}</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px;
   margin: 0 auto; }
</style>
<article>
    <h1>{{ html_heading }}</h1>
    <div>
        <p>{{ html_body }}</p>
    </div>
</article>
```

我们在模板中使用了两个变量；这两个变量可以在 `roles/apache/defaults/main.yml` 文件中找到，还有一个变量：

```
html_deploy: true
html_heading: "Success !!!"
html_body: |
  This HTML page has been deployed using Ansible to
   <b>{{ ansible_nodename }}</b>.<br>
  The user is <b>{{ users.0.name }}</b> who is in the
   <b>{{ apache_group }}</b> group.<br>
  The weboot is <b>{{ document_root }}</b>, the default index file is
   <b>{{ index_file }}</b>.<br>
```

作为任务的一部分，我们有以下一行：

```
when: html_deploy == true
```

这意味着只有当 `html_deploy` 等于 `true` 时，任务才会被执行。如果是其他任何值，那么任务将被跳过。我们将在本章后面讨论这一点，但现在，我们希望页面被部署，所以我们将保持在 `apache/defaults/main.yml` 文件中定义的默认值。

在运行角色之前要指出的最后一件事是 `html_body` 变量。如你所见，变量的内容分布在三行上。在变量名后使用 `|` 字符来实现这一点；这有助于使你的变量文件可读，同时也允许你开始将诸如密钥或证书之类的项目作为变量进行分发，同时还允许你使用 vault 进行编码。

# 运行角色

现在安装和配置 Apache 的角色已经完成，我们可以将其添加到我们的 playbook 中：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/common
    - roles/apache
```

在上一节的 playbook 之后，我们可以简单地重新运行以下命令：

```
$ ansible-playbook -i production site.yml
```

这将在执行 `apache` 角色之前通过通用角色工作。我在这里截断了 playbook 运行中通用角色的输出：

```
PLAY [boxes] ***************************************************************************************

TASK [Gathering Facts] *****************************************************************************
ok: [box]

TASK [roles/common : update all of the installed packages] *****************************************
ok: [box]

TASK [roles/common : install the common packages] **************************************************
ok: [box]

TASK [roles/common : copy the ntp.conf to /etc/ntp.conf] *******************************************
ok: [box]

TASK [roles/common : add group for our users] ******************************************************
ok: [box]
TASK [roles/common : add users to our group] *******************************************************
ok: [box]

TASK [roles/common : add keys to our users] ********************************************************
ok: [box]

TASK [roles/apache : install the apache packages] **************************************************
changed: [box] => (item=[u'httpd24u', u'httpd24u-filesystem', u'httpd24u-tools', u'httpd24u-mod_ssl', u'openssl', u'openssl-libs'])

TASK [roles/apache : Add user to apache group] *****************************************************
changed: [box] => (item={u'state': u'present', u'group': u'lamp', u'name': u'lamp', u'key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russmckendrick@me.com'})

TASK [roles/apache : create the document root for our website] *************************************
changed: [box]

TASK [roles/apache : set the permissions on the user folder] ***************************************
changed: [box]

TASK [roles/apache : copy the vhost.conf to /etc/httpd/conf.d/] ************************************
changed: [box]

TASK [roles/apache : set the selinux allowing httpd_t to be permissive] ****************************
changed: [box]

TASK [roles/apache : copy the test HTML page to the document root] *********************************
changed: [box]

RUNNING HANDLER [roles/apache : restart httpd] *****************************************************
changed: [box]

PLAY RECAP *****************************************************************************************
box : ok=15 changed=8 unreachable=0 failed=0
```

在浏览器中打开 `http://192.168.50.4.nip.io/` 应该会给我们一个看起来像以下截图的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/52829455-e57a-457c-9ade-a36ce728255a.png)

如你所见，模板已经捕捉到我们定义的所有变量；页面的源代码如下：

```
<!--Ansible managed-->
<!doctype html>
<title>Success !!!</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px;
    margin: 0 auto; }
</style>
<article>
  <h1>Success !!!</h1>
  <div>
    <p>This HTML page has been deployed using Ansible to
    <b>192.168.50.4.nip.io</b>.<br>
    The user is <b>lamp</b> who is in the <b>apache</b> group.<br>
    The weboot is <b>/home/lamp/web</b>, the default index file is
    <b>index.html</b>.<br></p>
  </div>
</article>
```

如果我们重新运行 playbook，我们应该会看到以下结果：

```
PLAY RECAP *****************************************************************************************
box : ok=14 changed=0 unreachable=0 failed=0
```

如你所见，有 `14` 个任务是 `ok`，没有发生任何 `changed`。

# MariaDB

接下来，我们将安装和配置 MariaDB，我们 LAMP 堆栈的数据库组件。

MariaDB 是 MySQL 的一个分支。它的开发由一些 MySQL 的原始开发人员领导；他们在 Oracle 收购 MySQL 后对 MySQL 的许可证引发了一些担忧后创建了这个分支。

第一步是创建我们将需要的角色文件；同样，我们将使用 `ansible-galaxy init` 命令来引导角色文件：

```
$ ansible-galaxy init roles/mariadb
```

# 安装 MariaDB

由于我们在 playbook 中使用了 IUS 仓库来安装其他软件包，所以从那里安装最新版本的 MariaDB 是有道理的。然而，我们首先需要解决一个冲突。

作为基本的 Vagrant 盒子安装，邮件服务器 Postfix 被安装了。Postfix 需要 `mariadb-libs` 软件包作为依赖，但安装这个软件包会导致与我们想要安装的后续版本软件包发生冲突。解决这个问题的方法是移除 `mariadb-libs` 软件包，然后安装我们需要的软件包，以及在卸载 `mariadb-libs` 时被移除的 Postfix。

角色中的第一个任务，我们需要添加到 `roles/mariadb/tasks/mail.yml`，看起来像这样：

```
- name: remove the packages so that they can be replaced
  yum:
    name: "{{ item }}"
    state: "absent"
  with_items: "{{ mariadb_packages_remove }}"
```

正如你可能已经怀疑的那样，`mariadb_packages_remove` 在 `roles/mariadb/defaults/main.yml` 文件中被定义：

```
mariadb_packages_remove:
  - "mariadb-libs.x86_64"
```

如你所见，我们正在使用完整的软件包名称。我们需要这样做，因为如果我们简单地使用 `mariadb-libs`，那么新安装的软件包将在每次 playbook 运行时被移除。这是不好的，因为这个任务也会卸载我们接下来要安装的所有 MariaDB 软件包，如果我们有一个正在运行的数据库，那将是一场灾难！

为了安装 MariaDB 的后续版本，我们需要添加以下任务：

```
- name: install the mariadb packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ mariadb_packages }}"
```

`mariadb_packages` 变量，同样可以在 defaults 文件夹中找到，看起来像这样：

```
mariadb_packages:
  - "mariadb101u"
  - "mariadb101u-server"
  - "mariadb101u-config"
  - "mariadb101u-common"
  - "mariadb101u-libs"
  - "MySQL-python"
  - "postfix"
```

我们正在安装 MariaDB 的软件包，以及上一个任务中被移除的 Postfix。我们还安装了 `MySQL-python` 软件包，这将允许 Ansible 与我们的 MariaDB 安装进行交互。

默认情况下，MariaDB 在安装过程中不会启动。通常，我们会使用处理程序在 playbook 运行的最后启动服务，正如我们从前面的部分学到的，处理程序在 playbook 执行的最后运行。如果我们不需要与 MariaDB 服务交互来配置它，这不会是一个问题。为了解决这个问题，我们需要将以下任务添加到我们的角色中：

```
- name: start mariadb
  service:
    name: "mariadb"
    state: "started"
    enabled: "yes"
```

这确保了 MariaDB 正在运行，并配置了服务以在启动时启动。

# 配置 MariaDB

现在 MariaDB 已安装并运行，我们开始配置它。我们默认安装的 MariaDB 没有定义根密码，所以这应该是我们设置的第一件事。我们可以使用`mysql_user`模块来做到这一点：

```
- name: change mysql root password
  mysql_user:
    name: "{{ mariadb_root_username }}" 
    host: "{{ item }}" 
    password: "{{ mariadb_root_password }}"
    check_implicit_admin: "yes"
    priv: "*.*:ALL,GRANT"
  with_items: "{{ mariadb_hosts }}"
```

正如你所看到的，我们使用了一些不同的变量；这些在`roles/mariadb/defaults/main.yml`中定义为：

```
mariadb_root_username: "root"
mariadb_root_password: "Pa55W0rd123"
mariadb_hosts:
  - "127.0.0.1"
  - "::1"
  - "{{ ansible_nodename }}"
  - "%"
  - "localhost"
```

`mariadb_hosts`中主机的顺序很重要；如果`localhost`不是最后一个更改的主机，那么 Ansible 将会给出一个关于无法连接到 MariaDB 的错误消息。这是因为我们利用了 MariaDB 没有默认 root 密码的事实来实际设置 root 密码。

现在，一旦我们配置了 root 用户的密码，我们仍然希望能够连接到 MySQL。我喜欢在根用户文件夹下设置一个`~/.my.cnf`文件。这可以在 Ansible 中完成如下：

```
- name: set up .my.cnf file
  template:
    src: "my.cnf.j2"
    dest: "~/.my.cnf"
```

模板文件可以在`lamp/roles/mariadb/templates/my.cnf.j2`中找到；它包含以下内容：

```
# {{ ansible_managed }}
[client]
password='{{ mariadb_root_password }}'
```

一旦放置好，这意味着系统根用户——不要与我们刚刚在 MariaDB 中设置的 root 用户混淆——将直接访问 MariaDB 而无需提供密码。接下来，我们可以删除默认创建的匿名用户。同样，我们将使用`mysql_user`模块来完成这个操作：

```
- name: delete anonymous MySQL user
  mysql_user:
    user: ""
    host: "{{ item }}"
    state: "absent"
  with_items: "{{ mariadb_hosts }}"
```

最后，还创建了一个`test`数据库。由于我们将创建自己的数据库，让我们也将其删除，这次使用`mysql_db`模块：

```
- name: remove the MySQL test database
  mysql_db:
    db: "test" 
    state: "absent"
```

这些配置任务相当于运行`mysql_secure_installation`命令。

# 导入示例数据库

现在我们的 MariaDB 安装已经完成，我们应该对其进行一些操作。GitHub 上有一些示例数据库可用。让我们来看看导入 datacharmer 提供的 employee 数据库。我们将使用一个稍微修改过的 SQL 转储文件版本，但稍后在本节中会详细介绍。

我们将在 playbook 的这一部分使用嵌套变量；这些可以在`mariadb/defaults/main.yml`中找到：

```
mariadb_sample_database:
  create_database: true
  source_url: "https://github.com/russmckendrick/test_db/archive/master.zip"
  path: "/tmp/test_db-master"
  db_name: "employees"
  db_user: "employees"
  db_password: "employees"
  dump_files:
    - "employees.sql"
    - "load_departments.dump"
    - "load_employees.dump"
    - "load_dept_emp.dump"
    - "load_dept_manager.dump"
    - "load_titles.dump"
    - "load_salaries1.dump"
    - "load_salaries2.dump"
    - "load_salaries3.dump"
    - "show_elapsed.sql"
```

当我们调用这些变量时，它们需要以`mariadb_sample_database`为前缀。例如，每当我们需要使用`db_name`变量时，我们将需要使用`mariadb_sample_database.db_name`。就像我们在上一节中复制 HTML 文件时一样，我们将为每个任务添加一个使用`when`的条件，这意味着如果需要，它们可以被跳过。

我们需要做的第一件事是从 GitHub 下载转储文件的副本并解压缩它们。为此，我们将使用`unarchive`模块：

```
- name: download and unarchive the sample database data
  unarchive:
    src: "{{ mariadb_sample_database.source_url }}"
    dest: "/tmp"
    remote_src: "yes"
  when: mariadb_sample_database.create_database == true
```

我们正在从远程位置获取文件，即 URL`mariadb_sample_database.source_url`，并在`/tmp`中解压缩它。由于我们将`remote_src`设置为`yes`，Ansible 知道它必须从远程源下载文件。如果我们没有提供完整的 URL，它将尝试从控制主机复制文件。

接下来的两个任务使用`mysql_db`和`mysql_user`模块来创建数据库和一个可以访问它的用户：

```
- name: create the sample database
  mysql_db:
    db: "{{ mariadb_sample_database.db_name }}" 
    state: "present"
  when: mariadb_sample_database.create_database == true

- name: create the user for the sample database
  mysql_user:
    name: "{{ mariadb_sample_database.db_user }}"
    password: "{{ mariadb_sample_database.db_password }}"
    priv: "{{ mariadb_sample_database.db_name }}.*:ALL"
    state: "present"
  with_items: "{{ mariadb_hosts }}"
  when: mariadb_sample_database.create_database == true
```

playbook 的最后部分将 MySQL 转储文件导入数据库；然而，在导入文件之前，我们应该首先检查转储文件是否已经被导入。如果我们每次运行 playbook 时不执行此检查，转储文件将被导入。为了检查数据是否已经被导入，我们将使用`stat`模块；这将检查文件的存在并收集有关它的信息。

如果我们已经导入了数据，`/var/lib/mysql/employees`文件夹中将会有一个名为`employees.frm`的文件，因此让我们检查一下：

```
- name: check to see if we need to import the sample database dumps
  stat:
    path: "/var/lib/mysql/{{ mariadb_sample_database.db_name }}/{{ mariadb_sample_database.db_name }}.frm"
  register: db_imported
  when: mariadb_sample_database.create_database == true
```

现在我们知道是否需要导入数据库转储，我们可以继续进行最后的任务，如果满足以下条件，将导入`mariadb_sample_database.dump_files`中列出的数据库转储：

+   变量`db_imported`是否已定义？如果没有，则我们将跳过导入示例数据库，并且应该跳过此任务。

+   `db_imported.stat.exists`是否等于`false`？如果是，则文件不存在，我们应该导入数据。

该任务本身使用`mysql_db`模块来导入数据：

```
- name: import the sample database
  mysql_db:
    name: "{{ mariadb_sample_database.db_name }}"
    state: "import"
    target: "{{ mariadb_sample_database.path }}/{{ item }}"
  with_items: "{{ mariadb_sample_database.dump_files }}"
  when: db_imported is defined and db_imported.stat.exists == false
```

这完成了将示例数据库导入到我们的 MariaDB 安装中；现在让我们运行 playbook 并调用角色。

# 运行角色

现在我们已经编写了我们的角色，我们可以将其添加到我们的 playbook 中：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/common
    - roles/apache
    - roles/mariadb
```

同样，我们可以使用以下命令重新运行 playbook：

```
$ ansible-playbook -i production site.yml
```

在继续进行 MariaDB 等效之前，这将通过常见和 Apache 角色进行操作。这个 playbook 输出开始于 MariaDB 角色开始之前：

```
TASK [roles/apache : set the selinux allowing httpd_t to be permissive] ***************************************************************************************************
ok: [box]

TASK [roles/apache : copy the test HTML page to the document root] ********************************************************************************************************
ok: [box]

TASK [roles/mariadb : remove the packages so that they can be replaced] ***************************************************************************************************
changed: [box] => (item=[u'mariadb-libs.x86_64'])

TASK [roles/mariadb : install the mariadb packages] ***********************************************************************************************************************
changed: [box] => (item=[u'mariadb101u', u'mariadb101u-server', u'mariadb101u-config', u'mariadb101u-common', u'mariadb101u-libs', u'MySQL-python', u'postfix'])

TASK [roles/mariadb : start mariadb] **************************************************************************************************************************************
changed: [box]

TASK [roles/mariadb : change mysql root password] *************************************************************************************************************************
changed: [box] => (item=127.0.0.1)
changed: [box] => (item=::1)
changed: [box] => (item=192.168.50.4.nip.io)
changed: [box] => (item=%)
changed: [box] => (item=localhost)

TASK [roles/mariadb : set up .my.cnf file] ********************************************************************************************************************************
changed: [box]

TASK [roles/mariadb : delete anonymous MySQL user] ************************************************************************************************************************
ok: [box] => (item=127.0.0.1)
ok: [box] => (item=::1)
changed: [box] => (item=192.168.50.4.nip.io)
ok: [box] => (item=%)
changed: [box] => (item=localhost)

TASK [roles/mariadb : remove the MySQL test database] *********************************************************************************************************************
changed: [box]

TASK [roles/mariadb : download and unarchive the sample database data] ****************************************************************************************************
changed: [box]

TASK [roles/mariadb : create the sample database] *************************************************************************************************************************
changed: [box]

TASK [roles/mariadb : create the user for the sample database] ************************************************************************************************************
changed: [box] => (item=127.0.0.1)
ok: [box] => (item=::1)
ok: [box] => (item=192.168.50.4.nip.io)
ok: [box] => (item=%)
ok: [box] => (item=localhost)

TASK [roles/mariadb : check to see if we need to import the sample database dumps] ****************************************************************************************
ok: [box]

TASK [roles/mariadb : import the sample database] *************************************************************************************************************************
changed: [box] => (item=employees.sql)
changed: [box] => (item=load_departments.dump)
changed: [box] => (item=load_employees.dump)
changed: [box] => (item=load_dept_emp.dump)
changed: [box] => (item=load_dept_manager.dump)
changed: [box] => (item=load_titles.dump)
changed: [box] => (item=load_salaries1.dump)
changed: [box] => (item=load_salaries2.dump)
changed: [box] => (item=load_salaries3.dump)
changed: [box] => (item=show_elapsed.sql)

PLAY RECAP ****************************************************************************************************************************************************************
box : ok=26 changed=11 unreachable=0 failed=0
```

如果我们重新运行 playbook，playbook 运行的最后部分将返回以下内容：

```
TASK [roles/mariadb : download and unarchive the sample database data] ****************************************************************************************************
ok: [box]

TASK [roles/mariadb : create the sample database] *************************************************************************************************************************
ok: [box]

TASK [roles/mariadb : create the user for the sample database] ************************************************************************************************************
ok: [box] => (item=127.0.0.1)
ok: [box] => (item=::1)
ok: [box] => (item=192.168.50.4.nip.io)
ok: [box] => (item=%)
ok: [box] => (item=localhost)

TASK [roles/mariadb : check to see if we need to import the sample database dumps] ****************************************************************************************
ok: [box]

TASK [roles/mariadb : import the sample database] *************************************************************************************************************************
skipping: [box] => (item=employees.sql)
skipping: [box] => (item=load_departments.dump)
skipping: [box] => (item=load_employees.dump)
skipping: [box] => (item=load_dept_emp.dump)
skipping: [box] => (item=load_dept_manager.dump)
skipping: [box] => (item=load_titles.dump)
skipping: [box] => (item=load_salaries1.dump)
skipping: [box] => (item=load_salaries2.dump)
skipping: [box] => (item=load_salaries3.dump)
skipping: [box] => (item=show_elapsed.sql)

PLAY RECAP ****************************************************************************************************************************************************************
box : ok=25 changed=0 unreachable=0 failed=0
```

如你所见，我们设置的检查以防止重新导入数据库转储的工作效果如预期。我们可以使用 Sequel Pro 或 MySQL Workbench 等工具测试我们的 MariaDB 安装；只需使用以下主机和凭据连接：

+   主机：`192.168.50.4.nip.io`

+   端口：`3306`

+   用户名：`root`

+   密码：`Pa55W0rd123`

以下截图来自 Sequel Pro，显示了我们导入到`employees 数据库`中的`employees`表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/b477b72d-02f7-46b0-8fd9-ef8613e90a8c.png)

现在我们已经安装、配置了 MariaDB，并导入了一些示例数据，让我们来看看创建一个安装 PHP 的角色，这是我们 LAMP 堆栈的最后一个组件。

# PHP

我们正在组合的堆栈的最后一个元素是 PHP。与其他三个元素一样，我们需要使用`ansible-galaxy init`命令创建一个角色：

```
$ ansible-galaxy init roles/php
```

与堆栈的其他部分一样，我们将使用 IUS 存储库中的软件包；这将允许我们安装 PHP 的最新版本，即 7.2 版本。

# 安装 PHP

与堆栈的前三部分一样，我们将从安装软件包开始。与以前一样，我们在`roles/php/default/main.yml`中定义了一个变量，列出了我们需要的所有软件包：

```
php_packages:
  - "php72u"
  - "php72u-bcmath"
  - "php72u-cli"
  - "php72u-common"
  - "php72u-dba"
  - "php72u-fpm"
  - "php72u-fpm-httpd"
  - "php72u-gd"
  - "php72u-intl"
  - "php72u-json"
  - "php72u-mbstring"
  - "php72u-mysqlnd"
  - "php72u-odbc"
  - "php72u-pdo"
  - "php72u-process"
  - "php72u-snmp"
  - "php72u-soap"
  - "php72u-xml"
  - "php72u-xmlrpc"
```

这是在`php/roles/tasks/main.yml`中使用 YUM 模块安装的：

```
- name: install the php packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ php_packages }}"
  notify:
    - "restart php-fpm"
    - "restart httpd"
```

从这个任务中可以看出，我们正在通知两个不同的处理程序，一个是 Apache，另一个是 PHP-FPM。你可能会想：为什么我们需要通知 Apache？

**FastCGI 进程管理器**（**FPM**）是一个 PHP FastCGI 实现，它有助于使繁忙的 PHP 网站运行更高效。它还增加了使用不同用户和组 ID 启动 PHP 工作者的能力，可以使用不同的`php.ini`文件在不同的端口上监听，从而允许您创建处理负载的 PHP 工作者池。

由于我们正在安装`php72u-fpm`软件包，我们需要配置 Apache 以使用`php72u-fpm-httpd`软件包中设置的配置；如果不这样做，Apache 将不会加载配置，这会指示它如何与 PHP-FPM 交互。

PHP-FPM 的处理程序可以在`roles/php/handlers/main.yml`中找到，其中包含以下内容：

```
- name: "restart php-fpm"
  service:
    name: "php-fpm"
    state: "restarted"
    enabled: "yes"
```

这就是 PHP 安装和配置的全部内容；现在我们应该有一个可用的 PHP 安装，并且我们可以使用 phpinfo 文件进行测试。

# phpinfo 文件

与 Apache 安装一样，我们可以添加选项来上传一个测试文件，这里是一个简单的 PHP 文件，调用`php_info`函数。这会显示关于我们的 PHP 安装的信息。上传此文件的任务如下所示：

```
- name: copy the test PHP page to the document root
  copy:
    src: "info.php"
    dest: "{{ document_root }}/info.php"
    mode: "0755"
    owner: "{{ users.0.name }}"
    group: "{{ apache_group }}"
  when: php_info == true
```

如你所见，只有在`roles/php/default/main.yml`中设置以下内容时才会被调用：

```
php_info: true
```

我们从我们的 Ansible 控制器复制到主机的文件可以在`roles/php/files/info.php`中找到，它包含以下三行：

```
<?php
  phpinfo();
?>
```

虽然这表明 PHP 已安装并运行，但并不是很有趣，因此在运行 playbook 之前，让我们添加一些将我们的 LAMP 堆栈所有元素联系在一起的步骤。

# Adminer

playbook 的最后一个任务将是安装一个名为 Adminer 的 PHP 脚本；这提供了一个用于与数据库交互和管理的基于 PHP 的界面。安装 Adminer 有三个步骤，所有这些步骤都使用`roles/php/defaults/main.yml`中的嵌套变量：

```
adminer:
  install: true
  path: "/usr/share/adminer"
  download: "https://github.com/vrana/adminer/releases/download/v4.6.2/adminer-4.6.2-mysql.php"
```

如您所见，我们再次使用嵌套变量，这次是告诉我们的 playbook 安装工具的位置，应该安装在哪里，以及可以从哪里下载。`roles/php/tasks/main.yml`中的第一个任务是创建我们将安装 Adminer 的目录：

```
- name: create the document root for adminer
  file:
    dest: "{{ adminer.path }}"
    state: "directory"
    mode: "0755"
  when: adminer.install == true
```

现在我们在 Vagrant 盒子上有了一个安装 Adminer 的地方，我们应该下载它。这一次，由于我们不是在下载存档，我们使用`get_url`模块：

```
- name: download adminer
  get_url:
    url: "{{ adminer.download }}"
    dest: "{{ adminer.path }}/index.php"
    mode: 0755
  when: adminer.install == true
```

如您所见，我们正在从 GitHub 下载`adminer-4.6.2-mysql.php`文件，并将其保存到**`/usr/share/adminer/index.php`**，那么我们如何访问它呢？任务的最后一部分使用模板模块将额外的 Apache 配置文件上传到`/etc/httpd/conf.d/adminer.conf`：

```
- name: copy the vhost.conf to /etc/httpd/conf.d/
  template:
    src: "adminer.conf.j2"
    dest: "/etc/httpd/conf.d/adminer.conf"
  when: adminer.install == true
  notify: "restart httpd"
```

`adminer.conf.j2` 模板应放置在 `roles/php/templates`，如下所示：

```
# {{ ansible_managed }}
Alias /adminer "{{ adminer.path }}"
  <Directory "{{ adminer.path }}">
    DirectoryIndex index.php
    AllowOverride All
    Require all granted
  </Directory>
```

如您所见，它正在创建一个名为`/adminer`的别名，然后指向`/usr/share/adminer/`中的`index.php`。由于我们正在添加到 Apache 配置文件，因此我们还通知`restart httpd`处理程序，以便 Apache 重新启动，从而获取我们更新的配置。

# 运行角色

现在我们的 LAMP 堆栈的最后一个元素的角色已经完成，我们可以将其添加到我们的 playbook 中。现在它应该看起来像下面这样：

```
---

- hosts: boxes
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/common
    - roles/apache
    - roles/mariadb
    - roles/php
```

使用以下命令运行它：

```
$ ansible-playbook -i production site.yml
```

这将在我们的 Vagrant 盒子上部署 PHP；此输出作为调用 PHP 角色：

```
TASK [roles/php : install the php packages] ********************************************************
changed: [box] => (item=[u'php72u', u'php72u-bcmath', u'php72u-cli', u'php72u-common', u'php72u-dba', u'php72u-fpm', u'php72u-fpm-httpd', u'php72u-gd', u'php72u-intl', u'php72u-json', u'php72u-mbstring', u'php72u-mysqlnd', u'php72u-odbc', u'php72u-pdo', u'php72u-process', u'php72u-snmp', u'php72u-soap', u'php72u-xml', u'php72u-xmlrpc'])

```

```
TASK [roles/php : copy the test PHP page to the document root] *************************************
changed: [box]

TASK [roles/php : create the document root for adminer] ********************************************
changed: [box]

TASK [roles/php : download adminer] ****************************************************************
changed: [box]

TASK [roles/php : copy the vhost.conf to /etc/httpd/conf.d/] ***************************************
changed: [box]

RUNNING HANDLER [roles/common : restart ntp] *******************************************************
changed: [box]

RUNNING HANDLER [roles/apache : restart httpd] *****************************************************
changed: [box]

RUNNING HANDLER [roles/php : restart php-fpm] ******************************************************
changed: [box]

PLAY RECAP *****************************************************************************************
box : ok=34 changed=32 unreachable=0 failed=0
```

安装完成后，您应该能够访问以下 URL：

+   `http://192.168.50.4.nip.io/info.php`

+   `http://192.168.50.4.nip.io/adminer/`

当您访问第一个链接时，您应该看到类似以下页面的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/8eb962a8-3707-4f0e-9012-5b1e92c0b487.png)

在第二个链接中，一旦使用用户名`root`和密码`Pa55W0rd123`登录，您应该能够看到`employees`数据库：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ae89246a-76c7-4ddb-b97d-933c6727b4c1.png)

使用 Adminer，我们有一个 PHP 脚本访问我们的 MariaDB 数据库；页面是由我们的 Linux Vagrant 盒子上的 Apache 提供的。

# 覆盖变量

在我们完成之前，我们应该快速讨论一下如何覆盖我们一直在设置的默认变量。为此，将以下行添加到`group_vars/common.yml`文件中：

```
html_body: |
  This HTML page has been deployed using Ansible to <b>{{ ansible_nodename }}</b>.<br>
  The user is <b>{{ users.0.name }}</b> who is in the <b>{{ apache_group }}</b> group.<br>
  The weboot is <b>{{ document_root }}</b>, the default index file is <b>{{ index_file }}</b>.<br>
  You can access a <a href="/info.php">PHP Info file</a> or <a href="/adminer/">Adminer</a>.
```

然后重新运行 playbook。一旦 playbook 完成，打开`http://192.168.50.4.nip.io/`将显示以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/aec7ff55-decf-451e-b465-b1234979f1aa.png)

如您所见，默认的`index.html`页面已更新为包含指向我们的 phpinfo 页面和 Adminer 的链接。我们配置为默认的任何变量都可以以这种方式被覆盖。

# 摘要

在本章中，我们已经通过编写一个 playbook，在我们的 CentOS 7 Vagrant 盒子上安装了一个 LAMP 堆栈。我们创建了四个角色，每个角色对应堆栈的一个元素，并在每个角色中构建了一些逻辑，可以覆盖以部署其他元素，如测试 HTML 和 PHP 页面，并且还内置了创建一个包含超过 40,000 条记录的测试数据库的选项。

到目前为止，我们已经安装了一些非常基本的软件包。在下一章中，我们将编写一个安装、配置和维护 WordPress 安装的 playbook。

# 问题

1.  您会使用哪个 Ansible 模块来下载和解压缩 zip 文件？

1.  真或假：在**`roles/rolename/default/`**文件夹中找到的变量会覆盖所有其他相同变量的引用。

1.  解释一下你会如何向我们的 playbook 中添加第二个用户

1.  真或假：你只能从一个任务中调用一个处理程序。

1.  更新最终的 playbook 以添加第二个虚拟主机，它提供不同的默认 HTML 页面。

# 进一步阅读

你可以在以下 URL 找到本章中涵盖的第三方工具的项目页面：

+   **CentOS**: [`www.centos.org/`](https://www.centos.org/)

+   **Apache**: [`httpd.apache.org/`](https://httpd.apache.org/)

+   **MariaDB**: [`mariadb.org/`](https://mariadb.org/)

+   **Datacharmer test database**: [`github.com/datacharmer/test_db`](https://github.com/datacharmer/test_db)

+   **PHP**: [`php.net/`](https://php.net/)

+   **PHP-FPM**: [`php-fpm.org/`](https://php-fpm.org)

+   **Adminer**: [`www.adminer.org`](https://www.adminer.org)
