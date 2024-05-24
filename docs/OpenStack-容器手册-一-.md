# OpenStack 容器手册（一）

> 原文：[`zh.annas-archive.org/md5/D8A2C6F8428362E7663D33F30363BDEB`](https://zh.annas-archive.org/md5/D8A2C6F8428362E7663D33F30363BDEB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

容器是近年来最受关注的技术之一。随着它们改变了我们开发、部署和运行软件应用程序的方式，它们变得越来越受欢迎。OpenStack 因被全球许多组织使用而获得了巨大的关注，随着容器的普及和复杂性的增加，OpenStack 需要为容器提供各种基础设施资源，如计算、网络和存储。

*OpenStack 中的容器化*旨在回答一个问题，那就是 OpenStack 如何跟上容器技术不断增长的挑战？您将首先熟悉容器和 OpenStack 的基础知识，以便了解容器生态系统和 OpenStack 如何协同工作。为了帮助您更好地掌握计算、网络、管理应用服务和部署工具，本书为不同的 OpenStack 项目专门设置了章节：Magnum、Zun、Kuryr、Murano 和 Kolla。

最后，您将了解一些保护容器和 OpenStack 上的容器编排引擎的最佳实践，并概述了如何使用每个 OpenStack 项目来处理不同的用例。

# 本书内容包括：

第一章，*使用容器*，从讨论虚拟化的历史开始，然后讨论容器的演变。之后，重点解释了容器、它们的类型和不同的容器运行时工具。然后深入介绍了 Docker 及其安装，并展示了如何使用 Docker 对容器执行操作。

第二章，*使用容器编排引擎*，从介绍容器编排引擎开始，然后介绍了当今可用的不同容器编排引擎。它解释了 Kubernetes 的安装以及如何在示例应用程序中使用它来管理容器。

第三章，*OpenStack 架构*，从介绍 OpenStack 及其架构开始。然后简要解释了 OpenStack 的核心组件及其架构。

第四章，*OpenStack 中的容器化*，解释了 OpenStack 中容器化的需求，并讨论了不同的与 OpenStack 相关的容器项目。

《第五章》（part0124.html#3M85O0-08510d04d33546e798ef8c1140114deb），*Magnum – OpenStack 中的 COE 管理*，详细介绍了 OpenStack 的 Magnum 项目。它讨论了 Magnum 的概念、组件和架构。然后，它演示了使用 DevStack 安装 Magnum 并进行实际操作。

《第六章》（part0152.html#4GULG0-08510d04d33546e798ef8c1140114deb），*Zun – OpenStack 中的容器管理*，详细介绍了 OpenStack 的 Zun 项目。它讨论了 Zun 的概念、组件和架构。然后，它演示了使用 DevStack 安装 Zun 并进行实际操作。

《第七章》（part0178.html#59O440-08510d04d33546e798ef8c1140114deb），*Kuryr – OpenStack 网络的容器插件*，详细介绍了 OpenStack 的 Kuryr 项目。它讨论了 Kuryr 的概念、组件和架构。然后，它演示了使用 DevStack 安装 Kuryr 并进行实际操作。

《第八章》（part0188.html#5J99O0-08510d04d33546e798ef8c1140114deb），*Murano – 在 OpenStack 上部署容器化应用*，详细介绍了 OpenStack 的 Murano 项目。它讨论了 Murano 的概念、组件和架构。然后，它演示了使用 DevStack 安装 Murano 并进行实际操作。

《第九章》（part0216.html#6DVPG0-08510d04d33546e798ef8c1140114deb），*Kolla – OpenStack 的容器化部署*，详细介绍了 OpenStack 的 Kolla 项目。它讨论了 Kolla 的子项目、主要特点和架构。然后，它解释了使用 Kolla 项目部署 OpenStack 生态系统的过程。

《第十章》（part0233.html#6U6J20-08510d04d33546e798ef8c1140114deb），*容器和 OpenStack 的最佳实践*，总结了不同与容器相关的 OpenStack 项目及其优势。然后，它还解释了容器的安全问题以及解决这些问题的最佳实践。

# 本书所需的内容

本书假定读者具有基本的云计算、Linux 操作系统和容器的理解。本书将指导您安装所需的任何工具。

您可以使用任何测试环境的工具，如 Vagrant、Oracle 的 VirtualBox 或 VMware 工作站。

在本书中，需要以下软件清单：

+   操作系统：Ubuntu 16.04

+   OpenStack：Pike 版本或更新版本

+   VirtualBox 4.5 或更新版本

+   Vagrant 1.7 或更新版本

要在开发环境中运行 OpenStack 安装，需要以下最低硬件资源：

+   具有 CPU 硬件虚拟化支持的主机

+   8 核 CPU

+   12 GB 的 RAM

+   60 GB 的免费磁盘空间

需要互联网连接来下载 OpenStack 和其他工具的必要软件包。

# 这本书适合谁

这本书的目标读者是云工程师、系统管理员，或者任何在 OpenStack 云上工作的生产团队成员。本书是一本端到端的指南，适用于任何想要在 OpenStack 中开始使用容器化概念的人。

# 约定

在本书中，您会发现一些不同类型信息的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`zun-compute`服务是 Zun 系统的主要组件。”

任何命令行输入或输出都以以下形式编写：

```
$ sudo mkdir -p /opt/stack
```

新术语和重要词以粗体显示。例如，在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中：“您可以在以下截图中看到，我们有两个选项可供选择作为我们的容器主机：Kubernetes Pod 和 Docker Standalone Host。”

警告或重要提示会出现在这样的框中。提示和技巧会以这样的形式出现。


# 第一章：使用容器

本章介绍了容器和与之相关的各种主题。在本章中，我们将涵盖以下主题：

+   虚拟化的历史背景

+   容器的介绍

+   容器组件

+   容器的类型

+   容器运行时工具的类型

+   Docker 的安装

+   Docker 实践

# 虚拟化的历史背景

传统虚拟化出现在 Linux 内核中，以 Xen 和 KVM 等虚拟机监视程序的形式。这允许用户以**虚拟机**（**VM**）的形式隔离其运行时环境。虚拟机运行其自己的操作系统内核。用户尝试尽可能多地使用主机机器上的资源。然而，使用这种形式的虚拟化难以实现高密度，特别是当部署的应用程序与内核相比较小时；主机的大部分内存被运行在其上的多个内核副本所消耗。因此，在这种高密度工作负载中，使用诸如*chroot jails*之类的技术来划分机器，提供了不完善的工作负载隔离并带来了安全隐患。

2001 年，以 Linux vServer 的形式引入了操作系统虚拟化，作为一系列内核补丁。

这导致了早期形式的容器虚拟化。在这种形式的虚拟化中，内核对属于不同租户的进程进行分组和隔离，每个租户共享相同的内核。

这是一张表，解释了各种发展，使操作系统虚拟化成为可能：

| **年份和发展** | **描述** |
| --- | --- |
| 1979 年：chroot | 容器概念早在 1979 年就出现了，使用 UNIX chroot。后来，在 1982 年，这被纳入了 BSD。使用 chroot，用户可以更改任何正在运行的进程及其子进程的根目录，将其与主操作系统和目录分离。 |
| 2000 年：FreeBSD Jails | FreeBSD Jails 是由 Derrick T. Woolworth 于 2000 年在 R＆D associates 为 FreeBSD 引入的。它是类似于 chroot 的操作系统系统调用，具有用于隔离文件系统、用户、网络等的附加进程沙盒功能。 |
| 2001 年：Linux vServer | 另一种可以在计算机系统上安全分区资源（文件系统、CPU 时间、网络地址和内存）的监狱机制。 |
| 2004 年：Solaris 容器 | Solaris 容器适用于 x86 和 SPARC 系统，并于 2004 年 2 月首次公开发布。它们是系统资源控制和区域提供的边界分离的组合。 |
| 2005 年：OpenVZ | OpenVZ 类似于 Solaris 容器，并利用经过修补的 Linux 内核提供虚拟化、隔离、资源管理和检查点。 |
| 2006 年：进程容器 | 谷歌在 2006 年实施了进程容器，用于限制、记账和隔离一组进程的资源使用（CPU、内存、磁盘 I/O、网络等）。 |
| 2007 年：控制组 | 控制组，也称为 CGroups，是由谷歌实施并于 2007 年添加到 Linux 内核中的。CGroups 有助于限制、记账和隔离一组进程的资源使用（内存、CPU、磁盘、网络等）。 |
| 2008 年：LXC | LXC 代表 Linux 容器，使用 CGroups 和 Linux 命名空间实施。与其他容器技术相比，LXC 在原始 Linux 内核上运行。 |
| 2011 年：Warden | Warden 是 Cloud Foundry 在 2011 年使用 LXC 初期阶段实施的；后来，它被他们自己的实现所取代。 |
| 2013 年：LMCTFY | **LMCTFY**代表**让我来为你容纳**。它是谷歌容器堆栈的开源版本，提供 Linux 应用程序容器。 |
| 2013 年：Docker | Docker 始于 2016 年。如今它是最广泛使用的容器管理工具。 |
| 2014 年：Rocket | Rocket 是来自 CoreOS 的另一个容器运行时工具。它出现是为了解决早期版本 Docker 的安全漏洞。Rocket 是另一个可以用来替代 Docker 的选择，具有更好的安全性、可组合性、速度和生产要求。 |
| 2016 年：Windows 容器 | 微软在 2015 年为基于 Windows 的应用程序向 Microsoft Windows Server 操作系统添加了容器支持（Windows 容器）。借助这一实施，Docker 将能够在 Windows 上本地运行 Docker 容器，而无需运行虚拟机。 |

# 容器简介

Linux 容器是操作系统级别的虚拟化，可以在单个主机上提供多个隔离的环境。它们不像虚拟机那样使用专用的客户操作系统，而是共享主机操作系统内核和硬件。

在容器成为关注焦点之前，主要使用多任务处理和基于传统虚拟化程序的虚拟化。多任务处理允许多个应用程序在同一台主机上运行，但是它在不同应用程序之间提供了较少的隔离。

基于传统虚拟化程序的虚拟化允许多个客户机在主机机器上运行。每个客户机都运行自己的操作系统。这种方法提供了最高级别的隔离，以及在同一硬件上同时运行不同操作系统的能力。

然而，它也带来了一些缺点：

+   每个操作系统启动需要一段时间

+   每个内核占用自己的内存和 CPU，因此虚拟化的开销很大

+   I/O 效率较低，因为它必须通过不同的层

+   资源分配不是基于细粒度的，例如，内存在虚拟机创建时分配，一个虚拟机空闲的内存不能被其他虚拟机使用

+   保持每个内核最新的维护负担很大

以下图解释了虚拟化的概念：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00005.jpeg)

容器提供了最好的两种方式。为了为容器提供隔离和安全的环境，它们使用 Linux 内核功能，如 chroot、命名空间、CGroups、AppArmor、SELinux 配置文件等。

通过 Linux 安全模块确保了容器对主机机器内核的安全访问。由于没有内核或操作系统启动，启动速度更快。资源分配是细粒度的，并由主机内核处理，允许有效的每个容器的服务质量（QoS）。下图解释了容器虚拟化。

然而，与基于传统虚拟化程序的虚拟化相比，容器也有一些缺点：客户操作系统受限于可以使用相同内核的操作系统。

传统的虚拟化程序提供了额外的隔离，这在容器中是不可用的，这意味着在容器中嘈杂的邻居问题比在传统的虚拟化程序中更为显著：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00006.jpeg)

# 容器组件

Linux 容器通常由五个主要组件组成：

+   **内核命名空间**: 命名空间是 Linux 容器的主要构建模块。它们将各种类型的 Linux 资源，如网络、进程、用户和文件系统，隔离到不同的组中。这允许不同组的进程完全独立地查看它们的资源。可以分隔的其他资源包括进程 ID 空间、IPC 空间和信号量空间。

+   **控制组**: 控制组，也称为 CGroups，限制和记录不同类型的资源使用，如 CPU、内存、磁盘 I/O、网络 I/O 等，跨一组不同的进程。它们有助于防止一个容器由于另一个容器导致的资源饥饿或争用，并因此维护 QoS。

+   **安全性**: 容器中的安全性是通过以下组件提供的:

+   **根权限**: 这将有助于通过降低根用户的权限来执行特权容器中的命名空间，有时甚至可以完全取消根用户的权限。

+   **自主访问控制(DAC)**: 它基于用户应用的策略来调解对资源的访问，以便个别容器不能相互干扰，并且可以由非根用户安全地运行。

+   **强制访问控制(MAC)**: 强制访问控制(MAC)，如 AppArmor 和 SELinux，并不是创建容器所必需的，但通常是其安全性的关键要素。MAC 确保容器代码本身以及容器中运行的代码都没有比进程本身需要的更大程度的访问权限。这样，它最小化了授予恶意或被入侵进程的权限。

+   **工具集**: 在主机内核之上是用户空间的工具集，如 LXD、Docker 和其他库，它们帮助管理容器。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00007.jpeg)

# 容器的类型

容器的类型如下:

# 机器容器

机器容器是共享主机操作系统内核但提供用户空间隔离的虚拟环境。它们看起来更像虚拟机。它们有自己的 init 进程，并且可以运行有限数量的守护程序。程序可以安装、配置和运行，就像在任何客户操作系统上一样。与虚拟机类似，容器内运行的任何内容只能看到分配给该容器的资源。当使用情况是运行一组相同或不同版本的发行版时，机器容器非常有用。

机器容器拥有自己的操作系统并不意味着它们正在运行自己内核的完整副本。相反，它们运行一些轻量级的守护程序，并具有一些必要的文件，以在另一个操作系统中提供一个独立的操作系统。

诸如 LXC、OpenVZ、Linux vServer、BSD Jails 和 Solaris zones 之类的容器技术都适用于创建机器容器。

以下图显示了机器容器的概念：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00008.jpeg)

# 应用容器

虽然机器容器旨在运行多个进程和应用程序，但应用容器旨在打包和运行单个应用程序。它们被设计得非常小。它们不需要包含 shell 或`init`进程。应用容器所需的磁盘空间非常小。诸如 Docker 和 Rocket 之类的容器技术就是应用容器的例子。

以下图解释了应用容器：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00009.jpeg)**

# 容器运行时工具的类型

今天有多种解决方案可用于管理容器。本节讨论了替代类型的容器。

# Docker

**Docker**是全球领先的容器平台软件。它自 2013 年以来就可用。Docker 是一个容器运行时工具，旨在通过使用容器更轻松地创建、部署和运行应用程序。Docker 通过容器化大大降低了管理应用程序的复杂性。它允许应用程序使用与主机操作系统相同的 Linux 内核，而不像虚拟机那样创建具有专用硬件的全新操作系统。Docker 容器可以在 Linux 和 Windows 工作负载上运行。Docker 容器已经在软件开发中实现了巨大的效率提升，但需要 Swarm 或 Kubernetes 等运行时工具。

# Rocket

**Rocket**是来自 CoreOS 的另一个容器运行时工具。它出现是为了解决 Docker 早期版本中的安全漏洞。Rocket 是 Docker 的另一种可能性或选择，具有最解决的安全性、可组合性、速度和生产要求。Rocket 在许多方面与 Docker 构建了不同的东西。主要区别在于 Docker 运行具有根权限的中央守护程序，并将一个新的容器作为其子进程，而 Rocket 从不以根权限旋转容器。然而，Docker 始终建议在 SELinux 或 AppArmor 中运行容器。自那时起，Docker 已经提出了许多解决方案来解决这些缺陷。

# LXD

**LXD**是 Ubuntu 管理 LXC 的容器超级监视器。LXD 是一个守护程序，提供运行容器和管理相关资源的 REST API。LXD 容器提供与传统虚拟机相同的用户体验，但使用 LXC，这提供了类似于容器的运行性能和比虚拟机更好的利用率。LXD 容器运行完整的 Linux 操作系统，因此通常运行时间较长，而 Docker 应用程序容器则是短暂的。这使得 LXD 成为一种与 Docker 不同的机器管理工具，并且更接近软件分发。

# OpenVZ

**OpenVZ**是 Linux 的基于容器的虚拟化技术，允许在单个物理服务器上运行多个安全、隔离的 Linux 容器，也被称为**虚拟环境**（**VEs**）和**虚拟专用服务器**（**VPS**）。OpenVZ 可以更好地利用服务器，并确保应用程序不发生冲突。它类似于 LXC。它只能在基于 Linux 的操作系统上运行。由于所有 OpenVZ 容器与主机共享相同的内核版本，用户不允许进行任何内核修改。然而，由于共享主机内核，它也具有低内存占用的优势。

# Windows Server 容器

Windows Server 2016 将 Linux 容器引入了 Microsoft 工作负载。微软与 Docker 合作，将 Docker 容器的优势带到 Microsoft Windows Server 上。他们还重新设计了核心 Windows 操作系统，以实现容器技术。有两种类型的 Windows 容器：Windows 服务器容器和 Hyper-V 隔离。

Windows 服务器容器用于在 Microsoft 工作负载上运行应用程序容器。它们使用进程和命名空间隔离技术，以确保多个容器之间的隔离。它们还与主机操作系统共享相同的内核，因为这些容器需要与主机相同的内核版本和配置。这些容器不提供严格的安全边界，不应用于隔离不受信任的代码。

# Hyper-V 容器

Hyper-V 容器是一种 Windows 容器，相对于 Windows 服务器容器提供了更高的安全性。Hyper-V 在轻量级、高度优化的 Hyper-V 虚拟机中托管 Windows 服务器容器。因此，它们提供了更高程度的资源隔离，但以牺牲主机的效率和密度为代价。当主机操作系统的信任边界需要额外的安全性时，可以使用它们。在这种配置中，容器主机的内核不与同一主机上的其他容器共享。由于这些容器不与主机或主机上的其他容器共享内核，它们可以运行具有不同版本和配置的内核。用户可以选择在运行时使用或不使用 Hyper-V 隔离来运行容器。

# 清晰容器

虚拟机安全但非常昂贵且启动缓慢，而容器启动快速并提供了更高效的替代方案，但安全性较低。英特尔的清晰容器是基于 Hypervisor 的虚拟机和 Linux 容器之间的折衷解决方案，提供了类似于传统 Linux 容器的灵活性，同时还提供了基于硬件的工作负载隔离。

清晰容器是一个包裹在自己独立的超快、精简的虚拟机中的容器，提供安全性和效率。清晰容器模型使用了经过优化以减少内存占用和提高启动性能的快速轻量级的 QEMU hypervisor。它还在内核中优化了 systemd 和核心用户空间，以实现最小内存消耗。这些特性显著提高了资源利用效率，并相对于传统虚拟机提供了增强的安全性和速度。

英特尔清晰容器提供了一种轻量级机制，用于将客户环境与主机隔离，并为工作负载隔离提供基于硬件的执行。此外，操作系统层从主机透明、安全地共享到每个英特尔清晰容器的地址空间中，提供了高安全性和低开销的最佳组合。

由于清晰容器提供的安全性和灵活性增强，它们的采用率很高。如今，它们与 Docker 项目无缝集成，并增加了英特尔 VT 的保护。英特尔和 CoreOS 密切合作，将清晰容器整合到 CoreOS 的 Rocket（Rkt）容器运行时中。

# Docker 的安装

Docker 有两个版本，**社区版（CE）**和**企业版（EE）**：

+   **Docker 社区版（CE）**：它非常适合希望开始使用 Docker 并可能正在尝试基于容器的应用程序的开发人员和小团队。

+   **Docker 企业版（EE）**：它专为企业开发和 IT 团队设计，他们在生产环境中构建，发布和运行业务关键应用程序

本节将演示在 Ubuntu 16.04 上安装 Docker CE 的说明。在官方 Ubuntu 16.04 存储库中提供的 Docker 安装包可能不是最新版本。要获取最新版本，请从官方 Docker 存储库安装 Docker。本节将向您展示如何做到这一点：

1.  首先，将官方 Docker 存储库的 GPG 密钥添加到系统中：

```
 $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg |
        sudo apt-key add 
```

1.  将 Docker 存储库添加到 APT 源：

```
 $ sudo add-apt-repository "deb [arch=amd64]
 https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" 
```

1.  接下来，使用新添加的存储库更新 Docker 软件包的软件包数据库：

```
 $ sudo apt-get update 
```

1.  确保要安装 Docker 存储库而不是默认的 Ubuntu 16.04 存储库：

```
 $ apt-cache policy docker-ce 
```

1.  您应该看到类似以下的输出：

```
 docker-ce:
          Installed: (none)
          Candidate: 17.06.0~ce-0~ubuntu
          Version table:
             17.06.0~ce-0~ubuntu 500
                500 https://download.docker.com/linux/ubuntu xenial/stable 
 amd64 Packages
             17.03.2~ce-0~ubuntu-xenial 500
                500 https://download.docker.com/linux/ubuntu xenial/stable 
 amd64 Packages
             17.03.1~ce-0~ubuntu-xenial 500
               500 https://download.docker.com/linux/ubuntu xenial/stable 
 amd64 Packages
             17.03.0~ce-0~ubuntu-xenial 500
              500 https://download.docker.com/linux/ubuntu xenial/stable 
 amd64 Packages
```

请注意，`docker-ce`未安装，但安装候选项来自 Ubuntu 16.04 的 Docker 存储库。`docker-ce`版本号可能不同。

1.  最后，安装 Docker：

```
 $ sudo apt-get install -y docker-ce 
```

1.  Docker 现在应该已安装，守护程序已启动，并且已启用进程以在启动时启动。检查它是否正在运行：

```
 $ sudo systemctl status docker
        docker.service - Docker Application Container Engine
           Loaded: loaded (/lib/systemd/system/docker.service; enabled; 
 vendor preset: enabled)
           Active: active (running) since Sun 2017-08-13 07:29:14 UTC; 45s
 ago
             Docs: https://docs.docker.com
         Main PID: 13080 (dockerd)
           CGroup: /system.slice/docker.service
                   ├─13080 /usr/bin/dockerd -H fd://
                   └─13085 docker-containerd -l 
 unix:///var/run/docker/libcontainerd/docker-containerd.sock --
 metrics-interval=0 --start
```

1.  通过运行 hello-world 镜像验证 Docker CE 是否正确安装：

```
 $ sudo docker run hello-world 
        Unable to find image 'hello-world:latest' locally 
        latest: Pulling from library/hello-world 
        b04784fba78d: Pull complete 
        Digest:
 sha256:f3b3b28a45160805bb16542c9531888519430e9e6d6ffc09d72261b0d26
 ff74f 
        Status: Downloaded newer image for hello-world:latest 

        Hello from Docker! 
 This message shows that your installation appears to be
 working correctly.
```

```
 To generate this message, Docker took the following steps:
 The Docker client contacted the Docker daemon
 The Docker daemon pulled the hello-world image from the Docker Hub
 The Docker daemon created a new container from that image, 
 which ran the executable that produced the output you are 
 currently reading 
 The Docker daemon streamed that output to the Docker client, 
 which sent it to your terminal
 To try something more ambitious, you can run an Ubuntu 
 container with the following:
 $ docker run -it ubuntu bash 
        Share images, automate workflows, and more with a free Docker ID: 
 https://cloud.docker.com/ 
 For more examples and ideas,
 visit: https://docs.docker.com/engine/userguide/.
```

# Docker 实践

本节将解释如何使用 Docker 在容器内运行任何应用程序。在上一节中解释的 Docker 安装也安装了 docker 命令行实用程序或 Docker 客户端。让我们探索`docker`命令。使用`docker`命令包括传递一系列选项和命令，后跟参数。

语法采用以下形式：

```
$ docker [option] [command] [arguments]
# To see help for individual command
$ docker help [command]  
```

要查看有关 Docker 和 Docker 版本的系统范围信息，请使用以下命令：

```
$ sudo docker info
$ sudo docker version  
```

Docker 有许多子命令来管理 Docker 守护程序管理的多个资源。以下是 Docker 支持的管理命令列表：

| **管理命令** | **描述** |
| --- | --- |
| `Config` | 管理 Docker 配置 |
| `container` | 管理容器 |
| `image` | 管理镜像 |
| `network` | 管理网络 |
| `Node` | 管理 Swarrn 节点 |
| `Plugin` | 管理插件 |
| `secret` | 管理 Docker 秘密 |
| `Service` | 管理服务 |
| `Stack` | 管理 Docker 堆栈 |
| `Swarm` | 管理群集 |
| `System` | 管理 Docker |
| `Volume` | 管理卷 |

在下一节中，我们将探索容器和镜像资源。

# 使用 Docker 镜像工作

镜像是一个轻量级的、独立的可执行包，包括运行软件所需的一切，包括代码、运行时、库、环境变量和配置文件。Docker 镜像用于创建 Docker 容器。镜像存储在 Docker Hub 中。

# 列出镜像

您可以通过运行 Docker images 子命令列出 Docker 主机中所有可用的镜像。默认的 Docker 镜像将显示所有顶级镜像，它们的存储库和标签，以及它们的大小：

```
$ sudo docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
wordpress           latest              c4260b289fc7        10 days ago         406MB
mysql               latest              c73c7527c03a        2 weeks ago         412MB
hello-world         latest              1815c82652c0        2 months ago        1.84kB 
```

# 获取新镜像

Docker 将自动下载在 Docker 主机系统中不存在的任何镜像。如果未提供标签，则`docker pull`子命令将始终下载该存储库中具有最新标签的镜像。如果提供了标签，它将拉取具有该标签的特定镜像。

要拉取基础镜像，请执行以下操作：

```
$ sudo docker pull Ubuntu 
# To pull specific version 
$ sudo docker pull ubuntu:16.04 
```

# 搜索 Docker 镜像

Docker 最重要的功能之一是许多人为各种目的创建了 Docker 镜像。其中许多已经上传到 Docker Hub。您可以通过使用 docker search 子命令在 Docker Hub 注册表中轻松搜索 Docker 镜像：

```
$ sudo docker search ubuntu
NAME                                           DESCRIPTION                                     STARS     OFFICIAL   AUTOMATED
rastasheep/ubuntu-sshd                         Dockerized SSH service, built on top of of...   97                   [OK]
ubuntu-upstart                                 Upstart is an event-based replacement for ...   76        [OK]
ubuntu-debootstrap                             debootstrap --variant=minbase --components...   30        [OK]
nuagebec/ubuntu                                Simple always updated Ubuntu docker images...   22                   [OK]
tutum/ubuntu                                   Simple Ubuntu docker images with SSH access     18  
```

# 删除镜像

要删除一个镜像，请运行以下命令：

```
$ sudo docker rmi hello-world
Untagged: hello-world:latest
Untagged: hello-world@sha256:b2ba691d8aac9e5ac3644c0788e3d3823f9e97f757f01d2ddc6eb5458df9d801
Deleted: sha256:05a3bd381fc2470695a35f230afefd7bf978b566253199c4ae5cc96fafa29b37
Deleted: sha256:3a36971a9f14df69f90891bf24dc2b9ed9c2d20959b624eab41bbf126272a023  
```

有关与 Docker 镜像相关的其余命令，请参考 Docker 文档。

# 使用 Docker 容器工作

容器是镜像的运行时实例。默认情况下，它完全与主机环境隔离，只有在配置为这样做时才能访问主机文件和端口。

# 创建容器

启动容器很简单，因为`docker run`传递了您想要运行的镜像名称以及在容器内运行此命令。如果镜像不存在于本地机器上，Docker 将尝试从公共镜像注册表中获取它：

```
$ sudo docker run --name hello_world ubuntu /bin/echo hello world  
```

在上面的例子中，容器将启动，打印 hello world，然后停止。容器被设计为在其中执行的命令退出后停止。

例如，让我们使用 Ubuntu 中的最新镜像运行一个容器。`-i`和`-t`开关的组合为您提供了对容器的交互式 shell 访问：

```
$ sudo docker run -it ubuntu
root@a5b3bce6ed1b:/# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root 
run  sbin  srv  sys  tmp  usr  var  
```

# 列出容器

您可以使用以下命令列出在 Docker 主机上运行的所有容器：

```
# To list active containers
$ sudo docker ps

# To list all containers
$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                      PORTS               NAMES
2db72a5a0b99        ubuntu              "/bin/echo hello w..." 
58 seconds ago      Exited (0) 58 seconds ago 
hello_world  
```

# 检查容器的日志

您还可以使用以下方法查看正在运行的容器记录的信息：

```
$ sudo docker logs hello_world
hello world  
```

# 启动容器

您可以使用以下方法启动已停止的容器：

```
$ sudo docker start hello_world  
```

同样，您可以使用诸如停止、暂停、取消暂停、重启、重新启动等命令来操作容器。

# 删除容器

您还可以使用以下方法删除已停止的容器：

```
$ sudo docker delete hello_world

# To delete a running container, use -force parameter
$ sudo docker delete --force [container]  
```

有关 Docker 容器的其他命令，请参考 Docker 文档。

# 摘要

在本章中，我们学习了容器及其类型。我们还了解了容器中的组件。我们看了不同的容器运行时工具。我们深入了解了 Docker，安装了它，并进行了实际操作练习。我们还学习了使用 Docker 管理容器和镜像的命令。在下一章中，我们将了解当今可用的不同 COE 工具。


# 第二章：与容器编排引擎合作

在本章中，我们将看一下容器编排引擎（COE）。容器编排引擎是帮助管理在多个主机上运行的许多容器的工具。

在本章中，我们将涵盖以下主题：

+   COE 简介

+   Docker Swarm

+   Apache Mesos

+   Kubernetes

+   Kubernetes 安装

+   Kubernetes 实践

# COE 简介

容器为用户提供了一种打包和运行其应用程序的简便方法。打包涉及定义用户应用程序运行所必需的库和工具。一旦转换为图像，这些软件包可以用于创建和运行容器。这些容器可以在任何地方运行，无论是在开发人员的笔记本电脑，QA 系统还是生产机器上，而不需要改变环境。Docker 和其他容器运行时工具提供了管理这些容器的生命周期的功能。

使用这些工具，用户可以构建和管理图像，运行容器，删除容器，并执行其他容器生命周期操作。但是这些工具只能在单个主机上管理一个容器。当我们在多个容器和多个主机上部署我们的应用程序时，我们需要某种自动化工具。这种自动化通常被称为编排。编排工具提供了许多功能，包括：

+   提供和管理容器将运行的主机

+   从存储库中拉取图像并实例化容器

+   管理容器的生命周期

+   根据主机资源的可用性在主机上调度容器

+   当一个容器死掉时启动一个新的容器

+   扩展容器以匹配应用程序的需求

+   在容器之间提供网络，以便它们可以在不同的主机上相互访问

+   将这些容器公开为服务，以便可以从外部访问

+   对容器进行健康监控

+   升级容器

通常，这些类型的编排工具提供 YAML 或 JSON 格式的声明性配置。这些定义携带与容器相关的所有信息，包括图像、网络、存储、扩展和其他内容。编排工具使用这些定义来应用相同的设置，以便每次都提供相同的环境。

有许多容器编排工具可用，例如 Docker Machine，Docker Compose，Kubernetes，Docker Swarm 和 Apache Mesos，但本章仅关注 Docker Swarm，Apache Mesos 和 Kubernetes。

# Docker Swarm

**Docker Swarm**是 Docker 自身的本地编排工具。它管理一组 Docker 主机并将它们转换为单个虚拟 Docker 主机。Docker Swarm 提供了标准的 Docker API 来管理集群上的容器。如果用户已经在使用 Docker 来管理他们的容器，那么他们很容易转移到 Docker Swarm。

Docker Swarm 遵循*swap，plug 和 play*原则。这为集群提供了可插拔的调度算法，广泛的注册表和发现后端支持。用户可以根据自己的需求使用各种调度算法和发现后端。以下图表示 Docker Swarm 架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00010.jpeg)

# Docker Swarm 组件

以下各节解释了 Docker Swarm 中的各种组件。

# 节点

节点是参与 Swarm 集群的 Docker 主机的实例。单个 Swarm 集群部署中可以有一个或多个节点。根据它们在系统中的角色，节点被分类为管理节点和工作节点。

# 管理节点

Swarm 管理节点管理集群中的节点。它提供 API 来管理集群中的节点和容器。管理节点将工作单元（也称为任务）分配给工作节点。如果有多个管理节点，那么它们会选择一个单一的领导者来执行编排任务。

# 工作节点

工作节点接收并执行由管理节点分发的任务。默认情况下，每个管理节点也是工作节点，但它们可以配置为仅运行管理任务。工作节点运行代理并跟踪正在运行的任务，并报告它们。工作节点还通知管理节点有关分配任务的当前状态。

# 任务

任务是具有在容器内运行的命令的单个 Docker 容器。管理节点分配任务给工作节点。任务是集群中调度的最小单位。

# 服务

服务是跨 Swarm 集群运行的一组 Docker 容器或任务的接口。

# 发现服务

发现服务存储集群状态，并提供节点和服务的可发现性。Swarm 支持可插拔的后端架构，支持 etcd、Consul、Zookeeper、静态文件、IP 列表等作为发现服务。

# 调度程序

Swarm 调度程序在系统中的不同节点上调度任务。Docker Swarm 带有许多内置的调度策略，使用户能够指导容器在节点上的放置，以最大化或最小化集群中的任务分布。Swarm 也支持随机策略。它选择一个随机节点来放置任务。

# Swarm 模式

在 1.12 版本中，Docker 引入了内置的 Swarm 模式。要运行一个集群，用户需要在每个 Docker 主机上执行两个命令：

进入 Swarm 模式：

```
$ docker swarm init
```

添加节点到集群：

```
$ docker swarm join  
```

与 Swarm 不同，Swarm 模式内置于 Docker 引擎本身，具有服务发现、负载平衡、安全性、滚动更新和扩展等功能。Swarm 模式使集群管理变得简单，因为它不需要任何编排工具来创建和管理集群。

# Apache Mesos

Apache Mesos 是一个开源的、容错的集群管理器。它管理一组称为从节点的节点，并向框架提供它们的可用计算资源。框架从主节点获取资源可用性，并在从节点上启动任务。Marathon 就是这样一个框架，它在 Mesos 集群上运行容器化应用程序。Mesos 和 Marathon 一起成为一个类似于 Swarm 或 Kubernetes 的容器编排引擎。

以下图表示了整个架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00011.jpeg)

# Apache Mesos 及其组件

以下是 Apache Mesos 组件的列表：

# 主节点

主节点管理系统中的从节点。系统中可能有许多主节点，但只有一个被选举为领导者。

# 从节点

从节点是提供其资源给主节点并运行框架提供的任务的节点。

# 框架

框架是长期运行的应用程序，由调度程序组成，这些调度程序从主节点接受资源提供并在从节点上执行任务。

# 提供

提供只是每个从节点的可用资源的集合。主节点从从节点获取这些提供，并将它们提供给框架，框架反过来在从节点上运行任务。

# 任务

任务是由框架调度在从节点上运行的最小工作单元。例如，一个容器化应用程序可以是一个任务

# Zookeeper

Zookeeper 是集群中的集中式配置管理器。Mesos 使用 Zookeeper 来选举主节点，并让从节点加入集群

此外，Mesos Marathon 框架为长时间运行的应用程序（如容器）提供了服务发现和负载均衡。Marathon 还提供了 REST API 来管理工作负载。

# Kubernetes

Kubernetes 是由谷歌创建的容器编排引擎，旨在自动化容器化应用程序的部署、扩展和运行。它是最快发展的 COE 之一，因为它提供了一个可靠的平台，可以在大规模上构建分布式应用程序。Kubernetes 自动化您的应用程序，管理其生命周期，并在服务器集群中维护和跟踪资源分配。它可以在物理或虚拟机集群上运行应用程序容器。

它提供了一个统一的 API 来部署 Web 应用程序、数据库和批处理作业。它包括一套丰富的复杂功能：

+   自动扩展

+   自愈基础设施

+   批处理作业的配置和更新

+   服务发现和负载均衡

+   应用程序生命周期管理

+   配额管理

# Kubernetes 架构

本节概述了 Kubernetes 架构和各种组件，以提供一个运行中的集群。

从顶层视图来看，Kubernetes 由以下组件组成：

+   外部请求

+   主节点

+   工作节点

以下图显示了 Kubernetes 的架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00012.jpeg)

我们将在下一节详细讨论每个组件。图中描述了一些关键组件。

# 外部请求

用户通过 API 与 Kubernetes 集群进行交互；他们解释他们的需求以及他们的应用程序的样子，Kubernetes 会为他们管理所有的工作。`kubectl`是 Kubernetes 项目中的命令行工具，可以简单地调用 Kubernetes API。

# 主节点

主节点提供了集群的控制平面。它在集群中充当控制器的角色。大部分主要功能，如调度、服务发现、负载均衡、响应集群事件等，都是由运行在主节点上的组件完成的。现在，让我们来看看主要组件及其功能。

# kube-apiserver

它公开了 Kubernetes 的 API。所有内部和外部请求都通过 API 服务器。它验证所有传入请求的真实性和正确的访问级别，然后将请求转发到集群中的目标组件。

# etcd

`etcd`用于存储 Kubernetes 的所有集群状态信息。`etcd`是 Kubernetes 中的关键组件。

# kube-controller-manager

Kubernetes 集群中有多个控制器，如节点控制器、复制控制器、端点控制器、服务账户和令牌控制器。这些控制器作为后台线程运行，处理集群中的常规任务。

# kube-scheduler

它监视所有新创建的 pod，并在它们未分配到任何节点时将它们调度到节点上运行。

请阅读 Kubernetes 文档（[`kubernetes.io/docs/concepts/overview/components/`](https://kubernetes.io/docs/concepts/overview/components/)）了解控制平面中的其他组件，包括：

+   Cloud-controller-manager

+   Web UI

+   容器资源监控

+   集群级别日志记录

# 工作节点

工作节点运行用户的应用程序和服务。集群中可以有一个或多个工作节点。您可以向集群添加或删除节点，以实现集群的可伸缩性。工作节点还运行多个组件来管理应用程序。

# kubelet

`kubelet`是每个工作节点上的主要代理。它监听`kube-apiserver`的命令执行。`kubelet`的一些功能包括挂载 pod 的卷、下载 pod 的秘密、通过 Docker 或指定的容器运行时运行 pod 的容器等。

# kube-proxy

它通过在主机上维护网络规则并执行连接转发，为 Kubernetes 提供了服务抽象。

# 容器运行时

使用 Docker 或 Rocket 创建容器。

# supervisord

`supervisord`是一个轻量级的进程监视和控制系统，可用于保持`kubelet`和 Docker 运行。

# fluentd

`fluentd`是一个守护程序，帮助提供集群级别的日志记录。

# Kubernetes 中的概念

在接下来的章节中，我们将学习 Kubernetes 的概念，这些概念用于表示您的集群。

# Pod

Pod 是 Kubernetes 中最小的可部署计算单元。Pod 是一个或多个具有共享存储或共享网络的容器组，以及如何运行这些容器的规范。容器本身不分配给主机，而密切相关的容器总是作为 Pod 一起共同定位和共同调度，并在共享上下文中运行。

Pod 模型是一个特定于应用程序的逻辑主机；它包含一个或多个应用程序容器，并且它们之间相对紧密地耦合。在没有容器的世界中，它们将在同一台物理或虚拟机上执行。使用 Pod，我们可以更好地共享资源、保证命运共享、进行进程间通信并简化管理。

# 副本集和复制控制器

副本集是复制控制器的下一代。两者之间唯一的区别是副本集支持更高级的基于集合的选择器，而复制控制器只支持基于相等性的选择器，因此副本集比复制控制器更灵活。然而，以下解释适用于两者。

Pod 是短暂的，如果它正在运行的节点宕机，它将不会被重新调度。副本集确保特定数量的 Pod 实例（或副本）在任何给定时间都在运行。

# 部署

部署是一个高级抽象，它创建副本集和 Pod。副本集维护运行状态中所需数量的 Pod。部署提供了一种简单的方式来通过改变部署规范来升级、回滚、扩展或缩减 Pod。

# Secrets

Secrets 用于存储敏感信息，如用户名、密码、OAuth 令牌、证书和 SSH 密钥。将这些敏感信息存储在 Secrets 中比将它们放在 Pod 模板中更安全、更灵活。Pod 可以引用这些 Secrets 并使用其中的信息。

# 标签和选择器

标签是可以附加到对象（如 Pod 甚至节点）的键值对。它们用于指定对象的标识属性，这些属性对用户来说是有意义和相关的。标签可以在创建对象时附加，也可以在以后添加或修改。它们用于组织和选择对象的子集。一些示例包括环境（开发、测试、生产、发布）、稳定、派克等。

标签不提供唯一性。使用标签选择器，客户端或用户可以识别并随后管理一组对象。这是 Kubernetes 的核心分组原语，在许多情况下使用。

Kubernetes 支持两种选择器：基于相等性和基于集合。基于相等性使用键值对进行过滤，而基于集合更强大，允许根据一组值对键进行过滤。

# 服务

由于 pod 在 Kubernetes 中是短暂的对象，分配给它们的 IP 地址不能长时间稳定。这使得 pod 之间的通信变得困难。因此，Kubernetes 引入了服务的概念。服务是对一些 pod 的抽象，以及访问它们的策略，通常需要运行代理来通过虚拟 IP 地址与其他服务进行通信。

# 卷

卷为 pod 或容器提供持久存储。如果数据没有持久存储在外部存储上，那么一旦容器崩溃，所有文件都将丢失。卷还可以使多个容器之间的数据共享变得容易。Kubernetes 支持许多类型的卷，pod 可以同时使用任意数量的卷。

# Kubernetes 安装

Kubernetes 可以在各种平台上运行，从笔记本电脑和云提供商的虚拟机到一排裸机服务器。今天有多种解决方案可以安装和运行 Kubernetes 集群。阅读 Kubernetes 文档，找到适合您特定用例的最佳解决方案。

在本章中，我们将使用`kubeadm`在 Ubuntu 16.04+上创建一个 Kubernetes 集群。`kubeadm`可以用一个命令轻松地在每台机器上创建一个集群。

在这个安装中，我们将使用一个名为`kubeadm`的工具，它是 Kubernetes 的一部分。安装`kubeadm`的先决条件是：

+   一台或多台运行 Ubuntu 16.04+的机器

+   每台机器至少需要 1GB 或更多的 RAM

+   集群中所有机器之间的完整网络连接

集群中的所有机器都需要安装以下组件：

1.  在所有机器上安装 Docker。根据 Kubernetes 文档，建议使用 1.12 版本。有关安装 Docker 的说明，请参阅第一章中的*安装 Docker*部分，*使用容器*。

1.  在每台机器上安装`kubectl`。`kubectl`是来自 Kubernetes 的命令行工具，用于在 Kubernetes 上部署和管理应用程序。您可以使用`kubectl`来检查集群资源，创建、删除和更新组件，并查看您的新集群并启动示例应用程序。再次强调，安装`kubectl`有多种选项。在本章中，我们将使用 curl 进行安装。请参考 Kubernetes 文档以获取更多选项。

1.  使用 curl 下载最新版本的`kubectl`：

```
        $ curl -LO https://storage.googleapis.com/kubernetes-
        release/release/$(curl -s https://storage.googleapis.com/kubernetes
        release/release/stable.txt)/bin/linux/amd64/kubectl
```

1.  使`kubectl`二进制文件可执行：

```
        $ chmod +x ./kubectl  
```

1.  现在，在所有机器上安装`kubelet`和`kubeadm`。`kubelet`是在集群中所有机器上运行的组件，负责启动 pod 和容器等工作。`kubeadm`是引导集群的命令：

1.  以 root 用户登录：

```
        $ sudo -i  
```

1.  更新并安装软件包：

```
        $ apt-get update && apt-get install -y apt-transport-https
```

1.  为软件包添加认证密钥：

```
        $ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg 
        | apt-key add -  
```

1.  将 Kubernetes 源添加到`apt`列表中：

```
        $ cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
        deb http://apt.kubernetes.io/ kubernetes-xenial main
        EOF  
```

1.  更新并安装工具：

```
        $ apt-get update
        $ apt-get install -y kubelet kubeadm  
```

以下步骤演示了如何使用`kubeadm`设置安全的 Kubernetes 集群。我们还将在集群上创建一个 pod 网络，以便应用程序组件可以相互通信。最后，在集群上安装一个示例微服务应用程序以验证安装。

1.  初始化主节点。要初始化主节点，请选择之前安装了`kubeadm`的机器之一，并运行以下命令。我们已指定`pod-network-cidr`以提供用于通信的网络：

```
          $ kubeadm init --pod-network-cidr=10.244.0.0/16  
```

请参考`kubeadm`参考文档，了解更多关于`kubeadm init`提供的标志。

这可能需要几分钟，因为`kubeadm init`将首先运行一系列预检查，以确保机器准备好运行 Kubernetes。它可能会暴露警告并根据预检查结果退出错误。然后，它将下载并安装控制平面组件和集群数据库。

前面命令的输出如下：

```
[kubeadm] WARNING: kubeadm is in beta, please do not use it for production clusters.
[init] Using Kubernetes version: v1.7.4
[init] Using Authorization modes: [Node RBAC]
[preflight] Running pre-flight checks
[preflight] WARNING: docker version is greater than the most recently validated version. Docker version: 17.06.1-ce. Max validated version: 1.12
[preflight] Starting the kubelet service
[kubeadm] WARNING: starting in 1.8, tokens expire after 24 hours by default (if you require a non-expiring token use --token-ttl 0)
[certificates] Generated CA certificate and key.
[certificates] Generated API server certificate and key.
[certificates] API Server serving cert is signed for DNS names [galvin kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local] and IPs [10.96.0.1 10.0.2.15]
[certificates] Generated API server kubelet client certificate and key.
[certificates] Generated service account token signing key and public key.
[certificates] Generated front-proxy CA certificate and key.
[certificates] Generated front-proxy client certificate and key.
[certificates] Valid certificates and keys now exist in "/etc/kubernetes/pki"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/admin.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/kubelet.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/controller-manager.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/scheduler.conf"
[apiclient] Created API client, waiting for the control plane to become ready
[apiclient] All control plane components are healthy after 62.001439 seconds
[token] Using token: 07fb67.033bd701ad81236a
[apiconfig] Created RBAC rules
[addons] Applied essential addon: kube-proxy
[addons] Applied essential addon: kube-dns  
Your Kubernetes master has initialized successfully:
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config 
You should now deploy a pod network to the cluster.
Run kubectl apply -f [podnetwork].yaml with one of the options listed at: http://kubernetes.io/docs/admin/addons/. You can now join any number of machines by running the following on each node as the root:
kubeadm join --token 07fb67.033bd701ad81236a 10.0.2.15:6443 
```

保存前面输出的`kubeadm join`命令。您将需要这个命令来将节点加入到您的 Kubernetes 集群中。令牌用于主节点和节点之间的相互认证。

现在，要开始使用您的集群，请以普通用户身份运行以下命令：

```
$ mkdir -p $HOME/.kube
$ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
$ sudo chown $(id -u):$(id -g) $HOME/.kube/config  
```

1.  安装 pod 网络。此网络用于集群中 pod 之间的通信：

在运行任何应用程序之前，必须部署网络。此外，诸如`kube-dns`之类的服务在安装网络之前不会启动。`kubeadm`仅支持**容器网络接口**（**CNI**）网络，不支持`kubenet`。

有多个网络附加项目可用于创建安全网络。要查看完整列表，请访问 Kubernetes 文档以供参考。在本例中，我们将使用 flannel 进行网络连接。Flannel 是一种覆盖网络提供程序：

```
 $ sudo kubectl apply -f 
https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
 serviceaccount "flannel" created
 configmap "kube-flannel-cfg" created
 daemonset "kube-flannel-ds" created
 $ sudo kubectl apply -f 
https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel-rbac.yml
 clusterrole "flannel" created
 clusterrolebinding "flannel" created  
```

您可以通过检查输出中的`kube-dns` pod 是否正在运行来确认它是否正在工作：

```
$ kubectl get pods --all-namespaces
NAMESPACE     NAME                             READY     STATUS    RESTARTS   AGE
kube-system   etcd-galvin                      1/1       Running   0          2m
kube-system   kube-apiserver-galvin            1/1       Running   0          2m
kube-system   kube-controller-manager-galvin   1/1       Running   0          2m
kube-system   kube-dns-2425271678-lz9fp        3/3       Running   0          2m
kube-system   kube-flannel-ds-f9nx8            2/2       Running   2          1m
kube-system   kube-proxy-wcmdg                 1/1       Running   0          2m
kube-system   kube-scheduler-galvin            1/1       Running   0          2m  
```

1.  将节点加入集群。要将节点添加到 Kubernetes 集群，请通过 SSH 连接到节点并运行以下命令：

```
$ sudo kubeadm join --token <token> <master-ip>:<port>
[kubeadm] WARNING: kubeadm is in beta, please do not use it for production clusters.
[preflight] Running pre-flight checks
[discovery] Trying to connect to API Server "10.0.2.15:6443"
[discovery] Created cluster-info discovery client, requesting info from "https://10.0.2.15:6443"
[discovery] Cluster info signature and contents are valid, will use API Server "https://10.0.2.15:6443"
[discovery] Successfully established connection with API Server "10.0.2.15:6443"
[bootstrap] Detected server version: v1.7.4
[bootstrap] The server supports the Certificates API (certificates.k8s.io/v1beta1)
[csr] Created API client to obtain unique certificate for this node, generating keys and certificate signing request
[csr] Received signed certificate from the API server, generating KubeConfig...
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/kubelet.conf"  
Node join complete:
Certificate signing request sent to master and response
Received
Kubelet informed of new secure connection details
Run kubectl get nodes on the master to see this machine join.
```

现在，运行以下命令来验证节点的加入：

```
$ kubectl get nodes
NAME      STATUS    AGE       VERSION
brunno    Ready     14m       v1.7.4
```

通过创建一个示例 Nginx pod 来验证您的安装：

```
$ kubectl run my-nginx --image=nginx --replicas=2 --port=80
deployment "my-nginx" created

$ kubectl get pods 
NAME                        READY     STATUS    RESTARTS   AGE
my-nginx-4293833666-c4c5p   1/1       Running   0          22s
my-nginx-4293833666-czrnf   1/1       Running   0          22s  
```

# Kubernetes 实践

我们在上一节中学习了如何安装 Kubernetes 集群。现在，让我们使用 Kubernetes 创建一个更复杂的示例。在这个应用程序中，我们将部署一个运行 WordPress 站点和 MySQL 数据库的应用程序，使用官方 Docker 镜像。

1.  创建持久卷。WordPress 和 MySQL 将使用此卷来存储数据。我们将创建两个大小为 5 GB 的本地持久卷。将以下内容复制到`volumes.yaml`文件中：

```
        apiVersion: v1
        kind: PersistentVolume
        metadata:
          name: pv-1
          labels:
            type: local
        spec:
          capacity:
            storage: 5Gi
          accessModes:
            - ReadWriteOnce
          hostPath:
            path: /tmp/data/pv-1
         storageClassName: slow 
        ---
        apiVersion: v1
        kind: PersistentVolume
        metadata:
          name: pv-2
          labels:
            type: local
        spec:
          capacity:
            storage: 5Gi
          accessModes:
            - ReadWriteOnce
          hostPath:
            path: /tmp/data/pv-2
        storageClassName: slow 

```

1.  现在，通过运行以下命令来创建卷：

```
 $ kubectl create -f volumes.yaml 
 persistentvolume "pv-1" created
 persistentvolume "pv-2" created    
```

1.  检查卷是否已创建：

```
          $ kubectl get pv
          NAME      CAPACITY   ACCESSMODES   RECLAIMPOLICY   STATUS      
          CLAIM     STORAGECLASS   REASON    AGE
          pv-1      5Gi        RWO           Retain          Available                                     
          8s
          pv-2      5Gi        RWO           Retain          Available                                    
          8s  
```

1.  创建一个用于存储 MySQL 密码的密钥。MySQL 和 WordPress pod 将引用此密钥，以便这些 pod 可以访问它：

```
        $ kubectl create secret generic mysql-pass -from-
        literal=password=admin
        secret "mysql-pass" created
```

1.  验证密钥是否已创建：

```
        $ kubectl get secrets
        NAME                  TYPE                                  DATA    
        AGE
        default-token-1tb58   kubernetes.io/service-account-token   3      
        3m
        mysql-pass            Opaque                                1   
        9s
```

1.  创建 MySQL 部署。现在，我们将创建一个服务，公开一个 MySQL 容器，一个 5 GB 的持久卷索赔，以及运行 MySQL 容器的 pod 的部署。将以下内容复制到`mysql-deployment.yaml`文件中：

```
        apiVersion: v1
        kind: Service
        metadata:
          name: wordpress-mysql
          labels:
            app: wordpress
        spec:
          ports:
            - port: 3306
          selector:
            app: wordpress
            tier: mysql
          clusterIP: None
        ---
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: mysql-pv-claim
          labels:
            app: wordpress
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 5Gi
        storageClassName: slow 

        ---
        apiVersion: extensions/v1beta1
        kind: Deployment
        metadata:
          name: wordpress-mysql
          labels:
            app: wordpress
        spec:
          strategy:
            type: Recreate
          template:
            metadata:
              labels:
                app: wordpress
                tier: mysql
            spec:
              containers:
              - image: mysql:5.6
                name: mysql
                env:
                - name: MYSQL_ROOT_PASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: mysql-pass
                      key: password
                    ports:
                - containerPort: 3306
                  name: mysql
                volumeMounts:
                - name: mysql-persistent-storage
                  mountPath: /var/lib/mysql
              volumes:
              - name: mysql-persistent-storage
                persistentVolumeClaim:
                   claimName: mysql-pv-claim  
```

1.  现在，启动 MySQL pod：

```
        $ kubectl create -f mysql-deployment.yaml 
          service "wordpress-mysql" created
          persistentvolumeclaim "mysql-pv-claim" created
          deployment "wordpress-mysql" created  
```

1.  检查 pod 的状态：

```
          $ kubectl get pods
          NAME                               READY     STATUS    RESTARTS
          AGE
            wordpress-mysql-2222028001-l8x9x   1/1       Running   0  
          6m      
```

1.  或者，您可以通过运行以下命令来检查 pod 的日志：

```
        $ kubectl logs wordpress-mysql-2222028001-l8x9x

        Initializing database
        2017-08-27 15:30:00 0 [Warning] TIMESTAMP with implicit DEFAULT 
        value is deprecated. Please use --explicit_defaults_for_timestamp 
        server 
        option (see documentation for more details).
        2017-08-27 15:30:00 0 [Note] Ignoring --secure-file-priv value as
        server is running with --bootstrap.
        2017-08-27 15:30:00 0 [Note] /usr/sbin/mysqld (mysqld 5.6.37)
        starting as process 36 ...

        2017-08-27 15:30:03 0 [Warning] TIMESTAMP with implicit DEFAULT
        value is deprecated. Please use --explicit_defaults_for_timestamp 
        server 
        option (see documentation for more details).
        2017-08-27 15:30:03 0 [Note] Ignoring --secure-file-priv value as 
        server is running with --bootstrap.
        2017-08-27 15:30:03 0 [Note] /usr/sbin/mysqld (mysqld 5.6.37)
        starting as process 59 ...
        Please remember to set a password for the MySQL root user!
 To do so, start the server, then issue the following 
 commands:
 /usr/bin/mysqladmin -u root password 'new-password' 
        /usr/bin/mysqladmin -u root -h wordpress-mysql-2917821887-dccql 
        password 'new-password' 
```

或者，您可以运行以下命令：

```
/usr/bin/mysql_secure_installation 
```

这还将为您提供删除默认创建的测试数据库和匿名用户的选项。强烈建议用于生产服务器。

查看手册以获取更多说明：

请在[`bugs.mysql.com/`](http://bugs.mysql.com/)报告任何问题。有关 MySQL 的最新信息可在网上获取：[`www.mysql.com`](http://www.mysql.com)。通过在[`shop.mysql.com`](http://shop.mysql.com)购买支持/许可证来支持 MySQL。

请注意，没有创建新的默认`config`文件；请确保您的`config`文件是最新的。

默认的`config`文件`/etc/mysql/my.cnf`存在于系统上。

此文件将被 MySQL 服务器默认读取。如果您不想使用它，要么删除它，要么使用以下命令：

```
--defaults-file argument to mysqld_safe when starting the server

Database initialized
MySQL init process in progress...
2017-08-27 15:30:05 0 [Warning] TIMESTAMP with implicit DEFAULT 
value is deprecated. Please use --explicit_defaults_for_timestamp 
server option (see documentation for more details).
2017-08-27 15:30:05 0 [Note] mysqld (mysqld 5.6.37) starting as 
process 87 ...
Warning: Unable to load '/usr/share/zoneinfo/iso3166.tab' as time 
zone. Skipping it.
Warning: Unable to load '/usr/share/zoneinfo/leap-seconds.list' as
time zone. Skipping it.
Warning: Unable to load '/usr/share/zoneinfo/zone.tab' as time
zone. Skipping it.  
```

MySQL 的`init`过程现在已经完成。我们已经准备好启动：

```
2017-08-27 15:30:11 0 [Warning] TIMESTAMP with implicit DEFAULT 
value is deprecated. Please use --explicit_defaults_for_timestamp
server 
option (see documentation for more details).
2017-08-27 15:30:11 0 [Note] mysqld (mysqld 5.6.37) starting as
process 5 ...  
```

通过运行以下命令检查持久卷索赔的状态：

```
$ kubectl get pvc
NAME             STATUS    VOLUME    CAPACITY   ACCESSMODES   
STORAGECLASS   AGE
mysql-pv-claim   Bound     pv-1      5Gi        RWO         
slow           2h
wp-pv-claim      Bound     pv-2      5Gi        RWO         
slow           2h
```

创建 WordPress 部署。我们现在将创建一个服务，公开一个 WordPress 容器，一个持久卷索赔 5GB，以及运行 WordPress 容器的 pod 的部署。将以下内容复制到`wordpress-deployment.yaml`文件中：

```
apiVersion: v1 
kind: Service 
metadata: 
  name: wordpress 
  labels: 
    app: wordpress 
spec: 
  ports: 
    - port: 80 
  selector: 
    app: wordpress 
    tier: frontend 
  type: NodePort 
--- 
apiVersion: v1 
kind: PersistentVolumeClaim 
metadata: 
  name: wp-pv-claim 
  labels: 
    app: wordpress 
spec: 
  accessModes: 
    - ReadWriteOnce 
  resources: 
    requests: 
      storage: 5Gi 
  storageClassName: slow  

--- 
apiVersion: extensions/v1beta1 
kind: Deployment 
metadata: 
  name: wordpress 
  labels: 
    app: wordpress 
spec: 
  strategy: 
    type: Recreate 
  template: 
    metadata: 
      labels: 
        app: wordpress 
        tier: frontend 
    spec: 
      containers: 
      - image: wordpress:4.7.3-apache 
        name: wordpress 
        env: 
        - name: WORDPRESS_DB_HOST 
          value: wordpress-mysql 
        - name: WORDPRESS_DB_PASSWORD 
          valueFrom: 
            secretKeyRef: 
              name: mysql-pass 
              key: password 
        ports: 
        - containerPort: 80 
          name: wordpress 
        volumeMounts: 
        - name: wordpress-persistent-storage 
          mountPath: /var/www/html 
      volumes: 
      - name: wordpress-persistent-storage 
        persistentVolumeClaim: 
          claimName: wp-pv-claim 
```

1.  现在，启动 WordPress pod：

```
    $ kubectl create -f wordpress-deployment.yaml 
      service "wordpress" created
      persistentvolumeclaim "wp-pv-claim" created
      deployment "wordpress" created

```

1.  检查服务的状态：

```
        $ kubectl get services wordpress
        NAME        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
        wordpress   10.99.124.161   <nodes>      80:31079/TCP   4m
```

应用程序现在正在运行！

以下列出了删除所有创建的资源所需的命令：

+   要删除您的秘密：

```
        $ kubectl delete secret mysql-pass  
```

+   要删除所有部署和服务：

```
        $ kubectl delete deployment -l app=wordpress
        $ kubectl delete service -l app=wordpress
```

+   要删除持久卷索赔和持久卷：

```
        $ kubectl delete pvc -l app=wordpress
        $ kubectl delete pv pv-1 pv-2  
```

# 摘要

在本章中，我们学习了容器编排引擎。我们看了不同的 COE，如 Docker Swarm 和 Apache Mesos。我们详细介绍了 Kubernetes 及其架构、组件和概念。

我们学会了如何使用`kubeadm`工具安装 Kubernetes 集群。然后，在最后，我们进行了一个实际操作，将 MySQL WordPress 应用程序在 Kubernetes 集群上运行。在下一章中，我们将了解 OpenStack 架构及其核心组件。


# 第三章：OpenStack 架构

本章将从介绍 OpenStack 开始。然后本章将解释 OpenStack 的架构，并进一步解释 OpenStack 中的每个核心项目。最后，本章将演示 DevStack 安装并使用它来执行一些 OpenStack 操作。本章将涵盖以下内容：

+   OpenStack 介绍

+   OpenStack 架构

+   KeyStone 介绍，OpenStack 身份服务

+   Nova 介绍，OpenStack 计算服务

+   Neutron 介绍，OpenStack 网络服务

+   Cinder 介绍，OpenStack 块存储服务

+   Glance 介绍，OpenStack 镜像服务

+   Swift 介绍，OpenStack 对象服务

+   DevStack 安装

# OpenStack 介绍

OpenStack 是一个用于创建私有和公共云的免费开源软件。它提供一系列相关的组件来管理和访问跨数据中心的大型计算、网络和存储资源池。用户可以使用基于 Web 的用户界面和命令行或 REST API 来管理它。OpenStack 于 2010 年由 Rackspace 和 NASA 开源。目前，它由非营利实体 OpenStack Foundation 管理。

# OpenStack 架构

以下图（来自：[`docs.openstack.org/arch-design/design.html`](https://docs.openstack.org/arch-design/design.html)）代表了 OpenStack 的逻辑架构以及用户如何连接到各种服务。OpenStack 有多个组件用于不同的目的，比如用于管理计算资源的 Nova，用于管理操作系统镜像的 Glance 等等。我们将在接下来的章节中详细了解每个组件。

简单来说，如果用户请求使用 CLI 或 API 来提供 VM，请求将由 Nova 处理。Nova 然后与 KeyStone 进行通信以验证请求，与 Glance 进行 OS 镜像通信，并与 Neutron 进行网络资源设置。然后，在从每个组件接收到响应后，启动 VM 并向用户返回响应：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00013.jpeg)

# KeyStone 介绍，OpenStack 身份服务

KeyStone 是一个 OpenStack 身份服务，提供以下功能：

+   **身份提供者**：在 OpenStack 中，身份以用户名和密码的形式表示为用户。在简单的设置中，KeyStone 将用户的身份存储在其数据库中。但建议在生产中使用 LDAP 等第三方身份提供者。

+   **API 客户端身份验证**：身份验证是验证用户身份的过程。KeyStone 可以通过使用诸如 LDAP 和 AD 等许多第三方后端来进行身份验证。一旦经过身份验证，用户将获得一个令牌，可以用来访问其他 OpenStack 服务的 API。

+   **多租户授权**：KeyStone 通过为每个租户的每个用户添加角色来提供访问特定资源的授权。当用户访问任何 OpenStack 服务时，服务会验证用户的角色以及他/她是否可以访问资源。

+   **服务发现**：KeyStone 管理一个服务目录，其他服务可以在其中注册它们的端点。每当其他服务想要与任何特定服务进行交互时，它可以参考服务目录并获取该服务的地址。

KeyStone 包含以下组件：

+   **KeyStone API**：KeyStone API 是一个 WSGI 应用程序，用于处理所有传入请求

+   **服务**：KeyStone 由许多通过 API 端点公开的内部服务组成。这些服务以一种组合的方式被前端 API 所使用

+   **身份**：身份服务处理与用户凭据验证和与用户和组数据相关的 CRUD 操作的请求。在生产环境中，可以使用诸如 LDAP 之类的第三方实体作为身份服务后端

+   **资源**：资源服务负责管理与项目和域相关的数据

+   **分配**：分配服务负责角色和将角色分配给用户

+   **令牌**：令牌服务负责管理和验证令牌

+   **目录**：目录服务负责管理服务端点并提供发现服务

+   **策略**：策略服务负责提供基于规则的授权

以下图表示了 KeyStone 的架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00014.jpeg)

# 介绍 Nova，OpenStack 计算服务

Nova 是 OpenStack 的计算服务，提供了一种创建和管理计算实例（也称为虚拟机）的方式。Nova 具有创建和管理以下功能：

+   虚拟机

+   裸金属服务器

+   系统容器

Nova 包含多个服务，每个服务执行不同的功能。它们通过 RPC 消息传递机制进行内部通信。

Nova 包含以下组件：

+   Nova API：Nova API 服务处理传入的 REST 请求，以创建和管理虚拟服务器。API 服务主要处理数据库读写，并通过 RPC 与其他服务通信，生成对 REST 请求的响应。

+   放置 API：Nova 放置 API 服务在 14.0.0 牛顿版本中引入。该服务跟踪每个提供程序的资源提供程序库存和使用情况。资源提供程序可以是共享存储池、计算节点等。

+   调度程序：调度程序服务决定哪个计算主机获得实例。

+   计算：计算服务负责与 hypervisors 和虚拟机通信。它在每个计算节点上运行。

+   主管：主管服务充当数据库代理，处理对象转换并协助请求协调。

+   数据库：数据库是用于数据存储的 SQL 数据库。

+   消息队列：此路由的信息在不同的 Nova 服务之间移动。

+   网络：网络服务管理 IP 转发、桥接、VLAN 等。

以下图表示了 Nova 的架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00015.jpeg)

# 介绍 Neutron，OpenStack 网络服务

Neutron 是 OpenStack 的网络服务，为 OpenStack 云提供各种网络选项。它的旧名称是 Quantum，后来更名为 Neutron。Neutron 使用各种插件提供不同的网络配置。

Neutron 包含以下组件：

+   Neutron 服务器（`neutron-server`和`neutron-*-plugin`）：Neutron 服务器处理传入的 REST API 请求。它使用插件与数据库通信

+   插件代理（`neutron-*-agent`）：插件代理在每个计算节点上运行，以管理本地虚拟交换机（vswitch）配置

+   DHCP 代理（`neutron-dhcp-agent`）：DHCP 代理为租户网络提供 DHCP 服务。此代理负责维护所有 DHCP 配置

+   L3 代理（`neutron-l3-agent`）：L3 代理为租户网络上 VM 的外部网络访问提供 L3/NAT 转发

+   网络提供商服务（SDN 服务器/服务）：此服务为租户网络提供额外的网络服务

+   消息队列：在 Neutron 进程之间路由信息

+   数据库：数据库是用于数据存储的 SQL 数据库

以下图表示了 Neutron 的架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00016.jpeg)

# Cinder 是 OpenStack 的块存储服务

Cinder 是 OpenStack 的块存储服务，为 Nova 中的虚拟机提供持久的块存储资源。Cinder 使用 LVM 或其他插件驱动程序来提供存储。用户可以使用 Cinder 来创建、删除和附加卷。此外，还可以使用更高级的功能，如克隆、扩展卷、快照和写入图像，作为虚拟机和裸金属的可引导持久实例。Cinder 也可以独立于其他 OpenStack 服务使用。

块存储服务由以下组件组成，并为管理卷提供高可用性、容错性和可恢复性的解决方案：

+   **cinder-api**：一个 WSGI 应用程序，用于验证和路由请求到 cinder-volume 服务

+   **cinder-scheduler**：调度对最佳存储提供程序节点的请求，以创建卷

+   **cinder-volume**：与各种存储提供程序进行交互，并处理读写请求以维护状态。它还与 cinder-scheduler 进行交互。

+   **cinder-backup**：将卷备份到 OpenStack 对象存储（Swift）。它还与各种存储提供程序进行交互

消息队列在块存储过程之间路由信息。以下图是 Cinder 的架构图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00017.jpeg)

# Glance 是 OpenStack 的图像服务

Glance 是 OpenStack 的图像服务项目，为磁盘和服务器图像的发现、注册和检索提供能力。用户可以上传和发现数据图像和元数据定义，这些定义旨在与其他服务一起使用。简而言之，Glance 是用于管理虚拟机、容器和裸金属图像的中央存储库。Glance 具有 RESTful API，允许查询图像元数据以及检索实际图像。

OpenStack 镜像服务 Glance 包括以下组件：

+   **glance-api**：一个 WSGI 应用程序，用于接受图像 API 调用以进行图像发现、检索和存储。它使用 Keystone 进行身份验证，并将请求转发到 glance-registry。

+   **glance-registry**：一个私有的内部服务，用于存储、处理和检索有关图像的元数据。元数据包括大小和类型等项目。

+   **数据库**：它存储图像元数据。您可以根据自己的喜好选择 MySQL 或 SQLite。

+   **图像文件的存储库**：支持各种存储库类型来存储图像。

+   **元数据定义服务**: 为供应商、管理员、服务和用户提供一个通用 API，以有意义地定义自己的自定义元数据。这些元数据可以用于不同类型的资源，如图像、工件、卷、口味和聚合。定义包括新属性的键、描述、约束以及它可以关联的资源类型。

以下图是 Glance 的架构图。Glance 还具有客户端-服务器架构，为用户提供 REST API，通过该 API 可以对服务器执行请求：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00018.jpeg)

# Swift 介绍，OpenStack 对象存储

Swift 是 OpenStack 的对象存储服务，可用于在能够存储 PB 级数据的服务器集群上存储冗余、可扩展的数据。它提供了一个完全分布式的、可通过 API 访问的存储平台，可以直接集成到应用程序中，也可用于备份、归档和数据保留。Swift 使用分布式架构，没有中央控制点，这使得它具有高可用性、分布式性和最终一致的对象存储解决方案。它非常适合存储可以无限增长并且可以检索和更新的非结构化数据。

数据被写入多个节点，扩展到不同区域，以确保数据在集群中的复制和完整性。集群可以通过添加新节点进行水平扩展。在节点故障的情况下，数据会被复制到其他活动节点。

Swift 以层次结构组织数据。它记录容器的存储列表，容器用于存储对象列表，对象用于存储带有元数据的实际数据。

Swift 具有以下主要组件，以实现高可用性、高耐久性和高并发性。Swift 还有许多其他服务，如更新程序、审计程序和复制程序，用于处理日常任务，以提供一致的对象存储解决方案：

+   **代理服务器**: 公共 API 通过代理服务器公开。它处理所有传入的 API 请求，并将请求路由到适当的服务。

+   **环**: 环将数据的逻辑名称映射到特定磁盘上的位置。Swift 中针对不同资源有不同的环。

+   **区域**: 区域将数据与其他区域隔离开来。如果一个区域发生故障，集群不会受到影响，因为数据在区域之间复制。

+   **账户**：账户是存储账户中容器列表的数据库。它分布在集群中。

+   **容器**：容器是存储容器中对象列表的数据库。它分布在集群中。

+   **对象**：数据本身。

+   **分区**：它存储对象、账户数据库和容器数据库，并帮助管理数据在集群中的位置。

以下图显示了 Swift 的架构图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ctn-opstk/img/00019.jpeg)

# DevStack 安装

DevStack 是一组可扩展的脚本，用于快速搭建完整的开发 OpenStack 环境。DevStack 仅用于开发和测试目的。请注意，它不应该在生产环境中使用。DevStack 默认安装所有核心组件，包括 Nova、Neutron、Cinder、Glance、Keystone 和 Horizon。

Devstack 可以在 Ubuntu 16.04/17.04、Fedora 24/25 和 CentOS/RHEL 7 以及 Debian 和 OpenSUSE 上运行。

在本节中，我们将在 Ubuntu 16.04 上设置一个基本的 OpenStack 环境，并尝试一些命令来测试 OpenStack 中的各个组件。

1.  使用以下方法添加一个 stack 用户。您应该以启用了`sudo`的非 root 用户身份运行 DevStack：

```
        $ sudo useradd -s /bin/bash -d /opt/stack -m stack   
```

1.  现在为用户添加`sudo`权限。

```
        $ echo "stack ALL=(ALL) NOPASSWD: ALL" | sudo tee 
        /etc/sudoers.d/stack
        $ sudo su - stack    
```

1.  下载 DevStack。DevStack 默认安装来自 Git 的项目的主版本。您也可以指定使用稳定的分支：

```
        $ git clone https://git.openstack.org/openstack-dev/devstack 
        /opt/stack/devstack
        $ cd /opt/stack/devstack  
```

1.  创建`local.conf`文件。这是 DevStack 用于安装的`config`文件。以下是 DevStack 启动所需的最小配置（请参考[`docs.openstack.org/devstack/latest/`](https://docs.openstack.org/devstack/latest/)获取更多配置信息）：

```
        $ cat > local.conf << END
        [[local|localrc]]
        DATABASE_PASSWORD=password
        RABBIT_PASSWORD=password
        SERVICE_TOKEN=password
        SERVICE_PASSWORD=password
        ADMIN_PASSWORD=password 
 enable_service s-proxy
 enable_service s-object
 enable_service s-container
 enable_service s-account 
 END 
```

1.  开始安装。这可能需要大约 15 到 20 分钟，具体取决于您的互联网连接和主机容量：

```
          $ ./stack.sh  
```

您将看到类似以下的输出：

```
=========================
DevStack Component Timing
=========================
Total runtime    3033

run_process       24
test_with_retry    3
apt-get-update    19
pip_install      709
osc              269
wait_for_service  25
git_timed        730
dbsync            20
apt-get          625
=========================

This is your host IP address: 10.0.2.15
This is your host IPv6 address: ::1
Horizon is now available at http://10.0.2.15/dashboard
Keystone is serving at http://10.0.2.15/identity/
The default users are: admin and demo
The password: password

WARNING:
Using lib/neutron-legacy is deprecated, and it will be removed in the future
With the removal of screen support, tail_log is deprecated and will be removed after Queens

Services are running under systemd unit files.
For more information see:
https://docs.openstack.org/devstack/latest/systemd.html

DevStack Version: pike
Change: 0f75c57ad6b0011561777ae95b53612051149518 Merge "doc: How to remote-pdb under systemd" 2017-09-08 02:24:21 +0000
OS Version: Ubuntu 16.04 xenial

2017-09-09 08:00:09.397 | stack.sh completed in 3033 seconds.  
```

您可以访问 Horizon 来体验 OpenStack 的 Web 界面，或者您可以在 shell 中使用`openrc`，然后使用 OpenStack 命令行工具来管理虚拟机、网络、卷和镜像。以下是您的操作步骤：

```
$ source openrc admin admin  
```

# 创建 KeyStone 用户

现在让我们创建一个用户，然后为其分配管理员角色。这些操作将由 KeyStone 处理：

```
$ openstack domain list 
+---------+---------+---------+--------------------+ 
| ID      | Name    | Enabled | Description        | 
+---------+---------+---------+--------------------+ 
| default | Default | True    | The default domain | 
+---------+---------+---------+--------------------+ 

$ openstack user create --domain default --password-prompt my-new-user 
User Password: 
Repeat User Password: 
+---------------------+----------------------------------+ 
| Field               | Value                            | 
+---------------------+----------------------------------+ 
| domain_id           | default                          | 
| enabled             | True                             | 
| id                  | 755bebd276f3451fa49f1194aee4dc20 | 
| name                | my-new-user                      | 
| options             | {}                               | 
| password_expires_at | None                             | 
+---------------------+----------------------------------+ 
```

# 为用户分配角色

我们将为我们的用户`my-new-user`分配一个管理员角色：

```
$ openstack role add --domain default --user my-new-user admin 

$ openstack user show my-new-user 
+---------------------+----------------------------------+ 
| Field               | Value                            | 
+---------------------+----------------------------------+ 
| domain_id           | default                          | 
| enabled             | True                             | 
| id                  | 755bebd276f3451fa49f1194aee4dc20 | 
| name                | my-new-user                      | 
| options             | {}                               | 
| password_expires_at | None                             | 
+---------------------+----------------------------------+ 
```

# 使用 Nova 创建虚拟机

让我们使用 Nova 创建一个虚拟机。我们将使用 Glance 中的 cirros 镜像和 Neutron 中的网络。

Glance 中可用的图像列表是由 DevStack 创建的：

```
$ openstack image list 
+--------------------------------------+--------------------------+--------+ 
| ID                                   | Name                     | Status | 
+--------------------------------------+--------------------------+--------+ 
| f396a79e-7ccf-4354-8201-623e4a6ec115 | cirros-0.3.5-x86_64-disk | active | 
| 0bc135f6-ebb5-4e8c-a44a-8b96954dfd93 | kubernetes/pause         | active | 
+--------------------------------------+--------------------------+--------+  
```

还要检查由 DevStack 安装创建的 Neutron 中的网络列表：

```
$ openstack network list
+--------------------------------------+---------+----------------------------------------------------------------------------+
| ID                                   | Name    | Subnets                                                                    |
+--------------------------------------+---------+----------------------------------------------------------------------------+
| 765cab64-cfaf-49f7-8e51-194cb9f40b9e | public  | af1dc81e-30f6-48b1-8e4f-6c978fe863e8, f430926e-5648-4f88-a4bd-d009bf316dda |
| a021cfcd-cf4b-41f2-b30a-033c12c542e4 | private | 254b646c-e518-4418-bcef-08ea0a44f4bc, 93651473-3533-46a3-b77e-a2056d6f6ec5 |
+--------------------------------------+---------+----------------------------------------------------------------------------+  
```

Nova 提供了一个指定 VM 资源的 flavor。以下是由 DevStack 在 Nova 中创建的 flavor 列表：

```
$ openstack flavor list                                                                                        +----+-----------+-------+------+-----------+-------+-----------+
| ID | Name      |   RAM | Disk | Ephemeral | VCPUs | Is Public |
+----+-----------+-------+------+-----------+-------+-----------+
| 1  | m1.tiny   |   512 |    1 |         0 |     1 | True      |
| 2  | m1.small  |  2048 |   20 |         0 |     1 | True      |
| 3  | m1.medium |  4096 |   40 |         0 |     2 | True      |
| 4  | m1.large  |  8192 |   80 |         0 |     4 | True      |
| 42 | m1.nano   |    64 |    0 |         0 |     1 | True      |
| 5  | m1.xlarge | 16384 |  160 |         0 |     8 | True      |
| 84 | m1.micro  |   128 |    0 |         0 |     1 | True      |
| c1 | cirros256 |   256 |    0 |         0 |     1 | True      |
| d1 | ds512M    |   512 |    5 |         0 |     1 | True      |
| d2 | ds1G      |  1024 |   10 |         0 |     1 | True      |
| d3 | ds2G      |  2048 |   10 |         0 |     2 | True      |
| d4 | ds4G      |  4096 |   20 |         0 |     4 | True      |
+----+-----------+-------+------+-----------+-------+-----------+  
```

我们将创建一个密钥对，用于 SSH 到在 Nova 中创建的 VM：

```
$ openstack keypair create --public-key ~/.ssh/id_rsa.pub mykey
+-------------+-------------------------------------------------+
| Field       | Value                                           |
+-------------+-------------------------------------------------+
| fingerprint | 98:0a:d5:70:30:34:16:06:79:3e:fc:33:14:b1:d9:b7 |
| name        | mykey                                           |
| user_id     | bbcd13444b1e4e4886eb8f36f4e80600                |
+-------------+-------------------------------------------------+  
```

让我们使用之前列出的所有资源创建一个 VM：

```
$ openstack server create --flavor m1.tiny --image f396a79e-7ccf-4354-8201-623e4a6ec115   --nic net-id=a021cfcd-cf4b-41f2-b30a-033c12c542e4  --key-name mykey test-vm
+-------------------------------------+-----------------------------------------------------------------+
| Field                               | Value                                                           |
+-------------------------------------+-----------------------------------------------------------------+
| OS-DCF:diskConfig                   | MANUAL                                                          |
| OS-EXT-AZ:availability_zone         |                                                                 |
| OS-EXT-SRV-ATTR:host                | None                                                            |
| OS-EXT-SRV-ATTR:hypervisor_hostname | None                                                            |
| OS-EXT-SRV-ATTR:instance_name       |                                                                 |
| OS-EXT-STS:power_state              | NOSTATE                                                         |
| OS-EXT-STS:task_state               | scheduling                                                      |
| OS-EXT-STS:vm_state                 | building                                                        |
| OS-SRV-USG:launched_at              | None                                                            |
| OS-SRV-USG:terminated_at            | None                                                            |
| accessIPv4                          |                                                                 |
| accessIPv6                          |                                                                 |
| addresses                           |                                                                 |
| adminPass                           | dTTHcP3dByXR                                                    |
| config_drive                        |                                                                 |
| created                             | 2017-09-09T08:36:55Z                                            |
| flavor                              | m1.tiny (1)                                                     |
| hostId                              |                                                                 |
| id                                  | 6dc0c74c-7259-4730-929e-b0f3d39a2c45                            |
| image                               | cirros-0.3.5-x86_64-disk (f396a79e-7ccf-4354-8201-623e4a6ec115) |
| key_name                            | mykey                                                           |
| name                                | test-vm                                                         |
| progress                            | 0                                                               |
| project_id                          | 7994b2ef08de4a05a5db61fcbee29506                                |
| properties                          |                                                                 |
| security_groups                     | name='default'                                                  |
| status                              | BUILD                                                           |
| updated                             | 2017-09-09T08:36:55Z                                            |
| user_id                             | bbcd13444b1e4e4886eb8f36f4e80600                                |
| volumes_attached                    |                                                                 |
+-------------------------------------+-----------------------------------------------------------------+    

```

检查服务器列表，以验证 VM 是否成功启动：

```
$ openstack server list
+--------------------------------------+---------+--------+--------------------------------------------------------+--------------------------+---------+
| ID                                   | Name    | Status | Networks                                               | Image                    | Flavor  |
+--------------------------------------+---------+--------+--------------------------------------------------------+--------------------------+---------+
| 6dc0c74c-7259-4730-929e-b0f3d39a2c45 | test-vm | ACTIVE | private=10.0.0.8, fd26:4d99:7734:0:f816:3eff:feaf:e37b | cirros-0.3.5-x86_64-disk | m1.tiny |
+--------------------------------------+---------+--------+-------------------------------------------------------+--------------------------+---------+  
```

# 将卷附加到 VM

现在我们的 VM 正在运行，让我们尝试做一些更有雄心的事情。我们现在将在 Cinder 中创建一个卷，并将其附加到我们正在运行的 VM 上：

```
$ openstack availability zone list
+-----------+-------------+
| Zone Name | Zone Status |
+-----------+-------------+
| internal  | available   |
| nova      | available   |
| nova      | available   |
| nova      | available   |
| nova      | available   |
+-----------+-------------+

$ openstack volume create --size 1 --availability-zone nova my-new-volume
+---------------------+--------------------------------------+
| Field               | Value                                |
+---------------------+--------------------------------------+
| attachments         | []                                   |
| availability_zone   | nova                                 |
| bootable            | false                                |
| consistencygroup_id | None                                 |
| created_at          | 2017-09-09T08:41:33.020340           |
| description         | None                                 |
| encrypted           | False                                |
| id                  | 889c1f21-7ca5-4913-aa80-44182cea824e |
| migration_status    | None                                 |
| multiattach         | False                                |
| name                | my-new-volume                        |
| properties          |                                      |
| replication_status  | None                                 |
| size                | 1                                    |
| snapshot_id         | None                                 |
| source_volid        | None                                 |
| status              | creating                             |
| type                | lvmdriver-1                          |
| updated_at          | None                                 |
| user_id             | bbcd13444b1e4e4886eb8f36f4e80600     |
+---------------------+--------------------------------------+  
```

让我们检查 Cinder 中的卷列表。我们将看到我们的卷已创建并处于可用状态：

```
$ openstack volume list
+--------------------------------------+---------------+-----------+------+-------------+
| ID                                   | Name          | Status    | Size | Attached to |
+--------------------------------------+---------------+-----------+------+-------------+
| 889c1f21-7ca5-4913-aa80-44182cea824e | my-new-volume | available |    1 |             |
+--------------------------------------+---------------+-----------+------+-------------+  
```

让我们将这个卷附加到我们的 VM 上：

```
$ openstack server add volume test-vm 889c1f21-7ca5-4913-aa80-44182cea824e

```

验证卷是否已附加：

```
$ openstack volume list
+--------------------------------------+---------------+--------+------+----------------------------------+
| ID                                   | Name          | Status | Size | Attached to                      |
+--------------------------------------+---------------+--------+------+----------------------------------+
| 889c1f21-7ca5-4913-aa80-44182cea824e | my-new-volume | in-use |    1 | Attached to test-vm on /dev/vdb  |
+--------------------------------------+---------------+--------+------+----------------------------------+  
```

您可以在这里看到卷已附加到我们的`test-vm`虚拟机上。

# 将图像上传到 Swift

我们将尝试将图像上传到 Swift。首先，检查帐户详细信息：

```
$ openstack object store account show
+------------+---------------------------------------+
| Field      | Value                                 |
+------------+---------------------------------------+
| Account    | AUTH_8ef89519b0454b57a038b6f044fa0101 |
| Bytes      | 0                                     |
| Containers | 0                                     |
| Objects    | 0                                     |
+------------+---------------------------------------+  
```

我们将创建一个图像容器来存储所有我们的图像。同样，我们可以在一个帐户中创建多个容器，使用任何逻辑名称来存储不同类型的数据：

```
$ openstack container create images
+---------------------------------------+-----------+------------------------------------+
| account                               | container | x-trans-id                         |
+---------------------------------------+-----------+------------------------------------+
| AUTH_8ef89519b0454b57a038b6f044fa0101 | images    | tx3f28728ccbbe4fcabfe1b-0059b3af9b |
+---------------------------------------+-----------+------------------------------------+

$ openstack container list
+--------+
| Name   |
+--------+
| images |
+--------+  
```

现在我们有了一个容器，让我们将一个图像上传到容器中：

```
$ openstack object create images sunrise.jpeg
+--------------+-----------+----------------------------------+
| object       | container | etag                             |
+--------------+-----------+----------------------------------+
| sunrise.jpeg | images    | 243f98a9d31d140bb123e56624703106 |
+--------------+-----------+----------------------------------+

$ openstack object list images
+--------------+
| Name         |
+--------------+
| sunrise.jpeg |
+--------------+

$ openstack container show images
+--------------+---------------------------------------+
| Field        | Value                                 |
+--------------+---------------------------------------+
| account      | AUTH_8ef89519b0454b57a038b6f044fa0101 |
| bytes_used   | 2337288                               |
| container    | images                                |
| object_count | 1                                     |
+--------------+---------------------------------------+  
```

您可以看到图像已成功上传到 Swift 对象存储。

在 OpenStack 中还有许多其他可用的功能，您可以在每个项目的用户指南中阅读到。

# 摘要

在本章中，我们为您提供了 OpenStack 的基本介绍以及 OpenStack 中可用的组件。我们讨论了各个项目的组件和架构。然后，我们完成了一个 DevStack 安装，为运行 OpenStack 设置了一个开发环境。然后，我们进行了一些关于使用 Nova 进行 VM 的实际配置。这包括添加一个 KeyStone 用户，为他们分配角色，并在 VM 配置完成后将卷附加到 VM。此外，我们还看了如何使用 Swift 上传和下载文件。在下一章中，我们将看看 OpenStack 中容器化的状态。


# 第四章：OpenStack 中的容器化

本章首先解释了 OpenStack 中容器的需求。然后，它还解释了 OpenStack 内部支持容器的不同过程。

容器是一个非常热门的话题。用户希望在虚拟机上运行他们的生产工作负载。它们之所以受欢迎，是因为以下原因：

+   容器使用包装概念提供不可变的基础架构模型

+   使用容器轻松开发和运行微服务

+   它们促进了应用程序的更快开发和测试

Linux 内核多年来一直支持容器。微软最近也开始支持 Windows Server 容器和 Hyper-V 容器。随着时间的推移，容器和 OpenStack 对容器的支持也在不断发展。OpenStack 提供 API 来管理数据中心内的容器及其编排引擎。

在本章中，我们将讨论 OpenStack 和容器如何结合在一起。本章涵盖以下主题：

+   OpenStack 中容器的需求

+   OpenStack 社区内支持容器的努力

# OpenStack 中容器的需求

许多组织使用 OpenStack。云基础设施供应商称 OpenStack 为维护私有云但具有公共云可扩展性和灵活性的开源替代品。OpenStack 在基于 Linux 的基础设施即服务（IaaS）方面很受欢迎。随着容器的流行，OpenStack 必须提供各种基础设施资源，如计算、网络和存储，以支持容器。开发人员和运营商可以通过提供跨平台 API 来管理虚拟机、容器和裸金属，而不是在其数据中心中创建新的垂直孤立。

# OpenStack 社区内支持容器的努力

OpenStack 提供以下功能：

+   计算资源

+   多租户安全和隔离

+   管理和监控

+   存储和网络

前面提到的服务对于任何云/数据中心管理工具都是必需的，无论使用哪种容器、虚拟机或裸金属服务器。容器补充了现有技术并带来了一系列新的好处。OpenStack 提供支持在裸金属或虚拟机上运行容器的支持。

在 OpenStack 中，以下项目已经采取了主动行动或提供了对容器和相关技术的支持。

# Nova

Nova 是 OpenStack 的计算服务。Nova 提供 API 来管理虚拟机。Nova 支持使用两个库（即 LXC 和 OpenVZ（Virtuozzo））来提供机器容器的配置。这些与容器相关的库由 libvirt 支持，Nova 使用它来管理虚拟机。

# Heat

Heat 是 OpenStack 的编排服务。自 OpenStack 的 Icehouse 版本以来，Heat 已经支持了对 Docker 容器的编排。用户需要在 Heat 中启用 Docker 编排插件才能使用这个功能。

# Magnum

Magnum 是 OpenStack 的容器基础设施管理服务。Magnum 提供 API 来在 OpenStack 基础设施上部署 Kubernetes、Swarm 和 Mesos 集群。Magnum 使用 Heat 模板在 OpenStack 上部署这些集群。用户可以使用这些集群来运行他们的容器化应用程序。

# Zun

Zun 是 OpenStack 的容器管理服务。Zun 提供 API 来管理 OpenStack 云中容器的生命周期。目前，Zun 支持在裸金属上运行容器，但在将来，它可能会支持在 Nova 创建的虚拟机上运行容器。Zun 使用 Kuryr 为容器提供 neutron 网络。Zun 使用 Cinder 为容器提供持久存储。

# Kuryr

Kuryr 是一个 Docker 网络插件，使用 Neutron 为 Docker 容器提供网络服务。

# Kolla

Kolla 是一个项目，它在 Docker 容器中部署 OpenStack 控制器平面服务。Kolla 通过将每个控制器服务打包为 Docker 容器中的微服务，简化了部署和操作。

# Murano

Murano 是一个为应用开发人员和云管理员提供应用程序目录的 OpenStack 项目，可以在 OpenStack Dashboard（Horizon）中的存储库中发布云就绪应用程序，这些应用程序可以在 Docker 或 Kubernetes 中运行。它为开发人员和运营商提供了控制应用程序完整生命周期的能力。

# Fuxi

Fuxi 是 Docker 容器的存储插件，使容器能够在其中使用 Cinder 卷和 Manila 共享作为持久存储。

# OpenStack-Helm

OpenStack-Helm 是另一个 OpenStack 项目，为运营商和开发人员提供了在 Kubernetes 之上部署 OpenStack 的框架。

# 总结

在本章中，我们了解了为什么 OpenStack 应该支持容器。我们还看了 OpenStack 社区为支持容器所做的努力。

在下一章中，我们将详细了解 Magnum（OpenStack 中的容器基础设施管理服务）。我们还将使用 Magnum 在 OpenStack 中进行一些 COE 管理的实践练习。
