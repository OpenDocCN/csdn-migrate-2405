# Docker 学习手册（二）（一）

> 原文：[`zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482`](https://zh.annas-archive.org/md5/1FDAAC9AD3D7C9F0A89A69D7710EA482)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

为了建立广受需求的软件可移植性，我们已经长时间研究虚拟化技术和工具。通过利用虚拟化这种有益的抽象，通过额外的间接层来消除软件和硬件之间的抑制性依赖因素。这个想法是在任何硬件上运行任何软件。这是通过将单个物理服务器分成多个虚拟机（VMs）来实现的，每个 VM 都有自己的操作系统（OS）。通过自动化工具和受控资源共享实现的隔离，异构应用程序可以在一台物理机上容纳。

通过虚拟化，IT 基础设施变得开放、可编程、可远程监控、可管理和可维护。业务工作负载可以托管在适当大小的虚拟机中，并传送到外部世界，确保更广泛和更频繁的利用。另一方面，对于高性能应用程序，可以轻松识别跨多台物理机的虚拟机，并迅速组合以保证任何种类的高性能需求。

虚拟化范式也有其缺点。由于冗长和臃肿（每个虚拟机都携带自己的操作系统），虚拟机的配置通常需要一段时间，性能会因过度使用计算资源而下降，等等。此外，对可移植性的不断增长需求并未完全得到虚拟化的满足。来自不同供应商的 Hypervisor 软件妨碍了应用程序的可移植性。操作系统和应用程序分发、版本、版本和补丁的差异阻碍了平稳的可移植性。计算机虚拟化蓬勃发展，而与之密切相关的网络和存储虚拟化概念刚刚起步。通过虚拟机相互作用构建分布式应用程序会引发和涉及一些实际困难。

让我们继续讨论容器化。所有这些障碍都促成了容器化理念的空前成功。一个容器通常包含一个应用程序，应用程序的所有库、二进制文件和其他依赖项都被一起打包，以作为一个全面而紧凑的实体呈现给外部世界。容器非常轻量级，高度可移植，易于快速配置等等。Docker 容器实现了本地系统性能。通过应用容器，DevOps 的目标得到了充分实现。作为最佳实践，建议每个容器托管一个应用程序或服务。

流行的 Docker 容器化平台推出了一个使容器的生命周期管理变得简单和快速的启用引擎。有行业强度和开放自动化工具免费提供，以满足容器网络和编排的需求。因此，生产和维护业务关键的分布式应用变得容易。业务工作负载被系统地容器化，以便轻松地转移到云环境，并为容器工匠和作曲家提供云端软件解决方案和服务。确切地说，容器正在成为 IT 和业务服务最具特色、受欢迎和精细调整的运行时环境。

本书精心设计和开发，旨在为开发人员、云架构师、业务经理和战略家提供有关 Docker 平台及其推动行业垂直领域中的关键、复合和分布式应用的所有正确和相关信息。

# 本书涵盖了以下内容

《第一章》（ch01.html“第一章。使用 Docker 入门”）*使用 Docker 入门*，介绍了 Docker 平台以及它如何简化和加速实现容器化工作负载的过程，以便在各种平台上轻松部署和运行。本章还详细介绍了安装 Docker 引擎、从集中式 Docker Hub 下载 Docker 镜像、创建 Docker 容器以及排除 Docker 容器故障的步骤。

第二章，“处理 Docker 容器”，主要是为了阐述管理 Docker 图像和容器所需的命令。本章提供了理解 Docker 命令输出所需的基本 Docker 术语。此外，本章还涵盖了在容器内启动交互会话，管理图像，运行容器以及跟踪容器内的更改等其他细节。

第三章，“构建图像”，介绍了 Docker 集成图像构建系统。本章还涵盖了 Dockerfile 语法的快速概述以及关于 Docker 如何存储图像的一些理论。

第四章，“发布图像”，侧重于在集中式 Docker Hub 上发布图像以及如何充分利用 Docker Hub。本章的其他重要内容包括有关 Docker Hub 的更多细节，如何将图像推送到 Docker Hub，图像的自动构建，创建 Docker Hub 上的组织，以及私有存储库。

第五章，“运行您的私有 Docker 基础设施”，解释了企业如何建立自己的私有存储库。由于某些原因，企业可能不希望将特定的 Docker 图像托管在公开可用的图像存储库（如 Docker Hub）中。因此，他们需要自己的私有存储库来保存这些图像。本章包含了设置和维护私有存储库所需的所有信息。

第六章，“在容器中运行服务”，说明了如何将 Web 应用程序作为服务在 Docker 容器内运行，以及如何公开该服务，以便外部世界找到并访问它。还详细描述了如何开发适当的 Dockerfile 以简化此任务。

第七章，“与容器共享数据”，向您展示如何使用 Docker 的卷功能在 Docker 主机和其容器之间共享数据。本章还涵盖了如何在容器之间共享数据，常见用例以及要避免的典型陷阱。

第八章 *编排容器*，着重于编排多个容器以实现复合、容器化的工作负载。众所周知，编排在生成复合应用程序中起着重要作用。本章包括一些关于编排和可用于启用编排过程的工具集的信息。最后，您将找到一个精心编排的示例，演示如何编排容器以产生高度可重用和业务感知的容器。

第九章 *使用 Docker 进行测试*，侧重于在 Docker 镜像内测试您的代码。在本章中，您将了解如何在临时 Docker 镜像内运行测试。最后，您将了解如何将 Docker 测试集成到持续集成服务器（如 Jenkins）中的详细信息。

第十章 *调试容器*，教您如何调试在容器内运行的应用程序。还涵盖了关于 Docker 如何确保容器内运行的进程与外部世界隔离的详细信息。此外，还包括了关于使用 nsenter 和 nsinit 工具进行有效调试的描述。

第十一章 *保护 Docker 容器*，旨在解释正在酝酿的安全和隐私挑战和关注点，以及通过使用充分的标准、技术和工具来解决这些问题。本章描述了在镜像内降低用户权限的机制。还简要介绍了在保护 Docker 容器时，SELinux 引入的安全功能如何派上用场。

# 本书所需内容

Docker 平台需要 64 位硬件系统才能运行。本书的 Docker 应用程序是在 Ubuntu 14.04 上开发的，但这并不意味着 Docker 平台不能在其他 Linux 发行版上运行，比如 Redhat、CentOS、CoreOS 等。但是，Linux 内核版本必须是 3.10 或更高版本。

# 本书适合对象

如果您是一名应用程序开发人员，想要学习 Docker 以利用其特性进行应用部署，那么这本书适合您。不需要 Docker 的先前知识。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“如果`docker`服务正在运行，则此命令将打印状态为`start/running`，并显示其进程 ID。”

代码块设置如下：

```
FROM busybox:latest
CMD echo Hello World!!
```

任何命令行输入或输出都以以下形式书写：

```
$ sudo docker tag 224affbf9a65localhost:5000/vinoddandy/dockerfileimageforhub

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“选择**Docker**选项，它在下拉菜单中，然后点击**立即启动**。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：Docker 入门

如今，Docker 技术在全球范围内的信息技术（IT）专业人士中获得了更多的市场份额和更多的关注。在本章中，我们想更多地介绍 Docker，并展示为什么它被誉为即将到来的云 IT 时代的下一个最佳选择。为了使本书与软件工程师相关，我们列出了制作高度可用的应用程序感知容器所需的步骤，将它们注册到公共注册库中，然后在多个 IT 环境（本地和离地）中部署它们。在本书中，我们清楚地解释了 Docker 的先决条件和最重要的细节，借助我们通过一系列在不同系统中谨慎实施的几个有用的 Docker 容器所获得的所有教育和经验。为了做到这一点，我们使用了我们自己的笔记本电脑以及一些领先的公共云服务提供商（CSP）。

我们想向您介绍 Docker 实用方面，以改变游戏规则的 Docker 启发式容器化运动。

在本章中，我们将涵盖以下主题：

+   Docker 简介

+   Linux 上的 Docker

+   区分容器化和虚拟化

+   安装 Docker 引擎

+   了解 Docker 设置

+   下载第一个镜像

+   运行第一个容器

+   在 Amazon Web Services（AWS）上运行 Docker 容器

+   解决 Docker 容器的故障

# Docker 简介

由于其在行业垂直领域的广泛使用，IT 领域已经充斥着许多新的和开创性的技术，这些技术不仅用于带来更具决定性的自动化，而且还用于克服现有的复杂性。虚拟化已经设定了将 IT 基础设施优化和可移植性带入前景的目标。然而，虚拟化技术存在严重缺陷，例如由于虚拟机（VM）的笨重性质而导致的性能下降，应用程序可移植性的缺乏，IT 资源的提供速度缓慢等。因此，IT 行业一直在稳步地踏上 Docker 启发式容器化之旅。Docker 倡议专门设计了使容器化范式更易于理解和使用的目的。Docker 使容器化过程能够以无风险和加速的方式完成。

确切地说，**Docker**是一个开源的容器化引擎，它自动化打包、运输和部署任何呈现为轻量、便携和自给自足容器的软件应用程序，可以在几乎任何地方运行。

Docker **容器**是一个软件桶，包括运行软件所需的一切。单台机器上可以有多个 Docker 容器，这些容器彼此完全隔离，也与主机机器隔离。

换句话说，Docker 容器包括一个软件组件以及其所有依赖项（二进制文件、库、配置文件、脚本、jar 等）。因此，Docker 容器可以在支持命名空间、控制组和文件系统（如**另一个联合文件系统**（AUFS））的 x64 Linux 内核上流畅运行。然而，正如本章所示，对于在其他主流操作系统（如 Windows、Mac 等）上运行 Docker，有实用的解决方法。Docker 容器有自己的进程空间和网络接口。它也可以以 root 身份运行，并且有自己的`/sbin/init`，这可能与主机机器不同。

简而言之，Docker 解决方案让我们快速组装复合、企业规模和业务关键的应用程序。为了做到这一点，我们可以使用不同的分布式软件组件：容器消除了将代码发送到远程位置时出现的摩擦。Docker 还让我们能够尽快测试代码，然后在生产环境中部署它。Docker 解决方案主要包括以下组件：

+   Docker 引擎

+   Docker Hub

Docker 引擎用于实现特定目的和通用 Docker 容器。Docker Hub 是 Docker 镜像的快速增长的存储库，可以以不同方式组合，以产生公开可查找、网络可访问和广泛可用的容器。

# Linux 上的 Docker

假设我们想要直接在 Linux 机器上运行容器。Docker 引擎产生、监控和管理多个容器，如下图所示：

![Linux 上的 Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_01_01.jpg)

上图生动地说明了未来的 IT 系统将拥有数百个应用感知容器，这些容器天生具有促进其无缝集成和编排以获得模块化应用程序（业务、社交、移动、分析和嵌入式解决方案）的能力。这些包含的应用程序可以流畅地运行在融合、联合、虚拟化、共享、专用和自动化的基础设施上。

# 容器化和虚拟化的区别

从容器化范式中提取和阐述 Docker 启发的容器化运动的颠覆性优势是至关重要和至关重要的，这超过了广泛使用和完全成熟的虚拟化范式。在容器化范式中，通过一些关键和明确定义的合理化和计算资源的深刻共享，战略上合理的优化已经完成。一些天生的而迄今为止未充分利用的 Linux 内核功能已经被重新发现。这些功能因为带来了备受期待的自动化和加速而受到了奖励，这将使新兴的容器化理念在未来的日子里达到更高的高度，特别是在云时代。这些显著的商业和技术优势包括裸金属级性能、实时可伸缩性、更高的可用性等。所有不需要的凸起和赘肉都被明智地消除，以便以成本效益的方式加快数百个应用容器的部署速度，并缩短营销和估值所需的时间。左侧的下图描述了虚拟化方面，而右侧的图形生动地说明了容器中所实现的简化：

![容器化和虚拟化的区别](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_01_02.jpg)

下表直接比较了虚拟机和容器：

| 虚拟机（VMs） | 容器 |
| --- | --- |
| 代表硬件级虚拟化 | 代表操作系统虚拟化 |
| 重量级 | 轻量级 |
| 缓慢的供应 | 实时供应和可伸缩性 |
| 有限的性能 | 本机性能 |
| 完全隔离，因此更安全 | 进程级隔离，因此不太安全 |

## 容器化和虚拟化的融合

正在开发一种混合模型，具有虚拟机和容器的特性。这就是系统容器的出现，如前述右侧图表所示。传统的虚拟化程序，隐式地代表硬件虚拟化，直接利用服务器硬件来保护环境。也就是说，虚拟机与其他虚拟机以及底层系统完全隔离。但对于容器来说，这种隔离是在进程级别进行的，因此容器容易受到任何安全侵入的影响。此外，一些在虚拟机中可用的重要功能在容器中是不可用的。例如，容器中没有对 SSH、TTY 和其他安全功能的支持。另一方面，虚拟机需要大量资源，因此它们的性能会大幅下降。事实上，在容器化术语中，经典虚拟化程序和客户操作系统的开销将被消除，以实现裸金属性能。因此，可以为单台机器提供一些虚拟机。因此，一方面，我们有性能一般的完全隔离的虚拟机，另一方面，我们有一些缺少一些关键功能但性能卓越的容器。在理解了随之而来的需求后，产品供应商正在研发系统容器。这一新举措的目标是提供具有裸金属服务器性能但具有虚拟机体验的完整系统容器。前述右侧图表中的系统容器代表了两个重要概念（虚拟化和容器化）的融合，以实现更智能的 IT。我们将在未来听到更多关于这种融合的信息。

## 容器化技术

认识到容器化范式对 IT 基础设施增强和加速的作用和相关性后，一些利用容器化理念的独特和决定性影响的技术应运而生，并被列举如下：

+   **LXC**（**Linux 容器**）：这是所有容器的鼻祖，它代表了在单个 Linux 机器上运行多个隔离的 Linux 系统（容器）的操作系统级虚拟化环境。

维基百科网站上的文章*LXC*指出：

> “Linux 内核提供了 cgroups 功能，允许对资源（CPU、内存、块 I/O、网络等）进行限制和优先级设置，而无需启动任何虚拟机，并提供了命名空间隔离功能，允许完全隔离应用程序对操作环境的视图，包括进程树、网络、用户 ID 和挂载的文件系统。”

您可以从[`en.wikipedia.org/wiki/LXC`](http://en.wikipedia.org/wiki/LXC)获取更多信息。

+   OpenVZ：这是一种基于 Linux 内核和操作系统的操作系统级虚拟化技术。OpenVZ 允许物理服务器运行多个隔离的操作系统实例，称为容器、虚拟专用服务器（VPS）或虚拟环境（VEs）。

+   FreeBSD 监狱：这是一种实现操作系统级虚拟化的机制，它允许管理员将基于 FreeBSD 的计算机系统分成几个独立的迷你系统，称为“监狱”。

+   AIX 工作负载分区（WPARs）：这些是操作系统级虚拟化技术的软件实现，提供应用环境隔离和资源控制。

+   Solaris 容器（包括 Solaris Zones）：这是针对 x86 和 SPARC 系统的操作系统级虚拟化技术的实现。Solaris 容器是由“区域”提供的系统资源控制和边界分离的组合。区域在单个操作系统实例内充当完全隔离的虚拟服务器。

在本书中，考虑到 Docker 的风靡和大规模采用，我们选择深入挖掘，详细讨论 Docker 平台，这是简化和优化容器化运动的一站式解决方案。

# 安装 Docker 引擎

Docker 引擎是建立在 Linux 内核之上的，并且广泛利用其功能。因此，目前 Docker 引擎只能直接在 Linux 操作系统发行版上运行。尽管如此，通过使用轻量级 Linux 虚拟机和适配器（如 Boot2Docker），Docker 引擎可以在 Mac 和 Microsoft Windows 操作系统上运行。由于 Docker 的迅猛增长，它现在被所有主要的 Linux 发行版打包，以便它们可以保留他们的忠实用户并吸引新用户。您可以使用相应的 Linux 发行版的打包工具来安装 Docker 引擎；例如，使用`apt-get`命令安装 Debian 和 Ubuntu，使用`yum`命令安装 RedHat、Fedora 和 CentOS。

### 注意

我们选择了*Ubuntu Trusty 14.04（LTS）（64 位）* Linux 发行版以供所有实际目的使用。

## 从 Ubuntu 软件包存储库安装

本节详细解释了从 Ubuntu 软件包存储库安装 Docker 引擎涉及的步骤。在撰写本书时，Ubuntu 存储库已经打包了 Docker 1.0.1，而最新版本的 Docker 是 1.5。我们强烈建议使用下一节中描述的任一方法安装 Docker 版本 1.5 或更高版本。

但是，如果出于任何原因您必须安装 Ubuntu 打包版本，请按照这里描述的步骤进行。

1.  安装 Ubuntu 打包版本的最佳做法是通过重新与 Ubuntu 软件包存储库同步开始安装过程。这一步将更新软件包存储库到最新发布的软件包，因此我们将确保始终使用此处显示的命令获取最新发布的版本：

```
$ sudo apt-get update

```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

1.  使用以下命令启动安装。此设置将安装 Docker 引擎以及一些支持文件，并立即启动`docker`服务：

```
$ sudo apt-get install -y docker.io

```

### 注意

Docker 软件包被称为`docker.io`，因为 Ubuntu 软件包的旧版本被称为`docker`。因此，所有名为`docker`的文件都被安装为`docker.io`。

例如`/usr/bin/docker.io`和`/etc/bash_completion.d/docker.io`。

1.  为了方便起见，你可以为`docker.io`创建一个名为`docker`的软链接。这将使你能够以`docker`而不是`docker.io`执行 Docker 命令。你可以使用以下命令来实现这一点：

```
$ sudo ln -sf /usr/bin/docker.io /usr/local/bin/docker

```

### 注意

官方的 Ubuntu 软件包不包含最新稳定版本的`docker`。

## 使用 docker.io 脚本安装最新的 Docker

官方发行版可能不会打包最新版本的 Docker。在这种情况下，你可以手动安装最新版本的 Docker，也可以使用 Docker 社区提供的自动化脚本。

要手动安装最新版本的 Docker，请按照以下步骤进行：

1.  将 Docker 发布工具的存储库路径添加到你的 APT 源中，如下所示：

```
$ sudo sh -c "echo deb https://get.docker.io/ubuntu \
 docker main > /etc/apt/sources.list.d/docker.list"

```

1.  通过运行以下命令导入 Docker 发布工具的公钥：

```
$ sudo apt-key adv --keyserver \
 hkp://keyserver.ubuntu.com:80 --recv-keys \
 36A1D7869245C8950F966E92D8576A8BA88D21E9

```

1.  使用以下命令重新与软件包存储库同步：

```
$ sudo apt-get update

```

1.  安装`docker`，然后启动`docker`服务。

```
$ sudo apt-get install -y lxc-docker

```

### 注意

`lxc-docker`命令将使用名称`docker`安装 Docker 镜像。

Docker 社区通过隐藏这些细节在自动安装脚本中迈出了一步。该脚本使得在大多数流行的 Linux 发行版上安装 Docker 成为可能，可以通过`curl`命令或`wget`命令来实现，如下所示：

+   对于 curl 命令：

```
$ sudo curl -sSL https://get.docker.io/ | sh

```

+   对于 wget 命令：

```
$ sudo wget -qO- https://get.docker.io/ | sh

```

### 注意

前面的自动化脚本方法将 AUFS 作为底层 Docker 文件系统。该脚本探测 AUFS 驱动程序，如果在系统中找不到，则自动安装它。此外，它还在安装后进行一些基本测试以验证其完整性。

# 理解 Docker 设置

重要的是要了解 Docker 的组件及其版本、存储、执行驱动程序、文件位置等。顺便说一句，对于理解 Docker 设置的追求也将揭示安装是否成功。你可以通过使用两个`docker`子命令来实现这一点，即`docker version`和`docker info`。

让我们通过`docker version`子命令开始我们的`docker`之旅，如下所示：

```
$ sudo docker version
Client version: 1.5.0
Client API version: 1.17
Go version (client): go1.4.1
Git commit (client): a8a31ef
OS/Arch (client): linux/amd64
Server version: 1.5.0
Server API version: 1.17
Go version (server): go1.4.1
Git commit (server): a8a31ef

```

尽管`docker version`子命令列出了许多文本行，作为 Docker 用户，你应该知道以下输出行的含义：

+   客户端版本

+   客户端 API 版本

+   服务器版本

+   服务器 API 版本

在这里考虑的客户端和服务器版本分别为 1.5.0 和客户端 API 和服务器 API 版本 1.17。

如果我们分析`docker version`子命令的内部，它首先会列出本地存储的与客户端相关的信息。随后，它将通过 HTTP 向服务器发出 REST API 调用，以获取与服务器相关的详细信息。

让我们使用`docker info`子命令来了解更多关于 Docker 环境的信息：

```
$ sudo docker -D info
Containers: 0
Images: 0
Storage Driver: aufs
 Root Dir: /var/lib/docker/aufs
 Backing Filesystem: extfs
 Dirs: 0
Execution Driver: native-0.2
Kernel Version: 3.13.0-45-generic
Operating System: Ubuntu 14.04.1 LTS
CPUs: 4
Total Memory: 3.908 GiB
Name: dockerhost
ID: ZNXR:QQSY:IGKJ:ZLYU:G4P7:AXVC:2KAJ:A3Q5:YCRQ:IJD3:7RON:IJ6Y
Debug mode (server): false
Debug mode (client): true
Fds: 10
Goroutines: 14
EventsListeners: 0
Init Path: /usr/bin/docker
Docker Root Dir: /var/lib/docker
WARNING: No swap limit support

```

正如您在新安装的 Docker 引擎的输出中所看到的，`容器`和`镜像`的数量始终为零。`存储驱动程序`已设置为`aufs`，并且目录已设置为`/var/lib/docker/aufs`位置。`执行驱动程序`已设置为`本机`模式。此命令还列出了详细信息，如`内核版本`、`操作系统`、`CPU`数量、`总内存`和`名称`，即新的 Docker 主机名。

## 客户端服务器通信

在 Linux 安装中，Docker 通常通过使用 Unix 套接字(`/var/run/docker.sock`)进行服务器-客户端通信。Docker 还有一个 IANA 注册的端口，即`2375`。然而，出于安全原因，此端口默认情况下未启用。

# 下载第一个 Docker 镜像

成功安装了 Docker 引擎后，下一个逻辑步骤是从 Docker 注册表中下载镜像。Docker 注册表是一个应用程序存储库，其中托管了一系列应用程序，从基本的 Linux 镜像到高级应用程序不等。`docker pull`子命令用于从注册表下载任意数量的镜像。在本节中，我们将使用以下命令下载一个名为`busybox`的小型 Linux 版本的镜像：

```
$ sudo docker pull busybox
511136ea3c5a: Pull complete
df7546f9f060: Pull complete
ea13149945cb: Pull complete
4986bf8c1536: Pull complete
busybox:latest: The image you are pulling has been verified. Important: image verification is a tech preview feature and should not be relied on to provide security.
Status: Downloaded newer image for busybox:latest

```

一旦镜像被下载，可以使用`docker images`子命令进行验证，如下所示：

```
$ sudo docker images
REPOSITORY    TAG     IMAGE ID         CREATED      VIRTUAL SIZE
busybox       latest  4986bf8c1536     12 weeks ago 2.433 MB

```

# 运行第一个 Docker 容器

现在，您可以启动您的第一个 Docker 容器。以基本的*Hello World!*应用程序开始是标准做法。在下面的示例中，我们将使用已经下载的`busybox`镜像来回显`Hello World!`，如下所示：

```
$ sudo docker run busybox echo "Hello World!"
"Hello World!"

```

很酷，不是吗？您已经在短时间内设置了您的第一个 Docker 容器。在上面的示例中，使用了`docker run`子命令来创建一个容器，并使用`echo`命令打印`Hello World!`。

# 在亚马逊网络服务上运行 Docker 容器

**亚马逊网络服务**（**AWS**）在 2014 年初宣布了 Docker 容器的可用性，作为其 Elastic Beanstalk 提供的一部分。在 2014 年底，他们改革了 Docker 部署，并为用户提供了以下选项来运行 Docker 容器：

+   亚马逊 EC2 容器服务（在撰写本书时仅处于**预览**模式）

+   通过使用亚马逊弹性豆服务进行 Docker 部署

亚马逊 EC2 容器服务允许您通过简单的 API 调用启动和停止容器启用的应用程序。AWS 引入了集群的概念，用于查看容器的状态。您可以从集中式服务查看任务，并且它为您提供了许多熟悉的亚马逊 EC2 功能，如安全组、EBS 卷和 IAM 角色。

请注意，此服务仍未在 AWS 控制台中可用。您需要在您的机器上安装 AWS CLI 来部署、运行和访问此服务。

AWS Elastic Beanstalk 服务支持以下内容：

+   使用控制台支持 Elastic Beanstalk 的单个容器。目前，它支持 PHP 和 Python 应用程序。

+   使用一个名为*eb*的命令行工具支持 Elastic Beanstalk 的单个容器。它支持相同的 PHP 和 Python 应用程序。

+   通过使用 Elastic Beanstalk 使用多个容器环境。

目前，AWS 支持最新的 Docker 版本，即 1.5。

本节提供了在运行在 AWS Elastic Beanstalk 上的 Docker 容器上部署示例应用程序的逐步过程。以下是部署的步骤：

1.  通过使用此[`console.aws.amazon.com/elasticbeanstalk/`](https://console.aws.amazon.com/elasticbeanstalk/) URL 登录到 AWS Elastic Beanstalk 控制台。

1.  选择要部署应用程序的区域，如下所示：![在亚马逊网络服务上运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_01_03.jpg)

1.  选择下拉菜单中的**Docker**选项，然后点击**立即启动**。几分钟后，下一个屏幕将显示如下：![在亚马逊网络服务上运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_01_04.jpg)

现在，点击旁边的 URL **Default-Environment (Default-Environment-pjgerbmmjm.elasticbeanstalk.com)**，如下所示：

![在亚马逊网络服务上运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_01_05.jpg)

# 故障排除

大多数情况下，安装 Docker 时不会遇到任何问题。然而，可能会发生意外故障。因此，有必要讨论突出的故障排除技术和技巧。让我们从本节讨论故障排除知识开始。第一个提示是使用以下命令检查 Docker 的运行状态：

```
$ sudo service docker status

```

但是，如果 Docker 是通过 Ubuntu 软件包安装的，则必须使用`docker.io`作为服务名称。如果`docker`服务正在运行，则此命令将打印状态为`start/running`以及其进程 ID。

如果您在 Docker 设置中仍然遇到问题，那么您可以使用`/var/log/upstart/docker.log`文件打开 Docker 日志进行进一步调查。

# 总结

容器化将成为未来企业和云 IT 环境的主导和决定性范式，因为它具有迄今为止未曾预见的自动化和加速能力。有几种机制可以将容器化运动推向更高的高度。然而，在这场激烈的竞赛中，Docker 已经遥遥领先，并成功摧毁了先前阐明的障碍。

在本章中，我们专注于 Docker 的实际应用，为您提供学习最有前途的技术的起点。我们列出了在不同环境中轻松安装 Docker 引擎的适当步骤和技巧，以及利用和构建、安装和运行一些示例 Docker 容器的方法，无论是在本地还是远程环境中。我们将深入探讨 Docker 的世界，并深入挖掘，以在接下来的章节中与您分享战术和战略上的可靠信息。请继续阅读，以获取有关高级主题（如容器集成、编排、管理、治理、安全等）的所需知识，通过 Docker 引擎。我们还将讨论大量第三方工具。


# 第二章：处理 Docker 容器

在上一章中，我们解释了激动人心和可持续的概念，展示了 Docker 打造未来和灵活的应用感知容器的方式。我们讨论了在多个环境（本地和离线）中生成 Docker 容器的所有相关细节。使用这些技术，您可以轻松地在自己的环境中复制这些功能，获得丰富的体验。因此，我们的下一步是以果断的方式了解容器的生命周期方面。您将学习如何以有效和无风险的方式最佳利用我们自己的容器以及其他第三方容器。容器可以被发现、评估、访问和利用，以实现更大更好的应用。出现了几种工具来简化容器的处理。

在本章中，我们将深入挖掘并详细描述容器处理的关键方面。本章还将讨论一些实用技巧和执行命令，以利用容器。

在这一章中，我们将涵盖以下主题：

+   澄清 Docker 术语

+   与 Docker 镜像和容器一起工作

+   Docker 注册表及其存储库的含义

+   Docker Hub 注册表

+   搜索 Docker 镜像

+   与交互式容器一起工作

+   跟踪容器内部的变化

+   控制和管理 Docker 容器

+   从容器构建镜像

+   将容器作为守护进程启动

# 澄清 Docker 术语

为了使本章更易于理解并尽量减少任何形式的歧义，常用术语将在下一节中解释。

## Docker 镜像和容器

Docker 镜像是构成软件应用程序的所有文件的集合。对原始镜像所做的每个更改都存储在单独的层中。准确地说，任何 Docker 镜像都必须源自基础镜像，根据各种要求。可以附加额外的模块到基础镜像，以派生出可以展现所需行为的各种镜像。每次提交到 Docker 镜像时，都会在 Docker 镜像上创建一个新的层，但原始镜像和每个现有的层都保持不变。换句话说，镜像通常是只读类型的。如果它们通过系统化附加新模块的方式得到增强，那么将创建一个带有新名称的新镜像。Docker 镜像正在成为开发和部署 Docker 容器的可行基础。

这里展示了一个基础镜像。Debian 是基础镜像，可以在基础镜像上合并各种所需的功能模块，以得到多个镜像：

![Docker 镜像和容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/B03936_02_01.jpg)

每个镜像都有一个唯一的`ID`，如下一节所述。基础镜像可以进行增强，以便它们可以创建父镜像，而父镜像反过来可以用于创建子镜像。基础镜像没有任何父级，也就是说，父镜像位于基础镜像之上。当我们使用一个镜像时，如果没有通过适当的标识（比如一个新名称）指定该镜像，那么 Docker 引擎将始终识别并使用`latest`镜像（最近生成的）。

根据 Docker 官网，Docker 镜像是一个只读模板。例如，一个镜像可以包含一个 Ubuntu 操作系统，上面安装了 Apache 和你的 Web 应用程序。Docker 提供了一种简单的方法来构建新的镜像或更新现有的镜像。你也可以下载其他人已经创建的 Docker 镜像。Docker 镜像是 Docker 容器的构建组件。一般来说，基础 Docker 镜像代表一个操作系统，在 Linux 的情况下，基础镜像可以是其发行版之一，比如 Debian。向基础镜像添加额外的模块最终形成一个容器。最简单的想法是，容器是一个位于一个或多个只读镜像上的读写层。当容器运行时，Docker 引擎不仅将所有所需的镜像合并在一起，还将读写层的更改合并到容器本身。这使得它成为一个自包含、可扩展和可执行的系统。可以使用 Docker 的`docker commit`子命令来合并更改。新容器将容纳对基础镜像所做的所有更改。新镜像将形成基础镜像的新层。

下图将清楚地告诉你一切。基础镜像是**Debian**发行版，然后添加了两个镜像（**emacs**和**Apache**服务器），这将导致容器：

![Docker 镜像和容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/B03936_02_02.jpg)

每次提交都会生成一个新镜像。这使得镜像数量稳步增加，因此管理它们变得复杂。然而，存储空间并不是一个大挑战，因为生成的新镜像只包括新添加的模块。在某种程度上，这类似于云环境中流行的对象存储。每次更新对象，都会创建一个带有最新修改的新对象，然后以新的`ID`存储。在对象存储的情况下，存储大小会显著增加。

## 一个 Docker 层

一个**Docker 层**可以代表只读镜像或读写镜像。然而，容器堆栈的顶层始终是读写（可写）层，其中托管着一个 Docker 容器。

## 一个 Docker 容器

从前面的图表可以看出，读写层是容器层。容器层下面可能有几个只读镜像。通常，容器是通过 `commit` 操作从只读镜像创建的。当您 `start` 一个容器时，实际上是通过其唯一的 `ID` 引用一个镜像。Docker 拉取所需的镜像及其父镜像。它继续拉取所有父镜像，直到达到基础镜像。

## Docker 注册表

**Docker 注册表**是 Docker 镜像可以存储的地方，以便全球开发人员可以快速创建新的复合应用程序，而不会有任何风险。因为所有存储的镜像都经过多次验证、核实和完善，这些镜像的质量将非常高。使用 Docker `push` 命令，您可以将 Docker 镜像发送到注册表，以便注册和存储。澄清一下，注册表是用于注册 Docker 镜像的，而仓库是用于在公开可发现和集中的位置存储这些已注册的 Docker 镜像。Docker 镜像存储在 Docker 注册表中的仓库中。每个用户或帐户的仓库都是唯一的。

## Docker 仓库

**Docker 仓库**是用于存储 Docker 镜像的命名空间。例如，如果您的应用程序命名为 `helloworld`，并且您的用户名或注册表的命名空间为 `thedockerbook`，那么在 Docker 仓库中，此镜像将存储在 Docker 注册表中，命名为 `thedockerbook/helloworld`。

基础镜像存储在 Docker 仓库中。基础镜像是实现更大更好镜像的源泉，通过谨慎添加新模块来帮助实现。子镜像是具有自己父镜像的镜像。基础镜像没有任何父镜像。坐在基础镜像上的镜像被称为父镜像，因为父镜像承载着子镜像。

# 使用 Docker 镜像

在上一章中，我们通过使用`busybox`镜像演示了典型的`Hello World!`示例。现在需要仔细观察`docker pull`子命令的输出，这是一个用于下载 Docker 镜像的标准命令。您可能已经注意到输出文本中存在`busybox:latest`的文本，我们将通过对`docker pull`子命令添加`-a`选项来详细解释这个谜团。

```
$ sudo docker pull -a busybox

```

令人惊讶的是，您会发现 Docker 引擎使用`-a`选项下载了更多的镜像。您可以通过运行`docker images`子命令轻松检查 Docker 主机上可用的镜像，这非常方便，并且通过运行此命令可以揭示有关`:latest`和其他附加镜像的更多细节。让我们运行这个命令：

```
$ sudo docker images

```

您将获得以下镜像列表：

```
REPOSITORY TAG                  IMAGE ID      CREATED       VIRTUAL SIZE
busybox    ubuntu-14.04         f6169d24347d  3 months ago  5.609 MB
busybox    ubuntu-12.04         492dad4279ba  3 months ago  5.455 MB
busybox    buildroot-2014.02    4986bf8c1536  3 months ago  2.433 MB
busybox    latest               4986bf8c1536  3 months ago  2.433 MB
busybox    buildroot-2013.08.1  2aed48a4e41d  3 months ago  2.489 MB

```

显然，我们在前面的列表中有五个项目，为了更好地理解这些项目，我们需要理解 Docker images 子命令打印出的信息。以下是可能的类别列表：

+   `仓库`: 这是仓库或镜像的名称。在前面的例子中，仓库名称是`busybox`。

+   `标签`: 这是与镜像相关联的标签，例如`buildroot-2014.02`，`ubuntu-14.04`，`latest`。一个镜像可以关联一个或多个标签。

### 注意

以`ubuntu-`*标记的镜像是使用`busybox-static` Ubuntu 软件包构建的，以`buildroot-`*标记的镜像是使用`buildroot`工具链从头开始构建的。

+   `镜像 ID`: 每个镜像都有一个唯一的`ID`。镜像`ID`由一个 64 位十六进制长的随机数表示。默认情况下，Docker images 子命令只会显示 12 位十六进制数。您可以使用`--no-trunc`标志显示所有 64 位十六进制数（例如：`sudo docker images --no-trunc`）。

+   `创建时间`: 表示镜像创建的时间。

+   `虚拟大小`: 突出显示镜像的虚拟大小。

也许您会想知道，在前面的例子中，一个带有`-a`选项的`pull`命令是如何能够下载五个镜像的，尽管我们只指定了一个名为`busybox`的镜像。这是因为每个 Docker 镜像存储库都可以有同一镜像的多个变体，`-a`选项会下载与该镜像相关的所有变体。在前面的例子中，这些变体被标记为`buildroot-2013.08.1`、`ubuntu-14.04`、`ubuntu-12.04`、`buildroot-2014.02`和`latest`。对镜像 ID 的仔细观察将揭示`buildroot-2014.02`和`latest`共享镜像 ID`4986bf8c1536`。

默认情况下，Docker 始终使用标记为`latest`的镜像。每个镜像变体都可以通过其标签直接识别。可以通过在标签和存储库名称之间添加`:`来将镜像标记为合格。例如，您可以使用`busybox:ubuntu-14.04`标签启动一个容器，如下所示：

```
$ sudo docker run -t -i busybox:ubuntu-14.04

```

`docker pull`子命令将始终下载具有该存储库中`latest`标签的镜像变体。但是，如果您选择下载除最新版本之外的其他镜像变体，则可以通过使用以下命令来限定镜像的标签名称来执行此操作：

```
$ sudo docker pull busybox:ubuntu-14.04

```

## Docker Hub 注册表

在上一节中，当您运行`docker pull`子命令时，`busybox`镜像神秘地被下载了。在本节中，让我们揭开`docker pull`子命令周围的神秘，并且 Docker Hub 对这一意外成功做出了巨大贡献。

Docker 社区的热心人士已经构建了一个镜像存储库，并且已经将其公开放置在默认位置`index.docker.io`。这个默认位置称为 Docker 索引。`docker pull`子命令被编程为在此位置查找镜像。因此，当您`pull`一个`busybox`镜像时，它会轻松地从默认注册表中下载。这种机制有助于加快 Docker 容器的启动速度。Docker Index 是官方存储库，其中包含由全球 Docker 开发社区创建和存放的所有经过精心策划的镜像。

这所谓的治疗措施是为了确保存储在 Docker 索引中的所有镜像都通过一系列隔离任务是安全的。有经过验证和验证的方法来清理任何故意或无意引入的恶意软件、广告软件、病毒等等，从这些 Docker 镜像中。数字签名是 Docker 镜像的最高完整性的突出机制。然而，如果官方镜像已经被损坏或篡改，那么 Docker 引擎将发出警告，然后继续运行镜像。

除了官方存储库之外，Docker Hub 注册表还为第三方开发人员和提供商提供了一个平台，供他们共享供一般用户使用的镜像。第三方镜像以其开发人员或存款人的用户 ID 为前缀。例如，`thedockerbook/helloworld`是一个第三方镜像，其中`thedockerbook`是用户 ID，`helloworld`是镜像存储库名称。您可以使用`docker pull`子命令下载任何第三方镜像，如下所示：

```
$ sudo docker pull thedockerbook/helloworld

```

除了前面的存储库之外，Docker 生态系统还提供了一种利用来自 Docker Hub 注册表以外的任何第三方存储库中的镜像的机制，并且它还提供了本地存储库中托管的镜像。如前所述，Docker 引擎默认情况下已编程为在`index.docker.io`中查找镜像，而在第三方或本地存储库中，我们必须手动指定应从哪里拉取镜像的路径。手动存储库路径类似于没有协议说明符的 URL，例如`https://`、`http://`和`ftp://`。以下是从第三方存储库中拉取镜像的示例：

```
$ sudo docker pull registry.example.com/myapp

```

## 搜索 Docker 镜像

正如我们在前一节中讨论的，Docker Hub 存储库通常托管官方镜像以及由第三方 Docker 爱好者贡献的镜像。在撰写本书时，超过 14,000 个镜像（也称为 Docker 化应用程序）可供用户使用。这些镜像可以直接使用，也可以作为用户特定应用程序的构建块使用。

您可以使用`docker search`子命令在 Docker Hub 注册表中搜索 Docker 镜像，如本示例所示：

```
$ sudo docker search mysql

```

在`mysql`上的搜索将列出 400 多个镜像，如下所示：

```
NAME             DESCRIPTION          STARS  OFFICIAL   AUTOMATED
mysql            MySQL is the...      147    [OK]
tutum/mysql      MySQL Server..       60                [OK]
orchardup/mysql                       34                [OK]
. . . OUTPUT TRUNCATED . . .

```

如前面的搜索输出摘录所示，图像是根据其星级排序的。搜索结果还表明图像是否官方。为了保持专注，在这个例子中，我们将只显示两个图像。在这里，您可以看到`mysql`的官方版本，它拉取了一个`147`星级的图像作为其第一个结果。第二个结果显示，这个版本的`mysql`图像是由用户`tutum`发布的。Docker 容器正迅速成为分布式应用程序的标准构建块。借助全球许多社区成员的热情贡献，将实现 Docker 图像的动态存储库。基于存储库的软件工程将使用户和程序员更容易快速编写和组装他们的项目。官方存储库可以免费从 Docker Hub Registry 下载，这些是经过策划的图像。它们代表了一个专注于为应用程序提供良好图像基础的社区努力，以便开发人员和系统管理员可以专注于构建新功能和功能，同时最大程度地减少他们在商品脚手架和管道上的重复工作。

根据 Docker Hub Registry 中的搜索查询和与许多开发人员社区成员的讨论，Docker 公司强有力而充满激情地领导了 Docker 运动，得出结论，开发人员社区希望获得他们最喜爱的编程语言的预构建堆栈。具体来说，开发人员希望尽快开始编写代码，而不浪费时间与环境、脚手架和依赖进行斗争。

# 与交互式容器一起工作

在第一章中，我们运行了我们的第一个`Hello World!`容器，以了解容器化技术的工作原理。在本节中，我们将以交互模式运行一个容器。`docker run`子命令以镜像作为输入，并将其作为容器启动。您必须在 docker run 子命令中传递`-t`和`-i`标志，以使容器变为交互式。`-i`标志是关键驱动程序，它通过获取容器的标准输入（`STDIN`）使容器变得交互式。`-t`标志分配一个伪 TTY 或伪终端（终端仿真器），然后将其分配给容器。

在下面的示例中，我们将使用`ubuntu:14.04`镜像和`/bin/bash`作为命令启动一个交互式容器：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash

```

由于`ubuntu`镜像尚未下载，如果我们使用`docker pull`子命令，那么我们将收到以下消息，并且`run`命令将自动开始拉取`ubuntu`镜像，并显示以下消息：

```
Unable to find image 'ubuntu:14.04' locally
Pulling repository ubuntu

```

一旦下载完成，容器将与`ubuntu:14.04`镜像一起启动。它还将在容器内启动一个 bash shell，因为我们已指定`/bin/bash`作为要执行的命令。这将使我们进入一个 bash 提示符，如下所示：

```
root@742718c21816:/#

```

前面的 bash 提示将确认我们的容器已成功启动，并且准备好接受我们的输入。如果您对提示中的十六进制数字`742718c21816`感到困惑，那么它只是容器的主机名。在 Docker 术语中，主机名与容器`ID`相同。

让我们快速交互式地运行一些命令，然后确认我们之前提到的提示是正确的，如下所示：

```
root@742718c21816:/# hostname
742718c21816
root@742718c21816:/# id
uid=0(root) gid=0(root) groups=0(root)
root@742718c21816:/# echo $PS1
${debian_chroot:+($debian_chroot)}\u@\h:\w\$
root@742718c21816:/#

```

从前面的三个命令可以清楚地看出，提示是通过使用用户 ID、主机名和当前工作目录组成的。

现在，让我们使用 Docker 的一个特色功能，将其从交互式容器中分离出来，然后查看 Docker 为该容器管理的细节。是的，我们可以通过使用*Ctrl* + *P*和*Ctrl* + *Q*转义序列将其从容器中分离出来。这个转义序列将从容器中分离 TTY，并将我们置于 Docker 主机提示符`$`中，但是容器将继续运行。`docker ps`子命令将列出所有正在运行的容器及其重要属性，如下所示：

```
$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED              STATUS              PORTS               NAMES
742718c21816        ubuntu:14.04        "/bin/bash"         About a minute ago   Up About a minute                       jolly_lovelace

```

`docker ps`子命令将列出以下详细信息：

+   `容器 ID`：这显示了与容器关联的容器`ID`。容器`ID`是一个 64 位十六进制长随机数。默认情况下，`docker ps`子命令将只显示 12 位十六进制数。您可以使用`--no-trunc`标志显示所有 64 位数字（例如：`sudo docker ps --no-trunc`）。

+   `镜像`：这显示了 Docker 容器所制作的镜像。

+   `命令`：这显示了容器启动期间执行的命令。

+   `创建时间`：这告诉您容器何时创建。

+   `状态`：这告诉您容器的当前状态。

+   `PORTS`：这告诉你是否已经为容器分配了任何端口。

+   `NAMES`：Docker 引擎通过连接形容词和名词自动生成一个随机容器名称。容器的`ID`或名称都可以用来对容器进行进一步操作。容器名称可以通过在`docker run`子命令中使用`--name`选项手动配置。

查看了容器状态后，让我们使用`docker attach`子命令将其重新附加到我们的容器中，如下例所示。我们可以使用容器的`ID`或名称。在这个例子中，我们使用了容器的名称。如果你看不到提示符，那么再次按下*Enter*键：

```
$ sudo docker attach jolly_lovelace
root@742718c21816:/#

```

### 注意

Docker 允许任意次数地附加到容器，这对屏幕共享非常方便。

`docker attach`子命令将我们带回容器提示符。让我们使用这些命令对正在运行的交互式容器进行更多实验：

```
root@742718c21816:/# pwd
/
root@742718c21816:/# ls
bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
boot  etc  lib   media  opt  root  sbin  sys  usr
root@742718c21816:/# cd usr
root@742718c21816:/usr# ls
bin  games  include  lib  local  sbin  share  src
root@742718c21816:/usr# exit
exit
$

```

一旦对交互式容器发出 bash 退出命令，它将终止 bash shell 进程，进而停止容器。因此，我们将会回到 Docker 主机的提示符`$`。

## 在容器内跟踪更改

在上一节中，我们演示了如何以`ubuntu`为基础镜像创建容器，然后运行一些基本命令，比如分离和附加容器。在这个过程中，我们还向您介绍了`docker ps`子命令，它提供了基本的容器管理功能。在本节中，我们将演示如何有效地跟踪我们在容器中引入的更改，并将其与我们启动容器的镜像进行比较。

让我们以交互模式启动一个容器，就像在上一节中所做的那样：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash

```

让我们把目录切换到`/home`，如下所示：

```
root@d5ad60f174d3:/# cd /home

```

现在我们可以使用`touch`命令创建三个空文件，如下面的代码片段所示。第一个`ls -l`命令将显示目录中没有文件，第二个`ls -l`命令将显示有三个空文件：

```
root@d5ad60f174d3:/home# ls -l
total 0
root@d5ad60f174d3:/home# touch {abc,cde,fgh}
root@d5ad60f174d3:/home# ls -l
total 0
-rw-r--r-- 1 root root 0 Sep 29 10:54 abc
-rw-r--r-- 1 root root 0 Sep 29 10:54 cde
-rw-r--r-- 1 root root 0 Sep 29 10:54 fgh
root@d5ad60f174d3:/home#

```

Docker 引擎优雅地管理其文件系统，并允许我们使用`docker diff`子命令检查容器文件系统。为了检查容器文件系统，我们可以将其与容器分离，或者使用 Docker 主机的另一个终端，然后发出`docker diff`子命令。由于我们知道任何`ubuntu`容器都有其主机名，这是其提示的一部分，也是容器的`ID`，我们可以直接使用从提示中获取的容器`ID`运行`docker diff`子命令，如下所示：

```
$ sudo docker diff d5ad60f174d3

```

在给定的示例中，`docker diff`子命令将生成四行，如下所示：

```
C /home
A /home/abc
A /home/cde
A /home/fgh

```

前面的输出表明`/home`目录已被修改，这由`C,`表示，`/home/abc`，`/home/cde`和`/home/fgh`文件已被添加，这些由`A`表示。此外，`D`表示删除。由于我们没有删除任何文件，因此它不在我们的示例输出中。

## 控制 Docker 容器

到目前为止，我们已经讨论了一些实际示例，以清楚地阐明 Docker 容器的细枝末节。在本节中，让我们介绍一些基本的以及一些高级的命令结构，以精确地说明如何管理 Docker 容器。

Docker 引擎使您能够使用一组`docker`子命令`start`，`stop`和`restart`容器。让我们从`docker stop`子命令开始，该子命令停止正在运行的容器。当用户发出此命令时，Docker 引擎向容器内运行的主进程发送 SIGTERM（-15）。**SIGTERM**信号请求进程优雅地终止自身。大多数进程会处理此信号并促进优雅退出。但是，如果此进程未能这样做，那么 Docker 引擎将等待一段宽限期。即使在宽限期之后，如果进程未被终止，那么 Docker 引擎将强制终止该进程。通过发送 SIGKILL（-9）来实现强制终止。**SIGKILL**信号无法被捕获或忽略，因此它将导致进程在没有适当清理的情况下突然终止。

现在，让我们启动我们的容器，并尝试使用`docker stop`子命令，如下所示：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash
root@da1c0f7daa2a:/#

```

启动容器后，让我们使用从提示中获取的容器`ID`在该容器上运行`docker stop`子命令。当然，我们必须使用第二个屏幕或终端来运行此命令，命令将始终回显到容器`ID`，如下所示：

```
$ sudo docker stop da1c0f7daa2a
da1c0f7daa2a

```

现在，如果我们切换到正在运行容器的屏幕或终端，我们将注意到容器正在被终止。如果你更仔细观察，你还会注意到容器提示旁边的文本`exit`。这是由于 bash shell 的 SIGTERM 处理机制导致的，如下所示：

```
root@da1c0f7daa2a:/# exit
$

```

如果我们再进一步运行`docker ps`子命令，那么我们将在列表中找不到这个容器。事实上，默认情况下，`docker ps`子命令总是列出处于运行状态的容器。由于我们的容器处于停止状态，它已经舒适地被从列表中排除了。现在，你可能会问，我们如何看到处于停止状态的容器呢？好吧，`docker ps`子命令带有一个额外的参数`-a`，它将列出 Docker 主机中的所有容器，而不管它的状态如何。可以通过运行以下命令来实现：

```
$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                CREATED             STATUS                      PORTS               NAMES
da1c0f7daa2a        ubuntu:14.04        "/bin/bash"            20 minutes ago        Exited (0) 10 minutes ago                        desperate_engelbart
$

```

接下来，让我们看看`docker start`子命令，它用于启动一个或多个已停止的容器。容器可以通过`docker stop`子命令或正常或异常地终止容器中的主进程而被移动到停止状态。对于正在运行的容器，此子命令没有任何效果。

让我们使用`docker start`子命令`start`先前停止的容器，如下所示：

```
$ sudo docker start da1c0f7daa2a
da1c0f7daa2a
$

```

默认情况下，`docker start`子命令不会附加到容器。您可以通过在`docker start`子命令中使用`-a`选项或显式使用`docker attach`子命令将其附加到容器，如下所示：

```
$ sudo docker attach da1c0f7daa2a
root@da1c0f7daa2a:/#

```

现在让我们运行`docker ps`并验证容器的运行状态，如下所示：

```
$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND                CREATED             STATUS                      PORTS               NAMES
da1c0f7daa2a        ubuntu:14.04        "/bin/bash"            25 minutes ago        Up 3 minutes                        desperate_engelbart
$

```

`restart`命令是`stop`和`start`功能的组合。换句话说，`restart`命令将通过`docker stop`子命令遵循的精确步骤`stop`一个正在运行的容器，然后它将启动`start`过程。此功能将默认通过`docker restart`子命令执行。

下一个重要的容器控制子命令集是`docker pause`和`docker unpause`。`docker pause`子命令将基本上冻结容器中所有进程的执行。相反，`docker unpause`子命令将解冻容器中所有进程的执行，并从冻结的点恢复执行。

在看完`pause`和`unpause`的技术解释后，让我们看一个详细的示例来说明这个功能是如何工作的。我们使用了两个屏幕或终端场景。在一个终端上，我们启动了容器，并使用了一个无限循环来显示日期和时间，每隔 5 秒睡眠一次，然后继续循环。我们将运行以下命令：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash
root@c439077aa80a:/# while true; do date; sleep 5; done
Thu Oct  2 03:11:19 UTC 2014
Thu Oct  2 03:11:24 UTC 2014
Thu Oct  2 03:11:29 UTC 2014
Thu Oct  2 03:11:34 UTC 2014
Thu Oct  2 03:11:59 UTC 2014
Thu Oct  2 03:12:04 UTC 2014
Thu Oct  2 03:12:09 UTC 2014
Thu Oct  2 03:12:14 UTC 2014
Thu Oct  2 03:12:19 UTC 2014
Thu Oct  2 03:12:24 UTC 2014
Thu Oct  2 03:12:29 UTC 2014
Thu Oct  2 03:12:34 UTC 2014
$

```

我们的小脚本非常忠实地每 5 秒打印一次日期和时间，但在以下位置有一个例外：

```
Thu Oct  2 03:11:34 UTC 2014
Thu Oct  2 03:11:59 UTC 2014

```

在这里，我们遇到了 25 秒的延迟，因为这是我们在第二个终端屏幕上启动了`docker pause`子命令的时候，如下所示：

```
$ sudo docker pause c439077aa80a
c439077aa80a

```

当我们暂停容器时，我们使用`docker ps`子命令查看了容器上的进程状态，它在同一屏幕上，并清楚地指示容器已被暂停，如此命令结果所示：

```
$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                   PORTS               NAMES
c439077aa80a        ubuntu:14.04        "/bin/bash"         47 seconds ago      Up 46 seconds (Paused)                       ecstatic_torvalds

```

我们继续使用`docker unpause`子命令，解冻了我们的容器，继续执行，并开始打印日期和时间，就像我们在前面的命令中看到的那样，如下所示：

```
$ sudo docker unpause c439077aa80a
c439077aa80a

```

我们在本节开始时解释了`pause`和`unpause`命令。最后，使用`docker stop`子命令停止了容器和其中运行的脚本，如下所示：

```
$ sudo docker stop c439077aa80a
c439077aa80a

```

## 容器清理

在许多先前的示例中，当我们发出`docker ps -a`时，我们看到了许多已停止的容器。如果我们选择不进行干预，这些容器可能会继续停留在停止状态很长时间。起初，这可能看起来像是一个故障，但实际上，我们可以执行操作，比如从容器中提交一个镜像，重新启动已停止的容器等。然而，并非所有已停止的容器都会被重用，每个未使用的容器都会占用 Docker 主机文件系统中的磁盘空间。Docker 引擎提供了几种方法来缓解这个问题。让我们开始探索它们。

在容器启动期间，我们可以指示 Docker 引擎在容器达到停止状态时立即清理容器。为此，`docker run`子命令支持`--rm`选项（例如：`sudo docker run -i -t --rm ubuntu:14.04 /bin/bash`）。

另一种选择是使用`docker ps`子命令的`-a`选项列出所有容器，然后通过使用`docker rm`子命令手动删除它们，如下所示：

```
$ sudo docker ps -a
CONTAINER ID IMAGE        COMMAND     CREATED       STATUS
                   PORTS   NAMES
7473f2568add ubuntu:14.04 "/bin/bash" 5 seconds ago Exited(0) 3 seconds ago         jolly_wilson
$ sudo docker rm 7473f2568add
7473f2568add
$

```

两个`docker`子命令，即`docker rm`和`docker ps`，可以组合在一起自动删除所有当前未运行的容器，如下命令所示：

```
$ sudo docker rm 'sudo docker ps -aq --no-trunc'

```

在上述命令中，反引号内的命令将产生每个容器的完整容器 ID 列表，无论是运行还是其他状态，这将成为`docker rm`子命令的参数。除非使用`-f`选项强制执行其他操作，否则`docker rm`子命令将仅删除未运行状态的容器。对于正在运行的容器，它将生成以下错误，然后继续到列表中的下一个容器：

```
Error response from daemon: You cannot remove a running container. Stop the container before attempting removal or use -f

```

## 从容器构建镜像

到目前为止，我们已经使用标准基本镜像`busybox`和`ubuntu`创建了一些容器。在本节中，让我们看看如何在运行的容器中向基本镜像添加更多软件，然后将该容器转换为镜像以供将来使用。

让我们以`ubuntu:14.04`作为基本镜像，安装`wget`应用程序，然后通过以下步骤将运行的容器转换为镜像：

1.  通过使用以下`docker run`子命令启动`ubuntu:14.04`容器，如下所示：

```
$ sudo docker run -i -t ubuntu:14.04 /bin/bash

```

1.  启动容器后，让我们快速验证我们的镜像中是否有`wget`可用。我们已经使用`which`命令并将`wget`作为参数用于此目的，在我们的情况下，它返回空值，这基本上意味着它在这个容器中找不到任何`wget`安装。该命令如下运行：

```
root@472c96295678:/# which wget
root@472c96295678:/#

```

1.  现在让我们继续下一步，涉及`wget`安装。由于这是一个全新的`ubuntu`容器，在安装`wget`之前，我们必须与`ubuntu`软件包存储库同步，如下所示：

```
root@472c96295678:/# apt-get update

```

1.  一旦`ubuntu`软件包存储库同步完成，我们可以继续安装`wget`，如下所示：

```
root@472c96295678:/# apt-get install -y wget

```

1.  完成`wget`安装后，让我们通过调用`which`命令并将`wget`作为参数来确认我们的`wget`安装，如下所示：

```
root@472c96295678:/#which wget
/usr/bin/wget
root@472c96295678:/#

```

1.  安装任何软件都会改变基础镜像的组成，我们也可以通过本章节*跟踪容器内部变化*介绍的`docker diff`子命令来追踪这些变化。我们可以在第二个终端或屏幕上使用`docker diff`子命令，如下所示：

```
$ sudo docker diff 472c96295678

```

前面的命令将显示对`ubuntu`镜像的几百行修改。这些修改包括软件包存储库的更新，`wget`二进制文件以及`wget`的支持文件。

1.  最后，让我们转向提交镜像的最重要步骤。Docker `commit`子命令可以在运行或停止的容器上执行。当在运行容器上执行`commit`时，Docker 引擎将在`commit`操作期间暂停容器，以避免任何数据不一致。我们强烈建议在停止的容器上执行`commit`操作。我们可以通过`docker commit`子命令将容器提交为镜像，如下所示：

```
$ sudo docker commit 472c96295678 \
 learningdocker/ubuntu_wget
a530f0a0238654fa741813fac39bba2cc14457aee079a7ae1fe1c64dc7e1ac25

```

我们已经使用名称`learningdocker/ubuntu_wget`提交了我们的镜像。

我们逐步看到了如何从容器创建镜像。现在，让我们快速列出我们的 Docker 主机上的镜像，并使用以下命令查看这个新创建的镜像是否是镜像列表的一部分：

```
$ sudo docker images
REPOSITORY                      TAG                 IMAGE ID            CREATED             VIRTUAL SIZE
learningdocker/ubuntu_wget   latest              a530f0a02386        48 seconds ago      221.3 MB
busybox                         buildroot-2014.02   e72ac664f4f0        2 days ago          2.433 MB
ubuntu                          14.04               6b4e8a7373fe        2 days ago          194.8 MB

```

从前面的`docker images`子命令输出中，很明显我们从容器创建的镜像非常成功。

现在您已经学会了如何通过几个简单的步骤从容器创建镜像，我们鼓励您主要使用这种方法进行测试。创建镜像的最优雅和最推荐的方法是使用`Dockerfile`方法，这将在下一章介绍。

## 作为守护进程启动容器

我们已经尝试过交互式容器，跟踪了对容器的更改，从容器创建了镜像，然后深入了解了容器化范式。现在，让我们继续了解 Docker 技术的真正工作马。是的，没错。在本节中，我们将为您介绍启动容器的步骤，以分离模式启动容器的步骤。换句话说，我们将了解启动容器作为守护进程所需的步骤。我们还将查看在容器中生成的文本。

`docker run`子命令支持一个选项`-d`，它将以分离模式启动一个容器，也就是说，它将以守护进程的方式启动一个容器。为了举例说明，让我们回到我们在“暂停和恢复”容器示例中使用的日期和时间脚本，如下所示：

```
$ sudo docker run -d ubuntu \
 /bin/bash -c "while true; do date; sleep 5; done"
0137d98ee363b44f22a48246ac5d460c65b67e4d7955aab6cbb0379ac421269b

```

`docker logs`子命令用于查看守护进程容器生成的输出，如下所示：

```
$ sudo docker logs \
0137d98ee363b44f22a48246ac5d460c65b67e4d7955aab6cbb0379ac421269b
Sat Oct  4 17:41:04 UTC 2014
Sat Oct  4 17:41:09 UTC 2014
Sat Oct  4 17:41:14 UTC 2014
Sat Oct  4 17:41:19 UTC 2014

```

# 总结

在本章中，我们描述了在后期实施阶段获得的知识，主要是关于 Docker 容器的操作方面。我们通过澄清重要术语（如镜像、容器、注册表和仓库）来开始本章，以便让您能够清晰地理解随后阐述的概念。我们解释了如何在 Docker 仓库中搜索镜像。我们还讨论了 Docker 容器的操作和处理，如何跟踪容器内部的更改，如何控制和维护容器。在下一章中，我们将以易于理解的方式解释 Docker 镜像构建的过程。


# 第三章：构建镜像

在上一章中，我们详细向您解释了镜像和容器处理以及其维护技巧和提示。除此之外，我们还解释了在 Docker 容器上安装任何软件包的标准过程，然后将容器转换为镜像以供将来使用和操作。本章与之前的章节非常不同，它清楚地描述了如何使用`Dockerfile`构建 Docker 镜像的标准方式，这是为软件开发社区提供高度可用的 Docker 镜像的最有力的方式。利用`Dockerfile`是构建强大镜像的最有竞争力的方式。

本章将涵盖以下主题：

+   Docker 集成的镜像构建系统

+   Dockerfile 的语法快速概述

+   `Dockerfile`构建指令

+   Docker 如何存储镜像

# Docker 集成的镜像构建系统

Docker 镜像是容器的基本构建模块。这些镜像可以是非常基本的操作环境，比如我们在前几章中使用 Docker 进行实验时发现的`busybox`或`ubuntu`。另外，这些镜像也可以构建用于企业和云 IT 环境的高级应用程序堆栈。正如我们在上一章中讨论的，我们可以通过从基础镜像启动容器，安装所有所需的应用程序，进行必要的配置文件更改，然后将容器提交为镜像来手动制作镜像。

作为更好的选择，我们可以采用使用`Dockerfile`自动化方法来制作镜像。`Dockerfile`是一个基于文本的构建脚本，其中包含了一系列特殊指令，用于从基础镜像构建正确和相关的镜像。`Dockerfile`中的顺序指令可以包括基础镜像选择、安装所需应用程序、添加配置和数据文件，以及自动运行服务并将这些服务暴露给外部世界。因此，基于 Dockerfile 的自动化构建系统简化了镜像构建过程。它还在构建指令的组织方式和可视化完整构建过程的方式上提供了很大的灵活性。

Docker 引擎通过`docker build`子命令紧密集成了这个构建过程。在 Docker 的客户端-服务器范式中，Docker 服务器（或守护程序）负责完整的构建过程，Docker 命令行界面负责传输构建上下文，包括将`Dockerfile`传输到守护程序。

为了窥探本节中`Dockerfile`集成构建系统，我们将向您介绍一个基本的`Dockerfile`。然后我们将解释将该`Dockerfile`转换为图像，然后从该图像启动容器的步骤。我们的`Dockerfile`由两条指令组成，如下所示：

```
$ cat Dockerfile
FROM busybox:latest
CMD echo Hello World!!

```

接下来，我们将讨论前面提到的两条指令：

+   第一条指令是选择基础图像。在这个例子中，我们将选择`busybox:latest`图像

+   第二条指令是执行`CMD`命令，指示容器`echo Hello World!!`。

现在，让我们通过调用`docker build`以及`Dockerfile`的路径来生成一个 Docker 图像。在我们的例子中，我们将从存储`Dockerfile`的目录中调用`docker build`子命令，并且路径将由以下命令指定：

```
$ sudo docker build .

```

发出上述命令后，`build`过程将通过将`build context`发送到`daemon`并显示以下文本开始：

```
Sending build context to Docker daemon 3.072 kB
Sending build context to Docker daemon
Step 0 : from busybox:latest

```

构建过程将继续，并在完成后显示以下内容：

```
Successfully built 0a2abe57c325

```

在前面的例子中，图像是由`IMAGE ID 0a2abe57c325`构建的。让我们使用这个图像通过使用`docker run`子命令来启动一个容器，如下所示：

```
$ sudo docker run 0a2abe57c325
Hello World!!

```

很酷，不是吗？凭借极少的努力，我们已经能够制作一个以`busybox`为基础图像，并且能够扩展该图像以生成`Hello World!!`。这是一个简单的应用程序，但是使用相同的技术也可以实现企业规模的图像。

现在让我们使用`docker images`子命令来查看图像的详细信息，如下所示：

```
$ sudo docker images
REPOSITORY     TAG         IMAGE ID      CREATED       VIRTUAL SIZE
<none>       <none>       0a2abe57c325    2 hours ago    2.433 MB

```

在这里，你可能会惊讶地看到`IMAGE`（`REPOSITORY`）和`TAG`名称被列为`<none>`。这是因为当我们构建这个图像时，我们没有指定任何图像或任何`TAG`名称。你可以使用`docker tag`子命令指定一个`IMAGE`名称和可选的`TAG`名称，如下所示：

```
$ sudo docker tag 0a2abe57c325 busyboxplus

```

另一种方法是在`build`时使用`-t`选项为`docker build`子命令构建镜像名称，如下所示：

```
$ sudo docker build -t busyboxplus .

```

由于`Dockerfile`中的指令没有变化，Docker 引擎将高效地重用具有`ID 0a2abe57c325`的旧镜像，并将镜像名称更新为`busyboxplus`。默认情况下，构建系统会将`latest`作为`TAG`名称。可以通过在`IMAGE`名称之后指定`TAG`名称并在它们之间放置`:`分隔符来修改此行为。也就是说，`<image name>:<tag name>`是修改行为的正确语法，其中`<image name>`是镜像的名称，`<tag name>`是标签的名称。

再次使用`docker images`子命令查看镜像详细信息，您会注意到镜像（存储库）名称为`busyboxplus`，标签名称为`latest`：

```
$ sudo docker images
REPOSITORY     TAG         IMAGE ID      CREATED       VIRTUAL SIZE
busyboxplus     latest       0a2abe57c325    2 hours ago    2.433 MB

```

始终建议使用镜像名称构建镜像是最佳实践。

在体验了`Dockerfile`的魔力之后，我们将在随后的章节中向您介绍`Dockerfile`的语法或格式，并解释一打`Dockerfile`指令。

### 注意

最新的 Docker 发布版（1.5）在`docker build`子命令中增加了一个额外选项（`-f`），用于指定具有替代名称的`Dockerfile`。

# Dockerfile 的语法快速概述

在本节中，我们将解释`Dockerfile`的语法或格式。`Dockerfile`由指令、注释和空行组成，如下所示：

```
# Comment

INSTRUCTION arguments
```

`Dockerfile`的指令行由两个组件组成，指令行以指令本身开头，后面跟着指令的参数。指令可以以任何大小写形式编写，换句话说，它是不区分大小写的。然而，标准做法或约定是使用*大写*以便与参数区分开来。让我们再次看一下我们之前示例中的`Dockerfile`的内容：

```
FROM busybox:latest
CMD echo Hello World!!
```

这里，`FROM`是一个指令，它以`busybox:latest`作为参数，`CMD`是一个指令，它以`echo Hello World!!`作为参数。

`Dockerfile` 中的注释行必须以 `#` 符号开头。指令后的 `#` 符号被视为参数。如果 `#` 符号前面有空格，则 `docker build` 系统将视其为未知指令并跳过该行。现在，让我们通过一个示例更好地理解这些情况，以更好地理解注释行：

+   有效的 `Dockerfile` 注释行始终以 `#` 符号作为行的第一个字符：

```
# This is my first Dockerfile comment
```

+   `#` 符号可以作为参数的一部分：

```
CMD echo ### Welcome to Docker ###
```

+   如果 `#` 符号前面有空格，则构建系统将其视为未知指令：

```
    # this is an invalid comment line
```

`docker build` 系统会忽略 `Dockerfile` 中的空行，因此鼓励 `Dockerfile` 的作者添加注释和空行，以大大提高 `Dockerfile` 的可读性。

# Dockerfile 构建指令

到目前为止，我们已经看过集成构建系统、`Dockerfile` 语法和一个示例生命周期，包括如何利用示例 `Dockerfile` 生成镜像以及如何从该镜像中生成容器。在本节中，我们将介绍 `Dockerfile` 指令、它们的语法以及一些合适的示例。

## FROM 指令

`FROM` 指令是最重要的指令，也是 `Dockerfile` 的第一个有效指令。它设置了构建过程的基础镜像。随后的指令将使用这个基础镜像并在其上构建。`docker build` 系统允许您灵活地使用任何人构建的镜像。您还可以通过添加更精确和实用的功能来扩展它们。默认情况下，`docker build` 系统在 Docker 主机中查找镜像。但是，如果在 Docker 主机中找不到镜像，则 `docker build` 系统将从公开可用的 Docker Hub Registry 拉取镜像。如果 `docker build` 系统在 Docker 主机和 Docker Hub Registry 中找不到指定的镜像，则会返回错误。

`FROM` 指令具有以下语法：

```
FROM <image>[:<tag>]
```

在上述代码语句中，请注意以下内容：

+   `<image>`：这是将用作基础镜像的镜像的名称。

+   `<tag>`：这是该镜像的可选标签限定符。如果未指定任何标签限定符，则假定为标签 `latest`。

以下是使用镜像名称 `centos` 的 `FROM` 指令的示例：

```
FROM centos
```

以下是带有镜像名称`ubuntu`和标签限定符`14.04`的`FROM`指令的另一个示例：

```
FROM ubuntu:14.04
```

Docker 允许在单个`Dockerfile`中使用多个`FROM`指令以创建多个镜像。Docker 构建系统将拉取`FROM`指令中指定的所有镜像。Docker 不提供对使用多个`FROM`指令生成的各个镜像进行命名的任何机制。我们强烈不建议在单个`Dockerfile`中使用多个`FROM`指令，因为可能会产生破坏性的冲突。

## MAINTAINER 指令

`MAINTAINER`指令是`Dockerfile`的信息指令。此指令能力使作者能够在镜像中设置详细信息。Docker 不对在`Dockerfile`中放置`MAINTAINER`指令施加任何限制。但强烈建议您在`FROM`指令之后放置它。

以下是`MAINTAINER`指令的语法，其中`<author's detail>`可以是任何文本。但强烈建议您使用镜像作者的姓名和电子邮件地址，如此代码语法所示：

```
MAINTAINER <author's detail>
```

以下是带有作者姓名和电子邮件地址的`MAINTAINER`指令的示例：

```
MAINTAINER Dr. Peter <peterindia@gmail.com>
```

## `COPY`指令

`COPY`指令使您能够将文件从 Docker 主机复制到新镜像的文件系统中。以下是`COPY`指令的语法：

```
COPY <src> ... <dst>
```

前面的代码术语包含了这里显示的解释：

+   `<src>`：这是源目录，构建上下文中的文件，或者是执行`docker build`子命令的目录。

+   `...`：这表示可以直接指定多个源文件，也可以通过通配符指定多个源文件。

+   `<dst>`：这是新镜像的目标路径，源文件或目录将被复制到其中。如果指定了多个文件，则目标路径必须是目录，并且必须以斜杠`/`结尾。

推荐为目标目录或文件使用绝对路径。如果没有绝对路径，`COPY`指令将假定目标路径将从根目录`/`开始。`COPY`指令足够强大，可以用于创建新目录，并覆盖新创建的镜像中的文件系统。

在下面的示例中，我们将使用`COPY`指令将源构建上下文中的`html`目录复制到镜像文件系统中的`/var/www/html`，如下所示：

```
COPY html /var/www/html
```

这是另一个示例，多个文件（`httpd.conf`和`magic`）将从源构建上下文复制到镜像文件系统中的`/etc/httpd/conf/`：

```
COPY httpd.conf magic /etc/httpd/conf/
```

## ADD 指令

`ADD`指令类似于`COPY`指令。但是，除了`COPY`指令支持的功能之外，`ADD`指令还可以处理 TAR 文件和远程 URL。我们可以将`ADD`指令注释为“功能更强大的 COPY”。

以下是`ADD`指令的语法：

```
ADD <src> ... <dst>
```

`ADD`指令的参数与`COPY`指令的参数非常相似，如下所示：

+   `<src>`：这既可以是构建上下文中的源目录或文件，也可以是`docker build`子命令将被调用的目录中的文件。然而，值得注意的区别是，源可以是存储在构建上下文中的 TAR 文件，也可以是远程 URL。

+   `...`：这表示多个源文件可以直接指定，也可以使用通配符指定。

+   `<dst>`：这是新镜像的目标路径，源文件或目录将被复制到其中。

这是一个示例，演示了将多个源文件复制到目标镜像文件系统中的各个目标目录的过程。在此示例中，我们在源构建上下文中使用了一个 TAR 文件（`web-page-config.tar`），其中包含`http`守护程序配置文件和网页文件的目录结构，如下所示：

```
$ tar tf web-page-config.tar
etc/httpd/conf/httpd.conf
var/www/html/index.html
var/www/html/aboutus.html
var/www/html/images/welcome.gif
var/www/html/images/banner.gif

```

`Dockerfile`内容中的下一行包含一个`ADD`指令，用于将 TAR 文件（`web-page-config.tar`）复制到目标镜像，并从目标镜像的根目录（`/`）中提取 TAR 文件，如下所示：

```
ADD web-page-config.tar /

```

因此，`ADD`指令的 TAR 选项可用于将多个文件复制到目标镜像。

## ENV 指令

`ENV`指令在新镜像中设置环境变量。环境变量是键值对，可以被任何脚本或应用程序访问。Linux 应用程序在启动配置中经常使用环境变量。

以下一行形成了`ENV`指令的语法：

```
ENV <key> <value>
```

在这里，代码术语表示以下内容：

+   `<key>`：这是环境变量

+   `<value>`：这是要设置为环境变量的值

以下几行给出了`ENV`指令的两个示例，在第一行中，`DEBUG_LVL`已设置为`3`，在第二行中，`APACHE_LOG_DIR`已设置为`/var/log/apache`：

```
ENV DEBUG_LVL 3
ENV APACHE_LOG_DIR /var/log/apache
```

## USER 指令

`USER`指令设置新镜像中的启动用户 ID 或用户名。默认情况下，容器将以`root`作为用户 ID 或`UID`启动。实质上，`USER`指令将把默认用户 ID 从`root`修改为此指令中指定的用户 ID。

`USER`指令的语法如下：

```
USER <UID>|<UName>
```

`USER`指令接受`<UID>`或`<UName>`作为其参数：

+   `<UID>`：这是一个数字用户 ID

+   `<UName>`：这是一个有效的用户名

以下是一个示例，用于在启动时将默认用户 ID 设置为`73`。这里`73`是用户的数字 ID：

```
USER 73
```

但是，建议您拥有一个与`/etc/passwd`文件匹配的有效用户 ID，用户 ID 可以包含任意随机数值。但是，用户名必须与`/etc/passwd`文件中的有效用户名匹配，否则`docker run`子命令将失败，并显示以下错误消息：

```
finalize namespace setup user get supplementary groups Unable to find user

```

## WORKDIR 指令

`WORKDIR`指令将当前工作目录从`/`更改为此指令指定的路径。随后的指令，如`RUN`、`CMD`和`ENTRYPOINT`也将在`WORKDIR`指令设置的目录上工作。

以下一行提供了`WORKDIR`指令的适当语法：

```
WORKDIR <dirpath>
```

在这里，`<dirpath>`是要设置的工作目录的路径。路径可以是绝对路径或相对路径。在相对路径的情况下，它将相对于`WORKDIR`指令设置的上一个路径。如果在目标镜像文件系统中找不到指定的目录，则将创建该目录。

以下一行是`Dockerfile`中`WORKDIR`指令的一个明确示例：

```
WORKDIR /var/log
```

## VOLUME 指令

`VOLUME`指令在镜像文件系统中创建一个目录，以后可以用于从 Docker 主机或其他容器挂载卷。

`VOLUME`指令有两种语法，如下所示：

+   第一种类型是 exec 或 JSON 数组（所有值必须在双引号（`"`）内）：

```
VOLUME ["<mountpoint>"]
```

+   第二种类型是 shell，如下所示：

```
VOLUME <mountpoint>
```

在前一行中，`<mountpoint>`是必须在新镜像中创建的挂载点。

## EXPOSE 指令

`EXPOSE`指令打开容器网络端口，用于容器与外部世界之间的通信。

`EXPOSE`指令的语法如下：

```
EXPOSE <port>[/<proto>] [<port>[/<proto>]...]
```

在这里，代码术语的含义如下：

+   `<port>`：这是要向外部世界暴露的网络端口。

+   `<proto>`：这是一个可选字段，用于指定特定的传输协议，如 TCP 和 UDP。如果未指定传输协议，则假定 TCP 为传输协议。

`EXPOSE`指令允许您在一行中指定多个端口。

以下是`Dockerfile`中`EXPOSE`指令的示例，将端口号`7373`暴露为`UDP`端口，端口号`8080`暴露为`TCP`端口。如前所述，如果未指定传输协议，则假定`TCP`传输协议为传输协议：

```
EXPOSE 7373/udp 8080
```

## RUN 指令

`RUN`指令是构建时的真正工作马，它可以运行任何命令。一般建议使用一个`RUN`指令执行多个命令。这样可以减少生成的 Docker 镜像中的层，因为 Docker 系统固有地为`Dockerfile`中每次调用指令创建一个层。

`RUN`指令有两种语法类型：

+   第一种是 shell 类型，如下所示：

```
RUN <command>
```

在这里，`<command>`是在构建时必须执行的 shell 命令。如果要使用这种类型的语法，那么命令总是使用`/bin/sh -c`来执行。

+   第二种语法类型要么是 exec，要么是 JSON 数组，如下所示：

```
RUN ["<exec>", "<arg-1>", ..., "<arg-n>"]
```

在其中，代码术语的含义如下：

+   `<exec>`：这是在构建时要运行的可执行文件。

+   `<arg-1>, ..., <arg-n>`：这些是可执行文件的参数（零个或多个）。

与第一种语法不同，这种类型不会调用`/bin/sh -c`。因此，这种类型不会发生 shell 处理，如变量替换（`$USER`）和通配符替换（`*`，`?`）。如果 shell 处理对您很重要，那么建议您使用 shell 类型。但是，如果您仍然更喜欢 exec（JSON 数组类型），那么请使用您喜欢的 shell 作为可执行文件，并将命令作为参数提供。

例如，`RUN ["bash", "-c", "rm", "-rf", "/tmp/abc"]`。

现在让我们看一下`RUN`指令的一些示例。在第一个示例中，我们将使用`RUN`指令将问候语添加到目标图像文件系统的`.bashrc`文件中，如下所示：

```
RUN echo "echo Welcome to Docker!" >> /root/.bashrc
```

第二个示例是一个`Dockerfile`，其中包含在`Ubuntu 14.04`基础镜像上构建`Apache2`应用程序镜像的指令。接下来的步骤将逐行解释`Dockerfile`指令：

1.  我们将使用`FROM`指令构建一个以`ubuntu:14.04`为基础镜像的镜像，如下所示：

```
###########################################
# Dockerfile to build an Apache2 image
###########################################
# Base image is Ubuntu
FROM ubuntu:14.04
```

1.  通过使用`MAINTAINER`指令设置作者的详细信息，如下所示：

```
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
```

1.  通过一个`RUN`指令，我们将同步`apt`存储库源列表，安装`apache2`软件包，然后清理检索到的文件，如下所示：

```
# Install apache2 package
RUN apt-get update && \
   apt-get install -y apache2 && \
   apt-get clean
```

## CMD 指令

`CMD`指令可以运行任何命令（或应用程序），类似于`RUN`指令。但是，这两者之间的主要区别在于执行时间。通过`RUN`指令提供的命令在构建时执行，而通过`CMD`指令指定的命令在从新创建的镜像启动容器时执行。因此，`CMD`指令为此容器提供了默认执行。但是，可以通过`docker run`子命令参数进行覆盖。应用程序终止时，容器也将终止，并且应用程序与之相反。

`CMD`指令有三种语法类型，如下所示：

+   第一种语法类型是 shell 类型，如下所示：

```
CMD <command>
```

在其中，`<command>`是 shell 命令，在容器启动时必须执行。如果使用此类型的语法，则始终使用`/bin/sh -c`执行命令。

+   第二种语法类型是 exec 或 JSON 数组，如下所示：

```
CMD ["<exec>", "<arg-1>", ..., "<arg-n>"]
```

在其中，代码术语的含义如下：

+   `<exec>`：这是要在容器启动时运行的可执行文件。

+   `<arg-1>, ..., <arg-n>`：这些是可执行文件的参数的变量（零个或多个）数字。

+   第三种语法类型也是 exec 或 JSON 数组，类似于前一种类型。但是，此类型用于将默认参数设置为`ENTRYPOINT`指令，如下所示：

```
CMD ["<arg-1>", ..., "<arg-n>"]
```

在其中，代码术语的含义如下：

+   `<arg-1>, ..., <arg-n>`：这些是`ENTRYPOINT`指令的变量（零个或多个）数量的参数，将在下一节中解释。

从语法上讲，你可以在`Dockerfile`中添加多个`CMD`指令。然而，构建系统会忽略除最后一个之外的所有`CMD`指令。换句话说，在多个`CMD`指令的情况下，只有最后一个`CMD`指令会生效。

在这个例子中，让我们使用`Dockerfile`和`CMD`指令来制作一个镜像，以提供默认执行，然后使用制作的镜像启动一个容器。以下是带有`CMD`指令的`Dockerfile`，用于`echo`一段文本：

```
########################################################
# Dockerfile to demonstrate the behaviour of CMD
########################################################
# Build from base image busybox:latest
FROM busybox:latest
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# Set command for CMD
CMD ["echo", "Dockerfile CMD demo"]
```

现在，让我们使用`docker build`子命令和`cmd-demo`作为镜像名称来构建一个 Docker 镜像。`docker build`系统将从当前目录（`.`）中读取`Dockerfile`中的指令，并相应地制作镜像，就像这里所示的那样：

```
$ sudo docker build -t cmd-demo .

```

构建了镜像之后，我们可以使用`docker run`子命令来启动容器，就像这里所示的那样：

```
$ sudo docker run cmd-demo
Dockerfile CMD demo

```

很酷，不是吗？我们为容器提供了默认执行，并且我们的容器忠实地回显了`Dockerfile CMD demo`。然而，这个默认执行可以很容易地被通过将另一个命令作为参数传递给`docker run`子命令来覆盖，就像下面的例子中所示：

```
$ sudo docker run cmd-demo echo Override CMD demo
Override CMD demo

```

## ENTRYPOINT 指令

`ENTRYPOINT`指令将帮助制作一个镜像，用于在容器的整个生命周期中运行一个应用程序（入口点），该应用程序将从镜像中衍生出来。当入口点应用程序终止时，容器也将随之终止，应用程序与容器相互关联。因此，`ENTRYPOINT`指令会使容器的功能类似于可执行文件。从功能上讲，`ENTRYPOINT`类似于`CMD`指令，但两者之间的主要区别在于入口点应用程序是通过`ENTRYPOINT`指令启动的，无法通过`docker run`子命令参数来覆盖。然而，这些`docker run`子命令参数将作为额外的参数传递给入口点应用程序。话虽如此，Docker 提供了通过`docker run`子命令中的`--entrypoint`选项来覆盖入口点应用程序的机制。`--entrypoint`选项只能接受一个单词作为其参数，因此其功能有限。

从语法上讲，`ENTRYPOINT`指令与`RUN`和`CMD`指令非常相似，它有两种语法，如下所示：

+   第一种语法是 shell 类型，如下所示：

```
ENTRYPOINT <command>
```

在这里，`<command>`是在容器启动时执行的 shell 命令。如果使用这种类型的语法，则始终使用`/bin/sh -c`执行命令。

+   第二种语法是 exec 或 JSON 数组，如下所示：

```
ENTRYPOINT ["<exec>", "<arg-1>", ..., "<arg-n>"]
```

在这里，代码术语的含义如下：

+   `<exec>`：这是在容器启动时必须运行的可执行文件。

+   `<arg-1>, ..., <arg-n>`：这些是可执行文件的变量（零个或多个）参数。

从语法上讲，你可以在`Dockerfile`中有多个`ENTRYPOINT`指令。然而，构建系统将忽略除最后一个之外的所有`ENTRYPOINT`指令。换句话说，在多个`ENTRYPOINT`指令的情况下，只有最后一个`ENTRYPOINT`指令会生效。

为了更好地理解`ENTRYPOINT`指令，让我们使用带有`ENTRYPOINT`指令的`Dockerfile`来创建一个镜像，然后使用这个镜像启动一个容器。以下是带有`ENTRYPOINT`指令的`Dockerfile`，用于回显文本：

```
########################################################
# Dockerfile to demonstrate the behaviour of ENTRYPOINT
########################################################
# Build from base image busybox:latest
FROM busybox:latest
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# Set entrypoint command
ENTRYPOINT ["echo", "Dockerfile ENTRYPOINT demo"]
```

现在，让我们使用`docker build`作为子命令和`entrypoint-demo`作为镜像名称来构建一个 Docker 镜像。`docker build`系统将从当前目录（`.`）中存储的`Dockerfile`中读取指令，并创建镜像，如下所示：

```
$ sudo docker build -t entrypoint-demo .

```

构建完镜像后，我们可以使用`docker run`子命令启动容器：

```
$ sudo docker run entrypoint-demo
Dockerfile ENTRYPOINT demo

```

在这里，容器将像可执行文件一样运行，回显`Dockerfile ENTRYPOINT demo`字符串，然后立即退出。如果我们向`docker run`子命令传递任何额外的参数，那么额外的参数将传递给入口点命令。以下是使用`docker run`子命令给出额外参数启动相同镜像的演示：

```
$ sudo docker run entrypoint-demo with additional arguments
Dockerfile ENTRYPOINT demo with additional arguments

```

现在，让我们看一个例子，我们可以使用`--entrypoint`选项覆盖构建时的入口应用程序，然后在`docker run`子命令中启动一个 shell（`/bin/sh`），如下所示：

```
$ sudo docker run --entrypoint="/bin/sh" entrypoint-demo
/ #

```

## ONBUILD 指令

`ONBUILD`指令将构建指令注册到镜像中，并在使用此镜像作为其基本镜像构建另一个镜像时触发。任何构建指令都可以注册为触发器，并且这些指令将在下游`Dockerfile`中的`FROM`指令之后立即触发。因此，`ONBUILD`指令可用于将构建指令的执行从基本镜像延迟到目标镜像。

`ONBUILD`指令的语法如下：

```
ONBUILD <INSTRUCTION>
```

在其中，`<INSTRUCTION>`是另一个`Dockerfile`构建指令，稍后将被触发。`ONBUILD`指令不允许链接另一个`ONBUILD`指令。此外，它不允许`FROM`和`MAINTAINER`指令作为`ONBUILD`触发器。

以下是`ONBUILD`指令的示例：

```
ONBUILD ADD config /etc/appconfig
```

## .dockerignore 文件

在*Docker 集成的镜像构建系统*部分，我们了解到`docker build`过程将完整的构建上下文发送到守护程序。在实际环境中，`docker build`上下文将包含许多其他工作文件和目录，这些文件和目录永远不会构建到镜像中。然而，`docker build`系统仍然会将这些文件发送到守护程序。因此，您可能想知道如何通过不将这些工作文件发送到守护程序来优化构建过程。嗯，Docker 背后的人也考虑过这个问题，并提供了一个非常简单的解决方案：使用`.dockerignore`文件。

`.dockerignore`是一个以换行分隔的文本文件，在其中您可以提供要从构建过程中排除的文件和目录。文件中的排除列表可以包含完全指定的文件或目录名称和通配符。

以下片段是一个示例`.dockerignore`文件，通过它，构建系统已被指示排除`.git`目录和所有具有`.tmp`扩展名的文件：

```
.git
*.tmp
```

# Docker 镜像管理的简要概述

正如我们在前一章和本章中所看到的，有许多方法可以控制 Docker 镜像。您可以使用`docker pull`子命令从公共存储库下载完全设置好的应用程序堆栈。否则，您可以通过使用`docker commit`子命令手动或使用`Dockerfile`和`docker build`子命令组合自动创建自己的应用程序堆栈。

Docker 镜像被定位为容器化应用程序的关键构建模块，从而实现了部署在云服务器上的分布式应用程序。Docker 镜像是分层构建的，也就是说，可以在其他镜像的基础上构建镜像。原始镜像称为父镜像，生成的镜像称为子镜像。基础镜像是一个捆绑包，包括应用程序的常见依赖项。对原始镜像所做的每个更改都将作为单独的层存储。每次提交到 Docker 镜像时，都会在 Docker 镜像上创建一个新的层，对原始镜像所做的每个更改都将作为单独的层存储。由于层的可重用性得到了便利，制作新的 Docker 镜像变得简单而快速。您可以通过更改`Dockerfile`中的一行来创建新的 Docker 镜像，而无需重新构建整个堆栈。

现在我们已经了解了 Docker 镜像中的层次结构，您可能想知道如何在 Docker 镜像中可视化这些层。好吧，`docker history`子命令是可视化图像层的一个非常好用的工具。

让我们看一个实际的例子，以更好地理解 Docker 镜像中的分层。为此，让我们按照以下三个步骤进行：

1.  在这里，我们有一个`Dockerfile`，其中包含自动构建 Apache2 应用程序镜像的指令，该镜像是基于 Ubuntu 14.04 基础镜像构建的。本章之前制作和使用的`Dockerfile`中的`RUN`部分将在本节中被重用，如下所示：

```
###########################################
# Dockerfile to build an Apache2 image
###########################################
# Base image is Ubuntu
FROM ubuntu:14.04
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# Install apache2 package
RUN apt-get update && \
   apt-get install -y apache2 && \
   apt-get clean
```

1.  现在，通过使用`docker build`子命令从上述`Dockerfile`中制作一个镜像，如下所示：

```
$ sudo docker build -t apache2 .

```

1.  最后，让我们使用`docker history`子命令来可视化 Docker 镜像中的层次结构：

```
$ sudo docker history apache2

```

1.  这将生成关于`apache2` Docker 镜像的每个层的详细报告，如下所示：

```
IMAGE          CREATED       CREATED BY                   SIZE
aa83b67feeba    2 minutes ago    /bin/sh -c apt-get update &&   apt-get inst  35.19 MB
c7877665c770    3 minutes ago    /bin/sh -c #(nop) MAINTAINER Dr. Peter <peter  0 B
9cbaf023786c    6 days ago     /bin/sh -c #(nop) CMD [/bin/bash]        0 B
03db2b23cf03    6 days ago     /bin/sh -c apt-get update && apt-get dist-upg  0 B
8f321fc43180    6 days ago     /bin/sh -c sed -i 's/^#\s*\(deb.*universe\)$/  1.895 kB
6a459d727ebb    6 days ago     /bin/sh -c rm -rf /var/lib/apt/lists/*     0 B
2dcbbf65536c    6 days ago     /bin/sh -c echo '#!/bin/sh' > /usr/sbin/polic 194.5 kB
97fd97495e49    6 days ago     /bin/sh -c #(nop) ADD file:84c5e0e741a0235ef8  192.6 MB
511136ea3c5a    16 months ago                            0 B

```

在这里，`apache2`镜像由十个镜像层组成。顶部两层，具有图像 ID`aa83b67feeba`和`c7877665c770`的层，是我们`Dockerfile`中`RUN`和`MAINTAINER`指令的结果。图像的其余八层将通过我们`Dockerfile`中的`FROM`指令从存储库中提取。

# 编写 Dockerfile 的最佳实践

毫无疑问，一套最佳实践总是在提升任何新技术中起着不可或缺的作用。有一份详细列出所有最佳实践的文件，用于编写`Dockerfile`。我们发现它令人难以置信，因此，我们希望分享给您以供您受益。您可以在[`docs.docker.com/articles/dockerfile_best-practices/`](https://docs.docker.com/articles/dockerfile_best-practices/)找到它。

# 摘要

构建 Docker 镜像是 Docker 技术的关键方面，用于简化容器化的繁琐任务。正如之前所指出的，Docker 倡议已经成为颠覆性和变革性的容器化范式。Dockerfile 是生成高效 Docker 镜像的最主要方式，可以被精心使用。我们已经阐明了所有命令、它们的语法和使用技巧，以赋予您所有易于理解的细节，这将简化您的镜像构建过程。我们提供了大量示例，以证实每个命令的内在含义。在下一章中，我们将讨论 Docker Hub，这是一个专门用于存储和共享 Docker 镜像的存储库，并且我们还将讨论它对容器化概念在 IT 企业中的深远贡献。


# 第四章：发布图像

在上一章中，我们学习了如何构建 Docker 镜像。下一个逻辑步骤是将这些镜像发布到公共存储库以供公众发现和使用。因此，本章重点介绍了在 Docker Hub 上发布图像以及如何充分利用 Docker Hub。我们可以使用`commit`命令和`Dockerfile`创建一个新的 Docker 镜像，对其进行构建，并将其推送到 Docker Hub。将讨论受信任存储库的概念。这个受信任的存储库是从 GitHub 或 Bitbucket 创建的。然后可以将其与 Docker Hub 集成，以便根据存储库中的更新自动构建图像。GitHub 上的这个存储库用于存储之前创建的`Dockerfile`。此外，我们将说明全球组织如何使他们的开发团队能够创建和贡献各种 Docker 镜像，并将其存储在 Docker Hub 中。Docker Hub REST API 可用于用户管理和以编程方式操作存储库。

本章涵盖以下主题：

+   理解 Docker Hub

+   如何将图像推送到 Docker Hub

+   图像的自动构建

+   Docker Hub 上的私有存储库

+   在 Docker Hub 上创建组织

+   Docker Hub REST API

# 理解 Docker Hub

Docker Hub 是一个用于在公共或私有存储库中保存 Docker 镜像的中心位置。Docker Hub 提供了存储 Docker 镜像的存储库、用户认证、自动化图像构建、与 GitHub 或 Bitbucket 的集成以及管理组织和团队的功能。Docker Hub 的 Docker Registry 组件管理存储库。

Docker Registry 是用于存储图像的存储系统。自动构建是 Docker Hub 的一个功能，在撰写本书时尚未开源。以下图表显示了典型的功能：

![理解 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_01.jpg)

要使用 Docker Hub，您必须在 Docker Hub 上注册，并使用以下链接创建帐户：[`hub.docker.com/account/signup`](https://hub.docker.com/account/signup)。您可以更新**用户名**、**密码**和**电子邮件地址**，如下面的屏幕截图所示：

![理解 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_02.jpg)

完成**注册**过程后，您需要完成通过电子邮件收到的验证。完成电子邮件验证后，当您登录到 Docker Hub 时，您将看到类似以下截图的内容：

![理解 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_03.jpg)

Docker Hub 中的帐户创建已成功完成，现在您可以使用[`hub.docker.com/account/login/?next=/account/welcome/`](https://hub.docker.com/account/login/?next=/account/welcome/)登录到您的 Docker Hub 帐户，如下截图所示：

![理解 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_04.jpg)

Docker Hub 还支持使用 Ubuntu 终端对 Docker Hub 进行命令行访问：

```
ubuntu@ip-172-31-21-44:~$ sudo docker login
Username: vinoddandy
Password:
Email: vinoddandy@gmail.com

```

成功登录后，输出如下：

```
Login Succeeded

```

您可以浏览 Docker Hub 中的可用图像，如下所示：

![理解 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_05.jpg)

此外，您可以查看您的设置，更新您的个人资料，并获取支持的社区的详细信息，如 Twitter、stackoverflow、#IRC、Google Groups 和 GitHub。

# 将图像推送到 Docker Hub

在这里，我们将在本地机器上创建一个 Docker 图像，并将此图像推送到 Docker Hub。您需要在本节中执行以下步骤：

1.  通过以下方式在本地机器上创建 Docker 图像之一：

+   使用`docker commit`子命令

+   使用`Dockerfile`的`docker commit`子命令

1.  将此创建的图像推送到 Docker Hub。

1.  从 Docker Hub 中删除图像。

我们将使用 Ubuntu 基础图像，运行容器，添加一个新目录和一个新文件，然后创建一个新图像。在第三章，*构建图像*中，我们已经看到了使用`Dockerfile`创建 Docker 图像。您可以参考这个来检查`Dockerfile`语法的细节。

我们将从基本的`ubuntu`图像中使用名称为`containerforhub`的容器运行容器，如下终端代码所示：

```
$ sudo docker run -i --name="containerforhub" -t ubuntu /bin/bash
root@e3bb4b138daf:/#

```

接下来，我们将在`containerforhub`容器中创建一个新目录和文件。我们还将更新新文件，以便稍后进行测试：

```
root@bd7cc5df6d96:/# mkdir mynewdir
root@bd7cc5df6d96:/# cd mynewdir
root@bd7cc5df6d96:/mynewdir# echo 'this is my new container to make image and then push to hub' >mynewfile
root@bd7cc5df6d96:/mynewdir# cat mynewfile
This is my new container to make image and then push to hub
root@bd7cc5df6d96:/mynewdir#

```

让我们使用刚刚创建的容器的`docker commit`命令构建新图像。请注意，`commit`命令将从主机机器上执行，从容器正在运行的位置执行，而不是从容器内部执行：

```
$ sudo docker commit -m="NewImage" containerforhub vinoddandy/imageforhub
3f10a35019234af2b39d5fab38566d586f00b565b99854544c4c698c4a395d03

```

现在，我们在本地机器上有一个名为`vinoddandy/imageforhub`的新 Docker 图像。此时，本地创建了一个带有`mynewdir`和`mynewfile`的新图像。

我们将使用`sudo docker login`命令登录到 Docker Hub，就像本章前面讨论的那样。

让我们从主机机器将此图像推送到 Docker Hub：

```
$ sudo docker push vinoddandy/imageforhub
The push refers to a repository [vinoddandy/imageforhub] (len: 1)
Sending image list
Pushing tag for rev [c664d94bbc55] on {https://cdn-registry-1.docker.io/v1/repositories/vinoddandy/imageforhub/tags/latest}

```

现在，我们将`登录`到 Docker Hub 并在**存储库**中验证图像。

为了测试来自 Docker Hub 的图像，让我们从本地机器中删除此图像。要删除图像，首先需要停止容器，然后删除容器：

```
$ sudo docker stop containerforhub
$ sudo docker rm containerforhub
$

```

我们还将删除`vinoddandy/imageforhub`图像：

```
$ sudo docker rmi vinoddandy/imageforhub

```

我们将从 Docker Hub 中拉取新创建的图像，并在本地机器上运行新容器：

```
$ sudo docker run -i --name="newcontainerforhub" -t vinoddandy/imageforhub /bin/bash
Unable to find image 'vinoddandy/imageforhub' locally
Pulling repository vinoddandy/imageforhub
c664d94bbc55: Pulling image (latest) from vinoddandy/imageforhub, endpoint: http
c664d94bbc55: Download complete
5506de2b643b: Download complete
root@9bd40f1b5585:/# cat /mynewdir/mynewfile
This is my new container to make image and then push to hub
root@9bd40f1b5585:/#

```

因此，我们已经从 Docker Hub 中拉取了最新的图像，并使用新图像`vinoddandy/imageforhub`创建了容器。请注意，`无法在本地找到图像'vinoddandy/imageforhub'`的消息证实了该图像是从 Docker Hub 的远程存储库中下载的。

`mynewfile`中的文字证实了它是之前创建的相同图像。

最后，我们将从 Docker Hub 中删除图像，使用[`registry.hub.docker.com/u/vinoddandy/imageforhub/`](https://registry.hub.docker.com/u/vinoddandy/imageforhub/)，然后点击**删除存储库**，如下面的截图所示：

![将图像推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_06.jpg)

我们将再次创建此图像，但使用`Dockerfile`过程。因此，让我们使用第三章中解释的`Dockerfile`概念创建 Docker 图像，并将此图像推送到 Docker Hub。

本地机器上的`Dockerfile`如下所示：

```
###########################################
# Dockerfile to build a new image
###########################################
# Base image is Ubuntu
FROM ubuntu:14.04
# Author: Dr. Peter
MAINTAINER Dr. Peter <peterindia@gmail.com>
# create 'mynewdir' and 'mynewfile'
RUN mkdir mynewdir
RUN touch /mynewdir/mynewfile
# Write the message in file
RUN echo 'this is my new container to make image and then push to hub' \
 >/mynewdir/mynewfile
```

现在，我们使用以下命令在本地构建图像：

```
$ sudo docker build -t="vinoddandy/dockerfileimageforhub" .
Sending build context to Docker daemon  2.56 kB
Sending build context to Docker daemon
Step 0 : FROM ubuntu:14.04
---> 5506de2b643b
Step 1 : MAINTAINER Vinod Singh <vinod.puchi@gmail.com>
---> Running in 9f6859e2ca75
---> a96cfbf4a810
removing intermediate container 9f6859e2ca75
Step 2 : RUN mkdir mynewdir
---> Running in d4eba2a31467
---> 14f4c15610a7
removing intermediate container d4eba2a31467
Step 3 : RUN touch /mynewdir/mynewfile
---> Running in 7d810a384819
---> b5bbd55f221c
removing intermediate container 7d810a384819
Step 4 : RUN echo 'this is my new container to make image and then push to hub'
/mynewdir/mynewfile
---> Running in b7b48447e7b3
---> bcd8f63cfa79
removing intermediate container b7b48447e7b3
successfully built 224affbf9a65
ubuntu@ip-172-31-21-44:~/dockerfile_image_hub$

```

我们将使用此图像运行容器，如下所示：

```
$ sudo docker run -i --name="dockerfilecontainerforhub" –t vinoddandy/dockerfileimageforhub
root@d3130f21a408:/# cat /mynewdir/mynewfile
this is my new container to make image and then push to hub

```

`mynewdir`中的这段文字证实了新图像是通过新目录和新文件正确构建的。

重复`登录`过程，在 Docker Hub 中，然后推送这个新创建的镜像：

```
$ sudo docker login
Username (vinoddandy):
Login Succeeded
$ sudo docker push vinoddandy/dockerfileimageforhub
The push refers to a repository [vinoddandy/dockerfileimageforhub] (len: 1)
Sending image list
Pushing repository vinoddandy/dockerfileimageforhub (1 tags)
511136ea3c5a: Image already pushed, skipping
d497ad3926c8: Image already pushed, skipping
b5bbd55f221c: Image successfully pushed
bcd8f63cfa79: Image successfully pushed
224affbf9a65: Image successfully pushed
Pushing tag for rev [224affbf9a65] on {https://cdn-registry-1.docker.io/v1/repos
itories/vinoddandy/dockerfileimageforhub/tags/latest}
$

```

最后，我们可以验证 Docker Hub 上图像的可用性：

![将图像推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_07.jpg)

# 自动化图像构建过程

我们学会了如何在本地构建图像并将这些图像推送到 Docker Hub。Docker Hub 还具有从存储在 GitHub 或 Bitbucket 仓库中的`Dockerfile`自动构建图像的功能。自动构建支持 GitHub 和 Bitbucket 的私有和公共仓库。Docker Hub Registry 保存所有自动构建图像。Docker Hub Registry 基于开源，并且可以从[`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)访问。

我们将讨论实施自动构建过程所需的步骤：

1.  我们首先将 Docker Hub 连接到我的 GitHub 帐户。

登录到 Docker Hub，并点击**查看个人资料**，然后转到**添加仓库** | **自动构建**，如下面的截图所示：

![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_08.jpg)

1.  现在我们选择**GitHub**：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_09.jpg)

1.  选择**GitHub**后，它将要求授权。在这里，我们将选择**公共和私有**，如下所示：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_10.jpg)

1.  点击**选择**后，它现在会显示您的 GitHub 仓库：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_11.jpg)

1.  点击您的仓库**vinodsinghh/dockerautomationbuild**的**选择**按钮，如前面的截图所示：

1.  我们选择默认分支，并使用`Githubimage`更新标签。此外，我们将保持位置为其默认值，即我们的 Docker Hub 的根目录，如下面的截图所示：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_12.jpg)

1.  最后，我们将点击**创建仓库**，如前面的截图所示：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_13.jpg)

1.  点击**构建详情**以跟踪构建状态，如前面的截图所示。它将引导您到下面的截图：![自动化构建图像的过程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_14.jpg)

因此，每当 GitHub 中的`Dockerfile`更新时，自动构建就会被触发，并且新的镜像将存储在 Docker Hub 注册表中。我们可以随时检查构建历史记录。我们可以在本地机器上更改`Dockerfile`并推送到 GitHub。然后，我们可以在 Docker Hub 上看到自动构建链接[`registry.hub.docker.com/u/vinoddandy/dockerautomatedbuild/builds_history/82194/`](https://registry.hub.docker.com/u/vinoddandy/dockerautomatedbuild/builds_history/82194/)。

# Docker Hub 上的私有仓库

Docker Hub 提供公共和私有仓库。公共仓库对用户免费，私有仓库是付费服务。私有仓库的计划有不同的大小，如微型、小型、中型或大型订阅。

Docker 已经将他们的公共仓库代码发布为开源，网址是[`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)。

通常，企业不喜欢将他们的 Docker 镜像存储在 Docker 的公共或私有仓库中。他们更喜欢保留、维护和支持自己的仓库。因此，Docker 也为企业提供了创建和安装自己的仓库的选项。

让我们使用 Docker 提供的注册表镜像在本地机器上创建一个仓库。我们将在本地机器上运行注册表容器，使用来自 Docker 的注册表镜像：

```
$ sudo docker run -p 5000:5000 -d registry
768fb5bcbe3a5a774f4996f0758151b1e9917dec21aedf386c5742d44beafa41

```

在自动构建部分，我们构建了`vinoddandy/dockerfileforhub`镜像。让我们将镜像 ID `224affbf9a65`标记到我们本地创建的`registry`镜像上。这个镜像的标记是为了在本地仓库中进行唯一标识。这个`registry`镜像可能在仓库中有多个变体，所以这个`tag`将帮助您识别特定的镜像：

```
$ sudo docker tag 224affbf9a65localhost:5000/vinoddandy/dockerfileimageforhub

```

标记完成后，使用`docker push`命令将此镜像推送到新的注册表：

```
$ sudo docker push localhost:5000/vinoddandy/dockerfile
imageforhub
The push refers to a repository [localhost:5000/vinoddandy/dockerfileimageforhub
] (len: 1)
Sending image list
Pushing repository localhost:5000/vinoddandy/dockerfileimageforhub (1 tags)
511136ea3c5a: Image successfully pushed
d497ad3926c8: Image successfully pushed
----------------------------------------------------
224affbf9a65: Image successfully pushed
Pushing tag for rev [224affbf9a65] on {http://localhost:5000/v1/repositories/vin
oddandy/dockerfileimageforhub/tags/latest}
ubuntu@ip-172-31-21-44:~$

```

现在，新的镜像已经在本地仓库中可用。您现在可以从本地注册表中检索此镜像并运行容器。这个任务留给你来完成。

# Docker Hub 上的组织和团队

私有仓库的一个有用方面是，您可以只与组织或团队成员共享它们。Docker Hub 允许您创建组织，在那里您可以与同事合作并管理私有仓库。您可以学习如何创建和管理组织。

第一步是在 Docker Hub 上创建一个组织，如下截图所示：

![Docker Hub 上的组织和团队](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_15.jpg)

在您的组织中，您可以添加更多的组织，然后向其中添加成员：

![Docker Hub 上的组织和团队](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_16.jpg)

您的组织和团队成员可以与组织和团队合作。在私人存储库的情况下，此功能将更加有用。

# Docker Hub 的 REST API

Docker Hub 提供了 REST API，通过程序集成 Hub 功能。 REST API 支持用户和存储库管理。

用户管理支持以下功能：

+   用户登录：用于用户登录到 Docker Hub：

```
GET /v1/users

$ curl --raw -L --user vinoddandy:password https://index.docker.io/v1/users
4
"OK"
0
$

```

+   用户注册：用于注册新用户：

```
POST /v1/users
```

+   更新用户：用于更新用户的密码和电子邮件：

```
PUT /v1/users/(usename)/
```

存储库管理支持以下功能：

+   创建用户存储库：这将创建一个用户存储库：

```
PUT /v1/repositories/(namespace)/(repo_name)/
```

```
$ curl --raw -L -X POST --post301 -H "Accept:application/json" -H "Content-Type: application/json" --data-ascii '{"email": "singh_vinod@yahoo.com", "password": "password", "username": "singhvinod494" }' https://index.docker.io/v1/users
e
"User created"
0

```

创建存储库后，您的存储库将在此处列出，如此屏幕截图所示：

![Docker Hub 的 REST API](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-pt2/img/7937OT_04_17.jpg)

+   删除用户存储库：这将删除用户存储库：

```
DELETE /v1/repositories/(namespace)/(repo_name)/
```

+   创建库存储库：这将创建库存储库，仅供 Docker 管理员使用：

```
PUT /v1/repositories/(repo_name)/
```

+   删除库存储库：这将删除库存储库，仅供 Docker 管理员使用：

```
DELETE /v1/repositories/(repo_name)/
```

+   更新用户存储库图像：这将更新用户存储库的图像：

```
PUT /v1/repositories/(namespace)/(repo_name)/images
```

+   列出用户存储库图像：这将列出用户存储库的图像：

```
GET /v1/repositories/(namespace)/(repo_name)/images
```

+   更新库存储库图像：这将更新库存储库的图像：

```
PUT /v1/repositories/(repo_name)/images
```

+   列出库存储库图像：这将列出库存储库的图像：

```
GET /v1/repositories/(repo_name)/images
```

+   为库存储库授权令牌：为库存储库授权令牌：

```
PUT /v1/repositories/(repo_name)/auth
```

+   为用户存储库授权令牌：为用户存储库授权令牌：

```
PUT /v1/repositories/(namespace)/(repo_name)/auth
```

# 总结

Docker 镜像是用于衍生真实世界 Docker 容器的最突出的构建模块，可以在任何网络上作为服务公开。开发人员可以查找和检查镜像的独特功能，并根据自己的目的使用它们，以创建高度可用、公开可发现、可访问网络和认知可组合的容器。所有精心制作的镜像都需要放在公共注册库中。在本章中，我们清楚地解释了如何在存储库中发布镜像。我们还谈到了受信任的存储库及其独特的特点。最后，我们演示了如何利用存储库的 REST API 来推送和操作 Docker 镜像以及用户管理。

Docker 镜像需要存储在公共、受控和可访问网络的位置，以便全球软件工程师和系统管理员可以轻松找到并利用。Docker Hub 被誉为集中聚合、筛选和管理 Docker 镜像的最佳方法，源自 Docker 爱好者（内部和外部）。然而，企业无法将其 Docker 镜像存储在公共域中，因此，下一章将专门介绍在私人 IT 基础设施中暴露镜像部署和管理所需的步骤。
