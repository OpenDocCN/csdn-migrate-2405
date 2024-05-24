# Docker 监控手册（一）

> 原文：[`zh.annas-archive.org/md5/90AFB362E78E33672A01E1BE9B0E27CA`](https://zh.annas-archive.org/md5/90AFB362E78E33672A01E1BE9B0E27CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着 Docker 容器的采用增加，监视正在运行的容器、它们正在消耗的资源以及它们如何影响系统整体性能的需求已成为一个与时间相关的需求。*监控 Docker*将教会您如何监视容器，并密切关注应用程序的工作方式，以提高在 Docker 上运行的应用程序的整体性能。

本书将介绍如何使用 Docker 的原生监控功能、各种插件以及帮助监控的第三方工具来监控容器。本书首先将介绍如何获取活动容器的详细统计信息、消耗的资源和容器行为。本书还将向读者展示如何利用这些统计数据来提高系统的整体性能。

# 本书涵盖内容

第一章 *介绍 Docker 监控*，讨论了与监视传统服务器（如虚拟机、裸机和云实例）相比，监视容器有多么不同（宠物与牛群、鸡与雪花）。本章还详细介绍了本书后面示例中涵盖的操作系统，并简要介绍了如何使用 vagrant 搭建本地测试环境，以便轻松地遵循安装说明和实际示例。

第二章 *使用内置工具*，帮助您了解从原始 Docker 安装中可以获得的基本指标，以及如何使用它们。此外，我们将了解如何获取正在运行的容器的实时统计信息，如何使用我们熟悉的命令，以及如何获取启动为每个容器的一部分的进程信息。

第三章 *高级容器资源分析*，介绍了来自 Google 的 cAdvisor，它为 Docker 提供的基本工具增加了更多精度。您还将学习如何安装 cAdvisor 并开始收集指标。

第四章，“监控容器的传统方法”，介绍了一种用于监控服务的传统工具。通过本章，您应该了解 Zabbix 以及您可以监控容器的各种方式。

第五章，“使用 Sysdig 进行查询”，描述了 Sysdig 作为“一个开源的系统级探索工具，用于捕获运行中 Linux 实例的系统状态和活动，然后保存、过滤和分析它。”在本章中，您将学习如何使用 Sysdig 实时查看容器的性能指标，并记录会话以供以后查询。

第六章，“探索第三方选项”，为您介绍了一些可用的软件即服务（SaaS）选项，以及为什么要使用它们，以及如何在主机服务器上安装它们的客户端。

第七章，“从容器内部收集应用程序日志”，探讨了如何将容器内运行的应用程序的日志文件内容传输到一个中央位置，以便即使您必须销毁和替换容器，这些日志也是可用的。

第八章，“接下来该做什么？”，探讨了在监控容器方面可以采取的下一步措施，讨论了将警报添加到监控中的好处。此外，我们将涵盖一些不同的场景，并查看哪种类型的监控适合每种场景。

# 本书所需内容

为了确保体验尽可能一致，我们将安装 vagrant 和 VirtualBox 来运行作为主机运行我们的容器的虚拟机。Vagrant 适用于 Linux、OS X 和 Windows；有关安装方法的详细信息，请参阅 vagrant 网站[`www.vagrantup.com/`](https://www.vagrantup.com/)。有关如何下载和安装 VirtualBox 的详细信息，请参阅[`www.virtualbox.org/`](https://www.virtualbox.org/)；同样，VirtualBox 可以安装在 Linux、OS X 和 Windows 上。

# 本书适合谁？

本书适用于希望管理 Docker 容器的 DevOps 工程师和系统管理员，希望使用专业技术和方法更好地管理这些容器，并更好地维护基于 Docker 构建的应用程序。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："我们可以通过使用`include`指令来包含其他上下文。"

代码块设置如下：

```
{
  "fields": {
    "@timestamp": [
      1444567706641
    ]
  },
  "sort": [
    1444567706641
  ]
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
{
  "fields": {
    "@timestamp": [
      1444567706641
    ]
  },
  "sort": [
 1444567706641
  ]
}
```

任何命令行输入或输出都以以下方式编写：

```
 cd ~/Documents/Projects/monitoring-docker/vagrant-ubuntu
 vagrant up

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："单击**下一步**按钮将您移至下一个屏幕。"

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：Docker 监控简介

Docker 是最近添加到系统管理员工具箱中的一个非常重要的工具。

Docker 自称是一个用于构建、发布和运行分布式应用程序的开放平台。这意味着开发人员可以捆绑他们的代码并将其传递给运维团队。从这里，他们可以放心地部署，因为他们知道它将以一种引入代码运行环境一致性的方式进行部署。

遵循这个过程后，应该会让开发人员与运维人员之间关于“在我的本地开发服务器上可以运行”的争论成为过去的事情。自 2014 年 6 月发布“可投入生产”的 1.0 版本之前，已经有超过 10,000 个 Docker 化的应用程序可用。到 2014 年底，这个数字已经上升到超过 71,000 个。您可以通过查看 Docker 在 2014 年的增长情况来了解 Docker 在 2014 年的增长情况，该信息图表是由 Docker 在 2015 年初发布的，可以在[`blog.docker.com/2015/01/docker-project-2014-a-whirlwind-year-in-review/`](https://blog.docker.com/2015/01/docker-project-2014-a-whirlwind-year-in-review/)找到。

尽管关于技术是否已经达到生产就绪的争论仍在继续，但 Docker 已经获得了一系列令人印象深刻的技术合作伙伴，包括 RedHat、Canonical、HP，甚至还有微软。

像 Google、Spotify、Soundcloud 和 CenturyLink 这样的公司都以某种方式开源了支持 Docker 的工具，还有许多独立开发人员发布了提供额外功能的应用程序，以补充核心 Docker 产品集。此外，围绕 Docker 生态系统还出现了许多公司。

本书假定您已经有一定程度的经验来构建、运行和管理 Docker 容器，并且您现在希望开始从正在运行的应用程序中获取指标，以进一步调整它们，或者您希望在容器出现问题时了解情况，以便调试任何正在发生的问题。

如果您以前从未使用过 Docker，您可能希望尝试一本优秀的书籍，介绍 Docker 提供的所有内容，比如《学习 Docker》，Packt Publishing 出版，或者 Docker 自己的容器介绍，可以在他们的文档页面找到，如下所示：

+   学习 Docker：[`www.packtpub.com/virtualization-and-cloud/learning-docker`](https://www.packtpub.com/virtualization-and-cloud/learning-docker)

+   官方 Docker 文档：[`docs.docker.com/`](https://docs.docker.com/)

现在，我们已经了解了 Docker 是什么；本章的其余部分将涵盖以下主题：

+   监视容器与监视传统服务器（如虚拟机、裸机和云实例）有多大不同（宠物、牛、鸡和雪花）。

+   您应该运行的 Docker 的最低版本是多少？

+   如何按照使用 Vagrant 在本地启动环境的说明，以便在本书的实际练习中进行跟踪

# 宠物、牛、鸡和雪花

在我们开始讨论各种监视容器的方法之前，我们应该了解一下现在系统管理员的工作是什么样子，以及容器在其中的位置。

典型的系统管理员可能会负责托管在内部或第三方数据中心的服务器群，有些甚至可能管理托管在亚马逊网络服务或微软 Azure 等公共云中的实例，一些系统管理员可能会在多个托管环境中管理他们的服务器群。

每个不同的环境都有自己的做事方式，以及执行最佳实践。2012 年 2 月，Randy Bias 在 Cloudscaling 发表了一篇关于开放和可扩展云架构的演讲。在幻灯片最后，Randy 介绍了宠物与牛的概念（他将其归因于当时在微软担任工程师的 Bill Baker）。

您可以在[`www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds`](http://www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds)上查看原始幻灯片。

宠物与牛现在被广泛接受为描述现代托管实践的好比喻。

## 宠物

宠物类似于传统物理服务器或虚拟机，如下所示：

+   每个宠物都有一个名字；例如，`myserver.domain.com`。

+   当它们不舒服时，您会带它们去兽医那里帮助它们康复。您雇用系统管理员来照顾它们。

+   你密切关注它们，有时长达数年。您备份它们，打补丁，并确保它们完全记录。

## 牛

另一方面，牛代表了更现代的云计算实例，如下所示：

+   你有太多了，无法一一列举，所以你给它们编号；例如，URL 可能看起来像`ip123123123123.eu.public-cloud.com`。

+   当它们生病时，你射杀它们，如果你的群需要，你替换你杀死的任何东西：服务器崩溃或显示出有问题的迹象，你终止它，你的配置会自动用精确的副本替换它。

+   你把它们放在田野里，远远地观察它们，你不指望它们能活得很久。与监视个别实例不同，你监视整个集群。当需要更多资源时，你添加更多实例，一旦不再需要资源，你终止实例以恢复到基本配置。

## 鸡

接下来是一个术语，它是描述容器如何适应宠物与牛之间的世界的好方法；在 ActiveState 的一篇名为“云计算：宠物、牛和...鸡？”的博客文章中，伯纳德·戈尔登将容器描述为鸡。

+   在资源使用方面，它们比牛更有效。一个容器可以在几秒钟内启动，而实例或服务器可能需要几分钟；它还比典型的虚拟机或云实例使用更少的 CPU 功率。

+   鸡比牛多得多。你可以在实例或服务器上密集地放置容器。

+   鸡的寿命往往比牛和宠物短。容器适合运行微服务；这些容器可能只活跃几分钟。

原始博客文章可以在[`www.activestate.com/blog/2015/02/cloud-computing-pets-cattle-and-chickens`](http://www.activestate.com/blog/2015/02/cloud-computing-pets-cattle-and-chickens)找到。

## 雪花

最后一个术语与动物无关，它描述了一种你绝对不想在服务器群中拥有的类型，即雪花。这个术语是由马丁·福勒在一篇名为“SnowflakeServer”的博客文章中创造的。雪花是一个用于“传统”或“继承”服务器的术语：

+   雪花是脆弱的，需要小心对待。通常，这台服务器从你开始在数据中心工作以来就一直存在。没有人知道最初是谁配置的，也没有文档记录；你只知道它很重要。

+   每个都是独一无二的，无法精确复制。即使是最坚强的系统管理员也害怕重新启动机器，因为它正在运行即将终止的软件，无法轻松重新安装。

马丁的文章可以在[`martinfowler.com/bliki/SnowflakeServer.html`](http://martinfowler.com/bliki/SnowflakeServer.html)找到。

## 那么这一切意味着什么呢？

根据您的要求和想要部署的应用程序，您的容器可以部署到宠物风格或牛群风格的服务器上。您还可以创建一群小鸡，并让您的容器运行微服务。

此外，理论上，您可以用满足软件生命周期要求的基于容器的应用程序替换您害怕的雪花服务器，同时仍然可以部署在现代可支持的平台上。

每种不同风格的服务器都有不同的监控要求，在最后一章中，我们将再次讨论宠物、牛群、鸡群和雪花，并讨论我们在接下来的章节中涵盖的工具。我们还将介绍在规划监控时应考虑的最佳实践。

# Docker

虽然 Docker 在一年多前达到了 1.0 版本的里程碑，但它仍处于初期阶段；每次新发布都会带来新功能、错误修复，甚至支持一些正在被淘汰的早期功能。

Docker 本身现在是几个较小项目的集合；其中包括以下内容：

+   Docker Engine

+   Docker Machine

+   Docker Compose

+   Docker Swarm

+   Docker Hub

+   Docker Registry

+   Kitmatic

在这本书中，我们将使用 Docker Engine，Docker Compose 和 Docker Hub。

Docker Engine 是 Docker 项目的核心组件，它提供了主要的 Docker 功能。每当在本书中提到 Docker 或`docker`命令时，我指的是 Docker Engine。

本书假设您已安装了 Docker Engine 1.71 或更高版本；旧版本的 Docker Engine 可能不包含运行接下来章节中涵盖的命令和软件所需的必要功能。

Docker Compose 最初是一个名为**Fig**的第三方编排工具，在 2014 年被 Docker 收购。它被描述为使用 YAML（[`yaml.org`](http://yaml.org)）定义多容器应用程序的一种方式。简而言之，这意味着您可以使用一个调用人类可读配置文件的单个命令快速部署复杂的应用程序。

我们假设您已安装了 Docker Compose 1.3.3 或更高版本；本书中提到的`docker-compose.yml`文件是根据这个版本编写的。

最后，本书中我们将部署的大部分镜像都将来自 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)），这里不仅有一个包含超过 40,000 个公共镜像的公共注册表，还有 100 个官方镜像。以下截图显示了 Docker Hub 网站上的官方存储库列表：

![Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00002.jpeg)

您还可以注册并使用 Docker Hub 来托管您自己的公共和私有镜像。

# 启动本地环境

在可能的情况下，我将尽量确保本书中的实际练习能够在本地机器上运行，比如您的台式机或笔记本电脑。在本书中，我将假设您的本地机器正在运行最新版本的 OS X 或最新的 Linux 发行版，并且具有足够高的规格来运行本章中提到的软件。

我们将使用的两个工具也可以在 Windows 上运行；因此，按照本书中的说明应该是可能的，尽管您可能需要参考语法的使用指南进行任何更改。

由于 Docker 的架构方式，本书的大部分内容将让您在充当主机机器的虚拟服务器上运行命令并与命令行进行交互，而不是直接与容器进行交互。因此，我们将不使用 Docker Machine 或 Kitematic。

这两个工具都是 Docker 提供的，用于在本地机器上快速引导启用 Docker 的虚拟服务器，不过这些工具部署的主机机器包含了一个经过优化的、尽可能小的 Docker 运行的精简操作系统。

由于我们将在主机上安装额外的软件包，“仅 Docker”操作系统可能没有可用的组件来满足我们将在后面章节中运行的软件的先决条件；因此，为了确保以后没有问题，我们将运行一个完整的操作系统。

就个人而言，我更喜欢基于 RPM 的操作系统，比如 RedHat Enterprise Linux，Fedora 或 CentOS，因为我几乎从第一次登录 Linux 服务器开始就一直在使用它们。

然而，由于很多读者熟悉基于 Debian 的 Ubuntu，我将为这两种操作系统提供实际示例。

为了确保体验尽可能一致，我们将安装 Vagrant 和 VirtualBox 来运行虚拟机，该虚拟机将充当运行我们容器的主机。

Vagrant 是由 Mitchell Hashimoto 编写的命令行工具，用于创建和配置可重现和可移植的虚拟机环境。有许多博客文章和文章实际上将 Docker 与 Vagrant 进行了比较；然而，在我们的情况下，这两种技术在提供可重复和一致的环境方面工作得相当好。

Vagrant 适用于 Linux、OS X 和 Windows。有关安装的详细信息，请访问 Vagrant 网站[`www.vagrantup.com/`](https://www.vagrantup.com/)。

VirtualBox 是一个非常全面的开源虚拟化平台，最初由 Sun 开发，现在由 Oracle 维护。它允许您在本地计算机上运行 32 位和 64 位的客户操作系统。有关如何下载和安装 VirtualBox 的详细信息，请访问[`www.virtualbox.org/`](https://www.virtualbox.org/)；同样，VirtualBox 可以安装在 Linux、OS X 和 Windows 上。

# 克隆环境

环境的源代码以及实际示例可以在 GitHub 的 Monitoring Docker 存储库中找到，网址为[`github.com/russmckendrick/monitoring-docker`](https://github.com/russmckendrick/monitoring-docker)。

要在本地计算机的终端上克隆存储库，请运行以下命令（根据需要替换文件路径）：

```
mkdir ~/Documents/Projects
cd ~/Documents/Projects/
git clone https://github.com/russmckendrick/monitoring-docker.git

```

克隆后，您应该看到一个名为`monitoring-docker`的目录，然后进入该目录，如下所示：

```
cd ~/Documents/Projects/monitoring-docker

```

# 运行虚拟服务器

在存储库中，您将找到两个包含启动 CentOS 7 或 Ubuntu 14.04 虚拟服务器所需的`Vagrant`文件的文件夹。

如果您想使用 CentOS 7 的 vagrant box，请将目录更改为`vagrant-centos`：

```
cd vagrant-centos

```

一旦您进入 vagrant-centos 目录，您将看到有一个`Vagrant`文件；这个文件就是启动 CentOS 7 虚拟服务器所需的全部内容。虚拟服务器启动后，将安装最新版本的`docker`和`docker-compose`，并且`monitoring-docker`目录也将被挂载到虚拟机内，挂载点为`/monitoring-docker`。

要启动虚拟服务器，只需输入以下命令：

```
vagrant up

```

这将从[`atlas.hashicorp.com/russmckendrick/boxes/centos71`](https://atlas.hashicorp.com/russmckendrick/boxes/centos71)下载 vagrant box 的最新版本，然后启动虚拟服务器；这是一个 450MB 的下载，所以可能需要几分钟的时间；它只需要做一次。

如果一切顺利，您应该会看到类似以下输出：

![运行虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00003.jpeg)

现在您已经启动了虚拟服务器，可以使用以下命令连接到它：

```
vagrant ssh

```

登录后，您应该验证`docker`和`docker-compose`是否都可用：

运行虚拟服务器

最后，您可以尝试使用以下命令运行`hello-world`容器：

```
docker run hello-world

```

如果一切顺利，您应该会看到以下输出：

![运行虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00005.jpeg)

要尝试更有雄心的事情，您可以使用以下命令运行一个 Ubuntu 容器：

```
docker run -it ubuntu bash

```

在启动并进入 Ubuntu 容器之前，让我们确认我们正在运行的是 CentOS 主机机器，通过检查可以在`/etc`中找到的发行文件：

![运行虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00006.jpeg)

现在，我们可以启动 Ubuntu 容器。使用相同的命令，我们可以确认我们在 Ubuntu 容器内部，通过查看其发行文件：

![运行虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00007.jpeg)

要退出容器，只需输入`exit`。这将停止容器的运行，因为它终止了容器内唯一正在运行的进程，即 bash，并将您返回到主机 CentOS 机器。

正如您在我们的 CentOS 7 主机中所看到的，我们已经启动并移除了一个 Ubuntu 容器。

CentOS 7 和 Ubuntu Vagrant 文件都将在您的虚拟机上配置静态 IP 地址。它是`192.168.33.10`；此外，此 IP 地址在[docker.media-glass.es](http://docker.media-glass.es)上有一个 DNS 记录。这将允许您访问任何在浏览器中公开自己的容器，无论是在`http://192.168.33.10/`还是[`docker.media-glass.es/`](http://docker.media-glass.es)。

### 提示

URL [`docker.media-glass.es/`](http://docker.media-glass.es/) 只有在 vagrant box 运行时才有效，并且您有一个运行 Web 页面的容器。

您可以通过运行以下命令来查看这一操作：

```
docker run -d -p 80:80russmckendrick/nginx-php

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载所购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

这将下载并启动一个运行 NGINX 的容器。然后您可以在浏览器中转到`http://192.168.33.10/`或[`docker.media-glass.es/`](http://docker.media-glass.es/)；您应该会看到一个禁止访问的页面。这是因为我们尚未为 NGINX 提供任何内容来提供服务（关于这一点，稍后将在本书中介绍）：

![运行虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00008.jpeg)

有关更多示例和想法，请访问[`docs.docker.com/userguide/`](http://docs.docker.com/userguide/)网站。

# 停止虚拟服务器

要注销虚拟服务器并返回到本地机器，您可以输入`exit`。

现在您应该看到本地机器的终端提示；但是，您启动的虚拟服务器仍将在后台运行，快乐地使用资源，直到您使用以下命令关闭它：

```
vagrant halt

```

使用`vagrant destroy`完全终止虚拟服务器：

```
vagrant destroy

```

要检查虚拟服务器的当前状态，可以运行以下命令：

```
vagrant status

```

上述命令的结果如下输出所示：

![停止虚拟服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00009.jpeg)

要么重新启动虚拟服务器，要么从头开始创建虚拟服务器，都可以通过再次发出`vagrant up`命令来实现。

上述详细信息显示了如何使用 CentOS 7 虚拟机箱。如果您希望启动 Ubuntu 14.04 虚拟服务器，可以通过以下命令进入`vagrant-ubuntu`目录下载并安装 vagrant box：

```
cd ~/Documents/Projects/monitoring-docker/vagrant-ubuntu
vagrant up

```

从这里，您将能够运行 vagrant up 并按照启动和与 CentOS 7 虚拟服务器交互所使用的相同说明进行操作。

# 摘要

在本章中，我们讨论了不同类型的服务器，并讨论了您的容器化应用程序如何适应每个类别。我们还安装了 VirtualBox 并使用 Vagrant 启动了 CentOS 7 或 Ubuntu 14.04 虚拟服务器，并安装了`docker`和`docker-compose`。

我们的新虚拟服务器环境将在接下来的章节中用于测试各种不同类型的监控。在下一章中，我们将通过使用 Docker 内置的功能来探索关于我们运行的容器的指标，开始我们的旅程。


# 第二章：使用内置工具

在本书的后面章节中，我们将探索围绕 Docker 在过去 24 个月中开始蓬勃发展的大型生态系统的监控部分。然而，在我们继续之前，我们应该看看使用原始安装的 Docker 可能实现什么。在本章中，我们将涵盖以下主题：

+   使用 Docker 内置工具实时获取容器性能指标

+   使用标准操作系统命令获取 Docker 正在执行的指标

+   生成一个测试负载，以便您可以查看指标的变化

# Docker 统计

自 1.5 版本以来，Docker 内置了一个基本的统计命令：

```
docker stats --help

Usage: docker stats [OPTIONS] CONTAINER [CONTAINER...]

Display a live stream of one or more containers' resource usage statistics

--help=false         Print usage
--no-stream=false    Disable streaming stats and only pull the first result

```

这个命令将实时流式传输容器的资源利用率详情。了解该命令的最佳方法是看它实际运行。

## 运行 Docker 统计

让我们使用 vagrant 环境启动一个容器，这是我们在上一章中介绍的：

```
[russ@mac ~]$ cd ~/Documents/Projects/monitoring-docker/vagrant-centos/
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==> default: Importing base box 'russmckendrick/centos71'...
==> default: Matching MAC address for NAT networking...
==> default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==> default: => Installing docker-engine ...
==> default: => Configuring vagrant user ...
==> default: => Starting docker-engine ...
==> default: => Installing docker-compose ...
==> default: => Finished installation of Docker
[russ@mac ~]$ vagrant ssh

```

现在您已连接到 vagrant 服务器，使用`/monitoring_docker/Chapter01/01-basic/`中的 Docker compose 文件启动容器：

```
[vagrant@centos7 ~]$ cd /monitoring_docker/Chapter01/01-basic/
[vagrant@centos7 01-basic]$ docker-compose up -d
Creating 01basic_web_1...

```

您现在已经拉取并在后台启动了一个容器。该容器名为`01basic_web_1`，它运行 NGINX 和 PHP，提供一个单独的 PHP 信息页面（[`php.net/manual/en/function.phpinfo.php`](http://php.net/manual/en/function.phpinfo.php)）。

要检查是否一切都按预期启动，请运行`docker-compose ps`。您应该看到您的单个容器的`State`为`Up`：

```
[vagrant@centos7 01-basic]$ docker-compose ps
Name             Command         State         Ports
---------------------------------------------------------------
01basic_web_1   /usr/local/bin/run   Up      0.0.0.0:80->80/tcp

```

最后，您应该能够在`http://192.168.33.10/`（此 IP 地址已硬编码到 vagrant 配置中）看到包含 PHP 信息输出的页面，如果您在本地浏览器中输入该地址：

![运行 Docker 统计](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00010.jpeg)

现在，您已经启动并运行了一个容器；让我们来看一些基本的统计数据。我们从`docker-compose`的输出中知道我们的容器叫做`01basic_web_1`，所以在终端中输入以下命令来开始流式传输统计数据：

```
docker stats 01basic_web_1

```

这需要一点时间来初始化；完成后，您应该看到您的容器列出以及以下统计信息：

+   `CPU %`：显示容器当前使用的可用 CPU 资源的百分比。

+   `MEM USEAGE/LIMIT`：这告诉你容器正在使用多少 RAM；它还显示了容器的允许量。如果你没有明确设置限制，它将显示主机机器上的 RAM 总量。

+   `MEM %`：这显示了容器使用的 RAM 允许量的百分比。

+   `NET I/O`：这显示了容器传输的带宽总量。

如果你回到浏览器窗口并开始刷新`http://192.168.33.10/`，你会看到每列中的值开始改变。要停止流式传输统计信息，按下*Ctrl* + *c*。

与其一遍又一遍地刷新，不如让我们给`01basic_web_1`生成大量流量，这应该会让容器承受重负。

在这里，我们将启动一个容器，使用 ApacheBench（[`httpd.apache.org/docs/2.2/programs/ab.html`](https://httpd.apache.org/docs/2.2/programs/ab.html)）向`01basic_web_1`发送 10,000 个请求。虽然执行需要一两分钟，但我们应该尽快运行`docker stats`：

```
docker run -d --name=01basic_load --link=01basic_web_1 russmckendrick/ab ab -k -n 10000 -c 5 http://01basic_web_1/ && docker stats 01basic_web_1 01basic_load

```

下载完 ApacheBench 镜像并启动名为`01basic_load`的容器后，你应该在终端中看到`01basic_web_1`和`01basic_load`的统计信息开始流动：

```
CONTAINER     CPU %     MEM USAGE/LIMIT     MEM %    NET I/O
01basic_load  18.11%    12.71 MB/1.905 GB   0.67%    335.2 MB/5.27 MB
01basic_web_1 139.62%   96.49 MB/1.905 GB   5.07%    5.27 MB/335.2 MB

```

过一会儿，你会注意到`01basic_load`的大部分统计数据会降至零；这意味着测试已经完成，运行测试的容器已退出。`docker stats`命令只能流式传输正在运行的容器的统计信息；已退出的容器不再运行，因此在运行`docker stats`时不会产生输出。

使用*Ctrl* + *c*退出`docker stats`；要查看 ApacheBench 命令的结果，可以输入`docker logs 01basic_load`；你应该会看到类似以下截图的内容：

![运行 Docker stats](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00011.jpeg)

如果你看到类似于前面输出中的任何失败，不用担心。这个练习纯粹是为了演示如何查看正在运行的容器的统计信息，而不是调整 Web 服务器来处理我们使用 ApacheBench 发送的流量量。

要删除我们启动的容器，请运行以下命令：

```
[vagrant@centos7 01-basic]$ docker-compose stop
Stopping 01basic_web_1...
[vagrant@centos7 01-basic]$ docker-compose rm
Going to remove 01basic_web_1
Are you sure? [yN] y
Removing 01basic_web_1...
[vagrant@centos7 01-basic]$ docker rm 01basic_load
01basic_load

```

要检查是否一切都已成功删除，请运行`docker ps -a`，你不应该看到任何带有`01basic_`的正在运行或已退出的容器。

# 刚刚发生了什么？

在运行 ApacheBench 测试时，您可能已经注意到运行 NGINX 和 PHP 的容器的 CPU 利用率很高；在前一节的示例中，它使用了可用 CPU 资源的 139.62%。

由于我们没有为启动的容器附加任何资源限制，因此我们的测试很容易使用主机虚拟机（VM）上的所有可用资源。如果这个 VM 被多个用户使用，他们都在运行自己的容器，他们可能已经开始注意到他们的应用程序开始变慢，甚至更糟糕的是，应用程序开始显示错误。

如果您发现自己处于这种情况，您可以使用`docker stats`来帮助追踪罪魁祸首。

运行`docker stats $(docker ps -q)`将为所有当前运行的容器流式传输统计信息：

```
CONTAINER       CPU %     MEM USAGE/LIMIT     MEM %    NET I/O
361040b7b33e    0.07%     86.98 MB/1.905 GB   4.57%    2.514 kB/738 B
56b459ae9092    120.06%   87.05 MB/1.905 GB   4.57%    2.772 kB/738 B
a3de616f84ba    0.04%     87.03 MB/1.905 GB   4.57%    2.244 kB/828 B
abdbee7b5207    0.08%     86.61 MB/1.905 GB   4.55%    3.69 kB/738 B
b85c49cf740c    0.07%     86.15 MB/1.905 GB   4.52%    2.952 kB/738 B

```

正如您可能已经注意到的，这显示的是容器 ID 而不是名称；然而，这些信息应该足够让您快速停止资源占用者：

```
[vagrant@centos7 01-basic]$ docker stop 56b459ae9092
56b459ae9092

```

停止后，您可以通过运行以下命令获取流氓容器的名称：

```
[vagrant@centos7 01-basic]$ docker ps -a | grep 56b459ae9092
56b459ae9092        russmckendrick/nginx-php   "/usr/local/bin/run" 9 minutes ago       Exited (0) 26 seconds ago      my_bad_container

```

或者，为了获得更详细的信息，您可以运行`docker inspect 56b459ae9092`，这将为您提供有关容器的所有所需信息。

# 进程怎么样？

Docker 的一个很棒的特点是它并不是真正的虚拟化；正如前一章所提到的，它是一种很好的隔离进程而不是运行整个操作系统的方法。

当运行诸如`top`或`ps`之类的工具时，这可能会变得令人困惑。为了了解这种情况有多令人困惑，让我们使用`docker-compose`启动几个容器并自己看看：

```
[vagrant@centos7 ~]$ cd /monitoring_docker/Chapter01/02-multiple
[vagrant@centos7 02-multiple]$ docker-compose up -d
Creating 02multiple_web_1...
[vagrant@centos7 02-multiple]$ docker-compose scale web=5
Creating 02multiple_web_2...
Creating 02multiple_web_3...
Creating 02multiple_web_4...
Creating 02multiple_web_5...
Starting 02multiple_web_2...
Starting 02multiple_web_3...
Starting 02multiple_web_4...
Starting 02multiple_web_5...

```

现在，我们有五个 Web 服务器，它们都是使用相同的镜像和相同的配置启动的。当我登录服务器进行故障排除时，我做的第一件事就是运行`ps -aux`；这将显示所有正在运行的进程。正如您所看到的，运行该命令时，列出了许多进程。

甚至只是尝试查看 NGINX 的进程也是令人困惑的，因为没有什么可以区分一个容器和另一个容器的进程，如下面的输出所示：

![进程怎么样？](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00012.jpeg)

那么，您如何知道哪个容器拥有哪些进程呢？

## Docker top

该命令列出了容器内运行的所有进程；可以将其视为对我们在主机上运行的`ps aux`命令输出进行过滤的一种方法：

![Docker top](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00013.jpeg)

由于`docker top`是标准`ps`命令的实现，因此您通常会传递给`ps`的任何标志都应该按照以下方式工作：

```
[vagrant@centos7 02-multiple]$ docker top 02multiple_web_3 –aux
[vagrant@centos7 02-multiple]$ docker top 02multiple_web_3 -faux

```

## Docker exec

查看容器内部发生的情况的另一种方法是进入容器。为了让您能够做到这一点，Docker 引入了`docker exec`命令。这允许您在已经运行的容器内生成一个额外的进程，然后附加到该进程；因此，如果我们想要查看`02multiple_web_3`上当前正在运行的内容，我们应该使用以下命令在已经运行的容器内生成一个 bash shell：

```
docker exec -t -i 02multiple_web_3 bash

```

一旦您在容器上有一个活动的 shell，您会注意到您的提示符已经改变为容器的 ID。您的会话现在被隔离到容器的环境中，这意味着您只能与进程进行交互，这些进程属于您进入的容器。

从这里，您可以像在主机机器上一样运行`ps aux`或`top`命令，并且只能看到与您感兴趣的容器相关的进程：

![Docker exec](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00014.jpeg)

要离开容器，请输入`exit`，您应该看到您的提示符在主机机器上恢复。

最后，您可以通过运行`docker-compose stop`和`docker-compose kill`来停止和删除容器。

# 摘要

在本章中，我们看到了如何实时获取正在运行的容器的统计信息，以及如何使用我们熟悉的命令来获取有关作为每个容器一部分启动的进程的信息。

从表面上看，`docker stats`似乎只是一个非常基本的功能，不过在发生问题时，它实际上是一个帮助您识别哪个容器正在使用所有资源的工具。然而，Docker 命令实际上是从一个非常强大的 API 中提取信息。

这个 API 是我们接下来几章将要看到的许多监控工具的基础。


# 第三章：高级容器资源分析

在上一章中，我们看到了如何使用内置到 Docker 中的 API 来洞察您的容器正在运行的资源。现在，我们将看到如何通过使用谷歌的 cAdvisor 将其提升到下一个级别。在本章中，您将涵盖以下主题：

+   如何安装 cAdvisor 并开始收集指标

+   了解有关 Web 界面和实时监控的所有信息

+   将指标发送到远程 Prometheus 数据库进行长期存储和趋势分析的选项是什么

# cAdvisor 是什么？

谷歌将 cAdvisor 描述如下：

> “cAdvisor（容器顾问）为容器用户提供了对其运行容器的资源使用情况和性能特征的理解。它是一个运行的守护程序，用于收集、聚合、处理和导出有关运行容器的信息。具体来说，对于每个容器，它保留资源隔离参数、历史资源使用情况、完整历史资源使用情况的直方图和网络统计信息。这些数据由容器导出，并且是整个机器范围内的。”

该项目最初是谷歌内部工具，用于洞察使用他们自己的容器堆栈启动的容器。

### 注意

谷歌自己的容器堆栈被称为“让我为你包含”，简称 lmctfy。对 lmctfy 的工作已经安装为谷歌端口功能到 Open Container Initiative 的 libcontainer。有关 lmctfy 的更多详细信息，请访问[`github.com/google/lmctfy/`](https://github.com/google/lmctfy/)。

cAdvisor 是用 Go 编写的（[`golang.org`](https://golang.org)）；您可以编译自己的二进制文件，也可以使用通过容器提供的预编译二进制文件，该容器可从谷歌自己的 Docker Hub 帐户获得。您可以在[`hub.docker.com/u/google/`](http://hub.docker.com/u/google/)找到它。

安装后，cAdvisor 将在后台运行并捕获类似于`docker stats`命令的指标。我们将在本章后面详细了解这些统计数据的含义。

cAdvisor 获取这些指标以及主机机器的指标，并通过一个简单易用的内置 Web 界面公开它们。

# 使用容器运行 cAdvisor

有许多安装 cAdvisor 的方法；开始的最简单方法是下载并运行包含预编译 cAdvisor 二进制文件副本的容器映像。

在运行 cAdvisor 之前，让我们启动一个新的 vagrant 主机：

```
[russ@mac ~]$ cd ~/Documents/Projects/monitoring-docker/vagrant-centos/
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==>default: Importing base box 'russmckendrick/centos71'...
==>default: Matching MAC address for NAT networking...
==>default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==>default: => Installing docker-engine ...
==>default: => Configuring vagrant user ...
==>default: => Starting docker-engine ...
==>default: => Installing docker-compose ...
==>default: => Finished installation of Docker
[russ@mac ~]$ vagrantssh

```

### 提示

**使用反斜杠**

由于我们有很多选项要传递给`docker run`命令，我们使用`\`来将命令拆分成多行，以便更容易跟踪发生了什么。

一旦您可以访问主机，运行以下命令：

```
docker run \
--detach=true \
--volume=/:/rootfs:ro \
--volume=/var/run:/var/run:rw \
--volume=/sys:/sys:ro \
--volume=/var/lib/docker/:/var/lib/docker:ro \
--publish=8080:8080 \
--privileged=true \
--name=cadvisor \
google/cadvisor:latest

```

现在您应该在主机上运行一个 cAdvisor 容器。在开始之前，让我们通过讨论为什么我们传递了所有选项给容器来更详细地了解 cAdvisor。

cAdvisor 二进制文件设计为在主机上与 Docker 二进制文件一起运行，因此通过在容器中启动 cAdvisor，我们实际上是将二进制文件隔离在其自己的环境中。为了让 cAdvisor 访问主机上需要的资源，我们必须挂载几个分区，并且还要给容器特权访问权限，让 cAdvisor 二进制文件认为它是在主机上执行的。

### 注意

当一个容器使用`--privileged`启动时，Docker 将允许对主机上的设备进行完全访问；此外，Docker 将配置 AppArmor 或 SELinux，以允许您的容器与在容器外部运行的进程具有相同的对主机的访问权限。有关`--privileged`标志的信息，请参阅 Docker 博客上的这篇文章[`blog.docker.com/2013/09/docker-can-now-run-within-docker/`](http://blog.docker.com/2013/09/docker-can-now-run-within-docker/)。

# 从源代码编译 cAdvisor

如前一节所述，cAdvisor 实际上应该在主机上执行；这意味着，您可能需要使用一个案例来编译自己的 cAdvisor 二进制文件并直接在主机上运行它。

要编译 cAdvisor，您需要执行以下步骤：

1.  在主机上安装 Go 和 Mercurial——需要版本 1.3 或更高版本的 Go 来编译 cAdvisor。

1.  设置 Go 的工作路径。

1.  获取 cAdvisor 和 godep 的源代码。

1.  设置 Go 二进制文件的路径。

1.  使用 godep 构建 cAdvisor 二进制文件以为我们提供依赖项。

1.  将二进制文件复制到`/usr/local/bin/`。

1.  下载`Upstart`或`Systemd`脚本并启动进程。

如果您按照上一节中的说明操作，您已经有一个 cAdvisor 进程正在运行。在从源代码编译之前，您应该从一个干净的主机开始；让我们注销主机并启动一个新的副本：

```
[vagrant@centos7 ~]$ exit
logout
Connection to 127.0.0.1 closed.
[russ@mac ~]$ vagrant destroy
default: Are you sure you want to destroy the 'default' VM? [y/N] y
==>default: Forcing shutdown of VM...
==>default: Destroying VM and associated drives...
==>default: Running cleanup tasks for 'shell' provisioner...
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==>default: Importing base box 'russmckendrick/centos71'...
==>default: Matching MAC address for NAT networking...
==>default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==>default: => Installing docker-engine ...
==>default: => Configuring vagrant user ...
==>default: => Starting docker-engine ...
==>default: => Installing docker-compose ...
==>default: => Finished installation of Docker
[russ@mac ~]$ vagrantssh

```

要在 CentOS 7 主机上构建 cAdvisor，请运行以下命令：

```
sudo yum install -y golanggit mercurial
export GOPATH=$HOME/go
go get -d github.com/google/cadvisor
go get github.com/tools/godep
export PATH=$PATH:$GOPATH/bin
cd $GOPATH/src/github.com/google/cadvisor
godep go build .
sudocpcadvisor /usr/local/bin/
sudowgethttps://gist.githubusercontent.com/russmckendrick/f647b2faad5d92c96771/raw/86b01a044006f85eebbe395d3857de1185ce4701/cadvisor.service -O /lib/systemd/system/cadvisor.service
sudosystemctl enable cadvisor.service
sudosystemctl start cadvisor

```

在 Ubuntu 14.04 LTS 主机上，运行以下命令：

```
sudo apt-get -y install software-properties-common
sudo add-apt-repository ppa:evarlast/golang1.4
sudo apt-get update

sudo apt-get -y install golang mercurial

export GOPATH=$HOME/go
go get -d github.com/google/cadvisor
go get github.com/tools/godep
export PATH=$PATH:$GOPATH/bin
cd $GOPATH/src/github.com/google/cadvisor
godep go build .
sudocpcadvisor /usr/local/bin/
sudowgethttps://gist.githubusercontent.com/russmckendrick/f647b2faad5d92c96771/raw/e12c100d220d30c1637bedd0ce1c18fb84beff77/cadvisor.conf -O /etc/init/cadvisor.conf
sudo start cadvisor

```

您现在应该有一个正在运行的 cAdvisor 进程。您可以通过运行`ps aux | grep cadvisor`来检查，您应该会看到一个路径为`/usr/local/bin/cadvisor`的进程正在运行。

# 收集指标

现在，您已经运行了 cAdvisor；为了开始收集指标，您需要做些什么？简短的答案是，根本不需要做任何事情。当您启动 cAdvisor 进程时，它立即开始轮询您的主机机器，以查找正在运行的容器，并收集有关正在运行的容器和主机机器的信息。

# Web 界面

cAdvisor 应该在`8080`端口上运行；如果您打开`http://192.168.33.10:8080/`，您应该会看到 cAdvisor 的标志和主机机器的概述：

![Web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00015.jpeg)

这个初始页面会实时传输有关主机机器的统计信息，尽管每个部分在您开始深入查看容器时都会重复。首先，让我们使用主机信息查看每个部分。

## 概览

这个概览部分为您提供了对系统的鸟瞰视图；它使用标尺，因此您可以快速了解哪些资源正在达到其限制。在下面的截图中，CPU 利用率很低，文件系统使用率相对较低；但是，我们使用了可用 RAM 的 64%：

![概览](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00016.jpeg)

## 进程

以下截图显示了我们在上一章中使用的`ps aux`，`dockerps`和`top`命令的输出的综合视图：

![进程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00017.jpeg)

以下是每个列标题的含义：

+   **用户**：这显示运行进程的用户

+   **PID**：这是唯一的进程 ID

+   **PPID**：这是父进程的**PID**

+   **启动时间**：这显示进程启动的时间

+   **CPU%**：这是进程当前消耗的 CPU 的百分比

+   **内存%**：这是进程当前消耗的 RAM 的百分比

+   **RSS**：这显示进程正在使用的主内存量

+   **虚拟大小**：这显示进程正在使用的虚拟内存量

+   **状态**：显示进程的当前状态；这些是标准的 Linux 进程状态代码

+   **运行时间**：显示进程运行的时间

+   **命令**：显示进程正在运行的命令

+   **容器**：显示进程附加到的容器；列为`/`的容器是主机机器

由于可能有数百个活动进程，此部分分为页面；您可以使用左下角的按钮导航到这些页面。此外，您可以通过单击任何标题对进程进行排序。

## CPU

以下图表显示了过去一分钟的 CPU 利用率：

![CPU](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00018.jpeg)

以下是每个术语的含义：

+   **总使用情况**：显示所有核心的总体使用情况

+   **每核使用情况**：此图表显示每个核的使用情况

+   **使用情况细分**（在上一个截图中未显示）：显示所有核心的总体使用情况，但将其细分为内核使用和用户拥有的进程使用

## 内存

**内存**部分分为两部分。图表告诉您所有进程使用的主机或容器的内存总量；这是热内存和冷内存的总和。**热**内存是当前的工作集：最近被内核访问的页面。**冷**内存是一段时间没有被访问的页面，如果需要可以回收。

**使用情况细分**以可视化方式表示了主机机器的总内存或容器的允许量，以及总使用量和热使用量。

![内存](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00019.jpeg)

## 网络

此部分显示了过去一分钟的传入和传出流量。您可以使用左上角的下拉框更改接口。还有一个图表显示任何网络错误。通常，此图表应该是平的。如果不是，那么您将看到主机机器或容器的性能问题：

![网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00020.jpeg)

## 文件系统

最后一部分显示了文件系统的使用情况。在下一个截图中，`/dev/sda1`是引导分区，`/dev/sda3`是主文件系统，`/dev/mapper/docker-8…`是正在运行的容器的写文件系统的总和：

![文件系统](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00021.jpeg)

# 查看容器统计信息

页面顶部有一个您正在运行的容器的链接；您可以单击该链接，也可以直接转到`http://192.168.33.10:8080/docker/`。页面加载后，您应该会看到所有正在运行的容器的列表，以及 Docker 进程的详细概述，最后是您已下载的镜像列表。

## 子容器

子容器显示了您的容器列表；每个条目都是一个可点击的链接，点击后将带您到一个页面，该页面将提供以下详细信息：

+   隔离：

+   **CPU**：这显示了容器的 CPU 允许量；如果您没有设置任何资源限制，您将看到主机的 CPU 信息

+   **内存**：这显示了容器的内存允许量；如果您没有设置任何资源限制，您的容器将显示无限制的允许量

+   用法：

+   **概览**：这显示了仪表，让您快速了解您距离任何资源限制有多近

+   **进程**：这显示了您选择的容器的进程

+   **CPU**：这显示了仅针对您的容器的 CPU 利用率图

+   **内存**：这显示了您容器的内存利用情况

## 驱动程序状态

该驱动程序提供了有关主要 Docker 进程的基本统计信息，以及有关主机机器的内核、主机名以及底层操作系统的信息。

它还提供了有关容器和镜像的总数的信息。您可能会注意到镜像的总数比您预期看到的要大得多；这是因为它将每个文件系统都计算为一个单独的镜像。

### 注意

有关 Docker 镜像的更多详细信息，请参阅 Docker 用户指南[`docs.docker.com/userguide/dockerimages/`](https://docs.docker.com/userguide/dockerimages/)。

它还为您提供了存储配置的详细分解。

## 镜像

最后，您将获得主机机器上可用的 Docker 镜像列表。它列出了存储库、标签、大小以及镜像创建的时间，以及镜像的唯一 ID。这让您知道镜像的来源（存储库）、您已下载的镜像的版本（标签）以及镜像的大小（大小）。

# 这一切都很棒，有什么问题吗？

所以您可能会想，您在浏览器中获得的所有这些信息真的很有用；能够以易于阅读的格式查看实时性能指标真的是一个很大的优势。

使用 cAdvisor 的 Web 界面最大的缺点，正如你可能已经注意到的，就是它只会显示一分钟的指标；你可以实时看到信息消失。

就像玻璃窗格可以实时查看您的容器一样，cAdvisor 是一个很棒的工具；如果您想查看超过一分钟的任何指标，那就没那么幸运了。

也就是说，除非你在某个地方配置存储所有数据；这就是 Prometheus 的用武之地。

# Prometheus

那么 Prometheus 是什么？它的开发人员描述如下：

> Prometheus 是一个在 SoundCloud 建立的开源系统监控和警报工具包。自 2012 年推出以来，它已成为在 SoundCloud 上为新服务进行仪表化的标准，并且正在看到越来越多的外部使用和贡献。

好吧，但这与 cAdvisor 有什么关系？嗯，Prometheus 有一个非常强大的数据库后端，它将导入的数据存储为事件的时间序列。

维基百科对时间序列的描述如下：

> *"时间序列是一系列数据点，通常由在一段时间间隔内进行的连续测量组成。时间序列的例子包括海洋潮汐、太阳黑子的计数和道琼斯工业平均指数的每日收盘价。时间序列经常通过折线图绘制。"*
> 
> *[`en.wikipedia.org/wiki/Time_series`](https://en.wikipedia.org/wiki/Time_series)*

cAdvisor 默认会做的一件事是在`/metrics`上公开它捕获的所有指标；您可以在我们的 cAdvisor 安装的`http://192.168.33.10:8080/metrics`上看到这一点。这些指标在每次加载页面时都会更新：

![Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00022.jpeg)

正如您在前面的屏幕截图中所看到的，这只是一个单独的长页面原始文本。Prometheus 的工作方式是，您配置它以在用户定义的间隔时间内抓取`/metrics` URL，比如每五秒；文本以 Prometheus 理解的格式，并被摄入到 Prometheus 的时间序列数据库中。

这意味着，使用 Prometheus 强大的内置查询语言，您可以开始深入挖掘您的数据。让我们来看看如何启动和运行 Prometheus。

## 启动 Prometheus

与 cAdvisor 一样，您可以以几种方式启动 Prometheus。首先，我们将启动一个容器，并注入我们自己的配置文件，以便 Prometheus 知道我们的 cAdvisor 端点在哪里：

```
docker run \
--detach=true \
--volume=/monitoring_docker/Chapter03/prometheus.yml:/etc/prometheus/prometheus.yml \
--publish=9090:9090 \
--name=prometheus \
prom/prometheus:latest

```

一旦您启动了容器，Prometheus 将可以通过以下 URL 访问：`http://192.168.33.10:9090`。当您首次加载 URL 时，您将被带到一个状态页面；这提供了有关 Prometheus 安装的一些基本信息。此页面的重要部分是目标列表。这列出了 Prometheus 将抓取以捕获指标的 URL；您应该看到您的 cAdvisor URL 列在其中，并显示为**HEALTHY**，如下面的截图所示：

![启动 Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00023.jpeg)

另一个信息页面包含以下内容：

+   **运行时信息**：显示 Prometheus 已经运行并轮询数据的时间，如果您已经配置了一个端点

+   **构建信息**：这包含了您正在运行的 Prometheus 版本的详细信息

+   **配置**：这是我们在启动容器时注入的配置文件的副本

+   **规则**：这是我们注入的任何规则的副本；这些将用于警报

+   **启动标志**：显示所有运行时变量及其值

## 查询 Prometheus

由于我们目前只有几个容器正在运行，让我们启动一个运行 Redis 的容器，这样我们就可以开始查看内置在 Prometheus 中的查询语言。

我们将使用官方的 Redis 镜像，并且我们只会将其用作示例，因此我们不需要传递任何用户变量：

```
docker run --name my-redis-server -d redis

```

我们现在有一个名为`my-redis-server`的容器正在运行。 cAdvisor 应该已经在向 Prometheus 公开有关容器的指标；让我们继续查看。在 Prometheus Web 界面中，转到页面顶部菜单中的**Graph**链接。在这里，您将看到一个文本框，您可以在其中输入查询。首先，让我们查看 Redis 容器的 CPU 使用情况。

在框中输入以下内容：

```
container_cpu_usage_seconds_total{job="cadvisor",name="my-redis-server"}
```

然后，点击**Execute**后，您应该会得到两个结果，列在页面的**Console**选项卡中。如果您记得，cAdvisor 记录容器可以访问的每个 CPU 核的 CPU 使用情况，这就是为什么我们得到了两个值，一个是"cpu00"，另一个是"cpu01"。点击**Graph**链接将显示一段时间内的结果：

![查询 Prometheus](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00024.jpeg)

正如您在上面的截图中所看到的，我们现在可以访问过去 25 分钟的使用情况图表，这大约是我在生成图表之前启动 Redis 实例的时间。

## 仪表板

此外，在主应用程序中使用查询工具创建图表时，您可以安装一个单独的仪表板应用程序。这个应用程序运行在第二个容器中，通过 API 连接到您的主 Prometheus 容器作为数据源。

在启动仪表板容器之前，我们应该初始化一个 SQLite3 数据库来存储我们的配置。为了确保数据库是持久的，我们将把它存储在主机机器上的`/tmp/prom/file.sqlite3`中：

```
docker run \
--volume=/tmp/prom:/tmp/prom \
-e DATABASE_URL=sqlite3:/tmp/prom/file.sqlite3 \
prom/promdash ./bin/rake db:migrate

```

一旦我们初始化了数据库，我们就可以正常启动仪表板应用程序了：

```
docker run \
--detach=true \
--volume=/tmp/prom:/tmp/prom \
-e DATABASE_URL=sqlite3:/tmp/prom/file.sqlite3 \
--publish=3000:3000  \
--name=promdash \
prom/promdash

```

该应用程序现在应该可以在`http://192.168.33.10:3000/`上访问。我们需要做的第一件事是设置数据源。要做到这一点，点击屏幕顶部的**服务器**链接，然后点击**新服务器**。在这里，您将被要求提供您的 Prometheus 服务器的详细信息。命名服务器并输入以下 URL：

+   **名称**：`cAdvisor`

+   **URL**：`http://192.168.33.10:9090`

+   **服务器类型**：`Prometheus`

一旦您点击**创建服务器**，您应该会收到一条消息，上面写着**服务器已成功创建**。接下来，您需要创建一个`目录`；这是您的仪表板将被存储的地方。

点击顶部菜单中的**仪表板**链接，然后点击**新目录**，创建一个名为`测试目录`的目录。现在，您可以开始创建仪表板了。点击**新仪表板**，命名为**我的仪表板**，放置在`测试目录`中。一旦您点击**创建仪表板**，您将进入预览屏幕。

从这里，您可以使用每个部分右上角的控件来构建仪表板。要添加数据，您只需在仪表板部分输入您想要查看的查询：

![仪表板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00025.jpeg)

### 注意

有关如何创建仪表板的详细信息，请参阅 Prometheus 文档中的**PROMDASH**部分，网址为[`prometheus.io/docs/visualization/promdash/`](http://prometheus.io/docs/visualization/promdash/)。

## 接下来的步骤

目前，我们正在单个容器中运行 Prometheus，并且其数据存储在同一个容器中。这意味着，如果由于任何原因容器被终止，我们的数据就会丢失；这也意味着我们无法升级而不丢失数据。为了解决这个问题，我们可以创建一个数据卷容器。

### 注意

数据卷容器是一种特殊类型的容器，仅用作其他容器的存储。有关更多详细信息，请参阅 Docker 用户指南[`docs.docker.com/userguide/dockervolumes/#creating-and-mounting-a-data-volume-container`](https://docs.docker.com/userguide/dockervolumes/#creating-and-mounting-a-data-volume-container)。

首先，让我们确保已删除所有正在运行的 Prometheus 容器：

```
docker stop prometheus&&dockerrm Prometheus

```

接下来，让我们创建一个名为`promdata`的数据容器：

```
docker create \
--volume=/promdata \
--name=promdata \
prom/prometheus /bin/true

```

最后，再次启动 Prometheus，这次使用数据容器：

```
docker run \
--detach=true \
--volumes-from promdata \
--volume=/monitoring_docker/Chapter03/prometheus.yml:/etc/prometheus/prometheus.yml \
--publish=9090:9090 \
--name=prometheus \
prom/prometheus

```

这将确保，如果您必须升级或重新启动容器，您一直在捕获的指标是安全的。

在本书的本节中，我们只是简单介绍了使用 Prometheus 的基础知识；有关该应用程序的更多信息，我建议以下链接作为一个很好的起点：

+   文档：[`prometheus.io/docs/introduction/overview/`](http://prometheus.io/docs/introduction/overview/)

+   Twitter：[`twitter.com/PrometheusIO`](https://twitter.com/PrometheusIO)

+   项目页面：[`github.com/prometheus/prometheus`](https://github.com/prometheus/prometheus)

+   Google 群组：[`groups.google.com/forum/#!forum/prometheus-developers`](https://groups.google.com/forum/#!forum/prometheus-developers)

# 其他选择？

Prometheus 有一些替代方案。其中一个替代方案是 InfluxDB，它自述如下：

> 一个无需外部依赖的开源分布式时间序列数据库。

然而，在撰写本文时，cAdvisor 目前与最新版本的 InfluxDB 不兼容。cAdvisor 的代码库中有补丁；然而，这些补丁尚未通过由 Google 维护的 Docker 镜像。

有关 InfluxDB 及其新的可视化投诉应用 Chronograf 的更多详细信息，请参阅项目网站[`influxdb.com/`](https://influxdb.com/)，有关如何将 cAdvisor 统计数据导出到 InfluxDB 的更多详细信息，请参阅 cAdvisor 的支持文档[`github.com/google/cadvisor/tree/master/docs`](https://github.com/google/cadvisor/tree/master/docs)。

# 总结

在本章中，我们学习了如何将容器的实时统计信息从命令行转移到 Web 浏览器中进行查看。我们探讨了一些不同的方法来安装谷歌的 cAdvisor 应用程序，以及如何使用其 Web 界面来监视我们正在运行的容器。我们还学习了如何从 cAdvisor 捕获指标并使用 Prometheus 存储这些指标，Prometheus 是一种现代时间序列数据库。

本章涵盖的两种主要技术仅在公开市场上可用不到十二个月。在下一章中，我们将介绍如何使用一种监控工具，这种工具已经在系统管理员的工具箱中使用了超过 10 年——Zabbix。


# 第四章：监控容器的传统方法

到目前为止，我们只看了一些监控容器的技术，因此在本章中，我们将更多地关注传统的监控服务工具。在本章结束时，您应该了解 Zabbix 以及您可以监控容器的各种方式。本章将涵盖以下主题：

+   如何使用容器运行 Zabbix 服务器

+   如何在 vagrant 机器上启动 Zabbix 服务器

+   如何准备我们的主机系统，使用 Zabbix 代理监控容器

+   如何在 Zabbix Web 界面中找到自己的位置

# Zabbix

首先，什么是 Zabbix，为什么要使用它？

我个人从 1.2 版本开始使用它；Zabbix 网站对其描述如下：

> “使用 Zabbix，可以从网络中收集几乎无限类型的数据。高性能实时监控意味着可以同时监控数万台服务器、虚拟机和网络设备。除了存储数据外，还提供了可视化功能（概览、地图、图表、屏幕等），以及非常灵活的数据分析方式，用于警报目的。”
> 
> “Zabbix 提供了出色的数据收集性能，并可以扩展到非常大的环境。使用 Zabbix 代理可以进行分布式监控。Zabbix 带有基于 Web 的界面、安全用户认证和灵活的用户权限模式。支持轮询和陷阱，具有从几乎任何流行操作系统收集数据的本机高性能代理；也提供了无代理的监控方法。”

在我开始使用 Zabbix 的时候，唯一真正可行的选择如下：

+   Nagios：[`www.nagios.org/`](https://www.nagios.org/)

+   Zabbix：[`www.zabbix.com/`](http://www.zabbix.com/)

+   Zenoss：[`www.zenoss.org/`](http://www.zenoss.org/)

在这三个选项中，当时 Zabbix 似乎是最直接的选择。它足以管理我要监控的几百台服务器，而无需额外学习设置 Nagios 或 Zenoss 的复杂性；毕竟，考虑到软件的任务，我需要相信我已经正确设置了它。

在本章中，虽然我将详细介绍设置和使用 Zabbix 的基础知识，但我们只会涉及一些功能，它可以做的远不止监视您的容器。有关更多信息，我建议以下作为一个很好的起点：

+   Zabbix 博客：[`blog.zabbix.com`](http://blog.zabbix.com)

+   Zabbix 2.4 手册：[`www.zabbix.com/documentation/2.4/manual`](https://www.zabbix.com/documentation/2.4/manual)

+   更多阅读：[`www.packtpub.com/all/?search=zabbix`](https://www.packtpub.com/all/?search=zabbix)

# 安装 Zabbix

正如您可能已经从上一节的链接中注意到的那样，Zabbix 中有很多活动部分。它利用了几种开源技术，而且一个生产就绪的安装需要比我们在本章中所能涉及的更多的规划。因此，我们将看一下两种快速安装 Zabbix 的方法，而不是过多地详细介绍。

## 使用容器

在撰写本文时，Docker Hub（[`hub.docker.com`](https://hub.docker.com)）上有 100 多个 Docker 镜像提到了 Zabbix。这些范围从完整的服务器安装到各种部分，如 Zabbix 代理或代理服务。

在列出的选项中，有一个是 Zabbix 本身推荐的。因此，我们将看一下这个；它可以在以下网址找到：

+   Docker Hub：[`hub.docker.com/u/zabbix/`](https://hub.docker.com/u/zabbix/)

+   项目页面：[`github.com/zabbix/zabbix-community-docker`](https://github.com/zabbix/zabbix-community-docker)

要使`ZabbixServer`容器运行起来，我们必须首先启动一个数据库容器。让我们通过运行以下命令从头开始使用我们的 vagrant 实例：

```
[russ@mac ~]$ cd ~/Documents/Projects/monitoring-docker/vagrant-centos/
[russ@mac ~]$ vagrant destroy
default: Are you sure you want to destroy the 'default' VM? [y/N] y
==>default: Forcing shutdown of VM...
==>default: Destroying VM and associated drives...
==>default: Running cleanup tasks for 'shell' provisioner...
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==>default: Importing base box 'russmckendrick/centos71'...
==>default: Matching MAC address for NAT networking...
==>default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==>default: => Installing docker-engine ...
==>default: => Configuring vagrant user ...
==>default: => Starting docker-engine ...
==>default: => Installing docker-compose ...
==>default: => Finished installation of Docker
[russ@mac ~]$ vagrantssh

```

现在，我们有一个干净的环境，是时候启动我们的数据库容器了，如下所示：

```
docker run \
--detach=true \
--publish=3306 \
--env="MARIADB_USER=zabbix" \
--env="MARIADB_PASS=zabbix_password" \
--name=zabbix-db \
million12/mariadb

```

这将从[`hub.docker.com/r/million12/mariadb/`](https://hub.docker.com/r/million12/mariadb/)下载`million12/mariadb`镜像，并启动一个名为`zabbix-db`的容器，运行 MariaDB 10（[`mariadb.org`](https://mariadb.org)），使用名为`zabbix`的用户，密码为`zabbix_password`。我们还在容器上打开了 MariaDB 端口`3306`，但由于我们将从链接的容器连接到它，因此无需在主机上暴露该端口。

现在，我们的数据库容器已经运行起来了，现在我们需要启动我们的 Zabbix 服务器容器：

```
docker run \
--detach=true \
--publish=80:80 \
--publish=10051:10051 \
--link=zabbix-db:db \
--env="DB_ADDRESS=db" \
--env="DB_USER=zabbix" \
--env="DB_PASS=zabbix_password" \
--name=zabbix \
zabbix/zabbix-server-2.4

```

这将下载镜像，目前为止，镜像大小超过 1GB，因此这个过程可能需要几分钟，具体取决于您的连接速度，并启动一个名为`zabbix`的容器。它将主机上的 Web 服务器（端口`80`）和 Zabbix 服务器进程（端口`10051`）映射到容器上，创建到我们数据库容器的链接，设置别名`db`，并将数据库凭据作为环境变量注入，以便在容器启动时运行的脚本可以填充数据库。

您可以通过检查容器上的日志来验证一切是否按预期工作。要做到这一点，输入`docker logs zabbix`。这将在屏幕上打印容器启动时发生的详细信息：

![使用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00026.jpeg)

现在，一旦我们启动了容器，就该转到浏览器，体验一下网络界面。在浏览器中输入`http://192.168.33.10/`，您将看到一个欢迎页面；在我们开始使用 Zabbix 之前，我们需要完成安装。

在欢迎页面上，点击**下一步**进入第一步。这将验证我们运行 Zabbix 服务器所需的一切是否都已安装。由于我们在容器中启动了它，您应该看到所有先决条件旁边都有**OK**。点击**下一步**进入下一步。

现在，我们需要为网络界面配置数据库连接。在这里，您应该有与启动容器时相同的细节，如下面的截图所示：

![使用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00027.jpeg)

一旦输入了详细信息，点击**测试连接**，您应该收到一个**OK**的消息；在此测试成功完成之前，您将无法继续。一旦输入了详细信息并收到了**OK**消息，点击**下一步**。

接下来是网络界面需要连接的 Zabbix 服务器的详细信息；在这里点击**下一步**。接下来，您将收到安装的摘要。要继续，请点击**下一步**，您将收到确认`/usr/local/src/zabbix/frontends/php/conf/zabbix.conf.php`文件已创建的消息。点击**完成**进入登录页面。

## 使用 vagrant

在撰写本章时，我考虑了为 Zabbix 服务器服务提供另一组安装说明。虽然本书都是关于监控 Docker 容器，但在容器内运行像 Zabbix 这样资源密集型的服务感觉有点违反直觉。因此，有一个 vagrant 机器使用 Puppet 来引导 Zabbix 服务器的工作安装：

```
[russ@mac ~]$ cd ~/Documents/Projects/monitoring-docker/vagrant-zabbix/
[russ@mac ~]$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==>default: Importing base box 'russmckendrick/centos71'...
==>default: Matching MAC address for NAT networking...
==>default: Checking if box 'russmckendrick/centos71' is up to date...

.....

==>default: Debug: Received report to process from zabbix.media-glass.es
==>default: Debug: Evicting cache entry for environment 'production'
==>default: Debug: Caching environment 'production' (ttl = 0 sec)
==>default: Debug: Processing report from zabbix.media-glass.es with processor Puppet::Reports::Store

```

您可能已经注意到，有大量的输出流到终端，那刚刚发生了什么？首先，启动了一个 CentOS 7 vagrant 实例，然后安装了 Puppet 代理。一旦安装完成，安装就交给了 Puppet。使用 Werner Dijkerman 的 Zabbix Puppet 模块，安装了 Zabbix 服务器；有关该模块的更多详细信息，请参阅其 Puppet Forge 页面[`forge.puppetlabs.com/wdijkerman/zabbix`](https://forge.puppetlabs.com/wdijkerman/zabbix)。

与 Zabbix 服务器的容器化版本不同，不需要额外的配置，因此您应该能够访问 Zabbix 登录页面[`zabbix.media-glass.es/`](http://zabbix.media-glass.es/)（配置中硬编码了 IP 地址`192.168.33.11`）。

## 准备我们的主机机器

在本章的其余部分，我将假设您正在使用在其自己的 vagrant 实例上运行的 Zabbix 服务器。这有助于确保您的环境与我们将要查看的 Zabbix 代理的配置一致。

为了将我们容器的统计数据传递给 Zabbix 代理，然后再将其暴露给 Zabbix 服务器，我们将使用由 Jan Garaj 开发的`Zabbix-Docker-Monitoring` Zabbix 代理模块进行安装。有关该项目的更多信息，请参见以下 URL：

+   项目页面：[`github.com/monitoringartist/Zabbix-Docker-Monitoring/`](https://github.com/monitoringartist/Zabbix-Docker-Monitoring/)

+   Zabbix 共享页面：[`share.zabbix.com/virtualization/docker-containers-monitoring`](https://share.zabbix.com/virtualization/docker-containers-monitoring)

为了安装、配置和运行代理和模块，我们需要执行以下步骤：

1.  安装 Zabbix 软件包存储库。

1.  安装 Zabbix 代理。

1.  安装模块的先决条件。

1.  将 Zabbix 代理用户添加到 Docker 组。

1.  下载自动发现的 bash 脚本。

1.  下载预编译的`zabbix_module_docker`二进制文件。

1.  使用我们的 Zabbix 服务器的详细信息以及 Docker 模块配置 Zabbix 代理。

1.  设置我们下载和创建的所有文件的正确权限。

1.  启动 Zabbix 代理。

虽然 CentOS 和 Ubuntu 的步骤是相同的，但进行初始软件包安装的操作略有不同。与其逐步显示安装和配置代理的命令，不如在`/monitoring_docker/chapter04/`文件夹中为每个主机操作系统准备一个脚本。要查看脚本，请从终端运行以下命令：

```
cat /monitoring_docker/chapter04/install-agent-centos.sh
cat /monitoring_docker/chapter04/install-agent-ubuntu.sh

```

现在，您已经查看了脚本，是时候运行它们了，要做到这一点，请输入以下命令之一。如果您正在运行 CentOS，请运行此命令：

```
bash /monitoring_docker/chapter04/install-agent-centos.sh

```

对于 Ubuntu，运行以下命令：

```
bash /monitoring_docker/chapter04/install-agent-ubuntu.sh

```

要验证一切是否按预期运行，请运行以下命令检查 Zabbix 代理日志文件：

```
cat /var/log/zabbix/zabbix_agentd.log

```

您应该会看到文件末尾确认代理已启动，并且`zabbix_module_docker.so`模块已加载：

![准备我们的主机](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00028.jpeg)

在我们进入 Zabbix Web 界面之前，让我们使用第二章中的`docker-compose`文件启动一些容器，*使用内置工具*：

```
[vagrant@docker ~]$ cd /monitoring_docker/chapter02/02-multiple/
[vagrant@docker 02-multiple]$ docker-compose up -d
[vagrant@docker 02-multiple]$ docker-compose scale web=3
[vagrant@docker 02-multiple]$ docker-compose ps

```

我们现在应该有三个运行中的 Web 服务器容器和一个在主机上运行的 Zabbix 代理。

## Zabbix Web 界面

一旦您安装了 Zabbix，您可以通过在浏览器中输入[`zabbix.media-glass.es/`](http://zabbix.media-glass.es/)来打开 Zabbix Web 界面，只有在 Zabbix 虚拟机正常运行时，此链接才有效，否则页面将超时。您应该会看到一个登录界面。在这里输入默认的用户名和密码，即`Admin`和`zabbix`（请注意用户名的*A*是大写），然后登录。

登录后，您需要添加主机模板。这些是预配置的环境设置，将为 Zabbix 代理发送到服务器的统计信息添加一些上下文，以及容器的自动发现。

要添加模板，转到顶部菜单中的**配置**选项卡，然后选择**模板**；这将显示当前安装的所有模板的列表。点击标题中的**导入**按钮，并上传两个模板文件的副本，您可以在主机的`~/Documents/Projects/monitoring-docker/chapter04/template`文件夹中找到；上传模板时无需更改规则。

一旦两个模板成功导入，就该是添加我们的 Docker 主机的时候了。再次，转到**配置**选项卡，但这次选择**主机**。在这里，您需要点击**创建主机**。然后，在**主机**选项卡中输入以下信息：

![Zabbix web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00029.jpeg)

以下是前述信息的详细信息：

+   **主机名**：这是我们 Docker 主机的主机名

+   **可见名称**：在 Zabbix 中将显示名称服务器

+   **组**：您希望 Docker 主机成为 Zabbix 中的哪个组

+   **代理接口**：这是我们 Docker 主机的 IP 地址或 DNS 名称

+   **已启用**：应该打勾

在点击**添加**之前，您应该点击**模板**选项卡，并将以下两个模板链接到主机：

+   **模板 App Docker**

+   **模板 OS Linux**

这是主机的屏幕截图：

![Zabbix web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00030.jpeg)

一旦添加了两个模板，点击**添加**以配置和启用主机。要验证主机是否已正确添加，您应该转到**监控**选项卡，然后**最新数据**。从这里，点击**显示过滤器**，并在**主机**框中输入主机机器。然后您应该开始看到项目出现：

![Zabbix web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00031.jpeg)

如果您立即看不到**Docker**部分，不要担心，默认情况下，Zabbix 将每五分钟尝试自动发现新容器。

# Docker 指标

对于每个容器，Zabbix 发现将记录以下指标：

+   容器（您的容器名称）正在运行

+   CPU 系统时间

+   CPU 用户时间

+   已使用的缓存内存

+   已使用的 RSS 内存

+   已使用的交换空间

除了“已使用的交换空间”外，这些都是 cAdvisor 记录的相同指标。

## 创建自定义图表

您可以访问 Zabbix 收集的任何指标的基于时间的图表；您还可以创建自己的自定义图表。在下图中，我创建了一个图表，绘制了我们在本章早些时候启动的三个 Web 容器的所有 CPU 系统统计信息：

![创建自定义图表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00032.jpeg)

正如您所见，我使用 ApacheBench 进行了一些测试，以使图表更加有趣。

有关如何创建自定义图表的更多信息，请参阅文档站点的图表部分[`www.zabbix.com/documentation/2.4/manual/config/visualisation/graphs`](https://www.zabbix.com/documentation/2.4/manual/config/visualisation/graphs)。

## 将容器与主机进行比较

由于我们已将 Linux OS 模板和 Docker 模板添加到主机，并且还记录了系统的大量信息，因此我们可以看出使用 ApacheBench 进行测试对整体处理器负载的影响：

![将容器与主机进行比较](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00033.jpeg)

我们可以进一步深入了解整体利用情况的信息：

![将容器与主机进行比较](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00034.jpeg)

## 触发器

Zabbix 的另一个特性是触发器：您可以定义当指标满足一定一组条件时发生的操作。在以下示例中，Zabbix 已配置了一个名为**容器下线**的触发器；这将将受监视项的状态更改为**问题**，严重性为**灾难**：

![触发器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00035.jpeg)

然后，状态的变化会触发一封电子邮件通知，通知某种原因导致容器不再运行：

![触发器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00036.jpeg)

这也可能触发其他任务，例如运行自定义脚本、通过 Jabber 发送即时消息，甚至触发 PagerDuty（[`www.pagerduty.com`](https://www.pagerduty.com)）或 Slack（[`slack.com`](https://slack.com)）等第三方服务。

有关触发器、事件和通知的更多信息，请参阅以下文档部分：

+   [`www.zabbix.com/documentation/2.4/manual/config/triggers`](https://www.zabbix.com/documentation/2.4/manual/config/triggers)

+   [`www.zabbix.com/documentation/2.4/manual/config/events`](https://www.zabbix.com/documentation/2.4/manual/config/events)

+   [`www.zabbix.com/documentation/2.4/manual/config/notifications`](https://www.zabbix.com/documentation/2.4/manual/config/notifications)

# 摘要

那么，这种传统的监控方法如何适应容器的生命周期呢？

回到宠物与牛群的比喻，乍一看，Zabbix 似乎更适合宠物：其功能集最适合监控长时间内静态的服务。这意味着监控宠物的相同方法也可以应用于在您的容器中运行的长时间进程。

Zabbix 也是监控混合环境的完美选择。也许您有几台数据库服务器没有作为容器运行，但您有几台运行 Docker 的主机，并且有交换机和存储区域网络等设备需要监控。Zabbix 可以为您提供一个单一的界面，显示所有环境的指标，并能够提醒您有问题。

到目前为止，我们已经看过了使用 Docker 和 LXC 提供的 API 和指标，但是我们还能使用哪些其他指标呢？在下一章中，我们将看到一个工具，它直接钩入主机机器的内核，以收集有关您的容器的信息。


# 第五章：使用 Sysdig 查询

我们之前看过的工具都依赖于对 Docker 进行 API 调用或从 LXC 读取指标。Sysdig 的工作方式不同，它通过将自身钩入主机机器的内核来工作，虽然这种方法违背了 Docker 每个服务在自己独立的容器中运行的理念，但通过运行 Sysdig 仅几分钟就可以获得的信息远远超过了任何不使用它的争论。

在本章中，我们将讨论以下主题：

+   如何在主机上安装 Sysdig 和 Csysdig

+   基本用法以及如何实时查询您的容器

+   如何捕获日志，以便以后可以查询

# 什么是 Sysdig？

在我们开始使用 Sysdig 之前，让我们先了解一下它是什么。当我第一次听说这个工具时，我心想它听起来太好了，以至于难以置信；网站描述了这个工具如下：

> *"Sysdig 是开源的，系统级的探索：从运行中的 Linux 实例中捕获系统状态和活动，然后保存、过滤和分析。Sysdig 可以在 Lua 中进行脚本编写，并包括一个命令行界面和一个功能强大的交互式 UI，csysdig，可以在终端中运行。将 sysdig 视为 strace + tcpdump + htop + iftop + lsof + 绝妙的酱汁。具有最先进的容器可见性。"*

这是一个相当大的说法，因为它声称的所有强大工具都是在查找问题时运行的一组命令，所以我起初有些怀疑。

任何曾经不得不尝试追踪 Linux 服务器上错误日志不够详细的故障或问题的人都知道，使用诸如 strace、lsof 和 tcpdump 等工具可能会很快变得复杂，通常涉及捕获大量数据，然后使用多种工具的组合来逐渐手动地跟踪问题，逐渐减少捕获的数据量。

想象一下，当 Sysdig 的声明被证明是真实的时候，我是多么高兴。这让我希望我在一线工程师时有这个工具，它会让我的生活变得更加轻松。

Sysdig 有两种不同的版本，第一种是开源版本，可在[`www.sysdig.org/`](http://www.sysdig.org/)上获得；这个版本带有一个 ncurses 界面，因此您可以轻松地从基于终端的 GUI 访问和查询数据。

### 注意

维基百科将**ncurses**（新的 curses）描述为一个编程库，它提供了一个 API，允许程序员以与终端无关的方式编写基于文本的用户界面。它是一个用于开发在终端仿真器下运行的“类 GUI”应用软件的工具包。它还优化屏幕更改，以减少在使用远程 shell 时经历的延迟。

还有一个商业服务，允许您将 Sysdig 流式传输到他们的外部托管服务；这个版本有一个基于 Web 的界面，用于查看和查询您的数据。

在本章中，我们将集中讨论开源版本。

# 安装 Sysdig

考虑到 Sysdig 有多么强大，它拥有我所遇到的最简单的安装和配置过程之一。要在 CentOS 或 Ubuntu 服务器上安装 Sysdig，请输入以下命令：

```
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash

```

运行上述命令后，您将获得以下输出：

![安装 Sysdig](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00037.jpeg)

就是这样，你已经准备好了。没有更多需要配置或做的事情。有一个手动安装过程，也有一种使用容器安装工具的方法来构建必要的内核模块；更多细节，请参阅以下安装指南：

[`www.sysdig.org/wiki/how-to-install-sysdig-for-linux/`](http://www.sysdig.org/wiki/how-to-install-sysdig-for-linux/)

# 使用 Sysdig

在我们看如何使用 Sysdig 之前，让我们通过运行以下命令使用`docker-compose`启动一些容器：

```
cd /monitoring_docker/chapter05/wordpress/
docker-compose up –d

```

这将启动一个运行数据库和两个 Web 服务器容器的 WordPress 安装，这些容器使用 HAProxy 容器进行负载平衡。一旦容器启动，您就可以在[`docker.media-glass.es/`](http://docker.media-glass.es/)上查看 WordPress 安装。在网站可见之前，您需要输入一些详细信息来创建管理员用户；按照屏幕提示完成这些步骤。

## 基础知识

在其核心，Sysdig 是一个生成数据流的工具；您可以通过输入`sudo sysdig`来查看流（要退出，请按*Ctrl*+*c*）。

那里有很多信息，所以让我们开始过滤流并运行以下命令：

```
sudosysdigevt.type=chdir

```

这将仅显示用户更改目录的事件；要查看其运行情况，打开第二个终端，您会看到当您登录时，在第一个终端中会看到一些活动。如您所见，它看起来很像传统的日志文件；我们可以通过运行以下命令格式化输出以提供用户名等信息：

```
sudosysdig -p"user:%user.name dir:%evt.arg.path" evt.type=chdir

```

然后，在您的第二个终端中，多次更改目录：

![基础知识](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00038.jpeg)

如您所见，这比原始未格式化的输出要容易阅读得多。按下*Ctrl* + *c*停止过滤。

## 捕获数据

在上一节中，我们看到了实时过滤数据；也可以将 Sysdig 数据流式传输到文件中，以便以后查询数据。退出第二个终端，并在第一个终端上运行以下命令：

```
sudosysdig -w ~/monitoring-docker.scap

```

当第一个终端上的命令正在运行时，登录到第二个终端上的主机，并多次更改目录。此外，在我们录制时，点击本节开头启动的 WordPress 网站，URL 为`http://docker.media-glass.es/`。完成后，按下*Crtl* + *c*停止录制；您现在应该已经回到提示符。您可以通过运行以下命令检查 Sysdig 创建的文件的大小：

```
ls -lha ~/monitoring-docker.scap

```

现在，我们可以使用我们捕获的数据应用与我们在查看实时流时相同的过滤器：

```
sudosysdig -r ~/monitoring-docker.scap -p"user:%user.name dir:%evt.arg.path" evt.type=chdir

```

通过运行上述命令，您将获得以下输出：

![捕获数据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00039.jpeg)

注意，我们获得了与实时查看数据时类似的结果。

## 容器

在`~/monitoring-docker.scap`中记录的一件事是系统状态的详细信息；这包括我们在本章开头启动的容器的信息。让我们使用这个文件来获取一些有关容器的统计信息。要列出在我们捕获数据文件期间处于活动状态的容器，请运行：

```
sudo sysdig -r ~/monitoring-docker.scap -c lscontainers

```

要查看哪个容器在大部分时间内使用了 CPU，我们点击 WordPress 网站运行：

```
sudo sysdig -r ~/monitoring-docker.scap -c topcontainers_cpu

```

要查看具有名称中包含“wordpress”的每个容器中的顶级进程，（在我们的情况下是所有容器），运行以下命令：

```
sudo sysdig -r ~/monitoring-docker.scap -c topprocs_cpu container.name contains wordpress

```

最后，我们的哪个容器传输了最多的数据？：

```
sudosysdig -r ~/monitoring-docker.scap -c topcontainers_net

```

通过运行上述命令，您将获得以下输出：

![容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00040.jpeg)

如您所见，我们从捕获的数据中提取了大量有关我们容器的信息。此外，使用该文件，您可以删除命令中的`-r ~/monitoring-docker.scap`部分，以实时查看容器指标。

值得一提的是，Sysdig 也有适用于 OS X 和 Windows 的二进制文件；虽然这些文件不会捕获任何数据，但它们可以用来读取您在 Linux 主机上记录的数据。

## 进一步阅读

通过本节介绍的一些基本练习，您应该开始了解 Sysdig 有多么强大。在[`www.sysdig.org/wiki/sysdig-examples/`](http://www.sysdig.org/wiki/sysdig-examples/)上有更多 Sysdig 网站上的例子。此外，我建议您阅读[`sysdig.com/fishing-for-hackers/`](https://sysdig.com/fishing-for-hackers/)的博客文章；这是我第一次接触 Sysdig，它真正展示了它的用处。

# 使用 Csysdig

使用命令行和手动过滤结果查看 Sysdig 捕获的数据就像这样简单，但随着您开始将更多命令串联在一起，情况可能会变得更加复杂。为了帮助尽可能方便地访问 Sysdig 捕获的数据，Sysdig 附带了一个名为**Csysdig**的 GUI。

启动 Csysdig 只需一个命令：

```
sudo csysdig

```

一旦进程启动，它应该立即对任何使用过 top 或 cAdvisor（减去图表）的人都很熟悉；它的默认视图将向您显示正在运行的进程的实时信息：

使用 Csysdig

要更改这个视图，即**进程**视图，按下*F2*打开**视图**菜单；从这里，您可以使用键盘上的上下箭头来选择视图。正如你可能已经猜到的，我们想看到**容器**视图：

使用 Csysdig

然而，在我们深入研究容器之前，让我们通过按*q*退出 Csysdig，并加载我们在上一节中创建的文件。要做到这一点，输入以下命令：

```
sudo csysdig -r ~/monitoring-docker.scap

```

一旦 Csysdig 加载，您会注意到**源**已从**实时系统**更改为我们数据文件的文件路径。从这里，按*F2*，使用上箭头选择容器，然后按*Enter*。从这里，您可以使用上下箭头选择两个 web 服务器中的一个，这些可能是`wordpress_wordpress1_1`或`wordpress_wordpress2_1`，如下图所示：

使用 Csysdig

### 注意

本章的剩余部分假设您已经打开了 Csysdig，它将指导您如何在工具中进行导航。请随时自行探索。

一旦您选择了一个服务器，按下*Enter*，您将看到容器正在运行的进程列表。同样，您可以使用箭头键选择一个进程进行进一步的查看。

我建议查看一个在**File**列中有数值的 Apache 进程。这一次，与其按*Enter*选择进程，不如让我们“Echo”捕获数据时进程的活动；选择进程后，按*F5*。

您可以使用上下箭头滚动输出：

![使用 Csysdig](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00044.jpeg)

要更好地格式化数据，请按*F2*并选择**可打印 ASCII**。正如您从前面的屏幕截图中看到的，这个 Apache 进程执行了以下任务：

+   接受了一个传入连接

+   访问了`.htaccess`文件

+   阅读`mod_rewrite`规则

+   从主机文件获取信息

+   连接到 MySQL 容器

+   发送了 MySQL 密码

通过在“Echo”结果中滚动查看进程的剩余数据，您应该能够轻松地跟踪与数据库的交互，直到页面被发送到浏览器。

要离开“Echo”屏幕，请按*Backspace*；这将始终使您返回上一级。

如果您想要更详细地了解进程的操作，请按*F6*进入**Dig**视图；这将列出进程在此时访问的文件，以及网络交互和内存访问方式。

要查看完整的命令列表和获取更多帮助，您可以随时按*F1*。此外，要获取屏幕上任何列的详细信息，请按*F7*。

# 摘要

正如我在本章开头提到的，Sysdig 可能是我近年来遇到的最强大的工具之一。

它的一部分力量在于它以一种从未感到压倒的方式暴露了大量信息和指标。显然，开发人员花了很多时间确保 UI 和命令的结构方式自然而且立即可理解，即使是运维团队中最新的成员也是如此。

唯一的缺点是，除非您想实时查看信息或查看开发中的问题，否则存储 Sysdig 生成的大量数据可能会在磁盘空间方面非常昂贵。

这是 Sysdig 已经认识到的一件事，为了帮助解决这个问题，该公司提供了一个基于云的商业服务，名为 Sysdig Cloud，让您可以将 Sysdig 数据流入其中。在下一章中，我们将看看这项服务，以及它的一些竞争对手。


# 第六章：探索第三方选项

到目前为止，我们一直在研究自己托管的工具和服务。除了这些自托管的工具之外，围绕 Docker 作为服务生态系统发展了大量基于云的软件。在本章中，我们将研究以下主题：

+   为什么要使用 SaaS 服务而不是自托管或实时指标？

+   有哪些可用的服务以及它们提供了什么？

+   在主机机器上安装 Sysdig Cloud、Datadog 和 New Relic 的代理

+   配置代理以传送指标

# 关于外部托管服务的说明

到目前为止，为了在本书中的示例中工作，我们已经使用了使用 vagrant 启动的本地托管虚拟服务器。在本章中，我们将使用需要能够与主机通信的服务，因此与其尝试使用本地机器来做这件事，不如将主机机器移到云中。

当我们查看服务时，我们将启动和停止远程主机，因此最好使用公共云，因为我们只会按使用量收费。

有几个公共云服务可供您评估本章涵盖的工具，您可以选择使用哪一个，您可以使用：

+   Digital Ocean：[`www.digitalocean.com/`](https://www.digitalocean.com/)

+   亚马逊网络服务：[`aws.amazon.com/`](https://aws.amazon.com/)

+   Microsoft Azure：[`azure.microsoft.com/`](https://azure.microsoft.com/)

+   VMware vCloud Air：[`vcloud.vmware.com/`](http://vcloud.vmware.com/)

或者使用您自己喜欢的提供商，唯一的先决条件是您的服务器是公开可访问的。

本章假设您有能力启动 CentOS 7 或 Ubuntu 14.04 云实例，并且您了解在云实例运行时可能会产生费用。

## 在云中部署 Docker

一旦您启动了云实例，您可以像使用 vagrant 安装一样引导 Docker。在 Git 存储库的`第六章`文件夹中，有两个单独的脚本可下载并在云实例上安装 Docker 引擎并组合它。

要安装 Docker，请确保您的云实例已更新，方法是运行：

```
sudo yum update

```

对于您的 CentOS 实例或 Ubuntu，请运行以下命令：

```
sudo apt-get update

```

更新后，运行以下命令安装软件。由于不同的云环境配置方式不同，最好切换到 root 用户以运行其余的命令，要做到这一点，请运行：

```
sudo su -

```

现在，您将能够使用以下命令运行安装脚本：

```
curl -fsS https://raw.githubusercontent.com/russmckendrick/monitoring-docker/master/chapter06/install_docker/install_docker.sh | bash

```

要检查一切是否按预期工作，请运行以下命令：

```
docker run hello-world

```

您应该看到类似于终端输出的内容，如下面的屏幕截图所示：

![在云中部署 Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00045.jpeg)

一旦您的 Docker 运行起来，我们可以开始查看 SaaS 服务。

# 为什么要使用 SaaS 服务？

您可能已经注意到，在前几章的示例中，如果我们需要开始收集更多的指标，我们使用的工具可能会使用很多资源，特别是如果我们要监视的应用程序正在生产中。

为了帮助减轻存储和 CPU 的负担，许多基于云的 SaaS 选项开始提供支持，记录容器的指标。许多这些服务已经提供了监视服务器的服务，因此为容器添加支持似乎是它们的自然发展。

这些通常需要您在主机上安装代理，一旦安装完成，代理将在后台运行并向服务报告，通常是基于云和 API 服务。

其中一些服务允许您将代理部署为 Docker 容器。它们提供容器化代理，以便服务可以在精简的操作系统上运行，例如：

+   CoreOS: [`coreos.com/`](https://coreos.com/)

+   RancherOS: [`rancher.com/rancher-os/`](http://rancher.com/rancher-os/)

+   Atomic: [`www.projectatomic.io/`](http://www.projectatomic.io/)

+   Ubuntu Snappy Core: [`developer.ubuntu.com/en/snappy/`](https://developer.ubuntu.com/en/snappy/)

这些操作系统与传统操作系统不同，因为您不能直接在它们上安装服务；它们的唯一目的是运行服务，比如 Docker，以便您可以启动需要作为容器运行的服务或应用程序。

由于我们正在运行完整的操作系统作为我们的主机系统，我们不需要这个选项，将直接部署代理到主机上。

我们将在本章中查看的 SaaS 选项如下：

+   Sysdig Cloud: [`sysdig.com/product/`](https://sysdig.com/product/)

+   Datadog: [`www.datadoghq.com/`](https://www.datadoghq.com/)

+   New Relic：[`newrelic.com`](http://newrelic.com)

它们都提供免费试用，其中两个提供主要服务的免费简化版本。乍一看，它们可能都提供类似的服务；然而，当您开始使用它们时，您会立即注意到它们实际上彼此非常不同。

# Sysdig Cloud

在上一章中，我们看了 Sysdig 的开源版本。我们看到有一个很棒的 ncurses 界面叫做 cSysdig，它允许我们浏览 Sysdig 收集的关于我们主机的所有数据。

Sysdig 收集的大量指标和数据意味着您必须尝试掌握它，可以通过将文件从服务器传输到亚马逊简单存储服务（S3）或一些本地共享存储来实现。此外，您可以在主机本身或使用命令行工具的安装在本地机器上查询数据。

这就是 Sysdig Cloud 发挥作用的地方；它提供了一个基于 Web 的界面，用于显示 Sysdig 捕获的指标，并提供将 Sysdig 捕获从主机机器传输到 Sysdig 自己的存储或您的 S3 存储桶的选项。

Sysdig 云提供以下功能：

+   ContainerVision™

+   实时仪表板

+   历史回放

+   动态拓扑

+   警报

此外，还可以在任何时间触发任何主机的捕获。

Sysdig 将 ContainerVision 描述为：

> “Sysdig Cloud 的专利核心技术 ContainerVision 是市场上唯一专门设计用于尊重容器独特特性的监控技术。ContainerVision 为您提供对容器化环境的所有方面-应用程序、基础设施、服务器和网络-的深入和全面的可见性，而无需向容器添加任何额外的仪器。换句话说，ContainerVision 为您提供对容器内部活动的 100%可见性，从外部看。”

在我们进一步深入了解 Sysdig Cloud 之前，我应该指出这是一个商业服务器，在撰写本文时，每台主机的费用为 25 美元。还提供 14 天完全功能的试用。如果您希望通过代理安装并按照本章的示例进行操作，您将需要一个在 14 天试用或付费订阅上运行的活跃帐户。

+   注册 14 天免费试用：[`sysdig.com/`](https://sysdig.com/)

+   定价详情：[`sysdig.com/pricing/`](https://sysdig.com/pricing/)

+   公司简介：[`sysdig.com/company/`](https://sysdig.com/company/)

## 安装代理

代理安装类似于安装开源版本；您需要确保您的云主机运行的是最新的内核，并且您也引导到了内核。

一些云服务提供商严格控制您可以引导的内核（例如，Digital Ocean），他们不允许您在主机上管理内核。相反，您需要通过他们的控制面板选择正确的版本。

安装了正确的内核后，您应该能够运行以下命令来安装代理。确保您用您自己的访问密钥替换命令末尾的访问密钥，您可以在**用户配置文件**页面或代理安装页面上找到它；您可以在以下位置找到这些信息：

+   用户配置文件：[`app.sysdigcloud.com/#/settings/user`](https://app.sysdigcloud.com/#/settings/user)

+   代理安装：[`app.sysdigcloud.com/#/settings/agentInstallation`](https://app.sysdigcloud.com/#/settings/agentInstallation)

运行的命令是：

```
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-agent | sudo bash -s -- --access_key wn5AYlhjRhgn3shcjW14y3yOT09WsF7d

```

Shell 输出应该如下屏幕所示：

![安装代理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00046.jpeg)

一旦代理安装完成，它将立即开始向 Sysdig Cloud 报告数据。如果您点击**探索**，您将看到您的主机和正在运行的容器：

![安装代理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00047.jpeg)

如您在这里所见，我有我的主机和四个容器运行着一个类似于我们在上一章中使用的 WordPress 安装。从这里，我们可以开始深入了解我们的指标。

要在基于云的机器上启动 WordPress 安装，请以 root 用户身份运行以下命令：

```
sudo su -
mkdir ~/wordpress
curl -L https://raw.githubusercontent.com/russmckendrick/monitoring-docker/master/chapter05/wordpress/docker-compose.yml > ~/wordpress/docker-compose.yml
cd ~/wordpress
docker-compose up -d

```

## 探索您的容器

Sysdig Cloud 的 Web 界面会让人感到非常熟悉，因为它与 cSysdig 共享类似的设计和整体感觉：

![探索您的容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00048.jpeg)

一旦您开始深入了解，您会发现底部窗格会打开，这是您可以查看统计数据的地方。我喜欢 Sysdig Cloud 的一点是它提供了丰富的指标，从这里您几乎不需要进行任何配置。

例如，如果您想知道在过去 2 小时内哪些进程消耗了最多的 CPU 时间，请单击次要菜单中的**2H**，然后从左下角的**Views**选项卡中单击**System: Top Processes**；这将为您提供一个按使用时间排序的进程表。

要将此视图应用于容器，请单击顶部部分中的容器，底部部分将立即更新以反映该容器的顶部 CPU 利用率；由于大多数容器只运行一个或两个进程，这可能并不那么有趣。因此，让我们深入了解进程本身。假设我们点击了我们的数据库容器，并且想要了解 MySQL 内部发生了什么。

Sysdig Cloud 配备了应用程序叠加层，当选择时，可以更详细地了解容器内的进程。选择**App: MySQL/PostgreSQL**视图可以让您深入了解 MySQL 进程当前正在做什么：

![探索您的容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00049.jpeg)

在这里，您可以看到底部部分的视图已经立即更新，提供了关于 MySQL 在过去 5 分钟内发生了什么的大量信息。

Sysdig Cloud 支持多种应用程序视图，包括：

+   Apache

+   HAProxy

+   NGINX

+   RabbitMQ

+   Redis

+   Tomcat

每个视图都可以立即访问指标，即使是最有经验的 SysAdmins 也会发现其价值。

您可能已经注意到第二个面板顶部还有一些图标，这些图标允许您：

+   **添加警报**：基于您打开的视图创建警报；它允许您调整阈值，并选择如何通知您。

+   **Sysdig Capture**：单击此按钮会弹出一个对话框，让您记录一个 Sysdig 会话。一旦记录完成，会话将传输到 Sysdig Cloud 或您自己的 S3 存储桶。会话可用后，您可以下载它或在 Web 界面中进行探索。

+   **SSH 连接**：从 Sysdig Cloud Web 界面在服务器上获取远程 shell；如果您无法立即访问笔记本电脑或台式机，并且想要进行一些故障排除，这将非常有用。

+   **固定到仪表板**：将当前视图添加到自定义仪表板。

在这些选项图标中，“添加警报”和“Sysdig 捕获”选项可能是您最终最常使用的选项。我发现有趣的最后一个视图是拓扑视图。它为您提供了对主机和容器的鸟瞰视图，这也对于查看容器和主机之间的交互非常有用。

![探索您的容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00050.jpeg)

在这里，您可以看到我从 WordPress 网站请求页面（在左边的框中），这个请求命中了我的主机（右边的框）。一旦它在主机上，它被路由到 HAProxy 容器，然后将页面请求传递给 Wordpress2 容器。从这里，Wordpress2 容器与在 MySQL 容器上运行的数据库进行交互。

## 摘要和进一步阅读

尽管 Sysdig Cloud 是一个相当新的服务，但它感觉立即熟悉，并且功能齐全，因为它是建立在一个已经建立和受人尊敬的开源技术之上。如果您喜欢从 Sysdig 的开源版本中获得的详细信息，那么 Sysdig Cloud 是您开始将指标存储在外部并配置警报的自然进步。了解更多关于 Sysdig Cloud 的一些好的起点是：

+   视频介绍：[`www.youtube.com/watch?v=p8UVbpw8n24`](https://www.youtube.com/watch?v=p8UVbpw8n24)

+   Sysdig 云最佳实践：[`support.sysdigcloud.com/hc/en-us/articles/204872795-Best-Practices`](http://support.sysdigcloud.com/hc/en-us/articles/204872795-Best-Practices)

+   仪表板：[`support.sysdigcloud.com/hc/en-us/articles/204863385-Dashboards`](http://support.sysdigcloud.com/hc/en-us/articles/204863385-Dashboards)

+   Sysdig 博客：[`sysdig.com/blog/`](https://sysdig.com/blog/)

### 提示

如果您已经启动了一个云实例，但不再使用它，现在是一个很好的时机来关闭实例或彻底终止它。这将确保您不会因为未使用的服务而被收费。

# Datadog

Datadog 是一个完整的监控平台；它支持各种服务器、平台和应用程序。维基百科描述了该服务：

> *"Datadog 是一个面向 IT 基础设施、运营和开发团队的基于 SaaS 的监控和分析平台。它汇集了来自服务器、数据库、应用程序、工具和服务的数据，以呈现云中规模运行的应用程序的统一视图。"*

它使用安装在主机上的代理；该代理定期将指标发送回 Datadog 服务。它还支持多个云平台，如亚马逊网络服务、微软 Azure 和 OpenStack 等。

目标是将所有服务器、应用程序和主机提供商的指标汇集到一个统一的视图中；从这里，您可以创建自定义仪表板和警报，以便在基础架构的任何级别收到通知。

您可以在[`app.datadoghq.com/signup`](https://app.datadoghq.com/signup)注册免费试用全套服务。您至少需要一个试用帐户来配置警报，如果您的试用已经过期，那么 lite 帐户也可以。有关 Datadog 定价结构的更多详细信息，请参阅[`www.datadoghq.com/pricing/`](https://www.datadoghq.com/pricing/)。

## 安装代理

代理可以直接安装在主机上，也可以作为容器安装。要直接在主机上安装，请运行以下命令，并确保使用您自己独特的`DD_API_KEY`：

```
DD_API_KEY=wn5AYlhjRhgn3shcjW14y3yOT09WsF7d bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/dd-agent/master/packaging/datadog-agent/source/install_agent.sh)"

```

要将代理作为容器运行，请使用以下命令，并确保使用您自己的`DD_API_KEY`：

```
sudo docker run -d --name dd-agent -h `hostname` -v /var/run/docker.sock:/var/run/docker.sock -v /proc/mounts:/host/proc/mounts:ro -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro -e API_KEY=wn5AYlhjRhgn3shcjW14y3yOT09WsF7d datadog/docker-dd-agent

```

安装代理后，它将回调 Datadog，并且主机将出现在您的帐户中。

如果代理直接安装在主机上，那么我们需要启用 Docker 集成；如果您使用容器安装代理，则这将自动完成。

为了做到这一点，首先需要允许 Datadog 代理访问您的 Docker 安装，方法是通过运行以下命令将`dd-agent`用户添加到 Docker 组中：

```
usermod -a -G docker dd-agent

```

下一步是创建`docker.yaml`配置文件，幸运的是，Datadog 代理附带了一个示例配置文件，我们可以使用；将其复制到指定位置，然后重新启动代理：

```
cp -pr /etc/dd-agent/conf.d/docker.yaml.example /etc/dd-agent/conf.d/docker.yaml
sudo /etc/init.d/datadog-agent restart

```

现在我们的主机上的代理已经配置好，最后一步是通过网站启用集成。要做到这一点，请转到[`app.datadoghq.com/`](https://app.datadoghq.com/)，点击**集成**，向下滚动，然后点击**Docker**上的安装：

![安装代理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00051.jpeg)

点击安装后，您将看到集成的概述，点击**配置**选项卡，这里提供了如何配置代理的说明；由于我们已经完成了这一步，您可以点击**安装集成**。

您可以在以下网址找到有关安装代理和集成的更多信息：

+   [`app.datadoghq.com/account/settings#agent`](https://app.datadoghq.com/account/settings#agent)

+   [`app.datadoghq.com/account/settings#integrations`](https://app.datadoghq.com/account/settings#integrations)

## 探索网络界面

现在，您已经安装了代理并启用了 Docker 集成，您可以开始浏览网络界面。要找到您的主机，请在左侧菜单中点击“基础设施”。

您应该看到一个包含您基础设施地图的屏幕。像我一样，您可能只列出了一个单个主机，点击它，一些基本统计数据应该出现在屏幕底部：

![探索网络界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00052.jpeg)

如果您还没有启动容器，现在是一个很好的时机，让我们再次使用以下内容启动 WordPress 安装：

```
sudo su -
mkdir ~/wordpress
curl -L https://raw.githubusercontent.com/russmckendrick/monitoring-docker/master/chapter05/wordpress/docker-compose.yml > ~/wordpress/docker-compose.yml
cd ~/wordpress
docker-compose up -d

```

现在，返回到网络界面，您可以点击六边形上列出的任何服务。这将为您选择的服务显示一些基本指标。如果您点击**docker**，您将看到 Docker 仪表板的链接，以及各种图表等；点击这个链接将带您进入容器的更详细视图：

![探索网络界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00053.jpeg)

正如您所看到的，这为我们提供了我们现在熟悉的 CPU 和内存指标的详细情况，以及仪表板右上角有关主机机器上容器活动的详细情况；这些记录了事件，例如停止和启动容器。

Datadog 目前记录以下指标：

+   `docker.containers.running`

+   `docker.containers.stopped`

+   `docker.cpu.system`

+   `docker.cpu.user`

+   `docker.images.available`

+   `docker.images.intermediate`

+   `docker.mem.cache`

+   `docker.mem.rss`

+   `docker.mem.swap`

从左侧菜单中的**指标**资源管理器选项开始绘制这些指标，一旦您有了图表，您可以开始将它们添加到您自己的自定义仪表板，甚至注释它们。当您注释一个图表时，将创建一个快照，并且图表将显示在事件队列中，以及其他已记录的事件，例如容器的停止和启动：

![探索网络界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00054.jpeg)

此外，在 Web 界面中，您可以配置监视器；这些允许您定义触发器，如果条件不满足，则会向您发出警报。警报可以通过电子邮件或通过 Slack、Campfire 或 PagerDuty 等第三方服务发送。

## 摘要和进一步阅读

虽然 Datadog 的 Docker 集成只为您提供容器的基本指标，但它具有丰富的功能和与其他应用程序和第三方的集成。如果您需要监视 Docker 容器以及其他不同服务，那么这项服务可能适合您：

+   主页：[`www.datadoghq.com`](https://www.datadoghq.com)

+   概述：[`www.datadoghq.com/product/`](https://www.datadoghq.com/product/)

+   使用 Datadog 监视 Docker：[`www.datadoghq.com/blog/monitor-docker-datadog/`](https://www.datadoghq.com/blog/monitor-docker-datadog/)

+   Twitter：[`twitter.com/datadoghq`](https://twitter.com/datadoghq)

### 提示

**请记住**

如果您已经启动了一个云实例，但不再使用它，现在是关闭实例或彻底终止它的好时机。这将确保您不会因为未使用的任何服务而被收费。

# 新的遗迹

New Relic 可以被认为是 SaaS 监控工具的鼻祖，如果您是开发人员，很有可能您已经听说过 New Relic。它已经存在一段时间了，是其他 SaaS 工具比较的标准。

多年来，New Relic 已经发展成为几种产品，目前，它们提供：

+   **New Relic APM**：主要的应用程序性能监控工具。这是大多数人会知道 New Relic 的东西；这个工具可以让您看到应用程序的代码级别可见性。

+   **New Relic Mobile**：一组库，嵌入到您的原生移动应用程序中，为您的 iOS 和 Android 应用程序提供 APM 级别的详细信息。

+   **New Relic Insights**：查看其他 New Relic 服务收集的所有指标的高级视图。

+   **New Relic Servers**：监视您的主机服务器，记录有关 CPU、RAM 和存储利用率的指标。

+   **New Relic Browser**：让您了解您的基于 Web 的应用程序离开服务器并进入最终用户浏览器后发生了什么

+   **New Relic Synthetics**：从世界各地的各个位置监视您的应用程序的响应能力。

与其查看所有这些提供的内容，让我们了解一下关于基于 Docker 的代码发生了什么，这可能是一本完整的书，我们将看一下服务器产品。

New Relic 提供的服务器监控服务是免费的，您只需要一个活跃的 New Relic 账户，您可以在[`newrelic.com/signup/`](https://newrelic.com/signup/)注册账户，有关 New Relic 定价的详细信息可以在他们的主页[`newrelic.com/`](http://newrelic.com/)找到。

## 安装代理

选择服务器将允许您开始探索代理正在记录的各种指标：

```
yum install http://download.newrelic.com/pub/newrelic/el5/i386/newrelic-repo-5-3.noarch.rpm
yum install newrelic-sysmond

```

对于 Ubuntu，运行以下命令：

```
echo 'deb http://apt.newrelic.com/debian/ newrelic non-free' | sudo tee /etc/apt/sources.list.d/newrelic.list
wget -O- https://download.newrelic.com/548C16BF.gpg | sudo apt-key add -
apt-get update
apt-get install newrelic-sysmond

```

![探索 Web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00056.jpeg)

```
nrsysmond-config --set license_key= wn5AYlhjRhgn3shcjW14y3yOT09WsF7d

```

现在代理已配置，我们需要将`newrelic`用户添加到`docker`组，以便代理可以访问我们的容器信息：

```
usermod -a -G docker newrelic

```

网络：让您查看主机的网络活动

```
/etc/init.d/newrelic-sysmond restart
/etc/init.d/docker restart

```

### 与本章中我们看过的其他 SaaS 产品一样，New Relic Servers 有一个基于主机的客户端，需要能够访问 Docker 二进制文件。要在 CentOS 机器上安装此客户端，请运行以下命令：

重新启动 Docker 将停止您正在运行的容器，请确保使用`docker ps`做好记录，然后在 Docker 服务重新启动后手动启动它们并备份。

几分钟后，您应该在 New Relic 控制面板上看到您的服务器出现。

## 探索 Web 界面

安装、配置和在主机上运行 New Relic 服务器代理后，单击顶部菜单中的**服务器**时，您将看到类似以下截图的内容：

![探索 Web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00055.jpeg)

磁盘：提供有关您使用了多少空间的详细信息

最后，我们需要启动 New Relic 服务器代理并重新启动 Docker：

从这里，您可以选择进一步深入：

+   现在您已经安装了代理，您需要使用以下命令配置代理与您的许可证密钥。确保添加您的许可证，可以在设置页面中找到：

+   进程：列出在主机和容器中运行的所有进程

+   提示

+   概述：快速概述您的主机

+   Docker：显示容器的 CPU 和内存利用率

您可能已经猜到，接下来我们将看一下**Docker**项目，点击它，您将看到您的活动镜像列表：

![探索 Web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00057.jpeg)

您可能已经注意到 New Relic 和其他服务之间的差异，正如您所看到的，New Relic 不会显示您正在运行的容器，而是显示 Docker 镜像的利用率。

在上面的屏幕截图中，我有四个活动的容器，并且正在运行我们在本书其他地方使用过的 WordPress 安装。如果我想要每个容器的详细信息，那么我就没那么幸运了，就像下面的屏幕所示：

![探索 Web 界面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/mnt-dkr/img/00058.jpeg)

这是一个相当乏味的屏幕，但它可以让您了解，如果您运行了使用相同镜像启动的多个容器，您将看到什么。那么这有什么用呢？嗯，再加上 New Relic 提供的其他服务，它可以让您了解在应用程序发生问题时您的容器在做什么。如果您还记得第一章中关于宠物与牛与鸡的类比，我们并不一定关心哪个容器做了什么；我们只是想看到它在我们正在调查的问题发生期间产生的影响。

## 总结和进一步阅读

由于 New Relic 提供的产品数量很多，一开始可能有点令人生畏，但如果您与一个开发团队合作，他们在日常工作流程中积极使用 New Relic，那么拥有关于您的基础设施的所有信息以及这些数据可能是非常有价值和必要的，特别是在出现问题时：

+   New Relic 服务器监控：[`newrelic.com/server-monitoring`](http://newrelic.com/server-monitoring)

+   New Relic 和 Docker：[`newrelic.com/docker/`](http://newrelic.com/docker/)

+   Twitter: [`twitter.com/NewRelic`](https://twitter.com/NewRelic)

### 提示

如果您启动了一个云实例，现在不再使用它，那么现在是关闭实例或彻底终止它的好时机，这将确保您不会因为未使用的任何服务而被收费。

# 总结

选择哪种 SaaS 服务取决于您的情况，在开始评估 SaaS 产品之前，您应该问自己一些问题：

+   您想要监控多少个容器？

+   您有多少台主机？

+   您需要监控非容器化基础架构吗？

+   您需要监控服务提供的哪些指标？

+   数据应该保留多长时间？

+   其他部门，比如开发部门，能否利用这项服务？

本章中我们只涵盖了三种可用的 SaaS 选项，还有其他选项可用，比如：

+   Ruxit: [`ruxit.com/docker-monitoring/`](https://ruxit.com/docker-monitoring/)

+   Scout: [`scoutapp.com/plugin_urls/19761-docker-monitor`](https://scoutapp.com/plugin_urls/19761-docker-monitor)

+   Logentries: [`logentries.com/insights/server-monitoring/`](https://logentries.com/insights/server-monitoring/)

+   Sematext: [`sematext.com/spm/integrations/docker-monitoring.html`](http://sematext.com/spm/integrations/docker-monitoring.html)

监控服务器和服务的效果取决于您收集的指标，如果可能并且预算允许，您应该充分利用所选提供商提供的服务，因为单个提供商记录的数据越多，不仅有利于分析容器化应用程序的问题，还有利于分析基础架构、代码甚至云提供商的问题。

例如，如果您正在使用相同的服务来监视主机和容器，那么通过使用自定义图形函数，您应该能够创建 CPU 负载峰值的叠加图，包括主机和容器。这比尝试将来自不同系统的两个不同图形进行比较要有用得多。

在下一章中，我们将看一下监控中经常被忽视的部分：将日志文件从容器/主机中传输到单一位置，以便进行监控和审查。
