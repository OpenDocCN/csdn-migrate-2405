# 精通 Docker 第三版（一）

> 原文：[`zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6`](https://zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Docker 在现代应用程序部署和架构方面是一个改变游戏规则的因素。它现在已经发展成为创新的关键驱动力，超越了系统管理，并对 Web 开发等领域产生了影响。但是，您如何确保您跟上了它所推动的创新？您如何确保您充分发挥了它的潜力？

本书向您展示了如何做到这一点；它不仅演示了如何更有效地使用 Docker，还帮助您重新思考和重新想象 Docker 的可能性。

您还将涵盖基本主题，如构建、管理和存储图像，以及在深入研究 Docker 安全性之前使您信心十足的最佳实践。您将找到与扩展和集成 Docker 相关的一切新颖创新的方法。Docker Compose，Docker Swarm 和 Kubernetes 将帮助您以高效的方式控制容器。

通过本书，您将对 Docker 的可能性有一个广泛而详细的认识，以及它如何无缝地融入到您的本地工作流程中，以及高可用的公共云平台和其他工具。

# 本书适合谁

如果您是 IT 专业人士，并认识到 Docker 在从系统管理到 Web 开发的创新中的重要性，但不确定如何充分利用它，那么本书适合您。

# 要充分利用本书

要充分利用本书，您需要一台能够运行 Docker 的机器。这台机器应至少具有 8GB RAM 和 30GB 可用硬盘空间，配备 Intel i3 或更高版本，运行以下操作系统之一：

+   macOS High Sierra 或更高版本

+   Windows 10 专业版

+   Ubuntu 18.04

此外，您将需要访问以下公共云提供商之一或全部：DigitalOcean，Amazon Web Services，Microsoft Azure 和 Google Cloud。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩软件解压缩文件夹。

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为 [`github.com/PacktPublishing/Mastering-Docker-Third-Edition`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在 **[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)** 上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789616606_ColorImages.pdf`。

# 代码示例

访问以下链接查看代码运行的视频：

[`bit.ly/2PUB9ww`](http://bit.ly/2PUB9ww)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“第一个文件是`nginx.conf`，其中包含基本的 nginx 配置文件。”

代码块设置如下：

```
user nginx;
worker_processes 1;

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}
```

任何命令行输入或输出都将按以下方式编写：

```
$ docker image inspect <IMAGE_ID>
```

粗体：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“单击“创建”后，您将被带到类似下一个屏幕截图的屏幕。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：Docker 概述

欢迎来到《Docker 大师》，第三版！本章将介绍您应该已经掌握的 Docker 基础知识。但是，如果您在这一点上还没有所需的知识，本章将帮助您掌握基础知识，以便后续章节不会感到沉重。在本书结束时，您应该是一个 Docker 大师，并且能够在您的环境中实施 Docker，构建和支持应用程序。

在本章中，我们将回顾以下高级主题：

+   理解 Docker

+   专用主机、虚拟机和 Docker 之间的区别

+   Docker 安装程序/安装

+   Docker 命令

+   Docker 和容器生态系统

# 技术要求

在本章中，我们将讨论如何在本地安装 Docker。为此，您需要运行以下三种操作系统之一的主机：

+   macOS High Sierra 及以上

+   Windows 10 专业版

+   Ubuntu 18.04

查看以下视频，了解代码的实际操作：

[`bit.ly/2NXf3rd`](http://bit.ly/2NXf3rd)

# 理解 Docker

在我们开始安装 Docker 之前，让我们先了解 Docker 技术旨在解决的问题。

# 开发人员

Docker 背后的公司一直将该程序描述为解决“*它在我的机器上运行良好*”的问题。这个问题最好由一个基于 Disaster Girl 模因的图像概括，简单地带有标语*在开发中运行良好，现在是运维问题*，几年前开始出现在演示文稿、论坛和 Slack 频道中。虽然很有趣，但不幸的是，这是一个非常真实的问题，我个人也曾经遇到过——让我们看一个例子，了解这是什么意思。

# 问题

即使在遵循 DevOps 最佳实践的世界中，开发人员的工作环境仍然很容易与最终生产环境不匹配。

例如，使用 macOS 版本的 PHP 的开发人员可能不会运行与托管生产代码的 Linux 服务器相同的版本。即使版本匹配，您还必须处理 PHP 版本运行的配置和整体环境之间的差异，例如不同操作系统版本之间处理文件权限的方式的差异，仅举一个潜在问题的例子。

当开发人员部署他们的代码到主机上时，如果出现问题，所有这些问题都会变得棘手。因此，生产环境应该配置成与开发人员的机器相匹配，还是开发人员只能在与生产环境匹配的环境中工作？

在理想的世界中，从开发人员的笔记本电脑到生产服务器，一切都应该保持一致；然而，这种乌托邦传统上很难实现。每个人都有自己的工作方式和个人偏好——即使只有一个工程师在系统上工作，要在多个平台上强制实现一致性已经很困难了，更不用说一个团队的工程师与数百名开发人员合作了。

# Docker 解决方案

使用 Docker for Mac 或 Docker for Windows，开发人员可以轻松地将他们的代码封装在一个容器中，他们可以自己定义，或者在与系统管理员或运营团队一起工作时创建为 Dockerfile。我们将在第二章《构建容器镜像》中涵盖这一点，以及 Docker Compose 文件，在第五章《Docker Compose》中我们将更详细地介绍。

他们可以继续使用他们选择的集成开发环境，并在处理代码时保持他们的工作流程。正如我们将在本章的后续部分中看到的，安装和使用 Docker 并不困难；事实上，考虑到过去维护一致的环境有多么繁琐，即使有自动化，Docker 似乎有点太容易了——几乎像作弊一样。

# 运营商

我在运营方面工作的时间比我愿意承认的时间长，以下问题经常出现。

# 问题

假设你正在管理五台服务器：三台负载均衡的 Web 服务器，以及两台专门运行应用程序 1 的主从配置的数据库服务器。你正在使用工具，比如 Puppet 或者 Chef，来自动管理这五台服务器上的软件堆栈和配置。

一切都进行得很顺利，直到有人告诉你，“我们需要在运行应用程序 1 的服务器上部署应用程序 2”。表面上看，这没有问题——你可以调整你的 Puppet 或 Chef 配置来添加新用户、虚拟主机，下载新代码等。然而，你注意到应用程序 2 需要比你为应用程序 1 运行的软件更高的版本。

更糟糕的是，你已经知道应用程序 1 坚决不愿意与新软件堆栈一起工作，而应用程序 2 也不向后兼容。

传统上，这给你留下了几个选择，无论哪种选择都会在某种程度上加剧问题：

1.  要求更多的服务器？虽然从技术上来说，这可能是最安全的解决方案，但这并不意味着会有额外资源的预算。

1.  重新设计解决方案？从技术角度来看，从负载均衡器或复制中取出一台 Web 和数据库服务器，然后重新部署它们与应用程序 2 的软件堆栈似乎是下一个最容易的选择。然而，你正在为应用程序 2 引入单点故障，并且也减少了应用程序 1 的冗余：你之前可能有理由在第一次运行三台 Web 和两台数据库服务器。

1.  尝试在服务器上并行安装新软件堆栈？嗯，这当然是可能的，而且似乎是一个不错的短期计划，可以让项目顺利进行，但当第一个关键的安全补丁需要应用于任一软件堆栈时，可能会导致整个系统崩溃。

# Docker 解决方案

这就是 Docker 开始发挥作用的地方。如果你在容器中跨三台 Web 服务器上运行应用程序 1，实际上你可能正在运行的容器不止三个；事实上，你可能已经运行了六个，容器的数量翻倍，使你能够在不降低应用程序 1 的可用性的情况下进行应用程序的滚动部署。

在这种环境中部署应用程序 2 就像简单地在三台主机上启动更多的容器，然后通过负载均衡器路由到新部署的应用程序一样简单。因为你只是部署容器，所以你不需要担心在同一台服务器上部署、配置和管理两个版本的相同软件堆栈的后勤问题。

我们将在《第五章》中详细介绍这种确切的情景，*Docker Compose*。

# 企业

企业遭受着之前描述的相同问题，因为他们既有开发人员又有运维人员；然而，他们在更大的规模上拥有这两个实体，并且还存在更多的风险。

# 问题

由于前述的风险，再加上任何停机时间可能带来的销售损失或声誉影响，企业需要在发布之前测试每次部署。这意味着新功能和修复被困在保持状态中，直到以下步骤完成：

+   测试环境被启动和配置

+   应用程序部署在新启动的环境中

+   测试计划被执行，应用程序和配置被调整，直到测试通过。

+   变更请求被编写、提交和讨论，以便将更新的应用程序部署到生产环境中

这个过程可能需要几天、几周，甚至几个月，具体取决于应用程序的复杂性和变更引入的风险。虽然这个过程是为了确保企业在技术层面上的连续性和可用性而必需的，但它确实可能在业务层面引入风险。如果你的新功能被困在这种保持状态中，而竞争对手发布了类似的，甚至更糟的功能，超过了你，那该怎么办呢？

这种情况对销售和声誉可能造成的损害与该过程最初为了保护你免受停机时间的影响一样严重。

# Docker 解决方案

首先，让我说一下，Docker 并不能消除这样一个过程的需求，就像刚才描述的那样，存在或者被遵循。然而，正如我们已经提到的，它确实使事情变得更容易，因为你已经在一贯地工作。这意味着你的开发人员一直在使用与生产环境中运行的相同的容器配置。这意味着这种方法论被应用到你的测试中并不是什么大问题。

例如，当开发人员检查他们在本地开发环境上知道可以正常工作的代码时（因为他们一直在那里工作），您的测试工具可以启动相同的容器来运行自动化测试。一旦容器被使用，它们可以被移除以释放资源供下一批测试使用。这意味着，突然之间，您的测试流程和程序变得更加灵活，您可以继续重用相同的环境，而不是为下一组测试重新部署或重新映像服务器。

这个流程的简化可以一直进行到您的新应用程序容器推送到生产环境。

这个过程完成得越快，您就可以更快地自信地推出新功能或修复问题，并保持领先地位。

# 专用主机、虚拟机和 Docker 之间的区别

因此，我们知道 Docker 是为了解决什么问题而开发的。现在我们需要讨论 Docker 究竟是什么以及它的作用。

Docker 是一个容器管理系统，可以帮助我们更轻松地以更简单和通用的方式管理 Linux 容器（LXC）。这使您可以在笔记本电脑上的虚拟环境中创建镜像并对其运行命令。您在本地机器上运行的这些环境中的容器执行的操作将是您在生产环境中运行它们时执行的相同命令或操作。

这有助于我们，因为当您从开发环境（例如本地机器上的环境）转移到服务器上的生产环境时，您不必做出不同的事情。现在，让我们来看看 Docker 容器和典型虚拟机环境之间的区别。

如下图所示，演示了专用裸金属服务器和运行虚拟机的服务器之间的区别：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/fc274237-51d9-4aa0-a6f0-25c3f3c46f70.png)

正如您所看到的，对于专用机器，我们有三个应用程序，都共享相同的橙色软件堆栈。运行虚拟机允许我们运行三个应用程序，运行两个完全不同的软件堆栈。下图显示了在使用 Docker 容器运行的相同橙色和绿色应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/358c4fdb-3334-4301-8fd9-da6571f08edd.png)

这张图表让我们对 Docker 的最大关键优势有了很多了解，也就是说，每次我们需要启动一个新的容器时都不需要完整的操作系统，这减少了容器的总体大小。由于几乎所有的 Linux 版本都使用标准的内核模型，Docker 依赖于使用主机操作系统的 Linux 内核，例如 Red Hat、CentOS 和 Ubuntu。

因此，您几乎可以将任何 Linux 操作系统作为您的主机操作系统，并能够在主机上叠加其他基于 Linux 的操作系统。嗯，也就是说，您的应用程序被认为实际上安装了一个完整的操作系统，但实际上，我们只安装了二进制文件，比如包管理器，例如 Apache/PHP 以及运行应用程序所需的库。

例如，在之前的图表中，我们可以让 Red Hat 运行橙色应用程序，让 Debian 运行绿色应用程序，但实际上不需要在主机上安装 Red Hat 或 Debian。因此，Docker 的另一个好处是创建镜像时的大小。它们构建时没有最大的部分：内核或操作系统。这使它们非常小，紧凑且易于传输。

# Docker 安装

安装程序是您在本地计算机和服务器环境上运行 Docker 时需要的第一件东西。让我们首先看一下您可以在哪些环境中安装 Docker：

+   Linux（各种 Linux 版本）

+   macOS

+   Windows 10 专业版

此外，您可以在公共云上运行它们，例如亚马逊网络服务、微软 Azure 和 DigitalOcean 等。在之前列出的各种类型的安装程序中，Docker 实际上在操作系统上以不同的方式运行。例如，Docker 在 Linux 上本地运行，因此如果您使用 Linux，那么 Docker 在您的系统上运行的方式就非常简单。但是，如果您使用 macOS 或 Windows 10，那么它的运行方式会有所不同，因为它依赖于使用 Linux。

让我们快速看一下在运行 Ubuntu 18.04 的 Linux 桌面上安装 Docker，然后在 macOS 和 Windows 10 上安装。

# 在 Linux（Ubuntu 18.04）上安装 Docker

正如前面提到的，这是我们将要看到的三个系统中最直接的安装。要安装 Docker，只需在终端会话中运行以下命令：

```
$ curl -sSL https://get.docker.com/ | sh
$ sudo systemctl start docker
```

您还将被要求将当前用户添加到 Docker 组中。要执行此操作，请运行以下命令，并确保您用自己的用户名替换用户名：

```
$ sudo usermod -aG docker username
```

这些命令将从 Docker 自己那里下载、安装和配置最新版本的 Docker。在撰写本文时，官方安装脚本安装的 Linux 操作系统版本为 18.06。

运行以下命令应该确认 Docker 已安装并正在运行：

```
$ docker version
```

您应该看到类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3955bf99-117a-4c4f-98a6-caa832558ac9.png)

有两个支持工具，我们将在未来的章节中使用，这些工具作为 Docker for macOS 或 Windows 10 安装程序的一部分安装。

为了确保我们在以后的章节中准备好使用这些工具，我们现在应该安装它们。第一个工具是**Docker Machine**。要安装这个工具，我们首先需要获取最新的版本号。您可以通过访问项目的 GitHub 页面的发布部分[`github.com/docker/machine/releases/`](https://github.com/docker/machine/releases/)找到这个版本。撰写本文时，版本为 0.15.0——在安装时，请使用以下代码块中的命令更新版本号为最新版本。

```
$ MACHINEVERSION=0.15.0
$ curl -L https://github.com/docker/machine/releases/download/v$MACHINEVERSION/docker-machine-$(uname -s)-$(uname -m) >/tmp/docker-machine
$ chmod +x /tmp/docker-machine
$ sudo mv /tmp/docker-machine /usr/local/bin/docker-machine
```

要下载并安装下一个和最终的工具**Docker Compose**，请运行以下命令，再次检查您是否通过访问[`github.com/docker/compose/releases/`](https://github.com/docker/compose/releases/)页面运行最新版本：

```
$ COMPOSEVERSION=1.22.0
$ curl -L https://github.com/docker/compose/releases/download/$COMPOSEVERSION/docker-compose-`uname -s`-`uname -m` >/tmp/docker-compose
$ chmod +x /tmp/docker-compose
$ sudo mv /tmp/docker-compose /usr/local/bin/docker-compose
```

安装完成后，您应该能够运行以下两个命令来确认软件的版本是否正确：

```
$ docker-machine version
$ docker-compose version
```

# 在 macOS 上安装 Docker

与命令行 Linux 安装不同，Docker for Mac 有一个图形安装程序。

在下载之前，您应该确保您正在运行 Apple macOS Yosemite 10.10.3 或更高版本。如果您正在运行旧版本，一切都不会丢失；您仍然可以运行 Docker。请参考本章的其他旧操作系统部分。

您可以从 Docker 商店下载安装程序，网址为[`store.docker.com/editions/community/docker-ce-desktop-mac`](https://store.docker.com/editions/community/docker-ce-desktop-mac)。只需点击获取 Docker 链接。下载完成后，您应该会得到一个 DMG 文件。双击它将挂载映像，打开桌面上挂载的映像应该会显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6e6f1020-b05a-4eb0-9277-fd283764567d.png)

将 Docker 图标拖到应用程序文件夹后，双击它，系统会询问您是否要打开已下载的应用程序。点击“是”将打开 Docker 安装程序，显示如下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/30550aa6-fdba-4bc9-b994-f91eb5494441.png)

点击“下一步”并按照屏幕上的说明操作。安装并启动后，您应该会在屏幕的左上角图标栏中看到一个 Docker 图标。点击该图标并选择“关于 Docker”应该会显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/27e05fdf-ed47-467d-be8a-bcdc9a539759.png)

您还可以打开终端窗口。运行以下命令，就像我们在 Linux 安装中所做的那样：

```
$ docker version
```

你应该看到类似以下终端输出的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e40b2f8a-148e-4b5a-b453-80bb899b59c9.png)

您还可以运行以下命令来检查与 Docker Engine 一起安装的 Docker Compose 和 Docker Machine 的版本：

```
$ docker-compose version
$ docker-machine version 
```

# 在 Windows 10 专业版上安装 Docker

与 Docker for Mac 一样，Docker for Windows 使用图形安装程序。

在下载之前，您应该确保您正在运行 Microsoft Windows 10 专业版或企业版 64 位。如果您正在运行旧版本或不受支持的 Windows 10 版本，您仍然可以运行 Docker；有关更多信息，请参阅本章其他旧操作系统部分。

Docker for Windows 有此要求是因为它依赖于 Hyper-V。Hyper-V 是 Windows 的本机虚拟化程序，允许您在 Windows 10 专业版或 Windows Server 上运行 x86-64 客户机。它甚至是 Xbox One 操作系统的一部分。

您可以从 Docker 商店下载 Docker for Windows 安装程序，网址为[`store.docker.com/editions/community/docker-ce-desktop-windows/`](https://store.docker.com/editions/community/docker-ce-desktop-windows/)。只需点击“获取 Docker”按钮下载安装程序。下载完成后，运行 MSI 包，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/30b99fc6-5abc-491e-b000-05b422ab97a9.png)

点击“是”，然后按照屏幕提示进行操作，这将不仅安装 Docker，还将启用 Hyper-V（如果您尚未启用）。

安装完成后，您应该在屏幕右下角的图标托盘中看到一个 Docker 图标。单击它，然后从菜单中选择关于 Docker，将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/69ea533f-f50a-4991-b357-6cfab5522f8d.png)

打开 PowerShell 窗口并输入以下命令：

```
$ docker version
```

这也应该显示与 Mac 和 Linux 版本类似的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3812b057-12d3-4f6d-975f-041408c61d89.png)

同样，您也可以运行以下命令来检查与 Docker Engine 一起安装的 Docker Compose 和 Docker Machine 的版本：

```
$ docker-compose version
$ docker-machine version
```

同样，您应该看到与 macOS 和 Linux 版本类似的输出。正如您可能已经开始了解的那样，一旦安装了这些软件包，它们的使用方式将会非常相似。这将在本章后面更详细地介绍。

# 旧操作系统

如果您在 Mac 或 Windows 上运行的操作系统版本不够新，那么您将需要使用 Docker Toolbox。考虑运行以下命令后打印的输出：

```
$ docker version
```

到目前为止，我们已经执行的三个安装都显示了两个不同的版本，一个客户端和一个服务器。可以预料的是，Linux 版本显示客户端和服务器的架构都是 Linux；然而，您可能会注意到 Mac 版本显示客户端正在运行 Darwin，这是苹果的类 Unix 内核，而 Windows 版本显示 Windows。但两个服务器都显示架构为 Linux，这是怎么回事呢？

这是因为 Docker 的 Mac 和 Windows 版本都会下载并在后台运行一个虚拟机，这个虚拟机运行着基于 Alpine Linux 的小型轻量级操作系统。虚拟机是使用 Docker 自己的库运行的，这些库连接到您选择的环境的内置 hypervisor。

对于 macOS 来说，这是内置的 Hypervisor.framework，而对于 Windows 来说，是 Hyper-V。

为了确保每个人都能体验 Docker，针对较旧版本的 macOS 和不受支持的 Windows 版本提供了一个不使用这些内置 hypervisor 的 Docker 版本。这些版本利用 VirtualBox 作为 hypervisor 来运行本地客户端连接的 Linux 服务器。

**VirtualBox**是由 Oracle 开发的开源 x86 和 AMD64/Intel64 虚拟化产品。它可以在 Windows、Linux、Macintosh 和 Solaris 主机上运行，并支持许多 Linux、Unix 和 Windows 客户操作系统。有关 VirtualBox 的更多信息，请参阅[`www.virtualbox.org/`](https://www.virtualbox.org/)。

有关**Docker Toolbox**的更多信息，请参阅项目网站[`www.docker.com/products/docker-toolbox/`](https://www.docker.%20com/products/docker-toolbox/)，您也可以在该网站上下载 macOS 和 Windows 的安装程序。

本书假设您已经在 Linux 上安装了最新的 Docker 版本，或者已经使用了 Docker for Mac 或 Docker for Windows。虽然使用 Docker Toolbox 安装 Docker 应该支持本书中的命令，但在将数据从本地机器挂载到容器时，您可能会遇到文件权限和所有权方面的问题。

# Docker 命令行客户端

既然我们已经安装了 Docker，让我们来看一些你应该已经熟悉的 Docker 命令。我们将从一些常用命令开始，然后看一下用于 Docker 镜像的命令。然后我们将深入了解用于容器的命令。

Docker 已经将他们的命令行客户端重构为更合乎逻辑的命令组合，因为客户端提供的功能数量增长迅速，命令开始互相交叉。在本书中，我们将使用新的结构。

我们将首先看一下一个最有用的命令，不仅在 Docker 中，而且在您使用的任何命令行实用程序中都是如此——`help`命令。它的运行方式很简单，就像这样：

```
$ docker help
```

这个命令将给你一个完整的 Docker 命令列表，以及每个命令的简要描述。要获取特定命令的更多帮助，可以运行以下命令：

```
$ docker <COMMAND> --help
```

接下来，让我们运行`hello-world`容器。要做到这一点，只需运行以下命令：

```
$ docker container run hello-world
```

无论您在哪个主机上运行 Docker，Linux、macOS 和 Windows 都会发生同样的事情。Docker 将下载`hello-world`容器镜像，然后执行它，一旦执行完毕，容器将被停止。

您的终端会话应该如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8835f878-d366-4d53-b18d-dd6987b23916.png)

让我们尝试一些更有冒险精神的事情——通过运行以下两个命令来下载并运行一个 nginx 容器：

```
$ docker image pull nginx
$ docker container run -d --name nginx-test -p 8080:80 nginx
```

这两个命令中的第一个下载了 nginx 容器镜像，第二个命令在后台启动了一个名为`nginx-test`的容器，使用我们拉取的`nginx`镜像。它还将主机机器上的端口`8080`映射到容器上的端口`80`，使其可以通过我们本地浏览器访问`http://localhost:8080/`。

正如你从以下截图中看到的，所有三种操作系统类型上的命令和结果都是完全相同的。这里是 Linux：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a4840240-de2f-457d-b638-ab11bb857ad6.png)

macOS 上的结果如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/017655c0-a14c-48b0-8487-3d8072dca595.png)

而在 Windows 上的效果如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/beb936ac-71fc-4f9b-ad05-00ab198855ca.png)

在接下来的三章中，我们将更详细地查看使用 Docker 命令行客户端。现在，让我们停止并删除我们的`nginx-test`容器，运行以下命令：

```
$ docker container stop nginx-test
$ docker container rm nginx-test
```

正如你所看到的，在我们安装了 Docker 的三个主机上运行一个简单的 nginx 容器的体验是完全相同的。我相信你可以想象，在没有像 Docker 这样的东西的情况下，在这三个平台上实现这一点是一种挑战，并且在每个平台上的体验也是非常不同的。传统上，这一直是本地开发环境差异的原因之一。

# Docker 和容器生态系统

如果你一直在关注 Docker 和容器的崛起，你会注意到，在过去几年里，Docker 网站的宣传语已经慢慢地从关于容器是什么转变为更加关注 Docker 作为公司提供的服务。

其中一个核心驱动因素是，一切传统上都被归类为“Docker”，这可能会让人感到困惑。现在人们不需要太多关于容器是什么以及他们可以用 Docker 解决什么问题的教育，公司需要尝试开始与其他为各种容器技术提供支持的公司区分开来。

因此，让我们尝试梳理一下 Docker 的一切，其中包括以下内容：

+   **开源项目**：Docker 启动了几个开源项目，现在由大量开发人员社区维护。

+   **Docker CE 和 Docker EE**：这是建立在开源组件之上的免费使用和商业支持的 Docker 工具的核心集合。

+   **Docker, Inc.**：这是一家成立的公司，旨在支持和开发核心 Docker 工具。

我们还将在后面的章节中研究一些第三方服务。与此同时，让我们更详细地了解每一个，从开源项目开始。

# 开源项目

Docker, Inc.在过去两年里一直在开源并向各种开源基金会和社区捐赠其核心项目。这些项目包括以下内容：

+   **Moby Project**是 Docker 引擎基于的上游项目。它提供了组装完全功能的容器系统所需的所有组件。

+   **Runc**是用于创建和配置容器的命令行界面，并且已经构建到 OCI 规范中。

+   **Containerd**是一个易于嵌入的容器运行时。它也是 Moby Project 的核心组件之一。

+   **LibNetwork**是一个提供容器网络的 Go 库。

+   **Notary**是一个旨在为签名的容器镜像提供信任系统的客户端和服务器。

+   **HyperKit**是一个工具包，允许您将虚拟化功能嵌入到自己的应用程序中，目前仅支持 macOS 和 Hypervisor.framework。

+   **VPNKit**为 HyperKit 提供 VPN 功能。

+   **DataKit**允许您使用类似 Git 的工作流来编排应用程序数据。

+   **SwarmKit**是一个工具包，允许您使用与 Docker Swarm 相同的 raft 一致性算法构建分布式系统。

+   **LinuxKit**是一个框架，允许您构建和编译一个小型便携的 Linux 操作系统，用于运行容器。

+   **InfraKit**是一套工具集，您可以使用它来定义基础架构，以运行您在 LinuxKit 上生成的发行版。

单独使用这些组件的可能性很小；然而，我们提到的每个项目都是由 Docker, Inc.维护的工具的组成部分。我们将在最后一章中更详细地介绍这些项目。

# Docker CE 和 Docker EE

Docker, Inc.提供并支持了许多工具。有些我们已经提到过，其他的我们将在后面的章节中介绍。在完成我们的第一章之前，我们应该了解一下我们将要使用的工具。其中最重要的是核心 Docker 引擎。

这是 Docker 的核心，我们将要介绍的所有其他工具都会使用它。在本章的 Docker 安装和 Docker 命令部分，我们已经在使用它。目前有两个版本的 Docker Engine；有 Docker **企业版**（**EE**）和 Docker **社区版**（**CE**）。在本书中，我们将使用 Docker CE。

从 2018 年 9 月开始，稳定版本的 Docker CE 的发布周期将是半年一次，这意味着它将有七个月的维护周期。这意味着您有足够的时间来审查和计划任何升级。目前，Docker CE 发布的当前时间表如下：

+   Docker 18.06 CE：这是季度 Docker CE 发布的最后一个版本，发布于 2018 年 7 月 18 日。

+   Docker 18.09 CE：这个版本预计将于 2018 年 9 月底/10 月初发布，是 Docker CE 半年发布周期的第一个版本。

+   Docker 19.03 CE：2019 年的第一个受支持的 Docker CE 计划于 2019 年 3 月/4 月发布。

+   Docker 19.09 CE：2019 年的第二个受支持的版本计划于 2019 年 9 月/10 月发布。

除了稳定版本的 Docker CE，Docker 还将通过夜间存储库（正式的 Docker CE Edge）提供 Docker Engine 的夜间构建，以及通过 Edge 渠道每月构建的 Docker for Mac 和 Docker for Windows。

Docker 还提供以下工具和服务：

+   Docker Compose：这是一个允许您定义和共享多容器定义的工具；详细内容请参阅第五章 *Docker Compose*。

+   Docker Machine：一个在多个平台上启动 Docker 主机的工具；我们将在第七章 *Docker Machine*中介绍这个工具。

+   Docker Hub：您的 Docker 镜像的存储库，将在接下来的三章中介绍。

+   Docker Store：官方 Docker 镜像和插件的商店，以及许可产品的存储库。同样，我们将在接下来的三章中介绍这个。

+   Docker Swarm：一个多主机感知编排工具，详细介绍请参阅第八章 *Docker Swarm*。

+   Docker for Mac：我们在本章中已经介绍了 Docker for Mac。

+   Docker for Windows：我们在本章中已经介绍了 Docker for Windows。

+   **Docker for Amazon Web Services**：针对 AWS 的最佳实践 Docker Swarm 安装，详见第十章，在*公共云中运行 Docker*中有介绍。

+   **Docker for Azure**：针对 Azure 的最佳实践 Docker Swarm 安装，详见第十章，在*公共云中运行 Docker*中有介绍。

# Docker, Inc.

Docker, Inc.是成立的公司，负责开发 Docker CE 和 Docker EE。它还为 Docker EE 提供基于 SLA 的支持服务。最后，他们为希望将现有应用程序容器化的公司提供咨询服务，作为 Docker 的**现代化传统应用**（**MTA**）计划的一部分。

# 总结

在本章中，我们涵盖了一些基本信息，这些信息您应该已经知道（或现在知道）用于接下来的章节。我们讨论了 Docker 的基本知识，以及与其他主机类型相比的优势。我们讨论了安装程序，它们在不同操作系统上的操作方式，以及如何通过命令行控制它们。请务必记住查看安装程序的要求，以确保您使用适合您操作系统的正确安装程序。

然后，我们深入了解了如何使用 Docker，并发出了一些基本命令来帮助您入门。在未来的章节中，我们将研究所有管理命令，以更深入地了解它们是什么，以及如何何时使用它们。最后，我们讨论了 Docker 生态系统以及不同工具的责任。

在接下来的章节中，我们将看看如何构建基本容器，我们还将深入研究 Dockerfile 和存储图像的位置，以及使用环境变量和 Docker 卷。

# 问题

1.  您可以从哪里下载 Mac 版 Docker 和 Windows 版 Docker？

1.  我们使用哪个命令来下载 NGINX 镜像？

1.  哪个开源项目是核心 Docker Engine 的上游项目？

1.  稳定的 Docker CE 版本的支持生命周期有多少个月？

1.  您会运行哪个命令来查找有关 Docker 容器子集命令的更多信息？

# 进一步阅读

在本章中，我们提到了以下虚拟化程序：

+   macOS Hypervisor 框架：[`developer.apple.com/reference/hypervisor/`](https://developer.apple.com/reference/hypervisor/)

+   Hyper-V: [`www.microsoft.com/en-gb/cloud-platform/server-virtualization`](https://www.microsoft.com/en-gb/cloud-platform/server-virtualization)

We referenced the following blog posts from Docker:

+   Docker CLI restructure blog post: [`blog.docker.com/2017/01/whats-new-in-docker-1-13/`](https://blog.docker.com/2017/01/whats-new-in-docker-1-13/)

+   Docker Extended Support Announcement: [`blog.docker.com/2018/07/extending-support-cycle-docker-community-edition/`](https://blog.docker.com/2018/07/extending-support-cycle-docker-community-edition/)

Next up, we discussed the following open source projects:

+   Moby Project: [`mobyproject.org/`](https://mobyproject.org/)

+   Runc: [`github.com/opencontainers/runc`](https://github.com/opencontainers/runc)

+   Containerd: [`containerd.io/`](https://containerd.io/)

+   LibNetwork; [`github.com/docker/libnetwork`](https://github.com/docker/libnetwork)

+   Notary: [`github.com/theupdateframework/notary`](https://github.com/theupdateframework/notary)

+   HyperKit: [`github.com/moby/hyperkit`](https://github.com/moby/hyperkit)

+   VPNKit: [`github.com/moby/vpnkit`](https://github.com/moby/vpnkit)

+   DataKit: [`github.com/moby/datakit`](https://github.com/moby/datakit)

+   SwarmKit: [`github.com/docker/swarmkit`](https://github.com/docker/swarmkit)

+   LinuxKit: [`github.com/linuxkit/linuxkit`](https://github.com/linuxkit/linuxkit)

+   InfraKit: [`github.com/docker/infrakit`](https://github.com/docker/infrakit)

+   The OCI specification: [`github.com/opencontainers/runtime-spec/`](https://github.com/opencontainers/runtime-spec/)

Finally, the meme mentioned at the start of the chapter can be found here:

+   *Worked fine in Dev, Ops problem now* - [`www.developermemes.com/2013/12/13/worked-fine-dev-ops-problem-now/`](http://www.developermemes.com/2013/12/13/worked-fine-dev-ops-problem-now/)


# 第二章：构建容器映像

在本章中，我们将开始构建容器映像。我们将看几种不同的方式，使用内置在 Docker 中的工具来定义和构建映像。我们将涵盖以下主题：

+   介绍 Dockerfile

+   使用 Dockerfile 构建容器映像

+   使用现有容器构建容器映像

+   从头开始构建容器映像

+   使用环境变量构建容器映像

+   使用多阶段构建构建容器映像

# 技术要求

在上一章中，我们在以下目标操作系统上安装了 Docker：

+   macOS High Sierra 及以上版本

+   Windows 10 专业版

+   Ubuntu 18.04

在本章中，我们将使用我们的 Docker 安装来构建映像。虽然本章中的截图将来自我的首选操作系统 macOS，但我们将在迄今为止安装了 Docker 的三个操作系统上运行的 Docker 命令都可以工作。然而，一些支持命令可能只适用于 macOS 和基于 Linux 的操作系统。

本章中使用的所有代码可以在以下位置找到：[`github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter02`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter02)

查看以下视频以查看代码实际操作：

[`bit.ly/2D0JA6v`](http://bit.ly/2D0JA6v)

# 介绍 Dockerfile

在本节中，我们将深入介绍 Dockerfile，以及使用的最佳实践。那么什么是 Dockerfile？

**Dockerfile**只是一个包含一组用户定义指令的纯文本文件。当 Dockerfile 被`docker image build`命令调用时，它用于组装容器映像。Dockerfile 看起来像下面这样：

```
FROM alpine:latest
LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
LABEL description="This example Dockerfile installs NGINX."
RUN apk add --update nginx && \
 rm -rf /var/cache/apk/* && \
 mkdir -p /tmp/nginx/

COPY files/nginx.conf /etc/nginx/nginx.conf
COPY files/default.conf /etc/nginx/conf.d/default.conf
ADD files/html.tar.gz /usr/share/nginx/

EXPOSE 80/tcp

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
```

如您所见，即使没有解释，也很容易了解 Dockerfile 的每个步骤指示`build`命令要做什么。

在我们继续处理之前的文件之前，我们应该快速了解一下 Alpine Linux。

**Alpine Linux**是一个小型、独立开发的非商业 Linux 发行版，旨在提供安全、高效和易用性。尽管体积小（见下一节），但由于其丰富的软件包仓库以及非官方的 grsecurity/PaX 移植，它在内核中提供了主动保护，可以防范数十种潜在的零日和其他漏洞。

Alpine Linux，由于其体积和强大的功能，已成为 Docker 官方容器镜像的默认基础。因此，在本书中我们将使用它。为了让你了解 Alpine Linux 官方镜像有多小，让我们将其与撰写时其他发行版进行比较：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2105ef9d-b875-4566-8cab-73e416e7fd93.png)

从终端输出可以看出，Alpine Linux 的体积仅为 4.41 MB，而最大的镜像 Fedora 则为 253 MB。Alpine Linux 的裸机安装体积约为 130 MB，仍然几乎是 Fedora 容器镜像的一半大小。

# 深入审查 Dockerfile

让我们来看看 Dockerfile 示例中使用的指令。我们将按照它们出现的顺序来看：

+   `FROM   `

+   `LABEL`

+   `RUN`

+   `COPY` 和 `ADD`

+   `EXPOSE`

+   `ENTRYPOINT` 和 `CMD`

+   其他 Dockerfile 指令

# FROM

`FROM`指令告诉 Docker 你想要使用哪个基础镜像；如前所述，我们使用的是 Alpine Linux，所以我们只需输入镜像的名称和我们希望使用的发布标签。在我们的情况下，要使用最新的官方 Alpine Linux 镜像，我们只需要添加`alpine:latest`。

# LABEL

`LABEL`指令可用于向镜像添加额外信息。这些信息可以是版本号或描述等任何内容。同时建议限制使用标签的数量。良好的标签结构将有助于以后使用我们的镜像的其他人。

然而，使用太多标签也会导致镜像效率低下，因此我建议使用[`label-schema.org/`](http://label-s%20chema.org/)中详细介绍的标签模式。你可以使用以下 Docker `inspect`命令查看容器的标签：

```
$ docker image inspect <IMAGE_ID>
```

或者，你可以使用以下内容来过滤标签：

```
$ docker image inspect -f {{.Config.Labels}} <IMAGE_ID>
```

在我们的示例 Dockerfile 中，我们添加了两个标签：

1.  `maintainer="Russ McKendrick <russ@mckendrick.io>"` 添加了一个标签，帮助镜像的最终用户识别谁在维护它

1.  `description="This example Dockerfile installs NGINX."` 添加了一个简要描述镜像的标签。

通常，最好在从镜像创建容器时定义标签，而不是在构建时，因此最好将标签限制在关于镜像的元数据上，而不是其他内容。

# RUN

`RUN`指令是我们与镜像交互以安装软件和运行脚本、命令和其他任务的地方。从我们的`RUN`指令中可以看到，实际上我们运行了三个命令：

```
RUN apk add --update nginx && \
 rm -rf /var/cache/apk/* && \
 mkdir -p /tmp/nginx/
```

我们三个命令中的第一个相当于在 Alpine Linux 主机上有一个 shell 时运行以下命令：

```
$ apk add --update nginx
```

此命令使用 Alpine Linux 的软件包管理器安装 nginx。

我们使用`&&`运算符来在前一个命令成功时继续执行下一个命令。为了更清晰地显示我们正在运行的命令，我们还使用`\`来将命令分成多行，使其易于阅读。

我们链中的下一个命令删除任何临时文件等，以使我们的镜像尺寸最小化：

```
$ rm -rf /var/cache/apk/*
```

我们链中的最后一个命令创建了一个路径为`/tmp/nginx/`的文件夹，这样当我们运行容器时，nginx 将能够正确启动：

```
$ mkdir -p /tmp/nginx/
```

我们也可以在 Dockerfile 中使用以下内容来实现相同的结果：

```
RUN apk add --update nginx
RUN rm -rf /var/cache/apk/*
RUN mkdir -p /tmp/nginx/
```

然而，就像添加多个标签一样，这被认为是低效的，因为它会增加镜像的总体大小，大多数情况下我们应该尽量避免这种情况。当然也有一些有效的用例，我们将在本章后面进行讨论。在大多数情况下，构建镜像时应避免这种命令的运行。

# COPY 和 ADD

乍一看，`COPY`和`ADD`看起来像是在执行相同的任务；然而，它们之间有一些重要的区别。`COPY`指令是两者中更为直接的：

```
COPY files/nginx.conf /etc/nginx/nginx.conf
COPY files/default.conf /etc/nginx/conf.d/default.conf
```

正如你可能已经猜到的那样，我们正在从构建镜像的主机上的文件夹中复制两个文件。第一个文件是`nginx.conf`，其中包含一个基本的 nginx 配置文件：

```
user nginx;
worker_processes 1;

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
 worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;
    sendfile off;
    keepalive_timeout 65;
    include /etc/nginx/conf.d/*.conf;
}
```

这将覆盖作为 APK 安装的一部分安装的 NGINX 配置在`RUN`指令中。接下来的文件`default.conf`是我们可以配置的最简单的虚拟主机，并且具有以下内容：

```
server {
  location / {
      root /usr/share/nginx/html;
  }
}
```

同样，这将覆盖任何现有文件。到目前为止，一切都很好，那么为什么我们要使用`ADD`指令呢？在我们的情况下，看起来像是以下的样子：

```
ADD files/html.tar.gz /usr/share/nginx/
```

正如你所看到的，我们正在添加一个名为`html.tar.gz`的文件，但实际上我们在 Dockerfile 中并没有对存档进行任何操作。这是因为`ADD`会自动上传、解压缩并将生成的文件夹和文件放置在我们告诉它的路径上，而在我们的情况下是`/usr/share/nginx/`。这给了我们我们在`default.conf`文件中定义的虚拟主机块中的 web 根目录`/usr/share/nginx/html/`。

`ADD`指令也可以用于从远程源添加内容。例如，考虑以下情况：

```
ADD http://www.myremotesource.com/files/html.tar.gz /usr/share/nginx/
```

上述命令行将从`http://www.myremotesource.com/files/`下载`html.tar.gz`并将文件放置在镜像的`/usr/share/nginx/`文件夹中。来自远程源的存档文件被视为文件，不会被解压缩，这在使用它们时需要考虑到，这意味着文件必须在`RUN`指令之前添加，这样我们就可以手动解压缩文件夹并删除`html.tar.gz`文件。

# EXPOSE

`EXPOSE`指令让 Docker 知道当镜像被执行时，定义的端口和协议将在运行时暴露。这个指令不会将端口映射到主机机器，而是打开端口以允许在容器网络上访问服务。

例如，在我们的 Dockerfile 中，我们告诉 Docker 在每次运行镜像时打开端口`80`：

```
EXPOSE 80/tcp
```

# ENTRYPOINT 和 CMD

使用`ENTRYPOINT`而不是`CMD`的好处是，你可以将它们结合使用。`ENTRYPOINT`可以单独使用，但请记住，只有在想要使容器可执行时才会单独使用`ENTRYPOINT`。

作为参考，如果你考虑一些你可能使用的 CLI 命令，你必须指定不仅仅是 CLI 命令。你可能还需要添加你希望命令解释的额外参数。这将是仅使用`ENTRYPOINT`的用例。

例如，如果你想要一个默认命令在容器内执行，你可以做类似以下示例的事情，但一定要使用一个保持容器活动的命令。在我们的情况下，我们使用以下命令：

```
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
```

这意味着每当我们从我们的镜像启动一个容器时，nginx 二进制文件都会被执行，因为我们已经将其定义为我们的`ENTRYPOINT`，然后我们定义的`CMD`也会被执行，这相当于运行以下命令：

```
$ nginx -g daemon off;
```

`ENTRYPOINT`的另一个用法示例如下：

```
$ docker container run --name nginx-version dockerfile-example -v
```

这相当于在我们的主机上运行以下命令：

```
$ nginx -v
```

请注意，我们不必告诉 Docker 使用 nginx。因为我们将 nginx 二进制文件作为我们的入口点，我们传递的任何命令都会覆盖 Dockerfile 中定义的`CMD`。

这将显示我们安装的 nginx 版本，并且我们的容器将停止，因为 nginx 二进制文件只会被执行以显示版本信息，然后进程将停止。我们将在本章后面看一下这个示例，一旦我们构建了我们的镜像。

# 其他 Dockerfile 指令

我们的示例 Dockerfile 中还有一些指令没有包括在内。让我们在这里看一下它们。

# USER

`USER`指令允许您在运行命令时指定要使用的用户名。`USER`指令可以在 Dockerfile 中的`RUN`指令、`CMD`指令或`ENTRYPOINT`指令上使用。此外，`USER`指令中定义的用户必须存在，否则您的镜像将无法构建。使用`USER`指令还可能引入权限问题，不仅在容器本身上，还在挂载卷时也可能出现权限问题。

# WORKDIR

`WORKDIR`指令为`USER`指令可以使用的相同一组指令（`RUN`、`CMD`和`ENTRYPOINT`）设置工作目录。它还允许您使用`CMD`和`ADD`指令。

# ONBUILD

`ONBUILD`指令允许您存储一组命令，以便在将来使用该镜像作为另一个容器镜像的基础镜像时使用。

例如，如果您想要向开发人员提供一个镜像，他们都有不同的代码库要测试，您可以使用`ONBUILD`指令在实际需要代码之前先打好基础。然后，开发人员只需将他们的代码添加到您告诉他们的目录中，当他们运行新的 Docker 构建命令时，它将把他们的代码添加到运行中的镜像中。

`ONBUILD`指令可以与`ADD`和`RUN`指令一起使用，例如以下示例：

```
ONBUILD RUN apk update && apk upgrade && rm -rf /var/cache/apk/*
```

这将在我们的镜像作为另一个容器镜像的基础时运行更新和软件包升级。

# ENV

`ENV`指令在构建镜像时和执行镜像时设置环境变量。这些变量在启动镜像时可以被覆盖。

# Dockerfile - 最佳实践

现在我们已经介绍了 Dockerfile 指令，让我们来看看编写我们自己的 Dockerfile 的最佳实践：

+   你应该养成使用`.dockerignore`文件的习惯。我们将在下一节介绍`.dockerignore`文件；如果你习惯使用`.gitignore`文件，它会让你感到非常熟悉。它在构建过程中将忽略你在文件中指定的项目。

+   记住每个文件夹只有一个 Dockerfile，以帮助你组织你的容器。

+   为你的 Dockerfile 使用版本控制系统，比如 Git；就像任何其他基于文本的文档一样，版本控制将帮助你不仅向前，还可以向后移动，如果有必要的话。

+   尽量减少每个镜像安装的软件包数量。在构建镜像时，你想要实现的最大目标之一就是尽量保持镜像尽可能小。不安装不必要的软件包将极大地帮助实现这一目标。

+   确保每个容器只有一个应用程序进程。每次需要一个新的应用程序进程时，最佳实践是使用一个新的容器来运行该应用程序。

+   保持简单；过度复杂化你的 Dockerfile 会增加臃肿，也可能在后续过程中引发问题。

+   以实例学习！Docker 自己为在 Docker Hub 上托管的官方镜像发布制定了相当详细的风格指南。你可以在本章末尾的进一步阅读部分找到相关链接。

# 构建容器镜像

在这一部分，我们将介绍`docker image build`命令。这就是所谓的关键时刻。现在是时候构建我们未来镜像的基础了。我们将探讨不同的方法来实现这一目标。可以将其视为您之前使用虚拟机创建的模板。这将通过完成艰苦的工作来节省时间；您只需创建需要添加到新镜像中的应用程序。

在使用`docker build`命令时，有很多开关可以使用。因此，让我们在`docker image build`命令上使用非常方便的`--help`开关，查看我们可以做的一切。

```
$ docker image build --help
```

然后列出了许多不同的标志，您可以在构建映像时传递这些标志。现在，这可能看起来很多，但在所有这些选项中，我们只需要使用`--tag`或其简写`-t`来命名我们的映像。

您可以使用其他选项来限制构建过程将使用多少 CPU 和内存。在某些情况下，您可能不希望`build`命令占用尽可能多的 CPU 或内存。该过程可能会运行得慢一些，但如果您在本地计算机或生产服务器上运行它，并且构建过程很长，您可能希望设置一个限制。还有一些选项会影响启动以构建我们的映像的容器的网络配置。

通常，您不会使用`--file`或`-f`开关，因为您是从包含 Dockerfile 的同一文件夹运行`docker build`命令。将 Dockerfile 放在单独的文件夹中有助于整理文件，并保持文件的命名约定相同。

值得一提的是，虽然您可以在构建时作为参数传递额外的环境变量，但它们仅在构建时使用，您的容器映像不会继承它们。这对于传递诸如代理设置之类的信息非常有用，这些信息可能仅适用于您的初始构建/测试环境。

如前所述，`.dockerignore`文件用于排除我们不希望包含在`docker build`中的文件或文件夹，默认情况下，与 Dockerfile 相同文件夹中的所有文件都将被上传。我们还讨论了将 Dockerfile 放在单独的文件夹中，对`.dockerignore`也适用。它应该放在放置 Dockerfile 的文件夹中。

将要在映像中使用的所有项目放在同一个文件夹中，这将有助于将`.dockerignore`文件中的项目数量（如果有的话）保持在最低限度。

# 使用 Dockerfile 构建容器映像

我们将要查看的第一种用于构建基本容器映像的方法是创建一个 Dockerfile。实际上，我们将使用上一节中的 Dockerfile，然后针对它执行`docker image build`命令，以获得一个 nginx 映像。因此，让我们再次开始查看 Dockerfile：

```
FROM alpine:latest
LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
LABEL description="This example Dockerfile installs NGINX."
RUN apk add --update nginx && \
 rm -rf /var/cache/apk/* && \
 mkdir -p /tmp/nginx/

COPY files/nginx.conf /etc/nginx/nginx.conf
COPY files/default.conf /etc/nginx/conf.d/default.conf
ADD files/html.tar.gz /usr/share/nginx/

EXPOSE 80/tcp

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
```

不要忘记您还需要在文件夹中的`default.conf`、`html.tar.gz`和`nginx.conf`文件。您可以在附带的 GitHub 存储库中找到这些文件。

因此，我们可以通过两种方式构建此图像。第一种方式是在使用`docker image build`命令时指定`-f`开关。我们还将利用`-t`开关为新图像指定一个唯一名称：

```
$ docker image build --file <path_to_Dockerfile> --tag <REPOSITORY>:<TAG> .
```

现在，`<REPOSITORY>`通常是您在 Docker Hub 上注册的用户名。我们将在第三章*存储和分发图像*中更详细地讨论这一点；目前，我们将使用`local`，而`<TAG>`是您想要提供的唯一容器值。通常，这将是一个版本号或其他描述符：

```
$ docker image build --file /path/to/your/dockerfile --tag local:dockerfile-example .
```

通常，不使用`--file`开关，当您需要将其他文件包含在新图像中时，可能会有些棘手。进行构建的更简单的方法是将 Dockerfile 单独放在一个文件夹中，以及使用`ADD`或`COPY`指令将任何其他文件注入到图像中：

```
$ docker image build --tag local:dockerfile-example .
```

最重要的是要记住最后的句点（或周期）。这是告诉`docker image build`命令在当前文件夹中构建的指示。构建图像时，您应该看到类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6e1391b3-78b9-41bb-be22-c2da8c578d51.png)

构建完成后，您应该能够运行以下命令来检查图像是否可用，以及图像的大小：

```
$ docker image ls
```

如您从以下终端输出中所见，我的图像大小为 5.98 MB：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/32a631a1-77f7-461d-8248-8080e5641502.png)

您可以通过运行此命令启动一个包含您新构建的图像的容器：

```
$ docker container run -d --name dockerfile-example -p 8080:80 local:dockerfile-example
```

这将启动一个名为`dockerfile-example`的容器，您可以使用以下命令检查它是否正在运行：

```
$ docker container ls 
```

打开浏览器并转到`http://localhost:8080/`应该会显示一个非常简单的网页，看起来像以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7eb0d970-366a-4736-89e2-9d1a482d4161.png)

接下来，我们可以快速运行本章前一节提到的一些命令，首先是以下命令：

```
$ docker container run --name nginx-version local:dockerfile-example -v
```

如您从以下终端输出中所见，我们目前正在运行 nginx 版本 1.14.0：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/c6575287-1cf9-45d9-8d35-d1a8125cc814.png)

接下来，我们可以看一下要运行的下一个命令，现在我们已经构建了第一个图像，显示了我们在构建时嵌入的标签。要查看此信息，请运行以下命令：

```
$ docker image inspect -f {{.Config.Labels}} local:dockerfile-example
```

如您从以下输出中所见，这显示了我们输入的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/27e551d4-99ed-4040-800e-986df10b1958.png)

在我们继续之前，你可以使用以下命令停止和删除我们启动的容器：

```
$ docker container stop dockerfile-example
$ docker container rm dockerfile-example nginx-version  
```

我们将在第四章“管理容器”中更详细地介绍 Docker 容器命令。

# 使用现有容器

构建基础镜像的最简单方法是从 Docker Hub 中的官方镜像之一开始。Docker 还将这些官方构建的 Dockerfile 保存在它们的 GitHub 存储库中。因此，你至少有两种选择可以使用其他人已经创建的现有镜像。通过使用 Dockerfile，你可以准确地看到构建中包含了什么，并添加你需要的内容。然后，如果你想以后更改或共享它，你可以对该 Dockerfile 进行版本控制。

还有另一种实现这一点的方法；然而，这并不被推荐或认为是良好的做法，我强烈不建议你使用它。

我只会在原型阶段使用这种方法，以检查我运行的命令是否在交互式 shell 中按预期工作，然后再将它们放入 Dockerfile 中。你应该总是使用 Dockerfile。

首先，我们应该下载我们想要用作基础的镜像；和以前一样，我们将使用 Alpine Linux：

```
$ docker image pull alpine:latest
```

接下来，我们需要在前台运行一个容器，这样我们就可以与它进行交互：

```
$ docker container run -it --name alpine-test alpine /bin/sh
```

容器运行后，你可以使用`apk`命令（在这种情况下）或者你的 Linux 版本的软件包管理命令来添加必要的软件包。

例如，以下命令将安装 nginx：

```
$ apk update
$ apk upgrade
$ apk add --update nginx
$ rm -rf /var/cache/apk/*
$ mkdir -p /tmp/nginx/
$ exit
```

安装完所需的软件包后，你需要保存容器。在前面一组命令的末尾使用`exit`命令将停止运行的容器，因为我们正在从中分离的 shell 进程恰好是保持容器在前台运行的进程。你可以在终端输出中看到这一点，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8dd37ad8-124e-4bdd-99da-053fe0af7dfe.png)

在这一点上，你应该真的停下来；我不建议你使用前面的命令来创建和分发镜像，除了我们将在本节的下一部分中涵盖的一个用例之外。

因此，要将我们停止的容器保存为镜像，你需要执行类似以下的操作：

```
$ docker container commit <container_name> <REPOSITORY>:<TAG>
```

例如，我运行了以下命令来保存我们启动和自定义的容器的副本：

```
$ docker container commit alpine-test local:broken-container 
```

注意我如何称呼我的镜像为`broken-container`？采用这种方法的一个用例是，如果由于某种原因您的容器出现问题，那么将失败的容器保存为镜像非常有用，甚至将其导出为 TAR 文件与他人分享，以便在解决问题时获得一些帮助。

要保存镜像文件，只需运行以下命令：

```
$ docker image save -o <name_of_file.tar> <REPOSITORY>:<TAG>
```

因此，对于我们的示例，我运行了以下命令：

```
$ docker image save -o broken-container.tar local:broken-container
```

这给了我一个名为`broken-container.tar`的 6.6 MB 文件。虽然我们有这个文件，您可以解压它并查看一下，就像您可以从以下结构中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b9291bbe-f356-443c-a892-c4198c3c5695.png)

镜像由一组 JSON 文件、文件夹和其他 TAR 文件组成。所有镜像都遵循这个结构，所以您可能会想，*为什么这种方法如此糟糕*？

最大的原因是信任——如前所述，您的最终用户将无法轻松地看到他们正在运行的镜像中有什么。您会随机下载一个来自未知来源的预打包镜像来运行您的工作负载吗，而不检查镜像是如何构建的？谁知道它是如何配置的，安装了什么软件包？使用 Dockerfile，您可以看到创建镜像时执行了什么，但使用此处描述的方法，您对此一无所知。

另一个原因是很难为您构建一个良好的默认设置；例如，如果您以这种方式构建您的镜像，那么您实际上将无法充分利用诸如`ENTRYPOINT`和`CMD`等功能，甚至是最基本的指令，比如`EXPOSE`。相反，用户将不得不在其`docker container run`命令期间定义所需的一切。

在 Docker 早期，分发以这种方式准备的镜像是常见做法。事实上，我自己也有过这样的行为，因为作为一名运维人员，启动一个“机器”，引导它，然后创建一个黄金镜像是完全合理的。幸运的是，在过去的几年里，Docker 已经将构建功能扩展到了这一点，以至于这个选项根本不再被考虑。

# 从头开始构建容器镜像

到目前为止，我们一直在使用 Docker Hub 上准备好的镜像作为我们的基础镜像。完全可以避免这一点（在某种程度上），并从头开始创建自己的镜像。

现在，当您通常听到短语*from **scratch*时，它的字面意思是从零开始。这就是我们在这里所做的——您什么都没有，必须在此基础上构建。这可能是一个好处，因为它将使镜像大小非常小，但如果您对 Docker 还比较新，这也可能是有害的，因为它可能会变得复杂。

Docker 已经为我们做了一些艰苦的工作，并在 Docker Hub 上创建了一个名为`scratch`的空 TAR 文件；您可以在 Dockerfile 的`FROM`部分中使用它。您可以基于此构建整个 Docker 构建，然后根据需要添加部分。

再次，让我们以 Alpine Linux 作为镜像的基本操作系统。这样做的原因不仅包括它被分发为 ISO、Docker 镜像和各种虚拟机镜像，还包括整个操作系统作为压缩的 TAR 文件可用。您可以在存储库或 Alpine Linux 下载页面上找到下载链接。

要下载副本，只需从下载页面中选择适当的下载，该页面位于[`www.alpinelinux.org/downloads/`](https://www.alpinelinux.org/downloads)。我使用的是**x86_64**，来自**MINI ROOT FILESYSTEM**部分。

一旦下载完成，您需要创建一个使用`scratch`的 Dockerfile，然后添加`tar.gz`文件，确保使用正确的文件，就像下面的例子一样：

```
FROM scratch
ADD files/alpine-minirootfs-3.8.0-x86_64.tar.gz /
CMD ["/bin/sh"]
```

现在您已经有了 Dockerfile 和操作系统的 TAR 文件，您可以通过运行以下命令构建您的镜像，就像构建任何其他 Docker 镜像一样：

```
$ docker image build --tag local:fromscratch .
```

您可以通过运行以下命令来比较镜像大小与我们构建的其他容器镜像：

```
$ docker image ls
```

正如您在以下截图中所看到的，我构建的镜像与我们从 Docker Hub 使用的 Alpine Linux 镜像的大小完全相同：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/743714e2-4da6-4fe1-a592-85dfe819b8cb.png)

现在我们已经构建了自己的镜像，可以通过运行以下命令来测试它：

```
$ docker container run -it --name alpine-test local:fromscratch /bin/sh
```

如果出现错误，则可能已经创建或正在运行名为 alpine-test 的容器。通过运行`docker container stop alpine-test`，然后运行`docker container rm alpine-test`来删除它。

这应该会启动到 Alpine Linux 镜像的 shell 中。您可以通过运行以下命令来检查：

```
$ cat /etc/*release
```

这将显示容器正在运行的版本信息。要了解整个过程的样子，请参见以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/357eb630-d8aa-4d78-b99e-17ca4fa62f75.png)

虽然一切看起来都很简单，这只是因为 Alpine Linux 包装他们的操作系统的方式。当你选择使用其他分发版包装他们的操作系统时，情况可能会变得更加复杂。

有几种工具可以用来生成操作系统的捆绑包。我们不会在这里详细介绍如何使用这些工具，因为如果你必须考虑这种方法，你可能有一些非常具体的要求。在本章末尾的进一步阅读部分有一些工具的列表。

那么这些要求可能是什么呢？对于大多数人来说，这将是遗留应用程序；例如，如果你有一个需要不再受支持或在 Docker Hub 上不再可用的操作系统的应用程序，但你需要一个更现代的平台来支持该应用程序，那么怎么办？嗯，你应该能够启动你的镜像并在那里安装应用程序，从而使你能够在现代、可支持的操作系统/架构上托管你的旧遗留应用程序。

# 使用环境变量

在本节中，我们将介绍非常强大的**环境变量**（**ENVs**），因为你将经常看到它们。你可以在 Dockerfile 中使用 ENVs 来做很多事情。如果你熟悉编码，这些可能对你来说很熟悉。

对于像我这样的其他人，起初它们似乎令人生畏，但不要灰心。一旦你掌握了它们，它们将成为一个很好的资源。它们可以用于在运行容器时设置信息，这意味着你不必去更新 Dockerfile 中的许多命令或在服务器上运行的脚本。

要在 Dockerfile 中使用 ENVs，你可以使用`ENV`指令。`ENV`指令的结构如下：

```
ENV <key> <value>
ENV username admin
```

或者，你也可以在两者之间使用等号：

```
ENV <key>=<value>
ENV username=admin
```

现在，问题是，为什么有两种定义它们的方式，它们有什么区别？在第一个例子中，你只能在一行上设置一个`ENV`；然而，它很容易阅读和理解。在第二个`ENV`示例中，你可以在同一行上设置多个环境变量，如下所示：

```
ENV username=admin database=wordpress tableprefix=wp
```

你可以使用 Docker `inspect`命令查看镜像上设置了哪些 ENVs：

```
$ docker image inspect <IMAGE_ID> 
```

现在我们知道它们在 Dockerfile 中需要如何设置，让我们看看它们的实际操作。到目前为止，我们一直在使用 Dockerfile 构建一个只安装了 nginx 的简单镜像。让我们来构建一些更加动态的东西。使用 Alpine Linux，我们将执行以下操作：

+   设置`ENV`来定义我们想要安装的 PHP 版本。

+   安装 Apache2 和我们选择的 PHP 版本。

+   设置镜像，使 Apache2 无问题启动。

+   删除默认的`index.html`并添加一个显示`phpinfo`命令结果的`index.php`文件。

+   在容器上暴露端口`80`。

+   将 Apache 设置为默认进程。

我们的 Dockerfile 如下所示：

```
FROM alpine:latest
LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
LABEL description="This example Dockerfile installs Apache & PHP."
ENV PHPVERSION=7

RUN apk add --update apache2 php${PHPVERSION}-apache2 php${PHPVERSION} && \
 rm -rf /var/cache/apk/* && \
 mkdir /run/apache2/ && \
 rm -rf /var/www/localhost/htdocs/index.html && \
 echo "<?php phpinfo(); ?>" > /var/www/localhost/htdocs/index.php && \
 chmod 755 /var/www/localhost/htdocs/index.php

EXPOSE 80/tcp

ENTRYPOINT ["httpd"]
CMD ["-D", "FOREGROUND"]
```

如您所见，我们选择安装了 PHP7；我们可以通过运行以下命令构建镜像：

```
$ docker build --tag local/apache-php:7 .
```

注意我们已经稍微改变了命令。这次，我们将镜像称为`local/apache-php`，并将版本标记为`7`。通过运行上述命令获得的完整输出可以在这里找到：

```
Sending build context to Docker daemon 2.56kB
Step 1/8 : FROM alpine:latest
 ---> 11cd0b38bc3c
Step 2/8 : LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
 ---> Using cache
 ---> 175e9ebf182b
Step 3/8 : LABEL description="This example Dockerfile installs Apache & PHP."
 ---> Running in 095e42841956
Removing intermediate container 095e42841956
 ---> d504837e80a4
Step 4/8 : ENV PHPVERSION=7
 ---> Running in 0df665a9b23e
Removing intermediate container 0df665a9b23e
 ---> 7f2c212a70fc
Step 5/8 : RUN apk add --update apache2 php${PHPVERSION}-apache2 php${PHPVERSION} && rm -rf /var/cache/apk/* && mkdir /run/apache2/ && rm -rf /var/www/localhost/htdocs/index.html && echo "<?php phpinfo(); ?>" > /var/www/localhost/htdocs/index.php && chmod 755 /var/www/localhost/htdocs/index.php
 ---> Running in ea77c54e08bf
fetch http://dl-cdn.alpinelinux.org/alpine/v3.8/main/x86_64/APKINDEX.tar.gz
fetch http://dl-cdn.alpinelinux.org/alpine/v3.8/community/x86_64/APKINDEX.tar.gz
(1/14) Installing libuuid (2.32-r0)
(2/14) Installing apr (1.6.3-r1)
(3/14) Installing expat (2.2.5-r0)
(4/14) Installing apr-util (1.6.1-r2)
(5/14) Installing pcre (8.42-r0)
(6/14) Installing apache2 (2.4.33-r1)
Executing apache2-2.4.33-r1.pre-install
(7/14) Installing php7-common (7.2.8-r1)
(8/14) Installing ncurses-terminfo-base (6.1-r0)
(9/14) Installing ncurses-terminfo (6.1-r0)
(10/14) Installing ncurses-libs (6.1-r0)
(11/14) Installing libedit (20170329.3.1-r3)
(12/14) Installing libxml2 (2.9.8-r0)
(13/14) Installing php7 (7.2.8-r1)
(14/14) Installing php7-apache2 (7.2.8-r1)
Executing busybox-1.28.4-r0.trigger
OK: 26 MiB in 27 packages
Removing intermediate container ea77c54e08bf
 ---> 49b49581f8e2
Step 6/8 : EXPOSE 80/tcp
 ---> Running in e1cbc518ef07
Removing intermediate container e1cbc518ef07
 ---> a061e88eb39f
Step 7/8 : ENTRYPOINT ["httpd"]
 ---> Running in 93ac42d6ce55
Removing intermediate container 93ac42d6ce55
 ---> 9e09239021c2
Step 8/8 : CMD ["-D", "FOREGROUND"]
 ---> Running in 733229cc945a
Removing intermediate container 733229cc945a
 ---> 649b432e8d47
Successfully built 649b432e8d47
Successfully tagged local/apache-php:7 
```

我们可以通过运行以下命令来检查一切是否按预期运行，以使用该镜像启动一个容器：

```
$ docker container run -d -p 8080:80 --name apache-php7 local/apache-php:7
```

一旦它启动，打开浏览器并转到`http://localhost:8080/`，您应该看到一个显示正在使用 PHP7 的页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/c5500d90-2c9c-4f4e-bfeb-f768b2c031b2.png)

不要被接下来的部分所困惑；没有 PHP6。要了解为什么没有，请访问[`wiki.php.net/rfc/php6`](https://wiki.php.net/rfc/php6)。

现在，在您的 Dockerfile 中，将`PHPVERSION`从`7`更改为`5`，然后运行以下命令构建新镜像：

```
$ docker image build --tag local/apache-php:5 .
```

如您从以下终端输出中所见，大部分输出都是相同的，除了正在安装的软件包：

```
Sending build context to Docker daemon 2.56kB
Step 1/8 : FROM alpine:latest
 ---> 11cd0b38bc3c
Step 2/8 : LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
 ---> Using cache
 ---> 175e9ebf182b
Step 3/8 : LABEL description="This example Dockerfile installs Apache & PHP."
 ---> Using cache
 ---> d504837e80a4
Step 4/8 : ENV PHPVERSION=5
 ---> Running in 0646b5e876f6
Removing intermediate container 0646b5e876f6
 ---> 3e17f6c10a50
Step 5/8 : RUN apk add --update apache2 php${PHPVERSION}-apache2 php${PHPVERSION} && rm -rf /var/cache/apk/* && mkdir /run/apache2/ && rm -rf /var/www/localhost/htdocs/index.html && echo "<?php phpinfo(); ?>" > /var/www/localhost/htdocs/index.php && chmod 755 /var/www/localhost/htdocs/index.php
 ---> Running in d55a7726e9a7
fetch http://dl-cdn.alpinelinux.org/alpine/v3.8/main/x86_64/APKINDEX.tar.gz
fetch http://dl-cdn.alpinelinux.org/alpine/v3.8/community/x86_64/APKINDEX.tar.gz
(1/10) Installing libuuid (2.32-r0)
(2/10) Installing apr (1.6.3-r1)
(3/10) Installing expat (2.2.5-r0)
(4/10) Installing apr-util (1.6.1-r2)
(5/10) Installing pcre (8.42-r0)
(6/10) Installing apache2 (2.4.33-r1)
Executing apache2-2.4.33-r1.pre-install
(7/10) Installing php5 (5.6.37-r0)
(8/10) Installing php5-common (5.6.37-r0)
(9/10) Installing libxml2 (2.9.8-r0)
(10/10) Installing php5-apache2 (5.6.37-r0)
Executing busybox-1.28.4-r0.trigger
OK: 32 MiB in 23 packages
Removing intermediate container d55a7726e9a7
 ---> 634ab90b168f
Step 6/8 : EXPOSE 80/tcp
 ---> Running in a59f40d3d5df
Removing intermediate container a59f40d3d5df
 ---> d1aadf757f59
Step 7/8 : ENTRYPOINT ["httpd"]
 ---> Running in c7a1ab69356d
Removing intermediate container c7a1ab69356d
 ---> 22a9eb0e6719
Step 8/8 : CMD ["-D", "FOREGROUND"]
 ---> Running in 8ea92151ce22
Removing intermediate container 8ea92151ce22
 ---> da34eaff9541
Successfully built da34eaff9541
Successfully tagged local/apache-php:5
```

我们可以通过运行以下命令在端口`9090`上启动一个容器：

```
$ docker container run -d -p 9090:80 --name apache-php5 local/apache-php:5
```

再次打开您的浏览器，但这次转到`http://localhost:9090/`，应该显示我们正在运行 PHP5：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/41bd2e7e-8182-4035-be75-312200013d41.png)

最后，您可以通过运行此命令来比较镜像的大小：

```
$ docker image ls
```

您应该看到以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/47fc018c-fd1e-4dd5-bc96-1c3d87281a7c.png)

这表明 PHP7 镜像比 PHP5 镜像要小得多。让我们讨论当我们构建了两个不同的容器镜像时实际发生了什么。

那么发生了什么？嗯，当 Docker 启动 Alpine Linux 镜像来创建我们的镜像时，它首先做的是设置我们定义的 ENV，使它们对容器内的所有 shell 可用。

幸运的是，Alpine Linux 中 PHP 的命名方案只是替换版本号并保持我们需要安装的软件包的相同名称，这意味着我们运行以下命令：

```
RUN apk add --update apache2 php${PHPVERSION}-apache2 php${PHPVERSION}
```

但实际上它被解释为以下内容：

```
RUN apk add --update apache2 php7-apache2 php7
```

或者，对于 PHP5，它被解释为以下内容：

```
RUN apk add --update apache2 php5-apache2 php5
```

这意味着我们不必手动替换版本号来浏览整个 Dockerfile。当从远程 URL 安装软件包时，这种方法特别有用，比如软件发布页面。

接下来是一个更高级的示例——一个安装和配置 HashiCorp 的 Consul 的 Dockerfile。在这个 Dockerfile 中，我们使用环境变量来定义文件的版本号和 SHA256 哈希：

```
FROM alpine:latest
LABEL maintainer="Russ McKendrick <russ@mckendrick.io>"
LABEL description="An image with the latest version on Consul."

ENV CONSUL_VERSION=1.2.2 CONSUL_SHA256=7fa3b287b22b58283b8bd5479291161af2badbc945709eb5412840d91b912060

RUN apk add --update ca-certificates wget && \
 wget -O consul.zip https://releases.hashicorp.com/consul/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_linux_amd64.zip && \
 echo "$CONSUL_SHA256 *consul.zip" | sha256sum -c - && \
 unzip consul.zip && \
 mv consul /bin/ && \
 rm -rf consul.zip && \
 rm -rf /tmp/* /var/cache/apk/*

EXPOSE 8300 8301 8301/udp 8302 8302/udp 8400 8500 8600 8600/udp

VOLUME [ "/data" ]

ENTRYPOINT [ "/bin/consul" ]
CMD [ "agent", "-data-dir", "/data", "-server", "-bootstrap-expect", "1", "-client=0.0.0.0"]
```

正如你所看到的，Dockerfiles 可以变得非常复杂，使用 ENV 可以帮助维护。每当 Consul 的新版本发布时，我只需要更新 `ENV` 行并将其提交到 GitHub，这将触发构建新镜像——如果我们配置了的话；我们将在下一章中讨论这个问题。

你可能也注意到我们在 Dockerfile 中使用了一个我们还没有涉及的指令。别担心，我们将在第四章中讨论 `VOLUME` 指令，*管理容器*。

# 使用多阶段构建

在我们使用 Dockerfiles 和构建容器镜像的旅程的最后部分，我们将看看使用一种相对新的构建镜像的方法。在本章的前几节中，我们看到直接通过包管理器（例如 Alpine Linux 的 APK）或者在最后一个示例中，通过从软件供应商下载预编译的二进制文件将二进制文件添加到我们的镜像。

如果我们想要在构建过程中编译我们自己的软件怎么办？从历史上看，我们将不得不使用包含完整构建环境的容器镜像，这可能非常庞大。这意味着我们可能不得不拼凑一个运行类似以下过程的脚本：

1.  下载构建环境容器镜像并启动“构建”容器

1.  将源代码复制到“构建”容器中

1.  在“构建”容器上编译源代码

1.  将编译的二进制文件复制到“build”容器之外

1.  移除“build”容器

1.  使用预先编写的 Dockerfile 构建镜像并将二进制文件复制到其中

这是很多逻辑——在理想的世界中，它应该是 Docker 的一部分。幸运的是，Docker 社区也这样认为，并在 Docker 17.05 中引入了实现这一功能的多阶段构建。

Dockerfile 包含两个不同的构建阶段。第一个名为`builder`，使用来自 Docker Hub 的官方 Go 容器镜像。在这里，我们正在安装先决条件，直接从 GitHub 下载源代码，然后将其编译成静态二进制文件：

```
FROM golang:latest as builder
WORKDIR /go-http-hello-world/
RUN go get -d -v golang.org/x/net/html 
ADD https://raw.githubusercontent.com/geetarista/go-http-hello-world/master/hello_world/hello_world.go ./hello_world.go
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM scratch 
COPY --from=builder /go-http-hello-world/app .
CMD ["./app"] 
```

由于我们的静态二进制文件具有内置的 Web 服务器，从操作系统的角度来看，我们实际上不需要其他任何东西。因此，我们可以使用`scratch`作为基础镜像，这意味着我们的镜像将只包含我们从构建镜像中复制的静态二进制文件，不会包含任何`builder`环境。

构建镜像，我们只需要运行以下命令：

```
$ docker image build --tag local:go-hello-world .
```

命令的输出可以在以下代码块中找到——有趣的部分发生在第 5 步和第 6 步之间：

```
Sending build context to Docker daemon 9.216kB
Step 1/8 : FROM golang:latest as builder
latest: Pulling from library/golang
55cbf04beb70: Pull complete
1607093a898c: Pull complete
9a8ea045c926: Pull complete
d4eee24d4dac: Pull complete
9c35c9787a2f: Pull complete
6a66653f6388: Pull complete
102f6b19f797: Pull complete
Digest: sha256:957f390aceead48668eb103ef162452c6dae25042ba9c41762f5210c5ad3aeea
Status: Downloaded newer image for golang:latest
 ---> d0e7a411e3da
Step 2/8 : WORKDIR /go-http-hello-world/
 ---> Running in e1d56745f358
Removing intermediate container e1d56745f358
 ---> f18dfc0166a0
Step 3/8 : RUN go get -d -v golang.org/x/net/html
 ---> Running in 5e97d81db53c
Fetching https://golang.org/x/net/html?go-get=1
Parsing meta tags from https://golang.org/x/net/html?go-get=1 (status code 200)
get "golang.org/x/net/html": found meta tag get.metaImport{Prefix:"golang.org/x/net", VCS:"git", RepoRoot:"https://go.googlesource.com/net"} at https://golang.org/x/net/html?go-get=1
get "golang.org/x/net/html": verifying non-authoritative meta tag
Fetching https://golang.org/x/net?go-get=1
Parsing meta tags from https://golang.org/x/net?go-get=1 (status code 200)
golang.org/x/net (download)
Removing intermediate container 5e97d81db53c
 ---> f94822756a52
Step 4/8 : ADD https://raw.githubusercontent.com/geetarista/go-http-hello-world/master/hello_world/hello_world.go ./hello_world.go
Downloading 393B
 ---> ecf3944740e1
Step 5/8 : RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
 ---> Running in 6e2d39c4d8ba
Removing intermediate container 6e2d39c4d8ba
 ---> 247fcbfb7a4d
Step 6/8 : FROM scratch
 --->
Step 7/8 : COPY --from=builder /go-http-hello-world/app .
 ---> a69cf59ab1d3
Step 8/8 : CMD ["./app"]
 ---> Running in c99076fad7fb
Removing intermediate container c99076fad7fb
 ---> 67296001bdc0
Successfully built 67296001bdc0
Successfully tagged local:go-hello-world
```

如您所见，在第 5 步和第 6 步之间，我们的二进制文件已经被编译，包含`builder`环境的容器已被移除，留下了存储我们二进制文件的镜像。第 7 步将二进制文件复制到使用 scratch 启动的新容器中，只留下我们需要的内容。

如果你运行以下命令，你会明白为什么不应该将应用程序与其构建环境一起发布是个好主意：

```
$ docker image ls
```

我们的输出截图显示，`golang`镜像为`794MB`；加上我们的源代码和先决条件后，大小增加到`832MB`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/c73e731e-21c0-461b-9e40-0ef64d69cfb5.png)

然而，最终镜像只有`6.56MB`。我相信您会同意这是相当大的空间节省。它还遵循了本章前面讨论的最佳实践，只在镜像中包含与我们应用程序相关的内容，并且非常小。

您可以通过使用以下命令启动一个容器来测试该应用程序：

```
$ docker container run -d -p 8000:80 --name go-hello-world local:go-hello-world
```

应用程序可以通过浏览器访问，并在每次加载页面时简单地递增计数器。要在 macOS 和 Linux 上进行测试，可以使用`curl`命令，如下所示：

```
$ curl http://localhost:8000/
```

这应该给您类似以下的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0dd95dc9-af1e-401b-82c8-567ecff6abee.png)

Windows 用户可以在浏览器中简单地访问`http://localhost:8000/`。要停止和删除正在运行的容器，请使用以下命令：

```
$ docker container stop go-hello-world
$ docker container rm go-hello-world
```

正如您所看到的，使用多阶段构建是一个相对简单的过程，并且符合应该已经开始感到熟悉的指令。

# 摘要

在本章中，我们深入了解了 Dockerfiles，编写它们的最佳实践，docker image build 命令以及我们可以构建容器的各种方式。我们还了解了可以从 Dockerfile 传递到容器内各个项目的环境变量。

在下一章中，现在我们知道如何使用 Dockerfiles 构建镜像，我们将看看 Docker Hub 以及使用注册表服务带来的所有优势。我们还将看看 Docker 注册表，它是开源的，因此您可以自己创建一个存储镜像的地方，而无需支付 Docker Enterprise 的费用，也可以使用第三方注册表服务。

# 问题

1.  真或假：`LABEL`指令在构建完图像后会给图像打标签？

1.  `ENTRYPOINT`和`CMD`指令之间有什么区别？

1.  真或假：使用`ADD`指令时，无法下载并自动解压外部托管的存档？

1.  使用现有容器作为图像基础的有效用途是什么？

1.  `EXPOSE`指令暴露了什么？

# 进一步阅读

您可以在以下位置找到官方 Docker 容器图像的指南：

+   [`github.com/docker-library/official-images/`](https://github.com/docker-library/official-images/)

一些帮助您从现有安装创建容器的工具如下：

+   Debootstrap: [`wiki.debian.org/Debootstrap/`](https://wiki.debian.org/Debootstrap/)

+   Yumbootstrap: [`github.com/dozzie/yumbootstrap/`](https://github.com/dozzie/yumbootstrap/)

+   Rinse: [`salsa.debian.org/debian/rinse/`](https://salsa.debian.org/debian/rinse/)

+   Docker contrib scripts: [`github.com/moby/moby/tree/master/contrib/`](https://github.com/moby/moby/tree/master/contrib/)

最后，Go HTTP Hello World 应用程序的完整 GitHub 存储库可以在以下位置找到：

+   [`github.com/geetarista/go-http-hello-world/`](https://github.com/geetarista/go-http-hello-world/)


# 第三章：存储和分发镜像

在本章中，我们将涵盖几项服务，如 Docker Hub，允许您存储您的镜像，以及 Docker Registry，您可以用来运行 Docker 容器的本地存储。我们将审查这些服务之间的区别，以及何时以及如何使用它们。

本章还将介绍如何使用 Webhooks 设置自动构建，以及设置它们所需的所有组件。让我们快速看一下本章将涵盖的主题：

+   Docker Hub

+   Docker Store

+   Docker Registry

+   第三方注册表

+   Microbadger

# 技术要求

在本章中，我们将使用我们的 Docker 安装来构建镜像。与之前一样，尽管本章的截图将来自我首选的操作系统 macOS，但我们将运行的命令将适用于上一章中涵盖的所有三个操作系统。本章中使用的代码的完整副本可以在以下位置找到：[`github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter03`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter03)。

观看以下视频以查看代码的实际操作：

[`bit.ly/2EBVJjJ`](http://bit.ly/2EBVJjJ)

# Docker Hub

虽然在前两章中我们介绍了 Docker Hub，但除了使用`docker image pull`命令下载远程镜像之外，我们并没有与其互动太多。

在本节中，我们将重点关注 Docker Hub，它有一个免费的选项，您只能托管公开可访问的镜像，还有一个订阅选项，允许您托管自己的私有镜像。我们将关注 Docker Hub 的网络方面以及您可以在那里进行的管理。

主页位于[`hub.docker.com/`](https://hub.docker.com/)，包含一个注册表格，并且在右上角有一个登录选项。如果您一直在尝试使用 Docker，那么您可能已经有一个 Docker ID。如果没有，请使用主页上的注册表格创建一个。如果您已经有 Docker ID，那么只需点击登录。

Docker Hub 是免费使用的，如果您不需要上传或管理自己的镜像，您不需要帐户来搜索拉取镜像。

# 仪表板

登录到 Docker Hub 后，您将进入以下着陆页。这个页面被称为 Docker Hub 的**仪表板**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/38b9210c-61b3-4d7c-a2b0-87a738efdfd8.png)

从这里，您可以进入 Docker Hub 的所有其他子页面。但是，在我们查看这些部分之前，我们应该稍微谈一下仪表板。从这里，您可以查看所有您的镜像，包括公共和私有。它们首先按星星数量排序，然后按拉取数量排序；这个顺序不能改变。

在接下来的部分中，我们将逐一介绍您在仪表板上看到的所有内容，从页面顶部的深蓝色菜单开始。

# 探索

**探索**选项会带您进入官方 Docker 镜像列表；就像您的**仪表板**一样，它们按星星和拉取次数排序。正如您从以下屏幕中看到的，每个官方镜像的拉取次数都超过 1000 万次：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7afcf1af-ec1e-4b5a-8e65-1b2f7282d0a3.png)

这不是首选的 Docker Store 下载官方镜像的方法。Docker 希望您现在使用 Docker Store，但是由于我们将在本章后面更详细地讨论这一点，我们在这里不会再详细介绍。

# 组织

**组织**是您创建或被添加到的组织。组织允许您为多人合作的项目添加控制层。组织有自己的设置，例如默认情况下是否将存储库存储为公共或私有，或更改计划，允许不同数量的私有存储库，并将存储库与您或其他人完全分开。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d413a10e-eab5-4e2b-96c5-ec0f63b8a236.png)

您还可以从**仪表板**下方的 Docker 标志处访问或切换帐户或组织，通常在您登录时会看到您的用户名：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/22313429-bbf7-4f75-9b8d-5506b6e5f7b2.png)

# 创建

我们将在后面的部分详细介绍如何创建存储库和自动构建，因此我在这里不会详细介绍，除了**创建**菜单给您三个选项：

+   **创建存储库**

+   **创建自动构建**

+   **创建组织**

这些选项可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/dcdcaa8c-ff8c-4ee3-a44f-02dde79a1dc1.png)

# 个人资料和设置

顶部菜单中的最后一个选项是关于管理**我的个人资料**和**设置**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/94f37f95-80e0-46e1-b62d-e5bf664e66b0.png)

设置页面允许您设置您的公共个人资料，其中包括以下选项：

+   更改您的密码

+   查看您所属的组织

+   查看您订阅的电子邮件更新

+   设置您想要接收的特定通知

+   设置哪些授权服务可以访问您的信息

+   查看已链接的帐户（例如您的 GitHub 或 Bitbucket 帐户）

+   查看您的企业许可证、计费和全局设置

目前唯一的全局设置是在创建时选择您的存储库默认为**公共**或**私有**。默认情况下，它们被创建为**公共**存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f9ed7275-c2eb-4c3c-9df5-286deb542a46.png)

“我的个人资料”菜单项将带您到您的公共个人资料页面；我的个人资料可以在[`hub.docker.com/u/russmckendrick/`](https://hub.docker.com/u/russmckendrick/)找到。

# 其他菜单选项

在**仪表板**页面顶部的深蓝色条下面还有两个我们尚未涵盖的区域。第一个是**星标**页面，允许您查看您自己标记为星标的存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b777bca4-59f4-4316-b611-3131dbb57188.png)

如果您发现一些您喜欢使用的存储库，并希望访问它们以查看它们是否最近已更新，或者这些存储库是否发生了其他任何更改，这将非常有用。

第二个是一个新的设置，**贡献**。点击这个将会显示一个部分，其中将列出您在自己的**存储库**列表之外做出贡献的存储库的列表。

# 创建自动构建

在这一部分，我们将看一下自动构建。自动构建是您可以链接到您的 GitHub 或 Bitbucket 帐户的构建，当您更新代码存储库中的代码时，您可以在 Docker Hub 上自动构建镜像。我们将看看完成此操作所需的所有部分，最后，您将能够自动化所有您的构建。

# 设置您的代码

创建自动构建的第一步是设置您的 GitHub 或 Bitbucket 存储库。在选择存储代码的位置时，您有两个选项。在我们的示例中，我将使用 GitHub，但是 GitHub 和 Bitbucket 的设置将是相同的。

实际上，我将使用附带本书的存储库。由于存储库是公开可用的，您可以 fork 它，并使用您自己的 GitHub 帐户跟随，就像我在下面的截图中所做的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/efc78b12-ed7f-4204-83d4-348842b88d6b.png)

在第二章中，*构建容器映像*，我们通过了几个不同的 Dockerfiles。我们将使用这些来进行自动构建。如果您还记得，我们安装了 nginx，并添加了一个带有消息**Hello world! This is being served from Docker**的简单页面，我们还进行了多阶段构建。

# 设置 Docker Hub

在 Docker Hub 中，我们将使用“创建”下拉菜单并选择“创建自动构建”。选择后，我们将被带到一个屏幕，显示您已链接到 GitHub 或 Bitbucket 的帐户：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0f0c0290-2ffa-4764-9c03-e24569febe0a.png)

从前面的截图中可以看出，我已经将我的 GitHub 帐户链接到了 Docker Hub 帐户。链接这两个工具的过程很简单，我所要做的就是按照屏幕上的说明，允许 Docker Hub 访问我的 GitHub 帐户。

当将 Docker Hub 连接到 GitHub 时，有两个选项：

+   **公共和私有**：这是推荐的选项。Docker Hub 将可以访问您的所有公共和私有存储库，以及组织。在设置自动构建时，Docker Hub 还将能够配置所需的 Webhooks。

+   **有限访问**：这将限制 Docker Hub 访问公开可用的存储库和组织。如果您使用此选项链接您的帐户，Docker Hub 将无法配置所需的用于自动构建的 Webhooks。然后，您需要从要从中创建自动构建的位置中搜索并选择存储库。这将基本上创建一个 Webhook，指示当在所选的代码存储库上进行提交时，在 Docker Hub 上将创建一个新的构建。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e86e4a7e-b777-454d-95e1-94f907c2bb98.png)

在前面的截图中，我选择了`Mastering-Docker-Third-Edition`，并访问了自动构建的设置页面。从这里，我们可以选择将图像附加到哪个 Docker Hub 配置文件，命名图像，将其从公共图像更改为私有可用图像，描述构建，并通过单击**单击此处自定义**来自定义它。我们可以让 Docker Hub 知道我们的 Dockerfile 的位置如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8b016edc-4f1a-43c1-8d1b-1823af07864f.png)

如果您在跟着做，我输入了以下信息：

+   **存储库命名空间和名称：** `dockerfile-example`

+   **可见性：**公共

+   **简短描述：**`测试自动构建`

+   **推送类型：**分支

+   **名称：**`master`

+   **Dockerfile 位置：**`/chapter02/dockerfile-example/`

+   **Docker 标签：**最新

点击**创建**后，您将会看到一个类似下一个截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/153124b2-b207-46d8-881c-ae926facd384.png)

现在我们已经定义了构建，可以通过点击**构建设置**来添加一些额外的配置。由于我们使用的是官方的 Alpine Linux 镜像，我们可以将其链接到我们自己的构建中。为此，在**存储库链接**部分输入 Alpine，然后点击**添加存储库链接**。这将在每次官方 Alpine Linux 镜像发布新版本时启动一个无人值守的构建。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6922478b-7d32-4c26-bd3c-c78d86a13edf.png)

现在我们的镜像将在我们更新 GitHub 存储库时自动重建和发布，或者当新的官方镜像发布时。由于这两种情况都不太可能立即发生，所以点击“触发”按钮手动启动构建。您会注意到按钮会在短时间内变成绿色，这证实了后台已经安排了一个构建。

一旦触发了您的构建，点击**构建详情**将会显示出该镜像的所有构建列表，包括成功和失败的构建。您应该会看到一个正在进行的构建；点击它将会显示构建的日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/17e9aace-1120-480c-9299-2a24a451349b.png)

构建完成后，您应该能够通过运行以下命令移动到本地的 Docker 安装中，确保拉取您自己的镜像（如果一直在跟进的话）：

```
$ docker image pull masteringdockerthirdedition/dockerfiles-example
$ docker image ls
```

命令如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/feae53be-7cf1-4484-aa8c-71d533a10bd0.png)

您也可以使用以下命令运行 Docker Hub 创建的镜像，再次确保使用您自己的镜像（如果有的话）：

```
$ docker container run -d -p8080:80 --name example masteringdockerthirdedition/dockerfiles-example
```

我也以完全相同的方式添加了多阶段构建。Docker Hub 对构建没有任何问题，您可以从以下日志中看到，它开始于一些关于 Docker 构建环境的信息：

```
Building in Docker Cloud's infrastructure...
Cloning into '.'...

KernelVersion: 4.4.0-1060-aws
Components: [{u'Version': u'18.03.1-ee-1-tp5', u'Name': u'Engine', u'Details': {u'KernelVersion': u'4.4.0-1060-aws', u'Os': u'linux', u'BuildTime': u'2018-06-23T07:58:56.000000000+00:00', u'ApiVersion': u'1.37', u'MinAPIVersion': u'1.12', u'GitCommit': u'1b30665', u'Arch': u'amd64', u'Experimental': u'false', u'GoVersion': u'go1.10.2'}}]
Arch: amd64
BuildTime: 2018-06-23T07:58:56.000000000+00:00
ApiVersion: 1.37
Platform: {u'Name': u''}
Version: 18.03.1-ee-1-tp5
MinAPIVersion: 1.12
GitCommit: 1b30665
Os: linux
GoVersion: go1.10.2
```

然后构建过程开始编译我们的代码如下：

```
Starting build of index.docker.io/masteringdockerthirdedition/multi-stage:latest...
Step 1/8 : FROM golang:latest as builder
 ---> d0e7a411e3da
Step 2/8 : WORKDIR /go-http-hello-world/
Removing intermediate container ea4bd2a1e92a
 ---> 0735d98776ef
Step 3/8 : RUN go get -d -v golang.org/x/net/html
 ---> Running in 5b180ef58abf
Fetching https://golang.org/x/net/html?go-get=1
Parsing meta tags from https://golang.org/x/net/html?go-get=1 (status code 200)
get "golang.org/x/net/html": found meta tag get.metaImport{Prefix:"golang.org/x/net", VCS:"git", RepoRoot:"https://go.googlesource.com/net"} at https://golang.org/x/net/html?go-get=1
get "golang.org/x/net/html": verifying non-authoritative meta tag
Fetching https://golang.org/x/net?go-get=1
Parsing meta tags from https://golang.org/x/net?go-get=1 (status code 200)
golang.org/x/net (download)
Removing intermediate container 5b180ef58abf
 ---> e2d566167ecd
Step 4/8 : ADD https://raw.githubusercontent.com/geetarista/go-http-hello-world/master/hello_world/hello_world.go ./hello_world.go
 ---> c5489fee49e0
Step 5/8 : RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
 ---> Running in 0c5892f9db02
Removing intermediate container 0c5892f9db02
 ---> 94087063b79a
```

现在我们的代码已经编译完成，接下来将应用程序二进制文件复制到最终镜像中：

```
Step 6/8 : FROM scratch
 ---> 
Step 7/8 : COPY --from=builder /go-http-hello-world/app .
 ---> e16f25bc4201
Step 8/8 : CMD ["./app"]
 ---> Running in c93cfe262c15
Removing intermediate container c93cfe262c15
 ---> bf3498b1f51e

Successfully built bf3498b1f51e
Successfully tagged masteringdockerthirdedition/multi-stage:latest
Pushing index.docker.io/masteringdockerthirdedition/multi-stage:latest...
Done!
Build finished
```

您可以使用以下命令拉取和启动包含该镜像的容器：

```
$ docker image pull masteringdockerthirdedition/multi-stage
$ docker image ls
$ docker container run -d -p 8000:80 --name go-hello-world masteringdockerthirdedition/multi-stage
$ curl http://localhost:8000/
```

如下截图所示，该镜像的行为方式与我们在本地创建时完全相同：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3e092fb2-c73e-41a6-8b86-35734fd9d03b.png)

如果您启动了容器，可以使用以下命令删除它们：

```
$ docker container stop example
$ docker container rm example
$ docker container stop go-hello-world
$ docker container rm go-hello-world
```

现在我们已经了解了自动化构建，我们可以讨论如何以其他方式将镜像推送到 Docker Hub。

# 推送您自己的镜像

在第二章中，*构建容器镜像*，我们讨论了在不使用 Dockerfile 的情况下创建镜像。虽然这仍然不是一个好主意，应该只在您真正需要时使用，但您可以将自己的镜像推送到 Docker Hub。

以这种方式将镜像推送到 Docker Hub 时，请确保不包括任何您不希望公开访问的代码、文件或环境变量。

为此，我们首先需要通过运行以下命令将本地 Docker 客户端链接到 Docker Hub：

```
$ docker login
```

然后会提示您输入 Docker ID 和密码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/87505ffd-86d7-430f-826b-a1cf9932b4d8.png)

此外，如果您使用的是 Docker for Mac 或 Docker for Windows，您现在将通过应用程序登录，并应该能够从菜单访问 Docker Hub：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2433ddec-62d9-4ecf-81b1-1257083a4df3.png)

现在我们的客户端已被授权与 Docker Hub 交互，我们需要一个要构建的镜像。让我们看看如何推送我们在第二章中构建的 scratch 镜像，*构建容器镜像*。首先，我们需要构建镜像。为此，我使用以下命令：

```
$ docker build --tag masteringdockerthirdedition/scratch-example:latest .
```

如果您在跟着做，那么您应该将`masteringdockerthirdedition`替换为您自己的用户名或组织：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/04aca08c-a396-4472-8bc3-03b726896b27.png)

构建完镜像后，我们可以通过运行以下命令将其推送到 Docker Hub：

```
$ docker image push masteringdockerthirdedition/scratch-example:latest
```

以下屏幕截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2f9e0035-3858-4913-895e-6becdb40de32.png)

正如您所看到的，因为我们在构建镜像时定义了`masteringdockerthirdedition/scratch-example:latest`，Docker 自动将镜像上传到该位置，从而向`Mastering Docker Third Edition`组织添加了一个新镜像。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b231c61b-33ef-44c5-bc04-12411bd0fb40.png)

您会注意到在 Docker Hub 中无法做太多事情。这是因为镜像不是由 Docker Hub 构建的，因此它实际上并不知道构建镜像时发生了什么。

# Docker 商店

您可能还记得在第一章中，*Docker 概述*，我们从 Docker Store 下载了 macOS 和 Windows 的 Docker。除了作为下载各种平台的**Docker CE**和**Docker EE**的单一位置外，它现在也是查找**Docker Images**和**Docker Plugins**的首选位置。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b86f1bae-110b-4f47-8388-c347e577d115.png)

虽然您只会在 Docker Store 中找到官方和认证的图像，但也可以使用 Docker Store 界面来搜索 Docker Hub。此外，您可以下载来自 Docker Hub 不可用的图像，例如 Citrix NetScaler CPX Express 图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9b47411c-b0aa-4ea5-8ac2-2ade614199e8.png)

如果您注意到，图像附加了价格（Express 版本为$0.00），这意味着您可以通过 Docker Store 购买商业软件，因为它内置了付款和许可。如果您是软件发布者，您可以通过 Docker Store 签署和分发自己的软件。

在后面的章节中，当我们涵盖 Docker 插件时，我们将更详细地了解 Docker Store。

# Docker Registry

在本节中，我们将研究 Docker Registry。**Docker Registry**是一个开源应用程序，您可以在任何地方运行并存储您的 Docker 图像。我们将看看 Docker Registry 和 Docker Hub 之间的比较，以及如何在两者之间进行选择。在本节结束时，您将学会如何运行自己的 Docker Registry，并查看它是否适合您。

# Docker Registry 概述

如前所述，Docker Registry 是一个开源应用程序，您可以利用它在您选择的平台上存储您的 Docker 图像。这使您可以根据需要将它们保持 100%私有，或者分享它们。

如果您想部署自己的注册表而无需支付 Docker Hub 的所有私有功能，那么 Docker Registry 就有很多意义。接下来，让我们看一下 Docker Hub 和 Docker Registry 之间的一些比较，以帮助您做出明智的决定，选择哪个平台来存储您的图像。

Docker Registry 具有以下功能：

+   从中您可以作为私有、公共或两者混合来提供所有存储库的主机和管理您自己的注册表

+   根据您托管的图像数量或提供的拉取请求数量，根据需要扩展注册表

+   一切都是基于命令行的

使用 Docker Hub，您将：

+   获得一个基于 GUI 的界面，您可以用来管理您的图像

+   在云中已经设置好了一个位置，可以处理公共和/或私有图像

+   放心，不必管理托管所有图像的服务器

# 部署您自己的 Registry

正如您可能已经猜到的，Docker Registry 作为 Docker Hub 的一个镜像分发，这使得部署它就像运行以下命令一样简单：

```
$ docker image pull registry:2
$ docker container run -d -p 5000:5000 --name registry registry:2
```

这些命令将为您提供最基本的 Docker Registry 安装。让我们快速看一下如何将图像推送到其中并从中拉取。首先，我们需要一个图像，所以让我们再次获取 Alpine 图像：

```
$ docker image pull alpine
```

现在我们有了 Alpine Linux 图像的副本，我们需要将其推送到我们的本地 Docker Registry，该 Registry 位于`localhost:5000`。为此，我们需要使用我们本地 Docker Registry 的 URL 来标记 Alpine Linux 图像，并使用不同的图像名称：

```
$ docker image tag alpine localhost:5000/localalpine
```

现在我们已经标记了我们的图像，我们可以通过运行以下命令将其推送到我们本地托管的 Docker Registry：

```
$ docker image push localhost:5000/localalpine
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e0fd1833-1710-4430-9a66-fed096319f3b.png)

尝试运行以下命令：

```
$ docker image ls
```

输出应该向您显示具有相同`IMAGE ID`的两个图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/35e7db0c-7e62-43ab-b156-cb532d6c26ba.png)

在我们从本地 Docker Registry 中重新拉取图像之前，我们应该删除图像的两个本地副本。我们需要使用`REPOSITORY`名称来执行此操作，而不是`IMAGE ID`，因为我们有两个位置的两个相同 ID 的图像，Docker 会抛出错误：

```
$ docker image rm alpine localhost:5000/localalpine
```

现在原始和标记的图像已被删除，我们可以通过运行以下命令从本地 Docker Registry 中拉取图像：

```
$ docker image pull localhost:5000/localalpine
$ docker image ls
```

正如您所看到的，我们现在有一个从 Docker Registry 中拉取的图像副本在`localhost:5000`上运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e0902ec1-c71c-4565-8cd7-a57665834ee0.png)

您可以通过运行以下命令停止和删除 Docker Registry：

```
$ docker container stop registry
$ docker container rm -v registry
```

现在，在启动 Docker Registry 时有很多选项和考虑因素。正如您所想象的那样，最重要的是围绕存储。

鉴于 Registry 的唯一目的是存储和分发图像，重要的是您使用一定级别的持久性 OS 存储。Docker Registry 目前支持以下存储选项：

+   文件系统：这正是它所说的；所有的镜像都存储在您定义的路径上。默认值是`/var/lib/registry`。

+   Azure：这使用微软 Azure Blob 存储。

+   GCS：这使用 Google 云存储。

+   S3：这使用亚马逊简单存储服务（Amazon S3）。

+   Swift：这使用 OpenStack Swift。

正如您所看到的，除了文件系统之外，所有支持的存储引擎都是高可用的，分布式对象级存储。我们将在后面的章节中看到这些云服务。

# Docker Trusted Registry

商业版**Docker 企业版**（**Docker EE**）附带的一个组件是**Docker Trusted Registry**（**DTR**）。把它看作是一个您可以在自己的基础设施中托管的 Docker Hub 版本。DTR 在免费的 Docker Hub 和 Docker 注册表提供的功能之上增加了以下功能：

+   集成到您的身份验证服务，如 Active Directory 或 LDAP

+   在您自己的基础设施（或云）部署在您的防火墙后面

+   图像签名以确保您的图像是可信的

+   内置安全扫描

+   直接从 Docker 获得优先支持

# 第三方注册表

不仅 Docker 提供图像注册表服务；像 Red Hat 这样的公司也提供他们自己的注册表，您可以在那里找到 Red Hat 容器目录，其中托管了所有 Red Hat 产品提供的容器化版本，以及支持其 OpenShift 产品的容器。

像 JFrog 的 Artifactory 这样的服务提供了私有的 Docker 注册表作为其构建服务的一部分。还有其他的注册表即服务提供，比如 CoreOS 的 Quay，现在被 Red Hat 拥有，还有来自亚马逊网络服务和微软 Azure 的服务。当我们继续研究云中的 Docker 时，我们将看看这些服务。

# Microbadger

**Microbadger**是一个很好的工具，当您考虑要运输您的容器或图像时。它将考虑到特定 Docker 图像的每个层中发生的一切，并为您提供实际大小或它将占用多少磁盘空间的输出。

当您导航到 Microbadger 网站时，您将看到这个页面，[`microbadger.com/`](https://microbadger.com/)：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/748cf6b5-1cb4-4cea-a32f-033fefa47af3.png)

您可以搜索 Docker Hub 上的镜像，让 Microbadger 为您提供有关该镜像的信息，或者加载一个示例镜像集，如果您想提供一些示例集，或者查看一些更复杂的设置。

在这个例子中，我们将搜索我们在本章前面推送的`masteringdockerthirdedition/dockerfiles-example`镜像，并选择最新的标签。如下截图所示，Docker Hub 会在您输入时自动搜索，并实时返回结果。

默认情况下，它将始终加载最新的标签，但您也可以通过从**版本**下拉菜单中选择所需的标签来更改您正在查看的标签。例如，如果您有一个暂存标签，并且正在考虑将这个新镜像推送到最新标签，但想要看看它对镜像大小的影响，这可能会很有用。

如下截图所示，Microbadger 提供了有关您的镜像包含多少层的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b3fb9585-9fd9-4bbb-9043-d262220d59d6.png)

通过显示每个层的大小和镜像构建过程中执行的 Dockerfile 命令，您可以看到镜像构建的哪个阶段添加了膨胀，这在减小镜像大小时非常有用。

另一个很棒的功能是，Microbadger 可以让您选择将有关您的镜像的基本统计信息嵌入到您的 Git 存储库或 Docker Hub 中；例如，以下屏幕显示了我自己的一个镜像的 Docker Hub 页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e6cfb3e3-e198-4527-a92e-98a92be2e939.png)

正如您从以下截图中所看到的，Microbadger 显示了镜像的总体大小，在这个例子中是 5.9MB，以及镜像由多少层组成的总数，为 7。Microbadger 服务仍处于测试阶段，新功能正在不断添加。我建议您密切关注它。

# 总结

在本章中，我们探讨了使用 Docker Hub 手动和自动构建容器镜像的几种方法。我们讨论了除了 Docker Hub 之外您可以使用的各种注册表，例如 Docker Store 和 Red Hat 的容器目录。

我们还研究了部署我们自己的本地 Docker 注册表，并提及了在部署时需要考虑的存储问题。最后，我们看了 Microbadger，这是一个允许您显示有关远程托管容器镜像信息的服务。

在下一章中，我们将看看如何从命令行管理我们的容器。

# 问题

1.  真或假：Docker Hub 是您可以下载官方 Docker 镜像的唯一来源。

1.  描述为什么您想要将自动构建链接到官方 Docker Hub 镜像。

1.  多阶段构建是否受 Docker Hub 支持？

1.  真或假：在命令行中登录 Docker 也会登录到桌面应用程序？

1.  您如何删除共享相同 IMAGE ID 的两个镜像？

1.  Docker Registry 默认运行在哪个端口？

# 进一步阅读

有关 Docker Store、Trusted Registry 和 Registry 的更多信息，请访问：

+   Docker Store 发布者注册：[`store.docker.com/publisher/signup/`](https://store.docker.com/publisher/signup/)

+   Docker Trusted Registry（DTR）：[`docs.docker.com/ee/dtr/`](https://docs.docker.com/ee/dtr/)

+   Docker Registry 文档：[`docs.docker.com/registry/`](https://docs.docker.com/registry/)

您可以在以下位置找到有关可用于 Docker Registry 的不同类型的基于云的存储的更多详细信息：

+   Azure Blob 存储：[`azure.microsoft.com/en-gb/services/storage/blobs/`](https://azure.microsoft.com/en-gb/services/storage/blobs/)

+   Google Cloud 存储：[`cloud.google.com/storage/`](https://cloud.google.com/storage/)

+   亚马逊简单存储服务（Amazon S3）：[`aws.amazon.com/s3/`](https://aws.amazon.com/s3/)

+   Swift：这使用 OpenStack Swift：[`wiki.openstack.org/wiki/Swift`](https://wiki.openstack.org/wiki/Swift)

一些第三方注册服务可以在这里找到：

+   Red Hat 容器目录：[`access.redhat.com/containers/`](https://access.redhat.com/containers/)

+   OpenShift：[`www.openshift.com/`](https://www.openshift.com/)

+   JFrog 的 Artifactory：[`www.jfrog.com/artifactory/`](https://www.jfrog.com/artifactory/)

+   Quay: [`quay.io/`](https://quay.io/)

最后，您可以在这里找到我的 Apache Bench 镜像的 Docker Hub 和 Microbadger 链接：

+   Apache Bench 镜像（Docker Hub）：[`hub.docker.com/r/russmckendrick/ab/`](https://hub.docker.com/r/russmckendrick/ab/)

+   Apache Bench 镜像（Microbadger）：[`microbadger.com/images/russmckendrick/ab`](https://microbadger.com/images/russmckendrick/ab)
