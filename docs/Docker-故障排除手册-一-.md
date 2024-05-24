# Docker 故障排除手册（一）

> 原文：[`zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3`](https://zh.annas-archive.org/md5/26C3652580332746A9E26A30363AEFD3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Docker 是一个开源的基于容器的平台，可以让任何人在任何地方一致地开发和部署稳定的应用程序。Docker 在创建可扩展和可移植环境方面提供了速度、简单性和安全性。随着 Docker 在现代微服务和 N 层应用的容器化中的出现和普及，有效地解决生产级部署的自动化工作流程是明智且必要的。

# 本书内容

第一章，理解容器场景和 Docker 概述，介绍了基本的容器化概念，以应用程序和基于操作系统的容器为例。我们将介绍 Docker 技术、其优势以及 Docker 容器的生命周期。

第二章，Docker 安装，将介绍在各种 Linux 发行版上安装 Docker 的步骤 - Ubuntu，CoreOS，CentOS，Red Hat Linux，Fedora 和 SUSE Linux。

第三章，构建基础和分层镜像，教授了在生产就绪的应用容器化中构建镜像的重要任务。我们还将讨论如何手动从头开始构建镜像。接下来，我们将详细探讨使用 Dockerfile 构建分层镜像，并列出 Dockerfile 命令。

第四章，设计微服务和 N 层应用，将探讨从开发到测试无缝设计的示例环境，消除了手动和容易出错的资源配置和配置的需求。在这样做的过程中，我们将简要介绍微服务应用程序如何进行测试、自动化、部署和管理。

第五章，移动容器化应用，将介绍 Docker 注册表。我们将从使用 Docker Hub 的 Docker 公共存储库的基本概念开始，以及与更大观众共享容器的用例。Docker 还提供了部署私有 Docker 注册表的选项，我们将探讨这一点，该注册表可用于在组织内部推送、拉取和共享 Docker 容器。

第六章，“使容器工作”，将教你关于特权容器，它们可以访问所有主机设备，以及超级特权容器，它们表明容器可以运行后台服务，用于在 Docker 容器中运行服务以管理底层主机。

第七章，“管理 Docker 容器的网络堆栈”，将解释 Docker 网络是如何通过 Docker0 桥接进行配置和故障排除的。我们还将探讨 Docker 网络与外部网络之间的通信问题的故障排除。我们将研究使用不同网络选项（如 Weave、OVS、Flannel 和 Docker 的最新覆盖网络）在多个主机之间进行容器通信，并比较它们以及它们配置中涉及的故障排除问题。

第八章，“使用 Kubernetes 管理 Docker 容器”，解释了如何借助 Kubernetes 管理 Docker 容器。我们将涵盖许多部署场景和在裸机、AWS、vSphere 或使用 minikube 部署 Kubernetes 时的故障排除问题。我们还将探讨有效部署 Kubernetes pods 和调试 Kubernetes 问题。

第九章，“挂载卷包”，将深入探讨与 Docker 相关的数据卷和存储驱动器概念。我们将讨论使用四种方法来故障排除数据卷，并研究它们的优缺点。存储数据在 Docker 容器内部的第一种情况是最基本的情况，但它不提供在生产环境中管理和处理数据的灵活性。第二和第三种情况是使用仅存储数据的容器或直接存储在主机上的情况。第四种情况是使用第三方卷插件，如 Flocker 或 Convoy，它将数据存储在单独的块中，即使容器从一个主机转移到另一个主机，或者容器死亡，也能提供数据的可靠性。

第十章，“在公共云中部署 Docker - AWS 和 Azure”，概述了在 Microsoft Azure 和 AWS 公共云上部署 Docker。

# 本书所需内容

您需要在 Windows、Mac OS 或 Linux 机器上安装 Docker 1.12+。可能需要 AWS、Azure 和 GCE 的公共云账户，这些在各章节的相应部分中提到。

# 本书适合对象

本书旨在帮助经验丰富的解决方案架构师、开发人员、程序员、系统工程师和管理员解决 Docker 容器化的常见问题。如果您希望构建用于自动部署的生产就绪的 Docker 容器，您将能够掌握和解决 Docker 的基本功能和高级功能。熟悉 Linux 命令行语法、单元测试、Docker 注册表、GitHub 以及领先的容器托管平台和云服务提供商（CSP）是先决条件。在本书中，您还将了解避免首次进行故障排除的方法和手段。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“使用`start_k8s.sh` shell 脚本重新启动集群。”

代码块设置如下：

```
ENTRYPOINT /usr/sbin/sshd -D 
VOLUME ["/home"] 
EXPOSE 22 
EXPOSE 8080
```

任何命令行输入或输出都以以下形式书写：

```
Docker build -t username/my-imagename -f /path/Dockerfile

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为：“指定**堆栈名称**、**密钥对**和集群 3。”

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：理解容器场景和 Docker 概述

Docker 是最近最成功的开源项目之一，它提供了任何应用程序的打包、运输和运行，作为轻量级容器。我们实际上可以将 Docker 容器比作提供标准、一致的运输任何应用程序的集装箱。Docker 是一个相当新的项目，借助本书的帮助，将很容易解决 Docker 用户在安装和使用 Docker 容器时遇到的一些常见问题。

本章重点将放在以下主题上：

+   解码容器

+   深入 Docker

+   Docker 容器的优势

+   Docker 生命周期

+   Docker 设计模式

+   单内核

# 解码容器

容器化是虚拟机的一种替代方案，它涉及封装应用程序并为其提供自己的操作环境。容器的基本基础是 Linux 容器（LXC），它是 Linux 内核封装特性的用户空间接口。借助强大的 API 和简单的工具，它让 Linux 用户创建和管理应用程序容器。LXC 容器介于`chroot`和完整的虚拟机之间。容器化和传统的虚拟化程序之间的另一个关键区别是，容器共享主机机器上运行的操作系统使用的 Linux 内核，因此在同一台机器上运行的多个容器使用相同的 Linux 内核。与虚拟机相比，它具有快速的优势，几乎没有性能开销。

容器的主要用例列在以下各节中。

## 操作系统容器

操作系统容器可以很容易地想象成一个虚拟机（VM），但与 VM 不同的是，它们共享主机操作系统的内核，但提供用户空间隔离。与 VM 类似，可以为容器分配专用资源，并且可以安装、配置和运行不同的应用程序、库等，就像在任何 VM 上运行一样。在可伸缩性测试的情况下，操作系统容器非常有用，可以轻松部署一系列具有不同发行版的容器，与部署 VM 相比成本要低得多。容器是从模板或镜像创建的，这些模板或镜像确定了容器的结构和内容。它允许您在所有容器中创建具有相同环境、相同软件包版本和配置的容器，主要用于开发环境设置的情况。

有各种容器技术，如 LXC、OpenVZ、Docker 和 BSD jails，适用于操作系统容器：

![操作系统容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_001.jpg)

基于操作系统的容器

## 应用容器

应用容器旨在在一个包中运行单个服务，而先前解释过的操作系统容器可以支持多个进程。自 Docker 和 Rocket 推出后，应用容器受到了很多关注。

每当启动一个容器时，它都会运行一个进程。这个进程运行一个应用程序进程，但在操作系统容器的情况下，它在同一个操作系统上运行多个服务。容器通常采用分层方法，就像 Docker 容器一样，这有助于减少重复和增加重用。容器可以从所有组件共同的基本镜像开始启动，然后我们可以在文件系统中添加特定于组件的层。分层文件系统有助于回滚更改，因为如果需要，我们可以简单地切换到旧层。在 Dockerfile 中指定的`run`命令为容器添加了一个新层。

应用容器的主要目的是将应用程序的不同组件打包到单独的容器中。应用程序的不同组件被单独打包到容器中，然后它们通过 API 和服务进行交互。分布式多组件系统部署是微服务架构的基本实现。在前述方法中，开发人员可以根据自己的需求打包应用程序，IT 团队可以在多个平台上部署容器，以实现系统的水平和垂直扩展：

### 注意

Hypervisor 是一个**虚拟机监视器**（**VMM**），用于允许多个操作系统在主机上运行和共享硬件资源。每个虚拟机被称为一个客户机。

![应用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_002.jpg)

Docker 层

以下简单示例解释了应用容器和操作系统容器之间的区别：

让我们考虑一下 Web 三层架构的例子。我们有一个数据库层，比如**MySQL**或**Nginx**用于负载均衡，应用层是**Node.js**：

![应用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_003.jpg)

一个操作系统容器

在操作系统容器的情况下，我们可以默认选择 Ubuntu 作为基本容器，并使用 Dockerfile 安装服务 MySQL，nginx 和 Node.js。这种打包适用于测试或开发设置，其中所有服务都打包在一起，并可以在开发人员之间共享和传送。但是，将此架构部署到生产环境中不能使用操作系统容器，因为没有考虑数据可扩展性和隔离性。应用容器有助于满足这种用例，因为我们可以通过部署更多的应用程序特定容器来扩展所需的组件，并且还有助于满足负载均衡和恢复用例。对于前述的三层架构，每个服务将被打包到单独的容器中，以满足架构部署的用例：

![应用容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_004.jpg)

应用容器的扩展

操作系统和应用容器之间的主要区别是：

| **操作系统容器** | **应用容器** |
| --- | --- |
| 旨在在同一操作系统容器上运行多个服务 | 旨在运行单个服务 |
| 本地，没有分层文件系统 | 分层文件系统 |
| 示例：LXC，OpenVZ，BSD Jails | 示例：Docker，Rocket |

## 深入 Docker

Docker 是一个容器实现，在近年来引起了巨大的兴趣。它整齐地捆绑了各种 Linux 内核特性和服务，如命名空间、cgroups、SELinux、AppArmor 配置文件等，以及 Union 文件系统，如 AUFS 和 BTRFS，以制作模块化的镜像。这些镜像为应用程序提供了高度可配置的虚拟化环境，并遵循一次编写，随处运行的原则。一个应用程序可以简单到运行一个进程，也可以是高度可扩展和分布式的进程共同工作。

Docker 因其性能敏锐和普遍可复制的架构而在行业中获得了很多关注，同时提供了现代应用开发的以下四个基石：

+   自治

+   去中心化

+   并行性

+   隔离

此外，Thoughtworks 的微服务架构或**大量小应用**（LOSA）的广泛采用进一步为 Docker 技术带来潜力。因此，谷歌、VMware 和微软等大公司已经将 Docker 移植到他们的基础设施上，并且随着 Tutum、Flocker、Giantswarm 等众多 Docker 初创公司的推出，这种势头还在持续。

由于 Docker 容器可以在任何地方复制其行为，无论是在开发机器、裸机服务器、虚拟机还是数据中心，应用程序设计者可以将注意力集中在开发上，而操作语义留给 DevOps。这使得团队工作流程模块化、高效和高产。Docker 不应与 VM 混淆，尽管它们都是虚拟化技术。Docker 共享操作系统，同时为运行在容器中的应用程序提供足够的隔离和安全性，然后完全抽象出操作系统并提供强大的隔离和安全性保证。但是与 VM 相比，Docker 的资源占用量微不足道，因此更受经济和性能的青睐。然而，它仍然不能完全取代 VM，容器的使用是 VM 技术的补充：

![深入 Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_005.jpg)

VM 和 Docker 架构

## Docker 容器的优势

以下是在微服务架构中使用 Docker 容器的一些优势：

+   **快速应用部署**：由于尺寸减小，容器可以快速部署，因为只有应用程序被打包。

+   **可移植性**：一个应用及其操作环境（依赖项）可以捆绑到一个单独的 Docker 容器中，独立于操作系统版本或部署模型。Docker 容器可以轻松地转移到另一台运行 Docker 容器的机器上，并且在没有任何兼容性问题的情况下执行。Windows 支持也将成为未来 Docker 版本的一部分。

+   **易共享**：预构建的容器镜像可以通过公共存储库以及用于内部使用的托管私有存储库轻松共享。

+   **轻量级占用空间**：即使 Docker 镜像非常小，也具有最小的占用空间，可以使用容器轻松部署新应用程序。

+   **可重用性**：Docker 容器的连续版本可以轻松构建，并且可以在需要时轻松回滚到先前的版本。它们因为可以重用来自现有层的组件而变得明显轻量级。

## Docker 生命周期

这些是 Docker 容器生命周期中涉及的一些基本步骤：

1.  使用包含打包所需的所有命令的 Dockerfile 构建 Docker 镜像。可以以以下方式运行：

```
Docker build

```

标签名称可以以以下方式添加：

```
Docker build -t username/my-imagename .

```

如果 Dockerfile 存在于不同的路径，则可以通过提供`-f`标志来执行 Docker `build`命令：

```
Docker build -t username/my-imagename -f /path/Dockerfile

```

1.  在创建镜像之后，可以使用`Docker run`来部署容器。可以使用`Docker ps`命令来检查正在运行的容器，该命令列出当前活动的容器。还有两个要讨论的命令：

+   `Docker pause`：此命令使用 cgroups 冻结器来暂停容器中运行的所有进程。在内部，它使用 SIGSTOP 信号。使用此命令，进程可以在需要时轻松暂停和恢复。

+   `Docker start`：此命令用于启动一个或多个已停止的容器。

1.  在使用容器后，可以将其停止或杀死；`Docker stop`命令将通过发送 SIGTERM 然后 SIGKILL 命令优雅地停止运行的容器。在这种情况下，仍然可以使用`Docker ps -a`命令列出容器。`Docker kill`将通过向容器内部运行的主进程发送 SIGKILL 来杀死运行的容器。

1.  如果在容器运行时对容器进行了一些更改，这些更改可能会被保留，可以在容器停止后使用`Docker commit`将容器转换回镜像：

Docker 生命周期

## Docker 设计模式

这里列出了八个 Docker 设计模式及其示例。Dockerfile 是我们定义 Docker 镜像的基本结构，它包含了组装镜像的所有命令。使用`Docker build`命令，我们可以创建一个自动化构建，执行所有前面提到的命令行指令来创建一个镜像：

```
$ Docker build
Sending build context to Docker daemon 6.51 MB
...

```

这里列出的设计模式可以帮助创建在卷中持久存在的 Docker 镜像，并提供各种灵活性，以便可以随时轻松地重新创建或替换它们。

### 基础镜像共享

为了创建基于 web 的应用程序或博客，我们可以创建一个基础镜像，可以共享并帮助轻松部署应用程序。这种模式有助于将所有所需的服务打包到一个基础镜像之上，以便这个 web 应用程序博客镜像可以在任何地方重复使用：

```
    FROM debian:wheezy 
    RUN apt-get update 
    RUN apt-get -y install ruby ruby-dev build-essential git 
    # For debugging 
    RUN apt-get install -y gdb strace 
    # Set up my user 
    RUN useradd -u 1000 -ms /bin/bash vkohli 
       RUN gem install -n /usr/bin bundler 
    RUN gem install -n /usr/bin rake 
    WORKDIR /home/vkohli/ 
    ENV HOME /home/vkohli 
    VOLUME ["/home"] 
    USER vkohli 
    EXPOSE 8080 

```

前面的 Dockerfile 显示了创建基于应用程序的镜像的标准方式。

### 注

Docker 镜像是一个压缩文件，是基础镜像中所有配置参数以及所做更改的快照（操作系统的内核）。

它在 Debian 基础镜像上安装了一些特定工具（Ruby 工具 rake 和 bundler）。它创建了一个新用户，将其添加到容器镜像中，并通过从主机挂载`"/home"`目录来指定工作目录，这在下一节中有详细说明。

### 共享卷

在主机级别共享卷允许其他容器获取它们所需的共享内容。这有助于更快地重建 Docker 镜像，或者在添加、修改或删除依赖项时。例如，如果我们正在创建前面提到的博客的主页部署，唯一需要共享的目录是`/home/vkohli/src/repos/homepage`目录，通过以下方式通过 Dockerfile 与这个 web 应用容器共享：

```
  FROM vkohli/devbase 
          WORKDIR /home/vkohli/src/repos/homepage 
          ENTRYPOINT bin/homepage web 

```

为了创建博客的开发版本，我们可以共享`/home/vkohli/src/repos/blog`文件夹，其中所有相关的开发者文件可以驻留。并且为了创建开发版本镜像，我们可以从预先创建的`devbase`中获取基础镜像：

```
FROM vkohli/devbase 
WORKDIR / 
USER root 
# For Graphivz integration 
RUN apt-get update 
RUN apt-get -y install graphviz xsltproc imagemagick 
       USER vkohli 
         WORKDIR /home/vkohli/src/repos/blog 
         ENTRYPOINT bundle exec rackup -p 8080 

```

### 开发工具容器

为了开发目的，我们在开发和生产环境中有不同的依赖关系，这些依赖关系很容易在某个时候混合在一起。容器可以通过将它们分开打包来帮助区分依赖关系。如下所示，我们可以从基本映像中派生开发工具容器映像，并在其上安装开发依赖，甚至允许`ssh`连接，以便我们可以处理代码：

```
FROM vkohli/devbase 
RUN apt-get update 
RUN apt-get -y install openssh-server emacs23-nox htop screen 

# For debugging 
RUN apt-get -y install sudo wget curl telnet tcpdump 
# For 32-bit experiments 
RUN apt-get -y install gcc-multilib  
# Man pages and "most" viewer: 
RUN apt-get install -y man most 
RUN mkdir /var/run/sshd 
ENTRYPOINT /usr/sbin/sshd -D 
VOLUME ["/home"] 
EXPOSE 22 
EXPOSE 8080 

```

如前面的代码所示，安装了基本工具，如`wget`、`curl`和`tcpdump`，这些工具在开发过程中是必需的。甚至安装了 SSHD 服务，允许在开发容器中进行`ssh`连接。

### 测试环境容器

在不同的环境中测试代码总是有助于简化流程，并有助于在隔离中发现更多的错误。我们可以创建一个 Ruby 环境在一个单独的容器中生成一个新的 Ruby shell，并用它来测试代码库。

```
FROM vkohli/devbase 
RUN apt-get update 
RUN apt-get -y install ruby1.8 git ruby1.8-dev 

```

在列出的 Dockerfile 中，我们使用`devbase`作为基本映像，并借助一个`docker run`命令，可以轻松地使用从该 Dockerfile 创建的映像创建一个新的环境来测试代码。

### 构建容器

我们的应用程序中涉及一些耗费时间的构建步骤。为了克服这一点，我们可以创建一个单独的构建容器，该容器可以使用构建过程中所需的依赖项。以下 Dockerfile 可用于运行单独的构建过程：

```
FROM sampleapp 
RUN apt-get update 
RUN apt-get install -y build-essential [assorted dev packages for libraries] 
VOLUME ["/build"] 
WORKDIR /build 
CMD ["bundler", "install","--path","vendor","--standalone"] 

```

`/build`目录是共享目录，可用于提供已编译的二进制文件，还可以将容器中的`/build/source`目录挂载到提供更新的依赖项。因此，通过使用构建容器，我们可以将构建过程和最终打包过程分离开来。它仍然通过将前面的过程分解为单独的容器来封装过程和依赖关系。

### 安装容器

该容器的目的是将安装步骤打包到单独的容器中。基本上，这是为了在生产环境中部署容器。

显示了将安装脚本打包到 Docker 映像中的示例 Dockerfile：

```
ADD installer /installer 
CMD /installer.sh 

```

`installer.sh` 可以包含特定的安装命令，在生产环境中部署容器，并提供代理设置和 DNS 条目，以便部署一致的环境。

### 服务容器

为了在一个容器中部署完整的应用程序，我们可以捆绑多个服务以提供完整的部署容器。在这种情况下，我们将 Web 应用程序、API 服务和数据库捆绑在一个容器中。这有助于简化各种独立容器之间的互联的痛苦。

```
services: 
  web: 
    git_url: git@github.com:vkohli/sampleapp.git 
    git_branch: test 
    command: rackup -p 3000 
    build_command: rake db:migrate 
    deploy_command: rake db:migrate 
    log_folder: /usr/src/app/log 
    ports: ["3000:80:443", "4000"] 
    volumes: ["/tmp:/tmp/mnt_folder"] 
    health: default 
  api: 
    image: quay.io/john/node 
    command: node test.js 
    ports: ["1337:8080"] 
    requires: ["web"] 
databases: 
  - "mysql" 
  - "redis" 

```

### 基础设施容器

正如我们在开发环境中讨论过的容器使用，还有一个重要的类别缺失-用于基础设施服务的容器的使用，比如代理设置，它提供了一个连贯的环境，以便提供对应用程序的访问。在下面提到的 Dockerfile 示例中，我们可以看到安装了`haproxy`并提供了其配置文件的链接：

```
FROM debian:wheezy 
ADD wheezy-backports.list /etc/apt/sources.list.d/ 
RUN apt-get update 
RUN apt-get -y install haproxy 
ADD haproxy.cfg /etc/haproxy/haproxy.cfg 
CMD ["haproxy", "-db", "-f", "/etc/haproxy/haproxy.cfg"] 
EXPOSE 80 
EXPOSE 443 

```

`haproxy.cfg`文件是负责对用户进行身份验证的配置文件：

```
backend test 
    acl authok http_auth(adminusers) 
    http-request auth realm vkohli if !authok 
    server s1 192.168.0.44:8084 

```

# Unikernels

Unikernels 将源代码编译成一个包括应用逻辑所需功能的自定义操作系统，生成一个专门的单地址空间机器映像，消除了不必要的代码。Unikernels 是使用*库操作系统*构建的，与传统操作系统相比具有以下优点：

+   快速启动时间：Unikernels 使得配置高度动态化，并且可以在不到一秒的时间内启动

+   小的占地面积：Unikernel 代码库比传统的操作系统等效代码库要小，而且管理起来也同样容易

+   提高安全性：由于不部署不必要的代码，攻击面大大减少

+   精细化优化：Unikernels 是使用编译工具链构建的，并且针对设备驱动程序和应用逻辑进行了优化

Unikernels 与微服务架构非常匹配，因为源代码和生成的二进制文件都可以很容易地进行版本控制，并且足够紧凑，可以重新构建。而另一方面，修改虚拟机是不允许的，只能对源代码进行修改，这是耗时且繁琐的。例如，如果应用程序不需要磁盘访问和显示功能。Unikernels 可以帮助从内核中删除这些不必要的设备驱动程序和显示功能。因此，生产系统变得极简，只打包应用代码、运行时环境和操作系统设施，这是不可变应用部署的基本概念，如果在生产服务器上需要进行任何应用程序更改，则会构建一个新的映像：

![Unikernels](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_01_007.jpg)

从传统容器过渡到基于 Unikernel 的容器

容器和 Unikernels 是彼此的最佳选择。最近，Unikernel 系统已成为 Docker 的一部分，这两种技术的合作很快将在下一个 Docker 版本中看到。如前图所示，第一个显示了支持多个 Docker 容器的传统打包方式。下一步显示了一对一的映射（一个容器对应一个 VM），这允许每个应用程序是自包含的，并且能更好地利用资源，但为每个容器创建一个单独的 VM 会增加开销。在最后一步中，我们可以看到 Unikernels 与当前现有的 Docker 工具和生态系统的合作，其中一个容器将获得特定于其需求的内核低库环境。

Unikernels 在 Docker 工具链中的采用将加速 Unikernels 的进展，并且它将被广泛使用和理解为一种打包模型和运行时框架，使 Unikernels 成为另一种类型的容器。在为 Docker 开发人员提供 Unikernels 抽象之后，我们将能够选择是使用传统的 Docker 容器还是 Unikernel 容器来创建生产环境。

# 摘要

在本章中，我们通过应用程序和基于操作系统的容器的帮助下学习了基本的容器化概念。本章中解释的它们之间的区别将清楚地帮助开发人员选择适合其系统的容器化方法。我们对 Docker 技术、其优势以及 Docker 容器的生命周期进行了一些介绍。本章中解释的八种 Docker 设计模式清楚地展示了在生产环境中实现 Docker 容器的方法。在本章结束时，介绍了 Unikernels 的概念，这是容器化领域未来发展的方向。在下一章中，我们将开始讨论 Docker 安装故障排除问题及其深入解决方案。


# 第二章：Docker 安装

大多数操作系统中 Docker 安装非常顺利，很少出错的机会。Docker 引擎安装在大多数 Linux、云、Windows 和 Mac OS X 环境中都得到支持。如果 Linux 版本不受支持，那么可以使用二进制文件安装 Docker 引擎。Docker 二进制安装主要面向那些想在各种操作系统上尝试 Docker 的黑客。通常涉及检查运行时依赖关系、内核依赖关系，并使用 Docker 特定于平台的二进制文件以便继续安装。

Docker Toolbox 是一个安装程序，可以快速在 Windows 或 Mac 机器上安装和设置 Docker 环境。Docker 工具箱还安装了：

+   **Docker 客户端**：它通过与 Docker 守护程序通信执行命令，如构建和运行，并发送容器

+   **Docker Machine**：它是一个用于在虚拟主机上安装 Docker 引擎并使用 Docker Machine 命令管理它们的工具

+   **Docker Compose**：它是一个用于定义和运行多容器 Docker 应用程序的工具

+   **Kitematic**：在 Mac OS X 和 Windows 操作系统上运行的 Docker GUI

使用工具箱安装 Docker 以及在各种支持的操作系统上的安装都非常简单，但我们列出了可能的陷阱和涉及的故障排除步骤。

在本章中，我们将探讨如何在各种 Linux 发行版上安装 Docker，例如以下内容：

+   Ubuntu

+   红帽 Linux

+   CentOS

+   CoreOS

+   Fedora

+   SUSE Linux

上述所有操作系统都可以部署在裸机上，但在某些情况下我们使用了 AWS 进行部署，因为这是一个理想的生产环境。此外，在 AWS 上快速启动环境也更快。我们在本章的各个部分中解释了相同的步骤，这将帮助您解决问题并加快在 AWS 上的部署速度。

# 在 Ubuntu 上安装 Docker

让我们开始在 Ubuntu 14.04 LTS 64 位上安装 Docker。我们可以使用 AWS AMI 来创建我们的设置。可以通过以下链接直接在 AMI 上启动镜像：

[`thecloudmarket.com/image/ami-a21529cc--ubuntu-images-hvm-ssd-ubuntu-trusty-14-04-amd64-server-20160114-5`](http://thecloudmarket.com/image/ami-a21529cc--ubuntu-images-hvm-ssd-ubuntu-trusty-14-04-amd64-server-20160114-5)

以下图表说明了在 Ubuntu 14.04 LTS 上安装 Docker 所需的安装步骤：

在 Ubuntu 上安装 Docker

## 先决条件

Docker 需要 64 位安装，无论 Ubuntu 版本如何。内核必须至少为 3.10。

让我们使用以下命令检查我们的内核版本：

```
$ uname -r

```

输出是 3.13.x 的内核版本，这很好：

```
3.13.0-74-generic

```

## 更新软件包信息

执行以下步骤来更新 APT 存储库并安装必要的证书：

1.  Docker 的 APT 存储库包含 Docker 1.7.x 或更高版本。要设置 APT 以使用新存储库中的软件包：

```
$ sudo apt-get update

```

1.  运行以下命令以确保 APT 使用 HTTPS 方法并安装 CA 证书：

```
$ sudo apt-get install apt-transport-https ca-certificates

```

`apt-transport-https`软件包使我们能够在`/etc/apt/sources.list`中使用`deb https://foo distro main`行，以便使用`libapt-pkg`库的软件包管理器可以访问通过 HTTPS 可访问的源中的元数据和软件包。

`ca-certificates`是容器的 CA 证书的 PEM 文件，允许基于 SSL 的应用程序检查 SSL 连接的真实性。

## 添加新的 GPG 密钥

**GNU 隐私保护**（称为**GPG**或**GnuPG)**是一款符合 OpenPGP（RFC4880）标准的免费加密软件：

```
$ sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

```

输出将类似于以下清单：

```
Executing: gpg --ignore-time-conflict --no-options --no-default-keyring --homedir /tmp/tmp.SaGDv5OvNN --no-auto-check-trustdb --trust-model always --keyring /etc/apt/trusted.gpg --primary-keyring /etc/apt/trusted.gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D 
gpg: requesting key 2C52609D from hkp server p80.pool.sks-keyservers.net 
gpg: key 2C52609D: public key "Docker Release Tool (releasedocker) <docker@docker.com>" imported 
gpg: Total number processed: 1 
gpg:               imported: 1  (RSA: 1)

```

## 故障排除

如果您发现`sks-keyservers`不可用，可以尝试以下命令：

```
$ sudo apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

```

## 为 Docker 添加新的软件包源

可以通过以下方式将 Docker 存储库添加到 APT 存储库中：

1.  使用新的源更新`/etc/apt/sources.list.d`作为 Docker 存储库。

1.  打开`/etc/apt/sources.list.d/docker.list`文件，并使用以下条目进行更新：

```
deb https://apt.dockerproject.org/repo ubuntu-trusty main

```

## 更新 Ubuntu 软件包

在添加 Docker 存储库后，可以更新 Ubuntu 软件包，如下所示：

```
$ sudo apt-get update

```

## 安装 linux-image-extra

对于 Ubuntu Trusty，建议安装`linux-image-extra`内核包；`linux-image-extra`包允许使用 AUFS 存储驱动程序：

```
$ sudo apt-get install linux-image-extra-$(uname -r)

```

输出将类似于以下清单：

```
Reading package lists... Done 
Building dependency tree        
Reading state information... Done 
The following extra packages will be installed: 
  crda iw libnl-3-200 libnl-genl-3-200 wireless-regdb 
The following NEW packages will be installed: 
  crda iw libnl-3-200 libnl-genl-3-200 linux-image-extra-3.13.0-74-generic 
  wireless-regdb 
0 upgraded, 6 newly installed, 0 to remove and 70 not upgraded. 
Need to get 36.9 MB of archives. 
After this operation, 152 MB of additional disk space will be used. 
Do you want to continue? [Y/n] Y 
Get:1 http://ap-northeast-1.ec2.archive.ubuntu.com/ubuntu/ trusty/main libnl-3-200 amd64 3.2.21-1 44 ..
Updating /boot/grub/menu.lst ... done 
run-parts: executing /etc/kernel/postinst.d/zz-update-grub 3.13.0-74-generic /boot/vmlinuz-3.13.0-74-generic 
Generating grub configuration file ... 
Found linux image: /boot/vmlinuz-3.13.0-74-generic 
Found initrd image: /boot/initrd.img-3.13.0-74-generic 
done 
Processing triggers for libc-bin (2.19-0ubuntu6.6) ...

```

## 可选 - 安装 AppArmor

如果尚未安装，使用以下命令安装 AppArmor：

```
$ apt-get install apparmor

```

输出将类似于以下清单：

```
sudo: unable to resolve host ip-172-30-0-227 
Reading package lists... Done 
Building dependency tree        
Reading state information... Done 
apparmor is already the newest version. 
0 upgraded, 0 newly installed, 0 to remove and 70 not upgraded.

```

## Docker 安装

让我们开始使用官方 APT 软件包在 Ubuntu 上安装 Docker Engine：

1.  更新 APT 软件包索引：

```
$ sudo apt-get update

```

1.  安装 Docker Engine：

```
$ sudo apt-get install docker-engine

```

1.  启动 Docker 守护程序：

```
$ sudo service docker start

```

1.  验证 Docker 是否正确安装：

```
$ sudo docker run hello-world

```

1.  输出将如下所示：

```
Latest: Pulling from library/hello-world 
        03f4658f8b78: Pull complete  
        a3ed95caeb02: Pull complete  
        Digest: sha256:8be990ef2aeb16dbcb9271ddfe2610fa6658d13f6dfb8b
        c72074cc1ca36966a7 
        Status: Downloaded newer image for hello-world:latest 
        Hello from Docker. 
        This message shows that your installation appears to be working 
        correctly.

```

# 在 Red Hat Linux 上安装 Docker

Docker 在 Red Hat Enterprise Linux 7.x 上受支持。本节概述了使用 Docker 管理的发行包和安装机制安装 Docker。使用这些软件包可以确保您能够获得最新版本的 Docker。

![在 Red Hat Linux 上安装 Docker

## 检查内核版本

可以使用以下命令检查 Linux 内核版本：

```
$ uname -r

```

在我们的情况下，输出是内核版本 3.10.x，这将很好地工作：

```
3.10.0-327.el7.x86 _64

```

## 更新 YUM 软件包

可以使用以下命令更新 YUM 存储库：

```
$ sudo yum update

```

给出输出列表；确保最后显示`Complete!`，如下所示：

```
Loaded plugins: amazon-id, rhui-lb, search-disabled-repos 
rhui-REGION-client-config-server-7       | 2.9 kB   
.... 
Running transaction check 
Running transaction test 
Transaction test succeeded 
Running transaction 
  Installing : linux-firmware-20150904-43.git6ebf5d5.el7.noarch      1/138  
  Updating   : tzdata-2016c-1.el7.noarch                             2/138  
  ....                              
Complete!

```

## 添加 YUM 存储库

让我们将 Docker 存储库添加到 YUM 存储库列表中：

```
$ sudo tee /etc/yum.repos.d/docker.repo <<-EOF 
[dockerrepo] 
name=Docker Repository 
baseurl=https://yum.dockerproject.org/repo/main/centos/7 
enabled=1 
gpgcheck=1 
gpgkey=https://yum.dockerproject.org/gpg 
EOF

```

## 安装 Docker 软件包

Docker 引擎可以使用 YUM 存储库进行安装，如下所示：

```
$ sudo yum install docker-engine

```

## 启动 Docker 服务

可以使用以下命令启动 Docker 服务：

```
$ sudo service docker start
Redirecting to /bin/systemctl start docker.service

```

## 测试 Docker 安装

使用以下命令列出 Docker 引擎中的所有进程可以验证 Docker 服务的安装是否成功：

```
$ sudo docker ps -a

```

以下是前述命令的输出：

```
CONTAINER   ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES

```

检查 Docker 版本以确保它是最新的：

```
$ docker --version
Docker version 1.11.0, build 4dc5990

```

## 检查安装参数

让我们运行 Docker 信息以查看默认安装参数：

```
$ sudo docker info

```

输出列表如下；请注意`存储驱动程序`为`devicemapper`：

```
Containers: 0 
 Running: 0 
 Paused: 0 
 Stopped: 0 
Images: 0 
Server Version: 1.11.0 
Storage Driver: devicemapper 
 Pool Name: docker-202:2-33659684-pool 
 Pool Blocksize: 65.54 kB 
 Base Device Size: 10.74 GB 
 Backing Filesystem: xfs 
 Data file: /dev/loop0 
 Metadata file: /dev/loop1 
... 
Cgroup Driver: cgroupfs 
Plugins:  
 Volume: local 
 Network: null host bridge 
Kernel Version: 3.10.0-327.el7.x86_64 
Operating System: Red Hat Enterprise Linux Server 7.2 (Maipo) 
OSType: linux 
Architecture: x86_64 
CPUs: 1 
Total Memory: 991.7 MiB 
Name: ip-172-30-0-16.ap-northeast-1.compute.internal 
ID: VW2U:FFSB:A2VP:DL5I:QEUF:JY6D:4SSC:LG75:IPKU:HTOK:63HD:7X5H 
Docker Root Dir: /var/lib/docker 
Debug mode (client): false 
Debug mode (server): false 
Registry: https://index.docker.io/v1/

```

## 故障排除提示

确保您使用最新版本的 Red Hat Linux 以便部署 Docker 1.11。另一个重要的事情要记住是内核版本必须是 3.10 或更高。其余的安装过程都很顺利。

# 部署 CentOS VM 在 AWS 上运行 Docker 容器

我们正在使用 AWS 作为环境来展示 Docker 安装的便利性。如果需要测试操作系统是否支持其 Docker 版本，AWS 是部署和测试的最简单和最快速的方式。

如果您不是在 AWS 环境中使用，请随意跳过涉及在 AWS 上启动 VM 的步骤。

在本节中，我们将看看在 AWS 上部署 CentOS VM 以快速启动环境并部署 Docker 容器。CentOS 类似于 Red Hat 的发行版，并使用与 YUM 相同的打包工具。我们将使用官方支持 Docker 的 CentOS 7.x：

首先，让我们在 AWS 上启动基于 CentOS 的 VM：

![在 AWS 上部署 CentOS VM 来运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_003.jpg)

我们使用**一键启动**和预先存在的密钥对进行启动。SSH 默认启用：

![在 AWS 上部署 CentOS VM 来运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_004.jpg)

一旦实例启动，从 AWS EC2 控制台获取公共 IP 地址。

SSH 进入实例并按照以下步骤进行安装：

```
$ ssh -i "ubuntu-1404-1.pem" centos@54.238.154.134

```

![在 AWS 上部署 CentOS VM 来运行 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_005.jpg)

## 检查内核版本

可以使用以下命令检查 Linux 操作系统的内核版本：

```
$ uname -r

```

在我们的情况下，输出是内核版本 3.10.x，这将很好地工作：

```
3.10.0-327.10.1.el7.x86_64

```

注意它与 Red Hat 内核版本 3.10.0-327.el7.x86_64 有多相似。

## 更新 YUM 包

YUM 包和存储库可以更新，如下所示：

```
$ sudo yum update 
Output listing is given, make sure it shows complete at the end 

Loaded plugins: fastestmirror 
base                                                     | 3.6 kB     00:00      
extras                                                   | 3.4 kB     00:00      
updates                                                  | 3.4 kB     00:00      
(1/4): base/7/x86_64/group_gz                            | 155 kB   00:00      
(2/4): extras/7/x86_64/primary_db                        | 117 kB   00:00      
(3/4): updates/7/x86_64/primary_db                       | 4.1 MB   00:00      
(4/4): base/7/x86_64/primary_db                          | 5.3 MB   00:00      
Determining fastest mirrors 
 * base: ftp.riken.jp 
 * extras: ftp.riken.jp 
 * updates: ftp.riken.jp 
Resolving Dependencies 
--> Running transaction check 
---> Package bind-libs-lite.x86_64 32:9.9.4-29.el7_2.2 will be updated 
---> Package bind-libs-lite.x86_64 32:9.9.4-29.el7_2.3 will be an update 
---> Package bind-license.noarch 32:9.9.4-29.el7_2.2 will be updated 
---> Package bind-license.noarch 32:9.9.4-29.el7_2.3 will be an update 
.... 
  teamd.x86_64 0:1.17-6.el7_2                                                    
  tuned.noarch 0:2.5.1-4.el7_2.3                                                 
  tzdata.noarch 0:2016c-1.el7                                                    
  util-linux.x86_64 0:2.23.2-26.el7_2.2                                          
Complete!

```

## 添加 YUM 存储库

让我们将 Docker 存储库添加到 YUM 存储库中：

```
$ sudo tee /etc/yum.repos.d/docker.repo <<-EOF 
[dockerrepo] 
name=Docker Repository 
baseurl=https://yum.dockerproject.org/repo/main/centos/7 
enabled=1 
gpgcheck=1 
gpgkey=https://yum.dockerproject.org/gpg 
EOF

```

## 安装 Docker 包

以下命令可用于使用 YUM 存储库安装 Docker Engine：

```
$ sudo yum install docker-engine

```

## 启动 Docker 服务

Docker 服务可以通过以下方式启动：

```
$ sudo service docker start
Redirecting to /bin/systemctl start docker.service

```

## 测试 Docker 安装

```
$ sudo docker ps -a

```

输出：

```
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES

```

检查 Docker 版本以确保它是最新的：

```
$ docker --version
Docker version 1.11.0, build 4dc5990

```

## 检查安装参数

让我们运行 Docker 信息来查看默认安装参数：

```
$ sudo docker info

```

输出如下；请注意`Storage Driver`是`devicemapper`：

```
Server Version: 1.11.0 
Storage Driver: devicemapper 
 ... 
Kernel Version: 3.10.0-327.10.1.el7.x86_64 
Operating System: CentOS Linux 7 (Core) 
OSType: linux 
Architecture: x86_64 
CPUs: 1 
Total Memory: 991.7 MiB 
Name: ip-172-30-0-236 
ID: EG2K:G4ZR:YHJ4:APYL:WV3S:EODM:MHKT:UVPE:A2BE:NONM:A7E2:LNED 
Docker Root Dir: /var/lib/docker 
Registry: https://index.docker.io/v1/

```

# 在 CoreOS 上安装 Docker

CoreOS 是为云构建的轻量级操作系统。它预先打包了 Docker，但版本比最新版本落后一些。由于它预先构建了 Docker，因此几乎不需要故障排除。我们只需要确保选择了正确的 CoreOS 版本。

CoreOS 可以在各种平台上运行，包括 Vagrant、Amazon EC2、QEMU/KVM、VMware 和 OpenStack，以及自定义硬件。CoreOS 使用 fleet 来管理容器集群以及 etcd（键值数据存储）。

## CoreOS 的安装通道

在我们的情况下，我们将使用稳定的**发布通道**：

![CoreOS 的安装通道](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_006.jpg)

首先，我们将使用 CloudFormation 模板在 AWS 上安装 CoreOS。您可以在以下链接找到此模板：

[`s3.amazonaws.com/coreos.com/dist/aws/coreos-stable-pv.template`](https://s3.amazonaws.com/coreos.com/dist/aws/coreos-stable-pv.template)

此模板提供以下参数：

+   实例类型

+   集群大小

+   发现 URL

+   广告 IP 地址

+   允许 SSH 来自

+   密钥对

这些参数可以在默认模板中设置如下：

```
{ 
  "Parameters": { 
    "InstanceType": { 
      "Description": "EC2 PV instance type (m3.medium, etc).", 
      "Type": "String", 
      "Default": "m3.medium", 
      "ConstraintDescription": "Must be a valid EC2 PV instance type." 
    }, 
    "ClusterSize": { 
      "Default": "3", 
      "MinValue": "3", 
      "MaxValue": "12", 
      "Description": "Number of nodes in cluster (3-12).", 
      "Type": "Number" 
    }, 
    "DiscoveryURL": { 
      "Description": "An unique etcd cluster discovery URL. Grab a new token from https://discovery.etcd.io/new?size=<your cluster size>", 
      "Type": "String" 
    }, 
    "AdvertisedIPAddress": { 
      "Description": "Use 'private' if your etcd cluster is within one region or 'public' if it spans regions or cloud providers.", 
      "Default": "private", 
      "AllowedValues": [ 
        "private", 
        "public" 
      ], 
      "Type": "String" 
    }, 
    "AllowSSHFrom": { 
      "Description": "The net block (CIDR) that SSH is available to.", 
      "Default": "0.0.0.0/0", 
      "Type": "String" 
    }, 
    "KeyPair": { 
      "Description": "The name of an EC2 Key Pair to allow SSH access to the instance.", 
      "Type": "String" 
    } 
  } 
} 

```

以下步骤将提供在 AWS 上使用截图进行 CoreOS 安装的完整步骤：

1.  选择 S3 模板进行启动：![CoreOS 的安装通道](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_007.jpg)

1.  指定**堆栈名称**，**密钥对**和集群 3：![CoreOS 的安装通道](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_008.jpg)

## 故障排除

以下是在之前安装过程中应遵循的一些故障排除提示和指南：

+   **堆栈名称**不应重复

+   **ClusterSize**不能低于 3，最大为 12

+   建议的**InstanceType**是`m3.medium`

+   **密钥对**应存在；如果不存在，集群将无法启动

SSH 进入实例并检查 Docker 版本：

```
core@ip-10-184-155-153 ~ $ docker --version
Docker version 1.9.1, build 9894698

```

# 在 Fedora 上安装 Docker

Docker 支持 Fedora 22 和 23 版本。以下是在 Fedora 23 上安装 Docker 的步骤。它可以部署在裸机上或作为虚拟机。

## 检查 Linux 内核版本

Docker 需要 64 位安装，无论 Fedora 版本如何。此外，内核版本应至少为 3.10。使用以下命令在安装之前检查内核版本：

```
$ uname -r
4.4.7-300.fc23.x86_64
Switch to root user
[os@osboxes ~]# su -
Password:
[root@vkohli ~]#

```

## 使用 DNF 安装

使用以下命令更新现有的 DNF 软件包：

```
$ sudo dnf update

```

## 添加到 YUM 存储库

让我们将 Docker 存储库添加到 YUM 存储库中：

```
$ sudo tee /etc/yum.repos.d/docker.repo <<-'EOF' 
> [dockerrepo] 
> name=Docker Repository 
> baseurl=https://yum.dockerproject.org/repo/main/fedora/$releasever/ 
> enabled=1 
> gpgcheck=1 
> gpgkey=https://yum.dockerproject.org/gpg 
> EOF 
[dockerrepo] 
name=Docker Repository 
baseurl=https://yum.dockerproject.org/repo/main/fedora/$releasever/ 
enabled=1 
gpgcheck=1 
gpgkey=https://yum.dockerproject.org/gpg

```

## 安装 Docker 软件包

可以使用 DNF 软件包安装 Docker 引擎：

```
$ sudo dnf install docker-engine

```

输出将类似于以下列表（此列表已被截断）：

```
Docker Repository                                32 kB/s | 7.8 kB     00:00 
Last metadata expiration check: 0:00:01 ago on Thu Apr 21 15:45:25 2016\. 
Dependencies resolved. 
Install  7 Packages 
... 
Running transaction test 
Transaction test succeeded. 
Running transaction 
  Installing: python-IPy-0.81-13.fc23.noarch                                                                     .... 
Installed: 
... 
Complete!

```

使用`systemctl`启动 Docker 服务：

```
$ sudo systemctl start docker

```

使用 Docker 的 hello-world 示例来验证 Docker 是否成功安装：

```
[root@osboxes ~]# docker run hello-world

```

输出将类似于以下列表：

```
Unable to find image 'hello-world:last' locally 
latest: Pulling from library/hello-world 
03f4658f8b78: Pull complete 
a3ed95caeb02: Pull complete 
Digest: sha256:8be990ef2aeb16dbcb9271ddfe2610fa6658d13f6dfb8bc72074cc1ca36966a7 
Status: Downloaded newer image for hello-world:latest 

Hello from Docker. 
This message shows that your installation appears to be working correctly.

```

为了生成这条消息，Docker 采取了以下步骤：

1.  Docker 客户端联系了 Docker 守护程序。

1.  Docker 守护程序从 Docker Hub 拉取了`hello-world`镜像。

1.  Docker 守护程序从该镜像创建了一个新的容器，该容器运行生成您当前正在阅读的输出的可执行文件。

1.  Docker 守护程序将输出流式传输到 Docker 客户端，然后发送到您的终端。

要尝试更雄心勃勃的事情，您可以使用以下命令运行 Ubuntu 容器：

```
$ docker run -it ubuntu bash

```

通过免费的 Docker Hub 帐户[`hub.docker.com`](https://hub.docker.com)共享图像，自动化工作流程等。

有关更多示例和想法，请访问[`docs.docker.com/userguide/md64-server-20160114.5 (ami-a21529cc)`](https://docs.docker.com/engine/userguide/)。

# 使用脚本安装 Docker

更新您的 DNF 包，如下所示：

```
$ sudo dnf update

```

## 运行 Docker 安装脚本

Docker 安装也可以通过执行 shell 脚本并从官方 Docker 网站获取来快速简便地完成：

```
$ curl -fsSL https://get.docker.com/ | sh
+ sh -c 'sleep 3; dnf -y -q install docker-engine'

```

启动 Docker 守护程序：

```
$ sudo systemctl start docker

```

Docker 运行`hello-world`：

```
$ sudo docker run hello-world

```

要创建 Docker 组并添加用户，请按照以下步骤进行操作：

```
$ sudo groupadd docker
$ sudo usermod -aG docker your_username

```

注销并使用用户登录以确保您的用户已成功创建：

```
$ docker run hello-world

```

要卸载 Docker，请按照以下步骤进行操作：

```
# sudo dnf -y remove docker-engine.x86_64

```

上述命令的截断输出如下所示：

```
Dependencies resolved. 
Transaction Summary 
================================================================ 
Remove  7 Packages 
Installed size: 57 M 
Running transaction check 
Transaction check succeeded. 
Running transaction test 
Transaction test succeeded. 
Running transaction 
... 
Complete! 
[root@osboxes ~]# rm -rf /var/lib/docker

```

# 在 SUSE Linux 上安装 Docker

在本节中，我们将在 SUSE Linux Enterprise Server 12 SP1 x86_64（64 位）上安装 Docker。我们还将看一下在安装过程中遇到的一些问题。

## 在 AWS 上启动 SUSE Linux VM

选择适当的 AMI 并从 EC2 控制台启动实例：

![在 AWS 上启动 SUSE Linux VM](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_009.jpg)

下一步显示了以下参数；请查看然后启动它们：

![在 AWS 上启动 SUSE Linux VM](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_010.jpg)

我们选择了一个现有的密钥对以 SSH 进入实例：

![在 AWS 上启动 SUSE Linux VM](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_011.jpg)

VM 启动后，请从终端登录到 VM：

```
$ ssh -i "ubuntu-1404-1.pem" ec2-user@54.199.222.91

```

截断的输出如下所示：

```
The authenticity of host '54.199.222.91 (54.199.222.91)' can't be established. 
... 
Management and Config: https://www.suse.com/suse-in-the-cloud-basics 
Documentation: http://www.suse.com/documentation/sles12/ 
Forum: https://forums.suse.com/forumdisplay.php?93-SUSE-Public-Cloud 
Have a lot of fun...  
ec2-user@ip-172-30-0-104:~>

```

由于我们已经启动了 VM，让我们专注于安装 docker。以下图表概述了在 SUSE Linux 上安装 docker 的步骤：

![在 AWS 上启动 SUSE Linux VM](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_02_012.jpg)

## 检查 Linux 内核版本

内核版本应至少为 3.10。在继续安装之前，请使用以下命令检查内核版本：

```
$ uname -r

```

## 添加 Containers-Module

在安装 docker 之前，需要更新本地软件包中的以下 Containers-Module。您可以在以下链接找到有关 Containers-Module 的更多详细信息：

[`www.suse.com/support/update/announcement/2015/suse-ru-20151158-1.html`](https://www.suse.com/support/update/announcement/2015/suse-ru-20151158-1.html)

执行以下命令：

```
ec2-user@ip-172-30-0-104:~> sudo SUSEConnect -p sle-module-containers/12/x86_64 -r ''

```

输出将类似于此：

```
Registered sle-module-containers 12 x86_64
To server: https://smt-ec2.susecloud.net
ec2-user@ip-172-30-0-104:~>

```

## 安装 Docker

执行以下命令：

```
ec2-user@ip-172-30-0-104:~> sudo zypper in Docker

```

截断的输出如下所示：

```
... 
 (2/2) Installing: docker-1.10.3-66.1 ...........................................................[done] 
Additional rpm output: 
creating group docker... 
Updating /etc/sysconfig/docker...

```

## 启动 Docker 服务

Docker 服务可以启动，如下所示：

```
ec2-user@ip-172-30-0-104:~> sudo systemctl start docker

```

## 检查 Docker 安装

执行 Docker 运行，如下所示，以测试安装：

```
ec2-user@ip-172-30-0-104:~> sudo docker run hello-world

```

输出将类似于这样：

```
Unable to find image 'hello-world:latest' locally 
latest: Pulling from library/hello-world 
4276590986f6: Pull complete  
a3ed95caeb02: Pull complete  
Digest: sha256:4f32210e234b4ad5cac92efacc0a3d602b02476c754f13d517e1ada048e5a8ba 
Status: Downloaded newer image for hello-world:latest 
Hello from Docker. 
This message shows that your installation appears to be working correctly. 
.... 
For more examples and ideas, visit: 
 https://docs.docker.com/engine/userguide/ 
ec2-user@ip-172-30-0-104:~>

```

## 故障排除

请注意，SUSE Linux 11 上的 Docker 安装并不是一次顺利的体验，因为 SUSE Connect 不可用。

# 总结

在本章中，我们介绍了如何在各种 Linux 发行版（Ubuntu，CoreOS，CentOS，Red Hat Linux，Fedora 和 SUSE Linux）上安装 Docker 的步骤。我们注意到在 Linux 上的步骤和常见先决条件的相似之处，而 Docker 模块需要从远程存储库下载和 Docker 模块的软件包管理在每个 Linux 操作系统上都有所不同。在下一章中，我们将探讨构建镜像的使命关键任务，了解基本和分层镜像，并探索故障排除方面。


# 第三章：构建基础和分层图像

在本章中，我们将学习如何为生产就绪的容器构建基础和分层图像。正如我们所见，Docker 容器为我们提供了理想的环境，我们可以在其中构建、测试、自动化和部署。这些确切环境的再现性为我们提供了更高效和更有信心的效果，目前可用的基于脚本的部署系统无法轻易复制。开发人员在本地构建、测试和调试的图像可以直接推送到分段和生产环境中，因为测试环境几乎是应用程序代码运行的镜像。

图像是容器的字面基础组件，定义了部署的 Linux 版本和要包含和提供给容器内部运行的代码的默认工具。因此，图像构建是应用程序容器化生命周期中最关键的任务之一；正确构建图像对于容器化应用程序的有效、可重复和安全功能至关重要。

容器镜像由一组应用程序容器的运行时变量组成。理想情况下，容器镜像应尽可能精简，仅提供所需的功能，这有助于高效处理容器镜像，显著减少了从注册表上传和下载镜像的时间，并在主机上占用空间最小。

我们的重点、意图和方向是为您的 Docker 容器构建、调试和自动化图像。

本章我们将涵盖以下主题：

+   构建容器镜像

+   从头开始构建基础镜像

+   来自 Docker 注册表的官方基础镜像

+   从 Dockerfile 构建分层图像

+   通过测试调试图像

+   带有测试的自动化图像构建

# 构建容器镜像

由于本书试图*解决 Docker*的问题，减少我们需要解决的错误的机会不是很有益吗？幸运的是，Docker 社区（以及开源社区）提供了一个健康的基础（或*根*）镜像注册表，大大减少了错误并提供了更可重复的过程。在**Docker Registry**中搜索，我们可以找到广泛且不断增长的容器镜像的官方和自动化构建状态。 Docker 官方仓库（[`docs.docker.com/docker-hub/official_repos/)`](https://docs.docker.com/docker-hub/official_repos/)）是由 Docker Inc.支持的仔细组织的镜像集合-自动化仓库，允许您验证特定镜像的源和内容也存在。

本章的一个主要重点和主题将是基本的 Docker 基础知识；虽然对于经验丰富的容器用户来说可能看起来微不足道，但遵循一些最佳实践和标准化水平将有助于我们避免麻烦，并增强我们解决问题的能力。

## Docker Registry 的官方图像

标准化是可重复过程的重要组成部分。因此，无论何时何地，都应选择**Docker Hub**中提供的标准基础镜像，用于不同的 Linux 发行版（例如 CentOS、Debian、Fedora、RHEL、Ubuntu 等）或特定用例（例如 WordPress 应用程序）。这些基础镜像源自各自的 Linux 平台镜像，并专门用于容器中使用。此外，标准化的基础镜像经过良好维护，并经常更新以解决安全公告和关键错误修复。

这些基础镜像由 Docker Inc.构建、验证和支持，并通过它们的单词名称（例如`centos`）轻松识别。此外，Docker 社区的用户成员还提供和维护预构建的镜像以解决特定用例。这些用户镜像以创建它们的 Docker Hub 用户名为前缀，后缀为镜像名称（例如`tutum/centos`）。

![Docker Registry 的官方图像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_001.jpg)

对我们来说，这些标准基础镜像仍然是准备就绪的，并且可以在 Docker Registry 上公开获取；可以使用`docker search`和`docker pull`终端命令简单地搜索和检索镜像。这将下载任何尚未位于 Docker 主机上的镜像。Docker Registry 在提供官方基础镜像方面变得越来越强大，可以直接使用，或者至少作为解决容器构建需求的一个可用的起点。

### 注意

虽然本书假设您熟悉 Docker Hub/Registry 和 GitHub/Bitbucket，但我们将首先介绍这些内容，作为您构建容器的高效镜像的首要参考线。您可以访问 Docker 镜像的官方注册表[`registry.hub.docker.com/`](https://registry.hub.docker.com/)。

![来自 Docker Registry 的官方镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_002.jpg)

Docker Registry 可以从您的 Docker Hub 帐户或直接从终端进行搜索，如下所示：

```
$ sudo docker search centos

```

可以对搜索条件应用标志来过滤星级评分、自动构建等图像。要使用来自注册表的官方`centos`镜像，请从终端执行：

+   `$ sudo docker pull centos`：这将把`centos`镜像下载到您的主机上。

+   `$ sudo docker run centos`：这将首先在主机上查找此镜像，如果找不到，将会将镜像下载到主机上。镜像的运行参数将在其 Dockerfile 中定义。

### 用户存储库

此外，正如我们所见，我们不仅仅局限于官方 Docker 镜像的存储库。事实上，社区用户（无论是个人还是来自公司企业）已经准备好了满足某些需求的镜像。例如，创建了一个`ubuntu`镜像，用于在运行在 Apache、MySql 和 PHP 上的容器中运行`joomla`内容管理系统。

在这里，我们有一个用户存储库，其中有这样的镜像（`命名空间/存储库名称`）：

![用户存储库](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_004.jpg)

### 注意

**试一下：** 从终端练习从 Docker Registry 拉取和运行图像。

`$ sudo docker pull cloudconsulted/joomla`

从容器中拉取我们的基础镜像，并且`$ sudo docker run -d -p 80:80 cloudconsulted/joomla` 运行我们的容器镜像，并将主机的端口`80`映射到容器的端口`80`。

将你的浏览器指向`http://localhost`，你将会看到一个新的 Joomla 网站的构建页面！

## 构建我们自己的基础镜像

然而，可能会有情况需要创建定制的镜像以适应我们自己的开发和部署环境。如果你的使用情况要求使用非标准化的基础镜像，你将需要自己创建镜像。与任何方法一样，事先适当的规划是必要的。在构建镜像之前，你应该花足够的时间充分了解你的容器所要解决的使用情况。没有必要运行不符合预期应用程序的容器。其他考虑因素可能包括你在镜像中包含的库或二进制文件是否可重用，等等。一旦你觉得完成了，再次审查你的需求和要求，并过滤掉不必要的部分；我们不希望毫无理由地膨胀我们的容器。

使用 Docker Registry，你可以找到自动构建。这些构建是从 GitHub/Bitbucket 的仓库中拉取的，因此可以被 fork 并根据你自己的规格进行修改。然后，你新 fork 的仓库可以同步到 Docker Registry，生成你的新镜像，然后可以根据需要被拉取和运行到你的容器中。

### 注意

**试一下**：从以下仓库中拉取 ubuntu minimal 镜像，并将其放入你的 Dockerfile 目录中，以创建你自己的镜像：

`$ sudo docker pull cloudconsulted/ubuntu-dockerbase` `$ mkdir dockerbuilder` `$ cd dockerbuilder`

打开一个编辑器（vi/vim 或 nano）并创建一个新的 Dockerfile：

`$ sudo nano Dockerfile`

稍后我们将深入讨论如何创建良好的 Dockerfile，以及分层和自动化的镜像构建。现在，我们只想创建我们自己的新基础镜像，只是象征性地通过创建 Dockerfile 的过程和位置。为了简单起见，我们只是从我们想要构建新镜像的基础镜像中调用：

```
FROM cloudconsulted/ubuntu-dockerbase:latest 

```

保存并关闭这个 Dockerfile。现在我们在本地构建我们的新镜像：

```
$ sudo docker build -t mynew-ubuntu

```

让我们检查一下确保我们的新镜像已列出：

```
$ sudo docker images

```

注意我们的**IMAGE ID**为**mynew-ubuntu**，因为我们很快会需要它：

在 Docker Hub 用户名下创建一个新的公共/私有仓库。我在这里添加了新的仓库，命名为`<namespace><reponame>`，如`cloudconsulted/mynew-ubuntu`：

![构建我们自己的基础镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_006.jpg)

接下来，返回到终端，这样我们就可以标记我们的新镜像以推送到我们的`<namespace>`下的新 Docker Hub 仓库：

```
$ sudo docker tag 1d4bf9f2c9c0 cloudconsulted/mynew-ubuntu:latest

```

确保我们的新镜像在我们的镜像列表中正确标记为`<namespace><repository>`：

```
$ sudo docker images

```

此外，我们将找到我们新创建的标记为推送到我们的 Docker Hub 仓库的镜像。

现在，让我们将镜像推送到我们的 Docker Hub 仓库：

```
$ sudo docker push cloudconsulted/mynew-ubuntu

```

然后，检查我们的新镜像是否在 Hub 上：

![构建我们自己的基础镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_008.jpg)

构建自己的 Docker 镜像基本上有两种方法：

+   通过 bash shell 手动交互式构建层来安装必要的应用程序

+   通过 Dockerfile 自动化构建带有所有必要应用程序的镜像

### 使用 scratch 仓库构建镜像

构建自己的 Docker 容器镜像高度依赖于您打算打包的 Linux 发行版。由于这种差异性，以及通过 Docker Registry 已经可用的镜像的盛行和不断增长的注册表，我们不会花太多时间在这样的手动方法上。

在这里，我们可以再次查看 Docker Registry，以提供我们使用的最小镜像。一个`scratch`仓库已经从一个空的 TAR 文件中创建，可以通过`docker pull`简单地使用。与以前一样，根据您的参数制作 Dockerfile，然后您就有了新的镜像，从头开始。

通过使用可用工具（例如**supermin**（Fedora 系统）或**debootstrap**（Debian 系统）），这个过程甚至可以进一步简化。例如，使用这些工具，构建 Ubuntu 基础镜像的过程可以简单如下：

```
$ sudo debootstrap raring raring > /dev/null 
$ sudo tar -c raring -c . |  docker import - raring a29c15f1bf7a 
$ sudo docker run raring cat /etc/lsb-release 
DISTRIB_ID=Ubuntu 
DISTRIB_RELEASE=14.04 
DISTRIB_CODENAME=raring 
DISTRIB_DESCRIPTION="Ubuntu 14.04" 

```

## 构建分层镜像

Docker 的一个核心概念和特性是分层镜像。Docker 的最重要的特性之一是**镜像分层**和镜像内容的管理。容器镜像的分层方法非常高效，因为您可以引用镜像中的内容，识别分层镜像中的层。在构建多个镜像时，使用 Docker Registry 来推送和拉取镜像非常强大。

![构建分层镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_009.jpg)

[镜像版权 © Docker, Inc.]

### 使用 Dockerfile 构建分层镜像

分层图像主要是使用**Dockerfile**构建的。实质上，Dockerfile 是一个脚本，它可以按照您需要的顺序从源（*基础*或*根*）镜像自动构建我们的容器，逐步、一层叠一层地由 Docker 守护程序执行。这些是在文件中列出的连续命令（指令）和参数，它们在基础镜像上执行一组规定的操作，每个命令构成一个新层，以构建一个新的镜像。这不仅有助于组织我们的镜像构建，而且通过简化大大增强了从头到尾的部署。Dockerfile 中的脚本可以以各种方式呈现给 Docker 守护程序，以为我们的容器构建新的镜像。

#### Dockerfile 构建

Dockerfile 的第一个命令通常是`FROM`命令。`FROM`指定要拉取的基础镜像。这个基础镜像可以位于公共 Docker 注册表（[`www.docker.com/`](https://www.docker.com/)）中，在私有注册表中，甚至可以是主机上的本地化 Docker 镜像。

Docker 镜像中的附加层根据 Dockerfile 中定义的指令进行填充。Dockerfile 具有非常方便的指令。在 Dockerfile 中定义的每个新指令都构成了分层图像中的一个**层**。通过`RUN`指令，我们可以指定要运行的命令，并将命令的结果作为图像中的附加层。

### 建议

强烈建议将图像中执行的操作逻辑分组，并将层的数量保持在最低限度。例如，在尝试为应用程序安装依赖项时，可以在一个`RUN`指令中安装所有依赖项，而不是使用每个依赖项的*N*个指令。

我们将在后面的章节“自动化镜像构建”中更仔细地检查 Dockerfile 的方面。现在，我们需要确保我们理解 Dockerfile 本身的概念和构造。让我们特别看一下可以使用的一系列简单命令。正如我们之前所看到的，我们的 Dockerfile 应该在包含我们现有代码（和/或其他依赖项、脚本和其他内容）的工作目录中创建。

### 建议

**注意：**避免使用根目录 [`/`] 作为源代码库的根目录。`docker build` 命令使用包含您的 Dockerfile 的目录作为构建上下文（包括其所有子目录）。构建上下文将在构建镜像之前发送到 Docker 守护程序，这意味着如果您使用 `/` 作为源代码库，您硬盘的整个内容将被发送到守护程序（因此发送到运行守护程序的机器）。在大多数情况下，最好将每个 Dockerfile 放在一个空目录中。然后，只向目录添加构建 Dockerfile 所需的文件。为了提高构建的性能，可以向上下文目录添加一个 `.dockerignore` 文件，以正确排除文件和目录。

#### Dockerfile 命令和语法

虽然简单，但我们的 Dockerfile 命令的顺序和语法非常重要。在这里正确关注细节和最佳实践不仅有助于确保成功的自动部署，还有助于任何故障排除工作。

让我们勾画一些基本命令，并直接用一个工作的 Dockerfile 来说明它们；我们之前的`joomla`镜像是一个基本的分层镜像构建的好例子。

### 注意

我们的示例 joomla 基本镜像位于公共 Docker 索引中

`cloudconsulted/joomla`。

**来自**

一个正确的 Dockerfile 从定义一个 `FROM` 镜像开始，构建过程从这里开始。这个指令指定要使用的基本镜像。它应该是 Dockerfile 中的第一个指令，对于通过 Dockerfile 构建镜像是必须的。您可以指定本地镜像、Docker 公共注册表中的镜像，或者私有注册表中的镜像。

**常见结构**

```
FROM <image> 
FROM <image>:<tag> 
FROM <image>@<digest> 

```

`<tag>` 和 `<digest>` 是可选的；如果您不指定它们，它默认为 `latest`。

**我们的 Joomla 镜像的示例 Dockerfile**

在这里，我们定义要用于容器的基本镜像：

```
# Image for container base 
FROM ubuntu 

```

**维护者**

这一行指定了构建镜像的*作者*。这是 Dockerfile 中的一个可选指令；然而，应该指定此指令与作者的姓名和/或电子邮件地址。`维护者`的详细信息可以放在您的 Dockerfile 中任何您喜欢的地方，只要它总是在您的 `FROM` 命令之后，因为它们不构成任何执行，而是一个定义的值（也就是一些额外的信息）。

**常见结构**

```
MAINTAINER <name><email> 

```

**我们的 Joomla 镜像的示例 Dockerfile**

在这里，我们为此容器和镜像定义了作者：

```
# Add name of image author 
MAINTAINER John Wooten <jwooten@cloudconsulted.com> 

```

**ENV**

此指令在 Dockerfile 中设置环境变量。设置的环境变量可以在后续指令中使用。

**常见结构**

```
ENV <key> <value> 

```

上述代码设置了一个环境变量`<key>`为`<value>`。

```
ENV <key1>=<value1> <key2>=<value2> 

```

上述指令设置了两个环境变量。使用`=`符号在环境变量的键和值之间，并用空格分隔两个环境键值来定义多个环境变量：

```
ENV key1="env value with space" 

```

对于具有空格值的环境变量，请使用引号。

以下是关于`ENV`指令的要点：

+   使用单个指令定义多个环境变量

+   创建容器时环境变量可用

+   可以使用`docker inspect <image>`从镜像中查看环境变量

+   环境变量的值可以通过向`docker run`命令传递`--env <key>=<value>`选项在运行时进行更改

**我们的 Joomla 镜像的示例 Dockerfile**

在这里，我们为 Joomla 和 Docker 镜像设置环境变量，而不使用交互式终端：

```
# Set the environment variables 
ENV DEBIAN_FRONTEND noninteractive 
ENV JOOMLA_VERSION 3.4.1 

```

**RUN**

此指令允许您运行命令并生成一个层。`RUN`指令的输出将是在进程中为镜像构建的一个层。传递给`RUN`指令的命令在此指令之前构建的层上运行；需要注意顺序。

**常见结构**

```
RUN <command> 

```

`<command>`在 shell 中执行-`/bin/sh -c` shell 形式。

```
RUN ["executable", "parameter1", "parameter2"] 

```

在这种特殊形式中，您可以在可执行形式中指定`可执行文件`和`参数`。确保在命令中传递可执行文件的绝对路径。这对于基础镜像没有`/bin/sh`的情况很有用。您可以指定一个可执行文件，它可以是基础镜像中的唯一可执行文件，并在其上构建层。

如果您不想使用`/bin/sh` shell，这也很有用。考虑一下：

```
RUN ["/bin/bash", "-c", "echo True!"] 
RUN <command1>;<command2> 

```

实际上，这是一个特殊形式的示例，您可以在其中指定多个由`;`分隔的命令。`RUN`指令一起执行这些命令，并为所有指定的命令构建一个单独的层。

**我们的 Joomla 镜像的示例 Dockerfile**

在这里，我们更新软件包管理器并安装所需的依赖项：

```
# Update package manager and install required dependencies 
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \ 
    mysql-server \ 
    apache2 \ 
    php5 \ 
    php5-imap \ 
    php5-mcrypt \ 
    php5-gd \ 
    php5-curl \ 
    php5-apcu \ 
    php5-mysqlnd \ 
    supervisor 

```

请注意，我们特意这样写，以便将新软件包作为它们自己的 apt-get install 行添加，遵循初始安装命令。

这样做是为了，如果我们需要添加或删除一个软件包，我们可以在 Dockerfile 中不需要重新安装所有其他软件包。显然，如果有这样的需要，这将节省大量的构建时间。

### 注意

**Docker 缓存：** Docker 首先会检查主机的镜像缓存，查找以前构建的任何匹配层。如果找到，Dockerfile 中的给定构建步骤将被跳过，以利用缓存中的上一层。因此，最佳实践是将 Dockerfile 的每个`apt-get -y install`命令单独列出。

正如我们所讨论的，Dockerfile 中的`RUN`命令将在 Docker 容器的上下文和文件系统下执行任何给定的命令，并生成具有任何文件系统更改的新镜像层。我们首先运行`apt-get update`以确保软件包的存储库和 PPA 已更新。然后，在单独的调用中，我们指示软件包管理器安装 MySQL、Apache、PHP 和 Supervisor。`-y`标志跳过交互式确认。

安装了我们所有必要的依赖项来运行我们的服务后，我们应该整理一下，以获得一个更干净的 Docker 镜像：

```
# Clean up any files used by apt-get 
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* 

```

**ADD**

这些信息用于将文件和目录从本地文件系统或远程 URL 中的文件复制到镜像中。源和目标必须在`ADD`指令中指定。

**常见结构**

```
ADD  <source_file>  <destination_directory> 

```

这里的`<source_file>`的路径是相对于构建上下文的。另外，`<destination_directory>`的路径可以是绝对的，也可以是相对于`WORKDIR`的：

```
ADD  <file1> <file2> <file3> <destination_directory> 

```

多个文件，例如`<file1>`，`<file2>`和`<file3>`，被复制到`<destination_directory>`中。请注意，这些源文件的路径应该相对于构建上下文，如下所示：

```
ADD <source_directory> <destination_directory> 

```

`<source_directory>`的内容与文件系统元数据一起复制到`<destination_directory>`中；目录本身不会被复制：

```
ADD text_* /text_files
```

在构建上下文目录中以`text_`开头的所有文件都会被复制到容器镜像中的`/text_files`目录中：

```
ADD ["filename with space",...,  "<dest>"] 

```

文件名中带有空格的情况可以在引号中指定；在这种情况下，需要使用 JSON 数组来指定 ADD 指令。

以下是关于`ADD`指令的要点：

+   所有复制到容器镜像中的新文件和目录的 UID 和 GID 都为`0`

+   在源文件是远程 URL 的情况下，目标文件将具有`600`的权限

+   在`ADD`指令的源中引用的所有本地文件应位于构建上下文目录或其子目录中

+   如果本地源文件是受支持的 tar 存档，则它将被解压缩为目录

+   如果指定了多个源文件，则目标必须是一个目录，并以斜杠`/`结尾

+   如果目标不存在，它将与路径中的所有父目录一起创建，如果需要的话

我们的 Joomla 镜像的示例 Dockerfile

在这里，我们将`joomla`下载到 Apache web 根目录：

```
# Download joomla and put it default apache web root 
ADD https://github.com/joomla/joomla-cms/releases/download/$JOOMLA_VERSION/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz /tmp/joomla/ 
RUN tar -zxvf /tmp/joomla/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz -C /tmp/joomla/ 
RUN rm -rf /var/www/html/* 
RUN cp -r /tmp/joomla/* /var/www/html/ 

# Put default htaccess in place 
RUN mv /var/www/html/htaccess.txt /var/www/html/.htaccess 

RUN chown -R www-data:www-data /var/www 

# Expose HTTP and MySQL 
EXPOSE 80 3306 

```

**COPY**

`COPY`命令指定应将位于输入路径的文件从与 Dockerfile 相同的目录复制到容器内部的输出路径。

**CMD**

`CMD`指令有三种形式-作为`ENTRYPOINT`的默认参数的 shell 形式和首选可执行形式。`CMD`的主要目的是为执行容器提供默认值。这些默认值可以包括或省略可执行文件，后者必须指定`ENTRYPOINT`指令。如果用户在 Docker `run`中指定参数，则它们将覆盖`CMD`中指定的默认值。如果您希望容器每次运行相同的可执行文件，则应考虑结合使用`ENTRYPOINT`和`CMD`。

以下是要记住的要点：

+   不要将`CMD`与`RUN`混淆-`RUN`实际上会执行命令并提交结果，而`CMD`不会在构建过程中执行命令，而是指定图像的预期命令

+   Dockerfile 只能执行一个`CMD`；如果列出多个，则只会执行最后一个`CMD`

我们的 Joomla 镜像的示例 Dockerfile

在这里，我们设置 Apache 以启动：

```
# Use supervisord to start apache / mysql 
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf 
CMD ["/usr/bin/supervisord", "-n"] 

```

以下是我们完成的 Joomla Dockerfile 的内容：

```
FROM ubuntu 
MAINTAINER John Wooten <jwooten@cloudconsulted.com> 

ENV DEBIAN_FRONTEND noninteractive 
ENV JOOMLA_VERSION 3.4.1 

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \ 
    mysql-server \ 
    apache2 \ 
    php5 \ 
    php5-imap \ 
    php5-mcrypt \ 
    php5-gd \ 
    php5-curl \ 
    php5-apcu \ 
    php5-mysqlnd \ 
    supervisor 

# Clean up any files used by apt-get 
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* 

# Download joomla and put it default apache web root 
ADD https://github.com/joomla/joomla-cms/releases/download/$JOOMLA_VERSION/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz /tmp/joomla/ 
RUN tar -zxvf /tmp/joomla/Joomla_$JOOMLA_VERSION-Stable-Full_Package.tar.gz -C /tmp/joomla/ 
RUN rm -rf /var/www/html/* 
RUN cp -r /tmp/joomla/* /var/www/html/ 

# Put default htaccess in place 
RUN mv /var/www/html/htaccess.txt /var/www/html/.htaccess 

RUN chown -R www-data:www-data /var/www 

# Expose HTTP and MySQL 
EXPOSE 80 3306 

# Use supervisord to start apache / mysql 
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf 
CMD ["/usr/bin/supervisord", "-n"] 

```

其他常见的 Dockerfile 命令如下：**ENTRYPOINT**

`ENTRYPOINT`允许您配置将作为可执行文件运行的容器。根据 Docker 的文档，我们将使用提供的示例；以下将启动`nginx`，并使用其默认内容，在端口`80`上进行侦听：

```
docker run -i -t --rm -p 80:80 nginx 

```

`docker run <image>`的命令行参数将在可执行形式的`ENTRYPOINT`中的所有元素之后追加，并将覆盖使用`CMD`指定的所有元素。这允许将参数传递给入口点，即`docker run <image> -d`将向入口点传递`-d`参数。您可以使用`docker run --entrypoint`标志覆盖`ENTRYPOINT`指令。

**LABEL**

该指令指定了图像的元数据。稍后可以使用`docker inspect <image>`命令来检查这些图像元数据。这里的想法是在图像元数据中添加关于图像的信息，以便轻松检索。为了从图像中获取元数据，不需要从图像创建容器（或将图像挂载到本地文件系统），Docker 将元数据与每个 Docker 图像关联，并为其定义了预定义的结构；使用`LABEL`，可以添加描述图像的附加关联元数据。

图像的标签是键值对。以下是在 Dockerfile 中使用`LABEL`的示例：

```
LABEL <key>=<value>  <key>=<value>  <key>=<value> 

```

此指令将向图像添加三个标签。还要注意，它将创建一个新层，因为所有标签都是在单个`LABEL`指令中添加的：

```
LABEL  "key"="value with spaces" 

```

如果标签值中有空格，请在标签中使用引号：

```
LABEL LongDescription="This label value extends over new \ 
line." 

```

如果标签的值很长，请使用反斜杠将标签值扩展到新行。

```
LABEL key1=value1 
LABEL key2=value2 

```

可以通过**行尾**（**EOL**）分隔它们来定义图像的多个标签。请注意，在这种情况下，将为两个不同的`LABEL`指令创建两个图像层。

关于`LABEL`指令的注意事项：

+   标签按照 Dockerfile 中描述的方式汇总在一起，并与`FROM`指令中指定的基本图像中的标签一起使用

+   如果标签中的`key`重复，后面的值将覆盖先前定义的键的值。

+   尝试在单个`LABEL`指令中指定所有标签，以生成高效的图像，从而避免不必要的图像层计数

+   要查看构建图像的标签，请使用`docker inspect <image>`命令

**WORKDIR**

此指令用于为 Dockerfile 中的后续`RUN`、`ADD`、`COPY`、`CMD`和`ENTRYPOINT`指令设置工作目录。

在 Dockerfile 中定义工作目录，容器中引用的所有后续相对路径将相对于指定的工作目录。

以下是使用`WORKDIR`指令的示例：

```
WORKDIR /opt/myapp 

```

前面的指令将`/opt/myapp`指定为后续指令的工作目录，如下所示：

```
WORKDIR /opt/ 
WORKDIR myapp 
RUN pwd 

```

前面的指令两次定义了工作目录。请注意，第二个`WORKDIR`将相对于第一个`WORKDIR`。`pwd`命令的结果将是`/opt/myapp`：

```
ENV SOURCEDIR /opt/src 
WORKDIR $SOURCEDIR/myapp 

```

工作目录可以解析之前定义的环境变量。在这个例子中，`WORKDIR`指令可以评估`SOURCEDIR`环境变量，结果的工作目录将是`/opt/src/myapp`。

**USER**

这将为后续的`RUN`、`CMD`和`ENTRYPOINT`指令设置用户。当从镜像创建和运行容器时，也会设置用户。

以下指令为镜像和容器设置了用户`myappuser`：

```
USER myappuser 

```

关于`USER`指令的注意事项：

+   可以使用`docker run`命令中的`--user=name|uid[:<group|gid>]`来覆盖用户容器的用户

# 镜像测试和调试

虽然我们可以赞赏容器的好处，但目前对其进行故障排除和有效监控会带来一些复杂性。由于容器设计上的隔离性，它们的环境可能会变得模糊不清。有效的故障排除通常需要进入容器本身的 shell，并且需要安装额外的 Linux 工具来查看信息，这使得调查变得更加困难。

通常，对我们的容器和镜像进行有意义的故障排除所需的工具、方法和途径需要在每个容器中安装额外的软件包。这导致以下结果：

+   连接或直接附加到容器的要求并非总是微不足道的

+   一次只能检查一个容器的限制

增加这些困难的是，使用这些工具给我们的容器增加了不必要的臃肿，这是我们最初在规划中试图避免的；极简主义是我们在使用容器时寻求的优势之一。让我们看看如何可以合理地利用一些基本命令获取有用的容器镜像信息，以及调查新出现的应用程序，使我们能够从外部监视和排除容器。

## 用于故障排除的 Docker 详细信息

现在您已经有了您的镜像（无论构建方法如何）并且 Docker 正在运行，让我们进行一些测试，以确保我们的构建一切正常。虽然这些可能看起来很常规和乏味，但作为故障排除的*自上而下*方法来运行以下任何或所有内容是一个很好的做法。

这里的前两个命令非常简单，看起来似乎太通用了，但它们将提供基本级别的细节，以便开始任何下游的故障排除工作--`$ docker version`和`$ docker info`。

## Docker 版本

首先确保我们知道我们正在运行的 Docker、Go 和 Git 的版本：

```
$ sudo docker version

```

## Docker 信息

此外，我们还应该了解我们的主机操作系统和内核版本，以及存储、执行和日志记录驱动程序。了解这些东西可以帮助我们从*自上而下*的角度进行故障排除：

```
$ sudo docker info

```

## Debian / Ubuntu 的故障排除说明

通过`$ sudo docker info`命令，您可能会收到以下警告中的一个或两个：

```
WARNING: No memory limit support 
WARNING: No swap limit support

```

您需要添加以下命令行参数到内核中，以启用内存和交换空间记账：

```
cgroup_enable=memory swapaccount=1

```

对于这些 Debian 或 Ubuntu 系统，如果使用默认的 GRUB 引导加载程序，则可以通过编辑`/etc/default/grub`并扩展`GRUB_CMDLINE_LINUX`来添加这些参数。找到以下行：

```
GRUB_CMDLINE_LINUX="" 

```

然后，用以下内容替换它：

```
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1" 

```

然后，运行`update-grub`并重新启动主机。

## 列出已安装的 Docker 镜像

我们还需要确保容器实例实际上已经在本地安装了您的镜像。SSH 进入 docker 主机并执行`docker images`命令。您应该看到您的 docker 镜像列在其中，如下所示：

```
$ sudo docker images

```

*如果我的镜像没有出现怎么办？*检查代理日志，并确保您的容器实例能够通过 curl 访问您的 docker 注册表并打印出可用的标签：

```
curl [need to add in path to registry!]

```

### 注意

**$ sudo docker images 告诉我们什么：**我们的容器镜像已成功安装在主机上。

## 手动启动您的 Docker 镜像

既然我们知道我们的镜像已安装在主机上，我们需要知道它是否对 Docker 守护程序可访问。测试确保您的镜像可以在容器实例上运行的简单方法是尝试从命令行运行您的镜像。这里还有一个额外的好处：我们现在有机会进一步检查应用程序日志以进行进一步的故障排除。

让我们看一下以下示例：

```
$ sudo docker run -it [need to add in path to registry/latest bin!]

```

### 注意

**`$ sudo docker run <imagename>`告诉我们什么：**我们可以从 docker 守护程序访问容器镜像，并且还提供可访问的输出日志以进行进一步的故障排除。

*如果我的镜像无法运行？*检查是否有任何正在运行的容器。如果预期的容器没有在主机上运行，可能会有阻止它启动的问题：

```
$ sudo docker ps

```

当容器启动失败时，它不会记录任何内容。容器启动过程的日志输出位于主机上的`/var/log/containers`中。在这里，您会找到遵循`<service>_start_errors.log`命名约定的文件。在这些日志中，您会找到我们的`RUN`命令生成的任何输出，并且这是故障排除的推荐起点，以了解为什么您的容器启动失败。

### 提示

**提示：** Logspout ([`github.com/gliderlabs/logspout`](https://github.com/gliderlabs/logspout)) 是 Docker 容器的日志路由器，运行在 Docker 内部。Logspout 附加到主机上的所有容器，然后将它们的日志路由到您想要的位置。

虽然我们也可以查看`/var/log/messages`中的输出来尝试故障排除，但我们还有一些其他途径可以追求，尽管可能需要更多的工作量。

## 从缓存中检查文件系统状态

正如我们讨论过的，每次成功的`RUN`命令在我们的 Dockerfile 中，Docker 都会缓存整个文件系统状态。我们可以利用这个缓存来检查失败的`RUN`命令之前的最新状态。

完成任务的方法：

+   访问 Dockerfile 并注释掉失败的`RUN`命令，以及任何后续的`RUN`命令

+   重新保存 Dockerfile

+   重新执行`$ sudo docker build`和`$ sudo docker run`

## 图像层 ID 作为调试容器

每次 Docker 成功执行 Dockerfile 中的`RUN`命令时，图像文件系统中都会提交一个新的层。方便起见，您可以使用这些层 ID 作为图像来启动一个新的容器。

考虑以下 Dockerfile 作为示例：

```
FROM centos 
RUN echo 'trouble' > /tmp/trouble.txt 
RUN echo 'shoot' >> /tmp/shoot.txt 

```

如果我们从这个 Dockerfile 构建：

```
$ docker build -force-rm -t so26220957 .

```

我们将获得类似以下的输出：

```
Sending build context to Docker daemon 3.584 kB 
Sending build context to Docker daemon 
Step 0 : FROM ubuntu 
   ---> b750fe79269d 
Step 1 : RUN echo 'trouble' > /tmp/trouble.txt 
   ---> Running in d37d756f6e55 
   ---> de1d48805de2 
Removing intermediate container d37d756f6e55 
Step 2 : RUN echo 'bar' >> /tmp/shoot.txt 
Removing intermediate container a180fdacd268 
Successfully built 40fd00ee38e1

```

然后，我们可以使用前面的图像层 ID 从`b750fe79269d`、`de1d48805de2`和`40fd00ee38e1`开始新的容器：

```
$ docker run -rm b750fe79269d cat /tmp/trouble.txt 
cat: /tmp/trouble.txt No such file or directory 
$ docker run -rm de1d48805de2 cat /tmp/trouble.txt 
trouble 
$ docker run -rm 40fd00ee38e1 cat /tmp/trouble.txt 
trouble 
shoot

```

### 注意

我们使用`--rm`来删除所有调试容器，因为没有理由让它们在运行后继续存在。

*如果我的容器构建失败会发生什么？*由于构建失败时不会创建任何映像，我们将无法获得容器的哈希 ID。相反，我们可以记录前一层的 ID，并使用该 ID 运行一个带有该 ID 的 shell 的容器：

```
$ sudo docker run --rm -it <id_last_working_layer> bash -il

```

进入容器后，执行失败的命令以重现问题，修复命令并进行测试，最后使用修复后的命令更新 Dockerfile。

您可能还想启动一个 shell 并浏览文件系统，尝试命令等等：

```
$ docker run -rm -it de1d48805de2 bash -il 
root@ecd3ab97cad4:/# ls -l /tmp 
total 4 
-rw-r-r-- 1 root root 4 Jul 3 12:14 trouble.txt 
root@ecd3ab97cad4:/# cat /tmp/trouble.txt 
trouble 
root@ecd3ab97cad4:/#

```

## 其他示例

最后一个示例是注释掉以下 Dockerfile 中的内容，包括有问题的行。然后我们可以手动运行容器和 docker 命令，并以正常方式查看日志。在这个 Dockerfile 示例中：

```
RUN trouble 
RUN shoot 
RUN debug 

```

此外，如果失败是在射击，那么注释如下：

```
RUN trouble 
# RUN shoot 
# RUN debug 

```

然后，构建和运行：

```
$ docker build -t trouble . 
$ docker run -it trouble bash 
container# shoot 
...grep logs...

```

## 检查失败的容器进程

即使您的容器成功从命令行运行，检查任何失败的容器进程，不再运行的容器，并检查我们的容器配置也是有益的。

运行以下命令来检查失败或不再运行的容器，并注意`CONTAINER ID`以检查特定容器的配置：

```
$ sudo docker ps -a

```

注意容器的**状态**。如果您的任何容器的**状态**显示除`0`之外的退出代码，可能存在容器配置的问题。举个例子，一个错误的命令会导致退出代码为`127`。有了这些信息，您可以调试任务定义`CMD`字段。

虽然有些有限，但我们可以进一步检查容器以获取额外的故障排除细节：

```
$ **sudo docker inspect <containerId>

```

最后，让我们也分析一下容器的应用程序日志。容器启动失败的错误消息将在这里输出：

```
$ sudo docker logs <containerId>

```

## 其他潜在有用的资源

`$ sudo docker` top 给出了容器内运行的进程列表。

当您需要比`top`提供的更多细节时，可以使用`$ sudo docker htop`，它提供了一个方便的、光标控制的界面。`htop`比`top`启动更快，您可以垂直和水平滚动列表以查看所有进程和完整的命令行，您不需要输入进程号来终止进程或优先级值来接收进程。

当本书付印时，排除容器和镜像的机制可能已经得到了显著改善。Docker 社区正在致力于*内置*报告和监控解决方案，市场力量也必将带来更多的选择。

## 使用 sysdig 进行调试

与任何新技术一样，一些最初固有的复杂性会随着时间的推移而被排除，新的工具和应用程序也会被开发出来以增强它们的使用。正如我们所讨论的，容器目前确实属于这一类别。虽然我们已经看到 Docker Registry 中官方标准化镜像的可用性有所改善，但我们现在也看到了新出现的工具，这些工具可以帮助我们有效地管理、监视和排除我们的容器。

![使用 sysdig 进行调试](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/tbst-dkr/img/image_03_016.jpg)

Sysdig 为容器提供应用程序监控[图片版权© 2014 Draios, Inc.]

**Sysdig** ([`www.sysdig.org/`](http://www.sysdig.org/) [)](http://www.sysdig.org/) 就是这样的一个工具。作为一个用于系统级探索和排除容器化环境可见性的*au courant*应用程序，`sysdig`的美妙之处在于我们能够从外部访问容器数据（尽管`sysdig`实际上也可以安装在容器内部）。从高层来看，`sysdig`为我们的容器管理带来了以下功能：

+   能够访问和审查每个容器中的进程（包括内部和外部 PID）

+   能够深入到特定容器中

+   能够轻松过滤一组容器以进行进程审查和分析

Sysdig 提供有关 CPU 使用、I/O、日志、网络、性能、安全和系统状态的数据。重申一遍，这一切都可以从外部完成，而无需在我们的容器中安装任何东西。

我们将在本书中继续有效地使用`sysdig`来监视和排除与我们的容器相关的特定进程，但现在我们将提供一些示例来排除我们基本的容器进程和日志问题。

让我们安装`sysdig`到我们的主机上，以展示它对我们和我们的容器可以做什么！

### 单步安装

通过以 root 或`sudo`执行以下命令，可以在一步中完成`sysdig`的安装：

```
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash

```

### 注意

**注意：**`sysdig`目前已在最新的 Debian 和 Ubuntu 版本中本地包含；但建议更新/运行安装以获取最新的软件包。

### 高级安装

根据`sysdig`维基百科，高级安装方法可能对脚本化部署或容器化环境有用。它也很容易；高级安装方法已列入 RHEL 和 Debian 系统。

### 什么是凿子？

要开始使用`sysdig`，我们应该了解一些专业术语，特别是**凿子**。在`sysdig`中，凿子是一些小脚本（用 Lua 编写），用于分析`sysdig`事件流以执行有用的操作。事件被有效地带到用户级别，附加上下文，然后可以应用脚本。凿子在活动系统上运行良好，但也可以与跟踪文件一起用于离线分析。您可以同时运行尽可能多的凿子。例如：

`topcontainers_error` chisel 将按错误数量显示顶部容器。

有关 sysdig 凿子的列表：

`$ sysdig -cl`（使用`-i`标志获取有关特定凿子的详细信息）

**单容器进程分析**

使用`topprocs_cpu`凿子的示例，我们可以应用过滤器：

```
$ sudo sysdig -pc -c topprocs_cpu container.name=zany_torvalds

```

这些是示例结果：

```
CPU%          Process       container.name   
------------------------------------------ 
02.49%        bash          zany_torvalds 
37.06%        curl          zany_torvalds 
0.82%         sleep         zany_torvalds

```

与使用`$ sudo docker top`（以及类似）不同，我们可以确定我们想要查看进程的确切容器；例如，以下示例仅显示来自`wordpress`容器的进程：

```
$ sudo sysdig -pc -c topprocs_cpu container.name contains wordpress 

CPU%           Process         container.name   
-------------------------------------------------- 
5.38%          apache2         wordpress3 
4.37%          apache2         wordpress2 
6.89%          apache2         wordpress4 
7.96%          apache2         wordpress1

```

**其他有用的 Sysdig 凿子和语法**

+   `topprocs_cpu`按 CPU 使用率显示顶部进程

+   `topcontainers_file`按 R+W 磁盘字节显示顶部容器

+   `topcontainers_net`按网络 I/O 显示顶部容器

+   `lscontainers`将列出正在运行的容器

+   `$ sudo sysdig -pc -cspy_logs`分析每个屏幕的所有日志

+   `$ sudo sysdig -pc -cspy_logs container.name=zany_torvalds`打印容器`zany_torvalds`的日志

## 故障排除-一个开放的社区等待您

一般来说，你可能遇到的大多数问题在其他地方和其他时间已经有人经历过。Docker 和开源社区、IRC 频道和各种搜索引擎都可以提供高度可访问的信息，并可能为你提供解决困扰的情况和条件的答案。充分利用开源社区（特别是 Docker 社区）来获取你所寻找的答案。就像任何新兴技术一样，在开始阶段，我们都在一起学习！

# 自动化镜像构建

有许多方法可以自动化构建容器镜像的过程；在一本书中无法合理地提供所有方法。在本书的后面章节中，我们将更深入地探讨一系列自动化选项和工具。在这种特定情况下，我们只讨论使用我们的 Dockerfile 进行自动化。我们已经讨论过 Dockerfile 可以用于自动化镜像构建，所以让我们更专门地研究 Dockerfile 自动化。

## 单元测试部署

在构建过程中，Docker 允许我们运行任何命令。让我们利用这一点，在构建镜像的同时启用单元测试。这些单元测试可以帮助我们在将镜像推送到分阶段或部署之前识别生产镜像中的问题，并且至少部分验证镜像的功能是否符合我们的意图和期望。如果单元测试成功运行，我们就有了一定程度的信心，我们有一个有效的服务运行环境。这也意味着，如果测试失败，我们的构建也会失败，有效地阻止了一个不工作的镜像进入生产环境。

使用我们之前的`cloudconsulted/joomla`仓库镜像，我们将建立一个自动构建的示例工作流程，并进行测试。我们将使用**PHPUnit**，因为它是 Joomla 项目开发团队正式使用的工具，它可以方便地针对整个堆栈（Joomla 代码、Apache、MySQL 和 PHP）运行单元测试。

进入`cloudconsulted/joomla`的 Dockerfile 目录（在我们的例子中是`dockerbuilder`），并进行以下更新。

执行以下命令安装 PHPUnit：

```
[# install composer to a specific directory 
curl -sS https://getcomposer.org/installer | php -- --install-dir=bin 
# use composer to install phpunit 
composer global require "phpunit/phpunit=4.1.*"]

```

PHPUnit 也可以通过执行以下命令进行安装：

```
[# install phpunit 
wget https://phar.phpunit.de/phpunit.phar 
chmod +x phpunit.phar 
mv phpunit.phar /usr/local/bin/phpunit 
# might also need to put the phpunit executable placed here? test this: 
cp /usr/local/bin/phpunit /usr/bin/phpunit]

```

现在，让我们用`phpunit`运行我们的单元测试：

```
# discover and run any tests within the source code 
RUN phpunit 

```

我们还需要确保将我们的单元测试`COPY`到镜像内的资产中：

```
# copy unit tests to assets 
COPY test /root/test 

```

最后，让我们做一些清理工作。为了确保我们的生产代码不能依赖（无论是意外还是其他原因）测试代码，一旦单元测试完成，我们应该删除那些测试文件：

```
# clean up test files 
RUN rm -rf test 

```

我们对 Dockerfile 的总更新包括：

```
wget https://phar.phpunit.de/phpunit.phar 
chmod +x phpunit.phar 
mv phpunit.phar /usr/local/bin/phpunit 

RUN phpunit   
COPY test /root/test 
RUN rm -rf test 

```

现在，我们有一个脚本化的 Dockerfile，每次构建此镜像时，都将完全测试我们的 Joomla 代码、Apache、MySQL 和 PHP 依赖项，作为构建过程的一个文字部分。结果是一个经过测试的、可重现的生产环境！

## 自动化测试部署

在我们对部署可行图像的信心增强之后，这个构建过程仍然需要开发人员或 DevOps 工程师在每次生产推送之前重新构建镜像。相反，我们将依赖于来自我们的 Docker 和 GitHub 存储库的自动构建。

我们的 GitHub 和 Docker Hub 存储库将用于自动化我们的构建。通过在 GitHub 上维护我们的 Dockerfile、依赖项、相关脚本等，对存储库进行任何推送或提交将自动强制将更新的推送到同步的 Docker Hub 存储库。我们在 Docker Hub 上拉取的生产图像会自动更新任何新的构建信息。

Docker Cloud 是最新的应用程序生命周期的一部分，它提供了一个托管的注册服务，具有构建和测试设施。Docker Cloud 扩展了 Tutum 的功能，并与 Docker Hub 更紧密地集成。借助 Docker Cloud 系统，管理员可以仅需点击几下即可在云中部署和扩展应用程序。持续交付代码集成和自动化构建、测试和部署工作流程。它还提供了对整个基础架构容器的可见性，并访问面向开发人员友好的 CLI 工具的程序化 RESTful API。因此，Docker Cloud 可用于自动化构建过程和测试部署。

以下是 Docker Cloud 的重要特性：

+   允许构建 Docker 镜像，并将云存储库链接到源代码，以便简化镜像构建过程

+   它允许将您的基础架构和云服务链接起来，以自动提供新节点

+   一旦镜像构建完成，它可以用于部署服务，并可以与 Docker Cloud 的服务和微服务集合进行链接

+   在 Docker Cloud 中，beta 模式下的 Swarm 管理可用于在 Docker Cloud 中创建 swarm 或将现有的 swarm 注册到 Docker Cloud 中使用 Docker ID

# 总结

Docker 和 Dockerfiles 为应用程序开发周期提供了可重复的流程，为开发人员和 DevOps 工程师提供了独特的便利-生产就绪的部署，注入了经过测试的镜像的信心和自动化的便利。这为最需要的人提供了高度的赋权，并导致了经过测试和生产就绪的图像构建的持续交付，我们可以完全自动化，延伸到我们的云端。

在本章中，我们了解到生产就绪的应用程序容器化中的一项关键任务是图像构建。构建基本和分层镜像以及避免故障排除的领域是我们涵盖的主要主题。在构建我们的基本镜像时，我们看到 Docker Registry 提供了丰富和经过验证的图像，我们可以自由地用于可重复的流程。我们还讨论了手动构建图像，从头开始。前进的时候，我们探讨了使用 Dockerfile 构建分层图像，并详细列出了 Dockerfile 命令。最后，一个示例工作流程说明了自动化图像构建以及镜像和容器的测试。在整个过程中，我们强调了故障排除领域和选项的方法和手段。

为您的应用程序容器构建简洁的 Docker 镜像对于应用程序的功能和可维护性至关重要。现在我们已经了解了构建基本和分层镜像以及基本的故障排除方法，我们将期待构建真实的应用程序镜像。在下一章中，我们将学习使用一组合适的镜像规划和构建多层应用程序。
