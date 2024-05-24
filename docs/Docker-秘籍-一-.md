# Docker 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/3BDF7E02FD45D3E3DF6846ABA9F12FB8`](https://zh.annas-archive.org/md5/3BDF7E02FD45D3E3DF6846ABA9F12FB8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

使用 Docker^(TM)，容器正在成为主流，企业已准备好在生产中使用它们。这本书专门设计帮助您快速掌握最新的 Docker 版本，并让您有信心在生产中使用它。本书还涵盖了 Docker 的用例、编排、集群、托管平台、安全性和性能，这将帮助您了解生产部署的不同方面。

Docker 及其生态系统正在以非常快的速度发展，因此了解基础知识并逐步采用新概念和工具非常重要。通过逐步的实用和适用的操作指南，“Docker Cookbook”不仅将帮助您使用当前版本的 Docker（1.6），而且通过附带的文本，将为您提供应对新版本 Docker 中的微小变化的概念信息。要了解更多关于本书的信息，请访问[`dockercookbook.github.io/`](http://dockercookbook.github.io/)。

Docker^(TM)是 Docker，Inc.的注册商标。

# 本书涵盖的内容

第一章，“介绍和安装”，将容器与裸机和虚拟机进行比较。它可以帮助您了解启用容器化的 Linux 内核功能；最后，我们将看一下安装操作。

第二章，“使用 Docker 容器”，涵盖了大部分与容器相关的操作，如启动、停止和删除容器。它还可以帮助您获取有关容器的低级信息。

第三章，“使用 Docker 镜像”，解释了与镜像相关的操作，如拉取、推送、导出、导入、基础镜像创建和使用 Dockerfile 创建镜像。我们还建立了一个私有注册表。

第四章，“容器的网络和数据管理”，涵盖了连接容器与另一个容器在外部世界的操作。它还涵盖了如何共享来自其他容器和主机系统的外部存储。

第五章，“Docker 的用例”，解释了大部分 Docker 的用例，如将 Docker 用于测试、CI/CD、设置 PaaS 以及将其用作计算引擎。

第六章，“Docker API 和语言绑定”，涵盖了 Docker 远程 API 和 Python 语言绑定作为示例。

第七章，“Docker 性能”，解释了一个人可以遵循的性能方法，以比较容器与裸金属和虚拟机的性能。它还涵盖了监控工具。

第八章，“Docker 编排和托管平台”，介绍了 Docker compose 和 Swarm。我们将研究 CoreOS 和 Project Atomic 作为容器托管平台，然后介绍 Docker 编排的 Kubernetes。

第九章，“Docker 安全性”，解释了一般安全准则，用于强制访问控制的 SELinux，以及更改功能和共享命名空间等其他安全功能。

第十章，“获取帮助和技巧和窍门”，提供了有关 Docker 管理和开发相关的帮助、技巧和资源。

# 本书需要什么

这本食谱中的食谱肯定会在安装了 Fedora 21 的物理机器或虚拟机上运行，因为我将该配置作为主要环境。由于 Docker 可以在许多平台和发行版上运行，您应该能够毫无问题地运行大多数食谱。对于一些食谱，您还需要 Vagrant ([`www.vagrantup.com/`](https://www.vagrantup.com/)) 和 Oracle Virtual Box ([`www.virtualbox.org/`](https://www.virtualbox.org/))。

# 本书适合谁

*Docker Cookbook*适用于希望在开发、QA 或生产环境中使用 Docker 的开发人员、系统管理员和 DevOps 工程师。

预计读者具有基本的 Linux/Unix 技能，如安装软件包，编辑文件，管理服务等。

任何关于虚拟化技术（如 KVM、XEN 和 VMware）的经验都将帮助读者更好地理解容器技术，但并非必需。

# 章节

在本书中，您会发现一些经常出现的标题（准备工作，如何做，它是如何工作的，还有更多，以及另请参阅）。

为了清晰地说明如何完成一个食谱，我们使用以下章节：

## 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置食谱所需的任何软件或任何初步设置。

## 如何做…

本节包含遵循食谱所需的步骤。

## 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

## 还有更多…

本节包括有关食谱的额外信息，以使读者更加了解食谱。

## 另请参阅

本节提供有关食谱的其他有用信息的链接。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“您可以使用`--driver/-d`选项来选择部署所需的多个端点之一。”

代码块设置如下：

```
[Unit] 
Description=MyApp 
After=docker.service 
Requires=docker.service 

[Service] 
TimeoutStartSec=0 
ExecStartPre=-/usr/bin/docker kill busybox1 
ExecStartPre=-/usr/bin/docker rm busybox1 
ExecStartPre=/usr/bin/docker pull busybox 
ExecStart=/usr/bin/docker run --name busybox1 busybox /bin/sh -c "while true; do echo Hello World; sleep 1; done" 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[Service] 
Type=notify 
EnvironmentFile=-/etc/sysconfig/docker 
EnvironmentFile=-/etc/sysconfig/docker-storage 
ExecStart=/usr/bin/docker -d -H fd:// $OPTIONS $DOCKER_STORAGE_OPTIONS 
LimitNOFILE=1048576 
LimitNPROC=1048576 

[Install] 
WantedBy=multi-user.target 
```

任何命令行输入或输出都以以下方式编写：

```
$ docker pull fedora 

```

**新术语**和**重要单词**以粗体显示。例如，在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“转到项目主页，在**APIs & auth**部分下，选择**APIs**，并启用 Google **Compute Engine API**。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

技巧和窍门会出现在这样的地方。


# 第一章：介绍和安装

在本章中，我们将涵盖以下内容：

+   验证 Docker 安装的要求

+   安装 Docker

+   拉取镜像并运行容器

+   向 Docker 添加非 root 用户进行管理

+   使用 Docker Machine 设置 Docker 主机

+   使用 Docker 命令行查找帮助

# 介绍

在 IT 革命的最初阶段，大多数应用程序是直接部署在物理硬件上，通过主机操作系统。由于单一用户空间，运行时在应用程序之间共享。部署是稳定的，以硬件为中心，并且具有长时间的维护周期。大多由 IT 部门管理，并且给开发人员提供了更少的灵活性。在这种情况下，硬件资源经常被低效利用。

以下图表描述了这样的设置：

![Introduction](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00262.jpeg)

传统应用程序部署（[`rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf`](https://rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf)）

为了克服传统部署设置的限制，虚拟化被发明了。使用诸如 KVM、XEN、ESX、Hyper-V 等的 hypervisor，我们模拟了虚拟机（VM）的硬件，并在每个虚拟机上部署了一个客户操作系统。VM 可以具有与其主机不同的操作系统；这意味着我们负责管理该 VM 的补丁、安全性和性能。通过虚拟化，应用程序在 VM 级别上被隔离，并由 VM 的生命周期定义。这在投资回报和灵活性方面提供了更好的回报，但增加了复杂性和冗余成本。以下图表描述了典型的虚拟化环境：

![Introduction](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00263.jpeg)

在虚拟化环境中的应用程序部署（[`rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf`](https://rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf)）

在虚拟化之后，我们现在正朝着更加应用中心化的 IT 发展。我们已经移除了虚拟机监视器层，以减少硬件仿真和复杂性。应用程序与其运行时环境一起打包，并使用容器进行部署。OpenVZ，Solaris Zones 和 LXC 是容器技术的一些例子。与虚拟机相比，容器的灵活性较低；例如，我们无法在 Linux 操作系统上运行 Microsoft Windows。与虚拟机相比，容器也被认为不太安全，因为在容器中，一切都在主机操作系统上运行。如果容器受到损害，那么可能会完全访问主机操作系统。设置、管理和自动化可能会变得有点复杂。这些是我们在过去几年中没有看到容器大规模采用的一些原因，尽管我们已经有了这项技术。

![Introduction](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00264.jpeg)

使用容器进行应用部署（[`rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf`](https://rhsummit.files.wordpress.com/2014/04/rhsummit2014-application-centric_packaging_with_docker_and_linux_containers-20140412riek7.pdf)）

有了 Docker，容器突然成为了一等公民。所有大公司，如 Google，Microsoft，Red Hat，IBM 等，现在都在努力使容器成为主流。

Docker 是由 Solomon Hykes 在 dotCloud 内部项目启动的，他目前是 Docker，Inc.的首席技术官。它于 2013 年 3 月以 Apache 2.0 许可证的形式开源发布。通过 dotCloud 的平台即服务经验，Docker 的创始人和工程师们意识到了运行容器的挑战。因此，他们开发了一种管理容器的标准方式。

Docker 使用了 Linux 的底层内核功能来实现容器化。以下图表描述了 Docker 使用的执行驱动程序和内核功能。我们稍后会讨论执行驱动程序。让我们先看一些 Docker 使用的主要内核功能：

![Introduction](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00265.jpeg)

Docker 使用的执行驱动程序和内核功能（[`blog.docker.com/wp-content/uploads/2014/03/docker-execdriver-diagram.png`](http://blog.docker.com/wp-content/uploads/2014/03/docker-execdriver-diagram.png)）

## 命名空间

命名空间是容器的构建模块。有不同类型的命名空间，每个命名空间都将应用程序相互隔离。它们是使用克隆系统调用创建的。也可以附加到现有的命名空间。Docker 使用的一些命名空间在以下部分进行了解释。

### pid 命名空间

`pid`命名空间允许每个容器拥有自己的进程编号。每个`pid`形成自己的进程层次结构。父命名空间可以看到子命名空间并影响它们，但子命名空间既不能看到父命名空间也不能影响它。

如果有两个层次结构，那么在顶层，我们将看到在子命名空间中运行的进程具有不同的 PID。因此，在子命名空间中运行的进程将具有两个 PID：一个在子命名空间中，另一个在父命名空间中。例如，如果我们在容器上运行一个程序（`container.sh`），那么我们也可以在主机上看到相应的程序。

在容器内：

![pid 命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00266.jpeg)

在主机上：

![pid 命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00267.jpeg)

### net 命名空间

有了`pid`命名空间，我们可以在不同的隔离环境中多次运行相同的程序；例如，我们可以在不同的容器上运行 Apache 的不同实例。但是没有`net`命名空间，我们将无法在每个容器上监听端口 80。`net`命名空间允许我们在每个容器上拥有不同的网络接口，从而解决了我之前提到的问题。回环接口在每个容器中也会有所不同。

要在容器中启用网络，我们可以在两个不同的`net`命名空间中创建一对特殊接口，并允许它们彼此通信。特殊接口的一端位于容器内，另一端位于主机系统中。通常，容器内的接口被命名为`eth0`，在主机系统中，它被赋予一个随机名称，如`vethcf1a`。然后，通过主机上的桥接器（`docker0`）将这些特殊接口连接起来，以实现容器之间的通信和数据包路由。

在容器内，你会看到类似以下的东西：

![net 命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00268.jpeg)

在主机上，它看起来像是这样：

![net 命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00269.jpeg)

此外，每个`net`命名空间都有自己的路由表和防火墙规则。

### ipc 命名空间

**进程间通信**（**ipc**）提供信号量、消息队列和共享内存段。这些天它并不被广泛使用，但一些程序仍然依赖它。

如果一个容器创建的`ipc`资源被另一个容器消耗，那么运行在第一个容器上的应用程序可能会失败。有了`ipc`命名空间，运行在一个命名空间中的进程无法访问另一个命名空间的资源。

### mnt 命名空间

只需一个 chroot，就可以检查来自 chroot 目录/命名空间的系统的相对路径。`mnt`命名空间将 chroot 的概念提升到了下一个级别。有了`mnt`命名空间，容器可以拥有自己的一组挂载的文件系统和根目录。一个`mnt`命名空间中的进程无法看到另一个`mnt`命名空间的挂载文件系统。

### uts 命名空间

有了`uts`命名空间，我们可以为每个容器设置不同的主机名。

### 用户命名空间

有了`user`命名空间支持，我们可以在主机上拥有非零 ID 的用户，但在容器内可以拥有零 ID。这是因为`user`命名空间允许用户和组 ID 的每个命名空间映射。

有多种方法可以在主机和容器之间以及容器和容器之间共享命名空间。我们将在后续章节中看到如何做到这一点。

## Cgroups

**控制组**（**cgroups**）为容器提供资源限制和计量。来自 Linux 内核文档：

> *控制组提供了一种聚合/分区任务集的机制，并将所有未来的子任务分成具有特定行为的分层组。*

简单来说，它们可以与`ulimit` shell 命令或`setrlimit`系统调用进行比较。cgroups 允许将资源限制设置为一组进程，而不是单个进程。

控制组分为不同的子系统，如 CPU、CPU 集、内存块 I/O 等。每个子系统可以独立使用，也可以与其他子系统分组。cgroups 提供的功能包括：

+   **资源限制**：例如，一个 cgroup 可以绑定到特定的 CPU，因此该组中的所有进程只能在给定的 CPU 上运行

+   **优先级**：一些组可能会获得更多的 CPU 份额

+   **计量**：您可以测量不同子系统的资源使用情况以进行计费

+   **控制**：冻结和重新启动组

一些可以由 cgroups 管理的子系统如下：

+   **blkio**：它设置对块设备（如磁盘、SSD 等）的 I/O 访问

+   **Cpu**：它限制对 CPU 的访问

+   **Cpuacct**：它生成 CPU 资源利用率

+   **Cpuset**：它将多核系统上的 CPU 分配给 cgroup 中的任务

+   **Devices**：它为 cgroup 中的一组任务提供访问

+   **Freezer**：它暂停或恢复 cgroup 中的任务

+   **Memory**：它设置 cgroup 中任务的内存使用限制

有多种方法可以控制 cgroups 的工作。最流行的两种方法是手动访问 cgroup 虚拟文件系统和使用`libcgroup`库访问它。要在 fedora 中使用`libcgroup`，运行以下命令安装所需的软件包：

```
$ sudo yum install libcgroup libcgroup-tools

```

安装后，您可以使用以下命令在伪文件系统中获取子系统及其挂载点的列表：

```
$ lssubsys -M

```

![Cgroups](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00270.jpeg)

虽然我们还没有看实际的命令，但让我们假设我们正在运行一些容器，并且想要获取容器的 cgroup 条目。要获取这些条目，我们首先需要获取容器 ID，然后使用`lscgroup`命令获取容器的 cgroup 条目，可以从以下命令中获取：

![Cgroups](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00271.jpeg)

### 注意

有关更多详细信息，请访问[`docs.docker.com/articles/runmetrics/`](https://docs.docker.com/articles/runmetrics/)。

## 联合文件系统

联合文件系统允许透明地叠加分开的文件系统（称为层）的文件和目录，以创建一个新的虚拟文件系统。在启动容器时，Docker 叠加附加到图像的所有层，并创建一个只读文件系统。在此基础上，Docker 创建一个读/写层，容器的运行时环境使用它。有关更多详细信息，请参阅本章的*拉取图像并运行容器*部分。Docker 可以使用多种联合文件系统变体，包括 AUFS、Btrfs、vfs 和 DeviceMapper。

Docker 可以与不同的执行驱动程序一起工作，例如`libcontainer`、`lxc`和`libvirt`来管理容器。默认的执行驱动程序是`libcontainer`，它是 Docker 的默认驱动程序。它可以为 Docker 操作命名空间、控制组、能力等。

# 验证 Docker 安装的要求

Docker 支持许多 Linux 平台，如 RHEL、Ubuntu、Fedora、CentOS、Debian、Arch Linux 等。它也支持许多云平台，如 Amazon EC2、Rackspace Cloud 和 Google Compute Engine。借助虚拟环境 Boot2Docker，它也可以在 OS X 和 Microsoft Windows 上运行。不久前，微软宣布将在其下一个 Microsoft Windows 版本中添加对 Docker 的本机支持。

在这篇文章中，让我们验证 Docker 安装的要求。我们将在安装了 Fedora 21 的系统上进行检查，尽管相同的步骤也适用于 Ubuntu。

## 准备工作

以 root 用户登录安装了 Fedora 21 的系统。

## 如何做…

执行以下步骤：

1.  Docker 不支持 32 位架构。要检查系统架构，请运行以下命令：

```
$ uname -i
x86_64

```

1.  Docker 支持内核 3.8 或更高版本。它已经被后移至一些内核 2.6，如 RHEL 6.5 及以上版本。要检查内核版本，请运行以下命令：

```
$ uname -r
3.18.7-200.fc21.x86_64

```

1.  运行的内核应支持适当的存储后端。其中一些是 VFS、DeviceMapper、AUFS、Btrfs 和 OverlayFS。

大多数情况下，默认的存储后端或驱动程序是 devicemapper，它使用设备映射器薄配置模块来实现层。它应该默认安装在大多数 Linux 平台上。要检查设备映射器，您可以运行以下命令：

```
$ grep device-mapper /proc/devices
253 device-mapper

```

在大多数发行版中，AUFS 需要一个修改过的内核。

1.  对于 cgroups 和命名空间的支持已经在内核中有一段时间了，并且应该默认启用。要检查它们的存在，您可以查看正在运行的内核的相应配置文件。例如，在 Fedora 上，我可以做类似以下的事情：

```
$ grep -i namespaces /boot/config-3.18.7-200.fc21.x86_64
CONFIG_NAMESPACES=y
$ grep -i cgroups /boot/config-3.18.7-200.fc21.x86_64
CONFIG_CGROUPS=y

```

## 工作原理…

通过前面的命令，我们验证了 Docker 安装的要求。

## 另请参阅

+   在 Docker 网站的安装文档中[`docs.docker.com/installation/`](https://docs.docker.com/installation/)

# 安装 Docker

由于有许多发行版支持 Docker，我们将在这篇文章中只看一下 Fedora 21 上的安装步骤。对于其他发行版，您可以参考本文的*另请参阅*部分中提到的安装说明。使用 Docker Machine，我们可以在本地系统、云提供商和其他环境上轻松设置 Docker 主机。我们将在另一篇文章中介绍这个。

## 准备工作

检查前面一篇文章中提到的先决条件。

## 如何做…

1.  使用 yum 安装 Docker：

```
$  yum -y install docker

```

## 它是如何工作的...

上述命令将安装 Docker 及其所需的所有软件包。

## 还有更多...

默认的 Docker 守护程序配置文件位于`/etc/sysconfig/docker`，在启动守护程序时使用。以下是一些基本操作：

+   启动服务：

```
$ systemctl start docker

```

+   验证安装：

```
$ docker info

```

+   更新软件包：

```
$ yum -y update docker

```

+   启用开机启动服务：

```
$ systemctl enable docker

```

+   停止服务：

```
$ systemctl stop docker

```

## 另请参阅

+   安装文档位于 Docker 网站上的[`docs.docker.com/installation/`](https://docs.docker.com/installation/)

# 拉取镜像并运行容器

我从下一章借用了这个配方来介绍一些概念。如果您在这个配方中找不到所有的解释，不要担心。我们将在本章节或接下来的几章中详细讨论所有的主题。现在，让我们拉取一个镜像并运行它。在这个配方中，我们还将熟悉 Docker 架构及其组件。

## 准备工作

获取安装了 Docker 的系统访问权限。

## 如何做到...

1.  要拉取一个镜像，请运行以下命令：

```
$ docker pull fedora

```

1.  使用以下命令列出现有的镜像：

```
$ docker images

```

![如何做到...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00272.jpeg)

1.  使用拉取的镜像创建一个容器，并列出容器为：![如何做到...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00273.jpeg)

## 它是如何工作的...

Docker 具有客户端-服务器架构。其二进制文件包括 Docker 客户端和服务器守护程序，并且可以驻留在同一台主机上。客户端可以通过套接字或 RESTful API 与本地或远程 Docker 守护程序通信。Docker 守护程序构建、运行和分发容器。如下图所示，Docker 客户端将命令发送到运行在主机上的 Docker 守护程序。Docker 守护程序还连接到公共或本地索引，以获取客户端请求的镜像：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00274.jpeg)

Docker 客户端-服务器架构 ([`docs.docker.com/introduction/understanding-docker/`](https://docs.docker.com/introduction/understanding-docker/))

因此，在我们的情况下，Docker 客户端向在本地系统上运行的守护程序发送请求，然后守护程序连接到公共 Docker 索引并下载镜像。一旦下载完成，我们就可以运行它。

## 还有更多...

让我们探索一些我们在这个配方中遇到的关键词：

+   **图像**：Docker 图像是只读模板，在运行时它们为我们提供容器。有一个基本图像和在其上的层的概念。例如，我们可以有一个基本图像的 Fedora 或 Ubuntu，然后我们可以安装软件包或对基本图像进行修改以创建一个新的层。基本图像和新层可以被视为一个新的图像。例如，在下图中，**Debian**是基本图像，**emacs**和**Apache**是添加在其上的两个层。它们非常易于移植，并且可以轻松共享：![更多信息...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00275.jpeg)

Docker 图像层([`docs.docker.com/terms/images/docker-filesystems-multilayer.png`](http://docs.docker.com/terms/images/docker-filesystems-multilayer.png))

层被透明地放在基本图像的顶部，以创建一个统一的文件系统。

+   **注册表**：注册表保存 Docker 图像。它可以是公共的或私有的，您可以从中下载或上传图像。公共 Docker 注册表称为**Docker Hub**，我们稍后会介绍。

+   **索引**：索引管理用户帐户、权限、搜索、标记以及 Docker 注册表公共 Web 界面中的所有好东西。

+   **容器**：容器是由基本图像和在其上的层组合创建的运行图像。它们包含运行应用程序所需的一切。如前图所示，在启动容器时还会添加一个临时层，如果在停止和删除容器后未提交，则会被丢弃。如果提交，则会创建另一个层。

+   **仓库**：一个图像的不同版本可以通过多个标签进行管理，这些标签保存在不同的 GUID 中。仓库是由 GUID 跟踪的图像集合。

## 另请参阅

+   Docker 网站上的文档[`docs.docker.com/introduction/understanding-docker/`](http://docs.docker.com/introduction/understanding-docker/)

+   使用 Docker 1.6，Docker 社区和微软 Windows 发布了 Windows 的 Docker 本机客户端[`azure.microsoft.com/blog/2015/04/16/docker-client-for-windows-is-now-available`](http://azure.microsoft.com/blog/2015/04/16/docker-client-for-windows-is-now-available)

# 添加非 root 用户以管理 Docker

为了方便使用，我们可以允许非 root 用户通过将其添加到 Docker 组来管理 Docker。

## 做好准备

1.  如果还没有，创建 Docker 组：

```
$ sudo group add docker

```

1.  创建要授予管理 Docker 权限的用户：

```
$ useradd dockertest

```

## 如何做…

运行以下命令以允许新创建的用户管理 Docker：

```
$ sudo  gpasswd -a dockertest docker

```

## 它是如何工作的…

上述命令将向 Docker 组添加一个用户。添加的用户因此可以执行所有 Docker 操作。这可能存在安全风险。请访问第九章，*Docker 安全*了解更多详情。

# 使用 Docker Machine 设置 Docker 主机

今年早些时候，Docker 发布了编排工具（[`blog.docker.com/2015/02/orchestrating-docker-with-machine-swarm-and-compose/`](https://blog.docker.com/2015/02/orchestrating-docker-with-machine-swarm-and-compose/)）和 Machine、Swarm 和 Compose 可以无缝部署容器。在这个配方中，我们将介绍 Docker Machine，并在以后的章节中查看其他内容。使用 Docker Machine 工具（[`github.com/docker/machine/`](https://github.com/docker/machine/)），您可以使用一个命令在本地云上设置 Docker 主机。它目前处于测试模式，不建议用于生产。它支持诸如 VirtualBox、OpenStack、Google、Digital Ocean 等环境。有关完整列表，您可以访问[`github.com/docker/machine/tree/master/drivers`](https://github.com/docker/machine/tree/master/drivers)。让我们使用这个工具在 Google Cloud 中设置一个主机。

### 注意

我们将仅在本配方中使用 Docker Machine。本章或其他章节中提到的配方可能在 Docker Machine 设置的主机上工作或不工作。

## 准备工作

Docker Machine 不会出现在默认安装中。您需要从其 GitHub 发布链接（[`github.com/docker/machine/releases`](https://github.com/docker/machine/releases)）下载它。请在下载之前检查最新版本和分发。作为 root 用户，下载二进制文件并使其可执行：

```
$ curl -L https://github.com/docker/machine/releases/download/v0.2.0/docker-machine_linux-amd64 > /usr/local/bin/docker-machine
$ chmod a+x  /usr/local/bin/docker-machine

```

如果您在**Google Compute Engine**（**GCE**）上没有帐户，那么您可以注册免费试用（[`cloud.google.com/compute/docs/signup`](https://cloud.google.com/compute/docs/signup)）来尝试这个配方。我假设您在 GCE 上有一个项目，并且在下载 Docker Machine 二进制文件的系统上安装了 Google Cloud SDK。如果没有，那么您可以按照以下步骤操作：

1.  在本地系统上设置 Google Cloud SDK：

```
$ curl https://sdk.cloud.google.com | bash

```

1.  在 GCE 上创建一个项目（[`console.developers.google.com/project`](https://console.developers.google.com/project)）并获取其项目 ID。请注意，项目名称和其 ID 是不同的。

1.  转到项目主页，在**API 和身份验证**部分下，选择**API**，并启用 Google **Compute Engine API**。

## 如何操作...

1.  将我们收集到的项目 ID 分配给变量`GCE_PROJECT`：

```
$ export  GCE_PROJECT="<Your Project ID>"

```

1.  运行以下命令并输入弹出的网页浏览器上提供的代码：

```
$ docker-machine  create -d google --google-project=$GCE_PROJECT  --google-machine-type=n1-standard-2 --google-disk-size=50 cookbook
INFO[0000] Opening auth URL in browser.
.......
......
INFO[0015] Saving token in /home/nkhare/.docker/machine/machines/cookbook/gce_token

INFO[0015] Creating host...
INFO[0015] Generating SSH Key
INFO[0015] Creating instance.
INFO[0016] Creating firewall rule.
INFO[0020] Waiting for Instance...
INFO[0066] Waiting for SSH...
INFO[0066] Uploading SSH Key
INFO[0067] Waiting for SSH Key
INFO[0224] "cookbook" has been created and is now the active machine.
INFO[0224] To point your Docker client at it, run this in your shell: eval "$(docker-machine_linux-amd64 env cookbook)"

```

1.  列出 Docker Machine 管理的现有主机：

```
$ ./docker-machine_linux-amd64 ls

```

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00276.jpeg)

您可以使用 Docker Machine 管理多个主机。`*`表示活动主机。

1.  显示设置 Docker 客户端环境的命令：

```
$  ./docker-machine_linux-amd64 env cookbook

```

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00277.jpeg)

因此，如果使用前面的环境变量指向 Docker 客户端，我们将连接到在 GCE 上运行的 Docker 守护程序。

1.  并且要指定 Docker 客户端使用我们新创建的机器，请运行以下命令：

```
$ eval "$(./docker-machine_linux-amd64 env  cookbook)"

```

从现在开始，所有 Docker 命令都将在我们在 GCE 上预配的机器上运行，直到设置前面的环境变量。

## 工作原理...

Docker Machine 连接到云提供商并设置带有 Docker Engine 的 Linux VM。它在当前用户的主目录下创建一个`.docker/machine/`目录以保存配置。

## 还有更多...

Docker Machine 提供管理命令，如`create`、`start`、`stop`、`restart`、`kill`、`remove`、`ssh`和其他命令来管理机器。有关详细选项，请查找 Docker Machine 的帮助选项：

```
$ docker-machine  -h

```

您可以使用`--driver/-d`选项来选择部署的许多端点之一。例如，要使用 VirtualBox 设置环境，请运行以下命令：

```
$ docker-machine create --driver virtualbox dev

```

![还有更多...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00278.jpeg)

在这里，`dev`是机器名称。默认情况下，最新部署的机器将成为主机。

## 另请参阅

+   Docker 网站上的文档[`docs.docker.com/machine/`](https://docs.docker.com/machine/)

+   在[`docs.docker.com/installation/google/`](https://docs.docker.com/installation/google/)上设置 Docker 在 Google Compute Engine 上的指南

# 使用 Docker 命令行查找帮助

Docker 命令有很好的文档，可以在需要时进行参考。在线文档也有很多，但可能与您正在运行的 Docker 版本的文档不同。

## 准备工作

在您的系统上安装 Docker。

## 如何操作...

1.  在基于 Linux 的系统上，您可以使用`man`命令查找帮助，如下所示：

```
$ man docker

```

1.  还可以使用以下任何命令找到特定子命令的帮助：

```
$ man docker ps
$ man docker-ps

```

## 工作原理…

`man`命令使用 Docker 软件包安装的`man`页面显示帮助信息。

## 另请参阅

+   Docker 网站上的文档位于[`docs.docker.com/reference/commandline/cli/`](http://docs.docker.com/reference/commandline/cli/)


# 第二章：使用 Docker 容器

在本章中，我们将涵盖以下配方：

+   列出/搜索镜像

+   拉取镜像

+   列出镜像

+   启动容器

+   列出容器

+   停止容器

+   查看容器的日志

+   删除容器

+   设置容器的重启策略

+   在容器内获取特权访问

+   在启动容器时暴露端口

+   在容器内访问主机设备

+   向正在运行的容器注入新进程

+   返回有关容器的低级信息

+   对容器进行标记和过滤

# 介绍

在上一章中，安装 Docker 后，我们拉取了一个镜像，并从中创建了一个容器。Docker 的主要目标是运行容器。在本章中，我们将看到我们可以对容器进行不同的操作，如启动、停止、列出、删除等。这将帮助我们将 Docker 用于不同的用例，如测试、CI/CD、设置 PaaS 等，我们将在后面的章节中进行介绍。在开始之前，让我们通过运行以下命令来验证 Docker 安装：

```
$ docker version

```

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00279.jpeg)

这将提供 Docker 客户端和服务器版本，以及其他详细信息。

我正在使用 Fedora 20/21 作为运行配方的主要环境。它们也应该适用于其他环境。

# 列出/搜索镜像

我们需要一个镜像来启动容器。让我们看看如何在 Docker 注册表上搜索镜像。正如我们在第一章中所看到的，*介绍和安装*，注册表保存 Docker 镜像，它可以是公共的也可以是私有的。默认情况下，搜索将在默认的公共注册表 Docker Hub 上进行，它位于 [`hub.docker.com/`](https://hub.docker.com/)。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  要在 Docker 注册表上搜索镜像，请运行以下命令：

```
docker search TERM

```

以下是搜索 Fedora 镜像的示例：

```
$ docker search fedora |  head -n5

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00280.jpeg)

前面的屏幕截图列出了图像的名称，描述和获得的星星数量。它还指出图像是否是官方和自动化的。`STARS`表示有多少人喜欢给定的图像。`OFFICIAL`列帮助我们确定图像是否是从可信任的来源构建的。`AUTOMATED`列是一种告诉我们图像是否是在 GitHub 或 Bitbucket 存储库中自动构建的方法。有关`AUTOMATED`的更多详细信息可以在下一章中找到。

### 提示

图像名称的约定是`<user>/<name>`，但它可以是任何东西。

## 它是如何工作的...

Docker 在 Docker 公共注册表上搜索镜像，该注册表在[`registry.hub.docker.com/`](https://registry.hub.docker.com/)上有一个镜像仓库。

我们也可以配置我们的私有索引，它可以进行搜索。

## 还有更多...

+   要列出获得超过 20 颗星并且是自动化的图像，请运行以下命令：

```
$ docker search -s 20 --automated fedora

```

![还有更多...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00281.jpeg)

在第三章中，*使用 Docker 镜像*，我们将看到如何设置自动构建。

+   从 Docker 1.3 开始，提供了`--insecure-registry`选项给 Docker 守护程序，允许我们从不安全的注册表中搜索/拉取/提交图像。有关更多详细信息，请查看[`docs.docker.com/reference/commandline/cli/#insecure-registries`](https://docs.docker.com/reference/commandline/cli/#insecure-registries)。

+   RHEL 7 和 Fedora 上的 Docker 软件包提供了`--add-registry`和`--block-registry`选项，分别用于添加和阻止注册表，以更好地控制图像搜索路径。有关更多详细信息，请查看以下链接：

+   [`rhelblog.redhat.com/2015/04/15/understanding-the-changes-to-docker-search-and-docker-pull-in-red-hat-enterprise-linux-7-1/`](http://rhelblog.redhat.com/2015/04/15/understanding-the-changes-to-docker-search-and-docker-pull-in-red-hat-enterprise-linux-7-1/)

+   [`github.com/docker/docker/pull/10411`](https://github.com/docker/docker/pull/10411)

## 另请参阅

+   要获取 Docker 搜索的帮助，请运行以下命令：

```
$ docker search --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#search`](https://docs.docker.com/reference/commandline/cli/#search)

# 拉取图像

搜索图像后，我们可以通过运行 Docker 守护程序将其拉取到系统中。让我们看看我们可以如何做到这一点。

## 准备工作

确保 Docker 守护程序在主机上运行，并且可以通过 Docker 客户端进行连接。

## 如何做...

1.  要在 Docker 注册表上拉取图像，请运行以下命令：

```
docker pull NAME[:TAG]

```

以下是拉取 Fedora 图像的示例：

```
$ docker pull fedora

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00282.jpeg)

## 它是如何工作的...

`pull`命令从 Docker 注册表下载所有层，这些层是在本地创建该图像所需的。我们将在下一章中看到有关层的详细信息。

## 还有更多...

+   图像标签将相同类型的图像分组。例如，CentOS 可以具有标签如`centos5`，`centos6`等的图像。例如，要拉取具有特定标签的图像，请运行以下命令：

```
$ docker pull centos:centos7

```

+   默认情况下，将拉取具有最新标签的图像。要拉取所有对应于所有标签的图像，请使用以下命令：

```
$ docker pull --all-tags centos

```

+   使用 Docker 1.6（[`blog.docker.com/2015/04/docker-release-1-6/`](https://blog.docker.com/2015/04/docker-release-1-6/)），我们可以通过称为“摘要”的新内容可寻址标识符构建和引用图像。当我们想要使用特定图像而不是标签时，这是一个非常有用的功能。要拉取具有特定摘要的图像，可以考虑以下语法：

```
$ docker pull  <image>@sha256:<digest>

```

以下是一个命令的示例：

```
$ docker pull debian@sha256:cbbf2f9a99b47fc460d422812b6a5adff7dfee951d8fa2e4a98caa0382cfbdbf

```

仅支持 Docker 注册表 v2 的摘要。

+   一旦图像被拉取，它将驻留在本地缓存（存储）中，因此后续的拉取将非常快。这个功能在构建 Docker 分层图像中扮演着非常重要的角色。

## 另请参阅

+   查看 Docker `pull`的`help`选项：

```
$ docker pull --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#pull`](https://docs.docker.com/reference/commandline/cli/#pull)

# 列出图像

我们可以列出运行 Docker 守护程序的系统上可用的图像。这些图像可能已经从注册表中拉取，通过`docker`命令导入，或者通过 Docker 文件创建。

## 准备工作

确保 Docker 守护程序在主机上运行，并且可以通过 Docker 客户端进行连接。

## 如何做...

1.  运行以下命令列出图像：

```
$ docker images

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00283.jpeg)

## 它是如何工作的...

Docker 客户端与 Docker 服务器通信，并获取服务器端的图像列表。

## 还有更多...

+   所有具有相同名称但不同标签的图像都会被下载。这里值得注意的有趣之处是它们具有相同的名称但不同的标签。此外，对于相同的`IMAGE ID`，有两个不同的标签，即`2d24f826cb16`。

+   您可能会看到与最新的 Docker 软件包不同的`REPOSITORY`输出，如下面的屏幕截图所示。![更多内容…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00284.jpeg)

这是因为镜像列表打印了 Docker 注册表主机名。如前面的屏幕截图所示，`docker.io`是注册表主机名。

## 另请参阅

+   查看`docker images`的`help`选项：

```
$ docker images --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#images`](https://docs.docker.com/reference/commandline/cli/#images)

# 启动容器

一旦我们有了镜像，就可以使用它们来启动容器。在这个示例中，我们将使用`fedora:latest`镜像启动一个容器，并查看幕后发生的所有事情。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  启动容器的语法如下：

```
docker run [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

以下是一个命令的示例：

```
$ docker run -i -t --name=f21 fedora /bin/bash

```

默认情况下，Docker 会选择带有最新标签的镜像：

+   `-i`选项以交互模式启动容器

+   使用`-t`选项分配一个`伪终端`并将其附加到标准输入

因此，通过上述命令，我们从`fedora:latest`镜像启动一个容器，附加`伪终端`，将其命名为`f21`，并运行`/bin/bash`命令。如果未指定名称，则将分配一个随机字符串作为名称。

此外，如果镜像在本地不可用，则会首先从注册表中下载，然后运行。在运行`run`命令之前，Docker 将运行`search`和`pull`命令。

## 工作原理…

在幕后，Docker：

+   将使用 UnionFS 合并构成该镜像的所有层。

+   为容器分配一个唯一的 ID，称为容器 ID。

+   为容器分配一个文件系统并挂载一个读/写层。对该层的任何更改都将是临时的，如果它们没有被提交，就会被丢弃。

+   分配一个网络/桥接口。

+   为容器分配一个 IP 地址。

+   执行用户指定的进程。

此外，默认情况下，Docker 会在`/var/lib/docker/containers`目录中创建一个包含容器 ID 的目录，其中包含容器的特定信息，如主机名、配置详细信息、日志和`/etc/hosts`。

## 更多内容…

+   要退出容器，请按*Ctrl* + *D*或输入`exit`。这类似于从 shell 中退出，但这将停止容器。

+   `run`命令创建并启动容器。使用 Docker 1.3 或更高版本，可以使用`create`命令只创建容器，然后使用`start`命令稍后运行它，如下例所示：

```
$ ID=$(docker create -t -i fedora bash)
$ docker start -a -i $ID

```

+   容器可以在后台启动，然后我们可以在需要时附加到它。我们需要使用`-d`选项在后台启动容器：

```
$ docker run -d -i -t fedora /bin/bash
0df95cc49e258b74be713c31d5a28b9d590906ed9d6e1a2dc756 72aa48f28c4f

```

前面的命令返回容器的容器 ID，稍后我们可以附加到该容器，如下所示：

```
$ ID='docker run -d -t -i fedora /bin/bash'
$ docker attach $ID

```

在前面的情况下，我们选择了`/bin/bash`在容器内运行。如果我们附加到容器，我们将获得一个交互式 shell。我们可以运行一个非交互式进程，并将其在后台运行，以创建一个守护进程容器，如下所示：

```
$ docker run -d  fedora /bin/bash -c  "while [ 1 ]; do echo hello docker ; sleep 1; done"

```

+   要在退出后删除容器，请使用`--rm`选项启动容器，如下所示：

```
$ docker run --rm fedora date

```

一旦`date`命令退出，容器将被删除。

+   `run`命令的`--read-only`选项将以`只读`模式挂载根文件系统：

```
$ docker run --read-only -d -i -t fedora /bin/bash

```

请记住，此选项只是确保我们不能修改根文件系统上的任何内容，但我们正在写入卷，这将在本书的后面部分进行介绍。当我们不希望用户意外地在容器内写入内容时，此选项非常有用，如果容器没有提交或复制到非临时存储（如卷）上，这些内容将会丢失。

+   您还可以为容器设置自定义标签，这些标签可以用于根据标签对容器进行分组。有关更多详细信息，请参阅本章中的*标记和过滤容器*配方。

### 提示

容器可以通过三种方式引用：按名称，按容器 ID（0df95cc49e258b74be713c31d5a28b9d590906ed9d6e1a2dc75672 aa48f28c4f）和按短容器 ID（0df95cc49e25）

## 另请参阅

+   查看`docker run`的`help`选项：

```
$ docker run --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#run`](https://docs.docker.com/reference/commandline/cli/#run)

+   Docker 1.3 发布公告[`blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/`](http://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/)

# 列出容器

我们可以列出正在运行和停止的容器。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您还需要一些正在运行和/或已停止的容器。

## 如何做…

1.  要列出容器，请运行以下命令：

```
docker ps [ OPTIONS ]

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00285.jpeg)

## 它是如何工作的…

Docker 守护程序可以查看与容器关联的元数据并将其列出。默认情况下，该命令返回：

+   容器 ID

+   创建它的镜像

+   在启动容器后运行的命令

+   有关创建时间的详细信息

+   当前状态

+   从容器中公开的端口

+   容器的名称

## 还有更多…

+   要列出运行和停止的容器，请使用`-a`选项，如下所示：![还有更多…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00286.jpeg)

+   要仅返回所有容器的容器 ID，请使用`-aq`选项，如下所示：![还有更多…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00287.jpeg)

+   要显示最后创建的容器，包括非运行容器，请运行以下命令：

```
$ docker ps -l

```

+   使用`--filter/-f`选项对`ps`进行标记，我们可以列出具有特定标签的容器。有关更多详细信息，请参阅本章中的*标记和过滤容器*示例。

## 另请参阅

查看`docker ps`的`man`页面以查看更多选项：

+   查看`docker ps`的`help`选项：

```
$ docker ps --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#ps`](https://docs.docker.com/reference/commandline/cli/#ps)

# 查看容器的日志

如果容器在`STDOUT`/`STDERR`上发出日志或输出，则可以在不登录到容器的情况下获取它们。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您还需要一个正在运行的容器，该容器会在`STDOUT`上发出日志/输出。

## 如何做…

1.  要从容器中获取日志，请运行以下命令：

```
docker logs [-f|--follow[=false]][-t|--timestamps[=false]] CONTAINER

```

1.  让我们以前面部分的示例为例，运行一个守护式容器并查看日志：

```
$ docker run -d  fedora /bin/bash -c  "while [ 1 ]; do echo hello docker ; sleep 1; done"

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00288.jpeg)

## 它是如何工作的…

Docker 将查看来自`/var/lib/docker/containers/<Container ID>`的容器特定日志文件并显示结果。

## 还有更多…

使用`-t`选项，我们可以在每个日志行中获取时间戳，并使用`-f`可以获得类似 tailf 的行为。

## 另请参阅

+   查看`docker logs`的`help`选项：

```
$ docker logs --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#logs`](https://docs.docker.com/reference/commandline/cli/#logs)

# 停止一个容器

我们可以一次停止一个或多个容器。在这个示例中，我们将首先启动一个容器，然后停止它。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您还需要一个或多个正在运行的容器。

## 如何做…

1.  要停止容器，请运行以下命令：

```
docker stop [-t|--time[=10]] CONTAINER [CONTAINER...]

```

1.  如果您已经有一个正在运行的容器，那么您可以继续停止它；如果没有，我们可以创建一个然后停止它，如下所示：

```
$ ID='docker run -d -i fedora /bin/bash'
$ docker stop $ID

```

## 它是如何工作的…

这将保存容器的状态并停止它。如果需要，可以重新启动。

## 还有更多…

+   要在等待一段时间后停止容器，请使用`--time/-t`选项。

+   要停止所有正在运行的容器，请运行以下命令：

```
$ docker stop 'docker ps -q'

```

## 另请参阅

+   查看`docker stop`的`help`选项：

```
$ docker stop --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#stop`](https://docs.docker.com/reference/commandline/cli/#stop)

# 删除容器

我们可以永久删除一个容器，但在此之前我们必须停止容器或使用强制选项。在这个示例中，我们将启动、停止和删除一个容器。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您还需要一些处于停止或运行状态的容器来删除它们。

## 如何做…

1.  使用以下命令：

```
$ docker rm [ OPTIONS ] CONTAINER [ CONTAINER ]

```

1.  让我们首先启动一个容器，然后停止它，然后使用以下命令删除它：

```
$ ID='docker run -d -i fedora /bin/bash '
$ docker stop $ID
$ docker rm $ID

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00289.jpeg)

正如我们从前面的屏幕截图中可以看到的，容器没有显示出来，这是在停止后输入`docker ps`命令后。我们必须提供`-a`选项来列出它。容器停止后，我们可以删除它。

## 还有更多…

+   强制删除容器而不进行中间停止，请使用`-f`选项。

+   要删除所有容器，我们首先需要停止所有正在运行的容器，然后再删除它们。在运行命令之前要小心，因为这些命令将删除正在运行和停止的容器：

```
$ docker stop 'docker ps -q'
$ docker rm 'docker ps -aq'

```

+   有选项可以删除与容器相关的指定链接和卷，我们将在后面探讨。

## 它是如何工作的…

Docker 守护程序将删除在启动容器时创建的读/写层。

## 另请参阅

+   查看`docker rm`的`help`选项

```
$ docker rm --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#rm`](https://docs.docker.com/reference/commandline/cli/#rm)

# 在容器上设置重启策略

在 Docker 1.2 之前，曾经有一个重新启动容器的选项。随着 Docker 1.2 的发布，它已经添加到了`run`命令中，并使用标志来指定重新启动策略。通过这个策略，我们可以配置容器在启动时启动。当容器意外死掉时，这个选项也非常有用。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 操作步骤…

您可以使用以下语法设置重新启动策略：

```
$ docker run --restart=POLICY [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

以下是一个命令的示例：

```
$ docker run --restart=always -d -i -t fedora /bin/bash

```

有三种重新启动策略可供选择：

+   `no`: 如果容器死掉，它不会重新启动

+   `on-failure`: 如果容器以非零退出代码失败，则重新启动容器

+   `always`: 这总是重新启动容器，不用担心返回代码

## 还有更多…

您还可以使用`on-failure`策略给出可选的重新启动计数，如下所示：

```
$ docker run --restart=on-failure:3 -d -i -t fedora /bin/bash

```

前面的命令只会在发生故障时重新启动容器三次。

## 另请参阅

+   查看`docker run`的`help`选项：

```
$ docker run --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#run`](https://docs.docker.com/reference/commandline/cli/#run)。

+   如果重新启动不符合您的要求，那么可以使用`systemd` ([`freedesktop.org/wiki/Software/systemd/`](http://freedesktop.org/wiki/Software/systemd/)) 来解决容器在失败时自动重新启动的问题。有关更多信息，请访问[`docs.docker.com/articles/host_integration/`](https://docs.docker.com/articles/host_integration/)。

# 在容器内获取特权访问

Linux 将传统上与超级用户关联的特权分为不同的单元，称为功能（在基于 Linux 的系统上运行`man capabilities`），可以独立启用和禁用。例如，`net_bind_service`功能允许非用户进程绑定到 1,024 以下的端口。默认情况下，Docker 以有限的功能启动容器。通过在容器内获取特权访问，我们可以赋予更多的功能来执行通常由 root 完成的操作。例如，让我们尝试在挂载磁盘映像时创建一个回环设备。

![在容器内获取特权访问](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00290.jpeg)

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 操作步骤…

1.  要使用`privileged`模式，请使用以下命令：

```
$ docker run --privileged [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

1.  现在让我们尝试使用特权访问的前面的示例：

```
$ docker run  --privileged  -i -t fedora /bin/bash

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00291.jpeg)

## 它是如何工作的…

通过在容器内提供几乎所有功能。

## 还有更多…

这种模式会带来安全风险，因为容器可以在 Docker 主机上获得根级访问权限。使用 Docker 1.2 或更高版本，添加了两个新标志`--cap-add`和`--cap-del`，以在容器内提供细粒度的控制。例如，要防止容器内的任何`chown`，请使用以下命令：

```
$ docker run --cap-drop=CHOWN [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

查看第九章，“Docker 安全性”，了解更多详情。

## 另请参阅

+   查看`docker run`的`help`选项：

```
$ docker run --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#run`](https://docs.docker.com/reference/commandline/cli/#run)

+   Docker 1.2 发布公告[`blog.docker.com/2014/08/announcing-docker-1-2-0/`](http://blog.docker.com/2014/08/announcing-docker-1-2-0/)

# 在启动容器时暴露端口

有多种方法可以暴露容器上的端口。其中一种是通过`run`命令，我们将在本章中介绍。其他方法是通过 Docker 文件和`--link`命令。我们将在其他章节中探讨它们。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  暴露端口的语法如下：

```
$ docker run --expose=PORT [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

例如，要在启动容器时暴露端口 22，请运行以下命令：

```
$ docker run --expose=22 -i -t fedora /bin/bash

```

## 还有更多…

有多种方法可以为容器暴露端口。现在，我们将看到如何在启动容器时暴露端口。我们将在后续章节中探讨其他暴露端口的选项。

## 另请参阅

+   查看`docker run`的`help`选项：

```
$ docker run --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#run`](https://docs.docker.com/reference/commandline/cli/#run)

# 在容器内访问主机设备

从 Docker 1.2 开始，我们可以使用`--device`选项将主机设备的访问权限提供给容器的`run`命令。以前，必须使用`-v`选项进行绑定挂载，并且必须使用`--privileged`选项进行操作。

## 准备就绪

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您还需要一个设备传递给容器。

## 如何做…

1.  您可以使用以下语法将主机设备的访问权限提供给容器：

```
$ docker run --device=<Host Device>:<Container Device Mapping>:<Permissions>   [ OPTIONS ]  IMAGE[:TAG]  [COMMAND]  [ARG...]

```

这是一个命令的例子：

```
$ docker run --device=/dev/sdc:/dev/xvdc -i -t fedora /bin/bash

```

## 它是如何工作的…

上述命令将访问容器内的`/dev/sdc`。

## 另请参阅

+   查看`docker run`的`help`选项：

```
 $ docker run --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#run`](https://docs.docker.com/reference/commandline/cli/#run)

# 向正在运行的容器注入新进程

在开发和调试过程中，我们可能想要查看已经运行的容器内部。有一些实用程序，比如`nsenter`([`github.com/jpetazzo/nsenter`](https://github.com/jpetazzo/nsenter))，允许我们进入容器的命名空间进行检查。使用在 Docker 1.3 中添加的`exec`选项，我们可以在运行的容器内注入新进程。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。您可能还需要一个正在运行的容器来注入进程。

## 如何做…

1.  您可以使用以下命令在运行的容器中注入进程：

```
 $ docker exec [-d|--detach[=false]] [--help] [-i|--interactive[=false]] [-t|--tty[=false]] CONTAINER COMMAND [ARG...]

```

1.  让我们启动一个`nginx`容器，然后注入`bash`进去：

```
$ ID='docker run -d nginx'
$ docker run -it $ID bash

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00292.jpeg)

## 工作原理…

`exec`命令进入容器的命名空间并启动新进程。

## 另请参阅

+   查看 Docker inspect 的`help`选项：

```
 $ docker exec --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#exec`](https://docs.docker.com/reference/commandline/cli/#exec)

# 返回有关容器的低级信息

在进行调试、自动化等操作时，我们将需要容器配置详细信息。Docker 提供了`inspect`命令来轻松获取这些信息。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  要检查容器/镜像，请运行以下命令：

```
$ docker inspect [-f|--format="" CONTAINER|IMAGE [CONTAINER|IMAGE...]

```

1.  我们将启动一个容器，然后对其进行检查：

```
$ ID='docker run -d -i fedora /bin/bash'
$ docker inspect $ID
[{
 "Args": [],
 "Config": {
 "AttachStderr": false,
 "AttachStdin": false,
 "AttachStdout": false,
 "Cmd": [
 "/bin/bash"
 ],
 .........
 .........
}]

```

## 工作原理…

Docker 将查看给定镜像或容器的元数据和配置，并呈现出来。

## 还有更多…

使用`-f | --format`选项，我们可以使用 Go（编程语言）模板来获取特定信息。以下命令将给出容器的 IP 地址：

```
$ docker inspect --format='{{.NetworkSettings.IPAddress}}'  $ID
172.17.0.2

```

## 另请参阅

+   查看`docker inspect`的`help`选项：

```
 $ docker inspect --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#inspect`](https://docs.docker.com/reference/commandline/cli/#inspect)

# 标记和过滤容器

使用 Docker 1.6，已添加了一个功能来标记容器和镜像，通过这个功能，我们可以向它们附加任意的键值元数据。您可以将它们视为环境变量，这些变量对于容器内运行的应用程序不可用，但对于管理镜像和容器的程序（Docker CLI）是可用的。附加到镜像的标签也会应用到通过它们启动的容器。我们还可以在启动容器时附加标签。

Docker 还为容器、镜像和事件提供了过滤器（[`docs.docker.com/reference/commandline/cli/#filtering`](https://docs.docker.com/reference/commandline/cli/#filtering)），我们可以与标签一起使用，以缩小搜索范围。

对于这个示例，让我们假设我们有一个带有标签 `distro=fedora21` 的镜像。在下一章中，我们将看到如何为镜像分配标签。

![标记和过滤容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00293.jpeg)

从上面的截图中可以看到，如果我们在 `docker images` 命令中使用过滤器，我们只会得到一个在镜像元数据中找到相应标签的镜像。

## 准备工作

确保主机上运行着 Docker 守护程序 1.6 及以上版本，并且您可以通过 Docker 客户端进行连接。

## 操作步骤如下…

1.  要使用 `--label/-l` 选项启动容器，请运行以下命令：

```
$ docker run --label environment=dev f21 date

```

1.  让我们启动一个没有标签的容器，并使用相同的标签启动另外两个：![操作步骤如下…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00294.jpeg)

如果我们列出所有没有标签的容器，我们将看到所有的容器，但如果我们使用标签，那么我们只会得到与标签匹配的容器。

![操作步骤如下…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00295.jpeg)

## 工作原理…

Docker 在启动容器时附加标签元数据，并在列出它们或其他相关操作时匹配标签。

## 更多信息…

+   我们可以通过 `inspect` 命令列出附加到容器的所有标签，这是我们在之前的示例中看到的。正如我们所看到的，`inspect` 命令返回了镜像和容器的标签。![更多信息…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00296.jpeg)

+   您可以从文件（使用 `--from-file` 选项）中应用标签，该文件包含以新的 EOL 分隔的标签列表。

+   这些标签与 Kubernetes 标签不同，我们将在第八章中看到，*Docker Orchestration and Hosting Platforms*。

## 另请参阅

+   Docker 官网上的文档[`docs.docker.com/reference/builder/#label`](https://docs.docker.com/reference/builder/#label)

+   [`rancher.com/docker-labels/`](http://rancher.com/docker-labels/)


# 第三章：使用 Docker 镜像

在本章中，我们将涵盖以下配方：

+   在 Docker Hub 上创建一个帐户

+   从容器创建一个镜像

+   将镜像发布到注册表

+   查看镜像的历史

+   删除镜像

+   导出镜像

+   导入镜像

+   使用 Dockerfile 构建镜像

+   构建 Apache 镜像 - 一个 Dockerfile 示例

+   从容器中访问 Firefox - 一个 Dockerfile 示例

+   构建 WordPress 镜像 - 一个 Dockerfile 示例

+   设置私有索引/注册表

+   自动化构建 - 使用 GitHub 和 Bitbucket

+   创建基础镜像 - 使用 supermin

+   创建基础镜像 - 使用 Debootstrap

+   可视化层之间的依赖关系

# 介绍

在本章中，我们将专注于与镜像相关的操作。正如我们所知，运行容器需要镜像。您可以使用现有的镜像或创建新的自定义镜像。您需要创建自定义镜像以适应您的开发和部署环境。创建镜像后，您可以通过公共或私有注册表共享它。在我们更多地探索 Docker 镜像之前，让我们看一下`docker info`命令的输出：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00297.jpeg)

前面的命令给出了当前系统范围的信息如下：

+   它有 21 个容器和 21 个镜像。

+   当前的存储驱动程序，`devicemapper`，以及与之相关的信息，如 thin pool 名称，数据，元数据文件等。其他类型的存储驱动程序包括 aufs，btrfs，overlayfs，vfs 等。Devicemapper，btrfs 和 overlayfs 在 Linux 内核中有原生支持。AUFS 支持需要一个经过修补的内核。我们在第一章中讨论了 Union 文件系统，*介绍和安装*。

+   为了利用启用容器化的内核特性，Docker 守护程序必须与 Linux 内核通信。这是通过执行驱动程序完成的。`libconatiner`或`native`是其中之一。其他的有`libvirt`，`lxc`等，我们在第一章中看到了，*介绍和安装*。

+   主机操作系统上的内核版本。

+   在下一节提到的注册表上注册的用户帐户以拉取/推送镜像。

### 注意

我正在使用 Fedora 20/21 作为运行配方的主要环境。它们也应该适用于其他环境。

# 在 Docker Hub 上创建一个帐户

Docker Hub 就像图像的 GitHub。它是一个公共注册表，您可以在其中托管图像，包括公共和私有图像，并与他人合作。它与 GitHub、Bitbucket 集成，并可以触发自动构建。

目前，在 Docker Hub 上创建帐户是免费的。一个仓库可以容纳图像的不同版本。您可以为您的图像创建任意数量的公共仓库。默认情况下，您将拥有一个私有仓库，该仓库对公众不可见。您可以购买更多的私有仓库。您可以通过 Web 浏览器或命令行创建帐户。

## 准备工作

要从命令行注册，您需要在系统上安装 Docker。

## 如何做...

1.  要通过 Docker Hub 的 Web 浏览器创建帐户，请访问[`hub.docker.com/account/signup/`](https://hub.docker.com/account/signup/)并创建一个帐户：![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00298.jpeg)

1.  要使用命令行创建一个帐户，请运行以下命令并提交所需的详细信息：

```
$ docker login

```

## 它是如何工作的...

上述步骤将为您创建一个 Docker Hub 帐户。帐户创建后，您将收到一封确认邮件，通过该邮件您需要确认您的身份。

## 另请参阅

+   Docker 网站上的文档：

+   [`docs.docker.com/docker-hub`](https://docs.docker.com/docker-hub)

+   [`docs.docker.com/docker-hub/accounts/`](https://docs.docker.com/docker-hub/accounts/)

# 从容器创建镜像

有几种创建镜像的方法，一种是手动提交层，另一种是通过 Dockerfile。在这个教程中，我们将看到前者，稍后在本章中再看 Dockerfile。

当我们启动一个新的容器时，会附加一个读/写层。如果我们不保存这个层，它将被销毁。在这个教程中，我们将看到如何保存这个层，并使用`docker commit`命令从正在运行或停止的容器中创建一个新的镜像。

## 准备工作

要获取 Docker 镜像，请使用它启动一个容器。

## 如何做...

1.  要进行提交，请运行以下命令：

```
docker commit -a|--author[=""] -m|--message[=""] CONTAINER [REPOSITORY[:TAG]]

```

1.  让我们启动一个容器并使用`install httpd`包创建/修改一些文件：![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00299.jpeg)

1.  然后，打开一个新的终端并通过提交创建一个新的镜像：

```
$ docker commit -a "Neependra Khare" -m "Fedora with HTTPD package" 0a15686588ef nkhare/fedora:httpd

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00300.jpeg)

如您所见，新的镜像现在正在使用`nkhare/fedora`作为名称和`httpd`作为标签提交到本地仓库。

## 它是如何工作的...

在第一章*介绍和安装*中，我们看到在启动容器时，将在容器启动的现有镜像层之上创建一个读/写文件系统层，并且通过安装软件包，一些文件将被添加/修改到该层中。所有这些更改目前都在临时的读/写文件系统层中，该层分配给容器。如果我们停止并删除容器，那么所有先前提到的修改将丢失。

使用 commit，我们创建一个新的层，其中包含自容器启动以来发生的更改，这些更改保存在后端存储驱动程序中。

## 还有更多…

+   查找自容器启动以来已更改的文件：

```
$ docker diff CONTAINER

```

在我们的情况下，我们将看到类似以下代码的内容：

```
$ docker diff 0a15686588ef
.....
C /var/log
A /var/log/httpd
C /var/log/lastlog
.....

```

我们可以在输出的每个条目之前看到一个前缀。以下是这些前缀的列表：

+   `A`: 当文件/目录被添加时

+   `C`: 当文件/目录被修改时

+   `D`: 当文件/目录被删除时

+   默认情况下，在执行提交时容器会被暂停。您可以通过传递`--pause=false`来更改其行为。

## 另请参阅

+   查看`docker commit`的`help`选项：

```
$ docker commit --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#commit`](https://docs.docker.com/reference/commandline/cli/#commit)

# 将镜像发布到注册表

假设您已经创建了一个适合组织开发环境的镜像。您可以使用 tar ball 进行共享，我们将在本章后面看到，或者将其放在用户可以拉取的中央位置。这个中央位置可以是公共的或私有的注册表。在本教程中，我们将看到如何使用`docker push`命令将镜像推送到注册表。在本章后面，我们将介绍如何设置私有注册表。

## 准备工作

您需要在 Docker Hub 上拥有有效的帐户才能推送镜像/仓库。

如果您要推送本地镜像/仓库，必须设置本地注册表。

## 如何做…

```
$ docker push NAME[:TAG]

```

默认情况下，前面的命令将使用`docker info`命令中显示的用户名和注册表来推送镜像。如前面的屏幕截图所示，该命令将使用`nkhare`作为用户名，`https://index.docker.io/v1/`作为注册表。

要推送在上一节中创建的图像，请运行以下命令：

```
$ docker push nkhare/fedora:httpd

```

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00301.jpeg)

假设您想要将图像推送到本地注册表，该注册表托管在名为`local-registry`的主机上。为此，您首先需要使用注册表主机的名称或 IP 地址以及注册表正在运行的端口号对图像进行标记，然后推送图像。

```
$ docker tag [-f|--force[=false] IMAGE [REGISTRYHOST/][USERNAME/]NAME[:TAG]
$ docker push [REGISTRYHOST/][USERNAME/]NAME[:TAG]

```

例如，假设我们的注册表配置在`shadowfax.example.com`上，然后使用以下命令标记图像：

```
$ docker tag nkhare/fedora:httpd shadowfax.example.com:5000/nkhare/fedora:httpd

```

然后，要推送图像，请使用以下命令：

```
$ docker push shadowfax.example.com:5000/nkhare/fedora:httpd

```

## 它是如何工作的...

它将首先列出制作特定图像所需的所有中间层。然后，它将检查这些层中有多少已经存在于注册表中。最后，它将复制所有不在注册表中的层，并附上构建图像所需的元数据。

## 更多内容...

当我们将图像推送到公共注册表时，我们可以登录 Docker Hub 并查找图像：

![更多内容...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00302.jpeg)

## 另请参阅

+   查看`docker push`的`help`选项：

```
$ docker push --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#push`](https://docs.docker.com/reference/commandline/cli/#push)

# 查看图像的历史记录

了解我们正在使用的图像是如何创建的很方便。`docker history`命令帮助我们找到所有中间层。

## 准备工作

拉取或导入任何 Docker 图像。

## 如何操作...

1.  要查看图像的历史记录，请考虑以下语法：

```
$ docker history [ OPTIONS ] IMAGE

```

以下是使用上述语法的示例：

```
$ docker history nkhare/fedora:httpd

```

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00303.jpeg)

## 它是如何工作的...

通过图像的元数据，Docker 可以知道图像是如何创建的。使用`history`命令，它将递归查看元数据以找到原始来源。

## 更多内容...

查看已提交层的提交消息：

```
$ docker inspect --format='{{.Comment}}' nkhare/fedora:httpd
Fedora with HTTPD package

```

目前，没有直接的方法可以使用一个命令查看每个层的提交消息，但是我们可以使用`inspect`命令，我们之前看到的，对每个层进行查看。

## 另请参阅

+   查看`docker history`的`help`选项：

```
$ docker history --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#history`](https://docs.docker.com/reference/commandline/cli/#history)

# 删除图像

要从主机中删除图像，我们可以使用`docker rmi`命令。但是，这不会从注册表中删除图像。

## 准备工作

确保一个或多个 Docker 图像在本地可用。

## 如何做…

1.  要删除图像，请考虑以下语法：

```
$ docker rmi [ OPTIONS ] IMAGE [IMAGE...]

```

在我们的情况下，以下是使用前述语法的示例：

```
$ docker rmi nkhare/fedora:httpd

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00304.jpeg)

## 还有更多…

如果要删除所有容器和镜像，请执行以下操作；但是，请确保自己知道自己在做什么，因为这是非常具有破坏性的：

+   要停止所有容器，请使用以下命令：

```
$ docker stop 'docker ps -q'

```

+   要删除所有容器，请使用以下命令：

```
$ docker rm 'docker ps -a -q'

```

+   要删除所有图像，请使用以下命令：

```
$ docker rmi 'docker images -q'

```

## 另请参阅

+   查看`docker rmi`的`help`选项：

```
$ docker rmi --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#rmi`](https://docs.docker.com/reference/commandline/cli/#rmi)

# 导出图像

假设您有一个客户，其非常严格的政策不允许他们使用来自公共领域的图像。在这种情况下，您可以通过 tar 文件共享图像，稍后可以在另一个系统上导入。在本示例中，我们将看到如何使用`docker save`命令来做到这一点。

## 准备工作

在 Docker 主机上拉取或导入一个或多个 Docker 图像。

## 如何做…

1.  使用以下语法将图像保存在 tar 文件中：

```
$ docker save [-o|--output=""] IMAGE [:TAG]

```

例如，要为 Fedora 创建一个 tar 归档，请运行以下命令：

```
$ docker save --output=fedora.tar fedora

```

如果指定了标签名称与我们要导出的图像名称，例如`fedora:latest`，那么只有与该标签相关的层将被导出。

## 还有更多…

如果没有使用`--output`或`-o`，输出将被流式传输到`STDOUT`：

```
$ docker save fedora:latest > fedora-latest.tar

```

类似地，可以使用以下命令导出容器文件系统的内容：

```
$ docker export CONTAINER  > containerXYZ.tar

```

## 另请参阅

+   查看`docker save`和`docker export`的`help`选项：

```
$ docker save -help
$ docker export --help

```

+   Docker 网站上的文档：

+   [`docs.docker.com/reference/commandline/cli/#save`](https://docs.docker.com/reference/commandline/cli/#save)

+   [`docs.docker.com/reference/commandline/cli/#export`](https://docs.docker.com/reference/commandline/cli/#export)

# 导入图像

要获得图像的本地副本，我们需要从可访问的注册表中拉取它，或者从已导出的图像中导入它，就像我们在之前的示例中看到的那样。使用`docker import`命令，我们导入一个已导出的图像。

## 准备工作

您需要一个可访问的导出的 Docker 镜像。

## 如何做…

1.  要导入图像，我们可以使用以下语法：

```
$ docker import URL|- [REPOSITORY[:TAG]]

```

以下是使用前述语法的示例：

```
$ cat fedora-latest.tar | docker import - fedora:latest

```

或者，您可以考虑以下示例：

```
$ docker import http://example.com/example.tar example/image

```

前面的示例将首先创建一个空的文件系统，然后导入内容。

## 参见

+   查看`docker import`的`help`选项：

```
$ docker import --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/commandline/cli/#import`](https://docs.docker.com/reference/commandline/cli/#import)

# 使用 Dockerfile 构建映像

Dockerfile 帮助我们自动化映像创建，并在我们每次需要时获得完全相同的映像。Docker 构建器从文本文件（Dockerfile）中读取指令，并按顺序依次执行。它可以与 Vagrant 文件进行比较，Vagrant 文件允许您以可预测的方式配置虚拟机。

## 准备工作

具有构建指令的 Dockerfile。

+   创建一个空目录：

```
$ mkdir sample_image
$ cd sample_image

```

+   创建一个名为`Dockerfile`的文件，内容如下：

```
$ cat Dockerfile
# Pick up the base image
FROM fedora
# Add author name
MAINTAINER Neependra Khare
# Add the command to run at the start of container
CMD date

```

## 操作方法...

1.  在创建 Dockerfile 的目录中运行以下命令来构建映像：

```
$ docker build .

```

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00305.jpeg)

在构建映像时，我们没有指定任何存储库或标签名称。我们可以使用`-t`选项来指定：

```
$ docker build -t fedora/test .

```

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00306.jpeg)

前面的输出与我们之前所做的不同。然而，在这里，我们在每个指令之后都使用缓存。Docker 尝试保存中间映像，就像我们之前看到的那样，并尝试在后续构建中使用它们来加速构建过程。如果你不想缓存中间映像，那么在构建时添加`--no-cache`选项。现在让我们来看一下可用的映像：

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00307.jpeg)

## 它是如何工作的...

上下文定义了用于构建 Docker 映像的文件。在前面的命令中，我们将上下文定义为构建。构建由 Docker 守护程序完成，并且整个上下文被传输到守护程序。这就是为什么我们看到`Sending build context to Docker daemon 2.048 kB`消息。如果当前工作目录中有一个名为`.dockerignore`的文件，其中包含文件和目录的列表（以换行符分隔），那么这些文件和目录将被构建上下文忽略。有关`.dockerignore`的更多详细信息，请参阅[`docs.docker.com/reference/builder/#the-dockerignore-file`](https://docs.docker.com/reference/builder/#the-dockerignore-file)。

执行每个指令后，Docker 会提交中间镜像并为下一个指令运行一个容器。在下一个指令运行后，Docker 将再次提交容器以创建中间镜像，并删除在上一步中创建的中间容器。

例如，在上面的屏幕截图中，`eb9f10384509`是一个中间镜像，`c5d4dd2b3db9`和`ffb9303ab124`是中间容器。执行最后一个指令后，将创建最终镜像。在这种情况下，最终镜像是`4778dd1f1a7a`：

![工作原理…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00308.jpeg)

可以在`docker images`命令中使用`-a`选项来查找中间层：

```
$ docker images -a

```

## 还有更多…

Dockerfile 的格式如下：

```
INSTRUCTION arguments

```

通常，指令以大写形式给出，但它们不区分大小写。它们按顺序进行评估。以`#`开头的内容被视为注释。

让我们来看看不同类型的指令：

+   `FROM`：这必须是任何 Dockerfile 的第一个指令，它为后续指令设置了基础镜像。默认情况下，假定为最新标签：

```
FROM  <image>

```

或者，考虑以下标签：

```
FROM  <images>:<tag>

```

一个 Dockerfile 中可以有多个`FROM`指令，以创建多个镜像。

如果只提供镜像名称，例如 Fedora 和 Ubuntu，则将从默认的 Docker 注册表（Docker Hub）下载镜像。如果要使用私有或第三方镜像，则必须按以下方式提及：

```
 [registry_hostname[:port]/]user_name/

```

以下是使用上述语法的示例：

```
FROM registry-host:5000/nkhare/f20:httpd

```

+   `MAINTAINER`：这为生成的镜像设置了作者，`MAINTAINER <name>`。

+   `RUN`：我们可以以两种方式执行`RUN`指令——首先，在 shell 中运行（`sh -c`）：

```
RUN <command> <param1> ... <pamamN>

```

其次，直接运行可执行文件：

```
RUN ["executable", "param1",...,"paramN" ]

```

正如我们所知，使用 Docker，我们创建一个覆盖层——在另一个层之上的一层——以创建最终的镜像。通过每个`RUN`指令，我们创建并提交一个层，放在之前提交的层之上。可以从任何已提交的层启动容器。

默认情况下，Docker 会尝试缓存不同`RUN`指令提交的层，以便在后续构建中使用。但是，可以在构建镜像时使用`--no-cache`标志来关闭此行为。

+   `LABEL`：Docker 1.6 添加了一个新功能，可以将任意键值对附加到 Docker 镜像和容器上。我们在第二章的*标记和过滤容器*中介绍了部分内容，*使用 Docker 容器*。要为图像添加标签，我们在 Dockerfile 中使用`LABEL`指令，如`LABEL distro=fedora21`。

+   `CMD`：`CMD`指令在启动容器时提供默认可执行文件。如果`CMD`指令没有可执行文件（参数 2），那么它将为`ENTRYPOINT`提供参数。

```
CMD  ["executable", "param1",...,"paramN" ]
CMD ["param1", ... , "paramN"]
CMD <command> <param1> ... <pamamN>

```

Dockerfile 中只允许一个`CMD`指令。如果指定了多个指令，则只有最后一个会被采纳。

+   `ENTRYPOINT`：这有助于我们将容器配置为可执行文件。与`CMD`类似，`ENTRYPOINT`最多只能有一条指令；如果指定了多条指令，则只有最后一条会被采纳：

```
ENTRYPOINT  ["executable", "param1",...,"paramN" ]
ENTRYPOINT <command> <param1> ... <pamamN>

```

一旦使用`ENTRYPOINT`指令定义了参数，它们就不能在运行时被覆盖。但是，如果我们想要对`ENTRYPOINT`使用不同的参数，可以将`ENTRYPOINT`用作`CMD`。

+   `EXPOSE`：这将在容器上暴露网络端口，容器将在其中运行时监听：

```
EXPOSE  <port> [<port> ... ]

```

我们还可以在启动容器时暴露端口。我们在第二章的*在启动容器时暴露端口*中介绍了这一点，*使用 Docker 容器*。

+   `ENV`：这将将环境变量`<key>`设置为`<value>`。它将传递所有未来的指令，并在从生成的镜像运行容器时持久存在：

```
ENV <key> <value>

```

+   `ADD`：这将文件从源复制到目的地：

```
ADD <src> <dest>

```

以下是包含空格的路径：

```
ADD ["<src>"... "<dest>"]

```

+   `<src>`：这必须是构建目录中的文件或目录，我们正在从中构建图像，也称为构建的上下文。源也可以是远程 URL。

+   `<dest>`：这必须是容器内的绝对路径，源中的文件/目录将被复制到其中。

+   `COPY`：这类似于`ADD.COPY <src> <dest>`：

```
COPY  ["<src>"... "<dest>"]

```

+   `VOLUME`：此指令将使用以下语法创建具有给定名称的挂载点，并将其标记为使用外部卷进行挂载：

```
VOLUME ["/data"]

```

或者，您可以使用以下代码：

```
VOLUME /data

```

+   `USER`：这将使用以下语法为任何后续的运行指令设置用户名：

```
USER  <username>/<UID>

```

+   `WORKDIR`：这为随后的`RUN`、`CMD`和`ENTRYPOINT`指令设置工作目录。它可以在同一个 Dockerfile 中有多个条目。可以给出相对路径，它将相对于之前的`WORKDIR`指令，使用以下语法：

```
WORKDIR <PATH>

```

+   `ONBUILD`：这将向图像添加触发指令，稍后将在将此图像用作另一个图像的基本图像时执行。此触发器将作为下游 Dockerfile 中的`FROM`指令的一部分运行，使用以下语法：

```
ONBUILD [INSTRUCTION]

```

## 另请参阅

+   查看`docker build`的`help`选项：

```
$ docker build -help

```

+   Docker 网站上的文档[`docs.docker.com/reference/builder/`](https://docs.docker.com/reference/builder/)

# 构建 Apache 镜像 - 一个 Dockerfile 示例

我将在从 Fedora-Dockerfiles GitHub 存储库（[`github.com/fedora-cloud/Fedora-Dockerfiles`](https://github.com/fedora-cloud/Fedora-Dockerfiles)）中引用 Dockerfiles，之后对其进行分叉。如果您使用的是 Fedora，那么您也可以安装`fedora-dockerfiles`软件包，以获取`/usr/share/fedora-dockerfiles`中的示例 Dockerfiles。在每个子目录中，您将放置一个 Dockerfile、支持文件和一个 README 文件。

Fedora-Dockerfiles GitHub 存储库将具有最新的示例，我强烈建议您尝试最新的内容。

## 准备工作

使用以下命令克隆 Fedora-Dockerfiles Git 存储库：

```
$ git clone https://github.com/nkhare/Fedora-Dockerfiles.git

```

现在，转到`apache`子目录：

```
$ cd Fedora-Dockerfiles/apache/
$ cat Dockerfile
FROM fedora:20
MAINTAINER "Scott Collier" <scollier@redhat.com>

RUN yum -y update && yum clean all
RUN yum -y install httpd && yum clean all
RUN echo "Apache" >> /var/www/html/index.html

EXPOSE 80

# Simple startup script to avoid some issues observed with container restart
ADD run-apache.sh /run-apache.sh
RUN chmod -v +x /run-apache.sh

CMD ["/run-apache.sh"]

```

其他支持文件包括：

+   `README.md`：这是 README 文件

+   `run-apache.sh`：这是在前台运行`HTTPD`的脚本

+   `LICENSE`：这是 GPL 许可证

## 如何做...

使用以下`build`命令，我们可以构建一个新的镜像：

```
$ docker build -t fedora/apache .
Sending build context to Docker daemon 23.55 kB
Sending build context to Docker daemon
Step 0 : FROM fedora:20
 ---> 6cece30db4f9
Step 1 : MAINTAINER "Scott Collier" <scollier@redhat.com>
 ---> Running in 2048200e6338
 ---> ae8e3c258061
Removing intermediate container 2048200e6338
Step 2 : RUN yum -y update && yum clean all
 ---> Running in df8bc8ee3117
.... Installing/Update packages ...
Cleaning up everything
 ---> 5a6d449e59f6
Removing intermediate container df8bc8ee3117
Step 3 : RUN yum -y install httpd && yum clean all
 ---> Running in 24449e520f18
.... Installing HTTPD ...
Cleaning up everything
 ---> ae1625544ef6
Removing intermediate container 24449e520f18
Step 4 : RUN echo "Apache" >> /var/www/html/index.html
 ---> Running in a35cbcd8d97a
 ---> 251eea31b3ce
Removing intermediate container a35cbcd8d97a
Step 5 : EXPOSE 80
 ---> Running in 734e54f4bf58
 ---> 19503ae2a8cf
Removing intermediate container 734e54f4bf58
Step 6 : ADD run-apache.sh /run-apache.sh
 ---> de35d746f43b
Removing intermediate container 3eec9a46da64
Step 7 : RUN chmod -v +x /run-apache.sh
 ---> Running in 3664efba393f
mode of '/run-apache.sh' changed from 0644 (rw-r--r--) to 0755 (rwxr-xr-x)
 ---> 1cb729521c3f
Removing intermediate container 3664efba393f
Step 8 : CMD /run-apache.sh
 ---> Running in cd5e7534e815
 ---> 5f8041b6002c
Removing intermediate container cd5e7534e815
Successfully built 5f8041b6002c

```

## 它是如何工作的...

构建过程需要一个基本镜像，安装所需的`HTTPD`软件包并创建一个 HTML 页面。然后，它公开端口`80`以提供网页，并设置指令在容器启动时启动 Apache。

## 更多内容...

让我们从创建的镜像中运行容器，获取其 IP 地址，并从中访问网页：

![更多内容...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00309.jpeg)

## 另请参阅

+   查看`docker build`的`help`选项：

```
$ docker build --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/builder/`](https://docs.docker.com/reference/builder/)

# 从容器访问 Firefox - 一个 Dockerfile 示例

我们可以通过 Dockerfile 做一些更有趣的事情，比如创建一个只运行 Firefox 的容器。这种用例可以帮助在同一台机器上运行不同版本的多个浏览器，这在进行多浏览器测试时非常有帮助。

## 准备工作

使用以下命令克隆 Fedora-Dockerfiles Git 存储库：

```
$ git clone  https://github.com/nkhare/Fedora-Dockerfiles.git

```

然后，转到`firefox`子目录。

```
$ cd Fedora-Dockerfiles/firefox
$ cat Dockerfile
FROM fedora
MAINTAINER scollier <emailscottcollier@gmail.com>

# Install the appropriate software
RUN yum -y update && yum clean all
RUN yum -y install x11vnc \
firefox xorg-x11-server-Xvfb \
xorg-x11-twm tigervnc-server \
xterm xorg-x11-font \
xulrunner-26.0-2.fc20.x86_64 \
dejavu-sans-fonts \
dejavu-serif-fonts \
xdotool && yum clean all

# Add the xstartup file into the image
ADD ./xstartup /

RUN mkdir /.vnc
RUN x11vnc -storepasswd 123456 /.vnc/passwd
RUN  \cp -f ./xstartup /.vnc/.
RUN chmod -v +x /.vnc/xstartup
RUN sed -i '/\/etc\/X11\/xinit\/xinitrc-common/a [ -x /usr/bin/firefox ] && /usr/bin/firefox &' /etc/X11/xinit/xinitrc

EXPOSE 5901

CMD    ["vncserver", "-fg" ]
# ENTRYPOINT ["vncserver", "-fg" ]

```

支持文件：

+   `README.md`：这是一个 README 文件

+   `LICENSE`：这是 GPL 许可证

+   `xstartup`：这是设置 X11 环境的脚本

## 如何做...

运行以下命令构建镜像：

```
$ docker build  -t fedora/firefox .
Sending build context to Docker daemon 24.58 kB
Sending build context to Docker daemon
Step 0 : FROM fedora
 ---> 834629358fe2
Step 1 : MAINTAINER scollier <emailscottcollier@gmail.com>
 ---> Running in ae0fd3c2cb2e
 ---> 7ffc6c9af827
Removing intermediate container ae0fd3c2cb2e
Step 2 : RUN yum -y update && yum clean all
 ---> Running in 1c67b8772718
..... Installing/Update packages ...
 ---> 075d6ceef3d0
Removing intermediate container 1c67b8772718
Step 3 : RUN yum -y install x11vnc firefox xorg-x11-server-Xvfb xorg-x11-twm tigervnc-server xterm xorg-x11-font xulrunner-26.0-2.fc20.x86_64 dejavu-sans-fonts dejavu-serif-fonts xdotool && yum clean all
..... Installing required packages packages ...
Cleaning up everything
 ---> 986be48760a6
Removing intermediate container c338a1ad6caf
Step 4 : ADD ./xstartup /
 ---> 24fa081dcea5
Removing intermediate container fe98d86ba67f
Step 5 : RUN mkdir /.vnc
 ---> Running in fdb8fe7e697a
 ---> 18f266ace765
Removing intermediate container fdb8fe7e697a
Step 6 : RUN x11vnc -storepasswd 123456 /.vnc/passwd
 ---> Running in c5b7cdba157f
stored passwd in file: /.vnc/passwd
 ---> e4fcf9b17aa9
Removing intermediate container c5b7cdba157f
Step 7 : RUN \cp -f ./xstartup /.vnc/.
 ---> Running in 21d0dc4edb4e
 ---> 4c53914323cb
Removing intermediate container 21d0dc4edb4e
Step 8 : RUN chmod -v +x /.vnc/xstartup
 ---> Running in 38f18f07c996
mode of '/.vnc/xstartup' changed from 0644 (rw-r--r--) to 0755 (rwxr-xr-x)
 ---> caa278024354
Removing intermediate container 38f18f07c996
Step 9 : RUN sed -i '/\/etc\/X11\/xinit\/xinitrc-common/a [ -x /usr/bin/firefox ] && /usr/bin/firefox &' /etc/X11/xinit/xinitrc
 ---> Running in 233e99cab02c
 ---> 421e944ac8b7
Removing intermediate container 233e99cab02c
Step 10 : EXPOSE 5901
 ---> Running in 530cd361cb3c
 ---> 5de01995c156
Removing intermediate container 530cd361cb3c
Step 11 : CMD vncserver -fg
 ---> Running in db89498ae8ce
 ---> 899be39b7feb
Removing intermediate container db89498ae8ce
Successfully built 899be39b7feb

```

## 它是如何工作的...

我们从基本的 Fedora 镜像开始，安装 X Windows System，Firefox，VNC 服务器和其他软件包。然后设置 VNC 服务器启动 X Windows System，然后启动 Firefox。

## 还有更多...

+   要启动容器，请运行以下命令：

```
$ docker run -it -p 5901:5901 fedora/firefox

```

并输入`123456`作为密码。

+   在运行容器时，我们将主机的`5901`端口映射到容器的`5901`端口。为了连接容器内的 VNC 服务器，只需从另一个终端运行以下命令：

```
$ vncviewer localhost:1

```

或者，从网络中的另一台机器上，用 Docker 主机的 IP 地址或 FQDN 替换`localhost`。

## 另请参阅

+   查看`docker build`的`help`选项：

```
$ docker build --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/builder/`](https://docs.docker.com/reference/builder/)

# 构建 WordPress 镜像-一个 Dockerfile 示例

到目前为止，我们已经看到了在容器中运行一个服务的示例。如果我们想要运行一个需要同时运行一个或多个服务的应用程序，那么我们要么需要在同一个容器上运行它们，要么在不同的容器上运行它们并将它们链接在一起。WordPress 就是一个这样的例子，它需要数据库和 web 服务。

Docker 只喜欢每个容器中运行的前台一个进程。因此，为了让 Docker 满意，我们有一个控制进程来管理数据库和 web 服务。在这种情况下，控制进程是 supervisord（[`supervisord.org/`](http://supervisord.org/)）。这是我们用来让 Docker 满意的一个技巧。

同样，我们将使用 Fedora-Dockerfiles 存储库中的 Dockerfile。

## 准备工作

使用以下命令克隆 Fedora-Dockerfiles Git 存储库：

```
$ git clone  https://github.com/nkhare/Fedora-Dockerfiles.git

```

然后，转到`wordpress_single_container`子目录：

```
$ cd Fedora-Dockerfiles/systemd/wordpress_single_container
$ cat Dockerfile
FROM fedora
MAINTAINER scollier <scollier@redhat.com>
RUN yum -y update && yum clean all
RUN yum -y install httpd php php-mysql php-gd pwgen supervisor bash-completion openssh-server psmisc tar && yum clean all
ADD ./start.sh /start.sh
ADD ./foreground.sh /etc/apache2/foreground.sh
ADD ./supervisord.conf /etc/supervisord.conf
RUN echo %sudo  ALL=NOPASSWD: ALL >> /etc/sudoers
ADD http://wordpress.org/latest.tar.gz /wordpress.tar.gz
RUN tar xvzf /wordpress.tar.gz
RUN mv /wordpress/* /var/www/html/.
RUN chown -R apache:apache /var/www/
RUN chmod 755 /start.sh
RUN chmod 755 /etc/apache2/foreground.sh
RUN mkdir /var/run/sshd
EXPOSE 80
EXPOSE 22
CMD ["/bin/bash", "/start.sh"]

```

前面代码中使用的支持文件解释如下：

+   `foreground.sh`：这是一个在前台运行 HTTPS 的脚本。

+   `LICENSE`、`LICENSE.txt`和`UNLICENSE.txt`：这些文件包含许可信息。

+   `README.md`：这是一个 README 文件。

+   `supervisord.conf`：这是一个结果容器，必须同时运行`SSHD`、`MySQL`和`HTTPD`。在这种特殊情况下，使用 supervisor 来管理它们。这是 supervisor 的配置文件。有关此的更多信息，请访问[`supervisord.org/`](http://supervisord.org/)。

+   `start.sh`：这是一个设置 MySQL、HTTPD 并启动 supervisor 守护进程的脚本。

## 如何做…

```
$ docker build -t fedora/wordpress  .
Sending build context to Docker daemon 41.98 kB
Sending build context to Docker daemon
Step 0 : FROM fedora
 ---> 834629358fe2
Step 1 : MAINTAINER scollier <scollier@redhat.com>
 ---> Using cache
 ---> f21eaf47c9fc
Step 2 : RUN yum -y update && yum clean all
 ---> Using cache
 ---> a8f497a6e57c
Step 3 : RUN yum -y install httpd php php-mysql php-gd pwgen supervisor bash-completion openssh-server psmisc tar && yum clean all
 ---> Running in 303234ebf1e1
.... updating/installing packages ....
Cleaning up everything
 ---> cc19a5f5c4aa
Removing intermediate container 303234ebf1e1
Step 4 : ADD ./start.sh /start.sh
 ---> 3f911077da44
Removing intermediate container c2bd643236ef
Step 5 : ADD ./foreground.sh /etc/apache2/foreground.sh
 ---> 3799902a60c5
Removing intermediate container c99b8e910009
Step 6 : ADD ./supervisord.conf /etc/supervisord.conf
 ---> f232433b8925
Removing intermediate container 0584b945f6f7
Step 7 : RUN echo %sudo  ALL=NOPASSWD: ALL >> /etc/sudoers
 ---> Running in 581db01d7350
 ---> ec686e945dfd
Removing intermediate container 581db01d7350
Step 8 : ADD http://wordpress.org/latest.tar.gz /wordpress.tar.gz
Downloading [==================================================>] 6.186 MB/6.186 MB
 ---> e4e902c389a4
Removing intermediate container 6bfecfbe798d
Step 9 : RUN tar xvzf /wordpress.tar.gz
 ---> Running in cd772500a776
.......... untarring wordpress .........
---> d2c5176228e5
Removing intermediate container cd772500a776
Step 10 : RUN mv /wordpress/* /var/www/html/.
 ---> Running in 7b19abeb509c
 ---> 09400817c55f
Removing intermediate container 7b19abeb509c
Step 11 : RUN chown -R apache:apache /var/www/
 ---> Running in f6b9b6d83b5c
 ---> b35a901735d9
Removing intermediate container f6b9b6d83b5c
Step 12 : RUN chmod 755 /start.sh
 ---> Running in 81718f8d52fa
 ---> 87470a002e12
Removing intermediate container 81718f8d52fa
Step 13 : RUN chmod 755 /etc/apache2/foreground.sh
 ---> Running in 040c09148e1c
 ---> 1c76f1511685
Removing intermediate container 040c09148e1c
Step 14 : RUN mkdir /var/run/sshd
 ---> Running in 77177a33aee0
 ---> f339dd1f3e6b
Removing intermediate container 77177a33aee0
Step 15 : EXPOSE 80
 ---> Running in f27c0b96d17f
 ---> 6078f0d7b70b
Removing intermediate container f27c0b96d17f
Step 16 : EXPOSE 22
 ---> Running in eb7c7d90b860
 ---> 38f36e5c7cab
Removing intermediate container eb7c7d90b860
Step 17 : CMD /bin/bash /start.sh
 ---> Running in 5635fe4783da
 ---> c1a327532355
Removing intermediate container 5635fe4783da
Successfully built c1a327532355

```

## 它是如何工作的…

与其他示例一样，我们从基本镜像开始，安装所需的软件包，并复制支持文件。然后设置`sudo`、`download`和`untar` WordPress 在 HTTPD 文档根目录内。之后，我们暴露端口并运行 start.sh 脚本，该脚本设置 MySQL、WordPress、HTTPS 权限并将控制权交给 supervisord。在`supervisord.conf`中，您将看到 supervisord 管理的以下服务条目：

```
[program:mysqld]
command=/usr/bin/mysqld_safe
[program:httpd]
command=/etc/apache2/foreground.sh
stopsignal=6
[program:sshd]
command=/usr/sbin/sshd -D
stdout_logfile=/var/log/supervisor/%(program_name)s.log
stderr_logfile=/var/log/supervisor/%(program_name)s.log
autorestart=true

```

## 还有更多…

+   启动容器，获取其 IP 地址并通过 Web 浏览器打开。在进行语言选择后，您应该看到欢迎屏幕，如下面的屏幕截图所示：![还有更多…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00310.jpeg)

+   现在可以在容器内运行 systemd，这是一种更受欢迎的方式。Systemd 可以管理多个服务。您可以在[`github.com/fedora-cloud/Fedora-Dockerfiles/tree/master/systemd`](https://github.com/fedora-cloud/Fedora-Dockerfiles/tree/master/systemd)中查看 systemd 的示例。

## 另请参阅

+   查看`docker build`的`help`选项：

```
$ docker build --help

```

+   Docker 网站上的文档[`docs.docker.com/reference/builder/`](https://docs.docker.com/reference/builder/)

# 设置私有索引/注册表

正如我们之前看到的，公共 Docker 注册表是可用的 Docker Hub（[`registry.hub.docker.com/`](https://registry.hub.docker.com/)），用户可以通过它推送/拉取镜像。我们还可以在本地环境或云上托管私有注册表。有几种设置本地注册表的方法：

+   使用 Docker Hub 的 Docker 注册表

+   从 Dockerfile 构建镜像并运行注册表容器：

[`github.com/fedora-cloud/Fedora-Dockerfiles/tree/master/registry`](https://github.com/fedora-cloud/Fedora-Dockerfiles/tree/master/registry)

+   配置特定于发行版的软件包，例如提供了 docker-registry 软件包的 Fedora。

设置它的最简单方法是通过注册表容器本身。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  要在容器上运行注册表，请运行以下命令：

```
$ docker run -p 5000:5000 registry

```

1.  要测试新创建的注册表，请执行以下步骤：

1.  使用以下命令启动容器及其 ID：

```
 $ ID='docker run -d -i fedora /bin/bash'

```

1.  如果需要，附加到新创建的容器并进行一些更改。然后，将这些更改提交到本地存储库：

```
 $ docker commit $ID fedora-20

```

1.  要将镜像推送到本地注册表，我们需要使用注册表主机的主机名或 IP 地址对镜像进行标记。假设我们的注册表主机是 `registry-host`；然后，要对其进行标记，请使用以下命令：

```
$ docker tag fedora-20 registry-host:5000/nkhare/f20

```

1.  由于我们在启动注册表时没有正确配置 HTTPS，因此我们将收到错误，例如 `ping attempt failed with error: Get https://dockerhost:5000/v1/_ping`，这是预期的。为了使我们的示例工作，我们需要向守护程序添加 `--insecure-registry registry-host:5000` 选项。如果您手动启动了 Docker 守护程序，那么我们必须按照以下方式运行命令以允许不安全的注册表：

```
$ docker -d   --insecure-registry registry-host:5000

```

1.  要推送镜像，请使用以下命令：

```
$ docker push registry-host:5000/nkhare/f20

```

1.  要从本地注册表中拉取镜像，请运行以下命令：

```
$ docker pull registry-host:5000/nkhare/f20

```

## 工作原理…

从 Docker Hub 下载官方注册表镜像并在端口 `5000` 上运行它的上述命令。`-p` 选项将容器端口发布到主机系统的端口。我们将在下一章中详细了解端口发布的细节。

也可以使用 docker-registry 应用程序在任何现有服务器上配置注册表。执行此操作的步骤可在 docker-registry GitHub 页面上找到：

[`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)

## 还有更多…

让我们看看 docker-registry 的 Dockerfile，以了解注册表镜像是如何创建的，以及如何设置不同的配置选项：

```
# VERSION 0.1
# DOCKER-VERSION  0.7.3
# AUTHOR:         Sam Alba <sam@docker.com>
# DESCRIPTION:    Image with docker-registry project and dependencies
# TO_BUILD:       docker build -rm -t registry .
# TO_RUN:         docker run -p 5000:5000 registry

# Latest Ubuntu LTS
FROM ubuntu:14.04

# Update
RUN apt-get update \
# Install pip
 && apt-get install -y \
 swig \
 python-pip \
# Install deps for backports.lzma (python2 requires it)
 python-dev \
 python-mysqldb \
 python-rsa \
 libssl-dev \
 liblzma-dev \
 libevent1-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . /docker-registry
COPY ./config/boto.cfg /etc/boto.cfg

# Install core
RUN pip install /docker-registry/depends/docker-registry-core

# Install registry
RUN pip install file:///docker-registry#egg=docker-registry[bugsnag,newrelic,cors]

RUN patch \
 $(python -c 'import boto; import os; print os.path.dirname(boto.__file__)')/connection.py \
 < /docker-registry/contrib/boto_header_patch.diff

ENV DOCKER_REGISTRY_CONFIG /docker-registry/config/config_sample.yml
ENV SETTINGS_FLAVOR dev
EXPOSE 5000
CMD ["docker-registry"]

```

使用上述 Dockerfile，我们将：

+   使用 Ubuntu 的基本镜像安装/更新软件包

+   将 docker-registry 源代码复制到镜像中

+   使用 `pip install` docker-registry

+   设置在运行注册表时使用的配置文件的环境变量

+   使用环境变量设置运行注册表时要使用的 flavor

+   暴露端口 `5000`

+   运行注册表可执行文件

配置文件（`/docker-registry/config/config_sample.yml`）中的风格提供了配置注册表的不同方式。使用上述 Dockerfile，我们将使用环境变量设置`dev`风格。不同类型的风格包括：

+   `common`: 这是所有其他风格的基本设置

+   `local`: 这将数据存储在本地文件系统中

+   `s3`: 这将数据存储在 AWS S3 存储桶中

+   `dev`: 这是使用本地风格的基本配置

+   `test`: 这是单元测试使用的配置

+   `prod`: 这是生产配置（基本上是 S3 风格的同义词）

+   `gcs`: 这将数据存储在 Google 云存储中

+   `swift`: 这将数据存储在 OpenStack Swift 中

+   `glance`: 这将数据存储在 OpenStack Glance 中，备用为本地存储

+   `glance-swift`: 这将数据存储在 OpenStack Glance 中，备用为 Swift

+   `elliptics`: 这将数据存储在椭圆键值存储中

对于上述每种风格，都有不同的配置选项，例如日志级别、身份验证等。所有选项的文档都可以在我之前提到的 docker-registry 的 GitHub 页面上找到。

## 另请参阅

+   GitHub 上的文档 [`github.com/docker/docker-registry`](https://github.com/docker/docker-registry)

# 使用 GitHub 和 Bitbucket 进行自动构建

我们之前已经看到如何将 Docker 镜像推送到 Docker Hub。Docker Hub 允许我们使用其构建集群从 GitHub/Bitbucket 存储库创建自动化镜像。GitHub/Bitbucket 存储库应包含 Dockerfile 和所需的内容以复制/添加到镜像中。让我们在接下来的部分中看一个 GitHub 的例子。

## 准备工作

您将需要在 Docker Hub 和 GitHub 上拥有帐户。您还需要一个具有相应 Dockerfile 的 GitHub 存储库，位于顶层。

## 如何做…

1.  登录到 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）并单击绿色加号。在右上角添加存储库图标，然后单击**自动化构建**。选择 GitHub 作为自动化构建的源。然后，选择**公共和私有（推荐）**选项以连接到 GitHub。在提示时提供 GitHub 用户名/密码。选择要执行自动化构建的 GitHub 存储库。![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00311.jpeg)

1.  选择 GitHub 存储库后，它会要求您选择要用于自动构建的分支。它还会要求您提供一个标签名称，以在自动构建的镜像之后使用。默认情况下，将使用最新的标签名称。然后，单击**保存并触发构建**按钮开始自动构建过程。就是这样！您的构建现在已提交。您可以单击构建状态来检查构建的状态。

## 它是如何工作的...

当我们选择 GitHub 存储库进行自动构建时，GitHub 会为该存储库启用 Docker 服务。您可以查看 GitHub 存储库的**设置**部分以进行更多配置。每当我们对这个 GitHub 存储库进行任何更改，比如提交，都会使用存储在 GitHub 存储库中的 Dockerfile 触发自动构建。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00312.jpeg)

## 还有更多...

您可以通过转到**您的存储库**部分来获取诸如 Dockerfile、构建详细信息标签和其他信息。它还包含了如何拉取您的镜像的详细信息：

![还有更多...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00313.jpeg)

使用自动构建过程创建的镜像无法通过`docker push`命令推送。

您可以在 GitHub 存储库的**Webhooks & Services**部分更改设置，以注销 Docker 服务。这将停止自动构建。

## 另请参阅

+   使用 Bitbucket 设置自动构建的步骤几乎相同。自动构建的挂钩在 Bitbucket 存储库的**设置**部分的**Hooks**部分下进行配置。

+   Docker 网站上的文档[`docs.docker.com/docker-hub/builds/`](https://docs.docker.com/docker-hub/builds/)

# 创建基础镜像-使用 supermin

在本章的前面，我们使用了`FROM`指令来选择要开始的基础镜像。我们创建的镜像可以成为另一个应用程序容器化的基础镜像，依此类推。从一开始到这个链条，我们将有一个来自我们想要使用的基础 Linux 发行版的基础镜像，比如 Fedora、Ubuntu、CentOS 等。

要构建这样的基础镜像，我们需要在目录中安装特定于发行版的基本系统，然后将其导入为 Docker 镜像。使用 chroot 实用程序，我们可以将一个目录伪装成根文件系统，然后在导入为 Docker 镜像之前将所有必要的文件放入其中。Supermin 和 Debootstrap 是可以帮助我们使前述过程更容易的工具。

Supermin 是构建 supermin 应用程序的工具。这些是微型应用程序，可以在飞行中完全实例化。早期这个程序被称为 febootstrap。

## 准备就绪

在要构建基础镜像的系统上安装 supermin。您可以使用以下命令在 Fedora 上安装 supermin：

```
$ yum install supermin

```

## 如何做...

1.  使用`prepare`模式在目录中安装`bash`，`coreutils`和相关依赖项。

```
$ supermin --prepare -o OUTPUTDIR PACKAGE [PACKAGE ...]

```

以下是使用前述语法的示例：

```
$ supermin --prepare bash coreutils -o f21_base

```

1.  现在，使用`build`模式为基础镜像创建一个 chroot 环境：

```
$ supermin --build -o OUTPUTDIR -f chroot|ext2 INPUT [INPUT ...]

```

以下是使用前述语法的示例：

```
$ supermin --build --format chroot f21_base -o f21_image

```

1.  如果我们在输出目录上执行`ls`，我们将看到一个类似于任何 Linux 根文件系统的目录树：

```
$ ls f21_image/
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

```

1.  现在我们可以使用以下命令将目录导出为 Docker 镜像：

```
$ tar -C f21_image/ -c . | docker import - nkhare/f21_base
d6db8b798dee30ad9c84480ef7497222f063936a398ecf639e60599eed7f6560

```

1.  现在，查看`docker images`输出。您应该有一个名为`nkhare/f21_base`的新镜像。

## 它是如何工作的...

Supermin 有两种模式，`prepare`和`build`。使用`prepare`模式，它只是将所有请求的软件包及其依赖项放在一个目录中，而不复制主机操作系统特定的文件。

使用`build`模式，先前通过`prepare`模式创建的 supermin 应用程序将被转换为具有所有必要文件的完整可引导应用程序。此步骤将从主机复制所需的文件/二进制文件到应用程序目录，因此必须在要在应用程序中使用的主机机器上安装软件包。

`build`模式有两种输出格式，chroot 和 ext2。使用 chroot 格式，目录树被写入目录中，而使用 ext2 格式，则创建磁盘映像。我们通过 chroot 格式导出创建的目录来创建 Docker 镜像。

## 还有更多...

Supermin 不特定于 Fedora，应该适用于任何 Linux 发行版。

## 另请参阅

+   使用以下命令查看 supermin 的`man`页面以获取更多信息：

```
$ man supermin

```

+   在线文档[`people.redhat.com/~rjones/supermin/`](http://people.redhat.com/~rjones/supermin/)

+   GitHub 存储库[`github.com/libguestfs/supermin`](https://github.com/libguestfs/supermin)

# 创建基本镜像-使用 Debootstrap

Debootstrap 是一种工具，用于将基于 Debian 的系统安装到已安装系统的目录中。

## 准备工作

在基于 Debian 的系统上使用以下命令安装`debootstrap`：

```
$ apt-get install debootstrap

```

## 如何做…

以下命令可用于使用 Debootstrap 创建基本镜像：

```
$ debootstrap [OPTION...]  SUITE TARGET [MIRROR [SCRIPT]]

```

`SUITE`指的是发布代码名称，`MIRROR`是相应的存储库。如果您想创建 Ubuntu 14.04.1 LTS（Trusty Tahr）的基本镜像，则执行以下操作：

1.  在要安装操作系统的目录上创建一个目录。Debootstrap 还创建了 chroot 环境以安装软件包，就像我们之前在 supermin 中看到的那样。

```
$ mkdir trusty_chroot

```

1.  现在，使用`debootstrap`在我们之前创建的目录中安装 Trusty Tahr：

```
$ debootstrap trusty ./trusty_chroot http://in.archive.ubuntu.com/ubuntu/

```

1.  您将看到类似于任何 Linux 根文件系统的目录树，位于 Trusty Tahr 安装的目录内。

```
$ ls ./trusty_chroot
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

```

1.  现在，我们可以使用以下命令将目录导出为 Docker 镜像：

```
$ tar -C trusty_chroot/ -c . |  docker import - nkhare/trusty_base

```

1.  现在，查看`docker images`输出。您应该有一个名为`nkhare/trusty_base`的新镜像。

## 另请参阅

+   Debootstrap 维基页面[`wiki.debian.org/Debootstrap`](https://wiki.debian.org/Debootstrap)。

+   还有其他几种创建基本镜像的方法。您可以在[`docs.docker.com/articles/baseimages/`](https://docs.docker.com/articles/baseimages/)找到链接。

# 可视化层之间的依赖关系

随着镜像数量的增加，找到它们之间的关系变得困难。有一些实用程序可以找到镜像之间的关系。

## 准备工作

在运行 Docker 守护程序的主机上有一个或多个 Docker 镜像。

## 如何做…

1.  运行以下命令以获取图像的树状视图：

```
$ docker images -t

```

## 工作原理…

层之间的依赖关系将从 Docker 镜像的元数据中获取。

## 还有更多…

从`--viz`到`docker` `images`，我们可以以图形方式看到依赖关系；要做到这一点，您需要安装`graphviz`软件包：

```
$ docker images --viz | dot -Tpng -o /tmp/docker.png
$ display /tmp/docker.png

```

正如在运行上述命令时出现的警告中所述，`-t`和`--viz`选项可能很快就会被弃用。

## 另请参阅

+   以下项目尝试通过使用来自 Docker 的原始 JSON 输出来可视化 Docker 数据[`github.com/justone/dockviz`](https://github.com/justone/dockviz)
