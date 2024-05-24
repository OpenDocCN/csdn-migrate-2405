# Docker 网络学习手册（一）

> 原文：[`zh.annas-archive.org/md5/EA91D8E763780FFC629216A68518897B`](https://zh.annas-archive.org/md5/EA91D8E763780FFC629216A68518897B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书帮助读者学习、创建、部署和提供 Docker 网络的管理步骤。Docker 是一个 Linux 容器实现，可以创建轻量级便携的开发和生产环境。这些环境可以进行增量更新。Docker 通过利用 cgroups 和 Linux 命名空间等封装原则以及基于覆盖文件系统的便携式镜像来实现这一点。

Docker 提供了网络原语，允许管理员指定不同容器如何与每个应用程序进行网络连接，连接到它们的各个组件，然后将它们分布在大量服务器上，并确保它们之间的协调，无论它们运行在哪个主机或虚拟机上。本书汇集了所有最新的 Docker 网络技术，并提供了深入的设置详细说明。

# 第一章《Docker 网络入门》解释了 Docker 网络的基本组件，这些组件是从简单的 Docker 抽象和强大的网络组件（如 Linux 桥接、Open vSwitch 等）演变而来。本章还解释了 Docker 容器可以以各种模式创建。在默认模式下，端口映射通过使用 iptables NAT 规则帮助我们，允许到达主机的流量到达容器。本章后面还涵盖了容器的基本链接以及下一代 Docker 网络——libnetwork。

本书内容

第二章《Docker 网络内部》讨论了 Docker 的内部网络架构。我们将了解 Docker 中的 IPv4、IPv6 和 DNS 配置。本章后面还涵盖了 Docker 桥接和单主机和多主机之间容器之间的通信。本章还解释了覆盖隧道和 Docker 网络上实现的不同方法，如 OVS、Flannel 和 Weave。

第三章，“构建您的第一个 Docker 网络”，展示了 Docker 容器如何使用不同的网络选项从多个主机进行通信，例如 Weave、OVS 和 Flannel。Pipework 使用传统的 Linux 桥接，Weave 创建虚拟网络，OVS 使用 GRE 隧道技术，Flannel 为每个主机提供单独的子网，以连接多个主机上的容器。一些实现，如 Pipework，是传统的，并将在一段时间内变得过时，而其他一些则设计用于特定操作系统的上下文中，例如 Flannel 与 CoreOS。本章还涵盖了 Docker 网络选项的基本比较。

第四章，“Docker 集群中的网络”，深入解释了 Docker 网络，使用各种框架，如原生 Docker Swarm，使用 libnetwork 或开箱即用的覆盖网络，Swarm 提供了多主机网络功能。另一方面，Kubernetes 与 Docker 有不同的观点，其中每个 pod 将获得一个唯一的 IP 地址，并且可以借助服务在 pod 之间进行通信。使用 Open vSwitch 或 IP 转发高级路由规则，可以增强 Kubernetes 网络，以在不同子网的主机之间提供连接，并将 pod 暴露给外部世界。在 Mesosphere 的情况下，我们可以看到 Marathon 被用作部署容器的网络后端。在 Mesosphere 的 DCOS 情况下，整个部署的机器堆栈被视为一个机器，以在部署的容器服务之间提供丰富的网络体验。

第五章，“Docker 容器的安全性和 QoS”，通过引用内核和 cgroups 命名空间，深入探讨 Docker 安全性。我们还将讨论文件系统和各种 Linux 功能的一些方面，容器利用这些功能来提供更多功能，例如特权容器，但以暴露更多威胁为代价。我们还将看到如何在 AWS ECS 中部署容器在安全环境中使用代理容器来限制易受攻击的流量。我们还将讨论 AppArmor 提供了丰富的强制访问控制（MAC）系统，提供内核增强功能，以限制应用程序对有限资源的访问。利用它们对 Docker 容器的好处有助于在安全环境中部署它们。在最后一节中，我们将快速深入研究 Docker 安全基准和一些在审核和在生产环境中部署 Docker 时可以遵循的重要建议。

第六章，“Docker 的下一代网络堆栈：libnetwork”，将深入探讨 Docker 网络的一些更深层次和概念性方面。其中之一是 libnetworking——Docker 网络模型的未来，随着 Docker 1.9 版本的发布已经初具规模。在解释 libnetworking 概念的同时，我们还将研究 CNM 模型，以及其各种对象和组件，以及其实现代码片段。接下来，我们将详细研究 CNM 的驱动程序，主要是覆盖驱动程序，并作为 Vagrant 设置的一部分进行部署。我们还将研究容器与覆盖网络的独立集成，以及 Docker Swarm 和 Docker Machine。在接下来的部分中，我们将解释 CNI 接口，其可执行插件，并提供使用 CNI 插件配置 Docker 网络的教程。在最后一节中，将详细解释 Project Calico，该项目提供基于 libnetwork 的可扩展网络解决方案，并与 Docker、Kubernetes、Mesos、裸机和虚拟机集成。

# 本书所需内容

基本上所有的设置都需要 Ubuntu 14.04（安装在物理机器上或作为虚拟机）和 Docker 1.9，这是截止目前的最新版本。如果需要，会在每个设置之前提到特定的操作系统和软件要求（开源 Git 项目）。

# 这本书适合谁

如果您是一名 Linux 管理员，想要通过使用 Docker 来学习网络知识，以确保对核心元素和应用程序进行高效管理，那么这本书适合您。假定您具有 LXC/Docker 的基础知识。

# 约定

您还会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例和它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名会显示如下：“您可能会注意到，我们使用了 Unix 命令`rm`来删除`Drush`目录，而不是 DOS 的`del`命令。”

代码块设置如下：

```
# * Fine Tuning
#
key_buffer = 16M
key_buffer_size = 32M
max_allowed_packet = 16M
thread_stack = 512K
thread_cache_size = 8
max_connections = 300
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```
# * Fine Tuning
#
key_buffer = 16M
key_buffer_size = 32M
max_allowed_packet = 16M
thread_stack = 512K
thread_cache_size = 8
max_connections = 300
```

任何命令行输入或输出都会以以下形式书写：

```
cd /ProgramData/Propeople
rm -r Drush
git clone --branch master http://git.drupal.org/project/drush.git

```

**新术语**和**重要单词**会以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中：“在**选择目标位置**屏幕上，点击**下一步**以接受默认目标。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

技巧和窍门会以这样的形式出现。


# 第一章：Docker 网络入门

Docker 是一种轻量级的容器技术，近年来引起了巨大的兴趣。它巧妙地捆绑了各种 Linux 内核特性和服务，如命名空间、cgroups、SELinux 和 AppArmor 配置文件，以及 AUFS 和 BTRFS 等联合文件系统，以创建模块化的镜像。这些镜像为应用程序提供了高度可配置的虚拟化环境，并遵循“一次编写，随处运行”的工作流程。一个应用可以由在 Docker 容器中运行的单个进程组成，也可以由在它们自己的容器中运行的多个进程组成，并随着负载的增加而复制。因此，有必要拥有强大的网络元素来支持各种复杂的用例。

在本章中，您将了解 Docker 网络的基本组件以及如何构建和运行简单的容器示例。

本章涵盖以下主题：

+   网络和 Docker

+   `docker0` 桥接网络

+   Docker OVS 网络

+   Unix 域网络

+   链接 Docker 容器

+   Docker 网络的新特性

Docker 在行业中备受关注，因为其性能敏锐和通用可复制的架构，同时提供现代应用开发的以下四个基石：

+   自治

+   去中心化

+   并行性

+   隔离

此外，Thoughtworks 的微服务架构或 LOSA（许多小应用程序）的广泛采用进一步为 Docker 技术带来潜力。因此，谷歌、VMware 和微软等大公司已经将 Docker 移植到他们的基础设施上，而无数的 Docker 初创公司的推出，如 Tutum、Flocker、Giantswarm 等，也在推动这股势头。

由于 Docker 容器可以在开发机器、裸金属服务器、虚拟机或数据中心中复制其行为，因此应用程序设计人员可以专注于开发，而操作语义留给了 DevOps。这使团队工作流程模块化、高效和高产。 Docker 不应与虚拟机（VM）混淆，尽管它们都是虚拟化技术。虽然 Docker 与提供足够隔离和安全性的应用程序共享操作系统，但它后来完全抽象了操作系统并提供了强大的隔离和安全性保证。但是，与 VM 相比，Docker 的资源占用量微不足道，因此更受经济和性能的青睐。但是，它仍然无法完全取代 VM，因此是 VM 技术的补充。以下图表显示了 VM 和 Docker 的架构：

![Docker Networking Primer](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00002.jpeg)

# 网络和 Docker

每个 Docker 容器都有自己的网络堆栈，这是由于 Linux 内核 NET 命名空间，每个容器都有一个新的 NET 命名空间，并且无法从容器外部或其他容器中看到。

Docker 网络由以下网络组件和服务提供支持。

## Linux 桥

这些是内核中内置的 L2/MAC 学习交换机，用于转发。

## Open vSwitch

这是一个可编程的高级桥梁，支持隧道。

## NAT

网络地址转换器是立即实体，用于转换 IP 地址和端口（SNAT、DNAT 等）。

## IPtables

这是内核中用于管理数据包转发、防火墙和 NAT 功能的策略引擎。

## AppArmor/SELinux

每个应用程序都可以使用这些定义防火墙策略。

可以使用各种网络组件来与 Docker 一起工作，提供了访问和使用基于 Docker 的服务的新方法。因此，我们看到了许多遵循不同网络方法的库。其中一些著名的是 Docker Compose、Weave、Kubernetes、Pipework、libnetwork 等。以下图表描述了 Docker 网络的根本思想：

![AppArmor/SELinux](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00003.jpeg)

# docker0 桥

`docker0`桥是默认网络的核心。当 Docker 服务启动时，在主机上创建一个 Linux 桥。容器上的接口与桥进行通信，桥代理到外部世界。同一主机上的多个容器可以通过 Linux 桥相互通信。

`docker0`可以通过`--net`标志进行配置，并且通常有四种模式：

+   `--net default`

+   `--net=none`

+   `--net=container:$container2`

+   `--net=host`

## --net default 模式

在此模式下，默认桥被用作容器相互连接的桥。

## --net=none 模式

使用此模式，创建的容器是真正隔离的，无法连接到网络。

## --net=container:$container2 模式

使用此标志，创建的容器与名为`$container2`的容器共享其网络命名空间。

## --net=host 模式

使用此模式，创建的容器与主机共享其网络命名空间。

### Docker 容器中的端口映射

在本节中，我们将看看容器端口是如何映射到主机端口的。这种映射可以由 Docker 引擎隐式完成，也可以被指定。

如果我们创建两个名为**Container1**和**Container2**的容器，它们都被分配了来自私有 IP 地址空间的 IP 地址，并连接到**docker0**桥上，如下图所示：

![Docker 容器中的端口映射](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00004.jpeg)

前述的两个容器都能够相互 ping 通，也能够访问外部世界。

为了外部访问，它们的端口将被映射到主机端口。

如前一节所述，容器使用网络命名空间。当创建第一个容器时，为容器创建了一个新的网络命名空间。在容器和 Linux 桥之间创建了一个 vEthernet 链接。从容器的`eth0`发送的流量通过 vEthernet 接口到达桥，然后进行切换。以下代码可用于显示 Linux 桥的列表：

```
# show linux bridges
$ sudo brctl show

```

输出将类似于以下所示，具有桥名称和其映射到的容器上的`veth`接口：

```
bridge name      bridge id        STP enabled    interfaces
docker0      8000.56847afe9799        no         veth44cb727
 veth98c3700

```

容器如何连接到外部世界？主机上的`iptables nat`表用于伪装所有外部连接，如下所示：

```
$ sudo iptables -t nat -L –n
...
Chain POSTROUTING (policy ACCEPT) target prot opt
source destination MASQUERADE all -- 172.17.0.0/16
!172.17.0.0/16
...

```

如何从外部世界访问容器？端口映射再次使用主机上的`iptables nat`选项完成。

![Docker 容器中的端口映射](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00005.jpeg)

# Docker OVS

Open vSwitch 是一个强大的网络抽象。下图显示了 OVS 如何与**VM**、**Hypervisor**和**Physical Switch**交互。每个**VM**都有一个与之关联的**vNIC**。每个**vNIC**通过**VIF**（也称为**虚拟接口**）与**虚拟交换机**连接：

![Docker OVS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00006.jpeg)

OVS 使用隧道机制，如 GRE、VXLAN 或 STT 来创建虚拟覆盖，而不是使用物理网络拓扑和以太网组件。下图显示了 OVS 如何配置为使用 GRE 隧道在多个主机之间进行容器通信：

![Docker OVS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00007.jpeg)

# Unix 域套接字

在单个主机内，UNIX IPC 机制，特别是 UNIX 域套接字或管道，也可以用于容器之间的通信：

```
$  docker run  --name c1 –v /var/run/foo:/var/run/foo –d –I –t base /bin/bash
$  docker run  --name c2 –v /var/run/foo:/var/run/foo –d –I –t base /bin/bash

```

`c1`和`c2`上的应用程序可以通过以下 Unix 套接字地址进行通信：

```
struct  sockaddr_un address;
address.sun_family = AF_UNIX;
snprintf(address.sun_path, UNIX_PATH_MAX, "/var/run/foo/bar" );

```

| C1: Server.c | C2: Client.c |
| --- | --- |

|

```
bind(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
listen(socket_fd, 5);
while((connection_fd = accept(socket_fd, (struct sockaddr *) &address, &address_length)) > -1)
nbytes = read(connection_fd, buffer, 256);
```

|

```
connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
write(socket_fd, buffer, nbytes);
```

|

# 链接 Docker 容器

在本节中，我们介绍了链接两个容器的概念。Docker 在容器之间创建了一个隧道，不需要在容器上外部公开任何端口。它使用环境变量作为从父容器传递信息到子容器的机制之一。

除了环境变量`env`之外，Docker 还将源容器的主机条目添加到`/etc/hosts`文件中。以下是主机文件的示例：

```
$ docker run -t -i --name c2 --rm --link c1:c1alias training/webapp /bin/bash
root@<container_id>:/opt/webapp# cat /etc/hosts
172.17.0.1  aed84ee21bde
...
172.17.0.2  c1alaias 6e5cdeb2d300 c1

```

有两个条目：

+   第一个是用 Docker 容器 ID 作为主机名的`c2`容器的条目

+   第二个条目，`172.17.0.2 c1alaias 6e5cdeb2d300 c1`，使用`link`别名来引用`c1`容器的 IP 地址

下图显示了两个容器**容器 1**和**容器 2**使用 veth 对连接到`docker0`桥接器，带有`--icc=true`。这意味着这两个容器可以通过桥接器相互访问：

![Linking Docker containers](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00008.jpeg)

## 链接

链接为 Docker 提供了服务发现。它们允许容器通过使用标志`-link name:alias`来发现并安全地相互通信。通过使用守护程序标志`-icc=false`可以禁用容器之间的相互通信。设置为`false`后，**容器 1**除非通过链接明确允许，否则无法访问**容器 2**。这对于保护容器来说是一个巨大的优势。当两个容器被链接在一起时，Docker 会在它们之间创建父子关系，如下图所示：

![链接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00009.jpeg)

从外部看，它看起来像这样：

```
# start the database
$  sudo docker run -dp 3306:3306 --name todomvcdb \
-v /data/mysql:/var/lib/mysql cpswan/todomvc.mysql

# start the app server
$  sudo docker run -dp 4567:4567 --name todomvcapp \
--link todomvcdb:db cpswan/todomvc.sinatra

```

在内部，它看起来像这样：

```
$  dburl = ''mysql://root:pa55Word@'' + \ ENV[''DB_PORT_3306_TCP_ADDR''] + ''/todomvc''
$  DataMapper.setup(:default, dburl)

```

# Docker 网络的新特性是什么？

Docker 网络处于非常初期阶段，开发者社区有许多有趣的贡献，如 Pipework、Weave、Clocker 和 Kubernetes。每个都反映了 Docker 网络的不同方面。我们将在后面的章节中了解它们。Docker, Inc.还建立了一个新项目，网络将被标准化。它被称为**libnetwork**。

libnetwork 实现了**容器网络模型**（**CNM**），它规范了为容器提供网络所需的步骤，同时提供了一个抽象，可以支持多个网络驱动程序。CNM 建立在三个主要组件上——沙盒、端点和网络。

## 沙盒

沙盒包含容器网络栈的配置。这包括容器的接口管理、路由表和 DNS 设置。沙盒的实现可以是 Linux 网络命名空间、FreeBSD 监狱或类似的概念。一个沙盒可以包含来自多个网络的许多端点。

## 端点

端点将沙盒连接到网络。端点的实现可以是 veth 对、Open vSwitch 内部端口或类似的东西。一个端点只能属于一个网络，但只能属于一个沙盒。

## 网络

网络是一组能够直接相互通信的端点。网络的实现可以是 Linux 桥接、VLAN 等。网络由许多端点组成，如下图所示：

![网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00010.jpeg)

# Docker CNM 模型

CNM 提供了网络和容器之间的以下约定：

+   同一网络上的所有容器可以自由通信

+   多个网络是在容器之间分段流量的方式，并且所有驱动程序都应该支持它

+   每个容器可以有多个端点，这是将容器连接到多个网络的方法。

+   端点被添加到网络沙箱中，以提供网络连接。

我们将在第六章中讨论 CNM 的实现细节，*Docker 的下一代网络堆栈：libnetwork*。

# 总结

在本章中，我们学习了 Docker 网络的基本组件，这些组件是从简单的 Docker 抽象和强大的网络组件（如 Linux 桥和 Open vSwitch）的耦合中发展而来的。

我们学习了 Docker 容器可以以各种模式创建。在默认模式下，通过端口映射可以帮助使用 iptables NAT 规则，使得到达主机的流量可以到达容器。在本章后面，我们介绍了容器的基本链接。我们还讨论了下一代 Docker 网络，称为 libnetwork。


# 第二章：Docker 网络内部

本章详细讨论了 Docker 网络的语义和语法，揭示了当前 Docker 网络范式的优势和劣势。

它涵盖以下主题：

+   为 Docker 配置 IP 堆栈

+   IPv4 支持

+   IPv4 地址管理问题

+   IPv6 支持

+   配置 DNS

+   DNS 基础知识

+   多播 DNS

+   配置 Docker 桥

+   覆盖网络和底层网络

+   它们是什么？

+   Docker 如何使用它们？

+   它们有哪些优势？

# 为 Docker 配置 IP 堆栈

Docker 使用 IP 堆栈通过 TCP 或 UDP 与外部世界进行交互。它支持 IPv4 和 IPv6 寻址基础设施，这些将在以下小节中解释。

## IPv4 支持

默认情况下，Docker 为每个容器提供 IPv4 地址，这些地址附加到默认的`docker0`桥上。可以在启动 Docker 守护程序时使用`--fixed-cidr`标志指定 IP 地址范围，如下面的代码所示：

```
$ sudo docker –d --fixed-cidr=192.168.1.0/25

```

我们将在*配置 Docker 桥*部分中更多讨论这个问题。

Docker 守护程序可以在 IPv4 TCP 端点上列出，还可以在 Unix 套接字上列出：

```
$ sudo docker -H tcp://127.0.0.1:2375 -H unix:///var/run/docker.sock -d &

```

## IPv6 支持

IPv4 和 IPv6 可以一起运行；这被称为**双栈**。通过使用`--ipv6`标志运行 Docker 守护程序来启用此双栈支持。Docker 将使用 IPv6 链路本地地址`fe80::1`设置`docker0`桥。所有容器之间共享的数据包都通过此桥流动。

要为您的容器分配全局可路由的 IPv6 地址，必须指定一个 IPv6 子网以选择地址。

以下命令通过`--fixed-cidr-v6`参数在启动 Docker 时设置 IPv6 子网，并向路由表添加新路由：

```
# docker –d --ipv6 --fixed-cidr-v6="1553:ba3:2::/64"
# docker run -t -i --name c0 ubuntu:latest /bin/bash

```

下图显示了配置了 IPv6 地址范围的 Docker 桥：

![IPv6 支持](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00011.jpeg)

如果在容器内部使用`ifconfig`检查 IP 地址范围，您会注意到适当的子网已分配给`eth0`接口，如下面的代码所示：

```
#ifconfig
eth0      Link encap:Ethernet HWaddr 02:42:ac:11:00:01
          inet addr:172.17.0.1  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe11:1/64 Scope:Link
          inet6 addr: 1553:ba3:2::242:ac11:1/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7 errors:0 dropped:0 overruns:0 frame:0
          TX packets:10 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:738 (738.0 B)  TX bytes:836 (836.0 B)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

所有流向`1553:ba3:2::/64`子网的流量将通过`docker0`接口路由。

前面的容器使用`fe80::42:acff:fe11:1/64`作为链路本地地址和`1553:ba3:2::242:ac11:1/64`作为全局可路由的 IPv6 地址。

### 注意

链路本地和环回地址具有链路本地范围，这意味着它们应该在直接连接的网络（链路）中使用。所有其他地址具有全局（或通用）范围，这意味着它们在全球范围内可路由，并且可以用于连接到任何具有全局范围的地址。

# 配置 DNS 服务器

Docker 为每个容器提供主机名和 DNS 配置，而无需我们构建自定义镜像。它在容器内部覆盖`/etc`文件夹，其中可以写入新信息。

通过在容器内运行`mount`命令可以看到这一点。容器在初始创建时会接收与主机机器相同的`resolv.conf`文件。如果主机的`resolv.conf`文件被修改，只有当容器重新启动时，这将反映在容器的`/resolv.conf`文件中。

在 Docker 中，您可以通过两种方式设置 DNS 选项：

+   使用`docker run --dns=<ip-address>`

+   将`DOCKER_OPTS="--dns ip-address"`添加到 Docker 守护程序文件中

您还可以使用`--dns-search=<DOMAIN>`指定搜索域。

下图显示了在 Docker 守护程序文件中使用`DOCKER_OPTS`设置在容器中配置**nameserver**：

![配置 DNS 服务器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00012.jpeg)

主 DNS 文件如下：

+   `/etc/hostname`

+   `/etc/resolv.conf`

+   `/etc/hosts`

以下是添加 DNS 服务器的命令：

```
# docker run --dns=8.8.8.8 --net="bridge" -t -i  ubuntu:latest /bin/bash

```

使用以下命令添加主机名：

```
#docker run --dns=8.8.8.8 --hostname=docker-vm1  -t -i  ubuntu:latest /bin/bash

```

## 容器与外部网络之间的通信

只有当`ip_forward`参数设置为`1`时，数据包才能在容器之间传递。通常，您将简单地将 Docker 服务器保留在其默认设置`--ip-forward=true`，并且当服务器启动时，Docker 会为您将`ip_forward`设置为`1`。

要检查设置或手动打开 IP 转发，请使用以下命令：

```
# cat /proc/sys/net/ipv4/ip_forward
0
# echo 1 > /proc/sys/net/ipv4/ip_forward
# cat /proc/sys/net/ipv4/ip_forward
1

```

通过启用`ip_forward`，用户可以使容器与外部世界之间的通信成为可能；如果您处于多桥设置中，这也将需要用于容器间通信。下图显示了`ip_forward = false`如何将所有数据包转发到/从容器到/从外部网络：

![容器与外部网络之间的通信](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00013.jpeg)

Docker 不会删除或修改 Docker 过滤链中的任何现有规则。这允许用户创建规则以限制对容器的访问。

Docker 使用`docker0`桥来在单个主机上的所有容器之间进行数据包流动。它添加了一个规则，使用 IPTables 转发链，以便数据包在两个容器之间流动。设置`--icc=false`将丢弃所有数据包。

当 Docker 守护程序配置为`--icc=false`和`--iptables=true`，并且使用`--link`选项调用`docker run`时，Docker 服务器将为新容器插入一对 IPTables 接受规则，以便连接到其他容器暴露的端口，这些端口是在其 Dockerfile 的暴露行中提到的端口。以下图显示了`ip_forward = false`如何丢弃所有来自/到达外部网络的容器的数据包：

![容器与外部网络之间的通信](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00014.jpeg)

默认情况下，Docker 的`forward`规则允许所有外部 IP。要允许只有特定 IP 或网络访问这些容器，插入一个否定规则到 Docker 过滤链的顶部。

例如，使用以下命令，您可以限制外部访问，只有源 IP`10.10.10.10`可以访问这些容器：

```
#iptables –I DOCKER –i ext_if ! –s 10.10.10.10 –j DROP

```

### 限制一个容器到另一个容器的 SSH 访问

按照以下步骤限制一个容器到另一个容器的 SSH 访问：

1.  创建两个容器，`c1`和`c2`。

对于`c1`，使用以下命令：

```
# docker run -i -t --name c1 ubuntu:latest /bin/bash

```

生成的输出如下：

```
root@7bc2b6cb1025:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:05
 inet addr:172.17.0.5  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: 2001:db8:1::242:ac11:5/64 Scope:Global
 inet6 addr: fe80::42:acff:fe11:5/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:7 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:738 (738.0 B)  TX bytes:696 (696.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

对于`c2`，使用以下命令：

```
# docker run -i -t --name c2 ubuntu:latest /bin/bash

```

生成的输出如下：

```
root@e58a9bf7120b:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:06
 inet addr:172.17.0.6  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: 2001:db8:1::242:ac11:6/64 Scope:Global
 inet6 addr: fe80::42:acff:fe11:6/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:6 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:648 (648.0 B)  TX bytes:696 (696.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

我们可以使用刚刚发现的 IP 地址测试容器之间的连接。现在让我们使用`ping`工具来看一下：

```
root@7bc2b6cb1025:/# ping 172.17.0.6
PING 172.17.0.6 (172.17.0.6) 56(84) bytes of data.
64 bytes from 172.17.0.6: icmp_seq=1 ttl=64 time=0.139 ms
64 bytes from 172.17.0.6: icmp_seq=2 ttl=64 time=0.110 ms
^C
--- 172.17.0.6 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.110/0.124/0.139/0.018 ms
root@7bc2b6cb1025:/#

root@e58a9bf7120b:/# ping 172.17.0.5
PING 172.17.0.5 (172.17.0.5) 56(84) bytes of data.
64 bytes from 172.17.0.5: icmp_seq=1 ttl=64 time=0.270 ms
64 bytes from 172.17.0.5: icmp_seq=2 ttl=64 time=0.107 ms
^C
--- 172.17.0.5 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 0.107/0.188/0.270/0.082 ms
root@e58a9bf7120b:/#

```

1.  在两个容器上安装`openssh-server`：

```
#apt-get install openssh-server

```

1.  在主机机器上启用 iptables：

1.  最初，您可以从一个容器 SSH 到另一个容器。

1.  停止 Docker 服务，并在主机机器的默认 Dockerfile 中添加`DOCKER_OPTS="--icc=false --iptables=true"`。此选项将启用 iptables 防火墙，并且丢弃容器之间的所有端口。

默认情况下，主机上未启用`iptables`。使用以下命令启用它：

```
root@ubuntu:~# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
DOCKER     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
DOCKER     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0

#service docker stop
#vi /etc/default/docker

```

1.  Docker Upstart 和 SysVinit 配置文件。自定义 Docker 二进制文件的位置（特别是用于开发测试）：

```
#DOCKER="/usr/local/bin/docker"

```

1.  使用`DOCKER_OPTS`修改守护程序的启动选项：

```
#DOCKER_OPTS="--dns 8.8.8.8 --dns 8.8.4.4"
#DOCKER_OPTS="--icc=false --iptables=true"

```

1.  重新启动 Docker 服务：

```
# service docker start

```

1.  检查`iptables`：

```
root@ubuntu:~# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source             destination
Chain FORWARD (policy ACCEPT)
target     prot opt source             destination
DOCKER     all  --  0.0.0.0/0          0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0          0.0.0.0/0    ctstate RELATED, ESTABLISHED
ACCEPT     all  --  0.0.0.0/0          0.0.0.0/0
DOCKER     all  --  0.0.0.0/0          0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0          0.0.0.0/0   ctstate RELATED, ESTABLISHED
ACCEPT     all  --  0.0.0.0/0          0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0          0.0.0.0/0
DROP       all  --  0.0.0.0/0          0.0.0.0/0

```

在主机上添加了一个`DROP`规则到 iptables，它会丢弃容器之间的连接。现在您将无法在容器之间进行 SSH。

1.  我们可以使用`--link`参数进行容器之间的通信或连接，以下是使用的步骤：

1.  创建第一个充当服务器的容器`sshserver`：

```
root@ubuntu:~# docker run -i -t -p 2222:22 --name sshserver ubuntu bash
root@9770be5acbab:/#

```

1.  执行`iptables`命令，您会发现添加了一个 Docker 链规则：

```
#root@ubuntu:~# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source         destination
Chain FORWARD (policy ACCEPT)
target     prot opt source         destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source         destination
Chain DOCKER (0 references)
target     prot opt source         destination
ACCEPT     tcp  --  0.0.0.0/0        172.17.0.3     tcp dpt:22

```

1.  创建第二个充当客户端的容器`sshclient`：

```
root@ubuntu:~# docker run -i -t --name sshclient --link sshserver:sshserver ubuntu bash
root@979d46c5c6a5:/#

```

1.  我们可以看到 Docker 链规则中添加了更多规则：

```
root@ubuntu:~# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
Chain DOCKER (0 references)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            172.17.0.3           tcp dpt:22
ACCEPT     tcp  --  172.17.0.4           172.17.0.3           tcp dpt:22
ACCEPT     tcp  --  172.17.0.3           172.17.0.4           tcp spt:22
root@ubuntu:~#

```

以下图片解释了使用`--link`标志之间容器之间的通信：

![限制一个容器到另一个容器的 SSH 访问](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00015.jpeg)

1.  您可以使用`docker inspect`命令检查已连接的容器：

```
root@ubuntu:~# docker inspect -f "{{ .HostConfig.Links }}" sshclient
[/sshserver:/sshclient/sshserver]

```

现在您可以使用其 IP 成功 ssh 到 sshserver。

```
#ssh root@172.17.0.3 –p 22

```

使用`--link`参数，Docker 在容器之间创建一个安全通道，不需要在容器上外部公开任何端口。

# 配置 Docker 桥

Docker 服务器默认在 Linux 内核中创建一个名为`docker0`的桥，并且可以在其他物理或虚拟网络接口之间来回传递数据包，使它们表现为单个以太网网络。运行以下命令以查找 VM 中接口的列表以及它们连接到的 IP 地址：

```
root@ubuntu:~# ifconfig
docker0   Link encap:Ethernet  HWaddr 56:84:7a:fe:97:99
 inet addr:172.17.42.1  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::5484:7aff:fefe:9799/64 Scope:Link
 inet6 addr: fe80::1/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:11909 errors:0 dropped:0 overruns:0 frame:0
 TX packets:14826 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:516868 (516.8 KB)  TX bytes:46460483 (46.4 MB)
eth0      Link encap:Ethernet  HWaddr 00:0c:29:0d:f4:2c
 inet addr:192.168.186.129  Bcast:192.168.186.255  Mask:255.255.255.0
 inet6 addr: fe80::20c:29ff:fe0d:f42c/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:108865 errors:0 dropped:0 overruns:0 frame:0
 TX packets:31708 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:59902195 (59.9 MB)  TX bytes:3916180 (3.9 MB)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:4 errors:0 dropped:0 overruns:0 frame:0
 TX packets:4 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:336 (336.0 B)  TX bytes:336 (336.0 B)

```

一旦您有一个或多个容器正在运行，您可以通过在主机上运行`brctl`命令并查看输出的`interfaces`列来确认 Docker 已将它们正确连接到`docker0`桥。

在配置`docker0`桥之前，安装桥接实用程序：

```
# apt-get install bridge-utils

```

以下是一个连接了两个不同容器的主机：

```
root@ubuntu:~# brctl show
bridge name     bridge id               STP enabled     interfaces
docker0         8000.56847afe9799       no              veth21b2e16
 veth7092a45

```

Docker 在创建容器时使用`docker0`桥接设置。每当创建新容器时，它会从桥上可用的范围中分配一个新的 IP 地址，如下所示：

```
root@ubuntu:~# docker run -t -i --name container1 ubuntu:latest /bin/bash
root@e54e9312dc04:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:07
 inet addr:172.17.0.7  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: 2001:db8:1::242:ac11:7/64 Scope:Global
 inet6 addr: fe80::42:acff:fe11:7/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:7 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:738 (738.0 B)  TX bytes:696 (696.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
root@e54e9312dc04:/# ip route
default via 172.17.42.1 dev eth0
172.17.0.0/16 dev eth0  proto kernel  scope link  src 172.17.0.7

```

默认情况下，Docker 提供名为`docker0`的虚拟网络，其 IP 地址为`172.17.42.1`。Docker 容器的 IP 地址在`172.17.0.0/16`范围内。

要更改 Docker 中的默认设置，请修改文件`/etc/default/docker`。

将默认桥从`docker0`更改为`br0`可以这样做：

```
# sudo service docker stop
# sudo ip link set dev docker0 down
# sudo brctl delbr docker0
# sudo iptables -t nat -F POSTROUTING
# echo 'DOCKER_OPTS="-b=br0"' >> /etc/default/docker
# sudo brctl addbr br0
# sudo ip addr add 192.168.10.1/24 dev br0
# sudo ip link set dev br0 up
# sudo service docker start

```

以下命令显示了 Docker 服务的新桥名称和 IP 地址范围：

```
root@ubuntu:~# ifconfig
br0       Link encap:Ethernet  HWaddr ae:b2:dc:ed:e6:af
 inet addr:192.168.10.1  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::acb2:dcff:feed:e6af/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:738 (738.0 B)
eth0      Link encap:Ethernet  HWaddr 00:0c:29:0d:f4:2c
 inet addr:192.168.186.129  Bcast:192.168.186.255  Mask:255.255.255.0
 inet6 addr: fe80::20c:29ff:fe0d:f42c/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:110823 errors:0 dropped:0 overruns:0 frame:0
 TX packets:33148 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:60081009 (60.0 MB)  TX bytes:4176982 (4.1 MB)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:4 errors:0 dropped:0 overruns:0 frame:0
 TX packets:4 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:336 (336.0 B)  TX bytes:336 (336.0 B)

```

# 覆盖网络和底层网络

覆盖是建立在底层网络基础设施（底层）之上的虚拟网络。其目的是实现在物理网络中不可用的网络服务。

网络覆盖大大增加了可以在物理网络之上创建的虚拟子网的数量，从而支持多租户和虚拟化。

Docker 中的每个容器都被分配一个 IP 地址，用于与其他容器通信。如果容器需要与外部网络通信，您可以在主机系统中设置网络，并将容器的端口暴露或映射到主机上。通过这种方式，容器内运行的应用程序将无法广告其外部 IP 和端口，因为这些信息对它们不可用。

解决方案是在所有主机上为每个 Docker 容器分配唯一的 IP，并且有一些网络产品来路由主机之间的流量。

有不同的项目来处理 Docker 网络，如下所示：

+   Flannel

+   Weave

+   Open vSwitch

Flannel 通过为每个容器分配一个 IP 来提供解决方案，用于容器之间的通信。它使用数据包封装，在主机网络上创建一个虚拟覆盖网络。默认情况下，Flannel 为主机提供一个`/24`子网，Docker 守护程序从中为容器分配 IP。以下图显示了使用 Flannel 进行容器之间通信：

![覆盖网络和底层网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00016.jpeg)

Flannel 在每个主机上运行一个代理**flanneld**，负责从预配置的地址空间中分配子网租约。Flannel 使用 etcd 存储网络配置、分配的子网和辅助数据（如主机的 IP）。

Flannel 使用通用的 TUN/TAP 设备，并使用 UDP 创建覆盖网络来封装 IP 数据包。子网分配是通过 etcd 的帮助完成的，它维护覆盖子网到主机的映射。

Weave 创建了一个虚拟网络，连接了部署在主机/虚拟机上的 Docker 容器，并实现它们的自动发现。以下图显示了 Weave 网络：

![覆盖网络和底层网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00017.jpeg)

Weave 可以穿越防火墙，在部分连接的网络中运行。流量可以选择加密，允许主机/虚拟机在不受信任的网络中连接。

Weave 增强了 Docker 现有（单个主机）的网络功能，比如`docker0`桥，因此这些功能可以继续被容器使用。

Open vSwitch 是一个开源的支持 OpenFlow 的虚拟交换机，通常与虚拟化程序一起使用，在主机内部和跨网络的不同主机之间连接虚拟机。覆盖网络需要使用支持的隧道封装来创建虚拟数据路径，例如 VXLAN 和 GRE。

覆盖数据路径是在 Docker 主机中的隧道端点之间进行配置的，这使得在给定提供者段内的所有主机看起来直接连接在一起。

当新容器上线时，前缀会在路由协议中更新，通过隧道端点宣布其位置。当其他 Docker 主机接收到更新时，转发规则会被安装到 OVS 中，用于主机所在的隧道端点。当主机取消配置时，类似的过程会发生，隧道端点 Docker 主机会移除取消配置容器的转发条目。下图显示了通过基于 OVS 的 VXLAN 隧道在多个主机上运行的容器之间的通信：

![覆盖网络和底层网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00018.jpeg)

# 总结

在本章中，我们讨论了 Docker 的内部网络架构。我们了解了 Docker 中的 IPv4、IPv6 和 DNS 配置。在本章的后面，我们涵盖了 Docker 桥接和单个主机内以及多个主机之间容器之间的通信。

我们还讨论了在 Docker 网络中实施的覆盖隧道和不同的方法，例如 OVS、Flannel 和 Weave。

在下一章中，我们将学习 Docker 网络的实际操作，结合各种框架。


# 第三章：构建您的第一个 Docker 网络

本章描述了 Docker 网络的实际示例，跨多个主机连接多个容器。我们将涵盖以下主题：

+   Pipework 简介

+   在多个主机上的多个容器

+   朝着扩展网络-介绍 Open vSwitch

+   使用覆盖网络进行网络连接-Flannel

+   Docker 网络选项的比较

# Pipework 简介

Pipework 让您在任意复杂的场景中连接容器。

在实际操作中，它创建了一个传统的 Linux 桥接，向容器添加一个新的接口，然后将接口连接到该桥接；容器获得了一个网络段，可以在其中相互通信。

# 在单个主机上的多个容器

Pipework 是一个 shell 脚本，安装它很简单：

```
#sudo wget -O /usr/local/bin/pipework https://raw.githubusercontent.com/jpetazzo/pipework/master/pipework && sudo chmod +x /usr/local/bin/pipework

```

以下图显示了使用 Pipework 进行容器通信：

![在单个主机上的多个容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00019.jpeg)

首先，创建两个容器：

```
#docker run -i -t --name c1 ubuntu:latest /bin/bash
root@5afb44195a69:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:10
 inet addr:172.17.0.16  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:10/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:13 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1038 (1.0 KB)  TX bytes:738 (738.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

#docker run -i -t --name c2 ubuntu:latest /bin/bash
root@c94d53a76a9b:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:11
 inet addr:172.17.0.17  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:11/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:8 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:648 (648.0 B)  TX bytes:738 (738.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

现在让我们使用 Pipework 来连接它们：

```
#sudo pipework brpipe c1 192.168.1.1/24

```

此命令在主机上创建一个桥接`brpipe`。它向容器`c1`添加一个`eth1`接口，IP 地址为`192.168.1.1`，并将接口连接到桥接如下：

```
root@5afb44195a69:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:10
 inet addr:172.17.0.16  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:10/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:13 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1038 (1.0 KB)  TX bytes:738 (738.0 B)
eth1      Link encap:Ethernet  HWaddr ce:72:c5:12:4a:1a
 inet addr:192.168.1.1  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::cc72:c5ff:fe12:4a1a/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:23 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:1806 (1.8 KB)  TX bytes:690 (690.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
#sudo pipework brpipe c2 192.168.1.2/24

```

此命令不会创建桥接`brpipe`，因为它已经存在。它将向容器`c2`添加一个`eth1`接口，并将其连接到桥接如下：

```
root@c94d53a76a9b:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:11
 inet addr:172.17.0.17  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:11/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:8 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:648 (648.0 B)  TX bytes:738 (738.0 B)
eth1      Link encap:Ethernet  HWaddr 36:86:fb:9e:88:ba
 inet addr:192.168.1.2  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::3486:fbff:fe9e:88ba/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:8 errors:0 dropped:0 overruns:0 frame:0
 TX packets:9 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:648 (648.0 B)  TX bytes:690 (690.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

现在容器已连接，将能够相互 ping 通，因为它们在同一个子网`192.168.1.0/24`上。Pipework 提供了向容器添加静态 IP 地址的优势。

## 编织您的容器

编织创建了一个虚拟网络，可以连接 Docker 容器跨多个主机，就像它们都连接到一个单一的交换机上一样。编织路由器本身作为一个 Docker 容器运行，并且可以加密路由的流量以通过互联网进行传输。在编织网络上由应用容器提供的服务可以被外部世界访问，无论这些容器在哪里运行。

使用以下代码安装 Weave：

```
#sudo curl -L git.io/weave -o /usr/local/bin/weave
#sudo chmod a+x /usr/local/bin/weave
```

以下图显示了使用 Weave 进行多主机通信：

![编织您的容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00020.jpeg)

在`$HOST1`上，我们运行以下命令：

```
# weave launch
# eval $(weave proxy-env)
# docker run --name c1 -ti ubuntu

```

接下来，我们在`$HOST2`上重复类似的步骤：

```
# weave launch $HOST1
# eval $(weave proxy-env)
# docker run --name c2 -ti ubuntu

```

在`$HOST1`上启动的容器中，生成以下输出：

```
root@c1:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:21
 inet addr:172.17.0.33  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:21/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:38 errors:0 dropped:0 overruns:0 frame:0
 TX packets:34 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:3166 (3.1 KB)  TX bytes:2299 (2.2 KB)
ethwe     Link encap:Ethernet  HWaddr aa:99:8a:d5:4d:d4
 inet addr:10.128.0.3  Bcast:0.0.0.0  Mask:255.192.0.0
 inet6 addr: fe80::a899:8aff:fed5:4dd4/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:65535  Metric:1
 RX packets:130 errors:0 dropped:0 overruns:0 frame:0
 TX packets:74 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:11028 (11.0 KB)  TX bytes:6108 (6.1 KB)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

您可以使用`ifconfig`命令查看编织网络接口`ethwe`：

```
root@c2:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:04
 inet addr:172.17.0.4  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:4/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:28 errors:0 dropped:0 overruns:0 frame:0
 TX packets:29 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:2412 (2.4 KB)  TX bytes:2016 (2.0 KB)
ethwe     Link encap:Ethernet  HWaddr 8e:7c:17:0d:0e:03
 inet addr:10.160.0.1  Bcast:0.0.0.0  Mask:255.192.0.0
 inet6 addr: fe80::8c7c:17ff:fe0d:e03/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:65535  Metric:1
 RX packets:139 errors:0 dropped:0 overruns:0 frame:0
 TX packets:74 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:11718 (11.7 KB)  TX bytes:6108 (6.1 KB)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

#root@c1:/# ping -c 1 -q c2
PING c2.weave.local (10.160.0.1) 56(84) bytes of data.
--- c2.weave.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.317/1.317/1.317/0.000 ms

```

同样，在`$HOST2`上启动的容器中，生成以下输出：

```
#root@c2:/# ping -c 1 -q c1
PING c1.weave.local (10.128.0.3) 56(84) bytes of data.
--- c1.weave.local ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.658/1.658/1.658/0.000 ms

```

所以我们有了—两个容器在不同的主机上愉快地交流。

# Open vSwitch

Docker 默认使用 Linux 桥`docker0`。但是，在某些情况下，可能需要使用**Open vSwitch**（**OVS**）而不是 Linux 桥。单个 Linux 桥只能处理 1024 个端口-这限制了 Docker 的可扩展性，因为我们只能创建 1024 个容器，每个容器只有一个网络接口。

## 单主机 OVS

现在我们将在单个主机上安装 OVS，创建两个容器，并将它们连接到 OVS 桥。

使用此命令安装 OVS：

```
# sudo apt-get install openvswitch-switch

```

使用以下命令安装`ovs-docker`实用程序：

```
# cd /usr/bin
# wget https://raw.githubusercontent.com/openvswitch/ovs/master/utilities/ovs-docker
# chmod a+rwx ovs-docker

```

以下图显示了单主机 OVS：

![单主机 OVS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00021.jpeg)

### 创建 OVS 桥

在这里，我们将添加一个新的 OVS 桥并对其进行配置，以便我们可以在不同的网络上连接容器，如下所示：

```
# ovs-vsctl add-br ovs-br1
# ifconfig ovs-br1 173.16.1.1 netmask 255.255.255.0 up

```

将一个端口从 OVS 桥添加到 Docker 容器，使用以下步骤：

1.  创建两个 Ubuntu Docker 容器：

```
# docker run -I -t --name container1 ubuntu /bin/bash
# docekr run -I -t --name container2 ubuntu /bin/bash

```

1.  将容器连接到 OVS 桥：

```
# ovs-docker add-port ovs-br1 eth1 container1 --ipaddress=173.16.1.2/24
# ovs-docker add-port ovs-br1 eth1 container2 --ipaddress=173.16.1.3/24

```

1.  使用`ping`命令测试通过 OVS 桥连接的两个容器之间的连接。首先找出它们的 IP 地址：

```
# docker exec container1 ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:10:11:02
 inet addr:172.16.17.2  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:acff:fe10:1102/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1472  Metric:1
 RX packets:36 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:4956 (4.9 KB)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

# docker exec container2 ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:10:11:03
 inet addr:172.16.17.3  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:acff:fe10:1103/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1472  Metric:1
 RX packets:27 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:4201 (4.2 KB)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

现在我们知道了`container1`和`container2`的 IP 地址，我们可以 ping 它们：

```
# docker exec container2 ping 172.16.17.2
PING 172.16.17.2 (172.16.17.2) 56(84) bytes of data.
64 bytes from 172.16.17.2: icmp_seq=1 ttl=64 time=0.257 ms
64 bytes from 172.16.17.2: icmp_seq=2 ttl=64 time=0.048 ms
64 bytes from 172.16.17.2: icmp_seq=3 ttl=64 time=0.052 ms

# docker exec container1 ping 172.16.17.2
PING 172.16.17.2 (172.16.17.2) 56(84) bytes of data.
64 bytes from 172.16.17.2: icmp_seq=1 ttl=64 time=0.060 ms
64 bytes from 172.16.17.2: icmp_seq=2 ttl=64 time=0.035 ms
64 bytes from 172.16.17.2: icmp_seq=3 ttl=64 time=0.031 ms

```

## 多主机 OVS

让我们看看如何使用 OVS 连接多个主机上的 Docker 容器。

让我们考虑一下我们的设置，如下图所示，其中包含两个主机，**主机 1**和**主机 2**，运行 Ubuntu 14.04：

![多主机 OVS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00022.jpeg)

在两个主机上安装 Docker 和 Open vSwitch：

```
# wget -qO- https://get.docker.com/ | sh
# sudo apt-get install openvswitch-switch

```

安装`ovs-docker`实用程序：

```
# cd /usr/bin
# wget https://raw.githubusercontent.com/openvswitch/ovs/master/utilities/ovs-docker
# chmod a+rwx ovs-docker

```

默认情况下，Docker 选择一个随机网络来运行其容器。它创建一个桥，`docker0`，并为其分配一个 IP 地址（`172.17.42.1`）。因此，**主机 1**和**主机 2**的`docker0`桥 IP 地址相同，这使得两个主机中的容器难以通信。为了克服这个问题，让我们为网络分配静态 IP 地址，即`192.168.10.0/24`。

让我们看看如何更改默认的 Docker 子网。

在主机 1 上执行以下命令：

```
# service docker stop
# ip link set dev docker0 down
# ip addr del 172.17.42.1/16 dev docker0
# ip addr add 192.168.10.1/24 dev docker0
# ip link set dev docker0 up
# ip addr show docker0
# service docker start

```

添加`br0` OVS 桥：

```
# ovs-vsctl add-br br0

```

创建到其他主机的隧道并将其附加到：

```
# add-port br0 gre0 -- set interface gre0 type=gre options:remote_ip=30.30.30.8

```

将`br0`桥添加到`docker0`桥：

```
# brctl addif docker0 br0

```

在主机 2 上执行以下命令：

```
# service docker stop
# iptables -t nat -F POSTROUTING
# ip link set dev docker0 down
# ip addr del 172.17.42.1/16 dev docker0
# ip addr add 192.168.10.2/24 dev docker0
# ip link set dev docker0 up
# ip addr show docker0
# service docker start

```

添加`br0` OVS 桥：

```
# ip link set br0 up
# ovs-vsctl add-br br0

```

创建到其他主机的隧道并将其附加到：

```
# br0 bridge ovs-vsctl add-port br0 gre0 -- set interface gre0 type=gre options:remote_ip=30.30.30.7

```

将`br0`桥添加到`docker0`桥：

```
# brctl addif docker0 br0

```

`docker0`桥连接到另一个桥`br0`。这次是一个 OVS 桥。这意味着容器之间的所有流量也通过`br0`路由。

此外，我们需要连接两台主机的网络，容器正在其中运行。为此目的使用 GRE 隧道。该隧道连接到`br0` OVS 桥，结果也连接到`docker0`。

在两台主机上执行上述命令后，您应该能够从两台主机上 ping 通`docker0`桥地址。

在主机 1 上，使用`ping`命令会生成以下输出：

```
# ping 192.168.10.2
PING 192.168.10.2 (192.168.10.2) 56(84) bytes of data.
64 bytes from 192.168.10.2: icmp_seq=1 ttl=64 time=0.088 ms
64 bytes from 192.168.10.2: icmp_seq=2 ttl=64 time=0.032 ms
^C
--- 192.168.10.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.032/0.060/0.088/0.028 ms

```

在主机 2 上，使用`ping`命令会生成以下输出：

```
# ping 192.168.10.1
PING 192.168.10.1 (192.168.10.1) 56(84) bytes of data.
64 bytes from 192.168.10.1: icmp_seq=1 ttl=64 time=0.088 ms
64 bytes from 192.168.10.1: icmp_seq=2 ttl=64 time=0.032 ms
^C
--- 192.168.10.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.032/0.060/0.088/0.028 ms

```

让我们看看如何在两台主机上创建容器。

在主机 1 上，使用以下代码：

```
# docker run -t -i --name container1 ubuntu:latest /bin/bash

```

在主机 2 上，使用以下代码：

```
# docker run -t -i --name container2 ubuntu:latest /bin/bash

```

现在我们可以从`container1` ping 通`container2`。通过这种方式，我们使用 Open vSwitch 连接多台主机上的 Docker 容器。

# 使用覆盖网络进行网络连接 - Flannel

Flannel 是提供给每个主机用于 Docker 容器的子网的虚拟网络层。它与 CoreOS 捆绑在一起，但也可以在其他 Linux OS 上进行配置。Flannel 通过实际连接自身到 Docker 桥来创建覆盖网络，容器连接到该桥，如下图所示。要设置 Flannel，需要两台主机或虚拟机，可以是 CoreOS 或更可取的是 Linux OS，如下图所示：

![使用覆盖网络进行网络连接 - Flannel](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00023.jpeg)

如果需要，可以从 GitHub 克隆 Flannel 代码并在本地构建，如下所示，可以在不同版本的 Linux OS 上进行。它已经预装在 CoreOS 中：

```
# git clone https://github.com/coreos/flannel.git
Cloning into 'flannel'...
remote: Counting objects: 2141, done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 2141 (delta 6), reused 0 (delta 0), pack-reused 2122
Receiving objects: 100% (2141/2141), 4.
Checking connectivity... done.

# sudo docker run -v `pwd`:/opt/flannel -i -t google/golang /bin/bash -c "cd /opt/flannel && ./build"
Building flanneld...

```

可以使用 Vagrant 和 VirtualBox 轻松配置 CoreOS 机器，如下链接中提到的教程：

[`coreos.com/os/docs/latest/booting-on-vagrant.html`](https://coreos.com/os/docs/latest/booting-on-vagrant.html)

创建并登录到机器后，我们将发现使用`etcd`配置自动创建了 Flannel 桥：

```
# ifconfig flannel0
flannel0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1472
 inet 10.1.30.0  netmask 255.255.0.0  destination 10.1.30.0
 unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500 (UNSPEC)
 RX packets 243  bytes 20692 (20.2 KiB)
 RX errors 0  dropped 0  overruns 0  frame 0
 TX packets 304  bytes 25536 (24.9 KiB)
 TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

可以通过查看`subnet.env`来检查 Flannel 环境：

```
# cat /run/flannel/subnet.env
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.30.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true

```

为了重新实例化 Flannel 桥的子网，需要使用以下命令重新启动 Docker 守护程序：

```
# source /run/flannel/subnet.env
# sudo rm /var/run/docker.pid
# sudo ifconfig docker0 ${FLANNEL_SUBNET}
# sudo docker -d --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU} & INFO[0000] [graphdriver] using prior storage driver "overlay"
INFO[0000] Option DefaultDriver: bridge
INFO[0000] Option DefaultNetwork: bridge
INFO[0000] Listening for HTTP on unix (/var/run/docker.sock)
INFO[0000] Firewalld running: false
INFO[0000] Loading containers: start.
..............
INFO[0000] Loading containers: done.
INFO[0000] Daemon has completed initialization
INFO[0000] Docker daemon
commit=cedd534-dirty execdriver=native-0.2 graphdriver=overlay version=1.8.3

```

也可以通过查看`subnet.env`来检查第二台主机的 Flannel 环境：

```
# cat /run/flannel/subnet.env
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.31.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true

```

为第二台主机分配了不同的子网。也可以通过指向 Flannel 桥来重新启动此主机上的 Docker 服务：

```
# source /run/flannel/subnet.env
# sudo ifconfig docker0 ${FLANNEL_SUBNET}
# sudo docker -d --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU} & INFO[0000] [graphdriver] using prior storage driver "overlay"
INFO[0000] Listening for HTTP on unix (/var/run/docker.sock)
INFO[0000] Option DefaultDriver: bridge
INFO[0000] Option DefaultNetwork: bridge
INFO[0000] Firewalld running: false
INFO[0000] Loading containers: start.
....
INFO[0000] Loading containers: done.
INFO[0000] Daemon has completed initialization
INFO[0000] Docker daemon
commit=cedd534-dirty execdriver=native-0.2 graphdriver=overlay version=1.8.3

```

Docker 容器可以在各自的主机上创建，并且可以使用`ping`命令进行测试，以检查 Flannel 叠加网络的连通性。

对于主机 1，请使用以下命令：

```
#docker run -it ubuntu /bin/bash
INFO[0013] POST /v1.20/containers/create
INFO[0013] POST /v1.20/containers/1d1582111801c8788695910e57c02fdba593f443c15e2f1db9174ed9078db809/attach?stderr=1&stdin=1&stdout=1&stream=1
INFO[0013] POST /v1.20/containers/1d1582111801c8788695910e57c02fdba593f443c15e2f1db9174ed9078db809/start
INFO[0013] POST /v1.20/containers/1d1582111801c8788695910e57c02fdba593f443c15e2f1db9174ed9078db809/resize?h=44&w=80

root@1d1582111801:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:0a:01:1e:02
 inet addr:10.1.30.2  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:aff:fe01:1e02/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1472  Metric:1
 RX packets:11 errors:0 dropped:0 overruns:0 frame:0
 TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:969 (969.0 B)  TX bytes:508 (508.0 B)
lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

对于主机 2，请使用以下命令：

```
# docker run -it ubuntu /bin/bash
root@ed070166624a:/# ifconfig
eth0       Link encap:Ethernet  HWaddr 02:42:0a:01:1f:02
 inet addr:10.1.31.2  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:aff:fe01:1f02/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1472  Metric:1
 RX packets:18 errors:0 dropped:2 overruns:0 frame:0
 TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1544 (1.5 KB)  TX bytes:598 (598.0 B)
lo         Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
root@ed070166624a:/# ping 10.1.30.2
PING 10.1.30.2 (10.1.30.2) 56(84) bytes of data.
64 bytes from 10.1.30.2: icmp_seq=1 ttl=60 time=3.61 ms
64 bytes from 10.1.30.2: icmp_seq=2 ttl=60 time=1.38 ms
64 bytes from 10.1.30.2: icmp_seq=3 ttl=60 time=0.695 ms
64 bytes from 10.1.30.2: icmp_seq=4 ttl=60 time=1.49 ms

```

因此，在上面的例子中，我们可以看到 Flannel 通过在每个主机上运行`flanneld`代理来减少的复杂性，该代理负责从预配置的地址空间中分配子网租约。Flannel 在内部使用`etcd`来存储网络配置和其他细节，例如主机 IP 和分配的子网。数据包的转发是使用后端策略实现的。

Flannel 还旨在解决在 GCE 以外的云提供商上部署 Kubernetes 时的问题，Flannel 叠加网格网络可以通过为每个服务器创建一个子网来简化为每个 pod 分配唯一 IP 地址的问题。

# 总结

在本章中，我们了解了 Docker 容器如何使用不同的网络选项（如 Weave、OVS 和 Flannel）在多个主机之间进行通信。Pipework 使用传统的 Linux 桥接，Weave 创建虚拟网络，OVS 使用 GRE 隧道技术，而 Flannel 为每个主机提供单独的子网，以便将容器连接到多个主机。一些实现，如 Pipework，是传统的，并将随着时间的推移而过时，而其他一些则设计用于在特定操作系统的上下文中使用，例如 Flannel 与 CoreOS。

以下图表显示了 Docker 网络选项的基本比较：

![Summary](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00024.jpeg)

在下一章中，我们将讨论在使用 Kubernetes、Docker Swarm 和 Mesosphere 等框架时，Docker 容器是如何进行网络连接的。


# 第四章：Docker 集群中的网络

在本章中，您将学习在使用 Kubernetes、Docker Swarm 和 Mesosphere 等框架时，Docker 容器是如何进行网络化的。

我们将涵盖以下主题：

+   Docker Swarm

+   Kubernetes

+   Kubernetes 集群中的网络化容器

+   Kubernetes 网络与 Docker 网络的不同之处

+   在 AWS 上的 Kubernetes

+   Mesosphere

# Docker Swarm

Docker Swarm 是 Docker 的本地集群系统。Docker Swarm 公开标准的 Docker API，以便与 Docker 守护程序通信的任何工具也可以与 Docker Swarm 通信。基本目标是允许一起创建和使用一组 Docker 主机。Swarm 的集群管理器根据集群中的可用资源调度容器。我们还可以在部署容器时指定受限资源。Swarm 旨在通过将容器打包到主机上来保存其他主机资源，以便为更重和更大的容器而不是将它们随机调度到集群中的主机。

与其他 Docker 项目类似，Docker Swarm 使用即插即用架构。Docker Swarm 提供后端服务来维护您的 Swarm 集群中的 IP 地址列表。有几种服务，如 etcd、Consul 和 Zookeeper；甚至可以使用静态文件。Docker Hub 还提供托管的发现服务，用于 Docker Swarm 的正常配置。

Docker Swarm 调度使用多种策略来对节点进行排名。当创建新容器时，Swarm 根据最高计算出的排名将其放置在节点上，使用以下策略：

1.  **Spread**：这根据节点上运行的容器数量来优化和调度容器

1.  **Binpack**：选择节点以基于 CPU 和 RAM 利用率来调度容器

1.  **随机策略**：这不使用计算；它随机选择节点来调度容器

Docker Swarm 还使用过滤器来调度容器，例如：

+   **Constraints**：这些使用与节点关联的键/值对，例如`environment=production`

+   **亲和力过滤器**：这用于运行一个容器，并指示它基于标签、镜像或标识符定位并运行在另一个容器旁边

+   **端口过滤器**：在这种情况下，选择节点是基于其上可用的端口

+   **依赖过滤器**：这会在同一节点上协同调度依赖容器

+   **健康过滤器**：这可以防止在不健康的节点上调度容器

以下图解释了 Docker Swarm 集群的各个组件：

![Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00025.jpeg)

## Docker Swarm 设置

让我们设置我们的 Docker Swarm 设置，其中将有两个节点和一个主节点。

我们将使用 Docker 客户端来访问 Docker Swarm 集群。Docker 客户端可以在一台机器或笔记本上设置，并且应该可以访问 Swarm 集群中的所有机器。

在所有三台机器上安装 Docker 后，我们将从命令行重新启动 Docker 服务，以便可以从本地 TCP 端口 2375（`0.0.0.0:2375`）或特定主机 IP 地址访问，并且可以使用 Unix 套接字在所有 Swarm 节点上允许连接，如下所示：

```
$ docker -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock –d &

```

Docker Swarm 镜像需要部署为 Docker 容器在主节点上。在我们的示例中，主节点的 IP 地址是`192.168.59.134`。请将其替换为您的 Swarm 主节点。从 Docker 客户端机器上，我们将使用以下命令在主节点上安装 Docker Swarm：

```
$ sudo docker -H tcp://192.168.59.134:2375 run --rm swarm create
Unable to find image 'swarm' locally
Pulling repository swarm
e12f8c5e4c3b: Download complete
cf43a42a05d1: Download complete
42c4e5c90ee9: Download complete
22cf18566d05: Download complete
048068586dc5: Download complete
2ea96b3590d8: Download complete
12a239a7cb01: Download complete
26b910067c5f: Download complete
4fdfeb28bd618291eeb97a2096b3f841

```

在执行命令后生成的 Swarm 令牌应予以注意，因为它将用于 Swarm 设置。在我们的案例中，它是这样的：

```
"4fdfeb28bd618291eeb97a2096b3f841"

```

以下是设置两节点 Docker Swarm 集群的步骤：

1.  从 Docker 客户端节点，需要执行以下`docker`命令，使用 Node 1 的 IP 地址（在我们的案例中为`192.168.59.135`）和在前面的代码中生成的 Swarm 令牌，以便将其添加到 Swarm 集群中：

```
$ docker -H tcp://192.168.59.135:2375 run -d swarm join --addr=192.168.59.135:2375 token:// 4fdfeb28bd618291eeb97a2096b3f841
Unable to find image 'swarm' locally
Pulling repository swarm
e12f8c5e4c3b: Download complete
cf43a42a05d1: Download complete
42c4e5c90ee9: Download complete
22cf18566d05: Download complete
048068586dc5: Download complete
2ea96b3590d8: Download complete
12a239a7cb01: Download complete
26b910067c5f: Download complete
e4f268b2cc4d896431dacdafdc1bb56c98fed01f58f8154ba13908c7e6fe675b

```

1.  通过用 Node 2 的 IP 地址替换 Node 1 的 IP 地址，重复上述步骤来为 Node 2 执行相同的操作。

1.  需要在 Docker 客户端节点上使用以下命令在主节点上设置 Swarm 管理器：

```
$ sudo docker -H tcp://192.168.59.134:2375 run -d -p 5001:2375 swarm manage token:// 4fdfeb28bd618291eeb97a2096b3f841
f06ce375758f415614dc5c6f71d5d87cf8edecffc6846cd978fe07fafc3d05d3

```

Swarm 集群已设置，并且可以使用驻留在主节点上的 Swarm 管理器进行管理。要列出所有节点，可以使用 Docker 客户端执行以下命令：

```
$ sudo docker -H tcp://192.168.59.134:2375 run --rm swarm list \ token:// 4fdfeb28bd618291eeb97a2096b3f841
192.168.59.135:2375
192.168.59.136:2375

```

1.  以下命令可用于获取有关集群的信息：

```
$ sudo docker -H tcp://192.168.59.134:5001 info
Containers: 0
Strategy: spread
Filters: affinity, health, constraint, port, dependency
Nodes: 2
agent-1: 192.168.59.136:2375
 └ Containers: 0
 └ Reserved CPUs: 0 / 8
 └ Reserved Memory: 0 B / 1.023 GiB
 agent-0: 192.168.59.135:2375
 └ Containers: 0
 └ Reserved CPUs: 0 / 8
 └ Reserved Memory: 0 B / 1.023 GiB

```

1.  可以通过指定名称为`swarm-ubuntu`并使用以下命令，在集群上启动测试`ubuntu`容器：

```
$ sudo docker -H tcp://192.168.59.134:5001 run -it --name swarm-ubuntu ubuntu /bin/sh

```

1.  可以使用 Swarm 主节点的 IP 地址列出容器：

```
$ sudo docker -H tcp://192.168.59.134:5001 ps

```

这样就完成了两节点 Docker Swarm 集群的设置。

## Docker Swarm 网络设置

Docker Swarm 网络与 libnetwork 集成，甚至支持覆盖网络。libnetwork 提供了一个 Go 实现来连接容器；它是一个强大的容器网络模型，为应用程序和容器的编程接口提供网络抽象。Docker Swarm 现在完全兼容 Docker 1.9 中的新网络模型（请注意，我们将在以下设置中使用 Docker 1.9）。覆盖网络需要键值存储，其中包括发现、网络、IP 地址和更多信息。

在以下示例中，我们将使用 Consul 更好地了解 Docker Swarm 网络：

1.  我们将使用`docker-machine`提供一个名为`sample-keystore`的 VirtualBox 机器：

```
$ docker-machine create -d virtualbox sample-keystore
Running pre-create checks...
Creating machine...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Provisioning created instance...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
To see how to connect Docker to this machine, run: docker-machine.exe env sample-keystore

```

1.  我们还将在`sample-keystore`机器上使用以下命令在端口`8500`部署`progrium/consul`容器：

```
$ docker $(docker-machine config sample-keystore) run -d \
 -p "8500:8500" \
 -h "consul" \
 progrium/consul -server –bootstrap
Unable to find image 'progrium/consul:latest' locally
latest: Pulling from progrium/consul
3b4d28ce80e4: Pull complete
e5ab901dcf2d: Pull complete
30ad296c0ea0: Pull complete
3dba40dec256: Pull complete
f2ef4387b95e: Pull complete
53bc8dcc4791: Pull complete
75ed0b50ba1d: Pull complete
17c3a7ed5521: Pull complete
8aca9e0ecf68: Pull complete
4d1828359d36: Pull complete
46ed7df7f742: Pull complete
b5e8ce623ef8: Pull complete
049dca6ef253: Pull complete
bdb608bc4555: Pull complete
8b3d489cfb73: Pull complete
c74500bbce24: Pull complete
9f3e605442f6: Pull complete
d9125e9e799b: Pull complete
Digest: sha256:8cc8023462905929df9a79ff67ee435a36848ce7a10f18d6d0faba9306b97274
Status: Downloaded newer image for progrium/consul:latest
1a1be5d207454a54137586f1211c02227215644fa0e36151b000cfcde3b0df7c

```

1.  将本地环境设置为`sample-keystore`机器：

```
$ eval "$(docker-machine env sample-keystore)"

```

1.  我们可以按以下方式列出 consul 容器：

```
$ docker ps
CONTAINER ID       IMAGE           COMMAND           CREATED       STATUS        PORTS                                 NAMES
1a1be5d20745   progrium/consul  /bin/start -server  5 minutes ago  Up 5 minutes   53/tcp, 53/udp, 8300-8302/tcp, 8400/tcp, 8301-8302/udp, 0.0.0.0:8500->8500/tcp   cocky_bhaskara

```

1.  使用`docker-machine`创建 Swarm 集群。两台机器可以在 VirtualBox 中创建；一台可以充当 Swarm 主节点。在创建每个 Swarm 节点时，我们将传递 Docker Engine 所需的选项以具有覆盖网络驱动程序：

```
$ docker-machine create -d virtualbox --swarm --swarm-image="swarm" --swarm-master --swarm-discovery="consul://$(docker-machine ip sample-keystore):8500" --engine-opt="cluster-store=consul://$(docker-machine ip sample-keystore):8500" --engine-opt="cluster-advertise=eth1:2376" swarm-master
Running pre-create checks...
Creating machine...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Provisioning created instance...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Configuring swarm...
To see how to connect Docker to this machine, run: docker-machine env swarm-master

```

在前面的命令中使用的参数如下：

+   `--swarm`：用于配置具有 Swarm 的机器。

+   `--engine-opt`：此选项用于定义必须提供的任意守护程序选项。在我们的情况下，我们将在创建时使用`--cluster-store`选项，告诉引擎覆盖网络可用性的键值存储的位置。`--cluster-advertise`选项将在特定端口将机器放入网络中。

+   `--swarm-discovery`：用于发现与 Swarm 一起使用的服务，在我们的情况下，`consul`将是该服务。

+   `--swarm-master`：用于将机器配置为 Swarm 主节点。

1.  还可以创建另一个主机并将其添加到 Swarm 集群，就像这样：

```
$ docker-machine create -d virtualbox --swarm --swarm-image="swarm:1.0.0-rc2" --swarm-discovery="consul://$(docker-machine ip sample-keystore):8500" --engine-opt="cluster-store=consul://$(docker-machine ip sample-keystore):8500" --engine-opt="cluster-advertise=eth1:2376" swarm-node-1
Running pre-create checks...
Creating machine...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Provisioning created instance...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Configuring swarm...
To see how to connect Docker to this machine, run: docker-machine env swarm-node-1

```

1.  可以按以下方式列出机器：

```
$ docker-machine ls
NAME            ACTIVE   DRIVER       STATE     URL               SWARM
sample-keystore   -     virtualbox   Running   tcp://192.168.99.100:2376
swarm-master      -     virtualbox   Running   tcp://192.168.99.101:2376  swarm-master (master)
swarm-node-1      -     virtualbox   Running   tcp://192.168.99.102:2376   swarm-master

```

1.  现在，我们将将 Docker 环境设置为`swarm-master`：

```
$ eval $(docker-machine env --swarm swarm-master)

```

1.  可以在主节点上执行以下命令以创建覆盖网络并实现多主机网络：

```
$ docker network create –driver overlay sample-net

```

1.  可以使用以下命令在主节点上检查网络桥：

```
$ docker network ls
NETWORK ID         NAME           DRIVER
9f904ee27bf5      sample-net      overlay
7fca4eb8c647       bridge         bridge
b4234109be9b       none            null
cf03ee007fb4       host            host

```

1.  切换到 Swarm 节点时，我们可以轻松地列出新创建的覆盖网络，就像这样：

```
$ eval $(docker-machine env swarm-node-1)
$ docker network ls
NETWORK ID        NAME            DRIVER
7fca4eb8c647      bridge          bridge
b4234109be9b      none             null
cf03ee007fb4      host            host
9f904ee27bf5     sample-net       overlay

```

1.  创建网络后，我们可以在任何主机上启动容器，并且它将成为网络的一部分：

```
$ eval $(docker-machine env swarm-master)

```

1.  使用约束环境设置为第一个节点启动示例`ubuntu`容器：

```
$ docker run -itd --name=os --net=sample-net --env="constraint:node==swarm-master" ubuntu

```

1.  我们可以使用`ifconfig`命令检查容器是否有两个网络接口，并且可以通过 Swarm 管理器部署的容器在任何其他主机上都可以访问。

# Kubernetes

Kubernetes 是一个容器集群管理工具。目前，它支持 Docker 和 Rocket。这是一个由 Google 支持的开源项目，于 2014 年 6 月在 Google I/O 上推出。它支持在各种云提供商上部署，如 GCE、Azure、AWS 和 vSphere，以及在裸机上部署。Kubernetes 管理器是精简的、可移植的、可扩展的和自愈的。

Kubernetes 有各种重要组件，如下列表所述：

+   **Node**：这是 Kubernetes 集群的物理或虚拟机部分，运行 Kubernetes 和 Docker 服务，可以在其上调度 pod。

+   **Master**：这维护 Kubernetes 服务器运行时的运行状态。这是所有客户端调用的入口点，用于配置和管理 Kubernetes 组件。

+   **Kubectl**：这是用于与 Kubernetes 集群交互的命令行工具，以提供对 Kubernetes API 的主访问权限。通过它，用户可以部署、删除和列出 pod。

+   **Pod**：这是 Kubernetes 中最小的调度单元。它是一组共享卷且没有端口冲突的 Docker 容器集合。可以通过定义一个简单的 JSON 文件来创建它。

+   **复制控制器**：它管理 pod 的生命周期，并确保在给定时间运行指定数量的 pod，通过根据需要创建或销毁 pod。

+   **标签**：标签用于基于键值对识别和组织 pod 和服务。

以下图表显示了 Kubernetes Master/Minion 流程：

![Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00026.jpeg)

## 在 AWS 上部署 Kubernetes

让我们开始在 AWS 上部署 Kubernetes 集群，可以使用 Kubernetes 代码库中已经存在的配置文件来完成：

1.  在[`aws.amazon.com/console/`](http://aws.amazon.com/console/)上登录 AWS 控制台。

1.  在[`console.aws.amazon.com/iam/home?#home`](https://console.aws.amazon.com/iam/home?#home)上打开 IAM 控制台。

1.  选择 IAM 用户名，选择**安全凭证**选项卡，然后单击**创建访问密钥**选项。

1.  创建密钥后，下载并保存在安全的地方。下载的`.csv`文件将包含`访问密钥 ID`和`秘密访问密钥`，这将用于配置 AWS CLI。

1.  安装并配置 AWS CLI。在本例中，我们使用以下命令在 Linux 上安装了 AWS CLI：

```
$ sudo pip install awscli

```

1.  要配置 AWS CLI，请使用以下命令：

```
$ aws configure
AWS Access Key ID [None]: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AWS Secret Access Key [None]: YYYYYYYYYYYYYYYYYYYYYYYYYYYY
Default region name [None]: us-east-1
Default output format [None]: text

```

1.  配置 AWS CLI 后，我们将创建一个配置文件并附加一个角色，该角色具有对 S3 和 EC2 的完全访问权限：

```
$ aws iam create-instance-profile --instance-profile-name Kube

```

1.  可以使用控制台或 AWS CLI 单独创建角色，并使用定义角色权限的 JSON 文件创建角色：

```
$ aws iam create-role --role-name Test-Role --assume-role-policy-document /root/kubernetes/Test-Role-Trust-Policy.json

```

可以将角色附加到上述配置文件，该配置文件将完全访问 EC2 和 S3，如下截图所示：

![在 AWS 上部署 Kubernetes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00027.jpeg)

1.  创建角色后，可以使用以下命令将其附加到策略：

```
$ aws iam add-role-to-instance-profile --role-name Test-Role --instance-profile-name Kube

```

1.  默认情况下，脚本使用默认配置文件。我们可以按照以下方式进行更改：

```
$ export AWS_DEFAULT_PROFILE=Kube

```

1.  Kubernetes 集群可以使用一个命令轻松部署，如下所示：

```
$ export KUBERNETES_PROVIDER=aws; wget -q -O - https://get.k8s.io | bash
Downloading kubernetes release v1.1.1 to /home/vkohli/kubernetes.tar.gz
--2015-11-22 10:39:18--  https://storage.googleapis.com/kubernetes-release/release/v1.1.1/kubernetes.tar.gz
Resolving storage.googleapis.com (storage.googleapis.com)... 216.58.220.48, 2404:6800:4007:805::2010
Connecting to storage.googleapis.com (storage.googleapis.com)|216.58.220.48|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 191385739 (183M) [application/x-tar]
Saving to: 'kubernetes.tar.gz'
100%[======================================>] 191,385,739 1002KB/s   in 3m 7s
2015-11-22 10:42:25 (1002 KB/s) - 'kubernetes.tar.gz' saved [191385739/191385739]
Unpacking kubernetes release v1.1.1
Creating a kubernetes on aws...
... Starting cluster using provider: aws
... calling verify-prereqs
... calling kube-up
Starting cluster using os distro: vivid
Uploading to Amazon S3
Creating kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a
make_bucket: s3://kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a/
+++ Staging server tars to S3 Storage: kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a/devel
upload: ../../../tmp/kubernetes.6B8Fmm/s3/kubernetes-salt.tar.gz to s3://kubernetes-staging-e458a611546dc9dc0f2a2ff2322e724a/devel/kubernetes-salt.tar.gz
Completed 1 of 19 part(s) with 1 file(s) remaining

```

1.  上述命令将调用`kube-up.sh`，然后使用`config-default.sh`脚本调用`utils.sh`，该脚本包含一个具有四个节点的 K8S 集群的基本配置，如下所示：

```
ZONE=${KUBE_AWS_ZONE:-us-west-2a}
MASTER_SIZE=${MASTER_SIZE:-t2.micro}
MINION_SIZE=${MINION_SIZE:-t2.micro}
NUM_MINIONS=${NUM_MINIONS:-4}
AWS_S3_REGION=${AWS_S3_REGION:-us-east-1}

```

1.  实例是运行 Ubuntu OS 的`t2.micro`。该过程需要 5 到 10 分钟，之后主节点和从节点的 IP 地址将被列出，并可用于访问 Kubernetes 集群。

## Kubernetes 网络及其与 Docker 网络的区别

Kubernetes 偏离了默认的 Docker 系统网络模型。其目标是使每个 pod 具有由系统管理命名空间赋予的 IP，该 IP 与系统上的其他物理机器和容器具有完全对应关系。为每个 pod 单元分配 IP 可以创建一个清晰、向后兼容且良好的模型，在这个模型中，可以像处理 VM 或物理主机一样处理单元，从端口分配、系统管理、命名、管理披露、负载平衡、应用程序设计以及从一个主机迁移到另一个主机的 pod 迁移的角度来看。所有 pod 中的所有容器都可以使用它们的地址与所有其他 pod 中的所有其他容器进行通信。这也有助于将传统应用程序转移到面向容器的方法。

由于每个 pod 都有一个真实的 IP 地址，它们可以在彼此之间进行通信，无需进行任何翻译。通过在 pod 内外进行相同的 IP 地址和端口配置，我们可以创建一个无 NAT 的扁平地址空间。这与标准的 Docker 模型不同，因为在那里，所有容器都有一个私有 IP 地址，这将使它们能够访问同一主机上的容器。但在 Kubernetes 的情况下，pod 内的所有容器都表现得好像它们在同一台主机上，并且可以在本地主机上访问彼此的端口。这减少了容器之间的隔离，并提供了简单性、安全性和性能。端口冲突可能是其中的一个缺点；因此，一个 pod 内的两个不同容器不能使用相同的端口。

在 GCE 中，使用 IP 转发和高级路由规则，Kubernetes 集群中的每个 VM 都会额外获得 256 个 IP 地址，以便轻松地在 pod 之间路由流量。

GCE 中的路由允许您在 VM 中实现更高级的网络功能，比如设置多对一 NAT。这被 Kubernetes 所利用。

除了虚拟机具有的主要以太网桥之外，还有一个容器桥`cbr0`，以区分它与 Docker 桥`docker0`。为了将 pod 中的数据包传输到 GCE 环境之外，它应该经历一个 SNAT 到虚拟机的 IP 地址，这样 GCE 才能识别并允许。

其他旨在提供 IP-per-pod 模型的实现包括 Open vSwitch、Flannel 和 Weave。

在类似 GCE 的 Open vSwitch 桥的 Kubernetes 设置中，采用了将 Docker 桥替换为`kbr0`以提供额外的 256 个子网地址的模型。此外，还添加了一个 OVS 桥（`ovs0`），它向 Kubernetes 桥添加了一个端口，以便提供 GRE 隧道来传输不同 minions 上的 pod 之间的数据包。IP-per-pod 模型也在即将出现的图表中有更详细的解释，其中还解释了 Kubernetes 的服务抽象概念。

服务是另一种广泛使用并建议在 Kubernetes 集群中使用的抽象类型，因为它允许一组 pod（应用程序）通过虚拟 IP 地址访问，并且被代理到服务中的所有内部 pod。在 Kubernetes 中部署的应用程序可能使用三个相同 pod 的副本，它们具有不同的 IP 地址。但是，客户端仍然可以访问外部公开的一个 IP 地址上的应用程序，而不管哪个后端 pod 接受请求。服务充当不同副本 pod 之间的负载均衡器，并且对于使用此应用程序的客户端来说是通信的单一点。Kubernetes 的服务之一 Kubeproxy 提供负载均衡，并使用规则访问服务 IP 并将其重定向到正确的后端 pod。

## 部署 Kubernetes pod

现在，在以下示例中，我们将部署两个 nginx 复制 pod（`rc-pod`）并通过服务公开它们，以便了解 Kubernetes 网络。决定应用程序可以通过虚拟 IP 地址公开以及请求应该代理到哪个 pod 副本（负载均衡器）由**服务代理**负责。有关更多详细信息，请参考以下图表：

![部署 Kubernetes pod](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00028.jpeg)

部署 Kubernetes pod 的步骤如下：

1.  在 Kubernetes 主节点上，创建一个新文件夹：

```
$ mkdir nginx_kube_example
$ cd nginx_kube_example

```

1.  在您选择的编辑器中，创建将用于部署 nginx pod 的`.yaml`文件：

```
$ vi nginx_pod.yaml

```

将以下内容复制到文件中：

```
apiVersion: v1
kind: ReplicationController
metadata:
 name: nginx
spec:
 replicas: 2
 selector:
 app: nginx
 template:
 metadata:
 name: nginx
 labels:
 app: nginx
 spec:
 containers:
 - name: nginx
 image: nginx
 ports:
 - containerPort: 80

```

1.  使用`kubectl`创建 nginx pod：

```
$ kubectl create -f nginx_pod.yaml

```

1.  在前面的 pod 创建过程中，我们创建了两个 nginx pod 的副本，并且可以使用以下命令列出其详细信息：

```
$ kubectl get pods

```

生成的输出如下：

```
NAME          READY     REASON    RESTARTS   AGE
nginx-karne   1/1       Running   0          14s
nginx-mo5ug   1/1       Running   0          14s

```

要列出集群上的复制控制器，请使用`kubectl get`命令：

```
$ kubectl get rc

```

生成的输出如下：

```
CONTROLLER   CONTAINER(S)   IMAGE(S)   SELECTOR    REPLICAS
nginx        nginx          nginx      app=nginx   2

```

1.  可以使用以下命令列出部署的 minion 上的容器：

```
$ docker ps

```

生成的输出如下：

```
CONTAINER ID        IMAGE                                   COMMAND                CREATED             STATUS              PORTS               NAMES
1d3f9cedff1d        nginx:latest                            "nginx -g 'daemon of   41 seconds ago      Up 40 seconds       k8s_nginx.6171169d_nginx-karne_default_5d5bc813-3166-11e5-8256-ecf4bb2bbd90_886ddf56
0b2b03b05a8d        nginx:latest                            "nginx -g 'daemon of   41 seconds ago      Up 40 seconds

```

1.  使用以下`.yaml`文件部署 nginx 服务以在主机端口`82`上公开 nginx pod：

```
$ vi nginx_service.yaml

```

将以下内容复制到文件中：

```
apiVersion: v1
kind: Service
metadata:
 labels:
 name: nginxservice
 name: nginxservice
spec:
 ports:
 # The port that this service should serve on.
 - port: 82
 # Label keys and values that must match in order to receive traffic for this service.
 selector:
 app: nginx
 type: LoadBalancer

```

1.  使用`kubectl create`命令创建 nginx 服务：

```
$kubectl create -f nginx_service.yaml
services/nginxservice

```

1.  可以使用以下命令列出 nginx 服务：

```
$ kubectl get services

```

生成的输出如下：

```
NAME           LABELS                                    SELECTOR    IP(S)          PORT(S)
kubernetes     component=apiserver,provider=kubernetes   <none>      192.168.3.1    443/TCP
nginxservice   name=nginxservice                         app=nginx   192.168.3.43   82/TCP

```

1.  现在，可以通过服务在以下 URL 上访问 nginx 服务器的测试页面：

`http://192.168.3.43:82`

# Mesosphere

Mesosphere 是一个软件解决方案，提供了管理服务器基础设施的方法，并基本上扩展了 Apache Mesos 的集群管理能力。Mesosphere 还推出了**DCOS**（**数据中心操作系统**），用于通过将所有机器跨越并将它们视为单台计算机来管理数据中心，提供了一种高度可扩展和弹性的部署应用程序的方式。DCOS 可以安装在任何公共云或您自己的私有数据中心，从 AWS、GCE 和 Microsoft Azure 到 VMware。Marathon 是 Mesos 的框架，旨在启动和运行应用程序；它用作 init 系统的替代品。Marathon 提供了诸如高可用性、应用程序健康检查和服务发现等各种功能，帮助您在 Mesos 集群环境中运行应用程序。

本节描述了如何启动单节点 Mesos 集群。

## Docker 容器

Mesos 可以使用 Marathon 框架来运行和管理 Docker 容器。

在本练习中，我们将使用 CentOS 7 来部署 Mesos 集群。

1.  使用以下命令安装 Mesosphere 和 Marathon：

```
# sudo rpm -Uvh http://repos.mesosphere.com/el/7/noarch/RPMS/mesosphere-el-repo-7-1.noarch.rpm
# sudo yum -y install mesos marathon

```

Apache Mesos 使用 Zookeeper 进行操作。Zookeeper 在 Mesosphere 架构中充当主选举服务，并为 Mesos 节点存储状态。

1.  通过指向 Zookeeper 的 RPM 存储库来安装 Zookeeper 和 Zookeeper 服务器包，如下所示：

```
# sudo rpm -Uvh http://archive.cloudera.com/cdh4/one-click-install/redhat/6/x86_64/cloudera-cdh-4-0.x86_64.rpm
# sudo yum -y install zookeeper zookeeper-server

```

1.  通过停止和重新启动 Zookeeper 来验证 Zookeeper：

```
# sudo service zookeeper-server stop
# sudo service zookeeper-server start

```

Mesos 使用简单的架构，在集群中智能地分配任务，而不用担心它们被安排在哪里。

1.  通过启动`mesos-master`和`mesos-slave`进程来配置 Apache Mesos，如下所示：

```
# sudo service mesos-master start
# sudo service mesos-slave start

```

1.  Mesos 将在端口`5050`上运行。如下截图所示，您可以使用您机器的 IP 地址访问 Mesos 界面，这里是`http://192.168.10.10:5050`：![Docker containers](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00029.jpeg)

1.  使用`mesos-execute`命令测试 Mesos：

```
# export MASTER=$(mesos-resolve `cat /etc/mesos/zk` 2>/dev/null)
# mesos help
# mesos-execute --master=$MASTER --name="cluster-test" --command="sleep 40"

```

1.  运行`mesos-execute`命令后，输入*Ctrl* + *Z*以暂停命令。您可以看到它在 Web UI 和命令行中的显示方式：

```
# hit ctrl-z
# mesos ps --master=$MASTER

```

Mesosphere 堆栈使用 Marathon 来管理进程和服务。它用作传统 init 系统的替代品。它简化了在集群环境中运行应用程序。下图显示了带有 Marathon 的 Mesosphere 主从拓扑结构：

![Docker containers](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00030.jpeg)

Marathon 可以用来启动其他 Mesos 框架；因为它设计用于长时间运行的应用程序，它将确保它启动的应用程序即使在它们运行的从节点失败时也会继续运行。

1.  使用以下命令启动 Marathon 服务：

```
# sudo service marathon start

```

您可以在`http://192.168.10.10:8080`上查看 Marathon GUI。

## 使用 Docker 部署 web 应用

在这个练习中，我们将安装一个简单的 Outyet web 应用程序：

1.  使用以下命令安装 Docker：

```
# sudo yum install -y golang git device-mapper-event-libs docker
# sudo chkconfig docker on
# sudo service docker start
# export GOPATH=~/go
# go get github.com/golang/example/outyet
# cd $GOPATH/src/github.com/golang/example/outyet
# sudo docker build -t outyet.

```

1.  在将其添加到 Marathon 之前，使用以下命令测试 Docker 文件：

```
# sudo docker run --publish 6060:8080 --name test --rm outyet

```

1.  在浏览器中转到`http://192.168.10.10:6060/`以确认它是否正常工作。一旦确认，您可以按下*CTRL* + *C*退出 Outyet Docker。

1.  使用 Marathon Docker 支持创建 Marathon 应用程序，如下所示：

```
# vi /home/user/outyet.json
{
 "id": "outyet",
 "cpus": 0.2,
 "mem": 20.0,
 "instances": 1,
 "constraints": [["hostname", "UNIQUE", ""]],
 "container": {
 "type": "DOCKER",
 "docker": {
 "image": "outyet",
 "network": "BRIDGE",
 "portMappings": [ { "containerPort": 8080, "hostPort": 0, "servicePort": 0, "protocol": "tcp" }
 ]
 }
 }
}

# echo 'docker,mesos' | sudo tee /etc/mesos-slave/containerizers
# sudo service mesos-slave restart

```

1.  使用 Marathon Docker 更好地配置和管理容器，如下所示：

```
# curl -X POST http://192.168.10.10:8080/v2/apps -d /home/user/outyet.json -H "Content-type: application/json"

```

1.  您可以在 Marathon GUI 上检查所有应用程序，如下截图所示，网址为`http://192.168.10.10:8080`：![使用 Docker 部署 web 应用](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00031.jpeg)

## 使用 DCOS 在 AWS 上部署 Mesos

在最后一节中，我们将在 AWS 上部署 Mesosphere 的最新版本 DCOS，以便在我们的数据中心管理和部署 Docker 服务：

1.  通过转到导航窗格并在**网络和安全**下选择**密钥对**来在需要部署集群的区域创建 AWS 密钥对：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00032.jpeg)

1.  创建后，可以按以下方式查看密钥，并应将生成的密钥对（.pem）文件存储在安全位置以备将来使用：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00033.jpeg)

1.  可以通过在官方 Mesosphere 网站上选择**1 Master**模板来创建 DCOS 集群：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00034.jpeg)

也可以通过在堆栈部署中提供亚马逊 S3 模板 URL 的链接来完成：

![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00035.jpeg)

1.  点击**下一步**按钮。填写诸如**堆栈名称**和**密钥名称**之类的细节，这些细节是在上一步中生成的：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00036.jpeg)

1.  在点击**创建**按钮之前，请查看细节：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00037.jpeg)

1.  5 到 10 分钟后，Mesos 堆栈将被部署，并且可以在以下截图中显示的 URL 上访问 Mesos UI：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00038.jpeg)

1.  现在，我们将在预先安装了 Python（2.7 或 3.4）和 pip 的 Linux 机器上安装 DCOS CLI，使用以下命令：

```
$ sudo pip install virtualenv
$ mkdir dcos
$ cd dcos
$ curl -O https://downloads.mesosphere.io/dcos-cli/install.sh
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
 Dload  Upload   Total   Spent    Left  Speed
100  3654  100  3654    0     0   3631      0  0:00:01  0:00:01 --:--:--  3635
$ ls
install.sh
$ bash install.sh . http://mesos-dco-elasticl-17lqe4oh09r07-1358461817.us-west-1.elb.amazonaws.com
Installing DCOS CLI from PyPI...
New python executable in /home/vkohli/dcos/bin/python
Installing setuptools, pip, wheel...done.
[core.reporting]: set to 'True'
[core.dcos_url]: set to 'http://mesos-dco-elasticl-17lqe4oh09r07-1358461817.us-west-1.elb.amazonaws.com'
[core.ssl_verify]: set to 'false'
[core.timeout]: set to '5'
[package.cache]: set to '/home/vkohli/.dcos/cache'
[package.sources]: set to '[u'https://github.com/mesosphere/universe/archive/version-1.x.zip']'
Go to the following link in your browser:
https://accounts.mesosphere.com/oauth/authorize?scope=&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&client_id=6a552732-ab9b-410d-9b7d-d8c6523b09a1&access_type=offline
Enter verification code: Skipping authentication.
Enter email address: Skipping email input.
Updating source [https://github.com/mesosphere/universe/archive/version-1.x.zip]
Modify your bash profile to add DCOS to your PATH? [yes/no]  yes
Finished installing and configuring DCOS CLI.
Run this command to set up your environment and to get started:
source ~/.bashrc && dcos help

```

DCOS 帮助文件可以列出如下：

```
$ source ~/.bashrc && dcos help
Command line utility for the Mesosphere Datacenter Operating System (DCOS). The Mesosphere DCOS is a distributed operating system built around Apache Mesos. This utility provides tools for easy management of a DCOS installation.
Available DCOS commands:

 config       Get and set DCOS CLI configuration properties
 help         Display command line usage information
 marathon     Deploy and manage applications on the DCOS
 node         Manage DCOS nodes
 package      Install and manage DCOS packages
 service      Manage DCOS services
 task         Manage DCOS tasks

```

1.  现在，我们将使用 DCOS 包在 Mesos 集群上部署一个 Spark 应用程序，然后更新它。使用`dcos <command> --help`获取详细的命令描述：

```
$ dcos config show package.sources
[
 "https://github.com/mesosphere/universe/archive/version-1.x.zip"
]
$ dcos package update
Updating source [https://github.com/mesosphere/universe/archive/version-1.x.zip]

$ dcos package search
NAME       VERSION            FRAMEWORK     SOURCE             DESCRIPTION
arangodb   0.2.1                True     https://github.com/mesosphere/universe/archive/version-1.x.zip   A distributed free and open-source database with a flexible data model for documents, graphs, and key-values. Build high performance applications using a convenient SQL-like query language or JavaScript extensions.
cassandra  0.2.0-1               True     https://github.com/mesosphere/universe/archive/version-1.x.zip  Apache Cassandra running on Apache Mesos.
chronos    2.4.0                 True     https://github.com/mesosphere/universe/archive/version-1.x.zip  A fault tolerant job scheduler for Mesos which handles dependencies and ISO8601 based schedules.
hdfs       0.1.7                 True     https://github.com/mesosphere/universe/archive/version-1.x.zip  Hadoop Distributed File System (HDFS), Highly Available.
kafka      0.9.2.0               True     https://github.com/mesosphere/universe/archive/version-1.x.zip  Apache Kafka running on top of Apache Mesos.
marathon   0.11.1                True     https://github.com/mesosphere/universe/archive/version-1.x.zip  A cluster-wide init and control system for services in cgroups or Docker containers.
spark      1.5.0-multi-roles-v2  True     https://github.com/mesosphere/universe/archive/version-1.x.zip  Spark is a fast and general cluster computing system for Big Data.

```

1.  Spark 包可以按以下方式安装：

```
$ dcos package install spark
Note that the Apache Spark DCOS Service is beta and there may be bugs, incomplete features, incorrect documentation or other discrepancies.
We recommend a minimum of two nodes with at least 2 CPU and 2GB of RAM available for the Spark Service and running a Spark job.
Note: The Spark CLI may take up to 5min to download depending on your connection.
Continue installing? [yes/no] yes
Installing Marathon app for package [spark] version [1.5.0-multi-roles-v2]
Installing CLI subcommand for package [spark] version [1.5.0-multi-roles-v2]

```

1.  部署后，可以在 DCOS UI 的**Services**选项卡下看到，如下图所示：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00039.jpeg)

1.  为了在前面的 Marathon 集群上部署一个虚拟的 Docker 应用程序，我们可以使用 JSON 文件来定义容器映像、要执行的命令以及部署后要暴露的端口：

```
$ nano definition.json
{
 "container": {
 "type": "DOCKER",
 "docker": {
 "image": "superguenter/demo-app"
 }
 },
 "cmd":  "python -m SimpleHTTPServer $PORT",
 "id": "demo",
 "cpus": 0.01,
 "mem": 256,
 "ports": [3000]
}

```

1.  应用程序可以添加到 Marathon 并列出如下：

```
$ dcos marathon app add definition.json
$ dcos marathon app list
ID       MEM    CPUS  TASKS  HEALTH  DEPLOYMENT  CONTAINER  CMD
/demo   256.0   0.01   1/1    ---       ---        DOCKER   python -m SimpleHTTPServer $PORT
/spark  1024.0  1.0    1/1    1/1       ---        DOCKER   mv /mnt/mesos/sandbox/log4j.properties conf/log4j.properties && ./bin/spark-class org.apache.spark.deploy.mesos.MesosClusterDispatcher --port $PORT0 --webui-port $PORT1 --master mesos://zk://master.mesos:2181/mesos --zk master.mesos:2181 --host $HOST --name spark

```

1.  可以按以下方式启动前面的 Docker 应用程序的三个实例：

```
$ dcos marathon app update --force demo instances=3
Created deployment 28171707-83c2-43f7-afa1-5b66336e36d7
$ dcos marathon deployment list
APP    ACTION  PROGRESS  ID
/demo  scale     0/1     28171707-83c2-43f7-afa1-5b66336e36d7

```

1.  通过单击**Services**下的**Tasks**选项卡，可以在 DCOS UI 中看到部署的应用程序：![在 AWS 上使用 DCOS 部署 Mesos](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00040.jpeg)

# 摘要

在本章中，我们学习了使用各种框架的 Docker 网络，例如本地 Docker Swarm。使用 libnetwork 或开箱即用的覆盖网络，Swarm 提供了多主机网络功能。

另一方面，Kubernetes 与 Docker 有不同的视角，其中每个 pod 都有一个独特的 IP 地址，并且可以通过服务的帮助在 pod 之间进行通信。使用 Open vSwitch 或 IP 转发和高级路由规则，Kubernetes 网络可以得到增强，以提供在不同子网上的主机之间以及将 pod 暴露给外部世界的连接能力。在 Mesosphere 的情况下，我们可以看到 Marathon 被用作部署容器的网络的后端。在 Mesosphere 的 DCOS 的情况下，整个部署的机器堆栈被视为一个机器，以提供在部署的容器服务之间丰富的网络体验。

在下一章中，我们将通过了解内核命名空间、cgroups 和虚拟防火墙，学习有关基本 Docker 网络的安全性和 QoS。
