# Docker Swarm 原生集群（一）

> 原文：[`zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D`](https://zh.annas-archive.org/md5/9B6C0DB62EFC5AC8A8FAA5F289DFA59D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎来到具有 Swarm 的本地 Docker 集群！这是一本关于容器和分布式系统的书。我们将展示如何使用本地 Docker 工具来建模微服务，生成任务，扩展应用程序的规模，并将容器推送到 Docker 集群的极限！一句话，我们将讨论 Docker 编排。

随着 Swarm Mode 的最近崛起以及在 Docker Engine 内部启用 Swarm，事实证明编排 Docker 的最佳方式是……Docker！

不错，但是“编排 Docker”是什么意思？什么是编排？更好的是，什么是管弦乐队？

![前言](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/preface.jpg)

管弦乐队是由指挥家带领的音乐家组成的合奏团，指挥家指挥着节奏、节奏和声音的形状。弦乐、木管、打击乐、键盘和其他乐器都遵循指挥家的指导来演奏令人惊叹的交响乐，例如贝多芬的第九交响曲。

同样，在容器编排系统中，音乐家是任务，指挥是领导服务（Swarm 原语）。任务不仅仅演奏交响乐，或者至少不仅仅是：更抽象地说，它们执行一些计算工作，例如运行 Web 服务器。指挥家 Swarm 负责它们的配置、可用性、链接和扩展。这（以及更多）就是我们所说的“Docker 编排”。

本书展示了如何配置这样的 Docker“管弦乐队”，如何保证服务的可用性，如何连接任务以及如何扩展平台，以演奏您应用程序的交响乐。

# 本书涵盖内容

第一章，“欢迎来到 Docker Swarm”，介绍了 Swarm，并解释了为什么您需要一个容器的集群解决方案。它说明了 Swarm 的特性，并对其架构进行了高层次的描述。我们定义了一些用例，并描述了 Swarm 与 Fleet、Kubernetes 和 Mesos 的不同之处。本章介绍了 Docker 工具的安装，最后介绍了两个 Swarm 配置：本地 Swarm Standalone 和 DigitalOcean 上的远程 Swarm Mode 集群。

第二章，“发现发现服务”，是一个描述性和大部分抽象的章节。我们将学习发现机制和共识算法是什么，以及它们对分布式系统的重要性。我们将详细描述 Raft 及其实现 Etcd，这是 Swarm 模式中包含的共识机制。我们还将通过使用 Consul 扩展本地微小示例来展示第一章中使用的发现机制的局限性，并重新部署它。

第三章，“了解 Docker Swarm 模式”，讲述了允许创建任意大小任务集群的新 Docker 工具包。我们将介绍 Swarmit，Docker Swarm 模式的基础，展示它在 Docker 1.12+中的工作原理，讨论其架构、概念，以及它与“旧”Swarm 的不同之处，以及它如何通过抽象服务和任务来组织工作负载。

第四章，“创建生产级别的 Swarm”，展示并讨论了由社区驱动的项目 Swarm2k 和 Swarm3k，我们的 2300 和 4800 节点 Swarm 集群实验，其中运行了数十万个容器。我们演示了如何规划、配置这样庞大的集群，并总结了我们所学到的经验教训。

第五章，“管理 Swarm 集群”，是关于基础设施的一章。我们将展示如何增加或减少 Swarm 的大小，如何提升和降级节点，以及如何更新集群和节点属性。我们将介绍 Shipyard 和 Portainer.io 作为 Swarm 的图形用户界面。

第六章，“在 Swarm 上部署真实应用程序”，是我们将在 Swarm 上运行真实应用程序并在讨论中添加一些关于 Compose、Docker Stacks 和 Docker Application Bundles 的注释的地方。我们将展示典型的部署工作流程，如何在集群上过滤和调度容器，将它们作为服务启动，以任务的形式处理容器。我们将开始定义一个带有 Nginx 的 web 服务，然后部署一个必需的带有 MySQL 的 Wordpress 示例。最后，我们将继续使用一个更现实的应用程序：Apache Spark。

第七章，“扩展你的平台”，将从上一章开发新的主题。在这里，我们将介绍 Flocker，为 Spark on Swarm 增加存储容量，并展示如何在与 Swarm 结合的规模上自动安装和使用它。我们将通过运行一些真正的大数据作业和为这个基础设施设置一个基本的监控系统来完善我们的 Spark 示例。

第八章，“探索 Swarm 的其他功能”，讨论了一些对 Swarm 非常重要的高级主题，比如 Libnetwork 和 Libkv。

第九章，“保护 Swarm 集群和 Docker 软件供应链”，将重点讨论 Swarm 集群的安全考虑。其中包括证书、平台防火墙概念，以及对 Notary 的提及。

第十章，“Swarm 和云”，是一章介绍在云提供商上运行 Swarm 的最流行选项。我们将在 AWS 和 Azure 上安装 Swarm，然后介绍 Docker Datacenter，最后我们将转向 OpenStack，展示如何在 Magnum 的顶部安装和管理 Swarm，Magnum 是 OpenStack 的容器即服务解决方案。

第十一章，“接下来是什么？”，通过概述下一个 Docker 编排趋势，比如软件定义基础设施、Infrakit、unikernels、容器即服务，结束了讨论。冒险还在继续！

# 你需要为这本书做些什么

我们假设读者有一些使用 Docker 命令行的经验：在整本书中，我们将不断地拉取镜像、运行容器、定义服务、暴露端口和创建网络。

另外，理想的读者具有对网络协议的基本理解，并熟悉公共和私有云概念，比如虚拟机和租户网络。

为了跟随文本中的示例，你需要 Docker 及其工具。第一章，“欢迎来到 Docker Swarm”，涵盖了它们的安装。

另外，为了从示例中获得最大的收益，你需要访问一个公共（例如 AWS、Azure 或 DigitalOcean）或私有（例如 OpenStack）云来实例化虚拟机。

# 这本书适合谁

这本书是为 Docker 用户 - 开发人员和系统管理员 - 而写的，他们想要利用当前的 Swarm 和 Swarmkit 功能来扩展容器的大规模应用。

# 约定

在这本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些样式的例子及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："当执行 `docker swarm init` 时，只需复制粘贴输出的行"

一块代码设置如下：

```
digitalocean:
      image: “docker-1.12-rc4”
      region: nyc3
      ssh_key_fingerprint: “your SSH ID”
      ssh_user: root
```

任何命令行输入或输出都是这样写的：

```
      **# Set $GOPATH here
      go get https://github.com/chanwit/belt

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，如："UI 具有预期的选项，包括启动容器的模板列表，例如**MySQL**或**私有注册表**，但在撰写本文时尚不支持 Swarm 服务"

### 注意

警告或重要说明会出现在这样的框中。

### 提示

技巧和窍门是这样出现的。


# 第一章：欢迎来到 Docker Swarm

毫无疑问，Docker 是当今最受欢迎的开源技术之一。原因很容易理解，Docker 使容器技术对所有人都可用，并且附带一个可移除的包含电池，并得到了一个充满活力的社区的祝福。

在早期，用户们开始使用 Docker，因为他们被这个易于使用的工具所迷住，这个工具让他们能够解决许多挑战：拉取、打包、隔离和使应用程序在系统之间可移植几乎没有负担。

![欢迎来到 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_001.jpg)

*简化的 Docker 生态系统*

您可能会注意到这里有一群鲸鱼与其他人相处融洽。然而，自容器问世以来，人们一直在寻找有效地编排大量容器的工具。Docker 团队在 2015 年发布了 Docker Swarm，简称 Swarm，作为 Docker 生态系统的一部分，与 Docker Machine 和 Docker Compose 一起发布。前面的图片显示了简化的 Docker 生态系统，其中 Docker Machine 提供了一个新的 Docker-ready 机器，然后一组机器将形成一个 Docker Swarm 集群。稍后，我们将能够使用 Docker Compose 将容器部署到集群中，就像它是一个普通的 Docker Engine 一样。

在 2014 年初，为 Docker 原生地创建一个集群管理系统的计划开始，作为一个名为*Beam*的通信协议项目。后来，它被实现为一个守护进程，用于控制具有 Docker API 的异构分布式系统。该项目已更名为`libswarm`，其守护进程为`Swarmd`。保持允许任何 Docker 客户端连接到一组 Docker 引擎的相同概念，该项目的第三代已经重新设计为使用相同的一组 Docker 远程 API，并于 2014 年 11 月更名为"Swarm"。基本上，Swarm 最重要的部分是其远程 API；维护者们努力保持它们与每个 Docker Engine 版本 100%兼容。我们将第一代 Swarm 称为"Swarm v1"。

2016 年 2 月，核心团队发现了集中式服务的扩展限制后，Swarm 再次在内部重新设计为`swarm.v2`。这一次，采用了分散式集群设计。2016 年 6 月，SwarmKit 作为分布式服务的编排工具包发布。Docker 宣布 SwarmKit 已合并到 Docker Engine 中，该消息是在 DockerCon 2016 上宣布的。我们将称这个版本的 Swarm 为“Swarm v2”或“Swarm 模式”。

正如我们将在后面看到的那样，这三位大侠（Docker Swarm，Docker Machine 和 Docker Compose）在一起运作时效果最佳，它们之间紧密地交织在一起，几乎不可能将它们视为单独的部分。

然而，即使如此，Machine 和 Compose 在其目标上确实非常直接，易于使用和理解，Swarm 是一个确实值得一本书的工具。

使用 Docker Machine，您可以在多个云平台上以及裸机上提供虚拟和物理机器来运行 Docker 容器。使用 Docker Compose，您可以通过使用 YAML 的简单而强大的语法描述行为，并通过“组合”这些文件来启动应用程序。Swarm 是一个强大的集群工具，需要更深入地研究。

在本章中，我们将看一下以下主题：

+   什么是容器编排

+   Docker Swarm 的基本原理和架构

+   与其他开源编排器的区别

+   “旧”Swarm，v1

+   “新”Swarm，Swarm 模式

# 集群工具和容器管理器

集群工具是一种软件，允许操作员与单个端点通信，并命令和*编排*一组资源，在我们的情况下是容器。与手动在集群上分发工作负载（容器）不同，集群工具用于自动化这一过程以及许多其他任务。集群工具将决定*何时*启动作业（容器），*如何*存储它们，*何时*最终重新启动它们等等。操作员只需配置一些行为，决定集群拓扑和大小，调整设置，并启用或禁用高级功能。Docker Swarm 是一个用于容器的集群工具的示例。

除了集群工具之外，还有容器管理平台的选择。它们不提供容器托管，但与一个或多个现有系统进行交互；这种软件通常提供良好的 Web 界面、监控工具和其他视觉或更高级的功能。容器管理平台的示例包括 Rancher 或 Tutum（在 2015 年被 Docker Inc.收购）。

# Swarm 目标

Swarm 被 Docker 本身描述为：

> *Docker Swarm 是 Docker 的本地集群。它将一组 Docker 主机转换为单个虚拟 Docker 主机。*

Swarm 是一个工具，它让您产生管理一个由许多 Docker 主机组成的单一巨大 Docker 主机的幻觉，就好像它们是一个，并且有一个命令入口点。它允许您使用常规的 Docker 工具，在这些主机上编排和操作一定数量的容器，无论是使用 Docker 本机还是 python-docker 客户端，甚至是使用 Docker 远程 API 的 curl。

这是一个在生产中看起来类似的最小的 Swarm 集群：

![Swarm goals](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_002.jpg)

# 为什么使用 Swarm

使用容器的集群解决方案有许多原因。随着您的应用程序增长，您将面临新的强制性要求，如可扩展性、可管理性和高可用性。

有许多可用的工具；选择 Docker Swarm 给我们带来了一些即时的优势：

+   **本地集群**：Swarm 是 Docker 的本地工具，由 Docker 团队和社区制作。其原始创作者是 Andrea Luzzardi 和 Victor Vieux，他们是 Docker Engine Remote API 的早期实施者。Swarm 与 Machine、Compose 和生态系统中的其他工具集成，无需额外要求。

+   **生产级**：Swarm v1 在 2015 年 11 月被宣布成熟，并准备投入生产使用。团队已经证明 Swarm 可以扩展到控制多达 1,000 个节点的引擎。Swarm v2 允许形成具有数千个节点的集群，因为它使用了分散式发现。

+   **开箱即用**：Swarm 不需要您重新设计您的应用程序以适应另一个编排工具。您可以使用您的 Docker 镜像和配置，无需更改即可进行规模部署。

+   **易于设置和使用**：Swarm 易于操作。只需向 Machine 命令添加一些标志或使用 Docker 命令，就可以进行有效的部署，因为 Docker 1.12 版已经集成了发现服务到 Swarm 模式中，使得安装变得迅速：无需设置外部的 Consul、Etcd 或 Zookeeper 集群。

+   **活跃的社区**：Swarm 是一个充满活力的项目，拥有一个非常活跃的社区，并且正在积极开发中。

+   **在 Hub 上可用**：你不需要安装 Swarm，它作为一个 Docker 镜像（Swarm v1）已经准备好了，所以你只需从 Hub 上拉取并运行它，或者集成到 Docker Engine 中。而 Swarm Mode 已经集成到 Docker 1.12+中。就是这样。

# 真实世界的用例示例

Docker Swarm 是几个项目的选择，例如：

+   Rackspace Carina 是建立在 Docker Swarm 之上的：Rackspace 提供托管的容器环境，内部基于 Docker Swarm

+   Zenly 正在使用 Swarm 在 Google Cloud Platform 和裸金属服务器上

+   ADP 使用 Docker 和 Swarm 来加速他们的传统部署

+   Swarm 可以直接在亚马逊 AWS 和微软 Azure 模板上部署到它们的公共云上

## 宠物与牲畜模型

在创建和利用基础设施时有两种相反的方法：宠物与牲畜。

在*宠物*模型中，管理员部署服务器或虚拟机，或者在我们的情况下，容器，并对它们进行管理。她或他登录，安装软件，配置它，并确保一切正常运行。因此，这就是她或他的宠物。

相比之下，管理员并不真正关心基础设施组件的命运，当把它们看作*牲畜*时。她或他不会登录到每个单元或手动处理它，而是使用批量方法，部署、配置和管理都是通过自动化工具完成的。如果服务器或容器死掉，它会自动复活，或者生成另一个来替代已经失效的。因此，操作员正在处理牲畜。

在本书中，我们将在第一章中使用宠物模型来向读者介绍一些基本概念。但是在进行严肃的事情时，我们将在后面采用牲畜模式。

# Swarm 特性

Swarm 的主要目的已经定义好了，但它是如何实现其目标的呢？以下是它的关键特性：

+   Swarm v1 支持 Docker Engine 1.6.0 或更高版本。Swarm v2 已经内置到 Docker Engine 自 1.12 版以来。

+   每个 Swarm 版本的 API 都与相同版本的 Docker API 兼容。API 兼容性向后维护一个版本。

+   在 Swarm v1 中，领导选举机制是使用领导库为多个 Swarm 主节点实现的（只有在部署带有发现服务的 Swarm 时才支持，例如 Etcd、Consul 或 Zookeeper）。

+   在 Swarm v2 中，领导者选举已经使用了分散机制进行构建。Swarm v2 不再需要专门的一组发现服务，因为它集成了 Etcd，这是 Raft 共识算法的实现（参见第二章，“发现发现服务”）。

+   在 Swarm v1 的术语中，领导 Swarm 主节点称为主节点，其他节点称为副本。在 Swarm v2 中，有主节点和工作节点的概念。领导节点由 Raft 集群自动管理。

+   基本和高级调度选项。调度器是一个决定容器必须物理放置在哪些主机上的算法。Swarm 带有一组内置调度器。

+   约束和亲和性让操作员对调度做出决策；例如，有人想要保持数据库容器在地理上靠近，并建议调度器这样做。约束和亲和性使用 Docker Swarm 标签。

+   在 Swarm v2 中，集群内负载平衡是通过内置的 DNS 轮询实现的，同时它支持通过路由网格机制实现的外部负载平衡，该机制是基于 IPVS 实现的。

+   高可用性和故障转移机制意味着您可以创建一个具有多个主节点的 Swarm；因此，如果它们宕机，将有其他主节点准备好接管。当我们形成至少 3 个节点的集群时，默认情况下可用 Swarm v2。所有节点都可以是主节点。此外，Swarm v2 包括健康指示器信息。

# 类似的项目

我们不仅有 Docker Swarm 来对容器进行集群化。为了完整起见，我们将简要介绍最广为人知的开源替代方案，然后完全深入到 Swarm 中。

## Kubernetes

**Kubernetes** ([`kubernetes.io`](http://kubernetes.io))，也被称为**k8s**，旨在实现与 Docker Swarm 相同的目标；它是一个容器集群的管理器。最初作为 Google 实验室的 Borg 项目开始，后来以稳定版本的形式开源并于 2015 年发布，支持**Google Cloud Platform**，**CoreOS**，**Azure**和**vSphere**。

到目前为止，Kubernetes 在 Docker 中运行容器，通过所谓的 Kubelet 通过 API 命令，这是一个注册和管理 Pods 的服务。从架构上讲，Kubernetes 将其集群逻辑上划分为 Pods，而不是裸容器。Pod 是最小的可部署单元，物理上是一个由一个或多个容器组成的应用程序的表示，通常是共同部署的，共享存储和网络等资源（用户可以使用 Compose 在 Docker 中模拟 Pods，并且从 Docker 1.12 开始创建 Docker **DABs**（**分布式应用程序包**））。

Kubernetes 包括一些预期的基本集群功能，如标签、健康检查器、Pods 注册表，具有可配置的调度程序，以及服务，如大使或负载均衡器。

在实践中，Kubernetes 用户利用 kubectl 客户端与 Kubernetes 主控制单元（命令 Kubernetes 节点执行工作的单元，称为 minions）进行交互。Minions 运行 Pods，所有内容都由 Etcd 粘合在一起。

在 Kubernetes 节点上，您会发现一个正在运行的 Docker 引擎，它运行一个 kube-api 容器，以及一个名为`kubelet.service`的系统服务。

有许多直观的 kubectl 命令，比如

+   `kubectl cluster-info`，`kubectl get pods`和`kubectl get nodes`用于检索有关集群及其健康状况的信息

+   `kubectl create -f cassandra.yaml`和任何派生的 Pod 命令，用于创建、管理和销毁 Pods

+   `kubectl scale rc cassandra --replicas=2`用于扩展 Pods 和应用程序

+   `kubectl label pods cassandra env=prod`用于配置 Pod 标签

这只是对 Kubernetes 的一个高层次全景。Kubernetes 和 Docker Swarm 之间的主要区别是：

+   Swarm 的架构更直观易懂。Kubernetes 需要更多的关注，只是为了掌握其基本原理。但学习总是好的！

+   再谈架构：Kubernetes 基于 Pods，Swarm 基于容器和 DABs。

+   您需要安装 Kubernetes。无论是在 GCE 上部署，使用 CoreOS，还是在 OpenStack 上，您都必须小心处理。您必须部署和配置一个 Kubernetes 集群，这需要额外的努力。Swarm 已集成到 Docker 中，无需额外安装。

+   Kubernetes 有一个额外的概念，叫做复制控制器，这是一种技术，确保某些模板描述的所有 Pod 在给定时间内都在运行。

+   Kubernetes 和 Swarm 都使用 Etcd。但在 Kubernetes 中，它被视为外部设施服务，而在 Swarm 中，它是集成的，并在管理节点上运行。

Kubernetes 和 Swarm 之间的性能比较可能会引发争论，我们希望避免这种做法。有一些基准测试显示 Swarm 启动容器的速度有多快，还有一些基准测试显示 Kubernetes 运行其工作负载的速度有多快。我们认为基准测试结果必须始终带有一定的保留态度。也就是说，Kubernetes 和 Swarm 都适合运行大型、快速和可扩展的容器集群。

## CoreOS Fleet

**Fleet** ([`github.com/coreos/fleet`](https://github.com/coreos/fleet))是容器编排器中的另一种可能选择。它来自 CoreOS 容器产品系列（包括 CoreOS、Rocket 和 Flannel），与 Swarm、Kubernetes 和 Mesos 基本不同，因为它被设计为系统的扩展。Fleet 通过调度程序在集群节点之间分配资源和任务。因此，它的目标不仅是提供纯粹的容器集群化，而是成为一个分布式的更一般的处理系统。例如，可以在 Fleet 上运行 Kubernetes。

Fleet 集群由负责调度作业、其他管理操作和代理的引擎组成，这些代理在每个主机上运行，负责执行它们被分配的作业并持续向引擎报告状态。Etcd 是保持一切连接的发现服务。

您可以通过 Fleet 集群的主要命令`fleetctl`与其交互，使用列表、启动和停止容器和服务选项。

因此，总结一下，Fleet 与 Docker Swarm 不同：

+   这是一个更高级的抽象，用于分发任务，而不仅仅是一个容器编排器。

+   将 Fleet 视为集群的分布式初始化系统。Systemd 适用于一个主机，而 Fleet 适用于一组主机。

+   Fleet 专门将一堆 CoreOS 节点集群化。

+   您可以在 Fleet 的顶部运行 Kubernetes，以利用 Fleet 的弹性和高可用性功能。

+   目前没有已知的稳定和强大的方法可以自动集成 Fleet 和 Swarm v1。

+   目前，Fleet 尚未经过测试，无法运行超过 100 个节点和 1000 个容器的集群（[`github.com/coreos/fleet/blob/master/Documentation/fleet-scaling.md`](https://github.com/coreos/fleet/blob/master/Documentation/fleet-scaling.md)），而我们能够运行具有 2300 个和后来 4500 个节点的 Swarm。

## Apache Mesos

无论您将 Fleet 视为集群的分布式初始化系统，您都可以将 Mesos（[`mesos.apache.org/`](https://mesos.apache.org/)）视为*分布式内核*。使用 Mesos，您可以将所有节点的资源都作为一个节点提供，并且在本书的范围内，在它们上运行容器集群。

Mesos 最初于 2009 年在伯克利大学开始，是一个成熟的项目，并且已经成功地在生产中使用，例如 Twitter。

它甚至比 Fleet 更通用，是多平台的（可以在 Linux、OS X 或 Windows 节点上运行），并且能够运行异构作业。您通常可以在 Mesos 上运行容器集群，旁边是纯粹的大数据作业（Hadoop 或 Spark）以及其他作业，包括持续集成、实时处理、Web 应用程序、数据存储，甚至更多。

Mesos 集群由一个 Master、从属和框架组成。正如您所期望的那样，主节点在从属上分配资源和任务，负责系统通信并运行发现服务（ZooKeeper）。但是框架是什么？框架是应用程序。框架由调度程序和执行程序组成，前者分发任务，后者执行任务。

对于我们的兴趣，通常通过一个名为 Marathon 的框架在 Mesos 上运行容器（[`mesosphere.github.io/marathon/docs/native-docker.html`](https://mesosphere.github.io/marathon/docs/native-docker.html)）。

在这里比较 Mesos 和 Docker Swarm 是没有意义的，因为它们很可能可以互补运行，即 Docker Swarm v1 可以在 Mesos 上运行，而 Swarm 的一部分源代码专门用于此目的。相反，Swarm Mode 和 SwarmKit 与 Mesos 非常相似，因为它们将作业抽象为任务，并将它们分组为服务，以在集群上分配负载。我们将在第三章中更好地讨论 SwarmKit 的功能，*了解 Docker Swarm Mode*。

## Kubernetes 与 Fleet 与 Mesos

Kubernetes，Fleet 和 Mesos 试图解决类似的问题；它们为您的资源提供了一个抽象层，并允许您与集群管理器进行接口。然后，您可以启动作业和任务，您选择的项目将对其进行排序。区别在于提供的开箱即用功能以及您可以自定义资源和作业分配和扩展精度的程度。在这三者中，Kubernetes 更加自动化，Mesos 更加可定制，因此从某种角度来看，更加强大（当然，如果您需要所有这些功能）。

Kubernetes 和 Fleet 对许多细节进行了抽象和默认设置，而这些对于 Mesos 来说是需要配置的，例如调度程序。在 Mesos 上，您可以使用 Marathon 或 Chronos 调度程序，甚至编写自己的调度程序。如果您不需要，不想或甚至无法深入研究这些技术细节，您可以选择 Kubernetes 或 Fleet。这取决于您当前和/或预测的工作负载。

## Swarm 与所有

那么，您应该采用哪种解决方案？像往常一样，您有一个问题，开源技术慷慨地提供了许多可以相互交叉帮助您成功实现目标的技术。问题在于如何选择解决问题的方式和方法。Kubernetes，Fleet 和 Mesos 都是强大且有趣的项目，Docker Swarm 也是如此。

在这四个项目中，如果考虑它们的自动化程度和易于理解程度，Swarm 是赢家。这并不总是一个优势，但在本书中，我们将展示 Docker Swarm 如何帮助您使真实的事情运转，要记住，在 DockerCon 的一个主题演讲中，Docker 的 CTO 和创始人 Solomon Hykes 建议*Swarm 将成为一个可以为许多编排和调度框架提供共同接口的层*。

# Swarm v1 架构

本节讨论了 Docker Swarm 的概述架构。Swarm 的内部结构在图 3 中描述。

![Swarm v1 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_003.jpg)

*Docker Swarm v1 的内部结构*

从**管理器**部分开始，你会看到图表左侧标有*Docker Swarm API*的块。如前所述，Swarm 暴露了一组类似于 Docker 的远程 API，这允许您使用任何 Docker 客户端连接到 Swarm。然而，Swarm 的 API 与标准的 Docker 远程 API 略有不同，因为 Swarm 的 API 还包含了与集群相关的信息。例如，对 Docker 引擎运行`docker info`将给出单个引擎的信息，但当我们对 Swarm 集群调用`docker info`时，我们还将得到集群中节点的数量以及每个节点的信息和健康状况。

紧邻 Docker Swarm API 的块是*Cluster Abstraction*。它是一个抽象层，允许不同类型的集群作为 Swarm 的后端实现，并共享相同的 Docker 远程 API 集。目前我们有两种集群后端，内置的 Swarm 集群实现和 Mesos 集群实现。*Swarm 集群*和*内置调度器*块代表内置的 Swarm 集群实现，而由*Mesos 集群*表示的块是 Mesos 集群实现。

Swarm 后端的*内置调度器*配备了多种*调度策略*。其中两种策略是*Spread*和*BinPack*，这将在后面的章节中解释。如果您熟悉 Swarm，您会注意到这里缺少了随机策略。随机策略被排除在解释之外，因为它仅用于测试目的。

除了调度策略，Swarm 还使用一组*Scheduling Filters*来帮助筛选未满足标准的节点。目前有六种过滤器，分别是*Health*、*Port*、*Container Slots*、*Dependency*、*Affinity*和*Constraint*。它们按照这个顺序应用于筛选，当有人在调度新创建的容器时。

在**代理**部分，有 Swarm 代理试图将其引擎的地址注册到发现服务中。

最后，集中式部分**DISCOVERY**是协调代理和管理器之间的引擎地址的。基于代理的 Discovery 服务目前使用 LibKV，它将发现功能委托给您选择的键值存储，如 Consul、Etcd 或 ZooKeeper。相比之下，我们也可以只使用 Docker Swarm 管理器而不使用任何键值存储。这种模式称为无代理发现*，*它是文件和节点（在命令行上指定地址）。

我们将在本章后面使用无代理模型来创建一个最小的本地 Swarm 集群。我们将在第二章中遇到其他发现服务，*发现发现服务*，以及第三章中的 Swarm Mode 架构，*了解 Docker Swarm Mode*。

## 术语

在继续其他部分之前，我们回顾一些与 Docker 相关的术语，以回顾 Docker 概念并介绍 Swarm 关键字。

+   Docker Engine 是在主机上运行的 Docker 守护程序。有时在本书中，我们会简称为 Engine。我们通常通过调用`docker daemon`来启动 Engine，通过 systemd 或其他启动服务。

+   Docker Compose 是一种工具，用于以 YAML 描述多容器服务的架构方式。

+   Docker 堆栈是创建多容器应用程序的镜像的二进制结果（由 Compose 描述），而不是单个容器。

+   Docker 守护程序是与 Docker Engine 可互换的术语。

+   Docker 客户端是打包在同一个 docker 可执行文件中的客户端程序。例如，当我们运行`docker run`时，我们正在使用 Docker 客户端。

+   Docker 网络是将同一网络中的一组容器连接在一起的软件定义网络。默认情况下，我们将使用与 Docker Engine 一起提供的 libnetwork（[`github.com/docker/libnetwork`](https://github.com/docker/libnetwork)）实现。但是，您可以选择使用插件部署您选择的第三方网络驱动程序。

+   Docker Machine 是用于创建能够运行 Docker Engine 的主机的工具，称为**machines***.*

+   Swarm v1 中的 Swarm 节点是预先安装了 Docker Engine 并且在其旁边运行 Swarm 代理程序的机器。Swarm 节点将自己注册到 Discovery 服务中。

+   Swarm v1 中的 Swarm 主节点是运行 Swarm 管理程序的机器。Swarm 主节点从其 Discovery 服务中读取 Swarm 节点的地址。

+   发现服务是由 Docker 或自托管的基于令牌的服务。对于自托管的服务，您可以运行 HashiCorp Consul、CoreOS Etcd 或 Apache ZooKeeper 作为键值存储，用作发现服务。

+   领导者选举是由 Swarm Master 执行的机制，用于找到主节点。其他主节点将处于复制角色，直到主节点宕机，然后领导者选举过程将重新开始。正如我们将看到的，Swarm 主节点的数量应该是奇数。

+   SwarmKit 是 Docker 发布的一个新的 Kit，用于抽象编排。理论上，它应该能够运行*任何*类型的服务，但实际上到目前为止它只编排容器和容器集。

+   Swarm Mode 是自 Docker 1.12 以来提供的新 Swarm，它将 SwarmKit 集成到 Docker Engine 中。

+   Swarm Master（在 Swarm Mode 中）是管理集群的节点：它调度服务，保持集群配置（节点、角色和标签），并确保有一个集群领导者。

+   Swarm Worker（在 Swarm Mode 中）是运行任务的节点，例如，托管容器。

+   服务是工作负载的抽象。例如，我们可以有一个名为"nginx"的服务，复制 10 次，这意味着您将在集群上分布并由 Swarm 本身负载均衡的 10 个任务（10 个 nginx 容器）。

+   任务是 Swarm 的工作单位。一个任务就是一个容器。

# 开始使用 Swarm

我们现在将继续安装两个小型的 Swarm v1 和 v2 概念验证集群，第一个在本地，第二个在 Digital Ocean 上。为了执行这些步骤，请检查配料清单，确保您已经准备好一切，然后开始。

要跟随示例，您将需要：

+   Windows、Mac OS X 或 Linux 桌面

+   Bash 或兼容 Bash 的 shell。在 Windows 上，您可以使用 Cygwin 或 Git Bash。

+   安装最新版本的 VirtualBox，用于本地示例

+   至少需要 4GB 内存，用于本地示例的 4 个 VirtualBox 实例，每个实例 1G 内存

+   至少需要 Docker 客户端 1.6.0 版本用于 Swarm v1 和 1.12 版本用于 Swarm v2

+   当前版本的 Docker Machine，目前为 0.8.1

## Docker for Mac

Docker 在 2016 年初宣布推出了 Docker for Mac 和 Docker for Windows 的桌面版本。它比 Docker Toolbox 更好，因为它包括您期望的 Docker CLI 工具，但不再使用 boot2docker 和 VirtualBox（它改用 unikernels，我们将在第十一章中介绍，*下一步是什么？*），并且完全集成到操作系统中（Mac OS X Sierra 或启用 Hyper-V 的 Windows 10）。

您可以从[`www.docker.com/products/overview#/install_the_platform`](https://www.docker.com/products/overview#/install_the_platform)下载 Docker 桌面版并轻松安装。

![Docker for Mac](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_004.jpg)

如果您使用的是 Mac OS X，只需将 Docker beta 图标拖放到应用程序文件夹中。输入您的 beta 注册码（如果有），就完成了。

![Docker for Mac](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_005.jpg)

在 OS X 上，您将在系统托盘中看到 Docker 鲸鱼，您可以打开它并配置您的设置。Docker 主机将在您的桌面上本地运行。

![Docker for Mac](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/docker.jpg)

## Docker for Windows

对于 Docker for Windows，它需要启用 Hyper-V 的 Windows 10。基本上，Hyper-V 随 Windows 10 专业版或更高版本一起提供。双击安装程序后，您将看到第一个屏幕，显示许可协议，看起来类似于以下截图。安装程序将要求您输入与 Docker for Mac 类似的密钥。

![Docker for Windows](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_007.jpg)

如果安装过程顺利进行，您将看到完成屏幕已准备好启动 Docker for Windows，如下所示：

![Docker for Windows](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_008.jpg)

在启动时，Docker 将初始化为 Hyper-V。一旦过程完成，您只需打开 PowerShell 并开始使用 Docker。

![Docker for Windows](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_009.jpg)

如果出现问题，您可以从托盘图标的菜单中打开日志窗口，并使用 Hyper-V 管理器进行检查。

![Docker for Windows](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_010.jpg)

## 准备好使用 Linux

我们将在本书中广泛使用 Machine，因此请确保您已经通过 Docker for Mac 或 Windows 或 Docker Toolbox 安装了它。如果您在桌面上使用 Linux，请使用您的软件包系统（apt 或 rpm）安装 Docker 客户端。您还需要下载裸机二进制文件，只需使用 curl 并为其分配执行权限；请按照[`docs.docker.com/machine/install-machine/`](https://docs.docker.com/machine/install-machine/)上的说明进行操作。当前稳定版本为 0.8.1。

```
$ curl -L 
https://github.com/docker/machine/releases/download/v0.8.1/docker-
machine-uname -s-uname -m > /usr/local/bin/docker-machine
$ chmod +x /usr/local/bin/docker-machine`

```

## 检查 Docker Machine 是否可用-所有系统

您可以通过命令行检查机器是否准备好使用以下命令：

```
$ docker-machine --version
docker-machine version 0.8.1, build 41b3b25

```

如果您遇到问题，请检查系统路径或为您的架构下载正确的二进制文件。

# 昨天的 Swarm

对于第一个示例，我们将在本地运行 Swarm v1 集群的最简单配置，以了解“旧”Swarm 是如何工作的（仍然有效）。这个小集群将具有以下特点：

+   由每个 1CPU，1GB 内存的四个节点组成，总共将包括四个 CPU 和 4GB 内存的基础设施

+   每个节点将在 VirtualBox 上运行

+   每个节点都连接到本地 VirtualBox 网络上的其他节点

+   不涉及发现服务：将使用静态的`nodes://`机制

+   没有配置安全性，换句话说 TLS 已禁用

我们的集群将类似于以下图表。四个引擎将通过端口`3376`在网格中相互连接。实际上，除了 Docker 引擎之外，它们每个都将运行一个在主机上暴露端口`3376`（Swarm）并将其重定向到自身的 Docker 容器。我们，操作员，将能够通过将环境变量`DOCKER_HOST`设置为`IP:3376`来连接到（任何一个）主机。如果您一步一步地跟随示例，一切都会变得更清晰。

![昨天的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/B05661_01_25.jpg)

首先，我们必须使用 Docker Machine 创建四个 Docker 主机。Docker Machine 可以自动化这些步骤，而不是手动创建 Linux 虚拟机，生成和上传证书，通过 SSH 登录到它，并安装和配置 Docker 守护程序。

机器将执行以下步骤：

1.  从 boot2docker 镜像启动一个 VirtualBox 虚拟机。

1.  为虚拟机分配一个 IP 地址在 VirtualBox 内部网络上。

1.  上传和配置证书和密钥。

1.  在此虚拟机上安装 Docker 守护程序。

1.  配置 Docker 守护程序并公开它，以便可以远程访问。

结果，我们将有一个运行 Docker 并准备好被访问以运行容器的虚拟机。

## Boot2Docker

使用 Tiny Core Linux 构建的**Boot2Docker**是一个轻量级发行版，专为运行 Docker 容器而设计。它完全运行在 RAM 上，启动时间非常快，从启动到控制台大约五秒。启动引擎时，Boot2Docker 默认在安全端口 2376 上启动 Docker 引擎。

Boot2Docker 绝不适用于生产工作负载。它仅用于开发和测试目的。我们将从使用 boot2docker 开始，然后在后续章节中转向生产。在撰写本文时，Boot2Docker 支持 Docker 1.12.3 并使用 Linux Kernel 4.4。它使用 AUFS 4 作为 Docker 引擎的默认存储驱动程序。

## 使用 Docker Machine 创建 4 个集群节点

如果我们执行：

```
$ docker-machine ls

```

在我们的新安装中列出可用的机器时，我们看到没有正在运行的机器。

因此，让我们从创建一个开始，使用以下命令：

```
$ docker-machine create --driver virtualbox node0

```

此命令明确要求使用 VirtualBox 驱动程序（-d 简称）并将机器命名为 node0。Docker Machines 可以在数十个不同的公共和私人提供商上提供机器，例如 AWS，DigitalOcean，Azure，OpenStack，并且有很多选项。现在，我们使用标准设置。第一个集群节点将在一段时间后准备就绪。

在这一点上，发出以下命令以控制此主机（以便远程访问）：

```
$ docker-machine env node0

```

这将打印一些 shell 变量。只需复制最后一行，即带有 eval 的那一行，粘贴并按 Enter。配置了这些变量后，您将不再操作本地守护程序（如果有的话），而是操作`node0`的 Docker 守护程序。

![使用 Docker Machine 创建 4 个集群节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_012.jpg)

如果再次检查机器列表，您将看到图像名称旁边有一个`*`，表示它是当前正在使用的机器。或者，您可以输入以下命令以打印当前活动的机器：

```
$ docker-machine active

```

![使用 Docker Machine 创建 4 个集群节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_013.jpg)

守护程序正在此机器上运行，并具有一些标准设置（例如在端口`tcp/2376`上启用了 TLS）。您可以通过 SSH 到节点并验证运行的进程来确保这一点：

```
$ docker-machine ssh node0 ps aux | grep docker
1320 root  /usr/local/bin/docker daemon -D -g /var/lib/docker -H 
    unix:// -H tcp://0.0.0.0:2376 --label provider=virtualbox --
    tlsverify --tlscacert=/var/lib/boot2docker/ca.pem -- 
    tlscert=/var/lib/boot2docker/server.pem -- 
    tlskey=/var/lib/boot2docker/server-key.pem -s aufs

```

因此，您可以通过立即启动容器并检查 Docker 状态来启动 Docker 守护程序：

![使用 Docker Machine 创建 4 个集群节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_014.jpg)

完美！现在我们以完全相同的方式为其他三个主机进行配置，将它们命名为`node1`、`node2`和`node3`：

```
$ docker-machine create --driver virtualbox node1
$ docker-machine create --driver virtualbox node2
$ docker-machine create --driver virtualbox node3

```

当它们完成时，您将有四个可用的 Docker 主机。使用 Docker Machine 检查。

![使用 Docker Machine 创建 4 个集群节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_015.jpg)

现在我们准备启动一个 Swarm 集群。但是，在此之前，为了使这个非常简单的第一个示例尽可能简单，我们将禁用运行引擎的 TLS。我们的计划是：在端口`2375`上运行 Docker 守护程序，没有 TLS。

让我们稍微整理一下，并详细解释所有端口组合。

| **不安全** | **安全** |
| --- | --- |
| 引擎：2375 | 引擎：2376 |
| Swarm: 3375 | Swarm: 3376 |
|  | Swarm v2 使用 2377 进行节点之间的发现 |

端口`2377`用于 Swarm v2 节点在集群中发现彼此的节点。

## 配置 Docker 主机

为了了解 TLS 配置在哪里，我们将通过关闭所有 Docker 主机的 TLS 来进行一些练习。在这里关闭它也是为了激励读者学习如何通过自己调用`swarm manage`命令来工作。

我们有四个主机在端口`tcp/2376`上运行 Docker，并且使用 TLS，因为 Docker Machine 默认创建它们。我们必须重新配置它们以将守护程序端口更改为`tls/2375`并删除 TLS。因此，我们登录到每个主机，使用以下命令：

```
$ docker-machine ssh node0

```

然后，我们获得了 root 权限：

```
$ sudo su -

```

并通过修改文件`/var/lib/boot2docker/profile`来配置`boot2docker`：

```
# cp /var/lib/boot2docker/profile /var/lib/boot2docker/profile-bak
# vi /var/lib/boot2docker/profile

```

我们删除了具有 CACERT、SERVERKEY 和 SERVERCERT 的行，并将守护程序端口配置为`tcp/2375`，将`DOCKER_TLS`配置为`no`。实际上，这将是我们的配置：

![配置 Docker 主机](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_016.jpg)

完成后退出 SSH 会话并重新启动机器：

```
$ docker-machine restart node0

```

Docker 现在在端口`tcp/2375`上运行，没有安全性。您可以使用以下命令检查：

```
$ docker-machine ssh node0 ps aux | grep docker
1127 root  /usr/local/bin/docker daemon -D -g /var/lib/docker -H 
     unix:// -H tcp://0.0.0.0:2375 --label provider=virtualbox -s aufs

```

最后，在您的本地桌面计算机上，取消设置`DOCKER_TLS_VERIFY`并重新导出`DOCKER_HOST`，以便使用在`tcp/2375`上监听且没有 TLS 的守护程序：

```
$ unset DOCKER_TLS_VERIFY
$ export DOCKER_HOST="tcp://192.168.99.103:2375"

```

我们必须为我们的第一个 Swarm 中的每个四个节点重复这些步骤。

## 启动 Docker Swarm

要开始使用 Swarm v1（毫不意外），必须从 Docker hub 拉取`swarm`镜像。打开四个终端，在第一个终端中为每台机器的环境变量设置环境变量，在第一个终端中设置 node0（`docker-machine env node0`，并将`env`变量复制并粘贴到 shell 中），在第二个终端中设置`node1`，依此类推 - ，并在完成更改标准端口和禁用 TLS 的步骤后，对每个终端执行以下操作：

```
$ docker pull swarm

```

![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_017.jpg)

我们将在第一个示例中不使用发现服务，而是使用最简单的机制，例如`nodes://`。使用`nodes://`，Swarm 集群节点是手动连接的，以形成对等网格。操作员所需做的就是简单地定义一个节点 IP 和守护进程端口的列表，用逗号分隔，如下所示：

```
nodes://192.168.99.101:2375,192.168.99.102:2375,192.168.99.103:2375,192.168.99.107:2375

```

要使用 Swarm，您只需使用一些参数运行 swarm 容器。要在线显示帮助，您可以输入：

```
$ docker run swarm --help

```

![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_018.jpg)

如您所见，Swarm 基本上有四个命令：

+   **Create**用于使用发现服务创建集群，例如`token://`

+   **List**显示集群节点的列表

+   **Manage**允许您操作 Swarm 集群

+   **Join**与发现服务结合使用，用于将新节点加入现有集群

现在，我们将使用`manage`命令。这是具有大多数选项的命令（您可以通过发出`docker run swarm manage --help`来进行调查）。我们现在限制连接节点。以下是每个节点的策略：

1.  通过 swarm 容器公开 Swarm 服务。

1.  以`daemon`（`-d`）模式运行此容器。

1.  将标准 Swarm 端口`tcp/3376`转发到内部（容器上）端口`tcp/2375`。

1.  使用`nodes://`指定集群中的主机列表 - 每个主机都必须是`IP:port`对，其中端口是 Docker 引擎端口（`tcp/2375`）。

因此，在每个终端上，您连接到每台机器，执行以下操作：

```
$ docker run \
-d \
-p 3376:2375 \
swarm manage \
nodes://192.168.99.101:2375,192.168.99.102:2375,
    192.168.99.103:2375,192.168.99.107:2375

```

### 提示

当使用`nodes://`机制时，您可以使用类似 Ansible 的主机范围模式，因此可以使用三个连续 IP 的紧凑语法，例如 nodes:`//192.168.99.101:2375,192.168.99.102:2375,192.168.99.103:2375` 在 nodes:`//192.168.99.[101:103]:2375`

现在，作为下一步，我们将连接到它并在开始运行容器之前检查其信息。为了方便起见，打开一个新的终端。我们现在连接的不再是我们的一个节点上的 Docker 引擎，而是 Docker Swarm。因此，我们将连接到`tcp/3376`而不再是`tcp/2375`。为了详细展示我们正在做什么，让我们从`node0`变量开始：

```
$ docker-machine env node0

```

复制并粘贴 eval 行，正如您已经知道的那样，并使用以下命令检查导出的 shell 变量：

```
$ export | grep DOCKER_

```

我们现在需要做以下事情：

1.  将`DOCKER_HOST`更改为连接到 Swarm 端口`tcp/3376`，而不是引擎`tcp/2375`

1.  禁用`DOCKER_TLS_VERIFY`。

1.  禁用`DOCKER_CERT_PATH`。![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_019.jpg)

您应该有类似于这样的配置：

![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_020.jpg)

如果我们现在连接到`3376`的 Docker Swarm，并显示一些信息，我们会看到我们正在运行 Swarm：

![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_021.jpg)

恭喜！您刚刚启动了您的第一个带有 Swarm 的 Docker 集群。我们可以看到除了四个 Swarm 之外，我们的集群上还没有运行任何容器，但服务器版本是 swarm/1.2.3，调度策略是 spread，最重要的是，我们的 Swarm 中有四个健康节点（每个 Swarm 节点的详细信息如下）。

此外，您可以获取有关此 Swarm 集群调度程序行为的一些额外信息：

```
Strategy: spread
Filters: health, port, containerslots, dependency, affinity, 
    constraint

```

spread 调度策略意味着 Swarm 将尝试将容器放置在使用较少的主机上，并且在创建容器时提供了列出的过滤器，因此允许您决定手动建议一些选项。例如，您可能希望使您的 Galera 集群容器在地理上靠近但位于不同的主机上。

但是，这个 Swarm 的大小是多少？您可以在输出的最后看到它：

![启动 Docker Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_022.jpg)

这意味着在这个小小的 Swarm 上，您拥有这些资源的总可用性：四个 CPU 和 4GB 的内存。这正是我们预期的，通过合并每个具有 1GB 内存的 CPU 的 4 个 VirtualBox 主机的计算资源。

# 测试您的 Swarm 集群

现在我们有了一个 Swarm 集群，是时候开始使用它了。我们将展示扩展策略算法将决定将容器放置在负载较轻的主机上。在这个例子中，这很容易，因为我们从四个空节点开始。所以，我们连接到 Swarm，Swarm 将在主机上放置容器。我们启动一个 nginx 容器，将其端口 tcp/80 映射到主机（机器）端口`tcp/80`。

```
$ docker run -d -p 80:80 nginx
2c049db55f9b093d19d575704c28ff57c4a7a1fb1937bd1c20a40cb538d7b75c

```

在这个例子中，我们看到 Swarm 调度程序决定将这个容器放到`node1`上：

![测试您的 Swarm 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_023.jpg)

由于我们必须将端口`tcp/80`绑定到任何主机，我们只有四次机会，四个不同主机上的四个容器。让我们创建新的 nginx 容器，看看会发生什么：

```
$ docker run -d -p 80:80 nginx
577b06d592196c34ebff76072642135266f773010402ad3c1c724a0908a6997f
$ docker run -d -p 80:80 nginx
9fabe94b05f59d01dd1b6b417f48155fc2aab66d278a722855d3facc5fd7f831
$ docker run -d -p 80:80 nginx
38b44d8df70f4375eb6b76a37096f207986f325cc7a4577109ed59a771e6a66d

```

现在我们有 4 个 nginx 容器放置在我们的 4 个 Swarm 主机上：

![测试您的 Swarm 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_024.jpg)

现在我们尝试创建一个新的 nginx：

```
$ docker run -d -p 80:80 nginx
docker: Error response from daemon: Unable to find a node that 
    satisfies the following conditions
[port 80 (Bridge mode)].
See 'docker run --help'.

```

发生的事情只是 Swarm 无法找到一个合适的主机来放置一个新的容器，因为在所有主机上，端口`tcp/80`都被占用。在运行了这 4 个 nginx 容器之后，再加上四个 Swarm 容器（用于基础设施管理），正如我们所预期的那样，我们在这个 Swarm 集群上有八个正在运行的容器：

![测试您的 Swarm 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_01_025.jpg)

这就是 Swarm v1 的预期工作方式（它仍然在工作）。

# Swarm，今天

在本节中，我们将使用内置在 Docker Engine 1.12 或更高版本中的新 Swarm 模式设置一个小集群。

在 DockerCon16 上，大量的公告中，有两个关于容器编排引起了很大的关注：

+   引擎和 Swarm 之间的集成，称为 Docker Swarm 模式。

+   SwarmKit

实际上，Docker 守护程序从 1.12 版本开始增加了运行所谓的 Swarm Mode 的可能性。docker 客户端添加了新的 CLI 命令，如`node`、`service`、`stack`、`deploy`，当然还有`swarm`。

我们将从第三章开始更详细地介绍 Swarm Mode 和 SwarmKit，但现在我们完成了 Swarm v1 的示例，我们将让读者体验一下 Swarm v2 比 v1 具有更简单的用户体验。使用 Swarm v2 的唯一要求是至少有 1.12-rc1 版本的守护程序版本。但是，使用 Docker Machine 0.8.0-rc1+，您可以使用通常的程序满足这一要求来提供 Docker 主机。

Docker 还在 DockerCon 2016 上宣布了 Docker for AWS 和 Docker for Azure。不仅仅是 AWS 和 Azure，实际上我们也是 DigitalOcean 的粉丝，所以我们创建了一个新工具，它包装了 DigitalOcean 命令行界面的`doctl`，以帮助以新的大规模方式提供 Docker 集群。该工具称为`belt`，现在可以从[`github.com/chanwit/belt`](http://github.com/chanwit/belt)获取。您可以使用以下命令拉取 belt：

`go get github.com/chanwit/belt`

或者从项目的**Release**标签中下载二进制文件。

首先，我们将为在 DigitalOcean 上进行配置准备一个模板文件。您的`.belt.yaml`将如下所示：

```
$ cat .belt.yaml
---
digitalocean:
region: sgp1
image: 18153887
ssh_user: root
ssh_key_fingerprint: 816630

```

请注意，我的镜像编号`18153887`是包含 Docker 1.12 的快照。DigitalOcean 通常会在每次发布后提供最新的 Docker 镜像。为了让您能够控制您的集群，需要有 SSH 密钥。对于字段`ssh_key_fingerprint`，您可以放置指纹以及密钥 ID。

不要忘记设置您的`DIGITALOCEAN_ACCESS_TOKEN`环境变量。此外，Belt 也识别相同的一组 Docker Machine shell 变量。如果您熟悉 Docker Machine，您将知道如何设置它们。刷新一下，这些是我们在上一节介绍的 shell 变量：

+   `export DOCKER_TLS_VERIFY="1"`

+   `export DOCKER_HOST="tcp://<IP ADDRESS>:2376"`

+   `export DOCKER_CERT_PATH="/Users/user/.docker/machine/machines/machine"`

+   `export DOCKER_MACHINE_NAME="machine"`

所以，现在让我们看看如何使用 Belt：

```
$ export DIGITALOCEAN_ACCESS_TOKEN=1b207 .. snip .. b6581c

```

现在我们创建一个包含 512M 内存的四个节点的 Swarm：

```
$ belt create 512mb node[1:4]
ID              Name    Public IPv4     Memory  VCPUs   Disk
18511682        node1                   512     1       20
18511683        node4                   512     1       20
18511684        node3                   512     1       20
18511681        node2                   512     1       20

```

您可以看到，我们可以使用类似的语法 node[1:4]指定一组节点。此命令在 DigitalOcean 上创建了四个节点。请等待大约 55 秒，直到所有节点都被配置。然后您可以列出它们：

```
$ belt ls
ID              Name    Public IPv4       Status  Tags
18511681        node2   128.199.105.119   active
18511682        node1   188.166.183.86    active
18511683        node4   188.166.183.103   active
18511684        node3   188.166.183.157   active

```

它们的状态现在已从“新”更改为“活动”。所有 IP 地址都已分配。目前一切都进行得很顺利。

现在我们可以启动 Swarm。

在此之前，请确保我们正在运行 Docker 1.12。我们在`node1`上检查这一点。

```
$ belt active node1
node1
$ belt docker version
Client:
Version:      1.12.0-rc2
API version:  1.24
Go version:   go1.6.2
Git commit:   906eacd
Built:        Fri Jun 17 21:02:41 2016
OS/Arch:      linux/amd64
Experimental: true
Server:
Version:      1.12.0-rc2
API version:  1.24
Go version:   go1.6.2
Git commit:   906eacd
Built:        Fri Jun 17 21:02:41 2016
OS/Arch:      linux/amd64
Experimental: true

```

`belt docker`命令只是一个薄包装命令，它将整个命令行通过 SSH 发送到您的 Docker 主机。因此，这个工具不会妨碍您的 Docker 引擎始终处于控制状态。

现在我们将使用 Swarm Mode 初始化第一个节点。

```
$ belt docker swarm init
Swarm initialized: current node (c0llmsc5t1tsbtcblrx6ji1ty) is now 
    a manager.

```

然后我们将其他三个节点加入到这个新形成的集群中。加入一个大集群是一项繁琐的任务。我们将让`belt`代替我们手动执行此操作，而不是逐个节点进行 docker swarm join：

```
$ belt swarm join node1 node[2:4]
node3: This node joined a Swarm as a worker.
node2: This node joined a Swarm as a worker.
node4: This node joined a Swarm as a worker.

```

### 提示

当然，您可以运行：`belt --host node2 docker swarm join <node1's IP>:2377`，手动将 node2 加入到您的集群中。

然后您将看到集群的这个视图：

```
$ belt docker node ls
ID          NAME   MEMBERSHIP  STATUS  AVAILABILITY  MANAGER STATUS
4m5479vud9qc6qs7wuy3krr4u    node2  Accepted    Ready   Active
4mkw7ccwep8pez1jfeok6su2o    node4  Accepted    Ready   Active
a395rnht2p754w1beh74bf7fl    node3  Accepted    Ready   Active
c0llmsc5t1tsbtcblrx6ji1ty *  node1  Accepted    Ready   Active        Leader

```

恭喜！您刚在 DigitalOcean 上安装了一个 Swarm 集群。

我们现在为`nginx`创建一个服务。这个命令将创建一个 Nginx 服务，其中包含 2 个容器实例，发布在 80 端口。

```
$ belt docker service create --name nginx --replicas 2 -p 80:80 
    nginx
d5qmntf1tvvztw9r9bhx1hokd

```

我们开始吧：

```
$ belt docker service ls
ID            NAME   REPLICAS  IMAGE  COMMAND
d5qmntf1tvvz  nginx  2/2       nginx

```

现在让我们将其扩展到 4 个节点。

```
$ belt docker service scale nginx=4
nginx scaled to 4
$ belt docker service ls
ID            NAME   REPLICAS  IMAGE  COMMAND
d5qmntf1tvvz  nginx  4/4       nginx

```

类似于 Docker Swarm，您现在可以使用`belt ip`来查看节点的运行位置。您可以使用任何 IP 地址来浏览 NGINX 服务。它在每个节点上都可用。

```
$ belt ip node2
128.199.105.119

```

这就是 Docker 1.12 开始的 Swarm 模式的样子。

# 总结

在本章中，我们了解了 Docker Swarm，定义了其目标、特性和架构。我们还回顾了一些其他可能的开源替代方案，并介绍了它们与 Swarm 的关系。最后，我们通过在 Virtualbox 和 Digital Ocean 上创建一个由四个主机组成的简单本地集群来安装和开始使用 Swarm。

使用 Swarm 对容器进行集群化将是整本书的主题，但在我们开始在生产环境中使用 Swarm 之前，我们将先了解一些理论知识，首先是发现服务的主题，即第二章*发现发现服务*。


# 第二章：发现发现服务

在第一章*欢迎来到 Docker Swarm*中，我们使用`nodes://`机制创建了一个简单但功能良好的本地 Docker Swarm 集群。这个系统对于学习 Swarm 的基本原理来说并不是很实用。

事实上，这只是一个扁平的模型，没有考虑任何真正的主从架构，更不用说高级服务，比如节点发现和自动配置、韧性、领导者选举和故障转移（高可用性）。实际上，它并不适合生产环境。

除了`nodes://`，Swarm v1 正式支持四种发现服务；然而，其中一种 Token，是一个微不足道的非生产级服务。基本上，使用 Swarm v1，你需要手动集成一个发现服务，而使用 Swarm Mode（从 Docker 1.12 开始），一个发现服务 Etcd 已经集成。在本章中，我们将涵盖：

+   发现服务

+   一个测试级别的发现服务：Token

+   Raft 理论和 Etcd

+   Zookeeper 和 Consul

在深入探讨这些服务之前，让我们讨论一下什么是发现服务？

# 一个发现服务

想象一下，你正在运行一个静态配置的 Swarm 集群，类似于第一章*欢迎来到 Docker Swarm*中的配置，网络是扁平的，每个容器都被分配了一个特定的任务，例如一个 MySQL 数据库。很容易找到 MySQL 容器，因为你为它分配了一个定义的 IP 地址，或者你运行了一些 DNS 服务器。很容易通知这个单独的容器是否工作，而且我们知道它不会改变它的端口（`tcp/3336`）。此外，我们的 MySQL 容器并不需要宣布它的可用性作为一个带有 IP 和端口的数据库容器：我们当然已经知道了。

这是一个宠物模型，由系统管理员手动模拟。然而，由于我们是更高级的运营者，我们想要驱动一头牛。

所以，想象一下，你正在运行一个由数百个节点组成的 Swarm，托管着运行一定数量服务的几个应用程序（Web 服务器、数据库、键值存储、缓存和队列）。这些应用程序运行在大量的容器上，这些容器可能会动态地改变它们的 IP 地址，要么是因为你重新启动它们，要么是因为你创建了新的容器，要么是因为你复制了它们，或者是因为一些高可用性机制为你启动了新的容器。

您如何找到您的 Acme 应用程序的 MySQL 服务？如何确保负载均衡器知道您的 100 个 Nginx 前端的地址，以便它们的功能不会中断？如果服务已经移动并具有不同的配置，您如何通知？

*您使用发现服务。*

所谓的发现服务是一个具有许多特性的机制。有不同的服务可供选择，具有更多或更少相似的特性，有其优点和缺点，但基本上所有的发现服务都针对分布式系统，因此它们必须分布在所有集群节点上，具有可伸缩性和容错性。发现服务的主要目标是帮助服务找到并相互通信。为了做到这一点，它们需要保存（注册）与每个服务的位置相关的信息，通过宣布自己来做到这一点，它们通常通过充当键值存储来实现。发现服务在 Docker 兴起之前就已经存在，但随着容器和容器编排的出现，问题变得更加困难。

再次总结，通过发现服务：

+   您可以定位基础设施中的单个服务

+   您可以通知服务配置更改

+   服务注册其可用性

+   等等

通常，发现服务是作为键值存储创建的。Docker Swarm v1 官方支持以下发现服务。但是，您可以使用`libkv`抽象接口集成自己的发现服务，如下所示：

[`github.com/docker/docker/tree/master/pkg/discovery`](https://github.com/docker/docker/tree/master/pkg/discovery)。

+   Token

+   Consul 0.5.1+

+   Etcd 2.0+

+   ZooKeeper 3.4.5+

然而，Etcd 库已经集成到 Swarm 模式中作为其内置的发现服务。

# Token

Docker Swarm v1 包括一个开箱即用的发现服务，称为 Token。Token 已集成到 Docker Hub 中；因此，它要求所有 Swarm 节点连接到互联网并能够访问 Docker Hub。这是 Token 的主要限制，但很快您将看到，Token 将允许我们在处理集群时进行一些实践。

简而言之，Token 要求您生成一个称为 token 的 UUID。有了这个 UUID，您可以创建一个管理器，充当主节点，并将从节点加入集群。

## 使用 token 重新设计第一章的示例

如果我们想保持实用性，现在是时候看一个例子了。我们将使用令牌来重新设计第一章的示例，*欢迎来到 Docker Swarm*。作为新功能，集群将不再是扁平的，而是由 1 个主节点和 3 个从节点组成，并且每个节点将默认启用安全性。

主节点将是暴露 Swarm 端口`3376`的节点。我们将专门连接到它，以便能够驱动整个集群。

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/B05661_02_01-1.jpg)

我们可以使用以下命令创建 4 个节点：

```
$ for i in `seq 0 3`; do docker-machine create -d virtualbox 
    node$i; 
    done

```

现在，我们有四台运行最新版本引擎的机器，启用了 TLS。这意味着，正如你记得的那样，引擎正在暴露端口`2376`而不是`2375`。

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_002.jpg)

我们现在将创建集群，从主节点开始。选择其中一个节点，例如`node0`，并获取其变量：

```
$ eval $(docker-machine env node0)

```

现在我们生成集群令牌和唯一 ID。为此，我们使用`swarm create`命令：

```
$ docker run swarm create
3b905f46fef903800d51513d51acbbbe

```

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_003.jpg)

结果，集群容器输出了令牌，并且在本示例中将调用所示的协议：`token://3b905f46fef903800d51513d51acbbbe`。

注意这个令牌 ID，例如将其分配给一个 shell 变量：

```
$ TOKEN=3b905f46fef903800d51513d51acbbbe

```

现在我们创建一个主节点，并尝试满足至少一些基本的标准安全要求，也就是说，我们将启用 TLS 加密。正如我们将在一会儿看到的，`swarm`命令接受 TLS 选项作为参数。但是我们如何将密钥和证书传递给容器呢？为此，我们将使用 Docker Machine 生成的证书，并将其放置在主机上的`/var/lib/boot2docker`中。

实际上，我们将从 Docker 主机挂载一个卷到 Docker 主机上的容器。所有远程控制都依赖于环境变量。

已经获取了`node0`变量，我们使用以下命令启动 Swarm 主节点：

```
$ docker run -ti -v /var/lib/boot2docker:/certs -p 3376:3376 swarm 
    manage -H 0.0.0.0:3376 -tls --tlscacert=/certs/ca.pem --
    tlscert=/certs/server.pem --tlskey=/certs/server-key.pem 
    token://$TOKEN

```

首先，我们以交互模式运行容器以观察 Swarm 输出。然后，我们将节点`/var/lib/boot2docker`目录挂载到 Swarm 容器内部的`/certs`目录。我们将`3376` Swarm 安全端口从 node0 重定向到 Swarm 容器。我们通过将其绑定到`0.0.0.0:3376`来以管理模式执行`swarm`命令。然后，我们指定一些证书选项和文件路径，并最后描述使用的发现服务是令牌，带有我们的令牌。

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_004.jpg)

有了这个节点运行，让我们打开另一个终端并加入一个节点到这个 Swarm。让我们首先源`node1`变量。现在，我们需要让 Swarm 使用`join`命令，以加入其主节点为`node0`的集群：

```
$ docker run -d swarm join --addr=192.168.99.101:2376 
    token://$TOKEN

```

在这里，我们指定主机（自身）的地址为`192.168.99.101`以加入集群。

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_005.jpg)

如果我们跳回第一个终端，我们会看到主节点已经注意到一个节点已经加入了集群。因此，此时我们有一个由一个主节点和一个从节点组成的 Swarm 集群。

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_006.jpg)

由于我们现在理解了机制，我们可以在终端中停止`docker`命令，并使用`-d`选项重新运行它们。因此，要在守护程序模式下运行容器：

主节点：

```
$ docker run -t-d -v /var/lib/boot2docker:/certs -p 3376:3376 swarm 
    manage -H 0.0.0.0:3376 -tls --tlscacert=/certs/ca.pem --
    tlscert=/certs/server.pem --tlskey=/certs/server-key.pem 
    token://$TOKEN

```

节点：

```
$ docker run -d swarm join --addr=192.168.99.101:2376  
    token://$TOKEN

```

我们现在将继续将其他两个节点加入集群，源其变量，并重复上述命令，如下所示：

```
$ eval $(docker-machine env node2)
$ docker run -d swarm join --addr=192.168.99.102:2376 
    token://$TOKEN
$ eval $(docker-machine env node3)
$ docker run -d swarm join --addr=192.168.99.103:2376 
    token://$TOKEN

```

例如，如果我们打开第三个终端，源`node0`变量，并且特别连接到端口`3376`（Swarm）而不是`2376`（Docker Engine），我们可以看到来自`docker info`命令的一些花哨的输出。例如，集群中有三个节点：

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_007.jpg)

因此，我们已经创建了一个具有一个主节点、三个从节点的集群，并启用了 TLS，准备接受容器。

我们可以从主节点确保并列出集群中的节点。我们现在将使用`swarm list`命令：

```
$ docker run swarm list token://$TOKEN

```

![使用令牌重新设计第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_008.jpg)

## 令牌限制

Token 尚未被弃用，但很可能很快就会被弃用。Swarm 中的每个节点都需要具有互联网连接的标准要求并不是很方便。此外，对 Docker Hub 的访问使得这种技术依赖于 Hub 的可用性。实际上，它将 Hub 作为单点故障。然而，使用 token，我们能够更好地了解幕后情况，并且我们遇到了 Swarm v1 命令：`create`、`manage`、`join`和`list`。

现在是时候继续前进，熟悉真正的发现服务和共识算法，这是容错系统中的一个基本原则。

# Raft

共识是分布式系统中的一种算法，它强制系统中的代理就一致的值达成一致意见并选举领导者。

一些著名的共识算法是 Paxos 和 Raft。Paxos 和 Raft 提供了类似的性能，但 Raft 更简单，更易于理解，因此在分布式存储实现中变得非常流行。

作为共识算法，Consul 和 Etcd 实现了 Raft，而 ZooKeeper 实现了 Paxos。CoreOS Etcd Go 库作为 SwarmKit 和 Swarm Mode 的依赖项（在`vendor/`中），因此在本书中我们将更多地关注它。

Raft 在 Ongaro、Ousterhout 的论文中有详细描述，可在[`ramcloud.stanford.edu/raft.pdf`](https://ramcloud.stanford.edu/raft.pdf)上找到。在接下来的部分中，我们将总结其基本概念。

## Raft 理论

Raft 的设计初衷是简单，与 Paxos 相比，它确实实现了这一目标（甚至有学术出版物证明了这一点）。对于我们的目的，Raft 和 Paxos 的主要区别在于，在 Raft 中，消息和日志只由集群领导者发送给其同行，使得算法更易于理解和实现。我们将在理论部分使用的示例库是由 CoreOS Etcd 提供的 Go 库，可在[`github.com/coreos/etcd/tree/master/raft`](https://github.com/coreos/etcd/tree/master/raft)上找到。

Raft 集群由节点组成，这些节点必须以一致的方式维护复制状态机，无论如何：新节点可以加入，旧节点可以崩溃或变得不可用，但这个状态机必须保持同步。

为了实现这个具有容错能力的目标，通常 Raft 集群由奇数个节点组成，例如三个或五个，以避免分裂脑。当剩下的节点分裂成无法就领导者选举达成一致的组时，就会发生分裂脑。如果节点数是奇数，它们最终可以以多数同意的方式选出领导者。而如果节点数是偶数，选举可能以 50%-50%的结果结束，这是不应该发生的。

回到 Raft，Raft 集群被定义为`raft.go`中的一种类型 raft 结构，并包括领导者 UUID、当前任期、指向日志的指针以及用于检查法定人数和选举状态的实用程序。让我们通过逐步分解集群组件 Node 的定义来阐明所有这些概念。Node 在`node.go`中被定义为一个接口，在这个库中被规范地实现为`type node struct`。

```
type Node interface {
Tick()
Campaign(ctx context.Context) error
Propose(ctx context.Context, data []byte) error
ProposeConfChange(ctx context.Context, cc pb.ConfChange) error
Step(ctx context.Context, msg pb.Message) error
Ready() <-chan Ready
Advance()
ApplyConfChange(cc pb.ConfChange) *pb.ConfState
Status() Status
ReportUnreachable(id uint64)
ReportSnapshot(id uint64, status SnapshotStatus)
Stop()
}

```

每个节点都保持一个滴答（通过`Tick()`递增），表示任意长度的当前运行时期或时间段或时代。在每个时期，一个节点可以处于以下 StateType 之一：

+   领导者

+   候选者

+   追随者

在正常情况下，只有一个领导者，所有其他节点都是跟随者。领导者为了让我们尊重其权威，定期向其追随者发送心跳消息。当追随者注意到心跳消息不再到达时，他们会意识到领导者不再可用，因此他们会增加自己的值，成为候选者，然后尝试通过运行`Campaign()`来成为领导者。他们从为自己投票开始，试图达成选举法定人数。当一个节点实现了这一点，就会选举出一个新的领导者。

`Propose()`是一种向日志附加数据的提案方法。日志是 Raft 中用于同步集群状态的数据结构，也是 Etcd 中的另一个关键概念。它保存在稳定存储（内存）中，当日志变得庞大时具有压缩日志以节省空间（快照）的能力。领导者确保日志始终处于一致状态，并且只有在确定信息已经通过大多数追随者复制时，才会提交新数据以附加到其日志（主日志）上，因此存在一致性。有一个`Step()`方法，它将状态机推进到下一步。

`ProposeConfChange()`是一个允许我们在运行时更改集群配置的方法。由于其两阶段机制，它被证明在任何情况下都是安全的，确保每个可能的多数都同意这一变更。`ApplyConfChange()`将此变更应用到当前节点。

然后是`Ready()`。在 Node 接口中，此函数返回一个只读通道，返回准备好被读取、保存到存储并提交的消息的封装规范。通常，在调用 Ready 并应用其条目后，客户端必须调用`Advance()`，以通知 Ready 已经取得进展。在实践中，`Ready()`和`Advance()`是 Raft 保持高一致性水平的方法的一部分，通过避免日志、内容和状态同步中的不一致性。

这就是 CoreOS' Etcd 中 Raft 实现的样子。

## Raft 的实践

如果您想要亲自尝试 Raft，一个好主意是使用 Etcd 中的`raftexample`并启动一个三成员集群。

由于 Docker Compose YAML 文件是自描述的，以下示例是一个准备运行的组合文件：

```
version: '2'
services:
raftexample1:
image: fsoppelsa/raftexample
command: --id 1 --cluster 
          http://127.0.0.1:9021,http://127.0.0.1:9022,
          http://127.0.0.1:9023 --port 9121
ports:
- "9021:9021"
- "9121:9121"
raftexample2:
image: fsoppelsa/raftexample
command: --id 2 --cluster    
          http://127.0.0.1:9021,http://127.0.0.1:9022,
          http://127.0.0.1:9023 --port 9122
ports:
- "9022:9022"
- "9122:9122"
raftexample3:
image: fsoppelsa/raftexample
command: --id 3 --cluster 
          http://127.0.0.1:9021,http://127.0.0.1:9022,
          http://127.0.0.1:9023 --port 9123
ports:
- "9023:9023"
- "9123:9123"

```

此模板创建了三个 Raft 服务（`raftexample1`，`raftexample2`和`raftexample3`）。每个都运行一个 raftexample 实例，通过`--port`公开 API，并使用`--cluster`进行静态集群配置。

您可以在 Docker 主机上启动它：

```
docker-compose -f raftexample.yaml up

```

现在您可以玩了，例如杀死领导者，观察新的选举，通过 API 向一个容器设置一些值，移除容器，更新该值，重新启动容器，检索该值，并注意到它已经正确升级。

与 API 的交互可以通过 curl 完成，如[`github.com/coreos/etcd/tree/master/contrib/raftexample`](https://github.com/coreos/etcd/tree/master/contrib/raftexample)中所述：

```
curl -L http://127.0.0.1:9121/testkey -XPUT -d value
curl -L http://127.0.0.1:9121/testkey

```

我们将这个练习留给更热心的读者。

### 提示

当您尝试采用 Raft 实现时，选择 Etcd 的 Raft 库以获得最高性能，并选择 Consul（来自 Serf 库）以获得即插即用和更容易的实现。

# Etcd

Etcd 是一个高可用、分布式和一致的键值存储，用于共享配置和服务发现。一些使用 Etcd 的知名项目包括 SwarmKit、Kubernetes 和 Fleet。

Etcd 可以在网络分裂的情况下优雅地管理主节点选举，并且可以容忍节点故障，包括主节点。应用程序，例如 Docker 容器和 Swarm 节点，可以读取和写入 Etcd 的键值存储中的数据，例如服务的位置。

## 重新设计第一章的示例，使用 Etcd

我们再次通过演示 Etcd 来创建一个管理器和三个节点的示例。

这次，我们将需要一个真正的发现服务。我们可以通过在 Docker 内部运行 Etcd 服务器来模拟非 HA 系统。我们创建了一个由四个主机组成的集群，名称如下：

+   `etcd-m`将是 Swarm 主节点，也将托管 Etcd 服务器

+   `etcd-1`：第一个 Swarm 节点

+   `etcd-2`：第二个 Swarm 节点

+   `etcd-3`：第三个 Swarm 节点

操作员通过连接到`etcd-m:3376`，将像往常一样在三个节点上操作 Swarm。

让我们从使用 Machine 创建主机开始：

```
for i in m `seq 1 3`; do docker-machine create -d virtualbox etcd-$i; 
done

```

现在我们将在`etcd-m`上运行 Etcd 主节点。我们使用来自 CoreOS 的`quay.io/coreos/etcd`官方镜像，遵循[`github.com/coreos/etcd/blob/master/Documentation/op-guide/clustering.md`](https://github.com/coreos/etcd/blob/master/Documentation/op-guide/clustering.md)上可用的文档。

首先，在终端中，我们设置`etcd-m` shell 变量：

```
term0$ eval $(docker-machine env etcd-m)

```

然后，我们以单主机模式运行 Etcd 主节点（即，没有容错等）：

```
docker run -d -p 2379:2379 -p 2380:2380 -p 4001:4001 \
--name etcd quay.io/coreos/etcd \
-name etcd-m -initial-advertise-peer-urls http://$(docker-machine 
    ip etcd-m):2380 \
-listen-peer-urls http://0.0.0.0:2380 \
-listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001 \
-advertise-client-urls http://$(docker-machine ip etcd-m):2379 \
-initial-cluster-token etcd-cluster-1 \
-initial-cluster etcd-m=http://$(docker-machine ip etcd-m):2380
-initial-cluster-state new

```

我们在这里做的是以守护进程（`-d`）模式启动 Etcd 镜像，并暴露端口`2379`（Etcd 客户端通信）、`2380`（Etcd 服务器通信）、`4001`（），并指定以下 Etcd 选项：

+   `name`：节点的名称，在这种情况下，我们选择 etcd-m 作为托管此容器的节点的名称

+   在这个静态配置中，`initial-advertise-peer-urls`是集群的地址:端口

+   `listen-peer-urls`

+   `listen-client-urls`

+   `advertise-client-urls`

+   `initial-cluster-token`

+   `initial-cluster`

+   `initial-cluster-state`

我们可以使用`etcdctl cluster-health`命令行实用程序确保这个单节点 Etcd 集群是健康的：

```
term0$ docker run fsoppelsa/etcdctl -C $(dm ip etcd-m):2379 
    cluster-health

```

![重新设计第一章的示例，使用 Etcd](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_009.jpg)

这表明 Etcd 至少已经启动运行，因此我们可以使用它来设置 Swarm v1 集群。

我们在同一台`etcd-m`主机上创建 Swarm 管理器：

```
term0$ docker run -d -p 3376:3376 swarm manage \
-H tcp://0.0.0.0:3376 \`
etcd://$(docker-machine ip etcd-m)/swarm

```

这将从主机到容器暴露通常的`3376`端口，但这次使用`etcd://` URL 启动管理器以进行发现服务。

现在我们加入节点，`etcd-1`，`etcd-2`和`etcd-3`。

像往常一样，我们可以为每个终端提供源和命令机器：

```
term1$ eval $(docker-machine env etcd-1)
term1$ docker run -d swarm join --advertise \
$(docker-machine ip etcd-1):2379 \
etcd://$(docker-machine ip etcd-m):2379
term2$ eval $(docker-machine env etcd-2)
term1$ docker run -d swarm join --advertise \
$(docker-machine ip etcd-2):2379 \
etcd://$(docker-machine ip etcd-m):2379
term3$ eval $(docker-machine env etcd-3)
term3$ docker run -d swarm join --advertise \
$(docker-machine ip etcd-3):2379 \
etcd://$(docker-machine ip etcd-m):2379

```

通过使用`-advertise`加入本地节点到 Swarm 集群，使用运行并暴露在`etcd-m`上的 Etcd 服务。

现在我们转到`etcd-m`并通过调用 Etcd 发现服务来查看我们集群的节点：

![使用 Etcd 重新架构第一章的示例](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_02_010.jpg)

我们已经如预期那样将三个主机加入了集群。

# ZooKeeper

ZooKeeper 是另一个广泛使用且高性能的分布式应用协调服务。Apache ZooKeeper 最初是 Hadoop 的一个子项目，但现在是一个顶级项目。它是一个高度一致、可扩展和可靠的键值存储，可用作 Docker Swarm v1 集群的发现服务。如前所述，ZooKeeper 使用 Paxos 而不是 Raft。

与 Etcd 类似，当 ZooKeeper 与法定人数形成节点集群时，它有一个领导者和其余的节点是跟随者。在内部，ZooKeeper 使用自己的 ZAB，即 ZooKeeper 广播协议，来维护一致性和完整性。

# Consul

我们将在这里看到的最后一个发现服务是 Consul，这是一个用于发现和配置服务的工具。它提供了一个 API，允许客户端注册和发现服务。与 Etcd 和 ZooKeeper 类似，Consul 是一个带有 REST API 的键值存储。它可以执行健康检查以确定服务的可用性，并通过 Serf 库使用 Raft 一致性算法。当然，与 Etcd 和 ZooKeeper 类似，Consul 可以形成具有领导者选举的高可用性法定人数。其成员管理系统基于`memberlist`，这是一个高效的 Gossip 协议实现。

## 使用 Consul 重新架构第一章的示例

现在我们将创建另一个 Swarm v1，但在本节中，我们将在云提供商 DigitalOcean 上创建机器。为此，您需要一个访问令牌。但是，如果您没有 DigitalOcean 帐户，可以将`--driver digitalocean`替换为`--driver virtualbox`并在本地运行此示例。

让我们从创建 Consul 主节点开始：

```
$ docker-machine create --driver digitalocean consul-m
$ eval $(docker-machine env consul-m)

```

我们在这里启动第一个代理。虽然我们称它为代理，但实际上我们将以服务器模式运行它。我们使用服务器模式（`-server`）并将其设置为引导节点（`-bootstrap`）。使用这些选项，Consul 将不执行领导者选择，因为它将强制自己成为领导者。

```
$ docker run -d --name=consul --net=host \
consul agent \
-client=$(docker-machine ip consul-m) \
-bind=$(docker-machine ip consul-m) \
-server -bootstrap

```

在 HA 的情况下，第二个和第三个节点必须以`-botstrap-expect 3`开头，以允许它们形成一个高可用性集群。

现在，我们可以使用`curl`命令来测试我们的 Consul quorum 是否成功启动。

```
$ curl -X GET http://$(docker-machine ip consul-m):8500/v1/kv/

```

如果没有显示任何错误，那么 Consul 就正常工作了。

接下来，我们将在 DigitalOcean 上创建另外三个节点。

```
$ for i in `seq 1 3`; do docker-machine create -d digitalocean 
    consul-$i; 
    done

```

让我们启动主节点并使用 Consul 作为发现机制：

```
$ eval $(docker-machine env consul-m)
$ docker run -d -p 3376:3376 swarm manage \
-H tcp://0.0.0.0:3376 \
consul://$(docker-machine ip consul-m):8500/swarm
$ eval $(docker-machine env consul-1)
$ docker run -d swarm join \
--advertise $(docker-machine ip consul-1):2376 \
consul://$(docker-machine ip consul-m):8500/swarm
$ eval $(docker-machine env consul-2)
$ docker run -d swarm join \
--advertise $(docker-machine ip consul-2):2376 \
consul://$(docker-machine ip consul-m):8500/swarm
$ eval $(docker-machine env consul-3)
$ docker run -d swarm join \
--advertise $(docker-machine ip consul-3):2376 \
consul://$(docker-machine ip consul-m):8500/swarm

```

运行`swarm list`命令时，我们得到的结果是：所有节点都加入了 Swarm，所以示例正在运行。

```
$ docker run swarm list consul://$(docker-machine ip consul-m):8500/swarm                                       time="2016-07-01T21:45:18Z" level=info msg="Initializing discovery without TLS"
104.131.101.173:2376
104.131.63.75:2376
104.236.56.53:2376

```

# 走向去中心化的发现服务

Swarm v1 架构的局限性在于它使用了集中式和外部的发现服务。这种方法使每个代理都要与外部发现服务进行通信，而发现服务服务器可能会看到它们的负载呈指数级增长。根据我们的实验，对于一个 500 节点的集群，我们建议至少使用三台中高规格的机器来形成一个 HA 发现服务，比如 8 核 8GB 的内存。

为了正确解决这个问题，SwarmKit 和 Swarm Mode 使用的发现服务是以去中心化为设计理念的。Swarm Mode 在所有节点上都使用相同的发现服务代码库 Etcd，没有单点故障。

# 总结

在本章中，我们熟悉了共识和发现服务的概念。我们了解到它们在编排集群中扮演着至关重要的角色，因为它们提供了容错和安全配置等服务。在详细分析了 Raft 等共识算法之后，我们看了两种具体的 Raft 发现服务实现，Etcd 和 Consul，并将它们应用到基本示例中进行了重新架构。在下一章中，我们将开始探索使用嵌入式 Etcd 库的 SwarmKit 和 Swarm。


# 第三章：了解 Docker Swarm 模式

在 Dockercon 16 上，Docker 团队提出了一种操作 Swarm 集群的新方式，称为 Swarm 模式。这一宣布略有预期，因为引入了一套新的工具，被称为*在任何规模上操作分布式系统*的**Swarmkit**。

在本章中，我们将：

+   介绍 Swarmkit

+   介绍 Swarm 模式

+   比较 Swarm v1、Swarmkit 和 Swarm 模式

+   创建一个测试 Swarmkit 集群，并在其上启动服务。

不要跳过阅读 Swarmkit 部分，因为 Swarmkit 作为 Swarm 模式的基础。看到 Swarmkit 是我们选择介绍 Swarm 模式概念的方式，比如节点、服务、任务。

我们将展示如何在第四章中创建生产级别的大型 Swarm 模式集群，*创建生产级别的 Swarm*。

# Swarmkit

除了 Swarm 模式，Docker 团队在 DockerCon16 发布了 Swarmkit，被定义为：

> *“用于在任何规模上编排分布式系统的工具包。它包括节点发现、基于 raft 的共识、任务调度等基元。”*

**Swarms**集群由活动节点组成，可以充当管理者或工作者。

管理者通过 Raft 进行协调（也就是说，当达成法定人数时，他们会选举领导者，如第二章中所述，*发现发现服务*），负责分配资源、编排服务和在集群中分发任务。工作者运行任务。

集群的目标是执行*服务*，因此需要在高层次上定义要运行的内容。例如，一个服务可以是“web”。分配给节点的工作单元称为**任务**。分配给“web”服务的任务可能是运行 nginx 容器的容器，可能被命名为 web.5。

非常重要的是要注意我们正在谈论服务，而服务可能是容器。可能不是必要的。在本书中，我们的重点当然是容器，但 Swarmkit 的意图理论上是抽象编排任何对象。

## 版本和支持

关于版本的说明。我们将在接下来的章节中介绍的 Docker Swarm 模式，只与 Docker 1.12+兼容。而 Swarmkit 可以编排甚至是以前版本的 Docker 引擎，例如 1.11 或 1.10。

## Swarmkit 架构

**Swarmkit**是发布的编排机制，用于处理任何规模的服务集群。

在 Swarmkit 集群中，节点可以是**管理者**（集群的管理者）或**工作节点**（集群的工作马，执行计算操作的节点）。

最好有奇数个管理者，最好是 3 或 5 个，这样就不会出现分裂的情况（如第二章中所解释的，*发现发现服务*），并且大多数管理者将驱动集群。Raft 一致性算法始终需要法定人数。

Swarmkit 集群可以承载任意数量的工作节点：1、10、100 或 2000。

在管理者上，**服务**可以被定义和负载平衡。例如，一个服务可以是“web”。一个“web”服务将由运行在集群节点上的多个**任务**组成，包括管理者，例如，一个任务可以是一个单独的 nginx Docker 容器。

![Swarmkit 架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_001.jpg)

在 Swarmkit 中，操作员使用**Swarmctl**二进制文件远程与系统交互，在领导主节点上调用操作。运行名为**Swarmd**的主节点通过 Raft 同意领导者，保持服务和任务的状态，并在工作节点上调度作业。

工作节点运行 Docker 引擎，并将作业作为单独的容器运行。

Swarmkit 架构可能会被重新绘制，但核心组件（主节点和工作节点）将保持不变。相反，可能会通过插件添加新对象，用于分配资源，如网络和卷。

### 管理者如何选择最佳节点执行任务

Swarmkit 在集群上生成任务的方式称为**调度**。调度程序是一个使用诸如过滤器之类的标准来决定在哪里物理启动任务的算法。

![管理者如何选择最佳节点执行任务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_002.jpg)

## SwarmKit 的核心：swarmd

启动 SwarmKit 服务的核心二进制文件称为`swarmd`，这是创建主节点和加入从节点的守护程序。

它可以绑定到本地 UNIX 套接字和 TCP 套接字，但无论哪种情况，都可以通过连接到（另一个）专用的本地 UNIX 套接字来由`swarmctl`实用程序管理。

在接下来的部分中，我们将使用`swarmd`在端口`4242/tcp`上创建一个第一个管理者，并再次使用`swarmd`在其他工作节点上，使它们加入管理者，最后我们将使用`swarmctl`来检查我们集群的一些情况。

这些二进制文件被封装到`fsoppelsa/swarmkit`镜像中，该镜像可在 Docker Hub 上获得，并且我们将在这里使用它来简化说明并避免 Go 代码编译。

这是 swarmd 的在线帮助。它在其可调整项中相当自解释，因此我们不会详细介绍所有选项。对于我们的实际目的，最重要的选项是`--listen-remote-api`，定义`swarmd`绑定的`address:port`，以及`--join-addr`，用于其他节点加入集群。

![SwarmKit 的核心：swarmd](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_003.jpg)

## SwarmKit 的控制器：swarmctl

`swarmctl`是 SwarmKit 的客户端部分。这是用于操作 SwarmKit 集群的工具，它能够显示已加入节点的列表、服务和任务的列表，以及其他信息。这里，再次来自`fsoppelsa/swarmkit`，`swarmctl`的在线帮助：

![SwarmKit 的控制器：swarmctl](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_004.jpg)

## 使用 Ansible 创建 SwarmKit 集群

在这一部分，我们将首先创建一个由单个管理节点和任意数量的从节点组成的 SwarmKit 集群。

为了创建这样的设置，我们将使用 Ansible 来使操作可重复和更加健壮，并且除了说明命令，我们还将通过检查 playbooks 结构来进行。您可以轻松地调整这些 playbooks 以在您的提供商或本地运行，但在这里我们将在 Amazon EC2 上进行。 

为了使这个示例运行，有一些基本要求。

如果您想在 AWS 上跟随示例，当然您必须拥有 AWS 账户并配置访问密钥。密钥可从 AWS 控制台中的**账户名称** | **安全凭据**下检索。您需要复制以下密钥的值：

+   访问密钥 ID

+   秘密访问密钥

我使用`awsctl`来设置这些密钥。只需从*brew*（Mac）安装它，或者如果您使用 Linux 或 Windows，则从您的打包系统安装它，并进行配置：

```
aws configure

```

在需要时通过粘贴密钥来回答提示问题。配置中，您可以指定例如一个喜爱的 AWS 区域（如`us-west-1`）存储在`~/.aws/config`中，而凭据存储在`~/.aws/credentials`中。这样，密钥会被 Docker Machine 自动配置和读取。

如果您想运行 Ansible 示例而不是命令，这些是软件要求：

+   Ansible 2.2+

+   与 docker-machine 将在 EC2 上安装的镜像兼容的 Docker 客户端（在我们的情况下，默认的是 Ubuntu 15.04 LTS）一起使用，写作时，Docker Client 1.11.2

+   Docker-machine

+   Docker-py 客户端（由 Ansible 使用）可以通过`pip install docker-py`安装

此外，示例使用标准端口`4242/tcp`，以使集群节点相互交互。因此，需要在安全组中打开该端口。

克隆存储库[`github.com/fsoppelsa/ansible-swarmkit`](https://github.com/fsoppelsa/ansible-swarmkit)，并开始设置 SwarmKit Manager 节点：

```
ansible-playbook aws_provision_master.yml

```

![使用 Ansible 配置 SwarmKit 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_005.jpg)

经过一些 docker-machine 的设置后，playbook 将在 Manager 主机上启动一个容器，充当 SwarmKit Manager。以下是 play 片段：

```
- name: Run the Swarmkit Master 
  docker: 
  name: swarmkit-master 
  image: "fsoppelsa/swarmkit" 
  command: swarmd --listen-remote-api 0.0.0.0:4242 
  expose: 
    - "4242" 
  ports: 
    - "0.0.0.0:4242:4242/tcp" 
  volumes: 
    - "/var/run/docker.sock:/var/run/docker.sock" 
  detach: yes 
  docker_url: "{{ dhost }}" 
  use_tls: encrypt 
  tls_ca_cert: "{{ dcert }}/ca.pem" 
  tls_client_cert: "{{ dcert }}/cert.pem" 
  tls_client_key: "{{ dcert }}/key.pem" 

```

在主机上，名为`swarmkit-master`的容器从图像`fsoppelsa/swarmkit`中运行`swarmd`以管理模式运行（它在`0.0.0.0:4242`处监听）。`swarmd`二进制文件直接使用主机上的 Docker Engine，因此 Engine 的套接字被挂载到容器内。容器将端口`4242`映射到主机端口`4242`，以便从属节点可以通过连接到主机`4242`端口直接访问`swarmd`。

实际上，这相当于以下 Docker 命令：

```
docker run -d -v /var/run/docker.sock:/var/run/docker.sock -p 
    4242:4242 fsoppelsa/swarmkit swarmd --listen-remote-api  
    0.0.0.0:4242

```

此命令以分离模式（`-d`）运行，通过卷（`-v`）将 Docker 机器 Docker 套接字传递到容器内部，将容器中的端口`4242`暴露到主机（`-p`），并通过将容器本身放在任何地址上的端口`4242`上运行`swarmd`，使其处于监听模式。

一旦 playbook 完成，您可以获取`swarmkit-master`机器的凭据并检查我们的容器是否正常运行：

![使用 Ansible 配置 SwarmKit 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_006.jpg)

现在是加入一些从属节点的时候了。要启动一个从属节点，您可以，猜猜看，只需运行：

```
ansible-playbook aws_provision_slave.yml

```

但由于我们希望至少加入几个节点到 SwarmKit 集群中，我们使用一点 shell 脚本：

```
for i in $(seq 5); do ansible-playbook aws_provision_slave.yml; 
    done

```

此命令运行五次 playbook，从而创建五个工作节点。playbook 在创建名为`swarmkit-RANDOM`的机器后，将启动一个`fsoppelsa/swarmkit`容器，执行以下操作：

```
- name: Join the slave to the Swarmkit cluster
  docker:
    name: "{{machine_uuid}}"
    image: "fsoppelsa/swarmkit"
    command: swarmd --join-addr "{{ masterip }}":4242
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    detach: yes
    docker_url: "{{ shost }}"
```

在这里，swarmd 以加入模式运行，并通过连接到端口`4242/tcp`加入在 Master 上启动的集群。这相当于以下 docker 命令：

```
docker run -d -v /var/run/docker.sock:/var/run/docker.sock 
    fsoppelsa/swarmkit swarmd --join-addr $(docker-machine ip swarmkit- 
    master):4242

```

ansible 的`loop`命令将需要一些时间来完成，这取决于有多少工作节点正在启动。当 playbook 完成后，我们可以使用`swarmctl`来控制集群是否正确创建。如果您还没有提供`swarmkit-master`机器凭据，现在是时候了：

```
eval $(docker-machine env swarmkit-master)

```

现在我们使用 exec 来调用运行 swarmd 主节点的容器：

```
docker exec -ti 79d9be555dab swarmctl -s /swarmkitstate/swarmd.sock 
    node ls

```

![使用 Ansible 配置 SwarmKit 集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_007.jpg)

所以，这里列出了已加入主节点的工作节点。

## 在 SwarmKit 上创建服务

使用通常的`swarmctl`二进制文件，我们现在可以创建一个服务（web），由 nginx 容器制成。

我们首先检查一下，确保这个全新的集群上没有活动服务：

![在 SwarmKit 上创建服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_008.jpg)

所以我们准备好开始了，使用这个命令：

```
docker exec -ti 79d9be555dab swarmctl service create --name web --
    image nginx --replicas 5

```

![在 SwarmKit 上创建服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_009.jpg)

该命令指定创建一个名为`web`的服务，由`nginx`容器镜像制成，并且使用因子`5`进行复制，以在集群中创建 5 个 nginx 容器。这需要一些时间生效，因为在集群的每个节点上，Swarm 将拉取并启动 nginx 镜像，但最终：

![在 SwarmKit 上创建服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_010.jpg)

**5/5**表示在 5 个期望的副本中，有 5 个正在运行。我们可以使用`swarmctl task ls`来详细查看这些容器生成的位置：

![在 SwarmKit 上创建服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_011.jpg)

但是，等等，manager 节点上是否正在运行 nginx 服务（web.5）？是的。默认情况下，SwarmKit 和 Swarm 模式管理者被允许运行任务，并且调度程序可以将作业分派给它们。

在真实的生产配置中，如果您想要保留管理者不运行作业，您需要应用带有标签和约束的配置。这是第五章*管理 Swarm 集群*的主题。

# Swarm 模式

Docker Swarm 模式（适用于版本 1.12 或更新版本的 Docker 引擎）导入了 SwarmKit 库，以便实现在多个主机上进行分布式容器编排，并且操作简单易行。

SwarmKit 和 Swarm 模式的主要区别在于，Swarm 模式集成到了 Docker 本身，从版本 1.12 开始。这意味着 Swarm 模式命令，如`swarm`，`nodes`，`service`和`task`在 Docker 客户端*内部*可用，并且通过 docker 命令可以初始化和管理 Swarm，以及部署服务和任务：

+   `docker swarm init`: 这是用来初始化 Swarm 集群的

+   `docker node ls`: 用于列出可用节点

+   `docker service tasks`: 用于列出与特定服务相关的任务

## 旧的 Swarm 与新的 Swarm 与 SwarmKit

在撰写本文时（2016 年 8 月），我们有三个 Docker 编排系统：旧的 Swarm v1，SwarmKit 和集成的新 Swarm 模式。

![旧的 Swarm 与新的 Swarm 与 SwarmKit](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_012.jpg)

我们在第一章中展示的原始 Swarm v1，*欢迎来到 Docker Swarm*，仍在使用，尚未被弃用。这是一种使用（回收利用？）旧基础设施的方式。但是从 Docker 1.12 开始，新的 Swarm 模式是开始新编排项目的推荐方式，特别是如果需要扩展到大规模。

为了简化事情，让我们用一些表格总结这些项目之间的区别。

首先，旧的 Swarm v1 与新的 Swarm 模式：

| **Swarm standalone** | **Swarm Mode** |
| --- | --- |
| 这是自 Docker 1.8 起可用 | 这是自 Docker 1.12 起可用 |
| 这可用作容器 | 这集成到 Docker Engine 中 |
| 这需要外部发现服务（如 Consul、Etcd 或 Zookeeper） | 这不需要外部发现服务，Etcd 集成 |
| 这默认不安全 | 这默认安全 |
| 复制和扩展功能不可用 | 复制和扩展功能可用 |
| 没有用于建模微服务的服务和任务概念 | 有现成的服务、任务、负载均衡和服务发现 |
| 没有额外的网络可用 | 这个集成了 VxLAN（网状网络） |

现在，为了澄清想法，让我们比较一下 SwarmKit 和 Swarm 模式：

| **SwarmKit** | **Swarm mode** |
| --- | --- |
| 这些发布为二进制文件（`swarmd`和`swarmctl`）-使用 swarmctl | 这些集成到 Docker Engine 中-使用 docker |
| 这些是通用任务 | 这些是容器任务 |
| 这些包括服务和任务 | 这些包括服务和任务 |
| 这些不包括服务高级功能，如负载平衡和 VxLAN 网络 | 这些包括开箱即用的服务高级功能，如负载平衡和 VxLAN 网络 |

## Swarm 模式放大

正如我们在 Swarm 独立与 Swarm 模式比较的前表中已经总结的，Swarm 模式中的主要新功能包括集成到引擎中，无需外部发现服务，以及包括副本、规模、负载平衡和网络。

### 集成到引擎中

使用 docker 1.12+，docker 客户端添加了一些新命令。我们现在对与本书相关的命令进行调查。

#### docker swarm 命令

这是管理 Swarm 的当前命令：

![docker swarm command](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_013.jpg)

它接受以下选项：

+   `init`：这将初始化一个 Swarm。在幕后，此命令为当前 Docker 主机创建一个管理者，并生成一个*秘密*（工作节点将通过 API 传递给密码以获得加入集群的授权）。

+   `join`：这是工作节点加入集群的命令，必须指定*秘密*和管理者 IP 端口值列表。

+   `join-token`：这用于管理`join-tokens`。`join-tokens`是用于使管理者或工作节点加入的特殊令牌秘密（管理者和工作节点具有不同的令牌值）。此命令是使 Swarm 打印加入管理者或工作节点所需命令的便捷方式：

```
docker swarm join-token worker

```

要将工作节点添加到此 Swarm，请运行以下命令：

```
docker swarm join \ --token SWMTKN-1-  
        36gj6glgi3ub2i28ekm1b1er8aa51vltv00760t7umh3wmo1sc- 
        aucj6a94tqhhn2k0iipnc6096 \ 192.168.65.2:2377
docker swarm join-token manager

```

要将管理者添加到此 Swarm，请运行以下命令：

```
docker swarm join \ --token SWMTKN-1- 
        36gj6glgi3ub2i28ekm1b1er8aa51vltv00760t7umh3wmo1sc- 
        98glton0ot50j1yn8eci48rvq \ 192.168.65.2:2377

```

+   `update`：这将通过更改一些值来更新集群，例如，您可以使用它来指定证书端点的新 URL

+   `leave`：此命令使当前节点离开集群。如果有什么阻碍了操作，有一个有用的`--force`选项。

#### docker 节点

这是处理集群节点的命令。您必须从管理者启动它，因此您需要连接到管理者才能使用它。

![docker 节点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_014.jpg)

+   `demote`和`promote`：这些是用于管理节点状态的命令。通过该机制，您可以将节点提升为管理者，或将其降级为工作节点。在实践中，Swarm 将尝试`demote`/`promote`。我们将在本章稍后介绍这个概念。

+   `inspect`：这相当于 docker info，但用于 Swarm 节点。它打印有关节点的信息。

+   `ls`：这列出了连接到集群的节点。

+   `rm`：这尝试移除一个 worker。如果你想移除一个 manager，在此之前你需要将其降级为 worker。

+   `ps`：这显示了在指定节点上运行的任务列表。

+   `update`：这允许您更改节点的一些配置值，即标签。

#### docker service

这是管理运行在 Swarm 集群上的服务的命令：

![docker service](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_015.jpg)

除了预期的命令，如`create`、`inspect`、`ps`、`ls`、`rm`和`update`，还有一个新的有趣的命令：`scale`。

#### Docker Stack

并不直接需要 Swarm 操作，但在 Docker 1.12 中作为实验引入了`stack`命令。Stacks 现在是容器的捆绑。例如，一个 nginx + php + mysql 容器设置可以被堆叠在一个自包含的 Docker Stack 中，称为**分布式应用程序包**（**DAB**），并由一个 JSON 文件描述。

docker stack 的核心命令将是 deploy，通过它将可以创建和更新 DABs。我们稍后会在第六章中遇到 stacks，*在 Swarm 上部署真实应用程序*。

### Etcd 的 Raft 已经集成

Docker Swarm Mode 已经通过 CoreOS Etcd Raft 库集成了 RAFT。不再需要集成外部发现服务，如 Zookeeper 或 Consul。Swarm 直接负责基本服务，如 DNS 和负载均衡。

安装 Swarm Mode 集群只是启动 Docker 主机并运行 Docker 命令的问题，使得设置变得非常容易。

### 负载均衡和 DNS

按设计，集群管理器为 Swarm 中的每个服务分配一个唯一的 DNS 名称，并使用内部 DNS 对运行的容器进行负载均衡。查询和解析可以自动工作。 

对于使用`--name myservice`创建的每个服务，Swarm 中的每个容器都将能够解析服务 IP 地址，就像它们正在解析（`dig myservice`）内部网络名称一样，使用 Docker 内置的 DNS 服务器。因此，如果你有一个`nginx-service`（例如由 nginx 容器组成），你可以只需`ping nginx-service`来到达前端。

此外，在 Swarm 模式下，操作员有可能将服务端口`发布`到外部负载均衡器。然后，端口在`30000`到`32767`的范围内暴露到外部。在内部，Swarm 使用 iptables 和 IPVS 来执行数据包过滤和转发，以及负载均衡。

Iptables 是 Linux 默认使用的数据包过滤防火墙，而 IPVS 是在 Linux 内核中定义的经验丰富的 IP 虚拟服务器，可用于负载均衡流量，这正是 Docker Swarm 所使用的。

端口要么在创建新服务时发布，要么在更新时发布，使用`--publish-add`选项。使用此选项，内部服务被发布，并进行负载均衡。

例如，如果我们有一个包含三个工作节点的集群，每个节点都运行 nginx（在名为`nginx-service`的服务上），我们可以将它们的目标端口暴露给负载均衡器：

```
docker service update --port-add 80 nginx-service

```

这将在集群的任何节点上创建一个映射，将发布端口`30000`与`nginx`容器（端口 80）关联起来。如果您连接到端口`30000`的任何节点，您将看到 Nginx 的欢迎页面。

![负载均衡和 DNS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_016.jpg)

但是这是如何工作的呢？正如您在上面的屏幕截图中看到的，有一个关联的虚拟 IP（`10.255.0.7/16`），或者 VIP，它位于由 Swarm 创建的覆盖网络**2xbr2upsr3yl**上，用于负载均衡器的入口：

![负载均衡和 DNS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_017.jpg)

从任何主机，您都可以访问`nginx-service`，因为 DNS 名称解析为 VIP，这里是 10.255.0.7，充当负载均衡器的前端：

在 Swarm 的每个节点上，Swarm 在内核中实现负载均衡，具体来说是在命名空间内部，通过在专用于网络的网络命名空间中的 OUTPUT 链中添加一个 MARK 规则，如下屏幕截图所示：

![负载均衡和 DNS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_03_018.jpg)

我们将在稍后的第五章 *管理 Swarm 集群*和第八章 *探索 Swarm 的其他功能*中更详细地介绍网络概念。

### 提升和降级

使用`docker node`命令，集群操作员可以将节点从工作节点提升为管理节点，反之亦然，将它们从管理节点降级为工作节点。

将节点从管理节点降级为工作节点是从集群中删除管理节点（现在是工作节点）的唯一方法。

我们将在第五章中详细介绍晋升和降级操作，*管理 Swarm 集群*。

### 副本和规模

在 Swarm 集群上部署应用意味着定义和配置服务，启动它们，并等待分布在集群中的 Docker 引擎启动容器。我们将在第六章中在 Swarm 上部署完整的应用程序，*在 Swarm 上部署真实应用程序*。

### 服务和任务

Swarm 工作负载的核心被划分为服务。服务只是一个将任意数量的任务（这个数量被称为*副本因子*或者*副本*）分组的抽象。任务是运行的容器。

#### docker service scale

使用`docker service scale`命令，您可以命令 Swarm 确保集群中同时运行一定数量的副本。例如，您可以从运行在集群上的 10 个容器开始执行一些*任务*，然后当您需要将它们的大小扩展到 30 时，只需执行：

```
docker service scale myservice=30

```

Swarm 被命令安排调度 20 个新容器，因此它会做出适当的决策来实现负载平衡、DNS 和网络的一致性。如果一个*任务*的容器关闭，使副本因子等于 29，Swarm 将在另一个集群节点上重新安排另一个容器（它将具有新的 ID）以保持因子等于 30。

关于副本和新节点添加的说明。人们经常询问 Swarm 的自动能力。如果您有五个运行 30 个任务的工作节点，并添加了五个新节点，您不应该期望 Swarm 自动地在新节点之间平衡 30 个任务，将它们从原始节点移动到新节点。Swarm 调度程序的行为是保守的，直到某个事件（例如，操作员干预）触发了一个新的`scale`命令。只有在这种情况下，调度程序才会考虑这五个新节点，并可能在 5 个新工作节点上启动新的副本任务。

我们将在第七章中详细介绍`scale`命令的实际工作，*扩展您的平台*。

# 总结

在本章中，我们遇到了 Docker 生态系统中的新角色：SwarmKit 和 Swarm Mode。我们通过在 Amazon AWS 上使用 Ansible 对 SwarmKit 集群进行了简单的实现。然后，我们介绍了 Swarm Mode 的基本概念，包括其界面和内部机制，包括 DNS、负载平衡、服务、副本以及晋升/降级机制。现在，是时候深入了解真正的 Swarm Mode 部署了，就像我们将在第四章 *创建一个生产级别的 Swarm*中看到的那样。


# 第四章：创建生产级别的 Swarm

在这一章中，您将学习如何创建拥有数千个节点的真实 Swarm 集群；具体来说，我们将涵盖以下主题：

+   部署大型 Swarm 的工具

+   Swarm2k：有史以来构建的最大 Swarm 模式集群之一，由 2,300 个节点组成

+   Swarm3k：第二个实验，一个拥有 4,700 个节点的集群

+   如何规划硬件资源

+   HA 集群拓扑

+   Swarm 基础设施管理、网络和安全

+   监控仪表板

+   从 Swarm2k 和 Swarm3k 实验中学到的东西

# 工具

使用 Swarm 模式，我们可以轻松设计生产级别的集群。

我们在这里阐述的原则和架构在一般情况下非常重要，并为如何设计生产安装提供了基础，无论使用何种工具。然而，从实际角度来看，使用的工具也很重要。

在撰写本书时，Docker Machine 并不是用于大规模 Swarm 设置的理想单一工具，因此我们将使用一个与本书同时诞生的工具来演示我们的生产规模部署，该工具已在第一章中介绍过，*欢迎来到 Docker Swarm*：belt ([`github.com/chanwit/belt`](https://github.com/chanwit/belt))。我们将与 Docker Machine、Docker Networking 和 DigitalOcean 的`doctl`命令一起使用它。

在第五章中，*管理 Swarm 集群*，您将学习如何自动化创建 Swarm；特别是如何通过脚本和其他机制（如 Ansible）快速加入大量的工作节点。

![工具](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_001.jpg)

# Swarm2k 的 HA 拓扑

Swarm2k 和 Swarm3k 是协作实验。我们通过呼吁参与者以 Docker 主机而不是金钱来筹集资金，结果令人惊讶-Swarm2k 和 Swarm3k 得到了数十个个人和公司地理分布的贡献者的支持。总共，对于 Swarm2k，我们收集了大约 2,300 个节点，而对于 Swarm3k，大约有 4,700 个节点。

让我们讨论*Swarm2k*的架构。在前面的图中，有三个管理者，分别标记为**mg0**、**mg1**和**mg2**。我们将使用三个管理者，因为这是 Docker 核心团队建议的最佳管理者数量。管理者在高速网络链路上形成法定人数，并且 Raft 节点需要大量资源来同步它们的活动。因此，我们决定将我们的管理者部署在同一数据中心的 40GB 以太网链路上。

在实验开始时，我们有以下配置：

+   mg0 是集群的管理者领导者

+   mg1 托管了统计收集器

+   mg2 是一个准备（备用）管理者

相反，**W**节点是 Swarm 工作者。

安装在 mg1 上的统计收集器从本地 Docker Engine 查询信息，并将其发送到远程时间序列数据库*InfluxDB*中存储。我们选择了 InfluxDB，因为它是*Telegraf*监控代理的本地支持。为了显示集群的统计信息，我们使用*Grafana*作为仪表板，稍后我们会看到。

## 管理者规格

管理者受 CPU 限制而不是内存限制。对于一个 500-1,000 节点的 Swarm 集群，我们经验性地观察到每个管理者具有 8 个虚拟 CPU 足以承担负载。然而，如果超过 2,000 个节点，我们建议每个管理者至少具有 16-20 个虚拟 CPU 以满足可能的 Raft 恢复。

### 在 Raft 恢复的情况下

下图显示了硬件升级期间的 CPU 使用情况以及大量工作者加入过程中的情况。在将硬件升级到 8 个虚拟 CPU 时（机器的停机时间由线条表示），我们可以看到领导者 mg0 的 CPU 使用率在 mg**1**和 mg**2**重新加入集群时飙升至 75-90%。触发此飙升的事件是 Raft 日志的同步和恢复。

在没有必要恢复的正常情况下，每个管理者的 CPU 使用率保持较低，如下图所示。

![在 Raft 恢复的情况下](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_002.jpg)

## Raft 文件

在管理主机上，Swarm 数据保存在`/var/lib/docker/swarm`中，称为*swarm 目录*。具体来说，Raft 数据保存在`/var/lib/docker/swarm/raft`中，包括预写式日志（WAL）和快照文件。

在这些文件中，有关节点、服务和任务的条目，按照 Protobuf 格式定义。

WAL 和快照文件经常写入磁盘。在 SwarmKit 和 Docker Swarm 模式中，它们每 10,000 个条目写入一次磁盘。根据这种行为，我们将 swarm 目录映射到具有增加吞吐量的快速和专用磁盘，特别是 SSD 驱动器。

我们将在第五章 *管理 Swarm 集群*中解释在 Swarm 目录损坏的情况下的备份和恢复程序。

## 运行任务

Swarm 集群的目标是运行服务，例如，由大量容器组成的大规模 Web 应用程序。我们将这种部署类型称为*单一*模型。在这个模型中，网络端口被视为必须全局发布的资源。在未来版本的 Docker Swarm 模式中，使用*命名空间*，部署可以是*多*模型，允许我们拥有多个子集群，这些子集群为不同的服务公开相同的端口。

在小型集群中，我们可以决定允许管理者谨慎地托管工作任务。对于更大的设置，管理者使用更多的资源。此外，如果管理者的负载饱和了其资源，集群将变得不稳定和无响应，并且不会执行任何命令。我们称这种状态为*狂暴* *状态*。

为了使大型集群，如 Swarm2k 或 Swarm3k 稳定，所有管理者的可用性必须设置为“排水”状态，以便所有任务不会被安排在它们上面，只会在工作节点上，具体为：

```
 docker node update --availability drain node-name

```

## 管理者拓扑结构

我们将在第五章 *管理 Swarm 集群*中再次讨论这个 HA 属性，但在这里，我们将介绍它来说明一些 Swarm 拓扑理论。HA 理论要求形成一个具有奇数节点数的 HA 集群。以下表格显示了单个数据中心的容错因素。在本章中，我们将称之为 5(1)-3-2 公式，用于 5 个节点在 1 个数据中心上的集群大小，其中 3 个节点法定人数允许 2 个节点故障。

| **集群大小** | **法定人数** | **允许节点故障** |
| --- | --- | --- |
| 3 | 2 | 1 |
| 5 | 3 | 2 |
| 7 | 4 | 3 |
| 9 | 5 | 4 |

然而，在多个数据中心的生产环境中可以设计出几种管理者拓扑结构。例如，3(3)管理者拓扑结构可以分布为 1 + 1 + 1，而 5(3)管理者拓扑结构可以分布为 2 + 2 + 1。以下图片显示了最佳的 5(3)管理者拓扑结构：

![管理者拓扑结构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_003.jpg)

在相同的容错水平下，下一张图片显示了一个替代的 5(4)拓扑，其中包含了 4 个数据中心的 5 个管理者。在数据中心 1 中运行了 2 个管理者 mg0 和 mg1，而剩下的管理者 mg2、mg3 和 mg4 分别在数据中心 2、3 和 4 中运行。mg0 和 mg1 管理者在高速网络上连接，而 mg2、mg3 和 mg4 可以使用较慢的链接。因此，在 3 个数据中心中的 2 + 2 + 1 将被重新排列为在 4 个数据中心中的 2 + 1 + 1 + 1。

![管理者拓扑结构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_004.jpg)

最后，还有另一种分布式拓扑，6(4)，它的性能更好，因为在其核心有 3 个节点在高速链接上形成中央仲裁。6 个管理者的集群需要一个 4 的仲裁大小。如果数据中心 1 失败，集群的控制平面将停止工作。在正常情况下，除了主要数据中心外，可以关闭 2 个节点或 2 个数据中心。

![管理者拓扑结构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_005.jpg)

总之，尽可能使用奇数个管理者。如果您想要管理者仲裁的稳定性，请在高速链接上形成它。如果您想要避免单点故障，请尽可能将它们分布开来。

要确认哪种拓扑结构适合您，请尝试形成它，并通过有意将一些管理者关闭然后测量它们恢复的速度来测试管理者的延迟。

对于 Swarm2k 和 Swarm3k，我们选择在单个数据中心上形成拓扑结构，因为我们希望实现最佳性能。

# 使用 belt 进行基础设施的配置。

首先，我们使用以下命令为 DigitalOcean 创建了一个名为`swarm2k`的集群模板：

```
 $ belt cluster new --driver digitalocean swarm2k

```

上述命令在当前目录中创建了一个名为`.belt/swarm2k/config.yml`的配置模板文件。这是我们定义其他属性的起点。

我们通过运行以下命令来检查我们的集群是否已定义：

```
 $ belt cluster ls
 CLUSTER       ACTIVE    LEADER    MASTERS    #NODES
 swarm2k       -         -         -          0 / 0

```

使用该命令，我们可以切换并使用可用的`swarm2k`集群，如下所示：

```
 $ belt use swarm2k
 swarm2k

```

在这一点上，我们完善了`swarm2k`模板的属性。

通过发出以下命令将 DigitalOcean 的实例区域设置为`sgp1`：

```
 $ belt cluster update region=sgp1

```

Belt 需要使用该命令定义所有必要的值。以下是我们在`config.yml`中指定的 DigitalOcean 驱动程序所需的模板键列表：

+   `image`：这是为了指定 DigitalOcean 镜像 ID 或快照 ID

+   `region`：这是为了指定 DigitalOcean 区域，例如 sgp1 或 nyc3

+   `ssh_key_fingerprint`：这是为了指定 DigitalOcean SSH 密钥 ID 或指纹

+   `ssh_user`：这是为了指定镜像使用的用户名，例如 root

+   `access_token`：这是为了指定 DigitalOcean 的访问令牌；建议不要在这里放任何令牌

### 提示

每个模板属性都有其对应的环境变量。例如，`access_token`属性可以通过`DIGITALOCEAN_ACCESS_TOKEN`来设置。因此，在实践中，我们也可以在继续之前将`DIGITALOCEAN_ACCESS_TOKEN`导出为一个 shell 变量。

配置就绪后，我们通过运行以下代码验证了当前的模板属性：

```
 $ belt cluster config
 digitalocean:
 image: "123456"
 region: sgp1
 ssh_key_fingerprint: "800000"
 ssh_user: root

```

现在，我们使用以下语法创建了一组 3 个 512MB 的管理节点，分别称为 mg0、mg1 和 mg2：

```
 $ belt create 8192MB mg[0:2]
 NAME   IPv4         MEMORY  REGION  IMAGE       STATUS
 mg2    128.*.*.11   8192     sgp1   Ubuntu docker-1.12.1 new
 mg1    128.*.*.220  8192     sgp1   Ubuntu docker-1.12.1 new
 mg0    128.*.*.21   8192     sgp1   Ubuntu docker-1.12.1 new

```

所有新节点都被初始化并进入新状态。

我们可以使用以下命令等待所有 3 个节点变为活动状态：

```
 $ belt status --wait active=3
 STATUS  #NODES  NAMES
 new         3   mg2, mg1, mg0
 STATUS  #NODES  NAMES
 new         3   mg2, mg1, mg0
 STATUS  #NODES  NAMES
 new         3   mg2, mg1, mg0
 STATUS  #NODES  NAMES
 active      3   mg2, mg1, mg0

```

然后，我们将 node1 设置为活动的管理主机，我们的 Swarm 将准备好形成。通过运行 active 命令可以设置活动主机，如下所示：

```
 $ belt active mg0
 swarm2k/mg0

```

在这一点上，我们已经形成了一个 Swarm。我们将 mg0 初始化为管理者领导者，如下所示：

```
 $ belt docker swarm init --advertise-addr 128.*.*.220
 Swarm initialized: current node (24j7sytbomhshtayt74lf7njo) is now 
    a manager.

```

前面的命令输出了要复制和粘贴以加入其他管理者和工作者的字符串，例如，看一下以下命令：

```
 docker swarm join \
 --token SWMTKN-1-1wwyxnfcgqt...fwzc1in3 \
 128.*.*.220:2377

```

Belt 提供了一个方便的快捷方式来加入节点，使用以下语法，这就是我们用来加入 mg1 和 mg2 到 Swarm 的方法：

```
 $ belt --host mg[1:2] docker swarm join \
 --token --token SWMTKN-1-1wwyxnfcgqt...fwzc1in3 \
 128.*.*.220:2377

```

现在，我们已经配置好了 mg0、mg1 和 mg2 管理者，并准备好获取工作者的 Swarm。

# 使用 Docker Machine 保护管理者

Docker Machine 对于大规模的 Docker Engine 部署不会很好，但事实证明它非常适用于自动保护少量节点。在接下来的部分中，我们将使用 Docker Machine 使用通用驱动程序来保护我们的 Swarm 管理器，这是一种允许我们控制现有主机的驱动程序。

在我们的情况下，我们已经在 mg0 上设置了一个 Docker Swarm 管理器。此外，我们希望通过为其远程端点启用 TLS 连接来保护 Docker Engine。

Docker Machine 如何为我们工作？首先，Docker Machine 通过 SSH 连接到主机；检测 mg0 的操作系统，在我们的情况下是 Ubuntu；以及 provisioner，在我们的情况下是 systemd。

之后，它安装了 Docker Engine；但是，如果已经有一个存在，就像这里一样，它会跳过这一步。

然后，作为最重要的部分，它生成了一个根 CA 证书，以及所有证书，并将它们存储在主机上。它还自动配置 Docker 使用这些证书。最后，它重新启动 Docker。

如果一切顺利，Docker Engine 将再次启动，并启用 TLS。

然后，我们使用 Docker Machine 在 mg0、mg1 和 mg2 上生成了 Engine 的根 CA，并配置了 TLS 连接。然后，我们稍后使用 Docker 客户端进一步控制 Swarm，而无需使用较慢的 SSH。

```
 $ docker-machine create \
 --driver generic \
 --generic-ip-address=$(belt ip mg0) mg0
 Running pre-create checks...
 Creating machine...
 (mg0) No SSH key specified. Assuming an existing key at the default 
    location.
 Waiting for machine to be running, this may take a few minutes...
 Detecting operating system of created instance...
 Waiting for SSH to be available...
 Detecting the provisioner...
 Provisioning with ubuntu(systemd)...
 Installing Docker...
 Copying certs to the local machine directory...
 Copying certs to the remote machine...
 Setting Docker configuration on the remote daemon...
 Checking connection to Docker...
 Then we can test our working swarm with `docker info`. We grep only 
    15 lines for the brevity.
 $ docker $(docker-machine config mg0) info | grep -A 15 Swarm
 Swarm: active
 NodeID: 24j7sytbomhshtayt74lf7njo
 Is Manager: true
 ClusterID: 8rshkwfq4hsil2tdb3idpqdeg
 Managers: 3
 Nodes: 3
 Orchestration:
 Task History Retention Limit: 5
 Raft:
 Snapshot Interval: 10000
 Heartbeat Tick: 1
 Election Tick: 3
 Dispatcher:
 Heartbeat Period: 5 seconds
 CA Configuration:
 Expiry Duration: 3 months

```

此外，`docker node ls`将在这个设置中正常工作。我们现在验证了 3 个管理者组成了初始的 Swarm，并且能够接受一堆工作节点：

```
 $ docker $(docker-machine config mg0) node ls
 ID                       HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
 24j7sytbomhshtayt74lf7njo *  mg0       Ready   Active        Leader
 2a4jcvp32aoa6olaxlelthkws    mg1       Ready   Active        Reachable
 94po1ln0j0g5fgjnjfvm1w02r    mg2       Ready   Active        Reachable

```

### 提示

**这个集群有多安全？**

我们将使用 Docker 客户端连接到配备 TLS 的 Docker Engine；此外，swarm 节点之间还有另一个 TLS 连接，CA 在三个月后到期，将自动轮换。高级安全设置将在第九章中讨论，*保护 Swarm 集群和 Docker 软件供应链*。

# 理解一些 Swarm 内部机制

此时，我们通过创建一个带有 3 个副本的 nginx 服务来检查 Swarm 是否可操作：

```
 $ eval $(docker-machine env mg0)
 $ docker service create --name nginx --replicas 3 nginx
 du2luca34cmy

```

之后，我们找到了运行 Nginx 的 net 命名空间 ID。我们通过 SSH 连接到 mg0。Swarm 的路由网格的网络命名空间是具有与特殊网络命名空间`1-5t4znibozx`相同时间戳的命名空间。在这个例子中，我们要找的命名空间是`fe3714ca42d0`。

```
 root@mg0:~# ls /var/run/docker/netns -al
 total 0
 drwxr-xr-x 2 root root 120 Aug 22 15:38 .
 drwx------ 5 root root 100 Aug 22 13:39 ..
 -r--r--r-- 1 root root   0 Aug 22 15:17 1-5t4znibozx
 -r--r--r-- 1 root root   0 Aug 22 15:36 d9ef48834a31
 -r--r--r-- 1 root root   0 Aug 22 15:17 fe3714ca42d0

```

我们可以使用 ipvsadm 找出我们的 IPVS 条目，并使用 nsenter 工具（[`github.com/jpetazzo/nsenter`](https://github.com/jpetazzo/nsenter)）在 net 命名空间内运行它，如下所示：

```
 root@node1:~# nsenter --net=/var/run/docker/netns/fe3714ca42d0 ipvsadm -L
 IP Virtual Server version 1.2.1 (size=4096)
 Prot LocalAddress:Port Scheduler Flags
 -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
 FWM  259 rr
 -> 10.255.0.8:0                 Masq    1      0          2

```

在这里，我们可以注意到有一个活动的轮询 IPVS 条目。IPVS 是内核级负载均衡器，与 iptables 一起用于 Swarm 来平衡流量，iptables 用于转发和过滤数据包。

清理 nginx 测试服务（`docker service rm nginx`）后，我们将设置管理者为 Drain 模式，以避免它们接受任务：

```
 $ docker node update --availability drain mg0
 $ docker node update --availability drain mg1
 $ docker node update --availability drain mg2

```

现在，我们准备在 Twitter 和 Github 上宣布我们的管理者的可用性，并开始实验！

## 加入工作节点

我们的贡献者开始将他们的节点作为工作节点加入到管理者**mg0**。任何人都可以使用自己喜欢的方法，包括以下方法：

+   循环`docker-machine ssh sudo docker swarm join`命令

+   Ansible

+   自定义脚本和程序

我们将在第五章中涵盖其中一些方法，*管理 Swarm 集群*。

过了一段时间，我们达到了 2,300 个工作节点的配额，并使用了 100,000 个副本因子启动了一个**alpine**服务：

![加入工人](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_006.jpg)

## 升级管理器

过了一段时间，我们达到了管理器的最大容量，并且不得不增加它们的物理资源。在生产中，实时升级和维护管理器可能是一项预期的操作。以下是我们执行此操作的方法。

### 实时升级管理器

使用奇数作为法定人数，安全地将管理器降级进行维护。

```
 $ docker node ls
 ID                  HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
 4viybni..h24zxde    mg1       Ready   Active        Reachable
 6xxwumb..j6zvtyg *  mg0       Ready   Active        Leader
 f1vs2e3..abdehnh    mg2       Ready   Active

```

在这里，我们将 mg1 作为可达的管理器，并使用以下语法将其降级为工作节点：

```
 $ docker node demote mg1
 Manager mg1 demoted in the swarm.

```

我们可以看到当 mg1 成为工作节点时，`mg1`的`Reachable`状态从节点列表输出中消失。

```
 $ docker node ls
 ID                  HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
 4viybni..h24zxde    mg1       Ready   Active
 6xxwumb..j6zvtyg *  mg0       Ready   Active        Leader
 f1vs2e3..abdehnh    mg2       Ready   Active

```

当节点不再是管理器时，可以安全地关闭它，例如，使用 DigitalOcean CLI，就像我们做的那样：

```
 $ doctl compute droplet-action shutdown 23362382

```

列出节点时，我们注意到 mg1 已经宕机了。

```
 $ docker node ls
 ID                   HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
 4viybni0ud2gjpay6ih24zxde    mg1       Down    Active
 6xxwumbdac34bbgh6hj6zvtyg *  mg0       Ready   Active        Leader
 f1vs2e3hjiqjaukmjqabdehnh    mg2       Ready   Active

```

我们将其资源升级为 16G 内存，然后再次启动该机器：

```
 $ doctl -c .doctlcfg compute droplet-action power-on 23362382

```

在列出这个时间时，我们可以预期一些延迟，因为 mg1 正在重新加入集群。

```
 $ docker node ls
 ID                  HOSTNAME  STATUS  AVAILABILITY  MANAGER STATUS
 4viybni..h24zxde    mg1       Ready   Active
 6xxwumb..j6zvtyg *  mg0       Ready   Active        Leader
 f1vs2e3..abdehnh    mg2       Ready   Active

```

最后，我们可以将其重新提升为管理器，如下所示：

```
 $ docker node promote mg1
 Node mg1 promoted to a manager in the swarm.

```

一旦完成这个操作，集群就正常运行了。所以，我们对 mg0 和 mg2 重复了这个操作。

# 监控 Swarm2k

对于生产级集群，通常希望设置某种监控。到目前为止，还没有一种特定的方法来监视 Swarm 模式中的 Docker 服务和任务。我们在 Swarm2k 中使用了 Telegraf、InfluxDB 和 Grafana 来实现这一点。

## InfluxDB 时间序列数据库

InfluxDB 是一个易于安装的时间序列数据库，因为它没有依赖关系。InfluxDB 对于存储指标、事件信息以及以后用于分析非常有用。对于 Swarm2k，我们使用 InfluxDB 来存储集群、节点、事件以及使用 Telegraf 进行任务的信息。

Telegraf 是可插拔的，并且具有一定数量的输入插件，用于观察系统环境。

### Telegraf Swarm 插件

我们为 Telegraf 开发了一个新的插件，可以将统计数据存储到 InfluxDB 中。该插件可以在[`github.com/chanwit/telegraf`](http://github.com/chanwit/telegraf)找到。数据可能包含*值*、*标签*和*时间戳*。值将根据时间戳进行计算或聚合。此外，标签将允许您根据时间戳将这些值分组在一起。

Telegraf Swarm 插件收集数据并创建以下系列，其中包含我们认为对 Swarmk2 最有趣的值、标签和时间戳到 InfluxDB 中：

+   系列`swarm_node`：该系列包含`cpu_shares`和`memory`作为值，并允许按`node_id`和`node_hostname`标签进行分组。

+   系列`swarm`：该系列包含`n_nodes`表示节点数量，`n_services`表示服务数量，`n_tasks`表示任务数量。该系列不包含标签。

+   系列`swarm_task_status`：该系列包含按状态分组的任务数量。该系列的标签是任务状态名称，例如 Started、Running 和 Failed。

要启用 Telegraf Swarm 插件，我们需要通过添加以下配置来调整`telegraf.conf`：

```
 # Read metrics about swarm tasks and services
 [[inputs.swarm]]
   # Docker Endpoint
   #   To use TCP, set endpoint = "tcp://[ip]:[port]"
 #   To use environment variables (ie, docker-machine), set endpoint =
 "ENV"
   endpoint = "unix:///var/run/docker.sock"
   timeout = “10s”

```

首先，按以下方式设置 InfluxDB 实例：

```
 $ docker run -d \
 -p 8083:8083 \
 -p 8086:8086 \
 --expose 8090 \
 --expose 8099 \
 -e PRE_CREATE_DB=telegraf \
 --name influxsrv
 tutum/influxdb

```

然后，按以下方式设置 Grafana：

```
 docker run -d \
 -p 80:3000 \
 -e HTTP_USER=admin \
 -e HTTP_PASS=admin \
 -e INFLUXDB_HOST=$(belt ip influxdb) \
 -e INFLUXDB_PORT=8086 \
 -e INFLUXDB_NAME=telegraf \
 -e INFLUXDB_USER=root \
 -e INFLUXDB_PASS=root \
 --name grafana \
 grafana/grafana

```

在设置 Grafana 实例后，我们可以从以下 JSON 配置创建仪表板：

[`objects-us-west-1.dream.io/swarm2k/swarm2k_final_grafana_dashboard.json`](https://objects-us-west-1.dream.io/swarm2k/swarm2k_final_grafana_dashboard.json)

要将仪表板连接到 InfluxDB，我们将不得不定义默认数据源并将其指向 InfluxDB 主机端口`8086`。以下是定义数据源的 JSON 配置。将`$INFLUX_DB_IP`替换为您的 InfluxDB 实例。

```
 {
 "name":"telegraf",
 "type":"influxdb",
 "access":"proxy",
 "url":"http://$INFLUX_DB_IP:8086",
 "user":"root",
 "password":"root",
 "database":"telegraf",
 "basicAuth":true,
 "basicAuthUser":"admin",
 "basicAuthPassword":"admin",
 "withCredentials":false,
 "isDefault":true
 }

```

将所有内容链接在一起后，我们将看到一个像这样的仪表板：

![Telegraf Swarm 插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_007.jpg)

# Swarm3k

Swarm3k 是第二个协作项目，试图使用 Swarm 模式形成一个非常大的 Docker 集群。它于 2016 年 10 月 28 日启动，有 50 多个个人和公司加入了这个项目。

Sematext 是最早提供帮助的公司之一，他们提供了他们的 Docker 监控和日志解决方案。他们成为了 Swarm3k 的官方监控系统。Stefan、Otis 和他们的团队从一开始就为我们提供了很好的支持。

![Swarm3k](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_008.jpg)

*Sematext 仪表板*

Sematext 是唯一一家允许我们将监控代理部署为全局 Docker 服务的 Docker 监控公司。这种部署模型大大简化了监控过程。

## Swarm3k 设置和工作负载

我们的目标是 3000 个节点，但最终，我们成功地形成了一个工作的、地理分布的 4700 个节点的 Docker Swarm 集群。

经理们的规格要求是在同一数据中心中使用高内存 128GB 的 DigitalOcean 节点，每个节点有 16 个 vCores。

集群初始化配置包括一个未记录的"KeepOldSnapshots"，告诉 Swarm 模式不要删除，而是保留所有数据快照以供以后分析。每个经理的 Docker 守护程序都以 DEBUG 模式启动，以便在移动过程中获得更多信息。

我们使用 belt 来设置经理，就像我们在前一节中展示的那样，并等待贡献者加入他们的工作节点。

经理们使用的是 Docker 1.12.3，而工作节点则是 1.12.2 和 1.12.3 的混合。我们在*ingress*和*overlay*网络上组织了服务。

我们计划了以下两个工作负载：

+   MySQL 与 Wordpress 集群

+   C1M（Container-1-Million）

打算使用 25 个节点形成一个 MySQL 集群。首先，我们创建了一个 overlay 网络`mydb`：

```
 $ docker network create -d overlay mydb

```

然后，我们准备了以下`entrypoint.sh`脚本：

```
 #!/bin/bash
 ETCD_SUBNET=${ETCD_SUBNET:-10.0.0.0}
 ETCD_HOST=$(ip route get $ETCD_SUBNET | awk 'NR==1 {print $NF}')
 /usr/local/bin/etcd \
 -name etcd0 \
 -advertise-client-urls 
       http://${ETCD_HOST}:2379,http://${ETCD_HOST}:4001 \
 -listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001 \
 -initial-advertise-peer-urls http://${ETCD_HOST}:2380 \
 -listen-peer-urls http://0.0.0.0:2380 \
 -initial-cluster-token etcd-cluster-1 \
 -initial-cluster etcd0=http://${ETCD_HOST}:2380 \
 -initial-cluster-state new

```

然后，我们将为我们特殊版本的 Etcd 准备一个新的 Dockerfile，如下所示：

```
 FROM quay.io/coreos/etcd
 COPY entrypoint.sh /usr/local/bin/entrypoint.sh
 RUN  chmod +x /usr/local/bin/entrypoint.sh
 ENTRYPOINT ['/usr/local/bin/entrypoint.sh']

```

在开始使用之前，不要忘记使用`$ docker build -t chanwit/etcd.`来构建它。

第三，我们启动了一个 Etcd 节点作为 MySQL 集群的中央发现服务，如下所示：

```
 $ docker service create --name etcd --network mydb chanwit/etcd

```

通过检查 Etcd 的虚拟 IP，我们将得到以下服务 VIP：

```
 $ docker service inspect etcd -f "{{ .Endpoint.VirtualIPs }}"
 [{... 10.0.0.2/24}]

```

有了这些信息，我们创建了我们的`mysql`服务，可以在任何程度上进行扩展。看看以下示例：

```
 docker service create \
 --name mysql \
 -p 3306:3306 \
 --network mydb \
 --env MYSQL_ROOT_PASSWORD=mypassword \
 --env DISCOVERY_SERVICE=10.0.0.2:2379 \
 --env XTRABACKUP_PASSWORD=mypassword \
 --env CLUSTER_NAME=galera \
 --mount "type=bind,src=/var/lib/mysql,dst=/var/lib/mysql" \
 perconalab/percona-xtradb-cluster:5.6

```

由于 Libnetwork 的一个 bug，我们在 mynet 和 ingress 网络中遇到了一些 IP 地址问题；请查看[`github.com/docker/docker/issues/24637`](https://github.com/docker/docker/issues/24637)获取更多信息。我们通过将集群绑定到一个*单一*overlay 网络`mydb`来解决了这个 bug。

现在，我们尝试使用复制因子 1 创建一个 WordPress 容器的`docker service create`。我们故意没有控制 WordPress 容器的调度位置。然而，当我们试图将这个 WordPress 服务与 MySQL 服务连接时，连接一直超时。我们得出结论，对于这种规模的 WordPress + MySQL 组合，最好在集群上加一些约束，使所有服务在同一数据中心中运行。

## 规模上的 Swarm 性能

从这个问题中我们还学到，覆盖网络的性能在很大程度上取决于每个主机上网络配置的正确调整。正如一位 Docker 工程师建议的那样，当有太多的 ARP 请求（当网络非常大时）并且每个主机无法回复时，我们可能会遇到“邻居表溢出”错误。这些是我们在 Docker 主机上增加的可调整项，以修复以下行为：

```
 net.ipv4.neigh.default.gc_thresh1 = 30000 
    net.ipv4.neigh.default.gc_thresh2 = 32000    
    net.ipv4.neigh.default.gc_thresh3 = 32768

```

在这里，`gc_thresh1`是预期的主机数量，`gc_thresh2`是软限制，`gc_thresh3`是硬限制。

因此，当 MySQL + Wordpress 测试失败时，我们改变了计划，尝试在路由网格上实验 NGINX。

入口网络设置为/16 池，因此最多可以容纳 64,000 个 IP 地址。根据 Alex Ellis 的建议，我们在集群上启动了 4,000（四千个！）个 NGINX 容器。在这个测试过程中，节点仍在不断进出。几分钟后，NGINX 服务开始运行，路由网格形成。即使一些节点不断失败，它仍然能够正确提供服务，因此这个测试验证了 1.12.3 版本中的路由网格是非常稳定且可以投入生产使用的。然后我们停止了 NGINX 服务，并开始测试尽可能多地调度容器，目标是 1,000,000 个，一百万个。

因此，我们创建了一个“alpine top”服务，就像我们为 Swarm2k 所做的那样。然而，这次调度速率稍慢。大约 30 分钟内我们达到了 47,000 个容器。因此，我们预计填满集群需要大约 10.6 小时来达到我们的 1,000,000 个容器。

由于预计会花费太多时间，我们决定再次改变计划，转而选择 70,000 个容器。

![规模下的 Swarm 性能](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_009.jpg)

调度大量的容器（**docker scale alpine=70000**）使集群压力山大。这创建了一个巨大的调度队列，直到所有 70,000 个容器完成调度才会提交。因此，当我们决定关闭管理节点时，所有调度任务都消失了，集群变得不稳定，因为 Raft 日志已损坏。

在这个过程中，我们想通过收集 CPU 配置文件信息来检查 Swarm 原语加载集群的情况。

![规模下的 Swarm 性能](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_010.jpg)

在这里，我们可以看到只有 0.42%的 CPU 用于调度算法。我们得出一些近似值的结论，即 Docker Swarm 1.12 版本的调度算法非常快。这意味着有机会引入一个更复杂的调度算法，在未来的 Swarm 版本中可能会导致更好的资源利用，只需增加一些可接受的开销。

![规模下的 Swarm 性能](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_011.jpg)

此外，我们发现大量的 CPU 周期被用于节点通信。在这里，我们可以看到 Libnetwork 成员列表层。它使用了整体 CPU 的约 12%。

![规模下的 Swarm 性能](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ntv-dkr-cls-swm/img/image_04_012.jpg)

然而，似乎主要的 CPU 消耗者是 Raft，在这里还显著调用了 Go 垃圾收集器。这使用了整体 CPU 的约 30%。

# Swarm2k 和 Swarm3k 的经验教训

以下是从这些实验中学到的总结：

+   对于大量的工作节点，管理者需要大量的 CPU。每当 Raft 恢复过程启动时，CPU 就会飙升。

+   如果领先的管理者死了，最好停止该节点上的 Docker，并等待集群再次稳定下来，直到剩下 n-1 个管理者。

+   尽量保持快照保留尽可能小。默认的 Docker Swarm 配置就可以了。持久化 Raft 快照会额外使用 CPU。

+   成千上万的节点需要大量的资源来管理，无论是在 CPU 还是网络带宽方面。尽量保持服务和管理者的拓扑地理上紧凑。

+   数十万个任务需要高内存节点。

+   现在，稳定的生产设置建议最多 500-1000 个节点。

+   如果管理者似乎被卡住了，等一等；他们最终会恢复过来。

+   `advertise-addr`参数对于路由网格的工作是必需的。

+   将计算节点尽可能靠近数据节点。覆盖网络很好，但需要调整所有主机的 Linux 网络配置，以使其发挥最佳作用。

+   Docker Swarm 模式很强大。即使在将这个庞大的集群连接在一起的不可预测的网络情况下，也没有任务失败。

对于 Swarm3k，我们要感谢所有的英雄：来自 PetalMD 的`@FlorianHeigl`、`@jmaitrehenry`；来自 Rackspace 的`@everett_toews`、来自 Demonware 的`@squeaky_pl`、`@neverlock`、`@tomwillfixit`；来自 Jabil 的`@sujaypillai`；来自 OVH 的`@pilgrimstack`；来自 Collabnix 的`@ajeetsraina`；来自 Aiyara Cluster 的`@AorJoa`和`@PNgoenthai`；来自 HotelQuickly 的`@GroupSprint3r`、`@toughIQ`、`@mrnonaki`、`@zinuzoid`；`@_EthanHunt_`；来自 Packet.io 的`@packethost`；来自 The Conference 的`@ContainerizeT-ContainerizeThis`；来自 FirePress 的`@_pascalandy`；来自 TRAXxs 的@lucjuggery；@alexellisuk；来自 Huli 的@svega；@BretFisher；来自 Emerging Technology Advisors 的`@voodootikigod`；`@AlexPostID`；来自 ThumpFlow 的`@gianarb`；`@Rucknar`、`@lherrerabenitez`；来自 Nipa Technology 的`@abhisak`；以及来自 NexwayGroup 的`@djalal`。

我们还要再次感谢 Sematext 提供的最佳 Docker 监控系统；以及 DigitalOcean 提供给我们的所有资源。

# 总结

在本章中，我们向您展示了如何使用 belt 在 Digital Ocean 上部署了两个庞大的 Swarm 集群。这些故事给了您很多值得学习的东西。我们总结了这些教训，并概述了一些运行庞大生产集群的技巧。同时，我们还介绍了一些 Swarm 的特性，比如服务和安全性，并讨论了管理者的拓扑结构。在下一章中，我们将详细讨论如何管理 Swarm。包括使用 belt、脚本和 Ansible 部署工作节点，管理节点，监控以及图形界面。
