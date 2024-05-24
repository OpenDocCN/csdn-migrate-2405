# Kubernetes 微服务实用指南（一）

> 原文：[`zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512`](https://zh.annas-archive.org/md5/C0567D22DC0AB8851752A75F6BAC2512)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*使用 Kubernetes 进行微服务实践*是您一直在等待的书籍。它将引导您同时开发微服务并将其部署到 Kubernetes 上。微服务架构与 Kubernetes 之间的协同作用非常强大。本书涵盖了所有方面。它解释了微服务和 Kubernetes 背后的概念，讨论了现实世界中的问题和权衡，带您完成了完整的基于微服务的系统开发，展示了最佳实践，并提供了充分的建议。

本书深入浅出地涵盖了大量内容，并提供了工作代码来说明。您将学习如何设计基于微服务的架构，构建微服务，测试您构建的微服务，并将它们打包为 Docker 镜像。然后，您将学习如何将系统部署为一组 Docker 镜像到 Kubernetes，并在那里进行管理。

在学习的过程中，您将熟悉最重要的趋势，如自动化的持续集成/持续交付（CI/CD），基于 gRPC 的微服务，无服务器计算和服务网格。

通过本书，您将获得大量关于规划、开发和操作基于微服务架构部署在 Kubernetes 上的大规模云原生系统的知识和实践经验。

# 本书适合对象

本书面向希望成为大规模软件工程前沿人员的软件开发人员和 DevOps 工程师。如果您有使用容器部署在多台机器上并由多个团队开发的大规模软件系统的经验，将会有所帮助。

# 本书涵盖内容

第一章，*面向开发人员的 Kubernetes 简介*，向您介绍了 Kubernetes。您将快速了解 Kubernetes，并了解其与微服务的契合程度。

第二章，*微服务入门*，讨论了微服务架构中常见问题的各个方面、模式和方法，以及它们与其他常见架构（如单体架构和大型服务）的比较。

第三章，*Delinkcious – 示例应用*，探讨了为什么我们应该选择 Go 作为 Delinkcious 的编程语言；然后我们将看看 Go kit。

第四章《设置 CI/CD 流水线》教你了解 CI/CD 流水线解决的问题，涵盖了 Kubernetes 的 CI/CD 流水线的不同选项，最后看看如何为 Delinkcious 构建 CI/CD 流水线。

第五章《使用 Kubernetes 配置微服务》将您带入微服务配置的实际和现实世界领域。此外，我们将讨论 Kubernetes 特定的选项，特别是 ConfigMaps。

第六章《在 Kubernetes 上保护微服务》深入探讨了如何在 Kubernetes 上保护您的微服务。我们还将讨论作为 Kubernetes 上微服务安全基础的支柱。

第七章《与世界交流- API 和负载均衡器》让我们向世界开放 Delinkcious，并让用户可以在集群外与其进行交互。此外，我们将添加一个基于 gRPC 的新闻服务，用户可以使用它获取关注的其他用户的新闻。最后，我们将添加一个消息队列，让服务以松散耦合的方式进行通信。

第八章《处理有状态服务》深入研究了 Kubernetes 的存储模型。我们还将扩展 Delinkcious 新闻服务，将其数据存储在 Redis 中，而不是在内存中。

第九章《在 Kubernetes 上运行无服务器任务》深入探讨了云原生系统中最热门的趋势之一：无服务器计算（也称为函数即服务，或 FaaS）。此外，我们将介绍在 Kubernetes 中进行无服务器计算的其他方法。

第十章《测试微服务》涵盖了测试及其各种类型：单元测试、集成测试和各种端到端测试。我们还深入探讨了 Delinkcious 测试的结构。

第十一章《部署微服务》涉及两个相关但分开的主题：生产部署和开发部署。

第十二章《监控、日志和指标》关注在 Kubernetes 上运行大规模分布式系统的操作方面，以及如何设计系统以及需要考虑的因素，以确保卓越的操作姿态。

第十三章，*服务网格-使用 Istio*，审查了服务网格的热门话题，特别是 Istio。这很令人兴奋，因为服务网格是一个真正的游戏改变者。

第十四章，*微服务和 Kubernetes 的未来*，涵盖了 Kubernetes 和微服务的主题，将帮助我们学习如何决定何时是采用和投资新技术的正确时机。

# 充分利用本书

任何软件要求要么列在每章的*技术要求*部分开头，要么，如果安装特定软件是本章材料的一部分，那么您需要的任何说明将包含在章节本身中。大多数安装都是安装到 Kubernetes 集群中的软件组件。这是本书实践性的重要部分。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压软件解压文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含了本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781789805468_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789805468_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“请注意，我确保它通过`chmod +x`是可执行的。”

代码块设置如下：

```
version: 2
jobs:
  build:
    docker:
    - image: circleci/golang:1.11
    - image: circleci/postgres:9.6-alpine
```

任何命令行输入或输出都是按照以下方式编写的：

```
$ tree -L 2
.
├── LICENSE
├── README.md
├── build.sh
```

**粗体**：表示一个新术语、一个重要词或者你在屏幕上看到的词。例如，菜单或对话框中的词会以这种方式出现在文本中。这是一个例子：“我们可以通过从 ACTIONS 下拉菜单中选择同步来同步它。”

警告或重要提示会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：开发人员的 Kubernetes 简介

在本章中，我们将向您介绍 Kubernetes。Kubernetes 是一个庞大的平台，在一个章节中很难充分展现它。幸运的是，我们有一整本书来探索它。如果您感到有些不知所措，请不要担心。我会简要提到许多概念和功能。在后面的章节中，我们将详细介绍其中的许多内容，以及这些 Kubernetes 概念之间的联系和互动。为了增加趣味并尽早动手，您还将在本地机器上创建一个 Kubernetes 集群（Minikube）。本章将涵盖以下主题：

+   Kubernetes 简介

+   Kubernetes 架构

+   Kubernetes 和微服务

+   创建一个本地集群

# 技术要求

在本章中，您将需要以下工具：

+   Docker

+   Kubectl

+   Minikube

# 安装 Docker

要安装 Docker，请按照这里的说明操作：[`docs.docker.com/install/#supported-platforms`](https://docs.docker.com/install/#supported-platforms)。我将在 macOS 上使用 Docker。

# 安装 kubectl

要安装 kubectl，请按照这里的说明操作：[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)。

Kubectl 是 Kubernetes 的 CLI，我们将在整本书中广泛使用它。

# 安装 Minikube

要安装 Minikube，请按照这里的说明操作：[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)。

请注意，您还需要安装一个 hypervisor。对于 macOS，我发现 VirtualBox 是最可靠的。您可能更喜欢另一个 hypervisor，比如 HyperKit。当您开始使用 Minikube 时，将会有更详细的说明。

# 代码

+   本章的代码在这里可用：[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter01`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter01)

+   我们将一起构建的 Delinkcious 示例应用程序还有另一个 Git 存储库：[`github.com/the-gigi/delinkcious`](https://github.com/the-gigi/delinkcious)

# Kubernetes 简介

在这一部分，您将了解 Kubernetes 的全部内容，它的历史以及它是如何变得如此受欢迎的。

# Kubernetes - 容器编排平台

Kubernetes 的主要功能是在一组机器（物理或虚拟）上部署和管理大量基于容器的工作负载。这意味着 Kubernetes 提供了将容器部署到集群的手段。它确保遵守各种调度约束，并将容器有效地打包到集群节点中。此外，Kubernetes 会自动监视您的容器，并在它们失败时重新启动它们。Kubernetes 还会将工作负载从有问题的节点重新定位到其他节点上。Kubernetes 是一个非常灵活的平台。它依赖于计算、内存、存储和网络的基础设施层，并利用这些资源发挥其魔力。

# Kubernetes 的历史

Kubernetes 和整个云原生领域发展迅猛，但让我们花点时间回顾一下我们是如何到达这里的。这将是一个非常简短的旅程，因为 Kubernetes 于 2014 年 6 月从谷歌推出，仅仅几年前。当 Docker 变得流行时，它改变了人们打包、分发和部署软件的方式。但很快就显而易见，Docker 本身无法满足大型分布式系统的规模。一些编排解决方案变得可用，比如 Apache Mesos，后来是 Docker 自己的 swarm。但它们从未达到 Kubernetes 的水平。Kubernetes 在概念上基于谷歌的 Borg 系统。它汇集了谷歌工程十年的设计和技术卓越性，但它是一个新的开源项目。在 2015 年的 OSCON 上，Kubernetes 1.0 发布了，大门敞开了。Kubernetes 及其生态系统的增长以及背后的社区，与其技术卓越性一样令人印象深刻。

Kubernetes 在希腊语中意味着舵手。你会注意到许多与 Kubernetes 相关项目的航海术语。

# Kubernetes 的现状

Kubernetes 现在是家喻户晓的名字。DevOps 世界几乎将容器编排与 Kubernetes 等同起来。所有主要的云服务提供商都提供托管的 Kubernetes 解决方案。它在企业和初创公司中无处不在。虽然 Kubernetes 仍然年轻，创新不断发生，但这一切都是以非常健康的方式进行的。核心非常稳固，经过了严格测试，并在许多公司的生产中使用。有一些非常大的参与者在合作并推动 Kubernetes 的发展，比如谷歌（显然）、微软、亚马逊、IBM 和 VMware。

**Cloud Native Computing Foundation**（**CNCF**）开源组织提供认证。每 3 个月，都会推出一个新的 Kubernetes 版本，这是数百名志愿者和有偿工程师合作的结果。有一个庞大的生态系统围绕着商业和开源项目的主要项目。稍后您将看到，Kubernetes 灵活和可扩展的设计鼓励了这个生态系统，并有助于将 Kubernetes 集成到任何云平台中。

# 了解 Kubernetes 架构

Kubernetes 是软件工程的奇迹。Kubernetes 的架构和设计是其成功的重要组成部分。每个集群都有一个控制平面和数据平面。控制平面由多个组件组成，例如 API 服务器，用于保持集群状态的元数据存储，以及负责管理数据平面中的节点并为用户提供访问权限的多个控制器。生产中的控制平面将分布在多台机器上，以实现高可用性和鲁棒性。数据平面由多个节点或工作节点组成。控制平面将在这些节点上部署和运行您的 pod（容器组），然后监视更改并做出响应。

以下是一个说明整体架构的图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/f4c49543-afdd-4a9f-98df-ec49113430c1.png)

让我们详细审查控制平面和数据平面，以及 kubectl，这是您用来与 Kubernetes 集群交互的命令行工具。

# 控制平面

控制平面由几个组件组成：

+   API 服务器

+   etcd 元数据存储

+   调度程序

+   控制器管理器

+   云控制器管理器

让我们来审查每个组件的作用。

# API 服务器

**kube-api-server**是一个大型的 REST 服务器，向世界公开 Kubernetes API。您可以在控制平面中拥有多个 API 服务器实例，以实现高可用性。API 服务器将集群状态保存在 etcd 中。

# etcd 存储

完整的集群存储在 etcd（[`coreos.com/etcd/`](https://coreos.com/etcd/)）中，这是一个一致且可靠的分布式键值存储。**etcd 存储**是一个开源项目（最初由 CoreOS 开发）。

通常会有三个或五个 etcd 实例以实现冗余。如果您丢失了 etcd 存储中的数据，您将丢失整个集群。

# 调度程序

kube 调度器负责将 pod 调度到工作节点。它实现了一个复杂的调度算法，考虑了很多信息，比如每个节点上的资源可用性，用户指定的各种约束条件，可用节点的类型，资源限制和配额，以及其他因素，比如亲和性，反亲和性，容忍和污点。

# 控制器管理器

kube 控制器管理器是一个包含多个控制器的单个进程，以简化操作。这些控制器监视集群的事件和变化，并做出相应的响应：

+   节点控制器：负责在节点宕机时发现并做出响应。

+   复制控制器：确保每个复制集或复制控制器对象有正确数量的 pod。

+   端点控制器：为每个服务分配一个列出服务 pod 的端点对象。

+   服务账户和令牌控制器：使用默认服务账户和相应的 API 访问令牌初始化新的命名空间。

# 数据平面

数据平面是集群中运行容器化工作负载的节点的集合。数据平面和控制平面可以共享物理或虚拟机。当你运行单节点集群（比如 Minikube）时，当然会发生这种情况。但是，通常在一个生产就绪的部署中，数据平面会有自己的节点。Kubernetes 在每个节点上安装了几个组件，以便通信、监视和调度 pod：kubelet、kube 代理和容器运行时（例如 Docker 守护程序）。

# kubelet

kubelet 是一个 Kubernetes 代理。它负责与 API 服务器通信，并在节点上运行和管理 pod。以下是 kubelet 的一些职责：

+   从 API 服务器下载 pod 的秘密

+   挂载卷

+   通过容器运行时接口（CRI）运行 pod 容器

+   报告节点和每个 pod 的状态

+   探测容器的存活状态

# kube 代理

kube 代理负责节点的网络方面。它作为服务的本地前端运行，并且可以转发 TCP 和 UDP 数据包。它通过 DNS 或环境变量发现服务的 IP 地址。

# 容器运行时

Kubernetes 最终运行容器，即使它们是组织在 pod 中的。Kubernetes 支持不同的容器运行时。最初，只支持 Docker。现在，Kubernetes 通过基于 gRPC 的**CRI**接口运行容器。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/b7e399a7-6d2c-4e1b-b8d3-6393bb8136c0.png)

每个实现 CRI 的容器运行时都可以在由**kubelet**控制的节点上使用，如前图所示。

# Kubectl

**Kubectl**是一个你应该非常熟悉的工具。它是你的 Kubernetes 集群的**命令行接口**（**CLI**）。我们将在整本书中广泛使用 kubectl 来管理和操作 Kubernetes。以下是 kubectl 在您的指尖上提供的功能的简短列表：

+   集群管理

+   部署

+   故障排除和调试

+   资源管理（Kubernetes 对象）

+   配置和元数据

只需键入`kubectl`即可获得所有命令的完整列表，`kubectl <command> --help`以获取有关特定命令的更详细信息。

# Kubernetes 和微服务-完美匹配

Kubernetes 是一个具有惊人能力和美妙生态系统的平台。它如何帮助您的系统？正如您将看到的，Kubernetes 和微服务之间有非常好的对齐。Kubernetes 的构建块，如命名空间、pod、部署和服务，直接映射到重要的微服务概念和敏捷**软件开发生命周期**（**SDLC**）。让我们深入研究。

# 打包和部署微服务

当您使用基于微服务的架构时，您将拥有大量的微服务。这些微服务通常可以独立开发和部署。打包机制只是容器。您开发的每个微服务都将有一个 Dockerfile。生成的镜像代表该微服务的部署单元。在 Kubernetes 中，您的微服务镜像将在一个 pod 中运行（可能与其他容器一起）。但是，运行在节点上的隔离 pod 并不是非常有弹性。如果 pod 的容器崩溃，节点上的 kubelet 将重新启动 pod 的容器，但是如果节点本身发生了什么事情，pod 就消失了。Kubernetes 具有构建在 pod 上的抽象和资源。

**ReplicaSets** 是具有一定数量副本的 pod 集。当你创建一个 ReplicaSet 时，Kubernetes 将确保你指定的正确数量的 pod 始终在集群中运行。部署资源进一步提供了一个与你考虑和思考微服务方式完全一致的抽象。当你准备好一个微服务的新版本时，你会想要部署它。这是一个 Kubernetes 部署清单：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.15.4
        ports:
        - containerPort: 80
```

该文件可以在 [`github.com/the-gigi/hands-on-microservices-with-kubernetes-code/blob/master/ch1/nginx-deployment.yaml.`](https://github.com/the-gigi/hands-on-microservices-with-kubernetes-code/blob/master/ch1/nginx-deployment.yaml) 找到

这是一个 YAML 文件（[`yaml.org/`](https://yaml.org/)），其中包含一些对所有 Kubernetes 资源通用的字段，以及一些特定于部署的字段。让我们一一分解。你在这里学到的几乎所有内容都适用于其他资源：

+   `apiVersion` 字段标记了 Kubernetes 资源的版本。Kubernetes API 服务器的特定版本（例如 V1.13.0）可以与不同资源的不同版本一起工作。资源版本有两个部分：API 组（在本例中为 `apps`）和版本号（`v1`）。版本号可能包括 **alpha** 或 **beta** 标识：

```
apiVersion: apps/v1
```

+   `kind` 字段指定了我们正在处理的资源或 API 对象是什么。在本章和以后，你将遇到许多种类的资源：

```
kind: Deployment
```

+   `metadata` 部分包含了资源的名称（`nginx`）和一组标签，这些标签只是键值对字符串。名称用于指代特定的资源。标签允许对共享相同标签的一组资源进行操作。标签非常有用和灵活。在这种情况下，只有一个标签（`app: nginx`）：

```
metadata:
  name: nginx
  labels:
    app: nginx
```

+   接下来，我们有一个 `spec` 字段。这是一个 ReplicaSet `spec`。你可以直接创建一个 ReplicaSet，但它将是静态的。部署的整个目的是管理其副本集。ReplicaSet `spec` 中包含什么？显然，它包含了 `replicas` 的数量（`3`）。它有一个带有一组 `matchLabels`（也是 `app: nginx`）的选择器，并且有一个 pod 模板。ReplicaSet 将管理具有与 `matchLabels` 匹配的标签的 pod：

```
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
     ...
```

+   让我们看一下 pod 模板。模板有两个部分：`metadata`和`spec`。`metadata`是您指定标签的地方。`spec`描述了 pod 中的`containers`。一个 pod 中可能有一个或多个容器。在这种情况下，只有一个容器。容器的关键字段是镜像（通常是 Docker 镜像），其中打包了您的微服务。这是我们想要运行的代码。还有一个名称（`nginx`）和一组端口：

```
metadata:
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.15.4
    ports:
    - containerPort: 80
```

还有更多可选字段。如果您想深入了解，请查看部署资源的 API 参考[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#deployment-v1-apps`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#deployment-v1-apps)。

# 暴露和发现微服务

我们使用部署部署了我们的微服务。现在，我们需要暴露它，以便其他集群中的服务可以使用它，并且可能还可以使其在集群外可见。Kubernetes 提供了`Service`资源来实现这一目的。Kubernetes 服务由标签标识的 pod 支持：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  ports:
  - port: 80
    protocol: TCP
  selector:
    app: nginx
```

服务在集群内部使用 DNS 或环境变量相互发现。这是默认行为。但是，如果您想使服务对外部可访问，通常会设置一个入口对象或负载均衡器。我们将在以后详细探讨这个主题。

# 保护微服务

Kubernetes 是为运行大规模关键系统而设计的，安全性是至关重要的。微服务通常比单片系统更具挑战性，因为在许多边界上存在大量内部通信。此外，微服务鼓励敏捷开发，这导致系统不断变化。没有稳定的状态可以一次性确保安全。您必须不断调整系统的安全性以适应变化。Kubernetes 预先配备了几个概念和机制，用于安全开发、部署和运行您的微服务。您仍然需要采用最佳实践，例如最小权限原则、深度安全和最小化影响范围。以下是 Kubernetes 的一些安全功能。

# 命名空间

命名空间可以让您将集群的不同部分相互隔离。您可以创建任意数量的命名空间，并将许多资源和操作范围限定在其命名空间内，包括限制和配额。在命名空间中运行的 pod 只能直接访问其自己的命名空间。要访问其他命名空间，它们必须通过公共 API 进行。

# 服务账户

服务账户为您的微服务提供身份。每个服务账户都将具有与其账户关联的特定特权和访问权限。服务账户非常简单：

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: custom-service-account
```

您可以将服务账户与 pod 关联（例如，在部署的 pod `spec`中），并且在 pod 内部运行的微服务将具有该身份以及与该账户关联的所有特权和限制。如果不分配服务账户，则 pod 将获得其命名空间的默认服务账户。每个服务账户都与用于对其进行身份验证的秘密相关联。

# 秘密

Kubernetes 为所有微服务提供了秘密管理功能。秘密可以在 etcd 上（自 Kubernetes 1.7 起）加密存储，并且始终在传输过程中进行加密（通过 HTTPS）。秘密是按命名空间管理的。秘密在 pod 中作为文件（秘密卷）或环境变量挂载。有多种方法可以创建秘密。秘密可以包含两个映射：`data`和`stringData`。数据映射中的值的类型可以是任意的，但必须是 base64 编码的。例如，请参考以下内容：

```
apiVersion: v1
kind: Secret
metadata:
  name: custom-secret
type: Opaque
data:
  username: YWRtaW4=
  password: MWYyZDFlMmU2N2Rm
```

以下是 pod 如何将秘密加载为卷：

```
apiVersion: v1
kind: Pod
metadata:
  name: db
spec:
  containers:
  - name: mypod
    image: postgres
    volumeMounts:
    - name: db_creds
      mountPath: "/etc/db_creds"
      readOnly: true
  volumes:
  - name: foo
    secret:
      secretName: custom-secret
```

最终结果是，由 Kubernetes 在 pod 外部管理的 DB 凭据秘密显示为 pod 内部的常规文件，可通过路径`/etc/db_creds`访问。

# 安全通信

Kubernetes 利用客户端证书来完全验证任何外部通信的双方身份（例如 kubectl）。所有从外部到 Kubernetes API 的通信都应该是通过 HTTP 进行的。API 服务器与节点上的 kubelet 之间的内部集群通信也是通过 HTTPS 进行的（kubelet 端点）。但是，默认情况下不使用客户端证书（您可以启用它）。

API 服务器与节点、pod 和服务之间的通信默认情况下是通过 HTTP 进行的，并且没有经过身份验证。您可以将它们升级为 HTTPS，但请注意客户端证书会被检查，因此不要在公共网络上运行工作节点。

# 网络策略

在分布式系统中，除了保护每个容器、pod 和节点之外，还至关重要的是控制网络上的通信。Kubernetes 支持网络策略，这使您可以完全灵活地定义和塑造整个集群中的流量和访问。

# 对微服务进行身份验证和授权

身份验证和授权也与安全性相关，通过限制对受信任用户和 Kubernetes 的有限方面的访问来实现。组织有多种方法来对其用户进行身份验证。Kubernetes 支持许多常见的身份验证方案，例如 X.509 证书和 HTTP 基本身份验证（不太安全），以及通过 webhook 的外部身份验证服务器，这样可以对身份验证过程进行最终控制。身份验证过程只是将请求的凭据与身份（原始用户或冒充用户）进行匹配。授权过程控制着用户被允许做什么。进入 RBAC。

# 基于角色的访问控制

**基于角色的访问控制**（**RBAC**）并非必需！您可以使用 Kubernetes 中的其他机制执行授权。但这是最佳实践。RBAC 基于两个概念：角色和绑定。角色是对资源的权限集，定义为规则。有两种类型的角色：`Role`，适用于单个命名空间，以及`ClusterRole`，适用于集群中的所有命名空间。

这是默认命名空间中的一个角色，允许获取、监视和列出所有的 pod。每个角色都有三个组成部分：API 组、资源和动词：

```
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
```

集群角色非常相似，只是没有命名空间字段，因为它们适用于所有命名空间。

绑定是将一组主体（用户、用户组或服务帐户）与角色关联起来。有两种类型的绑定，`RoleBinding`和`ClusterRoleBinding`，它们对应于`Role`和`ClusterRole`。

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: pod-reader
  namespace: default
subjects:
- kind: User
  name: gigi # Name is case sensitive
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role # must be Role or ClusterRole
  name: pod-reader # must match the name of the Role or ClusterRole you bind to
  apiGroup: rbac.authorization.k8s.io
```

有趣的是，您可以将`ClusterRole`绑定到单个命名空间中的主体。这对于定义应在多个命名空间中使用的角色非常方便，一次作为集群角色，然后将它们绑定到特定命名空间中的特定主体。

集群角色绑定类似，但必须绑定集群角色，并始终适用于整个集群。

请注意，RBAC 用于授予对 Kubernetes 资源的访问权限。它可以调节对您的服务端点的访问权限，但您可能仍然需要微服务中的细粒度授权。

# 升级微服务

部署和保护微服务只是开始。随着您的系统的发展和演变，您将需要升级您的微服务。关于如何进行这些操作有许多重要的考虑，我们稍后将讨论（版本控制、滚动更新、蓝绿部署和金丝雀发布）。Kubernetes 直接支持许多这些概念，并且在其之上构建的生态系统提供了许多不同的风格和有见解的解决方案。

目标通常是零停机时间和安全回滚，如果出现问题。Kubernetes 部署提供了原语，例如更新部署、暂停部署和回滚部署。具体的工作流程是建立在这些坚实的基础之上的。

升级服务的机制通常涉及将其镜像升级到新版本，有时还需要对其支持资源和访问进行更改：卷、角色、配额、限制等。

# 微服务的扩展

使用 Kubernetes 扩展微服务有两个方面。第一个方面是扩展支持特定微服务的 pod 数量。第二个方面是集群的总容量。您可以通过更新部署的副本数量来显式地扩展微服务，但这需要您不断保持警惕。对于长时间内处理请求量有很大变化的服务（例如，工作时间与非工作时间或工作日与周末），这可能需要大量的工作。Kubernetes 提供了基于 CPU、内存或自定义指标的水平 pod 自动扩展，可以自动地扩展您的服务。

以下是如何扩展我们当前固定为三个副本的`nginx`部署，使其在所有实例的平均 CPU 使用率之间在`2`和`5`之间变化：

```
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
    name: nginx
    namespace: default
spec:
    maxReplicas: 5
    minReplicas: 2
    targetCPUUtilizationPercentage: 90
    scaleTargetRef:
      apiVersion: v1
      kind: Deployment
      name: nginx
```

结果是 Kubernetes 将监视属于`nginx`部署的 pod 的 CPU 利用率。当一段时间内（默认为 5 分钟）的平均 CPU 超过 90%时，它将添加更多副本，直到最多为 5 个，或者直到利用率低于 90%。HPA 也可以缩小规模，但即使 CPU 利用率为零，它也将始终保持至少两个副本。

# 监控微服务

你的微服务部署并在 Kubernetes 上运行。你可以在需要时更新微服务的版本。Kubernetes 会自动处理修复和扩展。然而，你仍然需要监视你的系统并跟踪错误和性能。这对于解决问题很重要，但也对于通知你潜在的改进、优化和成本削减很重要。

有几类相关信息是重要的，你应该监控：

+   第三方日志

+   应用程序日志

+   应用程序错误

+   Kubernetes 事件

+   指标

当考虑由多个微服务和多个支持组件组成的系统时，日志的数量将是可观的。解决方案是中央日志记录，所有日志都会发送到一个地方，你可以随意切割和分析。当然可以记录错误，但通常有用的是报告带有额外元数据的错误，比如堆栈跟踪，并在专用环境中审查它们（例如 sentry 或 rollbar）。指标对于检测性能和系统健康问题或随时间变化的趋势是有用的。

Kubernetes 提供了几种机制和抽象来监视你的微服务。该生态系统还提供了许多有用的项目。

# 日志记录

有几种实现与 Kubernetes 的中央日志记录的方法：

+   在每个节点上运行一个日志代理

+   向每个应用程序 pod 注入一个日志边车容器

+   让你的应用程序直接发送日志到中央日志服务

每种方法都有其利弊。但是，主要的是 Kubernetes 支持所有方法，并使容器和 pod 日志可供使用。

参考[`kubernetes.io/docs/concepts/cluster-administration/logging/#cluster-level-logging-architectures`](https://kubernetes.io/docs/concepts/cluster-administration/logging/#cluster-level-logging-architectures)进行深入讨论。

# 指标

Kubernetes 附带了 cAdvisor（[`github.com/google/cadvisor`](https://github.com/google/cadvisor)），这是一个用于收集容器指标的工具，集成到 kubelet 二进制文件中。Kubernetes 以前提供了一个名为**heapster**的度量服务器，需要额外的后端和 UI。但是，如今，最佳的度量服务器是开源项目 Prometheus。如果你在 Google 的 GKE 上运行 Kubernetes，那么 Google Cloud Monitoring 是一个不需要在你的集群中安装额外组件的好选择。其他云提供商也与他们的监控解决方案集成（例如，EKS 上的 CloudWatch）。

# 创建本地集群

Kubernetes 作为部署平台的一个优势是，你可以创建一个本地集群，并且只需相对较少的努力，就可以拥有一个非常接近生产环境的真实环境。主要好处是开发人员可以在本地测试他们的微服务，并与集群中的其他服务进行协作。当你的系统由许多微服务组成时，更重要的测试通常是集成测试，甚至是配置和基础设施测试，而不是单元测试。Kubernetes 使这种测试变得更容易，需要更少脆弱的模拟。

在这一部分，你将安装一个本地 Kubernetes 集群和一些额外的项目，然后使用宝贵的 kubectl 命令行工具来探索它。

# 安装 Minikube

Minikube 是一个可以在任何地方安装的单节点 Kubernetes 集群。我在这里使用的是 macOS，但过去我也成功地在 Windows 上使用过。在安装 Minikube 本身之前，你必须安装一个 hypervisor。我更喜欢 HyperKit：

```
$ curl -LO https://storage.googleapis.com/minikube/releases/latest/docker-machine-driver-hyperkit \
 && chmod +x docker-machine-driver-hyperkit \
 && sudo mv docker-machine-driver-hyperkit /usr/local/bin/ \
 && sudo chown root:wheel /usr/local/bin/docker-machine-driver-hyperkit \
 && sudo chmod u+s /usr/local/bin/docker-machine-driver-hyperkit
```

但是，我偶尔会遇到 HyperKit 的问题。如果你无法解决这些问题，我建议使用 VirtualBox 作为 hypervisor。运行以下命令通过 Homebrew 安装 VirtualBox：

```
$ brew cask install virtualbox
```

现在，你可以安装 Minikube 本身。再次使用 Homebrew 是最好的方法：

```
brew cask install minikube
```

如果你不是在 macOS 上，请按照官方说明进行操作：[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)。

在使用 HyperKit 启动 Minikube 之前，你必须关闭任何 VPN。在 Minikube 启动后，你可以重新启动 VPN。

Minikube 支持多个版本的 Kubernetes。目前，默认版本是 1.10.0，但 1.13.0 已经发布并得到支持，所以让我们使用这个版本：

```
$ minikube start --vm-driver=hyperkit --kubernetes-version=v1.13.0
```

如果您使用 VirtualBox 作为您的 hypervisor，您不需要指定`--vm-driver`：

```
$ minikube start --kubernetes-version=v1.13.0
```

您应该看到以下内容：

```
$ minikube start --kubernetes-version=v1.13.0
Starting local Kubernetes v1.13.0 cluster...
Starting VM...
Downloading Minikube ISO
 178.88 MB / 178.88 MB [============================================] 100.00% 0s
Getting VM IP address...
E0111 07:47:46.013804   18969 start.go:211] Error parsing version semver:  Version string empty
Moving files into cluster...
Downloading kubeadm v1.13.0
Downloading kubelet v1.13.0
Finished Downloading kubeadm v1.13.0
Finished Downloading kubelet v1.13.0
Setting up certs...
Connecting to cluster...
Setting up kubeconfig...
Stopping extra container runtimes...
Starting cluster components...
Verifying kubelet health ...
Verifying apiserver health ...Kubectl is now configured to use the cluster.
Loading cached images from config file.

Everything looks great. Please enjoy minikube!
```

如果这是您第一次启动 Minikube 集群，Minikube 将自动下载 Minikube VM（178.88 MB）。

此时，您的 Minikube 集群已准备就绪。

# Minikube 故障排除

如果遇到问题（例如，如果您忘记关闭 VPN），请尝试删除 Minikube 安装并使用详细日志重新启动：

```
$ minikube delete
$ rm -rf ~/.minikube
$ minikube start --vm-driver=hyperkit --kubernetes-version=v1.13.0 --logtostderr --v=3
```

如果您的 Minikube 安装卡住了（可能在等待 SSH），您可能需要重新启动以解除卡住。如果这样做没有帮助，请尝试以下操作：

```
sudo mv /var/db/dhcpd_leases /var/db/dhcpd_leases.old
sudo touch /var/db/dhcpd_leases
```

然后，再次重启。

# 验证您的集群

如果一切正常，您可以检查您的 Minikube 版本：

```
$ minikube version
minikube version: v0.31.0
```

Minikube 还有许多其他有用的命令。只需输入`minikube`即可查看命令和标志列表。

# 玩转您的集群

Minikube 正在运行，所以让我们玩得开心。在本节中，您的 kubectl 将为您提供良好的服务。让我们从检查我们的节点开始：

```
$ kubectl get nodes
NAME       STATUS    ROLES     AGE       VERSION
minikube   Ready     master    4m        v1.13.0
```

您的集群已经有一些正在运行的 pod 和服务。原来 Kubernetes 正在使用自己的服务和 pod。但是，这些 pod 和服务在命名空间中运行。以下是所有的命名空间：

```
$ kubectl get ns
NAME          STATUS    AGE
default       Active    18m
kube-public   Active    18m
kube-system   Active    18m
```

要查看所有命名空间中的所有服务，可以使用`--all-namespaces`标志：

```
$ kubectl get svc --all-namespaces
NAMESPACE          NAME  TYPE   CLUSTER-IP  EXTERNAL-IP   PORT(S)   AGE
default  kubernetes   ClusterIP   10.96.0.1  <none>   443/TCP       19m
kube-system kube-dns  ClusterIP   10.96.0.10 <none>   53/UDP,53/TCP 19m
kube-system kubernetes-dashboard  ClusterIP 10.111.39.46 <none>        80/TCP          18m
```

Kubernetes API 服务器本身作为默认命名空间中的服务运行，然后我们有`kube-dns`和`kubernetes-dashboard`在`kube-system`命名空间中运行。

要探索仪表板，您可以运行专用的 Minikube 命令`minikube dashboard`。您还可以使用`kubectl`，它更通用，可以在任何 Kubernetes 集群上运行：

```
$ kubectl port-forward deployment/kubernetes-dashboard 9090
```

然后，浏览`http://localhost:9090`，您将看到以下仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/48590ed9-0382-4c6e-8f48-180a7b2403e5.png)

# 安装 Helm

Helm 是 Kubernetes 包管理器。它不随 Kubernetes 一起提供，因此您必须安装它。Helm 有两个组件：一个名为`tiller`的服务器端组件，以及一个名为`helm`的 CLI。

首先，让我们使用 Homebrew 在本地安装`helm`：

```
$ brew install kubernetes-helm
```

然后，正确初始化服务器和客户端类型：

```
$ helm init
$HELM_HOME has been configured at /Users/gigi.sayfan/.helm.

Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.

Please note: by default, Tiller is deployed with an insecure 'allow unauthenticated users' policy.
To prevent this, run `helm init` with the --tiller-tls-verify flag.
For more information on securing your installation see: https://docs.helm.sh/using_helm/#securing-your-helm-installation
Happy Helming!
```

有了 Helm，您可以轻松在 Kubernetes 集群中安装各种好东西。目前在稳定的图表存储库中有`275`个字符（Helm 术语表示一个包）：

```
$ helm search | wc -l
275
```

例如，查看所有标记为`db`类型的发布：

```
$ helm search db
NAME                               CHART VERSION  APP VERSION    DESCRIPTION
stable/cockroachdb                 2.0.6          2.1.1          CockroachDB is a scalable, survivable, strongly-consisten...
stable/hlf-couchdb                 1.0.5          0.4.9          CouchDB instance for Hyperledger Fabric (these charts are...
stable/influxdb                    1.0.0          1.7            Scalable datastore for metrics, events, and real-time ana...
stable/kubedb                      0.1.3          0.8.0-beta.2   DEPRECATED KubeDB by AppsCode - Making running production...
stable/mariadb                     5.2.3          10.1.37        Fast, reliable, scalable, and easy to use open-source rel...
stable/mongodb                     4.9.1          4.0.3          NoSQL document-oriented database that stores JSON-like do...
stable/mongodb-replicaset          3.8.0          3.6            NoSQL document-oriented database that stores JSON-like do...
stable/percona-xtradb-cluster      0.6.0          5.7.19         free, fully compatible, enhanced, open source drop-in rep...
stable/prometheus-couchdb-exporter 0.1.0          1.0            A Helm chart to export the metrics from couchdb in Promet...
stable/rethinkdb                   0.2.0          0.1.0          The open-source database for the realtime web
jenkins-x/cb-app-slack             0.0.1                         A Slack App for CloudBees Core
stable/kapacitor                   1.1.0          1.5.1          InfluxDB's native data processing engine. It can process ...
stable/lamp                        0.1.5          5.7            Modular and transparent LAMP stack chart supporting PHP-F...
stable/postgresql                  2.7.6          10.6.0         Chart for PostgreSQL, an object-relational database manag...
stable/phpmyadmin                  2.0.0          4.8.3          phpMyAdmin is an mysql administration frontend
stable/unifi                       0.2.1          5.9.29         Ubiquiti Network's Unifi Controller
```

我们将在整本书中大量使用 Helm。

# 摘要

在本章中，您对 Kubernetes 进行了一个快速的介绍，并了解了它与微服务的契合程度。Kubernetes 的可扩展架构赋予了大型企业组织、初创公司和开源组织一个强大的社区，使它们能够合作并围绕 Kubernetes 创建生态系统，从而增加其益处并确保其持久性。Kubernetes 内置的概念和抽象非常适合基于微服务的系统。它们支持软件开发生命周期的每个阶段，从开发、测试、部署，一直到监控和故障排除。Minikube 项目让每个开发人员都可以运行一个本地的 Kubernetes 集群，这对于在类似于生产环境的本地环境中进行 Kubernetes 实验和测试非常有用。Helm 项目是 Kubernetes 的一个很棒的补充，作为事实上的软件包管理解决方案提供了巨大的价值。在下一章中，我们将深入了解微服务的世界，并了解它们为何是开发复杂且快速移动的分布式系统的最佳方法。

# 进一步阅读

+   如果您想了解更多关于 Kubernetes 的信息，我推荐我的书《精通 Kubernetes-第二版》，由 Packt 出版：[`www.packtpub.com/application-development/mastering-kubernetes-second-edition`](https://www.packtpub.com/application-development/mastering-kubernetes-second-edition)


# 第二章：开始使用微服务

在上一章中，您了解了 Kubernetes 的全部内容，以及它如何适合作为开发、部署和管理微服务的平台，甚至还在本地 Kubernetes 集群中玩了一点。在本章中，我们将讨论微服务的一般情况，以及为什么它们是构建复杂系统的最佳方式。我们还将讨论解决基于微服务的系统中常见问题的各种方面、模式和方法，以及它们与其他常见架构（如单体和大型服务）的比较。

我们将在本章中涵盖大量材料：

+   在小规模编程中-少即是多

+   使您的微服务自主

+   使用接口和契约

+   通过 API 公开您的服务

+   使用客户端库

+   管理依赖关系

+   编排微服务

+   利用所有权

+   理解康威定律

+   跨多个服务进行故障排除

+   利用共享服务库

+   选择源代码控制策略

+   创建数据策略

# 技术要求

在本章中，您将看到一些使用 Go 的代码示例。我建议您安装 Go 并尝试自己构建和运行代码示例。

# 在 macOS 上使用 Homebrew 安装 Go

在 macOS 上，我建议使用 Homebrew：

```
$ brew install go
```

接下来，请确保`go`命令可用：

```
$ ls -la `which go`
lrwxr-xr-x  1 gigi.sayfan  admin  26 Nov 17 09:03 /usr/local/bin/go -> ../Cellar/go/1.11.2/bin/go
```

要查看所有选项，只需输入`go`。此外，请确保在您的`.bashrc`文件中定义`GOPATH`并将`$GOPATH/bin`添加到您的路径中。

Go 带有 Go CLI，提供了许多功能，但您可能希望安装其他工具。查看[`awesome-go.com/`](https://awesome-go.com/)。

# 在其他平台上安装 Go

在其他平台上，请按照官方说明操作：[`golang.org/doc/install.`](https://golang.org/doc/install)

# 代码

您可以在此处找到本章的代码：[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/tree/master/Chapter02)。

# 在小规模编程中-少即是多

想想你学习编程的时候。你写了一些接受简单输入、进行一些处理并产生一些输出的小程序。生活很美好。你可以把整个程序都记在脑子里。

您理解了每一行代码。调试和故障排除都很容易。例如，考虑一个用于在摄氏度和华氏度之间转换温度的程序：

```
package main

import (
        "fmt"
        "os"
        "strconv"
)

func celsius2fahrenheit(t float64) float64 {
        return 9.0/5.0*t + 32
}

func fahrenheit2celsius(t float64) float64 {
        return (t - 32) * 5.0 / 9.0
}

func usage() {
      fmt.Println("Usage: temperature_converter <mode> <temperature>")
      fmt.Println()
      fmt.Println("This program converts temperatures between Celsius and Fahrenheit")
      fmt.Println("'mode' is either 'c2f' or 'f2c'")
      fmt.Println("'temperature' is a floating point number to be converted according to mode")
     os.Exit(1)
}

func main() {
         if len(os.Args) != 3 {
                usage()
          }
          mode := os.Args[1]
          if mode != "f2c" && mode != "c2f" {
                  usage()
          }

          t, err := strconv.ParseFloat(os.Args[2], 64)
          if err != nil {
                  usage()
           }

          var converted float64
           if mode == "f2c" {
                  converted = fahrenheit2celsius(t)
           } else {
                   converted = celsius2fahrenheit(t)
           }
           fmt.Println(converted)
}
```

这个程序非常简单。它很好地验证了输入，并在出现问题时显示了使用信息。程序实际执行的计算只有两行代码，用于转换温度，但代码长度为 45 行。甚至没有任何注释。然而，这 45 行代码非常易读且易于测试。没有第三方依赖（只有 Go 标准库）。没有 IO（文件、数据库、网络）。不需要认证或授权。不需要限制调用速率。没有日志记录，没有指标收集。没有版本控制，健康检查或配置。没有在多个环境中部署和没有在生产中进行监控。

现在，考虑将这个简单的程序集成到一个大型企业系统中。您将不得不考虑其中许多方面。系统的其他部分将开始使用温度转换功能。突然之间，最简单的操作可能会产生连锁影响。系统的其他部分的更改可能会影响温度转换器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/22d9b791-c406-4820-9c02-7d5de80d40bf.png)

这种复杂性的增加是自然的。大型企业系统有许多要求。微服务的承诺是通过遵循适当的架构指南和已建立的模式，可以将额外的复杂性整齐地打包并用于许多小型微服务，这些微服务共同完成系统目标。理想情况下，服务开发人员大部分时间都可以不受包围系统的影响。然而，提供适当程度的隔离并且仍然允许在整个系统的上下文中进行测试和调试需要付出很大的努力。

# 使您的微服务自主

对抗复杂性的最佳方法之一是使您的微服务自主。自主服务是一种不依赖于系统中其他服务或第三方服务的服务。自主服务管理自己的状态，并且在很大程度上可以不了解系统的其余部分。

我喜欢将自主微服务看作类似于不可变函数。自主服务永远不会改变系统中其他组件的状态。这种服务的好处是，无论系统的其余部分如何发展，以及它们如何被其他服务使用，它们的复杂性都保持不变。

# 使用接口和契约

接口是软件工程师可以使用的最好工具之一。一旦将某物公开为接口，就可以自由更改其背后的实现。接口是在单个进程中使用的构造。它们对于测试与其他组件的交互非常有用，在基于微服务的系统中这种交互非常丰富。以下是我们示例应用程序的一个接口：

```
type UserManager interface {
   Register(user User) error
   Login(username string, authToken string) (session string, err error)
   Logout(username string, session string) error
}
```

`UserManager`接口定义了一些方法，它们的输入和输出。但是，它没有指定语义。例如，如果对已经登录的用户调用`Login()`方法会发生什么？这是一个错误吗？先前的会话是否终止并创建一个新会话？它是否返回现有会话而不出现错误（幂等方法）？这些问题由合同回答。合同很难完全指定，Go 不提供对合同的任何支持。但是，合同很重要，它们总是存在的，即使只是隐含地存在。

一些语言不支持接口作为语言的第一类语法结构。但是，实现相同效果非常容易。动态类型的语言，如 Python，Ruby 和 JavaScript，允许您传递任何满足调用者使用的属性和方法集的对象。静态语言，如 C 和 C++，通过函数指针集（C）或仅具有纯虚函数的结构（C++）来实现。

# 通过 API 公开您的服务

微服务之间有时会通过网络相互交互，有时还会与外部世界进行交互。服务通过 API 公开其功能。我喜欢将 API 想象为通过网络的接口。编程语言接口使用其所编写的语言的语法（例如，Go 的接口类型）。现代网络 API 也使用一些高级表示。基础是 UDP 和 TCP。但是，微服务通常会通过 Web 传输公开其功能，例如 HTTP（REST，GraphQL，SOAP），HTTP/2（gRPC），或者在某些情况下是 WebSockets。一些服务可能模仿其他的线路协议，例如 memcached，但这在特殊情况下很有用。在 2019 年，没有理由直接在 TCP/UDP 上构建自定义协议或使用专有和特定于语言的协议。像 Java RMI，.NET remoting，DCOM 和 CORBA 这样的方法最好留在过去，除非您需要支持一些遗留代码库。

有两种微服务的类别，如下所示：

+   内部微服务只能被通常在相同网络/集群中运行的其他微服务访问，这些服务可以暴露更专业的 API，因为你可以控制这两个服务及其客户端（其他服务）。

+   外部服务对外开放，并且通常需要从 Web 浏览器或使用多种语言的客户端进行消费。

使用标准网络 API 而不是标准语言无关的传输的好处在于它实现了微服务的多语言承诺。每个服务可以用自己的编程语言实现（例如，一个服务用 Go，另一个用 Python），它们甚至可以在以后完全不同的语言中迁移（比如 Rust），而不会造成中断，因为所有这些服务都通过网络 API 进行交互。我们将在后面讨论多语言方法及其权衡。

# 使用客户端库

接口非常方便。你可以在你的编程语言环境中操作，使用本地数据类型调用方法。使用网络 API 是不同的。你需要根据传输方式使用网络库。你需要序列化你的有效负载和响应，并处理网络错误、断开连接和超时。客户端库模式封装了远程服务和所有这些决策，并为你提供一个标准接口，作为服务的客户端，你只需调用它。客户端库在幕后会处理调用网络 API 所涉及的所有仪式。泄漏抽象的法则（[`www.joelonsoftware.com/2002/11/11/the-law-of-leaky-abstractions/`](https://www.joelonsoftware.com/2002/11/11/the-law-of-leaky-abstractions/)）说你实际上无法隐藏网络。然而，你可以很有效地隐藏它，使消费服务不受影响，并使用关于超时、重试和缓存的策略进行正确配置。

gRPC 最大的卖点之一是它为你生成了一个客户端库。

# 管理依赖关系

现代系统有很多依赖关系。有效地管理它们是**软件开发生命周期**（**SDLC**）的重要组成部分。有两种依赖关系：

+   库/包（链接到运行服务进程）

+   远程服务（可通过网络访问）

这些依赖关系中的每一个都可以是内部的或第三方的。您通过语言的包管理系统来管理库或软件包。Go 很长一段时间没有官方的包管理系统，出现了几种解决方案，例如 Glide 和 Dep。如今（Go 1.12），Go 模块是官方解决方案。

您通过发现端点和跟踪 API 版本来管理远程服务。内部依赖和第三方依赖之间的区别在于变化的速度。内部依赖将更快地发生变化。使用微服务时，您将依赖于其他微服务。版本控制和跟踪 API 背后的合同成为开发中非常重要的方面。

# 协调微服务

当将单体系统与基于微服务的系统进行比较时，有一件事是清楚的。一切都更多。单个微服务更简单，更容易理解，修改和排除单个服务的问题。但是，理解整个系统，跨多个服务进行更改和调试问题更具挑战性。还会在单独的微服务之间通过网络发生更多的交互，而在单体系统中，这些交互将在同一进程中发生。这意味着要从微服务中受益，您需要一种纪律严明的方法，需要应用最佳实践，并且需要有您可以使用的良好工具。

# 统一性与灵活性的权衡

假设您有一百个微服务，但它们都非常小且非常相似。它们都使用相同的数据存储（例如，相同类型的关系数据库）。它们都以相同的方式配置（例如，配置文件）。它们都将错误和日志报告给集中日志服务器。它们都使用相同的编程语言实现（例如，Go）。通常，系统将处理几个用例。每个用例将涉及这一百个微服务的一些子集。还将有一些通用微服务在大多数用例中使用（例如，授权服务）。然后，理解整个系统可能并不那么困难，只要有一些良好的文档。您可以单独查看每个用例，并且当您扩展系统并添加更多用例，并且可能增长到一千个微服务时，复杂性仍然受到限制。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/5ff8b12e-29ea-47cf-827d-3ecab507da8c.png)

一个很好的类比是文件和目录。假设您按流派、艺术家和歌曲组织您的音乐。最初，您有三种流派，20 位艺术家和 200 首歌曲。然后，您扩展了一切，现在有 10 种流派，50 位艺术家和 3,000 首歌曲。组织仍然是相同的旧的流派/艺术家/歌曲的层次结构。当您扩展到一定程度时，规模本身可能会带来新的问题。例如，对于音乐，当您的音乐太多，无法放入硬盘时，您需要一种质量上不同的解决方案（例如，将其保存在云中）。对于微服务也是如此，但分而治之的方法效果很好。如果您达到互联网规模——亚马逊、谷歌、Facebook——那么，是的，您需要更为复杂的解决方案来解决每个方面的问题。

但是，使用统一的微服务，你会牺牲许多好处。例如，团队和开发人员可能被迫使用不适合任务的编程语言，或者他们将不得不遵守严格的日志记录和错误报告的操作标准，即使是针对小型非关键的内部服务。

您需要了解统一与多样化微服务的利弊。这是一个从完全统一的微服务到任何事物都可以的范围，每个微服务都是独特的雪花的光谱。您的责任是在这个光谱上找到系统的最佳位置。

# 利用所有权

由于微服务很小。一个开发人员可以拥有整个微服务并完全了解它。其他开发人员也可能熟悉它，但即使只有一个开发人员熟悉一个服务，新开发人员接手应该也相对简单和无痛，因为范围是如此有限且理想情况下相似。

独占所有权可以非常强大。开发人员需要通过服务 API 与其他开发人员和团队进行沟通，但可以在实现上非常快速地迭代。您可能仍希望团队中的其他开发人员审查内部设计和实现，但即使在极端情况下，所有者完全独立工作且没有监督，潜在的损害也是有限的，因为每个微服务的范围都很小，并且通过明确定义的 API 与系统的其余部分进行交互。

生产力的差异可能令人瞠目结舌。

# 理解康威定律

康威定律的定义如下：

设计系统的组织受限于产生与这些组织的沟通结构相同的设计。

这意味着系统的结构将反映构建它的团队的结构。埃里克·雷蒙德的一个著名变体是：

“如果有四个组建编译器的团队，你将得到一个 4 通道编译器。”

这非常有洞察力，我个人在许多不同的组织中一再见证了这一点。这与基于微服务的系统非常相关。有了许多小的微服务，你不需要为每个微服务专门的团队。会有一些更高级别的微服务组合在一起，以产生系统的某些方面。现在，问题是如何考虑高层结构。有三个主要选项：

+   垂直

+   水平

+   矩阵

在这方面，微服务可能非常重要。作为小型自治组件，它们支持所有结构。但更重要的是，当组织需要从一种方法转变为另一种方法时。通常的轨迹是：水平|垂直|矩阵。

如果软件遵循微服务架构，组织可以以更少的摩擦进行这些转变。这甚至可能成为一个决定性因素。即使不遵循微服务架构的组织决定继续使用不合适的结构，因为打破单体的风险和努力太大。

# 垂直

垂直方法将系统的功能切片，包括多个微服务，并且一个团队完全负责该功能，从设计到实施，再到部署和维护。团队作为孤立体运作，它们之间的沟通通常是有限和正式的。这种方法有利于微服务的一些方面，比如以下内容：

+   多语言

+   灵活性

+   独立移动的部分

+   端到端的所有权

+   垂直切片内部的合同不太正式

+   易于扩展到更多的垂直切片（只需组建另一个团队）

+   跨垂直切片应用变更很困难，特别是随着垂直切片数量的增加。

这种方法在非常大的组织中很常见，因为它具有可扩展性的优势。这也需要大量的创造力和努力来在全面上取得改进。筒仓之间会有工作重复。追求完全重用和协调是徒劳的。垂直方法的诀窍在于找到甜蜜点，将通用功能打包成一种可以被多个筒仓使用的方式，但不需要明确的协调。

# 水平

水平方法将系统视为分层架构。团队结构沿着这些层组织。可能会有一个前端组、后端组和一个 DevOps 组。每个组对他们层面的所有方面负责。垂直功能是通过所有层的不同组之间的协作来实现的。这种方法更适合产品数量较少的较小组织（有时只有一个）。

水平方法的好处在于组织可以在整个水平层面建立专业知识并分享知识。通常，组织从水平组织开始，随着它们的增长，可能扩展到更多的产品，或者可能扩展到多个地理位置，它们会分成更垂直的结构。在每个筒仓内，结构通常是水平的。

# 矩阵

矩阵组织是最复杂的。你有你的垂直筒仓，但组织认识到筒仓之间的重复和变化浪费资源，也使得在筒仓之间转移人员变得具有挑战性，如果它们分散得太多。在矩阵组织中，除了垂直筒仓，还有横切组，他们与所有垂直筒仓合作，并试图带来一定程度的一致性、统一性和秩序。例如，组织可能规定所有垂直筒仓必须将他们的软件部署到 AWS 云上。在这种情况下，可能会有一个云平台组，由垂直筒仓之外管理，并为所有垂直筒仓提供指导、工具和其他共享服务。安全性是另一个很好的例子。许多组织认为安全是必须集中管理的领域，不能任由每个筒仓的心情而定。

# 跨多个服务进行故障排除

由于系统的大多数功能将涉及多个微服务之间的交互，能够跟踪请求从所有这些微服务和各种数据存储中进入是非常重要的。实现这一点的最佳方法之一是分布式跟踪，您可以为每个请求打上标记，并可以从头到尾跟踪它。

调试分布式系统和基于微服务的系统的微妙之处需要很多专业知识。考虑单个请求通过系统的以下方面：

+   处理请求的微服务可能使用不同的编程语言。

+   微服务可以使用不同的传输/协议公开 API。

+   请求可能是异步工作流的一部分，涉及在队列中等待和/或周期性处理。

+   请求的持久状态可能分布在许多由不同微服务控制的独立数据存储中。

当您需要在系统中跨越整个微服务范围调试问题时，每个微服务的自治性变成了一种障碍。您必须构建明确的支持，以便通过聚合来自多个微服务的内部信息来获得系统级别的可见性。

# 利用共享服务库

如果您选择统一的微服务方法，拥有一个所有服务都使用并实现许多横切关注点的共享库（或多个库）非常有用，例如以下内容：

+   配置

+   秘密管理

+   服务发现

+   API 包装

+   日志记录

+   分布式跟踪

这个库可以实现整个工作流程，比如与其他微服务或第三方依赖项交互的身份验证和授权，并为每个微服务进行繁重的工作。这样，微服务只负责正确使用这些库并实现自己的功能。

即使您选择多语言路径并支持多种语言，这种方法也可以工作。您可以为所有支持的语言实现这个库，服务本身可以用不同的语言实现。

然而，共享库的维护和演进以及所有微服务采用它们的速度都会带来成本。一个真正的危险是不同的微服务将使用许多版本的共享库，并且当使用不同版本的共享库的服务进行通信时会导致微妙（或不那么微妙）的问题。

我们将在书中后面探讨的服务网格方法可以为这个问题提供一些答案。

# 选择源代码控制策略

这是一个非常有趣的场景。有两种主要方法：monorepo 和多个 repos。让我们探讨每种方法的利弊。

# Monorepo

在 monorepo 方法中，你的整个代码库都在一个单一的源代码控制存储库中。对整个代码库执行操作非常容易。每当你进行更改时，它立即反映在整个代码库中。版本控制基本上不可行。这对于保持所有代码同步非常有用。但是，如果你确实需要逐步升级系统的某些部分，你需要想出解决方法，比如创建一个带有新更改的单独副本。此外，你的源代码始终保持同步并不意味着你部署的服务都在使用最新版本。如果你总是一次性部署所有服务，你基本上就是在构建一个单体应用。请注意，即使你的更改已经合并，你仍然可能有多个 repo，如果你为第三方开源项目做出贡献（即使你只使用你的更改合并后的上游版本）。

Monorepo 的另一个大问题是，你可能需要大量定制工具来管理你的多个 repo。像谷歌和微软这样的大公司使用多 repo 方法。他们有特殊的需求，定制工具方面并不会阻碍他们。我对于多 repo 方法是否适合较小的组织持保留态度。然而，我会在 Delinkcious（演示应用）中使用 monorepo，这样我们可以一起探索并形成意见。一个主要的缺点是许多现代 CI/CD 工具链使用 GitOps，这会触发源代码控制 repo 中的更改。当只有一个 monorepo 时，你失去了源代码控制 repo 和微服务之间的一对一映射。

# 多个 repos

多 repo 方法恰恰相反。每个项目，通常每个库，都有一个单独的源代码控制存储库。项目之间相互消费，就像第三方库一样。这种方法有几个优点：

+   项目和服务之间清晰的物理边界。

+   源代码控制存储库和服务或项目之间的一对一映射。

+   将服务的部署映射到源代码控制存储库非常容易。

+   统一对待所有依赖项——内部和第三方。

然而，这种方法存在显著的成本，特别是随着服务和项目数量的增长以及它们之间的依赖关系图变得更加复杂时：

+   经常需要在多个存储库中应用变更。

+   通常需要维护存储库的多个版本，因为不同的服务依赖不同的服务。

+   在所有存储库中应用横切变化是困难的。

# 混合

混合方法涉及使用少量存储库。每个存储库包含多个服务和项目。每个存储库与其他存储库隔离，但在每个存储库内，多个服务和项目可以同时开发。这种方法平衡了单存储库和多个存储库的利弊。当存在明确的组织边界和经常存在地理边界时，这可能是有用的。例如，如果一家公司有多个完全独立的产品线，将每个产品线分成自己的单存储库可能是一个好主意。

# 创建数据策略

软件系统最重要的责任之一是管理数据。有许多类型的数据，大多数数据应该在系统故障时幸存，或者您应该能够重建它。数据通常与其他数据有复杂的关系。这在关系数据库中非常明显，但也存在于其他类型的数据中。单体应用通常使用大型数据存储，保存所有相关数据，因此可以对整个数据集执行查询和事务。微服务是不同的。每个微服务都是自治的，负责自己的数据。然而，整个系统需要查询和操作现在存储在许多独立数据存储中并由许多不同服务管理的数据。让我们看看如何使用最佳实践来解决这一挑战。

# 每个微服务一个数据存储

每个微服务一个数据存储是微服务架构的关键元素。一旦两个微服务可以直接访问相同的数据存储，它们就紧密耦合，不再是独立的。有一些重要的细微差别需要理解。多个微服务使用同一个数据库实例可能没问题，但它们不能共享相同的逻辑数据库。

数据库实例是一个资源配置问题。在某些情况下，开发微服务的团队也负责为其提供数据存储。在这种情况下，明智的做法可能是为每个微服务有物理上分开的数据库实例，而不仅仅是逻辑实例。请注意，在使用云数据存储时，微服务开发人员无法控制并且不知道数据存储的物理配置。

我们同意两个微服务不应共享相同的数据存储。但是，如果一个单一的微服务管理两个或更多的数据存储呢？这通常也是不被赞同的。如果您的设计需要两个单独的数据存储，最好为每个专门指定一个微服务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/7138b4e0-3d48-4cae-9be7-551d2f68fc2f.png)

有一个常见的例外情况——您可能希望由同一个微服务管理内存数据存储（缓存）和持久数据存储。工作流程是服务将数据写入持久存储和缓存，并从缓存中提供查询。缓存可以定期刷新，或者基于更改通知，或者在缓存未命中时刷新。

但即使在这种情况下，使用一个单独的集中式缓存，比如由一个单独的微服务管理的 Redis，可能是更好的设计。请记住，在服务众多用户的大型系统中，每个微服务可能有多个实例。

另一个将数据存储的物理配置和配置从微服务本身抽象出来的原因是，这些配置在不同的环境中可能是不同的。您的生产环境可能为每个微服务有物理上分开的数据存储，但在开发环境中，最好只有一个物理数据库实例，有许多小的逻辑数据库。

# 运行分布式查询

我们同意每个微服务应该有自己的数据存储。这意味着系统的整体状态将分布在多个数据存储中，只能从它们自己的微服务中访问。大多数有趣的查询将涉及多个数据存储中可用的数据。每个消费者只需访问所有这些微服务并聚合所有数据以满足其查询。然而，出于几个原因，这是次优的：

+   消费者深刻了解系统如何管理数据。

+   消费者需要访问存储与查询相关数据的每项服务。

+   更改架构可能需要更改许多消费者。

解决这个问题的两种常见解决方案是 CQRS 和 API 组合。它的很酷之处在于，实现这两种解决方案的服务具有相同的 API，因此可以在不影响用户的情况下从一种解决方案切换到另一种解决方案，甚至混合使用。这意味着一些查询将由 CQRS 提供服务，而另一些查询将由 API 组合提供服务，所有这些都由同一个服务实现。总的来说，我建议从 API 组合开始，只有在存在适当条件并且收益是强制性的情况下才过渡到 CQRS，因为它的复杂性要高得多。

# 采用命令查询职责分离

通过**命令查询职责分离**（**CQRS**），来自各种微服务的数据被聚合到一个新的只读数据存储中，该存储被设计用来回答特定的查询。名称的含义是，您将更新数据（命令）的责任与读取数据（查询）的责任分开（分离）。不同的服务负责这些活动。通常通过观察所有数据存储的变化来实现，并需要一个变更通知系统。您也可以使用轮询，但这通常是不可取的。当已知查询经常使用时，这种解决方案会发挥作用。

以下是 CQRS 在实际中的示例。CQRS 服务（负责查询）从三个微服务（负责更新）接收到变更通知，并将它们聚合到自己的数据存储中。

当查询到来时，CQRS 服务通过访问自己的聚合视图来响应，而不会影响微服务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/e8fdf295-52a4-45a9-b42e-5c2a8c766feb.png)

优点如下：

+   查询不会干扰更新主数据存储。

+   聚合器服务公开了一个专门针对特定查询的 API。

+   更改数据在幕后的管理方式更容易，而不会影响消费者。

+   快速响应时间。

缺点如下：

+   它给系统增加了复杂性。

+   它复制了数据。

+   部分视图需要明确处理。

# 采用 API 组合

API 组合方法更加轻量级。表面上看，它看起来就像 CQRS 解决方案。它公开了一个 API，可以跨多个微服务回答众所周知的查询。不同之处在于它不保留自己的数据存储。每当有请求进来时，它将访问包含数据的各个微服务，组合结果并返回。当系统不支持事件通知数据更改时，以及对主要数据存储运行查询的负载是可以接受的时，这种解决方案就会发光。

这里是 API 组合在操作中的示例，其中对 API 组合器服务的查询在幕后被转换为对三个微服务的查询：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/65e81c02-8545-4248-97cf-31ecae54831b.png)

优点如下：

+   轻量级解决方案。

+   聚合器服务公开了一个专门针对特定查询的 API。

+   结果始终是最新的。

+   没有架构要求，比如事件通知。

缺点如下：

+   任何服务的失败都将导致查询失败。这需要关于重试和超时的策略决策。

+   大量查询可能会影响主要数据存储。

# 使用 saga 来管理跨多个服务的事务

当一切正常时，API 组合器和 CQRS 模式为分布式查询提供了足够的解决方案。然而，维护分布式数据完整性是一个复杂的问题。如果您将所有数据存储在单个关系数据库中，并在架构中指定适当的约束条件，那么您可以依赖数据库引擎来处理数据完整性。但是，当多个微服务在隔离的数据存储中维护您的数据时（关系或非关系），情况就大不相同了。数据完整性是必不可少的，但必须由您的代码来维护。saga 模式解决了这个问题。在深入了解 saga 模式之前，让我们先了解一般的数据完整性。

# 了解 ACID

数据完整性的一个常见度量是修改数据的所有事务都具有 ACID 属性：

+   **原子性**：事务中的所有操作都成功，或者全部失败。

+   **一致性**：事务之前和之后，数据的状态符合所有约束。

+   **隔离性**：并发事务的行为就像被串行化一样。

+   **持久性**：当事务成功完成时，结果被持久化。

ACID 属性并不特定于关系数据库，但通常在这个背景下使用，主要是因为关系模式及其形式约束提供了一种方便的一致性度量。隔离性属性通常会对性能产生严重影响，并且在一些更偏向高性能和最终一致性的系统中可能会放宽。

持久性属性是非常明显的。如果你的数据不能安全持久化，那么所有的努力都没有意义。持久性有不同的级别：

+   **持久性到磁盘**：可以在节点重启时存活，但不能在磁盘故障时存活

+   **多个节点上的冗余内存**：可以在节点和磁盘故障时存活，但不能在所有节点暂时故障时存活

+   **冗余磁盘**：可以在磁盘故障时存活

+   **地理分布式副本**：可以在整个数据中心宕机时存活

+   **备份**：存储大量信息更便宜，但恢复速度较慢，通常滞后于实时

原子性要求也是显而易见的。没有人喜欢部分更改，这可能会违反数据完整性并以难以排查的方式破坏系统。

# 理解 CAP 定理

CAP 定理指出，分布式系统不能同时具备以下三个特性：

+   一致性

+   可用性

+   分区弹性

在实践中，你可以选择 CP 系统或 AP 系统。**CP**系统（一致性和分区弹性）始终保持一致，并且在组件之间存在网络分区时不会提供查询或进行更改。它只在系统完全连接时才能运行。这显然意味着你没有可用性。另一方面，**AP**系统（可用性和分区弹性）始终可用，并且可以以分裂脑的方式运行。当系统分裂时，每个部分可能会继续正常运行，但系统将不一致，因为每个部分都不知道另一部分发生的事务。

AP 系统通常被称为最终一致系统，因为当恢复连接时，某些对账过程会确保整个系统再次同步。一个有趣的变体是冻结系统，在网络分区发生时，它们会优雅地退化，并且两个部分都会继续提供查询，但拒绝对系统的所有修改。请注意，在分区的那一刻，没有保证两个部分是一致的，因为一个部分中的一些事务可能仍未复制到另一部分。通常，这已经足够好了，因为分裂部分之间的差异很小，并且不会随着时间的推移而增加，因为新的更改会被拒绝。

# 将 saga 模式应用于微服务

关系数据库可以通过算法（例如两阶段提交和对所有数据的控制）为分布式系统提供 ACID 合规性。两阶段提交算法分为准备和提交两个阶段。然而，参与分布式事务的服务必须共享相同的数据库。这对于管理自己的数据库的微服务来说是行不通的。

进入 saga 模式。saga 模式的基本思想是对所有微服务的操作进行集中管理，并且对于每个操作，如果由于某种原因整个事务无法完成，将执行一个补偿操作。这实现了 ACID 的原子性属性。但是，每个微服务上的更改立即可见，而不仅仅在整个分布式事务结束时才可见。这违反了一致性和隔离性属性。如果您将系统设计为 AP，也就是**最终一致**，这不是问题。但是，这需要您的代码意识到这一点，并且能够处理可能部分不一致或过时的数据。在许多情况下，这是一个可以接受的妥协。

saga 是如何工作的？saga 是一组在微服务上的操作和相应的补偿操作。当一个操作失败时，将按相反的顺序调用其补偿操作以及所有先前操作的补偿操作，以回滚系统的整个状态。

实现 sagas 并不是一件简单的事，因为补偿操作也可能会失败。一般来说，瞬态状态必须是持久的，并标记为这样，必须存储大量的元数据以实现可靠的回滚。一个好的做法是有一个带外进程频繁运行，并清理在实时未能完成所有补偿操作的失败的 sagas。

一个很好的理解 sagas 的方式是将其视为工作流程。工作流程很酷，因为它们可以实现长时间的过程，甚至涉及人类而不仅仅是软件。

# 总结

在本章中，我们涵盖了很多内容。我们讨论了微服务的基本原则——少即是多——以及将系统分解为许多小型和自包含的微服务可以帮助其扩展。我们还讨论了开发人员在利用微服务架构时面临的挑战。我们提供了大量关于构建基于微服务的系统的概念、选项、最佳实践和务实建议。在这一点上，你应该欣赏到微服务提供的灵活性，但也应该对你可以选择利用它们的许多方式有些担忧。

在本书的其余部分，我们将详细探讨这个领域，并一起使用一些最好的可用框架和工具构建一个基于微服务的系统，并将其部署在 Kubernetes 上。在下一章中，你将会遇到 Delinkcious——我们的示例应用程序——它将作为一个动手实验室。你还将一窥 Go-kit，这是一个用于构建 Go 微服务的微服务框架。

# 进一步阅读

如果你对微服务感兴趣，我建议从以下文章开始阅读：[`www.martinfowler.com/`](https://www.martinfowler.com/)


# 第三章：Delinkcious - 示例应用程序

Delinkcious 是 Delicious（[`en.wikipedia.org/wiki/Delicious_(website)`](https://en.wikipedia.org/wiki/Delicious_(website)）的模仿者。Delicious 曾经是一个管理用户链接的互联网热门网站。它被雅虎收购，然后被转手多次。最终被 Pinboard 收购，后者运行类似的服务，并打算很快关闭 Delicious。

Delinkcious 允许用户将 URL 存储在网络上的酷炫位置，对其进行标记，并以各种方式查询它们。在本书中，Delinkcious 将作为一个实时实验室，演示许多微服务和 Kubernetes 概念，以及在真实应用程序环境中的功能。重点将放在后端，因此不会有时髦的前端 Web 应用程序或移动应用程序。我会把它们留给你作为可怕的练习。

在本章中，我们将了解为什么我选择 Go 作为 Delinkcious 的编程语言，然后看看**Go kit** - 一个我将用来构建 Delinkcious 的优秀的 Go 微服务工具包。然后，我们将使用社交图服务作为一个运行示例，剖析 Delinkcious 本身的不同方面。

我们将涵盖以下主题：

+   Delinkcious 微服务

+   Delinkcious 数据存储

+   Delinkcious API

+   Delinkcious 客户端库

# 技术要求

如果您迄今为止已经跟着本书走过，那么您已经安装了 Go。我建议安装一个好的 Go IDE 来跟随本章的代码，因为需要大量的学习。让我们看看几个不错的选择。

# Visual Studio Code

**Visual Studio Code**，也称为**VS Code**（[`code.visualstudio.com/docs/languages/go`](https://code.visualstudio.com/docs/languages/go)），是微软的开源 IDE。它不是专门针对 Go 的，但通过专门和复杂的 Go 扩展，与 Go 有深度集成。它被认为是最好的免费 Go IDE。

# GoLand

JetBrains 的 GoLand（[`www.jetbrains.com/go/`](https://www.jetbrains.com/go/)）是我个人最喜欢的。它遵循了 IntelliJ IDEA、PyCharm 和其他优秀 IDE 的优良传统。这是一个付费版本，有 30 天的免费试用期。不幸的是，没有社区版。如果您有能力，我强烈推荐它。如果您不能或不想为 IDE 付费（完全合理），请查看其他选项。

# LiteIDE

LiteIDE 或 LiteIDE X ([`github.com/visualfc/liteide`](https://github.com/visualfc/liteide))是一个非常有趣的开源项目。它是最早的 Go IDE 之一，早于 GoLand 和 VS Code 的 Go 扩展。我在早期使用过它，并对其质量感到惊讶。最终我放弃了它，因为使用 GNU Project Debugger（GDB）进行交互式调试时遇到了困难。它正在积极开发，有很多贡献者，并支持所有最新和最伟大的 Go 功能，包括 Go 1.1 和 Go 模块。现在您可以使用 Delve 进行调试，这是最好的 Go 调试器。

# 其他选项

如果您是一个死忠的命令行用户，根本不喜欢 IDE，您有可用的选项。大多数编程和文本编辑器都有某种形式的 Go 支持。Go 维基（[`github.com/golang/go/wiki/IDEsAndTextEditorPlugins`](https://github.com/golang/go/wiki/IDEsAndTextEditorPlugins)）有一个大列表的 IDE 和文本编辑器插件，所以去看看吧。

# 代码

在本章中，没有代码文件，因为您只会了解 Delinkcious 应用程序：

+   它托管在自己的 GitHub 存储库中，可以在以下位置找到：[`github.com/the-gigi/delinkcious`](https://github.com/the-gigi/delinkcious)。

+   查看**v0.1**标签 | 发布：[`github.com/the-gigi/delinkcious/releases/tag/v0.1`](https://github.com/the-gigi/delinkcious/releases/tag/v0.1)。

+   克隆它并使用您喜欢的 IDE 或文本编辑器进行跟进。

+   请记住，本书的一般代码示例在另一个 GitHub 存储库中：[`github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Kubernetes/)。

# 选择 Go 用于 Delinkcious

我用许多优秀的语言编写并发布了生产后端代码，如 C/C++、Python、C#，当然还有 Go。我也使用了一些不那么好的语言，但让我们不讨论这些。我决定使用 Go 作为 Delinkcious 的编程语言，因为它是微服务的绝佳语言：

+   Go 编译为单个二进制文件，没有外部依赖（对于简单的 Dockerfile 非常棒）。

+   Go 非常易读和易学。

+   Go 对网络编程和并发有很好的支持。

+   Go 是许多云原生数据存储、队列和框架（包括 Docker 和 Kubernetes）的实现语言。

你可能会说微服务应该是语言无关的，我不应该专注于一种语言。这是真的，但我的目标是在这本书中非常实际，并深入研究在 Kubernetes 上构建微服务的所有细节。为了做到这一点，我不得不做出具体的选择并坚持下去。试图在多种语言中达到相同的深度是徒劳的。也就是说，微服务的边界非常清晰（这是微服务的一个优点），你可以看到在另一种语言中实现微服务将对系统的其余部分造成一些问题。

# 了解 Go kit

您可以从头开始编写您的微服务（使用 Go 或任何其他语言），它们将通过它们的 API 很好地相互交互。然而，在现实世界的系统中，将有大量的共享和/或交叉关注点，您希望它们保持一致：

+   配置

+   秘密管理

+   中央日志记录

+   指标

+   认证

+   授权

+   安全

+   分布式跟踪

+   服务发现

实际上，在大多数大型生产系统中，微服务需要遵守特定的政策。

使用 Go kit（[`gokit.io/`](https://gokit.io/)）。Go kit 对微服务空间采取了非常模块化的方法。它提供了高度的关注点分离，这是构建微服务的推荐方法，以及很大的灵活性。正如网站所说，*少数意见，轻松持有*。

# 使用 Go kit 构建微服务

Go kit 关注的是最佳实践。您的业务逻辑是作为纯 Go 库实现的，它只处理接口和 Go 结构。所有涉及 API、序列化、路由和网络的复杂方面都将被分别放置在明确分离的层中，这些层利用了 Go kit 的概念和基础设施，如传输、端点和服务。这使得开发体验非常好，您可以在最简单的环境中演变和测试应用代码。这是 Delinkcious 服务之一-社交图的接口。请注意，它是纯 Go 的。没有 API、微服务，甚至没有 Go kit 的导入：

```
type SocialGraphManager interface {
   Follow(followed string, follower string) error
   Unfollow(followed string, follower string) error

   GetFollowing(username string) (map[string]bool, error)
   GetFollowers(username string) (map[string]bool, error)
}
```

这个接口的实现位于一个 Go 包中，它完全不知道 Go kit 甚至不知道它被用在微服务中：

```
package social_graph_manager

import (
   "errors"
   om "github.com/the-gigi/delinkcious/pkg/object_model"
)

type SocialGraphManager struct {
   store om.SocialGraphManager
}

func (m *SocialGraphManager) Follow(followed string, follower string) (err error) {
    ...
}

func (m *SocialGraphManager) Unfollow(followed string, follower string) (err error) {
    ...
}

func (m *SocialGraphManager) GetFollowing(username string) (map[string]bool, error) {
    ...
}

func (m *SocialGraphManager) GetFollowers(username string) (map[string]bool, error) {
    ...
}
```

将 Go kit 服务视为一个具有不同层的洋葱是一个很好的思路。核心是您的业务逻辑，上面叠加了各种关注点，如路由、速率限制、日志记录和度量标准，最终通过传输暴露给其他服务或全球：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-msvc-k8s/img/59dd4e46-c710-425f-a3b3-a15375980cc8.png)

Go kit 主要通过使用请求-响应模型支持 RPC 风格的通信。

# 理解传输

微服务最大的问题之一是它们通过网络相互交互和与客户端交互；换句话说，至少比在同一进程内调用方法复杂一个数量级。Go kit 通过传输概念明确支持微服务的网络方面。

Go kit 传输封装了所有复杂性，并与其他 Go kit 构造集成，如请求、响应和端点。Go kit 官方支持以下传输方式：

+   HTTP

+   gRPC

+   Thrift

+   net/rpc

但是，在其 GitHub 存储库中还有几种传输方式，包括用于消息队列和发布/订阅的 AMQP 和 NATS 传输。Go kit 传输的一个很酷的功能是，您可以在不更改代码的情况下通过多种传输方式公开相同的服务。

# 理解端点

Go kit 微服务实际上只是一组端点。每个端点对应于您服务接口中的一个方法。端点始终与至少一个传输和一个处理程序相关联，您实现该处理程序以处理请求。Go kit 端点支持 RPC 通信风格，并具有请求和响应结构。

这是`Follow()`方法端点的工厂函数：

```
func makeFollowEndpoint(svc om.SocialGraphManager) endpoint.Endpoint {
   return func(_ context.Context, request interface{}) (interface{}, error) {
      req := request.(followRequest)
      err := svc.Follow(req.Followed, req.Follower)
      res := followResponse{}
      if err != nil {
         res.Err = err.Error()
      }
      return res, nil
   }
}
```

我将很快解释这里发生了什么。现在，只需注意它接受`om.SocialGraphManager`类型的`svc`参数，这是一个接口，并调用其`Follow()`方法。

# 理解服务

这是您的代码插入系统的地方。当调用端点时，它会调用您的服务实现中的相应方法来完成所有工作。端点包装器会完成请求和响应的编码和解码工作。您可以使用最合理的抽象来专注于应用逻辑。

这是`SocialGraphManager`函数的`Follow()`方法的实现：

```
func (m *SocialGraphManager) Follow(followed string, follower string) (err error) {
   if followed == "" || follower == "" {
      err = errors.New("followed and follower can't be empty")
      return
   }

   return m.store.Follow(followed, follower)
}
```

# 理解中间件

正如前面的洋葱图所示，Go kit 是可组合的。除了必需的传输、端点和服务之外，Go kit 还使用装饰器模式可选择地包装服务和端点，以处理横切关注点，例如以下内容：

+   弹性（例如，带有指数回退的重试）

+   身份验证和授权

+   日志记录

+   度量收集

+   分布式跟踪

+   服务发现

+   速率限制

这种以固定核心为基础的方法，使用少量的抽象，如传输、端点和服务，可以通过统一的中间件机制进行扩展，易于理解和使用。Go kit 在为中间件提供足够的内置功能和留出空间以满足您的需求之间取得了平衡。例如，在 Kubernetes 上运行时，服务发现已经为您处理了。很棒的是，在这种情况下你不必绕过 Go kit。您不绝对需要的功能和能力是可选的。

# 理解客户端

在第二章中，*开始使用微服务*，我们讨论了微服务的客户端库原则。一个微服务与另一个微服务交流时，理想情况下会利用通过接口公开的客户端库。Go kit 为编写这种客户端库提供了出色的支持和指导。使用微服务只需接收一个接口。它实际上对于它正在与另一个服务交流这一事实是完全不可知的。在（几乎）所有意图和目的上，远程服务可能正在同一个进程中运行。这对于测试或重构服务并将稍微过大的服务拆分为两个独立服务非常有用。

Go kit 具有类似于服务端点的客户端端点，但工作方向相反。服务端点解码请求，委托工作给服务，并编码响应。客户端端点编码请求，在网络上调用远程服务，并解码响应。

以下是客户端的`Follow()`方法的样子：

```
func (s EndpointSet) Follow(followed string, follower string) (err error) {
   resp, err := s.FollowEndpoint(context.Background(), FollowRequest{Followed: followed, Follower: follower})
   if err != nil {
      return err
   }
   response := resp.(SimpleResponse)

   if response.Err != "" {
      err = errors.New(response.Err)
   }
   return
}
```

# 生成样板

Go kit 的清晰关注点分离和整洁的架构分层是有代价的。代价是大量乏味、令人昏昏欲睡和容易出错的样板代码，用于在不同结构和方法签名之间转换请求和响应。了解 Go kit 如何以通用方式支持强类型接口是有用的，但对于大型项目，首选解决方案是从 Go 接口和数据类型生成所有样板。有几个项目可以完成这项任务，包括 Go kit 本身正在开发的一个名为**kitgen**的项目（[`github.com/go-kit/kit/tree/master/cmd/kitgen`](https://github.com/go-kit/kit/tree/master/cmd/kitgen)）。

目前它被认为是实验性的。我非常喜欢代码生成，并强烈推荐它。然而，在接下来的章节中，我们将看到大量手动样板代码，以清楚地说明发生了什么，并避免任何魔法。

# 介绍 Delinkcious 目录结构

在初始开发阶段，Delinkcious 系统由三个服务组成：

+   链接服务

+   用户服务

+   社交图服务

高级目录结构包括以下子目录：

+   `cmd`

+   `pkg`

+   `svc`

`root`目录还包括一些常见文件，如`README.md`和重要的`go.mod`和`go.sum`文件，以支持 Go 模块。我在这里使用 monorepo 方法，因此整个 Delinkcious 系统将驻留在这个目录结构中，并被视为单个 Go 模块，尽管有许多包：

```
$ tree -L 1
.
├── LICENSE
├── README.md
├── go.mod
├── go.sum
├── cmd
├── pkg
└── svc
```

# cmd 子目录

`cmd`子目录包含各种工具和命令，以支持开发和运营，以及涉及多个参与者、服务或外部依赖的端到端测试；例如，通过其客户端库测试微服务。

目前，它只包含了社交图服务的单个端到端测试：

```
$ tree cmd
cmd
└── social_graph_service_e2e
 └── social_graph_service_e2e.go
```

# pkg 子目录

`pkg`子目录是所有包的所在地。它包括微服务的实现，客户端库，抽象对象模型，其他支持包和单元测试。大部分代码以 Go 包的形式存在，这些包在实际微服务之前很容易开发和测试：

```
$ tree pkg
pkg
├── link_manager
│   ├── abstract_link_store.go
│   ├── db_link_store.go
│   ├── db_link_store_test.go
│   ├── in_memory_link_store.go
│   ├── link_manager.go
│   └── link_manager_suite_test.go
├── link_manager_client
│   └── client.go
├── object_model
│   ├── README.md
│   ├── interfaces.go
│   └── types.go
├── social_graph_client
│   ├── client.go
│   └── endpoints.go
├── social_graph_manager
│   ├── db_scoial_graph_store.go
│   ├── db_social_graph_manager_test.go
│   ├── in_memory_social_graph_manager_test.go
│   ├── in_memory_social_graph_store.go
│   ├── social_graph_manager.go
│   └── social_graph_manager_suite_test.go
└── user_manager
 ├── db_user_manager_test.go
 ├── db_user_store.go
 ├── in_memory_user_manager.go
 ├── in_memory_user_manager_test.go
 ├── in_memory_user_store.go
 └── user_manager_suite_test.go
```

# svc 子目录

`svc`子目录是 Delinkcious 微服务的所在地。每个微服务都是一个独立的二进制文件，有自己的主包。`delinkcious_service`是一个遵循 API 网关模式的公共服务（[`microservices.io/patterns/apigateway.html`](https://microservices.io/patterns/apigateway.html)）：

```
$ tree svc
svc
├── delinkcious_service
│   └── README.md
├── link_service
│   ├── link_service.go
│   └── transport.go
├── social_graph_service
│   ├── social_graph_service.go
│   └── transport.go
└── user_service
 ├── transport.go
 └── user_service.go
```

# 介绍 Delinkcious 微服务

让我们详细检查 Delinkcious 服务，并逐步分析。我们将从内部开始，从服务层开始，一直到传输层。

有三种不同的服务：

+   链接服务

+   用户服务

+   社交图服务

它们共同合作，提供 Delinkcious 的功能，即为用户管理链接并跟踪他们的社交图（关注/粉丝关系）。

# 对象模型

对象模型是所有接口和相关数据类型的集合，由服务实现。我选择把它们都放在一个包里：`github.com/the-gigi/delinkcious/pkg/object_model`。它包含两个文件：`interfaces.go`和`types.go`。

`interfaces.go`文件包含了三个 Delinkcious 服务的接口：

```
package object_model

type LinkManager interface {
   GetLinks(request GetLinksRequest) (GetLinksResult, error)
   AddLink(request AddLinkRequest) error
   UpdateLink(request UpdateLinkRequest) error
   DeleteLink(username string, url string) error
}

type UserManager interface {
   Register(user User) error
   Login(username string, authToken string) (session string, err error)
   Logout(username string, session string) error
}

type SocialGraphManager interface {
   Follow(followed string, follower string) error
   Unfollow(followed string, follower string) error

   GetFollowing(username string) (map[string]bool, error)
   GetFollowers(username string) (map[string]bool, error)
}

type LinkManagerEvents interface {
   OnLinkAdded(username string, link *Link)
   OnLinkUpdated(username string, link *Link)
   OnLinkDeleted(username string, url string)
}
```

`types.go`文件包含了在各种接口方法的签名中使用的结构体：

```
package object_model

import "time"

type Link struct {
   Url         string
   Title       string
   Description string
   Tags        map[string]bool
   CreatedAt   time.Time
   UpdatedAt   time.Time
}

type GetLinksRequest struct {
   UrlRegex         string
   TitleRegex       string
   DescriptionRegex string
   Username         string
   Tag              string
   StartToken       string
}

type GetLinksResult struct {
   Links         []Link
   NextPageToken string
}

type AddLinkRequest struct {
   Url         string
   Title       string
   Description string
   Username    string
   Tags        map[string]bool
}

type UpdateLinkRequest struct {
   Url         string
   Title       string
   Description string
   Username    string
   AddTags     map[string]bool
   RemoveTags  map[string]bool
}

type User struct {
   Email string
   Name  string
}
```

`object_model`包只是使用基本的 Go 类型、标准库类型（`time.Time`）和用户定义的类型来表示 Delinkcious 领域。这都是纯粹的 Go。在这个层次上，没有网络、API、微服务或 Go kit 的依赖或意识。

# 服务实现

下一层是将服务接口实现为简单的 Go 包。在这一点上，每个服务都有自己的包：

+   `github.com/the-gigi/delinkcious/pkg/link_manager`

+   `github.com/the-gigi/delinkcious/pkg/user_manager`

+   `github.com/the-gigi/delinkcious/pkg/social_graph_manager`

请注意，这些是 Go 包名，而不是 URL。

让我们详细检查`social_graph_manager`包。它将`object_model`包导入为`om`，因为它需要实现`om.SocialGraphManager`接口。它定义了一个名为`SocialGraphManager`的`struct`，其中有一个名为`store`的字段，类型为`om.SocialGraphManager`。因此，在这种情况下，`store`字段的接口与管理器的接口是相同的：

```
package social_graph_manager

import (
   "errors"
   om "github.com/the-gigi/delinkcious/pkg/object_model"
)

type SocialGraphManager struct {
   store om.SocialGraphManager
}
```

这可能有点令人困惑。想法是`store`字段实现相同的接口，以便顶级管理器可以实现一些验证逻辑并将繁重的工作委托给存储。您很快就会看到这一点。

此外，`store`字段是一个接口的事实允许我们使用实现相同接口的不同存储。这非常有用。`NewSocialGraphManager()`函数接受一个`store`字段，该字段不能为`nil`，然后返回一个提供的存储的新的`SocialGraphManager`实例。

```
func NewSocialGraphManager(store om.SocialGraphManager) (om.SocialGraphManager, error) {
   if store == nil {
      return nil, errors.New("store can't be nil")
   }
   return &SocialGraphManager{store: store}, nil
}
```

`SocialGraphManager`结构本身非常简单。它执行一些有效性检查，然后将工作委托给它的`store`：

```
func (m *SocialGraphManager) Follow(followed string, follower string) (err error) {
   if followed == "" || follower == "" {
      err = errors.New("followed and follower can't be empty")
      return
   }

   return m.store.Follow(followed, follower)
}

func (m *SocialGraphManager) Unfollow(followed string, follower string) (err error) {
   if followed == "" || follower == "" {
      err = errors.New("followed and follower can't be empty")
      return
   }

   return m.store.Unfollow(followed, follower)
}

func (m *SocialGraphManager) GetFollowing(username string) (map[string]bool, error) {
   return m.store.GetFollowing(username)
}

func (m *SocialGraphManager) GetFollowers(username string) (map[string]bool, error) {
   return m.store.GetFollowers(username)
}
```

社交图管理器是一个非常简单的库。让我们继续剥离洋葱，看看服务本身，它位于`svc`子目录下：[`github.com/the-gigi/delinkcious/tree/master/svc/social_graph_service`](https://github.com/the-gigi/delinkcious/tree/master/svc/social_graph_service)。

让我们从`social_graph_service.go`文件开始。我们将介绍大多数服务相似的主要部分。该文件位于`service`包中，这是我使用的一个约定。它导入了几个重要的包：

```
package service

import (
   httptransport "github.com/go-kit/kit/transport/http"
   "github.com/gorilla/mux"
   sgm "github.com/the-gigi/delinkcious/pkg/social_graph_manager"
   "log"
   "net/http"
)
```

Go kit `http`传输包对于使用 HTTP 传输的服务是必需的。`gorilla/mux`包提供了一流的路由功能。`social_graph_manager`是执行所有繁重工作的服务的实现。`log`包用于记录日志，`net/http`包用于提供 HTTP 服务，因为它是一个 HTTP 服务。

只有一个名为`Run()`的函数。它首先创建一个社交图管理器的数据存储，然后创建社交图管理器本身，并将`store`字段传递给它。因此，`social_graph_manager`的功能是在包中实现的，但`service`负责做出策略决策并传递配置好的数据存储。如果在这一点上出了任何问题，服务将通过`log.Fatal()`调用退出，因为在这个早期阶段没有办法恢复。

```
func Run() {
   store, err := sgm.NewDbSocialGraphStore("localhost", 5432, "postgres", "postgres")
   if err != nil {
      log.Fatal(err)
   }
   svc, err := sgm.NewSocialGraphManager(store)
   if err != nil {
      log.Fatal(err)
   }
```

接下来是为每个端点构建处理程序的部分。这是通过调用 HTTP 传输的`NewServer()`函数来完成的。参数是`Endpoint`工厂函数（我们很快将对其进行审查）、请求解码器函数和`response`编码器函数。对于 HTTP 服务，通常将请求和响应编码为 JSON。

```
followHandler := httptransport.NewServer(
   makeFollowEndpoint(svc),
   decodeFollowRequest,
   encodeResponse,
)

unfollowHandler := httptransport.NewServer(
   makeUnfollowEndpoint(svc),
   decodeUnfollowRequest,
   encodeResponse,
)

getFollowingHandler := httptransport.NewServer(
   makeGetFollowingEndpoint(svc),
   decodeGetFollowingRequest,
   encodeResponse,
)

getFollowersHandler := httptransport.NewServer(
   makeGetFollowersEndpoint(svc),
   decodeGetFollowersRequest,
   encodeResponse,
)
```

此时，我们已经正确初始化了`SocialGraphManager`并且为所有端点准备好了处理程序。现在是时候通过`gorilla`路由器向世界公开它们了。每个端点都与一个路由和一个方法相关联。在这种情况下，`follow`和`unfollow`操作使用 POST 方法，`following`和`followers`操作使用 GET 方法：

```
r := mux.NewRouter()
r.Methods("POST").Path("/follow").Handler(followHandler)
r.Methods("POST").Path("/unfollow").Handler(unfollowHandler)
r.Methods("GET").Path("/following/{username}").Handler(getFollowingHandler)
r.Methods("GET").Path("/followers/{username}").Handler(getFollowersHandler)
```

最后一部分只是将配置好的路由器传递给标准 HTTP 包的`ListenAndServe()`方法。该服务硬编码为监听端口`9090`。在本书的后面，我们将看到如何以灵活和更具产业实力的方式配置这些东西：

```
log.Println("Listening on port 9090...")
log.Fatal(http.ListenAndServe(":9090", r))
```

# 实现支持函数

你可能还记得，`pkg/social_graph_manager`包中的社交图实现完全与传输无关。它根据 Go 实现`SocialGraphManager`接口，不管负载是 JSON 还是 protobuf，以及通过 HTTP、gRPC、Thrift 或任何其他方法传输。服务负责翻译、编码和解码。这些支持函数在`transport.go`文件中实现。

对于每个端点，都有三个函数，它们是 Go kit 的 HTTP 传输`NewServer()`函数的输入：

+   `Endpoint`工厂函数

+   `request`解码器

+   `response`编码器

让我们从`Endpoint`工厂函数开始，这是最有趣的部分。让我们以`GetFollowing()`操作为例。`makeGetFollowingEndpoint()`函数以`SocialGraphManager`接口作为输入（如你之前看到的，在实践中，它将是`pkg/social_graph_manager`中的实现）。它返回一个通用的`endpoint.Endpoint`函数，这是一个接受`Context`和通用`request`并返回通用`response`和`error`的函数：

```
type Endpoint func(ctx context.Context, request interface{}) (response interface{}, err error)
```

`makeGetFollowingEndpoint()`方法的工作是返回一个符合这个签名的函数。它返回这样一个函数，在其实现中，接受通用请求（空接口）和类型，然后将其断言为具体的请求，即`getByUsernameRequest`：

```
req := request.(getByUsernameRequest)
```

这是一个关键概念。我们从一个通用对象跨越边界，这个对象可以是任何东西，到一个强类型的结构体。这确保了，即使 Go kit 端点是以空接口的形式操作，我们的微服务的实现也经过了类型检查。如果请求不包含正确的字段，它会引发 panic。我也可以检查是否可能进行类型断言，而不是引发 panic，这在某些情况下可能更合适：

```
req, ok := request.(getByUsernameRequest)
if !ok {
   ...
}
```

让我们来看看请求本身。它只是一个带有一个名为`Username`的字符串字段的结构体。它有 JSON 结构标签，在这种情况下是可选的，因为 JSON 包可以通过大小写的不同来自动处理与实际 JSON 不同的字段名（例如`Username`与`username`）：

```
type getByUsernameRequest struct {
   Username string `json:"username"`
}
```

请注意，请求类型是`getByUsernameRequest`而不是`getFollowingRequest`，这可能与您期望的一致，以支持它正在支持的操作。原因是我实际上在多个端点上使用相同的请求。`GetFollowers()`操作也需要一个`username`，而`getByUsernameRequest`同时为`GetFollowing()`和`GetFollowers()`提供服务。

此时，我们从请求中得到了用户名，我们可以调用底层实现的`GetFollowing()`方法：

```
followingMap, err := svc.GetFollowing(req.Username)
```

结果是请求用户正在关注的用户的映射和标准错误。但是，这是一个 HTTP 端点，所以下一步是将这些信息打包到`getFollowingResponse`结构体中：

```
type getFollowingResponse struct {
   Following map[string]bool `json:"following"`
   Err       string          `json:"err"`
}
```

以下映射可以转换为`string->bool`的 JSON 映射。然而，Go 错误接口没有直接的等价物。解决方案是将错误编码为字符串（通过`err.Error()`），其中空字符串表示没有错误：

```
res := getFollowingResponse{Following: followingMap}
if err != nil {
   res.Err = err.Error()
}
```

这是整个函数：

```
func makeGetFollowingEndpoint(svc om.SocialGraphManager) endpoint.Endpoint {
   return func(_ context.Context, request interface{}) (interface{}, error) {
      req := request.(getByUsernameRequest)
      followingMap, err := svc.GetFollowing(req.Username)
      res := getFollowingResponse{Following: followingMap}
      if err != nil {
         res.Err = err.Error()
      }
      return res, nil
   }
}
```

现在，让我们来看看`decodeGetFollowingRequest()`函数。它接受标准的`http.Request`对象。它需要从请求中提取用户名，并返回一个`getByUsernameRequest`结构体，以便端点稍后可以使用。在 HTTP 请求级别，用户名将成为请求路径的一部分。该函数将解析路径，提取用户名，准备请求，并返回请求或错误（例如，未提供用户名）：

```
func decodeGetFollowingRequest(_ context.Context, r *http.Request) (interface{}, error) {
   parts := strings.Split(r.URL.Path, "/")
   username := parts[len(parts)-1]
   if username == "" || username == "following" {
      return nil, errors.New("user name must not be empty")
   }
   request := getByUsernameRequest{Username: username}
   return request, nil
```

最后一个支持函数是`encodeResonse()`函数。理论上，每个端点都可以有自己的自定义`response`编码函数。但在这种情况下，我使用了一个通用函数，它知道如何将所有响应编码为 JSON：

```
func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
   return json.NewEncoder(w).Encode(response)
}
```

这需要所有响应结构都可以被 JSON 序列化，这是通过将 Go 错误接口转换为端点实现的字符串来处理的。

# 通过客户端库调用 API。

社交图管理器现在可以通过 HTTP REST API 访问。这是一个快速的本地演示。首先，我将启动 Postgres DB（我有一个名为`postgres`的 Docker 镜像），它用作数据存储，然后我将在`service`目录中运行服务本身，即`delinkcious/svc/social_graph_service`：

```
$ docker restart postgres
$ go run main.go

2018/12/31 10:41:23 Listening on port 9090...
```

通过调用`/follow`端点来添加一些关注/被关注的关系。我将使用出色的 HTTPie（[`httpie.org/`](https://httpie.org/)），在我看来，这是一个更好的`curl`。但是，如果你喜欢，你也可以使用`curl`：

```
$ http POST http://localhost:9090/follow followed=liat follower=gigi
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Mon, 31 Dec 2018 09:19:01 GMT

{
 "err": ""
}

$ http POST http://localhost:9090/follow followed=guy follower=gigi
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Mon, 31 Dec 2018 09:19:01 GMT

{
 "err": ""
}
```

这两个调用使`gigi`用户关注`liat`和`guy`用户。让我们使用`/following`端点来验证这一点：

```
$ http GET http://localhost:9090/following/gigi
HTTP/1.1 200 OK
Content-Length: 37
Content-Type: text/plain; charset=utf-8
Date: Mon, 31 Dec 2018 09:37:21 GMT

{
 "err": "",
 "following": {
 "guy": true
 "liat": true
 }
}
```

JSON 响应中有一个空错误，`following`映射包含了`guy`和`liat`用户，如预期的那样。

虽然 REST API 很酷，但我们可以做得更好。我们不应该强迫调用者理解我们服务的 URL 模式，并解码和编码 JSON 负载，为什么不提供一个客户端库来完成所有这些呢？这对于所有使用少量语言进行交流的内部微服务来说尤其如此，在许多情况下，甚至只有一种语言。服务和客户端可以共享相同的接口，甚至可能有一些共同的类型。此外，Go kit 提供了对客户端端点的支持，这些端点与服务端端点非常相似。这直接转化为一个非常简化的端到端开发者体验，你只需留在编程语言空间。所有端点、传输、编码和解码可以大部分时间保持隐藏，作为实现细节。

社交图服务提供了一个客户端库，位于`pkg/social_graph_client`包中。`client.go`文件类似于`social_graph_service.go`文件，负责在`NewClient()`函数中创建一组端点，并返回`SocialGraphManager`接口。`NewClient()`函数以基本 URL 作为参数，然后使用 Go kit 的 HTTP 传输的`NewClient()`函数构建一组客户端端点。每个端点都需要一个 URL、一个方法（在本例中为`GET`或`POST`）、一个`request`编码器和一个`response`解码器。它就像服务的镜像。然后，它将客户端端点分配给`EndpointSet`结构体，可以通过`SocialGraphManager`接口公开它们：

```
func NewClient(baseURL string) (om.SocialGraphManager, error) {
   // Quickly sanitize the instance string.
   if !strings.HasPrefix(baseURL, "http") {
      baseURL = "http://" + baseURL
   }
   u, err := url.Parse(baseURL)
   if err != nil {
      return nil, err
   }

   followEndpoint := httptransport.NewClient(
      "POST",
      copyURL(u, "/follow"),
      encodeHTTPGenericRequest,
      decodeSimpleResponse).Endpoint()

   unfollowEndpoint := httptransport.NewClient(
      "POST",
      copyURL(u, "/unfollow"),
      encodeHTTPGenericRequest,
      decodeSimpleResponse).Endpoint()

   getFollowingEndpoint := httptransport.NewClient(
      "GET",
      copyURL(u, "/following"),
      encodeGetByUsernameRequest,
      decodeGetFollowingResponse).Endpoint()

   getFollowersEndpoint := httptransport.NewClient(
      "GET",
      copyURL(u, "/followers"),
      encodeGetByUsernameRequest,
      decodeGetFollowersResponse).Endpoint()

   // Returning the EndpointSet as an interface relies on the
   // EndpointSet implementing the Service methods. That's just a simple bit
   // of glue code.
   return EndpointSet{
      FollowEndpoint:       followEndpoint,
      UnfollowEndpoint:     unfollowEndpoint,
      GetFollowingEndpoint: getFollowingEndpoint,
      GetFollowersEndpoint: getFollowersEndpoint,
   }, nil
}
```

`EndpointSet`结构体在`endpoints.go`文件中定义。它包含端点本身，这些端点是函数，并实现了`SocialGraphManager`方法，在其中将工作委托给端点的函数：

```
type EndpointSet struct {
   FollowEndpoint       endpoint.Endpoint
   UnfollowEndpoint     endpoint.Endpoint
   GetFollowingEndpoint endpoint.Endpoint
   GetFollowersEndpoint endpoint.Endpoint
}
```

让我们检查`EndpointSet`结构体的`GetFollowing()`方法。它接受用户名作为字符串，然后调用带有填充输入用户名的`getByUserNameRequest`的端点。如果调用端点函数返回错误，它就会退出。否则，它进行类型断言，将通用响应转换为`getFollowingResponse`结构体。如果其错误字符串不为空，它会从中创建一个 Go 错误。最终，它将响应中的关注用户作为映射返回：

```
func (s EndpointSet) GetFollowing(username string) (following map[string]bool, err error) {
   resp, err := s.GetFollowingEndpoint(context.Background(), getByUserNameRequest{Username: username})
   if err != nil {
      return
   }

   response := resp.(getFollowingResponse)
   if response.Err != "" {
      err = errors.New(response.Err)
   }
   following = response.Following
   return
}
```

# 存储数据

我们已经看到了 Go kit 和我们自己的代码如何接受带有 JSON 负载的 HTTP 请求，将其转换为 Go 结构，调用服务实现，并将响应编码为 JSON 返回给调用者。现在，让我们更深入地了解数据的持久存储。社交图管理器负责维护用户之间的关注/粉丝关系。有许多选项可用于存储此类数据，包括关系数据库、键值存储，当然还有图数据库，这可能是最自然的。在这个阶段，我选择使用关系数据库，因为它熟悉、可靠，并且可以很好地支持所需的操作：

+   关注

+   取消关注

+   获取关注者

+   获取以下

然而，如果我们后来发现我们更喜欢不同的数据存储或者扩展关系型数据库以添加一些缓存机制，那么很容易做到，因为社交图管理器的数据存储被隐藏在一个接口后面。它实际上使用的是同一个接口，即 `SocialGraphManager`。正如您可能记得的那样，社交图管理器包在其工厂函数中接受了一个 `SocialGraphManager` 类型的存储参数：

```
func NewSocialGraphManager(store om.SocialGraphManager) (om.SocialGraphManager, error) {
   if store == nil {
      return nil, errors.New("store can't be nil")
   }
   return &SocialGraphManager{store: store}, nil
}
```

由于社交图管理器通过这个接口与其数据存储进行交互，因此可以在不对社交图管理器本身进行任何代码更改的情况下进行更改实现。

我将利用这一点进行单元测试，其中我使用一个易于设置的内存数据存储，可以快速填充测试数据，并允许我在本地运行测试。

让我们来看看内存中的社交图数据存储，可以在[`github.com/the-gigi/delinkcious/blob/master/pkg/social_graph_manager/in_memory_social_graph_store.go`](https://github.com/the-gigi/delinkcious/blob/master/pkg/social_graph_manager/in_memory_social_graph_store.go)找到。

它几乎没有依赖关系 - 只有 `SocialGraphManager` 接口和标准错误包。它定义了一个 `SocialUser` 结构，其中包含用户名以及它正在关注的用户的名称，以及正在关注它的用户的名称：

```
package social_graph_manager

import (
   "errors"
   om "github.com/the-gigi/delinkcious/pkg/object_model"
)

type Followers map[string]bool
type Following map[string]bool

type SocialUser struct {
   Username  string
   Followers Followers
   Following Following
}

func NewSocialUser(username string) (user *SocialUser, err error) {
   if username == "" {
      err = errors.New("user name can't be empty")
      return
   }

   user = &SocialUser{Username: username, Followers: Followers{}, Following: Following{}}
   return
}
```

数据存储本身是一个名为 `InMemorySocialGraphStore` 的结构，其中包含用户名和相应的 `SocialUser` 结构之间的映射：

```
type SocialGraph map[string]*SocialUser

type InMemorySocialGraphStore struct {
   socialGraph SocialGraph
}

func NewInMemorySocialGraphStore() om.SocialGraphManager {
   return &InMemorySocialGraphStore{
      socialGraph: SocialGraph{},
   }
}
```

这都是相当普通的。`InMemorySocialGraphStore` 结构实现了 `SocialGraphManager` 接口方法。例如，这是 `Follow()` 方法：

```
func (m *InMemorySocialGraphStore) Follow(followed string, follower string) (err error) {
   followedUser := m.socialGraph[followed]
   if followedUser == nil {
      followedUser, _ = NewSocialUser(followed)
      m.socialGraph[followed] = followedUser
   }

   if followedUser.Followers[follower] {
      return errors.New("already following")
   }

   followedUser.Followers[follower] = true

   followerUser := m.socialGraph[follower]
   if followerUser == nil {
      followerUser, _ = NewSocialUser(follower)
      m.socialGraph[follower] = followerUser
   }

   followerUser.Following[followed] = true

   return
```

此时，没有必要过多关注它的工作原理。我想要传达的主要观点是，通过使用接口作为抽象，您可以获得很大的灵活性和清晰的关注点分离，这在您想要在测试期间开发系统或服务的特定部分时非常有帮助。如果您想要进行重大更改，比如更改底层数据存储或可互换使用多个数据存储，那么拥有一个接口是一个救命稻草。

# 总结

在本章中，您仔细了解了 Go kit 工具包，整个 Delinkcious 系统及其微服务，并深入研究了 Delinkcious 的社交图组件。本章的主题是，Go kit 提供了清晰的抽象，如服务、端点和传输，以及用于将微服务分层的通用功能。然后，您可以为松散耦合但内聚的微服务系统添加代码。您还跟随了来自客户端的请求的路径，一直到服务，然后通过所有层返回。在这一点上，您应该对 Go kit 如何塑造 Delinkcious 架构以及它如何使任何其他系统受益有一个大致的了解。您可能会对所有这些信息感到有些不知所措，但请记住，这种复杂性被整齐地打包了起来，您大部分时间可以忽略它，专注于您的应用程序，并获得好处。

在下一章中，我们将讨论任何现代基于微服务的系统中非常关键的部分 - CI/CD 流水线。我们将创建一个 Kubernetes 集群，配置 CircleCI，部署 Argo CD 持续交付解决方案，并了解如何在 Kubernetes 上部署 Delinkcious。

# 进一步阅读

让我们参考以下参考资料：

+   要了解更多关于 Go kit 的信息，请访问[`gokit.io/`](https://gokit.io/)。

+   为了更好地理解 Delinkcious 利用的 SOLID 设计原则，请查看[`en.wikipedia.org/wiki/SOLID`](https://en.wikipedia.org/wiki/SOLID)。
