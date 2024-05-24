# Kubernetes Windows 实用指南（二）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：理解 Kubernetes 基础知识

理解 Kubernetes 基础知识对于开发和部署容器应用程序至关重要。在这里，您将了解 Kubernetes 与容器管理的关系以及该平台的关键组件是什么。

本节包括以下章节：

+   [第四章]，*Kubernetes 概念和 Windows 支持*

+   [第五章]，*Kubernetes 网络*

+   [第六章]，*与 Kubernetes 集群交互*


# 第四章：Kubernetes 概念和 Windows 支持

在之前的章节中，我们专注于 Windows 平台上的容器化和 Docker 支持。这些概念主要局限于单机场景，即应用程序只需要一个容器主机。对于生产级分布式容器系统，您必须考虑不同的方面，如可伸缩性、高可用性和负载平衡，这总是需要对运行在多个主机上的容器进行编排。

容器编排是在大型动态环境中管理容器生命周期的一种方式，从提供和部署容器到管理网络、提供容器的冗余和高可用性、自动扩展和缩减容器实例、自动健康检查和遥测收集。解决容器编排问题并不是一件简单的事情，这就是为什么 Kubernetes（简称 k8s，其中 8 代表省略的字符数）诞生的原因。

Kubernetes 的故事可以追溯到 21 世纪初的 Borg 系统，这是谷歌内部开发的用于大规模管理和调度作业的系统。随后，在 2010 年代初，谷歌开发了 Omega 集群管理系统，作为对 Borg 的全新重写。虽然 Omega 仍然只在谷歌内部使用，但在 2014 年，Kubernetes 作为开源容器编排解决方案宣布推出，它的根源来自 Borg 和 Omega。2015 年 7 月，Kubernetes 的 1.0 版本发布时，谷歌与 Linux 基金会合作成立了云原生计算基金会（CNCF）。该基金会旨在赋予组织能力，使它们能够在公共、私有和混合云等现代动态环境中构建和运行可扩展的应用程序。四年后的 2019 年 4 月，发布了 Kubernetes 1.14 版本，为 Windows 节点和 Windows 容器提供了生产级支持。本章主要讨论 Kubernetes 在 Windows 方面的当前状态！

**云原生应用**是容器编排中常用的术语，用于指代利用容器化、云计算框架和组件的松耦合（微服务）的应用程序。但这并不一定意味着云原生应用必须在云中运行 - 它们遵循一组原则，使它们易于在本地或公共/私有云中托管。如果您对了解更多关于 CNCF 感兴趣，请参考官方网页：[`www.cncf.io/`](https://www.cncf.io/)。

在本章中，我们将涵盖以下主题：

+   Kubernetes 高级架构

+   Kubernetes 对象

+   Windows 和 Kubernetes 生态系统

+   Windows 上的 Kubernetes 限制

+   从头开始创建您自己的开发集群

+   生产集群部署策略

+   托管的 Kubernetes 提供程序

# 技术要求

本章，您将需要以下内容：

+   已安装 Windows 10 Pro、企业版或教育版（1903 版或更高版本，64 位）

+   已安装 Docker Desktop for Windows 2.0.0.3 或更高版本

+   已安装的 Windows Chocolatey 软件包管理器（[`chocolatey.org/`](https://chocolatey.org/)）

+   已安装 Azure CLI

如何安装 Docker Desktop for Windows 及其系统要求已在第一章*，Creating Containers*中介绍过。

使用 Chocolatey 软件包管理器并非强制，但它可以使安装和应用程序版本管理变得更加容易。安装过程在此处有文档记录：[`chocolatey.org/install`](https://chocolatey.org/install)。

对于 Azure CLI，您可以在第二章*，*Managing State in Containers**中找到详细的安装说明。

要了解托管的 Kubernetes 提供程序，您将需要自己的 Azure 帐户，以便创建具有 Windows 节点的 AKS 实例。如果您之前没有为本书的前几章创建帐户，您可以在此处阅读有关如何获取个人使用的有限免费帐户的更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

您可以从本书的官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter04)。

# Kubernetes 高级架构

在本节和下一节中，我们将重点关注 Kubernetes 的高级架构及其核心组件。如果您已经对 Kubernetes 有一般了解，但想了解更多关于 Kubernetes 对 Windows 的支持，您可以跳到*Windows 和 Kubernetes 生态系统*部分。

# Kubernetes 是什么？

总的来说，Kubernetes 可以被看作是以下内容：

+   容器（微服务）编排系统

+   用于运行分布式应用程序的集群管理系统

作为一个容器编排器，Kubernetes 解决了在大规模部署容器化的云原生应用时出现的常见挑战。这包括以下内容：

+   在多个容器主机（节点）上进行容器的配置和部署

+   服务发现和负载均衡网络流量

+   自动扩展容器实例的规模

+   自动化部署和回滚新的容器镜像版本

+   自动的、最佳的容器资源（如 CPU 或内存）装箱

+   应用程序监控、遥测收集和健康检查

+   编排和抽象存储（本地、本地部署或云端）

与此同时，Kubernetes 也可以被描述为一个集群管理系统 - 主节点（或在高可用部署中的多个主节点）负责有效地协调处理实际容器工作负载的多个工作节点。这些工作负载不仅限于 Docker 容器 - Kubernetes 在工作节点上使用容器运行时接口（CRI）来抽象容器运行时。最终，集群客户端（例如 DevOps 工程师）可以使用主节点暴露的 RESTful API 来管理集群。集群管理使用声明式模型进行，这使得 Kubernetes 非常强大 - 您描述所需的状态，Kubernetes 会为了将集群的当前状态转换为所需的状态而进行所有繁重的工作。

使用临时命令进行命令式集群管理也是可能的，但通常不建议用于生产环境。操作是直接在活动集群上执行的，并且没有先前配置的历史记录。在本书中，我们将尽可能使用声明性对象配置技术。有关 Kubernetes 集群管理技术的更详细讨论，请参阅官方文档：[`kubernetes.io/docs/concepts/overview/working-with-objects/object-management/`](https://kubernetes.io/docs/concepts/overview/working-with-objects/object-management/)。

Kubernetes 的高级架构可以在以下图表中看到。我们将在接下来的几段中逐个介绍每个组件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/b69c82e9-b93c-440a-97ba-5e639a928a3e.png)

让我们首先关注 Kubernetes 主节点，也称为控制平面的角色。

# Kubernetes 主节点-控制平面

在 Kubernetes 集群中，主节点（控制平面）由一组负责全局决策的组件组成，例如将应用实例调度和部署到工作节点，以及管理集群事件。此外，主节点为工作节点和管理客户端之间的通信公开了 API。

主要组件不限于在专用主机上运行；它也可以在工作节点上运行。主节点可以像 Kubernetes 集群中的任何节点一样充当工作节点。但是，一般来说，由于可靠性原因，不建议这样做-而且对于生产环境，您应该考虑运行高可用性的 Kubernetes 设置，这需要多个主节点运行组件冗余。

运行 Kubernetes 主服务的最显著限制之一是它们必须托管在 Linux 机器上。不可能在 Windows 机器上拥有主组件，这意味着即使您计划仅运行 Windows 容器，您仍然需要 Linux 机器作为主机。目前，尚无计划实施仅限 Windows 的 Kubernetes 集群，尽管随着 Windows 子系统的开发进展，情况可能会发生变化。

我们将简要介绍组成主节点的组件。让我们首先看一下 Kubernetes API 服务器（或`kube-apiserver`，这是该组件的二进制名称）。

# kube-apiserver

**Kubernetes API 服务器**（**kube-apiserver**）是 Kubernetes 控制平面中的核心组件，充当客户端和集群组件之间所有交互的网关。其主要职责如下：

+   公开作为一组通过 HTTPS 的 RESTful 端点实现的集群 API。API 由管理集群的客户端以及内部 Kubernetes 组件使用。Kubernetes 集群中的所有资源都被抽象为 Kubernetes API 对象。

+   在`etcd`集群中持久化集群状态 - 客户端执行的每个操作或集群组件报告的状态更新都必须通过 API 服务器并持久化存储在集群中。

+   用户和服务账户的认证和授权。

+   请求的验证。

+   提供*watch* API 以通知订阅者（例如其他集群组件）有关集群状态变化的增量通知源。观察 API 是使 Kubernetes 高度可扩展和分布式的关键概念。

在高可用的 Kubernetes 部署中，`kube-apiserver`托管在多个主节点上，位于专用负载均衡器后面。

# etcd 集群

为了持久化集群状态，Kubernetes 使用`etcd` - 一个分布式、可靠的键值存储，利用 Raft 分布式一致性算法来提供顺序一致性。`etcd`集群是控制平面中最重要的部分 - 这是整个集群的真相来源，无论是当前状态还是集群的期望状态。

通常，仅建议用于测试目的的单节点`etcd`集群。对于生产场景，您应该始终考虑至少运行一个由五个成员组成的集群（成员数为奇数），以提供足够的容错能力。

在选择`etcd`集群部署拓扑时，可以考虑堆叠的 etcd 拓扑或外部的 etcd 拓扑。堆叠的 etcd 拓扑由每个 Kubernetes 主节点实例的一个 etcd 成员组成，而外部的 etcd 拓扑则利用了一个独立于 Kubernetes 部署的 etcd 集群，并通过负载均衡器可用。您可以在官方文档中了解更多关于这些拓扑的信息：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/)。

`etcd`公开的*watch*协议也是 Kubernetes 中 watch API 的核心功能，由`kube-apiserver`为其他组件提供。

# kube-scheduler

**Kubernetes Scheduler**（**kube-scheduler**）组件的主要责任是调度容器工作负载（Kubernetes Pods）并将它们分配给满足运行特定工作负载所需条件的健康工作节点。

Pod 是 Kubernetes 系统中最小的部署单元，是一个或多个具有共享网络和存储的容器组。我们将在下一节中介绍这个 Kubernetes 对象。

调度分为两个阶段：

+   过滤

+   评分

在过滤阶段，`kube-scheduler`确定能够运行给定 Pod 的节点集。这包括检查节点的实际状态，并验证 Pod 定义中指定的任何资源要求。在这一点上，如果没有节点可以运行给定的 Pod，那么 Pod 将无法调度并保持挂起状态。接下来，在评分步骤中，调度程序根据一组策略为每个节点分配分数。然后，调度程序将 Pod 分配给具有最高分数的节点。

您可以在官方文档中了解更多有关可用策略的信息：[`kubernetes.io/docs/concepts/scheduling/kube-scheduler/#kube-scheduler-implementation`](https://kubernetes.io/docs/concepts/scheduling/kube-scheduler/#kube-scheduler-implementation)。

Kubernetes 设计提供了很大的可扩展性和替换组件的可能性。Kube-scheduler 是用来演示这一原则的组件之一。即使其内部业务逻辑很复杂（所有高效的调度启发式算法都相当复杂...），调度程序只需要监视*未分配*的 Pod，确定最适合它们的节点，并通知 API 服务器进行分配。您可以在这里查看自定义调度程序的示例实现：[`banzaicloud.com/blog/k8s-custom-scheduler/`](https://banzaicloud.com/blog/k8s-custom-scheduler/)。

现在，让我们来看看`kube-controller-manager`。

# kube-controller-manager

**Kubernetes Controller Manager**（**kube-controller-manager**）是负责在集群中运行核心协调和控制循环的组件。控制器管理器由一组独立的专门控制器组成。控制器的主要目的是观察 API 服务器公开的*当前*和*期望*集群状态，并命令试图将*当前*状态转换为*期望*状态的变化。

`kube-controller-manager`二进制文件中提供的最重要的控制器如下：

+   **Node Controller（以前称为 nodelifecycle）**：观察节点的状态，并在节点不可用时做出反应。

+   **ReplicaSet Controller（replicaset）**：负责确保每个 ReplicaSet API 对象运行正确数量的 Pod。

+   **Deployment Controller（deployment）**：负责管理关联的 ReplicaSet API 对象并执行部署和回滚。

+   **Endpoints Controller（endpoint）**：管理 Endpoint API 对象。

+   **Service Account Controller（serviceaccount）和 Token Controller（serviceaccount-token）**：负责为新命名空间创建默认帐户和访问令牌。

您可以将 kube-controller-manager 视为确保集群的*当前*状态朝向*期望*集群状态移动的 Kubernetes 大脑。

# cloud-controller-manager

最初是`kube-controller-manager`的一部分，**Kubernetes Cloud Controller Manager**（**cloud-controller-manager**）提供特定于云的控制循环。分离云控制器管理器的原因是为了更容易地发展特定于云的连接器（提供商）代码，这些代码在大多数情况下以不同的节奏发布。

截至 Kubernetes 1.17，cloud-controller-manager 仍处于测试阶段。您可以在官方文档中检查该功能的当前状态：[`kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller`](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller)。

启用云控制器管理器时，必须禁用 kube-controller-manager 中的特定于云的控制循环。然后，以下控制器将依赖于云提供商的实现：

+   **Node Controller**：用于确定节点的状态并检测节点是否已删除。

+   路由控制器：需要提供者来设置网络路由。

+   服务控制器：通过提供者管理负载均衡器。

+   卷控制器：使用提供者管理存储卷。

作为 Kubernetes 的一部分提供的外部云提供者的列表不断发展，并且可以在官方文档（[`kubernetes.io/docs/concepts/cluster-administration/cloud-providers/`](https://kubernetes.io/docs/concepts/cluster-administration/cloud-providers/)）和 Kubernetes 的组织 GitHub 页面（[`github.com/kubernetes?q=cloud-provider-&type=&language=`](https://github.com/kubernetes?q=cloud-provider-&type=&language=)）上进行检查。

# Kubernetes 节点 - 数据平面

在 Kubernetes 集群中，数据平面由负责运行主控安排的容器工作负载的节点（以前称为*minions*）组成。节点可以是物理裸金属机器或虚拟机器，这在设计集群时提供了灵活性。

以下图表总结了组成 Kubernetes 节点的架构和组件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d035407d-e290-4389-a794-5f072d975582.png)

在 Windows 支持方面，所有节点组件都可以在 Windows 和 Linux 机器上运行。这意味着 Windows Kubernetes 节点在与 Linux 节点相同的方式下对主控可见，并且从这个角度来看，它们只在它们可以支持的容器类型上有所不同。

Kubernetes 节点的主要组件如下：

+   kubelet：主要的 Kubernetes 代理，负责确保容器工作负载（Pods）在节点上执行。

+   容器运行时：负责管理容器的软件。它由容器运行时接口（CRI）抽象出来。

+   kube-proxy：负责管理本地节点网络的网络代理。

让我们先来看看`kubelet`。

# kubelet

在集群中的每个节点上运行，`kubelet`是一个负责确保控制平面分配的容器工作负载（Pods）得到执行的服务。此外，它还负责以下工作：

+   报告节点和 Pods 状态给 API 服务器

+   报告资源利用情况

+   执行节点注册过程（加入新节点到集群时）

+   执行活跃性和就绪性探针（健康检查）并将其状态报告给 API 服务器

为执行实际的与容器相关的操作，kubelet 使用容器运行时。

# 容器运行时

Kubelet 并不直接与 Docker 耦合 - 实际上，正如我们在本节介绍中提到的，Docker 并不是 Kubernetes 支持的唯一**容器运行时**。为了执行与容器相关的任务，例如拉取镜像或创建新容器，kubelet 利用**容器运行时接口**（CRI），这是一个为不同运行时抽象所有常见容器操作的插件接口。

容器运行时接口的实际定义是一个 protobuf API 规范，可以在官方存储库中找到：[`github.com/kubernetes/cri-api/`](https://github.com/kubernetes/cri-api/)。任何实现此规范的容器运行时都可以用于在 Kubernetes 中执行容器工作负载。

目前，在 Linux 上可以与 Kubernetes 一起使用的容器运行时有很多。最流行的如下：

+   **Docker**：由`dockershim`抽象出的*传统* Docker 运行时，这是`kubelet`的 CRI 实现。

+   **CRI-containerd**：简而言之，`containerd`是 Docker 的一个组件，负责容器的管理。目前，CRI-containerd 是 Linux 上 Kubernetes 的推荐运行时。更多信息，请访问[`containerd.io/`](https://containerd.io/)。

+   **CRI-O**：专门用于 CRI 的容器运行时实现，遵循**Open Containers Initiative**（OCI）规范。更多信息，请访问[`cri-o.io/`](https://cri-o.io/)。

+   **gVisor**：与 Docker 和 containerd 集成的符合 OCI 标准的容器沙箱运行时。更多信息，请访问[`gvisor.dev/`](https://gvisor.dev/)。

dockershim 和 CRI-containerd 之间的区别可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/319c91e3-e62c-451e-90f5-5d6929202701.png)

CRI-containerd 运行时提供了一个更简单的架构，守护程序和进程之间的通信更少，从而消除了传统的 Docker 引擎。这个解决方案旨在提供一个裁剪版的 Docker 运行时，暴露出关键的组件供 Kubernetes 使用。

如果您对 Docker 和 containerd 分离的历史背景感兴趣，可以阅读以下文章：[`alexander.holbreich.org/docker-components-explained/`](http://alexander.holbreich.org/docker-components-explained/)。

对于 Windows，支持的列表要短得多，目前包括 Docker（企业版 18.09+，也由 dockershim 抽象）和即将支持的 CRI-containerd。预计当 containerd 1.3 的稳定版本发布并且 *runhcs shim* 得到全面支持时，这将可用。这还将带来对容器的 Hyper-V 隔离的新支持，目前（截至 Kubernetes 1.17）作为有限的实验性功能实现，没有使用 CRI-containerd。

# kube-proxy

在 Kubernetes 集群中，节点上的网络规则和路由由运行在每个节点上的 kube-proxy 管理。这些规则允许 Pod 与外部客户端之间进行通信，并且是 Service API 对象的重要组成部分。在 Linux 平台上，kube-proxy 使用 iptables 配置规则（最常见），而在 Windows 平台上，使用 **Host Networking Service** (**HNS**)。

我们将在下一章更详细地介绍 Kubernetes 网络。

# DNS

内部 DNS 服务器是可选的，并且可以作为附加组件安装，但在标准部署中强烈建议使用，因为它简化了服务发现和网络。目前，Kubernetes 使用的默认 DNS 服务器是 CoreDNS（[`coredns.io/`](https://coredns.io/)）。

Kubernetes 会自动为每个容器的域名解析配置添加一个内部静态 IP 地址的 DNS 服务器。这意味着在 Pod 中运行的进程可以通过知道它们的域名与集群中运行的服务和 Pod 进行通信，这些域名将解析为实际的内部 IP 地址。Kubernetes Service 对象的概念将在下一节中介绍。

现在，让我们来看一下最常用的 Kubernetes 对象。

# Kubernetes 对象

在本书的后面部分将介绍在 Windows 节点上设置 Kubernetes 集群的复杂性，并且将在 Linux 示例上演示原则。从 Kubernetes API 服务器的角度来看，Windows 和 Linux 节点的操作方式几乎相同。

在 Kubernetes 集群中，集群状态由 kube-apiserver 组件管理，并持久存储在`etcd`集群中。状态被抽象和建模为一组 Kubernetes 对象 - 这些实体描述了应该运行什么容器化应用程序，它们应该如何被调度，以及关于重新启动或扩展它们的策略。如果您想在 Kubernetes 集群中实现任何目标，那么您必须创建或更新 Kubernetes 对象。这种模型称为**声明性模型** - 您声明您的意图，Kubernetes 负责将集群的当前状态更改为期望的（预期的）状态。声明性模型和保持期望状态的理念是使 Kubernetes 如此强大和易于使用的原因。

在本书中，我们将遵循官方文档的惯例，其中对象是大写的；例如，Pod 或 Service。

每个 Kubernetes 对象的解剖结构完全相同；它有两个字段：

+   **Spec**：这定义了对象的*期望状态*。这是您在创建或更新对象时定义要求的地方。

+   **Status**：这是由 Kubernetes 提供的，并描述了对象的*当前状态*。

始终需要使用 Kubernetes API 来处理 Kubernetes 对象。最常见的情况是使用 Kubernetes 的**命令行接口**（CLI）来管理 Kubernetes 对象，该接口以`kubectl`二进制文件的形式提供。还可以使用客户端库直接与 Kubernetes API 进行交互。

`kubectl`的安装和其用法示例将在第六章中进行介绍，*与 Kubernetes 集群交互*。

现在，让我们快速看一下示例 Kubernetes 对象的结构。当直接与 Kubernetes API 交互时，对象必须以 JSON 格式指定。然而，`kubectl`允许我们使用 YAML 清单文件，在执行操作时将其转换为 JSON。通常建议使用 YAML 清单文件，并且您可以期望在文档中找到的大多数示例都遵循这个惯例。例如，我们将使用一个包含单个 nginx web 服务器 Linux 容器定义的 Pod 的定义，存储在名为`nginx.yaml`的文件中。

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod-example
  labels:
    app: nginx-host
spec:
  containers:
  - name: nginx
    image: nginx:1.17
    ports:
    - containerPort: 80
```

清单文件中的必需部分如下：

+   `apiVersion`：用于此对象的 Kubernetes API 的版本。

+   `kind`：Kubernetes 对象的类型。在这种情况下，这是`Pod`。

+   `metadata`：对象的附加元数据。

+   `spec`：对象规范。在示例规范中，nginx 容器使用`nginx:1.17` Docker 镜像并暴露端口`80`。每个 Kubernetes 对象的规范都不同，并且必须遵循 API 文档。例如，对于 Pod，您可以在这里找到 API 参考：[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#podspec-v1-core`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#podspec-v1-core)。

现在创建 Pod 就像运行以下`kubectl apply`命令一样简单：

```
kubectl apply -f nginx.yaml
```

如果您想尝试此命令而没有本地 Kubernetes 集群，我们建议使用 Kubernetes playground 中的一个；例如，[`www.katacoda.com/courses/kubernetes/playground`](https://www.katacoda.com/courses/kubernetes/playground)：

1.  在主窗口中运行以下`kubectl`命令，它将应用托管在 GitHub 上的清单文件：

```
kubectl apply -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/01_pod-example/nginx.yaml
```

1.  几秒钟后，Pod 将被创建，其`STATUS`应为`Running`：

```
master $ kubectl get pod -o wide
NAME                READY   STATUS    RESTARTS   AGE   IP          NODE     NOMINATED NODE   READINESS GATES
nginx-pod-example   1/1     Running   0          15s   10.40.0.1   node01   <none>           <none>
```

1.  在主窗口中使用`curl`命令获取 Pod 的 IP（在本例中为`10.40.0.1`）以验证容器是否确实在运行。您应该看到默认 nginx 网页的原始内容：

```
curl http://10.40.0.1:80
```

`kubectl`目前提供了两种声明性方法来管理 Kubernetes 对象：清单文件和 kustomization 文件。使用 kustomize 方法更加强大，因为它以可预测的结构组织清单文件和配置生成。您可以在这里了解更多关于 kustomize 的信息：[`github.com/kubernetes-sigs/kustomize/tree/master/docs`](https://github.com/kubernetes-sigs/kustomize/tree/master/docs)。

现在，让我们更仔细地看一下 Pod API 对象。

# Pods

Kubernetes 使用 Pod 作为部署和扩展的基本原子单位，并代表集群中运行的进程 - 从 Microsoft Hyper-V 的类比来说，就像是在 Hyper-V 集群中部署的单个虚拟机。Kubernetes Pod 由一个或多个共享内核命名空间、IPC、网络堆栈（您可以通过相同的集群 IP 地址对其进行寻址，并且它们可以通过 localhost 进行通信）和存储的容器组成。要理解 Pod，了解名称的起源是很有帮助的：在英语中，pod 是一群鲸鱼，而 Docker 使用鲸鱼作为其标志 - 将鲸鱼想象成 Docker 容器！

在最简单的形式中，你可以创建单容器 Pod - 这就是我们在本节介绍中演示 nginx Pod 创建时所做的。对于某些情况，你可能需要多容器 Pod，其中主容器伴随着其他容器，用于多种目的。让我们来看看其中一些：

+   **辅助** **容器**，可以执行各种*辅助*操作，比如日志收集，为主容器进行数据同步等。

+   **适配器** **容器**，可以规范输出或监视主容器的数据，以便其他服务可以使用。

+   **大使** **容器**，代理主容器与外部世界的通信。

+   **初始化** **容器**，这些是在 Pod 中的应用容器之前运行的专门容器。例如，它们可以设置环境，这在主容器镜像中没有执行。

从技术上讲，即使是单容器 Pod 也包含一个额外的基础设施容器，通常是一个暂停镜像。它充当了 Pod 中所有容器的*父*容器，并启用了内核命名空间共享。如果你对基础设施容器的更多细节感兴趣，请参考这篇文章：[`www.ianlewis.org/en/almighty-pause-container`](https://www.ianlewis.org/en/almighty-pause-container)。

Pod 的概念可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/bb6c0115-edb1-429f-ac9c-f3614a78d1c9.png)

在使用 Pod 时，有一些考虑事项需要牢记在心：

+   Pod 的容器始终在一个节点上运行，一旦 Pod 被创建，它就始终绑定到一个节点上。

+   通过增加更多的 Pod 来扩展你的应用，而不是在同一个 Pod 中增加更多的容器。

+   Pod 被认为是*就绪*并且能够响应请求时，*所有*它的容器都是就绪的。容器的状态由探针来确定，例如存活和就绪探针，这些可以在规范中定义。

+   Pod 是短暂的。它们被创建，它们死亡，如果需要的话，新的 Pod 会被重新创建。

+   当 Pod 被重新创建时，它会获得一个新的集群 IP。这意味着你的应用设计不应该依赖静态 IP 分配，并且假设 Pod 甚至可能在不同的节点上重新创建。

你很少会像我们在本节介绍中那样独立创建裸 Pod。在大多数情况下，它们是通过部署进行管理的。

Pod 具有有限的生命周期，如果容器内部崩溃或退出，根据重启策略，它们可能不会自动重新创建。为了在集群中保持一定数量的具有特定 Spec 和元数据的 Pod，您需要`ReplicaSet`对象。

# 副本集

Kubernetes 在 Pod 的基础上构建了许多强大的概念，使容器管理变得简单和可预测。最简单的概念是`ReplicaSet`API 对象（ReplicationController 的后继者），其目的是维护一定数量的健康 Pod（副本）以满足特定条件。换句话说，如果您说“我希望在我的集群中运行三个 nginx Pod”，ReplicaSet 会为您完成。如果一个 Pod 被销毁，`ReplicaSet`将自动创建一个新的 Pod 副本以恢复所需状态。

让我们看一个示例 ReplicaSet 清单`nginx-replicaset.yaml`文件，创建三个 nginx Pod 的副本：

```
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: nginx-replicaset-example
spec:
  replicas: 3
  selector:
    matchLabels:
      environment: test
  template:
    metadata:
      labels:
        environment: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.17
        ports:
        - containerPort: 80
```

`ReplicaSet` Spec 有三个主要组件：

+   `replicas`：定义应使用给定的`template`和匹配的`selector`运行的 Pod 副本的数量。为了保持所需的数量，可能会创建或删除 Pod。

+   `selector`：标签选择器，定义了如何识别 ReplicaSet 将获取的 Pod。请注意，这可能会导致`ReplicaSet`获取现有的裸 Pod！

+   `template`：定义 Pod 创建的模板。元数据中使用的标签必须与`selector`正向匹配。

您可以以类似的方式应用`ReplicaSet`清单，就像我们在 Katacoda 游乐场中应用 Pod 一样：

```
kubectl apply -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/02_replicaset-example/nginx-replicaset.yaml
```

您可以使用以下命令观察如何创建三个 Pod 副本：

```
kubectl get pod -o wide -w
```

ReplicaSets 通过将新创建或获取的 Pod 分配给 Pod 的`.metadata.ownerReferences`属性来标记它们自己（如果您感兴趣，可以使用`kubectl get pod <podId> -o yaml`命令进行检查）。这意味着，如果您创建完全相同的 ReplicaSet，具有完全相同的选择器但名称不同，例如`nginx-replicaset-example2`，它们不会*窃取*彼此的 Pod。但是，如果您已经创建了具有匹配标签的裸 Pod，例如`environment: test`，ReplicaSet 将获取它们，甚至可能删除 Pod，如果副本的数量太高！

如果您真的需要在 Kubernetes 集群中创建单个 Pod，最好使用`ReplicaSet`，将`replicas`字段设置为 1，这将充当容器的*监督者*。通过这种方式，您将防止创建没有所有者且仅与原始节点绑定的裸 Pods。

这可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/4a6bf410-9102-4124-9fc9-1ac27d4ef670.png)

通常，您不会自行创建 ReplicaSets，因为它们无法轻松执行滚动更新或回滚到早期版本。为了促进这种情况，Kubernetes 提供了建立在 ReplicaSets 之上的对象：部署和 StatefulSet。让我们先看一下部署。

# 部署

在这一点上，您已经知道了 Pods 和 ReplicaSets 的目的。部署是 Kubernetes 对象，为 Pods 和 ReplicaSets 提供声明性更新。您可以使用它们来声明性地执行以下操作：

+   执行新的 ReplicaSet 的*滚动*。

+   更改 Pod 模板并执行受控滚动。旧的 ReplicaSet 将逐渐缩减，而新的 ReplicaSet 将以相同的速度扩展。

+   执行*回滚*到部署的早期版本。

+   扩展 ReplicaSet 的规模。

部署与 ReplicaSets 和 Pods 的关系可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/553efa0f-59d7-44b6-94eb-5a837aaf5785.png)

您应该**避免**自行管理由部署创建的 ReplicaSets。如果需要对 ReplicaSet 进行任何更改，请在拥有的部署对象上执行更改。

请注意，由部署管理的 ReplicaSets 的*意外*获取 Pods 的问题不存在。原因是 Pods 和 ReplicaSets 使用一个特殊的、自动生成的标签，称为`pod-template-hash`，确保选择的唯一性。

让我们看一个示例部署清单，在`nginx-deployment.yaml`文件中： 

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-example
spec:
  replicas: 3
  selector:
    matchLabels:
      environment: test
  template:
    metadata:
      labels:
        environment: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.17
        ports:
        - containerPort: 80
```

如您所见，基本结构与`ReplicaSet`几乎相同，但在执行声明性更新时，部署的行为有显著的差异。让我们在示例中快速演示一下：

1.  手动创建部署清单文件，或使用`wget`命令下载它：

```
wget https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/03_deployment-example/nginx-deployment.yaml
```

1.  使用以下命令应用部署清单文件：

```
kubectl apply -f nginx-deployment.yaml --record
```

`--record`标志将`kubernetes.io/change-cause`的元数据注释添加到之前命令创建或修改的 API 对象中。此功能允许您轻松跟踪集群中的更改。

1.  等待部署完全完成（您可以使用`kubectl get deployment -w`观察部署中就绪的 Pod 数量）。

1.  现在，在 YAML 清单中的模板中更改 Pod 规范；例如，将`.spec.template.spec.containers[0].image`更改为`nginx:1.**16**`，然后再次应用部署清单。

1.  接着，使用以下命令观察部署的进展：

```
master $ kubectl rollout status deployment nginx-deployment-example
Waiting for deployment "nginx-deployment-example" rollout to finish: 1 out of 3 new replicas have been updated...
Waiting for deployment "nginx-deployment-example" rollout to finish: 2 out of 3 new replicas have been updated...
Waiting for deployment "nginx-deployment-example" rollout to finish: 1 old replicas are pending termination...
deployment "nginx-deployment-example" successfully rolled out
```

部署的规范比 ReplicaSet 丰富得多。您可以查看官方文档以获取更多详细信息：[`kubernetes.io/docs/concepts/workloads/controllers/deployment/#writing-a-deployment-spec`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#writing-a-deployment-spec)。官方文档包含了部署的多个用例，所有这些用例都有详细描述：[`kubernetes.io/docs/concepts/workloads/controllers/deployment/#use-case`](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#use-case)。

正如您所看到的，对部署模板定义的声明性更新导致新 Pod 副本的平稳部署。旧的 ReplicaSet 被缩减，同时，一个新的具有新 Pod 模板的 ReplicaSet 被创建并逐渐扩展。现在，您可以尝试对现有的裸 ReplicaSet 执行相同的操作进行`image`更新，然后您会发现...实际上，什么都没有发生。这是因为 ReplicaSet 只使用 Pod 模板来创建新的 Pod。现有的 Pod 不会因此更改而被更新或删除。

只有当对部署的`.spec.template`进行更改时，才会触发部署。对部署清单的其他更改不会触发部署。

接下来，让我们看一个与部署类似的概念：StatefulSets。

# StatefulSets

部署通常用于部署应用程序的无状态组件。对于有状态的组件，Kubernetes 提供了另一个名为`StatefulSet`的 API 对象。这种操作的原则与部署非常相似-它以声明方式管理 ReplicaSets 和 Pod，并提供平稳的部署和回滚。然而，也有一些关键区别：

+   StatefulSets 确保 Pod 具有确定性（粘性）ID，由`<statefulSetName>-<ordinal>`组成。对于部署，您将具有由`<deploymentName>-<randomHash>`组成的随机 ID。

+   对于 StatefulSets，Pod 将按特定的可预测顺序启动和终止，同时扩展 ReplicaSet。

+   在存储方面，Kubernetes 基于 StatefulSet 对象的`volumeClaimTemplates`为 StatefulSet 中的每个 Pod 创建 PersistentVolumeClaims，并始终将其附加到具有相同 ID 的 Pod。对于部署，如果选择使用`volumeClaimTemplates`，Kubernetes 将创建一个单一的 PersistentVolumeClaim，并将其附加到部署中的所有 Pod。

+   您需要创建一个负责管理 Pod 的确定性网络标识（DNS 名称）的无头 Service 对象。无头 Service 允许我们将所有 Pod IP 作为 DNS A 记录返回到 Service 后面，而不是使用 Service Cluster IP 返回单个 DNS A 记录。

StatefulSets 使用与部署类似的 Spec-您可以通过查看官方文档了解有关 StatefulSets 的更多信息：[`kubernetes.io/docs/concepts/workloads/controllers/statefulset/`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)。

# DaemonSets

DaemonSet 是另一个由控制器支持的对象，类似于 ReplicaSet，但旨在在集群中的每个节点上运行*确切一个*模板化的 Pod 副本（可选匹配选择器）。运行 DaemonSet 的最常见用例如下：

+   管理给定集群节点的监控遥测，例如运行 Prometheus Node Exporter

+   在每个节点上运行日志收集守护程序，例如`fluentd`或`logstash`

+   运行故障排除 Pod，例如 node-problem-detector（[`github.com/kubernetes/node-problem-detector`](https://github.com/kubernetes/node-problem-detector)）

在您的集群中可能会默认运行的 DaemonSets 之一是`kube-proxy`。在由 kubeadm 执行的标准集群部署中，`kube-proxy`作为 DaemonSet 分发到节点。您还可以在 Katacoda playground 上验证这一点：

```
master $ kubectl get daemonset --all-namespaces
NAMESPACE     NAME         DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
kube-system   kube-proxy   2         2         2       2            2           <none>          12m
kube-system   weave-net    2         2         2       2            2           <none>          12m
```

如果您想了解有关 DaemonSets 的更多信息，请参阅官方文档：[`kubernetes.io/docs/concepts/workloads/controllers/daemonset/`](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)。

# 服务

由 ReplicaSets 或 Deployments 创建的 Pods 具有有限的生命周期。在某个时候，您可以期望它们被终止，并且将创建新的 Pod 副本，具有新的 IP 地址。因此，如果您有一个运行 web 服务器 Pods 的 Deployment，需要与作为另一个 Deployment 一部分创建的 Pods 进行通信，例如后端 Pods，那么该怎么办呢？Web 服务器 Pods 不能假设任何关于后端 Pods 的 IP 地址或 DNS 名称的信息，因为它们可能随时间而改变。这个问题通过 Service API 对象得到解决，它为一组 Pods 提供可靠的网络连接。

通常，Services 针对一组 Pods，这是由标签选择器确定的。最常见的情况是通过使用完全相同的标签选择器为现有 Deployment 公开一个 Service。Service 负责提供可靠的 DNS 名称和 IP 地址，以及监视选择器结果并更新相关的 Endpoint 对象，其中包含匹配 Pods 的当前 IP 地址。

对于内部客户端（集群中的 Pods），到 Service 后面的 Pods 的通信是透明的 - 他们使用 Service 的 Cluster IP 或 DNS 名称，流量被路由到其中一个目标 Pods。路由能力由 kube-proxy 提供，但重要的是要知道流量不会通过任何主组件 - kube-proxy 在操作系统内核级别实现路由，并直接将其路由到适当的 Pod 的 IP 地址。在其最简单的形式中，目标 Pod 将被随机选择，但使用 **IP Virtual Server** (**IPVS**) 代理模式，您可以有更复杂的策略，例如最少连接或最短预期延迟。

Services 也可以将 Pods 暴露给外部流量。

Service 的工作原理可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3dcc1fc0-c4d7-4a3c-a0b0-898653ac3af3.png)

让我们为我们的 nginx Deployment 公开一个示例 Service：

1.  如果您在 Katacoda 游乐场上没有正在运行的 Deployment，可以使用以下命令创建一个：

```
kubectl apply -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/03_deployment-example/nginx-deployment.yaml --record
```

1.  使用以下 `kubectl expose` 命令为一个 Deployment 公开 Service：

```
kubectl expose deployment nginx-deployment-example
```

1.  这个命令是*命令式*的，应该避免使用，而应该使用*声明式*的清单。这个命令相当于应用以下 Service 清单：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-deployment-example
spec:
  selector:
    environment: test
  type: ClusterIP
  ports:
  - port: 80
    protocol: TCP
    targetPort: 80
```

1.  现在，在 Service 被公开后，创建一个交互式的 `busybox` Pod，并启动 Bourne shell 进程：

```
kubectl run --generator=run-pod/v1 -i --tty busybox --image=busybox --rm --restart=Never -- sh
```

1.  当容器外壳提示出现时，使用`nginx-deployment-example`服务名称作为 DNS 名称下载由 nginx Pods 提供的默认网页：

```
wget http://nginx-deployment-example && cat index.html
```

您还可以使用**完全限定域名**（**FQDN**），其格式如下：`<serviceName>.<namespaceName>.svc.<clusterDomain>`。在这种情况下，它是`nginx-deployment-example.default.svc.cluster.local`。

接下来，让我们快速看一下在 Kubernetes 中提供存储的对象。

# 与存储相关的对象

在本书中，我们只在需要时涵盖 Kubernetes 存储，因为这是一个广泛且复杂的主题-事实上，存储和管理任何集群的有状态组件通常是最难解决的挑战。如果您对 Kubernetes 中的存储细节感兴趣，请参考官方文档：[`kubernetes.io/docs/concepts/storage/`](https://kubernetes.io/docs/concepts/storage/)。

在 Docker 中，我们使用卷来提供持久性，可以是本地磁盘，也可以是远程/云存储，使用卷插件。 Docker 卷有一个独立于消耗它们的容器的生命周期。在 Kubernetes 中，有一个类似的概念，叫做 Volume，它与 Pod 紧密耦合，并且与 Pod 具有相同的生命周期。在 Kubernetes 中，Volume 的最重要的方面是它们支持多个后备存储提供者（类型）-这是由 Volume 插件和最近的**容器存储接口**（**CSI**）抽象出来的，这是一个用于独立于 Kubernetes 核心开发的外部 Volume 插件的接口。例如，您可以将 Amazon Web Services EBS 卷或 Microsoft Azure Files SMB 共享挂载为 Pod 的 Volume-完整的 Volume 类型列表在这里：[`kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes`](https://kubernetes.io/docs/concepts/storage/volumes/#types-of-volumes)。

Volume 类型之一是**PersistentVolumeClaim**（**PVC**），它旨在将 Pod 与实际存储解耦。PersistentVolumeClaim 是一个 API 对象，用于模拟对特定类型、类或大小存储的请求-可以将其视为说“我想要 10GB 的读/写一次 SSD 存储”。为了满足这样的请求，需要一个**PersistentVolume**（**PV**）API 对象，这是集群自动化过程提供的一部分存储。PersistentVolume 类型也以类似于 Volume 的插件方式实现。

现在，持久卷的整个配置过程可以是动态的 - 它需要创建一个 StorageClass（SC）API 对象，并在定义 PVC 时使用它。创建新的 StorageClass 时，您提供一个具有特定参数的供应商（或插件），并且使用给定 SC 的每个 PVC 将自动创建一个 PV。

这些依赖关系可以在以下图表中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/5c8b7508-c114-417d-a7ef-9954cccadf71.png)

当您想要部署一个挂载了 PersistentVolume 的 Pod 时，事件的顺序将如下：

1.  创建一个带有所需供应商的 StorageClass。

1.  创建一个使用 SC 的 PersistentVolumeClaim。

1.  PersistentVolume 是动态配置的。

1.  在创建 Pod 时，将 PVC 挂载为一个 Volume。

动态配置的 PersistentVolumes 的概念得到了 StatefulSets 的补充。StatefulSets 定义了 volumeClaimTemplates，可以用于动态创建给定 StorageClass 的 PersistentVolumeClaims。通过这样做，整个存储配置过程是完全动态的 - 您只需创建一个 StatefulSet，底层存储对象就由 StatefulSet 控制器管理。您可以在这里找到更多详细信息和示例：[`kubernetes.io/docs/concepts/workloads/controllers/statefulset/#stable-storage`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#stable-storage)。

Kubernetes 中的这种存储架构确保了工作负载的可移植性，这意味着您可以轻松地将部署和 PersistentVolumeClaims 移动到不同的集群。您所需要做的就是提供一个满足 PVC 要求的 StorageClass。无需对 StatefulSet 或 PVC 进行修改。

# Windows 和 Kubernetes 生态系统

最初，Kubernetes 是一个以 Linux 为中心的解决方案 - 这是因为主流的容器化也起源于 Linux 平台。2014 年，微软和 Windows 很快就加入了容器化世界 - 微软宣布将在即将发布的 Windows Server 2016 中支持 Docker Engine。Windows 的 Kubernetes 特别兴趣小组（SIG）于 2016 年 3 月启动，2018 年 1 月，Kubernetes 1.9 为 Windows Server 容器提供了 beta 支持。这种支持最终在 2019 年 4 月 Kubernetes 1.14 发布时成熟到生产级别。

为什么 Windows 对 Kubernetes 的支持如此重要？Windows 在企业工作负载中占据主导地位，而 Kubernetes 作为容器编排的事实标准，对 Windows 的支持带来了将绝大多数企业软件迁移到容器的可能性。开发人员和系统运营商现在可以利用相同的工具和流水线来部署 Windows 和 Linux 工作负载，以类似的方式扩展它们，并有效地监视它们。从商业角度来看，Windows 的容器采用意味着比普通虚拟机更好的运营成本和更好的硬件利用率。

Kubernetes 中的 Windows 容器支持不断发展，越来越多的限制正在被新功能取代。总的来说，有两个关键点需要记住：

+   目前，Windows 机器只能作为节点加入集群。没有可能性，也没有计划在 Windows 上运行主控组件。同时运行 Linux 和 Windows 节点的集群被称为混合或异构。

+   您需要最新稳定版本的 Kubernetes 和最新（或几乎最新）版本的 Windows Server 操作系统才能享受到提供的全面支持。例如，对于 Kubernetes 1.17，您需要 Windows Server 1809（半年频道发布）或 Windows Server 2019（来自长期服务频道的相同发布），尽管最新的 Windows Server 1903 也受支持。

目前，关于 Kubernetes 对 Windows 的支持的文档数量有限，但正在增长。最好的资源如下：

+   官方 Kubernetes 文档：[`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/)。

+   官方 Windows 容器化和 Kubernetes 支持文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows)。

+   Azure Kubernetes Engine Windows 操作指南：[`docs.microsoft.com/en-us/azure/aks/windows-container-cli`](https://docs.microsoft.com/en-us/azure/aks/windows-container-cli)。

+   SIG-Windows 会议记录和录音：[`github.com/kubernetes/community/tree/master/sig-windows`](https://github.com/kubernetes/community/tree/master/sig-windows)。

+   Kubernetes 发布说明和更改日志（查找 SIG-Windows 或与 Windows 相关的内容）：[`github.com/kubernetes/kubernetes/releases`](https://github.com/kubernetes/kubernetes/releases)。

+   Kubernetes 社区论坛上有关 Windows 讨论的链接：[`discuss.kubernetes.io/c/general-discussions/windows`](https://discuss.kubernetes.io/c/general-discussions/windows)。

+   SIG-Windows 的 Slack 频道（如果遇到问题，你可以在这里找到很多帮助）：[`kubernetes.slack.com/messages/sig-windows`](https://kubernetes.slack.com/messages/sig-windows)。

让我们来看一下 Kubernetes 对 Windows 的支持的当前状态以及截至 1.17 版本的限制。

# Windows 上的 Kubernetes 限制

Windows Server 容器支持存在一系列限制，随着每个新版本的 Kubernetes 发布和 Windows Server 的新版本的到来，这些限制不断变化。一般来说，从 Kubernetes API 服务器和 kubelet 的角度来看，在异构（混合）Linux/Windows Kubernetes 集群中，Windows 上的容器的行为几乎与 Linux 容器相同。但是，细节上存在一些关键的差异。首先，让我们来看一些高层次的主要限制：

+   Windows 机器只能作为 worker 节点加入集群。在 Windows 上运行 master 组件的可能性和计划都不存在。

+   Worker 节点的操作系统的最低要求是 Windows Server 1809 或 2019。不能使用 Windows 10 机器作为节点。

+   需要 Docker Enterprise Edition（基本版）18.09 或更高版本作为容器运行时。企业版对 Windows Server 操作系统免费提供。

+   Windows Server 操作系统需要许可证（[`www.microsoft.com/en-us/cloud-platform/windows-server-pricing`](https://www.microsoft.com/en-us/cloud-platform/windows-server-pricing)）。Windows 容器镜像需要遵守微软软件补充许可证（[`docs.microsoft.com/en-us/virtualization/windowscontainers/images-eula`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/images-eula)）。对于开发和评估目的，你也可以使用评估中心：[`www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019`](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019)。

+   运行在 Kubernetes 上的 Windows Server 容器的 Hyper-V 隔离处于实验阶段（alpha），当前的设计将被 containerd 实现的运行时所取代。在那之前，进程隔离容器的兼容性规则适用 - 你必须使用与主机操作系统版本匹配的基本操作系统镜像运行容器。你可以在 第一章 *创建容器* 中找到更多细节。

+   **Windows 上的 Linux 容器**（LCOW）不受支持。

+   对你来说可能最相关的是：为混合 Linux/Windows 集群设置本地 Kubernetes 开发环境非常复杂，目前没有标准解决方案，比如 Minikube 或 Windows 的 Docker Desktop，支持这样的配置。这意味着你需要一个本地的多节点集群或托管的云服务来开发和评估你的场景。

+   Windows 节点的加入过程不像 Linux 节点那样自动化。Kubeadm 很快将支持加入 Windows 节点的过程，但在那之前，你必须手动进行（借助一些 Powershell 脚本的帮助）。

对于容器工作负载/计算，一些限制如下：

+   Windows 节点不支持特权容器。这可能会带来其他一些限制，比如运行必须以特权模式运行的 CSI 插件。

+   Windows 没有内存进程杀手，目前 Pods 无法在内存使用方面受到限制。这对于进程隔离的容器是真实的，但一旦容器化 Hyper-V 隔离在 Kubernetes 上可用，就可以强制执行限制。

+   你需要指定适当的节点选择器，以防止例如 Linux DaemonSets 尝试在 Windows 节点上运行。这在技术上不是一个限制，但你应该意识到你需要控制这些选择器来部署你的应用。

关于网络，一些限制如下：

+   Windows 节点的网络管理更加复杂，Windows 容器网络类似于 VM 网络。

+   Windows 上支持的网络插件（CNI）较少。你需要选择一个适用于集群中的 Linux 和 Windows 节点的解决方案，例如带有 host-gw 后端的 Flannel。

+   L2bridge、l2tunnel 或覆盖网络不支持 IPv6 栈。

+   Windows 的 Kube-proxy 不支持 IPVS 和高级负载均衡策略。

+   从运行 Pod 的节点访问 NodePort 服务会失败。

+   Ingress Controllers 可以在 Windows 上运行，但只有在它们支持 Windows 容器的情况下；例如，*ingress-nginx*。

+   从集群内部使用 ICMP 数据包对外部网络主机进行 ping 不受支持。换句话说，当您使用 ping 测试从 Pod 到外部世界的连接时，不要感到惊讶。您可以使用`curl`或 Powershell `Invoke-WebRequest`代替。

对于存储，一些限制如下：

+   无法扩展已挂载的卷。

+   挂载到 Pod 的 Secrets 是使用节点存储以明文写入的。这可能存在安全风险，您需要采取额外的措施来保护集群。

+   Windows 节点仅支持以下卷类型：

+   FlexVolume（SMB，iSCSI）

+   azureDisk

+   azureFile

+   gcePersistentDisk

+   awsElasticBlockStore（自 1.16 版起）

+   vsphereVolume（自 1.16 版起）

以下限制涉及 Kubernetes 1.17 版。由于支持的功能和当前限制的列表会发生变化，我们建议您查看官方文档以获取更多最新详细信息：[`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#supported-functionality-and-limitations`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#supported-functionality-and-limitations)。

即使没有对 Windows 节点的本地开发集群的支持，我们仍然会对它们进行研究；很可能在不久的将来会支持 Windows 工作负载。

# 从头开始创建自己的开发集群

在本节中，您将学习如何在 Windows 操作系统上设置本地 Kubernetes 集群进行开发和学习。我们将使用 minikube，这是官方推荐的工具集，以及 Docker Desktop 用于 Windows Kubernetes 集群。请注意，当前的本地集群工具*不*支持 Windows 容器，因为它需要使用 Linux 主节点和 Windows Server 节点进行多节点设置。换句话说，这些工具允许您在 Windows 计算机上开发运行在 Linux 容器中的 Kubernetes 应用程序。基本上，它们提供了一个优化的 Linux 虚拟机，用于托管一个节点的 Kubernetes 集群。

如果您希望进行实验，可以使用 Katacoda Kubernetes playground（[`www.katacoda.com/courses/kubernetes/playground`](https://www.katacoda.com/courses/kubernetes/playground)），该平台用于演示本章中的 Kubernetes 对象，或者使用由 Docker, Inc.提供的 Play with Kubernetes（[`labs.play-with-k8s.com/`](https://labs.play-with-k8s.com/)）。

# minikube

**Minikube**可用于 Windows、Linux 和 macOS，并旨在为 Kubernetes 的本地开发提供稳定的环境。在 Windows 上的关键要求是需要安装 VM 虚拟化程序。对于 Docker Desktop for Windows 和 Windows 容器，我们已经使用了 Hyper-V，因此这将是我们的选择。如果您尚未启用 Hyper-V，请按照第一章中安装 Docker Desktop for Windows 的说明，*创建容器*，或者按照官方文档：[`docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v`](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v)。

要安装 minikube，您需要执行以下步骤：

1.  如果您没有 Hyper-V 虚拟外部网络交换机，请通过从开始菜单打开 Hyper-V 管理器并从操作选项卡中单击 Virtual Switch Manager...来创建一个。

1.  选择 External 并单击 Create Virtual Switch。

1.  使用 External Switch 作为虚拟交换机的名称，并选择要用于连接到互联网的网络适配器；例如，您的 Wi-Fi 适配器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/862cdc2b-1458-4961-980c-26cb2ed45ea9.png)

1.  单击确定以接受更改。

1.  使用*Chocolatey*软件包管理器安装 kubectl（Kubernetes CLI）。在 Powershell 窗口中以管理员身份执行以下命令：

```
choco install kubernetes-cli
```

1.  使用 Chocolatey 安装 minikube，也作为管理员：

```
choco install minikube
```

1.  将 Hyper-V 设置为 minikube 的默认虚拟化驱动程序：

```
minikube config set vm-driver hyperv
```

1.  将您的虚拟外部交换机默认设置为 minikube：

```
minikube config set hyperv-virtual-switch "External Switch"
```

1.  启动 minikube。这可能需要几分钟，因为需要设置 VM 并初始化 Kubernetes 节点：

```
minikube start
```

如果您需要在实际的 minikube VM 上调试问题（例如连接问题），您可以使用`minikube ssh`命令或直接从 Hyper-V 管理器连接到终端。登录用户名是`docker`，密码是`tcuser`。

1.  通过运行`kubectl`命令来验证安装是否成功，该命令将配置为连接到 minikube 集群。你应该看到`kube-system`命名空间中运行着各种 Pod：

```
kubectl get pods --all-namespaces
```

1.  你可以使用本章中使用的任何示例 Kubernetes 对象，或者创建你自己的对象：

```
kubectl apply -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/03_deployment-example/nginx-deployment.yaml --record
```

1.  最终，你可以尝试在 web 浏览器中使用 Kubernetes 仪表板。要初始化并打开仪表板，运行以下命令：

```
minikube dashboard
```

现在，我们将看另一种使用 Windows Docker 桌面版进行本地开发的方法。

# Windows 下的 Docker 桌面版

对于 Windows 用户来说，使用 Docker 桌面版和其内置的本地 Kubernetes 集群是最简单的方法。如果你在需要代理连接到互联网的环境中工作，建议使用这种方法，因为与 minikube 相比，设置是无缝的且更容易。

如果你还没有安装 Windows Docker 桌面版，你应该按照第一章 *创建容器*中的说明进行操作。要启用本地 Kubernetes 集群，你需要按照以下步骤进行：

1.  确保你正在 Linux 容器模式下运行。DockerDesktopVM 将负责托管 Kubernetes 集群。为此，打开 Windows Docker 桌面版的托盘图标，然后点击切换到 Linux 容器....

1.  操作完成后，从托盘图标中打开设置。

1.  打开 Kubernetes 部分。

1.  勾选启用 Kubernetes 复选框，然后点击应用。

1.  设置过程将需要几分钟来完成。

1.  如果你已经设置了 minikube，你需要**切换上下文**到 kubectl。从命令行中运行以下命令：

```
kubectl config use-context docker-desktop
```

1.  或者，你也可以从 Windows 托盘中切换 Docker 桌面版的上下文：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/68b696e6-7b41-48ac-84a1-1a88a2695862.png)

你将在第六章 *与 Kubernetes 集群交互*中了解更多有关 kubectl 配置及其上下文的信息。

1.  现在，你可以开始使用本地 Kubernetes 集群进行开发。让我们部署 Kubernetes 仪表板：

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/deploy/recommended/kubernetes-dashboard.yaml
```

1.  等待所有的 Pod 都处于运行状态：

```
 kubectl get pods --all-namespaces --watch
```

1.  获取默认服务账户令牌。从命令输出中复制`token:`的值：

```
kubectl describe secret -n kube-system default
```

1.  为集群启用 kubectl 代理。在访问仪表板时，这个过程应该在运行中：

```
kubectl proxy
```

1.  导航到[`localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#!/overview?namespace=kube-system`](http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#!/overview?namespace=kube-system)。

1.  选择令牌，粘贴您的默认令牌，然后登录。

使用 Windows 容器支持设置本地开发 Kubernetes 集群的替代策略涉及在本地机器上使用自动设置的 VM，例如 vagrant。您可以探索 GitHub 上使用此方法的一些小项目，但您应该期望它们已过时且不再受支持。

在下一节中，我们将简要概述我们可以为 Kubernetes 集群执行的生产集群部署策略，特别是带有 Windows 节点的情况。

# 生产集群部署策略

生产级别集群的部署甚至带有 Windows 节点的集群的开发需要非常不同的方法。有三个重要问题决定了您部署 Kubernetes 集群的选项：

+   您是在云中部署集群还是使用本地裸机或虚拟机？

+   您需要**高可用性**（**HA**）设置吗？

+   您需要 Windows 容器支持吗？

让我们总结目前最流行的部署工具。

# kubeadm

第一个是**kubeadm** ([`github.com/kubernetes/kubeadm`](https://github.com/kubernetes/kubeadm))，这是一个命令行工具，专注于以用户友好的方式启动并运行最小可行的安全集群。kubeadm 的一个方面是，它是一个仅限于给定机器和 Kubernetes API 通信的工具，因此，一般来说，它旨在成为管理整个集群的其他自动化工具的构建块。其原则很简单：在主节点上使用`kubeadm init`命令，在工作节点上使用`kubeadm join`。kubeadm 的特性可以总结如下：

+   您可以在本地环境和云环境中部署集群。

+   高可用集群得到支持，但截至 1.17 版本，此功能仍处于测试阶段。

+   目前计划在版本 1.18 上提供官方的 Windows 支持。当前版本的 kubeadm 是启动混合 Kubernetes 集群的良好基础。首先，您可以引导主节点和（可选）Linux 工作节点，然后继续使用微软提供的用于加入 Windows 节点的脚本（[`github.com/microsoft/SDN`](https://github.com/microsoft/SDN)）或在 sig-windows-tools GitHub 存储库中预览脚本的版本（[`github.com/kubernetes-sigs/sig-windows-tools`](https://github.com/kubernetes-sigs/sig-windows-tools)）。我们将在第七章《部署混合本地 Kubernetes 集群》中使用这种方法。

如果您计划自动化 Kubernetes 集群的部署方式，例如使用 Ansible，kubeadm 是一个很好的起点，因为它提供了很大程度的灵活性和易配置性。

# kops

下一个选项是使用**Kubernetes Operations**（**kops**，[`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)），它在内部使用 kubeadm。Kops 旨在管理云环境中的整个 Kubernetes 集群-您可以将其视为*用于集群的 kubectl*。其主要特点如下：

+   在 Amazon Web Services（官方支持）、Google Compute Engine 和 OpenStack（它们都处于测试阶段）上部署集群。除非您正在运行自己的 OpenStack 部署，否则不支持本地部署。VMware vSphere 支持处于 alpha 阶段。

+   对 HA 集群的生产级支持。

+   不支持 Windows 节点。

在本书中，我们不会关注 kops，因为它不支持 Windows。

# kubespray

**Kubespray**（[`github.com/kubernetes-sigs/kubespray`](https://github.com/kubernetes-sigs/kubespray)）是一组可配置的 Ansible playbooks，运行 kubeadm 以引导完全功能的、可用于生产的 Kubernetes 集群。kubespray 和 kops 的主要区别在于，kops 与云提供商更紧密集成，而 kubespray 旨在支持多个平台，包括裸金属部署。其特点可以总结如下：

+   支持为多个云提供商和裸金属机器安装 Kubernetes 集群。

+   对 HA 集群的生产级支持。

+   目前不支持 Windows 节点，但随着 kubeadm 对 Windows 节点的支持，kubespray 是最佳候选来扩展其支持。

由于 kubespray 目前不支持 Windows 节点，我们在本书中不会重点介绍它。

# AKS 引擎

**AKS 引擎**（[`github.com/Azure/aks-engine`](https://github.com/Azure/aks-engine)）是一个官方的开源工具，用于在 Azure 上提供自管理的 Kubernetes 集群。它旨在生成**Azure 资源管理器**（**ARM**）模板，引导 Azure 虚拟机并设置集群。

不应将 AKS 引擎与**Azure Kubernetes 服务**（**AKS**）混淆，后者是 Azure 提供的完全托管的 Kubernetes 集群服务。AKS 引擎在内部由 AKS 使用。

其特点可以总结如下：

+   仅适用于 Azure；不支持其他平台。

+   高可用性是通过 Azure VMSS 实现的（[`kubernetes.io/blog/2018/10/08/support-for-azure-vmss-cluster-autoscaler-and-user-assigned-identity/`](https://kubernetes.io/blog/2018/10/08/support-for-azure-vmss-cluster-autoscaler-and-user-assigned-identity/)）。

+   良好的 Windows 支持-官方测试套件在 AKS 引擎配置上得到验证。我们将在第八章中使用这种方法，*部署混合 Azure Kubernetes 引擎服务集群*。

但是，请注意，AKS 引擎提供了一些实验性功能，这些功能目前作为托管的 AKS 服务还不可用。这意味着，根据您使用的 AKS 引擎功能，这种方法可能并不总是适合运行生产工作负载。

# 托管的 Kubernetes 提供商

随着 Kubernetes 的不断普及，不同的云提供商和专门从事 Kubernetes 的公司提供了多个**完全托管**的 Kubernetes 服务。您可以在[`kubernetes.io/docs/setup/#production-environment`](https://kubernetes.io/docs/setup/#production-environment)找到一个长长的但不完整的 Kubernetes 提供商列表（不仅仅是托管）。在本节中，我们将总结一级云服务提供商的托管服务以及它们在 Windows 支持方面提供的服务，即以下内容：

+   微软 Azure：**Azure Kubernetes 服务**（**AKS**）

+   谷歌云平台：**谷歌 Kubernetes 引擎**（**GKE**）

+   亚马逊网络服务：**弹性 Kubernetes 服务**（**EKS**）

对于托管的 Kubernetes 提供商，关键原则是您不负责管理控制平面、数据平面和基础集群基础设施。从您的角度来看，您会得到一个已准备好的集群（可能会根据需求进行扩展），具有高可用性和适当的 SLA。您只需要部署您的工作负载！另一种较少托管的方法是**即插即用的云解决方案**，在这种情况下，您自己管理控制平面、数据平面和升级，但基础设施由云提供商管理。这种解决方案的一个很好的例子是在 Azure VM 上运行的**AKS Engine**。

所有这些云提供商在其托管的 Kubernetes 提供中都支持 Windows 容器，并且对于所有这些提供商，此功能目前处于预览阶段。您可以期待对该功能的有限支持和有限的向后兼容性。

2019 年 5 月，Azure Kubernetes 服务引入了对 Windows 节点的支持，并且是 Windows 容器的最成熟的提供者，其文档中有很好的支持（[`docs.microsoft.com/en-us/azure/aks/windows-container-cli`](https://docs.microsoft.com/en-us/azure/aks/windows-container-cli)）。这个提供是在 AKS Engine 内部构建的，因此您可以期待类似的功能也可以在那里使用。您可以通过访问[`github.com/Azure/AKS/projects/1`](https://github.com/Azure/AKS/projects/1)来监视即将到来的 Windows 支持功能的官方路线图。

Google Kubernetes 引擎在 2019 年 5 月宣布在其 Rapid 发布通道中支持 Windows 容器。目前，关于这个 alpha 功能的信息有限-对于 Google 云平台来说，部署 Kubernetes 用于 Windows 直接到 Google Compute Engine VMs 是最常见和经过验证的用例。

2019 年 3 月，亚马逊弹性 Kubernetes 服务宣布支持 Windows 容器的预览。您可以在官方文档中找到有关 EKS 中 Windows 容器支持的更多详细信息：[`docs.aws.amazon.com/eks/latest/userguide/windows-support.html`](https://docs.aws.amazon.com/eks/latest/userguide/windows-support.html)

# 创建带有 Windows 节点的 AKS 集群

要完成这个演练，您需要一个 Azure 账户和在您的机器上安装 Azure CLI。您可以在第二章中找到更多详细信息，即*在容器中管理状态*。

以下步骤也可以在本书的官方 GitHub 存储库中作为 Powershell 脚本使用：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter04/05_CreateAKSWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter04/05_CreateAKSWithWindowsNodes.ps1)。

让我们开始启用 AKS 的预览功能：

1.  使用 Azure CLI 从 Powershell 安装`aks-preview`扩展：

```
az extension add --name aks-preview
```

1.  将`aks-preview`扩展更新到最新可用版本：

```
az  extension  update --name aks-preview
```

1.  为您的订阅注册`WindowsPreview`功能标志，以启用多个节点池。Windows 节点需要单独的节点池。请注意，此操作应在测试或开发订阅上执行，因为在启用此标志后创建的任何集群都将使用此功能：

```
az  feature  register `
   --name WindowsPreview `
   --namespace Microsoft.ContainerService
```

1.  此操作将需要几分钟时间。您必须等到功能的“状态”为“已注册”才能继续。要检查当前的“状态”，运行以下命令：

```
az feature list `
 -o json `
 --query "[?contains(name, 'Microsoft.ContainerService/WindowsPreview')].{Name:name,State:properties.state}"
```

1.  当功能注册后，执行以下命令来传播更改：

```
az  provider  register `
 --namespace Microsoft.ContainerService
```

1.  现在，等待提供程序完成注册并将状态切换为“已注册”。您可以使用以下命令监视状态：

```
 az provider show -n Microsoft.ContainerService `
 | ConvertFrom-Json `
 | Select -ExpandProperty registrationState
```

AKS 的实际成本取决于托管集群的 Azure VM 的数量和大小。您可以在这里找到运行 AKS 集群的预测成本：[`azure.microsoft.com/en-in/pricing/details/kubernetes-service/`](https://azure.microsoft.com/en-in/pricing/details/kubernetes-service/)。建议如果您在完成本教程后不打算使用集群，则删除集群以避免额外费用。

启用预览功能后，您可以继续创建具有 Windows 节点的实际 AKS 集群。Kubernetes 的可用版本取决于您创建集群的位置。在本教程中，我们建议使用`westeurope` Azure 位置。按照以下步骤创建集群：

1.  为您的 AKS 集群创建一个专用资源组，例如`aks-windows-resource-group`：

```
az  group  create `
   --name aks-windows-resource-group `
   --location westeurope
```

1.  获取给定位置的可用 Kubernetes 版本列表：

```
 az aks get-versions `
 --location westeurope
```

1.  选择所需的版本。建议使用最新版本；例如，`1.15.3`。

1.  使用所选版本创建一个`aks-windows-cluster` AKS 实例，并提供所需的 Windows 用户名和密码（选择一个安全的！）。以下命令将创建一个运行在 VMSS 高可用性模式下的 Linux 节点的两节点池：

```
az aks create `
 --resource-group aks-windows-resource-group `
 --name aks-windows-cluster `
 --node-count 2 `
 --enable-addons monitoring `
 --kubernetes-version 1.15.3 `
 --generate-ssh-keys `
 --windows-admin-username azureuser `
 --windows-admin-password "S3cur3P@ssw0rd" `
 --enable-vmss `
 --network-plugin azure
```

1.  几分钟后，当 AKS 集群准备就绪时，将一个名为`w1pool`的 Windows 节点池添加到集群 - 此操作将需要几分钟。Windows 节点池名称的字符限制为六个：

```
az aks nodepool add `
 --resource-group aks-windows-resource-group `
 --cluster-name aks-windows-cluster `
 --os-type Windows `
 --name w1pool `
 --node-count 1 `
 --kubernetes-version 1.15.3
```

1.  如果您尚未安装`kubectl`，请使用 Azure CLI 进行安装：

```
az aks install-cli
```

1.  获取`kubectl`的集群凭据。以下命令将为`kubectl`添加一个新的上下文并切换到它：

```
az aks get-credentials `
   --resource-group aks-windows-resource-group `
   --name aks-windows-cluster
```

1.  验证集群是否已成功部署！运行任何`kubectl`命令：

```
kubectl get nodes kubectl get pods --all-namespaces
```

1.  现在，您可以开始使用具有 Windows 节点的第一个 Kubernetes 集群进行编程！例如，创建一个示例部署，其中在 Windows 容器中运行官方 ASP.NET 示例的三个副本，这些副本位于 LoadBalancer 类型的服务后面：

```
kubectl apply -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter04/06_windows-example/windows-example.yaml --record
```

1.  容器创建过程可能需要长达 10 分钟，因为需要首先拉取 Windows 基础映像。等待外部负载均衡器 IP 可用：

```
PS C:\> kubectl get service
NAME              TYPE           CLUSTER-IP    EXTERNAL-IP     PORT(S)        AGE
kubernetes        ClusterIP      10.0.0.1      <none>          443/TCP        32m
windows-example   LoadBalancer   10.0.179.85   13.94.168.209   80:30433/TCP   12m
```

1.  在 Web 浏览器中导航到地址以检查您的应用程序是否正常运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f891c6ea-8446-4bd7-b801-4f7362947187.png)

要删除 AKS 集群，请使用`az group delete --name aks-windows-resource-group --yes --no-wait`命令。

恭喜！您已成功创建了您的第一个完全托管的具有 Windows 节点的 Kubernetes 集群。在接下来的几章中，我们将探讨使用不同方法创建支持 Windows 容器的 Kubernetes 集群。

# 总结

在本章中，您了解了 Kubernetes 背后的关键理论 - 其高级架构和最常用的 Kubernetes API 对象。除此之外，我们总结了 Kubernetes 目前如何适应 Windows 生态系统以及 Windows 支持中的当前限制。接下来，您将学习如何使用推荐工具（如 minikube 和 Docker Desktop for Windows）为 Linux 容器设置自己的 Kubernetes 开发环境，以及可用的可能的生产集群部署策略。最后，我们回顾了支持 Windows 容器的托管 Kubernetes 产品，并成功部署了带有 Windows 节点池的 Azure Kubernetes Service 集群！

下一章将为您带来更多关于 Kubernetes 架构的知识-一般情况下以及在 Windows 生态系统中的 Kubernetes 网络。这将是最后一章，重点关注 Kubernetes 的理论和工作原理。

# 问题

1.  Kubernetes 中控制平面和数据平面之间有什么区别？

1.  声明模型和期望状态的概念是如何工作的，它的好处是什么？

1.  容器和 Pod 之间有什么区别？

1.  部署 API 对象的目的是什么？

1.  Kubernetes 在 Windows 上的主要限制是什么？

1.  minikube 是什么，何时应该使用它？

1.  AKS 和 AKS Engine 之间有什么区别？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 概念的更多信息，请参考以下 PacktPub 图书：

+   *完整的 Kubernetes 指南* ([`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide))

+   *开始使用 Kubernetes-第三版* ([`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition))

+   *面向开发人员的 Kubernetes* ([`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers))

+   您还可以参考优秀的官方 Kubernetes 文档([`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/))，这始终是关于 Kubernetes 的最新知识来源。对于特定于 Windows 的场景，建议参考官方的 Microsoft 虚拟化文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows)。


# 第五章：Kubernetes 网络

对于容器编排，有两个主要挑战需要解决：管理容器主机（节点）和管理容器之间的网络。如果将容器主机集群限制为仅一个节点，网络将会相当简单——对于 Linux 上的 Docker，您将使用默认的桥接网络驱动程序，它创建一个私有网络（内部到主机），允许容器相互通信。对容器的外部访问需要暴露和映射容器端口作为主机端口。但是，现在如果考虑多节点集群，这个解决方案就不太适用——您必须使用 NAT 并跟踪使用了哪些主机端口，而且运行在容器中的应用程序还必须了解网络拓扑。

幸运的是，Kubernetes 通过提供一个具有特定基本要求的网络模型来解决这一挑战——符合规范的任何网络解决方案都可以作为 Kubernetes 中的网络模型实现。该模型的目标是提供透明的容器间通信和对容器的外部访问，而无需容器化应用程序了解底层网络挑战。在本章中，我们将解释 Kubernetes 网络模型的假设以及如何在混合 Linux/Windows 集群中解决 Kubernetes 网络问题。

在本章中，我们将涵盖以下主题：

+   Kubernetes 网络原则

+   Kubernetes CNI 网络插件

+   Kubernetes 中的 Windows 服务器网络

+   选择 Kubernetes 网络模式

# 技术要求

对于本章，您将需要以下内容：

+   安装了 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）

+   安装了 Docker Desktop for Windows 2.0.0.3 或更高版本

+   如果您想要使用上一章中的 AKS 集群，则需要安装 Azure CLI

Docker Desktop for Windows 的安装和系统要求在第一章中有介绍，创建容器。

对于 Azure CLI，您可以在第二章中找到详细的安装说明，管理容器中的状态。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05)

# Kubernetes 网络原则

作为容器编排器，Kubernetes 提供了一个网络模型，其中包含任何给定网络解决方案必须满足的一组要求。最重要的要求如下：

+   在节点上运行的 Pod 必须能够与所有节点上的所有 Pod 进行通信（包括 Pod 所在的节点），而无需 NAT 和显式端口映射。

+   在节点上运行的所有 Kubernetes 组件，例如 kubelet 或系统守护程序/服务，必须能够与该节点上的所有 Pod 进行通信。

这些要求强制执行了一个平面、无 NAT 的网络模型，这是使 Kubernetes 如此强大、可扩展和易于使用的核心概念之一。从这个角度来看，Pod 类似于在 Hyper-V 集群中运行的 VMs——每个 Pod 都分配了自己的 IP 地址（IP-per-Pod 模型），Pod 内的容器共享相同的网络命名空间（就像 VM 上的进程），这意味着它们共享相同的本地主机并且需要知道端口分配。

简而言之，Kubernetes 中的网络有以下挑战需要克服：

+   **容器内部的 Pod 间通信**：由标准的本地主机通信处理。

+   **Pod 间通信**：由底层网络实现处理。

+   **Pod 到 Service 和外部到 Service 的通信**：由 Service API 对象处理，通信取决于底层网络实现。我们将在本节后面介绍这一点。

+   **当创建新的 Pod 时，kubelet 自动设置网络**：由**容器网络接口**（**CNI**）插件处理。我们将在下一节中介绍这一点。

Kubernetes 网络模型有许多实现，从简单的 L2 网络（例如，带有 host-gw 后端的 Flannel）到复杂的高性能**软件定义网络**（**SDN**）解决方案（例如，Big Cloud Fabric）。您可以在官方文档中找到不同实现的网络模型的列表：[`kubernetes.io/docs/concepts/cluster-administration/networking/#how-to-implement-the-kubernetes-networking-model`](https://kubernetes.io/docs/concepts/cluster-administration/networking/#how-to-implement-the-kubernetes-networking-model)。

本书中，我们将只关注从 Windows 角度相关的实现：

+   L2 网络

+   覆盖网络

让我们从最简单的网络实现 L2 网络开始。

# L2 网络

**第二层**（**L2**）指的是数据链路层，是网络协议设计的七层 OSI 参考模型中的第二层。该层用于在同一局域网中的节点之间传输数据（因此，考虑在 MAC 地址和交换机端口上操作，而不是 IP 地址，IP 地址属于 L3）。对于 Kubernetes，具有在每个 Kubernetes 节点上设置路由表的 L2 网络是满足 Kubernetes 网络模型实现要求的最简单的网络类型。一个很好的例子是带有 host-gw 后端的 Flannel。在高层次上，Flannel（host-gw）以以下方式为 Pod 提供网络：

1.  每个节点都运行一个**flanneld**（或者 Windows 上的**flanneld.exe**）代理，负责从一个称为**Pod CIDR**（**无类别域间路由**）的较大的预配置地址空间中分配子网租约。在下图中，Pod CIDR 是`10.244.0.0/16`，而节点 1 租用了子网`10.244.1.0/24`，节点 2 租用了子网`10.244.2.0/24`。

1.  在大多数情况下，Flannel 代理在集群中进行 Pod 网络安装时部署为**DaemonSet**。可以在这里找到一个示例 DaemonSet 定义：[`github.com/coreos/flannel/blob/master/Documentation/kube-flannel.yml`](https://github.com/coreos/flannel/blob/master/Documentation/kube-flannel.yml)。

1.  Flannel 使用 Kubernetes API 或**etcd**直接存储网络信息和租约数据，具体取决于其配置。

1.  当新节点加入集群时，Flannel 为给定节点上的所有 Pod 创建一个`cbr0`桥接口。节点上的操作系统中的路由表会被更新，其中包含集群中每个节点的一个条目。例如，在下图中的 Node 2 中，路由表有两个条目，分别通过`10.0.0.2`网关（到 Node 1 的节点间通信）路由到`10.244.1.0/24`，以及通过本地`cbr0`接口（Node 1 上 Pod 之间的本地通信）路由到`10.244.2.0/24`。

1.  当创建一个新的 Pod 时，会创建一个新的**veth**设备对。在 Pod 网络命名空间中创建一个`eth0`设备，以及在主机（根）命名空间中对端的`vethX`设备。虚拟以太网设备用作网络命名空间之间的隧道。

1.  为了触发上述操作，kubelet 使用了由 Flannel CNI 插件实现的 CNI：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/fb8dbafa-cca9-4a1c-a8ed-0c7cae1ac530.png)

Flannel 执行的所有操作都可以通过命令行手动执行，但是，Flannel 的目标当然是自动化新节点注册和新 Pod 网络创建的过程，对 Kubernetes 用户来说是透明的。

现在让我们快速分析一下当 Pod 1 中的容器`10.244.1.2`（位于 Node 1 上）想要向 Pod 4 中的容器`10.244.2.3`（位于 Node 2 上）发送 TCP 数据包时会发生什么：

1.  Pod 1 的出站数据包将被发送到`cbr0`桥接口，因为它被设置为`eth0` Pod 接口的默认网关。

1.  由于 Node 1 上的`10.244.2.0/24 → 10.0.0.3`路由表条目，数据包被转发到`10.0.0.3`网关。

1.  数据包通过物理 L2 网络交换机，并在 Node 2 的`eth0`接口接收。

1.  Node 2 的路由表包含一个条目，将流量转发到本地的`cbr0`桥接口的`10.244.2.0/24` CIDR。

1.  数据包被 Pod 2 接收。

请注意，上述示例使用了 Linux 网络接口命名和术语。这个模型的 Windows 实现通常是相同的，但在操作系统级别的原语上有所不同。

使用带有路由表的 L2 网络是高效且简单的设置；然而，它也有一些缺点，特别是在集群规模扩大时：

+   需要节点的 L2 邻接性。换句话说，所有节点必须在同一个本地区域网络中，中间没有 L3 路由器。

+   在所有节点之间同步路由表。当新节点加入时，所有节点都需要更新它们的路由表。

+   由于 L2 网络交换机在转发表中设置新的 MAC 地址的方式，可能会出现可能的故障和延迟，特别是对于短暂存在的容器。

带有 host-gw 后端的 Flannel 对 Windows 有稳定的支持。

一般来说，建议使用覆盖网络，这允许在现有的底层 L3 网络上创建一个虚拟的 L2 网络。

# 覆盖网络

作为一个一般概念，覆盖网络使用封装来创建一个新的、隧道化的虚拟网络，位于现有的 L2/L3 网络之上，称为底层网络。这个网络是在不对底层网络的实际物理网络基础设施进行任何更改的情况下创建的。覆盖网络中的网络服务通过封装与底层基础设施分离，封装是一种使用另一种类型的数据包来封装一种类型的数据包的过程。进入隧道时封装的数据包然后在隧道的另一端进行解封装。

覆盖网络是一个广泛的概念，有许多实现。在 Kubernetes 中，其中一个常用的实现是使用**虚拟可扩展局域网（VXLAN）**协议通过 UDP 数据包进行 L2 以太网帧的隧道传输。重要的是，这种类型的覆盖网络对 Linux 和 Windows 节点都适用。如果你有一个带有 VXLAN 后端的 Flannel 网络，Pods 的网络是以以下方式提供的：

1.  类似于 host-gw 后端，每个节点上都部署了一个 flanneld 代理作为 DaemonSet。

1.  当一个新的节点加入集群时，Flannel 为给定节点上的所有 Pods 创建一个`cbr0`桥接口和一个额外的`flannel.<vni>`VXLAN 设备（一个 VXLAN 隧道端点，或者简称为 VTEP；VNI 代表 VXLAN 网络标识符，在这个例子中是`1`）。这个设备负责流量的封装。IP 路由表只对新节点进行更新。发送到在同一节点上运行的 Pod 的流量被转发到`cbr0`接口，而所有剩余的发送到 Pod CIDR 的流量被转发到 VTEP 设备。例如，在下图中的节点 2，路由表有两个条目，将通信路由到`10.244.0.0/16`通过`flannel.1` VTEP 设备（覆盖网络中的节点间通信），并且将通信路由到`10.244.2.0/24`通过本地的`cbr0`接口（节点 1 上的 Pod 之间的本地通信）。

1.  当创建一个新的 Pod 时，会创建一个新的 veth 设备对，类似于 host-gw 后端的情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d1e6c841-ad79-4dd0-81fb-3bef9654e9c9.png)

现在让我们快速分析当 Pod 1 中的容器`10.244.1.2`（在节点 1 上）想要向 Pod 4 中的容器`10.244.2.3`（在节点 2 上）发送 TCP 数据包时会发生什么：

1.  Pod 1 的出站数据包将被发送到`cbr0`桥接口，因为它被设置为`eth0` Pod 接口的默认网关。

1.  由于节点 1 上的`10.244.0.0/16 → flannel.1`路由表条目，数据包被转发到`flannel.1` VTEP 设备。

1.  `flannel.1`使用`10.244.0.0/16`叠加网络中 Pod 4 的 MAC 地址作为内部数据包的目的地址。这个地址是由**flanneld**代理在**转发数据库**（**FDB**）中填充的。

1.  `flannel.1`使用 FDB 确定节点 2 的目标 VTEP 设备的 IP 地址，并使用`10.0.0.3`作为外部封装数据包的目的地址。

1.  数据包通过物理 L2/L3 网络传输，并被节点 2 接收。数据包由`flannel.1` VTEP 设备进行解封装。

1.  节点 2 的路由表包含一个条目，将流量转发到本地的`cbr0`桥接口的`10.244.2.0/24` CIDR。

1.  Pod 2 接收到数据包。

对于 Windows，Flannel 与 Overlay 后端目前仍处于 alpha 功能阶段。

使用 VXLAN 后端而不是 host-gw 后端的 Flannel 具有几个优势：

+   节点之间不需要 L2 邻接。

+   L2 叠加网络不容易受到生成树故障的影响，这种情况可能发生在跨多个逻辑交换机的 L2 域的情况下。

本节中描述的解决方案类似于 Docker 在**swarm 模式**下运行。您可以在官方文档中了解有关 swarm 模式的 Overlay 网络的更多信息：[`docs.docker.com/network/overlay/.`](https://docs.docker.com/network/overlay/.)

前两种网络解决方案是混合 Linux/Windows 集群中最常用的解决方案，特别是在本地运行时。对于其他情况，也可以使用**Open Virtual Network**（**OVN**）和**L2 隧道**进行 Azure 特定实现。

# 其他解决方案

就 Kubernetes 支持的 Windows 网络解决方案而言，还有两种额外的实现可以使用：

+   例如，**Open Virtual Network**（**OVN**）作为 OpenStack 部署的一部分

+   在 Azure 部署中使用**L2 隧道**

OVN 是一个用于实现 SDN 的网络虚拟化平台，它将物理网络拓扑与逻辑网络拓扑解耦。使用 OVN，用户可以定义由逻辑交换机和路由器组成的网络拓扑。Kubernetes 支持使用专用 CNI 插件**ovn-kubernetes**（[`github.com/ovn-org/ovn-kubernetes`](https://github.com/ovn-org/ovn-kubernetes)）进行 OVN 集成。

对于特定于 Azure 的场景，可以使用**Azure-CNI**插件，该插件依赖于**L2Tunnel** Docker 网络驱动程序，直接利用 Microsoft Cloud Stack 功能。简而言之，Pod 连接到现有的虚拟网络资源和配置，并且所有 Pod 数据包直接路由到虚拟化主机，以应用 Azure SDN 策略。Pod 在 Azure 提供的虚拟网络中获得完全的连通性，这意味着每个 Pod 都可以直接从集群外部访问。您可以在官方 AKS 文档中找到有关此解决方案的更多详细信息：[`docs.microsoft.com/bs-latn-ba/azure/aks/configure-azure-cni`](https://docs.microsoft.com/bs-latn-ba/azure/aks/configure-azure-cni)。

# 服务

在上一章中，我们介绍了服务作为 API 对象，并解释了它们如何与部署一起使用。简单回顾一下，服务 API 对象基于标签选择器，使一组 Pod 可以进行网络访问。在 Kubernetes 网络方面，服务是建立在标准网络模型之上的概念，旨在实现以下目标：

+   使用**虚拟 IP**（**VIP**）可靠地与一组 Pod 进行通信。客户端 Pod 不需要知道单个 Pod 的当前 IP 地址，因为这些地址随时间可能会发生变化。外部客户端也不需要知道 Pod 的当前 IP 地址。

+   将网络流量（内部和外部）负载均衡到一组 Pod。

+   在集群中启用服务发现。这需要在集群中运行 DNS 服务附加组件。

Kubernetes 中有四种可用的服务类型，可以在服务对象规范中指定。

+   ClusterIP

+   NodePort

+   LoadBalancer

+   ExternalName

我们将分别讨论每种类型，但首先让我们看看在部署和 Pod 的上下文中**服务**是什么样子的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/81db847a-1743-436c-a593-2c40163e4895.png)

上述图表显示了 ClusterIP 类型的最简单的内部 Service 是如何公开管理三个带有`environment: test`标签的 Pod 的现有部署。具有相同标签选择器`environment: test`的 ClusterIP Service 负责监视标签选择器评估的结果，并使用当前的存活和准备好的 Pod IP 更新**endpoint** API 对象。同时，kube-proxy 观察 Service 和 endpoint 对象，以在 Linux 节点上创建 iptables 规则或在 Windows 节点上创建 HNS 策略，用于实现具有 Service 规范中指定的 ClusterIP 值的虚拟 IP 地址。最后，当客户端 Pod 向虚拟 IP 发送请求时，它将使用 kube-proxy 设置的规则/策略转发到部署中的一个 Pod。正如您所看到的，kube-proxy 是实现服务的中心组件，实际上它用于所有服务类型，除了 ExternalName。

# ClusterIP

Kubernetes 中默认的 Service 类型是 ClusterIP，它使用内部 VIP 公开服务。这意味着 Service 只能在集群内部访问。假设您正在运行以下`nginx`部署：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-example
spec:
  replicas: 3
  selector:
    matchLabels:
      environment: test
  template:
    metadata:
      labels:
        environment: test
    spec:
      containers:
      - name: nginx
        image: nginx:1.17
        ports:
        - containerPort: 80
```

所有清单文件都可以在本书的官方 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05)。

您可以使用以下清单文件部署 ClusterIP 类型的 Service：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-deployment-example-clusterip
spec:
  selector:
    environment: test
  type: ClusterIP
  ports:
  - port: 8080
    protocol: TCP
    targetPort: 80
```

与每种 Service 类型一样，关键部分是`selector`规范，它必须与部署中的 Pod 匹配。您将`type`指定为`ClusterIP`，并在 Service 上分配`8080`作为端口，该端口映射到 Pod 上的`targetPort: 80`。这意味着客户端 Pod 将使用`nginx-deployment-example:8080` TCP 端点与 nginx Pods 进行通信。实际的 ClusterIP 地址是动态分配的，除非您在`spec`中明确指定一个。Kubernetes 集群中的内部 DNS 服务负责将`nginx-deployment-example`解析为实际的 ClusterIP 地址，作为服务发现的一部分。

本节其余部分的图表表示了服务在逻辑上是如何实现的。在幕后，kube-proxy 负责管理所有转发规则和公开端口，就像前面的图表中一样。

这在以下图表中进行了可视化：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/418727d5-dc7f-40bb-b753-5afd78678a49.png)

ClusterIP 服务是允许外部通信的其他服务类型的基础：NodePort 和 LoadBalancer。

# NodePort

允许对 Pod 进行外部入口通信的第一种服务类型是 NodePort 服务。这种类型的服务被实现为 ClusterIP 服务，并具有使用任何集群节点 IP 地址和指定端口可达的额外功能。为了实现这一点，kube-proxy 在 30000-32767 范围内的每个节点上公开相同的端口（可配置），并设置转发，以便将对该端口的任何连接转发到 ClusterIP。

您可以使用以下清单文件部署 NodePort 服务：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-deployment-example-nodeport
spec:
  selector:
    environment: test
  type: NodePort
  ports:
  - port: 8080
    nodePort: 31001
    protocol: TCP
    targetPort: 80
```

如果在规范中未指定`nodePort`，则将动态分配使用 NodePort 范围。请注意，服务仍然充当 ClusterIP 服务，这意味着它在其 ClusterIP 端点内部可达。

以下图表可视化了 NodePort 服务的概念：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f843f656-4526-48b2-a0ca-b918b742410f.png)

当您希望在服务前设置自己的负载均衡设置时，建议使用 NodePort 服务。您也可以直接暴露 NodePorts，但请记住，这样的解决方案更难以保护，并可能存在安全风险。

# LoadBalancer

允许外部入口通信的第二种服务类型是 LoadBalancer，在可以创建外部负载均衡器的 Kubernetes 集群中可用，例如云中的托管 Kubernetes 服务。这种类型的服务将 NodePort 的方法与额外的外部负载均衡器结合在一起，该负载均衡器将流量路由到 NodePorts。

您可以使用以下清单文件部署 LoadBalancer 服务：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-deployment-example-lb
spec:
  selector:
    environment: test
  type: LoadBalancer
  ports:
  - port: 8080
    protocol: TCP
    targetPort: 80
```

请注意，为了应用此清单文件，您需要支持外部负载均衡器的环境，例如我们在第四章中创建的 AKS 集群，*Kubernetes 概念和 Windows 支持*。Katacoda Kubernetes Playground 还能够创建可以从 Playground 终端访问的“外部”负载均衡器。如果您尝试在不支持创建外部负载均衡器的环境中创建 LoadBalancer 服务，将导致负载均衡器入口 IP 地址无限期处于*pending*状态。

为了获得外部负载均衡器地址，请执行以下命令：

```
PS C:\src> kubectl get svc nginx-deployment-example-lb
NAME                          TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)          AGE
nginx-deployment-example-lb   LoadBalancer   10.0.190.215   137.117.227.83   8080:30141/TCP   2m23s
```

`EXTERNAL-IP`列显示负载均衡器具有 IP 地址`137.117.227.83`，为了访问您的服务，您必须与`137.117.227.83:8080` TCP 端点通信。此外，您可以看到服务有自己的内部 ClusterIP，`10.0.190.215`，并且公开了 NodePort `30141`。在 AKS 上运行的 LoadBalancer 服务已在以下图表中可视化：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3bbb81f4-46df-4681-914d-c8d192f1d55c.png)

如果您对服务前面的 Azure 负载均衡器的配置感兴趣，您需要转到[`portal.azure.com`](https://portal.azure.com)并导航到负载均衡器资源，您将在那里找到 Kubernetes 负载均衡器实例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/ac15b906-1332-4ac6-8772-a7fb5d1069b5.png)

现在，让我们来看看最后一种服务类型：ExternalName。

# ExternalName

在某些情况下，您需要定义一个指向不托管在 Kubernetes 集群中的外部资源的服务。例如，这可能包括云托管的数据库实例。Kubernetes 提供了一种将通信抽象化到这些资源并通过使用 ExternalName 服务在集群服务发现中注册它们的方法。

ExternalName 服务不使用选择器，只是服务名称到外部 DNS 名称的原始映射：

```
apiVersion: v1
kind: Service
metadata:
  name: externalname-example-service
spec:
  type: ExternalName
  externalName: cloud.database.example.com
```

在解析服务 DNS 名称（`externalname-example-service.default.svc.cluster.local`）期间，内部集群 DNS 将响应具有值`cloud.database.example.com`的 CNAME 记录。没有使用 kube-proxy 规则进行实际的流量转发-重定向发生在 DNS 级别。

ExternalName 服务的一个很好的用例是根据环境类型提供外部服务的不同实例，例如数据库。从 Pod 的角度来看，这不需要任何配置或连接字符串更改。

# Ingress

LoadBalancer 服务仅提供 L4 负载平衡功能。这意味着您不能使用以下内容：

+   HTTPS 流量终止和卸载

+   使用相同的负载均衡器进行基于名称的虚拟主机托管多个域名

+   基于路径的路由到服务，例如作为 API 网关

为了解决这个问题，Kubernetes 提供了 Ingress API 对象（不是服务类型），可用于 L7 负载平衡。

Ingress 部署和配置是一个广泛的主题，超出了本书的范围。您可以在官方文档中找到关于 Ingress 和 Ingress 控制器的更详细信息：[`kubernetes.io/docs/concepts/services-networking/ingress/`](https://kubernetes.io/docs/concepts/services-networking/ingress/)。

使用 Ingress 首先需要在您的 Kubernetes 集群中部署一个 Ingress 控制器。Ingress 控制器是一个 Kubernetes 控制器，通常作为一个 DaemonSet 或运行专用 Pod 来处理入口流量负载均衡和智能路由，手动部署到集群中。Kubernetes 中常用的 Ingress 控制器是**ingress-nginx**（[`www.nginx.com/products/nginx/kubernetes-ingress-controller`](https://www.nginx.com/products/nginx/kubernetes-ingress-controller)），它作为一个 nginx web 主机的部署，具有一组规则来处理 Ingress API 对象。Ingress 控制器以一种取决于安装的类型的 Service 暴露出来。例如，对于只有 Linux 节点的 AKS 集群，可以使用以下清单执行 ingress-nginx 的基本安装，将其暴露为 LoadBalancer Service。

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/mandatory.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/cloud-generic.yaml
```

一般来说，Ingress 控制器的安装取决于 Kubernetes 集群环境和配置，并且必须根据您的需求进行调整。例如，对于带有 Windows 节点的 AKS，您需要确保适当的节点选择器被使用，以便正确调度 Ingress 控制器 Pod。

您可以在本书的官方 GitHub 存储库中找到针对带有 Windows 节点的 AKS 的定制 nginx Ingress 控制器定义，以及示例服务和 Ingress 定义：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05/05_ingress-example`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter05/05_ingress-example)。

当 Ingress 控制器已经安装在集群中时，Ingress API 对象可以被创建并且会被控制器处理。例如，假设您已经部署了两个 ClusterIP 服务`example-service1`和`example-service2`，Ingress 定义可能如下所示：

```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /service1
        backend:
          serviceName: example-service1
          servicePort: 80
      - path: /service2
        backend:
          serviceName: example-service2
          servicePort: 80
```

现在，当您对`https://<ingressServiceLoadBalancerIp>/service1`发出 HTTP 请求时，流量将由 nginx 路由到`example-service1`。请注意，您只使用一个云负载均衡器进行此操作，实际的路由到 Kubernetes 服务是由 Ingress 控制器使用基于路径的路由来执行的。

这种设计原则已在以下图表中显示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e56b2286-fc83-40f0-8ee7-bd8c662ff394.png)

对于 AKS，您可以考虑使用 HTTP 应用程序路由附加组件，它可以自动管理 Ingress 控制器和集群的 External-DNS 控制器。更多细节可以在官方文档中找到：[`docs.microsoft.com/en-us/azure/aks/http-application-routing`](https://docs.microsoft.com/en-us/azure/aks/http-application-routing)。

选择是否实现 Ingress 或 Service 的一个一般准则是使用 Ingress 来暴露 HTTP（尤其是 HTTPS）端点，并使用 Service 来处理其他协议。

# Kubernetes CNI 网络插件

在这一章中，我们已经提到了**容器网络接口**（**CNI**）和**CNI 插件**这两个术语，这是在 Kubernetes 网络设置的背景下。事实上，CNI 并不局限于 Kubernetes——这个概念起源于 Rkt 容器运行时，并被采纳为 CNCF 项目，旨在为任何容器运行时和网络实现提供一个简单明了的接口。容器运行时使用 CNI 插件来连接容器到网络，并在需要时将它们从网络中移除。

# 理解 CNI 项目

CNI 项目有三个明确的部分：

+   CNI 规范定义了一个通用的、基于插件的容器网络解决方案的架构，以及 CNI 插件必须实现的实际接口。规范可以在[`github.com/containernetworking/cni/blob/master/SPEC.md`](https://github.com/containernetworking/cni/blob/master/SPEC.md)找到。

+   将 CNI 集成到应用程序中的库可以在与规范相同的存储库中找到：[`github.com/containernetworking/cni/tree/master/libcni`](https://github.com/containernetworking/cni/tree/master/libcni)。

+   CNI 插件的参考实现可以在专用存储库中找到：[`github.com/containernetworking/plugins`](https://github.com/containernetworking/plugins)。

CNI 的规范非常简单明了，可以总结如下：

+   CNI 插件是作为独立的可执行文件实现的。

+   容器运行时负责在与 CNI 插件交互之前为容器准备一个新的网络命名空间（或在 Windows 情况下为网络隔间）。

+   CNI 插件负责将容器连接到由网络配置指定的网络。

+   网络配置以 JSON 格式由容器运行时通过标准输入提供给 CNI 插件。

+   使用环境变量向 CNI 插件提供参数。例如，`CNI_COMMAND`变量指定插件应执行的操作类型。命令集是有限的，包括`ADD`、`DEL`、`CHECK`和`VERSION`；其中最重要的是`ADD`和`DEL`，分别用于将容器添加到网络和从网络中删除容器。

对于 CNI 插件，有三种常见类型的插件，在网络配置期间负责不同的责任：

+   接口创建插件

+   **IP 地址管理（IPAM）**插件负责为容器分配 IP 地址。

+   元插件可以作为其他 CNI 插件的适配器，或为其他 CNI 插件提供额外的配置或转换它们的输出。

目前，在 Windows 上只能使用以下参考实现：host-local IPAM 插件、win-bridge 和 win-Overlay 接口创建插件，以及 flannel 元插件。也可以使用第三方插件；例如，微软提供了 Azure-CNI 插件，用于将容器与 Azure SDN 集成（[`github.com/Azure/azure-container-networking/blob/master/docs/cni.md`](https://github.com/Azure/azure-container-networking/blob/master/docs/cni.md)）。

在 Kubernetes 中，kubelet 在管理 Pod 的生命周期时使用 CNI 插件，以确保 Pod 的连通性和可达性。Kubelet 执行的最基本操作是在创建 Pod 时执行`ADD` CNI 命令，在销毁 Pod 时执行`DELETE` CNI 命令。在某些情况下，CNI 插件也可以用于调整 kube-proxy 的配置。

在部署新集群时，选择 CNI 插件并定义 CNI 插件的网络配置是在 Pod 网络附加组件安装步骤中执行的。最常见的安装方式是通过部署专用的 DaemonSet 来执行，该 DaemonSet 使用 init 容器执行 CNI 插件的安装，并在每个节点上运行额外的代理容器（如果需要的话）。这种安装的一个很好的例子是 Flannel 的官方 Kubernetes 清单：[`github.com/coreos/flannel/blob/master/Documentation/kube-flannel.yml`](https://github.com/coreos/flannel/blob/master/Documentation/kube-flannel.yml)。

# CoreOS Flannel

在使用 Linux/Windows 混合 Kubernetes 集群时，特别是在本地部署时，通常会将**Flannel**作为 Pod 网络附加组件安装（[`github.com/coreos/flannel`](https://github.com/coreos/flannel)）。Flannel 是一个面向多个节点的 Kubernetes 和容器的最小化 L2/L3 虚拟网络提供程序。Flannel 有三个主要组件：

+   在集群中的每个节点上都运行一个**flanneld**（或者在 Windows 机器上是`flanneld.exe`）代理/守护进程，通常作为 Kubernetes 中的一个 DaemonSet 部署。它负责为每个节点分配一个较大的 Pod CIDR 中的独占子网租约。例如，在本章中，我们一直在集群中使用`10.244.0.0/16`作为 Pod CIDR，而在单个节点上使用`10.244.1.0/24`或`10.244.2.0/24`作为子网租约。租约信息和节点网络配置由`flanneld`使用 Kubernetes API 或直接存储在`etcd`中。该代理的主要责任是同步子网租约信息，配置 Flannel 后端，并在节点上为其他组件（如 Flannel CNI 插件）公开配置（作为容器主机文件系统中的文件）。

+   Flannel 的**后端**定义了 Pod 之间的网络是如何创建的。在本章中我们已经使用过的在 Windows 和 Linux 上都支持的后端的例子有 Vxlan 和 host-gw。您可以在[`github.com/coreos/flannel/blob/master/Documentation/backends.md`](https://github.com/coreos/flannel/blob/master/Documentation/backends.md)找到更多关于 Flannel 后端的信息。

+   Flannel **CNI 插件**是由 kubelet 在将 Pod 添加到网络或从网络中移除 Pod 时执行的。Flannel CNI 插件是一个元插件，它使用其他创建接口和 IPAM 插件来执行操作。它的责任是读取`flanneld`提供的子网信息，为适当的 CNI 插件生成 JSON 配置，并执行它。目标插件的选择取决于 Flannel 使用的后端；例如，在 Windows 节点上使用 vxlan 后端，Flannel CNI 插件将调用 host-local IPAM 插件和 win-Overlay 插件。您可以在官方文档中找到有关这个元插件的更多信息：[`github.com/containernetworking/plugins/tree/master/plugins/meta/flannel`](https://github.com/containernetworking/plugins/tree/master/plugins/meta/flannel)。

让我们逐步看看在运行在 vxlan 后端的 Windows 节点上发生的事情——从 Flannel 代理部署到 kubelet 创建 Pod（类似的步骤也发生在 Linux 节点上，但执行不同的目标 CNI 插件）：

1.  `flanneld.exe`代理作为一个 DaemonSet 部署到节点上，或者按照当前 Windows 文档的建议手动启动。

1.  代理读取提供的`net-conf.json`文件，其中包含 Pod CIDR 和`vxlan`后端配置：

```
{
    "Network": "10.244.0.0/16",
    "Backend": {
        "Type": "vxlan",
        "VNI": 4096,
        "Port": 4789
    }
}
```

1.  代理为节点获取一个新的子网租约`10.244.1.0/24`。租约信息存储在 Kubernetes API 中。创建`vxlan0`网络，创建 VTEP 设备，并更新路由表和转发数据库。

1.  子网租约的信息被写入到节点文件系统中的`C:\run\flannel\subnet.env`。这是一个例子：

```
FLANNEL_NETWORK=10.244.0.0/16
FLANNEL_SUBNET=10.244.1.0/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
```

1.  每当一个新节点加入集群时，`flanneld.exe`代理会对路由表和转发数据库进行任何额外的重新配置。

1.  现在，一个新的 Pod 被调度到这个节点上，kubelet 初始化 pod 基础容器，并在 Flannel meta CNI 插件上执行`ADD`命令，使用配置 JSON，该 JSON 将接口创建委托给`win-Overlay`插件，并将 IPAM 管理委托给`host-local`插件。Flannel CNI 插件根据`subnet.env`和这些插件的输入配置生成配置 JSON。

1.  使用`host-local` IPAM 插件租用新的 IP。Flannel 不负责管理 IPAM，它只是从当前节点上的给定子网中检索一个新的空闲 IP 地址。

1.  `win-bridge`插件配置了 Pod 的**主机网络服务**（HNS）端点，并有效地将 Pod 连接到 Overlay 网络。

总之，Flannel 自动化了为 Pod 创建 L2/Overlay 网络的过程，并在创建新 Pod 或新节点加入集群时维护网络。目前，在 Windows 上，L2 网络（host-gw 后端）被认为是稳定的，而 Overlay 网络（vxlan 后端）在 Windows 上仍处于 alpha 阶段——在使用本地 Kubernetes 集群时，这两种后端都很有用。对于 AKS 和 AKS-engine 场景，安装 Pod 网络的最有效方式是使用默认的 Azure-CNI 插件。

# Kubernetes 中的 Windows Server 网络

在高层次上，Windows 节点的 Kubernetes 网络与 Linux 节点类似——kubelet 通过 CNI 与网络操作解耦。主要区别在于 Windows 容器网络的实际实现以及用于 Windows 容器的术语。

Windows 容器网络设置类似于 Hyper-V 虚拟机网络，并且实际上共享许多内部服务，特别是**主机网络服务**（**HNS**），它与**主机计算服务**（**HCS**）合作，后者管理容器的生命周期。创建新的 Docker 容器时，容器会接收自己的网络命名空间（隔间）和位于该命名空间中的**虚拟网络接口控制器**（**vNIC**或在 Hyper-V 中，隔离容器或**vmNIC**）。然后将 vNIC 连接到**Hyper-V 虚拟交换机**（**vSwitch**），该交换机还使用主机 vNIC 连接到主机默认网络命名空间。您可以将此结构宽松地映射到 Linux 容器世界中的**容器桥接口**（CBR）。vSwitch 利用 Windows 防火墙和**虚拟过滤平台**（**VFP**）Hyper-V vSwitch 扩展来提供网络安全、流量转发、VXLAN 封装和负载平衡。这个组件对于 kube-proxy 提供服务功能至关重要，您可以将 VFP 视为 Linux 容器世界中的*iptables*。vSwitch 可以是内部的（不连接到容器主机上的网络适配器）或外部的（连接到容器主机上的网络适配器）；这取决于容器网络驱动程序。在 Kubernetes 的情况下，您将始终使用创建外部 vSwitch 的网络驱动程序（L2Bridge、Overlay、Transparent）。

VFP 利用 Windows 内核功能来过滤和转发网络流量。直到 Kubernetes 1.8，kube-proxy 不支持 VFP，唯一的转发流量的方式是使用**用户空间**模式，该模式在用户空间而不是内核空间中进行所有流量管理。

在创建容器时，所有前述设置都是由 HNS 执行的。HNS 通常负责以下工作：

+   创建虚拟网络和 vSwitches

+   创建网络命名空间（隔间）

+   创建 vNICs（端点）并将它们放置在容器网络命名空间中

+   创建 vSwitch 端口

+   管理 VFP 网络策略（负载平衡、封装）

在 Kubernetes 的情况下，CNI 插件是设置容器网络的唯一方式（对于 Linux，可以选择不使用它们）。它们与 HNS 和 HCS 进行实际通信，以设置所选的网络模式。与标准的 Docker 网络设置相比，Kubernetes 的网络设置有一个重要的区别：容器 vNIC 连接到 pod 基础设施容器，并且网络命名空间在 Pod 中的所有容器之间共享。这与 Linux Pods 的概念相同。

这些结构在以下图表中可视化：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f7046c96-b38c-48fd-aace-8153927c5a66.png)

Windows 容器网络架构为 Kubernetes 有一个更重要的概念：网络驱动程序（模式）。在下一节中，我们将介绍选项，并看看它们中哪些适用于 Kubernetes，但首先，让我们快速看一下 Windows 上 Kubernetes 网络的当前限制。

# 限制

Windows 容器网络不断发展，许多功能的实现仍在进行中。目前，Kubernetes 在 Windows 平台上有一些网络限制。

+   Windows Pod 不支持主机网络模式。

+   不支持从节点本身访问 NodePort。

+   L2Bridge、L2Tunnel 和 Overlay 网络驱动不支持 IPv6 堆栈。

+   不支持外部网络的 ICMP。换句话说，您将无法 ping 通 Kubernetes 集群外的 IP 地址。

+   在 vxlan 后端上运行的 Flannel 受限于使用 VNI 4096 和 UDP 端口 4789。

+   不支持容器通信的 IPsec 加密。

+   容器内不支持 HTTP 代理。

+   对于在 Windows 节点上运行的 Ingress 控制器，您必须选择支持 Windows 和 Linux 节点的部署。

您可以期待这个列表变得更短，因为新版本的 Windows Server 和 Kubernetes 即将推出。

# 选择 Kubernetes 网络模式

网络模式（驱动程序）是 Docker 的一个概念，是**容器网络模型**（**CNM**）的一部分。这个规范是由 Docker 提出的，以模块化、可插拔的方式解决容器网络设置和管理的挑战。Docker 的 libnetwork 是 CNM 规范的规范实现。

此时，您可能想知道 CNM 与 CNI 的关系，它们解决了类似的问题。是的，它们是竞争的容器网络规范！对于 Linux 容器，Docker 网络驱动程序和 CNI 的实现可能会有很大的不同。然而，对于 Windows 容器，libnetwork 中实现的网络驱动程序只是 HNS 的一个简单的包装，执行所有的配置任务。CNI 插件，如 win-bridge 和 win-Overlay，也是一样的：调用 HNS API。这意味着对于 Windows 来说，Docker 网络驱动程序和 CNI 插件是平等的，并且完全依赖于 HNS 及其本地网络配置。如果您感兴趣，您可以查看 libnetwork 的 Windows 驱动程序实现，并了解它是如何与 HNS 交互的：[`github.com/docker/libnetwork/blob/master/drivers/windows/windows.go`](https://github.com/docker/libnetwork/blob/master/drivers/windows/windows.go)。

CNI 和 CNM 有着悠久的历史和一些显著的区别。在 Kubernetes 早期，决定不使用 Docker 的 libnetwork，而是选择 CNI 作为容器网络管理的抽象。您可以在 Kubernetes 的博客文章中阅读更多关于这个决定的信息：[`kubernetes.io/blog/2016/01/why-kubernetes-doesnt-use-libnetwork/`](https://kubernetes.io/blog/2016/01/why-kubernetes-doesnt-use-libnetwork/)。如果您对 CNI 与 CNM 的更多细节感兴趣，请参考这篇文章：[`thenewstack.io/container-networking-landscape-cni-coreos-cnm-docker/`](https://thenewstack.io/container-networking-landscape-cni-coreos-cnm-docker/)。

总的来说，对于 Windows 容器，您可以互换使用 Docker 网络驱动程序和 HNS 网络驱动程序这两个术语。

目前 Windows 容器支持五种 HNS 网络驱动程序：

+   l2bridge

+   l2tunnel

+   Overlay

+   透明

+   NAT（在 Kubernetes 中未使用）

您可以使用以下命令手动创建一个新的 Docker 网络：

```
docker network create -d <networkType> <additionalParameters> <name> 
```

某些网络类型需要额外的参数；您可以在官方文档中找到更多详细信息：[`docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/network-drivers-topologies`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/network-drivers-topologies)。Microsoft SDN 仓库还提供了一个简单的 PowerShell 模块，用于与 HNS API 进行交互，您可以使用它来分析您的网络配置：[`github.com/microsoft/SDN/blob/master/Kubernetes/windows/hns.psm1`](https://github.com/microsoft/SDN/blob/master/Kubernetes/windows/hns.psm1)。

您可以在 Microsoft 的支持政策中找到 Windows 容器的官方支持的网络配置：[`support.microsoft.com/da-dk/help/4489234/support-policy-for-windows-containers-and-docker-on-premises`](https://support.microsoft.com/da-dk/help/4489234/support-policy-for-windows-containers-and-docker-on-premises)。

现在让我们逐个了解每种类型的 HNS 网络，以了解它们如何适用于 Kubernetes，何时使用它们，以及它们与 CNI 插件的关系。

# L2Bridge

在 L2Bridge 网络模式下，容器连接到共享的外部 Hyper-V vSwitch，可以访问底层网络。容器还与容器主机共享相同的 IP 子网，容器 IP 地址必须使用与容器主机 IP 相同前缀的静态分配。MAC 地址在进入和离开时被重写为主机的地址（这需要启用 MAC 欺骗；在本地 Hyper-V VM 上测试 Kubernetes 集群时请记住这一点）。

以下 CNI 插件使用 L2Bridge 网络：

+   win-bridge

+   Azure-CNI

+   Flannel 使用 host-gw 后端（作为元插件，它调用 win-bridge）

以下是 L2Bridge 的优点：

+   win-bridge 和 Flannel（host-gw）易于配置

+   在 Windows 中有稳定的支持

+   最佳性能

以下是 L2Bridge 的缺点：

+   节点之间需要 L2 邻接

# L2Tunnel

L2Tunnel 网络模式是 L2Bridge 的特例，在此模式下，*所有* 来自容器的网络流量都被转发到虚拟化主机，以应用 SDN 策略。此网络类型仅适用于 Microsoft Cloud Stack。

以下 CNI 插件使用 L2Tunnel 网络：

+   Azure-CNI

以下是 L2Tunnel 的优点：

+   在 Azure 上的 AKS 和 AKS-engine 中使用，并且有稳定的支持。

+   您可以利用 Azure 虚拟网络提供的功能（[`azure.microsoft.com/en-us/services/virtual-network/`](https://azure.microsoft.com/en-us/services/virtual-network/)）。

L2Tunnel 的缺点包括：

+   它只能在 Azure 上使用

# 覆盖

覆盖网络模式使用 VFP 在外部 Hyper-V vSwitch 上创建 VXLAN 覆盖网络。每个覆盖网络都有自己的 IP 子网，由可定制的 IP 前缀确定。

以下 CNI 插件使用覆盖网络：

+   win-Overlay

+   带有 vxlan 后端的 Flannel（作为元插件，调用 win-Overlay）

覆盖网络的优点包括：

+   子网组织没有限制。

+   节点之间不需要 L2 邻接。您可以在 L3 网络中使用此模式。

+   增强了与底层网络的安全性和隔离性。

覆盖的缺点包括：

+   它目前处于 Windows 的 alpha 功能阶段。

+   您受限于特定的 VNI（4096）和 UDP 端口（4789）。

+   性能比 L2Bridge 差。

# Transparent

在 Windows 上，Kubernetes 支持的最后一个 HNS 网络类型是 Transparent。连接到透明网络的容器将连接到具有静态或动态分配的 IP 地址的外部 Hyper-V vSwitch。在 Kubernetes 中，此网络类型用于支持 OVN，其中逻辑交换机和路由器启用了 Pod 内部的通信。

以下 CNI 插件使用透明网络：

+   ovn-kubernetes

透明网络的缺点包括：

+   如果您想在本地托管的 Kubernetes 中使用这种网络类型，您必须部署 OVN 和 Open vSwitches，这本身就是一个复杂的任务。

# 总结

在本章中，您已经了解了 Kubernetes 中网络的原则。我们介绍了 Kubernetes 网络模型和任何模型实现必须满足的要求。接下来，我们从 Windows 的角度分析了两种最重要的网络模型实现：L2 网络和覆盖网络。在上一章中，您已经了解了 Service API 对象，而在本章中，您更深入地了解了服务在网络模型方面的实现。最后，您了解了 Windows 节点上的 Kubernetes 网络、CNI 插件以及何时使用每种插件类型。

下一章将重点介绍如何使用 Kubernetes 命令行工具（即**kubectl**）从 Windows 机器与 Kubernetes 集群进行交互。

# 问题

1.  实施 Kubernetes 网络模型的要求是什么？

1.  在 Kubernetes 中何时可以使用带有 host-gw 后端的 Flannel？

1.  ClusterIP 和 NodePort 服务之间有什么区别？

1.  使用 Ingress 控制器而不是 LoadBalancer 服务的好处是什么？

1.  CNI 插件是什么，它们如何被 Kubernetes 使用？

1.  内部和外部 Hyper-V vSwitch 之间有什么区别？

1.  CNI 插件和 Docker 网络驱动之间有什么区别？

1.  什么是覆盖网络？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

有关 Kubernetes 概念和网络的更多信息，请参考以下 Packt 图书和资源：

+   完整的 Kubernetes 指南（[`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide)）。

+   开始使用 Kubernetes-第三版（[`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition)）。

+   面向开发人员的 Kubernetes（[`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers)）。

+   Kubernetes 网络实践（视频）（[`www.packtpub.com/virtualization-and-cloud/hands-kubernetes-networking-video`](https://www.packtpub.com/virtualization-and-cloud/hands-kubernetes-networking-video)）。

+   您还可以参考优秀的官方 Kubernetes 文档（[`kubernetes.io/docs/concepts/cluster-administration/networking/`](https://kubernetes.io/docs/concepts/cluster-administration/networking/)），这始终是关于 Kubernetes 的最新知识来源。

+   对于特定于 Windows 的网络方案，建议参考官方的 Microsoft 虚拟化文档：[`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/network-topologies`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/network-topologies) 用于 Kubernetes 和[`docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture) 用于 Windows 容器网络。


# 第六章：与 Kubernetes 集群交互

作为 Kubernetes 集群的用户或操作员，您需要与 Kubernetes API 交互，以管理 Kubernetes 对象或调试在集群中运行的应用程序。一般来说，有两种方式与 Kubernetes API 通信：您可以直接使用表征状态传输（RESTful）HTTPS 端点，例如用于编程访问，或者您可以使用 kubectl，这是 Kubernetes 命令行工具（或**命令行接口**（**CLI**））。一般来说，kubectl 封装了 RESTful API 通信，并隐藏了有关定位和认证到 Kubernetes API 服务器的复杂性。创建或列出 Kubernetes 对象以及执行 Pod 容器等操作都作为整齐组织的 kubectl 子命令可用-您可以在对集群执行临时操作时使用这些命令，也可以作为应用程序的**持续集成/持续部署**（**CI/CD**）的一部分使用这些命令。

在本章中，我们将为您提供如何在 Windows 机器上安装 kubectl 以及如何使用 kubectl 管理多个 Kubernetes 集群的更好理解。您还将学习管理 Kubernetes 对象和调试容器化应用程序最常见和有用的 kubectl 命令。

本章包括以下主题：

+   安装 Kubernetes 命令行工具

+   访问 Kubernetes 集群

+   使用开发集群

+   查看常见的 kubectl 命令

# 技术要求

本章，您需要安装以下内容：

+   Windows 10 专业版、企业版或教育版（1903 版本或更高版本，64 位）

+   Windows 2.0.0.3 或更高版本的 Docker 桌面版

+   Windows 的 Chocolatey 软件包管理器（[`chocolatey.org/`](https://chocolatey.org/)）

+   Azure CLI

有关 Windows 上 Docker 桌面版的安装和系统要求，请参阅第一章*，*创建容器*。

使用 Chocolatey 软件包管理器并非强制，但它可以使安装过程和应用程序版本管理更加容易。安装过程在此处有文档记录：[`chocolatey.org/install`](https://chocolatey.org/install)。

对于 Azure CLI，您可以在第二章*，*管理容器中的状态**中找到详细的安装说明。

要使用**Azure Kubernetes Service**（**AKS**）进行跟随，您将需要自己的 Azure 帐户和已创建的 AKS 实例。如果您之前没有为前几章创建帐户，您可以在此处阅读有关如何获取个人使用的有限免费帐户的更多信息：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。AKS 集群部署在第四章中进行了介绍，*Kubernetes 概念和 Windows 支持*。您还可以在该章节中使用提供的 PowerShell 脚本。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter06)。

# 安装 Kubernetes 命令行工具

Kubectl 可在多种操作系统上使用，包括 Windows。如果您在 Linux 上使用 kubectl 有经验，您可以期望唯一的区别是安装过程，命令和基本原则保持不变。对于 Windows，您有几种 kubectl 安装选项，如下所示：

+   直接下载 kubectl 二进制文件。

+   使用 PowerShell Gallery（[`www.powershellgallery.com/`](https://www.powershellgallery.com/)）。

+   使用第三方 Windows 软件包管理器：Chocolatey（[`chocolatey.org/`](https://chocolatey.org/)）或 Scoop（[`scoop.sh/`](https://scoop.sh/)）。

在创建本地开发 Kubernetes 集群时，Docker Desktop for Windows 也可以自动安装 kubectl（可执行文件安装在`C:\Program Files\Docker\Docker\Resources\bin\kubectl.exe`），或者在创建 AKS 集群实例时使用 Azure CLI（使用`az aks install-cli`命令，在`~/.azure-kubectl/kubectl.exe`中安装 kubectl）。这可能会与不同位置已安装的 kubectl 实例产生冲突—您可以始终通过使用`(Get-Command kubectl).Path`命令在 PowerShell 中检查使用哪个 kubectl 安装。切换到不同的 kubectl 安装需要修改`PATH`环境并确保所需的优先级。

您可以在官方文档中找到所有安装类型的详细说明：[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)。我们将演示如何使用 Chocolatey 安装 kubectl，因为这是在 Windows 上安装 kubectl 的最简单和最便捷的方式。按照以下步骤进行操作：

1.  如果您还没有安装 Chocolatey 软件包管理器，您可以在这里找到安装说明：[`chocolatey.org/install`](https://chocolatey.org/install)。

1.  以管理员身份打开 PowerShell 窗口，并使用以下命令安装 kubectl：

```
choco install kubernetes-cli
```

1.  如果您需要将 kubectl 升级到最新版本，请使用以下命令：

```
choco upgrade kubernetes-cli
```

1.  验证 kubectl 是否已安装，例如使用以下命令：

```
kubectl version
```

根据 Kubernetes 版本支持策略，您应该使用一个在 kube-apiserver 的次要版本（较旧或较新）之内的 kubectl 版本。例如，kubectl 1.15 保证可以与 kube-apiserver 1.14、1.15 和 1.16 一起使用。建议您在可能的情况下使用集群的最新 kubectl 版本。

请注意，通过 Chocolatey 安装的 kubectl 版本有时可能比最新的稳定版本要旧。在这种情况下，如果您需要最新的稳定版本，请按照直接下载 kubectl 二进制文件的说明进行操作。

在下一节中，我们将演示如何组织访问多个 Kubernetes 集群。

# 访问 Kubernetes 集群

默认情况下，kubectl 使用位于`~\.kube\config`的`kubeconfig`文件（请注意我们称其为`kubeconfig`，但文件名为`config`），在 Windows 机器上会扩展为`C:\Users\<currentUser>\.kube\config`。这个 YAML 配置文件包含 kubectl 连接到您集群的 Kubernetes API 所需的所有参数。这个配置文件也可以被除 kubectl 之外的其他工具使用，例如*Helm*。

您可以使用`KUBECONFIG`环境变量或`--kubeconfig`标志来强制 kubectl 对个别命令使用不同的`kubeconfig`。对于`KUBECONFIG`环境变量，可以在运行时指定多个`kubeconfig`并合并它们。您可以在官方文档中阅读更多关于此功能的信息：[`kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#merging-kubeconfig-files`](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#merging-kubeconfig-files)。请注意，对于 Windows，您应该用分号分隔`KUBECONFIG`路径，而在 Linux 中，您应该使用冒号。

使用上下文在`kubeconfig`中协调访问多个 Kubernetes 集群。每个上下文包含以下信息：

+   **集群**：Kubernetes API 服务器的地址。

+   **用户**：用户的名称，映射到用户凭据（在`kubeconfig`中指定）。

+   **命名空间**：可选地，您可以提供要使用的默认命名空间。

如果您一直在关注之前的章节，我们演示了 Minikube 的安装和 Windows Docker 桌面上的本地 Kubernetes 集群的安装，您已经使用了在安装这些集群时自动添加的上下文。在使用 kubectl 时，始终有一个上下文标记为当前。您可以使用以下命令查看当前上下文：

```
PS C:\src> kubectl config current-context
minikube
```

列出`kubeconfig`中所有可用的上下文可以通过以下方式完成：

```
PS C:\src> kubectl config get-contexts
CURRENT   NAME                  CLUSTER               AUTHINFO                                                     NAMESPACE
 aks-windows-cluster   aks-windows-cluster   clusterUser_aks-windows-resource-group_aks-windows-cluster
 docker-desktop        docker-desktop        docker-desktop
 docker-for-desktop    docker-desktop        docker-desktop
*         minikube              minikube              minikube
```

如果您想切换到不同的上下文，例如`docker-desktop`，执行以下命令：

```
PS C:\src> kubectl config use-context docker-desktop
Switched to context "docker-desktop".
```

您可以从命令行手动修改现有上下文或添加自己的上下文。例如，以下命令将添加一个新的上下文`docker-desktop-kube-system`，它将连接到`docker-desktop`集群并默认使用`kube-system`命名空间。

```
kubectl config set-context docker-desktop-kube-system `
 --cluster docker-desktop `
 --user docker-desktop `
 --namespace kube-system
```

当您切换到新的上下文并运行任何命令时，例如`kubectl get pods`，它将针对`kube-system`命名空间执行。

在任何给定时间，您可以使用 kubectl 命令的`--cluster`、`--user`、`--namespace`甚至`--context`标志来覆盖当前上下文设置。

通常，在使用托管的 Kubernetes 提供程序或本地开发工具时，配置文件将作为一个单独的文件提供，通过`KUBECONFIG`环境变量进行下载和使用，或者直接合并到当前的`kubeconfig`中作为一个新的上下文（这就是在 AKS 的情况下`az aks get-credentials`命令所做的）。如果需要，您可以使用以下 PowerShell 命令手动合并`kubeconfigs`：

```
$env:KUBECONFIG="c:\path\to\config;~\.kube\config"
kubectl config view --raw
```

该命令的输出可以作为一个新的默认`kubeconfig`使用——在覆盖默认配置文件之前，您应该验证结果是否有效。您可以使用以下代码片段将默认的`kubeconfig`覆盖为合并后的配置：

```
$env:KUBECONFIG="c:\path\to\config;~\.kube\config"
kubectl config view --raw > ~\.kube\config_new
Move-Item -Force ~\.kube\config_new ~\.kube\config
```

请记住`kubeconfig`合并优先规则：如果在两个文件中找到相同的键，则第一个文件中的值将获胜。

现在您知道如何使用 kubeconfig 和 kubectl 上下文来管理对 Kubernetes 集群的访问权限，让我们专注于使用开发集群的策略。

# 使用开发集群

为 Kubernetes 开发应用程序引入了一些在传统开发流水线中不存在的独特挑战。完美的解决方案将是对流水线和流程进行最小的更改，但不幸的是，事情并不像那么简单。首先，您需要维护一个开发 Kubernetes 集群，用于部署、测试和调试您的应用程序。其次，您必须将应用程序容器化并部署到开发集群，可能比在安全的生产集群中具有更大的灵活性和访问权限。

非正式地，对于 Kubernetes 应用程序开发，您有四种模式（概念），如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/372af989-6426-492e-9380-3760131cdc5f.png)

让我们来看看这四种模式：

+   **完全脱机**：在完全脱机（本地）环境中，您的开发环境和 Kubernetes 集群托管在本地机器上。这种配置的一个很好的例子是 Minikube 或 Windows 本地 Kubernetes 集群的 Docker 桌面。在这两种情况下，Kubernetes 集群托管在专用的本地虚拟机（VM）中。这种开发工作流程需要构建 Docker 镜像，将它们推送到镜像注册表（本地或远程），并使用 kubectl 部署应用程序。当然，您可以利用集群在本地运行的事实，登录到集群节点并调试 Pod 容器。从 Windows 容器的角度来看，这需要在 Hyper-V VM 上运行完整的混合 Linux/Windows Kubernetes 集群。这种设置需要一台能够运行至少两个 VM 的本地机器：一个用于 Linux 主节点，一个用于 Windows 工作节点。我们将在第七章中部署一个完全功能的混合集群，*部署混合本地 Kubernetes 集群*。

下一章介绍的部署策略可以用于开发和生产集群。这种方法在开发中的缺点是与 Minikube 或其他完全脱机解决方案相比需要大量配置。不幸的是，目前还没有针对混合开发集群的易用的即插即用解决方案 - 如果您需要尽快为开发创建集群，完全托管的 AKS 是最佳选择。

+   **代理**：在使用代理环境时，您的 Kubernetes 集群托管在远程机器上（但也可以托管在本地 VM 上！）。开发环境仍然在您的本地机器上，但您配置了双向网络代理，以便您可以运行和调试应用程序，就好像您在集群中的 Pod 内部一样。换句话说，您可以简化开发工作流程，并跳过开发和调试场景的 Docker 开销。这可以通过使用诸如 Telepresence（[`www.telepresence.io/`](https://www.telepresence.io/)）之类的工具来实现。不幸的是，目前仅通过 Windows 子系统支持 Windows，这意味着没有本机 Windows 支持。

+   远程：下一个模式是远程模式，您可以在本地针对远程集群进行开发，这些集群可以托管在您的本地数据中心或作为托管的 Kubernetes 提供。这类似于在完全脱机环境中使用，但您必须注意使用托管 Kubernetes 集群的额外成本以及对 Kubernetes 节点的有限访问。对于 Windows，如果您正在运行 AKS，您将无法登录到 Linux 主节点，但如果您使用裸 Azure VM 上的 AKS 引擎进行部署，您可以访问 Linux 主节点和 Windows 节点。这种环境类型的优势在于您可以利用 Kubernetes 的所有云集成，例如负载均衡器服务或云卷。我们将在第八章中介绍 AKS 引擎部署，*部署混合 Azure Kubernetes 服务集群*。

+   完全在线：在完全在线模式下，您的开发环境与 Kubernetes 集群一起远程托管。这种方法的良好示例是 Eclipse Che ([`www.eclipse.org/che/docs/`](https://www.eclipse.org/che/docs/))和 Azure Dev Spaces ([`docs.microsoft.com/en-us/azure/dev-spaces/about`](https://docs.microsoft.com/en-us/azure/dev-spaces/about))，它与 Visual Studio Code 完全集成。在这一点上，对 Windows 节点的支持仍在开发中，并且需要手动配置([`docs.microsoft.com/en-us/azure/dev-spaces/how-to/run-dev-spaces-windows-containers`](https://docs.microsoft.com/en-us/azure/dev-spaces/how-to/run-dev-spaces-windows-containers))。将来，这是为 Windows 容器提供无缝 Kubernetes 开发生命周期的最佳选择。我们将在第十二章中介绍 Azure Dev Spaces，*Kubernetes 开发工作流程*。

有许多工具可以提高您的 Kubernetes 应用程序开发效率，并减少在“一切中间又有一个集群”的开销。例如，对于 Windows 支持，您可能希望查看 Azure Draft ([`draft.sh/`](https://draft.sh/))，它可以使用为您的应用程序自动生成的 Helm 图表简化开发流程，或者 ksync ([`ksync.github.io/ksync/`](https://ksync.github.io/ksync/))，它可用于将本地代码/二进制更改同步到 Pod 容器，无需重新部署。

在下一节中，我们将快速浏览一下您应该掌握的最常见和有用的 kubectl 命令。

# 查看常见的 kubectl 命令

Kubectl 是一个强大的工具，当与 Kubernetes 集群交互时，它提供了您所需的大部分功能。所有 kubectl 命令都遵循相同的语法，如下面的代码片段所示：

```
**kubectl [command] [type] [name] [flags]**

**# Example:**
**kubectl get service kube-dns --namespace kube-system** 
```

`[命令]`、`[类型]`、`[名称]`和`[标志]`的定义如下：

+   `[命令]`指定操作，例如`get`、`apply`、`delete`。

+   `[类型]`是资源类型（详细列表可以在文档中找到：[`kubernetes.io/docs/reference/kubectl/overview/#resource-types`](https://kubernetes.io/docs/reference/kubectl/overview/#resource-types)），以单数、复数或缩写形式（不区分大小写）指定，例如，`service`、`services`、`svc`。您可以使用`kubectl explain [type]`命令找到有关每个资源的更多信息。

+   `[名称]`确定资源的名称（区分大小写）。如果命令允许省略名称，则操作将应用于给定类型的所有资源。

+   `[标志]` 指定了额外的标志，这些标志可以是特定于命令的，也可以是全局的 kubectl 命令，例如，`--namespace kube-system`。

您可以随时使用`kubectl help`或`kubectl [command] --help`来访问关于每个命令如何工作以及可用标志的全面文档。kubectl 的官方参考资料可以在这里找到：[`kubernetes.io/docs/reference/generated/kubectl/kubectl-commands`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)。

术语*资源*和*对象*在 Kubernetes 中经常可以互换使用，尽管在考虑 Kubernetes 内部时存在一些差异。对象是 Kubernetes 系统实体（抽象概念），而资源是提供对象表示的实际 RESTful API 资源。

一些命令，如 `get` 或 `create`，允许您使用 `-o` 或 `--output` 标志指定输出格式。例如，您可以使用 `-o json` 强制使用 JSON 输出格式，或者使用 `-o jsonpath=<template>` 使用 JSONPath 模板提取信息。这在基于 kubectl 命令实施自动化时特别有用。您可以在这里找到有关输出类型的更多信息：[`kubernetes.io/docs/reference/kubectl/overview/#output-options`](https://kubernetes.io/docs/reference/kubectl/overview/#output-options)。

对于 *Bash* 和 *Zsh*，您可以通过使用自动补全（[`kubernetes.io/docs/tasks/tools/install-kubectl/#enabling-shell-autocompletion`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#enabling-shell-autocompletion)）来提高 kubectl 的生产力。对于 Windows，PowerShell 尚不支持自动补全，但是，如果您使用 Windows Subsystem for Linux 管理 Kubernetes 集群，也可以安装 Bash 自动补全。

# 创建资源

在第四章中，*Kubernetes 概念和 Windows 支持*，我们已经解释了 Kubernetes 中 *命令式* 和 *声明式* 资源管理背后的思想。简而言之，在使用命令式管理时，您依赖于创建、删除和替换资源的命令（可以将其视为脚本中的命令）。另一方面，在声明式管理中，您只描述资源的期望状态，Kubernetes 将执行所有必需的操作，以将资源的当前状态转换为期望状态。

以命令式方式在 Kubernetes 中创建资源可以使用 `kubectl create -f <manifestFile>` 命令。对于声明式方式，您必须使用 `kubectl apply -f <manifestFile>`。请注意，您可以应用 `-R` 标志并递归处理目录而不是单个文件。让我们在 Linux nginx Pods 的示例部署清单文件上演示这一点，您可以从本书的 GitHub 存储库下载：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter06/01_deployment-example/nginx-deployment.yaml`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter06/01_deployment-example/nginx-deployment.yaml)。

假设您将清单文件保存为 `nginx-deployment.yaml` 在当前目录中，使用 PowerShell 执行以下命令来创建 `nginx-deployment-example` 部署：

```
kubectl create -f .\nginx-deployment.yaml
```

您可以直接在 kubectl 中使用清单文件的 URL-例如，`kubectl create -f https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter06/01_deployment-example/nginx-deployment.yaml`。在将其部署到集群之前，请始终验证清单文件的内容，特别是从安全角度考虑。

您可以使用`kubectl apply`命令来实现相同的效果，如下所示：

```
kubectl apply -f .\nginx-deployment.yaml
```

在这一点上，这些命令的行为方式相同：它们只是创建 Deployment。但是现在，如果您修改`nginx-deployment.yaml`文件，以便将副本的数量增加到 4，请检查`kubectl create`和`kubectl apply`命令的结果：

```
PS C:\src> kubectl create -f .\nginx-deployment.yaml
Error from server (AlreadyExists): error when creating ".\\nginx-deployment.yaml": deployments.apps "nginx-deployment-example" already exists

PS C:\src> kubectl apply -f .\nginx-deployment.yaml
deployment.apps/nginx-deployment-example configured
```

由于已经创建了 Deployment，因此无法通过命令方式创建它-您需要替换它。在声明性的`apply`命令的情况下，更改已被接受，并且现有的 Deployment 已被扩展为 4 个副本。

对于声明性管理，kubectl 提供了`kubectl diff`命令，该命令显示了集群中资源的当前状态与清单文件中资源的差异。请注意，您需要在`PATH`环境变量中拥有`diff`工具，或者使用任何其他文件比较工具-例如 Meld ([`meldmerge.org/`](http://meldmerge.org/))，并使用`KUBECTL_EXTERNAL_DIFF`环境变量指定它。将`nginx-deployment.yaml`中的`replicas`数量增加到 5，并检查比较结果，如下所示：

```
$env:KUBECTL_EXTERNAL_DIFF="meld"
kubectl diff -f .\nginx-deployment.yaml
```

您可以立即在以下截图中看到，如果执行`kubectl apply`，将受到影响的属性：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e2108316-c229-42c4-b292-d6dcfd8a87c4.png)

一个经验法则是，尽可能坚持使用声明性资源管理，只将命令留给开发/黑客场景。对于 Kubernetes 应用程序的完全声明性管理，请考虑使用带有 Kustomize 的 kubectl。您可以在以下链接了解更多关于这种方法的信息：[`kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)。

# 删除资源

为了删除资源，您可以使用`kubectl delete [type] [name]`命令。这也是仍然建议在声明性集群管理中使用的命令之一，因为它更明确。使用带有`--prune`标志的`kubectl apply`更危险，因为您可能会意外删除更多资源。

使用以下命令删除`nginx-deployment-example`部署：

```
kubectl delete deployment nginx-deployment-example
```

如果您想删除给定类型的所有资源，可以使用`--all`标志而不是资源名称。

# 描述和列出资源

下一个你经常会使用的命令是`kubectl get [type] [name]`，它显示给定类型的资源的详细信息。例如，为了列出当前上下文中默认命名空间中的 Pods，执行以下命令：

```
kubectl get pods
```

您可以使用`--all-namespaces`或`--namespace=<namespace>`全局标志，允许您显示来自其他命名空间的资源，如下面的代码片段所示：

```
kubectl get pods --all-namespaces
```

默认情况下，这个命令显示有限的预定义列。您可以使用`-o wide`标志来查看更多细节，如下所示：

```
kubectl get pods -o wide
```

在某些情况下，您会发现观察资源很有用。以下命令列出所有 Pods，并定期刷新视图以获取最新数据：

```
kubectl get pods --watch
```

还有一个不同的命令，`kubectl describe`，它可以用于显示资源的详细信息，如下面的代码片段所示：

```
kubectl describe pod nginx-deployment-example-7f5cfc59d6-2bvvx
```

`get`和`describe`命令的区别在于，`get`显示来自 Kubernetes API 的资源的纯表示，而`describe`准备了一个包括事件、控制器和其他资源在内的详细描述。

`kubectl get`支持不同于表格的输出，例如，`-o json`或`-o yaml`，这对于与其他工具集成或将资源状态转储到文件非常有用，如下面的代码片段所示：

```
kubectl get pod nginx-deployment-example-7f5cfc59d6-2bvvx -o yaml
```

如果你需要对输出进行更多处理，你可以使用 JSONPath ([`github.com/json-path/JsonPath`](https://github.com/json-path/JsonPath))，它集成到 kubectl 中。例如，以下表达式将列出集群中 Pods 中使用的所有容器镜像：

```
kubectl get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}"
```

最后，您可能会发现使用单个命令列出所有命名空间中的所有资源很有用，如下所示：

```
kubectl get all --all-namespaces
```

这应该总是给你一个集群中正在发生的事情的很好的概述！

# 编辑资源

如本节前面提到的，通常不鼓励对 Kubernetes 资源进行命令式编辑。`kubectl edit` 是 `kubectl get`、打开您喜欢的文本编辑器和对修改后的清单文件进行 `kubectl apply` 的组合，如下面的代码块所示：

```
kubectl edit deployment nginx-deployment-example
```

在 Windows 机器上，此命令将打开 `notepad.exe`（或任何其他编辑器，如果您指定了 `EDITOR` 或 `KUBE_EDITOR` 环境变量），显示 `nginx-deployment-example` 的当前状态。编辑后，保存文件，关闭编辑器，您的更改将被应用。

另一种方法是使用补丁，可以在声明式管理中使用。`kubectl patch` 通过合并当前资源状态和仅包含修改属性的补丁来更新资源。修补的常见用例是在混合 Linux/Windows 集群中需要强制执行现有 DaemonSet 的节点选择器时。以下 JSON 补丁可用于确保诸如 Flannel 或 kube-proxy 的 DaemonSet 仅在 Linux 节点上运行：

```
{
    "spec": {
        "template": {
            "spec": {
                "nodeSelector": {
                    "beta.kubernetes.io/os": "linux"
                }
            }
        }
    }
}
```

也可以使用 YAML 补丁，但不幸的是，由于 PowerShell 转义规则，我们无法为 `beta.kubernetes.io/os` 选择器演示这一点。在 PowerShell 中，JSON 仍然需要额外的预处理。

为了将此补丁应用到 `nginx-deployment-example` 部署中，将补丁保存为 `linux-node-selector.json` 文件，并运行以下命令：

```
$patch = $(cat .\linux-node-selector.json)
$patch = $patch.replace('"', '\"')
kubectl patch deployment nginx-deployment-example --patch "$patch"
```

您可以在官方文档中找到有关资源修补和合并类型的更多信息：[`kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/`](https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/)。

# 运行临时 Pod

在调试场景中，您可能会发现运行临时 Pod 并附加到它很有用。您可以使用 `kubectl run` 命令执行此操作——请注意，此命令可以生成不同的资源，但除了 Pod 之外，所有生成器都已被弃用。以下代码段将创建一个带有一个 `busybox` 容器的 `busybox-debug` Pod，并在容器中运行一个交互式 Bourne shell 会话：

```
kubectl run --generator=run-pod/v1 busybox-debug -i --tty --image=busybox --rm --restart=Never -- sh
```

当 shell 提示符出现时，您可以在集群内执行操作，例如对内部 IP 进行 ping。退出 shell 后，容器将被自动删除。

您可以使用类似的方法为 Windows 节点创建交互式 PowerShell Pod。

# 访问 Pod 容器日志

在调试在 Kubernetes 上运行的应用程序时，容器日志提供了关键信息。您可以使用`kubectl logs`命令访问 Pod 容器日志，类似于您为 Docker CLI 所做的操作，如下所示：

```
kubectl logs etcd-docker-desktop -n kube-system
```

如果 Pod 只运行一个容器，这将起作用。如果 Pod 由多个容器组成，您需要使用`--container`或`--all-containers`标志。

此外，您可能希望尾随日志的`n`行（`--tail=n`标志）并启用日志的实时流（`--follow`标志），如下面的代码片段所示：

```
kubectl logs etcd-docker-desktop -n kube-system --tail=10 --follow
```

# 进入 Pod 容器

在调试在 Kubernetes 上运行的应用程序时，您可以像裸 Docker 容器一样`exec`到运行在 Pod 中的容器。例如，要列出容器当前工作目录中的所有文件，请使用以下`kubectl exec`命令：

```
kubectl exec nginx-deployment-example-5997d7d5fb-p9fbn -- ls -al
```

也可以附加交互式终端并运行 Bash 会话，如下所示：

```
kubectl exec nginx-deployment-example-5997d7d5fb-p9fbn -it bash
```

对于多容器 Pod，您必须使用`--container`标志，否则将选择 Pod 中的第一个容器。

# 复制 Pod 容器文件

Kubectl 为您提供了在您的计算机和 Pod 容器之间复制文件的可能性（双向），类似于 Docker CLI。例如，要将`/var/log/dpkg.log`文件从运行在`nginx-deployment-example-5997d7d5fb-p9fbn` Pod 中的容器复制到当前目录，请执行以下`kubectl cp`命令：

```
kubectl cp nginx-deployment-example-5997d7d5fb-p9fbn:/var/log/dpkg.log dpkg.log
```

一般来说，如果您将 Pod 容器用作源或目的地，您需要指定 Pod 名称和容器文件系统路径，用冒号（`:`）分隔。对于其他命令，如果 Pod 运行多个容器，您需要使用`--container`标志，否则将选择第一个容器。

# 端口转发和代理流量

Kubectl 可以充当访问您的 Kubernetes 集群的简单代理。如果需要直接从本地计算机通信到 Pod 上的特定端口，可以使用端口转发到 Pod。这可以通过使用`kubectl port-forward`命令来实现，而无需手动暴露服务对象。该命令可用于将流量转发到基于其他对象选择器自动选择的 Pod，例如 Deployment，如下所示：

```
kubectl port-forward deployment/nginx-deployment-example 7000:80
```

此命令将所有流量从本地计算机端口`7000`转发到`nginx-deployment-example` Deployment 中一个 Pod 的端口`80`。转到`http://localhost:7000`以验证默认的 nginx 页面是否可访问。完成后终止端口转发命令。

此外，kubectl 可以为您的本地机器提供访问 Kubernetes API 服务器的权限。使用`kubectl proxy`命令将 API 暴露在端口`8080`上，如下所示：

```
kubectl proxy --port=8080
```

现在，当您在浏览器中导航到`http://localhost:8080/api/v1/namespaces/default/pods`时，您将看到当前在集群中运行的 Pod 对象。恭喜您成功设置了 kubectl 端口转发！

# 摘要

在本章中，您已经学会了如何安装和使用 Kubernetes 命令行工具 kubectl。我们已经介绍了如何使用 kubectl 上下文来组织访问多个 Kubernetes 集群，以及处理开发集群的可能策略以及它们如何适用于 Windows 集群。除此之外，您现在还了解了基本的 kubectl 命令以及一些用于调试在 Kubernetes 上运行的应用程序的技术：运行临时 Pod、访问 Pod 容器日志、执行 Pod 容器内部的 exec 操作，以及在本地机器和 Pod 容器之间复制文件的几种技巧。

下一章将重点介绍在本地场景中部署混合 Linux/Windows Kubernetes 集群。我们将演示如何使用 Hyper-V VM 在本地机器上创建一个完全功能的多节点集群。

# 问题

1.  `kubeconfig`是什么？

1.  您如何为 kubectl 设置自定义的`kubeconfig`位置？

1.  kubectl 中上下文的作用是什么？

1.  `kubectl create`和`kubectl apply`命令有什么区别？

1.  什么是 kubectl 资源补丁，以及何时使用它？

1.  从 Pod 容器中显示实时日志的命令是什么？

1.  您如何使用 kubectl 在本地机器和 Pod 容器之间复制文件？

您可以在本书的*评估*部分找到这些问题的答案。

# 进一步阅读

+   有关 Kubernetes 概念和 Kubernetes CLI 的更多信息，请参阅以下 Packt 图书：

+   *完整的 Kubernetes 指南* ([`www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide`](https://www.packtpub.com/virtualization-and-cloud/complete-kubernetes-guide))

+   *开始学习 Kubernetes-第三版* ([`www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition`](https://www.packtpub.com/virtualization-and-cloud/getting-started-kubernetes-third-edition))

+   *面向开发人员的 Kubernetes* ([`www.packtpub.com/virtualization-and-cloud/kubernetes-developers`](https://www.packtpub.com/virtualization-and-cloud/kubernetes-developers))

+   您还可以参考优秀的官方 Kubernetes 文档（[`kubernetes.io/docs/home/`](https://kubernetes.io/docs/home/)）和 kubectl 参考文档（[`kubernetes.io/docs/reference/generated/kubectl/kubectl-commands`](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)）。
