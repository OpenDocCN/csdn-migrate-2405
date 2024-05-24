# 精通 Kubernetes（一）

> 原文：[`zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C`](https://zh.annas-archive.org/md5/0FB6BD53079686F120215D277D8C163C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Kubernetes 是一个开源系统，自动化部署、扩展和管理容器化应用程序。如果您运行的不仅仅是一些容器，或者想要自动化管理容器，您就需要 Kubernetes。本书重点介绍了如何通过高级管理 Kubernetes 集群。

本书首先解释了 Kubernetes 架构背后的基本原理，并详细介绍了 Kubernetes 的设计。您将了解如何在 Kubernetes 上运行复杂的有状态微服务，包括水平 Pod 自动缩放、滚动更新、资源配额和持久存储后端等高级功能。通过真实的用例，您将探索网络配置的选项，并了解如何设置、操作和排除各种 Kubernetes 网络插件。最后，您将学习自定义资源开发和在自动化和维护工作流中的利用。本书还将涵盖基于 Kubernetes 1.10 发布的一些额外概念，如 Promethus、基于角色的访问控制和 API 聚合。

通过本书，您将了解从中级到高级水平所需的一切。

# 本书适合对象

本书适用于具有 Kubernetes 中级知识水平的系统管理员和开发人员，现在希望掌握其高级功能。您还应该具备基本的网络知识。这本高级书籍为掌握 Kubernetes 提供了一条路径。

# 充分利用本书

为了跟随每一章的示例，您需要在您的计算机上安装最新版本的 Docker 和 Kubernetes，最好是 Kubernetes 1.10。如果您的操作系统是 Windows 10 专业版，您可以启用 hypervisor 模式；否则，您需要安装 VirtualBox 并使用 Linux 客户操作系统。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以从以下网址下载：[`www.packtpub.com/sites/default/files/downloads/MasteringKubernetesSecondEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/MasteringKubernetesSecondEdition_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“让我们使用`get nodes`来检查集群中的节点。”

代码块设置如下：

```
type Scheduler struct { 
    config *Config 
} 
```

任何命令行输入或输出都以以下方式编写：

```
> kubectl create -f candy.yaml
candy "chocolate" created 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“让我们点击 kubedns pod。”

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：了解 Kubernetes 架构

Kubernetes 是一个庞大的开源项目和生态系统，拥有大量的代码和功能。Kubernetes 由谷歌开发，但加入了**Cloud Native Computing Foundation**（**CNCF**），成为容器应用领域的明确领导者。简而言之，它是一个用于编排基于容器的应用程序部署、扩展和管理的平台。您可能已经了解过 Kubernetes，甚至在一些项目中使用过它，甚至在工作中使用过它。但要理解 Kubernetes 的全部内容，如何有效使用它以及最佳实践是什么，需要更多的知识。在本章中，我们将建立必要的知识基础，以充分利用 Kubernetes 的潜力。我们将首先了解 Kubernetes 是什么，Kubernetes 不是什么，以及容器编排的确切含义。然后，我们将介绍一些重要的 Kubernetes 概念，这些概念将构成我们在整本书中将使用的词汇。之后，我们将更详细地深入了解 Kubernetes 的架构，并看看它如何为用户提供所有这些功能。然后，我们将讨论 Kubernetes 支持的各种运行时和容器引擎（Docker 只是其中一种选择），最后，我们将讨论 Kubernetes 在完整的持续集成和部署流水线中的作用。

在本章结束时，您将对容器编排有扎实的了解，了解 Kubernetes 解决了哪些问题，Kubernetes 设计和架构的基本原理，以及它支持的不同运行时。您还将熟悉开源存储库的整体结构，并准备好随时跳入并找到任何问题的答案。

# Kubernetes 是什么？

Kubernetes 是一个涵盖大量服务和功能的平台，不断增长。它的核心功能是在您的基础设施中安排容器工作负载，但它并不止步于此。以下是 Kubernetes 带来的其他一些功能：

+   挂载存储系统

+   分发密钥

+   检查应用程序健康状况

+   复制应用程序实例

+   使用水平 Pod 自动缩放

+   命名和发现

+   负载均衡

+   滚动更新

+   监控资源

+   访问和摄取日志

+   调试应用程序

+   提供身份验证和授权

# Kubernetes 不是什么

Kubernetes 不是**平台即服务**（**PaaS**）。它不规定您所需系统的许多重要方面；相反，它将它们留给您或其他构建在 Kubernetes 之上的系统，如 Deis、OpenShift 和 Eldarion。例如：

+   Kubernetes 不需要特定的应用程序类型或框架

+   Kubernetes 不需要特定的编程语言

+   Kubernetes 不提供数据库或消息队列

+   Kubernetes 不区分应用程序和服务

+   Kubernetes 没有点击即部署的服务市场

+   Kubernetes 允许用户选择自己的日志记录、监控和警报系统

# 理解容器编排

Kubernetes 的主要责任是容器编排。这意味着确保执行各种工作负载的所有容器都被安排在物理或虚拟机上运行。容器必须被有效地打包，并遵循部署环境和集群配置的约束。此外，Kubernetes 必须监视所有运行的容器，并替换死掉的、无响应的或其他不健康的容器。Kubernetes 提供了许多其他功能，您将在接下来的章节中了解到。在本节中，重点是容器及其编排。

# 物理机器、虚拟机器和容器

一切都始于硬件，也以硬件结束。为了运行您的工作负载，您需要一些真实的硬件。这包括实际的物理机器，具有一定的计算能力（CPU 或核心）、内存和一些本地持久存储（旋转磁盘或固态硬盘）。此外，您还需要一些共享的持久存储和网络，以连接所有这些机器，使它们能够找到并相互通信。在这一点上，您可以在物理机器上运行多个虚拟机，或者保持裸金属级别（没有虚拟机）。Kubernetes 可以部署在裸金属集群（真实硬件）或虚拟机集群上。反过来，Kubernetes 可以在裸金属或虚拟机上直接编排它管理的容器。理论上，Kubernetes 集群可以由裸金属和虚拟机的混合组成，但这并不常见。

# 容器的好处

容器代表了大型复杂软件系统开发和运行中的真正范式转变。以下是与传统模型相比的一些好处：

+   敏捷的应用程序创建和部署

+   持续开发、集成和部署

+   开发和运维的关注点分离

+   在开发、测试和生产环境中保持环境一致性

+   云和操作系统的可移植性

+   以应用为中心的管理

+   松散耦合、分布式、弹性、自由的微服务

+   资源隔离

+   资源利用

# 云中的容器

容器非常适合打包微服务，因为它们在为微服务提供隔离的同时非常轻量，并且在部署许多微服务时不会产生很多开销，就像使用虚拟机一样。这使得容器非常适合云部署，因为为每个微服务分配整个虚拟机的成本是禁止的。

所有主要的云服务提供商，如亚马逊 AWS、谷歌的 GCE、微软的 Azure，甚至阿里巴巴云，现在都提供容器托管服务。谷歌的 GKE 一直以来都是基于 Kubernetes。AWS ECS 基于他们自己的编排解决方案。微软 Azure 的容器服务是基于 Apache Mesos 的。Kubernetes 可以部署在所有云平台上，但直到今天它才没有与其他服务深度集成。但在 2017 年底，所有云服务提供商宣布直接支持 Kubernetes。微软推出了 AKS，AWS 发布了 EKS，阿里巴巴云开始开发一个 Kubernetes 控制器管理器，以无缝集成 Kubernetes。

# 牲畜与宠物

在过去，当系统规模较小时，每台服务器都有一个名字。开发人员和用户清楚地知道每台机器上运行的软件是什么。我记得，在我工作过的许多公司中，我们经常讨论几天来决定服务器的命名主题。例如，作曲家和希腊神话人物是受欢迎的选择。一切都非常舒适。你对待你的服务器就像珍爱的宠物一样。当一台服务器死掉时，这是一场重大危机。每个人都争先恐后地想弄清楚从哪里获取另一台服务器，死掉的服务器上到底运行了什么，以及如何在新服务器上让它工作。如果服务器存储了一些重要数据，那么希望你有最新的备份，也许你甚至能够恢复它。

显然，这种方法是不可扩展的。当你有几十台或几百台服务器时，你必须开始像对待牲畜一样对待它们。你考虑的是整体，而不是个体。你可能仍然有一些宠物，但你的 Web 服务器只是牲畜。

Kubernetes 将牲畜的方法应用到了极致，并全权负责将容器分配到特定的机器上。大部分时间你不需要与单独的机器（节点）进行交互。这对于无状态的工作负载效果最好。对于有状态的应用程序，情况有些不同，但 Kubernetes 提供了一个称为 StatefulSet 的解决方案，我们很快会讨论它。

在这一部分，我们涵盖了容器编排的概念，并讨论了主机（物理或虚拟）和容器之间的关系，以及在云中运行容器的好处，并最后讨论了牲畜与宠物的区别。在接下来的部分，我们将了解 Kubernetes 的世界，并学习它的概念和术语。

# Kubernetes 概念

在这一部分，我将简要介绍许多重要的 Kubernetes 概念，并为您提供一些背景，说明它们为什么需要以及它们如何与其他概念互动。目标是熟悉这些术语和概念。稍后，我们将看到这些概念如何被编织在一起，并组织成 API 组和资源类别，以实现令人敬畏的效果。你可以把许多这些概念看作是构建块。一些概念，比如节点和主节点，被实现为一组 Kubernetes 组件。这些组件处于不同的抽象级别，我会在专门的部分* Kubernetes 组件*中详细讨论它们。

这是著名的 Kubernetes 架构图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/71bcaaf3-ee70-4f96-a1fb-41846aea760c.png)

# 集群

集群是 Kubernetes 用来运行组成系统的各种工作负载的计算、存储和网络资源的集合。请注意，您的整个系统可能由多个集群组成。我们将在后面详细讨论联邦的这种高级用例。

# 节点

一个节点是一个单独的主机。它可以是物理机或虚拟机。它的工作是运行 pod，我们马上会看到。每个 Kubernetes 节点都运行几个 Kubernetes 组件，比如 kubelet 和 kube 代理。节点由 Kubernetes 主节点管理。节点是 Kubernetes 的工作蜂，肩负着所有繁重的工作。过去，它们被称为**仆从**。如果你读过一些旧的文档或文章，不要感到困惑。仆从就是节点。

# 主节点

主节点是 Kubernetes 的控制平面。它由多个组件组成，如 API 服务器、调度程序和控制器管理器。主节点负责全局的集群级别的 pod 调度和事件处理。通常，所有主节点组件都设置在单个主机上。在考虑高可用性场景或非常大的集群时，您会希望有主节点冗余。我将在第四章中详细讨论高可用性集群，*高可用性和可靠性*。

# Pod

Pod 是 Kubernetes 中的工作单位。每个 pod 包含一个或多个容器。Pod 总是一起调度（即它们总是在同一台机器上运行）。Pod 中的所有容器具有相同的 IP 地址和端口空间；它们可以使用 localhost 或标准的进程间通信进行通信。此外，pod 中的所有容器都可以访问托管 pod 的节点上的共享本地存储。共享存储可以挂载在每个容器上。Pod 是 Kubernetes 的一个重要特性。通过在单个 Docker 容器中运行多个应用程序，例如通过将`supervisord`作为运行多个进程的主要 Docker 应用程序，可以实现这种做法，但出于以下原因，这种做法经常受到指责：

+   **透明度**：使得 pod 内的容器对基础设施可见，使得基础设施能够为这些容器提供服务，如进程管理和资源监控。这为用户提供了许多便利的功能。

+   **解耦软件依赖关系**：单个容器可以独立进行版本控制、重建和重新部署。Kubernetes 可能会支持单个容器的实时更新。

+   **易用性**：用户不需要运行自己的进程管理器，担心信号和退出代码的传播等问题。

+   **效率**：由于基础设施承担了更多的责任，容器可以更轻量化。

Pod 为管理彼此紧密相关且需要在同一主机上合作以完成其目的的容器组提供了一个很好的解决方案。重要的是要记住，pod 被认为是短暂的、可以随意丢弃和替换的实体。任何 pod 存储都会随着 pod 的丢弃而被销毁。每个 pod 都有一个**唯一 ID**（**UID**），因此在必要时仍然可以区分它们。

# 标签

标签是用于将一组对象（通常是 pod）分组在一起的键值对。这对于其他一些概念非常重要，比如复制控制器、副本集和操作动态对象组并需要识别组成员的服务。对象和标签之间存在 NxN 的关系。每个对象可能有多个标签，每个标签可能应用于不同的对象。标签有一些设计上的限制。对象上的每个标签必须具有唯一的键。标签键必须遵守严格的语法。它有两部分：前缀和名称。前缀是可选的。如果存在，则它与名称之间用斜杠(`/`)分隔，并且必须是有效的 DNS 子域。前缀最多可以有 253 个字符。名称是必需的，最多可以有 63 个字符。名称必须以字母数字字符（a-z，A-Z，0-9）开头和结尾，并且只能包含字母数字字符、点、破折号和下划线。值遵循与名称相同的限制。请注意，标签专用于识别对象，而不是附加任意元数据到对象。这就是注释的作用（请参见下一节）。

# 注释

注释允许您将任意元数据与 Kubernetes 对象关联起来。Kubernetes 只存储注释并提供它们的元数据。与标签不同，它们对允许的字符和大小限制没有严格的限制。

根据我的经验，对于复杂的系统，你总是需要这样的元数据，很高兴 Kubernetes 认识到了这个需求，并且提供了这个功能，这样你就不必自己想出一个单独的元数据存储并将对象映射到它们的元数据。

我们已经涵盖了大多数，如果不是全部，Kubernetes 的概念；我简要提到了一些其他概念。在下一节中，我们将继续探讨 Kubernetes 的架构，深入了解其设计动机、内部和实现，甚至研究源代码。

# 标签选择器

标签选择器用于根据它们的标签选择对象。基于相等性的选择器指定键名和值。有两个运算符，`=`（或`==`）和`!=`，表示基于值的相等性或不相等性。例如：

```
role = webserver  
```

这将选择所有具有该标签键和值的对象。

标签选择器可以有多个要求，用逗号分隔。例如：

```
role = webserver, application != foo  
```

基于集合的选择器扩展了功能，并允许基于多个值进行选择：

```
role in (webserver, backend)
```

# 复制控制器和副本集

复制控制器和副本集都管理由标签选择器标识的一组 pod，并确保某个特定数量始终处于运行状态。它们之间的主要区别在于，复制控制器通过名称相等来测试成员资格，而副本集可以使用基于集合的选择。副本集是更好的选择，因为它们是复制控制器的超集。我预计复制控制器在某个时候会被弃用。

Kubernetes 保证您始终会有与复制控制器或副本集中指定的相同数量的运行中的 pod。每当数量因托管节点或 pod 本身的问题而下降时，Kubernetes 都会启动新的实例。请注意，如果您手动启动 pod 并超出指定数量，复制控制器将会终止额外的 pod。

复制控制器曾经是许多工作流程的核心，比如滚动更新和运行一次性作业。随着 Kubernetes 的发展，它引入了对许多这些工作流程的直接支持，使用了专门的对象，比如**Deployment**、**Job**和**DaemonSet**。我们稍后会遇到它们。

# 服务

服务用于向用户或其他服务公开某种功能。它们通常包括一组 pod，通常由标签标识。您可以拥有提供对外部资源或直接在虚拟 IP 级别控制的 pod 的访问权限的服务。原生 Kubernetes 服务通过便捷的端点公开。请注意，服务在第 3 层（TCP/UDP）操作。Kubernetes 1.2 添加了`Ingress`对象，它提供对 HTTP 对象的访问——稍后会详细介绍。服务通过 DNS 或环境变量之一进行发布或发现。Kubernetes 可以对服务进行负载均衡，但开发人员可以选择在使用外部资源或需要特殊处理的服务的情况下自行管理负载均衡。

与 IP 地址、虚拟 IP 地址和端口空间相关的细节很多。我们将在未来的章节中深入讨论它们。

# 卷

Pod 上的本地存储是临时的，并随着 Pod 的消失而消失。有时这就是您所需要的，如果目标只是在节点的容器之间交换数据，但有时对数据的存活超过 Pod 或者需要在 Pod 之间共享数据是很重要的。卷的概念支持这种需求。请注意，虽然 Docker 也有卷的概念，但它相当有限（尽管它变得更加强大）。Kubernetes 使用自己独立的卷。Kubernetes 还支持其他容器类型，如 rkt，因此即使原则上也不能依赖 Docker 卷。

有许多卷类型。Kubernetes 目前直接支持许多卷类型，但通过**容器存储接口**（**CSI**）来扩展 Kubernetes 的现代方法是我稍后会详细讨论的。`emptyDir`卷类型在每个容器上挂载一个卷，该卷默认由主机上可用的内容支持。如果需要，您可以请求内存介质。当 Pod 因任何原因终止时，此存储将被删除。针对特定云环境、各种网络文件系统甚至 Git 存储库有许多卷类型。一个有趣的卷类型是`persistentDiskClaim`，它稍微抽象了一些细节，并使用环境中的默认持久存储（通常在云提供商中）。

# StatefulSet

Pod 会来来去去，如果您关心它们的数据，那么您可以使用持久存储。这都很好。但有时您可能希望 Kubernetes 管理分布式数据存储，例如 Kubernetes 或 MySQL Galera。这些集群存储将数据分布在唯一标识的节点上。您无法使用常规 Pod 和服务来建模。这就是`StatefulSet`的作用。如果您还记得，我之前讨论过将服务器视为宠物或牲畜以及牲畜是更好的方式。嗯，`StatefulSet`处于中间某个位置。`StatefulSet`确保（类似于复制集）在任何给定时间运行一定数量具有唯一标识的宠物。这些宠物具有以下属性：

+   可用于 DNS 的稳定主机名

+   序数索引

+   与序数和主机名相关联的稳定存储

`StatefulSet`可以帮助进行对等发现，以及添加或删除宠物。

# 秘密

Secrets 是包含敏感信息（如凭据和令牌）的小对象。它们存储在`etcd`中，可以被 Kubernetes API 服务器访问，并且可以被挂载为文件到需要访问它们的 pod 中（使用专用的秘密卷，这些卷依附在常规数据卷上）。同一个秘密可以被挂载到多个 pod 中。Kubernetes 本身为其组件创建秘密，您也可以创建自己的秘密。另一种方法是将秘密用作环境变量。请注意，pod 中的秘密始终存储在内存中（在挂载秘密的情况下为`tmpfs`），以提高安全性。

# 名称

Kubernetes 中的每个对象都由 UID 和名称标识。名称用于在 API 调用中引用对象。名称应该长达 253 个字符，并使用小写字母数字字符、破折号（`-`）和点（`.`）。如果删除一个对象，您可以创建另一个具有与已删除对象相同名称的对象，但 UID 必须在集群的生命周期内是唯一的。UID 是由 Kubernetes 生成的，所以您不必担心这个问题。

# 命名空间

命名空间是一个虚拟集群。您可以拥有一个包含多个由命名空间隔离的虚拟集群的单个物理集群。每个虚拟集群与其他虚拟集群完全隔离，它们只能通过公共接口进行通信。请注意，`node`对象和持久卷不属于命名空间。Kubernetes 可能会调度来自不同命名空间的 pod 在同一节点上运行。同样，来自不同命名空间的 pod 可以使用相同的持久存储。

在使用命名空间时，您必须考虑网络策略和资源配额，以确保对物理集群资源的适当访问和分配。

# 深入了解 Kubernetes 架构

Kubernetes 有非常雄心勃勃的目标。它旨在管理和简化在各种环境和云提供商中的分布式系统的编排、部署和管理。它提供了许多能力和服务，应该能够在所有这些多样性中工作，同时演变并保持足够简单，以便普通人使用。这是一个艰巨的任务。Kubernetes 通过遵循清晰的高级设计，并使用深思熟虑的架构来实现这一目标，促进可扩展性和可插拔性。Kubernetes 的许多部分仍然是硬编码或环境感知的，但趋势是将它们重构为插件，并保持核心的通用性和抽象性。在本节中，我们将像剥洋葱一样剥开 Kubernetes，从各种分布式系统设计模式开始，以及 Kubernetes 如何支持它们，然后介绍 Kubernetes 的机制，包括其一套 API，然后看一下组成 Kubernetes 的实际组件。最后，我们将快速浏览源代码树，以更好地了解 Kubernetes 本身的结构。

在本节结束时，您将对 Kubernetes 的架构和实现有扎实的了解，以及为什么会做出某些设计决策。

# 分布式系统设计模式

所有快乐（工作）的分布式系统都是相似的，借用托尔斯泰在《安娜·卡列尼娜》中的话。这意味着，为了正常运行，所有设计良好的分布式系统都必须遵循一些最佳实践和原则。Kubernetes 不只是想成为一个管理系统。它希望支持和促进这些最佳实践，并为开发人员和管理员提供高级服务。让我们来看看其中一些设计模式。

# 边车模式

边车模式是指在一个 pod 中除了主应用容器之外，还有另一个容器。应用容器对边车容器一无所知，只是按照自己的业务进行操作。一个很好的例子是中央日志代理。你的主容器可以直接记录到`stdout`，但是边车容器会将所有日志发送到一个中央日志服务，这样它们就会与整个系统的日志聚合在一起。使用边车容器与将中央日志添加到主应用容器中相比的好处是巨大的。首先，应用不再被中央日志所拖累，这可能会很麻烦。如果你想升级或更改你的中央日志策略，或者切换到一个全新的提供者，你只需要更新边车容器并部署它。你的应用容器都不会改变，所以你不会意外地破坏它们。

# 大使模式

大使模式是指将远程服务表示为本地服务，并可能强制执行某种策略。大使模式的一个很好的例子是，如果你有一个 Redis 集群，有一个主节点用于写入，还有许多副本用于读取。一个本地的大使容器可以作为代理，将 Redis 暴露给主应用容器在本地主机上。主应用容器只需连接到`localhost:6379`（Redis 的默认端口），但它连接到在同一个 pod 中运行的大使，大使会过滤请求，将写请求发送到真正的 Redis 主节点，将读请求随机发送到其中一个读取副本。就像我们在边车模式中看到的一样，主应用并不知道发生了什么。这在对真实的本地 Redis 进行测试时会有很大帮助。此外，如果 Redis 集群配置发生变化，只需要修改大使；主应用仍然毫不知情。

# 适配器模式

适配器模式是关于标准化主应用程序容器的输出。考虑一个逐步推出的服务的情况：它可能生成的报告格式与以前的版本不符。消费该输出的其他服务和应用程序尚未升级。适配器容器可以部署在与新应用程序容器相同的 pod 中，并可以修改其输出以匹配旧版本，直到所有消费者都已升级。适配器容器与主应用程序容器共享文件系统，因此它可以监视本地文件系统，每当新应用程序写入内容时，它立即进行适应。

# 多节点模式

Kubernetes 直接支持单节点模式，通过 pod。多节点模式，如领导者选举、工作队列和分散收集，不受直接支持，但通过使用标准接口组合 pod 来实现它们是一种可行的方法。

# Kubernetes API

如果你想了解一个系统的能力和提供的功能，你必须非常关注它的 API。这些 API 为用户提供了对系统可以做什么的全面视图。Kubernetes 通过 API 组向不同目的和受众暴露了几套 REST API。一些 API 主要由工具使用，一些可以直接由开发人员使用。关于 API 的一个重要事实是它们在不断发展。Kubernetes 开发人员通过尝试扩展它（通过向现有对象添加新对象和新字段）并避免重命名或删除现有对象和字段来使其可管理。此外，所有 API 端点都是有版本的，并且通常也有 alpha 或 beta 标记。例如：

```
/api/v1
/api/v2alpha1  
```

您可以通过`kubectl cli`、客户端库或直接通过 REST API 调用访问 API。我们将在后面的章节中探讨详细的身份验证和授权机制。如果您有适当的权限，您可以列出、查看、创建、更新和删除各种 Kubernetes 对象。在这一点上，让我们来一窥 API 的表面积。探索这些 API 的最佳方式是通过 API 组。一些 API 组是默认启用的。其他组可以通过标志启用/禁用。例如，要禁用批处理 V1 组并启用批处理 V2 alpha 组，您可以在运行 API 服务器时设置`--runtime-config`标志如下：

```
--runtime-config=batch/v1=false,batch/v2alpha=true 
```

默认情况下启用以下资源，除了核心资源：

+   `DaemonSets`

+   `Deployments`

+   `HorizontalPodAutoscalers`

+   ``Ingress``

+   `Jobs`

+   `ReplicaSets`

# 发现和负载平衡

默认情况下，工作负载只能在集群内访问，必须使用`LoadBalancer`或`NodePort`服务将其外部暴露。在开发过程中，可以通过使用`kubectl proxy`命令通过 API 主机访问内部可访问的工作负载：

+   `Endpoints`: 核心

+   `Ingress`: 扩展

+   `Service`: 核心

# 资源类别

除了 API 组之外，可用 API 的另一个有用的分类是功能。Kubernetes API 非常庞大，将其分成不同类别在你试图找到自己的路时非常有帮助。Kubernetes 定义了以下资源类别：

+   **工作负载**：您用来管理和运行集群上的容器的对象。

+   **发现和负载平衡**：您用来将工作负载暴露给外部可访问、负载平衡服务的对象。

+   **配置和存储**：您用来初始化和配置应用程序，并持久化容器外的数据的对象。

+   **集群**：定义集群本身配置的对象；这些通常只由集群操作员使用。

+   **元数据**：您用来配置集群内其他资源行为的对象，例如用于扩展工作负载的`HorizontalPodAutoscaler`。

在以下小节中，我将列出属于每个组的资源，以及它们所属的 API 组。我不会在这里指定版本，因为 API 从 alpha 迅速转移到 beta 到**一般可用性**（**GA**），然后从 V1 到 V2，依此类推。

# 工作负载 API

工作负载 API 包含以下资源：

+   `Container`: 核心

+   `CronJob`: 批处理

+   `DaemonSet`: 应用

+   `Deployment`: 应用

+   `Job`: 批处理

+   `Pod`: 核心

+   `ReplicaSet`: 应用

+   `ReplicationController`: 核心

+   `StatefulSet`: 应用

容器是由控制器使用 pod 创建的。Pod 运行容器并提供环境依赖项，如共享或持久存储卷，以及注入到容器中的配置或秘密数据。

以下是最常见操作之一的详细描述，它以 REST API 的形式获取所有 pod 的列表：

```
GET /api/v1/pods 
```

它接受各种查询参数（全部可选）：

+   `pretty`: 如果为 true，则输出将被漂亮地打印

+   `labelSelector`: 限制结果的选择器表达式

+   `watch`: 如果为 true，则会监视更改并返回事件流

+   `resourceVersion`: 仅返回在该版本之后发生的事件

+   `timeoutSeconds`: 列表或监视操作的超时

# 配置和存储

Kubernetes 的动态配置而无需重新部署是在您的 Kubernetes 集群上运行复杂分布式应用的基石：

+   `ConfigMap`: 核心

+   `Secret`: 核心

+   `PersistentVolumeClaim`: 核心

+   `StorageClass`: 存储

+   `VolumeAttachment`: 存储

# 元数据

元数据资源通常嵌入为它们配置的资源的子资源。例如，限制范围将成为 pod 配置的一部分。大多数情况下，您不会直接与这些对象交互。有许多元数据资源。您可以在[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#-strong-metadata-strong-`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#-strong-metadata-strong-)找到完整的列表。

# 集群

集群类别中的资源是为集群操作员设计的，而不是开发人员。这个类别中也有许多资源。以下是一些最重要的资源：

+   `Namespace`: 核心

+   `Node`: 核心

+   `PersistentVolume`: 核心

+   `ResourceQuota`：核心

+   `ClusterRole`: Rbac

+   `NetworkPolicy`：网络

# Kubernetes 组件

Kubernetes 集群有几个主要组件，用于控制集群，以及在每个集群节点上运行的节点组件。让我们了解所有这些组件以及它们如何一起工作。

# 主要组件

主要组件通常在一个节点上运行，但在高可用性或非常大的集群中，它们可能分布在多个节点上。

# API 服务器

Kube API 服务器公开了 Kubernetes REST API。由于它是无状态的，并且将所有数据存储在`etcd`集群中，因此可以轻松地进行水平扩展。API 服务器是 Kubernetes 控制平面的具体体现。

# Etcd

Etcd 是一个高度可靠的分布式数据存储。Kubernetes 使用它来存储整个集群状态。在一个小型的瞬态集群中，一个`etcd`的实例可以在与所有其他主要组件相同的节点上运行，但对于更大的集群，通常会有一个三节点甚至五节点的`etcd`集群，以实现冗余和高可用性。

# Kube 控制器管理器

Kube 控制器管理器是各种管理器的集合，汇总成一个二进制文件。它包含复制控制器、Pod 控制器、服务控制器、端点控制器等。所有这些管理器通过 API 监视集群的状态，它们的工作是将集群引导到期望的状态。

# 云控制器管理器

在云中运行时，Kubernetes 允许云提供商集成其平台，以管理节点、路由、服务和卷。云提供商代码与 Kubernetes 代码进行交互。它替换了 Kube 控制器管理器的一些功能。在使用云控制器管理器运行 Kubernetes 时，必须将 Kube 控制器管理器标志`--cloud-provider`设置为*external*。这将禁用云控制器管理器正在接管的控制循环。云控制器管理器是在 Kubernetes 1.6 中引入的，并且已被多个云提供商使用。

关于 Go 的一个快速说明，以帮助您解析代码：方法名首先出现，然后是方法的参数在括号中。每个参数都是一对，由名称和类型组成。最后，指定返回值。Go 允许多个返回类型。通常会返回一个`error`对象，除了实际结果。如果一切正常，`error`对象将为 nil。

这是`cloudprovider`包的主要接口：

```
package cloudprovider 

import ( 
    "errors" 
    "fmt" 
    "strings" 

    "k8s.io/api/core/v1" 
    "k8s.io/apimachinery/pkg/types" 
    "k8s.io/client-go/informers" 
    "k8s.io/kubernetes/pkg/controller" 
) 

// Interface is an abstract, pluggable interface for cloud providers. 
type Interface interface { 
    Initialize(clientBuilder controller.ControllerClientBuilder) 
    LoadBalancer() (LoadBalancer, bool) 
    Instances() (Instances, bool) 
    Zones() (Zones, bool) 
    Clusters() (Clusters, bool) 
    Routes() (Routes, bool) 
    ProviderName() string 
    HasClusterID() bool 
} 
```

大多数方法返回具有自己方法的其他接口。例如，这是`LoadBalancer`接口：

```
type LoadBalancer interface {
    GetLoadBalancer(clusterName string, 
                                 service *v1.Service) (status *v1.LoadBalancerStatus, 
                                                                   exists bool, 
                                                                   err error)
    EnsureLoadBalancer(clusterName string, 
                                       service *v1.Service, 
                                       nodes []*v1.Node) (*v1.LoadBalancerStatus, error)
    UpdateLoadBalancer(clusterName string, service *v1.Service, nodes []*v1.Node) error
    EnsureLoadBalancerDeleted(clusterName string, service *v1.Service) error
}
```

# Kube-scheduler

`kube-scheduler`负责将 Pod 调度到节点。这是一个非常复杂的任务，因为它需要考虑多个相互作用的因素，例如：

+   资源要求

+   服务要求

+   硬件/软件策略约束

+   节点亲和性和反亲和性规范

+   Pod 亲和性和反亲和性规范

+   污点和容忍

+   数据本地性

+   截止日期

如果您需要一些默认 Kube 调度程序未涵盖的特殊调度逻辑，可以用自己的自定义调度程序替换它。您还可以将自定义调度程序与默认调度程序并行运行，并且让自定义调度程序仅调度一部分 Pod。

# DNS

自 Kubernetes 1.3 以来，DNS 服务已成为标准 Kubernetes 集群的一部分。它被安排为一个常规的 pod。每个服务（除了无头服务）都会收到一个 DNS 名称。Pods 也可以收到 DNS 名称。这对于自动发现非常有用。

# 节点组件

集群中的节点需要一些组件来与集群主组件交互，并接收要执行的工作负载并更新其状态。

# 代理

Kube 代理在每个节点上进行低级别的网络维护。它在本地反映 Kubernetes 服务，并可以进行 TCP 和 UDP 转发。它通过环境变量或 DNS 找到集群 IP。

# Kubelet

kubelet 是节点上的 Kubernetes 代表。它负责与主组件通信并管理正在运行的 pod。这包括以下操作：

+   从 API 服务器下载 pod 的秘密

+   挂载卷

+   运行 pod 的容器（通过 CRI 或 rkt）

+   报告节点和每个 pod 的状态

+   运行容器的活动探测

在本节中，我们深入研究了 Kubernetes 的内部，探索了其架构（从非常高层次的角度），并支持了设计模式，通过其 API 和用于控制和管理集群的组件。在下一节中，我们将快速浏览 Kubernetes 支持的各种运行时。

# Kubernetes 运行时

Kubernetes 最初只支持 Docker 作为容器运行时引擎。但现在不再是这样。Kubernetes 现在支持几种不同的运行时：

+   `Docker`（通过 CRI shim）

+   `Rkt`（直接集成将被 rktlet 替换）

+   `Cri-o`

+   `Frakti`（在 hypervisor 上的 Kubernetes，以前是 Hypernetes）

+   `Rktlet`（rkt 的 CRI 实现）

+   `cri-containerd`

一个主要的设计政策是 Kubernetes 本身应该完全与特定的运行时解耦。**容器运行时接口**（**CRI**）使这成为可能。

在本节中，您将更仔细地了解 CRI，并了解各个运行时引擎。在本节结束时，您将能够就哪种运行时引擎适合您的用例做出明智的决定，并在何种情况下可以切换或甚至在同一系统中组合多个运行时。

# 容器运行时接口（CRI）

CRI 是一个 gRPC API，包含容器运行时与节点上的 kubelet 集成的规范/要求和库。在 Kubernetes 1.7 中，Kubernetes 中的内部 Docker 集成被 CRI-based 集成所取代。这是一件大事。它为利用容器领域的进步打开了多种实现的大门。Kubelet 不需要直接与多个运行时进行接口。相反，它可以与任何符合 CRI 的容器运行时进行通信。以下图表说明了流程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/853ca52c-c6d6-4597-9ff5-66679cb65e67.png)

有两个 gRPC 服务接口——`ImageService` 和 `RuntimeService`——CRI 容器运行时（或 shims）必须实现。`ImageService` 负责管理镜像。以下是 gRPC/protobuf 接口（这不是 Go）：

```
service ImageService { 
    rpc ListImages(ListImagesRequest) returns (ListImagesResponse) {} 
    rpc ImageStatus(ImageStatusRequest) returns (ImageStatusResponse) {} 
    rpc PullImage(PullImageRequest) returns (PullImageResponse) {} 
    rpc RemoveImage(RemoveImageRequest) returns (RemoveImageResponse) {} 
    rpc ImageFsInfo(ImageFsInfoRequest) returns (ImageFsInfoResponse) {} 
} 
```

`RuntimeService` 负责管理 pod 和容器。以下是 gRPC/profobug 接口：

```
service RuntimeService { 
    rpc Version(VersionRequest) returns (VersionResponse) {} 
    rpc RunPodSandbox(RunPodSandboxRequest) returns (RunPodSandboxResponse) {} 
    rpc StopPodSandbox(StopPodSandboxRequest) returns (StopPodSandboxResponse) {} 
    rpc RemovePodSandbox(RemovePodSandboxRequest) returns (RemovePodSandboxResponse) {} 
    rpc PodSandboxStatus(PodSandboxStatusRequest) returns (PodSandboxStatusResponse) {} 
    rpc ListPodSandbox(ListPodSandboxRequest) returns (ListPodSandboxResponse) {} 
    rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse) {} 
    rpc StartContainer(StartContainerRequest) returns (StartContainerResponse) {} 
    rpc StopContainer(StopContainerRequest) returns (StopContainerResponse) {} 
    rpc RemoveContainer(RemoveContainerRequest) returns (RemoveContainerResponse) {} 
    rpc ListContainers(ListContainersRequest) returns (ListContainersResponse) {} 
    rpc ContainerStatus(ContainerStatusRequest) returns (ContainerStatusResponse) {} 
    rpc UpdateContainerResources(UpdateContainerResourcesRequest) returns (UpdateContainerResourcesResponse) {} 
    rpc ExecSync(ExecSyncRequest) returns (ExecSyncResponse) {} 
    rpc Exec(ExecRequest) returns (ExecResponse) {} 
    rpc Attach(AttachRequest) returns (AttachResponse) {} 
    rpc PortForward(PortForwardRequest) returns (PortForwardResponse) {} 
    rpc ContainerStats(ContainerStatsRequest) returns (ContainerStatsResponse) {} 
    rpc ListContainerStats(ListContainerStatsRequest) returns (ListContainerStatsResponse) {} 
    rpc UpdateRuntimeConfig(UpdateRuntimeConfigRequest) returns (UpdateRuntimeConfigResponse) {} 
    rpc Status(StatusRequest) returns (StatusResponse) {} 
} 
```

用作参数和返回类型的数据类型称为消息，并且也作为 API 的一部分进行定义。以下是其中之一：

```
message CreateContainerRequest { 
    string pod_sandbox_id = 1; 
    ContainerConfig config = 2; 
    PodSandboxConfig sandbox_config = 3; 
} 
```

正如您所看到的，消息可以嵌套在彼此之内。`CreateContainerRequest` 消息有一个字符串字段和另外两个字段，它们本身也是消息：`ContainerConfig` 和 `PodSandboxConfig`。

现在您已经在代码级别熟悉了 Kubernetes 运行时引擎，让我们简要地看一下各个运行时引擎。

# Docker

当然，Docker 是容器的大象级存在。Kubernetes 最初设计仅用于管理 Docker 容器。多运行时功能首次在 Kubernetes 1.3 中引入，而 CRI 则在 Kubernetes 1.5 中引入。在那之前，Kubernetes 只能管理 Docker 容器。

如果您正在阅读本书，我假设您非常熟悉 Docker 及其带来的功能。Docker 受到了巨大的欢迎和增长，但也受到了很多批评。批评者经常提到以下关注点：

+   安全性

+   难以设置多容器应用程序（特别是网络）

+   开发、监控和日志记录

+   Docker 容器运行一个命令的限制

+   发布不完善的功能太快

Docker 意识到了这些批评，并解决了其中一些问题。特别是，Docker 已经投资于其 Docker Swarm 产品。Docker Swarm 是一个与 Kubernetes 竞争的 Docker 本地编排解决方案。它比 Kubernetes 更容易使用，但不如 Kubernetes 强大或成熟。

自 Docker 1.12 以来，swarm 模式已经内置在 Docker 守护程序中，这让一些人感到不满，因为它的臃肿和范围扩大。这反过来使更多的人转向 CoreOS rkt 作为替代解决方案。

自 Docker 1.11 发布于 2016 年 4 月以来，Docker 已经改变了运行容器的方式。运行时现在使用`containerd`和`runC`来在容器中运行**Open Container Initiative**（OCI）图像：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/c47c6e50-6bdf-4ffe-9a40-b4f39bdc0b77.png)

# Rkt

Rkt 是来自 CoreOS 的容器管理器（CoreOS Linux 发行版、etcd、flannel 等的开发者）。Rkt 运行时以其简单性和对安全性和隔离性的强调而自豪。它没有像 Docker 引擎那样的守护程序，而是依赖于操作系统的 init 系统，比如`systemd`，来启动 rkt 可执行文件。Rkt 可以下载图像（包括**应用容器**（appc）图像和 OCI 图像），验证它们，并在容器中运行。它的架构要简单得多。

# 应用容器

CoreOS 在 2014 年 12 月启动了一个名为 appc 的标准化工作。这包括标准图像格式（ACI）、运行时、签名和发现。几个月后，Docker 开始了自己的标准化工作，推出了 OCI。目前看来，这些努力将会融合。这是一件好事，因为工具、图像和运行时将能够自由地互操作。但我们还没有达到这一点。

# Cri-O

Cri-o 是一个 Kubernetes 孵化器项目。它旨在为 Kubernetes 和符合 OCI 标准的容器运行时（如 Docker）之间提供集成路径。其想法是 Cri-O 将提供以下功能：

+   支持多种图像格式，包括现有的 Docker 图像格式

+   支持多种下载图像的方式，包括信任和图像验证

+   容器镜像管理（管理镜像层、叠加文件系统等）

+   容器进程生命周期管理

+   满足 CRI 所需的监控和日志记录

+   根据 CRI 所需的资源隔离

然后任何符合 OCI 标准的容器运行时都可以被插入，并将与 Kubernetes 集成。

# Rktnetes

Rktnetes 是 Kubernetes 加上 rkt 作为运行时引擎。Kubernetes 仍在抽象化运行时引擎的过程中。Rktnetes 实际上并不是一个单独的产品。从外部来看，只需要在每个节点上运行 Kubelet 并加上几个命令行开关。

# rkt 准备好投入生产使用了吗？

我对 rkt 没有太多的实际经验。然而，它被 Tectonic 使用——这是基于 CoreOS 的商业 Kubernetes 发行版。如果你运行不同类型的集群，我建议你等到 rkt 通过 CRI/rktlet 与 Kubernetes 集成。在使用 rkt 与 Kubernetes 相比，有一些已知的问题需要注意，例如，缺少的卷不会自动创建，Kubectl 的 attach 和 get logs 不起作用，以及`init`容器不受支持，还有其他问题。

# 超级容器

超级容器是另一个选择。超级容器具有轻量级虚拟机（自己的客户机内核），并在裸金属上运行。它不依赖于 Linux cgroups 进行隔离，而是依赖于一个虚拟化程序。与难以设置的标准裸金属集群和在重量级虚拟机上部署容器的公共云相比，这种方法呈现出有趣的混合。

# Stackube

Stackube（之前称为 Hypernetes）是一个多租户分发，它使用超级容器以及一些 OpenStack 组件进行身份验证、持久存储和网络。由于容器不共享主机内核，因此可以安全地在同一物理主机上运行不同租户的容器。当然，Stackube 使用 Frakti 作为其容器运行时。

在本节中，我们已经涵盖了 Kubernetes 支持的各种运行时引擎，以及标准化和融合的趋势。在下一节中，我们将退一步，看看整体情况，以及 Kubernetes 如何适应 CI/CD 流水线。

# 持续集成和部署

Kubernetes 是运行基于微服务的应用程序的绝佳平台。但归根结底，它只是一个实现细节。用户，甚至大多数开发人员，可能不知道系统是部署在 Kubernetes 上的。但 Kubernetes 可以改变游戏规则，使以前难以实现的事情成为可能。

在本节中，我们将探讨 CI/CD 流水线以及 Kubernetes 带来了什么。在本节结束时，您将能够设计利用 Kubernetes 属性的 CI/CD 流水线，例如易扩展性和开发-生产一致性，以提高您日常开发和部署的生产力和稳健性。

# 什么是 CI/CD 流水线？

CI/CD 流水线是由开发人员或运营人员实施的一组步骤，用于修改系统的代码、数据或配置，对其进行测试，并将其部署到生产环境。一些流水线是完全自动化的，而一些是半自动化的，需要人工检查。在大型组织中，可能会有测试和暂存环境，更改会自动部署到这些环境，但发布到生产环境需要手动干预。下图描述了一个典型的流水线。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/07f96ca6-443c-4e47-a9f2-f3b8dc886bf4.png)

值得一提的是，开发人员可以完全与生产基础设施隔离开来。他们的接口只是一个 Git 工作流程——Deis 工作流程（在 Kubernetes 上的 PaaS；类似于 Heroku）就是一个很好的例子。

# 为 Kubernetes 设计 CI/CD 流水线

当你的部署目标是一个 Kubernetes 集群时，你应该重新思考一些传统的做法。首先，打包是不同的。你需要为你的容器烘焙镜像。使用智能标签可以轻松且即时地回滚代码更改。这给了你很多信心，即使一个糟糕的更改通过了测试网，你也能立即回滚到上一个版本。但你要小心。模式更改和数据迁移不能自动回滚。

Kubernetes 的另一个独特能力是开发人员可以在本地运行整个集群。当你设计你的集群时，这需要一些工作，但由于构成系统的微服务在容器中运行，并且这些容器通过 API 进行交互，这是可能和实际可行的。与往常一样，如果你的系统非常依赖数据，你需要为此做出调整，并提供数据快照和合成数据供开发人员使用。

# 摘要

在本章中，我们涵盖了很多内容，你了解了 Kubernetes 的设计和架构。Kubernetes 是一个用于运行容器化微服务应用程序的编排平台。Kubernetes 集群有主节点和工作节点。容器在 pod 中运行。每个 pod 在单个物理或虚拟机上运行。Kubernetes 直接支持许多概念，如服务、标签和持久存储。您可以在 Kubernetes 上实现各种分布式系统设计模式。容器运行时只需实现 CRI。支持 Docker、rkt、Hyper 容器等等。

在第二章中，*创建 Kubernetes 集群*，我们将探讨创建 Kubernetes 集群的各种方式，讨论何时使用不同的选项，并构建一个多节点集群。


# 第二章：创建 Kubernetes 集群

在上一章中，我们了解了 Kubernetes 的全部内容，它的设计方式，支持的概念，如何使用其运行时引擎，以及它如何适用于 CI/CD 流水线。

创建 Kubernetes 集群是一项非常重要的任务。有许多选择和工具可供选择，需要考虑许多因素。在本章中，我们将动手构建一些 Kubernetes 集群。我们还将讨论和评估诸如 Minikube、kubeadm、kube-spray、bootkube 和 stackube 等工具。我们还将研究部署环境，如本地、云和裸机。我们将涵盖的主题如下：

+   使用 Minikube 创建单节点集群

+   使用 kubeadm 创建多节点集群

+   在云中创建集群

+   从头开始创建裸机集群

+   审查其他创建 Kubernetes 集群的选项

在本章结束时，您将对创建 Kubernetes 集群的各种选项有扎实的了解，并了解支持创建 Kubernetes 集群的最佳工具；您还将构建一些集群，包括单节点和多节点。

# 使用 Minikube 快速创建单节点集群

在本节中，我们将在 Windows 上创建一个单节点集群。我们之所以使用 Windows，是因为 Minikube 和单节点集群对于本地开发者机器非常有用。虽然 Kubernetes 通常在生产环境中部署在 Linux 上，但许多开发人员使用 Windows PC 或 Mac。也就是说，如果您确实想在 Linux 上安装 Minikube，也没有太多区别：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/60646c29-b79f-4add-9880-40725cee6321.jpg)

# 准备工作

在创建集群之前，有一些先决条件需要安装。这些包括 VirtualBox，用于 Kubernetes 的`kubectl`命令行界面，当然还有 Minikube 本身。以下是撰写时的最新版本列表：

+   **VirtualBox**: [`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

+   **Kubectl**: [`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

+   **Minikube**: [`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)

# 在 Windows 上

安装 VirtualBox 并确保 kubectl 和 Minikube 在你的路径上。我个人只是把我使用的所有命令行程序都放在 `c:\windows` 中。你可能更喜欢另一种方法。我使用优秀的 ConEMU 来管理多个控制台、终端和 SSH 会话。它可以与 `cmd.exe`、PowerShell、PuTTY、Cygwin、msys 和 Git-Bash 一起使用。在 Windows 上没有比这更好的了。

在 Windows 10 Pro 中，你可以选择使用 Hyper-V hypervisor。这在技术上是比 VirtualBox 更好的解决方案，但它需要 Windows 的专业版，并且完全是 Windows 特有的。当使用 VirtualBox 时，这些说明是通用的，并且很容易适应其他版本的 Windows，或者其他操作系统。如果你已经启用了 Hyper-V，你必须禁用它，因为 VirtualBox 无法与 Hyper-V 共存。

我建议在管理员模式下使用 PowerShell。你可以将以下别名和函数添加到你的 PowerShell 配置文件中：

```
Set-Alias -Name k -Value kubectl 
function mk  
{  
minikube-windows-amd64 ` 
--show-libmachine-logs ` 
--alsologtostderr      ` 
@args 
} 
```

# 在 macOS 上

你可以在你的 `.bashrc` 文件中添加别名（类似于 Windows 上的 PowerShell 别名和函数）：

```
alias k='kubectl' 
alias mk='/usr/local/bin/minikube' 
```

现在我可以使用 `k` 和 `mk` 并且输入更少。`mk` 函数中的 Minikube 标志提供更好的日志记录方式，并将输出直接输出到控制台，以及文件中（类似于 tee）。

输入 `mk version` 来验证 Minikube 是否正确安装并运行：

```
> mk version 

minikube version: v0.26.0 
```

输入 `k version` 来验证 kubectl 是否正确安装并运行：

```
> k version
Client Version: version.Info{Major:"1", Minor:"9", GitVersion:"v1.9.0", GitCommit:"925c127ec6b946659ad0fd596fa959be43f0cc05", GitTreeState:"clean", BuildDate:"2017-12-16T03:15:38Z", GoVersion:"go1.9.2", Compiler:"gc", Platform:"darwin/amd64"}
Unable to connect to the server: dial tcp 192.168.99.100:8443: getsockopt: operation timed out
```

不要担心最后一行的错误。没有运行的集群，所以 kubectl 无法连接到任何东西。这是预期的。

你可以探索 Minikube 和 kubectl 的可用命令和标志。我不会逐个介绍每一个，只介绍我使用的命令。

# 创建集群

Minikube 工具支持多个版本的 Kubernetes。在撰写本文时，支持的版本列表如下：

```
> mk get-k8s-versions 
The following Kubernetes versions are available when using the localkube bootstrapper:  
- v1.10.0
- v1.9.4
- v1.9.0 
- v1.8.0 
- v1.7.5 
- v1.7.4 
- v1.7.3 
- v1.7.2 
- v1.7.0 
- v1.7.0-rc.1 
- v1.7.0-alpha.2 
- v1.6.4 
- v1.6.3 
- v1.6.0 
- v1.6.0-rc.1 
- v1.6.0-beta.4 
- v1.6.0-beta.3 
- v1.6.0-beta.2 
- v1.6.0-alpha.1 
- v1.6.0-alpha.0 
- v1.5.3 
- v1.5.2 
- v1.5.1 
- v1.4.5 
- v1.4.3 
- v1.4.2 
- v1.4.1 
- v1.4.0 
- v1.3.7 
- v1.3.6 
- v1.3.5 
- v1.3.4 
- v1.3.3 
- v1.3.0 
```

我将选择 1.10.0，最新的稳定版本。让我们使用 `start` 命令并指定 v1.10.0 作为版本来创建集群。

这可能需要一段时间，因为 Minikube 可能需要下载镜像，然后设置本地集群。让它运行就好了。这是预期的输出（在 Mac 上）：

```
> mk start --kubernetes-version="v1.10.0" 
Starting local Kubernetes v1.10.0 cluster... 
Starting VM... 
Getting VM IP address... 
Moving files into cluster... 
Finished Downloading kubeadm v1.10.0 **Finished Downloading kubelet v1.10.0** Setting up certs... 
Connecting to cluster... 
Setting up kubeconfig... 
Starting cluster components... 
Kubectl is now configured to use the cluster. 
Loading cached images from config file. 
```

让我们通过跟踪输出来回顾 Minikube 的操作。当从头开始创建集群时，你需要做很多这样的操作：

1.  启动 VirtualBox 虚拟机

1.  为本地机器和虚拟机创建证书

1.  下载镜像

1.  在本地机器和虚拟机之间设置网络

1.  在虚拟机上运行本地 Kubernetes 集群

1.  配置集群

1.  启动所有 Kubernetes 控制平面组件

1.  配置 kubectl 以与集群通信

# 故障排除

如果在过程中出现问题，请尝试遵循错误消息。您可以添加`--alsologtostderr`标志以从控制台获取详细的错误信息。Minikube 所做的一切都整齐地组织在`~/.minikube`下。以下是目录结构：

```
> tree ~/.minikube -L 2
/Users/gigi.sayfan/.minikube
├── addons
├── apiserver.crt
├── apiserver.key
├── ca.crt
├── ca.key
├── ca.pem
├── cache
│ ├── images
│ ├── iso
│ └── localkube
├── cert.pem
├── certs
│ ├── ca-key.pem
│ ├── ca.pem
│ ├── cert.pem
│ └── key.pem
├── client.crt
├── client.key
├── config
│ └── config.json
├── files
├── key.pem
├── last_update_check
├── logs
├── machines
│ ├── minikube
│ ├── server-key.pem
│ └── server.pem
├── profiles
│ └── minikube
├── proxy-client-ca.crt
├── proxy-client-ca.key
├── proxy-client.crt
└── proxy-client.key

13 directories, 21 files
```

# 检查集群

既然我们已经有一个运行中的集群，让我们来看看里面。

首先，让我们`ssh`进入虚拟机：

```
> mk ssh
 _ _
 _ _ ( ) ( )
 ___ ___ (_) ___ (_)| |/') _ _ | |_ __
/' _ ` _ `\| |/' _ `\| || , < ( ) ( )| '_`\ /'__`\
| ( ) ( ) || || ( ) || || |\`\ | (_) || |_) )( ___/
(_) (_) (_)(_)(_) (_)(_)(_) (_)`\___/'(_,__/'`\____)

$ uname -a

Linux minikube 4.9.64 #1 SMP Fri Mar 30 21:27:22 UTC 2018 x86_64 GNU/Linux$ 
```

太棒了！成功了。奇怪的符号是`minikube`的 ASCII 艺术。现在，让我们开始使用`kubectl`，因为它是 Kubernetes 的瑞士军刀，并且对所有集群（包括联合集群）都很有用。

我们将在我们的旅程中涵盖许多`kubectl`命令。首先，让我们使用`cluster-info`检查集群状态：

```
> k cluster-info    
```

Kubernetes 主节点正在运行在`https://192.168.99.101:8443`

KubeDNS 正在运行在`https://192.168.99.1010:8443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy`

要进一步调试和诊断集群问题，请使用`kubectl cluster-info dump`。您可以看到主节点正在正常运行。要以 JSON 类型查看集群中所有对象的更详细视图，请使用`k cluster-info dump`。输出可能有点令人生畏，因此让我们使用更具体的命令来探索集群。

让我们使用`get nodes`检查集群中的节点：

```
> k get nodes
NAME       STATUS    ROLES     AGE       VERSION

NAME       STATUS    ROLES     AGE       VERSION
minikube   Ready      master   15m       v1.10.0  
```

所以，我们有一个名为`minikube`的节点。要获取有关它的大量信息，请输入`k describe node minikube`。输出是冗长的；我会让您自己尝试。

# 做工作

我们有一个漂亮的空集群正在运行（好吧，不完全是空的，因为 DNS 服务和仪表板作为`kube-system`命名空间中的 pod 运行）。现在是时候运行一些 pod 了。让我们以`echo`服务器为例：

```
k run echo --image=gcr.io/google_containers/echoserver:1.8 --port=8080 deployment "echo" created  
```

Kubernetes 创建了一个部署，我们有一个正在运行的 pod。注意`echo`前缀：

```
> k get pods  
NAME                    READY    STATUS    RESTARTS    AGE echo-69f7cfb5bb-wqgkh    1/1     Running     0          18s  
```

要将我们的 pod 公开为服务，请输入以下内容：

```
> k expose deployment echo --type=NodePort service "echo" exposed  
```

将服务公开为`NodePort`类型意味着它对主机公开端口，但它不是我们在其上运行 pod 的`8080`端口。端口在集群中映射。要访问服务，我们需要集群 IP 和公开的端口：

```
> mk ip
192.168.99.101
> k get service echo --output='jsonpath="{.spec.ports[0].nodePort}"'
30388  
```

现在我们可以访问`echo`服务，它会返回大量信息：

```
> curl http://192.168.99.101:30388/hi  
```

恭喜！您刚刚创建了一个本地 Kubernetes 集群并部署了一个服务。

# 使用仪表板检查集群

Kubernetes 有一个非常好的 web 界面，当然是部署为一个 pod 中的服务。仪表板设计得很好，提供了对集群的高级概述，还可以深入到单个资源，查看日志，编辑资源文件等。当你想要手动检查你的集群时，它是一个完美的武器。要启动它，输入`minikube dashboard`。

Minikube 将打开一个带有仪表板 UI 的浏览器窗口。请注意，在 Windows 上，Microsoft Edge 无法显示仪表板。我不得不在不同的浏览器上运行它。

这是工作负载视图，显示部署、副本集、复制控制器和 Pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/cc5421c1-7fb6-4997-993a-5b8f1e0f30dc.png)

它还可以显示守护进程集、有状态集和作业，但在这个集群中我们没有这些。

在这一部分，我们在 Windows 上创建了一个本地的单节点 Kubernetes 集群，使用`kubectl`进行了一些探索，部署了一个服务，并尝试了 web UI。在下一部分，我们将继续创建一个多节点集群。

# 使用 kubeadm 创建一个多节点集群

在这一部分，我将向您介绍`kubeadm`，这是在所有环境中创建 Kubernetes 集群的推荐工具。它仍在积极开发中，但这是因为它是 Kubernetes 的一部分，并且始终体现最佳实践。为了使其对整个集群可访问，我们将以虚拟机为基础。这一部分是为那些想要亲自部署多节点集群的读者准备的。

# 设定期望

在踏上这段旅程之前，我想明确指出，这可能*不会*一帆风顺。`kubeadm`的任务很艰巨：它必须跟随 Kubernetes 本身的发展，而 Kubernetes 是一个不断变化的目标。因此，它并不总是稳定的。当我写第一版《精通 Kubernetes》时，我不得不深入挖掘并寻找各种解决方法来使其正常工作。猜猜？我在第二版中也不得不做同样的事情。准备好做一些调整并寻求帮助。如果你想要一个更简化的解决方案，我将在后面讨论一些非常好的选择。

# 准备工作

Kubeadm 在预配置的硬件（物理或虚拟）上运行。在创建 Kubernetes 集群之前，我们需要准备一些虚拟机并安装基本软件，如`docker`、`kubelet`、`kubeadm`和`kubectl`（仅在主节点上需要）。

# 准备一个 vagrant 虚拟机集群

以下 vagrant 文件将创建一个名为`n1`，`n2`，`n3`和`n4`的四个 VM 的集群。键入`vagrant up`以启动并运行集群。它基于 Bento/Ubuntu 版本 16.04，而不是 Ubuntu/Xenial，后者存在各种问题：

```
# -*- mode: ruby -*- 
# vi: set ft=ruby : 
hosts = { 
  "n1" => "192.168.77.10", 
  "n2" => "192.168.77.11", 
  "n3" => "192.168.77.12", 
  "n4" => "192.168.77.13" 
} 
Vagrant.configure("2") do |config| 
  # always use Vagrants insecure key 
  config.ssh.insert_key = false 
  # forward ssh agent to easily ssh into the different machines 
  config.ssh.forward_agent = true 

  check_guest_additions = false 
  functional_vboxsf     = false 

  config.vm.box = "bento/ubuntu-16.04" 
 hosts.each do |name, ip| 
    config.vm.hostname = name 
    config.vm.define name do |machine| 
      machine.vm.network :private_network, ip: ip 
      machine.vm.provider "virtualbox" do |v| 
        v.name = name 
      end 
    end 
  end 
end 

```

# 安装所需的软件

我非常喜欢 Ansible 进行配置管理。我在运行 Ubuntu 16.04 的`n4` VM 上安装了它。从现在开始，我将使用`n4`作为我的控制机器，这意味着我们正在在 Linux 环境中操作。我可以直接在我的 Mac 上使用 Ansible，但由于 Ansible 无法在 Windows 上运行，我更喜欢更通用的方法：

```
> vagrant ssh n4
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)

* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.
   vagrant@vagrant:~$ sudo apt-get -y --fix-missing install python-pip ￼sshpass
vagrant@vagrant:~$ sudo pip install  ansible   
```

我使用的是 2.5.0 版本。你应该使用最新版本：

```
vagrant@vagrant:~$ ansible --version
ansible 2.5.0
 config file = None
 configured module search path = [u'/home/vagrant/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
 ansible python module location = /home/vagrant/.local/lib/python2.7/site-packages/ansible
 executable location = /home/vagrant/.local/bin/ansible

 python version = 2.7.12 (default, Dec 4 2017, 14:50:18) [GCC 5.4.0 20160609] 
python version = 2.7.12 (default, Dec 4 2017, 14:50:18) [GCC 5.4.0 20160609]
```

我安装的`sshpass`程序将帮助`ansible`连接到所有带有内置 vagrant 用户的 vagrant VM。这仅对本地基于 VM 的多节点集群重要。

我创建了一个名为`ansible`的目录，并在其中放置了三个文件：`hosts`，`vars.yml`和`playbook.yml`。

# 主机文件

`host`文件是清单文件，告诉`ansible`目录要在哪些主机上操作。这些主机必须可以从控制机器进行 SSH 访问。以下是将安装集群的三个 VM：

```
[all] 
192.168.77.10 ansible_user=vagrant ansible_ssh_pass=vagrant 
192.168.77.11 ansible_user=vagrant ansible_ssh_pass=vagrant 
192.168.77.12 ansible_user=vagrant ansible_ssh_pass=vagrant 
```

# vars.yml 文件

`vars.yml`文件只是保留了我想要在每个节点上安装的软件包列表。`vim`，`htop`和`tmux`是我在需要管理的每台机器上安装的喜爱软件包。其他软件包是 Kubernetes 所需的：

```
--- 
PACKAGES: 
  - vim  - htop  - tmux  - docker.io 
  - kubelet 
  - kubeadm 
  - kubectl 
  - kubernetes-cni
```

# playbook.yml 文件

`playbook.yml`文件是您在所有主机上安装软件包时运行的文件：

```
---  
- hosts: all  
  become: true  
  vars_files:  
    - vars.yml  
  strategy: free  

  tasks: 
   - name: hack to resolve Problem with MergeList Issue 
     shell: 'find /var/lib/apt/lists -maxdepth 1 -type f -exec rm -v {} \;' 
   - name: update apt cache directly (apt module not reliable) 
     shell: 'apt-get clean && apt-get update' 
   - name: Preliminary installation     
     apt:  name=apt-transport-https force=yes 
   - name: Add the Google signing key  
     apt_key: url=https://packages.cloud.google.com/apt/doc/apt-key.gpg  state=present  
   - name: Add the k8s APT repo  
     apt_repository: repo='deb http://apt.kubernetes.io/ kubernetes-xenial main' state=present  
   - name: update apt cache directly (apt module not reliable) 
     shell: 'apt-get update'      
   - name: Install packages  
     apt: name={{ item }} state=installed force=yes 
     with_items: "{{ PACKAGES }}"  
```

由于一些软件包来自 Kubernetes APT 存储库，我需要添加它，以及 Google 签名密钥：

连接到`n4`：

```
> vagrant ssh n4  
```

您可能需要对`n1`，`n2`和`n3`节点中的每一个进行一次`ssh`：

```
vagrant@vagrant:~$ ssh 192.168.77.10
vagrant@vagrant:~$ ssh 192.168.77.11
vagrant@vagrant:~$ ssh 192.168.77.12 
```

一个更持久的解决方案是添加一个名为`~/.ansible.cfg`的文件，其中包含以下内容：

```
[defaults]
host_key_checking = False      
```

从`n4`运行 playbook 如下：

```
vagrant@n4:~$ ansible-playbook -i hosts playbook.yml  
```

如果遇到连接失败，请重试。Kubernetes APT 存储库有时会响应缓慢。您只需要对每个节点执行一次此操作。

# 创建集群

现在是创建集群本身的时候了。我们将在第一个 VM 上初始化主节点，然后设置网络并将其余的 VM 添加为节点。

# 初始化主节点

让我们在`n1`（`192.168.77.10`）上初始化主节点。在基于 vagrant VM 的云环境中，使用`--apiserver-advertise-address`标志是至关重要的：

```
> vagrant ssh n1

vagrant@n1:~$ sudo kubeadm init --apiserver-advertise-address 192.168.77.10  
```

在 Kubernetes 1.10.1 中，这导致了以下错误消息：

```
[init] Using Kubernetes version: v1.10.1
[init] Using Authorization modes: [Node RBAC]
[preflight] Running pre-flight checks.
 [WARNING FileExisting-crictl]: crictl not found in system path
[preflight] Some fatal errors occurred:
 [ERROR Swap]: running with swap on is not supported. Please disable swap
[preflight] If you know what you are doing, you can make a check non-fatal with `--ignore-preflight-errors=...`
```

原因是默认情况下未安装所需的 cri-tools。我们正在处理 Kubernetes 的最前沿。我创建了一个额外的 playbook 来安装 Go 和 cri-tools，关闭了交换，并修复了 vagrant VM 的主机名：

```
---
- hosts: all
 become: true
 strategy: free
 tasks:
 - name: Add the longsleep repo for recent golang version
 apt_repository: repo='ppa:longsleep/golang-backports' state=present
 - name: update apt cache directly (apt module not reliable)
 shell: 'apt-get update'
 args:
 warn: False
 - name: Install Go
 apt: name=golang-go state=present force=yes
 - name: Install crictl
 shell: 'go get github.com/kubernetes-incubator/cri-tools/cmd/crictl'
 become_user: vagrant
 - name: Create symlink in /usr/local/bin for crictl
 file:
 src: /home/vagrant/go/bin/crictl
 dest: /usr/local/bin/crictl
 state: link
 - name: Set hostname properly
 shell: "hostname n$((1 + $(ifconfig | grep 192.168 | awk '{print $2}' | tail -c 2)))"
 - name: Turn off swap
 shell: 'swapoff -a'
 –
```

记得再次在`n4`上运行它，以更新集群中的所有节点。

以下是成功启动 Kubernetes 的一些输出：

```
vagrant@n1:~$ sudo kubeadm init --apiserver-advertise-address 192.168.77.10
[init] Using Kubernetes version: v1.10.1
[init] Using Authorization modes: [Node RBAC]
[certificates] Generated ca certificate and key.
[certificates] Generated apiserver certificate and key.
[certificates] Valid certificates and keys now exist in "/etc/kubernetes/pki"
.
.
.
[addons] Applied essential addon: kube-dns
[addons] Applied essential addon: kube-proxy
Your Kubernetes master has initialized successfully!
```

以后加入其他节点到集群时，你需要写下更多的信息。要开始使用你的集群，你需要以普通用户身份运行以下命令：

```
vagrant@n1:~$ mkdir -p $HOME/.kube
vagrant@n1:~$ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
vagrant@n1:~$ sudo chown $(id -u):$(id -g) $HOME/.kube/config 
```

现在你可以通过在每个节点上以 root 身份运行一个命令来加入任意数量的机器。使用从`kubeadm init`命令返回的命令：`sudo kubeadm join --token << token>> --discovery-token-ca-cert-hash <<discvery token>> --skip-prflight-cheks`。

# 设置 Pod 网络

集群的网络是重中之重。Pod 需要能够相互通信。这需要一个 Pod 网络插件。有几种选择。由`kubeadm`生成的集群需要基于 CNI 的插件。我选择使用 Weave Net 插件，它支持网络策略资源。你可以选择任何你喜欢的。

在主 VM 上运行以下命令：

```
vagrant@n1:~$ sudo sysctl net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-iptables = 1vagrant@n1:~$ kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"      
```

你应该看到以下内容：

```
serviceaccount "weave-net" created
clusterrole.rbac.authorization.k8s.io "weave-net" created
clusterrolebinding.rbac.authorization.k8s.io "weave-net" created
role.rbac.authorization.k8s.io "weave-net" created
rolebinding.rbac.authorization.k8s.io "weave-net" created
daemonset.extensions "weave-net" created  
```

要验证，请使用以下命令：

```
vagrant@n1:~$ kubectl get po --all-namespaces 
NAMESPACE NAME READY STATUS RESTARTS AGE
kube-system etcd-n1 1/1 Running 0 2m
kube-system kube-apiserver-n1 1/1 Running 0 2m
kube-system kube-controller-manager-n1 1/1 Running 0 2m
kube-system kube-dns-86f4d74b45-jqctg 3/3 Running 0 3m
kube-system kube-proxy-l54s9 1/1 Running 0 3m
kube-system kube-scheduler-n1 1/1 Running 0 2m
kube-system weave-net-fl7wn 2/2 Running 0 31s
```

最后一个 Pod 是我们的`weave-net-fl7wn`，这正是我们要找的，以及`kube-dns pod`。两者都在运行。一切都很好！

# 添加工作节点

现在我们可以使用之前获得的令牌将工作节点添加到集群中。在每个节点上，运行以下命令（不要忘记`sudo`）并使用在主节点上初始化 Kubernetes 时获得的令牌：

```
sudo kubeadm join --token <<token>>  --discovery-token-ca-cert-hash  <<discovery token>> --ignore-preflight-errors=all  
```

在撰写本书时（使用 Kubernetes 1.10），一些预检查失败，但这是一个错误的负面结果。实际上一切都很好，你可以通过添加`--ignore-preflight-errors=all`来跳过这些预检查。希望当你阅读本书时，这些问题已经解决。你应该看到以下内容：

```
[discovery] Trying to connect to API Server "192.168.77.10:6443"
[discovery] Created cluster-info discovery client, requesting info from "https://192.168.77.10:6443"
[discovery] Requesting info from "https://192.168.77.10:6443" again to validate TLS against the pinned public key
[discovery] Cluster info signature and contents are valid and TLS certificate validates against pinned roots, will use API Server "192.168.77.10:6443"
[discovery] Successfully established connection with API Server "192.168.77.10:6443"     
```

此节点已加入集群：

```
* Certificate signing request was sent to master and a response
  was received.
* The Kubelet was informed of the new secure connection details.  
```

在主节点上运行`kubectl get nodes`，查看此节点加入集群。

由于 CNI 插件初始化的问题，某些组合可能无法正常工作。

# 在云中创建集群（GCP，AWS 和 Azure）

在本地创建集群很有趣，在开发过程中以及在尝试在本地解决问题时很重要。但最终，Kubernetes 是为云原生应用程序（在云中运行的应用程序）而设计的。Kubernetes 不希望了解单个云环境，因为这不可扩展。相反，Kubernetes 具有云提供程序接口的概念。每个云提供程序都可以实现此接口，然后托管 Kubernetes。请注意，截至 1.5 版本，Kubernetes 仍在其树中维护许多云提供程序的实现，但在将来，它们将被重构。

# 云提供程序接口

云提供程序接口是一组 Go 数据类型和接口。它在一个名为`cloud.go`的文件中定义，可在[`bit.ly/2fq4NbW`](http://bit.ly/2fq4NbW)上找到。这是主要接口：

```
type Interface interface { 
    Initialize(clientBuilder controller.ControllerClientBuilder) 
    LoadBalancer() (LoadBalancer, bool) 
    Instances() (Instances, bool) 
    Zones() (Zones, bool) 
    Clusters() (Clusters, bool) 
    Routes() (Routes, bool) 
    ProviderName() string 
    HasClusterID() bool 
} 
```

这很清楚。Kubernetes 以实例，`区域`，`集群`和`路由`运行，并且需要访问负载均衡器和提供者名称。主要接口主要是一个网关。大多数方法返回其他接口。

例如，`Clusters`接口非常简单：

```
type Clusters interface { 
  ListClusters() ([]string, error) 
  Master(clusterName string) (string, error) 
} 
```

`ListClusters()`方法返回集群名称。`Master()`方法返回主节点的 IP 地址或 DNS 名称。

其他接口并不复杂。整个文件有 214 行（截至目前为止），包括很多注释。重点是，如果您的云平台使用这些基本概念，实现 Kubernetes 提供程序并不太复杂。

# 谷歌云平台（GCP）

**谷歌云平台**（**GCP**）支持 Kubernetes 开箱即用。所谓的**谷歌 Kubernetes 引擎**（**GKE**）是建立在 Kubernetes 上的容器管理解决方案。您不需要在 GCP 上安装 Kubernetes，可以使用 Google Cloud API 创建 Kubernetes 集群并进行配置。Kubernetes 作为 GCP 的内置部分意味着它将始终被很好地集成和经过充分测试，您不必担心底层平台的更改会破坏云提供程序接口。

总的来说，如果您计划基于 Kubernetes 构建系统，并且在其他云平台上没有任何现有代码，那么 GCP 是一个可靠的选择。

# 亚马逊网络服务（AWS）

**亚马逊网络服务**（**AWS**）有自己的容器管理服务叫做 ECS，但它不是基于 Kubernetes 的。你可以在 AWS 上很好地运行 Kubernetes。它是一个受支持的提供者，并且有很多关于如何设置它的文档。虽然你可以自己提供一些 VM 并使用`kubeadm`，但我建议使用**Kubernetes 运维**（**Kops**）项目。Kops 是一个在 GitHub 上可用的 Kubernetes 项目（[`bit.ly/2ft5KA5`](http://bit.ly/2ft5KA5)）。它不是 Kubernetes 本身的一部分，但是由 Kubernetes 开发人员开发和维护。

它支持以下功能：

+   云端（AWS）自动化 Kubernetes 集群 CRUD

+   高可用（HA）的 Kubernetes 集群

+   它使用状态同步模型进行干运行和自动幂等性

+   `kubectl`的自定义支持插件

+   Kops 可以生成 Terraform 配置

+   它基于一个在目录树中定义的简单元模型

+   简单的命令行语法

+   社区支持

要创建一个集群，你需要通过`route53`进行一些最小的 DNS 配置，设置一个 S3 存储桶来存储集群配置，然后运行一个命令：

```
kops create cluster --cloud=aws --zones=us-east-1c ${NAME}  
```

完整的说明可以在[`bit.ly/2f7r6EK`](http://bit.ly/2f7r6EK)找到。

在 2017 年底，AWS 加入了 CNCF，并宣布了两个关于 Kubernetes 的重大项目：自己的基于 Kubernetes 的容器编排解决方案（EKS）和一个按需的容器解决方案（Fargate）。

# 亚马逊弹性容器服务用于 Kubernetes（EKS）

**亚马逊弹性容器服务用于 Kubernetes**是一个完全托管且高可用的 Kubernetes 解决方案。它有三个主节点在三个可用区运行。EKS 还负责升级和打补丁。EKS 的好处是它运行的是原始的 Kubernetes，没有任何改动。这意味着你可以使用社区开发的所有标准插件和工具。它还为与其他云提供商和/或你自己的本地 Kubernetes 集群方便的集群联合开启了大门。

EKS 与 AWS 基础设施深度集成。IAM 认证与 Kubernetes 的**基于角色的访问控制**（**RBAC**）集成。

如果你想直接从你自己的 Amazon VPC 访问你的 Kubernetes 主节点，你也可以使用`PrivateLink`。使用`PrivateLink`，你的 Kubernetes 主节点和 Amazon EKS 服务端点将显示为弹性网络接口，具有 Amazon VPC 中的私有 IP 地址。

拼图的另一个重要部分是一个特殊的 CNI 插件，它让您的 Kubernetes 组件可以使用 AWS 网络相互通信。

# Fargate

**Fargate**让您可以直接运行容器，而不必担心硬件配置。它消除了操作复杂性的很大一部分，但代价是失去了一些控制。使用 Fargate 时，您将应用程序打包到容器中，指定 CPU 和内存要求，并定义网络和 IAM 策略，然后就可以运行了。Fargate 可以在 ECS 和 EKS 上运行。它是无服务器阵营中非常有趣的一员，尽管它与 Kubernetes 没有直接关联。

# Azure

**Azure**曾经拥有自己的容器管理服务。您可以使用基于 Mesos 的 DC/OS 或 Docker Swarm 来管理它们，当然也可以使用 Kubernetes。您也可以自己配置集群（例如，使用 Azure 的期望状态配置），然后使用`kubeadm`创建 Kubernetes 集群。推荐的方法曾经是使用另一个非核心的 Kubernetes 项目，称为`kubernetes-anywhere`（[`bit.ly/2eCS7Ps`](http://bit.ly/2eCS7Ps)）。`kubernetes-anywhere`的目标是提供一种在云环境中创建集群的跨平台方式（至少对于 GCP、AWS 和 Azure）。

这个过程非常简单。您需要安装 Docker、`make`和`kubectl`，当然还需要您的 Azure 订阅 ID。然后，您克隆`kubernetes-anywhere`存储库，运行一些`make`命令，您的集群就可以运行了。

创建 Azure 集群的完整说明请参见[`bit.ly/2d56WdA`](http://bit.ly/2d56WdA)。

然而，在 2017 年下半年，Azure 也跳上了 Kubernetes 的列车，并推出了 AKS-Azure 容器服务。它类似于 Amazon EKS，尽管在实施上稍微领先一些。

AKS 提供了一个 REST API，以及一个 CLI，用于管理您的 Kubernetes 集群，但您也可以直接使用`kubectl`和任何其他 Kubernetes 工具。

以下是使用 AKS 的一些好处：

+   自动化的 Kubernetes 版本升级和修补

+   轻松扩展集群

+   自愈托管控制平面（主控）

+   节省成本-只为运行的代理节点付费

在本节中，我们介绍了云服务提供商接口，并介绍了在各种云服务提供商上创建 Kubernetes 集群的各种推荐方法。这个领域仍然很年轻，工具在迅速发展。我相信融合很快就会发生。诸如`kubeadm`、`kops`、`Kargo`和`kubernetes-anywhere`等工具和项目最终将合并，并提供一种统一且简单的方式来引导 Kubernetes 集群。

# 阿里巴巴云

中国的**阿里巴巴**云是云平台领域的新秀。它与 AWS 非常相似，尽管其英文文档还有很大的改进空间。我在阿里云上部署了一个生产应用，但没有使用 Kubernetes 集群。似乎阿里云对 Kubernetes 有官方支持，但文档是中文的。我在一个英文论坛帖子中找到了详细介绍如何在阿里云上部署 Kubernetes 集群的信息，链接为[`www.alibabacloud.com/forum/read-830`](https://www.alibabacloud.com/forum/read-830)。

# 从头开始创建裸机集群

在上一节中，我们讨论了在云服务提供商上运行 Kubernetes。这是 Kubernetes 的主要部署方式，但在裸机上运行 Kubernetes 也有很强的用例。我在这里不关注托管与本地部署；这是另一个维度。如果您已经在本地管理了很多服务器，那么您就处于最佳决策位置。

# 裸机的用例

裸机集群是一种特殊情况，特别是如果您自己管理它们。有一些公司提供裸机 Kubernetes 集群的商业支持，比如 Platform 9，但这些产品尚不成熟。一个坚实的开源选择是 Kubespray，它可以在裸机、AWS、GCE、Azure 和 OpenStack 上部署工业强度的 Kubernetes 集群。

以下是一些情况下使用裸机集群是有意义的：

+   **预算问题**：如果您已经管理了大规模的裸机集群，那么在您的物理基础设施上运行 Kubernetes 集群可能会更便宜

+   **低网络延迟**：如果您的节点之间必须有低延迟，那么虚拟机的开销可能会太大

+   **监管要求**：如果您必须遵守法规，可能不允许使用云服务提供商

+   **您想要对硬件拥有完全控制权**：云服务提供商为您提供了许多选择，但您可能有特殊需求

# 何时应考虑创建裸机集群？

从头开始创建集群的复杂性是显著的。Kubernetes 集群并不是一个微不足道的东西。关于如何设置裸机集群的文档很多，但随着整个生态系统的不断发展，许多这些指南很快就会过时。

如果您有操作能力，可以花时间在堆栈的每个级别调试问题，那么您应该考虑走这条路。大部分问题可能与网络有关，但文件系统和存储驱动程序也可能会困扰您，还有一般的不兼容性和组件之间的版本不匹配，比如 Kubernetes 本身、Docker（或 rkt，如果您敢尝试）、Docker 镜像、您的操作系统、您的操作系统内核以及您使用的各种附加组件和工具。

# 这个过程

有很多事情要做。以下是您需要解决的一些问题的列表：

+   实现自己的云提供商接口或绕过它

+   选择网络模型以及如何实现它（使用 CNI 插件或直接编译）

+   是否使用网络策略

+   选择系统组件的镜像

+   安全模型和 SSL 证书

+   管理员凭据

+   组件的模板，如 API 服务器、复制控制器和调度器

+   集群服务，如 DNS、日志记录、监控和 GUI

我建议阅读 Kubernetes 网站上的指南（[`bit.ly/1ToR9EC`](http://bit.ly/1ToR9EC)），以更深入地了解从头开始创建集群所需的步骤。

# 使用虚拟私有云基础设施

如果您的用例属于裸机用例，但您没有必要的熟练人手或者不愿意处理裸机的基础设施挑战，您可以选择使用私有云，比如 OpenStack（例如，使用 stackube）。如果您想在抽象层次上再高一点，那么 Mirantis 提供了一个建立在 OpenStack 和 Kubernetes 之上的云平台。

在本节中，我们考虑了构建裸机集群 Kubernetes 集群的选项。我们研究了需要它的用例，并突出了挑战和困难。

# Bootkube

**Bootkube**也非常有趣。它可以启动自托管的 Kubernetes 集群。自托管意味着大多数集群组件都作为常规 pod 运行，并且可以使用与您用于容器化应用程序相同的工具和流程进行管理、监控和升级。这种方法有显著的好处，简化了 Kubernetes 集群的开发和运行。

# 总结

在这一章中，我们进行了一些实际的集群创建。我们使用 Minikube 创建了一个单节点集群，使用`kubeadm`创建了一个多节点集群。然后我们看了很多使用云提供商创建 Kubernetes 集群的选项。最后，我们触及了在裸机上创建 Kubernetes 集群的复杂性。当前的情况非常动态。基本组件在迅速变化，工具仍然很年轻，每个环境都有不同的选择。建立 Kubernetes 集群并不是完全简单的，但通过一些努力和细节的关注，你可以快速完成。

在下一章中，我们将探讨监控、日志记录和故障排除等重要主题。一旦您的集群正常运行并开始部署工作负载，您需要确保它正常运行并满足要求。这需要持续关注和对现实世界中发生的各种故障做出响应。


# 第三章：监控、日志记录和故障排除

在第二章中，*创建 Kubernetes 集群*，您学习了如何在不同环境中创建 Kubernetes 集群，尝试了不同的工具，并创建了一些集群。

创建 Kubernetes 集群只是故事的开始。一旦集群运行起来，您需要确保它是可操作的，所有必要的组件都齐全并正确配置，并且部署了足够的资源来满足要求。响应故障、调试和故障排除是管理任何复杂系统的重要部分，Kubernetes 也不例外。

本章将涵盖以下主题：

+   使用 Heapster 进行监控

+   使用 Kubernetes 仪表板进行性能分析

+   中央日志记录

+   在节点级别检测问题

+   故障排除场景

+   使用 Prometheus

在本章结束时，您将对监视 Kubernetes 集群的各种选项有扎实的了解，知道如何访问日志以及如何分析它们。您将能够查看健康的 Kubernetes 集群并验证一切正常。您还将能够查看不健康的 Kubernetes 集群，并系统地诊断它，定位问题并解决它们。

# 使用 Heapster 监控 Kubernetes

Heapster 是一个为 Kubernetes 集群提供强大监控解决方案的 Kubernetes 项目。它作为一个 pod（当然）运行，因此可以由 Kubernetes 本身管理。Heapster 支持 Kubernetes 和 CoreOS 集群。它具有非常模块化和灵活的设计。Heapster 从集群中的每个节点收集操作指标和事件，将它们存储在持久后端（具有明确定义的模式）中，并允许可视化和编程访问。Heapster 可以配置为使用不同的后端（或在 Heapster 术语中称为 sinks）及其相应的可视化前端。最常见的组合是 InfluxDB 作为后端，Grafana 作为前端。谷歌云平台将 Heapster 与谷歌监控服务集成。还有许多其他不太常见的后端，如下所示：

+   日志

+   谷歌云监控

+   谷歌云日志

+   Hawkular-Metrics（仅指标）

+   OpenTSDB

+   Monasca（仅指标）

+   Kafka（仅指标）

+   Riemann（仅指标）

+   Elasticsearch

您可以通过在命令行上指定 sinks 来使用多个后端：

```
--sink=log --sink=influxdb:http://monitoring-influxdb:80/  
```

# cAdvisor

cAdvisor 是 kubelet 的一部分，它在每个节点上运行。它收集有关每个容器的 CPU/核心使用情况、内存、网络和文件系统的信息。它在端口`4194`上提供基本 UI，但是对于 Heapster 来说，最重要的是它通过 Kubelet 提供了所有这些信息。Heapster 记录了由 cAdvisor 在每个节点上收集的信息，并将其存储在其后端以进行分析和可视化。

如果您想快速验证特定节点是否设置正确，例如，在 Heapster 尚未连接时创建新集群，那么 cAdvisor UI 非常有用。

这是它的样子：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/994b310a-76bb-4d78-baf2-e16507c117e8.png)

# 安装 Heapster

Heapster 组件可能已安装或尚未安装在您的 Kubernetes 集群中。如果 Heapster 尚未安装，您可以使用几个简单的命令进行安装。首先，让我们克隆 Heapster 存储库：

```
> git clone https://github.com/kubernetes/heapster.git
> cd heapster 
```

在早期版本的 Kubernetes 中，Heapster 默认将服务公开为`NodePort`。现在，默认情况下，它们被公开为`ClusterIP`，这意味着它们仅在集群内可用。为了使它们在本地可用，我在`deploy/kube-config/influxdb`中的每个服务的规范中添加了 type: `NodePort`。例如，对于`deploy/kube-config/influxdb/influxdb.yaml`：

```
> git diff deploy/kube-config/influxdb/influxdb.yaml
diff --git a/deploy/kube-config/influxdb/influxdb.yaml b/deploy/kube-config/influxdb/influxdb.yaml
index 29408b81..70f52d2c 100644
--- a/deploy/kube-config/influxdb/influxdb.yaml
+++ b/deploy/kube-config/influxdb/influxdb.yaml
@@ -33,6 +33,7 @@ metadata:
 name: monitoring-influxdb
 namespace: kube-system
 spec:
+ type: NodePort
 ports:
 - port: 8086
 targetPort: 8086
```

我对`deploy/kube-config/influxdb/grafana.yaml`进行了类似的更改，其中`+ type: NodePort`这一行被注释掉了，所以我只是取消了注释。现在，我们实际上可以安装 InfluxDB 和 Grafana：

```
> kubectl create -f deploy/kube-config/influxdb  
```

您应该看到以下输出：

```
deployment "monitoring-grafana" created
service "monitoring-grafana" created
serviceaccount "heapster" created
deployment "heapster" created
service "heapster" created
deployment "monitoring-influxdb" created
service "monitoring-influxdb" created  
```

# InfluxDB 后端

InfluxDB 是一个现代而强大的分布式时间序列数据库。它非常适合用于集中式指标和日志记录，并被广泛使用。它也是首选的 Heapster 后端（在谷歌云平台之外）。唯一的问题是 InfluxDB 集群；高可用性是企业提供的一部分。

# 存储模式

InfluxDB 存储模式定义了 Heapster 在 InfluxDB 中存储的信息，并且可以在以后进行查询和绘图。指标分为多个类别，称为测量。您可以单独处理和查询每个指标，或者您可以将整个类别作为一个测量进行查询，并将单独的指标作为字段接收。命名约定是`<category>/<metrics name>`（除了正常运行时间，它只有一个指标）。如果您具有 SQL 背景，可以将测量视为表。每个指标都存储在每个容器中。每个指标都带有以下信息标签：

+   `pod_id`: 一个 pod 的唯一 ID

+   `pod_name`: pod 的用户提供的名称

+   `pod_namespace`: pod 的命名空间

+   `container_base_image`: 容器的基础镜像

+   `container_name`: 容器的用户提供的名称或系统容器的完整`cgroup`名称

+   `host_id`: 云服务提供商指定或用户指定的节点标识符

+   `hostname`: 容器运行的主机名

+   `labels`: 用户提供的标签的逗号分隔列表；格式为`key:value`

+   `namespace_id`: pod 命名空间的 UID

+   `resource_id`: 用于区分同一类型多个指标的唯一标识符，例如，文件系统/使用下的 FS 分区

以下是按类别分组的所有指标，可以看到，它非常广泛。

# CPU

CPU 指标包括：

+   `cpu/limit`: 毫核的 CPU 硬限制

+   `cpu/node_capacity`: 节点的 CPU 容量

+   `cpu/node_allocatable`: 节点的可分配 CPU

+   `cpu/node_reservation`: 节点可分配的 CPU 保留份额

+   `cpu/node_utilization`: CPU 利用率占节点可分配资源的份额

+   `cpu/request`: CPU 请求（资源的保证数量）（毫核）

+   `cpu/usage`: 所有核心的累积 CPU 使用率

+   `cpu/usage_rate`: 所有核心的 CPU 使用率（毫核）

# 文件系统

文件系统指标包括：

+   `filesystem/usage`: 文件系统上消耗的总字节数

+   `filesystem/limit`: 文件系统的总大小（字节）

+   `filesystem/available`: 文件系统中剩余的可用字节数

# 内存

内存指标包括：

+   `memory/limit`: 内存的硬限制（字节）

+   `memory/major_page_faults`: 主要页面错误的数量

+   `memory/major_page_faults_rate`: 每秒的主要页面错误数

+   `memory/node_capacity`: 节点的内存容量

+   `memory/node_allocatable`: 节点的可分配内存

+   `memory/node_reservation`: 节点可分配内存上保留的份额

+   `memory/node_utilization`: 内存利用率占内存可分配资源的份额

+   `memory/page_faults`: 页面错误的数量

+   `memory/page_faults_rate`: 每秒的页面错误数

+   `memory/request`: 内存请求（资源的保证数量）（字节）

+   `memory/usage`: 总内存使用量

+   `memory/working_set`: 总工作集使用量；工作集是内存的使用部分，不容易被内核释放

# 网络

网络指标包括：

+   `network/rx`: 累积接收的网络字节数

+   `network/rx_errors`: 接收时的累积错误数

网络

+   `network/rx_errors_rate`：在网络接收过程中每秒发生的错误次数

+   `network/rx_rate`：每秒通过网络接收的字节数

+   `network/tx`：通过网络发送的累积字节数

+   `network/tx_errors`：在网络发送过程中的累积错误次数

+   `network/tx_errors_rate`：在网络发送过程中发生的错误次数

+   `network/tx_rate`：每秒通过网络发送的字节数

# 正常运行时间

正常运行时间是容器启动以来的毫秒数。

如果您熟悉 InfluxDB，可以直接使用它。您可以使用其自己的 API 连接到它，也可以使用其 Web 界面。键入以下命令以查找其端口和端点：

```
> k describe service monitoring-influxdb --namespace=kube-system | grep NodePort
Type:               NodePort
NodePort:           <unset>  32699/TCP 
```

现在，您可以使用 HTTP 端口浏览 InfluxDB Web 界面。您需要将其配置为指向 API 端口。默认情况下，`用户名`和`密码`为`root`和`root`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/9ae3efb3-3192-44a7-be2b-3b9174c1d30c.png)

设置完成后，您可以选择要使用的数据库（请参阅右上角）。Kubernetes 数据库的名称为`k8s`。现在，您可以使用 InfluxDB 查询语言查询指标。

# Grafana 可视化

Grafana 在其自己的容器中运行，并提供一个与 InfluxDB 作为数据源配合良好的复杂仪表板。要找到端口，请键入以下命令：

```
k describe service monitoring-influxdb --namespace=kube-system | grep NodePort

Type:                NodePort
NodePort:            <unset> 30763/TCP  
```

现在，您可以在该端口上访问 Grafana Web 界面。您需要做的第一件事是设置数据源指向 InfluxDB 后端：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/79a74148-198b-4a7a-ac70-86144ee6ca9f.png)

确保测试连接，然后去探索仪表板中的各种选项。有几个默认的仪表板，但您应该能够根据自己的喜好进行自定义。Grafana 旨在让您根据自己的需求进行调整。

# 发现和负载平衡

发现和负载平衡类别通常是您开始的地方。服务是您的 Kubernetes 集群的公共接口。严重的问题将影响您的服务，从而影响您的用户：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/ac735902-2574-44a9-9489-ae1b94edd493.png)

当您通过单击服务进行深入了解时，您将获得有关服务的一些信息（最重要的是标签选择器）和一个 Pods 视图。

# 使用仪表板进行性能分析

迄今为止，我最喜欢的工具，当我只想知道集群中发生了什么时，就是 Kubernetes 仪表板。以下是几个原因：

+   它是内置的（始终与 Kubernetes 同步和测试）

+   它很快

+   它提供了一个直观的深入界面，从集群级别一直到单个容器

+   它不需要任何定制或配置

虽然 Heapster、InfluxDB 和 Grafana 更适合定制和重型视图和查询，但 Kubernetes 仪表板的预定义视图可能能够在 80-90%的时间内回答所有你的问题。

您还可以通过上传适当的 YAML 或 JSON 文件，使用仪表板部署应用程序并创建任何 Kubernetes 资源，但我不会涉及这个，因为这对于可管理的基础设施来说是一种反模式。在玩测试集群时可能有用，但对于实际修改集群状态，我更喜欢使用命令行。您的情况可能有所不同。

让我们先找到端口：

```
k describe service kubernetes-dashboard --namespace=kube-system | grep NodePort

Type:                   NodePort
NodePort:               <unset> 30000/TCP  
```

# 顶层视图

仪表板以左侧的分层视图组织（可以通过单击汉堡菜单隐藏），右侧是动态的、基于上下文的内容。您可以深入分层视图，以深入了解相关信息。

有几个顶层类别：

+   集群

+   概述

+   工作负载

+   发现和负载平衡

+   配置和存储

您还可以通过特定命名空间过滤所有内容或选择所有命名空间。

# 集群

集群视图有五个部分：命名空间、节点、持久卷、角色和存储类。它主要是观察集群的物理资源：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/3dbe8557-cce3-4e5b-9922-e7ed73042915.png)

一眼就可以获得大量信息：所有节点的 CPU 和内存使用情况，可用的命名空间，它们的状态和年龄。对于每个节点，您可以看到它的年龄、标签，以及它是否准备就绪。如果有持久卷和角色，您也会看到它们，然后是存储类（在这种情况下只是主机路径）。

如果我们深入节点并点击 minikube 节点本身，我们会得到有关该节点和分配资源的详细信息，以一个漂亮的饼图显示。这对处理性能问题至关重要。如果一个节点没有足够的资源，那么它可能无法满足其 pod 的需求：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/8143ad1c-4616-4b6c-b176-b8f28598c4cd.png)

如果您向下滚动，您会看到更多有趣的信息。条件窗格是最重要的地方。您可以清晰、简洁地查看每个节点的内存和磁盘压力：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/4b7585a5-ab73-4762-9170-f6e87759ad63.png)

还有 Pods 和 Events 窗格。我们将在下一节讨论 pod。

# 工作负载

工作负载类别是主要类别。它组织了许多类型的 Kubernetes 资源，如 CronJobs、Daemon Sets、Deployments、Jobs、Pods、Replica Sets、Replication Controllers 和 Stateful Sets。您可以沿着任何这些维度进行深入。这是默认命名空间的顶级工作负载视图，目前只部署了 echo 服务。您可以看到部署、副本集和 pod：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/0a80dca8-6665-4f68-ad1f-2e01735b4c88.png)

让我们切换到所有命名空间并深入研究 Pods 子类别。这是一个非常有用的视图。在每一行中，您可以看出 pod 是否正在运行，它重新启动了多少次，它的 IP，甚至嵌入了 CPU 和内存使用历史记录作为漂亮的小图形：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/da3368c6-80dc-4056-8fc0-3b186dc40164.png)

您也可以通过点击文本符号（从右边数第二个）查看任何 pod 的日志。让我们检查 InfluxDB pod 的日志。看起来一切都井井有条，Heapster 成功地向其写入：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/0358b581-6b6a-46f9-aa3e-a7995142fc90.png)

还有一个我们尚未探讨的更详细的层次。我们可以进入容器级别。让我们点击 kubedns pod。我们得到以下屏幕，显示了各个容器及其`run`命令；我们还可以查看它们的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/eb484adb-241d-444b-bcf7-ac80ffb637cd.png)

# 添加中央日志记录

中央日志记录或集群级日志记录是任何具有多个节点、pod 或容器的集群的基本要求。首先，单独查看每个 pod 或容器的日志是不切实际的。您无法获得系统的全局图片，而且将有太多的消息需要筛选。您需要一个聚合日志消息并让您轻松地切片和切块的解决方案。第二个原因是容器是短暂的。有问题的 pod 通常会死掉，它们的复制控制器或副本集将启动一个新实例，丢失所有重要的日志信息。通过记录到中央日志记录服务，您可以保留这些关键的故障排除信息。

# 规划中央日志记录

在概念上，中央日志非常简单。在每个节点上，您运行一个专用代理，拦截节点上所有 pod 和容器的所有日志消息，并将它们连同足够的元数据发送到一个中央存储库，其中它们被安全地存储。

像往常一样，如果您在谷歌平台上运行，那么 GKE 会为您提供支持，并且有一个谷歌集中日志服务集成得很好。对于其他平台，一个流行的解决方案是 fluentd、Elasticsearch 和 Kibana。有一个官方的附加组件来为每个组件设置适当的服务。`fluentd-elasticsearch`附加组件位于[`bit.ly/2f6MF5b`](http://bit.ly/2f6MF5b)。

它被安装为 Elasticsearch 和 Kibana 的一组服务，并且在每个节点上安装了 fluentd 代理。

# Fluentd

Fluentd 是一个统一的日志记录层，位于任意数据源和任意数据接收器之间，并确保日志消息可以从 A 流向 B。Kubernetes 带有一个附加组件，其中有一个部署 fluentd 代理的 Docker 镜像，它知道如何读取与 Kubernetes 相关的各种日志，如`Docker`日志、`etcd`日志和`Kube`日志。它还为每条日志消息添加标签，以便用户以后可以轻松地按标签进行过滤。这是`fluentd-es-configmap.yaml`文件的一部分：

```
# Example:
# 2016/02/04 06:52:38 filePurge: successfully removed file 
/var/etcd/data/member/wal/00000000000006d0-00000000010a23d1.wal
<source>
 type tail
 # Not parsing this, because it doesn't have anything particularly 
useful to
 # parse out of it (like severities).
 format none
 path /var/log/etcd.log
 pos_file /var/log/es-etcd.log.pos
 tag etcd
</source>
```

# Elasticsearch

Elasticsearch 是一个很棒的文档存储和全文搜索引擎。它在企业中很受欢迎，因为它非常快速、可靠和可扩展。它作为一个 Docker 镜像在 Kubernetes 中央日志附加组件中使用，并且部署为一个服务。请注意，一个完全成熟的 Elasticsearch 生产集群（将部署在 Kubernetes 集群上）需要自己的主节点、客户端节点和数据节点。对于大规模和高可用的 Kubernetes 集群，中央日志本身将被集群化。Elasticsearch 可以使用自我发现。这是一个企业级的解决方案：[`github.com/pires/kubernetes-elasticsearch-cluster`](https://github.com/pires/kubernetes-elasticsearch-cluster)。

# Kibana

Kibana 是 Elasticsearch 的搭档。它用于可视化和与 Elasticsearch 存储和索引的数据进行交互。它也作为一个服务被附加组件安装。这是 Kibana 的 Dockerfile 模板([`bit.ly/2lwmtpc`](http://bit.ly/2lwmtpc))。

# 检测节点问题

在 Kubernetes 的概念模型中，工作单位是 pod。但是，pod 被调度到节点上。在监控和可靠性方面，节点是最需要关注的，因为 Kubernetes 本身（调度器和复制控制器）负责 pod。节点可能遭受各种问题，而 Kubernetes 并不知晓。因此，它将继续将 pod 调度到有问题的节点上，而 pod 可能无法正常运行。以下是节点可能遭受的一些问题，尽管看起来是正常的：

+   CPU 问题

+   内存问题

+   磁盘问题

+   内核死锁

+   损坏的文件系统

+   Docker 守护进程问题

kubelet 和 cAdvisor 无法检测到这些问题，需要另一个解决方案。进入节点问题检测器。

# 节点问题检测器

节点问题检测器是在每个节点上运行的一个 pod。它需要解决一个困难的问题。它需要检测不同环境、不同硬件和不同操作系统上的各种问题。它需要足够可靠，不受影响（否则，它无法报告问题），并且需要具有相对较低的开销，以避免向主节点发送大量信息。此外，它需要在每个节点上运行。Kubernetes 最近收到了一个名为 DaemonSet 的新功能，解决了最后一个问题。

源代码位于[`github.com/kubernetes/node-problem-detector`](https://github.com/kubernetes/node-problem-detector)。

# 守护进程集

DaemonSet 是每个节点的一个 pod。一旦定义了 DaemonSet，集群中添加的每个节点都会自动获得一个 pod。如果该 pod 死掉，Kubernetes 将在该节点上启动该 pod 的另一个实例。可以将其视为带有 1:1 节点- pod 亲和性的复制控制器。节点问题检测器被定义为一个 DaemonSet，这与其要求完全匹配。可以使用亲和性、反亲和性和污点来更精细地控制 DaemonSet 的调度。

# 问题守护进程

节点问题检测器的问题（双关语）在于它需要处理太多问题。试图将所有这些问题都塞进一个代码库中会导致一个复杂、臃肿且永远不稳定的代码库。节点问题检测器的设计要求将报告节点问题的核心功能与特定问题检测分离开来。报告 API 基于通用条件和事件。问题检测应该由单独的问题守护程序（每个都在自己的容器中）来完成。这样，就可以添加和演进新的问题检测器，而不会影响核心节点问题检测器。此外，控制平面可能会有一个补救控制器，可以自动解决一些节点问题，从而实现自愈。

在这个阶段（Kubernetes 1.10），问题守护程序已经嵌入到节点问题检测器二进制文件中，并且它们作为 Goroutines 执行，因此您还没有获得松耦合设计的好处。

在这一部分，我们涵盖了节点问题的重要主题，这可能会妨碍工作负载的成功调度，以及节点问题检测器如何帮助解决这些问题。在下一节中，我们将讨论各种故障场景以及如何使用 Heapster、中央日志、Kubernetes 仪表板和节点问题检测器进行故障排除。

# 故障排除场景

在一个大型的 Kubernetes 集群中，有很多事情可能会出错，而且它们确实会出错，这是可以预料的。您可以采用最佳实践并最小化其中一些问题（主要是人为错误），通过严格的流程来减少一些问题。然而，一些问题，比如硬件故障和网络问题是无法完全避免的。即使是人为错误，如果这意味着开发时间变慢，也不应该总是被最小化。在这一部分，我们将讨论各种故障类别，如何检测它们，如何评估它们的影响，并考虑适当的应对措施。

# 设计健壮的系统

当您想设计一个强大的系统时，首先需要了解可能的故障模式，每种故障的风险/概率以及每种故障的影响/成本。然后，您可以考虑各种预防和缓解措施、损失削减策略、事件管理策略和恢复程序。最后，您可以制定一个与风险相匹配的缓解方案，包括成本。全面的设计很重要，并且需要随着系统的发展而进行更新。赌注越高，您的计划就应该越彻底。这个过程必须为每个组织量身定制。错误恢复和健壮性的一个角落是检测故障并能够进行故障排除。以下小节描述了常见的故障类别，如何检测它们以及在哪里收集额外信息。

# 硬件故障

Kubernetes 中的硬件故障可以分为两组：

+   节点无响应

+   节点有响应

当节点无响应时，有时很难确定是网络问题、配置问题还是实际的硬件故障。显然，您无法使用节点本身的日志或运行诊断。你能做什么？首先，考虑节点是否曾经有响应。如果这是一个刚刚添加到集群中的节点，更有可能是配置问题。如果这是集群中的一个节点，那么您可以查看来自 Heapster 或中央日志的节点的历史数据，并查看日志中是否有任何错误或性能下降的迹象，这可能表明硬件故障。

当节点有响应时，它可能仍然遭受冗余硬件的故障，例如非操作系统磁盘或一些核心。如果节点问题检测器在节点上运行并引起一些事件或节点条件引起主节点的注意，您可以检测硬件故障。或者，您可能会注意到 Pod 不断重新启动或作业完成时间较长。所有这些都可能是硬件故障的迹象。另一个硬件故障的强烈暗示是，如果问题局限在单个节点上，并且标准维护操作（如重新启动）不能缓解症状。

如果您的集群部署在云中，替换一个您怀疑存在硬件问题的节点是微不足道的。只需手动提供一个新的 VM 并删除坏的 VM 即可。在某些情况下，您可能希望采用更自动化的流程并使用一个补救控制器，正如节点问题检测器设计所建议的那样。您的补救控制器将监听问题（或缺少的健康检查），并可以自动替换坏的节点。即使在私有托管或裸金属中，这种方法也可以运行，只要您保留一些额外的节点准备投入使用。大规模集群即使在大部分时间内容量减少也可以正常运行。您可以容忍少量节点宕机时的轻微容量减少，或者您可以略微过度配置。这样，当一个节点宕机时，您就有了一些余地。

# 配额、份额和限制

Kubernetes 是一个多租户系统。它旨在高效利用资源，但是它根据命名空间中可用配额和限制以及 pod 和容器对保证资源的请求之间的一套检查和平衡系统来调度 pod 并分配资源。我们将在本书的后面深入讨论细节。在这里，我们只考虑可能出现的问题以及如何检测它。您可能会遇到几种不良结果：

+   资源不足：如果一个 pod 需要一定数量的 CPU 或内存，而没有可用容量的节点，那么该 pod 就无法被调度。

+   资源利用不足：一个 pod 可能声明需要一定数量的 CPU 或内存，Kubernetes 会满足，但是 pod 可能只使用其请求资源的一小部分。这只是浪费。

+   节点配置不匹配：一个需要大量 CPU 但很少内存的 pod 可能被调度到一个高内存的节点上，并使用所有的 CPU 资源，从而占用了节点，因此无法调度其他 pod，但未使用的内存却被浪费了。

查看仪表板是一种通过视觉寻找可疑情况的好方法。过度订阅或资源利用不足的节点和 pod 都是配额和资源请求不匹配的候选者。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/37fed9ea-0d5c-4666-a98f-cc4e23b9195d.png)

一旦您检测到一个候选项，您可以深入使用`describe`命令来查看节点或 pod 级别。在大规模集群中，您应该有自动化检查，以比较利用率与容量规划。这很重要，因为大多数大型系统都有一定程度的波动，而不会期望均匀的负载。确保您了解系统的需求，并且您的集群容量在正常范围内或可以根据需要弹性调整。

# 错误的配置

错误的配置是一个总称。您的 Kubernetes 集群状态是配置；您的容器的命令行参数是配置；Kubernetes、您的应用服务和任何第三方服务使用的所有环境变量都是配置；所有配置文件都是配置。在一些数据驱动的系统中，配置存储在各种数据存储中。配置问题非常常见，因为通常没有建立良好的实践来测试它们。它们通常具有各种回退（例如，配置文件的搜索路径）和默认值，并且生产环境配置与开发或暂存环境不同。

在 Kubernetes 集群级别，可能存在许多可能的配置问题，如下所示：

+   节点、pod 或容器的标签不正确

+   在没有复制控制器的情况下调度 pod

+   服务端口的规范不正确

+   不正确的 ConfigMap

大多数这些问题可以通过拥有适当的自动化部署流程来解决，但您必须深入了解您的集群架构以及 Kubernetes 资源如何配合。

配置问题通常发生在您更改某些内容之后。在每次部署或手动更改集群后，验证其状态至关重要。

Heapster 和仪表板在这里是很好的选择。我建议从服务开始，并验证它们是否可用、响应和功能正常。然后，您可以深入了解系统是否也在预期的性能参数范围内运行。

日志还提供了有用的提示，并可以确定特定的配置选项。

# 成本与性能

大型集群并不便宜。特别是在云中运行时。操作大规模系统的一个重要部分是跟踪开支。

# 在云上管理成本

云的最大好处之一是它可以满足弹性需求，满足系统根据需要自动扩展和收缩，通过根据需要分配和释放资源。Kubernetes 非常适合这种模型，并且可以扩展以根据需要提供更多节点。风险在于，如果不适当地限制，拒绝服务攻击（恶意的、意外的或自我造成的）可能导致昂贵资源的任意分配。这需要仔细监控，以便及早发现。命名空间的配额可以避免这种情况，但您仍然需要能够深入了解并准确定位核心问题。根本原因可能是外部的（僵尸网络攻击），配置错误，内部测试出错，或者是检测或分配资源的代码中的错误。

# 在裸金属上管理成本

在裸金属上，您通常不必担心资源分配失控，但是如果您需要额外的容量并且无法快速提供更多资源，您很容易遇到瓶颈。容量规划和监控系统性能以及及早检测需求是 OPS 的主要关注点。Heapster 可以显示历史趋势，并帮助识别高峰时段和总体需求增长。

# 管理混合集群的成本

混合集群在裸金属和云上运行（可能还在私人托管服务上）。考虑因素是相似的，但您可能需要汇总您的分析。我们将在稍后更详细地讨论混合集群。

# 使用 Prometheus

Heapster 和 Kubernetes 默认的监控和日志记录是一个很好的起点。然而，Kubernetes 社区充满了创新，有几种替代方案可供选择。其中最受欢迎的解决方案之一是 Prometheus。在本节中，我们将探索运营商的新世界，Prometheus 运营商，如何安装它以及如何使用它来监视您的集群。

# 什么是运营商？

运营商是一种新型软件，它封装了在 Kubernetes 之上开发、管理和维护应用程序所需的操作知识。这个术语是由 CoreOS 在 2016 年底引入的。运营商是一个特定于应用程序的控制器，它扩展了 Kubernetes API，以代表 Kubernetes 用户创建、配置和管理复杂有状态应用程序的实例。它建立在基本的 Kubernetes 资源和控制器概念之上，但包括领域或应用程序特定的知识，以自动化常见任务。

# Prometheus Operator

Prometheus ([`prometheus.io`](https://prometheus.io))是一个用于监控集群中应用程序的开源系统监控和警报工具包。它受 Google 的 Borgmon 启发，并设计用于 Kubernetes 模型的工作单元分配和调度。它于 2016 年加入 CNCF，并在整个行业广泛采用。InfluxDB 和 Prometheus 之间的主要区别在于，Prometheus 使用拉模型，任何人都可以访问/metrics 端点，其查询语言非常表达性强，但比 InfluxDB 的类似 SQL 的查询语言更简单。

Kubernetes 具有内置功能来支持 Prometheus 指标，而 Prometheus 对 Kuberneres 的认识不断改进。Prometheus Operator 将所有这些监控功能打包成一个易于安装和使用的捆绑包。

# 使用 kube-prometheus 安装 Prometheus

安装 Prometheus 的最简单方法是使用 kube-prometheus。它使用 Prometheus Operator 以及 Grafana 进行仪表板和`AlertManager`的管理。要开始，请克隆存储库并运行`deploy`脚本：

```
> git clone https://github.com/coreos/prometheus-operator.git 
> cd contrib/kube-prometheus
> hack/cluster-monitoring/deploy 
```

该脚本创建一个监控命名空间和大量的 Kubernetes 实体和支持组件。

+   Prometheus Operator 本身

+   Prometheus node_exporter

+   kube-state metrics

+   覆盖监控所有 Kubernetes 核心组件和导出器的 Prometheus 配置

+   集群组件健康的默认一组警报规则

+   为集群指标提供仪表板的 Grafana 实例

+   一个由三个节点组成的高可用性 Alertmanager 集群

让我们验证一切是否正常：

```
> kg po --namespace=monitoring
NAME                                READY     STATUS    RESTARTS   AGE
alertmanager-main-0                  2/2       Running   0          1h
alertmanager-main-1                  2/2       Running   0          1h
alertmanager-main-2                  0/2       Pending   0          1h
grafana-7d966ff57-rvpwk              2/2       Running   0          1h
kube-state-metrics-5dc6c89cd7-s9n4m  2/2       Running   0          1h
node-exporter-vfbhq                  1/1       Running   0          1h
prometheus-k8s-0                     2/2       Running   0          1h
prometheus-k8s-1                     2/2       Running   0          1h
prometheus-operator-66578f9cd9-5t6xw 1/1       Running   0          1h  
```

请注意，`alertmanager-main-2`处于挂起状态。我怀疑这是由于 Minikube 在两个核心上运行。在我的设置中，这实际上并没有造成任何问题。

# 使用 Prometheus 监控您的集群

一旦 Prometheus Operator 与 Grafana 和 Alertmanager 一起运行，您就可以访问它们的 UI 并与不同的组件进行交互：

+   节点端口`30900`上的 Prometheus UI

+   节点端口`30903`上的 Alertmanager UI

+   节点端口`30902`上的 Grafana

Prometheus 支持选择的指标种类繁多。以下是一个屏幕截图，显示了按容器分解的微秒级 HTTP 请求持续时间：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/e55c149a-84ac-4c8c-91a8-1addb887cc63.png)

要将视图限制为`prometheus-k8s`服务的仅 0.99 分位数，请使用以下查询：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/348f4501-a178-41e3-818c-d69d69a48a33.png)

```
http_request_duration_microseconds{service="prometheus-k8s", quantile="0.99"}  
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ms-k8s/img/a11d115c-7f30-4aea-871e-8c616f00f73d.png)

Alertmanager 是 Prometheus 监控故事的另一个重要部分。这是一个 Web UI 的截图，让您可以根据任意指标定义和配置警报。

# 总结

在本章中，我们讨论了监控、日志记录和故障排除。这是操作任何系统的关键方面，特别是像 Kubernetes 这样有许多移动部件的平台。每当我负责某件事情时，我最担心的是出现问题，而我没有系统化的方法来找出问题所在以及如何解决它。Kubernetes 内置了丰富的工具和设施，如 Heapster、日志记录、DaemonSets 和节点问题检测器。您还可以部署任何您喜欢的监控解决方案。

在第四章中，*高可用性和可靠性*，我们将看到高可用和可扩展的 Kubernetes 集群。这可以说是 Kubernetes 最重要的用例，它在与其他编排解决方案相比的时候表现出色。
