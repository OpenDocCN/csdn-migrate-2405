# Kubernetes 安全学习手册（一）

> 原文：[`zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C`](https://zh.annas-archive.org/md5/389AEFE03E8149C2BB9C34B66276B16C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

现实世界应用程序的不断复杂性和可扩展性已经导致了从单体架构向微服务架构的过渡。Kubernetes 已成为部署微服务的事实编排平台。作为一个开发者友好的平台，Kubernetes 可以启用不同的配置以适应不同的用例，使其成为大多数 DevOps 工程师的首选。Kubernetes 的开放性和高度可配置的特性增加了其复杂性。增加的复杂性会导致配置错误和安全问题，如果被利用，可能会对组织造成重大经济影响。如果您计划在您的环境中使用 Kubernetes，那么这本书就是为您准备的。

在这本书中，您将学习如何保护您的 Kubernetes 集群。我们在前两章中简要介绍了 Kubernetes（我们希望您在开始之前已经对 Kubernetes 有基本的了解）。然后，我们讨论了不同 Kubernetes 组件和对象的默认配置。Kubernetes 中的默认配置通常是不安全的。我们讨论了不同的方法来正确配置您的集群，以确保其安全。我们深入探讨了 Kubernetes 提供的不同内置安全机制，如准入控制器、安全上下文和网络策略，以帮助保护您的集群。我们还讨论了一些开源工具，这些工具可以补充 Kubernetes 中现有的工具包，以提高您的集群的安全性。最后，我们将看一些 Kubernetes 集群中的真实攻击和漏洞的例子，并讨论如何加固您的集群以防止此类攻击。

通过这本书，我们希望您能够在您的 Kubernetes 集群中安全地部署复杂的应用程序。Kubernetes 正在快速发展。通过我们提供的示例，我们希望您能学会如何为您的环境合理配置。

# 这本书适合谁

这本书适用于已经开始将 Kubernetes 作为他们主要的部署/编排平台并且对 Kubernetes 有基本了解的 DevOps/DevSecOps 专业人士。这本书也适用于希望学习如何保护和加固 Kubernetes 集群的开发人员。

# 这本书涵盖了什么

*第一章*, *Kubernetes 架构*，介绍了 Kubernetes 组件和 Kubernetes 对象的基础知识。

【第二章】介绍了 Kubernetes 的网络模型，并深入探讨了微服务之间的通信。

【第三章】讨论了 Kubernetes 中的重要资产、威胁者以及如何为部署在 Kubernetes 中的应用程序进行威胁建模。

【第四章】讨论了 Kubernetes 中的安全控制机制，帮助在两个领域实施最小特权原则：Kubernetes 主体的最小特权和 Kubernetes 工作负载的最小特权。

【第五章】讨论了 Kubernetes 集群中的安全域和安全边界。还介绍了加强安全边界的安全控制机制。

【第六章】讨论了 Kubernetes 组件中的敏感配置，如`kube-apiserver`、`kubelet`等。介绍了使用`kube-bench`来帮助识别 Kubernetes 集群中的配置错误。

【第七章】讨论了 Kubernetes 中的认证和授权机制。还介绍了 Kubernetes 中流行的准入控制器。

【第八章】讨论了使用 CIS Docker 基准来加固图像。介绍了 Kubernetes 安全上下文、Pod 安全策略和`kube-psp-advisor`，它有助于生成 Pod 安全策略。

【第九章】介绍了 DevOps 流水线中的图像扫描的基本概念和容器图像以及漏洞。还介绍了图像扫描工具 Anchore Engine 以及如何将其集成到 DevOps 流水线中。

*第十章*, *Kubernetes 集群的实时监控和资源管理*，介绍了资源请求/限制和 LimitRanger 等内置机制。它还介绍了 Kubernetes 仪表板和指标服务器等内置工具，以及 Prometheus 和名为 Grafana 的第三方监控工具。

*第十一章*, *深度防御*，讨论了与深度防御相关的各种主题：Kubernetes 审计、Kubernetes 的高可用性、密钥管理、异常检测和取证。

*第十二章*, *分析和检测加密货币挖矿攻击*，介绍了加密货币和加密货币挖矿攻击的基本概念。然后讨论了使用 Prometheus 和 Falco 等开源工具检测加密货币挖矿攻击的几种方法。

*第十三章*, *从 Kubernetes CVE 中学习*，讨论了四个众所周知的 Kubernetes CVE 以及一些相应的缓解策略。它还介绍了开源工具`kube-hunter`，帮助识别 Kubernetes 中已知的漏洞。

# 要充分利用本书

在开始阅读本书之前，我们希望您对 Kubernetes 有基本的了解。在阅读本书时，我们希望您以安全的心态看待 Kubernetes。本书有很多关于加固和保护 Kubernetes 工作负载配置和组件的示例。除了尝试这些示例之外，您还应该思考这些示例如何映射到不同的用例。我们在本书中讨论了如何使用不同的开源工具。我们希望您花更多时间了解每个工具提供的功能。深入了解工具提供的不同功能将帮助您了解如何为不同的环境配置每个工具：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Preface_table.jpg)

如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制/粘贴代码相关的潜在错误。

# 请下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择**支持**选项卡。

1.  点击**代码下载**。

1.  在**搜索**框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learn-Kubernetes-Security`](https://github.com/PacktPublishing/Learn-Kubernetes-Security)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 代码实例

本书的代码实例视频可在[`bit.ly/2YZKCJX`](https://bit.ly/2YZKCJX)上观看。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781839216503_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781839216503_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："此属性也在`PodSecurityContext`中可用，它在 Pod 级别生效。"

代码块设置如下：

```
{
  "filename": "/tmp/minerd2",
  "gid": 0,
  "linkdest": null,
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
{
  "scans": {
    "Fortinet": {
      "detected": true,
    }
  }
```

任何命令行输入或输出都以以下方式编写：

```
$ kubectl get pods -n insecure-nginx
```

**粗体**：表示新术语、重要词汇或屏幕上看到的词语。例如，菜单或对话框中的词语在文本中显示为这样。例如："屏幕截图显示了由 Prometheus 和 Grafana 监控的**insecure-nginx** pod 的 CPU 使用情况。"

提示或重要说明

就像这样。


# 第一部分：Kubernetes 简介

在本节中，您将掌握 Kubernetes 架构、网络模型、威胁模型以及应用于 Kubernetes 集群的核心安全原则的基本概念。

本节包括以下章节：

+   第一章，Kubernetes 架构

+   第二章，Kubernetes 网络

+   第三章，威胁建模

+   第四章，在 Kubernetes 中应用最小权限原则

+   第五章，配置 Kubernetes 安全边界


# 第一章：Kubernetes 架构

传统应用程序，如 Web 应用程序，通常遵循模块化架构，将代码分为应用层、业务逻辑、存储层和通信层。尽管采用了模块化架构，但组件被打包并部署为单体。单体应用虽然易于开发、测试和部署，但难以维护和扩展。这导致了微服务架构的增长。像 Docker 和 Linux 容器（LXC）这样的容器运行时的开发已经简化了应用程序作为微服务的部署和维护。

微服务架构将应用部署分为小型且相互连接的实体。微服务架构的日益流行导致了诸如 Apache Swarm、Mesos 和 Kubernetes 等编排平台的增长。容器编排平台有助于在大型和动态环境中管理容器。

Kubernetes 是一个开源的容器化应用编排平台，支持自动化部署、扩展和管理。它最初由 Google 在 2014 年开发，现在由云原生计算基金会（CNCF）维护。Kubernetes 是 2018 年首个毕业于 CNCF 的项目。成立的全球组织，如 Uber、Bloomberg、Blackrock、BlaBlaCar、纽约时报、Lyft、eBay、Buffer、Ancestry、GolfNow、高盛等，都在大规模生产中使用 Kubernetes。大型云服务提供商，如 Amazon 的弹性 Kubernetes 服务、微软的 Azure Kubernetes 服务、谷歌的谷歌 Kubernetes 引擎和阿里巴巴的阿里云 Kubernetes，都提供自己的托管 Kubernetes 服务。

在微服务模型中，应用程序开发人员确保应用程序在容器化环境中正常工作。他们编写 Docker 文件来打包他们的应用程序。DevOps 和基础设施工程师直接与 Kubernetes 集群进行交互。他们确保开发人员提供的应用程序包在集群中顺利运行。他们监视节点、Pod 和其他 Kubernetes 组件，以确保集群健康。然而，安全性需要双方和安全团队的共同努力。要了解如何保护 Kubernetes 集群，我们首先必须了解 Kubernetes 是什么以及它是如何工作的。

在本章中，我们将涵盖以下主题：

+   Docker 的崛起和微服务的趋势

+   Kubernetes 组件

+   Kubernetes 对象

+   Kubernetes 的变种

+   Kubernetes 和云服务提供商

# Docker 的崛起和微服务的趋势

在我们开始研究 Kubernetes 之前，了解微服务和容器化的增长是很重要的。随着单体应用程序的演变，开发人员面临着不可避免的问题：

+   **扩展**：单体应用程序很难扩展。已经证明解决可扩展性问题的正确方法是通过分布式方法。

+   **运营成本**：随着单体应用程序的复杂性增加，运营成本也会增加。更新和维护需要在部署之前进行仔细分析和足够的测试。这与可扩展性相反；你不能轻易地缩减单体应用程序，因为最低资源需求很高。

+   **发布周期更长**：对于单体应用程序，维护和开发的障碍非常高。对于开发人员来说，当出现错误时，在复杂且不断增长的代码库中识别根本原因需要很长时间。测试时间显著增加。回归、集成和单元测试在复杂的代码库中需要更长的时间才能通过。当客户的请求到来时，一个功能要发布需要几个月甚至一年的时间。这使得发布周期变长，并且对公司的业务产生重大影响。

这激励着将单片应用程序拆分为微服务。好处是显而易见的：

+   有了明确定义的接口，开发人员只需要关注他们拥有的服务的功能。

+   代码逻辑被简化了，这使得应用程序更容易维护和调试。此外，与单片应用程序相比，微服务的发布周期大大缩短，因此客户不必等待太长时间才能获得新功能。

当单片应用程序分解为许多微服务时，这增加了 DevOps 方面的部署和管理复杂性。这种复杂性是显而易见的；微服务通常使用不同的编程语言编写，需要不同的运行时或解释器，具有不同的软件包依赖关系、不同的配置等，更不用说微服务之间的相互依赖了。这正是 Docker 出现的合适时机。

让我们来看一下 Docker 的演变。进程隔离长期以来一直是 Linux 的一部分，以**控制组**（**cgroups**）和**命名空间**的形式存在。通过 cgroup 设置，每个进程都有限制的资源（CPU、内存等）可供使用。通过专用的进程命名空间，命名空间内的进程不会知道在同一节点但在不同进程命名空间中运行的其他进程。通过专用的网络命名空间，进程在没有适当的网络配置的情况下无法与其他进程通信，即使它们在同一节点上运行。

Docker 简化了基础设施和 DevOps 工程师的进程管理。2013 年，Docker 公司发布了 Docker 开源项目。DevOps 工程师不再需要管理命名空间和 cgroups，而是通过 Docker 引擎管理容器。Docker 容器利用 Linux 中的这些隔离机制来运行和管理微服务。每个容器都有专用的 cgroup 和命名空间。

相互依赖的复杂性仍然存在。编排平台是试图解决这个问题的平台。Docker 还提供了 Docker Swarm 模式（后来更名为 Docker 企业版，或 Docker EE）来支持集群容器，与 Kubernetes 大致同时期。

## Kubernetes 采用状态

根据 Sysdig 在 2019 年进行的容器使用报告（[`sysdig.com/blog/sysdig-2019-container-usage-report`](https://sysdig.com/blog/sysdig-2019-container-usage-report)），一家容器安全和编排供应商表示，Kubernetes 在使用的编排器中占据了惊人的 77%的份额。如果包括 OpenShift（来自 Red Hat 的 Kubernetes 变体），市场份额接近 90%：

![图 1.1 –编排平台的市场份额](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_01_01.jpg)

图 1.1 –编排平台的市场份额

尽管 Docker Swarm 与 Kubernetes 同时发布，但 Kubernetes 现在已成为容器编排平台的事实选择。这是因为 Kubernetes 能够在生产环境中很好地工作。它易于使用，支持多种开发人员配置，并且可以处理高规模环境。

## Kubernetes 集群

Kubernetes 集群由多台机器（或**虚拟机**（**VMs**））或节点组成。有两种类型的节点：主节点和工作节点。主控制平面，如`kube-apiserver`，运行在主节点上。每个工作节点上运行的代理称为`kubelet`，代表`kube-apiserver`运行，并运行在工作节点上。Kubernetes 中的典型工作流程始于用户（例如，DevOps），与主节点中的`kube-apiserver`通信，`kube-apiserver`将部署工作委派给工作节点。在下一节中，我们将更详细地介绍`kube-apiserver`和`kubelet`：

![图 1.2 – Kubernetes 部署](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_01_02.jpg)

图 1.2 – Kubernetes 部署

上图显示用户如何向主节点（`kube-apiserver`）发送部署请求，`kube-apiserver`将部署执行委派给一些工作节点中的`kubelet`。

# Kubernetes 组件

Kubernetes 遵循客户端-服务器架构。在 Kubernetes 中，多个主节点控制多个工作节点。每个主节点和工作节点都有一组组件，这些组件对于集群的正常工作是必需的。主节点通常具有`kube-apiserver`、`etcd`存储、`kube-controller-manager`、`cloud-controller-manager`和`kube-scheduler`。工作节点具有`kubelet`、`kube-proxy`、**容器运行时接口（CRI）**组件、**容器存储接口（CRI）**组件等。我们现在将详细介绍每一个：

+   `kube-apiserver`：Kubernetes API 服务器（`kube-apiserver`）是一个控制平面组件，用于验证和配置诸如 pod、服务和控制器等对象的数据。它使用 REST 请求与对象交互。

+   `etcd`：`etcd`是一个高可用的键值存储，用于存储配置、状态和元数据等数据。`etcd`的 watch 功能使 Kubernetes 能够监听配置的更新并相应地进行更改。

+   `kube-scheduler`：`kube-scheduler`是 Kubernetes 的默认调度程序。它监视新创建的 pod 并将 pod 分配给节点。调度程序首先过滤可以运行 pod 的一组节点。过滤包括根据用户设置的可用资源和策略创建可能节点的列表。一旦创建了这个列表，调度程序就会对节点进行排名，找到最适合 pod 的节点。

+   `kube-controller-manager`：Kubernetes 控制器管理器是一组核心控制器，它们监视状态更新并相应地对集群进行更改。目前随 Kubernetes 一起提供的控制器包括以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/01.jpg)

+   `cloud-controller-manager`：云容器管理器是在 v1.6 中引入的，它运行控制器与底层云提供商进行交互。这是为了将云供应商的代码与 Kubernetes 的代码解耦。

+   `kubelet`：`kubelet`在每个节点上运行。它向 API 服务器注册节点。`kubelet`监视使用 Podspecs 创建的 pod，并确保 pod 和容器健康。

+   `kube-proxy`：`kube-proxy`是在每个节点上运行的网络代理。它管理每个节点上的网络规则，并根据这些规则转发或过滤流量。

+   `kube-dns`：DNS 是在集群启动时启动的内置服务。从 v1.12 开始，CoreDNS 成为推荐的 DNS 服务器，取代了`kube-dns`。CoreDNS 使用单个容器（而不是`kube-dns`使用的三个容器）。它使用多线程缓存，并具有内置的负缓存，因此在内存和性能方面优于`kube-dns`。

在本节中，我们看了 Kubernetes 的核心组件。这些组件将存在于所有的 Kubernetes 集群中。Kubernetes 还有一些可配置的接口，允许对集群进行修改以适应组织的需求。

## Kubernetes 接口

Kubernetes 旨在灵活和模块化，因此集群管理员可以修改网络、存储和容器运行时能力，以满足组织的需求。目前，Kubernetes 提供了三种不同的接口，集群管理员可以使用这些接口来使用集群中的不同功能。

### 容器网络接口

Kubernetes 有一个默认的网络提供程序 `kubenet`，其功能有限。`kubenet` 只支持每个集群 50 个节点，显然无法满足大规模部署的任何要求。同时，Kubernetes 利用**容器网络接口**（**CNI**）作为网络提供程序和 Kubernetes 网络组件之间的通用接口，以支持大规模集群中的网络通信。目前支持的提供程序包括 Calico、Flannel、`kube-router` 等。

### 容器存储接口

Kubernetes 在 v1.13 中引入了容器存储接口。在 1.13 之前，新的卷插件是核心 Kubernetes 代码的一部分。容器存储接口提供了一个接口，用于向 Kubernetes 公开任意块和文件存储。云提供商可以使用 CSI 插件向 Kubernetes 公开高级文件系统。MapR 和 Snapshot 等插件在集群管理员中很受欢迎。

### 容器运行时接口

在 Kubernetes 的最低级别，容器运行时确保容器启动、工作和停止。最流行的容器运行时是 Docker。容器运行时接口使集群管理员能够使用其他容器运行时，如 `frakti`、`rktlet` 和 `cri-o`。

# Kubernetes 对象

系统的存储和计算资源被分类为反映集群当前状态的不同对象。对象使用 `.yaml` 规范进行定义，并使用 Kubernetes API 来创建和管理这些对象。我们将详细介绍一些常见的 Kubernetes 对象。

## Pods

Pod 是 Kubernetes 集群的基本构建块。它是一个或多个容器的组，这些容器预期在单个主机上共存。Pod 中的容器可以使用本地主机或**进程间通信**（**IPC**）相互引用。

## 部署

Kubernetes 部署可以根据标签和选择器来扩展或缩减 pod。部署的 YAML 规范包括 `replicas`，即所需的 pod 实例数量，以及 `template`，与 pod 规范相同。

## 服务

Kubernetes 服务是应用程序的抽象。服务为 pod 提供网络访问。服务和部署共同工作，以便简化不同应用程序的不同 pod 之间的管理和通信。

## 副本集

副本集确保系统中始终运行指定数量的 pod。最好使用部署而不是副本集。部署封装了副本集和 pod。此外，部署提供了进行滚动更新的能力。

## 卷

容器存储是暂时的。如果容器崩溃或重新启动，它会从启动时的原始状态开始。Kubernetes 卷有助于解决这个问题。容器可以使用卷来存储状态。Kubernetes 卷的生命周期与 pod 相同；一旦 pod 消失，卷也会被清理掉。一些支持的卷包括`awsElasticBlockStore`、`azureDisk`、`flocker`、`nfs`和`gitRepo`。

## 命名空间

命名空间帮助将物理集群划分为多个虚拟集群。多个对象可以在不同的命名空间中进行隔离。默认的 Kubernetes 附带三个命名空间：`default`、`kube-system`和`kube-public`。

## 服务账户

需要与`kube-apiserver`交互的 pod 使用服务账户来标识自己。默认情况下，Kubernetes 配置了一系列默认服务账户：`kube-proxy`、`kube-dns`、`node-controller`等。可以创建额外的服务账户来强制执行自定义访问控制。

## 网络策略

网络策略定义了一组规则，规定了一组 pod 如何允许与彼此和其他网络端点进行通信。所有传入和传出的网络连接都受网络策略的控制。默认情况下，一个 pod 可以与所有 pod 进行通信。

## Pod 安全策略

Pod 安全策略是一个集群级资源，定义了必须满足的一组条件，才能在系统上运行 pod。Pod 安全策略定义了 pod 的安全敏感配置。这些策略必须对请求用户或目标 pod 的服务账户可访问才能生效。

# Kubernetes 变体

在 Kubernetes 生态系统中，Kubernetes 是各种变体中的旗舰。然而，还有一些其他起着非常重要作用的船只。接下来，我们将介绍一些类似 Kubernetes 的平台，在生态系统中发挥不同的作用。

## Minikube

Minikube 是 Kubernetes 的单节点集群版本，可以在 Linux、macOS 和 Windows 平台上运行。Minikube 支持标准的 Kubernetes 功能，如`LoadBalancer`、服务、`PersistentVolume`、`Ingress`、容器运行时，以及开发人员友好的功能，如附加组件和 GPU 支持。

Minikube 是一个很好的起点，可以让您亲身体验 Kubernetes。它也是一个很好的地方来在本地运行测试，特别是集群依赖或工作在概念验证上。

## K3s

K3s 是一个轻量级的 Kubernetes 平台。其总大小不到 40MB。它非常适合边缘计算，物联网（IoT）和 ARM，先前是高级 RISC 机器，最初是 Acorn RISC Machine 的一系列用于各种环境的精简指令集计算（RISC）架构的计算机处理器。它应该完全符合 Kubernetes。与 Kubernetes 的一个重要区别是，它使用`sqlite`作为默认存储机制，而 Kubernetes 使用`etcd`作为其默认存储服务器。

## OpenShift

OpenShift 3 版本采用了 Docker 作为其容器技术，Kubernetes 作为其容器编排技术。在第 4 版中，OpenShift 切换到 CRI-O 作为默认的容器运行时。看起来 OpenShift 应该与 Kubernetes 相同；然而，它们之间有相当多的区别。

### OpenShift 与 Kubernetes

Linux 和 Red Hat Linux 之间的联系可能首先看起来与 OpenShift 和 Kubernetes 之间的联系相同。现在，让我们来看一下它们的一些主要区别。

#### 命名

在 Kubernetes 中命名的对象在 OpenShift 中可能有不同的名称，尽管有时它们的功能是相似的。例如，在 Kubernetes 中，命名空间称为 OpenShift 中的项目，并且项目创建附带默认对象。在 Kubernetes 中，Ingress 称为 OpenShift 中的路由。路由实际上比 Ingress 对象更早引入。在 OpenShift 下，路由由 HAProxy 实现，而在 Kubernetes 中有许多 Ingress 控制器选项。在 Kubernetes 中，部署称为`deploymentConfig`。然而，在底层实现上有很大的不同。

#### 安全性

Kubernetes 默认是开放的，安全性较低。OpenShift 相对封闭，并提供了一些良好的安全机制来保护集群。例如，在创建 OpenShift 集群时，DevOps 可以启用内部镜像注册表，该注册表不会暴露给外部。同时，内部镜像注册表充当受信任的注册表，图像将从中拉取和部署。OpenShift 项目在某些方面比`kubernetes`命名空间做得更好——在 OpenShift 中创建项目时，可以修改项目模板并向项目添加额外的对象，例如`NetworkPolicy`和符合公司政策的默认配额。这也有助于默认加固。

#### 成本

OpenShift 是 Red Hat 提供的产品，尽管有一个名为 OpenShift Origin 的社区版本项目。当人们谈论 OpenShift 时，他们通常指的是得到 Red Hat 支持的付费 OpenShift 产品。Kubernetes 是一个完全免费的开源项目。

# Kubernetes 和云提供商

很多人相信 Kubernetes 是基础设施的未来，也有一些人相信一切都会最终转移到云上。然而，这并不意味着你必须在云上运行 Kubernetes，但它确实在云上运行得非常好。

## Kubernetes 作为服务

容器化使应用程序更具可移植性，因此不太可能与特定的云提供商绑定。尽管有一些出色的开源工具，如`kubeadm`和`kops`，可以帮助 DevOps 创建 Kubernetes 集群，但云提供商提供的 Kubernetes 作为服务仍然很有吸引力。作为 Kubernetes 的原始创建者，Google 自 2014 年起就提供了 Kubernetes 作为服务。它被称为**Google Kubernetes Engine**（**GKE**）。2017 年，微软推出了自己的 Kubernetes 服务，称为**Azure Kubernetes Service**（**AKS**）。AWS 在 2018 年推出了**Elastic Kubernetes Service**（**EKS**）。

Kubedex（[`kubedex.com/google-gke-vs-microsoft-aks-vs-amazon-eks/`](https://kubedex.com/google-gke-vs-microsoft-aks-vs-amazon-eks/)）对云 Kubernetes 服务进行了很好的比较。以下表格列出了这三者之间的一些差异：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/02_a.jpg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/02_b.jpg)

前面列表中值得强调的一些亮点如下：

+   **可扩展性**：GKE 支持每个集群最多 5000 个节点，而 AKS 和 EKS 只支持少量节点或更少。

+   **高级安全选项**：GKE 支持 Istio 服务网格、Sandbox、二进制授权和入口管理的**安全套接字层**（**SSL**），而 AKS 和 EKS 则不支持。

如果计划在由云提供商提供的 Kubernetes 集群中部署和管理微服务，您需要考虑云提供商提供的可扩展性能力以及安全选项。如果您使用由云提供商管理的集群，则存在一些限制：

+   云提供商默认情况下会执行一些集群配置和加固，并且可能无法更改。

+   您失去了管理 Kubernetes 集群的灵活性。例如，如果您想要启用 Kubernetes 的审计策略并将审计日志导出到`splunk`，您可能需要对`kube-apiserver`清单进行一些配置更改。

+   对运行`kube-apiserver`的主节点的访问受到限制。如果您专注于部署和管理微服务，这种限制完全是有意义的。在某些情况下，您需要启用一些准入控制器，然后还需要对`kube-apiserver`清单进行更改。这些操作需要访问主节点。

如果您想要访问集群节点的 Kubernetes 集群，可以使用一个开源工具——`kops`。

## Kops

**Kubernetes 操作**（**kops**）有助于通过命令行创建、销毁、升级和维护高可用的生产级 Kubernetes 集群。它正式支持 AWS，并在 beta 版本中支持 GCE 和 OpenStack。与在云 Kubernetes 服务上提供 Kubernetes 集群的主要区别在于，提供是从 VM 层开始的。这意味着使用`kops`可以控制您想要使用的操作系统映像，并设置自己的管理员 SSH 密钥以访问主节点和工作节点。在 AWS 中创建 Kubernetes 集群的示例如下：

```
  # Create a cluster in AWS that has HA masters. This cluster
  # will be setup with an internal networking in a private VPC.
  # A bastion instance will be setup to provide instance access.
  export NODE_SIZE=${NODE_SIZE:-m4.large}
  export MASTER_SIZE=${MASTER_SIZE:-m4.large}
  export ZONES=${ZONES:-'us-east-1d,us-east-1b,us-east-1c'}
  export KOPS_STATE_STORE='s3://my-state-store'
  kops create cluster k8s-clusters.example.com \
  --node-count 3 \
  --zones $ZONES \
  --node-size $NODE_SIZE \
  --master-size $MASTER_SIZE \
  --master-zones $ZONES \
  --networking weave \
  --topology private \
  --bastion='true' \
  --yes
```

通过前面的`kops`命令，创建了一个包含三个工作节点的 Kubernetes 集群。用户可以选择主节点和 CNI 插件的大小。

## 为什么要担心 Kubernetes 的安全性？

Kubernetes 在 2018 年正式推出，并且仍在快速发展。还有一些功能仍在开发中，尚未达到 GA 状态（alpha 或 beta）。这表明 Kubernetes 本身远未成熟，至少从安全的角度来看。但这并不是我们需要关注 Kubernetes 安全性的主要原因。

Bruce Schneier 在 1999 年的一篇名为《简化的请求》的文章中最好地总结了这一点，他说“*复杂性是安全的最大敌人*”，准确预测了我们今天遇到的网络安全问题。为了满足稳定性、可扩展性、灵活性和安全性的所有主要编排需求，Kubernetes 被设计成复杂但紧密的方式。这种复杂性无疑带来了一些安全问题。

可配置性是 Kubernetes 平台对开发人员的主要优势之一。开发人员和云提供商可以自由配置他们的集群以满足他们的需求。Kubernetes 的这一特性是企业日益增加的安全担忧的主要原因之一。Kubernetes 代码的不断增长和 Kubernetes 集群的组件使得 DevOps 难以理解正确的配置。默认配置通常不安全（开放性确实为 DevOps 尝试新功能带来了优势）。

随着 Kubernetes 的使用增加，它因各种安全漏洞和缺陷而成为新闻头条：

+   Palo Alto Networks 的研究人员发现了 40,000 个 Docker 和 Kubernetes 容器暴露在互联网上。这是由于配置错误导致的结果。

+   攻击者利用了特斯拉的未加密管理控制台来运行加密挖矿设备。

+   在 Kubernetes 版本中发现了特权升级漏洞，允许经过精心设计的请求通过 API 服务器与后端建立连接并发送任意请求。

+   在生产环境中使用 Kubernetes 元数据测试版功能导致了对流行的电子商务平台 Shopify 的**服务器端请求伪造**（**SSRF**）攻击。这个漏洞暴露了 Kubernetes 元数据，揭示了 Google 服务帐户令牌和`kube-env`详细信息，使攻击者能够 compromise 集群。

The New Stack 最近的一项调查（[`thenewstack.io/top-challenges-kubernetes-users-face-deployment/`](https://thenewstack.io/top-challenges-kubernetes-users-face-deployment/)）显示，安全是运行 Kubernetes 的企业的主要关注点：

![图 1.3 - Kubernetes 用户的主要关注点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_01_03.jpg)

图 1.3 - Kubernetes 用户的主要关注点

Kubernetes 默认情况下不安全。我们将在后面的章节中详细解释这一点。安全成为用户的主要关注点之一是完全有道理的。这是一个需要妥善解决的问题，就像其他基础设施或平台一样。

# 摘要

微服务的趋势和 Docker 的兴起使得 Kubernetes 成为 DevOps 部署、扩展和管理容器化应用程序的事实标准平台。Kubernetes 将存储和计算资源抽象为 Kubernetes 对象，由`kube-apiserver`、`kubelet`、`etcd`等组件管理。

Kubernetes 可以在私有数据中心或云上或混合环境中创建。这使得 DevOps 可以与多个云提供商合作，而不会被锁定在任何一个云提供商上。尽管 Kubernetes 在 2018 年已经成熟，但它仍然年轻，并且发展非常迅速。随着 Kubernetes 受到越来越多的关注，针对 Kubernetes 的攻击也变得更加显著。

在下一章中，我们将介绍 Kubernetes 网络模型，并了解微服务在 Kubernetes 中如何相互通信。

# 问题

1.  单体架构的主要问题是什么？

1.  Kubernetes 的主要组件是什么？

1.  部署是什么？

1.  Kubernetes 的一些变体是什么？

1.  我们为什么关心 Kubernetes 的安全性？

# 进一步阅读

以下链接包含有关 Kubernetes、`kops`和 OpenShift 平台的更详细信息。在开始构建 Kubernetes 集群时，您会发现它们很有用：

+   [`kubernetes.io/docs/concepts/`](https://kubernetes.io/docs/concepts/)

+   [`kubernetes.io/docs/tutorials/`](https://kubernetes.io/docs/tutorials/)

+   [`github.com/kubernetes/kops`](https://github.com/kubernetes/kops)

+   [`docs.openshift.com/container-platform/4.2`](https://docs.openshift.com/container-platform/4.2)

+   [`cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview`](https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview)


# 第二章：Kubernetes 网络

当成千上万的微服务在 Kubernetes 集群中运行时，您可能会好奇这些微服务如何相互通信以及与互联网通信。在本章中，我们将揭示 Kubernetes 集群中所有通信路径。我们希望您不仅了解通信是如何发生的，还要以安全意识查看技术细节：常规通信渠道总是可以作为 kill 链的一部分被滥用。

在本章中，我们将涵盖以下主题：

+   Kubernetes 网络模型概述

+   在 pod 内部通信

+   在 pod 之间通信

+   引入 Kubernetes 服务

+   引入 CNI 和 CNI 插件

# Kubernetes 网络模型概述

在 Kubernetes 集群上运行的应用程序应该可以从集群内部或外部访问。从网络的角度来看，这意味着应用程序可能与**统一资源标识符**（**URI**）或**互联网协议**（**IP**）地址相关联。多个应用程序可以在同一 Kubernetes 工作节点上运行，但它们如何在不与彼此冲突的情况下暴露自己呢？让我们一起来看看这个问题，然后深入了解 Kubernetes 网络模型。

## 端口共享问题

传统上，如果在同一台机器上运行两个不同的应用程序，其中机器 IP 是公共的，并且这两个应用程序是公开访问的，那么这两个应用程序不能在机器上监听相同的端口。如果它们都尝试在同一台机器的相同端口上监听，由于端口被使用，一个应用程序将无法启动。下图提供了这个问题的简单说明：

![图 2.1 - 节点上的端口共享冲突（应用程序）](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_001.jpg)

图 2.1 - 节点上的端口共享冲突（应用程序）

为了解决端口共享冲突问题，这两个应用程序需要使用不同的端口。显然，这里的限制是这两个应用程序必须共享相同的 IP 地址。如果它们有自己的 IP 地址，但仍然位于同一台机器上会怎样？这就是纯 Docker 的方法。如果应用程序不需要外部暴露自己，这将有所帮助，如下图所示：

![图 2.2 - 节点上的端口共享冲突（容器）](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_002.jpg)

图 2.2 - 节点上的端口共享冲突（容器）

在上图中，两个应用程序都有自己的 IP 地址，因此它们都可以监听端口 80。它们可以相互通信，因为它们位于同一个子网中（例如，一个 Docker 桥接）。然而，如果两个应用程序都需要通过将容器端口绑定到主机端口来在外部公开自己，它们就不能绑定在相同的端口 80 上。至少一个端口绑定将失败。如上图所示，容器 B 无法绑定到主机端口 80，因为主机端口 80 被容器 A 占用。端口共享冲突问题仍然存在。

动态端口配置给系统带来了很多复杂性，涉及端口分配和应用程序发现；然而，Kubernetes 并不采取这种方法。让我们讨论一下 Kubernetes 解决这个问题的方法。

## Kubernetes 网络模型

在 Kubernetes 集群中，每个 Pod 都有自己的 IP 地址。这意味着应用程序可以在 Pod 级别相互通信。这种设计的美妙之处在于，它提供了一个清晰、向后兼容的模型，其中 Pod 在端口分配、命名、服务发现、负载平衡、应用程序配置和迁移方面的表现就像虚拟机（VM）或物理主机一样。同一 Pod 内的容器共享相同的 IP 地址。很少有类似的应用程序会在同一 Pod 内使用相同的默认端口（如 Apache 和 nginx）。实际上，捆绑在同一容器内的应用程序通常具有依赖性或提供不同的目的，这取决于应用程序开发人员将它们捆绑在一起。一个简单的例子是，在同一个 Pod 中，有一个超文本传输协议（HTTP）服务器或一个 nginx 容器来提供静态文件，以及一个用于提供动态内容的主 Web 应用程序。

Kubernetes 利用 CNI 插件来实现 IP 地址分配、管理和 Pod 通信。然而，所有插件都需要遵循以下两个基本要求：

1.  节点上的 Pod 可以与所有节点上的所有 Pod 进行通信，而无需使用网络地址转换（NAT）。

1.  诸如`kubelet`之类的代理可以与同一节点上的 Pod 进行通信。

这两个先前的要求强制了在虚拟机内迁移应用程序到 Pod 的简单性。

分配给每个 pod 的 IP 地址是一个私有 IP 地址或集群 IP 地址，不对公众开放。那么，一个应用程序如何在不与集群中的其他应用程序发生冲突的情况下变得对公众可访问呢？Kubernetes 服务就是将内部应用程序暴露给公众的方式。我们将在后面的章节中更深入地探讨 Kubernetes 服务的概念。现在，用下面的图表总结本章内容将会很有用：

![图 2.3 - 服务暴露给互联网](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_003.jpg)

图 2.3 - 服务暴露给互联网

在上一个图表中，有一个**k8s 集群**，其中有四个应用程序在两个 pod 中运行：**应用程序 A**和**应用程序 B**在**Pod X**中运行，并共享相同的 pod IP 地址—**100.97.240.188**—它们分别在端口**8080**和**9090**上监听。同样，**应用程序 C**和**应用程序 D**在**Pod Y**中运行，并分别在端口**8000**和**9000**上监听。所有这四个应用程序都可以通过以下面向公众的 Kubernetes 服务进行访问：**svc.a.com**，**svc.b.com**，**svc.c.com**和**svc.d.com**。这个图表中的 pod（X 和 Y）可以部署在一个单独的工作节点上，也可以在 1000 个节点上复制。然而，从用户或服务的角度来看，这并没有什么区别。尽管图表中的部署方式相当不寻常，但仍然需要在同一个 pod 内部部署多个容器。现在是时候来看看同一个 pod 内部容器之间的通信了。

# 在 pod 内部通信

同一个 pod 内的容器共享相同的 pod IP 地址。通常，将容器映像捆绑在一起并解决可能的资源使用冲突（如端口监听）是应用程序开发人员的责任。在本节中，我们将深入探讨容器内部通信的技术细节，并强调超出网络层面的通信。

## Linux 命名空间和暂停容器

Linux 命名空间是 Linux 内核的一个特性，用于分区资源以进行隔离。使用分配的命名空间，一组进程看到一组资源，而另一组进程看到另一组资源。命名空间是现代容器技术的一个重要基本方面。读者理解这个概念对于深入了解 Kubernetes 很重要。因此，我们列出了所有的 Linux 命名空间并进行了解释。自 Linux 内核版本 4.7 以来，有七种类型的命名空间，如下所示：

+   **cgroup**：隔离 cgroup 和根目录。cgroup 命名空间虚拟化了进程 cgroup 的视图。每个 cgroup 命名空间都有自己的 cgroup 根目录集。

+   **IPC**：隔离 System V 进程间通信（IPC）对象或 POSIX 消息队列。

+   **网络**：隔离网络设备、协议栈、端口、IP 路由表、防火墙规则等。

+   **挂载**：隔离挂载点。因此，每个挂载命名空间实例中的进程将看到不同的单目录层次结构。

+   **PID**：隔离进程 ID（PIDs）。不同 PID 命名空间中的进程可以具有相同的 PID。

+   **用户**：隔离用户 ID 和组 ID、根目录、密钥和功能。在用户命名空间内外，进程可以具有不同的用户和组 ID。

+   Unix 时间共享（UTS）：隔离两个系统标识符：主机名和网络信息服务（NIS）域名。

尽管每个命名空间都很强大，并且在不同资源上提供隔离目的，但并非所有命名空间都适用于同一 Pod 内的容器。同一 Pod 内的容器至少共享相同的 IPC 命名空间和网络命名空间；因此，K8s 需要解决端口使用可能的冲突。将创建一个回环接口，以及分配给 Pod 的 IP 地址的虚拟网络接口。更详细的图表将如下所示：

![图 2.4 - Pod 内的容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_004.jpg)

图 2.4 - Pod 内的容器

在这个图表中，有一个**Pause**容器与容器**A**和**B**一起运行在同一个 pod 中。如果您通过**Secure Shell**（**SSH**）进入 Kubernetes 集群节点并在节点内运行`docker ps`命令，您将看到至少一个使用`pause`命令启动的容器。`pause`命令会暂停当前进程，直到接收到信号。基本上，这些容器什么也不做，只是休眠。尽管没有活动，**Pause**容器在 pod 中扮演着关键的角色。它作为一个占位符，为同一个 pod 中的所有其他容器持有网络命名空间。与此同时，**Pause**容器获取了一个 IP 地址，用于所有其他容器之间以及与外部世界通信的虚拟网络接口。

## 超越网络通信

我们决定在同一个 pod 中的容器之间稍微超越网络通信。这样做的原因是通信路径有时可能成为杀伤链的一部分。因此，了解实体之间可能的通信方式非常重要。您将在*第三章*中看到更多相关内容，*威胁建模*。

在一个 pod 内，所有容器共享相同的 IPC 命名空间，以便容器可以通过 IPC 对象或 POSIX 消息队列进行通信。除了 IPC 通道，同一个 pod 内的容器还可以通过共享挂载卷进行通信。挂载的卷可以是临时内存、主机文件系统或云存储。如果卷被 Pod 中的容器挂载，那么容器可以读写卷中的相同文件。最后但并非最不重要的是，在 1.12 Kubernetes 版本的 beta 版中，`shareProcessNamespace`功能最终在 1.17 版本中稳定。用户可以简单地在 Podspec 中设置`shareProcessNamespace`选项，以允许 pod 内的容器共享一个公共 PID 命名空间。其结果是**Container A**中的**Application A**现在能够看到**Container B**中的**Application B**。由于它们都在相同的 PID 命名空间中，它们可以使用诸如 SIGTERM、SIGKILL 等信号进行通信。这种通信可以在以下图表中看到：

![图 2.5 - pod 内部容器之间可能的通信](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_005.jpg)

图 2.5 - pod 内部容器之间可能的通信

As the previous diagram shows, containers inside the same pod can communicate to each other via a network, an IPC channel, a shared volume, and through signals.

# Communicating between pods

Kubernetes pods are dynamic beings and ephemeral. When a set of pods is created from a deployment or a DaemonSet, each pod gets its own IP address; however, when patching happens or a pod dies and restarts, pods may have a new IP address assigned. This leads to two fundamental communication problems, given a set of pods (frontend) needs to communicate to another set of pods (backend), detailed as follows:

+   Given that the IP addresses may change, what are the valid IP addresses of the target pods?

+   Knowing the valid IP addresses, which pod should we communicate to?

Now, let's jump into the Kubernetes service as it is the solution for these two problems.

## The Kubernetes service

The Kubernetes service is an abstraction of a grouping of sets of pods with a definition of how to access the pods. The set of pods targeted by a service is usually determined by a selector based on pod labels. The Kubernetes service also gets an IP address assigned, but it is virtual. The reason to call it a virtual IP address is that, from a node's perspective, there is neither a namespace nor a network interface bound to a service as there is with a pod. Also, unlike pods, the service is more stable, and its IP address is less likely to be changed frequently. Sounds like we should be able to solve the two problems mentioned earlier. First, define a service for the target sets of pods with a proper selector configured; secondly, let some magic associated with the service decide which target pod is to receive the request. So, when we look at pod-to-pod communication again, we're in fact talking about pod-to-service (then to-pod) communication.

So, what's the magic behind the service? Now, we'll introduce the great network magician: the `kube-proxy` component.

## kube-proxy

你可以根据`kube-proxy`的名称猜到它的作用。一般来说，代理（不是反向代理）的作用是在客户端和服务器之间通过两个连接传递流量：从客户端到服务器的入站连接和从服务器到客户端的出站连接。因此，`kube-proxy`为了解决前面提到的两个问题，会将所有目标服务（虚拟 IP）的流量转发到由服务分组的 pod（实际 IP）；同时，`kube-proxy`会监视 Kubernetes 控制平面，以便添加或删除服务和端点对象（pod）。为了很好地完成这个简单的任务，`kube-proxy`已经发展了几次。

### 用户空间代理模式

用户空间代理模式中的`kube-proxy`组件就像一个真正的代理。首先，`kube-proxy`将在节点上的一个随机端口上作为特定服务的代理端口进行监听。任何对代理端口的入站连接都将被转发到服务的后端 pod。当`kube-proxy`需要决定将请求发送到哪个后端 pod 时，它会考虑服务的`SessionAffinity`设置。其次，`kube-proxy`将安装**iptables 规则**，将任何目标服务（虚拟 IP）的流量转发到代理端口，代理端口再将流量转发到后端端口。来自 Kubernetes 文档的以下图表很好地说明了这一点：

![图 2.6 - kube-proxy 用户空间代理模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_006.jpg)

图 2.6 - kube-proxy 用户空间代理模式

默认情况下，用户空间模式中的`kube-proxy`使用循环算法来选择要将请求转发到的后端 pod。这种模式的缺点是显而易见的。流量转发是在用户空间中完成的。这意味着数据包被编组到用户空间，然后在代理的每次传输中被编组回内核空间。从性能的角度来看，这种解决方案并不理想。

### iptables 代理模式

iptables 代理模式中的`kube-proxy`组件将转发流量的工作交给了`netfilter`，使用 iptables 规则。在 iptables 代理模式中的`kube-proxy`只负责维护和更新 iptables 规则。任何针对服务 IP 的流量都将根据`kube-proxy`管理的 iptables 规则由`netfilter`转发到后端 pod。来自 Kubernetes 文档的以下图表说明了这一点：

![图 2.7 - kube-proxy iptables 代理模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_007.jpg)

图 2.7 - kube-proxy iptables 代理模式

与用户空间代理模式相比，iptables 模式的优势是显而易见的。流量不再经过内核空间到用户空间，然后再返回内核空间。相反，它将直接在内核空间中转发。开销大大降低。这种模式的缺点是需要错误处理。例如，如果`kube-proxy`在 iptables 代理模式下运行，如果第一个选择的 pod 没有响应，连接将失败。然而，在用户空间模式下，`kube-proxy`会检测到与第一个 pod 的连接失败，然后自动重试与不同的后端 pod。

### IPVS 代理模式

**IP Virtual Server**（**IPVS**）代理模式中的`kube-proxy`组件管理和利用 IPVS 规则，将目标服务流量转发到后端 pod。就像 iptables 规则一样，IPVS 规则也在内核中工作。IPVS 建立在`netfilter`之上。它作为 Linux 内核的一部分实现传输层负载均衡，纳入**Linux Virtual Server**（**LVS**）中。LVS 在主机上运行，并充当一组真实服务器前面的负载均衡器，任何传输控制协议（TCP）或用户数据报协议（UDP）流量都将被转发到真实服务器。这使得真实服务器的 IPVS 服务看起来像单个 IP 地址上的虚拟服务。IPVS 与 Kubernetes 服务完美匹配。以下来自 Kubernetes 文档的图表说明了这一点：

![图 2.8 - kube-proxy IPVS 代理模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_008.jpg)

图 2.8 - kube-proxy IPVS 代理模式

与 iptables 代理模式相比，IPVS 规则和 iptables 规则都在内核空间中工作。然而，iptables 规则会对每个传入的数据包进行顺序评估。规则越多，处理时间越长。IPVS 的实现与 iptables 不同：它使用由内核管理的哈希表来存储数据包的目的地，因此具有比 iptables 规则更低的延迟和更快的规则同步。IPVS 模式还提供了更多的负载均衡选项。使用 IPVS 模式的唯一限制是必须在节点上有可供`kube-proxy`使用的 IPVS Linux。

# 介绍 Kubernetes 服务

Kubernetes 部署动态创建和销毁 pod。对于一般的三层 Web 架构，如果前端和后端是不同的 pod，这可能是一个问题。前端 pod 不知道如何连接到后端。Kubernetes 中的网络服务抽象解决了这个问题。

Kubernetes 服务使一组逻辑 pod 能够进行网络访问。通常使用标签来定义一组逻辑 pod。当对服务发出网络请求时，它会选择所有具有特定标签的 pod，并将网络请求转发到所选 pod 中的一个。

使用**YAML Ain't Markup Language** (**YAML**)文件定义了 Kubernetes 服务，如下所示：

```
apiVersion: v1
kind: Service
metadata:
  name: service-1
spec:
  type: NodePort 
  selector:
    app: app-1
  ports:
    - nodePort: 29763
      protocol: TCP
      port: 80
      targetPort: 9376
```

在这个 YAML 文件中，以下内容适用：

1.  `type`属性定义了服务如何向网络公开。

1.  `selector`属性定义了 Pod 的标签。

1.  `port`属性用于定义在集群内部公开的端口。

1.  `targetPort`属性定义了容器正在侦听的端口。

服务通常使用选择器来定义，选择器是附加到需要在同一服务中的 pod 的标签。服务可以在没有选择器的情况下定义。这通常是为了访问外部服务或不同命名空间中的服务。没有选择器的服务将使用端点对象映射到网络地址和端口，如下所示：

```
apiVersion: v1
kind: Endpoints
subsets:
  - addresses:
      - ip: 192.123.1.22
    ports:
      - port: 3909
```

此端点对象将路由流量`192:123.1.22:3909`到附加的服务。

## 服务发现

要找到 Kubernetes 服务，开发人员可以使用环境变量或**Domain Name System** (**DNS**)，详细如下：

1.  **环境变量**：创建服务时，在节点上创建了一组环境变量，形式为`[NAME]_SERVICE_HOST`和`[NAME]_SERVICE_PORT`。其他 pod 或应用程序可以使用这些环境变量来访问服务，如下面的代码片段所示：

```
DB_SERVICE_HOST=192.122.1.23
DB_SERVICE_PORT=3909
```

1.  **DNS**：DNS 服务作为附加组件添加到 Kubernetes 中。Kubernetes 支持两个附加组件：CoreDNS 和 Kube-DNS。DNS 服务包含服务名称到 IP 地址的映射。Pod 和应用程序使用此映射来连接到服务。

客户端可以通过环境变量和 DNS 查询来定位服务 IP，而且有不同类型的服务来为不同类型的客户端提供服务。

## 服务类型

服务可以有四种不同的类型，如下所示：

+   **ClusterIP**：这是默认值。此服务只能在集群内访问。可以使用 Kubernetes 代理来外部访问 ClusterIP 服务。使用`kubectl`代理进行调试是可取的，但不建议用于生产服务，因为它需要以经过身份验证的用户身份运行`kubectl`。

+   **NodePort**：此服务可以通过每个节点上的静态端口访问。NodePorts 每个端口暴露一个服务，并需要手动管理 IP 地址更改。这也使得 NodePorts 不适用于生产环境。

+   **LoadBalancer**：此服务可以通过负载均衡器访问。通常每个服务都有一个节点负载均衡器是一个昂贵的选择。

+   **ExternalName**：此服务有一个关联的**规范名称记录**（**CNAME**），用于访问该服务。

有几种要使用的服务类型，它们在 OSI 模型的第 3 层和第 4 层上工作。它们都无法在第 7 层路由网络请求。为了路由请求到应用程序，如果 Kubernetes 服务支持这样的功能将是理想的。那么，让我们看看 Ingress 对象如何在这里帮助。

## 用于路由外部请求的 Ingress

Ingress 不是一种服务类型，但在这里值得一提。Ingress 是一个智能路由器，为集群中的服务提供外部**HTTP/HTTPS**（**超文本传输安全协议**）访问。除了 HTTP/HTTPS 之外的服务只能暴露给 NodePort 或 LoadBalancer 服务类型。Ingress 资源是使用 YAML 文件定义的，就像这样：

```
apiVersion: extensions/v1beta1
kind: Ingress
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        backend:
          serviceName: service-1
          servicePort: 80
```

这个最小的 Ingress 规范将`testpath`路由的所有流量转发到`service-1`路由。

Ingress 对象有五种不同的变体，列举如下：

+   **单服务 Ingress**：通过指定默认后端和没有规则来暴露单个服务，如下面的代码块所示：

```
apiVersion: extensions/v1beta1
kind: Ingress
spec:
  backend:
    serviceName: service-1
    servicePort: 80
```

这个 Ingress 暴露了一个专用 IP 地址给`service-1`。

+   **简单的分流**：分流配置根据**统一资源定位符**（**URL**）将来自单个 IP 的流量路由到多个服务，如下面的代码块所示：

```
apiVersion: extensions/v1beta1
kind: Ingress
spec:
  rules:
  - host: foo.com
    http:
      paths:
      - path: /foo
        backend:
          serviceName: service-1
          servicePort: 8080
      - path: /bar
        backend:
          serviceName: service-2
          servicePort: 8080
```

这个配置允许`foo.com/foo`的请求到达`service-1`，并且`foo.com/bar`连接到`service-2`。

+   **基于名称的虚拟主机**：此配置使用多个主机名来达到一个 IP 到达不同服务的目的，如下面的代码块所示：

```
apiVersion: extensions/v1beta1
kind: Ingress
spec:
  rules:
  - host: foo.com
    http:
      paths:
      - backend:
          serviceName: service-1
          servicePort: 80
  - host: bar.com
    http:
      paths:
      - backend:
          serviceName: service-2
          servicePort: 80
```

这个配置允许`foo.com`的请求连接到`service-1`，`bar.com`的请求连接到`service-2`。在这种情况下，两个服务分配的 IP 地址是相同的。

+   传输层安全性（TLS）：可以向入口规范添加一个秘密以保护端点，如下面的代码块所示：

```
apiVersion: extensions/v1beta1
kind: Ingress
spec:
  tls:
  - hosts:
    - ssl.foo.com
    secretName: secret-tls
  rules:
    - host: ssl.foo.com
      http:
        paths:
        - path: /
          backend:
            serviceName: service-1
            servicePort: 443
```

通过这个配置，`secret-tls`提供了端点的私钥和证书。

+   负载平衡：负载平衡入口提供负载平衡策略，其中包括所有入口对象的负载平衡算法和权重方案。

在本节中，我们介绍了 Kubernetes 服务的基本概念，包括入口对象。这些都是 Kubernetes 对象。然而，实际的网络通信魔术是由几个组件完成的，比如`kube-proxy`。接下来，我们将介绍 CNI 和 CNI 插件，这是为 Kubernetes 集群的网络通信提供服务的基础。

# 介绍 CNI 和 CNI 插件

在 Kubernetes 中，CNI 代表容器网络接口。CNI 是云原生计算基金会（CNCF）的一个项目-您可以在 GitHub 上找到更多信息：[`github.com/containernetworking/cni`](https://github.com/containernetworking/cni)。基本上，这个项目有三个东西：一个规范，用于编写插件以配置 Linux 容器中的网络接口的库，以及一些支持的插件。当人们谈论 CNI 时，他们通常指的是规范或 CNI 插件。CNI 和 CNI 插件之间的关系是 CNI 插件是可执行的二进制文件，实现了 CNI 规范。现在，让我们高层次地看看 CNI 规范和插件，然后我们将简要介绍 CNI 插件之一，Calico。

## CNI 规范和插件

CNI 规范只关注容器的网络连接性，并在容器删除时移除分配的资源。让我更详细地解释一下。首先，从容器运行时的角度来看，CNI 规范为**容器运行时接口**（**CRI**）组件（如 Docker）定义了一个接口，用于与之交互，例如在创建容器时向网络接口添加容器，或者在容器死亡时删除网络接口。其次，从 Kubernetes 网络模型的角度来看，由于 CNI 插件实际上是 Kubernetes 网络插件的另一种类型，它们必须符合 Kubernetes 网络模型的要求，详细如下：

1.  节点上的 pod 可以与所有节点上的所有 pod 进行通信，而无需使用 NAT。

1.  `kubelet`等代理可以与同一节点中的 pod 进行通信。

有一些可供选择的 CNI 插件，比如 Calico、Cilium、WeaveNet、Flannel 等。CNI 插件的实施各不相同，但总的来说，CNI 插件的功能类似。它们执行以下任务：

+   管理容器的网络接口

+   为 pod 分配 IP 地址。这通常是通过调用其他**IP 地址管理**（**IPAM**）插件（如`host-local`）来完成的。

+   实施网络策略（可选）

CNI 规范中不要求实施网络策略，但是当 DevOps 选择要使用的 CNI 插件时，考虑安全性是很重要的。Alexis Ducastel 的文章（[`itnext.io/benchmark-results-of-kubernetes-network-plugins-cni-over-10gbit-s-network-36475925a560`](https://itnext.io/benchmark-results-of-kubernetes-network-plugins-cni-over-10gbit-s-network-36475925a560)）在 2019 年 4 月进行了主流 CNI 插件的良好比较。安全性比较值得注意，如下截图所示：

![图 2.9 - CNI 插件比较](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_009.jpg)

图 2.9 - CNI 插件比较

您可能会注意到列表中大多数 CNI 插件都不支持加密。Flannel 不支持 Kubernetes 网络策略，而`kube-router`仅支持入口网络策略。

由于 Kubernetes 默认使用`kubenet`插件，为了在 Kubernetes 集群中使用 CNI 插件，用户必须通过`--network-plugin=cni`命令行选项传递，并通过`--cni-conf-dir`标志或在`/etc/cni/net.d`默认目录中指定配置文件。以下是在 Kubernetes 集群中定义的示例配置，以便`kubelet`知道要与哪个 CNI 插件交互：

```
{
  'name': 'k8s-pod-network',
  'cniVersion': '0.3.0',
  'plugins': [
    {
      'type': 'calico',
      'log_level': 'info',
      'datastore_type': 'kubernetes',
      'nodename': '127.0.0.1',
      'ipam': {
        'type': 'host-local',
        'subnet': 'usePodCidr'
      },
      'policy': {
        'type': 'k8s'
      },
      'kubernetes': {
        'kubeconfig': '/etc/cni/net.d/calico-kubeconfig'
      }
    },
    {
      'type': 'portmap',
      'capabilities': {'portMappings': true}
    }
  ]
}
```

CNI 配置文件告诉`kubelet`使用 Calico 作为 CNI 插件，并使用`host-local`来为 pod 分配 IP 地址。在列表中，还有另一个名为`portmap`的 CNI 插件，用于支持`hostPort`，允许容器端口在主机 IP 上暴露。

在使用**Kubernetes Operations**（**kops**）创建集群时，您还可以指定要使用的 CNI 插件，如下面的代码块所示：

```
  export NODE_SIZE=${NODE_SIZE:-m4.large}
  export MASTER_SIZE=${MASTER_SIZE:-m4.large}
  export ZONES=${ZONES:-'us-east-1d,us-east-1b,us-east-1c'}
  export KOPS_STATE_STORE='s3://my-state-store'
  kops create cluster k8s-clusters.example.com \
  --node-count 3 \
  --zones $ZONES \
  --node-size $NODE_SIZE \
  --master-size $MASTER_SIZE \
  --master-zones $ZONES \
  --networking calico \
  --topology private \
  --bastion='true' \
  --yes
```

在此示例中，集群是使用`calico` CNI 插件创建的。

## Calico

Calico 是一个开源项目，可以实现云原生应用的连接和策略。它与主要的编排系统集成，如 Kubernetes、Apache Mesos、Docker 和 OpenStack。与其他 CNI 插件相比，Calico 有一些值得强调的优点：

1.  Calico 提供了一个扁平的 IP 网络，这意味着 IP 消息中不会附加 IP 封装（没有覆盖）。这也意味着分配给 pod 的每个 IP 地址都是完全可路由的。无需覆盖即可运行的能力提供了出色的吞吐特性。

1.  根据 Alexis Ducastel 的实验，Calico 具有更好的性能和更少的资源消耗。

1.  与 Kubernetes 内置的网络策略相比，Calico 提供了更全面的网络策略。Kubernetes 的网络策略只能定义白名单规则，而 Calico 网络策略可以定义黑名单规则（拒绝）。

将 Calico 集成到 Kubernetes 中时，您会看到以下三个组件在 Kubernetes 集群中运行：

+   `calico/node`是一个 DaemonSet 服务，这意味着它在集群中的每个节点上运行。它负责为本地工作负载编程和路由内核路由，并强制执行集群中当前网络策略所需的本地过滤规则。它还负责向其他节点广播路由表，以保持集群中 IP 路由的同步。

+   CNI 插件二进制文件。这包括两个可执行二进制文件（`calico`和`calico-ipam`）以及一个配置文件，直接与每个节点上的 Kubernetes `kubelet`进程集成。它监视 pod 创建事件，然后将 pod 添加到 Calico 网络中。

+   Calico Kubernetes 控制器作为一个独立的 pod 运行，监视 Kubernetes **应用程序编程接口**（**API**）以保持 Calico 同步。

Calico 是一个流行的 CNI 插件，也是**Google Kubernetes Engine**（**GKE**）中的默认 CNI 插件。Kubernetes 管理员完全可以自由选择符合其要求的 CNI 插件。只需记住安全性是至关重要的决定因素之一。在前面的章节中，我们已经谈了很多关于 Kubernetes 网络的内容。在你忘记之前，让我们快速回顾一下。

## 总结

在 Kubernetes 集群中，每个 pod 都被分配了一个 IP 地址，但这是一个内部 IP 地址，无法从外部访问。同一 pod 中的容器可以通过名称网络接口相互通信，因为它们共享相同的网络命名空间。同一 pod 中的容器还需要解决端口资源冲突的问题；然而，这种情况发生的可能性非常小，因为应用程序在同一 pod 中的不同容器中运行，目的是特定的。此外，值得注意的是，同一 pod 中的容器可以通过共享卷、IPC 通道和进程信号进行网络通信。

Kubernetes 服务有助于稳定 pod 之间的通信，因为 pod 通常是短暂的。该服务也被分配了一个 IP 地址，但这是虚拟的，意味着没有为服务创建网络接口。`kube-proxy`网络魔术师实际上将所有流量路由到目标服务的后端 pod。`kube-proxy`有三种不同的模式：用户空间代理、iptables 代理和 IPVS 代理。Kubernetes 服务不仅提供了对 pod 之间通信的支持，还能够实现来自外部源的通信。

有几种方法可以公开服务，使其可以从外部源访问，例如 NodePort、LoadBalancer 和 ExternalName。此外，您可以创建一个 Ingress 对象来实现相同的目标。最后，虽然很难，但我们将使用以下单个图表来尝试整合我们在本章中要强调的大部分知识：

![图 2.10 - 通信：pod 内部、pod 之间以及来自外部的源](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_02_010.jpg)

图 2.10 - 通信：pod 内部，pod 之间，以及来自外部来源

几乎每个 Kubernetes 集群前面都有一个负载均衡器。根据我们之前提到的不同服务类型，这可能是一个通过负载均衡器公开的单个服务（这是服务**A**），或者它可以通过 NodePort 公开。这是服务**B**，在两个节点上使用节点端口**30000**来接受外部流量。虽然 Ingress 不是一种服务类型，但与 LoadBalancer 类型服务相比，它更强大且成本效益更高。服务**C**和服务**D**的路由由同一个 Ingress 对象控制。集群中的每个 pod 可能在前面的标注图中有一个内部通信拓扑。

# 总结

在本章中，我们首先讨论了典型的端口资源冲突问题，以及 Kubernetes 网络模型如何在避免这一问题的同时保持对从 VM 迁移到 Kubernetes pod 的应用程序的良好兼容性。然后，我们讨论了 pod 内部的通信，pod 之间的通信，以及来自外部来源到 pod 的通信。

最后但并非最不重要的是，我们介绍了 CNI 的基本概念，并介绍了 Calico 在 Kubernetes 环境中的工作原理。在前两章中，我们希望您对 Kubernetes 组件的工作方式以及各个组件之间的通信有了基本的了解。

在下一章中，我们将讨论威胁建模 Kubernetes 集群。

# 问题

1.  在 Kubernetes 集群中，IP 地址分配给 pod 还是容器？

1.  在同一个 pod 内部，哪些 Linux 命名空间将被容器共享？

1.  暂停容器是什么，它有什么作用？

1.  Kubernetes 服务有哪些类型？

1.  除了 LoadBalancer 类型的服务，使用 Ingress 的优势是什么？

# 进一步阅读

如果您想构建自己的 CNI 插件或评估 Calico 更多，请查看以下链接：

+   [`github.com/containernetworking/cni`](https://github.com/containernetworking/cni)

+   [`docs.projectcalico.org/v3.11/reference/architecture/`](https://docs.projectcalico.org/v3.11/reference/architecture/)

+   [`docs.projectcalico.org/v3.11/getting-started/kubernetes/installation/integration`](https://docs.projectcalico.org/v3.11/getting-started/kubernetes/installation/integration)


# 第三章：威胁建模

Kubernetes 是一个庞大的生态系统，包括多个组件，如`kube-apiserver`、`etcd`、`kube-scheduler`、`kubelet`等。在第一章中，我们强调了不同 Kubernetes 组件的基本功能。在默认配置中，Kubernetes 组件之间的交互会导致开发人员和集群管理员应该意识到的威胁。此外，在 Kubernetes 中部署应用程序会引入应用程序与之交互的新实体，为应用程序的威胁模型增加新的威胁行为者和攻击面。

在本章中，我们将从简要介绍威胁建模开始，讨论 Kubernetes 生态系统内的组件交互。我们将研究默认 Kubernetes 配置中的威胁。最后，我们将讨论在 Kubernetes 生态系统中对应用进行威胁建模如何引入额外的威胁行为者和攻击面。

本章的目标是帮助您了解，默认的 Kubernetes 配置不足以保护您部署的应用免受攻击者的侵害。Kubernetes 是一个不断发展和由社区维护的平台，因此本章要突出的一些威胁并没有相应的缓解措施，因为威胁的严重程度会随着每个环境的不同而变化。

本章旨在突出 Kubernetes 生态系统中的威胁，其中包括 Kubernetes 集群中的 Kubernetes 组件和工作负载，以便开发人员和 DevOps 工程师了解其部署的风险，并制定已知威胁的风险缓解计划。在本章中，我们将涵盖以下主题：

+   威胁建模介绍

+   组件交互

+   Kubernetes 环境中的威胁行为者

+   Kubernetes 组件/对象威胁模型

+   在 Kubernetes 中对应用程序进行威胁建模

# 威胁建模介绍

威胁建模是在**软件开发生命周期**（**SDLC**）的设计阶段分析系统作为整体，以主动识别系统的风险的过程。威胁建模用于在开发周期的早期考虑安全需求，以从一开始减轻风险的严重性。威胁建模涉及识别威胁，了解每个威胁的影响，最终为每个威胁制定缓解策略。威胁建模旨在将生态系统中的风险突出显示为一个简单的矩阵，其中包括风险的可能性和影响，以及相应的风险缓解策略（如果存在）。

成功的威胁建模会使您能够定义以下内容：

1.  **资产**：生态系统中需要保护的财产。

1.  **安全控制**：系统的属性，用于保护资产免受已识别风险的影响。这些是对资产风险的防护措施或对策。

1.  **威胁行为者**：威胁行为者是利用风险的实体或组织，包括脚本小子、国家级攻击者和黑客活动分子。

1.  **攻击面**：威胁行为者与系统交互的部分。它包括威胁行为者进入系统的入口点。

1.  **威胁**：对资产的风险。

1.  **缓解**：缓解定义了如何减少对资产的威胁的可能性和影响。

行业通常遵循以下威胁建模方法之一：

+   **STRIDE**：STRIDE 模型于 1999 年由微软发布。它是欺骗、篡改、否认、信息泄露、拒绝服务和特权升级的首字母缩略词。STRIDE 模型威胁系统，以回答“系统可能出现什么问题？”的问题。

+   **PASTA**：攻击模拟和威胁分析过程是一种以风险为中心的威胁建模方法。PASTA 遵循以攻击者为中心的方法，由业务和技术团队开发以资产为中心的缓解策略。

+   **VAST**：Visual, Agile, and Simple Threat modeling 旨在将威胁建模整合到应用程序和基础架构开发中，与 SDLC 和敏捷软件开发相结合。它提供了一种可视化方案，为开发人员、架构师、安全研究人员和业务执行人员提供可操作的输出。

威胁建模还有其他方法，但前面三种是行业内最常用的方法。

如果威胁模型的范围没有明确定义，威胁建模可能是一个无限长的任务。在开始识别生态系统中的威胁之前，重要的是清楚地了解每个组件的架构和工作方式，以及组件之间的交互。

在前几章中，我们已经详细了解了每个 Kubernetes 组件的基本功能。现在，我们将在调查 Kubernetes 生态系统内的威胁之前，先看一下 Kubernetes 中不同组件之间的交互。

# 组件交互

Kubernetes 组件共同工作，以确保集群内运行的微服务能够如预期般运行。如果将微服务部署为 DaemonSet，则 Kubernetes 组件将确保每个节点上都有一个运行微服务的 pod，不多不少。那么在幕后会发生什么？让我们看一下高层次上组件之间的交互的图表：

![图 3.1 - Kubernetes 组件之间的交互](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_03_001.jpg)

图 3.1 - Kubernetes 组件之间的交互

这些组件的快速回顾：

+   kube-apiserver：Kubernetes API 服务器（`kube-apiserver`）是一个控制平面组件，用于验证和配置对象的数据。

+   etcd：`etcd`是一个高可用的键值存储，用于存储配置、状态和元数据等数据。

+   kube-scheduler：`kube-scheduler`是 Kubernetes 的默认调度程序。它监视新创建的 pod，并将 pod 分配给节点。

+   kube-controller-manager：Kubernetes 控制器管理器是一组核心控制器，它们监视状态更新并相应地对集群进行更改。

+   cloud-controller-manager：云控制器管理器运行控制器，与底层云提供商进行交互。

+   kubelet：`kubelet`向 API 服务器注册节点，并监视使用 Podspecs 创建的 pod，以确保 pod 和容器健康。

值得注意的是，只有`kube-apiserver`与`etcd`通信。其他 Kubernetes 组件，如`kube-scheduler`、`kube-controller-manager`和`cloud-controller manager`与运行在主节点上的`kube-apiserver`进行交互，以履行它们的责任。在工作节点上，`kubelet`和`kube-proxy`都与`kube-apiserver`通信。

让我们以 DaemonSet 创建为例，展示这些组件如何相互通信：

![图 3.2 - 在 Kubernetes 中创建 DaemonSet](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_03_002.jpg)

图 3.2 - 在 Kubernetes 中创建 DaemonSet

要创建一个 DaemonSet，我们使用以下步骤：

1.  用户通过 HTTPS 向`kube-apiserver`发送请求以创建 DaemonSet 工作负载。

1.  经过身份验证、授权和对象验证后，`kube-apiserver`在`etcd`数据库中为 DaemonSet 创建工作负载对象信息。默认情况下，`etcd`中的数据在传输和静止状态下都不加密。

1.  DaemonSet 控制器监视新的 DaemonSet 对象的创建，然后向`kube-apiserver`发送 pod 创建请求。请注意，DaemonSet 基本上意味着微服务将在每个节点的 pod 中运行。

1.  `kube-apiserver`重复*步骤 2*中的操作，并在`etcd`数据库中为 pod 创建工作负载对象信息。

1.  `kube-scheduler`监视新的 pod 的创建，然后根据节点选择标准决定在哪个节点上运行该 pod。之后，`kube-scheduler`向`kube-apiserver`发送有关 pod 将在哪个节点上运行的请求。

1.  `kube-apiserver`接收来自`kube-scheduler`的请求，然后使用 pod 的节点分配信息更新`etcd`。

1.  运行在工作节点上的`kubelet`监视分配给该节点的新 pod，然后向**容器运行时接口**（**CRI**）组件（如 Docker）发送请求以启动容器。之后，`kubelet`将 pod 的状态发送回`kube-apiserver`。

1.  `kube-apiserver`从目标节点上的`kubelet`接收 pod 的状态信息，然后更新`etcd`数据库中的 pod 状态。

1.  一旦创建了（来自 DaemonSet 的）pod，这些 pod 就能够与其他 Kubernetes 组件进行通信，微服务应该已经启动并运行。

请注意，并非所有组件之间的通信都默认安全。这取决于这些组件的配置。我们将在*第六章*中更详细地介绍这一点，*保护集群组件*。

# Kubernetes 环境中的威胁行为者

威胁行为者是系统中执行的应该受到保护的资产的实体或代码。从防御的角度来看，你首先需要了解你的潜在敌人是谁，否则你的防御策略将太模糊。Kubernetes 环境中的威胁行为者可以大致分为三类：

1.  终端用户：可以连接到应用程序的实体。该参与者的入口点通常是负载均衡器或入口。有时，Pod、容器或 NodePorts 可能直接暴露在互联网上，为终端用户增加了更多的入口点。

1.  内部攻击者：在 Kubernetes 集群内部具有有限访问权限的实体。集群内生成的恶意容器或 Pod 是内部攻击者的示例。

1.  特权攻击者：在 Kubernetes 集群内部具有管理员访问权限的实体。基础设施管理员、被 compromise 的`kube-apiserver`实例和恶意节点都是特权攻击者的示例。

威胁参与者的示例包括脚本小子、骇客活动分子和国家行为者。所有这些参与者都属于前面提到的三类，取决于参与者在系统中的位置。

以下图表突出了 Kubernetes 生态系统中的不同参与者：

![图 3.3– Kubernetes 环境中的威胁参与者](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_03_003.jpg)

图 3.3– Kubernetes 环境中的威胁参与者

正如您在此图表中所看到的，终端用户通常与入口控制器、负载均衡器或 Pod 暴露的 HTTP/HTTPS 路由进行交互。终端用户权限最低。另一方面，内部攻击者对集群内部的资源具有有限访问权限。特权攻击者权限最高，并且有能力修改集群。这三类攻击者有助于确定威胁的严重程度。涉及终端用户的威胁比涉及特权攻击者的威胁具有更高的严重性。尽管这些角色在图表中似乎是孤立的，但攻击者可以通过权限提升攻击从终端用户变为内部攻击者。

# Kubernetes 集群中的威胁

通过对 Kubernetes 组件和威胁参与者的新理解，我们将继续进行 Kubernetes 集群的威胁建模之旅。在下表中，我们涵盖了主要的 Kubernetes 组件、节点和 Pod。节点和 Pod 是运行工作负载的基本 Kubernetes 对象。请注意，所有这些组件都是资产，应该受到威胁的保护。这些组件中的任何一个被 compromise 都可能导致攻击的下一步，比如权限提升。还要注意，`kube-apiserver`和`etcd`是 Kubernetes 集群的大脑和心脏。如果它们中的任何一个被 compromise，那将是游戏结束。

下表突出了默认 Kubernetes 配置中的威胁。该表还突出了开发人员和集群管理员如何保护其资产免受这些威胁的影响：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.1-a.jpg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.1-b.jpg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.1-c.jpg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.1-d.jpg)

这张表只突出了一些威胁。还有更多的威胁，将在后面的章节中进行讨论。我们希望前面的表格能激发您对需要在 Kubernetes 集群中保护什么以及如何保护的思考。

# 在 Kubernetes 中进行威胁建模应用

现在我们已经看过 Kubernetes 集群中的威胁，让我们继续讨论在 Kubernetes 上部署的应用程序的威胁建模将会有何不同。在 Kubernetes 中部署会给威胁模型增加额外的复杂性。Kubernetes 增加了额外的考虑因素、资产、威胁行为者和需要在调查部署应用程序的威胁之前考虑的新安全控制。

让我们来看一个简单的三层 Web 应用的例子：

![图 3.4 - 传统 Web 应用的威胁模型](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_03_004.jpg)

图 3.4 - 传统 Web 应用的威胁模型

在 Kubernetes 环境中，同一应用看起来有些不同：

图 3.5 - Kubernetes 中三层 Web 应用的威胁模型

](image/B15566_03_005.jpg)

图 3.5 - Kubernetes 中三层 Web 应用的威胁模型

如前图所示，Web 服务器、应用服务器和数据库都在 pod 中运行。让我们对传统 Web 架构和云原生架构之间的威胁建模进行高层比较：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.2-a.jpg)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/Table_3.2-b.jpg)

总结前面的比较，您会发现在云原生架构中需要保护更多的资产，并且在这个领域会面临更多的威胁行为者。Kubernetes 提供了更多的安全控制，但也增加了更多的复杂性。更多的安全控制并不一定意味着更安全。请记住：复杂性是安全的敌人。

# 总结

在本章中，我们首先介绍了威胁建模的基本概念。我们讨论了 Kubernetes 环境中的重要资产、威胁和威胁行为者。我们讨论了不同的安全控制和缓解策略，以改善您的 Kubernetes 集群的安全状况。

然后我们通过应用程序威胁建模，考虑了部署在 Kubernetes 中的应用程序，并将其与传统的单片应用程序的威胁建模进行了比较。Kubernetes 设计引入的复杂性使威胁建模变得更加复杂，正如我们所展示的：需要保护的资产更多，威胁行为者也更多。而更多的安全控制并不一定意味着更安全。

您应该记住，尽管威胁建模可能是一个漫长而复杂的过程，但值得去了解您环境的安全状况。同时进行应用程序威胁建模和基础设施威胁建模对于更好地保护您的 Kubernetes 集群非常必要。

在下一章中，为了帮助您了解如何将您的 Kubernetes 集群安全性提升到更高水平，我们将讨论最小特权原则以及如何在 Kubernetes 集群中实施它。

# 问题

1.  何时开始对应用程序进行威胁建模？

1.  Kubernetes 环境中有哪些不同的威胁行为者？

1.  提到默认 Kubernetes 部署的最严重的威胁之一。

1.  为什么在 Kubernetes 环境中威胁建模更加困难？

1.  Kubernetes 部署的攻击面与传统架构中的部署相比如何？

# 进一步阅读

Trail of Bits 和 Atredis Partners 在 Kubernetes 组件的威胁建模方面做得很好。他们的白皮书详细介绍了每个 Kubernetes 组件中的威胁。您可以在[`github.com/kubernetes/community/blob/master/wg-security-audit/findings/Kubernetes%20Threat%20Model.pdf`](https://github.com/kubernetes/community/blob/master/wg-security-audit/findings/Kubernetes%20Threat%20Model.pdf)找到这份白皮书。

请注意，前述白皮书的威胁建模的意图、范围和方法是不同的。因此，结果会有些不同。


# 第四章：在 Kubernetes 中应用最小权限原则

最小权限原则规定生态系统的每个组件在其功能运行所需的数据和资源上应具有最小的访问权限。在多租户环境中，不同用户或对象可以访问多个资源。最小权限原则确保在这种环境中，如果用户或对象行为不端，对集群造成的损害是最小的。

在本章中，我们将首先介绍最小权限原则。鉴于 Kubernetes 的复杂性，我们将首先研究 Kubernetes 主题，然后是主题可用的权限。然后，我们将讨论 Kubernetes 对象的权限以及限制它们的可能方式。本章的目标是帮助您理解一些关键概念，如最小权限原则和基于角色的访问控制（RBAC）。在本章中，我们将讨论不同的 Kubernetes 对象，如命名空间、服务账户、角色和角色绑定，以及 Kubernetes 安全特性，如安全上下文、PodSecurityPolicy 和 NetworkPolicy，这些特性可以用来实现 Kubernetes 集群的最小权限原则。

在本章中，我们将涵盖以下主题：

+   最小权限原则

+   Kubernetes 主题的最小权限

+   Kubernetes 工作负载的最小权限

# 最小权限原则

特权是执行操作的权限，例如访问资源或处理一些数据。最小特权原则是任何主体、用户、程序、进程等都应该只具有执行其功能所需的最低特权的想法。例如，Alice，一个普通的 Linux 用户，能够在自己的主目录下创建文件。换句话说，Alice 至少具有在她的主目录下创建文件的特权或权限。然而，Alice 可能无法在另一个用户的目录下创建文件，因为她没有这样做的特权或权限。如果 Alice 的日常任务中没有一个实际行使在主目录中创建文件的特权，但她确实有这样做的特权，那么机器的管理员就没有遵守最小特权原则。在本节中，我们将首先介绍授权模型的概念，然后我们将讨论实施最小特权原则的好处。

## 授权模型

当我们谈论最小特权时，大多数时候我们是在授权的背景下谈论的，在不同的环境中，会有不同的授权模型。例如，**访问控制列表**（**ACL**）广泛用于 Linux 和网络防火墙，而 RBAC 用于数据库系统。环境的管理员也有责任定义授权策略，以确保基于系统中可用的授权模型的最小特权。以下列表定义了一些流行的授权模型：

+   **ACL**：ACL 定义了与对象关联的权限列表。它指定了哪些主体被授予对对象的访问权限，以及对给定对象允许的操作。例如，`-rw`文件权限是文件所有者的读写权限。

+   RBAC：授权决策基于主体的角色，其中包含一组权限或特权。例如，在 Linux 中，用户被添加到不同的组（如`staff`）以授予对文件夹的访问权限，而不是单独被授予对文件系统上文件夹的访问权限。

+   **基于属性的访问控制（ABAC）**：授权决策基于主体的属性，例如标签或属性。基于属性的规则检查用户属性，如`user.id="12345"`，`user.project="project"`和`user.status="active"`，以决定用户是否能够执行任务。

Kubernetes 支持 ABAC 和 RBAC。尽管 ABAC 功能强大且灵活，但在 Kubernetes 中的实施使其难以管理和理解。因此，建议在 Kubernetes 中启用 RBAC 而不是 ABAC。除了 RBAC，Kubernetes 还提供了多种限制资源访问的方式。在接下来的部分中我们将探讨 Kubernetes 中的 RBAC 和 ABAC 之前，让我们讨论确保最小特权的好处。

## 最小特权原则的奖励

尽管可能需要相当长的时间来理解主体的最低特权是为了执行其功能，但如果最小特权原则已经在您的环境中实施，奖励也是显著的：

+   **更好的安全性**：通过实施最小特权原则，可以减轻内部威胁、恶意软件传播、横向移动等问题。爱德华·斯诺登的泄密事件发生是因为缺乏最小特权。

+   **更好的稳定性**：鉴于主体只被适当地授予必要的特权，主体的活动变得更加可预测。作为回报，系统的稳定性得到了加强。

+   **改进的审计准备性**：鉴于主体只被适当地授予必要的特权，审计范围将大大减少。此外，许多常见的法规要求实施最小特权原则作为合规要求。

既然您已经看到了实施最小特权原则的好处，我也想介绍一下挑战：Kubernetes 的开放性和可配置性使得实施最小特权原则变得繁琐。让我们看看如何将最小特权原则应用于 Kubernetes 主体。

# Kubernetes 主体的最小特权

Kubernetes 服务账户、用户和组与`kube-apiserver`通信，以管理 Kubernetes 对象。启用 RBAC 后，不同的用户或服务账户可能具有操作 Kubernetes 对象的不同特权。例如，`system:master`组中的用户被授予`cluster-admin`角色，这意味着他们可以管理整个 Kubernetes 集群，而`system:kube-proxy`组中的用户只能访问`kube-proxy`组件所需的资源。首先，让我们简要介绍一下 RBAC 是什么。

## RBAC 简介

正如前面讨论的，RBAC 是一种基于授予用户或组角色的资源访问控制模型。从 1.6 版本开始，Kubernetes 默认启用了 RBAC。在 1.6 版本之前，可以通过使用带有`--authorization-mode=RBAC`标志的**应用程序编程接口**（**API**）服务器来启用 RBAC。RBAC 通过 API 服务器简化了权限策略的动态配置。

RBAC 的核心元素包括以下内容：

1.  **主体**：请求访问 Kubernetes API 的服务账户、用户或组。

1.  **资源**：需要被主体访问的 Kubernetes 对象。

1.  **动词**：主体在资源上需要的不同类型访问，例如创建、更新、列出、删除。

Kubernetes RBAC 定义了主体和它们在 Kubernetes 生态系统中对不同资源的访问类型。

## 服务账户、用户和组

Kubernetes 支持三种类型的主体，如下：

+   **普通用户**：这些用户是由集群管理员创建的。它们在 Kubernetes 生态系统中没有对应的对象。集群管理员通常使用**轻量级目录访问协议**（**LDAP**）、**Active Directory**（**AD**）或私钥来创建用户。

+   **服务账户**：Pod 使用服务账户对`kube-apiserver`对象进行身份验证。服务账户是通过 API 调用创建的。它们受限于命名空间，并且有关联的凭据存储为`secrets`。默认情况下，pod 使用`default`服务账户进行身份验证。

+   **匿名用户**：任何未与普通用户或服务账户关联的 API 请求都与匿名用户关联。

集群管理员可以通过运行以下命令创建与 pod 关联的新服务账户：

```
$ kubectl create serviceaccount new_account
```

在默认命名空间中将创建一个`new_account`服务账户。为了确保最小权限，集群管理员应将每个 Kubernetes 资源与具有最小权限的服务账户关联起来。

## 角色

角色是权限的集合——例如，命名空间 A 中的角色可以允许用户在命名空间 A 中创建 pods 并列出命名空间 A 中的 secrets。在 Kubernetes 中，没有拒绝权限。因此，角色是一组权限的添加。

角色受限于命名空间。另一方面，ClusterRole 在集群级别工作。用户可以创建跨整个集群的 ClusterRole。ClusterRole 可用于调解对跨集群的资源的访问，例如节点、健康检查和跨多个命名空间的对象，例如 pods。以下是一个角色定义的简单示例：

```
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: role-1
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
```

这个简单的规则允许`get`操作超越默认命名空间中的`pods`资源。可以通过执行以下命令使用 kubectl 创建此角色：

```
$ kubectl apply -f role.yaml
```

如果以下任一条件为真，则用户只能创建或修改角色：

+   用户在相同范围（命名空间或整个集群）中拥有角色中包含的所有权限。

+   用户与给定范围内的升级角色相关联。

这可以防止用户通过修改用户角色和权限来执行权限升级攻击。

## RoleBinding

RoleBinding 对象用于将角色与主体关联。与 ClusterRole 类似，ClusterRoleBinding 可以向跨命名空间的主体授予一组权限。让我们看几个例子：

1.  创建一个 RoleBinding 对象，将“custom-clusterrole”集群角色与默认命名空间中的`demo-sa`服务账户关联起来，就像这样：

```
kubectl create rolebinding new-rolebinding-sa \
     --clusterrole=custom-clusterrole \
     --serviceaccount=default:demo-sa
```

1.  创建一个 RoleBinding 对象，将`custom-clusterrole`集群角色与`group-1`组关联起来，就像这样：

```
kubectl create rolebinding new-rolebinding-group \
     --clusterrole=custom-clusterrole \
     --group=group-1 \
     --namespace=namespace-1
```

RoleBinding 对象将角色链接到主体，并使角色可重用且易于管理。

## Kubernetes 命名空间

命名空间是计算机科学中的一个常见概念，为相关资源提供了逻辑分组。命名空间用于避免名称冲突；同一命名空间内的资源应具有唯一名称，但跨命名空间的资源可以共享名称。在 Linux 生态系统中，命名空间允许隔离系统资源。

在 Kubernetes 中，命名空间允许多个团队和项目在逻辑上共享单个集群。使用 Kubernetes 命名空间，以下内容适用：

+   它们允许不同的应用程序、团队和用户在同一个集群中工作。

+   它们允许集群管理员为应用程序使用命名空间资源配额。

+   它们使用 RBAC 策略来控制对命名空间内特定资源的访问。RoleBinding 帮助集群管理员控制对命名空间内用户授予的权限。

+   它们允许在命名空间中使用网络策略进行网络分割。默认情况下，所有 pod 可以跨不同命名空间相互通信。

默认情况下，Kubernetes 有三个不同的命名空间。运行以下命令查看它们：

```
$ kubectl get namespace
NAME          STATUS    AGE
default       Active    1d
kube-system   Active    1d
kube-public   Active    1d
```

三个命名空间的描述如下：

+   `default`：不属于任何其他命名空间的资源的命名空间。

+   `kube-system`：Kubernetes 创建的对象的命名空间，如`kube-apiserver`、`kube-scheduler`、`controller-manager`和`coredns`。

+   `kube-public`：此命名空间内的资源对所有人都是可访问的。默认情况下，此命名空间中不会创建任何内容。

让我们看看如何创建一个命名空间。

### 创建命名空间

可以使用以下命令在 Kubernetes 中创建新的命名空间：

```
$ kubectl create namespace test
```

创建新的命名空间后，可以使用`namespace`属性将对象分配给命名空间，如下所示：

```
$ kubectl apply --namespace=test -f pod.yaml
```

同样地，可以使用`namespace`属性访问命名空间内的对象，如下所示：

```
$ kubectl get pods --namespace=test
```

在 Kubernetes 中，并非所有对象都有命名空间。低级别对象如`Nodes`和`persistentVolumes`跨越多个命名空间。

## 为 Kubernetes 主体实现最小特权

到目前为止，您应该熟悉 ClusterRole/Role、ClusterRoleBinding/RoleBinding、服务账户和命名空间的概念。为了为 Kubernetes 主体实现最小特权，您可以在创建 Kubernetes 中的 Role 或 RoleBinding 对象之前问自己以下问题：

+   主体是否需要在命名空间内或跨命名空间拥有权限？

这很重要，因为一旦主体具有集群级别的权限，它可能能够在所有命名空间中行使权限。

+   权限应该授予用户、组还是服务账户？

当您向一个组授予一个角色时，这意味着组中的所有用户将自动获得新授予角色的特权。在向组授予角色之前，请确保您了解其影响。其次，Kubernetes 中的用户是为人类而设，而服务账户是为 pod 中的微服务而设。请确保您了解 Kubernetes 用户的责任，并相应地分配特权。另外，请注意，一些微服务根本不需要任何特权，因为它们不直接与`kube-apiserver`或任何 Kubernetes 对象进行交互。

+   主体需要访问哪些资源？

在创建角色时，如果不指定资源名称或在`resourceNames`字段中设置`*`，则意味着已授予对该资源类型的所有资源的访问权限。如果您知道主体将要访问的资源名称，请在创建角色时指定资源名称。

Kubernetes 主体使用授予的特权与 Kubernetes 对象进行交互。了解您的 Kubernetes 主体执行的实际任务将有助于您正确授予特权。

# Kubernetes 工作负载的最小特权

通常，将会有一个（默认）服务账户与 Kubernetes 工作负载相关联。因此，pod 内的进程可以使用服务账户令牌与`kube-apiserver`通信。DevOps 应该仔细地为服务账户授予必要的特权，以实现最小特权的目的。我们在前一节已经介绍过这一点。

除了访问`kube-apiserver`来操作 Kubernetes 对象之外，pod 中的进程还可以访问工作节点上的资源以及集群中的其他 pod/微服务（在*第二章*，*Kubernetes 网络*中有介绍）。在本节中，我们将讨论对系统资源、网络资源和应用程序资源进行最小特权访问的可能实现。

## 访问系统资源的最小特权

请记住，运行在容器或 pod 内的微服务只是工作节点上的一个进程，在其自己的命名空间中隔离。根据配置，pod 或容器可以访问工作节点上的不同类型的资源。这由安全上下文控制，可以在 pod 级别和容器级别进行配置。配置 pod/容器安全上下文应该是开发人员的任务清单（在安全设计和审查的帮助下），而限制 pod/容器访问集群级别系统资源的另一种方式——pod 安全策略，应该是 DevOps 的任务清单。让我们深入了解安全上下文、Pod 安全策略和资源限制控制的概念。

### 安全上下文

安全上下文提供了一种方式来定义与访问系统资源相关的 pod 和容器的特权和访问控制设置。在 Kubernetes 中，pod 级别的安全上下文与容器级别的安全上下文不同，尽管它们有一些重叠的属性可以在两个级别进行配置。总的来说，安全上下文提供了以下功能，允许您为容器和 pod 应用最小特权原则：

+   自主访问控制（DAC）：这是用来配置将哪个用户 ID（UID）或组 ID（GID）绑定到容器中的进程，容器的根文件系统是否为只读等。强烈建议不要在容器中以 root 用户（UID = 0）身份运行您的微服务。安全影响是，如果存在漏洞并且容器逃逸到主机，攻击者立即获得主机上的 root 用户权限。

+   安全增强 Linux（SELinux）：这是用来配置 SELinux 安全上下文的，它为 pod 或容器定义了级别标签、角色标签、类型标签和用户标签。通过分配 SELinux 标签，pod 和容器可能会受到限制，特别是在能够访问节点上的卷方面。

+   特权模式：这是用来配置容器是否在特权模式下运行。特权容器内运行的进程的权限基本上与节点上的 root 用户相同。

+   **Linux 功能：** 这是为容器配置 Linux 功能。不同的 Linux 功能允许容器内的进程执行不同的活动或在节点上访问不同的资源。例如，`CAP_AUDIT_WRITE`允许进程写入内核审计日志，而`CAP_SYS_ADMIN`允许进程执行一系列管理操作。

+   **AppArmor：** 这是为 Pod 或容器配置 AppArmor 配置文件。AppArmor 配置文件通常定义了进程拥有哪些 Linux 功能，容器可以访问哪些网络资源和文件等。

+   **安全计算模式（seccomp）：** 这是为 Pod 或容器配置 seccomp 配置文件。seccomp 配置文件通常定义了允许执行的系统调用白名单和将被阻止在 Pod 或容器内执行的系统调用黑名单。

+   **AllowPrivilegeEscalation：** 这是用于配置进程是否可以获得比其父进程更多的权限。请注意，当容器以特权运行或具有`CAP_SYS_ADMIN`功能时，`AllowPrivilegeEscalation`始终为真。

我们将在*第八章*中更多地讨论安全上下文，*保护 Pods*。

### PodSecurityPolicy

PodSecurityPolicy 是 Kubernetes 集群级别的资源，用于控制与安全相关的 Pod 规范属性。它定义了一组规则。当要在 Kubernetes 集群中创建 Pod 时，Pod 需要遵守 PodSecurityPolicy 中定义的规则，否则将无法启动。PodSecurityPolicy 控制或应用以下属性：

+   允许运行特权容器

+   允许使用主机级别的命名空间

+   允许使用主机端口

+   允许使用不同类型的卷

+   允许访问主机文件系统

+   要求容器运行只读根文件系统

+   限制容器的用户 ID 和组 ID

+   限制容器的特权升级

+   限制容器的 Linux 功能

+   需要使用 SELinux 安全上下文

+   将 seccomp 和 AppArmor 配置文件应用于 Pod

+   限制 Pod 可以运行的 sysctl

+   允许使用`proc`挂载类型

+   限制 FSGroup 对卷的使用

我们将在《第八章》《Securing Kubernetes Pods》中更多地介绍 PodSecurityPolicy。PodSecurityPolicy 控制基本上是作为一个准入控制器实现的。您也可以创建自己的准入控制器，为您的工作负载应用自己的授权策略。**Open Policy Agent**（**OPA**）是另一个很好的选择，可以为工作负载实现自己的最小特权策略。我们将在《第七章》《Authentication, Authorization, and Admission Control》中更多地了解 OPA。

现在，让我们看一下 Kubernetes 中的资源限制控制机制，因为您可能不希望您的微服务饱和系统中的所有资源，比如**Central Processing Unit**（**CPU**）和内存。

### 资源限制控制

默认情况下，单个容器可以使用与节点相同的内存和 CPU 资源。运行加密挖矿二进制文件的容器可能会轻松消耗节点上其他 Pod 共享的 CPU 资源。为工作负载设置资源请求和限制始终是一个良好的实践。资源请求会影响调度器分配 Pod 的节点，而资源限制设置了容器终止的条件。为您的工作负载分配更多的资源请求和限制以避免驱逐或终止始终是安全的。但是，请记住，如果您将资源请求或限制设置得太高，您将在集群中造成资源浪费，并且分配给您的工作负载的资源可能无法充分利用。我们将在《第十章》《Real-Time Monitoring and Resource Management of a Kubernetes Cluster》中更多地介绍这个话题。

## 封装访问系统资源的最小特权

当 pod 或容器以特权模式运行时，与非特权 pod 或容器不同，它们具有与节点上的管理员用户相同的特权。如果您的工作负载以特权模式运行，为什么会这样？当一个 pod 能够访问主机级别的命名空间时，该 pod 可以访问主机级别的资源，如网络堆栈、进程和**进程间通信**（**IPC**）。但您真的需要授予主机级别的命名空间访问权限或设置特权模式给您的 pod 或容器吗？此外，如果您知道容器中的进程需要哪些 Linux 功能，最好放弃那些不必要的功能。您的工作负载需要多少内存和 CPU 才能完全正常运行？请考虑这些问题，以实现对您的 Kubernetes 工作负载的最小特权原则。正确设置资源请求和限制，为您的工作负载使用安全上下文，并为您的集群强制执行 PodSecurityPolicy。所有这些都将有助于确保您的工作负载以最小特权访问系统资源。

## 访问网络资源的最小特权

默认情况下，同一 Kubernetes 集群中的任何两个 pod 可以相互通信，如果在 Kubernetes 集群外没有配置代理规则或防火墙规则，一个 pod 可能能够与互联网通信。Kubernetes 的开放性模糊了微服务的安全边界，我们不应忽视容器或 pod 可以访问的其他微服务提供的 API 端点等网络资源。

假设您的工作负载（pod X）在名称空间 X 中只需要访问名称空间 NS1 中的另一个微服务 A；同时，名称空间 NS2 中有微服务 B。微服务 A 和微服务 B 都公开其**表述状态传输**（**REST**ful）端点。默认情况下，您的工作负载可以访问微服务 A 和 B，假设微服务级别没有身份验证或授权，以及名称空间 NS1 和 NS2 中没有强制执行网络策略。请看下面的图表，说明了这一点：

![图 4.1-没有网络策略的网络访问](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_04_001.jpg)

图 4.1-没有网络策略的网络访问

在前面的图中，**Pod X**能够访问这两个微服务，尽管它们位于不同的命名空间中。还要注意，**Pod X**只需要访问**NS1**命名空间中的**Microservice A**。那么，我们是否可以做一些事情，以限制**Pod X**仅出于最小特权的目的访问**Microservice A**？是的：Kubernetes 网络策略可以帮助。我们将在*第五章*中更详细地介绍网络策略，*配置 Kubernetes 安全边界*。一般来说，Kubernetes 网络策略定义了一组 Pod 允许如何相互通信以及与其他网络端点通信的规则。您可以为您的工作负载定义入口规则和出口规则。

注意

入口规则：定义哪些来源被允许与受网络策略保护的 Pod 通信的规则。

出口规则：定义哪些目的地被允许与受网络策略保护的 Pod 通信的规则。

在下面的示例中，为了在**Pod X**中实现最小特权原则，您需要在**Namespace X**中定义一个网络策略，其中包含一个出口规则，指定只允许**Microservice A**：

![图 4.2 - 网络策略阻止对微服务 B 的访问](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_04_002.jpg)

图 4.2 - 网络策略阻止对微服务 B 的访问

在前面的图中，**Namespace X**中的网络策略阻止了来自**Pod X**对**Microservice B**的任何请求，而**Pod X**仍然可以访问**Microservice A**，这是预期的。在您的网络策略中定义出口规则将有助于确保您的工作负载访问网络资源的最小特权。最后但同样重要的是，我们仍然需要从最小特权的角度关注应用程序资源级别。

## 访问应用程序资源的最小特权

虽然这个话题属于应用程序安全的范畴，但在这里提起也是值得的。如果有应用程序允许您的工作负载访问，并支持具有不同特权级别的多个用户，最好检查您的工作负载所代表的用户被授予的特权是否是必要的。例如，负责审计的用户不需要任何写入特权。应用程序开发人员在设计应用程序时应牢记这一点。这有助于确保您的工作负载访问应用程序资源的最小特权。

# 总结

在本章中，我们讨论了最小特权的概念。然后，我们讨论了 Kubernetes 中的安全控制机制，帮助在两个领域实现最小特权原则：Kubernetes 主体和 Kubernetes 工作负载。值得强调的是，全面实施最小特权原则的重要性。如果在任何领域中都忽略了最小特权，这可能会留下一个攻击面。

Kubernetes 提供了内置的安全控制，以实现最小特权原则。请注意，这是从开发到部署的一个过程：应用程序开发人员应与安全架构师合作，为与应用程序关联的服务账户设计最低特权，以及最低功能和适当的资源分配。在部署过程中，DevOps 应考虑使用 PodSecurityPolicy 和网络策略来强制执行整个集群的最小特权。

在下一章中，我们将从不同的角度看待 Kubernetes 的安全性：了解不同类型资源的安全边界以及如何加固它们。

# 问题

1.  在 Kubernetes 中，什么是 Role 对象？

1.  在 Kubernetes 中，什么是 RoleBinding 对象？

1.  RoleBinding 和 ClusterRoleBinding 对象之间有什么区别？

1.  默认情况下，Pod 无法访问主机级命名空间。列举一些允许 Pod 访问主机级命名空间的设置。

1.  如果您想限制 Pod 访问外部网络资源（例如内部网络或互联网），您可以做什么？

# 进一步阅读

您可能已经注意到，我们在本章中讨论的一些安全控制机制已经存在很长时间：SELinux 多类别安全/多级安全（MCS/MLS），AppArmor，seccomp，Linux 功能等。已经有许多书籍或文章介绍了这些技术。我鼓励您查看以下材料，以更好地了解如何使用它们来实现 Kubernetes 中的最小特权目标：

+   SELinux MCS: [`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/sec-mcs-getstarted`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/sec-mcs-getstarted)

+   AppArmor: [`ubuntu.com/server/docs/security-apparmor`](https://ubuntu.com/server/docs/security-apparmor)

+   Linux 能力：[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html)

+   帮助定义 RBAC 权限授予：[`github.com/liggitt/audit2rbac`](https://github.com/liggitt/audit2rbac)


# 第五章：配置 Kubernetes 安全边界

安全边界分隔了安全域，其中一组实体共享相同的安全关注和访问级别，而信任边界是程序执行和数据改变信任级别的分界线。安全边界中的控制确保在边界之间移动的执行不会在没有适当验证的情况下提升信任级别。如果数据或执行在没有适当控制的情况下在安全边界之间移动，安全漏洞就会出现。

在本章中，我们将讨论安全和信任边界的重要性。我们将首先重点介绍介绍，以澄清安全和信任边界之间的任何混淆。然后，我们将深入了解 Kubernetes 生态系统中的安全域和安全边界。最后，我们将看一些增强 Kubernetes 中应用程序安全边界的功能。

您应该了解安全域和安全边界的概念，并了解基于底层容器技术以及内置安全功能（如 PodSecurityPolicy 和 NetworkPolicy）构建的 Kubernetes 周围的安全边界。

本章将涵盖以下主题：

+   安全边界的介绍

+   安全边界与信任边界

+   Kubernetes 安全域

+   Kubernetes 实体作为安全边界

+   系统层的安全边界

+   网络层的安全边界

# 安全边界的介绍

安全边界存在于数据层、网络层和系统层。安全边界取决于 IT 部门或基础设施团队使用的技术。例如，公司使用虚拟机来管理他们的应用程序- hypervisor 是虚拟机的安全边界。Hypervisor 确保在虚拟机中运行的代码不会逃离虚拟机或影响物理节点。当公司开始采用微服务并使用编排器来管理他们的应用程序时，容器是安全边界之一。然而，与虚拟机监视器相比，容器并不提供强大的安全边界，也不打算提供。容器在应用程序层强制执行限制，但不能阻止攻击者从内核层绕过这些限制。

在网络层，传统上，防火墙为应用程序提供了强大的安全边界。在微服务架构中，Kubernetes 中的 Pod 可以相互通信。网络策略用于限制 Pod 和服务之间的通信。

数据层的安全边界是众所周知的。内核限制对系统或 bin 目录的写访问仅限于 root 用户或系统用户是数据层安全边界的一个简单例子。在容器化环境中，chroot 防止容器篡改其他容器的文件系统。Kubernetes 重新构建了应用程序部署的方式，可以在网络和系统层上强制执行强大的安全边界。

# 安全边界与信任边界

安全边界和信任边界经常被用作同义词。虽然相似，但这两个术语之间有微妙的区别。**信任边界**是系统改变其信任级别的地方。执行信任边界是指指令需要不同的特权才能运行的地方。例如，数据库服务器在`/bin`中执行代码就是执行越过信任边界的一个例子。同样，数据信任边界是指数据在不同信任级别的实体之间移动的地方。用户插入到受信任数据库中的数据就是数据越过信任边界的一个例子。

而**安全边界**是不同安全域之间的分界点，安全域是一组在相同访问级别内的实体。例如，在传统的 Web 架构中，面向用户的应用程序是安全域的一部分，而内部网络是不同安全域的一部分。安全边界有与之相关的访问控制。将信任边界看作墙，将安全边界看作围绕墙的栅栏。

在生态系统中识别安全和信任边界是很重要的。这有助于确保在指令和数据跨越边界之前进行适当的验证。在 Kubernetes 中，组件和对象跨越不同的安全边界。了解这些边界对于在攻击者跨越安全边界时制定风险缓解计划至关重要。CVE-2018-1002105 是一个缺少跨信任边界验证而导致的攻击的典型例子；API 服务器中的代理请求处理允许未经身份验证的用户获得对集群的管理员特权。同样，CVE-2018-18264 允许用户跳过仪表板上的身份验证过程，以允许未经身份验证的用户访问敏感的集群信息。

现在让我们来看看不同的 Kubernetes 安全领域。

# Kubernetes 安全领域

Kubernetes 集群可以大致分为三个安全领域：

+   **Kubernetes 主组件**：Kubernetes 主组件定义了 Kubernetes 生态系统的控制平面。主组件负责决策，以确保集群的顺利运行，如调度。主组件包括`kube-apiserver`、`etcd`、`kube-controller`管理器、DNS 服务器和`kube-scheduler`。Kubernetes 主组件的违规行为可能会危及整个 Kubernetes 集群。

+   **Kubernetes 工作组件**：Kubernetes 工作组件部署在每个工作节点上，确保 Pod 和容器正常运行。Kubernetes 工作组件使用授权和 TLS 隧道与主组件进行通信。即使工作组件受到损害，集群也可以正常运行。这类似于环境中的一个恶意节点，在识别后可以从集群中移除。

+   **Kubernetes 对象**：Kubernetes 对象是表示集群状态的持久实体：部署的应用程序、卷和命名空间。Kubernetes 对象包括 Pods、Services、卷和命名空间。这些是由开发人员或 DevOps 部署的。对象规范为对象定义了额外的安全边界：使用 SecurityContext 定义 Pod、与其他 Pod 通信的网络规则等。

高级安全领域划分应该帮助您专注于关键资产。记住这一点，我们将开始查看 Kubernetes 实体和围绕它们建立的安全边界。

# Kubernetes 实体作为安全边界

在 Kubernetes 集群中，您与之交互的 Kubernetes 实体（对象和组件）都有其自己内置的安全边界。这些安全边界源自实体的设计或实现。了解实体内部或周围构建的安全边界非常重要：

+   **容器**：容器是 Kubernetes 集群中的基本组件。容器使用 cgroups、Linux 命名空间、AppArmor 配置文件和 seccomp 配置文件为应用程序提供最小的隔离。

+   **Pods**：Pod 是一个或多个容器的集合。与容器相比，Pod 隔离更多资源，例如网络和 IPC。诸如 SecurityContext、NetworkPolicy 和 PodSecurityPolicy 之类的功能在 Pod 级别工作，以确保更高级别的隔离。

+   **节点**：Kubernetes 中的节点也是安全边界。可以使用`nodeSelectors`指定 Pod 在特定节点上运行。内核和虚拟化程序强制执行运行在节点上的 Pod 的安全控制。诸如 AppArmor 和 SELinux 之类的功能可以帮助改善安全姿态，以及其他主机加固机制。

+   **集群**：集群是一组 Pod、容器以及主节点和工作节点上的组件。集群提供了强大的安全边界。在集群内运行的 Pod 和容器在网络和系统层面上与其他集群隔离。

+   **命名空间**：命名空间是隔离 Pod 和服务的虚拟集群。LimitRanger 准入控制器应用于命名空间级别，以控制资源利用和拒绝服务攻击。网络策略可以应用于命名空间级别。

+   **Kubernetes API 服务器**：Kubernetes API 服务器与所有 Kubernetes 组件交互，包括`etcd`、`controller-manager`和集群管理员用于配置集群的`kubelet`。它调解与主组件的通信，因此集群管理员无需直接与集群组件交互。

我们在*第三章*中讨论了三种不同的威胁行为者，*威胁建模*：特权攻击者、内部攻击者和最终用户。这些威胁行为者也可能与前述的 Kubernetes 实体进行交互。我们将看到攻击者面对这些实体的安全边界：

+   **最终用户**：最终用户与入口、暴露的 Kubernetes 服务或直接与节点上的开放端口进行交互。对于最终用户，节点、Pod、`kube-apiserver`和外部防火墙保护集群组件免受危害。

+   **内部攻击者**：内部攻击者可以访问 Pod 和容器。由`kube-apiserver`强制执行的命名空间和访问控制可以防止这些攻击者提升权限或者危害集群。网络策略和 RBAC 控制可以防止横向移动。

+   **特权攻击者**：`kube-apiserver`是唯一保护主控件组件免受特权攻击者危害的安全边界。如果特权攻击者危害了`kube-apiserver`，那就完了。

在本节中，我们从用户的角度看了安全边界，并向您展示了 Kubernetes 生态系统中如何构建安全边界。接下来，让我们从微服务的角度来看系统层的安全边界。

# 系统层的安全边界

微服务运行在 Pod 内，Pod 被调度在集群中的工作节点上运行。在之前的章节中，我们已经强调容器是分配了专用 Linux 命名空间的进程。一个容器或 Pod 消耗了工作节点提供的所有必要资源。因此，了解系统层的安全边界以及如何加固它是很重要的。在本节中，我们将讨论基于 Linux 命名空间和 Linux 能力一起为微服务构建的安全边界。

## Linux namespaces 作为安全边界

Linux namespaces 是 Linux 内核的一个特性，用于分隔资源以进行隔离。分配了命名空间后，一组进程看到一组资源，而另一组进程看到另一组资源。我们已经在*第二章*，*Kubernetes Networking*中介绍了 Linux namespaces。默认情况下，每个 Pod 都有自己的网络命名空间和 IPC 命名空间。同一 Pod 中的每个容器都有自己的 PID 命名空间，因此一个容器不知道同一 Pod 中运行的其他容器。同样，一个 Pod 不知道同一工作节点中存在其他 Pod。

一般来说，默认设置在安全方面为微服务提供了相当好的隔离。然而，允许在 Kubernetes 工作负载中配置主机命名空间设置，更具体地说，在 Pod 规范中。启用这样的设置后，微服务将使用主机级别的命名空间：

+   **HostNetwork**：Pod 使用主机的网络命名空间。

+   **HostIPC**：Pod 使用主机的 IPC 命名空间。

+   **HostPID**：Pod 使用主机的 PID 命名空间。

+   **shareProcessNamespace**：同一 Pod 内的容器将共享一个 PID 命名空间。

当您尝试配置工作负载以使用主机命名空间时，请问自己一个问题：为什么您必须这样做？当使用主机命名空间时，Pod 在同一工作节点中对其他 Pod 的活动有完全的了解，但这也取决于为容器分配了哪些 Linux 功能。总的来说，事实是，您正在削弱其他微服务的安全边界。让我举个快速的例子。这是容器内可见的进程列表：

```
root@nginx-2:/# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.0  32648  5256 ?        Ss   23:47   0:00 nginx: master process nginx -g daemon off;
nginx          6  0.0  0.0  33104  2348 ?        S    23:47   0:00 nginx: worker process
root           7  0.0  0.0  18192  3248 pts/0    Ss   23:48   0:00 bash
root          13  0.0  0.0  36636  2816 pts/0    R+   23:48   0:00 ps aux
```

正如您所看到的，在`nginx`容器内，只有`nginx`进程和`bash`进程从容器中可见。这个`nginx` Pod 没有使用主机 PID 命名空间。让我们看看如果一个 Pod 使用主机 PID 命名空间会发生什么：

```
root@gke-demo-cluster-default-pool-c9e3510c-tfgh:/# ps axu
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0  99660  7596 ?        Ss   22:54   0:10 /usr/lib/systemd/systemd noresume noswap cros_efi
root          20  0.0  0.0      0     0 ?        I<   22:54   0:00 [netns]
root          71  0.0  0.0      0     0 ?        I    22:54   0:01 [kworker/u4:2]
root         101  0.0  0.1  28288  9536 ?        Ss   22:54   0:01 /usr/lib/systemd/systemd-journald
201          293  0.2  0.0  13688  4068 ?        Ss   22:54   0:07 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile 
274          297  0.0  0.0  22520  4196 ?        Ss   22:54   0:00 /usr/lib/systemd/systemd-networkd
root         455  0.0  0.0      0     0 ?        I    22:54   0:00 [kworker/0:3]
root        1155  0.0  0.0   9540  3324 ?        Ss   22:54   0:00 bash /home/kubernetes/bin/health-monitor.sh container-runtime
root        1356  4.4  1.5 1396748 118236 ?      Ssl  22:56   2:30 /home/kubernetes/bin/kubelet --v=2 --cloud-provider=gce --experimental
root        1635  0.0  0.0 773444  6012 ?        Sl   22:56   0:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.contai
root        1660  0.1  0.4 417260 36292 ?        Ssl  22:56   0:03 kube-proxy --master=https://35.226.122.194 --kubeconfig=/var/lib/kube-
root        2019  0.0  0.1 107744  7872 ?        Ssl  22:56   0:00 /ip-masq-agent --masq-chain=IP-MASQ --nomasq-all-reserved-ranges
root        2171  0.0  0.0  16224  5020 ?        Ss   22:57   0:00 sshd: gke-1a5c3c1c4d5b7d80adbc [priv]
root        3203  0.0  0.0   1024     4 ?        Ss   22:57   0:00 /pause
root        5489  1.3  0.4  48008 34236 ?        Sl   22:57   0:43 calico-node -felix
root        6988  0.0  0.0  32648  5248 ?        Ss   23:01   0:00 nginx: master process nginx -g daemon off;
nginx       7009  0.0  0.0  33104  2584 ?        S    23:01   0:00 nginx: worker process
```

前面的输出显示了在`nginx`容器中运行的进程。在这些进程中有系统进程，如`sshd`、`kubelet`、`kube-proxy`等等。除了 Pod 使用主机 PID 命名空间外，您还可以向其他微服务的进程发送信号，比如向一个进程发送`SIGKILL`来终止它。

## Linux 功能作为安全边界

Linux 功能是从传统的 Linux 权限检查演变而来的概念：特权和非特权。特权进程绕过所有内核权限检查。然后，Linux 将与 Linux 超级用户关联的特权划分为不同的单元- Linux 功能。有与网络相关的功能，比如`CAP_NET_ADMIN`、`CAP_NET_BIND_SERVICE`、`CAP_NET_BROADCAST`和`CAP_NET_RAW`。还有审计相关的功能：`CAP_AUDIT_CONTROL`、`CAP_AUDIT_READ`和`CAP_AUDIT_WRITE`。当然，还有类似管理员的功能：`CAP_SYS_ADMIN`。

如*第四章*中所述，*在 Kubernetes 中应用最小特权原则*，您可以为 Pod 中的容器配置 Linux 功能。默认情况下，以下是分配给 Kubernetes 集群中容器的功能列表：

+   `CAP_SETPCAP`

+   `CAP_MKNOD`

+   `CAP_AUDIT_WRITE`

+   `CAP_CHOWN`

+   `CAP_NET_RAW`

+   `CAP_DAC_OVERRIDE`

+   `CAP_FOWNER`

+   `CAP_FSETID`

+   `CAP_KILL`

+   `CAP_SETGID`

+   `CAP_SETUID`

+   `CAP_NET_BIND_SERVICE`

+   `CAP_SYS_CHROOT`

+   `CAP_SETFCAP`

对于大多数微服务来说，这些功能应该足以执行它们的日常任务。您应该放弃所有功能，只添加所需的功能。与主机命名空间类似，授予额外的功能可能会削弱其他微服务的安全边界。当您在容器中运行`tcpdump`命令时，以下是一个示例输出：

```
root@gke-demo-cluster-default-pool-c9e3510c-tfgh:/# tcpdump -i cali01fb9a4e4b4 -v
tcpdump: listening on cali01fb9a4e4b4, link-type EN10MB (Ethernet), capture size 262144 bytes
23:18:36.604766 IP (tos 0x0, ttl 64, id 27472, offset 0, flags [DF], proto UDP (17), length 86)
    10.56.1.14.37059 > 10.60.0.10.domain: 35359+ A? www.google.com.default.svc.cluster.local. (58)
23:18:36.604817 IP (tos 0x0, ttl 64, id 27473, offset 0, flags [DF], proto UDP (17), length 86)
    10.56.1.14.37059 > 10.60.0.10.domain: 35789+ AAAA? www.google.com.default.svc.cluster.local. (58)
23:18:36.606864 IP (tos 0x0, ttl 62, id 8294, offset 0, flags [DF], proto UDP (17), length 179)
    10.60.0.10.domain > 10.56.1.14.37059: 35789 NXDomain 0/1/0 (151)
23:18:36.606959 IP (tos 0x0, ttl 62, id 8295, offset 0, flags [DF], proto UDP (17), length 179)
    10.60.0.10.domain > 10.56.1.14.37059: 35359 NXDomain 0/1/0 (151)
23:18:36.607013 IP (tos 0x0, ttl 64, id 27474, offset 0, flags [DF], proto UDP (17), length 78)
    10.56.1.14.59177 > 10.60.0.10.domain: 7489+ A? www.google.com.svc.cluster.local. (50)
23:18:36.607053 IP (tos 0x0, ttl 64, id 27475, offset 0, flags [DF], proto UDP (17), length 78)
    10.56.1.14.59177 > 10.60.0.10.domain: 7915+ AAAA? www.google.com.svc.cluster.local. (50)
```

前面的输出显示，在容器内部，有`tcpdump`在网络接口`cali01fb9a4e4b4`上监听，该接口是为另一个 Pod 的网络通信创建的。通过授予主机网络命名空间和`CAP_NET_ADMIN`，您可以在容器内部从整个工作节点嗅探网络流量。一般来说，对容器授予的功能越少，对其他微服务的安全边界就越安全。

## 在系统层包装安全边界

默认情况下，为容器或 Pod 分配的专用 Linux 命名空间和有限的 Linux 功能为微服务建立了良好的安全边界。但是，用户仍然可以配置主机命名空间或为工作负载添加额外的 Linux 功能。这将削弱在同一工作节点上运行的其他微服务的安全边界。您应该非常小心地这样做。通常，监控工具或安全工具需要访问主机命名空间以执行其监控工作或检测工作。强烈建议使用`PodSecurityPolicy`来限制对主机命名空间以及额外功能的使用，以加强微服务的安全边界。

接下来，让我们从微服务的角度来看网络层设置的安全边界。

# 网络层的安全边界

Kubernetes 网络策略定义了不同组的 Pod 之间允许通信的规则。在前一章中，我们简要讨论了 Kubernetes 网络策略的出口规则，可以利用它来强制执行微服务的最小特权原则。在本节中，我们将更详细地介绍 Kubernetes 网络策略，并重点关注入口规则。我们将展示网络策略的入口规则如何帮助建立微服务之间的信任边界。

## 网络策略

如前一章所述，根据网络模型的要求，集群内的 Pod 可以相互通信。但从安全角度来看，您可能希望将您的微服务限制为只能被少数服务访问。我们如何在 Kubernetes 中实现这一点呢？让我们快速看一下以下 Kubernetes 网络策略示例：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 172.17.0.0/16
        except:
        - 172.17.1.0/24
    - namespaceSelector:
        matchLabels:
          project: myproject
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 6379
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978
```

`NetworkPolicy`策略命名为`test-network-policy`。网络策略规范中值得一提的一些关键属性列在这里，以帮助您了解限制是什么：

+   `podSelector`：基于 Pod 标签，应用策略的 Pod 的分组。

+   `Ingress`：适用于顶层`podSelector`中指定的 Pod 的入口规则。`Ingress`下的不同元素如下所述：

- `ipBlock`：允许与入口源进行通信的 IP CIDR 范围

- `namespaceSelector`：基于命名空间标签，允许作为入口源的命名空间

- `podSelector`：基于 Pod 标签，允许作为入口源的 Pod

- `ports`：所有 Pod 应允许通信的端口和协议

+   出口规则：适用于顶层`podSelector`中指定的 Pod 的出口规则。`Ingress`下的不同元素如下所述：

- `ipBlock`：允许作为出口目的地进行通信的 IP CIDR 范围

- `namespaceSelector`：基于命名空间标签，允许作为出口目的地的命名空间

- `podSelector`：基于 Pod 标签，允许作为出口目的地的 Pod

- `ports`：所有 Pod 应允许通信的目标端口和协议

通常，`ipBlock`用于指定允许在 Kubernetes 集群中与微服务交互的外部 IP 块，而命名空间选择器和 Pod 选择器用于限制在同一 Kubernetes 集群中微服务之间的网络通信。

为了从网络方面加强微服务的信任边界，您可能希望要么指定来自外部的允许的`ipBlock`，要么允许来自特定命名空间的微服务。以下是另一个示例，通过使用`namespaceSelector`和`podSelector`来限制来自特定 Pod 和命名空间的入口源：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-good
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          from: good
      podSelector:
        matchLabels:
          from: good
```

请注意，在`podSelector`属性前面没有`-`。这意味着入口源只能是具有标签`from: good`的命名空间中的 Pod。这个网络策略保护了默认命名空间中具有标签`app: web`的 Pod：

![图 5.1 - 通过 Pod 和命名空间标签限制传入流量的网络策略](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-k8s-sec/img/B15566_05_001.jpg)

图 5.1 - 通过 Pod 和命名空间标签限制传入流量的网络策略

在前面的图表中，`good`命名空间具有标签`from: good`，而`bad`命名空间具有标签`from: bad`。它说明只有在具有标签`from: good`的命名空间中的 Pod 才能访问默认命名空间中的`nginx-web`服务。其他 Pod，无论它们是否来自`good`命名空间但没有标签`from: good`，或者来自其他命名空间，都无法访问默认命名空间中的`nginx-web`服务。

# 摘要

在本章中，我们讨论了安全边界的重要性。了解 Kubernetes 生态系统中的安全域和安全边界有助于管理员了解攻击的影响范围，并制定限制攻击造成的损害的缓解策略。了解 Kubernetes 实体是巩固安全边界的起点。了解系统层中构建的安全边界与 Linux 命名空间和功能的能力是下一步。最后但同样重要的是，了解网络策略的威力也是构建安全细分到微服务中的关键。

在这一章中，您应该掌握安全领域和安全边界的概念。您还应该了解 Kubernetes 中的安全领域、常见实体，以及在 Kubernetes 实体内部或周围构建的安全边界。您应该知道使用内置安全功能（如 PodSecurityPolicy 和 NetworkPolicy）来加固安全边界，并仔细配置工作负载的安全上下文的重要性。

在下一章中，我们将讨论如何保护 Kubernetes 组件的安全。特别是，有一些配置细节需要您注意。

# 问题

1.  Kubernetes 中的安全领域是什么？

1.  您与哪些常见的 Kubernetes 实体进行交互？

1.  如何限制 Kubernetes 用户访问特定命名空间中的对象？

1.  启用 hostPID 对于 Pod 意味着什么？

1.  尝试配置网络策略以保护您的服务，只允许特定的 Pod 作为入口源。

# 进一步参考

+   Kubernetes 网络策略：[`kubernetes.io/docs/concepts/services-networking/network-policies/`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

+   CVE-2018-18264: [`groups.google.com/forum/#!searchin/kubernetes-announce/CVE-2018-18264%7Csort:date/kubernetes-announce/yBrFf5nmvfI/gUO60KIlCAAJ`](https://groups.google.com/forum/#!searchin/kubernetes-announce/CVE-2018-18264%7Csort:date/kubernetes-announce/yBrFf5nmvfI/gUO60KIlCAAJ)

+   CVE-2018-1002105: [`groups.google.com/forum/#!topic/kubernetes-announce/GVllWCg6L88`](https://groups.google.com/forum/#!topic/kubernetes-announce/GVllWCg6L88)


# 第二部分：保护 Kubernetes 部署和集群

在本节中，您将通过实际操作学习如何以两种方式保护 Kubernetes 部署/集群：您将学习如何在构建、部署和运行时阶段保护 DevOps 流水线，并且您将了解深度防御，包括合规性、配置、身份验证、授权、资源管理、日志记录和监控、检测以及事件响应。

本节包括以下章节：

+   第六章，保护集群组件

+   第七章，认证、授权和准入控制

+   第八章，保护 Kubernetes Pod

+   第九章，DevOps 流水线中的图像扫描

+   第十章，实时监控和资源管理 Kubernetes 集群

+   第十一章，深度防御


# 第六章：保护集群组件

在之前的章节中，我们看过了 Kubernetes 集群的架构。一个 Kubernetes 集群包括主要组件，包括`kube-apiserver`、`etcd`、`kube-scheduler`、CoreDNS、`kube-controller-manager`和`cloud-controller-manager`，以及节点组件，包括`kubelet`、`kube-proxy`和`container-runtime`。主要组件负责集群管理，它们构成了集群的控制平面。另一方面，节点组件负责节点上 pod 和容器的运行。

在*第三章*中，*威胁建模*，我们简要讨论了 Kubernetes 集群中的组件需要进行配置以确保集群的安全。任何集群组件的妥协都可能导致数据泄露。环境的错误配置是传统或微服务环境中数据泄露的主要原因之一。了解每个组件的配置以及每个设置如何打开新的攻击面是很重要的。因此，集群管理员了解不同的配置是很重要的。

在本章中，我们将详细讨论如何保护集群中的每个组件。在许多情况下，可能无法遵循所有安全最佳实践，但重要的是要强调风险，并制定一套缓解策略，以防攻击者试图利用易受攻击的配置。

对于每个主要和节点组件，我们简要讨论了 Kubernetes 集群中具有安全相关配置的组件的功能，并详细查看了每个配置。我们查看了这些配置的可能设置，并强调了推荐的最佳实践。最后，我们介绍了`kube-bench`，并演示了如何使用它来评估您集群的安全姿势。

在本章中，我们将涵盖以下主题：

+   保护 kube-apiserver

+   保护 kubelet

+   保护 etcd

+   保护 kube-scheduler

+   保护 kube-controller-manager

+   保护 CoreDNS

+   对集群的安全配置进行基准测试

# 保护 kube-apiserver

`kube-apiserver`是您集群的网关。它实现了**表述状态转移**（**REST**）**应用程序编程接口**（**API**）来授权和验证对象的请求。它是与 Kubernetes 集群内的其他组件进行通信和管理的中央网关。它执行三个主要功能：

+   **API 管理**：`kube-apiserver`公开用于集群管理的 API。开发人员和集群管理员使用这些 API 来修改集群的状态。

+   **请求处理**：对于对象管理和集群管理的请求进行验证和处理。

+   **内部消息传递**：API 服务器与集群中的其他组件进行交互，以确保集群正常运行。

API 服务器的请求在处理之前经过以下步骤：

1.  **身份验证**：`kube-apiserver`首先验证请求的来源。`kube-apiserver`支持多种身份验证模式，包括客户端证书、持有者令牌和**超文本传输协议**（**HTTP**）身份验证。

1.  **授权**：一旦验证了请求来源的身份，API 服务器会验证该来源是否被允许执行请求。`kube-apiserver`默认支持**基于属性的访问控制**（**ABAC**）、**基于角色的访问控制**（**RBAC**）、节点授权和用于授权的 Webhooks。RBAC 是推荐的授权模式。

1.  **准入控制器**：一旦`kube-apiserver`验证并授权请求，准入控制器会解析请求，以检查其是否在集群内允许。如果任何准入控制器拒绝请求，则该请求将被丢弃。

`kube-apiserver`是集群的大脑。API 服务器的妥协会导致集群的妥协，因此确保 API 服务器安全至关重要。Kubernetes 提供了大量设置来配置 API 服务器。让我们接下来看一些与安全相关的配置。

为了保护 API 服务器，您应该执行以下操作：

+   **禁用匿名身份验证**：使用`anonymous-auth=false`标志将匿名身份验证设置为`false`。这可以确保被所有身份验证模块拒绝的请求不被视为匿名并被丢弃。

+   **禁用基本身份验证**：基本身份验证在`kube-apiserver`中为方便起见而受支持，不应使用。基本身份验证密码会持续存在。`kube-apiserver`使用`--basic-auth-file`参数来启用基本身份验证。确保不使用此参数。

+   **禁用令牌认证**：`--token-auth-file`启用集群的基于令牌的认证。不建议使用基于令牌的认证。静态令牌会永久存在，并且需要重新启动 API 服务器才能更新。应该使用客户端证书进行认证。

+   **确保与 kubelet 的连接使用 HTTPS**：默认情况下，`--kubelet-https`设置为`true`。确保对于`kube-apiserver`，不要将此参数设置为`false`。

+   **禁用分析**：使用`--profiling`启用分析会暴露不必要的系统和程序细节。除非遇到性能问题，否则通过设置`--profiling=false`来禁用分析。

+   **禁用 AlwaysAdmit**：`--enable-admission-plugins`可用于启用默认未启用的准入控制插件。`AlwaysAdmit`接受请求。确保该插件不在`--enabled-admission-plugins`列表中。

+   **使用 AlwaysPullImages**：`AlwaysPullImages`准入控制确保节点上的镜像在没有正确凭据的情况下无法使用。这可以防止恶意 Pod 为节点上已存在的镜像创建容器。

+   **使用 SecurityContextDeny**：如果未启用`PodSecurityPolicy`，应使用此准入控制器。`SecurityContextDeny`确保 Pod 无法修改`SecurityContext`以提升特权。

+   **启用审计**：审计在`kube-apiserver`中默认启用。确保`--audit-log-path`设置为安全位置的文件。此外，确保审计的`maxage`、`maxsize`和`maxbackup`参数设置满足合规性要求。

+   **禁用 AlwaysAllow 授权**：授权模式确保具有正确权限的用户的请求由 API 服务器解析。不要在`--authorization-mode`中使用`AlwaysAllow`。

+   **启用 RBAC 授权**：RBAC 是 API 服务器的推荐授权模式。ABAC 难以使用和管理。RBAC 角色和角色绑定的易用性和易于更新使其适用于经常扩展的环境。

+   **确保对 kubelet 的请求使用有效证书**：默认情况下，`kube-apiserver`对`kubelet`的请求使用 HTTPS。启用`--kubelet-certificate-authority`、`--kubelet-client-key`和`--kubelet-client-key`确保通信使用有效的 HTTPS 证书。

+   **启用 service-account-lookup**：除了确保服务账户令牌有效外，`kube-apiserver`还应验证令牌是否存在于`etcd`中。确保`--service-account-lookup`未设置为`false`。

+   **启用 PodSecurityPolicy**：`--enable-admission-plugins`可用于启用`PodSecurityPolicy`。正如我们在[*第五章*]（B15566_05_Final_ASB_ePub.xhtml#_idTextAnchor144）中所看到的，*配置 Kubernetes 安全边界*，`PodSecurityPolicy`用于定义 pod 的安全敏感标准。我们将在[*第八章*]（B15566_08_Final_ASB_ePub.xhtml#_idTextAnchor249）中深入探讨创建 pod 安全策略。

+   **使用服务账户密钥文件**：使用`--service-account-key-file`可以启用对服务账户密钥的轮换。如果未指定此选项，`kube-apiserver`将使用**传输层安全性**（**TLS**）证书的私钥来签署服务账户令牌。

+   **启用对 etcd 的授权请求**：`--etcd-certfile`和`--etcd-keyfile`可用于标识对`etcd`的请求。这可以确保`etcd`可以拒绝任何未经识别的请求。

+   **不要禁用 ServiceAccount 准入控制器**：此准入控制自动化服务账户。启用`ServiceAccount`可确保可以将具有受限权限的自定义`ServiceAccount`与不同的 Kubernetes 对象一起使用。

+   **不要为请求使用自签名证书**：如果为`kube-apiserver`启用了 HTTPS，则应提供`--tls-cert-file`和`--tls-private-key-file`，以确保不使用自签名证书。

+   **连接到 etcd 的安全连接**：设置`--etcd-cafile`允许`kube-apiserver`使用证书文件通过**安全套接字层**（**SSL**）向`etcd`验证自身。

+   **使用安全的 TLS 连接**：将`--tls-cipher-suites`设置为仅使用强密码。`--tls-min-version`用于设置最低支持的 TLS 版本。TLS 1.2 是推荐的最低版本。

+   **启用高级审计**：通过将`--feature-gates`设置为`AdvancedAuditing=false`可以禁用高级审计。确保此字段存在并设置为`true`。高级审计有助于调查是否发生违规行为。

在 Minikube 上，`kube-apiserver`的配置如下：

```
$ps aux | grep kube-api
root      4016  6.1 17.2 495148 342896 ?       Ssl  01:03   0:16 kube-apiserver --advertise-address=192.168.99.100 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/var/lib/minikube/certs/ca.crt --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota --enable-bootstrap-token-auth=true --etcd-cafile=/var/lib/minikube/certs/etcd/ca.crt --etcd-certfile=/var/lib/minikube/certs/apiserver-etcd-client.crt --etcd-keyfile=/var/lib/minikube/certs/apiserver-etcd-client.key --etcd-servers=https://127.0.0.1:2379 --insecure-port=0 --kubelet-client-certificate=/var/lib/minikube/certs/apiserver-kubelet-client.crt --kubelet-client-key=/var/lib/minikube/certs/apiserver-kubelet-client.key --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname --proxy-client-cert-file=/var/lib/minikube/certs/front-proxy-client.crt --proxy-client-key-file=/var/lib/minikube/certs/front-proxy-client.key --requestheader-allowed-names=front-proxy-client --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --secure-port=8443 --service-account-key-file=/var/lib/minikube/certs/sa.pub --service-cluster-ip-range=10.96.0.0/12 --tls-cert-file=/var/lib/minikube/certs/apiserver.crt --tls-private-key-file=/var/lib/minikube/certs/apiserver.key
```

正如您所看到的，默认情况下，在 Minikube 上，`kube-apiserver`并未遵循所有安全最佳实践。例如，默认情况下未启用`PodSecurityPolicy`，也未设置强密码套件和`tls`最低版本。集群管理员有责任确保 API 服务器的安全配置。

# 保护 kubelet

`kubelet`是 Kubernetes 的节点代理。它管理 Kubernetes 集群中对象的生命周期，并确保节点上的对象处于健康状态。

要保护`kubelet`，您应该执行以下操作：

+   **禁用匿名身份验证**：如果启用了匿名身份验证，则被其他身份验证方法拒绝的请求将被视为匿名。确保为每个`kubelet`实例设置`--anonymous-auth=false`。

+   **设置授权模式**：使用配置文件设置`kubelet`的授权模式。可以使用`--config`参数指定配置文件。确保授权模式列表中没有`AlwaysAllow`。

+   **轮换 kubelet 证书**：可以使用`kubelet`配置文件中的`RotateCertificates`配置来轮换`kubelet`证书。这应与`RotateKubeletServerCertificate`一起使用，以自动请求轮换服务器证书。

+   **提供证书颁发机构（CA）包**：`kubelet`使用 CA 包来验证客户端证书。可以使用配置文件中的`ClientCAFile`参数进行设置。

+   **禁用只读端口**：默认情况下，`kubelet`启用了只读端口，应该禁用。只读端口没有身份验证或授权。

+   **启用 NodeRestriction 准入控制器**：`NodeRestriction`准入控制器仅允许`kubelet`修改其绑定的节点上的节点和 Pod 对象。

+   **限制对 Kubelet API 的访问**：只有`kube-apiserver`组件与`kubelet` API 交互。如果尝试在节点上与`kubelet` API 通信，将被禁止。这是通过为`kubelet`使用 RBAC 来确保的。

在 Minikube 上，`kubelet`配置如下：

```
root      4286  2.6  4.6 1345544 92420 ?       Ssl  01:03   0:18 /var/lib/minikube/binaries/v1.17.3/kubelet --authorization-mode=Webhook --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --cgroup-driver=cgroupfs --client-ca-file=/var/lib/minikube/certs/ca.crt --cluster-domain=cluster.local --config=/var/lib/kubelet/config.yaml --container-runtime=docker --fail-swap-on=false --hostname-override=minikube --kubeconfig=/etc/kubernetes/kubelet.conf --node-ip=192.168.99.100 --pod-manifest-path=/etc/kubernetes/manifests
```

与 API 服务器类似，默认情况下，`kubelet`上并非所有安全配置都被使用，例如禁用只读端口。接下来，我们将讨论集群管理员如何保护`etcd`。

# 保护 etcd

`etcd`是 Kubernetes 用于数据存储的键值存储。它存储了 Kubernetes 集群的状态、配置和秘密。只有`kube-apiserver`应该可以访问`etcd`。`etcd`的泄露可能导致集群泄露。

为了保护`etcd`，您应该执行以下操作：

+   **限制节点访问**：使用 Linux 防火墙确保只允许需要访问`etcd`的节点访问。

+   **确保 API 服务器使用 TLS**：`--cert-file`和`--key-file`确保对`etcd`的请求是安全的。

+   **使用有效证书**：`--client-cert-auth`确保客户端通信使用有效证书，并将`--auto-tls`设置为`false`确保不使用自签名证书。

+   **加密静态数据**：将`--encryption-provider-config`传递给 API 服务器，以确保在`etcd`中对静态数据进行加密。

在 Minikube 上，`etcd`配置如下：

```
$ ps aux | grep etcd
root      3992  1.9  2.4 10612080 48680 ?      Ssl  01:03   0:18 etcd --advertise-client-urls=https://192.168.99.100:2379 --cert-file=/var/lib/minikube/certs/etcd/server.crt --client-cert-auth=true --data-dir=/var/lib/minikube/etcd --initial-advertise-peer-urls=https://192.168.99.100:2380 --initial-cluster=minikube=https://192.168.99.100:2380 --key-file=/var/lib/minikube/certs/etcd/server.key --listen-client-urls=https://127.0.0.1:2379,https://192.168.99.100:2379 --listen-metrics-urls=http://127.0.0.1:2381 --listen-peer-urls=https://192.168.99.100:2380 --name=minikube --peer-cert-file=/var/lib/minikube/certs/etcd/peer.crt --peer-client-cert-auth=true --peer-key-file=/var/lib/minikube/certs/etcd/peer.key --peer-trusted-ca-file=/var/lib/minikube/certs/etcd/ca.crt --snapshot-count=10000 --trusted-ca-file=/var/lib/minikube/certs/etcd/ca.crt
```

`etcd`存储着 Kubernetes 集群的敏感数据，如私钥和秘密。`etcd`的泄露就意味着`api-server`组件的泄露。集群管理员在设置`etcd`时应特别注意。

# 保护 kube-scheduler

接下来，我们来看看`kube-scheduler`。正如我们在*第一章*中已经讨论过的，*Kubernetes 架构*，`kube-scheduler`负责为 pod 分配节点。一旦 pod 分配给节点，`kubelet`就会执行该 pod。`kube-scheduler`首先过滤可以运行 pod 的节点集，然后根据每个节点的评分，将 pod 分配给评分最高的过滤节点。`kube-scheduler`组件的泄露会影响集群中 pod 的性能和可用性。

为了保护`kube-scheduler`，您应该执行以下操作：

+   **禁用分析**：对`kube-scheduler`的分析会暴露系统细节。将`--profiling`设置为`false`可以减少攻击面。

+   **禁用 kube-scheduler 的外部连接**：应禁用`kube-scheduler`的外部连接。将`AllowExtTrafficLocalEndpoints`设置为`true`会启用`kube-scheduler`的外部连接。确保使用`--feature-gates`禁用此功能。

+   **启用 AppArmor**：默认情况下，`kube-scheduler`启用了`AppArmor`。确保不要禁用`kube-scheduler`的`AppArmor`。

在 Minikube 上，`kube-scheduler`配置如下：

```
$ps aux | grep kube-scheduler
root      3939  0.5  2.0 144308 41640 ?        Ssl  01:03   0:02 kube-scheduler --authentication-kubeconfig=/etc/kubernetes/scheduler.conf --authorization-kubeconfig=/etc/kubernetes/scheduler.conf --bind-address=0.0.0.0 --kubeconfig=/etc/kubernetes/scheduler.conf --leader-elect=true
```

与`kube-apiserver`类似，调度程序也没有遵循所有的安全最佳实践，比如禁用分析。

# 保护 kube-controller-manager

`kube-controller-manager`管理集群的控制循环。它通过 API 服务器监视集群的更改，并旨在将集群从当前状态移动到期望的状态。`kube-controller-manager`默认提供多个控制器管理器，如复制控制器和命名空间控制器。对`kube-controller-manager`的妥协可能导致对集群的更新被拒绝。

要保护`kube-controller-manager`，您应该使用`--use-service-account-credentials`，与 RBAC 一起使用可以确保控制循环以最低特权运行。

在 Minikube 上，`kube-controller-manager`的配置如下：

```
$ps aux | grep kube-controller-manager
root      3927  1.8  4.5 209520 90072 ?        Ssl  01:03   0:11 kube-controller-manager --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=0.0.0.0 --client-ca-file=/var/lib/minikube/certs/ca.crt --cluster-signing-cert-file=/var/lib/minikube/certs/ca.crt --cluster-signing-key-file=/var/lib/minikube/certs/ca.key --controllers=*,bootstrapsigner,tokencleaner --kubeconfig=/etc/kubernetes/controller-manager.conf --leader-elect=true --requestheader-client-ca-file=/var/lib/minikube/certs/front-proxy-ca.crt --root-ca-file=/var/lib/minikube/certs/ca.crt --service-account-private-key-file=/var/lib/minikube/certs/sa.key --use-service-account-credentials=true
```

接下来，让我们谈谈如何保护 CoreDNS。

# 保护 CoreDNS

`kube-dns`是 Kubernetes 集群的默认**域名系统**（**DNS**）服务器。DNS 服务器帮助内部对象（如服务、pod 和容器）相互定位。`kube-dns`由三个容器组成，详细如下：

+   `kube-dns`：此容器使用 SkyDNS 执行 DNS 解析服务。

+   `dnsmasq`：轻量级 DNS 解析器。它从 SkyDNS 缓存响应。

+   `sidecar`：这个监视健康并处理 DNS 的度量报告。

自 1.11 版本以来，`kube-dns`已被 CoreDNS 取代，因为 dnsmasq 存在安全漏洞，SkyDNS 存在性能问题。CoreDNS 是一个单一容器，提供了`kube-dns`的所有功能。

要编辑 CoreDNS 的配置文件，您可以使用`kubectl`，就像这样：

```
$ kubectl -n kube-system edit configmap coredns
```

在 Minikube 上，默认的 CoreDNS 配置文件如下：

```
# Please edit the object below. Lines beginning with a '#' 
# will be ignored, and an empty file will abort the edit. 
# If an error occurs while saving this file will be
# reopened with the relevant failures.
apiVersion: v1
data:
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }
```

要保护 CoreDNS，请执行以下操作：

+   **确保健康插件未被禁用**：`health`插件监视 CoreDNS 的状态。它用于确认 CoreDNS 是否正在运行。通过在`Corefile`中添加`health`来启用它。

+   **为 CoreDNS 启用 istio**：`istio`是 Kubernetes 使用的服务网格，用于提供服务发现、负载平衡和认证。它在 Kubernetes 中默认不可用，需要作为外部依赖项添加。您可以通过启动`istio`服务并将`istio`服务的代理添加到配置文件中来向集群添加`istio`，就像这样：

```
global:53 {
         errors
         proxy . {cluster IP of this istio-core-dns service}
    }
```

现在我们已经查看了集群组件的不同配置，重要的是要意识到随着组件变得更加复杂，将会添加更多的配置参数。集群管理员不可能记住这些配置。因此，接下来，我们将讨论一种帮助集群管理员监视集群组件安全状况的工具。

# 对集群安全配置进行基准测试

**互联网安全中心**（**CIS**）发布了一份 Kubernetes 基准，可以供集群管理员使用，以确保集群遵循推荐的安全配置。发布的 Kubernetes 基准超过 200 页。

`kube-bench`是一个用 Go 编写并由 Aqua Security 发布的自动化工具，运行 CIS 基准中记录的测试。这些测试是用**YAML Ain't Markup Language**（**YAML**）编写的，使其易于演变。

`kube-bench`可以直接在节点上使用`kube-bench`二进制文件运行，如下所示：

```
$kube-bench node --benchmark cis-1.4
```

对于托管在`gke`、`eks`和`aks`上的集群，`kube-bench`作为一个 pod 运行。一旦 pod 运行完成，您可以查看日志以查看结果，如下面的代码块所示：

```
$ kubectl apply -f job-gke.yaml
$ kubectl get pods
NAME               READY   STATUS      RESTARTS   AGE
kube-bench-2plpm   0/1     Completed   0          5m20s
$ kubectl logs kube-bench-2plpm
[INFO] 4 Worker Node Security Configuration
[INFO] 4.1 Worker Node Configuration Files
[WARN] 4.1.1 Ensure that the kubelet service file permissions are set to 644 or more restrictive (Not Scored)
[WARN] 4.1.2 Ensure that the kubelet service file ownership is set to root:root (Not Scored)
[PASS] 4.1.3 Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive (Scored)
[PASS] 4.1.4 Ensure that the proxy kubeconfig file ownership is set to root:root (Scored)
[WARN] 4.1.5 Ensure that the kubelet.conf file permissions are set to 644 or more restrictive (Not Scored)
[WARN] 4.1.6 Ensure that the kubelet.conf file ownership is set to root:root (Not Scored)
[WARN] 4.1.7 Ensure that the certificate authorities file permissions are set to 644 or more restrictive (Not Scored)
......
== Summary ==
0 checks PASS
0 checks FAIL
37 checks WARN
0 checks INFO
```

重要的是要调查具有`FAIL`状态的检查。您应该力求没有失败的检查。如果由于任何原因这是不可能的，您应该制定一个针对失败检查的风险缓解计划。

`kube-bench`是一个有用的工具，用于监视遵循安全最佳实践的集群组件。建议根据自己的环境添加/修改`kube-bench`规则。大多数开发人员在启动新集群时运行`kube-bench`，但定期运行它以监视集群组件是否安全很重要。

# 总结

在本章中，我们查看了每个主节点和节点组件的不同安全敏感配置：`kube-apiserver`、`kube-scheduler`、`kube-controller-manager`、`kubelet`、CoreDNS 和`etcd`。我们了解了如何保护每个组件。默认情况下，组件可能不遵循所有安全最佳实践，因此集群管理员有责任确保组件是安全的。最后，我们看了一下`kube-bench`，它可以用来了解正在运行的集群的安全基线。

重要的是要了解这些配置，并确保组件遵循这些检查表，以减少受到威胁的机会。

在下一章中，我们将介绍 Kubernetes 中的身份验证和授权机制。在本章中，我们简要讨论了一些准入控制器。我们将深入探讨不同的准入控制器，并最终讨论它们如何被利用以提供更精细的访问控制。

# 问题

1.  什么是基于令牌的身份验证？

1.  什么是`NodeRestriction`准入控制器？

1.  如何确保数据在`etcd`中处于加密状态？

1.  为什么 CoreDNS 取代了`kube-dns`？

1.  如何在**弹性 Kubernetes 服务**（**EKS**）集群上使用`kube-bench`？

# 进一步阅读

您可以参考以下链接，了解本章涵盖的主题的更多信息：

+   CIS 基准：[`www.cisecurity.org/benchmark/kubernetes/`](https://www.cisecurity.org/benchmark/kubernetes/)

+   GitHub（`kube-bench`）：[`github.com/aquasecurity/kube-bench`](https://github.com/aquasecurity/kube-bench)
